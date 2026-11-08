package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

// Exercise the actual direct and proxied send paths against a local server.
// The TLS profile and HTTP User-Agent must describe the same browser family.
func TestWebChannelSendsConfiguredBrowserHeaders(t *testing.T) {
	oldRuntime := rtCfg()
	t.Cleanup(func() { rtMu.Lock(); rtVal = oldRuntime; rtMu.Unlock() })
	for _, tc := range []struct {
		name      string
		profile   string
		proxy     bool
		wantUA    string
		wantHints bool
	}{
		{"direct Chrome", "chrome_146", false, ChromeUA, true},
		{"proxy Chrome", "chrome_146", true, ChromeUA, true},
		{"direct Firefox", "firefox_147", false, FirefoxUA, false},
		{"proxy Firefox", "firefox_147", true, FirefoxUA, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rtMu.Lock()
			rtVal = RuntimeConfig{Impersonate: tc.profile, RequestTimeout: 5}
			rtMu.Unlock()
			seen := make(chan http.Header, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Header.Clone()
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			target, proxyURL := server.URL+"/v1/processSession", ""
			if tc.proxy {
				target, proxyURL = "http://geminiweb-pa.clients6.google.com/v1/processSession", server.URL
			}
			resp, err := wcSend(context.Background(), "POST", target, "count=0", "SAPISID=test", proxyURL)
			if err != nil {
				t.Fatal(err)
			}
			resp.body.Close()
			header := <-seen
			if header.Get("User-Agent") != tc.wantUA {
				t.Errorf("configured browser profile was not used for User-Agent; got=%q", header.Get("User-Agent"))
			}
			if got := header.Get("Sec-Fetch-Site"); got != "same-site" {
				t.Errorf("Sec-Fetch-Site=%q, want same-site", got)
			}
			if (header.Get("Sec-Ch-Ua") != "") != tc.wantHints {
				t.Errorf("Chrome client hints do not match configured browser")
			}
			if header.Get("Sec-Fetch-Mode") != "cors" || header.Get("Sec-Fetch-Dest") != "empty" || !strings.Contains(header.Get("Cookie"), "SAPISID=test") {
				t.Error("missing expected request headers")
			}
		})
	}
}

// HTTPS/HTTP2 has a separate default User-Agent in fhttp, so also verify the
// real TLS send path. Certificate verification is disabled only for this local
// self-signed test server and test-specific client.
func TestWebChannelDirectHTTP2BrowserHeaders(t *testing.T) {
	oldRuntime := rtCfg()
	rtMu.Lock()
	rtVal = RuntimeConfig{Impersonate: "chrome_146", RequestTimeout: 5}
	rtMu.Unlock()
	t.Cleanup(func() { rtMu.Lock(); rtVal = oldRuntime; rtMu.Unlock() })
	client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), tlsclient.WithClientProfile(profiles.Chrome_146), tlsclient.WithTimeoutSeconds(5), tlsclient.WithInsecureSkipVerify())
	if err != nil {
		t.Fatal(err)
	}
	cacheKey := "chrome_146|5"
	clientCacheMu.Lock()
	oldClient, existed := clientCache[cacheKey]
	clientCache[cacheKey] = client
	clientCacheMu.Unlock()
	t.Cleanup(func() {
		client.CloseIdleConnections()
		clientCacheMu.Lock()
		if existed {
			clientCache[cacheKey] = oldClient
		} else {
			delete(clientCache, cacheKey)
		}
		clientCacheMu.Unlock()
	})
	type observation struct {
		proto  int
		header http.Header
	}
	seen := make(chan observation, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- observation{r.ProtoMajor, r.Header.Clone()}
		w.WriteHeader(http.StatusOK)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	resp, err := wcSend(context.Background(), "POST", server.URL+"/v1/processSession", "count=0", "SAPISID=test", "")
	if err != nil {
		t.Fatal(err)
	}
	resp.body.Close()
	got := <-seen
	if got.proto != 2 || got.header.Get("User-Agent") != ChromeUA || got.header.Get("Sec-Fetch-Site") != "same-site" {
		t.Fatalf("HTTP/2 did not send configured browser headers: proto=%d, UA=%q, site=%q", got.proto, got.header.Get("User-Agent"), got.header.Get("Sec-Fetch-Site"))
	}
}
