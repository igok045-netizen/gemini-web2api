package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExperimentalBrowserLocaleHeaders(t *testing.T) {
	t.Setenv("GEMINI_EXPERIMENTAL_BROWSER_LOCALE", "ru")
	oldRuntime := rtCfg()
	t.Cleanup(func() { rtMu.Lock(); rtVal = oldRuntime; rtMu.Unlock() })
	rtMu.Lock()
	rtVal = RuntimeConfig{FirefoxFingerprint: true, RequestTimeout: 5}
	rtMu.Unlock()
	seen := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Accept-Language")
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	if _, err := fetchAppPageURLWithContext(context.Background(), server.URL+"/app", "SAPISID=test", ""); err != nil {
		t.Fatal(err)
	}
	response, err := wcSend(context.Background(), "POST", server.URL+"/v1/processSession", "count=0", "SAPISID=test", "")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.body.Close()
	want := "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"
	if <-seen != want || <-seen != want || buildGeminiHeaders("", "", "")["Accept-Language"] != want {
		t.Fatal("experimental locale was not applied consistently")
	}
	t.Setenv("GEMINI_EXPERIMENTAL_BROWSER_LOCALE", "unsupported\r\nheader")
	if browserRequestLanguage() != "en" || browserAcceptLanguage() != "en-US,en;q=0.9" {
		t.Fatal("unsupported locale changed the default or allowed header injection")
	}
}

// Exercise the actual /app and legacy generation request paths through a
// local server, for both browser profiles and both connection modes.
func TestSessionAndGenerationSendBrowserHeaders(t *testing.T) {
	oldRuntime := rtCfg()
	t.Cleanup(func() { rtMu.Lock(); rtVal = oldRuntime; rtMu.Unlock() })
	for _, tc := range []struct {
		name, profile, wantUA string
		proxy, wantHints      bool
	}{
		{"direct Chrome", "chrome_146", ChromeUA, false, true},
		{"proxy Chrome", "chrome_146", ChromeUA, true, true},
		{"direct Firefox", "firefox_147", FirefoxUA, false, false},
		{"proxy Firefox", "firefox_147", FirefoxUA, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rtMu.Lock()
			rtVal = RuntimeConfig{Impersonate: tc.profile, RequestTimeout: 5}
			rtMu.Unlock()
			seen := make(chan http.Header, 2)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Header.Clone()
				_, _ = w.Write([]byte("ok"))
			}))
			defer server.Close()
			target, proxy := server.URL+"/app", ""
			if tc.proxy {
				target, proxy = "http://gemini.google.com/app", server.URL
			}
			if _, err := fetchAppPageURLWithContext(context.Background(), target, "SAPISID=test", proxy); err != nil {
				t.Fatal(err)
			}
			if _, _, _, _, err := doGeminiRequestWithContext(context.Background(), target, "test", buildGeminiHeaders("SAPISID=test", "", ""), proxy, nil); err != nil {
				t.Fatal(err)
			}
			for _, stage := range []string{"session page", "generation"} {
				h := <-seen
				if h.Get("User-Agent") != tc.wantUA || (h.Get("Sec-Ch-Ua") != "") != tc.wantHints {
					t.Errorf("%s did not send configured browser headers: UA=%q", stage, h.Get("User-Agent"))
				}
				if h.Get("Cookie") != "SAPISID=test" {
					t.Errorf("%s lost account cookie", stage)
				}
			}
		})
	}
}

// Check the real upload transport, not only the headers assembled by its caller.
func TestUploadSendsBrowserHeaders(t *testing.T) {
	oldRuntime := rtCfg()
	t.Cleanup(func() { rtMu.Lock(); rtVal = oldRuntime; rtMu.Unlock() })
	for _, tc := range []struct {
		name, profile, wantUA string
		proxy, wantHints      bool
	}{
		{"direct Chrome", "chrome_146", ChromeUA, false, true},
		{"proxy Chrome", "chrome_146", ChromeUA, true, true},
		{"direct Firefox", "firefox_147", FirefoxUA, false, false},
		{"proxy Firefox", "firefox_147", FirefoxUA, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rtMu.Lock()
			rtVal = RuntimeConfig{Impersonate: tc.profile, RequestTimeout: 5}
			rtMu.Unlock()
			seen := make(chan http.Header, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Header.Clone()
				_, _ = w.Write([]byte("ok"))
			}))
			defer server.Close()
			target, proxy := server.URL+"/upload", ""
			if tc.proxy {
				target, proxy = "http://push.clients6.google.com/upload", server.URL
			}
			status, _, _, err := uploadPost(target, map[string]string{"Cookie": "SAPISID=test", "Sec-Fetch-Site": "same-site"}, []byte("test"), proxy)
			if err != nil || status != http.StatusOK {
				t.Fatalf("upload status = %d, error = %v", status, err)
			}
			h := <-seen
			if h.Get("User-Agent") != tc.wantUA || (h.Get("Sec-Ch-Ua") != "") != tc.wantHints || h.Get("Sec-Fetch-Site") != "same-site" || h.Get("Cookie") != "SAPISID=test" {
				t.Errorf("upload did not send configured browser headers: UA=%q", h.Get("User-Agent"))
			}
		})
	}
}
