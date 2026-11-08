package app

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/quic-go-utls/http3"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
)

// Opt-in, unauthenticated read-only protocol probe. It does not use cookies or
// send a Gemini prompt, and it logs only HTTP status and protocol version.
func TestLiveDirectTransportProtocol(t *testing.T) {
	if os.Getenv("GEMINI_DIAGNOSTIC_PROTOCOL") != "1" {
		t.Skip("opt-in protocol diagnostic")
	}
	oldRuntime := rtCfg()
	t.Cleanup(func() { rtMu.Lock(); rtVal = oldRuntime; rtMu.Unlock() })
	rtMu.Lock()
	rtVal = RuntimeConfig{Impersonate: "firefox_147", RequestTimeout: 15}
	rtMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := fhttp.NewRequestWithContext(ctx, "GET", "https://geminiweb-pa.clients6.google.com/", nil)
	if err != nil {
		t.Fatal("cannot construct diagnostic request")
	}
	applyBrowserHeaderValues(req.Header, "same-site")
	resp, err := getTLSClient().Do(req)
	if err != nil {
		t.Fatal("protocol diagnostic could not reach Google")
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	t.Logf("Direct transport: HTTP status=%d protocol=%q", resp.StatusCode, resp.Proto)
}

// No racing and no fallback: a failed UDP attempt never resends a request.
// This only probes an unauthenticated GET, not generation or session state.
func TestLiveHTTP3TransportProtocol(t *testing.T) {
	if os.Getenv("GEMINI_DIAGNOSTIC_PROTOCOL") != "1" {
		t.Skip("opt-in protocol diagnostic")
	}
	transport := diagnosticHTTP3Transport(os.Getenv("GEMINI_DIAGNOSTIC_HTTP3_STATIC") == "1")
	defer transport.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := fhttp.NewRequestWithContext(ctx, "GET", "https://geminiweb-pa.clients6.google.com/", nil)
	if err != nil {
		t.Fatal("cannot construct diagnostic request")
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		category := "other"
		var dns *net.DNSError
		var op *net.OpError
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			category = "deadline"
		case errors.As(err, &dns):
			category = "DNS"
		case errors.As(err, &op):
			category = "network operation"
		case strings.Contains(strings.ToLower(err.Error()), "certificate"):
			category = "certificate"
		case strings.Contains(strings.ToLower(err.Error()), "handshake"):
			category = "handshake"
		case strings.Contains(strings.ToLower(err.Error()), "protocol"):
			category = "protocol"
		}
		var matches []string
		for _, term := range []string{"closed", "unreachable", "connection refused", "timeout", "deadline", "network", "dial", "handshake", "certificate", "protocol", "tls", "quic", "udp", "settings", "server_name", "server name", "response", "internal", "required insert count", "no dynamic table", "expected base", "invalid indexed"} {
			if strings.Contains(strings.ToLower(err.Error()), term) {
				matches = append(matches, term)
			}
		}
		t.Fatalf("HTTP/3 diagnostic could not reach Google: category=%s, error_type=%T, cause_type=%T, indicators=%v", category, err, errors.Unwrap(err), matches)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	t.Logf("Direct HTTP/3 transport: HTTP status=%d protocol=%q", resp.StatusCode, resp.Proto)
}

// This transport is isolated to diagnostics, always direct, and does not use
// the library's protocol-racing feature (which can duplicate POST requests).
func diagnosticHTTP3Transport(static bool) *http3.Transport {
	profile := profiles.Firefox_147
	settings := profile.GetHttp3Settings()
	order := profile.GetHttp3SettingsOrder()
	if static {
		settings = make(map[uint64]uint64)
		for id, value := range profile.GetHttp3Settings() {
			if id != 1 && id != 7 {
				settings[id] = value
			}
		}
		order = nil
		for _, id := range profile.GetHttp3SettingsOrder() {
			if id != 1 && id != 7 {
				order = append(order, id)
			}
		}
	}
	return &http3.Transport{
		TLSClientConfig:         &tls.Config{ServerName: "geminiweb-pa.clients6.google.com"},
		AdditionalSettings:      settings,
		AdditionalSettingsOrder: order,
		PseudoHeaderOrder:       profile.GetHttp3PseudoHeaderOrder(),
		SendGreaseFrames:        profile.GetHttp3SendGreaseFrames(),
		PriorityParam:           profile.GetHttp3PriorityParam(),
		MaxResponseHeaderBytes:  -1,
	}
}

func diagnosticHTTP3Send(transport *http3.Transport, ctx context.Context, method, target, body, cookie, proxy string) (*wcResp, string, error) {
	if proxy != "" {
		return nil, "", errors.New("diagnostic HTTP/3 does not support configured proxies")
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || u.Host != "geminiweb-pa.clients6.google.com" || u.Path != "/v1/processSession" {
		return nil, "", errors.New("invalid diagnostic HTTP/3 destination")
	}
	var data io.Reader
	if method == "POST" {
		data = strings.NewReader(body)
	}
	req, err := fhttp.NewRequestWithContext(ctx, method, target, data)
	if err != nil {
		return nil, "", safeWCNetworkError(err)
	}
	applyBrowserHeaderValues(req.Header, "same-site")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Origin", "https://gemini.google.com")
	req.Header.Set("Referer", "https://gemini.google.com/")
	if method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		return nil, "", safeWCNetworkError(err)
	}
	return &wcResp{status: resp.StatusCode, setCookie: resp.Header.Values("Set-Cookie"), sessionID: resp.Header.Get("X-HTTP-Session-Id"), body: resp.Body}, resp.Proto, nil
}

func TestDiagnosticHTTP3DoesNotBypassProxyOrChangeDestination(t *testing.T) {
	transport := diagnosticHTTP3Transport(true)
	defer transport.Close()
	if _, _, err := diagnosticHTTP3Send(transport, context.Background(), "GET", wcEndpoint, "", "", "http://proxy.invalid"); err == nil {
		t.Fatal("configured proxy was bypassed")
	}
	if _, _, err := diagnosticHTTP3Send(transport, context.Background(), "GET", "https://example.invalid/", "", "", ""); err == nil {
		t.Fatal("foreign endpoint accepted")
	}
	if _, ok := transport.AdditionalSettings[1]; ok {
		t.Fatal("dynamic QPACK capacity advertised")
	}
	if _, ok := transport.AdditionalSettings[7]; ok {
		t.Fatal("dynamic QPACK blocked streams advertised")
	}
}
