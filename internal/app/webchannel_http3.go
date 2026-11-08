package app

// Experimental, opt-in direct HTTP/3 for binary WebChannel. It never races
// another protocol, retries a POST at the application level, follows redirects,
// or ignores an explicitly configured proxy.
import (
	"context"
	"errors"
	"io"
	"net/url"
	"os"
	"strings"
	"sync"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/quic-go-utls/http3"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
)

type wcHTTP3ContextKey struct{}

func wcExperimentalHTTP3Requested() bool {
	return os.Getenv("GEMINI_WEBCHANNEL_EXPERIMENTAL_HTTP3") == "1"
}

func wcWithHTTP3(ctx context.Context, enabled bool) context.Context {
	return context.WithValue(ctx, wcHTTP3ContextKey{}, enabled)
}

func wcHTTP3EnabledForRequest(ctx context.Context) bool {
	enabled, _ := ctx.Value(wcHTTP3ContextKey{}).(bool)
	return enabled
}

var wcHTTP3Once sync.Once
var wcHTTP3Client *http3.Transport

func wcHTTP3Transport() *http3.Transport {
	wcHTTP3Once.Do(func() {
		profile := profiles.Firefox_147
		settings := make(map[uint64]uint64)
		for id, value := range profile.GetHttp3Settings() {
			// This client's decoder cannot use dynamic QPACK entries.
			if id != 1 && id != 7 {
				settings[id] = value
			}
		}
		var order []uint64
		for _, id := range profile.GetHttp3SettingsOrder() {
			if id != 1 && id != 7 {
				order = append(order, id)
			}
		}
		wcHTTP3Client = &http3.Transport{
			TLSClientConfig:         &tls.Config{ServerName: "geminiweb-pa.clients6.google.com"},
			AdditionalSettings:      settings,
			AdditionalSettingsOrder: order,
			PseudoHeaderOrder:       profile.GetHttp3PseudoHeaderOrder(),
			SendGreaseFrames:        profile.GetHttp3SendGreaseFrames(),
			PriorityParam:           profile.GetHttp3PriorityParam(),
			MaxResponseHeaderBytes:  -1,
		}
	})
	return wcHTTP3Client
}

func wcSendHTTP3(ctx context.Context, method, target, body, cookie, proxy string) (*wcResp, error) {
	if proxy != "" {
		return nil, errors.New("experimental HTTP/3 does not support configured proxies")
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || u.Host != "geminiweb-pa.clients6.google.com" || u.Path != "/v1/processSession" || (method != "POST" && method != "GET") {
		return nil, errors.New("invalid experimental HTTP/3 destination")
	}
	var data io.Reader
	if method == "POST" {
		data = strings.NewReader(body)
	}
	req, err := fhttp.NewRequestWithContext(ctx, method, target, data)
	if err != nil {
		return nil, safeWCNetworkError(err)
	}
	applyBrowserHeaderValues(req.Header, "same-site")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", browserAcceptLanguage())
	req.Header.Set("Origin", "https://gemini.google.com")
	req.Header.Set("Referer", "https://gemini.google.com/")
	if method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := wcHTTP3Transport().RoundTrip(req)
	if err != nil {
		return nil, safeWCNetworkError(err)
	}
	if resp.Proto != "HTTP/3.0" {
		_ = resp.Body.Close()
		return nil, errors.New("experimental HTTP/3 received an unexpected protocol")
	}
	return &wcResp{status: resp.StatusCode, setCookie: resp.Header.Values("Set-Cookie"), sessionID: resp.Header.Get("X-HTTP-Session-Id"), body: resp.Body}, nil
}
