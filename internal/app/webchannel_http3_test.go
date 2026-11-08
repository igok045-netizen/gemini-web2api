package app

import (
	"context"
	"testing"
)

func TestExperimentalHTTP3Safety(t *testing.T) {
	t.Setenv("GEMINI_WEBCHANNEL_EXPERIMENTAL_HTTP3", "1")
	if !wcExperimentalHTTP3Requested() || !wcHTTP3EnabledForRequest(wcWithHTTP3(context.Background(), true)) {
		t.Fatal("opt-in HTTP/3 request selection not retained")
	}
	if wcHTTP3EnabledForRequest(context.Background()) {
		t.Fatal("HTTP/3 enabled without an explicit request")
	}
	if _, err := wcSendHTTP3(context.Background(), "GET", wcEndpoint, "", "secret", "http://proxy.invalid"); err == nil {
		t.Fatal("configured proxy would be bypassed")
	}
	for _, target := range []string{"https://example.invalid/v1/processSession", "http://geminiweb-pa.clients6.google.com/v1/processSession", "https://geminiweb-pa.clients6.google.com/other"} {
		if _, err := wcSendHTTP3(context.Background(), "POST", target, "", "secret", ""); err == nil {
			t.Fatal("unapproved destination accepted")
		}
	}
	transport := wcHTTP3Transport()
	if _, ok := transport.AdditionalSettings[1]; ok {
		t.Fatal("dynamic QPACK capacity advertised")
	}
	if _, ok := transport.AdditionalSettings[7]; ok {
		t.Fatal("dynamic QPACK blocked streams advertised")
	}
	if _, _, _, _, err := doWebChannelRequestWithContext(context.Background(), wcRequest{Binary: true}, "http://proxy.invalid", nil); err == nil {
		t.Fatal("configured proxy not rejected before network access")
	}
	if _, _, _, _, err := doWebChannelRequestWithContext(context.Background(), wcRequest{}, "", nil); err == nil {
		t.Fatal("non-binary WebChannel accepted with HTTP/3 opt-in")
	}
}
