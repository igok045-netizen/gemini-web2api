package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestUploadPageFetchStopsOnCancellation(t *testing.T) {
	oldFetch := fetchSessionPageTokens
	cookie := "SAPISID=cancel-upload; __Secure-1PSID=cancel-upload"
	t.Cleanup(func() { fetchSessionPageTokens = oldFetch; invalidateXSRF(cookie) })
	started := make(chan struct{})
	fetchSessionPageTokens = func(ctx context.Context, cookie string, user int, proxy string) (xsrfEntry, []string, error) {
		close(started)
		<-ctx.Done()
		return xsrfEntry{}, nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := uploadBytesWithContext(ctx, cookie, 0, "", []byte("test"), "test.txt")
		result <- err
	}()
	<-started
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("upload page fetch cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("upload page fetch did not stop")
	}
}

func TestUploadHTTPStopsOnCancellation(t *testing.T) {
	oldRuntime := rtCfg()
	t.Cleanup(func() { rtMu.Lock(); rtVal = oldRuntime; rtMu.Unlock() })
	rtMu.Lock()
	rtVal = RuntimeConfig{Impersonate: "firefox_147", RequestTimeout: 5}
	rtMu.Unlock()
	for _, proxy := range []bool{false, true} {
		name := "direct"
		if proxy {
			name = "proxy"
		}
		t.Run(name, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(started)
				<-release
			}))
			defer server.Close()
			defer close(release)
			target, proxyURL := server.URL, ""
			if proxy {
				target, proxyURL = "http://push.clients6.google.com/upload", server.URL
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				_, _, _, err := uploadPostWithContext(ctx, target, nil, []byte("test"), proxyURL)
				result <- err
			}()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("upload did not reach local server")
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Errorf("upload error does not reflect cancellation: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("upload did not stop")
			}
		})
	}
}
