package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A challenge or network failure applies to the chosen egress, not to one
// account. It must not cause cookie refresh, account rotation, or fallback to
// anonymous mode on the same connection.
func TestAccountRecoveryStopsOnEgressFailure(t *testing.T) {
	oldFetch, oldRotate := fetchAccountXSRF, rotateAccountCredentials
	oldRuntime := rtCfg()
	t.Cleanup(func() {
		fetchAccountXSRF, rotateAccountCredentials = oldFetch, oldRotate
		rtMu.Lock()
		rtVal = oldRuntime
		rtMu.Unlock()
	})
	rtMu.Lock()
	rtVal.FallbackAnon = true
	rtVal.AnonFirst = false
	rtVal.PerIPConcurrent, rtVal.PerIPRPM, rtVal.PerIPRPH = 0, 0, 0
	rtMu.Unlock()

	for i := 0; i < 2; i++ {
		id, err := accountAdd(fmt.Sprintf("reliability-%d", i), fmt.Sprintf("SAPISID=reliability%d; __Secure-1PSID=reliability%d", i, i), "")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = accountDelete(id) })
	}
	for _, test := range []struct {
		name  string
		cause error
	}{
		{"challenge", newAppPageStatusError(302, "https://www.google.com/sorry/index?secret=ignored")},
		{"rate limit", newAppPageStatusError(429, "")},
		{"network error", errors.New("connection failed")},
	} {
		t.Run(test.name, func(t *testing.T) {
			fetches, rotations := 0, 0
			fetchAccountXSRF = func(context.Context, string, int, string) (string, []string, error) {
				fetches++
				time.Sleep(2 * time.Millisecond)
				return "", nil, test.cause
			}
			rotateAccountCredentials = func(CookieAccount) (time.Duration, []string, error) {
				rotations++
				return 0, nil, errors.New("should not rotate")
			}
			res, err := streamGenerateOnce("hello", "hello", Models["gemini-4-argon"], nil, nil, nil, nil)
			if !errors.Is(err, test.cause) {
				t.Fatalf("want original error; got %v", err)
			}
			if fetches != 1 || rotations != 0 {
				t.Fatalf("fetches=%d rotations=%d", fetches, rotations)
			}
			if res == nil || res.TotalMs < 1 {
				t.Fatalf("missing failure duration: %+v", res)
			}
			if strings.Contains(err.Error(), "secret=") {
				t.Fatal("redirect query was not redacted")
			}
		})
	}
}

func TestUpstreamRetryStatusPolicy(t *testing.T) {
	for _, tt := range []struct {
		status int
		retry  bool
	}{
		{http.StatusFound, false}, {http.StatusBadRequest, false},
		{http.StatusUnauthorized, false}, {http.StatusTooManyRequests, false},
		{http.StatusRequestTimeout, true}, {http.StatusTooEarly, true},
		{http.StatusInternalServerError, true}, {http.StatusServiceUnavailable, true},
	} {
		if got := retryableUpstreamHTTPStatus(tt.status); got != tt.retry {
			t.Errorf("status %d: retry=%v, want %v", tt.status, got, tt.retry)
		}
	}
}

// Verify the policy is enforced by the real request loop, not just classified.
func TestRequestLoopAvoidsImmediateRetriesOnChallenge(t *testing.T) {
	oldFetch, oldSend := fetchAccountXSRF, sendGeminiRequest
	oldRuntime := rtCfg()
	t.Cleanup(func() {
		fetchAccountXSRF, sendGeminiRequest = oldFetch, oldSend
		rtMu.Lock()
		rtVal = oldRuntime
		rtMu.Unlock()
	})
	rtMu.Lock()
	rtVal.RetryAttempts, rtVal.RetryDelaySec = 3, 0
	rtVal.GeminiBLAuto, rtVal.WebChannel = false, false
	rtVal.PerIPConcurrent, rtVal.PerIPRPM, rtVal.PerIPRPH = 0, 0, 0
	rtMu.Unlock()
	id, err := accountAdd("request-loop", "SAPISID=loop; __Secure-1PSID=loop", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = accountDelete(id) })
	fetchAccountXSRF = func(context.Context, string, int, string) (string, []string, error) { return "test-token", nil, nil }
	model := Models["gemini-4-argon"]
	model.PinAccountID = id
	for _, tt := range []struct{ status, wantAttempts int }{
		{http.StatusFound, 1}, {http.StatusTooManyRequests, 1},
		{http.StatusUnauthorized, 1}, {http.StatusServiceUnavailable, 3},
	} {
		t.Run(fmt.Sprintf("status-%d", tt.status), func(t *testing.T) {
			attempts := 0
			sendGeminiRequest = func(context.Context, string, string, map[string]string, string, func(string) error) (int, []byte, int64, []string, error) {
				attempts++
				time.Sleep(2 * time.Millisecond)
				return tt.status, []byte("test upstream failure"), 0, nil, nil
			}
			res, err := streamGenerateOnce("hello", "hello", model, nil, nil, nil, nil)
			if err == nil || attempts != tt.wantAttempts {
				t.Fatalf("attempts=%d, error=%v", attempts, err)
			}
			if res == nil || res.TotalMs < 1 {
				t.Fatalf("missing failure duration: %+v", res)
			}
		})
	}
}

func TestClientCancellationStopsGenerationAndRetries(t *testing.T) {
	oldFetch, oldSend, oldRuntime := fetchAccountXSRF, sendGeminiRequest, rtCfg()
	t.Cleanup(func() {
		fetchAccountXSRF, sendGeminiRequest = oldFetch, oldSend
		rtMu.Lock()
		rtVal = oldRuntime
		rtMu.Unlock()
	})
	rtMu.Lock()
	rtVal.RetryAttempts, rtVal.RetryDelaySec = 3, 1
	rtVal.GeminiBLAuto, rtVal.WebChannel = false, false
	rtVal.PerIPConcurrent, rtVal.PerIPRPM, rtVal.PerIPRPH = 0, 0, 0
	rtMu.Unlock()
	id, err := accountAdd("cancel-test", "SAPISID=cancel; __Secure-1PSID=cancel", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = accountDelete(id) })
	fetchAccountXSRF = func(context.Context, string, int, string) (string, []string, error) { return "test-token", nil, nil }
	started := make(chan struct{})
	attempts := 0
	sendGeminiRequest = func(ctx context.Context, _, _ string, _ map[string]string, _ string, _ func(string) error) (int, []byte, int64, []string, error) {
		attempts++
		close(started)
		<-ctx.Done()
		return 0, nil, 0, nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	model := Models["gemini-4-argon"]
	model.PinAccountID = id
	model.requestContext = ctx
	done := make(chan error, 1)
	go func() { _, err := streamGenerateOnce("hello", "hello", model, nil, nil, nil, nil); done <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || attempts != 1 {
			t.Fatalf("error=%v attempts=%d", err, attempts)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not stop request")
	}
}

func TestRequestLoopAvoidsDuplicateAfterAcceptedGeneration(t *testing.T) {
	oldFetch, oldSend, oldRuntime := fetchAccountXSRF, sendGeminiRequest, rtCfg()
	t.Cleanup(func() {
		fetchAccountXSRF, sendGeminiRequest = oldFetch, oldSend
		rtMu.Lock()
		rtVal = oldRuntime
		rtMu.Unlock()
	})
	rtMu.Lock()
	rtVal.RetryAttempts, rtVal.RetryDelaySec = 3, 0
	rtVal.GeminiBLAuto, rtVal.WebChannel = false, false
	rtVal.PerIPConcurrent, rtVal.PerIPRPM, rtVal.PerIPRPH = 0, 0, 0
	rtMu.Unlock()
	id, err := accountAdd("read-timeout", "SAPISID=timeout; __Secure-1PSID=timeout", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = accountDelete(id) })
	fetchAccountXSRF = func(context.Context, string, int, string) (string, []string, error) { return "test-token", nil, nil }
	model := Models["gemini-4-argon"]
	model.PinAccountID = id
	for _, tt := range []struct {
		name     string
		status   int
		sendErr  error
		attempts int
	}{
		{"accepted then timeout", 200, context.DeadlineExceeded, 1},
		{"connection failed before response", 0, errors.New("connection failed"), 3},
		{"recognized failure response", 200, errUpstreamFailureReply, 3},
	} {
		t.Run(tt.name, func(t *testing.T) {
			attempts := 0
			sendGeminiRequest = func(context.Context, string, string, map[string]string, string, func(string) error) (int, []byte, int64, []string, error) {
				attempts++
				return tt.status, nil, 1, nil, tt.sendErr
			}
			_, err := streamGenerateOnce("hello", "hello", model, nil, nil, nil, nil)
			if err == nil || attempts != tt.attempts {
				t.Fatalf("attempts=%d, error=%v", attempts, err)
			}
		})
	}
}

func TestCancelDuringRetryDelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- waitBeforeRetry(ctx, 10*time.Second) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("retry delay ignored cancellation")
	}
}

func TestAppPageFetchStopsOnClientCancellation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
	}))
	defer proxy.Close()
	defer close(release)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := fetchAppPageWithContext(ctx, "", 0, proxy.URL); done <- err }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("proxy was not reached")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected a cancellation error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("page fetch ignored cancellation")
	}
}

func TestHTTPUpstreamRequestUsesClientContext(t *testing.T) {
	started := make(chan struct{})
	stopped := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(started)
		select {
		case <-r.Context().Done():
			close(stopped)
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, _, _, _, err := doGeminiRequestWithContext(ctx, server.URL, "test", nil, server.URL, nil)
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("upstream not reached")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected cancelled upstream")
		}
	case <-time.After(time.Second):
		t.Fatal("upstream did not stop")
	}
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream connection remained open after cancellation")
	}
}
