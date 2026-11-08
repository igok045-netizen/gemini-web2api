package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Exercise a real local /app response, token cache, account storage and both
// generation paths, without putting any real account data in the test.
func TestAppCookieUpdatesReachGeneration(t *testing.T) {
	oldFetch, oldWeb, oldLegacy, oldRuntime := fetchSessionPageTokens, sendWebChannelRequest, sendGeminiRequest, rtCfg()
	t.Cleanup(func() {
		fetchSessionPageTokens, sendWebChannelRequest, sendGeminiRequest = oldFetch, oldWeb, oldLegacy
		rtMu.Lock()
		rtVal = oldRuntime
		rtMu.Unlock()
	})
	for _, useWeb := range []bool{false, true} {
		name := "legacy"
		if useWeb {
			name = "webchannel"
		}
		t.Run(name, func(t *testing.T) {
			original := "SAPISID=identity; __Secure-1PSID=identity; SIDCC=old-" + name
			id, err := accountAdd("local-app-cookie-"+name, original, "")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = accountDelete(id); invalidateXSRF(original) })
			pageFetches := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				pageFetches++
				w.Header().Add("Set-Cookie", "SIDCC=fresh; Domain=.google.com; Path=/; Secure")
				w.Header().Add("Set-Cookie", "SAPISID=other-account; Domain=.google.com; Path=/; Secure")
				w.Header().Add("Set-Cookie", "HOSTONLY=private; Path=/; Secure")
				w.Header().Add("Set-Cookie", "RESTRICTED=private; Domain=.google.com; Path=/other; Secure")
				w.Header().Add("Set-Cookie", "FOREIGN=private; Domain=.example.com; Path=/; Secure")
				_, _ = w.Write([]byte("test-token"))
			}))
			defer server.Close()
			fetchSessionPageTokens = func(ctx context.Context, cookie string, authuser int, proxy string) (xsrfEntry, []string, error) {
				body, updates, err := fetchAppPageURLAndCookiesWithContext(ctx, server.URL+"/app", cookie, "")
				return xsrfEntry{token: string(body), fetched: time.Now()}, updates, err
			}
			rtMu.Lock()
			rtVal = RuntimeConfig{RetryAttempts: 1, RequestTimeout: 5, Impersonate: "chrome_146", WebChannel: useWeb, GeminiBL: defaultConfig().GeminiBL}
			rtMu.Unlock()
			var sent string
			sendWebChannelRequest = func(ctx context.Context, req wcRequest, proxy string, cb func(string) error) (int, []byte, int64, []string, error) {
				sent = req.Cookie
				return 200, nil, 0, nil, errors.New("test response interrupted")
			}
			sendGeminiRequest = func(ctx context.Context, endpoint, body string, headers map[string]string, proxy string, cb func(string) error) (int, []byte, int64, []string, error) {
				sent = headers["Cookie"]
				return 200, nil, 0, nil, errors.New("test response interrupted")
			}
			model := Models["gemini-4-argon"]
			model.PinAccountID = id
			_, _ = streamGenerateOnce("hello", "hello", model, nil, nil, nil, nil)
			if !strings.Contains(sent, "SIDCC=fresh") || !strings.Contains(sent, "SAPISID=identity") || strings.Contains(sent, "other-account") || strings.Contains(sent, "private") {
				t.Fatal("generation did not receive the safe updated session")
			}
			stored := accountByID(id)
			if stored == nil || stored.Cookie != sent {
				t.Fatal("safe updates were not stored for this account")
			}
			t.Cleanup(func() { invalidateXSRF(stored.Cookie) })
			token, updates, err := getXSRFSessionWithContext(context.Background(), stored.Cookie, 0, "")
			if err != nil || token != "test-token" || len(updates) != 0 || pageFetches != 1 {
				t.Fatalf("refreshed session cache not reused: fetches=%d updates=%d err=%v", pageFetches, len(updates), err)
			}
		})
	}
}

func TestAppCookieUpdateDoesNotOverwriteConcurrentSession(t *testing.T) {
	original := "SAPISID=identity; __Secure-1PSID=identity; SIDCC=old"
	newer := "SAPISID=identity; __Secure-1PSID=identity; SIDCC=newer"
	id, err := accountAdd("local-app-cookie-race", original, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = accountDelete(id) })
	if _, err := getDB().Exec("UPDATE accounts SET cookie=? WHERE id=?", newer, id); err != nil {
		t.Fatal(err)
	}
	local := applyAppPageAccountCookies(id, original, 0, "test-token", "", []string{"SIDCC=intermediate; Domain=.google.com; Path=/; Secure"})
	stored := accountByID(id)
	if stored == nil || stored.Cookie != newer || !strings.Contains(local, "SIDCC=intermediate") {
		t.Fatal("concurrent account update was overwritten")
	}
}

func TestSessionPageUpdatesSurvivePrecheckAndApplyToStaleSnapshots(t *testing.T) {
	original := "SAPISID=precheck-identity; __Secure-1PSID=precheck-identity; SIDCC=old"
	oldFetch := fetchSessionPageTokens
	t.Cleanup(func() { fetchSessionPageTokens = oldFetch; invalidateXSRF(original) })
	fetches := 0
	fetchSessionPageTokens = func(context.Context, string, int, string) (xsrfEntry, []string, error) {
		fetches++
		return xsrfEntry{token: "test-token", fetched: time.Now()}, []string{"SIDCC=fresh; Domain=.google.com; Path=/; Secure"}, nil
	}
	if token, err := getXSRFWithContext(context.Background(), original, 0, ""); err != nil || token != "test-token" {
		t.Fatal("session precheck did not obtain a token")
	}
	token, updates, err := getXSRFSessionWithContext(context.Background(), original, 0, "")
	if err != nil || token != "test-token" || len(updates) != 1 || fetches != 1 {
		t.Fatalf("precheck lost updates: fetches=%d updates=%d err=%v", fetches, len(updates), err)
	}
	_, updates, err = getXSRFSessionWithContext(context.Background(), original, 0, "")
	if err != nil || len(updates) != 1 || fetches != 1 {
		t.Fatal("a stale snapshot did not receive cached updates")
	}
}

// Two requests may have already read the old account cookie even if the
// second reaches the cache just after the first page fetch completes.
func TestCachedSessionUpdatesReachEachStaleAccountSnapshot(t *testing.T) {
	cookie := "SAPISID=late-snapshot; __Secure-1PSID=late-snapshot; SIDCC=old"
	oldFetch := fetchSessionPageTokens
	t.Cleanup(func() { fetchSessionPageTokens = oldFetch; invalidateXSRF(cookie) })
	count := 0
	fetchSessionPageTokens = func(context.Context, string, int, string) (xsrfEntry, []string, error) {
		count++
		return xsrfEntry{token: "test-token", fetched: time.Now()}, []string{"SIDCC=fresh; Domain=.google.com; Path=/; Secure"}, nil
	}
	id, err := accountAdd("local-stale-snapshot", cookie, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = accountDelete(id) })
	tok1, updates1, err1 := getXSRFSessionWithContext(context.Background(), cookie, 0, "")
	tok2, updates2, err2 := getXSRFSessionWithContext(context.Background(), cookie, 0, "")
	if err1 != nil || err2 != nil || count != 1 || len(updates1) != 1 || len(updates2) != 1 {
		t.Fatalf("stale snapshots did not both receive updates: fetches=%d first=%d second=%d", count, len(updates1), len(updates2))
	}
	merged1 := applyAppPageAccountCookies(id, cookie, 0, tok1, "", updates1)
	merged2 := applyAppPageAccountCookies(id, cookie, 0, tok2, "", updates2)
	if cookieValue(merged1, "SIDCC") != "fresh" || cookieValue(merged2, "SIDCC") != "fresh" {
		t.Fatal("stale snapshots were not reconciled")
	}
	t.Cleanup(func() { invalidateXSRF(merged1) })
	_, newUpdates, err := getXSRFSessionWithContext(context.Background(), merged1, 0, "")
	if err != nil || len(newUpdates) != 0 || count != 1 {
		t.Fatal("updates replayed after the cookie was refreshed")
	}
}

func TestConcurrentGenerationUsesUpdatedSessionCookies(t *testing.T) {
	cookie := "SAPISID=generation-snapshot; __Secure-1PSID=generation-snapshot; SIDCC=old"
	oldPage, oldFetch, oldSend, oldRuntime := fetchSessionPageTokens, fetchAccountXSRF, sendWebChannelRequest, rtCfg()
	t.Cleanup(func() {
		fetchSessionPageTokens, fetchAccountXSRF, sendWebChannelRequest = oldPage, oldFetch, oldSend
		invalidateXSRF(cookie)
		rtMu.Lock()
		rtVal = oldRuntime
		rtMu.Unlock()
	})
	rtMu.Lock()
	rtVal = RuntimeConfig{RetryAttempts: 1, RequestTimeout: 5, WebChannelBinary: true, GeminiBL: defaultConfig().GeminiBL}
	rtMu.Unlock()
	id, err := accountAdd("local-concurrent-generation", cookie, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = accountDelete(id) })
	var fetches atomic.Int32
	fetchSessionPageTokens = func(context.Context, string, int, string) (xsrfEntry, []string, error) {
		fetches.Add(1)
		return xsrfEntry{token: "test-token", fetched: time.Now()}, []string{"SIDCC=fresh; Domain=.google.com; Path=/; Secure"}, nil
	}
	firstRead, release := make(chan struct{}), make(chan struct{})
	var accesses atomic.Int32
	fetchAccountXSRF = func(ctx context.Context, snapshot string, user int, proxy string) (string, []string, error) {
		token, updates, err := getXSRFSessionWithContext(ctx, snapshot, user, proxy)
		if accesses.Add(1) == 1 {
			close(firstRead)
			<-release
		} else {
			close(release)
		}
		return token, updates, err
	}
	sent := make(chan string, 2)
	sendWebChannelRequest = func(ctx context.Context, req wcRequest, proxy string, onLine func(string) error) (int, []byte, int64, []string, error) {
		sent <- cookieValue(req.Cookie, "SIDCC")
		return 0, nil, 0, nil, errors.New("local test stops before network")
	}
	model := Models["gemini-4-argon"]
	model.PinAccountID = id
	done := make(chan struct{}, 2)
	go func() { _, _ = streamGenerateOnce("first", "first", model, nil, nil, nil, nil); done <- struct{}{} }()
	<-firstRead
	go func() { _, _ = streamGenerateOnce("second", "second", model, nil, nil, nil, nil); done <- struct{}{} }()
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("concurrent request did not finish")
		}
	}
	for i := 0; i < 2; i++ {
		if <-sent != "fresh" {
			t.Fatal("generation sent stale session cookies")
		}
	}
	if fetches.Load() != 1 {
		t.Fatalf("page fetches = %d, want 1", fetches.Load())
	}
	if stored := accountByID(id); stored != nil {
		t.Cleanup(func() { invalidateXSRF(stored.Cookie) })
	}
}

func TestBinaryGenerationUsesCurrentSessionServerToken(t *testing.T) {
	oldFetch, oldSend, oldRuntime := fetchSessionPageTokens, sendWebChannelRequest, rtCfg()
	cookie := "SAPISID=local-server-token; __Secure-1PSID=local-server-token"
	t.Cleanup(func() {
		fetchSessionPageTokens, sendWebChannelRequest = oldFetch, oldSend
		invalidateXSRF(cookie)
		rtMu.Lock()
		rtVal = oldRuntime
		rtMu.Unlock()
	})
	if got := extractSessionServerToken([]byte(`{"PI9WOb":"local\\u002dtoken"}`)); got != `local\u002dtoken` {
		t.Fatal("escaped session token parsed incorrectly")
	}
	if got := extractSessionServerToken([]byte(`{"PI9WOb":"local\u002dtoken"}`)); got != "local-token" {
		t.Fatal("unicode-escaped session token parsed incorrectly")
	}
	if got := extractSessionServerToken([]byte(`{"PI9WOb":"evil\nheader"}`)); got != "" {
		t.Fatal("unsafe server token accepted")
	}
	fetchSessionPageTokens = func(context.Context, string, int, string) (xsrfEntry, []string, error) {
		return xsrfEntry{token: "local-xsrf", serverToken: "local-session-token", fetched: time.Now()}, nil, nil
	}
	rtMu.Lock()
	rtVal = RuntimeConfig{RetryAttempts: 1, RequestTimeout: 5, WebChannelBinary: true, GeminiBL: defaultConfig().GeminiBL}
	rtMu.Unlock()
	id, err := accountAdd("local-server-token", cookie, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = accountDelete(id) })
	var received string
	sendWebChannelRequest = func(ctx context.Context, req wcRequest, proxy string, onLine func(string) error) (int, []byte, int64, []string, error) {
		received = req.ServerToken
		return 0, nil, 0, nil, errors.New("local test stops before network")
	}
	model := Models["gemini-4-argon"]
	model.PinAccountID = id
	_, _ = streamGenerateOnce("test", "test", model, nil, nil, nil, nil)
	if received != "local-session-token" {
		t.Fatal("current session token not passed into binary request")
	}
	if cachedSessionServerToken(cookie, 0, "another-xsrf", "") != "" || cachedSessionServerToken(cookie, 1, "local-xsrf", "") != "" {
		t.Fatal("token reused for a different session")
	}
}

// Several concurrent requests for the same session should share one page
// fetch, and each already-waiting generation needs its cookie updates.
func TestConcurrentSessionFetchesSharePageAndUpdates(t *testing.T) {
	original := "SAPISID=concurrent-identity; __Secure-1PSID=concurrent-identity; SIDCC=old"
	oldFetch := fetchSessionPageTokens
	t.Cleanup(func() { fetchSessionPageTokens = oldFetch; invalidateXSRF(original) })
	var fetches atomic.Int32
	fetchSessionPageTokens = func(ctx context.Context, cookie string, authuser int, proxy string) (xsrfEntry, []string, error) {
		fetches.Add(1)
		select {
		case <-time.After(200 * time.Millisecond):
		case <-ctx.Done():
			return xsrfEntry{}, nil, ctx.Err()
		}
		return xsrfEntry{token: "test-token", fetched: time.Now()}, []string{"SIDCC=fresh; Domain=.google.com; Path=/; Secure"}, nil
	}
	const count = 5
	start := make(chan struct{})
	results := make(chan error, count)
	var ready sync.WaitGroup
	ready.Add(count)
	for i := 0; i < count; i++ {
		go func() {
			ready.Done()
			<-start
			token, updates, err := getXSRFSessionWithContext(context.Background(), original, 0, "")
			if err != nil || token != "test-token" || len(updates) != 1 {
				results <- errors.New("missing token or cookie updates")
				return
			}
			results <- nil
		}()
	}
	ready.Wait()
	close(start)
	for i := 0; i < count; i++ {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("concurrent callers fetched the same session page %d times", got)
	}
}

// One account can move between direct and proxy connections. Data fetched for
// one egress must never be served from cache to a different egress.
func TestSessionPageCacheSeparatesProxyRoutes(t *testing.T) {
	cookie := "SAPISID=route-test; __Secure-1PSID=route-test"
	oldFetch := fetchSessionPageTokens
	t.Cleanup(func() { fetchSessionPageTokens = oldFetch; invalidateXSRF(cookie) })
	var fetches atomic.Int32
	fetchSessionPageTokens = func(ctx context.Context, cookie string, user int, proxy string) (xsrfEntry, []string, error) {
		fetches.Add(1)
		return xsrfEntry{token: "xsrf:" + proxy, serverToken: "server:" + proxy, fetched: time.Now()}, nil, nil
	}
	for _, proxy := range []string{"", "http://proxy-a.invalid:1234", "http://proxy-b.invalid:1234"} {
		for i := 0; i < 2; i++ {
			token, _, err := getXSRFSessionWithContext(context.Background(), cookie, 0, proxy)
			if err != nil || token != "xsrf:"+proxy {
				t.Fatal("session token came from another route")
			}
		}
		if cachedSessionServerToken(cookie, 0, "xsrf:"+proxy, proxy) != "server:"+proxy {
			t.Fatal("server token came from another route")
		}
	}
	if cachedSessionServerToken(cookie, 0, "xsrf:http://proxy-a.invalid:1234", "http://proxy-b.invalid:1234") != "" {
		t.Fatal("server token crossed proxy routes")
	}
	if got := fetches.Load(); got != 3 {
		t.Fatalf("page fetches = %d, want one per route", got)
	}
	invalidateXSRF(cookie)
	_, _, err := getXSRFSessionWithContext(context.Background(), cookie, 0, "http://proxy-a.invalid:1234")
	if err != nil || fetches.Load() != 4 {
		t.Fatal("invalidation did not clear proxy-specific cache")
	}
}

func TestInvalidationDiscardsAllProxyRouteFlights(t *testing.T) {
	cookie := "SAPISID=route-invalidation; __Secure-1PSID=route-invalidation"
	oldFetch := fetchSessionPageTokens
	t.Cleanup(func() { fetchSessionPageTokens = oldFetch; invalidateXSRF(cookie) })
	started, release := make(chan struct{}, 2), make(chan struct{})
	var calls atomic.Int32
	fetchSessionPageTokens = func(ctx context.Context, cookie string, user int, proxy string) (xsrfEntry, []string, error) {
		if calls.Add(1) <= 2 {
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
				return xsrfEntry{}, nil, ctx.Err()
			}
			return xsrfEntry{token: "stale", fetched: time.Now()}, nil, nil
		}
		return xsrfEntry{token: "fresh", fetched: time.Now()}, nil, nil
	}
	results := make(chan error, 2)
	for _, proxy := range []string{"http://proxy-a.invalid:1234", "http://proxy-b.invalid:1234"} {
		go func(proxy string) {
			token, _, err := getXSRFSessionWithContext(context.Background(), cookie, 0, proxy)
			if err == nil && token != "fresh" {
				err = errors.New("invalidated route token survived")
			}
			results <- err
		}(proxy)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("route fetch did not start")
		}
	}
	invalidateXSRF(cookie)
	close(release)
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if got := calls.Load(); got != 4 {
		t.Fatalf("fetches = %d, want two old and two fresh", got)
	}
}

func TestRefreshedCookieCacheKeepsRouteIsolation(t *testing.T) {
	cookie := "SAPISID=route-rekey; __Secure-1PSID=route-rekey; SIDCC=old"
	proxyA, proxyB := "http://proxy-a.invalid:1234", "http://proxy-b.invalid:1234"
	oldFetch := fetchSessionPageTokens
	t.Cleanup(func() { fetchSessionPageTokens = oldFetch; invalidateXSRF(cookie) })
	var calls atomic.Int32
	fetchSessionPageTokens = func(ctx context.Context, cookie string, user int, proxy string) (xsrfEntry, []string, error) {
		calls.Add(1)
		return xsrfEntry{token: "xsrf:" + proxy, serverToken: "server:" + proxy, fetched: time.Now()}, []string{"SIDCC=fresh; Domain=.google.com; Path=/; Secure"}, nil
	}
	id, err := accountAdd("local-route-rekey", cookie, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = accountDelete(id) })
	tokenA, updates, err := getXSRFSessionWithContext(context.Background(), cookie, 0, proxyA)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := getXSRFSessionWithContext(context.Background(), cookie, 0, proxyB); err != nil {
		t.Fatal(err)
	}
	merged := applyAppPageAccountCookies(id, cookie, 0, tokenA, proxyA, updates)
	t.Cleanup(func() { invalidateXSRF(merged) })
	if cachedSessionServerToken(merged, 0, tokenA, proxyA) != "server:"+proxyA {
		t.Fatal("updated route lost its session token")
	}
	if cachedSessionServerToken(merged, 0, tokenA, proxyB) != "" {
		t.Fatal("updated session token crossed routes")
	}
	if _, _, err := getXSRFSessionWithContext(context.Background(), merged, 0, proxyB); err != nil || calls.Load() != 3 {
		t.Fatal("other route did not fetch its own session page")
	}
}

func TestUploadAndGenerationShareSessionFetch(t *testing.T) {
	for _, uploadFirst := range []bool{false, true} {
		name := "generation-first"
		if uploadFirst {
			name = "upload-first"
		}
		t.Run(name, func(t *testing.T) {
			cookie := "SAPISID=upload-test-" + name + "; __Secure-1PSID=upload-test"
			oldFetch := fetchSessionPageTokens
			t.Cleanup(func() { fetchSessionPageTokens = oldFetch; invalidateXSRF(cookie) })
			started, release := make(chan struct{}), make(chan struct{})
			var fetches atomic.Int32
			fetchSessionPageTokens = func(ctx context.Context, cookie string, user int, proxy string) (xsrfEntry, []string, error) {
				if fetches.Add(1) == 1 {
					close(started)
				}
				select {
				case <-release:
				case <-ctx.Done():
					return xsrfEntry{}, nil, ctx.Err()
				}
				return xsrfEntry{token: "test-xsrf", pushID: "test-push", pctx: "test-context", fetched: time.Now()}, []string{"SIDCC=fresh; Domain=.google.com; Path=/; Secure"}, nil
			}
			upload := func() error {
				push, pctx, err := getUploadTokens(cookie, 0, "")
				if err != nil || push != "test-push" || pctx != "test-context" {
					return errors.New("upload did not receive page tokens")
				}
				return nil
			}
			generate := func() error {
				token, updates, err := getXSRFSessionWithContext(context.Background(), cookie, 0, "")
				if err != nil || token != "test-xsrf" || len(updates) != 1 {
					return errors.New("generation did not receive token and cookie update")
				}
				return nil
			}
			first, second := generate, upload
			if uploadFirst {
				first, second = upload, generate
			}
			results := make(chan error, 2)
			go func() { results <- first() }()
			<-started
			go func() { results <- second() }()
			time.Sleep(50 * time.Millisecond)
			close(release)
			for i := 0; i < 2; i++ {
				if err := <-results; err != nil {
					t.Error(err)
				}
			}
			if got := fetches.Load(); got != 1 {
				t.Fatalf("page fetches = %d, want 1", got)
			}
		})
	}
}

func TestSessionFetchLeaderCancellationDoesNotCancelWaiter(t *testing.T) {
	original := "SAPISID=cancel-leader; __Secure-1PSID=cancel-leader"
	oldFetch := fetchSessionPageTokens
	t.Cleanup(func() { fetchSessionPageTokens = oldFetch; invalidateXSRF(original) })
	firstStarted := make(chan struct{})
	var fetches atomic.Int32
	fetchSessionPageTokens = func(ctx context.Context, cookie string, authuser int, proxy string) (xsrfEntry, []string, error) {
		if fetches.Add(1) == 1 {
			close(firstStarted)
			<-ctx.Done()
			return xsrfEntry{}, nil, ctx.Err()
		}
		return xsrfEntry{token: "new-token", fetched: time.Now()}, nil, nil
	}
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	defer cancelLeader()
	leaderResult := make(chan error, 1)
	go func() { _, _, err := getXSRFSessionWithContext(leaderCtx, original, 0, ""); leaderResult <- err }()
	<-firstStarted
	waiterResult := make(chan error, 1)
	go func() {
		token, _, err := getXSRFSessionWithContext(context.Background(), original, 0, "")
		if err == nil && token != "new-token" {
			err = errors.New("waiter received an incorrect token")
		}
		waiterResult <- err
	}()
	time.Sleep(50 * time.Millisecond)
	cancelLeader()
	if err := <-leaderResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader error = %v", err)
	}
	if err := <-waiterResult; err != nil {
		t.Fatalf("waiter unexpectedly failed: %v", err)
	}
	if fetches.Load() != 2 {
		t.Fatalf("fetches = %d, want 2", fetches.Load())
	}
}

func TestInvalidatingInFlightSessionFetchDiscardsItsResult(t *testing.T) {
	original := "SAPISID=invalidate-flight; __Secure-1PSID=invalidate-flight"
	oldFetch := fetchSessionPageTokens
	t.Cleanup(func() { fetchSessionPageTokens = oldFetch; invalidateXSRF(original) })
	firstStarted, release := make(chan struct{}), make(chan struct{})
	var fetches atomic.Int32
	fetchSessionPageTokens = func(ctx context.Context, cookie string, authuser int, proxy string) (xsrfEntry, []string, error) {
		if fetches.Add(1) == 1 {
			close(firstStarted)
			<-release
			return xsrfEntry{token: "old-token", fetched: time.Now()}, []string{"SIDCC=old; Domain=.google.com; Path=/; Secure"}, nil
		}
		return xsrfEntry{token: "new-token", fetched: time.Now()}, []string{"SIDCC=new; Domain=.google.com; Path=/; Secure"}, nil
	}
	result := make(chan error, 1)
	go func() {
		token, updates, err := getXSRFSessionWithContext(context.Background(), original, 0, "")
		if err == nil && (token != "new-token" || len(updates) != 1 || !strings.Contains(updates[0], "SIDCC=new")) {
			err = errors.New("invalidated token or cookies were reused")
		}
		result <- err
	}()
	<-firstStarted
	invalidateXSRF(original)
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if fetches.Load() != 2 {
		t.Fatalf("fetches = %d, want 2", fetches.Load())
	}
}
