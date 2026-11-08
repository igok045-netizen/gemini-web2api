package app

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The initial scoped header comes from Firefox's domain-aware store. Later
// values in current that differ from baseline were added by the isolated
// server's shared-domain page response; do not reintroduce excluded cookies.
func diagnosticScopedCookieUpdates(scoped, baseline, current string) (string, error) {
	initial, err := http.ParseCookie(baseline)
	if err != nil {
		return "", errors.New("invalid diagnostic baseline cookie header")
	}
	latest, err := http.ParseCookie(current)
	if err != nil {
		return "", errors.New("invalid diagnostic current cookie header")
	}
	before := map[string]string{}
	for _, c := range initial {
		before[c.Name] = c.Value
	}
	var updates []string
	for _, c := range latest {
		if old, found := before[c.Name]; !found || old != c.Value {
			if c.Name == "SAPISID" || c.Name == "__Secure-1PSID" {
				return "", errors.New("diagnostic account identity changed")
			}
			updates = append(updates, c.String())
		}
	}
	return mergeSetCookie(scoped, updates), nil
}

func TestDiagnosticScopedCookieUpdates(t *testing.T) {
	baseline := "SAPISID=anchor; SIDCC=old; GEMINI_ONLY=private"
	scoped := "SAPISID=anchor; SIDCC=old; CHANNEL=allowed"
	current := "SAPISID=anchor; SIDCC=fresh; GEMINI_ONLY=private; NEW_SHARED=added"
	got, err := diagnosticScopedCookieUpdates(scoped, baseline, current)
	if err != nil || !strings.Contains(got, "SIDCC=fresh") || !strings.Contains(got, "CHANNEL=allowed") || !strings.Contains(got, "NEW_SHARED=added") || strings.Contains(got, "GEMINI_ONLY") {
		t.Fatal("scoped diagnostic lost updates or reintroduced excluded cookies")
	}
	if _, err := diagnosticScopedCookieUpdates(scoped, baseline, "SAPISID=another-account"); err == nil {
		t.Fatal("diagnostic accepted a different account identity")
	}
}

func TestDiagnosticWebChannelCookieScope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cookies.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE moz_cookies (name TEXT, value TEXT, host TEXT, path TEXT, originAttributes TEXT, expiry INTEGER)`)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name, value, host, path, attrs string
		expiry                         int64
	}{
		{"SAPISID", "anchor-a", ".google.com", "/", "", time.Now().Add(time.Hour).Unix()},
		{"__Secure-1PSID", "anchor-b", ".google.com", "/", "", time.Now().Add(time.Hour).Unix()},
		{"base", "include", ".google.com", "/", "", time.Now().Add(time.Hour).Unix()},
		{"channel", "include", ".clients6.google.com", "/", "", time.Now().Add(time.Hour).Unix()},
		{"gemini-only", "exclude", "gemini.google.com", "/", "", time.Now().Add(time.Hour).Unix()},
		{"expired", "exclude", ".google.com", "/", "", time.Now().Add(-time.Hour).Unix()},
		{"other-container", "exclude", ".google.com", "/", "^userContextId=1", time.Now().Add(time.Hour).Unix()},
	} {
		if _, err = db.Exec(`INSERT INTO moz_cookies VALUES (?, ?, ?, ?, ?, ?)`, row.name, row.value, row.host, row.path, row.attrs, row.expiry); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	header, err := diagnosticWebChannelCookies("SAPISID=anchor-a; __Secure-1PSID=anchor-b", path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(header, "base=include") || !strings.Contains(header, "channel=include") || strings.Contains(header, "exclude") {
		t.Fatal("unexpected cookie domain or expiry selection")
	}
	if _, err := diagnosticWebChannelCookies("SAPISID=other; __Secure-1PSID=anchor-b", path); err == nil {
		t.Fatal("different account was accepted")
	}
	productionHeader, err := firefoxChannelCookies("SAPISID=anchor-a; __Secure-1PSID=anchor-b", path)
	if err != nil || productionHeader != header {
		t.Fatal("production cookie selection differs from validated diagnostic selection")
	}
	if _, err := firefoxChannelCookies("SAPISID=other; __Secure-1PSID=anchor-b", path); err == nil {
		t.Fatal("production cookie selection accepted a different account")
	}
	if _, err := firefoxChannelCookies("SAPISID=other; SAPISID=anchor-a; __Secure-1PSID=anchor-b", path); err == nil {
		t.Fatal("conflicting duplicate account identities were accepted")
	}
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal("cannot reopen synthetic cookie database")
	}
	for _, host := range []string{"gemini.google.com", ".clients6.google.com"} {
		if _, err := db.Exec(`INSERT INTO moz_cookies VALUES (?, ?, ?, '/', '', ?)`, "SAPISID", "different", host, time.Now().Add(time.Hour).Unix()); err != nil {
			t.Fatal("cannot create conflicting synthetic cookie")
		}
		if _, err := firefoxChannelCookies("SAPISID=anchor-a; __Secure-1PSID=anchor-b", path); err == nil {
			t.Fatal("conflicting browser identities were accepted")
		}
		if _, err := db.Exec(`DELETE FROM moz_cookies WHERE name=? AND host=?`, "SAPISID", host); err != nil {
			t.Fatal("cannot reset synthetic cookie database")
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal("cannot close synthetic cookie database")
	}
	if _, err := firefoxChannelCookies("SAPISID=anchor-a; __Secure-1PSID=anchor-b", path+"?mode=rw"); err == nil {
		t.Fatal("cookie database URI injection accepted")
	}

	// Exercise the production generation path, including updates from /app.
	t.Setenv("GEMINI_WEBCHANNEL_FIREFOX_COOKIES_DB", path)
	t.Setenv("GEMINI_EXPERIMENTAL_BROWSER_LOCALE", "ru")
	oldFetch, oldSend, oldRuntime := fetchAccountXSRF, sendWebChannelRequest, rtCfg()
	t.Cleanup(func() {
		fetchAccountXSRF, sendWebChannelRequest = oldFetch, oldSend
		rtMu.Lock()
		rtVal = oldRuntime
		rtMu.Unlock()
	})
	rtMu.Lock()
	rtVal = RuntimeConfig{RetryAttempts: 1, RequestTimeout: 10, WebChannelBinary: true, GeminiBL: defaultConfig().GeminiBL}
	rtMu.Unlock()
	original := "SAPISID=anchor-a; __Secure-1PSID=anchor-b; base=stale; gemini-only=obsolete"
	account, err := accountAdd("firefox-scope-test", original, "")
	if err != nil {
		t.Fatal("cannot create temporary account")
	}
	t.Cleanup(func() { _ = accountDelete(account) })
	var appHeaders []string
	fetchAccountXSRF = func(_ context.Context, cookie string, _ int, _ string) (string, []string, error) {
		appHeaders = append(appHeaders, cookie)
		if len(appHeaders) == 1 {
			return "token", []string{"SIDCC=fresh; Domain=.google.com; Path=/; Secure", "gemini-only=wrong; Domain=gemini.google.com; Path=/; Secure"}, nil
		}
		return "token", nil, nil
	}
	var sent []string
	var localeCorrect bool
	sendWebChannelRequest = func(_ context.Context, request wcRequest, _ string, _ func(string) error) (int, []byte, int64, []string, error) {
		sent = append(sent, request.Cookie)
		if len(request.Inner) > 1 {
			if locale, ok := request.Inner[1].([]interface{}); ok && len(locale) > 0 && locale[0] == "ru" {
				localeCorrect = true
			}
		}
		if len(sent) == 1 {
			return 0, nil, 0, []string{"SIDCC=newer; Domain=.google.com; Path=/; Secure"}, errors.New("local test stopped")
		}
		return 0, nil, 0, nil, errors.New("local test stopped")
	}
	_, _ = streamGenerateOnce("test", "test", Models["gemini-4-argon"], nil, nil, nil, nil)
	_, _ = streamGenerateOnce("test", "test", Models["gemini-4-argon"], nil, nil, nil, nil)
	if len(sent) != 2 || !strings.Contains(sent[0], "SIDCC=fresh") || !strings.Contains(sent[0], "channel=include") || strings.Contains(sent[0], "gemini-only") {
		t.Fatal("generation did not use scoped cookies and shared updates")
	}
	if !localeCorrect {
		t.Fatal("browser-sourced binary request did not use the configured locale")
	}
	if len(appHeaders) != 2 || !strings.Contains(appHeaders[0], "base=include") || !strings.Contains(appHeaders[0], "gemini-only=exclude") || strings.Contains(appHeaders[0], "channel=include") {
		t.Fatal("session page did not use fresh cookies for its own domain")
	}
	if !strings.Contains(appHeaders[1], "SIDCC=newer") || !strings.Contains(sent[1], "SIDCC=newer") {
		t.Fatal("shared WebChannel update was lost before the next request")
	}
	if current := accountByID(account); current == nil || current.Cookie != original {
		t.Fatal("browser-sourced request overwrote the stored account cookies")
	}
	var retryHeaders []string
	fetchAccountXSRF = func(_ context.Context, cookie string, _ int, _ string) (string, []string, error) {
		retryHeaders = append(retryHeaders, cookie)
		if len(retryHeaders) == 1 {
			return "", nil, errors.New("no SNlM0e in page")
		}
		return "token", nil, nil
	}
	_, _ = streamGenerateOnce("test", "test", Models["gemini-4-argon"], nil, nil, nil, nil)
	if len(retryHeaders) != 2 || !strings.Contains(retryHeaders[0], "SIDCC=newer") || strings.Contains(retryHeaders[1], "SIDCC=newer") {
		t.Fatal("a rejected overlay was not retried once using the untouched browser snapshot")
	}
	appSnapshot, channelSnapshot, err := firefoxCookieSnapshots(original, path)
	if err != nil {
		t.Fatal("cannot obtain synthetic browser snapshot")
	}
	key := firefoxOverlayKey(account, 0, "", appSnapshot, channelSnapshot)
	t.Cleanup(func() { firefoxOverlayClear(key) })
	firefoxOverlayUpdate(key, []string{"SIDCC=cached; Domain=.google.com; Path=/"})
	var challengeCalls int
	fetchAccountXSRF = func(context.Context, string, int, string) (string, []string, error) {
		challengeCalls++
		return "", nil, &appPageStatusError{Status: 302, Location: "www.google.com/sorry/index"}
	}
	_, _ = streamGenerateOnce("test", "test", Models["gemini-4-argon"], nil, nil, nil, nil)
	if challengeCalls != 1 {
		t.Fatal("a Google challenge was retried")
	}
}
