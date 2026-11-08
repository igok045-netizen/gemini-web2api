package app

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
)

// Count cookie update categories without logging names, values or page bytes.
func TestLiveAppCookieUpdateCategories(t *testing.T) {
	path := os.Getenv("GEMINI_DIAGNOSTIC_DB")
	if path == "" || os.Getenv("GEMINI_DIAGNOSTIC_APP_COOKIES") != "1" {
		t.Skip("opt-in app cookie diagnostic")
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal("source database unavailable")
	}
	defer db.Close()
	var cookie string
	var authuser int
	if err := db.QueryRow("SELECT cookie, authuser FROM accounts WHERE status='enabled' ORDER BY id LIMIT 1").Scan(&cookie, &authuser); err != nil {
		t.Fatal("no enabled account")
	}
	if firefox := os.Getenv("GEMINI_DIAGNOSTIC_FIREFOX_DB"); firefox != "" {
		cookie, err = diagnosticFullFirefoxCookies(cookie, firefox)
		if err != nil {
			t.Fatal("browser session unavailable")
		}
	}
	original, err := http.ParseCookie(cookie)
	if err != nil {
		t.Fatal("cannot parse session cookies")
	}
	before := map[string]string{}
	for _, c := range original {
		before[c.Name] = c.Value
	}
	oldRuntime := rtCfg()
	t.Cleanup(func() { rtMu.Lock(); rtVal = oldRuntime; rtMu.Unlock() })
	rtMu.Lock()
	rtVal = RuntimeConfig{Impersonate: "chrome_146", RequestTimeout: 20}
	rtMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := fhttp.NewRequestWithContext(ctx, "GET", geminiBase(authuser)+"/app", nil)
	if err != nil {
		t.Fatal("cannot create session page request")
	}
	applyBrowserHeaderValues(req.Header, "same-origin")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Cookie", cookie)
	resp, err := getTLSClient().Do(req)
	if err != nil {
		t.Fatal("session page request failed")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<20))
	var total, sharedRoot, hostOnly, changed, expired, identityChanged int
	for _, raw := range resp.Header.Values("Set-Cookie") {
		c, err := http.ParseSetCookie(raw)
		if err != nil {
			continue
		}
		total++
		if c.Domain == "" {
			hostOnly++
		}
		if strings.EqualFold(strings.TrimPrefix(c.Domain, "."), "google.com") && c.Path == "/" {
			sharedRoot++
		}
		if prior, found := before[c.Name]; found && prior != c.Value {
			changed++
		}
		if c.MaxAge < 0 || (!c.Expires.IsZero() && !c.Expires.After(time.Now())) {
			expired++
		}
		if (c.Name == "SAPISID" || c.Name == "__Secure-1PSID") && before[c.Name] != "" && before[c.Name] != c.Value {
			identityChanged++
		}
	}
	t.Logf("app status=%d parsed_set_cookie=%d shared_google_root=%d host_only=%d changed_existing=%d expired=%d identity_changed=%d", resp.StatusCode, total, sharedRoot, hostOnly, changed, expired, identityChanged)
	if resp.StatusCode != 200 {
		t.Fatal("session page did not return HTTP 200")
	}
}
