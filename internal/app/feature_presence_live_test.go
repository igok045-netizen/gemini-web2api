package app

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
)

// Report only whether the public client feature switch occurs and whether its
// value is true or false. Never print page bytes, cookies, or session tokens.
func TestLiveAttestationFeaturePresence(t *testing.T) {
	path := os.Getenv("GEMINI_DIAGNOSTIC_DB")
	if path == "" || os.Getenv("GEMINI_DIAGNOSTIC_FEATURES") != "1" {
		t.Skip("opt-in live diagnostic")
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal("source database unavailable")
	}
	defer db.Close()
	var cookie string
	var user int
	if err := db.QueryRow("SELECT cookie, authuser FROM accounts WHERE status = 'enabled' ORDER BY id LIMIT 1").Scan(&cookie, &user); err != nil {
		t.Fatal("no enabled account")
	}
	if path := os.Getenv("GEMINI_DIAGNOSTIC_FIREFOX_DB"); path != "" {
		cookie, err = diagnosticFirefoxCookies(cookie, path)
		if err != nil {
			t.Fatal("browser session unavailable")
		}
	}
	parsed, parseErr := http.ParseCookie(cookie)
	t.Logf("cookie header: parseable=%t entries=%d", parseErr == nil, len(parsed))
	page, err := fetchAppPage(cookie, user, "")
	if err != nil {
		t.Fatal("session page unavailable")
	}
	for _, id := range []string{"45428920", "45714150"} {
		pattern := regexp.MustCompile(id + `.{0,8}:\s*(true|false)`)
		matches := pattern.FindAllSubmatch(page, -1)
		var yes, no int
		for _, match := range matches {
			if string(match[1]) == "true" {
				yes++
			} else {
				no++
			}
		}
		t.Logf("feature %s: true=%d false=%d", id, yes, no)
	}
}

// Check the browser's optional direct SSE transport without logging the page,
// account data, the API key, or other configuration values.
func TestLiveSSEFeaturePresence(t *testing.T) {
	path := os.Getenv("GEMINI_DIAGNOSTIC_DB")
	if path == "" || os.Getenv("GEMINI_DIAGNOSTIC_SSE_FEATURE") != "1" {
		t.Skip("opt-in SSE feature diagnostic")
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal("source database unavailable")
	}
	defer db.Close()
	var cookie string
	var user int
	if err := db.QueryRow("SELECT cookie, authuser FROM accounts WHERE status = 'enabled' ORDER BY id LIMIT 1").Scan(&cookie, &user); err != nil {
		t.Fatal("no enabled account")
	}
	if path := os.Getenv("GEMINI_DIAGNOSTIC_FIREFOX_DB"); path != "" {
		cookie, err = diagnosticFirefoxCookies(cookie, path)
		if err != nil {
			t.Fatal("browser session unavailable")
		}
	}
	page, err := fetchAppPage(cookie, user, "")
	if err != nil {
		t.Fatal("session page unavailable")
	}
	flagMatches := regexp.MustCompile(`45806759.{0,8}:\s*(true|false)`).FindAllSubmatch(page, -1)
	var yes, no int
	for _, match := range flagMatches {
		if string(match[1]) == "true" {
			yes++
		} else {
			no++
		}
	}
	t.Logf("SSE feature flag: true=%d false=%d", yes, no)
	value := regexp.MustCompile(`"GK6dn"\s*:\s*("(?:\\.|[^"\\])*")`).FindSubmatch(page)
	if len(value) < 2 {
		t.Log("SSE base address: not present")
		return
	}
	var raw string
	if err := json.Unmarshal(value[1], &raw); err != nil {
		t.Fatal("invalid SSE base address encoding")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		!(u.Hostname() == "google.com" || strings.HasSuffix(u.Hostname(), ".google.com") || u.Hostname() == "googleapis.com" || strings.HasSuffix(u.Hostname(), ".googleapis.com")) {
		t.Fatal("SSE base address is outside the expected Google domain")
	}
	t.Logf("SSE base domain: %s; has non-root path=%t", u.Hostname(), u.Path != "" && u.Path != "/")
}
