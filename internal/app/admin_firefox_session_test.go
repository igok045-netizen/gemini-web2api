package app

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAdminChecksCurrentFirefoxSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cookies.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TABLE moz_cookies (name TEXT, value TEXT, host TEXT, path TEXT, originAttributes TEXT, expiry INTEGER)`); err != nil {
		t.Fatal(err)
	}
	for _, v := range [][2]string{{"SAPISID", "test-anchor-a"}, {"__Secure-1PSID", "test-anchor-b"}, {"SIDCC", "fresh-test"}} {
		if _, err = db.Exec(`INSERT INTO moz_cookies VALUES (?, ?, '.google.com', '/', '', ?)`, v[0], v[1], time.Now().Add(time.Hour).Unix()); err != nil {
			t.Fatal(err)
		}
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GEMINI_WEBCHANNEL_FIREFOX_COOKIES_DB", path)
	old, oldFetch := rtCfg(), fetchAccountXSRF
	t.Cleanup(func() { fetchAccountXSRF = oldFetch; rtMu.Lock(); rtVal = old; rtMu.Unlock() })
	rtMu.Lock()
	rtVal.WebChannelBinary = true
	rtMu.Unlock()
	const original = "SAPISID=test-anchor-a; __Secure-1PSID=test-anchor-b; SIDCC=old-test"
	id, err := accountAdd("firefox-admin-test", original, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = accountDelete(id) })
	fetches := 0
	fetchAccountXSRF = func(_ context.Context, cookie string, _ int, _ string) (string, []string, error) {
		fetches++
		if !strings.Contains(cookie, "SIDCC=fresh-test") {
			t.Error("admin checked the stored cookie instead of Firefox")
		}
		return "test-token", []string{"SIDCC=updated-test; Domain=.google.com; Path=/; Secure"}, nil
	}
	result := checkAccountCookie(*accountByID(id))
	if !result.OK || fetches != 1 || accountByID(id).Cookie != original {
		t.Fatal("Firefox check failed or modified stored cookies")
	}

	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE moz_cookies SET value='other-identity' WHERE name='__Secure-1PSID'`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	result = checkAccountCookie(*accountByID(id))
	if result.OK || fetches != 1 || accountByID(id).Cookie != original {
		t.Fatal("mismatched session was checked or stored")
	}

	recorder := httptest.NewRecorder()
	handleAdminCookieItem(recorder, httptest.NewRequest(http.MethodPost, fmt.Sprintf("/admin/api/cookies/%d/rotate", id), nil))
	if recorder.Code != http.StatusConflict || accountByID(id).Cookie != original {
		t.Fatal("manual rotation was not blocked in Firefox mode")
	}
}
