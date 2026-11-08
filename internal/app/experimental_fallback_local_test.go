package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExperimentalLegacyFallbackSelection(t *testing.T) {
	t.Setenv("GEMINI_EXPERIMENTAL_LEGACY_FALLBACK", "1")
	for _, tc := range []struct {
		name            string
		binary, browser bool
		pending, tool   int
		continuation    bool
		length, budget  int
		want            bool
	}{
		{"text stays binary", true, true, 0, 0, false, 100, 600, false},
		{"image", true, true, 1, 0, false, 100, 600, true},
		{"media", true, true, 0, 1, false, 100, 600, true},
		{"continuation", true, true, 0, 0, true, 100, 600, true},
		{"long context", true, true, 0, 0, false, 601, 600, true},
		{"unlimited context", true, true, 0, 0, false, 601, 0, false},
		{"without browser mode", true, false, 1, 0, false, 100, 600, false},
		{"binary disabled", false, true, 1, 0, false, 100, 600, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := useExperimentalLegacyFallback(tc.binary, tc.browser, tc.pending, true, tc.tool, tc.continuation, tc.length, tc.budget); got != tc.want {
				t.Fatalf("fallback=%t, want %t", got, tc.want)
			}
		})
	}
	t.Setenv("GEMINI_EXPERIMENTAL_LEGACY_FALLBACK", "0")
	if useExperimentalLegacyFallback(true, true, 1, true, 0, false, 100, 600) {
		t.Fatal("fallback was enabled without opt-in")
	}
	t.Setenv("GEMINI_EXPERIMENTAL_LEGACY_FALLBACK", "images")
	if !useExperimentalLegacyFallback(true, true, 1, true, 0, false, 100, 600) ||
		useExperimentalLegacyFallback(true, true, 1, false, 0, false, 100, 600) ||
		useExperimentalLegacyFallback(true, true, 0, true, 0, false, 800, 600) ||
		useExperimentalLegacyFallback(true, true, 1, true, 1, false, 100, 600) ||
		useExperimentalLegacyFallback(true, true, 1, true, 0, false, 800, 600) {
		t.Fatal("image-only route accepted unsupported inputs or rejected an image")
	}
}

// This exercises real request assembly and transport selection with local
// synthetic cookies and a fake upload. No request leaves the machine.
func TestExperimentalLegacyFallbackPreservesAttachments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cookies.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TABLE moz_cookies (name TEXT, value TEXT, host TEXT, path TEXT, originAttributes TEXT, expiry INTEGER)`); err != nil {
		t.Fatal(err)
	}
	for _, item := range [][2]string{{"SAPISID", "anchor-a"}, {"__Secure-1PSID", "anchor-b"}, {"SIDCC", "fresh"}} {
		if _, err = db.Exec(`INSERT INTO moz_cookies VALUES (?, ?, '.google.com', '/', '', ?)`, item[0], item[1], time.Now().Add(time.Hour).Unix()); err != nil {
			t.Fatal(err)
		}
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GEMINI_WEBCHANNEL_FIREFOX_COOKIES_DB", path)
	t.Setenv("GEMINI_EXPERIMENTAL_LEGACY_FALLBACK", "1")
	t.Setenv("GEMINI_EXPERIMENTAL_BROWSER_LOCALE", "ru")
	oldFetch, oldUpload, oldLegacy, oldWC, oldRuntime := fetchAccountXSRF, uploadGenerationAttachment, sendGeminiRequest, sendWebChannelRequest, rtCfg()
	t.Cleanup(func() {
		fetchAccountXSRF, uploadGenerationAttachment, sendGeminiRequest, sendWebChannelRequest = oldFetch, oldUpload, oldLegacy, oldWC
		rtMu.Lock()
		rtVal = oldRuntime
		rtMu.Unlock()
	})
	rtMu.Lock()
	rtVal = RuntimeConfig{RetryAttempts: 1, RequestTimeout: 5, WebChannelBinary: true, WebChannel: true, MaxPromptBytes: 600, GeminiBL: defaultConfig().GeminiBL}
	rtMu.Unlock()
	id, err := accountAdd("legacy-fallback-test", "SAPISID=anchor-a; __Secure-1PSID=anchor-b; SIDCC=stale", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = accountDelete(id) })
	var fetchedCookie string
	fetchAccountXSRF = func(_ context.Context, cookie string, _ int, _ string) (string, []string, error) {
		fetchedCookie = cookie
		return "test-token", nil, nil
	}
	var uploads, legacyCalls, binaryCalls int
	var uploadedName, uploadedData, requestBody string
	uploadGenerationAttachment = func(_ context.Context, cookie string, _ int, _ string, data []byte, name string) (string, error) {
		if !strings.Contains(cookie, "SIDCC=fresh") {
			return "", errors.New("wrong session")
		}
		uploads++
		uploadedName, uploadedData = name, string(data)
		return "/contrib_service/test-ref", nil
	}
	inner := make([]interface{}, 43)
	inner[4] = []interface{}{[]interface{}{"candidate", []interface{}{"OK"}}}
	encoded, _ := json.Marshal(inner)
	line, _ := json.Marshal([]interface{}{[]interface{}{"wrb.fr", nil, string(encoded)}})
	sendGeminiRequest = func(_ context.Context, _, body string, _ map[string]string, _ string, _ func(string) error) (int, []byte, int64, []string, error) {
		legacyCalls++
		requestBody = body
		return 200, line, 1, nil, nil
	}
	sendWebChannelRequest = func(_ context.Context, _ wcRequest, _ string, _ func(string) error) (int, []byte, int64, []string, error) {
		binaryCalls++
		return 200, line, 1, nil, nil
	}
	model := Models["gemini-4-argon"]
	model.PinAccountID = id
	for _, tc := range []struct {
		name, prompt           string
		pending                []pendingUpload
		wantUpload, wantLegacy bool
		wantName, wantData     string
	}{
		{"ordinary text", "hello", nil, false, false, "", ""},
		{"image", "describe", []pendingUpload{{Name: "picture.png", Mime: "image/png", Kind: 1, Data: []byte("synthetic-image")}}, true, true, "picture.png", "synthetic-image"},
		{"long context", strings.Repeat("x", 800), nil, true, true, contextFileName, strings.Repeat("x", 800)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uploads, legacyCalls, binaryCalls = 0, 0, 0
			uploadedName, uploadedData, requestBody, fetchedCookie = "", "", "", ""
			res, err := streamGenerateOnce(tc.prompt, "latest question", model, tc.pending, nil, nil, nil)
			if err != nil || res == nil {
				t.Fatalf("generation failed: %v", err)
			}
			if (uploads == 1) != tc.wantUpload || (legacyCalls == 1) != tc.wantLegacy || (binaryCalls == 1) == tc.wantLegacy {
				t.Fatal("unexpected transport or upload count")
			}
			if !strings.Contains(fetchedCookie, "SIDCC=fresh") {
				t.Fatal("Firefox session not used")
			}
			if tc.wantUpload {
				if uploadedName != tc.wantName || uploadedData != tc.wantData {
					t.Fatal("attachment content changed")
				}
				form, err := url.ParseQuery(requestBody)
				if err != nil || !strings.Contains(form.Get("f.req"), "/contrib_service/test-ref") {
					t.Fatal("uploaded attachment reference missing from request")
				}
			}
		})
	}
}
