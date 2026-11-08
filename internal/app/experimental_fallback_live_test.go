package app

import (
	"bytes"
	"context"
	"database/sql"
	"image"
	"image/color"
	"image/png"
	"os"
	"strings"
	"testing"
	"time"
)

// One opt-in request with a synthetic image. No credentials or response text
// are logged; TestMain provides a separate temporary database.
func TestLiveExperimentalFallbackImage(t *testing.T) {
	path := os.Getenv("GEMINI_DIAGNOSTIC_DB")
	if path == "" || os.Getenv("GEMINI_DIAGNOSTIC_FALLBACK_IMAGE") != "1" {
		t.Skip("opt-in live attachment diagnostic")
	}
	if firefoxChannelCookiePath() == "" {
		t.Fatal("browser session is required")
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal("source database unavailable")
	}
	defer db.Close()
	var cookie string
	var authuser int
	if err = db.QueryRow("SELECT cookie, authuser FROM accounts WHERE status = 'enabled' ORDER BY id LIMIT 1").Scan(&cookie, &authuser); err != nil {
		t.Fatal("no enabled account found")
	}
	id, err := accountAdd("image-diagnostic", cookie, "")
	if err != nil {
		t.Fatal("temporary account unavailable")
	}
	defer accountDelete(id)
	if _, err = getDB().Exec("UPDATE accounts SET authuser=? WHERE id=?", authuser, id); err != nil {
		t.Fatal("temporary account configuration failed")
	}
	t.Setenv("GEMINI_EXPERIMENTAL_LEGACY_FALLBACK", "1")
	oldRuntime := rtCfg()
	defer func() { rtMu.Lock(); rtVal = oldRuntime; rtMu.Unlock() }()
	rtMu.Lock()
	rtVal = RuntimeConfig{RetryAttempts: 1, RequestTimeout: 150, WebChannelBinary: true, WebChannel: true, FirefoxFingerprint: true, StrictModel: true, MaxPromptBytes: 128000, GeminiBL: defaultConfig().GeminiBL}
	rtMu.Unlock()
	oldUpload, oldLegacy, oldWC := uploadGenerationAttachment, sendGeminiRequest, sendWebChannelRequest
	defer func() {
		uploadGenerationAttachment, sendGeminiRequest, sendWebChannelRequest = oldUpload, oldLegacy, oldWC
	}()
	var uploads, legacyCalls, binaryCalls int
	uploadGenerationAttachment = func(ctx context.Context, cookie string, user int, proxy string, data []byte, name string) (string, error) {
		uploads++
		return oldUpload(ctx, cookie, user, proxy, data, name)
	}
	sendGeminiRequest = func(ctx context.Context, endpoint, body string, headers map[string]string, proxy string, onLine func(string) error) (int, []byte, int64, []string, error) {
		legacyCalls++
		return oldLegacy(ctx, endpoint, body, headers, proxy, onLine)
	}
	sendWebChannelRequest = func(ctx context.Context, req wcRequest, proxy string, onLine func(string) error) (int, []byte, int64, []string, error) {
		binaryCalls++
		return oldWC(ctx, req, proxy, onLine)
	}
	img := image.NewRGBA(image.Rect(0, 0, 64, 64))
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			img.Set(x, y, color.RGBA{R: 255, A: 255})
		}
	}
	var encoded bytes.Buffer
	if err = png.Encode(&encoded, img); err != nil {
		t.Fatal("cannot create synthetic image")
	}
	model := Models["gemini-4-argon"]
	model.PinAccountID = id
	start := time.Now()
	res, err := streamGenerateOnce("What is the dominant color of this image? Answer RED or BLUE.", "What is the dominant color?", model, []pendingUpload{{Name: "red.png", Mime: "image/png", Kind: 1, Data: encoded.Bytes()}}, nil, nil, nil)
	if err != nil || res == nil {
		t.Logf("live image diagnostic failed after %s; uploads=%d legacy=%d binary=%d", time.Since(start).Round(time.Millisecond), uploads, legacyCalls, binaryCalls)
		t.Fatal("upstream did not complete the image request")
	}
	red := strings.Contains(strings.ToLower(res.Raw), "red")
	t.Logf("live image diagnostic: duration=%s uploads=%d legacy=%d binary=%d model_is_argon=%t red_detected=%t", time.Since(start).Round(time.Millisecond), uploads, legacyCalls, binaryCalls, res.UpstreamModel == model.Upstream, red)
	if uploads != 1 || legacyCalls != 1 || binaryCalls != 0 || res.UpstreamModel != model.Upstream || !red {
		t.Fatal("image response did not meet diagnostic checks")
	}
}

// Use only generated filler and markers to test whether a real long history
// attached via the legacy route is read by the requested model.
func TestLiveExperimentalFallbackLongContext(t *testing.T) {
	path := os.Getenv("GEMINI_DIAGNOSTIC_DB")
	if path == "" || os.Getenv("GEMINI_DIAGNOSTIC_FALLBACK_CONTEXT") != "1" {
		t.Skip("opt-in long-context live diagnostic")
	}
	if firefoxChannelCookiePath() == "" {
		t.Fatal("browser session is required")
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal("source database unavailable")
	}
	defer db.Close()
	var cookie string
	var authuser int
	if err = db.QueryRow("SELECT cookie, authuser FROM accounts WHERE status = 'enabled' ORDER BY id LIMIT 1").Scan(&cookie, &authuser); err != nil {
		t.Fatal("no enabled account found")
	}
	id, err := accountAdd("context-diagnostic", cookie, "")
	if err != nil {
		t.Fatal("temporary account unavailable")
	}
	defer accountDelete(id)
	if _, err = getDB().Exec("UPDATE accounts SET authuser=? WHERE id=?", authuser, id); err != nil {
		t.Fatal("temporary account configuration failed")
	}
	t.Setenv("GEMINI_EXPERIMENTAL_LEGACY_FALLBACK", "1")
	oldRuntime := rtCfg()
	defer func() { rtMu.Lock(); rtVal = oldRuntime; rtMu.Unlock() }()
	rtMu.Lock()
	rtVal = RuntimeConfig{RetryAttempts: 1, RequestTimeout: 150, WebChannelBinary: true, WebChannel: true, FirefoxFingerprint: true, StrictModel: true, MaxPromptBytes: 128000, GeminiBL: defaultConfig().GeminiBL}
	rtMu.Unlock()
	oldUpload, oldLegacy, oldWC := uploadGenerationAttachment, sendGeminiRequest, sendWebChannelRequest
	defer func() {
		uploadGenerationAttachment, sendGeminiRequest, sendWebChannelRequest = oldUpload, oldLegacy, oldWC
	}()
	var uploads, legacyCalls, binaryCalls, uploadedBytes int
	uploadGenerationAttachment = func(ctx context.Context, cookie string, user int, proxy string, data []byte, name string) (string, error) {
		uploads++
		uploadedBytes = len(data)
		return oldUpload(ctx, cookie, user, proxy, data, name)
	}
	sendGeminiRequest = func(ctx context.Context, endpoint, body string, headers map[string]string, proxy string, onLine func(string) error) (int, []byte, int64, []string, error) {
		legacyCalls++
		return oldLegacy(ctx, endpoint, body, headers, proxy, onLine)
	}
	sendWebChannelRequest = func(ctx context.Context, req wcRequest, proxy string, onLine func(string) error) (int, []byte, int64, []string, error) {
		binaryCalls++
		return oldWC(ctx, req, proxy, onLine)
	}
	const first, second = "ECHO-98413", "MOSS-51794"
	latest := "Read the attached conversation and return only the first and second reference codes, in order."
	prompt := "First reference code: " + first + "\n" + strings.Repeat("Neutral filler line for context testing.\n", 3300) + "Second reference code: " + second + "\nUser: " + latest
	expectedFirst, expectedSecond := first, second
	toolHistory := os.Getenv("GEMINI_DIAGNOSTIC_FALLBACK_TOOL_HISTORY") == "1"
	if toolHistory {
		const fixture = "BIRCH-6307"
		expectedFirst, expectedSecond = fixture, fixture
		messages := []map[string]interface{}{
			{"role": "system", "content": strings.Repeat("Neutral filler line for context testing.\n", 3300)},
			{"role": "user", "content": "Use the read tool to read example.txt in the current directory, then reply with the exact file contents. Do not guess."},
			{"role": "assistant", "tool_calls": []interface{}{map[string]interface{}{"function": map[string]interface{}{"name": "read", "arguments": `{"path":"example.txt"}`}}}},
			{"role": "tool", "name": "read", "content": fixture},
		}
		tools := []map[string]interface{}{{"type": "function", "function": map[string]interface{}{"name": "read", "description": "Read a file", "parameters": map[string]interface{}{"type": "object", "properties": map[string]interface{}{"path": map[string]interface{}{"type": "string"}}}}}}
		prompt, latest = messagesToPrompt(messages, tools, nil)
	}
	model := Models["gemini-4-argon"]
	model.PinAccountID = id
	start := time.Now()
	res, err := streamGenerateOnce(prompt, latest, model, nil, nil, nil, nil)
	if err != nil || res == nil {
		t.Logf("long-context diagnostic failed after %s; uploads=%d legacy=%d binary=%d", time.Since(start).Round(time.Millisecond), uploads, legacyCalls, binaryCalls)
		t.Fatal("upstream did not complete the context request")
	}
	answer := extractResponseText(res.Raw)
	hasFirst, hasSecond := strings.Contains(answer, expectedFirst), strings.Contains(answer, expectedSecond)
	exact := strings.TrimSpace(answer) == expectedFirst
	t.Logf("long-context diagnostic: duration=%s prompt_bytes=%d uploaded_bytes=%d uploads=%d legacy=%d binary=%d model_is_argon=%t first_marker=%t second_marker=%t tool_history=%t exact_fixture=%t", time.Since(start).Round(time.Millisecond), len(prompt), uploadedBytes, uploads, legacyCalls, binaryCalls, res.UpstreamModel == model.Upstream, hasFirst, hasSecond, toolHistory, exact)
	if len(prompt) <= 128000 || uploadedBytes != len(prompt) || uploads != 1 || legacyCalls != 1 || binaryCalls != 0 || res.UpstreamModel != model.Upstream || !hasFirst || !hasSecond || (toolHistory && !exact) {
		t.Fatal("long-context response did not meet diagnostic checks")
	}
}
