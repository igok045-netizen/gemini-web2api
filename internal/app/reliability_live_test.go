package app

// This opt-in diagnostic reads only one account from an explicitly provided
// SQLite database. TestMain uses a separate temporary database; no account data
// or response content is printed. The test is skipped in ordinary test runs.
import (
	"bytes"
	"context"
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Exercise the OpenAI-compatible streaming endpoint with a tool definition,
// using an isolated temporary account and never printing credentials or text.
func TestLiveOpenCodeCompatibleRequest(t *testing.T) {
	path := os.Getenv("GEMINI_DIAGNOSTIC_DB")
	if path == "" || os.Getenv("GEMINI_DIAGNOSTIC_OPENCODE") != "1" {
		t.Skip("opt-in OpenCode-compatible live diagnostic")
	}
	measureStages := os.Getenv("GEMINI_DIAGNOSTIC_STAGE_TIMING") == "1"
	timeline := newDiagnosticTimeline()
	if measureStages {
		oldPage, oldKey := fetchSessionPageTokens, fetchWebChannelAPIKey
		fetchSessionPageTokens = func(ctx context.Context, cookie string, user int, proxy string) (xsrfEntry, []string, error) {
			finish := timeline.measure("session_page")
			entry, updates, err := oldPage(ctx, cookie, user, proxy)
			finish(0)
			return entry, updates, err
		}
		fetchWebChannelAPIKey = func(ctx context.Context, proxy string) (string, error) {
			finish := timeline.measure("webchannel_key")
			key, err := oldKey(ctx, proxy)
			finish(0)
			return key, err
		}
		t.Cleanup(func() {
			fetchSessionPageTokens, fetchWebChannelAPIKey = oldPage, oldKey
			t.Logf("Diagnostic stage timings (fixed labels, milliseconds): %+v", timeline.snapshot())
		})
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
	if firefox := os.Getenv("GEMINI_DIAGNOSTIC_FIREFOX_DB"); firefox != "" {
		if os.Getenv("GEMINI_DIAGNOSTIC_FULL_FIREFOX") == "1" {
			cookie, err = diagnosticFullFirefoxCookies(cookie, firefox)
		} else {
			cookie, err = diagnosticFirefoxCookies(cookie, firefox)
		}
		if err != nil {
			t.Fatal("cannot use browser session for comparison")
		}
	}
	id, err := accountAdd("opencode-diagnostic", cookie, "")
	if err != nil {
		t.Fatal("temporary account unavailable")
	}
	defer accountDelete(id)
	if _, err = getDB().Exec("UPDATE accounts SET authuser=? WHERE id=?", authuser, id); err != nil {
		t.Fatal("temporary account configuration failed")
	}
	if os.Getenv("GEMINI_DIAGNOSTIC_COUNT_SESSION_FETCH") == "1" {
		oldFetch := fetchSessionPageTokens
		var fetches atomic.Int32
		fetchSessionPageTokens = func(ctx context.Context, cookie string, user int, proxy string) (xsrfEntry, []string, error) {
			fetches.Add(1)
			return oldFetch(ctx, cookie, user, proxy)
		}
		t.Cleanup(func() {
			fetchSessionPageTokens = oldFetch
			t.Logf("Session page fetches: %d", fetches.Load())
		})
	}
	old := rtCfg()
	defer func() { rtMu.Lock(); rtVal = old; rtMu.Unlock() }()
	rtMu.Lock()
	timeout := 60
	if n, err := strconv.Atoi(os.Getenv("GEMINI_DIAGNOSTIC_TIMEOUT")); err == nil && n >= 5 && n <= 300 {
		timeout = n
	}
	rtVal = RuntimeConfig{RetryAttempts: 1, RequestTimeout: timeout, Impersonate: "chrome_146", GeminiBL: defaultConfig().GeminiBL}
	if os.Getenv("GEMINI_DIAGNOSTIC_FIREFOX_TRANSPORT") == "1" {
		rtVal.FirefoxFingerprint = true
	}
	if n, err := strconv.Atoi(os.Getenv("GEMINI_DIAGNOSTIC_CONTEXT_BUDGET")); err == nil && n >= 1000 && n <= 128000 {
		rtVal.MaxPromptBytes = n
	}
	if build := os.Getenv("GEMINI_DIAGNOSTIC_BUILD"); build != "" {
		if !blValueRe.MatchString(build) {
			rtMu.Unlock()
			t.Fatal("invalid diagnostic build")
		}
		rtVal.GeminiBL = build
	}
	if os.Getenv("GEMINI_DIAGNOSTIC_WC_BINARY") == "1" {
		rtVal.WebChannel = true
	}
	if os.Getenv("GEMINI_DIAGNOSTIC_PRODUCTION_BINARY") == "1" {
		rtVal.WebChannelBinary = true
	}
	if os.Getenv("GEMINI_DIAGNOSTIC_STRICT_MODEL") == "1" {
		rtVal.StrictModel = true
	}
	rtMu.Unlock()
	var historyMu sync.Mutex
	var historyCID, historyRID string
	var observedTextMu sync.Mutex
	var observedText string
	if os.Getenv("GEMINI_DIAGNOSTIC_PRODUCTION_BINARY") == "1" {
		oldSend, oldClassify := webChannelSend, classifyBinaryWebChannelFrame
		oldBinaryHeaders := buildBinaryWebChannelHeaders
		var channelCookie string
		if os.Getenv("GEMINI_DIAGNOSTIC_SCOPED_COOKIES") == "1" {
			channelCookie, err = diagnosticWebChannelCookies(cookie, os.Getenv("GEMINI_DIAGNOSTIC_FIREFOX_DB"))
			if err != nil {
				t.Fatal("cannot select matching WebChannel cookies")
			}
		}
		oldRequest := sendWebChannelRequest
		if os.Getenv("GEMINI_DIAGNOSTIC_RUSSIAN_REQUEST") == "1" || os.Getenv("GEMINI_DIAGNOSTIC_BROWSER_FIELDS") == "1" || channelCookie != "" {
			sendWebChannelRequest = func(ctx context.Context, req wcRequest, proxy string, onLine func(string) error) (int, []byte, int64, []string, error) {
				if os.Getenv("GEMINI_DIAGNOSTIC_BROWSER_FIELDS") == "1" {
					req.Inner = diagnosticBrowserRequestFields(req.Inner)
				}
				if os.Getenv("GEMINI_DIAGNOSTIC_RUSSIAN_REQUEST") == "1" && len(req.Inner) > 1 {
					req.Inner = append([]interface{}(nil), req.Inner...)
					req.Inner[1] = []interface{}{"ru"}
				}
				if channelCookie != "" {
					var scopeErr error
					req.Cookie, scopeErr = diagnosticScopedCookieUpdates(channelCookie, cookie, req.Cookie)
					if scopeErr != nil {
						return 0, nil, 0, nil, scopeErr
					}
				}
				return oldRequest(ctx, req, proxy, onLine)
			}
		}
		oldImmediate, oldBatch := webChannelImmediatePrompt, webChannelBatchPrompt
		webChannelImmediatePrompt = os.Getenv("GEMINI_DIAGNOSTIC_WC_IMMEDIATE") == "1"
		webChannelBatchPrompt = os.Getenv("GEMINI_DIAGNOSTIC_WC_BATCH") == "1"
		if os.Getenv("GEMINI_DIAGNOSTIC_BROWSER_HEADERS") == "1" {
			token, tokenErr := diagnosticServerToken(cookie, authuser)
			if tokenErr != nil {
				t.Fatal("session token unavailable")
			}
			buildBinaryWebChannelHeaders = func(apiKey string, req wcRequest, build string) string {
				h := oldBinaryHeaders(apiKey, req, build)
				ts := time.Now().Unix()
				var parts []string
				for _, item := range []struct{ name, value string }{{"SAPISIDHASH", req.SAPISID}, {"SAPISID1PHASH", cookieValue(req.Cookie, "__Secure-1PAPISID")}, {"SAPISID3PHASH", cookieValue(req.Cookie, "__Secure-3PAPISID")}} {
					if item.value != "" {
						digest := sha1.Sum([]byte(fmt.Sprintf("%d %s https://gemini.google.com", ts, item.value)))
						parts = append(parts, fmt.Sprintf("%s %d_%x", item.name, ts, digest))
					}
				}
				var lines []string
				for _, line := range strings.Split(h, "\r\n") {
					lower := strings.ToLower(line)
					if strings.HasPrefix(lower, "x-server-token:") || strings.HasPrefix(lower, "x-goog-ext-73010989-bin:") || strings.HasPrefix(lower, "x-goog-ext-73010990-bin:") {
						continue
					}
					if strings.HasPrefix(line, "Authorization:") {
						line = "Authorization:" + strings.Join(parts, " ")
					}
					lines = append(lines, line)
				}
				h = strings.Join(lines, "\r\n")
				return h + "X-Server-Token:" + token + "\r\n" +
					"x-goog-ext-73010989-bin:" + base64.StdEncoding.EncodeToString([]byte{8, 0}) + "\r\n" +
					"x-goog-ext-73010990-bin:" + base64.StdEncoding.EncodeToString([]byte{8, 0, 16, 0, 24, 0}) + "\r\n"
			}
		}
		var handshake, get, metadata, prompt, closed, frames, ack, content, done, ended atomic.Int32
		var textFrames, reasoningFrames atomic.Int32
		var tokenPresent, firstPartyHash, thirdPartyHash atomic.Bool
		var firstAck, firstModel, firstText, firstDone sync.Once
		var http3Used atomic.Bool
		transportSend := oldSend
		if os.Getenv("GEMINI_DIAGNOSTIC_HTTP3") == "1" {
			transport := diagnosticHTTP3Transport(true)
			t.Cleanup(func() { _ = transport.Close() })
			transportSend = func(ctx context.Context, method, target, body, cookie, proxy string) (*wcResp, error) {
				response, protocol, err := diagnosticHTTP3Send(transport, ctx, method, target, body, cookie, proxy)
				if protocol == "HTTP/3.0" {
					http3Used.Store(true)
				}
				return response, err
			}
		}
		var preflightChanged atomic.Int32
		var modelHashFrames, modelNameFrames, modelPairFrames, reportedArgonFrames atomic.Int32
		originalCookies, _ := http.ParseCookie(cookie)
		originalValues := map[string]string{}
		for _, c := range originalCookies {
			originalValues[c.Name] = c.Value
		}
		var shapesMu sync.Mutex
		var shapes []string
		webChannelSend = func(ctx context.Context, method, u, body, cookie, proxy string) (*wcResp, error) {
			stage := "other"
			if method == "GET" {
				get.Add(1)
				stage = "downlink_headers"
			} else if body == "count=0" {
				handshake.Add(1)
				stage = "handshake_headers"
				if parsed, parseErr := url.Parse(u); parseErr == nil {
					headers := parsed.Query().Get("$httpHeaders")
					tokenPresent.Store(strings.Contains(headers, "X-Server-Token:"))
					firstPartyHash.Store(strings.Contains(headers, "SAPISID1PHASH "))
					thirdPartyHash.Store(strings.Contains(headers, "SAPISID3PHASH "))
				}
				if actual, parseErr := http.ParseCookie(cookie); parseErr == nil {
					for _, c := range actual {
						if prior, found := originalValues[c.Name]; found && prior != c.Value {
							preflightChanged.Add(1)
						}
					}
				}
			} else if strings.HasPrefix(body, "count=1&ofs=0") {
				metadata.Add(1)
				stage = "metadata_post"
			} else if strings.HasPrefix(body, "count=1&ofs=1") {
				prompt.Add(1)
				stage = "prompt_post"
			} else if strings.HasPrefix(body, "count=1&ofs=2") {
				closed.Add(1)
				stage = "close_post"
			} else if strings.HasPrefix(body, "count=2&ofs=0") {
				metadata.Add(1)
				prompt.Add(1)
				stage = "metadata_and_prompt_post"
			}
			finish := timeline.measure(stage)
			response, err := transportSend(ctx, method, u, body, cookie, proxy)
			if measureStages {
				status := 0
				if response != nil {
					status = response.status
				}
				finish(status)
			}
			return response, err
		}
		classifyBinaryWebChannelFrame = func(raw json.RawMessage) wcEvent {
			frames.Add(1)
			if response := wcBinaryNested(wcBinaryPayload(raw), 2, 7, 1, 4, 4); response != nil {
				if fields, parseErr := wcBinaryParseWire(response); parseErr == nil {
					hash, name := wcBinaryMessageField(fields, 40), wcBinaryMessageField(fields, 43)
					if len(hash) > 0 {
						modelHashFrames.Add(1)
					}
					if len(name) > 0 {
						modelNameFrames.Add(1)
					}
					if len(hash) > 0 && len(name) > 0 {
						modelPairFrames.Add(1)
					}
					if strings.EqualFold(string(name), "4 Argon") {
						reportedArgonFrames.Add(1)
					}
				}
			}
			if os.Getenv("GEMINI_DIAGNOSTIC_HISTORY_ON_STALL") == "1" {
				cid, rid := diagnosticBinaryHistoryIDs(raw)
				historyMu.Lock()
				if cid != "" {
					historyCID = cid
				}
				if rid != "" {
					historyRID = rid
				}
				historyMu.Unlock()
			}
			ev := oldClassify(raw)
			if measureStages {
				if ev.Ack {
					firstAck.Do(func() { timeline.mark("first_ack") })
				}
				if extractUpstreamModel(ev.Line) != "" {
					firstModel.Do(func() { timeline.mark("first_model_metadata") })
				}
				if len(textsInLine(ev.Line)) > 0 {
					firstText.Do(func() { timeline.mark("first_text_frame") })
				}
				if ev.Done {
					firstDone.Do(func() { timeline.mark("generation_done") })
				}
			}
			for _, candidate := range renderedTextsInLine(ev.Line, false) {
				observedTextMu.Lock()
				observedText = cleanGeminiText(candidate)
				observedTextMu.Unlock()
			}
			if (!ev.Ack && ev.Line == "" && !ev.Done && !ev.End) || os.Getenv("GEMINI_DIAGNOSTIC_SHAPES_ALL") == "1" {
				shape := diagnosticBinaryShape(raw)
				if shape != "" {
					shapesMu.Lock()
					if len(shapes) < 8 {
						shapes = append(shapes, shape)
					}
					shapesMu.Unlock()
				}
			}
			if ev.Ack {
				ack.Add(1)
			}
			if ev.Line != "" {
				content.Add(1)
				if len(textsInLine(ev.Line)) > 0 {
					textFrames.Add(1)
				}
				if reasoningInLine(ev.Line) != "" {
					reasoningFrames.Add(1)
				}
			}
			if ev.Done {
				done.Add(1)
			}
			if ev.End {
				ended.Add(1)
			}
			return ev
		}
		t.Cleanup(func() {
			webChannelSend, classifyBinaryWebChannelFrame = oldSend, oldClassify
			buildBinaryWebChannelHeaders = oldBinaryHeaders
			sendWebChannelRequest = oldRequest
			webChannelImmediatePrompt = oldImmediate
			webChannelBatchPrompt = oldBatch
			t.Logf("Binary stages: handshake=%d downlink=%d metadata=%d prompt=%d close=%d frames=%d acknowledgements=%d content=%d done=%d end=%d", handshake.Load(), get.Load(), metadata.Load(), prompt.Load(), closed.Load(), frames.Load(), ack.Load(), content.Load(), done.Load(), ended.Load())
			t.Logf("Binary response detail: text_frames=%d reasoning_frames=%d (content includes metadata-only lines)", textFrames.Load(), reasoningFrames.Load())
			if os.Getenv("GEMINI_DIAGNOSTIC_CLI_TOOL") == "1" {
				observedTextMu.Lock()
				lastText := observedText
				observedTextMu.Unlock()
				_, calls := parseToolCalls(lastText)
				t.Logf("Last text shape: bytes=%d tool_fence=%t complete_tool_calls=%d", len(lastText), strings.Contains(lastText, toolFenceOpen), len(calls))
			}
			t.Logf("Handshake existing cookies changed since test start: %d", preflightChanged.Load())
			t.Logf("Binary handshake fields present: server_token=%t first_party_hash=%t third_party_hash=%t", tokenPresent.Load(), firstPartyHash.Load(), thirdPartyHash.Load())
			if os.Getenv("GEMINI_DIAGNOSTIC_HTTP3") == "1" {
				t.Logf("WebChannel used HTTP/3: %t", http3Used.Load())
			}
			t.Logf("Model metadata frames: hash=%d name=%d paired=%d reported_argon=%d", modelHashFrames.Load(), modelNameFrames.Load(), modelPairFrames.Load(), reportedArgonFrames.Load())
			shapesMu.Lock()
			defer shapesMu.Unlock()
			t.Logf("Selected binary frame structures (field numbers and lengths only): %v", shapes)
		})
	}
	if os.Getenv("GEMINI_DIAGNOSTIC_WC_BINARY") == "1" {
		serverToken := ""
		if os.Getenv("GEMINI_DIAGNOSTIC_WC_TOKEN") == "1" {
			serverToken, err = diagnosticServerToken(cookie, authuser)
			if err != nil {
				t.Fatal("session token unavailable")
			}
		}
		installDiagnosticBinaryTransport(t, serverToken)
	}
	if exe := os.Getenv("GEMINI_DIAGNOSTIC_OPENCODE_CLI"); exe != "" {
		if os.Getenv("GEMINI_DIAGNOSTIC_CLI_SYNTHETIC_LONG_CONTEXT") == "1" {
			want := 2
			if os.Getenv("GEMINI_DIAGNOSTIC_STOP_BEFORE_SECOND") == "1" {
				want = 1
			}
			t.Cleanup(func() {
				deadline := time.Now().Add(2 * time.Second)
				count := 0
				for time.Now().Before(deadline) {
					_ = getDB().QueryRow("SELECT COUNT(*) FROM requests WHERE endpoint=? AND status=200 AND upstream_model=? AND prompt_chars>128000", "chat.completions", "4 Argon").Scan(&count)
					if count >= want {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				t.Logf("Long-context requests confirmed as 4 Argon: %d", count)
				if count < want {
					t.Error("long-context model or prompt size not verified")
				}
			})
		}
		diagnosticOpenCodeCLI(t, exe)
		if os.Getenv("GEMINI_DIAGNOSTIC_HISTORY_ON_STALL") == "1" {
			historyMu.Lock()
			cid, rid := historyCID, historyRID
			historyMu.Unlock()
			if cid == "" || rid == "" {
				t.Logf("History diagnostic: conversation_id=%t response_id=%t", cid != "", rid != "")
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			token, err := getXSRFWithContext(ctx, cookie, authuser, "")
			cancel()
			if err != nil {
				t.Log("History diagnostic: session unavailable")
				return
			}
			attempts := 1
			if os.Getenv("GEMINI_DIAGNOSTIC_HISTORY_RECHECK") == "1" {
				attempts = 3
			}
			for i := 0; i < attempts; i++ {
				if i > 0 {
					time.Sleep(20 * time.Second)
				}
				body, err := pollHistoryRaw(cid, cookie, extractSAPISID(cookie), token, "", authuser)
				if err != nil {
					t.Logf("History diagnostic %d: history request failed", i+1)
					continue
				}
				turn, found := historyTurn(body, rid)
				reply, hasReply := turnReplyText(turn)
				t.Logf("History diagnostic %d: response_bytes=%d conversation_seen=%t request_seen=%t matching_turn=%t has_text=%t text_bytes=%d has_tool_block=%t", i+1, len(body), strings.Contains(body, cid), strings.Contains(body, rid), found, hasReply, len(reply), strings.Contains(reply, "```tool_call"))
				if hasReply {
					break
				}
			}
		}
		return
	}
	testToolCall := os.Getenv("GEMINI_DIAGNOSTIC_TOOL_CALL") == "1"
	prompt := "Reply with exactly OK. Do not call tools."
	if testToolCall {
		prompt = "Use the read_file tool to read example.txt. Do not respond with plain text."
	}
	requestBody := fmt.Sprintf(`{"model":"gemini-4-argon","stream":true,"messages":[{"role":"user","content":%q}],"tools":[{"type":"function","function":{"name":"read_file","description":"Read a file","parameters":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}}}]}`, prompt)
	if os.Getenv("GEMINI_DIAGNOSTIC_NO_TOOLS") == "1" && !testToolCall {
		requestBody = fmt.Sprintf(`{"model":"gemini-4-argon","stream":true,"messages":[{"role":"user","content":%q}]}`, prompt)
	}
	request := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(requestBody))
	recorder := httptest.NewRecorder()
	start := time.Now()
	handleChatCompletions(recorder, request)
	body := recorder.Body.String()
	textEmitted := false
	var answer strings.Builder
	for _, line := range strings.Split(body, "\n") {
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if strings.HasPrefix(line, "data: ") && json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &chunk) == nil {
			for _, choice := range chunk.Choices {
				if choice.Delta.Content != "" {
					textEmitted = true
					answer.WriteString(choice.Delta.Content)
				}
			}
		}
	}
	toolEmitted := strings.Contains(body, `"tool_calls"`) && strings.Contains(body, `"read_file"`)
	answerEmitted := textEmitted
	if testToolCall {
		answerEmitted = toolEmitted
	}
	exactOK := strings.TrimSpace(answer.String()) == "OK"
	observedTextMu.Lock()
	upstreamText := observedText
	observedTextMu.Unlock()
	t.Logf("Text comparison: upstream_present=%t upstream_exact_ok=%t api_matches_upstream=%t", upstreamText != "", strings.TrimSpace(upstreamText) == "OK", upstreamText != "" && answer.String() == upstreamText)
	if recorder.Code != 200 || !strings.Contains(body, "[DONE]") || !answerEmitted || (!testToolCall && !exactOK) || strings.Contains(body, `"error"`) {
		trimmed := strings.TrimSpace(answer.String())
		t.Logf("Synthetic answer shape: bytes=%d contains_OK=%t case_insensitive_OK=%t code_fence=%t", len(trimmed), strings.Contains(trimmed, "OK"), strings.EqualFold(trimmed, "OK"), strings.Contains(trimmed, "```"))
		lower := strings.ToLower(body)
		category := "other"
		for _, c := range []struct{ term, name string }{{"timeout", "timeout"}, {"deadline", "deadline"}, {"429", "rate limit"}, {"sorry", "google challenge"}, {"no content frame", "empty upstream response"}, {"context canceled", "canceled"}} {
			if strings.Contains(lower, c.term) {
				category = c.name
				break
			}
		}
		t.Fatalf("stream failed: HTTP=%d, done=%t, content=%t, exact_ok=%t, tool=%t, error=%t, category=%s, elapsed=%.1fs", recorder.Code, strings.Contains(body, "[DONE]"), textEmitted, exactOK, toolEmitted, strings.Contains(body, `"error"`), category, time.Since(start).Seconds())
	}
	var upstreamModel string
	_ = getDB().QueryRow("SELECT COALESCE(upstream_model,'') FROM requests ORDER BY id DESC LIMIT 1").Scan(&upstreamModel)
	t.Logf("OpenAI-compatible stream: HTTP=%d, completed=true, tool_call=%t, upstream_model=%q, elapsed=%.1fs", recorder.Code, toolEmitted, upstreamModel, time.Since(start).Seconds())
}

// These non-secret field values were observed in one browser capture. Their
// meaning and general applicability remain unknown; this is opt-in testing.
func diagnosticBrowserRequestFields(inner []interface{}) []interface{} {
	size := len(inner)
	if size < 99 {
		size = 99
	}
	out := make([]interface{}, size)
	copy(out, inner)
	out[2] = nil
	out[6] = []interface{}{1}
	out[30] = []interface{}{4, 16, 19}
	out[49] = 0
	out[67] = 0
	out[68] = 2
	out[91] = 1
	out[98] = 1
	return out
}

func installDiagnosticBinaryTransport(t *testing.T, serverToken string) {
	t.Helper()
	oldHeaders, oldEncoder, oldClassify := buildWebChannelHeaders, encodeWebChannelData, classifyWebChannelFrame
	oldPrepare := prepareWebChannelInner
	var frames, textFrames, doneFrames atomic.Int32
	t.Cleanup(func() {
		buildWebChannelHeaders, encodeWebChannelData, classifyWebChannelFrame = oldHeaders, oldEncoder, oldClassify
		prepareWebChannelInner = oldPrepare
		t.Logf("Binary response events: frames=%d text_frames=%d completed=%d", frames.Load(), textFrames.Load(), doneFrames.Load())
	})
	if os.Getenv("GEMINI_DIAGNOSTIC_WC_META_PROMPT") == "1" {
		prepareWebChannelInner = func(inner []interface{}) []interface{} { return append([]interface{}(nil), inner...) }
	}
	buildWebChannelHeaders = func(apiKey string, req wcRequest) string {
		header := strings.Replace(wcHTTPHeaders(apiKey, req), "application/json+protobuf", "application/x-protobuf", 1)
		if serverToken != "" {
			header += "X-Server-Token:" + serverToken + "\r\n"
		}
		if os.Getenv("GEMINI_DIAGNOSTIC_WC_CORRELATED") == "1" {
			header += "x-goog-ext-525005358-bin:" + wcTurnHeaderBin(req.TurnID) + "\r\n"
		}
		lines := strings.Split(header, "\r\n")
		for i, line := range lines {
			if strings.HasPrefix(strings.ToLower(line), "x-goog-ext-525001261-bin:") {
				lines[i] = "x-goog-ext-525001261-bin:" + diagnosticExpandedModelHeader(req, rtCfg().GeminiBL)
			}
		}
		return strings.Join(lines, "\r\n")
	}
	encodeWebChannelData = wcBinaryEncode
	classifyWebChannelFrame = func(payload json.RawMessage) wcEvent {
		ev := wcBinaryClassify(payload)
		frames.Add(1)
		if ev.Line != "" && len(textsInLine(ev.Line)) > 0 {
			textFrames.Add(1)
		}
		if ev.Done || ev.End {
			doneFrames.Add(1)
		}
		if ev.Ack || ev.Done || ev.End || ev.Line != "" {
			return ev
		}
		return wcClassify(payload)
	}
}

func diagnosticServerToken(cookie string, authuser int) (string, error) {
	page, err := fetchAppPage(cookie, authuser, "")
	if err != nil {
		return "", err
	}
	m := regexp.MustCompile(`"PI9WOb"\s*:\s*"([^"]*)"`).FindSubmatch(page)
	if len(m) < 2 || len(m[1]) == 0 {
		return "", fmt.Errorf("session token missing")
	}
	var token string
	if err := json.Unmarshal(append(append([]byte{'"'}, m[1]...), '"'), &token); err != nil || strings.ContainsAny(token, "\r\n") {
		return "", fmt.Errorf("invalid session token")
	}
	return token, nil
}

// Run the installed OpenCode binary against an ephemeral loopback server and
// temporary data directories. Only summary metadata reaches the test output.
func diagnosticOpenCodeCLI(t *testing.T, exe string) {
	t.Helper()
	const sentinel = "BIRCH-6307"
	dir := t.TempDir()
	var requests atomic.Int32
	var seeding atomic.Bool
	var fakeCompactions atomic.Int32
	var sawRealisticOverflow atomic.Bool
	var sawTools atomic.Bool
	var sawToolResult atomic.Bool
	var requestIncludesWorkspace atomic.Bool
	var readDescriptionRequiresAbsolute atomic.Bool
	var outcomesMu sync.Mutex
	var outcomes []string
	var deployedProxy *httputil.ReverseProxy
	if os.Getenv("GEMINI_DIAGNOSTIC_DEPLOYED_OPENCODE") == "1" {
		if os.Getenv("GEMINI_DIAGNOSTIC_DEPLOYED_KEY") == "" {
			t.Fatal("deployed server key unavailable")
		}
		deployedProxy = httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: "127.0.0.1:8084"})
		deployedProxy.FlushInterval = -1
		deployedProxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "diagnostic upstream unavailable", http.StatusBadGateway)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var body bytes.Buffer
		if _, err := body.ReadFrom(r.Body); err != nil {
			http.Error(w, "read error", 400)
			return
		}
		_ = r.Body.Close()
		for _, path := range []string{dir, filepath.ToSlash(dir)} {
			quoted, _ := json.Marshal(path)
			if len(quoted) > 2 && bytes.Contains(body.Bytes(), quoted[1:len(quoted)-1]) {
				requestIncludesWorkspace.Store(true)
			}
		}
		var req struct {
			Tools []json.RawMessage `json:"tools"`
		}
		_ = json.Unmarshal(body.Bytes(), &req)
		if os.Getenv("GEMINI_DIAGNOSTIC_PRINT_TEST_SCHEMA") == "1" && os.Getenv("GEMINI_DIAGNOSTIC_CLI_MOCK") == "1" {
			var names []string
			for _, raw := range req.Tools {
				var item struct{ Function struct{ Name string } }
				if json.Unmarshal(raw, &item) == nil && regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(item.Function.Name) {
					names = append(names, item.Function.Name)
				}
			}
			t.Logf("Artificial test available tool names: %v", names)
		}
		for _, raw := range req.Tools {
			var tool struct {
				Function struct {
					Name, Description string
					Parameters        struct {
						Properties map[string]struct{ Description string }
					}
				}
			}
			if json.Unmarshal(raw, &tool) == nil && tool.Function.Name == "read" {
				description := strings.ToLower(tool.Function.Description + " " + tool.Function.Parameters.Properties["path"].Description)
				readDescriptionRequiresAbsolute.Store(strings.Contains(description, "absolute"))
				if os.Getenv("GEMINI_DIAGNOSTIC_PRINT_TEST_SCHEMA") == "1" && os.Getenv("GEMINI_DIAGNOSTIC_CLI_MOCK") == "1" {
					t.Logf("Artificial test read schema: description=%q path_description=%q", truncate(tool.Function.Description, 400), truncate(tool.Function.Parameters.Properties["path"].Description, 400))
				}
			}
		}
		if os.Getenv("GEMINI_DIAGNOSTIC_CLI_TRIM_TOOLS") == "1" && len(req.Tools) > 0 {
			var selected []json.RawMessage
			for _, tool := range req.Tools {
				var descriptor struct {
					Function struct {
						Name string `json:"name"`
					} `json:"function"`
				}
				if json.Unmarshal(tool, &descriptor) == nil && (descriptor.Function.Name == "read" || descriptor.Function.Name == "read_file") {
					selected = append(selected, tool)
				}
			}
			if len(selected) != 1 {
				http.Error(w, "diagnostic read tool unavailable", 400)
				return
			}
			if os.Getenv("GEMINI_DIAGNOSTIC_CLI_MINIMAL_TOOL") == "1" {
				var selectedTool map[string]json.RawMessage
				var function map[string]json.RawMessage
				if json.Unmarshal(selected[0], &selectedTool) != nil || json.Unmarshal(selectedTool["function"], &function) != nil {
					http.Error(w, "diagnostic tool invalid", 400)
					return
				}
				function["description"] = json.RawMessage(`"Read a file from the local filesystem."`)
				selectedTool["function"], _ = json.Marshal(function)
				selected[0], _ = json.Marshal(selectedTool)
			}
			var original map[string]json.RawMessage
			if json.Unmarshal(body.Bytes(), &original) != nil {
				http.Error(w, "diagnostic request invalid", 400)
				return
			}
			original["tools"], _ = json.Marshal(selected)
			if os.Getenv("GEMINI_DIAGNOSTIC_CLI_TRIM_SYSTEM") == "1" {
				var messages []json.RawMessage
				if json.Unmarshal(original["messages"], &messages) != nil {
					http.Error(w, "diagnostic messages invalid", 400)
					return
				}
				filtered := make([]json.RawMessage, 0, len(messages))
				for _, message := range messages {
					var item struct {
						Role string `json:"role"`
					}
					if json.Unmarshal(message, &item) != nil {
						http.Error(w, "diagnostic message invalid", 400)
						return
					}
					if item.Role != "system" && item.Role != "developer" {
						filtered = append(filtered, message)
					}
				}
				original["messages"], _ = json.Marshal(filtered)
			}
			trimmed, _ := json.Marshal(original)
			body.Reset()
			_, _ = body.Write(trimmed)
			req.Tools = selected
		}
		if os.Getenv("GEMINI_DIAGNOSTIC_CLI_SYNTHETIC_LONG_CONTEXT") == "1" {
			var original map[string]json.RawMessage
			var messages []json.RawMessage
			if json.Unmarshal(body.Bytes(), &original) != nil || json.Unmarshal(original["messages"], &messages) != nil {
				http.Error(w, "diagnostic messages invalid", http.StatusBadRequest)
				return
			}
			filler, _ := json.Marshal(map[string]string{"role": "system", "content": strings.Repeat("Neutral filler line for context testing.\n", 3200)})
			messages = append([]json.RawMessage{filler}, messages...)
			original["messages"], _ = json.Marshal(messages)
			longBody, _ := json.Marshal(original)
			body.Reset()
			_, _ = body.Write(longBody)
		}
		if len(req.Tools) > 0 {
			sawTools.Store(true)
		}
		if os.Getenv("GEMINI_DIAGNOSTIC_CLI_FAKE_SEEDS") == "1" && !seeding.Load() && len(req.Tools) == 0 {
			fakeCompactions.Add(1)
		}
		if bytes.Contains(body.Bytes(), []byte(sentinel)) {
			sawToolResult.Store(true)
		}
		requestIndex := requests.Add(1)
		if os.Getenv("GEMINI_DIAGNOSTIC_CLI_FAKE_CONTEXT_LIMIT") == "1" && requestIndex == 3 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":{"message":"prompt is 130000 UTF-8 bytes, over the 128000-byte limit for the experimental binary WebChannel. Shorten or compact the conversation before retrying.","type":"invalid_request_error","code":"context_length_exceeded"}}`)
			return
		}
		if os.Getenv("GEMINI_DIAGNOSTIC_STOP_BEFORE_SECOND") == "1" && requestIndex == 2 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":{"message":"diagnostic stopped before second generation"}}`)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body.Bytes()))
		response := &diagnosticHTTPWriter{ResponseWriter: w}
		started := time.Now()
		if deployedProxy != nil {
			r.Header.Set("Authorization", "Bearer "+os.Getenv("GEMINI_DIAGNOSTIC_DEPLOYED_KEY"))
			deployedProxy.ServeHTTP(response, r)
		} else {
			handleChatCompletions(response, r)
		}
		if os.Getenv("GEMINI_DIAGNOSTIC_CLI_REALISTIC_LIMIT") == "1" && response.status == http.StatusBadRequest {
			sawRealisticOverflow.Store(true)
		}
		outcomesMu.Lock()
		if len(outcomes) < 8 {
			outcomes = append(outcomes, fmt.Sprintf("status=%d request_bytes=%d tools=%d response_bytes=%d category=%s duration=%.1fs", response.status, body.Len(), len(req.Tools), response.bytes, response.category, time.Since(started).Seconds()))
		}
		outcomesMu.Unlock()
	}))
	defer server.Close()
	testRealTool := os.Getenv("GEMINI_DIAGNOSTIC_CLI_TOOL") == "1"
	message := "Reply with exactly OK. Do not call any tools."
	if testRealTool {
		if err := os.WriteFile(filepath.Join(dir, "example.txt"), []byte(sentinel+"\n"), 0600); err != nil {
			t.Fatal("cannot create isolated test file")
		}
		message = "Use the read tool to read example.txt in the current directory, then reply with the exact file contents. Do not guess."
		if os.Getenv("GEMINI_DIAGNOSTIC_CLI_REALISTIC_LIMIT") == "1" {
			message = strings.Repeat("Synthetic current context. ", 800) + "\n" + message
		}
	}
	if marker := os.Getenv("GEMINI_DIAGNOSTIC_CLI_MARKER"); marker != "" {
		if !regexp.MustCompile(`^[A-Z0-9-]{4,40}$`).MatchString(marker) {
			t.Fatal("invalid diagnostic marker")
		}
		message += " Diagnostic reference: " + marker + "."
	}
	if os.Getenv("GEMINI_DIAGNOSTIC_CLI_MOCK") == "1" || os.Getenv("GEMINI_DIAGNOSTIC_CLI_FAKE_SEEDS") == "1" {
		oldSend := sendWebChannelRequest
		var mockCalls atomic.Int32
		t.Cleanup(func() { sendWebChannelRequest = oldSend })
		sendWebChannelRequest = func(ctx context.Context, req wcRequest, proxy string, onLine func(string) error) (int, []byte, int64, []string, error) {
			if os.Getenv("GEMINI_DIAGNOSTIC_CLI_FAKE_SEEDS") == "1" && !seeding.Load() {
				return oldSend(ctx, req, proxy, onLine)
			}
			maxMockCalls := int32(6)
			if os.Getenv("GEMINI_DIAGNOSTIC_CLI_REALISTIC_LIMIT") == "1" {
				maxMockCalls = 15
			}
			if mockCalls.Add(1) > maxMockCalls {
				return 502, []byte("local diagnostic stopped after three turns"), 1, nil, nil
			}
			text := sentinel
			if seeding.Load() {
				text = "Synthetic prior conversation acknowledged."
			} else if (os.Getenv("GEMINI_DIAGNOSTIC_CLI_FAKE_CONTEXT_LIMIT") == "1" || os.Getenv("GEMINI_DIAGNOSTIC_CLI_REALISTIC_LIMIT") == "1") && !strings.Contains(req.Prompt, "Available tools:") {
				fakeCompactions.Add(1)
				text = "## Objective\nRead example.txt and report its contents.\n## Completed\nThe read tool returned " + sentinel + ".\n## Next Move\nReturn that value."
				if os.Getenv("GEMINI_DIAGNOSTIC_CLI_REALISTIC_LIMIT") == "1" {
					text = "## Objective\nRead example.txt and report its contents.\n## Next Move\nUse the read tool to read example.txt."
				}
			} else if !strings.Contains(req.Prompt, sentinel) {
				path := filepath.Join(dir, "example.txt")
				if os.Getenv("GEMINI_DIAGNOSTIC_CLI_MOCK_RELATIVE") == "1" {
					path = "example.txt"
				}
				tool, _ := json.Marshal(map[string]interface{}{"name": "read", "arguments": map[string]string{"path": path}})
				text = "```tool_call\n" + string(tool) + "\n```"
			}
			inner := make([]interface{}, 43)
			candidate := make([]interface{}, 38)
			candidate[0], candidate[1] = "test-candidate", []interface{}{text}
			inner[4] = []interface{}{candidate}
			value, _ := json.Marshal(inner)
			line, _ := json.Marshal([]interface{}{[]interface{}{"wrb.fr", nil, string(value)}})
			if onLine != nil {
				if err := onLine(string(line)); err != nil {
					return 200, line, 1, nil, err
				}
			}
			return 200, line, 1, nil, nil
		}
	}
	config := map[string]interface{}{"providers": map[string]interface{}{
		"diagnostic-local": map[string]interface{}{
			"name": "Diagnostic server", "package": "@opencode/ai/providers/openai-compatible",
			"settings": map[string]interface{}{"baseURL": server.URL + "/v1", "apiKey": "diagnostic-only"},
			"models":   map[string]interface{}{"gemini-4-argon": map[string]interface{}{"name": "Gemini 4 Argon"}},
		},
	}}
	config["permissions"] = []interface{}{
		map[string]interface{}{"action": "*", "resource": "*", "effect": "deny"},
		map[string]interface{}{"action": "read", "resource": "example.txt", "effect": "allow"},
		map[string]interface{}{"action": "read", "resource": filepath.Join(dir, "example.txt"), "effect": "allow"},
	}
	var plugins []interface{}
	if os.Getenv("GEMINI_DIAGNOSTIC_CLI_GUARD") == "1" {
		plugin, err := filepath.Abs("opencode-gemini-retry-guard")
		if err != nil {
			t.Fatal("retry guard unavailable")
		}
		plugins = append(plugins, map[string]interface{}{
			"package": filepath.ToSlash(plugin), "options": map[string]interface{}{"providers": []string{"diagnostic-local"}},
		})
	}
	if len(plugins) > 0 {
		config["plugins"] = plugins
	}
	configJSON, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	cliTimeout := 75
	if n, err := strconv.Atoi(os.Getenv("GEMINI_DIAGNOSTIC_CLI_TIMEOUT")); err == nil && n >= 15 && n <= 300 {
		cliTimeout = n
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cliTimeout)*time.Second)
	defer cancel()
	args := []string{"--standalone", "run", "--format", "json", "--model", "diagnostic-local/gemini-4-argon"}
	if os.Getenv("GEMINI_DIAGNOSTIC_CLI_FAKE_CONTEXT_LIMIT") == "1" || os.Getenv("GEMINI_DIAGNOSTIC_CLI_REALISTIC_LIMIT") == "1" {
		args = append(args, "--continue")
	}
	if os.Getenv("GEMINI_DIAGNOSTIC_CLI_FIXED_TITLE") == "1" {
		args = append(args, "--title", "Diagnostic")
	}
	args = append(args, message)
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.WaitDelay = 2 * time.Second
	cmd.Dir = dir
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		key = strings.ToUpper(key)
		if strings.HasPrefix(key, "OPENCODE_") || strings.HasPrefix(key, "XDG_") || key == "APPDATA" || key == "LOCALAPPDATA" || key == "PWD" || key == "GEMINI_DIAGNOSTIC_DEPLOYED_KEY" {
			continue
		}
		cmd.Env = append(cmd.Env, entry)
	}
	cmd.Env = append(cmd.Env,
		"XDG_CONFIG_HOME="+filepath.Join(dir, "config"), "XDG_DATA_HOME="+filepath.Join(dir, "data"),
		"XDG_STATE_HOME="+filepath.Join(dir, "state"), "XDG_CACHE_HOME="+filepath.Join(dir, "cache"),
		"APPDATA="+filepath.Join(dir, "appdata"), "LOCALAPPDATA="+filepath.Join(dir, "localappdata"), "PWD="+dir,
		"OPENCODE_CONFIG_CONTENT="+string(configJSON), "OPENCODE_DISABLE_AUTOUPDATE=true", "OPENCODE_DISABLE_PROJECT_CONFIG=true")
	if os.Getenv("GEMINI_DIAGNOSTIC_CLI_FAKE_CONTEXT_LIMIT") == "1" || os.Getenv("GEMINI_DIAGNOSTIC_CLI_REALISTIC_LIMIT") == "1" {
		seeding.Store(true)
		seedCount, repeats := 1, 300
		if os.Getenv("GEMINI_DIAGNOSTIC_CLI_REALISTIC_LIMIT") == "1" {
			seedCount, repeats = 4, 1000
		}
		for i := 0; i < seedCount; i++ {
			seedArgs := []string{"--standalone", "run", "--format", "json", "--model", "diagnostic-local/gemini-4-argon", "--title", "Diagnostic"}
			if i > 0 {
				seedArgs = append(seedArgs, "--continue")
			}
			seedArgs = append(seedArgs, strings.Repeat("Synthetic earlier context. ", repeats))
			seed := exec.CommandContext(ctx, exe, seedArgs...)
			seed.Dir, seed.Env, seed.WaitDelay = dir, cmd.Env, 2*time.Second
			seed.Stdout, seed.Stderr = io.Discard, io.Discard
			if err := seed.Run(); err != nil {
				t.Fatal("could not create isolated test conversation")
			}
		}
		seeding.Store(false)
	}
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	started := time.Now()
	err = cmd.Run()
	output := out.String()
	textSeen, toolSeen, toolSucceeded, answerSeen, answerContains := false, false, false, false, false
	toolStatus, toolErrorCategory := "none", "none"
	var calledRead, hasPath, hasFilePath, hasInputObject bool
	var pathAbsolute, pathBasenameMatches, pathTargetsFixture bool
	for _, line := range strings.Split(output, "\n") {
		var event struct {
			Type string `json:"type"`
			Part struct {
				Text  string `json:"text"`
				Tool  string `json:"tool"`
				State struct {
					Status string          `json:"status"`
					Error  string          `json:"error"`
					Input  json.RawMessage `json:"input"`
				} `json:"state"`
			} `json:"part"`
		}
		if json.Unmarshal([]byte(line), &event) != nil {
			continue
		}
		if event.Type == "tool_use" {
			toolSeen = true
			calledRead = event.Part.Tool == "read"
			var args map[string]json.RawMessage
			if json.Unmarshal(event.Part.State.Input, &args) == nil && args != nil {
				hasInputObject = true
				_, hasPath = args["path"]
				_, hasFilePath = args["filePath"]
				var path string
				if json.Unmarshal(args["path"], &path) == nil && path != "" {
					pathAbsolute = filepath.IsAbs(path)
					pathBasenameMatches = strings.EqualFold(filepath.Base(path), "example.txt")
					resolved := path
					if !pathAbsolute {
						resolved = filepath.Join(dir, path)
					}
					pathTargetsFixture = strings.EqualFold(filepath.Clean(resolved), filepath.Join(dir, "example.txt"))
				}
			}
			switch event.Part.State.Status {
			case "pending", "running", "completed", "error":
				toolStatus = event.Part.State.Status
			default:
				toolStatus = "other"
			}
			if event.Part.State.Error != "" {
				toolErrorCategory = "other"
				lower := strings.ToLower(event.Part.State.Error)
				for _, candidate := range []struct{ term, category string }{
					{"tool not found", "tool unavailable"}, {"invalid", "invalid input"}, {"required", "required input"}, {"no such file", "file missing"},
					{"not found", "not found"}, {"permission", "permission"}, {"path", "path"},
				} {
					if strings.Contains(lower, candidate.term) {
						toolErrorCategory = candidate.category
						break
					}
				}
			}
			if event.Part.State.Status == "completed" {
				toolSucceeded = true
			}
			if os.Getenv("GEMINI_DIAGNOSTIC_CLI_MOCK") == "1" && event.Part.State.Status == "error" {
				msg := strings.ReplaceAll(event.Part.State.Error, dir, "[temporary directory]")
				t.Logf("Mock tool error: %s", truncate(msg, 200))
				break
			}
		}
		if event.Type == "text" {
			textSeen = true
			if strings.Contains(event.Part.Text, sentinel) {
				answerContains = true
			}
			if strings.TrimSpace(event.Part.Text) == sentinel {
				answerSeen = true
			}
		}
	}
	outcomesMu.Lock()
	finished := append([]string(nil), outcomes...)
	outcomesMu.Unlock()
	t.Logf("OpenCode request outcomes: %v", finished)
	t.Logf("OpenCode observed events: text=%t tool=%t tool_status=%s tool_error_category=%s tool_completed=%t tool_result_in_request=%t final_answer=%t contains_fixture=%t", textSeen, toolSeen, toolStatus, toolErrorCategory, toolSucceeded, sawToolResult.Load(), answerSeen, answerContains)
	t.Logf("OpenCode tool input shape: read=%t object=%t has_path=%t has_filePath=%t", calledRead, hasInputObject, hasPath, hasFilePath)
	t.Logf("OpenCode read tool description mentions absolute paths: %t", readDescriptionRequiresAbsolute.Load())
	t.Logf("OpenCode request includes test workspace path: %t", requestIncludesWorkspace.Load())
	if os.Getenv("GEMINI_DIAGNOSTIC_CLI_FAKE_CONTEXT_LIMIT") == "1" {
		if requests.Load() < 4 || fakeCompactions.Load() != 1 || !answerSeen || !toolSucceeded {
			t.Fatalf("context recovery incomplete: requests=%d compactions=%d tool_completed=%t final_answer=%t", requests.Load(), fakeCompactions.Load(), toolSucceeded, answerSeen)
		}
		t.Logf("Synthetic context limit recovered with %d local requests and one compaction", requests.Load())
		return
	}
	if os.Getenv("GEMINI_DIAGNOSTIC_CLI_REALISTIC_LIMIT") == "1" {
		if !sawRealisticOverflow.Load() || fakeCompactions.Load() != 1 || !toolSucceeded || !answerSeen {
			t.Fatalf("large-history recovery incomplete: overflow=%t compactions=%d tool_completed=%t final_answer=%t", sawRealisticOverflow.Load(), fakeCompactions.Load(), toolSucceeded, answerSeen)
		}
		t.Log("Synthetic oversized conversation was compacted and the tool cycle completed")
		return
	}
	if hasPath {
		t.Logf("OpenCode test path: absolute=%t correct_basename=%t targets_fixture=%t", pathAbsolute, pathBasenameMatches, pathTargetsFixture)
	}
	if os.Getenv("GEMINI_DIAGNOSTIC_EXPECT_RELATIVE_ERROR") == "1" {
		if !toolSeen || toolStatus != "error" || !pathTargetsFixture || pathAbsolute {
			t.Fatal("relative-path failure was not reproduced")
		}
		t.Log("Relative path reproduced an OpenCode tool error using the artificial model")
		return
	}
	if os.Getenv("GEMINI_DIAGNOSTIC_STOP_BEFORE_SECOND") == "1" && testRealTool {
		if !toolSucceeded || !sawToolResult.Load() || requests.Load() != 2 {
			t.Fatal("first tool call or controlled stop was not observed")
		}
		t.Log("First tool call completed; second generation was deliberately not sent")
		return
	}
	if os.Getenv("GEMINI_DIAGNOSTIC_CLI_GUARD") == "1" {
		marked := strings.Contains(output+stderr.String(), "gemini_outcome_unknown")
		if err == nil && testRealTool && toolSucceeded && sawToolResult.Load() && answerSeen && requests.Load() >= 2 && !marked {
			t.Logf("Live OpenCode tool cycle: succeeded, requests=%d, elapsed=%.1fs", requests.Load(), time.Since(started).Seconds())
			return
		}
		if testRealTool {
			t.Fatalf("OpenCode tool cycle incomplete: timed_out=%t requests=%d marked=%t tool_event=%t answer=%t", ctx.Err() != nil, requests.Load(), marked, toolSeen, answerSeen)
		}
		if ctx.Err() != nil || requests.Load() != 1 || !marked {
			t.Fatalf("live retry guard not verified: timed_out=%t requests=%d marked=%t text_event=%t", ctx.Err() != nil, requests.Load(), marked, textSeen)
		}
		t.Logf("Live OpenCode retry guard: one request, unknown-outcome error surfaced, elapsed=%.1fs", time.Since(started).Seconds())
		return
	}
	if err != nil || requests.Load() == 0 || !textSeen || (testRealTool && (!toolSucceeded || !sawToolResult.Load() || !answerSeen || requests.Load() < 2)) {
		category := "other"
		all := strings.ToLower(output + stderr.String())
		for _, item := range []struct{ term, name string }{{"timeout", "timeout"}, {"provider", "provider configuration"}, {"model", "model configuration"}, {"upstream", "upstream error"}, {"connect", "connection"}} {
			if strings.Contains(all, item.term) {
				category = item.name
				break
			}
		}
		t.Fatalf("OpenCode CLI failed: exit_error=%t, timed_out=%t, requests=%d, tools=%t, text_event=%t, tool_event=%t, answer=%t, category=%s, elapsed=%.1fs", err != nil, ctx.Err() != nil, requests.Load(), sawTools.Load(), textSeen, toolSeen, answerSeen, category, time.Since(started).Seconds())
	}
	t.Logf("OpenCode CLI: succeeded, requests=%d, sent_tools=%t, tool_event=%t, answer=%t, elapsed=%.1fs", requests.Load(), sawTools.Load(), toolSeen, answerSeen, time.Since(started).Seconds())
}

// Record only aggregate transport metadata and known failure categories.
type diagnosticHTTPWriter struct {
	http.ResponseWriter
	status   int
	bytes    int
	category string
}

type diagnosticCountingReader struct {
	r                       io.Reader
	started                 time.Time
	bytes, chunks, newlines int
	lastRead                time.Duration
}

func (r *diagnosticCountingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		r.bytes += n
		r.chunks++
		r.newlines += bytes.Count(p[:n], []byte{'\n'})
		r.lastRead = time.Since(r.started)
	}
	return n, err
}

func (w *diagnosticHTTPWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *diagnosticHTTPWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.bytes += len(p)
	if w.category == "" {
		lower := strings.ToLower(string(p))
		for _, item := range []struct{ term, name string }{{"no content frame", "empty frame"}, {"sorry/index", "google challenge"}, {"context canceled", "client canceled"}, {"awaiting headers", "timeout waiting for headers"}, {"while reading", "timeout reading response"}, {"deadline", "deadline"}, {"timeout", "timeout"}, {"http 429", "upstream rate limit"}, {"upstream error", "upstream error"}} {
			if strings.Contains(lower, item.term) {
				w.category = item.name
				break
			}
		}
	}
	return w.ResponseWriter.Write(p)
}

func (w *diagnosticHTTPWriter) Flush() {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func TestLiveTransportComparison(t *testing.T) {
	path := os.Getenv("GEMINI_DIAGNOSTIC_DB")
	if path == "" {
		t.Skip("opt-in live diagnostic")
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal("unable to open source database")
	}
	defer db.Close()
	var cookie string
	var authuser int
	if err = db.QueryRow("SELECT cookie, authuser FROM accounts WHERE status = 'enabled' ORDER BY id LIMIT 1").Scan(&cookie, &authuser); err != nil {
		t.Fatal("no enabled account found")
	}
	if firefoxPath := os.Getenv("GEMINI_DIAGNOSTIC_FIREFOX_DB"); firefoxPath != "" {
		if os.Getenv("GEMINI_DIAGNOSTIC_FULL_FIREFOX") == "1" {
			cookie, err = diagnosticFullFirefoxCookies(cookie, firefoxPath)
		} else {
			cookie, err = diagnosticFirefoxCookies(cookie, firefoxPath)
		}
		if err != nil {
			t.Fatal("cannot use browser session for comparison:", err)
		}
		t.Log("Using current browser cookies after matching session identity; credentials are not printed.")
	}
	id, err := accountAdd("diagnostic", cookie, "")
	if err != nil {
		t.Fatal("unable to create temporary diagnostic account")
	}
	defer accountDelete(id)
	if _, err = getDB().Exec("UPDATE accounts SET authuser=? WHERE id=?", authuser, id); err != nil {
		t.Fatal("unable to configure diagnostic account")
	}
	oldRuntime := rtCfg()
	oldRotate := rotateAccountCredentials
	oldFetchXSRF := fetchAccountXSRF
	oldGeminiSend := sendGeminiRequest
	oldGeminiRead := readGeminiResponse
	oldPromptGap := webChannelPromptGap
	oldPrepare := prepareWebChannelInner
	oldWCSend := webChannelSend
	oldHeaders := buildWebChannelHeaders
	oldClassify := classifyWebChannelFrame
	oldBinaryClassify := classifyBinaryWebChannelFrame
	oldEncoder := encodeWebChannelData
	defer func() {
		rtMu.Lock()
		rtVal = oldRuntime
		rtMu.Unlock()
		rotateAccountCredentials = oldRotate
		fetchAccountXSRF = oldFetchXSRF
		sendGeminiRequest = oldGeminiSend
		readGeminiResponse = oldGeminiRead
		webChannelPromptGap = oldPromptGap
		prepareWebChannelInner = oldPrepare
		webChannelSend = oldWCSend
		buildWebChannelHeaders = oldHeaders
		classifyWebChannelFrame = oldClassify
		classifyBinaryWebChannelFrame = oldBinaryClassify
		encodeWebChannelData = oldEncoder
	}()
	if os.Getenv("GEMINI_DIAGNOSTIC_TRIPLE_AUTH") == "1" {
		buildWebChannelHeaders = func(apiKey string, req wcRequest) string {
			h := wcHTTPHeaders(apiKey, req)
			if req.Cookie == "" || req.SAPISID == "" {
				return h
			}
			ts := time.Now().Unix()
			parts := []string{}
			for _, item := range []struct{ name, value string }{{"SAPISIDHASH", req.SAPISID}, {"SAPISID1PHASH", cookieValue(req.Cookie, "__Secure-1PAPISID")}, {"SAPISID3PHASH", cookieValue(req.Cookie, "__Secure-3PAPISID")}} {
				if item.value == "" {
					continue
				}
				digest := sha1.Sum([]byte(fmt.Sprintf("%d %s https://gemini.google.com", ts, item.value)))
				parts = append(parts, fmt.Sprintf("%s %d_%x", item.name, ts, digest))
			}
			lines := strings.Split(h, "\r\n")
			for i, line := range lines {
				if strings.HasPrefix(line, "Authorization:") {
					lines[i] = "Authorization:" + strings.Join(parts, " ")
				}
			}
			return strings.Join(lines, "\r\n")
		}
		t.Log("Using experimental three-part authorization header; values are withheld.")
	}
	if n, err := strconv.Atoi(os.Getenv("GEMINI_DIAGNOSTIC_WC_GAP_MS")); err == nil && n >= 0 && n <= 8000 {
		webChannelPromptGap = time.Duration(n) * time.Millisecond
		t.Logf("Testing WebChannel prompt delay of %d ms", n)
	}
	if os.Getenv("GEMINI_DIAGNOSTIC_WC_BROWSER_FIELDS") == "1" {
		buildWebChannelHeaders = func(apiKey string, req wcRequest) string {
			header := wcHTTPHeaders(apiKey, req)
			lines := strings.Split(header, "\r\n")
			for i, line := range lines {
				if strings.HasPrefix(strings.ToLower(line), "x-goog-ext-525001261-bin:") {
					lines[i] = "x-goog-ext-525001261-bin:" + diagnosticExpandedModelHeader(req, rtCfg().GeminiBL)
				}
			}
			return strings.Join(lines, "\r\n")
		}
		t.Log("Testing additional non-secret model-header fields seen in the browser.")
	}
	if os.Getenv("GEMINI_DIAGNOSTIC_WC_META_PROMPT") == "1" {
		prepareWebChannelInner = func(inner []interface{}) []interface{} { return append([]interface{}(nil), inner...) }
		t.Log("Testing prompt included in WebChannel initial metadata as well as the text event.")
	}
	binaryMode := os.Getenv("GEMINI_DIAGNOSTIC_WC_BINARY") == "1"
	if binaryMode {
		previous := buildWebChannelHeaders
		buildWebChannelHeaders = func(apiKey string, req wcRequest) string {
			header := strings.Replace(previous(apiKey, req), "application/json+protobuf", "application/x-protobuf", 1)
			if os.Getenv("GEMINI_DIAGNOSTIC_WC_CORRELATED") == "1" {
				header += "x-goog-ext-525005358-bin:" + wcTurnHeaderBin(req.TurnID) + "\r\n"
			}
			return header
		}
		encodeWebChannelData = wcBinaryEncode
		t.Log("Testing experimental binary protobuf requests; response content is not logged.")
	}
	var stageMu sync.Mutex
	timelineStart := time.Now()
	var stages []string
	var frames []string
	var frameShapes []string
	readGeminiResponse = func(body io.Reader, onLine func(string) error, start time.Time) ([]byte, int64, error) {
		reader := &diagnosticCountingReader{r: body, started: start}
		raw, ttfb, err := oldGeminiRead(reader, onLine, start)
		stageMu.Lock()
		stages = append(stages, fmt.Sprintf("body:bytes=%d:chunks=%d:newlines=%d:last_read=%.1fs", reader.bytes, reader.chunks, reader.newlines, reader.lastRead.Seconds()))
		stageMu.Unlock()
		return raw, ttfb, err
	}
	fetchAccountXSRF = func(ctx context.Context, cookie string, authuser int, proxy string) (string, []string, error) {
		started := time.Now()
		token, updates, err := oldFetchXSRF(ctx, cookie, authuser, proxy)
		stageMu.Lock()
		stages = append(stages, fmt.Sprintf("session-page:error=%t:%.1fs", err != nil, time.Since(started).Seconds()))
		stageMu.Unlock()
		return token, updates, err
	}
	sendGeminiRequest = func(ctx context.Context, endpoint, body string, headers map[string]string, proxy string, onLine func(string) error) (int, []byte, int64, []string, error) {
		started := time.Now()
		lines := 0
		contentLines := 0
		var lineShapes []string
		wrapped := func(line string) error {
			lines++
			if len(lineShapes) < 8 {
				lineShapes = append(lineShapes, fmt.Sprintf("length=%d,%s", len(line), diagnosticFrameShape(line)))
			}
			if len(textsInLine(line)) > 0 || reasoningInLine(line) != "" {
				contentLines++
			}
			if onLine != nil {
				return onLine(line)
			}
			return nil
		}
		status, raw, ttfb, cookies, err := oldGeminiSend(ctx, endpoint, body, headers, proxy, wrapped)
		stageMu.Lock()
		stages = append(stages, fmt.Sprintf("generation:status=%d:error=%t:bytes=%d:lines=%d:content_lines=%d:ttfb_ms=%d:%.1fs", status, err != nil, len(raw), lines, contentLines, ttfb, time.Since(started).Seconds()), fmt.Sprintf("line-shapes=%v", lineShapes))
		stageMu.Unlock()
		return status, raw, ttfb, cookies, err
	}
	classifyWebChannelFrame = func(payload json.RawMessage) wcEvent {
		ev := wcClassify(payload)
		if binaryMode {
			binaryEvent := wcBinaryClassify(payload)
			if binaryEvent.Ack || binaryEvent.Done || binaryEvent.End || binaryEvent.Line != "" {
				ev = binaryEvent
			}
		}
		code := 0
		if ev.Err != nil {
			code = ev.Err.Code
		}
		stageMu.Lock()
		if binaryMode && len(frameShapes) < 8 {
			if shape := diagnosticBinaryShape(payload); shape != "" {
				frameShapes = append(frameShapes, "binary:"+shape)
			}
		}
		if len(frames) < 32 {
			frames = append(frames, fmt.Sprintf("at=%.3fs ack=%t done=%t end=%t frame=%t texts=%d reasoning=%t error=%d", time.Since(timelineStart).Seconds(), ev.Ack, ev.Done, ev.End, ev.Line != "", len(textsInLine(ev.Line)), reasoningInLine(ev.Line) != "", code))
		}
		if ev.Line != "" && len(frameShapes) < 8 {
			frameShapes = append(frameShapes, diagnosticFrameShape(ev.Line))
		}
		stageMu.Unlock()
		return ev
	}
	if os.Getenv("GEMINI_DIAGNOSTIC_PRODUCTION_BINARY") == "1" {
		classifyBinaryWebChannelFrame = func(payload json.RawMessage) wcEvent {
			ev := oldBinaryClassify(payload)
			stageMu.Lock()
			if len(frames) < 32 {
				frames = append(frames, fmt.Sprintf("at=%.3fs ack=%t done=%t end=%t frame=%t", time.Since(timelineStart).Seconds(), ev.Ack, ev.Done, ev.End, ev.Line != ""))
			}
			stageMu.Unlock()
			return ev
		}
	}
	var cookieAuditMu sync.Mutex
	issuedCookieValues := map[string]string{}
	webChannelSend = func(ctx context.Context, method, u, body, cookie, proxy string) (*wcResp, error) {
		started := time.Now()
		matchedUpdates, missingUpdates := 0, 0
		cookieAuditMu.Lock()
		for name, value := range issuedCookieValues {
			if cookieValue(cookie, name) == value {
				matchedUpdates++
			} else {
				missingUpdates++
			}
		}
		cookieAuditMu.Unlock()
		stage := "downstream"
		if method == "POST" {
			stage = "post"
			if body == "count=0" {
				stage = "handshake"
			} else if strings.HasPrefix(body, "count=1&ofs=0") {
				stage = "metadata"
			} else if strings.HasPrefix(body, "count=1&ofs=1") {
				stage = "prompt"
			} else if strings.HasPrefix(body, "count=1&ofs=2") {
				stage = "close"
			}
		}
		res, err := wcSend(ctx, method, u, body, cookie, proxy)
		status := 0
		cookieCount := 0
		changedCookies := 0
		sharedCookies := 0
		control := ""
		if res != nil {
			status = res.status
			cookieCount = len(res.setCookie)
			for _, raw := range res.setCookie {
				c, parseErr := http.ParseSetCookie(raw)
				if parseErr != nil {
					continue
				}
				if old := cookieValue(cookie, c.Name); old != "" && old != c.Value {
					changedCookies++
				}
				if strings.EqualFold(strings.TrimPrefix(c.Domain, "."), "google.com") && c.Path == "/" {
					sharedCookies++
					if c.MaxAge >= 0 && c.Value != "" && (c.Expires.IsZero() || c.Expires.After(time.Now())) {
						cookieAuditMu.Lock()
						issuedCookieValues[c.Name] = c.Value
						cookieAuditMu.Unlock()
					}
				}
			}
			if stage == "metadata" || stage == "prompt" {
				body, readErr := io.ReadAll(io.LimitReader(res.body, 4096))
				_ = res.body.Close()
				res.body = io.NopCloser(bytes.NewReader(body))
				var values []int
				if readErr == nil && json.Unmarshal(body, &values) == nil && len(values) <= 8 {
					valid := true
					for _, v := range values {
						if v < 0 || v > 1000000 {
							valid = false
						}
					}
					if valid {
						control = fmt.Sprintf(" control=%v", values)
					}
				}
				if control == "" {
					control = fmt.Sprintf(" control_bytes=%d newlines=%d", len(body), bytes.Count(body, []byte{'\n'}))
				}
			}
		}
		stageMu.Lock()
		stages = append(stages, fmt.Sprintf("%s:%d:error=%t:set_cookies=%d:changed=%d:shared=%d:prior_updates_matched=%d:prior_updates_missing=%d:start=%.3fs:duration=%.3fs%s", stage, status, err != nil, cookieCount, changedCookies, sharedCookies, matchedUpdates, missingUpdates, started.Sub(timelineStart).Seconds(), time.Since(started).Seconds(), control))
		stageMu.Unlock()
		return res, err
	}
	rotateAccountCredentials = func(CookieAccount) (time.Duration, []string, error) {
		return 0, nil, fmt.Errorf("credential refresh disabled for diagnostic")
	}
	rtMu.Lock()
	diagnosticTimeout := 90
	if n, err := strconv.Atoi(os.Getenv("GEMINI_DIAGNOSTIC_TIMEOUT")); err == nil && n >= 5 && n <= 300 {
		diagnosticTimeout = n
	}
	rtVal = RuntimeConfig{RetryAttempts: 1, RequestTimeout: diagnosticTimeout, Impersonate: "chrome_146", GeminiBL: defaultConfig().GeminiBL}
	if build := os.Getenv("GEMINI_DIAGNOSTIC_BUILD"); build != "" {
		if !blValueRe.MatchString(build) {
			rtMu.Unlock()
			t.Fatal("invalid diagnostic build")
		}
		rtVal.GeminiBL = build
	}
	if os.Getenv("GEMINI_DIAGNOSTIC_FIREFOX_TRANSPORT") == "1" {
		rtVal.FirefoxFingerprint = true
	}
	rtMu.Unlock()
	modelName := os.Getenv("GEMINI_DIAGNOSTIC_MODEL")
	if modelName == "" {
		modelName = "gemini-4-argon"
	}
	model, ok := Models[modelName]
	if !ok {
		t.Fatal("unknown diagnostic model")
	}
	model.PinAccountID = id
	selectedModes := 0
	for _, mode := range []struct {
		name string
		wc   bool
	}{{"StreamGenerate", false}, {"WebChannel", true}} {
		if os.Getenv("GEMINI_DIAGNOSTIC_WC_ONLY") == "1" && !mode.wc {
			continue
		}
		if os.Getenv("GEMINI_DIAGNOSTIC_LEGACY_ONLY") == "1" && mode.wc {
			continue
		}
		selectedModes++
		rtMu.Lock()
		rtVal.WebChannel = mode.wc
		rtVal.WebChannelBinary = mode.wc && os.Getenv("GEMINI_DIAGNOSTIC_PRODUCTION_BINARY") == "1"
		rtMu.Unlock()
		started := time.Now()
		var firstContent time.Duration
		var firstReasoning time.Duration
		var emitted strings.Builder
		onDelta := func(s string) {
			emitted.WriteString(s)
			if s != "" && firstContent == 0 {
				firstContent = time.Since(started)
			}
		}
		onReasoning := func(s string) {
			if s != "" && firstReasoning == 0 {
				firstReasoning = time.Since(started)
			}
		}
		prompt := "Reply with exactly OK."
		if n, err := strconv.Atoi(os.Getenv("GEMINI_DIAGNOSTIC_PROMPT_BYTES")); err == nil && n >= 1 && n <= 24000 {
			prompt = strings.Repeat("Neutral test context. ", n/22) + "\nReply with exactly OK."
			t.Logf("Testing prompt size: %d bytes", len(prompt))
		}
		res, callErr := streamGenerateOnce(prompt, "Reply with exactly OK.", model, nil, onDelta, onReasoning, nil)
		{
			stageMu.Lock()
			copyStages := append([]string(nil), stages...)
			copyFrames := append([]string(nil), frames...)
			copyShapes := append([]string(nil), frameShapes...)
			stageMu.Unlock()
			t.Logf("%s stages: %v", mode.name, copyStages)
			if mode.wc {
				t.Logf("Authenticated WebChannel frames: %v", copyFrames)
				t.Logf("Authenticated WebChannel frame shapes: %v", copyShapes)
			}
		}
		if callErr != nil {
			msg := strings.ToLower(callErr.Error())
			category := "other"
			for _, c := range []struct{ needle, name string }{
				{"sorry", "google challenge"}, {"no content frame", "empty upstream response"},
				{"snlm0e", "login token missing"}, {"timeout", "timeout"}, {"超时", "timeout"},
				{"http 429", "upstream rate limit"}, {"http 403", "upstream 403"},
			} {
				if strings.Contains(msg, c.needle) {
					category = c.name
					break
				}
			}
			t.Logf("%s: FAILED after %.1fs, category=%s first_content=%t first_reasoning=%t", mode.name, time.Since(started).Seconds(), category, firstContent != 0, firstReasoning != 0)
			t.Errorf("%s did not complete", mode.name)
			continue
		}
		answerOK := strings.EqualFold(strings.TrimRight(strings.TrimSpace(emitted.String()), ".!。"), "OK")
		modelOK := res.UpstreamModel == model.Upstream
		t.Logf("%s: reported model=%q, first content=%.1fs, total=%.1fs, answer_is_OK=%t, requested_model_confirmed=%t", mode.name, res.UpstreamModel, firstContent.Seconds(), time.Since(started).Seconds(), answerOK, modelOK)
		if !answerOK || !modelOK {
			t.Errorf("%s returned an unexpected answer or model", mode.name)
		}
	}
	if selectedModes == 0 {
		t.Fatal("no transport selected")
	}
}

// Recreate only observed non-secret protobuf fields. The browser's server token,
// extra experiment blob and binary request body are deliberately not copied.
func diagnosticExpandedModelHeader(r wcRequest, build string) string {
	var b []byte
	varint := func(field, value uint64) { b = appendVarint(b, field<<3); b = appendVarint(b, value) }
	data := func(field uint64, value []byte) {
		b = appendVarint(b, field<<3|2)
		b = appendVarint(b, uint64(len(value)))
		b = append(b, value...)
	}
	varint(1, 1)
	if r.HexID != "" {
		data(5, []byte(r.HexID))
	}
	data(7, []byte("ru"))
	varint(8, 0)
	data(9, []byte{4, 33, 5, 6, 8, 16, 19, 20})
	varint(12, 2)
	if r.Mode > 0 {
		varint(15, uint64(r.Mode))
	}
	if r.Think > 0 {
		varint(16, uint64(r.Think))
	}
	data(17, []byte(uuid.NewString()))
	if build != "" {
		nested := appendVarint(nil, 10)
		nested = appendVarint(nested, uint64(len(build)))
		nested = append(nested, build...)
		data(18, nested)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// Assemble a test-only cookie header from default-container, unexpired,
// root-path cookies for gemini.google.com. Never modify either cookie store.
// Reject a different browser account before using or returning any values.
func diagnosticFullFirefoxCookies(existing, path string) (string, error) {
	original := map[string]string{}
	for _, part := range strings.Split(existing, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok {
			original[k] = v
		}
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return "", fmt.Errorf("browser database unavailable")
	}
	defer db.Close()
	rows, err := db.Query("SELECT name, value, host FROM moz_cookies WHERE host IN ('.google.com','gemini.google.com','.gemini.google.com') AND path = '/' AND originAttributes = '' AND expiry > ?", time.Now().Unix())
	if err != nil {
		return "", fmt.Errorf("browser cookies unavailable")
	}
	defer rows.Close()
	values := map[string]string{}
	hosts := map[string]string{}
	for rows.Next() {
		var name, value, host string
		if rows.Scan(&name, &value, &host) != nil {
			return "", fmt.Errorf("browser cookie read failed")
		}
		if name == "" || strings.ContainsAny(name, "\r\n;=") || strings.ContainsAny(value, "\r\n;") {
			continue
		}
		// Prefer the more specific Gemini host when duplicate names exist.
		if _, exists := values[name]; !exists || (hosts[name] == ".google.com" && host != ".google.com") {
			values[name], hosts[name] = value, host
		}
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("browser cookie read failed")
	}
	for _, name := range []string{"SAPISID", "__Secure-1PSID"} {
		if original[name] == "" || values[name] == "" || original[name] != values[name] {
			return "", fmt.Errorf("default browser session does not match selected server account")
		}
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, name+"="+values[name])
	}
	return strings.Join(parts, "; "), nil
}

// Build the cookie header for the actual WebChannel host from Firefox domain
// attributes. Only an anchored matching account may be used; values stay local.
func diagnosticWebChannelCookies(existing, path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("browser database unavailable")
	}
	original := map[string]string{}
	for _, part := range strings.Split(existing, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok {
			original[k] = v
		}
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return "", fmt.Errorf("browser database unavailable")
	}
	defer db.Close()
	rows, err := db.Query("SELECT name, value, host FROM moz_cookies WHERE host IN ('.google.com','.clients6.google.com','geminiweb-pa.clients6.google.com','.geminiweb-pa.clients6.google.com') AND path = '/' AND originAttributes = '' AND expiry > ?", time.Now().Unix())
	if err != nil {
		return "", fmt.Errorf("browser cookies unavailable")
	}
	defer rows.Close()
	values, hosts := map[string]string{}, map[string]string{}
	for rows.Next() {
		var name, value, host string
		if rows.Scan(&name, &value, &host) != nil {
			return "", fmt.Errorf("browser cookie read failed")
		}
		if name == "" || strings.ContainsAny(name, "\r\n;=") || strings.ContainsAny(value, "\r\n;") {
			continue
		}
		if _, exists := values[name]; !exists || len(host) > len(hosts[name]) {
			values[name], hosts[name] = value, host
		}
	}
	if rows.Err() != nil {
		return "", fmt.Errorf("browser cookie read failed")
	}
	for _, name := range []string{"SAPISID", "__Secure-1PSID"} {
		if original[name] == "" || values[name] == "" || original[name] != values[name] {
			return "", fmt.Errorf("browser account mismatch")
		}
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, name+"="+values[name])
	}
	return strings.Join(parts, "; "), nil
}

// Describe only container kinds and sizes, never string contents or IDs.
func diagnosticFrameShape(line string) string {
	var wrapper [][]json.RawMessage
	if json.Unmarshal([]byte(line), &wrapper) != nil || len(wrapper) == 0 || len(wrapper[0]) < 3 {
		return "invalid wrapper"
	}
	var innerString string
	if json.Unmarshal(wrapper[0][2], &innerString) != nil {
		return "invalid inner"
	}
	var inner []json.RawMessage
	if json.Unmarshal([]byte(innerString), &inner) != nil {
		return "inner not array"
	}
	parts := []string{fmt.Sprintf("fields=%d", len(inner))}
	for i := 0; i < len(inner) && i < 12; i++ {
		value := strings.TrimSpace(string(inner[i]))
		if value == "null" || value == "" {
			continue
		}
		kind := string(value[0])
		size := len(value)
		if kind == "[" {
			var a []json.RawMessage
			if json.Unmarshal(inner[i], &a) == nil {
				size = len(a)
			}
		}
		parts = append(parts, fmt.Sprintf("field%d=%s:%d", i, kind, size))
	}
	if len(inner) > 4 {
		var candidates []json.RawMessage
		if json.Unmarshal(inner[4], &candidates) == nil && len(candidates) > 0 {
			var fields []json.RawMessage
			if json.Unmarshal(candidates[0], &fields) == nil {
				parts = append(parts, fmt.Sprintf("candidate_fields=%d", len(fields)))
				if len(fields) > 1 {
					parts = append(parts, fmt.Sprintf("candidate_text_kind=%s", string(fields[1][:1])))
				}
			}
		}
	}
	if len(inner) > 2 {
		var obj map[string]json.RawMessage
		if json.Unmarshal(inner[2], &obj) == nil {
			keys := make([]string, 0, len(obj))
			for key := range obj {
				if _, err := strconv.ParseUint(key, 10, 64); err == nil {
					keys = append(keys, key)
				} else {
					keys = append(keys, "other")
				}
			}
			sort.Strings(keys)
			parts = append(parts, fmt.Sprintf("field2_object_keys=%v", keys))
			var any interface{}
			if json.Unmarshal(inner[2], &any) == nil {
				var codes []int
				var visit func(interface{})
				visit = func(value interface{}) {
					switch v := value.(type) {
					case float64:
						for _, candidate := range []int{403, 429, 1096, 1100, 1155} {
							if v == float64(candidate) {
								codes = append(codes, candidate)
							}
						}
					case []interface{}:
						for _, child := range v {
							visit(child)
						}
					case map[string]interface{}:
						for _, child := range v {
							visit(child)
						}
					}
				}
				visit(any)
				sort.Ints(codes)
				parts = append(parts, fmt.Sprintf("known_codes=%v", codes))
			}
		}
	}
	return strings.Join(parts, ",")
}

// Select only cookies whose names already exist in the server account; require
// both identity anchors to match before using any newer browser values. The
// returned data remains in the test process and its temporary database.
func diagnosticFirefoxCookies(existing, path string) (string, error) {
	original := map[string]string{}
	for _, p := range strings.Split(existing, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if ok {
			original[k] = v
		}
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return "", fmt.Errorf("browser database unavailable")
	}
	defer db.Close()
	rows, err := db.Query("SELECT name,value FROM moz_cookies WHERE host IN ('.google.com','gemini.google.com','.gemini.google.com')")
	if err != nil {
		return "", fmt.Errorf("browser cookies unavailable")
	}
	defer rows.Close()
	values := map[string]string{}
	for rows.Next() {
		var k, v string
		if rows.Scan(&k, &v) != nil {
			return "", fmt.Errorf("browser cookie read failed")
		}
		if _, ok := original[k]; ok || k == "__Secure-1PAPISID" || k == "__Secure-3PAPISID" {
			values[k] = v
		}
	}
	for _, k := range []string{"SAPISID", "__Secure-1PSID"} {
		if original[k] == "" || values[k] == "" || original[k] != values[k] {
			return "", fmt.Errorf("browser session identity does not match selected server account")
		}
	}
	parts := make([]string, 0, len(original))
	for _, p := range strings.Split(existing, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if !ok {
			continue
		}
		if next, ok := values[k]; ok {
			v = next
		}
		parts = append(parts, k+"="+v)
	}
	for _, k := range []string{"__Secure-1PAPISID", "__Secure-3PAPISID"} {
		if _, ok := original[k]; !ok && values[k] != "" {
			parts = append(parts, k+"="+values[k])
		}
	}
	return strings.Join(parts, "; "), rows.Err()
}

// Compare only presence and equality of named session cookies; values never
// leave memory and this test does not send a request or modify either store.
func TestLiveServerCookiePreflight(t *testing.T) {
	path := os.Getenv("GEMINI_DIAGNOSTIC_DB")
	if path == "" || os.Getenv("GEMINI_DIAGNOSTIC_PREFLIGHT") != "1" {
		t.Skip("opt-in account preflight")
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal("source database unavailable")
	}
	defer db.Close()
	var cookie string
	var authuser int
	if err := db.QueryRow("SELECT cookie, authuser FROM accounts WHERE status = 'enabled' ORDER BY id LIMIT 1").Scan(&cookie, &authuser); err != nil {
		t.Fatal("no enabled account")
	}
	old := rtCfg()
	t.Cleanup(func() { rtMu.Lock(); rtVal = old; rtMu.Unlock() })
	rtMu.Lock()
	rtVal = RuntimeConfig{FirefoxFingerprint: true, RequestTimeout: 20}
	rtMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, _, err = fetchAppTokensAndCookiesWithContext(ctx, cookie, authuser, "")
	if err == nil {
		t.Log("Account preflight: session page and token obtained")
		return
	}
	var status *appPageStatusError
	switch {
	case errors.As(err, &status):
		location := "other"
		if strings.Contains(status.Location, "/sorry/") {
			location = "Google challenge"
		} else if strings.Contains(status.Location, "accounts.google.com") {
			location = "Google sign-in"
		} else if status.Location == "" {
			location = "none"
		}
		t.Logf("Account preflight: HTTP status=%d destination=%s", status.Status, location)
	case strings.Contains(err.Error(), "no SNlM0e"):
		t.Log("Account preflight: session token absent")
	case errors.Is(err, context.DeadlineExceeded):
		t.Log("Account preflight: deadline exceeded")
	default:
		t.Log("Account preflight: other request failure")
	}
}

func TestLiveCookiePresence(t *testing.T) {
	serverPath, firefoxPath := os.Getenv("GEMINI_DIAGNOSTIC_DB"), os.Getenv("GEMINI_DIAGNOSTIC_FIREFOX_DB")
	if serverPath == "" || firefoxPath == "" {
		t.Skip("opt-in cookie comparison")
	}
	server, err := sql.Open("sqlite", "file:"+serverPath+"?mode=ro")
	if err != nil {
		t.Fatal("server database unavailable")
	}
	defer server.Close()
	var cookie string
	if err := server.QueryRow("SELECT cookie FROM accounts WHERE status = 'enabled' ORDER BY id LIMIT 1").Scan(&cookie); err != nil {
		t.Fatal("no enabled account")
	}
	original := map[string]string{}
	for _, part := range strings.Split(cookie, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok {
			original[k] = v
		}
	}
	browser, err := sql.Open("sqlite", "file:"+firefoxPath+"?mode=ro")
	if err != nil {
		t.Fatal("browser database unavailable")
	}
	defer browser.Close()
	rows, err := browser.Query("SELECT name, value FROM moz_cookies WHERE host IN ('.google.com','gemini.google.com','.gemini.google.com') AND expiry > ?", time.Now().Unix())
	if err != nil {
		t.Fatal("browser cookie metadata unavailable")
	}
	defer rows.Close()
	values := map[string]map[string]bool{}
	for rows.Next() {
		var name, value string
		if rows.Scan(&name, &value) != nil {
			t.Fatal("browser cookie metadata read failed")
		}
		if values[name] == nil {
			values[name] = map[string]bool{}
		}
		values[name][value] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal("browser cookie metadata read failed")
	}
	for _, name := range keyCookieWants {
		v, inServer := original[name]
		browserValues := values[name]
		t.Logf("cookie-name=%s server_present=%t browser_present=%t matches_any_browser_value=%t", name, inServer, len(browserValues) > 0, inServer && browserValues[v])
	}
	t.Logf("unique cookie names: server=%d browser=%d", len(original), len(values))
}

// Check only whether the public client configuration contains a server-token
// field; never print its value or save the fetched page.
func TestLiveBrowserTokenPresence(t *testing.T) {
	serverPath, firefoxPath := os.Getenv("GEMINI_DIAGNOSTIC_DB"), os.Getenv("GEMINI_DIAGNOSTIC_FIREFOX_DB")
	if serverPath == "" || firefoxPath == "" || os.Getenv("GEMINI_DIAGNOSTIC_TOKEN_PRESENCE") != "1" {
		t.Skip("opt-in session-page comparison")
	}
	db, err := sql.Open("sqlite", "file:"+serverPath+"?mode=ro")
	if err != nil {
		t.Fatal("database unavailable")
	}
	defer db.Close()
	var cookie string
	var authuser int
	if err := db.QueryRow("SELECT cookie,authuser FROM accounts WHERE status = 'enabled' ORDER BY id LIMIT 1").Scan(&cookie, &authuser); err != nil {
		t.Fatal("no enabled account")
	}
	cookie, err = diagnosticFirefoxCookies(cookie, firefoxPath)
	if err != nil {
		t.Fatal("browser session identity mismatch")
	}
	old := rtCfg()
	defer func() { rtMu.Lock(); rtVal = old; rtMu.Unlock() }()
	rtMu.Lock()
	rtVal = RuntimeConfig{RequestTimeout: 20, Impersonate: "chrome_146"}
	rtMu.Unlock()
	page, err := fetchAppPage(cookie, authuser, "")
	if err != nil {
		t.Fatal("session page unavailable")
	}
	match := regexp.MustCompile(`"PI9WOb"\s*:\s*"([^"]*)"`).FindSubmatch(page)
	t.Logf("session page: token_key_present=%t token_value_matched=%t token_length=%d", bytes.Contains(page, []byte("PI9WOb")), len(match) > 1, func() int {
		if len(match) > 1 {
			return len(match[1])
		}
		return 0
	}())
}

// Anonymous comparison needs no account credentials and does not touch the
// running server's database. This is intentionally opt-in and bounded.
func TestLiveAnonymousTransportComparison(t *testing.T) {
	if os.Getenv("GEMINI_DIAGNOSTIC_ANON") != "1" {
		t.Skip("opt-in live diagnostic")
	}
	oldRuntime := rtCfg()
	oldWebChannel := sendWebChannelRequest
	oldWCSend := webChannelSend
	defer func() {
		rtMu.Lock()
		rtVal = oldRuntime
		rtMu.Unlock()
		sendWebChannelRequest = oldWebChannel
		webChannelSend = oldWCSend
	}()
	rtMu.Lock()
	rtVal = RuntimeConfig{RetryAttempts: 1, RequestTimeout: 35, Impersonate: "chrome_146", GeminiBL: defaultConfig().GeminiBL}
	rtMu.Unlock()
	model := Models["gemini-3.6-flash"]
	var stageMu sync.Mutex
	var stages []string
	webChannelSend = func(ctx context.Context, method, u, body, cookie, proxy string) (*wcResp, error) {
		stage := "downstream"
		if method == "POST" {
			stage = "post"
			if body == "count=0" {
				stage = "handshake"
			} else if strings.HasPrefix(body, "count=1&ofs=0") {
				stage = "metadata"
			} else if strings.HasPrefix(body, "count=1&ofs=1") {
				stage = "prompt"
			} else if strings.HasPrefix(body, "count=1&ofs=2") {
				stage = "close"
			}
		}
		res, err := wcSend(ctx, method, u, body, cookie, proxy)
		status := 0
		if res != nil {
			status = res.status
		}
		stageMu.Lock()
		stages = append(stages, fmt.Sprintf("%s:status=%d:error=%t", stage, status, err != nil))
		stageMu.Unlock()
		return res, err
	}
	sendWebChannelRequest = func(ctx context.Context, req wcRequest, proxy string, onLine func(string) error) (int, []byte, int64, []string, error) {
		status, raw, ttfb, cookies, err := doWebChannelRequestWithContext(ctx, req, proxy, onLine)
		stageMu.Lock()
		capturedStages := append([]string(nil), stages...)
		stageMu.Unlock()
		t.Logf("WebChannel stages: %v", capturedStages)
		s := strings.ToLower(string(raw))
		rpcCode := "none"
		if match := regexp.MustCompile(`processsession status ([0-9]+)`).FindStringSubmatch(s); len(match) == 2 {
			rpcCode = match[1]
		}
		var flags []string
		for _, f := range []struct{ needle, name string }{
			{"processsession", "process-session"}, {"握手", "handshake"},
			{"status 7", "rpc-7"}, {"status 16", "rpc-16"}, {"status 2", "rpc-2"},
			{"credential", "credentials"}, {"unregistered", "unregistered"},
			{"bad gateway", "bad-gateway"}, {"invalid", "invalid"},
		} {
			if strings.Contains(s, f.needle) {
				flags = append(flags, f.name)
			}
		}
		t.Logf("WebChannel transport: status=%d, body_bytes=%d, transport_error=%t, rpc_code=%s, flags=%v", status, len(raw), err != nil, rpcCode, flags)
		return status, raw, ttfb, cookies, err
	}
	for _, mode := range []struct {
		name string
		wc   bool
	}{{"StreamGenerate", false}, {"WebChannel", true}} {
		if os.Getenv("GEMINI_DIAGNOSTIC_WC_ONLY") == "1" && !mode.wc {
			continue
		}
		rtMu.Lock()
		rtVal.WebChannel = mode.wc
		rtMu.Unlock()
		started := time.Now()
		var firstContent time.Duration
		var emitted strings.Builder
		res, err := streamGenerateOnce("Reply with exactly OK.", "Reply with exactly OK.", model, nil, func(s string) {
			emitted.WriteString(s)
			if s != "" && firstContent == 0 {
				firstContent = time.Since(started)
			}
		}, nil, nil)
		if err != nil {
			msg := strings.ToLower(err.Error())
			category := "other"
			var flags []string
			for _, f := range []struct{ needle, label string }{
				{"upstream http 502", "upstream-http-502"},
				{"processsession status 7", "rpc-code-7"},
				{"processsession status 16", "rpc-code-16"},
				{"processsession status 2", "rpc-code-2"},
				{"unregistered", "unregistered"},
				{"credentials_missing", "credentials-missing"},
				{"握手", "handshake"},
				{"bad gateway", "bad-gateway"},
			} {
				if strings.Contains(msg, f.needle) {
					flags = append(flags, f.label)
				}
			}
			for _, c := range []struct{ needle, name string }{{"sorry", "google challenge"}, {"no content frame", "empty response"}, {"timeout", "timeout"}, {"429", "rate limit"}, {"d2zjae", "webchannel key absent"}, {"failure reply", "upstream failure reply"}, {"握手没拿到会话", "webchannel handshake missing session"}, {"credential", "credentials rejected"}, {"processsession status 16", "webchannel auth status 16"}, {"http 400", "HTTP 400"}, {"http 401", "HTTP 401"}, {"http 403", "HTTP 403"}, {"http 502", "HTTP 502"}, {"deadline", "deadline"}, {"processsession", "webchannel transport error"}} {
				if strings.Contains(msg, c.needle) {
					category = c.name
					break
				}
			}
			answer := strings.TrimSpace(emitted.String())
			answerOK := strings.EqualFold(strings.TrimRight(answer, ".!。"), "OK")
			t.Logf("%s: FAILED after %.1fs, category=%s flags=%v first_content_emitted=%t answer_is_OK=%t emitted_byte_count=%d", mode.name, time.Since(started).Seconds(), category, flags, firstContent != 0, answerOK, emitted.Len())
			continue
		}
		t.Logf("%s: OK, reported=%q, first content=%.1fs, total=%.1fs, text_emitted=%t", mode.name, res.UpstreamModel, firstContent.Seconds(), time.Since(started).Seconds(), res.Emitted != "")
	}
}
