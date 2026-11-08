package app

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
)

// This is an opt-in, single-request comparison of the optional browser SSE
// endpoint. No prompt, response, account credential or raw frame is logged.
func TestLiveBrowserSSETransport(t *testing.T) {
	path := os.Getenv("GEMINI_DIAGNOSTIC_DB")
	if path == "" || os.Getenv("GEMINI_DIAGNOSTIC_BROWSER_SSE") != "1" {
		t.Skip("opt-in browser SSE diagnostic")
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
		cookie, err = diagnosticFirefoxCookies(cookie, firefox)
		if err != nil {
			t.Fatal("browser session unavailable")
		}
	}
	serverToken := ""
	if os.Getenv("GEMINI_DIAGNOSTIC_SSE_SERVER_TOKEN") == "1" {
		serverToken, err = diagnosticServerToken(cookie, authuser)
		if err != nil {
			t.Fatal("session token unavailable")
		}
	}
	id, err := accountAdd("sse-diagnostic", cookie, "")
	if err != nil {
		t.Fatal("temporary account unavailable")
	}
	t.Cleanup(func() { _ = accountDelete(id) })
	if _, err = getDB().Exec("UPDATE accounts SET authuser=? WHERE id=?", authuser, id); err != nil {
		t.Fatal("temporary account configuration failed")
	}
	oldRuntime, oldSend := rtCfg(), sendWebChannelRequest
	t.Cleanup(func() {
		sendWebChannelRequest = oldSend
		rtMu.Lock()
		rtVal = oldRuntime
		rtMu.Unlock()
	})
	rtMu.Lock()
	rtVal = RuntimeConfig{RetryAttempts: 1, RequestTimeout: 45, WebChannelBinary: true, Impersonate: "chrome_146", GeminiBL: defaultConfig().GeminiBL}
	rtMu.Unlock()
	var statusCode, dataLines, parsedLines, textLines, receivedBytes, readChunks int
	var firstShape string
	sendWebChannelRequest = func(ctx context.Context, r wcRequest, proxy string, onLine func(string) error) (int, []byte, int64, []string, error) {
		ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		apiKey, err := webChannelAPIKey(ctx, "")
		if err != nil {
			return 0, nil, 0, nil, err
		}
		body, err := json.Marshal(r.Inner)
		if err != nil {
			return 0, nil, 0, nil, err
		}
		endpoint := "https://geminiweb-pa.clients6.google.com/v1/conversations:streamGenerate?alt=sse"
		if serverToken != "" {
			endpoint += "&" + url.QueryEscape("$httpHeaders") + "=" + url.QueryEscape("X-Server-Token:"+serverToken+"\r\n")
		}
		req, err := fhttp.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(string(body)))
		if err != nil {
			return 0, nil, 0, nil, safeWCNetworkError(err)
		}
		applyBrowserHeaderValues(req.Header, "same-site")
		for _, line := range strings.Split(wcBinaryHeaders(apiKey, r, currentBL("")), "\r\n") {
			if key, value, found := strings.Cut(line, ":"); found {
				req.Header.Set(key, value)
			}
		}
		req.Header.Set("X-WebChannel-Content-Type", "application/json+protobuf")
		req.Header.Set("Content-Type", "application/json+protobuf")
		req.Header.Set("Accept", "text/event-stream")
		req.Header.Set("Origin", "https://gemini.google.com")
		req.Header.Set("Referer", "https://gemini.google.com/")
		req.Header.Set("Cookie", r.Cookie)
		started := time.Now()
		resp, err := getTLSClient().Do(req)
		if err != nil {
			return 0, nil, 0, nil, safeWCNetworkError(err)
		}
		defer resp.Body.Close()
		statusCode = resp.StatusCode
		if resp.StatusCode != 200 {
			return resp.StatusCode, []byte("SSE upstream rejected request"), 0, nil, nil
		}
		var raw strings.Builder
		reader := &diagnosticCountingReader{r: resp.Body, started: started}
		defer func() { receivedBytes, readChunks = reader.bytes, reader.chunks }()
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			dataLines++
			payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			var fields []json.RawMessage
			if json.Unmarshal([]byte(payload), &fields) != nil {
				continue
			}
			parsedLines++
			wrapped, _ := json.Marshal([]interface{}{[]interface{}{"wrb.fr", nil, payload}})
			text := string(wrapped)
			if firstShape == "" {
				firstShape = diagnosticFrameShape(text)
			}
			if len(textsInLine(text)) > 0 {
				textLines++
			}
			raw.WriteString(text)
			raw.WriteByte('\n')
			if onLine != nil {
				if err := onLine(text); err != nil {
					return resp.StatusCode, []byte(raw.String()), time.Since(started).Milliseconds(), nil, err
				}
			}
		}
		return resp.StatusCode, []byte(raw.String()), time.Since(started).Milliseconds(), nil, scanner.Err()
	}
	model := Models["gemini-4-argon"]
	model.PinAccountID = id
	var response strings.Builder
	started := time.Now()
	_, err = streamGenerateOnce("Reply with exactly OK.", "Reply with exactly OK.", model, nil, func(delta string) { response.WriteString(delta) }, nil, nil)
	t.Logf("SSE status=%d data_lines=%d parsed_lines=%d text_lines=%d bytes=%d chunks=%d exact_reply=%t elapsed=%.1fs error=%t", statusCode, dataLines, parsedLines, textLines, receivedBytes, readChunks, strings.TrimSpace(response.String()) == "OK", time.Since(started).Seconds(), err != nil)
	t.Logf("First SSE frame structure (types, field numbers and sizes only): %s", firstShape)
	if err != nil || strings.TrimSpace(response.String()) != "OK" {
		t.Fatal(fmt.Sprintf("SSE diagnostic did not complete successfully (HTTP %d)", statusCode))
	}
}
