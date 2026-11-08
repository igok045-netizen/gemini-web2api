package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A server can produce downlink content while the prompt POST's response is
// still pending. Streaming should not wait for that independent response.
func TestWebChannelStreamsWhilePromptPostIsPending(t *testing.T) {
	timingPath := filepath.Join(t.TempDir(), "timing.jsonl")
	t.Setenv("GEMINI_WEBCHANNEL_TIMING_FILE", timingPath)
	oldSend, oldKey, oldRuntime, oldGap := webChannelSend, fetchWebChannelAPIKey, rtCfg(), webChannelPromptGap
	t.Cleanup(func() {
		webChannelSend, fetchWebChannelAPIKey, webChannelPromptGap = oldSend, oldKey, oldGap
		rtMu.Lock()
		rtVal = oldRuntime
		rtMu.Unlock()
	})
	rtMu.Lock()
	rtVal.RequestTimeout = 5
	rtMu.Unlock()
	webChannelPromptGap = 0
	fetchWebChannelAPIKey = func(context.Context, string) (string, error) { return "test-key", nil }
	reader, writer := io.Pipe()
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	writeFrame := func(id int, payload string) {
		frame := fmt.Sprintf("[[%d,%s]]", id, payload)
		_, _ = fmt.Fprintf(writer, "%d\n%s", len(frame), frame)
	}
	webChannelSend = func(ctx context.Context, method, u, body, cookie, proxy string) (*wcResp, error) {
		if body == "count=0" {
			return &wcResp{status: 200, sessionID: "gsid", body: io.NopCloser(strings.NewReader("17\n[[1,[\"c\",\"sid\"]]]"))}, nil
		}
		if method == "GET" {
			return &wcResp{status: 200, body: reader}, nil
		}
		switch {
		case strings.HasPrefix(body, "count=1&ofs=0"):
			go writeFrame(1, `[[[]]]`)
		case strings.HasPrefix(body, "count=1&ofs=1"):
			go func() {
				writeFrame(2, wcContentPayload("0"))
				select {
				case <-release:
				case <-ctx.Done():
					return
				}
				writeFrame(3, wcContentPayload("1"))
			}()
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		case strings.HasPrefix(body, "count=1&ofs=2"):
			go func() { writeFrame(4, `[[null,null,null,[]]]`); _ = writer.Close() }()
		}
		return &wcResp{status: 200, body: io.NopCloser(strings.NewReader(""))}, nil
	}
	content := make(chan struct{}, 1)
	result := make(chan error, 1)
	go func() {
		status, _, _, _, err := doWebChannelRequest(wcRequest{Inner: []interface{}{[]interface{}{"", 0}}, Prompt: "test"}, "", func(string) error {
			select {
			case content <- struct{}{}:
			default:
			}
			return nil
		})
		if err == nil && status != 200 {
			err = fmt.Errorf("unexpected status %d", status)
		}
		result <- err
	}()
	select {
	case <-content:
	case <-time.After(750 * time.Millisecond):
		unblock()
		<-result
		t.Fatal("downlink content was delayed until prompt POST returned")
	}
	unblock()
	if err := <-result; err != nil {
		t.Fatalf("stream failed: %v", err)
	}
	data, err := os.ReadFile(timingPath)
	if err != nil {
		t.Fatal("timing record unavailable")
	}
	var record struct {
		Events map[string]int64 `json:"events_ms"`
	}
	if json.Unmarshal(data, &record) != nil {
		t.Fatal("invalid timing record")
	}
	for _, event := range []string{"prompt_started", "prompt_headers", "prompt_response", "first_frame_after_prompt", "first_content_frame", "first_line_delivered", "generation_done", "end"} {
		if _, ok := record.Events[event]; !ok {
			t.Fatalf("missing timing event %s", event)
		}
	}
	if record.Events["first_content_frame"] > record.Events["prompt_response"] {
		t.Fatal("timing did not preserve the early downlink frame")
	}
}

func TestWebChannelPromptFailureAfterContentHasUnknownOutcome(t *testing.T) {
	oldSend, oldKey, oldRuntime, oldGap := webChannelSend, fetchWebChannelAPIKey, rtCfg(), webChannelPromptGap
	t.Cleanup(func() {
		webChannelSend, fetchWebChannelAPIKey, webChannelPromptGap = oldSend, oldKey, oldGap
		rtMu.Lock()
		rtVal = oldRuntime
		rtMu.Unlock()
	})
	rtMu.Lock()
	rtVal.RequestTimeout = 5
	rtMu.Unlock()
	webChannelPromptGap = 0
	fetchWebChannelAPIKey = func(context.Context, string) (string, error) { return "test-key", nil }
	reader, writer := io.Pipe()
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	contentDelivered := make(chan struct{})
	writeFrame := func(id int, payload string) {
		frame := fmt.Sprintf("[[%d,%s]]", id, payload)
		_, _ = fmt.Fprintf(writer, "%d\n%s", len(frame), frame)
	}
	webChannelSend = func(ctx context.Context, method, u, body, cookie, proxy string) (*wcResp, error) {
		if body == "count=0" {
			return &wcResp{status: 200, sessionID: "gsid", body: io.NopCloser(strings.NewReader("17\n[[1,[\"c\",\"sid\"]]]"))}, nil
		}
		if method == "GET" {
			return &wcResp{status: 200, body: reader}, nil
		}
		switch {
		case strings.HasPrefix(body, "count=1&ofs=0"):
			go writeFrame(1, `[[[]]]`)
		case strings.HasPrefix(body, "count=1&ofs=1"):
			go writeFrame(2, wcContentPayload("0"))
			select {
			case <-contentDelivered:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return nil, errors.New("synthetic lost POST response")
		}
		return &wcResp{status: 200, body: io.NopCloser(strings.NewReader(""))}, nil
	}
	status, raw, _, _, err := doWebChannelRequest(wcRequest{Inner: []interface{}{[]interface{}{"", 0}}, Prompt: "test"}, "", func(string) error {
		close(contentDelivered)
		return nil
	})
	var unknown *wcPromptDeliveryUnknown
	if status != 200 || !hasContentFrame(string(raw)) || !errors.As(err, &unknown) {
		t.Fatalf("partial content lost or outcome not marked unknown: status=%d, unknown=%t", status, errors.As(err, &unknown))
	}
}

// A completed downlink can arrive before the prompt POST response carrying a
// cookie update. The final POST must wait and use that update.
func TestWebChannelCompletionWaitsForPromptCookies(t *testing.T) {
	oldSend, oldKey, oldRuntime, oldGap := webChannelSend, fetchWebChannelAPIKey, rtCfg(), webChannelPromptGap
	t.Cleanup(func() {
		webChannelSend, fetchWebChannelAPIKey, webChannelPromptGap = oldSend, oldKey, oldGap
		rtMu.Lock()
		rtVal = oldRuntime
		rtMu.Unlock()
	})
	rtMu.Lock()
	rtVal.RequestTimeout = 5
	rtMu.Unlock()
	webChannelPromptGap = 0
	fetchWebChannelAPIKey = func(context.Context, string) (string, error) { return "test-key", nil }
	reader, writer := io.Pipe()
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	closeCookie := make(chan string, 1)
	writeFrame := func(id int, payload string) {
		frame := fmt.Sprintf("[[%d,%s]]", id, payload)
		_, _ = fmt.Fprintf(writer, "%d\n%s", len(frame), frame)
	}
	webChannelSend = func(ctx context.Context, method, u, body, cookie, proxy string) (*wcResp, error) {
		if body == "count=0" {
			return &wcResp{status: 200, sessionID: "gsid", body: io.NopCloser(strings.NewReader("17\n[[1,[\"c\",\"sid\"]]]"))}, nil
		}
		if method == "GET" {
			return &wcResp{status: 200, body: reader}, nil
		}
		switch {
		case strings.HasPrefix(body, "count=1&ofs=0"):
			go writeFrame(1, `[[[]]]`)
		case strings.HasPrefix(body, "count=1&ofs=1"):
			go writeFrame(2, wcContentPayload("1"))
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return &wcResp{status: 200, setCookie: []string{"SIDCC=fresh; Domain=.google.com; Path=/; Secure"}, body: io.NopCloser(strings.NewReader(""))}, nil
		case strings.HasPrefix(body, "count=1&ofs=2"):
			closeCookie <- cookie
			go func() { writeFrame(3, `[[null,null,null,[]]]`); _ = writer.Close() }()
		}
		return &wcResp{status: 200, body: io.NopCloser(strings.NewReader(""))}, nil
	}
	content := make(chan struct{}, 1)
	result := make(chan error, 1)
	go func() {
		status, _, _, _, err := doWebChannelRequest(wcRequest{Inner: []interface{}{[]interface{}{"", 0}}, Prompt: "test", Cookie: "SIDCC=old"}, "", func(string) error { content <- struct{}{}; return nil })
		if err == nil && status != 200 {
			err = fmt.Errorf("unexpected status %d", status)
		}
		result <- err
	}()
	select {
	case <-content:
	case <-time.After(time.Second):
		unblock()
		<-result
		t.Fatal("completed content not delivered")
	}
	select {
	case <-closeCookie:
		unblock()
		<-result
		t.Fatal("close POST raced ahead of the prompt cookie update")
	case <-time.After(100 * time.Millisecond):
	}
	unblock()
	select {
	case got := <-closeCookie:
		if cookieValue(got, "SIDCC") != "fresh" {
			t.Error("close POST missed updated cookie")
		}
	case <-time.After(time.Second):
		t.Error("close POST was not sent")
	}
	if err := <-result; err != nil {
		t.Fatalf("stream failed: %v", err)
	}
}
