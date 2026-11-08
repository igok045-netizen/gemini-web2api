package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"testing"
)

func TestWebChannelTurnIDMatchesBodyAndHeader(t *testing.T) {
	inner := make([]interface{}, 60)
	inner[59] = "diagnostic-turn-id"
	req := wcWithTurnID(wcRequest{Inner: inner, TurnID: "different-id"})
	if req.TurnID != "diagnostic-turn-id" {
		t.Fatal("metadata turn id does not match request body")
	}
	encoded, err := base64.StdEncoding.DecodeString(wcTurnHeaderBin(req.TurnID))
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte{0x0a, byte(len(req.TurnID))}, []byte(req.TurnID)...)
	want = append(want, 0x10, 0x01)
	if string(encoded) != string(want) {
		t.Fatal("unexpected turn-id extension")
	}
	if wcWithTurnID(wcRequest{}).TurnID == "" {
		t.Fatal("missing fallback turn id")
	}
}

func TestWebChannelRequestErrorDoesNotExposeAuthorization(t *testing.T) {
	const secret = "diagnostic-authorization-secret"
	_, err := wcSend(context.Background(), "POST", "https://invalid host/processSession?$httpHeaders=Authorization%3A"+secret, "count=0", "", "")
	if err == nil {
		t.Fatal("expected malformed URL to fail")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("WebChannel error exposed authorization from request URL")
	}
	err = safeWCNetworkError(&url.Error{Op: "Post", URL: "https://example.test/?authorization=" + secret, Err: context.DeadlineExceeded})
	if strings.Contains(err.Error(), secret) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("sanitized timeout leaked credentials or lost its error identity")
	}
}

// Script real WebChannel orchestration without contacting Google. The status
// after an explicitly completed answer is a distinct case from a failure
// before completion or a later authentication failure.
func TestWebChannelPostCompletionStatus(t *testing.T) {
	oldSend, oldKey, oldRuntime := webChannelSend, fetchWebChannelAPIKey, rtCfg()
	t.Cleanup(func() {
		webChannelSend, fetchWebChannelAPIKey = oldSend, oldKey
		rtMu.Lock()
		rtVal = oldRuntime
		rtMu.Unlock()
	})
	rtMu.Lock()
	rtVal.RequestTimeout = 5
	rtMu.Unlock()
	fetchWebChannelAPIKey = func(context.Context, string) (string, error) { return "test-key", nil }

	for _, tt := range []struct {
		name   string
		done   bool
		status int
		want   int
	}{
		{"internal after completion", true, 13, 200},
		{"internal before completion", false, 13, 502},
		{"authentication after completion", true, 16, 401},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reader, writer := io.Pipe()
			t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
			writeFrame := func(id int, payload string) {
				frame := fmt.Sprintf("[[%d,%s]]", id, payload)
				_, _ = fmt.Fprintf(writer, "%d\n%s", len(frame), frame)
			}
			writeStatus := func() {
				writeFrame(3, fmt.Sprintf(`{"__sm__":{"status":[[[%d,"failure"]]]}}`, tt.status))
				_ = writer.Close()
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
						flag := "0"
						if tt.done {
							flag = "1"
						}
						writeFrame(2, wcContentPayload(flag))
						if !tt.done {
							writeStatus()
						}
					}()
				case strings.HasPrefix(body, "count=1&ofs=2"):
					go writeStatus()
				}
				return &wcResp{status: 200, body: io.NopCloser(strings.NewReader(""))}, nil
			}
			status, raw, _, _, err := doWebChannelRequest(wcRequest{Inner: []interface{}{[]interface{}{"", 0}}, Prompt: "test"}, "", nil)
			if err != nil || status != tt.want {
				t.Fatalf("status=%d, err=%v; want %d", status, err, tt.want)
			}
			if tt.want == 200 && !hasContentFrame(string(raw)) {
				t.Fatal("completed answer was lost")
			}
		})
	}
}
