package app

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

// Replay the user's browser downlink entirely in memory, through the actual
// OpenAI-compatible endpoint. Nothing from the capture is written or logged.
func TestBrowserHARReplayThroughChatEndpoint(t *testing.T) {
	path := os.Getenv("GEMINI_DIAGNOSTIC_BROWSER_HAR")
	if path == "" {
		t.Skip("no browser HAR supplied")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("cannot read browser HAR")
	}
	var capture struct {
		Log struct {
			Entries []struct {
				Request  struct{ Method, URL string }
				Response struct {
					Status  int
					Content struct{ Text string }
				}
			}
		}
	}
	if json.Unmarshal(b, &capture) != nil {
		t.Fatal("cannot parse browser HAR")
	}
	var lines []string
	for _, entry := range capture.Log.Entries {
		u, err := url.Parse(entry.Request.URL)
		if err != nil || u.Hostname() != "geminiweb-pa.clients6.google.com" || u.Path != "/v1/processSession" || entry.Request.Method != "GET" || entry.Response.Status != 200 {
			continue
		}
		if err := wcReadFrames(strings.NewReader(entry.Response.Content.Text), func(item wcItem) bool {
			e := wcBinaryClassify(item.Payload)
			if e.Line != "" {
				lines = append(lines, e.Line)
			}
			return true
		}); err != nil {
			t.Fatal("cannot parse browser downlink")
		}
	}
	raw := strings.Join(lines, "\n")
	expected := extractResponseText(raw)
	if expected == "" {
		t.Fatal("browser response contains no readable text")
	}
	if strings.Contains(expected, "```tool_call") {
		t.Skip("capture contains a tool invocation, not a plain answer")
	}
	oldSend, oldFetch, oldRuntime := sendWebChannelRequest, fetchAccountXSRF, rtCfg()
	t.Cleanup(func() {
		sendWebChannelRequest, fetchAccountXSRF = oldSend, oldFetch
		rtMu.Lock()
		rtVal = oldRuntime
		rtMu.Unlock()
	})
	rtMu.Lock()
	rtVal = RuntimeConfig{RetryAttempts: 1, RequestTimeout: 5, WebChannelBinary: true, GeminiBL: defaultConfig().GeminiBL}
	rtMu.Unlock()
	fetchAccountXSRF = func(context.Context, string, int, string) (string, []string, error) { return "test-token", nil, nil }
	id, err := accountAdd("local-har-replay", "SAPISID=test; __Secure-1PSID=test", "")
	if err != nil {
		t.Fatal("cannot create test account")
	}
	t.Cleanup(func() { _ = accountDelete(id) })
	sendWebChannelRequest = func(ctx context.Context, req wcRequest, proxy string, onLine func(string) error) (int, []byte, int64, []string, error) {
		if onLine != nil {
			for _, line := range lines {
				if err := onLine(line); err != nil {
					return 200, []byte(raw), 1, nil, err
				}
			}
		}
		return 200, []byte(raw), 1, nil, nil
	}
	for _, tc := range []struct{ name, tools string }{
		{"without tools", ""},
		{"with tools", `,"tools":[{"type":"function","function":{"name":"read_file","parameters":{"type":"object","properties":{}}}}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"gemini-4-argon","stream":true,"messages":[{"role":"user","content":"test"}]`+tc.tools+`}`))
			recorder := httptest.NewRecorder()
			handleChatCompletions(recorder, request)
			var got strings.Builder
			for _, line := range strings.Split(recorder.Body.String(), "\n") {
				if !strings.HasPrefix(line, "data: ") {
					continue
				}
				var event struct {
					Choices []struct {
						Delta struct {
							Content string `json:"content"`
						} `json:"delta"`
					} `json:"choices"`
				}
				if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event) == nil {
					for _, choice := range event.Choices {
						got.WriteString(choice.Delta.Content)
					}
				}
			}
			if recorder.Code != 200 || got.String() != expected {
				t.Fatal("endpoint output differs from captured final answer")
			}
		})
	}
}
