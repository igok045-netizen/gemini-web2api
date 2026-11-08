package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// This exercises the user's installed OpenCode against a local fake provider.
// No Google requests, user prompts, account data, or real configuration are used.
func TestLocalOpenCodeRetryGuard(t *testing.T) {
	exe := os.Getenv("GEMINI_DIAGNOSTIC_OPENCODE_CLI")
	if exe == "" {
		t.Skip("installed OpenCode CLI not provided")
	}
	plugin, err := filepath.Abs("opencode-gemini-retry-guard")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name             string
		unknown, enabled bool
		realServer       bool
		partial          bool
		wantCalls        int
		downgraded       bool
	}{
		{"unknown outcome stops", true, true, false, false, 1, false},
		{"ordinary error still retries", false, true, false, false, 2, false},
		{"other provider still retries", true, false, false, false, 2, false},
		{"actual server signals accepted timeout", true, true, true, false, 1, false},
		{"partial stream signals accepted timeout", true, true, true, true, 1, false},
		{"model downgrade stops", true, true, false, false, 1, true},
		{"actual binary model downgrade stops", true, true, true, false, 1, true},
		{"partial stream signals model mismatch", true, true, true, true, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			var upstreamCalls atomic.Int32
			var streamed atomic.Bool
			if tc.realServer {
				oldFetch, oldSend, oldRuntime := fetchAccountXSRF, sendWebChannelRequest, rtCfg()
				t.Cleanup(func() {
					fetchAccountXSRF, sendWebChannelRequest = oldFetch, oldSend
					rtMu.Lock()
					rtVal = oldRuntime
					rtMu.Unlock()
				})
				rtMu.Lock()
				rtVal = RuntimeConfig{RetryAttempts: 3, RequestTimeout: 5, WebChannelBinary: true, GeminiBL: defaultConfig().GeminiBL}
				rtVal.StrictModel = tc.downgraded
				rtMu.Unlock()
				id, err := accountAdd("opencode-retry-guard", "SAPISID=test; __Secure-1PSID=test", "")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = accountDelete(id) })
				fetchAccountXSRF = func(context.Context, string, int, string) (string, []string, error) { return "test-token", nil, nil }
				sendWebChannelRequest = func(_ context.Context, _ wcRequest, _ string, onLine func(string) error) (int, []byte, int64, []string, error) {
					upstreamCalls.Add(1)
					if tc.partial && onLine != nil {
						inner := []interface{}{nil, nil, nil, nil, []interface{}{[]interface{}{"candidate", []interface{}{"Partial test output"}}}}
						encoded, _ := json.Marshal(inner)
						line, _ := json.Marshal([]interface{}{[]interface{}{"wrb.fr", nil, string(encoded)}})
						if err := onLine(string(line)); err != nil {
							return http.StatusOK, line, 1, nil, err
						}
					}
					if tc.downgraded && onLine != nil {
						modelOnly := wcBinaryProto{}.blob(40, []byte("cf41b0e0dd7d53e5")).blob(43, []byte("3.5 Flash-Lite"))
						payload := wcBinaryProto{}.blob(2, wcBinaryProto{}.blob(7, wcBinaryProto{}.blob(1, wcBinaryProto{}.blob(4, wcBinaryProto{}.blob(4, modelOnly)))))
						encoded, _ := json.Marshal([]string{base64.StdEncoding.EncodeToString(payload)})
						if err := onLine(wcBinaryClassify(encoded).Line); err != nil {
							return http.StatusOK, nil, 1, nil, err
						}
					}
					return http.StatusOK, nil, 1, nil, context.DeadlineExceeded
				}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" {
					http.NotFound(w, r)
					return
				}
				n := calls.Add(1)
				if tc.realServer {
					observed := &diagnosticHTTPWriter{ResponseWriter: w}
					handleChatCompletions(observed, r)
					streamed.Store(observed.status == http.StatusOK)
					return
				}
				if n == 1 || (tc.unknown && tc.enabled) {
					w.Header().Set("Content-Type", "application/json")
					status := http.StatusBadGateway
					w.WriteHeader(status)
					message := "temporary upstream failure"
					if tc.unknown {
						message = "gemini_outcome_unknown: test generation may still finish"
					}
					if tc.downgraded {
						message = "gemini_model_downgraded: upstream reported a different model"
					}
					_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": map[string]string{"message": message, "type": "upstream_error"}})
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				for _, item := range []string{
					`{"id":"test","object":"chat.completion.chunk","created":1,"model":"test","choices":[{"index":0,"delta":{"role":"assistant","content":"OK"},"finish_reason":null}]}`,
					`{"id":"test","object":"chat.completion.chunk","created":1,"model":"test","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
				} {
					fmt.Fprintf(w, "data: %s\n\n", item)
				}
				fmt.Fprint(w, "data: [DONE]\n\n")
			}))
			defer server.Close()
			dir := t.TempDir()
			providers := []string{}
			if tc.enabled {
				providers = append(providers, "diagnostic-local")
			}
			config := map[string]interface{}{
				"plugins": []interface{}{map[string]interface{}{"package": filepath.ToSlash(plugin), "options": map[string]interface{}{"providers": providers}}},
				"providers": map[string]interface{}{"diagnostic-local": map[string]interface{}{
					"name": "Diagnostic", "package": "@opencode/ai/providers/openai-compatible",
					"settings": map[string]interface{}{"baseURL": server.URL + "/v1", "apiKey": "diagnostic-only"},
					"models":   map[string]interface{}{"gemini-4-argon": map[string]interface{}{"name": "Test"}},
				}},
			}
			configJSON, _ := json.Marshal(config)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, exe, "--standalone", "run", "--title", "Diagnostic", "--format", "json", "--model", "diagnostic-local/gemini-4-argon", "Reply OK")
			cmd.WaitDelay = 2 * time.Second
			cmd.Dir = dir
			for _, entry := range os.Environ() {
				key, _, _ := strings.Cut(entry, "=")
				key = strings.ToUpper(key)
				if strings.HasPrefix(key, "OPENCODE_") || strings.HasPrefix(key, "XDG_") || key == "APPDATA" || key == "LOCALAPPDATA" {
					continue
				}
				cmd.Env = append(cmd.Env, entry)
			}
			cmd.Env = append(cmd.Env, "XDG_CONFIG_HOME="+filepath.Join(dir, "config"), "XDG_DATA_HOME="+filepath.Join(dir, "data"), "XDG_STATE_HOME="+filepath.Join(dir, "state"), "XDG_CACHE_HOME="+filepath.Join(dir, "cache"), "APPDATA="+filepath.Join(dir, "appdata"), "LOCALAPPDATA="+filepath.Join(dir, "localappdata"), "OPENCODE_CONFIG_CONTENT="+string(configJSON), "OPENCODE_DISABLE_AUTOUPDATE=true", "OPENCODE_DISABLE_PROJECT_CONFIG=true")
			var out, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &stderr
			err := cmd.Run()
			marker := "gemini_outcome_unknown"
			if tc.downgraded {
				marker = "gemini_model_downgraded"
			}
			if tc.unknown && tc.enabled && !strings.Contains(out.String()+stderr.String(), marker) {
				t.Fatal("unknown-outcome error was not surfaced by OpenCode")
			}
			if tc.realServer && upstreamCalls.Load() != 1 {
				t.Fatalf("actual server sent %d upstream requests", upstreamCalls.Load())
			}
			if tc.partial && (!streamed.Load() || !strings.Contains(out.String(), "Partial test output")) {
				t.Fatal("partial response was not streamed before the failure")
			}
			if ctx.Err() != nil || int(calls.Load()) != tc.wantCalls || (!tc.unknown && err != nil) || (tc.unknown && !tc.enabled && err != nil) {
				t.Fatalf("unexpected local retry behavior: calls=%d want=%d timed_out=%t failed=%t stdout_bytes=%d stderr_bytes=%d", calls.Load(), tc.wantCalls, ctx.Err() != nil, err != nil, out.Len(), stderr.Len())
			}
		})
	}
}
