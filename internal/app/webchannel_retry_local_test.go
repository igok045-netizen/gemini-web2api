package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
)

// Google accepts the prompt but the response stream stalls. Exercise the real
// WebChannel orchestration and the generation retry loop, without the network.
func TestWebChannelAcceptedPromptIsNotRetriedOnTimeout(t *testing.T) {
	oldSend, oldKey, oldFetch, oldRuntime, oldGap := webChannelSend, fetchWebChannelAPIKey, fetchAccountXSRF, rtCfg(), webChannelPromptGap
	t.Cleanup(func() {
		webChannelSend, fetchWebChannelAPIKey, fetchAccountXSRF, webChannelPromptGap = oldSend, oldKey, oldFetch, oldGap
		rtMu.Lock()
		rtVal = oldRuntime
		rtMu.Unlock()
	})
	rtMu.Lock()
	rtVal = RuntimeConfig{RetryAttempts: 3, RequestTimeout: 1, WebChannelBinary: true, GeminiBL: defaultConfig().GeminiBL}
	rtMu.Unlock()
	webChannelPromptGap = 0
	fetchWebChannelAPIKey = func(context.Context, string) (string, error) { return "test-key", nil }
	fetchAccountXSRF = func(context.Context, string, int, string) (string, []string, error) { return "test-token", nil, nil }
	id, err := accountAdd("local-webchannel-timeout", "SAPISID=test; __Secure-1PSID=test", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = accountDelete(id) })
	var prompts atomic.Int32
	var pipesMu sync.Mutex
	var pipes []*io.PipeReader
	t.Cleanup(func() {
		pipesMu.Lock()
		defer pipesMu.Unlock()
		for _, pipe := range pipes {
			_ = pipe.Close()
		}
	})
	webChannelSend = func(ctx context.Context, method, u, body, cookie, proxy string) (*wcResp, error) {
		if body == "count=0" {
			return &wcResp{status: 200, sessionID: "gsid", body: io.NopCloser(strings.NewReader("17\n[[1,[\"c\",\"sid\"]]]"))}, nil
		}
		if method == "GET" {
			reader, writer := io.Pipe()
			pipesMu.Lock()
			pipes = append(pipes, reader)
			pipesMu.Unlock()
			go func() {
				encoded, _ := json.Marshal([]string{base64.StdEncoding.EncodeToString(wcBinaryProto{}.blob(1, nil))})
				frame := fmt.Sprintf("[[1,%s]]", encoded)
				_, _ = fmt.Fprintf(writer, "%d\n%s", len(frame), frame)
				<-ctx.Done()
				_ = writer.Close()
			}()
			return &wcResp{status: 200, body: reader}, nil
		}
		if strings.HasPrefix(body, "count=1&ofs=1") {
			prompts.Add(1)
		}
		return &wcResp{status: 200, body: io.NopCloser(strings.NewReader(""))}, nil
	}
	model := Models["gemini-4-argon"]
	model.PinAccountID = id
	_, err = streamGenerateOnce("hello", "hello", model, nil, nil, nil, nil)
	if !errors.Is(err, context.DeadlineExceeded) || prompts.Load() != 1 {
		t.Fatalf("accepted generation was retried or timeout lost: prompts=%d err=%v", prompts.Load(), err)
	}
	var unknown *generationOutcomeUnknown
	if !errors.As(err, &unknown) || !strings.Contains(err.Error(), "gemini_outcome_unknown:") {
		t.Fatal("accepted request timeout did not preserve its unknown-outcome marker")
	}
}

// A transport failure can happen after a prompt reaches Google but before the
// HTTP response reaches us. A metadata-only failure has no such ambiguity.
func TestWebChannelPromptTransportFailureDoesNotRetry(t *testing.T) {
	oldSend, oldKey, oldFetch := webChannelSend, fetchWebChannelAPIKey, fetchAccountXSRF
	oldRuntime, oldGap := rtCfg(), webChannelPromptGap
	oldImmediate, oldBatch := webChannelImmediatePrompt, webChannelBatchPrompt
	t.Cleanup(func() {
		webChannelSend, fetchWebChannelAPIKey, fetchAccountXSRF = oldSend, oldKey, oldFetch
		webChannelPromptGap, webChannelImmediatePrompt, webChannelBatchPrompt = oldGap, oldImmediate, oldBatch
		rtMu.Lock()
		rtVal = oldRuntime
		rtMu.Unlock()
	})
	rtMu.Lock()
	rtVal = RuntimeConfig{RetryAttempts: 3, RequestTimeout: 2, WebChannelBinary: true, GeminiBL: defaultConfig().GeminiBL}
	rtMu.Unlock()
	webChannelPromptGap = 0
	fetchWebChannelAPIKey = func(context.Context, string) (string, error) { return "test-key", nil }
	fetchAccountXSRF = func(context.Context, string, int, string) (string, []string, error) { return "test-token", nil, nil }
	id, err := accountAdd("local-webchannel-delivery", "SAPISID=test; __Secure-1PSID=test", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = accountDelete(id) })
	bodyReadFailure := errors.New("synthetic interrupted response body")
	for _, tc := range []struct {
		name                           string
		immediate, batch, failMetadata bool
		failDownlink                   bool
		failBody                       bool
		httpStatus                     int
		wantAttempts                   int32
		wantUnknown                    bool
	}{
		{"normal prompt", false, false, false, false, false, 0, 1, true},
		{"immediate prompt", true, false, false, false, false, 0, 1, true},
		{"batched prompt", false, true, false, false, false, 0, 1, true},
		{"metadata only", false, false, true, false, false, 0, 3, false},
		{"prompt response body lost", false, false, false, false, true, 0, 1, true},
		{"metadata response body lost", false, false, true, false, true, 0, 3, false},
		{"prompt rate limited", false, false, false, false, false, 429, 1, false},
		{"prompt rate limited body lost", false, false, false, false, true, 429, 1, false},
		{"metadata rate limited", false, false, true, false, false, 429, 1, false},
		{"downlink rate limited", false, false, false, true, false, 429, 1, false},
		{"metadata unavailable", false, false, true, false, false, 503, 3, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			webChannelImmediatePrompt, webChannelBatchPrompt = tc.immediate, tc.batch
			var failed atomic.Int32
			webChannelSend = func(ctx context.Context, method, u, body, cookie, proxy string) (*wcResp, error) {
				if body == "count=0" {
					return &wcResp{status: 200, sessionID: "gsid", body: io.NopCloser(strings.NewReader("17\n[[1,[\"c\",\"sid\"]]]"))}, nil
				}
				if method == "GET" {
					if tc.failDownlink {
						failed.Add(1)
						return &wcResp{status: tc.httpStatus, body: io.NopCloser(strings.NewReader("upstream failure"))}, nil
					}
					reader, writer := io.Pipe()
					go func() {
						encoded, _ := json.Marshal([]string{base64.StdEncoding.EncodeToString(wcBinaryProto{}.blob(1, nil))})
						frame := fmt.Sprintf("[[1,%s]]", encoded)
						_, _ = fmt.Fprintf(writer, "%d\n%s", len(frame), frame)
						<-ctx.Done()
						_ = writer.Close()
					}()
					return &wcResp{status: 200, body: reader}, nil
				}
				isPrompt := strings.HasPrefix(body, "count=1&ofs=1") || strings.HasPrefix(body, "count=2&ofs=0")
				isMetadata := strings.HasPrefix(body, "count=1&ofs=0")
				if (tc.failMetadata && isMetadata) || (!tc.failMetadata && isPrompt) {
					failed.Add(1)
					if tc.failBody {
						status := tc.httpStatus
						if status == 0 {
							status = 200
						}
						return &wcResp{status: status, body: io.NopCloser(iotest.ErrReader(bodyReadFailure))}, nil
					}
					if tc.httpStatus != 0 {
						return &wcResp{status: tc.httpStatus, body: io.NopCloser(strings.NewReader("upstream failure"))}, nil
					}
					return nil, errors.New("connection lost before response")
				}
				return &wcResp{status: 200, body: io.NopCloser(strings.NewReader(""))}, nil
			}
			model := Models["gemini-4-argon"]
			model.PinAccountID = id
			_, err := streamGenerateOnce("hello", "hello", model, nil, nil, nil, nil)
			var unknown *generationOutcomeUnknown
			if err == nil || errors.As(err, &unknown) != tc.wantUnknown || failed.Load() != tc.wantAttempts {
				t.Fatalf("attempts=%d unknown=%v err=%v", failed.Load(), errors.As(err, &unknown), err)
			}
			if tc.failBody && tc.httpStatus == 0 && !errors.Is(err, bodyReadFailure) {
				t.Fatal("response body read failure was hidden")
			}
		})
	}
}

func TestWebChannelRateLimitAfterPromptHasUnknownOutcome(t *testing.T) {
	oldSend, oldKey, oldFetch, oldRuntime, oldGap := webChannelSend, fetchWebChannelAPIKey, fetchAccountXSRF, rtCfg(), webChannelPromptGap
	t.Cleanup(func() {
		webChannelSend, fetchWebChannelAPIKey, fetchAccountXSRF, webChannelPromptGap = oldSend, oldKey, oldFetch, oldGap
		rtMu.Lock()
		rtVal = oldRuntime
		rtMu.Unlock()
	})
	rtMu.Lock()
	rtVal = RuntimeConfig{RetryAttempts: 3, RequestTimeout: 2, WebChannelBinary: true, GeminiBL: defaultConfig().GeminiBL}
	rtMu.Unlock()
	webChannelPromptGap = 0
	fetchWebChannelAPIKey = func(context.Context, string) (string, error) { return "test-key", nil }
	fetchAccountXSRF = func(context.Context, string, int, string) (string, []string, error) { return "test-token", nil, nil }
	id, err := accountAdd("local-webchannel-rate-limit", "SAPISID=test; __Secure-1PSID=test", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = accountDelete(id) })
	var prompts, gets atomic.Int32
	promptSent := make(chan struct{})
	webChannelSend = func(ctx context.Context, method, u, body, cookie, proxy string) (*wcResp, error) {
		if body == "count=0" {
			return &wcResp{status: 200, sessionID: "gsid", body: io.NopCloser(strings.NewReader("17\n[[1,[\"c\",\"sid\"]]]"))}, nil
		}
		if method == "GET" {
			if gets.Add(1) > 1 {
				return &wcResp{status: 429, body: io.NopCloser(strings.NewReader("upstream failure"))}, nil
			}
			reader, writer := io.Pipe()
			go func() {
				encoded, _ := json.Marshal([]string{base64.StdEncoding.EncodeToString(wcBinaryProto{}.blob(1, nil))})
				frame := fmt.Sprintf("[[1,%s]]", encoded)
				_, _ = fmt.Fprintf(writer, "%d\n%s", len(frame), frame)
				select {
				case <-promptSent:
				case <-ctx.Done():
				}
				_ = writer.Close()
			}()
			return &wcResp{status: 200, body: reader}, nil
		}
		if strings.HasPrefix(body, "count=1&ofs=1") {
			if prompts.Add(1) == 1 {
				close(promptSent)
			}
		}
		return &wcResp{status: 200, body: io.NopCloser(strings.NewReader(""))}, nil
	}
	model := Models["gemini-4-argon"]
	model.PinAccountID = id
	_, err = streamGenerateOnce("hello", "hello", model, nil, nil, nil, nil)
	var unknown *generationOutcomeUnknown
	if prompts.Load() != 1 || !errors.As(err, &unknown) {
		t.Fatalf("prompts=%d expected unknown outcome after reconnect: err=%v", prompts.Load(), err)
	}
}

// Rate limits may arrive inside a WebChannel status frame even though the
// downlink itself returned HTTP 200. Exercise both supported status shapes.
func TestWebChannelStatusFrameRateLimitDoesNotRetry(t *testing.T) {
	oldSend, oldKey, oldFetch, oldRuntime, oldGap := webChannelSend, fetchWebChannelAPIKey, fetchAccountXSRF, rtCfg(), webChannelPromptGap
	t.Cleanup(func() {
		webChannelSend, fetchWebChannelAPIKey, fetchAccountXSRF, webChannelPromptGap = oldSend, oldKey, oldFetch, oldGap
		rtMu.Lock()
		rtVal = oldRuntime
		rtMu.Unlock()
	})
	webChannelPromptGap = 0
	fetchWebChannelAPIKey = func(context.Context, string) (string, error) { return "test-key", nil }
	fetchAccountXSRF = func(context.Context, string, int, string) (string, []string, error) { return "test-token", nil, nil }
	id, err := accountAdd("local-webchannel-status", "SAPISID=test; __Secure-1PSID=test", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = accountDelete(id) })
	for _, binaryMode := range []bool{false, true} {
		for _, payload := range []string{
			`{"__sm__":{"status":[[[8,"resource exhausted"]]]}}`,
			`{"__sm__":{"status":[[{"error":{"code":429,"message":"rate limited"}}]]}}`,
		} {
			rtMu.Lock()
			rtVal = RuntimeConfig{RetryAttempts: 3, RequestTimeout: 2, WebChannel: true, WebChannelBinary: binaryMode, GeminiBL: defaultConfig().GeminiBL}
			rtMu.Unlock()
			var prompts atomic.Int32
			var writer *io.PipeWriter
			webChannelSend = func(ctx context.Context, method, u, body, cookie, proxy string) (*wcResp, error) {
				if body == "count=0" {
					return &wcResp{status: 200, sessionID: "gsid", body: io.NopCloser(strings.NewReader("17\n[[1,[\"c\",\"sid\"]]]"))}, nil
				}
				if method == "GET" {
					var reader *io.PipeReader
					reader, writer = io.Pipe()
					go func(w *io.PipeWriter) {
						ack := `[[[]]]`
						if binaryMode {
							encoded, _ := json.Marshal([]string{base64.StdEncoding.EncodeToString(wcBinaryProto{}.blob(1, nil))})
							ack = string(encoded)
						}
						frame := fmt.Sprintf("[[1,%s]]", ack)
						_, _ = fmt.Fprintf(w, "%d\n%s", len(frame), frame)
					}(writer)
					return &wcResp{status: 200, body: reader}, nil
				}
				if strings.HasPrefix(body, "count=1&ofs=1") {
					prompts.Add(1)
					go func(w *io.PipeWriter) {
						frame := fmt.Sprintf("[[2,%s]]", payload)
						_, _ = fmt.Fprintf(w, "%d\n%s", len(frame), frame)
						_ = w.Close()
					}(writer)
				}
				return &wcResp{status: 200, body: io.NopCloser(strings.NewReader(""))}, nil
			}
			model := Models["gemini-4-argon"]
			model.PinAccountID = id
			_, err := streamGenerateOnce("hello", "hello", model, nil, nil, nil, nil)
			if err == nil || !strings.Contains(err.Error(), "HTTP 429") || prompts.Load() != 1 {
				t.Fatalf("binary=%v prompts=%d expected one rate-limited request: err=%v", binaryMode, prompts.Load(), err)
			}
			var failCount int
			if err := getDB().QueryRow("SELECT fail_count FROM accounts WHERE id=?", id).Scan(&failCount); err != nil || failCount != 0 {
				t.Fatalf("rate limit incorrectly marked account as unhealthy: fail_count=%d err=%v", failCount, err)
			}
		}
	}
}
