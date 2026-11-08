package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestBinaryGenerationKeepsInitialTextEmpty(t *testing.T) {
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
	id, err := accountAdd("local-binary-empty-initial", "SAPISID=test; __Secure-1PSID=test", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = accountDelete(id) })
	called, emptyInitial, promptPresent := false, false, false
	sendWebChannelRequest = func(ctx context.Context, request wcRequest, proxy string, onLine func(string) error) (int, []byte, int64, []string, error) {
		called = true
		if len(request.Inner) > 0 {
			if first, ok := request.Inner[0].([]interface{}); ok && len(first) > 0 {
				emptyInitial = first[0] == ""
			}
		}
		promptPresent = request.Prompt == "test prompt"
		return 0, nil, 0, nil, errors.New("local test stops before network")
	}
	model := Models["gemini-4-argon"]
	model.PinAccountID = id
	_, _ = streamGenerateOnce("test prompt", "test prompt", model, nil, nil, nil, nil)
	if !called || !emptyInitial || !promptPresent {
		t.Fatalf("wrong binary messages: called=%t initial_empty=%t prompt_present=%t", called, emptyInitial, promptPresent)
	}
}

// A server may defer the downlink response headers until it has received
// session metadata, as allowed by streaming HTTP. The client must not wait for
// those headers before sending metadata or both sides wait indefinitely.
func TestWebChannelDownlinkWaitsForMetadata(t *testing.T) {
	oldSend, oldKey, oldRuntime, oldGap := webChannelSend, fetchWebChannelAPIKey, rtCfg(), webChannelPromptGap
	t.Cleanup(func() {
		webChannelSend, fetchWebChannelAPIKey, webChannelPromptGap = oldSend, oldKey, oldGap
		rtMu.Lock()
		rtVal = oldRuntime
		rtMu.Unlock()
	})
	rtMu.Lock()
	rtVal.RequestTimeout = 3
	rtVal.GeminiBLAuto = false
	rtMu.Unlock()
	webChannelPromptGap = 0
	fetchWebChannelAPIKey = func(context.Context, string) (string, error) { return "test-key", nil }
	metadata := make(chan struct{})
	reader, writer := io.Pipe()
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	frame := func(id int, payload []byte) {
		encoded, _ := json.Marshal([]string{base64.StdEncoding.EncodeToString(payload)})
		body := fmt.Sprintf("[[%d,%s]]", id, encoded)
		_, _ = fmt.Fprintf(writer, "%d\n%s", len(body), body)
	}
	webChannelSend = func(ctx context.Context, method, u, body, cookie, proxy string) (*wcResp, error) {
		if body == "count=0" {
			return &wcResp{status: 200, sessionID: "gsid", body: io.NopCloser(strings.NewReader("17\n[[1,[\"c\",\"sid\"]]]"))}, nil
		}
		if method == "GET" {
			select {
			case <-metadata:
				go frame(1, wcBinaryProto{}.blob(1, nil))
				return &wcResp{status: 200, body: reader}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if strings.HasPrefix(body, "count=1&ofs=0") {
			close(metadata)
		}
		if strings.HasPrefix(body, "count=1&ofs=1") {
			candidate := wcBinaryProto{}.blob(1, []byte("candidate")).blob(2, wcBinaryProto{}.blob(1, []byte("answer")))
			response := wcBinaryProto{}.blob(5, candidate)
			hue := wcBinaryProto{}.number(1, 1).blob(4, wcBinaryProto{}.blob(4, response))
			go frame(2, wcBinaryProto{}.blob(2, wcBinaryProto{}.blob(7, wcBinaryProto{}.blob(1, hue))))
		}
		if strings.HasPrefix(body, "count=1&ofs=2") {
			go func() { frame(3, wcBinaryProto{}.blob(4, nil)); _ = writer.Close() }()
		}
		return &wcResp{status: 200, body: io.NopCloser(strings.NewReader(""))}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r := wcRequest{Binary: true, Inner: []interface{}{[]interface{}{"sample", 0, nil, nil, nil, nil, 0}}, Prompt: "sample"}
	status, raw, _, _, err := doWebChannelRequestWithContext(ctx, r, "", nil)
	if err != nil || status != 200 || !hasContentFrame(string(raw)) {
		t.Fatalf("metadata/downlink ordering failed: status=%d err=%v", status, err)
	}
}

// Exercise the real binary transport selection and framing without Google.
func TestBinaryWebChannelIntegration(t *testing.T) {
	oldSend, oldKey, oldRuntime := webChannelSend, fetchWebChannelAPIKey, rtCfg()
	t.Cleanup(func() {
		webChannelSend, fetchWebChannelAPIKey = oldSend, oldKey
		rtMu.Lock()
		rtVal = oldRuntime
		rtMu.Unlock()
	})
	rtMu.Lock()
	rtVal.RequestTimeout = 5
	rtVal.GeminiBLAuto = false
	rtMu.Unlock()
	fetchWebChannelAPIKey = func(context.Context, string) (string, error) { return "test-key", nil }
	reader, writer := io.Pipe()
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	frame := func(id int, payload []byte) {
		encoded, _ := json.Marshal([]string{base64.StdEncoding.EncodeToString(payload)})
		body := fmt.Sprintf("[[%d,%s]]", id, encoded)
		_, _ = fmt.Fprintf(writer, "%d\n%s", len(body), body)
	}
	var metadataOK, promptOK, headerOK bool
	webChannelSend = func(ctx context.Context, method, u, body, cookie, proxy string) (*wcResp, error) {
		if body == "count=0" {
			parsed, _ := url.Parse(u)
			headers := parsed.Query().Get("$httpHeaders")
			headerOK = strings.Contains(headers, "application/x-protobuf") && strings.Contains(headers, "x-goog-ext-525005358-bin:")
			return &wcResp{status: 200, sessionID: "gsid", body: io.NopCloser(strings.NewReader("17\n[[1,[\"c\",\"sid\"]]]"))}, nil
		}
		if method == "GET" {
			return &wcResp{status: 200, body: reader}, nil
		}
		form, err := url.ParseQuery(body)
		if err != nil {
			return nil, err
		}
		binary, err := base64.StdEncoding.DecodeString(form.Get("req0___data__"))
		if err != nil {
			return nil, err
		}
		switch form.Get("ofs") {
		case "0":
			metadataOK = !strings.Contains(string(binary), "sample prompt") && string(wcBinaryNested(binary, 1, 1, 3)) == "ru"
			go frame(1, wcBinaryProto{}.blob(1, nil))
		case "1":
			promptOK = strings.Contains(string(binary), "sample prompt")
			candidate := wcBinaryProto{}.blob(1, []byte("candidate")).blob(2, wcBinaryProto{}.blob(1, []byte("answer")))
			response := wcBinaryProto{}.blob(5, candidate)
			hue := wcBinaryProto{}.number(1, 1).blob(4, wcBinaryProto{}.blob(4, response))
			go frame(2, wcBinaryProto{}.blob(2, wcBinaryProto{}.blob(7, wcBinaryProto{}.blob(1, hue))))
		case "2":
			go func() { frame(3, wcBinaryProto{}.blob(4, nil)); _ = writer.Close() }()
		}
		return &wcResp{status: 200, body: io.NopCloser(strings.NewReader(""))}, nil
	}
	request := wcRequest{Binary: true, Inner: []interface{}{[]interface{}{"", 0, nil, nil, nil, nil, 0}}, Prompt: "sample prompt"}
	status, raw, _, _, err := doWebChannelRequest(request, "", nil)
	if err != nil || status != 200 || !hasContentFrame(string(raw)) || !strings.Contains(string(raw), "answer") {
		t.Fatalf("binary request failed: status=%d err=%v", status, err)
	}
	if !metadataOK || !promptOK || !headerOK {
		t.Fatalf("binary request missing metadata=%t prompt=%t headers=%t", metadataOK, promptOK, headerOK)
	}
}

func TestBinaryWebChannelImmediatePrompt(t *testing.T) {
	testBinaryWebChannelQueuedPrompt(t, false)
}

func TestBinaryWebChannelBatchPrompt(t *testing.T) {
	testBinaryWebChannelQueuedPrompt(t, true)
}

func testBinaryWebChannelQueuedPrompt(t *testing.T, batch bool) {
	oldSend, oldKey, oldRuntime, oldImmediate, oldBatch := webChannelSend, fetchWebChannelAPIKey, rtCfg(), webChannelImmediatePrompt, webChannelBatchPrompt
	t.Cleanup(func() {
		webChannelSend, fetchWebChannelAPIKey, webChannelImmediatePrompt = oldSend, oldKey, oldImmediate
		webChannelBatchPrompt = oldBatch
		rtMu.Lock()
		rtVal = oldRuntime
		rtMu.Unlock()
	})
	rtMu.Lock()
	rtVal.RequestTimeout = 4
	rtVal.GeminiBLAuto = false
	rtMu.Unlock()
	webChannelImmediatePrompt = true
	webChannelBatchPrompt = batch
	fetchWebChannelAPIKey = func(context.Context, string) (string, error) { return "test-key", nil }
	reader, writer := io.Pipe()
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	frame := func(id int, payload []byte) {
		encoded, _ := json.Marshal([]string{base64.StdEncoding.EncodeToString(payload)})
		body := fmt.Sprintf("[[%d,%s]]", id, encoded)
		_, _ = fmt.Fprintf(writer, "%d\n%s", len(body), body)
	}
	webChannelSend = func(ctx context.Context, method, u, body, cookie, proxy string) (*wcResp, error) {
		if body == "count=0" {
			return &wcResp{status: 200, sessionID: "gsid", body: io.NopCloser(strings.NewReader("17\n[[1,[\"c\",\"sid\"]]]"))}, nil
		}
		if method == "GET" {
			return &wcResp{status: 200, body: reader}, nil
		}
		if strings.HasPrefix(body, "count=1&ofs=1") || strings.HasPrefix(body, "count=2&ofs=0") {
			if batch {
				form, err := url.ParseQuery(body)
				if err != nil || form.Get("req0___data__") == "" || form.Get("req1___data__") == "" {
					return nil, fmt.Errorf("missing batched message")
				}
			}
			candidate := wcBinaryProto{}.blob(1, []byte("candidate")).blob(2, wcBinaryProto{}.blob(1, []byte("answer")))
			response := wcBinaryProto{}.blob(5, candidate)
			hue := wcBinaryProto{}.number(1, 1).blob(4, wcBinaryProto{}.blob(4, response))
			go func() {
				frame(1, wcBinaryProto{}.blob(1, nil))
				frame(2, wcBinaryProto{}.blob(2, wcBinaryProto{}.blob(7, wcBinaryProto{}.blob(1, hue))))
			}()
		}
		if strings.HasPrefix(body, "count=1&ofs=2") {
			go func() { frame(3, wcBinaryProto{}.blob(4, nil)); _ = writer.Close() }()
		}
		return &wcResp{status: 200, body: io.NopCloser(strings.NewReader(""))}, nil
	}
	request := wcRequest{Binary: true, Inner: []interface{}{[]interface{}{"sample", 0, nil, nil, nil, nil, 0}}, Prompt: "sample"}
	status, raw, _, _, err := doWebChannelRequest(request, "", nil)
	if err != nil || status != 200 || !hasContentFrame(string(raw)) {
		t.Fatalf("immediate send failed: status=%d err=%v", status, err)
	}
}
