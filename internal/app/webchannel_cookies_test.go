package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestWebChannelCookiesRejectConflictingIdentity(t *testing.T) {
	for _, header := range []string{
		"SAPISID=one; SAPISID=two; __Secure-1PSID=same",
		"SAPISID=same; __Secure-1PSID=one; __Secure-1PSID=two",
	} {
		if _, err := newWebChannelCookies(header); err == nil {
			t.Fatal("conflicting account identity was accepted")
		}
	}
	if _, err := newWebChannelCookies("SAPISID=same; SAPISID=same; __Secure-1PSID=one"); err != nil {
		t.Fatal("identical duplicate account identity was rejected")
	}
}

func TestWebChannelCookiesRespectDeletionAndIdentity(t *testing.T) {
	state, err := newWebChannelCookies("SAPISID=account-a; __Secure-1PSID=account-b; SIDCC=old")
	if err != nil {
		t.Fatal(err)
	}
	state.apply([]string{
		"SIDCC=; Max-Age=0; Domain=.google.com; Path=/; Secure",
		"SAPISID=account-a; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Domain=.google.com; Path=/; Secure",
		"other-path=bad; Path=/unrelated; Secure",
	})
	header := state.header()
	if cookieValue(header, "SIDCC") != "" || cookieValue(header, "SAPISID") != "account-a" || cookieValue(header, "other-path") != "" {
		t.Fatal("cookie deletion, identity, or path was not respected")
	}
	if len(state.snapshot()) != 0 {
		t.Fatal("deletion or host-scoped cookie was propagated to account storage")
	}
}

func TestWebChannelAppliesScopedCookieUpdates(t *testing.T) {
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
	var handshakeOK, downstreamOK, metadataOK, promptOK bool
	webChannelSend = func(ctx context.Context, method, u, body, cookie, proxy string) (*wcResp, error) {
		if body == "count=0" {
			handshakeOK = cookieValue(cookie, "SIDCC") == "old" && cookieValue(cookie, "SAPISID") == "account-a"
			return &wcResp{status: 200, sessionID: "gsid", body: io.NopCloser(strings.NewReader("17\n[[1,[\"c\",\"sid\"]]]")), setCookie: []string{
				"SIDCC=handshake; Domain=.google.com; Path=/; Secure",
				"SAPISID=other-account; Domain=.google.com; Path=/; Secure",
				"not-google=bad; Domain=.example.com; Path=/; Secure",
			}}, nil
		}
		if method == "GET" {
			sidcc := cookieValue(cookie, "SIDCC")
			downstreamOK = (sidcc == "handshake" || sidcc == "metadata") && cookieValue(cookie, "SAPISID") == "account-a" && cookieValue(cookie, "not-google") == ""
			return &wcResp{status: 200, body: reader, setCookie: []string{
				"SIDCC=downstream; Domain=.google.com; Path=/; Secure",
				"channel-only=local; Path=/v1; Secure",
			}}, nil
		}
		if strings.HasPrefix(body, "count=1&ofs=0") {
			sidcc, local := cookieValue(cookie, "SIDCC"), cookieValue(cookie, "channel-only")
			metadataOK = (sidcc == "handshake" && local == "") || (sidcc == "downstream" && local == "local")
			go frame(1, wcBinaryProto{}.blob(1, nil))
			return &wcResp{status: 200, body: io.NopCloser(strings.NewReader("")), setCookie: []string{"SIDCC=metadata; Domain=.google.com; Path=/; Secure"}}, nil
		}
		if strings.HasPrefix(body, "count=1&ofs=1") {
			sidcc := cookieValue(cookie, "SIDCC")
			promptOK = (sidcc == "metadata" || sidcc == "downstream") && cookieValue(cookie, "channel-only") == "local" && cookieValue(cookie, "SAPISID") == "account-a"
			candidate := wcBinaryProto{}.blob(1, []byte("candidate")).blob(2, wcBinaryProto{}.blob(1, []byte("answer")))
			response := wcBinaryProto{}.blob(5, candidate)
			hue := wcBinaryProto{}.number(1, 1).blob(4, wcBinaryProto{}.blob(4, response))
			go frame(2, wcBinaryProto{}.blob(2, wcBinaryProto{}.blob(7, wcBinaryProto{}.blob(1, hue))))
		}
		if strings.HasPrefix(body, "count=1&ofs=2") {
			go func() { frame(3, wcBinaryProto{}.blob(4, nil)); _ = writer.Close() }()
		}
		return &wcResp{status: http.StatusOK, body: io.NopCloser(strings.NewReader(""))}, nil
	}
	request := wcRequest{Binary: true, Cookie: "SAPISID=account-a; __Secure-1PSID=account-b; SIDCC=old", SAPISID: "account-a", Inner: []interface{}{[]interface{}{"sample", 0, nil, nil, nil, nil, 0}}, Prompt: "sample"}
	status, raw, _, updates, err := doWebChannelRequest(request, "", nil)
	if err != nil || status != 200 || !hasContentFrame(string(raw)) || !handshakeOK || !downstreamOK || !metadataOK || !promptOK {
		t.Fatalf("cookie updates were not applied in order: status=%d err=%v handshake=%t downstream=%t metadata=%t prompt=%t", status, err, handshakeOK, downstreamOK, metadataOK, promptOK)
	}
	joined := strings.Join(updates, "|")
	if !strings.Contains(joined, "SIDCC=metadata") || strings.Contains(joined, "other-account") || strings.Contains(joined, "not-google") || strings.Contains(joined, "channel-only") {
		t.Fatal("wrong cookie updates propagated to shared account store")
	}
}
