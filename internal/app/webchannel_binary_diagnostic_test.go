package app

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

var diagnosticCIDPattern = regexp.MustCompile(`^c_[0-9a-f]{16}$`)
var diagnosticRIDPattern = regexp.MustCompile(`^r_[0-9a-f]{16}$`)

func TestBinaryBrowserHandshakeFields(t *testing.T) {
	r := wcRequest{Cookie: "SAPISID=root-cookie; __Secure-1PAPISID=one-cookie; __Secure-3PAPISID=three-cookie", SAPISID: "root-cookie", ServerToken: "test-session-token", TurnID: "test-turn"}
	want := "SAPISIDHASH 123_45ae29c2db5635731170079d13e6971df8ac5c1f SAPISID1PHASH 123_9f7957ddb958a2dd4841648d55419b4de5c91774 SAPISID3PHASH 123_353d31b867bbdbbffaa51a3de667276963f3072c"
	if got := wcBinaryAuthorization(r, 123); got != want {
		t.Fatal("session signatures do not match known vectors")
	}
	headers := wcBinaryHeaders("test-key", r, "")
	for _, line := range []string{"X-Server-Token:test-session-token\r\n", "x-goog-ext-73010989-bin:CAA=\r\n", "x-goog-ext-73010990-bin:CAAQABgA\r\n", "SAPISID1PHASH ", "SAPISID3PHASH "} {
		if !strings.Contains(headers, line) {
			t.Errorf("missing expected experimental binary header")
		}
	}
	r.ServerToken = "test\r\nInjected: x"
	if strings.Contains(wcBinaryHeaders("test-key", r, ""), "Injected:") {
		t.Fatal("invalid server token was emitted")
	}
	r.Cookie, r.SAPISID, r.ServerToken = "", "", ""
	if strings.Contains(wcBinaryHeaders("test-key", r, ""), "Authorization:") {
		t.Fatal("anonymous request unexpectedly carries authorization")
	}
}

func TestDiagnosticBrowserRequestFieldsEncode(t *testing.T) {
	original := make([]interface{}, 97)
	original[0] = []interface{}{"", 0, nil, nil, nil, nil, 0}
	original[2] = []interface{}{"", "", ""}
	original[6] = []interface{}{0}
	original[68] = 1
	encoded, err := wcBinaryEncodeInner(diagnosticBrowserRequestFields(original))
	if err != nil {
		t.Fatal(err)
	}
	fields, err := wcBinaryParseWire(encoded)
	if err != nil {
		t.Fatal(err)
	}
	scalars := map[uint64]uint64{}
	for _, f := range fields {
		if f.wire == 0 {
			scalars[f.number] = f.numberValue
		}
	}
	for field, value := range map[uint64]uint64{50: 0, 68: 0, 69: 2, 92: 1, 99: 1} {
		if actual, ok := scalars[field]; !ok || actual != value {
			t.Errorf("field %d missing or incorrect", field)
		}
	}
	if wcBinaryMessageField(fields, 3) != nil {
		t.Fatal("new conversation retained prior conversation metadata")
	}
	if !reflect.DeepEqual(wcBinaryMessageField(fields, 31), []byte{4, 16, 19}) {
		t.Fatal("unexpected packed capability fields")
	}
	if original[68] != 1 || original[2] == nil {
		t.Fatal("diagnostic mutation modified caller's input")
	}
}

// Identifiers are kept only in the diagnostic process and never logged. The
// strict format prevents querying a history that is not the current turn.
func diagnosticBinaryHistoryIDs(payload json.RawMessage) (string, string) {
	data := wcBinaryPayload(payload)
	cid := string(wcBinaryNested(data, 2, 7, 1, 4, 4, 2, 1))
	rid := string(wcBinaryNested(data, 2, 7, 1, 4, 4, 2, 2))
	if !diagnosticCIDPattern.MatchString(cid) {
		cid = ""
	}
	if !diagnosticRIDPattern.MatchString(rid) {
		rid = ""
	}
	return cid, rid
}

func TestDiagnosticBinaryHistoryIDs(t *testing.T) {
	ids := wcBinaryProto{}.blob(1, []byte("c_1234567890abcdef")).blob(2, []byte("r_abcdef1234567890"))
	response := wcBinaryProto{}.blob(2, ids)
	hue := wcBinaryProto{}.blob(4, wcBinaryProto{}.blob(4, response))
	wire := wcBinaryProto{}.blob(2, wcBinaryProto{}.blob(7, wcBinaryProto{}.blob(1, hue)))
	payload, _ := json.Marshal([]string{base64.StdEncoding.EncodeToString(wire)})
	cid, rid := diagnosticBinaryHistoryIDs(payload)
	if cid != "c_1234567890abcdef" || rid != "r_abcdef1234567890" {
		t.Fatal("conversation metadata not recovered")
	}
	if cid, rid := diagnosticBinaryHistoryIDs(json.RawMessage(`["invalid"]`)); cid != "" || rid != "" {
		t.Fatal("invalid identifiers accepted")
	}
}

func diagnosticBinaryShape(payload json.RawMessage) string {
	decoded := wcBinaryPayload(payload)
	if decoded == nil {
		return ""
	}
	return diagnosticWireFields(decoded, 0)
}

// Inspect only wire types, field numbers and lengths. No payload values leave
// the process. Nested parsing is bounded and may represent binary strings as
// messages; it is only a structural hint, not a verified schema.
func diagnosticWireFields(data []byte, depth int) string {
	if depth > 7 || len(data) == 0 {
		return ""
	}
	var parts []string
	for len(data) > 0 && len(parts) < 12 {
		tag, n := binary.Uvarint(data)
		if n <= 0 || tag>>3 == 0 || tag>>3 > 2000 {
			return "invalid"
		}
		data = data[n:]
		field, wire := tag>>3, tag&7
		switch wire {
		case 0:
			_, n = binary.Uvarint(data)
			if n <= 0 {
				return "invalid"
			}
			data = data[n:]
			parts = append(parts, fmt.Sprintf("%d:v", field))
		case 2:
			size, n := binary.Uvarint(data)
			if n <= 0 || size > uint64(len(data)-n) {
				return "invalid"
			}
			data = data[n:]
			part := data[:size]
			data = data[size:]
			nested := diagnosticWireFields(part, depth+1)
			if nested != "" && nested != "invalid" {
				parts = append(parts, fmt.Sprintf("%d:b%d{%s}", field, size, nested))
			} else {
				parts = append(parts, fmt.Sprintf("%d:b%d", field, size))
			}
		case 1:
			if len(data) < 8 {
				return "invalid"
			}
			data = data[8:]
			parts = append(parts, fmt.Sprintf("%d:64", field))
		case 5:
			if len(data) < 4 {
				return "invalid"
			}
			data = data[4:]
			parts = append(parts, fmt.Sprintf("%d:32", field))
		default:
			return "invalid"
		}
	}
	return strings.Join(parts, ",")
}

func TestDiagnosticBinaryWebChannelEncoding(t *testing.T) {
	inner := make([]interface{}, 97)
	inner[0] = []interface{}{"", 0, nil, nil, nil, nil, 0}
	inner[1] = []interface{}{"en"}
	inner[2] = []interface{}{"", "", "", nil, nil, nil, nil, nil, nil, ""}
	inner[6] = []interface{}{0}
	inner[7] = 1
	inner[10] = 1
	inner[11] = 0
	inner[17] = []interface{}{[]interface{}{0}}
	inner[18] = 0
	inner[27] = 1
	inner[30] = []interface{}{4}
	inner[41] = []interface{}{1}
	inner[53] = 0
	inner[59] = "test-turn"
	inner[61] = []interface{}{}
	inner[68] = 1
	inner[79] = 8
	inner[80] = 1
	inner[91] = 0
	inner[96] = 0
	meta := []interface{}{1, "test-model", "en", "test-turn"}
	message := []interface{}{[]interface{}{meta, 0, nil, nil, nil, nil, nil, []interface{}{nil, nil, nil, nil, []interface{}{inner, nil, nil, 1}}}}
	encoded, err := wcBinaryEncode(0, message)
	if err != nil {
		t.Fatal(err)
	}
	b, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(b) < 20 {
		t.Fatal("invalid encoded metadata")
	}
	prompt, err := wcBinaryEncode(1, []interface{}{nil, []interface{}{1, nil, nil, nil, nil, nil, nil, nil, []interface{}{"OK"}}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := base64.StdEncoding.DecodeString(prompt)
	if err != nil || !reflect.DeepEqual(p, []byte{0x12, 0x08, 0x08, 0x01, 0x4a, 0x04, 0x0a, 0x02, 'O', 'K'}) {
		t.Fatalf("unexpected prompt wire structure: %v", p)
	}
	inner[49] = 1
	if _, err := wcBinaryEncodeInner(inner); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatal("expected unsupported media field to be rejected")
	}
}

func TestDiagnosticBinaryTextEvent(t *testing.T) {
	encoded := func(value []byte) json.RawMessage {
		payload, _ := json.Marshal([]string{base64.StdEncoding.EncodeToString(value)})
		return payload
	}
	candidate := wcBinaryProto{}.blob(1, []byte("candidate")).blob(2, wcBinaryProto{}.blob(1, []byte("OK")))
	response := wcBinaryProto{}.blob(5, candidate).blob(40, []byte("1234567890abcdef")).blob(43, []byte("4 Argon"))
	hue := wcBinaryProto{}.number(1, 1).blob(4, wcBinaryProto{}.blob(4, response))
	payload := wcBinaryProto{}.blob(2, wcBinaryProto{}.blob(7, wcBinaryProto{}.blob(1, hue)))
	ev := wcBinaryClassify(encoded(payload))
	if !ev.Done || !reflect.DeepEqual(textsInLine(ev.Line), []string{"OK"}) {
		t.Fatal("binary text or completion flag was lost")
	}
	if extractUpstreamModel(ev.Line) != "4 Argon" {
		t.Fatal("server-reported model was lost")
	}
	modelOnly := wcBinaryProto{}.blob(40, []byte("1234567890abcdef")).blob(43, []byte("4 Argon"))
	modelPayload := wcBinaryProto{}.blob(2, wcBinaryProto{}.blob(7, wcBinaryProto{}.blob(1, wcBinaryProto{}.blob(4, wcBinaryProto{}.blob(4, modelOnly)))))
	modelEvent := wcBinaryClassify(encoded(modelPayload))
	if extractUpstreamModel(modelEvent.Line) != "4 Argon" || hasContentFrame(modelEvent.Line) {
		t.Fatal("separate model metadata was lost or mistaken for content")
	}
	reason := wcBinaryProto{}.blob(38, wcBinaryProto{}.blob(1, wcBinaryProto{}.blob(1, []byte("reason"))))
	marked := wcBinaryProto{}.blob(5, reason).number(32, 1)
	markedPayload := wcBinaryProto{}.blob(2, wcBinaryProto{}.blob(7, wcBinaryProto{}.blob(1, wcBinaryProto{}.blob(4, wcBinaryProto{}.blob(4, marked)))))
	markedEvent := wcBinaryClassify(encoded(markedPayload))
	if reasoningInLine(markedEvent.Line) != "reason" || !failureReplyInLine(markedEvent.Line) {
		t.Fatal("reasoning or upstream failure flag was lost")
	}
	failureOnly := wcBinaryProto{}.number(32, 1)
	failurePayload := wcBinaryProto{}.blob(2, wcBinaryProto{}.blob(7, wcBinaryProto{}.blob(1, wcBinaryProto{}.blob(4, wcBinaryProto{}.blob(4, failureOnly)))))
	failureEvent := wcBinaryClassify(encoded(failurePayload))
	if !failureReplyInLine(failureEvent.Line) || hasContentFrame(failureEvent.Line) {
		t.Fatal("separate failure flag was lost or mistaken for content")
	}
	if !wcBinaryClassify(encoded([]byte{0x0a, 0x00})).Ack {
		t.Fatal("binary acknowledgement not recognized")
	}
	if !wcBinaryClassify(encoded(wcBinaryProto{}.blob(4, nil))).End {
		t.Fatal("binary end not recognized")
	}
}

func TestDiagnosticBinaryAttachment(t *testing.T) {
	file := []interface{}{[]interface{}{"test-ref", 3, nil, "text/plain"}, "message.txt", nil, nil, nil, nil, nil, nil, []interface{}{0}}
	inner := make([]interface{}, 1)
	inner[0] = []interface{}{"test", 0, nil, []interface{}{file}, nil, nil, 0}
	encoded, err := wcBinaryEncodeInner(inner)
	if err != nil {
		t.Fatal(err)
	}
	ref := wcBinaryNested(encoded, 1, 4, 1, 1)
	name := wcBinaryNested(encoded, 1, 4, 2)
	if string(ref) != "test-ref" || string(name) != "message.txt" {
		t.Fatal("attachment reference lost")
	}
}
