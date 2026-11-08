package app

// Experimental binary WebChannel codec, derived from the public web client.
import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

// This header is based on the publicly served web client and remains
// experimental: Google may change the private protocol at any time.
func wcBinaryHeaders(apiKey string, r wcRequest, build string) string {
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
	header := strings.Replace(wcHTTPHeaders(apiKey, r), "application/json+protobuf", "application/x-protobuf", 1)
	lines := strings.Split(header, "\r\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "x-goog-ext-525001261-bin:") {
			lines[i] = "x-goog-ext-525001261-bin:" + base64.StdEncoding.EncodeToString(b)
		} else if strings.HasPrefix(strings.ToLower(line), "authorization:") {
			lines[i] = "Authorization:" + wcBinaryAuthorization(r, time.Now().Unix())
		}
	}
	header = strings.Join(lines, "\r\n") + "x-goog-ext-525005358-bin:" + wcTurnHeaderBin(r.TurnID) + "\r\n" +
		"x-goog-ext-73010989-bin:CAA=\r\n" + "x-goog-ext-73010990-bin:CAAQABgA\r\n"
	if r.ServerToken != "" && !strings.ContainsAny(r.ServerToken, "\r\n") {
		header += "X-Server-Token:" + r.ServerToken + "\r\n"
	}
	return header
}

// These signatures are computed from this request's cookies and timestamp;
// they are never copied from a browser capture or logged.
func wcBinaryAuthorization(r wcRequest, timestamp int64) string {
	var parts []string
	for _, item := range []struct{ scheme, value string }{
		{"SAPISIDHASH", r.SAPISID},
		{"SAPISID1PHASH", cookieValue(r.Cookie, "__Secure-1PAPISID")},
		{"SAPISID3PHASH", cookieValue(r.Cookie, "__Secure-3PAPISID")},
	} {
		if item.value == "" {
			continue
		}
		digest := sha1.Sum([]byte(fmt.Sprintf("%d %s https://gemini.google.com", timestamp, item.value)))
		parts = append(parts, fmt.Sprintf("%s %d_%x", item.scheme, timestamp, digest))
	}
	return strings.Join(parts, " ")
}

type wcBinaryField struct {
	number      uint64
	wire        uint64
	numberValue uint64
	data        []byte
}

func wcBinaryParseWire(data []byte) ([]wcBinaryField, error) {
	var out []wcBinaryField
	for len(data) > 0 {
		tag, n := binary.Uvarint(data)
		if n <= 0 || tag>>3 == 0 {
			return nil, fmt.Errorf("invalid protobuf tag")
		}
		data = data[n:]
		f := wcBinaryField{number: tag >> 3, wire: tag & 7}
		switch f.wire {
		case 0:
			v, n := binary.Uvarint(data)
			if n <= 0 {
				return nil, fmt.Errorf("invalid varint")
			}
			f.numberValue = v
			data = data[n:]
		case 2:
			length, n := binary.Uvarint(data)
			if n <= 0 || length > uint64(len(data)-n) {
				return nil, fmt.Errorf("invalid length")
			}
			data = data[n:]
			f.data = data[:length]
			data = data[length:]
		case 1:
			if len(data) < 8 {
				return nil, fmt.Errorf("short fixed64")
			}
			f.data = data[:8]
			data = data[8:]
		case 5:
			if len(data) < 4 {
				return nil, fmt.Errorf("short fixed32")
			}
			f.data = data[:4]
			data = data[4:]
		default:
			return nil, fmt.Errorf("unsupported wire type")
		}
		out = append(out, f)
		if len(out) > 8192 {
			return nil, fmt.Errorf("too many fields")
		}
	}
	return out, nil
}

func wcBinaryMessageField(fields []wcBinaryField, number uint64) []byte {
	for _, f := range fields {
		if f.number == number && f.wire == 2 {
			return f.data
		}
	}
	return nil
}

func wcBinaryNested(data []byte, path ...uint64) []byte {
	for _, number := range path {
		fields, err := wcBinaryParseWire(data)
		if err != nil {
			return nil
		}
		data = wcBinaryMessageField(fields, number)
		if data == nil {
			return nil
		}
	}
	return data
}

var wcBinaryModelHex = regexp.MustCompile(`^[0-9a-f]{16}$`)

// Translate only the text-bearing response variant into the established
// wrb.fr representation. This is still experimental and text-only.
func wcBinaryClassify(payload json.RawMessage) wcEvent {
	data := wcBinaryPayload(payload)
	if len(data) == 0 {
		return wcEvent{}
	}
	fields, err := wcBinaryParseWire(data)
	if err != nil {
		return wcEvent{}
	}
	for _, f := range fields {
		if f.number == 1 && f.wire == 2 && len(f.data) == 0 {
			return wcEvent{Ack: true}
		}
		if (f.number == 4 || f.number == 5) && f.wire == 2 {
			return wcEvent{End: true}
		}
	}
	hue := wcBinaryNested(data, 2, 7, 1)
	if hue == nil {
		return wcEvent{}
	}
	hueFields, err := wcBinaryParseWire(hue)
	if err != nil {
		return wcEvent{}
	}
	done := false
	for _, f := range hueFields {
		if f.number == 1 && f.wire == 0 && f.numberValue == 1 {
			done = true
		}
	}
	response := wcBinaryNested(hue, 4, 4)
	if response == nil {
		return wcEvent{Done: done}
	}
	responseFields, err := wcBinaryParseWire(response)
	if err != nil {
		return wcEvent{Done: done}
	}
	var candidates []interface{}
	for _, f := range responseFields {
		if f.number != 5 || f.wire != 2 {
			continue
		}
		cf, err := wcBinaryParseWire(f.data)
		if err != nil {
			continue
		}
		textBytes := wcBinaryNested(f.data, 2, 1)
		reasoningBytes := wcBinaryNested(f.data, 38, 1, 1)
		if (len(textBytes) == 0 || !utf8.Valid(textBytes)) && (len(reasoningBytes) == 0 || !utf8.Valid(reasoningBytes)) {
			continue
		}
		id := wcBinaryMessageField(cf, 1)
		candidate := make([]interface{}, 38)
		candidate[0] = string(id)
		if len(textBytes) > 0 && utf8.Valid(textBytes) {
			candidate[1] = []interface{}{string(textBytes)}
		}
		if len(reasoningBytes) > 0 && utf8.Valid(reasoningBytes) {
			candidate[37] = []interface{}{[]interface{}{string(reasoningBytes)}}
		}
		candidates = append(candidates, candidate)
	}
	inner := make([]interface{}, 43)
	if len(candidates) > 0 {
		inner[4] = candidates
	}
	failure := false
	for _, f := range responseFields {
		if f.number == 32 && f.wire == 0 && f.numberValue != 0 {
			inner[31] = true
			failure = true
		}
	}
	modelHash := string(wcBinaryMessageField(responseFields, 40))
	modelName := string(wcBinaryMessageField(responseFields, 43))
	modelPresent := wcBinaryModelHex.MatchString(modelHash) && modelName != "" && len(modelName) <= 40 && utf8.ValidString(modelName)
	if modelPresent {
		inner[39] = modelHash
		inner[42] = modelName
	}
	// Model and failure metadata can arrive separately from a candidate.
	// Keep them without treating such frames as generated text.
	if len(candidates) == 0 && !modelPresent && !failure {
		return wcEvent{Done: done}
	}
	innerJSON, _ := json.Marshal(inner)
	line, _ := json.Marshal([]interface{}{[]interface{}{"wrb.fr", nil, string(innerJSON)}})
	return wcEvent{Done: done, Line: string(line)}
}

func wcBinaryPayload(payload json.RawMessage) []byte {
	var messages []json.RawMessage
	if json.Unmarshal(payload, &messages) != nil || len(messages) == 0 {
		return nil
	}
	var text string
	if json.Unmarshal(messages[0], &text) != nil {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(text)
	}
	if err != nil {
		return nil
	}
	return decoded
}

type wcBinaryProto []byte

func (p wcBinaryProto) number(field int, value uint64) wcBinaryProto {
	p = appendVarint(p, uint64(field<<3))
	return appendVarint(p, value)
}
func (p wcBinaryProto) blob(field int, value []byte) wcBinaryProto {
	p = appendVarint(p, uint64(field<<3|2))
	p = appendVarint(p, uint64(len(value)))
	return append(p, value...)
}
func wcBinaryArray(value interface{}) ([]interface{}, error) {
	a, ok := value.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected message shape")
	}
	return a, nil
}
func wcBinaryInteger(value interface{}) (uint64, error) {
	switch n := value.(type) {
	case int:
		if n >= 0 {
			return uint64(n), nil
		}
	case float64:
		if n >= 0 && n == float64(uint64(n)) {
			return uint64(n), nil
		}
	case bool:
		if n {
			return 1, nil
		}
		return 0, nil
	}
	return 0, fmt.Errorf("unexpected integer value")
}

func wcBinaryEncodeAttachment(value interface{}) ([]byte, error) {
	file, err := wcBinaryArray(value)
	if err != nil || len(file) < 9 {
		return nil, fmt.Errorf("invalid attachment")
	}
	ref, err := wcBinaryArray(file[0])
	if err != nil || len(ref) < 4 {
		return nil, fmt.Errorf("invalid attachment reference")
	}
	path, ok := ref[0].(string)
	if !ok || path == "" {
		return nil, fmt.Errorf("invalid attachment path")
	}
	kind, err := wcBinaryInteger(ref[1])
	if err != nil {
		return nil, err
	}
	mime, ok := ref[3].(string)
	if !ok {
		return nil, fmt.Errorf("invalid attachment type")
	}
	name, ok := file[1].(string)
	if !ok {
		return nil, fmt.Errorf("invalid attachment name")
	}
	for _, v := range file[2:8] {
		if v != nil {
			return nil, fmt.Errorf("unsupported attachment field")
		}
	}
	if ref[2] != nil {
		return nil, fmt.Errorf("unsupported attachment reference")
	}
	meta, err := wcBinaryArray(file[8])
	if err != nil || len(meta) != 1 {
		return nil, fmt.Errorf("invalid attachment metadata")
	}
	zero, err := wcBinaryInteger(meta[0])
	if err != nil {
		return nil, err
	}
	link := wcBinaryProto{}.blob(1, []byte(path)).number(2, kind).blob(4, []byte(mime))
	return wcBinaryProto{}.blob(1, link).blob(2, []byte(name)).blob(9, wcBinaryProto{}.number(1, zero)), nil
}

// Encode the subset of GenerateRequest fields used by a text-only request.
// Fail closed for unknown nonempty fields instead of silently losing them.
func wcBinaryEncodeInner(value interface{}) ([]byte, error) {
	inner, err := wcBinaryArray(value)
	if err != nil {
		return nil, err
	}
	var out wcBinaryProto
	ints := map[int]bool{8: true, 11: true, 12: true, 19: true, 28: true, 46: true, 54: true, 68: true, 69: true, 80: true, 81: true, 92: true, 97: true, 99: true}
	for index, value := range inner {
		if value == nil {
			continue
		}
		field := index + 1
		if ints[field] {
			n, err := wcBinaryInteger(value)
			if err != nil {
				return nil, err
			}
			out = out.number(field, n)
			continue
		}
		switch field {
		case 50:
			n, err := wcBinaryInteger(value)
			if err != nil || n != 0 {
				return nil, fmt.Errorf("unsupported populated request field %d", field)
			}
			out = out.number(field, 0)
		case 1, 2, 3, 7, 18, 42, 62:
			a, err := wcBinaryArray(value)
			if err != nil {
				return nil, err
			}
			var nested wcBinaryProto
			for i, item := range a {
				if item == nil {
					continue
				}
				n := i + 1
				switch {
				case field == 1 && (n == 1 || n == 5), field == 2 && n <= 2, field == 3 && (n <= 5 || n == 7 || n == 10):
					str, ok := item.(string)
					if !ok {
						return nil, fmt.Errorf("unexpected string field %d.%d", field, n)
					}
					nested = nested.blob(n, []byte(str))
				case field == 1 && (n == 2 || n == 7), field == 7 && n == 1, field == 42 && n == 1:
					v, err := wcBinaryInteger(item)
					if err != nil {
						return nil, err
					}
					nested = nested.number(n, v)
				case field == 18 && n == 1:
					items, err := wcBinaryArray(item)
					if err != nil || len(items) != 1 {
						return nil, fmt.Errorf("unexpected turn index")
					}
					v, err := wcBinaryInteger(items[0])
					if err != nil {
						return nil, err
					}
					nested = nested.blob(1, wcBinaryProto{}.number(1, v))
				case field == 1 && n == 4:
					files, err := wcBinaryArray(item)
					if err != nil {
						return nil, err
					}
					for _, file := range files {
						encoded, err := wcBinaryEncodeAttachment(file)
						if err != nil {
							return nil, err
						}
						nested = nested.blob(4, encoded)
					}
				default:
					return nil, fmt.Errorf("unsupported populated field %d.%d", field, n)
				}
			}
			out = out.blob(field, nested)
		case 31:
			a, err := wcBinaryArray(value)
			if err != nil {
				return nil, err
			}
			var packed []byte
			for _, item := range a {
				n, err := wcBinaryInteger(item)
				if err != nil {
					return nil, err
				}
				packed = appendVarint(packed, n)
			}
			if len(packed) > 0 {
				out = out.blob(field, packed)
			}
		case 60:
			str, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("unexpected session identifier")
			}
			out = out.blob(field, []byte(str))
		default:
			return nil, fmt.Errorf("unsupported populated request field %d", field)
		}
	}
	return out, nil
}

func wcBinaryEncode(ofs int, value interface{}) (string, error) {
	a, err := wcBinaryArray(value)
	if err != nil {
		return "", err
	}
	var root wcBinaryProto
	switch ofs {
	case 0:
		if len(a) < 1 {
			return "", fmt.Errorf("missing metadata")
		}
		initial, err := wcBinaryArray(a[0])
		if err != nil || len(initial) < 8 {
			return "", fmt.Errorf("invalid metadata")
		}
		meta, err := wcBinaryArray(initial[0])
		if err != nil || len(meta) < 4 {
			return "", fmt.Errorf("invalid request metadata")
		}
		var metadata wcBinaryProto
		source, err := wcBinaryInteger(meta[0])
		if err != nil {
			return "", err
		}
		metadata = metadata.number(1, source)
		for i := 1; i < 4; i++ {
			s, ok := meta[i].(string)
			if !ok {
				return "", fmt.Errorf("invalid metadata string")
			}
			metadata = metadata.blob(i+1, []byte(s))
		}
		v, err := wcBinaryArray(initial[7])
		if err != nil || len(v) < 5 {
			return "", fmt.Errorf("invalid request wrapper")
		}
		wrapped, err := wcBinaryArray(v[4])
		if err != nil || len(wrapped) < 4 {
			return "", fmt.Errorf("invalid generation wrapper")
		}
		inner, err := wcBinaryEncodeInner(wrapped[0])
		if err != nil {
			return "", err
		}
		generation := wcBinaryProto{}.blob(1, inner).number(4, 1)
		parameters := wcBinaryProto{}.blob(5, generation)
		request := wcBinaryProto{}.blob(1, metadata).number(2, 0).blob(8, parameters)
		root = root.blob(1, request)
	case 1:
		if len(a) < 2 {
			return "", fmt.Errorf("missing prompt")
		}
		turn, err := wcBinaryArray(a[1])
		if err != nil || len(turn) < 9 {
			return "", fmt.Errorf("invalid prompt")
		}
		seq, err := wcBinaryInteger(turn[0])
		if err != nil {
			return "", err
		}
		content, err := wcBinaryArray(turn[8])
		if err != nil || len(content) < 1 {
			return "", fmt.Errorf("invalid text")
		}
		text, ok := content[0].(string)
		if !ok {
			return "", fmt.Errorf("invalid text")
		}
		root = root.blob(2, wcBinaryProto{}.number(1, seq).blob(9, wcBinaryProto{}.blob(1, []byte(text))))
	case 2:
		root = root.blob(4, wcBinaryProto{}.number(1, 1))
	default:
		return "", fmt.Errorf("unsupported WebChannel offset")
	}
	return base64.StdEncoding.EncodeToString(root), nil
}
