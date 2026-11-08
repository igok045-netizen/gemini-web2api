package app

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestShortContentFrame(t *testing.T) {
	inner := []interface{}{nil, nil, nil, nil, []interface{}{[]interface{}{"id", []interface{}{"OK"}}}}
	encoded, _ := json.Marshal(inner)
	frame, _ := json.Marshal([]interface{}{[]interface{}{"wrb.fr", nil, string(encoded)}})
	if len(frame) >= 200 {
		t.Fatal("test requires a short frame")
	}
	if got := textsInLine(string(frame)); !reflect.DeepEqual(got, []string{"OK"}) || !hasContentFrame(string(frame)) {
		t.Fatalf("short valid content frame was lost: %v", got)
	}
}

func TestShortFailureFrame(t *testing.T) {
	inner := make([]interface{}, 32)
	inner[31] = true
	encoded, _ := json.Marshal(inner)
	frame, _ := json.Marshal([]interface{}{[]interface{}{"wrb.fr", nil, string(encoded)}})
	if len(frame) >= 200 {
		t.Fatal("test requires a short frame")
	}
	if !failureReplyInLine(string(frame)) {
		t.Fatal("short valid failure frame was lost")
	}
}
