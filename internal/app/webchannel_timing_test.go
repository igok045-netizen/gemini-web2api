package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestChannelTimingOnlyRecordsFixedNonSecretEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "timing.jsonl")
	t.Setenv("GEMINI_WEBCHANNEL_TIMING_FILE", path)
	timing := newChannelTiming()
	timing.markFrameAfterPrompt()
	timing.mark("sensitive-synthetic-value")
	timing.mark("prompt_started")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); timing.markFrameAfterPrompt(); timing.mark("first_content_frame") }()
	}
	wg.Wait()
	timing.finish()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "sensitive-synthetic-value") {
		t.Fatal("unknown data leaked into timing output")
	}
	var record struct {
		Timestamp string           `json:"timestamp_utc"`
		TotalMS   int64            `json:"total_ms"`
		Events    map[string]int64 `json:"events_ms"`
	}
	if err := json.Unmarshal(content, &record); err != nil || record.Timestamp == "" || len(record.Events) != 3 {
		t.Fatal("unexpected timing record")
	}
	for _, key := range []string{"prompt_started", "first_frame_after_prompt", "first_content_frame"} {
		if _, ok := record.Events[key]; !ok {
			t.Fatalf("missing fixed event %s", key)
		}
	}
}

func TestChannelTimingIsOptionalAndDoesNotTruncateFullFile(t *testing.T) {
	t.Setenv("GEMINI_WEBCHANNEL_TIMING_FILE", "")
	if newChannelTiming() != nil {
		t.Fatal("timing enabled without a path")
	}
	path := filepath.Join(t.TempDir(), "full.jsonl")
	data := []byte(strings.Repeat("x", channelTimingMaxBytes))
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GEMINI_WEBCHANNEL_TIMING_FILE", path)
	timing := newChannelTiming()
	timing.mark("ack")
	timing.finish()
	info, err := os.Stat(path)
	if err != nil || info.Size() != channelTimingMaxBytes {
		t.Fatal("full timing file was changed")
	}
}
