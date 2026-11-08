package app

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Optional local timing only: neither request data nor account, address,
// headers, response contents or identifiers are accepted by this recorder.
// A full file is left untouched rather than being rotated or truncated.
const channelTimingMaxBytes = 2 << 20

var channelTimingFileMu sync.Mutex

type channelTiming struct {
	started time.Time
	path    string
	mu      sync.Mutex
	events  map[string]int64
}

func newChannelTiming() *channelTiming {
	path := os.Getenv("GEMINI_WEBCHANNEL_TIMING_FILE")
	if path == "" {
		return nil
	}
	return &channelTiming{started: time.Now(), path: path, events: make(map[string]int64)}
}

func (d *channelTiming) mark(label string) {
	if d == nil {
		return
	}
	// Restrict both the schema and the output values to fixed, non-secret data.
	switch label {
	case "session_key", "handshake", "downlink_ready", "metadata_post", "ack", "prompt_started", "prompt_headers", "prompt_response", "first_frame_after_prompt", "first_content_frame", "first_line_delivered", "generation_done", "end":
	default:
		return
	}
	d.mu.Lock()
	if _, exists := d.events[label]; !exists {
		d.events[label] = time.Since(d.started).Milliseconds()
	}
	d.mu.Unlock()
}

func (d *channelTiming) markFrameAfterPrompt() {
	if d == nil {
		return
	}
	d.mu.Lock()
	if _, started := d.events["prompt_started"]; started {
		if _, exists := d.events["first_frame_after_prompt"]; !exists {
			d.events["first_frame_after_prompt"] = time.Since(d.started).Milliseconds()
		}
	}
	d.mu.Unlock()
}

func (d *channelTiming) finish() {
	if d == nil {
		return
	}
	d.mu.Lock()
	record := struct {
		Timestamp string           `json:"timestamp_utc"`
		TotalMS   int64            `json:"total_ms"`
		EventsMS  map[string]int64 `json:"events_ms"`
	}{d.started.UTC().Format(time.RFC3339Nano), time.Since(d.started).Milliseconds(), make(map[string]int64, len(d.events))}
	for key, value := range d.events {
		record.EventsMS[key] = value
	}
	d.mu.Unlock()
	line, err := json.Marshal(record)
	if err != nil {
		return
	}
	channelTimingFileMu.Lock()
	defer channelTimingFileMu.Unlock()
	f, err := os.OpenFile(d.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size()+int64(len(line))+1 > channelTimingMaxBytes {
		return
	}
	_, _ = f.Write(append(line, '\n'))
}
