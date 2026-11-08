package app

import (
	"sort"
	"sync"
	"testing"
	"time"
)

// Diagnostic-only timing: labels are fixed by the test and no URLs, headers,
// cookies, prompts, responses or identifiers are recorded.
type diagnosticTimeline struct {
	start  time.Time
	mu     sync.Mutex
	events []diagnosticTimingEvent
}

func TestDiagnosticTimelineRecordsStages(t *testing.T) {
	timeline := newDiagnosticTimeline()
	finish := timeline.measure("request")
	timeline.mark("event")
	finish(200)
	events := timeline.snapshot()
	if len(events) != 2 {
		t.Fatal("timing events missing")
	}
	var request, event bool
	for _, item := range events {
		if item.Label == "request" && item.HTTPStatus == 200 && item.DurationMS >= 0 {
			request = true
		}
		if item.Label == "event" && item.HTTPStatus == 0 {
			event = true
		}
	}
	if !request || !event {
		t.Fatal("timing event shape incorrect")
	}
}

type diagnosticTimingEvent struct {
	Label      string
	StartMS    int64
	DurationMS int64
	HTTPStatus int
}

func newDiagnosticTimeline() *diagnosticTimeline {
	return &diagnosticTimeline{start: time.Now()}
}

func (t *diagnosticTimeline) measure(label string) func(int) {
	started := time.Now()
	return func(status int) {
		t.add(diagnosticTimingEvent{Label: label, StartMS: started.Sub(t.start).Milliseconds(), DurationMS: time.Since(started).Milliseconds(), HTTPStatus: status})
	}
}

func (t *diagnosticTimeline) mark(label string) {
	t.add(diagnosticTimingEvent{Label: label, StartMS: time.Since(t.start).Milliseconds()})
}

func (t *diagnosticTimeline) add(event diagnosticTimingEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.events) < 64 {
		t.events = append(t.events, event)
	}
}

func (t *diagnosticTimeline) snapshot() []diagnosticTimingEvent {
	t.mu.Lock()
	defer t.mu.Unlock()
	events := append([]diagnosticTimingEvent(nil), t.events...)
	sort.SliceStable(events, func(i, j int) bool { return events[i].StartMS < events[j].StartMS })
	return events
}
