package app

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A peer can repeatedly accept the downlink and then close it without a frame.
// The client must not turn that into a tight loop of HTTP requests.
func TestWebChannelEmptyDownlinksAreBackedOff(t *testing.T) {
	oldSend, oldKey := webChannelSend, fetchWebChannelAPIKey
	t.Cleanup(func() { webChannelSend, fetchWebChannelAPIKey = oldSend, oldKey })
	fetchWebChannelAPIKey = func(context.Context, string) (string, error) { return "test-key", nil }
	var gets atomic.Int32
	webChannelSend = func(ctx context.Context, method, u, body, cookie, proxy string) (*wcResp, error) {
		if body == "count=0" {
			return &wcResp{status: 200, sessionID: "gsid", body: io.NopCloser(strings.NewReader("17\n[[1,[\"c\",\"sid\"]]]"))}, nil
		}
		if method == "GET" {
			if gets.Add(1) > 10 {
				return nil, errors.New("too many immediate reconnects")
			}
			return &wcResp{status: 200, body: io.NopCloser(strings.NewReader(""))}, nil
		}
		return &wcResp{status: 200, body: io.NopCloser(strings.NewReader(""))}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	_, _, _, _, err := doWebChannelRequestWithContext(ctx, wcRequest{Inner: []interface{}{[]interface{}{"", 0}}, Prompt: "test"}, "", nil)
	if !errors.Is(err, context.DeadlineExceeded) || gets.Load() > 3 {
		t.Fatalf("empty downlinks reconnected too quickly: gets=%d err=%v", gets.Load(), err)
	}
}
