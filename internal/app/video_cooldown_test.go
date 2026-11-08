package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// withVideoAccounts adds n signed-in test accounts, stubs the video call and clears the
// cooldowns, all undone after the test.
func withVideoAccounts(t *testing.T, n int, call func(mc ModelConfig) (*StreamResult, error)) []int64 {
	t.Helper()
	var ids []int64
	for i := 0; i < n; i++ {
		id, err := accountAdd(fmt.Sprintf("v%d", i), fmt.Sprintf("SAPISID=dummy%d; SID=x", i), "")
		if err != nil {
			t.Fatalf("add account: %v", err)
		}
		ids = append(ids, id)
	}
	prevCall := videoCall
	videoCall = func(_, _ string, mc ModelConfig, _ []map[string]interface{}, _ []pendingUpload, _, _ func(string)) (string, []ToolCall, *StreamResult, error) {
		res, err := call(mc)
		return "", nil, res, err
	}
	videoCooldownMu.Lock()
	videoCooldown = map[int64]int64{}
	videoCooldownMu.Unlock()
	t.Cleanup(func() {
		videoCall = prevCall
		videoCooldownMu.Lock()
		videoCooldown = map[int64]int64{}
		videoCooldownMu.Unlock()
		for _, id := range ids {
			_ = accountDelete(id)
		}
	})
	return ids
}

func quotaErr() error {
	// 跟 callGemini 的包法一致：取回失败的原因被 %w 包在外层错误里。
	return fmt.Errorf("media generation succeeded but artifact retrieval failed: %w", errVideoQuotaUsed)
}

func newTestJob() *videoJob {
	j := &videoJob{ID: "video_test", Model: "gemini-video", Status: "queued", CreatedAt: time.Now().Unix(), Prompt: "a fox", Size: "720x1280"}
	putVideoJob(j)
	return j
}

// A job that lands on an exhausted account moves to the next one in the same job, and
// the exhausted account is skipped by the next video without another refusal.
func TestVideoJobMovesPastAnExhaustedAccount(t *testing.T) {
	var tried []int64
	var exhausted int64
	withVideoAccounts(t, 3, func(mc ModelConfig) (*StreamResult, error) {
		tried = append(tried, mc.PinAccountID)
		if exhausted == 0 {
			exhausted = mc.PinAccountID
		}
		if mc.PinAccountID == exhausted {
			return &StreamResult{AccountID: mc.PinAccountID}, quotaErr()
		}
		return &StreamResult{AccountID: mc.PinAccountID, Artifacts: []MediaArtifact{{Data: []byte("mp4"), Mime: "video/mp4"}}}, nil
	})
	j := newTestJob()
	runVideoJob(j, nil)
	if j.Status != "completed" || len(tried) != 2 || tried[1] == exhausted || j.accountID != tried[1] {
		t.Fatalf("job should finish on the second account: status=%s err=%q tried=%v", j.Status, j.Error, tried)
	}
	if !videoCoolingAccounts()[exhausted] {
		t.Fatalf("account #%d should be cooling down", exhausted)
	}
	tried = nil
	runVideoJob(newTestJob(), nil)
	if len(tried) != 1 || tried[0] == exhausted {
		t.Fatalf("the next video should skip the exhausted account: tried=%v", tried)
	}
}

// When every account is exhausted the job fails with the pool error and a retry time,
// and new requests get 429 with Retry-After instead of a doomed job.
func TestVideoPoolExhausted(t *testing.T) {
	calls := 0
	withVideoAccounts(t, 2, func(mc ModelConfig) (*StreamResult, error) {
		calls++
		return &StreamResult{AccountID: mc.PinAccountID}, quotaErr()
	})
	j := newTestJob()
	runVideoJob(j, nil)
	if j.Status != "failed" || calls != 2 || !strings.HasPrefix(j.Error, errVideoQuota) || !strings.Contains(j.Error, "every account") || !strings.Contains(j.Error, "retry_after=") {
		t.Fatalf("pool exhausted: status=%s calls=%d err=%q", j.Status, calls, j.Error)
	}
	body, _ := json.Marshal(map[string]any{"prompt": "a fox"})
	w := httptest.NewRecorder()
	handleCreateVideo(w, httptest.NewRequest("POST", "/v1/videos", bytes.NewReader(body)))
	if w.Code != 429 || w.Header().Get("Retry-After") == "" || !strings.Contains(w.Body.String(), `"code":"video_quota_exhausted"`) {
		t.Fatalf("create with an exhausted pool: %d %s", w.Code, w.Body)
	}
	if calls != 2 {
		t.Fatalf("no generation may be attempted while every account cools down: calls=%d", calls)
	}
}

// Cooldowns end on their own; the reset time carried by the refusal replaces the default,
// and one outside the plausible range is ignored.
func TestVideoCooldownExpiresAndLearnsReset(t *testing.T) {
	ids := withVideoAccounts(t, 1, func(ModelConfig) (*StreamResult, error) { return nil, nil })
	markVideoExhausted(ids[0], time.Now().Add(48*time.Hour).Unix())
	if exhausted, at := videoPoolExhausted(); !exhausted || at > time.Now().Add(videoCooldownDefault).Unix() {
		t.Fatalf("implausible reset should fall back to the default: exhausted=%v at=%d", exhausted, at)
	}
	if !errors.Is(fmt.Errorf("wrapped: %w", &videoQuotaError{}), errVideoQuotaUsed) {
		t.Fatal("videoQuotaError must match errVideoQuotaUsed")
	}
	reset := time.Now().Add(3 * time.Hour).Unix()
	markVideoExhausted(ids[0], videoQuotaReset(fmt.Errorf("wrapped: %w", &videoQuotaError{ResetAt: reset})))
	if exhausted, at := videoPoolExhausted(); !exhausted || at != reset {
		t.Fatalf("learned reset: exhausted=%v at=%d want %d", exhausted, at, reset)
	}
	videoCooldownMu.Lock()
	videoCooldown[ids[0]] = time.Now().Add(-time.Second).Unix()
	videoCooldownMu.Unlock()
	if exhausted, _ := videoPoolExhausted(); exhausted || videoCoolingAccounts()[ids[0]] {
		t.Fatal("an expired cooldown should be dropped")
	}
}

// 落到登录态失效的号上也在同一任务里换号；判据是错误类型，不是报错文案。
func TestVideoJobMovesPastASignedOutAccount(t *testing.T) {
	var tried []int64
	withVideoAccounts(t, 2, func(mc ModelConfig) (*StreamResult, error) {
		tried = append(tried, mc.PinAccountID)
		if len(tried) == 1 {
			return &StreamResult{AccountID: mc.PinAccountID}, &pinnedAccountError{ID: mc.PinAccountID, Err: errors.New("no SNlM0e")}
		}
		return &StreamResult{AccountID: mc.PinAccountID, Artifacts: []MediaArtifact{{Data: []byte("mp4"), Mime: "video/mp4"}}}, nil
	})
	j := newTestJob()
	runVideoJob(j, nil)
	if j.Status != "completed" || len(tried) != 2 || tried[0] == tried[1] {
		t.Fatalf("job should finish on the second account: status=%s err=%q tried=%v", j.Status, j.Error, tried)
	}
	if videoCoolingAccounts()[tried[0]] {
		t.Fatal("a signed-out account is not out of video quota and must not be put in the cooldown")
	}
}
