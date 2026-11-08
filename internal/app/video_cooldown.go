package app

// Video quota routing. An account whose video budget is used up is skipped for new
// videos until it resets, and a job that lands on such an account is moved to the next
// account inside the same job (a quota refusal consumes nothing). When every enabled
// account is in its cooldown, POST /v1/videos answers 429 video_quota_exhausted with
// Retry-After, and a running job fails with the same code and the earliest reset, so
// the client can wait instead of resubmitting into a pool that cannot make videos.
//
// 冷却到 Google 写在拒绝那一轮里的重置时间（videoQuotaError.ResetAt）；那一轮没写时
// 按 videoCooldownDefault。只放内存：重启后每个用完的号再被拒一次（不耗额度）就记回来。

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

const (
	videoCooldownDefault = time.Hour
	videoCooldownMax     = quotaWindow + time.Hour
)

var (
	videoCooldownMu sync.Mutex
	videoCooldown   = map[int64]int64{} // account id → unix time its video budget resets
)

// markVideoExhausted 把号放进视频冷却，到 reset（unix 秒）为止。reset 不在
// (现在, 现在+videoCooldownMax] 里（0 = 拒绝里没写，或时间戳不像重置时间）就按默认时长。
func markVideoExhausted(id, reset int64) {
	if id <= 0 {
		return
	}
	now := time.Now()
	until := now.Add(videoCooldownDefault).Unix()
	if reset > now.Unix() && reset <= now.Add(videoCooldownMax).Unix() {
		until = reset
	}
	videoCooldownMu.Lock()
	videoCooldown[id] = until
	videoCooldownMu.Unlock()
	logf("[video] 账号 #%d 视频额度用完，%s 前新视频跳过它", id, time.Unix(until, 0).Format("15:04"))
}

// videoCoolingAccounts returns the accounts still in their cooldown (expired ones are dropped).
func videoCoolingAccounts() map[int64]bool {
	now := time.Now().Unix()
	videoCooldownMu.Lock()
	defer videoCooldownMu.Unlock()
	out := map[int64]bool{}
	for id, until := range videoCooldown {
		if until <= now {
			delete(videoCooldown, id)
			continue
		}
		out[id] = true
	}
	return out
}

// videoPoolExhausted reports whether every enabled account is cooling down, and when the
// first of them resets.
func videoPoolExhausted() (bool, int64) {
	cooling := videoCoolingAccounts()
	var resets []int64
	enabled := 0
	videoCooldownMu.Lock()
	defer videoCooldownMu.Unlock()
	for _, a := range accountList() {
		if a.Status != "enabled" {
			continue
		}
		enabled++
		if !cooling[a.ID] {
			return false, 0
		}
		resets = append(resets, videoCooldown[a.ID])
	}
	if enabled == 0 {
		return false, 0
	}
	sort.Slice(resets, func(i, j int) bool { return resets[i] < resets[j] })
	return true, resets[0]
}

// videoPoolExhaustedError is the job error when no account can make a video right now.
func videoPoolExhaustedError(reset int64) string {
	return fmt.Sprintf("%s: every account is out of video quota; the first resets at %s (retry_after=%d)",
		errVideoQuota, time.Unix(reset, 0).Format("15:04"), retryAfterSeconds(reset))
}

func retryAfterSeconds(reset int64) int64 {
	if s := reset - time.Now().Unix(); s > 0 {
		return s
	}
	return 60
}
