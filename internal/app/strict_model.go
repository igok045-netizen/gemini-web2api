package app

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ModelDowngradedError 表示 strict_model 开着时上游把请求静默降级了。
// 它不是上游故障：同一个号重试只会再降级一次，所以重试循环见到它直接停。
type ModelDowngradedError struct {
	Requested string // 请求模型的显示名（ModelConfig.Upstream）
	Reported  string // 服务端自报实际用的
	AccountID int64  // 被降级的号，0 = 匿名
	// RetryAfter 是全池都在冷却时最早那个号解冻还要多久，0 = 不知道。
	RetryAfter time.Duration
}

func (e *ModelDowngradedError) Error() string {
	if e.Reported == "" {
		if e.RetryAfter > 0 {
			return fmt.Sprintf("gemini_model_downgraded: no eligible account remains for %s after a model mismatch; retry after %s", e.Requested, e.RetryAfter.Round(time.Second))
		}
		return fmt.Sprintf("gemini_model_downgraded: no eligible account remains for %s after a model mismatch", e.Requested)
	}
	return fmt.Sprintf("gemini_model_downgraded: requested %s but upstream reported %s; "+
		"strict model validation is enabled", e.Requested, e.Reported)
}

// 被降级的号按（账号, 模型）冷却：额度按档位算，Argon 用完了 Flash 照样能用，
// 所以不能把整个号停掉。只放内存——重启后每个号最多再被降级一次就重新记上。
type downgradeKey struct {
	accountID int64
	model     string // ModelConfig.Upstream
}

var (
	downgradeMu    sync.Mutex
	downgradeUntil = map[downgradeKey]time.Time{}
)

func markDowngraded(accountID int64, mc ModelConfig) {
	mins := rtCfg().StrictModelCooldownMin
	if accountID == 0 || mins <= 0 {
		return
	}
	downgradeMu.Lock()
	downgradeUntil[downgradeKey{accountID, mc.Upstream}] = time.Now().Add(time.Duration(mins) * time.Minute)
	downgradeMu.Unlock()
}

// coolingAccounts 返回正在为 mc 冷却的号，以及其中最早那个还要多久解冻。顺手清掉过期项。
func coolingAccounts(mc ModelConfig) (map[int64]bool, time.Duration) {
	out := map[int64]bool{}
	var soonest time.Duration
	now := time.Now()
	downgradeMu.Lock()
	defer downgradeMu.Unlock()
	for k, until := range downgradeUntil {
		left := until.Sub(now)
		if left <= 0 {
			delete(downgradeUntil, k)
			continue
		}
		if k.model != mc.Upstream {
			continue
		}
		out[k.accountID] = true
		if soonest == 0 || left < soonest {
			soonest = left
		}
	}
	return out, soonest
}

// pickAccountForModel 挑号，跳过 exclude（本次请求里已经被降级过的）和正在为 mc 冷却的号。
// 返回的 skip 是两者合集，换号重取时要接着用它。
//
// 池里有号但全被跳过时报 *ModelDowngradedError，而不是返回 nil 让请求退成匿名：
// 匿名对登录模型同样是降级，那正是开 strict_model 想避免的。
func pickAccountForModel(mc ModelConfig, exclude map[int64]bool) (*CookieAccount, map[int64]bool, error) {
	skip := map[int64]bool{}
	for id := range exclude {
		skip[id] = true
	}
	var soonest time.Duration
	if rtCfg().StrictModel && mc.Upstream != "" {
		var cooling map[int64]bool
		cooling, soonest = coolingAccounts(mc)
		for id := range cooling {
			skip[id] = true
		}
	}
	if a, ok := pickCookieAccountExcept(skip); ok {
		return a, skip, nil
	}
	if len(skip) > 0 && hasCookie() {
		return nil, skip, &ModelDowngradedError{Requested: mc.Upstream, RetryAfter: soonest}
	}
	return nil, skip, nil
}

// retryOnAnotherAccount 判断一次降级要不要换号重来，要的话先把这个号记进冷却和 exclude。
// 匿名降级没号可换；已经吐过内容的不能重来（客户端会收到两遍）。
func retryOnAnotherAccount(res *StreamResult, err error, mc ModelConfig, exclude map[int64]bool) bool {
	var mde *ModelDowngradedError
	if !errors.As(err, &mde) || mde.AccountID == 0 {
		return false
	}
	markDowngraded(mde.AccountID, mc)
	exclude[mde.AccountID] = true
	logf("[strict_model] 账号 #%d 在 %s 上被降级成 %s", mde.AccountID, mc.Upstream, mde.Reported)
	return res == nil || (res.Emitted == "" && res.EmittedReasoning == "")
}

// A model mismatch is an upstream failure, not proof of a quota limit.
func writeModelDowngraded(w http.ResponseWriter, e *ModelDowngradedError) {
	if e.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(e.RetryAfter.Seconds()))))
	}
	writeJSON(w, http.StatusBadGateway, map[string]interface{}{"error": map[string]string{
		"message": e.Error(),
		"type":    "upstream_error",
		"code":    "model_downgraded",
	}})
}

// strictLineCheck 返回逐行检查降级的函数；开关关着或模型没登记 Upstream 时返回 nil。
// 每行先过它再转发正文：显示名跟第一段正文在同一行或更早出现（2026-10-24 实测
// 逐行看过），所以先查再发就能在第一个字出去之前掐断。
func strictLineCheck(mc ModelConfig, accountID func() int64) func(line string) error {
	if !rtCfg().StrictModel || mc.Upstream == "" {
		return nil
	}
	return func(line string) error {
		if name := extractUpstreamModel(line); name != "" && modelDowngraded(mc, name) {
			return &ModelDowngradedError{Requested: mc.Upstream, Reported: name, AccountID: accountID()}
		}
		return nil
	}
}

// modelNameFoldRe 把字母数字和点以外的东西都折成空格：连字符、全角后缀（"扩展"）
// 一并抹掉，"3.5 Flash-Lite" 和 "3.5 flash lite" 才比得上。
var modelNameFoldRe = regexp.MustCompile(`[^a-z0-9.]+`)

func foldModelName(s string) string {
	return strings.TrimSpace(modelNameFoldRe.ReplaceAllString(strings.ToLower(s), " "))
}

// modelDowngraded 判断服务端自报的显示名是不是请求的那个模型。
//
// 按「整词前缀」比：思考档会在名字后面挂后缀（"3.1 Pro High"、"3.6 Flash 扩展"），
// 后缀改过名（扩展 → High），所以只认前缀；但必须断在词边界，否则 "3.5 Flash" 会
// 把 "3.5 Flash-Lite" 当成自己。
//
// 看不见就不判：没自报（reported 为空）或模型没登记 Upstream 一律当没降级——
// 误报会让开了开关的人白白丢请求，比漏判更伤。
func modelDowngraded(mc ModelConfig, reported string) bool {
	want := foldModelName(mc.Upstream)
	got := foldModelName(reported)
	if want == "" || got == "" {
		return false
	}
	return got != want && !strings.HasPrefix(got, want+" ")
}
