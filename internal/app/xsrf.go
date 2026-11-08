package app

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
)

// Gemini 在带登录 cookie 时要求 batchexecute 请求多带一个表单字段 at（XSRF token），
// 不带就直接 400，响应体形如 [["er",...,400,...,[{"48448350":["xsrf", ...]}]]]。
// 匿名请求不需要它，所以这个坑一直没暴露——一挂上有效 cookie，所有请求立刻全挂。
//
// token 来自 /app 页面 HTML 里的 "SNlM0e":"<token>:<毫秒时间戳>"，跟 cookie 会话
// 绑定，所以按 cookie 分别缓存。实测同一 token 可以复用，过期后服务端还是回 xsrf
// 错误，调用方拿到这个错要 invalidate 再取一次。
var (
	xsrfMu      sync.Mutex
	xsrfCache   = map[string]xsrfEntry{}
	xsrfFlights = map[string]*xsrfFlight{}
)

type xsrfFlight struct {
	key         string
	done        chan struct{}
	entry       xsrfEntry
	updates     []string
	err         error
	invalidated bool
}

var errXSRFFetchInvalidated = errors.New("session page fetch invalidated")

type xsrfEntry struct {
	token          string
	serverToken    string
	pushID         string // 上传文件用的 Push-ID 头
	pctx           string // 上传文件用的 X-Client-Pctx 头
	fetched        time.Time
	pendingCookies []string
}

// 页面上的 token 没写明有效期，取个保守值定期重取。
const xsrfTTL = 20 * time.Minute

var snlm0eRe = regexp.MustCompile(`"SNlM0e":"([^"]{10,200})"`)

var serverTokenRe = regexp.MustCompile(`"PI9WOb"\s*:\s*("(?:\\.|[^"\\])*")`)

func extractSessionServerToken(body []byte) string {
	m := serverTokenRe.FindSubmatch(body)
	if len(m) != 2 || len(m[1]) > 4096 {
		return ""
	}
	var token string
	if json.Unmarshal(m[1], &token) != nil || strings.ContainsAny(token, "\r\n") {
		return ""
	}
	return token
}

func cachedSessionServerToken(cookie string, authuser int, xsrf, proxyURL string) string {
	if cookie == "" || xsrf == "" {
		return ""
	}
	xsrfMu.Lock()
	defer xsrfMu.Unlock()
	e, ok := xsrfCache[xsrfRouteKey(cookie, authuser, proxyURL)]
	if !ok || e.token != xsrf || time.Since(e.fetched) >= xsrfTTL {
		return ""
	}
	return e.serverToken
}

// 上传要的两个页面参数，跟 XSRF token 同页取，省一次页面请求。
var pushIDRe = regexp.MustCompile(`"qKIAYe":"([^"]{4,400})"`)

var pctxRe = regexp.MustCompile(`"Ylro7b":"([^"]{4,400})"`)

// cookieKey 用 cookie 的短摘要当缓存键，避免把整串凭证塞进 map key。
func cookieKey(cookie string) string {
	sum := sha1.Sum([]byte(cookie))
	return hex.EncodeToString(sum[:8])
}

// xsrfKey 是缓存键：cookie 摘要 + 账号序号。同一串 cookie 里登着好几个号时，
// 每个号（/u/N）页面给的 SNlM0e 不一样，拿错号的 token 发请求直接 400。
func xsrfKey(cookie string, authuser int) string {
	return cookieKey(cookie) + "/" + strconv.Itoa(authuser)
}

// The session page and its data belong to the egress that fetched them.
// Proxy URLs can contain credentials, so keep only their digest in the key.
func xsrfRouteKey(cookie string, authuser int, proxyURL string) string {
	base := xsrfKey(cookie, authuser)
	if proxyURL == "" {
		return base
	}
	return base + "/" + cookieKey(proxyURL)
}

// geminiBase 是某个账号序号对应的 gemini.google.com 前缀。
//
// 浏览器多号登录时 cookie 只有一份，选哪个号看请求路径：/u/N/ 落到第 N 个号，
// 裸路径落到默认号（等同 /u/0/）。实测 StreamGenerate 和 batchexecute 都认路径，
// X-Goog-AuthUser 头被忽略（裸路径 + 头写 1，会话照样落在默认号）。
func geminiBase(authuser int) string {
	if authuser > 0 {
		return "https://gemini.google.com/u/" + strconv.Itoa(authuser)
	}
	return "https://gemini.google.com"
}

// invalidateXSRF 丢掉某个 cookie 的缓存 token，下次取会重新抓页面。
// 同一串 cookie 的各个账号序号一起作废：cookie 一变（轮转）或 token 被拒，
// 哪个号的缓存都不该再信。
func invalidateXSRF(cookie string) {
	if cookie == "" {
		return
	}
	xsrfMu.Lock()
	for n := 0; n <= maxAuthUser; n++ {
		key := xsrfKey(cookie, n)
		for cacheKey := range xsrfCache {
			if cacheKey == key || strings.HasPrefix(cacheKey, key+"/") {
				delete(xsrfCache, cacheKey)
			}
		}
		for _, flight := range xsrfFlights {
			if flight.key == key || strings.HasPrefix(flight.key, key+"/") {
				flight.invalidated = true
			}
		}
	}
	xsrfMu.Unlock()
}

// getXSRF 取该 cookie（第 authuser 个号）对应的 XSRF token；命中缓存且没过期就直接返回。
// cookie 为空（匿名）时返回空串——匿名请求不需要这个字段。
func getXSRF(cookie string, authuser int, proxyURL string) (string, error) {
	return getXSRFWithContext(context.Background(), cookie, authuser, proxyURL)
}

func getXSRFWithContext(ctx context.Context, cookie string, authuser int, proxyURL string) (string, error) {
	token, _, err := getXSRFWithCookiePolicy(ctx, cookie, authuser, proxyURL, false)
	return token, err
}

var fetchSessionPageTokens = fetchAppTokensAndCookiesWithContext

// Every request holding the same old cookie snapshot receives the updates
// fetched with that snapshot, even if it reaches the cache after the leader.
// Once the account cookie is refreshed the cache is rekeyed without updates.
func getXSRFSessionWithContext(ctx context.Context, cookie string, authuser int, proxyURL string) (string, []string, error) {
	return getXSRFWithCookiePolicy(ctx, cookie, authuser, proxyURL, true)
}

func getXSRFWithCookiePolicy(ctx context.Context, cookie string, authuser int, proxyURL string, consumeUpdates bool) (string, []string, error) {
	if cookie == "" {
		if err := ctx.Err(); err != nil {
			return "", nil, err
		}
		return "", nil, nil
	}
	e, updates, err := getSessionPageEntry(ctx, cookie, authuser, proxyURL, consumeUpdates)
	return e.token, updates, err
}

// Generation and uploads share the same page data and must not perform
// competing fetches that replace each other's token and pending cookies.
func getSessionPageEntry(ctx context.Context, cookie string, authuser int, proxyURL string, consumeUpdates bool) (xsrfEntry, []string, error) {
	key := xsrfRouteKey(cookie, authuser, proxyURL)
	flightKey := key
	for {
		if err := ctx.Err(); err != nil {
			return xsrfEntry{}, nil, err
		}
		xsrfMu.Lock()
		if e, ok := xsrfCache[key]; ok && time.Since(e.fetched) < xsrfTTL {
			var updates []string
			if consumeUpdates {
				updates = append([]string(nil), e.pendingCookies...)
			}
			xsrfMu.Unlock()
			return e, updates, nil
		}
		if flight := xsrfFlights[flightKey]; flight != nil {
			xsrfMu.Unlock()
			select {
			case <-ctx.Done():
				return xsrfEntry{}, nil, ctx.Err()
			case <-flight.done:
			}
			if errors.Is(flight.err, errXSRFFetchInvalidated) || ((errors.Is(flight.err, context.Canceled) || errors.Is(flight.err, context.DeadlineExceeded)) && ctx.Err() == nil) {
				continue
			}
			if flight.err != nil {
				return xsrfEntry{}, nil, flight.err
			}
			if !consumeUpdates {
				return flight.entry, nil, nil
			}
			return flight.entry, append([]string(nil), flight.updates...), nil
		}
		for k, e := range xsrfCache {
			if time.Since(e.fetched) >= xsrfTTL {
				delete(xsrfCache, k)
			}
		}
		flight := &xsrfFlight{key: key, done: make(chan struct{})}
		xsrfFlights[flightKey] = flight
		xsrfMu.Unlock()

		e, updates, err := fetchSessionPageTokens(ctx, cookie, authuser, proxyURL)
		xsrfMu.Lock()
		if flight.invalidated {
			err = errXSRFFetchInvalidated
		}
		if err == nil {
			e.pendingCookies = append([]string(nil), updates...)
			xsrfCache[key] = e
			flight.entry = e
			flight.updates = append([]string(nil), updates...)
		}
		flight.err = err
		delete(xsrfFlights, flightKey)
		close(flight.done)
		xsrfMu.Unlock()
		if errors.Is(err, errXSRFFetchInvalidated) {
			continue
		}
		if err != nil {
			return xsrfEntry{}, nil, err
		}
		if !consumeUpdates {
			return e, nil, nil
		}
		return e, updates, nil
	}
}

// Apply only non-deleting, account-preserving cookies explicitly scoped to the
// shared Google root. Account storage lacks per-cookie domain metadata. The
// compare-and-swap prevents an older fetch overwriting a concurrent update.
func applyAppPageAccountCookies(accountID int64, cookie string, authuser int, token, proxyURL string, updates []string) string {
	if accountID <= 0 || len(updates) == 0 {
		return cookie
	}
	merged := mergeSharedAppPageCookies(cookie, updates)
	if merged == cookie {
		return cookie
	}
	result, err := getDB().Exec(`UPDATE accounts SET cookie=? WHERE id=? AND cookie=?`, merged, accountID, cookie)
	if err == nil {
		if n, _ := result.RowsAffected(); n == 1 {
			xsrfMu.Lock()
			if entry, ok := xsrfCache[xsrfRouteKey(cookie, authuser, proxyURL)]; ok && entry.token == token && time.Since(entry.fetched) < xsrfTTL {
				entry.pendingCookies = nil
				xsrfCache[xsrfRouteKey(merged, authuser, proxyURL)] = entry
			}
			xsrfMu.Unlock()
		}
	}
	return merged
}

// Merge without persistence for a browser-sourced session. The source browser
// and the stored account are never overwritten with this temporary snapshot.
func mergeSharedAppPageCookies(cookie string, updates []string) string {
	state, err := newWebChannelCookies(cookie)
	if err != nil {
		return cookie
	}
	state.apply(updates)
	merged := mergeSetCookie(cookie, state.snapshot())
	if merged == cookie || cookieIdentity(merged) != cookieIdentity(cookie) {
		return cookie
	}
	return merged
}

// getUploadTokens 取上传要用的 Push-ID / X-Client-Pctx，跟 XSRF token 同一份缓存。
func getUploadTokens(cookie string, authuser int, proxyURL string) (pushID, pctx string, err error) {
	return getUploadTokensWithContext(context.Background(), cookie, authuser, proxyURL)
}

func getUploadTokensWithContext(ctx context.Context, cookie string, authuser int, proxyURL string) (pushID, pctx string, err error) {
	e, _, err := getSessionPageEntry(ctx, cookie, authuser, proxyURL, false)
	if err != nil {
		return "", "", err
	}
	return e.pushID, e.pctx, nil
}

// fetchAppPage 抓 gemini.google.com/app 的 HTML。
// 走跟主请求相同的出口：配了代理走 stdlib，没配走 tls-client，
// 免得页面里取到的 token 和后续请求来自两个不同 IP。
// cookie 传空串就是匿名抓（页面照样返回，只是没有登录态字段）。
// authuser>0 抓 /u/N/app，页面里的 token 才是第 N 个号的。
func fetchAppPage(cookie string, authuser int, proxyURL string) ([]byte, error) {
	return fetchAppPageWithContext(context.Background(), cookie, authuser, proxyURL)
}

func fetchAppPageWithContext(ctx context.Context, cookie string, authuser int, proxyURL string) ([]byte, error) {
	pageURL := geminiBase(authuser) + "/app"
	return fetchAppPageURLWithContext(ctx, pageURL, cookie, proxyURL)
}

func fetchAppPageURLWithContext(ctx context.Context, pageURL, cookie, proxyURL string) ([]byte, error) {
	body, _, err := fetchAppPageURLAndCookiesWithContext(ctx, pageURL, cookie, proxyURL)
	return body, err
}

func fetchAppPageURLAndCookiesWithContext(ctx context.Context, pageURL, cookie, proxyURL string) ([]byte, []string, error) {
	headers := map[string]string{
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": browserAcceptLanguage(),
	}
	if cookie != "" {
		headers["Cookie"] = cookie
	}

	var body []byte
	var setCookie []string
	if proxyURL != "" {
		req, err := http.NewRequestWithContext(ctx, "GET", pageURL, nil)
		if err != nil {
			return nil, nil, err
		}
		applyChromeHeaders(req)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := getStdlibClient(proxyURL).Do(req)
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, nil, newAppPageStatusError(resp.StatusCode, resp.Header.Get("Location"))
		}
		setCookie = resp.Header.Values("Set-Cookie")
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, nil, err
		}
	} else {
		req, err := fhttp.NewRequestWithContext(ctx, "GET", pageURL, nil)
		if err != nil {
			return nil, nil, err
		}
		applyBrowserHeaderValues(req.Header, "same-origin")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := getTLSClient().Do(req)
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, nil, newAppPageStatusError(resp.StatusCode, resp.Header.Get("Location"))
		}
		setCookie = resp.Header.Values("Set-Cookie")
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, nil, err
		}
	}
	return body, setCookie, nil
}

// fetchAppTokens 抓一次 /app 页面，把三个 token 一起抠出来。
func fetchAppTokens(cookie string, authuser int, proxyURL string) (xsrfEntry, error) {
	return fetchAppTokensWithContext(context.Background(), cookie, authuser, proxyURL)
}

func fetchAppTokensWithContext(ctx context.Context, cookie string, authuser int, proxyURL string) (xsrfEntry, error) {
	e, _, err := fetchAppTokensAndCookiesWithContext(ctx, cookie, authuser, proxyURL)
	return e, err
}

func fetchAppTokensAndCookiesWithContext(ctx context.Context, cookie string, authuser int, proxyURL string) (xsrfEntry, []string, error) {
	body, updates, err := fetchAppPageURLAndCookiesWithContext(ctx, geminiBase(authuser)+"/app", cookie, proxyURL)
	if err != nil {
		return xsrfEntry{}, nil, err
	}
	e := xsrfEntry{fetched: time.Now(), serverToken: extractSessionServerToken(body)}
	if m := snlm0eRe.FindSubmatch(body); m != nil {
		e.token = string(m[1])
	} else if cookie != "" {
		// 带 cookie 却拿不到 token = cookie 已失效被当成匿名。匿名本就没这字段，不算错。
		return xsrfEntry{}, nil, fmt.Errorf("no SNlM0e in page (cookie expired or not signed in)")
	}
	if p := pushIDRe.FindSubmatch(body); p != nil {
		e.pushID = string(p[1])
	}
	if p := pctxRe.FindSubmatch(body); p != nil {
		e.pctx = string(p[1])
	}
	return e, updates, nil
}

// isXSRFError 判断上游 400 是不是 XSRF token 的问题。
// 响应体形如：[["er",null,...,400,...,[{"48448350":["xsrf","<新token>",...]}]]]
func isXSRFError(raw string) bool {
	return strings.Contains(raw, `"xsrf"`)
}

// appPageStatusError 是抓 /app 拿到非 200 时的错误，带上重定向目标。
//
// 两个 client 都不跟随重定向，所以 302 本身说明不了原因：跳 accounts.google.com
// 是登录态没了，跳 www.google.com/sorry/ 是出口被 Google 拦，跟 cookie 无关。
// 只留 host+path：/sorry 的 query 里有长串 continue/q 参数，进日志和面板没用。
// 文本仍以 "fetch /app: HTTP <code>" 开头，按子串判 "HTTP 302" 的地方不受影响。
type appPageStatusError struct {
	Status   int
	Location string // host+path，没有 Location 头时为空
}

func newAppPageStatusError(status int, location string) *appPageStatusError {
	e := &appPageStatusError{Status: status}
	if location != "" {
		if u, err := url.Parse(location); err == nil {
			e.Location = u.Host + u.Path
		} else {
			e.Location = location
		}
	}
	return e
}

func (e *appPageStatusError) Error() string {
	if e.Location != "" {
		return fmt.Sprintf("fetch /app: HTTP %d -> %s", e.Status, e.Location)
	}
	return fmt.Sprintf("fetch /app: HTTP %d", e.Status)
}
