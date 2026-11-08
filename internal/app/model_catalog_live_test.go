package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Compare only non-secret scalar metadata for the Argon catalog entry.
// Neither the captured archive, page, account cookies nor response are logged.
func TestLiveBrowserModelCatalogMetadata(t *testing.T) {
	dbPath, firefox, archive := os.Getenv("GEMINI_DIAGNOSTIC_DB"), os.Getenv("GEMINI_DIAGNOSTIC_FIREFOX_DB"), os.Getenv("GEMINI_DIAGNOSTIC_HAR")
	if dbPath == "" || firefox == "" || archive == "" || os.Getenv("GEMINI_DIAGNOSTIC_CATALOG") != "1" {
		t.Skip("opt-in model catalog diagnostic")
	}
	var har struct {
		Log struct {
			Entries []struct {
				Request struct {
					URL string `json:"url"`
				} `json:"request"`
				Response struct {
					Content struct {
						Text string `json:"text"`
					} `json:"content"`
				} `json:"response"`
			} `json:"entries"`
		} `json:"log"`
	}
	file, err := os.Open(archive)
	if err != nil {
		t.Fatal("browser archive unavailable")
	}
	err = json.NewDecoder(file).Decode(&har)
	_ = file.Close()
	if err != nil {
		t.Fatal("browser archive invalid")
	}
	var recorded []any
	for _, entry := range har.Log.Entries {
		u, err := url.Parse(entry.Request.URL)
		if err == nil && u.Hostname() == "gemini.google.com" && u.Query().Get("rpcids") == "otAQ7b" {
			recorded = catalogArgonEntry(entry.Response.Content.Text)
			break
		}
	}
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	if err != nil {
		t.Fatal("source database unavailable")
	}
	defer db.Close()
	var account string
	var authuser int
	if err = db.QueryRow("SELECT cookie,authuser FROM accounts WHERE status='enabled' ORDER BY id LIMIT 1").Scan(&account, &authuser); err != nil {
		t.Fatal("source account unavailable")
	}
	cookie, _, err := firefoxCookieSnapshots(account, firefox)
	if err != nil {
		t.Fatal("matching Firefox session unavailable")
	}
	old := rtCfg()
	t.Cleanup(func() { rtMu.Lock(); rtVal = old; rtMu.Unlock() })
	rtMu.Lock()
	rtVal = RuntimeConfig{FirefoxFingerprint: true, RequestTimeout: 25, GeminiBL: defaultConfig().GeminiBL}
	rtMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	entry, updates, err := fetchAppTokensAndCookiesWithContext(ctx, cookie, authuser, "")
	if err != nil || entry.token == "" {
		t.Fatal("browser session page unavailable")
	}
	cookie = mergeSharedAppPageCookies(cookie, updates)
	args, _ := json.Marshal([]any{1})
	freq, _ := json.Marshal([]any{[]any{[]any{"otAQ7b", string(args), nil, "generic"}}})
	form := url.Values{"f.req": []string{string(freq)}, "at": []string{entry.token}}
	endpoint := fmt.Sprintf("%s/_/BardChatUi/data/batchexecute?rpcids=otAQ7b&source-path=%%2Fapp&bl=%s&hl=ru&rt=c", geminiBase(authuser), url.QueryEscape(defaultConfig().GeminiBL))
	headers := buildGeminiHeaders(cookie, extractSAPISID(cookie), "")
	setAuthUserHeaders(headers, authuser)
	status, _, body, err := uploadPostWithContext(ctx, endpoint, headers, []byte(form.Encode()), "")
	if err != nil {
		t.Fatal("model catalog request failed")
	}
	if status != 200 {
		t.Fatalf("model catalog HTTP status=%d", status)
	}
	current := catalogArgonEntry(string(body))
	t.Logf("Argon catalog entry: present_in_archive=%t present_now=%t", recorded != nil, current != nil)
	if recorded == nil || current == nil {
		return
	}
	var differentFields []int
	for i := 0; i < len(recorded) && i < len(current); i++ {
		if !reflect.DeepEqual(recorded[i], current[i]) {
			differentFields = append(differentFields, i)
		}
	}
	t.Logf("Argon catalog entry: archived_fields=%d current_fields=%d changed_field_indices=%v", len(recorded), len(current), differentFields)
	for _, i := range []int{4, 7, 9, 15, 17} {
		if i >= len(recorded) || i >= len(current) {
			continue
		}
		old, oldOK := catalogScalar(recorded[i])
		now, nowOK := catalogScalar(current[i])
		if oldOK && nowOK {
			t.Logf("Catalog scalar field %d: unchanged=%t", i, old == now)
		}
	}
}

func catalogArgonEntry(body string) []any {
	for _, payload := range wrbPayloads(body) {
		if len(payload) <= 15 {
			continue
		}
		models, ok := payload[15].([]any)
		if !ok {
			continue
		}
		for _, raw := range models {
			model, ok := raw.([]any)
			if !ok || len(model) < 2 {
				continue
			}
			name, _ := model[1].(string)
			if strings.EqualFold(name, "4 Argon") || strings.EqualFold(name, "Argon") {
				return model
			}
		}
	}
	return nil
}

func catalogScalar(value any) (string, bool) {
	switch value.(type) {
	case bool, float64, nil:
		return fmt.Sprint(value), true
	default:
		return "", false
	}
}
