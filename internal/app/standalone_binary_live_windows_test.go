package app

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Opt-in full binary integration. All files, settings and the server account
// are temporary; neither the user's server nor OpenCode configuration changes.
func TestLiveStandaloneBinaryOpenCode(t *testing.T) {
	binary := os.Getenv("GEMINI_DIAGNOSTIC_BINARY")
	cli := os.Getenv("GEMINI_DIAGNOSTIC_OPENCODE_CLI")
	source := os.Getenv("GEMINI_DIAGNOSTIC_DB")
	firefox := os.Getenv("GEMINI_DIAGNOSTIC_FIREFOX_DB")
	if binary == "" || cli == "" || source == "" || firefox == "" || os.Getenv("GEMINI_DIAGNOSTIC_STANDALONE") != "1" {
		t.Skip("opt-in standalone binary integration")
	}
	dbSource, err := sql.Open("sqlite", "file:"+source+"?mode=ro")
	if err != nil {
		t.Fatal("source database unavailable")
	}
	defer dbSource.Close()
	var cookie string
	var authuser int
	if err := dbSource.QueryRow("SELECT cookie, authuser FROM accounts WHERE status = 'enabled' ORDER BY id LIMIT 1").Scan(&cookie, &authuser); err != nil {
		t.Fatal("source account unavailable")
	}
	if os.Getenv("GEMINI_DIAGNOSTIC_STANDALONE_ORIGINAL") != "1" {
		cookie, err = diagnosticFullFirefoxCookies(cookie, firefox)
		if err != nil {
			t.Fatal("matching browser session unavailable")
		}
	}
	id, err := accountAdd("standalone-diagnostic", cookie, "")
	if err != nil {
		t.Fatal("temporary account unavailable")
	}
	t.Cleanup(func() { _ = accountDelete(id) })
	if _, err := getDB().Exec("UPDATE accounts SET authuser=? WHERE id=?", authuser, id); err != nil {
		t.Fatal("temporary account configuration failed")
	}
	dir := t.TempDir()
	settings := map[string]interface{}{"host": "127.0.0.1", "admin_enabled": false, "web_channel_binary": true, "firefox_fingerprint": true, "request_timeout_sec": 150, "retry_attempts": 1, "strict_model": true, "strict_model_cooldown_min": 0}
	settingsBytes, _ := json.Marshal(settings)
	settingsFile := filepath.Join(dir, "config.json")
	if os.WriteFile(settingsFile, settingsBytes, 0600) != nil {
		t.Fatal("cannot write temporary configuration")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("cannot allocate temporary port")
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	server := exec.Command(binary, "-config", settingsFile, "-db", cfg.DBPath, "-port", fmt.Sprint(port), "-api-key", "diagnostic-only")
	server.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	server.Dir = dir
	server.Env = append(os.Environ(), "GEMINI_WEBCHANNEL_EXPERIMENTAL_HTTP3=1")
	if os.Getenv("GEMINI_DIAGNOSTIC_STANDALONE_SCOPED") == "1" {
		server.Env = append(server.Env, "GEMINI_WEBCHANNEL_FIREFOX_COOKIES_DB="+firefox)
	}
	if os.Getenv("GEMINI_DIAGNOSTIC_STANDALONE_LOCALE") == "ru" {
		server.Env = append(server.Env, "GEMINI_EXPERIMENTAL_BROWSER_LOCALE=ru")
	}
	server.Stdout, server.Stderr = io.Discard, io.Discard
	if err := server.Start(); err != nil {
		t.Fatal("cannot start isolated server")
	}
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	ready := false
	deadline := time.Now().Add(15 * time.Second)
	client := &http.Client{Timeout: time.Second}
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest("GET", base+"/v1/models", nil)
		req.Header.Set("Authorization", "Bearer diagnostic-only")
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				ready = true
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !ready {
		t.Fatal("isolated server did not become ready")
	}
	const marker = "BIRCH-6307"
	if os.WriteFile(filepath.Join(dir, "example.txt"), []byte(marker+"\n"), 0600) != nil {
		t.Fatal("cannot create test file")
	}
	plugin, err := filepath.Abs("opencode-gemini-retry-guard")
	if err != nil {
		t.Fatal("retry guard unavailable")
	}
	config := map[string]interface{}{"plugins": []interface{}{map[string]interface{}{"package": filepath.ToSlash(plugin), "options": map[string]interface{}{"providers": []string{"diagnostic-local"}}}}, "providers": map[string]interface{}{"diagnostic-local": map[string]interface{}{"name": "Diagnostic", "package": "@opencode/ai/providers/openai-compatible", "settings": map[string]interface{}{"baseURL": base + "/v1", "apiKey": "diagnostic-only"}, "models": map[string]interface{}{"gemini-4-argon": map[string]interface{}{"name": "Gemini 4 Argon"}}}}}
	config["permissions"] = []interface{}{
		map[string]interface{}{"action": "*", "resource": "*", "effect": "deny"},
		map[string]interface{}{"action": "read", "resource": "example.txt", "effect": "allow"},
		map[string]interface{}{"action": "read", "resource": filepath.Join(dir, "example.txt"), "effect": "allow"},
	}
	configBytes, _ := json.Marshal(config)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, cli, "--standalone", "run", "--title", "Diagnostic", "--format", "json", "--model", "diagnostic-local/gemini-4-argon", "Use the read tool to read example.txt in the current directory, then reply with the exact file contents. Do not guess.")
	command.WaitDelay = 2 * time.Second
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	command.Dir = dir
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		key = strings.ToUpper(key)
		if strings.HasPrefix(key, "OPENCODE_") || strings.HasPrefix(key, "XDG_") || key == "APPDATA" || key == "LOCALAPPDATA" || key == "PWD" {
			continue
		}
		command.Env = append(command.Env, entry)
	}
	command.Env = append(command.Env, "PWD="+dir, "APPDATA="+filepath.Join(dir, "appdata"), "LOCALAPPDATA="+filepath.Join(dir, "localappdata"), "XDG_CONFIG_HOME="+filepath.Join(dir, "config"), "XDG_DATA_HOME="+filepath.Join(dir, "data"), "XDG_STATE_HOME="+filepath.Join(dir, "state"), "XDG_CACHE_HOME="+filepath.Join(dir, "cache"), "OPENCODE_CONFIG_CONTENT="+string(configBytes), "OPENCODE_DISABLE_AUTOUPDATE=true", "OPENCODE_DISABLE_PROJECT_CONFIG=true")
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, io.Discard
	start := time.Now()
	err = command.Run()
	var toolOK, answerOK, answerContains bool
	var textParts strings.Builder
	for _, line := range strings.Split(output.String(), "\n") {
		var event struct {
			Type string `json:"type"`
			Part struct {
				Text  string `json:"text"`
				Tool  string `json:"tool"`
				State struct {
					Status string `json:"status"`
				} `json:"state"`
			} `json:"part"`
		}
		if json.Unmarshal([]byte(line), &event) != nil {
			continue
		}
		if event.Type == "tool_use" && event.Part.Tool == "read" && event.Part.State.Status == "completed" {
			toolOK = true
		}
		if event.Type == "text" {
			textParts.WriteString(event.Part.Text)
			if strings.TrimSpace(event.Part.Text) == marker {
				answerOK = true
			}
			if strings.Contains(event.Part.Text, marker) {
				answerContains = true
			}
		}
	}
	if strings.TrimSpace(textParts.String()) == marker {
		answerOK = true
	}
	if strings.Contains(textParts.String(), marker) {
		answerContains = true
	}
	var successfulRequests, argonRequests int
	rows, queryErr := getDB().Query("SELECT upstream_model FROM requests WHERE status = 200")
	if queryErr == nil {
		for rows.Next() {
			var model sql.NullString
			if rows.Scan(&model) == nil {
				successfulRequests++
				if strings.EqualFold(model.String, "4 Argon") {
					argonRequests++
				}
			}
		}
		_ = rows.Close()
	}
	storedUnchanged := false
	if stored := accountByID(id); stored != nil {
		storedUnchanged = stored.Cookie == cookie
	}
	lower := strings.ToLower(output.String())
	t.Logf("Standalone binary cycle: tool_completed=%t exact_answer=%t answer_contains_test_value=%t text_bytes=%d timed_out=%t unknown_outcome=%t upstream_error=%t successful_requests=%d reported_argon=%d stored_cookie_unchanged=%t elapsed=%.1fs", toolOK, answerOK, answerContains, textParts.Len(), ctx.Err() != nil, strings.Contains(lower, "gemini_outcome_unknown"), strings.Contains(lower, "upstream error"), successfulRequests, argonRequests, storedUnchanged, time.Since(start).Seconds())
	if err != nil || !toolOK || !answerOK || successfulRequests < 2 || argonRequests != successfulRequests || !storedUnchanged {
		t.Fatal("standalone binary cycle incomplete")
	}
}
