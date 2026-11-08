package app

import (
	"context"
	"os"
	"testing"
)

// Optional test against the installed CLI. The upstream response is fake; it
// checks the real client's tool cycle without sending credentials or requests.
func TestLocalOpenCodeToolCycle(t *testing.T) {
	exe := os.Getenv("GEMINI_DIAGNOSTIC_OPENCODE_CLI")
	if exe == "" {
		t.Skip("installed OpenCode CLI not provided")
	}
	t.Setenv("GEMINI_DIAGNOSTIC_CLI_TOOL", "1")
	t.Setenv("GEMINI_DIAGNOSTIC_CLI_MOCK", "1")
	t.Setenv("GEMINI_DIAGNOSTIC_CLI_FIXED_TITLE", "1")
	t.Setenv("GEMINI_DIAGNOSTIC_CLI_TIMEOUT", "30")
	oldFetch, oldRuntime := fetchAccountXSRF, rtCfg()
	t.Cleanup(func() { fetchAccountXSRF = oldFetch; rtMu.Lock(); rtVal = oldRuntime; rtMu.Unlock() })
	fetchAccountXSRF = func(context.Context, string, int, string) (string, []string, error) { return "test-token", nil, nil }
	rtMu.Lock()
	rtVal = RuntimeConfig{RetryAttempts: 1, RequestTimeout: 20, WebChannelBinary: true, GeminiBL: defaultConfig().GeminiBL}
	if os.Getenv("GEMINI_DIAGNOSTIC_CLI_REALISTIC_LIMIT") == "1" {
		rtVal.MaxPromptBytes = 128000
	}
	rtMu.Unlock()
	id, err := accountAdd("local-opencode-test", "SAPISID=test; __Secure-1PSID=test", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = accountDelete(id) })
	diagnosticOpenCodeCLI(t, exe)
}

// Verify the relative path emitted in a live run without contacting Google.
func TestLocalOpenCodeRelativeRead(t *testing.T) {
	t.Setenv("GEMINI_DIAGNOSTIC_CLI_MOCK_RELATIVE", "1")
	TestLocalOpenCodeToolCycle(t)
}

func TestLocalOpenCodeStageOnly(t *testing.T) {
	t.Setenv("GEMINI_DIAGNOSTIC_STOP_BEFORE_SECOND", "1")
	TestLocalOpenCodeToolCycle(t)
}

// Exercise OpenCode's actual reaction to the proxy's context-limit response.
// The model replies and tool data are synthetic; no Google requests occur.
func TestLocalOpenCodeContextLimitRecovery(t *testing.T) {
	t.Setenv("GEMINI_DIAGNOSTIC_CLI_FAKE_CONTEXT_LIMIT", "1")
	TestLocalOpenCodeToolCycle(t)
}

func TestLocalOpenCodeLargeHistoryRecovery(t *testing.T) {
	if os.Getenv("GEMINI_DIAGNOSTIC_CLI_REALISTIC_LIMIT") != "1" {
		t.Skip("opt-in synthetic large-history diagnostic")
	}
	TestLocalOpenCodeToolCycle(t)
}

// Opt-in live check of the deployed loopback server using the installed CLI,
// isolated data directories and one synthetic file. Never print credentials.
func TestLiveDeployedOpenCode(t *testing.T) {
	if os.Getenv("GEMINI_DIAGNOSTIC_DEPLOYED_OPENCODE") != "1" {
		t.Skip("opt-in deployed OpenCode diagnostic")
	}
	exe := os.Getenv("GEMINI_DIAGNOSTIC_OPENCODE_CLI")
	if exe == "" || os.Getenv("GEMINI_DIAGNOSTIC_DEPLOYED_KEY") == "" {
		t.Fatal("diagnostic configuration unavailable")
	}
	t.Setenv("GEMINI_DIAGNOSTIC_CLI_TOOL", "1")
	t.Setenv("GEMINI_DIAGNOSTIC_CLI_FIXED_TITLE", "1")
	t.Setenv("GEMINI_DIAGNOSTIC_CLI_TIMEOUT", "300")
	diagnosticOpenCodeCLI(t, exe)
}
