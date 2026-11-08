package app

import (
	"testing"
	"time"
)

// 面板改 request_timeout_sec 要立刻作用到新请求：缓存的客户端不能沿用旧超时。
func TestClientCacheFollowsTimeout(t *testing.T) {
	rtMu.Lock()
	saved := rtVal
	rtVal.RequestTimeout = 20
	rtMu.Unlock()
	defer func() { rtMu.Lock(); rtVal = saved; rtMu.Unlock() }()

	const proxy = "http://127.0.0.1:1"
	if got := getStdlibClient(proxy).Timeout; got != 20*time.Second {
		t.Fatalf("timeout = %v, want 20s", got)
	}
	rtMu.Lock()
	rtVal.RequestTimeout = 180
	rtMu.Unlock()
	if got := getStdlibClient(proxy).Timeout; got != 180*time.Second {
		t.Fatalf("after change timeout = %v, want 180s", got)
	}
	if getTLSClient() == nil {
		t.Fatal("tls client nil")
	}
}
