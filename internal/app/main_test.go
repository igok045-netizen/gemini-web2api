package app

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestMain 把 DB 指向临时目录再跑测试。
//
// hasCookie() 现在只看 cookie 池，也就是要查 DB；不接管 cfg.DBPath 的话
// getDB() 会去开真实的 ./data/gemini.db，测试就会读写生产数据。
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "gw2a-test-")
	if err != nil {
		panic(err)
	}
	cfg.DBPath = filepath.Join(dir, "test.db")
	code := m.Run()
	if db != nil {
		if err := db.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "closing test database: %v\n", err)
			code = 1
		}
	}
	if err := os.RemoveAll(dir); err != nil {
		fmt.Fprintf(os.Stderr, "removing test database directory: %v\n", err)
		code = 1
	}
	os.Exit(code)
}

// withPoolCookie 往 cookie 池塞一条测试账号，用完自动删掉。
// 取代原来的 cookieRuntime.Store —— 那条单 cookie 路径已经取消。
func withPoolCookie(t *testing.T) {
	t.Helper()
	id, err := accountAdd("test", "SAPISID=dummy; SID=x", "")
	if err != nil {
		t.Fatalf("插测试 cookie 失败: %v", err)
	}
	t.Cleanup(func() { _ = accountDelete(id) })
}
