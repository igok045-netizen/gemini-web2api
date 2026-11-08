package app

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdminLocalGuard(t *testing.T) {
	t.Setenv("GEMINI_ADMIN_SAME_ORIGIN_ONLY", "1")
	h := adminLocalGuard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for _, tc := range []struct {
		name, host, origin, path string
		want                     int
	}{
		{"local browser", "127.0.0.1:8084", "http://127.0.0.1:8084", "/admin/api/cookies", 204},
		{"local navigation", "localhost:8084", "", "/admin/", 204},
		{"foreign origin", "127.0.0.1:8084", "https://evil.example", "/admin/api/apikey", 403},
		{"null origin", "127.0.0.1:8084", "null", "/admin/api/cookies/1/rotate", 403},
		{"rebinding host", "evil.example:8084", "http://evil.example:8084", "/admin/api/apikey", 403},
		{"api unaffected", "evil.example:8084", "https://evil.example", "/v1/models", 204},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "http://"+tc.host+tc.path, nil)
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d, want %d", w.Code, tc.want)
			}
		})
	}
}

func TestAdminLocalGuardIsEnabledForLocalDefault(t *testing.T) {
	t.Setenv("GEMINI_ADMIN_SAME_ORIGIN_ONLY", "")
	old := cfg
	t.Cleanup(func() { cfg = old })
	cfg = defaultConfig()
	h := adminLocalGuard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	r := httptest.NewRequest("GET", "http://127.0.0.1:8083/admin/api/apikey", nil)
	r.Header.Set("Origin", "https://example.org")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if cfg.Host != "127.0.0.1" || w.Code != http.StatusForbidden {
		t.Fatal("default local admin is not protected")
	}
}
