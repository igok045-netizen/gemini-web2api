package app

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireAPIKeyAcceptsGoogleSDKForms(t *testing.T) {
	saved := getAPIKey()
	apiKeyRuntime.Store("test-key-0123456789abcdef")
	defer apiKeyRuntime.Store(saved)

	h := requireAPIKey(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	cases := []struct {
		name string
		set  func(r *http.Request)
		want int
	}{
		{"bearer", func(r *http.Request) { r.Header.Set("Authorization", "Bearer test-key-0123456789abcdef") }, 204},
		{"x-api-key", func(r *http.Request) { r.Header.Set("x-api-key", "test-key-0123456789abcdef") }, 204},
		{"x-goog-api-key", func(r *http.Request) { r.Header.Set("x-goog-api-key", "test-key-0123456789abcdef") }, 204},
		{"query", func(r *http.Request) { r.URL.RawQuery = "key=test-key-0123456789abcdef&alt=sse" }, 204},
		{"wrong", func(r *http.Request) { r.Header.Set("x-goog-api-key", "nope") }, 401},
		{"none", func(r *http.Request) {}, 401},
	}
	for _, c := range cases {
		req := httptest.NewRequest("POST", "/v1beta/models/x:generateContent", nil)
		c.set(req)
		w := httptest.NewRecorder()
		h(w, req)
		if w.Code != c.want {
			t.Errorf("%s: got %d, want %d", c.name, w.Code, c.want)
		}
	}
}
