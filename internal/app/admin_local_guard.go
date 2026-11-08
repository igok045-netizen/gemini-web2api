package app

import (
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// Optional guard for an unauthenticated localhost admin. It prevents another
// website from reading admin responses or invoking actions through a browser.
func adminLocalGuard(next http.Handler) http.Handler {
	localWithoutToken := cfg.AdminEnabled && cfg.AdminToken == "" && (cfg.Host == "127.0.0.1" || cfg.Host == "localhost" || cfg.Host == "::1")
	if os.Getenv("GEMINI_ADMIN_SAME_ORIGIN_ONLY") != "1" && !localWithoutToken {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin" && !strings.HasPrefix(r.URL.Path, "/admin/") {
			next.ServeHTTP(w, r)
			return
		}
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		host = strings.Trim(strings.ToLower(host), "[]")
		if host != "127.0.0.1" && host != "localhost" && host != "::1" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || u.Scheme != "http" || !strings.EqualFold(u.Host, r.Host) || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
