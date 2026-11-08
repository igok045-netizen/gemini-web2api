package app

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// webChannelCookies is private to one request. A browser applies Set-Cookie
// before its next request; keeping one immutable Cookie header throughout a
// long WebChannel session can otherwise send stale session credentials.
type webChannelCookies struct {
	jar      *cookiejar.Jar
	endpoint *url.URL
	mu       sync.Mutex
	shared   []string
	identity map[string]string
}

func newWebChannelCookies(header string) (*webChannelCookies, error) {
	endpoint, err := url.Parse(wcEndpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid WebChannel endpoint")
	}
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, fmt.Errorf("cannot initialize session cookies")
	}
	state := &webChannelCookies{jar: jar, endpoint: endpoint, identity: map[string]string{}}
	if strings.TrimSpace(header) == "" {
		return state, nil
	}
	initial, err := http.ParseCookie(header)
	if err != nil {
		return nil, fmt.Errorf("invalid account cookie header")
	}
	for _, c := range initial {
		// Imported Cookie headers have no domain metadata. Limit this local jar
		// to WebChannel, and model initial cookies as shared Google root cookies.
		c.Domain, c.Path = "google.com", "/"
		if c.Name == "SAPISID" || c.Name == "__Secure-1PSID" {
			if prior, exists := state.identity[c.Name]; exists && prior != c.Value {
				return nil, fmt.Errorf("ambiguous account cookie identity")
			}
			state.identity[c.Name] = c.Value
		}
	}
	jar.SetCookies(endpoint, initial)
	return state, nil
}

func (s *webChannelCookies) header() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	request := &http.Request{Header: make(http.Header)}
	for _, cookie := range s.jar.Cookies(s.endpoint) {
		request.AddCookie(cookie)
	}
	return request.Header.Get("Cookie")
}

func (s *webChannelCookies) apply(headers []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, raw := range headers {
		cookie, err := http.ParseSetCookie(raw)
		if err != nil {
			continue
		}
		deletion := cookie.MaxAge < 0 || (!cookie.Expires.IsZero() && !cookie.Expires.After(time.Now()))
		if old, anchored := s.identity[cookie.Name]; anchored && (cookie.Value != old || deletion) {
			continue
		}
		s.jar.SetCookies(s.endpoint, []*http.Cookie{cookie})
		// Only explicitly Google-wide, root-path updates can be passed on to the
		// shared account store, which does not retain cookie domain metadata.
		if !deletion && strings.EqualFold(strings.TrimPrefix(cookie.Domain, "."), "google.com") && cookie.Path == "/" {
			s.shared = append(s.shared, raw)
		}
	}
}

func (s *webChannelCookies) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.shared...)
}
