package app

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Browser-sourced sessions do not write back to either cookie store. Retain
// Google-wide response cookies briefly in memory, tied to the exact browser
// snapshots, account and egress that generated them. Any browser change or
// route change therefore starts with an independent overlay.
type firefoxOverlayCookie struct {
	cookie  http.Cookie
	expires time.Time
}
type firefoxOverlayEntry struct {
	cookies map[string]firefoxOverlayCookie
	touched time.Time
}

var firefoxOverlay = struct {
	sync.Mutex
	entries map[string]*firefoxOverlayEntry
	timer   *time.Timer
}{entries: make(map[string]*firefoxOverlayEntry)}

const firefoxOverlayTTL = 5 * time.Minute

func firefoxOverlayKey(accountID int64, authuser int, proxy, app, channel string) string {
	h := sha256.New()
	for _, part := range []string{strconv.FormatInt(accountID, 10), strconv.Itoa(authuser), proxy, app, channel} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func firefoxOverlayGet(key string) []string {
	now := time.Now()
	firefoxOverlay.Lock()
	defer firefoxOverlay.Unlock()
	entry := firefoxOverlay.entries[key]
	if entry == nil {
		return nil
	}
	var names []string
	for name, stored := range entry.cookies {
		if !stored.expires.After(now) {
			delete(entry.cookies, name)
		} else {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		delete(firefoxOverlay.entries, key)
		return nil
	}
	sort.Strings(names)
	result := make([]string, 0, len(names))
	for _, name := range names {
		stored := entry.cookies[name]
		cookie := stored.cookie
		// Do not extend the overlay lifetime when applying it again.
		cookie.MaxAge = int(time.Until(stored.expires).Seconds()) + 1
		result = append(result, cookie.String())
	}
	return result
}

func firefoxOverlayClear(key string) {
	firefoxOverlay.Lock()
	delete(firefoxOverlay.entries, key)
	firefoxOverlay.Unlock()
}

func firefoxOverlayPrune() {
	firefoxOverlay.Lock()
	defer firefoxOverlay.Unlock()
	now := time.Now()
	for key, entry := range firefoxOverlay.entries {
		for name, value := range entry.cookies {
			if !value.expires.After(now) {
				delete(entry.cookies, name)
			}
		}
		if len(entry.cookies) == 0 {
			delete(firefoxOverlay.entries, key)
		}
	}
	if len(firefoxOverlay.entries) > 0 {
		firefoxOverlay.timer = time.AfterFunc(time.Minute, firefoxOverlayPrune)
	} else {
		firefoxOverlay.timer = nil
	}
}

func firefoxOverlayUpdate(key string, headers []string) {
	if len(headers) == 0 {
		return
	}
	now := time.Now()
	firefoxOverlay.Lock()
	defer firefoxOverlay.Unlock()
	entry := firefoxOverlay.entries[key]
	if entry == nil {
		entry = &firefoxOverlayEntry{cookies: make(map[string]firefoxOverlayCookie)}
		firefoxOverlay.entries[key] = entry
	}
	entry.touched = now
	for _, raw := range headers {
		cookie, err := http.ParseSetCookie(raw)
		if err != nil || cookie.Name == "SAPISID" || cookie.Name == "__Secure-1PSID" ||
			!strings.EqualFold(strings.TrimPrefix(cookie.Domain, "."), "google.com") || cookie.Path != "/" {
			continue
		}
		if cookie.MaxAge < 0 || (!cookie.Expires.IsZero() && !cookie.Expires.After(now)) {
			delete(entry.cookies, cookie.Name)
			continue
		}
		expires := now.Add(firefoxOverlayTTL)
		if cookie.MaxAge > 0 && cookie.MaxAge < int(firefoxOverlayTTL/time.Second) {
			expires = now.Add(time.Duration(cookie.MaxAge) * time.Second)
		}
		if !cookie.Expires.IsZero() && cookie.Expires.Before(expires) {
			expires = cookie.Expires
		}
		entry.cookies[cookie.Name] = firefoxOverlayCookie{cookie: *cookie, expires: expires}
	}
	if len(entry.cookies) == 0 {
		delete(firefoxOverlay.entries, key)
	}
	if len(firefoxOverlay.entries) > 0 && firefoxOverlay.timer == nil {
		firefoxOverlay.timer = time.AfterFunc(time.Minute, firefoxOverlayPrune)
	}
	if len(firefoxOverlay.entries) > 64 {
		var oldest string
		var touched time.Time
		for k, value := range firefoxOverlay.entries {
			if oldest == "" || value.touched.Before(touched) {
				oldest, touched = k, value.touched
			}
		}
		delete(firefoxOverlay.entries, oldest)
	}
}
