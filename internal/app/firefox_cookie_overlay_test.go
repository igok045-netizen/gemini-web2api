package app

import (
	"strings"
	"testing"
	"time"
)

func TestFirefoxCookieOverlayIsScopedAndExpires(t *testing.T) {
	key := firefoxOverlayKey(1, 0, "", "app", "channel")
	t.Cleanup(func() { firefoxOverlayClear(key) })
	firefoxOverlayUpdate(key, []string{
		"SIDCC=new; Domain=.google.com; Path=/; Max-Age=60; Secure",
		"BAD=x; Domain=gemini.google.com; Path=/",
		"SAPISID=other; Domain=.google.com; Path=/",
	})
	got := strings.Join(firefoxOverlayGet(key), ";")
	if !strings.Contains(got, "SIDCC=new") || strings.Contains(got, "BAD=") || strings.Contains(got, "SAPISID=") {
		t.Fatal("overlay did not enforce domain and identity restrictions")
	}
	for _, other := range []string{
		firefoxOverlayKey(2, 0, "", "app", "channel"),
		firefoxOverlayKey(1, 1, "", "app", "channel"),
		firefoxOverlayKey(1, 0, "proxy", "app", "channel"),
		firefoxOverlayKey(1, 0, "", "changed", "channel"),
		firefoxOverlayKey(1, 0, "", "app", "changed"),
	} {
		if len(firefoxOverlayGet(other)) != 0 {
			t.Fatal("overlay crossed an account, route or browser snapshot")
		}
	}
	firefoxOverlayUpdate(key, []string{"SIDCC=; Domain=.google.com; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"})
	if len(firefoxOverlayGet(key)) != 0 {
		t.Fatal("deleted cookie remained in overlay")
	}
	firefoxOverlayUpdate(key, []string{"SIDCC=short; Domain=.google.com; Path=/; Max-Age=1"})
	firefoxOverlay.Lock()
	stored := firefoxOverlay.entries[key].cookies["SIDCC"]
	stored.expires = time.Now().Add(-time.Second)
	firefoxOverlay.entries[key].cookies["SIDCC"] = stored
	firefoxOverlay.Unlock()
	if len(firefoxOverlayGet(key)) != 0 {
		t.Fatal("expired cookie remained in overlay")
	}
}
