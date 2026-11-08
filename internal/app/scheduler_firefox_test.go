package app

import "testing"

func TestCookieRotationTimerRespectsBrowserSession(t *testing.T) {
	t.Setenv("GEMINI_WEBCHANNEL_FIREFOX_COOKIES_DB", "")
	timer := cookieRotationTimer()
	if timer == nil {
		t.Fatal("normal account rotation unexpectedly disabled")
	}
	timer.Stop()
	t.Setenv("GEMINI_WEBCHANNEL_FIREFOX_COOKIES_DB", "browser.sqlite")
	if timer := cookieRotationTimer(); timer != nil {
		timer.Stop()
		t.Fatal("browser-sourced session would rotate stored cookies in the background")
	}
}
