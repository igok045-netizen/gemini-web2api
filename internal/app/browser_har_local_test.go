package app

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
)

// Compare the non-secret model selector fields in a captured browser
// handshake against the actual binary header built by the server. Dynamic
// UUID and build fields are deliberately not compared.
func TestBrowserHARArgonModelHeader(t *testing.T) {
	path := os.Getenv("GEMINI_DIAGNOSTIC_BROWSER_HAR")
	if path == "" {
		t.Skip("no browser HAR supplied")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("cannot read browser HAR")
	}
	var capture struct {
		Log struct {
			Entries []struct {
				Request struct {
					Method, URL string
					Headers     []struct{ Name, Value string }
				}
			}
		}
	}
	if json.Unmarshal(data, &capture) != nil {
		t.Fatal("cannot parse browser HAR")
	}
	var browser []byte
	var capturedLanguage string
	for _, entry := range capture.Log.Entries {
		u, err := url.Parse(entry.Request.URL)
		if err != nil || u.Hostname() != "geminiweb-pa.clients6.google.com" || u.Path != "/v1/processSession" || entry.Request.Method != "POST" {
			continue
		}
		browser = binaryModelHeader(u.Query().Get("$httpHeaders"))
		if len(browser) > 0 {
			for _, header := range entry.Request.Headers {
				if strings.EqualFold(header.Name, "Accept-Language") {
					capturedLanguage = header.Value
				}
			}
			break
		}
	}
	if len(browser) == 0 {
		t.Fatal("browser model header missing")
	}
	t.Setenv("GEMINI_EXPERIMENTAL_BROWSER_LOCALE", "ru")
	if capturedLanguage == "" || capturedLanguage != browserAcceptLanguage() {
		t.Error("experimental Accept-Language differs from the captured browser")
	}
	model := Models["gemini-4-argon"]
	server := binaryModelHeader(wcBinaryHeaders("test-key", wcRequest{HexID: model.HexID, Mode: model.Mode, Think: model.thinkWire()}, "test-build"))
	got, err := wcBinaryParseWire(server)
	if err != nil {
		t.Fatal("server model header invalid")
	}
	want, err := wcBinaryParseWire(browser)
	if err != nil {
		t.Fatal("browser model header invalid")
	}
	for _, number := range []uint64{1, 5, 7, 8, 9, 12, 15, 16} {
		var a, b []wcBinaryField
		for _, field := range got {
			if field.number == number {
				a = append(a, field)
			}
		}
		for _, field := range want {
			if field.number == number {
				b = append(b, field)
			}
		}
		if len(a) != 1 || len(b) != 1 || a[0].wire != b[0].wire || a[0].numberValue != b[0].numberValue || !bytes.Equal(a[0].data, b[0].data) {
			t.Errorf("captured and server model selector differ at field %d", number)
		}
	}
}

func binaryModelHeader(headers string) []byte {
	for _, line := range strings.Split(headers, "\n") {
		name, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && strings.EqualFold(name, "x-goog-ext-525001261-bin") {
			decoded, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
			return decoded
		}
	}
	return nil
}

// Opt-in local-only check. Never prints a captured URL, token, cookie, or text.
func TestBrowserHARDownlinkParser(t *testing.T) {
	path := os.Getenv("GEMINI_DIAGNOSTIC_BROWSER_HAR")
	if path == "" {
		t.Skip("no browser HAR supplied")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("cannot read browser HAR")
	}
	var capture struct {
		Log struct {
			Entries []struct {
				Request  struct{ Method, URL string }
				Response struct {
					Status  int
					Content struct{ Text string }
				}
			}
		}
	}
	if json.Unmarshal(data, &capture) != nil {
		t.Fatal("cannot parse browser HAR")
	}
	var streams, frames, content, done, end, acknowledgements, argonFrames, otherModelFrames int
	var previousText, forwardedText, lastText string
	monotonic := true
	tracker := &deltaTracker{}
	for _, entry := range capture.Log.Entries {
		u, err := url.Parse(entry.Request.URL)
		if err != nil || u.Hostname() != "geminiweb-pa.clients6.google.com" || u.Path != "/v1/processSession" || entry.Request.Method != "GET" || entry.Response.Status != 200 || entry.Response.Content.Text == "" {
			continue
		}
		streams++
		err = wcReadFrames(strings.NewReader(entry.Response.Content.Text), func(item wcItem) bool {
			frames++
			event := wcBinaryClassify(item.Payload)
			model := extractUpstreamModel(event.Line)
			if model == "4 Argon" || model == "4 Argon High" {
				argonFrames++
			} else if model != "" {
				otherModelFrames++
			}
			if event.Line != "" && hasContentFrame(event.Line) {
				content++
			}
			for _, text := range renderedTextsInLine(event.Line, false) {
				cleaned := cleanGeminiText(text)
				if previousText != "" && !strings.HasPrefix(cleaned, previousText) {
					monotonic = false
				}
				previousText, lastText = cleaned, cleaned
				forwardedText += tracker.Push(text)
			}
			if event.Done {
				done++
			}
			if event.End {
				end++
			}
			if event.Ack {
				acknowledgements++
			}
			return true
		})
		if err != nil {
			t.Fatal("cannot parse captured downlink framing")
		}
	}
	t.Logf("browser downlinks=%d frames=%d content=%d done=%d end=%d ack=%d", streams, frames, content, done, end, acknowledgements)
	t.Logf("captured frames with recognized Argon metadata=%d, other model metadata=%d", argonFrames, otherModelFrames)
	t.Logf("captured text cumulative=%t, streamed output matches last text=%t", monotonic, lastText != "" && forwardedText == lastText)
	if streams == 0 || content == 0 || done == 0 {
		t.Error("captured reply not fully recognized")
	}
}
