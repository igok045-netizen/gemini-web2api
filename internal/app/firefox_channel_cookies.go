package app

import (
	"database/sql"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// firefoxChannelCookies reads only cookies applicable to the WebChannel host.
// It is opt-in, read-only, and refuses to combine two different identities.
// The caller applies new, correctly scoped Set-Cookie updates separately.
func firefoxChannelCookies(accountHeader, dbPath string) (string, error) {
	_, channel, err := firefoxCookieSnapshots(accountHeader, dbPath)
	return channel, err
}

// Both headers come from a single SQLite read snapshot so browser updates
// cannot mix two independently read session states within the same request.
func firefoxCookieSnapshots(accountHeader, dbPath string) (string, string, error) {
	if dbPath == "" || strings.ContainsAny(dbPath, "?#") {
		return "", "", errors.New("invalid Firefox cookie database path")
	}
	path, err := filepath.Abs(dbPath)
	if err != nil {
		return "", "", errors.New("invalid Firefox cookie database path")
	}
	account, err := http.ParseCookie(accountHeader)
	if err != nil {
		return "", "", errors.New("invalid account cookie header")
	}
	identity := map[string]string{}
	for _, c := range account {
		if c.Name == "SAPISID" || c.Name == "__Secure-1PSID" {
			if prior, exists := identity[c.Name]; exists && prior != c.Value {
				return "", "", errors.New("ambiguous account cookie identity")
			}
			identity[c.Name] = c.Value
		}
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return "", "", errors.New("Firefox cookie database unavailable")
	}
	defer db.Close()
	rows, err := db.Query("SELECT name,value,host FROM moz_cookies WHERE host IN ('.google.com','gemini.google.com','.gemini.google.com','.clients6.google.com','geminiweb-pa.clients6.google.com','.geminiweb-pa.clients6.google.com') AND path = '/' AND originAttributes = '' AND expiry > ?", time.Now().Unix())
	if err != nil {
		return "", "", errors.New("Firefox cookies unavailable")
	}
	defer rows.Close()
	appValues, appHosts := map[string]string{}, map[string]string{}
	channelValues, channelHosts := map[string]string{}, map[string]string{}
	add := func(values, hosts map[string]string, name, value, host string) error {
		if prior, ok := values[name]; ok && prior != value && (name == "SAPISID" || name == "__Secure-1PSID") {
			return errors.New("ambiguous Firefox cookie identity")
		}
		if _, ok := values[name]; !ok || len(host) > len(hosts[name]) {
			values[name], hosts[name] = value, host
		}
		return nil
	}
	for rows.Next() {
		var name, value, host string
		if rows.Scan(&name, &value, &host) != nil {
			return "", "", errors.New("Firefox cookie read failed")
		}
		if (&http.Cookie{Name: name, Value: value}).Valid() != nil {
			continue
		}
		if host == ".google.com" || host == "gemini.google.com" || host == ".gemini.google.com" {
			if err := add(appValues, appHosts, name, value, host); err != nil {
				return "", "", err
			}
		}
		if host == ".google.com" || host == ".clients6.google.com" || host == "geminiweb-pa.clients6.google.com" || host == ".geminiweb-pa.clients6.google.com" {
			if err := add(channelValues, channelHosts, name, value, host); err != nil {
				return "", "", err
			}
		}
	}
	if rows.Err() != nil {
		return "", "", errors.New("Firefox cookie read failed")
	}
	for _, name := range []string{"SAPISID", "__Secure-1PSID"} {
		if identity[name] == "" || identity[name] != appValues[name] || identity[name] != channelValues[name] {
			return "", "", errors.New("Firefox session does not match the selected account")
		}
	}
	header := func(values map[string]string) string {
		names := make([]string, 0, len(values))
		for name := range values {
			names = append(names, name)
		}
		sort.Strings(names)
		parts := make([]string, 0, len(names))
		for _, name := range names {
			parts = append(parts, name+"="+values[name])
		}
		return strings.Join(parts, "; ")
	}
	return header(appValues), header(channelValues), nil
}

func firefoxChannelCookiePath() string {
	return os.Getenv("GEMINI_WEBCHANNEL_FIREFOX_COOKIES_DB")
}

func firefoxBrowserSessionEnabled() bool {
	return firefoxChannelCookiePath() != "" && rtCfg().WebChannelBinary
}
