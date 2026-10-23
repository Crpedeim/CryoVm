package main

import (
	"net"
	"testing"
)

func TestParseForward(t *testing.T) {
	for in, want := range map[string]forwardSpec{
		"8000":      {8000, 8000}, // the same number on both sides
		"9000:8000": {9000, 8000},
		":8000":     {0, 8000}, // any free local port
		"0:8000":    {0, 8000},
		"1:65535":   {1, 65535},
	} {
		if got, err := parseForward(in); err != nil || got != want {
			t.Errorf("%q: %+v %v, want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", ":", "8000:", "http", "0", "70000", "8000:0", "-1:80", "1:2:3", "a:80"} {
		if got, err := parseForward(bad); err == nil {
			t.Errorf("%q: accepted as %+v", bad, got)
		}
	}
}

func TestURLHost(t *testing.T) {
	for _, tc := range []struct {
		ip   string
		want string
	}{
		{"127.0.0.1", "127.0.0.1:8000"},
		{"0.0.0.0", "localhost:8000"}, // every address: a browser goes to localhost
		{"::", "localhost:8000"},
		{"::1", "[::1]:8000"},
	} {
		if got := urlHost(&net.TCPAddr{IP: net.ParseIP(tc.ip), Port: 8000}); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.ip, got, tc.want)
		}
	}
}
