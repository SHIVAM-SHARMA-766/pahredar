package easm

import "testing"

func TestCleanBanner(t *testing.T) {
	cases := []struct{ in, want string }{
		{"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
		{"220 mail.example.com ESMTP Postfix\r\n", "220 mail.example.com ESMTP Postfix"},
		{"+OK Dovecot ready.\n", "+OK Dovecot ready."},
		{"\x16\x03\x01\x00\xa5", ""}, // TLS handshake bytes → no banner
		{"ab", ""},                   // too short
		{"-ERR\r\nmore", "-ERR"},     // first line only
	}
	for _, c := range cases {
		if got := cleanBanner([]byte(c.in)); got != c.want {
			t.Errorf("cleanBanner(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
