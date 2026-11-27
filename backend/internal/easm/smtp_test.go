package easm

import (
	"bufio"
	"strings"
	"testing"
)

func TestParseEHLO(t *testing.T) {
	resp := "250-mail.example.com at your service\r\n" +
		"250-SIZE 35882577\r\n" +
		"250-STARTTLS\r\n" +
		"250-8BITMIME\r\n" +
		"250 AUTH LOGIN PLAIN\r\n"
	caps := parseEHLO(bufio.NewReader(strings.NewReader(resp)))
	set := map[string]bool{}
	for _, c := range caps {
		set[c] = true
	}
	for _, want := range []string{"SIZE", "STARTTLS", "8BITMIME", "AUTH"} {
		if !set[want] {
			t.Errorf("missing capability %q in %v", want, caps)
		}
	}
	// The greeting text line ("at your service") keyword is uppercased too, but
	// STARTTLS detection is what matters.
	if !set["STARTTLS"] {
		t.Error("STARTTLS not detected")
	}
}

func TestParseEHLOStopsAtFinalLine(t *testing.T) {
	resp := "250 ONLYLINE\r\nUNREACHABLE SHOULD-NOT-PARSE\r\n"
	caps := parseEHLO(bufio.NewReader(strings.NewReader(resp)))
	if len(caps) != 1 || caps[0] != "ONLYLINE" {
		t.Errorf("caps = %v, want [ONLYLINE] (must stop at the final 250 line)", caps)
	}
}
