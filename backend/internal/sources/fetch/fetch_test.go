package fetch

import (
	"net"
	"testing"
)

func TestIsPublic(t *testing.T) {
	for ip, want := range map[string]bool{
		"8.8.8.8": true, "2606:4700::1111": true,
		"127.0.0.1": false, "10.1.2.3": false, "192.168.1.1": false, "172.16.0.1": false,
		"169.254.169.254": false, "100.64.0.1": false, "0.0.0.0": false, "::1": false, "fe80::1": false, "fc00::1": false,
	} {
		if got := IsPublic(net.ParseIP(ip)); got != want {
			t.Errorf("IsPublic(%s) = %v, want %v", ip, got, want)
		}
	}
}
