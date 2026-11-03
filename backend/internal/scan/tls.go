package scan

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// TLSInfo describes the endpoint's TLS.
type TLSInfo struct {
	Supported   bool     `json:"supported"`
	Version     string   `json:"version"`      // highest negotiated
	MinObserved string   `json:"min_observed"` // lowest version that still handshakes
	Cipher      string   `json:"cipher"`
	Issuer      string   `json:"issuer"`
	Subject     string   `json:"subject"`
	SANs        []string `json:"sans"`
	NotBefore   string   `json:"not_before"`
	NotAfter    string   `json:"not_after"`
	DaysLeft    int      `json:"days_left"`
	KeyType     string   `json:"key_type"`
	SelfSigned  bool     `json:"self_signed"`
	HostMatch   bool     `json:"host_match"`
}

var tlsVersions = map[uint16]string{
	tls.VersionTLS10: "TLS 1.0", tls.VersionTLS11: "TLS 1.1",
	tls.VersionTLS12: "TLS 1.2", tls.VersionTLS13: "TLS 1.3",
}

// checkTLS connects over HTTPS, inspects the certificate, and probes which
// protocol versions still handshake (TLS 1.0/1.1 are findings).
func (sc *Scanner) checkTLS(ctx context.Context, host string, base *url.URL, rep *Report, mu *sync.Mutex) error {
	port := base.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(host, port)

	// Full handshake, verified, to read the chain and negotiated version.
	state, verifyErr, err := handshake(ctx, addr, host, tls.VersionTLS13, false)
	if err != nil {
		mu.Lock()
		defer mu.Unlock()
		if base.Scheme == "https" {
			rep.add(SevHigh, "tls", "HTTPS not available", "Could not complete a TLS handshake on port "+port+": "+err.Error())
		}
		return nil
	}
	info := &TLSInfo{Supported: true, SANs: []string{}}
	info.Version = tlsVersions[state.Version]
	info.Cipher = tls.CipherSuiteName(state.CipherSuite)

	var leaf *x509.Certificate
	if len(state.PeerCertificates) > 0 {
		leaf = state.PeerCertificates[0]
		info.Subject = leaf.Subject.CommonName
		if len(leaf.Issuer.Organization) > 0 {
			info.Issuer = leaf.Issuer.Organization[0]
		} else {
			info.Issuer = leaf.Issuer.CommonName
		}
		info.SANs = leaf.DNSNames
		info.NotBefore = leaf.NotBefore.UTC().Format("2006-01-02")
		info.NotAfter = leaf.NotAfter.UTC().Format("2006-01-02")
		info.DaysLeft = int(time.Until(leaf.NotAfter).Hours() / 24)
		info.KeyType = keyType(leaf)
		info.SelfSigned = leaf.Subject.String() == leaf.Issuer.String()
		info.HostMatch = leaf.VerifyHostname(host) == nil
	}

	// Lowest protocol version that still completes a handshake.
	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12} {
		if _, _, err := handshake(ctx, addr, host, v, true); err == nil {
			info.MinObserved = tlsVersions[v]
			break
		}
	}
	if info.MinObserved == "" {
		info.MinObserved = info.Version
	}

	mu.Lock()
	defer mu.Unlock()
	rep.TLS = info

	switch info.MinObserved {
	case "TLS 1.0", "TLS 1.1":
		rep.add(SevMedium, "tls", "Obsolete "+info.MinObserved+" accepted", "The server still negotiates "+info.MinObserved+", deprecated since 2021. Require TLS 1.2 or higher.")
	}
	if info.Version == "TLS 1.3" {
		rep.add(SevGood, "tls", "TLS 1.3 supported", "")
	}
	if leaf != nil {
		switch {
		case info.DaysLeft < 0:
			rep.add(SevCritical, "tls", "Certificate expired", "The certificate expired on "+info.NotAfter+". Browsers will refuse to connect.")
		case info.DaysLeft < 14:
			rep.add(SevHigh, "tls", fmt.Sprintf("Certificate expires in %d days", info.DaysLeft), "Renew it before "+info.NotAfter+".")
		case info.DaysLeft < 30:
			rep.add(SevMedium, "tls", fmt.Sprintf("Certificate expires in %d days", info.DaysLeft), "Renew it before "+info.NotAfter+".")
		}
		if info.SelfSigned {
			rep.add(SevHigh, "tls", "Self-signed certificate", "The certificate is not issued by a trusted CA, so browsers show a warning.")
		}
		if !info.HostMatch {
			rep.add(SevHigh, "tls", "Certificate does not match the hostname", "The certificate is not valid for "+host+" (SANs: "+strings.Join(info.SANs, ", ")+").")
		}
		if verifyErr != nil && !info.SelfSigned && info.HostMatch {
			rep.add(SevMedium, "tls", "Certificate chain does not verify", verifyErr.Error())
		}
		if k := info.KeyType; strings.HasPrefix(k, "RSA") && strings.Contains(k, "1024") {
			rep.add(SevHigh, "tls", "Weak certificate key", "The certificate uses a 1024-bit RSA key.")
		}
	}
	return nil
}

// handshake dials and performs a TLS handshake pinned to max version v. When
// insecure is true it skips verification (for probing old protocol support);
// otherwise it returns the verification error separately so the caller can
// still read the chain.
func handshake(ctx context.Context, addr, serverName string, max uint16, insecure bool) (tls.ConnectionState, error, error) {
	d := &net.Dialer{Timeout: 6 * time.Second}
	raw, err := dialPublic(ctx, d, "tcp", addr)
	if err != nil {
		return tls.ConnectionState{}, nil, err
	}
	defer raw.Close()
	if dl, ok := ctx.Deadline(); ok {
		raw.SetDeadline(dl)
	} else {
		raw.SetDeadline(time.Now().Add(8 * time.Second))
	}
	cfg := &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS10, MaxVersion: max, InsecureSkipVerify: true}
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		return tls.ConnectionState{}, nil, err
	}
	state := conn.ConnectionState()
	var verifyErr error
	if !insecure {
		opts := x509.VerifyOptions{DNSName: serverName, Intermediates: x509.NewCertPool()}
		for _, c := range state.PeerCertificates[1:] {
			opts.Intermediates.AddCert(c)
		}
		if len(state.PeerCertificates) > 0 {
			_, verifyErr = state.PeerCertificates[0].Verify(opts)
		}
	}
	return state, verifyErr, nil
}

func keyType(c *x509.Certificate) string {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d-bit", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	default:
		return c.PublicKeyAlgorithm.String()
	}
}
