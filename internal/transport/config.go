package transport

import (
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/jinomee/mc/internal/joincode"
)

// ALPN is the QUIC application protocol identifier.
const ALPN = "lanyard/1"

// ErrFingerprint means the peer presented a certificate that does not match the
// fingerprint from the join code: either a different host or an attack.
var ErrFingerprint = errors.New("transport: host certificate does not match the join code")

// ServerTLS returns the host's TLS configuration.
func ServerTLS(id *Identity) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{id.Cert},
		NextProtos:   []string{ALPN},
		MinVersion:   tls.VersionTLS13,
	}
}

// ClientTLS returns a guest TLS configuration that accepts exactly the
// certificate whose truncated SHA-256 equals fp. Chain validation is
// replaced by pinning, which is stronger here: there is no CA.
func ClientTLS(fp [joincode.FingerprintLen]byte) *tls.Config {
	return &tls.Config{
		ServerName:         "lanyard",
		NextProtos:         []string{ALPN},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, //nolint:gosec // verified by VerifyPeerCertificate (fingerprint pinning)
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return ErrFingerprint
			}
			got := FingerprintOf(raw[0])
			if subtle.ConstantTimeCompare(got[:], fp[:]) != 1 {
				return ErrFingerprint
			}
			return nil
		},
	}
}

// QUICConfig returns the QUIC settings shared by both sides. Keep-alives every
// 10 s keep NAT mappings open (typical UDP NAT timeouts are 30–120 s).
func QUICConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: 5 * time.Second,
		MaxIdleTimeout:       30 * time.Second,
		KeepAlivePeriod:      10 * time.Second,
		MaxIncomingStreams:   1024,
		// Conservative initial size: some cross-border paths and PPPoE links
		// drop large UDP datagrams. PMTU discovery still raises it.
		InitialPacketSize: 1252,
	}
}
