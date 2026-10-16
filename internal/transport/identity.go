package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/jinomee/lanyard/internal/joincode"
)

// Identity is the host's long-lived TLS identity. Its certificate fingerprint
// is embedded in invite codes so guests can pin it.
type Identity struct {
	Cert tls.Certificate
}

// Fingerprint returns the truncated SHA-256 of the certificate DER.
func (id *Identity) Fingerprint() [joincode.FingerprintLen]byte {
	return FingerprintOf(id.Cert.Certificate[0])
}

// FingerprintOf returns the truncated SHA-256 of a DER certificate.
func FingerprintOf(der []byte) [joincode.FingerprintLen]byte {
	sum := sha256.Sum256(der)
	var fp [joincode.FingerprintLen]byte
	copy(fp[:], sum[:])
	return fp
}

// NewIdentity generates a fresh self-signed ECDSA P-256 certificate.
func NewIdentity() (*Identity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "lanyard-host"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().AddDate(30, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"lanyard"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &Identity{Cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}}, nil
}

// LoadOrCreateIdentity reads the identity from path, creating it (0600) if absent.
func LoadOrCreateIdentity(path string) (*Identity, error) {
	if b, err := os.ReadFile(path); err == nil {
		cert, err := tls.X509KeyPair(b, b)
		if err == nil {
			return &Identity{Cert: cert}, nil
		}
		// Corrupt file: fall through and replace it.
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	id, err := NewIdentity()
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(id.Cert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return nil, err
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: id.Cert.Certificate[0]})
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, fmt.Errorf("save identity: %w", err)
	}
	return id, nil
}
