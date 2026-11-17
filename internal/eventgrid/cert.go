package eventgrid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // Event Grid identifies a client certificate by its SHA-1 thumbprint; it is a name, not a security boundary
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// certLifetime is how long a client certificate is valid. Event Grid checks the
// thumbprint, and rotation replaces the certificate, so the lifetime only bounds
// a certificate nobody rotates.
const certLifetime = 10 * 365 * 24 * time.Hour

// Cert is a client certificate and its private key. Event Grid never sees the
// key: the operator makes the pair, and the key lives only in the binding
// Secret. Printing a Cert never shows the key.
type Cert struct {
	// Thumbprint is the SHA-1 thumbprint of the certificate, upper-case hex, as
	// Event Grid's allowedThumbprints list it.
	Thumbprint string
	PEM        string
	key        string
}

// Key is the private key, PKCS#8, PEM encoded.
func (c Cert) Key() string { return c.key }

// String lists the certificate's identity, never the key.
func (c Cert) String() string { return "eventgrid.Cert{" + c.Thumbprint + "}" }

// GoString is String, for %#v.
func (c Cert) GoString() string { return c.String() }

// NewCert makes a self-signed ECDSA P-256 client certificate whose common name
// is the client's authentication name.
func NewCert(authName string, now time.Time) (Cert, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Cert{}, fmt.Errorf("%w: generate a key: %w", ErrAPI, err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return Cert{}, fmt.Errorf("%w: generate a serial number: %w", ErrAPI, err)
	}
	tpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: authName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(certLifetime),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		return Cert{}, fmt.Errorf("%w: sign the certificate: %w", ErrAPI, err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return Cert{}, fmt.Errorf("%w: encode the key: %w", ErrAPI, err)
	}
	return Cert{
		Thumbprint: Thumbprint(der),
		PEM:        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		key:        string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
	}, nil
}

// Thumbprint is the upper-case hex SHA-1 of a DER certificate.
func Thumbprint(der []byte) string {
	sum := sha1.Sum(der) //nolint:gosec // see the import
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// PEMThumbprint is the thumbprint of the first certificate in a PEM text, or ""
// when there is none.
func PEMThumbprint(certPEM string) string {
	b, _ := pem.Decode([]byte(certPEM))
	if b == nil || b.Type != "CERTIFICATE" {
		return ""
	}
	return Thumbprint(b.Bytes)
}

// NormalizeThumbprint upper-cases a thumbprint and drops colons and spaces, so
// two spellings of one thumbprint compare equal.
func NormalizeThumbprint(t string) string {
	return strings.ToUpper(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(t)))
}
