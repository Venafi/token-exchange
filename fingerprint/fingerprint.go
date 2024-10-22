package fingerprint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"filippo.io/keygen"
)

type Fingerprint [sha256.Size]byte

func (f Fingerprint) Hex() string {
	return hex.EncodeToString(f[:])
}

func (f Fingerprint) String() string {
	return f.Hex()
}

func For(c *x509.Certificate) Fingerprint {
	return sha256.Sum256(c.Raw)
}

func Rootmost(certs []*x509.Certificate) (Fingerprint, error) {
	if len(certs) == 0 {
		return Fingerprint{}, fmt.Errorf("no certificates provided")
	}

	rootCertificate := certs[len(certs)-1]

	return For(rootCertificate), nil
}

func SigningKey(fingerprint Fingerprint, secretKey []byte) (*ecdsa.PrivateKey, error) {
	h := sha256.New()

	// hash.Hash is documented to never return an error
	_, _ = h.Write(fingerprint[:])
	_, _ = h.Write(secretKey)

	pk, err := keygen.ECDSA(elliptic.P256(), h.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	return pk, nil
}

type RootMap map[Fingerprint]*ecdsa.PrivateKey
