/*
Copyright 2024 Venafi

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package fingerprint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"filippo.io/keygen"

	"github.com/Venafi/token-exchange/internal/rsagen"
)

func Decode(hexStr string) (Fingerprint, error) {
	decodedIDRaw, err := hex.DecodeString(hexStr)
	if err != nil {
		return Fingerprint{}, fmt.Errorf("failed to decode fingerprint in path as valid hex: %s", err)
	}

	if len(decodedIDRaw) != sha256.Size {
		return Fingerprint{}, fmt.Errorf("invalid size for decoded fingerprint: %d", len(decodedIDRaw))
	}

	return Fingerprint(decodedIDRaw), nil
}

// Fingerprint represents a SHA256 fingerprint, usually derived from an X.509 certificate
type Fingerprint [sha256.Size]byte

func (f Fingerprint) Hex() string {
	return hex.EncodeToString(f[:])
}

func (f Fingerprint) String() string {
	return f.Hex()
}

// seed generates a key-derivation-function seed from the fingerprint and given secret key.
// Generated seeds _must_ be kept private.
func (f Fingerprint) seed(secretKey []byte) [32]byte {
	return sha256.Sum256(append(f[:], secretKey...))
}

func (f Fingerprint) DeriveRSASigningKey(secretKey []byte) (*rsa.PrivateKey, error) {
	pk, err := rsagen.RSAChaCha(2048, f.seed(secretKey))
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	return pk, nil
}

func (f Fingerprint) DeriveECDSASigningKey(secretKey []byte) (*ecdsa.PrivateKey, error) {
	s := f.seed(secretKey)

	pk, err := keygen.ECDSA(elliptic.P256(), s[:])
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	return pk, nil
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

type RootMap map[Fingerprint]*rsa.PrivateKey
