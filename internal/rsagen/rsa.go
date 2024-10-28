package rsagen

import (
	"crypto/rsa"
	rand2 "math/rand/v2"
)

// RSAChaCha returns a deterministic RSA key from the given seed using the ChaCha8 algorithm
// as a cryptographic key derivation function.
// This uses `math/rand/v2.NewChaCha8` which is [documented](https://pkg.go.dev/math/rand/v2#ChaCha8)
// to be cryptographically secure, and has [tests](https://cs.opensource.google/go/go/+/refs/tags/go1.23.2:src/internal/chacha8rand/rand_test.go;l=102)
// to ensure that its output is deterministic.
// The seed must be kept secret, as must the returned key.
func RSAChaCha(bits int, seed [32]byte) (*rsa.PrivateKey, error) {
	rand := rand2.NewChaCha8(seed)

	return GenerateKey(rand, bits)
}
