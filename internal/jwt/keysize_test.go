package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"path/filepath"
	"testing"
)

// TestVerify_RejectsUndersizedRSAKey makes sure a correctly-signed token is
// still rejected when the only key backing it is below the strength floor.
func TestVerify_RejectsUndersizedRSAKey(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generating weak key: %v", err)
	}

	jwksPath := filepath.Join(t.TempDir(), "jwks.json")
	writeKeySet(t, jwksPath, keySet{Keys: []jwk{rsaJWK(weak, "weak-kid", "RS256")}})

	token := signToken(t, weak, "weak-kid", "RS256", baseClaims())

	if _, err := Verify(token, jwksPath, VerifyOptions{}); err == nil {
		t.Fatalf("expected a %d-bit RSA key to be refused", weak.N.BitLen())
	}
}
