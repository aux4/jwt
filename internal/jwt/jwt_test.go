package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testKeyPair generates a throwaway RSA key pair and writes a JWKS file
// exposing its public half, for fully offline (no network) test fixtures.
func testKeyPair(t *testing.T) (*rsa.PrivateKey, string, string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}

	kid := "test-kid-1"
	jwksPath := filepath.Join(t.TempDir(), "jwks.json")

	set := keySet{
		Keys: []jwk{rsaJWK(key, kid, "RS256")},
	}

	writeKeySet(t, jwksPath, set)

	return key, kid, jwksPath
}

func rsaJWK(key *rsa.PrivateKey, kid, alg string) jwk {
	return jwk{
		Kty: "RSA",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(bigIntBytes(key.PublicKey.E)),
		Alg: alg,
	}
}

func writeKeySet(t *testing.T, path string, set keySet) {
	t.Helper()

	data, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshaling jwks: %v", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("writing jwks file: %v", err)
	}
}

func bigIntBytes(e int) []byte {
	// Standard RSA public exponent (65537) encodes to 3 bytes; this helper
	// keeps the test fixture generic instead of hardcoding "AQAB".
	b := []byte{byte(e >> 16), byte(e >> 8), byte(e)}
	// Trim leading zero bytes, matching how JWKS encodes E.
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	return b
}

func encodeSegments(t *testing.T, alg, kid string, claims map[string]interface{}) string {
	t.Helper()

	header := map[string]interface{}{"alg": alg, "typ": "JWT"}
	if kid != "" {
		header["kid"] = kid
	}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	return headerB64 + "." + claimsB64
}

func signToken(t *testing.T, key *rsa.PrivateKey, kid string, alg string, claims map[string]interface{}) string {
	t.Helper()

	signingInput := encodeSegments(t, alg, kid, claims)

	if alg != "RS256" {
		// Used only to build a malformed/unsigned-style token for the alg
		// rejection test; the "signature" is meaningless.
		return signingInput + ".bm90LWEtc2lnbmF0dXJl"
	}

	hashed := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("signing test token: %v", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func baseClaims() map[string]interface{} {
	now := time.Now()
	return map[string]interface{}{
		"sub":   "user-123",
		"email": "user@example.com",
		"scope": "cloud:invoke",
		"iss":   "https://sso.aux4.io",
		"aud":   "aux4-machine-invoke",
		"iat":   now.Unix(),
		"exp":   now.Add(15 * time.Minute).Unix(),
	}
}

// --- the eleven checks carried over from the aux4 core implementation -------

func TestVerify_ValidToken(t *testing.T) {
	key, kid, jwksPath := testKeyPair(t)
	token := signToken(t, key, kid, "RS256", baseClaims())

	claims, err := Verify(token, jwksPath, VerifyOptions{
		Issuer:    "https://sso.aux4.io",
		Scope:     "cloud:invoke",
		ClockSkew: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("expected valid token to verify, got error: %v", err)
	}
	if claims.String("sub") != "user-123" {
		t.Errorf("expected sub=user-123, got %q", claims.String("sub"))
	}
	if claims.String("email") != "user@example.com" {
		t.Errorf("expected email claim to survive, got %q", claims.String("email"))
	}
}

func TestVerify_EmptyToken(t *testing.T) {
	_, _, jwksPath := testKeyPair(t)
	if _, err := Verify("", jwksPath, VerifyOptions{}); err == nil {
		t.Fatal("expected empty token to fail closed")
	}
}

func TestVerify_MalformedToken(t *testing.T) {
	_, _, jwksPath := testKeyPair(t)
	if _, err := Verify("not-a-jwt", jwksPath, VerifyOptions{}); err == nil {
		t.Fatal("expected malformed token to fail closed")
	}
}

func TestVerify_ExpiredToken(t *testing.T) {
	key, kid, jwksPath := testKeyPair(t)
	claims := baseClaims()
	claims["exp"] = time.Now().Add(-1 * time.Hour).Unix()
	token := signToken(t, key, kid, "RS256", claims)

	if _, err := Verify(token, jwksPath, VerifyOptions{ClockSkew: 30 * time.Second}); err == nil {
		t.Fatal("expected expired token to fail closed")
	}
}

func TestVerify_MissingExpClaim(t *testing.T) {
	key, kid, jwksPath := testKeyPair(t)
	claims := baseClaims()
	delete(claims, "exp")
	token := signToken(t, key, kid, "RS256", claims)

	if _, err := Verify(token, jwksPath, VerifyOptions{}); err == nil {
		t.Fatal("expected token with no exp claim to fail closed")
	}
}

func TestVerify_WrongSignature(t *testing.T) {
	_, kid, jwksPath := testKeyPair(t)

	// Sign with a DIFFERENT key but publish the original key's JWKS - the
	// signature must not verify against a key that didn't produce it.
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating imposter key: %v", err)
	}
	imposterToken := signToken(t, otherKey, kid, "RS256", baseClaims())

	if _, err := Verify(imposterToken, jwksPath, VerifyOptions{}); err == nil {
		t.Fatal("expected signature from a non-matching key to fail closed")
	}
}

func TestVerify_RejectsNoneAlg(t *testing.T) {
	key, kid, jwksPath := testKeyPair(t)
	token := signToken(t, key, kid, "none", baseClaims())

	if _, err := Verify(token, jwksPath, VerifyOptions{}); err == nil {
		t.Fatal("expected alg=none token to be rejected (fail closed)")
	}
}

func TestVerify_UnknownKid(t *testing.T) {
	key, _, jwksPath := testKeyPair(t)
	token := signToken(t, key, "some-other-kid", "RS256", baseClaims())

	if _, err := Verify(token, jwksPath, VerifyOptions{}); err == nil {
		t.Fatal("expected unknown kid to fail closed")
	}
}

func TestVerify_ScopeMismatch(t *testing.T) {
	key, kid, jwksPath := testKeyPair(t)
	token := signToken(t, key, kid, "RS256", baseClaims())

	if _, err := Verify(token, jwksPath, VerifyOptions{Scope: "cloud:build"}); err == nil {
		t.Fatal("expected scope mismatch to fail closed")
	}
}

func TestVerify_IssuerMismatch(t *testing.T) {
	key, kid, jwksPath := testKeyPair(t)
	token := signToken(t, key, kid, "RS256", baseClaims())

	if _, err := Verify(token, jwksPath, VerifyOptions{Issuer: "https://evil.example.com"}); err == nil {
		t.Fatal("expected issuer mismatch to fail closed")
	}
}

func TestVerify_MissingJwksFile(t *testing.T) {
	key, kid, _ := testKeyPair(t)
	token := signToken(t, key, kid, "RS256", baseClaims())

	if _, err := Verify(token, "/nonexistent/jwks.json", VerifyOptions{}); err == nil {
		t.Fatal("expected a missing jwks file to fail closed, not silently pass")
	}
}

// --- checks added for the generalised, public package ----------------------

func TestVerify_NoJwksFileConfigured(t *testing.T) {
	key, kid, _ := testKeyPair(t)
	token := signToken(t, key, kid, "RS256", baseClaims())

	if _, err := Verify(token, "", VerifyOptions{}); err == nil {
		t.Fatal("expected an empty jwks path to fail closed")
	}
}

// TestVerify_RejectsHS256SignedWithPublicKey is the algorithm-confusion
// attack in full: the attacker takes the RSA public key straight out of the
// published JWKS, uses it as an HMAC secret, and mints a token whose header
// says HS256. A verifier that trusted the token's own alg would accept it.
func TestVerify_RejectsHS256SignedWithPublicKey(t *testing.T) {
	key, kid, jwksPath := testKeyPair(t)

	signingInput := encodeSegments(t, "HS256", kid, baseClaims())
	mac := hmac.New(sha256.New, key.PublicKey.N.Bytes())
	mac.Write([]byte(signingInput))
	forged := signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if _, err := Verify(forged, jwksPath, VerifyOptions{}); err == nil {
		t.Fatal("expected an HS256 token forged from the JWKS public key to be rejected")
	}
}

func TestVerify_AlgorithmNotInAllowList(t *testing.T) {
	key, kid, jwksPath := testKeyPair(t)
	token := signToken(t, key, kid, "RS256", baseClaims())

	if _, err := Verify(token, jwksPath, VerifyOptions{Algorithms: []string{"ES256"}}); err == nil {
		t.Fatal("expected an alg outside the allow-list to fail closed")
	}
}

func TestVerify_AudienceMismatch(t *testing.T) {
	key, kid, jwksPath := testKeyPair(t)
	token := signToken(t, key, kid, "RS256", baseClaims())

	if _, err := Verify(token, jwksPath, VerifyOptions{Audience: "someone-else"}); err == nil {
		t.Fatal("expected audience mismatch to fail closed")
	}
}

func TestVerify_AudienceArray(t *testing.T) {
	key, kid, jwksPath := testKeyPair(t)
	claims := baseClaims()
	claims["aud"] = []string{"other", "aux4-machine-invoke"}
	token := signToken(t, key, kid, "RS256", claims)

	if _, err := Verify(token, jwksPath, VerifyOptions{Audience: "aux4-machine-invoke"}); err != nil {
		t.Fatalf("expected an audience array containing the value to verify, got: %v", err)
	}
}

func TestVerify_SubjectMismatch(t *testing.T) {
	key, kid, jwksPath := testKeyPair(t)
	token := signToken(t, key, kid, "RS256", baseClaims())

	if _, err := Verify(token, jwksPath, VerifyOptions{Subject: "someone-else"}); err == nil {
		t.Fatal("expected subject mismatch to fail closed")
	}
}

func TestVerify_NotYetValid(t *testing.T) {
	key, kid, jwksPath := testKeyPair(t)
	claims := baseClaims()
	claims["nbf"] = time.Now().Add(10 * time.Minute).Unix()
	token := signToken(t, key, kid, "RS256", claims)

	if _, err := Verify(token, jwksPath, VerifyOptions{}); err == nil {
		t.Fatal("expected a not-yet-valid token to fail closed")
	}
}

func TestVerify_ClockSkewAllowsRecentlyExpired(t *testing.T) {
	key, kid, jwksPath := testKeyPair(t)
	claims := baseClaims()
	claims["exp"] = time.Now().Add(-10 * time.Second).Unix()
	token := signToken(t, key, kid, "RS256", claims)

	if _, err := Verify(token, jwksPath, VerifyOptions{ClockSkew: 60 * time.Second}); err != nil {
		t.Fatalf("expected clock skew to cover a 10s-expired token, got: %v", err)
	}
	if _, err := Verify(token, jwksPath, VerifyOptions{ClockSkew: 0}); err == nil {
		t.Fatal("expected the same token to be rejected with no skew")
	}
}

func TestVerify_MaxAge(t *testing.T) {
	key, kid, jwksPath := testKeyPair(t)
	claims := baseClaims()
	claims["iat"] = time.Now().Add(-10 * time.Minute).Unix()
	token := signToken(t, key, kid, "RS256", claims)

	if _, err := Verify(token, jwksPath, VerifyOptions{MaxAge: 5 * time.Minute}); err == nil {
		t.Fatal("expected a token older than maxAge to fail closed")
	}
	if _, err := Verify(token, jwksPath, VerifyOptions{MaxAge: 30 * time.Minute}); err != nil {
		t.Fatalf("expected a token within maxAge to verify, got: %v", err)
	}
}

func TestVerify_MaxAgeRequiresIat(t *testing.T) {
	key, kid, jwksPath := testKeyPair(t)
	claims := baseClaims()
	delete(claims, "iat")
	token := signToken(t, key, kid, "RS256", claims)

	if _, err := Verify(token, jwksPath, VerifyOptions{MaxAge: 5 * time.Minute}); err == nil {
		t.Fatal("expected maxAge with no iat claim to fail closed")
	}
}

// TestVerify_KeyTypeIsBoundToAlgorithm publishes an EC key under the same kid
// the token names. A verifier that picked the key by kid alone and then asked
// "what kind of key is this?" would try to use it; this one refuses because
// RS256 requires an RSA key.
func TestVerify_KeyTypeIsBoundToAlgorithm(t *testing.T) {
	key, kid, jwksPath := testKeyPair(t)
	token := signToken(t, key, kid, "RS256", baseClaims())

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ec key: %v", err)
	}

	writeKeySet(t, jwksPath, keySet{Keys: []jwk{{
		Kty: "EC",
		Kid: kid,
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(ecKey.PublicKey.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(ecKey.PublicKey.Y.Bytes()),
	}}})

	if _, err := Verify(token, jwksPath, VerifyOptions{}); err == nil {
		t.Fatal("expected an RS256 token to be rejected when the kid resolves to an EC key")
	}
}

func TestVerify_SkipsEncryptionOnlyKeys(t *testing.T) {
	key, kid, jwksPath := testKeyPair(t)
	token := signToken(t, key, kid, "RS256", baseClaims())

	encKey := rsaJWK(key, kid, "")
	encKey.Use = "enc"
	writeKeySet(t, jwksPath, keySet{Keys: []jwk{encKey}})

	if _, err := Verify(token, jwksPath, VerifyOptions{}); err == nil {
		t.Fatal("expected a key marked use=enc to be ignored for signature verification")
	}
}

func TestVerify_PicksTheRightKeyAmongMany(t *testing.T) {
	key, kid, jwksPath := testKeyPair(t)
	token := signToken(t, key, kid, "RS256", baseClaims())

	decoy, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating decoy key: %v", err)
	}

	writeKeySet(t, jwksPath, keySet{Keys: []jwk{
		rsaJWK(decoy, "decoy-kid", "RS256"),
		rsaJWK(key, kid, "RS256"),
	}})

	if _, err := Verify(token, jwksPath, VerifyOptions{}); err != nil {
		t.Fatalf("expected the matching kid to be found among several keys, got: %v", err)
	}
}

func TestVerify_MalformedJwksFile(t *testing.T) {
	key, kid, jwksPath := testKeyPair(t)
	token := signToken(t, key, kid, "RS256", baseClaims())

	if err := os.WriteFile(jwksPath, []byte("this is not json"), 0644); err != nil {
		t.Fatalf("writing malformed jwks: %v", err)
	}

	if _, err := Verify(token, jwksPath, VerifyOptions{}); err == nil {
		t.Fatal("expected a malformed jwks file to fail closed")
	}
}

func TestVerify_ES256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ec key: %v", err)
	}

	jwksPath := filepath.Join(t.TempDir(), "jwks.json")
	writeKeySet(t, jwksPath, keySet{Keys: []jwk{{
		Kty: "EC",
		Kid: "ec-kid",
		Crv: "P-256",
		Alg: "ES256",
		X:   base64.RawURLEncoding.EncodeToString(padLeft(key.PublicKey.X.Bytes(), 32)),
		Y:   base64.RawURLEncoding.EncodeToString(padLeft(key.PublicKey.Y.Bytes(), 32)),
	}}})

	signingInput := encodeSegments(t, "ES256", "ec-kid", baseClaims())
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("signing es256 token: %v", err)
	}
	sig := append(padLeft(r.Bytes(), 32), padLeft(s.Bytes(), 32)...)
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	if _, err := Verify(token, jwksPath, VerifyOptions{}); err != nil {
		t.Fatalf("expected a valid ES256 token to verify, got: %v", err)
	}

	if _, err := Verify(token, jwksPath, VerifyOptions{Algorithms: []string{"RS256"}}); err == nil {
		t.Fatal("expected ES256 to be rejected when only RS256 is allowed")
	}
}

func TestVerify_EdDSA(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating ed25519 key: %v", err)
	}

	jwksPath := filepath.Join(t.TempDir(), "jwks.json")
	writeKeySet(t, jwksPath, keySet{Keys: []jwk{{
		Kty: "OKP",
		Kid: "ed-kid",
		Crv: "Ed25519",
		Alg: "EdDSA",
		X:   base64.RawURLEncoding.EncodeToString(pub),
	}}})

	signingInput := encodeSegments(t, "EdDSA", "ed-kid", baseClaims())
	sig := ed25519.Sign(priv, []byte(signingInput))
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	if _, err := Verify(token, jwksPath, VerifyOptions{}); err != nil {
		t.Fatalf("expected a valid EdDSA token to verify, got: %v", err)
	}
}

func TestDecodeUnverified_DoesNotValidate(t *testing.T) {
	key, kid, _ := testKeyPair(t)
	claims := baseClaims()
	claims["exp"] = time.Now().Add(-10 * time.Hour).Unix()
	token := signToken(t, key, kid, "RS256", claims)

	header, decoded, err := DecodeUnverified(token)
	if err != nil {
		t.Fatalf("expected an expired token to still decode, got: %v", err)
	}
	if header.Alg != "RS256" {
		t.Errorf("expected alg=RS256 in the header, got %q", header.Alg)
	}
	if decoded.String("sub") != "user-123" {
		t.Errorf("expected sub=user-123, got %q", decoded.String("sub"))
	}
}

func TestDecodeUnverified_RejectsGarbage(t *testing.T) {
	if _, _, err := DecodeUnverified("nope"); err == nil {
		t.Fatal("expected a non-JWT string to fail to decode")
	}
}

func TestValidateAlgorithmNames(t *testing.T) {
	if err := ValidateAlgorithmNames([]string{"RS256", "ES384"}); err != nil {
		t.Fatalf("expected supported algorithms to validate, got: %v", err)
	}
	for _, bad := range []string{"none", "HS256", "RS257", ""} {
		if err := ValidateAlgorithmNames([]string{bad}); err == nil {
			t.Fatalf("expected %q to be rejected at configuration time", bad)
		}
	}
}

func TestValidateKeySetBytes(t *testing.T) {
	key, _, _ := testKeyPair(t)

	good, err := json.Marshal(keySet{Keys: []jwk{rsaJWK(key, "k1", "RS256")}})
	if err != nil {
		t.Fatalf("marshaling jwks: %v", err)
	}
	if n, err := ValidateKeySetBytes(good); err != nil || n != 1 {
		t.Fatalf("expected 1 usable key, got %d (%v)", n, err)
	}

	if _, err := ValidateKeySetBytes([]byte(`{"keys":[]}`)); err == nil {
		t.Fatal("expected an empty key set to be rejected")
	}
	if _, err := ValidateKeySetBytes([]byte(`<html>nope</html>`)); err == nil {
		t.Fatal("expected a non-JSON response to be rejected")
	}
}

func TestListKeys(t *testing.T) {
	_, kid, jwksPath := testKeyPair(t)

	keys, err := ListKeys(jwksPath)
	if err != nil {
		t.Fatalf("listing keys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0]["kid"] != kid {
		t.Errorf("expected kid=%q, got %q", kid, keys[0]["kid"])
	}
	if keys[0]["kty"] != "RSA" {
		t.Errorf("expected kty=RSA, got %q", keys[0]["kty"])
	}
}

func padLeft(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
