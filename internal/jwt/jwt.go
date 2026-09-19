// Package jwt verifies asymmetrically-signed JWTs entirely locally against a
// JWKS (JSON Web Key Set) already present on disk. It performs NO network I/O:
// fetching the JWKS is a separate, explicit, setup-time concern so that the
// trust anchor used at verification time is a plain local file that cannot be
// swapped by whoever controls the network.
//
// The implementation is built only on the Go standard library - no third-party
// JWT/JOSE dependency - so the trusted computing base of a verifier stays
// small and auditable.
//
// Security posture:
//
//   - Only asymmetric signature algorithms are accepted (RS*, PS*, ES*, EdDSA).
//     "none" and the HMAC family (HS*) are rejected unconditionally and there
//     is no option to enable them. Accepting "none" would skip signing
//     entirely; accepting HS256 would let an attacker forge a token using the
//     RSA public key published in the JWKS as if it were an HMAC secret - the
//     classic algorithm-confusion attack against JWKS-based verifiers.
//   - The key type is selected from the *requested algorithm*, never from the
//     token. A token claiming ES256 can only ever be checked against an EC
//     P-256 key from the JWKS; an RSA key is not even considered.
//   - There is no partial-success path. Any failure returns a non-nil error
//     and nil claims. Callers must treat any error as "unauthenticated" and
//     never fall through to an unscoped identity.
//   - Errors never contain the token or any part of it.
package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"
)

// Claims is the decoded JWT payload (the second segment).
type Claims map[string]interface{}

// String returns the named claim as a string, or "" if it is absent or not
// a string.
func (c Claims) String(name string) string {
	if v, ok := c[name]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// Header is the decoded JOSE header (the first segment).
type Header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type scheme int

const (
	schemePKCS1 scheme = iota
	schemePSS
	schemeECDSA
	schemeEdDSA
)

type algSpec struct {
	// kty is the JWK key type this algorithm requires. Binding the key type
	// to the algorithm (rather than to whatever key the token points at) is
	// what makes algorithm confusion impossible here.
	kty    string
	crv    string
	scheme scheme
	hash   crypto.Hash
	// sigSize is the expected raw signature length for ECDSA (r concatenated
	// with s).
	sigSize int
}

// supportedAlgorithms is the complete set of algorithms this verifier can
// ever accept. It contains no symmetric algorithm and no "none" entry, by
// design: an algorithm that is not in this map cannot be enabled by any flag,
// environment variable or token header.
var supportedAlgorithms = map[string]algSpec{
	"RS256": {kty: "RSA", scheme: schemePKCS1, hash: crypto.SHA256},
	"RS384": {kty: "RSA", scheme: schemePKCS1, hash: crypto.SHA384},
	"RS512": {kty: "RSA", scheme: schemePKCS1, hash: crypto.SHA512},
	"PS256": {kty: "RSA", scheme: schemePSS, hash: crypto.SHA256},
	"PS384": {kty: "RSA", scheme: schemePSS, hash: crypto.SHA384},
	"PS512": {kty: "RSA", scheme: schemePSS, hash: crypto.SHA512},
	"ES256": {kty: "EC", crv: "P-256", scheme: schemeECDSA, hash: crypto.SHA256, sigSize: 64},
	"ES384": {kty: "EC", crv: "P-384", scheme: schemeECDSA, hash: crypto.SHA384, sigSize: 96},
	"ES512": {kty: "EC", crv: "P-521", scheme: schemeECDSA, hash: crypto.SHA512, sigSize: 132},
	"EdDSA": {kty: "OKP", crv: "Ed25519", scheme: schemeEdDSA},
}

// DefaultAlgorithms is the algorithm allow-list applied when the caller does
// not pin one. Every entry requires a key of a matching type from the trusted
// JWKS, so there is no downgrade between them - which algorithms are actually
// usable is decided by the keys the JWKS owner publishes.
var DefaultAlgorithms = []string{
	"RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512",
	"EdDSA",
}

// MinRSAKeyBits is the smallest RSA modulus this verifier will use. Keys
// below it are ignored, which means a JWKS offering only undersized keys
// fails closed rather than verifying weakly.
const MinRSAKeyBits = 2048

// SupportedAlgorithms returns the names of every algorithm this verifier can
// accept.
func SupportedAlgorithms() []string {
	return append([]string(nil), DefaultAlgorithms...)
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type keySet struct {
	Keys []jwk `json:"keys"`
}

// VerifyOptions controls claim validation beyond the signature itself. Any
// field left at its zero value skips that check - callers that care about a
// check must configure it, and the command layer warns loudly about every
// check it is skipping.
type VerifyOptions struct {
	// Issuer, if non-empty, must exactly match the token's "iss" claim.
	Issuer string
	// Audience, if non-empty, must appear in the token's "aud" claim (which
	// may be a single string or an array of strings per the JWT spec).
	Audience string
	// Subject, if non-empty, must exactly match the token's "sub" claim.
	Subject string
	// Scope, if non-empty, must be one of the space-delimited tokens in the
	// token's "scope" claim (OAuth2 scope string, RFC 6749 section 3.3).
	Scope string
	// Algorithms is the allow-list of acceptable "alg" header values. When
	// empty, DefaultAlgorithms applies. Values outside supportedAlgorithms
	// are an error, not a silent widening.
	Algorithms []string
	// ClockSkew is the leeway applied to exp, nbf and iat checks.
	ClockSkew time.Duration
	// MaxAge, if greater than zero, requires an "iat" claim no older than
	// this duration.
	MaxAge time.Duration
	// Now overrides the clock, for tests.
	Now func() time.Time
}

func (o VerifyOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// DecodeUnverified splits a token and decodes its header and payload WITHOUT
// checking the signature or any claim. It exists for inspection and debugging
// only. Its result says nothing at all about whether the token is authentic:
// anybody can mint a token with any claims they like. Never make an
// authorization decision from this function's output - use Verify.
func DecodeUnverified(token string) (Header, Claims, error) {
	parts, err := split(token)
	if err != nil {
		return Header{}, nil, err
	}

	header, claims, err := decodeSegments(parts)
	if err != nil {
		return Header{}, nil, err
	}

	return header, claims, nil
}

// Verify checks the signature of token against the public keys in the JWKS
// file at jwksFilePath (matched by the token's "kid" header and constrained
// to the key type the algorithm requires), then validates the standard time
// claims (exp required, nbf if present) and whatever is requested in opts.
//
// It returns the decoded claims only when every check passes. Any failure -
// malformed token, unsupported or disallowed alg, no matching key, bad
// signature, expired, or an option mismatch - returns a non-nil error and nil
// claims.
func Verify(token string, jwksFilePath string, opts VerifyOptions) (Claims, error) {
	if strings.TrimSpace(jwksFilePath) == "" {
		return nil, errors.New("no jwks file configured")
	}

	parts, err := split(token)
	if err != nil {
		return nil, err
	}

	header, claims, err := decodeSegments(parts)
	if err != nil {
		return nil, err
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("malformed signature: not valid base64url")
	}

	spec, err := resolveAlgorithm(header.Alg, opts.Algorithms)
	if err != nil {
		return nil, err
	}

	keys, err := candidateKeys(jwksFilePath, header.Kid, header.Alg, spec)
	if err != nil {
		return nil, err
	}

	signingInput := []byte(parts[0] + "." + parts[1])

	verified := false
	for _, key := range keys {
		if verifySignature(spec, key, signingInput, sig) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, errors.New("invalid signature")
	}

	if err := validateClaims(claims, opts); err != nil {
		return nil, err
	}

	return claims, nil
}

func split(token string) ([]string, error) {
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("empty token")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token: expected 3 dot-separated segments")
	}

	return parts, nil
}

// decodeSegments base64url-decodes and JSON-parses the header and payload.
// Error messages are deliberately generic: wrapping the underlying JSON error
// could echo bytes of the token back into a log.
func decodeSegments(parts []string) (Header, Claims, error) {
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Header{}, nil, errors.New("malformed header: not valid base64url")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Header{}, nil, errors.New("malformed payload: not valid base64url")
	}

	var header Header
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return Header{}, nil, errors.New("malformed header: not valid JSON")
	}

	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return Header{}, nil, errors.New("malformed payload: not valid JSON")
	}

	return header, claims, nil
}

// resolveAlgorithm maps the token's declared alg onto a supported spec, after
// checking it against the caller's allow-list. The token never gets to widen
// the allow-list, and an algorithm outside supportedAlgorithms (notably
// "none" and the HS family) can never be resolved.
func resolveAlgorithm(alg string, allowed []string) (algSpec, error) {
	if alg == "" {
		return algSpec{}, errors.New("token header has no alg")
	}

	spec, ok := supportedAlgorithms[alg]
	if !ok {
		return algSpec{}, fmt.Errorf("unsupported alg %q (only asymmetric algorithms are accepted: %s)", alg, strings.Join(DefaultAlgorithms, ", "))
	}

	if len(allowed) == 0 {
		allowed = DefaultAlgorithms
	}

	for _, a := range allowed {
		if a == alg {
			return spec, nil
		}
	}

	return algSpec{}, fmt.Errorf("alg %q is not in the allowed set (%s)", alg, strings.Join(allowed, ", "))
}

// ValidateAlgorithmNames rejects an allow-list containing anything this
// verifier cannot accept, so that a typo or an attempt to enable "none" or
// "HS256" fails at configuration time instead of silently doing nothing.
func ValidateAlgorithmNames(names []string) error {
	for _, name := range names {
		if _, ok := supportedAlgorithms[name]; !ok {
			return fmt.Errorf("unsupported algorithm %q (supported: %s)", name, strings.Join(DefaultAlgorithms, ", "))
		}
	}
	return nil
}

// ListKeys loads a JWKS file and returns the public metadata of each key.
// A JWKS used for verification holds public keys only, and only their
// identifying metadata is returned here.
func ListKeys(path string) ([]map[string]string, error) {
	set, err := readKeySet(path)
	if err != nil {
		return nil, err
	}

	out := make([]map[string]string, 0, len(set.Keys))
	for _, k := range set.Keys {
		entry := map[string]string{"kty": k.Kty}
		if k.Kid != "" {
			entry["kid"] = k.Kid
		}
		if k.Alg != "" {
			entry["alg"] = k.Alg
		}
		if k.Use != "" {
			entry["use"] = k.Use
		}
		if k.Crv != "" {
			entry["crv"] = k.Crv
		}
		out = append(out, entry)
	}

	return out, nil
}

// ValidateKeySetBytes checks that data is a JWKS containing at least one key
// usable by this verifier. It is used before a fetched JWKS is written to
// disk, so a garbage or empty response never replaces a working trust anchor.
func ValidateKeySetBytes(data []byte) (int, error) {
	var set keySet
	if err := json.Unmarshal(data, &set); err != nil {
		return 0, errors.New("response is not a valid JWKS document")
	}

	usable := 0
	for _, k := range set.Keys {
		switch k.Kty {
		case "RSA":
			if k.N != "" && k.E != "" {
				usable++
			}
		case "EC":
			if k.X != "" && k.Y != "" && k.Crv != "" {
				usable++
			}
		case "OKP":
			if k.X != "" && k.Crv == "Ed25519" {
				usable++
			}
		}
	}

	if usable == 0 {
		return 0, errors.New("JWKS document contains no usable public key")
	}

	return usable, nil
}

func readKeySet(path string) (keySet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return keySet{}, fmt.Errorf("reading jwks file: %w", err)
	}

	var set keySet
	if err := json.Unmarshal(data, &set); err != nil {
		return keySet{}, errors.New("malformed jwks file: not a valid JWKS document")
	}

	return set, nil
}

// candidateKeys returns every key in the JWKS that is eligible to have
// produced a signature with the given algorithm: the kid must match when the
// token carries one, the key's own "use" and "alg" hints must not contradict,
// and the key type and curve must be exactly what the algorithm requires.
func candidateKeys(jwksFilePath, kid, alg string, spec algSpec) ([]crypto.PublicKey, error) {
	set, err := readKeySet(jwksFilePath)
	if err != nil {
		return nil, err
	}

	keys := make([]crypto.PublicKey, 0, len(set.Keys))
	for _, k := range set.Keys {
		if kid != "" && k.Kid != kid {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if k.Alg != "" && k.Alg != alg {
			continue
		}
		if k.Kty != spec.kty {
			continue
		}
		if spec.crv != "" && k.Crv != spec.crv {
			continue
		}

		key, err := buildPublicKey(k, spec)
		if err != nil {
			continue
		}
		keys = append(keys, key)
	}

	if len(keys) == 0 {
		if kid != "" {
			return nil, fmt.Errorf("no %s key with kid %q found in jwks", alg, kid)
		}
		return nil, fmt.Errorf("no %s key found in jwks (token has no kid)", alg)
	}

	return keys, nil
}

func buildPublicKey(k jwk, spec algSpec) (crypto.PublicKey, error) {
	switch spec.kty {
	case "RSA":
		return buildRSAPublicKey(k)
	case "EC":
		return buildECPublicKey(k, spec)
	case "OKP":
		return buildEd25519PublicKey(k)
	}
	return nil, fmt.Errorf("unsupported key type %q", spec.kty)
}

func buildRSAPublicKey(k jwk) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, errors.New("malformed jwks modulus")
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, errors.New("malformed jwks exponent")
	}
	if len(nBytes) == 0 || len(eBytes) == 0 || len(eBytes) > 8 {
		return nil, errors.New("malformed jwks rsa key")
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() || e.Int64() < 3 {
		return nil, errors.New("malformed jwks rsa exponent")
	}
	// A 1024-bit RSA key has been below the accepted strength floor since
	// 2013 (NIST SP 800-57). Accepting one would make the whole verification
	// theatre, so such a key is simply not a candidate.
	if n.BitLen() < MinRSAKeyBits {
		return nil, fmt.Errorf("rsa key is %d bits, below the %d-bit minimum", n.BitLen(), MinRSAKeyBits)
	}

	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func buildECPublicKey(k jwk, spec algSpec) (*ecdsa.PublicKey, error) {
	curve, err := curveFor(spec.crv)
	if err != nil {
		return nil, err
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, errors.New("malformed jwks ec x coordinate")
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, errors.New("malformed jwks ec y coordinate")
	}

	key := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	if !curve.IsOnCurve(key.X, key.Y) {
		return nil, errors.New("jwks ec point is not on the curve")
	}

	return key, nil
}

func buildEd25519PublicKey(k jwk) (ed25519.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, errors.New("malformed jwks okp x coordinate")
	}
	if len(xBytes) != ed25519.PublicKeySize {
		return nil, errors.New("malformed jwks ed25519 key")
	}
	return ed25519.PublicKey(xBytes), nil
}

func curveFor(name string) (elliptic.Curve, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	}
	return nil, fmt.Errorf("unsupported curve %q", name)
}

func verifySignature(spec algSpec, key crypto.PublicKey, signingInput, sig []byte) bool {
	switch spec.scheme {
	case schemePKCS1:
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return false
		}
		digest := hashOf(spec.hash, signingInput)
		return rsa.VerifyPKCS1v15(pub, spec.hash, digest, sig) == nil

	case schemePSS:
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return false
		}
		digest := hashOf(spec.hash, signingInput)
		// JOSE fixes the PSS salt length to the hash length (RFC 7518 3.5).
		options := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: spec.hash}
		return rsa.VerifyPSS(pub, spec.hash, digest, sig, options) == nil

	case schemeECDSA:
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		// JOSE ECDSA signatures are the fixed-width concatenation of r and s,
		// not the ASN.1 form; a wrong length is a rejection, never a best
		// effort.
		if len(sig) != spec.sigSize {
			return false
		}
		half := spec.sigSize / 2
		r := new(big.Int).SetBytes(sig[:half])
		s := new(big.Int).SetBytes(sig[half:])
		digest := hashOf(spec.hash, signingInput)
		return ecdsa.Verify(pub, digest, r, s)

	case schemeEdDSA:
		pub, ok := key.(ed25519.PublicKey)
		if !ok {
			return false
		}
		if len(sig) != ed25519.SignatureSize {
			return false
		}
		return ed25519.Verify(pub, signingInput, sig)
	}

	return false
}

func hashOf(h crypto.Hash, data []byte) []byte {
	switch h {
	case crypto.SHA256:
		sum := sha256.Sum256(data)
		return sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384(data)
		return sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512(data)
		return sum[:]
	}
	return nil
}

func validateClaims(claims Claims, opts VerifyOptions) error {
	skew := opts.ClockSkew
	now := opts.now()

	// exp is mandatory. A token that never expires is not something this
	// verifier will accept, regardless of how well it is signed.
	exp, ok := numericClaim(claims, "exp")
	if !ok {
		return errors.New("token has no exp claim")
	}
	if now.After(time.Unix(exp, 0).Add(skew)) {
		return errors.New("token expired")
	}

	if nbf, ok := numericClaim(claims, "nbf"); ok {
		if now.Before(time.Unix(nbf, 0).Add(-skew)) {
			return errors.New("token not yet valid")
		}
	}

	if opts.MaxAge > 0 {
		iat, ok := numericClaim(claims, "iat")
		if !ok {
			return errors.New("token has no iat claim, which maxAge requires")
		}
		if now.After(time.Unix(iat, 0).Add(opts.MaxAge).Add(skew)) {
			return errors.New("token is older than the allowed maxAge")
		}
	}

	if opts.Issuer != "" && claims.String("iss") != opts.Issuer {
		return fmt.Errorf("unexpected issuer %q", claims.String("iss"))
	}

	if opts.Audience != "" && !audienceMatches(claims["aud"], opts.Audience) {
		return errors.New("unexpected audience")
	}

	if opts.Subject != "" && claims.String("sub") != opts.Subject {
		return errors.New("unexpected subject")
	}

	if opts.Scope != "" && !scopeContains(claims.String("scope"), opts.Scope) {
		return fmt.Errorf("token scope does not include %q", opts.Scope)
	}

	return nil
}

func numericClaim(claims Claims, name string) (int64, bool) {
	v, ok := claims[name]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	case string:
		i, err := strconv.ParseInt(n, 10, 64)
		return i, err == nil
	}
	return 0, false
}

func audienceMatches(aud interface{}, expected string) bool {
	switch v := aud.(type) {
	case string:
		return v == expected
	case []interface{}:
		for _, a := range v {
			if s, ok := a.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}

// scopeContains checks whether expected is one of the whitespace-delimited
// tokens in scopeClaim (OAuth2 space-delimited scope string, RFC 6749 3.3).
func scopeContains(scopeClaim, expected string) bool {
	for _, s := range strings.Fields(scopeClaim) {
		if s == expected {
			return true
		}
	}
	return false
}
