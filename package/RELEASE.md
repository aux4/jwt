# aux4/jwt 0.1.0

First release: local JWT verification against a JWKS file on disk, with no network call anywhere in the verification path.

- **`aux4 jwt verify`** — checks the signature against a local key set and enforces the claim checks you configure, then prints the claims as JSON. `--claim` pulls out one value, `--quiet true` makes it a pure exit-code gate. Fails closed: any problem is a non-zero exit with an empty stdout, and the token itself is never printed in output, errors or logs.
- **Asymmetric algorithms only** — RS256/384/512, PS256/384/512, ES256/384/512 and EdDSA. `none` and the HMAC family are rejected unconditionally, and asking for one via `--algorithms` is a configuration error rather than a silent no-op. The key type is chosen from the algorithm, never from the token, so an `ES256` token can only ever meet an EC P-256 key — the algorithm-confusion attack that forges an HS256 token from a published RSA public key has no path through.
- **`exp` is mandatory**, `nbf` and clock skew are honoured (`--clockSkew`, default 30s), `--maxAge` adds a freshness bound on `iat`, and RSA keys below 2048 bits are not used.
- **Unconfigured checks are announced, never silent** — when `--issuer` or `--audience` is not set, that claim is not checked and a warning saying so goes to stderr. `--strict true` turns a missing issuer or audience into a refusal to run; `--warnings false` silences the notice once the omission is deliberate.
- **`aux4 jwt decode-unverified`** — prints what a token says about itself, checking nothing. Named so it cannot be mistaken for verification, kept in its own command, and printing a warning to stderr on every invocation. Debugging aid only.
- **`aux4 jwt jwks list`** — the identifying metadata of the keys in a local key set, which is how an "unknown kid" failure gets diagnosed.
- **`aux4 jwt jwks fetch`** — downloads a key set over HTTPS to a file, discovering the endpoint from an OpenID Connect issuer when given `--issuer`. Setup time only and strictly separate from verification: HTTPS-only including redirects, the response validated before anything is written, and the write atomic so an interrupted download cannot leave a half-written trust anchor.
- **Configurable entirely by environment** — `AUX4_JWT_JWKS_FILE`, `AUX4_JWT_ISSUER`, `AUX4_JWT_AUDIENCE` and the rest, so a host can be set up once and callers need no command-line plumbing. A flag always overrides the environment.
- **No third-party dependency** — the Go standard library alone, so the trusted computing base of a verifier is the package itself.
