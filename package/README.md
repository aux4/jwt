# aux4/jwt

Verify JSON Web Tokens against a JWKS file on disk, with no network call in the
verification path. Point it at a key set you already have, hand it a token, and
it either prints the claims or exits non-zero — fast enough for a per-request
check, and usable on a host with no outbound access at all.

It is built on the Go standard library alone: no JOSE dependency, nothing to
audit beyond the package itself.

## Installation

```bash
aux4 aux4 pkger install aux4/jwt
```

## Quick Start

```bash
# Install the trust anchor once
aux4 jwt jwks fetch --issuer https://issuer.example.com --output /etc/aux4/jwks.json

# Verify a token and print its claims
aux4 jwt verify --tokenFile /run/token \
  --jwksFile /etc/aux4/jwks.json \
  --issuer https://issuer.example.com \
  --audience my-api

# Pull out one claim
aux4 jwt verify --tokenFile /run/token --jwksFile /etc/aux4/jwks.json \
  --issuer https://issuer.example.com --audience my-api --claim sub
```

```text
user-123
```

Use it as a gate in a script — nothing reaches stdout unless the token passed
every check:

```bash
aux4 jwt verify --tokenFile /run/token --jwksFile /etc/aux4/jwks.json \
  --issuer https://issuer.example.com --audience my-api --quiet true \
  || exit 1
```

## Commands

| Command | What it does |
|---------|--------------|
| `aux4 jwt verify` | Verify a token against a local JWKS and print its claims |
| `aux4 jwt decode-unverified` | Print what a token claims, checking nothing. Debugging only |
| `aux4 jwt jwks list` | List the keys in a local JWKS file |
| `aux4 jwt jwks fetch` | Download a JWKS over HTTPS to a local file. Setup time only |

## Verifying a Token

`aux4 jwt verify` is the only command whose output may be used to make an
authorization decision.

```bash
aux4 jwt verify [<token>] --jwksFile <path> [options]
```

| Option | Environment variable | Default | Description |
|--------|---------------------|---------|-------------|
| `--jwksFile` | `AUX4_JWT_JWKS_FILE` | — | Local JWKS file holding the trusted public keys. Required |
| `--tokenFile` | `AUX4_JWT_TOKEN_FILE` | — | Read the token from a file |
| `<token>` | `AUX4_JWT_TOKEN` | — | The token, as a positional argument |
| `--issuer` | `AUX4_JWT_ISSUER` | — | Require this exact `iss` claim |
| `--audience` | `AUX4_JWT_AUDIENCE` | — | Require this value in the `aud` claim |
| `--subject` | `AUX4_JWT_SUBJECT` | — | Require this exact `sub` claim |
| `--scope` | `AUX4_JWT_SCOPE` | — | Require this value among the space-delimited `scope` claim |
| `--algorithms` | `AUX4_JWT_ALGORITHMS` | all asymmetric | Comma-separated allow-list of signature algorithms |
| `--clockSkew` | `AUX4_JWT_CLOCK_SKEW` | `30` | Leeway in seconds for `exp`, `nbf` and `iat` |
| `--maxAge` | `AUX4_JWT_MAX_AGE` | `0` | Reject tokens issued more than this many seconds ago. `0` disables |
| `--claim` | — | — | Print only this claim instead of the whole claim set |
| `--quiet` | — | `false` | Print nothing on success; rely on the exit code |
| `--strict` | `AUX4_JWT_STRICT` | `false` | Refuse to run unless issuer and audience are both configured |
| `--warnings` | `AUX4_JWT_WARNINGS` | `true` | Warn about every claim check that is not configured |

### What is always checked

- The signature, against a key from the JWKS selected by the token's `kid`.
- The algorithm, against the accepted set (see below).
- `exp`, which is **mandatory**. A token with no expiry is rejected however
  well it is signed.
- `nbf`, when present.
- Key strength: RSA keys below 2048 bits are not used.

### What is checked only when you configure it

`--issuer`, `--audience`, `--subject`, `--scope` and `--maxAge` are enforced
only when set.

**When `--issuer` or `--audience` is not configured, that claim is not checked
and a warning saying so is printed to stderr.** Silently skipping a check is
how tools like this get misused, so the skip is always announced. Warnings go
to stderr, never stdout, so they cannot corrupt claims you are piping
somewhere.

Two ways to deal with the warning, depending on what you meant:

```bash
# You want both checks enforced: refuse to run without them
aux4 jwt verify --tokenFile /run/token --jwksFile jwks.json --strict true
```

```text
strict mode requires --issuer and --audience to be configured
```

```bash
# You genuinely do not want the check: say so and silence the notice
aux4 jwt verify --tokenFile /run/token --jwksFile jwks.json --warnings false
```

### Failure behaviour

There is no partial success. On any failure the command exits non-zero, writes
the reason to stderr and writes **nothing** to stdout.

| Exit code | Meaning |
|-----------|---------|
| `0` | Verified; every configured check passed |
| `1` | The token was rejected |
| `2` | The command could not run as asked (bad usage, unreadable JWKS) |

The token is never printed — not in output, not in errors, not in logs.

### Supplying the token

A token can come from a positional argument, from `AUX4_JWT_TOKEN`, or from
`--tokenFile`. A leading `Bearer ` is accepted and stripped, so the value of an
Authorization header can be passed straight through.

**Note:** a token passed as a command-line argument is visible to every process
on the machine through the process list. Prefer `AUX4_JWT_TOKEN` or a file.

Supplying both a token and a `--tokenFile` is an error rather than a silent
precedence rule, so it is always unambiguous which credential was checked.

## Algorithms

Accepted: `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`,
`ES384`, `ES512`, `EdDSA`.

`none` and the HMAC family (`HS256` and friends) are rejected unconditionally.
**No flag or environment variable can enable them**, and asking for one is a
configuration error rather than a silent no-op:

```bash
aux4 jwt verify --tokenFile token.txt --jwksFile jwks.json --algorithms HS256
```

```text
unsupported algorithm "HS256" (supported: RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA)
```

This is what stops the classic algorithm-confusion attack, in which a forger
takes the RSA public key out of a published JWKS, uses it as an HMAC secret and
relabels the header `HS256`.

The key type is chosen from the algorithm, never from the token: a token
declaring `ES256` can only ever be checked against an EC P-256 key, and a JWKS
key whose own `alg` or `use` contradicts the token is not a candidate at all.

`--algorithms` narrows the set further when you know exactly what your issuer
signs with:

```bash
aux4 jwt verify --tokenFile token.txt --jwksFile jwks.json \
  --issuer https://issuer.example.com --audience my-api --algorithms RS256
```

## Configuring by Environment

Every option can be set by environment variable, so a host can be configured
once and callers need no command-line plumbing. **A flag always overrides the
environment.**

```bash
export AUX4_JWT_JWKS_FILE=/etc/aux4/jwks.json
export AUX4_JWT_ISSUER=https://issuer.example.com
export AUX4_JWT_AUDIENCE=my-api

aux4 jwt verify --tokenFile /run/token --claim sub
```

```text
user-123
```

## Inspecting a Token Without Verifying It

`decode-unverified` prints what a token says about itself and checks nothing.

```bash
aux4 jwt decode-unverified --tokenFile /run/token --part header
```

```json
{
  "alg": "RS256",
  "kid": "rsa-2019",
  "typ": "JWT"
}
```

**Its output is not evidence of anything.** A JWT is three base64 segments;
anybody can mint one with any claims they like and this command will print them
back just as readily as it prints a genuine token's. It exists to answer "why
did verification fail?" — for example, comparing the `kid` above with
`aux4 jwt jwks list` shows at a glance that the key set is stale. To decide
whether a token may be trusted, use `aux4 jwt verify`.

Every invocation prints a warning to stderr saying that nothing was checked.
`--part` selects `payload` (the default), `header` or `all`; `--claim` prints a
single payload claim.

## Working With Key Sets

List what a local key set holds:

```bash
aux4 jwt jwks list /etc/aux4/jwks.json
```

```json
[
  {
    "alg": "RS256",
    "kid": "rsa-2026",
    "kty": "RSA",
    "use": "sig"
  }
]
```

Download one over HTTPS, discovering the endpoint from the issuer:

```bash
aux4 jwt jwks fetch --issuer https://issuer.example.com --output /etc/aux4/jwks.json
```

```text
/etc/aux4/jwks.json
```

`fetch` is a **setup-time** command, kept strictly separate from verification.
`verify` never fetches anything — it reads the file on disk. That separation is
the point: a deployment that installs the key set once, into an image or a
read-only path, has a trust anchor that cannot be re-fetched or rewritten while
the service runs, so whoever controls the network or a name server gets no say
in which keys are trusted.

The guards on `fetch` follow from the same reasoning:

- **HTTPS only.** Any other scheme is refused, for both the endpoint and the
  discovery URL, and redirects are followed only while they stay on HTTPS.
- **The response is validated before anything is written.** It must parse as a
  key set with at least one usable key, or the existing file is left untouched.
  A stale key set beats one replaced by an error page.
- **The write is atomic**, so an interrupted download cannot leave a
  half-written key set where a verifier will read it.

## Environment Variables

| Variable | Used by | Description |
|----------|---------|-------------|
| `AUX4_JWT_TOKEN` | `verify`, `decode-unverified` | The token to read |
| `AUX4_JWT_TOKEN_FILE` | `verify`, `decode-unverified` | File to read the token from |
| `AUX4_JWT_JWKS_FILE` | `verify`, `jwks list`, `jwks fetch` | Local JWKS file |
| `AUX4_JWT_JWKS_URL` | `jwks fetch` | JWKS endpoint to download from |
| `AUX4_JWT_ISSUER` | `verify`, `jwks fetch` | Required `iss` claim; issuer to discover from |
| `AUX4_JWT_AUDIENCE` | `verify` | Required `aud` value |
| `AUX4_JWT_SUBJECT` | `verify` | Required `sub` claim |
| `AUX4_JWT_SCOPE` | `verify` | Required scope |
| `AUX4_JWT_ALGORITHMS` | `verify` | Algorithm allow-list |
| `AUX4_JWT_CLOCK_SKEW` | `verify` | Leeway in seconds |
| `AUX4_JWT_MAX_AGE` | `verify` | Maximum token age in seconds |
| `AUX4_JWT_STRICT` | `verify` | Require issuer and audience to be configured |
| `AUX4_JWT_WARNINGS` | `verify` | Warn about unconfigured checks |
