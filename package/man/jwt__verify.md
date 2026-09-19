#### Description

The `verify` command checks a JSON Web Token against the public keys in a local
JWKS file and, when every check passes, prints the token's claims as JSON. It
is the only command in this package whose output may be used to make an
authorization decision.

No network request is made. The key set is read from `--jwksFile` on every
call, so the trust anchor is whatever is on disk — which is exactly what makes
it suitable for a hot path or a host with no outbound access.

**What is always checked**

- The signature, against a key from the JWKS chosen by the token's `kid` and
  constrained to the key type the algorithm requires.
- The algorithm. Only RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384,
  ES512 and EdDSA are ever accepted. A token declaring `none` or an HMAC
  algorithm such as HS256 is rejected outright; there is no option to allow
  them. This is what blocks the algorithm-confusion attack in which a forger
  signs a token with the JWKS public key used as an HMAC secret.
- `exp`, which is mandatory. A token with no expiry is rejected however well
  it is signed.
- `nbf`, when the token carries one.
- The key strength. RSA keys below 2048 bits are not used.

**What is checked only when you ask**

`--issuer`, `--audience`, `--subject`, `--scope` and `--maxAge` are each
enforced only when configured. **When `--issuer` or `--audience` is not
configured, that claim is not checked and a warning naming the skipped check is
printed to stderr.** Warnings go to stderr, never stdout, so they cannot
corrupt piped claims. Use `--strict true` to turn a missing issuer or audience
into a refusal to run, or `--warnings false` to silence the notice once you
have decided the check is genuinely not wanted.

**Failure behaviour**

There is no partial success. On any failure the command exits non-zero, writes
the reason to stderr and writes nothing to stdout. Exit code `1` means the
token was rejected; exit code `2` means the command could not run as asked, for
example an unreadable JWKS or a contradictory set of flags. The token itself is
never printed, in output, errors or logs.

**Supplying the token**

Pass it as an argument, set `AUX4_JWT_TOKEN`, or point `--tokenFile` at a file.
A leading `Bearer ` is accepted and stripped, so the value of an Authorization
header can be handed over unchanged. Passing a token as a command-line argument
makes it visible to every process on the machine; the environment variable or a
file is preferable. Supplying both a token and a `--tokenFile` is an error
rather than a silent precedence rule.

**Environment variables**

`AUX4_JWT_TOKEN`, `AUX4_JWT_TOKEN_FILE`, `AUX4_JWT_JWKS_FILE`,
`AUX4_JWT_ISSUER`, `AUX4_JWT_AUDIENCE`, `AUX4_JWT_SUBJECT`, `AUX4_JWT_SCOPE`,
`AUX4_JWT_ALGORITHMS`, `AUX4_JWT_CLOCK_SKEW`, `AUX4_JWT_MAX_AGE`,
`AUX4_JWT_STRICT` and `AUX4_JWT_WARNINGS`. A flag always overrides the
environment.

#### Usage

```bash
aux4 jwt verify [<token>] --jwksFile <path> [--tokenFile <path>] [--issuer <iss>] [--audience <aud>] [--subject <sub>] [--scope <scope>] [--algorithms <list>] [--clockSkew <seconds>] [--maxAge <seconds>] [--claim <name>] [--quiet <true|false>] [--strict <true|false>] [--warnings <true|false>]
```

--jwksFile    Path to the local JWKS file holding the trusted public keys. Required (env: AUX4_JWT_JWKS_FILE)
--tokenFile   Read the token from this file instead of passing it as an argument (env: AUX4_JWT_TOKEN_FILE)
--issuer      Require this exact iss claim. Not checked when unset (env: AUX4_JWT_ISSUER)
--audience    Require this value in the aud claim, which may be a string or an array. Not checked when unset (env: AUX4_JWT_AUDIENCE)
--subject     Require this exact sub claim (env: AUX4_JWT_SUBJECT)
--scope       Require this value among the space-delimited scope claim (env: AUX4_JWT_SCOPE)
--algorithms  Comma-separated allow-list of signature algorithms. Default: every supported asymmetric algorithm (env: AUX4_JWT_ALGORITHMS)
--clockSkew   Leeway in seconds applied to exp, nbf and iat. Default: 30 (env: AUX4_JWT_CLOCK_SKEW)
--maxAge      Reject tokens issued more than this many seconds ago. Requires an iat claim. Default: 0, disabled (env: AUX4_JWT_MAX_AGE)
--claim       Print only this claim instead of the whole claim set
--quiet       Print nothing on success and rely on the exit code alone. Default: false
--strict      Refuse to run unless both issuer and audience are configured. Default: false (env: AUX4_JWT_STRICT)
--warnings    Print a warning for every claim check that is not configured. Default: true (env: AUX4_JWT_WARNINGS)

#### Example

Verify a token and print its claims:

```bash
aux4 jwt verify --tokenFile /run/token --jwksFile /etc/aux4/jwks.json --issuer https://issuer.example.com --audience my-api
```

```json
{
  "admin": true,
  "aud": "my-api",
  "email": "sally@example.com",
  "exp": 4102444800,
  "iat": 1700000000,
  "iss": "https://issuer.example.com",
  "scope": "read write",
  "sub": "user-123"
}
```

Use it as a gate, pulling everything from the environment:

```bash
export AUX4_JWT_JWKS_FILE=/etc/aux4/jwks.json
export AUX4_JWT_ISSUER=https://issuer.example.com
export AUX4_JWT_AUDIENCE=my-api

aux4 jwt verify --tokenFile /run/token --scope write --quiet true && echo authorized
```

```text
authorized
```

A rejected token writes nothing to stdout:

```bash
aux4 jwt verify --tokenFile /run/stale-token --jwksFile /etc/aux4/jwks.json --issuer https://issuer.example.com --audience my-api
```

```text
token rejected: token expired
```
