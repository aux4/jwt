#### Description

The `jwt` command group verifies and inspects JSON Web Tokens against a JWKS
(JSON Web Key Set) file held locally. Verification does no network I/O at all:
the trust anchor is a file on disk, read fresh on every call, so a token can be
checked in a container, on an air-gapped host, or in a hot request path without
paying for an HTTP round trip to the issuer.

- **`verify`** — the only command that answers "may I trust this token?". It
  checks the signature against the local key set and enforces the claim checks
  you configure. It fails closed: any problem is a non-zero exit with an empty
  stdout.
- **`decode-unverified`** — prints what a token says about itself, checking
  nothing. A debugging aid, never an authorization decision.
- **`jwks list`** — shows which keys a local JWKS file holds.
- **`jwks fetch`** — downloads a key set over HTTPS and writes it to a file.
  Setup time only; nothing in the verification path ever calls it.

Only asymmetric signature algorithms are accepted: RS256, RS384, RS512, PS256,
PS384, PS512, ES256, ES384, ES512 and EdDSA. `none` and the HMAC family are
rejected unconditionally, and no flag or environment variable can enable them.

Every option can be set by environment variable as well as by flag, with the
flag winning, so a host can be configured once and callers need no plumbing.

#### Usage

```bash
aux4 jwt verify [--tokenFile <path>] --jwksFile <path> --issuer <iss> --audience <aud>
aux4 jwt decode-unverified <token> [--part <payload|header|all>]
aux4 jwt jwks list [<path>]
aux4 jwt jwks fetch --issuer <url> --output <path>
```

#### Example

```bash
aux4 jwt jwks fetch --issuer https://issuer.example.com --output /etc/aux4/jwks.json
aux4 jwt verify --tokenFile /run/token --jwksFile /etc/aux4/jwks.json --issuer https://issuer.example.com --audience my-api --claim sub
```

```text
user-123
```
