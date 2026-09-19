#### Description

The `list` command reads a local JWKS file and prints the identifying metadata
of each key it holds: `kid`, `kty`, `alg`, `use` and, for elliptic-curve keys,
`crv`. Fields the key set does not carry are omitted.

It is usually the next thing to run after a verification failure reporting that
no key matched the token's `kid`: comparing this output with the `kid` from
`aux4 jwt decode-unverified --part header` shows immediately whether the key
set is stale.

A JWKS used for verification contains public keys only, and only their metadata
is printed — never the key material itself.

The file can be given as an argument or through `AUX4_JWT_JWKS_FILE`, which is
the same variable `verify` reads, so the two commands always look at the same
key set by default.

#### Usage

```bash
aux4 jwt jwks list [<path>]
```

<path>  Path to the JWKS file (env: AUX4_JWT_JWKS_FILE)

#### Example

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
  },
  {
    "alg": "ES256",
    "crv": "P-256",
    "kid": "ec-2026",
    "kty": "EC",
    "use": "sig"
  }
]
```
