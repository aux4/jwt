#### Description

The `jwks` command group works with JSON Web Key Set files — the local trust
anchor that `aux4 jwt verify` reads.

- **`list`** — show the identifying metadata of the keys in a local key set.
- **`fetch`** — download a key set over HTTPS and write it to a file.

`fetch` is a setup-time command and is the only place in the package where a
network request happens. Verification never fetches: it reads the file you
installed, which is what lets a deployment bake the trust anchor into an image
where it cannot be re-fetched or rewritten at runtime.

#### Usage

```bash
aux4 jwt jwks list [<path>]
aux4 jwt jwks fetch --issuer <url> --output <path>
```

#### Example

```bash
aux4 jwt jwks fetch --issuer https://issuer.example.com --output /etc/aux4/jwks.json
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
