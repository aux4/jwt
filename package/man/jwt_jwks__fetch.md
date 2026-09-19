#### Description

The `fetch` command downloads a JSON Web Key Set over HTTPS and writes it to a
local file, so that `aux4 jwt verify` has a trust anchor to read.

It is a **setup-time** command and is kept strictly separate from verification.
`verify` never fetches anything: it reads the file on disk. That separation is
deliberate. A deployment that bakes the key set into an image, or installs it
once into a read-only path, has a trust anchor that cannot be re-fetched or
rewritten while the service is running — an attacker who controls the network
or a name server gets no say in which keys are trusted. Fetching on demand
would hand that decision back to whoever answers the request.

**Guards**

- **HTTPS only.** A plain `http`, `file` or any other scheme is refused, for
  both the endpoint and the discovery URL. Redirects are followed only while
  they stay on HTTPS, and no more than five deep.
- **The response is validated before anything is written.** It must parse as a
  key set and contain at least one usable public key; otherwise the existing
  file is left exactly as it was. A stale key set is far better than one that
  was replaced by an error page.
- **The write is atomic.** The file is replaced in a single step, so an
  interrupted download cannot leave a half-written key set where a verifier
  will read it.
- The response is read up to 1 MB.

**Discovery**

Give `--issuer` instead of `--url` to read `jwks_uri` from the issuer's
OpenID Connect discovery document at `/.well-known/openid-configuration` and
download from there. Pass one or the other, not both.

On success the destination path is printed to stdout and a short summary of
how many keys were written goes to stderr.

Because `--output` also reads `AUX4_JWT_JWKS_FILE`, the same variable that
`verify` and `jwks list` use, a host can be configured once and every command
will agree on where the key set lives.

#### Usage

```bash
aux4 jwt jwks fetch [--url <https url>] [--issuer <https url>] --output <path> [--timeout <seconds>]
```

--url      The JWKS endpoint to download from. Must be https (env: AUX4_JWT_JWKS_URL)
--issuer   An OpenID Connect issuer to discover the JWKS endpoint from, instead of --url (env: AUX4_JWT_ISSUER)
--output   Where to write the JWKS file (env: AUX4_JWT_JWKS_FILE)
--timeout  Request timeout in seconds. Default: 10

#### Example

Discover the endpoint from the issuer and install the key set:

```bash
aux4 jwt jwks fetch --issuer https://issuer.example.com --output /etc/aux4/jwks.json
```

```text
/etc/aux4/jwks.json
```

Download from a known endpoint:

```bash
aux4 jwt jwks fetch --url https://issuer.example.com/.well-known/jwks.json --output /etc/aux4/jwks.json
```

```text
/etc/aux4/jwks.json
```
