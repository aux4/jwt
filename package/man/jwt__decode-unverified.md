#### Description

The `decode-unverified` command prints what a token says about itself. It does
not check the signature, the expiry, the issuer, the audience or anything else.

**Its output is not evidence of anything.** A JWT is three base64 segments;
anybody can produce one with any claims they like, and this command will print
them back just as happily as it prints a genuine one. Use it to see why a
verification failed, to read the `kid` a token is asking for, or to inspect a
token you already trust. To decide whether a token may be trusted, use
`aux4 jwt verify`.

The command is deliberately separate from verification, with a name that says
what it is, and it prints a warning to stderr on every invocation. The warning
goes to stderr so it never contaminates the JSON on stdout.

Token input works exactly as it does for `verify`: an argument, the
`AUX4_JWT_TOKEN` environment variable, or `--tokenFile`. A leading `Bearer `
prefix is accepted and stripped.

#### Usage

```bash
aux4 jwt decode-unverified [<token>] [--tokenFile <path>] [--part <payload|header|all>] [--claim <name>]
```

--tokenFile  Read the token from this file instead of passing it as an argument (env: AUX4_JWT_TOKEN_FILE)
--part       Which segment to print: payload, header or all. Default: payload
--claim      Print only this payload claim. Cannot be combined with --part header

#### Example

Read the claims of a token that verification rejected:

```bash
aux4 jwt decode-unverified --tokenFile /run/stale-token
```

```json
{
  "aud": "my-api",
  "exp": 1600003600,
  "iat": 1600000000,
  "iss": "https://issuer.example.com",
  "sub": "user-123"
}
```

Find out which key a token is asking for, when verification reported an unknown
`kid`:

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
