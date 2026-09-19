# jwt jwks fetch

`jwks fetch` is the only command in the package that touches the network, and
it is a setup-time command: it downloads a key set once and writes it to a
file. Verification never calls it and never reaches the network.

The tests below cover its guards, which are what matter for a command that
installs a trust anchor. They make no network request.

## refusing anything that is not https

A key set is a trust anchor. Fetching one over a channel an attacker can
rewrite would defeat the entire point of verifying signatures.

### should refuse a plain http url

```execute
aux4 jwt jwks fetch --url http://issuer.example.com/.well-known/jwks.json --output jwks.json
```

```error:partial
refusing to fetch a trust anchor over "http": https is required
```

### should refuse a file url

```execute
aux4 jwt jwks fetch --url file:///etc/jwks.json --output jwks.json
```

```error:partial
refusing to fetch a trust anchor over "file": https is required
```

### should refuse a plain http issuer

```execute
aux4 jwt jwks fetch --issuer http://issuer.example.com --output jwks.json
```

```error:partial
refusing to fetch a trust anchor over "http": https is required
```

## usage errors

### should require a url or an issuer

```execute
aux4 jwt jwks fetch --output jwks.json
```

```error:partial
pass --url with a JWKS endpoint or --issuer to discover one
```

### should refuse a url and an issuer together

```execute
aux4 jwt jwks fetch --url https://issuer.example.com/jwks.json --issuer https://issuer.example.com --output jwks.json
```

```error:partial
pass either --url or --issuer, not both
```

### should require an output file

```execute
aux4 jwt jwks fetch --url https://issuer.example.com/jwks.json
```

```error:partial
no output file configured
```

### should reject a timeout that is not a number of seconds

```execute
aux4 jwt jwks fetch --url http://issuer.example.com/jwks.json --output jwks.json --timeout soon
```

```error:partial
timeout must be a whole number of seconds, got "soon"
```

## configuration by environment variable

### should take the url and the destination from the environment

```execute
AUX4_JWT_JWKS_URL=http://issuer.example.com/jwks.json AUX4_JWT_JWKS_FILE=jwks.json aux4 jwt jwks fetch
```

```error:partial
refusing to fetch a trust anchor over "http": https is required
```

### should let a flag override the environment url

```execute
AUX4_JWT_JWKS_URL=https://issuer.example.com/jwks.json AUX4_JWT_JWKS_FILE=jwks.json aux4 jwt jwks fetch --url ftp://issuer.example.com/jwks.json
```

```error:partial
refusing to fetch a trust anchor over "ftp": https is required
```
