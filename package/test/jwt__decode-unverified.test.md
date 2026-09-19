# jwt decode-unverified

`decode-unverified` reads a token and prints what it says about itself. It
checks nothing. Every invocation prints a warning on stderr saying so, and the
tests below assert that warning is there, because the moment it disappears the
command becomes dangerous.

```file:expired.txt
eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYS0yMDI2IiwidHlwIjoiSldUIn0.eyJhdWQiOiJteS1hcGkiLCJleHAiOjE2MDAwMDM2MDAsImlhdCI6MTYwMDAwMDAwMCwiaXNzIjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20iLCJzdWIiOiJ1c2VyLTEyMyJ9.o_L8B0Z-JeLxaAT3jM8FO1fVFzuznYIvH-8ztPcVHV1ANVfw5LdEZpoSvyA0bpiWnMqJ4FLMbL_wP5abml4HGxFKsBN-xl46Sg-Pi8ZTucaFdKLvyLyZq1NyVEjWAj830sZnUqZeAAvAjW1VGrJVk7pZMKY1urAQd16TwmZWiNGKD7C9lLoDc90m6IgaoZh6AJdEgiMnnv4VHWmcMKECge7IWDqnFrXCAVRR4wCVhp3BU5VFi2O0QY3CEEIep8dHuv9bdsvHbmI3xVJn7FWy58hE5hAXp6OErUMmdQ9aXm0Hv759UKKTElW3gWZymh-svRjl_2_7TMutK7zg8ed_Aw
```

```file:alg-none.txt
eyJhbGciOiJub25lIiwia2lkIjoicnNhLTIwMjYiLCJ0eXAiOiJKV1QifQ.eyJhZG1pbiI6dHJ1ZSwiYXVkIjoibXktYXBpIiwiZW1haWwiOiJzYWxseUBleGFtcGxlLmNvbSIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzAwMDAwMDAwLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsInNjb3BlIjoicmVhZCB3cml0ZSIsInN1YiI6InVzZXItMTIzIn0.
```

## default output

### should print the payload of a token that verification would reject

```execute
aux4 jwt decode-unverified --tokenFile expired.txt
```

```expect:json
{
  "aud": "my-api",
  "exp": 1600003600,
  "iat": 1600000000,
  "iss": "https://issuer.example.com",
  "sub": "user-123"
}
```

### should always say on stderr that nothing was checked

```execute
aux4 jwt decode-unverified --tokenFile expired.txt
```

```error:partial
WARNING: decode-unverified does NOT check the signature or any claim.
```

### should point at the verification command in the warning

```execute
aux4 jwt decode-unverified --tokenFile expired.txt
```

```error:partial
use: aux4 jwt verify
```

## selecting a segment

### should print the header with --part header

```execute
aux4 jwt decode-unverified --tokenFile expired.txt --part header
```

```expect:json
{
  "alg": "RS256",
  "kid": "rsa-2026",
  "typ": "JWT"
}
```

### should print both segments with --part all

```execute
aux4 jwt decode-unverified --tokenFile expired.txt --part all
```

```expect:json
{
  "header": {
    "alg": "RS256",
    "kid": "rsa-2026",
    "typ": "JWT"
  },
  "payload": {
    "aud": "my-api",
    "exp": 1600003600,
    "iat": 1600000000,
    "iss": "https://issuer.example.com",
    "sub": "user-123"
  }
}
```

### should print a single claim with --claim

```execute
aux4 jwt decode-unverified --tokenFile expired.txt --claim sub
```

```expect
user-123
```

## it really does not verify anything

### should happily decode an unsigned alg=none token

The same token is refused outright by `aux4 jwt verify`. Reading it here is
fine; believing it is not.

```execute
aux4 jwt decode-unverified --tokenFile alg-none.txt --part header
```

```expect:json
{
  "alg": "none",
  "kid": "rsa-2026",
  "typ": "JWT"
}
```

### should decode a token whose signature is plain nonsense

```execute
aux4 jwt decode-unverified eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbnlib2R5LWF0LWFsbCJ9.bm90LWEtc2lnbmF0dXJl --claim sub
```

```expect
anybody-at-all
```

## usage errors

### should refuse to combine --claim with --part header

```execute
aux4 jwt decode-unverified --tokenFile expired.txt --part header --claim sub
```

```error:partial
--claim reads a payload claim and cannot be combined with --part header
```

### should reject an unknown part

```execute
aux4 jwt decode-unverified --tokenFile expired.txt --part signature
```

```error:partial
unknown part "signature" (expected header, payload or all)
```

### should reject a string that is not a token

```execute
aux4 jwt decode-unverified not-a-jwt
```

```error:partial
cannot decode token: malformed token: expected 3 dot-separated segments
```

### should report a missing claim

```execute
aux4 jwt decode-unverified --tokenFile expired.txt --claim department
```

```error:partial
token has no "department" claim
```

### should refuse to run with no token

```execute
aux4 jwt decode-unverified
```

```error:partial
no token provided
```
