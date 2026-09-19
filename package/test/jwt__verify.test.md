# jwt verify

Every test here runs against a JWKS file on disk. No network call happens at
any point, which is the whole point of the command.

The fixtures below use a throwaway key pair generated for this test suite. The
tokens expire in the year 2100 so the suite never starts failing on a calendar
boundary.

```file:jwks.json
{
  "keys": [
    {
      "alg": "RS256",
      "e": "AQAB",
      "kid": "rsa-2026",
      "kty": "RSA",
      "n": "tJNJJYTXZ5MrGu25tnoLv1MrLNZKg_E3nTRKxoQtHS4FrtW7cL1ySejHOAEKmPhquMLefQMmHluenCVxCs5z2cxdTCMbB9OVWb9HBGGfCpiO3zHAhd0bBeOPuaJ8np1SB80tF9jKTsJcj9faVA-HXJ14hxJ4dlOxKMuTuSxgqJgzkSwetkmK-ouxTu_-WlXjbf9BPZJgNoU8uVHpSgDiUC29USVBAu1_E60gFOp_1TU8E2ynejoutQxsrxd3cXsyQjJz1lEyWR7Q86Mw6_Fft_Bw8z17z0VDfPnWUpypo80HaRvGR2TRqnd-5qAqdkMsMybB56J0WQRHKCUey5nNAw",
      "use": "sig"
    },
    {
      "alg": "ES256",
      "crv": "P-256",
      "kid": "ec-2026",
      "kty": "EC",
      "use": "sig",
      "x": "5DdLDjJpgQp0Vn7Yi4Fza_B_7dCn0eRJJeo5Mq2tmzo",
      "y": "Xpc2maFF2q24MpAYuVSxY7NEARJFjijXzLTFEy9igWM"
    }
  ]
}
```

```file:valid.txt
eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYS0yMDI2IiwidHlwIjoiSldUIn0.eyJhZG1pbiI6dHJ1ZSwiYXVkIjoibXktYXBpIiwiZW1haWwiOiJzYWxseUBleGFtcGxlLmNvbSIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzAwMDAwMDAwLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsInNjb3BlIjoicmVhZCB3cml0ZSIsInN1YiI6InVzZXItMTIzIn0.jHasmgdmZn7AJD41hFBAZCEXHiZZhXw6GcTMsEHJ5SYV70Qbp3DkDOATV5MG9SmhQJFlQ4-zQvbCdCWqikqXBRPbBkPJ9721j1293gsw6_orIz0I1t2P4I3eMc5E-1j42Q8Jsa63DVsfkeeXvHS2_i7rn4bZxjbcEUgJynr-HoiuUBZSA6kB2uH2CUvFU0xteGadlhRTh-sLcPhvhxPxwSQ7UpP0Uznm4fvPLq-Wvf4YKWJdTRblRztl_poBPb7lSF3eEG-_tDFF5QivM0u-sidY8g1T9ieAQRMGGJXljUqZGFcWII9hwfzVWs1__VGEF_INOF373UCyvsfLi3i9bw
```

## a token that passes every configured check

### should print the claims as JSON

```execute
aux4 jwt verify --tokenFile valid.txt --jwksFile jwks.json --issuer https://issuer.example.com --audience my-api
```

```expect:json
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

### should print a single claim with --claim

```execute
aux4 jwt verify --tokenFile valid.txt --jwksFile jwks.json --issuer https://issuer.example.com --audience my-api --claim sub
```

```expect
user-123
```

### should print a boolean claim as a bare value

```execute
aux4 jwt verify --tokenFile valid.txt --jwksFile jwks.json --issuer https://issuer.example.com --audience my-api --claim admin
```

```expect
true
```

### should accept a token passed as an argument

```execute
aux4 jwt verify eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYS0yMDI2IiwidHlwIjoiSldUIn0.eyJhZG1pbiI6dHJ1ZSwiYXVkIjoibXktYXBpIiwiZW1haWwiOiJzYWxseUBleGFtcGxlLmNvbSIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzAwMDAwMDAwLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsInNjb3BlIjoicmVhZCB3cml0ZSIsInN1YiI6InVzZXItMTIzIn0.jHasmgdmZn7AJD41hFBAZCEXHiZZhXw6GcTMsEHJ5SYV70Qbp3DkDOATV5MG9SmhQJFlQ4-zQvbCdCWqikqXBRPbBkPJ9721j1293gsw6_orIz0I1t2P4I3eMc5E-1j42Q8Jsa63DVsfkeeXvHS2_i7rn4bZxjbcEUgJynr-HoiuUBZSA6kB2uH2CUvFU0xteGadlhRTh-sLcPhvhxPxwSQ7UpP0Uznm4fvPLq-Wvf4YKWJdTRblRztl_poBPb7lSF3eEG-_tDFF5QivM0u-sidY8g1T9ieAQRMGGJXljUqZGFcWII9hwfzVWs1__VGEF_INOF373UCyvsfLi3i9bw --jwksFile jwks.json --issuer https://issuer.example.com --audience my-api --claim email
```

```expect
sally@example.com
```

### should accept a token carrying the Bearer prefix

```file:bearer.txt
Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYS0yMDI2IiwidHlwIjoiSldUIn0.eyJhZG1pbiI6dHJ1ZSwiYXVkIjoibXktYXBpIiwiZW1haWwiOiJzYWxseUBleGFtcGxlLmNvbSIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzAwMDAwMDAwLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsInNjb3BlIjoicmVhZCB3cml0ZSIsInN1YiI6InVzZXItMTIzIn0.jHasmgdmZn7AJD41hFBAZCEXHiZZhXw6GcTMsEHJ5SYV70Qbp3DkDOATV5MG9SmhQJFlQ4-zQvbCdCWqikqXBRPbBkPJ9721j1293gsw6_orIz0I1t2P4I3eMc5E-1j42Q8Jsa63DVsfkeeXvHS2_i7rn4bZxjbcEUgJynr-HoiuUBZSA6kB2uH2CUvFU0xteGadlhRTh-sLcPhvhxPxwSQ7UpP0Uznm4fvPLq-Wvf4YKWJdTRblRztl_poBPb7lSF3eEG-_tDFF5QivM0u-sidY8g1T9ieAQRMGGJXljUqZGFcWII9hwfzVWs1__VGEF_INOF373UCyvsfLi3i9bw
```

```execute
aux4 jwt verify --tokenFile bearer.txt --jwksFile jwks.json --issuer https://issuer.example.com --audience my-api --claim sub
```

```expect
user-123
```

## using it as a gate

### should print nothing on success with --quiet

```execute
aux4 jwt verify --tokenFile valid.txt --jwksFile jwks.json --issuer https://issuer.example.com --audience my-api --quiet true && echo authorized
```

```expect
authorized
```

### should exit non-zero when the audience does not match

```execute
aux4 jwt verify --tokenFile valid.txt --jwksFile jwks.json --issuer https://issuer.example.com --audience someone-else --quiet true || echo denied
```

```expect
denied
```

```error:partial
token rejected: unexpected audience
```

## claim checks

### should reject a mismatched issuer

```execute
aux4 jwt verify --tokenFile valid.txt --jwksFile jwks.json --issuer https://evil.example.com --audience my-api
```

```error:partial
token rejected: unexpected issuer "https://issuer.example.com"
```

### should reject a mismatched subject

```execute
aux4 jwt verify --tokenFile valid.txt --jwksFile jwks.json --issuer https://issuer.example.com --audience my-api --subject someone-else
```

```error:partial
token rejected: unexpected subject
```

### should accept a scope present in the scope claim

```execute
aux4 jwt verify --tokenFile valid.txt --jwksFile jwks.json --issuer https://issuer.example.com --audience my-api --scope write --claim scope
```

```expect
read write
```

### should reject a scope missing from the scope claim

```execute
aux4 jwt verify --tokenFile valid.txt --jwksFile jwks.json --issuer https://issuer.example.com --audience my-api --scope delete
```

```error:partial
token rejected: token scope does not include "delete"
```

### should accept an audience listed in an aud array

```file:multi-aud.txt
eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYS0yMDI2IiwidHlwIjoiSldUIn0.eyJhdWQiOlsib3RoZXItYXBpIiwibXktYXBpIl0sImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzAwMDAwMDAwLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6InVzZXItMTIzIn0.PoPV5M9Hn0Vq5IOY8AHcFkv4bGlkEXWNEv6aozG8Q9LI1kUfSUHfuPWm1Bn6VLrJW4nCgT9_9kUn3oKkdtdFVJx9M319_k0puhMXsa6meNLvrt-mPGOclIqvRaUaMqj4NBCNSTbrsZV-RKKkmqivsAaJUQKTKQxqINDR_Ebsdjw2KO6ce6uJ45B-5FKhF9jM-11G_g5iUKc6_-LnYY1M1LrFg4H0BZusIqYULBpl4lDz_yG4OjnXfiP6UlRCcZ5Z-CUd6ZxgysNxpuQhw7iXSP3znp24JOmqr6hn6boOYyc4ylO7ZAQhqjOu6viHTZiI3a_q7byoeycf4YhBRJ4aqA
```

```execute
aux4 jwt verify --tokenFile multi-aud.txt --jwksFile jwks.json --issuer https://issuer.example.com --audience my-api --claim sub
```

```expect
user-123
```

## time checks

### should reject an expired token

```file:expired.txt
eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYS0yMDI2IiwidHlwIjoiSldUIn0.eyJhdWQiOiJteS1hcGkiLCJleHAiOjE2MDAwMDM2MDAsImlhdCI6MTYwMDAwMDAwMCwiaXNzIjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20iLCJzdWIiOiJ1c2VyLTEyMyJ9.o_L8B0Z-JeLxaAT3jM8FO1fVFzuznYIvH-8ztPcVHV1ANVfw5LdEZpoSvyA0bpiWnMqJ4FLMbL_wP5abml4HGxFKsBN-xl46Sg-Pi8ZTucaFdKLvyLyZq1NyVEjWAj830sZnUqZeAAvAjW1VGrJVk7pZMKY1urAQd16TwmZWiNGKD7C9lLoDc90m6IgaoZh6AJdEgiMnnv4VHWmcMKECge7IWDqnFrXCAVRR4wCVhp3BU5VFi2O0QY3CEEIep8dHuv9bdsvHbmI3xVJn7FWy58hE5hAXp6OErUMmdQ9aXm0Hv759UKKTElW3gWZymh-svRjl_2_7TMutK7zg8ed_Aw
```

```execute
aux4 jwt verify --tokenFile expired.txt --jwksFile jwks.json --issuer https://issuer.example.com --audience my-api
```

```error:partial
token rejected: token expired
```

### should reject a token that is not yet valid

```file:not-yet.txt
eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYS0yMDI2IiwidHlwIjoiSldUIn0.eyJhdWQiOiJteS1hcGkiLCJleHAiOjQxMDI0NDg0MDAsImlhdCI6MTcwMDAwMDAwMCwiaXNzIjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20iLCJuYmYiOjQxMDI0NDQ4MDAsInN1YiI6InVzZXItMTIzIn0.NA1NWuax8iH_hqT9ehyiOLIAbhU92ngtNJQM-ODXnDAprjeB3zomEE1D8Wm7y4zA7FfwZ8b3D1MUy7tR1se_DBMuMBnfvAZBaNWSz5NrcVtFJ_kbbb75tXwoxunOBKn5cA9AByfuNQNLN8-3GRDXftaWOzWQpnrJpmr_HEJ94Fyaw81OqmcpD3cZmPJygSZhIRU4lGtGRc14oIJ71T0CCs04QNLY2tzeYCceDhy1gyiZxT7HNGxHx3Yy58haMyiDGMXsbDKjVxfGDlRlTbqRzXY-EEL7-6qceopr5PpR6d73YepN3YwFnQAEk6JRrK0fg3jVpEYTXafMaEiEI-jRQw
```

```execute
aux4 jwt verify --tokenFile not-yet.txt --jwksFile jwks.json --issuer https://issuer.example.com --audience my-api
```

```error:partial
token rejected: token not yet valid
```

### should reject a token with no exp claim

```file:no-exp.txt
eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYS0yMDI2IiwidHlwIjoiSldUIn0.eyJhdWQiOiJteS1hcGkiLCJpYXQiOjE3MDAwMDAwMDAsImlzcyI6Imh0dHBzOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwic3ViIjoidXNlci0xMjMifQ.jl9Ucy3BH3hKR3_ecqZmY3Ohdg3CFfd3OKCnUucEAVgJPb1HVlXJnjZ5ffGwuJFLXVYXqnZtmC3wxr5CeIQQhdr7HlxfgXioImYIZ-fswLTHjrhiBrEiSs1IE88cYflGEdvOPfI3VvWTqODlXrEzMDFuAsPQqO0Aobez2drb_TAOmvCkWJrbQHQHcSEm5__-8pQ9Q10l8qyLpM8V4vFnvVg1ftRFxpZoh7bWoCfaIJjftsbSxVgAtXCAjmF1B3_qBeaa_uvk0PGjnRCgbpptAAGu6pZgzLa7UetPEVzRw3vsEmwZvisEkH46IvTt0lPSr_GgZESiVYaX100f45naWQ
```

```execute
aux4 jwt verify --tokenFile no-exp.txt --jwksFile jwks.json --issuer https://issuer.example.com --audience my-api
```

```error:partial
token rejected: token has no exp claim
```

### should reject a token older than maxAge

```execute
aux4 jwt verify --tokenFile valid.txt --jwksFile jwks.json --issuer https://issuer.example.com --audience my-api --maxAge 60
```

```error:partial
token rejected: token is older than the allowed maxAge
```

## signature and algorithm checks

```file:es256.txt
eyJhbGciOiJFUzI1NiIsImtpZCI6ImVjLTIwMjYiLCJ0eXAiOiJKV1QifQ.eyJhZG1pbiI6dHJ1ZSwiYXVkIjoibXktYXBpIiwiZW1haWwiOiJzYWxseUBleGFtcGxlLmNvbSIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzAwMDAwMDAwLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsInNjb3BlIjoicmVhZCB3cml0ZSIsInN1YiI6InVzZXItMTIzIn0.7LMo4S7jdRiPX8RwyNPLZO-kBXYCVMfcfmox6U1yzmLzkeL1GYKnmCVXYpWgi9dOUPKHeFt4WKgY02QtjHPj_Q
```

### should reject a signature made with another key

```file:wrong-signature.txt
eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYS0yMDI2IiwidHlwIjoiSldUIn0.eyJhZG1pbiI6dHJ1ZSwiYXVkIjoibXktYXBpIiwiZW1haWwiOiJzYWxseUBleGFtcGxlLmNvbSIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzAwMDAwMDAwLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsInNjb3BlIjoicmVhZCB3cml0ZSIsInN1YiI6InVzZXItMTIzIn0.pbQtX3CD-30uIku2sUqLSjKLiwWv-pMwkB8zJ89gq6yGdcA-m4p3faQVVhCp344y7Ps2VMAkqIDk7wXVwjIb2MhD60g4Y6kz3TlOdcqBrcx4bGiryqmTPQHA2a9e0wTnvSQuTWS39QT3CS22Tk8RgvudY2NkHkAl2hJsohxGJEvmOk3EH176KPvrML704B7fwa2XTQSWU75sHMDZU3bIkcnYYS3Ve9eqw_R10rGDkHVfDWgzA0GJD19851QtUPEi4FdWI9pZM_5gCqAxlANALxFMlXsId1C9U72I5NoIoGlAn7LKQdbM1ZBLnNdgb8tvchbkmjsz8QbyhHvCnuwSOA
```

```execute
aux4 jwt verify --tokenFile wrong-signature.txt --jwksFile jwks.json --issuer https://issuer.example.com --audience my-api
```

```error:partial
token rejected: invalid signature
```

### should reject an alg=none token

```file:alg-none.txt
eyJhbGciOiJub25lIiwia2lkIjoicnNhLTIwMjYiLCJ0eXAiOiJKV1QifQ.eyJhZG1pbiI6dHJ1ZSwiYXVkIjoibXktYXBpIiwiZW1haWwiOiJzYWxseUBleGFtcGxlLmNvbSIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzAwMDAwMDAwLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsInNjb3BlIjoicmVhZCB3cml0ZSIsInN1YiI6InVzZXItMTIzIn0.
```

```execute
aux4 jwt verify --tokenFile alg-none.txt --jwksFile jwks.json --issuer https://issuer.example.com --audience my-api
```

```error:partial
token rejected: unsupported alg "none"
```

### should reject an HS256 token forged from the published public key

This is the algorithm-confusion attack: the attacker takes the RSA public key
out of the JWKS, uses it as an HMAC secret, and relabels the header HS256.

```file:alg-hs256.txt
eyJhbGciOiJIUzI1NiIsImtpZCI6InJzYS0yMDI2IiwidHlwIjoiSldUIn0.eyJhZG1pbiI6dHJ1ZSwiYXVkIjoibXktYXBpIiwiZW1haWwiOiJzYWxseUBleGFtcGxlLmNvbSIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzAwMDAwMDAwLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsInNjb3BlIjoicmVhZCB3cml0ZSIsInN1YiI6InVzZXItMTIzIn0.Le_fU4jGAuuunDTTutMFE5HjxNkCX7kZXzPEG-F7CXc
```

```execute
aux4 jwt verify --tokenFile alg-hs256.txt --jwksFile jwks.json --issuer https://issuer.example.com --audience my-api
```

```error:partial
token rejected: unsupported alg "HS256"
```

### should reject a kid that is not in the JWKS

```file:unknown-kid.txt
eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYS0yMDE5IiwidHlwIjoiSldUIn0.eyJhZG1pbiI6dHJ1ZSwiYXVkIjoibXktYXBpIiwiZW1haWwiOiJzYWxseUBleGFtcGxlLmNvbSIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzAwMDAwMDAwLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsInNjb3BlIjoicmVhZCB3cml0ZSIsInN1YiI6InVzZXItMTIzIn0.edG8V43MiLXIhRYE0N4TCqmSyV-z87z1dkIXhiGb4_vb3_bk5hpaxyHPk26HGqKhF-Stj_6vHvoIUzl3BS2G0YgqS5dcYTlLiYE2sQT1vNNUs4YNsZkgusXrsnPpsWEw6qC2XnGsQZWzXXzd6iOOMGJUr3Kc7KTIFUaqyc6a2Rfhm4s_RQvrw64v8IAiwTa1l2DbO97wbWbMptHkQtfP08lFj45Gh1WF6LYLQTbhoV8oJsBMzFoTcgYart4RZGYl2WtEhVpvpzgEtsoUMO5zkcf0VIykLqkAAuuf7BIX1LkEj36MnwiIjoA9nzSm3kEk07M5thYfZZRzybegvxmMDA
```

```execute
aux4 jwt verify --tokenFile unknown-kid.txt --jwksFile jwks.json --issuer https://issuer.example.com --audience my-api
```

```error:partial
token rejected: no RS256 key with kid "rsa-2019" found in jwks
```

### should verify an ES256 token against the EC key in the same JWKS

```execute
aux4 jwt verify --tokenFile es256.txt --jwksFile jwks.json --issuer https://issuer.example.com --audience my-api --claim sub
```

```expect
user-123
```

### should reject ES256 when only RS256 is allowed

```execute
aux4 jwt verify --tokenFile es256.txt --jwksFile jwks.json --issuer https://issuer.example.com --audience my-api --algorithms RS256
```

```error:partial
token rejected: alg "ES256" is not in the allowed set (RS256)
```

### should refuse to configure an algorithm it can never accept

```execute
aux4 jwt verify --tokenFile valid.txt --jwksFile jwks.json --issuer https://issuer.example.com --audience my-api --algorithms HS256
```

```error:partial
unsupported algorithm "HS256"
```

## unconfigured checks are announced, never silent

### should warn about every check that is not configured

```execute
aux4 jwt verify --tokenFile valid.txt --jwksFile jwks.json --claim sub
```

```expect
user-123
```

```error
warning: no issuer configured, the iss claim was NOT checked
warning: no audience configured, the aud claim was NOT checked
```

### should stay quiet when the warnings are turned off

```execute
aux4 jwt verify --tokenFile valid.txt --jwksFile jwks.json --warnings false --claim sub
```

```expect
user-123
```

```error

```

### should refuse to run in strict mode without an issuer and an audience

```execute
aux4 jwt verify --tokenFile valid.txt --jwksFile jwks.json --strict true
```

```error:partial
strict mode requires --issuer and --audience to be configured
```

### should run in strict mode once both are configured

```execute
aux4 jwt verify --tokenFile valid.txt --jwksFile jwks.json --strict true --issuer https://issuer.example.com --audience my-api --claim sub
```

```expect
user-123
```

## configuration by environment variable

A VM can be set up entirely through the environment, with no command-line
plumbing at the call site.

### should read everything from the environment

```execute
AUX4_JWT_JWKS_FILE=jwks.json AUX4_JWT_ISSUER=https://issuer.example.com AUX4_JWT_AUDIENCE=my-api AUX4_JWT_TOKEN_FILE=valid.txt aux4 jwt verify --claim sub
```

```expect
user-123
```

### should let a flag override the environment

The environment names an issuer the token does not have; the flag names the
right one and wins, so the token verifies.

```execute
AUX4_JWT_JWKS_FILE=jwks.json AUX4_JWT_ISSUER=https://evil.example.com AUX4_JWT_TOKEN_FILE=valid.txt aux4 jwt verify --issuer https://issuer.example.com --audience my-api --claim sub
```

```expect
user-123
```

### should reject the token when only the environment issuer applies

```execute
AUX4_JWT_JWKS_FILE=jwks.json AUX4_JWT_ISSUER=https://evil.example.com AUX4_JWT_AUDIENCE=my-api AUX4_JWT_TOKEN_FILE=valid.txt aux4 jwt verify
```

```error:partial
token rejected: unexpected issuer "https://issuer.example.com"
```

### should read the token itself from the environment

```execute
AUX4_JWT_JWKS_FILE=jwks.json AUX4_JWT_TOKEN=eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYS0yMDI2IiwidHlwIjoiSldUIn0.eyJhZG1pbiI6dHJ1ZSwiYXVkIjoibXktYXBpIiwiZW1haWwiOiJzYWxseUBleGFtcGxlLmNvbSIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzAwMDAwMDAwLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsInNjb3BlIjoicmVhZCB3cml0ZSIsInN1YiI6InVzZXItMTIzIn0.jHasmgdmZn7AJD41hFBAZCEXHiZZhXw6GcTMsEHJ5SYV70Qbp3DkDOATV5MG9SmhQJFlQ4-zQvbCdCWqikqXBRPbBkPJ9721j1293gsw6_orIz0I1t2P4I3eMc5E-1j42Q8Jsa63DVsfkeeXvHS2_i7rn4bZxjbcEUgJynr-HoiuUBZSA6kB2uH2CUvFU0xteGadlhRTh-sLcPhvhxPxwSQ7UpP0Uznm4fvPLq-Wvf4YKWJdTRblRztl_poBPb7lSF3eEG-_tDFF5QivM0u-sidY8g1T9ieAQRMGGJXljUqZGFcWII9hwfzVWs1__VGEF_INOF373UCyvsfLi3i9bw AUX4_JWT_ISSUER=https://issuer.example.com AUX4_JWT_AUDIENCE=my-api aux4 jwt verify --claim sub
```

```expect
user-123
```

## usage errors

### should refuse to run with no JWKS file

```execute
aux4 jwt verify --tokenFile valid.txt
```

```error:partial
no JWKS file configured
```

### should refuse to run with no token

```execute
aux4 jwt verify --jwksFile jwks.json
```

```error:partial
no token provided
```

### should refuse a token and a tokenFile together

```execute
aux4 jwt verify abc.def.ghi --tokenFile valid.txt --jwksFile jwks.json
```

```error:partial
a token and a tokenFile were both provided
```

### should fail when the JWKS file does not exist

```execute
aux4 jwt verify --tokenFile valid.txt --jwksFile missing.json --issuer https://issuer.example.com --audience my-api
```

```error:partial
token rejected: reading jwks file: *?
```

### should fail when the JWKS file is not a key set

```file:broken.json
this is not a key set
```

```execute
aux4 jwt verify --tokenFile valid.txt --jwksFile broken.json --issuer https://issuer.example.com --audience my-api
```

```error:partial
token rejected: malformed jwks file
```

### should reject a string that is not a token

```execute
aux4 jwt verify not-a-jwt --jwksFile jwks.json --issuer https://issuer.example.com --audience my-api
```

```error:partial
token rejected: malformed token: expected 3 dot-separated segments
```

### should fail when the requested claim is absent

```execute
aux4 jwt verify --tokenFile valid.txt --jwksFile jwks.json --issuer https://issuer.example.com --audience my-api --claim department
```

```error:partial
token rejected: verified token has no "department" claim
```
