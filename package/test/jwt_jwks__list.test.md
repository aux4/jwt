# jwt jwks list

`jwks list` shows which keys a local JWKS file actually holds. It is the usual
answer to a verification failure that says the token's `kid` was not found.

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

## listing a key set

### should list the identifying metadata of every key

```execute
aux4 jwt jwks list jwks.json
```

```expect:json
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

### should accept the file through the environment

```execute
AUX4_JWT_JWKS_FILE=jwks.json aux4 jwt jwks list
```

```expect:partial
[
  {
    "alg": "RS256",
    **
]
```

### should return an empty list for a key set with no keys

```file:empty.json
{
  "keys": []
}
```

```execute
aux4 jwt jwks list empty.json
```

```expect
[]
```

## usage errors

### should fail when no file is given

```execute
aux4 jwt jwks list
```

```error:partial
no JWKS file configured
```

### should fail when the file does not exist

```execute
aux4 jwt jwks list missing.json
```

```error:partial
reading jwks file: *?
```

### should fail when the file is not a key set

```file:broken.json
this is not a key set
```

```execute
aux4 jwt jwks list broken.json
```

```error:partial
malformed jwks file: not a valid JWKS document
```
