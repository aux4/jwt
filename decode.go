package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/aux4/jwt/internal/jwt"
)

// unverifiedBanner is printed to stderr on every single invocation of
// decode-unverified. The command name already says it, but a banner survives
// being copied into a script, a screenshot or a ticket.
const unverifiedBanner = "WARNING: decode-unverified does NOT check the signature or any claim. " +
	"Anybody can mint a token with any contents. Never make an authorization decision from this output - use: aux4 jwt verify"

// cmdDecodeUnverified prints what a token says about itself. It is a
// debugging aid, deliberately kept in its own command with its own name so
// that it can never be reached by accident from a verification code path.
func cmdDecodeUnverified(args []string) error {
	var (
		rawToken  = arg(args, 0)
		tokenFile = arg(args, 1)
		part      = strings.TrimSpace(strings.ToLower(arg(args, 2)))
		claimName = arg(args, 3)
	)

	if part == "" {
		part = "payload"
	}

	token, err := resolveToken(rawToken, tokenFile)
	if err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, unverifiedBanner)

	header, claims, err := jwt.DecodeUnverified(token)
	if err != nil {
		return usagef("cannot decode token: %s", err.Error())
	}

	if claimName != "" {
		if part == "header" {
			return usagef("--claim reads a payload claim and cannot be combined with --part header")
		}
		value, ok := claims[claimName]
		if !ok {
			return usagef("token has no %q claim", claimName)
		}
		return printClaimValue(value)
	}

	switch part {
	case "payload":
		return printJSON(claims)
	case "header":
		return printJSON(headerMap(header))
	case "all":
		return printJSON(map[string]interface{}{
			"header":  headerMap(header),
			"payload": claims,
		})
	}

	return usagef("unknown part %q (expected header, payload or all)", part)
}

func headerMap(header jwt.Header) map[string]string {
	out := map[string]string{"alg": header.Alg}
	if header.Kid != "" {
		out["kid"] = header.Kid
	}
	if header.Typ != "" {
		out["typ"] = header.Typ
	}
	return out
}
