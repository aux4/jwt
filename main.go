// Command aux4-jwt is the binary behind the aux4/jwt package.
//
// Exit codes are part of its contract:
//
//	0  the token was verified and every configured check passed
//	1  the token was rejected (bad signature, expired, claim mismatch, ...)
//	2  the command could not run as asked (bad usage, unreadable JWKS, ...)
//
// Anything other than 0 means "do not trust this token". Nothing usable is
// ever written to stdout on a non-zero exit.
package main

import (
	"fmt"
	"os"
)

const (
	exitOK       = 0
	exitRejected = 1
	exitUsage    = 2
)

// usageError marks a failure that is about how the command was invoked rather
// than about the token, so it can be reported with a distinct exit code.
type usageError struct {
	err error
}

func (e usageError) Error() string {
	return e.err.Error()
}

func usagef(format string, args ...interface{}) error {
	return usageError{err: fmt.Errorf(format, args...)}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: aux4-jwt <command> [args...]")
		os.Exit(exitUsage)
	}

	command := os.Args[1]
	args := os.Args[2:]

	if err := dispatch(command, args); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		if _, ok := err.(usageError); ok {
			os.Exit(exitUsage)
		}
		os.Exit(exitRejected)
	}

	os.Exit(exitOK)
}

func dispatch(command string, args []string) error {
	switch command {
	case "verify":
		return cmdVerify(args)
	case "decode-unverified":
		return cmdDecodeUnverified(args)
	case "jwks-list":
		return cmdJwksList(args)
	case "jwks-fetch":
		return cmdJwksFetch(args)
	default:
		return usagef("unknown command: %s", command)
	}
}

// arg returns the positional argument at index i, or "" when it was not
// supplied. aux4 passes every declared variable positionally, so a missing
// index means the caller invoked the binary directly.
func arg(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}
