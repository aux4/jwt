package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aux4/jwt/internal/jwt"
)

// cmdVerify is the only command in this package that answers the question
// "may I trust this token?". Everything it does is fail-closed: on any error
// it returns non-nil, main prints the reason to stderr, and stdout stays
// empty so a caller that pipes stdout can never mistake a failure for a pass.
func cmdVerify(args []string) error {
	var (
		rawToken   = arg(args, 0)
		tokenFile  = arg(args, 1)
		jwksFile   = arg(args, 2)
		issuer     = arg(args, 3)
		audience   = arg(args, 4)
		subject    = arg(args, 5)
		scope      = arg(args, 6)
		algorithms = arg(args, 7)
		clockSkew  = arg(args, 8)
		maxAge     = arg(args, 9)
		claimName  = arg(args, 10)
		quiet      = parseBool(arg(args, 11))
		strict     = parseBool(arg(args, 12))
		warnings   = parseBoolDefault(arg(args, 13), true)
	)

	if strings.TrimSpace(jwksFile) == "" {
		return usagef("no JWKS file configured: pass --jwksFile or set AUX4_JWT_JWKS_FILE")
	}

	token, err := resolveToken(rawToken, tokenFile)
	if err != nil {
		return err
	}

	algList, err := parseAlgorithms(algorithms)
	if err != nil {
		return usageError{err: err}
	}

	skew, err := parseSeconds(clockSkew, "clockSkew")
	if err != nil {
		return usageError{err: err}
	}

	age, err := parseSeconds(maxAge, "maxAge")
	if err != nil {
		return usageError{err: err}
	}

	// Unconfigured checks are not silently skipped. In strict mode a missing
	// issuer or audience is a refusal to run at all; otherwise every skipped
	// check is named on stderr, where it cannot corrupt the claims on stdout
	// but is impossible to miss while setting the tool up.
	if strict {
		var missing []string
		if issuer == "" {
			missing = append(missing, "--issuer")
		}
		if audience == "" {
			missing = append(missing, "--audience")
		}
		if len(missing) > 0 {
			return usagef("strict mode requires %s to be configured", strings.Join(missing, " and "))
		}
	} else if warnings {
		if issuer == "" {
			fmt.Fprintln(os.Stderr, "warning: no issuer configured, the iss claim was NOT checked")
		}
		if audience == "" {
			fmt.Fprintln(os.Stderr, "warning: no audience configured, the aud claim was NOT checked")
		}
	}

	claims, err := jwt.Verify(token, jwksFile, jwt.VerifyOptions{
		Issuer:     issuer,
		Audience:   audience,
		Subject:    subject,
		Scope:      scope,
		Algorithms: algList,
		ClockSkew:  skew,
		MaxAge:     age,
	})
	if err != nil {
		// The reason is useful; the token never is. Nothing here echoes it.
		return fmt.Errorf("token rejected: %w", err)
	}

	if quiet {
		return nil
	}

	if claimName != "" {
		value, ok := claims[claimName]
		if !ok {
			return fmt.Errorf("token rejected: verified token has no %q claim", claimName)
		}
		return printClaimValue(value)
	}

	return printJSON(claims)
}

// resolveToken picks the token up from the argument (which aux4 also fills
// from AUX4_JWT_TOKEN) or from a file. Having both set is an error rather
// than a silent precedence rule: a verifier should never leave the operator
// guessing which credential was actually checked.
func resolveToken(rawToken, tokenFile string) (string, error) {
	rawToken = strings.TrimSpace(rawToken)
	tokenFile = strings.TrimSpace(tokenFile)

	if rawToken != "" && tokenFile != "" {
		return "", usagef("a token and a tokenFile were both provided: pass exactly one")
	}

	if tokenFile != "" {
		data, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", usagef("reading token file: %s", pathErrorMessage(err))
		}
		rawToken = string(data)
	}

	token := stripBearer(strings.TrimSpace(rawToken))
	if token == "" {
		return "", usagef("no token provided: pass it as an argument, set AUX4_JWT_TOKEN, or use --tokenFile")
	}

	return token, nil
}

// pathErrorMessage keeps the filesystem reason without letting an underlying
// error format leak anything unexpected into a log line.
func pathErrorMessage(err error) string {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return fmt.Sprintf("%s: %s", pathErr.Path, pathErr.Err.Error())
	}
	return err.Error()
}

// stripBearer accepts the value of an Authorization header as-is, which is
// where a token usually comes from.
func stripBearer(token string) string {
	if len(token) >= 7 && strings.EqualFold(token[:7], "bearer ") {
		return strings.TrimSpace(token[7:])
	}
	return token
}

func parseAlgorithms(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	var names []string
	for _, part := range strings.Split(raw, ",") {
		name := strings.TrimSpace(part)
		if name != "" {
			names = append(names, name)
		}
	}

	if len(names) == 0 {
		return nil, nil
	}

	if err := jwt.ValidateAlgorithmNames(names); err != nil {
		return nil, err
	}

	return names, nil
}

func parseSeconds(raw, name string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}

	seconds, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be a whole number of seconds, got %q", name, raw)
	}
	if seconds < 0 {
		return 0, fmt.Errorf("%s must not be negative", name)
	}

	return time.Duration(seconds) * time.Second, nil
}

func parseBool(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "1", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func parseBoolDefault(raw string, fallback bool) bool {
	if strings.TrimSpace(raw) == "" {
		return fallback
	}
	return parseBool(raw)
}

func printJSON(value interface{}) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding output: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

// printClaimValue prints a scalar claim bare so it can be captured straight
// into a shell variable, and structured claims as JSON.
func printClaimValue(value interface{}) error {
	switch v := value.(type) {
	case string:
		fmt.Println(v)
		return nil
	case bool:
		fmt.Println(strconv.FormatBool(v))
		return nil
	case float64:
		if v == float64(int64(v)) {
			fmt.Println(strconv.FormatInt(int64(v), 10))
			return nil
		}
		fmt.Println(strconv.FormatFloat(v, 'f', -1, 64))
		return nil
	case nil:
		fmt.Println("")
		return nil
	}
	return printJSON(value)
}
