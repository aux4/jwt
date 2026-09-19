package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aux4/jwt/internal/jwt"
)

// maxJwksBytes caps how much of a response is read. A JWKS is a few kilobytes;
// anything larger is not one.
const maxJwksBytes = 1 << 20

// cmdJwksList shows what is inside a local JWKS file. It is the answer to
// "verify says unknown kid - what keys do I actually trust?".
func cmdJwksList(args []string) error {
	jwksFile := strings.TrimSpace(arg(args, 0))
	if jwksFile == "" {
		return usagef("no JWKS file configured: pass --jwksFile or set AUX4_JWT_JWKS_FILE")
	}

	keys, err := jwt.ListKeys(jwksFile)
	if err != nil {
		return usageError{err: err}
	}

	return printJSON(keys)
}

// cmdJwksFetch downloads a JWKS over HTTPS and writes it to a file. It is a
// setup-time command, entirely separate from verification: nothing in the
// verify path ever reaches the network, so the trust anchor in use is always
// the file on disk and not whatever a name server answered this second.
func cmdJwksFetch(args []string) error {
	var (
		rawURL    = strings.TrimSpace(arg(args, 0))
		issuer    = strings.TrimSpace(arg(args, 1))
		output    = strings.TrimSpace(arg(args, 2))
		timeoutIn = arg(args, 3)
	)

	if rawURL == "" && issuer == "" {
		return usagef("pass --url with a JWKS endpoint or --issuer to discover one")
	}
	if rawURL != "" && issuer != "" {
		return usagef("pass either --url or --issuer, not both")
	}
	if output == "" {
		return usagef("no output file configured: pass --output or set AUX4_JWT_JWKS_FILE")
	}

	timeout, err := parseSeconds(timeoutIn, "timeout")
	if err != nil {
		return usageError{err: err}
	}
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	client := httpsOnlyClient(timeout)

	if issuer != "" {
		rawURL, err = discoverJwksURI(client, issuer)
		if err != nil {
			return usageError{err: err}
		}
	}

	if err := requireHTTPS(rawURL); err != nil {
		return usageError{err: err}
	}

	body, err := fetch(client, rawURL)
	if err != nil {
		return usageError{err: err}
	}

	count, err := jwt.ValidateKeySetBytes(body)
	if err != nil {
		return usageError{err: fmt.Errorf("refusing to write %s: %w", output, err)}
	}

	if err := writeFileAtomically(output, body); err != nil {
		return usageError{err: err}
	}

	fmt.Fprintf(os.Stderr, "wrote %d key(s) from %s\n", count, rawURL)
	fmt.Println(output)
	return nil
}

// httpsOnlyClient refuses to follow a redirect off HTTPS, so a downgrade
// cannot smuggle a substituted key set past the scheme check.
func httpsOnlyClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return requireHTTPS(req.URL.String())
		},
	}
}

func requireHTTPS(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid url %q", rawURL)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("refusing to fetch a trust anchor over %q: https is required", parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("invalid url %q: no host", rawURL)
	}
	return nil
}

// discoverJwksURI reads an OpenID Connect discovery document and returns the
// jwks_uri it advertises.
func discoverJwksURI(client *http.Client, issuer string) (string, error) {
	if err := requireHTTPS(issuer); err != nil {
		return "", err
	}

	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"

	body, err := fetch(client, discoveryURL)
	if err != nil {
		return "", err
	}

	var document struct {
		JwksURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		return "", fmt.Errorf("%s did not return a valid discovery document", discoveryURL)
	}
	if document.JwksURI == "" {
		return "", fmt.Errorf("%s has no jwks_uri", discoveryURL)
	}

	return document.JwksURI, nil
}

func fetch(client *http.Client, rawURL string) ([]byte, error) {
	response, err := client.Get(rawURL)
	if err != nil {
		return nil, fmt.Errorf("fetching %s failed", rawURL)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s returned HTTP %d", rawURL, response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxJwksBytes))
	if err != nil {
		return nil, fmt.Errorf("reading the response from %s failed", rawURL)
	}

	return body, nil
}

// writeFileAtomically replaces the destination in one step, so an interrupted
// fetch can never leave a half-written key set where a verifier will read it.
func writeFileAtomically(path string, data []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0755); err != nil {
		return fmt.Errorf("creating %s: %w", directory, err)
	}

	temporary, err := os.CreateTemp(directory, ".jwks-*")
	if err != nil {
		return fmt.Errorf("creating a temporary file in %s: %w", directory, err)
	}
	temporaryName := temporary.Name()

	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		os.Remove(temporaryName)
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := temporary.Close(); err != nil {
		os.Remove(temporaryName)
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := os.Chmod(temporaryName, 0644); err != nil {
		os.Remove(temporaryName)
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		os.Remove(temporaryName)
		return fmt.Errorf("writing %s: %w", path, err)
	}

	return nil
}
