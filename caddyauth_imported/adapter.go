package caddyauthimported

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
)

// Same code as forwardproxy's basicauth former implementation
func getCredsFromHeader(r *http.Request) (string, string, error) {
	pa := strings.Split(r.Header.Get("Proxy-Authorization"), " ")
	if len(pa) != 2 {
		return "", "", errors.New("Proxy-Authorization is required! Expected format: <type> <credentials>")
	}
	if strings.ToLower(pa[0]) != "basic" {
		return "", "", errors.New("auth type is not supported")
	}
	buf := make([]byte, base64.StdEncoding.DecodedLen(len(pa[1])))
	_, _ = base64.StdEncoding.Decode(buf, []byte(pa[1])) // should not err ever since we are decoding a known good input // TODO true?
	credarr := strings.Split(string(buf), ":")

	return credarr[0], credarr[1], nil
}

// Authenticate validates the user credentials in req and returns the user, if valid.
// Same code as caddy's basicAuth, but it doesn't write anything on the ResponseWriter
func (hba HTTPBasicAuth) AuthenticateNoCredsPrompt(req *http.Request) (User, bool, error) {
	username, plaintextPasswordStr, err := getCredsFromHeader(req)
	if err != nil {
		return User{}, false, err
	}

	account, accountExists := hba.Accounts[username]
	if !accountExists {
		// don't return early if account does not exist; we want
		// to try to avoid side-channels that leak existence, so
		// we use a fake password to simulate realistic CPU cycles
		account.password = hba.fakePassword
	}

	same, err := hba.correctPassword(account, []byte(plaintextPasswordStr))
	if err != nil || !same || !accountExists {
		return User{ID: username}, false, err
	}

	return User{ID: username}, true, nil
}
