package oauth2

import (
	"context"
	"fmt"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	oa2 "golang.org/x/oauth2"
)

// ParseTokenFunc is a function to verify an external token and create private claims for the internal token from it.
type ParseTokenFunc func(*oa2.Token) (jwt.MapClaims, error)

// LoginHandler triggers the respective login flow for the user.
func LoginHandler(config *oa2.Config, stateString string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := config.AuthCodeURL(stateString)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	})
}

// CallbackHandler creates a session token and returns it to the client.
// It is designed to handle the OAuth2 callback endpoint.
func CallbackHandler(config *oa2.Config, sessionSecret string, stateString string, tokenTTL time.Duration, redirectURI string, parseTok ParseTokenFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			status := http.StatusBadRequest
			http.Error(w, http.StatusText(status), status)
			return
		}

		state := r.FormValue("state")
		if state != stateString {
			url := config.AuthCodeURL(stateString)
			http.Redirect(w, r, url, http.StatusTemporaryRedirect)
			return
		}

		code := r.FormValue("code")
		tok, err := config.Exchange(context.Background(), code)
		if err != nil {
			url := config.AuthCodeURL(stateString)
			http.Redirect(w, r, url, http.StatusTemporaryRedirect)
			return
		}

		claims, err := parseTok(tok)
		if err != nil {
			fmt.Println("error parsing token:", err)
			url := config.AuthCodeURL(stateString)
			http.Redirect(w, r, url, http.StatusTemporaryRedirect)
			return
		}

		issueSession(w, r, claims, tokenTTL, sessionSecret, redirectURI)
	})
}
