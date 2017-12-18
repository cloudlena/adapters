package oauth2

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	oa2 "golang.org/x/oauth2"
)

// ParseTokenFunc is a function to verify an external token and create private claims for the internal token from it.
type ParseTokenFunc func(*oa2.Token) (jwt.MapClaims, error)

// LoginHandler triggers the respective login flow for the user.
func LoginHandler(config *oa2.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			status := http.StatusBadRequest
			http.Error(w, http.StatusText(status), status)
			return
		}

		redirectURI := url.QueryEscape(r.FormValue("redirect_uri"))
		url := config.AuthCodeURL(redirectURI)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	})
}

// CallbackHandler creates a session token and returns it to the client.
// It is designed to handle the OAuth2 callback endpoint.
func CallbackHandler(config *oa2.Config, sessionSecret string, tokenTTL time.Duration, parseTok ParseTokenFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			status := http.StatusBadRequest
			http.Error(w, http.StatusText(status), status)
			return
		}

		redirectURI, err := url.QueryUnescape(r.FormValue("state"))
		if err != nil {
			status := http.StatusBadRequest
			http.Error(w, http.StatusText(status), status)
			return
		}

		code := r.FormValue("code")
		tok, err := config.Exchange(context.Background(), code)
		if err != nil {
			url := config.AuthCodeURL(redirectURI)
			http.Redirect(w, r, url, http.StatusTemporaryRedirect)
			return
		}

		claims, err := parseTok(tok)
		if err != nil {
			fmt.Println("error parsing token:", err)
			url := config.AuthCodeURL(redirectURI)
			http.Redirect(w, r, url, http.StatusTemporaryRedirect)
			return
		}

		issueSession(w, r, claims, tokenTTL, sessionSecret, redirectURI)
	})
}

// TokenLoginHandler logs a user who already has an access token in.
func TokenLoginHandler(config *oa2.Config, sessionSecret string, tokenTTL time.Duration, parseTok ParseTokenFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			status := http.StatusBadRequest
			http.Error(w, http.StatusText(status), status)
			return
		}

		accessToken := r.FormValue("access_token")
		tok := &oa2.Token{AccessToken: accessToken}

		claims, err := parseTok(tok)
		if err != nil {
			fmt.Println("error parsing token:", err)
			status := http.StatusUnauthorized
			http.Error(w, http.StatusText(status), status)
			return
		}

		issueSession(w, r, claims, tokenTTL, sessionSecret, "")
	})
}
