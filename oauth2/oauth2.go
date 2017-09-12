package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2"
)

// expirationClaimKey is the key under which the expiration will be saved in the token claims.
const expirationClaimKey = "exp"

// TokenResponse is what the client will get upon successful login.
type TokenResponse struct {
	TokenType   string `json:"tokenType"`
	AccessToken string `json:"accessToken"`
	ExpiresIn   int    `json:"expiresIn"`
}

// CreatePrivateClaimsFunc is a function to create private claims out of an access token string.
type CreatePrivateClaimsFunc func(string) (jwt.MapClaims, error)

// LoginHandler triggers the respective login flow for the user.
func LoginHandler(config *oauth2.Config, stateString string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := config.AuthCodeURL(stateString, oauth2.AccessTypeOnline)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	})
}

// CallbackHandler creates a session token and returns it to the client.
// It is designed to handle the OAuth2 callback endpoint.
func CallbackHandler(config *oauth2.Config, sessionSecret string, stateString string, tokenTTL time.Duration, createPrivateClaims CreatePrivateClaimsFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			status := http.StatusBadRequest
			http.Error(w, http.StatusText(status), status)
			return
		}

		state := r.FormValue("state")
		if state != stateString {
			url := config.AuthCodeURL(stateString, oauth2.AccessTypeOnline)
			http.Redirect(w, r, url, http.StatusTemporaryRedirect)
			return
		}

		code := r.FormValue("code")
		tok, err := config.Exchange(context.Background(), code)
		if err != nil {
			url := config.AuthCodeURL(stateString, oauth2.AccessTypeOnline)
			http.Redirect(w, r, url, http.StatusTemporaryRedirect)
			return
		}

		claims, err := createPrivateClaims(tok.AccessToken)
		if err != nil {
			fmt.Println("error creating private claims:", err)
			url := config.AuthCodeURL(stateString, oauth2.AccessTypeOnline)
			http.Redirect(w, r, url, http.StatusTemporaryRedirect)
			return
		}

		issueSession(w, claims, tokenTTL, sessionSecret)
	})
}

// issueSession creates a JWT and returns it to the client.
func issueSession(w http.ResponseWriter, claims jwt.MapClaims, tokenTTL time.Duration, sessionSecret string) {
	exp := time.Now().Add(tokenTTL)
	claims[expirationClaimKey] = exp.Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedTok, err := token.SignedString([]byte(sessionSecret))
	if err != nil {
		fmt.Println("error signing token:", err)
		status := http.StatusInternalServerError
		http.Error(w, http.StatusText(status), status)
		return
	}

	resp := TokenResponse{
		TokenType:   "bearer",
		AccessToken: signedTok,
		ExpiresIn:   int(tokenTTL.Seconds()),
	}

	w.Header().Set("Content-Type", "application/json; encoding=utf-8")

	err = json.NewEncoder(w).Encode(resp)
	if err != nil {
		fmt.Println("error encoding response JSON:", err)
		status := http.StatusInternalServerError
		http.Error(w, http.StatusText(status), status)
	}
}
