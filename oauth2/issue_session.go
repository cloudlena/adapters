package oauth2

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// expirationClaimKey is the key under which the expiration will be saved.
const expirationClaimKey = "exp"

// TokenResponse is what the client will get upon successful login.
type TokenResponse struct {
	TokenType   string `json:"tokenType"`
	AccessToken string `json:"accessToken"`
	ExpiresIn   int    `json:"expiresIn"`
}

// issueSession creates a JWT and returns it to the client.
func issueSession(
	w http.ResponseWriter,
	r *http.Request,
	claims jwt.MapClaims,
	tokenTTL time.Duration,
	sessionSecret,
	redirectURI string,
) {
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
		TokenType:   "Bearer",
		AccessToken: signedTok,
		ExpiresIn:   int(tokenTTL.Seconds()),
	}

	if redirectURI != "" {
		uri := fmt.Sprintf("%s?access_token=%s", redirectURI, signedTok)
		http.Redirect(w, r, uri, http.StatusTemporaryRedirect)
	} else {
		w.Header().Set("Content-Type", "application/json; encoding=utf-8")

		err = json.NewEncoder(w).Encode(resp)
		if err != nil {
			fmt.Println("error encoding response JSON:", err)
			status := http.StatusInternalServerError
			http.Error(w, http.StatusText(status), status)
		}
	}
}
