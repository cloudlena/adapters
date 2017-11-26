package oauth2

import (
	"fmt"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// ParseTokenStringFunc is a function to verify an external token string and create private claims for the internal token from it.
type ParseTokenStringFunc func(string) (jwt.MapClaims, error)

// IDTokenLoginHandler allows to log in directly with an existing ID token string from an IDP.
func IDTokenLoginHandler(sessionSecret string, tokenTTL time.Duration, parseTok ParseTokenStringFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			status := http.StatusBadRequest
			http.Error(w, http.StatusText(status), status)
			return
		}

		tok := r.FormValue("id_token")

		claims, err := parseTok(tok)
		if err != nil {
			fmt.Println("error parsing ID token:", err)
			status := http.StatusUnauthorized
			http.Error(w, http.StatusText(status), status)
			return
		}

		issueSession(w, r, claims, tokenTTL, sessionSecret, "")
	})
}
