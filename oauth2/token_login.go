package oauth2

import (
	"fmt"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// IDTokenLoginHandler allows to log in directly with an existing ID Token from an IDP.
func IDTokenLoginHandler(sessionSecret string, tokenTTL time.Duration, createPrivateClaims func(string) (jwt.MapClaims, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			status := http.StatusBadRequest
			http.Error(w, http.StatusText(status), status)
			return
		}

		tokenString := r.FormValue("id_token")

		claims, err := createPrivateClaims(tokenString)
		if err != nil {
			fmt.Println("error creating private claims:", err)
			status := http.StatusInternalServerError
			http.Error(w, http.StatusText(status), status)
			return
		}

		issueSession(w, claims, tokenTTL, sessionSecret)
	})
}
