package oauth2

import (
	"fmt"
	"net/http"
	"time"

	oa2 "golang.org/x/oauth2"
)

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
