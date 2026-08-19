package oauth2

import (
	"log"
	"net/http"
	"time"

	oa2 "golang.org/x/oauth2"
)

// CallbackHandler creates a session token and returns it to the client.
// It is designed to handle the OAuth2 callback endpoint.
// If redirectURI isn't empty, the client is redirected there with the token
// attached as an access_token query parameter, otherwise it is returned as JSON.
func CallbackHandler(
	config *oa2.Config,
	sessionSecret string,
	tokenTTL time.Duration,
	redirectURI string,
	parseTok ParseTokenFunc,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()

		// Only honor callbacks belonging to a login flow this client started.
		if !hasStateNonce(r, query.Get("state")) {
			status := http.StatusForbidden
			http.Error(w, http.StatusText(status), status)
			return
		}

		tok, err := config.Exchange(r.Context(), query.Get("code"))
		if err != nil {
			log.Println("error exchanging code:", err)
			status := http.StatusBadRequest
			http.Error(w, http.StatusText(status), status)
			return
		}

		claims, err := parseTok(tok)
		if err != nil {
			log.Println("error parsing token:", err)
			status := http.StatusUnauthorized
			http.Error(w, http.StatusText(status), status)
			return
		}

		issueSession(w, r, claims, tokenTTL, sessionSecret, redirectURI)
	})
}
