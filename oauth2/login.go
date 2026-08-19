package oauth2

import (
	"net/http"

	oa2 "golang.org/x/oauth2"
)

// LoginHandler triggers the respective login flow for the user.
func LoginHandler(config *oa2.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uri := config.AuthCodeURL(newStateNonce(w, r))
		http.Redirect(w, r, uri, http.StatusTemporaryRedirect)
	})
}
