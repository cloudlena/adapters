package oauth2

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	oa2 "golang.org/x/oauth2"
)

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
