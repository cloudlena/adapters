package oauth2

import (
	"net/http"
	"net/url"

	oa2 "golang.org/x/oauth2"
)

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
