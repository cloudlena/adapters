package oauth2

import (
	"crypto/rand"
	"crypto/subtle"
	"net/http"
)

// stateCookieName holds the nonce binding an OAuth 2 callback to its login request.
const stateCookieName = "oauth2_state"

// stateCookieMaxAge is how long a login flow may take to complete.
const stateCookieMaxAge = 600

// newStateNonce hands the client an unguessable nonce and returns it for use as
// the state parameter.
func newStateNonce(w http.ResponseWriter, r *http.Request) string {
	nonce := rand.Text()

	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    nonce,
		Path:     "/",
		MaxAge:   stateCookieMaxAge,
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteLaxMode,
	})

	return nonce
}

// hasStateNonce reports whether nonce is the one handed out at login.
func hasStateNonce(r *http.Request, nonce string) bool {
	cookie, err := r.Cookie(stateCookieName)
	if err != nil || nonce == "" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(nonce)) == 1
}
