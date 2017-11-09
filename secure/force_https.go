package secure

import (
	"net/http"

	"github.com/mastertinner/adapters"
)

// ForceHTTPS redirects any HTTP request to HTTPS.
func ForceHTTPS(enabled bool) adapters.Adapter {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			notSecure := r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https"
			if enabled && notSecure {
				url := "https://" + r.Host + r.URL.String()
				http.Redirect(w, r, url, http.StatusPermanentRedirect)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
