package secure

import (
	"net/http"

	"github.com/mastertinner/adapters"
)

// Handler redirects any HTTP request to HTTPS.
func Handler(enabled bool) adapters.Adapter {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if enabled && r.TLS == nil {
				url := "https://" + r.Host + r.URL.String()
				http.Redirect(w, r, url, http.StatusPermanentRedirect)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
