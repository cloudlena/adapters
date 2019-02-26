package enforcehttps

import "net/http"

// Handler redirects any HTTP request to HTTPS.
func Handler(enabled bool) func(http.Handler) http.Handler {
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
