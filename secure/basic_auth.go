package secure

import (
	"fmt"
	"net/http"

	"github.com/mastertinner/adapters"
)

// BasicAuth enforces basic authenthication.
func BasicAuth(username string, password string, realm string) adapters.Adapter {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, pass, ok := r.BasicAuth()
			if !ok || user != username || pass != password {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=\"%s\"", realm))
				status := http.StatusUnauthorized
				http.Error(w, http.StatusText(status), status)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
