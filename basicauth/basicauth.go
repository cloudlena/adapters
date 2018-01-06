package basicauth

import (
	"fmt"
	"net/http"
)

// User is a set of username and password.
type User struct {
	Username string
	Password string
}

// Handler enforces basic authenthication.
func Handler(realm string, users []User) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, pass, ok := r.BasicAuth()
			if !ok {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=\"%s\"", realm))
				status := http.StatusUnauthorized
				http.Error(w, http.StatusText(status), status)
				return
			}

			var found bool
			for _, u := range users {
				if user == u.Username && pass == u.Password {
					found = true
				}
			}
			if !found {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=\"%s\"", realm))
				status := http.StatusUnauthorized
				http.Error(w, http.StatusText(status), status)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
