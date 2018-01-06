package logging

import (
	"io"
	"log"
	"net/http"
	"time"
)

// Handler logs HTTP requests.
func Handler(out io.Writer) func(http.Handler) http.Handler {
	l := log.New(out, "", log.Ldate|log.Ltime)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func(start time.Time) {
				l.Printf(
					"%s\t%s\t%s",
					r.Method,
					r.RequestURI,
					time.Since(start),
				)
			}(time.Now())

			next.ServeHTTP(w, r)
		})
	}
}
