package cors

import (
	"net/http"
	"strings"
)

// Options configure a CORS handler.
type Options struct {
	Origins string
	Methods string
	Headers string
}

// Handler adds CORS headers to the response.
func Handler(o Options) func(http.Handler) http.Handler {
	if o.Origins == "" {
		o.Origins = "*"
	}
	if o.Methods == "" {
		o.Methods = strings.Join([]string{
			http.MethodPost,
			http.MethodGet,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
			http.MethodHead,
		}, ", ")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if o.Headers == "" {
				o.Headers = r.Header.Get("Access-Control-Request-Headers")
			}

			if r.Header.Get("Origin") != "" {
				w.Header().Set("Access-Control-Allow-Origin", o.Origins)
				w.Header().Set("Access-Control-Allow-Methods", o.Methods)
				if o.Headers != "" {
					w.Header().Set("Access-Control-Allow-Headers", o.Headers)
				}
			}

			if r.Method == http.MethodOptions {
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
