package cors

import (
	"net/http"
	"strconv"
	"strings"
)

// Options configure a CORS handler.
type Options struct {
	Origins     []string
	Methods     []string
	Headers     []string
	Credentials bool
}

// Handler adds CORS headers to the response.
func Handler(o Options) func(http.Handler) http.Handler {
	if o.Origins == nil {
		o.Origins = []string{"*"}
	}

	if o.Methods == nil {
		o.Methods = []string{
			http.MethodGet,
			http.MethodPut,
			http.MethodPatch,
			http.MethodPost,
			http.MethodDelete,
			http.MethodHead,
		}
	}

	if o.Headers == nil {
		o.Headers = []string{
			"Content-Type",
			"Authorization",
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(o.Headers) == 0 {
				reqHeaders := r.Header.Get("Access-Control-Request-Headers")
				if reqHeaders != "" {
					o.Headers = append(o.Headers, reqHeaders)
				}
			}

			if r.Header.Get("Origin") != "" {
				if len(o.Origins) > 0 {
					w.Header().Set("Access-Control-Allow-Origin", strings.Join(o.Origins, ", "))
				}
				if len(o.Methods) > 0 {
					w.Header().Set("Access-Control-Allow-Methods", strings.Join(o.Methods, ", "))
				}
				if len(o.Headers) > 0 {
					w.Header().Set("Access-Control-Allow-Headers", strings.Join(o.Headers, ", "))
				}
				w.Header().Set("Access-Control-Allow-Credentials", strconv.FormatBool(o.Credentials))
			}

			if r.Method == http.MethodOptions {
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
