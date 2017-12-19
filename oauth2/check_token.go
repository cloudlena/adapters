package oauth2

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/mastertinner/adapters"
)

// CheckToken checks if a request is authenticated through OAuth2 and JWT.
// If it is, it will add the token to the request's context.
func CheckToken(sessionSecret string, tokenContextKey interface{}) adapters.Adapter {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")

			token, err := jwt.Parse(tokenString, func(tok *jwt.Token) (interface{}, error) {
				if _, ok := tok.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", tok.Header["alg"])
				}
				return []byte(sessionSecret), nil
			})
			if err != nil || !token.Valid {
				status := http.StatusUnauthorized
				http.Error(w, http.StatusText(status), status)
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, tokenContextKey, token)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}
