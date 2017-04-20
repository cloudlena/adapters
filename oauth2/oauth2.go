package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"gopkg.in/redis.v5"

	"github.com/mastertinner/adapters"
	"github.com/satori/go.uuid"

	"golang.org/x/oauth2"
)

const (
	cookieName      = "sess_cookie"
	tokenExpiration = 4 * 24 * time.Hour
)

// Handler checks if a request is authenticated through OAuth2
func Handler(cache *redis.Client, config *oauth2.Config, stateString string, tokenContextKey interface{}) adapters.Adapter {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var sessionCookie *http.Cookie
			cookies := r.Cookies()

			// Get session cookie from cookies
			for _, c := range cookies {
				if strings.EqualFold(c.Name, cookieName) {
					sessionCookie = c
					break
				}
			}
			if sessionCookie == nil {
				url := config.AuthCodeURL(stateString, oauth2.AccessTypeOnline)
				http.Redirect(w, r, url, http.StatusTemporaryRedirect)
				return
			}

			token, err := tokenFromCache(cache, sessionCookie.Value)
			if err != nil || token == nil || !token.Valid() {
				url := config.AuthCodeURL(stateString, oauth2.AccessTypeOnline)
				http.Redirect(w, r, url, http.StatusTemporaryRedirect)
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, tokenContextKey, token)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

// CallbackHandler creates a token and saves it to the cache
func CallbackHandler(cache *redis.Client, config *oauth2.Config, stateString string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			code := http.StatusInternalServerError
			http.Error(w, http.StatusText(code), code)
			return
		}

		state := r.FormValue("state")
		if state != stateString {
			url := config.AuthCodeURL(stateString, oauth2.AccessTypeOnline)
			http.Redirect(w, r, url, http.StatusFound)
			return
		}

		code := r.FormValue("code")
		token, err := config.Exchange(context.Background(), code)
		if err != nil {
			url := config.AuthCodeURL(stateString, oauth2.AccessTypeOnline)
			http.Redirect(w, r, url, http.StatusTemporaryRedirect)
			return
		}

		cookieVal := uuid.NewV4().String()

		// Setup the cookie and set it
		cookieToSend := &http.Cookie{
			Name:     cookieName,
			Value:    cookieVal,
			MaxAge:   0,
			Secure:   false,
			HttpOnly: false,
		}

		http.SetCookie(w, cookieToSend)

		// Serialize token and insert to cache
		srlzdToken, err := json.Marshal(&token)
		if err != nil {
			log.Println("error marshalling token:", err.Error())
			url := config.AuthCodeURL(stateString, oauth2.AccessTypeOnline)
			http.Redirect(w, r, url, http.StatusTemporaryRedirect)
			return
		}

		err = cache.Set(cookieVal, srlzdToken, tokenExpiration).Err()
		if err != nil {
			log.Println("error adding token to cache:", err.Error())
			url := config.AuthCodeURL(stateString, oauth2.AccessTypeOnline)
			http.Redirect(w, r, url, http.StatusTemporaryRedirect)
			return
		}

		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	})
}

// tokenFromCache retrieves a tokenURL from the cache
func tokenFromCache(cache *redis.Client, cookieID string) (*oauth2.Token, error) {
	serializedToken, err := cache.Get(cookieID).Result()
	if err != nil {
		return nil, errors.New("error finding token in cache")
	}

	var token *oauth2.Token
	err = json.Unmarshal([]byte(serializedToken), &token)
	if err != nil || token == nil {
		return nil, errors.New("error unmarshalling token")
	}

	return token, nil
}
