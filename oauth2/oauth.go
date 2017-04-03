package oauth2

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/mastertinner/adapters"
	uuid "github.com/satori/go.uuid"

	redis "gopkg.in/redis.v5"

	oa2 "golang.org/x/oauth2"
)

const cookieName = "sess_cookie"

// Handler checks if a request is authenticated
func Handler(redisClient *redis.Client, config *oa2.Config, stateString string) adapters.Adapter {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var sessionCookie *http.Cookie
			cookies := r.Cookies()

			// Get session cookie from cookies
			for _, cookie := range cookies {
				if strings.EqualFold(cookie.Name, cookieName) {
					sessionCookie = cookie
					break
				}
			}
			if sessionCookie == nil {
				url := config.AuthCodeURL(stateString, oa2.AccessTypeOnline)
				http.Redirect(w, r, url, http.StatusTemporaryRedirect)
				return
			}

			cachedToken, err := tokenFromCache(redisClient, sessionCookie.Value)
			if err != nil || cachedToken == nil || !cachedToken.Valid() {
				url := config.AuthCodeURL(stateString, oa2.AccessTypeOnline)
				http.Redirect(w, r, url, http.StatusTemporaryRedirect)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// OauthCallbackHandler creates a token and saves it to the cache
func CallbackHandler(redisClient *redis.Client, config *oa2.Config, stateString string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		state := r.FormValue("state")
		if state != stateString {
			url := config.AuthCodeURL(stateString, oa2.AccessTypeOnline)
			http.Redirect(w, r, url, http.StatusFound)
			return
		}

		code := r.FormValue("code")
		token, err := config.Exchange(oa2.NoContext, code)
		if err != nil {
			url := config.AuthCodeURL(stateString, oa2.AccessTypeOnline)
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

		err = redisClient.Set(cookieVal, srlzdToken, 0).Err()
		if err != nil {
			log.Printf("Could not add token to cache: %v", err)
		}

		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	})
}

// tokenFromCache retrieves a tokenURL from the cache
func tokenFromCache(redisClient *redis.Client, cookieUUID string) (*oa2.Token, error) {
	serializedToken, err := redisClient.Get(cookieUUID).Result()
	if err != nil {
		return nil, errors.New("Couldn't find token in cache")
	}

	var token *oa2.Token
	err = json.Unmarshal([]byte(serializedToken), &token)

	if token == nil {
		return nil, errors.New("Couldn't unmarshall token")
	}

	return token, nil
}
