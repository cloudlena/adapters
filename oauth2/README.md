# OAuth 2

The OAuth 2 handler allows to issue [OAuth 2](https://oauth.net/2/) sessions using [JWTs](https://jwt.io/) and to check if requests are authenticated with them.

This allows you to use multiple IDPs at the same time and federate your sessions among them.

## Usage

```go
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/cloudlena/adapters/oauth2"
	jwt "github.com/golang-jwt/jwt/v5"
	oa2 "golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
)

// IndexHandler says what it loves.
func IndexHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
	})
}

// parseFacebookToken creates the private claims for an internal JWT from a Facebook OAuth2 token.
func parseFacebookToken(tok *oa2.Token) (jwt.MapClaims, error) {
	var claims struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}

	meURL := "https://graph.facebook.com/me?fields=id,email,first_name,last_name&access_token=" + url.QueryEscape(tok.AccessToken)
	res, err := http.Get(meURL)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	// Check if request was successful
	if res.StatusCode != http.StatusOK {
		return nil, errors.New("invalid token response")
	}

	err = json.NewDecoder(res.Body).Decode(&claims)
	if err != nil {
		return nil, err
	}

	return jwt.MapClaims{
		"id":    claims.ID,
		"email": claims.Email,
	}, nil
}

func main() {
	sessionSecret := "my-session-secret" // Shouldn't be in your source code

	facebookConfig := &oa2.Config{
		ClientID:     "my-client-ID",
		ClientSecret: "my-client-secret",
		RedirectURL:  "http://localhost:8080/auth/callback/facebook",
		Endpoint:     facebook.Endpoint,
		Scopes:       []string{"email", "public_profile"},
	}
	// Where to send the client after a successful login. If empty, the session
	// token is returned as JSON instead.
	redirectURI := "http://localhost:8080/dashboard"

	http.Handle("/auth/login/facebook", oauth2.LoginHandler(facebookConfig))
	http.Handle("/auth/callback/facebook", oauth2.CallbackHandler(facebookConfig, sessionSecret, 24*time.Hour, redirectURI, parseFacebookToken))

	checkTokenMiddleware := oauth2.CheckTokenHandler(sessionSecret, "token")
	http.Handle("/", checkTokenMiddleware(IndexHandler()))
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

## Login flow

`LoginHandler` sends the client to the identity provider and `CallbackHandler` turns the provider's callback into a session JWT.

If `redirectURI` is empty, the session JWT is returned as a JSON body:

```json
{ "tokenType": "Bearer", "accessToken": "...", "expiresIn": 86400 }
```

Otherwise the client is redirected to `redirectURI` with the session JWT appended as an `access_token` query parameter.

## Security

The session JWT is a bearer credential, so whoever receives it is logged in as the user:

- **The redirect target is configured by the application, never by the client.** Nothing a client sends can influence where the token is sent.
- **Callbacks are bound to their login request.** `LoginHandler` uses an unguessable nonce as the OAuth 2 `state` parameter and hands the same nonce to the client in an `HttpOnly`, `SameSite=Lax` cookie. `CallbackHandler` only accepts a callback whose `state` matches that cookie and rejects anything else with `403 Forbidden`. The login and callback endpoints therefore have to be served from the same site.

Keep in mind that a token in a redirect URI also ends up in the browser history, in `Referer` headers and in any proxy or access log along the way, so prefer having it returned as JSON.
