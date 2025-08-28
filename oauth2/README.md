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
func parseFacebookToken(tok *oauth2.Token) (jwt.MapClaims, error) {
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
	http.Handle("/auth/login/facebook", oauth2.LoginHandler(facebookConfig))
	http.Handle("/auth/callback/facebook", oauth2.CallbackHandler(facebookConfig, sessionSecret, 24*time.Hour, parseFacebookToken))

	checkTokenMiddleware := oauth2.CheckTokenHandler(sessionSecret, "token")
	http.Handle("/", checkTokenMiddleware(IndexHandler()))
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```
