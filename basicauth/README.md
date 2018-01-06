# Basic Authentication

The basic authentication handler checks for [basic authentication](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication).

## Usage

```go
package main

import (
        "fmt"
        "log"
        "net/http"

        "github.com/mastertinner/adapters/basicauth"
)

// IndexHandler says what it loves.
func IndexHandler() http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
        })
}

func main() {
        users := []basicauth.User{
                {Username: "user", Password: "pass"},
        }
        authMiddleware := basicauth.Handler("My Realm", users)
        http.Handle("/", authMiddleware(IndexHandler()))
        log.Fatal(http.ListenAndServe(":8080", nil))
}
```
