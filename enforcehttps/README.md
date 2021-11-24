# Enforce HTTPS

The enforce HTTPS handler redirects HTTP requests to HTTPS.

## Usage

```go
package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/cloudlena/adapters/enforcehttps"
)

// IndexHandler says what it loves.
func IndexHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
	})
}

func main() {
	httpsMiddleware := enforcehttps.Handler(true)
	http.Handle("/", httpsMiddleware(IndexHandler()))
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```
