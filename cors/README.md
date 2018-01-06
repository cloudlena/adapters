# CORS

The CORS handler adds the necessary [CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS) headers to a response.

## Usage

```go
package main

import (
        "fmt"
        "log"
        "net/http"

        "github.com/mastertinner/adapters/cors"
)

// IndexHandler says what it loves.
func IndexHandler() http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
        })
}

func main() {
        corsMiddleware := cors.Handler(cors.Options{})
        http.Handle("/", corsMiddleware(IndexHandler()))
        log.Fatal(http.ListenAndServe(":8080", nil))
}
```
