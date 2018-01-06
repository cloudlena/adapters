# Logging

The logging handler logs incoming requests and the time it took to serve them.

## Usage

```go
package main

import (
        "fmt"
        "log"
        "net/http"
        "os"

        "github.com/mastertinner/adapters/logging"
)

// IndexHandler says what it loves.
func IndexHandler() http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
        })
}

func main() {
        loggingMiddleware := logging.Handler(os.Stdout)
        http.Handle("/", loggingMiddleware(IndexHandler()))
        log.Fatal(http.ListenAndServe(":8080", nil))
}
```
