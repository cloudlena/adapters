# Adapters

Adapters is a collection of useful HTTP middleware or "Adapters". They follow the Adapter Pattern described by Mat Ryer in his blog post [Writing middleware in #golang and how Go makes it so much fun.](https://medium.com/@matryer/writing-middleware-in-golang-and-how-go-makes-it-so-much-fun-4375c1246e81)

## Usage

```go
package main

import (
    "fmt"
    "net/http"

    "github.com/mastertinner/adapters"
)

func IndexHandler() http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
        })
}

func main() {
        http.Handler("/", adapters.Adapt(IndexHandler(), adapters.Logger()))
        http.ListenAndServe(":8080", nil)
}
```

## Adapters

Currently, this package contains the following adapters:

* OAuth: Checks if a request is authenticated through OAuth
* Logger: Logs the request
