# Adapters

[![Go Report Card](https://goreportcard.com/badge/github.com/mastertinner/adapters)](https://goreportcard.com/report/github.com/mastertinner/adapters)
[![GoDoc](https://godoc.org/github.com/golang/gddo?status.svg)](http://godoc.org/github.com/mastertinner/adapters)

Adapters is a collection of useful HTTP middleware or "Adapters". They follow the Adapter Pattern described by Mat Ryer in his blog post [Writing middleware in #golang and how Go makes it so much fun.](https://medium.com/@matryer/writing-middleware-in-golang-and-how-go-makes-it-so-much-fun-4375c1246e81)

Adapters can be chained in many ways (e.g. with [Alice](https://github.com/justinas/alice) or [gorilla/mux](https://github.com/gorilla/mux#middleware)) because they all implement `func (http.Handler) http.Handler`.

## Contents

This package contains the following adapters:

* [Basic Auth](https://github.com/mastertinner/adapters/tree/master/basicauth): Checks for basic authentication
* [CORS](https://github.com/mastertinner/adapters/tree/master/cors): Adds the necessary CORS headers to a response
* [Enforce HTTPS](https://github.com/mastertinner/adapters/tree/master/enforcehttps): Redirects HTTP requests to HTTPS
* [Logging](https://github.com/mastertinner/adapters/tree/master/logging): Logs incoming requests and the time it took to serve them
* [OAuth 2](https://github.com/mastertinner/adapters/tree/master/oauth2): Checks for OAuth 2 authentication and issues sessions using JWTs
