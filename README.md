# Adapters

[![Go Report Card](https://goreportcard.com/badge/github.com/cloudlena/adapters?style=flat-square)](https://goreportcard.com/report/github.com/cloudlena/adapters)
[![Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Factions-badge.atrox.dev%2Fcloudlena%2Fadapters%2Fbadge&style=flat-square)](https://github.com/cloudlena/adapters/actions)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/cloudlena/adapters)](https://pkg.go.dev/github.com/cloudlena/adapters)

Adapters is a collection of useful HTTP middleware or "Adapters". They follow the Adapter Pattern described by Mat Ryer in his blog post [Writing middleware in #golang and how Go makes it so much fun.](https://medium.com/@matryer/writing-middleware-in-golang-and-how-go-makes-it-so-much-fun-4375c1246e81)

Adapters can be chained in many ways (e.g. with [Alice](https://github.com/justinas/alice) or [gorilla/mux](https://github.com/gorilla/mux#middleware)) because they all implement `func (http.Handler) http.Handler`.

## Contents

This package contains the following adapters:

- [Basic Auth](https://github.com/cloudlena/adapters/tree/main/basicauth): Checks for basic authentication
- [CORS](https://github.com/cloudlena/adapters/tree/main/cors): Adds the necessary CORS headers to a response
- [Enforce HTTPS](https://github.com/cloudlena/adapters/tree/main/enforcehttps): Redirects HTTP requests to HTTPS
- [Logging](https://github.com/cloudlena/adapters/tree/main/logging): Logs incoming requests and the time it took to serve them
- [OAuth 2](https://github.com/cloudlena/adapters/tree/main/oauth2): Checks for OAuth 2 authentication and issues sessions using JWTs
