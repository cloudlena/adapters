package oauth2

import (
	jwt "github.com/dgrijalva/jwt-go"
	oa2 "golang.org/x/oauth2"
)

// ParseTokenFunc is a function to verify an external token and create private claims for the internal token from it.
type ParseTokenFunc func(*oa2.Token) (jwt.MapClaims, error)
