package oauth2_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	oa2 "golang.org/x/oauth2"

	cloudoa2 "github.com/cloudlena/adapters/oauth2"
)

const testSecret = "super-secret-key"

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read error") }

type contextKey string

const tokenKey contextKey = "token"

func signedToken(t *testing.T, secret string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return s
}

func mockOAuthServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "mock-access-token",
			"token_type":   "Bearer",
		})
	}))
}

// --- LoginHandler ---

func TestLoginHandler_RedirectsToAuthURL(t *testing.T) {
	config := &oa2.Config{
		ClientID: "client-id",
		Endpoint: oa2.Endpoint{
			AuthURL:  "https://provider.example/auth",
			TokenURL: "https://provider.example/token",
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/?redirect_uri=https://app.example/callback", nil)
	rr := httptest.NewRecorder()
	cloudoa2.LoginHandler(config).ServeHTTP(rr, req)

	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected %d, got %d", http.StatusTemporaryRedirect, rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://provider.example/auth") {
		t.Errorf("expected redirect to auth URL, got %q", loc)
	}
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	// LoginHandler calls url.QueryEscape on the redirect_uri before passing it as state.
	if got := parsed.Query().Get("state"); got != url.QueryEscape("https://app.example/callback") {
		t.Errorf("expected state to be encoded redirect URI, got %q", got)
	}
}

func TestLoginHandler_NoRedirectURI(t *testing.T) {
	config := &oa2.Config{
		ClientID: "client-id",
		Endpoint: oa2.Endpoint{
			AuthURL:  "https://provider.example/auth",
			TokenURL: "https://provider.example/token",
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	cloudoa2.LoginHandler(config).ServeHTTP(rr, req)

	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected %d, got %d", http.StatusTemporaryRedirect, rr.Code)
	}
}

// --- CallbackHandler ---

func TestCallbackHandler_Success(t *testing.T) {
	srv := mockOAuthServer(t)
	defer srv.Close()

	config := &oa2.Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Endpoint: oa2.Endpoint{
			AuthURL:  srv.URL + "/auth",
			TokenURL: srv.URL + "/token",
		},
	}

	parseTok := func(tok *oa2.Token) (jwt.MapClaims, error) {
		return jwt.MapClaims{"sub": "user1"}, nil
	}

	state := url.QueryEscape("")
	req := httptest.NewRequest(http.MethodGet, "/?code=valid-code&state="+state, nil)
	rr := httptest.NewRecorder()
	cloudoa2.CallbackHandler(config, testSecret, time.Hour, parseTok).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	var resp cloudoa2.TokenResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("expected token type Bearer, got %q", resp.TokenType)
	}
	if resp.AccessToken == "" {
		t.Error("expected non-empty access token")
	}
}

func TestCallbackHandler_BadState(t *testing.T) {
	srv := mockOAuthServer(t)
	defer srv.Close()

	config := &oa2.Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Endpoint: oa2.Endpoint{
			AuthURL:  srv.URL + "/auth",
			TokenURL: srv.URL + "/token",
		},
	}

	parseTok := func(tok *oa2.Token) (jwt.MapClaims, error) {
		return nil, errors.New("should not be called")
	}

	// %25zz decodes to %zz in form values, which is an invalid percent-encoding for QueryUnescape.
	req := httptest.NewRequest(http.MethodGet, "/?code=x&state=%25zz", nil)
	rr := httptest.NewRecorder()
	cloudoa2.CallbackHandler(config, testSecret, time.Hour, parseTok).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected %d for malformed state, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestCallbackHandler_ExchangeError_Redirects(t *testing.T) {
	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer failSrv.Close()

	config := &oa2.Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Endpoint: oa2.Endpoint{
			AuthURL:  failSrv.URL + "/auth",
			TokenURL: failSrv.URL + "/token",
		},
	}

	parseTok := func(tok *oa2.Token) (jwt.MapClaims, error) {
		return nil, errors.New("should not be called")
	}

	req := httptest.NewRequest(http.MethodGet, "/?code=bad-code&state=", nil)
	rr := httptest.NewRecorder()
	cloudoa2.CallbackHandler(config, testSecret, time.Hour, parseTok).ServeHTTP(rr, req)

	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected %d on exchange error, got %d", http.StatusTemporaryRedirect, rr.Code)
	}
}

func TestCallbackHandler_ParseTokenError_Redirects(t *testing.T) {
	srv := mockOAuthServer(t)
	defer srv.Close()

	config := &oa2.Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Endpoint: oa2.Endpoint{
			AuthURL:  srv.URL + "/auth",
			TokenURL: srv.URL + "/token",
		},
	}

	parseTok := func(tok *oa2.Token) (jwt.MapClaims, error) {
		return nil, errors.New("invalid token")
	}

	req := httptest.NewRequest(http.MethodGet, "/?code=valid-code&state=", nil)
	rr := httptest.NewRecorder()
	cloudoa2.CallbackHandler(config, testSecret, time.Hour, parseTok).ServeHTTP(rr, req)

	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected %d on parse error, got %d", http.StatusTemporaryRedirect, rr.Code)
	}
}

func TestCallbackHandler_WithRedirectURI(t *testing.T) {
	srv := mockOAuthServer(t)
	defer srv.Close()

	config := &oa2.Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Endpoint: oa2.Endpoint{
			AuthURL:  srv.URL + "/auth",
			TokenURL: srv.URL + "/token",
		},
	}

	parseTok := func(tok *oa2.Token) (jwt.MapClaims, error) {
		return jwt.MapClaims{"sub": "user1"}, nil
	}

	state := url.QueryEscape("https://app.example/dashboard")
	req := httptest.NewRequest(http.MethodGet, "/?code=valid-code&state="+state, nil)
	rr := httptest.NewRecorder()
	cloudoa2.CallbackHandler(config, testSecret, time.Hour, parseTok).ServeHTTP(rr, req)

	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected %d with redirect URI, got %d", http.StatusTemporaryRedirect, rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://app.example/dashboard") {
		t.Errorf("expected redirect to dashboard, got %q", loc)
	}
	if !strings.Contains(loc, "access_token=") {
		t.Errorf("expected access_token in redirect URL, got %q", loc)
	}
}

// --- CheckTokenHandler ---

func TestCheckTokenHandler_ValidToken(t *testing.T) {
	claims := jwt.MapClaims{
		"sub": "user1",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	signed := signedToken(t, testSecret, claims)

	var nextCalled bool
	h := cloudoa2.CheckTokenHandler(testSecret, tokenKey)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		tok, ok := r.Context().Value(tokenKey).(*jwt.Token)
		if !ok || tok == nil {
			t.Error("expected token in context")
		}
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !nextCalled {
		t.Error("expected next handler to be called with valid token")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestCheckTokenHandler_MissingToken(t *testing.T) {
	h := cloudoa2.CheckTokenHandler(testSecret, tokenKey)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCheckTokenHandler_InvalidToken(t *testing.T) {
	h := cloudoa2.CheckTokenHandler(testSecret, tokenKey)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer not-a-valid-jwt")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestCheckTokenHandler_WrongSigningMethod(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	claims := jwt.MapClaims{"sub": "user1", "exp": time.Now().Add(time.Hour).Unix()}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	h := cloudoa2.CheckTokenHandler(testSecret, tokenKey)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong signing method, got %d", rr.Code)
	}
}

func TestCheckTokenHandler_WrongSecret(t *testing.T) {
	claims := jwt.MapClaims{"sub": "user1", "exp": time.Now().Add(time.Hour).Unix()}
	signed := signedToken(t, "other-secret", claims)

	h := cloudoa2.CheckTokenHandler(testSecret, tokenKey)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --- TokenLoginHandler ---

func TestTokenLoginHandler_ParseFormError(t *testing.T) {
	parseTok := func(tok *oa2.Token) (jwt.MapClaims, error) {
		return nil, errors.New("should not be called")
	}
	h := cloudoa2.TokenLoginHandler(testSecret, time.Hour, parseTok)

	req := httptest.NewRequest(http.MethodPost, "/", errReader{})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 on form parse error, got %d", rr.Code)
	}
}

func TestTokenLoginHandler_ValidToken(t *testing.T) {
	parseTok := func(tok *oa2.Token) (jwt.MapClaims, error) {
		if tok.AccessToken != "my-token" {
			return nil, errors.New("unexpected token")
		}
		return jwt.MapClaims{"sub": "user1"}, nil
	}

	h := cloudoa2.TokenLoginHandler(testSecret, time.Hour, parseTok)

	form := url.Values{"access_token": {"my-token"}}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	var resp cloudoa2.TokenResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("expected token type Bearer, got %q", resp.TokenType)
	}
}

func TestTokenLoginHandler_InvalidToken(t *testing.T) {
	parseTok := func(tok *oa2.Token) (jwt.MapClaims, error) {
		return nil, errors.New("bad token")
	}

	h := cloudoa2.TokenLoginHandler(testSecret, time.Hour, parseTok)

	form := url.Values{"access_token": {"bad-token"}}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}
