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

const (
	stateCookieName = "oauth2_state"
	testNonce       = "TESTNONCETESTNONCETESTNONC"
)

func testConfig(authURL, tokenURL string) *oa2.Config {
	return &oa2.Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Endpoint: oa2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
	}
}

// callbackRequest builds a callback request as the identity provider would send
// it, with cookieNonce the nonce the client holds and state the one sent back.
func callbackRequest(code, cookieNonce, state string) *http.Request {
	target := "/?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state)
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if cookieNonce != "" {
		req.AddCookie(&http.Cookie{Name: stateCookieName, Value: cookieNonce})
	}

	return req
}

// stateCookie returns the state cookie set by a handler.
func stateCookie(t *testing.T, rr *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rr.Result().Cookies() {
		if c.Name == stateCookieName {
			return c
		}
	}
	t.Fatalf("expected a %s cookie, got %v", stateCookieName, rr.Result().Cookies())

	return nil
}

// --- LoginHandler ---

func TestLoginHandler_RedirectsToAuthURL(t *testing.T) {
	config := testConfig("https://provider.example/auth", "https://provider.example/token")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
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

	// The state must be a nonce which is also handed to the client as a cookie.
	state := parsed.Query().Get("state")
	if state == "" {
		t.Error("expected a state parameter")
	}
	cookie := stateCookie(t, rr)
	if cookie.Value != state {
		t.Errorf("expected state cookie to hold the state %q, got %q", state, cookie.Value)
	}
	if !cookie.HttpOnly {
		t.Error("expected state cookie to be HTTP only")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected state cookie to be same site lax, got %v", cookie.SameSite)
	}
}

// GHSA-w7px-636p-4c44: nothing the client sends may end up in the state.
func TestLoginHandler_IgnoresRequestParams(t *testing.T) {
	config := testConfig("https://provider.example/auth", "https://provider.example/token")

	req := httptest.NewRequest(http.MethodGet, "/?redirect_uri=https://attacker.example/capture", nil)
	rr := httptest.NewRecorder()
	cloudoa2.LoginHandler(config).ServeHTTP(rr, req)

	if loc := rr.Header().Get("Location"); strings.Contains(loc, "attacker.example") {
		t.Errorf("expected the request parameter to be ignored, got %q", loc)
	}
}

// --- CallbackHandler ---

func TestCallbackHandler_Success(t *testing.T) {
	srv := mockOAuthServer(t)
	defer srv.Close()

	config := testConfig(srv.URL+"/auth", srv.URL+"/token")

	parseTok := func(tok *oa2.Token) (jwt.MapClaims, error) {
		return jwt.MapClaims{"sub": "user1"}, nil
	}

	req := callbackRequest("valid-code", testNonce, testNonce)
	rr := httptest.NewRecorder()
	cloudoa2.CallbackHandler(config, testSecret, time.Hour, "", parseTok).ServeHTTP(rr, req)

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

func TestCallbackHandler_LoginFlow(t *testing.T) {
	srv := mockOAuthServer(t)
	defer srv.Close()

	config := testConfig(srv.URL+"/auth", srv.URL+"/token")

	parseTok := func(tok *oa2.Token) (jwt.MapClaims, error) {
		return jwt.MapClaims{"sub": "user1"}, nil
	}

	// Complete a flow with the state and cookie LoginHandler handed out.
	loginRR := httptest.NewRecorder()
	cloudoa2.LoginHandler(config).ServeHTTP(loginRR, httptest.NewRequest(http.MethodGet, "/", nil))
	loc, err := url.Parse(loginRR.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}

	req := callbackRequest("valid-code", "", loc.Query().Get("state"))
	req.AddCookie(stateCookie(t, loginRR))
	rr := httptest.NewRecorder()
	cloudoa2.CallbackHandler(config, testSecret, time.Hour, "", parseTok).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for a callback of a started login flow, got %d (body: %s)", rr.Code, rr.Body.String())
	}
}

func TestCallbackHandler_MissingStateCookie(t *testing.T) {
	srv := mockOAuthServer(t)
	defer srv.Close()

	config := testConfig(srv.URL+"/auth", srv.URL+"/token")

	parseTok := func(tok *oa2.Token) (jwt.MapClaims, error) {
		return nil, errors.New("should not be called")
	}

	req := callbackRequest("valid-code", "", testNonce)
	rr := httptest.NewRecorder()
	cloudoa2.CallbackHandler(config, testSecret, time.Hour, "", parseTok).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected %d for a callback without state cookie, got %d", http.StatusForbidden, rr.Code)
	}
}

func TestCallbackHandler_WrongState(t *testing.T) {
	srv := mockOAuthServer(t)
	defer srv.Close()

	config := testConfig(srv.URL+"/auth", srv.URL+"/token")

	parseTok := func(tok *oa2.Token) (jwt.MapClaims, error) {
		return nil, errors.New("should not be called")
	}

	req := callbackRequest("valid-code", testNonce, "some-other-nonce")
	rr := httptest.NewRecorder()
	cloudoa2.CallbackHandler(config, testSecret, time.Hour, "", parseTok).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected %d for a state which doesn't match the cookie, got %d", http.StatusForbidden, rr.Code)
	}
}

// GHSA-w7px-636p-4c44: a state carrying a redirect URI must not send the token there.
func TestCallbackHandler_AttackerControlledState(t *testing.T) {
	srv := mockOAuthServer(t)
	defer srv.Close()

	config := testConfig(srv.URL+"/auth", srv.URL+"/token")

	parseTok := func(tok *oa2.Token) (jwt.MapClaims, error) {
		return nil, errors.New("should not be called")
	}

	req := callbackRequest("valid-code", testNonce, "https://attacker.example/capture")
	rr := httptest.NewRecorder()
	cloudoa2.CallbackHandler(config, testSecret, time.Hour, "", parseTok).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected %d, got %d", http.StatusForbidden, rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "" {
		t.Errorf("expected no redirect, got %q", loc)
	}
	if body := rr.Body.String(); strings.Contains(body, "access_token") {
		t.Errorf("expected no token in the response, got %q", body)
	}
}

func TestCallbackHandler_ExchangeError(t *testing.T) {
	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer failSrv.Close()

	config := testConfig(failSrv.URL+"/auth", failSrv.URL+"/token")

	parseTok := func(tok *oa2.Token) (jwt.MapClaims, error) {
		return nil, errors.New("should not be called")
	}

	req := callbackRequest("bad-code", testNonce, testNonce)
	rr := httptest.NewRecorder()
	cloudoa2.CallbackHandler(config, testSecret, time.Hour, "", parseTok).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected %d on exchange error, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestCallbackHandler_ParseTokenError(t *testing.T) {
	srv := mockOAuthServer(t)
	defer srv.Close()

	config := testConfig(srv.URL+"/auth", srv.URL+"/token")

	parseTok := func(tok *oa2.Token) (jwt.MapClaims, error) {
		return nil, errors.New("invalid token")
	}

	req := callbackRequest("valid-code", testNonce, testNonce)
	rr := httptest.NewRecorder()
	cloudoa2.CallbackHandler(config, testSecret, time.Hour, "", parseTok).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected %d on parse error, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestCallbackHandler_WithRedirectURI(t *testing.T) {
	srv := mockOAuthServer(t)
	defer srv.Close()

	config := testConfig(srv.URL+"/auth", srv.URL+"/token")

	parseTok := func(tok *oa2.Token) (jwt.MapClaims, error) {
		return jwt.MapClaims{"sub": "user1"}, nil
	}

	const redirectURI = "https://app.example/dashboard?foo=bar"
	req := callbackRequest("valid-code", testNonce, testNonce)
	rr := httptest.NewRecorder()
	cloudoa2.CallbackHandler(config, testSecret, time.Hour, redirectURI, parseTok).ServeHTTP(rr, req)

	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected %d with redirect URI, got %d (body: %s)", http.StatusTemporaryRedirect, rr.Code, rr.Body.String())
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if loc.Scheme != "https" || loc.Host != "app.example" || loc.Path != "/dashboard" {
		t.Errorf("expected redirect to the dashboard, got %q", loc)
	}
	if loc.Query().Get("access_token") == "" {
		t.Errorf("expected access_token in redirect URL, got %q", loc)
	}
	if got := loc.Query().Get("foo"); got != "bar" {
		t.Errorf("expected existing query parameters to be kept, got %q", got)
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
