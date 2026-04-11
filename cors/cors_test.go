package cors_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudlena/adapters/cors"
)

func okHandler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestHandler_NoOrigin(t *testing.T) {
	h := cors.Handler(cors.Options{})(okHandler(t))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("expected no CORS headers when no Origin is set")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestHandler_WithOrigin(t *testing.T) {
	h := cors.Handler(cors.Options{})(okHandler(t))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://example.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Error("expected Access-Control-Allow-Origin header")
	}
	if rr.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("expected Access-Control-Allow-Methods header")
	}
	if rr.Header().Get("Access-Control-Allow-Headers") == "" {
		t.Error("expected Access-Control-Allow-Headers header")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestHandler_OptionsRequest(t *testing.T) {
	var nextCalled bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})
	h := cors.Handler(cors.Options{})(next)

	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://example.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if nextCalled {
		t.Error("expected next handler not to be called for OPTIONS request")
	}
}

func TestHandler_CustomOptions(t *testing.T) {
	opts := cors.Options{
		Origins:     []string{"https://example.com"},
		Methods:     []string{http.MethodGet},
		Headers:     []string{"X-Custom-Header"},
		Credentials: true,
	}
	h := cors.Handler(opts)(okHandler(t))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://example.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://example.com" {
		t.Errorf("expected origin %q, got %q", "https://example.com", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Methods"); got != "GET" {
		t.Errorf("expected methods %q, got %q", "GET", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Headers"); got != "X-Custom-Header" {
		t.Errorf("expected headers %q, got %q", "X-Custom-Header", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("expected credentials %q, got %q", "true", got)
	}
}

func TestHandler_EmptyHeaders_UsesRequestHeaders(t *testing.T) {
	opts := cors.Options{
		Headers: []string{},
	}
	h := cors.Handler(opts)(okHandler(t))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Headers", "X-Requested-With")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Headers"); got != "X-Requested-With" {
		t.Errorf("expected reflected request headers, got %q", got)
	}
}
