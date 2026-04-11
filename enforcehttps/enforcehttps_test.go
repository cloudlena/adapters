package enforcehttps_test

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudlena/adapters/enforcehttps"
)

func TestHandler_Disabled(t *testing.T) {
	var nextCalled bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})
	h := enforcehttps.Handler(false)(next)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !nextCalled {
		t.Error("expected next handler to be called when enforcement is disabled")
	}
}

func TestHandler_EnabledPlainHTTP(t *testing.T) {
	h := enforcehttps.Handler(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/path?q=1", nil)
	req.Host = "example.com"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusPermanentRedirect {
		t.Errorf("expected %d, got %d", http.StatusPermanentRedirect, rr.Code)
	}
	if got := rr.Header().Get("Location"); got != "https://example.com/path?q=1" {
		t.Errorf("expected redirect to https URL, got %q", got)
	}
}

func TestHandler_EnabledTLS(t *testing.T) {
	var nextCalled bool
	h := enforcehttps.Handler(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	}))

	req := httptest.NewRequest(http.MethodGet, "https://example.com/path", nil)
	req.TLS = &tls.ConnectionState{}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !nextCalled {
		t.Error("expected next handler to be called for TLS request")
	}
}

func TestHandler_EnabledForwardedProto(t *testing.T) {
	var nextCalled bool
	h := enforcehttps.Handler(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !nextCalled {
		t.Error("expected next handler to be called when X-Forwarded-Proto is https")
	}
}
