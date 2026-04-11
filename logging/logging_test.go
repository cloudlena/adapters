package logging_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cloudlena/adapters/logging"
)

func TestHandler_LogsRequest(t *testing.T) {
	var buf bytes.Buffer
	var nextCalled bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	h := logging.Handler(&buf)(next)
	req := httptest.NewRequest(http.MethodGet, "/some/path", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !nextCalled {
		t.Error("expected next handler to be called")
	}
	out := buf.String()
	if !strings.Contains(out, http.MethodGet) {
		t.Errorf("expected log to contain method %q, got: %s", http.MethodGet, out)
	}
	if !strings.Contains(out, "/some/path") {
		t.Errorf("expected log to contain path, got: %s", out)
	}
}

func TestHandler_LogsPostRequest(t *testing.T) {
	var buf bytes.Buffer
	h := logging.Handler(&buf)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !strings.Contains(buf.String(), http.MethodPost) {
		t.Errorf("expected log to contain POST, got: %s", buf.String())
	}
}
