package basicauth_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudlena/adapters/basicauth"
)

func TestHandler(t *testing.T) {
	users := []basicauth.User{
		{Username: "user", Password: "password"},
	}
	realm := "My Realm"

	tests := []struct {
		name           string
		username       string
		password       string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "No credentials",
			username:       "",
			password:       "",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Unauthorized\n",
		},
		{
			name:           "Invalid credentials",
			username:       "wronguser",
			password:       "wrongpass",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Unauthorized\n",
		},
		{
			name:           "Valid credentials",
			username:       "user",
			password:       "password",
			expectedStatus: http.StatusOK,
			expectedBody:   "OK",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.username != "" || tt.password != "" {
				req.SetBasicAuth(tt.username, tt.password)
			}
			rr := httptest.NewRecorder()

			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err := fmt.Fprint(w, "OK")
				if err != nil {
					t.FailNow()
				}
			})

			handler := basicauth.Handler(realm, users)(nextHandler)
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
			if rr.Body.String() != tt.expectedBody {
				t.Errorf("Expected body %q, got %q", tt.expectedBody, rr.Body.String())
			}
		})
	}
}
