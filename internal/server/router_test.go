package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestRequireMethod(t *testing.T) {
	called := false
	handler := requireMethod(http.MethodPost, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusMethodNotAllowed)
	}
	if recorder.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("Allow = %q, want %q", recorder.Header().Get("Allow"), http.MethodPost)
	}
	if called {
		t.Fatal("next handler was called")
	}
}

func TestRequestIDMiddleware(t *testing.T) {
	s := &Server{}
	handler := s.requestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestIDFromContext(r.Context()) == "" {
			t.Fatal("request ID missing from context")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	if recorder.Header().Get("X-Request-ID") == "" {
		t.Fatal("X-Request-ID response header is empty")
	}
}

func TestTimeoutMiddleware(t *testing.T) {
	s := &Server{RequestTimeout: time.Millisecond}
	handler := s.timeoutMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		if r.Context().Err() != context.DeadlineExceeded {
			t.Fatalf("context error = %v, want deadline exceeded", r.Context().Err())
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
}

func TestRateLimitMiddleware(t *testing.T) {
	s := &Server{RateLimiter: rate.NewLimiter(0.000001, 1)}
	handler := s.rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/", nil))
	if first.Code != http.StatusNoContent {
		t.Fatalf("first status = %d, want %d", first.Code, http.StatusNoContent)
	}

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/", nil))
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want %d", second.Code, http.StatusTooManyRequests)
	}
	if second.Header().Get("Retry-After") != "1" {
		t.Fatalf("Retry-After = %q, want 1", second.Header().Get("Retry-After"))
	}
}

func TestRecoverMiddleware(t *testing.T) {
	s := &Server{}
	handler := s.recoverMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("test panic")
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusInternalServerError)
	}
}

func TestDecodeJSONBody(t *testing.T) {
	type payload struct {
		Name string `json:"name"`
	}

	tests := []struct {
		name        string
		contentType string
		body        string
		maxBytes    int64
		wantErr     bool
	}{
		{name: "valid", contentType: "application/json", body: `{"name":"kms"}`, maxBytes: 100},
		{name: "valid charset", contentType: "application/json; charset=utf-8", body: `{"name":"kms"}`, maxBytes: 100},
		{name: "wrong content type", contentType: "text/plain", body: `{"name":"kms"}`, maxBytes: 100, wantErr: true},
		{name: "unknown field", contentType: "application/json", body: `{"name":"kms","extra":true}`, maxBytes: 100, wantErr: true},
		{name: "trailing value", contentType: "application/json", body: `{"name":"kms"} {}`, maxBytes: 100, wantErr: true},
		{name: "empty", contentType: "application/json", body: ``, maxBytes: 100, wantErr: true},
		{name: "too large", contentType: "application/json", body: `{"name":"kms"}`, maxBytes: 5, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{MaxBodyBytes: tt.maxBytes}
			request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tt.body))
			request.Header.Set("Content-Type", tt.contentType)
			var got payload

			err := s.decodeJSONBody(httptest.NewRecorder(), request, &got)
			if (err != nil) != tt.wantErr {
				t.Fatalf("decodeJSONBody() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWriteErrorIncludesRequestID(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request = request.WithContext(context.WithValue(request.Context(), requestIDContextKey, "request-123"))
	recorder := httptest.NewRecorder()

	writeError(recorder, request, http.StatusBadRequest, "invalid_request", "invalid request")

	var response errorResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.RequestID != "request-123" {
		t.Fatalf("requestID = %q, want request-123", response.RequestID)
	}
}
