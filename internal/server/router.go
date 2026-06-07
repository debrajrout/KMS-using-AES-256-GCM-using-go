package server

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"my-kms/internal/auth"
)

type contextKey string

const (
	identityContextKey  contextKey = "identity"
	requestIDContextKey contextKey = "requestID"
)

// Routes sets up the HTTP endpoints.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/generate-data-key", requireMethod(http.MethodPost, http.HandlerFunc(s.GenerateDataKeyHandler)))
	mux.Handle("/encrypt", requireMethod(http.MethodPost, http.HandlerFunc(s.EncryptHandler)))
	mux.Handle("/decrypt", requireMethod(http.MethodPost, http.HandlerFunc(s.DecryptHandler)))
	mux.Handle("/rotate-master-key", requireMethod(http.MethodPost, http.HandlerFunc(s.RotateMasterKeyHandler)))
	mux.Handle("/delete-data-key", requireMethod(http.MethodDelete, http.HandlerFunc(s.DeleteDataKeyHandler)))

	return s.recoverMiddleware(
		s.requestIDMiddleware(
			s.timeoutMiddleware(
				s.rateLimitMiddleware(
					s.firebaseAuthMiddleware(mux),
				),
			),
		),
	)
}

// firebaseAuthMiddleware authenticates the Firebase JWT, retrieves role from MongoDB, sets identity in context.
func (s *Server) firebaseAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
		scheme, token, found := strings.Cut(authHeader, " ")
		if !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
			writeError(w, r, http.StatusUnauthorized, "invalid_authorization", "valid Bearer authorization is required")
			return
		}

		decodedToken, err := s.FirebaseAuth.VerifyIDToken(r.Context(), strings.TrimSpace(token))
		if err != nil {
			log.Printf("Failed to verify ID token: %v", err)
			writeError(w, r, http.StatusUnauthorized, "invalid_token", "invalid or expired token")
			return
		}

		firebaseUID := decodedToken.UID
		user, err := s.MongoUserStore.GetUserByFirebaseUID(r.Context(), firebaseUID)
		if err != nil {
			log.Printf("Failed to retrieve user from MongoDB: %v", err)
			writeError(w, r, http.StatusUnauthorized, "user_not_authorized", "user is not authorized")
			return
		}

		identity := auth.Identity{
			Name: firebaseUID,
			Role: auth.Role(user.Role),
		}

		ctx := context.WithValue(r.Context(), identityContextKey, identity)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.RateLimiter.Allow() {
			w.Header().Set("Retry-After", "1")
			writeError(w, r, http.StatusTooManyRequests, "rate_limit_exceeded", "request rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) timeoutMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), s.RequestTimeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if requestID == "" || len(requestID) > 128 {
			requestID = uuid.NewString()
		}
		w.Header().Set("X-Request-ID", requestID)
		ctx := context.WithValue(r.Context(), requestIDContextKey, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				log.Printf("panic recovered requestID=%s: %v", requestIDFromContext(r.Context()), recovered)
				writeError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func requireMethod(method string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		next.ServeHTTP(w, r)
	})
}
