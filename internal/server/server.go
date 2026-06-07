package server

import (
	"time"

	firebaseauth "firebase.google.com/go/auth"
	"golang.org/x/time/rate"

	"my-kms/internal/storage"
)

// Server holds references to the MasterKeyStore, MongoUserStore, DEKStore, etc.
type Server struct {
	KeyStore       *storage.MasterKeyStore
	MongoUserStore *storage.MongoUserStore
	DEKStore       *storage.MongoDEKStore
	FirebaseAuth   *firebaseauth.Client
	RequestTimeout time.Duration
	MaxBodyBytes   int64
	RateLimiter    *rate.Limiter
}

// NewServer creates a new Server with the given dependencies.
func NewServer(
	ks *storage.MasterKeyStore,
	mus *storage.MongoUserStore,
	dekStore *storage.MongoDEKStore,
	fa *firebaseauth.Client,
	requestTimeout time.Duration,
	maxBodyBytes int64,
	rateLimitRequestsPerSecond float64,
	rateLimitBurst int,
) *Server {
	return &Server{
		KeyStore:       ks,
		MongoUserStore: mus,
		DEKStore:       dekStore,
		FirebaseAuth:   fa,
		RequestTimeout: requestTimeout,
		MaxBodyBytes:   maxBodyBytes,
		RateLimiter:    rate.NewLimiter(rate.Limit(rateLimitRequestsPerSecond), rateLimitBurst),
	}
}
