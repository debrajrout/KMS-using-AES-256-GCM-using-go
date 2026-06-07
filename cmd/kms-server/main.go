package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	firebase "firebase.google.com/go"
	"google.golang.org/api/option"

	"my-kms/internal/config"
	"my-kms/internal/server"
	"my-kms/internal/storage"
)

func main() {
	log.Println("KMS server is starting...")

	// 1. Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 2. Parse master keys
	configMasterKeys, err := cfg.ParseMasterKeys()
	if err != nil {
		log.Fatalf("Failed to parse master keys: %v", err)
	}

	// Convert config.MasterKey to storage.MasterKey
	storageMasterKeys := make([]storage.MasterKey, len(configMasterKeys))
	for i, mk := range configMasterKeys {
		storageMasterKeys[i] = storage.MasterKey{
			ID:  mk.ID,
			Key: mk.Key,
		}
	}

	// 3. Initialize MasterKeyStore
	masterKeyStore, err := storage.NewMasterKeyStore(storageMasterKeys)
	if err != nil {
		log.Fatalf("Failed to initialize MasterKeyStore: %v", err)
	}

	// 4. Initialize MongoDB user store
	userStoreCtx, cancelUserStore := context.WithTimeout(context.Background(), cfg.RequestTimeout)
	userStore, err := storage.NewMongoUserStore(userStoreCtx, cfg.MongoURI, cfg.MongoDBName, cfg.MongoUsersCollection)
	cancelUserStore()
	if err != nil {
		log.Fatalf("Failed to create MongoUserStore: %v", err)
	}

	// 5. Initialize MongoDB DEK store
	dekStoreCtx, cancelDEKStore := context.WithTimeout(context.Background(), cfg.RequestTimeout)
	dekStore, err := storage.NewMongoDEKStore(dekStoreCtx, cfg.MongoURI, cfg.MongoDBName, cfg.MongoDEKCollection)
	cancelDEKStore()
	if err != nil {
		log.Fatalf("Failed to create MongoDEKStore: %v", err)
	}

	// 6. Initialize Firebase
	opt := option.WithCredentialsFile(cfg.FirebaseServiceAccountPath)
	firebaseCtx, cancelFirebase := context.WithTimeout(context.Background(), cfg.RequestTimeout)
	app, err := firebase.NewApp(firebaseCtx, nil, opt)
	if err != nil {
		cancelFirebase()
		log.Fatalf("Failed to initialize Firebase App: %v", err)
	}
	firebaseAuth, err := app.Auth(firebaseCtx)
	cancelFirebase()
	if err != nil {
		log.Fatalf("Failed to get Firebase Auth client: %v", err)
	}

	// 7. Create the KMS server
	kmsServer := server.NewServer(
		masterKeyStore,
		userStore,
		dekStore,
		firebaseAuth,
		cfg.RequestTimeout,
		cfg.MaxRequestBodyBytes,
		cfg.RateLimitRequestsPerSecond,
		cfg.RateLimitBurst,
	)

	// 8. Setup routes
	router := kmsServer.Routes()

	// 9. Start HTTPS server with graceful shutdown
	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: cfg.HTTPReadHeaderTimeout,
		ReadTimeout:       cfg.HTTPReadTimeout,
		WriteTimeout:      cfg.HTTPWriteTimeout,
		IdleTimeout:       cfg.HTTPIdleTimeout,
		MaxHeaderBytes:    cfg.HTTPMaxHeaderBytes,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
	}

	go func() {
		log.Printf("KMS server listening on %s", cfg.HTTPAddr)
		if err := httpServer.ListenAndServeTLS(cfg.TLSCertPath, cfg.TLSKeyPath); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Handle graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), cfg.HTTPShutdownTimeout)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	closeUserStoreCtx, cancelCloseUserStore := context.WithTimeout(context.Background(), cfg.HTTPShutdownTimeout)
	if err := userStore.Close(closeUserStoreCtx); err != nil {
		log.Printf("Failed to close MongoUserStore: %v", err)
	}
	cancelCloseUserStore()

	closeDEKStoreCtx, cancelCloseDEKStore := context.WithTimeout(context.Background(), cfg.HTTPShutdownTimeout)
	if err := dekStore.Close(closeDEKStoreCtx); err != nil {
		log.Printf("Failed to close MongoDEKStore: %v", err)
	}
	cancelCloseDEKStore()

	log.Println("Server gracefully stopped.")
}
