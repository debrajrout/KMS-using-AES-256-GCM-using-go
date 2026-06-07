package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"

	"my-kms/internal/auth"
	"my-kms/internal/crypto"
)

// ---------------------------------------------------------------------
// Generate Data Key
// ---------------------------------------------------------------------

type GenerateDataKeyResponse struct {
	DEKID       string `json:"dekID"`
	MasterKeyID string `json:"masterKeyID"`
}

func (s *Server) GenerateDataKeyHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[AUDIT] /generate-data-key called by %s", r.RemoteAddr)

	identity, err := getIdentity(r)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	if err := auth.IsAuthorized(identity, auth.ActionGenerateDataKey); err != nil {
		log.Printf("Unauthorized attempt by role=%s to generate data key", identity.Role)
		writeError(w, r, http.StatusForbidden, "forbidden", "action not authorized")
		return
	}

	// Generate new DEK
	dek, err := crypto.GenerateKey()
	if err != nil {
		log.Printf("Failed to generate DEK: %v", err)
		writeError(w, r, http.StatusInternalServerError, "key_generation_failed", "failed to generate data key")
		return
	}

	// Encrypt (wrap) DEK using master key
	encryptedDEK, masterKeyID, err := s.KeyStore.EncryptDataKey(dek)
	if err != nil {
		log.Printf("Failed to encrypt DEK: %v", err)
		writeError(w, r, http.StatusInternalServerError, "key_wrapping_failed", "failed to wrap data key")
		return
	}

	// Store in Mongo
	dekID, err := s.DEKStore.InsertDEK(r.Context(), encryptedDEK, masterKeyID)
	if err != nil {
		log.Printf("Failed to store DEK in MongoDB: %v", err)
		writeError(w, r, http.StatusInternalServerError, "storage_error", "failed to store data key")
		return
	}

	resp := GenerateDataKeyResponse{
		DEKID:       dekID,
		MasterKeyID: masterKeyID,
	}
	writeJSON(w, resp)
}

// ---------------------------------------------------------------------
// Encrypt JSON
// ---------------------------------------------------------------------

type EncryptRequest struct {
	DEKID    string          `json:"dekID"`
	JSONData json.RawMessage `json:"jsonData"` // raw JSON to encrypt
}

type EncryptResponse struct {
	Ciphertext string `json:"ciphertext"` // base64-encoded
}

func (s *Server) EncryptHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[AUDIT] /encrypt called by %s", r.RemoteAddr)

	identity, err := getIdentity(r)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	if err := auth.IsAuthorized(identity, auth.ActionEncrypt); err != nil {
		log.Printf("Unauthorized attempt by role=%s to encrypt data", identity.Role)
		writeError(w, r, http.StatusForbidden, "forbidden", "action not authorized")
		return
	}

	var req EncryptRequest
	if err := s.decodeJSONBody(w, r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if req.DEKID == "" || len(req.JSONData) == 0 {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "dekID and jsonData are required")
		return
	}

	// Retrieve DEK from Mongo
	dekDoc, err := s.DEKStore.GetDEK(r.Context(), req.DEKID)
	if err != nil {
		log.Printf("Failed to get DEK: %v", err)
		writeError(w, r, http.StatusNotFound, "data_key_not_found", "data key not found")
		return
	}

	// Unwrap the DEK
	dek, err := s.KeyStore.DecryptDataKey(dekDoc.DEK, dekDoc.MasterKeyID)
	if err != nil {
		log.Printf("Failed to decrypt DEK: %v", err)
		writeError(w, r, http.StatusInternalServerError, "key_unwrap_failed", "failed to unwrap data key")
		return
	}

	// Encrypt the raw JSON
	ciphertextBytes, err := crypto.EncryptAES256GCM(dek, req.JSONData)
	if err != nil {
		log.Printf("Failed to encrypt JSON: %v", err)
		writeError(w, r, http.StatusInternalServerError, "encryption_failed", "encryption failed")
		return
	}

	resp := EncryptResponse{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertextBytes),
	}
	writeJSON(w, resp)
}

// ---------------------------------------------------------------------
// Decrypt JSON
// ---------------------------------------------------------------------

type DecryptRequest struct {
	DEKID      string `json:"dekID"`
	Ciphertext string `json:"ciphertext"` // base64
}

type DecryptResponse struct {
	JSONData json.RawMessage `json:"jsonData"`
}

func (s *Server) DecryptHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[AUDIT] /decrypt called by %s", r.RemoteAddr)

	identity, err := getIdentity(r)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	if err := auth.IsAuthorized(identity, auth.ActionDecrypt); err != nil {
		log.Printf("Unauthorized attempt by role=%s to decrypt data", identity.Role)
		writeError(w, r, http.StatusForbidden, "forbidden", "action not authorized")
		return
	}

	var req DecryptRequest
	if err := s.decodeJSONBody(w, r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if req.DEKID == "" || req.Ciphertext == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "dekID and ciphertext are required")
		return
	}

	dekDoc, err := s.DEKStore.GetDEK(r.Context(), req.DEKID)
	if err != nil {
		log.Printf("Failed to get DEK: %v", err)
		writeError(w, r, http.StatusNotFound, "data_key_not_found", "data key not found")
		return
	}

	// Unwrap the DEK
	dek, err := s.KeyStore.DecryptDataKey(dekDoc.DEK, dekDoc.MasterKeyID)
	if err != nil {
		log.Printf("Failed to decrypt DEK: %v", err)
		writeError(w, r, http.StatusInternalServerError, "key_unwrap_failed", "failed to unwrap data key")
		return
	}

	// Decode ciphertext
	ciphertextBytes, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_ciphertext", "ciphertext must be valid base64")
		return
	}

	// Decrypt
	plaintextBytes, err := crypto.DecryptAES256GCM(dek, ciphertextBytes)
	if err != nil {
		log.Printf("Failed to decrypt data: %v", err)
		writeError(w, r, http.StatusBadRequest, "decryption_failed", "decryption failed")
		return
	}

	resp := DecryptResponse{
		JSONData: plaintextBytes,
	}
	writeJSON(w, resp)
}

// ---------------------------------------------------------------------
// Rotate Master Key
// ---------------------------------------------------------------------

type RotateKeyResponse struct {
	NewMasterKeyID string `json:"newMasterKeyID"`
}

func (s *Server) RotateMasterKeyHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[AUDIT] /rotate-master-key called by %s", r.RemoteAddr)

	identity, err := getIdentity(r)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	if err := auth.IsAuthorized(identity, auth.ActionRotateMasterKey); err != nil {
		log.Printf("Unauthorized attempt by role=%s to rotate master key", identity.Role)
		writeError(w, r, http.StatusForbidden, "forbidden", "action not authorized")
		return
	}

	newKey, err := s.KeyStore.RotateMasterKey()
	if err != nil {
		log.Printf("Failed to rotate master key: %v", err)
		writeError(w, r, http.StatusInternalServerError, "master_key_rotation_failed", "master key rotation failed")
		return
	}

	resp := RotateKeyResponse{NewMasterKeyID: newKey.ID}
	writeJSON(w, resp)
}

// ---------------------------------------------------------------------
// Delete Data Key
// ---------------------------------------------------------------------

type DeleteDEKRequest struct {
	DEKID string `json:"dekID"`
}

func (s *Server) DeleteDataKeyHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[AUDIT] /delete-data-key called by %s", r.RemoteAddr)

	identity, err := getIdentity(r)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	// If you want to restrict deletion to Admins or a special action, define a new action or reuse an existing one:
	// For example, re-use ActionRotateMasterKey or define ActionDeleteDataKey
	if err := auth.IsAuthorized(identity, auth.ActionRotateMasterKey); err != nil {
		log.Printf("Unauthorized attempt by role=%s to delete DEK", identity.Role)
		writeError(w, r, http.StatusForbidden, "forbidden", "action not authorized")
		return
	}

	var req DeleteDEKRequest
	if err := s.decodeJSONBody(w, r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if req.DEKID == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "dekID is required")
		return
	}

	if err := s.DEKStore.DeleteDEK(r.Context(), req.DEKID); err != nil {
		log.Printf("Failed to delete DEK: %v", err)
		writeError(w, r, http.StatusInternalServerError, "data_key_deletion_failed", "failed to delete data key")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------

func getIdentity(r *http.Request) (auth.Identity, error) {
	ctxVal := r.Context().Value(identityContextKey)
	id, ok := ctxVal.(auth.Identity)
	if !ok {
		return auth.Identity{}, ErrNoIdentity
	}
	return id, nil
}

var ErrNoIdentity = &jsonError{"could not read identity"}

type jsonError struct {
	Message string `json:"message"`
}

func (e *jsonError) Error() string {
	return e.Message
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("writeJSON error: %v", err)
	}
}

type errorResponse struct {
	Error     string `json:"error"`
	Message   string `json:"message"`
	RequestID string `json:"requestID,omitempty"`
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(errorResponse{
		Error:     code,
		Message:   message,
		RequestID: requestIDFromContext(r.Context()),
	}); err != nil {
		log.Printf("writeError error: %v", err)
	}
}

func requestIDFromContext(ctx context.Context) string {
	requestID, _ := ctx.Value(requestIDContextKey).(string)
	return requestID
}

func (s *Server) decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) error {
	contentType := r.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" {
		return errors.New("Content-Type must be application/json")
	}

	r.Body = http.MaxBytesReader(w, r.Body, s.MaxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return fmt.Errorf("request body must not exceed %d bytes", s.MaxBodyBytes)
		}
		if errors.Is(err, io.EOF) {
			return errors.New("request body must not be empty")
		}
		return errors.New("request body must contain valid JSON with known fields only")
	}

	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain a single JSON object")
	}
	return nil
}
