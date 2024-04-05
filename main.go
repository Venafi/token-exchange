package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"time"

	"filippo.io/keygen"
	jose "github.com/go-jose/go-jose/v4"
	jwtgen "github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/acme/autocert"
)

const (
	tokenEndpoint    = "token.tim-ramlot-gcp.jetstacker.net"
	discoverEndpoint = "discover.tim-ramlot-gcp.jetstacker.net"
)

var secretKeyID = "key1"
var secretKey = []byte{
	0x85, 0x04, 0xe2, 0xab, 0xd7, 0x62, 0x2a, 0x81,
	0x44, 0x4b, 0xf4, 0x90, 0xa5, 0x56, 0xea, 0x4d,
	0x7b, 0xce, 0xb0, 0xad, 0x78, 0xa9, 0xb6, 0x7f,
	0x22, 0xd9, 0x80, 0x34, 0x83, 0x43, 0x9d, 0x53,
}
var issuerURL = "https://" + discoverEndpoint

func main() {
	addr := "0.0.0.0:443"

	runCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer stop()

	m := &autocert.Manager{
		Cache:      autocert.DirCache("secret-dir"),
		Prompt:     autocert.AcceptTOS,
		Email:      "tim.ramlot@venafi.com",
		HostPolicy: autocert.HostWhitelist(tokenEndpoint, discoverEndpoint),
	}

	tokenTLS := m.TLSConfig()
	tokenTLS.ClientAuth = tls.RequireAnyClientCert
	tokenTLS.MinVersion = tls.VersionTLS12

	discoverTLS := m.TLSConfig()
	discoverTLS.MinVersion = tls.VersionTLS12

	rootTLS := m.TLSConfig()
	rootTLS.MinVersion = tls.VersionTLS12
	rootTLS.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		if strings.HasPrefix(chi.ServerName, "token") {
			return tokenTLS, nil
		}

		return discoverTLS, nil
	}

	tokenSrv := &http.Server{
		BaseContext: func(_ net.Listener) context.Context { return runCtx },

		Addr:           addr,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 10 * 1024,

		TLSConfig: rootTLS,

		Handler: http.HandlerFunc(jsonResponseHandlerWrappper(handleRequestRoot)),
	}
	tokenSrv.SetKeepAlivesEnabled(false)

	go func() {
		if err := tokenSrv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			panic(err)
		}
	}()

	fmt.Printf("Server listening on %s/token\n", addr)
	fmt.Printf("Server listening on %s/.well-known\n", addr)

	<-runCtx.Done()

	fmt.Println("Shutting down server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tokenSrv.Shutdown(shutdownCtx); err != nil {
		panic(err)
	}
	if err := tokenSrv.Shutdown(shutdownCtx); err != nil {
		panic(err)
	}
}

type httpError struct {
	HttpCode int    `json:"http_code"`
	Message  string `json:"message"`
}

func NewHttpError(code int) *httpError {
	return &httpError{
		HttpCode: code,
	}
}

func NewHttpErrorMessage(code int, message error) *httpError {
	return &httpError{
		HttpCode: code,
		Message:  message.Error(),
	}
}

func jsonResponseHandlerWrappper(handler func(http.ResponseWriter, *http.Request) *httpError) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := handler(w, r); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(err.HttpCode)

			if err.Message != "" {
				if err := json.NewEncoder(w).Encode(err); err != nil {
					http.Error(w, "failed to encode error message", http.StatusInternalServerError)
				}
			}
		}
	}
}

type tokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	ExpiresIn       int    `json:"expires_in"`
}

func handleRequestRoot(w http.ResponseWriter, r *http.Request) *httpError {
	path := strings.TrimPrefix(r.URL.Path, "/")

	if path == "token" {
		return handleTokenRequest(w, r)
	}

	// Extract the root certificate ID from the path
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 || len(parts[0]) != 64 {
		return NewHttpError(http.StatusNotFound)
	}

	rootIDRaw, err := hex.DecodeString(parts[0])
	if err != nil {
		return NewHttpError(http.StatusNotFound)
	}

	rootID := rootIdentifier(rootIDRaw)

	if parts[1] == ".well-known/openid-configuration" {
		return rootID.handleOIDCDiscovery(w, r)
	}

	if parts[1] == ".well-known/jwks" {
		return rootID.handleJWKS(w, r)
	}

	return NewHttpError(http.StatusNotFound)
}

func handleTokenRequest(w http.ResponseWriter, r *http.Request) *httpError {
	if r.Method != http.MethodPost {
		return NewHttpError(http.StatusMethodNotAllowed)
	}

	w.Header().Set("Content-Type", "application/json")

	// Decode the form data
	if err := r.ParseForm(); err != nil {
		return NewHttpErrorMessage(http.StatusBadRequest, fmt.Errorf("failed to parse form: %w", err))
	}

	// Check the form data
	if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" {
		return NewHttpErrorMessage(http.StatusBadRequest, fmt.Errorf("invalid grant type: %s", r.Form.Get("grant_type")))
	}

	if r.Form.Get("subject_token_type") != "urn:ietf:params:oauth:token-type:tls-client-auth" {
		return NewHttpErrorMessage(http.StatusBadRequest, fmt.Errorf("invalid subject token type: %s", r.Form.Get("subject_token_type")))
	}

	extraCertificatesRaw := r.Form.Get("subject_token")

	extraCertificates, err := x509.ParseCertificates([]byte(extraCertificatesRaw))
	if err != nil {
		return NewHttpErrorMessage(http.StatusBadRequest, fmt.Errorf("failed to parse certificate chain: %w", err))
	}

	if len(r.TLS.PeerCertificates) == 0 {
		return NewHttpErrorMessage(http.StatusBadRequest, fmt.Errorf("no certificates provided"))
	}

	clientCertChain, err := buildChain(
		append(slices.Clone(r.TLS.PeerCertificates), extraCertificates...),
	)
	if err != nil {
		return NewHttpErrorMessage(http.StatusBadRequest, fmt.Errorf("failed to build certificate chain: %w", err))
	}

	rootId, err := getUniqueRootId(clientCertChain)
	if err != nil {
		return NewHttpErrorMessage(http.StatusInternalServerError, fmt.Errorf("failed to get unique root id: %w", err))
	}

	key, kid, err := generatePrivateKey(rootId)
	if err != nil {
		return NewHttpErrorMessage(http.StatusInternalServerError, fmt.Errorf("failed to generate private key: %w", err))
	}

	audience := r.Form.Get("audience")
	issuedAt := time.Now()
	expiresAt := issuedAt.Add(1 * time.Hour)
	subject := clientCertChain[0].Subject.CommonName

	var claims = &jwtgen.RegisteredClaims{
		Issuer:    issuerURL + "/" + hex.EncodeToString(rootId),
		Subject:   subject,
		Audience:  []string{audience},
		IssuedAt:  jwtgen.NewNumericDate(issuedAt),
		ExpiresAt: jwtgen.NewNumericDate(expiresAt),
	}

	token := jwtgen.NewWithClaims(jwtgen.SigningMethodES256, claims)
	token.Header["kid"] = kid

	jwt, err := token.SignedString(key)
	if err != nil {
		return NewHttpErrorMessage(http.StatusInternalServerError, fmt.Errorf("failed to sign token: %w", err))
	}

	// Send the response
	if err := json.NewEncoder(w).Encode(tokenResponse{
		AccessToken:     jwt,
		IssuedTokenType: "urn:ietf:params:oauth:token-type:jwt",
		ExpiresIn:       int(expiresAt.Sub(issuedAt).Seconds()),
	}); err != nil {
		return NewHttpErrorMessage(http.StatusInternalServerError, fmt.Errorf("failed to encode response: %w", err))
	}

	return nil
}

type rootIdentifier []byte

func (ri rootIdentifier) handleOIDCDiscovery(w http.ResponseWriter, r *http.Request) *httpError {
	if r.Method != http.MethodGet {
		return NewHttpError(http.StatusMethodNotAllowed)
	}

	w.Header().Set("Content-Type", "application/json")

	jwksHost := r.Host

	response := map[string]interface{}{
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"issuer":                                issuerURL + "/" + hex.EncodeToString(ri),
		"jwks_uri":                              "https://" + jwksHost + "/" + hex.EncodeToString(ri) + "/.well-known/jwks",
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		return NewHttpErrorMessage(http.StatusInternalServerError, fmt.Errorf("failed to encode response: %w", err))
	}

	return nil
}

func (ri rootIdentifier) handleJWKS(w http.ResponseWriter, r *http.Request) *httpError {
	if r.Method != http.MethodGet {
		return NewHttpError(http.StatusMethodNotAllowed)
	}

	w.Header().Set("Content-Type", "application/json")

	var publicKey crypto.PublicKey
	var kid string
	{
		var pk *ecdsa.PrivateKey
		var err error
		pk, kid, err = generatePrivateKey(ri)
		if err != nil {
			return NewHttpError(http.StatusInternalServerError)
		}
		publicKey = pk.Public()
	}

	response := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Algorithm: string(jose.ES256),
				Key:       publicKey,
				KeyID:     kid,
				Use:       "sig",
			},
		},
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		return NewHttpError(http.StatusInternalServerError)
	}

	return nil
}

func buildChain(certs []*x509.Certificate) ([]*x509.Certificate, error) {
	for _, cert := range certs {
		if cert == nil {
			return nil, fmt.Errorf("certificate chain contains nil certificate")
		}

		if len(cert.Raw) == 0 {
			return nil, fmt.Errorf("certificate chain contains certificate without Raw set")
		}
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates provided")
	}

	if len(certs) > 10 {
		return nil, fmt.Errorf("client provided too many certificates (max 10)")
	}

	leafCertificate := certs[0]
	remainingCandidates := slices.Clone(certs[1:])

	chain := make([]*x509.Certificate, 0, len(certs))
	chain = append(chain, leafCertificate)

	for {
		foundCandidate := false

		for i, candiate := range remainingCandidates {
			if candiate == nil {
				continue
			}

			if isPossibleParent(chain[len(chain)-1], candiate) {
				chain = append(chain, candiate)
				remainingCandidates[i] = nil
				foundCandidate = true
			}
		}

		if !foundCandidate {
			break
		}
	}

	rootCertificate := chain[len(chain)-1]
	if !bytes.Equal(rootCertificate.RawIssuer, rootCertificate.RawSubject) {
		return nil, fmt.Errorf("failed to find chain ending in a self-signed root certificate")
	}
	if rootCertificate.CheckSignatureFrom(rootCertificate) != nil {
		return nil, fmt.Errorf("root certificate signature is invalid")
	}

	opts := x509.VerifyOptions{
		Roots:         x509.NewCertPool(),
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	opts.Roots.AddCert(rootCertificate)
	for _, cert := range chain[1:] {
		opts.Intermediates.AddCert(cert)
	}

	if _, err := chain[0].Verify(opts); err != nil {
		return nil, fmt.Errorf("failed to verify certificate chain: %w", err)
	}

	return chain, nil
}

func isPossibleParent(child, maybeParent *x509.Certificate) bool {
	if !bytes.Equal(child.RawIssuer, maybeParent.RawSubject) {
		return false
	}

	return child.CheckSignatureFrom(maybeParent) == nil
}

// getUniqueRootId finds the root certificate in the chain and
// returns a unique identifier based on it's raw value.
//
// Normally, since we checked that the client provided all
// certificates in the chain, this signature should be shared
// between all x509 certificates in the certificate tree.
func getUniqueRootId(chain []*x509.Certificate) ([]byte, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("no certificates provided")
	}

	// Find the root-most certificate in the chain
	rootCertificate := chain[len(chain)-1]

	hash := crypto.SHA256.New()
	if _, err := hash.Write(rootCertificate.Raw); err != nil {
		return nil, fmt.Errorf("failed to write root certificate: %w", err)
	}

	return hash.Sum(nil), nil
}

func generatePrivateKey(rootId []byte) (*ecdsa.PrivateKey, string, error) {
	hash := crypto.SHA256.New()
	if _, err := hash.Write(rootId); err != nil {
		return nil, "", fmt.Errorf("failed to write rootId: %w", err)
	}
	if _, err := hash.Write(secretKey); err != nil {
		return nil, "", fmt.Errorf("FAILED TO WRITE PRIVATE KEY")
	}

	pk, err := keygen.ECDSA(elliptic.P256(), hash.Sum(nil))
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate private key: %w", err)
	}

	return pk, secretKeyID, nil
}
