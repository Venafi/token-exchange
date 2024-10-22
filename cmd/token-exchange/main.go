package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"token-exchange/fingerprint"
	"token-exchange/logging"
	"token-exchange/tokenserver"
)

const (
	tokenEndpoint    = "token.tim-ramlot-gcp.jetstacker.net"
	discoverEndpoint = "discover.tim-ramlot-gcp.jetstacker.net"
)

var secretKey = []byte{
	0x85, 0x04, 0xe2, 0xab, 0xd7, 0x62, 0x2a, 0x81,
	0x44, 0x4b, 0xf4, 0x90, 0xa5, 0x56, 0xea, 0x4d,
	0x7b, 0xce, 0xb0, 0xad, 0x78, 0xa9, 0xb6, 0x7f,
	0x22, 0xd9, 0x80, 0x34, 0x83, 0x43, 0x9d, 0x53,
}

var issuerURL = "https://" + discoverEndpoint

func run(ctx context.Context, logger *slog.Logger) error {
	var tlsChainLocation string
	var tlsPrivateKeyLocation string
	var trustBundleLocation string

	flag.StringVar(&tlsChainLocation, "tls-chain-location", "", "Required: filesystem location of TLS cert")
	flag.StringVar(&tlsPrivateKeyLocation, "tls-private-key-location", "", "Required: filesystem location of TLS private key")

	flag.StringVar(&trustBundleLocation, "trust-bundle-location", "", "Required: filesystem location of TLS trust bundle for client certs")

	flag.Parse()

	if tlsChainLocation == "" {
		return fmt.Errorf("missing required flag: tls-chain-location")
	}

	if tlsPrivateKeyLocation == "" {
		return fmt.Errorf("missing required flag: tls-private-key-location")
	}

	if trustBundleLocation == "" {
		return fmt.Errorf("missing required flag: trust-bundle-location")
	}

	cert, err := tls.LoadX509KeyPair(tlsChainLocation, tlsPrivateKeyLocation)
	if err != nil {
		return fmt.Errorf("failed to load cert %s / key %s: %s", tlsChainLocation, tlsPrivateKeyLocation, err)
	}

	rawBundle, err := os.ReadFile(trustBundleLocation)
	if err != nil {
		return fmt.Errorf("failed to read trust bundle from %q: %s", trustBundleLocation, err)
	}

	trustedCertsParsed, err := decodePEM(rawBundle)
	if err != nil {
		return err
	}

	trustPool := x509.NewCertPool()
	rootMap := make(fingerprint.RootMap)

	for _, cert := range trustedCertsParsed {
		trustPool.AddCert(cert)

		fprint := fingerprint.For(cert)

		sk, err := fingerprint.SigningKey(fprint, secretKey)
		if err != nil {
			return err
		}

		rootMap[fprint] = sk
	}

	tokenServerCfg := &tokenserver.Config{
		Address: "0.0.0.0:9966",

		Certificate: cert,

		TrustPool: trustPool,

		RootMap: rootMap,
	}

	tokenServer, err := tokenserver.Create(ctx, tokenServerCfg)

	go func() {
		err := tokenServer.ListenAndServeTLS("", "")

		if err != http.ErrServerClosed {
			logger.Error("token server error", "err", err)
		}
	}()

	// TODO: wellknown

	logger.Info("token server listening", "addr", tokenServerCfg.Address)

	//fmt.Printf("Server listening on %s/.well-known\n", addr)

	<-ctx.Done()

	logger.Info("shutting down server")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := tokenServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("failed to shut down token server: %s", err)
	}

	return nil
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	ctx := logging.ContextWithLogger(context.Background(), logger)

	runCtx, stop := signal.NotifyContext(ctx, os.Interrupt, os.Kill)
	defer stop()

	err := run(runCtx, logger)
	if err != nil {
		logger.Error("fatal error", "err", err)
		os.Exit(1)
	}
}

/*
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

	var clientCertChain []*x509.Certificate

	if len(r.TLS.VerifiedChains) > 0 {
		// TODO: maybe handle other chains
		clientCertChain = r.TLS.VerifiedChains[0]
	} else {
		extraCertificatesRaw := r.Form.Get("subject_token")

		extraCertificates, err := x509.ParseCertificates([]byte(extraCertificatesRaw))
		if err != nil {
			return NewHttpErrorMessage(http.StatusBadRequest, fmt.Errorf("failed to parse certificate chain: %w", err))
		}

		if len(r.TLS.PeerCertificates) == 0 {
			return NewHttpErrorMessage(http.StatusBadRequest, fmt.Errorf("no certificates provided"))
		}

		clientCertChain, err = buildChain(
			append(slices.Clone(r.TLS.PeerCertificates), extraCertificates...),
		)
		if err != nil {
			return NewHttpErrorMessage(http.StatusBadRequest, fmt.Errorf("failed to build certificate chain: %w", err))
		}

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
*/

// decodePEM will decode a concatenated set of PEM encoded x509 Certificates.
// Taken from cert-manager pki.DecodeX509CertificateSetBytes
func decodePEM(pemBytes []byte) ([]*x509.Certificate, error) {
	certs := []*x509.Certificate{}

	var block *pem.Block

	for {
		// decode certificate PEM
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			break
		}

		// parse the certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing TLS certificate: %s", err)
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("error decoding certificate PEM block")
	}

	return certs, nil
}
