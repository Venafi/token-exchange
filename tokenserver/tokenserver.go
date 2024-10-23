package tokenserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	jwtgen "github.com/golang-jwt/jwt/v5"

	"token-exchange/fingerprint"
	"token-exchange/srvtool"
)

type Config struct {
	Address string

	Certificate tls.Certificate

	TrustPool *x509.CertPool

	RootMap fingerprint.RootMap

	DiscoveryEndpoint string
}

func Create(ctx context.Context, config *Config) (*http.Server, error) {
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{config.Certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    config.TrustPool,
		MinVersion:   tls.VersionTLS12,
	}

	tokenSrv := &http.Server{
		BaseContext: func(_ net.Listener) context.Context { return ctx },

		Addr:           config.Address,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 10 * 1024,

		ErrorLog: slog.NewLogLogger(logr.FromContextAsSlogLogger(ctx).Handler(), slog.LevelError),

		TLSConfig: tlsCfg,

		Handler: newServer(config.RootMap, config.DiscoveryEndpoint),
	}

	tokenSrv.SetKeepAlivesEnabled(false)

	return tokenSrv, nil
}

func newServer(roots fingerprint.RootMap, discoverEndpoint string) *tokenServer {
	mux := http.NewServeMux()

	srv := &tokenServer{
		roots: roots,

		issuerURL: "https://" + discoverEndpoint,

		mux: mux,
	}

	mux.HandleFunc("POST /token", srvtool.JSONHandler(srv.handleTokenRequest))
	mux.HandleFunc("GET /status", srvtool.JSONHandler(srv.handleStatusRequest))

	return srv
}

type tokenServer struct {
	roots fingerprint.RootMap

	issuerURL string

	mux *http.ServeMux
}

func (ts *tokenServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	srvtool.ServeHTTPWithLogs(ts.mux, w, r)
}

type statusMsg struct {
	Status string `json:"status"`
}

func (ts *tokenServer) handleStatusRequest(r *http.Request) srvtool.Response {
	return srvtool.Ok(statusMsg{
		Status: "OK",
	})
}

type tokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	ExpiresIn       int    `json:"expires_in"`
}

func (ts *tokenServer) handleTokenRequest(r *http.Request) srvtool.Response {
	logger := logr.FromContextAsSlogLogger(r.Context())

	if len(r.TLS.VerifiedChains) == 0 {
		// this means that the token server wasn't configured to require TLS
		logger.Error("got no verified chains on a call to handleTokenRequest")
		return srvtool.Error(http.StatusInternalServerError, "invalid configuration on server")
	}

	// Decode the form data
	if err := r.ParseForm(); err != nil {
		return srvtool.Errorf(http.StatusBadRequest, "failed to parse form input: %s", err)
	}

	// Check the form data
	if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" {
		return srvtool.Errorf(http.StatusBadRequest, "invalid grant_type in form: %s", r.Form.Get("grant_type"))
	}

	if r.Form.Get("subject_token_type") != "urn:ietf:params:oauth:token-type:tls-client-auth" {
		return srvtool.Errorf(http.StatusBadRequest, "invalid subject_token_type in form: %s", r.Form.Get("subject_token_type"))
	}

	clientCertChain := r.TLS.VerifiedChains[0]

	fprint, err := fingerprint.Rootmost(clientCertChain)
	if err != nil {
		logger.Error("failed to get unique root ID from chain", "err", err)
		return srvtool.Error(http.StatusInternalServerError, "failed to get unique root ID from provided chain")
	}

	key, ok := ts.roots[fprint]
	if !ok {
		logger.Error("failed to get private key corresponding to root", "err", err, "fingerprint", fprint)
		return srvtool.Error(http.StatusInternalServerError, "failed to retrieve private key corresponding to received root")
	}

	// TODO: handle empty aud / subject?
	audience := r.Form.Get("audience")
	issuedAt := time.Now()
	expiresAt := issuedAt.Add(1 * time.Hour)
	subject := clientCertChain[0].Subject.CommonName

	claims := &jwtgen.RegisteredClaims{
		Issuer:    ts.issuerURL + "/" + fprint.Hex(),
		Subject:   subject,
		Audience:  []string{audience},
		IssuedAt:  jwtgen.NewNumericDate(issuedAt),
		ExpiresAt: jwtgen.NewNumericDate(expiresAt),
	}

	token := jwtgen.NewWithClaims(jwtgen.SigningMethodES256, claims)
	token.Header["kid"] = fprint.Hex()

	jwt, err := token.SignedString(key)
	if err != nil {
		logger.Error("failed to sign token", "err", err)
		return srvtool.Error(http.StatusInternalServerError, "failed to sign token")
	}

	return srvtool.Ok(
		tokenResponse{
			AccessToken:     jwt,
			IssuedTokenType: "urn:ietf:params:oauth:token-type:jwt",
			ExpiresIn:       int(expiresAt.Sub(issuedAt).Seconds()),
		},
	)
}
