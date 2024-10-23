package wellknownserver

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"
	"token-exchange/fingerprint"
	"token-exchange/srvtool"

	jose "github.com/go-jose/go-jose/v4"
)

type Config struct {
	Address string

	Certificate tls.Certificate

	RootMap fingerprint.RootMap
}

func Create(ctx context.Context, config *Config) (*http.Server, error) {
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{config.Certificate},
		MinVersion:   tls.VersionTLS12,
	}

	wellKnownSrv := &http.Server{
		BaseContext: func(_ net.Listener) context.Context { return ctx },

		Addr:           config.Address,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 10 * 1024,

		TLSConfig: tlsCfg,

		Handler: newServer(config.RootMap),
	}

	return wellKnownSrv, nil
}

func newServer(roots fingerprint.RootMap) *wellKnownServer {
	mux := http.NewServeMux()

	srv := &wellKnownServer{
		roots: roots,

		// TODO
		issuerURL: "https://example.com",

		mux: mux,
	}

	mux.HandleFunc("GET /.well-known/{rootIDHex}/openid-configuration", srvtool.JSON(srv.handleOpenIDConfiguration))
	mux.HandleFunc("GET /.well-known/{rootIDHex}/jwks", srvtool.JSON(srv.handleJWKs))
	mux.HandleFunc("GET /status", srvtool.JSON(srv.handleStatusRequest))

	return srv
}

type wellKnownServer struct {
	roots fingerprint.RootMap

	issuerURL string

	mux *http.ServeMux
}

func (wks *wellKnownServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	wks.mux.ServeHTTP(w, r)
}

func (wks *wellKnownServer) extractRootID(r *http.Request) (fingerprint.Fingerprint, *srvtool.HTTPError) {
	rootIDHex := r.PathValue("rootIDHex")

	if rootIDHex == "" {
		return fingerprint.Fingerprint{}, srvtool.Error(http.StatusBadRequest, "missing root ID in path")
	}

	rootIDHex = strings.ToLower(rootIDHex)

	fprint, err := fingerprint.Decode(rootIDHex)
	if err != nil {
		return fingerprint.Fingerprint{}, srvtool.Errorf(http.StatusBadRequest, "failed to decode root ID: %s", err)
	}

	_, known := wks.roots[fprint]
	if !known {
		return fingerprint.Fingerprint{}, srvtool.Errorf(http.StatusNotFound, "unknown root fingerprint %s", fprint)
	}

	return fprint, nil
}

type oidcConfigurationResponse struct {
	SupportedSigningAlgs   []string `json:"id_token_signing_alg_values_supported"`
	SupportedResponseTypes []string `json:"response_types_supported"`
	SupportedSubjectTypes  []string `json:"public"`

	Issuer  string `json:"issuer"`
	JWKsURI string `json:"jwks_uri"`
}

func (wks *wellKnownServer) handleOpenIDConfiguration(w http.ResponseWriter, r *http.Request) (*srvtool.Response, *srvtool.HTTPError) {
	fprint, httpErr := wks.extractRootID(r)
	if httpErr != nil {
		return nil, httpErr
	}

	jwksHost := r.Host

	return &srvtool.Response{
		Body: oidcConfigurationResponse{
			SupportedSigningAlgs:   []string{"RS256"}, // TODO: should depend on signing key type? haven't checked
			SupportedResponseTypes: []string{"id_token"},
			SupportedSubjectTypes:  []string{"public"},

			Issuer: wks.issuerURL + "/" + fprint.Hex(),

			JWKsURI: "https://" + jwksHost + "/" + fprint.Hex() + "/.well-known/jwks",
		},
	}, nil
}

type jwksResponse struct{}

func (wks *wellKnownServer) handleJWKs(w http.ResponseWriter, r *http.Request) (*srvtool.Response, *srvtool.HTTPError) {
	fprint, httpErr := wks.extractRootID(r)
	if httpErr != nil {
		return nil, httpErr
	}

	key, ok := wks.roots[fprint]
	if !ok {
		// shouldn't happen, extractRootID checks that it exists in wks.roots
		return nil, srvtool.Error(http.StatusInternalServerError, "couldn't find signing key corresponding to fingerprint")
	}

	publicKey := key.Public()

	response := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Algorithm: string(jose.ES256), // TODO: should vary on key type?
				Key:       publicKey,
				KeyID:     fprint.Hex(),
				Use:       "sig",
			},
		},
	}

	return &srvtool.Response{
		Body: response,
	}, nil
}

type statusMsg struct {
	Status string `json:"status"`
}

func (wks *wellKnownServer) handleStatusRequest(w http.ResponseWriter, r *http.Request) (*srvtool.Response, *srvtool.HTTPError) {
	return &srvtool.Response{
		Body: statusMsg{
			Status: "OK",
		},
	}, nil
}
