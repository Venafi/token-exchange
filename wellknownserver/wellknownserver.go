/*
Copyright 2024 Venafi

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package wellknownserver

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-logr/logr"

	"github.com/Venafi/token-exchange/fingerprint"
	"github.com/Venafi/token-exchange/srvtool"
)

type Config struct {
	Address string

	Certificate tls.Certificate

	RootMap fingerprint.RootMap

	DiscoveryEndpoint string
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

		ErrorLog: slog.NewLogLogger(logr.FromContextAsSlogLogger(ctx).Handler(), slog.LevelError),

		TLSConfig: tlsCfg,

		Handler: newServer(config.RootMap, config.DiscoveryEndpoint),
	}

	return wellKnownSrv, nil
}

func newServer(roots fingerprint.RootMap, discoverEndpoint string) *wellKnownServer {
	mux := http.NewServeMux()

	srv := &wellKnownServer{
		roots: roots,

		issuerURL: "https://" + discoverEndpoint,

		mux: mux,
	}

	mux.HandleFunc("GET /.well-known/{rootIDHex}/openid-configuration", srvtool.JSONHandler(srv.handleOpenIDConfiguration))
	mux.HandleFunc("GET /.well-known/{rootIDHex}/jwks", srvtool.JSONHandler(srv.handleJWKs))

	mux.HandleFunc("GET /status", srvtool.JSONHandler(srv.handleStatusRequest))

	return srv
}

type wellKnownServer struct {
	roots fingerprint.RootMap

	issuerURL string

	mux *http.ServeMux
}

func (wks *wellKnownServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	srvtool.ServeHTTPWithLogs(wks.mux, w, r)
}

func (wks *wellKnownServer) extractRootID(r *http.Request) (fingerprint.Fingerprint, srvtool.Response) {
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

func (wks *wellKnownServer) handleOpenIDConfiguration(r *http.Request) srvtool.Response {
	fprint, httpErr := wks.extractRootID(r)
	if httpErr != nil {
		return httpErr
	}

	jwksHost := r.Host

	return srvtool.Ok(oidcConfigurationResponse{
		SupportedSigningAlgs:   []string{"RS256"}, // TODO: should depend on signing key type? haven't checked
		SupportedResponseTypes: []string{"id_token"},
		SupportedSubjectTypes:  []string{"public"},

		Issuer: wks.issuerURL + "/" + fprint.Hex(),

		JWKsURI: "https://" + jwksHost + "/" + fprint.Hex() + "/.well-known/jwks",
	})
}

func (wks *wellKnownServer) handleJWKs(r *http.Request) srvtool.Response {
	fprint, httpErr := wks.extractRootID(r)
	if httpErr != nil {
		return httpErr
	}

	key, ok := wks.roots[fprint]
	if !ok {
		// shouldn't happen, extractRootID checks that it exists in wks.roots
		return srvtool.Error(http.StatusInternalServerError, "couldn't find signing key corresponding to fingerprint")
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

	return srvtool.Ok(response)
}

type statusMsg struct {
	Status string `json:"status"`
}

func (wks *wellKnownServer) handleStatusRequest(r *http.Request) srvtool.Response {
	return srvtool.Ok(statusMsg{
		Status: "OK",
	})
}
