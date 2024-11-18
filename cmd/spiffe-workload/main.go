package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/Venafi/token-exchange/fingerprint"
	"github.com/Venafi/token-exchange/tokenserver"
	"github.com/Venafi/token-exchange/wellknownserver"
)

const (
	defaultSocketPath = "/var/run/secrets/workload-spiffe-uds/socket"

	defaultCertPath = "/var/run/secrets/spiffe.io"

	defaultChainFilename      = "tls.crt"
	defaultPrivateKeyFilename = "tls.key"

	defaultCABundlePath = "/tls-trust/bundle.pem"

	defaultTokenExchangeTokenURL     = "https://token-exchange-token.token-exchange.svc.cluster.local"
	defaultTokenExchangeWellKnownURL = "https://token-exchange-wellknown.token-exchange.svc.cluster.local"
)

var (
	// errSSRFProtection is the gRPC error returned if SSRF protection is invoked. The SPIFFE spec requires that the error
	// type is "InvalidArgument"; see validateSSRFMetadata for more details
	errSSRFProtection = status.Error(codes.InvalidArgument, "no metadata provided; rejecting request for SSRF prevention")
)

// cryptoPubKey is the interface defined in `crypto.PublicKey` to always be implemented for stdlib public keys
type cryptoPubKey interface {
	Equal(x crypto.PublicKey) bool
}

type SVIDBundle struct {
	ParsedChain []*x509.Certificate

	FullChainWithRoot []*x509.Certificate

	RootFingerprint fingerprint.Fingerprint

	LeafSPIFFEID spiffeid.ID

	ChainPEM []byte
	ChainDER []byte

	PrivateKeyPEM   []byte
	PKCS8PrivateKey []byte

	CABundlePEM       []byte
	CABundleDER       []byte
	CABundleSPIFFEMap map[string][]byte
	CABundlePool      *x509.CertPool
}

func (sb *SVIDBundle) MTLSClient() (*http.Client, error) {
	cert, err := tls.X509KeyPair(sb.ChainPEM, sb.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to use bundle to create client certificate: %w", err)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(sb.CABundlePEM)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      sb.CABundlePool,
				Certificates: []tls.Certificate{cert},
			},
		},
	}

	return client, nil
}

func (sb *SVIDBundle) TLSClient() (*http.Client, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: sb.CABundlePool,
			},
		},
	}

	return client, nil
}

// workloadServer is a provider for the SPIFFE workload API integrating with token-exchange, exposing endpoints for returning
// X.509 and JWT SVIDs and trust stores.
// It takes a path to a location on-disk from which an X.509 SVID can be read, usually created with csi-driver or csi-driver-spiffe.
// A path is taken, rather than a parsed cert, so that any updates to the on-disk certificate can be picked up.
// When serving requests for X.509 SVIDs, the on-disk SVID is returned.
// When serving requests for JWT SVIDs, the on-disk X.509 SVID is exchanged for a JWT SVID using token-exchange.
type workloadServer struct {
	// UnimplementedSpiffeWorkloadAPIServer is required to be embedded for forwards compatibility
	workload.UnimplementedSpiffeWorkloadAPIServer

	logger *slog.Logger

	chainLocation      string
	privateKeyLocation string
	caBundleLocation   string

	tokenExchangeTokenBaseURL     string
	tokenExchangeWellKnownBaseURL string
}

func (ws *workloadServer) postTokenURL() string {
	p, err := url.JoinPath(ws.tokenExchangeTokenBaseURL, "token")
	if err != nil {
		// shouldn't happen - we should have validated the base URL before this function is called
		panic(err)
	}

	return p
}

func (ws *workloadServer) getJWKsURL(bundle *SVIDBundle) string {
	fprint, err := fingerprint.Rootmost(bundle.FullChainWithRoot)
	if err != nil {
		panic("jwksURL called with empty bundle")
	}

	p, err := url.JoinPath(ws.tokenExchangeWellKnownBaseURL, fprint.Hex(), ".well-known", "jwks")
	if err != nil {
		// shouldn't happen - we should have validated the base URL before this function is called
		panic(err)
	}

	return p
}

func (ws *workloadServer) loadSVIDBundle() (*SVIDBundle, error) {
	chainBytes, err := os.ReadFile(ws.chainLocation)
	if err != nil {
		return nil, fmt.Errorf("failed to read chain from filesystem: %w", err)
	}

	privateKeyBytes, err := os.ReadFile(ws.privateKeyLocation)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key from fileystem: %w", err)
	}

	bundleBytes, err := os.ReadFile(ws.caBundleLocation)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA bundle from filesystem: %w", err)
	}

	bundleDER := pemToDER(bundleBytes)

	bundlePool := x509.NewCertPool()
	bundlePool.AppendCertsFromPEM(bundleBytes)

	derChain := pemToDER(chainBytes)

	parsedChain, err := x509.ParseCertificates(derChain)
	if err != nil {
		return nil, fmt.Errorf("failed to parse chain from filesystem: %w", err)
	}

	if len(parsedChain) == 0 {
		// shouldn't happen (ParseCertificates would error) but to ensure we don't panic...
		return nil, fmt.Errorf("found no certificates in filesystem SVID")
	}

	var interPool *x509.CertPool

	if len(parsedChain) > 1 {
		interPool = x509.NewCertPool()
		for _, cert := range parsedChain[1:] {
			interPool.AddCert(cert)
		}
	}

	leaf := parsedChain[0]

	validatedChains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         bundlePool,
		Intermediates: interPool,
	})
	if err != nil {
		return nil, fmt.Errorf("found no validated chains with on-disk root and trust bundle")
	}

	if len(validatedChains) == 0 {
		return nil, fmt.Errorf("failed to find any validated chains")
	}

	if len(validatedChains) > 1 {
		ws.logger.Info("skipping at least one validated chain", "num_chains", len(validatedChains))
	}

	validatedChainsWithRoot := validatedChains[0]

	var pk any
	var pkParseErr error

	switch leaf.PublicKeyAlgorithm {
	case x509.RSA:
		pk, pkParseErr = x509.ParsePKCS1PrivateKey(pemToDER(privateKeyBytes))

	case x509.ECDSA:
		pk, pkParseErr = x509.ParseECPrivateKey(pemToDER(privateKeyBytes))

	case x509.Ed25519:
		pk, pkParseErr = x509.ParsePKCS8PrivateKey(pemToDER(privateKeyBytes))

	default:
		return nil, fmt.Errorf("unknown key type for on-disk certificate: %s", leaf.PublicKeyAlgorithm.String())
	}

	if pkParseErr != nil {
		return nil, fmt.Errorf("failed to parse private key from filesystem: %w", err)
	}

	pkcs8PrivateKeyDER, err := x509.MarshalPKCS8PrivateKey(pk)
	if err != nil {
		return nil, fmt.Errorf("failed to write private key to PKCS#8 format: %w", err)
	}

	pkSigner, ok := pk.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("got unexpected key type %T from on-disk private key", pk)
	}

	expectedPubKey, ok := pkSigner.Public().(cryptoPubKey)
	if !ok {
		// shouldn't happen for stdlib public keys
		return nil, fmt.Errorf("public key doesn't seem to support standard library methods")
	}

	if !expectedPubKey.Equal(leaf.PublicKey) {
		return nil, fmt.Errorf("got mismatched public / private key; was chain updated without private key also being updated?")
	}

	if len(leaf.URIs) != 1 {
		return nil, fmt.Errorf("invalid X.509 SVID on-disk; expected only one URI but got %d", len(leaf.URIs))
	}

	rawSPIFFEID := leaf.URIs[0]

	parsedSPIFFEID, err := spiffeid.FromURI(rawSPIFFEID)
	if err != nil {
		return nil, fmt.Errorf("invalid X.509 SVID on-disk; failed to parse SPIFFE ID %q: %s", rawSPIFFEID.String(), err)
	}

	allBundleCerts, err := x509.ParseCertificates(bundleDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse all certs in X.509 CA bundle from filesystem: %w", err)
	}

	bundleMap := make(map[string][]byte)

	for i, cert := range allBundleCerts {
		if len(cert.URIs) != 1 {
			ws.logger.Error("skipping certificate in CA bundle due to invalid number of URIs (expected exactly 1)", "bundle-position", i, "uri-count", len(cert.URIs))
			continue
		}

		rawSPIFFEID := cert.URIs[0]

		parsedSPIFFEID, err := spiffeid.FromURI(rawSPIFFEID)
		if err != nil {
			ws.logger.Error("skipping certificate in CA bundle due to un-parseable SPIFFE ID", "bundle-position", i, "err", err)
			continue
		}

		var newEntry []byte

		old, exists := bundleMap[parsedSPIFFEID.String()]
		if exists {
			newEntry = append(old, cert.Raw...)
		} else {
			newEntry = cert.Raw
		}

		bundleMap[parsedSPIFFEID.String()] = newEntry
	}

	// TODO: PEM should be sanitised to remove comments, non-PEM data, etc

	return &SVIDBundle{
		ParsedChain: parsedChain,

		FullChainWithRoot: validatedChainsWithRoot,

		LeafSPIFFEID: parsedSPIFFEID,

		ChainDER: derChain,
		ChainPEM: chainBytes,

		PKCS8PrivateKey: pkcs8PrivateKeyDER,
		PrivateKeyPEM:   privateKeyBytes,

		CABundlePEM: bundleBytes,
		CABundleDER: bundleDER,

		CABundleSPIFFEMap: bundleMap,

		CABundlePool: bundlePool,
	}, nil
}

func (ws *workloadServer) FetchX509SVID(req *workload.X509SVIDRequest, server workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	if err := validateSSRFMetadata(server.Context()); err != nil {
		return err
	}

	ws.logger.Info("got FetchX509SVID request")

	bundle, err := ws.loadSVIDBundle()
	if err != nil {
		ws.logger.Error("failed to read SVID bundle from filesystem", "chain-location", ws.chainLocation, "key-location", ws.privateKeyLocation, "ca-bundle-location", ws.caBundleLocation, "err", err)
		return status.Error(codes.FailedPrecondition, "internal error: failed to read on-disk SVID bundle")
	}

	response := &workload.X509SVIDResponse{
		Svids: []*workload.X509SVID{{
			SpiffeId:    bundle.LeafSPIFFEID.String(),
			X509Svid:    bundle.ChainDER,
			X509SvidKey: bundle.PKCS8PrivateKey,
			Bundle:      bundle.CABundleDER,
		}},
	}

	err = server.Send(response)
	if err != nil {
		return err
	}

	return nil
}

func (ws *workloadServer) FetchX509Bundles(req *workload.X509BundlesRequest, server workload.SpiffeWorkloadAPI_FetchX509BundlesServer) error {
	if err := validateSSRFMetadata(server.Context()); err != nil {
		return err
	}

	ws.logger.Info("got FetchX509Bundles request")

	bundle, err := ws.loadSVIDBundle()
	if err != nil {
		ws.logger.Error("failed to read SVID bundle from filesystem", "chain-location", ws.chainLocation, "key-location", ws.privateKeyLocation, "ca-bundle-location", ws.caBundleLocation, "err", err)
		return status.Error(codes.FailedPrecondition, "internal error: failed to read on-disk SVID bundle")
	}

	response := &workload.X509BundlesResponse{
		Bundles: bundle.CABundleSPIFFEMap,
	}

	err = server.Send(response)
	if err != nil {
		return err
	}

	return nil
}

func (ws *workloadServer) FetchJWTSVID(ctx context.Context, req *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
	if err := validateSSRFMetadata(ctx); err != nil {
		return nil, err
	}

	ws.logger.Info("got FetchJWTSVID request")

	bundle, err := ws.loadSVIDBundle()
	if err != nil {
		ws.logger.Error("failed to read SVID bundle from filesystem", "chain-location", ws.chainLocation, "key-location", ws.privateKeyLocation, "ca-bundle-location", ws.caBundleLocation, "err", err)
		return nil, status.Error(codes.FailedPrecondition, "internal error: failed to read on-disk SVID bundle")
	}

	// tokenurl="https://token.tim-ramlot-gcp.jetstacker.net"
	// curl -s -X POST "$tokenurl/token" \
	//   --key leaf1_key.pem --cert leaf1_cert_chain.pem \
	//	 -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token_type=urn:ietf:params:oauth:token-type:tls-client-auth&audience=MYAUD"

	client, err := bundle.MTLSClient()
	if err != nil {
		ws.logger.Error("failed to create MTLS client for token-exchange", "err", err)
		return nil, status.Error(codes.FailedPrecondition, "internal error: failed to read on-disk SVID bundle")
	}

	formData := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:tls-client-auth"},
		"audience":           {strings.Join(req.Audience, ",")},
	}

	tokenRequest, err := http.NewRequest("POST", ws.postTokenURL(), strings.NewReader(formData.Encode()))
	if err != nil {
		ws.logger.Error("failed to create token request", "err", err)
		return nil, status.Error(codes.FailedPrecondition, "failed to create request for token")
	}

	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	serverResponse, err := client.Do(tokenRequest)
	if err != nil {
		ws.logger.Error("token request failed", "err", err)
		return nil, status.Error(codes.FailedPrecondition, "token request failed")
	}

	defer serverResponse.Body.Close()

	if serverResponse.StatusCode != 200 {
		errMsg := "unknown error"

		fullBody, err := io.ReadAll(serverResponse.Body)
		if err != nil {
			ws.logger.Error("failed to read error response", "err", err)
		} else {
			ws.logger.Error("error response from token request", "resp", fullBody)
			errMsg = string(fullBody)
		}

		return nil, status.Errorf(codes.FailedPrecondition, "got an error response from the server: %s", errMsg)
	}

	fullBody, err := io.ReadAll(serverResponse.Body)
	if err != nil {
		ws.logger.Error("failed to read token response", "err", err)
		return nil, status.Error(codes.FailedPrecondition, "failed to read server response")
	}

	var token tokenserver.GetTokenResponse

	err = json.Unmarshal(fullBody, &token)
	if err != nil {
		ws.logger.Error("failed to parse token JSON", "err", err, "raw", string(fullBody))
		return nil, status.Error(codes.FailedPrecondition, "failed to read server JSON token response")
	}

	resp := &workload.JWTSVIDResponse{
		Svids: []*workload.JWTSVID{{
			SpiffeId: token.SPIFFEID,
			Svid:     string(token.AccessToken),
		}},
	}

	return resp, nil
}

func (ws *workloadServer) FetchJWTBundles(req *workload.JWTBundlesRequest, server workload.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	ws.logger.Info("got FetchJWTBundles request")

	bundle, err := ws.loadSVIDBundle()
	if err != nil {
		ws.logger.Error("failed to read SVID bundle from filesystem", "chain-location", ws.chainLocation, "key-location", ws.privateKeyLocation, "ca-bundle-location", ws.caBundleLocation, "err", err)
		return status.Error(codes.FailedPrecondition, "internal error: failed to read on-disk SVID bundle")
	}

	client, err := bundle.TLSClient()
	if err != nil {
		ws.logger.Error("failed to create TLS client for token-exchange", "err", err)
		return status.Error(codes.FailedPrecondition, "internal error: failed to read on-disk SVID bundle")
	}

	url := ws.getJWKsURL(bundle)

	logger := ws.logger.With("url", url)

	resp, err := client.Get(url)
	if err != nil {
		logger.Error("failed to request JWKs from token-exchange", "err", err)
		return status.Error(codes.FailedPrecondition, "failed to request JWT bundles")
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errMsg := "unknown error"

		fullBody, err := io.ReadAll(resp.Body)
		if err != nil {
			ws.logger.Error("failed to read error response", "err", err)
		} else {
			ws.logger.Error("error response from token request", "resp", fullBody)
			errMsg = string(fullBody)
		}

		return status.Errorf(codes.FailedPrecondition, "got an error response from the server: %s", errMsg)
	}

	fullBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("failed to read JWKs response", "err", err)
		return status.Error(codes.FailedPrecondition, "failed to read server JWKs response")
	}

	var jwks wellknownserver.GetJWKsResponse

	err = json.Unmarshal(fullBody, &jwks)
	if err != nil {
		logger.Error("failed to parse JSON JWK bundles", "err", err, "raw", string(fullBody))
		return status.Error(codes.FailedPrecondition, "failed to read server JWKs response")
	}

	// we just unmarshalled above, but this step is explicit here in case GetJWKsResponse is
	// changed in the future
	marshalledJWKs, err := json.Marshal(jwks)
	if err != nil {
		logger.Error("failed to marshal JWKs", "err", err)
		return status.Error(codes.FailedPrecondition, "failed to marshal JWKs for response")
	}

	response := &workload.JWTBundlesResponse{
		Bundles: map[string][]byte{
			bundle.LeafSPIFFEID.TrustDomain().ID().String(): marshalledJWKs,
		},
	}

	err = server.Send(response)
	if err != nil {
		logger.Error("failed to send response", "err", err)
		return err
	}

	return nil
}

func do(ctx context.Context, logger *slog.Logger) error {
	var socketPath string

	var chainLocation string
	var privateKeyLocation string

	var caBundleLocation string

	var tokenExchangeTokenURL string
	var tokenExchangeWellKnownURL string

	flag.StringVar(&socketPath, "socket-path", defaultSocketPath, "Filesystem path for UNIX domain socket to listen on")

	flag.StringVar(&chainLocation, "tls-chain-location", filepath.Join(defaultCertPath, defaultChainFilename), "Filesystem location of PEM-encoded X.509 chain to serve in requested X.509 SVID")
	flag.StringVar(&privateKeyLocation, "tls-private-key-location", filepath.Join(defaultCertPath, defaultPrivateKeyFilename), "Filesystem location of PEM-encoded private key to serve in requested X.509 SVID")

	flag.StringVar(&caBundleLocation, "ca-bundle-location", defaultCABundlePath, "Filesystem location of PEM-encoded X.509 certificate bundle to serve in requested X.509 bundles")

	flag.StringVar(&tokenExchangeTokenURL, "token-exchange-token-url", defaultTokenExchangeTokenURL, "URL of token-exchange token server to use for JWT SVIDs")
	flag.StringVar(&tokenExchangeWellKnownURL, "token-exchange-wellknown-url", defaultTokenExchangeWellKnownURL, "URL of token-exchange 'wellknown' server to use for querying JWKs")

	flag.Parse()

	// this is used to confirm early that the URL is valid; the actual calls come later, from the workloadServer methods
	_, err := url.JoinPath(tokenExchangeTokenURL, "/status")
	if err != nil {
		return fmt.Errorf("invalid token-exchange-token-url %q: %s", tokenExchangeTokenURL, err)
	}

	// this is used to confirm early that the URL is valid; the actual calls come later, from the workloadServer methods
	_, err = url.JoinPath(tokenExchangeWellKnownURL, "/status")
	if err != nil {
		return fmt.Errorf("invalid token-exchange-wellknown-url %q: %s", tokenExchangeWellKnownURL, err)
	}

	workloadHandler := &workloadServer{
		logger: logger,

		chainLocation:      chainLocation,
		privateKeyLocation: privateKeyLocation,

		caBundleLocation: caBundleLocation,

		tokenExchangeTokenBaseURL:     tokenExchangeTokenURL,
		tokenExchangeWellKnownBaseURL: tokenExchangeWellKnownURL,
	}

	grpcServer := grpc.NewServer()
	workload.RegisterSpiffeWorkloadAPIServer(grpcServer, workloadHandler)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}

	defer listener.Close()

	go func() {
		logger.Info("starting listener", "path", socketPath)

		err := grpcServer.Serve(listener)
		if err != nil {
			logger.Error("failed to serve gRPC", "err", err)
		}
	}()

	<-ctx.Done()

	grpcServer.GracefulStop()

	logger.Info("shutting down")

	return nil
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	sigs := make(chan os.Signal)

	signal.Notify(sigs, os.Interrupt, os.Kill)

	go func() {
		<-sigs

		cancel()
	}()

	err := do(ctx, logger)
	if err != nil {
		logger.Error("fatal error", "err", err)
		os.Exit(1)
	}
}

// pemToDER converts PEM data to raw DER data, e.g. by converting a chain of PEM encoded certificates to their DER formats.
// DER is required to be returned by the SPIFFE spec.
func pemToDER(pemData []byte) []byte {
	var out []byte
	var block *pem.Block

	for {
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}

		out = append(out, block.Bytes...)
	}

	return out
}

// validateSSRFMetadata checks that valid metadata was passed in the request, as is required by the SPIFFE spec;
// in the spec, metadata with key "workload.spiffe.io" and value "true" must be present for SSRF protection.
// See https://github.com/spiffe/spiffe/blob/67dc2b7d3f34f865be6d8bff20a7d6c6d29a4065/standards/SPIFFE_Workload_Endpoint.md#3-transport
func validateSSRFMetadata(ctx context.Context) error {
	meta, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return errSSRFProtection
	}

	workloadMetadata := meta.Get("workload.spiffe.io")
	if len(workloadMetadata) != 1 || workloadMetadata[0] != "true" {
		return errSSRFProtection
	}

	return nil
}
