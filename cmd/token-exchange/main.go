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

	"github.com/go-logr/logr"

	"github.com/Venafi/token-exchange/fingerprint"
	"github.com/Venafi/token-exchange/tokenserver"
	"github.com/Venafi/token-exchange/wellknownserver"
)

var secretKey = []byte{
	0x85, 0x04, 0xe2, 0xab, 0xd7, 0x62, 0x2a, 0x81,
	0x44, 0x4b, 0xf4, 0x90, 0xa5, 0x56, 0xea, 0x4d,
	0x7b, 0xce, 0xb0, 0xad, 0x78, 0xa9, 0xb6, 0x7f,
	0x22, 0xd9, 0x80, 0x34, 0x83, 0x43, 0x9d, 0x53,
}

func run(ctx context.Context, logger *slog.Logger) error {
	var tokenEndpoint string
	var discoverEndpoint string

	var tlsChainLocation string
	var tlsPrivateKeyLocation string

	var trustBundleLocation string

	flag.StringVar(&tokenEndpoint, "token-endpoint", "token.example.com", "DNS name at which the token server is available")
	flag.StringVar(&discoverEndpoint, "discover-endpoint", "discover.example.com", "DNS name at which the well-known / discovery server is available")

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

		logger.Info("loaded new root fingerprint", "hex", fprint.Hex())

		sk, err := fprint.DeriveECDSASigningKey(secretKey)
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

		DiscoveryEndpoint: discoverEndpoint,
	}

	tokenServer, err := tokenserver.Create(ctx, tokenServerCfg)

	wellKnownServerCfg := &wellknownserver.Config{
		Address: "0.0.0.0:9119",

		Certificate: cert,

		RootMap: rootMap,

		DiscoveryEndpoint: discoverEndpoint,
	}

	wellKnownServer, err := wellknownserver.Create(ctx, wellKnownServerCfg)

	go func() {
		err := tokenServer.ListenAndServeTLS("", "")

		if err != http.ErrServerClosed {
			logger.Error("token server error", "err", err)
		}
	}()

	go func() {
		err := wellKnownServer.ListenAndServeTLS("", "")

		if err != http.ErrServerClosed {
			logger.Error("well-known server error", "err", err)
		}
	}()

	logger.Info("token server listening", "addr", tokenServerCfg.Address)
	logger.Info("well-known server listening", "addr", wellKnownServerCfg.Address)

	<-ctx.Done()

	logger.Info("shutting down server")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := tokenServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("failed to shut down token server: %s", err)
	}

	if err := wellKnownServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("failed to shut down well-known server: %s", err)
	}

	return nil
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	ctx := logr.NewContextWithSlogLogger(context.Background(), logger)

	runCtx, stop := signal.NotifyContext(ctx, os.Interrupt, os.Kill)
	defer stop()

	err := run(runCtx, logger)
	if err != nil {
		logger.Error("fatal error", "err", err)
		os.Exit(1)
	}
}

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
