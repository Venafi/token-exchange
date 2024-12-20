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

package tokenserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Venafi/token-exchange/fingerprint"
	"github.com/Venafi/token-exchange/srvtool"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
)

func genSelfSignedCertificate(t *testing.T, cert *x509.Certificate) *x509.Certificate {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, pk.Public(), pk)
	require.NoError(t, err)
	parsedCert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)
	return parsedCert
}

func Test_handleTokenRequest(t *testing.T) {
	for _, tt := range []struct {
		name     string
		postForm map[string][]string
		certs    []*x509.Certificate
		expValue func(*testing.T, *GetTokenResponse)
		expError *srvtool.ErrMsg
	}{
		{
			name: "valid",
			postForm: map[string][]string{
				"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
				"subject_token_type": {"urn:ietf:params:oauth:token-type:tls-client-auth"},
				"audience":           {"test"},
			},
			certs: []*x509.Certificate{
				genSelfSignedCertificate(t, &x509.Certificate{
					Version:               3,
					SerialNumber:          big.NewInt(12345),
					URIs:                  []*url.URL{must[*url.URL](t)(url.Parse("spiffe://example.com/identity001"))},
					BasicConstraintsValid: true,
					IsCA:                  true,
					NotAfter:              time.Now().Add(time.Hour),
				}),
			},
			expValue: func(t *testing.T, tr *GetTokenResponse) {
				require.NotEmpty(t, tr.AccessToken)
				require.Equal(t, "urn:ietf:params:oauth:token-type:jwt", tr.IssuedTokenType)
				require.Equal(t, 3600, tr.ExpiresIn)

				token, err := jwt.ParseSigned(tr.AccessToken, []jose.SignatureAlgorithm{jose.RS256})
				require.NoError(t, err)

				out := jwt.Claims{}
				err = token.UnsafeClaimsWithoutVerification(&out)
				require.NoError(t, err)

				require.Equal(t, "test", out.Audience[0])
				require.True(t, strings.HasPrefix(out.Issuer, "https://example.com/"))
				require.Equal(t, "spiffe://example.com/identity001", out.Subject)
			},
		},
		/*
			{
				name: "non-ca-self-signed",
				postForm: map[string][]string{
					"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
					"subject_token_type": {"urn:ietf:params:oauth:token-type:tls-client-auth"},
					"audience":           {"test"},
				},
				certs: []*x509.Certificate{
					genSelfSignedCertificate(t, &x509.Certificate{
						Version:      3,
						SerialNumber: big.NewInt(12345),
						Subject: pkix.Name{
							CommonName: "test",
						},
						BasicConstraintsValid: true,
						IsCA:                  false,
						NotAfter:              time.Now().Add(time.Hour),
					}),
				},
				expError: &srvtool.ErrMsg{
					Error: "failed to build certificate chain: root certificate signature is invalid",
				},
			},
		*/
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctx := logr.NewContextWithSlogLogger(context.Background(), slog.New(slog.NewJSONHandler(os.Stdout, nil)))

			// Create a new request
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/token", nil)
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Accept", "application/json")

			req.PostForm = tt.postForm

			req.TLS = &tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{
					tt.certs,
				},
			}

			rootFingerprint, err := fingerprint.Rootmost(tt.certs)
			if err != nil {
				t.Fatal(err)
			}

			// Create a new response recorder
			rec := httptest.NewRecorder()

			// Call the handler function with the http recorder and request
			srvtool.JSONHandler(
				(&tokenServer{
					roots: fingerprint.RootMap{
						rootFingerprint: func() *rsa.PrivateKey {
							pk, err := rootFingerprint.DeriveRSASigningKey([32]byte{})
							require.NoError(t, err)
							return pk
						}(),
					},
					issuerURL: "https://example.com",
				}).handleTokenRequest,
			)(rec, req)

			bytes, err := io.ReadAll(rec.Body)
			require.NoError(t, err)

			if rec.Code != http.StatusOK {
				var tokenResponse srvtool.ErrMsg
				if err := json.Unmarshal(bytes, &tokenResponse); err != nil {
					t.Fatal(err)
				}

				if tt.expError == nil {
					t.Fatalf("unexpected error: %v", tokenResponse)
				} else {
					require.Equal(t, *tt.expError, tokenResponse)
				}
			} else {
				var tokenResponse tokenResponse
				if err := json.Unmarshal(bytes, &tokenResponse); err != nil {
					t.Fatal(err)
				}

				if tt.expValue == nil {
					t.Fatalf("unexpected response: %v", tokenResponse)
				} else {
					tt.expValue(t, &tokenResponse)
				}
			}
		})
	}
}

func must[T any](t *testing.T) func(val T, err error) T {
	return func(val T, err error) T {
		t.Helper()
		require.NoError(t, err)
		return val
	}
}
