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

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func Test_token(t *testing.T) {
	for _, tt := range []struct {
		name     string
		postForm map[string][]string
		certs    []*x509.Certificate
		expValue func(*testing.T, *tokenResponse)
		expError *httpError
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
					Version:      3,
					SerialNumber: big.NewInt(12345),
					Subject: pkix.Name{
						CommonName: "test",
					},
					BasicConstraintsValid: true,
					IsCA:                  true,
					NotAfter:              time.Now().Add(time.Hour),
				}),
			},
			expValue: func(t *testing.T, tr *tokenResponse) {
				require.NotEmpty(t, tr.AccessToken)
				require.Equal(t, "urn:ietf:params:oauth:token-type:jwt", tr.IssuedTokenType)
				require.Equal(t, 3600, tr.ExpiresIn)
			},
		},
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
			expError: &httpError{
				HttpCode: 400,
				Message:  "failed to build certificate chain: root certificate signature is invalid",
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Create a new request
			req, err := http.NewRequest(http.MethodPost, "/token", nil)
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Accept", "application/json")

			req.PostForm = tt.postForm

			req.TLS = &tls.ConnectionState{
				PeerCertificates: tt.certs,
			}

			// Create a new response recorder
			rec := httptest.NewRecorder()

			// Call the handler function with the http recorder and request
			jsonResponseHandlerWrappper(handleRequestRoot)(rec, req)

			bytes, err := io.ReadAll(rec.Body)
			require.NoError(t, err)

			if rec.Code != http.StatusOK {
				var tokenResponse httpError
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
