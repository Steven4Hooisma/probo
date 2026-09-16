// Copyright (c) 2026 Probo Inc <hello@probo.com>.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package connector

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.gearno.de/kit/httpclient"
)

// newTestKeyPEM returns a fresh P-256 key in PKCS#8 PEM form, the shape Apple
// hands out for an Apple Business Manager API account.
func newTestKeyPEM(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), key
}

func TestPrivateKeyJWTConnection_Validate(t *testing.T) {
	t.Parallel()

	keyPEM, _ := newTestKeyPEM(t)

	base := func() *PrivateKeyJWTConnection {
		return &PrivateKeyJWTConnection{
			ClientID:      "BUSINESSAPI.abc",
			KeyID:         "key-1",
			PrivateKeyPEM: keyPEM,
			TokenURL:      "https://account.apple.com/auth/oauth2/token",
			Audience:      "https://account.apple.com/auth/oauth2/v2/token",
			Scope:         "business.api",
		}
	}

	t.Run("a complete connection validates", func(t *testing.T) {
		t.Parallel()

		assert.NoError(t, base().Validate())
	})

	for _, tc := range []struct {
		name    string
		mutate  func(*PrivateKeyJWTConnection)
		wantErr string
	}{
		{"missing client id", func(c *PrivateKeyJWTConnection) { c.ClientID = "" }, "missing client id"},
		{"missing key id", func(c *PrivateKeyJWTConnection) { c.KeyID = "" }, "missing key id"},
		{"missing token url", func(c *PrivateKeyJWTConnection) { c.TokenURL = "" }, "missing token url"},
		{"missing audience", func(c *PrivateKeyJWTConnection) { c.Audience = "" }, "missing audience"},
		{"empty key", func(c *PrivateKeyJWTConnection) { c.PrivateKeyPEM = "" }, "empty PEM"},
		{"garbage key", func(c *PrivateKeyJWTConnection) { c.PrivateKeyPEM = "not a pem" }, "cannot parse private key"},
	} {
		t.Run(tc.name+" is rejected", func(t *testing.T) {
			t.Parallel()

			conn := base()
			tc.mutate(conn)

			err := conn.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}

	// An RSA key would be silently signed with the wrong algorithm for the
	// `alg: ES256` header the assertion advertises, which the issuer rejects
	// with a message that points at the credential rather than the key type.
	t.Run("a non-ECDSA key is rejected", func(t *testing.T) {
		t.Parallel()

		conn := base()
		conn.PrivateKeyPEM = rsaKeyPEM(t)

		err := conn.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ES256 requires an ECDSA key")
	})
}

func rsaKeyPEM(t *testing.T) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// TestPrivateKeyJWTConnection_ClientExchangesAssertion pins the whole wire
// contract in one pass: the token request's form parameters, the assertion's
// header and claims, and the Authorization header the API call then carries.
func TestPrivateKeyJWTConnection_ClientExchangesAssertion(t *testing.T) {
	t.Parallel()

	keyPEM, key := newTestKeyPEM(t)

	var (
		tokenCalls atomic.Int64
		gotForm    chan map[string]string
	)

	gotForm = make(chan map[string]string, 4)

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())

		form := map[string]string{}
		for k := range r.Form {
			form[k] = r.Form.Get(k)
		}

		gotForm <- form
		tokenCalls.Add(1)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-123","token_type":"Bearer","expires_in":3600}`))
	}))
	defer tokenServer.Close()

	var gotAuth atomic.Value

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer apiServer.Close()

	conn := &PrivateKeyJWTConnection{
		ClientID:      "BUSINESSAPI.abc",
		KeyID:         "key-1",
		PrivateKeyPEM: keyPEM,
		TokenURL:      tokenServer.URL,
		Audience:      "https://account.apple.com/auth/oauth2/v2/token",
		Scope:         "business.api",
	}

	// httptest binds to loopback, which the SSRF-protected default transport
	// refuses; the exchange and the API call share one transport, so the
	// allowance has to cover both.
	client, err := conn.client(
		context.Background(),
		httpclient.WithSSRFProtection(),
		httpclient.WithSSRFAllowLoopback(),
	)
	require.NoError(t, err)

	resp, err := client.Get(apiServer.URL + "/v1/orgDevices")
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	form := <-gotForm
	assert.Equal(t, "client_credentials", form["grant_type"])
	assert.Equal(t, "BUSINESSAPI.abc", form["client_id"])
	assert.Equal(t, "business.api", form["scope"])
	assert.Equal(
		t,
		"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		form["client_assertion_type"],
	)

	assertion := form["client_assertion"]
	require.NotEmpty(t, assertion)

	parts := strings.Split(assertion, ".")
	require.Len(t, parts, 3, "assertion must be a three-part JWS")

	header := decodeJWTSegment(t, parts[0])
	assert.Equal(t, "ES256", header["alg"])
	assert.Equal(t, "key-1", header["kid"])

	claims := decodeJWTSegment(t, parts[1])
	assert.Equal(t, "BUSINESSAPI.abc", claims["iss"])
	assert.Equal(t, "BUSINESSAPI.abc", claims["sub"])
	assert.Equal(t, "https://account.apple.com/auth/oauth2/v2/token", claims["aud"])
	assert.NotEmpty(t, claims["jti"])

	// The signature must verify against the key, in the fixed-width R||S form
	// JWS mandates — a DER-encoded signature would be 70-72 bytes and is
	// rejected by every conforming verifier.
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	require.Len(t, sig, 64, "ES256 signature must be 64 bytes of R||S")

	digest := sha256Sum(parts[0] + "." + parts[1])
	r := new(big.Int).SetBytes(sig[:32])
	sv := new(big.Int).SetBytes(sig[32:])
	assert.True(t, ecdsa.Verify(&key.PublicKey, digest, r, sv), "assertion signature must verify")

	authHeader, _ := gotAuth.Load().(string)
	assert.Equal(t, "Bearer tok-123", authHeader)

	// A second call within the token's lifetime must reuse the cached bearer
	// token rather than mint a fresh assertion for every request.
	resp2, err := client.Get(apiServer.URL + "/v1/orgDevices")
	require.NoError(t, err)
	require.NoError(t, resp2.Body.Close())

	assert.Equal(t, int64(1), tokenCalls.Load(), "token must be cached across requests")
}

func TestPrivateKeyJWTConnection_ClientRejectsTokenError(t *testing.T) {
	t.Parallel()

	keyPEM, _ := newTestKeyPEM(t)

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	defer tokenServer.Close()

	conn := &PrivateKeyJWTConnection{
		ClientID:      "BUSINESSAPI.abc",
		KeyID:         "key-1",
		PrivateKeyPEM: keyPEM,
		TokenURL:      tokenServer.URL,
		Audience:      "https://account.apple.com/auth/oauth2/v2/token",
	}

	client, err := conn.client(
		context.Background(),
		httpclient.WithSSRFProtection(),
		httpclient.WithSSRFAllowLoopback(),
	)
	require.NoError(t, err)

	_, err = client.Get("https://example.invalid/v1/orgDevices")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token endpoint returned 400")
}

// TestPrivateKeyJWTConnection_RoundTripsThroughStorage pins that the
// credential survives the encrypt/decrypt round trip coredata performs, since
// a dropped field there would surface only as a failing sync.
func TestPrivateKeyJWTConnection_RoundTripsThroughStorage(t *testing.T) {
	t.Parallel()

	keyPEM, _ := newTestKeyPEM(t)

	original := &PrivateKeyJWTConnection{
		ClientID:      "BUSINESSAPI.abc",
		KeyID:         "key-1",
		PrivateKeyPEM: keyPEM,
		TokenURL:      "https://account.apple.com/auth/oauth2/token",
		Audience:      "https://account.apple.com/auth/oauth2/v2/token",
		Scope:         "business.api",
	}

	encoded, err := json.Marshal(original)
	require.NoError(t, err)

	decoded, err := UnmarshalConnection(
		string(ProtocolPrivateKeyJWT),
		"APPLE_BUSINESS_MANAGER",
		encoded,
	)
	require.NoError(t, err)

	restored, ok := decoded.(*PrivateKeyJWTConnection)
	require.True(t, ok, "expected a *PrivateKeyJWTConnection, got %T", decoded)

	assert.Equal(t, original, restored)
	assert.Equal(t, []string{"business.api"}, restored.Scopes())
	assert.Equal(t, ProtocolPrivateKeyJWT, restored.Type())
}

// sha256Sum returns the digest ES256 signs, matching what the connection
// computes over the assertion's signing input.
func sha256Sum(input string) []byte {
	sum := sha256.Sum256([]byte(input))

	return sum[:]
}

func decodeJWTSegment(t *testing.T, segment string) map[string]any {
	t.Helper()

	raw, err := base64.RawURLEncoding.DecodeString(segment)
	require.NoError(t, err)

	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out))

	return out
}
