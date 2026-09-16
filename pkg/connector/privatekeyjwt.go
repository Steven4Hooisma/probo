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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.gearno.de/kit/httpclient"
	"go.probo.inc/probo/pkg/crypto/pem"
	proborand "go.probo.inc/probo/pkg/crypto/rand"
)

// PrivateKeyJWTConnection authenticates with the private_key_jwt client
// authentication method of RFC 7523: instead of presenting a shared secret,
// Probo signs a short-lived assertion with a customer-supplied private key and
// exchanges it for a bearer token. The key itself never crosses the network,
// which is why Apple Business Manager mandates this method and neither
// APIKeyConnection nor OAuth2Connection can stand in for it.
//
// The stored fields are the three values Apple's API-account screen issues
// (Client ID, Key ID, private key) plus the endpoints, which are recorded per
// connection rather than resolved from the registry at use time so that a
// deployment-level endpoint override cannot silently re-point an already
// minted credential at a different token issuer.
type PrivateKeyJWTConnection struct {
	ClientID string `json:"client_id"`
	KeyID    string `json:"key_id"`
	// PrivateKeyPEM is the PKCS#8 or SEC1 PEM downloaded from the provider.
	// It is secret: the whole Connection is encrypted at rest by
	// coredata.Connector, and it is never surfaced through the API.
	PrivateKeyPEM string `json:"private_key_pem"`
	// TokenURL is where the assertion is exchanged. Note that it is NOT the
	// same string as Audience for Apple — see that field.
	TokenURL string `json:"token_url"`
	// Audience is the `aud` claim of the assertion. Apple documents the v2
	// path here while the exchange itself POSTs to the unversioned path, so
	// deriving one from the other produces a credential the issuer rejects
	// with invalid_client.
	Audience string `json:"audience"`
	// Scope is sent verbatim on the token request ("business.api" for Apple
	// Business Manager).
	Scope string `json:"scope,omitempty"`
	// AssertionTTL bounds the lifetime of each minted assertion. Apple permits
	// up to 180 days but the assertion is created per exchange and discarded,
	// so a short window is free. Zero means defaultAssertionTTL.
	AssertionTTL time.Duration `json:"assertion_ttl,omitempty"`
}

const (
	// defaultAssertionTTL keeps a minted assertion valid just long enough to
	// survive clock skew and the round trip.
	defaultAssertionTTL = 5 * time.Minute

	// tokenRefreshSkew renews the bearer token early so an in-flight sync
	// cannot be handed a token that expires mid-pagination.
	tokenRefreshSkew = 60 * time.Second

	clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

var _ Connection = (*PrivateKeyJWTConnection)(nil)

func (c *PrivateKeyJWTConnection) Type() ProtocolType {
	return ProtocolPrivateKeyJWT
}

// Scopes reports the granted scopes. The scope is a single space-delimited
// string on the wire; it is split here so callers can treat it like every
// other connection's scope list.
func (c *PrivateKeyJWTConnection) Scopes() []string {
	if c.Scope == "" {
		return nil
	}

	return strings.Fields(c.Scope)
}

func (c *PrivateKeyJWTConnection) MarshalJSON() ([]byte, error) {
	type alias PrivateKeyJWTConnection

	return json.Marshal((*alias)(c))
}

func (c *PrivateKeyJWTConnection) UnmarshalJSON(data []byte) error {
	type alias PrivateKeyJWTConnection

	return json.Unmarshal(data, (*alias)(c))
}

// Validate reports whether the connection carries everything an exchange
// needs, and that the private key is one this code can actually sign with.
// Callers run it at connect time so a bad credential is rejected by the
// create-connector mutation instead of by the first sync an hour later.
func (c *PrivateKeyJWTConnection) Validate() error {
	if c.ClientID == "" {
		return fmt.Errorf("cannot validate private key jwt connection: missing client id")
	}

	if c.KeyID == "" {
		return fmt.Errorf("cannot validate private key jwt connection: missing key id")
	}

	if c.TokenURL == "" {
		return fmt.Errorf("cannot validate private key jwt connection: missing token url")
	}

	if c.Audience == "" {
		return fmt.Errorf("cannot validate private key jwt connection: missing audience")
	}

	if _, err := c.signingKey(); err != nil {
		return err
	}

	return nil
}

// signingKey parses the stored PEM into the ECDSA key the ES256 assertion is
// signed with. Any other key type is rejected rather than silently signed with
// a different algorithm than the `alg` header advertises.
func (c *PrivateKeyJWTConnection) signingKey() (*ecdsa.PrivateKey, error) {
	if c.PrivateKeyPEM == "" {
		return nil, fmt.Errorf("cannot parse private key: empty PEM")
	}

	signer, err := pem.DecodePrivateKey([]byte(c.PrivateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("cannot parse private key: %w", err)
	}

	key, ok := signer.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("cannot use private key: ES256 requires an ECDSA key, got %T", signer)
	}

	if key.Curve.Params().BitSize != 256 {
		return nil, fmt.Errorf("cannot use private key: ES256 requires a P-256 key, got a %d-bit curve", key.Curve.Params().BitSize)
	}

	return key, nil
}

// Client returns an HTTP client that mints a bearer token on first use and
// reuses it until shortly before expiry. The token cache lives on the returned
// transport rather than on the connection so that the persisted value stays a
// pure credential and concurrent syncs never share mutable state.
func (c *PrivateKeyJWTConnection) Client(ctx context.Context) (*http.Client, error) {
	return c.client(ctx, httpclient.WithSSRFProtection())
}

// client builds the authenticated client with explicit transport options, so
// tests can reach an httptest server on loopback without relaxing SSRF
// protection for the production path above.
func (c *PrivateKeyJWTConnection) client(_ context.Context, opts ...httpclient.Option) (*http.Client, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}

	underlying := httpclient.DefaultPooledTransport(opts...)

	return &http.Client{
		Transport: &privateKeyJWTTransport{
			conn:       c,
			underlying: underlying,
			// The exchange must not recurse through this transport, which
			// would try to authenticate the token request with the token it
			// is fetching.
			exchange: &http.Client{Transport: underlying},
		},
	}, nil
}

type privateKeyJWTTransport struct {
	conn       *PrivateKeyJWTConnection
	underlying http.RoundTripper
	exchange   *http.Client

	mu          sync.Mutex
	accessToken string
	expiresAt   time.Time
}

func (t *privateKeyJWTTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.token(req.Context())
	if err != nil {
		return nil, err
	}

	req2 := req.Clone(req.Context())
	req2.Header.Set("Authorization", "Bearer "+token)

	return t.underlying.RoundTrip(req2)
}

func (t *privateKeyJWTTransport) token(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.accessToken != "" && time.Now().Before(t.expiresAt.Add(-tokenRefreshSkew)) {
		return t.accessToken, nil
	}

	assertion, err := t.conn.signAssertion(time.Now())
	if err != nil {
		return "", err
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", t.conn.ClientID)
	form.Set("client_assertion_type", clientAssertionType)
	form.Set("client_assertion", assertion)

	if t.conn.Scope != "" {
		form.Set("scope", t.conn.Scope)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.conn.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("cannot build token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := t.exchange.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot exchange client assertion: %w", err)
	}

	defer resp.Body.Close()

	// The error body can echo request parameters, so it is bounded and never
	// logged by this layer; the caller decides what to record.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("cannot read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("cannot exchange client assertion: token endpoint returned %d", resp.StatusCode)
	}

	var payload struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}

	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("cannot decode token response: %w", err)
	}

	if payload.AccessToken == "" {
		return "", fmt.Errorf("cannot exchange client assertion: token endpoint returned no access token")
	}

	expiresIn := payload.ExpiresIn
	if expiresIn <= 0 {
		// Apple documents 60 minutes. A missing expires_in is treated as a
		// short lifetime rather than an unbounded one so a stale token is
		// re-minted instead of being retried until the provider 401s.
		expiresIn = 300
	}

	t.accessToken = payload.AccessToken
	t.expiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)

	return t.accessToken, nil
}

// signAssertion builds and signs the ES256 client assertion. The JWT is
// assembled by hand rather than pulled from a JWT library because the repo has
// no direct JWT dependency and the assertion is a fixed, five-claim document.
func (c *PrivateKeyJWTConnection) signAssertion(now time.Time) (string, error) {
	key, err := c.signingKey()
	if err != nil {
		return "", err
	}

	jti, err := proborand.HexString(16)
	if err != nil {
		return "", fmt.Errorf("cannot generate assertion id: %w", err)
	}

	ttl := c.AssertionTTL
	if ttl <= 0 {
		ttl = defaultAssertionTTL
	}

	header := map[string]any{
		"alg": "ES256",
		"kid": c.KeyID,
		"typ": "JWT",
	}

	claims := map[string]any{
		"iss": c.ClientID,
		"sub": c.ClientID,
		"aud": c.Audience,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
		"jti": jti,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("cannot encode assertion header: %w", err)
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("cannot encode assertion claims: %w", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) +
		"." + base64.RawURLEncoding.EncodeToString(claimsJSON)

	digest := sha256.Sum256([]byte(signingInput))

	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", fmt.Errorf("cannot sign assertion: %w", err)
	}

	// JWS ES256 requires the fixed-width R||S form, not the ASN.1 DER encoding
	// ecdsa.SignASN1 produces: a DER signature is accepted by no JWT verifier.
	keyBytes := (key.Curve.Params().BitSize + 7) / 8
	signature := make([]byte, 2*keyBytes)
	r.FillBytes(signature[:keyBytes])
	s.FillBytes(signature[keyBytes:])

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
