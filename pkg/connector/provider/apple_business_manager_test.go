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

package provider_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.probo.inc/probo/pkg/connector/provider"
	"go.probo.inc/probo/pkg/coredata"
)

func TestAppleBusinessManagerRegistration(t *testing.T) {
	t.Parallel()

	r := provider.NewBuiltinRegistry()

	reg, ok := r.Get(coredata.ConnectorProviderAppleBusinessManager)
	require.True(t, ok, "Apple Business Manager must be registered")

	t.Run("authenticates with private key JWT only", func(t *testing.T) {
		t.Parallel()

		assert.True(t, reg.SupportsPrivateKeyJWT)
		assert.False(t, reg.SupportsAPIKey)
		assert.False(t, reg.SupportsClientCredentials)
		assert.False(t, reg.ManagedAPIKey)
	})

	// Apple documents the versioned path as the assertion's audience while the
	// exchange POSTs to the unversioned one. Collapsing the two is the single
	// easiest way to break this connector, and the failure surfaces as
	// invalid_client — which reads like a bad customer key. Pin them apart.
	t.Run("audience is distinct from the token endpoint", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, "https://account.apple.com/auth/oauth2/token", reg.Endpoints.Token)
		assert.Equal(t, "https://account.apple.com/auth/oauth2/v2/token", reg.Endpoints.TokenAudience)
		assert.NotEqual(t, reg.Endpoints.Token, reg.Endpoints.TokenAudience)
	})

	t.Run("scope is the business API scope", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, "business.api", reg.PrivateKeyJWTScope)
	})

	// Apple Business Manager publishes hardware, not accounts. A NewDriver
	// here would put it in the access-review catalog, where it has nothing to
	// review.
	t.Run("is a device source and not an access review driver", func(t *testing.T) {
		t.Parallel()

		assert.NotNil(t, reg.NewDeviceSource)
		assert.Nil(t, reg.NewDriver)

		var found bool

		for _, source := range r.DeviceSources() {
			if source.Provider == coredata.ConnectorProviderAppleBusinessManager {
				found = true
			}
		}

		assert.True(t, found, "Apple Business Manager must appear in DeviceSources()")
	})
}

// TestRegisterPrivateKeyJWTRequiresEndpoints pins the startup guard: a
// private_key_jwt provider missing its token endpoint or audience would mint
// assertions the issuer rejects, so registration must fail at boot rather than
// at first sync.
func TestRegisterPrivateKeyJWTRequiresEndpoints(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		reg     *provider.Registration
		wantErr string
	}{
		{
			name: "missing token endpoint",
			reg: &provider.Registration{
				Provider:              coredata.ConnectorProviderAppleBusinessManager,
				DisplayName:           "Apple Business Manager",
				SupportsPrivateKeyJWT: true,
				Endpoints:             provider.Endpoints{TokenAudience: "https://example.com/v2/token"},
			},
			wantErr: "requires Endpoints.Token",
		},
		{
			name: "missing audience",
			reg: &provider.Registration{
				Provider:              coredata.ConnectorProviderAppleBusinessManager,
				DisplayName:           "Apple Business Manager",
				SupportsPrivateKeyJWT: true,
				Endpoints:             provider.Endpoints{Token: "https://example.com/token"},
			},
			wantErr: "requires Endpoints.TokenAudience",
		},
		{
			name: "audience without the private key JWT path",
			reg: &provider.Registration{
				Provider:    coredata.ConnectorProviderAppleBusinessManager,
				DisplayName: "Apple Business Manager",
				Endpoints:   provider.Endpoints{TokenAudience: "https://example.com/v2/token"},
			},
			wantErr: "requires SupportsPrivateKeyJWT",
		},
		{
			name: "scope without the private key JWT path",
			reg: &provider.Registration{
				Provider:           coredata.ConnectorProviderAppleBusinessManager,
				DisplayName:        "Apple Business Manager",
				PrivateKeyJWTScope: "business.api",
			},
			wantErr: "PrivateKeyJWTScope requires SupportsPrivateKeyJWT",
		},
	} {
		t.Run(tc.name+" is rejected", func(t *testing.T) {
			t.Parallel()

			err := provider.NewRegistry().Register(tc.reg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}
