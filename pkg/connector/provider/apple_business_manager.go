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

package provider

import (
	"context"
	"net/http"

	"go.gearno.de/kit/log"
	"go.probo.inc/probo/pkg/coredata"
	"go.probo.inc/probo/pkg/itam/devicesources"
)

// appleBusinessManagerRegistration wires Apple Business Manager as a device
// inventory source.
//
// It is the first registration with no NewDriver: Apple Business Manager
// publishes hardware, not application accounts, so it has nothing to say to an
// access review and is filtered out of that catalog by the nil factory. It is
// likewise the first provider on the private_key_jwt path — Apple issues a
// Client ID, a Key ID and an EC private key, and accepts no secret-based or
// authorization-code flow.
func appleBusinessManagerRegistration() *Registration {
	return &Registration{
		Provider:    coredata.ConnectorProviderAppleBusinessManager,
		DisplayName: "Apple Business Manager",
		Endpoints: Endpoints{
			// The exchange POSTs to the unversioned path while the assertion
			// must claim the versioned one. They are not interchangeable:
			// swapping either produces invalid_client.
			Token:         "https://account.apple.com/auth/oauth2/token",
			TokenAudience: "https://account.apple.com/auth/oauth2/v2/token",
			APIBase:       "https://api-business.apple.com/v1",
			// Listing a single device is the cheapest call that proves both
			// the assertion and the granted scope, and it shares APIBase's
			// host as Register requires.
			Probe: "https://api-business.apple.com/v1/orgDevices?limit=1",
		},
		SupportsPrivateKeyJWT: true,
		PrivateKeyJWTScope:    "business.api",
		NewDeviceSource: func(
			_ context.Context,
			c *http.Client,
			_ *coredata.Connector,
			_ *log.Logger,
			ep Endpoints,
		) (devicesources.Driver, error) {
			return devicesources.NewAppleBusinessManagerDriver(c, ep.APIBase), nil
		},
	}
}
