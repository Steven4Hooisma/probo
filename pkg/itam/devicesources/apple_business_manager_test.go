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

package devicesources_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.probo.inc/probo/pkg/itam/devicesources"
)

func TestAppleBusinessManagerDriver_ListDevices(t *testing.T) {
	t.Parallel()

	t.Run("maps every published attribute", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/orgDevices", r.URL.Path)
			assert.Equal(t, "100", r.URL.Query().Get("limit"))

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"data": [{
					"type": "orgDevices",
					"id": "ABM-1",
					"attributes": {
						"serialNumber": "C02XY1234567",
						"model": "MacBook Pro 14\"",
						"productFamily": "Mac",
						"productType": "MacBookPro18,3",
						"color": "SPACE GRAY",
						"orderNumber": "SO-9912",
						"status": "ASSIGNED",
						"purchaseSourceType": "APPLE",
						"addedToOrgDateTime": "2026-02-01T10:00:00Z",
						"updatedDateTime": "2026-08-14T08:30:00Z"
					}
				}]
			}`))
		}))
		defer server.Close()

		driver := devicesources.NewAppleBusinessManagerDriver(server.Client(), server.URL)

		devices, err := driver.ListDevices(context.Background())
		require.NoError(t, err)
		require.Len(t, devices, 1)

		device := devices[0]
		assert.Equal(t, "ABM-1", device.ExternalID)
		assert.Equal(t, "C02XY1234567", device.SerialNumber)
		assert.Equal(t, `MacBook Pro 14"`, device.Model)
		assert.Equal(t, "Mac", device.ProductFamily)
		assert.Equal(t, "MacBookPro18,3", device.ProductType)
		assert.Equal(t, "SPACE GRAY", device.Color)
		assert.Equal(t, "SO-9912", device.OrderNumber)
		assert.Equal(t, "ASSIGNED", device.Status)
		assert.Equal(t, "APPLE", device.PurchaseSourceType)

		require.NotNil(t, device.AddedAt)
		assert.Equal(t, time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC), device.AddedAt.UTC())
		require.NotNil(t, device.UpdatedAt)
	})

	t.Run("follows pagination to exhaustion", func(t *testing.T) {
		t.Parallel()

		var server *httptest.Server

		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			if r.URL.Query().Get("cursor") == "" {
				_, _ = fmt.Fprintf(w, `{
					"data": [{"id": "ABM-1", "attributes": {"serialNumber": "S1"}}],
					"links": {"next": %q}
				}`, server.URL+"/orgDevices?cursor=page2")

				return
			}

			_, _ = w.Write([]byte(`{"data": [{"id": "ABM-2", "attributes": {"serialNumber": "S2"}}]}`))
		}))
		defer server.Close()

		driver := devicesources.NewAppleBusinessManagerDriver(server.Client(), server.URL)

		devices, err := driver.ListDevices(context.Background())
		require.NoError(t, err)
		require.Len(t, devices, 2)
		assert.Equal(t, "ABM-1", devices[0].ExternalID)
		assert.Equal(t, "ABM-2", devices[1].ExternalID)
	})

	// A `links.next` pointing off-host would replay the bearer token to a
	// third party. It is refused rather than followed, and the refusal fails
	// the whole sync so a partial list never triggers a reconcile.
	t.Run("refuses a cross-host next link", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"data": [{"id": "ABM-1", "attributes": {}}],
				"links": {"next": "https://evil.example/orgDevices"}
			}`))
		}))
		defer server.Close()

		driver := devicesources.NewAppleBusinessManagerDriver(server.Client(), server.URL)

		_, err := driver.ListDevices(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match")
	})

	t.Run("skips records without an identifier", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"data": [
					{"id": "", "attributes": {"serialNumber": "S0"}},
					{"id": "ABM-2", "attributes": {"serialNumber": "S2"}}
				]
			}`))
		}))
		defer server.Close()

		driver := devicesources.NewAppleBusinessManagerDriver(server.Client(), server.URL)

		devices, err := driver.ListDevices(context.Background())
		require.NoError(t, err)
		require.Len(t, devices, 1)
		assert.Equal(t, "ABM-2", devices[0].ExternalID)
	})

	t.Run("surfaces a non-200 response", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer server.Close()

		driver := devicesources.NewAppleBusinessManagerDriver(server.Client(), server.URL)

		_, err := driver.ListDevices(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "got status 401")
	})

	// A malformed timestamp must not fail the sync: one bad date among
	// thousands of valid devices would otherwise block the whole inventory.
	t.Run("tolerates an unparseable timestamp", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"data": [{"id": "ABM-1", "attributes": {"addedToOrgDateTime": "yesterday"}}]
			}`))
		}))
		defer server.Close()

		driver := devicesources.NewAppleBusinessManagerDriver(server.Client(), server.URL)

		devices, err := driver.ListDevices(context.Background())
		require.NoError(t, err)
		require.Len(t, devices, 1)
		assert.Nil(t, devices[0].AddedAt)
	})
}
