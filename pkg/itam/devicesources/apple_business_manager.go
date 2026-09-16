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

package devicesources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// abmPageLimit is the page size requested from Apple. The API accepts 1-1000;
// 100 keeps each response small enough to decode without buffering megabytes
// while still finishing a several-thousand-device estate in a few requests.
const abmPageLimit = 100

// abmMaxPages bounds pagination so a malformed or looping `links.next` cannot
// spin the sync worker forever. At abmPageLimit per page this covers 100k
// devices, which is far beyond any single Apple Business Manager org.
const abmMaxPages = 1000

// abmMaxResponseBytes bounds a single page's body. The connection's transport
// already enforces SSRF protection; this guards against a truncated or
// adversarial response exhausting memory.
const abmMaxResponseBytes = 8 << 20

// AppleBusinessManagerDriver mirrors the device list from Apple Business
// Manager's `/orgDevices` collection.
//
// Apple publishes purchase-time facts (serial, model, order) and no runtime
// telemetry: there is no OS version, hostname or last-check-in here. That is
// why a synced device fills the inventory columns and leaves every
// agent-reported column NULL rather than guessing at them.
type AppleBusinessManagerDriver struct {
	client  *http.Client
	baseURL string
}

var _ Driver = (*AppleBusinessManagerDriver)(nil)

// NewAppleBusinessManagerDriver returns a driver reading from baseURL, which
// is the registration's APIBase so a deployment endpoint override reaches the
// driver rather than being bypassed by a hardcoded host.
func NewAppleBusinessManagerDriver(client *http.Client, baseURL string) *AppleBusinessManagerDriver {
	return &AppleBusinessManagerDriver{client: client, baseURL: baseURL}
}

// abmDeviceResponse is the JSON:API envelope Apple returns. Only the fields
// Probo stores are decoded; unknown members are ignored so Apple adding an
// attribute cannot break the sync.
type abmDeviceResponse struct {
	Data []struct {
		ID         string `json:"id"`
		Attributes struct {
			SerialNumber       string `json:"serialNumber"`
			Model              string `json:"model"`
			ProductFamily      string `json:"productFamily"`
			ProductType        string `json:"productType"`
			Color              string `json:"color"`
			OrderNumber        string `json:"orderNumber"`
			Status             string `json:"status"`
			PurchaseSourceType string `json:"purchaseSourceType"`
			AddedToOrgDateTime string `json:"addedToOrgDateTime"`
			UpdatedDateTime    string `json:"updatedDateTime"`
		} `json:"attributes"`
	} `json:"data"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
}

func (d *AppleBusinessManagerDriver) ListDevices(ctx context.Context) ([]Device, error) {
	next, err := url.JoinPath(d.baseURL, "orgDevices")
	if err != nil {
		return nil, fmt.Errorf("cannot build apple business manager devices URL: %w", err)
	}

	parsed, err := url.Parse(next)
	if err != nil {
		return nil, fmt.Errorf("cannot parse apple business manager devices URL: %w", err)
	}

	query := parsed.Query()
	query.Set("limit", fmt.Sprintf("%d", abmPageLimit))
	parsed.RawQuery = query.Encode()
	next = parsed.String()

	// Apple's own host for this collection, used to refuse a `links.next` that
	// points somewhere else. Following an attacker-controlled next link would
	// replay the bearer token to a third-party host, which SSRF protection
	// alone does not prevent because the target may be perfectly routable.
	origin, err := url.Parse(d.baseURL)
	if err != nil {
		return nil, fmt.Errorf("cannot parse apple business manager base URL: %w", err)
	}

	var devices []Device

	for page := 0; next != ""; page++ {
		if page >= abmMaxPages {
			return nil, fmt.Errorf("cannot list apple business manager devices: pagination exceeded %d pages", abmMaxPages)
		}

		body, err := d.get(ctx, next)
		if err != nil {
			return nil, err
		}

		var payload abmDeviceResponse
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, fmt.Errorf("cannot decode apple business manager devices: %w", err)
		}

		for _, item := range payload.Data {
			if item.ID == "" {
				// Without the origin identifier the record cannot be
				// reconciled on the next run, so it is skipped rather than
				// inserted as a row that would duplicate every sync.
				continue
			}

			devices = append(devices, Device{
				ExternalID:         item.ID,
				SerialNumber:       item.Attributes.SerialNumber,
				Model:              item.Attributes.Model,
				ProductFamily:      item.Attributes.ProductFamily,
				ProductType:        item.Attributes.ProductType,
				Color:              item.Attributes.Color,
				OrderNumber:        item.Attributes.OrderNumber,
				PurchaseSourceType: item.Attributes.PurchaseSourceType,
				Status:             item.Attributes.Status,
				AddedAt:            parseABMTime(item.Attributes.AddedToOrgDateTime),
				UpdatedAt:          parseABMTime(item.Attributes.UpdatedDateTime),
			})
		}

		next, err = nextPageURL(payload.Links.Next, origin)
		if err != nil {
			return nil, err
		}
	}

	return devices, nil
}

// nextPageURL validates the server-supplied pagination link, returning "" when
// the page was the last one.
func nextPageURL(raw string, origin *url.URL) (string, error) {
	if raw == "" {
		return "", nil
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("cannot parse apple business manager next page URL: %w", err)
	}

	if !parsed.IsAbs() {
		return origin.ResolveReference(parsed).String(), nil
	}

	if !strings.EqualFold(parsed.Host, origin.Host) {
		return "", fmt.Errorf(
			"cannot follow apple business manager next page URL: host %q does not match %q",
			parsed.Host,
			origin.Host,
		)
	}

	return parsed.String(), nil
}

func (d *AppleBusinessManagerDriver) get(ctx context.Context, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot build apple business manager request: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot call apple business manager: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, abmMaxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("cannot read apple business manager response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cannot call apple business manager: got status %d", resp.StatusCode)
	}

	return body, nil
}

// parseABMTime accepts the RFC 3339 timestamps Apple emits and returns nil for
// an absent or unparseable value, so one malformed date never fails a sync of
// several thousand otherwise-valid devices.
func parseABMTime(raw string) *time.Time {
	if raw == "" {
		return nil
	}

	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil
	}

	return &t
}
