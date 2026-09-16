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

// Package devicesources holds the read-only drivers that mirror a third-party
// device inventory into Probo's device register.
//
// It deliberately mirrors the shape of pkg/accessreview/drivers — one file per
// provider, a narrow interface, no persistence — but stays a separate package
// because the two consume different connectors and produce different records.
// pkg/connector/provider imports this package to wire the NewDeviceSource
// factory; nothing here may import pkg/connector/provider or pkg/itam in
// return, or the registry would not compile.
package devicesources

import (
	"context"
	"time"
)

// Device is one record as published by the origin system. Every field except
// ExternalID is optional: inventory systems disagree about what they expose,
// and an absent value must be distinguishable from an empty one so a sync
// never overwrites a populated column with "".
type Device struct {
	// ExternalID is the origin system's own identifier. It must be stable
	// across syncs — it is the key the upsert reconciles on, so a provider
	// that renumbers its devices would duplicate them here.
	ExternalID string

	SerialNumber       string
	Model              string
	ProductFamily      string
	ProductType        string
	Color              string
	OrderNumber        string
	PurchaseSourceType string

	// Status is the origin system's own lifecycle value, kept verbatim
	// because its vocabulary is provider-specific and mapping it onto
	// coredata.DeviceState would discard the distinction between, say, an
	// unassigned device and a released one.
	Status string

	// AddedAt is when the origin system first recorded the device, which is
	// not when Probo first saw it.
	AddedAt *time.Time
	// UpdatedAt is the origin system's last-modified timestamp, used to skip
	// writes for records that have not changed.
	UpdatedAt *time.Time
}

// Driver lists the devices an organization holds in one third-party
// inventory. Implementations are read-only: Probo never writes back.
type Driver interface {
	// ListDevices returns every device visible to the connection, following
	// the provider's pagination to exhaustion. It returns an error rather
	// than a partial list, because a partial list is indistinguishable from
	// devices having been removed and would trigger a spurious reconcile.
	ListDevices(ctx context.Context) ([]Device, error)
}
