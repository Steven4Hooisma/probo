// Copyright (c) 2025-2026 Probo Inc <hello@probo.com>.
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

package itam

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.gearno.de/kit/log"
	"go.gearno.de/kit/pg"
	"go.probo.inc/probo/pkg/coredata"
	"go.probo.inc/probo/pkg/gid"
	"go.probo.inc/probo/pkg/itam/devicesources"
)

type (
	// SyncDevicesRequest names one connector to reconcile the device register
	// against.
	SyncDevicesRequest struct {
		OrganizationID gid.GID
		ConnectorID    gid.GID
	}

	// SyncDevicesResult reports what one reconciliation changed. Seen counts
	// the records the provider published; Revoked counts the devices that had
	// been synced before and were absent this time.
	SyncDevicesResult struct {
		Seen    int
		Revoked int64
	}
)

// deviceSourceStatusLabel namespaces the origin system's own lifecycle value
// inside the device's labels. It is kept as a label rather than promoted to a
// column because its vocabulary is provider-specific and adding a column per
// provider's status enum would not generalise.
const deviceSourceStatusLabel = "device_source_status"

// SyncDevices mirrors one connector's device inventory into the device
// register: every device the provider publishes is inserted or refreshed, and
// every previously synced device the provider no longer publishes is revoked.
//
// The provider is listed first and persisted second, in a single transaction,
// so a provider error leaves the register exactly as it was. A partial list
// would otherwise be indistinguishable from devices having been removed and
// would revoke the estate.
func (s *Service) SyncDevices(
	ctx context.Context,
	scope coredata.Scoper,
	req SyncDevicesRequest,
) (*SyncDevicesResult, error) {
	syncStartedAt := time.Now()

	dbConnector := &coredata.Connector{}

	err := s.pg.WithConn(ctx, func(ctx context.Context, conn pg.Querier) error {
		return dbConnector.LoadByID(ctx, conn, scope, req.ConnectorID, s.encryptionKey)
	})
	if err != nil {
		return nil, fmt.Errorf("cannot load connector %s: %w", req.ConnectorID, err)
	}

	if dbConnector.OrganizationID != req.OrganizationID {
		return nil, fmt.Errorf("cannot sync devices: connector %s does not belong to organization %s", req.ConnectorID, req.OrganizationID)
	}

	driver, err := s.deviceSourceDriver(ctx, dbConnector)
	if err != nil {
		return nil, err
	}

	sourceDevices, err := driver.ListDevices(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot list devices from %s: %w", dbConnector.Provider, err)
	}

	source, err := deviceSourceForProvider(dbConnector.Provider)
	if err != nil {
		return nil, err
	}

	result := &SyncDevicesResult{Seen: len(sourceDevices)}

	err = s.pg.WithTx(ctx, func(ctx context.Context, tx pg.Tx) error {
		now := time.Now()

		for _, sourceDevice := range sourceDevices {
			device, err := newSyncedDevice(dbConnector, source, sourceDevice, syncStartedAt, now)
			if err != nil {
				return err
			}

			if err := device.UpsertFromSource(ctx, tx, scope); err != nil {
				return fmt.Errorf("cannot upsert device %s: %w", sourceDevice.ExternalID, err)
			}
		}

		devices := &coredata.Devices{}

		revoked, err := devices.RevokeMissingSyncedDevices(
			ctx,
			tx,
			scope,
			req.ConnectorID,
			syncStartedAt,
			now,
		)
		if err != nil {
			return err
		}

		result.Revoked = revoked

		return nil
	})
	if err != nil {
		return nil, err
	}

	s.logger.InfoCtx(
		ctx,
		"synced devices from connector",
		log.String("provider", string(dbConnector.Provider)),
		log.Int("seen", result.Seen),
		log.Int64("revoked", result.Revoked),
	)

	return result, nil
}

// newSyncedDevice maps one provider record onto a device row. The freshly
// minted GID is used only when the row does not already exist; UpsertFromSource
// replaces it with the stored id on conflict.
func newSyncedDevice(
	dbConnector *coredata.Connector,
	source coredata.DeviceSource,
	sourceDevice devicesources.Device,
	syncStartedAt time.Time,
	now time.Time,
) (*coredata.Device, error) {
	connectorID := dbConnector.ID
	externalID := sourceDevice.ExternalID

	labels := json.RawMessage(`{}`)

	if sourceDevice.Status != "" {
		encoded, err := json.Marshal(map[string]string{deviceSourceStatusLabel: sourceDevice.Status})
		if err != nil {
			return nil, fmt.Errorf("cannot encode device labels: %w", err)
		}

		labels = encoded
	}

	return &coredata.Device{
		ID:             gid.New(dbConnector.OrganizationID.TenantID(), coredata.DeviceEntityType),
		OrganizationID: dbConnector.OrganizationID,
		// A synced device is a real, in-service asset the moment the provider
		// publishes it: there is no enrollment handshake to wait for, so
		// PENDING — which means "awaiting agent enrollment" — would never
		// resolve.
		State:              coredata.DeviceStateActive,
		Source:             source,
		ConnectorID:        &connectorID,
		ExternalID:         &externalID,
		SerialNumber:       optionalString(sourceDevice.SerialNumber),
		Model:              optionalString(sourceDevice.Model),
		ProductFamily:      optionalString(sourceDevice.ProductFamily),
		ProductType:        optionalString(sourceDevice.ProductType),
		Color:              optionalString(sourceDevice.Color),
		OrderNumber:        optionalString(sourceDevice.OrderNumber),
		PurchaseSourceType: optionalString(sourceDevice.PurchaseSourceType),
		Labels:             labels,
		DeviceAddedAt:      sourceDevice.AddedAt,
		// Stamped with the instant the run began, not the instant this row was
		// written, so that RevokeMissingSyncedDevices' `last_synced_at <
		// syncStartedAt` comparison cannot revoke a device written moments
		// after the cutoff during a long sync.
		LastSyncedAt: &syncStartedAt,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

// optionalString maps the provider's empty string onto NULL, so an attribute
// the provider omits is stored as absent rather than as a blank value that
// would read as "known to be empty".
func optionalString(v string) *string {
	if v == "" {
		return nil
	}

	return &v
}

// deviceSourceForProvider maps a connector provider onto the device source
// recorded on the row. It is an explicit switch rather than a string
// conversion so that adding a provider without deciding how its devices are
// labelled fails here instead of writing an invalid enum.
func deviceSourceForProvider(p coredata.ConnectorProvider) (coredata.DeviceSource, error) {
	switch p {
	case coredata.ConnectorProviderAppleBusinessManager:
		return coredata.DeviceSourceAppleBusinessManager, nil
	}

	return "", fmt.Errorf("cannot sync devices: provider %q is not a device source", p)
}

func (s *Service) deviceSourceDriver(
	ctx context.Context,
	dbConnector *coredata.Connector,
) (devicesources.Driver, error) {
	reg, ok := s.providerRegistry.Get(dbConnector.Provider)
	if !ok || reg.NewDeviceSource == nil {
		return nil, fmt.Errorf("cannot sync devices: provider %q has no device source driver", dbConnector.Provider)
	}

	httpClient, err := deviceSourceHTTPClient(ctx, dbConnector)
	if err != nil {
		return nil, err
	}

	return reg.NewDeviceSource(ctx, httpClient, dbConnector, s.logger, reg.Endpoints)
}

// deviceSourceHTTPClient builds the authenticated client for the connection.
// Unlike the access-review path there is no OAuth2 refresh to persist: a
// private_key_jwt connection mints its own short-lived token from the stored
// key on every use, so nothing about the credential changes here.
func deviceSourceHTTPClient(
	ctx context.Context,
	dbConnector *coredata.Connector,
) (*http.Client, error) {
	if dbConnector.Connection == nil {
		return nil, fmt.Errorf("cannot build client for connector %s: connection is empty", dbConnector.ID)
	}

	client, err := dbConnector.Connection.Client(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot build client for %s connector: %w", dbConnector.Provider, err)
	}

	return client, nil
}
