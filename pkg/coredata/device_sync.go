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

package coredata

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/jackc/pgx/v5"
	"go.gearno.de/kit/pg"
	"go.probo.inc/probo/pkg/gid"
)

// UpsertFromSource writes one externally sourced device, creating it on first
// sight and refreshing it afterwards. It reconciles on (connector_id,
// external_id) — the origin system's own identifier — rather than on the
// serial number, because a serial can be absent or reused across Apple's
// purchase records while the device id is stable for the life of the
// enrollment.
//
// Only the inventory columns are written. The agent-reported columns
// (hostname, platform, os_version, agent_version, posture) and the owner are
// deliberately untouched on update: an operator who assigned an owner in Probo
// must not have that assignment erased by the next sync, and a device that was
// later enrolled with the agent keeps the richer data the agent supplied.
func (d *Device) UpsertFromSource(
	ctx context.Context,
	conn pg.Tx,
	scope Scoper,
) error {
	if d.Source == "" || !d.Source.IsExternal() {
		return fmt.Errorf("cannot upsert device from source: source %q is not an external source", d.Source)
	}

	if d.ConnectorID == nil || d.ExternalID == nil || *d.ExternalID == "" {
		return fmt.Errorf("cannot upsert device from source: missing connector id or external id")
	}

	labels := d.Labels
	if len(labels) == 0 {
		labels = emptyJSONObject
	}

	q := `
INSERT INTO devices (
    id,
    tenant_id,
    organization_id,
    state,
    source,
    connector_id,
    external_id,
    serial_number,
    model,
    product_family,
    product_type,
    color,
    order_number,
    purchase_source_type,
    labels,
    device_added_at,
    last_synced_at,
    created_at,
    updated_at
) VALUES (
    @device_id,
    @tenant_id,
    @organization_id,
    @state,
    @source,
    @connector_id,
    @external_id,
    @serial_number,
    @model,
    @product_family,
    @product_type,
    @color,
    @order_number,
    @purchase_source_type,
    @labels,
    @device_added_at,
    @last_synced_at,
    @created_at,
    @updated_at
)
ON CONFLICT (connector_id, external_id)
WHERE connector_id IS NOT NULL
  AND external_id IS NOT NULL
  AND deleted_at IS NULL
DO UPDATE SET
    serial_number = EXCLUDED.serial_number,
    model = EXCLUDED.model,
    product_family = EXCLUDED.product_family,
    product_type = EXCLUDED.product_type,
    color = EXCLUDED.color,
    order_number = EXCLUDED.order_number,
    purchase_source_type = EXCLUDED.purchase_source_type,
    labels = devices.labels || EXCLUDED.labels,
    device_added_at = EXCLUDED.device_added_at,
    last_synced_at = EXCLUDED.last_synced_at,
    updated_at = EXCLUDED.updated_at
RETURNING id
`
	args := pgx.StrictNamedArgs{
		"device_id":            d.ID,
		"tenant_id":            scope.GetTenantID(),
		"organization_id":      d.OrganizationID,
		"state":                d.State,
		"source":               d.Source,
		"connector_id":         d.ConnectorID,
		"external_id":          d.ExternalID,
		"serial_number":        d.SerialNumber,
		"model":                d.Model,
		"product_family":       d.ProductFamily,
		"product_type":         d.ProductType,
		"color":                d.Color,
		"order_number":         d.OrderNumber,
		"purchase_source_type": d.PurchaseSourceType,
		"labels":               labels,
		"device_added_at":      d.DeviceAddedAt,
		"last_synced_at":       d.LastSyncedAt,
		"created_at":           d.CreatedAt,
		"updated_at":           d.UpdatedAt,
	}

	rows, err := conn.Query(ctx, q, args)
	if err != nil {
		return fmt.Errorf("cannot upsert device from source: %w", err)
	}

	// The RETURNING id is what distinguishes an insert from an update: on
	// conflict the row keeps the id it already had, and the caller's freshly
	// minted GID must be discarded rather than reported as the device's id.
	id, err := pgx.CollectExactlyOneRow(rows, pgx.RowTo[gid.GID])
	if err != nil {
		return fmt.Errorf("cannot collect upserted device id: %w", err)
	}

	d.ID = id

	return nil
}

// RevokeMissingSyncedDevices revokes every device belonging to connectorID
// that the latest sync did not see, identified by a last_synced_at older than
// the instant the run began.
//
// The rows are revoked rather than deleted so the device's history, its owner
// assignment and anything linked to it survive: a device disappearing from
// Apple Business Manager means it left the organization's purchase records,
// which is exactly the fact an auditor wants preserved, not erased.
func (ds *Devices) RevokeMissingSyncedDevices(
	ctx context.Context,
	conn pg.Querier,
	scope Scoper,
	connectorID gid.GID,
	syncStartedAt time.Time,
	now time.Time,
) (int64, error) {
	q := `
UPDATE devices
SET
    state = 'REVOKED',
    revoked_at = @now,
    updated_at = @now
WHERE
    %s
    AND connector_id = @connector_id
    AND state != 'REVOKED'
    AND deleted_at IS NULL
    AND (last_synced_at IS NULL OR last_synced_at < @sync_started_at)
`
	q = fmt.Sprintf(q, scope.SQLFragment())

	args := pgx.StrictNamedArgs{
		"connector_id":    connectorID,
		"sync_started_at": syncStartedAt,
		"now":             now,
	}
	maps.Copy(args, scope.SQLArguments())

	tag, err := conn.Exec(ctx, q, args)
	if err != nil {
		return 0, fmt.Errorf("cannot revoke missing synced devices: %w", err)
	}

	return tag.RowsAffected(), nil
}

// CountByConnectorID reports how many live devices a connector currently
// supplies, for surfacing the sync result without paging the whole list.
func (ds *Devices) CountByConnectorID(
	ctx context.Context,
	conn pg.Querier,
	scope Scoper,
	connectorID gid.GID,
) (int, error) {
	q := `
SELECT
	COUNT(id)
FROM
	devices
WHERE
	%s
	AND connector_id = @connector_id
	AND state != 'REVOKED'
	AND deleted_at IS NULL
`
	q = fmt.Sprintf(q, scope.SQLFragment())

	args := pgx.StrictNamedArgs{"connector_id": connectorID}
	maps.Copy(args, scope.SQLArguments())

	rows, err := conn.Query(ctx, q, args)
	if err != nil {
		return 0, fmt.Errorf("cannot count devices by connector: %w", err)
	}

	count, err := pgx.CollectExactlyOneRow(rows, pgx.RowTo[int])
	if err != nil {
		return 0, fmt.Errorf("cannot collect device count: %w", err)
	}

	return count, nil
}

// ErrNoDeviceSyncAvailable is returned when no connector is due for a device
// sync, so the worker can distinguish an idle poll from a failure.
var ErrNoDeviceSyncAvailable = fmt.Errorf("no device sync available")

// DeviceSyncClaim identifies one connector the worker has taken ownership of
// for this round.
type DeviceSyncClaim struct {
	ConnectorID    gid.GID `db:"id"`
	OrganizationID gid.GID `db:"organization_id"`
	TenantID       string  `db:"tenant_id"`
}

// ClaimNextDeviceSync takes the connector that has gone longest without a
// device sync among the given providers, stamping devices_synced_at before
// returning it.
//
// The stamp is written on claim rather than on completion so that a sync which
// crashes mid-run does not leave its connector permanently due and hot-loop the
// provider; the next run picks it up one interval later. SKIP LOCKED lets
// several workers share the queue without blocking on each other.
//
// It is not scoped to a tenant: the worker runs deployment-wide, and the
// returned TenantID is what the caller builds its scope from.
func ClaimNextDeviceSync(
	ctx context.Context,
	tx pg.Tx,
	providers []ConnectorProvider,
	staleBefore time.Time,
	now time.Time,
) (DeviceSyncClaim, error) {
	if len(providers) == 0 {
		return DeviceSyncClaim{}, ErrNoDeviceSyncAvailable
	}

	names := make([]string, 0, len(providers))
	for _, p := range providers {
		names = append(names, p.String())
	}

	q := `
UPDATE connectors
SET devices_synced_at = @now
WHERE id = (
    SELECT id
    FROM connectors
    WHERE
        provider = ANY(@providers::connector_provider[])
        AND (devices_synced_at IS NULL OR devices_synced_at < @stale_before)
    ORDER BY devices_synced_at ASC NULLS FIRST
    LIMIT 1
    FOR UPDATE SKIP LOCKED
)
RETURNING id, organization_id, tenant_id
`
	args := pgx.StrictNamedArgs{
		"providers":    names,
		"stale_before": staleBefore,
		"now":          now,
	}

	rows, err := tx.Query(ctx, q, args)
	if err != nil {
		return DeviceSyncClaim{}, fmt.Errorf("cannot claim device sync: %w", err)
	}

	claim, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByName[DeviceSyncClaim])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return DeviceSyncClaim{}, ErrNoDeviceSyncAvailable
		}

		return DeviceSyncClaim{}, fmt.Errorf("cannot collect device sync claim: %w", err)
	}

	return claim, nil
}
