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
	"errors"
	"time"

	"go.gearno.de/kit/log"
	"go.gearno.de/kit/pg"
	"go.gearno.de/kit/worker"
	"go.probo.inc/probo/pkg/coredata"
)

// DefaultDeviceSyncInterval is how stale a connector's device inventory may get
// before the worker refreshes it. Apple Business Manager reflects purchases and
// MDM assignments, which change on the order of days, so an hourly refresh is
// far more than enough and keeps well clear of any rate limit.
const DefaultDeviceSyncInterval = time.Hour

// deviceSyncHandler claims one connector at a time and reconciles its device
// inventory into the register.
type deviceSyncHandler struct {
	service   *Service
	pg        *pg.Client
	providers []coredata.ConnectorProvider
	interval  time.Duration
	logger    *log.Logger
}

// NewDeviceSyncWorker builds the worker that keeps externally sourced devices
// current. providers is taken from the registry rather than hardcoded, so a
// provider that gains a NewDeviceSource factory is picked up with no change
// here; an empty list makes Claim a no-op rather than an error.
func NewDeviceSyncWorker(
	service *Service,
	pgClient *pg.Client,
	providers []coredata.ConnectorProvider,
	interval time.Duration,
	logger *log.Logger,
	opts ...worker.Option,
) *worker.Worker[coredata.DeviceSyncClaim] {
	if interval <= 0 {
		interval = DefaultDeviceSyncInterval
	}

	h := &deviceSyncHandler{
		service:   service,
		pg:        pgClient,
		providers: providers,
		interval:  interval,
		logger:    logger,
	}

	defaultOpts := []worker.Option{
		// The poll is a single indexed lookup that almost always finds
		// nothing, so it can run often; the interval above, not this one,
		// controls how often a given connector is actually refreshed.
		worker.WithInterval(time.Minute),
		// One in-flight sync per worker: a sync holds a transaction open for
		// the length of the upsert loop, and device inventories are small
		// enough that there is nothing to gain from overlapping them.
		worker.WithMaxConcurrency(1),
	}

	return worker.New(
		"device-sync-worker",
		h,
		logger,
		append(defaultOpts, opts...)...,
	)
}

func (h *deviceSyncHandler) Claim(ctx context.Context) (coredata.DeviceSyncClaim, error) {
	if len(h.providers) == 0 {
		return coredata.DeviceSyncClaim{}, worker.ErrNoTask
	}

	var claim coredata.DeviceSyncClaim

	now := time.Now()

	err := h.pg.WithTx(
		ctx,
		func(ctx context.Context, tx pg.Tx) error {
			var err error

			claim, err = coredata.ClaimNextDeviceSync(
				ctx,
				tx,
				h.providers,
				now.Add(-h.interval),
				now,
			)

			return err
		},
	)
	if err != nil {
		if errors.Is(err, coredata.ErrNoDeviceSyncAvailable) {
			return coredata.DeviceSyncClaim{}, worker.ErrNoTask
		}

		return coredata.DeviceSyncClaim{}, err
	}

	return claim, nil
}

func (h *deviceSyncHandler) Process(ctx context.Context, claim coredata.DeviceSyncClaim) error {
	scope := coredata.NewScopeFromObjectID(claim.ConnectorID)

	result, err := h.service.SyncDevices(
		ctx,
		scope,
		SyncDevicesRequest{
			OrganizationID: claim.OrganizationID,
			ConnectorID:    claim.ConnectorID,
		},
	)
	if err != nil {
		// The claim already stamped devices_synced_at, so a failure here costs
		// one interval rather than retrying immediately against a provider
		// that is likely still failing. Returning nil keeps the worker from
		// treating an expired customer credential as a worker fault.
		h.logger.WarnCtx(
			ctx,
			"cannot sync devices for connector",
			log.String("connector_id", claim.ConnectorID.String()),
			log.Error(err),
		)

		return nil
	}

	h.logger.InfoCtx(
		ctx,
		"device sync completed",
		log.String("connector_id", claim.ConnectorID.String()),
		log.Int("seen", result.Seen),
		log.Int64("revoked", result.Revoked),
	)

	return nil
}
