-- Copyright (c) 2026 Probo Inc <hello@probo.com>.
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in
-- all copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.

-- Devices may now originate from an external inventory system (Apple Business
-- Manager) instead of an enrolled agent. Such a device has no agent binary, no
-- API key and no posture telemetry, so every column the agent populates stays
-- NULL and the agent-only CHECK constraints are re-scoped to source = 'AGENT'.
CREATE TYPE device_source AS ENUM (
    'AGENT',
    'APPLE_BUSINESS_MANAGER'
);

ALTER TABLE devices
    ADD COLUMN source device_source NOT NULL DEFAULT 'AGENT',
    ADD COLUMN connector_id TEXT REFERENCES connectors(id) ON UPDATE CASCADE ON DELETE CASCADE,
    ADD COLUMN external_id TEXT,
    ADD COLUMN model TEXT,
    ADD COLUMN product_family TEXT,
    ADD COLUMN product_type TEXT,
    ADD COLUMN color TEXT,
    ADD COLUMN order_number TEXT,
    ADD COLUMN purchase_source_type TEXT,
    ADD COLUMN device_added_at TIMESTAMP WITH TIME ZONE,
    ADD COLUMN last_synced_at TIMESTAMP WITH TIME ZONE;

-- The agent reports hardware UUID, hostname, platform, OS and agent version on
-- enrollment; an externally sourced device reports none of them, so requiring
-- them of every ACTIVE row would make an ABM device unrepresentable.
ALTER TABLE devices
    DROP CONSTRAINT devices_active_fields_check;

ALTER TABLE devices
    ADD CONSTRAINT devices_active_fields_check CHECK (
        source != 'AGENT'
        OR state != 'ACTIVE'
        OR (
            hardware_uuid IS NOT NULL
            AND hostname IS NOT NULL
            AND platform IS NOT NULL
            AND os_version IS NOT NULL
            AND agent_version IS NOT NULL
            AND enrolled_at IS NOT NULL
            AND last_seen_at IS NOT NULL
        )
    );

-- api_key_hash authenticates the agent's own callbacks. A synced device never
-- calls back, so it holds no key and the ACTIVE-requires-a-key rule applies to
-- agent devices only.
ALTER TABLE devices
    DROP CONSTRAINT devices_active_api_key_hash_check;

ALTER TABLE devices
    ADD CONSTRAINT devices_active_api_key_hash_check CHECK (
        source != 'AGENT'
        OR state != 'ACTIVE'
        OR api_key_hash IS NOT NULL
    );

-- A synced device is only reconcilable against its origin when it carries both
-- the connector it came from and that system's own identifier for it; without
-- the pair the next sync cannot tell an update from an insert.
ALTER TABLE devices
    ADD CONSTRAINT devices_external_source_check CHECK (
        source = 'AGENT'
        OR (connector_id IS NOT NULL AND external_id IS NOT NULL)
    );

-- Conversely an agent device is never tied to a connector, so the columns stay
-- NULL rather than holding a stale connector after a disconnect.
ALTER TABLE devices
    ADD CONSTRAINT devices_agent_source_check CHECK (
        source != 'AGENT'
        OR (connector_id IS NULL AND external_id IS NULL)
    );

-- The sync upserts on this pair. Soft-deleted rows are excluded so a device
-- removed in Probo and later re-appearing in ABM can be re-created.
CREATE UNIQUE INDEX devices_connector_external_id_idx
    ON devices (connector_id, external_id)
    WHERE connector_id IS NOT NULL
      AND external_id IS NOT NULL
      AND deleted_at IS NULL;

CREATE INDEX devices_organization_source_idx
    ON devices (organization_id, source);

-- The device sync worker claims connectors round-robin by staleness, so the
-- due-time lives on the connector rather than being derived from its devices:
-- a connector whose inventory is empty has no device row to date, and would
-- otherwise never be claimed.
ALTER TABLE connectors
    ADD COLUMN devices_synced_at TIMESTAMP WITH TIME ZONE;

CREATE INDEX connectors_device_sync_idx
    ON connectors (provider, devices_synced_at NULLS FIRST);
