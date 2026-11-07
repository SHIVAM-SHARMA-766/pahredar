-- +goose Up

-- Incidents (Phase 4B, docs/phase4.md): one living incident per asset that rolls
-- up the asset's problems (the alert rows become its items). When a new problem
-- appears the incident re-surfaces (unread) and re-queues for delivery. Lifecycle
-- (acknowledge/resolve) lands in 4B-M2.
CREATE TABLE incident (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    asset_id        bigint NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    client_id       bigint REFERENCES client(id) ON DELETE CASCADE,
    status          text NOT NULL DEFAULT 'triggered'
                    CHECK (status IN ('triggered', 'acknowledged', 'resolved')),
    severity        text NOT NULL DEFAULT 'medium',
    title           text NOT NULL DEFAULT '',
    item_count      int  NOT NULL DEFAULT 0,
    opened_at       timestamptz NOT NULL DEFAULT now(),
    last_event_at   timestamptz NOT NULL DEFAULT now(),
    acknowledged_at timestamptz,
    resolved_at     timestamptz,
    read_at         timestamptz,
    delivered_at    timestamptz
);

-- At most one open (non-resolved) incident per asset.
CREATE UNIQUE INDEX incident_open_asset_idx ON incident (asset_id) WHERE status <> 'resolved';
CREATE INDEX incident_client_idx ON incident (client_id);
CREATE INDEX incident_last_event_idx ON incident (last_event_at DESC);
CREATE INDEX incident_undelivered_idx ON incident (delivered_at) WHERE delivered_at IS NULL;
CREATE INDEX incident_unread_idx ON incident (read_at) WHERE read_at IS NULL;

-- +goose Down

DROP TABLE incident;
