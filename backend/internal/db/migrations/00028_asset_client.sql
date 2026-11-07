-- +goose Up

-- Assets belong to a client (Phase 4 tenancy, docs/phase4.md). Uniqueness moves
-- from (kind, value) to (client_id, kind, value) so two clients can track the
-- same domain. Legacy rows keep a NULL client_id (admin-only until reassigned).
ALTER TABLE asset ADD COLUMN client_id bigint REFERENCES client(id) ON DELETE CASCADE;
ALTER TABLE asset DROP CONSTRAINT asset_kind_value_key;
ALTER TABLE asset ADD CONSTRAINT asset_client_kind_value_key UNIQUE (client_id, kind, value);
CREATE INDEX asset_client_idx ON asset (client_id);

-- +goose Down

DROP INDEX asset_client_idx;
ALTER TABLE asset DROP CONSTRAINT asset_client_kind_value_key;
ALTER TABLE asset ADD CONSTRAINT asset_kind_value_key UNIQUE (kind, value);
ALTER TABLE asset DROP COLUMN client_id;
