-- +goose Up

-- KEV added a forensic-triage flag (BOD 26-04).
ALTER TABLE kev ADD COLUMN forensic_triage text;

-- True when any reference is tagged as an exploit; one input to "has public
-- exploit" alongside the exploit and kev tables. Maintained by the CVE upsert;
-- backfilled here for rows written before this column existed.
ALTER TABLE cve ADD COLUMN exploit_ref boolean NOT NULL DEFAULT false;
UPDATE cve SET exploit_ref = true
WHERE EXISTS (
    SELECT 1 FROM jsonb_array_elements(refs) r, jsonb_array_elements_text(coalesce(r -> 'tags', '[]')) t
    WHERE lower(t) = 'exploit'
);

CREATE INDEX kev_cve_id_date_idx ON kev (date_added DESC, cve_id);

-- +goose Down

DROP INDEX kev_cve_id_date_idx;
ALTER TABLE cve DROP COLUMN exploit_ref;
ALTER TABLE kev DROP COLUMN forensic_triage;
