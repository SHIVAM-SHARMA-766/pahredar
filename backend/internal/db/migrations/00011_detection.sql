-- +goose Up

-- Per-source extras used to build scan commands: for Metasploit the module
-- type, whether it has a non-destructive check, default port, targets; for
-- Nuclei the severity and protocol.
ALTER TABLE exploit ADD COLUMN meta jsonb;

-- Detection content that names CVEs: Sigma rules (logs / SIEM), Suricata
-- rules from ET Open (network), and Nmap NSE scripts (active checks). One
-- row per rule; a rule can name several CVEs.
CREATE TABLE detection_rule (
    source  text NOT NULL CHECK (source IN ('sigma', 'suricata', 'nmap')),
    rule_id text NOT NULL,
    title   text NOT NULL,
    url     text,
    body    text NOT NULL,
    meta    jsonb NOT NULL DEFAULT '{}',
    cve_ids text[] NOT NULL,
    PRIMARY KEY (source, rule_id)
);

CREATE INDEX detection_rule_cve_ids_idx ON detection_rule USING gin (cve_ids);

-- +goose Down

DROP TABLE detection_rule;
ALTER TABLE exploit DROP COLUMN meta;
