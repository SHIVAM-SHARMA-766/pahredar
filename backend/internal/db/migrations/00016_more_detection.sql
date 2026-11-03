-- +goose Up

-- More detection sources: Splunk security_content, Elastic detection-rules,
-- Snort 3 community rules, and YARA (signature-base).
ALTER TABLE detection_rule DROP CONSTRAINT detection_rule_source_check;
ALTER TABLE detection_rule ADD CONSTRAINT detection_rule_source_check
    CHECK (source IN ('sigma', 'suricata', 'nmap', 'splunk', 'elastic', 'snort', 'yara'));

-- +goose Down

DELETE FROM detection_rule WHERE source IN ('splunk', 'elastic', 'snort', 'yara');
ALTER TABLE detection_rule DROP CONSTRAINT detection_rule_source_check;
ALTER TABLE detection_rule ADD CONSTRAINT detection_rule_source_check CHECK (source IN ('sigma', 'suricata', 'nmap'));
