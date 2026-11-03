-- +goose Up

-- Greenbone Community Feed vulnerability tests (metadata only).
ALTER TABLE detection_rule DROP CONSTRAINT detection_rule_source_check;
ALTER TABLE detection_rule ADD CONSTRAINT detection_rule_source_check
    CHECK (source IN ('sigma', 'suricata', 'nmap', 'splunk', 'elastic', 'snort', 'yara', 'greenbone'));

-- +goose Down

DELETE FROM detection_rule WHERE source = 'greenbone';
ALTER TABLE detection_rule DROP CONSTRAINT detection_rule_source_check;
ALTER TABLE detection_rule ADD CONSTRAINT detection_rule_source_check
    CHECK (source IN ('sigma', 'suricata', 'nmap', 'splunk', 'elastic', 'snort', 'yara'));
