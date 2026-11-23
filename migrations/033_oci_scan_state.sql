-- SPDX-FileCopyrightText: The OpenArtifact Authors
--
-- SPDX-License-Identifier: AGPL-3.0-or-later

ALTER TABLE oci_scan_queue
    ADD COLUMN is_rescan boolean NOT NULL DEFAULT false,
    ADD COLUMN target_revision timestamptz,
    ADD COLUMN scan_error text,
    ADD COLUMN report_id uuid REFERENCES vuln_results(id) ON DELETE SET NULL,
    ADD COLUMN database_updated_at timestamptz,
    ADD COLUMN finding_changes jsonb;

DROP INDEX idx_oci_scan_queue_due;
CREATE INDEX idx_oci_scan_queue_due ON oci_scan_queue (is_rescan, available_at) WHERE available_at < 'infinity';
