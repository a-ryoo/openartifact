-- SPDX-FileCopyrightText: The OpenArtifact Authors
--
-- SPDX-License-Identifier: AGPL-3.0-or-later

CREATE TABLE oci_scan_queue (
    repository_id uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    digest text NOT NULL,
    available_at timestamptz NOT NULL,
    claimed_until timestamptz,
    PRIMARY KEY (repository_id, digest)
);

CREATE INDEX idx_oci_scan_queue_due ON oci_scan_queue (available_at) WHERE available_at < 'infinity';

ALTER TABLE sbom_results ADD COLUMN generated_from_image boolean NOT NULL DEFAULT false;
