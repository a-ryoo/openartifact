-- SPDX-FileCopyrightText: The OpenArtifact Authors
--
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- name: EnqueueOCIScan :exec
INSERT INTO oci_scan_queue (repository_id, digest, available_at)
VALUES ($1, $2, now() + interval '5 minutes')
ON CONFLICT (repository_id, digest) DO NOTHING;

-- name: ClaimOCIScan :one
-- An attached SBOM makes the pending job eligible before its deadline.
WITH candidate AS (
    SELECT q.repository_id, q.digest, m.media_type, m.size, m.image
    FROM oci_scan_queue q
    JOIN LATERAL (
        SELECT dm.media_type, dm.size, dm.image
        FROM docker_manifests dm
        WHERE dm.repository_id = q.repository_id
          AND dm.digest = q.digest AND dm.deleted_at IS NULL
        LIMIT 1
    ) m ON true
    WHERE q.available_at < 'infinity' AND (q.claimed_until IS NULL OR q.claimed_until <= now())
      AND (q.available_at <= now() OR EXISTS (
          SELECT 1 FROM artifact_refs ref
          JOIN scan_jobs sj ON sj.artifact_ref_id = ref.id AND sj.scan_type = 'sbom'
          JOIN sbom_results sr ON sr.scan_job_id = sj.id AND sr.blob_id IS NOT NULL
          WHERE ref.repository_id = q.repository_id AND ref.artifact_path = q.digest
      ))
    ORDER BY q.available_at, q.repository_id, q.digest
    LIMIT 1
    FOR UPDATE OF q SKIP LOCKED
)
UPDATE oci_scan_queue q SET claimed_until = sqlc.arg(lease_until)
FROM candidate c WHERE q.repository_id = c.repository_id AND q.digest = c.digest
RETURNING q.repository_id, q.digest, q.claimed_until, c.media_type, c.size, c.image;
