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
    WHERE q.available_at < 'infinity'
      AND sqlc.arg(db_revision)::timestamptz >= COALESCE(
          (SELECT value::timestamptz FROM system_settings WHERE key = 'oci_scan_database_revision'), '-infinity')
      AND (q.target_revision IS NULL OR q.target_revision <= sqlc.arg(db_revision)::timestamptz)
      AND (q.claimed_until IS NULL OR q.claimed_until <= now())
      AND (q.available_at <= now() OR EXISTS (
          SELECT 1 FROM artifact_refs ref
          JOIN scan_jobs sj ON sj.artifact_ref_id = ref.id AND sj.scan_type = 'sbom'
          JOIN sbom_results sr ON sr.scan_job_id = sj.id AND sr.blob_id IS NOT NULL
          WHERE ref.repository_id = q.repository_id AND ref.artifact_path = q.digest
      ))
    ORDER BY q.is_rescan, q.available_at, q.repository_id, q.digest
    LIMIT 1
    FOR UPDATE OF q SKIP LOCKED
)
UPDATE oci_scan_queue q SET claimed_until = sqlc.arg(lease_until), target_revision = sqlc.arg(db_revision)::timestamptz
FROM candidate c WHERE q.repository_id = c.repository_id AND q.digest = c.digest
RETURNING q.repository_id, q.digest, q.claimed_until, c.media_type, c.size, c.image;

-- name: ScheduleOCIRescans :exec
-- Advance the shared revision once, even when several worker replicas refresh
-- their own caches. Walk tagged indexes and select the manifests with a BOM.
WITH RECURSIVE revision AS (
    INSERT INTO system_settings (key, value)
    VALUES ('oci_scan_database_revision', (sqlc.arg(db_revision)::timestamptz)::text)
    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
    WHERE system_settings.value::timestamptz < EXCLUDED.value::timestamptz
    RETURNING value
), reachable AS (
    SELECT m.id, m.repository_id, m.image, m.digest, m.subject_digest, m.media_type
    FROM revision
    CROSS JOIN docker_tags t
    JOIN repositories r ON r.id = t.repository_id AND r.format = 'docker' AND r.repo_type = 'hosted'
    JOIN docker_manifests m ON m.repository_id = t.repository_id AND m.image = t.image AND m.digest = t.manifest_digest
    WHERE t.deleted_at IS NULL AND m.deleted_at IS NULL
    UNION
    SELECT child.id, child.repository_id, child.image, child.digest, child.subject_digest, child.media_type
    FROM reachable parent
    JOIN docker_manifest_refs ref ON ref.manifest_id = parent.id AND ref.repository_id = parent.repository_id
        AND ref.image = parent.image AND ref.kind = 'manifest'
    JOIN docker_manifests child ON child.repository_id = parent.repository_id AND child.image = parent.image
        AND child.digest = ref.digest AND child.deleted_at IS NULL
)
INSERT INTO oci_scan_queue (repository_id, digest, available_at, target_revision, is_rescan)
SELECT DISTINCT m.repository_id, m.digest, now(), sqlc.arg(db_revision)::timestamptz, true
FROM reachable m
WHERE m.subject_digest IS NULL
  AND m.media_type IN ('application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json')
  AND EXISTS (
      SELECT 1 FROM artifact_refs ref
      JOIN scan_jobs sj ON sj.artifact_ref_id = ref.id AND sj.scan_type = 'sbom'
      JOIN sbom_results sr ON sr.scan_job_id = sj.id AND sr.blob_id IS NOT NULL
      WHERE ref.repository_id = m.repository_id AND ref.artifact_path = m.digest
  )
ORDER BY m.repository_id, m.digest
ON CONFLICT (repository_id, digest) DO UPDATE
    SET target_revision = EXCLUDED.target_revision, available_at = LEAST(oci_scan_queue.available_at, now()),
        is_rescan = oci_scan_queue.is_rescan OR oci_scan_queue.available_at = 'infinity'
WHERE oci_scan_queue.target_revision IS NULL OR oci_scan_queue.target_revision < EXCLUDED.target_revision;

-- name: RetryOCIScan :execrows
UPDATE oci_scan_queue q SET available_at = now(), is_rescan = false
WHERE q.repository_id = $1 AND q.digest = $2 AND q.available_at = 'infinity'
  AND q.scan_error IS NOT NULL
  AND EXISTS (SELECT 1 FROM docker_manifests m
      WHERE m.repository_id = q.repository_id AND m.digest = q.digest AND m.deleted_at IS NULL);
