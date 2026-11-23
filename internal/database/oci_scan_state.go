// SPDX-FileCopyrightText: The OpenArtifact Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openartifact/openartifact/internal/database/models"
)

const ociStatusSQL = `CASE
		    WHEN q.claimed_until > now() THEN 'scanning'
		    WHEN q.available_at <= now() THEN 'queued'
		    WHEN q.available_at < 'infinity' AND NOT EXISTS (
		        SELECT 1 FROM artifact_refs ref
		        JOIN scan_jobs sj ON sj.artifact_ref_id = ref.id AND sj.scan_type = 'sbom'
		        JOIN sbom_results sr ON sr.scan_job_id = sj.id AND sr.blob_id IS NOT NULL
		        WHERE ref.repository_id = q.repository_id AND ref.artifact_path = q.digest
		    ) THEN 'waiting_for_sbom'
		    WHEN q.available_at < 'infinity' THEN 'queued'
		    WHEN q.scan_error IS NOT NULL THEN 'failed'
		    ELSE 'completed'
		END`

// ListOCIScanStates reads attempts and their surviving reports for a tagged version.
func (p *VulnStore) ListOCIScanStates(ctx context.Context, repoID, packageName, version string) ([]models.OCIScanState, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT q.digest, `+ociStatusSQL+`, COALESCE(q.scan_error, ''), COALESCE(q.report_id::text, ''),
		q.database_updated_at, q.finding_changes
		FROM oci_scan_queue q
		WHERE q.repository_id = $1 AND q.digest IN (SELECT artifact_id FROM docker_tag_artifacts($1, $2, $3))
		ORDER BY q.digest
	`, repoID, packageName, version)
	if err != nil {
		return nil, fmt.Errorf("list OCI scan state: %w", err)
	}
	defer rows.Close()

	out := []models.OCIScanState{}
	for rows.Next() {
		var s models.OCIScanState
		var revision sql.NullTime
		var changes []byte
		if err := rows.Scan(&s.Digest, &s.Status, &s.Error, &s.ReportID, &revision, &changes); err != nil {
			return nil, fmt.Errorf("read OCI scan state: %w", err)
		}

		if revision.Valid {
			s.DatabaseUpdatedAt = &revision.Time
		}
		if changes != nil {
			if err := json.Unmarshal(changes, &s.Changes); err != nil {
				return nil, fmt.Errorf("decode OCI finding changes: %w", err)
			}
		}

		out = append(out, s)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read OCI scan states: %w", err)
	}

	return out, nil
}

// RetryOCIScan makes a failed attempt eligible. Concurrent retries coalesce.
func (p *VulnStore) RetryOCIScan(ctx context.Context, repoID, digest string) (bool, error) {
	tag, err := p.db.ExecContext(ctx, `
		UPDATE oci_scan_queue q SET available_at = now(), is_rescan = false
		WHERE q.repository_id = $1 AND q.digest = $2 AND q.available_at = 'infinity'
		  AND q.scan_error IS NOT NULL
		  AND EXISTS (SELECT 1 FROM docker_manifests m
		      WHERE m.repository_id = q.repository_id AND m.digest = q.digest AND m.deleted_at IS NULL)
	`, repoID, digest)
	if err != nil {
		return false, fmt.Errorf("retry OCI scan: %w", err)
	}
	n, err := tag.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("check OCI scan retry: %w", err)
	}
	return n == 1, nil
}

// GetOCIScanStatus reports the initial automatic attempt to the digest gate.
func (p *VulnStore) GetOCIScanStatus(ctx context.Context, repoID, digest string) (string, error) {
	var status string
	err := p.db.QueryRowContext(ctx, `
		SELECT `+ociStatusSQL+` FROM oci_scan_queue q WHERE q.repository_id = $1 AND q.digest = $2
	`, repoID, digest).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read OCI scan status: %w", err)
	}
	return status, nil
}
