// SPDX-FileCopyrightText: The OpenArtifact Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openartifact/openartifact/internal/database/models"
)

var errOCIScanLeaseExpired = errors.New("OCI scan lease expired")

// OCIScanJob is a claimed automatic scan of a hosted image manifest.
type OCIScanJob struct {
	RepositoryID, Digest, MediaType, Image string
	Size                                   int64
	ClaimedUntil                           time.Time
}

// ClaimOCIScan takes one eligible image for the duration of the lease.
func (p *VulnStore) ClaimOCIScan(ctx context.Context, until time.Time) (*OCIScanJob, error) {
	row, err := p.q.ClaimOCIScan(ctx, &until)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil //nolint:nilnil // no eligible work
	}

	if err != nil {
		return nil, fmt.Errorf("claim OCI scan: %w", err)
	}

	return &OCIScanJob{row.RepositoryID, row.Digest, row.MediaType, row.Image, row.Size, *row.ClaimedUntil}, nil
}

// FinishOCIScan commits the result and acknowledges the lease together. A
// worker whose lease expired cannot overwrite the result of its replacement.
func (p *VulnStore) FinishOCIScan(ctx context.Context, job OCIScanJob, scan *models.VulnScanResult) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin OCI scan completion: %w", err)
	}

	defer func() { _ = tx.Rollback() }()

	tag, err := tx.ExecContext(ctx, `
		UPDATE oci_scan_queue SET available_at = 'infinity', claimed_until = NULL
		WHERE repository_id = $1 AND digest = $2 AND claimed_until = $3 AND claimed_until > now()
	`, job.RepositoryID, job.Digest, job.ClaimedUntil)
	if err != nil {
		return fmt.Errorf("acknowledge OCI scan: %w", err)
	}

	n, err := tag.RowsAffected()
	if err != nil {
		return fmt.Errorf("check OCI scan lease: %w", err)
	}

	if n != 1 {
		return errOCIScanLeaseExpired
	}

	if err := createVulnScanResult(ctx, tx, scan); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit OCI scan: %w", err)
	}

	return nil
}
