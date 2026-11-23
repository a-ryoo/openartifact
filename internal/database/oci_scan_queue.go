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
	"time"

	"github.com/openartifact/openartifact/internal/database/dbsqlc"
	"github.com/openartifact/openartifact/internal/database/models"
)

var errOCIScanLeaseExpired = errors.New("OCI scan lease expired")

// OCIScanJob is a claimed automatic scan of a hosted image manifest.
type OCIScanJob struct {
	RepositoryID, Digest, MediaType, Image string
	Size                                   int64
	ClaimedUntil, Revision                 time.Time
}

// ClaimOCIScan takes one eligible image for the duration of the lease.
func (p *VulnStore) ClaimOCIScan(ctx context.Context, until, revision time.Time) (*OCIScanJob, error) {
	row, err := p.q.ClaimOCIScan(ctx, dbsqlc.ClaimOCIScanParams{LeaseUntil: &until, DbRevision: revision})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil //nolint:nilnil // no eligible work
	}

	if err != nil {
		return nil, fmt.Errorf("claim OCI scan: %w", err)
	}

	return &OCIScanJob{row.RepositoryID, row.Digest, row.MediaType, row.Image, row.Size, *row.ClaimedUntil, revision}, nil
}

// FinishOCIScan commits the result and acknowledges the lease together. A
// worker whose lease expired cannot overwrite the result of its replacement.
func (p *VulnStore) FinishOCIScan(ctx context.Context, job OCIScanJob, scan *models.VulnScanResult) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin OCI scan completion: %w", err)
	}

	defer func() { _ = tx.Rollback() }()

	previous, err := finishOCILease(ctx, tx, job, scan.ScanError)
	if err != nil {
		return err
	}

	if scan.ScanStatus == "completed" {
		if err := storeOCISuccess(ctx, tx, job, scan, previous); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit OCI scan: %w", err)
	}

	return nil
}

func finishOCILease(ctx context.Context, tx *sql.Tx, job OCIScanJob, scanError string) ([]byte, error) {
	var previous []byte
	err := tx.QueryRowContext(ctx, `
		UPDATE oci_scan_queue q
		SET available_at = CASE WHEN target_revision > $4 THEN now() ELSE 'infinity' END,
		    claimed_until = NULL, scan_error = NULLIF($5, '')
		WHERE repository_id = $1 AND digest = $2 AND claimed_until = $3 AND claimed_until > now()
		RETURNING (SELECT vulnerabilities FROM vuln_results WHERE id = q.report_id)
	`, job.RepositoryID, job.Digest, job.ClaimedUntil, job.Revision, scanError).Scan(&previous)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errOCIScanLeaseExpired
	}
	if err != nil {
		return nil, fmt.Errorf("acknowledge OCI scan: %w", err)
	}

	return previous, nil
}

func storeOCISuccess(ctx context.Context, tx *sql.Tx, job OCIScanJob, scan *models.VulnScanResult, previous []byte) error {
	var changes []byte
	if previous != nil {
		var before []models.Vulnerability
		if err := json.Unmarshal(previous, &before); err != nil {
			return fmt.Errorf("decode previous OCI findings: %w", err)
		}

		var err error
		changes, err = json.Marshal(compareOCIFindings(before, scan.Vulnerabilities))
		if err != nil {
			return fmt.Errorf("encode OCI findings changes: %w", err)
		}
	}

	scan.Scanner = models.OCIAutomaticScanner
	if err := createVulnScanResult(ctx, tx, scan); err != nil {
		return err
	}

	_, err := tx.ExecContext(ctx, `
		UPDATE oci_scan_queue SET report_id = $3, database_updated_at = $4, finding_changes = $5
		WHERE repository_id = $1 AND digest = $2
	`, job.RepositoryID, job.Digest, scan.ID, job.Revision, changes)
	if err != nil {
		return fmt.Errorf("update OCI scan report: %w", err)
	}

	return nil
}

func compareOCIFindings(before, after []models.Vulnerability) models.OCIFindingChanges {
	return models.OCIFindingChanges{Added: newOCIFindings(before, after), Removed: newOCIFindings(after, before)}
}

func newOCIFindings(before, after []models.Vulnerability) []models.OCIFinding {
	existing := make(map[[2]string]bool, len(before))
	for _, v := range before {
		existing[[2]string{v.ID, v.Package}] = true
	}

	changes := []models.OCIFinding{}
	for _, v := range after {
		if key := [2]string{v.ID, v.Package}; !existing[key] {
			changes = append(changes, models.OCIFinding{ID: v.ID, Package: v.Package, Severity: v.Severity})
			existing[key] = true
		}
	}

	return changes
}

// ScheduleOCIRescans queues tagged images with stored SBOMs once per newer database.
func (p *VulnStore) ScheduleOCIRescans(ctx context.Context, revision time.Time) error {
	if err := p.q.ScheduleOCIRescans(ctx, revision); err != nil {
		return fmt.Errorf("schedule OCI rescans: %w", err)
	}
	return nil
}

// ReleaseOCIScan gives a claimed job back when shutdown or a database switch
// interrupts it. An expired claimant cannot release a replacement's lease.
func (p *VulnStore) ReleaseOCIScan(ctx context.Context, job OCIScanJob) error {
	_, err := p.db.ExecContext(ctx, `
		UPDATE oci_scan_queue SET claimed_until = NULL
		WHERE repository_id = $1 AND digest = $2 AND claimed_until = $3
	`, job.RepositoryID, job.Digest, job.ClaimedUntil)
	if err != nil {
		return fmt.Errorf("release OCI scan: %w", err)
	}
	return nil
}
