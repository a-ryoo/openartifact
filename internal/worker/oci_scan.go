// SPDX-FileCopyrightText: The OpenArtifact Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"context"
	"errors"
	"time"

	"github.com/openartifact/openartifact/internal/bgtask"
	"github.com/openartifact/openartifact/internal/database"
	"github.com/openartifact/openartifact/internal/database/models"
	"github.com/openartifact/openartifact/internal/imagesbom"
	"github.com/openartifact/openartifact/internal/storage"
	"github.com/openartifact/openartifact/internal/vuln"
	"github.com/openartifact/openartifact/pkg/logger"
)

const (
	ociPollInterval = 5 * time.Second
	ociScanTimeout  = 15 * time.Minute
	ociStoreTimeout = 30 * time.Second
	ociScanLease    = ociScanTimeout + time.Minute
)

// OCIScanWorker consumes persisted whole-image work. Each instance processes
// one image at a time and shares the database queue with other workers.
type OCIScanWorker struct {
	db       *database.PostgresDB
	blobs    storage.BlobStore
	sboms    *imagesbom.Reader
	ingestor *imagesbom.Ingestor
	trivy    *vuln.Registry
	log      *logger.Logger
}

func NewOCIScanWorker(db *database.PostgresDB, blobs storage.BlobStore, trivy *vuln.Registry, log *logger.Logger) *OCIScanWorker {
	return &OCIScanWorker{
		db: db, blobs: blobs, sboms: imagesbom.NewReader(db, blobs),
		ingestor: imagesbom.NewIngestor(db, db, blobs, log), trivy: trivy, log: log,
	}
}

// Run serves scans until the worker lifecycle ends.
func (w *OCIScanWorker) Run(ctx context.Context, announce func(context.Context, *models.VulnScanResult)) {
	for ctx.Err() == nil {
		claimCtx, stop := context.WithTimeout(ctx, ociStoreTimeout)
		job, err := w.db.ClaimOCIScan(claimCtx, time.Now().Add(ociScanLease))
		stop()

		if err != nil && ctx.Err() == nil {
			w.log.Errorw("automatic OCI scan claim failed", "error", err)
		}

		if job == nil {
			_ = bgtask.Sleep(ctx, ociPollInterval)
			continue
		}

		w.runScan(ctx, *job, announce)
	}
}

func (w *OCIScanWorker) runScan(ctx context.Context, job database.OCIScanJob, announce func(context.Context, *models.VulnScanResult)) {
	scanCtx, cancel := context.WithTimeout(ctx, ociScanTimeout)
	findings, err := w.scan(scanCtx, job)
	cancel()

	if ctx.Err() != nil {
		// A replacement can reclaim this lease. Shutdown is not a scan failure.
		return
	}

	now := time.Now()
	result := &models.VulnScanResult{
		RepositoryID: job.RepositoryID, ArtifactID: job.Digest, PackageName: job.Digest,
		Ecosystem: vuln.ImageEcosystem, Scanner: "trivy", ScanStatus: vuln.StatusCompleted,
		Vulnerabilities: findings, VulnCount: len(findings), ScannedAt: &now, CreatedAt: now, UpdatedAt: now,
	}
	result.CriticalCount, result.HighCount, result.MediumCount, result.LowCount = vuln.CountSeverities(findings)

	if err != nil {
		w.log.Warnw("automatic OCI scan failed", "repository_id", job.RepositoryID, "digest", job.Digest, "error", err)

		result.ScanStatus = vuln.StatusFailed
		result.FailedScanners = []string{"trivy"}
		result.Vulnerabilities = []models.Vulnerability{}
		result.ScanError = "image contents or SBOM could not be processed"
		if failure, ok := errors.AsType[*vuln.ScanError](err); ok {
			result.ScanError = failure.PublicMessage()
		}
	}

	storeCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), ociStoreTimeout)
	defer stop()

	if err := w.db.FinishOCIScan(storeCtx, job, result); err != nil {
		w.log.Errorw("automatic OCI scan completion failed", "repository_id", job.RepositoryID, "digest", job.Digest, "error", err)
		return
	}

	announce(storeCtx, result)
}

func (w *OCIScanWorker) scan(ctx context.Context, job database.OCIScanJob) ([]models.Vulnerability, error) {
	body, err := w.sboms.Body(ctx, job.RepositoryID, job.Digest)
	if errors.Is(err, imagesbom.ErrNoSBOM) {
		body, err = w.generateSBOM(ctx, job)
	}

	if err != nil {
		return nil, err
	}

	return w.trivy.ScanImageSBOM(ctx, body)
}

func (w *OCIScanWorker) generateSBOM(ctx context.Context, job database.OCIScanJob) ([]byte, error) {
	dir, cleanup, err := w.imageLayout(ctx, job)
	if err != nil {
		return nil, err
	}

	defer cleanup()

	body, err := w.trivy.GenerateImageSBOM(ctx, dir)
	if err != nil {
		return nil, err
	}

	if err := w.ingestor.StoreGenerated(ctx, job.RepositoryID, job.Digest, body); err != nil {
		return nil, err
	}

	// An attachment can arrive while the image is being analysed.
	return w.sboms.Body(ctx, job.RepositoryID, job.Digest)
}
