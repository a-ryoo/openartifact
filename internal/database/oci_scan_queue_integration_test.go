// SPDX-FileCopyrightText: The OpenArtifact Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build integration

package database

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/openartifact/openartifact/internal/database/models"
)

func TestOCIScanQueueDeduplicatesAndReclaims(t *testing.T) {
	pg := newQuotaTestDB(t, 8)
	ctx := t.Context()
	s := newQuotaSeeder(t, pg, "oci-scan", "docker")
	digest := "sha256:" + strings.Repeat("a", 64)
	revision := time.Date(2026, 11, 23, 1, 0, 0, 0, time.UTC)

	push := func(image string) {
		t.Helper()
		if err := pg.CreateDockerManifest(ctx, &models.DockerManifest{
			RepositoryID: s.repo, Image: image, Digest: digest,
			MediaType: "application/vnd.oci.image.manifest.v1+json", BlobID: s.blob(10), Size: 10,
			Refs: &models.DockerManifestRefs{}, AutoScan: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	assertNoClaim := func() {
		t.Helper()
		if claimed, err := pg.ClaimOCIScan(ctx, time.Now().Add(time.Minute), revision); claimed != nil || err != nil {
			t.Fatalf("claim = %+v, %v; want no job", claimed, err)
		}
	}

	push("app")
	push("copy")
	assertNoClaim()

	now := time.Now()
	external := &models.SBOMReport{
		RepositoryID: s.repo, ArtifactID: digest, Format: "cyclonedx", SpecVersion: "1.6",
		ContentType: "application/vnd.cyclonedx+json", BlobSHA256: strings.Repeat("b", 64), BlobSizeBytes: 12,
		GeneratedAt: now,
	}
	if err := pg.CreateSBOMReport(ctx, external); err != nil {
		t.Fatal(err)
	}

	claimed, err := pg.ClaimOCIScan(ctx, now.Add(time.Minute), revision)
	if err != nil || claimed == nil || claimed.Digest != digest {
		t.Fatalf("claim after attaching SBOM = %+v, %v", claimed, err)
	}
	assertNoClaim()

	result := &models.VulnScanResult{
		RepositoryID: s.repo, ArtifactID: digest, Scanner: "trivy", Ecosystem: "docker",
		Vulnerabilities: []models.Vulnerability{}, ScanStatus: "completed", ScannedAt: &now,
	}

	// Simulate an expired lease left behind by a stopped process.
	if _, err := pg.db.ExecContext(ctx, `UPDATE oci_scan_queue SET claimed_until = now() - interval '1 minute'`); err != nil {
		t.Fatal(err)
	}
	reclaimed, err := pg.ClaimOCIScan(ctx, now.Add(2*time.Minute), revision)
	if err != nil || reclaimed == nil || reclaimed.Digest != digest {
		t.Fatalf("claim after a restart = %+v, %v", reclaimed, err)
	}

	if err := pg.FinishOCIScan(ctx, *claimed, result); err == nil {
		t.Fatal("an expired lease could publish a result")
	}
	if err := pg.FinishOCIScan(ctx, *reclaimed, result); err != nil {
		t.Fatal(err)
	}
	if err := pg.FinishOCIScan(ctx, *reclaimed, result); err == nil {
		t.Fatal("an acknowledged lease could publish a second result")
	}

	push("app")
	assertNoClaim()
	stored, err := pg.GetVulnScanResult(ctx, s.repo, digest)
	if err != nil || stored == nil || stored.ID != result.ID || stored.ScanStatus != "completed" {
		t.Fatalf("stored result = %+v, %v", stored, err)
	}
}

func TestOCIRescanKeepsReportAndComparesSuccessfulAttempts(t *testing.T) {
	pg := newQuotaTestDB(t, 8)
	ctx := t.Context()
	s := newQuotaSeeder(t, pg, "oci-history", "docker")
	pkg := "oci-history/app"
	eachRevision := time.Date(2026, 11, 23, 1, 0, 0, 0, time.UTC)
	packageID := "openssl@1.2.3"

	manifest := func(seed string, children ...string) string {
		t.Helper()
		digest := "sha256:" + strings.Repeat(seed, 64)
		mediaType := "application/vnd.oci.image.manifest.v1+json"
		if len(children) > 0 {
			mediaType = "application/vnd.oci.image.index.v1+json"
		}
		err := pg.CreateDockerManifest(ctx, &models.DockerManifest{
			RepositoryID: s.repo, Image: "app", Digest: digest,
			MediaType: mediaType, BlobID: s.blob(10), Size: 10,
			Refs: &models.DockerManifestRefs{Manifests: children},
		})
		require.NoError(t, err)
		return digest
	}

	leaf, orphan := manifest("a"), manifest("b")
	root := manifest("c", manifest("d", leaf))
	for _, tag := range []string{"current", "another"} {
		require.NoError(t, pg.UpsertDockerTag(ctx, &models.DockerTag{
			RepositoryID: s.repo, Image: "app", Name: tag, ManifestDigest: root,
		}))
	}
	for _, digest := range []string{leaf, orphan} {
		require.NoError(t, pg.CreateSBOMReport(ctx, &models.SBOMReport{
			RepositoryID: s.repo, ArtifactID: digest, Format: "cyclonedx", SpecVersion: "1.6",
			ContentType: "application/vnd.cyclonedx+json", BlobSHA256: strings.Repeat("e", 64), BlobSizeBytes: 10,
			GeneratedAt: time.Now(),
		}))
	}

	schedule := func(revision time.Time) {
		t.Helper()
		require.NoError(t, pg.ScheduleOCIRescans(ctx, revision))
	}
	claim := func(revision time.Time, want bool) *OCIScanJob {
		t.Helper()
		job, err := pg.ClaimOCIScan(ctx, time.Now().Add(time.Minute), revision)
		require.NoError(t, err)
		if want {
			require.NotNil(t, job)
			require.Equal(t, leaf, job.Digest)
		} else {
			require.Nil(t, job)
		}
		return job
	}
	finish := func(job *OCIScanJob, vulnID, failure string) string {
		t.Helper()
		now := time.Now()
		scan := &models.VulnScanResult{
			RepositoryID: s.repo, ArtifactID: leaf, PackageName: leaf, Ecosystem: "docker",
			ScannedAt: &now, ScanStatus: "completed", ScanError: failure,
			Vulnerabilities: []models.Vulnerability{{ID: vulnID, Package: packageID, Severity: "HIGH"}},
		}
		if failure != "" {
			scan.ScanStatus = "failed"
		}
		require.NoError(t, pg.FinishOCIScan(ctx, *job, scan))
		return scan.ID
	}
	state := func(want string) models.OCIScanState {
		t.Helper()
		rows, err := pg.ListOCIScanStates(ctx, s.repo, pkg, "current")
		require.NoError(t, err)
		require.Len(t, rows, 1)
		require.Equal(t, want, rows[0].Status)
		return rows[0]
	}

	schedule(eachRevision)
	state("queued")
	first := claim(eachRevision, true)
	state("scanning")
	id := finish(first, "RHSA-2024:8906", "")
	initial := state("completed")
	require.Equal(t, id, initial.ReportID)
	require.Nil(t, initial.Changes)
	require.Equal(t, eachRevision, initial.DatabaseUpdatedAt.UTC())
	schedule(eachRevision)
	claim(eachRevision, false)

	second := eachRevision.Add(6 * time.Hour)
	schedule(second)
	claim(eachRevision, false)
	finish(claim(second, true), "", "scanner exited with an error")
	failed := state("failed")
	require.Equal(t, id, failed.ReportID)
	require.Equal(t, "scanner exited with an error", failed.Error)
	require.Equal(t, eachRevision, failed.DatabaseUpdatedAt.UTC())

	for _, want := range []bool{true, false} {
		queued, err := pg.RetryOCIScan(ctx, s.repo, leaf)
		require.NoError(t, err)
		require.Equal(t, want, queued)
	}
	require.Equal(t, id, finish(claim(second, true), "CVE-2026-1234", ""))
	latest := state("completed")
	require.Empty(t, latest.Error)
	require.Equal(t, second, latest.DatabaseUpdatedAt.UTC())
	require.NotNil(t, latest.Changes)
	require.Equal(t, []models.OCIFinding{{ID: "CVE-2026-1234", Package: packageID, Severity: "HIGH"}}, latest.Changes.Added)
	require.Equal(t, []models.OCIFinding{{ID: "RHSA-2024:8906", Package: packageID, Severity: "HIGH"}}, latest.Changes.Removed)
	claim(second, false)
}
