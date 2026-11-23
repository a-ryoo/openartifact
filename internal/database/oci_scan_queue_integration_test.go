// SPDX-FileCopyrightText: The OpenArtifact Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build integration

package database

import (
	"strings"
	"testing"
	"time"

	"github.com/openartifact/openartifact/internal/database/models"
)

func TestOCIScanQueueDeduplicatesAndReclaims(t *testing.T) {
	pg := newQuotaTestDB(t, 8)
	ctx := t.Context()
	s := newQuotaSeeder(t, pg, "oci-scan", "docker")
	digest := "sha256:" + strings.Repeat("a", 64)

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
		if claimed, err := pg.ClaimOCIScan(ctx, time.Now().Add(time.Minute)); claimed != nil || err != nil {
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

	claimed, err := pg.ClaimOCIScan(ctx, now.Add(time.Minute))
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
	reclaimed, err := pg.ClaimOCIScan(ctx, now.Add(2*time.Minute))
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
