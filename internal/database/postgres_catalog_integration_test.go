// SPDX-FileCopyrightText: The OpenArtifact Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build integration

package database

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openartifact/openartifact/internal/database/models"
	"github.com/stretchr/testify/require"
)

type catalogFixture struct {
	pg   *PostgresDB
	db   *sql.DB
	repo string
	seed *quotaSeeder
	// ids maps "name@version" to the package file id.
	ids map[string]string
}

// seedNPMVersion stores one npm version with a blob of the given size.
func (f *catalogFixture) seedNPMVersion(t *testing.T, name, version string, size int64, created time.Time) {
	t.Helper()

	f.ids[name+"@"+version] = seedPackageFile(t, f.pg, packageSeed{
		repo: f.repo, format: "npm", name: name, version: version, filename: name + "-" + version + ".tgz",
		blobSeed: fmt.Sprintf("%s/%s/%s", f.repo, name, version), blobSize: size, created: created,
	})
}

func newCatalogFixture(t *testing.T) *catalogFixture {
	t.Helper()

	pg := newQuotaTestDB(t, 4)
	db := pg.GetDB()

	repo := seedRepo(t, db, "catalog-npm", "npm")

	return &catalogFixture{pg: pg, db: db, repo: repo, seed: &quotaSeeder{tb: t, pg: pg, repo: repo}, ids: map[string]string{}}
}

// seedCatalog stores alpha 1.0.0 and 2.0.0 and beta 1.0.0, the latest alpha
// scanned with 1 critical, 2 high, 3 medium and 4 low findings.
func seedCatalog(t *testing.T) (*catalogFixture, time.Time) {
	t.Helper()

	f := newCatalogFixture(t)
	base := time.Now().UTC().Truncate(time.Microsecond).Add(-24 * time.Hour)

	f.seedNPMVersion(t, "alpha", "1.0.0", 10, base)
	f.seedNPMVersion(t, "alpha", "2.0.0", 20, base.Add(time.Hour))
	f.seedNPMVersion(t, "beta", "1.0.0", 5, base.Add(2*time.Hour))

	job := seedScanJob(t, f.db, f.repo, f.ids["alpha@2.0.0"], "vuln", "grype", "completed", base.Add(3*time.Hour))
	seedVulnResult(t, f.db, job, `[]`, 1, 2, 3, 4, false)

	return f, base
}

func TestCatalogRollupGroupsVersions(t *testing.T) {
	f, _ := seedCatalog(t)
	ctx := context.Background()

	rows, total, err := f.pg.ListRepoPackageRollup(ctx, models.PackageRollupOptions{
		RepoID: f.repo, RepoFormat: "npm", SortByName: true, Page: 1, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}

	if total != 2 || len(rows) != 2 {
		t.Fatalf("total %d rows %d, want 2", total, len(rows))
	}

	a := rows[0]
	if a.Name != "alpha" || a.LatestVersion != "2.0.0" || a.VersionCount != 2 || a.SizeBytes != 20 ||
		!slices.Equal(a.LatestIDs, []string{f.ids["alpha@2.0.0"]}) {
		t.Fatalf("alpha rollup %+v", a)
	}
}

func TestCatalogRollupFlagged(t *testing.T) {
	f, _ := seedCatalog(t)
	ctx := context.Background()

	rows, total, err := f.pg.ListRepoPackageRollup(ctx, models.PackageRollupOptions{
		RepoID: f.repo, RepoFormat: "npm", Flagged: true, Page: 1, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}

	if total != 1 || len(rows) != 1 || rows[0].Name != "alpha" {
		t.Fatalf("flagged rollup total %d rows %+v", total, rows)
	}
}

func TestCatalogRollupPagePastTheEnd(t *testing.T) {
	f, _ := seedCatalog(t)
	ctx := context.Background()

	rows, total, err := f.pg.ListRepoPackageRollup(ctx, models.PackageRollupOptions{RepoID: f.repo, RepoFormat: "npm", Page: 5, Limit: 10})
	if err != nil || len(rows) != 0 || total != 2 {
		t.Fatalf("rows %d total %d err %v", len(rows), total, err)
	}
}

func TestCatalogArtifactSecurity(t *testing.T) {
	f, _ := seedCatalog(t)
	ctx := context.Background()

	sec, err := f.pg.ArtifactSecurity(ctx, f.repo, []string{f.ids["alpha@2.0.0"], f.ids["alpha@1.0.0"]})
	if err != nil {
		t.Fatal(err)
	}

	got, ok := sec[f.ids["alpha@2.0.0"]]
	if !ok || got.Critical != 1 || got.High != 2 || got.Medium != 3 || got.Low != 4 || got.ScannedAt == nil || got.Quarantined {
		t.Fatalf("scanned row %+v ok=%v", got, ok)
	}

	if _, ok := sec[f.ids["alpha@1.0.0"]]; ok {
		t.Fatal("an unscanned row must have no entry")
	}
}

func TestCatalogArtifactSecurityResolvesOCITag(t *testing.T) {
	pg := newQuotaTestDB(t, 8)
	ctx := t.Context()
	seed := newQuotaSeeder(t, pg, "catalog-oci", "docker")
	manifest := func(char string, children ...string) string {
		t.Helper()
		digest := "sha256:" + strings.Repeat(char, 64)
		mediaType := "application/vnd.oci.image.manifest.v1+json"
		if len(children) != 0 {
			mediaType = "application/vnd.oci.image.index.v1+json"
		}
		require.NoError(t, pg.CreateDockerManifest(ctx, &models.DockerManifest{
			RepositoryID: seed.repo, Image: "app", Digest: digest, MediaType: mediaType,
			BlobID: seed.blob(10), Size: 10, Refs: &models.DockerManifestRefs{Manifests: children},
		}))
		return digest
	}
	amd64, arm64, next := manifest("a"), manifest("b"), manifest("c")
	index := manifest("e", amd64, manifest("d", amd64, arm64))
	tag := &models.DockerTag{RepositoryID: seed.repo, Image: "app", Name: "latest", ManifestDigest: index}
	require.NoError(t, pg.UpsertDockerTag(ctx, tag))

	lastScan := time.Now().UTC().Truncate(time.Microsecond)
	for _, result := range []*models.VulnScanResult{
		{ArtifactID: amd64, Scanner: "trivy", ScanStatus: "completed", HighCount: 2, ScannedAt: &lastScan},
		{ArtifactID: arm64, Scanner: models.OCIAutomaticScanner, ScanStatus: "completed", MediumCount: 3, ScannedAt: &lastScan},
		{ArtifactID: amd64, Scanner: "grype", ScanStatus: "failed"},
	} {
		result.RepositoryID = seed.repo
		require.NoError(t, pg.CreateVulnScanResult(ctx, result))
	}

	entries, err := pg.ArtifactSecurity(ctx, seed.repo, []string{tag.ID, tag.ID})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.EqualValues(t, 2, entries[tag.ID].High)
	require.EqualValues(t, 3, entries[tag.ID].Medium)
	require.NotNil(t, entries[tag.ID].ScannedAt)
	require.True(t, entries[tag.ID].ScannedAt.Equal(lastScan))
	flagged, _, err := pg.ListRepoPackageRollup(ctx, models.PackageRollupOptions{
		RepoID: seed.repo, RepoFormat: "docker", Flagged: true, Page: 1, Limit: 10,
	})
	require.NoError(t, err)
	require.Len(t, flagged, 1)
	require.Equal(t, "catalog-oci/app", flagged[0].Name)

	// A second tag keeps the same reports reachable without double counting.
	alias := &models.DockerTag{RepositoryID: seed.repo, Image: "app", Name: "alias", ManifestDigest: index}
	require.NoError(t, pg.UpsertDockerTag(ctx, alias))
	reconcileRepoStats(t, pg)
	stats, err := pg.RepoCatalogStats(ctx, []string{seed.repo})
	require.NoError(t, err)
	require.EqualValues(t, 3, stats[seed.repo].Security.Medium)

	tag.ManifestDigest = next
	require.NoError(t, pg.UpsertDockerTag(ctx, tag))
	entries, err = pg.ArtifactSecurity(ctx, seed.repo, []string{tag.ID})
	require.NoError(t, err)
	require.Empty(t, entries)

	alias.ManifestDigest = next
	require.NoError(t, pg.UpsertDockerTag(ctx, alias))
	// Retagging schedules an immediate refresh even though the cached row is fresh.
	reconcileRepoStats(t, pg)
	stats, err = pg.RepoCatalogStats(ctx, []string{seed.repo})
	require.NoError(t, err)
	require.Zero(t, stats[seed.repo].Security.Medium)
	require.Nil(t, stats[seed.repo].Security.ScannedAt)
}

func TestCatalogRepositoryStats(t *testing.T) {
	f, base := seedCatalog(t)
	ctx := context.Background()

	reconcileRepoStats(t, f.pg)

	stats, err := f.pg.RepoCatalogStats(ctx, []string{f.repo})
	if err != nil {
		t.Fatal(err)
	}

	s := stats[f.repo]
	if s.Security.Critical != 1 || s.Security.High != 2 || s.Security.ScannedAt == nil || !s.Security.Flagged() {
		t.Fatalf("security %+v", s.Security)
	}

	if s.LastPublishedAt == nil || s.LastPublishedAt.Before(base) {
		t.Fatalf("last published %v", s.LastPublishedAt)
	}

	if s.PackageCount != 2 {
		t.Fatalf("package count %d, want 2", s.PackageCount)
	}
}

func TestCatalogRecentPackages(t *testing.T) {
	f, _ := seedCatalog(t)
	ctx := context.Background()

	recent, err := f.pg.ListRecentPackages(ctx, []string{f.repo}, 2)
	if err != nil {
		t.Fatal(err)
	}

	if len(recent) != 2 || recent[0].Name != "beta" || recent[1].Name != "alpha" || recent[1].Version != "2.0.0" ||
		recent[0].Repository != "catalog-npm" {
		t.Fatalf("recent %+v", recent)
	}

	if none, err := f.pg.ListRecentPackages(ctx, nil, 5); err != nil || len(none) != 0 {
		t.Fatalf("no repositories: %v %v", none, err)
	}
}

func TestCatalogComponentDetail(t *testing.T) {
	f, _ := seedCatalog(t)
	ctx := context.Background()

	d, err := f.pg.GetRepoComponentDetail(ctx, f.repo, f.ids["alpha@2.0.0"])
	if err != nil || d == nil || d.Name != "alpha" || d.Version != "2.0.0" || d.Format != "npm" {
		t.Fatalf("detail %+v err %v", d, err)
	}

	other := seedRepo(t, f.db, "catalog-other", "npm")
	if d, err := f.pg.GetRepoComponentDetail(ctx, other, f.ids["alpha@2.0.0"]); err != nil || d != nil {
		t.Fatalf("foreign repository must not resolve the row: %+v %v", d, err)
	}

	if d, err := f.pg.GetRepoComponentDetail(ctx, f.repo, "not-a-uuid"); err != nil || d != nil {
		t.Fatalf("malformed id: %+v %v", d, err)
	}
}

// The hosted branch lists no file of a trashed repository, whichever
// repository ids the caller passes.
func TestCatalogHostedBranchSkipsTrashedRepository(t *testing.T) {
	f, _ := seedCatalog(t)
	ctx := context.Background()

	if _, err := f.db.ExecContext(ctx, `UPDATE repositories SET deleted_at = now() WHERE id = $1::uuid`, f.repo); err != nil {
		t.Fatal(err)
	}

	recent, err := f.pg.ListRecentPackages(ctx, []string{f.repo}, 10)
	if err != nil || len(recent) != 0 {
		t.Fatalf("recent of a trashed repository = %v, err %v; want none", recent, err)
	}

	reconcileRepoStats(t, f.pg)

	if s := repoStatsOf(t, f.pg, f.repo); s.PackageCount != 0 || s.LastPublishedAt != nil {
		t.Fatalf("stats of a trashed repository %+v; want none", s)
	}
}
