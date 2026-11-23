// SPDX-FileCopyrightText: The OpenArtifact Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vuln

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/openartifact/openartifact/internal/database/models"
)

// GenerateImageSBOM runs Trivy on a local, single-manifest OCI layout.
func (r *Registry) GenerateImageSBOM(ctx context.Context, layout string) ([]byte, error) {
	return r.runTrivyImage(ctx, "image", "cyclonedx", "--input", layout, "--cache-backend", "memory")
}

// ScanImageSBOM checks a whole stored CycloneDX or SPDX document with Trivy.
func (r *Registry) ScanImageSBOM(ctx context.Context, sbom []byte) ([]models.Vulnerability, error) {
	dir, err := os.MkdirTemp("", "oa-trivy-sbom-")
	if err != nil {
		return nil, fmt.Errorf("create Trivy SBOM directory: %w", err)
	}

	defer func() { _ = os.RemoveAll(dir) }()

	target := filepath.Join(dir, "sbom.json")
	if err := os.WriteFile(target, sbom, 0o600); err != nil {
		return nil, fmt.Errorf("write Trivy SBOM input: %w", err)
	}

	data, err := r.runTrivyImage(ctx, "sbom", "json", "--scanners", "vuln", target)
	if err != nil {
		return nil, err
	}

	return parseTrivyImageReport(data)
}

func (r *Registry) runTrivyImage(ctx context.Context, command, format string, target ...string) ([]byte, error) {
	bin, pre := r.trivy.preflight()
	if pre != nil {
		return nil, pre
	}

	args := []string{"--config=", command, "--format", format, "--quiet", "--offline-scan",
		"--skip-version-check", "--skip-db-update", "--skip-java-db-update", "--cache-dir=" + r.trivy.cacheDir}

	data, stderr, err := runScanner(ctx, nil, bin, append(args, target...)...)
	if err != nil {
		r.log.Warnw("Trivy image processing failed", "command", command, "error", err, "stderr", stderr)
		return nil, runFailure(ctx, scannerTrivy, err, stderr)
	}

	return data, nil
}

var errTrivyReportSchema = errors.New("unrecognized Trivy report schema")

func parseTrivyImageReport(data []byte) ([]models.Vulnerability, error) {
	var report struct {
		trivyOutput

		SchemaVersion int `json:"SchemaVersion"` //nolint:tagliatelle // Trivy report schema
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, newScanError(scannerTrivy, FailureInvalidOutput, fmt.Errorf("decode Trivy report: %w", err))
	}
	if report.SchemaVersion != 2 {
		return nil, newScanError(scannerTrivy, FailureInvalidOutput, errTrivyReportSchema)
	}

	findings := []models.Vulnerability{}
	seen := make(map[[2]string]bool)

	for _, result := range report.Results {
		for _, finding := range result.Vulnerabilities {
			pkg := finding.PkgName + "@" + finding.InstalledVersion
			key := [2]string{finding.VulnerabilityID, pkg}
			if !seen[key] {
				item := finding.model()
				item.Package = pkg
				findings = append(findings, item)
				seen[key] = true
			}
		}
	}

	return findings, nil
}
