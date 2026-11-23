// SPDX-FileCopyrightText: The OpenArtifact Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"

	"github.com/openartifact/openartifact/internal/api"
	"github.com/openartifact/openartifact/internal/attestation"
	formatdocker "github.com/openartifact/openartifact/internal/format/docker"
	"github.com/openartifact/openartifact/internal/imagesbom"
)

// imageSBOMHook builds the SBOM ingest of container images and returns the
// manifest push hook that feeds it. buildVulnScanning connects it to the scans.
func (a *app) imageSBOMHook() formatdocker.ManifestPutHook {
	ingestor := imagesbom.NewIngestor(a.db, a.db, a.store.blobs, a.log)

	return func(ctx context.Context, ev formatdocker.ManifestEvent) {
		err := ingestor.Handle(ctx, imagesbom.Push{
			RepoID:        ev.RepoID,
			RepoName:      ev.RepoName,
			Image:         ev.Image,
			Tag:           ev.Tag,
			ArtifactType:  ev.ArtifactType,
			Annotations:   ev.Annotations,
			SubjectDigest: ev.SubjectDigest,
			Manifest:      ev.Manifest,
		})
		if err != nil {
			a.log.Errorw("image SBOM ingest failed", "repository", ev.RepoName, "digest", ev.Digest, "error", err)
		}
	}
}

// attachImageSBOMs lets the vulnerability handler scan and evaluate the
// ingested SBOMs of images and report the
// attestations of an image in the digest gate.
func (a *app) attachImageSBOMs(handler *api.VulnHandler) {
	handler.WithImages(imagesbom.NewReader(a.db, a.store.blobs)).
		WithImagePlatform(func(ctx context.Context, digest string) string {
			return formatdocker.ImagePlatform(ctx, a.store.blobs, digest)
		}).
		WithAttestations(attestationSummaries{svc: attestation.NewService(a.log, a.db, a.store.blobs)}).
		WithOCIScans(a.db)
}

// attestationSummaries answers the digest gate from the attestation index.
type attestationSummaries struct{ svc *attestation.Service }

func (s attestationSummaries) AttestationSummary(ctx context.Context, repoID, subject string) (api.AttestationSummary, error) {
	rows, err := s.svc.List(ctx, repoID, subject, "")
	if err != nil {
		return api.AttestationSummary{}, err //nolint:wrapcheck // the gate names the check
	}

	sum := api.AttestationSummary{Total: len(rows)}

	for _, row := range rows {
		switch {
		case row.Verified:
			sum.Verified++
		case row.VerifyError != "":
			sum.Failed++
		}
	}

	return sum, nil
}
