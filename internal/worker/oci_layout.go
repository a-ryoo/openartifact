// SPDX-FileCopyrightText: The OpenArtifact Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/openartifact/openartifact/internal/database"
)

const (
	maxOCIManifestBytes = 4 << 20
	// Limit the scratch space one local scan can consume. Layers stay compressed.
	maxOCILayoutBytes = 8 << 30
)

var (
	errOCIManifestSize = errors.New("image manifest exceeds scan size limit")
	errOCILayoutSize   = errors.New("image exceeds local scan size limit")
	errOCIUnusableBlob = errors.New("image references an unavailable or invalid blob")
	errOCIBadDigest    = errors.New("invalid OCI scan digest")
	errOCIBlobSize     = errors.New("OCI blob size differs from its descriptor")
)

type layoutDescriptor struct {
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	MediaType string `json:"mediaType"` //nolint:tagliatelle // OCI descriptor
}

// imageLayout copies only the image manifest and its own blobs into a private
// directory. Trivy reads the OCI layout without a registry token or a daemon.
func (w *OCIScanWorker) imageLayout(ctx context.Context, job database.OCIScanJob) (string, func(), error) {
	if job.Size <= 0 || job.Size > maxOCIManifestBytes {
		return "", nil, errOCIManifestSize
	}

	dir, err := os.MkdirTemp("", "oa-image-layout-")
	if err != nil {
		return "", nil, fmt.Errorf("create OCI layout directory: %w", err)
	}

	cleanup := func() { _ = os.RemoveAll(dir) }
	if err := w.writeLayout(ctx, dir, job); err != nil {
		cleanup()
		return "", nil, err
	}

	return dir, cleanup, nil
}

func (w *OCIScanWorker) writeLayout(ctx context.Context, dir string, job database.OCIScanJob) error {
	blobDir := filepath.Join(dir, "blobs", "sha256")
	if err := os.MkdirAll(blobDir, 0o700); err != nil {
		return fmt.Errorf("create OCI blob directory: %w", err)
	}

	manifestKey, err := layoutKey(job.Digest)
	if err != nil {
		return err
	}

	manifestPath := filepath.Join(blobDir, manifestKey)
	if err := w.copyLayoutBlob(ctx, manifestKey, manifestPath, job.Size); err != nil {
		return err
	}

	body, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("open OCI manifest: %w", err)
	}

	var manifest struct {
		Config layoutDescriptor   `json:"config"`
		Layers []layoutDescriptor `json:"layers"`
	}
	if err := json.Unmarshal(body, &manifest); err != nil {
		return fmt.Errorf("decode OCI manifest: %w", err)
	}

	seen := map[string]bool{job.Digest: true}
	remaining := int64(maxOCILayoutBytes) - job.Size

	for _, desc := range append(manifest.Layers, manifest.Config) {
		if seen[desc.Digest] {
			continue
		}

		if desc.Size < 0 || desc.Size > remaining {
			return errOCILayoutSize
		}

		if err := w.stageImageBlob(ctx, blobDir, job, desc); err != nil {
			return err
		}

		seen[desc.Digest] = true
		remaining -= desc.Size
	}

	index, err := json.Marshal(struct {
		SchemaVersion int                `json:"schemaVersion"` //nolint:tagliatelle // OCI index
		Manifests     []layoutDescriptor `json:"manifests"`
	}{2, []layoutDescriptor{{Digest: job.Digest, Size: job.Size, MediaType: job.MediaType}}})
	if err != nil {
		return fmt.Errorf("encode OCI index: %w", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "index.json"), index, 0o600); err != nil {
		return fmt.Errorf("write OCI index: %w", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600); err != nil {
		return fmt.Errorf("write OCI layout metadata: %w", err)
	}

	return nil
}

func (w *OCIScanWorker) stageImageBlob(ctx context.Context, dir string, job database.OCIScanJob, desc layoutDescriptor) error {
	key, err := layoutKey(desc.Digest)
	if err != nil {
		return err
	}

	blob, err := w.db.GetDockerBlob(ctx, job.RepositoryID, desc.Digest)
	if err != nil {
		return fmt.Errorf("look up OCI scan blob: %w", err)
	}

	if blob == nil || blob.Size != desc.Size || blob.BlobSHA256 != key {
		return errOCIUnusableBlob
	}

	visible, err := w.db.DockerBlobVisible(ctx, job.RepositoryID, job.Image, desc.Digest)
	if err != nil {
		return fmt.Errorf("verify OCI scan blob visibility: %w", err)
	}
	if !visible {
		return errOCIUnusableBlob
	}

	return w.copyLayoutBlob(ctx, key, filepath.Join(dir, key), desc.Size)
}

func layoutKey(digest string) (string, error) {
	key, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || len(key) != 64 || key != strings.ToLower(key) {
		return "", errOCIBadDigest
	}

	if _, err := hex.DecodeString(key); err != nil {
		return "", fmt.Errorf("invalid OCI scan digest: %w", err)
	}

	return key, nil
}

func (w *OCIScanWorker) copyLayoutBlob(ctx context.Context, key, path string, size int64) error {
	blob, err := w.blobs.Get(ctx, key)
	if err != nil {
		return fmt.Errorf("open OCI scan blob: %w", err)
	}

	defer func() { _ = blob.Close() }()

	dst, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create local OCI blob: %w", err)
	}

	n, copyErr := io.Copy(dst, io.LimitReader(blob, size+1))
	closeErr := dst.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return fmt.Errorf("write local OCI blob: %w", err)
	}

	if n != size {
		return errOCIBlobSize
	}

	return nil
}
