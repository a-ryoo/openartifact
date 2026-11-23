// SPDX-FileCopyrightText: The OpenArtifact Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"net/http"

	"github.com/openartifact/openartifact/internal/database/models"
	"github.com/openartifact/openartifact/internal/urlparams"
)

type ociScanStore interface {
	GetOCIScanStatus(ctx context.Context, repoID, digest string) (string, error)
	ListOCIScanStates(ctx context.Context, repoID, packageName, version string) ([]models.OCIScanState, error)
	RetryOCIScan(ctx context.Context, repoID, digest string) (bool, error)
}

func (h *VulnHandler) WithOCIScans(store ociScanStore) *VulnHandler {
	h.ociScans = store
	return h
}

func publicVulnScanner(scanner string) string {
	if scanner == models.OCIAutomaticScanner {
		return "trivy"
	}
	return scanner
}

type ociScanStateResponse struct {
	Digest            string                    `json:"digest"`
	Platform          string                    `json:"platform,omitempty"`
	Status            string                    `json:"status"`
	Error             string                    `json:"error,omitempty"`
	ReportID          string                    `json:"report_id,omitempty"`
	DatabaseUpdatedAt *string                   `json:"database_updated_at,omitempty"`
	Changes           *models.OCIFindingChanges `json:"changes,omitempty"`
}

func (h *VulnHandler) handleOCIScanStates(w http.ResponseWriter, r *http.Request) {
	repo, ok := h.adminRepo(w, r, "list automatic OCI scans")
	if !ok {
		return
	}

	packageName, version := r.URL.Query().Get("package_name"), r.URL.Query().Get("version")
	if packageName == "" || version == "" || !h.hasOCIScans(repo) {
		writeError(
			w,
			http.StatusBadRequest,
			"validation_failed",
			"package_name and version must select a tag in a hosted Docker repository",
		)
		return
	}

	ctx := r.Context()
	states, err := h.ociScans.ListOCIScanStates(ctx, repo.ID, packageName, version)
	if err != nil {
		h.dbError(w, "list automatic OCI scans", err)
		return
	}

	out := make([]ociScanStateResponse, 0, len(states))
	for _, s := range states {
		item := ociScanStateResponse{
			Digest: s.Digest, Status: s.Status, Error: s.Error, ReportID: s.ReportID,
			DatabaseUpdatedAt: formatTimePtr(s.DatabaseUpdatedAt), Changes: s.Changes,
		}
		if h.imagePlatform != nil {
			item.Platform = h.imagePlatform(ctx, s.Digest)
		}
		out = append(out, item)
	}

	writeJSON(w, http.StatusOK, map[string]any{"scans": out})
}

func (h *VulnHandler) handleRetryOCIScan(w http.ResponseWriter, r *http.Request) {
	repo, ok := h.adminRepo(w, r, "retry automatic OCI scan")
	if !ok {
		return
	}

	digest := urlparams.Vars(r)["digest"]
	if !h.hasOCIScans(repo) || !imageDigestRe.MatchString(digest) {
		writeError(w, http.StatusBadRequest, "validation_failed", "retry needs a manifest digest in a hosted Docker repository")
		return
	}

	queued, err := h.ociScans.RetryOCIScan(r.Context(), repo.ID, digest)
	if err != nil {
		h.dbError(w, "retry automatic OCI scan", err)
		return
	}
	if !queued {
		writeError(w, http.StatusConflict, "scan_not_retryable", "there is no failed automatic scan eligible to retry")
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *VulnHandler) hasOCIScans(repo *models.Repository) bool {
	return h.ociScans != nil && repo.Format == "docker" && repo.RepoType == "hosted"
}
