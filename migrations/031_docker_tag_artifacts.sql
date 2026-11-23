-- SPDX-FileCopyrightText: The OpenArtifact Authors
--
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Include the tag row for older package scans, and all live manifests inside
-- the tagged index for digest-based image scans.
CREATE FUNCTION docker_tag_artifacts(repo uuid, package_name text, version text)
RETURNS TABLE (artifact_id text)
LANGUAGE sql STABLE STRICT AS $$
    WITH RECURSIVE tag AS (
        SELECT t.id, t.image, t.manifest_digest
        FROM repositories r
        JOIN docker_tags t ON t.repository_id = r.id
        WHERE r.id = repo AND r.format = 'docker' AND r.repo_type = 'hosted'
          AND t.name = version AND t.deleted_at IS NULL
          AND t.image = CASE
              WHEN package_name = r.name THEN ''
              WHEN starts_with(package_name, r.name || '/') THEN substring(package_name FROM length(r.name) + 2)
          END
    ), manifests AS (
        SELECT m.id, m.image, m.digest
        FROM tag t JOIN docker_manifests m ON m.repository_id = repo
            AND m.image = t.image AND m.digest = t.manifest_digest AND m.deleted_at IS NULL
        UNION
        SELECT child.id, child.image, child.digest
        FROM manifests parent
        JOIN docker_manifest_refs ref ON ref.manifest_id = parent.id AND ref.repository_id = repo
            AND ref.image = parent.image AND ref.kind = 'manifest'
        JOIN docker_manifests child ON child.repository_id = repo AND child.image = parent.image
            AND child.digest = ref.digest AND child.deleted_at IS NULL
    )
    SELECT id::text FROM tag
    UNION ALL
    SELECT digest FROM manifests;
$$;
