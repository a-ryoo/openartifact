-- SPDX-FileCopyrightText: The OpenArtifact Authors
--
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Walk up from a scanned platform manifest to its live, tagged indexes.
-- Keep the image name on every edge: the same digest can exist in several images.
CREATE FUNCTION docker_manifest_tags(repo uuid, target text)
RETURNS TABLE (image text, tag text)
LANGUAGE sql STABLE AS $$
    WITH RECURSIVE ancestors(image, digest) AS (
        SELECT m.image, m.digest
        FROM docker_manifests m
        WHERE m.repository_id = repo AND m.digest = target AND m.deleted_at IS NULL
        UNION
        SELECT parent.image, parent.digest
        FROM ancestors a
        JOIN docker_manifest_refs ref ON ref.repository_id = repo AND ref.image = a.image
            AND ref.kind = 'manifest' AND ref.digest = a.digest
        JOIN docker_manifests parent ON parent.id = ref.manifest_id AND parent.repository_id = repo
            AND parent.image = a.image AND parent.deleted_at IS NULL
    )
    SELECT DISTINCT t.image, t.name
    FROM ancestors a
    JOIN docker_tags t ON t.repository_id = repo AND t.image = a.image
        AND t.manifest_digest = a.digest AND t.deleted_at IS NULL;
$$;
