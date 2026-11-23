-- SPDX-FileCopyrightText: The OpenArtifact Authors
--
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Repository security figures now depend on which manifests live tags reach.
DROP TRIGGER repo_stats_mark ON public.docker_tags;
CREATE TRIGGER repo_stats_mark
    AFTER INSERT OR DELETE OR UPDATE OF repository_id, image, manifest_digest, deleted_at ON public.docker_tags
    FOR EACH ROW EXECUTE FUNCTION public.repo_stats_trg_repository();

CREATE TRIGGER repo_stats_mark
    AFTER INSERT OR DELETE OR UPDATE OF deleted_at ON public.docker_manifests
    FOR EACH ROW EXECUTE FUNCTION public.repo_stats_trg_repository();

INSERT INTO public.repo_stats_dirty (repository_id)
SELECT id FROM public.repositories
WHERE format = 'docker' AND repo_type = 'hosted' AND deleted_at IS NULL;
