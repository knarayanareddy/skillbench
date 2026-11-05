-- Lifecycle purge role: grants and the narrow enumeration helper.
--
-- The lifecycle process runs as `lifecycle_login` (member of `baseline_lifecycle`)
-- and is the only runtime identity allowed to destroy content. It cannot write
-- audit, reviews, trials or analyses: those stay append-only and are revoked below.
--
-- Every table it touches is RLS-scoped per project, so the purger cannot enumerate
-- projects on its own. `core.lifecycle_projects()` is the one narrow SECURITY
-- DEFINER function that lists (project, organization) pairs; it returns no content
-- and is executable only by the lifecycle role.
BEGIN;

-- Expired uploads, expired artifacts and the purge backlog are found by time.
CREATE INDEX IF NOT EXISTS artifacts_expiring ON core.artifacts(expires_at)
  WHERE state <> 'deleted';
CREATE INDEX IF NOT EXISTS uploads_expiring ON core.uploads(expires_at)
  WHERE state IN ('created','uploaded');
CREATE INDEX IF NOT EXISTS deletions_open ON core.deletions(purge_deadline)
  WHERE state <> 'complete';
CREATE INDEX IF NOT EXISTS sessions_expiring ON core.sessions(absolute_expires_at);

CREATE OR REPLACE FUNCTION core.lifecycle_projects()
RETURNS TABLE(project_id uuid, organization_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,core,public AS $$
  SELECT p.id, p.organization_id FROM core.projects p ORDER BY p.id
$$;
REVOKE ALL ON FUNCTION core.lifecycle_projects() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION core.lifecycle_projects() TO baseline_lifecycle;

-- Deletion tombstones are created by the purger when content expires without an
-- explicit request; an operator-requested deletion is created by the API.
GRANT INSERT ON core.deletions TO baseline_lifecycle;

-- Reference check for purge decisions. Answering "is this artifact still used?"
-- needs a peek at suites and trial traces, which this role may not read; the
-- function returns a boolean for one project-scoped artifact and no content.
CREATE OR REPLACE FUNCTION core.artifact_is_referenced(p_project uuid, p_artifact uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,core,skb,public AS $$
  SELECT EXISTS (SELECT 1 FROM skb.packages p
                  WHERE p.project_id=p_project AND p.artifact_id=p_artifact)
      OR EXISTS (SELECT 1 FROM skb.suites s
                  WHERE s.project_id=p_project AND s.rights_manifest_artifact_id=p_artifact)
      OR EXISTS (SELECT 1 FROM skb.trials t
                  WHERE t.project_id=p_project AND t.trace_artifact_id=p_artifact)
      OR EXISTS (SELECT 1 FROM core.uploads u
                  WHERE u.project_id=p_project AND u.artifact_id=p_artifact
                    AND u.state <> 'expired')
$$;
REVOKE ALL ON FUNCTION core.artifact_is_referenced(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION core.artifact_is_referenced(uuid,uuid) TO baseline_lifecycle;

-- Expiring a stale upload is a state transition, not a content change.
GRANT UPDATE(state) ON core.uploads TO baseline_lifecycle;

-- Backlog and expiry pruning. Sessions and idempotency records are operational
-- state, not evidence; auth transactions are single-use and short-lived.
-- Deleting by time needs to read the expiry columns, and only those: token
-- digests and session payloads stay invisible to this role.
GRANT DELETE ON core.sessions, core.auth_transactions TO baseline_lifecycle;
GRANT SELECT(organization_id, absolute_expires_at, revoked_at) ON core.sessions TO baseline_lifecycle;
GRANT SELECT(expires_at) ON core.auth_transactions TO baseline_lifecycle;
GRANT DELETE ON core.idempotency_project, core.idempotency_organization TO baseline_lifecycle;
GRANT SELECT(project_id, expires_at) ON core.idempotency_project TO baseline_lifecycle;
GRANT SELECT(organization_id, expires_at) ON core.idempotency_organization TO baseline_lifecycle;

-- Outbox rows are marked delivered by this process only when delivery is enabled.
GRANT SELECT, UPDATE(delivered_at) ON core.outbox TO baseline_lifecycle;

-- Belt and braces: the append-only evidence surfaces stay unreachable.
REVOKE ALL ON core.audit_events, skb.package_reviews, skb.trials, skb.analyses
  FROM baseline_lifecycle;

COMMIT;
