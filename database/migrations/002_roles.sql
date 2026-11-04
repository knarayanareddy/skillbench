-- PostgreSQL roles, grants and Row Level Security — baseline revision r2.
-- No passwords are created here. Operators provision login/service identities
-- externally; the application never connects as the migration owner.
BEGIN;
DO $$ BEGIN
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='baseline_app') THEN CREATE ROLE baseline_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS; END IF;
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='baseline_lifecycle') THEN CREATE ROLE baseline_lifecycle NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS; END IF;
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='baseline_dispatcher') THEN CREATE ROLE baseline_dispatcher NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS; END IF;
END $$;

GRANT USAGE ON SCHEMA core,skb TO baseline_app,baseline_lifecycle,baseline_dispatcher;
GRANT EXECUTE ON FUNCTION core.resolve_identity(text,text) TO baseline_app;
GRANT EXECUTE ON FUNCTION core.resolve_api_key(bytea) TO baseline_app;
GRANT EXECUTE ON FUNCTION core.resolve_session(bytea) TO baseline_app;
GRANT EXECUTE ON FUNCTION core.resolve_user_context(uuid) TO baseline_app;
GRANT EXECUTE ON FUNCTION core.claim_job(text[],integer) TO baseline_dispatcher;

-- ---------------------------------------------------------------------------
-- baseline_app: the trusted API. Insert/select/update only; no DELETE.
-- ---------------------------------------------------------------------------
GRANT SELECT,INSERT ON core.organizations,core.memberships,core.projects,core.project_roles TO baseline_app;
GRANT SELECT ON core.users TO baseline_app;
GRANT SELECT,INSERT ON core.sessions TO baseline_app;
GRANT SELECT,INSERT,UPDATE ON core.idempotency_project,core.idempotency_organization TO baseline_app;
GRANT SELECT,INSERT ON core.auth_transactions TO baseline_app;
GRANT UPDATE(consumed_at) ON core.auth_transactions TO baseline_app;
GRANT SELECT,INSERT ON core.artifacts,core.uploads,core.artifact_links TO baseline_app;
GRANT UPDATE(state,sha256,byte_size) ON core.artifacts TO baseline_app;
GRANT UPDATE(state,staged_sha256,staged_bytes,finalized_at) ON core.uploads TO baseline_app;
GRANT SELECT,INSERT ON core.jobs,core.job_attempts,core.outbox,core.budget_reservations TO baseline_app;
GRANT UPDATE(state,attempt,fence,lease_until,revision,updated_at,result_id,error_code) ON core.jobs TO baseline_app;
GRANT UPDATE(state,finished_at) ON core.job_attempts TO baseline_app;
GRANT UPDATE(delivered_at) ON core.outbox TO baseline_app;
GRANT SELECT,INSERT,UPDATE ON core.deletions TO baseline_app;
GRANT SELECT,INSERT ON core.audit_events TO baseline_app;
GRANT SELECT,INSERT ON skb.packages,skb.package_entries,skb.package_findings,skb.package_reviews,skb.suites,skb.plans,skb.experiments,skb.trials,skb.analyses TO baseline_app;
GRANT UPDATE(state,revision,inspection_sha256,inspection_summary,inspected_at,rejection_code) ON skb.packages TO baseline_app;
GRANT UPDATE(state,revision,preregistered_at) ON skb.plans TO baseline_app;
GRANT UPDATE(state,updated_at) ON skb.experiments TO baseline_app;
GRANT UPDATE(idle_expires_at,last_seen_at,revoked_at) ON core.sessions TO baseline_app;
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA core,skb TO baseline_app;

-- Hidden scoring material and machine-key digests are never reachable by the API role.
REVOKE ALL ON skb.hidden_answers FROM baseline_app;
REVOKE ALL ON core.api_keys FROM baseline_app;
-- Identity administration is operator/administrator work, not a runtime mutation.
REVOKE INSERT,UPDATE ON core.organizations,core.memberships,core.project_roles FROM baseline_app;
-- Projects may be created by an organization admin (RLS keeps it in-org) but never updated by the runtime.
REVOKE UPDATE ON core.projects FROM baseline_app;
-- Append-only records: the immutability triggers also enforce this.
REVOKE UPDATE,DELETE ON core.audit_events,skb.package_reviews,skb.trials,skb.analyses,skb.package_findings FROM baseline_app;

-- ---------------------------------------------------------------------------
-- baseline_dispatcher: the trusted worker. No identity tables, no deletes.
-- ---------------------------------------------------------------------------
GRANT SELECT,UPDATE ON core.jobs,core.outbox TO baseline_dispatcher;
GRANT SELECT,INSERT,UPDATE ON core.job_attempts TO baseline_dispatcher;
GRANT SELECT ON core.artifacts,core.projects,core.idempotency_project TO baseline_dispatcher;
GRANT SELECT,INSERT,UPDATE ON skb.packages,skb.package_entries,skb.package_findings,skb.trials,skb.experiments TO baseline_dispatcher;
GRANT SELECT ON skb.suites,skb.plans TO baseline_dispatcher;
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA core,skb TO baseline_dispatcher;

-- ---------------------------------------------------------------------------
-- baseline_lifecycle: purge identity for revoked/tombstoned content only.
-- ---------------------------------------------------------------------------
GRANT SELECT,DELETE ON core.artifacts,core.uploads,core.artifact_links,core.deletions TO baseline_lifecycle;
GRANT UPDATE(state,expires_at) ON core.artifacts TO baseline_lifecycle;
GRANT UPDATE(state,completed_at) ON core.deletions TO baseline_lifecycle;
GRANT SELECT,DELETE ON skb.packages,skb.package_entries,skb.package_findings TO baseline_lifecycle;
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA core,skb TO baseline_lifecycle;
REVOKE DELETE ON core.audit_events FROM baseline_lifecycle;

-- ---------------------------------------------------------------------------
-- Row Level Security. Content tables use FORCE so even the table owner is
-- constrained during application queries. Identity tables deliberately do not
-- use FORCE: the narrow SECURITY DEFINER lookups above are owned by the
-- migration owner and must resolve a subject before any organization/project
-- context exists. The runtime app is never that owner and is fully constrained.
-- ---------------------------------------------------------------------------
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'core.artifacts','core.uploads','core.artifact_links','core.jobs','core.job_attempts',
    'core.outbox','core.budget_reservations','core.deletions','core.idempotency_project',
    'skb.packages','skb.package_entries','skb.package_findings','skb.package_reviews',
    'skb.suites','skb.hidden_answers','skb.plans','skb.experiments','skb.trials','skb.analyses'
  ] LOOP
    EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY',t);
    EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY',t);
    EXECUTE format($f$CREATE POLICY project_scope ON %s
      USING (project_id = nullif(current_setting('baseline.project_id',true),'')::uuid)
      WITH CHECK (project_id = nullif(current_setting('baseline.project_id',true),'')::uuid)$f$,t);
  END LOOP;

  FOREACH t IN ARRAY ARRAY[
    'core.memberships','core.projects','core.sessions','core.idempotency_organization'
  ] LOOP
    EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY',t);
    EXECUTE format($f$CREATE POLICY organization_scope ON %s
      USING (organization_id = nullif(current_setting('baseline.organization_id',true),'')::uuid)
      WITH CHECK (organization_id = nullif(current_setting('baseline.organization_id',true),'')::uuid)$f$,t);
  END LOOP;
END $$;

-- core.organizations is keyed by its own id, not an organization_id column.
ALTER TABLE core.organizations ENABLE ROW LEVEL SECURITY;
CREATE POLICY organization_scope ON core.organizations
  USING (id = nullif(current_setting('baseline.organization_id',true),'')::uuid)
  WITH CHECK (id = nullif(current_setting('baseline.organization_id',true),'')::uuid);

ALTER TABLE core.project_roles ENABLE ROW LEVEL SECURITY;
CREATE POLICY project_scope ON core.project_roles
  USING (project_id = nullif(current_setting('baseline.project_id',true),'')::uuid)
  WITH CHECK (project_id = nullif(current_setting('baseline.project_id',true),'')::uuid);

ALTER TABLE core.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.audit_events FORCE ROW LEVEL SECURITY;
-- Audit rows are organization-scoped. When a project context is present it is
-- additionally confined to that project (organization-level operations such as
-- project creation run with only the organization context set).
CREATE POLICY organization_scope ON core.audit_events
  USING (organization_id = nullif(current_setting('baseline.organization_id',true),'')::uuid
         AND (nullif(current_setting('baseline.project_id',true),'') IS NULL
              OR project_id IS NULL
              OR project_id = nullif(current_setting('baseline.project_id',true),'')::uuid))
  WITH CHECK (organization_id = nullif(current_setting('baseline.organization_id',true),'')::uuid
         AND (nullif(current_setting('baseline.project_id',true),'') IS NULL
              OR project_id IS NULL
              OR project_id = nullif(current_setting('baseline.project_id',true),'')::uuid));

-- Application must set project/organization context transaction-locally; pooled
-- context MUST NOT persist and is verified by tests/db/test_rls.py.
-- RLS is defense in depth against query bugs, not authorization against a
-- compromised trusted application.
COMMIT;
