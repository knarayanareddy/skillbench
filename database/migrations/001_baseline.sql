-- Normative PostgreSQL 16 migration — baseline revision r2 (2026-11-04).
-- Applied once as migration owner, never as a runtime role.
-- Reviewable changes versus r1 are recorded in docs/Baseline_Revision_r2.md and
-- evidence/tickets/B02-database.md. r1 was never applied to any database in this
-- repository (no deployment or migration evidence exists), so r2 is a baseline
-- revision rather than an in-place edit of applied history. A future deployment
-- that has applied r1 MUST take the additive migration path documented there.
BEGIN;
CREATE SCHEMA core;
CREATE SCHEMA skb;

-- ---------------------------------------------------------------------------
-- Identity, membership and project workspace (core)
-- ---------------------------------------------------------------------------
CREATE TABLE core.organizations(
  id uuid PRIMARY KEY,
  name text NOT NULL CHECK(length(name) BETWEEN 1 AND 120),
  created_at timestamptz NOT NULL DEFAULT now());

-- Users are preprovisioned by an operator/administrator; the application never
-- inserts identities and there is no password or public registration path.
CREATE TABLE core.users(
  id uuid PRIMARY KEY,
  issuer text NOT NULL,
  subject text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(issuer,subject));

CREATE TABLE core.memberships(
  organization_id uuid NOT NULL REFERENCES core.organizations,
  user_id uuid NOT NULL REFERENCES core.users,
  org_role text NOT NULL CHECK(org_role IN ('member','admin')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(organization_id,user_id));

CREATE TABLE core.projects(
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES core.organizations,
  name text NOT NULL CHECK(length(name) BETWEEN 1 AND 120),
  content_capture text NOT NULL DEFAULT 'metadata_only' CHECK(content_capture IN ('metadata_only','redacted')),
  external_transfer boolean NOT NULL DEFAULT false,
  revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(organization_id,id));

CREATE TABLE core.project_roles(
  project_id uuid NOT NULL REFERENCES core.projects,
  user_id uuid NOT NULL REFERENCES core.users,
  role text NOT NULL CHECK(role IN ('viewer','analyst','operator','maintainer')),
  granted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(project_id,user_id,role));

-- Scoped machine keys. Only the SHA-256 digest of a high-entropy secret is stored.
CREATE TABLE core.api_keys(
  id uuid PRIMARY KEY,
  project_id uuid NOT NULL REFERENCES core.projects,
  actor_id uuid NOT NULL REFERENCES core.users,
  key_digest bytea NOT NULL UNIQUE,
  scopes text[] NOT NULL CHECK(array_length(scopes,1) >= 1),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz);

-- Server-side browser sessions. The cookie carries a random token; only its
-- digest is persisted. Session identity is never a signed browser token.
CREATE TABLE core.sessions(
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES core.organizations,
  user_id uuid NOT NULL REFERENCES core.users,
  token_digest bytea NOT NULL UNIQUE,
  csrf_token text NOT NULL CHECK(length(csrf_token) >= 32),
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  idle_expires_at timestamptz NOT NULL,
  absolute_expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  CHECK(idle_expires_at > created_at),
  CHECK(absolute_expires_at > created_at));

-- One-use authorization-code transaction (state + nonce + PKCE verifier).
CREATE TABLE core.auth_transactions(
  id uuid PRIMARY KEY,
  state_digest bytea NOT NULL UNIQUE,
  nonce text NOT NULL,
  code_verifier text NOT NULL,
  return_to text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz);

-- ---------------------------------------------------------------------------
-- Scoped idempotency: the approved behaviour is one table per authorization
-- scope. Ordinary project mutations are unique per (project, actor, operation,
-- key). Project creation happens before a project exists and is unique per
-- (organization, actor, operation, key). Neither table carries a scope-free
-- uniqueness rule and neither permits a NULL scope.
-- ---------------------------------------------------------------------------
CREATE TABLE core.idempotency_project(
  project_id uuid NOT NULL REFERENCES core.projects,
  actor_id uuid NOT NULL REFERENCES core.users,
  operation text NOT NULL CHECK(length(operation) BETWEEN 1 AND 120),
  key uuid NOT NULL,
  request_sha256 text NOT NULL CHECK(request_sha256 ~ '^[a-f0-9]{64}$'),
  state text NOT NULL CHECK(state IN ('in_progress','completed')),
  response_status integer CHECK(response_status BETWEEN 200 AND 599),
  response_body jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY(project_id,actor_id,operation,key),
  CHECK(expires_at > created_at),
  CHECK((state='in_progress' AND response_status IS NULL AND response_body IS NULL)
     OR (state='completed' AND response_status IS NOT NULL AND response_body IS NOT NULL)));

CREATE TABLE core.idempotency_organization(
  organization_id uuid NOT NULL REFERENCES core.organizations,
  actor_id uuid NOT NULL REFERENCES core.users,
  operation text NOT NULL CHECK(length(operation) BETWEEN 1 AND 120),
  key uuid NOT NULL,
  request_sha256 text NOT NULL CHECK(request_sha256 ~ '^[a-f0-9]{64}$'),
  state text NOT NULL CHECK(state IN ('in_progress','completed')),
  response_status integer CHECK(response_status BETWEEN 200 AND 599),
  response_body jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY(organization_id,actor_id,operation,key),
  CHECK(expires_at > created_at),
  CHECK((state='in_progress' AND response_status IS NULL AND response_body IS NULL)
     OR (state='completed' AND response_status IS NOT NULL AND response_body IS NOT NULL)));

CREATE INDEX idempotency_project_expiry ON core.idempotency_project(expires_at);
CREATE INDEX idempotency_organization_expiry ON core.idempotency_organization(expires_at);

-- ---------------------------------------------------------------------------
-- Artifacts, staging uploads and lineage
-- ---------------------------------------------------------------------------
CREATE TABLE core.artifacts(
  id uuid PRIMARY KEY,
  project_id uuid NOT NULL REFERENCES core.projects,
  sha256 text NOT NULL CHECK(sha256 ~ '^[a-f0-9]{64}$'),
  byte_size bigint NOT NULL CHECK(byte_size>0 AND byte_size<=104857600),
  media_type text NOT NULL,
  filename text CHECK(filename IS NULL OR length(filename) BETWEEN 1 AND 200),
  classification text NOT NULL CHECK(classification IN ('synthetic','public_authorized','sensitive')),
  state text NOT NULL CHECK(state IN ('pending','ready','quarantined','deleting','deleted')),
  storage_key text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  UNIQUE(project_id,id));

CREATE TABLE core.uploads(
  id uuid PRIMARY KEY,
  project_id uuid NOT NULL,
  artifact_id uuid NOT NULL,
  expected_size bigint NOT NULL CHECK(expected_size>0 AND expected_size<=104857600),
  expected_sha256 text NOT NULL CHECK(expected_sha256 ~ '^[a-f0-9]{64}$'),
  media_type text NOT NULL,
  state text NOT NULL DEFAULT 'created' CHECK(state IN ('created','uploaded','finalized','expired')),
  staged_sha256 text CHECK(staged_sha256 ~ '^[a-f0-9]{64}$'),
  staged_bytes bigint CHECK(staged_bytes>0 AND staged_bytes<=104857600),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  finalized_at timestamptz,
  UNIQUE(project_id,id),
  FOREIGN KEY(project_id,artifact_id) REFERENCES core.artifacts(project_id,id));

CREATE TABLE core.artifact_links(
  project_id uuid NOT NULL,
  parent_id uuid NOT NULL,
  child_id uuid NOT NULL,
  relation text NOT NULL CHECK(length(relation) BETWEEN 1 AND 60),
  PRIMARY KEY(project_id,parent_id,child_id,relation),
  CHECK(parent_id<>child_id),
  FOREIGN KEY(project_id,parent_id) REFERENCES core.artifacts(project_id,id),
  FOREIGN KEY(project_id,child_id) REFERENCES core.artifacts(project_id,id));

-- ---------------------------------------------------------------------------
-- Jobs, attempts, outbox
-- ---------------------------------------------------------------------------
CREATE TABLE core.jobs(
  id uuid PRIMARY KEY,
  project_id uuid NOT NULL REFERENCES core.projects,
  kind text NOT NULL CHECK(length(kind) BETWEEN 1 AND 80),
  state text NOT NULL CHECK(state IN ('queued','leased','running','cancel_requested','succeeded','failed','timed_out','cancelled','failed_unknown_effect')),
  payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object'),
  attempt integer NOT NULL DEFAULT 0 CHECK(attempt>=0),
  fence bigint NOT NULL DEFAULT 0 CHECK(fence>=0),
  revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
  lease_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  result_id uuid,
  error_code text,
  UNIQUE(project_id,id),
  CHECK((state IN ('leased','running')) = (lease_until IS NOT NULL)));

CREATE INDEX jobs_dispatch ON core.jobs(created_at,id) WHERE state IN ('queued','leased','running','cancel_requested');
CREATE INDEX jobs_project ON core.jobs(project_id,created_at DESC);

CREATE TABLE core.job_attempts(
  project_id uuid NOT NULL,
  job_id uuid NOT NULL,
  attempt integer NOT NULL CHECK(attempt>0),
  fence bigint NOT NULL CHECK(fence>0),
  state text NOT NULL CHECK(state IN ('running','succeeded','failed','timed_out','cancelled','abandoned')),
  started_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  PRIMARY KEY(job_id,attempt),
  FOREIGN KEY(project_id,job_id) REFERENCES core.jobs(project_id,id));

CREATE TABLE core.outbox(
  id bigserial PRIMARY KEY,
  project_id uuid NOT NULL REFERENCES core.projects,
  kind text NOT NULL,
  body jsonb NOT NULL CHECK(jsonb_typeof(body)='object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz);

CREATE INDEX outbox_pending ON core.outbox(id) WHERE delivered_at IS NULL;

CREATE TABLE core.budget_reservations(
  id uuid PRIMARY KEY,
  project_id uuid NOT NULL REFERENCES core.projects,
  job_id uuid NOT NULL,
  token_limit bigint NOT NULL CHECK(token_limit>=0),
  call_limit integer NOT NULL CHECK(call_limit>=0),
  reserved_eur numeric(20,8) CHECK(reserved_eur>=0),
  observed_eur numeric(20,8) CHECK(observed_eur>=0),
  state text NOT NULL CHECK(state IN ('reserved','settled','unknown','released')),
  FOREIGN KEY(project_id,job_id) REFERENCES core.jobs(project_id,id));

CREATE TABLE core.audit_events(
  id bigserial PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES core.organizations,
  project_id uuid REFERENCES core.projects,
  actor_id uuid,
  action text NOT NULL,
  target_id uuid,
  decision text NOT NULL,
  policy_version text NOT NULL,
  request_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now());

CREATE TABLE core.deletions(
  id uuid PRIMARY KEY,
  project_id uuid NOT NULL REFERENCES core.projects,
  target_kind text NOT NULL,
  target_id uuid NOT NULL,
  state text NOT NULL CHECK(state IN ('requested','revoked','purging','complete','failed')),
  revoked_at timestamptz NOT NULL,
  purge_deadline timestamptz NOT NULL,
  completed_at timestamptz,
  UNIQUE(project_id,target_kind,target_id));

-- ---------------------------------------------------------------------------
-- SkillBench domain (skb)
-- ---------------------------------------------------------------------------
CREATE TABLE skb.packages(
  id uuid PRIMARY KEY,
  project_id uuid NOT NULL,
  artifact_id uuid NOT NULL,
  name text NOT NULL CHECK(length(name) BETWEEN 1 AND 120),
  sha256 text NOT NULL CHECK(sha256 ~ '^[a-f0-9]{64}$'),
  state text NOT NULL CHECK(state IN ('quarantined','inspected','approved','rejected')),
  revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
  execution_profile text NOT NULL CHECK(execution_profile='fixture_only'),
  source_commit text CHECK(source_commit IS NULL OR source_commit ~ '^[a-f0-9]{40}$'),
  license_expression text CHECK(license_expression IS NULL OR length(license_expression)<=200),
  inspection_sha256 text CHECK(inspection_sha256 IS NULL OR inspection_sha256 ~ '^[a-f0-9]{64}$'),
  inspection_summary jsonb,
  inspected_at timestamptz,
  rejection_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(project_id,id),
  FOREIGN KEY(project_id,artifact_id) REFERENCES core.artifacts(project_id,id));

CREATE INDEX packages_project ON skb.packages(project_id,created_at DESC);

-- Metadata only: entry paths, sizes and the decision, never extracted content.
CREATE TABLE skb.package_entries(
  project_id uuid NOT NULL,
  package_id uuid NOT NULL,
  path text NOT NULL CHECK(length(path) BETWEEN 1 AND 1024),
  entry_type text NOT NULL CHECK(entry_type IN ('file','directory')),
  byte_size bigint NOT NULL CHECK(byte_size>=0),
  compressed_size bigint NOT NULL CHECK(compressed_size>=0),
  ordinal integer NOT NULL CHECK(ordinal>=0),
  PRIMARY KEY(package_id,path),
  FOREIGN KEY(project_id,package_id) REFERENCES skb.packages(project_id,id));

CREATE TABLE skb.package_findings(
  id uuid PRIMARY KEY,
  project_id uuid NOT NULL,
  package_id uuid NOT NULL,
  code text NOT NULL CHECK(length(code) BETWEEN 1 AND 80),
  severity text NOT NULL CHECK(severity IN ('info','low','medium','high','critical')),
  detail text NOT NULL CHECK(length(detail) BETWEEN 1 AND 500),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(project_id,package_id,code,detail),
  FOREIGN KEY(project_id,package_id) REFERENCES skb.packages(project_id,id));

CREATE TABLE skb.package_reviews(
  id uuid PRIMARY KEY,
  project_id uuid NOT NULL,
  package_id uuid NOT NULL,
  package_sha256 text NOT NULL CHECK(package_sha256 ~ '^[a-f0-9]{64}$'),
  package_revision bigint NOT NULL CHECK(package_revision>0),
  actor_id uuid NOT NULL REFERENCES core.users,
  decision text NOT NULL CHECK(decision IN ('approved','rejected')),
  reason text NOT NULL CHECK(length(reason) BETWEEN 5 AND 1000),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(project_id,id),
  FOREIGN KEY(project_id,package_id) REFERENCES skb.packages(project_id,id));

CREATE TABLE skb.suites(
  id uuid PRIMARY KEY,
  project_id uuid NOT NULL,
  name text NOT NULL CHECK(length(name) BETWEEN 1 AND 120),
  version integer NOT NULL CHECK(version>0),
  sha256 text NOT NULL CHECK(sha256 ~ '^[a-f0-9]{64}$'),
  definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object'),
  task_count integer NOT NULL CHECK(task_count>0),
  rights_manifest_artifact_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(project_id,id),
  FOREIGN KEY(project_id,rights_manifest_artifact_id) REFERENCES core.artifacts(project_id,id));

-- Hidden answers/scorers are never exposed by the product API and are revoked
-- from the runtime application role (see 002_roles.sql).
CREATE TABLE skb.hidden_answers(
  id uuid PRIMARY KEY,
  project_id uuid NOT NULL,
  suite_id uuid NOT NULL,
  artifact_id uuid NOT NULL,
  FOREIGN KEY(project_id,suite_id) REFERENCES skb.suites(project_id,id),
  FOREIGN KEY(project_id,artifact_id) REFERENCES core.artifacts(project_id,id));

CREATE TABLE skb.plans(
  id uuid PRIMARY KEY,
  project_id uuid NOT NULL,
  package_id uuid NOT NULL,
  package_sha256 text NOT NULL CHECK(package_sha256 ~ '^[a-f0-9]{64}$'),
  suite_id uuid NOT NULL,
  suite_sha256 text NOT NULL CHECK(suite_sha256 ~ '^[a-f0-9]{64}$'),
  sha256 text NOT NULL CHECK(sha256 ~ '^[a-f0-9]{64}$'),
  state text NOT NULL CHECK(state IN ('draft','preregistered')),
  revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
  definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  preregistered_at timestamptz,
  UNIQUE(project_id,id),
  FOREIGN KEY(project_id,package_id) REFERENCES skb.packages(project_id,id),
  FOREIGN KEY(project_id,suite_id) REFERENCES skb.suites(project_id,id),
  CHECK((state='preregistered') = (preregistered_at IS NOT NULL)));

CREATE TABLE skb.experiments(
  id uuid PRIMARY KEY,
  project_id uuid NOT NULL,
  plan_id uuid NOT NULL,
  plan_sha256 text NOT NULL CHECK(plan_sha256 ~ '^[a-f0-9]{64}$'),
  plan_revision bigint NOT NULL CHECK(plan_revision>0),
  state text NOT NULL CHECK(state IN ('queued','running','completed','stopped','failed')),
  job_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(project_id,id),
  FOREIGN KEY(project_id,plan_id) REFERENCES skb.plans(project_id,id),
  FOREIGN KEY(project_id,job_id) REFERENCES core.jobs(project_id,id));

CREATE TABLE skb.trials(
  id uuid PRIMARY KEY,
  project_id uuid NOT NULL,
  experiment_id uuid NOT NULL,
  task_id text NOT NULL CHECK(length(task_id) BETWEEN 1 AND 100),
  repeat integer NOT NULL CHECK(repeat>=0),
  arm text NOT NULL CHECK(arm IN ('baseline','treatment')),
  attempt integer NOT NULL CHECK(attempt>0),
  outcome text NOT NULL CHECK(outcome IN ('pass','fail','infra_error','policy_block','activation_failed','cancelled')),
  cost_eur numeric(20,8) CHECK(cost_eur>=0),
  currency text NOT NULL DEFAULT 'EUR' CHECK(currency='EUR'),
  trace_artifact_id uuid,
  result jsonb NOT NULL CHECK(jsonb_typeof(result)='object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY(project_id,experiment_id) REFERENCES skb.experiments(project_id,id),
  FOREIGN KEY(project_id,trace_artifact_id) REFERENCES core.artifacts(project_id,id),
  UNIQUE(experiment_id,task_id,repeat,arm,attempt));

CREATE INDEX trials_experiment ON skb.trials(experiment_id,task_id,repeat,arm);

CREATE TABLE skb.analyses(
  id uuid PRIMARY KEY,
  project_id uuid NOT NULL,
  experiment_id uuid NOT NULL,
  input_sha256 text NOT NULL CHECK(input_sha256 ~ '^[a-f0-9]{64}$'),
  version text NOT NULL CHECK(version='paired-task-bootstrap/1'),
  status text NOT NULL CHECK(status IN ('valid','partial','insufficient')),
  result jsonb NOT NULL CHECK(jsonb_typeof(result)='object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(project_id,id),
  FOREIGN KEY(project_id,experiment_id) REFERENCES skb.experiments(project_id,id));

-- One analysis per frozen input: re-analysis is a replay of the same digest, never
-- a second competing verdict over identical data.
CREATE UNIQUE INDEX analyses_input_digest ON skb.analyses(experiment_id, input_sha256, version);

-- ---------------------------------------------------------------------------
-- Append-only / immutability guards
-- ---------------------------------------------------------------------------
CREATE FUNCTION core.prevent_mutation() RETURNS trigger LANGUAGE plpgsql AS
$$ BEGIN RAISE EXCEPTION 'immutable_record' USING ERRCODE='23000'; END $$;

CREATE TRIGGER no_review_mutation BEFORE UPDATE OR DELETE ON skb.package_reviews FOR EACH ROW EXECUTE FUNCTION core.prevent_mutation();
CREATE TRIGGER no_trial_mutation BEFORE UPDATE OR DELETE ON skb.trials FOR EACH ROW EXECUTE FUNCTION core.prevent_mutation();
CREATE TRIGGER no_analysis_mutation BEFORE UPDATE OR DELETE ON skb.analyses FOR EACH ROW EXECUTE FUNCTION core.prevent_mutation();
CREATE TRIGGER no_audit_mutation BEFORE UPDATE OR DELETE ON core.audit_events FOR EACH ROW EXECUTE FUNCTION core.prevent_mutation();
CREATE TRIGGER no_finding_mutation BEFORE UPDATE OR DELETE ON skb.package_findings FOR EACH ROW EXECUTE FUNCTION core.prevent_mutation();

-- Draft plans may be updated; a preregistered plan is frozen except for the
-- trigger's own bookkeeping (none exists: preregistration is a one-way state).
CREATE FUNCTION skb.freeze_plan() RETURNS trigger LANGUAGE plpgsql AS
$$ BEGIN
  IF OLD.state='preregistered' THEN
    RAISE EXCEPTION 'preregistered_plan_immutable' USING ERRCODE='23000';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER freeze_plan BEFORE UPDATE ON skb.plans FOR EACH ROW EXECUTE FUNCTION skb.freeze_plan();
CREATE TRIGGER freeze_plan_delete BEFORE DELETE ON skb.plans FOR EACH ROW EXECUTE FUNCTION skb.freeze_plan();

-- Artifact identity is committed by finalize and immutable afterwards.
CREATE FUNCTION core.freeze_artifact_identity() RETURNS trigger LANGUAGE plpgsql AS
$$ BEGIN
  IF OLD.state='ready' AND (NEW.sha256 <> OLD.sha256 OR NEW.byte_size <> OLD.byte_size
                            OR NEW.project_id <> OLD.project_id OR NEW.storage_key <> OLD.storage_key) THEN
    RAISE EXCEPTION 'artifact_identity_immutable' USING ERRCODE='23000';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER freeze_artifact_identity BEFORE UPDATE ON core.artifacts FOR EACH ROW EXECUTE FUNCTION core.freeze_artifact_identity();

-- Package content is immutable: digest and artifact binding can never change.
CREATE FUNCTION skb.freeze_package_identity() RETURNS trigger LANGUAGE plpgsql AS
$$ BEGIN
  IF NEW.sha256 <> OLD.sha256 OR NEW.artifact_id <> OLD.artifact_id OR NEW.project_id <> OLD.project_id THEN
    RAISE EXCEPTION 'package_identity_immutable' USING ERRCODE='23000';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER freeze_package_identity BEFORE UPDATE ON skb.packages FOR EACH ROW EXECUTE FUNCTION skb.freeze_package_identity();

-- ---------------------------------------------------------------------------
-- Narrow SECURITY DEFINER lookups for the pre-context authentication phase and
-- for the trusted scheduler claim. Each function has a fixed search_path, no
-- dynamic SQL and returns only the columns the runtime needs.
-- ---------------------------------------------------------------------------
CREATE FUNCTION core.resolve_identity(p_issuer text, p_subject text)
RETURNS TABLE(user_id uuid, organization_id uuid, org_role text, project_id uuid, project_role text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,core,public AS $$
  SELECT u.id, m.organization_id, m.org_role, pr.project_id, pr.role
  FROM core.users u
  JOIN core.memberships m ON m.user_id=u.id
  LEFT JOIN core.project_roles pr ON pr.user_id=u.id
    AND pr.project_id IN (SELECT p.id FROM core.projects p WHERE p.organization_id=m.organization_id)
  WHERE u.issuer=p_issuer AND u.subject=p_subject
$$;

CREATE FUNCTION core.resolve_api_key(p_digest bytea)
RETURNS TABLE(key_id uuid, actor_id uuid, project_id uuid, organization_id uuid, scopes text[], expires_at timestamptz, revoked_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,core,public AS $$
  SELECT k.id, k.actor_id, k.project_id, p.organization_id, k.scopes, k.expires_at, k.revoked_at
  FROM core.api_keys k JOIN core.projects p ON p.id=k.project_id
  WHERE k.key_digest=p_digest
$$;

CREATE FUNCTION core.resolve_session(p_digest bytea)
RETURNS TABLE(session_id uuid, user_id uuid, organization_id uuid, csrf_token text, idle_expires_at timestamptz, absolute_expires_at timestamptz, revoked_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,core,public AS $$
  SELECT s.id, s.user_id, s.organization_id, s.csrf_token, s.idle_expires_at, s.absolute_expires_at, s.revoked_at
  FROM core.sessions s WHERE s.token_digest=p_digest
$$;

-- Membership/capability context for an already-authenticated user.
CREATE FUNCTION core.resolve_user_context(p_user_id uuid)
RETURNS TABLE(user_id uuid, organization_id uuid, org_role text, project_id uuid, project_role text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,core,public AS $$
  SELECT u.id, m.organization_id, m.org_role, pr.project_id, pr.role
  FROM core.users u
  JOIN core.memberships m ON m.user_id=u.id
  LEFT JOIN core.project_roles pr ON pr.user_id=u.id
    AND pr.project_id IN (SELECT p.id FROM core.projects p WHERE p.organization_id=m.organization_id)
  WHERE u.id=p_user_id
$$;

-- Trusted scheduler claim. Returns at most one queued or lease-expired job and
-- fences it atomically; a duplicate claim cannot observe the same row.
CREATE FUNCTION core.claim_job(p_kinds text[], p_lease_seconds integer DEFAULT 30)
RETURNS TABLE(project_id uuid, job_id uuid, kind text, payload jsonb, attempt integer, fence bigint,
              cancel_requested boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,core,public AS $$
DECLARE r record; v_cancel boolean;
BEGIN
  IF p_lease_seconds < 1 OR p_lease_seconds > 900 THEN RAISE EXCEPTION 'invalid_lease'; END IF;
  SELECT j.id, j.project_id INTO r
  FROM core.jobs j
  WHERE j.kind = ANY(p_kinds)
    AND (j.state IN ('queued','cancel_requested')
         OR (j.state IN ('leased','running') AND j.lease_until < now()))
  ORDER BY j.created_at, j.id
  FOR UPDATE SKIP LOCKED LIMIT 1;
  IF NOT FOUND THEN RETURN; END IF;
  -- Cancellation intent survives the claim: the worker stops before doing work.
  SELECT j.state='cancel_requested' INTO v_cancel FROM core.jobs j WHERE j.id=r.id;
  -- A lease-expired attempt is abandoned, not silently reported as success.
  UPDATE core.job_attempts a SET state='abandoned', finished_at=now()
   WHERE a.job_id=r.id AND a.state='running';
  UPDATE core.jobs j SET state='leased',
    attempt=j.attempt+1,
    fence=j.fence+1,
    lease_until=now()+make_interval(secs=>p_lease_seconds),
    revision=j.revision+1, updated_at=now()
  WHERE j.id=r.id
  RETURNING j.project_id, j.id, j.kind, j.payload, j.attempt, j.fence
  INTO project_id, job_id, kind, payload, attempt, fence;
  cancel_requested := v_cancel;
  INSERT INTO core.job_attempts(project_id,job_id,attempt,fence,state)
  VALUES (project_id, job_id, attempt, fence, 'running');
  RETURN NEXT;
END $$;

REVOKE ALL ON FUNCTION core.resolve_identity(text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION core.resolve_api_key(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION core.resolve_session(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION core.resolve_user_context(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION core.claim_job(text[],integer) FROM PUBLIC;

COMMIT;
