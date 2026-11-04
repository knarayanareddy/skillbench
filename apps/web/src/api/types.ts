/** Response shapes mirrored from contracts/schemas. Never invented client-side. */

export type UUID = string;

export interface Problem {
  type: string;
  title: string;
  status: number;
  code: string;
  detail: string;
  request_id?: string;
  field_errors?: Array<{ path: string; code: string }>;
}

export interface ProjectMembership {
  project_id: UUID;
  roles: string[];
}

export interface SessionBody {
  actor_id: UUID;
  organization_id: UUID;
  org_role: "member" | "admin";
  principal: "session" | "api_key";
  csrf_token: string;
  projects: ProjectMembership[];
  expires_at: string;
}

export interface Project {
  id: UUID;
  name: string;
  content_capture: "metadata_only" | "full_content";
  external_transfer: boolean;
  revision: number;
  created_at: string;
}

export type PackageState = "quarantined" | "inspected" | "approved" | "rejected";

export interface Package {
  id: UUID;
  project_id: UUID;
  artifact_id: UUID;
  sha256: string;
  state: PackageState;
  execution_profile: "fixture_only";
  revision: number;
}

export interface PackageEntry {
  path: string;
  entry_type: string;
  byte_size: number;
  compressed_size: number;
  ordinal: number;
}

export interface Finding {
  code: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  detail: string;
}

export interface PackageReview {
  id: UUID;
  package_sha256: string;
  package_revision: number;
  decision: "approved" | "rejected";
  reason: string;
  created_at: string;
}

export interface PackageDetail extends Package {
  name: string;
  inspection_sha256: string | null;
  inspection_summary: Record<string, unknown> | null;
  rejection_code: string | null;
  inspected_at: string | null;
  entries: PackageEntry[];
  findings: Finding[];
  reviews: PackageReview[];
  labels: string[];
}

export interface Suite {
  id: UUID;
  project_id: UUID;
  sha256: string;
  version: number;
  task_count: number;
  created_at: string;
}

export type PlanState = "draft" | "preregistered";

export interface Plan {
  id: UUID;
  project_id: UUID;
  sha256: string;
  state: PlanState;
  revision: number;
  definition: Record<string, unknown>;
  created_at: string;
}

export type ExperimentState = "queued" | "running" | "completed" | "stopped" | "failed";

export interface Experiment {
  id: UUID;
  project_id: UUID;
  plan_id: UUID;
  plan_sha256: string;
  state: ExperimentState;
  job_id: UUID;
  created_at: string;
}

export interface Trial {
  task_id: string;
  repeat: number;
  arm: "baseline" | "treatment";
  outcome: "pass" | "fail" | "infra_error" | "policy_block" | "activation_failed" | "cancelled";
  cost: string | null;
  currency: string;
  attempt: number;
  trace_artifact_id: UUID | null;
}

export type AnalysisStatus = "valid" | "partial" | "insufficient";

export interface Analysis {
  id: UUID;
  experiment_id: UUID;
  analysis_version: "paired-task-bootstrap/1";
  input_sha256: string;
  status: AnalysisStatus;
  n_tasks: number;
  n_complete_tasks: number;
  delta: number | null;
  ci_low: number | null;
  ci_high: number | null;
  bound_low: number | null;
  bound_high: number | null;
  interpretation: "descriptive_no_certification";
  missing_trials: number;
}

export interface Job {
  id: UUID;
  project_id: UUID;
  kind: string;
  state: string;
  attempt: number;
  revision: number;
  created_at: string;
  result_id: UUID | null;
  error_code: string | null;
}

export interface ListBody<T> {
  items: T[];
  next_cursor: string | null;
}

export interface UploadTicket {
  id: UUID;
  artifact_id: UUID;
  project_id: UUID;
  put_path: string;
  expires_at: string;
}
