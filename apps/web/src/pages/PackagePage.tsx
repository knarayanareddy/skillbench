import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ApiError, request, requestWithEtag } from "../api/client";
import type { PackageDetail, SessionBody } from "../api/types";
import { Alert, EmptyState, SimulationNotice, Skeleton, StatusBadge, formatBytes } from "../components/ui";

export function PackagePage({ session }: { session: SessionBody }): JSX.Element {
  const { projectId = "", packageId = "" } = useParams<{ projectId: string; packageId: string }>();
  const [detail, setDetail] = useState<PackageDetail | null>(null);
  const [etag, setEtag] = useState<string | null>(null);
  const [problem, setProblem] = useState<ApiError | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const roles = session.projects.find((item) => item.project_id === projectId)?.roles ?? [];
  const canInspect = roles.some((role) => role === "operator" || role === "maintainer");
  const canApprove = roles.includes("maintainer");

  const load = useCallback(async () => {
    try {
      const response = await fetch(`/api/v1/skb/packages/${packageId}/inspection`, {
        headers: { Accept: "application/json", "X-Project-ID": projectId },
        credentials: "same-origin",
      });
      if (!response.ok) {
        const body = (await response.json()) as { detail?: string; title?: string };
        throw new ApiError({
          type: "about:blank",
          title: body.title ?? "Unavailable",
          status: response.status,
          code: "error",
          detail: body.detail ?? "Package unavailable.",
        });
      }
      setDetail((await response.json()) as PackageDetail);
      setEtag(response.headers.get("etag"));
      setProblem(null);
    } catch (caught) {
      if (caught instanceof ApiError) setProblem(caught);
      else setProblem(new ApiError({
        type: "about:blank",
        title: "Unavailable",
        status: 0,
        code: "network",
        detail: "Could not reach the service.",
      }));
    }
  }, [packageId, projectId]);

  useEffect(() => {
    void load();
  }, [load]);

  async function inspect(): Promise<void> {
    setBusy(true);
    setNotice(null);
    try {
      await request(`/api/v1/skb/packages/${packageId}:inspect`, {
        method: "POST",
        projectId,
        body: {},
      });
      setNotice("Inspection queued. The package stays quarantined until the scan finishes.");
      await load();
    } catch (caught) {
      if (caught instanceof ApiError) setProblem(caught);
    } finally {
      setBusy(false);
    }
  }

  async function review(decision: "approved" | "rejected", reason: string): Promise<void> {
    if (!detail || !etag) return;
    setBusy(true);
    setProblem(null);
    try {
      await requestWithEtag(`/api/v1/skb/packages/${packageId}/reviews`, etag, {
        method: "POST",
        projectId,
        body: { decision, package_sha256: detail.sha256, reason },
      });
      setNotice(decision === "approved" ? "Package approved for this exact digest." : "Package rejected.");
      await load();
    } catch (caught) {
      if (caught instanceof ApiError) setProblem(caught);
    } finally {
      setBusy(false);
    }
  }

  if (problem) {
    return (
      <section className="stack stack--narrow">
        <Alert title={problem.problem.title}>{problem.problem.detail}</Alert>
        <Link className="button" to={`/projects/${projectId}`}>
          Back to project
        </Link>
      </section>
    );
  }
  if (!detail) {
    return (
      <section className="stack">
        <Skeleton rows={4} />
      </section>
    );
  }

  const summary = detail.inspection_summary ?? {};
  const accepted = summary["accepted"] === true;
  const scanError = typeof summary["error"] === "string" ? summary["error"] : null;
  const findings = detail.findings;

  return (
    <section className="stack">
      <p className="breadcrumb">
        <Link to={`/projects/${projectId}`}>Project</Link> / <span>Package</span>
      </p>
      <header className="page-header">
        <div>
          <h1>{detail.name || "Skill package"}</h1>
          <p className="mono small">{detail.sha256}</p>
          <p className="row">
            <StatusBadge state={detail.state} /> <span className="muted">revision {detail.revision}</span>
          </p>
        </div>
        <div className="page-header__actions">
          {canInspect && detail.state !== "approved" && detail.state !== "rejected" ? (
            <button type="button" className="button" onClick={() => void inspect()} disabled={busy}>
              Queue inert inspection
            </button>
          ) : null}
        </div>
      </header>

      <SimulationNotice>
        Inspection is metadata-only: entries are listed, never extracted or executed. Approval binds
        this exact digest for fixture-only experiments.
      </SimulationNotice>

      {notice ? <Alert tone="info" title="Status">{notice}</Alert> : null}
      {scanError ? (
        <Alert tone="warn" title="Inspection could not complete">
          The scanner reported <span className="mono">{scanError}</span>. The package stays
          quarantined; this is never treated as a clean scan.
        </Alert>
      ) : null}

      <section className="panel" aria-labelledby="evidence-heading">
        <h2 id="evidence-heading">Inspection evidence</h2>
        {detail.inspected_at ? (
          <dl className="facts">
            <div>
              <dt>Verdict</dt>
              <dd>{accepted ? "Accepted (no blocking findings)" : `Blocked${detail.rejection_code ? `: ${detail.rejection_code}` : ""}`}</dd>
            </div>
            <div>
              <dt>Inspected at</dt>
              <dd>{new Date(detail.inspected_at).toLocaleString()}</dd>
            </div>
            <div>
              <dt>Files</dt>
              <dd>{detail.entries.length}</dd>
            </div>
            <div>
              <dt>Expanded bytes</dt>
              <dd>{formatBytes(detail.entries.reduce((sum, entry) => sum + entry.byte_size, 0))}</dd>
            </div>
          </dl>
        ) : (
          <EmptyState title="Not inspected yet">
            <p>Queue an inspection to record the file inventory and findings.</p>
          </EmptyState>
        )}
      </section>

      <section className="panel" aria-labelledby="findings-heading">
        <h2 id="findings-heading">Findings</h2>
        {findings.length === 0 ? (
          <p className="muted">No findings recorded.</p>
        ) : (
          <table className="table">
            <caption className="visually-hidden">Inspection findings</caption>
            <thead>
              <tr>
                <th scope="col">Severity</th>
                <th scope="col">Code</th>
                <th scope="col">Detail</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((finding) => (
                <tr key={`${finding.code}-${finding.detail}`}>
                  <th scope="row">{finding.severity}</th>
                  <td className="mono">{finding.code}</td>
                  <td>{finding.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="panel" aria-labelledby="files-heading">
        <h2 id="files-heading">File inventory</h2>
        {detail.entries.length === 0 ? (
          <p className="muted">No entries recorded.</p>
        ) : (
          <table className="table">
            <caption className="visually-hidden">Package entries (paths only)</caption>
            <thead>
              <tr>
                <th scope="col">Path</th>
                <th scope="col">Type</th>
                <th scope="col">Declared size</th>
                <th scope="col">Compressed</th>
              </tr>
            </thead>
            <tbody>
              {detail.entries.map((entry) => (
                <tr key={`${entry.ordinal}-${entry.path}`}>
                  <th scope="row" className="mono">
                    {entry.path}
                  </th>
                  <td>{entry.entry_type}</td>
                  <td>{formatBytes(entry.byte_size)}</td>
                  <td>{formatBytes(entry.compressed_size)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {canApprove && detail.state === "inspected" ? (
        <ReviewForm busy={busy} onSubmit={review} digest={detail.sha256} revision={detail.revision} />
      ) : null}

      <section className="panel" aria-labelledby="reviews-heading">
        <h2 id="reviews-heading">Review decisions</h2>
        {detail.reviews.length === 0 ? (
          <p className="muted">No decision recorded.</p>
        ) : (
          <ul className="list">
            {detail.reviews.map((review) => (
              <li key={review.id}>
                <StatusBadge state={review.decision} />
                <span className="mono small"> {review.package_sha256.slice(0, 12)}…</span>
                <p>{review.reason}</p>
                <p className="muted small">
                  revision {review.package_revision} · {new Date(review.created_at).toLocaleString()}
                </p>
              </li>
            ))}
          </ul>
        )}
      </section>
    </section>
  );
}

function ReviewForm({
  busy,
  digest,
  revision,
  onSubmit,
}: {
  busy: boolean;
  digest: string;
  revision: number;
  onSubmit: (decision: "approved" | "rejected", reason: string) => Promise<void>;
}): JSX.Element {
  const [reason, setReason] = useState("");
  const [decision, setDecision] = useState<"approved" | "rejected">("approved");
  const valid = reason.trim().length >= 5 && reason.trim().length <= 1000;
  return (
    <form
      className="panel form"
      onSubmit={(event) => {
        event.preventDefault();
        if (valid) void onSubmit(decision, reason.trim());
      }}
    >
      <h2>Record a review decision</h2>
      <p className="muted small">
        You are reviewing digest <span className="mono">{digest.slice(0, 16)}…</span> at revision{" "}
        {revision}. The decision is final for this revision.
      </p>
      <fieldset className="field">
        <legend>Decision</legend>
        <label className="row">
          <input
            type="radio"
            name="decision"
            value="approved"
            checked={decision === "approved"}
            onChange={() => setDecision("approved")}
          />
          Approve for fixture-only experiments
        </label>
        <label className="row">
          <input
            type="radio"
            name="decision"
            value="rejected"
            checked={decision === "rejected"}
            onChange={() => setDecision("rejected")}
          />
          Reject
        </label>
      </fieldset>
      <label className="field">
        <span>Reason (recorded in the audit trail)</span>
        <textarea
          required
          minLength={5}
          maxLength={1000}
          rows={4}
          value={reason}
          onChange={(event) => setReason(event.target.value)}
        />
      </label>
      <div className="form__actions">
        <button type="submit" className="button button--primary" disabled={busy || !valid}>
          Record decision
        </button>
      </div>
    </form>
  );
}
