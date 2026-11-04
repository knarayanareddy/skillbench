import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ApiError, request } from "../api/client";
import type { Analysis, Experiment, ListBody, SessionBody, Trial } from "../api/types";
import {
  Alert,
  EmptyState,
  SimulationNotice,
  Skeleton,
  StatusBadge,
  formatNumber,
} from "../components/ui";

export function ExperimentPage({ session }: { session: SessionBody }): JSX.Element {
  const { projectId = "", experimentId = "" } = useParams<{ projectId: string; experimentId: string }>();
  const [experiment, setExperiment] = useState<Experiment | null>(null);
  const [trials, setTrials] = useState<Trial[] | null>(null);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [problem, setProblem] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const roles = session.projects.find((item) => item.project_id === projectId)?.roles ?? [];
  const canAnalyse = roles.some((role) => role === "analyst" || role === "maintainer");

  const load = useCallback(async () => {
    try {
      const [experimentBody, trialBody] = await Promise.all([
        request<Experiment>(`/api/v1/skb/experiments/${experimentId}`, { projectId }),
        request<ListBody<Trial>>(`/api/v1/skb/experiments/${experimentId}/trials`, { projectId }),
      ]);
      setExperiment(experimentBody);
      setTrials(trialBody.items);
      setProblem(null);
    } catch (caught) {
      if (caught instanceof ApiError) setProblem(caught);
    }
  }, [experimentId, projectId]);

  useEffect(() => {
    void load();
  }, [load]);

  async function analyse(): Promise<void> {
    setBusy(true);
    setProblem(null);
    try {
      const body = await request<Analysis>(`/api/v1/skb/experiments/${experimentId}/analyses`, {
        method: "POST",
        projectId,
        body: {},
      });
      setAnalysis(body);
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
  if (!experiment) {
    return (
      <section className="stack">
        <Skeleton rows={4} />
      </section>
    );
  }

  const counts = summarise(trials ?? []);

  return (
    <section className="stack">
      <p className="breadcrumb">
        <Link to={`/projects/${projectId}`}>Project</Link> / <span>Experiment</span>
      </p>
      <header className="page-header">
        <div>
          <h1>Fixture experiment</h1>
          <p className="row">
            <StatusBadge state={experiment.state} />{" "}
            <span className="muted mono small">plan {experiment.plan_sha256.slice(0, 12)}…</span>
          </p>
          <p className="muted small">
            {experiment.state === "queued"
              ? "Queued: the worker replays recorded synthetic trials for every task and arm."
              : experiment.state === "running"
                ? "Running: trials appear as the worker commits them."
                : "The run has finished; unexecuted trials are absent, never invented."}
          </p>
        </div>
        <div className="page-header__actions">
          <button type="button" className="button" onClick={() => void load()}>
            Refresh
          </button>
          {canAnalyse && ["completed", "stopped", "failed"].includes(experiment.state) ? (
            <button type="button" className="button button--primary" onClick={() => void analyse()} disabled={busy}>
              Compute descriptive analysis
            </button>
          ) : null}
        </div>
      </header>

      <SimulationNotice />

      <section className="panel" aria-labelledby="trials-heading">
        <h2 id="trials-heading">Recorded trials</h2>
        {trials === null ? <Skeleton rows={2} /> : null}
        {trials?.length === 0 ? (
          <EmptyState title="No trials recorded">
            <p>A queued run replays recorded synthetic trials for each task and arm.</p>
          </EmptyState>
        ) : null}
        {trials && trials.length > 0 ? (
          <>
            <dl className="facts">
              <div>
                <dt>Trials</dt>
                <dd>{trials.length}</dd>
              </div>
              <div>
                <dt>Pass</dt>
                <dd>{counts.pass}</dd>
              </div>
              <div>
                <dt>Fail</dt>
                <dd>{counts.fail}</dd>
              </div>
              <div>
                <dt>Unknown (infra error)</dt>
                <dd>{counts.infra_error}</dd>
              </div>
            </dl>
            <details>
              <summary>Show all recorded trials</summary>
              <table className="table table--dense">
                <caption className="visually-hidden">All recorded trials</caption>
                <thead>
                  <tr>
                    <th scope="col">Task</th>
                    <th scope="col">Repeat</th>
                    <th scope="col">Arm</th>
                    <th scope="col">Outcome</th>
                    <th scope="col">Attempt</th>
                  </tr>
                </thead>
                <tbody>
                  {trials.map((trial) => (
                    <tr key={`${trial.task_id}-${trial.repeat}-${trial.arm}-${trial.attempt}`}>
                      <th scope="row" className="mono">
                        {trial.task_id}
                      </th>
                      <td>{trial.repeat}</td>
                      <td>{trial.arm}</td>
                      <td>{trial.outcome.replace(/_/g, " ")}</td>
                      <td>{trial.attempt}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </details>
          </>
        ) : null}
      </section>

      <section className="panel" aria-labelledby="analysis-heading">
        <h2 id="analysis-heading">Descriptive analysis</h2>
        {analysis === null ? (
          <p className="muted">
            No analysis yet. Analysis is descriptive: it reports a paired mean difference and an
            interval, not proof of improvement, equivalence or safety.
          </p>
        ) : (
          <>
            <p className="row">
              <StatusBadge state={analysis.status} label={`evidence status: ${analysis.status}`} />
              <span className="muted small">descriptive, no certification</span>
            </p>
            <dl className="facts">
              <div>
                <dt>Tasks</dt>
                <dd>
                  {analysis.n_complete_tasks} / {analysis.n_tasks} complete
                </dd>
              </div>
              <div>
                <dt>Mean paired difference</dt>
                <dd>{formatNumber(analysis.delta)}</dd>
              </div>
              <div>
                <dt>Interval (95%)</dt>
                <dd>
                  {formatNumber(analysis.ci_low)} … {formatNumber(analysis.ci_high)}
                </dd>
              </div>
              <div>
                <dt>Bounds (missing pairs)</dt>
                <dd>
                  {formatNumber(analysis.bound_low)} … {formatNumber(analysis.bound_high)}
                </dd>
              </div>
              <div>
                <dt>Missing trials</dt>
                <dd>{analysis.missing_trials}</dd>
              </div>
              <div>
                <dt>Input digest</dt>
                <dd className="mono small">{analysis.input_sha256.slice(0, 16)}…</dd>
              </div>
            </dl>
            <p className="muted small">
              {analysis.status === "insufficient"
                ? "Too few complete tasks for an interval; treat this as no result."
                : "Partial or valid descriptive statistics over recorded synthetic trials. They do not license efficacy, equivalence or safety claims."}
            </p>
          </>
        )}
      </section>
    </section>
  );
}

function summarise(trials: Trial[]): Record<string, number> {
  const counts: Record<string, number> = { pass: 0, fail: 0, infra_error: 0 };
  for (const trial of trials) {
    counts[trial.outcome] = (counts[trial.outcome] ?? 0) + 1;
  }
  return counts;
}
