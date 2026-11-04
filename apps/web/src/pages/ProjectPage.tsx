import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ApiError, request } from "../api/client";
import type { Experiment, ListBody, Package, SessionBody, Suite } from "../api/types";
import { Alert, EmptyState, SimulationNotice, Skeleton, StatusBadge } from "../components/ui";

export function ProjectPage({ session }: { session: SessionBody }): JSX.Element {
  const { projectId = "" } = useParams<{ projectId: string }>();
  const canMaintain = (session.projects.find((p) => p.project_id === projectId)?.roles ?? []).includes("maintainer");
  const [packages, setPackages] = useState<Package[] | null>(null);
  const [suites, setSuites] = useState<Suite[] | null>(null);
  const [experiments, setExperiments] = useState<Experiment[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const base = `/api/v1/projects/${projectId}/skb`;
      const [packageBody, suiteBody, experimentBody] = await Promise.all([
        request<ListBody<Package>>(`${base}/packages`, { projectId }),
        request<ListBody<Suite>>(`${base}/suites`, { projectId }),
        request<ListBody<Experiment>>(`${base}/experiments`, { projectId }),
      ]);
      setPackages(packageBody.items);
      setSuites(suiteBody.items);
      setExperiments(experimentBody.items);
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.problem.detail : "Could not load this project.");
    }
  }, [projectId]);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <section className="stack">
      <header className="page-header">
        <div>
          <p className="breadcrumb">
            <Link to="/">Projects</Link> / <span>Project</span>
          </p>
          <h1>Project workspace</h1>
          <p className="muted mono">{projectId}</p>
        </div>
        <div className="page-header__actions">
          {canMaintain ? (
            <Link className="button button--primary" to={`/projects/${projectId}/packages/new`}>
              Register a package
            </Link>
          ) : null}
          <button type="button" className="button" onClick={() => void load()}>
            Refresh
          </button>
        </div>
      </header>

      <SimulationNotice />

      {error ? <Alert title="Project data unavailable">{error}</Alert> : null}

      <section className="panel" aria-labelledby="packages-heading">
        <h2 id="packages-heading">Packages</h2>
        {packages === null ? <Skeleton rows={2} /> : null}
        {packages?.length === 0 ? (
          <EmptyState title="No packages yet">
            <p>Upload a ZIP, inspect it inertly, then have a maintainer approve the exact digest.</p>
          </EmptyState>
        ) : null}
        {packages && packages.length > 0 ? (
          <table className="table">
            <caption className="visually-hidden">Packages in this project</caption>
            <thead>
              <tr>
                <th scope="col">Digest</th>
                <th scope="col">State</th>
                <th scope="col">Execution</th>
                <th scope="col">Revision</th>
              </tr>
            </thead>
            <tbody>
              {packages.map((item) => (
                <tr key={item.id}>
                  <th scope="row">
                    <Link className="mono" to={`/projects/${projectId}/packages/${item.id}`}>
                      {item.sha256.slice(0, 12)}…
                    </Link>
                  </th>
                  <td>
                    <StatusBadge state={item.state} />
                  </td>
                  <td>{item.execution_profile === "fixture_only" ? "Fixtures only" : item.execution_profile}</td>
                  <td>{item.revision}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </section>

      <section className="panel" aria-labelledby="suites-heading">
        <h2 id="suites-heading">Suites</h2>
        <p className="muted small">Suites are immutable once created; a new version is a new suite.</p>
        {suites === null ? <Skeleton rows={1} /> : null}
        {suites?.length === 0 ? <EmptyState title="No suites yet" /> : null}
        {suites && suites.length > 0 ? (
          <table className="table">
            <caption className="visually-hidden">Suites in this project</caption>
            <thead>
              <tr>
                <th scope="col">Digest</th>
                <th scope="col">Tasks</th>
                <th scope="col">Version</th>
                <th scope="col">Created</th>
              </tr>
            </thead>
            <tbody>
              {suites.map((suite) => (
                <tr key={suite.id}>
                  <td className="mono">{suite.sha256.slice(0, 12)}…</td>
                  <td>{suite.task_count}</td>
                  <td>{suite.version}</td>
                  <td>{new Date(suite.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </section>

      <section className="panel" aria-labelledby="experiments-heading">
        <h2 id="experiments-heading">Experiments</h2>
        {experiments === null ? <Skeleton rows={1} /> : null}
        {experiments?.length === 0 ? <EmptyState title="No experiments yet" /> : null}
        {experiments && experiments.length > 0 ? (
          <table className="table">
            <caption className="visually-hidden">Experiments in this project</caption>
            <thead>
              <tr>
                <th scope="col">Experiment</th>
                <th scope="col">State</th>
                <th scope="col">Plan digest</th>
                <th scope="col">Created</th>
              </tr>
            </thead>
            <tbody>
              {experiments.map((experiment) => (
                <tr key={experiment.id}>
                  <th scope="row">
                    <Link to={`/projects/${projectId}/experiments/${experiment.id}`}>
                      Open experiment
                    </Link>
                  </th>
                  <td>
                    <StatusBadge state={experiment.state} />
                  </td>
                  <td className="mono">{experiment.plan_sha256.slice(0, 12)}…</td>
                  <td>{new Date(experiment.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </section>
    </section>
  );
}
