import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ApiError, request, requestWithEtag } from "../api/client";
import type { ListBody, Package, Plan, SessionBody, Suite } from "../api/types";
import { Alert, SimulationNotice } from "../components/ui";

export function NewPlanPage({ session, projectId }: { session: SessionBody; projectId: string }): JSX.Element {
  const navigate = useNavigate();
  const [packages, setPackages] = useState<Package[]>([]);
  const [suites, setSuites] = useState<Suite[]>([]);
  const [packageId, setPackageId] = useState("");
  const [suiteId, setSuiteId] = useState("");
  const [repetitions, setRepetitions] = useState(3);
  const [problem, setProblem] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const canMaintain = (session.projects.find((item) => item.project_id === projectId)?.roles ?? []).includes(
    "maintainer",
  );

  useEffect(() => {
    const base = `/api/v1/projects/${projectId}/skb`;
    void Promise.all([
      request<ListBody<Package>>(`${base}/packages`, { projectId }),
      request<ListBody<Suite>>(`${base}/suites`, { projectId }),
    ])
      .then(([packageBody, suiteBody]) => {
        setPackages(packageBody.items.filter((item) => item.state === "approved"));
        setSuites(suiteBody.items);
        const approved = packageBody.items.find((item) => item.state === "approved");
        if (approved) setPackageId(approved.id);
        const suite = suiteBody.items[0];
        if (suite) setSuiteId(suite.id);
      })
      .catch(() => undefined);
  }, [projectId]);

  async function submit(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setProblem(null);
    setBusy(true);
    try {
      const pkg = packages.find((item) => item.id === packageId);
      const suite = suites.find((item) => item.id === suiteId);
      if (!pkg || !suite) throw new Error("missing selection");
      const plan = await request<Plan>(`/api/v1/projects/${projectId}/skb/plans`, {
        method: "POST",
        projectId,
        body: {
          package_id: pkg.id,
          package_sha256: pkg.sha256,
          suite_id: suite.id,
          suite_sha256: suite.sha256,
          harness: "fixture/1",
          model: "recorded/1",
          repetitions,
          seed: 17,
          bootstrap_iterations: 2000,
          practical_margin: 0.05,
          primary_metric: "task_mean_success_delta",
          missing_rule: "report_bounds_no_silent_drop",
          mode: "fixture_only",
        },
      });
      // The plan body carries the revision in a header; preregistering needs it.
      const etag = `"${plan.revision}"`;
      await requestWithEtag(`/api/v1/skb/plans/${plan.id}:preregister`, etag, {
        method: "POST",
        projectId,
        body: {},
      });
      navigate(`/projects/${projectId}`);
    } catch (caught) {
      if (caught instanceof ApiError) setProblem(caught);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="stack stack--narrow">
      <p className="breadcrumb">
        <Link to={`/projects/${projectId}`}>Project</Link> / <span>New plan</span>
      </p>
      <h1>Preregister an experiment plan</h1>
      <SimulationNotice>
        The plan fixes the package digest, suite digest, repetition count and analysis settings before
        any trial exists. Preregistration freezes the plan: it cannot be edited afterwards.
      </SimulationNotice>
      {problem ? <Alert title={problem.problem.title}>{problem.problem.detail}</Alert> : null}
      {!canMaintain ? (
        <Alert tone="warn" title="Maintainer role required">
          Preregistration is limited to project maintainers.
        </Alert>
      ) : null}
      <form className="form" onSubmit={(event) => void submit(event)}>
        <label className="field">
          <span>Approved package</span>
          <select value={packageId} required onChange={(event) => setPackageId(event.target.value)}>
            <option value="">Select an approved package</option>
            {packages.map((item) => (
              <option key={item.id} value={item.id}>
                {item.sha256.slice(0, 12)}… ({item.state})
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>Suite</span>
          <select value={suiteId} required onChange={(event) => setSuiteId(event.target.value)}>
            <option value="">Select a suite</option>
            {suites.map((suite) => (
              <option key={suite.id} value={suite.id}>
                {suite.task_count} tasks · {suite.sha256.slice(0, 12)}…
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>Repetitions per task (2–5)</span>
          <input
            type="number"
            min={2}
            max={5}
            value={repetitions}
            onChange={(event) => setRepetitions(Number(event.target.value))}
          />
        </label>
        <p className="muted small">
          Fixed seed 17, 2000 bootstrap iterations, paired task-level analysis with bounds for
          missing pairs. Analysis is descriptive only.
        </p>
        <button type="submit" className="button button--primary" disabled={busy || !canMaintain}>
          {busy ? "Preregistering…" : "Create and preregister"}
        </button>
      </form>
    </section>
  );
}
