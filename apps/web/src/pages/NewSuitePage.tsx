import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, request } from "../api/client";
import type { ListBody, Package, Suite } from "../api/types";
import { Alert, SimulationNotice } from "../components/ui";

export function NewSuitePage({ projectId }: { projectId: string }): JSX.Element {
  const [packages, setPackages] = useState<Package[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [name, setName] = useState("Synthetic validation suite");
  const [problem, setProblem] = useState<ApiError | null>(null);
  const [created, setCreated] = useState<Suite | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    request<ListBody<Package>>(`/api/v1/projects/${projectId}/skb/packages`, { projectId })
      .then((body) => {
        setPackages(body.items);
        const approved = body.items.find((item) => item.state === "approved");
        if (approved) setSelected(approved.artifact_id);
      })
      .catch(() => setPackages([]));
  }, [projectId]);

  async function submit(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setProblem(null);
    setBusy(true);
    try {
      const tasks = Array.from({ length: 12 }, (_, index) => ({
        id: `task-${String(index).padStart(2, "0")}`,
        category: "synthetic",
        input_artifact_id: selected,
        split: "validation",
        scorer_id: "exact_match",
      }));
      const suite = await request<Suite>(`/api/v1/projects/${projectId}/skb/suites`, {
        method: "POST",
        projectId,
        body: { name: name.trim(), tasks, rights_manifest_artifact_id: selected },
      });
      setCreated(suite);
    } catch (caught) {
      if (caught instanceof ApiError) setProblem(caught);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="stack stack--narrow">
      <p className="breadcrumb">
        <Link to={`/projects/${projectId}`}>Project</Link> / <span>New suite</span>
      </p>
      <h1>Create a frozen suite</h1>
      <SimulationNotice>
        Tasks reference a rights-manifest artifact in this project. A suite is immutable once
        created and is identified by its content digest.
      </SimulationNotice>
      {problem ? <Alert title={problem.problem.title}>{problem.problem.detail}</Alert> : null}
      {created ? (
        <Alert tone="info" title="Suite created">
          <p className="mono small">{created.sha256}</p>
          <p>
            Next: create a plan and preregister it.{" "}
            <Link to={`/projects/${projectId}/plans/new`}>Create a plan</Link>
          </p>
        </Alert>
      ) : (
        <form className="form" onSubmit={(event) => void submit(event)}>
          <label className="field">
            <span>Name</span>
            <input value={name} minLength={1} maxLength={120} required onChange={(event) => setName(event.target.value)} />
          </label>
          <label className="field">
            <span>Rights-manifest artifact</span>
            <select value={selected} required onChange={(event) => setSelected(event.target.value)}>
              <option value="">Select a ready artifact</option>
              {packages.map((item) => (
                <option key={item.artifact_id} value={item.artifact_id}>
                  {item.artifact_id} ({item.state})
                </option>
              ))}
            </select>
            <span className="hint">Only artifacts already bound to an approved package should be used.</span>
          </label>
          <button type="submit" className="button button--primary" disabled={busy || !selected}>
            {busy ? "Creating…" : "Create suite"}
          </button>
        </form>
      )}
    </section>
  );
}
