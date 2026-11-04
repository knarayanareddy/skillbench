import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ApiError, putBytes, request, sha256Hex } from "../api/client";
import type { Package, UploadTicket } from "../api/types";
import { Alert, SimulationNotice } from "../components/ui";

const MAX_BYTES = 20 * 1024 * 1024;

export function NewPackagePage({ projectId }: { projectId: string }): JSX.Element {
  const navigate = useNavigate();
  const [file, setFile] = useState<File | null>(null);
  const [name, setName] = useState("");
  const [sourceCommit, setSourceCommit] = useState("");
  const [license, setLicense] = useState("MIT");
  const [busy, setBusy] = useState(false);
  const [step, setStep] = useState<"idle" | "uploading" | "registering">("idle");
  const [problem, setProblem] = useState<ApiError | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  async function submit(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!file) return;
    setProblem(null);
    setMessage(null);
    if (file.size === 0 || file.size > MAX_BYTES) {
      setMessage("Choose a non-empty ZIP no larger than 20 MiB.");
      return;
    }
    setBusy(true);
    try {
      const digest = await sha256Hex(file);
      setStep("uploading");
      const ticket = await request<UploadTicket>(`/api/v1/projects/${projectId}/uploads`, {
        method: "POST",
        projectId,
        body: {
          filename: file.name,
          media_type: "application/zip",
          byte_size: file.size,
          sha256: digest,
          classification: "synthetic",
        },
      });
      await putBytes(ticket.put_path, file, projectId);
      await request<unknown>(`/api/v1/uploads/${ticket.id}:finalize`, {
        method: "POST",
        projectId,
        body: { sha256: digest, byte_size: file.size },
      });
      setStep("registering");
      const created = await request<Package>(`/api/v1/projects/${projectId}/skb/packages`, {
        method: "POST",
        projectId,
        body: {
          artifact_id: ticket.artifact_id,
          name: name.trim(),
          source_commit: sourceCommit.trim(),
          license_expression: license.trim(),
        },
      });
      navigate(`/projects/${projectId}/packages/${created.id}`);
    } catch (caught) {
      if (caught instanceof ApiError) setProblem(caught);
      else setMessage("Upload failed. Nothing was registered.");
    } finally {
      setBusy(false);
      setStep("idle");
    }
  }

  return (
    <section className="stack stack--narrow">
      <p className="breadcrumb">
        <Link to={`/projects/${projectId}`}>Project</Link> / <span>Register package</span>
      </p>
      <h1>Register a skill package</h1>
      <SimulationNotice>
        The ZIP is stored privately and inspected without extraction or execution. Registering does
        not approve it: a maintainer must review the exact digest.
      </SimulationNotice>

      {problem ? (
        <Alert title={problem.problem.title}>
          <p>{problem.problem.detail}</p>
          {problem.problem.request_id ? <p className="mono small">Request {problem.problem.request_id}</p> : null}
          {problem.problem.field_errors?.length ? (
            <ul>
              {problem.problem.field_errors.map((field) => (
                <li key={`${field.path}-${field.code}`}>
                  <span className="mono">{field.path}</span>: {field.code}
                </li>
              ))}
            </ul>
          ) : null}
        </Alert>
      ) : null}
      {message ? <Alert tone="warn" title="Check the form">{message}</Alert> : null}

      <form className="form" onSubmit={(event) => void submit(event)} noValidate>
        <label className="field">
          <span>Package ZIP</span>
          <input
            type="file"
            accept="application/zip,.zip"
            required
            onChange={(event) => setFile(event.target.files?.[0] ?? null)}
          />
          <span className="hint">ZIP only, up to 20 MiB. Symlinks, traversal paths and executables are rejected.</span>
        </label>
        <label className="field">
          <span>Display name</span>
          <input
            type="text"
            required
            minLength={1}
            maxLength={120}
            value={name}
            onChange={(event) => setName(event.target.value)}
            autoComplete="off"
          />
        </label>
        <label className="field">
          <span>Source commit</span>
          <input
            type="text"
            required
            pattern="[0-9a-f]{40}"
            value={sourceCommit}
            onChange={(event) => setSourceCommit(event.target.value)}
            placeholder="40 hexadecimal characters"
            autoComplete="off"
          />
        </label>
        <label className="field">
          <span>License expression</span>
          <input type="text" required value={license} onChange={(event) => setLicense(event.target.value)} />
        </label>
        <div className="form__actions">
          <button type="submit" className="button button--primary" disabled={busy || !file}>
            {busy ? statusLabel(step) : "Upload and register"}
          </button>
          <Link className="button button--ghost" to={`/projects/${projectId}`}>
            Cancel
          </Link>
        </div>
      </form>
    </section>
  );
}

function statusLabel(step: "idle" | "uploading" | "registering"): string {
  if (step === "uploading") return "Uploading…";
  if (step === "registering") return "Registering…";
  return "Working…";
}
