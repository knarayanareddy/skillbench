import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, request } from "../api/client";
import type { ListBody, Project, SessionBody } from "../api/types";
import { Alert, EmptyState, Skeleton } from "../components/ui";

export function ProjectsPage({ session }: { session: SessionBody }): JSX.Element {
  const [projects, setProjects] = useState<Project[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    request<ListBody<Project>>("/api/v1/projects")
      .then((body) => {
        if (!cancelled) setProjects(body.items);
      })
      .catch((caught: unknown) => {
        if (!cancelled) setError(caught instanceof ApiError ? caught.problem.detail : "Could not load projects.");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const roles = new Map(session.projects.map((item) => [item.project_id, item.roles]));

  return (
    <section className="stack">
      <header className="page-header">
        <div>
          <h1>Projects</h1>
          <p className="muted">
            Your organization: {session.organization_id}. Project access is granted per project; an
            organization role never implies content access.
          </p>
        </div>
      </header>
      {error ? <Alert title="Projects unavailable">{error}</Alert> : null}
      {projects === null && !error ? <Skeleton rows={3} /> : null}
      {projects !== null && projects.length === 0 ? (
        <EmptyState title="No projects yet">
          <p>Ask an organization administrator to create the first project.</p>
        </EmptyState>
      ) : null}
      {projects !== null && projects.length > 0 ? (
        <table className="table">
          <caption className="visually-hidden">Projects you can open</caption>
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">Captured content</th>
              <th scope="col">External transfer</th>
              <th scope="col">Your roles</th>
            </tr>
          </thead>
          <tbody>
            {projects.map((project) => (
              <tr key={project.id}>
                <th scope="row">
                  <Link to={`/projects/${project.id}`}>{project.name}</Link>
                </th>
                <td>{project.content_capture === "metadata_only" ? "Metadata only" : "Full content"}</td>
                <td>{project.external_transfer ? "Enabled" : "Disabled"}</td>
                <td>
                  {(roles.get(project.id) ?? []).length > 0
                    ? (roles.get(project.id) ?? []).join(", ")
                    : "No grant"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </section>
  );
}
