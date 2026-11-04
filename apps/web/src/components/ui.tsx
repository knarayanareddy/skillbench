import type { ReactNode } from "react";

/** Text + shape + colour: status is never conveyed by colour alone. */
export function StatusBadge({ state, label }: { state: string; label?: string }): JSX.Element {
  const tone = toneFor(state);
  return (
    <span className={`badge badge--${tone}`} data-state={state}>
      <span aria-hidden="true" className="badge__dot" />
      {label ?? state.replace(/_/g, " ")}
    </span>
  );
}

function toneFor(state: string): string {
  if (["approved", "completed", "succeeded", "valid"].includes(state)) return "ok";
  if (["rejected", "failed", "failed_unknown_effect", "insufficient"].includes(state)) return "danger";
  if (["inspected", "preregistered", "running", "partial"].includes(state)) return "info";
  if (["quarantined","queued","draft","stopped","cancelled"].includes(state)) return "warn";
  return "neutral";
}

export function SimulationNotice({ children }: { children?: ReactNode }): JSX.Element {
  return (
    <aside className="notice notice--simulation" role="note">
      <strong>Simulation</strong>
      <span>
        {children ??
          "Recorded synthetic trials only. Outcomes are replayed from a versioned fixture; no skill code runs and no model is called. These numbers are not evidence that a skill improves any agent."}
      </span>
    </aside>
  );
}

export function Alert({ tone = "danger", title, children }: { tone?: "danger" | "warn" | "info"; title: string; children?: ReactNode }): JSX.Element {
  return (
    <div className={`alert alert--${tone}`} role="alert">
      <p className="alert__title">{title}</p>
      {children ? <div className="alert__body">{children}</div> : null}
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }): JSX.Element {
  return (
    <div className="empty">
      <p className="empty__title">{title}</p>
      {children ? <div>{children}</div> : null}
    </div>
  );
}

export function Skeleton({ rows = 3 }: { rows?: number }): JSX.Element {
  return (
    <div className="skeleton" aria-busy="true" aria-live="polite">
      <span className="visually-hidden">Loading</span>
      {Array.from({ length: rows }).map((_, index) => (
        <div key={index} className="skeleton__row" />
      ))}
    </div>
  );
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

export function formatNumber(value: number | null, digits = 3): string {
  return value === null ? "—" : value.toFixed(digits);
}
