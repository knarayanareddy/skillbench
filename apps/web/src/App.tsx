import { Link, NavLink, Navigate, Route, Routes, useParams } from "react-router-dom";
import { useSession } from "./state/SessionProvider";
import { Skeleton } from "./components/ui";
import { LoginPage } from "./pages/LoginPage";
import { ProjectsPage } from "./pages/ProjectsPage";
import { ProjectPage } from "./pages/ProjectPage";
import { NewPackagePage } from "./pages/NewPackagePage";
import { PackagePage } from "./pages/PackagePage";
import { NewSuitePage } from "./pages/NewSuitePage";
import { NewPlanPage } from "./pages/NewPlanPage";
import { ExperimentPage } from "./pages/ExperimentPage";

export function App(): JSX.Element {
  const { session, loading } = useSession();

  if (loading) {
    return (
      <main className="shell" id="main">
        <Skeleton rows={4} />
      </main>
    );
  }
  if (!session) {
    return (
      <Routes>
        <Route path="*" element={<LoginPage />} />
      </Routes>
    );
  }
  return (
    <div className="shell">
      <Header />
      <main id="main" className="main">
        <Routes>
          <Route path="/" element={<ProjectsPage session={session} />} />
          <Route path="/projects/:projectId" element={<ProjectPage session={session} />} />
          <Route path="/projects/:projectId/packages/new" element={<NewPackageRoute />} />
          <Route path="/projects/:projectId/packages/:packageId" element={<PackagePage session={session} />} />
          <Route path="/projects/:projectId/suites/new" element={<NewSuiteRoute />} />
          <Route path="/projects/:projectId/plans/new" element={<NewPlanRoute session={session} />} />
          <Route path="/projects/:projectId/experiments/:experimentId" element={<ExperimentPage session={session} />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}

function NewPackageRoute(): JSX.Element {
  const { projectId } = useParams<{ projectId: string }>();
  return <NewPackagePage projectId={projectId ?? ""} />;
}

function NewSuiteRoute(): JSX.Element {
  const { projectId } = useParams<{ projectId: string }>();
  return <NewSuitePage projectId={projectId ?? ""} />;
}

function NewPlanRoute({ session }: { session: ReturnType<typeof useSession>["session"] }): JSX.Element {
  const { projectId } = useParams<{ projectId: string }>();
  if (!session) return <Navigate to="/" replace />;
  return <NewPlanPage session={session} projectId={projectId ?? ""} />;
}

function Header(): JSX.Element {
  const { session, logout } = useSession();
  return (
    <header className="header">
      <Link className="header__brand" to="/">
        SkillBench
      </Link>
      <p className="header__tag">Private fixture-first skill evaluation</p>
      <nav className="header__nav" aria-label="Primary">
        <NavLink to="/">Projects</NavLink>
      </nav>
      <div className="header__identity">
        <span>
          {session?.org_role === "admin" ? "Organization admin" : "Signed in"}
          {session ? ` · ${session.actor_id.slice(0, 8)}` : ""}
        </span>
        <button type="button" className="button button--ghost" onClick={() => void logout()}>
          Sign out
        </button>
      </div>
    </header>
  );
}
