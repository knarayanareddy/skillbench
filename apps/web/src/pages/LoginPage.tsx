import { Alert } from "../components/ui";
import { useSession } from "../state/SessionProvider";

export function LoginPage(): JSX.Element {
  const { error } = useSession();
  return (
    <div className="shell shell--centered">
      <main id="main" className="card card--login">
        <h1>SkillBench</h1>
        <p>
          A private, fixture-first evaluation workspace for skill packages. Packages are inspected
          inertly; recorded synthetic trials are replayed; nothing is executed and no model is called.
        </p>
        {error ? <Alert title="Sign-in required">{error}</Alert> : null}
        <a className="button button--primary" href="/api/v1/auth/login?return_to=/">
          Sign in with your organization account
        </a>
        <p className="muted small">
          Accounts are provisioned by an administrator. There are no default credentials and no
          self-registration.
        </p>
      </main>
    </div>
  );
}
