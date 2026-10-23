"use client";

import { useEffect, useState, type CSSProperties, type FormEvent } from "react";
import { api, post, type Session } from "./api";
import { ErrorNotice, Icon, Shield } from "./components";

const quotes = ["Know your scope. Follow the evidence.", "Every conclusion begins with an observation.", "Trust is earned. Authorization is explicit."];

export default function Login({ onLogin }: { onLogin: (session: Session) => void }) {
  const [initialized, setInitialized] = useState<boolean>();
  const [showForm, setShowForm] = useState(false);
  const [quote, setQuote] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error>();

  useEffect(() => {
    const controller = new AbortController();
    api<{ initialized: boolean }>("/auth/bootstrap", { signal: controller.signal }).then(data => setInitialized(data.initialized)).catch(error => { if (error.name !== "AbortError") setError(error); });
    const timer = window.setInterval(() => setQuote(current => (current + 1) % quotes.length), 7000);
    return () => { controller.abort(); window.clearInterval(timer); };
  }, []);

  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true); setError(undefined);
    try {
      const code = (form.get("code") as string | null)?.trim() || undefined;
      const session = await post<Session>("/auth/login", { username: form.get("username"), password: form.get("password"), code });
      onLogin(session);
    } catch (error) { setError(error instanceof Error ? error : new Error("Sign-in failed.")); }
    finally { setBusy(false); }
  }

  return <main className="entrance">
    <div className="rain" aria-hidden="true">{Array.from({ length: 48 }, (_, index) => <i key={index} style={{ "--x": `${(index * 37 % 103)}%`, "--delay": `${-(index * 0.71)}s`, "--duration": `${2.5 + (index * 11 % 19) / 10}s`, "--opacity": 0.08 + (index % 6) * 0.03 } as CSSProperties}/>)}</div>
    <div className="entrance-top"><span className="tiny">LOCAL SECURITY WORKSPACE</span><span className="tiny"><span className="status-dot"/> SCOPE CONTROLLED</span></div>
    <div className="orbit" aria-hidden="true"><div/><div/><div/></div>
    <section className="login-center">
      <div className="login-emblem"><Shield/></div>
      <h1 className="wordmark">SHARAY</h1>
      <p className="creator">by Shardul</p>
      <p className="entrance-description">A deliberate space for security work.</p>
      {showForm ? <form className="login-form" onSubmit={login}>
        <label>Username<input name="username" autoComplete="username" required maxLength={100}/></label>
        <label>Password<input name="password" type="password" autoComplete="current-password" required/></label>
        <label>MFA code <small>(if enabled)</small><input name="code" inputMode="numeric" autoComplete="one-time-code" maxLength={16} placeholder="6-digit or backup code"/></label>
        <ErrorNotice error={error}/>
        <button className="primary" disabled={busy}>{busy ? "Authenticating…" : "Unlock workspace"}<Icon name="arrow"/></button>
        <button type="button" className="text-button" onClick={() => setShowForm(false)}>Back</button>
      </form> : initialized === false ? <div className="provisioning"><p>Create your owner account in the local terminal.</p><code>.venv/bin/python -m sharay init-owner</code><p className="muted">Then reopen SHARAY. There are no default credentials.</p></div> : <>
        <button className="primary entrance-button" onClick={() => setShowForm(true)} disabled={initialized === undefined}><Icon name="lock"/>{initialized === undefined ? "Connecting…" : "Enter workspace"}<Icon name="arrow"/></button>
        <ErrorNotice error={error}/>
      </>}
      <p className="entrance-note"><Icon name="lock" size={12}/> Access is limited to authorized operators.</p>
    </section>
    <footer className="entrance-footer"><div className="quote-line"/><p key={quote} className="quote">“{quotes[quote]}”</p><span className="tiny">SHARAY / DESKTOP EDITION</span></footer>
  </main>;
}
