"use client";

import { useState, type FormEvent } from "react";
import { api, ApiError, date, laboratoryScope, localDateTime, post, scopeActionError, scopeIsActive, type Assessment, type Collection, type Project, type Scope, type Target, type User } from "./api";
import { Badge, Empty, ErrorNotice, Icon, Loading, Panel, SectionHead, useResource } from "./components";
import { AssessmentTable } from "./assessments";
import ScopePreview from "./scope-preview";

export default function Projects({ user, revision, refresh, openAssessment }: { user: User; revision: number; refresh: () => void; openAssessment: (id: string) => void }) {
  const [selected, setSelected] = useState<string>();
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<Error>();
  const [busy, setBusy] = useState(false);
  const resource = useResource<Collection<Project>>("/projects?limit=100", revision);
  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const data = new FormData(event.currentTarget); setBusy(true); setError(undefined);
    try { const project = await post<Project>("/projects", { name: data.get("name"), description: data.get("description") }); refresh(); setCreating(false); setSelected(project.id); }
    catch (error) { setError(error instanceof Error ? error : new Error("Project creation failed.")); } finally { setBusy(false); }
  }
  if (selected) return <ProjectDetail id={selected} user={user} revision={revision} refresh={refresh} back={() => setSelected(undefined)} openAssessment={openAssessment}/>;
  return <>
    <SectionHead eyebrow="WORKSPACE / PROJECTS" title="Projects" action={user.role !== "viewer" && <button className="primary" onClick={() => setCreating(value => !value)}><Icon name={creating ? "close" : "plus"}/>{creating ? "Close form" : "New project"}</button>}>Keep targets, scope and assessment history together.</SectionHead>
    {creating && <Panel title="Create a project"><form className="project-form" onSubmit={create}><label>Project name<input name="name" placeholder="e.g. Local API laboratory" required maxLength={160}/></label><label>Description<textarea name="description" placeholder="What are you assessing, and why?" maxLength={2000} rows={3}/></label><ErrorNotice error={error}/><button className="primary" disabled={busy}>{busy ? "Creating…" : "Create project"}<Icon name="arrow"/></button></form></Panel>}
    {resource.loading ? <Loading/> : resource.error ? <ErrorNotice error={resource.error}/> : <Panel title="All projects" action={<span className="muted">{resource.data?.total ?? resource.data?.items.length} projects</span>}>{!resource.data?.items.length ? <Empty title="Give your work a home" action={user.role !== "viewer" && <button className="secondary" onClick={() => setCreating(true)}><Icon name="plus" size={16}/>Create your first project</button>}>A project groups your authorized targets, assessments, evidence and remediation.</Empty> : <div className="project-list">{resource.data.items.map(project => <button key={project.id} className="project-row" onClick={() => setSelected(project.id)}><span className="project-icon"><Icon name="projects" size={22}/></span><span><strong>{project.name}</strong><small>{project.description || "No description"}</small></span><span className="project-date">Created {date(project.created_at)}</span><Icon name="arrow"/></button>)}</div>}</Panel>}
  </>;
}

function ProjectDetail({ id, user, revision, refresh, back, openAssessment }: { id: string; user: User; revision: number; refresh: () => void; back: () => void; openAssessment: (id: string) => void }) {
  const resource = useResource<Project>(`/projects/${encodeURIComponent(id)}`, revision, true);
  const [adding, setAdding] = useState(false);
  const [launch, setLaunch] = useState<Target>();
  const [editing, setEditing] = useState<Target>();
  const canManage = ["owner", "security_administrator"].includes(user.role);
  if (resource.loading) return <Loading/>;
  if (resource.error) return <ErrorNotice error={resource.error}/>;
  const project = resource.data!;
  return <>
    <button className="text-button back-button" onClick={back}>← All projects</button>
    <SectionHead eyebrow="PROJECT WORKSPACE" title={project.name} action={canManage && !project.archived && <button className="primary" onClick={() => { setAdding(value => !value); setEditing(undefined); setLaunch(undefined); }}><Icon name={adding ? "close" : "plus"}/>{adding ? "Close form" : "Register target"}</button>}>{project.description || "Authorized targets and assessment history."}</SectionHead>
    {project.archived && <div className="notice">This project is archived. Scope editing, authorization and new assessments are unavailable.</div>}
    {adding && !project.archived && <TargetRegistration projectId={id} done={() => { setAdding(false); refresh(); }}/>}
    {editing && !project.archived && <TargetRegistration key={`${editing.id}:${editing.scope_version}`} projectId={id} target={editing} done={() => { setEditing(undefined); refresh(); }} cancel={() => setEditing(undefined)}/>}
    {launch && !project.archived && <Launch key={`${launch.id}:${launch.scope_version}`} target={launch} done={assessment => { setLaunch(undefined); refresh(); openAssessment(assessment.id); }} cancel={() => setLaunch(undefined)} reload={() => { setLaunch(undefined); refresh(); }}/>}
    <Panel title="Authorized targets" action={<span className="muted">{project.targets?.length ?? 0} registered</span>}>{!project.targets?.length ? <Empty title="Define your first assessment boundary">Register an explicit loopback laboratory URL. Review its permitted paths and exclusions, then record authorization before launching.</Empty> : <div className="target-list">{project.targets.map(target => <TargetRow key={`${target.id}:${target.scope_version}`} target={target} canManage={canManage && !project.archived} canLaunch={user.role !== "viewer" && !project.archived} refresh={refresh} edit={() => { setLaunch(undefined); setEditing(target); setAdding(false); }} launch={() => { setEditing(undefined); setLaunch(target); }}/>)}</div>}</Panel>
    <Panel title="Assessment history">{project.assessments?.length ? <AssessmentTable items={project.assessments} open={openAssessment}/> : <p className="panel-note">No assessments for this project yet.</p>}</Panel>
    <div className="notice">Current profile: safe HTTP header inspection and TLS metadata for HTTPS. DNS queries are skipped for literal IP targets. Broader target types, authenticated testing and intrusive profiles remain unavailable.</div>
  </>;
}

function TargetRegistration({ projectId, target, done, cancel }: { projectId: string; target?: Target; done: () => void; cancel?: () => void }) {
  const [preview, setPreview] = useState<{ url: string; scope: Scope }>();
  const [error, setError] = useState<Error>();
  const [busy, setBusy] = useState(false);
  const [draft, setDraft] = useState(() => {
    const starts = target?.scope.starts_at ?? new Date().toISOString();
    const expires = target?.scope.expires_at ?? new Date(new Date(starts).getTime() + 86_400_000).toISOString();
    return {
      url: target?.url ?? "", included: target?.scope.allowed_paths.join("\n") ?? "/",
      excluded: target?.scope.excluded_paths.join("\n") ?? "", starts: localDateTime(starts),
      expires: localDateTime(expires), initialStarts: starts, initialExpires: expires,
    };
  });
  const stale = error instanceof ApiError && error.status === 409;
  function review(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setError(undefined);
    try {
      const starts = !target && draft.starts === localDateTime(draft.initialStarts) ? draft.initialStarts : draft.starts;
      const expires = !target && draft.expires === localDateTime(draft.initialExpires) ? draft.initialExpires : draft.expires;
      setPreview({ url: draft.url, scope: laboratoryScope(draft.url, draft.included, draft.excluded, expires, target?.scope, starts) });
    }
    catch (error) { setError(scopeActionError(error, "Invalid scope.")); }
  }
  async function save() {
    setBusy(true); setError(undefined);
    try {
      if (target) await api(`/targets/${encodeURIComponent(target.id)}/scope`, { method: "PATCH", body: JSON.stringify({ ...preview, expected_scope_version: target.scope_version }) });
      else await post(`/projects/${encodeURIComponent(projectId)}/targets`, preview);
      done();
    }
    catch (error) { setError(scopeActionError(error, target ? "Scope update failed." : "Target registration failed.")); } finally { setBusy(false); }
  }
  return <Panel title={preview ? "02 / Review exact scope" : target ? `Edit target · scope v${target.scope_version}` : "01 / Register laboratory target"}>
    {target && <p className="notice">Changing this scope requires fresh authorization, cancels queued assessments and requests cancellation of active assessments. Existing assessment snapshots are preserved. Saving an unchanged scope keeps its version.</p>}
    {preview ? <><ScopePreview scope={preview.scope} url={preview.url}/><ErrorNotice error={error}/><div className="form-actions"><button className="secondary" onClick={() => setPreview(undefined)} disabled={busy}>Edit scope</button><button className="primary" onClick={save} disabled={busy || stale}>{busy ? "Saving…" : target ? "Save scope change" : "Register target"}<Icon name="arrow"/></button>{stale && <button className="secondary" onClick={done}>Reload target</button>}{cancel && <button className="secondary" onClick={cancel} disabled={busy}>Cancel edit</button>}</div><p className="panel-note">A separate, explicit laboratory authorization is required before assessment.</p></> : <form className="scope-form" onSubmit={review}><div className="form-wide"><label>Target URL<input name="url" type="url" placeholder="http://127.0.0.1:8766/" value={draft.url} onChange={event => setDraft({ ...draft, url: event.target.value })} required/><small>Only literal 127.0.0.1 or [::1] laboratory addresses are available.</small></label></div><label>Permitted paths<textarea name="included" value={draft.included} onChange={event => setDraft({ ...draft, included: event.target.value })} required rows={3}/><small>One path per line. / includes the whole origin.</small></label><label>Excluded paths<textarea name="excluded" value={draft.excluded} onChange={event => setDraft({ ...draft, excluded: event.target.value })} rows={3} placeholder="/admin\n/private"/><small>Exclusions override permitted paths.</small></label><label>Scope starts<input name="starts" type="datetime-local" value={draft.starts} onChange={event => setDraft({ ...draft, starts: event.target.value })} step="any" required/><small>Your local time. Start now or earlier; the validity window can be at most 24 hours.</small></label><label>Scope expires<input name="expires" type="datetime-local" value={draft.expires} onChange={event => setDraft({ ...draft, expires: event.target.value })} step="any" required/><small>Your local time. Expired scopes cannot execute.</small></label><div className="scope-profile"><strong>Safe HTTP profile</strong><span>{target?.scope.request_rate ?? 1} request/second · concurrency {target?.scope.max_concurrency ?? 1}</span><span>Unauthenticated · non-intrusive</span>{target && <small>Other registered policy fields are preserved and shown in the full preview.</small>}</div><ErrorNotice error={error}/><div className="form-wide form-actions"><button className="primary" type="submit">Review exact scope<Icon name="arrow"/></button>{cancel && <button className="secondary" type="button" onClick={cancel}>Cancel edit</button>}</div></form>}
  </Panel>;
}

function TargetRow({ target, canManage, canLaunch, refresh, edit, launch }: { target: Target; canManage: boolean; canLaunch: boolean; refresh: () => void; edit: () => void; launch: () => void }) {
  const [accepted, setAccepted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error>();
  const expired = new Date(target.scope.expires_at) <= new Date();
  const active = scopeIsActive(target.scope);
  async function approve() {
    setBusy(true); setError(undefined);
    try { await post(`/targets/${encodeURIComponent(target.id)}/approve`, { acknowledgement: "I authorize this controlled laboratory target", expected_scope_version: target.scope_version }); refresh(); }
    catch (error) { setAccepted(false); setError(scopeActionError(error, "Authorization failed.")); } finally { setBusy(false); }
  }
  return <div className="target-row"><div className="target-title"><div><strong className="mono">{target.url}</strong><small>Scope v{target.scope_version} · expires {date(target.scope.expires_at)}</small></div><Badge value={expired ? "expired" : target.verification_status}/>{canManage && <button className="secondary compact" onClick={edit}>Edit scope</button>}{canLaunch && target.verification_status === "verified_lab" && <button className="primary compact" onClick={launch} disabled={!active}>Review & launch<Icon name="arrow" size={15}/></button>}</div><details><summary>Review scope and authorization</summary><ScopePreview scope={target.scope} url={target.url}/>{target.approved_at && <p className="panel-note">Approved {date(target.approved_at)} · authorizing user {target.authorized_by}</p>}</details>{canManage && target.verification_status !== "verified_lab" && <div className="authorization"><label className="checkbox-label"><input type="checkbox" checked={accepted} onChange={event => setAccepted(event.target.checked)}/>I authorize this controlled laboratory target within the displayed scope and time window.</label><button className="secondary compact" disabled={!accepted || busy || !active} onClick={approve}>{busy ? "Recording…" : "Record authorization"}</button></div>}<ErrorNotice error={error}/>{error instanceof ApiError && error.status === 409 && <button className="secondary compact" onClick={refresh}>Reload target</button>}</div>;
}

function Launch({ target, done, cancel, reload }: { target: Target; done: (assessment: Assessment) => void; cancel: () => void; reload: () => void }) {
  const [accepted, setAccepted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error>();
  const [idempotency] = useState(() => crypto.randomUUID());
  const ready = target.verification_status === "verified_lab" && scopeIsActive(target.scope);
  async function start() {
    setBusy(true); setError(undefined);
    try { done(await post<Assessment>("/assessments", { target_id: target.id, idempotency_key: idempotency, expected_scope_version: target.scope_version })); }
    catch (error) { setAccepted(false); setError(scopeActionError(error, "Launch failed.")); } finally { setBusy(false); }
  }
  return <Panel title={`03 / Confirm assessment · scope v${target.scope_version}`}><ScopePreview scope={target.scope} url={target.url}/><p className="notice">Only the displayed safe HTTP profile will run. Redirects are rechecked against the scope. This assessment is unauthenticated and does not run exploitation payloads.</p>{!ready && <p className="notice">This scope must be active and authorized before an assessment can launch.</p>}<label className="checkbox-label"><input type="checkbox" checked={accepted} onChange={event => setAccepted(event.target.checked)} disabled={!ready || busy}/>I reviewed this exact scope and approve launching this assessment.</label><ErrorNotice error={error}/><div className="form-actions"><button className="secondary" onClick={cancel} disabled={busy}>Back</button>{error instanceof ApiError && error.status === 409 && <button className="secondary" onClick={reload}>Reload target</button>}<button className="primary" onClick={start} disabled={!accepted || !ready || busy || (error instanceof ApiError && error.status === 409)}>{busy ? "Launching…" : "Launch assessment"}<Icon name="arrow"/></button></div></Panel>;
}
