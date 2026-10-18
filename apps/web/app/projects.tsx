"use client";

import { useState, type FormEvent } from "react";
import { api, ApiError, date, laboratoryScope, localDateTime, post, projectFields, scopeActionError, scopeIsActive, type Assessment, type Collection, type Project, type Scope, type Target, type User } from "./api";
import { Badge, Empty, ErrorNotice, Icon, Loading, Panel, SectionHead, useResource } from "./components";
import { AssessmentTable } from "./assessments";
import ScopePreview from "./scope-preview";
import OperatorTerminal from "./terminal";

export default function Projects({ user, revision, refresh, openAssessment }: { user: User; revision: number; refresh: () => void; openAssessment: (id: string) => void }) {
  const [selected, setSelected] = useState<string>();
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<Error>();
  const [busy, setBusy] = useState(false);
  const resource = useResource<Collection<Project>>("/projects?limit=100", revision);
  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const data = new FormData(event.currentTarget); setBusy(true); setError(undefined);
    try { const project = await post<Project>("/projects", projectFields(String(data.get("name") ?? ""), String(data.get("description") ?? ""))); refresh(); setCreating(false); setSelected(project.id); }
    catch (error) { setError(error instanceof Error ? error : new Error("Project creation failed.")); } finally { setBusy(false); }
  }
  if (selected) return <ProjectDetail id={selected} user={user} revision={revision} refresh={refresh} back={() => setSelected(undefined)} openAssessment={openAssessment}/>;
  return <>
    <SectionHead eyebrow="WORKSPACE / PROJECTS" title="Projects" action={user.role !== "viewer" && <button className="primary" onClick={() => setCreating(value => !value)}><Icon name={creating ? "close" : "plus"}/>{creating ? "Close form" : "New project"}</button>}>Keep targets, scope and assessment history together.</SectionHead>
    {creating && <Panel title="Create a project"><form className="project-form" onSubmit={create}><label>Project name<input name="name" placeholder="e.g. Local API laboratory" required maxLength={320}/></label><label>Description<textarea name="description" placeholder="What are you assessing, and why?" maxLength={8000} rows={3}/></label><ErrorNotice error={error}/><button className="primary" disabled={busy}>{busy ? "Creating…" : "Create project"}<Icon name="arrow"/></button></form></Panel>}
    {resource.loading ? <Loading/> : resource.error ? <ErrorNotice error={resource.error}/> : <Panel title="All projects" action={<span className="muted">{resource.data?.total ?? resource.data?.items.length} projects</span>}>{!resource.data?.items.length ? <Empty title="Give your work a home" action={user.role !== "viewer" && <button className="secondary" onClick={() => setCreating(true)}><Icon name="plus" size={16}/>Create your first project</button>}>A project groups your authorized targets, assessments, evidence and remediation.</Empty> : <div className="project-list">{resource.data.items.map(project => <button key={project.id} className="project-row" onClick={() => setSelected(project.id)}><span className="project-icon"><Icon name="projects" size={22}/></span><span><strong>{project.name}{project.archived && " · Archived"}</strong><small>{project.description || "No description"}</small></span><span className="project-date">Created {date(project.created_at)}</span><Icon name="arrow"/></button>)}</div>}</Panel>}
  </>;
}

function ProjectDetail({ id, user, revision, refresh, back, openAssessment }: { id: string; user: User; revision: number; refresh: () => void; back: () => void; openAssessment: (id: string) => void }) {
  const resource = useResource<Project>(`/projects/${encodeURIComponent(id)}`, revision, true);
  const [adding, setAdding] = useState(false);
  const [launch, setLaunch] = useState<Target>();
  const [editing, setEditing] = useState<Target>();
  const [terminalTarget, setTerminalTarget] = useState<Target>();
  const canManage = ["owner", "security_administrator"].includes(user.role);
  if (resource.loading) return <Loading/>;
  if (resource.error) return <ErrorNotice error={resource.error}/>;
  const project = resource.data!;
  const currentLaunch = project.targets?.find(target => target.id === launch?.id);
  const canLaunch = ["owner", "security_administrator", "analyst"].includes(user.role);
  return <>
    <button className="text-button back-button" onClick={back}>← All projects</button>
    <SectionHead eyebrow="PROJECT WORKSPACE" title={project.name} action={canManage && !project.archived && <button className="primary" onClick={() => { setAdding(value => !value); setEditing(undefined); setLaunch(undefined); }}><Icon name={adding ? "close" : "plus"}/>{adding ? "Close form" : "Register target"}</button>}>{project.description || "Authorized targets and assessment history."}</SectionHead>
    {project.archived && <div className="notice">This project is archived. Scope editing, authorization and new assessments are unavailable.</div>}
    {canManage && <ProjectSettings key={project.id} project={project} refresh={refresh}/>}
    {adding && !project.archived && <TargetRegistration projectId={id} done={() => { setAdding(false); refresh(); }}/>}
    {editing && !project.archived && <TargetRegistration key={`${editing.id}:${editing.scope_version}`} projectId={id} target={editing} done={() => { setEditing(undefined); refresh(); }} cancel={() => setEditing(undefined)}/>}
    {currentLaunch && canLaunch && !project.archived && <Launch key={`${currentLaunch.id}:${currentLaunch.scope_version}`} target={currentLaunch} done={assessment => { setLaunch(undefined); refresh(); openAssessment(assessment.id); }} cancel={() => setLaunch(undefined)} reload={() => { setLaunch(undefined); refresh(); }}/>}
    <Panel title="Authorized targets" action={<span className="muted">{project.targets?.length ?? 0} registered</span>}>{!project.targets?.length ? <Empty title="Define your first assessment boundary">Register a target URL, review its permitted paths and exclusions, then record authorization. Execution availability is shown for each target.</Empty> : <div className="target-list">{project.targets.map(target => <TargetRow key={`${target.id}:${target.scope_version}`} target={target} canManage={canManage && !project.archived} canLaunch={user.role !== "viewer" && !project.archived} refresh={refresh} edit={() => { setLaunch(undefined); setEditing(target); setAdding(false); }} launch={() => { setEditing(undefined); setLaunch(target); }} takeover={() => setTerminalTarget(target)}/>)}</div>}</Panel>
    <Panel title="Assessment history">{project.assessments?.length ? <AssessmentTable items={project.assessments} open={openAssessment}/> : <p className="panel-note">No assessments for this project yet.</p>}</Panel>
    <div className="notice">Targets can include hostnames and IP addresses. The current safe HTTP worker runs approved literal 127.0.0.1 and [::1] targets, with header inspection and TLS metadata for HTTPS. DNS queries are skipped for literal IP targets. Authenticated testing and intrusive profiles remain unavailable.</div>
    {terminalTarget && <OperatorTerminal target={terminalTarget} onClose={() => setTerminalTarget(undefined)}/>}
  </>;
}

function ProjectSettings({ project, refresh }: { project: Project; refresh: () => void }) {
  const [editing, setEditing] = useState<{ name: string; description: string }>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error>();
  async function update(fields: { name?: string; description?: string; archived?: boolean }) {
    setBusy(true); setError(undefined);
    try { await api(`/projects/${encodeURIComponent(project.id)}`, { method: "PATCH", body: JSON.stringify(fields) }); refresh(); if (fields.name !== undefined) setEditing(undefined); }
    catch (error) { setError(error instanceof Error ? error : new Error("Project update failed.")); } finally { setBusy(false); }
  }
  function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setError(undefined);
    const data = new FormData(event.currentTarget);
    try {
      if (editing?.name !== project.name || editing?.description !== project.description) throw new Error("Project details changed while you were editing. Close settings and reopen them to review the current values.");
      void update(projectFields(String(data.get("name") ?? ""), String(data.get("description") ?? "")));
    }
    catch (error) { setError(error instanceof Error ? error : new Error("Invalid project settings.")); }
  }
  return <Panel title="Project settings" action={<button className="secondary compact" onClick={() => { setEditing(value => value ? undefined : { name: project.name, description: project.description }); setError(undefined); }} disabled={busy} aria-expanded={!!editing}>{editing ? "Close settings" : "Edit project"}</button>}>
    {editing ? <form className="project-form" onSubmit={save} aria-busy={busy}><label>Project name<input name="name" defaultValue={editing.name} required maxLength={320} disabled={busy}/></label><label>Description<textarea name="description" defaultValue={editing.description} maxLength={8000} rows={4} disabled={busy}/><small>Up to 4000 characters. Clear this field to remove the description.</small></label><ErrorNotice error={error}/><button className="primary" disabled={busy}>{busy ? "Saving…" : "Save project settings"}</button></form> : <ErrorNotice error={error}/>}
    <p className="panel-note">Archiving preserves targets and assessment history, and blocks target changes and new assessments. Already queued or running assessments continue. Restoring keeps the existing scope and authorization requirements.</p>
    <div className="form-actions"><button className="secondary" onClick={() => { void update({ archived: !project.archived }); }} disabled={busy}>{busy ? "Updating…" : project.archived ? "Restore project" : "Archive project"}</button></div>
  </Panel>;
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
  return <Panel title={preview ? "02 / Review exact scope" : target ? `Edit target · scope v${target.scope_version}` : "01 / Register target"}>
    {target && <p className="notice">Changing this scope requires fresh authorization, cancels queued assessments and requests cancellation of active assessments. Existing assessment snapshots are preserved. Saving an unchanged scope keeps its version.</p>}
    {preview ? <><ScopePreview scope={preview.scope} url={preview.url}/><ErrorNotice error={error}/><div className="form-actions"><button className="secondary" onClick={() => setPreview(undefined)} disabled={busy}>Edit scope</button><button className="primary" onClick={save} disabled={busy || stale}>{busy ? "Saving…" : target ? "Save scope change" : "Register target"}<Icon name="arrow"/></button>{stale && <button className="secondary" onClick={done}>Reload target</button>}{cancel && <button className="secondary" onClick={cancel} disabled={busy}>Cancel edit</button>}</div><p className="panel-note">A separate, explicit target authorization is required before assessment. Recording authorization does not make an unavailable execution profile runnable.</p></> : <form className="scope-form" onSubmit={review}><div className="form-wide"><label>Target URL<input name="url" type="url" placeholder="http://127.0.0.1:8766/" value={draft.url} onChange={event => setDraft({ ...draft, url: event.target.value })} required/><small>Use a canonical hostname or IP address. The current worker runs only approved literal 127.0.0.1 or [::1] targets.</small></label></div><label>Permitted paths<textarea name="included" value={draft.included} onChange={event => setDraft({ ...draft, included: event.target.value })} required rows={3}/><small>One path per line. / includes the whole origin.</small></label><label>Excluded paths<textarea name="excluded" value={draft.excluded} onChange={event => setDraft({ ...draft, excluded: event.target.value })} rows={3} placeholder="/admin\n/private"/><small>Exclusions override permitted paths.</small></label><label>Scope starts<input name="starts" type="datetime-local" value={draft.starts} onChange={event => setDraft({ ...draft, starts: event.target.value })} step="any" required/><small>Your local time. Start now or earlier; the validity window can be at most 24 hours.</small></label><label>Scope expires<input name="expires" type="datetime-local" value={draft.expires} onChange={event => setDraft({ ...draft, expires: event.target.value })} step="any" required/><small>Your local time. Expired scopes cannot execute.</small></label><div className="scope-profile"><strong>Safe HTTP profile</strong><span>Scope ceiling: {target?.scope.request_rate ?? 1} request/second · concurrency {target?.scope.max_concurrency ?? 1}</span><small>The current worker uses one connection at a time.</small><span>Unauthenticated · non-intrusive</span>{target && <small>Other registered policy fields are preserved and shown in the full preview.</small>}</div><ErrorNotice error={error}/><div className="form-wide form-actions"><button className="primary" type="submit">Review exact scope<Icon name="arrow"/></button>{cancel && <button className="secondary" type="button" onClick={cancel}>Cancel edit</button>}</div></form>}
  </Panel>;
}

function TargetRow({ target, canManage, canLaunch, refresh, edit, launch, takeover }: { target: Target; canManage: boolean; canLaunch: boolean; refresh: () => void; edit: () => void; launch: () => void; takeover: () => void }) {
  const [accepted, setAccepted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error>();
  const expired = new Date(target.scope.expires_at) <= new Date();
  const active = scopeIsActive(target.scope);
  async function approve() {
    setBusy(true); setError(undefined);
    try { await post(`/targets/${encodeURIComponent(target.id)}/approve`, { acknowledgement: "I authorize this target within the displayed scope", expected_scope_version: target.scope_version }); refresh(); }
    catch (error) { setAccepted(false); setError(scopeActionError(error, "Authorization failed.")); } finally { setBusy(false); }
  }
  return <div className="target-row"><div className="target-title"><div><strong className="mono">{target.url}</strong><small>Scope v{target.scope_version} · expires {date(target.scope.expires_at)}</small></div><Badge value={expired ? "expired" : target.verification_status}/>{canManage && <button className="secondary compact" onClick={edit}>Edit scope</button>}{canLaunch && ["verified_lab", "operator_authorized"].includes(target.verification_status) && !target.execution_blocker && <><button className="secondary compact" onClick={takeover} title="Open live diagnostic and takeover console">Takeover Console</button><button className="primary compact" onClick={launch} disabled={!active}>Review & launch<Icon name="arrow" size={15}/></button></>}</div><details><summary>Review scope and authorization</summary><ScopePreview scope={target.scope} url={target.url}/>{target.approved_at && <p className="panel-note">Approved {date(target.approved_at)} · authorizing user {target.authorized_by}</p>}</details>{target.execution_blocker && <p className="notice">{target.execution_blocker}</p>}{canManage && !["verified_lab", "operator_authorized"].includes(target.verification_status) && <div className="authorization"><label className="checkbox-label"><input type="checkbox" checked={accepted} onChange={event => setAccepted(event.target.checked)}/>I authorize this target within the displayed scope and time window.</label><button className="secondary compact" disabled={!accepted || busy || !active} onClick={approve}>{busy ? "Recording…" : "Record authorization"}</button></div>}<ErrorNotice error={error}/>{error instanceof ApiError && error.status === 409 && <button className="secondary compact" onClick={refresh}>Reload target</button>}</div>;
}

function Launch({ target, done, cancel, reload }: { target: Target; done: (assessment: Assessment) => void; cancel: () => void; reload: () => void }) {
  const [accepted, setAccepted] = useState(false);
  const [reviewedScope, setReviewedScope] = useState<string>();
  const scopeIdentity = JSON.stringify([target.id, target.scope_version, target.url, target.scope]);
  const reviewed = accepted && reviewedScope === scopeIdentity;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error>();
  const [idempotency, setIdempotency] = useState(() => crypto.randomUUID());
  const live = target.verification_status === "operator_authorized";
  const [profile, setProfile] = useState<"safe_http" | "approved_templates" | "comprehensive">(live ? "comprehensive" : "safe_http");
  const [mode, setMode] = useState<"adaptive" | "standard" | "aggressive" | "passive">("adaptive");
  const [depth, setDepth] = useState<number>(2);
  const [rate, setRate] = useState<number>(target.scope.request_rate);
  const [tags, setTags] = useState<string>("");
  const [toolNmap, setToolNmap] = useState(true);
  const [toolCrawler, setToolCrawler] = useState(true);
  const [toolSensitive, setToolSensitive] = useState(true);
  const [toolDiff, setToolDiff] = useState(true);
  const [toolNuclei, setToolNuclei] = useState(true);
  const [toolZap, setToolZap] = useState(false);
  const [toolMsf, setToolMsf] = useState(false);
  const [toolBrowser, setToolBrowser] = useState(true);
  const [toolSchema, setToolSchema] = useState(true);
  const [toolAuthMatrix, setToolAuthMatrix] = useState(true);
  const [toolPayloadForge, setToolPayloadForge] = useState(true);
  const [toolReproducer, setToolReproducer] = useState(true);
  const ready = ["verified_lab", "operator_authorized"].includes(target.verification_status) && !target.execution_blocker && scopeIsActive(target.scope);

  function invalidateReview() {
    setAccepted(false); setError(undefined); setIdempotency(crypto.randomUUID());
  }

  function enableAllSOTA() {
    setProfile("comprehensive");
    setMode("adaptive");
    setDepth(3);
    setToolNmap(true);
    setToolCrawler(true);
    setToolSensitive(true);
    setToolDiff(true);
    setToolNuclei(true);
    setToolBrowser(true);
    setToolSchema(true);
    setToolAuthMatrix(true);
    setToolPayloadForge(true);
    setToolReproducer(true);
    setToolZap(true);
    setToolMsf(true);
    invalidateReview();
  }

  async function start() {
    if (!reviewed || !ready || busy) return;
    setBusy(true); setError(undefined);
    try {
      if (!Number.isFinite(rate) || rate <= 0 || rate > 5000) throw new Error("Request rate must be positive and at most 5000 req/s.");
      const activeTools: string[] = [];
      if (toolNmap) activeTools.push("nmap");
      if (toolCrawler) activeTools.push("crawler");
      if (toolSensitive) activeTools.push("sensitive");
      if (toolDiff) activeTools.push("diff");
      if (toolNuclei) activeTools.push("nuclei");
      if (toolZap) activeTools.push("zap");
      if (toolMsf) activeTools.push("metasploit");
      if (toolBrowser) activeTools.push("browser");
      if (toolSchema) activeTools.push("schema");
      if (toolAuthMatrix) activeTools.push("auth_matrix");
      if (toolPayloadForge) activeTools.push("payload_forge");
      if (toolReproducer) activeTools.push("reproducer");

      const config = live && profile !== "safe_http" ? {
        mode: profile === "approved_templates" ? "standard" : mode,
        depth: profile === "approved_templates" ? 2 : Number(depth),
        rate: Number(rate),
        tags: tags.trim() ? tags.trim() : undefined,
        tools: profile === "approved_templates" ? ["nuclei"] : mode === "passive" ? [] : activeTools,
      } : undefined;

      done(await post<Assessment>("/assessments", {
        target_id: target.id,
        idempotency_key: idempotency,
        expected_scope_version: target.scope_version,
        profile,
        config,
      }));
    }
    catch (error) { setAccepted(false); setError(scopeActionError(error, "Launch failed.")); } finally { setBusy(false); }
  }

  return (
    <Panel title={`03 / Confirm assessment · scope v${target.scope_version}`}>
      <ScopePreview scope={target.scope} url={target.url}/>
      <p className="notice">
        {live && profile === "comprehensive"
          ? "The comprehensive profile is prepared for reconnaissance, HTTP facts and selected tools. External execution remains unavailable until its controls are verified."
          : live && profile === "approved_templates"
          ? "The approved-templates profile is prepared for Nuclei checks. External execution remains unavailable until its controls are verified."
          : "The safe HTTP profile inspects security headers and TLS metadata. Redirects are rechecked against the scope."}
      </p>
      {live && (
        <label>
          Assessment profile
          <select value={profile} onChange={event => { setProfile(event.target.value as "safe_http" | "approved_templates" | "comprehensive"); invalidateReview(); }} disabled={busy}>
            <option value="comprehensive">Comprehensive — Full Automated Pipeline (Recon + Headers + Ports + Crawler + Nuclei)</option>
            <option value="approved_templates">Approved templates — nuclei</option>
            <option value="safe_http">Safe HTTP — security headers &amp; TLS</option>
          </select>
        </label>
      )}

      {live && profile === "comprehensive" && (
        <details open style={{ margin: "14px 20px" }}>
          <summary className="scan-config-toggle-summary">
            <strong>Scan Strategy &amp; Customization Controls</strong> (Click to toggle)
          </summary>
          <div className="scan-config-box">
            <div className="scan-config-grid">
              <label>
                Scan Mode
                <select value={mode} onChange={e => { setMode(e.target.value as "adaptive" | "standard" | "aggressive" | "passive"); invalidateReview(); }} disabled={busy}>
                  <option value="adaptive">Adaptive — Stack intelligence &amp; tailored tags (Recommended)</option>
                  <option value="standard">Standard — Discovery &amp; baseline active checks</option>
                  <option value="aggressive">Aggressive — Deep crawler &amp; expanded vulnerability checks</option>
                  <option value="passive">Passive — Baseline discovery only</option>
                </select>
                <small>
                  {mode === "adaptive"
                    ? "Detects web servers and runtimes, auto-synthesizing tailored Nuclei tags."
                    : mode === "passive"
                    ? "Baseline reads can send scoped HTTP/TLS requests; active subsystem selections are disabled."
                    : mode === "aggressive"
                    ? "Deep 3+ depth spidering and all severity template checks."
                    : "Standard balanced testing."}
                </small>
              </label>

              <label>
                <div className="slider-header">
                  <span>Crawler Link Depth</span>
                  <span className="slider-val">{depth} level{depth > 1 ? "s" : ""}</span>
                </div>
                <input type="range" min={1} max={5} value={depth} onChange={e => { setDepth(Number(e.target.value)); invalidateReview(); }} disabled={busy || mode === "passive"} />
                <small>Recursive link spidering depth (1 = root/sitemap only, 5 = deep spidering).</small>
              </label>

              <label>
                <div className="slider-header">
                  <span>Request Rate Limit</span>
                  <span className="slider-val">{rate} req/s</span>
                </div>
                <input type="number" min={0.1} max={5000} step="any" value={rate} onChange={e => { setRate(Number(e.target.value)); invalidateReview(); }} disabled={busy} />
                <small>Scan throughput: {rate} req/s (Operator configurable up to 5000 req/s).</small>
              </label>

              <label>
                Custom Nuclei Template Tags (Optional)
                <input type="text" maxLength={512} placeholder="e.g. cve,misconfig,panel,tech" value={tags} onChange={e => { setTags(e.target.value); invalidateReview(); }} disabled={busy || mode === "passive"} />
                <small>Override active tags. Leave empty to use auto-synthesized adaptive tags.</small>
              </label>
            </div>

            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
              <div className="tool-toggles-title" style={{ margin: 0 }}>ENABLED SUBSYSTEM MODULES (12 SOTA ENGINES)</div>
              <button
                type="button"
                className="secondary compact"
                onClick={enableAllSOTA}
                style={{
                  background: "rgba(30,136,229,0.15)",
                  borderColor: "#1e88e5",
                  color: "#64b5f6",
                  fontWeight: 600,
                  fontSize: "12px",
                  cursor: "pointer",
                }}
              >
                ⚡ Preset: Automatic SOTA Everything
              </button>
            </div>
            <div className="tool-toggles-grid">
              <label className="checkbox-label">
                <input type="checkbox" checked={mode !== "passive" && toolNmap} onChange={e => { setToolNmap(e.target.checked); invalidateReview(); }} disabled={busy || mode === "passive"} />
                Nmap Port &amp; Service Scanner
              </label>
              <label className="checkbox-label">
                <input type="checkbox" checked={mode !== "passive" && toolCrawler} onChange={e => { setToolCrawler(e.target.checked); invalidateReview(); }} disabled={busy || mode === "passive"} />
                In-Scope Web Spider &amp; Sitemap
              </label>
              <label className="checkbox-label">
                <input type="checkbox" checked={mode !== "passive" && toolBrowser} onChange={e => { setToolBrowser(e.target.checked); invalidateReview(); }} disabled={busy || mode === "passive"} />
                Headless Chromium DOM Sink XSS &amp; SPA Router
              </label>
              <label className="checkbox-label">
                <input type="checkbox" checked={mode !== "passive" && toolSchema} onChange={e => { setToolSchema(e.target.checked); invalidateReview(); }} disabled={busy || mode === "passive"} />
                OpenAPI, GraphQL &amp; WSDL Schema Ingestion
              </label>
              <label className="checkbox-label">
                <input type="checkbox" checked={mode !== "passive" && toolAuthMatrix} onChange={e => { setToolAuthMatrix(e.target.checked); invalidateReview(); }} disabled={busy || mode === "passive"} />
                Dual-Identity IDOR Authorization Matrix
              </label>
              <label className="checkbox-label">
                <input type="checkbox" checked={mode !== "passive" && toolPayloadForge} onChange={e => { setToolPayloadForge(e.target.checked); invalidateReview(); }} disabled={busy || mode === "passive"} />
                Deterministic AST Payload Forge &amp; WAF Fuzzer
              </label>
              <label className="checkbox-label">
                <input type="checkbox" checked={mode !== "passive" && toolReproducer} onChange={e => { setToolReproducer(e.target.checked); invalidateReview(); }} disabled={busy || mode === "passive"} />
                3x Deterministic Reproducer &amp; Negative Canary
              </label>
              <label className="checkbox-label">
                <input type="checkbox" checked={mode !== "passive" && toolSensitive} onChange={e => { setToolSensitive(e.target.checked); invalidateReview(); }} disabled={busy || mode === "passive"} />
                Sensitive File Hunter (.git, .env)
              </label>
              <label className="checkbox-label">
                <input type="checkbox" checked={mode !== "passive" && toolDiff} onChange={e => { setToolDiff(e.target.checked); invalidateReview(); }} disabled={busy || mode === "passive"} />
                Behavioral Differential Testing
              </label>
              <label className="checkbox-label">
                <input type="checkbox" checked={mode !== "passive" && toolNuclei} onChange={e => { setToolNuclei(e.target.checked); invalidateReview(); }} disabled={busy || mode === "passive"} />
                Multi-Endpoint Nuclei Runner
              </label>
              <label className="checkbox-label">
                <input type="checkbox" checked={mode !== "passive" && toolZap} onChange={e => { setToolZap(e.target.checked); invalidateReview(); }} disabled={busy || mode === "passive"} />
                OWASP ZAP Passive Web Scanner
              </label>
              <label className="checkbox-label">
                <input type="checkbox" checked={mode !== "passive" && toolMsf} onChange={e => { setToolMsf(e.target.checked); invalidateReview(); }} disabled={busy || mode === "passive"} />
                Metasploit Auxiliary Verifier
              </label>
            </div>
          </div>
        </details>
      )}

      {accepted && !reviewed && <p className="notice">Scope changed; review the displayed replacement before confirming launch.</p>}
      {!ready && <p className="notice">{target.execution_blocker || "This scope must be active and authorized before an assessment can launch."}</p>}
      <label className="checkbox-label">
        <input type="checkbox" checked={reviewed} onChange={event => { setAccepted(event.target.checked); setReviewedScope(scopeIdentity); if (reviewedScope !== scopeIdentity) setIdempotency(crypto.randomUUID()); }} disabled={!ready || busy}/>
        I reviewed this exact scope and configuration and approve launching this assessment.
      </label>
      <ErrorNotice error={error}/>
      <div className="form-actions">
        <button className="secondary" onClick={cancel} disabled={busy}>Back</button>
        {error instanceof ApiError && error.status === 409 && <button className="secondary" onClick={reload}>Reload target</button>}
        <button className="primary" onClick={start} disabled={!reviewed || !ready || busy || (error instanceof ApiError && error.status === 409)}>
          {busy ? "Launching…" : "Launch assessment"}
          <Icon name="arrow"/>
        </button>
      </div>
    </Panel>
  );
}
