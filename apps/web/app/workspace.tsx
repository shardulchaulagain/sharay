"use client";

import { useEffect, useState } from "react";
import { api, date, post, setCsrf, type Session, type Overview as OverviewData, type Collection, type Assessment, type Integration, type Event, type Target, type User } from "./api";
import Login from "./login";
import { Badge, Empty, ErrorNotice, Icon, Loading, Panel, SectionHead, Shield, useResource, Pagination, ReportLinks } from "./components";
import Projects from "./projects";
import Assessments, { AssessmentTable } from "./assessments";
import Findings from "./findings";

type Page = "overview" | "projects" | "assets" | "assessments" | "findings" | "reports" | "integrations" | "audit" | "settings";
const pages: { id: Page; title: string }[] = [{ id: "overview", title: "Overview" }, { id: "projects", title: "Projects" }, { id: "assets", title: "Assets" }, { id: "assessments", title: "Assessments" }, { id: "findings", title: "Findings" }, { id: "reports", title: "Reports" }];
const adminPages: { id: Page; title: string }[] = [{ id: "integrations", title: "Integrations" }, { id: "audit", title: "Audit log" }, { id: "settings", title: "Settings" }];

export default function Aegis() {
  const [session, setSession] = useState<Session>();
  const [checking, setChecking] = useState(true);
  const [page, setPage] = useState<Page>("overview");
  const [assessment, setAssessment] = useState<string>();
  const [revision, setRevision] = useState(0);
  const [error, setError] = useState<Error>();
  const refresh = () => setRevision(value => value + 1);

  useEffect(() => {
    const controller = new AbortController();
    api<Session>("/auth/session", { signal: controller.signal }).then(data => { setCsrf(data.csrf_token); setSession(data); }).catch(() => {}).finally(() => setChecking(false));
    const expired = () => { setSession(undefined); setCsrf(""); setPage("overview"); setAssessment(undefined); };
    window.addEventListener("aegis-session-expired", expired);
    return () => { controller.abort(); window.removeEventListener("aegis-session-expired", expired); };
  }, []);

  function signIn(value: Session) { setCsrf(value.csrf_token); setSession(value); setPage("overview"); refresh(); }
  async function signOut() {
    try { await post("/auth/logout"); setSession(undefined); setCsrf(""); setAssessment(undefined); }
    catch (error) { setError(error instanceof Error ? error : new Error("Sign-out failed.")); }
  }
  function navigate(next: Page) { setPage(next); setAssessment(undefined); setError(undefined); }
  function openAssessment(id: string) { setAssessment(id); setPage("assessments"); }
  if (checking) return <main className="boot-screen"><Shield/><p className="eyebrow">SHARAY</p><Loading/></main>;
  if (!session) return <Login onLogin={signIn}/>;
  const user = session.user;
  const manager = ["owner", "security_administrator"].includes(user.role);
  return <div className="workspace">
    <a href="#main" className="skip-link">Skip to workspace</a>
    <aside className="sidebar">
      <div className="brand"><Shield small/><div><strong>SHARAY</strong><span>SECURITY WORKSPACE</span></div></div>
      <div className="workspace-select"><span className="workspace-icon">S</span><div><strong>Local organization</strong><span>Desktop workspace</span></div><span className="local-label">LOCAL</span></div>
      <p className="nav-label">WORKSPACE</p>
      <nav aria-label="Workspace">{pages.map(item => <button key={item.id} className={page === item.id ? "nav-item active" : "nav-item"} onClick={() => navigate(item.id)} aria-current={page === item.id ? "page" : undefined}><Icon name={item.id}/>{item.title}{page === item.id && <span className="nav-active-dot"/>}</button>)}</nav>
      <p className="nav-label">SYSTEM</p>
      <nav aria-label="System">{(manager ? adminPages : adminPages.filter(item => item.id === "integrations")).map(item => <button key={item.id} className={page === item.id ? "nav-item active" : "nav-item"} onClick={() => navigate(item.id)} aria-current={page === item.id ? "page" : undefined}><Icon name={item.id}/>{item.title}</button>)}</nav>
      <div className="roadmap-label"><Icon name="sparkle" size={15}/><span>AI investigations<br/><small>Planned · no provider enabled</small></span></div>
      <div className="roadmap-label"><Icon name="overview" size={15}/><span>Evaluation lab<br/><small>Planned · no benchmark data</small></span></div>
      <div className="sidebar-bottom"><div className="session-person"><span className="avatar">{user.username[0]?.toUpperCase()}</span><div><strong>{user.username}</strong><span>{user.role.replaceAll("_", " ")}</span></div><button className="icon-button" onClick={signOut} aria-label="Sign out"><Icon name="logout"/></button></div><p><span className="status-dot"/> LOCAL DESKTOP · 0.1</p></div>
    </aside>
    <div className="main-column">
      <header className="topbar"><div><span className="muted">Workspace</span><span className="breadcrumb">/</span><span>{[...pages, ...adminPages].find(item => item.id === page)?.title}</span></div><div className="topbar-right"><span className="environment"><span className="status-dot"/> Controlled laboratory</span><button className="icon-button" onClick={refresh} aria-label="Refresh workspace"><Icon name="refresh"/></button><span className="avatar small">{user.username[0]?.toUpperCase()}</span></div></header>
      <main id="main" className="main-content" tabIndex={-1}>
        <ErrorNotice error={error}/>
        {page === "overview" && <Overview revision={revision} navigate={navigate} openAssessment={openAssessment} user={user}/>}
        {page === "projects" && <Projects user={user} revision={revision} refresh={refresh} openAssessment={openAssessment}/>}
        {page === "assets" && <Assets revision={revision}/>}
        {page === "assessments" && <Assessments user={user} revision={revision} refresh={refresh} selected={assessment} openAssessment={openAssessment} clear={() => setAssessment(undefined)}/>}
        {page === "findings" && <Findings user={user} revision={revision} refresh={refresh} openAssessment={openAssessment}/>}
        {page === "reports" && <Reports revision={revision} openAssessment={openAssessment}/>}
        {page === "integrations" && <Integrations revision={revision}/>}
        {page === "audit" && <Audit revision={revision}/>}
        {page === "settings" && manager && <Settings user={user} revision={revision} refresh={refresh}/>}
      </main>
      <footer className="workspace-footer"><span>SHARAY / Evidence before conclusions</span><span>Local edition · Safe HTTP profile</span></footer>
    </div>
  </div>;
}

function Overview({ revision, navigate, openAssessment, user }: { revision: number; navigate: (page: Page) => void; openAssessment: (id: string) => void; user: User }) {
  const resource = useResource<OverviewData>("/overview", revision, true);
  if (resource.loading) return <Loading/>;
  if (resource.error) return <ErrorNotice error={resource.error}/>;
  const data = resource.data!;
  return <>
    <SectionHead eyebrow="OPERATIONS / OVERVIEW" title="Your security workspace" action={user.role !== "viewer" && <button className="primary" onClick={() => navigate("projects")}><Icon name="plus"/>Create assessment</button>}>A clear view of the work. Every result grounded in evidence.</SectionHead>
    <div className="workspace-notice"><Icon name="lock"/><p><strong>Local laboratory mode</strong><span>Only explicitly approved loopback targets can run. Safe HTTP checks · No intrusive testing · AI disabled</span></p><Badge value="scope enforced"/></div>
    <div className="metrics">{[{ label: "ACTIVE ASSESSMENTS", value: data.active_assessments, caption: "Queued or running", icon: "assessments" }, { label: "COMPLETED", value: data.completed_assessments, caption: "Finished assessments", icon: "check" }, { label: "CONFIRMED FINDINGS", value: data.confirmed_findings, caption: "Evidence-backed observations", icon: "findings" }, { label: "OPEN REMEDIATION", value: data.open_findings, caption: "Findings awaiting resolution", icon: "projects" }].map(metric => <div className="metric" key={metric.label}><div><span>{metric.label}</span><Icon name={metric.icon}/></div><strong>{metric.value}</strong><small>{metric.caption}</small></div>)}</div>
    <div className="overview-layout"><div>
      <Panel title="Recent assessments" action={<button className="text-button" onClick={() => navigate("assessments")}>View all <Icon name="arrow" size={14}/></button>}>{data.recent_assessments.length ? <AssessmentTable items={data.recent_assessments} open={openAssessment}/> : <Empty title="Your first assessment starts here" action={user.role !== "viewer" && <button className="secondary" onClick={() => navigate("projects")}>Set up a project <Icon name="arrow" size={15}/></button>}>Create a project, register a laboratory target, review its scope and approve the assessment.</Empty>}</Panel>
      <Panel title="Assessment workflow" className="workflow-panel"><ol className="workflow-strip"><li><span>01</span><strong>Define scope</strong><p>Register an authorized lab target.</p></li><li><span>02</span><strong>Approve & assess</strong><p>Run bounded, safe HTTP checks.</p></li><li><span>03</span><strong>Review evidence</strong><p>Inspect findings and export a report.</p></li><li><span>04</span><strong>Fix & retest</strong><p>Verify the effect of remediation.</p></li></ol></Panel>
    </div><div>
      <Panel title="Workspace inventory"><div className="inventory-line"><span><Icon name="projects"/>Projects</span><strong>{data.projects}</strong></div><div className="inventory-line"><span><Icon name="assets"/>Registered assets</span><strong>{data.assets}</strong></div><p className="panel-note">Counts reflect your organization’s stored records.</p></Panel>
      <Panel title="Recent activity"><Activity items={data.recent_events}/></Panel>
    </div></div>
  </>;
}

function Activity({ items }: { items: Event[] }) {
  if (!items.length) return <p className="panel-note">No activity yet. Project, authorization and assessment events will appear here.</p>;
  return <ol className="activity">{items.map((item, index) => <li key={item.id ?? index}><span className="activity-dot"/><div><strong>{(item.action ?? item.event ?? item.message ?? "Event recorded").replaceAll("_", " ")}</strong><p>{date(item.created_at ?? item.timestamp)}</p>{item.resource_id && <code>{item.resource_id.slice(0, 12)}</code>}</div></li>)}</ol>;
}

function Assets({ revision }: { revision: number }) {
  const resource = useResource<Collection<Target>>("/assets", revision);
  return <><SectionHead eyebrow="INVENTORY" title="Assets">Registered laboratory targets and their authorization status.</SectionHead>{resource.loading ? <Loading/> : resource.error ? <ErrorNotice error={resource.error}/> : <Panel title="Target inventory">{!resource.data?.items.length ? <Empty title="No assets registered">Register a controlled target inside a project to build your asset inventory.</Empty> : <div className="table-scroll"><table><thead><tr><th>Target</th><th>Authorization</th><th>Scope version</th><th>Expires</th></tr></thead><tbody>{resource.data.items.map(target => <tr key={target.id}><td><strong className="mono">{target.url}</strong><small>Explicit target registration</small></td><td><Badge value={target.verification_status}/></td><td>{target.scope_version}</td><td>{date(target.scope.expires_at)}</td></tr>)}</tbody></table></div>}</Panel>}</>;
}

function Reports({ revision, openAssessment }: { revision: number; openAssessment: (id: string) => void }) {
  const resource = useResource<Collection<Assessment>>("/assessments", revision);
  const items = resource.data?.items.filter(item => ["completed", "completed_with_errors", "failed", "cancelled"].includes(item.status)) ?? [];
  return <><SectionHead eyebrow="DELIVERABLES" title="Reports">Export stored evidence, scope, methodology and assessment limitations.</SectionHead>{resource.loading ? <Loading/> : resource.error ? <ErrorNotice error={resource.error}/> : <Panel title="Assessment reports">{!items.length ? <Empty title="No assessment reports yet">Complete an assessment to generate a report from its real results. Failed and cancelled assessments include their coverage limitations.</Empty> : <div className="table-scroll"><table><thead><tr><th>Assessment</th><th>Outcome</th><th>Finished</th><th>Export</th></tr></thead><tbody>{items.map(item => <tr key={item.id}><td><button className="link-button mono" onClick={() => openAssessment(item.id)}>{item.id.slice(0, 12)}</button></td><td><Badge value={item.status}/></td><td>{date(item.finished_at)}</td><td><ReportLinks id={item.id}/></td></tr>)}</tbody></table></div>}</Panel>}</>;
}

function Integrations({ revision }: { revision: number }) {
  const resource = useResource<Collection<Integration> & { worker?: string }>("/integrations", revision);
  return <><SectionHead eyebrow="SYSTEM / CAPABILITIES" title="Integrations">Availability is reported explicitly. An installed tool is never treated as an executed scan.</SectionHead>{resource.loading ? <Loading/> : resource.error ? <ErrorNotice error={resource.error}/> : <Panel title="Scanner and provider availability" action={<Badge value={`worker ${resource.data?.worker ?? "unknown"}`}/>}><div className="integration-list">{resource.data?.items.map((item, index) => <div className="integration-row" key={item.id ?? index}><div className="integration-icon"><Icon name="integrations"/></div><div><h3>{item.name}</h3><p>{item.description ?? item.reason ?? String(item.scope ?? "Scope unavailable")}</p>{item.version && <code>Version {item.version}</code>}{Boolean(item.limitations) && <p>{Array.isArray(item.limitations) ? item.limitations.join(" · ") : String(item.limitations)}</p>}</div><Badge value={item.status}/></div>)}</div></Panel>}<div className="notice">External scanner execution and AI provider configuration remain planned. Deterministic assessment and report generation work without an LLM.</div></>;
}

function Audit({ revision }: { revision: number }) {
  const [offset, setOffset] = useState(0);
  const resource = useResource<Collection<Event> & { integrity_valid: boolean }>(`/audit?limit=50&offset=${offset}`, revision);
  return <><SectionHead eyebrow="SYSTEM / ACCOUNTABILITY" title="Audit log">Recorded authorization, execution and data-management decisions.</SectionHead>{resource.loading ? <Loading/> : resource.error ? <ErrorNotice error={resource.error}/> : <Panel title="Organization events" action={<Badge value={resource.data?.integrity_valid ? "integrity verified" : "integrity failure"}/>}>{resource.data?.items.length ? <><div className="table-scroll"><table><thead><tr><th>Event</th><th>Actor</th><th>Resource</th><th>Recorded</th></tr></thead><tbody>{resource.data.items.map(item => <tr key={item.id}><td>{item.action?.replaceAll("_", " ") ?? item.event}</td><td className="mono">{item.actor?.slice(0, 12) ?? item.actor_id?.slice(0, 12) ?? "System"}</td><td className="mono">{item.resource_id?.slice(0, 12) ?? "—"}</td><td>{date(item.created_at ?? item.timestamp)}</td></tr>)}</tbody></table></div><Pagination offset={offset} total={resource.data.total ?? resource.data.items.length} limit={50} setOffset={setOffset}/></> : <Empty title="No audit events">Activity will be recorded as you work.</Empty>}</Panel>}</>;
}

function Settings({ user, revision, refresh }: { user: User; revision: number; refresh: () => void }) {
  const resource = useResource<Collection<User>>("/auth/members", revision);
  const [error, setError] = useState<Error>();
  const [busy, setBusy] = useState(false);
  async function create(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form = event.currentTarget; const data = new FormData(form); setBusy(true); setError(undefined);
    try { await post("/auth/members", { username: data.get("username"), password: data.get("password"), role: data.get("role") }); form.reset(); refresh(); }
    catch (error) { setError(error instanceof Error ? error : new Error("Account creation failed.")); } finally { setBusy(false); }
  }
  return <><SectionHead eyebrow="SYSTEM / ORGANIZATION" title="Settings">Local accounts and the boundaries of this desktop installation.</SectionHead><Panel title="Organization members">{resource.loading ? <Loading/> : resource.error ? <ErrorNotice error={resource.error}/> : <div className="table-scroll"><table><thead><tr><th>Username</th><th>Role</th></tr></thead><tbody>{resource.data?.items.map(member => <tr key={member.id}><td>{member.username}{member.id === user.id && <small>Current account</small>}</td><td><Badge value={member.role}/></td></tr>)}</tbody></table></div>}</Panel>{user.role === "owner" && <Panel title="Create local account"><form onSubmit={create} className="member-form"><label>Username<input name="username" autoComplete="off" required minLength={3} maxLength={100}/></label><label>Initial password<input name="password" type="password" autoComplete="new-password" required minLength={12}/><small>At least 12 characters. Share through your approved private channel.</small></label><label>Role<select name="role" defaultValue="viewer"><option value="viewer">Viewer</option><option value="analyst">Analyst</option><option value="security_administrator">Security administrator</option></select></label><button className="primary" disabled={busy}>{busy ? "Creating…" : "Create account"}</button><ErrorNotice error={error}/></form></Panel>}<Panel title="Desktop configuration"><dl className="facts"><div><dt>Execution profile</dt><dd>Safe HTTP · loopback laboratory only</dd></div><div><dt>AI providers</dt><dd>Disabled · configuration planned</dd></div><div><dt>Evidence retention</dt><dd>Indefinite local retention · automatic deletion unavailable</dd></div><div><dt>Session security</dt><dd>Opaque session cookie · server-side role checks · CSRF protection</dd></div></dl></Panel></>;
}
