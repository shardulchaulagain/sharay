"use client";

import { useEffect, useState } from "react";
import { api, date, post, setCsrf, type Session, type Overview as OverviewData, type Collection, type Assessment, type Integration, type Event, type Target, type User, type AIStatus, type AIInvestigation } from "./api";
import Login from "./login";
import { Badge, Empty, ErrorNotice, Icon, Loading, Panel, SectionHead, Shield, useResource, Pagination, ReportLinks } from "./components";
import Projects from "./projects";
import Assessments, { AssessmentTable } from "./assessments";
import Findings from "./findings";
import SourceAnalysis from "./source";

type Page = "overview" | "projects" | "assets" | "assessments" | "findings" | "source" | "reports" | "integrations" | "audit" | "settings" | "ai";
const pages: { id: Page; title: string }[] = [{ id: "overview", title: "Overview" }, { id: "projects", title: "Projects" }, { id: "assets", title: "Assets" }, { id: "assessments", title: "Assessments" }, { id: "findings", title: "Findings" }, { id: "source", title: "Source analysis" }, { id: "reports", title: "Reports" }, { id: "ai", title: "AI investigations" }];
const adminPages: { id: Page; title: string }[] = [{ id: "integrations", title: "Integrations" }, { id: "audit", title: "Audit log" }, { id: "settings", title: "Settings" }];

export default function Sharay() {
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
      <nav aria-label="Workspace">{pages.map(item => <button key={item.id} className={page === item.id ? "nav-item active" : "nav-item"} onClick={() => navigate(item.id)} aria-current={page === item.id ? "page" : undefined}><Icon name={item.id === "ai" ? "sparkle" : item.id}/>{item.title}{page === item.id && <span className="nav-active-dot"/>}</button>)}</nav>
      <p className="nav-label">SYSTEM</p>
      <nav aria-label="System">{(manager ? adminPages : adminPages.filter(item => item.id === "integrations")).map(item => <button key={item.id} className={page === item.id ? "nav-item active" : "nav-item"} onClick={() => navigate(item.id)} aria-current={page === item.id ? "page" : undefined}><Icon name={item.id}/>{item.title}</button>)}</nav>
      <button type="button" className="roadmap-label" style={{ cursor: "pointer", border: 0, textAlign: "left", background: "#0c231e" }} onClick={() => navigate("ai")}><Icon name="sparkle" size={15}/><span>AI investigations<br/><small style={{ color: "#75c9bc" }}>Active · Attack Graph Ready</small></span></button>
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
        {page === "source" && <SourceAnalysis/>}
        {page === "reports" && <Reports revision={revision} openAssessment={openAssessment}/>}
        {page === "ai" && <AIInvestigations revision={revision}/>}
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
    <div className="workspace-notice"><Icon name="lock"/><p><strong>Operator Scope &amp; Target Assessment</strong><span>Authorized target scopes registered with full multi-port scanning, perimeter recon, deep vulnerability fuzzing &amp; AI investigations active.</span></p><Badge value="operator authorized"/></div>
    <div className="metrics">{[{ label: "ACTIVE ASSESSMENTS", value: data.active_assessments, caption: "Queued or running", icon: "assessments" }, { label: "COMPLETED", value: data.completed_assessments, caption: "Finished assessments", icon: "check" }, { label: "CONFIRMED FINDINGS", value: data.confirmed_findings, caption: "Evidence-backed observations", icon: "findings" }, { label: "OPEN REMEDIATION", value: data.open_findings, caption: "Findings awaiting resolution", icon: "projects" }].map(metric => <div className="metric" key={metric.label}><div><span>{metric.label}</span><Icon name={metric.icon}/></div><strong>{metric.value}</strong><small>{metric.caption}</small></div>)}</div>
    <div className="overview-layout"><div>
      <Panel title="Recent assessments" action={<button className="text-button" onClick={() => navigate("assessments")}>View all <Icon name="arrow" size={14}/></button>}>{data.recent_assessments.length ? <AssessmentTable items={data.recent_assessments} open={openAssessment}/> : <Empty title="Your first assessment starts here" action={user.role !== "viewer" && <button className="secondary" onClick={() => navigate("projects")}>Set up a project <Icon name="arrow" size={15}/></button>}>Create a project, register a target and review its scope. Execution availability is shown before assessment.</Empty>}</Panel>
      <Panel title="Assessment workflow" className="workflow-panel"><ol className="workflow-strip"><li><span>01</span><strong>Define scope</strong><p>Register an authorized target.</p></li><li><span>02</span><strong>Approve & assess</strong><p>Run bounded, safe HTTP checks.</p></li><li><span>03</span><strong>Review evidence</strong><p>Inspect findings and export a report.</p></li><li><span>04</span><strong>Fix & retest</strong><p>Verify the effect of remediation.</p></li></ol></Panel>
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
  return <><SectionHead eyebrow="INVENTORY" title="Assets">Registered targets and their authorization status.</SectionHead>{resource.loading ? <Loading/> : resource.error ? <ErrorNotice error={resource.error}/> : <Panel title="Target inventory">{!resource.data?.items.length ? <Empty title="No assets registered">Register a controlled target inside a project to build your asset inventory.</Empty> : <div className="table-scroll"><table><thead><tr><th>Target</th><th>Authorization</th><th>Scope version</th><th>Expires</th></tr></thead><tbody>{resource.data.items.map(target => <tr key={target.id}><td><strong className="mono">{target.url}</strong><small>Explicit target registration</small></td><td><Badge value={target.verification_status}/></td><td>{target.scope_version}</td><td>{date(target.scope.expires_at)}</td></tr>)}</tbody></table></div>}</Panel>}</>;
}

function Reports({ revision, openAssessment }: { revision: number; openAssessment: (id: string) => void }) {
  const resource = useResource<Collection<Assessment>>("/assessments", revision);
  const items = resource.data?.items.filter(item => ["completed", "completed_with_errors", "failed", "cancelled"].includes(item.status)) ?? [];
  return <><SectionHead eyebrow="DELIVERABLES" title="Reports">Export stored evidence, scope, methodology and assessment limitations.</SectionHead>{resource.loading ? <Loading/> : resource.error ? <ErrorNotice error={resource.error}/> : <Panel title="Assessment reports">{!items.length ? <Empty title="No assessment reports yet">Complete an assessment to generate a report from its real results. Failed and cancelled assessments include their coverage limitations.</Empty> : <div className="table-scroll"><table><thead><tr><th>Assessment</th><th>Outcome</th><th>Finished</th><th>Export</th></tr></thead><tbody>{items.map(item => <tr key={item.id}><td><button className="link-button mono" onClick={() => openAssessment(item.id)}>{item.id.slice(0, 12)}</button></td><td><Badge value={item.status}/></td><td>{date(item.finished_at)}</td><td><ReportLinks id={item.id}/></td></tr>)}</tbody></table></div>}</Panel>}</>;
}

function AIInvestigations({ revision }: { revision: number }) {
  const [selectedProvider, setProvider] = useState<"google" | "anthropic" | "openai">();
  const [selectedAssessmentId, setSelectedAsmt] = useState("");
  const [investigationResult, setInvestigationResult] = useState<{ key: string; data: AIInvestigation }>();
  const [investigating, setInvestigating] = useState(false);
  const [activeTab, setActiveTab] = useState<"graph" | "paths" | "rootcause" | "remediation" | "killchain">("graph");
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const assessmentsResource = useResource<Collection<Assessment>>("/assessments", revision);
  const assessments = assessmentsResource.data?.items.filter(a => ["completed", "completed_with_errors"].includes(a.status)) ?? [];
  const selectedAsmt = assessments.some(a => a.id === selectedAssessmentId) ? selectedAssessmentId : assessments[0]?.id ?? "";
  const aiStatusResource = useResource<AIStatus>("/ai/status", revision);
  const aiStatus = aiStatusResource.data;
  const activeProvider = aiStatus?.active_provider;
  const provider = selectedProvider ?? (activeProvider === "google" || activeProvider === "anthropic" || activeProvider === "openai" ? activeProvider : "google");
  const investigationResource = useResource<AIInvestigation>(selectedAsmt ? `/ai/investigations/${encodeURIComponent(selectedAsmt)}` : null, revision);
  const investigationKey = `${selectedAsmt}:${revision}`;
  const submittedResult = investigationResult?.key === investigationKey ? investigationResult.data : undefined;
  const investigation = submittedResult ?? investigationResource.data;
  const loading = Boolean(selectedAsmt) && investigationResource.loading && !submittedResult;

  async function triggerDeepInvestigation() {
    if (!selectedAsmt) return;
    setInvestigating(true);
    try {
      const result = await post<AIInvestigation>(`/ai/investigate/${encodeURIComponent(selectedAsmt)}`);
      setInvestigationResult({ key: investigationKey, data: result });
    } catch (e) {
      console.error(e);
    } finally {
      setInvestigating(false);
    }
  }

  function copyDiff(id: string, text: string) {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  }

  return (
    <>
      <SectionHead eyebrow="REASONING / ADVERSARIAL" title="AI Investigations & Attack Graphs">
        Directed adversarial attack graph modeling, multi-step kill chains, and White/C-Team root cause remediation patches.
      </SectionHead>

      <div className="metrics" style={{ gridTemplateColumns: "repeat(4, 1fr)", marginBottom: 20 }}>
        <div className="metric">
          <div className="metric-label"><span>POSTURE SCORE</span></div>
          <div className="metric-value" style={{ color: investigation?.posture_score == null ? "#94a3b8" : investigation.posture_score >= 80 ? "#75c9bc" : "#e08a4e", fontSize: 22 }}>
            {!investigation ? "—" : investigation.posture_score == null ? "Not assessed" : `${investigation.posture_score} / 100`}
          </div>
          <p className="panel-note" style={{ margin: "4px 0 0" }}>Defensive Posture Rating</p>
        </div>
        <div className="metric">
          <div className="metric-label"><span>ATTACK GRAPH</span></div>
          <div className="metric-value" style={{ fontSize: 18 }}>
            {investigation ? `${investigation.graph.nodes_count} Nodes · ${investigation.graph.edges_count} Edges` : "Active"}
          </div>
          <p className="panel-note" style={{ margin: "4px 0 0" }}>Directed Acyclic Graph (DAG)</p>
        </div>
        <div className="metric">
          <div className="metric-label"><span>ACTIVE AI ENGINE</span></div>
          <div className="metric-value" style={{ fontSize: 18, textTransform: "capitalize", color: "#75c9bc" }}>
            {aiStatus?.active_provider ? aiStatus.active_provider : provider}
          </div>
          <p className="panel-note" style={{ margin: "4px 0 0" }}>{aiStatus?.model || "gemini-2.5-pro"} · HTTPS</p>
        </div>
        <div className="metric">
          <div className="metric-label"><span>TOKEN REDACTION</span></div>
          <div className="metric-value" style={{ color: "#75c9bc", fontSize: 20 }}>Enforced</div>
          <p className="panel-note" style={{ margin: "4px 0 0" }}>0 Credential Leakage Gate</p>
        </div>
      </div>

      <Panel title="Assessment Investigation Control">
        <div style={{ display: "flex", gap: 16, alignItems: "center", flexWrap: "wrap", padding: "4px 0" }}>
          <label style={{ margin: 0, flex: 2, minWidth: 260 }}>
            Target Assessment:
            <select
              value={selectedAsmt}
              onChange={e => setSelectedAsmt(e.target.value)}
              style={{ marginTop: 6, width: "100%" }}
            >
              {assessments.map(a => (
                <option key={a.id} value={a.id}>
                  {a.scope_snapshot?.target_url || a.target_url || a.id.slice(0, 12)} ({a.status} · {date(a.finished_at || a.created_at)})
                </option>
              ))}
              {!assessments.length && <option value="">No completed assessments found</option>}
            </select>
          </label>

          <label style={{ margin: 0, flex: 1, minWidth: 200 }}>
            Model Provider:
            <select
              value={provider}
              onChange={e => setProvider(e.target.value as "google" | "anthropic" | "openai")}
              style={{ marginTop: 6, width: "100%" }}
            >
              <option value="google">Google Gemini (Gemini 2.5 Pro)</option>
              <option value="anthropic">Anthropic Claude (Claude 3.5 Sonnet)</option>
              <option value="openai">OpenAI (GPT-4o)</option>
            </select>
          </label>

          <div style={{ alignSelf: "flex-end" }}>
            <button
              className="primary"
              disabled={!selectedAsmt || investigating || loading}
              onClick={triggerDeepInvestigation}
              style={{ display: "flex", alignItems: "center", gap: 8, height: 40 }}
            >
              <Icon name="sparkle" size={16} />
              {investigating ? "Reasoning & Analyzing..." : "Run Deep AI Investigation"}
            </button>
          </div>
        </div>

        {investigation?.ai_executive_summary && (
          <div style={{ marginTop: 16, padding: "14px 16px", background: "rgba(117, 201, 188, 0.08)", borderLeft: "3px solid #75c9bc", borderRadius: "0 6px 6px 0" }}>
            <strong style={{ color: "#75c9bc", display: "block", marginBottom: 6, fontSize: 13, textTransform: "uppercase", letterSpacing: "0.05em" }}>
              AI Threat Modeling &amp; Executive Summary
            </strong>
            <p style={{ margin: 0, lineHeight: 1.6, fontSize: 14 }}>{investigation.ai_executive_summary}</p>
          </div>
        )}
      </Panel>

      <div style={{ display: "flex", gap: 8, margin: "20px 0 14px", borderBottom: "1px solid var(--border-color, #273138)", paddingBottom: 8 }}>
        <button
          className={activeTab === "graph" ? "nav-item active" : "nav-item"}
          onClick={() => setActiveTab("graph")}
          style={{ padding: "8px 14px", borderRadius: 4 }}
        >
          Attack Graph (DAG) ({investigation?.graph.nodes_count ?? 0} Nodes)
        </button>
        <button
          className={activeTab === "paths" ? "nav-item active" : "nav-item"}
          onClick={() => setActiveTab("paths")}
          style={{ padding: "8px 14px", borderRadius: 4 }}
        >
          Exploit Kill Chains ({investigation?.attack_paths.length ?? 0} Paths)
        </button>
        <button
          className={activeTab === "rootcause" ? "nav-item active" : "nav-item"}
          onClick={() => setActiveTab("rootcause")}
          style={{ padding: "8px 14px", borderRadius: 4 }}
        >
          White/C-Team Root Cause ({investigation?.root_causes.length ?? 0} Categories)
        </button>
        <button
          className={activeTab === "remediation" ? "nav-item active" : "nav-item"}
          onClick={() => setActiveTab("remediation")}
          style={{ padding: "8px 14px", borderRadius: 4 }}
        >
          Remediation Patches &amp; Diffs ({investigation?.remediation_patches.length ?? 0})
        </button>
      </div>

      {loading && <Loading />}

      {!loading && activeTab === "graph" && (
        <Panel title="Adversarial Attack Surface Graph (DAG)">
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Node Type</th>
                  <th>Identifier / Component</th>
                  <th>Node ID</th>
                  <th>Risk Weight</th>
                  <th>Attributes / Exposure Details</th>
                </tr>
              </thead>
              <tbody>
                {investigation?.graph.nodes.map(n => (
                  <tr key={n.id}>
                    <td>
                      <Badge value={n.kind} /> <strong>{n.kind.toUpperCase()}</strong>
                    </td>
                    <td><strong>{n.label}</strong></td>
                    <td className="mono">{n.id}</td>
                    <td>
                      <span style={{ color: n.kind === "vulnerability" ? "#e08a4e" : "inherit" }}>
                        {n.kind === "vulnerability" ? "High Risk" : "Standard"}
                      </span>
                    </td>
                    <td><small>{JSON.stringify(n.attributes)}</small></td>
                  </tr>
                ))}
                {!investigation?.graph.nodes.length && (
                  <tr>
                    <td colSpan={5} style={{ textAlign: "center", padding: 20 }}>
                      No nodes loaded. Run an assessment or select an assessment above.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      {!loading && activeTab === "paths" && (
        <>
          <Panel title="5-Phase Red Team Kill Chain Execution">
            <div style={{ display: "grid", gap: 12 }}>
              {investigation?.red_team_kill_chain.map(kc => (
                <div key={kc.phase} style={{ padding: 12, border: "1px solid rgba(255,255,255,0.08)", borderRadius: 6 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                    <strong>{kc.phase}</strong>
                    <Badge value={kc.status} />
                  </div>
                  <p style={{ margin: "4px 0", fontSize: 13, color: "rgba(255,255,255,0.8)" }}>{kc.summary}</p>
                  <div style={{ display: "flex", gap: 6, marginTop: 6 }}>
                    {kc.tools.map(t => <span key={t} className="mono" style={{ fontSize: 11, background: "rgba(255,255,255,0.06)", padding: "2px 6px", borderRadius: 4 }}>{t}</span>)}
                  </div>
                </div>
              ))}
            </div>
          </Panel>

          <Panel title="Traced Multi-Step Exploit Attack Paths">
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Root Entrypoint</th>
                    <th>Exploit Progression Steps</th>
                    <th>Target Vulnerability</th>
                    <th>Remediation Requirement</th>
                  </tr>
                </thead>
                <tbody>
                  {investigation?.attack_paths.map(p => (
                    <tr key={p.path_id}>
                      <td><Badge value={p.severity} /></td>
                      <td><strong>{p.root_exposure}</strong></td>
                      <td>
                        <span className="mono" style={{ fontSize: 12 }}>{p.steps.join(" → ")}</span>
                      </td>
                      <td style={{ color: "#e08a4e" }}><strong>{p.target_vulnerability}</strong></td>
                      <td>{p.remediation}</td>
                    </tr>
                  ))}
                  {!investigation?.attack_paths.length && (
                    <tr>
                      <td colSpan={5} style={{ textAlign: "center", padding: 20 }}>
                        No multi-step exploit paths detected in this target scope.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </Panel>
        </>
      )}

      {!loading && activeTab === "rootcause" && (
        <Panel title="White/C-Team Architectural Root Cause Breakdown">
          <div style={{ display: "grid", gap: 16 }}>
            {investigation?.root_causes.map(rc => (
              <div key={rc.category} style={{ padding: 16, border: "1px solid rgba(255,255,255,0.1)", borderRadius: 6, background: "rgba(0,0,0,0.2)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <Badge value={rc.severity} />
                    <strong style={{ fontSize: 16 }}>{rc.category}</strong>
                  </div>
                  <span className="mono" style={{ fontSize: 12, color: "#75c9bc" }}>{rc.cwe_id} · {rc.owasp_category}</span>
                </div>
                <p style={{ margin: "8px 0", lineHeight: 1.5, fontSize: 14 }}><strong>Mechanism:</strong> {rc.mechanism}</p>
                <p style={{ margin: "8px 0", lineHeight: 1.5, fontSize: 14, color: "#e08a4e" }}><strong>Blast Radius:</strong> {rc.blast_radius}</p>
                <div style={{ marginTop: 10, padding: 10, background: "rgba(117,201,188,0.06)", borderLeft: "3px solid #75c9bc", borderRadius: "0 4px 4px 0" }}>
                  <strong style={{ color: "#75c9bc", display: "block", fontSize: 12 }}>STRATEGIC ARCHITECTURAL FIX:</strong>
                  <p style={{ margin: "4px 0 0", fontSize: 13 }}>{rc.strategic_fix}</p>
                </div>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {!loading && activeTab === "remediation" && (
        <Panel title="Deployable Code-Level Remediation Patches &amp; Config Diffs">
          <div style={{ display: "grid", gap: 20 }}>
            {investigation?.remediation_patches.map(patch => (
              <div key={patch.id} style={{ border: "1px solid rgba(255,255,255,0.1)", borderRadius: 6, overflow: "hidden" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 14px", background: "rgba(255,255,255,0.04)", borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
                  <div>
                    <strong>{patch.title}</strong>
                    <span className="mono" style={{ display: "block", fontSize: 11, color: "rgba(255,255,255,0.6)", marginTop: 2 }}>
                      Component: {patch.target_component} ({patch.file_type})
                    </span>
                  </div>
                  <button
                    className="secondary"
                    onClick={() => copyDiff(patch.id, patch.diff)}
                    style={{ fontSize: 12, padding: "4px 10px", height: "auto" }}
                  >
                    {copiedId === patch.id ? "✓ Copied!" : "Copy Diff"}
                  </button>
                </div>
                <div style={{ padding: "8px 14px" }}>
                  <p style={{ margin: "4px 0 10px", fontSize: 13, color: "rgba(255,255,255,0.8)" }}>{patch.description}</p>
                  <pre className="mono" style={{ margin: 0, padding: 12, background: "#0d1117", borderRadius: 4, overflowX: "auto", fontSize: 12, lineHeight: 1.5, color: "#e6edf3" }}>
                    {patch.diff.split("\n").map((line, i) => (
                      <div
                        key={i}
                        style={{
                          color: line.startsWith("+") ? "#7ee787" : line.startsWith("-") ? "#ffa198" : line.startsWith("@") ? "#79c0ff" : "inherit",
                          background: line.startsWith("+") ? "rgba(46,160,67,0.15)" : line.startsWith("-") ? "rgba(248,81,73,0.15)" : "transparent",
                        }}
                      >
                        {line}
                      </div>
                    ))}
                  </pre>
                </div>
              </div>
            ))}
          </div>
        </Panel>
      )}
    </>
  );
}

function Integrations({ revision }: { revision: number }) {
  const resource = useResource<Collection<Integration> & { worker?: string }>("/integrations", revision);
  return <><SectionHead eyebrow="SYSTEM / CAPABILITIES" title="Integrations">Availability is reported explicitly. An installed tool is never treated as an executed scan.</SectionHead>{resource.loading ? <Loading/> : resource.error ? <ErrorNotice error={resource.error}/> : <Panel title="Scanner and provider availability" action={<Badge value={`worker ${resource.data?.worker ?? "unknown"}`}/>}><div className="integration-list">{resource.data?.items.map((item, index) => <div className="integration-row" key={item.id ?? index}><div className="integration-icon"><Icon name="integrations"/></div><div><h3>{item.name}</h3><p>{item.description ?? item.reason ?? String(item.scope ?? "Scope unavailable")}</p>{item.version && <code>Version {item.version}</code>}{typeof item.guidance === "string" && <p>{item.guidance}</p>}{Boolean(item.limitations) && <p>{Array.isArray(item.limitations) ? item.limitations.join(" · ") : String(item.limitations)}</p>}</div><Badge value={item.status}/></div>)}</div></Panel>}<div className="notice">Containerized scanner execution (Nuclei, Podman Egress Isolation) and Interactive Takeover Console are active. Deterministic assessment and report generation work without external LLM dependencies.</div></>;
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
  return <><SectionHead eyebrow="SYSTEM / ORGANIZATION" title="Settings">Local accounts and the boundaries of this desktop installation.</SectionHead><Panel title="Organization members">{resource.loading ? <Loading/> : resource.error ? <ErrorNotice error={resource.error}/> : <div className="table-scroll"><table><thead><tr><th>Username</th><th>Role</th></tr></thead><tbody>{resource.data?.items.map(member => <tr key={member.id}><td>{member.username}{member.id === user.id && <small>Current account</small>}</td><td><Badge value={member.role}/></td></tr>)}</tbody></table></div>}</Panel>{user.role === "owner" && <Panel title="Create local account"><form onSubmit={create} className="member-form"><label>Username<input name="username" autoComplete="off" required minLength={3} maxLength={100}/></label><label>Initial password<input name="password" type="password" autoComplete="new-password" required minLength={12}/><small>At least 12 characters. Share through your approved private channel.</small></label><label>Role<select name="role" defaultValue="viewer"><option value="viewer">Viewer</option><option value="analyst">Analyst</option><option value="security_administrator">Security administrator</option></select></label><button className="primary" disabled={busy}>{busy ? "Creating…" : "Create account"}</button><ErrorNotice error={error}/></form></Panel>}<Panel title="Desktop configuration"><dl className="facts"><div><dt>Execution profile</dt><dd>Full Spectrum (Multi-Port · Vulnerability Fuzzing · In-Scope Crawler · DNS Intelligence)</dd></div><div><dt>AI providers</dt><dd>Active · Multi-model adversarial reasoning (Gemini · Claude · OpenAI)</dd></div><div><dt>Evidence retention</dt><dd>Indefinite local retention · automatic deletion unavailable</dd></div><div><dt>Session security</dt><dd>Opaque session cookie · server-side role checks · CSRF protection</dd></div></dl></Panel></>;
}
