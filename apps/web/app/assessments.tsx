"use client";

import { useState } from "react";
import { api, ApiError, date, post, scopeActionError, scopeIsActive, type Assessment, type Collection, type Project, type Target, type User } from "./api";
import { Badge, Empty, ErrorNotice, Icon, Json, Loading, Panel, SectionHead, useResource, Pagination, ReportLinks } from "./components";
import ScopePreview from "./scope-preview";

export default function Assessments({ user, revision, refresh, selected, openAssessment, clear }: { user: User; revision: number; refresh: () => void; selected?: string; openAssessment: (id: string) => void; clear: () => void }) {
  const [offset, setOffset] = useState(0);
  const resource = useResource<Collection<Assessment>>(`/assessments?limit=25&offset=${offset}`, revision, !selected);
  if (selected) return <AssessmentDetail key={selected} id={selected} user={user} revision={revision} refresh={refresh} back={clear} openAssessment={openAssessment}/>;
  return <><SectionHead eyebrow="WORKSPACE / EXECUTION" title="Assessments">Real worker stages and outcomes. Coverage is explicit, including failed and skipped checks.</SectionHead>{resource.loading ? <Loading/> : resource.error ? <ErrorNotice error={resource.error}/> : <Panel title="Assessment history">{resource.data?.items.length ? <><AssessmentTable items={resource.data.items} open={openAssessment}/><Pagination offset={offset} total={resource.data.total ?? resource.data.items.length} limit={25} setOffset={setOffset}/></> : <Empty title="No assessments yet">Launch an assessment from an explicitly approved target in Projects.</Empty>}</Panel>}</>;
}

export function AssessmentTable({ items, open }: { items: Assessment[]; open: (id: string) => void }) {
  return <div className="table-scroll"><table><thead><tr><th>Assessment</th><th>Status</th><th>Current stage</th><th>Created</th><th><span className="sr-only">Open</span></th></tr></thead><tbody>{items.map(item => <tr key={item.id}><td><button className="link-button mono" onClick={() => open(item.id)}>{item.id.slice(0, 12)}</button>{item.retest_of && <small>Retest of {item.retest_of.slice(0, 8)}</small>}</td><td><Badge value={item.status}/></td><td>{item.stage || "Queued"}</td><td>{date(item.created_at)}</td><td><button className="icon-button" aria-label={`Open assessment ${item.id}`} onClick={() => open(item.id)}><Icon name="arrow" size={16}/></button></td></tr>)}</tbody></table></div>;
}

function AssessmentDetail({ id, user, revision, refresh, back, openAssessment }: { id: string; user: User; revision: number; refresh: () => void; back: () => void; openAssessment: (id: string) => void }) {
  const resource = useResource<Assessment>(`/assessments/${encodeURIComponent(id)}`, revision, true);
  const project = useResource<Project>(resource.data ? `/projects/${encodeURIComponent(resource.data.project_id)}` : null, revision, true);
  const [error, setError] = useState<Error>();
  const [busy, setBusy] = useState(false);
  const [confirmRetest, setConfirmRetest] = useState(false);
  const [retestApproved, setRetestApproved] = useState(false);
  const [retestKey, setRetestKey] = useState(() => crypto.randomUUID());
  const [retestTarget, setRetestTarget] = useState<Target>();
  async function reviewRetest(reload = false) {
    setRetestApproved(false); setError(undefined);
    if (confirmRetest && !reload) { setConfirmRetest(false); setRetestTarget(undefined); return; }
    setRetestTarget(undefined); setConfirmRetest(false);
    setBusy(true);
    try {
      const target = await api<Target>(`/targets/${encodeURIComponent(resource.data!.target_id)}`);
      setRetestTarget(target); setRetestKey(crypto.randomUUID()); setConfirmRetest(true);
    }
    catch (error) { setError(scopeActionError(error, "Could not load the current target scope.")); }
    finally { setBusy(false); }
  }
  async function cancel() {
    setBusy(true); setError(undefined);
    try { await post(`/assessments/${encodeURIComponent(id)}/cancel`); refresh(); }
    catch (error) { setError(error instanceof Error ? error : new Error("Cancellation failed.")); } finally { setBusy(false); }
  }
  async function retest() {
    setBusy(true); setError(undefined);
    try { if (!retestTarget) throw new Error("Review the current target scope before launching."); const next = await post<Assessment>("/assessments", { target_id: retestTarget.id, expected_scope_version: retestTarget.scope_version, retest_of: id, idempotency_key: retestKey }); setConfirmRetest(false); setRetestApproved(false); refresh(); openAssessment(next.id); }
    catch (error) { setRetestApproved(false); setError(scopeActionError(error, "Retest failed.")); } finally { setBusy(false); }
  }
  if (resource.loading) return <Loading/>;
  if (resource.error) return <ErrorNotice error={resource.error}/>;
  const data = resource.data!;
  const running = ["queued", "running", "cancelling"].includes(data.status);
  const elapsed = data.started_at && (data.finished_at || resource.observedAt) ? Math.max(0, Math.floor(((data.finished_at ? new Date(data.finished_at).getTime() : resource.observedAt!) - new Date(data.started_at).getTime()) / 1000)) : undefined;
  const canAct = user.role !== "viewer";
  const canRetest = canAct && project.data && !project.data.archived;
  const retestReady = retestTarget?.verification_status === "verified_lab" && !retestTarget.execution_blocker && scopeIsActive(retestTarget.scope);
  const stale = error instanceof ApiError && error.status === 409;
  return <>
    <button className="text-button back-button" onClick={back}>← All assessments</button>
    <SectionHead eyebrow={`ASSESSMENT / ${id.slice(0, 12)}`} title="Assessment detail" action={canAct && (running ? <button className="danger" disabled={busy || data.status === "cancelling"} onClick={cancel}>{data.status === "cancelling" ? "Cancelling…" : busy ? "Requesting…" : "Cancel assessment"}</button> : canRetest && ["completed", "completed_with_errors"].includes(data.status) && <button className="primary" disabled={busy} onClick={() => void reviewRetest()}>Review retest<Icon name="refresh"/></button>)}>Safe, bounded checks against the approved scope.</SectionHead>
    <ErrorNotice error={error}/>
    <div className="assessment-status"><div><Badge value={data.status}/><h2>{data.stage || "Awaiting worker"}</h2><p>{running ? "Refreshing actual worker state every 2.5 seconds." : `Finished ${date(data.finished_at)}`}</p></div><div><span className="eyebrow">ELAPSED</span><strong>{elapsed === undefined ? "—" : `${elapsed}s`}</strong></div><div><span className="eyebrow">OBSERVATIONS</span><strong>{data.observations?.length ?? 0}</strong></div><div><span className="eyebrow">FINDINGS</span><strong>{data.findings?.length ?? 0}</strong></div></div>
    {data.error && <div className="notice error" role="alert">{data.error}</div>}
    {project.data?.archived && <div className="notice">This project is archived. New retests are unavailable.</div>}
    {canAct && project.error && <ErrorNotice error={`Retest unavailable: ${project.error}`}/>}
    {confirmRetest && retestTarget && canRetest && <Panel title={`Confirm retest · current scope v${retestTarget.scope_version}`}><p className="panel-note">This is the target’s current registered scope, captured for this review. A concurrent scope change will reject launch. Only a successful header check can establish a fix.</p><ScopePreview scope={retestTarget.scope} url={retestTarget.url}/>{!retestReady && <p className="notice">{retestTarget.execution_blocker || "This target needs a current, explicit scope authorization in Projects before a retest can launch."}</p>}<label className="checkbox-label"><input type="checkbox" checked={retestApproved} onChange={event => setRetestApproved(event.target.checked)} disabled={!retestReady || busy || stale}/>I reviewed scope v{retestTarget.scope_version} and approve another safe assessment within this exact boundary.</label><div className="form-actions"><button className="secondary" onClick={() => { setConfirmRetest(false); setRetestApproved(false); setRetestTarget(undefined); }} disabled={busy}>Back</button><button className="secondary" onClick={() => void reviewRetest(true)} disabled={busy}>Reload current target</button><button className="primary" disabled={!retestApproved || !retestReady || busy || stale} onClick={retest}>{busy ? "Launching…" : "Launch retest"}<Icon name="arrow"/></button></div></Panel>}

    <div className="detail-layout"><div><Panel title="Check coverage"><div className="check-list">{data.checks?.length ? data.checks.map((check, index) => <div className="check-row" key={index}><div><strong>{check.name ?? check.category?.replaceAll("_", " ") ?? "Check"}</strong><p>{String(check.reason ?? check.message ?? check.detail ?? "No additional detail recorded.")}</p></div><Badge value={check.status}/></div>) : <p className="panel-note">The worker has not recorded checks yet.</p>}</div></Panel><Panel title="Findings in this assessment">{data.findings?.length ? <div className="finding-summary-list">{data.findings.map(finding => <details key={finding.id}><summary><Badge value={finding.severity}/><strong>{finding.title}</strong><Badge value={finding.status}/></summary><p>{finding.description}</p><dl className="facts"><div><dt>Confidence</dt><dd>{finding.confidence}</dd></div><div><dt>Remediation</dt><dd>{finding.remediation}</dd></div></dl><Json value={finding.evidence}/></details>)}</div> : <p className="panel-note">No findings recorded. Review check coverage before interpreting this as evidence of security.</p>}</Panel><Panel title="Sanitized observations">{data.observations?.length ? data.observations.map((observation, index) => <details className="observation" key={observation.id}><summary>Observation {index + 1} · {date(observation.observed_at)}</summary><p className="evidence-hash">SHA-256 {observation.evidence_hash}</p><Json value={observation.data}/></details>) : <p className="panel-note">No observations recorded.</p>}</Panel></div><div><Panel title="Assessment configuration"><dl className="facts vertical"><div><dt>Profile</dt><dd>{data.profile ?? "safe_http"}</dd></div><div><dt>Created</dt><dd>{date(data.created_at)}</dd></div><div><dt>Started</dt><dd>{date(data.started_at)}</dd></div><div><dt>Scope version</dt><dd>{data.scope_version ?? "—"}</dd></div><div><dt>Target reference</dt><dd className="mono">{data.target_id}</dd></div>{data.retest_of && <div><dt>Retest of</dt><dd><button className="link-button mono" onClick={() => openAssessment(data.retest_of!)}>{data.retest_of.slice(0, 12)}</button></dd></div>}</dl>{data.scope_snapshot && <details><summary>Immutable scope snapshot</summary><Json value={data.scope_snapshot}/></details>}</Panel><Panel title="Export report"><p className="panel-note">Reports include stored findings, evidence, failures and coverage limitations.</p>{running ? <p className="panel-note">Available when the assessment stops.</p> : <ReportLinks id={id}/>}</Panel><Panel title="Execution timeline">{data.events?.length ? <ol className="activity">{data.events.map((event, index) => <li key={event.id ?? index}><span className="activity-dot"/><div><strong>{event.action ?? event.message ?? event.event}</strong><p>{date(event.created_at ?? event.timestamp)}</p></div></li>)}</ol> : <p className="panel-note">Events will appear when recorded.</p>}</Panel></div></div>
  </>;
}
