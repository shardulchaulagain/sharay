"use client";

import { useState } from "react";
import { api, date, type Collection, type Finding, type User } from "./api";
import { Badge, Empty, ErrorNotice, Json, Loading, Panel, SectionHead, useResource, Pagination } from "./components";

const triageStatuses = ["needs_triage", "suspected", "inconclusive", "false_positive", "accepted_risk", "remediation_in_progress"];

export default function Findings({ user, revision, refresh, openAssessment }: { user: User; revision: number; refresh: () => void; openAssessment: (id: string) => void }) {
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const query = new URLSearchParams({ limit: "25", offset: String(offset), ...(severity && { severity }), ...(status && { status }) });
  const resource = useResource<Collection<Finding>>(`/findings?${query}`, revision);
  const items = resource.data?.items.filter(finding => `${finding.title} ${finding.affected_url} ${finding.category}`.toLowerCase().includes(search.toLowerCase())) ?? [];
  return <><SectionHead eyebrow="WORKSPACE / EVIDENCE" title="Findings">Severity describes the issue. Confidence describes the evidence. They remain separate.</SectionHead><div className="filters"><label>Search this page<input type="search" placeholder="Title, asset or category…" value={search} onChange={event => setSearch(event.target.value)}/></label><label>Severity<select value={severity} onChange={event => { setSeverity(event.target.value); setOffset(0); }}><option value="">All severities</option>{["critical", "high", "medium", "low", "info"].map(value => <option key={value} value={value}>{value === "info" ? "Informational" : value}</option>)}</select></label><label>Status<select value={status} onChange={event => { setStatus(event.target.value); setOffset(0); }}><option value="">All statuses</option>{["confirmed", "fixed", "reopened", ...triageStatuses].map(value => <option key={value} value={value}>{value.replaceAll("_", " ")}</option>)}</select></label></div>{resource.loading ? <Loading/> : resource.error ? <ErrorNotice error={resource.error}/> : <Panel title="Evidence-backed findings" action={<span className="muted">{resource.data?.total ?? 0} records</span>}>{items.length ? <div className="finding-list">{items.map(finding => <FindingItem key={finding.id} finding={finding} canEdit={user.role !== "viewer"} refresh={refresh} openAssessment={openAssessment}/>)}</div> : <Empty title={severity || status || search ? "No matching findings" : "No findings recorded"}>{severity || status || search ? "Adjust the filters or page search to see other records." : "After an assessment, verified observations and remediation status appear here. A clean list alone does not establish complete coverage."}</Empty>}<Pagination offset={offset} total={resource.data?.total ?? 0} limit={25} setOffset={setOffset}/></Panel>}</>;
}

function FindingItem({ finding, canEdit, refresh, openAssessment }: { finding: Finding; canEdit: boolean; refresh: () => void; openAssessment: (id: string) => void }) {
  const [error, setError] = useState<Error>();
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("");
  async function triage() {
    setBusy(true); setError(undefined);
    try { await api(`/findings/${encodeURIComponent(finding.id)}`, { method: "PATCH", body: JSON.stringify({ status }) }); refresh(); setStatus(""); }
    catch (error) { setError(error instanceof Error ? error : new Error("Triage failed.")); } finally { setBusy(false); }
  }
  return <details className="finding-item"><summary><Badge value={finding.severity}/><div><strong>{finding.title}</strong><small className="mono">{finding.affected_url ?? finding.affected_asset ?? finding.asset ?? finding.id}</small></div><span className="finding-confidence">Confidence <strong>{finding.confidence}</strong></span><Badge value={finding.status}/></summary><div className="finding-body"><p className="eyebrow">OBSERVED CONCLUSION</p><p>{finding.description}</p><dl className="facts"><div><dt>Finding reference</dt><dd className="mono">{finding.id}</dd></div><div><dt>Category</dt><dd>{finding.category?.replaceAll("_", " ") ?? "Unspecified"}</dd></div><div><dt>First / last seen</dt><dd>{date(finding.first_seen)} / {date(finding.last_seen)}</dd></div><div><dt>CVSS / business impact</dt><dd>Not scored / not assessed</dd></div></dl><p className="eyebrow">RECOMMENDED REMEDIATION</p><p>{finding.remediation}</p><p className="eyebrow">SANITIZED EVIDENCE</p>{finding.evidence?.length ? finding.evidence.map((evidence, index) => <div className="finding-evidence" key={String(evidence.id ?? index)}><div className="evidence-caption"><span>Evidence {index + 1}</span>{typeof evidence.assessment_id === "string" && <button className="link-button" onClick={() => openAssessment(evidence.assessment_id as string)}>Open assessment {evidence.assessment_id.slice(0, 8)} →</button>}</div><Json value={evidence}/></div>) : <p className="muted">No evidence was returned for this record.</p>}<details><summary>Status history</summary><Json value={finding.history ?? []}/></details>{canEdit && <div className="triage-form"><label>Triage status<select value={status} onChange={event => setStatus(event.target.value)}><option value="">Choose a status</option>{triageStatuses.map(value => <option key={value} value={value}>{value.replaceAll("_", " ")}</option>)}</select></label><button className="secondary" disabled={!status || busy} onClick={triage}>{busy ? "Saving…" : "Record triage"}</button><p>Confirmed and fixed states require scanner evidence. Retest from the linked assessment to verify remediation.</p></div>}<ErrorNotice error={error}/></div></details>;
}
