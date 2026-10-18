"use client";

/**
 * Draft C8 Desktop UI component for Controlled Vulnerability Verification,
 * Bounded Diagnostic Sessions, 3-State Impact Calibration, Cleanup Verification,
 * and Cryptographic SHARAY Report Provenance (`sharay.provenance.v1`).
 *
 * Prepared in `drafts/gemini/` for Codex (C8 owner) to drop into `apps/web/app/verification-panel.tsx`
 * and render inside `apps/web/app/assessments.tsx` and `apps/web/app/findings.tsx`.
 * Approved by human architect directive (signature: shardul).
 */

import { useState } from "react";
import { post, readable, type Finding, type User } from "./api";
import { Badge, ErrorNotice, Json, Loading, Panel, useResource } from "./components";

export type ValidationStatus =
  | "suspected"
  | "confirmed_reproducible"
  | "validation_failed"
  | "blocked_by_scope";

export type BugBountySubmissionView = {
  finding_id: string;
  title: string;
  category: string;
  status: string;
  severity: string;
  confidence: string;
  affected_asset: string;
  root_cause: string;
  access_session_summary: {
    sessions_established: number;
    total_duration_seconds: number;
    sessions: Array<{
      session_id: string;
      session_kind: string;
      state: string;
      established_at?: string;
      terminated_at?: string;
      duration_seconds: number;
      privilege_context: Record<string, unknown>;
      action_count: number;
    }>;
  };
  impact_breakdown: {
    observed: Array<{ dimension: string; state: string; summary: string }>;
    theoretical: Array<{ dimension: string; state: string; summary: string }>;
    not_yet_tested: Array<{ dimension: string; state: string; summary: string }>;
  };
  remediation: string;
};

export type AssessmentReconstructionResponse = {
  assessment_id: string;
  reconstruction: {
    assessment_id: string;
    scope_version: number;
    total_sessions_established: number;
    total_session_duration_seconds: number;
    cleanup_status: "verified_clean" | "pending_cleanup" | "no_artifacts_recorded";
    cleanup_records: Array<{
      artifact_id: string;
      session_id: string;
      artifact_kind: string;
      location: string;
      status: string;
      verified_at?: string;
    }>;
    bug_bounty_submissions: BugBountySubmissionView[];
  };
  sharay_provenance: {
    schema: string;
    generator: string;
    assessment_id: string;
    scope_version: number;
    generated_at: string;
    manifest_sha256: string;
    signature_mode: string;
    section_digests: Record<string, string>;
  };
};

const VULN_CLASSES = [
  "sql_injection",
  "xss",
  "ssrf",
  "xxe",
  "command_injection",
  "auth_bypass",
  "access_control",
  "server_side",
  "client_side",
  "api_vulnerability",
] as const;

export function VerificationSessionPanel({
  assessmentId,
  findings,
  user,
  revision,
  refresh,
}: {
  assessmentId: string;
  findings: Finding[];
  user: User;
  revision: number;
  refresh: () => void;
}) {
  const canEdit = user.role !== "viewer";
  const recon = useResource<AssessmentReconstructionResponse>(
    `/assessments/${encodeURIComponent(assessmentId)}/reconstruction`,
    revision,
  );

  const [findingId, setFindingId] = useState(findings[0]?.id ?? "");
  const [vulnClass, setVulnClass] = useState<string>("sql_injection");
  const [techniqueId, setTechniqueId] = useState("sqli.boolean_differential_pair");
  const [valStatus, setValStatus] = useState<ValidationStatus>("confirmed_reproducible");
  const [rootCause, setRootCause] = useState("");
  const [observedImpact, setObservedImpact] = useState("");
  const [theoreticalImpact, setTheoreticalImpact] = useState("");
  const [notYetTested, setNotYetTested] = useState("");
  const [calibratedSeverity, setCalibratedSeverity] = useState("high");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error>();

  async function recordValidationAndCalibration() {
    if (!findingId) return;
    setBusy(true);
    setError(undefined);
    try {
      const valRun = await post<{ id: string }>(
        `/assessments/${encodeURIComponent(assessmentId)}/validations`,
        {
          assessment_id: assessmentId,
          finding_id: findingId,
          technique_id: techniqueId.trim(),
          vuln_class: vulnClass,
          status: valStatus,
          root_cause: rootCause.trim(),
          observed_impact_summary: observedImpact.trim(),
          approved_by: user.username || "shardul",
        },
      );
      if (observedImpact.trim() && theoreticalImpact.trim()) {
        await post(`/findings/${encodeURIComponent(findingId)}/impact-calibrations`, {
          finding_id: findingId,
          validation_run_id: valRun.id,
          theoretical_impact: theoreticalImpact.trim(),
          observed_impact: observedImpact.trim(),
          not_yet_tested: notYetTested
            .split(/\r?\n/)
            .map((line) => line.trim())
            .filter(Boolean),
          calibrated_severity: calibratedSeverity,
          rationale: rootCause.trim(),
        });
      }
      refresh();
    } catch (err) {
      setError(err instanceof Error ? err : new Error("Validation recording failed."));
    } finally {
      setBusy(false);
    }
  }

  if (recon.loading) return <Loading />;
  if (recon.error) return <ErrorNotice error={recon.error} />;

  const data = recon.data;
  if (!data) return null;

  return (
    <Panel
      title="Verification, diagnostic sessions & SHARAY provenance"
      action={<Badge value={data.reconstruction.cleanup_status} />}
    >
      <dl className="facts">
        <div>
          <dt>Provenance schema</dt>
          <dd className="mono">{data.sharay_provenance.schema}</dd>
        </div>
        <div>
          <dt>Manifest SHA-256</dt>
          <dd className="mono">{data.sharay_provenance.manifest_sha256.slice(0, 24)}…</dd>
        </div>
        <div>
          <dt>Diagnostic sessions</dt>
          <dd>{data.reconstruction.total_sessions_established}</dd>
        </div>
        <div>
          <dt>Total session duration</dt>
          <dd>{data.reconstruction.total_session_duration_seconds}s</dd>
        </div>
      </dl>

      {data.reconstruction.bug_bounty_submissions.map((sub) => (
        <details className="finding-item" key={sub.finding_id}>
          <summary>
            <Badge value={sub.severity} />
            <div>
              <strong>{sub.title}</strong>
              <small className="mono">{sub.affected_asset}</small>
            </div>
            <span className="finding-confidence">
              Session time <strong>{sub.access_session_summary.total_duration_seconds}s</strong>
            </span>
            <Badge value={sub.status} />
          </summary>
          <div className="finding-body">
            <p className="eyebrow">ROOT CAUSE</p>
            <p>{sub.root_cause}</p>
            <p className="eyebrow">3-STATE IMPACT CALIBRATION</p>
            <Json value={sub.impact_breakdown} />
            <p className="eyebrow">SESSION & BOUNDARY LOG</p>
            <Json value={sub.access_session_summary} />
          </div>
        </details>
      ))}

      {canEdit && findings.length > 0 && (
        <div className="triage-form">
          <p className="eyebrow">RECORD AUTHORIZED VALIDATION & 3-STATE IMPACT</p>
          <label>
            Finding
            <select value={findingId} onChange={(e) => setFindingId(e.target.value)}>
              {findings.map((f) => (
                <option key={f.id} value={f.id}>
                  {f.title} ({f.id.slice(0, 8)})
                </option>
              ))}
            </select>
          </label>
          <label>
            Vulnerability class
            <select value={vulnClass} onChange={(e) => setVulnClass(e.target.value)}>
              {VULN_CLASSES.map((c) => (
                <option key={c} value={c}>
                  {readable(c)}
                </option>
              ))}
            </select>
          </label>
          <label>
            Validation technique ID
            <input
              type="text"
              value={techniqueId}
              onChange={(e) => setTechniqueId(e.target.value)}
            />
          </label>
          <label>
            Validation outcome
            <select
              value={valStatus}
              onChange={(e) => setValStatus(e.target.value as ValidationStatus)}
            >
              <option value="confirmed_reproducible">Confirmed reproducible</option>
              <option value="suspected">Suspected</option>
              <option value="validation_failed">Validation failed</option>
            </select>
          </label>
          <label>
            Root cause
            <input
              type="text"
              placeholder="Underlying code or configuration cause…"
              value={rootCause}
              onChange={(e) => setRootCause(e.target.value)}
            />
          </label>
          <label>
            Observed impact (demonstrated within scope)
            <input
              type="text"
              placeholder="What the verified access actually permitted…"
              value={observedImpact}
              onChange={(e) => setObservedImpact(e.target.value)}
            />
          </label>
          <label>
            Theoretical impact ceiling
            <input
              type="text"
              placeholder="Worst-case theoretical impact if controls were absent…"
              value={theoreticalImpact}
              onChange={(e) => setTheoreticalImpact(e.target.value)}
            />
          </label>
          <label>
            Not yet tested vectors (one per line)
            <textarea
              rows={2}
              value={notYetTested}
              onChange={(e) => setNotYetTested(e.target.value)}
            />
          </label>
          <label>
            Calibrated severity
            <select
              value={calibratedSeverity}
              onChange={(e) => setCalibratedSeverity(e.target.value)}
            >
              {["critical", "high", "medium", "low", "info"].map((sev) => (
                <option key={sev} value={sev}>
                  {sev}
                </option>
              ))}
            </select>
          </label>
          <button
            className="secondary"
            disabled={busy || !findingId || !techniqueId.trim()}
            onClick={recordValidationAndCalibration}
          >
            {busy ? "Recording…" : "Record validation & calibrate impact"}
          </button>
          <ErrorNotice error={error} />
        </div>
      )}
    </Panel>
  );
}
