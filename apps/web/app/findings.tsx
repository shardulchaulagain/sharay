"use client";

import { useState } from "react";
import { api, date, type Collection, type Finding, type Scope, type Target, type User } from "./api";
import { Badge, Empty, ErrorNotice, Icon, Json, Loading, Panel, SectionHead, useResource, Pagination } from "./components";
import OperatorTerminal from "./terminal";

const triageStatuses = ["needs_triage", "suspected", "inconclusive", "false_positive", "accepted_risk", "remediation_in_progress"];

const FALLBACK_SCOPE: Scope = {
  hosts: [], allowed_origins: [], allowed_paths: ["/"], excluded_paths: [], allowed_cidrs: [], categories: ["http_headers"],
  authenticated: false, credential_refs: [], request_rate: 10, max_concurrency: 1,
  starts_at: "2026-01-01T00:00:00Z", expires_at: "2028-01-01T00:00:00Z",
  intrusive: false, approval_required: false, emergency_stop_conditions: []
};

export type ReplicationStep = {
  number: number;
  title: string;
  description: string;
  command?: string;
};

export type FindingReplicationGuide = {
  title: string;
  category: string;
  summary: string;
  verificationOracle: string;
  consoleCommand: string;
  steps: ReplicationStep[];
};

function getHost(url?: string): string {
  if (!url) return "target.host";
  try {
    const parsed = new URL(url.includes("://") ? url : "https://" + url);
    return parsed.hostname || "target.host";
  } catch {
    return url.replace(/^[a-z]+:\/\//, "").split("/")[0].split(":")[0] || "target.host";
  }
}

export function getFindingReplicationGuide(finding: Finding): FindingReplicationGuide {
  const asset = finding.affected_url || finding.affected_asset || finding.asset || "http://127.0.0.1:8765";
  const host = getHost(asset);
  const category = (finding.category || "").toLowerCase();
  const title = (finding.title || "").toLowerCase();
  const evidenceObj = Array.isArray(finding.evidence) && finding.evidence.length > 0
    ? (finding.evidence[0] as Record<string, unknown>).data as Record<string, unknown> | undefined
    : undefined;
  const pocObj = (typeof finding.poc === "object" && finding.poc !== null ? finding.poc as Record<string, unknown> : undefined) || (evidenceObj?.poc as Record<string, unknown> | undefined);
  const param = String(pocObj?.parameter || "id");
  const cleanUrl = asset.split("?")[0];
  const queryJoin = cleanUrl.includes("?") ? "&" : "?";

  if (category.includes("sql") || title.includes("sql") || title.includes("sqli")) {
    const trueProbe = `${cleanUrl}${queryJoin}${param}=1%27%20OR%20%271%27%3D%271`;
    const falseProbe = `${cleanUrl}${queryJoin}${param}=1%27%20AND%20%271%27%3D%272`;
    return {
      title: "SQL Injection (CWE-89) Replication Protocol",
      category: "Differential SQLi Oracle",
      summary: "Systematically test parameter input handling using boolean differential pairs. Do NOT rely on naive error string matching; verify differential response divergence or database syntax errors.",
      consoleCommand: `http GET ${trueProbe}`,
      verificationOracle: "Differential Response Oracle: Jaccard similarity distance J < 0.88 between boolean true vs false conditions, or verified database syntax error signatures.",
      steps: [
        {
          number: 1,
          title: "Baseline Context",
          description: "Send baseline request to record normal HTTP status, content length, and response body structure without injected metacharacters.",
          command: `http GET ${cleanUrl}`,
        },
        {
          number: 2,
          title: "Boolean Tautology (True Condition)",
          description: "Inject boolean true condition ' OR '1'='1. Verify that application evaluates expression as true and returns content consistent with baseline (Jaccard similarity J > 0.90).",
          command: `http GET ${trueProbe}`,
        },
        {
          number: 3,
          title: "Boolean Contradiction (False Condition)",
          description: "Inject boolean false condition ' AND '1'='2. Verify that database condition evaluation alters result set, returns differential content (Jaccard distance J < 0.88), or triggers database syntax exception.",
          command: `http GET ${falseProbe}`,
        },
        {
          number: 4,
          title: "Automated Negative-Control Retest",
          description: "Dispatch 3x automated reproducer with randomized negative-control canary parameters to eliminate environmental noise.",
          command: `retest ${finding.id}`,
        },
      ],
    };
  }

  if (category.includes("xss") || title.includes("xss") || category.includes("cross_site_scripting")) {
    const xssProbe = `${cleanUrl}${queryJoin}${param}=%22%3E%3Cscript%3Ealert(%27SHARAY%27)%3C%2Fscript%3E`;
    return {
      title: "Cross-Site Scripting (CWE-79) Replication Protocol",
      category: "Reflected Canary Oracle",
      summary: "Verify whether untrusted user input is reflected into the HTML response document without contextual HTML entity encoding and without restrictive Content-Security-Policy protection.",
      consoleCommand: `http GET ${xssProbe}`,
      verificationOracle: "Reflected Canary Oracle: Injected payload reflected verbatim in HTML context without contextual entity encoding and without restrictive Content-Security-Policy.",
      steps: [
        {
          number: 1,
          title: "Header & Policy Audit",
          description: "Probe the endpoint to verify Content-Type (must be text/html) and evaluate existing Content-Security-Policy directives (e.g. script-src).",
          command: `probe ${asset}`,
        },
        {
          number: 2,
          title: "Non-Destructive Canary Reflection",
          description: "Inject harmless canary probe \"><script>alert('SHARAY')</script>. Inspect response body preview to verify if characters ', \", <, and > are reflected unencoded.",
          command: `http GET ${xssProbe}`,
        },
        {
          number: 3,
          title: "DOM & Execution Verification",
          description: "Confirm that reflection occurs within an executable HTML context (not inside raw json, script comment, or safe attribute) without effective CSP mitigation.",
          command: `playbook ${finding.id}`,
        },
        {
          number: 4,
          title: "Automated Headless Browser Retest",
          description: "Queue automated browser evaluation to execute canary payload in isolated DOM sandbox.",
          command: `retest ${finding.id}`,
        },
      ],
    };
  }

  if (category.includes("ssrf") || title.includes("ssrf") || category.includes("request_forgery")) {
    const loopbackProbe = `${cleanUrl}${queryJoin}url=http%3A%2F%2F127.0.0.1%3A80`;
    return {
      title: "Server-Side Request Forgery (CWE-918) Replication Protocol",
      category: "Differential Socket & Callback Oracle",
      summary: "Eliminate false positives from naive server banner matches. Real SSRF requires verified differential responses, loopback socket errors, or out-of-band interaction telemetry.",
      consoleCommand: `http GET ${loopbackProbe}`,
      verificationOracle: "Out-of-Band & Differential Socket Oracle: Verified loopback socket error (ECONNREFUSED) or recorded DNS/HTTP callback telemetry at out-of-band canary.",
      steps: [
        {
          number: 1,
          title: "Baseline Remote Fetch",
          description: "Provide a valid, accessible external URL parameter to observe normal server-mediated fetch behavior and response format.",
          command: `http GET ${asset}`,
        },
        {
          number: 2,
          title: "Loopback Socket Canary",
          description: "Supply loopback destination http://127.0.0.1:80 or http://169.254.169.254. Check for differential loopback socket error (ECONNREFUSED) or internal service metadata.",
          command: `http GET ${loopbackProbe}`,
        },
        {
          number: 3,
          title: "Out-of-Band Telemetry Audit",
          description: "Confirm that asynchronous requests trigger logged interactions at out-of-band canary listeners.",
          command: `playbook ${finding.id}`,
        },
        {
          number: 4,
          title: "Automated Retest",
          description: "Run automated reproducer with negative-control canaries to verify callback integrity.",
          command: `retest ${finding.id}`,
        },
      ],
    };
  }

  if (category.includes("command") || title.includes("command") || title.includes("rce") || category.includes("rce") || category.includes("execution")) {
    const rceProbe = `${cleanUrl}${queryJoin}${param}=1|echo%20SHARAY_CANARY`;
    return {
      title: "OS Command Injection / RCE (CWE-78) Safety Protocol",
      category: "Execution Evidence Oracle",
      summary: "CRITICAL: Potential Remote Code Execution. Adhere strictly to safe testing protocols: never execute destructive commands. Use isolated echo tokens or dispatch sandboxed AutoPyVerifier.",
      consoleCommand: `http GET ${rceProbe}`,
      verificationOracle: "Execution Evidence Oracle: Measured delay exceeding threshold or exact match of non-destructive canary execution token.",
      steps: [
        {
          number: 1,
          title: "Baseline Context",
          description: "Record baseline latency, response headers, and normal parameter behavior.",
          command: `probe ${asset}`,
        },
        {
          number: 2,
          title: "Isolated Echo Canary",
          description: "Inject non-destructive echo canary token 1|echo SHARAY_CANARY to verify command separation without modifying system state.",
          command: `http GET ${rceProbe}`,
        },
        {
          number: 3,
          title: "Forensic Containment Playbook",
          description: "Review containment and sandboxing requirements before performing manual shell verification.",
          command: `playbook ${finding.id}`,
        },
        {
          number: 4,
          title: "AutoPyVerifier Hermetic Dispatch",
          description: "Queue sandboxed AutoPyVerifier to synthesize and run hermetic verification script.",
          command: `retest ${finding.id}`,
        },
      ],
    };
  }

  if (category.includes("ssti") || title.includes("ssti") || title.includes("template")) {
    const sstiProbe = `${cleanUrl}${queryJoin}${param}=%7B%7B7*7%7D%7D`;
    return {
      title: "Server-Side Template Injection (CWE-1336) Protocol",
      category: "Mathematical Evaluation Oracle",
      summary: "Distinguish between literal string reflection and server-side template engine expression evaluation.",
      consoleCommand: `http GET ${sstiProbe}`,
      verificationOracle: "Mathematical Evaluation Oracle: Rendered response reflects evaluated arithmetic (49) confirming server-side template interpreter execution.",
      steps: [
        {
          number: 1,
          title: "Baseline Benign Text",
          description: "Send alphanumeric test string to verify normal reflection without template markers.",
          command: `http GET ${cleanUrl}`,
        },
        {
          number: 2,
          title: "Arithmetic Expression Canary",
          description: "Inject template arithmetic expression {{7*7}} or ${7*7} into parameter.",
          command: `http GET ${sstiProbe}`,
        },
        {
          number: 3,
          title: "Evaluation Verification",
          description: "Confirm vulnerability if response renders evaluated mathematical product '49' rather than literal '{{7*7}}'.",
          command: `playbook ${finding.id}`,
        },
        {
          number: 4,
          title: "Automated Retest",
          description: "Dispatch automated assessment to confirm template sandbox boundaries.",
          command: `retest ${finding.id}`,
        },
      ],
    };
  }

  if (category.includes("dns") || title.includes("dmarc") || title.includes("spf") || category.includes("email_spoofing")) {
    const dmarcHost = `_dmarc.${host.replace(/^_dmarc\./, "")}`;
    return {
      title: "Email Spoofing & DNS Authentication (CWE-345) Posture",
      category: "DNS Resource Record Oracle",
      summary: "Verify authoritative DNS policy records to assess protection against domain spoofing in accordance with RFC 7489 and RFC 7208.",
      consoleCommand: `dns ${dmarcHost} TXT`,
      verificationOracle: "DNS Resource Record Oracle: Authoritative TXT lookup reveals absent record or permissive policy (p=none) failing spoof rejection criteria.",
      steps: [
        {
          number: 1,
          title: "DMARC Policy Query",
          description: `Inspect DMARC TXT record for ${dmarcHost} using authoritative DNS lookup.`,
          command: `dns ${dmarcHost} TXT`,
        },
        {
          number: 2,
          title: "SPF Sender Envelope Query",
          description: `Inspect SPF TXT record for ${host} to identify authorized sending mechanisms.`,
          command: `dns ${host} TXT`,
        },
        {
          number: 3,
          title: "Anti-Spoofing Policy Audit",
          description: "Verify if policy enforces reject or quarantine. Flag if record is absent or permissive (p=none).",
          command: `playbook ${finding.id}`,
        },
        {
          number: 4,
          title: "Remediation Verification",
          description: "Re-query DNS records after publishing recommended defensive TXT records.",
          command: `retest ${finding.id}`,
        },
      ],
    };
  }

  if (category.includes("tls") || title.includes("tls") || title.includes("certificate") || title.includes("ssl")) {
    return {
      title: "TLS & Cryptographic Transport (CWE-310) Posture",
      category: "TLS Protocol & Trust Chain Oracle",
      summary: "Verify transport layer security configuration, negotiated ciphers, and certificate validity.",
      consoleCommand: `ssl ${host}`,
      verificationOracle: "TLS Protocol & Trust Chain Oracle: Negotiated protocol version < TLS 1.2, non-AEAD cipher suite, or certificate validity failure.",
      steps: [
        {
          number: 1,
          title: "Live TLS Handshake",
          description: `Initiate scoped TLS handshake to negotiate protocol version and cipher suite for ${host}.`,
          command: `ssl ${host}`,
        },
        {
          number: 2,
          title: "Certificate Validity Inspection",
          description: "Inspect certificate expiration date, issuer chain, and Subject Alternative Names (SAN).",
          command: `playbook ${finding.id}`,
        },
        {
          number: 3,
          title: "Forward Secrecy Verification",
          description: "Verify enforcement of modern TLS 1.2+ protocols with Ephemeral Diffie-Hellman and AEAD ciphers.",
          command: `retest ${finding.id}`,
        },
      ],
    };
  }

  const isPosture = category.includes("header") || category.includes("configuration") || category.includes("banner") || title.includes("header") || title.includes("csp") || title.includes("hsts");
  if (isPosture) {
    return {
      title: "HTTP Security Header & Configuration Posture",
      category: "Response Header Oracle",
      summary: "Evaluate defensive HTTP response headers following all approved redirect chains to the landing endpoint.",
      consoleCommand: `probe ${asset}`,
      verificationOracle: "Header & Configuration Oracle: Evaluated landing response headers lack defensive directives or expose server version metadata.",
      steps: [
        {
          number: 1,
          title: "Response Header Probe",
          description: "Follow HTTP redirects to landing endpoint and capture complete response headers.",
          command: `probe ${asset}`,
        },
        {
          number: 2,
          title: "Defensive Directives Audit",
          description: "Verify presence of HSTS, CSP, X-Content-Type-Options: nosniff, and frame protection.",
          command: `playbook ${finding.id}`,
        },
        {
          number: 3,
          title: "Remediation Verification",
          description: "Re-probe endpoint after updating web server / reverse proxy configuration.",
          command: `retest ${finding.id}`,
        },
      ],
    };
  }

  return {
    title: `${finding.title} Replication Protocol`,
    category: "Forensic Differential Oracle",
    summary: finding.description || "Verify the observed security condition using scoped diagnostic commands.",
    consoleCommand: `probe ${asset}`,
    verificationOracle: "Forensic Differential Oracle: Observed behavior diverges from baseline specification according to recorded execution evidence.",
    steps: [
      {
        number: 1,
        title: "Target Reachability",
        description: "Run probe to establish baseline HTTP response headers and latency.",
        command: `probe ${asset}`,
      },
      {
        number: 2,
        title: "Diagnostic Inspection",
        description: "Execute in-scope HTTP request matching observed vulnerability condition.",
        command: `http GET ${asset}`,
      },
      {
        number: 3,
        title: "Forensic Playbook Review",
        description: "Print full verification playbook and oracle criteria in the terminal.",
        command: `playbook ${finding.id}`,
      },
      {
        number: 4,
        title: "Automated Retest",
        description: "Queue automated assessment retest to verify status.",
        command: `retest ${finding.id}`,
      },
    ],
  };
}

export default function Findings({ user, revision, refresh, openAssessment }: { user: User; revision: number; refresh: () => void; openAssessment: (id: string) => void }) {
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const [consoleFinding, setConsoleFinding] = useState<Finding>();
  const [consoleTarget, setConsoleTarget] = useState<Target>();
  const [consoleCommand, setConsoleCommand] = useState<string>();

  const query = new URLSearchParams({ limit: "25", offset: String(offset), ...(severity && { severity }), ...(status && { status }) });
  const resource = useResource<Collection<Finding>>(`/findings?${query}`, revision);
  const items = resource.data?.items.filter(finding => `${finding.title} ${finding.affected_url} ${finding.category}`.toLowerCase().includes(search.toLowerCase())) ?? [];

  async function openFindingConsole(item: Finding, initialCmd?: string) {
    setConsoleFinding(item);
    setConsoleCommand(initialCmd);
    try {
      if (item.target_id) {
        const tgt = await api<Target>(`/targets/${encodeURIComponent(item.target_id)}`);
        setConsoleTarget(tgt);
      } else {
        setConsoleTarget({
          id: item.id,
          project_id: item.project_id || "",
          url: item.affected_url || "http://127.0.0.1:8765",
          scope: FALLBACK_SCOPE,
          scope_version: 1,
          verification_status: "operator_authorized",
        });
      }
    } catch {
      setConsoleTarget({
        id: item.target_id || item.id,
        project_id: item.project_id || "",
        url: item.affected_url || "http://127.0.0.1:8765",
        scope: FALLBACK_SCOPE,
        scope_version: 1,
        verification_status: "operator_authorized",
      });
    }
  }

  return <>
    <SectionHead eyebrow="WORKSPACE / EVIDENCE" title="Findings">Severity describes the issue. Confidence describes the evidence. Every detected vulnerability can be manually rechecked and confirmed in an isolated operator console with live AI recommendations.</SectionHead>
    <div className="filters">
      <label>Search this page<input type="search" placeholder="Title, asset or category…" value={search} onChange={event => setSearch(event.target.value)}/></label>
      <label>Severity<select value={severity} onChange={event => { setSeverity(event.target.value); setOffset(0); }}><option value="">All severities</option>{["critical", "high", "medium", "low", "info"].map(value => <option key={value} value={value}>{value === "info" ? "Informational" : value}</option>)}</select></label>
      <label>Status<select value={status} onChange={event => { setStatus(event.target.value); setOffset(0); }}><option value="">All statuses</option>{["confirmed", "demoted", "fixed", "reopened", ...triageStatuses].map(value => <option key={value} value={value}>{value.replaceAll("_", " ")}</option>)}</select></label>
    </div>
    {resource.loading ? <Loading/> : resource.error ? <ErrorNotice error={resource.error}/> : <Panel title="Evidence-backed findings" action={<span className="muted">{resource.data?.total ?? 0} records</span>}>
      {items.length ? (
        <div className="finding-list">
          {items.map(finding => (
            <FindingItem
              key={finding.id}
              finding={finding}
              canEdit={user.role !== "viewer"}
              refresh={refresh}
              openAssessment={openAssessment}
              onOpenConsole={(cmd) => void openFindingConsole(finding, cmd)}
            />
          ))}
        </div>
      ) : (
        <Empty title={severity || status || search ? "No matching findings" : "No findings recorded"}>
          {severity || status || search ? "Adjust the filters or page search to see other records." : "After an assessment, verified observations and remediation status appear here. A clean list alone does not establish complete coverage."}
        </Empty>
      )}
      <Pagination offset={offset} total={resource.data?.total ?? 0} limit={25} setOffset={setOffset}/>
    </Panel>}

    {consoleFinding && consoleTarget && (
      <OperatorTerminal
        target={consoleTarget}
        finding={consoleFinding}
        initialCommand={consoleCommand}
        onClose={() => { setConsoleFinding(undefined); setConsoleTarget(undefined); setConsoleCommand(undefined); }}
        onFindingUpdated={refresh}
      />
    )}
  </>;
}

function FindingItem({ finding, canEdit, refresh, openAssessment, onOpenConsole }: {
  finding: Finding; canEdit: boolean; refresh: () => void; openAssessment: (id: string) => void; onOpenConsole: (cmd?: string) => void;
}) {
  const [error, setError] = useState<Error>();
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("");
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

  const guide = getFindingReplicationGuide(finding);

  function copyToClipboard(text: string) {
    if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
      void navigator.clipboard.writeText(text);
      setCopiedCmd(text);
      setTimeout(() => setCopiedCmd(null), 2000);
    }
  }

  async function triage() {
    setBusy(true); setError(undefined);
    try { await api(`/findings/${encodeURIComponent(finding.id)}`, { method: "PATCH", body: JSON.stringify({ status }) }); refresh(); setStatus(""); }
    catch (error) { setError(error instanceof Error ? error : new Error("Triage failed.")); } finally { setBusy(false); }
  }

  return <details className="finding-item">
    <summary>
      <Badge value={finding.severity}/>
      <div>
        <strong>{finding.title}</strong>
        <small className="mono">{finding.affected_url ?? finding.affected_asset ?? finding.asset ?? finding.id}</small>
      </div>
      <button type="button" className="secondary compact console-trigger-pill" onClick={(e) => { e.preventDefault(); e.stopPropagation(); onOpenConsole(guide.consoleCommand); }}>
        <Icon name="terminal" size={12} />
        <span>Recheck in Console</span>
      </button>
      <span className="finding-confidence">Confidence <strong>{finding.confidence}</strong></span>
      <Badge value={finding.status}/>
    </summary>
    <div className="finding-body">
      <div className="finding-action-bar">
        <button type="button" className="primary compact console-action-btn" onClick={() => onOpenConsole(`poc ${finding.id}`)}>
          <Icon name="terminal" size={13} />
          <strong>Replay Research-Grade PoC</strong>
        </button>
        <button type="button" className="secondary compact" onClick={() => onOpenConsole(`exploit ${finding.id}`)}>
          <Icon name="terminal" size={12} />
          <span>Metasploit Exploit Check</span>
        </button>
        <button type="button" className="secondary compact" onClick={() => onOpenConsole(guide.consoleCommand)}>
          <Icon name="terminal" size={12} />
          <span>Run Diagnostic</span>
        </button>
        <button type="button" className="secondary compact" onClick={() => onOpenConsole(`retest ${finding.id}`)}>
          <Icon name="terminal" size={12} />
          <span>Retest Finding</span>
        </button>
        <span className="action-hint">Replay PoC with live oracle verification, test Metasploit modules, or execute differential probes.</span>
      </div>

      <div className="finding-playbook-card">
        <div className="playbook-top-bar">
          <div className="playbook-title-group">
            <Icon name="terminal" size={14} />
            <strong className="playbook-card-title">{guide.title}</strong>
            <span className="playbook-badge">{guide.category}</span>
          </div>
          <div className="playbook-header-actions">
            <button
              type="button"
              className="secondary compact copy-action-btn"
              onClick={() => copyToClipboard(guide.consoleCommand)}
              title="Copy primary console diagnostic command"
            >
              <Icon name="copy" size={12} />
              <span>{copiedCmd === guide.consoleCommand ? "Copied!" : "Copy Command"}</span>
            </button>
            <button
              type="button"
              className="primary compact"
              onClick={() => onOpenConsole(guide.consoleCommand)}
              title="Open console and execute primary diagnostic"
            >
              <Icon name="terminal" size={12} />
              <span>Run Diagnostic</span>
            </button>
          </div>
        </div>

        <p className="playbook-summary">{guide.summary}</p>

        <div className="playbook-protocol">
          <div className="protocol-label">STEP-BY-STEP REPLICATION &amp; VERIFICATION PROTOCOL:</div>
          <ol className="playbook-steps">
            {guide.steps.map((step) => (
              <li key={step.number} className="playbook-step-item">
                <div className="step-num-badge">Step {step.number}</div>
                <div className="step-content">
                  <div className="step-title-row">
                    <strong>{step.title}</strong>
                    {step.command && (
                      <div className="step-btn-group">
                        <button
                          type="button"
                          className="step-exec-link"
                          onClick={() => onOpenConsole(step.command)}
                          title={`Run '${step.command}' in Console`}
                        >
                          <Icon name="terminal" size={11} />
                          <span>Run in Console</span>
                        </button>
                        <button
                          type="button"
                          className="step-copy-link"
                          onClick={() => copyToClipboard(step.command!)}
                          title="Copy command"
                        >
                          <Icon name="copy" size={11} />
                          <span>{copiedCmd === step.command ? "Copied" : "Copy"}</span>
                        </button>
                      </div>
                    )}
                  </div>
                  <p className="step-desc">{step.description}</p>
                  {step.command && (
                    <div className="step-cmd-line">
                      <code>{step.command}</code>
                    </div>
                  )}
                </div>
              </li>
            ))}
          </ol>
        </div>

        <div className="playbook-oracle-block">
          <div className="oracle-title">
            <Icon name="check" size={13} />
            <strong>VERIFICATION ORACLE (Scientific Proof Criteria)</strong>
          </div>
          <p className="oracle-text">{guide.verificationOracle}</p>
          <div className="oracle-rule">
            <strong>SHARAY Verification Gate:</strong> If canary probes fail differential confirmation, the finding must be demoted in triage. Never confirm without verified evidence.
          </div>
        </div>
      </div>

      <p className="eyebrow">OBSERVED CONCLUSION</p>
      <p>{finding.description}</p>
      <dl className="facts">
        <div><dt>Finding reference</dt><dd className="mono">{finding.id}</dd></div>
        <div><dt>Category</dt><dd>{finding.category?.replaceAll("_", " ") ?? "Unspecified"}</dd></div>
        <div><dt>First / last seen</dt><dd>{date(finding.first_seen)} / {date(finding.last_seen)}</dd></div>
        <div><dt>CVSS / business impact</dt><dd>Not scored / not assessed</dd></div>
      </dl>
      <p className="eyebrow">RECOMMENDED REMEDIATION</p>
      <p>{finding.remediation}</p>
      <p className="eyebrow">SANITIZED EVIDENCE</p>
      {finding.evidence?.length ? finding.evidence.map((evidence, index) => (
        <div className="finding-evidence" key={String(evidence.id ?? index)}>
          <div className="evidence-caption">
            <span>Evidence {index + 1}</span>
            {typeof evidence.assessment_id === "string" && (
              <button className="link-button" onClick={() => openAssessment(evidence.assessment_id as string)}>Open assessment {evidence.assessment_id.slice(0, 8)} →</button>
            )}
          </div>
          <Json value={evidence}/>
        </div>
      )) : <p className="muted">No evidence was returned for this record.</p>}
      <details><summary>Status history</summary><Json value={finding.history ?? []}/></details>
      {canEdit && <div className="triage-form">
        <label>Triage status<select value={status} onChange={event => setStatus(event.target.value)}><option value="">Choose a status</option>{triageStatuses.map(value => <option key={value} value={value}>{value.replaceAll("_", " ")}</option>)}</select></label>
        <button className="secondary" disabled={!status || busy} onClick={triage}>{busy ? "Saving…" : "Record triage"}</button>
        <p>Confirmed and fixed states require scanner evidence. Retest from the linked assessment or launch the Operator Console to verify remediation.</p>
      </div>}
      <ErrorNotice error={error}/>
    </div>
  </details>;
}
