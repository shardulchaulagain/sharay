"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api, post, type Target, type Finding } from "./api";
import { Badge, Icon } from "./components";
import { terminalText } from "./terminal-output";

type Ownership = "HUMAN_OWNED" | "AGENT_OWNED" | "SHARED";
export type InteractiveSessionMeta = {
  id: string; target_id: string; target_url: string; target_ip: string;
  state: "active" | "terminated"; ownership_state?: Ownership; pid?: number;
};

const COMMAND_HELP = [
  {
    cmd: "poc <id>",
    syntax: "poc",
    summary: "Replays the exact Research-Grade PoC with live oracle verification, captures response headers and differential delta, and generates a forensic visual evidence snapshot.",
    purpose: "Replicate and verify vulnerability existence using OWASP WSTG and HackerOne scientific proof standards.",
  },
  {
    cmd: "msf <module> [check|run] [KEY=VAL ...]",
    syntax: "msf",
    summary: "Executes Metasploit auxiliary and exploit modules (in non-destructive check mode or live verification) via isolated container runner against the pinned target.",
    purpose: "Perform authoritative offensive checks and exploit verifications without leaving the console.",
  },
  {
    cmd: "exploit <id>",
    syntax: "exploit",
    summary: "Dispatches targeted exploit verification against the finding's vulnerable component using mapped Metasploit modules or synthesized AutoPyVerifier checks.",
    purpose: "Prove exploitability and establish failed security boundary.",
  },
  {
    cmd: "http [METHOD] <url> [-d data] [-H header]",
    syntax: "http",
    summary: "Sends a scoped HTTP request (GET, POST, HEAD) with method, custom headers, and body preview to the pinned target.",
    purpose: "Perform live differential probes, verify boolean injections, and inspect response bodies directly in the console.",
  },
  {
    cmd: "curl <url> [options]",
    syntax: "curl",
    summary: "Executes curl commands through SHARAY's rate-controlled, DNS-pinned HTTP transport.",
    purpose: "Run reproduction commands directly without leaving the console.",
  },
  {
    cmd: "playbook <id>",
    syntax: "playbook",
    summary: "Displays the comprehensive step-by-step reproduction playbook and verification oracle for a finding.",
    purpose: "Review scientific methodology for replicating and proving vulnerability existence.",
  },
  {
    cmd: "probe <url>",
    syntax: "probe",
    summary: "Sends a scoped HTTP/HTTPS HEAD request and follows approved redirects, displaying status, latency, and response headers.",
    purpose: "Verify endpoint reachability, redirect chains, and response header configuration.",
  },
  {
    cmd: "retest <id>",
    syntax: "retest",
    summary: "Queues the finding's full approved assessment profile using its latest completed baseline.",
    purpose: "Dispatch automated verification engine with negative control canaries.",
  },
  {
    cmd: "dns <domain> [type]",
    syntax: "dns",
    summary: "Queries DNS records (A, AAAA, TXT for DMARC/SPF, MX, etc.) for the authorized target hostname with dig.",
    purpose: "Inspect current address records or verify email spoofing policy (TXT records).",
  },
  {
    cmd: "ssl <host>",
    syntax: "ssl",
    summary: "Inspects one verified TLS handshake: negotiated protocol, cipher, certificate fingerprint, and validity dates.",
    purpose: "Inspect the approved HTTPS endpoint's negotiated TLS connection.",
  },
  {
    cmd: "beacon",
    syntax: "beacon",
    summary: "Measures TCP connection latency to the pinned target and reports the application destination guard.",
    purpose: "Check target connectivity and latency.",
  },
  {
    cmd: "whoami",
    syntax: "whoami",
    summary: "Displays operator identity, tenant role, session ID, pinned target address, rate cap, and authorized scope boundaries.",
    purpose: "Confirm your authorized boundaries and active permissions.",
  },
  {
    cmd: "clear",
    syntax: "clear",
    summary: "Clears the active console output buffer.",
    purpose: "Reset terminal view.",
  },
  {
    cmd: "help",
    syntax: "help",
    summary: "Displays interactive CLI documentation directly inside the terminal session.",
    purpose: "Show in-session CLI commands.",
  },
];

function getHost(url?: string): string {
  if (!url) return "target.host";
  try {
    const parsed = new URL(url.includes("://") ? url : "https://" + url);
    return parsed.hostname || "target.host";
  } catch {
    return url.replace(/^[a-z]+:\/\//, "").split("/")[0].split(":")[0] || "target.host";
  }
}

function getRecommendations(finding?: Finding, targetUrl?: string) {
  const host = getHost(finding?.affected_url || targetUrl);
  const endpoint = finding?.affected_url || targetUrl || "/";

  if (!finding) {
    return {
      playbookTitle: "General Security Assessment & Diagnostics",
      summary: "Inspect perimeter services, test live HTTP headers, and verify that the target origin responds within authorized scope parameters.",
      steps: [
        { label: "Step 1: Check Scope & Identity", command: "whoami", tip: "Verify that your operator role and authorized CIDRs match the target." },
        { label: "Step 2: Inspect Target Headers", command: `probe ${endpoint}`, tip: "Inspect response headers and verify that redirects stay within approved origin." },
        { label: "Step 3: In-Scope HTTP GET", command: `http GET ${endpoint}`, tip: "Execute live GET request and inspect response body preview." },
        { label: "Step 4: Inspect TLS Handshake", command: `ssl ${host}`, tip: "Inspect negotiated TLS connection and certificate validity." },
        { label: "Step 5: Check Connectivity", command: "beacon", tip: "Measure target TCP latency and destination guard status." },
      ]
    };
  }

  const category = (finding.category || "").toLowerCase();
  const title = (finding.title || "").toLowerCase();
  const evidenceObj = Array.isArray(finding.evidence) && finding.evidence.length > 0
    ? (finding.evidence[0] as Record<string, unknown>).data as Record<string, unknown> | undefined
    : undefined;
  const pocObj = (finding.poc as Record<string, unknown> | undefined) || (evidenceObj?.poc as Record<string, unknown> | undefined);
  const param = String(pocObj?.parameter || "id");
  const cleanUrl = endpoint.split("?")[0];
  const queryJoin = cleanUrl.includes("?") ? "&" : "?";

  if (category.includes("sql") || title.includes("sql") || title.includes("sqli")) {
    const trueProbe = `${cleanUrl}${queryJoin}${param}=1%27%20OR%20%271%27%3D%271`;
    const falseProbe = `${cleanUrl}${queryJoin}${param}=1%27%20AND%20%271%27%3D%272`;
    return {
      playbookTitle: "SQL Injection (CWE-89) Verification Playbook",
      summary: "Evaluate whether the application parameter improperly constructs database queries. Execute differential responses to compare baseline vs boolean tautology vs contradiction.",
      steps: [
        { label: "Step 1: Replay Research-Grade PoC", command: `poc ${finding.id}`, tip: "Replay exact trigger, verify differential oracle, and generate visual snapshot." },
        { label: "Step 2: Baseline Request", command: `http GET ${cleanUrl}`, tip: "Capture normal response body length and HTTP status." },
        { label: "Step 3: Boolean Tautology (True Condition)", command: `http GET ${trueProbe}`, tip: "True condition should return content matching baseline (J > 0.90)." },
        { label: "Step 4: Boolean Contradiction (False Condition)", command: `http GET ${falseProbe}`, tip: "False condition causes missing records, altered length (J < 0.88), or syntax error." },
        { label: "Step 5: Metasploit Verification Check", command: `exploit ${finding.id}`, tip: "Run safe non-destructive Metasploit check module." },
        { label: "Step 6: Queue Automated Retest", command: `retest ${finding.id}`, tip: "Queue 3x reproducer with negative control canaries." },
      ]
    };
  }

  if (category.includes("command") || title.includes("command") || title.includes("rce") || category.includes("rce")) {
    const rceProbe = `${cleanUrl}${queryJoin}${param}=1|echo%20SHARAY_CANARY`;
    return {
      playbookTitle: "OS Command Injection / RCE (CWE-78) Safety Playbook",
      summary: "CRITICAL: Potential Remote Code Execution. Do NOT execute destructive payloads. Use isolated non-destructive canary or dispatch sandboxed AutoPyVerifier.",
      steps: [
        { label: "Step 1: Replay Research-Grade PoC", command: `poc ${finding.id}`, tip: "Replay exact canary probe and capture forensic proof." },
        { label: "Step 2: Inspect Target Reachability", command: `probe ${endpoint}`, tip: "Inspect server banner, latency, and response behavior." },
        { label: "Step 3: Isolated Echo Canary Probe", command: `http GET ${rceProbe}`, tip: "Test non-destructive reflection of isolated canary token." },
        { label: "Step 4: Metasploit Non-Destructive Check", command: `exploit ${finding.id}`, tip: "Dispatch safe Metasploit check mode." },
        { label: "Step 5: Queue Automated Retest", command: `retest ${finding.id}`, tip: "Queue sandboxed AutoPyVerifier evaluation." },
      ]
    };
  }

  if (category.includes("ssrf") || title.includes("ssrf")) {
    const loopbackProbe = `${cleanUrl}${queryJoin}url=http%3A%2F%2F127.0.0.1%3A80`;
    return {
      playbookTitle: "Server-Side Request Forgery (CWE-918) Playbook",
      summary: "Review differential responses, verified loopback socket errors, or callback telemetry in assessment evidence before confirming SSRF.",
      steps: [
        { label: "Step 1: Baseline Remote Fetch", command: `http GET ${endpoint}`, tip: "Establish normal behavior when fetching valid external resources." },
        { label: "Step 2: Loopback Canary Probe", command: `http GET ${loopbackProbe}`, tip: "Differential response reveals loopback socket error (ECONNREFUSED) absent from baseline." },
        { label: "Step 3: View Forensic Playbook", command: `playbook ${finding.id}`, tip: "Inspect SSRF verification oracle details." },
        { label: "Step 4: Queue Automated Retest", command: `retest ${finding.id}`, tip: "Verify out-of-band callback telemetry." },
      ]
    };
  }

  if (category.includes("xss") || title.includes("xss") || category.includes("cross_site_scripting")) {
    const xssProbe = `${cleanUrl}${queryJoin}${param}=%22%3E%3Cscript%3Ealert(%27SHARAY%27)%3C%2Fscript%3E`;
    return {
      playbookTitle: "Cross-Site Scripting (CWE-79) Verification Playbook",
      summary: "Check whether parameter values reflect unescaped inside HTML response context. Verify Content-Type and Content-Security-Policy headers.",
      steps: [
        { label: "Step 1: Check Headers & CSP", command: `probe ${endpoint}`, tip: "Inspect Content-Type, Content-Security-Policy, and X-XSS-Protection." },
        { label: "Step 2: Reflected Canary Probe", command: `http GET ${xssProbe}`, tip: "Observe whether payload reflects verbatim in HTML body without contextual escaping." },
        { label: "Step 3: View Forensic Playbook", command: `playbook ${finding.id}`, tip: "View complete XSS reproduction and CSP criteria." },
        { label: "Step 4: Queue Retest", command: `retest ${finding.id}`, tip: "Queue automated headless browser verification." },
      ]
    };
  }

  if (category.includes("tls") || title.includes("tls") || title.includes("certificate") || title.includes("ssl")) {
    return {
      playbookTitle: "TLS / Cryptographic Posture (CWE-310) Playbook",
      summary: "Inspect the negotiated TLS protocol, cipher, certificate fingerprint, and validity dates. Verify modern AEAD ciphers and valid trust chain.",
      steps: [
        { label: "Step 1: Live SSL Handshake", command: `ssl ${host}`, tip: "Inspect negotiated cipher, TLS version, and certificate validity." },
        { label: "Step 2: View Cryptographic Playbook", command: `playbook ${finding.id}`, tip: "Review TLS hardening standards." },
        { label: "Step 3: Queue Retest", command: `retest ${finding.id}`, tip: "Queue comprehensive TLS posture scan." },
      ]
    };
  }

  if (category.includes("dns") || title.includes("dmarc") || title.includes("spf") || category.includes("email_spoofing")) {
    const dmarcHost = `_dmarc.${host.replace(/^_dmarc\./, "")}`;
    return {
      playbookTitle: "DNS & Email Authentication (CWE-345) Playbook",
      summary: "Verify authoritative DNS resource records for anti-spoofing policies (DMARC and SPF TXT records).",
      steps: [
        { label: "Step 1: Query DMARC Policy", command: `dns ${dmarcHost} TXT`, tip: "Query DMARC TXT record; verify v=DMARC1; p=reject or quarantine." },
        { label: "Step 2: Query SPF Policy", command: `dns ${host} TXT`, tip: "Query SPF TXT record; inspect authorized sender envelope." },
        { label: "Step 3: View Forensic Playbook", command: `playbook ${finding.id}`, tip: "Review DMARC/SPF compliance guide." },
        { label: "Step 4: Queue Retest", command: `retest ${finding.id}`, tip: "Queue DNS intelligence recheck." },
      ]
    };
  }

  return {
    playbookTitle: `${finding.title} Verification Playbook`,
    summary: finding.description || "Verify the observed security condition using scoped diagnostic commands.",
    steps: [
      { label: "Step 1: Probe Target Headers", command: `probe ${endpoint}`, tip: "Verify HTTP status and headers." },
      { label: "Step 2: In-Scope HTTP GET", command: `http GET ${endpoint}`, tip: "Execute live GET request and inspect response body." },
      { label: "Step 3: View Forensic Playbook", command: `playbook ${finding.id}`, tip: "Print complete reproduction guide into terminal." },
      { label: "Step 4: Queue Retest", command: `retest ${finding.id}`, tip: "Queue automated assessment retest." },
    ]
  };
}

export default function OperatorTerminal({ target, finding, initialSession, initialCommand, onClose, onFindingUpdated }: {
  target: Target; finding?: Finding; initialSession?: InteractiveSessionMeta; initialCommand?: string; onClose: () => void; onFindingUpdated?: () => void;
}) {
  const [session, setSession] = useState(initialSession);
  const [output, setOutput] = useState("");
  const [status, setStatus] = useState<"connecting" | "connected" | "terminated" | "error">("connecting");
  const [error, setError] = useState<string>();
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [maximized, setMaximized] = useState(false);
  const [ownership, setOwnership] = useState<Ownership>(initialSession?.ownership_state || "HUMAN_OWNED");
  const [activeTab, setActiveTab] = useState<"ai_guidance" | "command_help">("ai_guidance");
  const [triageBusy, setTriageBusy] = useState(false);
  const [triageNotice, setTriageNotice] = useState<string>();
  const terminalRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const outputRef = useRef<HTMLTextAreaElement>(null);
  const rendered = useRef({ text: "", pending: "" });
  const history = useRef<string[]>([]);
  const historyIndex = useRef(0);
  const initRequest = useRef<{ targetId: string; promise: Promise<InteractiveSessionMeta> } | null>(null);
  const sending = useRef(false);
  const ranInitialCommand = useRef(false);

  const appendOutput = useCallback((chunk: string) => {
    rendered.current = terminalText(rendered.current.text, chunk, rendered.current.pending);
    setOutput(rendered.current.text);
  }, []);

  useEffect(() => {
    if (initialSession) return;
    let mounted = true;
    if (initRequest.current?.targetId !== target.id) {
      initRequest.current = { targetId: target.id, promise: post<InteractiveSessionMeta>("/interactive/sessions", { target_id: target.id, cols: 100, rows: 28 }) };
    }
    void initRequest.current.promise.then(result => {
      if (mounted) {
        rendered.current = { text: "", pending: "" }; setOutput("");
        setSession(result); setOwnership(result.ownership_state || "HUMAN_OWNED");
      }
    }).catch((reason: unknown) => {
      if (mounted) { setStatus("error"); setError(reason instanceof Error ? reason.message : "Session creation failed."); }
    });
    return () => { mounted = false; };
  }, [initialSession, target.id]);

  useEffect(() => {
    if (!session || session.state === "terminated") return;
    const controller = new AbortController();
    async function stream() {
      try {
        const response = await fetch(`/api/v1/interactive/sessions/${encodeURIComponent(session!.id)}/stream`, {
          signal: controller.signal, credentials: "same-origin",
        });
        if (!response.ok || !response.body) throw new Error(`Console stream failed (${response.status}).`);
        if (controller.signal.aborted) return;
        setStatus("connected");
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        try {
          while (!controller.signal.aborted) {
            const result = await reader.read();
            if (result.done) break;
            appendOutput(decoder.decode(result.value, { stream: true }));
          }
          if (!controller.signal.aborted) { appendOutput(decoder.decode()); setStatus("terminated"); }
        } finally { reader.releaseLock(); }
      } catch (reason: unknown) {
        if (!controller.signal.aborted) {
          setStatus("error"); setError(reason instanceof Error ? reason.message : "Console stream disconnected.");
        }
      }
    }
    void stream();
    return () => controller.abort();
  }, [session, appendOutput]);

  useEffect(() => {
    const terminal = terminalRef.current;
    if (terminal) terminal.scrollTop = terminal.scrollHeight;
    if (outputRef.current) outputRef.current.scrollTop = outputRef.current.scrollHeight;
  }, [output]);

  useEffect(() => { if (status === "connected") inputRef.current?.focus(); }, [status]);

  useEffect(() => {
    if (!session || status !== "connected" || !terminalRef.current) return;
    let timer: ReturnType<typeof setTimeout>;
    const observer = new ResizeObserver(entries => {
      clearTimeout(timer);
      const { width, height } = entries[0].contentRect;
      timer = setTimeout(() => {
        void post(`/interactive/sessions/${encodeURIComponent(session.id)}/resize`, {
          cols: Math.max(10, Math.min(400, Math.floor(width / 8))),
          rows: Math.max(5, Math.min(200, Math.floor(height / 18))),
        }).catch(() => {});
      }, 100);
    });
    observer.observe(terminalRef.current);
    return () => { observer.disconnect(); clearTimeout(timer); };
  }, [session, status]);

  async function sendInput(data: string) {
    const control = data === "\x03" || data === "\x04";
    if (!session || session.target_id !== target.id || status !== "connected" || (sending.current && !control)) return;
    if (!control) { sending.current = true; setBusy(true); }
    try {
      const result = await post<{ ownership_state: Ownership }>(`/interactive/sessions/${encodeURIComponent(session.id)}/input`, { data, sender: "human" });
      setOwnership(result.ownership_state);
      if (data === "\x04") setStatus("terminated");
    } catch (reason: unknown) {
      appendOutput(`\r\nERROR: ${reason instanceof Error ? reason.message : "Input failed."}\r\n`);
    } finally { if (!control) { sending.current = false; setBusy(false); } }
  }

  useEffect(() => {
    if (status === "connected" && initialCommand && !ranInitialCommand.current) {
      ranInitialCommand.current = true;
      const timer = setTimeout(() => {
        void sendInput(initialCommand + "\n");
      }, 400);
      return () => clearTimeout(timer);
    }
  }, [status, initialCommand]);

  async function changeOwnership(state: Ownership) {
    if (!session) return;
    try {
      const result = await post<{ ownership_state: Ownership }>(`/interactive/sessions/${encodeURIComponent(session.id)}/ownership`, { state });
      setOwnership(result.ownership_state);
    } catch (reason: unknown) { setError(reason instanceof Error ? reason.message : "Ownership change failed."); }
  }

  async function terminate() {
    if (!session) return;
    try {
      await post(`/interactive/sessions/${encodeURIComponent(session.id)}/terminate`, {});
      setStatus("terminated");
    } catch (reason: unknown) { setError(reason instanceof Error ? reason.message : "Termination failed."); }
  }

  function handleKeyDown(event: React.KeyboardEvent<HTMLInputElement>) {
    if (event.key === "Enter" && !event.nativeEvent?.isComposing && !busy && !sending.current) {
      event.preventDefault();
      const command = input.trim();
      if (command) history.current.push(command);
      historyIndex.current = history.current.length;
      setInput("");
      void sendInput(command + "\n");
    } else if (event.ctrlKey && event.key === "l") {
      event.preventDefault(); setOutput(""); rendered.current = { text: "", pending: "" };
    } else if (event.ctrlKey && event.key.toLowerCase() === "c") {
      event.preventDefault(); setInput(""); void sendInput("\x03");
    } else if (event.ctrlKey && event.key.toLowerCase() === "d") {
      event.preventDefault(); void sendInput("\x04");
    } else if (event.key === "ArrowUp" || event.key === "ArrowDown") {
      event.preventDefault();
      historyIndex.current = Math.max(0, Math.min(history.current.length, historyIndex.current + (event.key === "ArrowUp" ? -1 : 1)));
      setInput(history.current[historyIndex.current] || "");
    } else if (event.key === "Tab" && !event.shiftKey) {
      const choices = ["poc", "msf", "exploit", "probe", "http", "curl", "dns", "ssl", "beacon", "retest", "playbook", "whoami", "clear", "help"].filter(command => command.startsWith(input));
      if (choices.length === 1) { event.preventDefault(); setInput(choices[0] + " "); }
    }
  }

  function insertCommand(cmd: string, autoRun = false) {
    setInput(cmd);
    if (autoRun && status === "connected" && !busy && !sending.current) {
      history.current.push(cmd);
      historyIndex.current = history.current.length;
      setInput("");
      void sendInput(cmd + "\n");
    } else {
      inputRef.current?.focus();
    }
  }

  async function triageFinding(newStatus: string) {
    if (!finding) return;
    setTriageBusy(true);
    setTriageNotice(undefined);
    try {
      await api(`/findings/${encodeURIComponent(finding.id)}`, { method: "PATCH", body: JSON.stringify({ status: newStatus }) });
      setTriageNotice(`Status updated to: ${newStatus.replaceAll("_", " ")}`);
      if (onFindingUpdated) onFindingUpdated();
    } catch (err: unknown) {
      setTriageNotice(`Update failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setTriageBusy(false);
    }
  }

  const recs = getRecommendations(finding, target.url);
  const targetHost = getHost(finding?.affected_url || target.url);

  return <div className={`terminal-overlay ${maximized ? "maximized" : ""}`}>
    <dialog open className="terminal-window" aria-label="Operator takeover console" onKeyDown={event => { if (event.key === "Escape") onClose(); }}>
      <div className="terminal-header">
        <div className="terminal-title">
          <Icon name="terminal" />
          <span>OPERATOR CONSOLE</span>
          <Badge value={status} />
          <span className="terminal-target-badge">{target.url}</span>
          <span className="enterprise-badge">COMMERCIAL HITL ACTIVE</span>
        </div>
        <div className="terminal-controls">
          <button className="ghost compact" onClick={() => setMaximized(value => !value)} aria-label={maximized ? "Restore terminal" : "Maximize terminal"}><Icon name="expand" /></button>
          <button className="danger compact" disabled={!session || status === "terminated"} onClick={() => void terminate()}>Terminate</button>
          <button className="ghost compact" onClick={onClose} aria-label="Close terminal"><Icon name="close" /></button>
        </div>
      </div>
      <div className="terminal-toolbar">
        <span className="mono">Control: <strong>{ownership}</strong></span>
        <button className="compact" onClick={() => void changeOwnership("HUMAN_OWNED")}>Take control</button>
        <button className="compact" onClick={() => void changeOwnership("AGENT_OWNED")}>Release to agent</button>
        <button className="compact" onClick={() => void changeOwnership("SHARED")}>Share</button>
        <div className="quick-commands">
          <span className="quick-label">Quick:</span>
          {finding && <button className="compact primary" onClick={() => insertCommand(`poc ${finding.id}`)}>poc</button>}
          <button className="ghost compact" onClick={() => insertCommand("msf auxiliary/scanner/http/title")}>msf</button>
          {finding && <button className="ghost compact" onClick={() => insertCommand(`exploit ${finding.id}`)}>exploit</button>}
          <button className="ghost compact" onClick={() => insertCommand(`probe ${finding?.affected_url || target.url}`)}>probe</button>
          <button className="ghost compact" onClick={() => insertCommand(`http GET ${finding?.affected_url || target.url}`)}>http</button>
          {finding && <button className="ghost compact" onClick={() => insertCommand(`playbook ${finding.id}`)}>playbook</button>}
          {finding && <button className="ghost compact" onClick={() => insertCommand(`retest ${finding.id}`)}>retest</button>}
          <button className="ghost compact" onClick={() => insertCommand(`ssl ${targetHost}`)}>ssl</button>
          <button className="ghost compact" onClick={() => insertCommand(`dns ${targetHost}`)}>dns</button>
          <button className="ghost compact" onClick={() => insertCommand("beacon")}>beacon</button>
          <button className="ghost compact" onClick={() => insertCommand("whoami")}>whoami</button>
        </div>
        <span className="mono status-hint">{busy ? "Executing diagnostic command…" : "Human operator in control"}</span>
      </div>
      {error && <p className="terminal-error" role="alert">{error}</p>}

      <div className="terminal-split-view">
        <div className="terminal-main-pane">
          <div className="terminal-body" ref={terminalRef}>
            <textarea ref={outputRef} className="terminal-output" aria-label="Console output" readOnly value={output} rows={14} />
            {status === "connected" && <div className="terminal-input-row">
              <span className="terminal-prompt mono">&gt;</span>
              <input ref={inputRef} className="terminal-input mono" type="text" value={input} onChange={event => setInput(event.target.value)}
                onKeyDown={handleKeyDown} aria-label="Terminal input" aria-busy={busy} autoComplete="off" spellCheck={false} placeholder="Enter scoped diagnostic command (http, curl, probe, playbook, retest, dns, ssl, beacon, whoami)..." />
            </div>}
            {status === "terminated" && <p className="terminal-status-notice">[SESSION TERMINATED]</p>}
          </div>
        </div>

        <aside className="terminal-sidebar" aria-label="AI Operator Guidance and Command Reference">
          <div className="sidebar-tab-row">
            <button className={`tab-button ${activeTab === "ai_guidance" ? "active" : ""}`} onClick={() => setActiveTab("ai_guidance")}>
              <Icon name="sparkle" size={13} /> AI Verification Copilot
            </button>
            <button className={`tab-button ${activeTab === "command_help" ? "active" : ""}`} onClick={() => setActiveTab("command_help")}>
              <Icon name="overview" size={13} /> Command Help &amp; Manual
            </button>
          </div>

          {activeTab === "ai_guidance" && <div className="sidebar-content">
            {finding ? (
              <div className="finding-focus-card">
                <div className="focus-header">
                  <span className="eyebrow">INSPECTING VULNERABILITY</span>
                  <Badge value={finding.severity} />
                </div>
                <h4 className="focus-title">{finding.title}</h4>
                <p className="focus-asset mono">{finding.affected_url || target.url}</p>
                <div className="focus-meta">
                  <span>Category: <strong>{finding.category?.replaceAll("_", " ") || "general"}</strong></span>
                  <span>Confidence: <strong>{String(finding.confidence)}</strong></span>
                </div>
                <div className="focus-triage">
                  <span className="eyebrow">OPERATOR VERIFICATION DECISION</span>
                  <div className="triage-buttons">
                    <button className="primary compact" disabled={triageBusy} onClick={() => void triageFinding("confirmed")}>Confirm Finding</button>
                    <button className="secondary compact" disabled={triageBusy} onClick={() => void triageFinding("false_positive")}>Mark False Positive</button>
                    <button className="secondary compact" disabled={triageBusy} onClick={() => void triageFinding("demoted")}>Demote</button>
                  </div>
                  {triageNotice && <p className="triage-notice">{triageNotice}</p>}
                </div>
              </div>
            ) : (
              <div className="finding-focus-card generic">
                <span className="eyebrow">ACTIVE TARGET SCOPE</span>
                <h4 className="focus-title">{target.url}</h4>
                <p className="focus-asset mono">Version {target.scope_version} · Status: {target.verification_status}</p>
              </div>
            )}

            <div className="guidance-section">
              <div className="guidance-header">
                <Icon name="sparkle" size={14} />
                <strong>{recs.playbookTitle}</strong>
              </div>
              <p className="guidance-summary">{recs.summary}</p>

              <div className="step-list">
                {recs.steps.map((step, idx) => (
                  <div className="step-card" key={idx}>
                    <div className="step-header">
                      <strong>{step.label}</strong>
                    </div>
                    <code className="step-command">{step.command}</code>
                    <p className="step-tip">{step.tip}</p>
                    <div className="step-actions">
                      <button className="compact" onClick={() => insertCommand(step.command)}>Insert into Terminal</button>
                      <button className="compact primary" disabled={status !== "connected" || busy} onClick={() => insertCommand(step.command, true)}>Run Live</button>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="license-footer">
              <Icon name="lock" size={13} />
              <span>SHARAY Commercial Enterprise Edition · Scope Guardrails Enforced</span>
            </div>
          </div>}

          {activeTab === "command_help" && <div className="sidebar-content">
            <div className="help-intro">
              <strong>Interactive Operator Command Manual</strong>
              <p>Diagnostics enforce the approved origin, paths, and pinned peer. OS/container firewall attestation is unavailable. Only the listed diagnostic commands are accepted.</p>
            </div>

            <div className="command-guide-list">
              {COMMAND_HELP.map(item => (
                <div className="command-card" key={item.cmd}>
                  <div className="command-head">
                    <code className="cmd-name">{item.cmd}</code>
                    <button className="compact" onClick={() => insertCommand(item.syntax)}>Use</button>
                  </div>
                  <p className="cmd-summary">{item.summary}</p>
                  <p className="cmd-purpose"><strong>When to use:</strong> {item.purpose}</p>
                </div>
              ))}
            </div>

            <div className="help-shortcuts">
              <span className="eyebrow">KEYBOARD SHORTCUTS</span>
              <ul>
                <li><kbd>Enter</kbd> Dispatch command</li>
                <li><kbd>Tab</kbd> Autocomplete command name</li>
                <li><kbd>↑</kbd> / <kbd>↓</kbd> Command history</li>
                <li><kbd>Ctrl</kbd> + <kbd>C</kbd> Cancel active command</li>
                <li><kbd>Ctrl</kbd> + <kbd>L</kbd> Clear terminal buffer</li>
                <li><kbd>Esc</kbd> Close operator console</li>
              </ul>
            </div>
          </div>}
        </aside>
      </div>
    </dialog>
  </div>;
}
