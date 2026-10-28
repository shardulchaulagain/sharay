export type User = { id: string; username: string; role: string; organization_id: string };
export type Credential = { id: string; name: string; kind: string; header_name: string | null; identity: string | null; subject_id: string | null; created_at: string };
export type Session = { user: User; csrf_token: string };
export type Collection<T> = { items: T[]; total?: number };
export type Scope = {
  hosts: string[]; allowed_origins: string[]; allowed_paths: string[]; excluded_paths: string[];
  allowed_cidrs: string[]; categories: string[]; authenticated: boolean; credential_refs: string[];
  request_rate: number; max_concurrency: number; starts_at: string; expires_at: string;
  intrusive: boolean; approval_required: boolean; emergency_stop_conditions: string[];
};
export type Target = {
  id: string; project_id: string; url: string; scope: Scope; scope_version: number;
  verification_status: string; approved_at?: string; authorized_by?: string;
  execution_blocker?: string | null;
};
export type Project = { id: string; name: string; description: string; created_at: string; archived: boolean; targets?: Target[]; assessments?: Assessment[]; findings?: Finding[] };
export type ScanConfig = {
  mode: "passive" | "standard" | "adaptive" | "aggressive";
  tags?: string;
  rate: number;
  depth: number;
  tools?: string[];
};
export type Assessment = {
  id: string; project_id: string; target_id: string; target_url?: string; status: string; stage: string;
  created_at: string; started_at?: string; finished_at?: string; error?: string; retest_of?: string;
  observations?: Observation[]; findings?: Finding[]; checks?: Check[]; events?: Event[]; scope_snapshot?: Scope & { target_url?: string; scan_config?: ScanConfig }; scope_version?: number; profile?: string;
};
export type Observation = { id: string; assessment_id: string; evidence_hash: string; observed_at: string; data: Record<string, unknown> };
export type Finding = {
  id: string; title: string; severity: string; confidence: string | number; status: string;
  project_id?: string; target_id?: string;
  verification_status?: string; affected_asset?: string; affected_url?: string; asset?: string; description?: string;
  remediation?: string; category?: string; first_seen?: string; last_seen?: string;
  cwe_id?: string; fingerprint?: string;
  assessment_id?: string; assessment_ids?: string[]; evidence?: Record<string, unknown>[];
  history?: Record<string, unknown>[];
  poc?: unknown;
};
export type Check = { name?: string; category?: string; status: string; reason?: string; message?: string; [key: string]: unknown };
export type Event = { id: string; action?: string; event?: string; message?: string; created_at?: string; timestamp?: string; actor?: string; actor_id?: string; resource_id?: string; [key: string]: unknown };
export type Overview = {
  active_assessments: number; completed_assessments: number; confirmed_findings: number;
  open_findings: number; projects: number; assets: number; recent_assessments: Assessment[]; recent_events: Event[];
};
export type Integration = { id?: string; name: string; status: string; version?: string; description?: string; reason?: string; [key: string]: unknown };

export type AIStatus = {
  active_provider: string;
  model: string;
  api_key_configured: boolean;
  share_assessment_data: boolean;
  supported_providers: string[];
  status: string;
};

export type AttackGraphNode = {
  id: string;
  kind: string;
  label: string;
  attributes: Record<string, unknown>;
};

export type AttackGraphEdge = {
  source: string;
  target: string;
  relationship: string;
  risk_weight: number;
  description: string;
};

export type AttackPath = {
  path_id: string;
  severity: string;
  steps: string[];
  root_exposure: string;
  target_vulnerability: string;
  category: string;
  remediation: string;
};

export type RootCauseItem = {
  category: string;
  cwe_id: string;
  owasp_category: string;
  severity: string;
  finding_count: number;
  affected_items: string[];
  mechanism: string;
  blast_radius: string;
  strategic_fix: string;
};

export type RemediationPatch = {
  id: string;
  title: string;
  file_type: string;
  target_component: string;
  description: string;
  diff: string;
};

export type KillChainPhase = {
  phase: string;
  tools: string[];
  summary: string;
  status: string;
};

export type AIInvestigation = {
  assessment_id: string;
  created_at?: string;
  target_url: string;
  posture_score: number | null;
  assessed?: boolean;
  coverage?: string;
  graph: {
    nodes_count: number;
    edges_count: number;
    nodes: AttackGraphNode[];
    edges: AttackGraphEdge[];
    attack_paths: AttackPath[];
  };
  attack_paths: AttackPath[];
  hypotheses: Array<{ id: string; statement: string; severity: string; status: string }>;
  root_causes: RootCauseItem[];
  remediation_patches: RemediationPatch[];
  red_team_kill_chain: KillChainPhase[];
  ai_executive_summary: string;
  total_findings: number;
  total_observations: number;
};

export class ApiError extends Error {
  status: number;
  requestId?: string;
  constructor(message: string, status: number, requestId?: string) { super(message); this.status = status; this.requestId = requestId; }
}

let csrf = "";
export function setCsrf(value: string) { csrf = value; }

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const method = options.method ?? "GET";
  const headers = new Headers(options.headers);
  headers.set("Accept", "application/json");
  if (options.body) headers.set("Content-Type", "application/json");
  if (method !== "GET" && method !== "HEAD" && csrf) headers.set("X-CSRF-Token", csrf);
  const response = await fetch(`/api/v1${path}`, { ...options, headers, credentials: "same-origin", cache: "no-store" });
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    let message = data?.message ?? data?.detail ?? `Request failed (${response.status}).`;
    if (Array.isArray(message)) message = message.map((issue: { loc?: string[]; msg?: string }) => `${issue.loc?.slice(1).join(".")}: ${issue.msg}`).join("; ");
    if (typeof message !== "string") message = "The server rejected this request. Review your input and try again.";
    const error = new ApiError(message, response.status, data?.request_id);
    if (response.status === 401 && path !== "/auth/login" && path !== "/auth/session") {
      window.dispatchEvent(new Event("aegis-session-expired"));
    }
    throw error;
  }
  return data as T;
}

export function post<T>(path: string, data: unknown = {}) {
  return api<T>(path, { method: "POST", body: JSON.stringify(data) });
}

export function del<T>(path: string) {
  return api<T>(path, { method: "DELETE" });
}

export function projectFields(name: string, description: string) {
  name = name.trim();
  if (!name || Array.from(name).length > 160) throw new Error("Enter a project name between 1 and 160 characters.");
  if (Array.from(description).length > 4000) throw new Error("Keep the project description within 4000 characters.");
  return { name, description };
}

export function readable(value: string) { return value.replaceAll("_", " "); }
export function date(value?: string) {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function localDateTime(value: string) {
  const parsed = new Date(value);
  return new Date(parsed.getTime() - parsed.getTimezoneOffset() * 60_000).toISOString().slice(0, -1);
}

export function scopeIsActive(scope: Scope) {
  const now = Date.now();
  return new Date(scope.starts_at).getTime() <= now && new Date(scope.expires_at).getTime() > now;
}

export function scopeActionError(error: unknown, fallback: string) {
  if (error instanceof ApiError && error.status === 409) return new ApiError(`${error.message} Reload and review the target’s current scope before trying again.`, error.status, error.requestId);
  return error instanceof Error ? error : new Error(fallback);
}

function scopePath(value: string) {
  if (!value.startsWith("/") || value.length > 2048 || /[?#\\]/.test(value)) throw new Error("Enter absolute paths without queries, fragments or backslashes.");
  let decoded: string;
  try { decoded = decodeURIComponent(value); }
  catch { throw new Error("Use valid UTF-8 path encoding."); }
  if (/[;%\\]/.test(decoded) || [...decoded].some(char => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127) || decoded.includes("//") || decoded.split("/").some(part => part === "." || part === "..") || /%(2f|5c)/i.test(value)) throw new Error("Ambiguous path encoding, traversal and semicolon parameters are unavailable.");
  return encodeURI(decoded).replace(/[?#]/g, encodeURIComponent);
}

export function laboratoryScope(url: string, included: string, excluded: string, expires: string, existing?: Scope, starts = existing?.starts_at ?? new Date().toISOString(), authenticated = false, credentialRefs: string[] = []): Scope {
  const raw = url.match(/^https?:\/\/(\[[0-9a-f:]+\]|[a-z0-9.-]+)(?::([1-9]\d*))?(\/[^?#]*)?$/i);
  if (!raw || url.length > 2048 || url.includes("\\") || [...url].some(char => char.charCodeAt(0) <= 32 || char.charCodeAt(0) === 127)) throw new Error("Use a canonical HTTP or HTTPS URL without whitespace, credentials, a query string or a fragment.");
  const parsed = new URL(url);
  const host = parsed.hostname.startsWith("[") ? parsed.hostname.slice(1, -1) : parsed.hostname;
  if (parsed.hostname !== raw[1] || host.startsWith("::ffff:")) throw new Error("Use a canonical IP address without alternate numeric or IPv4-mapped representations.");
  if (!parsed.hostname.startsWith("[") && !/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    const labels = host.split(".");
    if (host.length > 253 || labels.some(label => !label || label.length > 63 || label.startsWith("-") || label.endsWith("-")) || !/[a-z]/.test(labels.at(-1)!)) throw new Error("Use a canonical lowercase ASCII hostname (punycode for international names).");
  }
  const defaultCidrs = host === "127.0.0.1" ? ["127.0.0.1/32"] : host === "::1" ? ["::1/128"] : [];
  const targetPath = scopePath(raw[3] || "/"); // Validate before URL can strip dot segments.
  const paths = (value: string) => value.split(/\r?\n/).map(path => path.trim()).filter(Boolean).map(scopePath);
  const allowed = paths(included), excludedPaths = paths(excluded);
  if (!allowed.length || allowed.length > 32 || excludedPaths.length > 32) throw new Error("Enter up to 32 paths per list, with at least one permitted path.");
  const matches = (prefix: string) => prefix === "/" || targetPath === prefix.replace(/\/+$/, "") || targetPath.startsWith(prefix.replace(/\/+$/, "") + "/");
  if (!allowed.some(matches) || excludedPaths.some(matches)) throw new Error("The target URL must be inside permitted paths and outside excluded paths.");
  const savedExpiry = existing && expires === localDateTime(existing.expires_at) ? existing.expires_at : undefined;
  const expiresAt = new Date(savedExpiry ?? expires);
  if (Number.isNaN(expiresAt.getTime()) || expiresAt <= new Date()) throw new Error("Choose an expiration time in the future.");
  const savedStart = existing && starts === localDateTime(existing.starts_at) ? existing.starts_at : undefined;
  const startsAt = new Date(savedStart ?? starts);
  if (Number.isNaN(startsAt.getTime()) || startsAt >= expiresAt || expiresAt.getTime() - startsAt.getTime() > 86_400_000) throw new Error("Choose a validity window of up to 24 hours, starting before expiry.");
  if (startsAt > new Date()) throw new Error("The scope must have started before it can be registered or approved.");
  if (existing) {
    const sameOrigin = existing.allowed_origins.includes(parsed.origin);
    return {
      ...existing,
      // A URL change within the registered origins preserves the complete host/IP boundary.
      hosts: sameOrigin ? existing.hosts : [host],
      allowed_origins: sameOrigin ? existing.allowed_origins : [parsed.origin],
      allowed_cidrs: sameOrigin ? existing.allowed_cidrs : defaultCidrs,
      allowed_paths: allowed, excluded_paths: excludedPaths,
      authenticated, credential_refs: credentialRefs,
      starts_at: savedStart ?? startsAt.toISOString(), expires_at: savedExpiry ?? expiresAt.toISOString(),
    };
  }
  return {
    hosts: [host], allowed_origins: [parsed.origin],
    allowed_paths: allowed, excluded_paths: excludedPaths, allowed_cidrs: defaultCidrs,
    categories: ["http_headers", "tls", "dns"], authenticated, credential_refs: credentialRefs, request_rate: 150,
    max_concurrency: 5, starts_at: startsAt.toISOString(), expires_at: expiresAt.toISOString(), intrusive: false,
    approval_required: true, emergency_stop_conditions: ["operator_cancel", "scope_expired", "policy_violation"],
  };
}
