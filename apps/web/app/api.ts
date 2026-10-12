export type User = { id: string; username: string; role: string; organization_id: string };
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
};
export type Project = { id: string; name: string; description: string; created_at: string; targets?: Target[]; assessments?: Assessment[]; findings?: Finding[] };
export type Assessment = {
  id: string; project_id: string; target_id: string; target_url?: string; status: string; stage: string;
  created_at: string; started_at?: string; finished_at?: string; error?: string; retest_of?: string;
  observations?: Observation[]; findings?: Finding[]; checks?: Check[]; events?: Event[]; scope_snapshot?: Scope & { target_url?: string }; scope_version?: number; profile?: string;
};
export type Observation = { id: string; assessment_id: string; evidence_hash: string; observed_at: string; data: Record<string, unknown> };
export type Finding = {
  id: string; title: string; severity: string; confidence: string | number; status: string;
  verification_status?: string; affected_asset?: string; affected_url?: string; asset?: string; description?: string;
  remediation?: string; category?: string; first_seen?: string; last_seen?: string;
  assessment_id?: string; assessment_ids?: string[]; evidence?: Record<string, unknown>[];
  history?: Record<string, unknown>[];
};
export type Check = { name?: string; category?: string; status: string; reason?: string; message?: string; [key: string]: unknown };
export type Event = { id: string; action?: string; event?: string; message?: string; created_at?: string; timestamp?: string; actor?: string; actor_id?: string; resource_id?: string; [key: string]: unknown };
export type Overview = {
  active_assessments: number; completed_assessments: number; confirmed_findings: number;
  open_findings: number; projects: number; assets: number; recent_assessments: Assessment[]; recent_events: Event[];
};
export type Integration = { id?: string; name: string; status: string; version?: string; description?: string; reason?: string; [key: string]: unknown };

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

export function readable(value: string) { return value.replaceAll("_", " "); }
export function date(value?: string) {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function laboratoryScope(url: string, included: string, excluded: string, expires: string): Scope {
  const parsed = new URL(url);
  if (parsed.hostname !== "127.0.0.1" && parsed.hostname !== "[::1]") throw new Error("Use an explicit laboratory address: 127.0.0.1 or [::1].");
  if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password || parsed.hash || parsed.search) throw new Error("Use HTTP or HTTPS without credentials, a query string or a fragment.");
  const paths = (value: string) => value.split(/\r?\n/).map(path => path.trim()).filter(Boolean);
  const allowed = paths(included);
  if (!allowed.length || [...allowed, ...paths(excluded)].some(path => !path.startsWith("/") || path.includes("?") || path.includes("#"))) throw new Error("Enter paths beginning with /, one per line, without query strings or fragments.");
  const expiresAt = new Date(expires);
  if (Number.isNaN(expiresAt.getTime()) || expiresAt <= new Date()) throw new Error("Choose an expiration time in the future.");
  return {
    hosts: [parsed.hostname === "[::1]" ? "::1" : parsed.hostname], allowed_origins: [parsed.origin],
    allowed_paths: allowed, excluded_paths: paths(excluded), allowed_cidrs: [parsed.hostname === "[::1]" ? "::1/128" : "127.0.0.1/32"],
    categories: ["http_headers", "tls", "dns"], authenticated: false, credential_refs: [], request_rate: 1,
    max_concurrency: 1, starts_at: new Date().toISOString(), expires_at: expiresAt.toISOString(), intrusive: false,
    approval_required: true, emergency_stop_conditions: ["operator_cancel", "scope_expired", "policy_violation"],
  };
}
