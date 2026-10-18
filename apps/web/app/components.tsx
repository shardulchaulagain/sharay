"use client";

import { useEffect, useState, type ReactNode } from "react";
import { api, ApiError, readable } from "./api";

export function useResource<T>(path: string | null, revision = 0, poll = false) {
  const [result, setResult] = useState<{ path: string | null; data?: T; error?: string; loading: boolean; observedAt?: number }>({ path, loading: true });
  useEffect(() => {
    if (!path) return;
    const controller = new AbortController();
    let active = true;
    const refresh = async () => {
      try {
        const data = await api<T>(path, { signal: controller.signal });
        if (active) setResult({ path, data, loading: false, observedAt: Date.now() });
      } catch (error) {
        if (active && !(error instanceof DOMException && error.name === "AbortError")) setResult({ path, error: error instanceof Error ? error.message : "Request failed.", loading: false });
      }
    };
    void refresh();
    const interval = poll ? window.setInterval(refresh, 2500) : undefined;
    return () => { active = false; controller.abort(); if (interval) window.clearInterval(interval); };
  }, [path, revision, poll]);
  return result.path === path ? result : { path, loading: true };
}

export function Shield({ small = false }: { small?: boolean }) {
  return <svg width={small ? "27" : "60"} height={small ? "32" : "72"} viewBox="0 0 60 72" fill="none" aria-hidden="true"><path d="M30 3 54 12v24c0 15-13 26-24 32C19 62 6 51 6 36V12L30 3Z" stroke="currentColor" strokeWidth="1.5"/><path d="M41 20H25a8 8 0 0 0 0 16h10a8 8 0 0 1 0 16H19" stroke="currentColor" strokeWidth="1.5"/></svg>;
}

export function Icon({ name, size = 18 }: { name: string; size?: number }) {
  const paths: Record<string, ReactNode> = {
    overview: <><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></>,
    projects: <path d="M3 7V5h6l2 2h10v13H3V7Z"/>,
    assessments: <><path d="M4 20h16M5 16l4-6 4 3 6-9"/><path d="M15 4h4v4"/></>,
    findings: <><path d="m12 3 10 18H2L12 3Z"/><path d="M12 9v5m0 3v1"/></>,
    assets: <><rect x="3" y="3" width="18" height="12" rx="2"/><path d="M8 21h8m-4-6v6M7 7h10"/></>,
    reports: <><path d="M6 3h9l4 4v14H6V3Z"/><path d="M14 3v5h5M9 12h7m-7 4h7"/></>,
    integrations: <><path d="m9 3 3 3-3 3M3 6h9M15 15l-3 3 3 3m-3-3h9M7 12h10"/></>,
    audit: <><path d="M5 3h14v18H5V3ZM9 7h6m-6 5h6m-6 5h6"/></>,
    settings: <><path d="M4 6h16M4 12h16M4 18h16"/><circle cx="8" cy="6" r="2"/><circle cx="16" cy="12" r="2"/><circle cx="10" cy="18" r="2"/></>,
    arrow: <path d="M4 12h16m-6-6 6 6-6 6"/>,
    plus: <path d="M12 4v16M4 12h16"/>,
    lock: <><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2"/></>,
    logout: <><path d="M9 4H4v16h5m0-8h12m-5-5 5 5-5 5"/></>,
    refresh: <><path d="M20 10a8 8 0 1 0-2 8M20 3v7h-7"/></>,
    check: <path d="m4 12 5 5L20 6"/>,
    close: <path d="m5 5 14 14M5 19 19 5"/>,
    sparkle: <><path d="m12 3 2.5 6.5L21 12l-6.5 2.5L12 21l-2.5-6.5L3 12l6.5-2.5L12 3Z"/></>,
    terminal: <><path d="m4 17 6-6-6-6"/><path d="M12 19h8"/></>,
    copy: <><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></>,
  };
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name] ?? paths.overview}</svg>;
}

export function Badge({ value }: { value: string }) { return <span className={`badge badge-${value.replaceAll(" ", "_")}`}>{readable(value)}</span>; }
export function ErrorNotice({ error }: { error?: string | Error }) {
  if (!error) return null;
  return <div className="notice error" role="alert"><strong>Couldn’t complete this request.</strong> {error instanceof Error ? error.message : error}{error instanceof ApiError && error.requestId && <small>Request {error.requestId}</small>}</div>;
}
export function Loading() { return <div className="loading" role="status"><span className="spinner"/>Reading your workspace…</div>; }
export function Empty({ title, children, action }: { title: string; children: ReactNode; action?: ReactNode }) {
  return <div className="empty"><div className="empty-mark"><Icon name="projects" size={26}/></div><h3>{title}</h3><p>{children}</p>{action}</div>;
}
export function SectionHead({ eyebrow, title, children, action }: { eyebrow?: string; title: string; children?: ReactNode; action?: ReactNode }) {
  return <div className="section-head"><div>{eyebrow && <p className="eyebrow">{eyebrow}</p>}<h1>{title}</h1>{children && <p className="subtitle">{children}</p>}</div>{action}</div>;
}
export function Panel({ title, children, action, className = "" }: { title: string; children: ReactNode; action?: ReactNode; className?: string }) {
  return <section className={`panel ${className}`}><div className="panel-head"><h2>{title}</h2>{action}</div>{children}</section>;
}
export function Json({ value }: { value: unknown }) { return <pre className="evidence">{JSON.stringify(value, null, 2)}</pre>; }

export function ReportLinks({ id }: { id: string }) { return <div className="report-links">{["html", "json", "markdown", "pdf"].map(format => <a key={format} href={`/api/v1/reports/${encodeURIComponent(id)}?format=${format}`} target="_blank" rel="noopener noreferrer">{format === "markdown" ? "MD" : format.toUpperCase()}</a>)}</div>; }

export function Pagination({ offset, total, limit, setOffset }: { offset: number; total: number; limit: number; setOffset: (offset: number) => void }) { return <div className="pagination"><span>{total ? `${offset + 1}–${Math.min(offset + limit, total)} of ${total}` : "0 records"}</span><div><button className="secondary compact" disabled={!offset} onClick={() => setOffset(Math.max(0, offset - limit))}>Previous</button><button className="secondary compact" disabled={offset + limit >= total} onClick={() => setOffset(offset + limit)}>Next</button></div></div>; }
