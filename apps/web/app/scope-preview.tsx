"use client";

import { date, type Scope } from "./api";
import { Badge, Icon, Json } from "./components";

export default function ScopePreview({ scope, url }: { scope: Scope; url: string }) {
  return <div className="scope-preview"><div className="scope-url"><Icon name="assets"/><code>{url}</code><Badge value="safe HTTP"/></div><dl className="facts"><div><dt>Allowed origins</dt><dd className="mono">{scope.allowed_origins.join(", ")}</dd></div><div><dt>Hosts / IP policy</dt><dd className="mono">{scope.hosts.join(", ")} / {scope.allowed_cidrs.join(", ")}</dd></div><div><dt>Included paths</dt><dd className="mono">{scope.allowed_paths.join(", ")}</dd></div><div><dt>Excluded paths</dt><dd className="mono">{scope.excluded_paths.join(", ") || "None"}</dd></div><div><dt>Test categories</dt><dd>{scope.categories.map(category => category.replaceAll("_", " ")).join(", ")}</dd></div><div><dt>Rate / concurrency</dt><dd>{scope.request_rate} request per second / {scope.max_concurrency} connection</dd></div><div><dt>Authentication / intrusive tests</dt><dd>{scope.authenticated ? "Authenticated" : "Unauthenticated"} / {scope.intrusive ? "Enabled" : "Disabled"}</dd></div><div><dt>Approved test accounts</dt><dd>{scope.credential_refs.join(", ") || "None"}</dd></div><div><dt>Validity</dt><dd>{date(scope.starts_at)} → {date(scope.expires_at)}</dd></div><div><dt>Emergency stop</dt><dd>{scope.emergency_stop_conditions.map(item => item.replaceAll("_", " ")).join(", ")}</dd></div></dl><details><summary>View reproducible scope configuration</summary><Json value={scope}/></details></div>;
}
