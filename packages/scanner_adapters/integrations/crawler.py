"""In-scope recursive web crawler and endpoint discovery engine.

Spider web applications within explicit target scope to discover endpoints,
parameters, forms, and API routes. Only issues read-only GET/HEAD requests
pinned to the authorized destination IP.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import socket
import ssl
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse, urlsplit

from packages.security_policies import Destination

_MAX_PAGE_BYTES = 512 * 1024  # 512 KB per page
_MAX_DEPTH = 5
_MAX_PAGES_CAP = 300  # large-surface ceiling for authorized big-site scopes (Sector O9)
# Fetching these while authenticated ends the session; skip them so the scan stays logged in.
_SESSION_DESTROYING = re.compile(r"(?:^|/)(?:logout|signout|logoff|signoff|log-out|sign-out)\b", re.I)

_SENSITIVE_PROBES = [
    ("/robots.txt", "robots"),
    ("/sitemap.xml", "sitemap"),
    ("/.well-known/security.txt", "security_txt"),
    ("/.git/HEAD", "git_head"),
    ("/.env", "env_file"),
    ("/.DS_Store", "ds_store"),
    ("/config.json", "config_json"),
    ("/backup.sql", "backup_sql"),
    ("/backup.zip", "backup_zip"),
    ("/web.config", "web_config"),
    ("/.htaccess", "htaccess"),
]

_IGNORED_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".ico",
    ".css",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".mp3",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
}


class _HTMLStructureExtractor(HTMLParser):
    """Fast, safe HTML parser extracting links, forms, inputs, and scripts."""

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: set[str] = set()
        self.scripts: set[str] = set()
        self.forms: list[dict[str, Any]] = []
        self.csrf_tokens: dict[str, str] = {}
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict = {k.lower(): (v or "").strip() for k, v in attrs}
        tag = tag.lower()

        if tag == "meta" and "name" in attr_dict and "content" in attr_dict:
            mname = attr_dict["name"].lower()
            if any(k in mname for k in ("csrf", "token", "xsrf")):
                self.csrf_tokens[mname] = attr_dict["content"]

        elif tag == "a":
            if "href" in attr_dict:
                href = attr_dict["href"]
                if href and not href.startswith(("javascript:", "mailto:", "tel:", "#")):
                    full_url = urljoin(self.base_url, href)
                    self.links.add(full_url)
            onclick = attr_dict.get("onclick", "")
            if onclick:
                for match in re.findall(
                    r"""(?:popUp|window\.open|location\.href\s*=)\s*\(\s*['"]([^'"]+)['"]""",
                    onclick,
                    re.IGNORECASE,
                ):
                    self.links.add(urljoin(self.base_url, match))

        elif tag == "script" and "src" in attr_dict:
            src = attr_dict["src"]
            if src:
                self.scripts.add(urljoin(self.base_url, src))

        elif tag == "form":
            action = attr_dict.get("action", "")
            method = attr_dict.get("method", "get").upper()
            form_url = urljoin(self.base_url, action) if action else self.base_url
            self._current_form = {
                "action": form_url,
                "method": method,
                "inputs": [],
            }
            self.forms.append(self._current_form)

        elif tag in ("input", "textarea", "select") and self._current_form is not None:
            name = attr_dict.get("name", "")
            input_type = attr_dict.get("type", "text").lower()
            val = attr_dict.get("value", "")
            if name:
                self._current_form["inputs"].append({"name": name, "type": input_type, "value": val})
                if any(
                    k in name.lower() for k in ("csrf", "token", "xsrf", "authenticity_token", "user_token")
                ):
                    self.csrf_tokens[name] = val

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._current_form = None


def _is_in_scope(url: str, target_host: str, target_scheme: str) -> bool:
    try:
        parsed = urlsplit(url)
        if parsed.scheme != target_scheme:
            return False
        if parsed.hostname is None or parsed.hostname.lower() != target_host.lower():
            return False
        # Filter static binaries
        path = parsed.path.lower()
        if any(path.endswith(ext) for ext in _IGNORED_EXTENSIONS):
            return False
        return True
    except Exception:
        return False


def _fetch_page(
    url: str,
    target_host: str,
    target_port: int,
    allow_ip: str,
    is_https: bool,
    timeout: float = 5.0,
    session_cookies: dict[str, str] | None = None,
    auth_headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], str]:
    """Fetch a single page pinned to allow_ip with TLS, cookie jar, and redirect boundaries."""
    parsed = urlsplit(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    headers = {
        "Host": target_host,
        "User-Agent": "SHARAY-Crawler/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "close",
    }
    if auth_headers:
        headers.update(auth_headers)

    cookie_dict = dict(session_cookies or {})
    if "vulnerabilities" in url or "dvwa" in target_host.lower() or target_port == 4280:
        sec = os.environ.get("SHARAY_DVWA_SECURITY", os.environ.get("SHARAY_LAB_SECURITY_LEVEL", "high"))
        cookie_dict.setdefault("security", sec)

    if cookie_dict:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookie_dict.items())

    conn: http.client.HTTPConnection | http.client.HTTPSConnection
    if is_https:
        tls_ctx = ssl.create_default_context()
        tls_ctx.check_hostname = False
        tls_ctx.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((allow_ip, target_port), timeout=timeout)
        conn_sock = tls_ctx.wrap_socket(sock, server_hostname=target_host)
        conn = http.client.HTTPSConnection(target_host, target_port, timeout=timeout)
        conn.sock = conn_sock
    else:
        conn = http.client.HTTPConnection(allow_ip, target_port, timeout=timeout)

    try:
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        status = resp.status
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}

        # Maintain session cookies across requests
        if session_cookies is not None:
            for k, v in resp.getheaders():
                if k.lower() == "set-cookie":
                    cookie_part = v.split(";")[0]
                    if "=" in cookie_part:
                        cname, cval = cookie_part.split("=", 1)
                        session_cookies[cname.strip()] = cval.strip()

        body_bytes = resp.read(_MAX_PAGE_BYTES)
        body = body_bytes.decode("utf-8", errors="replace")
        return status, resp_headers, body
    finally:
        conn.close()


def parse_robots_txt(content: str) -> dict[str, list[str]]:
    """Parse robots.txt to extract Disallow paths, Allow paths, and Sitemaps."""
    disallowed: list[str] = []
    allowed: list[str] = []
    sitemaps: list[str] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            directive, _, val = line.partition(":")
            d = directive.strip().lower()
            v = val.strip()
            if not v:
                continue
            if d == "disallow":
                disallowed.append(v)
            elif d == "allow":
                allowed.append(v)
            elif d == "sitemap":
                sitemaps.append(v)
    return {"disallowed": disallowed, "allowed": allowed, "sitemaps": sitemaps}


def parse_sitemap_xml(content: str) -> list[str]:
    """Parse sitemap.xml to extract URLs from <loc> tags."""
    urls: list[str] = []
    try:
        root = ET.fromstring(content)
        for elem in root.iter():
            if elem.tag.endswith("loc") and elem.text:
                url = elem.text.strip()
                if url:
                    urls.append(url)
    except Exception:
        for m in re.finditer(r"<loc>\s*(https?://[^<]+)\s*</loc>", content, re.IGNORECASE):
            urls.append(m.group(1).strip())
    return urls


_SCHEMA_PROBES = [
    ("/openapi.json", "openapi"),
    ("/swagger.json", "swagger"),
    ("/api/swagger.json", "swagger"),
    ("/api/v1/swagger.json", "swagger"),
    ("/api-docs", "swagger"),
    ("/graphql", "graphql"),
    ("/api/graphql", "graphql"),
    ("/?wsdl", "wsdl"),
    ("/service?wsdl", "wsdl"),
    ("/soap?wsdl", "wsdl"),
]


def parse_openapi_spec(content: str) -> tuple[list[str], list[str]]:
    """Extract declared endpoints and parameter names from OpenAPI/Swagger JSON string."""
    endpoints: list[str] = []
    parameters: list[str] = []
    try:
        data = json.loads(content)
        paths = data.get("paths", {})
        if isinstance(paths, dict):
            for path_key, path_obj in paths.items():
                if isinstance(path_key, str) and path_key.startswith("/"):
                    endpoints.append(path_key)
                    if isinstance(path_obj, dict):
                        for _, op_obj in path_obj.items():
                            if isinstance(op_obj, dict):
                                for param in op_obj.get("parameters", []):
                                    if isinstance(param, dict) and "name" in param:
                                        parameters.append(str(param["name"]))
    except Exception:
        pass
    return sorted(set(endpoints)), sorted(set(parameters))


def parse_graphql_introspection(content: str, base_endpoint: str = "/graphql") -> tuple[list[str], list[str]]:
    """Extract operations and construct queries from GraphQL introspection JSON."""
    endpoints: list[str] = []
    operations: list[str] = []
    try:
        data = json.loads(content)
        schema = data.get("data", {}).get("__schema", {})
        types = schema.get("types", [])
        for t in types:
            if isinstance(t, dict) and t.get("name") in ("Query", "Mutation", "Subscription"):
                for field in t.get("fields") or []:
                    if isinstance(field, dict) and "name" in field:
                        fname = str(field["name"])
                        operations.append(fname)
                        endpoints.append(f"{base_endpoint}?query={{{fname}}}")
    except Exception:
        pass
    return sorted(set(endpoints)), sorted(set(operations))


def parse_wsdl(content: str, base_url: str = "") -> tuple[list[str], list[str]]:
    """Extract SOAP operations from WSDL XML document."""
    endpoints: list[str] = []
    operations: list[str] = []
    try:
        root = ET.fromstring(content)
        for elem in root.iter():
            tag_name = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            if tag_name.lower() == "operation" and "name" in elem.attrib:
                op_name = elem.attrib["name"]
                operations.append(op_name)
                clean_base = base_url.rstrip("/") if base_url else ""
                endpoints.append(f"{clean_base}#{op_name}")
    except Exception:
        for m in re.finditer(
            r'<[a-zA-Z0-9_:]*operation\s+[^>]*name=["\']([^"\']+)["\']', content, re.IGNORECASE
        ):
            op_name = m.group(1)
            operations.append(op_name)
            clean_base = base_url.rstrip("/") if base_url else ""
            endpoints.append(f"{clean_base}#{op_name}")
    return sorted(set(endpoints)), sorted(set(operations))


def probe_sensitive_files(
    destination: Destination,
    allow_ip: str,
    timeout: float = 3.0,
) -> list[dict[str, Any]]:
    """Probe for exposed sensitive files (.git, .env, .DS_Store, backups, configs)."""
    exposed: list[dict[str, Any]] = []
    target_host = destination.host
    target_port = destination.port
    is_https = destination.scheme == "https"
    base = destination.url.rstrip("/")

    fails = 0
    for path, probe_type in _SENSITIVE_PROBES:
        probe_url = f"{base}{path}"
        try:
            status, _, body = _fetch_page(
                probe_url, target_host, target_port, allow_ip, is_https, timeout=min(timeout, 1.5)
            )
            fails = 0
            if status == 200:
                is_real_match = False
                if probe_type == "git_head" and (
                    "ref: refs/" in body or re.match(r"^[0-9a-f]{40}", body.strip())
                ):
                    is_real_match = True
                elif probe_type == "env_file" and any(
                    k in body for k in ("APP_", "DB_", "SECRET", "KEY", "TOKEN", "PASSWORD")
                ):
                    is_real_match = True
                elif probe_type == "ds_store" and (len(body) > 10 and not body.strip().startswith("<")):
                    is_real_match = True
                elif (
                    probe_type in ("backup_sql", "backup_zip", "config_json", "web_config", "htaccess")
                    and not body.strip().startswith("<!DOCTYPE")
                    and not body.strip().startswith("<html")
                ):
                    is_real_match = True
                elif probe_type in ("robots", "sitemap", "security_txt"):
                    is_real_match = True

                if is_real_match:
                    exposed.append(
                        {
                            "path": path,
                            "probe_type": probe_type,
                            "url": probe_url,
                            "status": status,
                            "body_snippet": body[:200].strip(),
                        }
                    )
        except Exception:
            fails += 1
            if fails >= 2:
                break
    return exposed


def crawl(
    destination: Destination,
    allow_ip: str,
    *,
    max_depth: int = 2,
    max_pages: int = 30,
    timeout: float = 5.0,
    cookies: dict[str, str] | None = None,
    auth_headers: dict[str, str] | None = None,
    probe_sensitive: bool = True,
) -> dict[str, Any]:
    """Recursively crawl the authorized target within strict depth and page boundaries,
    maintaining session cookies and extracting CSRF tokens (Sector 2.4)."""
    depth_limit = min(max(1, max_depth), _MAX_DEPTH)
    page_limit = min(max(1, max_pages), _MAX_PAGES_CAP)

    session_cookies: dict[str, str] = dict(cookies or {})
    active_auth_headers: dict[str, str] = dict(auth_headers or {})
    all_csrf_tokens: dict[str, str] = {}

    target_host = destination.host
    target_port = destination.port
    is_https = destination.scheme == "https"
    base_url = (
        f"{destination.scheme}://{target_host}:{target_port}"
        if target_port not in (80, 443)
        else destination.url.rstrip("/")
    )

    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(base_url, 0)]
    dest_path = urlsplit(destination.url).path or "/"
    if dest_path and dest_path != "/":
        queue.insert(0, (destination.url, 0))

    discovered_endpoints: set[str] = {dest_path} if dest_path and dest_path != "/" else set()
    discovered_parameters: set[str] = set()
    discovered_forms: list[dict[str, Any]] = []
    discovered_scripts: set[str] = set()
    discovered_urls: set[str] = {base_url, destination.url}
    spider_extracted_endpoints: set[str] = set()
    pages_crawled: list[dict[str, Any]] = []

    # 1. Ingest robots.txt
    robots_disallowed: list[str] = []
    sitemaps_to_fetch: list[str] = [f"{base_url}/sitemap.xml"]
    try:
        r_status, _, r_body = _fetch_page(
            f"{base_url}/robots.txt", target_host, target_port, allow_ip, is_https, timeout=timeout
        )
        if r_status == 200 and r_body:
            robots_data = parse_robots_txt(r_body)
            robots_disallowed = robots_data.get("disallowed", [])
            for dis in robots_disallowed:
                clean_dis = dis.strip()
                if clean_dis.startswith("/"):
                    full_dis = urljoin(base_url, clean_dis)
                    discovered_endpoints.add(clean_dis)
                    discovered_urls.add(full_dis)
                    if clean_dis not in ("/", "/*"):
                        queue.append((full_dis, 1))
            for sm in robots_data.get("sitemaps", []):
                if _is_in_scope(sm, target_host, destination.scheme):
                    sitemaps_to_fetch.append(sm)
    except Exception:
        pass

    # 2. Ingest sitemap.xml
    sitemap_urls_discovered: list[str] = []
    for sm_url in list(dict.fromkeys(sitemaps_to_fetch))[:3]:
        try:
            sm_status, _, sm_body = _fetch_page(
                sm_url, target_host, target_port, allow_ip, is_https, timeout=timeout
            )
            if sm_status == 200 and sm_body:
                sm_links = parse_sitemap_xml(sm_body)
                for link in sm_links:
                    if _is_in_scope(link, target_host, destination.scheme):
                        sitemap_urls_discovered.append(link)
                        discovered_urls.add(link)
                        parsed_link = urlparse(link)
                        discovered_endpoints.add(parsed_link.path or "/")
                        if len(queue) < page_limit * 2:
                            queue.append((link, 1))
        except Exception:
            pass

    # 2.5 Ingest OpenAPI, GraphQL, and WSDL Schemas (B4)
    schema_declared_endpoints: set[str] = set()
    for s_path, s_type in _SCHEMA_PROBES:
        try:
            s_url = f"{base_url}{s_path}"
            s_status, _, s_body = _fetch_page(
                s_url, target_host, target_port, allow_ip, is_https, timeout=min(timeout, 2.0)
            )
            if s_status == 200 and s_body:
                if s_type in ("openapi", "swagger") and (
                    "openapi" in s_body or "swagger" in s_body or "paths" in s_body
                ):
                    eps, params = parse_openapi_spec(s_body)
                    for ep in eps:
                        schema_declared_endpoints.add(ep)
                        discovered_endpoints.add(ep)
                        discovered_urls.add(urljoin(base_url, ep))
                    for p in params:
                        discovered_parameters.add(p)
                elif s_type == "graphql" and ("__schema" in s_body or "data" in s_body):
                    eps, _ = parse_graphql_introspection(s_body, base_endpoint=s_path)
                    for ep in eps:
                        schema_declared_endpoints.add(ep)
                        discovered_endpoints.add(ep)
                        discovered_urls.add(urljoin(base_url, ep))
                elif s_type == "wsdl" and ("definitions" in s_body or "wsdl" in s_body):
                    eps, _ = parse_wsdl(s_body, base_url=s_path)
                    for ep in eps:
                        schema_declared_endpoints.add(ep)
                        discovered_endpoints.add(ep)
        except Exception:
            pass

    # 3. Sensitive File Probing -- only dispatched when the caller enabled it. Probing is itself an
    # active request to sensitive paths (/.git, /.env, backups), so when the "sensitive" option is
    # off the probes must not run at all, not merely have their results suppressed downstream (F03).
    exposed_files = probe_sensitive_files(destination, allow_ip, timeout=timeout) if probe_sensitive else []
    for exp in exposed_files:
        discovered_endpoints.add(exp["path"])
        discovered_urls.add(exp["url"])

    # 4. Recursive Web Spidering
    while queue and len(visited) < page_limit:
        current_url, depth = queue.pop(0)

        # Normalize URL: strip fragment and trailing slashes for deduplication
        parsed = urlparse(current_url)
        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            clean_url = f"{clean_url}?{parsed.query}"
            for param in parsed.query.split("&"):
                if "=" in param:
                    k = param.split("=")[0]
                    if k:
                        discovered_parameters.add(k)

        if clean_url in visited:
            continue
        visited.add(clean_url)

        endpoint_path = parsed.path or "/"
        discovered_endpoints.add(endpoint_path)
        spider_extracted_endpoints.add(endpoint_path)
        discovered_urls.add(clean_url)

        # Never fetch a logout/sign-out link while authenticated: visiting it destroys the session, so
        # every later authenticated probe (crawl + active audit) would silently revert to anonymous.
        # The endpoint is still recorded above; we just don't trigger it.
        if (session_cookies or active_auth_headers) and _SESSION_DESTROYING.search(endpoint_path):
            continue

        try:
            status, headers, body = _fetch_page(
                clean_url,
                target_host,
                target_port,
                allow_ip,
                is_https,
                timeout=timeout,
                session_cookies=session_cookies,
                auth_headers=active_auth_headers,
            )
        except Exception as exc:
            pages_crawled.append({"url": clean_url, "status": 0, "error": type(exc).__name__})
            continue

        pages_crawled.append({"url": clean_url, "status": status, "depth": depth})

        # Update session cookies from response headers
        set_cookie = headers.get("set-cookie")
        if set_cookie:
            for part in set_cookie.split(","):
                cookie_seg = part.split(";")[0].strip()
                if "=" in cookie_seg:
                    cname, cval = cookie_seg.split("=", 1)
                    session_cookies[cname.strip()] = cval.strip()

        content_type = headers.get("content-type", "")
        if "html" not in content_type and "xml" not in content_type and not body.strip().startswith("<"):
            continue

        extractor = _HTMLStructureExtractor(clean_url)
        try:
            extractor.feed(body)
            all_csrf_tokens.update(extractor.csrf_tokens)
        except Exception:
            pass

        for form in extractor.forms:
            form_action = form.get("action", "")
            if _is_in_scope(form_action, target_host, destination.scheme):
                discovered_forms.append(form)
                discovered_urls.add(form_action)
                spider_extracted_endpoints.add(urlparse(form_action).path or "/")
                for inp in form.get("inputs", []):
                    name = inp.get("name")
                    if name:
                        discovered_parameters.add(name)

        for script in extractor.scripts:
            if _is_in_scope(script, target_host, destination.scheme):
                discovered_scripts.add(script)
                discovered_urls.add(script)

        if depth < depth_limit:
            for link in extractor.links:
                if _is_in_scope(link, target_host, destination.scheme):
                    parsed_link = urlparse(link)
                    clean_link = f"{parsed_link.scheme}://{parsed_link.netloc}{parsed_link.path}"
                    if parsed_link.query:
                        clean_link = f"{clean_link}?{parsed_link.query}"
                    discovered_urls.add(clean_link)
                    spider_extracted_endpoints.add(parsed_link.path or "/")
                    if clean_link not in visited:
                        queue.append((clean_link, depth + 1))

    # Calculate Schema vs Dynamic Spider Coverage (B4)
    spider_norm = {ep.rstrip("/") or "/" for ep in spider_extracted_endpoints}
    covered_schema: set[str] = set()
    uncovered_schema: set[str] = set()
    for s_ep in schema_declared_endpoints:
        base_s_ep = s_ep.split("{")[0].rstrip("/") or "/"
        if s_ep in spider_extracted_endpoints or s_ep.rstrip("/") in spider_norm or base_s_ep in spider_norm:
            covered_schema.add(s_ep)
        else:
            uncovered_schema.add(s_ep)

    schema_count = len(schema_declared_endpoints)
    covered_count = len(covered_schema)
    coverage_ratio = round(covered_count / schema_count, 3) if schema_count > 0 else 1.0

    schema_coverage_report = {
        "declared_count": schema_count,
        "covered_count": covered_count,
        "coverage_ratio": coverage_ratio,
        "covered": sorted(covered_schema)[:50],
        "uncovered": sorted(uncovered_schema)[:50],
    }

    # Honest coverage signal: if the page limit was reached while URLs remained queued, the crawl was
    # truncated. frontier_remaining counts distinct not-yet-visited URLs still in the frontier, so a
    # large-site under-crawl is reported rather than silently incomplete.
    frontier_remaining = len({u for u, _ in queue if u not in visited})
    coverage_truncated = len(visited) >= page_limit and frontier_remaining > 0
    return {
        "pages_visited": len(visited),
        "page_limit": page_limit,
        "frontier_remaining": frontier_remaining,
        "coverage_truncated": coverage_truncated,
        "endpoints": sorted(discovered_endpoints),
        "urls": sorted(discovered_urls),
        "parameters": sorted(discovered_parameters),
        "forms": discovered_forms[:50],
        "scripts": sorted(discovered_scripts)[:50],
        "robots_disallowed": sorted(set(robots_disallowed)),
        "sitemap_urls_count": len(sitemap_urls_discovered),
        "exposed_sensitive_files": exposed_files,
        "schema_coverage": schema_coverage_report,
        "pages": pages_crawled,
        "session_cookies": session_cookies,
        "csrf_tokens": all_csrf_tokens,
        "authenticated": bool(session_cookies or active_auth_headers),
    }


__all__ = ["crawl", "parse_openapi_spec", "parse_graphql_introspection", "parse_wsdl"]
