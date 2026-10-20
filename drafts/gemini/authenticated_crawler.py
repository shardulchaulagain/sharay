"""Stateful Authenticated Web Crawler & Session Maintenance Engine.

Part of SHARAY Sector 2 (Scanning & Detection Coverage).
Provides RFC 6265 compliant cookie jar tracking, dynamic CSRF token extraction
from forms, headers, and meta tags, proactive session expiry detection (401/403/redirects),
and transparent automated re-authentication with loop-breaking circuit breakers.
"""

from __future__ import annotations

import email.utils
import http.client
import json
import logging
import re
import socket
import ssl
import time
from html.parser import HTMLParser
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urlsplit

logger = logging.getLogger(__name__)

_DEFAULT_MAX_PAGE_BYTES = 512 * 1024
_MAX_RELOGINS_DEFAULT = 5

_CSRF_INPUT_NAMES = {
    "csrf",
    "csrf_token",
    "_csrf",
    "_csrf_token",
    "csrftoken",
    "xsrf",
    "xsrf_token",
    "_xsrf",
    "authenticity_token",
    "user_token",  # DVWA pattern
    "antiforgery",
    "anti_csrf_token",
}

_LOGIN_PATH_INDICATORS = {
    "/login",
    "/signin",
    "/sign-in",
    "/auth/login",
    "/user/login",
    "/login.php",
    "/session/new",
}

_LOGIN_BODY_INDICATORS = [
    r'<form[^>]*action=["\'][^"\']*(?:login|signin|session)[^"\']*["\']',
    r'<input[^>]*name=["\'](?:password|passwd|pwd)["\']',
    r"please\s+(?:sign\s+in|log\s+in)",
    r"session\s+(?:has\s+)?expired",
    r"authentication\s+required",
]


class CookieItem:
    """Represents a single HTTP cookie with RFC 6265 attributes."""

    def __init__(
        self,
        name: str,
        value: str,
        domain: str,
        path: str = "/",
        expires: Optional[float] = None,
        max_age: Optional[int] = None,
        secure: bool = False,
        httponly: bool = False,
        same_site: str = "Lax",
        created_at: Optional[float] = None,
    ) -> None:
        self.name = name
        self.value = value
        self.domain = domain.lower().lstrip(".")
        self.path = path or "/"
        self.expires = expires
        self.max_age = max_age
        self.secure = secure
        self.httponly = httponly
        self.same_site = same_site
        self.created_at = created_at if created_at is not None else time.time()

    def is_expired(self, now: Optional[float] = None) -> bool:
        current_time = now if now is not None else time.time()
        if self.max_age is not None:
            if self.max_age <= 0:
                return True
            if current_time >= self.created_at + self.max_age:
                return True
        if self.expires is not None:
            if current_time >= self.expires:
                return True
        return False

    def matches(self, target_domain: str, target_path: str, is_secure: bool) -> bool:
        clean_target = target_domain.lower().lstrip(".")
        if self.domain != clean_target and not clean_target.endswith("." + self.domain):
            return False
        clean_target_path = target_path or "/"
        if not clean_target_path.startswith(self.path):
            if not self.path.endswith("/") and clean_target_path == self.path:
                pass
            else:
                return False
        if self.secure and not is_secure:
            return False
        return True


class CookieJar:
    """In-memory RFC 6265 compliant cookie jar with path matching and expiry handling."""

    def __init__(self) -> None:
        self._cookies: Dict[Tuple[str, str, str], CookieItem] = {}  # (domain, path, name) -> CookieItem

    def set_cookie(
        self,
        name: str,
        value: str,
        domain: str,
        path: str = "/",
        expires: Optional[float] = None,
        max_age: Optional[int] = None,
        secure: bool = False,
        httponly: bool = False,
        same_site: str = "Lax",
        now: Optional[float] = None,
    ) -> None:
        item = CookieItem(
            name=name,
            value=value,
            domain=domain,
            path=path,
            expires=expires,
            max_age=max_age,
            secure=secure,
            httponly=httponly,
            same_site=same_site,
            created_at=now,
        )
        key = (item.domain, item.path, item.name)
        if item.is_expired(now):
            self._cookies.pop(key, None)
        else:
            self._cookies[key] = item

    def parse_set_cookie(self, header_value: str, request_url: str, now: Optional[float] = None) -> None:
        """Parse a Set-Cookie header value into the jar."""
        if not header_value:
            return
        parsed_url = urlsplit(request_url)
        default_domain = (parsed_url.hostname or "").lower()
        default_path = (parsed_url.path or "/").rsplit("/", 1)[0] or "/"

        parts = [p.strip() for p in header_value.split(";") if p.strip()]
        if not parts:
            return

        first = parts[0]
        if "=" not in first:
            return
        c_name, _, c_val = first.partition("=")
        c_name = c_name.strip()
        c_val = c_val.strip()

        domain = default_domain
        path = default_path
        expires_ts: Optional[float] = None
        max_age_val: Optional[int] = None
        secure = False
        httponly = False
        same_site = "Lax"

        for attr in parts[1:]:
            attr_name, _, attr_val = attr.partition("=")
            attr_name = attr_name.strip().lower()
            attr_val = attr_val.strip()

            if attr_name == "domain" and attr_val:
                domain = attr_val.lower().lstrip(".")
            elif attr_name == "path" and attr_val:
                path = attr_val
            elif attr_name == "max-age":
                try:
                    max_age_val = int(attr_val)
                except ValueError:
                    pass
            elif attr_name == "expires":
                try:
                    dt = email.utils.parsedate_to_datetime(attr_val)
                    if dt:
                        expires_ts = dt.timestamp()
                except Exception:
                    pass
            elif attr_name == "secure":
                secure = True
            elif attr_name == "httponly":
                httponly = True
            elif attr_name == "samesite":
                same_site = attr_val.capitalize() or "Lax"

        self.set_cookie(
            name=c_name,
            value=c_val,
            domain=domain,
            path=path,
            expires=expires_ts,
            max_age=max_age_val,
            secure=secure,
            httponly=httponly,
            same_site=same_site,
            now=now,
        )

    def get_cookie_header(self, url: str, now: Optional[float] = None) -> str:
        """Construct the Cookie: header string for matching cookies for the given URL."""
        parsed = urlsplit(url)
        domain = (parsed.hostname or "").lower()
        path = parsed.path or "/"
        is_secure = parsed.scheme.lower() == "https"

        matching: List[Tuple[str, str]] = []
        for key, cookie in list(self._cookies.items()):
            if cookie.is_expired(now):
                self._cookies.pop(key, None)
                continue
            if cookie.matches(domain, path, is_secure):
                matching.append((cookie.name, cookie.value))

        if not matching:
            return ""
        # Sort by path length descending per RFC 6265
        return "; ".join(f"{name}={val}" for name, val in matching)

    def get_cookie_value(self, name: str) -> Optional[str]:
        for (_, _, c_name), item in self._cookies.items():
            if c_name == name and not item.is_expired():
                return item.value
        return None

    def export_dict(self) -> Dict[str, str]:
        res: Dict[str, str] = {}
        for (_, _, name), item in self._cookies.items():
            if not item.is_expired():
                res[name] = item.value
        return res


class CSRFExtractor(HTMLParser):
    """Extracts CSRF tokens from HTML forms, hidden inputs, and meta tags."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tokens: Dict[str, str] = {}
        self.meta_tokens: Dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        tag = tag.lower()
        attr_dict = {k.lower(): (v or "").strip() for k, v in attrs}

        if tag == "meta":
            meta_name = attr_dict.get("name", "").lower()
            meta_content = attr_dict.get("content", "")
            if meta_content:
                if "csrf" in meta_name or "xsrf" in meta_name or meta_name == "authenticity_token":
                    self.meta_tokens[meta_name] = meta_content
                    self.tokens[meta_name] = meta_content

        elif tag == "input":
            name = attr_dict.get("name", "")
            val = attr_dict.get("value", "")
            input_type = attr_dict.get("type", "text").lower()

            if name and val:
                clean_name = name.lower()
                if (
                    clean_name in _CSRF_INPUT_NAMES
                    or "csrf" in clean_name
                    or "xsrf" in clean_name
                    or "token" in clean_name
                ):
                    self.tokens[name] = val


def extract_csrf_tokens(
    body: str,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """Dynamically extract CSRF tokens across HTML bodies, headers, and cookies."""
    found: Dict[str, str] = {}

    # 1. From HTML
    if body and ("<" in body):
        extractor = CSRFExtractor()
        try:
            extractor.feed(body)
            found.update(extractor.tokens)
        except Exception:
            pass

        # Regex fallback for non-compliant HTML
        for match in re.finditer(
            r"""<input[^>]+name=["']([^"']*(?:csrf|xsrf|token)[^"']*)["'][^>]+value=["']([^"']+)["']""",
            body,
            re.IGNORECASE,
        ):
            found[match.group(1)] = match.group(2)
        for match in re.finditer(
            r"""<meta[^>]+name=["']([^"']*(?:csrf|xsrf|token)[^"']*)["'][^>]+content=["']([^"']+)["']""",
            body,
            re.IGNORECASE,
        ):
            found[match.group(1)] = match.group(2)

    # 2. From HTTP response headers
    if headers:
        for k, v in headers.items():
            kl = k.lower()
            if kl in ("x-csrf-token", "x-xsrf-token", "anti-csrf-token", "csrf-token"):
                found[k] = v

    # 3. From cookies
    if cookies:
        for cname, cval in cookies.items():
            cl = cname.lower()
            if cl in ("xsrf-token", "csrftoken", "_csrf", "csrf_token"):
                found[cname] = cval

    return found


class SessionExpiryDetector:
    """Detects whether a server response indicates an expired or unauthenticated session."""

    @staticmethod
    def is_expired(
        status: int,
        headers: Dict[str, str],
        body: str,
        request_url: str,
    ) -> Tuple[bool, str]:
        # 1. Direct 401 or 403 status
        if status == 401:
            return True, "HTTP 401 Unauthorized"
        if status == 403:
            return True, "HTTP 403 Forbidden"

        # 2. Redirects to login routes
        if status in (301, 302, 303, 307, 308):
            loc = headers.get("location", "")
            if loc:
                parsed_loc = urlsplit(loc)
                loc_path = (parsed_loc.path or "").lower()
                for ind in _LOGIN_PATH_INDICATORS:
                    if ind in loc_path:
                        return True, f"Redirect to login endpoint: {loc}"

        # 3. HTTP 200 response containing login form on an authenticated endpoint
        req_path = urlsplit(request_url).path.lower()
        is_expected_login_page = any(ind in req_path for ind in _LOGIN_PATH_INDICATORS)
        if not is_expected_login_page and status == 200 and body:
            body_lower = body.lower()
            for pattern in _LOGIN_BODY_INDICATORS:
                if re.search(pattern, body_lower):
                    return True, f"Login form/indicator detected in body: {pattern}"

        return False, ""


class StatefulAuthCrawlerSession:
    """Manages full session state for crawling: cookies, CSRF, login and re-authentication."""

    def __init__(
        self,
        login_url: str,
        credentials: Dict[str, str],
        login_format: str = "form",  # "form" or "json"
        auth_headers: Optional[Dict[str, str]] = None,
        max_relogins: int = _MAX_RELOGINS_DEFAULT,
        login_success_indicator: Optional[str] = None,
    ) -> None:
        self.login_url = login_url
        self.credentials = credentials
        self.login_format = login_format
        self.custom_auth_headers = auth_headers or {}
        self.max_relogins = max_relogins
        self.login_success_indicator = login_success_indicator

        self.cookie_jar = CookieJar()
        self.csrf_tokens: Dict[str, str] = {}
        self.relogin_count = 0
        self.is_authenticated = False
        self.history: List[Dict[str, Any]] = []

    def prepare_request_headers(self, url: str) -> Dict[str, str]:
        """Generate headers with active session cookies, CSRF tokens, and auth headers."""
        headers: Dict[str, str] = {
            "User-Agent": "SHARAY-Crawler/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "close",
        }
        cookie_hdr = self.cookie_jar.get_cookie_header(url)
        if cookie_hdr:
            headers["Cookie"] = cookie_hdr

        # Include custom auth headers (e.g. Bearer token)
        for k, v in self.custom_auth_headers.items():
            headers[k] = v

        # Include anti-CSRF token header if known
        for tname, tval in self.csrf_tokens.items():
            tl = tname.lower()
            if "token" in tl:
                headers["X-CSRF-Token"] = tval
                break

        return headers

    def authenticate(
        self,
        fetcher: Callable[[str, str, Dict[str, str], Optional[bytes]], Tuple[int, Dict[str, str], str]],
        allow_ip: str,
    ) -> bool:
        """Execute full authentication sequence: harvest CSRF tokens, submit credentials, store session."""
        self.relogin_count += 1
        record: Dict[str, Any] = {
            "attempt": self.relogin_count,
            "login_url": self.login_url,
            "timestamp": time.time(),
        }

        # Step 1: Pre-flight GET to harvest initial CSRF token and set-cookie (e.g. PHPSESSID)
        pre_headers = {
            "User-Agent": "SHARAY-Crawler/1.0",
            "Accept": "text/html,*/*",
        }
        cookie_hdr = self.cookie_jar.get_cookie_header(self.login_url)
        if cookie_hdr:
            pre_headers["Cookie"] = cookie_hdr

        try:
            status, resp_headers, body = fetcher(self.login_url, "GET", pre_headers, None)
            for k, v in resp_headers.items():
                if k.lower() == "set-cookie":
                    self.cookie_jar.parse_set_cookie(v, self.login_url)

            # Extract CSRF token from login page
            discovered_tokens = extract_csrf_tokens(
                body, resp_headers, self.cookie_jar.export_dict()
            )
            self.csrf_tokens.update(discovered_tokens)
        except Exception as exc:
            record["preflight_error"] = str(exc)

        # Step 2: Prepare POST payload
        post_headers = {
            "User-Agent": "SHARAY-Crawler/1.0",
            "Connection": "close",
        }
        cookie_hdr = self.cookie_jar.get_cookie_header(self.login_url)
        if cookie_hdr:
            post_headers["Cookie"] = cookie_hdr

        payload_bytes: bytes
        if self.login_format == "json":
            post_headers["Content-Type"] = "application/json"
            post_data = dict(self.credentials)
            # Inject CSRF token into payload if available
            if self.csrf_tokens:
                best_csrf = next(iter(self.csrf_tokens.values()))
                post_data["_csrf"] = best_csrf
            payload_bytes = json.dumps(post_data).encode("utf-8")
        else:
            post_headers["Content-Type"] = "application/x-www-form-urlencoded"
            # Build form payload with CSRF token
            form_parts = [f"{k}={v}" for k, v in self.credentials.items()]
            for tk_name, tk_val in self.csrf_tokens.items():
                form_parts.append(f"{tk_name}={tk_val}")
            # Support DVWA 'Login=Login' button trigger
            if "Login" not in self.credentials and "login" not in self.credentials:
                form_parts.append("Login=Login")
            payload_bytes = "&".join(form_parts).encode("utf-8")

        # Step 3: Dispatch Login Request
        try:
            post_status, post_resp_headers, post_body = fetcher(
                self.login_url, "POST", post_headers, payload_bytes
            )
            for k, v in post_resp_headers.items():
                if k.lower() == "set-cookie":
                    self.cookie_jar.parse_set_cookie(v, self.login_url)

            # Check for JSON auth token
            if "application/json" in post_resp_headers.get("content-type", "").lower():
                try:
                    js = json.loads(post_body)
                    for token_key in ("token", "jwt", "access_token", "authToken"):
                        if token_key in js:
                            self.custom_auth_headers["Authorization"] = f"Bearer {js[token_key]}"
                            break
                        if isinstance(js.get("authentication"), dict) and "token" in js["authentication"]:
                            self.custom_auth_headers["Authorization"] = f"Bearer {js['authentication']['token']}"
                            break
                except Exception:
                    pass

            # Update CSRF tokens from login response
            new_tokens = extract_csrf_tokens(
                post_body, post_resp_headers, self.cookie_jar.export_dict()
            )
            self.csrf_tokens.update(new_tokens)

            # Verify authentication success:
            # 1. Status 302/303 redirect away from login page
            # 2. Or Status 200 with matching login_success_indicator
            # 3. Or Cookie jar populated and non-401/403
            success = False
            if post_status in (301, 302, 303, 307):
                loc = post_resp_headers.get("location", "")
                if not any(ind in loc.lower() for ind in _LOGIN_PATH_INDICATORS):
                    success = True
            elif post_status == 200:
                if self.login_success_indicator and self.login_success_indicator in post_body:
                    success = True
                elif bool(self.cookie_jar.export_dict()) or "Authorization" in self.custom_auth_headers:
                    # Check if login body didn't echo "Invalid credentials"
                    if "invalid" not in post_body.lower() and "incorrect" not in post_body.lower():
                        success = True

            self.is_authenticated = success
            record["status"] = post_status
            record["success"] = success
            self.history.append(record)
            return success
        except Exception as exc:
            record["error"] = str(exc)
            record["success"] = False
            self.history.append(record)
            self.is_authenticated = False
            return False

    def handle_response(
        self,
        url: str,
        status: int,
        headers: Dict[str, str],
        body: str,
        fetcher: Callable[[str, str, Dict[str, str], Optional[bytes]], Tuple[int, Dict[str, str], str]],
        allow_ip: str,
    ) -> Tuple[bool, bool]:
        """Processes response. Returns (is_session_valid, was_reauthenticated)."""
        # Ingest cookies
        for k, v in headers.items():
            if k.lower() == "set-cookie":
                self.cookie_jar.parse_set_cookie(v, url)

        # Ingest CSRF tokens
        new_csrf = extract_csrf_tokens(body, headers, self.cookie_jar.export_dict())
        self.csrf_tokens.update(new_csrf)

        expired, reason = SessionExpiryDetector.is_expired(status, headers, body, url)
        if not expired:
            return True, False

        # Attempt re-login if within quota
        if self.relogin_count < self.max_relogins:
            reauth_ok = self.authenticate(fetcher, allow_ip)
            return reauth_ok, True

        self.is_authenticated = False
        return False, False


def execute_network_request(
    url: str,
    method: str,
    headers: Dict[str, str],
    body_bytes: Optional[bytes],
    allow_ip: str,
    timeout: float = 5.0,
) -> Tuple[int, Dict[str, str], str]:
    """Issues pinned HTTP/HTTPS request honoring target IP and custom headers."""
    parsed = urlsplit(url)
    target_host = parsed.hostname or allow_ip
    target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    is_https = parsed.scheme == "https"
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    req_headers = dict(headers)
    if "Host" not in req_headers:
        req_headers["Host"] = target_host
    if "Connection" not in req_headers:
        req_headers["Connection"] = "close"

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
        conn.request(method, path, body=body_bytes, headers=req_headers)
        resp = conn.getresponse()
        resp_status = resp.status
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        resp_body = resp.read(_DEFAULT_MAX_PAGE_BYTES).decode("utf-8", errors="replace")
        return resp_status, resp_headers, resp_body
    finally:
        conn.close()


class StatefulAuthenticatedCrawler:
    """Complete authenticated crawler maintaining session lifecycle across crawling runs."""

    def __init__(
        self,
        base_url: str,
        allow_ip: str,
        auth_session: Optional[StatefulAuthCrawlerSession] = None,
        max_depth: int = 3,
        max_pages: int = 50,
        timeout: float = 5.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.allow_ip = allow_ip
        self.auth_session = auth_session
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout

        parsed = urlsplit(self.base_url)
        self.target_host = parsed.hostname or allow_ip
        self.target_scheme = parsed.scheme or "http"
        self.target_port = parsed.port or (443 if self.target_scheme == "https" else 80)

    def fetch(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body_bytes: Optional[bytes] = None,
    ) -> Tuple[int, Dict[str, str], str]:
        all_headers = {}
        if self.auth_session:
            all_headers = self.auth_session.prepare_request_headers(url)
        if headers:
            all_headers.update(headers)
        return execute_network_request(
            url=url,
            method=method,
            headers=all_headers,
            body_bytes=body_bytes,
            allow_ip=self.allow_ip,
            timeout=self.timeout,
        )

    def run(self) -> Dict[str, Any]:
        """Executes crawl with pre-authentication, session persistence, and re-login on expiry."""
        # 1. Pre-authenticate if session configured
        if self.auth_session:
            fetcher = lambda u, m, h, b: execute_network_request(u, m, h, b, self.allow_ip, self.timeout)
            self.auth_session.authenticate(fetcher, self.allow_ip)

        visited: Set[str] = set()
        queue: List[Tuple[str, int]] = [(self.base_url, 0)]
        discovered_endpoints: Set[str] = set()
        authenticated_endpoints: Set[str] = set()
        discovered_forms: List[Dict[str, Any]] = []
        pages_crawled: List[Dict[str, Any]] = []
        reauth_events: List[Dict[str, Any]] = []

        fetcher = lambda u, m, h, b: execute_network_request(u, m, h, b, self.allow_ip, self.timeout)

        while queue and len(visited) < self.max_pages:
            current_url, depth = queue.pop(0)
            parsed = urlparse(current_url)
            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                clean_url = f"{clean_url}?{parsed.query}"

            if clean_url in visited:
                continue
            visited.add(clean_url)
            discovered_endpoints.add(parsed.path or "/")

            try:
                status, headers, body = self.fetch(clean_url)
            except Exception as exc:
                pages_crawled.append({"url": clean_url, "status": 0, "error": str(exc)})
                continue

            # Process session response & check expiry
            if self.auth_session:
                is_valid, was_reauthed = self.auth_session.handle_response(
                    clean_url, status, headers, body, fetcher, self.allow_ip
                )
                if was_reauthed:
                    reauth_events.append({"url": clean_url, "status": status, "reauth_ok": is_valid})
                    # Retry request with renewed session
                    if is_valid:
                        status, headers, body = self.fetch(clean_url)

                if self.auth_session.is_authenticated and status == 200:
                    authenticated_endpoints.add(parsed.path or "/")

            pages_crawled.append({"url": clean_url, "status": status, "depth": depth})

            # Extract links and forms
            content_type = headers.get("content-type", "")
            if "html" in content_type or "<html" in body.lower():
                from packages.scanner_adapters.integrations.crawler import (
                    _HTMLStructureExtractor,
                    _is_in_scope,
                )

                extractor = _HTMLStructureExtractor(clean_url)
                try:
                    extractor.feed(body)
                except Exception:
                    pass

                for form in extractor.forms:
                    form_action = form.get("action", "")
                    if _is_in_scope(form_action, self.target_host, self.target_scheme):
                        discovered_forms.append(form)

                if depth < self.max_depth:
                    for link in extractor.links:
                        if _is_in_scope(link, self.target_host, self.target_scheme):
                            p = urlparse(link)
                            c_link = f"{p.scheme}://{p.netloc}{p.path}"
                            if p.query:
                                c_link = f"{c_link}?{p.query}"
                            if c_link not in visited:
                                queue.append((c_link, depth + 1))

        return {
            "pages_visited": len(visited),
            "discovered_endpoints": sorted(discovered_endpoints),
            "authenticated_endpoints": sorted(authenticated_endpoints),
            "forms": discovered_forms,
            "reauth_events": reauth_events,
            "session_active": self.auth_session.is_authenticated if self.auth_session else False,
            "cookies": self.auth_session.cookie_jar.export_dict() if self.auth_session else {},
            "csrf_tokens": self.auth_session.csrf_tokens if self.auth_session else {},
            "pages": pages_crawled,
        }
