"""Sector O9: large-surface handling -- route-template dedup, prioritization, discovery ingestion,
adaptive rate control, and resumable crawl state.

On a big site the budget must hit where bugs live, not a flat sample. These are pure, deterministic
helpers: collapse thousands of URLs to route templates, rank the surface by risk signals, ingest
sitemap/robots, back off on throttling, and checkpoint/resume a crawl.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_LONGHEX = re.compile(r"^[0-9a-f]{12,}$", re.I)


def _templatize_segment(seg: str) -> str:
    if not seg:
        return seg
    if seg.isdigit() or _UUID.match(seg) or _LONGHEX.match(seg):
        return "{id}"
    # slug-with-trailing-number, e.g. product-12345 -> product-{id}
    if re.search(r"\d{3,}$", seg):
        return re.sub(r"\d{3,}$", "{id}", seg)
    return seg


def route_template(url: str) -> str:
    """Collapse variable path segments to {id} so /user/1 and /user/2 share one template."""
    parts = urlsplit(url)
    path = "/".join(_templatize_segment(s) for s in parts.path.split("/"))
    q = "?" + "&".join(sorted(k for k in (kv.split("=", 1)[0] for kv in parts.query.split("&")) if k)) if parts.query else ""
    return f"{parts.scheme}://{parts.netloc}{path}{q}"


def dedupe_route_templates(urls: list[str]) -> list[str]:
    """Return one representative URL per distinct route template (order-preserving)."""
    seen: set[str] = set()
    out: list[str] = []
    for u in urls:
        t = route_template(u)
        if t not in seen:
            seen.add(t)
            out.append(u)
    return out


_HIGH_PATH = ("admin", "login", "auth", "account", "token", "password", "secret", "config", "debug", "console")
_API_PATH = ("/api", "graphql", "/v1", "/v2", "/rest", "/rpc")
_FILE_PATH = ("upload", "import", "export", "download", "attachment", "file", "avatar", "backup")
_WRITE_PATH = ("delete", "update", "edit", "create", "save", "remove", "reset")
_ID_PARAM = ("id", "uid", "user", "pid", "order", "doc", "file", "path", "url", "page", "ref")


def surface_score(url: str) -> int:
    parts = urlsplit(url)
    path = parts.path.lower()
    query = parts.query.lower()
    score = 0
    if query:
        score += 5
    if any(k in path for k in _HIGH_PATH):
        score += 4
    if any(k in path for k in _API_PATH):
        score += 3
    if any(k in path for k in _FILE_PATH):
        score += 3
    if any(k in path for k in _WRITE_PATH):
        score += 2
    param_names = {kv.split("=", 1)[0] for kv in query.split("&") if kv}
    if param_names & set(_ID_PARAM):
        score += 2
    if path.count("/") > 3:
        score += 1
    return score


def prioritize_surface(urls: list[str]) -> list[str]:
    """Rank a (deduped) surface so a bounded budget tests the high-value endpoints first.

    Stable sort by descending risk score; ties keep discovery order.
    """
    deduped = dedupe_route_templates(urls)
    ranked = sorted(enumerate(deduped), key=lambda t: (-surface_score(t[1]), t[0]))
    return [u for _, u in ranked]


def parse_sitemap(xml: bytes) -> list[str]:
    """Extract <loc> URLs from a sitemap.xml (handles urlset and sitemapindex)."""
    text = xml.decode("utf-8", "replace")
    return [m.strip() for m in re.findall(r"<loc>\s*(.*?)\s*</loc>", text, re.I | re.S) if m.strip()]


def parse_robots(txt: bytes) -> dict[str, list[str]]:
    """Parse robots.txt into allow/disallow/sitemap lists. Disallowed paths are often the juicy ones."""
    allow: list[str] = []
    disallow: list[str] = []
    sitemaps: list[str] = []
    for raw in txt.decode("utf-8", "replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "disallow" and value:
            disallow.append(value)
        elif key == "allow" and value:
            allow.append(value)
        elif key == "sitemap" and value:
            sitemaps.append(value)
    return {"allow": allow, "disallow": disallow, "sitemaps": sitemaps}


@dataclass
class AdaptiveRateController:
    """Per-origin adaptive pacing: back off on throttling/5xx, speed up on sustained success."""

    base_interval: float = 0.1
    min_interval: float = 0.02
    max_interval: float = 5.0
    interval: float = 0.1
    _success_streak: int = 0

    def observe(self, status: int) -> float:
        if status in (429, 503) or status >= 500:
            self._success_streak = 0
            self.interval = min(self.max_interval, max(self.base_interval, self.interval) * 1.8)
        else:
            self._success_streak += 1
            if self._success_streak >= 5:
                self.interval = max(self.min_interval, self.interval * 0.8)
                self._success_streak = 0
        return self.interval


@dataclass
class ResumableSurfaceState:
    """Checkpointable crawl frontier so a large assessment can resume where it left off."""

    visited: set[str] = field(default_factory=set)
    pending: list[str] = field(default_factory=list)

    def add(self, url: str) -> None:
        t = route_template(url)
        if t not in self.visited and url not in self.pending:
            self.pending.append(url)

    def next_batch(self, n: int) -> list[str]:
        batch = self.pending[:n]
        self.pending = self.pending[n:]
        for u in batch:
            self.visited.add(route_template(u))
        return batch

    def to_dict(self) -> dict[str, Any]:
        return {"visited": sorted(self.visited), "pending": list(self.pending)}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ResumableSurfaceState":
        return cls(visited=set(data.get("visited", [])), pending=list(data.get("pending", [])))


__all__ = [
    "route_template",
    "dedupe_route_templates",
    "surface_score",
    "prioritize_surface",
    "parse_sitemap",
    "parse_robots",
    "AdaptiveRateController",
    "ResumableSurfaceState",
]
