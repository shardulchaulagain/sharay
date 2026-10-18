"""Reference implementation of enhanced SPARouteExtractor for Claude to adopt in browser.py."""

import re


class EnhancedSPARouteExtractor:
    """Discovers dynamic Single Page Application (SPA) routes from client-side bundles."""

    ROUTE_PATTERNS = [
        # Angular and Vue route definitions (e.g. path: 'score-board', path: '/score-board')
        re.compile(r"""(?:path|to)\s*:\s*["']([a-zA-Z0-9_\-/{}:]+)["']""", re.IGNORECASE),
        # React Route components
        re.compile(r"""<Route\s+[^>]*path=["']([a-zA-Z0-9_\-/{}:]+)["']""", re.IGNORECASE),
        # History pushState / replaceState
        re.compile(
            r"""history\.(?:pushState|replaceState)\s*\([^,]+,[^,]+,["']([a-zA-Z0-9_\-/{}:]+)["']""",
            re.IGNORECASE,
        ),
        # API and REST endpoints (versioned and unversioned)
        re.compile(r"""["'](/(?:api|rest|v[0-9]+)/[^"'\s]+)["']""", re.IGNORECASE),
        # Hash navigation (e.g. #/score-board, router.navigate(['#/tokens']))
        re.compile(r"""(?:href|hash|url)\s*[:=]\s*["']#?/([a-zA-Z0-9_\-/{}:]+)["']""", re.IGNORECASE),
        re.compile(r"""["'](#/[a-zA-Z0-9_\-/{}:]+)["']""", re.IGNORECASE),
    ]

    def extract_routes(self, content: str, base_url: str = "") -> list[str]:
        routes: set[str] = set()
        for pattern in self.ROUTE_PATTERNS:
            for match in pattern.finditer(content):
                raw_match = match.group(1).strip()
                # Clean query parameters or string concatenations if present
                route = raw_match.split("?")[0].strip()
                if route.startswith("#/"):
                    route = route[1:]  # normalize '#/score-board' -> '/score-board'
                elif not route.startswith("/"):
                    route = f"/{route}"

                # Ignore file extensions and image assets
                if not any(
                    route.endswith(ext)
                    for ext in (
                        ".png",
                        ".jpg",
                        ".jpeg",
                        ".gif",
                        ".css",
                        ".js",
                        ".svg",
                        ".ico",
                        ".woff",
                        ".woff2",
                        ".ttf",
                    )
                ):
                    routes.add(route)
        return sorted(routes)
