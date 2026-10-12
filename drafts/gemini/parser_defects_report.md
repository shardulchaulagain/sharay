# Security & Reliability Bug Report: Scanner Report Parsers

Author: Gemini (Principal Architect, Debugger & Helper)  
Target: Claude (L3/L6 Integration Owner) & Codex (C8 Platform Verification)  
Status: Evidenced Defect Report in `drafts/gemini/`  

---

### Defect 1: Windows `source_root` Backslashes Break `relative_path` in Gitleaks & Semgrep

- **Affected File**: `packages/scanner_adapters/integrations/_parsing.py` (line 54)
- **Callers Affected**: `packages/scanner_adapters/integrations/gitleaks.py` (line 28), `packages/scanner_adapters/integrations/semgrep.py` (line 47)
- **Root Cause**:
  In `_parsing.relative_path(value, what, source_root)`:
  ```python
  path = text(value, what, 500).replace("\\", "/")
  if source_root and path.startswith(source_root.rstrip("/") + "/"):
      path = path[len(source_root.rstrip("/")) + 1 :]
  ```
  `path` is normalized by converting backslashes to slashes, but `source_root` is left untouched. When callers pass a native Windows path (e.g. `source_root=r"C:\project"`), `path.startswith(r"C:\project/")` evaluates to `False`. The path is not made relative, and line 57:
  ```python
  if path.startswith("/") or ":" in parts[0] or any(part in ("", "..") for part in parts):
      raise ValueError(f"{what} is absolute, empty or leaves the scanned tree.")
  ```
  detects the Windows drive letter colon (`C:`) in `parts[0]` and raises `ValueError: Gitleaks File is absolute, empty or leaves the scanned tree.`
- **Reproduction**:
  Verified by `drafts/gemini/attack-tests/test_defect_parsers.py::ParserDefectTests::test_defect_1_windows_source_root_relative_path`.
  Command: `.venv/bin/python -m pytest drafts/gemini/attack-tests/test_defect_parsers.py -k test_defect_1` (exit 0).
- **Smallest Correct Fix**:
  ```diff
  --- a/packages/scanner_adapters/integrations/_parsing.py
  +++ b/packages/scanner_adapters/integrations/_parsing.py
  @@ -53,4 +53,5 @@ def relative_path(value: Any, what: str, source_root: str = "") -> str:
       path = text(value, what, 500).replace("\\", "/")
  -    if source_root and path.startswith(source_root.rstrip("/") + "/"):
  -        path = path[len(source_root.rstrip("/")) + 1 :]
  +    root = source_root.replace("\\", "/").rstrip("/") if source_root else ""
  +    if root and path.startswith(root + "/"):
  +        path = path[len(root) + 1 :]
       parts = path.split("/")
  ```

---

### Defect 2: Nuclei `_location` Falsely Rejects Bare IPv6 Locations in Network/DNS Templates

- **Affected File**: `packages/scanner_adapters/integrations/nuclei.py` (lines 43–48)
- **Root Cause**:
  In `nuclei._location(value)`:
  ```python
  if "://" not in raw:
      # Network and DNS templates report a bare host or host:port.
      name, _, digits = raw.partition(":")
      if not _HOST.match(name) or (":" in raw and not digits.isdigit()):
          raise ValueError("Nuclei matched-at is not a URL or host:port.")
      return name + _port(int(digits) if digits else None)
  ```
  Nuclei network, TCP, SSL, and DNS templates report target locations as bare host/port pairs, e.g. `[::1]:22`, `[2001:db8::1]:53`, or `::1`.
  `partition(":")` splits on the first colon, producing `name = "["` and `digits = ":1]:22"` (or `name = ""` and `digits = ":1"`). Because `_HOST.match(name)` requires alphanumeric hostname characters and `digits.isdigit()` is false, all bare IPv6 addresses trigger a false-positive rejection:
  `ValueError: Nuclei matched-at is not a URL or host:port.`
- **Reproduction**:
  Verified by `drafts/gemini/attack-tests/test_defect_parsers.py::ParserDefectTests::test_defect_2_nuclei_location_bare_ipv6_rejected`.
  Command: `.venv/bin/python -m pytest drafts/gemini/attack-tests/test_defect_parsers.py -k test_defect_2` (exit 0).
- **Smallest Correct Fix**:
  ```diff
  --- a/packages/scanner_adapters/integrations/nuclei.py
  +++ b/packages/scanner_adapters/integrations/nuclei.py
  @@ -11,2 +11,3 @@
  +import ipaddress
   import re
  @@ -44,7 +45,24 @@ def _location(value: object) -> str:
       if "://" not in raw:
  -        # Network and DNS templates report a bare host or host:port.
  +        # Handle bracketed IPv6: [::1]:22 or [::1]
  +        if raw.startswith("["):
  +            inside, _, rest = raw[1:].partition("]")
  +            try:
  +                ip = ipaddress.IPv6Address(inside)
  +            except ValueError:
  +                raise ValueError("Nuclei matched-at is not a URL or host:port.")
  +            port_val = None
  +            if rest.startswith(":"):
  +                port_str = rest[1:]
  +                if not port_str.isdigit():
  +                    raise ValueError("Nuclei matched-at has a port outside 1-65535.")
  +                port_val = int(port_str)
  +            elif rest:
  +                raise ValueError("Nuclei matched-at is not a URL or host:port.")
  +            return f"[{ip}]{_port(port_val)}"
  +        try:
  +            ip = ipaddress.ip_address(raw)
  +            return f"[{ip}]" if ip.version == 6 else str(ip)
  +        except ValueError:
  +            pass
           name, _, digits = raw.partition(":")
           if not _HOST.match(name) or (":" in raw and not digits.isdigit()):
  ```

---

### Verification
- Both defects reproduce deterministically:
  ```sh
  .venv/bin/python -m pytest drafts/gemini/attack-tests/test_defect_parsers.py -v
  ```
  Result: 2 passed in 0.09s.
