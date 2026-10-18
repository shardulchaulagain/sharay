# Reconnaissance parsers (L5) — TLS, DNS, asset inventory

Parsers in `packages/scanner_adapters/integrations/` that turn already-collected reconnaissance
data into validated observations and discovered assets. **No probe or lookup happens here**: every
function takes supplied bytes/structures, exactly like the scanner report parsers. Live DNS/TLS/HTTP
reconnaissance needs network, which the loopback-only backend does not grant, so collection is not
wired; these cover the parsing, validation and asset rollup. Nothing here authorizes contact with
any asset. Tests: `tests/integration/test_tls.py`, `test_dns.py`, `test_recon.py`.

| Module | Call | Returns |
| --- | --- | --- |
| `tls` | `parse_peer_certificate(cert_dict, *, now_epoch=None)` | from an `ssl.getpeercert()` dict: `subject_cn`, `issuer_cn`, validated `sans` (`dns`/`ip`), `not_before`/`not_after` (epoch), `self_signed`, `expired`, `not_yet_valid`, `days_until_expiry`, `fingerprint` |
| `dns` | `parse_records(answers)` | from `[{"name","type","data","ttl"}]`: validated `records` (A→IPv4, AAAA→IPv6, CNAME/NS/PTR→host, MX→pref+host, TXT/SOA/CAA→bounded text) plus `assets` (`hostnames`/`ips`) and `truncated` |
| `recon` | `collect_assets([{"source","hostnames","ips"}])` | one deduplicated asset list, each `{value, kind, sources[]}`, merging TLS SANs / DNS assets / nmap hosts with provenance |

Shared rules: a malformed field or unknown record type rejects the batch rather than being
guessed at; hostnames are validated, lowercased and de-duplicated and IPs normalised; TXT and
certificate text pass through redaction and length bounds (SPF/DKIM tokens, odd CNs); counts are
bounded. `recon.collect_assets` is recon output for scoping and review — **not** the control
plane's authorized-target inventory (C3).
