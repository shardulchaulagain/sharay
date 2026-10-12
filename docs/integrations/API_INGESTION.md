# API description ingestion (L3) — OpenAPI endpoint inventory

`packages/scanner_adapters/integrations/openapi.ingest(path)` reads one supplied OpenAPI 3.0/3.1 **JSON** file and returns what the document declares. It sends no request and contacts nothing, so every result is a statement about the document, not about a running service; the result's `basis` field says so. It is **not connected to the product**: no upload endpoint, no dispatch, no category. Tests: `tests/integration/test_openapi_ingestion.py`.

| Output | Meaning |
| --- | --- |
| `endpoints` | Method, path template, operation id, parameters (name, place, required), whether a request body is declared, whether deprecated, and the operation's effective declared authentication: `required`, `optional` (an empty alternative is allowed), `none`, or `unknown` when the requirement is malformed. An operation's own `security`, including an empty list, replaces the document default. |
| `security_schemes` | Name and type facts of each declared scheme. |
| `servers` | Scheme and host only. Credentials, paths and query strings in server URLs are never returned. |
| `observations` | Declared facts worth a reviewer's attention, each tied to an operation: no authentication declared, optional authentication, API key carried in the query string, HTTP Basic, a reference to an undefined scheme, a server declared over plain HTTP. These are not findings and not vulnerabilities. |
| `unresolved` | Everything not understood, with a fixed reason: malformed operations or parameters, external or chained references, relative or templated servers. A rejected path key is never echoed, since it can carry a query-string token. |

Descriptions, examples and other free text are never returned, because API descriptions often contain sample credentials; a test plants one secret in four places and asserts it is absent from the output.

Limits: YAML is not read (no YAML parser is installed; adding one is a dependency decision); Swagger 2.0 is reported as unsupported, not converted; only local `#/components/...` references are followed, one level deep; schemas and response bodies are not analysed. Input must be a regular file of at most 5 MiB.
