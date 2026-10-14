import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { laboratoryScope, localDateTime } from "../app/api.ts";

const future = () => new Date(Date.now() + 3_600_000).toISOString();

test("scope preview preserves the explicit target boundary and safe profile", () => {
  const scope = laboratoryScope("http://127.0.0.1:8766/application", "/application\n/api", "/api/private", future());
  assert.deepEqual(scope.allowed_origins, ["http://127.0.0.1:8766"]);
  assert.deepEqual(scope.allowed_paths, ["/application", "/api"]);
  assert.deepEqual(scope.excluded_paths, ["/api/private"]);
  assert.deepEqual(scope.allowed_cidrs, ["127.0.0.1/32"]);
  assert.equal(scope.intrusive, false);
  assert.equal(scope.authenticated, false);
  assert.equal(scope.approval_required, true);
});

test("scope preview accepts broader inventory without manufacturing loopback ranges", () => {
  for (const [url, host] of [["https://example.com/", "example.com"], ["http://localhost:3000/", "localhost"], ["http://192.168.1.1/", "192.168.1.1"], ["https://[2001:db8::1]/", "2001:db8::1"]]) {
    const scope = laboratoryScope(url, "/", "", future());
    assert.deepEqual(scope.hosts, [host]);
    assert.deepEqual(scope.allowed_cidrs, []);
  }
});

test("scope preview rejects malformed hosts and ambiguous URLs", () => {
  for (const url of ["http://127.1/", "http://2130706433/", "http://example.0xabc/", "http://example.com./", "http://bad_host.example/", "http://[::ffff:127.0.0.1]/", "http://127.0.0.1/?token=secret", "http://user:password@127.0.0.1/", "http://127.0.0.1/#fragment", "ftp://127.0.0.1/"]) {
    assert.throws(() => laboratoryScope(url, "/", "", future()));
  }
});

test("broader edits preserve reviewed address ranges and reset only a changed origin", () => {
  const original = laboratoryScope("HTTP://example.com/", "/", "", future());
  original.allowed_cidrs = ["192.168.1.0/24"];
  original.categories = ["http_headers"];
  original.request_rate = 10;
  original.max_concurrency = 5;
  const preserved = laboratoryScope("http://example.com/app", "/app", "", original.expires_at, original, original.starts_at);
  assert.deepEqual(preserved.allowed_cidrs, original.allowed_cidrs);
  assert.deepEqual(preserved.categories, original.categories);
  assert.equal(preserved.request_rate, 10);
  assert.equal(preserved.max_concurrency, 5);
  const replaced = laboratoryScope("http://other.example/", "/", "", original.expires_at, original, original.starts_at);
  assert.deepEqual(replaced.hosts, ["other.example"]);
  assert.deepEqual(replaced.allowed_cidrs, []);
  assert.deepEqual(original.allowed_cidrs, ["192.168.1.0/24"]);
});

test("IPv6 laboratory scope is explicit and expiration is mandatory", () => {
  const scope = laboratoryScope("https://[::1]:8766/", "/", "", future());
  assert.deepEqual(scope.hosts, ["::1"]);
  assert.deepEqual(scope.allowed_cidrs, ["::1/128"]);
  assert.throws(() => laboratoryScope("http://127.0.0.1/", "relative/path", "", future()));
  assert.throws(() => laboratoryScope("http://127.0.0.1/", "/", "", "invalid"));
  assert.throws(() => laboratoryScope("http://127.0.0.1/", "/", "", "2020-01-01T00:00:00Z"));
});

test("scope edits preserve policy fields and unchanged validity at full precision", () => {
  const original = laboratoryScope("http://127.0.0.1:8766/", "/\n/api", "/private", future());
  original.categories = ["http_headers"];
  original.request_rate = 0.5;
  original.allowed_origins.push("http://127.0.0.1:8767");
  const unchanged = laboratoryScope("http://127.0.0.1:8766/", "/\n/api", "/private", localDateTime(original.expires_at), original, localDateTime(original.starts_at));
  assert.deepEqual(unchanged, original);
  const edited = laboratoryScope("http://127.0.0.1:8766/api", "/api", "/api/private", localDateTime(original.expires_at), original, localDateTime(original.starts_at));
  assert.deepEqual(edited.categories, ["http_headers"]);
  assert.equal(edited.request_rate, 0.5);
  assert.deepEqual(edited.allowed_origins, original.allowed_origins);
  assert.deepEqual(original.allowed_paths, ["/", "/api"]);
});

test("untouched API timestamps preserve all six fractional digits", () => {
  const starts = new Date(Date.now() - 1000).toISOString().replace(/\.\d{3}Z$/, ".123456Z");
  const expires = future().replace(/\.\d{3}Z$/, ".654321Z");
  const original = { ...laboratoryScope("http://127.0.0.1:8766/", "/", "", expires, undefined, starts), starts_at: starts, expires_at: expires };
  const unchanged = laboratoryScope("http://127.0.0.1:8766/", "/", "", localDateTime(expires), original, localDateTime(starts));
  assert.deepEqual(unchanged, original);
});

test("validity review rejects reversed and longer than 24-hour windows", () => {
  const starts = new Date(Date.now() + 3_600_000).toISOString();
  assert.throws(() => laboratoryScope("http://127.0.0.1/", "/", "", future(), undefined, "invalid"));
  assert.throws(() => laboratoryScope("http://127.0.0.1/", "/", "", new Date(new Date(starts).getTime() - 1000).toISOString(), undefined, starts));
  assert.throws(() => laboratoryScope("http://127.0.0.1/", "/", "", new Date(new Date(starts).getTime() + 86_400_001).toISOString(), undefined, starts));
});

test("scope review rejects a validity window that has not started", () => {
  const starts = new Date(Date.now() + 600_000).toISOString();
  const expires = new Date(Date.now() + 3_600_000).toISOString();
  assert.throws(() => laboratoryScope("http://127.0.0.1/", "/", "", expires, undefined, starts));
});

test("scope review rejects ambiguous paths and targets outside their paths", () => {
  for (const path of ["/api;v=1", "/api%3bv=1", "/../private", "/%2e%2e/private", "/a//b", "/a\\b", "/a%2fb", "/bad%", "/bad%00", "/bad%252f"]) {
    assert.throws(() => laboratoryScope("http://127.0.0.1/", path, "", future()), path);
    assert.throws(() => laboratoryScope("http://127.0.0.1/", "/", path, future()), path);
    assert.throws(() => laboratoryScope("http://127.0.0.1" + path, "/", "", future()), path);
  }
  assert.throws(() => laboratoryScope("http://127.0.0.1/app", "/api", "", future()));
  assert.throws(() => laboratoryScope("http://127.0.0.1/api/private", "/api", "/api/private", future()));
  assert.throws(() => laboratoryScope("http://127.0.0.1/apix", "/api", "", future()));
  for (const url of ["http://127.0.0.1/?", "http://127.0.0.1/#", "http://0177.0.0.1/", "http://127.0.0.1:0/"]) {
    assert.throws(() => laboratoryScope(url, "/", "", future()), url);
  }
});

test("scope review matches normalized path boundaries without losing encoded data", () => {
  const scope = laboratoryScope("http://127.0.0.1/app/caf%C3%A9", "/app/", "/app/private", future());
  assert.deepEqual(scope.allowed_paths, ["/app/"]);
  assert.deepEqual(scope.excluded_paths, ["/app/private"]);
  const encoded = laboratoryScope("http://127.0.0.1/%3F", "/%3F", "", future());
  assert.deepEqual(encoded.allowed_paths, ["/%3F"]);
});

test("an unchanged scope retains the instant during a repeated daylight-saving hour", () => {
  const run = spawnSync(process.execPath, ["--experimental-strip-types", "--input-type=module", "-e", `
    import assert from "node:assert/strict";
    import { laboratoryScope, localDateTime } from ${JSON.stringify(new URL("../app/api.ts", import.meta.url).href)};
    const year = new Date().getFullYear() + 1;
    const sunday = 1 + (7 - new Date(Date.UTC(year, 10, 1)).getUTCDay()) % 7;
    const starts = new Date(Date.UTC(year, 10, sunday, 6, 30)).toISOString();
    const expires = new Date(Date.UTC(year, 10, sunday, 6, 50)).toISOString();
    const NativeDate = Date;
    globalThis.Date = class extends NativeDate {
      constructor(value) { super(value === undefined ? Date.UTC(year, 10, sunday, 6, 35) : value); }
    };
    const scope = laboratoryScope("http://127.0.0.1/", "/", "", expires, undefined, starts);
    assert.deepEqual(laboratoryScope("http://127.0.0.1/", "/", "", localDateTime(expires), scope, localDateTime(starts)), scope);
  `], { env: { ...process.env, TZ: "America/New_York" }, encoding: "utf8", timeout: 5000 });
  assert.ifError(run.error);
  assert.equal(run.status, 0, run.stderr);
});
