import assert from "node:assert/strict";
import { test } from "node:test";
import { laboratoryScope } from "../app/api.ts";

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

test("scope preview rejects non-laboratory destinations and ambiguous URLs", () => {
  for (const url of ["http://example.com/", "http://localhost/", "http://192.168.1.1/", "http://127.0.0.1/?token=secret", "http://user:password@127.0.0.1/", "http://127.0.0.1/#fragment", "ftp://127.0.0.1/"]) {
    assert.throws(() => laboratoryScope(url, "/", "", future()));
  }
});

test("IPv6 laboratory scope is explicit and expiration is mandatory", () => {
  const scope = laboratoryScope("https://[::1]:8766/", "/", "", future());
  assert.deepEqual(scope.hosts, ["::1"]);
  assert.deepEqual(scope.allowed_cidrs, ["::1/128"]);
  assert.throws(() => laboratoryScope("http://127.0.0.1/", "relative/path", "", future()));
  assert.throws(() => laboratoryScope("http://127.0.0.1/", "/", "", "invalid"));
  assert.throws(() => laboratoryScope("http://127.0.0.1/", "/", "", "2020-01-01T00:00:00Z"));
});
