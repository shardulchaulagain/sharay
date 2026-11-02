import assert from "node:assert/strict";
import test from "node:test";
import * as api from "../app/api.ts";

test("project fields trim the name and preserve the complete editable description", () => {
  assert.deepEqual(api.projectFields("  Recovery workspace  ", "Line one\n  Line two  "), {
    name: "Recovery workspace", description: "Line one\n  Line two  ",
  });
  assert.deepEqual(api.projectFields("Project", ""), { name: "Project", description: "" });
  assert.equal(api.projectFields("n".repeat(160), "d".repeat(4000)).description.length, 4000);
});

test("invalid project fields fail with corrective errors before any request", () => {
  for (const name of ["", "  \t ", "n".repeat(161)]) {
    assert.throws(() => api.projectFields(name, ""), /name/i);
  }
  assert.throws(() => api.projectFields("Project", "d".repeat(4001)), /description/i);
});

test("project character limits match backend Unicode code points", () => {
  const name = "🧪".repeat(160), description = "🧪".repeat(4000);
  assert.deepEqual(api.projectFields(name, description), { name, description });
  assert.throws(() => api.projectFields(`${name}x`, ""), /name/i);
  assert.throws(() => api.projectFields("Project", `${description}x`), /description/i);
});

test("project metadata patch uses the existing authenticated API and keeps errors observable", async () => {
  const oldFetch = globalThis.fetch;
  const calls: Array<{ url: string; options: RequestInit }> = [];
  api.setCsrf("synthetic-csrf");
  try {
    globalThis.fetch = async (url, options = {}) => {
      calls.push({ url: String(url), options });
      return new Response(JSON.stringify({ id: "fixture", name: "Updated", description: "", archived: false }), { status: 200 });
    };
    await api.api("/projects/fixture", { method: "PATCH", body: JSON.stringify(api.projectFields(" Updated ", "")) });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "/api/v1/projects/fixture");
    assert.equal(calls[0].options.method, "PATCH");
    assert.equal(calls[0].options.credentials, "same-origin");
    assert.equal(new Headers(calls[0].options.headers).get("X-CSRF-Token"), "synthetic-csrf");
    assert.deepEqual(JSON.parse(String(calls[0].options.body)), { name: "Updated", description: "" });
    globalThis.fetch = async () => new Response(JSON.stringify({ detail: "Role cannot manage projects" }), { status: 403 });
    await assert.rejects(api.api("/projects/fixture", { method: "PATCH", body: "{}" }), /Role cannot manage projects/);
  } finally {
    globalThis.fetch = oldFetch;
    api.setCsrf("");
  }
});
