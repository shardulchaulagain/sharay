import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import process from "node:process";
import { test } from "node:test";
import { setImmediate } from "node:timers";
import { URL } from "node:url";

const require = createRequire(import.meta.url);
const ts = require("typescript"), React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
const cache = new Map();

// Execute the actual handlers with controlled hooks and transport. Only these
// reviewed local modules load; no DOM dependency or production export is added.
function load(name) {
  if (cache.has(name)) return cache.get(name).exports;
  const module = { exports: {} }; cache.set(name, module);
  let source = readFileSync(new URL(`../app/${name}.${name === "api" ? "ts" : "tsx"}`, import.meta.url), "utf8");
  if (name === "assessments") source += "\nexport { AssessmentDetail };";
  if (name === "projects") source += "\nexport { TargetRegistration, TargetRow, Launch };";
  const code = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX } }).outputText;
  new Function("require", "module", "exports", code)(id => id.startsWith("./") ? load(id.slice(2)) : require(id), module, module.exports);
  return module.exports;
}

function nodes(value, found = []) {
  if (Array.isArray(value)) for (const item of value) nodes(item, found);
  else if (React.isValidElement(value)) { found.push(value); nodes(value.props.children, found); nodes(value.props.action, found); }
  return found;
}
function text(value) {
  if (typeof value === "string" || typeof value === "number") return String(value);
  if (Array.isArray(value)) return value.map(text).join("");
  return React.isValidElement(value) ? text(value.props.children) : "";
}
const button = (tree, label) => nodes(tree).find(node => node.type === "button" && text(node.props.children) === label);

function controlledState() {
  const original = React.useState;
  const values = []; let cursor = 0;
  React.useState = initial => {
    const index = cursor++;
    if (!(index in values)) values[index] = typeof initial === "function" ? initial() : initial;
    return [values[index], next => { values[index] = typeof next === "function" ? next(values[index]) : next; }];
  };
  return { render: callback => { cursor = 0; return callback(); }, restore: () => { React.useState = original; } };
}

test("failed retest reload invalidates its captured review until a new fetch succeeds", async () => {
  const assessments = load("assessments"), components = load("components"), api = load("api");
  const now = Date.now();
  const scope = api.laboratoryScope("http://127.0.0.1:8766/", "/", "", new Date(now + 3600000).toISOString());
  const target = { id: "target-1", project_id: "project-1", url: "http://127.0.0.1:8766/", scope, scope_version: 4, verification_status: "verified_lab" };
  const assessment = { id: "assessment-1", project_id: "project-1", target_id: "target-1", status: "completed", created_at: new Date(now).toISOString() };
  const originals = { resource: components.useResource, api: api.api, post: api.post };
  try {
    for (const failure of [new api.ApiError("Synthetic reload failure", 500), new Error("Synthetic network failure")]) {
      const state = controlledState(), requests = [], posts = [], opened = [];
      components.useResource = request => ({ data: request.startsWith("/assessments/") ? assessment : { archived: false }, loading: false });
      api.api = async request => { requests.push(request); return target; };
      api.post = async (route, payload) => { posts.push({ route, payload }); return { ...assessment, id: "assessment-2" }; };
      const render = () => state.render(() => assessments.AssessmentDetail({ id: assessment.id, user: { role: "owner" }, revision: 0, refresh() {}, back() {}, openAssessment(id) { opened.push(id); } }));
      try {
        button(render(), "Review retest").props.onClick();
        await new Promise(resolve => setImmediate(resolve));
        let tree = render();
        assert.ok(button(tree, "Reload current target"), "Initial successful GET must open the current review");
        api.api = async request => { requests.push(request); throw failure; };
        button(tree, "Reload current target").props.onClick();
        await new Promise(resolve => setImmediate(resolve));
        tree = render();
        assert.ok(renderToStaticMarkup(tree).includes('role="alert"'));
        assert.equal(button(tree, "Launch retest"), undefined, "Failed reload must invalidate launch");
        assert.equal(nodes(tree).find(node => node.type === "input" && node.props.type === "checkbox"), undefined);
        assert.deepEqual(posts, []);
        const changed = { ...target, url: "http://127.0.0.1:8766/v5", scope: { ...scope, allowed_paths: ["/v5"], excluded_paths: ["/v5/private"] }, scope_version: 5 };
        api.api = async request => { requests.push(request); return changed; };
        button(tree, "Review retest").props.onClick();
        await new Promise(resolve => setImmediate(resolve));
        tree = render();
        const preview = nodes(tree).find(node => node.props.scope);
        assert.equal(preview.props.url, changed.url);
        assert.deepEqual(preview.props.scope, changed.scope);
        assert.equal(button(tree, "Launch retest").props.disabled, true, "New capture must require reapproval");
        assert.deepEqual(posts, []);
        nodes(tree).find(node => node.type === "input" && node.props.type === "checkbox").props.onChange({ target: { checked: true } });
        await button(render(), "Launch retest").props.onClick();
        assert.deepEqual(requests, Array(3).fill("/targets/target-1"));
        assert.equal(posts.length, 1);
        assert.equal(posts[0].route, "/assessments");
        assert.equal(posts[0].payload.target_id, target.id);
        assert.equal(posts[0].payload.retest_of, assessment.id);
        assert.equal(posts[0].payload.expected_scope_version, 5);
        assert.deepEqual(opened, ["assessment-2"]);
      } finally { state.restore(); }
    }
  } finally { components.useResource = originals.resource; api.api = originals.api; api.post = originals.post; }
});

test("new target defaults preserve their UTC instants during a repeated local hour", () => {
  const projects = load("projects"), NativeDate = Date, originalZone = process.env.TZ;
  const fixed = NativeDate.UTC(2027, 10, 7, 6, 30);
  process.env.TZ = "America/New_York";
  globalThis.Date = class extends NativeDate {
    constructor(...args) { super(...(args.length ? args : [fixed])); }
    static now() { return fixed; }
  };
  const state = controlledState();
  try {
    const render = () => state.render(() => projects.TargetRegistration({ projectId: "project-1", done() {} }));
    let tree = render();
    nodes(tree).find(node => node.type === "input" && node.props.name === "url").props.onChange({ target: { value: "http://127.0.0.1:8766/" } });
    tree = render();
    nodes(tree).find(node => node.type === "form").props.onSubmit({ preventDefault() {} });
    tree = render();
    assert.equal(tree.props.title, "02 / Review exact scope");
    const preview = nodes(tree).find(node => node.props.scope);
    assert.equal(preview.props.scope.starts_at, new NativeDate(fixed).toISOString());
    assert.equal(preview.props.scope.expires_at, new NativeDate(fixed + 86400000).toISOString());
  } finally {
    state.restore(); globalThis.Date = NativeDate;
    if (originalZone === undefined) delete process.env.TZ; else process.env.TZ = originalZone;
  }
});

test("authorization, launch and retest controls require an active scope window", async () => {
  const projects = load("projects"), assessments = load("assessments"), components = load("components"), api = load("api");
  const now = Date.now(), scope = api.laboratoryScope("http://127.0.0.1:8766/", "/", "", new Date(now + 3600000).toISOString());
  const assessment = { id: "assessment-1", project_id: "project-1", target_id: "target-1", status: "completed" };
  const originals = { resource: components.useResource, api: api.api };
  try {
    for (const [starts, expires, active] of [[now + 60000, now + 3600000, false], [now - 3600000, now - 60000, false], [now - 60000, now + 3600000, true]]) {
      const target = { id: "target-1", project_id: "project-1", url: "http://127.0.0.1:8766/", scope: { ...scope, starts_at: new Date(starts).toISOString(), expires_at: new Date(expires).toISOString() }, scope_version: 4, verification_status: "verified_lab" };
      const state = controlledState();
      try {
        let tree = state.render(() => projects.TargetRow({ target, canManage: true, canLaunch: true, refresh() {}, edit() {}, launch() {} }));
        assert.equal(button(tree, "Review & launch").props.disabled, !active);
        tree = state.render(() => projects.TargetRow({ target: { ...target, verification_status: "unverified" }, canManage: true, canLaunch: true, refresh() {}, edit() {}, launch() {} }));
        nodes(tree).find(node => node.type === "input" && node.props.type === "checkbox").props.onChange({ target: { checked: true } });
        tree = state.render(() => projects.TargetRow({ target: { ...target, verification_status: "unverified" }, canManage: true, canLaunch: true, refresh() {}, edit() {}, launch() {} }));
        assert.equal(button(tree, "Record authorization").props.disabled, !active);
      } finally { state.restore(); }
      const launchState = controlledState();
      try {
        const render = () => launchState.render(() => projects.Launch({ target, done() {}, cancel() {}, reload() {} }));
        nodes(render()).find(node => node.type === "input" && node.props.type === "checkbox").props.onChange({ target: { checked: true } });
        assert.equal(button(render(), "Launch assessment").props.disabled, !active);
      } finally { launchState.restore(); }
      const retestState = controlledState();
      try {
        components.useResource = request => ({ data: request.startsWith("/assessments/") ? assessment : { archived: false }, loading: false });
        api.api = async () => target;
        const render = () => retestState.render(() => assessments.AssessmentDetail({ id: assessment.id, user: { role: "owner" }, revision: 0, refresh() {}, back() {}, openAssessment() {} }));
        button(render(), "Review retest").props.onClick();
        await new Promise(resolve => setImmediate(resolve));
        nodes(render()).find(node => node.type === "input" && node.props.type === "checkbox").props.onChange({ target: { checked: true } });
        assert.equal(button(render(), "Launch retest").props.disabled, !active);
      } finally { retestState.restore(); }
    }
  } finally { components.useResource = originals.resource; api.api = originals.api; }
});
