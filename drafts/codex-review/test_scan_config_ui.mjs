import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(new URL("../../apps/web/package.json", import.meta.url));
const React = require("react"), ts = require("typescript");

function nodes(value, found = []) {
  if (Array.isArray(value)) value.forEach(item => nodes(item, found));
  else if (React.isValidElement(value)) { found.push(value); nodes(value.props.children, found); }
  return found;
}
function text(value) {
  if (Array.isArray(value)) return value.map(text).join("");
  if (React.isValidElement(value)) return text(value.props.children);
  return value === undefined || value === null ? "" : String(value);
}
const button = tree => nodes(tree).find(node => node.type === "button" && text(node.props.children).includes("Launch assessment"));
const approval = tree => nodes(tree).find(node => node.type === "label" && text(node.props.children).includes("reviewed this exact scope")).props.children[0];
const control = (tree, label) => nodes(tree).find(node => node.type === "label" && text(node.props.children).includes(label)).props.children;
const input = (tree, label) => nodes(control(tree, label)).find(node => node.type === "input" || node.type === "select");

function fixture(live = true, ceiling = 0.1) {
  const original = React.useState, values = []; let cursor = 0;
  React.useState = initial => {
    const index = cursor++;
    if (!(index in values)) values[index] = typeof initial === "function" ? initial() : initial;
    return [values[index], next => { values[index] = typeof next === "function" ? next(values[index]) : next; }];
  };
  const posts = [], cache = new Map(); let project, role = "owner";
  function load(name) {
    if (cache.has(name)) return cache.get(name);
    const source = readFileSync(new URL(`../../apps/web/app/${name}.${name === "api" ? "ts" : "tsx"}`, import.meta.url), "utf8") + (name === "projects" ? "\nexport { Launch, ProjectDetail, TargetRow };" : "");
    const module = { exports: {} };
    const code = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX } }).outputText;
    new Function("require", "module", "exports", code)(id => {
      if (id === "./api") return load("api");
      if (id.startsWith("./")) return new Proxy({}, { get: (_target, name) => name === "useResource" ? () => ({ data: project, loading: false }) : function Component() { return name; } });
      return require(id);
    }, module, module.exports);
    cache.set(name, module.exports);
    return module.exports;
  }
  const api = load("api");
  api.post = async (route, payload) => { posts.push({ route, payload }); return { id: "synthetic-assessment" }; };
  const projects = load("projects"), now = Date.now();
  const target = { id: "synthetic-target", url: "http://127.0.0.1:8766/", scope_version: 1,
    verification_status: live ? "operator_authorized" : "verified_lab",
    scope: { request_rate: ceiling, starts_at: new Date(now - 60000).toISOString(), expires_at: new Date(now + 3600000).toISOString() } };
  project = { id: "synthetic-project", name: "Synthetic", targets: [target], assessments: [], archived: false };
  return { posts, setTarget(value) { Object.assign(target, value); }, setProject(value) { Object.assign(project, value); }, setRole(value) { role = value; },
    openProjectLaunch() { nodes(this.renderProject()).find(node => node.type === projects.TargetRow).props.launch(); },
    projectLaunch() { return nodes(this.renderProject()).find(node => node.type === projects.Launch); },
    renderProject() { cursor = 0; return projects.ProjectDetail({ id: project.id, user: { role }, revision: 0, refresh() {}, back() {}, openAssessment() {} }); },
    render() { cursor = 0; return projects.Launch({ target, done() {}, cancel() {}, reload() {} }); }, restore() { React.useState = original; } };
}

test("lab launches submit safe HTTP without external configuration", async () => {
  const f = fixture(false);
  try {
    approval(f.render()).props.onChange({ target: { checked: true } });
    await button(f.render()).props.onClick();
    assert.equal(f.posts[0].payload.profile, "safe_http");
    assert.equal(f.posts[0].payload.config, undefined);
  } finally { f.restore(); }
});

test("rate control inherits and cannot exceed a fractional approved ceiling", async () => {
  const f = fixture();
  try {
    const rate = input(f.render(), "Request Rate Limit");
    assert.equal(rate.props.value, 0.1);
    assert.equal(rate.props.max, 0.1);
    assert.ok(Number(rate.props.min) > 0 && Number(rate.props.min) <= 0.1);
    assert.equal(rate.props.step, "any");
    approval(f.render()).props.onChange({ target: { checked: true } });
    await button(f.render()).props.onClick();
    assert.equal(f.posts[0].payload.config.rate, 0.1);
  } finally { f.restore(); }
});

test("each option change invalidates approval and makes a fresh request identity", async () => {
  const labels = ["Assessment profile", "Scan Mode", "Crawler Link Depth", "Request Rate Limit", "Custom Nuclei", "Nmap Port", "Web Spider", "Sensitive File", "Behavioral Differential", "Nuclei Runner", "OWASP ZAP", "Metasploit Auxiliary"];
  for (const label of labels) {
    const f = fixture(true, 1);
    try {
      approval(f.render()).props.onChange({ target: { checked: true } });
      await button(f.render()).props.onClick();
      const firstKey = f.posts[0].payload.idempotency_key;
      input(f.render(), label).props.onChange({ target: { value: label === "Assessment profile" ? "approved_templates" : label === "Scan Mode" ? "standard" : label.includes("Depth") ? "3" : label.includes("Rate") ? "0.5" : "tech", checked: false } });
      assert.equal(button(f.render()).props.disabled, true, label);
      assert.equal(approval(f.render()).props.checked, false, label);
      await button(f.render()).props.onClick();
      assert.equal(f.posts.length, 1, "A stale handler cannot bypass disabled review");
      approval(f.render()).props.onChange({ target: { checked: true } });
      await button(f.render()).props.onClick();
      assert.notEqual(f.posts[1].payload.idempotency_key, firstKey, label);
    } finally { f.restore(); }
  }
});

test("passive configuration never submits selected active tools", async () => {
  const f = fixture();
  try {
    input(f.render(), "Scan Mode").props.onChange({ target: { value: "passive" } });
    const nmap = input(f.render(), "Nmap Port");
    assert.equal(nmap.props.disabled, true);
    assert.equal(nmap.props.checked, false);
    approval(f.render()).props.onChange({ target: { checked: true } });
    await button(f.render()).props.onClick();
    assert.deepEqual(f.posts[0].payload.config.tools, []);
  } finally { f.restore(); }
});

test("switching to safe HTTP omits unsupported options", async () => {
  const f = fixture();
  try {
    input(f.render(), "Assessment profile").props.onChange({ target: { value: "safe_http" } });
    approval(f.render()).props.onChange({ target: { checked: true } });
    await button(f.render()).props.onClick();
    assert.equal(f.posts[0].payload.config, undefined);
  } finally { f.restore(); }
});

test("an observed replacement scope invalidates the captured launch approval", async () => {
  const f = fixture(false);
  try {
    approval(f.render()).props.onChange({ target: { checked: true } });
    assert.equal(button(f.render()).props.disabled, false);
    f.setTarget({ scope_version: 2 });
    assert.equal(button(f.render()).props.disabled, true);
    assert.equal(approval(f.render()).props.checked, false);
    await button(f.render()).props.onClick();
    assert.deepEqual(f.posts, []);
    approval(f.render()).props.onChange({ target: { checked: true } });
    await button(f.render()).props.onClick();
    assert.equal(f.posts[0].payload.expected_scope_version, 2);
  } finally { f.restore(); }
});

test("ProjectDetail forwards the latest target and hides review after removal or lost permission", () => {
  const f = fixture(false, 1);
  try {
    f.openProjectLaunch();
    const original = f.projectLaunch().props.target;
    const current = { ...original, scope_version: 2, scope: { ...original.scope, request_rate: 0.1 } };
    f.setProject({ targets: [current] });
    assert.equal(f.projectLaunch().props.target, current);
    assert.equal(f.projectLaunch().key, `${current.id}:2`);
    f.setRole("viewer");
    assert.equal(f.projectLaunch(), undefined);
    f.setRole("owner"); f.setProject({ archived: true });
    assert.equal(f.projectLaunch(), undefined);
    f.setProject({ archived: false, targets: [] });
    assert.equal(f.projectLaunch(), undefined);
  } finally { f.restore(); }
});
