import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(new URL("../../apps/web/package.json", import.meta.url));
const React = require("react"), ts = require("typescript");

function fixture() {
  const originals = Object.fromEntries(["useState", "useEffect", "useRef", "useCallback"].map(key => [key, React[key]]));
  // Render the connected state without executing the session/stream effects.
  React.useState = value => [value === "connecting" ? "connected" : typeof value === "function" ? value() : value, () => {}];
  React.useEffect = () => {}; // Session/stream effects must never run in this acceptance.
  React.useRef = value => ({ current: value });
  React.useCallback = callback => callback;
  const posts = []; let closes = 0;
  const source = readFileSync(new URL("../../apps/web/app/terminal.tsx", import.meta.url), "utf8");
  const code = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX } }).outputText;
  const module = { exports: {} };
  new Function("require", "module", "exports", code)(id => {
    if (id === "./api") return { post: async (route, body) => { posts.push({ route, body }); } };
    if (id === "./components") return { Badge() {}, Icon() {} };
    return require(id);
  }, module, module.exports);
  const tree = module.exports.default({ target: { id: "synthetic-target", url: "https://synthetic.invalid/" }, initialSession: { id: "synthetic-session", state: "active", target_ip: "192.0.2.1" }, onClose() { closes++; } });
  const nodes = [];
  function visit(value) {
    if (Array.isArray(value)) value.forEach(visit);
    else if (React.isValidElement(value)) { nodes.push(value); visit(value.props.children); }
  }
  visit(tree);
  return { nodes, posts, closes: () => closes, restore() { Object.assign(React, originals); } };
}

test("terminal has a named dialog and labelled input without native autofocus", () => {
  const f = fixture();
  try {
    const dialog = f.nodes.find(node => node.type === "dialog" || node.props.role === "dialog");
    assert.ok(dialog?.props["aria-label"]);
    const input = f.nodes.find(node => node.type === "input");
    assert.ok(input.props["aria-label"]);
    assert.equal(input.props.autoFocus, undefined);
  } finally { f.restore(); }
});

test("Shift+Tab remains keyboard navigation rather than terminal input", () => {
  const f = fixture(); let prevented = false;
  try {
    f.nodes.find(node => node.type === "input").props.onKeyDown({ key: "Tab", shiftKey: true, preventDefault() { prevented = true; } });
    assert.equal(prevented, false);
    assert.deepEqual(f.posts, []);
  } finally { f.restore(); }
});

test("plain Tab retains explicit terminal completion", () => {
  const f = fixture(); let prevented = false;
  try {
    f.nodes.find(node => node.type === "input").props.onKeyDown({ key: "Tab", shiftKey: false, preventDefault() { prevented = true; } });
    assert.equal(prevented, true);
    assert.deepEqual(f.posts, [{ route: "/interactive/sessions/synthetic-session/input", body: { data: "\t" } }]);
  } finally { f.restore(); }
});

test("Escape dismisses the dialog without sending terminal input", () => {
  const f = fixture();
  try {
    const dialog = f.nodes.find(node => node.type === "dialog" || node.props.role === "dialog");
    assert.equal(typeof dialog?.props.onKeyDown, "function");
    dialog.props.onKeyDown({ key: "Escape" });
    assert.equal(f.closes(), 1);
    assert.deepEqual(f.posts, []);
  } finally { f.restore(); }
});
