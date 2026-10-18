import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import test from "node:test";
import { URL } from "node:url";

const require = createRequire(new URL("../package.json", import.meta.url));
const React = require("react"), ts = require("typescript");

function fixture({ busy = false, post } = {}) {
  const originals = Object.fromEntries(["useState", "useEffect", "useRef", "useCallback"].map(key => [key, React[key]]));
  // Render the connected state without executing the session/stream effects.
  let stateIndex = 0;
  React.useState = value => [stateIndex++ === 5 ? busy : value === "connecting" ? "connected" : typeof value === "function" ? value() : value, () => {}];
  React.useEffect = () => {}; // Session/stream effects must never run in this acceptance.
  React.useRef = value => ({ current: value });
  React.useCallback = callback => callback;
  const posts = []; let closes = 0;
  const source = readFileSync(new URL("../app/terminal.tsx", import.meta.url), "utf8");
  const code = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX } }).outputText;
  const module = { exports: {} };
  new Function("require", "module", "exports", code)(id => {
    if (id === "./api") return { post: async (route, body) => { posts.push({ route, body }); return post ? post(route, body) : { ownership_state: "HUMAN_OWNED" }; } };
    if (id === "./components") return { Badge() {}, Icon() {} };
    if (id === "./terminal-output") return { terminalText: () => ({ text: "", pending: "" }) };
    return require(id);
  }, module, module.exports);
  const tree = module.exports.default({ target: { id: "synthetic-target", url: "https://synthetic.invalid/" }, initialSession: { id: "synthetic-session", target_id: "synthetic-target", state: "active", target_ip: "192.0.2.1" }, onClose() { closes++; } });
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

test("ambiguous Tab preserves keyboard navigation without sending keystrokes", () => {
  const f = fixture(); let prevented = false;
  try {
    f.nodes.find(node => node.type === "input").props.onKeyDown({ key: "Tab", shiftKey: false, preventDefault() { prevented = true; } });
    assert.equal(prevented, false);
    assert.deepEqual(f.posts, []);
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

test("Ctrl-C and Ctrl-D reach a busy console", () => {
  const f = fixture({ busy: true });
  try {
    const input = f.nodes.find(node => node.type === "input");
    for (const key of ["C", "d"]) {
      let prevented = false;
      input.props.onKeyDown({ key, ctrlKey: true, preventDefault() { prevented = true; } });
      assert.equal(prevented, true);
    }
    assert.deepEqual(f.posts.map(post => post.body.data), ["\x03", "\x04"]);
  } finally { f.restore(); }
});

test("in-flight command still permits controls and rejects duplicate submissions", async () => {
  let complete;
  const f = fixture({ post: (_route, body) => body.data === "\n" ? new Promise(resolve => { complete = resolve; }) : { ownership_state: "HUMAN_OWNED" } });
  try {
    const input = f.nodes.find(node => node.type === "input");
    const press = (key, ctrlKey = false) => input.props.onKeyDown({ key, ctrlKey, preventDefault() {} });
    press("Enter");
    press("c", true);
    await Promise.resolve();
    press("Enter");
    assert.deepEqual(f.posts.map(post => post.body.data), ["\n", "\x03"]);
    complete({ ownership_state: "HUMAN_OWNED" });
    await Promise.resolve();
  } finally { f.restore(); }
});
