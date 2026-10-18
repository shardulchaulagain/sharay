import assert from "node:assert/strict";
import { test } from "node:test";
import { terminalText } from "../app/terminal-output.ts";

test("split ANSI sequences are consumed across chunks", () => {
  let result = terminalText("", "before \x1b[");
  assert.deepEqual(result, { text: "before ", pending: "\x1b[" });
  result = terminalText(result.text, "1;32mafter\x1b[0m\r", result.pending);
  result = terminalText(result.text, "\nready", result.pending);
  assert.equal(result.text, "before after\nready");
  assert.equal(result.pending, "");
});

test("clear, carriage returns and backspace change visible content", () => {
  assert.equal(terminalText("old output", "\x1b[2J\x1b[Hnew").text, "new");
  assert.equal(terminalText("line\nold", "\rnew").text, "line\nnew");
  assert.equal(terminalText("abc", "\bD").text, "abD");
  assert.equal(terminalText("", "\x1b]0;title\x07safe").text, "safe");
});

test("terminal output remains bounded for normal and incomplete control chunks", () => {
  for (const suffix of ["abc", "abc\x1b", "abc\r", "abc\x1b[", "abc\x1b]title"]) {
    assert.ok(terminalText("x".repeat(524288), suffix).text.length <= 524288);
  }
});

test("long split OSC metadata never leaks its payload into visible output", () => {
  let result = terminalText("ready\n", "\x1b]0;" + "x".repeat(70000));
  assert.ok(result.pending.length <= 3);
  result = terminalText(result.text, "hidden title\x1b", result.pending);
  result = terminalText(result.text, "\\visible", result.pending);
  assert.equal(result.text, "ready\nvisible");
  assert.equal(result.pending, "");
});

test("backspace removes a complete Unicode code point", () => {
  assert.equal(terminalText("ready \ud83d\udc08", "\b!").text, "ready !");
});
