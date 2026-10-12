import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { ESLint } from "eslint";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const corpus = JSON.parse(readFileSync(join(root, "tests/accessibility-corpus.json"), "utf8"));

test("accessibility lint preserves the measured 31-rule baseline and option decisions", () => {
  const folder = mkdtempSync(join(root, ".lint-check-"));
  try {
    const files = corpus.map((probe, index) => {
      const file = join(folder, `${index}.tsx`);
      writeFileSync(file, `export default function Example({role}: {role: string}) {return (${probe.jsx});}`);
      return file;
    });
    const run = spawnSync(join(root, "node_modules/.bin/oxlint"), ["--config", ".oxlintrc.json", "--format", "json", ...files], {
      cwd: root, encoding: "utf8", timeout: 15_000,
    });
    assert.ifError(run.error);
    assert.equal(run.status, 1, "The intentionally inaccessible fixtures must fail lint.");
    const result = JSON.parse(run.stdout);
    assert.equal(result.number_of_rules, 31);
    for (const [index, probe] of corpus.entries()) {
      const denied = result.diagnostics.some(diagnostic =>
        resolve(root, diagnostic.filename) === files[index] && diagnostic.code === `jsx-a11y(${probe.rule})`,
      );
      assert.equal(denied, probe.denied, `${probe.rule}: ${probe.jsx}`);
    }
  } finally { rmSync(folder, { recursive: true, force: true }); }
});

test("ESLint still rejects unsafe typing and conditional React hooks", async () => {
  const linter = new ESLint({ cwd: root });
  const [invalid] = await linter.lintText(`import { useState } from "react";
    export default function Example({active}: {active: boolean}) {
      if (active) useState(0);
      const value: any = 1;
      return <button>{value}</button>;
    }`, { filePath: join(root, "app/lint-probe.tsx") });
  const rules = invalid.messages.map(message => message.ruleId);
  assert.ok(rules.includes("@typescript-eslint/no-explicit-any"));
  assert.ok(rules.includes("react-hooks/rules-of-hooks"));
  const [valid] = await linter.lintText(`import { useState } from "react";
    export default function Example() {
      const [value] = useState(0);
      return <button>{value}</button>;
    }`, { filePath: join(root, "app/lint-probe.tsx") });
  assert.equal(valid.errorCount, 0);
});
