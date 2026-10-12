import { defineConfig, globalIgnores } from "eslint/config";
import js from "@eslint/js";
import ts from "typescript-eslint";
import hooks from "eslint-plugin-react-hooks";

export default defineConfig([
  js.configs.recommended,
  ...ts.configs.recommended,
  hooks.configs.flat.recommended,
  { files: ["**/*.ts", "**/*.tsx", "**/*.mjs"], languageOptions: { globals: { window: "readonly", document: "readonly", console: "readonly", fetch: "readonly", crypto: "readonly", Headers: "readonly", FormData: "readonly", Event: "readonly", AbortController: "readonly", DOMException: "readonly", React: "readonly" } } },
  globalIgnores(["out/**", ".next/**", "next-env.d.ts"]),
]);
