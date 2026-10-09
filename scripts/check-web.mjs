// Checks the dashboard translations: every language has every English key, with the same
// {placeholders}, and every key used by index.html and app.js exists. Run: node scripts/check-web.mjs
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";

const web = new URL("../web/", import.meta.url);
const read = (name) => readFileSync(new URL(name, web), "utf8");

const sandbox = { window: {} };
runInNewContext(read("i18n.js"), sandbox, { filename: "i18n.js" });
const { languages, strings } = sandbox.window.FILEFENDER_I18N;

const errors = [];
const placeholders = (text) => [...text.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join(",");
const reference = strings.en;

for (const { code } of languages) {
  const table = strings[code];
  if (!table) {
    errors.push(`${code}: no strings`);
    continue;
  }
  for (const [key, text] of Object.entries(reference)) {
    if (!(key in table)) errors.push(`${code}: missing "${key}"`);
    else if (typeof table[key] !== "string" || !table[key].trim()) errors.push(`${code}: empty "${key}"`);
    else if (placeholders(table[key]) !== placeholders(text)) errors.push(`${code}: placeholders differ in "${key}"`);
  }
  for (const key of Object.keys(table)) {
    if (!(key in reference)) errors.push(`${code}: unknown key "${key}"`);
  }
}
for (const code of Object.keys(strings)) {
  if (!languages.some((l) => l.code === code)) errors.push(`${code}: not listed in languages`);
}

const used = new Set();
for (const m of read("index.html").matchAll(/data-i18n(?:-[a-z]+)?="([^"]+)"/g)) used.add(m[1]);
for (const m of read("app.js").matchAll(/\bt\(\s*["']([\w.-]+)["']/g)) used.add(m[1]);
for (const key of used) {
  if (!(key in reference)) errors.push(`used but not translated: "${key}"`);
}

if (errors.length) {
  console.error(errors.join("\n"));
  process.exit(1);
}
console.log(`${languages.length} languages, ${Object.keys(reference).length} keys, ${used.size} literal uses: OK`);
