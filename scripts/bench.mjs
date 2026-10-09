#!/usr/bin/env node
// Scan speed of a running FileFender instance, measured with generated files that are never cached.
// Usage: FILEFENDER_URL=http://127.0.0.1:8080 FILEFENDER_KEY=ff_... node scripts/bench.mjs [--clients 16] [--json results.json]
// Prints a Markdown report on stdout and progress on stderr. Needs Node.js 20 or later, nothing else.
import { randomBytes, randomFillSync } from "node:crypto";
import { writeFileSync } from "node:fs";
import { performance } from "node:perf_hooks";
import zlib from "node:zlib";

const url = (process.env.FILEFENDER_URL || "http://127.0.0.1:8080").replace(/\/+$/, "");
const key = process.env.FILEFENDER_KEY;
if (!key) {
  console.error("set FILEFENDER_KEY to an API key");
  process.exit(2);
}
const option = (name, fallback) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : fallback;
};
const clients = Number(option("clients", 16));
const jsonPath = option("json");
const log = (...parts) => console.error(...parts);

// ---------- generated files: random content makes every file unique, so no verdict comes from the cache

const CRC_TABLE = Int32Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c;
});
const crc32 =
  zlib.crc32 ??
  ((buf) => {
    let c = -1;
    for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
    return (c ^ -1) >>> 0;
  });

const WORDS = ("invoice order customer payment delivery report quarter budget account contract supplier " +
  "product service total amount due paid pending refund meeting project review approved draft").split(" ");
const pick = () => WORDS[Math.floor(Math.random() * WORDS.length)];
const sentence = (n) => Array.from({ length: n }, pick).join(" ");
const unique = () => randomBytes(8).toString("hex");

function csv(bytes) {
  const lines = [`id,date,customer,description,amount,${unique()}`];
  let size = lines[0].length;
  while (size < bytes) {
    const line = `${Math.floor(Math.random() * 1e9)},2026-0${1 + Math.floor(Math.random() * 9)}-1${Math.floor(Math.random() * 9)},${pick()} ${pick()},${sentence(6)},${(Math.random() * 10000).toFixed(2)}`;
    lines.push(line);
    size += line.length + 1;
  }
  return Buffer.from(`${lines.join("\n")}\n`);
}

function png(width, height) {
  const row = width * 3 + 1;
  const raw = randomFillSync(Buffer.alloc(row * height));
  for (let y = 0; y < height; y++) raw[y * row] = 0;
  const chunk = (type, data) => {
    const body = Buffer.concat([Buffer.from(type), data]);
    const out = Buffer.alloc(body.length + 8);
    out.writeUInt32BE(data.length, 0);
    body.copy(out, 4);
    out.writeUInt32BE(crc32(body), body.length + 4);
    return out;
  };
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8;
  header[9] = 2;
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk("IHDR", header),
    chunk("IDAT", zlib.deflateSync(raw, { level: 0 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

function zip(entries) {
  const parts = [];
  const central = [];
  let offset = 0;
  for (const { name, data, deflate } of entries) {
    const body = deflate ? zlib.deflateRawSync(data) : data;
    const crc = crc32(data);
    const fileName = Buffer.from(name);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(deflate ? 8 : 0, 8);
    local.writeUInt16LE(0x21, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(fileName.length, 26);
    const entry = Buffer.alloc(46);
    entry.writeUInt32LE(0x02014b50, 0);
    entry.writeUInt16LE(20, 4);
    entry.writeUInt16LE(20, 6);
    entry.writeUInt16LE(deflate ? 8 : 0, 10);
    entry.writeUInt16LE(0x21, 14);
    entry.writeUInt32LE(crc, 16);
    entry.writeUInt32LE(body.length, 20);
    entry.writeUInt32LE(data.length, 24);
    entry.writeUInt16LE(fileName.length, 28);
    entry.writeUInt32LE(offset, 42);
    parts.push(local, fileName, body);
    central.push(entry, fileName);
    offset += 30 + fileName.length + body.length;
  }
  const directory = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...parts, directory, end]);
}

function pdf() {
  const side = 280;
  const image = randomFillSync(Buffer.alloc(side * side * 3));
  const objects = [];
  objects[0] = "<< /Type /Catalog /Pages 2 0 R >>";
  objects[2] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>";
  objects[3] = [`<< /Type /XObject /Subtype /Image /Width ${side} /Height ${side} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Length ${image.length} >>\nstream\n`, image, "\nendstream"];
  const kids = [];
  for (let page = 1; page <= 8; page++) {
    const lines = [`BT /F1 11 Tf 56 780 Td 14 TL (Report ${unique()}, page ${page}) Tj`];
    for (let l = 0; l < 48; l++) lines.push(`T* (${sentence(12)}) Tj`);
    lines.push("ET");
    if (page === 1) lines.push("q 300 0 0 300 150 60 cm /Im1 Do Q");
    const stream = zlib.deflateSync(Buffer.from(lines.join("\n")));
    const number = objects.length + 1;
    objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> /XObject << /Im1 4 0 R >> >> /Contents ${number + 1} 0 R >>`);
    objects.push([`<< /Length ${stream.length} /Filter /FlateDecode >>\nstream\n`, stream, "\nendstream"]);
    kids.push(`${number} 0 R`);
  }
  objects[1] = `<< /Type /Pages /Kids [${kids.join(" ")}] /Count ${kids.length} >>`;
  const out = [];
  let size = 0;
  const write = (part) => {
    const bytes = Buffer.isBuffer(part) ? part : Buffer.from(part, "latin1");
    out.push(bytes);
    size += bytes.length;
  };
  const offsets = [];
  write("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n");
  objects.forEach((object, i) => {
    offsets.push(size);
    write(`${i + 1} 0 obj\n`);
    for (const part of [object].flat()) write(part);
    write("\nendobj\n");
  });
  const xref = size;
  write(`xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`);
  for (const offset of offsets) write(`${String(offset).padStart(10, "0")} 00000 n \n`);
  write(`trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`);
  return Buffer.concat(out);
}

const CONTENT_TYPES =
  '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' +
  '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>' +
  '<Default Extension="png" ContentType="image/png"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>';
const RELS =
  '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
  '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>';

function docx() {
  const paragraphs = Array.from({ length: 1500 }, () => `<w:p><w:r><w:t>${sentence(14)}</w:t></w:r></w:p>`).join("");
  const document =
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>' +
    `<w:p><w:r><w:t>${unique()}</w:t></w:r></w:p>${paragraphs}</w:body></w:document>`;
  return zip([
    { name: "[Content_Types].xml", data: Buffer.from(CONTENT_TYPES), deflate: true },
    { name: "_rels/.rels", data: Buffer.from(RELS), deflate: true },
    { name: "word/document.xml", data: Buffer.from(document), deflate: true },
    { name: "word/media/image1.png", data: png(200, 200) },
  ]);
}

const archive = () => zip(Array.from({ length: 20 }, (_, i) => ({ name: `data/part-${String(i + 1).padStart(2, "0")}.bin`, data: randomBytes(250_000) })));

const SCENARIOS = [
  { label: "CSV text", ext: "csv", count: 420, make: () => csv(20_000) },
  { label: "PDF with a picture", ext: "pdf", count: 220, make: pdf },
  { label: "Word document", ext: "docx", count: 220, make: docx },
  { label: "PNG picture", ext: "png", count: 110, make: () => png(816, 816) },
  { label: "ZIP of 20 files", ext: "zip", count: 46, make: archive },
  { label: "Binary file", ext: "bin", count: 20, make: () => randomBytes(25_000_000) },
];

// ---------- measurement

async function scan(name, data) {
  const started = performance.now();
  try {
    const response = await fetch(`${url}/v1/scan?filename=${encodeURIComponent(name)}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/octet-stream" },
      body: data,
    });
    const body = await response.json().catch(() => null);
    return { status: response.status, ms: performance.now() - started, engineMs: body?.duration_ms, verdict: body?.verdict, cached: body?.cached };
  } catch (err) {
    return { status: 0, ms: performance.now() - started, error: err.cause?.code || err.message };
  }
}

async function pool(files, parallel) {
  const results = [];
  let next = 0;
  const started = performance.now();
  await Promise.all(
    Array.from({ length: Math.min(parallel, files.length) }, async () => {
      while (next < files.length) {
        const i = next++;
        results[i] = await scan(files[i].name, files[i].data);
      }
    }),
  );
  return { results, seconds: (performance.now() - started) / 1000 };
}

function percentile(values, p) {
  const sorted = values.filter((v) => typeof v === "number").sort((a, b) => a - b);
  if (!sorted.length) return null;
  return sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)];
}

function summarize(results) {
  const ok = results.filter((r) => r.status === 200);
  const verdicts = {};
  for (const r of ok) verdicts[r.verdict] = (verdicts[r.verdict] || 0) + 1;
  return {
    files: results.length,
    errors: results.length - ok.length,
    cached: ok.filter((r) => r.cached).length,
    verdicts,
    medianMs: percentile(ok.map((r) => r.ms), 50),
    p95Ms: percentile(ok.map((r) => r.ms), 95),
    engineMedianMs: percentile(ok.map((r) => r.engineMs), 50),
  };
}

const ms = (v) => (v === null ? "—" : v < 10 ? `${v.toFixed(1)} ms` : v < 1000 ? `${Math.round(v)} ms` : `${(v / 1000).toFixed(2)} s`);
const size = (bytes) => (bytes >= 1e6 ? `${(bytes / 1e6).toFixed(1)} MB` : `${Math.round(bytes / 1e3)} kB`);
const rate = (v) => (v >= 100 ? Math.round(v).toLocaleString("en-US") : v >= 10 ? v.toFixed(1) : v.toFixed(2));

async function main() {
  const status = await (await fetch(`${url}/v1/status`, { headers: { Authorization: `Bearer ${key}` } })).json();
  if (!status.ready) throw new Error("FileFender is not ready yet: wait for /readyz");
  const clamav = status.engines.clamav;
  const yara = status.engines.yara;
  const daily = (clamav.databases || []).find((d) => d.name === "daily");
  const meta = {
    url,
    version: status.version,
    clamav: { version: clamav.engine_version, signatures: clamav.signatures, daily: daily?.version },
    yara: yara.status === "ready" ? { package: yara.package, release: yara.release, rules: yara.rules } : null,
    malwarebazaar: status.engines.malwarebazaar.status,
    serverParallelScans: status.limits.max_concurrent_scans,
    clients,
    date: new Date().toISOString(),
  };

  const rows = [];
  for (const scenario of SCENARIOS) {
    log(`${scenario.label}: generating ${scenario.count} files`);
    const files = Array.from({ length: scenario.count }, (_, i) => ({ name: `bench-${i}.${scenario.ext}`, data: scenario.make() }));
    const sequential = files.slice(0, Math.max(4, Math.round(scenario.count / 10)));
    const parallel = files.slice(sequential.length);
    const averageBytes = files.reduce((sum, f) => sum + f.data.length, 0) / files.length;
    log(`  one at a time: ${sequential.length} files`);
    const alone = summarize((await pool(sequential, 1)).results);
    log(`  ${clients} clients: ${parallel.length} files`);
    const loaded = await pool(parallel, clients);
    const load = summarize(loaded.results);
    const bytes = parallel.reduce((sum, f) => sum + f.data.length, 0);
    rows.push({
      label: scenario.label,
      averageBytes,
      alone,
      load: { ...load, seconds: loaded.seconds, filesPerSecond: parallel.length / loaded.seconds, megabytesPerSecond: bytes / 1e6 / loaded.seconds },
    });
  }

  log("EICAR and cached verdicts");
  const eicarText = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
  // Trailing spaces keep it a valid test file and make each copy new to the cache.
  const eicar = summarize((await pool(Array.from({ length: 10 }, (_, i) => ({ name: `eicar-${i}.com`, data: Buffer.from(eicarText + " ".repeat(i + 1)) })), 1)).results);
  const known = { name: "known.csv", data: csv(20_000) };
  await scan(known.name, known.data);
  const cache = summarize((await pool(Array.from({ length: 20 }, () => known), 1)).results);

  const totalErrors = rows.reduce((sum, r) => sum + r.alone.errors + r.load.errors, 0) + eicar.errors + cache.errors;
  const results = { meta, scenarios: rows, eicar, cache, errors: totalErrors };
  if (jsonPath) writeFileSync(jsonPath, `${JSON.stringify(results, null, 2)}\n`);

  const out = [];
  const engines = [`ClamAV ${meta.clamav.version} (${meta.clamav.signatures.toLocaleString("en-US")} signatures, daily ${meta.clamav.daily})`];
  if (meta.yara) engines.push(`YARA Forge ${meta.yara.package} ${meta.yara.release} (${meta.yara.rules.toLocaleString("en-US")} rules)`);
  out.push(`FileFender ${meta.version} · ${engines.join(" · ")} · MalwareBazaar ${meta.malwarebazaar}`);
  out.push(`${meta.serverParallelScans} scans at a time on the server, ${clients} parallel clients, raw uploads, every file new to the cache.`);
  out.push("");
  out.push(`| File | Size | One at a time: median | p95 | Engines | ${clients} clients: files/s | MB/s | median | p95 |`);
  out.push("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |");
  for (const r of rows) {
    out.push(
      `| ${r.label} | ${size(r.averageBytes)} | ${ms(r.alone.medianMs)} | ${ms(r.alone.p95Ms)} | ${ms(r.alone.engineMedianMs)} | ${rate(r.load.filesPerSecond)} | ${rate(r.load.megabytesPerSecond)} | ${ms(r.load.medianMs)} | ${ms(r.load.p95Ms)} |`,
    );
  }
  out.push("");
  out.push("Engines: median scan time inside FileFender (`duration_ms`), without the upload.");
  const eicarOk = eicar.verdicts.malicious === eicar.files;
  out.push(`EICAR test file: ${eicarOk ? "detected" : "NOT detected"} ${eicar.verdicts.malicious || 0}/${eicar.files} times, ${ms(eicar.medianMs)} median (${ms(eicar.engineMedianMs)} in the engines).`);
  out.push(`Same file again, answered from the cache: ${ms(cache.medianMs)} median, ${cache.cached}/${cache.files} cached.`);
  const verdicts = {};
  for (const r of rows) for (const part of [r.alone, r.load]) for (const [v, n] of Object.entries(part.verdicts)) verdicts[v] = (verdicts[v] || 0) + n;
  out.push(`Verdicts of the generated files: ${Object.entries(verdicts).map(([v, n]) => `${n} ${v}`).join(", ")}. Errors: ${totalErrors}.`);
  console.log(out.join("\n"));
  if (totalErrors || !eicarOk) process.exitCode = 1;
}

main().catch((err) => {
  console.error(`benchmark failed: ${err.message}`);
  process.exit(1);
});
