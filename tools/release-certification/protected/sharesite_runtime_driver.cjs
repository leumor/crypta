/* Private stdin/stdout adapter for the installed Site Publisher controller. No publication. */
"use strict";
const fs = require("node:fs");
const http = require("node:http");
const vm = require("node:vm");
const crypto = require("node:crypto");

function fail() { throw new Error("sharesite_runtime_failed"); }
function sha(bytes) { return "sha256:" + crypto.createHash("sha256").update(bytes).digest("hex"); }
function target(value, api) {
  const parsed = new URL(value);
  if (parsed.protocol !== "http:" || !["127.0.0.1", "[::1]"].includes(parsed.hostname)
      || !parsed.port || parsed.username || parsed.password || parsed.search || parsed.hash
      || parsed.pathname !== (api ? "/api/v1" : "/") || /\s/.test(value)) fail();
  return parsed;
}
function client(config) {
  const endpoint = target(config.api, true);
  target(config.origin, false);
  if (typeof config.session !== "string" || !config.session || config.session.length > 4096
      || /[\r\n]/.test(config.session)) fail();
  return function request(method, route, value, field) {
    if (!["/app-data/status", "/app-data/records", "/app-data/records/sharesite-drafts/dataset"].includes(route)
        && !/^\/app-data\/records\/soak-quota\/case-[0-9]{2}$/.test(route)) fail();
    const body = value ? new URLSearchParams(Object.entries(value).map(([key, item]) => [key, String(item)])).toString() : null;
    if (body && Buffer.byteLength(body) > 786432) fail();
    return new Promise((resolve, reject) => {
      const request = http.request({ hostname: endpoint.hostname.replace(/^\[|\]$/g, ""),
        port: endpoint.port, method, path: endpoint.pathname + route, agent: false,
        headers: { Origin: config.origin, "X-Crypta-App-Session": config.session,
          "Content-Type": "application/x-www-form-urlencoded", ...(body ? { "Content-Length": Buffer.byteLength(body) } : {}) } }, response => {
        let bytes = 0; const chunks = [];
        response.on("data", chunk => { bytes += chunk.length; if (bytes > 1048576) request.destroy(); else chunks.push(chunk); });
        response.on("error", () => { clearTimeout(timer); reject(new Error("sharesite_http_failed")); });
        response.on("end", () => {
          clearTimeout(timer);
          try {
            const parsed = JSON.parse(Buffer.concat(chunks));
            if (response.statusCode < 200 || response.statusCode >= 300) {
              const error = new Error("sharesite_http_denied");
              error.code = parsed.error?.code || parsed.code; reject(error); return;
            }
            if (!parsed || typeof parsed !== "object" || !(field in parsed)) fail();
            resolve(parsed[field]);
          } catch (_) { reject(new Error("sharesite_http_failed")); }
        });
      });
      const timer = setTimeout(() => request.destroy(), 25000);
      request.on("error", () => { clearTimeout(timer); reject(new Error("sharesite_http_failed")); });
      request.end(body);
    });
  };
}

async function run(config) {
  if (!["import", "recover", "restore"].includes(config.stage)) fail();
  const script = fs.readFileSync(config.controllerFile);
  if (script.length > 262144 || sha(script) !== config.controllerDigest) fail();
  const context = { window: { crypto: crypto.webcrypto }, document: { addEventListener() {} },
    TextEncoder, TextDecoder, URL, Uint8Array, atob, btoa };
  vm.createContext(context);
  vm.runInContext(script.toString("utf8"), context, { timeout: 1000 });
  const request = client(config);
  const api = { data: { status: () => request("GET", "/app-data/status", null, "status"),
    records: { get: () => request("GET", "/app-data/records/sharesite-drafts/dataset", null, "record"),
      put: value => request("POST", "/app-data/records", value, "record") } } };
  const drafts = context.window.SitePublisherDrafts;
  const model = drafts.controller(api);
  const initial = await model.load();
  const raw = fs.readFileSync(config.migrationFile);
  if (raw.length > 524288) fail();
  const converted = await drafts.parsePackage(new Uint8Array(raw));
  const expected = converted.dataset.drafts;
  const checks = {};
  function verifyFidelity(actual) {
    const selected = actual.drafts.filter(item => expected.some(original => item.id === original.id));
    if (JSON.stringify(selected) !== JSON.stringify(expected)) fail();
  }
  if (config.stage === "import") {
    if (initial.operations.length || initial.drafts.length) fail();
    fs.writeFileSync(config.backupFile, model.backup(), { mode: 0o600, flag: "wx" });
    const preview = await model.previewImport(converted);
    if (preview.replay) fail();
    const fresh = drafts.controller(api);
    if ((await fresh.load()).drafts.length) fail();
    await model.commit();
    verifyFidelity(await model.load());
    checks.importCommit = checks.literalFidelity = "pass";
    const replay = await model.previewImport(converted);
    if (replay.replay !== true) fail();
    checks.replay = "pass";
    fs.writeFileSync(config.retainedBackupFile, model.backup(), { mode: 0o600, flag: "wx" });
    // Exit the controller with an actual uncommitted guarded preview. The next stage must
    // observe that interrupted preparation did not mutate durable text after daemon restart.
    await model.previewEdit(expected[0].id, expected[0].text + "\nUncommitted bounded preview");
  } else if (config.stage === "recover") {
    verifyFidelity(initial);
    checks.restartPersistence = "pass";
    checks.interruptionRecovery = "pass";
    const originalText = expected[0].text;
    const changedText = originalText + "\nSynthetic bounded edit";
    await model.previewEdit(expected[0].id, changedText);
    await model.commit();
    if ((await model.load()).drafts.find(item => item.id === expected[0].id).text !== changedText) fail();
    checks.editSave = "pass";
    await model.previewEdit(expected[0].id, originalText);
    await model.commit();
    const competing = drafts.controller(api);
    await competing.load();
    await model.previewEdit(expected[0].id, changedText);
    await competing.previewEdit(expected[0].id, changedText + "\nSecond guarded writer");
    await competing.commit();
    try { await model.commit(); fail(); }
    catch (error) { if (!["sharesite_stale_preview", "app_data_write_conflict"].includes(error.code)) throw error; }
    checks.stalePreview = "pass";
    await model.load();
    await model.previewEdit(expected[0].id, originalText);
    await model.commit();
    await model.previewUndo(converted.package.operationId);
    await model.commit();
    const undone = await model.load();
    if (undone.drafts.length || undone.operations.length !== 1 || undone.operations[0].status !== "undone") fail();
    checks.dataUndo = "pass";
  } else {
    if (initial.operations.length || initial.drafts.length) fail();
    await model.previewRestore(new Uint8Array(fs.readFileSync(config.retainedBackupFile)));
    await model.commit();
    verifyFidelity(await model.load());
    checks.privateRestore = "pass";
    const status = await api.data.status();
    const quota = status.quota?.manifestDataQuotaBytes;
    const recordBytes = Math.min(status.limits?.maxRecordBytes || 0, 65536);
    const created = [];
    let denied = false;
    if (!Number.isSafeInteger(quota) || quota <= 0 || quota > 4 * 1024 * 1024
        || recordBytes < 1024 || status.quota?.manifestDataQuotaEnforced !== true) fail();
    try {
      for (let index = 0; index < 64; index++) {
        const key = `case-${String(index).padStart(2, "0")}`;
        try {
          await request("POST", "/app-data/records", { namespace: "soak-quota", key,
            schemaVersion: 1, contentType: "text/plain", valueText: "q".repeat(recordBytes), ifMatchSha256: "absent" }, "record");
          created.push(key);
        } catch (error) {
          if (error.code !== "app_data_quota_exceeded") throw error;
          denied = true; break;
        }
      }
      if (!denied) fail();
    } finally {
      for (const key of created) await request("DELETE", "/app-data/records/soak-quota/" + key, null, "record");
    }
    verifyFidelity(await model.load());
    checks.quotaFailure = "pass";
  }
  return { schemaVersion: 1, kind: "sharesite-runtime-stage", stage: config.stage,
    selectedCount: expected.length, checks };
}

if (require.main === module) {
  let input = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", chunk => { input += chunk; if (input.length > 16384) process.exit(2); });
  process.stdin.on("end", async () => {
    try { process.stdout.write(JSON.stringify(await run(JSON.parse(input))) + "\n"); }
    catch (_) { process.stderr.write("sharesite_runtime_failed\n"); process.exitCode = 1; }
  });
}
module.exports = { run, target };
