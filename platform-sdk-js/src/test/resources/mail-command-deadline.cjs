// Executed in the SDK test harness against the actual SDK, with a deterministic timer clock.
// A real watchdog prevents Node from treating an unresolved promise as successful process exit.
const watchdog = setTimeout(() => { console.error("Mail deadline scenario did not finish"); process.exit(1); }, 10000);
const timers = new Map();
let nextTimer = 1;
context.setTimeout = (callback, delay) => {
  const id = nextTimer++;
  timers.set(id, { callback, delay });
  return id;
};
context.clearTimeout = id => timers.delete(id);
const normalFetch = context.fetch;
if (!stalledStage.startsWith("bootstrap")) {
  enqueueBootstrap();
  await CryptaPlatform.bootstrap.load({ appId: "feed-reader" });
}
const observed = [];
let reached;
const atStall = new Promise(resolve => { reached = resolve; });
const aborted = signal => new Promise((resolve, reject) => {
  assert.ok(signal, "Every HTTP wait must have the overall deadline signal");
  signal.addEventListener("abort", () => reject(signal.reason), { once: true });
});
const jsonResponse = body => ({ ok: true, json: async () => body });
let submitted = false;
context.fetch = async (url, options) => {
  const target = String(url);
  observed.push({ target, signal: options.signal });
  assert.ok([...timers.values()].some(t => t.delay === 30000), "Deadline starts before submission");
  const isBootstrap = target.endsWith("/.well-known/cryptad-bootstrap.json");
  const isCommand = target.endsWith("/api/v1/mail/command");
  const isResult = target.endsWith("/api/v1/mail/result");
  const stall = (isBootstrap && (stalledStage.startsWith("bootstrap") || stalledStage.startsWith("refresh")))
    || (isCommand && stalledStage.startsWith("submission"))
    || (isResult && stalledStage.startsWith("result"));
  if (stall) {
    if (stalledStage.endsWith("body")) return { ok: true, json() { reached(); return aborted(options.signal); } };
    reached();
    return aborted(options.signal);
  }
  if (isBootstrap) return jsonResponse(bootstrap);
  if (isCommand) {
    if (stalledStage.startsWith("refresh") && !submitted) {
      submitted = true;
      return { ok: false, status: 401, json: async () => ({ error: { code: "invalid_app_browser_session" } }) };
    }
    return jsonResponse({ mail: { requestId: "synthetic-command" } });
  }
  assert.ok(isResult);
  reached();
  return jsonResponse({ mail: { status: "pending" } });
};

const operation = CryptaPlatform.mail.command("status", {});
const rejection = assert.rejects(operation, /Mail worker timed out\. Check operation status before retrying\./);
await atStall;
// Drain await continuations so the polling delay is installed in the polling case.
await new Promise(resolve => setImmediate(resolve));
const [deadlineId, deadline] = [...timers.entries()].find(([, timer]) => timer.delay === 30000);
timers.delete(deadlineId);
deadline.callback();
await rejection;
assert.ok(observed.length > 0);
assert.ok(observed.every(call => call.signal.aborted), "Timeout must abort in-flight network/body reads");
assert.ok(observed.every(call => call.signal === observed[0].signal), "Use one overall deadline");
assert.strictEqual(timers.size, 0, "Deadline and polling timers must be removed");
const stoppedCount = observed.length;
await new Promise(resolve => setImmediate(resolve));
assert.strictEqual(observed.length, stoppedCount, "No late result polling or resubmission");

// An explicit subsequent command works with a fresh deadline and session.
context.fetch = normalFetch;
enqueueBootstrap();
await CryptaPlatform.bootstrap.load({ appId: "feed-reader", force: true });
enqueueResponse(url => url.endsWith("/api/v1/mail/command"), { mail: { requestId: "next-command" } });
enqueueResponse(url => url.endsWith("/api/v1/mail/result"),
  { mail: { status: "complete", payloadBase64: "e30=" } });
await CryptaPlatform.mail.command("status", {});
assert.strictEqual(timers.size, 0, "Successful commands must also clear their deadline");
clearTimeout(watchdog);
