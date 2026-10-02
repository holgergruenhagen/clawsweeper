import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { supervisorArguments, unitStopped } from "./repair-config-guest-qualification.mjs";

export const PINS = Object.freeze({
  base: "2f777941de926c6f11cb0c6363ecfe4bbee94371",
  tree: "212409328808e514cbf65914fec600db05747d7a",
  patch: "d19dcf5559136bdffa4cbf6883fb20b2ce45d4532aac3090a3dc51e711bd5b53",
  candidate: "2e75822d6d09b54e217b19fcc09581daad75b96253f2ccafdda20eb448506d74",
  files: 1882,
  codex: "0.159.3", scanner: "3.97.4", pnpm: "12.4.1",
  crabbox: "5cf55179574e7cd82c478b3d44ebcab9d2f33906821f22c2e006e74bc0d2cd5a",
  label: "crabbox-proof-20261001-b-7c91e5a2",
  branch: "proof/repair-codex-config-20261001",
});
export const LIMITS = Object.freeze({
  nativeExecStarts: 12, nativeExecMs: 180_000, matrixMs: 2_700_000,
  cleanupMs: 300_000, fixtureBytes: 128 * 1024 * 1024, fixtureFiles: 1024,
  retainedBytes: 64 * 1024 * 1024, retainedFiles: 58,
});
const ROOT = "/opt/repair-config-proof-20261001";
const INPUTS = `${ROOT}/matrix-inputs.json`;
const QUALIFICATION = `${ROOT}/qualification.json`;
const SELF = fileURLToPath(import.meta.url);
const GUEST_SELF = `${ROOT}/tools/repair-config-matrix.mjs`;
const REPO = "openclaw/fixture";
const CLUSTER = "repair-config-fixture";
const ISSUE = `https://github.com/${REPO}/issues/1`;
const BEFORE = "# Fixture\n\nThis is teh fixture.\n";
const AFTER = "# Fixture\n\nThis is the fixture.\n";
const CHANGED = [
  "src/repair/env-utils.ts", "src/repair/execute-fix-artifact.ts",
  "src/repair/execute-fix-policy.ts", "src/repair/process-env.ts", "src/repair/run-worker.ts",
  "test/repair/execute-fix-policy.test.ts", "test/repair/process-env.test.ts",
];
const CELLS = ["baseline-ordinary", "baseline-maintainer", "candidate-ordinary", "candidate-maintainer"];
let executionDeadline = Infinity;
let terminationDeadline = Infinity;
const STAGE_PHASES = Object.freeze([
  "input", "root", "payload", "receipt", "fresh-paths", "head",
  "scanner-identity", "scanner-environment", "scanner-version", "boot", "prepare", "archive",
  "baseline-extract", "baseline-inventory", "baseline-ownership", "baseline-corepack",
  "baseline-install", "baseline-build", "baseline-seal",
  "candidate-extract", "candidate-apply-check", "candidate-apply", "candidate-inventory",
  "candidate-ownership", "candidate-corepack", "candidate-install", "candidate-build", "candidate-seal",
  "tools", "private-outputs", "seal", "output",
]);
const STAGE_ERROR_CODES = Object.freeze([
  "EACCES", "EPERM", "ENOENT", "ENOTDIR", "EEXIST", "EINVAL", "EIO", "ENOSPC",
  "ENOMEM", "EAGAIN", "ELOOP", "ETIMEDOUT", "ENOBUFS", "ERR_ASSERTION",
  "ERR_INVALID_ARG_TYPE", "ERR_INVALID_ARG_VALUE", "ERR_OUT_OF_RANGE",
]);
const STAGE_SIGNALS = Object.freeze([
  "SIGTERM", "SIGKILL", "SIGINT", "SIGHUP", "SIGABRT", "SIGSEGV", "SIGBUS", "SIGILL", "SIGFPE", "SIGPIPE",
]);
let stageDiagnostic = null;
export const digest = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const json = (value) => `${JSON.stringify(value)}\n`;
const readJSON = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const isHash = (value) => /^[a-f0-9]{64}$/.test(value);
const assertRoot = () => assert(process.platform === "linux" && process.getuid() === 0, "trusted guest supervisor only");

export function admitDeadline(expiresAt, now = Date.now()) {
  const expires = Date.parse(expiresAt);
  assert(Number.isFinite(expires) && expires - now >= LIMITS.matrixMs + LIMITS.cleanupMs, "insufficient native lease lifetime");
  return now + LIMITS.matrixMs;
}

export function validateEntries(entries) {
  assert(Array.isArray(entries) && entries.length === PINS.files);
  const seen = new Set();
  for (const entry of entries) {
    assert(typeof entry.path === "string" && entry.path !== "" && !path.isAbsolute(entry.path));
    assert(!entry.path.split("/").some((part) => ["", ".", "..", ".git"].includes(part)));
    assert(!seen.has(entry.path)); seen.add(entry.path);
    assert(["100644", "100755"].includes(entry.mode));
    assert(Number.isSafeInteger(entry.bytes) && entry.bytes >= 0 && isHash(entry.sha256));
  }
  assert.deepEqual(entries.map((entry) => entry.path), [...seen].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b))));
}

export function sourceInventory(root, entries) {
  return entries.map(({ path: name, mode }) => {
    const file = path.join(root, name), stat = fs.lstatSync(file);
    assert(stat.isFile() && !stat.isSymbolicLink());
    assert.equal(stat.mode & 0o111 ? "100755" : "100644", mode);
    const bytes = fs.readFileSync(file);
    return { path: name, mode, bytes: bytes.length, sha256: digest(bytes) };
  });
}

export function executionEnvelope(plan) {
  assert.equal(plan.mode, "plan");
  assert.equal(plan.status, "planned");
  assert.equal(plan.repo, REPO);
  assert.equal(plan.cluster_id, CLUSTER);
  assert.deepEqual(plan.needs_human, []);
  assert(plan.actions.some((action) => action.action === "fix_needed" && action.status === "planned"));
  const fix = plan.fix_artifact;
  assert(fix && fix.repair_strategy === "new_fix_pr" && fix.changelog_required === false && fix.allow_no_pr === false);
  assert.deepEqual(fix.likely_files, ["README.md"]);
  assert.deepEqual(fix.affected_surfaces, ["docs"]);
  assert.deepEqual(fix.source_prs, []);
  assert.deepEqual(fix.branch_update_blockers, []);
  assert.deepEqual(fix.validation_commands, ["git diff --check"]);
  assert.deepEqual(fix.repair_contract, { must_touch: ["README.md"], match: "all" });
  return { ...structuredClone(plan), mode: "execute" };
}

export function fixtureGH(args, cell) {
  const ok = (value) => ({ status: 0, stdout: typeof value === "string" ? value : JSON.stringify(value), stderr: "" });
  const endpoint = args[1];
  if (JSON.stringify(args) === JSON.stringify(["auth", "token"])) return ok("");
  if (args[0] === "api" && args.length === 2) {
    if (endpoint === `repos/${REPO}`) return ok({ full_name: REPO, private: false, default_branch: "main" });
    if (endpoint === `repos/${REPO}/branches/main`) return ok({ name: "main", commit: { sha: cell.baseSha } });
    if (endpoint === `repos/${REPO}/issues/1`) return ok({
      number: 1, state: "open", title: "README: replace teh with the", body: "",
      html_url: ISSUE, user: { login: "fixture-author" },
      author_association: cell.profile === "maintainer" ? "MEMBER" : "CONTRIBUTOR",
      labels: [], comments: 0, locked: false,
      created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z",
    });
    if (endpoint === `repos/${REPO}/issues/1/comments`) return ok([]);
    if (endpoint === `repos/${REPO}/collaborators/fixture-author/permission`)
      return ok({ permission: cell.profile === "maintainer" ? "write" : "read" });
  }
  const branch = `clawsweeper/${CLUSTER}`;
  if (JSON.stringify(args) === JSON.stringify(["api", `repos/${REPO}/git/ref/heads/${encodeURIComponent(branch)}`, "--jq", ".object.sha"]))
    return { status: 1, stdout: "", stderr: "Not Found (HTTP 404)\n" };
  if (JSON.stringify(args) === JSON.stringify(["pr", "list", "--repo", REPO, "--head", branch, "--state", "open", "--json", "url", "--jq", '.[0].url // ""']))
    return ok("");
  if (JSON.stringify(args) === JSON.stringify(["pr", "list", "--repo", REPO, "--state", "open", "--limit", "500", "--json", "number,title,url,headRefName"]))
    return ok([]);
  throw new Error("unexpected GH fixture operation");
}

export function fixtureGit(args, cell) {
  assert(!args.includes("push"), "every push is prohibited, including dry-run");
  const mapped = args.map((arg) => arg === `https://github.com/${REPO}.git` ? cell.origin : arg);
  assert(!mapped.some((arg) => /(?:[a-z][a-z0-9+.-]*:\/\/|^[^/]*@[^/]+:|^ext::)/i.test(arg)), "nonlocal Git destination");
  // Origin is an immutable local bare fixture. Git's protocol policy blocks other transports.
  return ["-c", "protocol.allow=never", "-c", "protocol.file.allow=always", "-c", `safe.directory=${cell.origin}`, ...mapped];
}

export function gitLauncherSource(node = process.execPath, root = ROOT) {
  assert(path.isAbsolute(node) && path.isAbsolute(root));
  // The compiled containment mounts this executable, not sibling modules or
  // external cell receipts. The read-only validation needs none of those files.
  return `#!${node}
import assert from "node:assert/strict";
import fs from "node:fs";
import {spawnSync} from "node:child_process";
const REPO=${JSON.stringify(REPO)};
${fixtureGit.toString()}
try {
  const root=${JSON.stringify(root)};
  const names=${JSON.stringify(CELLS)};
  const name=names.find(name=>process.cwd()===root+"/private/cells/"+name||process.cwd().startsWith(root+"/private/cells/"+name+"/"));
  assert(name, "nonfixture Git cwd");
  const home=root+"/private/cells/"+name;
  const args=process.argv.slice(2), mapped=fixtureGit(args,{origin:home+"/origin.git"});
  if (JSON.stringify(args)!==JSON.stringify(["diff","--check"])) {
    const file=home+"/trace.jsonl";
    const row=JSON.stringify({kind:"git",args:args.map(arg=>arg.replaceAll(home,"<cell>"))})+"\\n";
    const size=fs.existsSync(file)?fs.statSync(file).size:0;
    assert(size+Buffer.byteLength(row)<=256*1024);
    fs.appendFileSync(file,row,{mode:0o600});
  }
  const result=spawnSync("/usr/bin/git",mapped,{cwd:process.cwd(),env:process.env,stdio:"inherit",timeout:60000,killSignal:"SIGKILL"});
  process.exitCode=result.error||result.signal?1:result.status??1;
} catch {process.stderr.write("fixture Git failed closed\\n");process.exitCode=1;}
`;
}

export function classifyExec(args, cell) {
  assert.equal(args[0], "exec");
  assert(!args.includes("--dangerously-bypass-approvals-and-sandbox"));
  const output = args[args.indexOf("--output-last-message") + 1];
  assert(args.includes("--output-last-message") && path.isAbsolute(output));
  const schemaIndex = args.indexOf("--output-schema");
  const schema = schemaIndex < 0 ? "" : args[schemaIndex + 1];
  const phase = schema.endsWith("/schema/repair/codex-result.schema.json") ? "plan"
    : schema === `${cell.work}/codex-review.schema.json` ? "review" : schema === "" ? "edit" : null;
  assert(phase, "unrecognized native phase");
  assert(output.startsWith(phase === "plan" ? `${cell.runRoot}/` : `${cell.work}/`));
  assert.equal(args[args.indexOf("--sandbox") + 1], phase === "edit" ? "workspace-write" : "read-only");
  const configs = args.flatMap((arg, index) => arg === "-c" ? [args[index + 1]] : []);
  const ordered = ['approval_policy="never"', 'forced_login_method="api"', 'model_reasoning_effort="medium"'];
  if (cell.profile === "maintainer") ordered.push('service_tier="fast"');
  const start = configs.indexOf(ordered[0]);
  assert(start >= 0);
  assert.deepEqual(configs.slice(start, start + ordered.length), ordered);
  assert.equal(configs.filter((value) => value.startsWith("service_tier=")).length, cell.profile === "maintainer" ? 1 : 0);
  assert(!configs.some((value) => value.includes("danger-full-access")));
  return phase;
}

export function reserveStart(dir, cellName, phase) {
  assert(CELLS.includes(cellName) && ["plan", "edit", "review"].includes(phase));
  const existing = fs.readdirSync(dir).filter((name) => name.endsWith(".start.json"));
  assert(existing.length < LIMITS.nativeExecStarts, "native exec start ceiling");
  const slot = `${cellName}-${phase}.start.json`;
  const reservation = path.join(dir, `${cellName}-${phase}.reserved`);
  fs.mkdirSync(reservation, { mode: 0o700 });
  const receipt = path.join(reservation, "receipt.json");
  fs.writeFileSync(receipt, json({ cell: cellName, phase, admittedAt: Date.now() }), { flag: "wx", mode: 0o600 });
  // link is atomic and exclusive: the watchdog cannot observe a partial receipt.
  fs.linkSync(receipt, path.join(dir, slot));
  return slot;
}

export function assertRetention(paths, reserveFiles = 0, reserveBytes = 0) {
  let files = 0, bytes = 0;
  const identities = new Set();
  for (const file of paths) {
    const stat = fs.lstatSync(file);
    assert(stat.isFile() && !stat.isSymbolicLink());
    const identity = `${stat.dev}:${stat.ino}`;
    assert(!identities.has(identity)); identities.add(identity);
    files++; bytes += stat.size;
  }
  assert(files + reserveFiles <= LIMITS.retainedFiles && bytes + reserveBytes <= LIMITS.retainedBytes, "aggregate retained evidence ceiling");
  return { files, bytes };
}

// Input validation only, not GitHub group authority. The future reviewed
// acquisition payload must call this before warmup; controllerPlan is too late.
export function admitAcquisitionInput({ runnerGroupId } = {}) {
  assert(Number.isSafeInteger(runnerGroupId) && runnerGroupId > 0, "explicit repository JIT group id required");
  return { runnerGroupId, inputValidated: true, authorityVerified: false };
}

export function controllerPlan({ crabbox, runnerGroupId, leaseId, qualificationDigest, inputDigest, proofHead, proofTree, proofDigest }) {
  admitAcquisitionInput({ runnerGroupId });
  assert(path.isAbsolute(crabbox));
  assert(/^cbx_[a-f0-9]{12}$/.test(leaseId));
  assert([qualificationDigest, inputDigest, proofDigest].every(isHash));
  assert([proofHead, proofTree].every((value) => /^[a-f0-9]{40}$/.test(value)));
  const runnerName = `${PINS.label}-${leaseId}`;
  return {
    crabboxSHA256: PINS.crabbox, requiredProvider: "aws", target: "linux",
    acquisitionFlags: ["--ttl", "90m", "--idle-timeout", "90m", "--keep", "--keep-on-failure", "--no-hydrate"],
    beforeRegistration: [
      { argv: [crabbox, "run", "--id", leaseId, "--no-sync", "--no-hydrate", "--script-stdin"], purpose: "credential-free native qualification" },
      { argv: [crabbox, "run", "--id", leaseId, "--no-sync", "--no-hydrate", "--script-stdin"], purpose: "bound source staging; sealed inputs" },
    ],
    registration: {
      argv: [crabbox, "actions", "register", "--id", leaseId, "--repo", "openclaw/clawsweeper", "--name", runnerName,
        "--labels", PINS.label, "--ephemeral", "--jit", "--runner-group-id", String(runnerGroupId)],
      requires: ["authoritative repository JIT group id", "pre-warmup input admission", "qualified guest receipt",
        "sealed source/build inputs", "current code audits", "native precommit review", "signed advertised proof head"],
      // Native owns 16s request + 180s install + 30s guest/16s API cleanup.
      // This allowance is not a proved wall bound or an outer kill timer.
      allowanceMs: 300_000, nativePhaseBudgetMs: 242_000, overheadMs: 58_000, provedWallClockBound: false,
      supervision: "native phase cleanup; caller supervision requires separate review",
      capture: "bounded complete private CLI receipt; no JIT secret",
      evidenceRequired: ["binarySHA256", "argv", "code", "signal", "stdout", "stderr", "truncated", "durationMs"],
    },
    preDispatch: {
      proofHead, runnerName, runnerLabel: PINS.label,
      headArgv: ["api", `repos/openclaw/clawsweeper/git/ref/heads/${PINS.branch}`],
      runnerArgv: ["api", `repos/openclaw/clawsweeper/actions/runners?name=${encodeURIComponent(runnerName)}&per_page=2`],
    },
    dispatch: ["workflow", "run", "ci.yml", "--repo", "openclaw/clawsweeper", "--ref", PINS.branch,
      "-f", `lease_id=${leaseId}`, "-f", `source_head=${proofHead}`, "-f", `runner_name=${runnerName}`,
      "-f", `source_tree=${proofTree}`, "-f", `source_digest=${proofDigest}`,
      "-f", `qualification_digest=${qualificationDigest}`, "-f", `matrix_input_digest=${inputDigest}`],
    exactCleanup: [crabbox, "stop", leaseId],
    leasePolicy: { ttlSeconds: 5400, idleSeconds: 5400, minimumMatrixRemainingSeconds: 3000, renewal: false },
  };
}

const controllerFailures = new WeakMap();

function jitLaunchReceipt(text, runnerName) {
  assert(Buffer.byteLength(text) <= 1024);
  const receipt = JSON.parse(text);
  assert(Number.isSafeInteger(receipt?.runnerId) && receipt.runnerId > 0);
  // Match the pinned native encoder's complete record, including its newline.
  // This also rejects duplicate keys, trailing output and unreviewed fields.
  assert.equal(text, json({
    kind: "actions-jit-registration", stage: "launch-accepted", ownership: "owned",
    runnerId: receipt.runnerId, runnerName, httpStatus: 201, apiExit: 0,
    launchAccepted: true, guestCleanup: "not-started", runnerCleanup: "handoff-on-success",
  }));
  return receipt;
}

function controllerNativeFacts(result = {}) {
  const error = result.error || result.errorCode != null
    ? { code: result.error?.code ?? result.errorCode } : null;
  const facts = stageNativeFacts({ ...result, error });
  facts.timedOut ||= result.timedOut === true;
  return facts;
}

export function controllerFailureRecord(error) {
  return controllerFailures.get(error) ?? json({
    kind: "repair-config-controller-failure", phase: "input", field: "input",
    errorCode: stageErrorCode(error), reads: 0, elapsedMs: 0,
  });
}

export function dispatchAfterReadback(options, ghxCall, clock = {}) {
  const now = clock.now ?? (() => performance.now()), wallNow = clock.wallNow ?? Date.now;
  const sleep = clock.sleep ?? ((ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms));
  const started = now(), wallStarted = wallNow();
  const context = { phase: "input", field: "input", reads: 0, elapsedMs: 0 };
  let sampled = started;
  const check = (field, matches) => {
    context.field = field;
    assert(matches, "controller admission failed closed");
  };
  const elapsed = () => {
    const value = now();
    check("deadline", Number.isFinite(value) && value >= sampled);
    sampled = value;
    context.elapsedMs = Math.floor(value - started);
    return value - started;
  };
  const remaining = () => {
    const ms = Math.floor(60_000 - elapsed());
    check("deadline", ms > 0);
    return ms;
  };
  const invoke = (phase, args) => {
    context.phase = phase;
    delete context.native;
    const timeout = Math.min(30_000, remaining());
    context.field = "transport";
    let response;
    try {
      if (phase === "dispatch") context.dispatchStarted = true;
      response = ghxCall(args, { timeout, killSignal: "SIGKILL", maxBuffer: 64 * 1024 });
    } catch (error) {
      context.native = controllerNativeFacts({ error });
      throw error;
    }
    context.native = controllerNativeFacts(response ?? {});
    check("transport", response?.status === 0 && response.signal === null && !response.error
      && context.native.errorCode === null && !context.native.timedOut && !response.truncated);
    check("response", typeof response.stdout === "string" && typeof response.stderr === "string"
      && Buffer.byteLength(response.stdout) <= 64 * 1024 && Buffer.byteLength(response.stderr) <= 64 * 1024);
    remaining();
    context.field = "response";
    return response.stdout;
  };
  try {
    const plan = controllerPlan(options), expected = plan.preDispatch;
    if (!ghxCall) {
      context.phase = "tool";
      check("path", typeof options.ghx === "string" && path.isAbsolute(options.ghx) && isHash(options.ghxSHA256));
      check("path", fs.realpathSync(options.ghx) === options.ghx);
      context.field = "identity";
      check("identity", digest(fs.readFileSync(options.ghx)) === options.ghxSHA256);
      ghxCall = (args, limits) => spawnSync(options.ghx, ["--no-cache", ...args], {
        env: process.env, encoding: "utf8", ...limits,
      });
    }
    context.phase = "registration";
    const registration = options.registration;
    context.native = controllerNativeFacts({ ...registration, status: registration?.code });
    check("binary", registration?.binarySHA256 === PINS.crabbox);
    context.field = "argv";
    assert.deepEqual(registration.argv, plan.registration.argv);
    check("exit", registration.code === 0 && !registration.error && !registration.errorCode
      && !registration.failure && registration.truncated === false && !registration.timedOut
      && context.native.errorCode === null && !context.native.timedOut);
    check("signal", registration.signal === null);
    check("allowance", Number.isSafeInteger(registration.durationMs) && registration.durationMs >= 0
      && registration.durationMs <= plan.registration.allowanceMs);
    check("output", ["stdout", "stderr"].every((key) => typeof registration[key] === "string"
      && Buffer.byteLength(registration[key]) <= 64 * 1024));
    context.field = "receipt";
    const receipt = jitLaunchReceipt(registration.stdout, expected.runnerName);
    context.runnerId = receipt.runnerId;
    let runner, runnerSeen = false;
    for (;;) {
      context.phase = "runner";
      remaining();
      check("read-limit", context.reads < 12);
      context.reads++;
      const list = JSON.parse(invoke("runner", expected.runnerArgv));
      check("response", list !== null && typeof list === "object" && !Array.isArray(list)
        && Number.isSafeInteger(list.total_count) && list.total_count >= 0 && Array.isArray(list.runners));
      context.totalCount = list.total_count;
      context.rowCount = list.runners.length;
      check("cardinality", list.total_count === list.runners.length && list.total_count <= 1);
      delete context.matches;
      delete context.status;
      if (list.total_count === 0) {
        check("disappearance", !runnerSeen);
      } else {
        runner = list.runners[0];
        check("id", runner !== null && typeof runner === "object" && Number.isSafeInteger(runner.id) && runner.id > 0);
        check("id", context.runnerId === runner.id);
        context.status = ["online", "offline"].includes(runner.status) ? runner.status : "unknown";
        // Same-lease source/boot qualification and the native AWS/Linux installer
        // bind Linux execution to this runner ID; REST OS metadata is not authority.
        context.matches = {
          name: runner.name === expected.runnerName,
          os: runner.os === "linux" || runner.os === "unknown", busy: runner.busy === false,
          labels: Array.isArray(runner.labels) && runner.labels.length === 1
            && runner.labels[0]?.name === expected.runnerLabel && ["custom", "read-only"].includes(runner.labels[0]?.type),
          ephemeralPresent: Object.hasOwn(runner, "ephemeral"),
          ephemeral: !Object.hasOwn(runner, "ephemeral") || runner.ephemeral === true,
        };
        for (const field of ["name", "os", "labels", "busy", "ephemeral"]) check(field, context.matches[field]);
        // Native registration proves ephemeral when the API omits that field.
        check("status", context.status !== "unknown");
        runnerSeen = true;
        if (runner.status === "online") break;
      }
      check("read-limit", context.reads < 12);
      sleep(Math.min(5_000, remaining()));
      remaining();
    }
    // No API calls intervene between the exact head read, lifetime admission and
    // the one dispatch. The lease fields come from native authoritative metadata.
    const ref = JSON.parse(invoke("head", expected.headArgv));
    check("ref", ref?.ref === `refs/heads/${PINS.branch}`);
    check("type", ref?.object?.type === "commit");
    check("head", ref.object.sha === expected.proofHead);
    context.phase = "lifetime";
    check("lease", options.lease?.leaseId === options.leaseId && options.lease.provider === "aws");
    const spent = elapsed();
    context.field = "expiry";
    admitDeadline(options.lease.expiresAt, Math.max(wallNow(), wallStarted + spent));
    invoke("dispatch", plan.dispatch);
    return { dispatched: true, proofHead: expected.proofHead, runnerId: runner.id, runnerName: runner.name,
      runnerLabel: expected.runnerLabel, registrationDigest: digest(JSON.stringify(registration)),
      reads: context.reads, elapsedMs: context.elapsedMs };
  } catch (error) {
    // Context contains only fixed field names, enums, booleans, counts and
    // native stream hashes. Preserve the first failing field, never raw errors.
    const finished = now();
    if (Number.isFinite(finished) && finished >= sampled)
      context.elapsedMs = Math.min(Number.MAX_SAFE_INTEGER, Math.floor(finished - started));
    const failure = new Error("controller failed closed");
    const record = json({ kind: "repair-config-controller-failure", ...context, errorCode: stageErrorCode(error) });
    assert(Buffer.byteLength(record) <= 1024);
    controllerFailures.set(failure, record);
    throw failure;
  }
}

export function controllerClosure(leaseId, result) {
  assert(/^cbx_[a-f0-9]{12}$/.test(leaseId));
  const native = controllerNativeFacts({ ...result, status: result?.code });
  const bounded = result && ["stdout", "stderr"].every((key) => typeof result[key] === "string"
    && Buffer.byteLength(result[key]) <= 64 * 1024);
  const complete = bounded && result.truncated === false && !result.error && !result.errorCode
    && !result.failure && !result.timedOut && result.code === 0 && result.signal === null
    && native.errorCode === null && !native.timedOut;
  const lines = bounded ? [result.stdout, result.stderr].map((stream) => stream.split("\n")) : [];
  const unterminated = lines.some((stream) => /^released(?:\s|$)/.test(stream.at(-1)));
  const markers = lines.flatMap((stream) => stream.slice(0, -1)).filter((line) => line.startsWith("released lease="));
  const pattern = new RegExp(`^released lease=${leaseId} server=[A-Za-z0-9._:-]{1,128}$`);
  const released = complete && !unterminated && markers.length > 0 && markers.every((line) => pattern.test(line));
  return { leaseId, released: released ? true : null, leaseDisposition: released ? "released" : "unconfirmed",
    runnerDisposition: "unconfirmed", native };
}

export function scannerInvocation(scanner, args) {
  assert(path.isAbsolute(scanner) && !args.includes("--no-verification"));
  return ["/usr/bin/unshare", ["--user", "--map-root-user", "--net", "--", scanner, ...args]];
}

function cleanEnv(home, tmp = `${home}/tmp`) {
  return { HOME: home, PATH: `${ROOT}/tools:${path.dirname(process.execPath)}:/usr/local/bin:/usr/bin:/bin`,
    LANG: "C.UTF-8", TMPDIR: tmp, TMP: tmp, TEMP: tmp, GIT_TERMINAL_PROMPT: "0", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" };
}

function stagePhase(phase) {
  assert(STAGE_PHASES.includes(phase));
  stageDiagnostic = { phase };
}

const stageErrorCode = (error) => error == null ? null
  : STAGE_ERROR_CODES.includes(error.code) ? error.code : "unclassified";

function stageNativeFacts(result) {
  const output = (value) => typeof value === "string" || Buffer.isBuffer(value)
    ? { bytes: Buffer.byteLength(value), sha256: digest(value) } : null;
  return {
    exit: Number.isInteger(result.status) && result.status >= 0 && result.status <= 255 ? result.status : null,
    signal: result.signal == null ? null : STAGE_SIGNALS.includes(result.signal) ? result.signal : "unclassified",
    errorCode: stageErrorCode(result.error), timedOut: result.error?.code === "ETIMEDOUT",
    stdout: output(result.stdout), stderr: output(result.stderr),
  };
}

export function stageFailureRecord(context, error) {
  const facts = {};
  for (const key of ["uidMatch", "modeMatch", "versionMatch"])
    if (typeof context?.facts?.[key] === "boolean") facts[key] = context.facts[key];
  const record = {
    kind: "repair-config-stage-failure",
    phase: STAGE_PHASES.includes(context?.phase) ? context.phase : "input",
    errorCode: stageErrorCode(error), facts,
  };
  // Only this credential-free phase may retain command metadata. Never serialize
  // error objects, messages, command inputs, or native output bytes.
  if (context?.native) {
    const native = context.native;
    const output = (value) => value && Number.isSafeInteger(value.bytes) && value.bytes >= 0
      && typeof value.sha256 === "string" && value.sha256.length === 64 && isHash(value.sha256)
      ? { bytes: value.bytes, sha256: value.sha256 } : null;
    record.native = {
      exit: Number.isInteger(native.exit) && native.exit >= 0 && native.exit <= 255 ? native.exit : null,
      signal: native.signal == null ? null : STAGE_SIGNALS.includes(native.signal) ? native.signal : "unclassified",
      errorCode: native.errorCode == null ? null : STAGE_ERROR_CODES.includes(native.errorCode) ? native.errorCode : "unclassified",
      timedOut: native.timedOut === true, stdout: output(native.stdout), stderr: output(native.stderr),
    };
  }
  const bytes = json(record);
  assert(Buffer.byteLength(bytes) <= 1024);
  return bytes;
}

export function scannerStageOptions(q) {
  const home = `${ROOT}/private`, tmp = `${home}/tmp`;
  const stats = [home, tmp].map((file) => fs.lstatSync(file));
  const uidMatch = stats.every((stat) => stat.uid === q.proofUid && stat.gid === q.proofGid);
  const modeMatch = stats.every((stat) => stat.isDirectory() && !stat.isSymbolicLink() && (stat.mode & 0o7777) === 0o700);
  if (stageDiagnostic) stageDiagnostic.facts = { uidMatch, modeMatch };
  assert(uidMatch && modeMatch);
  return { cwd: ROOT, uid: q.proofUid, gid: q.proofGid, env: cleanEnv(home, tmp) };
}

export function commandTimeout(options = {}, now = Date.now(), workUntil = executionDeadline, cleanupUntil = terminationDeadline) {
  const timeout = Math.min(options.timeout ?? 180_000, (options.cleanup ? cleanupUntil : workUntil) - now);
  assert(timeout > 0, options.cleanup ? "termination deadline" : "matrix deadline");
  return timeout;
}

function command(command, args, options = {}) {
  const timeout = commandTimeout(options);
  const result = spawnSync(command, args, { cwd: options.cwd ?? ROOT, env: options.env ?? cleanEnv(`${ROOT}/prepare`),
    encoding: options.binary ? undefined : "utf8", timeout,
    maxBuffer: options.maxBuffer ?? 1024 * 1024, killSignal: "SIGKILL",
    ...(options.uid === undefined ? {} : { uid: options.uid, gid: options.gid }),
    ...(options.input === undefined ? {} : { input: options.input }),
  });
  if (stageDiagnostic) stageDiagnostic.native = stageNativeFacts(result);
  if (!options.allowFailure) assert(!result.error && !result.signal && result.status === 0, `${path.basename(command)} failed closed`);
  return result;
}

function sealed(file, expectedDigest) {
  const stat = fs.lstatSync(file);
  assert(stat.isFile() && !stat.isSymbolicLink() && stat.uid === 0 && stat.nlink === 1 && (stat.mode & 0o222) === 0);
  const bytes = fs.readFileSync(file);
  if (expectedDigest) assert.equal(digest(bytes), expectedDigest);
  return JSON.parse(bytes);
}

function writeSealed(file, value) {
  fs.writeFileSync(file, json(value), { flag: "wx", mode: 0o444 });
}

function toolIdentity(file, sha256) {
  const real = fs.realpathSync(file), stat = fs.lstatSync(real);
  assert(stat.isFile() && stat.uid === 0 && (stat.mode & 0o022) === 0 && (stat.mode & 0o111) !== 0);
  for (let parent = path.dirname(real); ; parent = path.dirname(parent)) {
    const stat = fs.lstatSync(parent);
    assert(stat.isDirectory() && stat.uid === 0 && (stat.mode & 0o022) === 0);
    if (parent === "/") break;
  }
  const actual = digest(fs.readFileSync(real));
  if (sha256) assert.equal(actual, sha256);
  return { path: real, sha256: actual };
}

function treeInventory(root, skip = new Set()) {
  const entries = [];
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const file = path.join(dir, entry.name), name = path.relative(root, file);
      if (skip.has(name)) continue;
      const stat = fs.lstatSync(file);
      if (stat.isDirectory()) walk(file);
      else {
        assert(stat.isFile() || stat.isSymbolicLink());
        const bytes = stat.isSymbolicLink() ? Buffer.from(fs.readlinkSync(file)) : fs.readFileSync(file);
        entries.push({ path: name, mode: stat.mode & 0o777, bytes: bytes.length, sha256: digest(bytes) });
      }
    }
  }
  walk(root);
  entries.sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
  return { files: entries.length, digest: digest(JSON.stringify(entries)) };
}

export function fixtureUsage(root = `${ROOT}/private`, io = fs) {
  let files = 0, bytes = 0;
  function walk(dir, isRoot = false) {
    let entries;
    try { entries = io.readdirSync(dir, { withFileTypes: true }); }
    catch (error) { if (error.code === "ENOENT" && !isRoot) return; throw error; }
    for (const entry of entries) {
      const file = path.join(dir, entry.name);
      let stat;
      try { stat = io.lstatSync(file); } catch (error) { if (error.code === "ENOENT") continue; throw error; }
      if (stat.isDirectory()) walk(file);
      else { files++; bytes += stat.size; }
    }
  }
  walk(root, true);
  assert(files <= LIMITS.fixtureFiles && bytes <= LIMITS.fixtureBytes, "aggregate disposable fixture ceiling");
  return { files, bytes };
}

function verifyInputs(expectedDigest) {
  const inputs = sealed(INPUTS, expectedDigest), qualification = sealed(QUALIFICATION, inputs.qualificationDigest);
  assert(qualification.qualified && qualification.supervisor.terminated);
  assert.equal(inputs.leaseId, qualification.leaseId);
  assert.equal(inputs.guestBootDigest, digest(fs.readFileSync("/proc/sys/kernel/random/boot_id")));
  assert.equal(inputs.guestBootDigest, qualification.guestBootDigest);
  assert.equal(inputs.scriptDigest, digest(fs.readFileSync(SELF)));
  assert.equal(inputs.qualifierDigest, digest(fs.readFileSync(path.join(path.dirname(SELF), "repair-config-guest-qualification.mjs"))));
  toolIdentity(inputs.node.path, inputs.node.sha256);
  toolIdentity(inputs.codex.path, inputs.codex.sha256);
  toolIdentity(inputs.scanner.path, inputs.scanner.sha256);
  assert.deepEqual(treeInventory(`${ROOT}/tools`), inputs.tools);
  for (const revision of ["baseline", "candidate"]) {
    const source = `${ROOT}/sources/${revision}`;
    assert.equal(digest(JSON.stringify(sourceInventory(source, inputs[revision].entries))), inputs[revision].sourceDigest);
    assert.deepEqual(treeInventory(`${source}/dist`), inputs[revision].compiled);
  }
  return { inputs, qualification };
}

export function makePayload(bWorktree, options) {
  const git = (...args) => command("/usr/bin/git", ["-C", bWorktree, ...args], { cwd: bWorktree }).stdout;
  assert.equal(git("rev-parse", "HEAD").trim(), PINS.base);
  assert.equal(git("rev-parse", "HEAD^{tree}").trim(), PINS.tree);
  assert.equal(git("diff", "--cached", "--name-only"), "");
  assert.deepEqual(git("diff", "--name-only", "HEAD").trim().split("\n"), CHANGED);
  const patch = git("diff", "--no-ext-diff", "--full-index", "--no-color", "HEAD");
  assert.equal(digest(patch), PINS.patch);
  const entries = git("ls-files", "--stage", "-z").split("\0").filter(Boolean).map((row) => {
    const [mode, , stage] = row.slice(0, row.indexOf("\t")).split(" ");
    assert.equal(stage, "0");
    return { path: row.slice(row.indexOf("\t") + 1), mode };
  });
  const candidate = sourceInventory(bWorktree, entries);
  validateEntries(candidate);
  assert.equal(digest(JSON.stringify(candidate)), PINS.candidate);
  assert(/^cbx_[a-f0-9]{12}$/.test(options.leaseId) && isHash(options.qualificationDigest));
  assert.equal(options.provider, "aws");
  assert.equal(options.target, "linux");
  assert(Number.isFinite(Date.parse(options.expiresAt)));
  assert(isHash(options.nativeLeaseDescriptorDigest));
  return { ...options, base: PINS.base, tree: PINS.tree, patch, candidate };
}

function ownTree(root, uid, gid, readonly = false) {
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const file = path.join(root, entry.name), stat = fs.lstatSync(file);
    if (stat.isDirectory()) ownTree(file, uid, gid, readonly);
    if (!stat.isSymbolicLink()) {
      fs.chownSync(file, uid, gid);
      if (readonly) fs.chmodSync(file, stat.isDirectory() || stat.mode & 0o111 ? 0o555 : 0o444);
    }
  }
  fs.chownSync(root, uid, gid);
  if (readonly) fs.chmodSync(root, 0o555);
}

function stage(payload) {
  stagePhase("root");
  stageDiagnostic.facts = { uidMatch: process.getuid() === 0 };
  assertRoot();
  stagePhase("payload");
  assert.equal(payload.base, PINS.base); assert.equal(payload.tree, PINS.tree);
  assert.equal(digest(payload.patch), PINS.patch);
  validateEntries(payload.candidate);
  assert.equal(digest(JSON.stringify(payload.candidate)), PINS.candidate);
  stagePhase("receipt");
  const q = sealed(QUALIFICATION, payload.qualificationDigest);
  assert(q.qualified && q.probes.containment.markerMatch && q.probes.sandbox.markerMatch && q.supervisor.terminated);
  assert.equal(payload.leaseId, q.leaseId);
  stagePhase("fresh-paths");
  assert(!fs.existsSync(INPUTS) && !fs.existsSync(`${ROOT}/sources`) && !fs.existsSync(`${ROOT}/tools`));
  stagePhase("head");
  const repository = fs.realpathSync(process.cwd());
  assert.equal(command("/usr/bin/git", ["-c", `safe.directory=${repository}`, "rev-parse", "HEAD"], { cwd: repository }).stdout.trim(), q.source.head);
  stagePhase("scanner-identity");
  const scanner = toolIdentity(payload.scanner.path, payload.scanner.sha256);
  stagePhase("scanner-environment");
  const scannerOptions = scannerStageOptions(q);
  stagePhase("scanner-version");
  const [scannerCommand, scannerArgs] = scannerInvocation(scanner.path, ["--version"]);
  const scannerVersion = command(scannerCommand, scannerArgs, scannerOptions);
  stageDiagnostic.facts = { versionMatch: `${scannerVersion.stdout}${scannerVersion.stderr}`.trim() === `trufflehog ${PINS.scanner}` };
  assert.equal(`${scannerVersion.stdout}${scannerVersion.stderr}`.trim(), `trufflehog ${PINS.scanner}`);
  const inputs = {
    format: 1, leaseId: payload.leaseId, expiresAt: payload.expiresAt,
    nativeLeaseDescriptorDigest: payload.nativeLeaseDescriptorDigest, qualificationDigest: payload.qualificationDigest,
    guestBootDigest: q.guestBootDigest, proofUid: q.proofUid, proofGid: q.proofGid,
    node: q.node, codex: q.codex, scanner, scriptDigest: digest(fs.readFileSync(SELF)),
    qualifierDigest: digest(fs.readFileSync(path.join(path.dirname(SELF), "repair-config-guest-qualification.mjs"))),
    nativeExecStartsLimit: 12, underlyingModelRequestCount: null,
  };
  stagePhase("boot");
  assert.equal(digest(fs.readFileSync("/proc/sys/kernel/random/boot_id")), q.guestBootDigest);
  stagePhase("prepare");
  const prepare = `${ROOT}/prepare`;
  fs.mkdirSync(prepare, { mode: 0o700 });
  fs.chownSync(prepare, q.runnerUid, fs.statSync(repository).gid);
  fs.mkdirSync(`${prepare}/tmp`, { mode: 0o700 });
  fs.chownSync(`${prepare}/tmp`, q.runnerUid, fs.statSync(repository).gid);
  stagePhase("archive");
  const archive = command("/usr/bin/git", ["-c", `safe.directory=${repository}`, "archive", PINS.base], { cwd: repository, binary: true, maxBuffer: 128 * 1024 * 1024 }).stdout;
  for (const revision of ["baseline", "candidate"]) {
    stagePhase(`${revision}-extract`);
    const source = `${ROOT}/sources/${revision}`;
    fs.mkdirSync(source, { recursive: true, mode: 0o755 });
    command("/usr/bin/tar", ["-x", "--no-same-owner", "--no-same-permissions", "-C", source], { input: archive });
    if (revision === "candidate") {
      stagePhase("candidate-apply-check");
      command("/usr/bin/git", ["apply", "--check", "-"], { cwd: source, input: payload.patch });
      stagePhase("candidate-apply");
      command("/usr/bin/git", ["apply", "-"], { cwd: source, input: payload.patch });
    }
    stagePhase(`${revision}-inventory`);
    const entries = sourceInventory(source, payload.candidate);
    if (revision === "candidate") assert.deepEqual(entries, payload.candidate);
    inputs[revision] = { entries, sourceDigest: digest(JSON.stringify(entries)) };
    stagePhase(`${revision}-ownership`);
    ownTree(source, q.runnerUid, fs.statSync(repository).gid);
    const buildOptions = { cwd: source, env: cleanEnv(prepare), uid: q.runnerUid, gid: fs.statSync(repository).gid };
    stagePhase(`${revision}-corepack`);
    const pnpmVersion = command("corepack", ["pnpm", "--version"], buildOptions).stdout.trim();
    stageDiagnostic.facts = { versionMatch: pnpmVersion === PINS.pnpm };
    assert.equal(pnpmVersion, PINS.pnpm);
    stagePhase(`${revision}-install`);
    command("corepack", ["pnpm", "install", "--frozen-lockfile"], buildOptions);
    stagePhase(`${revision}-build`);
    command("corepack", ["pnpm", "run", "build:node"], buildOptions);
    stagePhase(`${revision}-seal`);
    assert.deepEqual(sourceInventory(source, entries), entries);
    ownTree(source, 0, 0, true);
    inputs[revision].compiled = treeInventory(`${source}/dist`);
    // Only native runtime output is writable; source/dependencies/build stay sealed.
    fs.chmodSync(source, 0o755);
    fs.mkdirSync(`${source}/.clawsweeper-repair`, { mode: 0o755 });
    fs.symlinkSync(`${ROOT}/private/runs/${revision}`, `${source}/.clawsweeper-repair/runs`);
    fs.chmodSync(source, 0o555);
  }
  stagePhase("tools");
  fs.mkdirSync(`${ROOT}/tools`, { mode: 0o755 });
  fs.copyFileSync(SELF, GUEST_SELF, fs.constants.COPYFILE_EXCL);
  fs.copyFileSync(path.join(path.dirname(SELF), "repair-config-guest-qualification.mjs"), `${ROOT}/tools/repair-config-guest-qualification.mjs`, fs.constants.COPYFILE_EXCL);
  for (const [name, mode] of [["codex", "record-codex"], ["gh", "fixture-gh"], ["trufflehog", "scanner"]])
    fs.writeFileSync(`${ROOT}/tools/${name}`, `#!${inputs.node.path}\nimport {main} from "./repair-config-matrix.mjs"; await main([${JSON.stringify(mode)}, ...process.argv.slice(2)]);\n`, { flag: "wx", mode: 0o555 });
  fs.writeFileSync(`${ROOT}/tools/git`, gitLauncherSource(inputs.node.path), { flag: "wx", mode: 0o555 });
  fs.writeFileSync(`${ROOT}/tools/package.json`, '{"type":"module"}\n', { flag: "wx", mode: 0o444 });
  ownTree(`${ROOT}/tools`, 0, 0, true);
  inputs.tools = treeInventory(`${ROOT}/tools`);
  stagePhase("private-outputs");
  for (const dir of ["cells", "runs", "runs/baseline", "runs/candidate", "admission"])
    fs.mkdirSync(`${ROOT}/private/${dir}`, { recursive: true, mode: 0o700 });
  ownTree(`${ROOT}/private`, q.proofUid, q.proofGid);
  stagePhase("seal");
  writeSealed(INPUTS, inputs);
  return { staged: true, inputDigest: digest(fs.readFileSync(INPUTS)), leaseId: inputs.leaseId,
    baseline: inputs.baseline.sourceDigest, candidate: inputs.candidate.sourceDigest, patch: PINS.patch };
}

export function observeService(unit, control = command, files = fs) {
  assert(/^repair-proof-[a-f0-9]{12}-[a-f0-9-]{36}\.service$/.test(unit));
  const state = control("/usr/bin/systemctl", ["--no-ask-password", "show", unit, "--property=LoadState,ActiveState,MainPID,ControlPID,ControlGroup"],
    { timeout: 15_000, allowFailure: true, cleanup: true });
  const fields = Object.fromEntries((state.stdout ?? "").trim().split("\n").map((line) => {
    const at = line.indexOf("="); return [line.slice(0, at), line.slice(at + 1)];
  }));
  const group = `/system.slice/${unit}`;
  assert(!fields.ControlGroup || fields.ControlGroup === group);
  let groupExists = true, populated = null;
  try {
    assert(files.lstatSync(`/sys/fs/cgroup${group}`).isDirectory());
    const events = files.readFileSync(`/sys/fs/cgroup${group}/cgroup.events`, "utf8");
    assert(/^populated [01]$/m.test(events));
    populated = /^populated 1$/m.test(events);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    groupExists = false;
  }
  return { fields, groupExists, terminated: [0, 1, 4].includes(state.status) && !state.error && !state.signal && unitStopped(fields, groupExists, populated) };
}

async function rootService(inputs, name, commandPath, args, env, options = {}) {
  assertRoot();
  const unit = `repair-proof-${inputs.leaseId.slice(4)}-${crypto.randomUUID()}.service`;
  const seconds = Math.min(options.seconds ?? 450, Math.floor((options.deadline - Date.now() - 10_000) / 1000));
  assert(seconds > 10);
  const target = ["/usr/bin/setpriv", "--reuid", String(inputs.proofUid), "--regid", String(inputs.proofGid),
    "--clear-groups", "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all", "--no-new-privs",
    "/usr/bin/env", "-i", ...Object.entries(env).map(([key, value]) => `${key}=${value}`), commandPath, ...args];
  const serviceArgs = supervisorArguments(unit, target[0], target.slice(1)).map((arg) =>
    arg === "--property=RuntimeMaxSec=100s" ? `--property=RuntimeMaxSec=${seconds}s` : arg);
  const prior = observeService(unit);
  assert(prior.terminated && prior.fields.LoadState === "not-found" && !prior.groupExists, "new task unit only");
  let outputBytes = 0, stdout = "", failure = null, stopped = false;
  const stop = () => {
    if (stopped) return; stopped = true;
    try {
      const result = command("/usr/bin/systemctl", ["--no-ask-password", "stop", unit], { timeout: 20_000, allowFailure: true, cleanup: true });
      if (result.error || result.signal || result.status !== 0) failure ??= "native-stop";
    } catch { failure ??= "native-stop"; }
  };
  let status;
  try {
    status = await new Promise((resolve) => {
      const child = spawn("/usr/bin/timeout", ["--signal=TERM", "--kill-after=5s", `${seconds + 10}s`, "/usr/bin/systemd-run", ...serviceArgs], {
        cwd: ROOT, env: cleanEnv(`${ROOT}/prepare`), stdio: [options.input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
      });
      const monitor = setInterval(() => {
        try {
          fixtureUsage();
          if (Date.now() >= options.deadline) throw new Error("matrix deadline");
          for (const slot of fs.readdirSync(`${ROOT}/private/admission`).filter((name) => name.endsWith(".start.json"))) {
            const admission = readJSON(`${ROOT}/private/admission/${slot}`);
            if (!fs.existsSync(`${ROOT}/private/admission/${slot.replace(".start.json", ".exit.json")}`)
              && Date.now() - admission.admittedAt >= LIMITS.nativeExecMs - 5_000)
              throw new Error("native start deadline");
          }
        }
        catch { failure ??= "fixture-or-time-budget"; stop(); }
      }, 200);
      const capture = (chunk, isStdout) => {
        outputBytes += chunk.length;
        if (outputBytes > 2 * 1024 * 1024) { failure ??= "output-budget"; stop(); return; }
        if (isStdout && !options.secret) stdout += chunk;
      };
      child.stdout.on("data", (chunk) => capture(chunk, true));
      child.stderr.on("data", (chunk) => capture(chunk, false));
      child.on("error", () => { failure ??= "spawn"; });
      if (child.stdin) { child.stdin.on("error", () => { failure ??= "stdin"; }); child.stdin.end(options.input); }
      child.on("close", (code, signal) => { clearInterval(monitor); resolve({ code, signal }); });
    });
  } finally {
    let settled;
    try { settled = observeService(unit); } catch { failure ??= "termination-observation"; }
    if (!settled?.terminated) {
      stop();
      try { settled = observeService(unit); } catch { failure ??= "termination-observation"; }
    }
    assert(settled?.terminated, "native child termination unconfirmed");
  }
  assert(status?.code === 0 && !status.signal && !failure, `${name} failed closed`);
  return { status: 0, outputBytes, stdout };
}

function cellEnvironment(inputs, cell) {
  return {
    ...cleanEnv(cell.home, cell.tmp), CODEX_HOME: `${ROOT}/private/codex`,
    CODEX_BIN: `${ROOT}/tools/codex`, GH_BIN: `${ROOT}/tools/gh`,
    REPAIR_MATRIX_CELL: cell.name,
    CLAWSWEEPER_STEERABLE_CODEX: "0", CLAWSWEEPER_TARGET_CHECKOUT: cell.target,
    CLAWSWEEPER_RESULT_REPAIR_ATTEMPTS: "0", CLAWSWEEPER_FIX_EDIT_ATTEMPTS: "1",
    CLAWSWEEPER_CODEX_REVIEW_ATTEMPTS: "1", CLAWSWEEPER_ALLOW_EXECUTE: "1",
    CLAWSWEEPER_ALLOW_FIX_PR: "1", CLAWSWEEPER_ALLOWED_OWNER: "openclaw",
    CLAWSWEEPER_INSTALL_TARGET_DEPS: "0", CLAWSWEEPER_CODEX_LOGIN_METHOD: "api",
    CLAWSWEEPER_MODEL: "internal", CLAWSWEEPER_CODEX_TIMEOUT_MS: "175000",
    CLAWSWEEPER_CODEX_REVIEW_TIMEOUT_MS: "175000", CLAWSWEEPER_NETWORK_COMMAND_TIMEOUT_MS: "30000",
    CLAWSWEEPER_FIX_STEP_TIMEOUT_MS: "450000", CLAWSWEEPER_FIX_REPORT_RESERVE_MS: "10000",
    CLAWSWEEPER_FIX_LATE_WORKER_RESERVE_MS: "10000",
    CLAWSWEEPER_GIT_USER_NAME: "Fixture Author", CLAWSWEEPER_GIT_USER_EMAIL: "fixture@example.invalid",
  };
}

export function jobText(mode) {
  assert(["plan", "execute"].includes(mode));
  return `---\nrepo: ${REPO}\ncluster_id: ${CLUSTER}\nmode: ${mode}\nallowed_actions: [fix, raise_pr]\nallow_fix_pr: true\nsecurity_sensitive: false\ncandidates: ['#1']\ncanonical: ['#1']\n---\nFix only the README typo "teh" to "the". Do not use nested agents or model commands.\nPlan a new_fix_pr for this issue, with a fix_needed/planned action. No human decision is needed.\nThe fix artifact must have affected_surfaces ["docs"], likely_files ["README.md"], validation_commands ["git diff --check"], repair_contract {"must_touch":["README.md"],"match":"all"}, source_prs [], branch_update_blockers [], changelog_required false, and allow_no_pr false. Do not publish anything.\n`;
}

function makeCell(inputs, name) {
  const [revision, profile] = name.split("-");
  const home = `${ROOT}/private/cells/${name}`;
  const cell = { name, revision, profile, home, target: `${home}/target`, origin: `${home}/origin.git`,
    work: `${home}/work`, tmp: `${home}/tmp`, source: `${ROOT}/sources/${revision}`,
    runRoot: `${ROOT}/sources/${revision}/.clawsweeper-repair/runs` };
  for (const dir of [home, cell.target, cell.work, cell.tmp]) fs.mkdirSync(dir, { mode: 0o700 });
  const env = { ...cleanEnv(home, cell.tmp), GIT_AUTHOR_NAME: "Fixture Author", GIT_AUTHOR_EMAIL: "fixture@example.invalid",
    GIT_COMMITTER_NAME: "Fixture Author", GIT_COMMITTER_EMAIL: "fixture@example.invalid",
    GIT_AUTHOR_DATE: "2026-01-01T00:00:00Z", GIT_COMMITTER_DATE: "2026-01-01T00:00:00Z" };
  const git = (...args) => command("/usr/bin/git", args, { cwd: cell.target, env }).stdout.trim();
  git("init", "-b", "main");
  fs.writeFileSync(`${cell.target}/README.md`, "# Fixture\n");
  git("add", "README.md"); git("-c", "commit.gpgsign=false", "commit", "-m", "fixture foundation");
  fs.writeFileSync(`${cell.target}/README.md`, BEFORE);
  git("add", "README.md"); git("-c", "commit.gpgsign=false", "commit", "-m", "fixture typo");
  cell.baseSha = git("rev-parse", "HEAD");
  git("clone", "--bare", "--no-local", cell.target, cell.origin);
  git("remote", "add", "origin", cell.origin);
  git("fetch", "origin");
  fs.writeFileSync(`${home}/plan.md`, jobText("plan"), { mode: 0o600 });
  fs.writeFileSync(`${home}/execute.md`, jobText("execute"), { mode: 0o600 });
  ownTree(home, inputs.proofUid, inputs.proofGid);
  ownTree(cell.origin, 0, 0, true);
  cell.originInventory = treeInventory(cell.origin);
  writeSealed(`${ROOT}/cell-${name}.json`, cell);
  return cell;
}

function currentCell() {
  const fromCwd = CELLS.find((name) => process.cwd() === `${ROOT}/private/cells/${name}` || process.cwd().startsWith(`${ROOT}/private/cells/${name}/`));
  const name = process.env.REPAIR_MATRIX_CELL ?? fromCwd;
  assert(CELLS.includes(name));
  if (fromCwd) assert.equal(name, fromCwd);
  const cell = sealed(`${ROOT}/cell-${name}.json`);
  assert.equal(cell.name, name);
  return cell;
}

function trace(cell, value) {
  const bytes = json(value);
  const file = `${cell.home}/trace.jsonl`;
  const size = fs.existsSync(file) ? fs.statSync(file).size : 0;
  assert(size + Buffer.byteLength(bytes) <= 256 * 1024, "cell trace ceiling");
  fs.appendFileSync(file, bytes, { mode: 0o600 });
}

async function recordCodex(args) {
  const inputs = sealed(INPUTS), cell = currentCell();
  assert.equal(process.getuid(), inputs.proofUid);
  const phase = classifyExec(args, cell);
  for (const name of Object.keys(process.env))
    assert(!/^(?:GITHUB_|ACTIONS_|RUNNER_|GH_TOKEN$|REPO_TOKEN$|OPENAI_|CODEX_API_KEY$|CLAWSWEEPER_INTERNAL_MODEL$|CLAWSWEEPER_.*(?:TOKEN|URL)$|GIT_CONFIG_(?:COUNT|PARAMETERS|KEY_.*|VALUE_.*)$)/.test(name), "unqualified model environment");
  let slot;
  try { slot = reserveStart(`${ROOT}/private/admission`, cell.name, phase); }
  catch (error) { trace(cell, { kind: "rejected-native-start", phase }); throw error; }
  const output = args[args.indexOf("--output-last-message") + 1];
  const normalized = args.map((value) => (phase === "plan" ? value.replaceAll(path.dirname(output), "<run>") : value)
    .replaceAll(cell.source, "<source>").replaceAll(cell.home, "<cell>")
    .replaceAll(`${ROOT}/private/runs/${cell.revision}`, "<runs>"));
  const started = Date.now();
  const status = await new Promise((resolve) => {
    const child = spawn(inputs.codex.path, args, {
      cwd: process.cwd(), env: process.env, stdio: "inherit",
    });
    // The root service monitor terminates the whole cgroup at the start deadline.
    child.on("spawn", () => trace(cell, { kind: "native-start", phase, argv: normalized, githubActionsPresent: false, credentialsInEnvironment: false }));
    child.on("error", () => resolve(1));
    child.on("close", (code, signal) => resolve(signal ? 1 : code ?? 1));
  });
  trace(cell, { kind: "native-exit", phase, status, durationMs: Date.now() - started });
  fs.writeFileSync(`${ROOT}/private/admission/${slot.replace(".start.json", ".exit.json")}`, json({ status }), { flag: "wx", mode: 0o600 });
  process.exitCode = status;
}

function runFixture(mode, args) {
  if (mode === "scanner") {
    const inputs = sealed(INPUTS);
    const [scannerCommand, scannerArgs] = scannerInvocation(inputs.scanner.path, args);
    const result = spawnSync(scannerCommand, scannerArgs, {
      env: process.env, stdio: "inherit", timeout: 180_000, killSignal: "SIGKILL",
    });
    process.exitCode = result.error || result.signal ? 1 : result.status ?? 1;
    return;
  }
  const cell = currentCell();
  try {
    if (mode === "fixture-gh") {
      const result = fixtureGH(args, cell);
      trace(cell, { kind: "gh", args, status: result.status });
      process.stdout.write(result.stdout); process.stderr.write(result.stderr); process.exitCode = result.status;
    } else {
      const mapped = fixtureGit(args, cell);
      trace(cell, { kind: "git", args: args.map((arg) => arg.replaceAll(cell.home, "<cell>")) });
      const result = spawnSync("/usr/bin/git", mapped, { cwd: process.cwd(), env: process.env, stdio: "inherit", timeout: 60_000 });
      process.exitCode = result.error || result.signal ? 1 : result.status ?? 1;
    }
  } catch (error) {
    trace(cell, { kind: "rejected-fixture-operation", operation: mode });
    throw error;
  }
}

async function loginRoot(packet) {
  assertRoot();
  const { inputs } = verifyInputs(packet.inputDigest);
  assert(!fs.existsSync(`${ROOT}/login.json`));
  admitDeadline(inputs.expiresAt);
  assert(typeof packet.apiKey === "string" && packet.apiKey.length > 0 && packet.apiKey.length < 16_384 && !/[\r\n\0]/.test(packet.apiKey));
  assert(typeof packet.model === "string" && packet.model.trim() === packet.model && packet.model.length > 0 && packet.model.length < 256);
  const home = `${ROOT}/private`, codexHome = `${home}/codex`;
  assert(!fs.existsSync(`${codexHome}/auth.json`), "no existing authentication reuse");
  fs.writeFileSync(`${codexHome}/config.toml`, `model = ${JSON.stringify(packet.model)}\nmodel_reasoning_effort = "medium"\n`, { flag: "wx", mode: 0o600 });
  fs.chownSync(`${codexHome}/config.toml`, inputs.proofUid, inputs.proofGid);
  const env = { ...cleanEnv(home), CODEX_HOME: codexHome };
  await rootService(inputs, "native-api-login", inputs.codex.path, ["login", "--with-api-key"], env,
    { input: `${packet.apiKey}\n`, secret: true, seconds: 30, deadline: Date.now() + 60_000 });
  packet.apiKey = ""; packet.model = "";
  writeSealed(`${ROOT}/login.json`, { api: true, inputDigest: digest(fs.readFileSync(INPUTS)), guestBootDigest: inputs.guestBootDigest, nativeStatus: 0 });
  return { authenticated: true, nativeStatus: 0, credentialsLogged: false };
}

async function matrix(expectedDigest) {
  assertRoot();
  const { inputs } = verifyInputs(expectedDigest);
  const login = sealed(`${ROOT}/login.json`);
  assert(login.api && login.nativeStatus === 0 && login.inputDigest === expectedDigest);
  const deadline = admitDeadline(inputs.expiresAt);
  executionDeadline = deadline;
  // Cleanup cannot admit new work. It can only stop/observe the exact owned unit
  // and finalize evidence within the already-reserved native lease lifetime.
  terminationDeadline = deadline + LIMITS.cleanupMs - 5_000;
  assert(!fs.existsSync(`${ROOT}/matrix-started.json`), "one matrix attempt only");
  writeSealed(`${ROOT}/matrix-started.json`, { deadline, inputDigest: expectedDigest });
  const observations = [];
  let failure = null, peak = { files: 0, bytes: 0 };
  try {
    for (const name of CELLS) {
      const cell = makeCell(inputs, name), env = cellEnvironment(inputs, cell);
      const node = inputs.node.path;
      const runsBefore = fs.readdirSync(`${ROOT}/private/runs/${cell.revision}`);
      await rootService(inputs, `${name}-plan`, node, [`${cell.source}/dist/repair/run-worker.js`, `${cell.home}/plan.md`, "--mode", "plan"], env, { deadline, seconds: 220 });
      assert.equal(fs.readFileSync(`${cell.target}/README.md`, "utf8"), BEFORE);
      const additions = fs.readdirSync(`${ROOT}/private/runs/${cell.revision}`).filter((entry) => !runsBefore.includes(entry));
      assert.equal(additions.length, 1);
      const runDir = `${ROOT}/private/runs/${cell.revision}/${additions[0]}`;
      await rootService(inputs, `${name}-deterministic-review`, node, [`${cell.source}/dist/repair/review-results.js`, runDir], env, { deadline, seconds: 40 });
      const planBytes = fs.readFileSync(`${runDir}/result.json`), plan = JSON.parse(planBytes);
      const envelope = executionEnvelope(plan);
      const clusterBytes = fs.readFileSync(`${runDir}/cluster-plan.json`);
      const cluster = JSON.parse(clusterBytes);
      const item = cluster.items.find((item) => item.ref === "#1");
      assert.equal(item.author_association, cell.profile === "maintainer" ? "MEMBER" : "CONTRIBUTOR");
      const executionDir = `${cell.home}/execution`;
      fs.mkdirSync(executionDir, { mode: 0o700 });
      fs.writeFileSync(`${executionDir}/result.json`, json(envelope), { mode: 0o600 });
      fs.writeFileSync(`${executionDir}/cluster-plan.json`, clusterBytes, { mode: 0o600 });
      ownTree(executionDir, inputs.proofUid, inputs.proofGid);
      const executed = await rootService(inputs, `${name}-fix-review`, node, [`${cell.source}/dist/repair/execute-fix-artifact.js`,
        `${cell.home}/execute.md`, `${executionDir}/result.json`, "--target-dir", cell.target, "--work-dir", cell.work,
        "--dry-run", "--defer-publication"], env, { deadline, seconds: 450 });
      const syncLines = executed.stdout.split("\n").filter((line) => line.includes("final base sync result"));
      assert.equal(syncLines.length, 1);
      assert.match(syncLines[0], /"status"\s*:\s*"already-current"/);
      assert.deepEqual(fs.readFileSync(`${runDir}/result.json`), planBytes);
      assert.deepEqual(fs.readFileSync(`${executionDir}/cluster-plan.json`), clusterBytes);
      assert.equal(fs.readFileSync(`${cell.target}/README.md`, "utf8"), AFTER);
      const git = (...args) => command("/usr/bin/git", ["-c", `safe.directory=${cell.target}`, ...args], { cwd: cell.target }).stdout.trim();
      assert.equal(git("status", "--porcelain"), "");
      assert.equal(git("diff", "--name-only", cell.baseSha, "HEAD"), "README.md");
      const report = readJSON(`${executionDir}/fix-execution-report.json`);
      assert.equal(report.dry_run, true);
      const action = report.actions.find((action) => action.action === "open_fix_pr");
      assert(action && action.status === "planned" && action.commit === git("rev-parse", "HEAD"));
      assert.equal(action.merge_preflight.codex_review.findings_addressed, true);
      assert(["clean", "passed"].includes(action.merge_preflight.codex_review.status));
      assert(action.merge_preflight.validation_commands.includes("git diff --check"));
      assert.deepEqual(treeInventory(cell.origin), cell.originInventory);
      const traces = fs.readFileSync(`${cell.home}/trace.jsonl`, "utf8").trim().split("\n").map(JSON.parse);
      assert(!traces.some((entry) => entry.kind.startsWith("rejected")));
      const starts = traces.filter((entry) => entry.kind === "native-start");
      assert.deepEqual(starts.map((entry) => entry.phase), ["plan", "edit", "review"]);
      const exits = traces.filter((entry) => entry.kind === "native-exit");
      assert.equal(exits.length, 3);
      assert(exits.every((entry) => entry.status === 0 && entry.durationMs <= LIMITS.nativeExecMs));
      assert(traces.some((entry) => entry.kind === "git" && entry.args.includes("fetch")));
      observations.push({ name, profile: cell.profile, nativeExecStarts: 3, phaseCounts: { plan: 1, edit: 1, review: 1 },
        starts, finalDiff: git("diff", "--no-ext-diff", "--no-color", cell.baseSha, "HEAD"), commit: action.commit,
        planDigest: digest(planBytes), clusterDigest: digest(clusterBytes), resultDigest: digest(json(report)), originUnchanged: true, finalBaseSync: "already-current" });
      const usage = fixtureUsage();
      peak = { files: Math.max(peak.files, usage.files), bytes: Math.max(peak.bytes, usage.bytes) };
      // Seal completed cells against later model writes; preserve raw observations until capture.
      ownTree(cell.home, 0, 0, true);
      ownTree(runDir, 0, 0, true);
    }
    for (const profile of ["ordinary", "maintainer"]) {
      const a = observations.find((cell) => cell.name === `baseline-${profile}`);
      const b = observations.find((cell) => cell.name === `candidate-${profile}`);
      assert.deepEqual(a.starts, b.starts);
      assert.equal(a.finalDiff, b.finalDiff);
    }
    assert.equal(fs.readdirSync(`${ROOT}/private/admission`).filter((name) => name.endsWith(".start.json")).length, 12);
    verifyInputs(expectedDigest);
  } catch {
    failure = "matrix failed closed; no retry or fallback";
  }
  const actualStarts = CELLS.flatMap((name) => {
    const file = `${ROOT}/private/cells/${name}/trace.jsonl`;
    return fs.existsSync(file) ? fs.readFileSync(file, "utf8").trim().split("\n").filter(Boolean).map(JSON.parse).filter((row) => row.kind === "native-start") : [];
  });
  const result = { passed: failure === null, failure, leaseId: inputs.leaseId, nativeExecStarts: actualStarts.length,
    phaseCounts: Object.fromEntries(["plan", "edit", "review"].map((phase) => [phase, actualStarts.filter((row) => row.phase === phase).length])),
    underlyingModelRequestCount: null, observations, peak, inputDigest: expectedDigest, durationMs: LIMITS.matrixMs - (deadline - Date.now()),
    limits: "Compiled fixture plan/edit/review only; no production publication or deployment proof" };
  writeSealed(`${ROOT}/matrix-result.json`, result);
  if (failure) process.exitCode = 1;
  return result;
}

function readInput(maxBytes = 1024 * 1024) {
  const bytes = fs.readFileSync(0);
  assert(bytes.length <= maxBytes);
  return JSON.parse(bytes);
}

export async function main(argv = process.argv.slice(2)) {
  const [mode, ...args] = argv;
  try {
    if (mode === "record-codex") return await recordCodex(args);
    if (["fixture-gh", "fixture-git", "scanner"].includes(mode)) return runFixture(mode, args);
    let result;
    if (mode === "stage") {
      stagePhase("input");
      result = stage(readInput(2 * 1024 * 1024));
      stagePhase("output");
    }
    else if (mode === "payload") {
      assert.equal(args.length, 1);
      result = makePayload(fs.realpathSync(args[0]), readInput());
    } else if (mode === "controller-plan") result = controllerPlan(readInput());
    else if (mode === "controller-dispatch") result = dispatchAfterReadback(readInput());
    else if (mode === "controller-closure") {
      const input = readInput();
      result = controllerClosure(input.leaseId, input.result);
      if (!result.released) process.exitCode = 1;
    }
    else if (mode === "verify-stage") {
      assert.equal(args.length, 1);
      const { inputs } = verifyInputs(args[0]);
      admitDeadline(inputs.expiresAt);
      result = { verified: true, inputDigest: args[0] };
    } else if (mode === "login") {
      assert.equal(args.length, 1);
      assert.equal(process.env.GITHUB_ACTIONS, "true");
      assert.equal(process.env.GITHUB_REPOSITORY, "openclaw/clawsweeper");
      assert.equal(process.env.GITHUB_REF, `refs/heads/${PINS.branch}`);
      const { inputs } = verifyInputs(args[0]);
      const packet = { inputDigest: args[0], apiKey: process.env.OPENAI_API_KEY, model: process.env.CLAWSWEEPER_INTERNAL_MODEL };
      const result = command("/usr/bin/sudo", ["-n", "--", "/usr/bin/timeout", "--kill-after=5s", "60s", inputs.node.path, GUEST_SELF, "login-root"], {
        cwd: ROOT, env: cleanEnv(`${ROOT}/private`), input: json(packet), timeout: 70_000, allowFailure: true,
      });
      packet.apiKey = ""; packet.model = "";
      assert(result.status === 0 && !result.error && !result.signal, "native login failed closed");
      result.stdout = ""; result.stderr = "";
      return process.stdout.write('{"authenticated":true,"credentialsLogged":false}\n');
    } else if (mode === "login-root") result = await loginRoot(readInput(32 * 1024));
    else if (mode === "run-matrix") {
      assert.equal(args.length, 1);
      const { inputs } = verifyInputs(args[0]);
      admitDeadline(inputs.expiresAt);
      const child = command("/usr/bin/sudo", ["-n", "--", "/usr/bin/timeout", "--signal=TERM", "--kill-after=5s", "2995s",
        inputs.node.path, GUEST_SELF, "matrix", args[0]], {
        cwd: ROOT, env: cleanEnv(`${ROOT}/private`), timeout: LIMITS.matrixMs + LIMITS.cleanupMs + 5_000, maxBuffer: 512 * 1024, allowFailure: true,
      });
      if (child.stdout) {
        const report = JSON.parse(child.stdout);
        assert(report.leaseId === inputs.leaseId && report.inputDigest === args[0]);
        process.stdout.write(json(report));
      }
      assert(child.status === 0 && !child.error && !child.signal, "matrix failed closed");
      return;
    }
    else if (mode === "matrix") {
      assert.equal(args.length, 1);
      result = await matrix(args[0]);
    } else throw new Error("unknown matrix mode");
    const output = json(result);
    assert(Buffer.byteLength(output) <= (mode === "payload" ? 2 * 1024 * 1024 : 256 * 1024));
    process.stdout.write(output);
  } catch (error) {
    if (mode === "stage") process.stderr.write(stageFailureRecord(stageDiagnostic, error));
    if (mode === "controller-dispatch") process.stderr.write(controllerFailureRecord(error));
    process.stderr.write(`repair-config ${["stage", "payload", "controller-plan", "controller-dispatch", "controller-closure", "verify-stage", "login", "login-root", "run-matrix", "matrix", "record-codex", "fixture-gh", "fixture-git", "scanner"].includes(mode) ? mode : "admission"} failed closed\n`);
    process.exitCode = 1;
  } finally {
    if (mode === "stage") stageDiagnostic = null;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === SELF) await main();
