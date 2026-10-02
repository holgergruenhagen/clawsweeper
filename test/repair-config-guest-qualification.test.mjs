import assert from "node:assert/strict";
import childProcess from "node:child_process";
import crypto from "node:crypto";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import os from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { main } from "../scripts/e2e/repair-config-guest-qualification.mjs";
import {
  LIMITS, PINS, admitAcquisitionInput, admitDeadline, assertRetention, classifyExec, commandTimeout, controllerClosure, controllerFailureRecord, controllerPlan, digest,
  dispatchAfterReadback, executionEnvelope, fixtureGH, fixtureGit, fixtureUsage, gitLauncherSource, jobText, observeService,
  main as matrixMain, reserveStart, scannerInvocation, scannerStageOptions, sourceInventory, stageFailureRecord, validateEntries,
} from "../scripts/e2e/repair-config-matrix.mjs";

const BASE = "2f777941de926c6f11cb0c6363ecfe4bbee94371";
const TREE = "212409328808e514cbf65914fec600db05747d7a";
const ROOT = "/opt/repair-config-proof-20261001";
const RECEIPT = `${ROOT}/qualification.json`;
const NODE = "/usr/local/bin/fixture-node";
const CODEX = "/usr/local/bin/fixture-codex";
const HEAD = "a".repeat(40);
const PROOF_TREE = "b".repeat(40);
const LEASE = "cbx_012345abcdef";
const BOOT = "01234567-89ab-4def-8abc-0123456789ab\n";
const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const script = fileURLToPath(new URL("../scripts/e2e/repair-config-guest-qualification.mjs", import.meta.url));
const workflow = fileURLToPath(new URL("../.github/workflows/ci.yml", import.meta.url));

// Exercise the actual verifier, replacing only guest I/O. No sudo, Git, tool,
// namespace, credential, provider, or model command is executed by these tests.
async function verifyFixture(t, change = () => {}) {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "repair-config-verifier-"));
  const runnerHome = path.join(temporary, "runner");
  const workspace = path.join(runnerHome, "workspace");
  const guest = path.join(temporary, "guest");
  const nodeFile = path.join(temporary, "node");
  const codexFile = path.join(temporary, "codex");
  const actualReceipt = path.join(guest, "qualification.json");
  const source = Buffer.from('{"packageManager":"pnpm@12.4.1"}\n');
  const compiled = Buffer.from("export const fixture = true;\n");
  const nodeBytes = Buffer.from("fixture native Node bytes");
  const codexBytes = Buffer.from("fixture native Codex bytes");
  const proofUid = process.getuid() + 10_000;
  fs.mkdirSync(workspace, { recursive: true });
  fs.chmodSync(runnerHome, 0o700);
  fs.mkdirSync(path.join(guest, "build", "dist"), { recursive: true });
  fs.chmodSync(guest, 0o755);
  fs.mkdirSync(path.join(guest, "private"), { mode: 0o700 });
  fs.writeFileSync(path.join(workspace, "package.json"), source, { mode: 0o644 });
  fs.writeFileSync(path.join(guest, "build", "dist", "probe.js"), compiled, { mode: 0o644 });
  fs.writeFileSync(nodeFile, nodeBytes, { mode: 0o755 });
  fs.writeFileSync(codexFile, codexBytes, { mode: 0o755 });
  const manifest = [{ path: "package.json", mode: "100644", size: source.length, sha256: hash(source) }];
  const receipt = {
    format: 1, mode: "qualify", qualified: true,
    base: BASE, tree: TREE, label: "crabbox-proof-20261001-b-7c91e5a2",
    leaseId: LEASE, guestBootDigest: hash(BOOT),
    harnessDigest: hash(fs.readFileSync(script)),
    runnerUid: process.getuid(), proofUid, proofGid: proofUid,
    source: { head: HEAD, tree: PROOF_TREE, files: 1, digest: hash(JSON.stringify(manifest)) },
    node: { path: NODE, sha256: hash(nodeBytes), version: process.version },
    compiled: { files: 1, digest: hash(JSON.stringify([{ path: "probe.js", mode: 0o644, size: compiled.length, sha256: hash(compiled) }])) },
    codex: { path: CODEX, sha256: hash(codexBytes), version: "0.159.3" },
    probes: {
      uidBoundary: true, unexpectedSocketDescriptors: 0,
      containment: { markerMatch: true }, sandbox: { markerMatch: true },
    },
    supervisor: { terminated: true },
    steps: [{ setting: "kernel.unprivileged_userns_clone", readable: true, after: "1" }],
  };
  const expectedSource = structuredClone(receipt.source);
  const fixture = {
    receipt, missingReceipt: false, rawReceipt: undefined, expectedReceiptHash: undefined,
    missingAncestry: false, boot: BOOT, guest, workspace, nodeFile, codexFile,
  };
  change(fixture);
  const bytes = fixture.rawReceipt ?? `${JSON.stringify(receipt)}\n`;
  if (!fixture.missingReceipt) fs.writeFileSync(actualReceipt, bytes, { mode: 0o444 });
  const expectedHash = fixture.expectedReceiptHash ?? hash(bytes);
  const original = {
    cwd: process.cwd(), env: process.env, exitCode: process.exitCode,
    realpathSync: fs.realpathSync, lstatSync: fs.lstatSync, statSync: fs.statSync,
    readFileSync: fs.readFileSync, readdirSync: fs.readdirSync,
  };
  const mapPath = (file) => {
    if (file === NODE) return nodeFile;
    if (file === CODEX) return codexFile;
    if (file === ROOT || (typeof file === "string" && file.startsWith(`${ROOT}/`)))
      return path.join(guest, file.slice(ROOT.length));
    return file;
  };
  const metadata = (file, nativeStat) => {
    let stat;
    if (["/", "/usr", "/usr/local", "/usr/local/bin"].includes(file)) {
      stat = original.statSync(guest);
      stat.uid = 0;
      stat.mode = (stat.mode & ~0o777) | 0o755;
    } else {
      stat = nativeStat(mapPath(file));
      if (file === ROOT || file === RECEIPT || file === NODE || file === CODEX) stat.uid = 0;
      if (file === `${ROOT}/private`) stat.uid = proofUid;
    }
    return stat;
  };
  const commands = [];
  const gitOutput = (args) => {
    const key = JSON.stringify(args);
    const outputs = new Map([
      [JSON.stringify(["rev-parse", "HEAD"]), HEAD],
      [JSON.stringify(["rev-parse", "HEAD^{tree}"]), PROOF_TREE],
      [JSON.stringify(["rev-parse", `${BASE}^{tree}`]), TREE],
      [JSON.stringify(["merge-base", "--is-ancestor", BASE, "HEAD"]), ""],
      [JSON.stringify(["status", "--porcelain", "--untracked-files=no"]), ""],
      [JSON.stringify(["diff", "--name-only", BASE, "HEAD"]), ".github/workflows/ci.yml"],
      [JSON.stringify(["ls-files", "--stage", "-z"]), `100644 ${"c".repeat(40)} 0\tpackage.json\0`],
    ]);
    assert(outputs.has(key), `unexpected Git fixture command: ${key}`);
    return { text: outputs.get(key), status: fixture.missingAncestry && args[0] === "merge-base" ? 1 : 0 };
  };
  let output = "", exitCode;
  try {
    process.chdir(workspace);
    process.env = {
      HOME: runnerHome, PATH: "/usr/local/bin:/usr/bin:/bin",
      GITHUB_ACTIONS: "true", GITHUB_EVENT_NAME: "workflow_dispatch",
      GITHUB_REPOSITORY: "openclaw/clawsweeper",
      GITHUB_REF: "refs/heads/proof/repair-codex-config-20261001", GITHUB_SHA: HEAD,
    };
    process.exitCode = undefined;
    t.mock.method(fs, "realpathSync", (file) => file === process.execPath || file === NODE ? NODE : file === CODEX ? CODEX : original.realpathSync(file));
    t.mock.method(fs, "lstatSync", (file) => metadata(file, original.lstatSync));
    t.mock.method(fs, "statSync", (file) => metadata(file, original.statSync));
    t.mock.method(fs, "readFileSync", (file, options) => file === "/proc/sys/kernel/random/boot_id"
      ? Buffer.from(fixture.boot) : original.readFileSync(mapPath(file), options));
    t.mock.method(fs, "readdirSync", (file, options) => original.readdirSync(mapPath(file), options));
    t.mock.method(childProcess, "spawn", (command, args, options) => {
      commands.push({ command, args });
      assert.deepEqual(Object.keys(options.env).sort(), ["HOME", "LANG", "PATH", "TEMP", "TMP", "TMPDIR"]);
      let result;
      if (command === "/usr/bin/git") result = gitOutput(args);
      else if (command === "/usr/bin/id") {
        assert(["-u", "-g"].includes(args[0]) && args[1] === "repair-config-proof" && args.length === 2);
        result = { text: String(proofUid), status: 0 };
      } else if (command === "/usr/sbin/sysctl") {
        assert.deepEqual(args, ["-n", "kernel.unprivileged_userns_clone"]);
        result = { text: "1", status: 0 };
      } else assert.fail(`verifier attempted a non-read-only command: ${command}`);
      const child = Object.assign(new EventEmitter(), {
        stdout: new PassThrough(), stderr: new PassThrough(), stdin: null,
      });
      queueMicrotask(() => {
        child.stdout.end(result.text);
        child.stderr.end();
        child.emit("close", result.status, null);
      });
      return child;
    });
    syncBuiltinESMExports();
    t.mock.method(process.stdout, "write", (bytes, encoding, callback) => {
      output += bytes.toString();
      if (typeof encoding === "function") encoding();
      if (typeof callback === "function") callback();
      return true;
    });
    await main([
      "verify", "--lease-id", LEASE, "--source-head", HEAD, "--source-tree", PROOF_TREE,
      "--source-digest", expectedSource.digest, "--receipt-sha256", expectedHash,
    ]);
    exitCode = process.exitCode ?? 0;
  } finally {
    t.mock.restoreAll();
    syncBuiltinESMExports();
    process.chdir(original.cwd);
    process.env = original.env;
    process.exitCode = original.exitCode;
    fs.rmSync(temporary, { recursive: true, force: true });
  }
  assert(commands.every(({ command }) => ["/usr/bin/git", "/usr/bin/id", "/usr/sbin/sysctl"].includes(command)));
  return { report: JSON.parse(output), exitCode, commands };
}

test("verifier accepts the matching qualified guest receipt without rerunning qualification", async (t) => {
  const { report, exitCode, commands } = await verifyFixture(t);
  assert.equal(exitCode, 0, JSON.stringify(report));
  assert.equal(report.verified, true);
  assert.equal(report.failure, undefined);
  assert.equal(report.limits.modelCalls, 0);
  assert(report.steps.some((step) => step.qualificationReexecuted === false));
  assert(commands.some(({ command }) => command === "/usr/bin/id"));
  assert(commands.some(({ command }) => command === "/usr/sbin/sysctl"));
});

const cases = [
  ["missing receipt", (f) => { f.missingReceipt = true; }],
  ["malformed JSON", (f) => { f.rawReceipt = "{not-json\n"; }],
  ["null receipt", (f) => { f.rawReceipt = "null\n"; }],
  ["unqualified receipt", (f) => { f.receipt.qualified = false; }],
  ["wrong receipt mode", (f) => { f.receipt.mode = "verify"; }],
  ["wrong receipt digest", (f) => { f.expectedReceiptHash = "0".repeat(64); }],
  ["wrong lease", (f) => { f.receipt.leaseId = "cbx_fedcba987654"; }],
  ["wrong guest boot", (f) => { f.boot = "different-guest\n"; }],
  ["wrong source head", (f) => { f.receipt.source.head = "d".repeat(40); }],
  ["wrong source tree", (f) => { f.receipt.source.tree = "d".repeat(40); }],
  ["wrong source manifest", (f) => { f.receipt.source.digest = "d".repeat(64); }],
  ["wrong source count", (f) => { f.receipt.source.files++; }],
  ["wrong harness", (f) => { f.receipt.harnessDigest = "d".repeat(64); }],
  ["wrong Node path", (f) => { f.receipt.node.path = "/usr/local/bin/another-node"; }],
  ["wrong Node digest", (f) => { f.receipt.node.sha256 = "d".repeat(64); }],
  ["wrong Node version", (f) => { f.receipt.node.version = "v0.0.0"; }],
  ["changed Node executable", (f) => { fs.appendFileSync(f.nodeFile, "changed"); }],
  ["wrong compiled digest", (f) => { f.receipt.compiled.digest = "d".repeat(64); }],
  ["wrong compiled count", (f) => { f.receipt.compiled.files++; }],
  ["changed compiled bytes", (f) => { fs.appendFileSync(path.join(f.guest, "build/dist/probe.js"), "changed"); }],
  ["wrong Codex version", (f) => { f.receipt.codex.version = "0.159.2"; }],
  ["missing Codex path", (f) => { f.receipt.codex.path = `${ROOT}/missing-codex`; }],
  ["wrong Codex digest", (f) => { f.receipt.codex.sha256 = "d".repeat(64); }],
  ["changed Codex executable", (f) => { fs.appendFileSync(f.codexFile, "changed"); }],
  ["unqualified sandbox", (f) => { f.receipt.probes.sandbox.markerMatch = false; }],
  ["unconfirmed termination", (f) => { f.receipt.supervisor.terminated = false; }],
];
for (const [name, change] of cases) {
  test(`verifier rejects ${name}`, async (t) => {
    const { report, exitCode } = await verifyFixture(t, change);
    assert.equal(exitCode, 1);
    assert.equal(report.verified, false);
    assert.equal(report.failure.stage, "verify-existing-receipt");
  });
}

test("verifier fails closed on missing frozen ancestry without fetching", async (t) => {
  const { report, exitCode, commands } = await verifyFixture(t, (f) => { f.missingAncestry = true; });
  assert.equal(exitCode, 1);
  assert.equal(report.failure.stage, "admission");
  assert(!commands.some(({ args }) => args.includes("fetch")));
});

test("workflow uses repository-established immutable action pins and bounded history", () => {
  const body = fs.readFileSync(workflow, "utf8");
  assert.match(body, /uses: actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\b/);
  assert.match(body, /uses: actions\/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a\b/);
  assert.match(body, /fetch-depth: 11\b/);
  assert.match(body, /fetch-tags: false\b/);
  assert.doesNotMatch(body, /fetch-depth: 0\b|--unshallow|--deepen|uses: actions\/(?:checkout|upload-artifact)@v/);
});

function temporaryFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "repair-config-contract-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

test("matrix lifetime admission reserves 2700 seconds plus 300 seconds for cleanup", () => {
  const now = Date.parse("2026-10-01T12:00:00Z");
  assert.equal(admitDeadline(new Date(now + 3_000_000).toISOString(), now), now + 2_700_000);
  assert.throws(() => admitDeadline(new Date(now + 2_999_999).toISOString(), now));
  assert.throws(() => admitDeadline("invalid", now));
  assert.equal(LIMITS.nativeExecStarts, 12);
  assert.equal(LIMITS.nativeExecMs, 180_000);
});

test("expired work admission still permits bounded exact-unit termination and observation", () => {
  assert.throws(() => commandTimeout({ timeout: 1000 }, 2000, 1000, 3000), /matrix deadline/);
  assert.equal(commandTimeout({ timeout: 2000, cleanup: true }, 2000, 1000, 3000), 1000);
  assert.throws(() => commandTimeout({ timeout: 1000, cleanup: true }, 3000, 1000, 3000), /termination deadline/);
  const unit = `repair-proof-012345abcdef-${"a".repeat(36)}.service`;
  const calls = [];
  const control = (bin, args, options) => {
    calls.push({ bin, args, options });
    assert.equal(options.cleanup, true);
    assert.equal(commandTimeout(options, 2000, 1000, 30_000), 15_000);
    return { status: 0, signal: null, stdout: "LoadState=loaded\nActiveState=inactive\nMainPID=0\nControlPID=0\nControlGroup=\n" };
  };
  const missing = { lstatSync() { throw Object.assign(new Error("absent"), { code: "ENOENT" }); } };
  assert.equal(observeService(unit, control, missing).terminated, true);
  assert.deepEqual(calls[0].args.slice(0, 3), ["--no-ask-password", "show", unit]);
  const denied = { lstatSync() { throw Object.assign(new Error("denied"), { code: "EACCES" }); } };
  assert.throws(() => observeService(unit, control, denied));
  assert.equal(observeService(unit, () => ({ status: 1, error: new Error("timeout"), stdout: "" }), missing).terminated, false);
  const populated = { lstatSync: () => ({ isDirectory: () => true }), readFileSync: () => "populated 1\n" };
  assert.equal(observeService(unit, control, populated).terminated, false);
});

test("manifest admission requires exact count, safe unique sorted paths, modes and hashes", () => {
  const entries = Array.from({ length: PINS.files }, (_, i) => ({
    path: `file-${String(i).padStart(4, "0")}`, mode: "100644", bytes: i, sha256: "a".repeat(64),
  }));
  validateEntries(entries);
  for (const change of [
    (e) => e.pop(),
    (e) => { e[0].path = "../escape"; },
    (e) => { e[0].path = "/absolute"; },
    (e) => { e[0].path = ".git/config"; },
    (e) => { e[0].path = e[1].path; },
    (e) => { [e[0], e[1]] = [e[1], e[0]]; },
    (e) => { e[0].mode = "120000"; },
    (e) => { e[0].bytes = -1; },
    (e) => { e[0].sha256 = "invalid"; },
  ]) {
    const changed = structuredClone(entries); change(changed);
    assert.throws(() => validateEntries(changed));
  }
});

test("source inventory binds actual bytes and executable mode and rejects symlinks", (t) => {
  const root = temporaryFixture(t), file = path.join(root, "source");
  fs.writeFileSync(file, "fixture source", { mode: 0o644 });
  const entries = [{ path: "source", mode: "100644" }];
  assert.deepEqual(sourceInventory(root, entries), [{ ...entries[0], bytes: 14, sha256: digest("fixture source") }]);
  fs.chmodSync(file, 0o755);
  assert.throws(() => sourceInventory(root, entries));
  fs.symlinkSync(file, path.join(root, "link"));
  assert.throws(() => sourceInventory(root, [{ path: "link", mode: "100644" }]));
});

function fixturePlan() {
  return {
    mode: "plan", status: "planned", repo: "openclaw/fixture", cluster_id: "repair-config-fixture",
    needs_human: [], actions: [{ action: "fix_needed", status: "planned" }],
    fix_artifact: {
      repair_strategy: "new_fix_pr", changelog_required: false, allow_no_pr: false,
      likely_files: ["README.md"], affected_surfaces: ["docs"], source_prs: [], branch_update_blockers: [],
      validation_commands: ["git diff --check"], repair_contract: { must_touch: ["README.md"], match: "all" },
    },
    preserved: { nested: "model result" },
  };
}

test("execution envelope changes only mode, preserves planner result and rejects nonqualifying results", () => {
  const plan = fixturePlan(), before = structuredClone(plan), copy = executionEnvelope(plan);
  assert.deepEqual(plan, before);
  assert.deepEqual(copy, { ...before, mode: "execute" });
  copy.preserved.nested = "changed copy";
  assert.deepEqual(plan, before);
  for (const change of [
    (p) => { p.mode = "execute"; },
    (p) => { p.status = "failed"; },
    (p) => { p.needs_human.push("decision"); },
    (p) => { p.fix_artifact.likely_files = ["other"]; },
    (p) => { p.fix_artifact.validation_commands = []; },
    (p) => { p.fix_artifact.repair_contract.match = "any"; },
    (p) => { p.fix_artifact.allow_no_pr = true; },
  ]) {
    const invalid = fixturePlan(); change(invalid);
    assert.throws(() => executionEnvelope(invalid));
  }
  assert.match(jobText("plan"), /mode: plan/);
  assert.match(jobText("execute"), /mode: execute/);
  assert.throws(() => jobText("publish"));
});

const fixtureCell = {
  name: "baseline-ordinary", profile: "ordinary", baseSha: "a".repeat(40), origin: "/fixture/origin.git",
  work: "/fixture/work", runRoot: "/source/.clawsweeper-repair/runs",
};

test("GH fixture selects real profile inputs and denies unexpected routes and mutations", () => {
  const issue = ["api", "repos/openclaw/fixture/issues/1"];
  assert.equal(JSON.parse(fixtureGH(issue, fixtureCell).stdout).author_association, "CONTRIBUTOR");
  assert.equal(JSON.parse(fixtureGH(issue, { ...fixtureCell, profile: "maintainer" }).stdout).author_association, "MEMBER");
  assert.equal(JSON.parse(fixtureGH(["api", "repos/openclaw/fixture/collaborators/fixture-author/permission"], fixtureCell).stdout).permission, "read");
  assert.deepEqual(fixtureGH(["auth", "token"], fixtureCell), { status: 0, stdout: "", stderr: "" });
  assert.equal(fixtureGH(["api", "repos/openclaw/fixture/git/ref/heads/clawsweeper%2Frepair-config-fixture", "--jq", ".object.sha"], fixtureCell).status, 1);
  const capacity = ["pr", "list", "--repo", "openclaw/fixture", "--state", "open", "--limit", "500", "--json", "number,title,url,headRefName"];
  assert.deepEqual(JSON.parse(fixtureGH(capacity, fixtureCell).stdout), []);
  assert.throws(() => fixtureGH(capacity.map((arg) => arg === "500" ? "501" : arg), fixtureCell));
  assert.throws(() => fixtureGH(capacity.map((arg) => arg === "openclaw/fixture" ? "openclaw/other" : arg), fixtureCell));
  for (const args of [
    ["api", "repos/openclaw/fixture/issues/2"], ["auth", "status"],
    ["api", "-X", "POST", "repos/openclaw/fixture/issues"],
    ["api", "repos/openclaw/fixture/issues/1", "--method", "PATCH"],
    ["pr", "create"], ["api", "https://github.com/"],
  ]) assert.throws(() => fixtureGH(args, fixtureCell));
});

test("Git fixture rewrites only the declared clone URL and rejects every push and nonlocal transport", () => {
  const mapped = fixtureGit(["clone", "https://github.com/openclaw/fixture.git", "/fixture/target"], fixtureCell);
  assert.deepEqual(mapped.slice(-3), ["clone", fixtureCell.origin, "/fixture/target"]);
  assert(mapped.includes("protocol.allow=never") && mapped.includes("protocol.file.allow=always"));
  assert.deepEqual(fixtureGit(["status", "--porcelain"], fixtureCell).slice(-2), ["status", "--porcelain"]);
  for (const args of [
    ["push", "--dry-run", "origin"], ["push", fixtureCell.origin],
    ["fetch", "https://github.com/other/repo.git"], ["fetch", "git@github.com:other/repo.git"],
    ["fetch", "ext::anything"], ["clone", "file:///unexpected"],
  ]) assert.throws(() => fixtureGit(args, fixtureCell));
});

test("Git launcher runs standalone read-only validation without siblings, metadata or trace writes", (t) => {
  const root = temporaryFixture(t), home = path.join(root, "private/cells/baseline-ordinary");
  const target = path.join(home, "target"), tools = path.join(root, "tools"), shim = path.join(tools, "git");
  fs.mkdirSync(target, { recursive: true }); fs.mkdirSync(tools);
  const env = { HOME: root, PATH: "/usr/bin:/bin", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" };
  const invoke = (bin, args) => childProcess.spawnSync(bin, args, { cwd: target, env, encoding: "utf8", timeout: 5000, maxBuffer: 8192 });
  assert.equal(invoke("/usr/bin/git", ["init", "-b", "main"]).status, 0);
  fs.writeFileSync(path.join(target, "README.md"), "fixture\n");
  assert.equal(invoke("/usr/bin/git", ["add", "README.md"]).status, 0);
  fs.writeFileSync(shim, gitLauncherSource(process.execPath, root), { mode: 0o700 });
  assert.deepEqual(fs.readdirSync(tools), ["git"]);
  const result = invoke(shim, ["diff", "--check"]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(fs.existsSync(path.join(home, "trace.jsonl")), false);
  assert.equal(invoke("/usr/bin/git", ["init", "--bare", path.join(home, "origin.git")]).status, 0);
  const fetch = invoke(shim, ["ls-remote", "https://github.com/openclaw/fixture.git"]);
  assert.equal(fetch.status, 0, fetch.stderr);
  const trace = JSON.parse(fs.readFileSync(path.join(home, "trace.jsonl"), "utf8"));
  assert.deepEqual(trace.args, ["ls-remote", "https://github.com/openclaw/fixture.git"]);
  for (const args of [["push", "--dry-run"], ["ls-remote", "https://github.com/other/repo.git"]])
    assert.equal(invoke(shim, args).status, 1);
});

function nativeArgs(phase, profile = "ordinary") {
  const configs = ['approval_policy="never"', 'forced_login_method="api"', 'model_reasoning_effort="medium"'];
  if (profile === "maintainer") configs.push('service_tier="fast"');
  return ["exec", "--sandbox", phase === "edit" ? "workspace-write" : "read-only",
    ...configs.flatMap((value) => ["-c", value]),
    ...(phase === "edit" ? [] : ["--output-schema", phase === "plan"
      ? "/source/schema/repair/codex-result.schema.json" : `${fixtureCell.work}/codex-review.schema.json`]),
    "--output-last-message", `${phase === "plan" ? fixtureCell.runRoot : fixtureCell.work}/result.json`, "-"];
}

test("native phase admission checks sandbox and ordered ordinary/maintainer config", () => {
  for (const profile of ["ordinary", "maintainer"]) for (const phase of ["plan", "edit", "review"])
    assert.equal(classifyExec(nativeArgs(phase, profile), { ...fixtureCell, profile }), phase);
  for (const args of [
    ["review"], nativeArgs("plan").map((arg) => arg === "read-only" ? "danger-full-access" : arg),
    nativeArgs("edit").map((arg) => arg === 'forced_login_method="api"' ? 'forced_login_method="chatgpt"' : arg),
    nativeArgs("plan", "maintainer"),
    [...nativeArgs("edit"), "--dangerously-bypass-approvals-and-sandbox"],
  ]) assert.throws(() => classifyExec(args, fixtureCell));
});

test("native start admission permits each of twelve cell/phases once and rejects extras before launch", (t) => {
  const dir = temporaryFixture(t);
  reserveStart(dir, "baseline-ordinary", "plan");
  assert.throws(() => reserveStart(dir, "baseline-ordinary", "plan"));
  assert.throws(() => reserveStart(dir, "unknown", "edit"));
  for (const cell of ["baseline-ordinary", "baseline-maintainer", "candidate-ordinary", "candidate-maintainer"])
    for (const phase of ["plan", "edit", "review"])
      if (cell !== "baseline-ordinary" || phase !== "plan") reserveStart(dir, cell, phase);
  assert.equal(fs.readdirSync(dir).filter((name) => name.endsWith(".start.json")).length, 12);
  assert.throws(() => reserveStart(dir, "candidate-maintainer", "review"));
});

test("watchdog sees complete start receipts only, while duplicate reservations remain exclusive", (t) => {
  const dir = temporaryFixture(t), originalWrite = fs.writeFileSync, originalLink = fs.linkSync;
  let watchedDuringWrite = false, watchedDuringPublish = false;
  t.mock.method(fs, "writeFileSync", (file, bytes, options) => {
    assert.equal(fs.readdirSync(dir).filter((name) => name.endsWith(".start.json")).length, 0);
    watchedDuringWrite = true;
    return originalWrite(file, bytes, options);
  });
  t.mock.method(fs, "linkSync", (from, to) => {
    const receipt = JSON.parse(fs.readFileSync(from, "utf8"));
    assert.equal(receipt.phase, "plan");
    assert.equal(fs.existsSync(to), false);
    originalLink(from, to);
    assert.deepEqual(JSON.parse(fs.readFileSync(to, "utf8")), receipt);
    watchedDuringPublish = true;
  });
  try {
    reserveStart(dir, "baseline-ordinary", "plan");
    assert(watchedDuringWrite && watchedDuringPublish);
    assert.throws(() => reserveStart(dir, "baseline-ordinary", "plan"), { code: "EEXIST" });
  } finally { t.mock.restoreAll(); }
});

test("fixture measurement tolerates descendant cleanup races but rejects missing root or denied visibility", () => {
  const root = "/fixture";
  const io = {
    readdirSync(dir) {
      if (dir === root) return [{ name: "vanished" }, { name: "file" }];
      throw Object.assign(new Error("removed by cleanup"), { code: "ENOENT" });
    },
    lstatSync(file) { return { isDirectory: () => file.endsWith("/vanished"), size: 7 }; },
  };
  assert.deepEqual(fixtureUsage(root, io), { files: 1, bytes: 7 });
  assert.throws(() => fixtureUsage(root, { ...io, readdirSync() { throw Object.assign(new Error("root removed"), { code: "ENOENT" }); } }));
  assert.throws(() => fixtureUsage(root, {
    ...io, readdirSync(dir) {
      if (dir === root) return [{ name: "vanished" }];
      throw Object.assign(new Error("denied"), { code: "EACCES" });
    },
  }));
});

test("retention accounts for all explicit captures plus file/byte reserve", (t) => {
  const dir = temporaryFixture(t), files = [];
  for (let i = 0; i < 58; i++) {
    const file = path.join(dir, `${i}.log`); fs.writeFileSync(file, "x"); files.push(file);
  }
  assert.equal(LIMITS.retainedFiles, 58);
  assert.equal(LIMITS.retainedBytes, 64 * 1024 * 1024);
  assert.deepEqual(assertRetention(files), { files: 58, bytes: 58 });
  assert.deepEqual(assertRetention(files, 0, LIMITS.retainedBytes - 58), { files: 58, bytes: 58 });
  assert.throws(() => assertRetention(files, 1));
  const extra = path.join(dir, "58.log"); fs.writeFileSync(extra, "x");
  assert.throws(() => assertRetention([...files, extra]));
  assert.throws(() => assertRetention(files, 0, LIMITS.retainedBytes - 57));
  assert.throws(() => assertRetention([files[0], files[0]]));
  const link = path.join(dir, "symlink"); fs.symlinkSync(files[0], link);
  assert.throws(() => assertRetention([link]));
});

test("lease-independent admission validates only explicit input, never GitHub authority", () => {
  for (const runnerGroupId of [23, Number.MAX_SAFE_INTEGER]) {
    assert.deepEqual(admitAcquisitionInput({ runnerGroupId }), { runnerGroupId, inputValidated: true, authorityVerified: false });
  }
  for (const runnerGroupId of [undefined, null, "UNBOUND", "", "23", 0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, true]) {
    assert.throws(() => admitAcquisitionInput({ runnerGroupId }));
    assert.throws(() => controllerPlan({ runnerGroupId }));
  }
  assert.throws(() => admitAcquisitionInput());
  const source = fs.readFileSync(new URL("../scripts/e2e/repair-config-matrix.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(source, /registration-token|registrationAdapterSource|registration-adapter/);
});

test("removed legacy adapter mode cannot mint or create a fallback", (t) => {
  const result = childProcess.spawnSync(process.execPath, [
    fileURLToPath(new URL("../scripts/e2e/repair-config-matrix.mjs", import.meta.url)), "registration-adapter",
  ], { env: { PATH: path.dirname(process.execPath), HOME: temporaryFixture(t) }, encoding: "utf8", timeout: 3000, maxBuffer: 4096 });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr, "repair-config admission failed closed\n");
});

test("controller plan binds sole-label registration after qualification and exact-lease cleanup", () => {
  const plan = controllerPlan({
    crabbox: "/fixture/crabbox", runnerGroupId: 23, leaseId: LEASE,
    qualificationDigest: "a".repeat(64), inputDigest: "b".repeat(64),
    proofHead: HEAD, proofTree: PROOF_TREE, proofDigest: "c".repeat(64),
  });
  assert.equal(plan.crabboxSHA256, PINS.crabbox);
  assert.deepEqual(plan.leasePolicy, { ttlSeconds: 5400, idleSeconds: 5400, minimumMatrixRemainingSeconds: 3000, renewal: false });
  assert.equal(plan.beforeRegistration.length, 2);
  assert(plan.beforeRegistration.every(({ argv }) => argv.includes("--no-sync") && argv.includes("--script-stdin")));
  assert.deepEqual(plan.registration.argv.slice(-6), ["--labels", PINS.label, "--ephemeral", "--jit", "--runner-group-id", "23"]);
  assert.equal(plan.registration.allowanceMs, 300_000);
  assert.equal(plan.registration.nativePhaseBudgetMs, 16_000 + 180_000 + 30_000 + 16_000);
  assert.equal(plan.registration.overheadMs, 58_000);
  assert.equal(plan.registration.provedWallClockBound, false);
  assert.equal(plan.registration.nativePhaseBudgetMs + plan.registration.overheadMs, plan.registration.allowanceMs);
  assert(!Object.hasOwn(plan.registration, "timeout") && !Object.hasOwn(plan.registration, "killSignal"));
  assert(!Object.hasOwn(plan.registration, "prependPATH"));
  assert(plan.registration.requires.includes("authoritative repository JIT group id"));
  assert(plan.registration.requires.includes("pre-warmup input admission"));
  assert.deepEqual(plan.exactCleanup, ["/fixture/crabbox", "stop", LEASE]);
  assert(plan.dispatch.includes(`matrix_input_digest=${"b".repeat(64)}`));
  assert.equal(plan.preDispatch.proofHead, HEAD);
  assert(plan.dispatch.includes(`source_head=${HEAD}`));
  assert.equal(plan.registration.argv[plan.registration.argv.indexOf("--name") + 1], plan.preDispatch.runnerName);
});

function controllerFixture() {
  let elapsed = 0, wallOffset = 0;
  const wall = Date.parse("2026-10-01T15:00:00Z");
  const options = {
    crabbox: "/fixture/crabbox", runnerGroupId: 23, leaseId: LEASE,
    qualificationDigest: "a".repeat(64), inputDigest: "b".repeat(64),
    proofHead: HEAD, proofTree: PROOF_TREE, proofDigest: "c".repeat(64),
    lease: { leaseId: LEASE, provider: "aws", expiresAt: new Date(wall + 5_400_000).toISOString() },
  };
  const plan = controllerPlan(options);
  options.registration = {
    binarySHA256: PINS.crabbox, argv: plan.registration.argv, code: 0, signal: null,
    stdout: `${JSON.stringify({
      kind: "actions-jit-registration", stage: "launch-accepted", ownership: "owned",
      runnerId: 123, runnerName: plan.preDispatch.runnerName, httpStatus: 201, apiExit: 0,
      launchAccepted: true, guestCleanup: "not-started", runnerCleanup: "handoff-on-success",
    })}\n`,
    stderr: "", truncated: false, durationMs: 10_000,
  };
  const value = {
    ref: { ref: `refs/heads/${PINS.branch}`, object: { type: "commit", sha: HEAD } },
    list: { total_count: 1, runners: [{
      id: 123, name: plan.preDispatch.runnerName, os: "linux", status: "online", busy: false,
      labels: [{ name: PINS.label, type: "custom" }],
    }] },
  };
  const calls = [], sleeps = [];
  const clock = {
    now: () => elapsed, wallNow: () => wall + elapsed + wallOffset,
    sleep: (ms) => { sleeps.push(ms); elapsed += ms; },
  };
  const response = (phase) => nativeControllerResult(phase === "runner" ? value.list : phase === "head" ? value.ref : "");
  const run = (respond = response) => dispatchAfterReadback(options, (args, limits) => {
    const phase = JSON.stringify(args) === JSON.stringify(plan.preDispatch.runnerArgv) ? "runner"
      : JSON.stringify(args) === JSON.stringify(plan.preDispatch.headArgv) ? "head" : "dispatch";
    if (phase === "dispatch") assert.deepEqual(args, plan.dispatch);
    calls.push({ phase, args, ...limits, at: elapsed });
    return respond(phase, limits);
  }, clock);
  return { options, plan, value, calls, sleeps, clock, run, response, wall,
    advance: (ms) => { elapsed += ms; }, wallOffset: (ms) => { wallOffset = ms; } };
}

function nativeControllerResult(value, extra = {}) {
  return { status: 0, signal: null, stdout: typeof value === "string" ? value : JSON.stringify(value), stderr: "", ...extra };
}

function controllerRejection(run) {
  let record;
  assert.throws(run, (error) => {
    const text = controllerFailureRecord(error);
    assert(Buffer.byteLength(text) <= 1024);
    assert(!text.includes("FIXTURE_SECRET") && !text.includes("/private/path"));
    record = JSON.parse(text);
    return error.message === "controller failed closed";
  });
  return record;
}

test("dispatch consumes exact native registration, runner, fresh head and lease lifetime in order", () => {
  const f = controllerFixture(), result = f.run();
  assert.equal(result.runnerId, 123);
  assert.equal(result.registrationDigest, digest(JSON.stringify(f.options.registration)));
  assert.equal(result.reads, 1);
  assert.deepEqual(f.calls.map(({ args }) => args), [f.plan.preDispatch.runnerArgv, f.plan.preDispatch.headArgv, f.plan.dispatch]);
  assert(f.calls.every(({ timeout, maxBuffer, killSignal }) => timeout === 30_000 && maxBuffer === 64 * 1024 && killSignal === "SIGKILL"));
  for (const ephemeral of [true, undefined]) {
    const next = controllerFixture();
    if (ephemeral !== undefined) next.value.list.runners[0].ephemeral = ephemeral;
    assert.equal(next.run().dispatched, true);
  }
});

for (const type of ["custom", "read-only"]) {
  test(`sole exact ${type} JIT label preserves empty/offline propagation and online Linux admission`, () => {
    const f = controllerFixture();
    f.value.list.runners[0].labels[0].type = type;
    let reads = 0;
    const result = f.run((phase) => {
      if (phase !== "runner") return f.response(phase);
      reads++;
      if (reads === 1) return nativeControllerResult({ total_count: 0, runners: [] });
      f.value.list.runners[0].status = reads === 2 ? "offline" : "online";
      f.value.list.runners[0].os = reads === 2 ? "unknown" : "linux";
      return f.response(phase);
    });
    assert.equal(result.dispatched, true); assert.equal(result.runnerId, 123);
    assert.equal(result.reads, 3); assert.deepEqual(f.sleeps, [5000, 5000]);
    assert.equal(f.calls.filter(({ phase }) => phase === "dispatch").length, 1);
  });
}

test("registration allowance admits complete on-time captures without claiming a wall-clock supervisor", () => {
  for (const durationMs of [0, 242_000, 300_000]) {
    const f = controllerFixture();
    f.options.registration.durationMs = durationMs;
    assert.equal(f.run().dispatched, true);
  }
  for (const durationMs of [0.5, NaN, Number.MAX_SAFE_INTEGER]) {
    const f = controllerFixture();
    f.options.registration.durationMs = durationMs;
    assert.equal(controllerRejection(f.run).field, "allowance");
    assert.equal(f.calls.length, 0);
  }
});

for (const [name, change] of [
  ["wrong kind", (r) => { r.kind = "legacy"; }],
  ["not launch-accepted", (r) => { r.stage = "install"; }],
  ["unknown ownership", (r) => { r.ownership = "unknown"; }],
  ["missing runner id", (r) => { delete r.runnerId; }],
  ["string runner id", (r) => { r.runnerId = "123"; }],
  ["zero runner id", (r) => { r.runnerId = 0; }],
  ["unsafe runner id", (r) => { r.runnerId = Number.MAX_SAFE_INTEGER + 1; }],
  ["wrong name", (r) => { r.runnerName = "FIXTURE_SECRET"; }],
  ["non-201", (r) => { r.httpStatus = 200; }],
  ["string status", (r) => { r.httpStatus = "201"; }],
  ["failed API exit", (r) => { r.apiExit = 1; }],
  ["missing API exit", (r) => { delete r.apiExit; }],
  ["string launch acceptance", (r) => { r.launchAccepted = "true"; }],
  ["cleanup already run", (r) => { r.guestCleanup = "confirmed"; }],
  ["cleanup unknown", (r) => { r.runnerCleanup = "unknown"; }],
  ["unreviewed field", (r) => { r.secret = "FIXTURE_SECRET"; }],
]) test(`typed JIT receipt rejects ${name} before readback`, () => {
  const f = controllerFixture(), receipt = JSON.parse(f.options.registration.stdout);
  change(receipt);
  f.options.registration.stdout = `${JSON.stringify(receipt)}\n`;
  const record = controllerRejection(f.run);
  assert.equal(record.phase, "registration"); assert.equal(record.field, "receipt");
  assert.equal(f.calls.length, 0);
});

for (const [name, change] of [
  ["incomplete final line", (text) => text.slice(0, -1)],
  ["truncated JSON", (text) => text.slice(0, -3)],
  ["duplicate key", (text) => text.replace('"apiExit":0', '"apiExit":1,"apiExit":0')],
  ["duplicate receipt", (text) => text + text],
  ["trailing output", (text) => text + "FIXTURE_SECRET\n"],
  ["oversized receipt", (text) => text.trimEnd() + " ".repeat(1024) + "\n"],
  ["null", () => "null\n"],
  ["array", () => "[]\n"],
  ["legacy success", () => "actions runner registered ephemeral=true\n"],
]) test(`complete native JIT record rejects ${name}`, () => {
  const f = controllerFixture();
  f.options.registration.stdout = change(f.options.registration.stdout);
  assert.equal(controllerRejection(f.run).field, "receipt");
  assert.equal(f.calls.length, 0);
});

for (const [field, change] of [
  ["binary", (r) => { r.binarySHA256 = "d".repeat(64); }],
  ["argv", (r) => { r.argv = ["FIXTURE_SECRET"]; }],
  ["exit", (r) => { r.code = 1; }],
  ["exit", (r) => { r.error = { code: "EIO", message: "FIXTURE_SECRET" }; }],
  ["exit", (r) => { r.truncated = true; }],
  ["signal", (r) => { r.signal = "SIGTERM"; }],
  ["output", (r) => { r.stdout = "x".repeat(65537); }],
  ["output", (r) => { r.stderr = "x".repeat(65537); }],
  ["exit", (r) => { delete r.truncated; }],
  ["output", (r) => { delete r.stderr; }],
  ["allowance", (r) => { r.durationMs = 300_001; }],
  ["allowance", (r) => { delete r.durationMs; }],
  ["allowance", (r) => { r.durationMs = -1; }],
  ["allowance", (r) => { r.durationMs = "10000"; }],
  ["allowance", (r) => { r.durationMs = Infinity; }],
  ["receipt", (r) => { r.stdout = r.stdout.replace('"launchAccepted":true', '"launchAccepted":false'); }],
  ["receipt", (r) => { r.stdout = "FIXTURE_SECRET /private/path\n"; }],
]) test(`registration ${field} rejection has bounded diagnostics and makes no API call`, () => {
  const f = controllerFixture(); change(f.options.registration);
  const record = controllerRejection(f.run);
  assert.equal(record.phase, "registration"); assert.equal(record.field, field);
  assert.equal(f.calls.length, 0);
});

for (const [field, change] of [
  ["binary", (f) => { f.options.registration = undefined; }],
  ["cardinality", (f) => { f.value.list.total_count = 2; }],
  ["cardinality", (f) => { f.value.list.runners = []; }],
  ["id", (f) => { f.value.list.runners[0].id = 0; }],
  ["id", (f) => { f.value.list.runners[0].id = "123"; }],
  ["id", (f) => { f.value.list.runners[0].id = 124; }],
  ["id", (f) => { f.value.list.runners[0] = null; }],
  ["name", (f) => { f.value.list.runners[0].name = "FIXTURE_SECRET"; }],
  ["os", (f) => { f.value.list.runners[0].os = "windows"; }],
  ["status", (f) => { f.value.list.runners[0].status = "unknown"; }],
  ["busy", (f) => { f.value.list.runners[0].busy = true; }],
  ["busy", (f) => { delete f.value.list.runners[0].busy; }],
  ["ephemeral", (f) => { f.value.list.runners[0].ephemeral = false; }],
  ["ephemeral", (f) => { f.value.list.runners[0].ephemeral = null; }],
  ["ephemeral", (f) => { f.value.list.runners[0].ephemeral = "true"; }],
  ["labels", (f) => { f.value.list.runners[0].labels.push({ name: "self-hosted", type: "read-only" }); }],
  ["labels", (f) => { f.value.list.runners[0].labels[0].name = "FIXTURE_SECRET"; }],
  ["labels", (f) => { f.value.list.runners[0].labels[0].type = "system"; }],
  ["labels", (f) => { f.value.list.runners[0].labels[0].type = "Read-Only"; }],
  ["labels", (f) => { f.value.list.runners[0].labels[0].type = null; }],
  ["labels", (f) => { delete f.value.list.runners[0].labels[0].type; }],
  ["labels", (f) => { f.value.list.runners[0].labels[0] = { name: "self-hosted", type: "read-only" }; }],
  ["labels", (f) => { f.value.list.runners[0].labels[0].type = "read-only"; f.value.list.runners[0].labels.push({ name: "self-hosted", type: "read-only" }); }],
  ["labels", (f) => { delete f.value.list.runners[0].labels; }],
  ["ref", (f) => { f.value.ref.ref = "refs/heads/main"; }],
  ["type", (f) => { f.value.ref.object.type = "tag"; }],
  ["head", (f) => { f.value.ref.object.sha = "d".repeat(40); }],
  ["lease", (f) => { f.options.lease.leaseId = "cbx_ffffffffffff"; }],
  ["lease", (f) => { f.options.lease.provider = "other"; }],
  ["expiry", (f) => { delete f.options.lease.expiresAt; }],
]) test(`controller preserves the first failing ${field} field and never dispatches drift`, () => {
  const f = controllerFixture(); change(f);
  const record = controllerRejection(f.run);
  assert.equal(record.field, field);
  assert(!f.calls.some(({ phase }) => phase === "dispatch"));
  assert.equal(f.sleeps.length, 0);
});

test("empty propagation waits preserve the receipt ID until the exact runner is seen", () => {
  const f = controllerFixture();
  let reads = 0;
  const result = f.run((phase) => {
    if (phase !== "runner") return f.response(phase);
    reads++;
    if (reads === 1) return nativeControllerResult({ total_count: 0, runners: [] });
    f.value.list.runners[0].status = reads === 2 ? "offline" : "online";
    f.value.list.runners[0].os = reads === 2 ? "unknown" : "linux";
    return f.response(phase);
  });
  assert.equal(result.reads, 3); assert.equal(result.runnerId, 123);
  assert.deepEqual(f.sleeps, [5000, 5000]);
  assert.deepEqual(f.calls.map(({ at }) => at), [0, 5000, 10000, 10000, 10000]);
});

test("initial empty propagation cannot rebind the JIT receipt to a different runner", () => {
  const f = controllerFixture();
  const record = controllerRejection(() => f.run((phase) => {
    if (f.calls.length === 1) return nativeControllerResult({ total_count: 0, runners: [] });
    f.value.list.runners[0].id = 124;
    return f.response(phase);
  }));
  assert.equal(record.field, "id"); assert.equal(record.runnerId, 123);
  assert.equal(f.calls.length, 2); assert.deepEqual(f.sleeps, [5000]);
});

test("unknown OS is only a literal offline wait, never online admission", () => {
  for (const [status, os] of [["online", "unknown"], ["offline", ""], ["offline", undefined], ["offline", null], ["offline", "windows"]]) {
    const f = controllerFixture();
    Object.assign(f.value.list.runners[0], { status, os });
    assert.equal(controllerRejection(f.run).field, "os");
    assert.equal(f.calls.length, 1); assert.equal(f.sleeps.length, 0);
  }
  const f = controllerFixture();
  f.value.list.runners[0].os = "unknown";
  const record = controllerRejection(() => f.run((phase) => {
    f.value.list.runners[0].status = f.calls.length === 1 ? "offline" : "online";
    return f.response(phase);
  }));
  assert.equal(record.field, "os"); assert.equal(record.runnerId, 123);
  assert.equal(f.calls.length, 2); assert.deepEqual(f.sleeps, [5000]);
});

for (const [field, change] of [
  ["disappearance", (f) => { f.value.list = { total_count: 0, runners: [] }; }],
  ["id", (f) => { f.value.list.runners[0].id = 124; }],
  ["cardinality", (f) => { f.value.list.total_count = 2; f.value.list.runners.push({ ...f.value.list.runners[0] }); }],
  ["name", (f) => { f.value.list.runners[0].name = "FIXTURE_SECRET"; }],
  ["busy", (f) => { f.value.list.runners[0].busy = true; }],
]) test(`bound offline runner ${field} drift is fatal, not another wait`, () => {
  const f = controllerFixture(); f.value.list.runners[0].status = "offline";
  const record = controllerRejection(() => f.run((phase) => {
    if (f.calls.length === 2) change(f);
    return f.response(phase);
  }));
  assert.equal(record.field, field); assert.equal(record.runnerId, 123);
  assert.equal(f.calls.length, 2); assert.deepEqual(f.sleeps, [5000]);
});

for (const response of ["FIXTURE_SECRET", null, [], {}, { total_count: -1, runners: [] },
  { total_count: 0, runners: null }, { total_count: "0", runners: [] }]) {
  test("malformed runner response is fatal with no raw response disclosure", () => {
    const f = controllerFixture();
    const record = controllerRejection(() => f.run(() => nativeControllerResult(response)));
    assert.equal(record.field, "response"); assert.equal(record.phase, "runner");
    assert.equal(f.calls.length, 1); assert.equal(f.sleeps.length, 0);
  });
}

test("controller records bounded native transport facts without retry or sensitive streams", () => {
  for (const extra of [
    { status: 7 }, { signal: "SIGTERM" }, { error: { code: "EACCES", message: "FIXTURE_SECRET" } },
    { error: { code: "FIXTURE_SECRET", message: "/private/path" } },
    { error: { code: "ETIMEDOUT" }, status: null, signal: "SIGKILL" }, { truncated: true },
    { stdout: "FIXTURE_SECRET".repeat(6000) },
  ]) {
    const f = controllerFixture();
    const response = nativeControllerResult("FIXTURE_SECRET /private/path", { stderr: "FIXTURE_SECRET", ...extra });
    const record = controllerRejection(() => f.run(() => { f.advance(30000); return response; }));
    assert.equal(record.phase, "runner");
    assert.equal(record.elapsedMs, 30000);
    assert.equal(record.native.stdout.sha256, digest(response.stdout));
    assert.equal(record.native.stderr.bytes, Buffer.byteLength(response.stderr));
    assert.equal(record.native.timedOut, extra.error?.code === "ETIMEDOUT");
    assert.equal(f.calls.length, 1); assert.equal(f.sleeps.length, 0);
  }
  const f = controllerFixture();
  const record = controllerRejection(() => f.run(() => { throw Object.assign(new Error("FIXTURE_SECRET"), { code: "ENOENT" }); }));
  assert.equal(record.field, "transport"); assert.equal(record.native.errorCode, "ENOENT");
  assert.equal(record.native.stdout, null);
});

test("controller retains normalized error/timeout facts without deriving timeout from signals", () => {
  for (const [extra, errorCode, timedOut] of [
    [{ errorCode: "ENOBUFS" }, "ENOBUFS", false],
    [{ errorCode: "ETIMEDOUT" }, "ETIMEDOUT", true],
    [{ timedOut: true }, null, true],
    [{ signal: "SIGKILL" }, null, false],
    [{ errorCode: "FIXTURE_SECRET" }, "unclassified", false],
    [{ errorCode: "" }, "unclassified", false],
    [{ error: new Error("FIXTURE_SECRET"), errorCode: "EACCES" }, "EACCES", false],
  ]) {
    const f = controllerFixture();
    const api = controllerRejection(() => f.run(() => nativeControllerResult("", extra)));
    assert.equal(api.field, "transport");
    assert.equal(api.native.errorCode, errorCode); assert.equal(api.native.timedOut, timedOut);
    const registration = controllerFixture(); Object.assign(registration.options.registration, extra);
    const admission = controllerRejection(registration.run);
    assert.equal(admission.phase, "registration");
    assert.equal(admission.native.errorCode, errorCode); assert.equal(admission.native.timedOut, timedOut);
    assert.equal(registration.calls.length, 0);
    const closure = controllerClosure(LEASE, {
      code: 0, signal: null, truncated: false, stdout: `released lease=${LEASE} server=0\n`, stderr: "", ...extra,
    });
    assert.equal(closure.released, null);
    assert.equal(closure.native.errorCode, errorCode); assert.equal(closure.native.timedOut, timedOut);
    assert(!JSON.stringify(closure).includes("FIXTURE_SECRET"));
  }
});

test("readiness has one monotonic deadline with a twelve-read cap and five-second spacing", () => {
  const f = controllerFixture();
  const record = controllerRejection(() => f.run(() => nativeControllerResult({ total_count: 0, runners: [] })));
  assert.equal(record.field, "read-limit"); assert.equal(record.reads, 12);
  assert.equal(record.elapsedMs, 55000);
  assert.equal(f.calls.length, 12); assert.equal(f.sleeps.length, 11);
  assert(f.sleeps.every((ms) => ms === 5000));
  assert.deepEqual(f.calls.map(({ timeout }) => timeout), Array.from({ length: 12 }, (_, index) => Math.min(30000, 60000 - index * 5000)));
});

test("API latency reduces sleep and subprocess budgets without admitting a late read", () => {
  const f = controllerFixture();
  const record = controllerRejection(() => f.run(() => {
    f.advance(f.calls.length === 1 ? 29000 : 23000);
    return nativeControllerResult({ total_count: 0, runners: [] });
  }));
  assert.equal(record.field, "deadline"); assert.equal(record.elapsedMs, 60000);
  assert.deepEqual(f.calls.map(({ timeout }) => timeout), [30000, 26000]);
  assert.deepEqual(f.sleeps, [5000, 3000]);
  assert.equal(f.calls.length, 2);
});

test("a response at the monotonic deadline cannot advance to head read or dispatch", () => {
  for (const latePhase of ["runner", "head"]) {
    const f = controllerFixture();
    const record = controllerRejection(() => f.run((phase) => {
      if (phase === "runner") f.advance(latePhase === "runner" ? 60000 : 59999);
      if (phase === "head") f.advance(1);
      return f.response(phase);
    }));
    assert.equal(record.field, "deadline"); assert.equal(record.phase, latePhase);
    assert(!f.calls.some(({ phase }) => phase === "dispatch"));
    if (latePhase === "head") assert.equal(f.calls.at(-1).timeout, 1);
  }
});

test("native timeout at the remaining API budget is fatal and does not restart readiness", () => {
  const f = controllerFixture();
  const record = controllerRejection(() => f.run((phase, { timeout }) => {
    if (f.calls.length < 6) {
      f.advance(6000);
      return nativeControllerResult({ total_count: 0, runners: [] });
    }
    assert.equal(timeout, 5000); f.advance(timeout);
    return nativeControllerResult("", { status: null, signal: "SIGKILL", error: { code: "ETIMEDOUT" } });
  }));
  assert.equal(record.reads, 6); assert.equal(record.elapsedMs, 60000);
  assert.equal(record.native.timedOut, true); assert.equal(record.field, "transport");
});

test("fresh head precedes lifetime admission; wall-clock rollback cannot extend native expiry", () => {
  const exact = controllerFixture();
  exact.options.lease.expiresAt = new Date(exact.wall + 3000000).toISOString();
  assert.equal(exact.run().dispatched, true);
  for (const rollback of [false, true]) {
    const f = controllerFixture();
    f.options.lease.expiresAt = new Date(f.wall + 3000000).toISOString();
    const record = controllerRejection(() => f.run((phase) => {
      if (phase === "head") { f.advance(1); if (rollback) f.wallOffset(-60000); }
      return f.response(phase);
    }));
    assert.equal(record.phase, "lifetime"); assert.equal(record.field, "expiry");
    assert.deepEqual(f.calls.map(({ phase }) => phase), ["runner", "head"]);
  }
});

test("a failed or timed-out dispatch is attempted once, never retried", () => {
  for (const extra of [{ status: 1 }, { error: { code: "ETIMEDOUT" }, status: null, signal: "SIGKILL" }]) {
    const f = controllerFixture();
    const record = controllerRejection(() => f.run((phase) => phase === "dispatch"
      ? nativeControllerResult("FIXTURE_SECRET", extra) : f.response(phase)));
    assert.equal(record.phase, "dispatch"); assert.equal(record.dispatchStarted, true);
    assert.equal(record.runnerId, 123);
    assert.equal(f.calls.filter(({ phase }) => phase === "dispatch").length, 1);
  }
});

test("closure accepts the exact native release marker from either complete stream, runner separately", () => {
  for (const stream of ["stdout", "stderr"]) {
    const result = { code: 0, signal: null, truncated: false, stdout: "", stderr: "",
      [stream]: `released lease=${LEASE} server=i-0123456789abcdef0\n` };
    const record = controllerClosure(LEASE, result);
    assert.equal(record.released, true); assert.equal(record.leaseDisposition, "released");
    assert.equal(record.runnerDisposition, "unconfirmed");
    assert(!JSON.stringify(record).includes("i-0123456789abcdef0"));
  }
});

test("unterminated release-looking lines in either stream defeat otherwise valid closure evidence", () => {
  const complete = `released lease=${LEASE} server=0\n`;
  for (const stream of ["stdout", "stderr"]) {
    const other = stream === "stdout" ? "stderr" : "stdout";
    for (const trailing of [
      "released lease=cbx_ffffffffffff server=0",
      "released lease=cbx_", "released lease=", "released lease", "released",
      complete.trimEnd(),
    ]) {
      for (const sameStream of [false, true]) {
        const result = { code: 0, signal: null, truncated: false, stdout: "", stderr: "",
          [stream]: complete + (sameStream ? trailing : ""), [other]: sameStream ? "" : trailing };
        const record = controllerClosure(LEASE, result);
        assert.equal(record.released, null);
        assert.equal(record.leaseDisposition, "unconfirmed");
        assert.equal(record.runnerDisposition, "unconfirmed");
      }
    }
  }
});

test("closure keeps missing, mismatched, failed, incomplete and truncated native evidence unconfirmed", () => {
  for (const change of [
    (r) => { r.stdout = ""; }, (r) => { r.stdout = r.stdout.replace(LEASE, "cbx_ffffffffffff"); },
    (r) => { r.stdout = r.stdout.trimEnd(); }, (r) => { r.stdout = r.stdout.slice(0, 20); },
    (r) => { r.stderr = "x".repeat(65537); }, (r) => { r.stdout += `released lease=cbx_ffffffffffff server=0\n`; },
    (r) => { r.code = 1; }, (r) => { r.signal = "SIGTERM"; },
    (r) => { r.error = { code: "EIO", message: "FIXTURE_SECRET" }; },
    (r) => { r.errorCode = "ENOBUFS"; }, (r) => { r.failure = "deadline"; },
    (r) => { r.timedOut = true; }, (r) => { r.truncated = true; }, (r) => { delete r.truncated; },
    (r) => { r.stdout = Buffer.from(r.stdout); }, (r) => { delete r.stderr; },
  ]) {
    const result = { code: 0, signal: null, truncated: false, stdout: `released lease=${LEASE} server=0\n`, stderr: "" };
    change(result);
    const record = controllerClosure(LEASE, result);
    assert.equal(record.released, null); assert.equal(record.leaseDisposition, "unconfirmed");
    assert.equal(record.runnerDisposition, "unconfirmed");
    assert(!JSON.stringify(record).includes("FIXTURE_SECRET"));
  }
  assert.equal(controllerClosure(LEASE, undefined).released, null);
});

async function controllerCliFixture(t, { mode = "controller-dispatch", edit = () => {}, input, response } = {}) {
  const f = controllerFixture(), tool = Buffer.from("fixture ghx");
  f.options.ghx = "/fixture/ghx"; f.options.ghxSHA256 = digest(tool);
  f.options.lease.expiresAt = new Date(Date.now() + 5_400_000).toISOString();
  edit(f.options);
  const original = { read: fs.readFileSync, exitCode: process.exitCode };
  const calls = [];
  let stdout = "", stderr = "", exitCode;
  try {
    t.mock.method(fs, "readFileSync", (file, ...args) => {
      if (file === 0) return Buffer.from(input ?? JSON.stringify(f.options));
      if (file === "/fixture/ghx") return tool;
      return original.read(file, ...args);
    });
    t.mock.method(fs, "realpathSync", (file) => file);
    t.mock.method(childProcess, "spawnSync", (command, args, limits) => {
      assert.equal(command, "/fixture/ghx"); assert.equal(args[0], "--no-cache");
      assert(limits.timeout > 0 && limits.timeout <= 30000);
      assert.equal(limits.killSignal, "SIGKILL"); assert.equal(limits.maxBuffer, 64 * 1024);
      const phase = args[1] === "workflow" ? "dispatch" : args[2].includes("/actions/runners?") ? "runner" : "head";
      calls.push(phase);
      return response ? response(phase) : f.response(phase);
    });
    syncBuiltinESMExports();
    t.mock.method(process.stdout, "write", (bytes) => { stdout += bytes; return true; });
    t.mock.method(process.stderr, "write", (bytes) => { stderr += bytes; return true; });
    await matrixMain([mode]);
    exitCode = process.exitCode ?? 0;
  } finally {
    t.mock.restoreAll(); syncBuiltinESMExports(); process.exitCode = original.exitCode;
  }
  assert(!`${stdout}${stderr}`.includes("FIXTURE_SECRET") && !`${stdout}${stderr}`.includes("/private/path"));
  return { stdout, stderr, exitCode, calls };
}

test("actual controller CLI uses the single instrumented path and bounded native adapter", async (t) => {
  const result = await controllerCliFixture(t);
  assert.equal(result.exitCode, 0); assert.equal(result.stderr, "");
  assert.equal(JSON.parse(result.stdout).dispatched, true);
  assert.deepEqual(result.calls, ["runner", "head", "dispatch"]);
});

for (const [phase, field, fixture] of [
  ["input", "input", { input: "FIXTURE_SECRET /private/path" }],
  ["tool", "path", { edit: (o) => { o.ghx = "FIXTURE_SECRET"; } }],
  ["tool", "identity", { edit: (o) => { o.ghxSHA256 = "f".repeat(64); } }],
  ["registration", "receipt", { edit: (o) => { o.registration.stdout = "FIXTURE_SECRET"; } }],
  ["runner", "response", { response: () => nativeControllerResult("FIXTURE_SECRET") }],
  ["runner", "transport", { response: () => { throw Object.assign(new Error("FIXTURE_SECRET /private/path"), { code: "EACCES" }); } }],
]) test(`actual CLI preserves ${phase}/${field} admission diagnostics before generic catch`, async (t) => {
  const result = await controllerCliFixture(t, fixture);
  assert.equal(result.exitCode, 1); assert.equal(result.stdout, "");
  const lines = result.stderr.trimEnd().split("\n");
  assert.equal(lines.length, 2); assert.equal(lines[1], "repair-config controller-dispatch failed closed");
  assert(Buffer.byteLength(lines[0]) <= 1024);
  const record = JSON.parse(lines[0]);
  assert.equal(record.phase, phase); assert.equal(record.field, field);
  assert(!result.calls.includes("dispatch"));
});

test("actual closure CLI exits nonzero on unconfirmed evidence and keeps runner disposition separate", async (t) => {
  for (const truncated of [false, true]) {
    const input = JSON.stringify({ leaseId: LEASE, result: {
      code: 0, signal: null, truncated, stdout: "", stderr: `released lease=${LEASE} server=0\n`,
    } });
    const result = await controllerCliFixture(t, { mode: "controller-closure", input });
    assert.equal(result.exitCode, truncated ? 1 : 0);
    assert.equal(result.stderr, ""); assert.equal(result.calls.length, 0);
    const record = JSON.parse(result.stdout);
    assert.equal(record.released, truncated ? null : true); assert.equal(record.runnerDisposition, "unconfirmed");
  }
});

test("scanner version and actual scans use the same isolated network namespace without altered arguments", () => {
  for (const args of [
    ["--version"],
    ["filesystem", "/fixture/staging", "--results=verified,unknown", "--fail", "--fail-on-scan-errors", "--no-update", "--json", "--no-color"],
  ]) assert.deepEqual(scannerInvocation("/fixture/trufflehog", args),
    ["/usr/bin/unshare", ["--user", "--map-root-user", "--net", "--", "/fixture/trufflehog", ...args]]);
  assert.throws(() => scannerInvocation("/fixture/trufflehog", ["--no-verification"]));
});

// Exercise the real stage entrypoint with guest I/O replaced. Synthetic source
// digests admit only this fixture; no root filesystem or native command is used.
async function stageFixture(t, options = {}) {
  const stopAt = options.stopAt ?? "archive", proofUid = 999, proofGid = 982;
  const scanner = "/usr/local/bin/fixture-scanner", source = Buffer.from("fixture source");
  const candidate = Array.from({ length: PINS.files }, (_, i) => ({
    path: `file-${String(i).padStart(4, "0")}`, mode: "100644", bytes: source.length, sha256: hash(source),
  }));
  const patch = "fixture patch", candidateJSON = JSON.stringify(candidate);
  const receipt = {
    qualified: true, leaseId: LEASE, proofUid, proofGid, runnerUid: 1000,
    probes: { containment: { markerMatch: true }, sandbox: { markerMatch: true } },
    supervisor: { terminated: true }, source: { head: HEAD },
    node: { path: NODE }, codex: { path: CODEX }, guestBootDigest: hash(BOOT),
  };
  const receiptBytes = JSON.stringify(receipt);
  const payload = {
    base: stopAt === "payload" ? "wrong" : PINS.base, tree: PINS.tree, patch, candidate,
    qualificationDigest: hash(receiptBytes), leaseId: LEASE,
    scanner: { path: scanner, sha256: hash("fixture scanner") },
  };
  const original = { read: fs.readFileSync, hash: crypto.createHash, exitCode: process.exitCode };
  const calls = [], writes = [];
  let stdout = "", stderr = "", exitCode;
  const nativeFailure = options.result ?? {
    status: 7, signal: null, stdout: "FIXTURE_SECRET /private/path\n", stderr: "FIXTURE_SECRET error\n",
  };
  try {
    process.exitCode = undefined;
    t.mock.method(process, "getuid", () => stopAt === "root" ? 1000 : 0);
    t.mock.method(crypto, "createHash", (...args) => {
      const native = original.hash(...args), chunks = [];
      return {
        update(bytes) { chunks.push(Buffer.from(bytes)); native.update(bytes); return this; },
        digest(encoding) {
          const text = Buffer.concat(chunks).toString();
          const pin = text === patch ? PINS.patch : text === candidateJSON ? PINS.candidate : null;
          return pin && encoding === "hex" ? pin : native.digest(encoding);
        },
      };
    });
    t.mock.method(fs, "readFileSync", (file, encoding) => {
      if (file === 0) return Buffer.from(stopAt === "input" ? "FIXTURE_SECRET invalid JSON" : JSON.stringify(payload));
      if (file === RECEIPT) {
        if (stopAt === "receipt") throw Object.assign(new Error("FIXTURE_SECRET /private/path"), { code: "EACCES" });
        return receiptBytes;
      }
      if (file === scanner) return Buffer.from("fixture scanner");
      if (file === "/proc/sys/kernel/random/boot_id") return Buffer.from(stopAt === "boot" ? "different" : BOOT);
      if (String(file).startsWith(`${ROOT}/sources/`)) return source;
      return original.read(file, encoding);
    });
    t.mock.method(fs, "realpathSync", (file) => file);
    t.mock.method(fs, "existsSync", (file) => stopAt === "fresh-paths" && file === `${ROOT}/matrix-inputs.json`);
    t.mock.method(fs, "lstatSync", (file) => {
      const privateDir = [ `${ROOT}/private`, `${ROOT}/private/tmp` ].includes(file);
      const regular = file === RECEIPT || file === scanner || /\/file-\d+$/.test(file);
      return {
        isFile: () => regular, isDirectory: () => !regular, isSymbolicLink: () => false, nlink: 1,
        uid: privateDir ? proofUid : file === scanner && stopAt === "scanner-identity" ? 1000 : 0,
        gid: privateDir ? proofGid : 0,
        mode: file === RECEIPT ? 0o444 : privateDir ? stopAt === "scanner-environment" ? 0o755 : 0o700
          : file === scanner || !regular ? 0o755 : 0o644,
      };
    });
    t.mock.method(fs, "statSync", () => ({ gid: 1000 }));
    t.mock.method(fs, "readdirSync", () => []);
    for (const name of ["mkdirSync", "chownSync", "chmodSync"]) t.mock.method(fs, name, (file) => {
      writes.push({ name, file });
      if (stopAt === "prepare" && name === "mkdirSync") throw Object.assign(new Error("FIXTURE_SECRET"), { code: "EACCES" });
    });
    t.mock.method(fs, "symlinkSync", (target, file) => { writes.push({ name: "symlinkSync", file }); });
    for (const name of ["copyFileSync", "writeFileSync"])
      t.mock.method(fs, name, () => assert.fail("fixture must stop before final sealed writes"));
    t.mock.method(childProcess, "spawnSync", (command, args, commandOptions) => {
      let phase, text = "";
      const revision = commandOptions.cwd?.endsWith("/candidate") ? "candidate" : "baseline";
      if (command === "/usr/bin/git" && args.includes("rev-parse")) { phase = "head"; text = HEAD; }
      else if (command === "/usr/bin/unshare") {
        phase = "scanner-version"; text = `trufflehog ${PINS.scanner}`;
        assert.deepEqual(args, ["--user", "--map-root-user", "--net", "--", scanner, "--version"]);
        assert.equal(commandOptions.uid, proofUid); assert.equal(commandOptions.gid, proofGid);
        assert.equal(commandOptions.env.HOME, `${ROOT}/private`);
        for (const key of ["TMPDIR", "TMP", "TEMP"]) assert.equal(commandOptions.env[key], `${ROOT}/private/tmp`);
        assert(!writes.some(({ file }) => file.startsWith(`${ROOT}/prepare`) || file.startsWith(`${ROOT}/private`)));
      } else if (command === "/usr/bin/git" && args.includes("archive")) phase = "archive";
      else if (command === "/usr/bin/tar") phase = `${args.at(-1).endsWith("/candidate") ? "candidate" : "baseline"}-extract`;
      else if (command === "/usr/bin/git" && args[0] === "apply") phase = args.includes("--check") ? "candidate-apply-check" : "candidate-apply";
      else if (command === "corepack") {
        phase = `${revision}-${args.includes("--version") ? "corepack" : args.includes("install") ? "install" : "build"}`;
        if (args.includes("--version")) text = PINS.pnpm;
      } else assert.fail("unexpected fixture native command");
      calls.push({ phase, env: commandOptions.env });
      assert.deepEqual(Object.keys(commandOptions.env).sort(),
        ["GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "GIT_TERMINAL_PROMPT", "HOME", "LANG", "PATH", "TEMP", "TMP", "TMPDIR"]);
      if (phase === stopAt) {
        if (options.thrown) throw options.thrown;
        return nativeFailure;
      }
      return { status: 0, signal: null, stdout: commandOptions.encoding ? text : Buffer.from(text), stderr: "" };
    });
    syncBuiltinESMExports();
    t.mock.method(process.stdout, "write", (bytes) => { stdout += bytes; return true; });
    t.mock.method(process.stderr, "write", (bytes) => { stderr += bytes; return true; });
    await matrixMain([options.mode ?? "stage"]);
    exitCode = process.exitCode ?? 0;
  } finally {
    t.mock.restoreAll(); syncBuiltinESMExports(); process.exitCode = original.exitCode;
  }
  assert.equal(exitCode, 1); assert.equal(stdout, "");
  assert(!stderr.includes("FIXTURE_SECRET") && !stderr.includes("/private/path"));
  const lines = stderr.trimEnd().split("\n");
  if (options.mode) {
    assert.deepEqual(lines, [`repair-config ${options.mode} failed closed`]);
    return;
  }
  assert.equal(lines.length, 2); assert.equal(lines[1], "repair-config stage failed closed");
  assert(Buffer.byteLength(lines[0]) <= 1024);
  return { report: JSON.parse(lines[0]), calls };
}

for (const phase of [
  "input", "root", "payload", "receipt", "fresh-paths", "head", "scanner-identity", "scanner-environment",
  "scanner-version", "boot", "prepare", "archive", "baseline-extract", "baseline-corepack",
  "baseline-install", "baseline-build", "candidate-extract", "candidate-apply-check", "candidate-apply",
  "candidate-corepack", "candidate-install", "candidate-build",
]) test(`stage failure identifies ${phase} without native output or sensitive error text`, async (t) => {
  const { report } = await stageFixture(t, { stopAt: phase });
  assert.equal(report.phase, phase);
  assert.equal(report.kind, "repair-config-stage-failure");
  if (report.native) {
    assert.equal(report.native.exit, 7);
    assert.equal(report.native.stdout.sha256, hash("FIXTURE_SECRET /private/path\n"));
    assert.equal(report.native.stderr.bytes, Buffer.byteLength("FIXTURE_SECRET error\n"));
  }
});

for (const [name, result, expected] of [
  ["spawn", { error: Object.assign(new Error("FIXTURE_SECRET"), { code: "ENOENT" }), status: null, signal: null }, { errorCode: "ENOENT", exit: null, signal: null, timedOut: false }],
  ["timeout", { error: Object.assign(new Error("FIXTURE_SECRET"), { code: "ETIMEDOUT" }), status: null, signal: "SIGKILL" }, { errorCode: "ETIMEDOUT", exit: null, signal: "SIGKILL", timedOut: true }],
  ["signal", { status: null, signal: "SIGTERM" }, { errorCode: null, exit: null, signal: "SIGTERM", timedOut: false }],
]) test(`stage records allowlisted ${name} facts without inferring a timeout from a signal`, async (t) => {
  const { report } = await stageFixture(t, { stopAt: "head", result });
  for (const [key, value] of Object.entries(expected)) assert.equal(report.native[key], value);
});

test("thrown native spawn error retains only its allowlisted code and phase", async (t) => {
  const { report } = await stageFixture(t, {
    stopAt: "head", thrown: Object.assign(new Error("FIXTURE_SECRET /private/path"), { code: "EACCES" }),
  });
  assert.equal(report.phase, "head"); assert.equal(report.errorCode, "EACCES");
  assert.equal(report.native, undefined);
});

for (const phase of ["scanner-version", "baseline-corepack", "candidate-corepack"])
  test(`stage distinguishes ${phase} mismatch from native command failure`, async (t) => {
    const { report } = await stageFixture(t, {
      stopAt: phase, result: { status: 0, signal: null, stdout: "FIXTURE_SECRET unexpected version", stderr: "" },
    });
    assert.equal(report.phase, phase); assert.equal(report.native.exit, 0);
    assert.equal(report.facts.versionMatch, false);
    assert.equal(report.errorCode, "ERR_ASSERTION");
  });

test("stage diagnostic serialization is bounded and excludes arbitrary keys and unclassified values", () => {
  const secret = "FIXTURE_SECRET".repeat(10_000);
  const record = stageFailureRecord({
    phase: secret, stack: secret, payload: secret, facts: { uidMatch: false, modeMatch: true, versionMatch: false, secret },
    native: { exit: secret, signal: secret, errorCode: secret, timedOut: secret,
      stdout: { bytes: 1024 ** 3, sha256: "a".repeat(64), raw: secret }, stderr: { bytes: -1, sha256: secret }, env: secret },
  }, Object.assign(new Error(secret), { code: secret }));
  assert(Buffer.byteLength(record) <= 1024);
  assert(!record.includes("FIXTURE_SECRET"));
  assert.deepEqual(JSON.parse(record), {
    kind: "repair-config-stage-failure", phase: "input", errorCode: "unclassified",
    facts: { uidMatch: false, modeMatch: true, versionMatch: false },
    native: { exit: null, signal: "unclassified", errorCode: "unclassified", timedOut: false,
      stdout: { bytes: 1024 ** 3, sha256: "a".repeat(64) }, stderr: null },
  });
});

test("scanner environment requires existing proof-owned private HOME/tmp without permission changes", (t) => {
  const q = { proofUid: 999, proofGid: 982 }, seen = [];
  let change = () => {};
  t.mock.method(fs, "lstatSync", (file) => {
    seen.push(file);
    const stat = { isDirectory: () => true, isSymbolicLink: () => false, uid: 999, gid: 982, mode: 0o40700 };
    change(stat, file); return stat;
  });
  try {
    const options = scannerStageOptions(q);
    assert.deepEqual(seen, [`${ROOT}/private`, `${ROOT}/private/tmp`]);
    assert.equal(options.env.HOME, `${ROOT}/private`);
    assert.equal(options.env.TMPDIR, `${ROOT}/private/tmp`);
    assert.equal(options.uid, 999); assert.equal(options.gid, 982);
    for (const edit of [
      (s) => { s.uid = 1000; }, (s) => { s.gid = 1000; }, (s) => { s.mode = 0o40755; },
      (s) => { s.mode = 0o42700; }, (s) => { s.isDirectory = () => false; },
      (s) => { s.isSymbolicLink = () => true; },
      () => { throw Object.assign(new Error("absent"), { code: "ENOENT" }); },
    ]) {
      change = (stat, file) => { if (file.endsWith("/tmp")) edit(stat); };
      assert.throws(() => scannerStageOptions(q));
    }
  } finally { t.mock.restoreAll(); }
});

test("stage diagnostics do not appear in subsequent credential-bearing login failures", async (t) => {
  await stageFixture(t);
  await stageFixture(t, { mode: "login" });
});

test("workflow verifies qualification and staged inputs before API login then runs without secret env", () => {
  const body = fs.readFileSync(workflow, "utf8");
  const verify = body.indexOf("repair-config-guest-qualification.mjs verify");
  const stage = body.indexOf("repair-config-matrix.mjs verify-stage");
  const login = body.indexOf("repair-config-matrix.mjs login");
  const run = body.indexOf("repair-config-matrix.mjs run-matrix");
  assert(verify >= 0 && stage > verify && login > stage && run > login);
  const matrixStep = body.slice(body.indexOf("- name: Run four-cell"), body.indexOf("- uses: actions/upload"));
  assert.doesNotMatch(matrixStep, /secrets\.|OPENAI_API_KEY|CLAWSWEEPER_INTERNAL_MODEL/);
  assert.equal((body.match(/secrets\.OPENAI_API_KEY/g) ?? []).length, 1);
  assert.doesNotMatch(body, /auth\.json|--with-token|--body-file -|--input -/);
  assert.match(body, /timeout-minutes: 55/);
  assert.match(body, /github\.sha == inputs\.source_head/);
  assert.match(body, /test "\$RUNNER_NAME" = "\$REPAIR_PROOF_RUNNER_NAME"/);
});
