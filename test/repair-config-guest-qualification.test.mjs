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
  LIMITS, PINS, admitDeadline, assertRetention, classifyExec, commandTimeout, controllerPlan, digest,
  dispatchAfterReadback, executionEnvelope, fixtureGH, fixtureGit, fixtureUsage, gitLauncherSource, jobText, observeService, registrationAdapterSource,
  reserveStart, scannerInvocation, sourceInventory, validateEntries,
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
  assert.match(body, /fetch-depth: 8\b/);
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
  for (let i = 0; i < 22; i++) {
    const file = path.join(dir, `${i}.log`); fs.writeFileSync(file, "x"); files.push(file);
  }
  assert.deepEqual(assertRetention(files), { files: 22, bytes: 22 });
  assert.throws(() => assertRetention(files, 1));
  assert.throws(() => assertRetention(files, 0, LIMITS.retainedBytes));
  assert.throws(() => assertRetention([files[0], files[0]]));
  const link = path.join(dir, "symlink"); fs.symlinkSync(files[0], link);
  assert.throws(() => assertRetention([link]));
});

test("registration adapter delegates exactly one pinned ghx operation and keeps failed output private", (t) => {
  const dir = temporaryFixture(t), ghx = path.join(dir, "fixture-ghx"), adapter = path.join(dir, "adapter.mjs");
  const expected = ["--no-cache", "api", "-X", "POST", "repos/openclaw/clawsweeper/actions/runners/registration-token", "--jq", ".token"];
  const body = `#!${process.execPath}\nimport assert from "node:assert/strict"; assert.deepEqual(process.argv.slice(2), ${JSON.stringify(expected)}); process.stdout.write("FIXTURE_ONLY_TOKEN_123\\n");\n`;
  fs.writeFileSync(path.join(dir, "package.json"), '{"type":"module"}');
  fs.writeFileSync(ghx, body, { mode: 0o700 });
  fs.writeFileSync(adapter, registrationAdapterSource(ghx, digest(body)));
  const run = (args) => childProcess.spawnSync(process.execPath, [adapter, ...args], {
    env: { PATH: path.dirname(process.execPath) }, encoding: "utf8", timeout: 3000, maxBuffer: 4096,
  });
  const accepted = run(expected.slice(1));
  assert.equal(accepted.status, 0, accepted.stderr);
  assert.equal(accepted.stdout, "FIXTURE_ONLY_TOKEN_123\n");
  for (const args of [[], ["auth", "token"], [...expected.slice(1), "--input", "-"]]) {
    const rejected = run(args);
    assert.equal(rejected.status, 1); assert.equal(rejected.stdout, "");
    assert.equal(rejected.stderr, "registration adapter failed closed\n");
  }
  fs.appendFileSync(ghx, "// changed binary\n");
  const changed = run(expected.slice(1));
  assert.equal(changed.status, 1); assert.equal(changed.stdout, "");
});

test("controller plan binds sole-label registration after qualification and exact-lease cleanup", () => {
  const plan = controllerPlan({
    crabbox: "/fixture/crabbox", ghAdapter: "/fixture/gh", leaseId: LEASE,
    qualificationDigest: "a".repeat(64), inputDigest: "b".repeat(64),
    proofHead: HEAD, proofTree: PROOF_TREE, proofDigest: "c".repeat(64),
  });
  assert.equal(plan.crabboxSHA256, PINS.crabbox);
  assert.deepEqual(plan.leasePolicy, { ttlSeconds: 5400, idleSeconds: 5400, minimumMatrixRemainingSeconds: 3000, renewal: false });
  assert.equal(plan.beforeRegistration.length, 2);
  assert(plan.beforeRegistration.every(({ argv }) => argv.includes("--no-sync") && argv.includes("--script-stdin")));
  assert.deepEqual(plan.registration.argv.slice(-3), ["--labels", PINS.label, "--ephemeral"]);
  assert.deepEqual(plan.exactCleanup, ["/fixture/crabbox", "stop", LEASE]);
  assert(plan.dispatch.includes(`matrix_input_digest=${"b".repeat(64)}`));
  assert.equal(plan.preDispatch.proofHead, HEAD);
  assert(plan.dispatch.includes(`source_head=${HEAD}`));
  assert.equal(plan.registration.argv[plan.registration.argv.indexOf("--name") + 1], plan.preDispatch.runnerName);
});

test("dispatch consumes fresh exact head and unique runner identity/labels; drift never dispatches", () => {
  const options = {
    crabbox: "/fixture/crabbox", ghAdapter: "/fixture/gh", leaseId: LEASE,
    qualificationDigest: "a".repeat(64), inputDigest: "b".repeat(64),
    proofHead: HEAD, proofTree: PROOF_TREE, proofDigest: "c".repeat(64),
  };
  const plan = controllerPlan(options);
  options.registration = {
    binarySHA256: PINS.crabbox, argv: plan.registration.argv, code: 0, signal: null,
    stdout: `actions runner registered repo=openclaw/clawsweeper name=${plan.preDispatch.runnerName} labels=${PINS.label} ephemeral=true\n`,
  };
  const fixture = () => ({
    ref: { ref: `refs/heads/${PINS.branch}`, object: { type: "commit", sha: HEAD } },
    list: { total_count: 1, runners: [{
      id: 123, name: plan.preDispatch.runnerName, os: "linux", status: "online", busy: false,
      labels: [{ name: PINS.label, type: "custom" }],
    }] },
  });
  const run = (value, calls) => dispatchAfterReadback(options, (args) => {
    calls.push(args);
    if (JSON.stringify(args) === JSON.stringify(plan.preDispatch.runnerArgv)) return JSON.stringify(value.list);
    if (JSON.stringify(args) === JSON.stringify(plan.preDispatch.headArgv)) return JSON.stringify(value.ref);
    assert.deepEqual(args, plan.dispatch); return "";
  });
  const calls = [], result = run(fixture(), calls);
  assert.equal(result.runnerId, 123);
  assert.equal(result.registrationDigest, digest(JSON.stringify(options.registration)));
  assert.deepEqual(calls, [plan.preDispatch.runnerArgv, plan.preDispatch.headArgv, plan.dispatch]);
  for (const change of [
    (f) => { f.ref.object.sha = "d".repeat(40); },
    (f) => { f.ref.ref = "refs/heads/main"; },
    (f) => { f.list.total_count = 2; },
    (f) => { f.list.runners = []; },
    (f) => { f.list.runners[0].id = 0; },
    (f) => { f.list.runners[0].name = "foreign"; },
    (f) => { f.list.runners[0].os = "windows"; },
    (f) => { f.list.runners[0].status = "offline"; },
    (f) => { f.list.runners[0].busy = true; },
    (f) => { f.list.runners[0].ephemeral = false; },
    (f) => { f.list.runners[0].labels.push({ name: "self-hosted", type: "read-only" }); },
    (f) => { f.list.runners[0].labels[0].name = "other"; },
  ]) {
    const value = fixture(), rejectedCalls = []; change(value);
    assert.throws(() => run(value, rejectedCalls));
    assert(!rejectedCalls.some((args) => args[0] === "workflow"));
  }
  for (const change of [
    (r) => { r.binarySHA256 = "d".repeat(64); },
    (r) => { r.argv = ["wrong-registration-command"]; },
    (r) => { r.code = 1; },
    (r) => { r.signal = "SIGTERM"; },
    (r) => { r.stdout = r.stdout.replace("ephemeral=true", "ephemeral=false"); },
    (r) => { r.stdout = r.stdout.replace(plan.preDispatch.runnerName, "foreign-runner"); },
  ]) {
    const registration = structuredClone(options.registration); change(registration);
    let calls = 0;
    assert.throws(() => dispatchAfterReadback({ ...options, registration }, () => { calls++; }));
    assert.equal(calls, 0);
  }
  assert.throws(() => dispatchAfterReadback({ ...options, registration: undefined }, () => assert.fail("must reject before API")));
});

test("scanner version and actual scans use the same isolated network namespace without altered arguments", () => {
  for (const args of [
    ["--version"],
    ["filesystem", "/fixture/staging", "--results=verified,unknown", "--fail", "--fail-on-scan-errors", "--no-update", "--json", "--no-color"],
  ]) assert.deepEqual(scannerInvocation("/fixture/trufflehog", args),
    ["/usr/bin/unshare", ["--user", "--map-root-user", "--net", "--", "/fixture/trufflehog", ...args]]);
  assert.throws(() => scannerInvocation("/fixture/trufflehog", ["--no-verification"]));
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
