import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Task-only prerequisite. Qualification runs natively before runner registration.
const BASE = "2f777941de926c6f11cb0c6363ecfe4bbee94371";
const TREE = "212409328808e514cbf65914fec600db05747d7a";
const BRANCH = "refs/heads/proof/repair-codex-config-20261001";
const LABEL = "crabbox-proof-20261001-b-7c91e5a2";
const ROOT = "/opt/repair-config-proof-20261001";
const RECEIPT = `${ROOT}/qualification.json`;
const USER = "repair-config-proof";
const CODEX_VERSION = "0.159.3";
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

export function proofCodexConfig(model) {
  const settings = model === undefined ? "" : `model = ${JSON.stringify(model)}\nmodel_reasoning_effort = "medium"\n`;
  return `${settings}[features]\nplugins = false\n`;
}

export function pluginsDisabled(output) {
  if (!output.endsWith("\n") || /[^\t\n\x20-\x7e]/.test(output)) return false;
  const rows = output.split("\n").filter((line) => /^[ \t]*plugins\b/.test(line));
  return rows.length === 1
    && /^plugins[ \t]+stable[ \t]+false$/.test(rows[0]);
}

export function removeQualificationConfig(file, expected, uid, gid, terminated) {
  assert.equal(terminated, true, "qualification children must be terminated");
  const bytes = Buffer.from(proofCodexConfig());
  assert.equal(expected?.sha256, sha256(bytes));
  assert.equal(expected.uid, uid);
  assert.equal(expected.gid, gid);
  assert.equal(expected.mode, 0o600);
  assert.equal(expected.nlink, 1);
  assert.equal(expected.size, bytes.length);
  const check = (stat) => {
    assert(stat.isFile() && !stat.isSymbolicLink());
    for (const key of ["dev", "ino", "uid", "gid", "nlink", "size"])
      assert.equal(stat[key], expected[key], `qualification config ${key} mismatch`);
    assert.equal(stat.mode & 0o7777, 0o600);
  };
  check(fs.lstatSync(file));
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    check(fs.fstatSync(fd));
    const actual = fs.readFileSync(fd);
    assert(actual.equals(bytes));
    assert.equal(sha256(actual), expected.sha256);
    check(fs.fstatSync(fd));
  } finally {
    fs.closeSync(fd);
  }
  check(fs.lstatSync(file));
  fs.unlinkSync(file);
}

export function parseArguments(argv) {
  const [mode, ...rest] = argv;
  assert(["qualify", "verify"].includes(mode), "explicit mode required");
  const names = ["lease-id", "source-head", "source-tree", "source-digest"];
  names.push(...(mode === "qualify" ? ["codex-bin", "codex-sha256"] : ["receipt-sha256"]));
  assert.equal(rest.length, names.length * 2, "exact arguments required");
  const args = { mode };
  for (let i = 0; i < rest.length; i += 2) {
    const name = rest[i].slice(2);
    assert(rest[i].startsWith("--") && names.includes(name) && !Object.hasOwn(args, name));
    args[name] = rest[i + 1];
  }
  assert(/^cbx_[a-f0-9]{12}$/.test(args["lease-id"]));
  for (const name of ["source-head", "source-tree"]) assert(/^[a-f0-9]{40}$/.test(args[name]));
  for (const name of ["source-digest", mode === "qualify" ? "codex-sha256" : "receipt-sha256"])
    assert(/^[a-f0-9]{64}$/.test(args[name]));
  if (mode === "qualify") assert(path.isAbsolute(args["codex-bin"]));
  return args;
}

export function classifySocketDescriptors(entries) {
  const standardStreams = [];
  for (const [fd, target] of entries) {
    if (!target.startsWith("socket:")) continue;
    // These are the two explicit launcher capture streams, not host service sockets.
    assert(fd === "1" || fd === "2", "unexpected inherited socket descriptor");
    standardStreams.push(Number(fd));
  }
  return { socketBackedStandardStreams: standardStreams.sort(), unexpectedSocketDescriptors: 0 };
}

export function supervisorArguments(unit, command, args) {
  assert(/^repair-proof-[a-f0-9]{12}-[a-f0-9-]{36}\.service$/.test(unit));
  return [
    "--quiet", "--no-ask-password", "--wait", "--pipe", "--service-type=exec",
    `--unit=${unit}`, `--working-directory=${ROOT}`, "--expand-environment=no",
    "--property=Slice=system.slice", "--property=RuntimeMaxSec=100s",
    "--property=TimeoutStopSec=5s", "--property=KillMode=control-group",
    "--property=SendSIGKILL=yes", "--property=ExitType=cgroup",
    "--", command, ...args,
  ];
}

export function unitStopped(fields, groupExists, populated) {
  if (fields.LoadState === "not-found")
    return fields.ActiveState === "inactive" && !groupExists;
  return fields.LoadState === "loaded" && ["inactive", "failed"].includes(fields.ActiveState)
    && fields.MainPID === "0" && fields.ControlPID === "0" && (!groupExists || populated === false);
}

export function assertReceiptBinding(receipt, expected) {
  assert.equal(receipt.format, 1);
  assert.equal(receipt.qualified, true);
  assert.equal(receipt.mode, "qualify");
  for (const key of ["base", "tree", "label", "leaseId", "guestBootDigest", "harnessDigest", "runnerUid"])
    assert.deepEqual(receipt[key], expected[key], `receipt ${key} mismatch`);
  assert.deepEqual(receipt.source, expected.source);
  assert.deepEqual(receipt.node, expected.node);
  assert(receipt.proofUid > 0 && receipt.proofUid !== receipt.runnerUid && receipt.proofGid > 0);
  assert.equal(receipt.probes?.uidBoundary, true);
  assert.equal(receipt.probes?.unexpectedSocketDescriptors, 0);
  assert.equal(receipt.probes?.containment?.markerMatch, true);
  assert.equal(receipt.probes?.sandbox?.markerMatch, true);
  const plugins = receipt.probes?.plugins;
  assert(plugins?.status === 0 && !plugins.signal && !plugins.failure && !plugins.signalFailure && plugins.markerMatch);
  assert.equal(plugins.stderrBytes, 0);
  assert.equal(receipt.supervisor?.terminated, true);
  assert.equal(receipt.temporaryConfigRemoved, true);
  assert.equal(receipt.codex?.version, CODEX_VERSION);
}

function inventory(root) {
  const entries = [];
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const file = path.join(dir, entry.name);
      assert(!entry.isSymbolicLink(), "unexpected build symlink");
      if (entry.isDirectory()) walk(file);
      else {
        const stat = fs.statSync(file);
        assert(entry.isFile(), "unexpected build entry");
        entries.push({ path: path.relative(root, file), mode: stat.mode & 0o777, size: stat.size, sha256: sha256(fs.readFileSync(file)) });
      }
    }
  }
  walk(root);
  entries.sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
  return { files: entries.length, digest: sha256(JSON.stringify(entries)) };
}

function sourceInventory(workspace, index) {
  const entries = [];
  for (const row of index.split("\0").filter(Boolean)) {
    const match = /^(100644|100755) [a-f0-9]{40} 0\t(.+)$/.exec(row);
    assert(match);
    const [mode, name] = match.slice(1);
    const file = path.join(workspace, name), stat = fs.lstatSync(file);
    assert(stat.isFile() && !stat.isSymbolicLink());
    assert.equal((stat.mode & 0o111) !== 0, mode === "100755");
    entries.push({ path: name, mode, size: stat.size, sha256: sha256(fs.readFileSync(file)) });
  }
  entries.sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
  return { files: entries.length, digest: sha256(JSON.stringify(entries)) };
}

function protectedExecutable(file) {
  const actual = fs.realpathSync(file);
  const stat = fs.lstatSync(actual);
  assert(stat.isFile() && (stat.mode & 0o111) !== 0 && stat.uid === 0 && (stat.mode & 0o022) === 0);
  for (let dir = path.dirname(actual); ; dir = path.dirname(dir)) {
    const parent = fs.lstatSync(dir);
    assert(parent.isDirectory() && parent.uid === 0 && (parent.mode & 0o022) === 0);
    if (dir === "/") break;
  }
  return { path: actual, sha256: sha256(fs.readFileSync(actual)) };
}

// Serialized into the root-supervised child; it receives no controller environment.
async function guestProbes(options, classifySockets, renderConfig, checkPlugins) {
  const { default: assert } = await import("node:assert/strict");
  const fs = await import("node:fs");
  const path = await import("node:path");
  const { createHash } = await import("node:crypto");
  const { spawn } = await import("node:child_process");
  const result = { uidBoundary: false, peak: { files: 0, bytes: 0 } };
  let stage = "uid-boundary";
  function measure() {
    let files = 0, bytes = 0;
    function walk(dir) {
      let entries;
      try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
      catch (error) { if (error.code === "ENOENT") return; throw error; }
      for (const entry of entries) {
        const file = path.join(dir, entry.name);
        let stat;
        try { stat = fs.lstatSync(file); }
        catch (error) { if (error.code === "ENOENT") continue; throw error; }
        if (stat.isDirectory()) walk(file);
        else { files++; bytes += stat.size; }
      }
    }
    walk(process.env.HOME);
    result.peak.files = Math.max(result.peak.files, files);
    result.peak.bytes = Math.max(result.peak.bytes, bytes);
    assert(files <= 1024 && bytes <= 128 * 1024 * 1024, "fixture budget");
  }
  async function child(command, args, marker) {
    return await new Promise((resolve) => {
      const child = spawn(command, args, {
        cwd: path.join(process.env.HOME, "work"), env: process.env,
        stdio: ["ignore", "pipe", "pipe"],
      });
      let bytes = 0, stderrBytes = 0, stdout = "", failure = null, signalFailure = null;
      function stop(reason) {
        failure ??= reason;
        // This is only our direct same-UID child. PID 1 owns cross-UID/cgroup cleanup.
        try { child.kill("SIGKILL"); }
        catch (error) { signalFailure = error.code === "EPERM" ? "EPERM" : "signal-error"; }
      }
      const timer = setTimeout(() => stop("deadline"), 35_000);
      const monitor = setInterval(() => { try { measure(); } catch { stop("fixture-budget"); } }, 200);
      function capture(chunk, isStdout) {
        bytes += chunk.length;
        if (!isStdout) stderrBytes += chunk.length;
        if (bytes > 1024 * 1024) { stop("output-budget"); return; }
        if (isStdout) stdout += chunk;
      }
      child.stdout.on("data", (chunk) => capture(chunk, true));
      child.stderr.on("data", (chunk) => capture(chunk, false));
      child.on("error", () => { failure = "spawn"; });
      child.on("close", (status, signal) => {
        clearTimeout(timer);
        clearInterval(monitor);
        try { measure(); } catch { failure ??= "fixture-budget"; }
        resolve({ status, signal, failure, signalFailure, stderrBytes, markerMatch: typeof marker === "function" ? marker(stdout) : marker.test(stdout) });
      });
    });
  }
  try {
    assert.equal(process.getuid(), options.uid);
    assert.deepEqual(Object.keys(process.env).sort(), options.envNames);
    for (const dir of [process.env.HOME, process.env.TMPDIR, process.env.CODEX_HOME, path.join(process.env.HOME, "work")]) {
      const stat = fs.statSync(dir);
      assert.equal(stat.uid, process.getuid());
      assert.equal(stat.mode & 0o777, 0o700);
    }
    assert.deepEqual(fs.readdirSync(process.env.CODEX_HOME), []);
    const status = fs.readFileSync("/proc/self/status", "utf8");
    assert.equal(status.split("\n").find((line) => line.startsWith("Groups:")).slice(7).trim(), "");
    for (const name of ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"])
      assert.equal(BigInt("0x" + status.match(new RegExp("^" + name + ":\\s*(\\w+)", "m"))[1]), 0n);
    assert.match(status, /^NoNewPrivs:\s+1$/m);
    assert.throws(() => fs.readFileSync(options.canary), { code: "EACCES" });
    const descriptors = [];
    for (const fd of fs.readdirSync("/proc/self/fd")) {
      try { descriptors.push([fd, fs.readlinkSync(`/proc/self/fd/${fd}`)]); }
      catch (error) { if (error.code !== "ENOENT") throw error; }
    }
    Object.assign(result, classifySockets(descriptors));
    for (const socket of ["/run/docker.sock", "/var/run/docker.sock", "/run/podman/podman.sock"]) {
      try { fs.accessSync(socket, fs.constants.R_OK | fs.constants.W_OK); assert.fail("host socket accessible"); }
      catch (error) { assert(["ENOENT", "EACCES"].includes(error.code)); }
    }
    Object.assign(result, { uidBoundary: true, supplementaryGroups: 0, capabilities: 0, canaryUnreadable: true });
    stage = "temporary-config";
    const config = path.join(process.env.CODEX_HOME, "config.toml"), configBytes = Buffer.from(renderConfig());
    const fd = fs.openSync(config, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    try {
      fs.writeFileSync(fd, configBytes);
      const stat = fs.fstatSync(fd);
      assert(stat.isFile() && stat.uid === process.getuid() && stat.gid === process.getgid()
        && (stat.mode & 0o7777) === 0o600 && stat.nlink === 1 && stat.size === configBytes.length);
      result.temporaryConfig = Object.fromEntries(["dev", "ino", "uid", "gid", "nlink", "size"].map((key) => [key, stat[key]]));
      Object.assign(result.temporaryConfig, { mode: 0o600, sha256: createHash("sha256").update(configBytes).digest("hex") });
    } finally {
      fs.closeSync(fd);
    }
    measure();
    for (const [name, command, args, marker] of [
      ["codexVersion", options.codex, ["--version"], /^codex-cli 0\.159\.3\n$/],
      ["plugins", options.codex, ["features", "list"], checkPlugins],
      ["containment", process.execPath, [options.preflight], /^mount_readonly=\S+ landlock=\S+\n$/],
      ["sandbox", options.codex, [
        "sandbox", "--permission-profile", ":read-only", "-C", path.join(process.env.HOME, "work"),
        "--", "/bin/sh", "-eu", "-c", "printf 'REPAIR_CONFIG_SANDBOX_OK\\n'",
      ], /^REPAIR_CONFIG_SANDBOX_OK\n$/],
    ]) {
      stage = name;
      result[name] = await child(command, args, marker);
      const value = result[name];
      assert(value.status === 0 && !value.signal && !value.failure && !value.signalFailure && value.markerMatch);
      if (name === "plugins") assert.equal(value.stderrBytes, 0);
    }
  } catch {
    result.failure = { stage, reason: "guest prerequisite failed closed" };
    process.exitCode = 1;
  }
  process.stdout.write(JSON.stringify(result));
}

export function guestProbeSource(options) {
  return `import assert from "node:assert/strict"; await (${guestProbes.toString()})(${JSON.stringify(options)}, ${classifySocketDescriptors.toString()}, ${proofCodexConfig.toString()}, ${pluginsDisabled.toString()});`;
}

export function qualificationConfigCleanupSource(expected, uid, gid, terminated) {
  return `import assert from "node:assert/strict"; import fs from "node:fs"; import crypto from "node:crypto";
    const proofCodexConfig = ${proofCodexConfig.toString()};
    const sha256 = ${sha256.toString()};
    (${removeQualificationConfig.toString()})(${JSON.stringify(`${ROOT}/private/codex/config.toml`)}, ${JSON.stringify(expected)}, ${uid}, ${gid}, ${JSON.stringify(terminated)});`;
}

export async function main(argv = process.argv.slice(2)) {
  const started = Date.now(), deadline = started + 12 * 60 * 1000;
  const report = {
    format: 1, base: BASE, tree: TREE, label: LABEL,
    claim: "Guest UID, compiled containment and native sandbox prerequisites only",
    limits: { modelCalls: 0, credentialsForwarded: false, registrationPerformed: false,
      providerIdentity: "Controller binds the lease ID to its native AWS record",
      policyCause: "Not inferred from guest configuration changes", sandbox: "Credential-free tiny native command, not a model or API proof" },
    steps: [],
  };
  let stage = "admission", childOutputBytes = 0;
  const emit = (value) => report.steps.push({ stage, ...value });
  const cleanEnvironment = (home = process.env.HOME, tmp = "/tmp") => {
    assert(path.isAbsolute(home) && path.isAbsolute(tmp));
    return { HOME: home, PATH: `${path.dirname(process.execPath)}:/usr/local/bin:/usr/bin:/bin`, LANG: "C.UTF-8", TMPDIR: tmp, TMP: tmp, TEMP: tmp };
  };
  async function run(command, args, options = {}) {
    const seconds = Math.ceil(Math.min(options.timeout ?? 60_000, deadline - Date.now()) / 1000);
    assert(seconds > 0, "qualification deadline");
    const result = await new Promise((resolve) => {
      const child = spawn(command, args, {
        cwd: options.cwd ?? process.cwd(), env: cleanEnvironment(),
        stdio: [options.input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
        detached: !options.nativeDeadline,
      });
      let stdout = "", stderr = "", bytes = 0, failure = null, signalFailure = null, killTimer;
      function kill(signal) {
        if (!child.pid) return;
        try { process.kill(-child.pid, signal); }
        catch (error) { if (error.code !== "ESRCH") signalFailure = error.code === "EPERM" ? "EPERM" : "signal-error"; }
      }
      function stop(reason) {
        if (failure) return;
        failure = reason;
        // Privileged commands use a root-owned native timeout, never caller signals.
        if (!options.nativeDeadline) {
          kill("SIGTERM");
          killTimer = setTimeout(() => kill("SIGKILL"), 5_000);
        }
      }
      const timer = options.nativeDeadline ? null : setTimeout(() => stop("deadline"), seconds * 1000);
      function capture(chunk, stream) {
        bytes += chunk.length;
        childOutputBytes += chunk.length;
        if (bytes > 1024 * 1024 || childOutputBytes > 4 * 1024 * 1024) { stop("output-budget"); return; }
        if (stream === "stdout") stdout += chunk; else stderr += chunk;
      }
      child.stdout.on("data", (chunk) => capture(chunk, "stdout"));
      child.stderr.on("data", (chunk) => capture(chunk, "stderr"));
      child.on("error", () => { failure = "spawn"; });
      if (child.stdin) {
        child.stdin.on("error", () => { failure ??= "stdin"; });
        child.stdin.end(options.input);
      }
      child.on("close", (status, signal) => {
        clearTimeout(timer); clearTimeout(killTimer);
        resolve({ status, signal, failure, signalFailure, stdout, stderr });
      });
    });
    emit({ command: path.basename(command), status: result.status, signal: result.signal, failure: result.failure, signalFailure: result.signalFailure });
    if (!options.allowFailure) assert(result.status === 0 && !result.signal && !result.failure && !result.signalFailure, `command failed at ${stage}`);
    return result;
  }
  const rootCommand = (command, args, options = {}) => {
    const seconds = Math.ceil(Math.min(options.timeout ?? 15_000, deadline - Date.now()) / 1000);
    assert(seconds > 0);
    return run("/usr/bin/sudo", [
      "-n", "--", "/usr/bin/timeout", "--signal=TERM", "--kill-after=5s", `${seconds}s`, command, ...args,
    ], { ...options, nativeDeadline: true });
  };
  const git = async (...args) => (await run("/usr/bin/git", args)).stdout.trim();
  try {
    const args = parseArguments(argv);
    report.mode = args.mode;
    report.leaseId = args["lease-id"];
    assert(process.platform === "linux" && process.arch === "x64" && process.getuid() !== 0);
    assert(Number(process.versions.node.split(".")[0]) >= 24);
    for (const name of ["OPENAI_API_KEY", "CODEX_API_KEY", "CLAWSWEEPER_INTERNAL_MODEL", "PROXY_API_KEY"])
      assert(!Object.hasOwn(process.env, name), "credential-free prerequisite only");
    if (args.mode === "qualify") {
      for (const name of Object.keys(process.env))
        assert(!/^(GITHUB_|GH_|ACTIONS_|RUNNER_|OPENAI_|CODEX_)/.test(name), "native credential-free invocation required");
    } else {
      assert.equal(process.env.GITHUB_ACTIONS, "true");
      assert.equal(process.env.GITHUB_EVENT_NAME, "workflow_dispatch");
      assert.equal(process.env.GITHUB_REPOSITORY, "openclaw/clawsweeper");
      assert.equal(process.env.GITHUB_REF, BRANCH);
      assert.equal(process.env.GITHUB_SHA, args["source-head"]);
    }
    const workspace = fs.realpathSync(process.cwd());
    const runnerHome = fs.realpathSync(process.env.HOME);
    assert.equal(fs.statSync(runnerHome).uid, process.getuid());
    assert(workspace.startsWith(`${runnerHome}/`));
    report.runnerUid = process.getuid();
    report.guestBootDigest = sha256(fs.readFileSync("/proc/sys/kernel/random/boot_id"));
    report.node = { ...protectedExecutable(process.execPath), version: process.version };
    report.harnessDigest = sha256(fs.readFileSync(fileURLToPath(import.meta.url)));
    const head = await git("rev-parse", "HEAD"), tree = await git("rev-parse", "HEAD^{tree}");
    assert.equal(head, args["source-head"]);
    assert.equal(tree, args["source-tree"]);
    assert.equal(await git("rev-parse", `${BASE}^{tree}`), TREE);
    await git("merge-base", "--is-ancestor", BASE, "HEAD");
    assert.equal(await git("status", "--porcelain", "--untracked-files=no"), "");
    const changed = (await git("diff", "--name-only", BASE, "HEAD")).split("\n").filter(Boolean);
    const allowed = [
      ".github/workflows/ci.yml",
      "scripts/e2e/repair-config-guest-qualification.mjs",
      "scripts/e2e/repair-config-matrix.mjs",
      "test/repair-config-guest-qualification.test.mjs",
    ];
    assert(changed.length > 0 && changed.every((name) => allowed.includes(name)));
    const index = (await run("/usr/bin/git", ["ls-files", "--stage", "-z"])).stdout;
    report.source = { head, tree, ...sourceInventory(workspace, index) };
    assert.equal(report.source.digest, args["source-digest"]);
    emit({ sourceBound: true });

    if (args.mode === "verify") {
      stage = "verify-existing-receipt";
      const parent = fs.lstatSync(ROOT), stat = fs.lstatSync(RECEIPT);
      assert(parent.isDirectory() && parent.uid === 0 && (parent.mode & 0o022) === 0);
      assert(stat.isFile() && stat.nlink === 1 && stat.uid === 0 && (stat.mode & 0o777) === 0o444 && stat.size <= 64 * 1024);
      const bytes = fs.readFileSync(RECEIPT);
      assert.equal(sha256(bytes), args["receipt-sha256"]);
      const receipt = JSON.parse(bytes);
      assertReceiptBinding(receipt, report);
      assert.deepEqual(inventory(`${ROOT}/build/dist`), receipt.compiled);
      assert.deepEqual(protectedExecutable(receipt.codex.path), { path: receipt.codex.path, sha256: receipt.codex.sha256 });
      assert.equal((await run("/usr/bin/id", ["-u", USER])).stdout.trim(), String(receipt.proofUid));
      assert.equal((await run("/usr/bin/id", ["-g", USER])).stdout.trim(), String(receipt.proofGid));
      const homeStat = fs.lstatSync(`${ROOT}/private`);
      assert(homeStat.isDirectory() && homeStat.uid === receipt.proofUid && (homeStat.mode & 0o777) === 0o700);
      assert.equal(fs.statSync(runnerHome).mode & 0o777, 0o700);
      for (const step of receipt.steps.filter((step) => step.setting && step.readable))
        assert.equal((await run("/usr/sbin/sysctl", ["-n", step.setting])).stdout.trim(), step.after);
      report.verified = true;
      report.receiptDigest = args["receipt-sha256"];
      emit({ qualificationReexecuted: false, credentialsUsed: false, registrationPerformed: false });
    } else {
      stage = "toolchain";
      assert(!fs.existsSync(ROOT), "task guest root already exists");
      assert(!fs.existsSync("dist"), "fresh build required");
      report.codex = { ...protectedExecutable(args["codex-bin"]), version: CODEX_VERSION };
      assert.equal(report.codex.sha256, args["codex-sha256"]);
      assert.equal(JSON.parse(fs.readFileSync("package.json", "utf8")).packageManager, "pnpm@12.4.1");
      assert.equal((await run("corepack", ["pnpm", "--version"])).stdout.trim(), "12.4.1");
      await run("corepack", ["pnpm", "install", "--frozen-lockfile"], { timeout: 240_000 });
      await run("corepack", ["pnpm", "run", "build:node"], { timeout: 180_000 });
      emit({ pnpm: "12.4.1", frozenInstall: true, buildNode: true });

      stage = "private-uid";
      assert.equal((await run("/usr/bin/getent", ["passwd", USER], { allowFailure: true })).status, 2);
      assert.equal((await run("/usr/bin/getent", ["group", USER], { allowFailure: true })).status, 2);
      fs.chmodSync(runnerHome, 0o700);
      const canary = path.join(runnerHome, ".repair-config-proof-canary");
      fs.writeFileSync(canary, crypto.randomBytes(32), { mode: 0o600, flag: "wx" });
      await rootCommand("/usr/bin/install", ["-d", "-m", "755", "-o", "root", "-g", "root", ROOT]);
      const home = `${ROOT}/private`, build = `${ROOT}/build`;
      await rootCommand("/usr/sbin/useradd", ["--system", "--no-create-home", "--user-group", "--home-dir", home, "--shell", "/usr/sbin/nologin", USER]);
      const uid = Number((await run("/usr/bin/id", ["-u", USER])).stdout.trim());
      const gid = Number((await run("/usr/bin/id", ["-g", USER])).stdout.trim());
      assert(uid > 0 && uid !== process.getuid() && gid > 0);
      assert.deepEqual((await run("/usr/bin/id", ["-G", USER])).stdout.trim().split(/\s+/), [String(gid)]);
      report.proofUid = uid; report.proofGid = gid;
      for (const dir of [home, `${home}/tmp`, `${home}/work`, `${home}/codex`])
        await rootCommand("/usr/bin/install", ["-d", "-m", "700", "-o", String(uid), "-g", String(gid), dir]);
      await rootCommand("/usr/bin/install", ["-d", "-m", "755", "-o", String(process.getuid()), "-g", String(process.getgid()), build]);
      const before = inventory("dist");
      fs.cpSync("dist", `${build}/dist`, { recursive: true, errorOnExist: true });
      fs.writeFileSync(`${build}/package.json`, '{"type":"module"}\n', { flag: "wx", mode: 0o644 });
      assert.deepEqual(inventory(`${build}/dist`), before);
      await rootCommand("/usr/bin/chown", ["-R", "root:root", build]);
      await rootCommand("/usr/bin/chmod", ["-R", "a+rX,go-w", build]);
      report.compiled = inventory(`${build}/dist`);
      emit({ compiled: report.compiled, dependenciesCopied: false });

      stage = "guest-ci-settings";
      for (const [name, desired] of [["kernel.unprivileged_userns_clone", "1"], ["kernel.apparmor_restrict_unprivileged_userns", "0"]]) {
        const observed = await run("/usr/sbin/sysctl", ["-n", name], { allowFailure: true });
        assert(!observed.failure && !observed.signal);
        if (observed.status !== 0) { emit({ setting: name, readable: false, changed: false }); continue; }
        const current = observed.stdout.trim();
        assert(/^[01]$/.test(current));
        if (current !== desired) await rootCommand("/usr/sbin/sysctl", ["-w", `${name}=${desired}`]);
        assert.equal((await run("/usr/sbin/sysctl", ["-n", name])).stdout.trim(), desired);
        emit({ setting: name, readable: true, before: current, after: desired, changed: current !== desired });
      }

      stage = "ordinary-uid-probes";
      assert(deadline - Date.now() >= 200_000, "reserve supervisor and cleanup time");
      assert(fs.statSync("/sys/fs/cgroup/cgroup.controllers").isFile(), "cgroup v2 required");
      const proofEnv = { ...cleanEnvironment(home, `${home}/tmp`), CODEX_HOME: `${home}/codex` };
      const options = { uid, canary, codex: report.codex.path, preflight: `${build}/dist/repair/containment-preflight.js`, envNames: Object.keys(proofEnv).sort() };
      const code = guestProbeSource(options);
      const unit = `repair-proof-${args["lease-id"].slice(4)}-${crypto.randomUUID()}.service`;
      const probeArgs = [
        "--reuid", String(uid), "--regid", String(gid), "--clear-groups",
        "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all", "--no-new-privs",
        "/usr/bin/env", "-i", ...Object.entries(proofEnv).map(([key, value]) => `${key}=${value}`),
        process.execPath, "--input-type=module", "-e", code,
      ];
      const group = `/system.slice/${unit}`;
      async function observeUnit() {
        const state = await rootCommand("/usr/bin/systemctl", ["--no-ask-password", "show", unit, "--property=LoadState,ActiveState,SubState,MainPID,ControlPID,ControlGroup,Result"], { allowFailure: true });
        const fields = Object.fromEntries(state.stdout.trim().split("\n").map((line) => { const at = line.indexOf("="); return [line.slice(0, at), line.slice(at + 1)]; }));
        assert(!fields.ControlGroup || fields.ControlGroup === group);
        let groupExists = true, populated = null;
        try {
          assert(fs.lstatSync(`/sys/fs/cgroup${group}`).isDirectory());
          const events = fs.readFileSync(`/sys/fs/cgroup${group}/cgroup.events`, "utf8");
          assert(/^populated [01]$/m.test(events));
          populated = /^populated 1$/m.test(events);
        } catch (error) {
          if (error.code !== "ENOENT") throw error;
          groupExists = false;
        }
        return { fields, groupExists, terminated: [0, 1, 4].includes(state.status) && !state.failure && !state.signal && unitStopped(fields, groupExists, populated) };
      }
      const prior = await observeUnit();
      assert(prior.terminated && prior.fields.LoadState === "not-found" && !prior.groupExists, "new task unit only");
      const probe = await rootCommand("/usr/bin/systemd-run", supervisorArguments(unit, "/usr/bin/setpriv", probeArgs), { cwd: ROOT, timeout: 115_000, allowFailure: true });
      // PID 1, not the ordinary caller, owns all descendants across UID transitions.
      let settled, stopped, observationFailed = false;
      try { settled = await observeUnit(); } catch { observationFailed = true; }
      if (!settled?.terminated) {
        stopped = await rootCommand("/usr/bin/systemctl", ["--no-ask-password", "stop", unit], { allowFailure: true });
        try { settled = await observeUnit(); } catch { observationFailed = true; }
      }
      report.supervisor = {
        kind: "systemd-control-group", unit, stopStatus: stopped?.status ?? null,
        observationFailed, terminated: settled?.terminated === true,
      };
      assert(report.supervisor.terminated, "privileged child termination unconfirmed");
      assert(!observationFailed, "supervisor observation failed");
      try { report.probes = JSON.parse(probe.stdout); } catch { report.probes = { uidBoundary: false }; }
      stage = "remove-temporary-config";
      await rootCommand(process.execPath, ["--input-type=module", "-e",
        qualificationConfigCleanupSource(report.probes.temporaryConfig, uid, gid, report.supervisor.terminated)]);
      report.temporaryConfigRemoved = true;
      assert(!stopped || (stopped.status === 0 && !stopped.failure && !stopped.signal));
      assert(probe.status === 0 && !probe.failure && !probe.signal && !report.probes.failure);
      assert(report.probes.uidBoundary && report.probes.containment?.markerMatch && report.probes.sandbox?.markerMatch
        && report.probes.plugins?.markerMatch);
      assert.deepEqual(inventory(`${build}/dist`), report.compiled);
      assert.equal(await git("status", "--porcelain", "--untracked-files=no"), "");
      assert.deepEqual({ head, tree, ...sourceInventory(workspace, index) }, report.source);
      report.qualified = true;
      report.durationMs = Date.now() - started;
      const bytes = `${JSON.stringify(report)}\n`;
      assert(Buffer.byteLength(bytes) <= 64 * 1024);
      stage = "seal-receipt";
      await rootCommand(process.execPath, ["--input-type=module", "-e", `
        import fs from "node:fs";
        const bytes = fs.readFileSync(0);
        if (bytes.length > 65536) throw new Error("receipt budget");
        fs.writeFileSync(${JSON.stringify(RECEIPT)}, bytes, {flag:"wx", mode:0o444});
      `], { input: bytes });
      assert.equal(sha256(fs.readFileSync(RECEIPT)), sha256(bytes));
      report.receiptDigest = sha256(bytes);
    }
  } catch (error) {
    report.qualified = false;
    report.verified = false;
    report.failure = { stage, code: error?.code === "ERR_ASSERTION" ? "ERR_ASSERTION" : null, reason: "prerequisite failed closed" };
    process.exitCode = 1;
  }
  report.durationMs = Date.now() - started;
  report.childOutputBytes = childOutputBytes;
  const bytes = `${JSON.stringify(report, null, 2)}\n`;
  assert(Buffer.byteLength(bytes) <= 64 * 1024, "qualification evidence budget");
  process.stdout.write(bytes);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  await main();
