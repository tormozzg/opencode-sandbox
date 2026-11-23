// qodana-mcp: stdio MCP server exposing exactly three tools:
//   qodana_start_scan {project_dir, files?}  -> launches a detached native-mode
//      qodana scan (no docker), state lives on disk, returns immediately.
//   qodana_scan_diff {project_dir, diff_base} -> same, but the CLI runs
//      --diff-start <diff_base> so only files changed since that commit are
//      analysed; failure is loud (status failed via qodana_findings), never a
//      silent fallback to a full scan.
//   qodana_findings {scan_id?, files?}       -> compact SARIF-derived findings.
// Raw SARIF is never returned. No other tools.
// Single-flight is PER PROJECT (one scan per project across all server
// instances, enforced by a lock file plus the on-disk scan state): concurrent
// calls for the same project return the running scan's scan_id with
// already_running:true and owner info and start nothing, while scans of
// DIFFERENT projects run concurrently with isolated per-project cache dirs.

import { execFileSync, spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

// --- Configuration -----------------------------------------------------------
// QODANA_HOME_DIR is a test seam only (used by QA to point state at /tmp);
// in the image it stays at the pinned default below.

const QODANA_ROOT = process.env.QODANA_HOME_DIR ?? '/home/opencode/.cache/qodana';
const SCANS_DIR = path.join(QODANA_ROOT, 'scans');
const LOCKS_DIR = path.join(QODANA_ROOT, 'locks');
const LINTER = 'qodana-jvm-community';
const MAX_FINDINGS = 200;

// The cache dir is PER PROJECT: <QODANA_ROOT>/cache/projects/<hash12>/current,
// hash12 = first 12 hex chars of sha1 of the RESOLVED project dir. The
// trailing "current" level exists because the qodana CLI computes the IDE
// dist location as Dir(Dir(--cache-dir)) (compute.go), so with the plain
// <QODANA_ROOT>/cache the 2.4 GB qodana-QDJVMC-<build>.tar lands one level
// ABOVE this dir (in ~/.cache), outside the shared container mount;
// Dir(Dir(cache/projects/<h>/current)) = <QODANA_ROOT>/cache/projects keeps it
// inside the mount. The projects/<hash12> level exists because a shared
// cache/current holds single-slot IDE state (idea/263/index,
// config/263/jdk.table.xml, .idea/workspace.xml) that concurrent scans of
// different projects would clobber — per-project namespacing inside the IDE
// cache exists only under idea/263/projects, so the isolation happens at the
// --cache-dir level. Dist-placement consequence: on a cold start the CLI
// installs the 2.4 GB dist under <QODANA_ROOT>/cache/projects/ (once, then
// reused in place); findWarmDist only scans QODANA_ROOT, so a dist at
// cache/projects/ is not auto-pinned — in the deployed image the dist at
// QODANA_ROOT is already warm and QODANA_DIST pins it (findWarmDist
// unchanged). Per-project cache dirs also obsolete the old cross-project
// .idea scrub: each project's .idea now lives under its own hash dir.

function projectHash12(projectDir) {
  return crypto.createHash('sha1').update(projectDir).digest('hex').slice(0, 12);
}

function cacheDirFor(projectDir) {
  return path.join(QODANA_ROOT, 'cache', 'projects', projectHash12(projectDir), 'current');
}

// No-DNS hardening: in native mode the CLI resolves the IDE version via a feed
// HEAD to https://download.jetbrains.com/qodana/feed/<linter>.releases.json
// before EVERY scan (installers.go getIde -> getProductByLinterName), even when
// the dist is already warm in the cache. There is no --linter version pin
// (FindLinterByName matches bare names only; "name:version" is rejected). The
// official bypass is QODANA_DIST pointing at the extracted IDE home
// (PathNativeAnalyzer, DownloadDist()==false -> the feed call never happens).
// The warm dist dir is created by the CLI itself: downloadAndInstallIDE
// installs to Dir(Dir(--cache-dir))/<download-name-without-.gz>, which keeps a
// trailing ".tar" — so the directory is reused in place when present; cold
// starts (dist not yet downloaded, DNS needed) are left untouched.
const WARM_DIST_PREFIX = 'qodana-QDJVMC-'; // product code of qodana-jvm-community

function findWarmDist() {
  let entries = [];
  try {
    entries = fs.readdirSync(QODANA_ROOT, { withFileTypes: true });
  } catch {
    return null; // QODANA_ROOT not created yet: cold start
  }
  const dist = entries.find(
    (entry) => entry.isDirectory() && entry.name.startsWith(WARM_DIST_PREFIX) && entry.name.endsWith('.tar'),
  );
  if (!dist) return null;
  const distPath = path.join(QODANA_ROOT, dist.name);
  // The CLI fatals if QODANA_DIST is not a valid dist: only reuse a complete one.
  if (!fs.existsSync(path.join(distPath, 'product-info.json'))) return null;
  return distPath;
}

// Inspection groups for the narrow semantic profile. CONFIRMED 2026-11-21
// against v2026.3.1 SARIF (real scan, qodana-jvm-community): inspection groups
// are the `tool.driver.taxa` IDs (no "category:" prefix; "Java/Redundancy" and
// "Kotlin/Unused Symbol" do not exist — the redundancy catch-alls are
// "Java/Verbose or redundant code constructs" and "Kotlin/Redundant constructs").
// The leading "- enabled: false" entry CRASHES the linter ("Missing group or
// inspection id"); disable-all via group "All" instead (verified: semantic
// findings produced, zero style rules in SARIF results).
const SEMANTIC_GROUPS = [
  'Java/Probable bugs',
  'Java/Declaration redundancy',
  'Java/Verbose or redundant code constructs',
  'Kotlin/Probable bugs',
  'Kotlin/Redundant constructs',
];

// Lower rank = more severe; unknown severities sink to the bottom.
const SEVERITY_RANK = { error: 0, warning: 1, note: 2 };

// --- Findings mapping (pure, exported for unit tests) ------------------------

export function filterFindings(sarif, files = []) {
  const mapped = (sarif.runs ?? []).flatMap((run) => (run.results ?? []).map(mapResult));
  const selected = files.length === 0
    ? mapped
    : mapped.filter((finding) => files.some((needle) => finding.file.includes(needle)));
  selected.sort(bySeverityThenFile);
  return {
    findings: selected.slice(0, MAX_FINDINGS),
    counts: { total: selected.length, returned: Math.min(selected.length, MAX_FINDINGS) },
    truncated: selected.length > MAX_FINDINGS,
  };
}

function mapResult(result) {
  // Real Qodana 2026.3 SARIF nests the location under results[].locations[0];
  // the flat result.physicalLocation shape is kept as a fallback for fixtures.
  const physical = result.locations?.[0]?.physicalLocation ?? result.physicalLocation;
  const uri = physical?.artifactLocation?.uri ?? '';
  return {
    file: decodeURIComponent(uri.replace(/^file:\/\//, '')),
    line: physical?.region?.startLine ?? 0,
    severity: result.level ?? 'note',
    rule: result.ruleId ?? '',
    message: result.message?.text ?? '',
  };
}

function bySeverityThenFile(a, b) {
  const rankDelta = (SEVERITY_RANK[a.severity] ?? SEVERITY_RANK.note + 1) - (SEVERITY_RANK[b.severity] ?? SEVERITY_RANK.note + 1);
  if (rankDelta !== 0) return rankDelta;
  if (a.file !== b.file) return a.file < b.file ? -1 : 1;
  return a.line - b.line;
}

// --- Scan state on disk ------------------------------------------------------

function scanId() {
  return new Date().toISOString().replace(/[-:.]/g, '');
}

function listScanDirs() {
  if (!fs.existsSync(SCANS_DIR)) return [];
  return fs.readdirSync(SCANS_DIR, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && fs.existsSync(path.join(SCANS_DIR, entry.name, 'status.json')))
    .map((entry) => path.join(SCANS_DIR, entry.name))
    .sort()
    .reverse(); // timestamp-based names: lexicographic order == chronological
}

function readStatus(scanDir) {
  return JSON.parse(fs.readFileSync(path.join(scanDir, 'status.json'), 'utf8'));
}

function writeStatus(scanDir, status) {
  fs.writeFileSync(path.join(scanDir, 'status.json'), JSON.stringify(status, null, 2));
}

function finalizeScan(scanDir, patch) {
  writeStatus(scanDir, { ...readStatus(scanDir), ...patch });
}

// A "running" scan whose watcher (the server process) died must not block
// idempotent start_scan forever: if the qodana pid is gone, finalize from
// disk evidence (SARIF present -> done, else failed). The pid check also
// treats zombies as gone (container init may not reap orphans).
function reconcile(scanDir) {
  const status = readStatus(scanDir);
  if (status.state !== 'running') return status;
  if (isPidAlive(status.pid)) return status;
  const sarifExists = fs.existsSync(path.join(scanDir, 'results', 'qodana.sarif.json'));
  const next = { ...status, state: sarifExists ? 'done' : 'failed', finishedAt: status.finishedAt ?? new Date().toISOString() };
  writeStatus(scanDir, next);
  return next;
}

function isPidAlive(pid) {
  if (pid === null || pid === undefined) return false; // no recorded watcher: rely on disk evidence
  try {
    process.kill(pid, 0);
  } catch (err) {
    return err.code === 'EPERM';
  }
  // kill(pid, 0) also succeeds for a zombie: an orphaned qodana child
  // reparents to container init, which may never reap it, so the zombie
  // would look "running" forever and block single-flight start. It can
  // never progress to done, so disk-evidence finalization must win.
  // /proc format is "State:\tZ (zombie)" — tab after the colon.
  try {
    const status = fs.readFileSync(`/proc/${pid}/status`, 'utf8');
    const stateLine = status.split('\n').find((line) => line.startsWith('State:'));
    if (stateLine && /^State:\s*Z/.test(stateLine)) return false; // zombie: treat as not alive
  } catch {
    // /proc absent or unreadable (e.g. non-linux): fall back to the kill result (alive)
  }
  return true;
}

// --- Per-project scan locks --------------------------------------------------
// One scan per project across ALL server instances: an atomic lock file per
// project, <QODANA_ROOT>/locks/<hash12>.lock, acquired after validation and
// released in the child's exit/error handlers. The payload names the owning
// scan (scan_id, pid = the SERVER process holding the lock — known at acquire
// time, unlike the child pid — plus startedAt, project_dir, mode and diff_base
// when incremental) so a concurrent caller can answer honestly with the
// running scan's identity. A lock whose owner pid is dead or a zombie, or
// whose content is unreadable/corrupt, is stealable: a crashed server must not
// block a project forever. Release re-reads the payload first so a successor's
// lock is never unlinked by an exiting elder.
//
// Content atomicity invariant: a reader sees NO lock or the COMPLETE payload,
// never a partial file. The payload is written to a unique temp file in the
// same directory and fs.linkSync then creates the lock name as an atomic
// exclusive create (EEXIST when taken); readers resolve the hardlink to the
// already-complete temp content. wx+write is two syscalls and exposes an
// empty file in between: a racer hitting that window reads null, mistakes the
// live lock for corrupt, steals it, and two same-project scans would run
// sharing one per-project cache dir. The temp file lingers only if the
// process dies between write and link; it is never read.
//
// Steal discipline (two-stealer race, observed live as two 'started'
// responses for one project): a stale lock is unlinked ONLY when the content
// at unlink time still IS the dead payload just diagnosed — a fresh winner's
// payload never matches a dead diagnosis, so live locks survive and the
// unlink storm terminates once the stale generation is gone. A post-win
// re-read closes the residual read→unlink window: if our brand-new lock was
// displaced between create and verify, we hold nothing and re-race — exactly
// one acquirer's payload ends up in the file, and that one proceeds.

function lockPathFor(projectDir) {
  return path.join(LOCKS_DIR, `${projectHash12(projectDir)}.lock`);
}

function createLockAtomically(lockPath, lockPayload) {
  const temp = `${lockPath}.${process.pid}.${Date.now()}.tmp`;
  try {
    fs.writeFileSync(temp, JSON.stringify(lockPayload, null, 2));
    fs.linkSync(temp, lockPath); // atomic exclusive create: EEXIST when taken
  } finally {
    try {
      fs.unlinkSync(temp); // canonical lock name keeps the content (link count 2→1)
    } catch {
      // the temp never existed: the payload write itself failed
    }
  }
}

function readLockFile(lockPath) {
  try {
    return JSON.parse(fs.readFileSync(lockPath, 'utf8'));
  } catch {
    return null; // unreadable or already unlinked: caller re-races or steals
  }
}

// Lock-holder identity: all three fields TOGETHER — scan_id and startedAt are
// millisecond timestamps that can collide across processes acquiring in the
// same millisecond (observed live); the holding server's pid cannot.
function sameLockOwner(a, b) {
  return a.scan_id === b.scan_id && a.pid === b.pid && a.startedAt === b.startedAt;
}

// Race rounds before giving up loudly. Convergence needs 2-3 under an
// 8-instance same-project storm (one steal round for the stale generation,
// one for an ε-displaced victim); 4 leaves headroom without masking a bug —
// the terminal throw is unreachable under the protocol itself.
const LOCK_RACE_ROUNDS = 4;

function acquireProjectLock(projectDir, lockPayload) {
  fs.mkdirSync(LOCKS_DIR, { recursive: true });
  const lockPath = lockPathFor(projectDir);
  for (let round = 0; ; round++) {
    if (round >= LOCK_RACE_ROUNDS) {
      // Fail loud rather than answer busy without a real scan_id.
      throw new Error(`project lock ${lockPath} unresolved after ${LOCK_RACE_ROUNDS} race rounds`);
    }
    let taken = false;
    try {
      createLockAtomically(lockPath, lockPayload);
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
      taken = true;
    }
    if (!taken) {
      // Post-win verification: if our brand-new lock was displaced between
      // create and this read (ε-window stealer) or vanished, we hold nothing
      // — re-race; whoever's payload is in the file proceeds, we answer busy
      // with it.
      const mine = readLockFile(lockPath);
      if (mine && sameLockOwner(mine, lockPayload)) return { ok: true, lockPath };
      continue;
    }
    const owner = readLockFile(lockPath);
    if (owner && isPidAlive(owner.pid)) return { ok: false, owner };
    if (!owner) {
      // Absent (vanished mid-race) or unreadable. A protocol lock is never
      // unreadable (content is complete before the name appears), so this is
      // free-to-race or foreign garbage: clear it and race again.
      try {
        fs.unlinkSync(lockPath);
      } catch {
        // already gone
      }
      continue;
    }
    // Dead owner: steal — but unlink ONLY the exact payload just diagnosed.
    // Re-read at unlink time: a fresh winner may have appeared between the
    // read above and here, and deleting its lock would let two same-project
    // scans run.
    const atUnlink = readLockFile(lockPath);
    if (!atUnlink) continue; // vanished: race the create again
    if (!sameLockOwner(atUnlink, owner)) {
      if (isPidAlive(atUnlink.pid)) return { ok: false, owner: atUnlink };
      continue; // a different stale payload: re-diagnose from the top
    }
    console.error(`qodana-mcp: stealing stale project lock ${lockPath} (owner pid ${owner.pid} not alive)`);
    try {
      fs.unlinkSync(lockPath);
    } catch {
      // already gone: the next round races the create
    }
  }
}

function releaseProjectLock(lockPath, scanId) {
  const owner = readLockFile(lockPath);
  if (!owner || owner.scan_id !== scanId) return; // a successor holds it now
  try {
    fs.unlinkSync(lockPath);
  } catch {
    // already gone: nothing to release
  }
}

// --- Local endpoint stub (JetBrains IP-fencing workaround) -------------------
// The qodana CLI hard-requires https://qodana.cloud/api/versions before any
// scan, but qodana.cloud is IP-fenced for this user's network (HTTP 451
// "Customer Sanctions Notice" — JetBrains withdrew service from the region;
// user decision recorded 2026-11-21 in the purchased-license context). The
// official QODANA_ENDPOINT env var (per Qodana docs) redirects the CLI to a
// replacement host, so each scan gets an in-process stub server on an
// ephemeral 127.0.0.1 port serving the one endpoint the CLI resolves — the
// /api/versions payload reconstructed from qodana-cli v2026.3.1
// internal/cloud/versions.go (needs api major 1 + minor >= 0; community +
// no-token scans never fetch the URLs and make no further cloud calls).
// The stub only answers endpoint resolution: no token is set, no cloud
// features are touched, and nothing leaves the machine except this request
// to localhost. The stub lives in the MCP process; if the MCP server dies
// mid-scan the child fails its endpoint call and reconcile() finalizes the
// scan as failed. Any other path gets 404 — the drivers show the CLI probes
// only /api/versions.

function startEndpointStub() {
  return new Promise((resolve, reject) => {
    const stub = http.createServer((req, res) => {
      if (req.url === '/api/versions') {
        const { port } = stub.address();
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({
          api: { versions: [{ version: '1.0', url: `http://127.0.0.1:${port}/api` }] },
          linters: { versions: [{ version: '1.0', url: `http://127.0.0.1:${port}/linters/api` }] },
        }));
      } else {
        res.writeHead(404);
        res.end();
      }
    });
    stub.on('error', reject);
    stub.listen(0, '127.0.0.1', () => resolve(stub));
  });
}

// --- Tool: qodana_start_scan -------------------------------------------------
// opts = { mode: 'incremental', diffStart } drives qodana_scan_diff; the
// default ({}) is the full-project scan. Incremental mode records mode and
// diff_base in status.json (and in the project lock) so already_running
// callers can tell what the running scan actually is.

// Honest busy answer for both tools: the caller gets the RUNNING scan's
// identity instead of a started scan (lock payload or the scan dir's
// status.json). diff_base appears only when the running scan actually has
// one. A caller that passed its own scan_id compares it to scan_id here.
function busyRunningJson(owner) {
  const payload = {
    scan_id: owner.scan_id,
    status: 'running',
    already_running: true,
    owner: { pid: owner.pid, startedAt: owner.startedAt },
    mode: owner.mode ?? 'full',
  };
  if (owner.diff_base !== undefined) payload.diff_base = owner.diff_base;
  return json(payload);
}

async function startScan(args, opts = {}) {
  const invalid = validateStartScanArgs(args, opts);
  if (invalid) return toolError(invalid);

  const projectDir = path.resolve(args.project_dir);
  if (!fs.existsSync(projectDir) || !fs.statSync(projectDir).isDirectory()) {
    return toolError(`project_dir does not exist or is not a directory: ${projectDir}`);
  }

  const id = scanId();
  const lockPath = lockPathFor(projectDir);
  const lockPayload = {
    scan_id: id,
    pid: process.pid,
    startedAt: new Date().toISOString(),
    project_dir: projectDir,
    mode: opts.mode === 'incremental' ? 'incremental' : 'full',
  };
  if (opts.mode === 'incremental') lockPayload.diff_base = opts.diffStart;

  // Per-project gate, two sources, in this order: the lock first (atomic), then
  // the disk scan state (covers a running scan whose lock was lost, e.g. manual
  // deletion). Both busy paths return without starting anything or creating a
  // scan dir.
  const lock = acquireProjectLock(projectDir, lockPayload);
  if (!lock.ok) return busyRunningJson(lock.owner);

  const running = listScanDirs().find((dir) => {
    const status = reconcile(dir);
    return status.state === 'running' && status.project_dir === projectDir;
  });
  if (running) {
    releaseProjectLock(lockPath, id);
    return busyRunningJson({ ...readStatus(running), scan_id: path.basename(running) });
  }

  // Start the stub BEFORE creating any scan state: if it fails to listen, the
  // toolError below returns with no orphan scan dir (nothing was created) and
  // the project lock is released. It must also be listening BEFORE the spawn:
  // the CLI calls /api/versions on the first attempt (it retries 3x with ~30s
  // gaps, then fatals), and must not fail on the first attempt.
  let stub;
  try {
    stub = await startEndpointStub();
  } catch (err) {
    releaseProjectLock(lockPath, id);
    return toolError(`could not start local endpoint stub: ${err.message}`);
  }
  stub.unref();
  console.error(`qodana-mcp: endpoint stub listening at 127.0.0.1:${stub.address().port} (QODANA_ENDPOINT)`);

  // Scan-state creation and spawn: any failure here (e.g. scan dir creation)
  // closes the stub, releases the lock, and returns without orphaning either.
  try {
    const scanDir = path.join(SCANS_DIR, id);
    fs.mkdirSync(path.join(scanDir, 'results'), { recursive: true });
    const gitignorePatterns = collectGitignorePatterns(projectDir);
    const profilePath = path.join(scanDir, 'profile.yaml');
    fs.writeFileSync(profilePath, inspectionProfileYaml());
    const scanArgs = [
      'scan', '--within-docker', 'false', '--linter', LINTER,
      '--project-dir', projectDir, '--cache-dir', cacheDirFor(projectDir),
      '--results-dir', path.join(scanDir, 'results'), '--profile-path', profilePath,
    ];
    if (gitignorePatterns.length > 0) {
      if (hasProjectQodanaConfig(projectDir)) {
        // The user's own qodana.yaml wins: --config would replace it, so
        // degrade to full scope instead of clobbering project settings.
        console.error('qodana-mcp: project has its own qodana.yaml, gitignore excludes skipped');
      } else {
        const configPath = path.join(scanDir, 'qodana-exclude.yaml');
        fs.writeFileSync(configPath, qodanaExcludeConfigYaml(gitignorePatterns));
        scanArgs.push('--config', configPath);
      }
    }
    if (opts.mode === 'incremental') {
      scanArgs.push('--diff-start', opts.diffStart);
    }
    const logFd = fs.openSync(path.join(scanDir, 'qodana.log'), 'a');

    // QODANA_TOKEN is deliberately stripped from the child env: no cloud
    // features — the README promises a code-enforced no-token scan.
    const env = { ...process.env };
    delete env.QODANA_TOKEN;
    env.QODANA_ENDPOINT = `http://127.0.0.1:${stub.address().port}`;
    const warmDist = findWarmDist();
    if (warmDist) {
      env.QODANA_DIST = warmDist;
      console.error(`qodana-mcp: warm IDE dist found, pinning QODANA_DIST=${warmDist} (skips feed HEAD)`);
    }

    const child = spawn('qodana', scanArgs, {
      detached: true,
      stdio: ['ignore', logFd, logFd],
      env,
    });
    const statusPayload = {
      state: 'running',
      project_dir: projectDir,
      files: args.files ?? [],
      startedAt: new Date().toISOString(),
      pid: child.pid,
    };
    if (opts.mode === 'incremental') {
      statusPayload.mode = 'incremental';
      statusPayload.diff_base = opts.diffStart;
    }
    writeStatus(scanDir, statusPayload);
    child.on('exit', (exitCode) => {
      finalizeScan(scanDir, { state: exitCode === 0 ? 'done' : 'failed', exitCode, finishedAt: new Date().toISOString() });
      releaseProjectLock(lockPath, id);
      stub.close();
    });
    child.on('error', (err) => {
      finalizeScan(scanDir, { state: 'failed', exitCode: null, finishedAt: new Date().toISOString(), error: String(err) });
      releaseProjectLock(lockPath, id);
      stub.close();
    });
    child.unref(); // survives the MCP server process; results are read from disk
  } catch (err) {
    stub.close();
    releaseProjectLock(lockPath, id);
    return toolError(`could not start qodana scan: ${err.message}`);
  }

  if (opts.mode === 'incremental') {
    return json({ scan_id: id, status: 'started', mode: 'incremental', diff_base: opts.diffStart });
  }
  return json({ scan_id: id, status: 'started' });
}

function validateStartScanArgs(args, opts = {}) {
  if (typeof args.project_dir !== 'string' || args.project_dir.length === 0) {
    return 'project_dir is required and must be a string (absolute path).';
  }
  if (opts.mode === 'incremental') {
    if (typeof opts.diffStart !== 'string' || opts.diffStart.length === 0) {
      return 'diff_base is required and must be a non-empty string (commit to diff from).';
    }
    return null;
  }
  return validateFilesArg(args.files);
}

function validateFilesArg(files) {
  if (files === undefined) return null;
  if (!Array.isArray(files) || !files.every((f) => typeof f === 'string')) {
    return 'files must be an array of strings when provided.';
  }
  return null;
}

// --- Gitignore-derived ignore patterns --------------------------------------
// Findings on paths the project's own git ignores (build outputs, vendored
// code) are noise. Git itself is the source of truth for ignore semantics
// (nested .gitignores, per-dir excludes) — we never parse .gitignore by hand.
// `--directory` collapses fully-ignored dirs to "dir/" entries; the trailing
// slash is stripped because the exclude config matches PLAIN dir paths
// recursively — the documented "dir/**" glob form is silently NOT honored by
// v2026.3.1 exclude configs (proven live; plain dirs are).

const GITIGNORE_PATTERN_CAP = 500;
const GIT_LS_FILES_TIMEOUT_MS = 10_000;

function collectGitignorePatterns(projectDir) {
  let stdout;
  try {
    stdout = execFileSync('git', ['ls-files', '--others', '--ignored', '--exclude-standard', '--directory'], {
      cwd: projectDir,
      timeout: GIT_LS_FILES_TIMEOUT_MS,
      encoding: 'utf8',
    });
  } catch (err) {
    // Not a git repo, git missing, or timeout: degrade to full scan scope.
    console.error(`qodana-mcp: gitignore ignores: 0 patterns (git ls-files failed: ${String(err.message).split('\n')[0]})`);
    return [];
  }
  const patterns = [...new Set(
    stdout.split('\n')
      .map((line) => line.trim())
      .filter((entry) => entry !== '' && entry !== '/' && entry !== '.')
      .map((entry) => (entry.endsWith('/') ? entry.slice(0, -1) : entry)),
  )].sort().slice(0, GITIGNORE_PATTERN_CAP);
  console.error(`qodana-mcp: gitignore ignores: ${patterns.length} patterns`);
  return patterns;
}

function inspectionProfileYaml() {
  const groups = SEMANTIC_GROUPS
    .map((group) => `  - group: "${group}"\n    enabled: true`)
    .join('\n');
  return [
    '# Narrow Qodana profile: semantic inspections only (no style checks).',
    '# Group IDs confirmed against v2026.3.1 SARIF tool.driver.taxa.',
    'name: qodana-mcp-semantic',
    'inspections:',
    '  - group: "All"\n    enabled: false',
    groups,
    '',
  ].join('\n');
}

// Git-ignored paths are excluded via a qodana.yaml `exclude` config (name:
// All = every inspection, paths relative to the project dir) passed to the
// CLI with --config. PROVEN against v2026.3.1 live scans: (1) per-entry
// `ignore:` lists in a standalone --profile-path profile file are silently
// NOT honored (plain paths, "dir/**" globs, and a separate group-ALL ignore
// entry all left ignored-path findings in the SARIF); (2) the exclude config
// removes them and keeps the narrow profile intact. --config accepts an
// absolute path outside the project, so the user's project tree is never
// modified; exclude paths resolve against the project dir regardless of the
// server process cwd, and the glob form must be avoided (plain dirs only).
function qodanaExcludeConfigYaml(patterns) {
  const quoteYaml = (pattern) => `"${pattern.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
  return [
    'version: "1.0"',
    `linter: ${LINTER}`,
    'exclude:',
    '  - name: All',
    '    paths:',
    ...patterns.map((pattern) => `      - ${quoteYaml(pattern)}`),
    '',
  ].join('\n');
}

function hasProjectQodanaConfig(projectDir) {
  return ['qodana.yaml', 'qodana.yml'].some((name) => fs.existsSync(path.join(projectDir, name)));
}

// --- Tool: qodana_findings ---------------------------------------------------

function getFindings(args) {
  const invalid = validateFindingsArgs(args);
  if (invalid) return toolError(invalid);

  if (args.scan_id !== undefined) {
    if (!/^[0-9A-Za-z]+$/.test(args.scan_id)) {
      return toolError(`scan_id must be a plain identifier, got: ${args.scan_id}`);
    }
    const scanDir = path.join(SCANS_DIR, args.scan_id);
    if (!fs.existsSync(path.join(scanDir, 'status.json'))) {
      return toolError(`Unknown scan_id: ${args.scan_id}`);
    }
    return respondForScan(scanDir, args.files ?? []);
  }

  const lastDone = listScanDirs().find((dir) => reconcile(dir).state === 'done');
  if (!lastDone) {
    return json({
      status: 'no_results',
      hint: 'No completed Qodana scan yet. Call qodana_start_scan first; a scan takes minutes.',
    });
  }
  return respondForScan(lastDone, args.files ?? []);
}

function validateFindingsArgs(args) {
  if (args.scan_id !== undefined && (typeof args.scan_id !== 'string' || args.scan_id.length === 0)) {
    return 'scan_id must be a non-empty string when provided.';
  }
  return validateFilesArg(args.files);
}

function respondForScan(scanDir, files) {
  const status = reconcile(scanDir);
  const scan_id = path.basename(scanDir);
  if (status.state === 'running') return json({ status: 'running', scan_id });
  if (status.state === 'failed') {
    return json({ status: 'failed', scan_id, exitCode: status.exitCode ?? null, log: path.join(scanDir, 'qodana.log') });
  }
  const sarifPath = path.join(scanDir, 'results', 'qodana.sarif.json');
  let sarif;
  try {
    sarif = JSON.parse(fs.readFileSync(sarifPath, 'utf8'));
  } catch {
    return json({ status: 'failed', scan_id, exitCode: status.exitCode ?? null, log: path.join(scanDir, 'qodana.log'), error: `SARIF not readable at ${sarifPath}` });
  }
  const { findings, counts, truncated } = filterFindings(sarif, files);
  return json({ status: 'done', scan_id, truncated, counts, findings });
}

// --- MCP wiring --------------------------------------------------------------

const server = new Server({ name: 'qodana-mcp', version: '0.2.0' }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'qodana_start_scan',
      description: 'Start a Qodana (JetBrains) static analysis scan on a project directory in native mode. Returns scan_id immediately; polls via qodana_findings. Single-flight is per project across all server instances: if a scan of the SAME project is already running, its scan_id is returned with already_running: true and owner info (pid, startedAt) and nothing is started; scans of DIFFERENT projects run concurrently with isolated per-project cache dirs.',
      inputSchema: {
        type: 'object',
        properties: {
          project_dir: { type: 'string', description: 'Absolute path to the project directory to analyze' },
          files: { type: 'array', items: { type: 'string' }, description: 'Optional file paths to narrow the findings filter later' },
        },
        required: ['project_dir'],
      },
    },
    {
      name: 'qodana_findings',
      description: 'Get compact Qodana findings (file, line, severity, rule, message) for a scan. Without scan_id, returns the most recent completed scan. Raw SARIF is never returned; results are capped at 200.',
      inputSchema: {
        type: 'object',
        properties: {
          scan_id: { type: 'string', description: 'Optional scan id from qodana_start_scan; omit for the most recent completed scan' },
          files: { type: 'array', items: { type: 'string' }, description: 'Optional file path substrings to filter findings by' },
        },
      },
    },
    {
      name: 'qodana_scan_diff',
      description: 'Start a Qodana scan limited to the files changed since diff_base (a commit, passed to the CLI as --diff-start). Same lifecycle and per-project single-flight as qodana_start_scan: if a scan of the SAME project is already running, its scan_id is returned with already_running: true, owner info (pid, startedAt), and the running scan\'s mode (plus diff_base when the running scan is itself a diff scan) — the diff scan is NOT started.',
      inputSchema: {
        type: 'object',
        properties: {
          project_dir: { type: 'string', description: 'Absolute path to the project directory to analyze' },
          diff_base: { type: 'string', description: 'Commit to diff from (e.g. HEAD~1); only files changed since it are analysed' },
        },
        required: ['project_dir', 'diff_base'],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const args = request.params.arguments ?? {};
  if (request.params.name === 'qodana_start_scan') return startScan(args);
  if (request.params.name === 'qodana_findings') return getFindings(args);
  if (request.params.name === 'qodana_scan_diff') {
    return startScan(args, { mode: 'incremental', diffStart: args.diff_base });
  }
  return toolError(`Unknown tool: ${request.params.name}`);
});

const json = (payload) => ({ content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }] });
const toolError = (message) => ({ content: [{ type: 'text', text: message }], isError: true });

async function main() {
  await server.connect(new StdioServerTransport());
  console.error('qodana-mcp: running on stdio');
}

// Only serve when run directly (`node index.js`); importing the module must
// stay side-effect free so filterFindings is unit-testable.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
