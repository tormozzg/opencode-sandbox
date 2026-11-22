// qodana-mcp: stdio MCP server exposing exactly two tools:
//   qodana_start_scan {project_dir, files?}  -> launches a detached native-mode
//      qodana scan (no docker), state lives on disk, returns immediately.
//   qodana_findings {scan_id?, files?}       -> compact SARIF-derived findings.
// Raw SARIF is never returned. No other tools.

import { spawn } from 'node:child_process';
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
// CACHE_DIR gets an extra "current" level: the qodana CLI computes the IDE
// dist location as Dir(Dir(--cache-dir)) (compute.go), so with the plain
// <QODANA_ROOT>/cache the 2.4 GB qodana-QDJVMC-<build>.tar lands one level
// ABOVE this dir (in ~/.cache), outside the shared container mount. With
// <QODANA_ROOT>/cache/current, Dir(Dir(...)) = <QODANA_ROOT> = the shared
// mount, keeping the dist shared across containers.
const CACHE_DIR = path.join(QODANA_ROOT, 'cache', 'current');
const LINTER = 'qodana-jvm-community';
const MAX_FINDINGS = 200;

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
// disk evidence (SARIF present -> done, else failed).
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
    return true;
  } catch (err) {
    return err.code === 'EPERM';
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

// --- Cross-project IDE-config scrub -----------------------------------------
// The IDE's saved project config lives in the shared cache at
// <CACHE_DIR>/.idea/ and is keyed by --cache-dir ONLY, not by project:
// scanning project B after project A restores A's .idea into B, and the IDE
// opens B as "already imported", silently skipping B's build-system sync
// ("No source roots detected" — zero source-file findings; proven
// bidirectionally Gradle→Maven→Gradle in .opencode/evidence/silent-planet/
// idea-cache-fix/ — font-libs proved the mechanism only). To keep each scan's project
// context correct we persist the LAST scanned project_dir in
// last-project.json on the shared mount (survives server restarts), and when
// it differs from the project now being scanned delete <CACHE_DIR>/.idea
// before spawning (a first-ever scan counts as a switch: if .idea does not
// exist the removal is a no-op, but the marker is still recorded so a later
// project switch triggers a scrub).
// The scrub forces one build-system re-sync per project switch — the honest
// trade-off for correctness; the IDE's warm inspection caches elsewhere in
// the same cache dir stay, so repeat scans of the SAME project remain fast.
// Scans are serialized by the running-scan check in startScan, so the scrub
// never races a live scan of another project (the pre-existing TOCTOU window
// in that check is unaffected here).

const LAST_PROJECT_FILE = path.join(QODANA_ROOT, 'last-project.json');

function scrubStaleIdeaCache(projectDir) {
  let last = null;
  try {
    last = JSON.parse(fs.readFileSync(LAST_PROJECT_FILE, 'utf8')).project_dir ?? null;
  } catch {
    last = null; // no marker yet (first-ever scan) or unreadable: assume a switch
  }
  if (last === projectDir) return;
  const ideaDir = path.join(CACHE_DIR, '.idea');
  if (fs.existsSync(ideaDir)) {
    fs.rmSync(ideaDir, { recursive: true });
    console.error(`qodana-mcp: scrubbed stale IDE project config ${ideaDir} (last scanned: ${last ?? 'none'})`);
  }
  try {
    fs.mkdirSync(QODANA_ROOT, { recursive: true });
    fs.writeFileSync(LAST_PROJECT_FILE, JSON.stringify({ project_dir: projectDir }));
  } catch (err) {
    // Best-effort: a missed marker write only costs one redundant scrub next
    // time — never fail the scan over it.
    console.error(`qodana-mcp: could not write ${LAST_PROJECT_FILE}: ${err.message}`);
  }
}

// --- Tool: qodana_start_scan -------------------------------------------------

async function startScan(args) {
  const invalid = validateStartScanArgs(args);
  if (invalid) return toolError(invalid);

  const projectDir = path.resolve(args.project_dir);
  if (!fs.existsSync(projectDir) || !fs.statSync(projectDir).isDirectory()) {
    return toolError(`project_dir does not exist or is not a directory: ${projectDir}`);
  }

  const running = listScanDirs().find((dir) => reconcile(dir).state === 'running');
  if (running) {
    return json({ scan_id: path.basename(running), status: 'running', already_running: true });
  }

  // Start the stub BEFORE creating any scan state: if it fails to listen,
  // the toolError below returns with no orphan scan dir (nothing was created).
  // It must also be listening BEFORE the spawn: the CLI calls /api/versions on
  // the first attempt (it retries 3x with ~30s gaps, then fatals), and must
  // not fail on the first attempt.
  let stub;
  try {
    stub = await startEndpointStub();
  } catch (err) {
    return toolError(`could not start local endpoint stub: ${err.message}`);
  }
  stub.unref();
  console.error(`qodana-mcp: endpoint stub listening at 127.0.0.1:${stub.address().port} (QODANA_ENDPOINT)`);

  // AFTER the stub (the only await that can fail — no cache side effects may
  // precede it) and BEFORE any scan-state creation or the spawn. On a scrub
  // I/O failure close the stub (mirroring the child handlers) so the throw
  // cannot leak the listener; marker-write failure-safety stays best-effort.
  try {
    scrubStaleIdeaCache(projectDir);
  } catch (err) {
    stub.close();
    return toolError(`could not scrub stale IDE project config: ${err.message}`);
  }

  const id = scanId();
  const scanDir = path.join(SCANS_DIR, id);
  fs.mkdirSync(path.join(scanDir, 'results'), { recursive: true });
  const profilePath = path.join(scanDir, 'profile.yaml');
  fs.writeFileSync(profilePath, inspectionProfileYaml());
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

  const child = spawn('qodana', [
    'scan', '--within-docker', 'false', '--linter', LINTER,
    '--project-dir', projectDir, '--cache-dir', CACHE_DIR,
    '--results-dir', path.join(scanDir, 'results'), '--profile-path', profilePath,
  ], {
    detached: true,
    stdio: ['ignore', logFd, logFd],
    env,
  });
  writeStatus(scanDir, {
    state: 'running',
    project_dir: projectDir,
    files: args.files ?? [],
    startedAt: new Date().toISOString(),
    pid: child.pid,
  });
  child.on('exit', (exitCode) => {
    finalizeScan(scanDir, { state: exitCode === 0 ? 'done' : 'failed', exitCode, finishedAt: new Date().toISOString() });
    stub.close();
  });
  child.on('error', (err) => {
    finalizeScan(scanDir, { state: 'failed', exitCode: null, finishedAt: new Date().toISOString(), error: String(err) });
    stub.close();
  });
  child.unref(); // survives the MCP server process; results are read from disk

  return json({ scan_id: id, status: 'started' });
}

function validateStartScanArgs(args) {
  if (typeof args.project_dir !== 'string' || args.project_dir.length === 0) {
    return 'project_dir is required and must be a string (absolute path).';
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

const server = new Server({ name: 'qodana-mcp', version: '0.1.0' }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'qodana_start_scan',
      description: 'Start a Qodana (JetBrains) static analysis scan on a project directory in native mode. Returns scan_id immediately; polls via qodana_findings. Idempotent: if a scan is already running, its scan_id is returned with already_running: true.',
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
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const args = request.params.arguments ?? {};
  if (request.params.name === 'qodana_start_scan') return startScan(args);
  if (request.params.name === 'qodana_findings') return getFindings(args);
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
