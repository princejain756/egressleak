#!/usr/bin/env node
import {
  RULE_META,
  auditAgentEgress,
  generatePreToolUseHook,
  getDemoResult
} from "../src/analyzer.mjs";

const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const GREEN = "\x1b[32m";
const CYAN = "\x1b[36m";
const MAGENTA = "\x1b[35m";

function printHelp() {
  console.log(`
${BOLD}egressleak${RESET} v0.1.0 - Agent Outbound Egress, User-Agent Email & Context PII Auditor

Usage:
  npx egressleak [options]

Options:
  --claude-dir <path>      Custom ~/.claude directory path
  --codex-dir <path>       Custom ~/.codex directory path
  --claude-json <path>     Custom ~/.claude.json file path
  --dir <path>             Scan a specific folder of .jsonl transcripts
  --emit-hook              Output deterministic PreToolUse guardrail hook + settings.json
  --json                   Output structured JSON report
  --fail-on <severity>     Exit 1 if findings >= severity (CRITICAL, HIGH, MEDIUM, LOW)
  --demo                   Render benchmarked 153-session corpus audit output
  -h, --help               Show help
  -v, --version            Show version
`);
}

function parseArgs(argv) {
  const opts = {
    claudeDir: null,
    codexDir: null,
    claudeJsonPath: undefined,
    customDir: null,
    emitHook: false,
    json: false,
    failOn: null,
    demo: false,
    help: false,
    version: false
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-h" || a === "--help") opts.help = true;
    else if (a === "-v" || a === "--version") opts.version = true;
    else if (a === "--demo") opts.demo = true;
    else if (a === "--json") opts.json = true;
    else if (a === "--emit-hook") opts.emitHook = true;
    else if (a === "--claude-dir") opts.claudeDir = argv[++i];
    else if (a === "--codex-dir") opts.codexDir = argv[++i];
    else if (a === "--claude-json") opts.claudeJsonPath = argv[++i];
    else if (a === "--dir") opts.customDir = argv[++i];
    else if (a === "--fail-on") opts.failOn = String(argv[++i] || "").toUpperCase();
  }
  return opts;
}

function severityColor(sev) {
  if (sev === "CRITICAL") return `${BOLD}${RED}`;
  if (sev === "HIGH") return RED;
  if (sev === "MEDIUM") return YELLOW;
  if (sev === "LOW") return CYAN;
  return DIM;
}

function renderReport(res) {
  const gradeColor =
    res.grade === "A" ? GREEN : res.grade === "B" ? CYAN : res.grade === "C" ? YELLOW : RED;

  console.log(`\n${BOLD}${CYAN}egressleak v0.1.0${RESET} ${DIM}| Agent Outbound Egress & Context PII Audit${RESET}`);
  console.log(`${DIM}${"=".repeat(74)}${RESET}`);
  console.log(
    `Sessions Scanned: ${BOLD}${res.sessionsScanned}${RESET}   ` +
      `Deduplicated Tool Calls: ${BOLD}${res.deduplicatedToolCalls}${RESET}   ` +
      `Privacy Score: ${BOLD}${gradeColor}${res.score}/100 (Grade ${res.grade})${RESET}`
  );
  console.log(
    `Severities:       ` +
      `${BOLD}${RED}CRITICAL: ${res.severityCounts.CRITICAL}${RESET}  ` +
      `${RED}HIGH: ${res.severityCounts.HIGH}${RESET}  ` +
      `${YELLOW}MEDIUM: ${res.severityCounts.MEDIUM}${RESET}  ` +
      `${CYAN}LOW: ${res.severityCounts.LOW}${RESET}  ` +
      `${DIM}INFO: ${res.severityCounts.INFO}${RESET}`
  );
  console.log(`${DIM}${"-".repeat(74)}${RESET}`);

  const m = res.metrics;
  console.log(`${BOLD}${MAGENTA}[Plane 1] Context Identity, Telemetry & Tunnel Surface${RESET}`);
  console.log(
    `  * OAuth Email Auto-Inject (#55743): ${
      m.hasOauthEmail ? `${RED}ACTIVE in ~/.claude.json${RESET}` : `${GREEN}Not present in ~/.claude.json${RESET}`
    }`
  );
  console.log(
    `  * Hardware & Statsig Telemetry IDs: ${
      m.hasHardwareIds ? `${RED}ACTIVE (userID + machineID, telemetry enabled)${RESET}` : `${GREEN}Opted out / clean${RESET}`
    }`
  );
  console.log(
    `  * Remote SSH / Network MCP Tunnels: ${
      m.remoteMcpCount > 0 ? `${RED}${m.remoteMcpCount} remote MCP server(s) configured${RESET}` : `${GREEN}0 remote MCP tunnels${RESET}`
    }`
  );
  console.log(
    `  * OS Username Path (/Users/<USER>): ${YELLOW}${m.sessionsWithHomePath}/${res.sessionsScanned} sessions${RESET}`
  );

  console.log(`\n${BOLD}${MAGENTA}[Plane 2] Outbound HTTP Egress & Transcript PII Replay${RESET}`);
  const extDomainsStr =
    m.topExternalDomains.length > 0
      ? m.topExternalDomains.map(([d, c]) => `${d} (${c})`).join(", ")
      : "none";
  console.log(
    `  * External HTTP Egress Calls:       ${
      m.externalEgressCalls > 0
        ? `${RED}${m.externalEgressCalls} call(s) across ${m.externalDomainCount} domain(s)${RESET} [${extDomainsStr}]`
        : `${GREEN}0 external HTTP calls${RESET}`
    }`
  );
  console.log(
    `  * Loopback Dev Traffic Separated:   ${CYAN}${m.loopbackCalls} call(s) to 127.0.0.1/localhost (EGL014 false-positive guard)${RESET}`
  );
  const emailDomainsStr =
    m.topEmailDomains.length > 0
      ? m.topEmailDomains.map(([d, c]) => `${d} (${c})`).join(", ")
      : "none";
  console.log(
    `  * Real PII Emails in Transcripts:   ${
      m.totalRealEmails > 0
        ? `${YELLOW}${m.totalRealEmails} hit(s) in ${m.sessionsWithRealEmail} sessions across ${m.realEmailDomainCount} domains${RESET} [${emailDomainsStr}]`
        : `${GREEN}0 real email hits${RESET}`
    }`
  );
  console.log(
    `  * Synthetic AI Trailer Emails:      ${CYAN}${m.totalSyntheticEmails} filtered (noreply@anthropic.com / example.com)${RESET}`
  );

  console.log(`\n${BOLD}Rule Breakdown:${RESET}`);
  const sortedRules = Object.entries(res.ruleCounts).sort((a, b) => {
    const order = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
    const ma = RULE_META[a[0]] || { severity: "INFO" };
    const mb = RULE_META[b[0]] || { severity: "INFO" };
    return (order[mb.severity] || 0) - (order[ma.severity] || 0) || b[1] - a[1];
  });

  for (const [ruleId, count] of sortedRules) {
    const meta = RULE_META[ruleId];
    if (!meta) continue;
    const col = severityColor(meta.severity);
    console.log(
      `  ${col}[${meta.severity.padEnd(8)}]${RESET} ${BOLD}${ruleId}${RESET} (${String(count).padStart(2)}x) ${meta.title}`
    );
  }

  const notable = [
    ...res.findings.filter((f) => f.severity === "CRITICAL"),
    ...res.findings.filter((f) => f.severity === "HIGH")
  ].slice(0, 6);
  if (notable.length > 0) {
    console.log(`\n${BOLD}Top Redacted Evidence Samples:${RESET}`);
    for (const f of notable) {
      const col = severityColor(f.severity);
      console.log(`  ${col}* ${f.ruleId}${RESET}: ${f.detail}`);
    }
  }

  console.log(`\n${DIM}Run 'npx egressleak --emit-hook' to generate a deterministic PreToolUse guardrail against #107757 leaks.${RESET}\n`);
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    printHelp();
    process.exit(0);
  }
  if (opts.version) {
    console.log("0.1.0");
    process.exit(0);
  }
  if (opts.emitHook) {
    const { hookScript, settingsSnippet } = generatePreToolUseHook();
    if (opts.json) {
      console.log(JSON.stringify({ hookScript, settingsSnippet }, null, 2));
    } else {
      console.log(`${BOLD}${CYAN}# 1. Save to ~/.claude/hooks/egress-guard-hook.mjs:${RESET}\n`);
      console.log(hookScript);
      console.log(`${BOLD}${CYAN}# 2. Merge into ~/.claude/settings.json:${RESET}\n`);
      console.log(JSON.stringify(settingsSnippet, null, 2));
    }
    process.exit(0);
  }

  const result = opts.demo
    ? getDemoResult()
    : auditAgentEgress({
        claudeDir: opts.claudeDir,
        codexDir: opts.codexDir,
        claudeJsonPath: opts.claudeJsonPath,
        customDir: opts.customDir
      });

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    renderReport(result);
  }

  if (opts.failOn) {
    const ranks = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    const threshold = ranks[opts.failOn] || 4;
    const triggered = result.findings.some((f) => (ranks[f.severity] || 0) >= threshold);
    if (triggered) process.exit(1);
  }
}

main();
