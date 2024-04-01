import fs from "node:fs";
import path from "node:path";
import os from "node:os";

export const RULE_META = {
  EGL001: {
    id: "EGL001",
    plane: "identity",
    severity: "CRITICAL",
    title: "OAuth Account Email Auto-Injected into LLM Context (#55743 / #107757)",
    points: 25
  },
  EGL002: {
    id: "EGL002",
    plane: "identity",
    severity: "HIGH",
    title: "Hardware & Telemetry Tracking IDs Active Without Telemetry Opt-Out",
    points: 12
  },
  EGL003: {
    id: "EGL003",
    plane: "identity",
    severity: "HIGH",
    title: "Remote SSH or Network-Tunneled MCP Server Configured",
    points: 15
  },
  EGL004: {
    id: "EGL004",
    plane: "identity",
    severity: "MEDIUM",
    title: "Personal Email or Phone Hardcoded in Global Agent Instructions / Git Config",
    points: 8
  },
  EGL005: {
    id: "EGL005",
    plane: "identity",
    severity: "MEDIUM",
    title: "OS Username & Local Workspace Paths Exposed Across Session Contexts",
    points: 6
  },
  EGL006: {
    id: "EGL006",
    plane: "identity",
    severity: "LOW",
    title: "Synthetic AI Trailer Emails Filtered from PII Count (False-Positive Guard)",
    points: 0
  },
  EGL007: {
    id: "EGL007",
    plane: "egress",
    severity: "CRITICAL",
    title: "Email or Operator Identity Sent in Outbound User-Agent / HTTP Header (#107757)",
    points: 30
  },
  EGL008: {
    id: "EGL008",
    plane: "egress",
    severity: "CRITICAL",
    title: "Email or Personal Identifier Leaked in Outbound URL Query / Payload",
    points: 25
  },
  EGL009: {
    id: "EGL009",
    plane: "egress",
    severity: "CRITICAL",
    title: "Bearer Token, API Key, or Secret Passed in Outbound HTTP Request",
    points: 30
  },
  EGL010: {
    id: "EGL010",
    plane: "egress",
    severity: "HIGH",
    title: "Local File or Environment Variable Exfiltrated via Outbound HTTP POST",
    points: 20
  },
  EGL011: {
    id: "EGL011",
    plane: "egress",
    severity: "HIGH",
    title: "External Third-Party Domain Contacted via Agent Tool Call",
    points: 8
  },
  EGL012: {
    id: "EGL012",
    plane: "egress",
    severity: "MEDIUM",
    title: "Sensitive Path, Email, or Internal Hostname in WebSearch Query",
    points: 12
  },
  EGL013: {
    id: "EGL013",
    plane: "egress",
    severity: "MEDIUM",
    title: "Real Personal or Customer PII Persisted in Unencrypted Session Transcripts",
    points: 10
  },
  EGL014: {
    id: "EGL014",
    plane: "egress",
    severity: "INFO",
    title: "Loopback / Localhost Dev Request Separated from External Egress",
    points: 0
  }
};

const SYNTHETIC_EMAIL_DOMAINS = new Set([
  "anthropic.com",
  "example.com",
  "example.org",
  "example.net"
]);

const SYNTHETIC_LOCAL_PARTS = new Set(["noreply", "no-reply", "donotreply", "test", "user", "admin"]);

export function isSyntheticEmail(email) {
  const clean = String(email || "").trim().toLowerCase();
  const parts = clean.split("@");
  if (parts.length !== 2) return true;
  const [local, domain] = parts;
  if (SYNTHETIC_EMAIL_DOMAINS.has(domain)) return true;
  if (SYNTHETIC_LOCAL_PARTS.has(local)) return true;
  return false;
}

export function isLoopbackHost(hostname) {
  const h = String(hostname || "").trim().toLowerCase();
  return h === "localhost" || h === "127.0.0.1" || h === "0.0.0.0" || h === "::1" || h === "[::1]";
}

export function redactSensitive(input) {
  if (!input) return "";
  return String(input)
    .replace(/\b([a-zA-Z0-9._%+-]{1,40})@([a-zA-Z0-9.-]{1,40}\.[a-zA-Z]{2,12})\b/g, (_m, local, dom) => {
      if (isSyntheticEmail(`${local}@${dom}`)) return `${local}@${dom}`;
      return `<REDACTED_EMAIL>@${dom.toLowerCase()}`;
    })
    .replace(/\b(sk-[a-zA-Z0-9_-]{8,}|ghp_[a-zA-Z0-9]{10,}|AIza[0-9A-Za-z-_]{12,})\b/g, "<REDACTED_TOKEN>")
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/-]+=*/gi, "$1<REDACTED_TOKEN>")
    .replace(/\b(?!127\.0\.0\.1\b|0\.0\.0\.0\b)(?:\d{1,3}\.){3}\d{1,3}\b/g, "<REDACTED_IP>")
    .replace(/\/Users\/[a-zA-Z0-9._-]+/g, "/Users/<USER>")
    .replace(/\/home\/[a-zA-Z0-9._-]+/g, "/home/<USER>");
}

const EMAIL_RE =
  /\b([a-zA-Z0-9._%+-]{1,40})@([a-zA-Z0-9.-]{1,40}\.(?:com|org|net|io|dev|ai|co|in|edu|gov|sh|app|me|uk|de|fr|jp))\b/gi;
const URL_RE = /https?:\/\/[a-zA-Z0-9._~:/?#\[\]@!$&()*+,;=%-]+/gi;
const SECRET_TOKEN_RE = /\b(sk-[a-zA-Z0-9_-]{12,}|ghp_[a-zA-Z0-9]{16,}|AIza[0-9A-Za-z-_]{20,}|xox[baprs]-[a-zA-Z0-9-]{12,})\b/;

function realEmailsIn(text) {
  return [...text.matchAll(EMAIL_RE)].map((m) => `${m[1]}@${m[2]}`).filter((e) => !isSyntheticEmail(e));
}

export function scanStaticIdentitySurface({ claudeJsonPath, claudeSettingsPath, gitConfigPath, instructionPaths = [] }) {
  const findings = [];
  const stats = {
    hasOauthEmail: false,
    hasHardwareIds: false,
    telemetryDisabled: false,
    remoteMcpCount: 0,
    instructionEmailCount: 0
  };

  if (claudeSettingsPath && fs.existsSync(claudeSettingsPath)) {
    try {
      const settingsObj = JSON.parse(fs.readFileSync(claudeSettingsPath, "utf8"));
      const env = settingsObj?.env || {};
      if (env.DISABLE_TELEMETRY === "1" || env.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC === "1") {
        stats.telemetryDisabled = true;
      }
    } catch {
      // ignore malformed JSON
    }
  }

  if (claudeJsonPath && fs.existsSync(claudeJsonPath)) {
    try {
      const cj = JSON.parse(fs.readFileSync(claudeJsonPath, "utf8"));
      const oauthEmail = cj?.oauthAccount?.emailAddress;
      if (oauthEmail) {
        stats.hasOauthEmail = true;
        findings.push({
          ruleId: "EGL001",
          plane: "identity",
          severity: "CRITICAL",
          file: claudeJsonPath,
          detail: `oauthAccount.emailAddress (${redactSensitive(oauthEmail)}) is stored in ~/.claude.json and auto-injected into session context (#55743 / #107757)`,
          evidence: redactSensitive(`oauthAccount.emailAddress = "${oauthEmail}"`)
        });
      }

      if ((cj?.userID || cj?.machineID) && !stats.telemetryDisabled) {
        stats.hasHardwareIds = true;
        const idParts = [];
        if (cj.userID) idParts.push("userID");
        if (cj.machineID) idParts.push("machineID");
        findings.push({
          ruleId: "EGL002",
          plane: "identity",
          severity: "HIGH",
          file: claudeJsonPath,
          detail: `Persistent tracking identifiers (${idParts.join(", ")}) active in ~/.claude.json without DISABLE_TELEMETRY=1`,
          evidence: `Active keys: ${idParts.join(", ")}`
        });
      }

      for (const [name, cfg] of Object.entries(cj?.mcpServers || {})) {
        const cmd = String(cfg?.command || "");
        const args = Array.isArray(cfg?.args) ? cfg.args.map(String) : [];
        const url = String(cfg?.url || "");
        const joined = `${cmd} ${args.join(" ")} ${url}`.trim();
        if (/\bssh\b/i.test(cmd) || /^https?:\/\//i.test(url) || args.some((a) => /^https?:\/\//i.test(a))) {
          stats.remoteMcpCount++;
          findings.push({
            ruleId: "EGL003",
            plane: "identity",
            severity: "HIGH",
            file: claudeJsonPath,
            detail: `Remote MCP server "${name}" transmits tool arguments over SSH or network (${redactSensitive(joined)})`,
            evidence: redactSensitive(`${name}: ${joined}`)
          });
        }
      }
    } catch {
      // ignore unreadable state
    }
  }

  const allInstructionFiles = [...instructionPaths];
  if (gitConfigPath && fs.existsSync(gitConfigPath)) allInstructionFiles.push(gitConfigPath);

  for (const p of allInstructionFiles) {
    if (!p || !fs.existsSync(p)) continue;
    try {
      const realEmails = realEmailsIn(fs.readFileSync(p, "utf8"));
      if (realEmails.length > 0) {
        stats.instructionEmailCount += realEmails.length;
        const uniqueRedacted = [...new Set(realEmails.map((e) => redactSensitive(e)))];
        findings.push({
          ruleId: "EGL004",
          plane: "identity",
          severity: "MEDIUM",
          file: p,
          detail: `${realEmails.length} personal/work email reference(s) (${uniqueRedacted.slice(0, 3).join(", ")}) loaded into agent context`,
          evidence: uniqueRedacted.slice(0, 3).join(", ")
        });
      }
    } catch {
      // ignore unreadable instruction file
    }
  }

  return { findings, stats };
}

export function analyzeOutboundCall({ toolName, rawInput, sourceFile }) {
  const findings = [];
  const externalDomains = [];
  let loopbackCount = 0;

  const text = String(rawInput || "");
  if (!text) return { findings, externalDomains, loopbackCount };

  const hasUserAgentFlag =
    /User-Agent\s*[:=]/i.test(text) ||
    /\bcurl\b[^\n]*?\s(?:-A|--user-agent)\s+/i.test(text) ||
    /headers\s*=\s*\{[^}]*['"]User-Agent['"]/i.test(text);

  if (hasUserAgentFlag) {
    const emails = realEmailsIn(text);
    if (emails.length > 0) {
      findings.push({
        ruleId: "EGL007",
        plane: "egress",
        severity: "CRITICAL",
        file: sourceFile,
        detail: `Outbound ${toolName} sets User-Agent header containing real email (${redactSensitive(emails[0])})`,
        evidence: redactSensitive(text.slice(0, 220))
      });
    }
  }

  for (const rawUrl of text.match(URL_RE) || []) {
    const cleanUrl = rawUrl.replace(/[\\"')\]}>.,;]+$/, "");
    let parsed;
    try {
      parsed = new URL(cleanUrl);
    } catch {
      continue;
    }

    const host = parsed.hostname.toLowerCase();
    if (isLoopbackHost(host)) {
      loopbackCount++;
      findings.push({
        ruleId: "EGL014",
        plane: "egress",
        severity: "INFO",
        file: sourceFile,
        detail: `Loopback HTTP request to ${host}${parsed.port ? ":" + parsed.port : ""} separated from external egress`,
        evidence: redactSensitive(cleanUrl.slice(0, 160))
      });
      continue;
    }

    externalDomains.push(host);

    const urlEmails = [...cleanUrl.matchAll(EMAIL_RE)].map((m) => `${m[1]}@${m[2]}`).filter((e) => !isSyntheticEmail(e));
    if (urlEmails.length > 0 || /[?&](?:authuser|email|user_email|contact)=([^&]+)/i.test(cleanUrl)) {
      findings.push({
        ruleId: "EGL008",
        plane: "egress",
        severity: "CRITICAL",
        file: sourceFile,
        detail: `Outbound URL to ${host} leaks email/identity in query parameters (${redactSensitive(cleanUrl)})`,
        evidence: redactSensitive(cleanUrl.slice(0, 200))
      });
    }

    // Check if URL query leaks a token/key
    if (/[?&](?:api_key|apikey|token|access_token|secret|key)=(?:[a-zA-Z0-9._-]{8,})/i.test(cleanUrl)) {
      findings.push({
        ruleId: "EGL009",
        plane: "egress",
        severity: "CRITICAL",
        file: sourceFile,
        detail: `Outbound URL to ${host} passes API key or token in query string`,
        evidence: redactSensitive(cleanUrl.slice(0, 200))
      });
    }

    findings.push({
      ruleId: "EGL011",
      plane: "egress",
      severity: "HIGH",
      file: sourceFile,
      detail: `External outbound request to ${host} via ${toolName}`,
      evidence: redactSensitive(cleanUrl.slice(0, 180))
    });
  }

  if (
    /Authorization\s*:\s*Bearer\s+[^\s"']+/i.test(text) ||
    /x-api-key\s*:\s*[^\s"']+/i.test(text) ||
    SECRET_TOKEN_RE.test(text)
  ) {
    if (/\b(curl|wget|fetch|http|https|requests\.)\b/i.test(text) || toolName === "WebFetch") {
      findings.push({
        ruleId: "EGL009",
        plane: "egress",
        severity: "CRITICAL",
        file: sourceFile,
        detail: `Outbound ${toolName} includes Authorization Bearer header or secret API token`,
        evidence: redactSensitive(text.slice(0, 200))
      });
    }
  }

  if (
    /\bcurl\b[^\n]*?\s(?:-d|--data|--data-binary|--data-raw|-F|--form)\s+(?:@|\$[A-Za-z_])/i.test(text) ||
    /\bcurl\b[^\n]*?(?:\.env|id_rsa|credentials|\.claude\.json)/i.test(text)
  ) {
    findings.push({
      ruleId: "EGL010",
      plane: "egress",
      severity: "HIGH",
      file: sourceFile,
      detail: `Outbound ${toolName} uploads local file or interpolated environment variable via HTTP POST`,
      evidence: redactSensitive(text.slice(0, 200))
    });
  }

  if (toolName === "WebSearch" || /"query"\s*:/.test(text)) {
    const queryEmails = realEmailsIn(text);
    if (
      queryEmails.length > 0 ||
      /\/Users\/[a-zA-Z0-9._-]+|\/home\/[a-zA-Z0-9._-]+/.test(text) ||
      SECRET_TOKEN_RE.test(text)
    ) {
      findings.push({
        ruleId: "EGL012",
        plane: "egress",
        severity: "MEDIUM",
        file: sourceFile,
        detail: `Search query leaks email, local username path, or token to search provider`,
        evidence: redactSensitive(text.slice(0, 200))
      });
    }
  }

  return { findings, externalDomains, loopbackCount };
}

export function scanTranscriptFile(filePath, seenCallIds = new Set()) {
  const findings = [];
  const externalDomains = new Map();
  const realEmailDomains = new Map();
  let syntheticEmailCount = 0;
  let realEmailCount = 0;
  let loopbackUrlCount = 0;
  let deduplicatedToolCalls = 0;
  let hasHomePathExposure = false;

  const content = fs.readFileSync(filePath, "utf8");

  for (const line of content.split("\n")) {
    if (!line.trim()) continue;

    // Context / PII pass runs on every ordinary line, skipping huge base64 blobs
    if (line.length < 100000) {
      if (!hasHomePathExposure && (/\/Users\/[a-zA-Z0-9._-]+/.test(line) || /\/home\/[a-zA-Z0-9._-]+/.test(line))) {
        hasHomePathExposure = true;
      }
      if (line.includes("@")) {
        for (const m of line.matchAll(EMAIL_RE)) {
          const full = `${m[1]}@${m[2]}`;
          const dom = m[2].toLowerCase();
          if (isSyntheticEmail(full)) {
            syntheticEmailCount++;
          } else {
            realEmailCount++;
            realEmailDomains.set(dom, (realEmailDomains.get(dom) || 0) + 1);
          }
        }
      }
    }

    if (!line.includes("tool_use") && !line.includes("function_call")) continue;

    let obj;
    try {
      obj = JSON.parse(line);
    } catch {
      continue;
    }

    // Streaming writers repeat the same tool_use.id across rows, so dedupe on it
    for (const item of obj?.message?.content || []) {
      if (item?.type !== "tool_use") continue;
      const id = item.id || `${filePath}:${deduplicatedToolCalls}`;
      if (seenCallIds.has(id)) continue;
      seenCallIds.add(id);
      deduplicatedToolCalls++;

      const toolName = String(item.name || "unknown");
      const rawInput = JSON.stringify(item.input || {}).slice(0, 8000);
      if (
        toolName === "Bash" ||
        toolName === "WebFetch" ||
        toolName === "WebSearch" ||
        toolName.startsWith("mcp__") ||
        rawInput.includes("http")
      ) {
        const res = analyzeOutboundCall({ toolName, rawInput, sourceFile: filePath });
        findings.push(...res.findings);
        loopbackUrlCount += res.loopbackCount;
        for (const d of res.externalDomains) {
          externalDomains.set(d, (externalDomains.get(d) || 0) + 1);
        }
      }
    }

    // Codex CLI stores exec calls as response_item / function_call envelopes
    if (obj?.type === "response_item" && obj?.payload?.type === "function_call") {
      const id = obj.payload.call_id || `${filePath}:${deduplicatedToolCalls}`;
      if (seenCallIds.has(id)) continue;
      seenCallIds.add(id);
      deduplicatedToolCalls++;

      const toolName = String(obj.payload.name || "exec_command");
      const rawInput = String(obj.payload.arguments || "").slice(0, 8000);
      if (rawInput.includes("http") || /\b(curl|wget|fetch|User-Agent)\b/i.test(rawInput)) {
        const res = analyzeOutboundCall({ toolName, rawInput, sourceFile: filePath });
        findings.push(...res.findings);
        loopbackUrlCount += res.loopbackCount;
        for (const d of res.externalDomains) {
          externalDomains.set(d, (externalDomains.get(d) || 0) + 1);
        }
      }
    }
  }

  return {
    findings,
    externalDomains,
    realEmailDomains,
    syntheticEmailCount,
    realEmailCount,
    loopbackUrlCount,
    deduplicatedToolCalls,
    hasHomePathExposure
  };
}

function walkJsonl(dir, out = []) {
  if (!dir || !fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walkJsonl(full, out);
    else if (entry.name.endsWith(".jsonl")) out.push(full);
  }
  return out;
}

export function discoverDefaultTargets(homeDir = os.homedir()) {
  const claudeDir = path.join(homeDir, ".claude");
  const codexDir = path.join(homeDir, ".codex");
  return {
    claudeJsonPath: path.join(homeDir, ".claude.json"),
    claudeSettingsPath: path.join(claudeDir, "settings.json"),
    gitConfigPath: path.join(homeDir, ".gitconfig"),
    instructionPaths: [path.join(claudeDir, "CLAUDE.md"), path.join(homeDir, ".agents", "AGENTS.md")].filter((p) =>
      fs.existsSync(p)
    ),
    transcriptFiles: [
      ...walkJsonl(path.join(claudeDir, "projects")),
      ...walkJsonl(path.join(codexDir, "sessions"))
    ]
  };
}

export function auditAgentEgress(options = {}) {
  const homeDir = options.homeDir || os.homedir();
  const defaults = discoverDefaultTargets(homeDir);

  const claudeJsonPath = options.claudeJsonPath ?? defaults.claudeJsonPath;
  const claudeSettingsPath = options.claudeSettingsPath ?? defaults.claudeSettingsPath;
  const gitConfigPath = options.gitConfigPath ?? defaults.gitConfigPath;
  const instructionPaths = options.instructionPaths ?? defaults.instructionPaths;

  let transcriptFiles = options.transcriptFiles;
  if (!transcriptFiles) {
    if (options.customDir) {
      transcriptFiles = walkJsonl(options.customDir);
    } else {
      const customList = [];
      if (options.claudeDir) walkJsonl(path.join(options.claudeDir, "projects"), customList);
      if (options.codexDir) walkJsonl(path.join(options.codexDir, "sessions"), customList);
      transcriptFiles = customList.length > 0 ? customList : defaults.transcriptFiles;
    }
  }

  const staticResult = scanStaticIdentitySurface({
    claudeJsonPath,
    claudeSettingsPath,
    gitConfigPath,
    instructionPaths
  });

  const allFindings = [...staticResult.findings];
  const seenCallIds = new Set();
  const externalDomains = new Map();
  const realEmailDomains = new Map();

  let totalSyntheticEmails = 0;
  let totalRealEmails = 0;
  let totalLoopbackUrls = 0;
  let totalDeduplicatedCalls = 0;
  let sessionsWithHomePath = 0;

  for (const tf of transcriptFiles) {
    const res = scanTranscriptFile(tf, seenCallIds);
    allFindings.push(...res.findings);
    totalSyntheticEmails += res.syntheticEmailCount;
    totalRealEmails += res.realEmailCount;
    totalLoopbackUrls += res.loopbackUrlCount;
    totalDeduplicatedCalls += res.deduplicatedToolCalls;
    if (res.hasHomePathExposure) sessionsWithHomePath++;

    for (const [d, c] of res.externalDomains.entries()) {
      externalDomains.set(d, (externalDomains.get(d) || 0) + c);
    }
    for (const [d, c] of res.realEmailDomains.entries()) {
      realEmailDomains.set(d, (realEmailDomains.get(d) || 0) + c);
    }
  }

  if (sessionsWithHomePath > 0) {
    allFindings.push({
      ruleId: "EGL005",
      plane: "identity",
      severity: "MEDIUM",
      file: "session-transcripts",
      detail: `Local OS username path (/Users/<USER>) injected into ${sessionsWithHomePath}/${transcriptFiles.length} session transcripts`,
      evidence: `/Users/<USER> present in ${sessionsWithHomePath} sessions`
    });
  }

  if (totalSyntheticEmails > 0) {
    allFindings.push({
      ruleId: "EGL006",
      plane: "identity",
      severity: "LOW",
      file: "session-transcripts",
      detail: `Filtered ${totalSyntheticEmails} synthetic AI trailer email(s) (noreply@anthropic.com / example.com) so PII counts are not inflated`,
      evidence: `${totalSyntheticEmails} synthetic vs ${totalRealEmails} real email occurrences`
    });
  }

  if (totalRealEmails > 0) {
    const topDomains = [...realEmailDomains.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([d, c]) => `${d} (${c})`)
      .join(", ");
    allFindings.push({
      ruleId: "EGL013",
      plane: "egress",
      severity: "MEDIUM",
      file: "session-transcripts",
      detail: `${totalRealEmails} real personal/third-party email occurrence(s) persisted across ${realEmailDomains.size} domains in plaintext transcripts`,
      evidence: `Top domains: ${topDomains}`
    });
  }

  const summary = computeRiskSummary(allFindings);

  return {
    sessionsScanned: transcriptFiles.length,
    deduplicatedToolCalls: totalDeduplicatedCalls,
    score: summary.score,
    grade: summary.grade,
    severityCounts: summary.severityCounts,
    ruleCounts: summary.ruleCounts,
    metrics: {
      sessionsWithHomePath,
      totalRealEmails,
      totalSyntheticEmails,
      externalDomainCount: externalDomains.size,
      externalEgressCalls: [...externalDomains.values()].reduce((a, b) => a + b, 0),
      loopbackCalls: totalLoopbackUrls,
      topExternalDomains: [...externalDomains.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8),
      remoteMcpCount: staticResult.stats.remoteMcpCount,
      hasOauthEmail: staticResult.stats.hasOauthEmail,
      hasHardwareIds: staticResult.stats.hasHardwareIds
    },
    findings: allFindings
  };
}

export function generatePreToolUseHook() {
  const hookScript = `#!/usr/bin/env node
// Generated by egressleak (https://github.com/princejain756/egressleak)
// Deterministic PreToolUse guardrail against #107757 / #55743 outbound email & token leaks.
import fs from "node:fs";

const input = fs.readFileSync(0, "utf8");
let payload;
try {
  payload = JSON.parse(input);
} catch {
  process.exit(0);
}

const toolName = String(payload?.tool_name || "");
const toolInput = JSON.stringify(payload?.tool_input || {});

if (!["Bash", "WebFetch", "WebSearch"].includes(toolName)) {
  process.exit(0);
}

const EMAIL_IN_UA = /(?:User-Agent|-A|--user-agent)[^\\n]{0,120}\\b[a-zA-Z0-9._%+-]{1,40}@(?!anthropic\\.com|example\\.com)[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,12}\\b/i;
const EMAIL_IN_URL = /https?:\\/\\/[^\\s"']*?[?&](?:authuser|email|contact)=[^\\s&"']+/i;
const SECRET_IN_HTTP = /(?:curl|wget|https?:\\/\\/)[^\\n]{0,200}\\b(sk-[a-zA-Z0-9_-]{12,}|ghp_[a-zA-Z0-9]{16,}|AIza[0-9A-Za-z-_]{20,})\\b/;

if (EMAIL_IN_UA.test(toolInput) || EMAIL_IN_URL.test(toolInput) || SECRET_IN_HTTP.test(toolInput)) {
  console.error("[egressleak] BLOCKED outbound tool call containing personal email or secret token in User-Agent/URL.");
  process.exit(2);
}
`;

  const settingsSnippet = {
    env: {
      DISABLE_TELEMETRY: "1",
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1"
    },
    hooks: {
      PreToolUse: [
        {
          matcher: "Bash|WebFetch|WebSearch",
          hooks: [
            {
              type: "command",
              command: "node ~/.claude/hooks/egress-guard-hook.mjs"
            }
          ]
        }
      ]
    }
  };

  return { hookScript, settingsSnippet };
}

export function computeRiskSummary(findings) {
  const ruleCounts = {};
  const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };

  for (const f of findings) {
    ruleCounts[f.ruleId] = (ruleCounts[f.ruleId] || 0) + 1;
    if (severityCounts[f.severity] !== undefined) severityCounts[f.severity]++;
  }

  let rawPenalty = 0;
  for (const [ruleId, count] of Object.entries(ruleCounts)) {
    const meta = RULE_META[ruleId];
    if (!meta || meta.points === 0) continue;
    // Cap per-rule penalty at 2x base points so high-volume logs stay proportional
    const multiplier = Math.min(2.0, 1 + Math.log10(count) * 0.5);
    rawPenalty += Math.round(meta.points * multiplier);
  }
  const penalty = rawPenalty;

  const score = Math.max(0, Math.min(100, 100 - penalty));
  let grade = "A";
  if (score < 45) grade = "F";
  else if (score < 60) grade = "D";
  else if (score < 75) grade = "C";
  else if (score < 90) grade = "B";

  return { score, grade, ruleCounts, severityCounts };
}
