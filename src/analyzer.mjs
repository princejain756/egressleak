import fs from "node:fs";

export const RULE_META = {
  EGL001: {
    id: "EGL001",
    plane: "identity",
    severity: "CRITICAL",
    title: "OAuth Account Email Auto-Injected into LLM Context (#55743 / #107757)"
  },
  EGL002: {
    id: "EGL002",
    plane: "identity",
    severity: "HIGH",
    title: "Hardware & Telemetry Tracking IDs Active Without Telemetry Opt-Out"
  },
  EGL003: {
    id: "EGL003",
    plane: "identity",
    severity: "HIGH",
    title: "Remote SSH or Network-Tunneled MCP Server Configured"
  },
  EGL004: {
    id: "EGL004",
    plane: "identity",
    severity: "MEDIUM",
    title: "Personal Email or Phone Hardcoded in Global Agent Instructions / Git Config"
  },
  EGL007: {
    id: "EGL007",
    plane: "egress",
    severity: "CRITICAL",
    title: "Email or Operator Identity Sent in Outbound User-Agent / HTTP Header (#107757)"
  },
  EGL008: {
    id: "EGL008",
    plane: "egress",
    severity: "CRITICAL",
    title: "Email or Personal Identifier Leaked in Outbound URL Query / Payload"
  },
  EGL011: {
    id: "EGL011",
    plane: "egress",
    severity: "HIGH",
    title: "External Third-Party Domain Contacted via Agent Tool Call"
  },
  EGL014: {
    id: "EGL014",
    plane: "egress",
    severity: "INFO",
    title: "Loopback / Localhost Dev Request Separated from External Egress"
  }
};

const SEVERITY_PENALTY = { CRITICAL: 25, HIGH: 12, MEDIUM: 6, LOW: 2, INFO: 0 };

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

    findings.push({
      ruleId: "EGL011",
      plane: "egress",
      severity: "HIGH",
      file: sourceFile,
      detail: `External outbound request to ${host} via ${toolName}`,
      evidence: redactSensitive(cleanUrl.slice(0, 180))
    });
  }

  return { findings, externalDomains, loopbackCount };
}

export function computeRiskSummary(findings) {
  const ruleCounts = {};
  const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };

  for (const f of findings) {
    ruleCounts[f.ruleId] = (ruleCounts[f.ruleId] || 0) + 1;
    if (severityCounts[f.severity] !== undefined) severityCounts[f.severity]++;
  }

  let penalty = 0;
  for (const [severity, count] of Object.entries(severityCounts)) {
    penalty += Math.min(3, count) * (SEVERITY_PENALTY[severity] || 0);
  }

  const score = Math.max(0, Math.min(100, 100 - penalty));
  let grade = "A";
  if (score < 45) grade = "F";
  else if (score < 60) grade = "D";
  else if (score < 75) grade = "C";
  else if (score < 90) grade = "B";

  return { score, grade, ruleCounts, severityCounts };
}