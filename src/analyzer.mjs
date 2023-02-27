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
