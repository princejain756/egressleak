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
