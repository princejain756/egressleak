import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { isSyntheticEmail, isLoopbackHost, redactSensitive, scanStaticIdentitySurface } from "../src/analyzer.mjs";

test("1. filters synthetic AI trailer emails (noreply@anthropic.com) while flagging real PII emails", () => {
  assert.equal(isSyntheticEmail("noreply@anthropic.com"), true);
  assert.equal(isSyntheticEmail("user@example.com"), true);
  assert.equal(isSyntheticEmail("founder@gmail.com"), false);
  assert.equal(isSyntheticEmail("ops@sarojjain.com"), false);
});

test("2. classifies loopback hosts so dev-server traffic is not reported as egress", () => {
  assert.equal(isLoopbackHost("127.0.0.1"), true);
  assert.equal(isLoopbackHost("localhost"), true);
  assert.equal(isLoopbackHost("api.stripe.com"), false);
});

test("3. detects Plane 1 oauthAccount.emailAddress (#55743), hardware tracking IDs, and SSH MCP tunnels", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "egressleak-static-"));
  const cjPath = path.join(tmpDir, ".claude.json");
  const settingsPath = path.join(tmpDir, "settings.json");

  fs.writeFileSync(
    cjPath,
    JSON.stringify({
      userID: "uid-123",
      machineID: "mid-456",
      oauthAccount: { emailAddress: "alice@startup.io" },
      mcpServers: {
        prodVps: {
          command: "ssh",
          args: ["root@203.0.113.42", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/root"]
        }
      }
    })
  );
  fs.writeFileSync(settingsPath, JSON.stringify({ env: {} }));

  const res = scanStaticIdentitySurface({
    claudeJsonPath: cjPath,
    claudeSettingsPath: settingsPath,
    instructionPaths: []
  });

  const ids = res.findings.map((f) => f.ruleId);
  assert.ok(ids.includes("EGL001"), "Should detect EGL001 oauthAccount.emailAddress");
  assert.ok(ids.includes("EGL002"), "Should detect EGL002 hardware telemetry IDs");
  assert.ok(ids.includes("EGL003"), "Should detect EGL003 remote SSH MCP tunnel");
  assert.ok(
    res.findings.every((f) => !f.detail.includes("203.0.113.42") && !f.detail.includes("alice@startup.io")),
    "Should redact IP and email local part"
  );

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("4. redacts emails, tokens, public IPs, and OS home paths while preserving loopback", () => {
  const raw = "curl -A 'bot (ceo@ corp.ai)' http://127.0.0.1:3000 https://198.51.100.7/x?e=ceo@corp.ai /Users/prince/secret";
  const safe = redactSensitive(raw);
  assert.ok(safe.includes("127.0.0.1:3000"), "Should preserve loopback IP");
  assert.ok(safe.includes("<REDACTED_IP>"), "Should redact public IP");
  assert.ok(safe.includes("<REDACTED_EMAIL>@corp.ai"), "Should redact email local part");
  assert.ok(safe.includes("/Users/<USER>/secret"), "Should redact local username");
});
