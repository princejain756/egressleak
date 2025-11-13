import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import {
  isSyntheticEmail,
  isLoopbackHost,
  redactSensitive,
  scanStaticIdentitySurface,
  analyzeOutboundCall,
  scanTranscriptFile,
  auditAgentEgress,
  generatePreToolUseHook
} from "../src/analyzer.mjs";

test("1. filters synthetic AI trailer emails (noreply@anthropic.com) while flagging real PII emails", () => {
  assert.equal(isSyntheticEmail("noreply@anthropic.com"), true);
  assert.equal(isSyntheticEmail("user@example.com"), true);
  assert.equal(isSyntheticEmail("billing@acme.com"), true);
  assert.equal(isSyntheticEmail("founder@gmail.com"), false);
  assert.equal(isSyntheticEmail("ops@sarojjain.com"), false);
});

test("2. detects #107757 User-Agent email leak (EGL007) and URL query email leak (EGL008) while separating 127.0.0.1 loopback (EGL014)", () => {
  const secCall = analyzeOutboundCall({
    toolName: "Bash",
    rawInput: JSON.stringify({
      command: 'curl -s -A "MyAgent/1.0 (founder@gmail.com)" https://data.sec.gov/api/xbrl/companyconcept/CIK0000320193/us-gaap/Assets.json'
    }),
    sourceFile: "session.jsonl"
  });

  const ruleIds = secCall.findings.map((f) => f.ruleId);
  assert.ok(ruleIds.includes("EGL007"), "Should detect EGL007 User-Agent email leak");
  assert.ok(ruleIds.includes("EGL011"), "Should detect EGL011 external domain data.sec.gov");
  assert.ok(
    secCall.findings.every((f) => !f.detail.includes("founder@gmail.com")),
    "Should redact email local part in findings"
  );

  const queryCall = analyzeOutboundCall({
    toolName: "Bash",
    rawInput: JSON.stringify({
      command: "curl https://gemini.google.com/app?authuser=dev@gmail.com && curl http://127.0.0.1:8080/health"
    }),
    sourceFile: "session.jsonl"
  });

  const qRuleIds = queryCall.findings.map((f) => f.ruleId);
  assert.ok(qRuleIds.includes("EGL008"), "Should detect EGL008 query param email leak");
  assert.ok(qRuleIds.includes("EGL014"), "Should classify 127.0.0.1 as EGL014 loopback");
  assert.equal(queryCall.loopbackCount, 1);
  assert.deepEqual(queryCall.externalDomains, ["gemini.google.com"]);
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
      oauthAccount: {
        emailAddress: "alice@startup.io"
      },
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

test("4. deduplicates streaming tool_use.id rows in JSONL transcripts", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "egressleak-jsonl-"));
  const tf = path.join(tmpDir, "session.jsonl");

  const duplicateToolCall = {
    type: "assistant",
    message: {
      content: [
        {
          type: "tool_use",
          id: "toolu_dup_99",
          name: "Bash",
          input: {
            command: 'curl -H "Authorization: Bearer sk-live-1234567890abcdef" https://api.stripe.com/v1/charges'
          }
        }
      ]
    }
  };

  const trailerLine = {
    type: "user",
    message: {
      content: "Co-Authored-By: Claude Opus <noreply@anthropic.com> and contact bob@company.io in /Users/bob/app"
    }
  };

  fs.writeFileSync(
    tf,
    [JSON.stringify(duplicateToolCall), JSON.stringify(duplicateToolCall), JSON.stringify(trailerLine)].join("\n")
  );

  const report = auditAgentEgress({
    claudeJsonPath: path.join(tmpDir, "missing.json"),
    claudeSettingsPath: path.join(tmpDir, "missing-settings.json"),
    gitConfigPath: path.join(tmpDir, "missing-git"),
    instructionPaths: [],
    transcriptFiles: [tf]
  });

  assert.equal(report.deduplicatedToolCalls, 1, "Should count toolu_dup_99 only once");
  assert.equal(report.metrics.totalSyntheticEmails, 1, "Should count noreply@anthropic.com as synthetic");
  assert.equal(report.metrics.totalRealEmails, 1, "Should count bob@company.io as real PII");
  assert.equal(report.ruleCounts.EGL009, 1, "Should flag Bearer token leak once");

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("5. redacts emails, tokens, public IPs, and OS home paths while preserving loopback and generates PreToolUse hook", () => {
  const raw = "curl -A 'bot (ceo@ corp.ai)' http://127.0.0.1:3000 https://198.51.100.7/x?e=ceo@corp.ai -H 'Bearer sk-1234567890abcdef' /Users/prince/secret";
  const safe = redactSensitive(raw);
  assert.ok(safe.includes("127.0.0.1:3000"), "Should preserve loopback IP");
  assert.ok(safe.includes("<REDACTED_IP>"), "Should redact public IP");
  assert.ok(safe.includes("<REDACTED_EMAIL>@corp.ai"), "Should redact email local part");
  assert.ok(safe.includes("<REDACTED_TOKEN>"), "Should redact secret token");
  assert.ok(safe.includes("/Users/<USER>/secret"), "Should redact local username");

  const hook = generatePreToolUseHook();
  assert.ok(hook.hookScript.includes("EMAIL_IN_UA"));
  assert.equal(hook.settingsSnippet.env.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC, "1");
});
