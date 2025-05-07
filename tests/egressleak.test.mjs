import test from "node:test";
import assert from "node:assert/strict";
import { isSyntheticEmail, isLoopbackHost, redactSensitive } from "../src/analyzer.mjs";

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

test("3. redacts emails, tokens, and OS home paths while preserving loopback", () => {
  const raw = "curl -A 'bot (ceo@ corp.ai)' http://127.0.0.1:3000 https://198.51.100.7/x?e=ceo@corp.ai /Users/prince/secret";
  const safe = redactSensitive(raw);
  assert.ok(safe.includes("127.0.0.1:3000"), "Should preserve loopback IP");
  assert.ok(safe.includes("<REDACTED_IP>"), "Should redact public IP");
  assert.ok(safe.includes("<REDACTED_EMAIL>@corp.ai"), "Should redact email local part");
  assert.ok(safe.includes("/Users/<USER>/secret"), "Should redact local username");
});
