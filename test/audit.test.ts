import { test } from "node:test"
import assert from "node:assert/strict"
import { appendAudit, type AuditEvent } from "../src/audit.ts"
import { mkdtempSync, readFileSync, existsSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

test("appendAudit writes one JSON line per event with whitelisted fields only", () => {
  const dir = mkdtempSync(join(tmpdir(), "guard-audit-"))
  const ev: AuditEvent = {
    ts: new Date().toISOString(),
    kind: "tool.before",
    tool: "write",
    categories: ["api-key", "credential"],
    count: 2,
    action: "redacted",
  }
  appendAudit(dir, ev)
  appendAudit(dir, { ...ev, kind: "shell", tool: undefined, action: "blocked" })

  const file = join(dir, "guard-audit.jsonl")
  assert.ok(existsSync(file))
  const lines = readFileSync(file, "utf8").trim().split("\n")
  assert.equal(lines.length, 2)

  const parsed = JSON.parse(lines[0])
  const keys = Object.keys(parsed).sort()
  assert.deepEqual(keys, ["action", "categories", "count", "kind", "tool", "ts"])
  assert.equal(parsed.count, 2)
  assert.equal(parsed.action, "redacted")

  const second = JSON.parse(lines[1])
  assert.equal(second.kind, "shell")
  assert.ok(!("tool" in second))
  rmSync(dir, { recursive: true, force: true })
})

test("audit event schema never carries raw secret text", () => {
  const dir = mkdtempSync(join(tmpdir(), "guard-audit-"))
  appendAudit(dir, {
    ts: new Date().toISOString(),
    kind: "prompt",
    categories: ["api-key"],
    count: 1,
    action: "redacted",
  })
  const content = readFileSync(join(dir, "guard-audit.jsonl"), "utf8")
  assert.ok(!content.includes("sk-"))
  assert.ok(!content.includes("value"))
  rmSync(dir, { recursive: true, force: true })
})

test("appendAudit does not throw on unwritable dir (fails silent, never crashes plugin)", () => {
  assert.doesNotThrow(() =>
    appendAudit("Z:\\nonexistent\\guard\\dir", {
      ts: new Date().toISOString(),
      kind: "prompt",
      categories: ["api-key"],
      count: 1,
      action: "redacted",
    }),
  )
})
