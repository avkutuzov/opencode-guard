import { test } from "node:test"
import assert from "node:assert/strict"
import { registerGuard } from "../src/guard.ts"
import { resolveConfig } from "../src/config.ts"

// Integration pins: scanOpts (piiEmailAllowDomains) actually reaches the
// guard.ts plumbing (tool.after scrub + outbound context scrub) — the MAJOR-1
// regression class. Spec: docs/pii-email-spec.md.

function makeCtx() {
  const handlers = new Map<string, Array<(e: unknown) => void>>()
  const reg = (name: string, fn: (e: unknown) => void) => {
    const list = handlers.get(name) ?? []
    list.push(fn)
    handlers.set(name, list)
    return Promise.resolve({ dispose: async () => {} })
  }
  const ctx = {
    location: { directory: "C:\\proj" },
    session: { hook: (name: string, fn: (e: unknown) => void) => reg("session:" + name, fn) },
    tool: { hook: (name: string, fn: (e: unknown) => void) => reg("tool:" + name, fn) },
    shell: { hook: (name: string, fn: (e: unknown) => void) => reg("shell:" + name, fn) },
  }
  const fire = (name: string, event: unknown) => {
    for (const fn of handlers.get(name) ?? []) fn(event)
  }
  return { ctx: ctx as never, fire }
}

function makeCfg() {
  const cfg = resolveConfig({ mode: "enforce", piiEmailAllowDomains: ["corp.example"] })
  cfg.audit.enabled = false
  return cfg
}

const EM = "user" + "@" + "corp.example"
const OTHER = "user" + "@" + "other.com"

test("scanOpts reaches tool.after content scrub (MAJOR-1 regression pin)", () => {
  const { ctx, fire } = makeCtx()
  registerGuard(ctx, makeCfg())
  const ev = { tool: "bash", sessionID: "s", status: "success", result: { content: "mail " + EM + " end" } }
  fire("tool:execute.after", ev)
  assert.equal(ev.result.content, "mail " + EM + " end", "allowlisted email must survive tool.after")
  const ev2 = { tool: "bash", sessionID: "s", status: "success", result: { content: "mail " + OTHER + " end" } }
  fire("tool:execute.after", ev2)
  assert.equal(ev2.result.content, "mail <REDACTED:pii> end", "other email must still be masked")
})

test("scanOpts reaches outbound context scrub", () => {
  const { ctx, fire } = makeCtx()
  registerGuard(ctx, makeCfg())
  const part = { type: "text", text: "owner " + EM + " here" }
  const ev = { system: [part], messages: [] }
  fire("session:context", ev)
  assert.equal(part.text, "owner " + EM + " here", "allowlisted email must survive outbound scrub")
  const part2 = { type: "text", text: "owner " + OTHER + " here" }
  fire("session:context", { system: [part2], messages: [] })
  assert.equal(part2.text, "owner <REDACTED:pii> here")
})

test("cursor invariant: skipped path email does not swallow a free email in the same string", () => {
  const { ctx, fire } = makeCtx()
  registerGuard(ctx, makeCfg())
  const ev = { tool: "bash", sessionID: "s", status: "success", result: { content: "ls /home/" + EM + " and mail " + OTHER } }
  fire("tool:execute.after", ev)
  assert.equal(
    ev.result.content,
    "ls /home/" + EM + " and mail <REDACTED:pii>",
    "path email skipped, free email masked"
  )
})
