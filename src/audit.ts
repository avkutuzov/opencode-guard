import { appendFileSync, mkdirSync } from "node:fs"
import { join } from "node:path"

export interface AuditEvent {
  ts: string
  kind: "prompt" | "tool.before" | "tool.after" | "shell" | "context" | "skill" | "deps"
  tool?: string
  sessionID?: string
  categories: string[]
  count: number
  action: "redacted" | "blocked" | "warn"
  /** optional severity breakdown (npm post-audit) */
  severities?: Record<string, number>
}

/**
 * Append-only JSONL audit trail. Deliberately carries NO raw text:
 * only categories, counts and actions. Fails silent — a broken audit
 * file must never crash the plugin (and with it the session).
 */
export function appendAudit(dir: string, ev: AuditEvent): void {
  try {
    mkdirSync(dir, { recursive: true })
    appendFileSync(join(dir, "guard-audit.jsonl"), JSON.stringify(ev) + "\n", { encoding: "utf8", mode: 0o600 })
  } catch {
    // never throw
  }
}
