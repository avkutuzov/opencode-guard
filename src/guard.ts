import { Error as ToolError } from "@opencode/plugin/promise/tool"
import type { Plugin } from "@opencode/plugin"
import { createHash } from "node:crypto"
import { spawn } from "node:child_process"
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs"
import { homedir } from "node:os"
import { isAbsolute, join } from "node:path"
import { activePatterns, type Pattern } from "./patterns.ts"
import { redact, scan } from "./scan.ts"
import { isPathBlocked, isPathExempt, isPathWriteProtected } from "./glob.ts"
import type { GuardConfig } from "./config.ts"
import { appendAudit, type AuditEvent } from "./audit.ts"
import { scanSkillDir } from "./skillcheck.ts"
import { checkInstall, isNpmInstall, extractNpmPrefix, expandShellVars, parseAuditReport } from "./deps.ts"

type Ctx = Plugin.Context

const PATH_KEY = /^(filePath|path|file|directory|dir|folder|uri)$/i
const WRITE_TOOLS = new Set(["write", "edit", "patch"])
const SHELL_TOOLS = new Set(["shell", "bash"])
/** never rewrite these (matching anchors must stay byte-identical to the file) */
const SKIP_REDACT_KEYS = new Set(["oldString", "old_string", "oldText"])

function audit(cfg: GuardConfig, ev: AuditEvent): void {
  if (!cfg.audit.enabled) return
  appendAudit(cfg.audit.dir, ev)
}

function veto(message: string): never {
  throw new ToolError({ message })
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v)
}

function keepValue(key: string): boolean {
  return SKIP_REDACT_KEYS.has(key) || PATH_KEY.test(key)
}

/**
 * Recursively count (and optionally mask) secret matches in string values.
 * Skips match-anchors and path-like keys (paths are policy-checked, not rewritten).
 */
function deepRedact(value: unknown, patterns: readonly Pattern[], mutate: boolean, skipKey?: string): number {
  if (typeof value === "string") {
    if (skipKey && keepValue(skipKey)) return 0
    return redact(value, patterns).matches.length
  }
  if (Array.isArray(value)) {
    let n = 0
    for (let i = 0; i < value.length; i++) n += deepRedact(value[i], patterns, mutate)
    return n
  }
  if (isRecord(value)) {
    let n = 0
    for (const [k, v] of Object.entries(value)) {
      if (typeof v === "string") {
        if (!keepValue(k)) {
          const r = redact(v, patterns)
          if (r.matches.length > 0) {
            if (mutate) value[k] = r.text
            n += r.matches.length
          }
        }
      } else {
        n += deepRedact(v, patterns, mutate, k)
      }
    }
    return n
  }
  return 0
}

/** Collect strings stored under path-like keys. */
function pathStrings(value: unknown, out: string[] = []): string[] {
  if (Array.isArray(value)) {
    for (const v of value) pathStrings(v, out)
    return out
  }
  if (isRecord(value)) {
    for (const [k, v] of Object.entries(value)) {
      if (typeof v === "string" && PATH_KEY.test(k)) out.push(v)
      else pathStrings(v, out)
    }
  }
  return out
}

/** Extract target paths from unified-diff ---/+++ headers in patch text. */
function patchPaths(text: string): string[] {
  const out: string[] = []
  for (const line of text.split("\n")) {
    const m = /^(?:---|\+\+\+)\s+"?([^\s"]+)"?/.exec(line)
    if (m && m[1] !== "/dev/null") out.push(m[1].replace(/^[ab]\//, ""))
  }
  return out
}

function commandTokens(command: string): string[] {
  return command
    .split(/[\s"'`;&|()<>]+/)
    .flatMap((t) => t.split("="))
    .map((t) => t.replace(/^[<>]+/, ""))
    .filter((t) => t.length > 0)
}

function checkCommandPaths(command: string, cfg: GuardConfig): string | undefined {
  // limitation: ~, $VAR and shell globs are not expanded here — the runtime
  // shell may still resolve them to blocked paths. Tracked as a known gap.
  for (const token of commandTokens(command)) {
    if (isPathBlocked(token, cfg)) return token
  }
  return undefined
}

function categoriesOf(matches: readonly { category: string }[]): string[] {
  return [...new Set(matches.map((m) => m.category))].sort()
}

function uriToPath(uri: string): string | undefined {
  if (!uri.startsWith("file://")) return undefined
  const raw = uri.slice("file://".length)
  try {
    return decodeURIComponent(raw)
  } catch {
    return raw
  }
}

function trackHook(reg: Promise<{ dispose(): Promise<void> }>): void {
  void reg.then(
    (r) => tracked.push(r),
    (err) => console.error("guard: hook registration failed", err),
  )
}

const tracked: { dispose(): Promise<void> }[] = []

/** recent deps-audit dedup: tool.before and shell.create.before both see the same command */
const DEPS_AUDIT_TTL_MS = 2000
const depsAuditRecent = new Map<string, number>()

/** post-audit: give the install ~60s to finish, then npm audit in the project dir (warn-only) */
const POST_AUDIT_DELAY_MS = 60_000
const POST_AUDIT_TIMEOUT_MS = 120_000
/** don't stack audits for the same project dir (a burst of installs schedules one audit) */
const postAuditRecent = new Map<string, number>()
const POST_AUDIT_DEDUP_MS = 5 * 60_000

/** install target dir for the post-audit: --prefix wins, resolved against the base dir when relative */
function auditDirFor(command: string, baseDir: string): string {
  try {
    const prefix = extractNpmPrefix(command)
    if (!prefix) return baseDir
    const expanded = expandShellVars(prefix)
    return isAbsolute(expanded) ? expanded : join(baseDir, expanded)
  } catch {
    return baseDir
  }
}

let cachedNpmCmd: string | undefined
/** absolute npm.cmd path when findable (the service host env may lack System32/nodejs in PATH) */
function npmCmdPath(): string {
  if (cachedNpmCmd !== undefined) return cachedNpmCmd
  cachedNpmCmd = "npm.cmd"
  try {
    const candidates: string[] = []
    for (const dir of (process.env.PATH ?? "").split(";")) {
      if (dir) candidates.push(join(dir, "npm.cmd"))
    }
    // well-known install locations (nodejs ships node.exe next to npm.cmd, so a stripped PATH is fine)
    const pf = process.env.ProgramFiles ?? "C:\\Program Files"
    const local = process.env.LOCALAPPDATA ?? ""
    const roaming = process.env.APPDATA ?? ""
    candidates.push(join(pf, "nodejs", "npm.cmd"))
    if (local) candidates.push(join(local, "Programs", "nodejs", "npm.cmd"))
    if (roaming) candidates.push(join(roaming, "npm", "npm.cmd"))
    for (const candidate of candidates) {
      try {
        if (existsSync(candidate)) {
          cachedNpmCmd = candidate
          break
        }
      } catch {}
    }
  } catch {}
  return cachedNpmCmd
}

/** npm audit invocation that works under both Node and Bun on any OS */
function npmAuditRunner(): { cmd: string; args: string[] } {
  // Windows: .cmd files need a cmd.exe host under BOTH runtimes (direct spawn -> EINVAL),
  // and the service host env may lack System32 in PATH — resolve absolute paths.
  if (process.platform === "win32") {
    const sysRoot = process.env.SystemRoot ?? process.env.windir ?? "C:\\Windows"
    const cmd = join(sysRoot, "System32", "cmd.exe")
    return { cmd, args: ["/d", "/s", "/c", `"${npmCmdPath()}" audit --json`] }
  }
  return { cmd: "npm", args: ["audit", "--json"] }
}

function schedulePostAudit(command: string, cwd: string, cfg: GuardConfig): void {  try {
    if (!isNpmInstall(command)) return
    const last = postAuditRecent.get(cwd)
    if (last && Date.now() - last < POST_AUDIT_DEDUP_MS) return
    postAuditRecent.set(cwd, Date.now())
    if (postAuditRecent.size > 100) postAuditRecent.clear()
    // breadcrumb: an allowed install is booked for auditing (useful trail on its own)
    audit(cfg, {
      ts: new Date().toISOString(),
      kind: "deps",
      categories: ["audit-scheduled"],
      count: 1,
      action: "warn",
      detail: cwd,
    })
    const timer = setTimeout(() => {
      try {
        const runner = npmAuditRunner()
        const child = spawn(runner.cmd, runner.args, {
          cwd,
          windowsHide: true,
        })
        let stdout = ""
        child.stdout?.on("data", (d: Buffer) => {
          stdout += d.toString()
        })
        child.on("error", (err: Error) => {
          // permanent visibility: a failed audit spawn is itself audited
          audit(cfg, {
            ts: new Date().toISOString(),
            kind: "deps",
            categories: ["audit-error"],
            count: 1,
            action: "warn",
            detail: String(err?.message ?? err).slice(0, 200),
          })
        })
        // built-in spawn timeout only kills the win32 wrapper — enforce our own
        let closed = false
        const killer = setTimeout(() => {
          try {
            if (closed) return
            if (process.platform === "win32") {
              if (child.pid === undefined) return
              const sysRoot = process.env.SystemRoot ?? process.env.windir ?? "C:\\Windows"
              const taskkill = join(sysRoot, "System32", "taskkill.exe")
              spawn(taskkill, ["/PID", String(child.pid), "/T", "/F"], { windowsHide: true }).on("error", () => {})
            } else {
              child.kill("SIGTERM")
            }
          } catch {}
        }, POST_AUDIT_TIMEOUT_MS)
        killer.unref?.()
        child.on("close", (code: number | null) => {
          try {
            closed = true
            clearTimeout(killer)
            if (!stdout.trim()) {
              // visibility: the audit ran but produced nothing (broken runner env, missing npm, ...)
              audit(cfg, {
                ts: new Date().toISOString(),
                kind: "deps",
                categories: ["audit-error"],
                count: 1,
                action: "warn",
                detail: `empty stdout, code=${code}, bun=${"bun" in process.versions}, runner=${runner.cmd}`,
              })
              return
            }
            // partial JSON after a forced kill simply fails to parse — dropped, by design
            const report = parseAuditReport(stdout)
            if (!report || report.total === 0) return
            const sev = Object.entries(report.severities)
              .map(([k, v]) => `${k}:${v}`)
              .join(" ")
            audit(cfg, {
              ts: new Date().toISOString(),
              kind: "deps",
              categories: ["audit-vulnerability"],
              count: report.total,
              action: "warn",
              severities: report.severities,
            })
            console.warn(`guard: npm audit в ${cwd} — ${report.total} уязвимостей (${sev}), детали в аудите`)
          } catch {
            // never crash the plugin over a post-audit result
          }
        })
        child.unref?.()
      } catch (e) {
        audit(cfg, {
          ts: new Date().toISOString(),
          kind: "deps",
          categories: ["audit-error"],
          count: 1,
          action: "warn",
          detail: "timer: " + String(e).slice(0, 200),
        })
      }
    }, POST_AUDIT_DELAY_MS)
    timer.unref?.()
  } catch {
    // never crash the hook
  }
}

export function registerGuard(ctx: Ctx, cfg: GuardConfig): () => Promise<void> {
  const patterns = activePatterns(cfg.disabledPatterns)
  const now = () => new Date().toISOString()

  // --- startup scan of installed skills (warn-only, never blocks plugin load) ---
  if (cfg.scanSkillsOnLoad) {
    try {
      const dir = join(homedir(), ".config", "opencode", "skills")
      const findings = scanSkillDir(dir, patterns, cfg.exemptSkills)
      // hot-reload: skip re-audit when the findings summary is unchanged
      const hash = createHash("sha256").update(JSON.stringify(findings)).digest("hex")
      const marker = join(cfg.audit.dir, "guard-skillscan.state")
      let prev: string | null = null
      try {
        prev = readFileSync(marker, "utf8")
      } catch {
        prev = null
      }
      if (prev !== hash) {
        try {
          mkdirSync(cfg.audit.dir, { recursive: true })
          writeFileSync(marker, hash, "utf8")
        } catch {
          // state file is best-effort
        }
        for (const f of findings) {
          audit(cfg, { ts: now(), kind: "skill", categories: f.categories, count: f.count, action: "warn" })
        }
        if (findings.length > 0) {
          console.warn(`guard: ${findings.length} скилл(ов) с подозрительным содержимым: ${findings.map((f) => f.skill).join(", ")} — детали в аудите`)
        }
      }
    } catch {
      // never crash plugin load
    }
  }

  // --- user prompts ---
  if (cfg.scanPrompts) {
    trackHook(
      ctx.session.hook("prompt", (event) => {
        const mutate = cfg.mode === "enforce"
        const action: AuditEvent["action"] = mutate ? "redacted" : "warn"

        // attachment path policy: a blocked file must not enter the context
        const files = event.prompt.files ?? []
        for (let i = files.length - 1; i >= 0; i--) {
          const p = uriToPath(files[i].uri)
          if (p && isPathBlocked(p, cfg)) {
            if (mutate) files.splice(i, 1)
            audit(cfg, { ts: now(), kind: "prompt", sessionID: event.sessionID, categories: ["path"], count: 1, action })
          }
        }

        const text = event.prompt.text
        if (!text) return
        const r = redact(text, patterns)
        if (r.matches.length === 0) return
        if (mutate) {
          event.prompt.text = r.text
          // fix mention offsets (files/agents/skills) invalidated by the rewrite
          const delta = (pos: number) =>
            r.matches.filter((m) => m.start < pos).reduce((d, m) => d + (m.mask.length - (m.end - m.start)), 0)
          const mentioned = [
            ...(event.prompt.files ?? []),
            ...((event.prompt as { agents?: { mention?: { start: number; end: number; text: string } | undefined }[] }).agents ?? []),
            ...((event.prompt as { skills?: { mention?: { start: number; end: number; text: string } | undefined }[] }).skills ?? []),
          ]
          for (const item of mentioned) {
            const m = item.mention
            if (!m) continue
            if (r.matches.some((x) => x.start < m.end && x.end > m.start)) {
              item.mention = undefined
            } else {
              item.mention = { ...m, start: m.start + delta(m.start), end: m.end + delta(m.end) }
            }
          }
        }
        audit(cfg, { ts: now(), kind: "prompt", sessionID: event.sessionID, categories: categoriesOf(r.matches), count: r.matches.length, action })
      }),
    )
  }

  // --- tool calls ---
  trackHook(
    ctx.tool.hook("execute.before", (event) => {
      const tool = event.tool
      const input = event.input
      const mutate = cfg.mode === "enforce"
      const action: AuditEvent["action"] = mutate ? "blocked" : "warn"

      // path policy (per path: isPathBlocked is exemption-aware)
      const paths = pathStrings(input)
      if (tool === "patch" && isRecord(input) && typeof input.patchText === "string") {
        paths.push(...patchPaths(input.patchText))
      }
      for (const p of paths) {
        if (isPathBlocked(p, cfg)) {
          audit(cfg, { ts: now(), kind: "tool.before", tool, sessionID: event.sessionID, categories: ["path"], count: 1, action })
          if (mutate) veto(`guard: доступ к '${p}' заблокирован — путь в списке запрещённых (секреты/ПДн). Попроси пользователя явно одобрить работу с этим файлом.`)
          return
        }
        if (WRITE_TOOLS.has(tool) && isPathWriteProtected(p, cfg)) {
          audit(cfg, { ts: now(), kind: "tool.before", tool, sessionID: event.sessionID, categories: ["path"], count: 1, action })
          if (mutate) veto(`guard: запись в '${p}' заблокирована — путь защищён от изменений.`)
          return
        }
      }

      if (SHELL_TOOLS.has(tool) && isRecord(input) && typeof input.command === "string") {
        const blockedPath = checkCommandPaths(input.command, cfg)
        if (blockedPath) {
          audit(cfg, { ts: now(), kind: "tool.before", tool, sessionID: event.sessionID, categories: ["path"], count: 1, action })
          if (mutate) veto(`guard: команда обращается к '${blockedPath}' — доступ запрещён.`)
          return
        }
        if (cfg.depsCheck) {
          const verdict = checkInstall(input.command, cfg.blockedPackages, cfg.allowedPackages)
          if (verdict) {
            const cat = verdict.reason === "blocklist" ? "malicious-package" : "typosquat"
            depsAuditRecent.set(input.command, Date.now())
            if (depsAuditRecent.size > 100) depsAuditRecent.clear()
            audit(cfg, { ts: now(), kind: "deps", tool, sessionID: event.sessionID, categories: [cat], count: 1, action })
            if (mutate) {
              const why =
                verdict.reason === "blocklist"
                  ? "пакет в списке известных вредоносных (инциденты цепочки поставок)"
                  : `имя похоже на '${verdict.target}' (typosquat)`
              veto(`guard: установка '${verdict.name}' заблокирована — ${why}. Если установка легитимна — попроси пользователя выполнить её вручную.`)
            }
            return
          }
        }
        // agent shell commands never reach shell.create.before — schedule the post-audit here,
        // using the server location as the project dir (an explicit --prefix overrides it)
        if (cfg.postAudit && isNpmInstall(input.command)) {
          schedulePostAudit(input.command, auditDirFor(input.command, ctx.location.directory), cfg)
        }
      }

      // secret redaction on mutating input (only when every involved path is exempt)
      if (cfg.redactOnWrite) {
        const allExempt = paths.length > 0 && paths.every((p) => isPathExempt(p, cfg))
        if (!allExempt) {
          const count = deepRedact(input, patterns, mutate)
          if (count > 0) {
            audit(cfg, { ts: now(), kind: "tool.before", tool, sessionID: event.sessionID, categories: ["secret"], count, action: mutate ? "redacted" : "warn" })
          }
        }
      }
    }),
  )

  // --- tool results (secrets must not flow into context/logs) ---
  trackHook(
    ctx.tool.hook("execute.after", (event) => {
      const mutate = cfg.mode === "enforce"

      if (event.status === "error") {
        // bash providers often echo the failing command/stderr into the message
        const msg = event.error?.message
        if (typeof msg === "string") {
          const r = redact(msg, patterns)
          if (r.matches.length > 0) {
            if (mutate) event.error = new ToolError({ message: r.text })
            audit(cfg, { ts: now(), kind: "tool.after", tool: event.tool, sessionID: event.sessionID, categories: categoriesOf(r.matches), count: r.matches.length, action: mutate ? "redacted" : "warn" })
          }
        }
        return
      }

      const result = event.result as { content?: unknown; output?: unknown; metadata?: unknown }
      const cats = new Set<string>()
      let n = 0

      const scrubText = (s: string): string => {
        const r = redact(s, patterns)
        if (r.matches.length > 0) {
          n += r.matches.length
          for (const m of r.matches) cats.add(m.category)
          return mutate ? r.text : s
        }
        return s
      }

      const content = result.content
      if (typeof content === "string") {
        result.content = scrubText(content)
      } else if (Array.isArray(content)) {
        for (const part of content) {
          if (isRecord(part) && part.type === "text" && typeof part.text === "string") {
            part.text = scrubText(part.text)
          }
        }
      }

      // content was already scrubbed above — scan the remainder (output/metadata)
      // so matches are counted once
      const rest = { ...result, content: undefined }
      n += deepRedact(rest, patterns, mutate)
      if (n > 0) {
        audit(cfg, { ts: now(), kind: "tool.after", tool: event.tool, sessionID: event.sessionID, categories: [...cats].sort(), count: n, action: mutate ? "redacted" : "warn" })
      }
    }),
  )

  // --- shell backstop: every shell creation, including background shells ---
  trackHook(
    ctx.shell.hook("create.before", (event) => {
      const mutate = cfg.mode === "enforce"
      const blockedPath = checkCommandPaths(event.command, cfg)
      if (blockedPath) {
        // no throw here: shell hooks cannot veto, only tool.execute.before can.
        // neutralize the command instead, then audit the guaranteed block.
        if (mutate) {
          const safe = blockedPath.replace(/["'`<>|&]/g, "")
          event.command = `echo "guard: blocked access to '${safe}'" && exit 1`
        }
        audit(cfg, { ts: now(), kind: "shell", categories: ["path"], count: 1, action: mutate ? "blocked" : "warn" })
        return
      }
      if (cfg.depsCheck) {
        const verdict = checkInstall(event.command, cfg.blockedPackages, cfg.allowedPackages)
        if (verdict) {
          const cat = verdict.reason === "blocklist" ? "malicious-package" : "typosquat"
          if (mutate) {
            const safe = verdict.name.replace(/["'`<>|&]/g, "")
            event.command = `echo "guard: install blocked '${safe}'" && exit 1`
          }
          const last = depsAuditRecent.get(event.command)
          if (!last || Date.now() - last > DEPS_AUDIT_TTL_MS) {
            audit(cfg, { ts: now(), kind: "deps", categories: [cat], count: 1, action: mutate ? "blocked" : "warn" })
          }
          // warn mode lets the install through — it still qualifies for post-audit
          if (!mutate && cfg.postAudit) schedulePostAudit(event.command, auditDirFor(event.command, event.cwd), cfg)
          return
        }
      }
      if (cfg.postAudit) schedulePostAudit(event.command, auditDirFor(event.command, event.cwd), cfg)
      if (!cfg.redactOnWrite) return
      const r = redact(event.command, patterns)
      if (r.matches.length > 0) {
        if (mutate) event.command = r.text
        audit(cfg, { ts: now(), kind: "shell", categories: categoriesOf(r.matches), count: r.matches.length, action: mutate ? "redacted" : "warn" })
      }
      for (const [k, v] of Object.entries(event.env)) {
        if (typeof v !== "string") continue
        const m = scan(v, patterns)
        if (m.length > 0) {
          if (mutate) event.env[k] = "<REDACTED:env>"
          audit(cfg, { ts: now(), kind: "shell", categories: categoriesOf(m), count: m.length, action: mutate ? "redacted" : "warn" })
        }
      }
    }),
  )

  // --- outbound context scrub (defense in depth) ---
  if (cfg.scanOutbound) {
    trackHook(
      ctx.session.hook("context", (event) => {
        const mutate = cfg.mode === "enforce"
        let n = 0
        const cats = new Set<string>()
        const scrub = (s: string): string => {
          const r = redact(s, patterns)
          if (r.matches.length > 0) {
            n += r.matches.length
            for (const m of r.matches) cats.add(m.category)
            return mutate ? r.text : s
          }
          return s
        }
        const system = event.system as Array<{ type: string; text?: string }>
        for (const part of system) {
          if (part.type === "text" && typeof part.text === "string") part.text = scrub(part.text)
        }
        for (const msg of event.messages) {
          const m = msg as { content?: unknown }
          if (typeof m.content === "string") {
            m.content = scrub(m.content)
          } else if (Array.isArray(m.content)) {
            for (const p of m.content) {
              if (isRecord(p) && p.type === "text" && typeof p.text === "string") {
                p.text = scrub(p.text)
              }
            }
          }
        }
        if (n > 0) audit(cfg, { ts: now(), kind: "context", categories: [...cats].sort(), count: n, action: mutate ? "redacted" : "warn" })
      }),
    )
  }

  return async () => {
    for (const r of tracked.splice(0)) await r.dispose()
  }
}
