/**
 * deps-guard (phase 2): intercept package installation commands.
 * Deterministic pre-install checks only: known-malicious blocklist and
 * typosquat detection (Levenshtein distance 1 to a curated top-name list).
 * Post-install auditing (npm audit / OSV) is a later phase — it needs the
 * project cwd, which the hook API does not guarantee.
 */

export interface InstallPackage {
  name: string
  version?: string
}

export interface InstallTarget {
  manager: "npm" | "yarn" | "pnpm" | "pip" | "cargo" | "npx" | "bun"
  packages: InstallPackage[]
}

const MANAGERS = new Set(["npm", "yarn", "pnpm", "pip", "pip3", "cargo", "npx", "pnpx", "bun", "bunx"])

const SUBCOMMANDS: Record<string, readonly string[]> = {
  npm: ["install", "i"],
  yarn: ["add", "dlx"],
  pnpm: ["add", "install", "dlx"],
  pip: ["install"],
  pip3: ["install"],
  cargo: ["add"],
  bun: ["add", "install", "x"],
}

/** flags that consume the NEXT token as their operand (never a package name) */
const FLAG_TAKES_ARG: Record<string, ReadonlySet<string>> = {
  npm: new Set(["-w", "--workspace", "--prefix", "--include", "--cache", "--userconfig", "--registry"]),
  yarn: new Set(["--cwd"]),
  pnpm: new Set(["--filter", "-F", "--dir", "-C"]),
  pip: new Set(["-r", "--requirement", "-e", "--editable", "-t", "--target", "-f", "--find-links", "-i", "--index-url", "--extra-index-url", "-c", "--constraint"]),
  cargo: new Set(["--path", "--git", "--rev", "--branch", "--tag", "--manifest-path", "--registry"]),
}

/** incident names from supply-chain history; installs need explicit human approval */
export const BLOCKED_PACKAGES: ReadonlySet<string> = new Set([
  "event-stream", // 2018: flatmap-stream payload (coinminer) via maintainer handover
  "flatmap-stream", // the payload package itself
  "node-ipc", // 2022: protestware (peacenotwar) in 9.2.x-11.0.0
  "ua-parser-js", // 2021: account hijack, coinminer/password stealer versions
  "coa", // 2021: hijack, script-based payload
  "rc", // 2021: hijack, same campaign as coa
])

/** affix squatting: trusted + short dictionary affix, with or without a dash (npm-only check) */
const AFFIX_SUFFIXES = ["js", "ts", "node", "cli", "dev", "-js", "-ts", "-node", "-cli", "-dev"] as const
const AFFIX_PREFIXES = ["node-", "nodejs-"] as const
/** historical legit names that would otherwise match the affix rule */
const AFFIX_ALLOWLIST: ReadonlySet<string> = new Set(["angularjs", "reactjs", "vuejs", "expressjs", "nodejs", "vue-cli", "angular-cli"])

/** git/url install specs are not registry names — never flag them */
function isGitOrUrlSpec(token: string): boolean {
  return (
    /:\/\//.test(token) ||
    /^(?:git@|github:|gitlab:|bitbucket:|gist:)/.test(token) ||
    /\.(?:tgz|tar\.gz|zip)$/i.test(token)
  )
}

/** split name@version on the LAST '@' (respects scoped names: @scope/pkg@1.0.0) */
function splitNameVersion(entry: string): { name: string; version?: string } {
  const at = entry.lastIndexOf("@")
  if (at > 0) return { name: entry.slice(0, at), version: entry.slice(at + 1) || undefined }
  return { name: entry }
}

/**
 * npx / pnpm dlx / yarn dlx: the executed package is a positional token, not an install operand.
 * Flags skipped; -p/--package operands ARE packages; everything after `--` is the command's args.
 */
function parseExecTokens(tokens: string[], start: number): InstallTarget | null {
  const packages: InstallPackage[] = []
  let positionalTaken = false
  let ignorePositional = false
  for (let j = start; j < tokens.length; j++) {
    const t = tokens[j]
    if (t === "--") break // rest belongs to the executed command
    if (t.startsWith("-")) {
      if (t === "-p" || t === "--package") {
        const next = tokens[++j]
        if (next && !isGitOrUrlSpec(next)) packages.push(splitNameVersion(next))
        continue
      }
      if (t.startsWith("-p=")) {
        const v = t.slice(3)
        if (v && !isGitOrUrlSpec(v)) packages.push(splitNameVersion(v))
        continue
      }
      if (t.startsWith("--package=")) {
        const v = t.slice("--package=".length)
        if (v && !isGitOrUrlSpec(v)) packages.push(splitNameVersion(v))
        continue
      }
      if (t === "-c" || t === "--call") {
        j++ // consume the shell string
        ignorePositional = true
        continue
      }
      continue
    }
    if (!positionalTaken && !ignorePositional && !isGitOrUrlSpec(t)) {
      packages.push(splitNameVersion(t))
      positionalTaken = true
    }
  }
  if (packages.length === 0) return null
  return { manager: "npx", packages }
}

/** curated popular npm names for typosquat distance-1 checks (119 unique) */
export const TRUSTED_TOP: ReadonlySet<string> = new Set([
  "lodash", "react", "react-dom", "vue", "angular", "express", "axios", "moment",
  "chalk", "commander", "debug", "request", "async", "underscore", "bluebird",
  "ramda", "dayjs", "date-fns", "jquery", "bootstrap", "webpack", "babel-core",
  "typescript", "eslint", "prettier", "jest", "mocha", "chai", "sinon", "supertest",
  "mongoose", "sequelize", "knex", "typeorm", "prisma", "mysql", "pg", "redis",
  "socket.io", "koa", "fastify", "hapi", "nestjs", "next", "nuxt", "gatsby",
  "redux", "mobx", "zustand", "react-router", "react-query", "swr", "axios-retry",
  "tailwindcss", "sass", "less", "postcss", "autoprefixer", "styled-components",
  "graphql", "apollo-server", "urql", "dataloader", "jsonwebtoken", "bcrypt",
  "crypto-js", "uuid", "nanoid", "semver", "dotenv", "cross-env", "rimraf",
  "glob", "minimatch", "fs-extra", "path-to-regexp", "mime-types", "qs",
  "body-parser", "cookie-parser", "cors", "helmet", "compression", "morgan",
  "winston", "pino", "bunyan", "loglevel", "inquirer", "enquirer", "yargs",
  "minimist", "yup", "joi", "zod", "ajv", "validator", "class-validator",
  "nodemailer", "multer", "sharp", "jimp", "pdfkit", "puppeteer", "playwright",
  "cheerio", "jsdom", "lodash-es", "core-js", "regenerator-runtime", "whatwg-fetch",
  "node-fetch", "undici", "got", "ky", "phin", "superagent", "xml2js", "js-yaml",
  "toml", "ini", "csv-parse", "xlsx", "exceljs", "archiver", "adm-zip", "tar",
  "yauzl", "decompress", "ffmpeg-static", "canvas", "three", "d3",
  "chart.js", "echarts", "pixi.js", "matter-js", "tone", "howler",
])

function parseSegment(segment: string): InstallTarget | null {
  const tokens = segment
    .split(/[\s;&|()"'`]+/)
    .filter((t) => t.length > 0)
  let i = 0
  // tolerate leading env assignments, `env`, and `sudo` with its flags
  while (i < tokens.length) {
    const t = tokens[i]
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t) || t === "env") {
      i++
      continue
    }
    if (t === "sudo") {
      i++
      while (i < tokens.length && tokens[i].startsWith("-")) {
        const flag = tokens[i]
        i++
        if (flag === "-u" || flag === "-g" || flag === "-h" || flag === "-p") {
          if (i < tokens.length) i++ // consume the flag's operand
        }
      }
      continue
    }
    break
  }
  // Windows runners: npm.cmd, pnpm.cmd, pip.exe, yarn.ps1, ... — strip the script/extension suffix
  const raw = tokens[i]
  if (!raw) return null
  const manager = raw.replace(/\.(?:cmd|ps1|exe|bat)$/i, "").toLowerCase()
  if (!MANAGERS.has(manager)) return null
  // execution-without-install forms: npx/pnpx/bunx pkg / pnpm|yarn dlx / bun x
  if (manager === "npx" || manager === "pnpx" || manager === "bunx") return parseExecTokens(tokens, i + 1)
  if ((manager === "pnpm" || manager === "yarn") && tokens[i + 1]?.toLowerCase() === "dlx") {
    return parseExecTokens(tokens, i + 2)
  }
  if (manager === "bun" && tokens[i + 1]?.toLowerCase() === "x") {
    return parseExecTokens(tokens, i + 2)
  }
  // global flags may precede the subcommand: npm --prefix . install pkg / yarn --cwd p add pkg
  const takesArgEarly = FLAG_TAKES_ARG[manager]
  let k = i + 1
  let globalFlag = false
  while (k < tokens.length && tokens[k].startsWith("-")) {
    const flag = tokens[k]
    if (flag === "-g" || flag === "--global") globalFlag = true
    k++
    if (takesArgEarly?.has(flag) && k < tokens.length) k++ // consume the flag's operand
  }
  if (globalFlag) return null
  const sub = tokens[k]?.toLowerCase()
  if (!SUBCOMMANDS[manager]?.includes(sub)) return null
  if (manager === "yarn" && tokens[k + 1]?.toLowerCase() === "global") return null

  const takesArg = FLAG_TAKES_ARG[manager]
  const packages: InstallPackage[] = []
  for (let j = k + 1; j < tokens.length; j++) {
    const t = tokens[j]
    if (t.startsWith("-")) {
      if (t === "-g" || t === "--global") return null
      if (takesArg?.has(t) && j + 1 < tokens.length) j++ // consume the flag's operand
      continue
    }
    let name = t
    let version: string | undefined
    if (manager === "pip" || manager === "pip3") {
      const m = /^([^=<>~!]+?)([=<>~!].*)?$/.exec(t)
      if (!m || !m[1]) continue
      name = m[1].replace(/\[[^\]]*\]$/, "") // extras: event-stream[socks] -> event-stream
      version = m[2] ? m[2].replace(/^[=<>~!]+/, "") : undefined
    } else {
      const at = t.lastIndexOf("@")
      if (at > 0) {
        name = t.slice(0, at)
        version = t.slice(at + 1)
        // npm alias: alias@npm:event-stream actually installs event-stream
        if (version.startsWith("npm:") && version.length > 4) {
          name = version.slice(4)
          version = undefined
        }
      }
    }
    if (!name) continue
    packages.push({ name, version })
  }
  if (packages.length === 0) return null
  return { manager: manager === "pip3" ? "pip" : (manager as InstallTarget["manager"]), packages }
}

/**
 * All install targets found in a (possibly compound) command — one per segment
 * (segments split by && || ; | or newline). Empty array if none.
 */
export function parseSegments(command: string): InstallTarget[] {
  const out: InstallTarget[] = []
  for (const segment of command.split(/&&|\|\||[;|&]|\n/)) {
    const hit = parseSegment(segment)
    if (hit) out.push(hit)
  }
  return out
}

/** first install target in the command, or null */
export function parseInstallCommand(command: string): InstallTarget | null {
  return parseSegments(command)[0] ?? null
}

export function levenshtein(a: string, b: string): number {
  if (a === b) return 0
  const m = a.length
  const n = b.length
  if (m === 0) return n
  if (n === 0) return m
  // optimal string alignment: transposition (ab->ba) costs 1 — catches typosquats like lodahs/lodash
  const d: number[][] = Array.from({ length: m + 1 }, (_, i) => {
    const row = new Array<number>(n + 1).fill(0)
    row[0] = i
    return row
  })
  for (let j = 1; j <= n; j++) d[0][j] = j
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1
      let best = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        best = Math.min(best, d[i - 2][j - 2] + 1)
      }
      d[i][j] = best
    }
  }
  return d[m][n]
}

/** returns the trusted name this package is squatting, or null (case-insensitive) */
export function isTyposquat(name: string): string | null {
  const n = name.toLowerCase()
  if (n.length < 4) return null
  // scoped: only @types/* is checked (arbitrary scopes need an official-scope list — phase 3)
  if (n.startsWith("@")) {
    if (!n.startsWith("@types/")) return null
    const base = n.slice("@types/".length)
    if (TRUSTED_TOP.has(base)) return null
    for (const trusted of TRUSTED_TOP) {
      if (Math.abs(trusted.length - base.length) > 1) continue
      if (levenshtein(base, trusted) === 1) return trusted
    }
    return null
  }
  if (TRUSTED_TOP.has(n)) return null
  for (const trusted of TRUSTED_TOP) {
    if (Math.abs(trusted.length - n.length) > 1) continue
    if (levenshtein(n, trusted) === 1) return trusted
  }
  return null
}

/** affix squatting: lodashjs / node-lodash / react-cli — trusted + dictionary affix */
export function isAffixSquat(name: string): string | null {
  const n = name.toLowerCase()
  if (TRUSTED_TOP.has(n) || AFFIX_ALLOWLIST.has(n)) return null
  for (const trusted of TRUSTED_TOP) {
    for (const suffix of AFFIX_SUFFIXES) {
      if (n === trusted + suffix) return trusted
    }
    for (const prefix of AFFIX_PREFIXES) {
      if (n === prefix + trusted) return trusted
    }
  }
  return null
}

export interface DepsVerdict {
  name: string
  reason: "blocklist" | "typosquat"
  target?: string
}

/**
 * Check a raw shell command; returns the first violation or null.
 * extraBlocked/allowed entries: plain "name" (all versions) or "name@version" (that version only).
 */
export function checkInstall(command: string, extraBlocked: readonly string[] = [], allowed: readonly string[] = []): DepsVerdict | null {
  const targets = parseSegments(command)
  if (targets.length === 0) return null

  const allowedWide = new Set<string>()
  const allowedVer = new Set<string>() // "name@version", lowercased
  for (const e of allowed) {
    const { name, version } = splitNameVersion(e)
    const l = name.toLowerCase()
    if (version) allowedVer.add(l + "@" + version.toLowerCase())
    else allowedWide.add(l)
  }

  const blockedWide = new Set<string>()
  const blockedVer = new Map<string, Set<string>>()
  for (const e of [...BLOCKED_PACKAGES, ...extraBlocked]) {
    const { name, version } = splitNameVersion(e)
    const l = name.toLowerCase()
    if (version) {
      const s = blockedVer.get(l) ?? new Set<string>()
      s.add(version.toLowerCase())
      blockedVer.set(l, s)
    } else {
      blockedWide.add(l)
    }
  }

  const npmish = new Set(["npm", "yarn", "pnpm", "npx", "bun"])
  for (const target of targets) {
    for (const pkg of target.packages) {
      const lower = pkg.name.toLowerCase()
      const ver = pkg.version ? pkg.version.toLowerCase() : undefined
      if (allowedWide.has(lower)) continue
      // a versioned allow entry must NOT lift a name-wide block (spec: it lifts only versioned blocks)
      if (blockedWide.has(lower)) {
        return { name: pkg.name, reason: "blocklist" }
      }
      if (ver && allowedVer.has(lower + "@" + ver)) continue
      if (ver) {
        const s = blockedVer.get(lower)
        if (s?.has(ver)) {
          return { name: pkg.name, reason: "blocklist" }
        }
      }
      // squat checks are npm-ecosystem-only: other ecosystems reuse the same names legitimately (pip "requests" vs npm "request")
      if (npmish.has(target.manager)) {
        // affix first: "lodash-js" is affix of lodash (exact form), not a dist-1 edit of lodash-es
        const squat = isAffixSquat(pkg.name) ?? isTyposquat(pkg.name)
        if (squat) {
          return { name: pkg.name, reason: "typosquat", target: squat }
        }
      }
    }
  }
  return null
}

/** true if any segment is an npm install (drives the post-audit scheduler; npx/dlx don't count) */
export function isNpmInstall(command: string): boolean {
  return parseSegments(command).some((t) => t.manager === "npm")
}

export interface AuditSummary {
  total: number
  severities: Record<string, number>
}

/** npm audit severity vocabulary; anything else folds into "unknown" (blocks __proto__-style key damage) */
const SEVERITY_NAMES = new Set(["info", "low", "moderate", "high", "critical"])

/** aggregate `npm audit --json` output (v2 auditReport.vulnerabilities or v1 advisories); null if unusable */
export function parseAuditReport(text: string): AuditSummary | null {
  let json: unknown
  try {
    json = JSON.parse(text)
  } catch {
    return null
  }
  if (typeof json !== "object" || json === null) return null
  const obj = json as Record<string, unknown>
  const sources: unknown[] = []
  // npm >= 11: top-level `vulnerabilities` (auditReportVersion 3)
  sources.push(obj.vulnerabilities)
  // older v2 shape
  if (typeof obj.auditReport === "object" && obj.auditReport !== null) {
    sources.push((obj.auditReport as Record<string, unknown>).vulnerabilities)
  }
  // v1 shape
  if (typeof obj.advisories === "object" && obj.advisories !== null) {
    sources.push(obj.advisories)
  }
  const found = sources.filter((s) => typeof s === "object" && s !== null && !Array.isArray(s))
  if (found.length === 0) return null
  const severities: Record<string, number> = {}
  let total = 0
  for (const s of found) {
    for (const entry of Object.values(s as Record<string, unknown>)) {
      if (typeof entry !== "object" || entry === null) continue
      const sev = (entry as Record<string, unknown>).severity
      const key = typeof sev === "string" && SEVERITY_NAMES.has(sev) ? sev : "unknown"
      severities[key] = (severities[key] ?? 0) + 1
      total++
    }
  }
  return { total, severities }
}
