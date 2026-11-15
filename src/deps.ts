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
  manager: "npm" | "yarn" | "pnpm" | "pip" | "cargo"
  packages: InstallPackage[]
}

const MANAGERS = new Set(["npm", "yarn", "pnpm", "pip", "pip3", "cargo"])

const SUBCOMMANDS: Record<string, readonly string[]> = {
  npm: ["install", "i"],
  yarn: ["add"],
  pnpm: ["add", "install"],
  pip: ["install"],
  pip3: ["install"],
  cargo: ["add"],
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
  const manager = tokens[i]
  if (!manager || !MANAGERS.has(manager)) return null
  const sub = tokens[i + 1]
  if (!SUBCOMMANDS[manager]?.includes(sub)) return null
  if (manager === "yarn" && tokens[i + 2] === "global") return null

  const takesArg = FLAG_TAKES_ARG[manager]
  const packages: InstallPackage[] = []
  for (let j = i + 2; j < tokens.length; j++) {
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
      name = m[1]
      version = m[2] ? m[2].replace(/^[=<>~!]+/, "") : undefined
    } else {
      const at = t.lastIndexOf("@")
      if (at > 0) {
        name = t.slice(0, at)
        version = t.slice(at + 1)
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
  for (const segment of command.split(/&&|\|\||[;|]|\n/)) {
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
  if (n.startsWith("@") || n.length < 4) return null
  if (TRUSTED_TOP.has(n)) return null
  for (const trusted of TRUSTED_TOP) {
    if (Math.abs(trusted.length - n.length) > 1) continue
    if (levenshtein(n, trusted) === 1) return trusted
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
 * extraBlocked: user names added to the blocklist; allowed: user names exempted from it.
 */
export function checkInstall(command: string, extraBlocked: readonly string[] = [], allowed: readonly string[] = []): DepsVerdict | null {
  const targets = parseSegments(command)
  if (targets.length === 0) return null
  const ok = new Set(allowed.map((p) => p.toLowerCase()))
  const blocked = new Set([...BLOCKED_PACKAGES, ...extraBlocked].map((p) => p.toLowerCase()))
  for (const target of targets) {
    const npmish = target.manager === "npm" || target.manager === "yarn" || target.manager === "pnpm"
    for (const pkg of target.packages) {
      const lower = pkg.name.toLowerCase()
      if (ok.has(lower)) continue
      if (blocked.has(lower)) {
        return { name: pkg.name, reason: "blocklist" }
      }
      // squat check is npm-only: other ecosystems reuse the same names legitimately (pip "requests" vs npm "request")
      if (npmish) {
        const squat = isTyposquat(pkg.name)
        if (squat) {
          return { name: pkg.name, reason: "typosquat", target: squat }
        }
      }
    }
  }
  return null
}
