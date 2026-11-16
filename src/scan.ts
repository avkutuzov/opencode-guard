import { CRITICAL_ENV_KEYS } from "./config.ts"
import { DEFAULT_PATTERNS, type Pattern } from "./patterns.ts"

export interface Match {
  start: number
  end: number
  category: string
  /** id of the pattern that produced this match */
  matchedBy: string
  /** the raw matched text */
  raw: string
  /** replacement text */
  mask: string
}

export interface ScanOptions {
  /** email domains never masked (exact, case-insensitive; subdomains NOT included) */
  piiEmailAllowDomains?: readonly string[]
}

const compiled = new Map<string, RegExp>()

function compile(p: Pattern): RegExp {
  let re = compiled.get(p.id)
  if (!re) {
    const flags = [...new Set((p.flags ?? "") + "gd")].join("")
    re = new RegExp(p.regex, flags)
    compiled.set(p.id, re)
  }
  return re
}

export function isLuhnValid(text: string): boolean {
  const digits = text.replace(/\D/g, "")
  if (digits.length < 13) return false
  let sum = 0
  let dbl = false
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48
    if (dbl) {
      d *= 2
      if (d > 9) d -= 9
    }
    sum += d
    dbl = !dbl
  }
  return sum % 10 === 0
}

/**
 * Context check (spec: docs/pii-email-spec.md FR1): a PII match is skipped when
 * a path separator is immediately adjacent to it — `/` or `\` touching the match
 * boundary means the "email" is a path segment (e.g. /home/<REDACTED:pii>/.config,
 * C:\Users\<REDACTED:pii>). An scp-style user@host: is NOT a path (right neighbor
 * is `:`) and stays masked. Secrets are never subject to this check.
 */
export function isPathContext(match: Pick<Match, "start" | "end">, source: string): boolean {
  const left = match.start > 0 ? source[match.start - 1] : ""
  const right = match.end < source.length ? source[match.end] : ""
  // '~<login>' is the home-dir shorthand for that user (X5: the login IS an email)
  return left === "/" || left === "\\" || left === "~" || right === "/" || right === "\\"
}

/** domain after the last @ lowercased; exact equality against the allowlist */
function emailDomainAllowed(raw: string, allow: readonly string[] | undefined): boolean {
  if (!allow || allow.length === 0) return false
  const at = raw.lastIndexOf("@")
  if (at < 0) return false
  const domain = raw.slice(at + 1).toLowerCase()
  return allow.includes(domain)
}

function maskFor(p: Pattern, raw: string): string {
  const label = `<REDACTED:${p.category}>`
  if (p.keepLast && raw.length > p.keepLast + 4) {
    return `<REDACTED:${p.category}:${raw.slice(0, 3)}…${raw.slice(-p.keepLast)}>`
  }
  return label
}

function collect(p: Pattern, text: string): Match[] {
  const re = compile(p)
  re.lastIndex = 0
  const out: Match[] = []
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    const group = p.maskGroup ?? 0
    const idx = m.indices?.[group]
    const raw = m[group] ?? m[0]
    if (!idx || raw === undefined || raw === "") {
      if (m[0] === "") re.lastIndex++
      continue
    }
    if (p.luhn && !isLuhnValid(raw)) {
      if (m[0] === "") re.lastIndex++
      continue
    }
    if (p.validate && !p.validate(raw, text, idx[0], idx[1])) {
      if (m[0] === "") re.lastIndex++
      continue
    }
    out.push({ start: idx[0], end: idx[1], category: p.category, matchedBy: p.id, raw, mask: maskFor(p, raw) })
    if (m[0] === "") re.lastIndex++
  }
  return out
}

// --- encoded-blob detection (base64/hex evasion) ---
// A blob that decodes into printable text matching a known pattern is masked
// as a whole. Depth is 1 (no nested decoding) and hard limits bound the cost.
const ENCODED_MAX_BLOBS = 24
const ENCODED_MAX_BLOB_CHARS = 8192
const ENCODED_MIN_DECODED_BYTES = 8

/** printable ratio threshold for treating decoded bytes as text (UTF-8 high bytes allowed) */
const ENCODED_PRINTABLE_RATIO = 0.9

function isMostlyPrintable(bytes: Uint8Array): boolean {
  if (bytes.length < ENCODED_MIN_DECODED_BYTES) return false
  let ok = 0
  for (const b of bytes) {
    if (b === 9 || b === 10 || b === 13 || (b >= 32 && b <= 126) || b >= 128) ok++
  }
  return ok / bytes.length >= ENCODED_PRINTABLE_RATIO
}

/** strict decode: returns bytes only if re-encoding reproduces the input exactly */
function decodeBase64Strict(raw: string): Uint8Array | null {
  const norm = raw.replace(/=+$/, "")
  if (norm.length % 4 === 1) return null
  let bin: string
  try {
    bin = atob(norm)
  } catch {
    return null
  }
  let re: string
  try {
    re = btoa(bin).replace(/=+$/, "")
  } catch {
    return null
  }
  return re === norm ? new Uint8Array([...bin].map((c) => c.charCodeAt(0))) : null
}

function decodeHexStrict(raw: string): Uint8Array | null {
  const h = raw.startsWith("0x") || raw.startsWith("0X") ? raw.slice(2) : raw
  if (h.length % 2 !== 0 || h.length < 16 || !/^[0-9a-fA-F]+$/.test(h)) return null
  const bytes = new Uint8Array(h.length / 2)
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16)
  let re = ""
  for (const b of bytes) re += b.toString(16).padStart(2, "0")
  return re === h.toLowerCase() ? bytes : null
}

interface EncodedBlob {
  start: number
  end: number
  decoded: string
}

function findEncodedBlobs(text: string, isProtected: (s: number, e: number) => boolean): EncodedBlob[] {
  const out: EncodedBlob[] = []
  // same span may match several encodings (a hex string is also valid base64);
  // keep every distinct interpretation and let the caller pick by decoded match
  const seen = new Set<string>()
  const consider = (m: RegExpExecArray, decode: (raw: string) => Uint8Array | null): boolean => {
    if (out.length >= ENCODED_MAX_BLOBS) return false
    const raw = m[0]
    if (raw.length > ENCODED_MAX_BLOB_CHARS) return true
    const start = m.index
    const end = start + raw.length
    if (isProtected(start, end)) return true
    const bytes = decode(raw)
    if (!bytes || !isMostlyPrintable(bytes)) return true
    const decoded = new TextDecoder().decode(bytes)
    const key = `${start}:${end}:${decoded}`
    if (seen.has(key)) return true
    seen.add(key)
    out.push({ start, end, decoded })
    return true
  }
  // standard and url-safe base64
  let m: RegExpExecArray | null
  const b64 = /[A-Za-z0-9+/]{16,}={0,2}/g
  while ((m = b64.exec(text)) !== null) {
    if (!consider(m, decodeBase64Strict)) break
    if (m[0] === "") b64.lastIndex++
  }
  const b64url = /[A-Za-z0-9_-]{16,}={0,2}/g
  while ((m = b64url.exec(text)) !== null) {
    if (!consider(m, (raw) => decodeBase64Strict(raw.replace(/-/g, "+").replace(/_/g, "/")))) break
    if (m[0] === "") b64url.lastIndex++
  }
  const hex = /(?:0[xX])?[0-9a-fA-F]{16,}/g
  while ((m = hex.exec(text)) !== null) {
    if (!consider(m, decodeHexStrict)) break
    if (m[0] === "") hex.lastIndex++
  }
  return out
}

/**
 * Find sensitive data in text. Earlier patterns in the list win overlaps
 * (specific beats generic: jwt before credential-assignment, etc.).
 */
export function scan(text: string, patterns: readonly Pattern[] = DEFAULT_PATTERNS, opts?: ScanOptions): Match[] {
  return scanInner(text, patterns, true, opts)
}

function scanInner(
  text: string,
  patterns: readonly Pattern[],
  allowEncoded: boolean,
  opts?: ScanOptions,
): Match[] {
  if (!text) return []
  // already-masked regions are untouchable: no pattern may fire inside a placeholder
  const protectedSpans: Array<[number, number]> = []
  const ph = /<REDACTED:[a-z-]+(:[^<>]*)?>/g
  let pm: RegExpExecArray | null
  while ((pm = ph.exec(text)) !== null) protectedSpans.push([pm.index, pm.index + pm[0].length])
  const isProtected = (start: number, end: number) =>
    protectedSpans.some(([s, e]) => start < e && end > s)

  // encoded blobs (base64/hex) are decoded and re-scanned; a hit masks the whole blob.
  // The recursive scan runs with allowEncoded=false so decoding depth stays at 1.
  // A span is claimed only when the decoded content actually matches a pattern —
  // otherwise another interpretation of the same span (hex string read as base64)
  // must get its chance.
  const encoded: Match[] = []
  const claimed: Array<[number, number]> = []
  if (allowEncoded) {
    for (const blob of findEncodedBlobs(text, isProtected)) {
      if (claimed.some(([s, e]) => blob.start < e && blob.end > s)) continue
      const decodedMatches = scanInner(blob.decoded, patterns, false, opts)
      if (decodedMatches.length === 0) continue
      claimed.push([blob.start, blob.end])
      const first = decodedMatches[0]
      encoded.push({
        start: blob.start,
        end: blob.end,
        category: first.category,
        matchedBy: `${first.matchedBy}:encoded`,
        raw: text.slice(blob.start, blob.end),
        mask: `<REDACTED:${first.category}:encoded>`,
      })
    }
  }
  const hitsEncoded = (start: number, end: number) =>
    encoded.some((e) => start < e.end && end > e.start)

  const all: { order: number; match: Match }[] = []
  patterns.forEach((p, order) => {
    for (const match of collect(p, text)) {
      if (isProtected(match.start, match.end) || hitsEncoded(match.start, match.end)) continue
      all.push({ order, match })
    }
  })
  for (const e of encoded) all.push({ order: -1, match: e })
  // walk left-to-right in position order; at the same start the earlier
  // (more specific) pattern wins. A wider match starting earlier accepts
  // first and swallows anything nested inside it, so containers like
  // connection-string mask their whole span including embedded keys.
  all.sort((a, b) => a.match.start - b.match.start || a.order - b.order || b.match.end - a.match.end)
  const accepted: Match[] = []
  let cursor = -1
  for (const { match } of all) {
    // FR1: PII inside file paths is not masked (mask would break the command);
    // secrets always stay masked
    if (match.category === "pii" && isPathContext(match, text)) continue
    // FR3: allowlisted email domains are treated as public identifiers
    if (match.matchedBy.split(":")[0] === "pii-email" && emailDomainAllowed(match.raw, opts?.piiEmailAllowDomains)) {
      continue
    }
    if (match.start >= cursor) {
      accepted.push(match)
      cursor = match.end
    }
  }
  return accepted
}

export function redact(text: string, patterns: readonly Pattern[] = DEFAULT_PATTERNS, opts?: ScanOptions): { text: string; matches: Match[] } {
  const matches = scan(text, patterns, opts)
  if (matches.length === 0) return { text, matches }
  let out = text
  for (let i = matches.length - 1; i >= 0; i--) {
    const m = matches[i]
    out = out.slice(0, m.start) + m.mask + out.slice(m.end)
  }
  return { text: out, matches }
}

export type EnvMaskAction = "skip" | "full" | "substring"

export interface EnvMaskResult {
  value: string
  action: EnvMaskAction
  matches: Match[]
}

/**
 * FR2/FR5 (spec: docs/pii-email-spec.md): env value handling for shell.create.before.
 * - secret categories (anything but pii/pii-name) fully replace the value — a
 *   partially masked secret could leave a recognizable remainder;
 * - PII in a CRITICAL_ENV_KEYS var is left untouched — masking it would break
 *   every child process (the X5 $HOME incident);
 * - PII elsewhere masks only the matched substrings.
 */
export function redactEnvValue(
  key: string,
  value: string,
  patterns: readonly Pattern[] = DEFAULT_PATTERNS,
  opts?: ScanOptions,
): EnvMaskResult {
  const matches = scan(value, patterns, opts)
  if (matches.length === 0) return { value, action: "skip", matches }
  const hasNonPii = matches.some((x) => x.category !== "pii" && x.category !== "pii-name")
  if (hasNonPii) return { value: "<REDACTED:env>", action: "full", matches }
  // Windows env keys are case-insensitive (Path, Home); normalize before lookup
  if (CRITICAL_ENV_KEYS.has(key) || CRITICAL_ENV_KEYS.has(key.toUpperCase())) return { value, action: "skip", matches }
  let out = value
  for (let i = matches.length - 1; i >= 0; i--) {
    const m = matches[i]
    out = out.slice(0, m.start) + m.mask + out.slice(m.end)
  }
  return { value: out, action: "substring", matches }
}
