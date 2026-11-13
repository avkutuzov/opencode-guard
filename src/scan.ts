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
    out.push({ start: idx[0], end: idx[1], category: p.category, matchedBy: p.id, raw, mask: maskFor(p, raw) })
    if (m[0] === "") re.lastIndex++
  }
  return out
}

/**
 * Find sensitive data in text. Earlier patterns in the list win overlaps
 * (specific beats generic: jwt before credential-assignment, etc.).
 */
export function scan(text: string, patterns: readonly Pattern[] = DEFAULT_PATTERNS): Match[] {
  if (!text) return []
  // already-masked regions are untouchable: no pattern may fire inside a placeholder
  const protectedSpans: Array<[number, number]> = []
  const ph = /<REDACTED:[a-z-]+(:[^<>]*)?>/g
  let pm: RegExpExecArray | null
  while ((pm = ph.exec(text)) !== null) protectedSpans.push([pm.index, pm.index + pm[0].length])
  const isProtected = (start: number, end: number) =>
    protectedSpans.some(([s, e]) => start < e && end > s)

  const all: { order: number; match: Match }[] = []
  patterns.forEach((p, order) => {
    for (const match of collect(p, text)) {
      if (!isProtected(match.start, match.end)) all.push({ order, match })
    }
  })
  // walk left-to-right in position order; at the same start the earlier
  // (more specific) pattern wins. A wider match starting earlier accepts
  // first and swallows anything nested inside it, so containers like
  // connection-string mask their whole span including embedded keys.
  all.sort((a, b) => a.match.start - b.match.start || a.order - b.order || b.match.end - a.match.end)
  const accepted: Match[] = []
  let cursor = -1
  for (const { match } of all) {
    if (match.start >= cursor) {
      accepted.push(match)
      cursor = match.end
    }
  }
  return accepted
}

export function redact(text: string, patterns: readonly Pattern[] = DEFAULT_PATTERNS): { text: string; matches: Match[] } {
  const matches = scan(text, patterns)
  if (matches.length === 0) return { text, matches }
  let out = text
  for (let i = matches.length - 1; i >= 0; i--) {
    const m = matches[i]
    out = out.slice(0, m.start) + m.mask + out.slice(m.end)
  }
  return { text: out, matches }
}
