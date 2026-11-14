import { readdirSync, readFileSync, statSync } from "node:fs"
import { join } from "node:path"
import { scan } from "./scan.ts"
import { DEFAULT_PATTERNS, type Pattern } from "./patterns.ts"

const SKILL_MAX_BYTES = 5_000_000

export interface SkillFinding {
  /** directory name of the skill, e.g. "some-skill" */
  skill: string
  count: number
  categories: string[]
}

/**
 * Scan installed skills (~/.config/opencode/skills/<name>/SKILL.md) for prompt
 * injection and secrets. Returns counters only — never raw fragments, so the
 * report itself cannot leak the injected content. Fails silent.
 */
export function scanSkillDir(
  dir: string,
  patterns: readonly Pattern[] = DEFAULT_PATTERNS,
  exempt: readonly string[] = [],
): SkillFinding[] {
  try {
    const out: SkillFinding[] = []
    for (const entry of readdirSync(dir).sort()) {
      if (exempt.includes(entry)) continue
      try {
        const file = join(dir, entry, "SKILL.md")
        if (statSync(file).size > SKILL_MAX_BYTES) continue
        const text = readFileSync(file, "utf8")
        const matches = scan(text, patterns)
        if (matches.length === 0) continue
        out.push({ skill: entry, count: matches.length, categories: [...new Set(matches.map((m) => m.category))].sort() })
      } catch {
        continue // not a skill dir, unreadable file, race with deletion, etc.
      }
    }
    return out
  } catch {
    return []
  }
}
