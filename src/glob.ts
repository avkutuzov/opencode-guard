export function normalizePath(p: string): string {
  const collapsed = p.replace(/\\/g, "/").replace(/([^:/])\/{2,}/g, "$1/")
  if (collapsed.length > 1 && collapsed.endsWith("/") && !/^[A-Za-z]:\/$/.test(collapsed)) {
    return collapsed.slice(0, -1)
  }
  return collapsed
}

function escapeSeg(seg: string): string {
  return seg
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "\0") // placeholder so * → [^/]* doesn't touch it
    .replace(/\*/g, "[^/]*")
    .replace(/\?/g, "[^/]")
    .replace(/\0/g, "[^/]*") // "**" inside a segment behaves like "*"
}

/** ".env" should also match ".env.local": allow extra dotted suffix for dotfiles without wildcards */
function dotFileAware(escapedSeg: string): string {
  return /^\\\.[^.[\]*?]+$/.test(escapedSeg) ? `${escapedSeg}(\\..+)?` : escapedSeg
}

/** Convert a glob to an anchored RegExp. No-slash globs match at any depth. */
export function globToRegExp(glob: string): RegExp {
  const segments = glob.split("/")
  let src = ""
  segments.forEach((seg, i) => {
    const piece = seg === "**" ? (i === segments.length - 1 ? ".*" : "(?:[^/]+/)*") : escapeSeg(seg)
    if (i === 0) {
      src = seg === "**" ? "" : piece
      if (seg === "**") src = "(?:.*/)?"
      return
    }
    // a previous "**" piece already ends with "/" inside its group
    src += segments[i - 1] === "**" ? piece : "/" + piece
  })
  if (!glob.includes("/")) src = `(?:^|.*/)${dotFileAware(escapeSeg(glob))}`
  return new RegExp(`^${src}$`)
}

/**
 * "**" as a whole segment matches any depth, including zero directories
 * (trailing "**" keeps a greedy ".*" so ".ssh/**" still requires the ".ssh/" prefix).
 */
function segToRegExp(seg: string, isLast: boolean): string {
  if (seg === "**") return isLast ? ".*" : "(?:[^/]+/)*"
  return escapeSeg(seg)
}

function suffixes(path: string): string[] {
  const parts = path.split("/")
  const out: string[] = [path]
  for (let i = 1; i < parts.length; i++) out.push(parts.slice(i).join("/"))
  return out
}

function globMatches(path: string, glob: string): boolean {
  const re = globToRegExp(glob)
  const candidates = glob.includes("/") ? suffixes(path) : [path]
  return candidates.some((c) => re.test(c))
}

export interface PathLists {
  blockPaths: readonly string[]
  writeProtectPaths: readonly string[]
  exemptPaths: readonly string[]
}

export function isPathExempt(path: string, cfg: PathLists): boolean {
  const p = normalizePath(path)
  return cfg.exemptPaths.some((g) => globMatches(p, g))
}

export function isPathBlocked(path: string, cfg: PathLists): boolean {
  const p = normalizePath(path)
  if (isPathExempt(p, cfg)) return false
  return cfg.blockPaths.some((g) => globMatches(p, g))
}

/** Write-protected: read allowed, write blocked. Exemptions do not apply. */
export function isPathWriteProtected(path: string, cfg: PathLists): boolean {
  const p = normalizePath(path)
  return cfg.writeProtectPaths.some((g) => globMatches(p, g))
}
