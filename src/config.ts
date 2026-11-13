import { homedir } from "node:os"
import { join } from "node:path"

export interface GuardConfig {
  /** enforce: block+redact; warn: audit only */
  mode: "enforce" | "warn"
  scanPrompts: boolean
  redactOnWrite: boolean
  scanOutbound: boolean
  blockPaths: string[]
  writeProtectPaths: string[]
  exemptPaths: string[]
  audit: { enabled: boolean; dir: string }
  disabledPatterns: string[]
}

export const DEFAULT_BLOCK_PATHS: readonly string[] = [
  ".env",
  ".env.*",
  "*.pem",
  "*.key",
  "*.pfx",
  "*.p12",
  "*.keystore",
  "id_rsa*",
  "id_ed25519*",
  ".ssh/**",
  ".aws/**",
  ".gnupg/**",
  "**/credentials",
  "*.tfstate",
  "*.tfstate.*",
  "kubeconfig",
  "**/kube/config",
  "**/*.kubeconfig",
]

export const DEFAULT_AUDIT_DIR = join(homedir(), ".local", "share", "opencode", "guard")

function str(v: unknown): v is string {
  return typeof v === "string" && v.length > 0
}

function strArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every(str)
}

export function resolveConfig(options: unknown): GuardConfig {
  const o = (options ?? {}) as Record<string, unknown>
  const audit = (o.audit ?? {}) as Record<string, unknown>

  return {
    mode: o.mode === "warn" ? "warn" : "enforce",
    scanPrompts: o.scanPrompts !== false,
    redactOnWrite: o.redactOnWrite !== false,
    scanOutbound: o.scanOutbound !== false,
    blockPaths: strArray(o.blockPaths) ? [...new Set([...DEFAULT_BLOCK_PATHS, ...o.blockPaths])] : [...DEFAULT_BLOCK_PATHS],
    writeProtectPaths: strArray(o.writeProtectPaths) ? [...o.writeProtectPaths] : [],
    exemptPaths: strArray(o.exemptPaths) ? [...o.exemptPaths] : [],
    audit: {
      enabled: audit.enabled !== false,
      dir: str(audit.dir) ? audit.dir : DEFAULT_AUDIT_DIR,
    },
    disabledPatterns: strArray(o.disabledPatterns) ? [...o.disabledPatterns] : [],
  }
}
