import { test } from "node:test"
import assert from "node:assert/strict"
import { resolveConfig, CRITICAL_ENV_KEYS, DEFAULT_AUDIT_DIR } from "../src/config.ts"

test("resolveConfig: piiEmailAllowDomains defaults to empty", () => {
  const cfg = resolveConfig({})
  assert.deepEqual(cfg.piiEmailAllowDomains, [])
})

test("resolveConfig: piiEmailAllowDomains parsed and lowercased; non-array ignored", () => {
  const cfg = resolveConfig({ piiEmailAllowDomains: ["CORP.EXAMPLE", "Corp.Example.COM"] })
  assert.deepEqual(cfg.piiEmailAllowDomains, ["corp.example", "corp.example.com"])
  assert.deepEqual(resolveConfig({ piiEmailAllowDomains: "corp.example" }).piiEmailAllowDomains, [])
  assert.deepEqual(resolveConfig({ piiEmailAllowDomains: ["ok", 5] }).piiEmailAllowDomains, [])
})

test("CRITICAL_ENV_KEYS covers the corp-critical vars and nothing exotic", () => {
  for (const k of ["HOME", "USERPROFILE", "HOMEPATH", "HOMEDRIVE", "PATH", "PWD", "OLDPWD", "USER", "USERNAME", "LOGNAME", "SHELL", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "TERM", "SHLVL", "HOSTNAME"]) {
    assert.ok(CRITICAL_ENV_KEYS.has(k), `${k} must be critical`)
  }
  assert.ok(!CRITICAL_ENV_KEYS.has("WORKMAIL"))
  assert.ok(!CRITICAL_ENV_KEYS.has("MY_TOKEN"))
})

test("resolveConfig: existing defaults unchanged (mode, audit dir)", () => {
  const cfg = resolveConfig({})
  assert.equal(cfg.mode, "enforce")
  assert.equal(cfg.audit.dir, DEFAULT_AUDIT_DIR)
  assert.equal(cfg.postAudit, true)
})
