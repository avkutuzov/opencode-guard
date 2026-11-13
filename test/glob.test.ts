import { test } from "node:test"
import assert from "node:assert/strict"
import { globToRegExp, isPathBlocked, isPathWriteProtected, isPathExempt, normalizePath } from "../src/glob.ts"
import { resolveConfig } from "../src/config.ts"

test("normalizePath converts backslashes and strips trailing slash", () => {
  assert.equal(normalizePath("C:\\proj\\a\\.env"), "C:/proj/a/.env")
  assert.equal(normalizePath("C:/proj/a/.env"), "C:/proj/a/.env")
  assert.equal(normalizePath("dir/.env/"), "dir/.env")
  assert.equal(normalizePath("C:/"), "C:/")
})

test("glob *.pem matches basename in any directory", () => {
  const re = globToRegExp("*.pem")
  assert.ok(re.test("keys/server.pem"))
  assert.ok(re.test("server.pem"))
  assert.ok(!re.test("server.pem.txt"))
})

test("glob .env matches .env and .env.local but not env.txt", () => {
  const re = globToRegExp(".env")
  assert.ok(re.test(".env"))
  assert.ok(re.test(".env.local"))
  assert.ok(re.test("config/.env"))
  assert.ok(!re.test("env.txt"))
  assert.ok(!re.test("environment"))
})

test("glob .ssh/** matches everything under .ssh", () => {
  const re = globToRegExp(".ssh/**")
  assert.ok(re.test(".ssh/config"))
  assert.ok(re.test(".ssh/keys/id_rsa"))
  assert.ok(!re.test(".sshrc"))
})

test("mid-pattern ** matches zero directories", () => {
  const re = globToRegExp("a/**/b")
  assert.ok(re.test("a/b"))
  assert.ok(re.test("a/x/b"))
  assert.ok(re.test("a/x/y/b"))
  assert.ok(!re.test("a/c"))
})

test("glob id_rsa* matches id_rsa and id_rsa.pub", () => {
  const re = globToRegExp("id_rsa*")
  assert.ok(re.test("id_rsa"))
  assert.ok(re.test("id_rsa.pub"))
  assert.ok(!re.test("my_id_rsa"))
})

test("default config blocks sensitive paths (both separators)", () => {
  const cfg = resolveConfig({})
  for (const p of [
    "C:/proj/.env",
    "C:\\proj\\app\\.env.local",
    "keys/server.pem",
    "user/.ssh/config",
    "user/.aws/credentials",
    "secrets/id_rsa",
    "kube/config",
    "state.tfstate",
  ]) {
    assert.ok(isPathBlocked(p, cfg), `should be blocked: ${p}`)
  }
})

test("normal source files are not blocked", () => {
  const cfg = resolveConfig({})
  for (const p of ["src/index.ts", "README.md", "package.json", "src/config.ts"]) {
    assert.ok(!isPathBlocked(p, cfg), `should NOT be blocked: ${p}`)
  }
})

test("write-protected paths: read allowed, write blocked", () => {
  const cfg = resolveConfig({ writeProtectPaths: ["logs/**"] })
  assert.ok(isPathWriteProtected("logs/app.log", cfg))
  assert.ok(!isPathBlocked("logs/app.log", cfg))
})

test("exempt paths override block list", () => {
  const cfg = resolveConfig({ exemptPaths: ["fixtures/**"] })
  assert.ok(isPathExempt("fixtures/sample.env", cfg))
  assert.ok(!isPathBlocked("fixtures/sample.env", cfg))
  assert.ok(isPathBlocked("src/.env", cfg))
})

test("user blockPaths extend defaults (union, defaults never silently lost)", () => {
  const cfg = resolveConfig({ blockPaths: ["secrets/**"] })
  assert.ok(isPathBlocked("secrets/a.txt", cfg))
  assert.ok(isPathBlocked(".env", cfg))
})

test("resolveConfig merges scalars and keeps defaults for missing keys", () => {
  const cfg = resolveConfig({ mode: "warn", scanPrompts: false })
  assert.equal(cfg.mode, "warn")
  assert.equal(cfg.scanPrompts, false)
  assert.equal(cfg.redactOnWrite, true)
  assert.ok(cfg.blockPaths.length > 0)
})

test("resolveConfig appends extraPatterns-like arrays and honors disabledPatterns", () => {
  const cfg = resolveConfig({
    disabledPatterns: ["pii-email"],
    writeProtectPaths: ["var/**"],
  })
  assert.ok(cfg.disabledPatterns.includes("pii-email"))
  assert.ok(isPathWriteProtected("var/x.log", cfg))
})
