import { test } from "node:test"
import assert from "node:assert/strict"
import { parseInstallCommand, levenshtein, isTyposquat, checkInstall, BLOCKED_PACKAGES } from "../src/deps.ts"
import { resolveConfig } from "../src/config.ts"

// --- parseInstallCommand ---

test("parse: npm install basic forms", () => {
  assert.deepEqual(parseInstallCommand("npm install lodash"), {
    manager: "npm",
    packages: [{ name: "lodash", version: undefined }],
  })
  assert.deepEqual(parseInstallCommand("npm i a b"), {
    manager: "npm",
    packages: [{ name: "a", version: undefined }, { name: "b", version: undefined }],
  })
  assert.deepEqual(parseInstallCommand("npm install pkg@1.2.3"), {
    manager: "npm",
    packages: [{ name: "pkg", version: "1.2.3" }],
  })
})

test("parse: scoped names and versions", () => {
  assert.deepEqual(parseInstallCommand("npm i @scope/pkg"), {
    manager: "npm",
    packages: [{ name: "@scope/pkg", version: undefined }],
  })
  assert.deepEqual(parseInstallCommand("npm i @scope/pkg@1.0.0"), {
    manager: "npm",
    packages: [{ name: "@scope/pkg", version: "1.0.0" }],
  })
})

test("parse: flags skipped, env prefix ok, no packages -> null", () => {
  assert.deepEqual(parseInstallCommand("npm i -D pkg"), {
    manager: "npm",
    packages: [{ name: "pkg", version: undefined }],
  })
  assert.equal(parseInstallCommand("npm install"), null)
  assert.equal(parseInstallCommand("npm ci"), null)
  assert.deepEqual(parseInstallCommand("FOO=bar npm i pkg"), {
    manager: "npm",
    packages: [{ name: "pkg", version: undefined }],
  })
})

test("parse: global installs are out of scope", () => {
  assert.equal(parseInstallCommand("npm install -g pkg"), null)
  assert.equal(parseInstallCommand("npm install --global pkg"), null)
})

test("parse: non-install commands -> null", () => {
  assert.equal(parseInstallCommand("npm run build"), null)
  assert.equal(parseInstallCommand("npm run install:all"), null)
  assert.equal(parseInstallCommand("curl -s https://registry.npmjs.org"), null)
  assert.equal(parseInstallCommand("git clone https://github.com/x/y"), null)
})

test("parse: pip and cargo", () => {
  assert.deepEqual(parseInstallCommand("pip install requests==2.31.0"), {
    manager: "pip",
    packages: [{ name: "requests", version: "2.31.0" }],
  })
  assert.deepEqual(parseInstallCommand("pip3 install flask>=2.0"), {
    manager: "pip",
    packages: [{ name: "flask", version: "2.0" }],
  })
  assert.deepEqual(parseInstallCommand("cargo add serde"), {
    manager: "cargo",
    packages: [{ name: "serde", version: undefined }],
  })
})

// --- levenshtein ---

test("levenshtein unit checks", () => {
  assert.equal(levenshtein("abc", "abc"), 0)
  assert.equal(levenshtein("abc", "abd"), 1)
  assert.equal(levenshtein("abc", "ab"), 1)
  assert.equal(levenshtein("kitten", "sitting"), 3)
  assert.equal(levenshtein("lodash", "lodahs"), 1)
})

// --- typosquat ---

test("typosquat: distance-1 to a top name", () => {
  assert.equal(isTyposquat("lodahs"), "lodash")
  assert.equal(isTyposquat("reactt"), "react")
  assert.equal(isTyposquat("axio"), "axios")
})

test("typosquat: clean names", () => {
  assert.equal(isTyposquat("lodash"), null)
  assert.equal(isTyposquat("my-own-pkg-123"), null)
  assert.equal(isTyposquat("moment-js"), null) // distance > 1
})

// --- blocklist ---

test("blocklist: known malicious packages detected, case-insensitive", () => {
  assert.ok(BLOCKED_PACKAGES.has("event-stream"))
  const v = checkInstall("npm install event-stream")
  assert.equal(v?.reason, "blocklist")
  assert.equal(v?.name, "event-stream")
  const v2 = checkInstall("npm install EVENT-STREAM")
  assert.equal(v2?.reason, "blocklist")
})

test("checkInstall: typosquat verdict names the target", () => {
  const v = checkInstall("npm install lodahs")
  assert.equal(v?.reason, "typosquat")
  assert.equal(v?.target, "lodash")
})

test("checkInstall: clean commands -> null", () => {
  assert.equal(checkInstall("npm install lodash"), null)
  assert.equal(checkInstall("npm test"), null)
  assert.equal(checkInstall("pip install requests"), null)
})

test("checkInstall: user blockedPackages extend the built-in list", () => {
  const cfg = resolveConfig({ blockedPackages: ["my-internal-banned"] })
  const v = checkInstall("npm install my-internal-banned", cfg.blockedPackages)
  assert.equal(v?.reason, "blocklist")
})

// --- config ---

test("config: depsCheck default true, disable works, blockedPackages parsed", () => {
  assert.equal(resolveConfig({}).depsCheck, true)
  assert.equal(resolveConfig({ depsCheck: false }).depsCheck, false)
  assert.deepEqual(resolveConfig({ blockedPackages: ["a", "b"] }).blockedPackages, ["a", "b"])
  assert.deepEqual(resolveConfig({}).blockedPackages, [])
  assert.deepEqual(resolveConfig({ allowedPackages: ["rc"] }).allowedPackages, ["rc"])
  assert.deepEqual(resolveConfig({}).allowedPackages, [])
})

// --- review pass 1 regressions ---

test("C1: compound commands are scanned segment by segment", () => {
  assert.equal(checkInstall("cd proj && npm install event-stream")?.reason, "blocklist")
  assert.equal(checkInstall("cat x | npm install lodahs")?.reason, "typosquat")
  assert.equal(checkInstall("echo hi; npm install event-stream")?.reason, "blocklist")
  assert.equal(checkInstall("sudo -E npm install event-stream")?.reason, "blocklist")
  assert.equal(checkInstall("sudo -u root npm install lodahs")?.reason, "typosquat")
  assert.equal(checkInstall("env FOO=bar npm install event-stream")?.reason, "blocklist")
})

test("M1: flag operands are not package names", () => {
  assert.equal(checkInstall("npm install --prefix rc lodash"), null)
  assert.equal(checkInstall("pip install -r rc"), null)
  assert.equal(checkInstall("npm i lodash -w app"), null)
  assert.equal(checkInstall("pip install -r requirements.txt"), null)
})

test("M2: registry names are case-insensitive — Lodash is not a squat", () => {
  assert.equal(checkInstall("npm i Lodash"), null)
  assert.equal(checkInstall("npm i LODASH"), null)
})

test("multi-package commands: second package violations caught", () => {
  assert.equal(checkInstall("npm install qs event-stream")?.name, "event-stream")
  assert.equal(checkInstall("npm install qs lodahs")?.target, "lodash")
  assert.equal(checkInstall("npm install qs && npm install coa")?.name, "coa")
})

test("quoted and local/git specs are handled", () => {
  assert.equal(checkInstall('npm install "event-stream"')?.reason, "blocklist")
  assert.equal(checkInstall("npm install ./local-dir"), null)
  assert.equal(checkInstall("npm install github:user/repo"), null)
  assert.equal(checkInstall("npm install ../event-stream"), null)
})

test("known gaps pinned: dry-run blocked, npx not covered, scoped squat not covered", () => {
  // --dry-run still blocks (nothing installs, but we keep it simple and safe)
  assert.equal(checkInstall("npm install lodahs --dry-run")?.reason, "typosquat")
  // npx executes packages without install — phase 2.5
  assert.equal(checkInstall("npx lodahs"), null)
  // scoped names are not squat-checked — phase 2.5
  assert.equal(checkInstall("npm i @types/lodahs"), null)
})

test("allowedPackages exempts from the blocklist", () => {
  assert.equal(checkInstall("npm install rc", [], ["rc"]), null)
  assert.equal(checkInstall("npm install rc", [], ["RC"]), null)
})

test("pip/cargo go through the blocklist (no squat check)", () => {
  assert.equal(checkInstall("pip install event-stream")?.reason, "blocklist")
  assert.equal(checkInstall("pip install requests"), null) // legit, no squat outside npm
  assert.equal(checkInstall("cargo add serde"), null)
})

// --- review of live dogfood (npm-published 1.0.0): Windows manager suffixes ---

test("Windows: npm.cmd / pnpm.cmd / yarn.cmd / pip.exe are recognized as managers", () => {
  assert.equal(checkInstall("npm.cmd install lodahs")?.reason, "typosquat")
  assert.equal(checkInstall("npm.cmd install event-stream")?.reason, "blocklist")
  assert.equal(checkInstall("pnpm.cmd add lodahs")?.reason, "typosquat")
  assert.equal(checkInstall("yarn.cmd add event-stream")?.reason, "blocklist")
  assert.equal(checkInstall("pip.exe install event-stream")?.reason, "blocklist")
  assert.equal(checkInstall("npm.cmd install lodash"), null)
  assert.equal(checkInstall("npm.cmd test"), null)
})
