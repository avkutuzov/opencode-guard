import { test } from "node:test"
import assert from "node:assert/strict"
import { scan, redact, redactEnvValue, isLuhnValid } from "../src/scan.ts"
import { CRITICAL_ENV_KEYS } from "../src/config.ts"
import { DEFAULT_PATTERNS } from "../src/patterns.ts"

const pats = DEFAULT_PATTERNS

test("detects OpenAI-style sk- key", () => {
  const m = scan("ключ: sk-AbCdEfGhIjKlMnOpQrStUvWx", pats)
  assert.equal(m.length, 1)
  assert.equal(m[0].category, "api-key")
})

test("detects GitHub token", () => {
  const m = scan("ghp_AbCdEfGhIjKlMnOpQrStUvWx1234567890", pats)
  assert.ok(m.some((x) => x.category === "api-key"))
})

test("detects JWT (header.payload.signature)", () => {
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
  const m = scan(`auth: ${jwt}`, pats)
  assert.ok(m.some((x) => x.category === "token"))
})

test("detects AWS access key id", () => {
  const m = scan("AKIAIOSFODNN7EXAMPLE", pats)
  assert.ok(m.some((x) => x.category === "api-key"))
})

test("detects PEM private key block spanning lines", () => {
  const pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----"
  const m = scan(pem, pats)
  assert.ok(m.some((x) => x.category === "private-key"))
  const r = redact(pem, pats)
  assert.ok(!r.text.includes("b3BlbnNzaC1rZXktdjE"))
  assert.ok(r.text.includes("<REDACTED:private-key>"))
})

test("detects credential assignment and masks only the value", () => {
  const r = redact('password = "hunter2"', pats)
  assert.ok(r.text.includes("password=") || r.text.includes("password ="))
  assert.ok(!r.text.includes("hunter2"))
  assert.ok(r.text.includes("<REDACTED:credential>"))
})

test("detects Bearer token", () => {
  const m = scan('Authorization: Bearer abcDEF123_abcDEF123_abcDEF123', pats)
  assert.ok(m.some((x) => x.category === "token"))
})

test("detects postgres connection string with password", () => {
  const m = scan("DATABASE_URL=postgres://admin:s3cretP@ss@db.internal:5432/app", pats)
  assert.ok(m.some((x) => x.category === "connection-string"))
})

test("detects ИНН only with context word (no noise from plain 12 digits)", () => {
  assert.equal(scan("сумма 771501234512 перевод", pats).length, 0)
  const m = scan("ИНН: 771501234512", pats)
  assert.ok(m.some((x) => x.category === "pii"))
})

test("detects СНИЛС", () => {
  const m = scan("СНИЛС 123-456-789 01", pats)
  assert.ok(m.some((x) => x.category === "pii"))
})

test("detects Russian phone +7 and 8(9xx) formats", () => {
  for (const s of ["+7 916 123-45-67", "+7(916)1234567", "8 916 123 45 67", "89161234567"]) {
    assert.ok(scan(s, pats).some((x) => x.category === "pii"), `should detect: ${s}`)
  }
})

test("detects email as PII", () => {
  const m = scan("mail ivan.petrov@example.com end", pats)
  assert.ok(m.some((x) => x.category === "pii"))
})

test("detects ФИО only with context marker, masks only the name", () => {
  const r = redact("ФИО: Иванова Мария Сергеевна, статус ок", pats)
  assert.ok(!r.text.includes("Иванова"))
  assert.ok(r.text.includes("<REDACTED:pii-name>"))
  assert.ok(r.text.includes("статус ок"))
  // без контекстного маркера — не трогаем
  assert.equal(scan("Иванова Мария Сергеевна пришла", pats).length, 0)
})

test("detects паспорт with context word", () => {
  const m = scan("паспорт 4510 № 123456 выдан", pats)
  assert.ok(m.some((x) => x.category === "pii"))
  assert.equal(scan("документы 4510 123456 лежат", pats).filter((x) => x.category === "pii" && /паспорт/i.test(x.matchedBy)).length, 0)
})

test("detects Luhn-valid card, ignores random 16-digit number", () => {
  assert.ok(scan("карта 4111 1111 1111 1111", pats).some((x) => x.category === "pii"))
  assert.equal(scan("id 1234 5678 9012 3456", pats).length, 0)
})

test("clean text has no matches", () => {
  const clean = "привет, сделай рефакторинг src/index.ts и запусти тесты"
  assert.equal(scan(clean, pats).length, 0)
})

test("redact replaces multiple secrets and reports each category", () => {
  const r = redact("key=sk-AbCdEfGhIjKlMnOpQrStUvWx и ИНН: 771501234512", pats)
  assert.ok(!r.text.includes("AbCdEfGhIjKl"))
  assert.ok(!r.text.includes("771501234512"))
  assert.ok(r.matches.length >= 2)
})

test("redact is idempotent", () => {
  const once = redact("sk-AbCdEfGhIjKlMnOpQrStUvWx", pats).text
  const twice = redact(once, pats)
  assert.equal(twice.text, once)
  assert.equal(twice.matches.length, 0)
})

test("overlapping patterns: JWT not double-masked by generic token pattern", () => {
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
  const r = redact(`token ${jwt}`, pats)
  assert.equal(r.text.match(/<REDACTED:token>/g)?.length ?? 0, 1)
  assert.ok(!r.text.includes("eyJhbGciOiJIUzI1NiJ9"))
})

test("Luhn validator unit checks", () => {
  assert.ok(isLuhnValid("4111111111111111"))
  assert.ok(!isLuhnValid("4111111111111112"))
  assert.ok(isLuhnValid("4111 1111 1111 1111"))
})

test("long token-like strings with known prefix keep last 4 chars in labeled mask", () => {
  const r = redact("sk-AbCdEfGhIjKlMnOpQrStUvWx", pats)
  assert.ok(r.text.startsWith("<REDACTED:api-key:sk-…"))
  assert.ok(r.text.endsWith("UvWx>"))
})

test("password is fully masked (never keeps suffix)", () => {
  const r = redact("password=hunter2", pats)
  assert.ok(!r.text.includes("hunter2"))
  assert.ok(!r.text.includes("ter2"))
})

test("containment: api-key inside connection-string is fully covered by the outer mask", () => {
  const r = redact("<REDACTED:connection-string>db:5432/app", pats)
  assert.ok(!r.text.includes("AbCdEfGhIjKl"))
  assert.ok(!r.text.includes("admin:"))
  assert.ok(r.text.includes("<REDACTED:connection-string>"))
})

test("late-priority pattern at an early position is not swallowed (cross-line)", () => {
  // fio-context is last in the pattern list but must still match on its line
  const text = "api_key=sk-AbCdEfGhIjKlMnOpQrStUvWx\npassword=hunter2\nИНН: 771501234512\nФИО: Иванова Мария Сергеевна\n+7 916 123-45-67"
  const m = scan(text)
  assert.ok(m.some((x) => x.matchedBy === "fio-context"), "fio must be found")
  assert.equal(m.length, 5)
})

test("phone does not match inside a long digit run", () => {
  assert.equal(scan("счет 812345678901234 оплачен", pats).length, 0)
})

test("stripe, gitlab, telegram tokens detected", () => {
  assert.ok(scan("sk_live_4eC39HqLyjWDarjtT1zdp7dc", pats).some((x) => x.matchedBy === "stripe-key"))
  assert.ok(scan("glpat-x1y2z3a4b5c6d7e8f9g0h1i2j3k4l5m6n7o8", pats).some((x) => x.matchedBy === "gitlab-pat"))
  assert.ok(scan("123456789:ABCdefGHIjklMNOpqrSTUvwxyz012345678", pats).some((x) => x.matchedBy === "telegram-bot-token"))
})

// --- context-safe email masking (spec: docs/pii-email-spec.md, корп. field lessons) ---

const EM = "user" + "@" + "corp.example"
const SKK = "sk-ABCD" + "EFGH1234567890"

test("FR1: pii email inside a file path is not masked", () => {
  assert.equal(redact("ls /home/" + EM + "/.config", pats).text, "ls /home/" + EM + "/.config")
  assert.equal(redact("ls /home/" + EM, pats).text, "ls /home/" + EM)
  assert.equal(redact(String.raw`dir C:\\Users\\${EM}\\docs`, pats).text, String.raw`dir C:\\Users\\${EM}\\docs`)
  assert.equal(redact("cat ~/proj/" + EM + "/file.txt", pats).text, "cat ~/proj/" + EM + "/file.txt")
  assert.equal(redact("open " + EM + "/file", pats).text, "open " + EM + "/file")
})

test("FR1: email in plain text is still masked (G2)", () => {
  assert.equal(redact("mail me: " + EM + ".", pats).text, "mail me: <REDACTED:pii>.")
  assert.equal(redact("email: " + EM, pats).text, "email: <REDACTED:pii>")
  assert.equal(redact("mailto:" + EM, pats).text, "mailto:<REDACTED:pii>")
  assert.equal(redact("contact: " + EM + " end", pats).text, "contact: <REDACTED:pii> end")
})

test("FR1 resolved: scp-style <REDACTED:pii> is NOT a path and gets masked", () => {
  const dotted = "user" + "@" + "host.com"
  const r = redact("scp " + dotted + ":~/file.txt .", pats)
  assert.equal(r.text, "scp <REDACTED:pii>:~/file.txt .")
  const plain = "user" + "@" + "host"
  assert.equal(redact("scp " + plain + ":~/f .", pats).text, "scp " + plain + ":~/f .")
})

test("FR1/G3: secrets are masked even inside paths", () => {
  const km = "<REDACTED:api-" + "key:sk-…7890>"
  assert.equal(redact("cat /tmp/" + SKK + "/x", pats).text, "cat /tmp/" + km + "/x")
})

test("FR3: domain allowlist keeps listed emails unmasked, case-insensitive", () => {
  const opts = { piiEmailAllowDomains: ["corp.example"] }
  const up = "user" + "@" + "CORP.EXAMPLE"
  assert.equal(redact("owner " + up + " here", pats, opts).text, "owner " + up + " here")
  const other = "user" + "@" + "other.com"
  assert.equal(redact("owner " + other + " here", pats, opts).text, "owner <REDACTED:pii> here")
})

test("FR3: allowlist is exact-domain only - subdomains and lookalikes are masked", () => {
  const opts = { piiEmailAllowDomains: ["corp.example"] }
  const sub = "user" + "@" + "mail.corp.example"
  assert.equal(redact("mail " + sub + " end", pats, opts).text, "mail <REDACTED:pii> end")
  const look = "user" + "@" + "corp.example.evil.com"
  assert.equal(redact("mail " + look + " end", pats, opts).text, "mail <REDACTED:pii> end")
})

test("FR3: allowlisted email inside a path stays unmasked (path-context agrees)", () => {
  const opts = { piiEmailAllowDomains: ["corp.example"] }
  assert.equal(redact("ls /home/" + EM + "/x", pats, opts).text, "ls /home/" + EM + "/x")
})

test("FR3/G3: allowlist does not lift secrets - connection string still masked", () => {
  const opts = { piiEmailAllowDomains: ["db.corp.example"] }
  const cs = "postgres://u:" + "s3cret@" + "db.corp.example:5432/app"
  const r = redact("url " + cs, pats, opts)
  assert.ok(r.matches.some((x) => x.category === "connection-string"))
  assert.equal(r.text, "url <REDACTED:connection-string>db.corp.example:5432/app")
})

// --- FR2/FR5: env value handling (корп. инцидент: broken HOME) ---

test("FR2: PII in a critical env var is left untouched", () => {
  const r = redactEnvValue("HOME", "/home/" + EM, pats)
  assert.equal(r.action, "skip")
  assert.equal(r.value, "/home/" + EM)
})

test("FR2: every CRITICAL_ENV_KEYS entry skips PII", () => {
  for (const key of CRITICAL_ENV_KEYS) {
    const r = redactEnvValue(key, "prefix " + EM + " suffix", pats)
    assert.equal(r.action, "skip", key + " must skip PII")
    assert.equal(r.value, "prefix " + EM + " suffix")
  }
})

test("FR2/G3: secrets are fully replaced even in critical env vars", () => {
  const r = redactEnvValue("HOME", "x " + SKK + " y", pats)
  assert.equal(r.action, "full")
  assert.equal(r.value, "<REDACTED:env>")
})

test("FR5: PII in a non-critical env var masks only the substring", () => {
  const r = redactEnvValue("WORKMAIL", "work " + EM + " mail", pats)
  assert.equal(r.action, "substring")
  assert.equal(r.value, "work <REDACTED:pii> mail")
})

test("FR5: clean env values are skipped without changes", () => {
  const r = redactEnvValue("PATH", "/usr/bin:/bin", pats)
  assert.equal(r.action, "skip")
  assert.equal(r.value, "/usr/bin:/bin")
})

test("FR5: email-shaped value that is a path stays whole (no matches at all)", () => {
  const r = redactEnvValue("WORKDIR", "/home/" + EM, pats)
  assert.equal(r.action, "skip")
  assert.equal(r.value, "/home/" + EM)
})

test("FR2/FR5: mixed nonPii+PII in one var fully replaces (secrets win)", () => {
  const r = redactEnvValue("LEGACY", "mail " + EM + " key " + SKK, pats)
  assert.equal(r.action, "full")
  assert.equal(r.value, "<REDACTED:env>")
})

test("FR3: allowlisted email in a non-critical env var is left whole", () => {
  const r = redactEnvValue("WORKMAIL", "work " + EM + " mail", pats, { piiEmailAllowDomains: ["corp.example"] })
  assert.equal(r.action, "skip")
  assert.equal(r.value, "work " + EM + " mail")
})

// --- review pass 1 regressions (v1.2) ---

test("R1: tilde home shorthand with an email login is a path and stays whole", () => {
  assert.equal(redact("ls ~/" + EM + "/f", pats).text, "ls ~/" + EM + "/f")
  assert.equal(redact("ls ~" + EM, pats).text, "ls ~" + EM)
})

test("R1: quoted path with email stays whole", () => {
  assert.equal(redact('ls "/home/' + EM + '"', pats).text, 'ls "/home/' + EM + '"')
})

test("R1 boundary: pii-name with a trailing separator is still masked (category pii-name)", () => {
  const r = redact("ФИО: Ивано" + "ва Ма" + "рия Сер" + "геевна/", pats)
  assert.equal(r.matches.filter((x) => x.category === "pii-name").length, 1)
})

test("R1 boundary: phone and card in paths are skipped like email (category pii)", () => {
  assert.equal(redact("cat /x/<REDACTED:pii>/y", pats).text, "cat /x/<REDACTED:pii>/y")
  assert.equal(redact("cat /x/771501234512/y", pats).text, "cat /x/771501234512/y")
})

test("R2 windows: env key case-insensitive for the critical list", () => {
  const r1 = redactEnvValue("Path", "prefix " + EM + " suffix", pats)
  assert.equal(r1.action, "skip")
  const r2 = redactEnvValue("home", "prefix " + EM + " suffix", pats)
  assert.equal(r2.action, "skip")
  const r3 = redactEnvValue("HOMEPATH", "x " + SKK + " y", pats)
  assert.equal(r3.action, "full")
})

test("R4: pii-email has no quadratic backtracking on long class runs", () => {
  const digits = "7".repeat(100000)
  let t0 = performance.now()
  const m1 = scan(digits, pats)
  const d1 = performance.now() - t0
  assert.equal(m1.length, 0)
  assert.ok(d1 < 500, "100K digit run must scan under 500ms, took " + d1.toFixed(1))
  const dots = "a.".repeat(50000)
  t0 = performance.now()
  const m2 = scan(dots, pats)
  const d2 = performance.now() - t0
  assert.equal(m2.length, 0)
  assert.ok(d2 < 500, "100K a-dot run must scan under 500ms, took " + d2.toFixed(1))
})

test("R4 boundary: local part up to 64 chars is detected, 65 is not (RFC)", () => {
  const dom = "@" + "d.com"
  const ok64 = "a".repeat(64) + dom
  assert.equal(scan(ok64, pats).length, 1, "64-char local part is a valid email")
  const giant = "a".repeat(1000) + dom
  const t0 = performance.now()
  const mg = scan(giant, pats)
  assert.equal(mg.length, 1, "over-long local still matches its RFC-valid 64-char tail")
  assert.ok(performance.now() - t0 < 500)
})

test("R3: allowlist reaches encoded email through the decoded rescan", () => {
  const opts = { piiEmailAllowDomains: ["corp.example"] }
  const b64 = Buffer.from("mail " + EM + " end").toString("base64")
  assert.equal(scan(b64, pats, opts).length, 0)
  const other = "user" + "@" + "other.com"
  const b64b = Buffer.from("mail " + other + " end").toString("base64")
  assert.ok(scan(b64b, pats, opts).some((x) => x.matchedBy.startsWith("pii-email")))
})


