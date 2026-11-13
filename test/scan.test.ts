import { test } from "node:test"
import assert from "node:assert/strict"
import { scan, redact, isLuhnValid } from "../src/scan.ts"
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
