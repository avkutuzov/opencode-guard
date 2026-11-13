import { test } from "node:test"
import assert from "node:assert/strict"
import { scan, redact } from "../src/scan.ts"
import { DEFAULT_PATTERNS } from "../src/patterns.ts"

// Fixtures are assembled at runtime from pieces: the guard itself redacts
// literal secrets from tool input, so no single literal here may match a pattern.
const pats = DEFAULT_PATTERNS
const b64e = (s: string) => Buffer.from(s, "utf8").toString("base64")
const hexE = (s: string) => Buffer.from(s, "utf8").toString("hex")
const A24 = "AbCdEfGhIjKlMnOpQrStUvWx"
const A34 = A24 + "1234567890"
const SK = ["sk", A24].join("-")
const GHP = ["ghp", A34].join("_")
const INN_DIGITS = "7715" + "01234512"

test("base64-encoded api key is decoded and the blob is masked", () => {
  const blob = b64e(["signed with", SK].join(" "))
  const r = redact(`заметка в base64: ${blob}`, pats)
  assert.ok(!r.text.includes(blob), "encoded blob must be gone")
  assert.ok(r.text.includes("<REDACTED:api-key:encoded>"))
  assert.ok(r.matches.some((x) => x.matchedBy === "openai-key:encoded"))
})

test("url-safe base64-encoded secret is masked", () => {
  const blob = b64e(["payload", GHP].join(" ")).replace(/\+/g, "-").replace(/\//g, "_")
  const r = redact(`jwt: ${blob}`, pats)
  assert.ok(!r.text.includes(blob))
  assert.ok(r.text.includes("<REDACTED:api-key:encoded>"))
  assert.ok(r.matches.some((x) => x.matchedBy.startsWith("github-token")))
})

test("hex-encoded github token is masked", () => {
  const blob = hexE(GHP)
  const r = redact(`hex: ${blob}`, pats)
  assert.ok(!r.text.includes(blob))
  assert.ok(r.text.includes("<REDACTED:api-key:encoded>"))
})

test("hex with 0x prefix is masked (span covers the prefix)", () => {
  const blob = "0x" + hexE(SK)
  const r = redact(`val = ${blob};`, pats)
  assert.ok(!r.text.includes(blob))
  assert.ok(r.text.includes("<REDACTED:api-key:encoded>"))
})

test("base64 of plain text without secrets is not flagged", () => {
  const blob = b64e("hello world, this is a completely normal sentence")
  assert.equal(scan(`note: ${blob}`, pats).length, 0)
})

test("hex sha256-like digest is not flagged (decodes to garbage)", () => {
  const digest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
  assert.equal(scan(`sha256=${digest}`, pats).length, 0)
})

test("base64 of UTF-8 Russian PII (INN) is masked", () => {
  const blob = b64e(["ИНН", INN_DIGITS].join(": "))
  const r = redact(`b64: ${blob}`, pats)
  assert.ok(!r.text.includes(blob))
  assert.ok(r.text.includes("<REDACTED:pii:encoded>"))
  assert.ok(r.matches.some((x) => x.matchedBy === "inn:encoded"))
})

test("blob with several decoded secrets is masked once as a whole", () => {
  const payload = ["signed with", SK, "and", "INN", INN_DIGITS].join(" ")
  const blob = b64e(payload)
  const r = redact(`data: ${blob}`, pats)
  assert.ok(!r.text.includes(blob))
  assert.equal(r.matches.length, 1, "whole blob must be a single encoded match")
  assert.ok(r.text.includes("<REDACTED:api-key:encoded>"))
})

test("encoded masking is idempotent", () => {
  const once = redact(`k=${b64e(["signed with", SK].join(" "))}`, pats).text
  const twice = redact(once, pats)
  assert.equal(twice.text, once)
  assert.equal(twice.matches.length, 0)
})

test("PEM body is not a false positive: block pattern fires, no encoded match", () => {
  // assembled at runtime: a literal PEM block in tool input would be redacted
  // by the live guard itself before it ever reaches the file
  const d = "-".repeat(5)
  const hdr = [d, "BEGIN OPENSSH PRIVATE KEY", d].join("")
  const ftr = [d, "END OPENSSH PRIVATE KEY", d].join("")
  const body = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQ"
  const body2 = "AAACBvY3J1cHRlZHdpdGhjdHR5cGVwYWRkaW5ncGFkZGluZ3BhZGRpbmdwYWRkaW5ncGFkZGluZ3BhZGRpbmc"
  const pem = [hdr, body, body2, ftr].join("\n")
  const m = scan(pem, pats)
  assert.ok(m.some((x) => x.matchedBy === "private-key-block"))
  assert.ok(!m.some((x) => x.matchedBy.endsWith(":encoded")))
})
