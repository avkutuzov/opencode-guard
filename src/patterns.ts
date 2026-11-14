export type PatternCategory =
  | "api-key"
  | "token"
  | "private-key"
  | "credential"
  | "connection-string"
  | "pii"
  | "pii-name"
  | "prompt-injection"

export interface Pattern {
  /** stable id, used in audit and disabledPatterns */
  id: string
  category: PatternCategory
  /** regex source; compiled lazily with flags + "gd" */
  regex: string
  flags?: string
  /** capture group to mask; 0 = whole match (default) */
  maskGroup?: number
  /** keep last N chars visible in the mask (e.g. sk-…UvWx); omitted = full mask */
  keepLast?: number
  /** validate digit-only match with Luhn before accepting */
  luhn?: boolean
  /** arbitrary acceptance check; gets the raw span and its position in the full text */
  validate?: (raw: string, text: string, start: number, end: number) => boolean
}

export const DEFAULT_PATTERNS: readonly Pattern[] = [
  // --- private keys (whole block) ---
  {
    id: "private-key-block",
    category: "private-key",
    regex: "-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----[\\s\\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----",
  },
  // --- cloud / service API keys ---
  { id: "stripe-key", category: "api-key", regex: "(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}", keepLast: 4 },
  { id: "gitlab-pat", category: "api-key", regex: "glpat-[A-Za-z0-9_-]{20,}", keepLast: 4 },
  { id: "telegram-bot-token", category: "api-key", regex: "\\d{8,10}:[A-Za-z0-9_-]{35}", keepLast: 4 },
  { id: "slack-webhook", category: "api-key", regex: "https://hooks\\.slack\\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+", keepLast: 4 },
  { id: "openai-key", category: "api-key", regex: "sk-[A-Za-z0-9_-]{10,}", keepLast: 4 },
  { id: "github-token", category: "api-key", regex: "gh[pousr]_[A-Za-z0-9]{20,}", keepLast: 4 },
  { id: "github-fine-pat", category: "api-key", regex: "github_pat_[A-Za-z0-9_]{20,}", keepLast: 4 },
  { id: "slack-token", category: "api-key", regex: "xox[baprs]-[A-Za-z0-9-]{10,}", keepLast: 4 },
  { id: "aws-access-key", category: "api-key", regex: "(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}", keepLast: 4 },
  { id: "google-api-key", category: "api-key", regex: "AIza[0-9A-Za-z_-]{35}", keepLast: 4 },
  { id: "google-oauth-token", category: "api-key", regex: "ya29\\.[A-Za-z0-9_-]+", keepLast: 4 },
  { id: "huggingface-key", category: "api-key", regex: "hf_[A-Za-z0-9]{20,}", keepLast: 4 },
  { id: "npm-token", category: "api-key", regex: "npm_[A-Za-z0-9]{20,}", keepLast: 4 },
  // --- tokens ---
  { id: "jwt", category: "token", regex: "eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}" },
  { id: "bearer-token", category: "token", regex: "Bearer\\s+[A-Za-z0-9._~+/=-]{20,}", flags: "i" },
  // --- credentials in URLs and connection strings ---
  { id: "basic-auth-url", category: "credential", regex: "(?<=https?://)[^\\s/:]+:[^\\s@]+(?=@)" },
  { id: "connection-string", category: "connection-string", regex: "(?:postgres(?:ql)?|mysql|mongodb(?:\\+srv)?|redis|amqp|mssql):\\/\\/[^\\s/:]+:[^\\s@]+@" },
  // --- generic key=value credentials (value masked, key kept) ---
  {
    id: "credential-assignment",
    category: "credential",
    regex: "(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|refresh[_-]?token|client[_-]?secret)\\b\\s*[:=]\\s*['\"]?(?!<REDACTED:)([^\\s'\"]{4,})",
    flags: "i",
    maskGroup: 1,
  },
  // --- PII (RU) ---
  { id: "inn", category: "pii", regex: "(?<![A-Za-zА-Яа-яЁё0-9])(?:инн|inn)(?![A-Za-zА-Яа-яЁё0-9])\\s*[:№]?\\s*(\\d{10}(?:\\d{2})?)", flags: "i", maskGroup: 1 },
  { id: "snils", category: "pii", regex: "\\d{3}-\\d{3}-\\d{3}[ ]\\d{2}\\b" },
  { id: "passport-ru", category: "pii", regex: "(?<=паспорт[\\s:№]{0,6})\\d{4}[\\s-]*№?\\s*\\d{6}" },
  { id: "phone-ru", category: "pii", regex: "(?<!\\d)(?:\\+7|8)[\\s(-]*\\d{3}[\\s)-]*\\d{3}[\\s-]*\\d{2}[\\s-]*\\d{2}(?!\\d)" },
  { id: "pii-email", category: "pii", regex: "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}" },
  { id: "bank-card", category: "pii", regex: "\\b\\d{4}[ -]?\\d{4}[ -]?\\d{4}[ -]?\\d{4}(?:[ -]?\\d{3})?\\b", luhn: true },
  // --- ФИО: only with explicit context marker, name itself masked ---
  {
    id: "fio-context",
    category: "pii-name",
    regex: "(?:фио|фамилия\\s+имя\\s+отчество)\\s*[:：]?\\s*([А-ЯЁ][а-яё]+(?:[- ][А-ЯЁ][а-яё]+){1,2})",
    flags: "i",
    maskGroup: 1,
  },
  // --- prompt injection (skill-guard) ---
  {
    id: "inj-override",
    category: "prompt-injection",
    regex:
      "ignore\\s+(?:(?:all|any|the|your|of|and),?\\s+){0,3}(?:previous|prior|above|earlier)\\s+instructions" +
      "|disregard\\s+(?:(?:all|any|the|your|of|and)\\s+){0,3}(?:previous|prior|above|earlier|everything)(?:\\s+instructions)?" +
      "|forget\\s+(?:everything|all\\s+(?:previous\\s+)?instructions|what\\s+you\\s+(?:were\\s+)?(?:told|instructed))" +
      "|ignore\\s+the\\s+above" +
      "|from\\s+now\\s+on\\s+(?:you\\b|ignore|follow|obey)" +
      "|игнорируй(?:те)?\\s+(?:[а-яё'-]+?\\s+){0,3}[а-яё'-]*?(?:инструкци[ийяюеё]|указани[ийяюеё]|сказанн[оыеёа]|изложенн[оыеёа])" +
      "|забудь(?:те)?\\s+(?:(?:всё|все)\\s+инструкции|предыдущие(?:\\s+инструкции)?)" +
      "|отныне\\s+ты",
    flags: "i",
  },
  {
    id: "inj-exfil-combo",
    category: "prompt-injection",
    regex:
      "~[/\\\\](?:\\.ssh|\\.aws|\\.gnupg)[/\\\\]?[^\\s'\"\\\\]*" +
      "|(?:[/\\\\]|(?<![\\w.]))\\.env\\b(?:\\.[A-Za-z0-9._-]+)?" +
      "|\\bid_rsa\\b" +
      "|\\bcredentials\\.(?:json|csv|ini|txt|ya?ml)\\b|[/\\\\]credentials\\b",
    validate: (raw, text, start, end) => {
      const window = text.slice(Math.max(0, start - 200), end + 200)
      return /curl|wget|(?:^|\s)nc\s|netcat|exfiltrat|base64|send(?:ing)?\b|post(?:ing)?\b|fetch(?:ing)?\b|upload(?:ing)?\b|transfer(?:ing|red)?\b|отправь|отправить|выгрузи|выгрузить|залей|передай|пришли|скинь/i.test(window)
    },
  },
  {
    id: "inj-zerowidth",
    category: "prompt-injection",
    // U+200D (ZWJ) excluded: legit emoji/composite scripts; a lone BOM at position 0 is routine.
    regex: "[\\u200B\\u200C\\u2060\\uFEFF\\u202E\\u202B]+",
    validate: (raw, _text, start) => !(start === 0 && raw.length === 1 && raw.charCodeAt(0) === 0xfeff),
  },
]

/** patterns minus disabled ids; single source of truth for the active set */
export function activePatterns(disabledPatterns: readonly string[]): readonly Pattern[] {
  if (disabledPatterns.length === 0) return DEFAULT_PATTERNS
  const off = new Set(disabledPatterns)
  return DEFAULT_PATTERNS.filter((p) => !off.has(p.id))
}
