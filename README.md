# opencode-guard

Security plugin for [OpenCode](https://opencode.ai) V2: intercepts prompts, tool calls and shell commands, detects secrets and personal data, and masks them **before** they reach disk, model context, logs or the network. No LLM involved — only deterministic patterns.

**[Русская версия ниже / Russian version below](#русская-версия)**

## Overview

| Hook | Action |
|---|---|
| `session.prompt` | Scans user prompt text on entry; secrets are replaced with `<REDACTED:category>` before persistence; mention offsets (files/agents/skills) are recalculated; attachments from blocked paths are detached |
| `tool.execute.before` | Vetoes (`Tool.Error`) reads/writes of forbidden paths (`.env`, `*.pem`, `.ssh/**`, …) and writes to write-protected paths; masks secrets in mutating input (write/edit/patch, shell) |
| `tool.execute.after` | Masks secrets in tool results (content, output, metadata) and error messages — keeps secrets out of context/logs |
| `shell.create.before` | Backstop for every shell creation: neutralizes commands touching blocked paths (echo + exit 1), masks inline secrets in commands and secret values in env |
| `session.context` | Last line of defense: scrubs system/messages before they go to the provider |

Audit: JSONL at `~/.local/share/opencode/guard/guard-audit.jsonl` — categories/counts/actions only, **never** raw values.

## Detection (28 patterns)

- API keys: OpenAI `sk-`, GitHub `ghp_`/`github_pat_`, AWS `AKIA`, Google `AIza`/`ya29.`, Slack `xox` + webhooks, Stripe, GitLab `glpat-`, Telegram bot, HuggingFace, npm
- Tokens: JWT, `Bearer …`
- Credentials: `password=…`, basic-auth in URLs, connection strings `scheme://user:pass@…`
- Private keys: whole PEM blocks
- PII (RU): ИНН/СНИЛС/passport (context word required), +7/8 phones, email, bank cards (Luhn-validated), ФИО <REDACTED:pii-name> (only after a "ФИО:" marker)

Specific patterns take priority over generic ones; nested matches collapse into the outer mask (no `user:sk-…` fragments survive).

## Installation

In `~/.config/opencode/opencode.json`:

```json
"plugins": [
  {
    "package": "/path/to/opencode-guard",
    "options": { "mode": "enforce" }
  }
]
```

Then `opencode service restart`. Verify with `opencode api get "/api/plugin?directory=..."` — look for `"id":"guard"` with `"status":"active"`.

## Options

| Key | Default | Description |
|---|---|---|
| `mode` | `"enforce"` | `enforce` — block + redact; `warn` — audit only, touches nothing |
| `scanPrompts` | `true` | scan user prompts |
| `redactOnWrite` | `true` | redact on write/shell |
| `scanOutbound` | `true` | scrub outbound context |
| `blockPaths` | built-in list | **added** to defaults (union) |
| `writeProtectPaths` | `[]` | read ok, write blocked |
| `exemptPaths` | `[]` | exceptions (fixtures with legitimate keys) |
| `disabledPatterns` | `[]` | disable patterns by id |
| `audit` | `{enabled:true, dir:~/.local/share/opencode/guard}` | audit log |

## Known limitations

- `~`, `$VAR` and shell globs are not expanded in static command checks — a command is neutralized only if a token literally matches a blocked path
- `opencode run` may admit a prompt before plugins are ready — the context scrub covers that window
- ФИО <REDACTED:pii-name> requires an explicit marker (too many false positives otherwise)
- The shell hook cannot throw a veto (API limitation) — the command is replaced with `echo … && exit 1`

## Development

```bash
npm install
npm test          # node --test (42 tests)
npm run typecheck # tsc --noEmit
```

The OpenCode server watches `src/**` and reloads the plugin on save — no service restart needed.

---

<a id="русская-версия"></a>
## Русская версия

Плагин безопасности для [OpenCode](https://opencode.ai) V2: перехватывает промпты, tool-вызовы и shell-команды, детектирует секреты и ПДн, маскирует их **до** того, как они попадут на диск, в контекст модели, в логи или сеть. Без LLM — только детерминированные паттерны.

## Что делает

| Хук | Действие |
|---|---|
| `session.prompt` | Сканирует текст промпта пользователя на входе; секреты заменяются на `<REDACTED:категория>` до персиста; оффсеты mention (files/agents/skills) пересчитываются; вложения-файлы из blocked-путей открепляются |
| `tool.execute.before` | Блокирует (вето `Tool.Error`) чтение/запись запрещённых путей (`.env`, `*.pem`, `.ssh/**`, …) и запись в write-protected пути; маскирует секреты в mutating-input (write/edit/patch, shell) |
| `tool.execute.after` | Маскирует секреты в результатах тулов (content, output, metadata) и в сообщениях об ошибках — не даёт секретам войти в контекст/лог |
| `shell.create.before` | Бэкстоп на все shell-создания: нейтрализует команды с blocked-путями (echo + exit 1), маскирует инлайн-секреты в команде и секретные значения в env |
| `session.context` | Последний рубеж: скрабит system/messages перед отправкой провайдеру |

Аудит: JSONL в `~/.local/share/opencode/guard/guard-audit.jsonl` — только категории/количества/действия, **никогда** сырые значения.

## Детекция (28 паттернов)

- API-ключи: OpenAI `sk-`, GitHub `ghp_`/`github_pat_`, AWS `AKIA`, Google `AIza`/`ya29.`, Slack `xox`+webhooks, Stripe, GitLab `glpat-`, Telegram bot, HuggingFace, npm
- Токены: JWT, `Bearer …`
- Креды: `password=<REDACTED:credential> basic-auth в URL, строки подключения `scheme://user:pass@…`
- Private keys: PEM-блоки целиком
- ПДн (RU): ИНН/СНИЛС/паспорт (только с контекстным словом), телефоны +7/8, email, банковские карты (с Luhn-валидацией), ФИО (только после маркера «ФИО:»)

Приоритет — специфичные паттерны выше generic; вложенные матчи схлопываются во внешнюю маску (никаких остатков `user:sk-…`).

## Установка

В `~/.config/opencode/opencode.json`:

```json
"plugins": [
  {
    "package": "/absolute/path/to/opencode-guard",
    "options": { "mode": "enforce" }
  }
]
```

## Опции

| Ключ | По умолчанию | Описание |
|---|---|---|
| `mode` | `"enforce"` | `enforce` — блокировать+маскировать; `warn` — только аудит, ничего не трогает |
| `scanPrompts` | `true` | скан промптов пользователя |
| `redactOnWrite` | `true` | маскировка при записи/шелле |
| `scanOutbound` | `true` | скраб исходящего контекста |
| `blockPaths` | дефолтный список | **добавляется** к дефолтам (union) |
| `writeProtectPaths` | `[]` | read ok, write blocked |
| `exemptPaths` | `[]` | исключения (фикстуры с легитимными ключами) |
| `disabledPatterns` | `[]` | отключить паттерны по id |
| `audit` | `{enabled:true, dir:~/.local/share/opencode/guard}` | аудит-лог |

## Ограничения (известные)

- `~`, `$VAR`, шелл-глобы в командах не раскрываются при статической проверке — команда нейтрализуется только если токен буквально совпадает с blocked-путём
- `opencode run` может адмитить промпт до готовности плагинов — защиту в этом окне догоняет context-скраб
- ФИО — только с явным маркером (без него — слишком много ложных срабатываний)
- shell-хук не может кидать вето (API так не умеет) — команда заменяется на `echo … && exit 1`

## Разработка

```bash
npm install
npm test          # node --test (41 тест)
npm run typecheck # tsc --noEmit
```

Сервер OpenCode сам следит за `src/**` и перезагружает плагин при сохранении — рестарт сервиса не нужен.
