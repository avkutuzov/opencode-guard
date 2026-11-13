# opencode-guard

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
- Креды: `password=…`-присвоения, basic-auth в URL, строки подключения `<REDACTED:connection-string>…`
- Private keys: PEM-блоки целиком
- ПДн (RU): ИНН/СНИЛС/паспорт (только с контекстным словом), телефоны +7/8, email, банковские карты (с Luhn-валидацией), ФИО (только после маркера «ФИО:»)

Приоритет — специфичные паттерны выше generic; вложенные матчи схлопываются во внешнюю маску (никаких остатков `user:sk-…`).

## Установка

В `~/.config/opencode/opencode.json`:

```json
"plugins": [
  {
    "package": "C:/pojects/AI_Projects/opencode-guard",
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
- ФИО <REDACTED:pii-name> с явным маркером (без него — слишком много ложных срабатываний)
- shell-хук не может кидать вето (API так не умеет) — команда заменяется на `echo … && exit 1`

## Разработка

```bash
npm install
npm test          # node --test (41 тест)
npm run typecheck # tsc --noEmit
```

Сервер OpenCode сам следит за `src/**` и перезагружает плагин при сохранении — рестарт сервиса не нужен.
