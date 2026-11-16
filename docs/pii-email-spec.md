# Спека: PII-redaction — контекстно-безезопасное маскирование email

Статус: принята к реализации | Релиз: v1.2.0 | Источник: field lessons X5 (13–16.11.2026)
Процесс: спека → TDD → ревью субагентами → живая проверка → publish.

## 1. Проблема

Логин пользователя = email, домашняя директория содержит его: /home/<email>/...
Плоский regex pii-email (src/patterns.ts:68) даёт два инцидента в enforce-режиме:
1. Маска `<REDACTED:pii>` внутри пути ломает парсинг shell-команды.
2. env-скан (guard.ts) заменяет ВСЁ значение переменной при любом матче →
   HOME=<путь с email> → сломанный $HOME во всех дочерних шеллах.
Обход «disabledPatterns: [pii-email]» отключает защиту email в тексте целиком.

## 2. Цели

- G1: pii-email держать включённым на машинах с email-логинами без разрушения команд/env.
- G2: маскирование email в тексте (промпты, tool results, outbound) сохранено.
- G3: маскирование секретов (api-key, token, credential, connection-string,
  private-key) не ослаблено ни в одном контексте.
Не-цели: остальные PII-паттерны не трогаем; парсер shell не делаем.

## 3. Решения по реализации (зафиксировано)

- **FR1 (path-context) применяется ГЛОБАЛЬНО** — в scan()/redact(), т.е. во всех
  контекстах (shell-команды, env, промпты, tool results, outbound). Маска email
  внутри пути вредна везде (ломает понимание пути LLM'ом так же, как команду).
- **Определение path-context — непосредственное примыкание**: матч pii-категории
  пропускается, если символ НЕПОСРЕДСТВЕННО перед start или после end — `/`, `\`,
  а также `~` слева (home-шорткат `~<login>` — реальный X5-кейс).
  (Формулировка «в пределах слова» из черновика противоречит примеру scp и
  отвергнута.) Последствия:
  - `/home/<email>/x`, `C:\Users\<email>`, `~/p/<email>/f`, `~<email>`, `<email>/x` → skip;
  - `scp <email>:~/x` → НЕ skip (слева пробел, справа `:`) → маскируется;
  - `mail: <email>.`, `email: <email>` (YAML), `mailto:<email>` → маскируются;
  - `https://<email>/page` → skip (примыкает `//`) — приемлемо: без пароля это
    не секрет, а маска сломала бы URL.
- **FR1 только для category === "pii"** (pii-name/fio-context — отдельная задача,
  открытый вопрос 3 черновика). Секреты маскируются везде, включая пути.
- **FR3 (allowlist доменов) применяется только к матчам pii-email** (включая
  encoded-форму `:encoded`). НЕ спасает email внутри connection-string/basic-auth —
  они маскируются раньше как секреты (G3).
- **Поле skipped в аудит-записях НЕ добавляем** (FR4 разрешал, не требовал):
  пропуск — норма, а не инцидент; аудит пропусков = спам на каждый шелл.
- **FR2: CRITICAL_ENV_KEYS в src/config.ts**, case-insensitive lookup
  (`key` и `key.toUpperCase()` — Windows-ключи `Path`/`Home`),
  конфигом не расширяется (v1).
- **FR5 логика вынесена в чистую функцию** `redactEnvValue(key, value, patterns, opts)`
  в src/scan.ts — тестируемо без хуков:
  - секреты (любая категория кроме pii/pii-name) → полная замена `<REDACTED:env>`;
  - PII в критической переменной → skip, значение целиком;
  - PII в не-критической → подстроки `<REDACTED:pii>`, остаток значения цел;
  - смешанный secret+PII → полная замена (секреты побеждают).

## 4. Требования (синхронизировано с черновиком)

- FR1: isPathContext — предикат рядом с redact() в src/scan.ts; skip для category "pii".
- FR2: секреты маскируются в любых env; PII-категории пропускаются в
  CRITICAL_ENV_KEYS = HOME, PATH, PWD, OLDPWD, USER, USERNAME, LOGNAME, SHELL,
  TMPDIR, TEMP, TMP, LANG, LC_ALL, TERM, SHLVL, HOSTNAME.
- FR3: опция `piiEmailAllowDomains: string[]` (default []), case-insensitive,
  точный домен после последнего `@`, поддомены НЕ включаются (x5.ru ≠ mail.x5.ru).
  Нормализация в lowercase при resolveConfig.
- FR4: обратная совместимость — disabledPatterns работает как раньше; дефолты не
  меняют поведение конфигов с отключённым pii-email.
- FR5: подстрока для PII в не-критических env; полная замена для секретов.

## 5. Критерии приёмки (сценарий X5: логин = email, конфиг {"mode":"enforce"})

| # | Действие | Ожидание |
|---|---|---|
| A1 | shell: ls /home/<email>/.config | выполняется, путь не замаскирован |
| A2 | дочерний шелл: echo $HOME | значение целое |
| A3 | shell: echo contact: <email> | замаскирован в команде |
| A4 | + piiEmailAllowDomains:["x5.ru"]: echo <корп. email> | не маскируется |
| A5 | env MY_TOKEN=<REDACTED:credential> | полная замена значения |
| A6 | env WORKMAIL=<email> | подстрока замаскирована, остаток цел |
| A7 | disabledPatterns:["pii-email"] | паттерн отключён полностью |
| A8 | sk-… в тексте команды | маскируется (регрессия секретов) |

Живая проверка на машине без email-логина: A1/A3/A4/A8 через реальный opencode;
A2/A5/A6 юнит-тестами redactEnvValue + частично через shell с env.

## 6. План тестов (TDD)

- unit: isPathContext через redact() — POSIX/Windows-пути, scp-адрес (маскируется),
  YAML/mailto (маскируются), секрет в пути (маскируется — G3);
- unit: allowlist — регистр, точный домен, поддомен НЕ включён, путь с allowlist-доменом
  всё равно skip, connection-string с allowlist-доменом маскируется (G3);
- unit: redactEnvValue — критические/не-критические × pii/secret/смешанное;
- unit: resolveConfig — piiEmailAllowDomains парсинг + lowercase;
- regression: все 144 существующих теста без правок (цель: ~173).

## 7. Файлы

| Файл | Изменение |
|---|---|
| src/config.ts | CRITICAL_ENV_KEYS, GuardConfig.piiEmailAllowDomains, resolveConfig |
| src/scan.ts | ScanOptions, isPathContext, domain-фильтр в scanInner, redactEnvValue |
| src/guard.ts | scanOpts прокидывается во ВСЕ scan/redact (incl. tool.after, outbound, skillcheck); env-цикл → redactEnvValue |
| src/skillcheck.ts | scanSkillDir принимает ScanOptions |
| test/scan.test.ts | +22 теста |
| test/config.test.ts | +4 теста |
| test/guard-opts.test.ts | +3 теста (mock-ctx доставка scanOpts) |
| README.md | опция + поведение email-в-путях/env (EN+RU), счётчик тестов |

## 8. Known gaps (после v1.2)

- **Pre-existing DoS-вектор (найден ревью v1.2)**: regex pii-email
  `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}` на длинном однотонном ране
  (≥100К символов класса) даёт O(n²)-бэктрекинг — ~19с блокировки хука.
  Триггер редок (base64/hex-дампы, минифицированный JS в выводе тулов), но
  фикс обязателен: ограничить локальную часть `{1,64}` (RFC-реалистично) +
  пин-тест на ран. Отдельный патч, не блокирует v1.2.
- Пропуски PII в критических env не аудируются (намеренно — иначе спам на каждый
  шелл); в enforce-режиме такой PII проходит в дочерние процессы без следа.
- `~<email>` внутри сложных шелл-конструкций (`$(...)`, backticks) не
  раскрывается (общий gap парсинга).
- ФИО (pii-name) в путях по-прежнему маскируются (открытый вопрос 3 черновика —
  отдельная задача).
| docs/pii-email-spec.md | этот файл |
