# Спека: deps-guard фаза 2.5 — доводка перехвата зависимостей

Статус: принята к реализации. Процесс: спека → тесты (красный) → реализация (зелёный) → ревью субагентами → живая проверка → v1.1.0.

Закрывает §9 deps-spec.md. Исследование API (шаг 0): `shell.create.before` несёт `cwd` —
пост-аудит реализуем на нём; `tool.execute.before` cwd не несёт (sessionID/agent/messageID/input).

## 1. npx / dlx-перехват (загрузка без install)

`npx pkg[@ver]`, `pnpm dlx pkg`, `yarn dlx pkg` скачивают и исполняют пакет без install — тот же
риск, что у install. Детерминированный парсинг:

- менеджер: `npx` (+Windows `npx.cmd`/`.ps1`/`.exe`), подкоманды `dlx` у `pnpm`/`yarn`.
- флаги пропускаются; `-p`/`--package` (npx) — операнд(ы) ЭТО пакеты (проверяются).
- первый позиционный токен после флагов — пакет для исполнения (имя до `@`, версия после).
  Токены после `--` — аргументы исполняемой команды, НЕ пакеты (стоп).
- `-c`/`--call` со строкой-командой — не парсим (содержимое строки не трогаем).
- git/url-спеки (`npx github:user/repo`) → null.
- применяются те же проверки: blocklist (case-insens) + squat npm-only + affix (п.3).
- `npm exec` НЕ покрывается (семантика позиционных аргументов неоднозначна) — documented gap.

## 2. Scoped-сквоттинг (@types)

`@types/<base>`: если `<base>` ∈ TRUSTED_TOP → ок; иначе levenshtein(base, trusted) == 1 → typosquat.
Примеры: `@types/lodahs` → lodash (вето); `@types/lodash` → ок; `@scope/lodahs` → ок (фаза 3:
scoped-сквоттинг произвольных скоупов требует списка официальных скоупов).

## 3. Affix-сквоттинг (префикс/суффикс)

Имя = trusted + словарный аффикс (склейка или через дефис):
- суффиксы: `js`, `ts`, `node`, `cli`, `dev` (+ дефисные формы `-js`, `-ts`, `-node`, `-cli`, `-dev`)
- префиксы: `node-`, `nodejs-`
Ловит `lodashjs`, `node-lodash`, `react-cli`, `lodash-js`. Не ловит `lodash-es` (сам в TRUSTED_TOP).
Allowlist легитимных исторических имён: `angularjs`, `reactjs`, `vuejs`, `expressjs`, `nodejs`,
`vue-cli`, `angular-cli` (официальные legacy CLI). Только npm-экосистема.
Причина в аудите: `typosquat` (target = trusted).

## 4. Версионный блоклист

Записи `blockedPackages` вида `name@version` блокируют ТОЛЬКО эту версию; голые `name` — как раньше,
всё имя. `rc@1.2.9` в блоклисте: `npm i rc@1.2.9` → вето, `npm i rc` → ок, `npm i rc@2.0.0` → ок.
Scoped: `@scope/pkg@1.0.0` парсится корректно (последний `@`).
`allowedPackages` поддерживает обе формы; голое имя exempt-ит все версии.
Версионный allow НЕ снимает имённый блок (только версионную запись того же имени).
Встроенный BLOCKED_PACKAGES остаётся имённым (инцидентные имена).

## 5. Пост-аудит (npm audit, warn-only)

В `shell.create.before`: если команда — пропущенный npm-install (npm/yarn/pnpm? — только npm:
npm audit работает по npm-lockfile; yarn/pnpm — gap) и `postAudit` (default true) —
через 60 сек (эвристика: install успеет завершиться) отсоединённо запускаем
`npm audit --json` в `event.cwd` (timeout 120s, stdio pipe, ошибки глотаем).
Результат: `parseAuditReport(json)` агрегирует по severity (npm ≥11: top-level `vulnerabilities`;
v2: `auditReport.vulnerabilities`; v1: `advisories`; неизвестные severity → `unknown` — блокирует
`__proto__`-строки). Находки → аудит
`{"kind":"deps","categories":["audit-vulnerability"],"count":N,"action":"warn",severities:{...}}`
+ console.warn. Блокировать постфактум нельзя — это детекция уже установленного.
Планируется и для пропущенных команд в warn-режиме (install выполнился — самый опасный класс).
Дедуп по cwd (5 мин). Таймаут: на win32 свой `taskkill /PID /T /F` (встроенный spawn-timeout
убивает только cmd.exe-обёртку), иначе SIGTERM; оборванный отчёт отбрасывается.

## 6. Конфиг

Новый ключ: `postAudit: boolean` (default `true`). Остальное — через существующие
blockedPackages/allowedPackages (новые формы записи, п.4).

## 7. Файлы

| Файл | Изменение |
|---|---|
| `src/deps.ts` | npx/dlx парсинг, @types-scoped, affix, версионный блоклист, parseAuditReport |
| `src/guard.ts` | post-audit планировщик в shell.create.before |
| `src/config.ts` | `postAudit` |
| `src/audit.ts` | AuditEvent: опциональный `severities?: Record<string, number>` |
| `test/deps.test.ts` | +~25 тестов |
| `README.md` | секция deps: npx/dlx, @types, affix, версионный блоклист, пост-аудит (EN+RU) |

## 8. План тестов (TDD)

1. npx: `npx lodahs`→squat; `npx -y lodahs@1.2.3`→squat; `npx -p event-stream`→blocklist;
   `npx -p lodash node x.js`→первый позиционный `node`… подождать: `-p` пакеты проверяются,
   позиционные тоже; `npx lodash`→null; `npx node script.js`→null; `npx -- lodahs`→null
   (после `--` аргументы); `npx.cmd lodahs`→squat (Windows); `npx github:x/y`→null.
2. dlx: `pnpm dlx lodahs`→squat; `yarn dlx event-stream`→blocklist; `pnpm dlx lodash`→null.
3. @types: `@types/lodahs`→squat(lodash); `@types/lodash`→null; `@types/reactt`→squat(react);
   `@scope/lodahs`→null.
4. affix: `lodashjs`/`node-lodash`/`react-cli`→squat; `angularjs`/`expressjs`/`vuejs`/
   `nodejs`/`reactjs`→null (allowlist); `lodash-es`→null (trusted); `nodemailer`→null.
5. версионный блоклист: `rc@1.2.9` блокирует только эту версию; `@scope/pkg@1.0.0` scoped-парс;
   allowed `rc` снимает версионный тоже; allowed `rc@1.2.9` снимает только её.
6. parseAuditReport: v2-фикстура (2 critical, 1 high) → severities агрегированы; v1-фикстура;
   мусор → null; пустой отчёт → нули.
7. регрессии: все существующие 111 тестов зелёные.

## 9. Критерии готовности

- 111 + новые тесты зелёные, tsc чисто.
- Ревью субагентом: critical/major исправлены.
- Живая проверка: `npx lodahs` → вето; `npm install lodash` → ок + через ~60с в аудите
  kind:"deps" с audit-vulnerability (если в проекте есть уязвимости) либо тишина.
- Публикация v1.1.0.

## 10. Known gaps (после 2.5)

- `npm exec`, произвольные scoped-скоупы, yarn/pnpm audit, affix-словарь фиксирован.
- пост-аудит: эвристическая задержка 60s, npm-only, детекция без блокировки.
- OSV-API как альтернатива npm audit — фаза 3 (нужен выбор источника без ключа).
