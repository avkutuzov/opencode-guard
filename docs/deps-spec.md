# Спека: deps-guard (фаза 2) — перехват установки зависимостей

Статус: принята к реализации. Процесс: спека → тесты (красный) → реализация (зелёный) → ревью субагентами → живая проверка.

## 1. Цель

Агент OpenCode постоянно ставит пакеты (`npm install X`). Два детерминированных риска ловимся ДО установки:
- **известные вредоносные пакеты** (blocklist с историческими инцидентами);
- **typosquat** — имя на расстоянии Левенштейна 1 от популярного пакета (`lodahs` ≈ `lodash`).
Пост-аудит (npm audit/OSV) — НЕ входит в фазу 2 (нужен cwd проекта, API не гарантирует его в хуке;
отдельное исследование — фаза 2.5). Экосистема: npm полноценно; pip/cargo — парсинг + blocklist,
squat-лист только npm.

## 2. Детекция

### 2.1 Парсинг install-команд (src/deps.ts)

Команда режется на сегменты (`&&`, `||`, `;`, `|`, перевод строки) — менеджер ищется на старте
каждого сегмента (после ведущих env-присваиваний, `env`, `sudo` с флагами). Это закрывает обход
вида `cd proj && npm install <blocked>`. Менеджеры: `npm|yarn|pnpm|pip|pip3|cargo`; подкоманды
npm: install|i, yarn: add, pnpm: add|install, pip: install, cargo: add. Флаги пропускаются;
флаги с операндом (`-w`, `--prefix`, `-r`, `--filter`, … — таблица FLAG_TAKES_ARG) пропускают
и следующий токен. `-g`/`--global` и `yarn global add` → null (вне зоны охвата). Форматы имён:
`pkg`, `pkg@1.2.3`, `@scope/pkg@1.0.0` (версия после последнего `@`), pip: `pkg==1.0` (операторы
стрипаются). Все сегменты проверяются на нарушения (parseSegments), не только первый.
Прочее (curl, git clone, npx) → null.

### 2.2 Blocklist (встроенный список)

Исторические инциденты цепочки поставок: event-stream/flatmap-stream (2018), node-ipc (2022
protestware), ua-parser-js/coa/rc (hijack-2021). Точное совпадение имени, case-insensitive,
union с пользовательским `blockedPackages`. Совпадение → вето с именем и причиной.
Осознанное решение: colors/faker (wiper-2022) НЕ блокируются — текущие версии чисты и пакеты
живы, цена FP выше пользы (тот же trade-off, что и для rc/coa, см. §9). Обход FP — через
`allowedPackages: string[]` (снимает имя с блоклиста без отключения depsCheck).

### 2.3 Typosquat (расстояние Левенштейна)

Встроенный список ~120 популярных npm-имён (lodash, react, axios, …). Для не-scoped имени:
levenshtein(name, trusted) === 1 → подозрение. === 2 и пунктуация — шум, не ловим.
Scoped-имена (`@scope/pkg`) не проверяются (фаза 2.5). Подозрение → вето с указанием «похоже на X».

## 3. Точки перехвата

| Хук | Действие |
|---|---|
| `tool.execute.before` (shell/bash) | parse → blocklist/squat → veto (`ToolError`) в enforce, warn-аудит в warn |
| `shell.create.before` | то же; вето невозможно → команда заменяется на `echo "guard: ..." && exit 1` |

Оба пути пишут аудит `{"kind":"deps","categories":[...],"action":"blocked"|"warn"}`.
Ровно одна запись на попытку установки: в warn-режиме shell.create.before не дублирует аудит
tool.before (TTL-дедуп 2с по строке команды).

## 4. Конфиг

`depsCheck: boolean` (default `true`) — включить/выключить весь модуль. Отдельной политики нет:
подчиняется общему `mode` (enforce/warn). Пользовательские списки: `blockedPackages: string[]`
(union со встроенным блоклистом) и `allowedPackages: string[]` (снятие имён с блоклиста).

## 5. Аудит

- `AuditEvent.kind` += `"deps"`.
- categories: `["malicious-package"]` (blocklist) / `["typosquat"]` (squat).
- Имена пакетов в аудит писать можно (не секреты).

## 6. Файлы

| Файл | Изменение |
|---|---|
| `src/deps.ts` | новый: parseInstallCommand, levenshtein, isTyposquat, BLOCKLIST, TRUSTED_TOP, checkInstall |
| `src/guard.ts` | вызовы в tool.execute.before и shell.create.before за path-check |
| `src/config.ts` | `depsCheck`, `blockedPackages` |
| `src/audit.ts` | kind `"deps"` |
| `test/deps.test.ts` | новый |
| `README.md` | секция обновится после реализации |

## 7. План тестов (TDD, test/deps.test.ts)

1. parse: `npm install lodash` → {eco:npm, pkgs:[lodash]}; `npm i a b` → 2 пакета; `npm install pkg@1.2.3` → версия отделена; `npm i -D pkg` → флаг пропущен; `npm install` → null; `npm install --global pkg` → null (только -g/--global → экосистемный риск вне проекта, не блокируем); `@scope/pkg@1.0.0` → имя/версия корректно; `FOO=bar npm i pkg` → ок; `pip install pkg==1.0` → pip; `cargo add pkg` → cargo; `curl ...` / `git clone` → null; `npm run install:x` → null (не install).
2. levenshtein: unit-чеки (kitten/sitting=3, abc/abd=1, abc/ab=1, abc/abc=0).
3. squat: lodahs→lodash, reactt→react, axio→axios, moment→moment нет; случайное имя → null; расстояние 2 → null.
4. blocklist: event-stream → malicious; EVENT-STREAM (регистр) → malicious; пользовательский blockedPackages: union.
5. checkInstall-интеграция: чистая команда → null; вредоносная → verdict с reason; squat → verdict с target.
6. config: depsCheck default true, отключение; blockedPackages через resolveConfig.

## 8. Критерии готовности

- 88 + новые тесты зелёные, tsc чисто.
- Ревью субагентом: critical/major исправлены, второй проход без новых.
- Живая проверка: `npm install lodahs` в сессии → вето/нейтрализация + аудит `kind:"deps"`;
  `npm install lodash` → проходит.

## 9. Known gaps (заранее + зафиксировано ревью)

- Без пост-аудита: уже установленные уязвимости фаза 2 не видит (фаза 2.5: npm audit/OSV при наличии cwd).
- Окно атаки install-скриптами: вредоносный postinstall сработает до любого пост-аудита;
  опция `--ignore-scripts` не включается по умолчанию — ломает нативные модули.
- Squat-лист фиксирован (119 имён), не обновляется автоматически; префикс/суффикс-сквоттинг
  (`lodashjs`, `node-lodash`) расстоянием 1 не ловится — фаза 2.5 (правило «подстрока + dist ≤ 2»).
- Scoped-имена (`@types/lodahs`) и dist-tag (`pkg@latest`) — фаза 2.5.
- `npx pkg` скачивает и исполняет пакет без install — не перехватывается; фаза 2.5 (проверять как npm squat).
- `--dry-run` блокируется наравне с реальной установкой (безопасно, но создаёт трение) — осознанно.
- Блокировка ИМЕНИ для пакетов с чистыми текущими версиями (rc, coa, ua-parser-js, node-ipc) —
  trade-off фазы 2; обход через `allowedPackages`, версионный блоклист — фаза 2.5.
