# План реализации кроссплатформенного PKCS#12 Converter

## 1. Назначение и границы документа

Цель проекта — одно desktop-приложение для Windows и macOS, которое извлекает из
PKCS#12 (`.p12`/`.pfx`):

- клиентский сертификат в PEM;
- приватный ключ в зашифрованном PKCS#8/PEM;
- и публикует результаты только после успешной проверки сертификата, ключа и их
  соответствия.

На текущем этапе `legacy/macos.sh` и `legacy/windows.ps1` остаются без изменений.
Этот документ фиксирует их поведение, расхождения, security-инварианты и
поэтапный путь к Python + PySide6.

## 2. Резюме сравнения legacy-скриптов

Оба скрипта реализуют один и тот же основной сценарий через OpenSSL 3:

1. Находят OpenSSL версии 3.x.
2. Проверяют наличие входного PKCS#12 и строят имена выходных файлов рядом с ним:
   `<base>.crt` и `<base>_private_encrypted.key`.
3. Запрашивают пароль контейнера без отображения на экране.
4. Сначала пробуют открыть контейнер в обычном режиме, затем автоматически
   повторяют с `pkcs12 -legacy`.
5. Извлекают клиентский сертификат (`-clcerts -nokeys`) и нормализуют его через
   `openssl x509 -outform PEM`.
6. Извлекают приватный ключ без шифрования контейнера и повторно шифруют его как
   PKCS#8 с `-v2 aes-256-cbc`.
7. Проверяют сертификат и получают публичные ключи сертификата и приватного
   ключа.
8. Сравнивают публичные ключи и завершают операцию ошибкой при несовпадении.
9. Удаляют временные данные и пароль контейнера из окружения.

При этом security-поведение скриптов не равноценно. macOS-вариант строже:

- незашифрованный приватный ключ передаётся через pipe и не сохраняется в файл;
- новый пароль проверяется на пустое значение и подтверждается, число попыток
  ограничено тремя;
- зашифрованный ключ явно проходит `openssl pkey -check -noout`;
- старые результаты не изменяются до завершения всех проверок;
- права выставляются как `0644` для сертификата и `0600` для ключа.

Windows-вариант, напротив, временно пишет незашифрованный ключ на диск, заранее
удаляет прежние результаты, пишет новые файлы непосредственно в финальные пути
до окончания проверок и не выполняет отдельный `pkey -check`. Чтение ключа через
`pkey -pubout` доказывает, что ключ можно расшифровать и разобрать, но не является
полным эквивалентом `pkey -check`.

Единое приложение должно сохранить объединение существующих проверок и взять за
минимальную норму более строгое поведение macOS-скрипта. Это не должно лишить
Windows-ветку её явного поиска и подключения legacy provider.

## 3. Общая бизнес-логика

### 3.1. Вход и результат

Входные данные:

- существующий обычный файл `.p12` или `.pfx`;
- непустой пароль PKCS#12;
- непустой новый пароль приватного ключа и его подтверждение;
- решение пользователя о замене уже существующих результатов.

Результат при успехе:

- `<base>.crt` — только выбранный клиентский X.509 certificate в PEM;
- `<base>_private_encrypted.key` — зашифрованный PKCS#8 в PEM;
- сертификат синтаксически читается OpenSSL;
- приватный ключ расшифровывается новым паролем и проходит проверку OpenSSL;
- публичный ключ сертификата совпадает с публичным ключом приватного ключа.

При любой ошибке новые результаты не должны публиковаться, а ранее существовавшая
пара файлов должна остаться неизменной.

### 3.2. Канонический pipeline

1. Провалидировать запрос, расширение, тип входного объекта и допустимость
   выходных путей.
2. Найти доверенный OpenSSL 3 и совместимый каталог provider-модулей.
3. Создать приватный временный workspace.
4. Выполнить probe: `openssl pkcs12 -in ... -passin ... -noout`.
5. Только после неуспеха обычного probe выполнить тот же probe с `-legacy`.
6. Если оба probe неуспешны, не продолжать извлечение. Сообщение не должно
   утверждать, что причина точно известна: одинаково могут проявляться неверный
   пароль, повреждение, неподдерживаемая структура и проблема provider.
7. Извлечь `-clcerts -nokeys`, затем получить чистый PEM через `openssl x509`.
8. Извлечь `-nocerts -noenc` в pipe и сразу передать данные в
   `openssl pkcs8 -topk8 -v2 aes-256-cbc`.
9. Проверить сертификат командой `openssl x509 -noout`.
10. Проверить зашифрованный приватный ключ командой
    `openssl pkey -check -noout` с новым паролем.
11. Получить канонический public-key PEM через `x509 -pubkey -noout` и
    `pkey -pubout`, затем сравнить байты (или их SHA-256 digest).
12. Выставить необходимые права/ACL на staged-файлах.
13. Опубликовать оба результата с rollback при частичном сбое.
14. Очистить секреты по мере возможностей Python, дочерних процессов и ОС,
    удалить workspace независимо от исхода.

Проверка `x509 -noout` означает проверку корректности формата сертификата, но не
проверку цепочки доверия, срока действия или отзыва. UI и документация не должны
называть её проверкой доверия сертификату.

## 4. Platform-specific части

| Область | macOS (`macos.sh`) | Windows (`windows.ps1`) | Целевой подход |
|---|---|---|---|
| Поиск OpenSSL | Homebrew ARM/Intel, `/usr/local`, затем `PATH` | `PATH`, Shining Light paths, Git for Windows | Во время разработки — platform locator; в релизе предпочтительно поставлять и выбирать подписанный/pinned OpenSSL 3 |
| Legacy provider | Полагается на `-legacy` и конфигурацию найденного OpenSSL | Ищет `legacy.dll`, задаёт `OPENSSL_MODULES` и `-provider-path` | Общий probe, отдельный поиск каталога модулей для каждого bundle/layout; окружение только конкретного child process |
| Пути | POSIX paths, `dirname`, `basename` | Win32 paths, `Resolve-Path`, `Join-Path` | `pathlib.Path`, без shell-интерполяции; отдельная защита от symlink/reparse-point коллизий |
| Ввод пароля | `read -s`, пароль передаётся через environment | `SecureString`, временный BSTR, затем environment; новый пароль читает OpenSSL | Password widgets; backend получает секрет только на время операции; секрет никогда не попадает в argv, логи, настройки или clipboard |
| Private-key flow | `pkcs12 stdout \| pkcs8`, plaintext не пишется на диск | plaintext key во временном файле | Единый pipe/memory flow без plaintext key file на обеих ОС |
| Временный каталог | `mktemp -d` | GUID под системным temp с унаследованным ACL | Защищённый workspace с `0700` на macOS и ограниченным DACL на Windows |
| Права результата | `0644` certificate, `0600` key | Явная настройка ACL отсутствует | POSIX mode на macOS; DACL только текущему пользователю и требуемым системным субъектам на Windows |
| Замена результатов | После проверок, но два последовательных `mv` | Старые файлы удаляются заранее | Общий staged publisher с backup + rollback; staging на том же filesystem, что и output |
| Сравнение пары | `cmp` двух public-key PEM | SHA-256 двух public-key PEM | Общая реализация сравнения канонического OpenSSL output |
| Ошибки | Раздельные временные stderr logs | OpenSSL пишет в console | Структурированные категории ошибок; ограниченный и очищенный stderr доступен в details |
| Отмена | `trap` для `INT`/`TERM` | `finally` при штатном unwind | Worker cancellation с завершением process tree, обязательным cleanup и rollback |
| Packaging | app bundle, notarization, universal/отдельные architectures | installer/MSIX, code signing, DLL search rules | Отдельные packaging adapters и CI jobs; бизнес-ядро общее |

GUI, orchestration и OpenSSL-команды не должны ветвиться по ОС. В
platform-specific слоях остаются только обнаружение/компоновка OpenSSL, права
доступа, process termination и packaging.

## 5. Security-sensitive места и обязательные инварианты

### 5.1. Секреты

- Сейчас оба варианта передают пароль P12 через environment. Это безопаснее
  command-line argument, но окружение всё ещё копируется в дочерний процесс и
  может быть доступно диагностическим инструментам с соответствующими правами.
- macOS экспортирует также новый пароль ключа. `unset` удаляет переменную, но не
  гарантирует затирание всех копий строки из памяти shell и OpenSSL.
- Windows корректно освобождает BSTR через `ZeroFreeBSTR`, однако создаёт обычную
  managed string `$P12Pass`, сохраняет её в process environment и явно не затирает
  все копии. `SecureString` сам по себе не даёт end-to-end защиты после конвертации.
- Целевое приложение не передаёт пароли в argv, не включает полное environment в
  exception/report, не сохраняет пароль через `QSettings` и не логирует команды
  вместе с secret transport.
- Environment для OpenSSL следует формировать отдельно для каждого процесса, не
  изменяя глобальный `os.environ`. Возможность перейти на anonymous pipe/stdin
  исследуется прототипом отдельно для Windows и macOS; нельзя переходить на
  password temp-file как на «упрощение».
- В Python нельзя обещать гарантированное стирание immutable `str`. Внутренний API
  должен минимизировать время жизни и количество копий секретов; это ограничение
  явно документируется в threat model.

### 5.2. Незашифрованный приватный ключ

- Windows-скрипт создаёт plaintext `$TmpKey` и затем удаляет его. Обычное удаление
  не гарантирует уничтожение данных на SSD, journaled filesystem, backup или при
  аварийном завершении.
- Целевой pipeline сохраняет свойство macOS-скрипта: plaintext существует только
  в памяти процессов и OS pipe. Он никогда не записывается в temp, лог или crash
  report приложения.
- stdout процесса, содержащий plaintext key, маркируется как secret stream: его
  запрещено собирать в debug log и включать в текст исключения.

### 5.3. Временные и финальные файлы

- Workspace должен создаваться без предсказуемого имени и быть недоступным другим
  обычным пользователям: `0700` на macOS, restricted DACL на Windows.
- Key-файл получает `0600` на macOS и эквивалентный ограниченный DACL на Windows
  до публикации. Certificate остаётся публичным (`0644`) там, где это совместимо
  с политикой директории.
- Нельзя следовать неожиданным symlink/reparse points для output. Перед commit
  повторно проверяются тип и identity целевых объектов.
- Staging следует делать в защищённом каталоге на filesystem назначения. Иначе
  `rename/replace` через границы volumes превращается в copy и теряет ожидаемые
  свойства атомарности.
- Файловая система не предоставляет одной атомарной операции для пары файлов.
  Поэтому publisher использует уникальные staged-файлы, backups существующей пары,
  последовательные `replace`, `fsync` где применимо и rollback при любом частичном
  сбое. Успех показывается только после commit обоих файлов.
- В Windows-скрипте старые результаты удаляются до извлечения, а новые пишутся
  непосредственно в финальные пути. Этот риск нельзя переносить в приложение.

### 5.4. Проверки криптографических объектов

Нельзя удалять или объединять так, чтобы потерять смысл, следующие отдельные
этапы:

1. normal PKCS#12 probe;
2. legacy PKCS#12 probe только как fallback;
3. преобразование извлечённого certificate через `x509`;
4. `x509 -noout` для проверки certificate;
5. `pkey -check -noout` для проверки private key;
6. независимое извлечение обоих public keys;
7. сравнение public keys;
8. запрет публикации до успеха всех проверок.

Шифрование ключа на первом этапе сохраняется совместимым с legacy-скриптами:
`pkcs8 -topk8 -v2 aes-256-cbc`, то есть PBES2/PBKDF2/AES-256-CBC с параметрами по
умолчанию выбранной версии OpenSSL. Iteration count и digest нельзя молча менять:
сначала нужны зафиксированные fixtures, compatibility tests и отдельное решение о
миграции формата.

### 5.5. OpenSSL и provider loading

- Выполнение первого `openssl` из `PATH` создаёт риск подмены binary. Hard-coded
  installation paths также не доказывают происхождение файла.
- Для выпуска рекомендуется bundled OpenSSL 3 с зафиксированной версией и legacy
  module той же сборки, проверяемый code signature/hash и обновляемый вместе с
  приложением. Использование системного OpenSSL допустимо как явно обозначенный
  development fallback, а не как неявный production default.
- Нельзя глобально менять `OPENSSL_MODULES`: это влияет на другие дочерние процессы
  приложения. Provider path передаётся только конкретному OpenSSL invocation.
- `-legacy` разрешается только после провала normal probe и только для чтения
  исходного PKCS#12. Выходной приватный ключ всегда шифруется современным PKCS#8
  pipeline.

### 5.6. Ошибки, диагностика и отказоустойчивость

- OpenSSL stderr может содержать пути и сведения о структуре файла. UI показывает
  краткую безопасную ошибку, а details — очищенный и ограниченный по размеру текст.
- Ни command object, ни progress event не должны содержать password или plaintext
  key bytes.
- Неверный пароль и необходимость legacy mode нельзя надёжно различить по одному
  провалу normal probe. После провала обоих режимов сообщение перечисляет причины,
  но не делает ложного точного вывода.
- Отмена, исключение, завершение приложения и ошибка второго процесса pipeline
  должны завершать весь process tree, закрывать pipe, удалять staged data и
  восстанавливать старую пару файлов.

## 6. Предлагаемая архитектура Python + PySide6

### 6.1. Выбор backend

На первом этапе OpenSSL 3 остаётся единственным криптографическим backend. Это
сохраняет реальное legacy-поведение, формат выходного PKCS#8 и существующие
проверки. Замена импорта PKCS#12 на `cryptography`/нативные Keychain/CNG API могла
бы изменить поддержку старых algorithms, выбор bags и диагностику, поэтому не
входит в начальную миграцию.

### 6.2. Слои

**Domain**

- неизменяемые модели `ConversionRequest`, `OutputPaths`, `OpenSSLInstallation`,
  `ConversionResult`, `LegacyMode`;
- типизированные категории ошибок без stderr и секретов;
- состояния операции и progress events.

**Application**

- `ConversionService` как единый state machine/orchestrator;
- порты `CryptoBackend`, `Workspace`, `OutputPublisher`, `Permissions`,
  `CancellationToken`;
- политика overwrite и rollback;
- никаких imports из PySide6.

**Infrastructure**

- `OpenSSLLocator` и проверка `OpenSSL 3.x`;
- `OpenSSLRunner`, принимающий argv list и scoped environment, всегда с
  `shell=False`;
- builder команд PKCS#12/x509/pkey/pkcs8;
- двухпроцессный pipe `pkcs12 -> pkcs8` с проверкой exit code обоих процессов;
- защищённый workspace, permission adapters и transactional publisher;
- sanitizer для stderr и диагностических событий.

**Platform adapters**

- macOS: Homebrew/dev discovery, bundle paths, POSIX modes, process-group kill;
- Windows: `.exe`/`legacy.dll` layout, restricted DACL, process-tree termination,
  безопасные правила DLL search;
- signing/packaging не проникают в application/domain.

**Presentation (PySide6)**

- выбор `.p12`/`.pfx` и отображение рассчитанных output paths;
- password fields с disabled copy/context menu по принятому UX-решению;
- отдельное подтверждение overwrite до запуска destructive commit;
- progress, cancel и безопасное отображение ошибки/details;
- операция выполняется в worker (`QThread`/`QThreadPool`), UI thread не блокируется;
- UI подписывается на progress events и не вызывает OpenSSL напрямую.

### 6.3. Поток управления

```text
MainWindow
    -> ConversionController / worker
        -> ConversionService
            -> OpenSSLCryptoBackend
                -> OpenSSLRunner -> openssl + legacy provider
            -> SecureWorkspace
            -> PlatformPermissions
            -> TransactionalOutputPublisher
        <- progress/result/sanitized error
    <- UI update
```

Сервис сначала полностью создаёт и проверяет staged-результаты. Publisher получает
управление только после этого. Диалог overwrite не является разрешением удалить
старые файлы заранее — это лишь разрешение на финальный transactional commit.

## 7. Предлагаемая структура директорий

```text
certificat/
├── pyproject.toml
├── README.md
├── IMPLEMENTATION_PLAN.md
├── LICENSES/
│   └── openssl/                     # notices и лицензии bundled dependencies
├── docs/
│   ├── behavior-baseline.md
│   ├── security.md                  # threat model и работа с секретами
│   ├── packaging-macos.md
│   └── packaging-windows.md
├── legacy/
│   ├── macos.sh
│   └── windows.ps1
├── src/
│   └── certificat/
│       ├── __init__.py
│       ├── __main__.py
│       ├── domain/
│       │   ├── models.py
│       │   ├── errors.py
│       │   └── events.py
│       ├── application/
│       │   ├── conversion_service.py
│       │   └── ports.py
│       ├── infrastructure/
│       │   ├── openssl/
│       │   │   ├── backend.py
│       │   │   ├── commands.py
│       │   │   ├── locator.py
│       │   │   ├── provider.py
│       │   │   └── runner.py
│       │   └── filesystem/
│       │       ├── publisher.py
│       │       └── workspace.py
│       ├── platforms/
│       │   ├── macos.py
│       │   └── windows.py
│       └── presentation/
│           ├── app.py
│           ├── controller.py
│           ├── main_window.py
│           ├── dialogs.py
│           ├── worker.py
│           └── resources/
├── packaging/
│   ├── macos/
│   ├── windows/
│   └── openssl/                     # fetch/verify/stage recipes, не secrets
└── tests/
    ├── unit/
    ├── integration/
    ├── security/
    ├── fixtures/
    │   ├── README.md                # provenance и expected behavior
    │   ├── generated/
    │   └── malformed/
    └── helpers/
```

Реальные пользовательские `.p12`, `.pfx`, `.key`, пароли и извлечённые
сертификаты не коммитятся. Test fixtures генерируются специально для тестов,
имеют публично известные пароли и не содержат production material.

## 8. Поэтапный план разработки

### Этап 0. Зафиксировать baseline без изменения legacy

- Описать матрицу команд и результатов обоих скриптов.
- Подготовить только синтетические fixtures: normal PKCS#12, legacy PKCS#12,
  неверный пароль, повреждённый файл, certificate/key mismatch, EC и RSA keys,
  существующая output pair.
- Зафиксировать точный PEM/PKCS#8 envelope и характеристики результата через
  OpenSSL, не сравнивая encrypted key побайтно из-за salt/IV.
- Запустить legacy-набор на настоящих Windows и macOS runners и сохранить только
  несекретные expected metadata.

**Критерий выхода:** задокументировано, что именно считается совместимым; legacy
scripts и реальные пользовательские данные не изменены.

### Этап 1. Создать Python skeleton и quality gates

- Настроить поддерживаемую версию Python, `src` layout, PySide6 dependency и
  отдельные test/dev dependencies.
- Подключить formatter/linter, type checking, pytest и secret scanning.
- Создать domain models, error taxonomy и progress states без реализации GUI.
- Настроить CI matrix для Windows и macOS.

**Критерий выхода:** пакет импортируется и проверяется на обеих ОС; domain не
зависит от PySide6 и subprocess details.

### Этап 2. OpenSSL discovery и provider prototype

- Реализовать проверку версии строго `3.x` и capability probes.
- Поддержать текущие Homebrew и Windows layouts как development fallback.
- Прототипировать bundled layouts для обеих architectures/ОС, включая совместимый
  legacy provider.
- Проверить явный provider path, scoped `OPENSSL_MODULES`, DLL/dylib loading и
  диагностические ошибки.
- Зафиксировать версию, checksum/signature verification и license obligations.

**Критерий выхода:** normal и legacy fixtures предсказуемо открываются на обеих
ОС одним backend API; неподходящий OpenSSL отвергается до обработки секретов.

### Этап 3. Безопасный process runner и workspace

- Реализовать запуск только через argv arrays и `shell=False`.
- Реализовать secret transport, не использующий argv; сравнить scoped environment
  и anonymous pipe/stdin на обеих ОС и задокументировать выбранный механизм.
- Реализовать pipeline двух процессов с независимыми exit codes, закрытием handles
  и запретом логирования secret stdout.
- Реализовать private workspace, cleanup при exception/cancel и ограничение
  stderr/log sizes.
- Добавить тесты на spaces/Unicode/metacharacters в путях и отсутствие паролей в
  logs/errors/process arguments.

**Критерий выхода:** plaintext key не появляется на диске, оба exit codes
учитываются, cancellation не оставляет processes и temp files.

### Этап 4. Headless conversion core

- Реализовать normal-then-legacy probe без эвристического упрощения.
- Реализовать извлечение и нормализацию certificate.
- Реализовать pipe extraction + PKCS#8 AES-256-CBC encryption.
- Выполнить отдельные `x509 -noout`, `pkey -check -noout` и public-key comparison.
- Сохранить naming convention и selection flags `-clcerts`, `-nokeys`, `-nocerts`.
- Возвращать структурированный результат и безопасные progress events.

**Критерий выхода:** headless API проходит baseline matrix, включая legacy,
неверный пароль, malformed container и mismatch; до publisher нет final files.

### Этап 5. Права доступа и transactional publication

- Реализовать staging на destination filesystem.
- Реализовать overwrite preflight, backups, pair commit и rollback.
- Добавить защиту от symlink/reparse point и повторную проверку targets перед
  commit.
- Выставлять `0644`/`0600` на macOS и документированный restricted DACL на Windows.
- Инъекцией ошибок проверить сбой перед первым replace, между двумя replace и
  после второго replace; проверить cancel и потерю доступа к директории.

**Критерий выхода:** при каждом смоделированном сбое остаётся старая полная пара
или новая полная пара, но не удалённая/смешанная пара; key permissions проверены.

### Этап 6. PySide6 GUI

- Реализовать минимальный flow выбора файла, двух password inputs, confirmation,
  overwrite prompt, progress, cancel и result view.
- Не переносить command construction и filesystem mutations в UI.
- Обеспечить single active operation, корректное закрытие окна во время операции и
  доступную keyboard navigation.
- Очистить password widgets сразу после передачи запроса worker и после завершения.
- Проверить, что UI не обещает chain/trust/expiry validation.

**Критерий выхода:** GUI полностью использует тот же headless service, остаётся
responsive, корректно обрабатывает success/error/cancel и не раскрывает секреты.

### Этап 7. Packaging и release security

- Собрать signed app bundle для macOS и signed Windows package/installer.
- Включить OpenSSL binary, config и provider modules из одной проверенной сборки;
  не полагаться на текущую рабочую директорию или небезопасный DLL search path.
- Настроить hardened runtime/notarization для macOS и code signing для Windows.
- Включить third-party notices, SBOM и reproducible dependency lock.
- Проверить запуск на чистых supported systems без Homebrew/Git/OpenSSL в `PATH`.

**Критерий выхода:** normal и legacy fixtures проходят на чистых VM; подписи и
notarization валидны; bundle не загружает provider из посторонней директории.

### Этап 8. Security и regression acceptance

- Провести review threat model, process invocation, provider loading, ACL/modes,
  rollback и redaction.
- Выполнить негативные тесты на path substitution, symlinks/reparse points,
  malformed/oversized input, disk full, read-only directory и принудительный kill.
- Сравнить результаты приложения с baseline legacy scripts по смысловым
  характеристикам.
- Подготовить пользовательскую документацию по паролям, output permissions,
  limitations и безопасному удалению исходного PKCS#12.

**Критерий выхода:** все обязательные инварианты из раздела 5 покрыты тестами;
нет известных путей публикации непроверенной или неполной пары.

## 9. Обязательная regression matrix

| Сценарий | Ожидаемый результат |
|---|---|
| Normal PKCS#12 + верный пароль | Обработка без `-legacy`, все проверки успешны |
| Legacy PKCS#12 + верный пароль | Первый probe неуспешен, fallback `-legacy` успешен |
| Неверный P12 password | Оба probe не дают публикации файлов |
| Legacy provider отсутствует/не загружается | Понятная ошибка capability/provider, старые outputs не меняются |
| Повреждённый или не-PKCS#12 файл | Ошибка без публикации и без ложного точного диагноза |
| Пустой новый key password | Запрос отклонён до запуска encryption |
| Password confirmation mismatch | Запрос отклонён; OpenSSL не запускается |
| Certificate syntactically invalid | Провал `x509` validation, публикации нет |
| Private key invalid | Провал `pkey -check`, публикации нет |
| Certificate/key mismatch | Провал public-key comparison, публикации нет |
| Уже есть оба output-файла, пользователь отказался | Никаких изменений |
| Уже есть один или оба output-файла, пользователь согласился | Замена только после всех проверок |
| Ошибка/отмена во время commit | Rollback сохраняет согласованную пару |
| Путь содержит spaces, Unicode и shell metacharacters | Обработка без shell interpretation |
| RSA и EC material | Валидация и сравнение работают одинаково |
| Принудительная ошибка любого OpenSSL subprocess | Учитывается exit code нужного процесса, temp очищается |

## 10. Решения, которые нужно принять до production-кода

1. Поддерживаемые минимальные версии Windows, macOS и architectures.
2. Точная версия и источник bundled OpenSSL 3 для каждой платформы.
3. Формат доставки: universal macOS bundle или отдельные builds; MSI/MSIX/другой
   Windows installer.
4. Конкретный Windows DACL для key и staged directory с учётом корпоративных
   backup/administration policies.
5. Secret transport для каждого OpenSSL invocation после cross-platform prototype.
6. Допустимо ли сохранять существующие OpenSSL defaults PBKDF2 или параметры
   должны быть явно зафиксированы в будущей versioned output policy.
7. Политика выбора certificate/key, если PKCS#12 содержит несколько подходящих
   bags. Текущие scripts не дают пользователю выбора и фактически полагаются на
   порядок OpenSSL output; менять это без отдельного compatibility decision нельзя.

Эти решения не блокируют фиксацию baseline и создание headless interfaces, но
должны быть закрыты до packaging и заявления о production security.
