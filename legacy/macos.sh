#!/bin/bash

set -euo pipefail

# ============================================================
# Helpers
# ============================================================

info() {
    echo "==> $*"
}

die() {
    echo
    echo "ОШИБКА: $*" >&2
    exit 1
}

show_openssl_error() {
    local file="$1"

    if [ -s "$file" ]; then
        echo
        echo "Подробности OpenSSL:"
        sed 's/^/  /' "$file"
    fi
}

# ============================================================
# Find OpenSSL 3
# ============================================================

find_openssl() {
    local candidates=(
        "/opt/homebrew/opt/openssl@3/bin/openssl"
        "/usr/local/opt/openssl@3/bin/openssl"
        "/opt/homebrew/bin/openssl"
        "/usr/local/bin/openssl"
        "$(command -v openssl 2>/dev/null || true)"
    )

    local candidate

    for candidate in "${candidates[@]}"; do
        [ -n "$candidate" ] || continue
        [ -x "$candidate" ] || continue

        if "$candidate" version 2>/dev/null | grep -q '^OpenSSL 3\.'; then
            echo "$candidate"
            return 0
        fi
    done

    return 1
}

OPENSSL="$(find_openssl || true)"

if [ -z "$OPENSSL" ]; then
    echo "OpenSSL версии 3.x не найден."
    echo
    echo "Установите OpenSSL 3 через Homebrew:"
    echo
    echo "  brew install openssl@3"
    echo
    echo "После установки запустите скрипт ещё раз."
    exit 1
fi

# ============================================================
# Input
# ============================================================

if [ "$#" -ne 1 ]; then
    echo "Использование:"
    echo
    echo "  $0 файл.p12"
    echo
    echo "Пример:"
    echo
    echo "  $0 alifgroup.p12"
    echo
    exit 1
fi

P12="$1"

[ -f "$P12" ] || die "Файл не найден: $P12"

DIR="$(cd "$(dirname "$P12")" && pwd)"
FILENAME="$(basename "$P12")"
BASE="${FILENAME%.*}"

CERT="$DIR/${BASE}.crt"
ENC_KEY="$DIR/${BASE}_private_encrypted.key"

# ============================================================
# Temporary workspace
# ============================================================

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/p12-convert.XXXXXX")"

TMP_CERT_RAW="$TMP_DIR/certificate-raw.pem"
TMP_CERT="$TMP_DIR/certificate.crt"
TMP_KEY="$TMP_DIR/private-encrypted.key"

TMP_CERT_PUB="$TMP_DIR/cert-public.pem"
TMP_KEY_PUB="$TMP_DIR/key-public.pem"

TMP_P12_ERROR="$TMP_DIR/p12-error.log"
TMP_CERT_ERROR="$TMP_DIR/cert-error.log"
TMP_KEY_ERROR="$TMP_DIR/key-error.log"
TMP_VERIFY_ERROR="$TMP_DIR/verify-error.log"

cleanup() {
    unset P12_PASS 2>/dev/null || true
    unset KEY_PASS 2>/dev/null || true
    unset KEY_PASS_CONFIRM 2>/dev/null || true

    rm -rf "$TMP_DIR"
}

trap cleanup EXIT
trap 'echo; echo "Операция прервана пользователем."; exit 130' INT
trap 'echo; echo "Операция прервана."; exit 143' TERM

# ============================================================
# Header
# ============================================================

echo
echo "========================================"
echo "Конвертация PKCS#12"
echo "========================================"
echo
echo "Исходный файл:"
echo "  $P12"
echo
echo "Будут созданы:"
echo "  $CERT"
echo "  $ENC_KEY"
echo

info "Используется OpenSSL:"
"$OPENSSL" version
echo

# ============================================================
# Check existing output files
# ============================================================

if [ -e "$CERT" ] || [ -e "$ENC_KEY" ]; then
    echo "Некоторые выходные файлы уже существуют:"
    echo

    [ -e "$CERT" ] && echo "  $CERT"
    [ -e "$ENC_KEY" ] && echo "  $ENC_KEY"

    echo
    echo "Они будут заменены только после того,"
    echo "как новые файлы успешно пройдут все проверки."
    echo

    printf "Overwrite them? [y/N]: "
    IFS= read -r ANSWER

    case "$ANSWER" in
        y|Y|yes|YES)
            ;;
        *)
            die "Операция отменена. Существующие файлы не изменены."
            ;;
    esac
fi

# ============================================================
# Ask for P12 password
# ============================================================

echo
echo "Для открытия P12 требуется текущий пароль контейнера."
echo

printf "Введите пароль от P12: "
IFS= read -r -s P12_PASS
echo

if [ -z "$P12_PASS" ]; then
    die "Пароль от P12 не может быть пустым."
fi

export P12_PASS

# ============================================================
# Detect normal / legacy mode
# ============================================================

echo
info "Проверяем контейнер PKCS#12..."

LEGACY_ARGS=()

if "$OPENSSL" pkcs12 \
    -in "$P12" \
    -passin env:P12_PASS \
    -noout \
    >/dev/null 2>&1
then
    info "Контейнер успешно открыт."

else
    info "Обычный режим не подошёл."
    info "Пробуем режим совместимости со старыми алгоритмами..."

    if "$OPENSSL" pkcs12 \
        -legacy \
        -in "$P12" \
        -passin env:P12_PASS \
        -noout \
        >/dev/null 2>&1
    then
        LEGACY_ARGS=(-legacy)

        info "Контейнер успешно открыт в режиме совместимости."

    else
        echo
        echo "Не удалось открыть PKCS#12 контейнер."
        echo
        echo "Возможные причины:"
        echo "  - введён неверный пароль от P12"
        echo "  - файл повреждён"
        echo "  - файл не является корректным PKCS#12 (.p12/.pfx)"
        echo "  - используются неподдерживаемые алгоритмы"
        exit 1
    fi
fi

# ============================================================
# Ask for new private-key password
# ============================================================

echo
info "Задаём пароль для нового приватного ключа..."
echo
echo "Это НОВЫЙ пароль."
echo
echo "Он:"
echo "  - не обязан совпадать с паролем от P12"
echo "  - будет защищать файл приватного ключа"
echo "  - понадобится при использовании созданного .key файла"
echo

MAX_PASSWORD_ATTEMPTS=3
ATTEMPT=1
PASSWORD_SET=0

while [ "$ATTEMPT" -le "$MAX_PASSWORD_ATTEMPTS" ]; do

    printf "Введите новый пароль: "
    IFS= read -r -s KEY_PASS
    echo

    if [ -z "$KEY_PASS" ]; then
        echo
        echo "Пароль не может быть пустым."

    else
        printf "Повторите новый пароль: "
        IFS= read -r -s KEY_PASS_CONFIRM
        echo

        if [ "$KEY_PASS" = "$KEY_PASS_CONFIRM" ]; then
            PASSWORD_SET=1
            break
        fi

        echo
        echo "Пароли не совпадают."
    fi

    REMAINING=$((MAX_PASSWORD_ATTEMPTS - ATTEMPT))

    if [ "$REMAINING" -gt 0 ]; then
        echo "Осталось попыток: $REMAINING"
        echo
    fi

    ATTEMPT=$((ATTEMPT + 1))
done

if [ "$PASSWORD_SET" -ne 1 ]; then
    die "Не удалось задать пароль после $MAX_PASSWORD_ATTEMPTS попыток."
fi

unset KEY_PASS_CONFIRM
export KEY_PASS

info "Новый пароль принят."

# ============================================================
# Extract certificate
# ============================================================

echo
info "Извлекаем сертификат..."

: > "$TMP_P12_ERROR"

if ! "$OPENSSL" pkcs12 \
    "${LEGACY_ARGS[@]}" \
    -in "$P12" \
    -passin env:P12_PASS \
    -clcerts \
    -nokeys \
    -out "$TMP_CERT_RAW" \
    2>"$TMP_P12_ERROR"
then
    echo
    echo "Не удалось извлечь сертификат."
    show_openssl_error "$TMP_P12_ERROR"
    exit 1
fi

# Удаляем PKCS#12 metadata и сохраняем чистый PEM certificate.

: > "$TMP_CERT_ERROR"

if ! "$OPENSSL" x509 \
    -in "$TMP_CERT_RAW" \
    -outform PEM \
    -out "$TMP_CERT" \
    2>"$TMP_CERT_ERROR"
then
    echo
    echo "Не удалось обработать извлечённый сертификат."
    show_openssl_error "$TMP_CERT_ERROR"
    exit 1
fi

info "Сертификат извлечён."

# ============================================================
# Extract and encrypt private key
# ============================================================

echo
info "Извлекаем приватный ключ..."
info "Шифруем его в формате PKCS#8..."

: > "$TMP_P12_ERROR"
: > "$TMP_KEY_ERROR"

set +e

"$OPENSSL" pkcs12 \
    "${LEGACY_ARGS[@]}" \
    -in "$P12" \
    -passin env:P12_PASS \
    -nocerts \
    -noenc \
    -out /dev/stdout \
    2>"$TMP_P12_ERROR" \
|
"$OPENSSL" pkcs8 \
    -topk8 \
    -v2 aes-256-cbc \
    -passout env:KEY_PASS \
    -out "$TMP_KEY" \
    2>"$TMP_KEY_ERROR"

PIPE_STATUS=("${PIPESTATUS[@]}")

set -e

PKCS12_STATUS="${PIPE_STATUS[0]}"
PKCS8_STATUS="${PIPE_STATUS[1]}"

if [ "$PKCS12_STATUS" -ne 0 ]; then
    echo
    echo "Не удалось извлечь приватный ключ из P12."

    show_openssl_error "$TMP_P12_ERROR"
    exit 1
fi

if [ "$PKCS8_STATUS" -ne 0 ]; then
    echo
    echo "Не удалось зашифровать приватный ключ."

    show_openssl_error "$TMP_KEY_ERROR"
    exit 1
fi

info "Приватный ключ создан и зашифрован."

# ============================================================
# Validate certificate
# ============================================================

echo
info "Проверяем сертификат..."

: > "$TMP_VERIFY_ERROR"

if ! "$OPENSSL" x509 \
    -in "$TMP_CERT" \
    -noout \
    >/dev/null \
    2>"$TMP_VERIFY_ERROR"
then
    echo
    echo "Сертификат не прошёл проверку."

    show_openssl_error "$TMP_VERIFY_ERROR"
    exit 1
fi

info "Сертификат корректен."

# ============================================================
# Validate private key
# ============================================================

echo
info "Проверяем приватный ключ..."

: > "$TMP_VERIFY_ERROR"

if ! "$OPENSSL" pkey \
    -in "$TMP_KEY" \
    -passin env:KEY_PASS \
    -check \
    -noout \
    >/dev/null \
    2>"$TMP_VERIFY_ERROR"
then
    echo
    echo "Приватный ключ не прошёл проверку."

    show_openssl_error "$TMP_VERIFY_ERROR"
    exit 1
fi

info "Приватный ключ корректен."

# ============================================================
# Compare certificate and private key
# ============================================================

echo
info "Проверяем соответствие сертификата и приватного ключа..."

: > "$TMP_VERIFY_ERROR"

if ! "$OPENSSL" x509 \
    -in "$TMP_CERT" \
    -pubkey \
    -noout \
    -out "$TMP_CERT_PUB" \
    2>"$TMP_VERIFY_ERROR"
then
    echo
    echo "Не удалось получить публичный ключ из сертификата."

    show_openssl_error "$TMP_VERIFY_ERROR"
    exit 1
fi

: > "$TMP_VERIFY_ERROR"

if ! "$OPENSSL" pkey \
    -in "$TMP_KEY" \
    -passin env:KEY_PASS \
    -pubout \
    -out "$TMP_KEY_PUB" \
    2>"$TMP_VERIFY_ERROR"
then
    echo
    echo "Не удалось получить публичный ключ из приватного ключа."

    show_openssl_error "$TMP_VERIFY_ERROR"
    exit 1
fi

if ! cmp -s "$TMP_CERT_PUB" "$TMP_KEY_PUB"; then
    echo
    echo "Сертификат и приватный ключ НЕ соответствуют друг другу."
    echo
    echo "Выходные файлы не будут заменены."
    exit 1
fi

info "Сертификат и приватный ключ соответствуют друг другу."

# ============================================================
# Install final files
# ============================================================

echo
info "Сохраняем готовые файлы..."

chmod 644 "$TMP_CERT"
chmod 600 "$TMP_KEY"

# До этой точки существующие файлы не изменялись.
# Заменяем их только после успешного прохождения всех проверок.

mv -f "$TMP_CERT" "$CERT"
mv -f "$TMP_KEY" "$ENC_KEY"

chmod 644 "$CERT"
chmod 600 "$ENC_KEY"

# Пароли больше не нужны.

unset P12_PASS
unset KEY_PASS

# ============================================================
# Final result
# ============================================================

echo
echo "========================================"
echo "ГОТОВО"
echo "========================================"
echo
echo "Все операции успешно завершены."
echo "Сертификат и приватный ключ проверены."
echo
echo "Созданы файлы:"
echo
echo "Сертификат:"
echo "  $CERT"
echo
echo "Зашифрованный приватный ключ:"
echo "  $ENC_KEY"
echo
echo "Приватный ключ:"
echo "  Формат:     PKCS#8 / PEM"
echo "  Шифрование: PBES2 + PBKDF2 + AES-256-CBC"
echo
echo "Права доступа:"
echo "  Сертификат:     644"
echo "  Приватный ключ: 600"
echo
echo "Сохраните пароль от приватного ключа в надёжном месте."
echo
