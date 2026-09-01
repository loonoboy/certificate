"""Command-line interface for the Certificat conversion core."""

from __future__ import annotations

import argparse
import getpass
from pathlib import Path
import sys
from typing import Sequence, TextIO

from .application.conversion_service import convert_pkcs12, discover_openssl
from .domain.errors import ConversionCancelledError, ConversionError
from .domain.events import ProgressEvent
from .domain.models import ConversionRequest, ConversionResult

_PASSWORD_ATTEMPTS = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="certificat",
        description=(
            "Extract a PEM client certificate and an encrypted PKCS#8 private "
            "key from a PKCS#12 container."
        ),
    )
    parser.add_argument(
        "container",
        type=Path,
        help="path to a .p12 or .pfx container",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="replace an existing certificate/private-key output pair",
    )
    parser.add_argument(
        "--openssl",
        type=Path,
        metavar="PATH",
        help="use this OpenSSL 3 executable instead of automatic discovery",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="hide conversion progress messages",
    )
    return parser


def _prompt_passwords(error_stream: TextIO) -> tuple[str, str] | None:
    p12_password = getpass.getpass("PKCS#12 password: ")
    if not p12_password:
        print("Error: the PKCS#12 password must not be empty.", file=error_stream)
        return None

    for attempt in range(1, _PASSWORD_ATTEMPTS + 1):
        private_key_password = getpass.getpass("New private-key password: ")
        confirmation = getpass.getpass("Confirm private-key password: ")
        if not private_key_password:
            message = "the private-key password must not be empty"
        elif private_key_password != confirmation:
            message = "private-key passwords do not match"
        else:
            return p12_password, private_key_password

        remaining = _PASSWORD_ATTEMPTS - attempt
        suffix = f"; {remaining} attempt(s) remaining" if remaining else ""
        print(f"Error: {message}{suffix}.", file=error_stream)

    return None


def _print_result(result: ConversionResult, output_stream: TextIO) -> None:
    print(f"Certificate: {result.certificate_path}", file=output_stream)
    print(f"Private key: {result.private_key_path}", file=output_stream)
    print(f"PKCS#12 mode: {result.mode.value}", file=output_stream)
    print(f"OpenSSL: {result.openssl_version}", file=output_stream)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # Reject an unavailable or incompatible backend before reading secrets.
    try:
        installation = discover_openssl(args.openssl)
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130
    except ConversionError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    try:
        passwords = _prompt_passwords(sys.stderr)
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.", file=sys.stderr)
        return 130
    if passwords is None:
        return 2
    p12_password, private_key_password = passwords

    request = ConversionRequest(
        p12_path=args.container,
        p12_password=p12_password,
        private_key_password=private_key_password,
        overwrite=args.overwrite,
    )

    def report_progress(event: ProgressEvent) -> None:
        if not args.quiet:
            print(event.message, file=sys.stderr, flush=True)

    try:
        result = convert_pkcs12(
            request,
            openssl=installation,
            progress=report_progress,
        )
    except (ConversionCancelledError, KeyboardInterrupt):
        print("\nCancelled.", file=sys.stderr)
        return 130
    except ConversionError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    _print_result(result, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
