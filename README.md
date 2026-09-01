# Certificat core

Headless Python core for extracting a client certificate and an encrypted
PKCS#8 private key from PKCS#12 containers. OpenSSL 3 is used as the
cryptographic backend. The existing scripts in `legacy/` remain the behavioral
reference and are not invoked or modified by the Python package.

## Current status

The headless conversion pipeline, command-line interface, and transactional
output publisher are implemented. Tests cover normal and legacy PKCS#12 input,
secret-free OpenSSL invocation, certificate/key validation, permissions,
cooperative cancellation, and rollback before, between, and after installation
of the output pair. The PySide6 interface, packaged OpenSSL runtime, installers,
and release-security acceptance are not implemented yet.

## Command line

Run the converter from the repository root:

```text
PYTHONPATH=src python3 -m certificat /path/to/client.p12
```

The PKCS#12 password and the new private-key password are requested through
hidden terminal prompts and are never accepted as command-line arguments. Use
`--overwrite` to replace existing outputs, `--openssl PATH` to select a specific
OpenSSL 3 executable, and `--quiet` to suppress progress messages. Installed
packages also expose the `certificat` command.

## Python API

The high-level API is `certificat.convert_pkcs12`. Passwords are passed to child
processes through a per-process environment and never through command-line
arguments. The unencrypted private key flows directly from `openssl pkcs12` to
`openssl pkcs8` through an OS pipe and is not written to disk.

```python
from pathlib import Path

from certificat import ConversionRequest, convert_pkcs12

result = convert_pkcs12(
    ConversionRequest(
        p12_path=Path("client.p12"),
        p12_password="container password",
        private_key_password="new key password",
        overwrite=False,
    )
)

print(result.certificate_path)
print(result.private_key_path)
print(result.mode.value)
```

For cooperative cancellation, create a `CancellationToken`, pass it as the
`cancellation` argument, and call `cancel()` from the UI/controller thread.
An interrupted operation raises `ConversionCancelledError`; temporary files
are cleaned and a publication already in progress is rolled back at its safe
cancellation checkpoints.

Run the test suite from the repository root:

```text
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

