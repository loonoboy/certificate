# Certificat core

Current application version: **0.2.0-alpha**.

Python application for extracting a client certificate and an encrypted PKCS#8
private key from PKCS#12 containers. The OpenSSL command adapter supports
OpenSSL 1.1.1, 3.x, and 4.x. OpenSSL 2.x never existed as a public release
generation. The existing scripts in `legacy/` remain the behavioral reference
and are not invoked or modified by the Python package.

## Current status

The headless conversion pipeline, command-line interface, and transactional
output publisher are implemented. Tests cover normal and legacy PKCS#12 input,
secret-free OpenSSL invocation, certificate/key validation, permissions,
cooperative cancellation, and rollback before, between, and after installation
of the output pair. The PySide6 interface is available for development use.
The packaged OpenSSL runtime, installers, and release-security acceptance are
not implemented yet.

## Command line

Run the converter from the repository root:

```text
PYTHONPATH=src python3 -m certificat /path/to/client.p12
```

The PKCS#12 password and the new private-key password are requested through
hidden terminal prompts and are never accepted as command-line arguments. Use
`--overwrite` to replace existing outputs, `--openssl PATH` to select a specific
supported OpenSSL executable, and `--quiet` to suppress progress messages.
Installed packages also expose the `certificat` command. Run
`certificat --version` to print the application version.

OpenSSL 1.1.1 uses its built-in legacy algorithms and the historical `-nodes`
option. It is supported for compatibility only and should not be bundled in a
new production release. OpenSSL 3.x and 4.x are first tried normally and then
with `-legacy` and the legacy provider when the container requires old
algorithms.

## Desktop application

Install the optional GUI dependency and start the application:

```text
python3 -m pip install -e ".[gui]"
certificat-gui
```

From a source checkout it can also be started with:

```text
PYTHONPATH=src python3 -m certificat.presentation
```

The window keeps conversion work off the UI thread, permits one active operation,
and supports cooperative cancellation and safe overwrite confirmation.

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
python3 -m pip install -e ".[test]"
python3 -m unittest discover -s tests -v
```

The `test` extra installs PySide6 so the desktop tests run instead of being
skipped. GitHub Actions runs the complete suite on Windows x64, macOS Intel,
and macOS Apple Silicon using the minimum supported Python and Python 3.12.

