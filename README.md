# Certificat core

Headless Python core for extracting a client certificate and an encrypted
PKCS#8 private key from PKCS#12 containers. OpenSSL 3 is used as the
cryptographic backend. The existing scripts in `legacy/` remain the behavioral
reference and are not invoked or modified by the Python package.

## Current status

The headless conversion pipeline and the transactional output publisher are
implemented. Unit and integration tests cover normal and legacy PKCS#12 input,
secret-free OpenSSL invocation, certificate/key validation, permissions, and
rollback before, between, and after installation of the output pair. The
PySide6 interface, packaged OpenSSL runtime, installers, and release-security
acceptance are not implemented yet.

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

Run the test suite from the repository root:

```text
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

