param(
    [Parameter(Mandatory = $true)]
    [string]$P12
)

$ErrorActionPreference = "Continue"

function Fail($Message) {
    Write-Host ""
    Write-Host "ERROR: $Message" -ForegroundColor Red
    exit 1
}

function Info($Message) {
    Write-Host "==> $Message"
}

# ----------------------------------------
# Find OpenSSL 3.x
# ----------------------------------------

function Find-OpenSSL {
    $candidates = @()

    $cmd = Get-Command openssl -ErrorAction SilentlyContinue

    if ($cmd) {
        $candidates += $cmd.Source
    }

    $candidates += @(
        "C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
        "C:\Program Files\OpenSSL-Win32\bin\openssl.exe",
        "C:\Program Files (x86)\OpenSSL-Win32\bin\openssl.exe",
        "C:\Program Files\Git\usr\bin\openssl.exe",
        "C:\Program Files\Git\mingw64\bin\openssl.exe"
    )

    foreach ($candidate in $candidates | Select-Object -Unique) {

        if (-not $candidate) {
            continue
        }

        if (-not (Test-Path $candidate)) {
            continue
        }

        try {
            $version = & $candidate version 2>$null

            if (
                $LASTEXITCODE -eq 0 -and
                $version -match "^OpenSSL 3\."
            ) {
                return $candidate
            }
        }
        catch {
        }
    }

    return $null
}

# ----------------------------------------
# Find legacy.dll
# ----------------------------------------

function Find-LegacyProvider {
    param(
        [string]$OpenSSLPath
    )

    $OpenSSLDir = Split-Path $OpenSSLPath -Parent

    $possiblePaths = @(
        (Join-Path $OpenSSLDir "legacy.dll"),
        (Join-Path $OpenSSLDir "ossl-modules\legacy.dll"),
        (Join-Path $OpenSSLDir "..\lib\ossl-modules\legacy.dll"),
        (Join-Path $OpenSSLDir "..\lib64\ossl-modules\legacy.dll"),
        "C:\Program Files\OpenSSL-Win64\bin\legacy.dll",
        "C:\Program Files\OpenSSL-Win64\lib\ossl-modules\legacy.dll",
        "C:\Program Files\OpenSSL-Win32\bin\legacy.dll",
        "C:\Program Files\OpenSSL-Win32\lib\ossl-modules\legacy.dll"
    )

    foreach ($path in $possiblePaths | Select-Object -Unique) {

        try {
            $resolved = [System.IO.Path]::GetFullPath($path)
        }
        catch {
            continue
        }

        if (Test-Path $resolved -PathType Leaf) {
            return $resolved
        }
    }

    return $null
}

# ----------------------------------------
# Find OpenSSL
# ----------------------------------------

$OpenSSL = Find-OpenSSL

if (-not $OpenSSL) {

    Write-Host ""
    Write-Host "OpenSSL 3.x was not found."
    Write-Host ""
    Write-Host "Install OpenSSL 3.x and run the script again."

    exit 1
}

Info "Using OpenSSL:"
Write-Host "    $OpenSSL"
& $OpenSSL version

# ----------------------------------------
# Find legacy provider
# ----------------------------------------

$LegacyDLL = Find-LegacyProvider -OpenSSLPath $OpenSSL

if ($LegacyDLL) {

    $LegacyDir = Split-Path $LegacyDLL -Parent

    Info "Legacy provider found:"
    Write-Host "    $LegacyDLL"

}
else {

    $LegacyDir = $null

    Write-Host ""
    Write-Host "Legacy provider was not found."
    Write-Host "Normal PKCS#12 files can still be processed."
    Write-Host "Legacy PKCS#12 files may fail."

}

# ----------------------------------------
# Input file
# ----------------------------------------

if (-not (Test-Path $P12 -PathType Leaf)) {
    Fail "File not found: $P12"
}

$P12 = (Resolve-Path $P12).Path

$Dir = Split-Path $P12 -Parent
$Base = [System.IO.Path]::GetFileNameWithoutExtension($P12)

$Cert = Join-Path $Dir "$Base.crt"
$EncKey = Join-Path $Dir "${Base}_private_encrypted.key"

# ----------------------------------------
# Temporary directory
# ----------------------------------------

$TmpDir = Join-Path `
    ([System.IO.Path]::GetTempPath()) `
    ("p12-" + [guid]::NewGuid().ToString())

New-Item `
    -ItemType Directory `
    -Path $TmpDir |
    Out-Null

$TmpCert = Join-Path $TmpDir "certificate.pem"
$TmpKey = Join-Path $TmpDir "private.key"
$TmpCertPub = Join-Path $TmpDir "cert-public.pem"
$TmpKeyPub = Join-Path $TmpDir "key-public.pem"

# Save old OPENSSL_MODULES
$OldOpenSSLModules = $env:OPENSSL_MODULES

try {

    # ----------------------------------------
    # Ask for P12 password
    # ----------------------------------------

    Write-Host ""

    $SecureP12Pass = Read-Host `
        "Enter password for P12 container" `
        -AsSecureString

    $Ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR(
        $SecureP12Pass
    )

    try {

        $P12Pass = `
            [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Ptr)

    }
    finally {

        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Ptr)

    }

    $env:P12_PASS = $P12Pass

    # ----------------------------------------
    # Check normal mode
    # ----------------------------------------

    Write-Host ""
    Info "Checking PKCS#12 container..."

    & $OpenSSL pkcs12 `
        -in $P12 `
        -passin env:P12_PASS `
        -noout `
        2>$null

    if ($LASTEXITCODE -eq 0) {

        Info "Container can be read normally."

        $Legacy = $false

    }
    else {

        # ----------------------------------------
        # Try legacy mode
        # ----------------------------------------

        Info "Normal mode failed."

        if (-not $LegacyDir) {

            Fail @"
The PKCS#12 container appears to require legacy mode,
but legacy.dll was not found.
"@

        }

        Info "Trying legacy provider..."

        # Tell OpenSSL where provider DLLs are
        $env:OPENSSL_MODULES = $LegacyDir

        & $OpenSSL pkcs12 `
            -legacy `
            -in $P12 `
            -passin env:P12_PASS `
            -noout `
            2>$null

        if ($LASTEXITCODE -eq 0) {

            $Legacy = $true

            Info "Legacy mode is required."
            Info "OPENSSL_MODULES:"
            Write-Host "    $LegacyDir"

        }
        else {

            Fail @"
Unable to open PKCS#12 container.

Possible causes:
  - incorrect P12 password
  - corrupted P12 file
  - legacy provider cannot be loaded
  - unsupported PKCS#12 structure
"@

        }
    }

    # ----------------------------------------
    # Existing output files
    # ----------------------------------------

    if (
        (Test-Path $Cert) -or
        (Test-Path $EncKey)
    ) {

        Write-Host ""
        Write-Host "Output files already exist:"

        if (Test-Path $Cert) {
            Write-Host "  $Cert"
        }

        if (Test-Path $EncKey) {
            Write-Host "  $EncKey"
        }

        Write-Host ""

        $Answer = Read-Host "Overwrite them? [y/N]"

        if ($Answer -notmatch "^(y|yes)$") {
            Fail "Cancelled."
        }

        Remove-Item `
            $Cert `
            -Force `
            -ErrorAction SilentlyContinue

        Remove-Item `
            $EncKey `
            -Force `
            -ErrorAction SilentlyContinue
    }

    # ----------------------------------------
    # Build common PKCS12 arguments
    # ----------------------------------------

    $BasePkcs12Args = @(
        "pkcs12"
    )

    if ($Legacy) {

        $BasePkcs12Args += @(
            "-legacy",
            "-provider-path",
            $LegacyDir
        )
    }

    # ----------------------------------------
    # Extract certificate
    # ----------------------------------------

    Write-Host ""
    Info "Extracting certificate..."

    $CertArgs = $BasePkcs12Args + @(

        "-in", $P12,
        "-passin", "env:P12_PASS",
        "-clcerts",
        "-nokeys",
        "-out", $TmpCert

    )

    & $OpenSSL @CertArgs

    if ($LASTEXITCODE -ne 0) {
        Fail "Certificate extraction failed."
    }

    # Clean CRT: certificate only
    & $OpenSSL x509 `
        -in $TmpCert `
        -outform PEM `
        -out $Cert

    if ($LASTEXITCODE -ne 0) {
        Fail "Certificate conversion failed."
    }

    Info "Certificate created:"
    Write-Host "    $Cert"

    # ----------------------------------------
    # Extract private key
    # ----------------------------------------

    Write-Host ""
    Info "Extracting private key..."

    $KeyArgs = $BasePkcs12Args + @(

        "-in", $P12,
        "-passin", "env:P12_PASS",
        "-nocerts",
        "-nodes",
        "-out", $TmpKey

    )

    & $OpenSSL @KeyArgs

    if ($LASTEXITCODE -ne 0) {
        Fail "Private key extraction failed."
    }

    # ----------------------------------------
    # Encrypt private key PKCS#8
    # ----------------------------------------

    Write-Host ""
    Info "Encrypting private key as PKCS#8..."
    Write-Host ""
    Write-Host "Enter a NEW password for the private key."
    Write-Host ""

    & $OpenSSL pkcs8 `
        -topk8 `
        -v2 aes-256-cbc `
        -in $TmpKey `
        -out $EncKey

    if ($LASTEXITCODE -ne 0) {
        Fail "Private key encryption failed."
    }

    # Remove unencrypted temp key immediately
    Remove-Item `
        $TmpKey `
        -Force `
        -ErrorAction SilentlyContinue

    Info "Encrypted private key created:"
    Write-Host "    $EncKey"

    # ----------------------------------------
    # Validate certificate
    # ----------------------------------------

    Write-Host ""
    Info "Validating certificate..."

    & $OpenSSL x509 `
        -in $Cert `
        -noout

    if ($LASTEXITCODE -ne 0) {
        Fail "Certificate validation failed."
    }

    Info "Certificate is valid."

    # ----------------------------------------
    # Check certificate/private key pair
    # ----------------------------------------

    Write-Host ""
    Info "Checking certificate and private key match..."
    Write-Host ""
    Write-Host "Enter the NEW private-key password once more."
    Write-Host ""

    & $OpenSSL x509 `
        -in $Cert `
        -pubkey `
        -noout `
        -out $TmpCertPub

    if ($LASTEXITCODE -ne 0) {
        Fail "Failed to read certificate public key."
    }

    & $OpenSSL pkey `
        -in $EncKey `
        -pubout `
        -out $TmpKeyPub

    if ($LASTEXITCODE -ne 0) {
        Fail "Failed to read encrypted private key."
    }

    $CertHash = (
        Get-FileHash `
            $TmpCertPub `
            -Algorithm SHA256
    ).Hash

    $KeyHash = (
        Get-FileHash `
            $TmpKeyPub `
            -Algorithm SHA256
    ).Hash

    if ($CertHash -ne $KeyHash) {
        Fail "Certificate and private key do NOT match."
    }

    Info "Certificate and private key match."

    # ----------------------------------------
    # Success
    # ----------------------------------------

    Write-Host ""
    Write-Host "========================================"
    Write-Host "SUCCESS"
    Write-Host "========================================"
    Write-Host ""

    Write-Host "Certificate:"
    Write-Host "  $Cert"
    Write-Host ""

    Write-Host "Encrypted private key:"
    Write-Host "  $EncKey"
    Write-Host ""

    Write-Host "Private key format:"
    Write-Host "  PKCS#8 / PEM"
    Write-Host ""

    Write-Host "Encryption:"
    Write-Host "  PBES2 + PBKDF2 + AES-256-CBC"

}
finally {

    # ----------------------------------------
    # Remove password
    # ----------------------------------------

    Remove-Item `
        Env:P12_PASS `
        -ErrorAction SilentlyContinue

    # ----------------------------------------
    # Restore OPENSSL_MODULES
    # ----------------------------------------

    if ($null -eq $OldOpenSSLModules) {

        Remove-Item `
            Env:OPENSSL_MODULES `
            -ErrorAction SilentlyContinue

    }
    else {

        $env:OPENSSL_MODULES = $OldOpenSSLModules

    }

    # ----------------------------------------
    # Delete temporary files
    # ----------------------------------------

    if (Test-Path $TmpDir) {

        Remove-Item `
            $TmpDir `
            -Recurse `
            -Force `
            -ErrorAction SilentlyContinue

    }
}
