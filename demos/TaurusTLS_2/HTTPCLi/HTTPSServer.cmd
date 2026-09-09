@echo off
setlocal EnableExtensions EnableDelayedExpansion

:: ============================================================================
:: TaurusTLS Web Server Emulation Script
:: Target: OpenSSL 3.x / 4.x s_server
:: Modes: PKI Generation, No-SNI, SNI, ECH
:: ============================================================================

set "SCRIPT_DIR=%~dp0"
set "PORT=8443"
set "OPENSSL_DIR="
set "MODE="
set "EXTRA_ARGS="
set "OPENSSL_BIN="

:: ----------------------------------------------------------------------------
:: Command-Line Argument Parsing
:: ----------------------------------------------------------------------------
:parse_args
if "%~1"=="" goto validate_env

if /i "%~1"=="/?" goto show_help
if /i "%~1"=="-h" goto show_help
if /i "%~1"=="--help" goto show_help

if /i "%~1"=="/O" (
    set "OPENSSL_DIR=%~2"
    shift
    shift
    goto parse_args
)
if /i "%~1"=="--openssl-dir" (
    set "OPENSSL_DIR=%~2"
    shift
    shift
    goto parse_args
)
if /i "%~1"=="/M" (
    set "MODE=%~2"
    shift
    shift
    goto parse_args
)
if /i "%~1"=="--mode" (
    set "MODE=%~2"
    shift
    shift
    goto parse_args
)
if /i "%~1"=="/P" (
    set "PORT=%~2"
    shift
    shift
    goto parse_args
)
if /i "%~1"=="--port" (
    set "PORT=%~2"
    shift
    shift
    goto parse_args
)
if /i "%~1"=="/X" (
    set "EXTRA_ARGS=%~2"
    shift
    shift
    goto parse_args
)
if /i "%~1"=="--extra" (
    set "EXTRA_ARGS=%~2"
    shift
    shift
    goto parse_args
)

:: If unknown parameter starts with quote or tick, consider it extra args
set "PARAM=%~1"
if "!PARAM:~0,1!"=="'" (
    set "EXTRA_ARGS=!PARAM!"
    shift
    goto parse_args
)

echo [WARN] Unknown parameter: %~1
shift
goto parse_args


:: ----------------------------------------------------------------------------
:: Displays command-line parameters help screen
:: ----------------------------------------------------------------------------
:show_help
echo.
echo TaurusTLS Server Emulation Script
echo.
echo Usage:
echo   %~nx0 [/O ^<path^>] [/M ^<mode^>] [/P ^<port^>] [/X '^<extra_args^>']
echo   %~nx0 [/? ^| -h ^| --help]
echo.
echo Parameters:
echo   /O, --openssl-dir ^<path^>    Path to OpenSSL installation directory or bin folder.
echo                                If omitted, OpenSSL will be resolved from system PATH.
echo   /M, --mode ^<mode^>           Operation mode. If omitted, on-screen menu is displayed.
echo                                Supported modes:
echo                                  pki   - Generate CA, server certificates, and ECH key.
echo                                  nosni - Run direct connect server (localhost/default).
echo                                  sni   - Run server with SNI switching to 'sni.demo.tld'.
echo                                  ech     - Run server with ECH support enabled.
echo                                  clean   - Remove all generated PKI and ECH files.
echo   /P, --port ^<port^>           Listening port (default: 8443).
echo   /X, --extra '^<flags^>'       Additional parameters passed to 'openssl s_server'.
echo                                Must be enclosed in single quotes.
echo.
echo Examples:
echo   %~nx0 /M pki
echo   %~nx0 /M sni /P 8443 /X '-trace -msg'
echo   %~nx0 /O "C:\Program Files\OpenSSL" /M ech
exit /b 0

:: ----------------------------------------------------------------------------
:: Validate Environment & OpenSSL Binary Resolution
:: ----------------------------------------------------------------------------
:validate_env
:: Clean single quotes from EXTRA_ARGS if wrapped
if defined EXTRA_ARGS (
    if "!EXTRA_ARGS:~0,1!"=="'" (
        set "EXTRA_ARGS=!EXTRA_ARGS:~1!"
    )
    if "!EXTRA_ARGS:~-1!"=="'" (
        set "EXTRA_ARGS=!EXTRA_ARGS:~0,-1!"
    )
)

if defined OPENSSL_DIR (
    if exist "%OPENSSL_DIR%\openssl.exe" (
        set "OPENSSL_BIN=%OPENSSL_DIR%\openssl.exe"
    ) else if exist "%OPENSSL_DIR%\bin\openssl.exe" (
        set "OPENSSL_BIN=%OPENSSL_DIR%\bin\openssl.exe"
    ) else (
        echo [ERROR] openssl.exe not found in specified directory: %OPENSSL_DIR%
        exit /b 1
    )
) else (
    where openssl.exe >nul 2>&1
    if !errorlevel! equ 0 (
        for /f "delims=" %%I in ('where openssl.exe') do (
            if not defined OPENSSL_BIN set "OPENSSL_BIN=%%I"
        )
    ) else (
        echo [ERROR] openssl.exe not found in PATH and no /O directory provided.
        exit /b 1
    )
)

echo [INFO] Using OpenSSL binary: %OPENSSL_BIN%

:: If mode is specified, jump directly; otherwise enter interactive menu
if defined MODE goto dispatch_mode
goto main_menu

:: ----------------------------------------------------------------------------
:: Interactive On-Screen Menu
:: ----------------------------------------------------------------------------
:main_menu
echo.
echo ======================================================
echo           TaurusTLS Server Emulation Menu
echo ======================================================
echo Target Port: %PORT%
if defined EXTRA_ARGS echo Extra Flags: %EXTRA_ARGS%
echo.
echo   1. Generate PKI and ECH Materials
echo   2. Run Server: No-SNI (Default / Outer Direct)
echo   3. Run Server: SNI Switching (sni.demo.tld)
echo   4. Run Server: ECH (Outer fallback + Inner sni.demo.tld)
echo   5. Clean-up PKI Artifacts
echo   6. Change Port (Current: %PORT%)
echo   7. Set Extra OpenSSL Parameters
echo   8. Exit
echo ======================================================
set /p "CHOICE=Select an option [1-8]: " <con

if "%CHOICE%"=="1" (
    set "MODE=pki"
    goto exec_pki
)
if "%CHOICE%"=="2" (
    set "MODE=nosni"
    goto exec_nosni
)
if "%CHOICE%"=="3" (
    set "MODE=sni"
    goto exec_sni
)
if "%CHOICE%"=="4" (
    set "MODE=ech"
    goto exec_ech
)
if "%CHOICE%"=="5" (
    set "MODE=clean"
    goto exec_cleanup
)
if "%CHOICE%"=="6" (
    set /p "PORT=Enter new port: " <con
    if not defined PORT set "PORT=8443"
    goto main_menu
)
if "%CHOICE%"=="7" goto menu_set_extra
if "%CHOICE%"=="8" exit /b 0

echo [ERROR] Invalid selection.
goto main_menu
:: ----------------------------------------------------------------------------
:: Dispatcher for CLI-Specified Modes
:: ----------------------------------------------------------------------------
:dispatch_mode
if /i "%MODE%"=="pki"   goto exec_pki
if /i "%MODE%"=="nosni" goto exec_nosni
if /i "%MODE%"=="sni"   goto exec_sni
if /i "%MODE%"=="ech"   goto exec_ech

echo [ERROR] Unknown mode '%MODE%'. Supported: pki, nosni, sni, ech.
exit /b 1

:: ----------------------------------------------------------------------------
:: Action: PKI Generation
:: ----------------------------------------------------------------------------
:: ----------------------------------------------------------------------------
:: Action: PKI Generation (2-Tier Hierarchy + ECH)
:: ----------------------------------------------------------------------------
:exec_pki
echo.
echo [INFO] Generating 2-tier PKI and ECH materials...

cd /d "%SCRIPT_DIR%"

:: ----------------------------------------------------------------------------
:: 1. Root CA (Self-Signed)
:: ----------------------------------------------------------------------------
if not exist "ca_root.key" (
    echo [INFO] Generating Root CA private key...
    "%OPENSSL_BIN%" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca_root.key || goto pki_err
)

(
    echo [ req ]
    echo prompt = no
    echo distinguished_name = dn_root
    echo x509_extensions = v3_ca
    echo [ dn_root ]
    echo C = US
    echo O = TaurusTLS Dev
    echo CN = TaurusTLS Root CA
    echo [ v3_ca ]
    echo basicConstraints = critical, CA:TRUE
    echo keyUsage = critical, keyCertSign, cRLSign
    echo subjectKeyIdentifier = hash
    echo authorityKeyIdentifier = keyid:always,issuer
) > cnf_root.cnf

echo [INFO] Generating Root CA certificate...
"%OPENSSL_BIN%" req -new -x509 -days 3650 -key ca_root.key -out ca_root.crt ^
    -config cnf_root.cnf || goto pki_err
del /f /q cnf_root.cnf

:: ----------------------------------------------------------------------------
:: 2. Intermediate CA (Signed by Root CA)
:: ----------------------------------------------------------------------------
if not exist "ca_intermediate.key" (
    echo [INFO] Generating Intermediate CA private key...
    "%OPENSSL_BIN%" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca_intermediate.key || goto pki_err
)

(
    echo [ req ]
    echo prompt = no
    echo distinguished_name = dn_intermediate
    echo [ dn_intermediate ]
    echo C = US
    echo O = TaurusTLS Dev
    echo CN = TaurusTLS Intermediate CA
) > cnf_inter.cnf

"%OPENSSL_BIN%" req -new -key ca_intermediate.key -out csr_inter.pem ^
    -config cnf_inter.cnf || goto pki_err
del /f /q cnf_inter.cnf

(
    echo basicConstraints = critical, CA:TRUE, pathlen:0
    echo keyUsage = critical, keyCertSign, cRLSign
    echo subjectKeyIdentifier = hash
    echo authorityKeyIdentifier = keyid:always,issuer
) > ext_inter.cnf

"%OPENSSL_BIN%" x509 -req -in csr_inter.pem -CA ca_root.crt -CAkey ca_root.key -CAcreateserial ^
    -out ca_intermediate.crt -days 1825 -extfile ext_inter.cnf || goto pki_err
del /f /q csr_inter.pem ext_inter.cnf

:: Build CA bundle silently
copy /b /y ca_intermediate.crt + ca_root.crt ca_bundle.crt >nul
copy /y ca_root.crt ca.crt >nul

:: ----------------------------------------------------------------------------
:: 3. Default Server Certificate (Outer / Fallback)
:: ----------------------------------------------------------------------------
echo [INFO] Generating Default server key and certificate...
"%OPENSSL_BIN%" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out key_default.pem || goto pki_err

(
    echo [ req ]
    echo prompt = no
    echo distinguished_name = dn_default
    echo [ dn_default ]
    echo CN = localhost
) > cnf_default.cnf

"%OPENSSL_BIN%" req -new -key key_default.pem -out csr_default.pem ^
    -config cnf_default.cnf || goto pki_err
del /f /q cnf_default.cnf

(
    echo basicConstraints = critical, CA:FALSE
    echo keyUsage = critical, digitalSignature, keyEncipherment
    echo extendedKeyUsage = serverAuth
    echo subjectKeyIdentifier = hash
    echo authorityKeyIdentifier = keyid,issuer
    echo subjectAltName = IP:127.0.0.1,IP:::1,DNS:default.demo.tld,DNS:default
) > ext_default.cnf

"%OPENSSL_BIN%" x509 -req -in csr_default.pem -CA ca_intermediate.crt -CAkey ca_intermediate.key -CAcreateserial ^
    -out leaf_default.pem -days 825 -extfile ext_default.cnf || goto pki_err
del /f /q csr_default.pem ext_default.cnf

:: Full chain for s_server (Leaf + Intermediate) silently
copy /b /y leaf_default.pem + ca_intermediate.crt cert_default.pem >nul
del /f /q leaf_default.pem

:: ----------------------------------------------------------------------------
:: 4. SNI Server Certificate (Virtual Host)
:: ----------------------------------------------------------------------------
echo [INFO] Generating SNI server key and certificate...
"%OPENSSL_BIN%" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out key_sni.pem || goto pki_err

(
    echo [ req ]
    echo prompt = no
    echo distinguished_name = dn_sni
    echo [ dn_sni ]
    echo CN = sni.demo.tld
) > cnf_sni.cnf

"%OPENSSL_BIN%" req -new -key key_sni.pem -out csr_sni.pem ^
    -config cnf_sni.cnf || goto pki_err
del /f /q cnf_sni.cnf

(
    echo basicConstraints = critical, CA:FALSE
    echo keyUsage = critical, digitalSignature, keyEncipherment
    echo extendedKeyUsage = serverAuth
    echo subjectKeyIdentifier = hash
    echo authorityKeyIdentifier = keyid,issuer
    echo subjectAltName = DNS:sni.demo.tld,DNS:sni
) > ext_sni.cnf

"%OPENSSL_BIN%" x509 -req -in csr_sni.pem -CA ca_intermediate.crt -CAkey ca_intermediate.key -CAcreateserial ^
    -out leaf_sni.pem -days 825 -extfile ext_sni.cnf || goto pki_err
del /f /q csr_sni.pem ext_sni.cnf

:: Full chain for s_server (Leaf + Intermediate) silently
copy /b /y leaf_sni.pem + ca_intermediate.crt cert_sni.pem >nul
del /f /q leaf_sni.pem

:: ----------------------------------------------------------------------------
:: 5. ECH Keypair Generation (RFC 9934)
:: ----------------------------------------------------------------------------
echo [INFO] Generating ECH keypair...
"%OPENSSL_BIN%" ech -help >nul 2>&1
if !errorlevel! equ 0 (
    "%OPENSSL_BIN%" ech -public_name default.demo.tld -out ech_keypair.pem || goto pki_err
    "%OPENSSL_BIN%" ech -in ech_keypair.pem -out ech_pub.pem || goto pki_err
    echo [INFO] ECH keypair created: %SCRIPT_DIR%ech_keypair.pem
    echo [INFO] Client ECH public config: %SCRIPT_DIR%ech_pub.pem
) else (
    echo [WARN] 'openssl ech' CLI is not supported in this OpenSSL build. Skipping ECH.
)

echo.
echo [INFO] PKI and ECH materials generated successfully.
if not defined MODE goto main_menu
goto end

:pki_err
echo [ERROR] PKI material generation failed.
exit /b 1

:: ----------------------------------------------------------------------------
:: Action: Run Server (No-SNI)
:: ----------------------------------------------------------------------------
:exec_nosni
call :verify_certs cert_default.pem key_default.pem || exit /b 1
echo.
echo [INFO] Starting s_server in No-SNI mode on port %PORT%...
echo Command: "%OPENSSL_BIN%" s_server -accept %PORT% -cert cert_default.pem -key key_default.pem -CAfile ca.crt -www %EXTRA_ARGS%
echo.
"%OPENSSL_BIN%" s_server -accept %PORT% -cert cert_default.pem -key key_default.pem -CAfile ca.crt -www %EXTRA_ARGS% <nul
goto end

:: ----------------------------------------------------------------------------
:: Action: Run Server (SNI Switching)
:: ----------------------------------------------------------------------------
:exec_sni
call :verify_certs cert_default.pem key_default.pem cert_sni.pem key_sni.pem || exit /b 1
echo.
echo [INFO] Starting s_server in SNI mode on port %PORT% (Host switch: sni.demo.tld)...
echo Command: "%OPENSSL_BIN%" s_server -accept %PORT% -cert cert_default.pem -key key_default.pem -servername sni.demo.tld -cert2 cert_sni.pem -key2 key_sni.pem -CAfile ca.crt -www %EXTRA_ARGS%
echo.
"%OPENSSL_BIN%" s_server -accept %PORT% -cert cert_default.pem -key key_default.pem -servername sni.demo.tld -cert2 cert_sni.pem -key2 key_sni.pem -CAfile ca.crt -www %EXTRA_ARGS% <nul
goto end

:: ----------------------------------------------------------------------------
:: Action: Run Server (ECH Mode)
:: ----------------------------------------------------------------------------
:exec_ech
call :verify_certs cert_default.pem key_default.pem cert_sni.pem key_sni.pem ech_keypair.pem || exit /b 1
echo.
echo [INFO] Starting s_server in ECH mode on port %PORT%...
echo Command: "%OPENSSL_BIN%" s_server -accept %PORT% -cert cert_default.pem -key key_default.pem -servername sni.demo.tld -cert2 cert_sni.pem -key2 key_sni.pem -ech_key ech_keypair.pem -CAfile ca.crt -www %EXTRA_ARGS%
echo.
"%OPENSSL_BIN%" s_server -accept %PORT% -cert cert_default.pem -key key_default.pem -servername sni.demo.tld -cert2 cert_sni.pem -key2 key_sni.pem -ech_key ech_keypair.pem -CAfile ca.crt -www %EXTRA_ARGS% <nul
goto end

:: ----------------------------------------------------------------------------
:: Helper: Verify existence of required certificates
:: ----------------------------------------------------------------------------
:verify_certs
if "%~1"=="" exit /b 0

if not exist "%SCRIPT_DIR%%~1" goto :missing_cert_err

shift
goto verify_certs

:missing_cert_err
echo [ERROR] Required artifact "%~1" was not found in:
echo         %SCRIPT_DIR%
echo [ERROR] Run PKI generation [Option 1 or /M pki] to create required materials.
exit /b 1

:: ----------------------------------------------------------------------------
:: Action: Clean-up PKI Artifacts
:: ----------------------------------------------------------------------------
:exec_cleanup
echo.
echo [INFO] Removing generated PKI and ECH artifacts...
cd /d "%SCRIPT_DIR%"

set "FILES_TO_DELETE=ca.crt ca.srl ca_root.key ca_root.crt ca_root.srl ca_intermediate.key ca_intermediate.crt ca_intermediate.srl ca_bundle.crt key_default.pem cert_default.pem leaf_default.pem key_sni.pem cert_sni.pem leaf_sni.pem ech_keypair.pem ech_pub.pem ech.key openssl.cnf ext_default.cnf ext_sni.cnf ext_inter.cnf cnf_root.cnf cnf_inter.cnf cnf_default.cnf cnf_sni.cnf csr_default.pem csr_sni.pem csr_inter.pem"

for %%F in (%FILES_TO_DELETE%) do (
    if exist "%%F" (
        del /f /q "%%F"
        echo [REMOVED] %%F
    )
)

echo [INFO] Clean-up complete.
if not defined MODE goto main_menu
goto end

:: ----------------------------------------------------------------------------
:: Action: Add additional parameters to the openssl.exe
:: ----------------------------------------------------------------------------
:menu_set_extra
echo.
echo Enter OpenSSL flags (enclosed in single quotes, e.g., '-trace -msg'):
set "USER_EXTRA="
set /p "USER_EXTRA=Flags: " <con

if defined USER_EXTRA (
    if "!USER_EXTRA:~0,1!"=="'" set "USER_EXTRA=!USER_EXTRA:~1!"
    if "!USER_EXTRA:~-1!"=="'" set "USER_EXTRA=!USER_EXTRA:~0,-1!"
    set "EXTRA_ARGS=!USER_EXTRA!"
    echo [INFO] Extra arguments set to: !EXTRA_ARGS!
) else (
    set "EXTRA_ARGS="
    echo [INFO] Extra arguments cleared.
)
goto main_menu

:end
endlocal