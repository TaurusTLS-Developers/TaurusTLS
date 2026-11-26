@echo off
setlocal DisableDelayedExpansion
rem Runs one fresh process per provider configuration. Requires PowerShell 7+.
rem Run this script from CMD or a CI command step. Quote paths containing spaces.
rem Legacy/default example:
rem   TaurusTLS.UT.Providers.Run.cmd -Executable "Win64\Debug\TaurusTLS.UT.Providers.exe" -OpenSSLPath ".\test-assets\openssl-windows-x64.zip"
rem FIPS example (requires matching installed provider/configuration):
rem   TaurusTLS.UT.Providers.Run.cmd -Executable "Win64\Debug\TaurusTLS.UT.Providers.exe" -OpenSSLPath ".\test-assets\openssl-fips-x64" -FIPSModuleConfig ".\test-assets\openssl-fips-x64\fipsmodule.cnf"
rem Pipeline example; each testarg= token forwards one complete test argument:
rem   TaurusTLS.UT.Providers.Run.cmd -Executable "%PROVIDER_TEST_EXE%" -OpenSSLPath "%OPENSSL_PATH%" -ReportDirectory "artifacts\providers" testarg=--hidebanner testarg=-l:Information
rem Optional: -Provider Legacy/FIPS/All, -Scenario NAME, -TimeoutSeconds SECONDS.
rem For a forwarded argument containing spaces, quote the whole testarg= token.
rem Scenario/filter, library/FIPS selection, XML paths and exit behavior are
rem launcher-owned. Other test options are forwarded unchanged to each process.
rem This wrapper propagates the PowerShell/test failure exit code to the caller.
where pwsh.exe >nul 2>&1
if errorlevel 1 (
    echo PowerShell 7 or newer ^(pwsh.exe^) is required. 1>&2
    exit /b 2
)
pwsh.exe -NoLogo -NoProfile -File "%~dp0TaurusTLS.UT.Providers.Run.ps1" %*
exit /b %errorlevel%