# Provider activation tests
Examples use generic, relative test-assets paths. Supply real executable, library
and installed-provider paths through command-line arguments or CI environment
variables. Do not put workstation paths, usernames or private share names in
committed scripts, documentation or project files.

`TaurusTLS.UT.Providers` runs one named scenario per process. A missing, unknown
or unsupported scenario fails before loading OpenSSL. DUnitX run/category filters
are rejected; use `-scenario:<name>` instead.

`TaurusTLS.UT.Providers.Common.pas` extends the existing `TOsslBaseFixture` from
`TaurusTLS.UT.TestClasses.pas`. It reuses `SetupFromCmd`, `Load`, `Unload` and
`Loader`, adding temporary configuration ownership and cleanup. It does not
reference `TaurusTLS.UT.Loader` or register ordinary-suite fixtures.

## Run a single scenario

List scenarios supported by the compiled linking model:

```powershell
.\Win64\Debug\TaurusTLS.UT.Providers.exe -scenario:list
```

Run one Legacy activation case with the matching native distribution:

```powershell
.\Win64\Debug\TaurusTLS.UT.Providers.exe -scenario:legacy-active -osp:".\test-assets\openssl-windows-x64.zip" --exitbehavior:Continue
```

Run an installed FIPS case with matching libraries, provider modules and installed
integrity configuration:

```powershell
.\Win64\Debug\TaurusTLS.UT.Providers.exe -scenario:fips-selected -osp:".\test-assets\openssl-fips-x64" -fmc:".\test-assets\openssl-fips-x64\fipsmodule.cnf" --exitbehavior:Continue
```

The same arguments work on Linux; replace the executable and native paths.
FIPS activation is unsupported in archive/static builds. The native libraries
and modules must match the executable architecture. Do not use the supplied
Win64 FIPS installation with a Win32 executable.

## Run scenarios in separate processes

The external PowerShell 7 script supplies a 30-second deadline, captures logs
and requires one successful case in each XML report. It discovers scenario names
from the executable; no scenario list is duplicated in the script.

```powershell
.\TaurusTLS.UT.Providers.Run.ps1 -Executable .\Win64\Debug\TaurusTLS.UT.Providers.exe -OpenSSLPath '.\test-assets\openssl-fips-x64' -FIPSModuleConfig '.\test-assets\openssl-fips-x64\fipsmodule.cnf'
```

Use `-Provider Legacy` to run the Legacy/default cases without installed FIPS data,
`-Provider FIPS` for FIPS cases, or `-Scenario fips-missing-module` for the
module-free negative case. `-ReportDirectory` and `-TimeoutSeconds` are optional.
The script uses argument arrays, rather than shell command strings, and runs
with `pwsh` on supported Windows/Linux/macOS hosts.

## Scope

The dynamic runner currently exposes 31 cases: 14 Legacy/default and 17 FIPS.
Each invocation executes one case. Native default-context provider state may
survive loader unload; never combine scenarios in one process.

Installed FIPS configuration is read-only. Negative tests modify temporary
copies. The FIPS unit contains no child launching, shell calls, child selectors,
or XML parsing. Those responsibilities belong to the external script.

The ordinary `TaurusTLS.UT` runner retains loader and Indy adapter behavior tests.
It no longer includes the Legacy activation unit or the configured FIPS fixture,
and needs neither installed FIPS data nor a FIPS category exclusion.

The old `TaurusTLS.UT.LegacyProviders.pas` is retained on disk but removed from
the ordinary project; the provider project uses the renamed unit. A separate
archive executable without `TaurusTLS_ProviderLegacy` is still needed to prove
absence of linked registration. Existing archive registration-without-activation
and dependency-map acceptance remain separate follow-up work.

## Windows launchers

`TaurusTLS.UT.Providers.Run.cmd` forwards arguments to
`TaurusTLS.UT.Providers.Run.ps1`. Both require PowerShell 7+ (`pwsh.exe`).
Without installed FIPS data, the default `Auto` selection runs Legacy/default
cases. Supplying `-FIPSModuleConfig` selects all supported cases. Explicit
`-Provider Legacy`, `-Provider FIPS`, `-Provider All` and `-Scenario` override
the automatic choice. Exit codes propagate to the calling shell or CI job.

CMD, using a matching Windows x64 distribution:

```cmd
TaurusTLS.UT.Providers.Run.cmd -Executable "Win64\Debug\TaurusTLS.UT.Providers.exe" -OpenSSLPath ".\test-assets\openssl-windows-x64.zip"
```

PowerShell, including the installed Win64 FIPS provider:

```powershell
.\TaurusTLS.UT.Providers.Run.ps1 -Executable .\Win64\Debug\TaurusTLS.UT.Providers.exe -OpenSSLPath '.\test-assets\openssl-fips-x64' -FIPSModuleConfig '.\test-assets\openssl-fips-x64\fipsmodule.cnf'
```

Use the Win32 executable and x86 distribution for Win32 Legacy/default tests.
FIPS scenarios require an architecture-matched FIPS installation.

## Linux and macOS Bash launcher

`TaurusTLS.UT.Providers.Run.sh` supports the Bash 3.2 supplied with macOS and
newer Linux Bash. Invoke it through `bash`; executable file permissions on the
script itself are not required. The compiled test executable must be executable.
No PowerShell, Python, GNU `timeout` or GNU-specific Bash utilities are needed.
Each invocation has a deadline, separate log and XML report. Only one successful
DUnitX test-case record is accepted per scenario.

Linux, Legacy/default cases:

```bash
bash ./TaurusTLS.UT.Providers.Run.sh --executable ./Linux64/Debug/TaurusTLS.UT.Providers --openssl-path ./test-assets/openssl/lib
```

Linux, including an installed FIPS provider:

```bash
bash ./TaurusTLS.UT.Providers.Run.sh --executable ./Linux64/Debug/TaurusTLS.UT.Providers --openssl-path ./test-assets/openssl/lib --fips-config ./test-assets/openssl/lib/fipsmodule.cnf
```

macOS, using the deployed archive-linked executable:

```bash
bash ./TaurusTLS.UT.Providers.Run.sh --executable ./TaurusTLS.UT.Providers
```

macOS always selects Legacy/default cases, even with `--provider all`, and
rejects explicit FIPS scenario requests. No FIPS installation is needed there.
The executable's linking model determines which Legacy scenarios are available.

Use `--scenario legacy-active` (repeat for additional cases), `--provider legacy`,
`--provider fips`, `--report-directory DIR` and `--timeout SECONDS` as needed.
`--help` lists all options. Each selected case still runs in its own process.

## Passing extra test arguments from a pipeline

All three launchers now include inline run and CI examples. Extra test options
are forwarded as separate arguments to each scenario process, preserving spaces
and punctuation. They are not forwarded to scenario discovery.

PowerShell: pass an array (also documented by `Get-Help .\TaurusTLS.UT.Providers.Run.ps1 -Examples`):

```powershell
$testOptions = @('--hidebanner', '-l:Information')
.\TaurusTLS.UT.Providers.Run.ps1 -Executable $env:PROVIDER_TEST_EXE -OpenSSLPath $env:OPENSSL_PATH -ReportDirectory './artifacts/providers' -TestArguments $testOptions
```

CMD: repeat `testarg=VALUE`; quote the whole token if the value contains spaces:

```cmd
TaurusTLS.UT.Providers.Run.cmd -Executable "%PROVIDER_TEST_EXE%" -OpenSSLPath "%OPENSSL_PATH%" -ReportDirectory "artifacts\providers" testarg=--hidebanner testarg=-l:Information
```

Bash: put extra test arguments after `--`, preserving array quoting in CI:

```bash
test_options=(--hidebanner -l:Information)
bash ./TaurusTLS.UT.Providers.Run.sh --executable "$PROVIDER_TEST_EXE" --openssl-path "$OPENSSL_PATH" --report-directory ./artifacts/providers -- "${test_options[@]}"
```

Scenario/filter switches, library/FIPS selection, XML filenames, help and exit
behavior remain launcher-owned. Set these through launcher options, including
`-Scenario`/`--scenario`, `-OpenSSLPath`/`--openssl-path`,
`-FIPSModuleConfig`/`--fips-config` and `-ReportDirectory`/`--report-directory`.
Other supported runner options are passed directly. Invalid forwarded options
fail the scenario and propagate a nonzero script exit code.
