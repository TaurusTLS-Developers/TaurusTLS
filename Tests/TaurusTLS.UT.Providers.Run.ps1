<#
.SYNOPSIS
Runs each selected provider configuration in a fresh test process.
.DESCRIPTION
Requires PowerShell 7+. Auto selects Legacy/default cases, adding FIPS when
-FIPSModuleConfig is supplied. macOS excludes FIPS. Logs and XML reports are
written separately for every scenario; a failure or timeout returns exit code 1.

Use -Executable for the compiled test program and -OpenSSLPath for a matching
native distribution. Use -Scenario for individual cases, -Provider for a group,
-ReportDirectory for CI artifacts and -TimeoutSeconds for the per-case deadline.
.PARAMETER TestArguments
Additional arguments forwarded unchanged to every test invocation, not discovery.
In PowerShell, pass an array of strings. Through CMD, repeat testarg=VALUE tokens
and quote the entire token when its value contains spaces. No shell evaluation
or command-string construction is used for child arguments.

Scenario/filter, library/FIPS selection, XML filename and exit behavior belong
to the launcher. Use its named parameters instead of forwarding those switches.
.EXAMPLE
.\TaurusTLS.UT.Providers.Run.ps1 -Executable .\Win64\Debug\TaurusTLS.UT.Providers.exe -OpenSSLPath '.\test-assets\openssl-windows-x64.zip'
Runs all Legacy/default configurations with the selected x64 distribution.
.EXAMPLE
.\TaurusTLS.UT.Providers.Run.ps1 -Executable .\Win64\Debug\TaurusTLS.UT.Providers.exe -OpenSSLPath '.\test-assets\openssl-fips-x64' -FIPSModuleConfig '.\test-assets\openssl-fips-x64\fipsmodule.cnf'
Runs all configurations, including FIPS, with matching installed provider data.
.EXAMPLE
$runnerOptions = @('--hidebanner', '-l:Information')
.\TaurusTLS.UT.Providers.Run.ps1 -Executable $env:PROVIDER_TEST_EXE -OpenSSLPath $env:OPENSSL_PATH -ReportDirectory './artifacts/providers' -TestArguments $runnerOptions
CI example forwarding additional DUnitX options to every scenario process.
#>

#requires -Version 7.0

[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory)][string]$Executable,
    [Parameter(Mandatory)][string]$OpenSSLPath,
    [ValidateSet('Auto', 'All', 'Legacy', 'FIPS')][string]$Provider = 'Auto',
    [string]$FIPSModuleConfig,
    [string[]]$Scenario,
    [string]$ReportDirectory,
    [ValidateRange(1, 600)][int]$TimeoutSeconds = 30,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$TestArguments = @()
)

$ErrorActionPreference = 'Stop'
$forwardedArguments = @($TestArguments | ForEach-Object {
    if ($_.StartsWith('testarg=', [System.StringComparison]::OrdinalIgnoreCase)) {
        $_.Substring(8)
    } else {
        $_
    }
})
foreach ($testArgument in $forwardedArguments) {
    if ($testArgument -match '^(?:--?|/)(?:scenario|sc|run|r|runlist|rl|include|i|exclude|e|xml|xmlfile|exitbehavior|exit|osp|opensslpath|fmc|fips-module-config|help|h|\?)(?:[:=]|$)') {
        throw "Launcher-owned option cannot be forwarded: $testArgument. Use the launcher parameters instead."
    }
}
# Default to ordinary providers unless installed FIPS data was supplied.
if ($IsMacOS) {
    if ($Provider -eq 'FIPS' -or @($Scenario | Where-Object { $_ -like 'fips-*' }).Count -gt 0) {
        throw 'FIPS provider scenarios are unsupported on macOS'
    }
    $Provider = 'Legacy'
    $FIPSModuleConfig = $null
} elseif ($Provider -eq 'Auto') {
    $Provider = if ($FIPSModuleConfig) { 'All' } else { 'Legacy' }
}
$providerExecutable = (Resolve-Path -LiteralPath $Executable).Path
$availableScenarios = @(& $providerExecutable -scenario:list --exitbehavior:Continue |
    Where-Object { $_ -match '^[a-z0-9]+(-[a-z0-9]+)+$' })
if ($LASTEXITCODE -ne 0 -or $availableScenarios.Count -eq 0) {
    throw 'Cannot obtain the provider runner scenario list'
}
if ($Scenario) {
    $selectedScenarios = $Scenario
    foreach ($caseName in $selectedScenarios) {
        if ($caseName -notin $availableScenarios) {
            throw "Unknown or unsupported provider scenario: $caseName"
        }
    }
} else {
    $selectedScenarios = @($availableScenarios | Where-Object {
        $Provider -eq 'All' -or
        ($Provider -eq 'FIPS' -and $_.StartsWith('fips-')) -or
        ($Provider -eq 'Legacy' -and -not $_.StartsWith('fips-'))
    })
}
if ($selectedScenarios.Count -eq 0) { throw 'No supported scenarios selected' }
$requiresInstalledFIPS = @($selectedScenarios | Where-Object {
    $_.StartsWith('fips-') -and $_ -ne 'fips-missing-module'
}).Count -gt 0
if ($requiresInstalledFIPS -and -not $FIPSModuleConfig) {
    throw 'Selected FIPS scenarios require -FIPSModuleConfig with installed fipsmodule.cnf'
}
if (-not $ReportDirectory) {
    $ReportDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ('TaurusTLS-Providers-' + [guid]::NewGuid().ToString('N'))
}
New-Item -ItemType Directory -Path $ReportDirectory -Force | Out-Null
$ReportDirectory = (Resolve-Path -LiteralPath $ReportDirectory).Path
$failedScenarios = 0

foreach ($caseName in $selectedScenarios) {
    # A unique basename prevents an old report from satisfying a new invocation.
    $reportStem = Join-Path $ReportDirectory ($caseName + '-' + [guid]::NewGuid().ToString('N'))
    $xmlPath = $reportStem + '.xml'
    $logPath = $reportStem + '.log'
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $providerExecutable
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in @("-scenario:$caseName", "-osp:$OpenSSLPath",
        '--exitbehavior:Continue', '-cm:Quiet', "--xml:$xmlPath")) {
        $startInfo.ArgumentList.Add($argument)
    }
    if ($FIPSModuleConfig) { $startInfo.ArgumentList.Add("-fmc:$FIPSModuleConfig") }
    foreach ($testArgument in $forwardedArguments) {
        $startInfo.ArgumentList.Add($testArgument)
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $scenarioPassed = $false
    try {
        if (-not $process.Start()) { throw "Cannot start scenario $caseName" }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $finished = $process.WaitForExit($TimeoutSeconds * 1000)
        if (-not $finished) {
            $process.Kill($true)
            $process.WaitForExit()
        }
        $diagnostics = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
        [System.IO.File]::WriteAllText($logPath, $diagnostics)
        if ($finished -and $process.ExitCode -eq 0 -and (Test-Path -LiteralPath $xmlPath)) {
            [xml]$report = Get-Content -Raw -LiteralPath $xmlPath
            $testCases = @($report.SelectNodes('//test-case'))
            $scenarioPassed = $testCases.Count -eq 1 -and
                $testCases[0].executed -eq 'True' -and $testCases[0].result -eq 'Success'
        }
        if ($scenarioPassed) {
            Write-Output "PASS $caseName"
        } else {
            $failedScenarios++
            $reason = if ($finished) { "exit $($process.ExitCode)" } else { 'timeout' }
            Write-Output "FAIL $caseName ($reason); log: $logPath"
        }
    } finally {
        $process.Dispose()
    }
}
Write-Output "$($selectedScenarios.Count - $failedScenarios)/$($selectedScenarios.Count) scenarios passed. Reports: $ReportDirectory"
if ($failedScenarios -gt 0) { exit 1 }
