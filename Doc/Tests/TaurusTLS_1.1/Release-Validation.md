# TaurusTLS 1.1 release validation

Recorded: 2026-11-26.
Scope: common Delphi test suite, standalone loader lifecycle probes, adapter
isolation and separate provider scenarios for the 1.1 release branch.

## Exit requirement status

The common suite passed on Linux64, macOS64, Win32 and Win64. Windows adapter
isolation checks passed on both architectures. The full dynamic provider scenario
set passed on Win64; Win32 Legacy/default and missing-FIPS rejection checks passed.

**Installed Win32 FIPS validation remains outstanding.** No matching installed
x86 FIPS module/configuration was available for these runs. Release owners must
either complete that validation or explicitly accept it as outside the release's
validated scope. This record does not provide an unconditional release sign-off
or count unavailable coverage as passed.

## Common unit and integration tests

The developer supplied the following successful TaurusTLS.UT results after the
POSIX path-buffer correction, PAnsiChar(@LResolved):

| Target | Passed / total |
| --- | ---: |
| Linux64 | 684/684 |
| macOS64 | 628/628 |
| Win32 | 697/697 |
| Win64 | 697/697 |

The correction passes the address of the destination array to realpath instead
of converting its first character into temporary string storage. These totals
are developer-reported results, not newly executed suites during preparation of
this record. They do not independently establish memory-sanitizer cleanliness.

## Standalone loader lifecycle tests

TaurusTLS.Loader.Shutdown and TaurusTLS.Loader.FirstCreation were updated to
recognize ErrUnBound as the unloaded dynamic binding rather than requiring nil.
The developer confirmed both standalone programs passed after correction. A
locally rebuilt Win64 FirstCreation run also passed its candidate-publication,
singleton identity and no-implicit-loading checks.

The developer's confirmation did not separately enumerate every architecture or
the shutdown cleanup-failure injection mode; this record does not infer that matrix.
The shutdown program covers reverse cleanup callbacks and final state/metadata
checks. It does not prove OS module release or singleton destruction while
external interfaces are retained.

## Windows adapter isolation

Debug executables were rebuilt through RAD Studio for Win32 and Win64 and run
in fresh processes with matching dynamic OpenSSL 4.0.2 distributions.

| Program / mode | Win32 | Win64 |
| --- | --- | --- |
| TaurusTLS.NTLM.Isolation | Passed | Passed |
| TaurusTLS.FIPS.Isolation | Passed | Passed |
| TaurusTLS.FIPS.Isolation --missing-module | Passed | Passed |

All six executions returned exit code zero. These probes validate adapter hook
isolation, configuration ownership and rejection paths without requiring an
installed FIPS module. They are not positive FIPS-provider activation evidence.

## Separate provider scenarios

The PowerShell provider launcher ran each selected scenario in its own process
and checked the individual XML result, exit status and deadline.

| Target and native setup | Scenarios | Result |
| --- | --- | ---: |
| Win64, installed OpenSSL 4.1.0 x64 runtime with FIPS installation data | Legacy/default | 14/14 |
| Win64, same installed runtime | FIPS activation/policy/negative cases | 17/17 |
| Win32, OpenSSL 4.0.2 x86 distribution | Legacy/default | 14/14 |
| Win32, same distribution; no installed FIPS required | fips-missing-module | 1/1 |

Win64 completed **31/31** scenarios. FIPS cases include selected/unselected
policy, digest and HMAC results, Legacy rejection, self-test, reload, inactive
provider behavior and invalid installation/configuration data.

Win32 completed **15/15 selected scenarios**; this is not a 31-case pass. Positive
installed-FIPS and associated installation-data cases remain unvalidated there.

Reports were generated under the local test output directories:

- Tests/Win64/Debug/provider-release-check
- Tests/Win32/Debug/provider-release-check
- Tests/Win32/Debug/provider-release-check-fips-negative

Logs/XML and installed native assets are runtime artifacts, not part of this
published record. Existing Indy compiler warnings and a provider-test unused-value
hint did not prevent successful builds. No provider/isolation source correction
was required by these runs.

## Boundaries and remaining decision

- Linux/macOS totals do not establish execution of the separate provider runner
  or standalone isolation programs on those targets.
- Selected tests do not establish every compiler, SDK, distribution or linking
  model. Static FIPS support is not claimed.
- Successful functional assertions do not replace investigation of a reported
  invalid memory access, leak or asynchronous teardown issue.
- An installed and selected FIPS provider does not certify an application.
- Record the release owner's Win32 installed-FIPS coverage decision before
  treating this evidence as complete release exit approval.

## Reproduction guidance

- [Test setup and fixture ownership](../../../Tests/Readme.md)
- [Provider runner and prerequisites](../../../Tests/TaurusTLS.UT.Providers.md)
- [Migration and deployment](../../../Migration_to_1_1.md)
- [IOHandler design](../../Design/IOHandlers/IOHandler_init_HLD.md)
- [Loader design](../../Design/Loader/Loader_paths_HLD.md)
