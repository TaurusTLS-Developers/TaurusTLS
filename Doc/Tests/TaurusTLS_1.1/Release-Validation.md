# TaurusTLS 1.1 release validation

Recorded: 2026-11-26.

The common Delphi test suite passed on Linux64, macOS64, Win32 and Win64.
Windows NTLM/FIPS adapter isolation checks and all separate provider scenarios
passed on both Win32 and Win64.

## Common unit and integration tests

| Target | Passed / total |
| --- | ---: |
| Linux64 | 684/684 |
| macOS64 | 628/628 |
| Win32 | 697/697 |
| Win64 | 697/697 |

These results were supplied by the developer after the POSIX path-buffer fix.
The corrected assignment, PAnsiChar(@LResolved), passes the destination array's
address to realpath.

## Standalone loader lifecycle checks

The standalone shutdown and first-creation programs passed after their unloaded
binding checks were updated to expect ErrUnBound. These checks exercise singleton
identity, initialization state, callback ordering and finalization metadata cleanup.

## Windows adapter isolation

Debug executables were built through RAD Studio and run in fresh processes with
architecture-matched OpenSSL 4.1.0 distributions and their supplied modules.

| Program / mode | Win32 | Win64 |
| --- | --- | --- |
| TaurusTLS.NTLM.Isolation | Passed | Passed |
| TaurusTLS.FIPS.Isolation | Passed | Passed |
| TaurusTLS.FIPS.Isolation --missing-module | Passed | Passed |

All six executions returned exit code zero. These probes cover independent
adapter hooks, configuration ownership and missing-provider rejection.

## Provider activation and FIPS policy

Each provider scenario ran in a separate process using the matching OpenSSL
4.1.0 runtime and installed FIPS configuration. The launcher verified the exit
status, deadline and individual XML test result.

| Scenario group | Win32 | Win64 |
| --- | ---: | ---: |
| Legacy/default | 14/14 | 14/14 |
| FIPS | 17/17 | 17/17 |
| Total | **31/31** | **31/31** |

FIPS coverage includes provider availability and selection, digest and HMAC
vectors, rejection of Legacy operations under FIPS policy, self-tests, reload,
inactive-provider behavior, invalid installation data and missing-module rejection.
Win32 installation data was generated successfully with the matching OpenSSL
fipsinstall command; its installation self-tests passed. The supplied Win64
installation data was used without modification.

## Scope

Results apply to the tested executables, targets and configurations. The
separate provider and adapter-isolation results above cover Windows dynamic
loading; they do not establish static FIPS support or application certification.

## Reproduction guidance

- [Test setup and fixture ownership](../../../Tests/Readme.md)
- [Provider runner and prerequisites](../../../Tests/TaurusTLS.UT.Providers.md)
- [Migration and deployment](../../../Migration_to_1_1.md)
- [IOHandler design](../../Design/IOHandlers/IOHandler_init_HLD.md)
- [Loader design](../../Design/Loader/Loader_paths_HLD.md)
