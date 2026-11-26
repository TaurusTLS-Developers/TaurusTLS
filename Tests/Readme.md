# TaurusTLS tests

The Delphi DUnitX projects cover loader lifecycle, cryptographic helpers,
IOHandler initialization and real loopback TLS transfers. Test runs have been
performed on Windows32, Windows64, Linux64 and macOS64. This does not imply
that every target, compiler version or OpenSSL distribution has been validated.

## Build prerequisites

- Delphi with the SDK/toolchain for the selected target. The sources use Delphi
  namespaces and System.IOUtils; project files contain target-specific settings.
- A source version of [DUnitX](https://github.com/VSoftTechnologies/DUnitX)
  supporting the test attributes used here, including AutoNameTestCase.
  DUnitX is an external dependency, not a TaurusTLS submodule. Obtain a separate
  source checkout and configure its Source directory through the DUNITX path
  macro used by the test project (or the compiler search path).
- [Indy](https://github.com/IndySockets/Indy) and the matching TaurusTLS sources.
- OpenSSL 3.x or 4.x matching the executable architecture and linking model.
  Dynamic builds need matching libcrypto/libssl installations; linked targets
  need compatible archives and linker search paths.
- Optional Windows [FastMM5](https://github.com/pleriche/FastMM5) sources and,
  for detailed diagnostics, the matching debug-support DLL.

See the [migration guide](../Migration_to_1_1.md) for initialization,
configuration, providers and deployment. These Delphi tests are distinct from
[the Lazarus menu regression program](Lazarus/README.md).

## Projects and build settings

Open `TaurusTLS.UT.dproj` in RAD Studio and select the platform and configuration.
Check its search paths for TaurusTLS, Indy, DUnitX and optional FastMM5 sources.
Rebuild after changes to compiler defines or linking mode so the tests and
library units use the same configuration. The project uses UNITTEST for test-only
loader reset/hooks; do not enable this define in production builds.

`TaurusTLS.UT.dpr` contains the ordinary suite, including the IOHandler loopback
integration fixtures. Those fixtures need IPv4 loopback sockets and a writable
temporary directory. Their certificate assets are embedded in the test sources.

Provider activation tests run separately, one scenario per process, using
`TaurusTLS.UT.Providers`. Follow its [runner instructions](TaurusTLS.UT.Providers.md)
for supported scenarios, configuration, modules and FIPS prerequisites. The
ordinary suite passing does not establish provider installation or FIPS approval.

The repository also contains focused lifecycle/isolation programs such as
`TaurusTLS.Loader.Shutdown.dpr` and `TaurusTLS.FIPS.Isolation.dpr`. They are not
additional fixtures automatically run by the ordinary executable.

## Running the ordinary suite

Run from the IDE or invoke the newly built executable. For example, from `Tests`:

```powershell
.\Win64\Debug\TaurusTLS.UT.exe -osp:".\test-assets\openssl-x64" --exitbehavior:Continue
.\Win64\Debug\TaurusTLS.UT.exe -osp:".\test-assets\openssl-x64" -oscp:".\test-assets\openssl.cnf" -i:Loader --exitbehavior:Continue
```

Replace example paths with a real installation. A directory name ending in
`.zip` in a local setup must still name an accessible directory, not an archive
that the loader extracts. Match the executable architecture. On Linux run the
compiled executable with the same loader options; on macOS deploy the linked
application and required runtime configuration/trust assets.

DUnitX options control filtering, console output, XML output and exit behavior.
The ordinary runner installs an NUnit XML logger. Inspect the reported failures,
errors and leak results; do not use process exit status as the only diagnostic,
since its outer exception handler prints unexpected exceptions without assigning
an explicit failure exit code. TestInsight builds use a separate runner path.

### Ordinary-suite configuration options

| Option | Meaning |
| --- | --- |
| `--opensslpath:value` / `-osp:value` | Dynamic library search directory; startup default comes from OPENSSL_PATH |
| `--openssl-config-path:value` / `-oscp:value` | Configuration filename; startup default comes from OPENSSL_CONF |

Options configure fixtures; parsing them does not load OpenSSL. The main suite
registers these two loader options. Do not assume provider-runner options such as
module-path/scenario selection are available in this executable. Dynamic suffix
selection follows the loader defaults unless a fixture configures it explicitly.
Static/imported builds ignore the runtime library directory.

Missing optional explicit configuration files are skipped without falling back
to another file. Existing invalid files fail. Use the provider runner for scenarios
that require a specifically validated provider configuration.

## Fixture development and ownership

`TOsslBaseFixture` supplies Loader, SetupFromCmd, Load, Unload, CheckLoaded and
ResetRuntime. It does **not** automatically load OpenSSL for each fixture. Use it
for tests that control loading, failure/reset or configuration themselves.

`TOsslAutoloadFixture` loads once in SetupFixture and resets/unloads in
TearDownFixture. Most tests needing a ready runtime should derive from this class.
Override its virtual fixture methods with the corresponding DUnitX attributes,
call inherited SetupFixture first, and inherited TearDownFixture last. Release
all native consumers and stop worker threads before inherited teardown. Tests
share one process-wide loader and must execute serially.

A False automatic Load result becomes EOsslBaseFixture; exceptions raised by
Load propagate with their original types. Setup failure attempts cleanup, and the
autoload fixture destructor provides fallback cleanup if fixture teardown was
skipped. Individual tests still own and release their own native resources.

Include new units in the test project and register fixtures explicitly:

```pascal
initialization
  TDUnitX.RegisterTestFixture(TMyFixture);
end.
```

Use existing readable helpers and meaningful failure/ownership assertions.
Tests that mutate global loader state must restore it at their owning boundary;
registration callbacks must be removed before their owners are destroyed.

## Windows memory diagnostics

`TaurusTLSUTCompilerDefines.inc` controls optional FastMM5 integration:

- USE_FASTMM5 selects FastMM5 on Windows.
- MEMLEAK_CHECK enables the DUnitX per-test FastMM5 monitor and implies USE_FASTMM5.
- MEMLEAK_DETAILS enables detailed diagnostic support and implies USE_FASTMM5.
- Non-Windows builds disable USE_FASTMM5 in this include.

Define the required symbols in the project compiler settings and supply matching
sources/DLLs. Keep FastMM5 first in the program uses list, as the entry point does.
The fixture class constructor warms process-wide resource caches before test
snapshots. Retained caches and asynchronous teardown still require ownership
analysis; a functional pass does not prove the absence of invalid memory access.

When the FastMM helper is active, its registered options include:

| Option | Meaning |
| --- | --- |
| `--fastmmdebugdll:value` / `-fmd:value` | Debug-support DLL path |
| `--fme:value` / `-fastmmlogenable:value` | Enable/disable detailed logging; this ordering reflects the current registration |
| `--fastmmlogname:value` / `-fml:value` | Event log filename; default comes from FastMM_GetEventLogFilename, not stdout |

These options belong to the optional helper; do not assume they are registered
in builds that omit it. Detailed logging does not replace per-test leak accounting.

## Design references

- [Documentation index](../Doc/README.md)
- [IOHandler initialization](../Doc/Design/IOHandlers/IOHandler_init_HLD.md)
- [Loader design](../Doc/Design/Loader/Loader_paths_HLD.md)
- [Provider design](../Doc/Design/Providers/openssl_providers_HLD.md)
