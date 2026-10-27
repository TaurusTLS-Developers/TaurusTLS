# TaurusTLS Legacy Provider Integration - DDD

Status: Registration-only provider and independent Indy adapters are committed; isolated Win64 dynamic provider tests pass. Archive/dependency isolation, Release and final non-Windows execution remain pending.
Revision date: 2026-10-27.
Architecture: [Legacy HLD](legacy_providers_HLD.md).
General lifecycle: [OpenSSL DDD](openssl_providers_DDD.md).
Tracking: [Provider plan](openssl_providers_plan.md) and
[loader/readiness checklist](../../Plans/Unit-Tests/Loader-Status-and-Readiness.md).

## 1. Selected contract

Use the default context (`nil`) throughout. Configuration owns provider module
paths, parameters and activation. The loader applies configuration using its
existing `ConfigFile` contract before post-configuration actions.

Retain `Source/TaurusTLS_ProviderLegacy.pas` for archive linking and builtin
registration. Shared-library deployments need no reference to this unit merely
to activate an external module from `openssl.cnf`.

There is no new public `ActivateProvider`, `LoadProvider`, provider registry,
provider path property or FIPS-mode API in `IOpenSSLLoader`. The recent
programmatic activation proposal is superseded by configuration-only activation.

## 2. Unit boundaries

| Unit | Intended responsibilities |
|---|---|
| `TaurusTLSLoader` | Existing native lifecycle, explicit/default configuration, readiness, callback rollback and metadata |
| `TaurusTLSHeaders_provider` | OpenSSL declarations/imports only |
| `TaurusTLS_ProviderLegacy` | Optional archive reference and builtin entry-point registration before configuration |
| `TaurusTLSIdNTLM` | Stable Indy callbacks, passive readiness/algorithm checks and LM/NT response operations |
| `TaurusTLS_ProviderFIPS` | Cached native FIPS API validation and passive `IsFIPSProviderLoaded`; no activation or Indy hooks |
| `TaurusTLSIdFIPS` | Independent Indy hash/HMAC hooks, configured FIPS reporting and a non-mutating policy setter |

The core loader and NTLM unit must not reference the optional legacy archive unit.
Keep archive ABI declarations behind the existing artifact configuration
(`STATICLOAD_OPENSSL` for Delphi). `OPENSSL_STATIC_LINK_MODEL` alone also selects
startup shared-library imports and is not an archive discriminator.

The unit split is delivered in `43b6aa8`. Deprecated `TaurusTLSFIPS` and
`TaurusTLS_NTLM` contain only interface uses of their replacement adapters.
Deprecated `TaurusTLS_LegacyProviders` also forwards the old public status query.
They remain in Source for compatibility and are excluded from current runtime
package membership. Generated package files are rebuilt by the package tool,
rather than edited as part of the source/test commits.

Retain the corrected `cdecl` declaration and parameter types for
`ossl_legacy_provider_init` from the existing header/artifact contract. Keep
the linked symbol reference in the optional unit; do not move it into the core.

## 3. Registration mechanism and lifetime

Under STATICLOAD_OPENSSL, the optional unit registers in its initialization:

~~~pascal
if OSSL_PROVIDER_add_builtin(nil, 'legacy', @ossl_legacy_provider_init) <> 1 then
  ETaurusTLSAPICryptoError.RaiseException(RSLegacyProviderRegisterFailed);
~~~

OpenSSL's add_builtin implementation stores the entry point. It does not load
configuration or activate the provider. Therefore the existing unit initialization
ordering suffices before application Load; no loader phase/API is added.
The existing post-configuration osaLoad callback is removed from this unit.

Initialization is once per Pascal unit lifetime. Static unload/reload and config
failure/retry neither repeat registration nor attempt native unregister. The unit
retains no provider handles and has no provider finalizer. Multiple consumers
share the linked unit. Conflicting same-name registrations by other modules and
already configured external default contexts are outside this ownership contract;
the application must establish registration before its first config/crypto use.

A registration failure raises the existing crypto exception with native error
details and RSLegacyProviderRegisterFailed during startup. No loader transition
has occurred, so this is not reported through its failure circuit breaker.
The unit's compatibility status query returns False while the loader is inactive
and otherwise uses OSSL_PROVIDER_available without acquiring a reference.

Native source review establishes absence of config/activation calls in this path.
Fresh-process archive execution is still required to validate the actual artifact.

## 4. Acquisition, release and passive status

The former manager's retained default/legacy handles, calls to
`OSSL_PROVIDER_load`/`OSSL_PROVIDER_unload` and automatic activation have been
removed. The provider unit performs archive-only registration and passive queries.

Do not replace these with activation in NTLM, FIPS/hash hooks, a readiness query,
or a new public loader method. OpenSSL configuration supplies activation.

Configuration-owned references stay owned by OpenSSL. A consumer fetches/releases
its own digest, cipher or context objects. Never unload a borrowed handle, drain
reference counts, or treat a reference-count decrease as proof of deactivation.
Normal loader cleanup releases only resources it actually owns; this refactor
does not add explicit provider handles to it.

`IsLegacyProviderLoaded` in TaurusTLS_ProviderLegacy returns False unless the
loader is ready; otherwise it evaluates OSSL_PROVIDER_available(nil, 'legacy')
without acquiring a reference. The deprecated wrapper forwards to that function.
It never loads/resets the loader or activates a provider. Availability alone
still does not guarantee MD4/DES permission under current properties.

## 5. Configuration and native initialization

Use `activate = 1` for providers intended to be active. Configuration may include
a matching module path or rely on OpenSSL discovery. Do not parse provider sections
in Delphi, substitute `OpenSSLPath` as a hidden module path, or mutate customer
environment variables.

Archive configs omit external `module` and rely on the previously registered
entry point. Shared-library configs use their matching deployed module.
Explicitly activate default where ordinary non-FIPS applications require it;
do not automatically add it to FIPS configurations.

Empty `ConfigFile` still requests standard configuration initialization.
A discovered default filename does not prove that file was read. Existing
initialization and static unload/reload may retain native configuration/policy.
Rollback does not promise transactional reversal of native configuration.

Omitting a provider's `activate` avoids explicit activation by that config.
Prefer omission to `activate = 0` in cross-version examples because older OpenSSL
versions treated presence as activation. Deferred activation via a public API is
outside the selected implementation scope.

## 6. NTLM and FIPS behavior

NTLM implementation is committed in `95e7bd2`:

- Assign the four Indy callbacks once via initialization; never rewrite them on
  load/unload. Preserve foreign assignments made afterward.
- Retain `IdFIPS` for Indy declarations and policy, with no NTLM dependency on
  `TaurusTLSIdFIPS` or `TaurusTLS_ProviderLegacy`.
- Keep `LoadNTLMLibrary` status-only. Availability checks readiness, Indy policy,
  and fetched MD4/DES-ECB under current default-context properties.
- Preserve pre-existing native errors during a negative availability probe.
- Use direct EVP MD4 over UTF-16LE for NT responses; DES uses expanded odd-parity
  keys, no padding, exact block lengths and checked buffers/output.
- Keep existing platform-default LM encoding and 14-byte truncation. A general
  OEM encoding policy and NTLMv2 RC4 integration remain separate work.

An active FIPS provider is not proof that algorithm selection uses FIPS
implementations. Distinguish native API support, provider availability, configured
properties, Indy policy and actual operation permission. Preserve policy in
availability/operation hooks; do not enable legacy to bypass restrictions.

TaurusTLSIdFIPS reports mode only for a ready supported dynamic runtime with
configured FIPS selection and an available FIPS provider. SetFIPSMode accepts
only a no-op matching that policy. When FIPS is selected but unavailable,
reporting is False and operations reject rather than fall back to default.
Ordinary hashing/HMAC remains supported when FIPS is not selected.
TaurusTLS_ProviderFIPS owns cached API validation and passive provider status;
its loader action does not activate providers. Static FIPS remains unsupported.
Per-operation approval indicators and certification provenance are separate;
a loaded module, vector or readiness query is not a certification claim.

## 7. Test runner and package boundaries

The source split is committed in 43b6aa8; provider test extraction is committed
in 90d409c. The ordinary TaurusTLS.UT project no longer includes the Legacy
activation unit or TConfiguredFIPSProviderFixture. It retains loader/readiness,
native-policy and Indy adapter behavior without installed FIPS prerequisites
or a FIPS category exclusion.

TaurusTLS.UT.Providers.Legacy contains the moved positive configuration/availability
and digest fixtures plus the dynamic no-activation fixture. Its reference to
TaurusTLS_ProviderLegacy remains conditional on STATICLOAD_OPENSSL. The old
TaurusTLS.UT.LegacyProviders file remains on disk but is not in the ordinary project.

TaurusTLS.UT.Providers.Common extends TOsslBaseFixture from
TaurusTLS.UT.TestClasses with temporary-config ownership and cleanup, reusing
SetupFromCmd, Load, Unload and Loader. The Legacy fixture directly uses the same
manual base. Do not reference TaurusTLS.UT.Loader merely for fixture helpers:
its initialization registers ordinary-suite tests.

The provider runner requires -scenario:<known-name>. It lists supported cases
with -scenario:list and rejects missing/unknown selectors or arbitrary DUnitX
run/category filters. After selecting one exact case it rebuilds the DUnitX
filter cached by CheckCommandLine, disables RTTI fixture discovery and requires
one pass with no failures/errors/ignored/leaks. Each process handles one native
configuration scenario. The tests have no process-launch or child-report code.

The external CMD/PowerShell/Bash launchers discover names from that executable,
run each selected case with a deadline and retain logs/XML. PowerShell forwards
-TestArguments arrays, CMD forwards testarg=VALUE tokens and Bash forwards
arguments after --. Launcher-owned selectors, libraries/FIPS input, report
filenames and exit behavior cannot be overridden through forwarded options.
macOS runs only supported Legacy/default cases. Read
[platform instructions](../../../Tests/TaurusTLS.UT.Providers.md); keep published
examples relative or environment-based, with no private paths or identities.

Current runtime package membership includes the new adapter/provider units and
excludes the three deprecated wrappers. Audit actual generated package/linker
closure independently of source uses clauses. An NTLM-only or FIPS-only probe
must not be accidentally supplied with another optional integration by the runner.

## 8. Fixtures and acceptance matrix

Provider fixtures create their own temporary configuration before explicit Load,
unload before settings/file cleanup and handle failed setup/destructor cleanup.
The ordinary NTLM crypto fixture retains its controlled non-FIPS config through
the shared manual infrastructure. These settings are test-owned, not customer
policy defaults. Static unload/retry does not reset OpenSSL's native context.

| Case | Evidence or remaining gate |
|---|---|
| Dynamic config activation without archive unit | 14/14 Win64 Legacy/default scenarios pass in separate processes |
| Dynamic no-activation | Fresh case confirms Legacy/MD4/DES absence; included in those 14 |
| FIPS selection/policy rejection | Covered by the 17 Win64 FIPS scenarios, including active Legacy under fips=yes |
| Archive inclusion without activation | Pending fresh archive execution; registration alone must not supply active Legacy algorithms |
| Archive config activation | Pending fresh archive execution using the linked provider with no external module |
| Archive absence | Requires another executable without TaurusTLS_ProviderLegacy; not proven by the included-unit runner |
| Unused or missing archive provider | Pending artifact-specific absence/failure scenarios |
| Multiple consumers | Pending provider-specific acceptance; own fetched algorithms only, never borrowed provider handles |
| Repeated Load and callback stability | Existing lifecycle/adapter coverage; retain final platform execution evidence |
| Failure/retry and retained static context | Pending provider-specific archive execution; do not assume native reset |
| Optional dependency isolation | Pending linker maps/package closure for adapters and unused archives |
| Shutdown | Existing loader-only probes are separate evidence; all operations/objects must be retired before release |

Dynamic Win64/OpenSSL 4.1 total: 31/31 separate-process scenarios (14 Legacy/default,
17 FIPS); each reports one pass, zero ignored/leaked/failed/errored and exit 0.
The provider Win64 and ordinary Linux64 full builds succeed, with recorded
dependency warnings/hints. Final ordinary-suite execution and actual Linux/macOS
provider runs after extraction remain pending; simulated macOS script checks do
not establish native execution. FPC, Release and remaining archive gates stay open.
Earlier combined-runner/platform totals predate this extraction and are retained
as historical evidence in the local plan, not as acceptance of these final projects.

## 9. References

- [OpenSSL provider API](https://docs.openssl.org/3.0/man3/OSSL_PROVIDER/)
- [Provider configuration](https://docs.openssl.org/4.0/man5/config/#provider-configuration)
- [FIPS guidance](https://docs.openssl.org/4.0/man7/fips_module/)
