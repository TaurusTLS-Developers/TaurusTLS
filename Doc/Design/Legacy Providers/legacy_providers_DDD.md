# TaurusTLS Legacy Provider Integration - DDD

Status: Registration-only unit and config-owning fixtures implemented; execution/isolated archive acceptance pending.
Revision date: 2026-10-24.
Architecture: [Legacy HLD](legacy_providers_HLD.md).
General lifecycle: [OpenSSL DDD](openssl_providers_DDD.md).
Tracking: [Provider plan](openssl_providers_plan.md) and
[loader/readiness checklist](../../Plans/Unit-Tests/Loader-Status-and-Readiness.md).

## 1. Selected contract

Use the default context (`nil`) throughout. Configuration owns provider module
paths, parameters and activation. The loader applies configuration using its
existing `ConfigFile` contract before post-configuration actions.

Retain `Source/TaurusTLS_LegacyProviders.pas` for archive linking and builtin
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
| `TaurusTLS_LegacyProviders` | Optional archive reference and builtin entry-point registration before configuration |
| `TaurusTLS_NTLM` | Stable Indy callbacks, passive readiness/algorithm checks and LM/NT response operations |
| `TaurusTLSFIPS` | Independent hash/FIPS integration and policy reporting, with final policy semantics deferred |

The core loader and NTLM unit must not reference the optional legacy archive unit.
Keep archive ABI declarations behind the existing artifact configuration
(`STATICLOAD_OPENSSL` for Delphi). `OPENSSL_STATIC_LINK_MODEL` alone also selects
startup shared-library imports and is not an archive discriminator.

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

## 4. Remove automatic acquisition and release

Remove the existing manager's retained default/legacy handles, calls to
`OSSL_PROVIDER_load` and matching `OSSL_PROVIDER_unload`, and activation from
initialization/finalization and `Register_SSLLoaderAction` callbacks.

Do not replace these with activation in NTLM, FIPS/hash hooks, a readiness query,
or a new public loader method. OpenSSL configuration supplies activation.

Configuration-owned references stay owned by OpenSSL. A consumer fetches/releases
its own digest, cipher or context objects. Never unload a borrowed handle, drain
reference counts, or treat a reference-count decrease as proof of deactivation.
Normal loader cleanup releases only resources it actually owns; this refactor
does not add explicit provider handles to it.

Review `IsLegacyProviderLoaded` compatibility semantics against ready configured
provider availability after the manager handles are removed. A passive status
query must not load/reset the loader or activate providers; provider presence
alone does not guarantee MD4/DES permission. Exact facade implementation is pending.

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
  `TaurusTLSFIPS` or `TaurusTLS_LegacyProviders`.
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

Final `GetFIPSMode`/`SetFIPSMode`, provenance and broader HMAC work remain
separately reviewed. Static FIPS is unsupported; no certification claim follows
from loading a module, passing a vector or reporting loader readiness.

## 7. Test runner and package changes

The regular runner retains UT.LegacyProviders for coverage, but its production
legacy dependency is now conditional on STATICLOAD_OPENSSL. Category exclusion
still does not suppress unit initialization; the shared dependency is actually
absent and the archive dependency only registers.

Provider fixtures now use the manual base with their own temporary configuration.
A shared-runtime negative fixture omits activate, then checks legacy, MD4 and DES
are unavailable. Static/archive absence remains a separate fresh-process check
because configuration activation can survive static Unload.

Audit `TaurusTLS_RT` membership/transitive initialization as well as application
uses clauses. NTLM-only and FIPS-only executable checks must prove that optional
integration is not accidentally supplied by the combined runner.

## 8. Fixtures and acceptance matrix

The manual `TOsslBaseFixture` provides a loader and configuration/lifecycle
helpers; it does not eagerly load OpenSSL. `TOsslAutoloadFixture` supplies the
automatic lifecycle for fixtures that need it.

NTLM test changes are committed in `0b42e6a`. The positive fixture creates and
applies a unique temporary default/legacy config before loading, discovers an
existing architecture-matched module where appropriate, then unloads, restores
loader settings and deletes temporary files. Cleanup on setup failure and a
destructor fallback are covered by the fixture implementation. These are controlled
non-FIPS tests, not customer policy defaults.

| Pending case | Expected observation |
|---|---|
| Shared build, config activation | Matching module loads without the legacy wrapper unit |
| Archive inclusion without activation | Entry point is registered but legacy algorithms remain unavailable |
| Archive config activation | Linked provider activates after registration, without external module loading |
| Unused module with invalid path and no activation | No implicit attempt to activate it |
| Missing required provider/algorithm | Passive status false; operations report the established failure |
| FIPS selection or denying Indy policy | NTLM algorithms stay unavailable/prohibited; no fallback activation |
| Multiple consumers | Share configured provider; own only fetched algorithm objects |
| Repeated ready Load | No duplicate preparation/configuration or callback assignment |
| Failure/retry and static retained context | Registration/config lifetime handled without assumed native reset |
| Optional dependency isolation | Dynamic NTLM/FIPS runners do not pull in the legacy unit |
| Shutdown | Operations and objects retired before native library release |

Run distinct default-context configurations in fresh processes where isolation is
required. Existing combined-runner results do not validate the pending refactor.
Developer results before this refactor: Windows32/64 each 522/522, Linux 509/510,
macOS 472/473. Non-Windows category inclusion and remaining failure identities were
not supplied. No new platform or FPC validation is implied.

## 9. References

- [OpenSSL provider API](https://docs.openssl.org/3.0/man3/OSSL_PROVIDER/)
- [Provider configuration](https://docs.openssl.org/4.0/man5/config/#provider-configuration)
- [FIPS guidance](https://docs.openssl.org/4.0/man7/fips_module/)
