# TaurusTLS Legacy Provider Integration - HLD

Status: Provider/Indy separation and dedicated provider tests are committed. Win64 dynamic Legacy/default scenarios pass 14/14; archive and final non-Windows acceptance remain pending.
Revision date: 2026-10-27.
General architecture: [OpenSSL HLD](openssl_providers_HLD.md).
Details: [Legacy DDD](legacy_providers_DDD.md).
Tracking: [Provider plan](openssl_providers_plan.md) and
[loader/readiness checklist](../../Plans/Unit-Tests/Loader-Status-and-Readiness.md).

## 1. Decision and scope

Retain the default OpenSSL library context. OpenSSL configuration owns provider
module paths, parameters and activation. Use `activate = 1` in `openssl.cnf`
to activate a provider when the loader applies configuration. Neither NTLM nor
FIPS integration implicitly acquires providers.

The proposed unified `ActivateProvider` API and NTLM `osaLoad` activation
alternative were considered and are not part of the selected design. No public
provider manager, second reference counter or provider search-path API is needed.

This revision replaces the earlier automatic default/legacy activation design.
Including a unit must not opt the application into an algorithm policy.

## 2. Deployment and optional units

| Deployment | Legacy support required | Activation owner |
|---|---|---|
| Runtime-loaded shared libraries | Deploy a matching external legacy module; name its path or use standard OpenSSL discovery in configuration | OpenSSL configuration |
| Startup shared-library imports | Same external-module arrangement; direct imports do not imply a linked provider archive | OpenSSL configuration |
| Linked archives, including Delphi macOS | Explicitly include `TaurusTLS_ProviderLegacy` to link the legacy archive and register its entry point before configuration | OpenSSL configuration |

`STATICLOAD_OPENSSL` identifies the existing Delphi archive configuration.
`OPENSSL_STATIC_LINK_MODEL` also covers startup shared-library imports and must
not be used alone to select the legacy archive symbol. Existing FPC archive
support requires separate verification; no new target support is claimed.

`TaurusTLS_ProviderLegacy.pas` supplies archive opt-in through linking and
registration only. The former default/legacy load/unload handles and automatic
activation have been removed.
Dynamic applications do not need this unit for configuration-based activation.
The core loader must not reference optional legacy, FIPS or Indy integration
units merely to make their code available.

The provider/adapter split is committed in `43b6aa8`. `TaurusTLSIdNTLM` supplies
Indy response callbacks; `TaurusTLSIdFIPS` supplies hash/HMAC and passive FIPS
policy hooks. `TaurusTLS_ProviderFIPS` owns native API validation and passive FIPS
availability; it does not activate a provider or install Indy hooks. The former
`TaurusTLS_NTLM`, `TaurusTLSFIPS` and `TaurusTLS_LegacyProviders` units remain
deprecated source wrappers, outside current runtime package membership.

## 3. Lifecycle and ownership

The implemented lifecycle sequence is:

1. The application selects loader options while inactive.
2. Optional linked legacy registration becomes available before configuration.
3. The loader applies explicit or standard OpenSSL configuration to the default context.
4. OpenSSL activates the providers selected by that configuration.
5. Existing post-configuration consumer callbacks complete; the loader becomes ready.
6. Consumers fetch and release their own algorithm objects.
7. Application shutdown retires active operations before loader cleanup.

Selected minimal mechanism: archive-only unit initialization calls
OSSL_PROVIDER_add_builtin once and checks its result. OpenSSL stores the entry
point without loading configuration or activating the provider. This precedes
application Load/config selection without a new loader phase, registry or API.
Failure raises the existing crypto exception with a specific resource message
during unit initialization; it is not a loader failure-state transition.

Pascal unit initialization runs once; later consumers and static Load/Unload do
not repeat registration. There is no provider finalizer/unregister or owned
provider handle. This assumes the application has not already configured/used
the shared default context or installed a conflicting same-name builtin.
External cross-module registration ownership is not managed by TaurusTLS.

OpenSSL configuration owns its activation references. Consumers must not unload
borrowed or configuration-owned handles. Repeated consumer use does not require
another provider load. OpenSSL reference counting neither leases TaurusTLS dynamic
library handles nor makes unloading safe while crypto objects remain active.
Loader rollback does not promise to reverse native configuration.

## 4. Consumer status and Indy integration

Loader readiness, provider availability, configured FIPS selection and permission
to perform an operation are separate facts.

- `TaurusTLSIdNTLM` installs stable Indy callbacks once at unit initialization.
  It does not use `TaurusTLSIdFIPS` or `TaurusTLS_ProviderLegacy`.
- NTLM availability requires a ready loader, an allowing Indy policy, and usable
  MD4 and DES-ECB fetched under the current default-context properties.
  LM responses require DES-ECB; NT responses require MD4 and DES-ECB.
- Ordinary FIPS/hash integration remains optional in `TaurusTLSIdFIPS`.
  `IdFIPS` still declares Indy's ordinary crypto/NTLM callbacks; using that
  declaration unit does not itself establish native FIPS policy.
- An active FIPS provider alone does not establish FIPS algorithm selection.
  `GetFIPSMode` requires readiness, validated APIs, fips=yes selection and native
  provider availability. `SetFIPSMode` accepts only a no-op matching configured
  policy; it never activates a provider or clears a selected-but-unavailable policy.
- Status checks and operations never activate missing providers or weaken policy.

The NTLM separation and response corrections are committed in `95e7bd2`;
test coverage and fixture-owned config are committed in `0b42e6a`.
The later provider/adapter split (`43b6aa8`) and isolated tests (`90d409c`)
complete the source/test separation; remaining acceptance is listed below.

## 5. Configuration and deployment examples

For an ordinary non-FIPS application using shared libraries:

~~~ini
openssl_conf = application_init
config_diagnostics = 1

[application_init]
providers = application_providers

[application_providers]
default = default_settings
legacy = legacy_settings

[default_settings]
activate = 1

[legacy_settings]
activate = 1
module = "./test-assets/providers/legacy-module"
~~~

Replace the module placeholder with the deployed platform artifact
(`legacy.dll`, `legacy.so` or the matching macOS shared module when applicable),
or omit `module` when standard discovery is intentionally configured.
Archive applications use the same provider sections without `module`; their
explicitly included unit supplies linked registration before the config is read.

This example explicitly keeps default algorithms available for ordinary NTLM.
It is not a FIPS configuration and must not replace a customer's FIPS policy.
FIPS deployment requires its installed module/configuration data and explicit configuration-owned selection policy. Static FIPS and mixed archive/external-provider
deployments remain unsupported by this design.

Empty `Loader.ConfigFile` requests standard OpenSSL configuration; it does not
mean configuration loading is disabled. Omit a provider from the selected config,
or omit its `activate` setting, to avoid explicit activation by that config.
For cross-version examples, omit `activate` rather than using `activate = 0`:
older OpenSSL versions treated the setting's presence as activation.

## 6. Test boundaries and acceptance

Provider activation coverage is committed in `TaurusTLS.UT.Providers` (90d409c),
using `.Common`, `.FIPS` and `.Legacy` units. The ordinary `TaurusTLS.UT` runner
no longer references the Legacy activation unit or the configured FIPS fixture.
Loader/readiness and ordinary Indy adapter tests remain there.

The Legacy test unit imports `TaurusTLS_ProviderLegacy` only under
`STATICLOAD_OPENSSL`. Dynamic tests activate matching modules through temporary
configuration without the production archive unit. Each selected case runs in
a separate invocation via `-scenario:<known-name>`; `-scenario:list` discovers
cases supported by that executable. Missing/unknown selectors fail.

Use `TOsslBaseFixture` for configuration before explicit loading.
`TaurusTLS.UT.Providers.Common.TProviderTestFixture` extends it with temporary
configuration ownership and cleanup, reusing SetupFromCmd, Load, Unload and
Loader. The Legacy fixture also uses the manual base. Neither depends on the
ordinary loader-test fixture unit. Setup failure and destructor fallback restore
test-owned settings/files; unload does not establish a pristine native context.

Win64/OpenSSL 4.1 recorded evidence is 14/14 Legacy/default scenarios and 17/17
FIPS scenarios, each in a new process, for 31/31 with no ignored/leaked/failed/
errored tests. This is dynamic-provider evidence. Win64 provider and Linux64
ordinary full builds succeeded; final ordinary-suite and native Linux/macOS
execution after extraction remain open.

The CMD/PowerShell/Bash launchers provide separate-process execution, deadlines,
logs and one-case XML verification. macOS excludes FIPS. Additional test options
are forwarded as arrays through PowerShell -TestArguments, CMD testarg=VALUE
tokens or Bash --. See [portable run instructions](../../../Tests/TaurusTLS.UT.Providers.md).
Examples must use relative paths or environment variables, never private
workstation paths, usernames or shares.

Remaining gates include fresh archive registration without activation, archive
config activation, absent/unused providers, multiple consumers, failure/retry,
retained contexts and linker-map/package dependency closure. Proving absence of
the archive requires another executable without `TaurusTLS_ProviderLegacy`.
Passing dynamic scenarios or a combined ordinary suite cannot prove this.

Runtime Release, concurrency/range-checking evidence and remaining consumer
compatibility decisions are tracked in the loader/readiness plan. Static FIPS,
mixed deployment, FPC validation and certification are not implied by these runs.

## 7. References

- [OpenSSL provider API](https://docs.openssl.org/3.0/man3/OSSL_PROVIDER/)
- [Provider configuration](https://docs.openssl.org/4.0/man5/config/#provider-configuration)
- [FIPS module guidance](https://docs.openssl.org/4.0/man7/fips_module/)
