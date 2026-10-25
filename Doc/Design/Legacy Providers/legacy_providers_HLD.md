# TaurusTLS Legacy Provider Integration - HLD

Status: Registration-only legacy unit and config-owning tests implemented; cross-platform execution pending.
Revision date: 2026-10-24.
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
| Linked archives, including Delphi macOS | Explicitly include `TaurusTLS_LegacyProviders` to link the legacy archive and register its entry point before configuration | OpenSSL configuration |

`STATICLOAD_OPENSSL` identifies the existing Delphi archive configuration.
`OPENSSL_STATIC_LINK_MODEL` also covers startup shared-library imports and must
not be used alone to select the legacy archive symbol. Existing FPC archive
support requires separate verification; no new target support is claimed.

Retain `TaurusTLS_LegacyProviders.pas` for archive opt-in. Its intended role is
linking and registration only. Remove its default/legacy load/unload handles and
automatic activation in initialization, finalization and loader callbacks.
Dynamic applications do not need this unit for configuration-based activation.
The core loader must not reference optional legacy, FIPS or Indy integration
units merely to make their code available.

## 3. Lifecycle and ownership

The intended sequence is:

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

- `TaurusTLS_NTLM` installs stable Indy callbacks once at unit initialization.
  It does not use `TaurusTLSFIPS` or `TaurusTLS_LegacyProviders`.
- NTLM availability requires a ready loader, an allowing Indy policy, and usable
  MD4 and DES-ECB fetched under the current default-context properties.
  LM responses require DES-ECB; NT responses require MD4 and DES-ECB.
- Ordinary FIPS/hash integration remains optional in `TaurusTLSFIPS`.
  `IdFIPS` still declares Indy's ordinary crypto/NTLM callbacks; using that
  declaration unit does not itself establish native FIPS policy.
- An active FIPS provider alone does not establish FIPS algorithm selection.
  Final `GetFIPSMode`/`SetFIPSMode` semantics remain separately reviewed work.
- Status checks and operations never activate missing providers or weaken policy.

The NTLM separation and response corrections are committed in `95e7bd2`;
test coverage and fixture-owned config are committed in `0b42e6a`.
These commits do not complete the legacy registration refactor or FIPS redesign.

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
module = "/absolute/path/to/matching/legacy-module"
~~~

Replace the module placeholder with the deployed platform artifact
(`legacy.dll`, `legacy.so` or the matching macOS shared module when applicable),
or omit `module` when standard discovery is intentionally configured.
Archive applications use the same provider sections without `module`; their
explicitly included unit supplies linked registration before the config is read.

This example explicitly keeps default algorithms available for ordinary NTLM.
It is not a FIPS configuration and must not replace a customer's FIPS policy.
FIPS deployment requires its installed module/configuration data and separately
reviewed selection policy. Static FIPS and mixed archive/external-provider
deployments remain unsupported by this design.

Empty `Loader.ConfigFile` requests standard OpenSSL configuration; it does not
mean configuration loading is disabled. Omit a provider from the selected config,
or omit its `activate` setting, to avoid explicit activation by that config.
For cross-version examples, omit `activate` rather than using `activate = 0`:
older OpenSSL versions treated the setting's presence as activation.

## 6. Test boundaries and acceptance

UT.LegacyProviders now references the production legacy unit only under
STATICLOAD_OPENSSL. Shared builds keep provider-specific coverage without the
wrapper; archive builds retain explicit registration. Both positive provider
fixtures own their temporary default/legacy config before loading. A runtime-shared
negative fixture lists legacy without activate and checks legacy/MD4/DES absence.
Archive absence scenarios still require separate fresh-process execution.

Audit runtime-package membership and transitive dependencies as well as uses
clauses. A combined-runner pass does not prove optional dependency closure.

Use `TOsslBaseFixture` when setup must configure before loading; use
`TOsslAutoloadFixture` for automatic lifecycle. The NTLM crypto fixture already
creates a unique temporary non-FIPS default/legacy config and restores settings
and files on cleanup. That fixture does not prove a pristine default context.

Pending acceptance includes fresh-process tests for archive registration with no
activation, config-selected activation, absent/unused providers, multiple consumers,
failure/retry, dependency isolation and retained static context behavior.
Validate Windows32/64, Linux64 and macOS; record actual categories and baseline
failures separately. Existing platform results precede this provider refactor.

## 7. References

- [OpenSSL provider API](https://docs.openssl.org/3.0/man3/OSSL_PROVIDER/)
- [Provider configuration](https://docs.openssl.org/4.0/man5/config/#provider-configuration)
- [FIPS module guidance](https://docs.openssl.org/4.0/man7/fips_module/)
