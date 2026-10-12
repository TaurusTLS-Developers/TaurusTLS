# TaurusTLS OpenSSL Loader and Provider Support — HLD

Status: Proposed design, prepared before source refactoring.
Date: 2026-10-11.
Companion documents: [DDD](openssl_providers_DDD.md), [implementation plan](openssl_providers_plan.md).

## 1. Purpose and design baseline

Provide one provider lifecycle for OpenSSL 3.x/4.x, supporting FIPS selection and optional legacy algorithms across TaurusTLS linking models. Preserve Indy's procedural hook signatures and existing pre-3.0 behavior where the library actually supports it.

This pair supersedes the legacy-only HLD/DDD for future implementation. The original documents remain historical references and are not modified. Repository observations include authoritative IDE buffers, including unsaved TaurusTLSFIPS changes.

Chosen defaults: use OpenSSL's default library context; reject prohibited Indy operations under FIPS; retain legacy as opt-in; support external modules and explicit built-in registration. These are engineering defaults recorded for review, not assertions that the user approved every policy choice.

A successful FIPS switch means the provider can supply required algorithms and the default fetch policy requires fips=yes. It does not establish certification of TaurusTLS, the application, or every operation. Deployment must satisfy the chosen module's security policy, permitted parameters and installation requirements.

## 2. Current problems and scope

- FIPS hooks return disabled in static mode; modern compatibility wrappers load providers without enabling FIPS fetch policy and confuse availability with mode.
- Provider handles are split between crypto compatibility wrappers and the legacy unit. Failure rollback and synchronization are incomplete.
- IOpenSSLLoader already exposes ProvidersPath; the old HLD's ProviderSearchPath is obsolete. Current code does not implement the documented relative-path resolution.
- OPENSSL_STATIC_LINK_MODEL includes startup-linked shared libraries as well as archive builds; it cannot determine provider deployment.
- Legacy registration has an incorrect provider-context output parameter and an overly broad compile guard for a narrowly declared archive constant.
- Indy protocol checks are selective. Hash/HMAC classes can choose native Pascal fallback when interface availability is false. Low-level DES consumers do not inherit EVP fetch policy.
- The inspected HMAC hooks mix HMAC_CTX creation with EVP_MAC_CTX operations; this must be corrected in the integration work.

Include loader/provider ownership, configuration, FIPS hooks, legacy facade and necessary NTLM guards. Exclude unrelated socket/ECH refactoring, alternate experimental LoaderNG migration, new cryptographic algorithms and certificate acquisition.

## 3. Architecture and linking matrix

| Component | Responsibility |
|---|---|
| OpenSSL header units | Correct ABI, imports, version-aware binding and capability reporting; no provider ownership |
| TaurusTLSLoader | Library binding, serialized lifecycle, configuration and public provider extension |
| New TaurusTLS_Providers unit | Shared internal manager for provider registrations, owned handles, FIPS policy and diagnostics |
| TaurusTLSFIPS | Install Indy hooks and enforce policy at hook boundaries; route mode calls to loader service |
| TaurusTLS_LegacyProviders | Compatibility facade requesting default + legacy support; preserve IsLegacyProviderLoaded |
| TaurusTLS_NTLM | Preserve hook registration; reject prohibited operations before low-level DES execution |

Extend IOpenSSLLoader directly under the planned API version bump, updating its GUID for the changed contract and documenting changed or deprecated members. ProvidersPath has not shipped and has no released compatibility obligation. The loader singleton implements the revised interface in every linking model. Static Load initializes managed state; it does not load already linked libraries. Static Unload releases owned provider references without unloading startup-linked libraries.

| Build model | OpenSSL API availability | Provider deployment |
|---|---|---|
| Runtime binding | After explicit library load and symbol binding | External modules by default; built-ins permitted through explicit registration |
| Startup-linked shared libraries | At startup | External modules by default; do not require a legacy archive |
| Actual archive build | At startup | External modules where the build supports them, or supplied built-in entry points |

Do not invent a static FIPS archive or hardcode its private entry point. Built-in FIPS support is generic registration capability; end-to-end validation requires an actual supported artifact and applicable policy. Link directives remain platform/compiler specific.

## 4. Initialization, FIPS and legacy behavior

Initialization order: custom allocator setup if configured; API readiness; provider path and OpenSSL configuration; built-in registration; provider activation; lifecycle callbacks; readiness publication. No provider API may allocate before custom allocator installation. Retain current startup availability for legacy facade initialization in static builds through this same initialization path.

Normal operation retains default alongside requested legacy. Missing optional legacy produces diagnostics and leaves modern crypto usable. An explicit FIPS request loads fips and base, probes required implementations and enables the FIPS property. Failure returns false without claiming successful enablement or silently substituting default-provider algorithms.

Providers may coexist. Loading legacy does not permit its algorithms during FIPS operation. MD2/MD4/MD5 hash and HMAC-MD5 hooks reject through Indy's EIdFIPSAlgorithmNotAllowed; this includes availability hooks so rejection cannot select native fallback. NTLM entry points reject before DES or hashing. Other availability hooks distinguish ordinary absence from policy exclusion.

GetFIPSMode follows actual default-context policy; provider-loaded status is separate. Existing contexts are not retroactively converted. SetFIPSMode is initialization/quiescent-phase control: the application must stop crypto workers and retire existing contexts before switching. Internal locks serialize manager operations but cannot make external OpenSSL use safe during a policy change.

Disabling clears only the FIPS property, preserving unrelated default properties, and retains manager-owned provider handles until teardown. Restore ordinary default-provider availability before reporting successful disablement. Configuration-enabled FIPS is respected at initial load; there is no automatic downgrade.

Shutdown runs consumer callbacks first, releases owned provider references while APIs remain callable, then unbinds and unloads dynamic libraries. Release only references acquired by TaurusTLS. Reload is permitted only with no outstanding crypto objects, threads or external references; do not call irreversible OPENSSL_cleanup as a reload step.

## 5. Compatibility, validation and sources

Retain existing Indy hook signatures and legacy opt-in semantics. Extend IOpenSSLLoader directly under the planned API version bump; document changed or deprecated members and rebuild affected packages. ProvidersPath is unreleased and may be revised as part of this design. Preserve real pre-3.0 FIPS routines; unsupported versions report false without invoking modern provider stubs.

Applications that do not use FIPS must require no application source, configuration, deployment or startup-sequence changes. Normal loading and existing legacy activation remain automatic. New FIPS configuration, module deployment and quiescent policy-switch requirements apply only to applications opting into FIPS (including through OpenSSL configuration). Existing non-FIPS archive settings must keep working without a new application-defined symbol.

Acceptance covers static API readiness, OpenSSL 3.0-compatible provider APIs, 3.5 and 4.x deployments, legacy coexistence, FIPS algorithm provenance, native fallback rejection, Unicode paths, missing configuration/module, rollback and shutdown ordering. Test old-library behavior separately. Run global-policy scenarios in isolated processes.

Primary references:
- [OpenSSL FIPS module guide](https://docs.openssl.org/4.0/man7/fips_module/): configuration, provider coexistence and TLS context behavior.
- [OpenSSL default properties](https://docs.openssl.org/4.0/man3/EVP_set_default_properties/): FIPS property manipulation and initialization-phase thread restrictions.
- [OpenSSL provider API](https://docs.openssl.org/3.0/man3/OSSL_PROVIDER/): provider registration, load, reference release and search paths.
- [Legacy provider](https://docs.openssl.org/3.0/man7/OSSL_PROVIDER-legacy/): available legacy implementations; availability varies by build.
