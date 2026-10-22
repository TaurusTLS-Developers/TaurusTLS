# TaurusTLS OpenSSL Configuration, FIPS and Legacy Support — HLD

Status: Revised design for developer review. Sections 2A and the associated lifecycle changes are proposed, not implemented.
Revision date: 2026-10-22.
Details: [DDD](openssl_providers_DDD.md).

## 1. Purpose and constraints

Support modern OpenSSL FIPS mode through the default library context in TaurusTLS dynamic builds. Preserve non-FIPS hashing, HMAC, TLS and optional NTLM/legacy support. Keep implementation small enough for the TaurusTLS team to maintain.

The product supports two deployment models:

| Model | Library/provider deployment | Supported TaurusTLS behavior |
|---|---|---|
| Pure dynamic | Explicitly loaded libcrypto/libssl; external provider modules discovered by OpenSSL | Normal crypto, optional legacy, FIPS when configured and validated. Managed via `TOpenSSLDynamicLoader` |
| Pure static | Library code and required provider code linked into the application | Normal crypto, configuration management, and optional linked legacy; FIPS unsupported. Managed via `TOpenSSLStaticLoader` |

There is no supported static-library/external-provider combination. OPENSSL_STATIC_LINK_MODEL remains the existing compiler discriminator; it does not introduce permission for mixed provider deployment. Startup-linked shared-library configurations, where retained by existing platform settings, must follow the established platform arrangement and must not be presented as a new supported mixed-deployment model. STATICLOAD_OPENSSL (linked archives) and OPENSSL_USE_SHARED_LIBRARY (startup shared-library imports) are mutually exclusive on all targets; TaurusTLSLinkDefines.inc rejects conflicting definitions.

Applications explicitly initialize through `IOpenSSLLoader.Load`; a future `TTaurusTLSLoader` component is deferred. The compatibility `LoadOpenSSLLibrary` routine is proposed to forward to the same operation. Queries and NTLM readiness hooks must not initialize OpenSSL. Non-FIPS applications need no mandatory configuration file or FIPS assets. Removing implicit initialization requires documented migration and review.

Support OpenSSL 3.x/4.x in the refactored path; do not carry OpenSSL 0.9–1.1.1 branches into it. ProvidersPath is unreleased and removed in favor of optional ConfigFile. Preserve the existing IOpenSSLLoader GUID {BBB0F670-CC26-42BC-A9E0-33647361941A}, as directed by the developer for interface extensions. Rebuild affected packages and consumers together; preserving the GUID does not preserve an old compiled interface layout.

## 2. Architecture

| Component | Responsibility |
|---|---|
| TaurusTLSHeaders_* | OpenSSL API declarations/imports, binding and compatibility stubs; no TaurusTLS capability or provider-management helpers |
| TaurusTLSLoader | Unified lifecycle/readiness in both models; modern OpenSSL initialization, configuration and runtime metadata; callback registration and rollback |
| TaurusTLSFIPS / internal FIPS manager | Readiness-aware Indy hooks and configured-policy reporting; final FIPS reporting/setter behavior remains deferred |
| TaurusTLS_LegacyProviders | Linked-provider registration where required and configured legacy readiness; activation belongs to openssl.cnf |
| TaurusTLS_NTLM | Ordinary Indy NTLM hooks, available without FIPS; reject prohibited operations when dynamic FIPS is active |
| Private TaurusTLS runtime class (proposed) | Own TaurusTLS TLS callback locks; register initialization/cleanup actions with the loader; no independent public readiness flag |

`IOpenSSLLoader` provides a unified contract across both dynamic and static linking models. `TOpenSSLBaseLoader` encapsulates common state, instance locking (`FLoaderLock`), configuration path validation, OpenSSL error extraction, and action callback dispatching/rollback.

* **Dynamic Linking (`TOpenSSLDynamicLoader`):** Implements dynamic library discovery (`FindLibrary`), symbol resolution (`GLibCryptoLoadList`/`GLibSSLLoadList`), version verification, and handle cleanup (`GUnLoadList`, `FreeLibrary`).
* **Static Linking (`TOpenSSLStaticLoader`):** Operates on statically linked symbols. Dynamic-only properties (`OpenSSLPath`, `SSLLibVersions`, `FailedToLoad`) provide safe/inert defaults (`''` and empty list). Handles configuration application and action callbacks without dynamic library loading or symbol unbinding.

Repeated `Load` calls when ready return `True` without repeating initialization or acquiring references. One explicit `Unload` performs cleanup; further `Unload` calls are safe. The application controls shutdown and must finish active crypto operations first.

The loader applies configuration before post-binding/post-configuration actions. OpenSSL performs provider discovery and activation from openssl.cnf. TaurusTLS hooks must not silently activate providers or weaken configured policy. Linked builtin registration, when needed, must precede configuration; it cannot be performed by the existing post-configuration action alone. Its mechanism requires separate design approval. No public provider activation API is introduced.

The implemented public `State` reports `lsNotLoaded`, `lsLoadedReady`, or `lsLoadedFailed`. Internal loading/unloading states map to `lsNotLoaded`. `State`/`IsLoaded` are atomic snapshots and do not acquire the lifecycle lock. Recursive public Load/Unload calls during lifecycle callbacks raise `ETaurusTLSLoaderError`; internal rollback is a separate operation.

## 2A. Unified runtime lifecycle and metadata (draft)

This refactoring unifies the API and gives `IOpenSSLLoader` sole responsibility
for coordinating the OpenSSL lifecycle. It owns shared-library loading and
unloading in the dynamic model and coordinates OpenSSL initialization and
TaurusTLS runtime setup in both dynamic and static models. Configuration,
runtime resources and readiness are therefore managed through one Load/Unload
contract.

Extend `IOpenSSLLoader` with read-only Version, ConfigDirectory, ModulesDirectory
and EnginesDirectory properties, with matching Get* accessors. Keep a single
Load/Unload implementation and one readiness state.

| Property | Source and meaning |
|---|---|
| Version | `OpenSSL_version(OPENSSL_VERSION_CONST)` |
| ConfigDirectory | Directory containing the effective `ConfigFile`, resolved at load time |
| ModulesDirectory | `OPENSSL_info(OPENSSL_INFO_MODULES_DIR)`: compiled default provider module directory |
| EnginesDirectory | OpenSSL 3.x: supported `OPENSSL_info(OPENSSL_INFO_ENGINES_DIR)` query; OpenSSL 4.x: empty string |

ConfigDirectory describes the selected/discovered configuration filename; it is
not the compiled OPENSSLDIR and does not prove the file was read or exists.
A relative discovered filename is resolved at load time. An empty filename
produces an empty directory. Module/engine directories do not enumerate configured
module paths or certify that a provider/engine is available. No SSLeay fallback or
version-string parsing is retained. Engine-directory support was removed in OpenSSL 4.0;
preserve the compatibility routine with an empty result rather than returning a
disabled-engine marker. [Modern metadata APIs](https://docs.openssl.org/4.0/man3/OpenSSL_version/).

All metadata properties are passive. Not-ready or unavailable values are empty.
The proposed implementation captures copied Pascal strings before successful
publication, clears them on cleanup, and serializes access with the lifecycle
lock. Only State/IsLoaded carry the nonblocking-query guarantee.

Preserve the six global routines as thin forwarding compatibility wrappers,
inline where supported:

| Existing routine | Proposed target |
|---|---|
| LoadOpenSSLLibrary | `GetOpenSSLLoader.Load` |
| UnLoadOpenSSLLibrary | `GetOpenSSLLoader.Unload` |
| OpenSSLVersion | `GetOpenSSLLoader.Version` |
| OpenSSLDir | `GetOpenSSLLoader.ConfigDirectory` |
| OpenSSLModulesDir | `GetOpenSSLLoader.ModulesDirectory` |
| OpenSSLEnginesDir | `GetOpenSSLLoader.EnginesDirectory` |

Review the wrapper contract before implementation: Load remains an explicit
lifecycle entry point; metadata queries never load. OpenSSLDir changes from a
compiled default-directory query to the directory of ConfigFile. Review internal
constructor/other implicit-load sites against explicit application initialization.

Move general OpenSSL initialization into TaurusTLSLoader for both linking models.
A private class in TaurusTLS owns the TLS callback locks and participates through
Register_SSLLoaderAction. Use class vars/class methods for these resources, with
a callback method compatible with the existing method-pointer type. Remove
SSLIsLoaded as a competing readiness source. A failed action cleans its own
partially allocated resources; completed actions unwind in reverse order before
unbinding. Readiness includes successful registered runtime actions, not socket
creation or a guarantee that unloading is safe with live objects.

Remove obsolete OpenSSL locking/thread-ID callbacks and obsolete error-string
setup from this path, while preserving TaurusTLS's own callback locks. Do not
replace old global state with a second lifecycle in the private class.

Before code changes, review initialization flags/order for explicit versus default
configuration, optional custom allocators, pre-configuration builtin registration,
external initialization and static reload limitations. Custom memory functions
must be installed before OpenSSL allocations; a post-configuration callback is too
late. Audit callback sizes and C ABI. No OPENSSL_cleanup in reloadable teardown.
[Memory function ordering](https://docs.openssl.org/3.0/man3/OPENSSL_malloc/).

## 3. Configuration and discovery

Add optional ConfigFile to IOpenSSLLoader, available in both linking models:
- Empty preserves normal OpenSSL configuration/environment behavior.
- A specified file is validated and loaded into the default context before provider callbacks or cryptographic operations.
- Invalid/missing explicit paths raise `ETaurusTLSConfigFilePathError`; OpenSSL loading failures raise `ETaurusTLSConfigFileLoadError`. Both derive from `ETaurusTLSAPICryptoError`; load failures preserve the OpenSSL error details and filename.

Use `CONF_modules_load_file_ex(nil, filename, nil, 0)` for explicit configuration across both models. It selects the default context and allows module errors to remain visible. `CONF_get1_default_config_file` discovers the default configuration filename when `ConfigFile` is empty; free its returned allocation with `OPENSSL_free`. Discovery alone neither loads that file nor proves it was applied. The current loader only discovers it; actual default initialization must be defined before configuration completion can be reported. [OpenSSL configuration APIs](https://docs.openssl.org/3.0/man3/CONF_modules_load_file/).

Remove ProvidersPath, its accessors and loader calls to `OSSL_PROVIDER_set_default_search_path`. Do not substitute a hidden TaurusTLS search directory or mutate customer process environment. OpenSSL resolves providers through its standard module discovery or the provider section's module setting. Configuration controls module paths, activation and provider parameters. [OpenSSL 4.0 provider configuration](https://docs.openssl.org/4.0/man5/config/#provider-configuration).

A customer's FIPS configuration references installed FIPS module data; TaurusTLS neither generates installation integrity data nor replaces that configuration with application defaults. Loading configuration can activate providers and policy; therefore it must precede legacy callbacks and any crypto use.

Keep application configuration selection initialization-only. This design does not offer live replacement of the default context's configuration or claim transactional rollback of OpenSSL configuration changes.

## 4. Provider and policy behavior

Provider activation is controlled only by openssl.cnf. Including a TaurusTLS unit
or querying readiness must not activate default, legacy, fips or base providers.
A later programmatic provider API is a separate decision. Static builtin
registration makes linked code discoverable; configuration still controls
activation. Do not register it for the first time after configuration has run.

Loader readiness, provider availability, enabled FIPS policy and permission to
perform a particular operation are distinct. NTLM requires configured legacy
algorithms; loading legacy does not override FIPS selection rules. Hook readiness
must be checked before querying or using OpenSSL.

Indy's IdFIPS also supplies ordinary crypto hooks. The remaining design work must
review algorithm-specific availability, NTLM execution failure contracts and
possible native fallback. Preserve the agreed status-only LoadNTLMLibrary
contract. FIPS GetFIPSMode/SetFIPSMode reporting and setter semantics remain
deferred; the previous programmatic activation/toggling design is superseded,
not an instruction to implement it.

Static FIPS and mixed provider deployment remain outside the supported scope.
Application-controlled shutdown is required for both models; a readiness query
does not protect a subsequent crypto call against an unsafe concurrent unload.
Do not claim FIPS certification from provider activation or loader success.

## 5. Scope and acceptance

This design covers loader readiness/configuration contracts and the proposed runtime/metadata integration, including consumer/NTLM readiness. Broader hook hardening, HMAC context consistency and FIPS reporting/policy require separate design review. Exclude static FIPS, mixed deployments, programmatic provider activation, the new component, unrelated socket/ECH work and certification claims.

Preserve supported configuration/module discovery and document intentional compatibility changes, including explicit initialization and OpenSSLDir semantics. Test those changes in controlled environments without requiring machine-wide configuration.

Acceptance:
- Explicit application initialization with one shared lifecycle across both linking models.
- Passive modern metadata and compatibility forwarding; no competing TLS ready flag.
- Dynamic and static configuration paths, path validation, and strict typed failures.
- Non-nil `IOpenSSLLoader` across both dynamic and static targets (`TOpenSSLStaticLoader` on macOS/static targets).
- Thread-safe callback registration with on-demand lock initialization.
- Configuration-only provider activation; static registration ordering resolved before implementation.
- Deferred FIPS/NTLM policy questions tracked without claiming they are resolved.
- Runtime and test builds/runs on Win32, Win64, Linux64 and OSX64; track the known unrelated InputRanges baseline separately. Successful integration does not establish application/module certification.

The test harness continues accepting the existing -osp/-osmp parameters. Its environment preparation is test infrastructure, separate from loader APIs and customer requirements.
