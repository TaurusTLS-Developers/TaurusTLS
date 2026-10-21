# TaurusTLS OpenSSL Configuration, FIPS and Legacy Support — HLD

Status: Revised design for developer review; supersedes the previous combined design.
Revision date: 2026-10-14.
Details: [DDD](openssl_providers_DDD.md). Work tracking: [plan](openssl_providers_plan.md).

## 1. Purpose and constraints

Support modern OpenSSL FIPS mode through the default library context in TaurusTLS dynamic builds. Preserve non-FIPS hashing, HMAC, TLS and optional NTLM/legacy support. Keep implementation small enough for the TaurusTLS team to maintain.

The product supports two deployment models:

| Model | Library/provider deployment | Supported TaurusTLS behavior |
|---|---|---|
| Pure dynamic | Explicitly loaded libcrypto/libssl; external provider modules discovered by OpenSSL | Normal crypto, optional legacy, FIPS when configured and validated. Managed via `TOpenSSLDynamicLoader` |
| Pure static | Library code and required provider code linked into the application | Normal crypto, configuration management, and optional linked legacy; FIPS unsupported. Managed via `TOpenSSLStaticLoader` |

There is no supported static-library/external-provider combination. OPENSSL_STATIC_LINK_MODEL remains the existing compiler discriminator; it does not introduce permission for mixed provider deployment. Startup-linked shared-library configurations, where retained by existing platform settings, must follow the established platform arrangement and must not be presented as a new supported mixed-deployment model. STATICLOAD_OPENSSL (linked archives) and OPENSSL_USE_SHARED_LIBRARY (startup shared-library imports) are mutually exclusive on all targets; TaurusTLSLinkDefines.inc rejects conflicting definitions.

Non-FIPS applications require no new initialization calls, configuration file or FIPS assets. Preserve their existing source/setup/build behavior. ProvidersPath is unreleased and removed in favor of optional ConfigFile. Preserve the existing IOpenSSLLoader GUID {BBB0F670-CC26-42BC-A9E0-33647361941A} for this change, as directed by the developer. The usual package rebuild requirement remains release engineering work.

## 2. Architecture

| Component | Responsibility |
|---|---|
| TaurusTLSHeaders_* | OpenSSL API declarations/imports, binding and compatibility stubs; no TaurusTLS capability or provider-management helpers |
| TaurusTLSLoader | Unified loader contract (`IOpenSSLLoader`) across both linking models; optional configuration application; thread-safe callback registration; Template Method lifecycle orchestration |
| TaurusTLSFIPS / internal FIPS manager | Internal FIPS API validation, dynamic-only provider validation, owned fips/base references, policy and Indy hook enforcement |
| TaurusTLS_LegacyProviders | Optional default/legacy lifecycle in both models; registers action callback via `Register_SSLLoaderAction` executing after configuration |
| TaurusTLS_NTLM | Ordinary Indy NTLM hooks, available without FIPS; reject prohibited operations when dynamic FIPS is active |
| Existing TaurusTLS TLS initialization | Use the same default context and avoid duplicate/conflicting configuration initialization |

`IOpenSSLLoader` provides a unified contract across both dynamic and static linking models. `TOpenSSLBaseLoader` encapsulates common state, instance locking (`FLoaderLock`), configuration path validation, OpenSSL error extraction, and action callback dispatching/rollback.

* **Dynamic Linking (`TOpenSSLDynamicLoader`):** Implements dynamic library discovery (`FindLibrary`), symbol resolution (`GLibCryptoLoadList`/`GLibSSLLoadList`), version verification, and handle cleanup (`GUnLoadList`, `FreeLibrary`).
* **Static Linking (`TOpenSSLStaticLoader`):** Operates on statically linked symbols. Dynamic-only properties (`OpenSSLPath`, `SSLLibVersions`, `FailedToLoad`) provide safe/inert defaults (`''` and empty list). Handles configuration application and action callbacks without dynamic library loading or symbol unbinding.

The loader applies configuration before provider callbacks. OpenSSL performs provider discovery and initialization. TaurusTLSFIPS and TaurusTLS_LegacyProviders manage their own provider references and validation through these APIs. No additional public TaurusTLS provider registry is required.

## 3. Configuration and discovery

Add optional ConfigFile to IOpenSSLLoader, available in both linking models:
- Empty preserves normal OpenSSL configuration/environment behavior.
- A specified file is validated and loaded into the default context before provider callbacks or cryptographic operations.
- Invalid/missing explicit paths raise `ETaurusTLSConfigFilePathError`; OpenSSL loading failures raise `ETaurusTLSConfigFileLoadError`. Both derive from `ETaurusTLSAPICryptoError`; load failures preserve the OpenSSL error details and filename.

Use `CONF_modules_load_file_ex(nil, filename, nil, 0)` for explicit configuration across both models. It selects the default context and allows module errors to remain visible. Add its missing OpenSSL import. `CONF_get1_default_config_file` is used to reflect the active default configuration path when `ConfigFile` is empty; free its returned allocation with `OPENSSL_free`. [OpenSSL configuration APIs](https://docs.openssl.org/3.0/man3/CONF_modules_load_file/).

Remove ProvidersPath, its accessors and loader calls to `OSSL_PROVIDER_set_default_search_path`. Do not substitute a hidden TaurusTLS search directory or mutate customer process environment. OpenSSL resolves providers through its standard module discovery or the provider section's module setting. Configuration controls module paths, activation and provider parameters. [OpenSSL 4.0 provider configuration](https://docs.openssl.org/4.0/man5/config/#provider-configuration).

A customer's FIPS configuration references installed FIPS module data; TaurusTLS neither generates installation integrity data nor replaces that configuration with application defaults. Loading configuration can activate providers and policy; therefore it must precede legacy callbacks and any crypto use.

Keep application configuration selection initialization-only. This design does not offer live replacement of the default context's configuration or claim transactional rollback of OpenSSL configuration changes.

## 4. Provider and policy behavior

API availability, provider initialization and FIPS-enabled policy are distinct:

- The FIPS unit privately validates required API availability during manager initialization and may cache that result internally. No FIPS capability getter/property is exposed by the loader; hash/HMAC operations must not repeatedly scan binding diagnostics.
- The legacy manager retains default and legacy references. It registers its `osaLoad`/`osaUnload` hook via `Register_SSLLoaderAction` in both models. In static mode it registers the linked legacy callback (`ossl_legacy_provider_init`) via `OSSL_PROVIDER_add_builtin` before `OSSL_PROVIDER_load`. Both models call `OSSL_PROVIDER_unload` for owned references.
- The dynamic FIPS manager acquires fips/base references and validates required implementations before reporting successful enablement. Provider activation alone does not mean FIPS policy is enabled.
- Static `GetFIPSMode` reports false; static `SetFIPSMode` reports unsupported. Legacy, hash and HMAC hooks still operate normally.

Indy's IdFIPS is a hook container for ordinary crypto as well as FIPS controls. NTLM consumers call its hooks outside FIPS. Returning false from prohibited algorithm availability hooks can select native Indy fallback, so active FIPS policy must cause explicit rejection at the relevant availability and instance hooks, and before NTLM low-level DES calls.

Policy switching applies to future algorithm selection. Require application-controlled quiescence and retirement of existing crypto contexts before switching; loader locks do not protect third-party OpenSSL users. Retain provider references across mode toggles and release them during safe shutdown. [OpenSSL property API](https://docs.openssl.org/4.0/man3/EVP_set_default_properties/).

## 5. Scope and acceptance

Include optional explicit configuration, internal FIPS API validation, FIPS initialization/policy, unified static and dynamic loaders via Template Method pattern, legacy lifecycle fixes, NTLM guards, HMAC context consistency and regression tests. Exclude static FIPS, mixed deployments, a public generic provider API, unrelated socket/ECH work and certification claims.

Keep normal non-FIPS deployment unchanged. Validate standard/configured provider discovery against the existing deployments before removing path overrides; a failed existing deployment is a compatibility blocker to resolve and report, not permission to silently impose a new customer setup requirement.

Acceptance:
- Unchanged non-FIPS application behavior.
- Dynamic and static configuration paths, path validation, and strict typed failures.
- Non-nil `IOpenSSLLoader` across both dynamic and static targets (`TOpenSSLStaticLoader` on macOS/static targets).
- Thread-safe callback registration with on-demand lock initialization.
- Actual FIPS algorithm provenance; prohibited native fallback rejection.
- Static legacy functionality without FIPS; correct reference cleanup.
- Win32 IDE builds/tests and developer-run macOS tests pass green. Successful integration does not establish application/module certification or approved parameters for every operation.

The test harness continues accepting the existing -osp/-osmp parameters. Its environment preparation is test infrastructure, separate from loader APIs and customer requirements.
