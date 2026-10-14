# TaurusTLS OpenSSL Configuration, FIPS and Legacy Support — DDD

Status: Revised implementation specification for developer review.
Revision date: 2026-10-12.
Architecture: [HLD](openssl_providers_HLD.md). Progress: [plan](openssl_providers_plan.md).

## 1. Public API and linking boundaries

Keep the existing dynamic IOpenSSLLoader and its library-path/version/loading/diagnostic members. Remove GetProvidersPath, SetProvidersPath and ProvidersPath, including the proposed EffectiveProvidersPath. Add:

~~~pascal
function GetConfigFile: string;
procedure SetConfigFile(const AValue: string);

property ConfigFile: string read GetConfigFile write SetConfigFile;
~~~

Preserve the existing IOpenSSLLoader GUID {BBB0F670-CC26-42BC-A9E0-33647361941A} when replacing ProvidersPath with ConfigFile. ProvidersPath was never officially released; the developer explicitly directed that no GUID change be made at this point. The historical intermediate A04 GUID E835AF63-93CE-4C79-B3AB-B782F8E06CCD is not used.

GetOpenSSLLoader returns the dynamic singleton; it remains nil in static mode. Static call sites must use the compile-time branch and never dereference it. Remove TOpenSSLStaticLoader and its dependencies.

TaurusTLSLinkDefines.inc must reject simultaneous STATICLOAD_OPENSSL and OPENSSL_USE_SHARED_LIBRARY definitions on every target. STATICLOAD_OPENSSL selects linked archives; OPENSSL_USE_SHARED_LIBRARY selects startup shared-library imports. The Windows compiler-include example enables only OPENSSL_USE_SHARED_LIBRARY. Linked legacy callback imports and registration use IFDEF STATICLOAD_OPENSSL; OPENSSL_STATIC_LINK_MODEL alone also covers shared-library imports and is insufficient for selecting the archive callback.

Do not add public LoadProvider/RegisterBuiltinProvider/FIPS-mode methods to IOpenSSLLoader. Preserve the Indy SetFIPSMode/GetFIPSMode signatures. Their backend remains in TaurusTLSFIPS, with dynamic-only internal FIPS management. IsLegacyProviderLoaded remains the legacy facade's public status function.

Headers remain OpenSSL-only. A03's two property API imports stay valid, including static import declarations; their existence does not imply TaurusTLS supports static FIPS. Add CONF_modules_load_file_ex to TaurusTLSHeaders_conf with exact C ABI, dynamic load/unload/error handling and OpenSSL 3.0 introduction metadata. Legacy configuration routines remain available.

## 2. Configuration lifecycle

ConfigFile defaults to empty. Set it before dynamic library initialization; reject changes once loading has started or succeeded. When the library is unloaded, `GetConfigFile` returns the configured value (`FConfigFile`). Once dynamic initialization succeeds, `GetConfigFile` reflects the effective active configuration (`FEffectiveConfigFile`):
- For an explicit configuration, it returns the normalized full file path.
- When `ConfigFile` is left empty, it returns the discovered default OpenSSL configuration path obtained via `CONF_get1_default_config_file()` and freed with `OPENSSL_free`.
Upon library unload, `FEffectiveConfigFile` is cleared and `GetConfigFile` returns back to reporting `FConfigFile`.

Normalize a nonempty relative filename against the current full path and pass a UTF-8 buffer to OpenSSL. Explicit `ConfigFile` loading uses `CONF_modules_load_file_ex` and requires OpenSSL 3.0 or higher; OpenSSL 1.1.x is excluded from support with this configuration mechanism. Leave OpenSSL's own include/module path semantics unchanged.

Configuration behavior:

| Input | Required behavior |
|---|---|
| Empty ConfigFile | Preserve normal OpenSSL configuration and OPENSSL_CONF behavior; no required new customer calls. Active configuration resolves via `CONF_get1_default_config_file()` once loaded |
| Nonempty ConfigFile | Suppress implicit default configuration loading; explicitly apply the selected file to nil/default context via `CONF_modules_load_file_ex` (requires OpenSSL 3.0+) |
| Invalid/missing explicit file path | Raise ETaurusTLSConfigFilePathError before provider callbacks; engage failure circuit breaker |
| OpenSSL configuration-loading failure | Capture OpenSSL error queue and raise ETaurusTLSConfigFileLoadError with effective filename; engage failure circuit breaker |
| Existing external initialization | Document the default-context ownership precondition; do not promise that prior configuration can be replaced |
| Static model | No loader configuration API, external provider loading or FIPS initialization |

Dynamic sequence:
1. Bind library APIs without invoking providers. Install configured memory callbacks before OpenSSL allocations.
2. Finish header binding; do not publish FIPS-specific capabilities through the loader.
3. If ConfigFile is specified:
   - Validate file system path: reject invalid path characters, directories, or non-existent files via ETaurusTLSConfigFilePathError.
   - Call OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, nil) before any provider operation can trigger implicit configuration.
   - Call CONF_modules_load_file_ex(nil, UTF8Filename, nil, 0). Require a positive result; on <= 0, extract the OpenSSL error and raise ETaurusTLSConfigFileLoadError.
4. If ConfigFile is empty:
   - Preserve the existing normal/default configuration route.
   - Retrieve and cache the active configuration path from CONF_get1_default_config_file().
5. Track callback execution with `FLastLoadActionIdx` and dispatch existing osaLoad callbacks in registration order only after the configuration decision is complete.
6. Publish successful loader readiness (`FLibraryLoaded.Value := True`).

Ensure later TaurusTLS.OPENSSL_init_ssl calls do not load a different configuration after the explicit path; initialization options must be coordinated in the common dynamic entry path, including hash-only/NTLM loads.

### Failure handling, circuit breaker, and callback rollback

If library loading fails at any point (validation error, OpenSSL configuration failure, or an exception inside an `osaLoad` callback):
1. The loader captures the OpenSSL error details before executing teardown.
2. An internal `Unload(False)` executes:
   - Dispatches `osaUnload` in reverse order strictly to callbacks that already executed `osaLoad` (`FLastLoadActionIdx downto 0`). Callbacks that failed or have not yet run are not dispatched `osaUnload`.
   - Executes header unloaders (`GUnLoadList`).
   - Frees loaded library handles (`FLibSSL`, `FLibCrypto`).
   - Clears `FEffectiveConfigFile`.
   - Sets `FFailedToLoad := True` while preserving recorded diagnostics in `FailedToLoad`.
3. The captured exception is raised to the caller.
4. **Circuit Breaker:** While `FFailedToLoad` is active, any subsequent calls to `Load` immediately exit `False` without re-attempting initialization. Applications must explicitly call `Unload` (which resets `FFailedToLoad` and clears diagnostics) before attempting to load again.

Do not promise transactional rollback of OpenSSL configuration modifications that OpenSSL core already applied prior to failure.

### Configuration exceptions

Declare these in TaurusTLSExceptionHandlers.pas:

~~~pascal
ETaurusTLSConfigFilePathError = class(ETaurusTLSAPICryptoError);
ETaurusTLSConfigFileLoadError = class(ETaurusTLSAPICryptoError);
~~~

Use ETaurusTLSAPICryptoError because configuration APIs belong to libcrypto. ETaurusTLSAPISSLError uses SSL_get_error with an SSL object/return code and is inappropriate for this operation.

Validate the normalized explicit path:
- At `SetConfigFile` time, validate path character syntax (reject embedded NUL or invalid characters via `TPath.HasValidPathChars`). Reject changes if already loaded.
- At `Load` time, validate the target: reject directories or non-existent files. Raise ETaurusTLSConfigFilePathError with the effective filename and reason. Construct that exception directly with the existing exception constructor; do not consume an unrelated OpenSSL error queue for a filesystem-validation failure. Its OpenSSL ErrorCode remains zero.

When CONF_modules_load_file_ex returns <=0, call ETaurusTLSConfigFileLoadError.RaiseException with a message naming the operation and effective filename. The inherited class method retrieves the OpenSSL error queue and formats it using existing TaurusTLS conventions. Raise immediately, before cleanup can alter the error queue; `Unload(False)` executes in the exception block while preserving the exception. Error reporting still includes the filename if OpenSSL supplies no error code.

Add resource strings in TaurusTLS_ResourceStrings for both stages:
- `RSOSSLConfigFileAlreadyLoaded`
- `RSOSSLConfigFilePathInvalid`
- `RSOSSLConfigFileIsDirectory`
- `RSOSSLConfigFileNotFound`
- `RSOSSLConfigFileLoadFailed`

Do not collapse these exceptions into false or suppress them at the loader boundary. The FIPS mode backend must preserve configuration exceptions while reporting provider/policy enablement failures through its existing Boolean/diagnostic contract.

Tests must assert the specific exception class and filename for invalid/missing/directory paths and malformed/unreadable/module-failing configuration, with configuration failures isolated in fresh processes.

For an explicit file, do not use IGNORE_ERRORS, IGNORE_RETURN_CODES or IGNORE_MISSING_FILE. Do not add SILENT or rewrite the customer's configuration. If configuration deliberately soft-loads a provider, successful file loading still does not establish FIPS readiness; FIPS validation must catch a missing/unusable provider.

ConfigFile is a full OpenSSL configuration with openssl_conf/provider/algorithm sections and references to installation data where appropriate. A standalone fipsmodule.cnf is not assumed sufficient. Do not run fipsinstall or synthesize integrity values.

CONF_get1_default_config_file is diagnostic/discovery support only. Its caller owns the returned string and frees it with OPENSSL_free. It does not select or change configuration. CONF_modules_load_file_ex is the chosen explicit loader; do not redundantly call both it and OSSL_LIB_CTX_load_config for the same file. [Configuration loading API](https://docs.openssl.org/3.0/man3/CONF_modules_load_file/).
## 3. Discovery, ownership and legacy support

OSSL_PROVIDER_load receives a provider name, not a TaurusTLS-resolved path. Module discovery belongs to OpenSSL configuration or standard search rules, including OPENSSL_MODULES. Remove loader search-path overrides and all calls made for ProvidersPath.

In OpenSSL 4.0 activate is Boolean; in 3.0, presence alone activates. Omit activate when deferring activation in cross-version configuration. A configured module path is also available to explicit loading by provider name. Do not parse provider sections in Delphi or reproduce OpenSSL configuration semantics. [OpenSSL 4.0 provider configuration](https://docs.openssl.org/4.0/man5/config/#provider-configuration), [OpenSSL 3.0 configuration](https://docs.openssl.org/3.0/man5/config/#provider-configuration).

The optional TaurusTLS_LegacyProviders unit remains the request for TaurusTLS legacy functionality. Configuration may already have activated providers; acquire one additional owned reference per requested provider rather than inferring ownership from OSSL_PROVIDER_available.

Dynamic legacy lifecycle:
- Existing osaLoad callback retains default first, then requests legacy by name.
- Missing optional legacy records diagnostics and leaves default available; no FIPS fallback is introduced.
- osaUnload releases owned legacy/default references before header unbinding.

Static legacy lifecycle:
- Import the linked liblegacy.a initialization symbol only under the existing artifact/platform configuration that supplies it; do not require an extra define from existing customers.
- Correct callback ABI: cdecl; var output dispatch pointer and var provider context.
- Check OSSL_PROVIDER_add_builtin registration, then retain default and load legacy by name.
- Unit finalization releases owned handles while linked APIs remain callable. No IOpenSSLLoader or external module is used.

OSSL_PROVIDER_add_builtin alone does not initialize a provider; both static and dynamic lifecycles require load/unload. Make registration/acquisition idempotent and serialize manager access; release only owned references. Preserve the existing automatic static startup behavior.

Normal TLS and hashing use default-provider algorithms. Explicitly loading legacy must retain default rather than suppressing its fallback unintentionally. The legacy unit remains useful outside FIPS and is required by TaurusTLS_NTLM's MD4-based path.

## 4. Dynamic FIPS manager and Indy policy

Use an internal manager in TaurusTLSFIPS and the existing loader lifecycle integration. Inclusion installs hooks but does not itself request FIPS activation.

FIPS API validation is private to TaurusTLSFIPS; IOpenSSLLoader has no FIPSPropertiesAvailable getter/property and exposes no FIPS-specific cache. A private function validates readiness, version and the two property APIs during FIPS manager initialization. It must distinguish actual exports from binding stubs using the existing binding/version diagnostics; inspect those once per initialization, not on each hash/HMAC operation. Cache the result inside the FIPS manager if repeated mode queries need it, reset on osaUnload, and revalidate on a new library initialization. No public header helper or loader resolver test seam remains.

Keep genuine older FIPS_mode/FIPS_mode_set behavior where supported in dynamic builds; modern property APIs are unavailable before 3.0. Internal availability is separate from provider health and enabled policy. Test the private validation at the FIPS-unit boundary rather than mutating a public loader capability.

Modern dynamic GetFIPSMode:
- Return false before library readiness.
- After readiness, use the FIPS module's internal API validation and EVP_default_properties_is_fips_enabled(nil).
- Report actual default-context FIPS policy, independently of owned provider handles.

Modern dynamic SetFIPSMode(true):
1. Ensure successful dynamic Load/configuration and required genuine APIs.
2. Obtain owned fips/base references once. Config-activated providers still need an owned reference for explicit lifetime management.
3. Verify SHA256/HMAC implementations under FIPS selection, provider provenance and permitted positive-test parameters.
4. Apply EVP_default_properties_enable_fips(nil, 1), preserving unrelated default properties.
5. Verify ordinary effective fetches use FIPS and return true only after success.

Failure returns false with diagnostics, restores the previous FIPS property when safely possible and releases only references acquired by that attempt. Never claim success or silently downgrade already-configured FIPS policy. If restoration fails, preserve restrictive state/needed handles and report the failure.

SetFIPSMode(false) retains default before clearing the FIPS property and verifying it. Keep fips/base references until teardown rather than unloading/reloading for every toggle. Provider loading does not certify individual operations or algorithm parameters.

For static mode GetFIPSMode returns false and SetFIPSMode returns false (unsupported for both enable/disable requests). No provider probing, external module load, capability getter or library loader is called. Static hash/HMAC/legacy hooks remain functional.

Active FIPS restrictions apply at prohibited MD2/MD4/MD5 digest and HMAC-MD5 availability AND instance hooks, raising EIdFIPSAlgorithmNotAllowed before Indy can choose native fallback. Guard both NTLM response entry points before low-level DES/hash operations. Preserve hook reinstallation and optional installer behavior. Correct modern HMAC contexts to EVP_MAC consistently; older supported dynamic branches use matching legacy HMAC operations.

Mode changes require application-enforced quiescence and retirement of previously fetched contexts. Internal serialization does not make default-property mutation safe alongside external crypto threads. [OpenSSL default properties](https://docs.openssl.org/4.0/man3/EVP_set_default_properties/).

At osaUnload release FIPS-owned references before unbinding; preserve config-owned references. Coordinate existing managers without introducing a generic public registry. No OPENSSL_cleanup in a reloadable teardown path; live external objects/threads prohibit library unload.

## 5. Tests and review gates

Add tests to existing TaurusTLS.UT, inherit fixtures from TOsslBaseFixture, call inherited SetupFixture first and inherited TearDownFixture last, and register with TDUnitX.RegisterTestFixture. Global initialization/configuration/policy scenarios use isolated processes and configure before inherited setup loads OpenSSL.

Preserve the runner interface:
- Win32 uses the supplied -osp:<folder> -osmp:providers parameters.
- Refactor TOsslLoader's -osmp handling to test-process preparation: resolve a relative value against -osp and set OPENSSL_MODULES before loading. Do not expose a product ProvidersPath replacement.
- Test infrastructure alone changes its environment; customer loader code does not.
- Static tests do not use IOpenSSLLoader; verify legacy readiness/algorithms and unsupported FIPS hooks.
- Compile through Kai in the open group and ask the developer to execute MacOS64 tests.

Acceptance matrix:

| Case | Expected result |
|---|---|
| Internal FIPS availability before readiness/after unload | False |
| Genuine/missing property exports | Private FIPS validation distinguishes exports/stubs; repeated operations do not rescan diagnostics |
| Internal FIPS validation lifecycle | Revalidate at initialization; invalidate on unload |
| Explicit valid configuration/module paths | Default context configured before callbacks; configured provider is usable |
| Invalid explicit config, missing/tampered FIPS data | Initialization/enable fails visibly; no silent downgrade |
| Default configuration | Existing non-FIPS setup continues to work |
| Dynamic legacy opt-in | default/legacy references managed; MD4 works with FIPS off |
| Static legacy | Linked callback registered, provider initialized and algorithms usable |
| Static FIPS request | Unsupported, no external loading |
| Dynamic FIPS + legacy/NTLM | Prohibited operations cannot escape via native fallback or DES |
| Disable/re-enable and teardown | Policy preserved appropriately; no duplicate owned references or premature unbinding |

Record unresolved standard-discovery compatibility failures explicitly rather than claiming the no-customer-change requirement is met. Existing MacOS64 common-name test failure remains a known unrelated baseline issue. No certification claim is part of acceptance.
