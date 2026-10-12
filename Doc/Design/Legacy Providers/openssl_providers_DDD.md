# TaurusTLS OpenSSL Loader and Provider Support — DDD

Status: Proposed implementation contract.
Date: 2026-10-11.
Architecture: [HLD](openssl_providers_HLD.md). Execution: [plan](openssl_providers_plan.md).

## 1. Public contracts and unit dependencies

Extend IOpenSSLLoader directly under the planned API version bump, using a new interface GUID for the changed contract. GetOpenSSLLoader returns the revised singleton interface in both linking models; do not introduce IOpenSSLProviderLoader or GetOpenSSLProviderLoader. Existing members may be revised or deprecated with documented migration guidance. ProvidersPath has not shipped and has no released compatibility obligation; retain its proposed name and resolution contract for this design.

Add the following methods and properties to IOpenSSLLoader:

~~~pascal
function GetConfigFile: string;
procedure SetConfigFile(const AValue: string);
function GetEffectiveProvidersPath: string;
function GetProvidersSupported: Boolean;
function GetFIPSPropertiesAvailable: Boolean;
function RegisterBuiltinProvider(const AName: string;
  AInit: OSSL_provider_init_fn): Boolean;
function LoadProvider(const AName: string): Boolean;
function IsProviderLoaded(const AName: string): Boolean;
function SetFIPSMode(const AEnabled: Boolean): Boolean;
function GetFIPSMode: Boolean;
function GetProviderDiagnostics: string;

property ConfigFile: string read GetConfigFile write SetConfigFile;
property EffectiveProvidersPath: string read GetEffectiveProvidersPath;
property ProvidersSupported: Boolean read GetProvidersSupported;
property FIPSPropertiesAvailable: Boolean read GetFIPSPropertiesAvailable;
property ProviderDiagnostics: string read GetProviderDiagnostics;
~~~

No public raw provider handles or independent UnloadProvider API: managed references live until loader teardown. Boolean controls report expected OpenSSL failures through false plus diagnostics; argument misuse raises ETaurusTLSError. Existing Load failure/exception behavior remains documented, with complete rollback in both cases.

Name arguments must be nonempty ASCII provider identifiers (letters, digits, underscore, hyphen, period); reject module paths and embedded NUL. Deploy modules through ProvidersPath/configuration. Built-in callback must be non-nil. Repeated registration of the same name/callback succeeds without another OpenSSL registration; a different callback for the same name is rejected. Registration is permitted only before manager initialization; late registration raises ETaurusTLSError. Record built-ins by name and callback until initialization.

OSSL_provider_init_fn uses cdecl and output parameters by reference:

~~~pascal
function(const AHandle: POSSL_CORE_HANDLE;
  const AIn: POSSL_DISPATCH; var AOut: POSSL_DISPATCH;
  var AProviderContext: Pointer): TIdC_INT; cdecl;
~~~

Use the existing header type; correct local imports to match it. Built-in declarations compile only when the corresponding artifact is explicitly selected. No blanket archive import under OPENSSL_STATIC_LINK_MODEL.

TaurusTLS_Providers exposes its manager to loader implementation only. Place provider callback types in a dependency-safe header/core type unit if necessary; avoid interface-level cycles. Headers may reference loader registration in implementation. Crypto compatibility wrappers call the same service and never own handles.

## 2. State, configuration and locking

Internal state: Uninitialized, Initializing, Ready, Unloading. Track full OpenSSL version, provider capabilities, owned references indexed by provider name, registrations, last diagnostics, legacy request and the initial/current FIPS property. IsLoaded means complete library/manager readiness, not a nonzero libcrypto handle. In static mode it becomes true after managed Load completes.

FIPSPropertiesAvailable is a cached loader API capability, not provider health or FIPS mode. Its getter reads a Boolean under the lifecycle lock, with no list search, symbol lookup or OpenSSL call. Dynamic capture uses genuine libcrypto exports, not Assigned on header variables after binding. False before readiness, after failed load or unload, and on pre-3.0; recompute for each new library load. Do not derive it from mutable FailedToLoad diagnostics. Static Load publishes capability from required imports without loading a FIPS module. Changes to diagnostics or application-owned header pointers do not mutate the cached binding snapshot; concurrent rebinding remains unsupported.

Provider-specific managers use cached APIs but perform their own configuration/initialization/validation: FIPS requires fips/base and FIPS algorithm checks; legacy retains default and treats missing optional legacy as nonfatal. Their state must not overwrite API capability flags. Remove TaurusTLSFIPSPropertiesAvailable; consumers and tests use GetOpenSSLLoader.FIPSPropertiesAvailable.

ProvidersPath getter returns configured text, consistently before/after load. EffectiveProvidersPath is a separate resolved value. Preserve Windows default configured value 'providers'; other platforms start empty.

| Setting | Resolution |
|---|---|
| Absolute ProvidersPath | Use normalized absolute directory |
| Relative ProvidersPath + nonempty OpenSSLPath | Resolve against normalized OpenSSLPath |
| Relative ProvidersPath + empty OpenSSLPath | Resolve against executable directory |
| Empty ProvidersPath + nonempty OpenSSLPath | Use OpenSSLPath |
| Both empty | Leave OpenSSL search defaults/environment unchanged |
| Nonempty ConfigFile | Normalize absolute file path; relative values resolve against executable directory |
| Empty ConfigFile | Use normal OpenSSL configuration/environment |

Use platform path APIs; Windows drive-relative paths such as C:folder are not absolute and must be rejected. Preserve UNC handling. Convert configured C API paths to UTF-8 using a named local buffer. Check every path-setting result. Do not call the 3.2-only search-path getter to support OpenSSL 3.0.

Configuration setters are allowed only while Uninitialized. Resolve paths when initialization begins. Explicit ConfigFile must be a full OpenSSL configuration containing the provider-section wiring and installed FIPS data, not an assumed standalone fipsmodule.cnf. Load it once through OSSL_LIB_CTX_load_config(nil, ...). Empty uses OpenSSL default loading. Set OPENSSL_INIT_NO_LOAD_CONFIG when using explicit configuration before any implicit initialization; otherwise use normal configuration loading. Never generate integrity MACs or run fipsinstall in application code.

Use one recursive lifecycle critical section shared by loader and provider manager. Internal initialization/shutdown routines require that lock and never call public Load recursively. Public provider operations initialize outside callback dispatch then use locked internal routines. During load callbacks, already-ready APIs/manager permit provider acquisition on the same thread without restarting Load. Nested Load, Unload or FIPS switching during callback dispatch is rejected explicitly. Register lifecycle callbacks before initialization; preserve forward load and reverse unload order.

Non-FIPS applications require no new configuration calls, initialization calls, provider artifacts or application-defined build symbols. Preserve automatic initialization and existing deployment defaults; optional provider/FIPS APIs are not prerequisites for ordinary Load. FIPS-specific configuration and policy-switch obligations apply only after FIPS opt-in. Package rebuilds for the API version bump are release engineering work, not new application setup requirements.

FIPS property mutation and teardown require application quiescence. Do not claim that this lock protects third-party OpenSSL callers. Read-only getters acquire the same lock. Never change default policy concurrently with fetches or TLS handshakes.

## 3. Library and provider lifecycle

### Initialization

1. Install configured TaurusTLS memory callbacks before any OpenSSL allocation. For dynamic mode, bind the necessary functions first; move allocator setup into the common loader readiness path so hash-only Load does not bypass it.
2. Dynamic mode acquires libcrypto and libssl, verifies supported version and binds registered headers. Static mode uses imports and obtains version directly.
3. Capture genuine export availability in the loader before header binding replaces missing exports with exception stubs. For A04, resolve the two FIPS property export names directly against the acquired libcrypto handle and cache their combined availability, gated by OpenSSL >=3.0. Static linking establishes API presence through required imports. Publish flags only after successful readiness and clear them on failed initialization/unload. Broader provider/configuration capabilities follow the same model during B. On pre-3.0, skip all provider APIs.
4. Apply the effective module path and register supplied built-ins, including an artifact-selected legacy built-in. Check both operations before configuration can activate any provider.
5. Initialize OpenSSL configuration according to section 2. Fail required initialization if configuration loading fails; built-ins must already be discoverable.
6. Activate requested normal providers: default first, legacy if opted in. Missing legacy is optional; preserve default reference and report the failure. FIPS provider is not implicitly requested merely because TaurusTLSFIPS installs hooks.
7. Dispatch osaLoad callbacks with manager/API readiness established. Mark public Ready only after all required initialization and callbacks succeed.

Config-activated providers may already exist. Obtain an explicit owned reference with OSSL_PROVIDER_load when adopting a provider; never assume ownership from OSSL_PROVIDER_available.

LoadProvider is idempotent per name for this manager: one owned reference per provider. Loading legacy also ensures default. Explicit calls return false on failure; optional unit activation records that failure without aborting normal loader readiness. IsProviderLoaded reports this manager's successful acquisition; it does not promise algorithm permission.

### Rollback and teardown

Maintain a completion ledger for newly acquired library handles, provider references and completed callbacks. If a callback raises, unwind that callback's partial work through its osaUnload handler, then completed callbacks in reverse. Each callback must support partial initialization. Continue cleanup after individual exceptions, preserving the original failure and recording cleanup errors.

Release provider references in reverse acquisition order before clearing bindings. Clear state only after release succeeds; if OSSL_PROVIDER_unload fails, preserve handles and libraries, record an error and reject library unload. Do not retry blindly in finalization. Partial libcrypto/libssl acquisition must also be released if the second library fails. Clear the failed-attempt latch so a corrected configuration can retry.

Unload requires no outstanding contexts or consumer threads. Run unload callbacks before provider release. Restore the initial FIPS property only if TaurusTLS changed it and it is safe to do so; a failed restoration prevents dynamic library unload. Do not change externally configured policy merely because a provider handle is released. Static teardown never frees imported libraries. Registration tracking survives static provider release because built-in registrations remain in the context; dynamic tracking is reset only with the actual library lifecycle.

No OPENSSL_cleanup during reloadable teardown. Do not promise that arbitrary external references/configuration state disappear on DLL unload.

## 4. FIPS enable, disable and compatibility wrappers

Indy TGetFIPSMode/TSetFIPSMode signatures remain unchanged. Modern hooks and modern crypto compatibility wrappers delegate to the same manager. Remove header-global fips_provider/base_provider ownership and static local wrappers that always return zero.

GetFIPSMode must not load libraries as a side effect. Before readiness it reports false; after readiness on OpenSSL 3/4 it reads EVP_default_properties_is_fips_enabled(nil). This is a policy query, not provider health or certification. On earlier versions call a genuinely bound legacy FIPS_mode, excluding missing-function stubs.

SetFIPSMode(true), during an application-controlled quiescent phase:

1. Ensure loader initialization and required modern capabilities. Snapshot the current FIPS property and manager-owned handles.
2. Acquire fips and base exactly once. Provider load performs initialization/self-tests; do not run an extra self-test on every toggle.
3. Probe SHA256 and HMAC with explicit fips=yes,provider=fips queries and free probe objects. A conflicting pre-existing property query must cause failure rather than being silently erased.
4. Enable through EVP_default_properties_enable_fips(nil, 1), preserving unrelated properties.
5. Verify the property and an ordinary nil-query SHA256 fetch resolves to fips; verify HMAC initialization with a permitted key and digest.
6. Return true only after all checks. On failure restore the previous FIPS property, release only references added by this attempt and return false with diagnostics. If restoration fails, retain required handles, preserve the actual restrictive state, record a critical diagnostic and do not pretend the old state was restored.

Repeat enable performs health/policy checks without duplicating references. If configuration already enabled FIPS, acquisition and verification still occur when explicit enable is requested. Load itself verifies configured FIPS with the same probes; if configuration demands FIPS but verification fails, fail initialization without downgrade.

SetFIPSMode(false) ensures default is retained before removing the FIPS property via enable_fips(nil, 0). Leave fips/base references retained until shutdown; no active-provider churn during toggles. Preserve unrelated properties and verify the resulting flag. Repeat disable succeeds when policy is already disabled. GetFIPSMode may legitimately remain true after a failed disable.

On OpenSSL <3, use genuinely available legacy functions only. FIPS provider methods report unsupported. Retain the repository's existing minimum-version policy; this change does not expand historical FIPS claims.

Bind EVP_default_properties_enable_fips and EVP_default_properties_is_fips_enabled in both import models with proper 3.0 introduction metadata. Preserve the existing version encoding expected by header loaders. Test on 3.0 without requiring any 3.2+ provider functions. Static OpenSSL 4 support also requires configured import library names matching deployed libraries rather than hardcoded libcrypto-3 names.

## 5. Indy algorithms, HMAC and legacy facade

Preserve InstallFIPSHooks and optional hook installer behavior.

- MD2/MD4/MD5 digest availability AND instance hooks call the corresponding Indy permission checks before fetching. A FIPS prohibition raises EIdFIPSAlgorithmNotAllowed; it never returns false and selects native fallback.
- HMAC-MD5 availability AND instance hooks likewise reject with FIPSAlgorithmNotAllowed('HMAC-MD5').
- Normal algorithm absence returns false from availability. Instance construction reports the existing algorithm-not-found exception. General hashing availability remains library readiness.
- Other advertised algorithms query effective EVP availability. For an algorithm excluded by FIPS policy, an availability hook must raise before Indy can select its native implementation; distinguish exclusion using an explicit algorithm policy table for supported hook algorithms, not a fetch with fips=no.
- Modern HMAC uses EVP_MAC_fetch('HMAC'), EVP_MAC_CTX_new, OSSL_PARAM digest parameters, EVP_MAC_init/update/final and EVP_MAC_CTX_free consistently. Legacy branches use HMAC_CTX with matching legacy operations throughout. Free allocated contexts and fetched methods on initialization/finalization errors.
- NTLM availability reports policy prohibition by exception while FIPS is enabled. Both LM and NT response hooks reject before low-level DES or hashing; retain existing MD4 checks. Full NTLM EVP migration is outside this refactor.
- TaurusTLS_LegacyProviders initialization requests legacy activation through the common service. Dynamic builds register the request before Load. Static builds initialize through common Load to preserve startup behavior. IsLegacyProviderLoaded delegates to managed state.
- The facade imports a built-in legacy callback only when an actual archive artifact is selected. Derive the internal TAURUSTLS_BUILTIN_LEGACY_PROVIDER selection from existing supported archive/platform settings so current non-FIPS applications need no new define. Permit an explicit override for custom artifacts. Startup-linked shared builds do not import an archive callback.
- Runtime packages containing the facade can activate it through package initialization; document that effective opt-in includes package composition.

Do not add fips=no overrides or automatic dedicated non-FIPS contexts. Direct third-party calls into Indy native methods remain outside this provider integration's enforcement boundary; tests and documentation must not claim whole-application compliance.

## 6. Diagnostics and acceptance

ProviderDiagnostics is a locked string snapshot for the latest failed operation, including stage, provider, full OpenSSL version, effective path and relevant OpenSSL errors. Clear it at the start of a new control operation. Preserve all failure messages within that operation and cleanup. FailedToLoad remains the existing symbol-binding list; provider errors are separate. Do not clear the entire application error queue on successful status queries.

Add new DUnitX fixtures to the existing Tests/TaurusTLS.UT project and inherit them from TOsslBaseFixture in TaurusTLS.UT.TestClasses.pas. Descendant fixture setup calls inherited SetupFixture first; fixture teardown calls inherited TearDownFixture last. Register each fixture with TDUnitX.RegisterTestFixture. Compile through Kai in the open project group using the plan's IDE-first build procedure. Global configuration/FIPS tests run in fresh processes; configure pre-load scenarios before inherited setup loads OpenSSL, and do not mutate shared suite policy concurrently.

| Scenario | Acceptance |
|---|---|
| No FIPS opt-in | Existing application source, configuration, deployment, startup sequence and legacy build settings work unchanged; no FIPS module/config is required |
| Legacy module/built-in available | default + legacy acquired once; MD4 works with FIPS off |
| Missing optional legacy | normal Load succeeds; legacy false; diagnostic recorded |
| FIPS installed correctly | enable true; flag true; SHA256/HMAC provenance is fips |
| Missing/tampered FIPS config/module | enable false; no downgrade of existing policy; no new reference leak |
| Legacy + FIPS | MD4/MD5/HMAC-MD5/LM/NTLM rejected before native/DES execution |
| FIPS disable | unrelated properties retained; modern default operations restored |
| Repeat load/enable/disable/unload | no duplicate acquisition; correct cleanup order |
| Callback/path/binding failure | reverse rollback, no stale readiness or partial library handles |
| Unicode/relative/UNC paths | deterministic resolution and UTF-8 bridge |
| OpenSSL 1.x without FIPS | safe unsupported result; provider APIs never invoked |
| Startup shared/archive builds | no unconditional legacy archive; ABI-correct supplied built-in |
| FIPS TLS | allowed TLS handshake and key decoding succeed in default context |

Document missing artifact/platform validation as unverified, not passed. Static built-in FIPS acceptance requires an actual compatible artifact; generic registration tests alone do not establish it.

Sources and constraints: see HLD references. OpenSSL property mutation is initialization-only in its thread-safety contract; this design requires application-enforced quiescence for any later switch.
