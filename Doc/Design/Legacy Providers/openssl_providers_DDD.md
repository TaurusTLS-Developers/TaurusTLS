# TaurusTLS OpenSSL Configuration, FIPS and Legacy Support — DDD

Status: Revised specification for developer review. Section 2A is a proposed runtime/metadata design, not implemented behavior.
Revision date: 2026-10-22.
Architecture: [HLD](openssl_providers_HLD.md).

## 1. Public API and linking boundaries

Preserve the existing `IOpenSSLLoader` contract across both dynamic and static linking models, including its library-path, version, loading, and diagnostic members. Remove `GetProvidersPath`, `SetProvidersPath` and `ProvidersPath`, including any proposed effective path property. Add:

~~~pascal
function GetConfigFile: string;
procedure SetConfigFile(const AValue: string);

property ConfigFile: string read GetConfigFile write SetConfigFile;
~~~

Preserve the existing `IOpenSSLLoader` GUID `{BBB0F670-CC26-42BC-A9E0-33647361941A}` for ConfigFile, State and the proposed metadata accessors, as directed by the developer. Rebuild all affected packages and consumers together; the unchanged GUID does not make earlier compiled interface layouts compatible.

`GetOpenSSLLoader` returns the singleton `IOpenSSLLoader` instance across all platforms:
- In dynamic builds (`{$IFNDEF OPENSSL_STATIC_LINK_MODEL}`), it instantiates and returns `TOpenSSLDynamicLoader`.
- In static builds (`{$IFDEF OPENSSL_STATIC_LINK_MODEL}`), it instantiates and returns `TOpenSSLStaticLoader`. It is non-nil on both.

In static mode, dynamic-specific properties (`OpenSSLPath`, `SSLLibVersions`, `FailedToLoad`) provide safe/inert defaults (`''` and an empty list) to maintain unified cross-platform consumer code without requiring conditional compilation in client applications.

`TaurusTLSLinkDefines.inc` must reject simultaneous `STATICLOAD_OPENSSL` and `OPENSSL_USE_SHARED_LIBRARY` definitions on every target. `STATICLOAD_OPENSSL` selects linked archives; `OPENSSL_USE_SHARED_LIBRARY` selects startup shared-library imports. The Windows compiler-include example enables only `OPENSSL_USE_SHARED_LIBRARY`. Linked legacy callback imports and registration use `{$IFDEF STATICLOAD_OPENSSL}`; `OPENSSL_STATIC_LINK_MODEL` alone also covers shared-library imports and is insufficient for selecting the archive callback.

Do not add public `LoadProvider`/`RegisterBuiltinProvider`/FIPS-mode methods to `IOpenSSLLoader`. Preserve the Indy `SetFIPSMode`/`GetFIPSMode` signatures. Their backend remains in `TaurusTLSFIPS`, with dynamic-only internal FIPS management. `IsLegacyProviderLoaded` remains the legacy facade's public status function.

Headers remain OpenSSL-only. Modern property API imports do not imply TaurusTLS supports static FIPS. The implemented `CONF_modules_load_file_ex` import belongs to `TaurusTLSHeaders_conf`. Use only modern OpenSSL 3.x/4.x routines in the new runtime/metadata path; do not move OpenSSL 0.9–1.1.1 compatibility branches into it.

## 2. Configuration lifecycle and Template Method architecture

`ConfigFile` defaults to empty. Set it while inactive; reject changes while loading, ready or unloading. Reassigning the exact configured input is a no-op. Static OpenSSLPath/SSLLibVersions setters remain inert. Changes after failed cleanup do not reset the failure breaker. When the library is unloaded, `GetConfigFile` returns the configured value (`FConfigFile`). Once initialization succeeds, `GetConfigFile` reflects the effective active configuration (`FEffectiveConfigFile`):
- For an explicit configuration, it returns the normalized full file path.
- When `ConfigFile` is left empty, it returns the discovered default OpenSSL configuration path obtained via `CONF_get1_default_config_file()` and freed with `OPENSSL_free`.
Upon library unload, `FEffectiveConfigFile` is cleared and `GetConfigFile` returns back to reporting `FConfigFile`.

Calling `Load` again when the loader is ready returns `True` without repeating configuration or callbacks. Load calls do not acquire references. One explicit `Unload` performs cleanup, even after several successful `Load` calls; further `Unload` calls are safe. The application must finish active crypto operations before unloading.

Normalize a nonempty relative filename against the current full path and pass a UTF-8 buffer to OpenSSL. Explicit `ConfigFile` loading uses `CONF_modules_load_file_ex` and requires OpenSSL 3.0 or higher; OpenSSL 1.1.x is excluded from support with this configuration mechanism. Leave OpenSSL's own include/module path semantics unchanged.

Configuration behavior:

| Input | Required behavior |
|---|---|
| Empty ConfigFile | Current loader discovers the default filename with `CONF_get1_default_config_file()`; this does not load it. Modern default initialization and OPENSSL_CONF behavior must be defined before claiming the file was applied |
| Nonempty ConfigFile | Suppress implicit default configuration loading; explicitly apply the selected file to nil/default context via `CONF_modules_load_file_ex` (requires OpenSSL 3.0+) |
| Invalid/missing explicit file path | Raise ETaurusTLSConfigFilePathError before provider callbacks; engage failure circuit breaker |
| OpenSSL configuration-loading failure | Capture OpenSSL error queue and raise ETaurusTLSConfigFileLoadError with effective filename; engage failure circuit breaker |
| Existing external initialization | Document the default-context ownership precondition; do not promise that prior configuration can be replaced |
| Static model | Supported via `TOpenSSLStaticLoader`. Explicit `ConfigFile` is applied to default context via `CONF_modules_load_file_ex`; empty config preserves default configuration. No external module loading or FIPS initialization |

### Template Method pattern & loader class hierarchy

To eliminate code duplication, centralize error handling, and guarantee thread safety, `TaurusTLSLoader` employs the Template Method pattern:

* **`TOpenSSLBaseLoader` (Abstract Base):**
  - Manages `FLoaderLock: TIdCriticalSection`, the atomic `FState` backing field, `FLastLoadActionIdx: NativeInt`, `FConfigFile`, and `FEffectiveConfigFile`. No separate loaded/failed Boolean supplies readiness.
  - Non-virtual template methods `Load` and `Unload` govern the state machine, thread locking, and circuit breaker.
  - Declares abstract/virtual hooks `function DoLoad: Boolean; virtual; abstract;` and `procedure DoUnload; virtual; abstract;`.
  - Encapsulates shared configuration validation (`ApplyConfiguration`), OpenSSL static-inline call wrappers, and action callback dispatching/rollback (`DispatchLoadActions`, `RollbackLoadActions`).
* **`TOpenSSLDynamicLoader` (`{$IFNDEF OPENSSL_STATIC_LINK_MODEL}`):**
  - Owns `FLibCrypto`, `FLibSSL`, `FOpenSSLPath`, `FSSLLibVersions` (initialized to `DefaultLibVersions`), and `FFailed`.
  - In `DoLoad`: locates dynamic libraries (`FindLibrary`), validates OpenSSL 3.x/4.x version, binds symbols (`GLibCryptoLoadList`/`GLibSSLLoadList`), applies configuration, and dispatches action callbacks.
  - In `DoUnload`: rolls back action callbacks while symbols/handles are live, unbinds header symbols (`GUnLoadList`), and frees dynamic libraries.
* **`TOpenSSLStaticLoader` (`{$IFDEF OPENSSL_STATIC_LINK_MODEL}`):**
  - Owns static-specific behavior with inert `OpenSSLPath`, `SSLLibVersions`, and empty `FailedToLoad`.
  - In `DoLoad`: verifies statically linked version, applies configuration, and dispatches action callbacks.
  - In `DoUnload`: rolls back action callbacks; dynamic libraries and symbols are not unbound.

### OpenSSL API bridge wrappers

In static mode, statically imported `external` routines cannot be evaluated with `Assigned()` because they are not procedural variables. To bridge this, `TOpenSSLBaseLoader` provides static inline methods with conditional compilation:
- `SslInitCrypto`: calls `OPENSSL_init_crypto` directly in static mode; guards with `if Assigned(OPENSSL_init_crypto)` in dynamic mode.
- `SslModulesLoadFileEx`: calls `CONF_modules_load_file_ex` directly in static mode; guards with `if Assigned(CONF_modules_load_file_ex)` in dynamic mode.
- `SslGet1DefaultConfigFile`: calls `CONF_get1_default_config_file` directly in static mode; guards with `if Assigned(CONF_get1_default_config_file)` in dynamic mode.
- `SslFree`: calls `OPENSSL_free` directly in static mode; guards with `if Assigned(OPENSSL_free)` in dynamic mode.

Method pointer typecasts for action callbacks are wrapped in `IsActionAssigned` and `ClearAction` with `{$IFDEF DCC}{$WARN UNSAFE_CAST OFF}{$ENDIF}` to suppress Delphi `W1048` compiler warnings.

### Thread-safe registration & initialization order

`Register_SSLLoader`, `Register_SSLUnloader`, and `Register_SSLLoaderAction` can be invoked at runtime from any thread or during unit initialization.
1. All registration routines are synchronized using `GRegistrationLock: TIdCriticalSection`.
2. To prevent dropped registrations caused by Delphi unit dependency order (where `TaurusTLSHeaders_*` initialize prior to `TaurusTLSLoader`), `GRegistrationLock` is initialized on-demand via `EnsureRegistrationLock`.
3. Iteration during `DispatchLoadActions` and `RollbackLoadActions` acquires `GRegistrationLock` when indexing callbacks, preventing concurrent mutation hazards.

### Failure handling, circuit breaker, and callback rollback

If library loading fails at any point (validation error, OpenSSL configuration failure, or an exception inside an `osaLoad` callback):
1. The loader captures the OpenSSL error details before executing teardown.
2. Internal `UnloadInternal(False)` executes; public recursive Unload is not used:
   - Dispatches `osaUnload` in reverse order strictly to callbacks that already executed `osaLoad` (`FLastLoadActionIdx downto 0`). Callbacks that failed or have not yet run are not dispatched `osaUnload`.
   - Executes header unloaders (`GUnLoadList`) in dynamic mode.
   - Frees loaded library handles (`FLibSSL`, `FLibCrypto`) in dynamic mode.
   - Clears `FEffectiveConfigFile`.
   - Publishes `lsLoadedFailed` while preserving recorded diagnostics in `FailedToLoad`.
3. The captured exception is raised to the caller.
4. **Circuit Breaker:** While State is `lsLoadedFailed`, subsequent Load calls return False without reinitializing. Explicit Unload resets to `lsNotLoaded` and clears diagnostics on successful cleanup. Cleanup errors must still leave a stable non-ready state.

Do not promise transactional rollback of OpenSSL configuration modifications that OpenSSL core already applied prior to failure.

### Configuration exceptions

Declare these in TaurusTLSExceptionHandlers.pas:

~~~pascal
ETaurusTLSConfigFilePathError = class(ETaurusTLSAPICryptoError);
ETaurusTLSConfigFileLoadError = class(ETaurusTLSAPICryptoError);
~~~

Use `ETaurusTLSAPICryptoError` because configuration APIs belong to libcrypto. `ETaurusTLSAPISSLError` uses `SSL_get_error` with an SSL object/return code and is inappropriate for this operation.

Validate the normalized explicit path:
- At `SetConfigFile` time, validate path character syntax (reject embedded NUL or invalid characters via `TPath.HasValidPathChars`). Reject changes if already loaded.
- At `Load` time, validate the target: reject directories or non-existent files. Raise `ETaurusTLSConfigFilePathError` with the effective filename and reason. Construct that exception directly with the existing exception constructor; do not consume an unrelated OpenSSL error queue for a filesystem-validation failure. Its OpenSSL ErrorCode remains zero.

When `CONF_modules_load_file_ex` returns <= 0, call `ETaurusTLSConfigFileLoadError.RaiseException` with a message naming the operation and effective filename. The inherited class method retrieves the OpenSSL error queue and formats it using existing TaurusTLS conventions. Raise immediately, before cleanup can alter the error queue; `UnloadInternal(False)` executes in the exception block while preserving the original exception even if cleanup also fails. Error reporting still includes the filename if OpenSSL supplies no error code.

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

`CONF_get1_default_config_file` is diagnostic/discovery support only. Its caller owns the returned string and frees it with `OPENSSL_free`. It does not select or change configuration. `CONF_modules_load_file_ex` is the chosen explicit loader; do not redundantly call both it and `OSSL_LIB_CTX_load_config` for the same file. [Configuration loading API](https://docs.openssl.org/3.0/man3/CONF_modules_load_file/).

## 2A. Unified runtime and metadata implementation (proposed)

### Readiness and interface shape

The implemented state contract is:

~~~pascal
TTaurusTLSLoaderStateAll = (
  lsLoading, lsUnloading, lsNotLoaded, lsLoadedReady, lsLoadedFailed);
TTaurusTLSLoaderState = lsNotLoaded..lsLoadedFailed;
~~~

GetState maps transitions to lsNotLoaded; IsLoaded tests lsLoadedReady.
The installed Delphi 13 generic TInterlocked methods require class types.
Current code therefore uses Integer atomic storage with typed accessors and
explicit Ord conversions, without pointer/var enum casts. FPC compilation remains
unverified. Public Load/Unload rejects recursive lifecycle calls with
ETaurusTLSLoaderError. Internal rollback is separate. Only State/IsLoaded are
nonblocking status queries.

Proposed additions to IOpenSSLLoader:

~~~pascal
function GetVersion: string;
function GetConfigDirectory: string;
function GetModulesDirectory: string;
function GetEnginesDirectory: string;

property Version: string read GetVersion;
property ConfigDirectory: string read GetConfigDirectory;
property ModulesDirectory: string read GetModulesDirectory;
property EnginesDirectory: string read GetEnginesDirectory;
~~~

Use the existing Load/Unload members. Do not add a second set of lifecycle names
or a second public class facade.

### Metadata collection and lifetime

After configuration and all registered actions succeed, collect metadata while
routines remain callable and before publishing lsLoadedReady:

| Value | Implementation |
|---|---|
| Version | Copy the result of OpenSSL_version(OPENSSL_VERSION_CONST) |
| ConfigDirectory | Extract the directory of the effective configuration filename |
| ModulesDirectory | Copy OPENSSL_info(OPENSSL_INFO_MODULES_DIR) |
| EnginesDirectory | OpenSSL 3.x: copy supported OPENSSL_info(OPENSSL_INFO_ENGINES_DIR); OpenSSL 4.x: empty string |

Use the existing static/direct-call versus dynamic/procedural-variable pattern.
Do not call Assigned on static imports; do not treat a dynamic compatibility stub
as evidence that a native API is available. Unavailable or nil metadata becomes
an empty string. Version/info strings are borrowed; copy them, do not free them.
Only the allocated CONF_get1_default_config_file result is freed with OPENSSL_free.
[Metadata APIs](https://docs.openssl.org/3.0/man3/OpenSSL_version/).

Do not use SSLeay_version, GetDirFromOpenSSLVerString, quoted-text parsing, or a
fallback to an older OpenSSL API. EnginesDirectory is a directory query, not
engine initialization or a claim that engines are available. OpenSSL 4.0 removed
engine-directory support; explicitly return empty on 4.x rather than exposing a
disabled-engine marker or invoking a removed compatibility branch.
[OpenSSL 4.0 metadata changes](https://docs.openssl.org/4.0/man3/OpenSSL_version/).

For ConfigDirectory, use the same effective filename represented by ConfigFile
once ready. Resolve any relative discovered filename against the working
directory during loading and retain the resulting directory. Do not normalize a
relative filename later in a getter, because the working directory can change.
Empty filename means empty directory. Do not add a filesystem existence check
for a merely discovered default filename, or substitute OPENSSL_INFO_CONFIG_DIR.

The module/engine values are compiled default directories, not effective
OPENSSL_MODULES overrides, configured module filenames or a provider inventory.
A nonempty ConfigDirectory likewise does not prove that the file was read.

Store managed Pascal strings in the base loader. Protect collection/publication,
clearing and getter copies with FLoaderLock. Getters test readiness under that lock
and return empty when not ready; they never invoke Load. A competing lifecycle
operation may make a getter wait; only State/IsLoaded are guaranteed not to wait.
During same-thread lifecycle callbacks the recursive lock is already held and
the getter returns empty. Clear metadata on failure and unload. No native pointer
escapes the lifecycle boundary and no readiness result leases OpenSSL resources.

### Lifecycle ownership and initialization ordering

The core loader owns general OpenSSL initialization and configuration for both
linking models. TaurusTLS owns only its runtime-specific resources through a
private class. Proposed sequence, subject to the review gates below:

1. Publish internal lsLoading; obtain libraries/symbols or validate static imports.
2. Complete required pre-initialization work before OpenSSL allocations:
   optional custom memory callbacks and linked builtin registration.
3. Initialize modern libcrypto with an explicit configuration policy. For a
   selected file suppress implicit default loading, then apply that file once
   with CONF_modules_load_file_ex. For empty input define actual default
   initialization separately from filename discovery.
4. Complete modern libssl initialization with OPENSSL_init_ssl using reviewed
   flags. Do not reapply default configuration after an explicit selection.
5. Run registered osaLoad actions, including TaurusTLS runtime resources.
6. Capture metadata and publish lsLoadedReady only after successful completion.

Ordering must be audited for calls that allocate earlier than expected, including
discovery/configuration. The existing osaLoad phase occurs after configuration
and cannot serve steps 2–3. Do not invent a public pre-initialization API without
review. OpenSSL initialization options may be fixed by the first caller;
external initialization and static reloads cannot be treated as a fresh process.
No OPENSSL_cleanup in a reloadable lifecycle.
[Initialization semantics](https://docs.openssl.org/3.0/man3/OPENSSL_init_crypto/).

Optional OPENSSL_SET_MEMORY_FUNCS needs a separate design decision before moving
it: audit size_t, filename/line parameters, cdecl ABI and realloc semantics, and
install it before the first OpenSSL allocation. A post-configuration load action
is too late. [Memory callback contract](https://docs.openssl.org/3.0/man3/OPENSSL_malloc/).

### Private TaurusTLS runtime class

Replace the existing global TLS initialization resources with class vars and
class methods in a private implementation class in TaurusTLS. Keep TaurusTLS
socket/Indy dependencies out of TaurusTLSLoader. Register a load/unload action
whose method is compatible with the existing procedure-of-object signature;
use an ordinary class method where a static method would lose the method pointer.

The class owns the locks still required by TaurusTLS info/level/password/verify/
SNI callbacks. It does not publish another ready Boolean or acquire a separate
global lifecycle lock. Remove SSLIsLoaded as a competing state source after
auditing its users. Modern OpenSSL supplies its own threading support; remove
CRYPTO_num_locks/locking/thread-ID setup and corresponding legacy cleanup from
this path. Remove obsolete explicit error-string setup and obsolete init flags.

The action cleans up partial allocations before propagating its own failure,
because the loader only unwinds completed actions. Successful actions release
resources in osaUnload before native unbinding. Internal callbacks never call
public Load/Unload. Review action registration lifetime and unit/package
finalization so callbacks never target finalized resources.

### Compatibility wrappers and migration

Keep these routines and make each a forwarding wrapper, inline where supported:

| Routine | Forwarding expression/operation |
|---|---|
| LoadOpenSSLLibrary | GetOpenSSLLoader.Load |
| UnLoadOpenSSLLibrary | GetOpenSSLLoader.Unload |
| OpenSSLVersion | GetOpenSSLLoader.Version |
| OpenSSLDir | GetOpenSSLLoader.ConfigDirectory |
| OpenSSLModulesDir | GetOpenSSLLoader.ModulesDirectory |
| OpenSSLEnginesDir | GetOpenSSLLoader.EnginesDirectory |

This forwarding contract is proposed for review. LoadOpenSSLLibrary remains an
explicit application initialization entry point. One Unload globally tears down
the runtime even after multiple successful Load calls; no reference counter is
introduced. Metadata wrappers are passive and return empty before readiness.
OpenSSLDir now means the directory containing ConfigFile; document this change.

Audit internal context constructors and all other implicit Load calls in the
consumer review. They must not be used to conceal an initialization
requirement. Application shutdown must retire live objects/operations first.

### Decisions required before implementation

- Approve accessor/property names and compatibility forwarding/migration.
- Approve the core/native-init versus private TLS-resource split.
- Select default/explicit init flags and failure reporting; avoid duplicate config.
- Define optional allocator setup and pre-configuration builtin registration.
- Define registration/finalization ordering without introducing circular units.
- Test both models and failure rollback; keep provider/FIPS policy work deferred.

## 3. Discovery, ownership and legacy support

Provider activation is controlled only by openssl.cnf. Neither unit inclusion,
metadata queries nor NTLM availability hooks may call OSSL_PROVIDER_load to
silently activate default, legacy, fips or base. The previous design for automatic
default/legacy acquisition is superseded. A programmatic activation API is deferred.

OpenSSL configuration/environment resolves modules. Do not restore ProvidersPath,
set a hidden default search path, mutate the customer's environment or parse
provider sections in Delphi. In OpenSSL 4.0 activate is Boolean; in 3.0 presence
alone activates. Omit activate to defer activation across these versions.
[OpenSSL 4.0 provider configuration](https://docs.openssl.org/4.0/man5/config/#provider-configuration),
[OpenSSL 3.0 provider configuration](https://docs.openssl.org/3.0/man5/config/#provider-configuration).

For linked legacy code, import ossl_legacy_provider_init only under the artifact
configuration that supplies it (STATICLOAD_OPENSSL), with the exact C ABI.
OSSL_PROVIDER_add_builtin registers a discoverable implementation and does not
activate it. This registration must precede configuration. The existing
post-configuration osaLoad callback cannot provide that ordering; its replacement
mechanism is a design gate, not an instruction to add another public API.

Configuration owns its activation references. Do not unload handles merely
observed by TaurusTLS. Any later retained-reference design must be explicit,
reviewed and release only owned references before dynamic unbinding.
IsLegacyProviderLoaded/readiness semantics must be reviewed against configured
algorithm availability; a provider name alone is not an NTLM execution guarantee.
No fallback activation or weakening of configured FIPS selection is permitted.

## 4. FIPS reporting and Indy policy (deferred)

The earlier programmatic FIPS activation/toggle specification is superseded.
Provider activation belongs to configuration. Final GetFIPSMode/SetFIPSMode
reporting and setter behavior require a separate discussion with the developer;
Loader initialization must not activate providers or change FIPS policy.

Keep FIPS-specific checks in TaurusTLSFIPS, not public loader capability flags.
Distinguish genuine native API availability from binding stubs, provider
availability, enabled default properties and operation-specific permission.
Use modern APIs only; do not retain FIPS_mode/FIPS_mode_set compatibility with
OpenSSL before 3.0 in this refactor.

Readiness hooks must first check loader state and must never initialize or
reset the loader. The agreed LoadNTLMLibrary adapter is a status-only query.
Algorithm availability and execution hooks still need review, including Indy
native fallbacks and whether each failure can safely raise an exception.

Legacy activation does not override FIPS property selection or make MD4/DES
acceptable under an enabled FIPS policy. Do not solve that conflict by weakening
default properties. Static FIPS remains unsupported within this design.

HMAC migration to modern EVP_MAC, detailed hook enforcement, FIPS implementation
provenance checks and any future policy API remain separate reviewed work.
No loader success, provider activation or test result establishes certification.

## 5. Tests and review gates

Use existing DUnitX fixtures and register with TDUnitX.RegisterTestFixture.
Loader/lifecycle fixtures must control initialization themselves rather than
inherit an eager OpenSSL load. Crypto-dependent fixtures can use TOsslBaseFixture.
Use controlled temporary configurations and failure-safe restoration; isolate
process-wide initialization options or provider-policy scenarios in fresh
processes where necessary.

Preserve the runner's existing -osp/-osmp parameters and test-only environment
preparation. Do not require OPENSSL_CONF to be set before launching from the IDE.
Windows OpenSSL 4.0.2 x86/x64 distributions are the agreed development inputs.
Compile runtime then tests through Kai/developer-assisted builds; validate Win32,
Win64, Linux64 and OSX64. iOS/Android and broader distributions are deferred.

Runtime and metadata acceptance:

| Case | Expected result |
|---|---|
| Direct loader.Load | Native initialization/configuration and registered TLS runtime actions complete before ready, in both models |
| Compatibility lifecycle calls | Same loader and global ownership; repeated loads do not duplicate resources |
| Passive metadata | Empty before readiness/after cleanup; queries never trigger Load or provider activation |
| Version/module/engine values | Match supported modern native queries; unavailable values and OpenSSL 4.x engine directory are empty |
| ConfigDirectory | Derived from effective ConfigFile; relative discovery fixed at load time; empty filename yields empty |
| Working directory changes | Metadata does not drift after loading |
| Unicode/macOS aliases | Existing Unicode and canonical-path handling preserved |
| Callback observations | Non-ready during load/unload/rollback; native routines callable until unbinding; metadata empty |
| Partial TLS action failure | Own partial resources cleaned, earlier actions unwound, loader failed, original error preserved |
| Unload/reload | Metadata/resources cleared; no duplicate callbacks, legacy locking setup or second ready flag |
| Configuration ownership | No duplicate default configuration after explicit selection; discovery alone not reported as proof of application |
| Providers | Configuration-only activation; linked builtin registration ordering reviewed separately |

Review the HLD/DDD before production changes. After implementation, reconcile
XMLDoc and migration notes with the actual behavior and record platform results.
Keep the known InputRanges common-name failure on Linux/macOS separate from
regressions; record Windows LegacyProvider exclusions explicitly. FPC remains
unverified. No plans/design documents are staged or committed.
