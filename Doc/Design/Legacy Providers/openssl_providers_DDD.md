# TaurusTLS OpenSSL Configuration, FIPS and Legacy Support — DDD

Status: Loader/runtime lifecycle and independent NTLM hooks/responses are implemented. Configuration-owned activation and registration-only legacy refactoring are implemented; provider execution/isolated acceptance and final FIPS policy remain pending.
Revision date: 2026-10-24.
Architecture: [HLD](openssl_providers_HLD.md).

## 1. Public API and linking boundaries

Preserve the existing `IOpenSSLLoader` contract across both dynamic and static linking models, including its library-path, version, loading, and diagnostic members. Remove `GetProvidersPath`, `SetProvidersPath` and `ProvidersPath`, including any proposed effective path property. Add:

~~~pascal
function GetConfigFile: string;
procedure SetConfigFile(const AValue: string);

property ConfigFile: string read GetConfigFile write SetConfigFile;
~~~

Preserve the existing `IOpenSSLLoader` GUID `{BBB0F670-CC26-42BC-A9E0-33647361941A}` for ConfigFile, State and the metadata accessors, as directed by the developer. Rebuild all affected packages and consumers together; the unchanged GUID does not make earlier compiled interface layouts compatible.

`GetOpenSSLLoader` returns the singleton `IOpenSSLLoader` instance across all platforms:
- In dynamic builds (`{$IFNDEF OPENSSL_STATIC_LINK_MODEL}`), it instantiates and returns `TOpenSSLDynamicLoader`.
- In static builds (`{$IFDEF OPENSSL_STATIC_LINK_MODEL}`), it instantiates and returns `TOpenSSLStaticLoader`. It is non-nil on both.

In static mode, dynamic-specific properties (`OpenSSLPath`, `SSLLibVersions`, `FailedToLoad`) provide safe/inert defaults (`''` and an empty list) to maintain unified cross-platform consumer code without requiring conditional compilation in client applications.

`TaurusTLSLinkDefines.inc` must reject simultaneous `STATICLOAD_OPENSSL` and `OPENSSL_USE_SHARED_LIBRARY` definitions on every target. `STATICLOAD_OPENSSL` selects linked archives; `OPENSSL_USE_SHARED_LIBRARY` selects startup shared-library imports. The Windows compiler-include example enables only `OPENSSL_USE_SHARED_LIBRARY`. Linked legacy callback imports and registration use `{$IFDEF STATICLOAD_OPENSSL}`; `OPENSSL_STATIC_LINK_MODEL` alone also covers shared-library imports and is insufficient for selecting the archive callback.

Do not add public `ActivateProvider`/`LoadProvider`/`RegisterBuiltinProvider`/FIPS-mode methods to `IOpenSSLLoader`. The 2026-10-24 activation-API proposal is superseded by configuration-only activation. Preserve Indy `SetFIPSMode`/`GetFIPSMode` signatures in `TaurusTLSFIPS`; final reporting/setter semantics remain pending. Retain the legacy unit for archive registration and review its `IsLegacyProviderLoaded` compatibility semantics without manager-owned activation handles.

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
| Empty ConfigFile | Request `OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, nil)`, then discover the default filename with `CONF_get1_default_config_file()`. Discovery itself does not load or validate that file; prior initialization may have fixed the native configuration policy |
| Nonempty ConfigFile | Suppress implicit default configuration loading; explicitly apply the selected file to nil/default context via `CONF_modules_load_file_ex` (requires OpenSSL 3.0+) |
| Invalid/missing explicit file path | Raise ETaurusTLSConfigFilePathError before provider callbacks; engage failure circuit breaker |
| OpenSSL configuration-loading failure | Capture OpenSSL error queue and raise ETaurusTLSConfigFileLoadError with effective filename; engage failure circuit breaker |
| Existing external initialization | Document the default-context ownership precondition; do not promise that prior configuration can be replaced |
| Static model | Supported via `TOpenSSLStaticLoader`. Explicit `ConfigFile` is applied to default context via `CONF_modules_load_file_ex`; empty config preserves default configuration. No external module loading or FIPS initialization |

### Template Method pattern & loader class hierarchy

To eliminate code duplication, centralize error handling, and guarantee thread safety, `TaurusTLSLoader` employs the Template Method pattern:

* **`TOpenSSLBaseLoader` (Abstract Base):**
  - Owns the atomic singleton slot and class-owned action registry. Each instance owns `FRegistrationLock`, `FLoaderLock`, the atomic `FState` backing field, `FLastLoadActionIdx`, configuration strings and cached metadata. No separate loaded/failed Boolean supplies readiness.
  - Non-virtual template methods `Load` and `Unload` govern the state machine, thread locking, and circuit breaker.
  - Declares abstract/virtual hooks `function DoLoad: Boolean; virtual; abstract;` and `procedure DoUnload; virtual; abstract;`.
  - Encapsulates shared configuration validation (`ApplyConfiguration`), OpenSSL static-inline call wrappers, and action callback dispatching/rollback (`DispatchLoadActions`, `RollbackLoadActions`).
* **`TOpenSSLDynamicLoader` (`{$IFNDEF OPENSSL_STATIC_LINK_MODEL}`):**
  - Owns class registries `FCryptoLoaders`, `FSSLLoaders` and `FUnloaders`; each instance owns `FLibCrypto`, `FLibSSL`, `FOpenSSLPath`, `FSSLLibVersions` (initialized to `DefaultLibVersions`), and `FFailed`.
  - In `DoLoad`: locates dynamic libraries (`FindLibrary`), validates OpenSSL 3.x/4.x version, binds symbols (`FCryptoLoaders`/`FSSLLoaders`), applies configuration, and dispatches action callbacks.
  - In `DoUnload`: rolls back action callbacks while symbols/handles are live, unbinds header symbols (`FUnloaders`), and frees dynamic libraries.
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

### Thread-safe singleton publication and registration

The loader may be constructed by TaurusTLSLoader unit initialization or earlier
by Register_SSLLoader/Register_SSLUnloader. Register_SSLLoaderAction and
GetOpenSSLLoader use the same path, including in static builds. Construction only
creates Pascal infrastructure and reads loader settings; it never calls Load,
initializes OpenSSL or dispatches actions.

TOpenSSLBaseLoader.EnsureInstance atomically reads FInstance. If it is nil, it
constructs the selected concrete loader using an ordinary nonvirtual constructor.
OPENSSL_STATIC_LINK_MODEL selects only TOpenSSLStaticLoader versus
TOpenSSLDynamicLoader. Both branches return to the same CompareExchangeInstance
publication call; static builds do not bypass CAS, including calls from other
threads through GetOpenSSLLoader.
The base instance constructor creates FRegistrationLock and FLoaderLock
unconditionally. Each candidate has its own locks, diagnostic list and unloaded
state. Constructors do not mutate registration lists.

After the concrete constructor completes, acquire one ownership reference with
_AddRef, then publish the object using CAS with nil as the comparand. The winner
transfers that reference to the singleton slot. A losing candidate releases its
reference with _Release and returns the published winner. Constructor failure
does not publish a partial instance.

For Delphi, use a typed TInterlocked.CompareExchange<TOpenSSLBaseLoader> slot;
for FPC, use its Pointer CAS overload behind the same typed helper. Do not CAS
a managed interface variable. GetInstance converts the published object to
IOpenSSLLoader, giving each caller its normal interface reference. The slot's
separate ownership reference keeps the object alive after callers release theirs.
FPC compilation remains unverified.

The registries remain class variables: FLoadActions in the base loader, and
FCryptoLoaders/FSSLLoaders/FUnloaders in the dynamic loader. Registration obtains
the published instance's FRegistrationLock, holds that same lock for the update,
then releases it. There is no separate lazy registration-lock allocation.

Lifecycle action registration first acquires FLoaderLock and requires the
internal state to be exactly lsNotLoaded. Other states, including failure,
raise ETaurusTLSLoaderError using RSOSSLLoaderActionRegistrationInactive.
FRegistrationLock is acquired only after this check, following the lifecycle
operation's lock order. A concurrent Load cannot skip a newly accepted action;
action registration from a lifecycle callback is rejected. No automatic
catch-up initialization is performed for late actions. After failure, explicit
Unload resets the state before registration is permitted.

Unit initialization calls EnsureInstance and preserves an earlier winner and all
early registrations. Lifecycle callback iteration and dynamic symbol binding/reset
use that winner's registration lock. The existing lifecycle lock continues to
serialize Load/Unload independently.

At unit finalization, atomically read the existing singleton without creating
one, then call its full Unload operation while the slot remains published.
Cleanup callbacks can therefore query the same singleton, observe non-ready
state and call native routines before symbol reset and library release. Catch
cleanup exceptions at this finalization boundary after Unload has attempted
all cleanup stages. Then atomically exchange the singleton slot with nil,
release its ownership reference and free the class-owned registries.

TaurusTLS finalization independently calls GetOpenSSLLoader.Unload directly
before the loader unit finalizes, with the same exception containment.
Repeated cleanup is safe. Loader-only applications therefore also receive the
full lifecycle cleanup rather than relying on destructor-level handle release.
Explicit public Unload calls continue to propagate cleanup errors.

Finalization is not a concurrent shutdown API: applications must stop all
callers and retire active crypto objects first. Callback owners must remain
valid until their cleanup has run; registration does not retain them.
No singleton replacement or public reset operation is introduced.

Small nonvirtual helpers and forwarding routines use
{$IFDEF USE_INLINE}inline; {$ENDIF}, including singleton forwarding, the CAS
helper, atomic state accessors and metadata forwarders. Inlining is a compiler
optimization request; it does not change synchronization or lifetime rules.
EnsureInstance retains the complete candidate construction/publication path.

### Failure handling, circuit breaker, and callback rollback

If library loading fails at any point (validation error, OpenSSL configuration failure, or an exception inside an `osaLoad` callback):
1. The loader captures the OpenSSL error details before executing teardown.
2. Internal `UnloadInternal(False)` executes; public recursive Unload is not used:
   - Dispatches `osaUnload` in reverse order strictly to callbacks that already executed `osaLoad` (`FLastLoadActionIdx downto 0`). Callbacks that failed or have not yet run are not dispatched `osaUnload`.
   - Executes header unloaders (`FUnloaders`) in dynamic mode.
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

The shared resource-string unit also owns loader lifecycle and native
initialization failure messages. TaurusTLSLoader declares no local resourcestring
section. The unused custom-memory-hook code and its allocator-only failure
message have been removed.

Do not collapse these exceptions into false or suppress them at the loader boundary. The FIPS mode backend must preserve configuration exceptions while reporting provider/policy enablement failures through its existing Boolean/diagnostic contract.

Tests must assert the specific exception class and filename for invalid/missing/directory paths and malformed/unreadable/module-failing configuration, with configuration failures isolated in fresh processes.

For an explicit file, do not use IGNORE_ERRORS, IGNORE_RETURN_CODES or IGNORE_MISSING_FILE. Do not add SILENT or rewrite the customer's configuration. If configuration deliberately soft-loads a provider, successful file loading still does not establish FIPS readiness; FIPS validation must catch a missing/unusable provider.

ConfigFile is a full OpenSSL configuration with openssl_conf/provider/algorithm sections and references to installation data where appropriate. A standalone fipsmodule.cnf is not assumed sufficient. Do not run fipsinstall or synthesize integrity values.

`CONF_get1_default_config_file` is diagnostic/discovery support only. Its caller owns the returned string and frees it with `OPENSSL_free`. It does not select or change configuration. `CONF_modules_load_file_ex` is the chosen explicit loader; do not redundantly call both it and `OSSL_LIB_CTX_load_config` for the same file. [Configuration loading API](https://docs.openssl.org/3.0/man3/CONF_modules_load_file/).

## 2A. Unified runtime and metadata implementation

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

Implemented metadata members of IOpenSSLLoader:

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
private TTaurusTLSRuntime class. The implemented sequence is:

1. Publish internal lsLoading; load and bind dynamic libraries, or validate the
   linked OpenSSL version.
2. For an explicit file, validate the path, call
   OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, nil), then strictly apply the
   selected file with CONF_modules_load_file_ex(nil, filename, nil, 0). For empty
   input, call OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, nil), then discover
   the default filename. Failed crypto initialization raises ETaurusTLSLoaderError.
3. Record the effective filename and resolve its directory at load time; public
   effective configuration and metadata remain hidden until readiness.
4. Call OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, nil). A missing dynamic
   routine or failed initialization raises ETaurusTLSOpenSSLInitFailed.
5. Run registered osaLoad actions, including TaurusTLS runtime resources.
6. Capture remaining metadata and publish lsLoadedReady after successful completion.

Required linked builtin registration must precede configuration. That phase is
not implemented by this sequence; existing osaLoad actions run too late to
provide it. Its mechanism remains a separate design decision. Do not invent a
public pre-initialization API without review. OpenSSL initialization options may be fixed by the first caller;
external initialization and static reloads cannot be treated as a fresh process.
No OPENSSL_cleanup in a reloadable lifecycle.
[Initialization semantics](https://docs.openssl.org/3.0/man3/OPENSSL_init_crypto/).

OpenSSL uses its own memory management. TaurusTLS does not install custom
allocation callbacks.

### Private TaurusTLS runtime class

TTaurusTLSRuntime owns TLS initialization resources through class vars and
class methods in the TaurusTLS implementation section. Keep TaurusTLS
socket/Indy dependencies out of TaurusTLSLoader. Register a load/unload action
whose method is compatible with the existing procedure-of-object signature;
use an ordinary class method where a static method would lose the method pointer.

The class owns the locks still required by TaurusTLS info/level/password/verify/
SNI callbacks. It does not publish another ready Boolean or acquire a separate
global lifecycle lock. SSLIsLoaded and its internal uses have been removed;
readiness comes from the loader. Modern OpenSSL supplies its own threading
support. The old CRYPTO_num_locks/locking/thread-ID setup, corresponding cleanup
and obsolete explicit error-string setup have been removed from this path.

The action cleans up partial allocations before propagating its own failure,
because the loader only unwinds completed actions. Successful actions release
resources in osaUnload before native unbinding. Internal callbacks never call
public Load/Unload. Review action registration lifetime and unit/package
finalization so callbacks never target finalized resources.

### Compatibility wrappers and migration

Retain these routines as deprecated forwarding wrappers, inline where supported.
Compiler deprecation messages name the corresponding IOpenSSLLoader member.
Use GetOpenSSLLoader to obtain the interface for new code:

| Routine | Forwarding expression/operation |
|---|---|
| LoadOpenSSLLibrary | GetOpenSSLLoader.Load |
| UnLoadOpenSSLLibrary | GetOpenSSLLoader.Unload |
| OpenSSLVersion | GetOpenSSLLoader.Version |
| OpenSSLDir | GetOpenSSLLoader.ConfigDirectory |
| OpenSSLModulesDir | GetOpenSSLLoader.ModulesDirectory |
| OpenSSLEnginesDir | GetOpenSSLLoader.EnginesDirectory |

This forwarding contract is implemented and retained for compatibility.
LoadOpenSSLLibrary remains an explicit application initialization entry point,
but new callers should use IOpenSSLLoader.Load. Internal context initialization
and unit finalization call the loader directly. Compatibility tests retain
wrapper calls with deprecation warnings suppressed only around those routines.
One Unload globally tears down
the runtime even after multiple successful Load calls; no reference counter is
introduced. Metadata wrappers are passive and return empty before readiness.
OpenSSLDir now means the directory containing ConfigFile; document this change.

Audit internal context constructors and all other implicit Load calls in the
consumer review. They must not be used to conceal an initialization
requirement. Application shutdown must retire live objects/operations first.

### Remaining design and review work

- Define pre-configuration builtin registration and reconcile existing provider
  callbacks with configuration-only activation.
- Complete remaining consumer implicit-Load compatibility decisions. NTLM hook
  separation, algorithm checks and LM/NT response corrections are committed;
  NTLMv2 RC4, non-ASCII LM encoding and dependency-isolation validation remain.
- Resolve FIPS reporting and policy separately.
- Keep dedicated competing-first-publication stress separate from concurrent
  lookup/registration fixtures, which start after unit initialization.
- FPC compilation remains unverified.

## 3. Discovery, ownership and legacy support

Decision confirmed 2026-10-24: provider activation is controlled by `openssl.cnf`.
The loader applies configuration; `activate = 1` activates selected providers.
The recently discussed unified activation API and NTLM loader-action alternative
are superseded. No explicit provider handles or provider reference counter are
added to the loader.

OpenSSL resolves module paths and parameters. Do not restore ProvidersPath, parse
provider sections in Delphi, set hidden paths or mutate customer environment.
Empty ConfigFile requests standard configuration; it does not disable config.
Omit `activate` to avoid explicit activation by a config across supported versions:
older OpenSSL 3.0 treats presence as activation, unlike modern Boolean handling.
[Provider configuration](https://docs.openssl.org/4.0/man5/config/#provider-configuration).

Retain `TaurusTLS_LegacyProviders` for archive linking and builtin registration,
using the existing artifact-specific `STATICLOAD_OPENSSL` guard and corrected ABI.
It is unnecessary for dynamic/startup-shared config-based module activation.
Remove the existing manager's default/legacy acquisitions, retained handles,
release calls and activation in initialization/finalization or osaLoad/osaUnload.

Builtin registration is implemented once in archive-only unit initialization,
before application Load/configuration. Checked OSSL_PROVIDER_add_builtin stores
the entry point without loading config or activating it; failure raises a crypto
exception at startup. No new loader phase/API, provider handles or finalizer.
Static unload/retry does not repeat registration. Applications must establish
this ordering before external default-context configuration/crypto use and avoid
conflicting cross-module same-name registration. Keep archive references out of
the core loader and NTLM unit; isolated artifact execution remains pending.

Configuration owns its activation references. Multiple consumers fetch/free their
own algorithm objects; they do not acquire another provider reference merely to
use it. Never release a configuration-owned/borrowed reference. Native reference
counting is not a dynamic-library lease or a guarantee of immediate teardown.
Static Unload and loader rollback do not promise a pristine default context.

UT.LegacyProviders now imports the production unit only in archive builds.
Shared builds retain provider tests without the wrapper. Positive fixtures own
temporary provider config; a runtime-shared negative fixture verifies omission of
activate leaves legacy/MD4/DES unavailable. Archive absence is still a fresh-process
acceptance case. Audit runtime-package/transitive integration separately; the
existing Windows runtime package still contains the now-passive legacy facade.

Review the existing legacy status facade against ready configured provider
availability; provider presence alone does not establish usable MD4/DES.
Detailed boundaries and pending cases: [Legacy DDD](legacy_providers_DDD.md).

### Implemented NTLM integration

Runtime commit `95e7bd2` assigns stable callbacks once during initialization.
Neither Load nor Unload reassigns them. NTLM has no dependency on TaurusTLSFIPS,
TaurusTLS_LegacyProviders or Indy's hash backend; IdFIPS remains for declarations
and policy. LoadNTLMLibrary only checks readiness.

Availability checks loader readiness, Indy policy and MD4/DES-ECB fetches using
current default-context properties. A negative probe preserves earlier native
errors. LM requires DES-ECB; NT requires MD4 and DES-ECB.

NT uses EVP MD4 over UTF-16LE. Corrected DES key expansion/parity, no padding,
exact output lengths and three response block offsets are covered by tests.
LM retains platform-default encoding and 14-byte truncation. Non-ASCII OEM policy
and NTLMv2 RC4 are separate work. Operations validate readiness and buffers, free
native objects, and preserve prohibiting native/Indy selection policy.

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

Readiness hooks first check loader state and never initialize/reset the loader.
LoadNTLMLibrary is status-only; NTLM algorithm/response guards are implemented.
An active FIPS provider does not imply FIPS algorithm selection. Final FIPS/hash
reporting, broader fallback/HMAC enforcement and setter semantics remain pending.

Legacy activation does not override FIPS property selection or make MD4/DES
acceptable under an enabled FIPS policy. Do not solve that conflict by weakening
default properties. Static FIPS remains unsupported within this design.

HMAC migration to modern EVP_MAC, detailed hook enforcement, FIPS implementation
provenance checks and any future policy API remain separate reviewed work.
No loader success, provider activation or test result establishes certification.

## 5. Tests and review gates

Use existing DUnitX fixtures and register with TDUnitX.RegisterTestFixture.
Loader/lifecycle fixtures use manual TOsslBaseFixture and control initialization
explicitly. TOsslAutoloadFixture supplies automatic setup/teardown for fixtures
that require it. SetupFromCmd reuses parsed settings without loading; Boolean Load
preserves exceptions. No TOsslLoader wrapper/load counter is required.
Use controlled temporary configurations and failure-safe restoration; isolate
process-wide initialization options or provider-policy scenarios in fresh
processes where necessary.

Current runner options are -osp and optional -oscp; -osmp is retired. Preserve
test-only environment isolation. Do not require external OPENSSL_CONF setup.
The positive NTLM fixture (test commit 0b42e6a) generates a unique temporary
non-FIPS default/legacy config before loading, restores loader settings and
deletes its files after unloading, including setup-failure cleanup. It uses
a matching deployed module or linked registration and needs no external -oscp.
Its neutral test properties must not become customer FIPS defaults.
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
| Providers | Config-only activation; optional archive registration before config; dynamic wrapper dependency removed and fresh-process absence/activation/isolation cases verified |
| Late lifecycle action registration | Rejected outside lsNotLoaded without changing state or the action registry |
| Unit finalization | Full unload runs with the singleton still published; cleanup errors do not escape the unit finalizers |

The developer reports no new failures or regressions on Win32, Win64, Linux64
and OSX64, including after the conditional-inline updates. Fresh Windows runs
recorded 85/85 Loader tests on each Windows target and 454/454 Win64 regression
tests with LegacyProviders excluded; all other result counts were zero. No
additional platform totals are inferred. These results do not establish
cold-start CAS contention coverage or completion of deferred provider/FIPS work.
Keep the known InputRanges common-name failure on Linux/macOS separate from
regressions. FPC remains unverified.

After the registration and finalization safety changes, fresh Win64 runs passed
89/89 Loader tests and 458/458 regression tests with LegacyProviders excluded;
both runs reported zero ignored, leaked, failed or errored tests. The developer
reports unchanged results across all platforms. No additional platform totals
are inferred. Loaded loader-only application termination in a separate process
remains unverified by these fixture runs.

Latest pre-provider-refactor developer reports: both Windows 522/522, Linux
509/510 and macOS 472/473. Non-Windows NTLM inclusion/exclusions and remaining
failure identities were not supplied; counts alone do not establish complete
NTLM coverage. These runs do not validate the pending provider refactor.
