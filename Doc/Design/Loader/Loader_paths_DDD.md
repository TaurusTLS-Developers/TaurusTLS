# OpenSSL library discovery and effective settings — DDD

See [the HLD](Loader_paths_HLD.md) for the public contract.

## Storage and locking

TOpenSSLDynamicLoader retains FOpenSSLPath and FSSLLibVersions as configured
inputs. FLoadedPath and FLoadedSuffix belong to the current load attempt.

Both library getters acquire FLoaderLock. They expose effective fields only
when IsLoaded is True. During load, unload, and rollback callbacks they return
configured inputs, matching ConfigFile's existing publication rule.

The effective fields may be populated before header binding, but readiness
remains False until all load actions and metadata capture succeed. They cannot
be observed as ready metadata during a failed attempt.

## Discovery

FindLibrary returns a handle and the successful candidate suffix. Its search
order remains unchanged: non-Windows builds try the unversioned filename first,
then configured suffixes; Windows follows the configured list. A quoted empty
candidate remains supported.

LoadAndVerifyLibraries stops immediately when crypto discovery returns no
handle. It validates crypto before attempting SSL. It derives the directory
from LibraryFileName, then constructs only one SSL filename with that directory
and suffix. There is no second candidate search for SSL.

LibraryFileName uses a growing GetModuleFileName buffer on Windows. On POSIX,
dladdr receives a symbol owned by the requested module: OpenSSL_version_num
for crypto and SSL_new for SSL. The latter is essential because looking up a
crypto symbol through SSL may identify its dependency instead. realpath
resolves symbolic links before directory comparison. The POSIX buffer is 4096 bytes. Delphi passes it through a MarshaledAString
variable; FPC uses PAnsiChar. This avoids an invalid cast of the fixed array
when calling realpath.

Windows compares directory names without case sensitivity; POSIX compares
canonical directory names exactly. Failure to obtain a usable module filename
raises a loader error instead of guessing from the configured search path.

## Error and cleanup flow

All handles remain in the existing FLibCrypto and FLibSSL fields, so the base
Load exception boundary retains responsibility for rollback and failure state.
The implementation does not create a second cleanup path.

FreeDynamicLibraries clears effective path and suffix fields, then releases SSL
before crypto. Configured inputs are never changed by discovery or cleanup.
The existing callback rollback, header reset, and metadata cleanup stages remain
in force.

New resource strings identify unavailable module paths, matching SSL load
failure, and a resolved directory mismatch. Library-pair errors use
ETaurusTLSLoaderError and preserve the original exception through rollback.

## Configuration

FConfigFile and FEffectiveConfigFile separate configured input from the applied
configuration. A selected explicit or discovered filename is expanded against the
load-time working directory before checking or applying it. Only a successful
file application populates effective metadata. The cached path and ConfigDirectory
remain stable if the working directory changes later. Configured inputs are never
replaced by discovery or by skipping a missing optional file. Provider and engine
paths are not rebased to the library directory.

## Tests

The dynamic lifecycle fixture captures a working installation, unloads it, and
retries using absolute or relative input and a candidate list containing a
missing entry. Ready getters must expose the chosen installation; unload must
restore the full inputs; a subsequent load must work.

The mixed-suffix test copies the working crypto and SSL binaries into a temporary
directory but gives SSL a different candidate suffix. Loading must raise, leave
headers unbound, preserve configuration, and retain the failure circuit breaker.
Adding the correctly named SSL file and explicitly unloading must permit recovery.

The existing crypto-only deployment test now expects a loader exception.
Existing configuration-publication and callback-mutation cases remain applicable.

A UNITTEST-only filename hook models the OS reporting SSL from another directory
after an absolute request. The test checks the precise mismatch exception,
unbound headers, preserved inputs, failure state, and recovery after reset.
The hook is removed in a finally block. Production builds contain no hook.
Actual OS reuse rules and Linux symlink behavior still require native platform
validation; the modeled result tests the rejection policy, not those OS rules.

## Fixture lifetime and test-only reset

TOsslAutoloadFixture loads once in SetupFixture and unloads in TearDownFixture.
Derived cases clean up their own objects without resetting this shared runtime.
Lifecycle fixtures retain explicit per-case control of loading and cleanup.

ResetOpenSSLLoaderForTests is compiled only with UNITTEST. It uses the existing
singleton and normal unload path, restores empty configured paths and the default
suffix list, and releases spare diagnostic and action-list storage. It preserves
unit registrations and existing interface identities. Each test must remove its
own temporary registrations and retire native consumers before resetting.

Resource-string and RTL warm-up runs once from the base fixture's class
constructor, before per-case memory snapshots. It is not part of library loading.
These measures reduce first-use accounting noise; they do not establish that
remaining memory reports are harmless.

## Validation status — 2026-11-15

The maintainer reported native runs passing on macOS64 (611/611), Linux64
(658/658), and Windows64 (670/670) during the path refactoring. Later additions
raised the Windows suite to 671 cases. Subsequent Windows runs still produced
intermittent memory reports; the earlier reports of dozens of memory-accounting
failures are historical and no longer describe the current fixture setup.

Repeated-load diagnostics reproduced declining Windows thread-local-storage
slot counts with OpenSSL 4.x outside TaurusTLS. A reported 4.1 run failed at cycle
272 with no slots available; 3.6.5 completed 600 cycles with stable final counts.
The maintainer subsequently reported that rebooting the VM resolved the suite
initialization failures, including a 4.x suite run. This does not establish that
the separate repeated-load retention has been resolved.

Regression testing will use OpenSSL 3.x for now. Track the repeated-load issue at
[OpenSSL #33756](https://github.com/openssl/openssl/issues/33756). The original path refactoring did not add native cleanup. The extension below adds global cleanup for dynamic OpenSSL 4+.
The standalone diagnostic experiments are separate from the loader implementation.
## OpenSSL 4 cleanup extension

CaptureMetadata stores the raw native version in FVersionNumber. ClearMetadata
resets it to zero. GetVersionNumber holds FLoaderLock and exposes the cached value
only when ready. TTaurusTLSLoader delegates its VersionNumber property to the
same interface. Consumers must rebuild against the extended interface.

LoadAndVerifyLibraries uses the raw version for cleanup selection, separately
from the shifted header-binding version. After identity and version validation,
versions >= $40000000 resolve OPENSSL_cleanup directly from FLibCrypto into
FCleanup. A missing export raises ETaurusTLSAPIFunctionNotPresent. Resolution
precedes SSL acquisition and header binding, covering failures in those stages.
Cleanup therefore does not depend on a header variable that a test may replace
or that rollback has not yet bound.

DoUnload runs RollbackLoadActions, then CleanupOpenSSL, then UnbindHeaderSymbols,
then FreeDynamicLibraries, preserving finally boundaries between stages.
CleanupOpenSSL clears FCleanup before invoking its saved procedure pointer.
FreeDynamicLibraries also calls this idempotent helper as a fallback before
releasing SSL and crypto. No OpenSSL calls follow global cleanup. Public metadata
is hidden throughout unloading and cleared by the common unload boundary.

3.x never assigns FCleanup. The static loader does not use this dynamic cleanup
path. No OPENSSL_thread_stop call is introduced; global unload still requires
all consumers and their threads to have completed their native work.

Life_VersionNumber compares the property with OpenSSL_version_num(), verifies
zero before/after readiness, and repeats load/unload three times. Metadata-empty
callback and rollback checks also include VersionNumber. Existing initialization
failure and library-pair rollback cases exercise cleanup before retry.

Win64 Debug loader-category validation: 257/257 passed against both OpenSSL
3.6.5 and 4.0.2, with zero reported leaks, failures, or errors.
Win32 Debug loader-category runs also passed 257/257 on both 3.6.5 and 4.0.2,
with zero reported leaks, failures, or errors.


## Relative-directory correction

FindLibrary expands a nonempty FOpenSSLPath once into local LSearchPath, using
TPath.GetFullPath and IncludeTrailingPathDelimiter when HAS_UNIT_IOUtils is
available (Delphi 2010+ and FPC 3.2.4+); older compilers use ExpandFileName.
It uses LSearchPath for every
candidate; an empty value remains empty. This avoids passing relative filenames
to Windows, where the relative part can be appended to DLL search directories.
FOpenSSLPath is not modified. SSL continues to use crypto's actual directory.

The relative settings test changes to the installation's parent directory and
asserts that its input is relative. This avoids ExtractRelativePath returning
an absolute path when the executable and installation are on different drives.
The original working directory is restored after unloading in a finally block.


LSearchPath is resolved before any candidate is attempted and is not recalculated
inside the suffix loop. Later working-directory changes cannot redirect later
crypto candidates. SSL discovery remains anchored to the resolved crypto module.
This reduces the working-directory race window; it does not synchronize external
SetCurrentDir calls or make the initial relative-path resolution independent of
the process working directory. No process directory is changed by the loader.


## RequireConfigFile implementation

FRequireConfigFile defaults to False. Getter and setter hold FLoaderLock. Identical
assignments remain safe; changes are rejected while loading, ready, unloading,
or retaining a crypto handle, consistently with ConfigFile. Unload preserves
the flag; ResetOpenSSLLoaderForTests restores False.

The common Load template rejects a required empty filename within its existing
failure/rollback boundary before DoLoad. ApplyConfiguration normalizes a nonempty
filename and rejects directories. If the file does not exist, the required policy
raises RSOSSLConfigFileNotFound; the optional policy clears the local filename
and initializes without configuration. FConfigFile is never changed by this skip.
An existing malformed configuration still fails under either policy. Effective
metadata records the selected explicit file or the default discovery result.

The platform item setters reject enabling RequireConfigFile with an empty filename,
and clearing the filename while required. During streaming they defer this check
to collection Validate, called before automatic loading even with LoadOnStart=False
or in the designer. Assign copies the filename and policy. Runtime access through
TTaurusTLSLoader delegates to the shared interface.

Tests cover the complete empty/valid/missing/malformed/directory policy matrix,
preflight ordering, failed-state recovery, runtime and callback mutation rules,
reset, component sharing, streaming and assignment, and rejected design-time edits.
Existing missing-file failure tests explicitly enable RequireConfigFile.


Revised-policy validation: full Win64/OpenSSL 4.0.2 and Win32/OpenSSL 3.6.5 runs
passed 692/692, with zero reported leaks, failures, or errors. Native Linux and
macOS runs require renewed validation after this policy correction.


## Verified configuration selection

ApplyConfiguration initializes crypto once with OPENSSL_INIT_NO_LOAD_CONFIG.
It starts with FConfigFile and calls SslGet1DefaultConfigFile only if that configured
input is empty. Discovery uses OpenSSL's own environment; its allocated return
value is freed through SslFree. The chosen nonempty filename is normalized with
TPath.GetFullPath (or the older-compiler fallback), checked for directories and
existence, then applied with SslModulesLoadFileEx and flags 0. Existing invalid
files therefore raise instead of relying on automatic discovery's ignore flags.

A missing optional candidate clears only the local filename. No second filename
is selected. FEffectiveConfigFile and ConfigDirectory are populated only after
successful file application; they remain empty when no file was applied. Explicit
missing inputs remain preserved in FConfigFile through readiness and unload.
Required empty input is still rejected by the common preflight before DoLoad.

The dynamic discovery hook tests empty, valid relative, missing, malformed, and
directory candidates. No-fallback cases supply valid and malformed default files,
select a different missing explicit file, and assert that discovery was never
queried, automatic loading was disabled, and effective metadata is empty. The
preserved configured input is checked after unload. Normal discovery expectations
now exclude nonexistent candidate filenames.

Final no-fallback validation: full Win64/OpenSSL 4.0.2 and Win32/OpenSSL 3.6.5
runs each passed 697/697 with no reported leaks, failures, or errors. Native
macOS and Linux validation is pending for this configuration-loading change.

An empty effective filename means this load applied no configuration file. It
does not erase configuration retained by an already-initialized native runtime,
including statically linked builds; their existing lifecycle rules still apply.


## Delphi Object Inspector validation

For Delphi 2010+ the design-time registration unit installs dedicated editors for
TTaurusTLSPlatformSetting.ConfigFile and RequireConfigFile. They translate only
ETaurusTLSConfigFilePathError into ETaurusTLSDesignPropertyError, a descendant of
EDesignPropertyError (ENonAIRException). Expected rejected edits can therefore use
the IDE's normal validation reporting rather than its incident reporter.

The filename editor wraps SetValue and Edit. The Boolean editor wraps SetValue,
Edit, and the checkbox MouseUp path. Since the inherited MouseUp is nonvirtual,
the descendant reimplements ICustomPropertyMessage so checkbox requests reach its
translation code. Other mouse methods and drawing remain inherited.

The runtime package does not reference designide, ToolsAPI, or IDE exception
classes. Its guards and typed runtime exceptions remain unchanged. Setter checks
still happen before modifying fields, and unexpected exceptions are not translated.
Older Delphi registrations remain unchanged. Lazarus uses the adapter described below.

The Delphi Win32 Release design-time package compiled and was regenerated.
Object Inspector verification requires repeating both invalid edit operations
with this updated package loaded.


## Lazarus package and property editors

The FPC registration path supplies filename and Boolean editors derived from
TFileNamePropertyEditor and TBoolPropertyEditor. SetValue and Edit translate only
ETaurusTLSConfigFilePathError into ETaurusTLSLazarusPropertyError, a descendant of
Lazarus's standard EPropertyError. Checkbox changes reach SetValue in Lazarus;
the Delphi-specific ICustomPropertyMessage adapter is not used. Runtime mutation
guards and exception classes are unchanged.

The design-time LPK explicitly requires IDEIntf and LCL, and lists the About dialog
LFM resource. The VersionManager template carries the same dependencies and form
entry so regeneration preserves them. Lazarus's generated package Pascal source
remains generated by lazbuild.

Validation: a clean build rebuilt runtime and design-time packages successfully
with Windows64 Lazarus/FPC 3.2.2. The updated design package then rebuilt with the
new editors successfully. Activating installed editors requires rebuilding the
Lazarus IDE; interactive property validation remains to be checked there.

## Lazarus collection capacity

There are two independent Add paths. The modeless collection editor invokes
Collection.Add from its action handler after the property editor's Edit method
has returned. The Object Inspector tree creates its own Add Item context menu
and also invokes Collection.Add directly. A custom collection dialog alone does
not protect that context menu; catching exceptions around Edit protects neither
later action.

For FPC, TTaurusTLSPlatformSettings implements the CORBA contract used by
Lazarus Controls.IObjInspInterface. The nonvisual loader declares the same GUID,
method order and Boolean signatures locally, avoiding an LCL dependency. AllowAdd
returns False when Count reaches the number of TTaurusTLSPlatform values.
Lazarus queries this on the collection when building its context menu, omitting
Add Item when False. The same collection is queried when an item is selected.
AllowDelete returns True, preserving the previous default deletion policy.
These queries do not replace CheckMutable or NewTarget's overflow validation.

TTaurusTLSPlatformSettingsProperty is registered only for TTaurusTLSLoader's
PlatformSettings property. It opens a separate descendant of Lazarus's existing
TCollectionPropertyEditorForm, retaining selection, designer notifications,
delete and reorder behavior. The form replaces only the Add action handlers.
Both OnUpdate and AddItem use the collection's Object Inspector interface for
capacity. OnUpdate disables Add at capacity; AddItem checks again before calling
the inherited Add handler. An attempt at capacity produces an informational
message instead of invoking Add. The disabled action's hint explains that every
platform already has settings. Deletion makes Add available again.

The application owns the form; destruction clears the cached editor pointer, and
the inherited form removes designer hooks. Lazarus's shared editor for unrelated
collections is untouched. No runtime exception is suppressed: direct collection
mutation still uses CheckMutable and NewTarget's existing capacity validation.
The interface adapter is FPC-only; Delphi collection behavior is unchanged.

Tests/Lazarus/TaurusTLS.PlatformSettings.Menu.lpi queries the collection through
the actual LCL Controls.IObjInspInterface declaration and the same string GUID
query used by the Object Inspector. It verifies interface compatibility, capacity,
delete/re-add, unchanged direct-overflow rejection, and the runtime edit guard.
It requires no OpenSSL libraries. This specifically covers the menu path omitted
by the first collection-dialog-only implementation.

Validation: the runtime and design-time packages rebuilt successfully with
Windows64 Lazarus/FPC 3.2.2. The standalone regression program built and passed.
After rebuilding the installed Lazarus IDE, verify Add Item disappears from the
Object Inspector tree context menu at six entries, for both collection and item
selection, and returns after deleting one. Also check the collection dialog Add
button, close/reopen the editor, delete the owner, and verify unrelated collection
editors retain standard behavior. The user confirmed that running the rebuilt
IDE executable resolves the reported Add Item issue; the additional interactive
checks above remain a manual checklist.
