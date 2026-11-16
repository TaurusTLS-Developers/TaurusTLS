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

FConfigFile and FEffectiveConfigFile already separate input from effective
configuration. After explicit configuration or native discovery, any nonempty
effective filename is expanded against the load-time working directory. The
cached filename and ConfigDirectory therefore remain stable if that directory
changes later. An empty discovery result remains empty; the configured input
is preserved. This is metadata normalization after native configuration, not
a change to discovery precedence, provider activation, or library-relative paths.

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
