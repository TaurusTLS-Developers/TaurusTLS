# OpenSSL library discovery and effective settings — HLD

## Purpose

Load libcrypto and libssl as one installation. Keep the application's search
settings intact while reporting the installation actually in use.

## Public behavior

| Property | Inactive, failed, or load/unload callback | Ready |
| --- | --- | --- |
| OpenSSLPath | Configured search directory | Absolute directory of the loaded libraries, with trailing delimiter |
| SSLLibVersions | Configured candidate list | Suffix selected when loading crypto; empty means the unversioned candidate |
| ConfigFile | Configured filename | Absolute effective explicit or discovered filename, or empty if discovery returns none |

The component delegates to the same singleton interface. Static builds continue
to return empty library paths and suffixes and ignore their setters. ConfigFile
works in both linking models.

Reading a property never initializes OpenSSL. A setter always compares against
the configured input, including when a getter exposes an effective value.
Assigning that same input remains a no-op during loading, readiness, and cleanup.
Other changes are rejected during loading, readiness, unloading, or while a crypto
handle is retained. Changing settings in a failed state does not clear that state;
an explicit Unload is still required before retrying.

## Loading policy

1. Discover libcrypto using the configured directory and ordered suffixes.
   An empty directory retains the platform's normal library search.
2. Stop if crypto cannot be loaded. Do not attempt SSL.
3. Check crypto's identity and supported version.
4. Obtain crypto's actual module directory from the operating system.
5. Request libssl by absolute filename in that directory, using the same suffix.
6. Check the directory of the resulting SSL module. A different directory is an
   error, even when the requested filename was absolute.
7. Bind headers, apply configuration, initialize SSL, and run lifecycle actions.
8. Publish readiness. Only now do getters expose effective library settings.

A missing matching SSL library, unresolved module location, or directory mismatch
raises ETaurusTLSLoaderError. Missing crypto retains the existing False result.
A failure releases acquired handles and blocks retries until explicit Unload.

## Lifetime and compatibility

Unload and rollback clear effective library settings but preserve configured
inputs. A later Load performs discovery again using those inputs.

Applications that previously combined libraries from separate directories or
different suffix candidates are deliberately rejected. This policy reduces
accidental mixing; it is not a general guarantee about every dependency loaded
by the operating system. Deployment directories still need appropriate access
permissions.

OpenSSL configuration behavior is unchanged. Explicit ConfigFile overrides
default discovery. A discovered default filename does not prove that the file
was read. Provider and engine paths are not rebased to the library directory.

## Validation

Exercise Windows32/64 and Linux64 dynamic builds, plus a static build for
unchanged behavior. Cover absolute and relative input paths, suffix selection,
reload, missing crypto, missing matching SSL, mixed suffix rejection, different
resolved directories, and failure rollback. Preserve existing callback and
configuration-publication tests.

## Test runtime lifetime

Fixtures that use an initialized OpenSSL runtime load it in SetupFixture and
unload it in TearDownFixture. Each case still releases its own connections,
contexts, and callback state. Tests of the loader lifecycle deliberately control
Load and Unload within the case and restore their settings afterward. Test
isolation does not require unloading the native libraries after every case.

Use OpenSSL 3.x as the current regression-test baseline. Repeated native DLL
load/unload cycles have shown Windows thread-local-storage slot retention with
4.x; this is tracked in [OpenSSL issue #33756](https://github.com/openssl/openssl/issues/33756).
This test policy does not change the loader's supported version checks.