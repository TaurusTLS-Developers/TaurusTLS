# Explicit OpenSSL loading migration

TTaurusTLSContext construction no longer loads OpenSSL. Configure and load once
before opening TLS connections, enabling listeners, or calling InitContext.
This applies to dynamic and static builds. Readiness failure raises
ETaurusTLSLoaderError before native context calls.

For programmatic startup:

~~~pascal
uses TaurusTLS, TaurusTLSLoader, TaurusTLSExceptionHandlers;

Loader := TTaurusTLSLoader.Create(nil);
try
  Loader.OpenSSLPath := ApplicationOpenSSLDirectory;
  Loader.ConfigFile := ApplicationOpenSSLConfig; // empty selects OpenSSL defaults
  if not Loader.Load then
    raise ETaurusTLSLoaderError.Create('OpenSSL startup failed');
  // Now create/activate TLS consumers.
finally
  Loader.Free; // Does not unload the shared runtime.
end;
~~~

The two application variables above are application-supplied paths, not new
library API. Existing applications may instead call GetOpenSSLLoader.Load
directly after configuring the singleton. Both entry points share state.

For a streamed component, add exact-target items to PlatformSettings. The collection
starts empty; missing targets and blank fields select loader defaults. The scalar
OpenSSLPath, SSLLibVersions and ConfigFile properties are public shared runtime properties,
and are no longer published or streamed.
LoadOnStart defaults to True and loads from Loaded after properties are read.
It never loads in the designer. Automatic False results raise ETaurusTLSLoaderError;
other loader exceptions propagate unchanged. Creating a component in code does
not invoke Loaded: call Load explicitly after configuration.

Keep connections and servers inactive in streamed forms/data modules. Establish
application startup order explicitly: configure/load first, then enable consumers.
If a consumer creates native TLS state during streaming, disable that behavior
and activate it after startup loading. Placing components in a particular order
does not establish ordering across owners.

Runtime scalars configure the singleton directly; all components share one runtime. Repeated
successful Load returns True without acquiring a lease. One Unload cleans up
globally. Destroy consumers and finish their operations before explicitly calling
Unload; do not unload from a component destructor. Failed loads block retries
until explicit Unload resets the failure state. Correcting properties alone does
not permit a retry. Readiness queries and metadata getters do not load OpenSSL.

The class is in the existing runtime unit and registered on the TaurusTLS palette.
Rebuild/install design-time palette
integration with the project's developer package-generation tooling; this change
does not manually edit generated package lists.

## Component properties

| Property | Behavior |
|---|---|
| PlatformSettings | Published owned collection, initially empty. One entry per exact target; duplicates raise an error. |
| OpenSSLPath | Public shared library directory. Empty uses platform search; filename settings remain inert in static builds. |
| SSLLibVersions | Public shared suffix list, following the low-level loader semantics. Static builds return empty. |
| ConfigFile | Public shared filename. Empty requests standard configuration. Returns the effective filename while ready. |
| LoadOnStart | Per-component Boolean, default True. Controls automatic loading from the runtime streaming callback only. Assigning True does not immediately load. |
| IsLoaded | Read-only readiness snapshot, True only after configuration and every load action succeed. |
| State | Read-only stable state: lsNotLoaded, lsLoadedReady or lsLoadedFailed. Loading and unloading report lsNotLoaded. |
| Version | Cached loaded OpenSSL version text; empty while not ready. |
| ConfigDirectory | Directory containing the effective configuration filename; empty while not ready. Discovery does not prove that a configuration file was applied. |
| ModulesDirectory | Compiled default provider-module directory; not the configured search path or OPENSSL_MODULES value. Empty while not ready or unavailable. |
| EnginesDirectory | Compiled engine directory on OpenSSL 3; empty on OpenSSL 4 or while not ready. |
| FailedToLoad | Borrowed singleton-owned TStringList of unresolved dynamic symbols. Never free it. An empty list does not establish successful initialization. |

Collection and item edits are allowed only in the designer or during streaming.
Runtime edits raise ETaurusTLSLoaderError before modification. Public scalar
setters configure the singleton directly without loading, and changed values
are rejected while ready. Changing configuration does not reset a failure.
Metadata getters do not initialize OpenSSL. State and IsLoaded are nonblocking
snapshots; cached string metadata is read under the loader lifecycle lock.

## Lifecycle and errors

Explicit Load returns True when initialization succeeds or the singleton is
already ready. It returns False for a soft failure or a retry blocked by earlier
failure. Configuration, version-validation and callback exceptions propagate.
At design time, the component's explicit Load raises ETaurusTLSLoaderError
before delegating to the singleton. Runtime automatic loading converts False
into ETaurusTLSLoaderError rather than silently continuing startup.

Unload performs global cleanup, resets failure state and binding diagnostics,
and permits a corrected configuration to be loaded. Repeated Unload is safe
after consumers have been retired. In static builds the library code stays
linked, but readiness and registered resources still follow this lifecycle.
The component does not guard Unload against design-time calls.

For a controlled retry, first retire any application consumers, call Unload,
correct the configuration, then call Load and check its result. A ready-state
snapshot is not a lock or lease: the application must coordinate shutdown with
every user of native objects.

## Multiple components

Each TTaurusTLSLoader caches an interface reference to the same singleton.
This saves repeated singleton lookup and temporary interface reference traffic;
it does not create independent runtimes. Design settings belong to each component.
Component destruction
releases its Delphi interface reference automatically and does not call Unload.

LoadOnStart is local to each component. Setting it to False does not prevent
another component or direct singleton caller from loading. Two automatic Load
calls share an idempotent initialization, while one explicit Unload affects both.
Later streamed components leave a ready or failed singleton unchanged. There
is no comparison of component settings. Prefer one application startup owner
while allowing any number of component instances.

A retained interface reference keeps the Delphi loader object alive, not its
OpenSSL resources or unit-level registration infrastructure. Do not use retained
components after loader unit finalization.

## Startup and shutdown example

Keep the facade alive for application startup and shutdown if that matches the
application's ownership model. The following procedures stand for application
operations; they are not TaurusTLS API:

~~~pascal
Loader := TTaurusTLSLoader.Create(nil);
try
  Loader.OpenSSLPath := ApplicationOpenSSLDirectory;
  Loader.ConfigFile := ApplicationOpenSSLConfig;
  if not Loader.Load then
    raise ETaurusTLSLoaderError.Create('OpenSSL startup failed');
  try
    StartTLSConsumers;
    try
      RunApplication;
    finally
      StopAndDestroyTLSConsumers;
    end;
  finally
    // Only after every native consumer has been retired.
    Loader.Unload;
  end;
finally
  Loader.Free;
end;
~~~

StartTLSConsumers must clean up partial startup if it raises. Shutdown must also
account for consumers owned elsewhere in the application; freeing this facade
does not establish that they are gone.

For streamed forms or data modules, keep servers and connections inactive in
their saved properties. An explicit bootstrap Load before creating consumers
gives the clearest startup order. If using LoadOnStart, ensure consumers do not
create native contexts until the loader owner's streaming has finished. The
Loaded callback is not a general application-start notification.

## Platform collection editing

In the Object Inspector, open PlatformSettings and add an item for each desired
target. Set Target, OpenSSLPath, ConfigFile and optional CustomSSLLibVersions.
These collections cannot be populated by application code.

CustomSSLLibVersions is the only version-selection field. Empty uses the loader's
normal target defaults. A nonempty value supplies an ordered raw suffix list,
passed through unchanged. For example, -4-x64;-3-x64; on Win64 or .4:.3 on POSIX.
Use semicolons on Windows and colons on POSIX. A value of two double quotes
requests an unversioned candidate. Standard OpenSSL 3+ names use major versions;
there is no VersionMode, numeric version list or minor-version suffix generation.

WinARM64EC defaults use arm64 filenames from the supplied ARM64X distribution.
Stable target names can be streamed on other hosts; an enum entry does not
establish toolchain support. POSIX retains its existing unversioned-first lookup.

Existing development forms with VersionMode or LibraryVersions entries must
remove them and, if needed, put the intended suffixes in CustomSSLLibVersions.

## Runtime configuration and existing forms

Loaded applies the selected platform settings while inactive, including when
LoadOnStart=False. Empty/missing entries and blank fields select defaults.
A ready or failed singleton is not reconfigured. Set scalar properties after
streaming for runtime configuration, then call Load explicitly if needed.
Explicit Load does not reapply platform settings.

Programmatic instances use scalar properties and explicit Load. Static builds
return empty library path/suffixes and ignore filename search settings; ConfigFile
still participates in initialization. All getters describe shared state.

Old DFM/LFM scalar assignments must be removed and their values moved to the
appropriate PlatformSettings item. These scalar properties are no longer
published; old form entries are not silently imported.

Returned settings and items are owned; do not free them separately.
The component does not promise atomic multi-property configuration transactions.
Coordinate startup and retire every native consumer before global Unload.

## Supported component targets

The shared Delphi/FPC collection enum contains exactly:
tlpAndroid32, tlpAndroid64, tlpiOSARM64, tlpiOSSimulatorARM64, tlpMacOS64,
tlpLinux64, tlpWin32, tlpWin64 and tlpWinARM64EC.

MacOS64 covers both Intel and ARM; it is not split by architecture. Android32
remains available. There is no Unknown entry. Resolving an unlisted compiler
target raises ETaurusTLSLoaderError instead of choosing a misleading fallback.

Normal suffix defaults now try OpenSSL 4 and 3 only. Generated preferences reject
versions below 3.x. Custom suffix naming does not imply support for older APIs.