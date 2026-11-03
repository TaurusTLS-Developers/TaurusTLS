# Migrating from TaurusTLS 1.0 to 1.1

This migration aligns TaurusTLS with the OpenSSL 3.x/4.x APIs and their
provider-based cryptography model. OpenSSL 3 introduced providers and deprecated
older engine, FIPS-mode and low-level crypto APIs; OpenSSL 4 removes additional
legacy APIs, including engine support. TaurusTLS 1.1 uses modern EVP/provider
operations and configuration rather than the older initialization and FIPS-mode
patterns. See the [OpenSSL migration guide](https://docs.openssl.org/4.0/man7/ossl-guide-migration/).

## 1. Incompatibility: OpenSSL initialization is now explicit

TaurusTLS 1.1 no longer loads and initializes OpenSSL implicitly when a TLS
context is created. An application that previously relied on this behavior must
now initialize the shared runtime before its first TLS, hash/HMAC or NTLM
operation. Native TLS context initialization raises `ETaurusTLSLoaderError` if
the loader is not ready. The normal minimum supported OpenSSL version is 3.0.0.

### Why this changed

With OpenSSL 3.x/4.x, configuration determines which providers and algorithm
properties are available. Implicit initialization can occur before the application
has selected its library path, `openssl.cnf` file and security policy. The first
operation could then use an unintended library or default provider configuration,
including processing data before the application's required FIPS selection has
been established. This is a security-policy risk, not just a startup-order issue.

Once another component has initialized the shared runtime, changing those
settings is too late. Explicit loading gives the application a controlled point
to apply its configuration and check initialization before handling sensitive
data. Applications must also coordinate with other libraries using the same
OpenSSL runtime; TaurusTLS cannot replace policy established by an earlier user.

### What to change

Initialize through the `IOpenSSLLoader` interface's `Load` method, or through
`TTaurusTLSLoader`, which delegates to that same interface. `GetOpenSSLLoader`
is the accessor that returns the shared `IOpenSSLLoader` instance; obtaining the
interface does not initialize OpenSSL.

Configure the loader first, then call `Load` and handle False and exceptions.
Only start OpenSSL-dependent operations after success. Configuration and passive
readiness queries may be used before loading.

## 2. Migration approaches

Choose the simplest approach that fits your application. All approaches use the
same shared runtime; applications do not need a separate loader for each socket.

### Approach 1: add TTaurusTLSLoader with LoadOnStart checked

1. Place `TTaurusTLSLoader` on the startup form or data module.
2. Review its `PlatformSettings` collection. Add an entry for each deployment
   platform that needs settings different from the defaults.
3. Leave `LoadOnStart=True` checked.
4. Keep TLS clients and listeners inactive in their saved properties.
5. Start those consumers after the startup owner has finished loading.

Each `PlatformSettings` item groups the following settings for one target:

| Setting | What to enter |
|---|---|
| `Target` | The platform group to which this item applies. |
| `OpenSSLPath` | The directory containing the runtime-loaded OpenSSL libraries. |
| `ConfigFile` | The deployment's main `openssl.cnf` filename, when explicitly selected. |
| `CustomSSLLibVersions` | Optional custom library-name suffixes; normally leave blank. |

An empty collection is valid: the loader uses the normal platform library search,
standard OpenSSL configuration discovery and TaurusTLS's default library-name
suffixes. A missing target entry, or blank fields in its entry, also selects
these defaults. Empty `ConfigFile` does not disable OpenSSL configuration or
activate FIPS/Legacy by itself. More detail is in the Platform settings reference
at the end of this guide. For explicit provider policy, use approach 4.

The component calls `Load` after its runtime form/data-module properties have
been streamed. It does not load OpenSSL in the designer.

Create the startup owner before any other form or data module uses OpenSSL.
Component order does not establish initialization order across different owners.

### Approach 2: call the component's Load method

Use this when application settings must be read first, or when initialization
should wait until the user starts a network operation. Set `LoadOnStart=False`
on the streamed component, then call its `Load` before using a TLS consumer:

```pascal
uses
  TaurusTLSLoader, TaurusTLSExceptionHandlers;

procedure TMainForm.ConnectButtonClick(Sender: TObject);
begin
  if not TaurusTLSLoader1.Load then
    raise ETaurusTLSLoaderError.Create('OpenSSL initialization failed');

  TLSClient.Connect;
end;
```

`TaurusTLSLoader1` is the component on the form; `TLSClient` is an Indy client
with a TaurusTLS IOHandler assigned. For a server, use the same check immediately
before `TLSServer.Active := True`.

Check the Boolean result and let initialization exceptions reach the application's
error handler. A component created in code also needs an explicit `Load` call;
its `LoadOnStart` property is acted on during form streaming, not construction.

### Approach 3: initialize through IOpenSSLLoader

Applications without a loader component can use `IOpenSSLLoader` directly.
Obtain the shared instance with `GetOpenSSLLoader`, then call the interface:

```pascal
uses
  TaurusTLSLoader, TaurusTLSExceptionHandlers;

procedure InitializeOpenSSL;
var
  LLoader: IOpenSSLLoader;
begin
  LLoader := GetOpenSSLLoader;
  if not LLoader.Load then
    raise ETaurusTLSLoaderError.Create('OpenSSL initialization failed');
end;
```

Call this during application startup, or immediately before `Client.Connect` or
`Server.Active := True`. It must also precede any earlier hash/HMAC or NTLM use.
Repeated successful `Load` calls return True without repeating initialization.

### Approach 4: customize library paths and openssl.cnf

Use explicit `openssl.cnf` configuration when the application requires Indy's
FIPS support, LM/NTLMv1 algorithms from the Legacy provider, or algorithms from a
custom OpenSSL provider. These are OpenSSL 3.x/4.x provider configurations. This
approach also lets the application select a specific native-library directory.

The selected configuration must activate the required providers and define the
intended algorithm properties. Set `ConfigFile` to that deployment's file before
the first load; do not change provider policy separately for each connection.
FIPS and NTLMv1 use different algorithm policies, detailed in the next sections.

With a designer component, open `PlatformSettings`, add the required platform
group, and set:

| Setting | Purpose |
|---|---|
| `Target` | Platform group to which this entry applies. |
| `OpenSSLPath` | Directory used to find runtime-loaded libcrypto/libssl. |
| `ConfigFile` | Path to the main OpenSSL configuration, usually `openssl.cnf`. |
| `CustomSSLLibVersions` | Optional ordered library-name suffixes; blank uses defaults. |

Keep `LoadOnStart=True` if these design-time settings are sufficient. Otherwise,
set it False and apply application-supplied runtime settings before calling Load.
The component's public runtime properties are `OpenSSLPath`, `ConfigFile` and
`SSLLibVersions`; `CustomSSLLibVersions` belongs to a platform-settings item.

For interface-based configuration:

```pascal
uses
  TaurusTLSLoader, TaurusTLSExceptionHandlers;

procedure InitializeOpenSSL(const ALibraryDirectory, AConfigFile: string);
var
  LLoader: IOpenSSLLoader;
begin
  LLoader := GetOpenSSLLoader;
  LLoader.OpenSSLPath := ALibraryDirectory;
  LLoader.ConfigFile := AConfigFile;
  if not LLoader.Load then
    raise ETaurusTLSLoaderError.Create('OpenSSL initialization failed');
end;
```

The paths are application-supplied deployment settings. Set them before any
OpenSSL-dependent consumer runs. Library discovery and provider discovery are
separate: `OpenSSLPath` locates libcrypto/libssl, not provider modules.

`ConfigFile` is available in both linking models. TaurusTLS passes that file to
OpenSSL before consumer initialization; OpenSSL handles provider activation,
module paths, included configuration files and algorithm properties. An explicit
file can have a relative or Unicode path. Missing/invalid paths raise
`ETaurusTLSConfigFilePathError`; native configuration failures raise
`ETaurusTLSConfigFileLoadError` with available diagnostics.

Leaving `ConfigFile` blank requests standard OpenSSL configuration initialization
and discovery. It does not disable configuration. A discovered filename alone
does not prove that the file was applied. Setting a filename does not itself
initialize OpenSSL or activate a provider; that happens during `Load`.

Use the OpenSSL documentation matching the deployed native version:

- [Configuration syntax](https://docs.openssl.org/3.0/man5/config/).
- [Provider configuration](https://docs.openssl.org/3.0/man5/config/#provider-configuration).
- [Engine configuration for OpenSSL 3](https://docs.openssl.org/3.0/man5/config/#engine-configuration).

Engine configuration requires an engine-enabled OpenSSL 3 build; engines are
deprecated there and are no longer supported in OpenSSL 4. Prefer providers for
new deployments. An engine's configuration does not establish that the adapters'
fetched EVP algorithms use it. See the
[OpenSSL migration guide](https://docs.openssl.org/4.0/man7/ossl-guide-migration/).

FIPS and Legacy providers require additional configuration, described next.

## 3. FIPS support for Indy

OpenSSL 3.x/4.x implements FIPS algorithms through a provider, replacing the
older FIPS-mode API approach. TaurusTLS's FIPS support requires the
`TaurusTLS_ProviderFIPS` unit. For FIPS-backed Indy hash/HMAC operations and mode
reporting, include both units in the application's `uses` clause:

```pascal
uses
  TaurusTLS_ProviderFIPS,
  TaurusTLSIdFIPS;
```

`TaurusTLS_ProviderFIPS` supplies TaurusTLS's native FIPS API validation and
provider-availability reporting. `TaurusTLSIdFIPS` installs Indy's hash/HMAC and
mode callbacks; it also depends on that provider-support unit. Listing both
makes the two responsibilities explicit. Neither unit activates the native
provider: the selected custom `openssl.cnf` and its included installation data
must do that when the loader initializes OpenSSL.

Despite its name, `TaurusTLSIdFIPS` also supplies ordinary OpenSSL-backed
hash/HMAC without FIPS selection. It uses modern EVP digest contexts and the
EVP_MAC HMAC API; availability follows the configured OpenSSL 3.x/4.x providers
and properties.

The unit installs callbacks once during Pascal unit initialization. `Load` and
`Unload` do not reinstall the backend or replace callbacks selected later by
another unit. Avoid competing Indy OpenSSL backend initializers when choosing the
TaurusTLS backend. The adapter's loading/availability callback checks readiness;
it does not load Indy's separate OpenSSL backend or initialize TaurusTLS.

### Dynamic-binding FIPS requirements

1. Include `TaurusTLS_ProviderFIPS` and `TaurusTLSIdFIPS` in the application.
2. Deploy matching OpenSSL shared libraries, the FIPS provider module and its
   installed `fipsmodule.cnf` data for the process architecture. Follow the
   distribution's installation procedure; do not invent or copy integrity data
   from another installation.
3. Prepare a custom `openssl.cnf` that selects a provider initialization section,
   includes that installed FIPS configuration, activates FIPS and any supporting
   provider needed by the application, and sets `default_properties = fips=yes`.
4. Set the loader's `ConfigFile` to this main `openssl.cnf`, then call `Load`
   before any protected operation.
5. After success, verify `IdFIPS.GetFIPSMode()` and algorithm availability before
   operations that require configured FIPS selection.

For a Linux-style deployment, the configuration structure can be:

```ini
config_diagnostics = 1
openssl_conf = app_init
.include "/deployment/openssl/fipsmodule.cnf"

[app_init]
providers = app_providers
alg_section = app_algorithms

[app_providers]
fips = fips_sect
base = base_sect

[base_sect]
activate = 1

[fips_sect]
activate = 1
module = "/deployment/openssl/providers/fips.so"

[app_algorithms]
default_properties = fips=yes
```

Replace the example paths with the installed files; the included provider data
must define the installation's FIPS section and activation. This is a structural
example, not a portable module filename or a FIPS installation recipe. Follow
OpenSSL's [FIPS module documentation](https://docs.openssl.org/3.0/man7/fips_module/)
and the documentation for the actual module/distribution you deploy.

`IdFIPS.GetFIPSMode()` returns True only when the dynamic-binding runtime is ready,
the required modern APIs are available, native FIPS properties are selected and
the FIPS provider is available. Provider availability alone is insufficient.
`IsFIPSProviderLoaded` is a passive query and does not acquire a provider handle.

`IdFIPS.SetFIPSMode` is a compatibility no-op. It cannot activate providers, change
selection, or clear a restrictive policy. It returns True only when the requested
mode already matches the configured policy; a True request also requires an
available FIPS provider. It returns False for a requested policy change.

When FIPS is selected, the adapter requires provider=fips for fetched hash/HMAC
implementations, including the HMAC's nested digest. Failure does not trigger a
retry with weaker properties or another backend. Mode reporting is not a
certification statement or proof that every operation is approved.

### Static/direct-import limits

TaurusTLS does not support the FIPS provider in statically linked applications.
This includes the standard Delphi archive deployments for both macOS Intel and
Apple Silicon, and all supported mobile targets (iOS and Android). The linked
Legacy provider described below does not change that FIPS limitation.

For `OPENSSL_STATIC_LINK_MODEL`, including startup shared-library direct imports,
FIPS mode/provider reporting and both setter requests return False. These are
TaurusTLS implementation limits; OpenSSL 3.x/4.x provider APIs do not imply that
TaurusTLS supports static FIPS deployment.

Ordinary hash/HMAC callbacks still require explicit TaurusTLS initialization and
fetch algorithms under the native default-context properties. Keep all hash/MAC
objects and operations inside the initialized runtime's lifetime.

## 4. NTLMv1 support for Indy

In OpenSSL 3.x/4.x, the Legacy provider supplies the MD4/DES algorithms used by
Indy's LM/NTLMv1 adapter. This follows the provider API model rather than older
low-level crypto/backend assumptions. Legacy is an algorithm provider, not an
NTLM authentication provider itself.

Include `TaurusTLSIdNTLM` in the application's `uses` clause to install the
LM/NTLMv1 response callbacks. Shared-library deployments activate the external
Legacy provider using a custom `openssl.cnf`; archive deployments additionally
include `TaurusTLS_ProviderLegacy` to link/register the builtin implementation.
Configure the appropriate path before calling `Load` and starting authentication.
The FIPS adapter is independent and is not required for NTLMv1.

The adapter uses EVP MD4 and DES-ECB operations. LM responses require DES-ECB; NT
responses require both MD4 and DES-ECB. Its loading hook is readiness-only;
`IsNTLMFuncsAvail` also checks algorithm fetches under the current native
properties and the Indy FIPS policy. Direct response operations reject a
non-ready loader. Enabling legacy does not override selected FIPS restrictions.

An application can include both Indy adapters, but that does not make NTLMv1
available under a FIPS-only algorithm policy. Activating both FIPS and Legacy
providers does not override `fips=yes` or Indy's prohibiting FIPS policy. Choose
the intended policy at application initialization and handle unavailable NTLM
without silently weakening it.

This work covers the LM/NTLMv1 callbacks. It does not establish NTLMv2 support,
including separate RC4/backend dependencies. Non-ASCII LM OEM policy is also
outside these changes. Validate the authentication variant your application uses.

### Dynamic binding and startup-loaded shared libraries

For OpenSSL 3.x/4.x shared-library deployment:

1. Include `TaurusTLSIdNTLM` in the application.
2. Deploy the matching external Legacy provider module with the native libraries.
3. Prepare a custom `openssl.cnf` that activates Legacy and Default and permits
   the required MD4/DES-ECB algorithms under the application's policy.
4. Set `ConfigFile` to that file before `Load`, then check NTLM availability before
   beginning authentication.

 The
[OpenSSL legacy-provider reference](https://docs.openssl.org/3.0/man7/OSSL_PROVIDER-legacy/)
lists these algorithm families; build options still affect availability.

The following configuration activates default and legacy providers:

```ini
config_diagnostics = 1
openssl_conf = app_init

[app_init]
providers = app_providers

[app_providers]
default = default_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1
```

This example relies on OpenSSL's module discovery. If needed, add an actual
`module = "..."` path inside `legacy_sect`. Select this file using `ConfigFile`
before `Load`, then check `IdFIPS.IsNTLMFuncsAvail()` before starting authentication.
Do not weaken an application's FIPS selection to make this availability test pass.

### Static macOS/mobile deployment with STATICLOAD_OPENSSL

The standard Delphi macOS (Intel and Apple Silicon) and mobile (iOS/Android)
archive deployments use a statically linked OpenSSL 3.x/4.x Legacy implementation.
Include both units:

```pascal
uses
  TaurusTLS_ProviderLegacy,
  TaurusTLSIdNTLM;
```

Deploy the OpenSSL archives for the target to the linker, including Legacy.
The current TaurusTLS archive names are `libcrypto.a`, `libssl.a` and
**`liblegacy.a`**. `CLibLegacyProvider` selects `liblegacy.a` in this target
configuration, and the optional unit references `ossl_legacy_provider_init`
from that archive.

The unit registers the linked legacy implementation in the default OpenSSL
context during unit initialization. Registration does not activate it. Use a
configuration activating default and legacy, as above, and explicitly call Load.
For this built-in provider path, omit the external legacy `module` setting.
Linking the registration unit alone does not make the provider available.

This is Legacy-provider support for OpenSSL 3.x/4.x; it does not enable static
FIPS. Configure Default and Legacy activation in the application's main
`openssl.cnf` and select it with `ConfigFile` before explicit initialization.

The registration guard is specifically `STATICLOAD_OPENSSL`. FPC's separate
`OPENSSL_USE_STATIC_LIBRARY` selection alone does not run that registration.
Its supported archive/provider setup needs maintainer confirmation before this
guide can give enablement instructions for that combination.

## Reference and deployment notes

### Platform settings

The component supports six groups: `tlpAndroid`, `tlpiOS`, `tlpMacOS`,
`tlpLinux`, `tlpWindows32` and `tlpWindows64`. Each group can occur only once.
Non-Windows groups share settings across architectures; Windows64 includes
ARM64EC while native library defaults still follow the compiled architecture.
Missing entries and blank fields use loader defaults:

| Empty setting | Effective behavior |
|---|---|
| Collection or running-target entry | Resolve all fields using the defaults below. |
| `OpenSSLPath` | Normal library discovery for that platform/linking model. |
| `ConfigFile` | Request standard OpenSSL 3.x/4.x configuration initialization and filename discovery. |
| `CustomSSLLibVersions` | Use TaurusTLS's target-specific default library-name suffixes for OpenSSL 4 and 3. |

Defaults do not mean a new isolated OpenSSL context. Provider activation still
comes from the configuration selected/discovered at initialization, and missing
FIPS/Legacy/custom provider configuration is not supplied automatically. Use an
explicit `ConfigFile` when the application must control that policy.

`PlatformSettings` is editable in the designer or during streaming. Runtime
collection/item mutation raises `ETaurusTLSLoaderError`; use the public scalar
properties for runtime configuration. The filename picker browses the designer
host, so remote deployment paths may need manual entry.

For a streamed component, selected settings are applied while the singleton is
inactive even when `LoadOnStart=False`. An already ready/failed singleton is not
reconfigured. Explicit `Load` does not reapply the collection. Later scalar
assignments therefore remain effective. Separate setters are not an atomic
configuration transaction; coordinate configuration before concurrent use.

### Failure, retry and shutdown

`Load` may return False or raise an exception. Failure leaves a circuit breaker:
changing properties alone does not permit a retry. After retiring consumers,
call `Unload`, correct the configuration and load again.

Repeated successful loads acquire no leases or initialization reference counts.
One `Unload` performs global cleanup. Before calling it, stop workers, finish
operations and free every native consumer. Do not unload in a connection's
bind/disconnect event while other connections may still need the runtime.
Freeing a component or releasing an interface does not unload OpenSSL.

In archive/direct-import builds, Load is still required for configuration and
TaurusTLS readiness even though the code is already linked/imported. Cleanup
neither removes linked code nor guarantees reset of OpenSSL's own initialization
policy. Coordinate startup with other OpenSSL users in the process: TaurusTLS
cannot promise to replace configuration established by another library first.

### Upgrade checks

- Select paths and provider policy before the first Load.
- Initialize before TLS, hash/HMAC and NTLM operations; handle False and exceptions.
- Keep streamed TLS consumers inactive until startup initialization completes.
- Rebuild packages and consumers together after the loader interface changes.
- Validate native library/provider files for each process architecture.
- Test missing/invalid configuration and missing-provider failures.
- Check FIPS selection and algorithm availability separately from readiness.
- Keep NTLMv1 requirements distinct from FIPS policy and NTLMv2 dependencies.
- Finish native operations before global Unload.

### Linking-mode requirements

| Build selection | Library binding | Explicit TaurusTLS Load | FIPS mode reporting | LM/NTLMv1 requirements |
|---|---|---|---|---|
| Runtime binding, no linking override | TaurusTLS loads shared libcrypto/libssl | Required | Implemented when configured FIPS module and APIs are available | Configured MD4 and DES-ECB, normally from a deployed legacy module |
| `OPENSSL_USE_SHARED_LIBRARY` | Direct external imports; OS startup loading | Required for readiness/configuration | Unsupported by the current `OPENSSL_STATIC_LINK_MODEL` implementation | MD4/DES-ECB available to the imported library through configuration |
| `STATICLOAD_OPENSSL` | Linked archives | Required | Unsupported | Include the optional legacy-provider registration unit and link its archive when legacy algorithms are needed; activate through configuration |
| FPC `OPENSSL_USE_STATIC_LIBRARY` | Existing FPC archive-linking path | Required | Unsupported | FPC-specific legacy-provider deployment instructions pending maintainer confirmation |

`STATICLOAD_OPENSSL` and `OPENSSL_USE_SHARED_LIBRARY` are mutually exclusive.
`OPENSSL_USE_STATIC_LIBRARY` is FPC-only. `OPENSSL_STATIC_LINK_MODEL` is an internal
category covering direct API imports and does not by itself mean archive linking.
The compiler include already selects archive linking for some Delphi targets,
including desktop macOS; inspect the effective build selection rather than
assuming a linking model from the platform name.

### Loader interface and compatibility routines

The exact before/after comparison is pending confirmation of the 1.0 baseline.
The current interface is defined in
[`Source/TaurusTLSLoader.pas`](Source/TaurusTLSLoader.pas).

| Member | 1.1 contract |
|---|---|
| `Load: Boolean` | Performs initialization or returns True if already ready; False and exceptions must be handled. |
| `Unload` | Performs global cleanup, clears failure/binding diagnostics and permits retry. |
| `Unload(AResetFailState: Boolean)` | False preserves the failed-state breaker/diagnostics; parameterless Unload is the normal application reset/shutdown entry point. |
| `IsLoaded: Boolean` | True only after configuration and every load action complete successfully. |
| `State` / `GetState` | `lsNotLoaded`, `lsLoadedReady` or `lsLoadedFailed`; load/unload/rollback transitions report not loaded. |
| `ConfigFile` / `GetConfigFile` / `SetConfigFile` | Configures initialization in both linking models; see the next section. |
| `Version` / `GetVersion` | Cached loaded OpenSSL version text; empty while not ready. |
| `ConfigDirectory` / `GetConfigDirectory` | Directory of the effective configuration filename; empty while not ready. |
| `ModulesDirectory` / `GetModulesDirectory` | OpenSSL's compiled provider-module directory; not a report of configured module paths or `OPENSSL_MODULES`. |
| `EnginesDirectory` / `GetEnginesDirectory` | Compiled engine directory on OpenSSL 3; empty on OpenSSL 4 or while not ready. |
| `OpenSSLPath` | Runtime-binding library directory; empty uses platform discovery. Direct-import/archive builds return empty and ignore assignments. |
| `SSLLibVersions` | Ordered runtime-binding filename suffixes; direct-import/archive builds return empty and ignore assignments. |
| `FailedToLoad` | Borrowed singleton-owned list of unresolved dynamic symbols. Never free it; an empty list does not prove readiness. |

`State` and `IsLoaded` are nonblocking snapshots. Cached string metadata is read
under the lifecycle lock. Metadata queries do not initialize OpenSSL.

Changed configuration is rejected while loading, ready, unloading or holding an
active dynamic handle. Reassigning the exact configured value is a no-op.
Changes after failure do not reset the failure state. Coordinate multi-property
configuration in application startup; separate setters are not one transaction.

The interface GUID remains `{BBB0F670-CC26-42BC-A9E0-33647361941A}`. This does not
preserve the old binary interface layout: rebuild affected packages and consumers
together rather than mixing old and new BPL/DCP/DCU artifacts.

The compatibility functions in `TaurusTLS` are deprecated forwards:

| Compatibility function | Preferred interface member |
|---|---|
| `LoadOpenSSLLibrary` | `Load` |
| `UnLoadOpenSSLLibrary` | `Unload` |
| `OpenSSLVersion` | `Version` |
| `OpenSSLDir` | `ConfigDirectory` |
| `OpenSSLModulesDir` | `ModulesDirectory` |
| `OpenSSLEnginesDir` | `EnginesDirectory` |

The current `OpenSSLDir` reports the directory of the effective configuration
filename. It is not the compiled default directory query. The final comparison
with 1.0 will identify which old query behavior must be changed.

## Implementation references

These sources establish the TaurusTLS behavior described here:

- [Loader interface, component, configuration and lifecycle](Source/TaurusTLSLoader.pas)
- [Core context readiness and compatibility functions](Source/TaurusTLS.pas)
- [Linking selections](Source/TaurusTLSLinkDefines.inc) and [library names](Source/TaurusTLSConsts.pas)
- [Indy hash/HMAC and FIPS adapter](Source/TaurusTLSIdFIPS.pas)
- [FIPS provider/API reporting](Source/TaurusTLS_ProviderFIPS.pas)
- [Indy LM/NTLMv1 adapter](Source/TaurusTLSIdNTLM.pas)
- [Optional archive legacy-provider registration](Source/TaurusTLS_ProviderLegacy.pas)
- [Configured FIPS tests](Tests/TaurusTLS.UT.Providers.FIPS.pas) and [NTLM tests](Tests/TaurusTLS.UT.NTLM.pas)

## Maintainer review before publication

This remains a draft. Confirm the exact 1.0 baseline for the API comparison and
the supported FPC archive NTLM setup before publishing instructions for
`OPENSSL_USE_STATIC_LIBRARY`. Do not infer runtime/static execution coverage
from successful compilation or from another linking model's results.
