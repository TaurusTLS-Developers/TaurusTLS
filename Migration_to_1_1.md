# Migrating from TaurusTLS 1.0 to 1.1

TaurusTLS 1.1 supports OpenSSL 3.x and 4.x and drops support for OpenSSL 1.1.1
and earlier. It uses OpenSSL's newer cryptographic APIs and providers.

The main change for your application is when OpenSSL is initialized. Choose
one of the approaches below, configure any providers you need, and initialize
OpenSSL before making connections or using its cryptographic functions.

OpenSSL 3 introduced providers and deprecated several older APIs. OpenSSL 4
removes more of those APIs, including engine support. For background, see the
[OpenSSL migration guide](https://docs.openssl.org/4.0/man7/ossl-guide-migration/).

## 1. Initialize OpenSSL before using it

By default, TaurusTLS 1.1 no longer loads OpenSSL automatically when it creates
a TLS context. Call the loader before your first TLS connection, hash, HMAC or
NTLM operation. You can also enable the IOHandler's optional `AutoLoad`
property, described in approach 4.

This applies to both shared and statically linked libraries. With shared
libraries, the loader loads the files and initializes OpenSSL. With static
libraries, it initializes the OpenSSL code already linked into your application.
The minimum supported OpenSSL version is 3.0.0.

### Why initialization order matters

OpenSSL configuration controls which providers and algorithms your application
can use. Set the library path, configuration file and security policy before
initializing OpenSSL. This is especially important when the application
requires FIPS: that policy must be in place before processing data.

Other libraries in your application may also use OpenSSL. Coordinate their
initialization so they use the intended configuration. TaurusTLS cannot
guarantee that it can replace settings established by another library first.

### What you need to change

Use `IOpenSSLLoader.Load` or the `TTaurusTLSLoader` component. Both work with
the same OpenSSL loader for the application.

`GetOpenSSLLoader` returns the shared interface. Getting the interface, setting
its properties or checking its state does not initialize OpenSSL.

Set the properties you need, call `Load`, and handle both a False result and
any exceptions. Start connections and cryptographic operations only after
initialization succeeds. Low-level TLS context initialization raises
`ETaurusTLSLoaderError` if OpenSSL is not ready.

## 2. Choose how to initialize OpenSSL

You need one loader setup for the application, rather than one for each socket.

### Approach 1: initialize at startup with TTaurusTLSLoader

1. Place a `TTaurusTLSLoader` component on your startup form or data module.
2. Open its `PlatformSettings` collection. Add entries for platforms that need
   settings different from the defaults.
3. Leave `LoadOnStart=True`.
4. Keep TLS clients and servers inactive in the designer.
5. Start them after the form or data module has finished loading.

Each entry in `PlatformSettings` contains these properties:

| Property | What to enter |
|---|---|
| `Target` | The platform these settings apply to. |
| `OpenSSLPath` | The directory containing the shared OpenSSL libraries. |
| `ConfigFile` | The main OpenSSL configuration file, usually `openssl.cnf`. |
| `CustomSSLLibVersions` | Custom library-name suffixes, if needed. Usually leave this blank. |

You can leave the collection empty to use the defaults. A missing platform
entry or an empty property also uses the corresponding default: the platform's
library search, OpenSSL's configuration discovery, or TaurusTLS's library-name
suffixes.

An empty `ConfigFile` lets OpenSSL find its configuration. It does not disable
configuration or activate FIPS or Legacy by itself. Use approach 5 if your
application needs specific provider settings.

The component initializes OpenSSL after the form or data module's saved
properties have been loaded. It does not load OpenSSL in the designer.

Create this startup form or data module before any other form or data module
uses OpenSSL. The order of components on separate forms does not control
which form is created first.

### Approach 2: call the loader component yourself

Use this approach when you need to read application settings first, or want to
wait until the user starts a connection. Set the component's `LoadOnStart`
property to False, then call `Load`:

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

Replace `TaurusTLSLoader1` with your loader component's name. `TLSClient` is
your Indy client with a TaurusTLS IOHandler assigned. For a server, make the
same check before setting `TLSServer.Active := True`.

Handle a False result and let initialization exceptions reach your application's
error handler.

If you create the loader component in code, call `Load` yourself.
`LoadOnStart` is used when loading a form or data module's saved properties;
creating a component does not trigger it.

### Approach 3: use IOpenSSLLoader directly

You can initialize OpenSSL without placing a loader component on a form:

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

Call this procedure at startup or before `Client.Connect` or
`Server.Active := True`. If the application uses OpenSSL for hashes, HMAC or
NTLM earlier, initialize it before those operations.

Calling `Load` again after success returns True without repeating initialization.

### Approach 4: let the IOHandler initialize OpenSSL

`AutoLoad` was added to make migration easier for applications that do not need
any additional OpenSSL configuration. Both TaurusTLS IOHandlers have this
property, and its default value is False.

Set it to True before starting the connection or server:

```pascal
ClientTLSIOHandler.AutoLoad := True;
TLSClient.Connect;

// For a listening server:
ServerTLSIOHandler.AutoLoad := True;
TLSServer.Active := True;
```

Replace `ClientTLSIOHandler` and `ServerTLSIOHandler` with the names of the
TaurusTLS IOHandler components in your application.

If you configure OpenSSL through a `TTaurusTLSLoader` component or the
`IOpenSSLLoader` interface, leave `AutoLoad=False` and initialize OpenSSL there
before starting connections. Otherwise, the IOHandler may initialize OpenSSL
before the component applies its `PlatformSettings` or your code sets the
intended configuration. OpenSSL would then start with the settings available
at that moment, which may not be the ones your application requires.
Applying your settings afterward is too late for that initialization.

`AutoLoad` uses the same shared loader as the other approaches. If OpenSSL is
already ready, it reuses it without changing its configuration.

The IOHandler initializes OpenSSL and prepares its TLS context even when the
connection starts in plaintext mode. Handle loading and configuration errors
when starting the client or server.

Client clones and handlers created by the server inherit `AutoLoad`.
Copying this property does not load OpenSSL.

A failed load still needs an explicit `Unload` before retrying. Stop operations
and free objects that use OpenSSL before calling `Unload`. Destroying an
IOHandler does not unload OpenSSL.

### Approach 5: choose your libraries and configuration file

Use this approach when you need FIPS, the Legacy provider for LM/NTLMv1, or a
custom provider. You can also use it to load shared libraries from a particular
directory.

Prepare an `openssl.cnf` file that activates the required providers and selects
the algorithms your application needs. Set `ConfigFile` before the first
`Load`. Keep this configuration consistent across the application's connections.
The FIPS and NTLM sections below explain their different requirements.

With a `TTaurusTLSLoader` component, enter the settings in `PlatformSettings`:

| Property | Purpose |
|---|---|
| `Target` | The platform these settings apply to. |
| `OpenSSLPath` | Where TaurusTLS looks for shared libcrypto and libssl libraries. |
| `ConfigFile` | The main OpenSSL configuration file. |
| `CustomSSLLibVersions` | Library-name suffixes to try, in order. Leave blank for the defaults. |

Leave `LoadOnStart=True` if those settings are enough. Otherwise, set it to
False, apply your settings in code, and call `Load`.

When configuring the component in code, use its `OpenSSLPath`, `ConfigFile`
and `SSLLibVersions` properties. The name `CustomSSLLibVersions` is used only
for entries in `PlatformSettings`.

With the interface, set the properties before calling `Load`:

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

Use the paths from your application's installation. `OpenSSLPath` tells
TaurusTLS where to find libcrypto and libssl. OpenSSL locates provider modules
separately.

`ConfigFile` works with shared and statically linked libraries. During `Load`,
TaurusTLS passes the selected file to OpenSSL before running the application's
registered load callbacks. OpenSSL reads the provider settings, module paths,
included files and algorithm properties.

The filename can contain Unicode characters or be relative. Invalid or missing
paths raise `ETaurusTLSConfigFilePathError`. If OpenSSL cannot apply the
configuration, TaurusTLS raises `ETaurusTLSConfigFileLoadError` with the
available error details.

Leaving `ConfigFile` empty lets OpenSSL find its configuration in the usual
way. A filename returned by discovery does not prove that the file was read.
Setting `ConfigFile` alone does not initialize OpenSSL; call `Load` afterward.

Use the documentation for the OpenSSL version you deploy:

- [Configuration syntax](https://docs.openssl.org/3.0/man5/config/).
- [Provider configuration](https://docs.openssl.org/3.0/man5/config/#provider-configuration).
- [Engine configuration for OpenSSL 3](https://docs.openssl.org/3.0/man5/config/#engine-configuration).

Engines require an engine-enabled OpenSSL 3 build. They are deprecated in
OpenSSL 3 and removed in OpenSSL 4, so use providers for new deployments.
Configuring an engine does not guarantee that TaurusTLS's EVP-based Indy
adapters will use it. See the
[OpenSSL migration guide](https://docs.openssl.org/4.0/man7/ossl-guide-migration/).

### Configure paths for your installation

Choose an OpenSSL distribution that suits your application and follow its
configuration instructions. TaurusTLS uses OpenSSL's own configuration rules.
It does not require the OpenSSL-Distribution package layout, look beside
libcrypto for a missing configuration file, or change paths inside that file.

Use absolute paths if your application may start from different working
directories. TaurusTLS resolves a relative `ConfigFile` against the working
directory when loading. Loading libcrypto from another directory does not
change that base.

OpenSSL has separate rules for provider paths and `.include` files. Those
paths are not automatically relative to the main configuration file. See
[OpenSSL's include-path rules](https://docs.openssl.org/3.0/man5/config/#directives).

You can set the environment before starting your application. For example,
a PowerShell launcher on Windows could contain:

```powershell
$env:OPENSSL_CONF = 'C:\Apps\Example\config\openssl.cnf'
$env:OPENSSL_MODULES = 'C:\Apps\Example\crypto\providers'
$env:OPENSSL_CONF_INCLUDE = 'C:\Apps\Example\config'
& 'C:\Apps\Example\Example.exe'
```

Replace these paths with the locations you use for your application.

You can also choose the configuration file through either the `IOpenSSLLoader`
interface or the `TTaurusTLSLoader` component. Set `ConfigFile` to the file you
want to use; this takes priority over `OPENSSL_CONF`.

Leave `ConfigFile` empty to let OpenSSL use `OPENSSL_CONF` or its default
configuration location. Set `OpenSSLPath` separately if you need to choose
where TaurusTLS loads shared libraries.

| Environment variable | What it controls |
|---|---|
| `OPENSSL_CONF` | The main configuration file. An empty value disables configuration-file loading through OpenSSL's normal discovery. |
| `OPENSSL_MODULES` | The directory for external provider modules. Providers still need to be activated. |
| `OPENSSL_CONF_INCLUDE` | The directory OpenSSL prepends to relative `.include` paths. |
| `OPENSSL_ENGINES` | The dynamic engine directory for engine-enabled OpenSSL 3 builds. |

Check the deployed version's
[environment-variable documentation](https://docs.openssl.org/3.0/man7/openssl-env/),
including the rules for privileged processes. Setting these variables before
starting the application also avoids differences between Delphi's environment
and the C runtime used by OpenSSL.

Configure OpenSSL before any library in the process initializes it. Some
[initialization settings last for the lifetime of the process](https://docs.openssl.org/3.0/man3/OPENSSL_init_crypto/).

This minimal configuration explicitly activates the default provider:

```ini
config_diagnostics = 1
openssl_conf = openssl_init

[openssl_init]
providers = provider_section

[provider_section]
default = default_section

[default_section]
activate = 1
```

Add other providers only when your application needs them, following the
[provider configuration instructions](https://docs.openssl.org/3.0/man5/config/#provider-configuration).
The FIPS and NTLM sections below give more specific examples. You still need
to configure certificate verification and the TLS policy for your application.

The example enables `config_diagnostics`. This makes configuration errors
visible, but an error can prevent the application from initializing OpenSSL.
Read OpenSSL's explanation of
[configuration diagnostics](https://docs.openssl.org/3.0/man5/config/)
when choosing how to handle these errors.

Protect the configuration files and provider/engine directories from changes
by untrusted users. These files can control which native modules OpenSSL loads
and which cryptographic settings it uses. Keep your distribution updated and
follow [OpenSSL security advisories](https://www.openssl-library.org/news/vulnerabilities/),
its [security policy](https://www.openssl-library.org/policies/general/security-policy/),
and its [installation guidance](https://github.com/openssl/openssl/blob/master/INSTALL.md).

Test the application using its deployment account and working directory. Check
certificate-chain and hostname verification, the TLS protocols you allow, and
the providers your application needs. A successful library load alone does not
confirm that these settings are correct.

### Initialize OpenSSL before starting a server

If the server IOHandler has `AutoLoad=False`, initialize OpenSSL before setting
`Server.Active := True`. This applies to shared and statically linked libraries.

If you maintain your own server class, you can initialize OpenSSL in `Startup`
before calling the inherited method:

```pascal
uses
  IdTCPServer, TaurusTLSLoader, TaurusTLSExceptionHandlers;

type
  TApplicationTCPServer = class(TIdTCPServer)
  protected
    procedure Startup; override;
  end;

procedure TApplicationTCPServer.Startup;
begin
  if not GetOpenSSLLoader.Load then
    raise ETaurusTLSLoaderError.Create('OpenSSL initialization failed');

  inherited Startup;
end;
```

Set the loader's properties before activating the server. For an existing
server component, you can simply call the loader immediately before
`Active := True`, as shown in approaches 2 and 3.

The class above is an example you can add to your application. Do not unload
OpenSSL each time a client disconnects or a server stops; other parts of the
application may still be using it.

## 3. Using FIPS with Indy

OpenSSL 3.x and 4.x provide FIPS support through a provider. For FIPS-backed
Indy hashes, HMAC and FIPS-mode reporting, add these units:

```pascal
uses
  TaurusTLS_ProviderFIPS,
  TaurusTLSIdFIPS;
```

`TaurusTLS_ProviderFIPS` checks the required OpenSSL APIs and provider
availability. `TaurusTLSIdFIPS` connects Indy's hash, HMAC and FIPS callbacks
to TaurusTLS. It also uses the provider-support unit internally.

Choose an `openssl.cnf` file that activates FIPS and includes the installation's
FIPS configuration data. OpenSSL applies it when the loader initializes the
library. Adding the units alone does not activate FIPS.

Despite its name, `TaurusTLSIdFIPS` also provides ordinary OpenSSL-backed
hashes and HMAC without FIPS enabled. It uses the newer EVP digest and EVP_MAC
APIs. The available algorithms depend on your provider configuration.

The unit installs its Indy callbacks once, during unit initialization.
Calling `Load` or `Unload` does not reinstall them or replace callbacks assigned
by another unit later. Avoid installing another Indy OpenSSL backend alongside
the TaurusTLS backend.

Indy's availability callbacks check whether TaurusTLS is ready. They do not
initialize it or load Indy's separate OpenSSL backend.

### FIPS with runtime-loaded shared libraries

1. Add `TaurusTLS_ProviderFIPS` and `TaurusTLSIdFIPS`.
2. Install matching OpenSSL shared libraries, the FIPS provider and its
   `fipsmodule.cnf` data for your application's architecture. Follow the
   distribution's installation instructions.
3. Prepare a main `openssl.cnf` that includes the installed FIPS configuration,
   activates FIPS and any supporting provider, and sets
   `default_properties = fips=yes`.
4. Set `ConfigFile` to that main file and call `Load` before using OpenSSL.
5. Check `IdFIPS.GetFIPSMode()` and the required algorithms before starting
   operations that require FIPS.

For a Linux installation, the main configuration can have this structure:

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

Replace the paths with your installed files. Use the FIPS configuration and
integrity data generated for that installation; do not invent the values or
copy them from another installation. The included file must define the
installation's FIPS section and activation settings.

Follow the [OpenSSL FIPS module instructions](https://docs.openssl.org/3.0/man7/fips_module/)
and your distribution's documentation for installation. The example shows how
the configuration fits together, rather than providing an installation recipe
or a module filename that works on every platform.

`IdFIPS.GetFIPSMode()` returns True only when the loader is ready, the required
APIs are available, OpenSSL has FIPS properties enabled, and the FIPS provider
is available. `IsFIPSProviderLoaded` checks availability without taking ownership
of a provider handle.

`IdFIPS.SetFIPSMode` is kept for compatibility. It cannot activate a provider or
change the policy selected in your configuration. It returns True only when
the requested mode already matches that policy. Requesting True also requires
the FIPS provider to be available.

With FIPS enabled, the adapter requests `provider=fips` for hashes and HMAC,
including the digest used inside HMAC. If the required algorithm is unavailable,
the operation fails rather than retrying with weaker settings or another backend.

These checks do not certify the application or prove that every operation
meets FIPS requirements.

### FIPS limitations with linked libraries

TaurusTLS does not support FIPS in statically linked applications. This includes
the standard Delphi macOS builds for Intel and Apple Silicon, and the supported
iOS and Android builds. Linking the Legacy provider does not add FIPS support.

The current implementation also reports False for FIPS mode, FIPS provider
availability and both `SetFIPSMode` requests when using
`OPENSSL_STATIC_LINK_MODEL`. This includes shared libraries imported at startup.
These are TaurusTLS limitations.

Ordinary hashes and HMAC still work when their algorithms are available under
the configured OpenSSL policy. Initialize TaurusTLS first, and free all hash
and HMAC objects before unloading it.

## 4. Using LM/NTLMv1 with Indy

OpenSSL's Legacy provider supplies the MD4 and DES algorithms needed by Indy's
LM/NTLMv1 callbacks. It supplies the cryptographic algorithms; Indy handles
the authentication protocol.

Add `TaurusTLSIdNTLM` to install those callbacks. For shared libraries, activate
the external Legacy provider in `openssl.cnf`. For static Delphi builds, also
add `TaurusTLS_ProviderLegacy` to link and register the provider.

Select your configuration and call `Load` before starting authentication.
The FIPS adapter is separate and is not required for NTLMv1.

LM responses require DES-ECB. NT responses require both MD4 and DES-ECB.
`IsNTLMFuncsAvail` checks whether the configured OpenSSL providers and Indy
policy allow the required operations. The loading callback checks readiness
only; it does not initialize OpenSSL. Calling the response functions before
initialization fails.

You can include both Indy adapters, but NTLMv1 remains unavailable under a
FIPS-only policy or when Indy's FIPS policy prohibits it. Activating Legacy
does not override those restrictions. Select the policy at startup and handle
unavailable authentication without weakening it automatically.

This support covers LM/NTLMv1 callbacks. It does not establish NTLMv2 support,
which can have separate RC4/backend requirements. Handling non-ASCII text for
LM's OEM encoding is also outside these changes. Check which authentication
variant your application actually uses.

### LM/NTLMv1 with shared libraries

This applies both when TaurusTLS loads the libraries and when the operating
system imports them at startup:

1. Add `TaurusTLSIdNTLM`.
2. Install the matching Legacy provider module with your OpenSSL libraries.
3. Prepare an `openssl.cnf` that activates Default and Legacy and allows the
   required MD4 and DES-ECB algorithms.
4. Set `ConfigFile`, call `Load`, and check
   `IdFIPS.IsNTLMFuncsAvail()` before authenticating.

The [OpenSSL Legacy provider reference](https://docs.openssl.org/3.0/man7/OSSL_PROVIDER-legacy/)
lists the algorithms it supplies. Availability also depends on how your
OpenSSL distribution was built.

This configuration activates Default and Legacy:

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

OpenSSL uses its module search rules to find Legacy. If necessary, add the
installed module's path as `module = "..."` in `legacy_sect`.
Select this file with `ConfigFile` before calling `Load`.

Keep the application's FIPS policy intact if the NTLM availability check fails.

### LM/NTLMv1 with static macOS and mobile libraries

Standard Delphi builds for macOS, iOS and Android use linked OpenSSL archives.
To include Legacy, add both units:

```pascal
uses
  TaurusTLS_ProviderLegacy,
  TaurusTLSIdNTLM;
```

Make these archives available to the linker: `libcrypto.a`, `libssl.a` and
**`liblegacy.a`**. In this configuration, `CLibLegacyProvider` selects
`liblegacy.a`, and the optional provider unit references its
`ossl_legacy_provider_init` entry point.

The unit registers the provider during Pascal unit initialization. To activate
it, choose a configuration that enables Default and Legacy, as shown above,
then call `Load`. Omit the external Legacy `module` setting when using this
linked provider.

This adds Legacy support, not FIPS support.

The registration unit uses `STATICLOAD_OPENSSL`. Selecting FPC's
`OPENSSL_USE_STATIC_LIBRARY` alone does not run that registration. The supported
FPC setup for linked Legacy still needs maintainer confirmation before we can
give instructions for it here.

## Reference and deployment notes

### Platform settings

`PlatformSettings` supports six groups: `tlpAndroid`, `tlpiOS`, `tlpMacOS`,
`tlpLinux`, `tlpWindows32` and `tlpWindows64`. Add at most one entry per group.

Non-Windows settings apply across architectures. Windows64 includes ARM64EC;
the default library filenames still match the application's architecture.

Missing entries and empty properties use these defaults:

| Setting left empty | What happens |
|---|---|
| Collection or target entry | The loader uses the defaults listed below. |
| `OpenSSLPath` | Libraries are found through the platform's normal search. This property is ignored for directly imported or static libraries. |
| `ConfigFile` | OpenSSL uses its usual configuration discovery and initialization. |
| `CustomSSLLibVersions` | TaurusTLS tries its default library-name suffixes for OpenSSL 4 and 3. |

All these approaches use OpenSSL's default library context. An empty setting
does not create a separate configuration for each component or activate a
missing provider. Set `ConfigFile` when you need to choose the provider policy.

Edit `PlatformSettings` in the designer. The component can also restore it when
loading saved properties. Changing the collection in a running application
raises `ETaurusTLSLoaderError`; use `OpenSSLPath`, `ConfigFile` and
`SSLLibVersions` instead. A filename selected in the designer is a path on the
development machine, so check it when deploying to another machine.

When a saved component loads and the shared loader is inactive, it applies its
platform settings even with `LoadOnStart=False`. Calling `Load` later does not
apply them again, so changes you make through the runtime properties are kept.

A component does not reconfigure a loader that is already ready or has failed.
Set all properties during startup, before other threads start using the loader.
Several property assignments are separate operations, not one combined update.

### Handle failures and shut down safely

`Load` can return False or raise an exception. After a failed load, further
attempts are blocked until you call `Unload`. Changing a property alone does
not clear that failure.

Before retrying, stop operations and free objects that use OpenSSL. Call
`Unload`, correct the settings, and call `Load` again.

Repeated `Load` calls do not need matching `Unload` calls. A single `Unload`
cleans up the shared loader for the whole application. Stop workers, finish
operations and free all OpenSSL objects before calling it.

Destroying a component or releasing its loader interface does not unload
OpenSSL. Avoid calling `Unload` from a connection event while other connections
or cryptographic operations may still be running.

With linked libraries, `Unload` leaves the code linked into the application.
It also cannot guarantee a reset of OpenSSL's earlier initialization choices.
Coordinate configuration with other libraries that use the same OpenSSL
instance.

### Before you finish migrating

- Choose library paths and provider settings before the first `Load`.
- Initialize before TLS, hash, HMAC and NTLM operations; handle False and exceptions.
- Keep TLS clients and servers inactive in the designer until startup is ready.
- Rebuild TaurusTLS packages and your application together.
- Install matching library and provider files for each process architecture.
- Test invalid or missing configurations and missing provider modules.
- Check FIPS settings and algorithm availability separately from loader readiness.
- Check your application's NTLM variant and its compatibility with the chosen policy.
- Finish all OpenSSL operations and free their objects before `Unload`.

### Linking options

| Build setting | How OpenSSL is linked | Call the TaurusTLS loader? | FIPS reporting | LM/NTLMv1 setup |
|---|---|---|---|---|
| No linking override | TaurusTLS loads shared libcrypto and libssl | Yes | Available with a correctly configured FIPS provider and required APIs | Activate the deployed Legacy provider and allow MD4/DES-ECB. |
| `OPENSSL_USE_SHARED_LIBRARY` | The operating system imports shared libraries at startup | Yes | Unsupported by the current implementation | Configure the imported libraries to provide MD4/DES-ECB. |
| `STATICLOAD_OPENSSL` | Archives are linked into the application | Yes | Unsupported | Link/register Legacy when needed, then activate it through configuration. |
| FPC `OPENSSL_USE_STATIC_LIBRARY` | FPC's archive-linking option | Yes | Unsupported | FPC-specific linked Legacy instructions still need maintainer confirmation. |

`STATICLOAD_OPENSSL` and `OPENSSL_USE_SHARED_LIBRARY` cannot be used together.
`OPENSSL_USE_STATIC_LIBRARY` is for FPC only.

`OPENSSL_STATIC_LINK_MODEL` is an internal symbol for direct API calls. It
covers both imported shared libraries and linked archives.

The compiler include already selects archive linking for some Delphi targets,
including desktop macOS. Check the effective compiler settings rather than
assuming the linking mode from the platform name alone.

### Loader interface

The current interface is declared in
[`Source/TaurusTLSLoader.pas`](Source/TaurusTLSLoader.pas).
The exact comparison with the 1.0 API still needs maintainer confirmation.

| Member | What it does |
|---|---|
| `Load: Boolean` | Initializes OpenSSL, or returns True if already ready. Handle False and exceptions. |
| `Unload` | Cleans up the shared loader, clears failures and allows another load attempt. |
| `Unload(AResetFailState: Boolean)` | Passing False keeps the failure state and error list. Use the parameterless method for normal shutdown or reset. |
| `IsLoaded: Boolean` | Returns True after configuration and all registered load callbacks have completed. |
| `State` / `GetState` | Reports `lsNotLoaded`, `lsLoadedReady` or `lsLoadedFailed`. During loading or unloading it reports `lsNotLoaded`. |
| `ConfigFile` / `GetConfigFile` / `SetConfigFile` | Selects the main OpenSSL configuration file for either linking model. |
| `Version` / `GetVersion` | Returns the cached OpenSSL version, or an empty string while not ready. |
| `ConfigDirectory` / `GetConfigDirectory` | Returns the directory of the selected or discovered configuration filename, or an empty string while not ready. |
| `ModulesDirectory` / `GetModulesDirectory` | Reports OpenSSL's default provider-module directory, rather than the configured module paths or `OPENSSL_MODULES`. Empty while not ready or unavailable. |
| `EnginesDirectory` / `GetEnginesDirectory` | Reports OpenSSL's default engine directory on OpenSSL 3. Returns an empty string on OpenSSL 4 or while not ready. |
| `OpenSSLPath` | Sets the shared-library search directory. Empty uses the platform search; imported/static builds return empty and ignore assignments. |
| `SSLLibVersions` | Lists the library-name suffixes to try. Imported/static builds return empty and ignore assignments. |
| `FailedToLoad` | Returns the loader's list of unresolved dynamic symbols. Do not free this list. An empty list does not prove that loading succeeded. |

`State` and `IsLoaded` return immediately without waiting for the loader lock.
They describe the state at the time you read them; they do not keep OpenSSL
loaded while you use it. The string properties return cached information under
the loader lock. Reading these properties does not initialize OpenSSL.

You cannot change configuration while the loader is loading, ready, unloading
or still holds a dynamic library handle. Assigning the value already stored has
no effect. After a failure, reset the loader with `Unload` before retrying.

The interface GUID is still `{BBB0F670-CC26-42BC-A9E0-33647361941A}`, but its
method layout has changed. Rebuild packages and applications together.
Do not mix old and new BPL, DCP or DCU files.

### Older helper functions

The following functions in `TaurusTLS` are deprecated. Use the loader interface
in new code:

| Older function | Use instead |
|---|---|
| `LoadOpenSSLLibrary` | `Load` |
| `UnLoadOpenSSLLibrary` | `Unload` |
| `OpenSSLVersion` | `Version` |
| `OpenSSLDir` | `ConfigDirectory` |
| `OpenSSLModulesDir` | `ModulesDirectory` |
| `OpenSSLEnginesDir` | `EnginesDirectory` |

`OpenSSLDir` now returns the directory of the selected or discovered configuration
filename. It does not query the compiled default directory. The final comparison
with TaurusTLS 1.0 still needs review.

## Source references

For implementation details, see:

- [Loader interface, component and configuration](Source/TaurusTLSLoader.pas)
- [TLS contexts and compatibility functions](Source/TaurusTLS.pas)
- [Linking options](Source/TaurusTLSLinkDefines.inc) and [library names](Source/TaurusTLSConsts.pas)
- [Indy hash/HMAC and FIPS adapter](Source/TaurusTLSIdFIPS.pas)
- [FIPS provider checks](Source/TaurusTLS_ProviderFIPS.pas)
- [Indy LM/NTLMv1 adapter](Source/TaurusTLSIdNTLM.pas)
- [Linked Legacy provider registration](Source/TaurusTLS_ProviderLegacy.pas)
- [FIPS tests](Tests/TaurusTLS.UT.Providers.FIPS.pas) and [NTLM tests](Tests/TaurusTLS.UT.NTLM.pas)

## Notes for maintainers before publishing

This guide is still a draft. Confirm the comparison with the 1.0 API and the
supported FPC setup for linked Legacy before publishing those instructions.

Record build and runtime test results separately. A successful compilation or
a passing test on one platform does not establish support for another platform
or linking mode.
