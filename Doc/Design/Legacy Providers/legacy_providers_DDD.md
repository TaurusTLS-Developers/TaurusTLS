# TaurusTLS — Detailed Design Document: Legacy Provider Integration (Adjusted)

## 1. Introduction & Objectives

### 1.1 Purpose
This document provides the detailed technical specification for integrating OpenSSL 3.x/4.x Legacy Provider support into **TaurusTLS**. It defines unit architectures, core loader extensions, static archive linking mechanics, dynamic symbol resolution, UTF-8 path configuration, and thread-safe lifetime management.

### 1.2 Scope
* **Target Units:**
  * `Source/TaurusTLSLoader.pas`: Adds `ProvidersPath` property to `IOpenSSLLoader` and applies `OSSL_PROVIDER_set_default_search_path` during engine load.
  * `Source/TaurusTLS_LegacyProviders.pas`: Optional modular unit activating legacy and default providers.
* **Prerequisites:** `Source/TaurusTLSHeaders_provider.pas` imports all `OSSL_PROVIDER_*` routines.
* **Compilation Targets:** Dual support for Dynamic Linking (`{$IFNDEF OPENSSL_STATIC_LINK_MODEL}`) and Static Archive Linking (`{$IFDEF OPENSSL_STATIC_LINK_MODEL}`).

---

## 2. Technical Architecture & Unit Interactions

```
+-----------------------------------------------------------------------------------+
|                                  User Application                                 |
|               (Includes TaurusTLS_LegacyProviders in project uses clause)         |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                           TaurusTLS_LegacyProviders.pas                           |
|       TTaurusTLSLegacyProviderManager.OnLoadAction(AAction: TOpenSSLLoadAction)   |
+-----------------------------------------------------------------------------------+
          |                                                               |
          | {$IFNDEF OPENSSL_STATIC_LINK_MODEL}                           | {$IFDEF OPENSSL_STATIC_LINK_MODEL}
          v                                                               v
+-----------------------------------------+             +-----------------------------------+
| TaurusTLSLoader.pas                     |             | Static Linker                     |
|-----------------------------------------|             |-----------------------------------|
| 1. Bind symbols via GLibCryptoLoadList  |             | 1. Embeds liblegacy (.lib / .a)   |
|    (TaurusTLSHeaders_provider)          |             | 2. Direct symbol linkage for      |
| 2. Set default search path (UTF-8)      |             |    ossl_legacy_provider_init      |
| 3. Execute GOnLoadActionList:           |             +-----------------------------------+
|    └─ OnLoadAction(osaLoad)             |                               |
|       ├─ OSSL_PROVIDER_load('default')  |                               v
|       └─ OSSL_PROVIDER_load('legacy')   |             +-----------------------------------+
+-----------------------------------------+             | Unit Initialization Stage         |
          |                                             |-----------------------------------|
          v                                             | OSSL_PROVIDER_add_builtin         |
+-----------------------------------------+             | OSSL_PROVIDER_load('default')     |
| Dynamic Shared Modules                  |             | OSSL_PROVIDER_load('legacy')      |
| (libcrypto-3, legacy.dll/so)            |             +-----------------------------------+
+-----------------------------------------+
```

---

## 3. Core Loader Extensions (`Source/TaurusTLSLoader.pas`)

### 3.1 Interface Extensions (`IOpenSSLLoader`)

```pascal
  IOpenSSLLoader = interface
    ['{BBB0F670-CC26-42BC-A9E0-33647361941A}']
    // Existing accessors ...
    function GetOpenSSLPath: string;
    procedure SetOpenSSLPath(const Value: string);

    // --- Provider Path Accessors ---
    /// <summary>
    ///   Property get function for ProvidersPath.
    /// </summary>
    function GetProvidersPath: string;

    /// <summary>
    ///   Property set procedure for ProvidersPath.
    /// </summary>
    procedure SetProvidersPath(const Value: string);

    // Existing methods ...
    function Load: Boolean;
    procedure Unload;
    function IsLoaded: Boolean;

    property OpenSSLPath: string read GetOpenSSLPath write SetOpenSSLPath;

    /// <summary>
    ///   Search path for OpenSSL external providers (such as legacy.dll/so).
    ///   Can be an absolute path or relative to OpenSSLPath.
    ///   If empty, the loader defaults to OpenSSLPath.
    /// </summary>
    property ProvidersPath: string read GetProvidersPath write SetProvidersPath;
  end;
```

### 3.2 Path Normalization & UTF-8 Application in `TOpenSSLLoader`

`TOpenSSLLoader` manages `FProvidersPath` and resolves the effective path. OpenSSL requires paths to be **UTF-8 encoded** across all platforms.

```pascal
function TOpenSSLLoader.IsAbsolutePath(const APath: string): Boolean;
begin
  if APath = '' then
    Result := False
  else
  {$IFDEF WINDOWS}
    Result := ((Length(APath) >= 2) and (APath[2] = ':')) or
              ((Length(APath) >= 1) and ((APath[1] = '\') or (APath[1] = '/')));
  {$ELSE}
    Result := (Length(APath) >= 1) and (APath[1] = '/');
  {$ENDIF}
end;

function TOpenSSLLoader.GetEffectiveProvidersPath: string;
begin
  if FProvidersPath = '' then
    Result := FOpenSSLPath
  else if IsAbsolutePath(FProvidersPath) then
    Result := FProvidersPath
  else
    Result := FOpenSSLPath + FProvidersPath;
end;
```

### 3.3 Execution Sequence in `TOpenSSLLoader.Load`

During dynamic loading, after all library headers have bound their exported symbols (including `OSSL_PROVIDER_set_default_search_path`), the loader applies the search path prior to invoking registered action callbacks:

```pascal
// Inside TOpenSSLLoader.Load:
var
  LEffectivePath: string;
  LUTF8SearchPath: UTF8String;
begin
  // 1. Symbol resolution
  for i := 0 to GLibCryptoLoadList.Count - 1 do
    TOpenSSLLoadProc(GLibCryptoLoadList[i])(FLibCrypto, LSSLVersionNo, FFailed);
  for i := 0 to GLibSSLLoadList.Count - 1 do
    TOpenSSLLoadProc(GLibSSLLoadList[i])(FLibSSL, LSSLVersionNo, FFailed);

  // 2. Configure provider search path in UTF-8
  LEffectivePath := GetEffectiveProvidersPath;
  if (LEffectivePath <> '') and Assigned(OSSL_PROVIDER_set_default_search_path) then
  begin
    LUTF8SearchPath := UTF8Encode(LEffectivePath);
    OSSL_PROVIDER_set_default_search_path(nil, PIdAnsiChar(LUTF8SearchPath));
  end;

  // 3. Fire registered lifecycle actions (triggers legacy provider activation)
  for i := 0 to GOnLoadActionList.Count - 1 do
    GOnLoadActionList[i](osaLoad);
end;
```

---

## 4. Legacy Provider Unit (`Source/TaurusTLS_LegacyProviders.pas`)

### 4.1 Specification

* **No Manual Symbol Resolution:** Uses declarations from `TaurusTLSHeaders_provider.pas`.
* **Zero Allocation Callback:** Uses a `class procedure` of `TTaurusTLSLegacyProviderManager` as the `TTaurusTLSOnLoadAction` handler.
* **Dual-Model Support:**
  * In dynamic mode, registers with `Register_SSLLoaderAction` during `initialization`.
  * In static mode, registers the built-in symbol `ossl_legacy_provider_init` during `initialization`.

### 4.2 Implementation

```pascal
unit TaurusTLS_LegacyProviders;

{$I TaurusTLSCompilerDefines.inc}

interface

uses
  IdCTypes,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_provider,
  TaurusTLSLoader;

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
  {$IFDEF MSWINDOWS}
    {$L liblegacy.lib}
  {$ELSE}
    {$L liblegacy.a}
  {$ENDIF}

  // Static entry point exported by liblegacy archive
  function ossl_legacy_provider_init(
    const handle: POSSL_CORE_HANDLE;
    const in_struct: POSSL_DISPATCH;
    out out_struct: POSSL_DISPATCH;
    prov_ctx: pointer
  ): TIdC_INT; cdecl; external;
{$ENDIF}

type
  /// <summary>
  ///   Manager class providing class methods for OpenSSL provider lifecycle hooks.
  /// </summary>
  TTaurusTLSLegacyProviderManager = class
  public
    class procedure OnLoadAction(AAction: TOpenSSLLoadAction);
    class procedure InitLegacyProvider;
    class procedure UninitLegacyProvider;
  end;

implementation

uses
  SysUtils;

var
  FDefaultProvider: POSSL_PROVIDER = nil;
  FLegacyProvider: POSSL_PROVIDER = nil;

class procedure TTaurusTLSLegacyProviderManager.InitLegacyProvider;
begin
  if FLegacyProvider <> nil then
    Exit;

  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  // Register static built-in initialization routine
  OSSL_PROVIDER_add_builtin(nil, 'legacy', @ossl_legacy_provider_init);
  {$ENDIF}

  // 1. Explicitly load 'default' provider to prevent disabling modern ciphers
  if Assigned(OSSL_PROVIDER_load) then
  begin
    if FDefaultProvider = nil then
      FDefaultProvider := OSSL_PROVIDER_load(nil, 'default');

    // 2. Load 'legacy' provider
    if FLegacyProvider = nil then
      FLegacyProvider := OSSL_PROVIDER_load(nil, 'legacy');
  end;
end;

class procedure TTaurusTLSLegacyProviderManager.UninitLegacyProvider;
begin
  if Assigned(OSSL_PROVIDER_unload) then
  begin
    if FLegacyProvider <> nil then
    begin
      OSSL_PROVIDER_unload(FLegacyProvider);
      FLegacyProvider := nil;
    end;

    if FDefaultProvider <> nil then
    begin
      OSSL_PROVIDER_unload(FDefaultProvider);
      FDefaultProvider := nil;
    end;
  end;
end;

class procedure TTaurusTLSLegacyProviderManager.OnLoadAction(AAction: TOpenSSLLoadAction);
begin
  case AAction of
    osaLoad:   InitLegacyProvider;
    osaUnload: UninitLegacyProvider;
  end;
end;

initialization
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  // Register class procedure callback into loader action list
  Register_SSLLoaderAction(TTaurusTLSLegacyProviderManager.OnLoadAction);
{$ELSE}
  // Static linking: Symbols are immediately available at startup
  TTaurusTLSLegacyProviderManager.InitLegacyProvider;
{$ENDIF}

finalization
  TTaurusTLSLegacyProviderManager.UninitLegacyProvider;

end.
```

---

## 5. Path Encoding & String Safety (Unicode vs UTF-8)

OpenSSL C-APIs expect UTF-8 encoded strings (`const char *`). Passing standard ANSI strings on Windows fails when the file system path contains characters outside the active system code page (e.g., non-Latin user profile directories).

| Layer | Type | Encoding |
| :--- | :--- | :--- |
| **Delphi User Code** | `string` / `UnicodeString` | UTF-16 |
| **Loader Property** | `IOpenSSLLoader.ProvidersPath` | UTF-16 |
| **OpenSSL API Bridge** | `UTF8Encode(Path)` -> `PIdAnsiChar` | UTF-8 (`PAnsiChar`) |

---

## 6. Execution Lifecycle Sequence

```
DYNAMIC LINKING LIFECYCLE:

[ App Boot ] ─────────> TaurusTLS_LegacyProviders initialization
                          │
                          └──> Register_SSLLoaderAction(TTaurusTLSLegacyProviderManager.OnLoadAction)
                          │
[ Engine Load ] ──────> TOpenSSLLoader.Load
                          │
                          ├──> 1. Load DLLs (libcrypto, libssl)
                          ├──> 2. Execute GLibCryptoLoadList -> Binds TaurusTLSHeaders_provider
                          ├──> 3. Resolve EffectiveProvidersPath & convert to UTF-8
                          ├──> 4. OSSL_PROVIDER_set_default_search_path(nil, UTF8Path)
                          └──> 5. Dispatch GOnLoadActionList -> OnLoadAction(osaLoad)
                                  │
                                  ├──> OSSL_PROVIDER_load(nil, 'default')
                                  └──> OSSL_PROVIDER_load(nil, 'legacy')
                          │
[ Engine Unload / ] ──> TOpenSSLLoader.Unload / Process Exit
[ App Shutdown  ]         │
                          └──> Dispatch GOnLoadActionList -> OnLoadAction(osaUnload)
                                  │
                                  ├──> OSSL_PROVIDER_unload(FLegacyProvider)
                                  └──> OSSL_PROVIDER_unload(FDefaultProvider)
```

---

## 7. Verification & Safety Checklist

1. **Modern Algorithm Integrity:** Verify TLS 1.3 / AES-256-GCM functions identically before and after adding `TaurusTLS_LegacyProviders` to ensure the `default` provider remains intact.
2. **Missing `legacy.dll` Fault Tolerance:** If `legacy.dll` is not found, `FLegacyProvider` evaluates to `nil`. Standard OpenSSL operations must continue without crashing.
3. **Shutdown Cleanliness:** Providers must unload during `osaUnload` before `FreeLibrary` is called on `libcrypto` to prevent shutdown Access Violations.
