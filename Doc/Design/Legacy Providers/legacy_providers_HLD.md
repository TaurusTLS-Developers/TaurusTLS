# TaurusTLS — Legacy Provider Integration Design Document (Updated)

## 1. Overview & Objectives

In OpenSSL 3.x and 4.x, legacy cryptographic algorithms (such as Blowfish, RC4, MD4, RIPEMD, and DES) were moved out of the standard library core into a dedicated external module known as the **Legacy Provider** (`legacy.dll` / `legacy.so` / `liblegacy.a`).

By default, OpenSSL only loads the `default` provider implicitly. To support legacy protocols and ciphers while preserving TaurusTLS’s modular architecture, this document details the design for legacy provider integration in **TaurusTLS**.

### Key Architectural Objectives

1. **Modular Opt-In Design:** Legacy provider logic is isolated in `TaurusTLS_LegacyProviders.pas`. Simply including this unit in a project’s `uses` clause activates legacy support without bloating or altering core operations.
2. **Dual-Model Support:**
   * **Dynamic Linking (`{$IFNDEF OPENSSL_STATIC_LINK_MODEL}`):** Hooks into the existing `Register_SSLLoaderAction` mechanism in `TaurusTLSLoader.pas`, deferring provider activation until `libcrypto` symbols are bound.
   * **Static Linking (`{$IFDEF OPENSSL_STATIC_LINK_MODEL}`):** Statically links `liblegacy` and registers `ossl_legacy_provider_init` via `OSSL_PROVIDER_add_builtin`.
3. **Search Path Flexibility & Fallback:** Allows custom search directories for dynamic provider binaries via `IOpenSSLLoader.ProviderSearchPath`, automatically falling back to `OpenSSLPath` if unconfigured.
4. **Mandatory Default Provider Retention:** Explicitly loads the `default` provider alongside `legacy` to avoid disabling OpenSSL's modern cipher suites (AES-GCM, TLS 1.3).

---

## 2. Component Architecture & Data Flow

```
+-----------------------------------------------------------------------------+
|                                Application                                  |
|         (uses TaurusTLS_LegacyProviders in project source file)             |
+-----------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------+
|                       TaurusTLS_LegacyProviders.pas                         |
+-----------------------------------------------------------------------------+
       |                                                               |
       | {$IFNDEF OPENSSL_STATIC_LINK_MODEL}                           | {$IFDEF OPENSSL_STATIC_LINK_MODEL}
       v                                                               v
+------------------------------------+               +------------------------------------+
| Dynamic Binding Phase              |               | Static Initialization Phase        |
|------------------------------------|               |------------------------------------|
| 1. TaurusTLSHeaders_provider binds |               | 1. Link liblegacy (.lib / .a)      |
|    symbols via GLibCryptoLoadList  |               | 2. OSSL_PROVIDER_add_builtin(...)  |
| 2. Hook registered via             |               | 3. OSSL_PROVIDER_load('default')   |
|    Register_SSLLoaderAction        |               | 4. OSSL_PROVIDER_load('legacy')    |
| 3. Set Provider Search Path        |               +------------------------------------+
| 4. OSSL_PROVIDER_load('default')   |
| 5. OSSL_PROVIDER_load('legacy')    |
+------------------------------------+
```

---

## 3. Dynamic Linking Model Strategy (`{$IFNDEF OPENSSL_STATIC_LINK_MODEL}`)

Dynamic loading in TaurusTLS executes lazily when the user or engine loads OpenSSL.

### 3.1 Separation of Responsibilities

* **`TaurusTLSHeaders_provider.pas` (Headers Layer):**
  Registers its symbol loader procedure into `GLibCryptoLoadList` via `Register_SSLLoader`. It binds raw C function pointers (`OSSL_PROVIDER_load`, `OSSL_PROVIDER_unload`, `OSSL_PROVIDER_set_default_search_path`, `OSSL_PROVIDER_add_builtin`).
* **`TaurusTLS_LegacyProviders.pas` (Management Layer):**
  Does **not** bind raw symbols. Instead, it registers an action handler with `Register_SSLLoaderAction` to listen for `osaLoad` and `osaUnload`.

### 3.2 Provider Search Path Resolution

Before any provider is loaded, OpenSSL must know where to locate `legacy.dll` / `legacy.so`:
1. `TOpenSSLLoader` exposes property `ProviderSearchPath: string`.
2. When loading `libcrypto`, if `ProviderSearchPath` is unset, it falls back to `OpenSSLPath`.
3. If a search path is resolved and `Assigned(OSSL_PROVIDER_set_default_search_path)`, `TOpenSSLLoader.Load` applies it to the default library context (`nil`) prior to executing `GOnLoadActionList`.

### 3.3 Provider Activation & Teardown Sequence

Within the `TTaurusTLSOnLoadAction` handler:
* **On `osaLoad`:**
  1. `FDefaultProvider := OSSL_PROVIDER_load(nil, 'default');` (retains core/modern algorithms).
  2. `FLegacyProvider  := OSSL_PROVIDER_load(nil, 'legacy');`
* **On `osaUnload`:**
  1. Unload `FLegacyProvider` via `OSSL_PROVIDER_unload`.
  2. Unload `FDefaultProvider` via `OSSL_PROVIDER_unload`.
  3. Reset both handles to `nil`.

---

## 4. Static Linking Model Strategy (`{$IFDEF OPENSSL_STATIC_LINK_MODEL}`)

In static compilation mode, `legacy.dll` / `legacy.so` is not present on disk. The static library (`liblegacy.a` or `liblegacy.lib`) is linked directly into the binary.

### 4.1 Linker Integration

`TaurusTLS_LegacyProviders.pas` specifies the appropriate archive library binding directives:

```pascal
{$IFDEF MSWINDOWS}
  {$L liblegacy.lib}
{$ELSE}
  {$L liblegacy.a}
{$ENDIF}
```

### 4.2 C-Symbol Import & Registration

Because OpenSSL cannot discover static symbols via `dlopen`/`LoadLibrary`, the static entry-point symbol must be registered into OpenSSL's internal table:

1. **External Declaration:**
   ```pascal
   function ossl_legacy_provider_init(
     const handle: POSSL_CORE_HANDLE;
     const in_struct: POSSL_DISPATCH;
     out out_struct: POSSL_DISPATCH;
     prov_ctx: pointer): TIdC_INT; cdecl; external;
   ```
2. **Registration & Activation:**
   * `OSSL_PROVIDER_add_builtin(nil, 'legacy', @ossl_legacy_provider_init);`
   * `FDefaultProvider := OSSL_PROVIDER_load(nil, 'default');`
   * `FLegacyProvider  := OSSL_PROVIDER_load(nil, 'legacy');`
3. **Teardown (`finalization`):**
   * Releases `FLegacyProvider` and `FDefaultProvider` via `OSSL_PROVIDER_unload`.

---

## 5. Core Loader Extensions (`TaurusTLSLoader.pas`)

To support provider path configuration and preserve lifecycle integrity, `TaurusTLSLoader.pas` receives the following targeted enhancements:

### 5.1 Provider Search Path Property
Extend `IOpenSSLLoader` and `TOpenSSLLoader`:
* **Property:** `ProviderSearchPath: string read GetProviderSearchPath write SetProviderSearchPath;`
* **Logic:** If `FProviderSearchPath` is empty, getter/resolver falls back to `FOpenSSLPath`.

### 5.2 Search Path Application in `TOpenSSLLoader.Load`
Directly after `GLibCryptoLoadList` executes (when `OSSL_PROVIDER_set_default_search_path` is resolved) and before triggering `GOnLoadActionList`:
* If path is non-empty, invoke `OSSL_PROVIDER_set_default_search_path(nil, PIdAnsiChar(AnsiString(EffectivePath)))`.

### 5.3 Unified Action Registry
Keep `Register_SSLLoaderAction` as the single registration point for post-load / pre-unload actions. Because `TTaurusTLSOnLoadAction = procedure(AAction: TOpenSSLLoadAction) of object;`, `TaurusTLS_LegacyProviders.pas` implements an internal manager instance to handle the callback.

---

## 6. Execution Lifecycle Sequence

| Phase | Dynamic Mode (`{$IFNDEF OPENSSL_STATIC_LINK_MODEL}`) | Static Mode (`{$IFDEF OPENSSL_STATIC_LINK_MODEL}`) |
| :--- | :--- | :--- |
| **Unit `initialization`** | Registers action method with `Register_SSLLoaderAction`. | Calls `OSSL_PROVIDER_add_builtin(nil, 'legacy', @ossl_legacy_provider_init)`. |
| **Header Binding Stage** | `TaurusTLSLoader.Load` executes `GLibCryptoLoadList` (resolving `OSSL_PROVIDER_*`). | Built directly into executable at link time. |
| **Search Path Stage** | Invokes `OSSL_PROVIDER_set_default_search_path` using `ProviderSearchPath` (or `OpenSSLPath`). | N/A (Embedded). |
| **Provider Activation Stage** | Loader fires `GOnLoadActionList[i](osaLoad)`: loads `default` and `legacy`. | Loads `default` and `legacy` via `OSSL_PROVIDER_load`. |
| **Provider Teardown Stage** | Loader fires `GOnLoadActionList[i](osaUnload)` in reverse: unloads `legacy` and `default`. | Unit `finalization` unloads `legacy` and `default`. |
| **Engine Unload Stage** | Loader clears symbols (`GUnLoadList`) and frees DLL handles. | Application process termination. |

---

## 7. Key Safeguards & Checklist for Developers

1. **Mandatory `default` Provider Retention:** Explicitly loading `legacy` disables OpenSSL's implicit fallback. `default` must always be loaded alongside `legacy`.
2. **Strict Shutdown Symmetry:** Providers **must** be unloaded during `osaUnload` before `FreeLibrary(FLibCrypto)` is called. Unloading a provider after freeing `libcrypto` results in immediate Access Violations.
3. **Graceful Handling of Missing Module:** If `OSSL_PROVIDER_load(nil, 'legacy')` returns `nil` (e.g. `legacy.dll` missing), the error must be captured cleanly rather than causing an unhandled crash, allowing the application to continue with standard algorithms if desired.
