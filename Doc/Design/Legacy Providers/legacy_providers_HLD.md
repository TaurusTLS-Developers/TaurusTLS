# TaurusTLS — Legacy Provider Integration Design Document

## 1. Overview & Objectives

In OpenSSL 3.x and 4.x, legacy cryptographic algorithms (such as Blowfish, RC4, MD4, RIPEMD, and DES) were moved out of the standard library core into a dedicated external module known as the **Legacy Provider** (`legacy.dll` / `legacy.so` / `liblegacy.a`).

By default, OpenSSL only loads the `default` provider. To support legacy servers or clients while preserving TaurusTLS’s modular architecture, this document outlines the high-level design for implementing legacy provider support in **TaurusTLS**.

### Key Architectural Objectives

1. **Modular Opt-In Design:** Legacy provider code remains isolated in `TaurusTLS_LegacyProviders.pas`. Simply adding this unit to a project's `uses` clause enables legacy support without polluting the core engine.
2. **Dual-Model Support:**
* **Dynamic Linking (`{$IFNDEF OPENSSL_STATIC_LINK_MODEL}`):** Uses TaurusTLS's registration pattern via `Register_SSLLoader` to defer symbol binding until `libcrypto` is loaded, followed by post-load hook execution.
* **Static Linking (`{$IFDEF OPENSSL_STATIC_LINK_MODEL}`):** Statically links `liblegacy` and registers `OSSL_provider_init_legacy` via `OSSL_PROVIDER_add_builtin` during unit `initialization`.


3. **Provider Search Path Flexibility:** Exposes configuration to set custom search directories (`OSSL_PROVIDER_set_default_search_path`) for dynamic provider binaries (e.g., `.\modules\` or `.\providers\`).
4. **Mandatory Default Provider Retention:** Ensures the `default` provider is explicitly loaded alongside `legacy` so modern algorithms (e.g., AES-GCM, TLS 1.3 suites) remain functional.

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
| 1. Register_SSLLoader(...)         |               | 1. Link liblegacy (.lib / .a)      |
| 2. Register_SSLPostLoadHook(...)   |               | 2. OSSL_PROVIDER_add_builtin(...)  |
| 3. Set Provider Search Path        |               | 3. OSSL_PROVIDER_load('default')   |
| 4. OSSL_PROVIDER_load('default')   |               | 4. OSSL_PROVIDER_load('legacy')    |
| 5. OSSL_PROVIDER_load('legacy')    |               +------------------------------------+
+------------------------------------+

```

---

## 3. Dynamic Linking Model Strategy (`{$IFNDEF OPENSSL_STATIC_LINK_MODEL}`)

Because TaurusTLS dynamic loading executes lazily when the user or engine initializes OpenSSL (and not during Pascal unit `initialization`), C-API calls cannot be made at startup.

### 3.1 Symbol Registration Hook

During unit `initialization`, `TaurusTLS_LegacyProviders.pas` registers a loader procedure into `GLibCryptoLoadList` using the existing `Register_SSLLoader` framework.

* **Target Unit:** `TaurusTLS_LegacyProviders.pas`
* **Registration Method:**
```pascal
Register_SSLLoader(LoadLegacyProviderSymbols, 'LibCrypto');

```


* **Binding Action:** `LoadLegacyProviderSymbols` binds provider function pointers already imported by `TaurusTLSHeaders_provider.pas` (e.g., `OSSL_PROVIDER_load`, `OSSL_PROVIDER_unload`, `OSSL_PROVIDER_set_default_search_path`).

### 3.2 Provider Activation & Search Path Hook

Symbol resolution alone does not activate the provider. A post-load hook executes immediately after `libcrypto` symbol binding completes.

1. **Provider Search Path Configuration:**
* Before calling `OSSL_PROVIDER_load`, the loader checks if a custom search path is specified in `TaurusTLSLoader` (e.g., `TTaurusTLSLoader.ProviderSearchPath`).
* If set, it invokes `OSSL_PROVIDER_set_default_search_path(nil, PAnsiChar(Path))`.


2. **Dual Provider Loading:**
* Invokes `OSSL_PROVIDER_load(nil, 'default')` (prevents implicit provider unload).
* Invokes `OSSL_PROVIDER_load(nil, 'legacy')`.



---

## 4. Static Linking Model Strategy (`{$IFDEF OPENSSL_STATIC_LINK_MODEL}`)

In static compilation mode (e.g., iOS, Android, or statically linked Windows/Linux binaries), `legacy.dll` / `legacy.so` is not present on disk. The static library (`liblegacy.a` or `liblegacy.lib`) is embedded directly into the application executable.

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

Because OpenSSL cannot dynamically discover static symbols via `dlopen`/`LoadLibrary`, the entry-point symbol `OSSL_provider_init_legacy` must be registered manually into OpenSSL's internal provider table:

1. **External Declaration:**
```pascal
function OSSL_provider_init_legacy(handle: POSSL_CORE_HANDLE; 
  in_struct: POSSL_DISPATCH; out_struct: PPOSSL_DISPATCH; 
  prov_ctx: PPOSSL_CALLBACK): Integer; cdecl; external;

```


2. **Initialization Sequence:** Executed directly inside `initialization` (or loader startup):
* `OSSL_PROVIDER_add_builtin(nil, 'legacy', @OSSL_provider_init_legacy);`
* `OSSL_PROVIDER_load(nil, 'default');`
* `OSSL_PROVIDER_load(nil, 'legacy');`



---

## 5. Core Loader Extensions (`TaurusTLSLoader.pas`)

To support configurable search paths and clean post-load hooks, `TaurusTLSLoader.pas` requires two minor enhancements:

### 5.1 Provider Search Path Support

Add a thread-safe global setting or property on `TTaurusTLSLoader`:

* **Property:** `ProviderSearchPath: string`
* **Responsibility:** Stores custom pathing for provider binaries.
* **Execution Timing:** Applied immediately after `libcrypto` dynamic symbols are resolved and before any `OSSL_PROVIDER_load` calls occur.

### 5.2 Post-Load Hook Registry

Introduce a post-load callback mechanism (if not already present in `TaurusTLSLoader`):

* **Registry List:** `GLibCryptoPostLoadList: TList<TProc>` or dedicated callback hook.
* **Purpose:** Allows optional units like `TaurusTLS_LegacyProviders.pas` to execute activation routines automatically once dynamic library binding finishes.

---

## 6. Execution Lifecycle Sequence

| Phase | Dynamic Mode (`{$IFNDEF OPENSSL_STATIC_LINK_MODEL}`) | Static Mode (`{$IFDEF OPENSSL_STATIC_LINK_MODEL}`) |
| --- | --- | --- |
| **Unit `initialization**` | Calls `Register_SSLLoader` to add symbol loader to `GLibCryptoLoadList`. Registers post-load hook. | Registers `OSSL_provider_init_legacy` via `OSSL_PROVIDER_add_builtin`. |
| **Engine Load Stage** | `TaurusTLSLoader.Load` binds function pointers from `libcrypto-3`. | N/A (Symbols linked at build time). |
| **Provider Search Path Stage** | Invokes `OSSL_PROVIDER_set_default_search_path` if path is configured. | N/A (Built directly into binary). |
| **Provider Activation Stage** | Post-load hook executes `OSSL_PROVIDER_load('default')` and `OSSL_PROVIDER_load('legacy')`. | Calls `OSSL_PROVIDER_load('default')` and `OSSL_PROVIDER_load('legacy')`. |
| **Unit `finalization**` | Unloads legacy and default provider handles via `OSSL_PROVIDER_unload`. | Unloads legacy and default provider handles via `OSSL_PROVIDER_unload`. |

---

## 7. Key Safeguards & Checklist for Developers

1. **Never Omit the `default` Provider:** Explicitly loading the `legacy` provider overrides OpenSSL's implicit fallback mechanism. Loading `legacy` without explicitly loading `default` will break modern ciphers (AES-GCM, TLS 1.3).
2. **Thread-Safety:** Provider registration modifies global `OSSL_LIB_CTX` state. Registration **must** occur during application bootstrap before multi-threaded `TTaurusTLSIOHandlerSocket` operations begin.
3. **Deployment Assets:** When deploying dynamic builds, ensure `legacy.dll` / `legacy.so` is bundled in the application directory or designated provider search directory alongside `libcrypto-3` and `libssl-3`.