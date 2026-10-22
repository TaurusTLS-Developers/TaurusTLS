{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2024 TaurusTLS Developers, All Rights Reserved              * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 – 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  * }
{ ****************************************************************************** }
{$I TaurusTLSCompilerDefines.inc}
/// <summary>
///   Shared OpenSSL lifecycle, configuration, and provider action registration
///   for dynamic binding and static linking.
/// </summary>
/// <remarks>
///   Dynamic builds load shared libraries and bind TaurusTLSHeaders_* procedural
///   variables. Static builds call linked routines directly. Both models expose
///   the same loader interface and dispatch initialization and cleanup actions.
///   In static builds, Unload runs cleanup callbacks and resets loader state.
///   The OpenSSL routines remain part of the application.
/// </remarks>
unit TaurusTLSLoader;

{$I TaurusTLSLinkDefines.inc}

interface

uses
  Classes,
  IdGlobal,
  IdCTypes,
  IdThreadSafe;

{$IF NOT DECLARED(TIdLibHandle)}
type
  {$IFDEF FPC}
  TIdLibHandle = {$IFDEF WINDOWS}PtrUInt{$ELSE}PtrInt{$ENDIF};
  {$ELSE}
  TIdLibHandle = THandle;
  {$ENDIF}

  {$IFDEF WINCE}
  TIdLibFuncName = TIdUnicodeString;
  PIdLibFuncNameChar = PWideChar;
  {$ELSE}
  TIdLibFuncName = String;
  PIdLibFuncNameChar = PChar;
  {$ENDIF}

const
  {$IFDEF FPC}
  IdNilHandle = {$IFDEF WINDOWS}PtrUInt(0){$ELSE}PtrInt(0){$ENDIF};
  {$ELSE}
  IdNilHandle = THandle(0);
  {$ENDIF}
{$IFEND}

type
  /// <summary>Internal lifecycle states, including operations in progress.</summary>
  TTaurusTLSLoaderStateAll = (
    lsLoading, lsUnloading, lsNotLoaded, lsLoadedReady, lsLoadedFailed);
  /// <summary>Stable states exposed to applications; transitions report lsNotLoaded.</summary>
  TTaurusTLSLoaderState = lsNotLoaded..lsLoadedFailed;

  { IOpenSSLLoader }

  /// <summary>Identifies a lifecycle action dispatched in either linking model.</summary>
  TOpenSSLLoadAction = (
    /// <summary>Initializes consumers after configuration and, in dynamic builds, symbol binding.</summary>
    osaLoad,
    /// <summary>Cleans up consumers before dynamic symbols are unbound or static loader state is reset.</summary>
    osaUnload);

  /// <summary>Instance method used to initialize or release OpenSSL-dependent resources.</summary>
  /// <param name="AAction">The initialization or cleanup action to perform.</param>
  /// <remarks>
  ///   OpenSSL routines are callable during both actions. A load exception aborts
  ///   loading and rolls back completed actions. Cleanup exceptions are suppressed
  ///   so remaining actions can run. The loader does not own the callback object.
  /// </remarks>
  TTaurusTLSOnLoadAction = procedure(AAction: TOpenSSLLoadAction) of object;

  /// <summary>Provides a common lifecycle and configuration API for both linking models.</summary>
  /// <remarks>
  ///   Load is idempotent, not reference counted. A failure blocks later Load
  ///   calls until Unload resets the failure state. Static builds retain linked
  ///   code and use the loader for configuration and lifecycle actions.
  /// </remarks>
  IOpenSSLLoader = interface
    ['{BBB0F670-CC26-42BC-A9E0-33647361941A}']
    /// <summary>Returns the dynamic library search directory, or an empty string in static builds.</summary>
    function GetOpenSSLPath: string;
    /// <summary>Returns dynamic library filename suffixes, or an empty string in static builds.</summary>
    function GetSSLLibVersions: string;
    /// <summary>Sets the dynamic library directory; ignored in static builds.</summary>
    procedure SetOpenSSLPath(const Value: string);
    /// <summary>Returns the effective filename while loaded, otherwise the configured filename.</summary>
    function GetConfigFile: string;
    /// <summary>Selects a configuration filename while the loader is inactive.</summary>
    procedure SetConfigFile(const Value: string);
    /// <summary>Returns the loader-owned symbol-binding diagnostic list.</summary>
    function GetFailedToLoad: TStringList;

    /// <summary>Loads and binds dynamic libraries or initializes the static loader lifecycle.</summary>
    /// <returns>True on success or when already loaded; False on a soft failure or blocked retry.</returns>
    /// <remarks>
    ///   Applies configuration before dispatching osaLoad. Failures unwind completed
    ///   actions and dynamic bindings and trip the circuit breaker. Configuration,
    ///   version-validation, and callback exceptions propagate to the caller.
    /// </remarks>
    function Load: Boolean;
    /// <summary>Sets dynamic library filename suffixes; ignored in static builds.</summary>
    procedure SetSSLLibVersions(const AValue: string);
    /// <summary>Runs cleanup, releases dynamic bindings, and resets the failure state and diagnostics.</summary>
    /// <remarks>
    ///   Repeated calls are safe. Static code remains linked. The configured
    ///   filename is retained; only the effective loaded filename is cleared.
    /// </remarks>
    procedure Unload; overload;
    /// <summary>Runs cleanup and controls whether subsequent Load calls may retry.</summary>
    /// <param name="AResetFailState">
    ///   True clears the circuit breaker and diagnostics. False preserves
    ///   diagnostics and blocks Load until an explicit reset.
    /// </param>
    /// <remarks>False is used for internal failure rollback.</remarks>
    procedure Unload(const AResetFailState: Boolean); overload;

    /// <summary>True only after configuration and every load callback complete successfully.</summary>
    /// <remarks>False during load, unload, and rollback in both linking models.</remarks>
    function IsLoaded: Boolean;
    /// <summary>Returns an atomic readiness snapshot without acquiring the lifecycle lock.</summary>
    /// <remarks>
    ///   Internal loading/unloading states report lsNotLoaded. Failed state blocks
    ///   retries until explicit Unload. A snapshot does not protect live crypto
    ///   objects or operations against concurrent unloading.
    /// </remarks>
    function GetState: TTaurusTLSLoaderState;

    /// <summary>Current stable readiness state; independent of library-handle presence.</summary>
    property State: TTaurusTLSLoaderState read GetState;

    /// <summary>Ordered filename suffixes used to find dynamic OpenSSL libraries.</summary>
    /// <remarks>
    ///   Entries use the platform directory-list delimiter (semicolon on Windows,
    ///   colon on POSIX). Changes are rejected while loaded or a crypto handle is
    ///   active. Static builds return an empty string and ignore assignments.
    /// </remarks>
    property SSLLibVersions: string read GetSSLLibVersions write SetSSLLibVersions;
    /// <summary>Directory searched for dynamic OpenSSL libraries.</summary>
    /// <remarks>
    ///   Nonempty values receive a trailing path delimiter. An empty value uses
    ///   the platform library search. Changes are rejected while loaded or a
    ///   crypto handle is active. Static builds return empty and ignore assignments.
    /// </remarks>
    property OpenSSLPath: string read GetOpenSSLPath write SetOpenSSLPath;
    /// <summary>Explicit configuration filename, or the effective filename while loaded.</summary>
    /// <remarks>
    ///   Both models accept relative and Unicode paths. Load expands an explicit
    ///   path, checks that it names an existing file, and applies it to the default
    ///   OpenSSL context using UTF-8. Invalid paths and configuration load failures
    ///   raise exceptions. An empty value only queries OpenSSL's default filename;
    ///   this branch does not explicitly load that file. Discovery can reflect a
    ///   C-runtime environment different from Delphi's process environment.
    ///   Changes are rejected while loaded or a crypto handle is active; assigning
    ///   the existing configured value is a no-op. Unload retains the configured
    ///   value and clears the effective filename.
    /// </remarks>
    property ConfigFile: string read GetConfigFile write SetConfigFile;
    /// <summary>Loader-owned list of symbols that could not be bound dynamically.</summary>
    /// <remarks>
    ///   Static builds have no binding diagnostics. This list is distinct from
    ///   the circuit breaker: a failure may block Load even when the list is empty.
    ///   Internal rollback preserves entries; Unload with reset clears them.
    ///   Do not free the returned list.
    /// </remarks>
    property FailedToLoad: TStringList read GetFailedToLoad;
  end;

  /// <summary>Header registration procedure that binds dynamic OpenSSL routine addresses.</summary>
  /// <param name="ADllHandle">The loaded crypto or SSL library handle.</param>
  /// <param name="LibVersion">The numeric OpenSSL version shifted right by 12 bits for header binding.</param>
  /// <param name="AFailed">Loader-owned list receiving symbol-binding diagnostics.</param>
  TOpenSSLLoadProc = procedure(const ADllHandle: TIdLibHandle;
    LibVersion: TIdC_UINT; const AFailed: TStringList);

  /// <summary>Header cleanup procedure that resets dynamic procedural variables to nil.</summary>
  TOpenSSLUnloadProc = procedure;

var
  /// <summary>Shared thread-safe flag allocated and released by this unit.</summary>
  /// <remarks>
  ///   The current loader implementations do not update this flag. Use the
  ///   singleton loader's IsLoaded method to inspect loader state.
  /// </remarks>
  SSLIsLoaded: TIdThreadSafeBoolean = nil;

/// <summary>Returns the singleton loader selected by OPENSSL_STATIC_LINK_MODEL.</summary>
/// <returns>The dynamic or static loader interface, available after unit initialization.</returns>
function GetOpenSSLLoader: IOpenSSLLoader;

/// <summary>Registers a header symbol-binding procedure for dynamic loads.</summary>
/// <param name="LoadProc">Procedure that binds a header unit's procedural variables.</param>
/// <param name="module_name">Case-sensitive library selector: LibCrypto or LibSSL.</param>
/// <remarks>
///   Registration is protected by the registration lock. Static loading does not
///   invoke these procedures because its external routines are linked directly.
/// </remarks>
procedure Register_SSLLoader(LoadProc: TOpenSSLLoadProc; const module_name: string);

/// <summary>Registers a dynamic symbol-reset procedure, run in reverse registration order.</summary>
/// <param name="UnloadProc">Procedure that clears a header unit's procedural variables.</param>
/// <remarks>Runs after lifecycle cleanup actions and before dynamic library release.</remarks>
procedure Register_SSLUnloader(UnloadProc: TOpenSSLUnloadProc);

/// <summary>Registers initialization and cleanup actions for both linking models.</summary>
/// <param name="AActionProc">Instance method whose object must remain valid while registered.</param>
/// <remarks>
///   Intended for provider and other OpenSSL-dependent resource initialization.
///   osaLoad runs in registration order after configuration and dynamic binding.
///   osaUnload runs in reverse order while routines remain callable. If loading
///   fails, only actions whose osaLoad completed receive rollback cleanup.
///   Repeated Load calls while loaded do not redispatch actions. Registrations
///   persist across load cycles; register once, before loading. There is no
///   unregistration API, and registrations do not retain callback objects.
/// </remarks>
procedure Register_SSLLoaderAction(const AActionProc: TTaurusTLSOnLoadAction);

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IF NOT DECLARED(LoadLibFunction)}
  {$DEFINE LOADLIB_UNAVAIL}
  {$IFDEF LOADLIB_UNAVAIL}
/// <summary>Resolves a routine address from a loaded dynamic library handle.</summary>
function LoadLibFunction(const ALibHandle: TIdLibHandle; const AProcName: TIdLibFuncName): Pointer;
  {$ENDIF}
{$IFEND}
{$ENDIF}

implementation

uses
{$IFDEF HAS_UNIT_Generics_Collections}
  System.Generics.Collections,
{$ENDIF}
  TaurusTLSExceptionHandlers,
  {$IFDEF FPC}
  IdGlobalProtocols,
  {$ENDIF}
  TaurusTLS_ResourceStrings,
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  {$IFDEF WINDOWS}
    {$IFDEF VCL_XE2_OR_ABOVE}WinAPI.Windows{$ELSE}Windows{$ENDIF},
  {$ENDIF}
  {$IFDEF FPC}
    dynlibs,
  {$ENDIF}
{$ENDIF}
{$IFDEF VCL_2010_OR_ABOVE}
  System.IOUtils,
  System.AnsiStrings,
{$ENDIF}
  TaurusTLSConsts,
  TaurusTLSHeaders_crypto,
  TaurusTLSHeaders_conf,
  {$IFNDEF FPC}
  SyncObjs,
  {$ENDIF}
  SysUtils;

resourcestring
  RSOSSLLoaderLifecycleInProgress =
    'Cannot call %s while the OpenSSL loader is loading or unloading';

{$IFNDEF HAS_UNIT_Generics_Collections}
type
  TMethodList = class
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} private
    FList: TList;
    function Get(Index: NativeInt): TTaurusTLSOnLoadAction;
    procedure Put(Index: NativeInt; const Value: TTaurusTLSOnLoadAction);
    function NewItem(const AItem: TTaurusTLSOnLoadAction): PMethod;
    procedure ReleaseItem(AItem: PMethod);
    function GetCount: NativeInt;
  public
    constructor Create;
    destructor Destroy; override;

    function Add(Item: TTaurusTLSOnLoadAction): NativeInt;
    procedure Delete(Index: NativeInt);

    property Count: NativeInt read GetCount;
    property Items[Index: NativeInt]: TTaurusTLSOnLoadAction read Get write Put; default;
  end;

{ TMethodList }

constructor TMethodList.Create;
begin
  inherited Create;
  FList := TList.Create;
end;

destructor TMethodList.Destroy;
var
  i: NativeInt;
begin
  if Assigned(FList) then
  begin
    for i := 0 to FList.Count - 1 do
      ReleaseItem(FList[i]);
    FreeAndNil(FList);
  end;
  inherited Destroy;
end;

{$IFDEF DCC}{$WARN UNSAFE_CAST OFF}{$ENDIF}
{$IFDEF DCC}{$WARN UNSAFE_CODE OFF}{$ENDIF}

function TMethodList.Add(Item: TTaurusTLSOnLoadAction): NativeInt;
begin
  if Assigned(TMethod(Item).Code) and Assigned(TMethod(Item).Data) then
    Result := FList.Add(NewItem(Item))
  else
    Result := -1;
end;

procedure TMethodList.Delete(Index: NativeInt);
var
  lItem: PMethod;
begin
  if (Index >= 0) and (Index < Count) then
  begin
    lItem := FList.Items[Index];
    try
      FList.Delete(Index);
    finally
      ReleaseItem(lItem);
    end;
  end;
end;

function TMethodList.GetCount: NativeInt;
begin
  Result := FList.Count;
end;

function TMethodList.Get(Index: NativeInt): TTaurusTLSOnLoadAction;
var
  lItem: PMethod;
begin
  lItem := FList[Index];
  if Assigned(lItem) then
  begin
    TMethod(Result).Code := lItem^.Code;
    TMethod(Result).Data := lItem^.Data;
  end
  else
  begin
    TMethod(Result).Code := nil;
    TMethod(Result).Data := nil;
  end;
end;

procedure TMethodList.Put(Index: NativeInt; const Value: TTaurusTLSOnLoadAction);
var
  lOldItem, lNewItem: PMethod;
begin
  if Assigned(TMethod(Value).Code) and Assigned(TMethod(Value).Data) then
  begin
    lNewItem := NewItem(Value);
    lOldItem := FList[Index];
    FList[Index] := lNewItem;
    ReleaseItem(lOldItem);
  end
  else
    Delete(Index);
end;

function TMethodList.NewItem(const AItem: TTaurusTLSOnLoadAction): PMethod;
begin
  Result := nil;
  try
    New(Result);
    Result^.Code := TMethod(AItem).Code;
    Result^.Data := TMethod(AItem).Data;
  except
    ReleaseItem(Result);
    raise;
  end;
end;

procedure TMethodList.ReleaseItem(AItem: PMethod);
begin
  if Assigned(AItem) then
    Dispose(AItem);
end;

{$IFDEF DCC}{$WARN UNSAFE_CAST DEFAULT}{$ENDIF}
{$IFDEF DCC}{$WARN UNSAFE_CODE DEFAULT}{$ENDIF}
{$ENDIF}

var
  GOpenSSLLoader: IOpenSSLLoader = nil;
  GRegistrationLock: TIdCriticalSection = nil;
{$IFDEF HAS_UNIT_Generics_Collections}
  GLibCryptoLoadList: TList<TOpenSSLLoadProc> = nil;
  GLibSSLLoadList: TList<TOpenSSLLoadProc> = nil;
  GUnLoadList: TList<TOpenSSLUnloadProc> = nil;
  GOnLoadActionList: TList<TTaurusTLSOnLoadAction> = nil;
{$ELSE}
  GLibCryptoLoadList: TList = nil;
  GLibSSLLoadList: TList = nil;
  GUnLoadList: TList = nil;
  GOnLoadActionList: TMethodList = nil;
{$ENDIF}

function GetOpenSSLLoader: IOpenSSLLoader;
begin
  Result := GOpenSSLLoader;
end;

/// <summary>Creates the registration lock when a header registers before loader initialization.</summary>
procedure EnsureRegistrationLock;
begin
  if not Assigned(GRegistrationLock) then
    GRegistrationLock := TIdCriticalSection.Create;
end;

procedure Register_SSLLoader(LoadProc: TOpenSSLLoadProc; const module_name: string);
begin
  EnsureRegistrationLock;
  GRegistrationLock.Acquire;
  try
    if GLibCryptoLoadList = nil then
{$IFDEF HAS_UNIT_Generics_Collections}
      GLibCryptoLoadList := TList<TOpenSSLLoadProc>.Create;
{$ELSE}
      GLibCryptoLoadList := TList.Create;
{$ENDIF}

    if GLibSSLLoadList = nil then
{$IFDEF HAS_UNIT_Generics_Collections}
      GLibSSLLoadList := TList<TOpenSSLLoadProc>.Create;
{$ELSE}
      GLibSSLLoadList := TList.Create;
{$ENDIF}

    if module_name = 'LibCrypto' then
      GLibCryptoLoadList.Add(LoadProc)
    else if module_name = 'LibSSL' then
      GLibSSLLoadList.Add(LoadProc)
    else
      raise ETaurusTLSError.CreateFmt(ROSUnrecognisedLibName, [module_name]);
  finally
    GRegistrationLock.Release;
  end;
end;

procedure Register_SSLUnloader(UnloadProc: TOpenSSLUnloadProc);
begin
  EnsureRegistrationLock;
  GRegistrationLock.Acquire;
  try
    if GUnLoadList = nil then
{$IFDEF HAS_UNIT_Generics_Collections}
      GUnLoadList := TList<TOpenSSLUnloadProc>.Create;
{$ELSE}
      GUnLoadList := TList.Create;
{$ENDIF}
    GUnLoadList.Add(UnloadProc);
  finally
    GRegistrationLock.Release;
  end;
end;

procedure Register_SSLLoaderAction(const AActionProc: TTaurusTLSOnLoadAction);
begin
  EnsureRegistrationLock;
  GRegistrationLock.Acquire;
  try
    if GOnLoadActionList = nil then
{$IFDEF HAS_UNIT_Generics_Collections}
      GOnLoadActionList := TList<TTaurusTLSOnLoadAction>.Create;
{$ELSE}
      GOnLoadActionList := TMethodList.Create;
{$ENDIF}
    GOnLoadActionList.Add(AActionProc);
  finally
    GRegistrationLock.Release;
  end;
end;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFDEF LOADLIB_UNAVAIL}
function LoadLibFunction(const ALibHandle: TIdLibHandle; const AProcName: TIdLibFuncName): Pointer;
begin
  Result := {$IFDEF WINDOWS}{$IFDEF VCL_XE2_OR_ABOVE}WinAPI.{$ENDIF}Windows.{$ENDIF}GetProcAddress(
    ALibHandle, PIdLibFuncNameChar(AProcName));
end;
{$ENDIF}
{$ENDIF}

type
  { TOpenSSLBaseLoader }

  /// <summary>
  ///   Abstract base loader providing synchronized state management, configuration
  ///   application, and action callback dispatching for all linking models.
  /// </summary>
  TOpenSSLBaseLoader = class(TInterfacedObject, IOpenSSLLoader)
  strict protected
    FLoaderLock: TIdCriticalSection;
    // Delphi's generic TInterlocked overloads require class types. Keep the
    // ordinal storage private; all reads/writes use typed atomic accessors.
    FState: Integer;
    FLastLoadActionIdx: NativeInt;
    FConfigFile: string;
    FEffectiveConfigFile: string;
    /// <summary>Reads the internal lifecycle state atomically.</summary>
    function GetInternalState: TTaurusTLSLoaderStateAll;
    /// <summary>Publishes the internal lifecycle state atomically.</summary>
    procedure SetInternalState(const AState: TTaurusTLSLoaderStateAll);
    /// <summary>Performs cleanup while the caller holds the lifecycle lock.</summary>
    procedure UnloadInternal(const AResetFailState: Boolean);

// --- OpenSSL API Wrappers (Static vs Dynamic Bridge) ---
    /// <summary>Initializes OpenSSL directly in static builds or through an assigned dynamic routine.</summary>
    class procedure SslInitCrypto(opts: TIdC_UINT64; settings: pointer); static; {$IFDEF USE_INLINE}inline;{$ENDIF}
    /// <summary>Loads configuration into the supplied context; returns -1 if the dynamic routine is absent.</summary>
    class function SslModulesLoadFileEx(libctx: pointer; filename, appname: PIdAnsiChar; flags: TIdC_ULONG): TIdC_INT; static; {$IFDEF USE_INLINE}inline;{$ENDIF}
    /// <summary>Obtains an OpenSSL-allocated discovery filename; release it with SslFree.</summary>
    class function SslGet1DefaultConfigFile: PIdAnsiChar; static; {$IFDEF USE_INLINE}inline;{$ENDIF}
    /// <summary>Releases OpenSSL-owned memory through the matching linking model; accepts nil.</summary>
    class procedure SslFree(addr: Pointer); static; {$IFDEF USE_INLINE}inline;{$ENDIF}

// --- Method Pointer Helpers (DCC Unsafe Cast Warning Suppression) ---
    /// <summary>Checks both the code and instance pointers of a lifecycle action.</summary>
    class function IsActionAssigned(const AAction: TTaurusTLSOnLoadAction): Boolean; static; {$IFDEF USE_INLINE}inline;{$ENDIF}
    /// <summary>Clears both pointers of a lifecycle action.</summary>
    class procedure ClearAction(var AAction: TTaurusTLSOnLoadAction); static; {$IFDEF USE_INLINE}inline;{$ENDIF}

    // --- Virtual Template Hooks ---
    /// <summary>Performs model-specific loading, configuration, and action dispatch under the loader lock.</summary>
    function DoLoad: Boolean; virtual; abstract;
    /// <summary>Cleans up completed actions and any model-specific bindings under the loader lock.</summary>
    procedure DoUnload; virtual; abstract;
    /// <summary>Reports whether partial initialization requires cleanup even when IsLoaded is false.</summary>
    function NeedUnloadCleanup: Boolean; virtual;
    /// <summary>Reports whether a dynamic crypto handle prevents configuration changes.</summary>
    function IsActiveHandlePresent: Boolean; virtual;

    // --- Configuration and Lifecycle Helpers ---
    /// <summary>Loads an explicit configuration or records the native discovery filename without loading it.</summary>
    procedure ApplyConfiguration; virtual;
    /// <summary>Invokes registered load actions in order and records each successfully completed action.</summary>
    procedure DispatchLoadActions; virtual;
    /// <summary>Runs completed actions in reverse order, suppresses cleanup exceptions, and resets progress.</summary>
    procedure RollbackLoadActions; virtual;
    /// <summary>Rejects versions below min_supported_ssl_version with an unsupported-version exception.</summary>
    function CheckOpenSSLVersion(const AVersionNo: TIdC_ULONG): Boolean; virtual;

    // --- IOpenSSLLoader Abstract/Virtual Property Accessors ---
    /// <summary>Returns the model-specific dynamic library path.</summary>
    function GetOpenSSLPath: string; virtual; abstract;
    /// <summary>Updates the model-specific path while inactive; static implementations ignore it.</summary>
    procedure SetOpenSSLPath(const Value: string); virtual; abstract;
    /// <summary>Returns the model-specific dynamic filename suffix list.</summary>
    function GetSSLLibVersions: string; virtual; abstract;
    /// <summary>Updates the model-specific filename suffix list while inactive.</summary>
    procedure SetSSLLibVersions(const AValue: string); virtual; abstract;
    /// <summary>Returns the effective filename while loaded, otherwise the configured filename.</summary>
    function GetConfigFile: string; virtual;
    /// <summary>Validates path characters and rejects configuration changes while active.</summary>
    procedure SetConfigFile(const Value: string); virtual;
    /// <summary>Returns the model-owned binding diagnostic list.</summary>
    function GetFailedToLoad: TStringList; virtual; abstract;
    /// <summary>Reads the stable public state without taking the lifecycle lock.</summary>
    function GetState: TTaurusTLSLoaderState;
    /// <summary>True only when the common state is lsLoadedReady.</summary>
    function IsLoaded: Boolean;
  public
    /// <summary>Creates the loader lock and initializes unloaded state with no completed actions.</summary>
    constructor Create; virtual;
    /// <summary>Releases the loader lock.</summary>
    destructor Destroy; override;

    // Non-virtual template methods managing thread locking and circuit breakers
    /// <summary>Runs the synchronized load template with idempotency, rollback, and circuit-breaker checks.</summary>
    function Load: Boolean;
    /// <summary>Runs the cleanup template and resets failure state and binding diagnostics.</summary>
    procedure Unload; overload;
    /// <summary>Runs synchronized cleanup, preserving or resetting failure state as requested.</summary>
    procedure Unload(const AResetFailState: Boolean); overload;

    property State: TTaurusTLSLoaderState read GetState;
    property OpenSSLPath: string read GetOpenSSLPath write SetOpenSSLPath;
    property ConfigFile: string read GetConfigFile write SetConfigFile;
    property FailedToLoad: TStringList read GetFailedToLoad;
  end;

{ TOpenSSLBaseLoader }

constructor TOpenSSLBaseLoader.Create;
begin
  inherited Create;
  FLoaderLock := TIdCriticalSection.Create;
  FLastLoadActionIdx := -1;
  SetInternalState(lsNotLoaded);
  FConfigFile := '';
  FEffectiveConfigFile := '';
end;

destructor TOpenSSLBaseLoader.Destroy;
begin
  FreeAndNil(FLoaderLock);
  inherited Destroy;
end;

class procedure TOpenSSLBaseLoader.SslInitCrypto(opts: TIdC_UINT64; settings: pointer);
begin
{$IFDEF OPENSSL_STATIC_LINK_MODEL}
  OPENSSL_init_crypto(opts, settings);
{$ELSE}
  if Assigned(OPENSSL_init_crypto) then
    OPENSSL_init_crypto(opts, settings);
{$ENDIF}
end;

class function TOpenSSLBaseLoader.SslModulesLoadFileEx(libctx: pointer;
  filename, appname: PIdAnsiChar; flags: TIdC_ULONG): TIdC_INT;
begin
{$IFDEF OPENSSL_STATIC_LINK_MODEL}
  Result := CONF_modules_load_file_ex(libctx, filename, appname, flags);
{$ELSE}
  if Assigned(CONF_modules_load_file_ex) then
    Result := CONF_modules_load_file_ex(libctx, filename, appname, flags)
  else
    Result := -1;
{$ENDIF}
end;

class function TOpenSSLBaseLoader.SslGet1DefaultConfigFile: PIdAnsiChar;
begin
{$IFDEF OPENSSL_STATIC_LINK_MODEL}
  Result := CONF_get1_default_config_file();
{$ELSE}
  if Assigned(CONF_get1_default_config_file) then
    Result := CONF_get1_default_config_file()
  else
    Result := nil;
{$ENDIF}
end;

class procedure TOpenSSLBaseLoader.SslFree(addr: Pointer);
begin
  if not Assigned(addr) then
    Exit;
{$IFDEF OPENSSL_STATIC_LINK_MODEL}
  OPENSSL_free(addr);
{$ELSE}
  if Assigned(OPENSSL_free) then
    OPENSSL_free(addr);
{$ENDIF}
end;

{$IFDEF DCC}
{$WARN UNSAFE_CAST OFF}
{$ENDIF}

class function TOpenSSLBaseLoader.IsActionAssigned(const AAction: TTaurusTLSOnLoadAction): Boolean;
begin
  Result := Assigned(TMethod(AAction).Code) and Assigned(TMethod(AAction).Data);
end;

class procedure TOpenSSLBaseLoader.ClearAction(var AAction: TTaurusTLSOnLoadAction);
begin
  TMethod(AAction).Code := nil;
  TMethod(AAction).Data := nil;
end;

{$IFDEF DCC}
{$WARN UNSAFE_CAST DEFAULT}
{$ENDIF}

function TOpenSSLBaseLoader.GetInternalState: TTaurusTLSLoaderStateAll;
begin
  {$IFDEF FPC}
  Result := TTaurusTLSLoaderStateAll(
    InterlockedCompareExchange(FState, Ord(lsNotLoaded), Ord(lsNotLoaded)));
  {$ELSE}
  Result := TTaurusTLSLoaderStateAll(
    TInterlocked.CompareExchange(FState, Ord(lsNotLoaded), Ord(lsNotLoaded)));
  {$ENDIF}
end;

procedure TOpenSSLBaseLoader.SetInternalState(const AState: TTaurusTLSLoaderStateAll);
begin
  {$IFDEF FPC}
  InterlockedExchange(FState, Ord(AState));
  {$ELSE}
  TInterlocked.Exchange(FState, Ord(AState));
  {$ENDIF}
end;

function TOpenSSLBaseLoader.GetState: TTaurusTLSLoaderState;
var
  LState: TTaurusTLSLoaderStateAll;
begin
  LState := GetInternalState;
  case LState of
    lsNotLoaded, lsLoadedReady, lsLoadedFailed:
      Result := LState;
  else
    Result := lsNotLoaded;
  end;
end;

function TOpenSSLBaseLoader.IsLoaded: Boolean;
begin
  Result := GetState = lsLoadedReady;
end;

function TOpenSSLBaseLoader.Load: Boolean;
begin
  if GetInternalState = lsLoadedFailed then
    Exit(False);

  FLoaderLock.Acquire;
  try
    case GetInternalState of
      lsLoading, lsUnloading:
        raise ETaurusTLSLoaderError.CreateFmt(RSOSSLLoaderLifecycleInProgress, ['Load']);
      lsLoadedFailed:
        Exit(False);
      lsLoadedReady:
        Exit(True);
    end;

    SetInternalState(lsLoading);
    FLastLoadActionIdx := -1;
    try
      Result := DoLoad;
    except
      // Preserve the original configuration/binding/callback exception.
      try
        UnloadInternal(False);
      except
        // UnloadInternal publishes failed state even if cleanup raises.
      end;
      raise;
    end;
    if Result then
      SetInternalState(lsLoadedReady)
    else
      UnloadInternal(False);
  finally
    FLoaderLock.Release;
  end;
end;

procedure TOpenSSLBaseLoader.Unload;
begin
  Unload(True);
end;

procedure TOpenSSLBaseLoader.Unload(const AResetFailState: Boolean);
begin
  FLoaderLock.Acquire;
  try
    if GetInternalState in [lsLoading, lsUnloading] then
      raise ETaurusTLSLoaderError.CreateFmt(RSOSSLLoaderLifecycleInProgress, ['Unload']);
    UnloadInternal(AResetFailState);
  finally
    FLoaderLock.Release;
  end;
end;

procedure TOpenSSLBaseLoader.UnloadInternal(const AResetFailState: Boolean);
var
  LWasReady: Boolean;
  LCompleted: Boolean;
begin
  LWasReady := IsLoaded;
  LCompleted := False;
  SetInternalState(lsUnloading);
  try
    // Keep cleanup predicates inside the state-restoration boundary.
    if LWasReady or NeedUnloadCleanup then
      DoUnload;
    if AResetFailState and Assigned(FailedToLoad) then
      FailedToLoad.Clear;
    LCompleted := True;
  finally
    FEffectiveConfigFile := '';
    if AResetFailState and LCompleted then
      SetInternalState(lsNotLoaded)
    else
      SetInternalState(lsLoadedFailed);
  end;
end;

function TOpenSSLBaseLoader.NeedUnloadCleanup: Boolean;
begin
  Result := (FLastLoadActionIdx >= 0);
end;

function TOpenSSLBaseLoader.IsActiveHandlePresent: Boolean;
begin
  Result := False;
end;

function TOpenSSLBaseLoader.CheckOpenSSLVersion(const AVersionNo: TIdC_ULONG): Boolean;
begin
  Result := (AVersionNo >= min_supported_ssl_version);
  if not Result then
    raise ETaurusTLSError.CreateFmt(RSOSSUnsupportedVersion, [AVersionNo]);
end;

procedure TOpenSSLBaseLoader.ApplyConfiguration;
var
  LNormalizedConfig: string;
  LDefaultConfig: PIdAnsiChar;
begin
  LNormalizedConfig := '';
  if FConfigFile <> '' then
  begin
    {$IFDEF VCL_2010_OR_ABOVE}
    LNormalizedConfig := TPath.GetFullPath(FConfigFile);

    if TDirectory.Exists(LNormalizedConfig) then
      raise ETaurusTLSConfigFilePathError.CreateFmt(
        RSOSSLConfigFileIsDirectory, [LNormalizedConfig]);

    if not TFile.Exists(LNormalizedConfig) then
      raise ETaurusTLSConfigFilePathError.CreateFmt(
        RSOSSLConfigFileNotFound, [LNormalizedConfig]);
    {$ELSE}
    LNormalizedConfig := ExpandFileName(FConfigFile);

    if DirectoryExists(LNormalizedConfig) then
      raise ETaurusTLSConfigFilePathError.CreateFmt(
        RSOSSLConfigFileIsDirectory, [LNormalizedConfig]);

    if not FileExists(LNormalizedConfig) then
      raise ETaurusTLSConfigFilePathError.CreateFmt(
        RSOSSLConfigFileNotFound, [LNormalizedConfig]);
    {$ENDIF}

    SslInitCrypto(OPENSSL_INIT_NO_LOAD_CONFIG, nil);

    if SslModulesLoadFileEx(nil, PIdAnsiChar(UTF8Encode(LNormalizedConfig)), nil, 0) <= 0 then
      ETaurusTLSConfigFileLoadError.RaiseException(
        Format(RSOSSLConfigFileLoadFailed, [LNormalizedConfig]));
  end
  else
  begin
    LDefaultConfig := SslGet1DefaultConfigFile();
    if Assigned(LDefaultConfig) then
    try
      LNormalizedConfig := UTF8ToString(LDefaultConfig);
    finally
      SslFree(LDefaultConfig);
    end;
  end;

  FEffectiveConfigFile := LNormalizedConfig;
end;

procedure TOpenSSLBaseLoader.DispatchLoadActions;
var
  i: Integer;
  LCount: Integer;
  LAction: TTaurusTLSOnLoadAction;
begin
  GRegistrationLock.Acquire;
  try
    if Assigned(GOnLoadActionList) then
      LCount := GOnLoadActionList.Count
    else
      LCount := 0;
  finally
    GRegistrationLock.Release;
  end;

  for i := 0 to LCount - 1 do
  begin
    GRegistrationLock.Acquire;
    try
      if Assigned(GOnLoadActionList) and (i < GOnLoadActionList.Count) then
        LAction := GOnLoadActionList[i]
      else
        ClearAction(LAction);
    finally
      GRegistrationLock.Release;
    end;

    if IsActionAssigned(LAction) then
    begin
      LAction(osaLoad);
      Inc(FLastLoadActionIdx);
    end;
  end;
end;

procedure TOpenSSLBaseLoader.RollbackLoadActions;
var
  i: NativeInt;
  LAction: TTaurusTLSOnLoadAction;
begin
  if (FLastLoadActionIdx >= 0) and Assigned(GOnLoadActionList) then
  begin
    for i := FLastLoadActionIdx downto 0 do
    begin
      GRegistrationLock.Acquire;
      try
        if Assigned(GOnLoadActionList) and (i < GOnLoadActionList.Count) then
          LAction := GOnLoadActionList[i]
        else
          ClearAction(LAction);
      finally
        GRegistrationLock.Release;
      end;

      if IsActionAssigned(LAction) then
      try
        LAction(osaUnload);
      except
      end;
    end;
  end;
  FLastLoadActionIdx := -1;
end;

function TOpenSSLBaseLoader.GetConfigFile: string;
begin
  FLoaderLock.Acquire;
  try
    if IsLoaded then
      Result := FEffectiveConfigFile
    else
      Result := FConfigFile;
  finally
    FLoaderLock.Release;
  end;
end;

procedure TOpenSSLBaseLoader.SetConfigFile(const Value: string);
begin
  FLoaderLock.Acquire;
  try
    if Value = FConfigFile then
      Exit;

    if (GetInternalState in [lsLoading, lsUnloading, lsLoadedReady]) or IsActiveHandlePresent then
      raise ETaurusTLSConfigFilePathError.Create(RSOSSLConfigFileAlreadyLoaded);

    if Value <> '' then
    begin
      {$IFDEF VCL_2010_OR_ABOVE}
      if not TPath.HasValidPathChars(Value, False) then
        raise ETaurusTLSConfigFilePathError.CreateFmt(
          RSOSSLConfigFilePathInvalid, [Value]);
      {$ENDIF}
    end;

    FConfigFile := Value;
  finally
    FLoaderLock.Release;
  end;
end;

{ ============================================================================ }
{ Static Linking Implementation                                                }
{ ============================================================================ }

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
type
  /// <summary>Applies configuration and lifecycle actions to routines linked into the executable.</summary>
  /// <remarks>Library path/version settings are inert; unloading does not unlink OpenSSL.</remarks>
  TOpenSSLStaticLoader = class(TOpenSSLBaseLoader)
  strict private
    FFailed: TStringList;
  strict protected
    function DoLoad: Boolean; override;
    procedure DoUnload; override;
    function GetOpenSSLPath: string; override;
    procedure SetOpenSSLPath(const Value: string); override;
    function GetSSLLibVersions: string; override;
    procedure SetSSLLibVersions(const AValue: string); override;
    function GetFailedToLoad: TStringList; override;
  public
    constructor Create; override;
    destructor Destroy; override;
  end;

constructor TOpenSSLStaticLoader.Create;
begin
  inherited Create;
  FFailed := TStringList.Create;
end;

destructor TOpenSSLStaticLoader.Destroy;
begin
  FreeAndNil(FFailed);
  inherited Destroy;
end;

function TOpenSSLStaticLoader.GetOpenSSLPath: string;
begin
  Result := '';
end;

procedure TOpenSSLStaticLoader.SetOpenSSLPath(const Value: string);
begin
  // Inert for static link model
end;

function TOpenSSLStaticLoader.GetSSLLibVersions: string;
begin
  Result := '';
end;

procedure TOpenSSLStaticLoader.SetSSLLibVersions(const AValue: string);
begin
  // Inert for static link model
end;

function TOpenSSLStaticLoader.GetFailedToLoad: TStringList;
begin
  Result := FFailed;
end;



function TOpenSSLStaticLoader.DoLoad: Boolean;
begin
  // Verify statically linked OpenSSL 3.x / 4.x version
  CheckOpenSSLVersion(OpenSSL_version_num());

  // Apply explicit/default configuration
  ApplyConfiguration;

  // Execute registered action callbacks
  DispatchLoadActions;

  Result := True;
end;

procedure TOpenSSLStaticLoader.DoUnload;
begin
  RollbackLoadActions;
end;
{$ENDIF}

{ ============================================================================ }
{ Dynamic Linking Implementation                                               }
{ ============================================================================ }

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
type
  /// <summary>Loads shared libraries, binds header routines, and manages lifecycle actions.</summary>
  TOpenSSLDynamicLoader = class(TOpenSSLBaseLoader)
  strict private
    FLibCrypto: TIdLibHandle;
    FLibSSL: TIdLibHandle;
    FOpenSSLPath: string;
    FSSLLibVersions: string;
    FFailed: TStringList;

    /// <summary>Tries the configured directory and ordered platform filename suffixes.</summary>
    function FindLibrary(const LibName, LibVersions: string): TIdLibHandle;
    /// <summary>Loads crypto and SSL libraries and validates the crypto library identity and version.</summary>
    function LoadAndVerifyLibraries: Boolean;
    /// <summary>Runs registered crypto and SSL header binders and collects diagnostics.</summary>
    procedure BindHeaderSymbols(const AVersionNo: TIdC_ULONG);
    /// <summary>Attempts all symbol resetters in reverse order, then re-raises the first failure.</summary>
    procedure UnbindHeaderSymbols;
    /// <summary>Releases the SSL and crypto library handles and resets them to IdNilHandle.</summary>
    procedure FreeDynamicLibraries;
    /// <summary>Checks the native version string for the expected OpenSSL prefix.</summary>
    class function IsOpenSSLPrefix(const AStr: PAnsiChar): Boolean; static;
      {$IFDEF USE_INLINE}inline;{$ENDIF}
  strict protected
    function DoLoad: Boolean; override;
    procedure DoUnload; override;
    function NeedUnloadCleanup: Boolean; override;
    function IsActiveHandlePresent: Boolean; override;
    function GetOpenSSLPath: string; override;
    procedure SetOpenSSLPath(const Value: string); override;
    function GetSSLLibVersions: string; override;
    procedure SetSSLLibVersions(const AValue: string); override;
    function GetFailedToLoad: TStringList; override;
  public
    constructor Create; override;
    destructor Destroy; override;
  end;

function DoLoadLibrary(const FullLibName: string): TIdLibHandle;
{$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := SafeLoadLibrary(FullLibName, {$IFDEF WINDOWS}SEM_FAILCRITICALERRORS{$ELSE}0{$ENDIF});
end;

{$IF NOT DECLARED(rpos)}
function RPos(Substr: string; S: string): Integer;
var
  i: Integer;
begin
  Result := 0;
  if ((Length(S) > 0) and (Length(Substr) > 0)) then
    if (Length(S) >= Length(Substr)) then
      for i := (Length(S) - Length(Substr)) downto 1 do
        if (Copy(S, i, Length(Substr)) = Substr) then
        begin
          Result := i;
          Exit;
        end;
end;
{$IFEND}

function TaurusTLSExtractFileNameWithoutExt(const LibName: string): string;
{$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  {$IFDEF VCL_2010_OR_ABOVE}
  Result := TPath.GetFileNameWithoutExtension(LibName);
  {$ELSE}
  if ExtractFileExt(LibName) <> '' then
    Result := ExtractFilename(Copy(LibName, 1, RPos(ExtractFileExt(LibName), LibName) - 1))
  else
    Result := ExtractFilename(LibName);
  {$ENDIF}
end;

function TaurusTLSExtractFileExt(const LibName: string): string;
{$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  {$IFDEF VCL_2010_OR_ABOVE}
  Result := TPath.GetExtension(LibName);
  {$ELSE}
  Result := ExtractFileExt(LibName);
  {$ENDIF}
end;

constructor TOpenSSLDynamicLoader.Create;
begin
  inherited Create;
  FFailed := TStringList.Create;
  FLibCrypto := IdNilHandle;
  FLibSSL := IdNilHandle;
  FSSLLibVersions := DefaultLibVersions;
  OpenSSLPath := GetEnvironmentVariable(TaurusTLSLibraryPath);
end;

destructor TOpenSSLDynamicLoader.Destroy;
begin
  FreeDynamicLibraries;
  FreeAndNil(FFailed);
  inherited Destroy;
end;

function TOpenSSLDynamicLoader.GetOpenSSLPath: string;
begin
  Result := FOpenSSLPath;
end;

function TOpenSSLDynamicLoader.GetSSLLibVersions: string;
begin
  Result := FSSLLibVersions;
end;

procedure TOpenSSLDynamicLoader.SetOpenSSLPath(const Value: string);
begin
  FLoaderLock.Acquire;
  try
    if Value = FOpenSSLPath then
      Exit;

    if (GetInternalState in [lsLoading, lsUnloading, lsLoadedReady]) or IsActiveHandlePresent then
      raise ETaurusTLSConfigFilePathError.Create(RSOSSLConfigFileAlreadyLoaded);

    if Value = '' then
      FOpenSSLPath := ''
    else
      FOpenSSLPath := IncludeTrailingPathDelimiter(Value);
  finally
    FLoaderLock.Release;
  end;
end;

procedure TOpenSSLDynamicLoader.SetSSLLibVersions(const AValue: string);
begin
  FLoaderLock.Acquire;
  try
    if AValue = FSSLLibVersions then
      Exit;

    if (GetInternalState in [lsLoading, lsUnloading, lsLoadedReady]) or IsActiveHandlePresent then
      raise ETaurusTLSConfigFilePathError.Create(RSOSSLConfigFileAlreadyLoaded);

    FSSLLibVersions := AValue;
  finally
    FLoaderLock.Release;
  end;
end;

function TOpenSSLDynamicLoader.GetFailedToLoad: TStringList;
begin
  Result := FFailed;
end;



class function TOpenSSLDynamicLoader.IsOpenSSLPrefix(
  const AStr: PAnsiChar): Boolean;
begin
  if not Assigned(AStr) then
    Exit(False);
{$IFDEF FPC}
  Result := StrLComp(AStr, CVerStrOpenSSLPfx, Length(CVerStrOpenSSLPfx)) = 0;
{$ELSE}
  Result := System.AnsiStrings.AnsiStrLComp(AStr,
    CVerStrOpenSSLPfx, Length(CVerStrOpenSSLPfx)) = 0;
{$ENDIF}
end;

function TOpenSSLDynamicLoader.NeedUnloadCleanup: Boolean;
begin
  Result := inherited NeedUnloadCleanup or (FLibCrypto <> IdNilHandle) or (FLibSSL <> IdNilHandle);
end;

function TOpenSSLDynamicLoader.IsActiveHandlePresent: Boolean;
begin
  Result := (FLibCrypto <> IdNilHandle);
end;

function TOpenSSLDynamicLoader.FindLibrary(const LibName, LibVersions: string): TIdLibHandle;
var
  LibVersionsList: TStringList;
  i: integer;
  {$IFDEF OSX}
  LFileName, LExt: string;
  {$ENDIF}
begin
{$IFNDEF WINDOWS}
  Result := DoLoadLibrary(OpenSSLPath + LibName);
  if (Result = IdNilHandle) and (LibVersions <> '') then
  begin
{$ELSE}
  Result := IdNilHandle;
{$ENDIF}
  {$IFDEF OSX}
  LFileName := TaurusTLSExtractFileNameWithoutExt(LibName);
  LExt := TaurusTLSExtractFileExt(LibName);
  {$ENDIF}
  LibVersionsList := TStringList.Create;
  try
    LibVersionsList.Delimiter := DirListDelimiter;
    LibVersionsList.StrictDelimiter := True;
    LibVersionsList.DelimitedText := LibVersions;
    for i := 0 to LibVersionsList.Count - 1 do
    begin
      {$IFDEF OSX}
      Result := DoLoadLibrary(OpenSSLPath + LFileName + LibVersionsList[i] + LExt);
      {$ELSE}
      Result := DoLoadLibrary(OpenSSLPath + LibName + LibVersionsList[i]);
      {$ENDIF}
      if Result <> IdNilHandle then
        Break;
    end;
  finally
    LibVersionsList.Free;
  end;
{$IFNDEF WINDOWS}
  end;
{$ENDIF}
end;

function TOpenSSLDynamicLoader.LoadAndVerifyLibraries: Boolean;
type
  TOpenSSL_version_num = function: TIdC_ULONG; cdecl;
  TOpenSSL_version = function(t: TIdC_INT): PIdAnsiChar; cdecl;
var
  LOpenSSL_version_num: TOpenSSL_version_num;
  LOpenSSL_version: TOpenSSL_version;
  LSSLVersionNo: TIdC_ULONG;
  LVersionPChar: PIdAnsiChar;
begin
  Result := False;

  FLibCrypto := FindLibrary(CLibCryptoBase + LibSuffix, FSSLLibVersions);
  FLibSSL := FindLibrary(CLibSSLBase + LibSuffix, FSSLLibVersions);

  if (FLibCrypto = IdNilHandle) or (FLibSSL = IdNilHandle) then
    Exit;

  // 1. Verify genuine OpenSSL identity using zero-allocation PAnsiChar/PChar check
  LOpenSSL_version := LoadLibFunction(FLibCrypto, 'OpenSSL_version');
  if not Assigned(LOpenSSL_version) then
    LOpenSSL_version := LoadLibFunction(FLibCrypto, 'SSLeay_version');

  if not Assigned(LOpenSSL_version) then
    raise ETaurusTLSLoaderError.Create(RSOSSLCantGetSSLVersionString);

  LVersionPChar := LOpenSSL_version(OPENSSL_VERSION_CONST); // 0 = OPENSSL_VERSION
  if (not Assigned(LVersionPChar)) or (not IsOpenSSLPrefix(LVersionPChar)) then
    raise ETaurusTLSLoaderError.Create(RSOSSLUnsupportedCryptoLibrary);

  // 2. Numeric version check (supports OpenSSL 3.x and 4.x)
  LOpenSSL_version_num := LoadLibFunction(FLibCrypto, 'OpenSSL_version_num');
  if not Assigned(LOpenSSL_version_num) then
    LOpenSSL_version_num := LoadLibFunction(FLibCrypto, 'SSLeay');

  if not Assigned(LOpenSSL_version_num) then
    raise ETaurusTLSLoaderError.Create(ROSSLCantGetSSLVersionNo);

  LSSLVersionNo := LOpenSSL_version_num();
  CheckOpenSSLVersion(LSSLVersionNo);

  Result := True;
end;

procedure TOpenSSLDynamicLoader.BindHeaderSymbols(const AVersionNo: TIdC_ULONG);
var
  i: Integer;
begin
  GRegistrationLock.Acquire;
  try
    if Assigned(GLibCryptoLoadList) then
      for i := 0 to GLibCryptoLoadList.Count - 1 do
        TOpenSSLLoadProc(GLibCryptoLoadList[i])(FLibCrypto, AVersionNo, FFailed);

    if Assigned(GLibSSLLoadList) then
      for i := 0 to GLibSSLLoadList.Count - 1 do
        TOpenSSLLoadProc(GLibSSLLoadList[i])(FLibSSL, AVersionNo, FFailed);
  finally
    GRegistrationLock.Release;
  end;
end;

procedure TOpenSSLDynamicLoader.UnbindHeaderSymbols;

  // Finish remaining resetters before re-raising the first cleanup exception.
  // Nested failures are handled the same way without retaining exception objects.
  procedure UnbindFrom(const ALastIndex: Integer);
  var
    i: Integer;
  begin
    for i := ALastIndex downto 0 do
    try
      TOpenSSLUnloadProc(GUnLoadList[i]);
    except
      try
        UnbindFrom(i - 1);
      except
        // Preserve the first failure after all remaining resetters were tried.
      end;
      raise;
    end;
  end;

begin
  GRegistrationLock.Acquire;
  try
    if Assigned(GUnLoadList) then
      UnbindFrom(GUnLoadList.Count - 1);
  finally
    GRegistrationLock.Release;
  end;
end;

procedure TOpenSSLDynamicLoader.FreeDynamicLibraries;
begin
  if FLibSSL <> IdNilHandle then
  begin
    FreeLibrary(FLibSSL);
    FLibSSL := IdNilHandle;
  end;
  if FLibCrypto <> IdNilHandle then
  begin
    FreeLibrary(FLibCrypto);
    FLibCrypto := IdNilHandle;
  end;
end;

function TOpenSSLDynamicLoader.DoLoad: Boolean;
type
  TOpenSSL_version_num = function: TIdC_ULONG; cdecl;
var
  LOpenSSL_version_num: TOpenSSL_version_num;
  LSSLVersionNo: TIdC_ULONG;
begin
  Result := False;

  // 1. Locate and load DLL handles
  if not LoadAndVerifyLibraries then
    Exit;

  // 2. Resolve version for header bindings (shifted by 12 bits)
  LOpenSSL_version_num := LoadLibFunction(FLibCrypto, 'OpenSSL_version_num');
  if not Assigned(LOpenSSL_version_num) then
    LOpenSSL_version_num := LoadLibFunction(FLibCrypto, 'SSLeay');
  LSSLVersionNo := LOpenSSL_version_num() shr 12;

  // 3. Bind function pointers from dynamic libraries
  BindHeaderSymbols(LSSLVersionNo);

  // 4. Apply explicit or default configuration (with all OpenSSL calls guarded)
  ApplyConfiguration;

  // 5. Execute registered lifecycle actions
  DispatchLoadActions;

  Result := True;
end;

procedure TOpenSSLDynamicLoader.DoUnload;
begin
  // Each cleanup stage must run even if an earlier stage raises.
  try
    RollbackLoadActions;
  finally
    try
      UnbindHeaderSymbols;
    finally
      FreeDynamicLibraries;
    end;
  end;
end;
{$ENDIF}

initialization
  Assert(SSLIsLoaded = nil);
  SSLIsLoaded := TIdThreadSafeBoolean.Create;
  GRegistrationLock := TIdCriticalSection.Create;

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
  GOpenSSLLoader := TOpenSSLStaticLoader.Create;
{$ELSE}
  GOpenSSLLoader := TOpenSSLDynamicLoader.Create;
{$ENDIF}

finalization
  GOpenSSLLoader := nil;

  FreeAndNil(GOnLoadActionList);
  FreeAndNil(GLibCryptoLoadList);
  FreeAndNil(GLibSSLLoadList);
  FreeAndNil(GUnLoadList);

  FreeAndNil(GRegistrationLock);
  FreeAndNil(SSLIsLoaded);
end.
