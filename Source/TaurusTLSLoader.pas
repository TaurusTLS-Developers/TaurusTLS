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
  SysUtils,
  Classes,
  {$IFNDEF FPC}
  System.SyncObjs,
  {$ENDIF}
  IdGlobal,
  IdCTypes;

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
  ///   State reports lsNotLoaded and IsLoaded is False during load, unload, and
  ///   rollback callbacks. Initialization callbacks use callable OpenSSL routines
  ///   directly; they must not require application-ready state to establish it.
  ///   Application crypto entry points must wait for lsLoadedReady.
  /// </remarks>
  TTaurusTLSOnLoadAction = procedure(AAction: TOpenSSLLoadAction) of object;

  /// <summary>Provides a common lifecycle and configuration API for both linking models.</summary>
  /// <remarks>
  ///   Calling Load again when ready returns True without repeating initialization.
  ///   Load calls do not acquire references; one Unload performs cleanup.
  ///   A failure blocks later Load calls until Unload resets the failure state. Static builds retain linked
  ///   code and use the loader for configuration and lifecycle actions.
  ///   Metadata getters copy cached strings under the lifecycle lock and never
  ///   initialize OpenSSL. Only State and IsLoaded are nonblocking queries.
  /// </remarks>
  IOpenSSLLoader = interface
    ['{BBB0F670-CC26-42BC-A9E0-33647361941A}']
    /// <summary>Returns the dynamic library search directory, or an empty string in static builds.</summary>
    function GetOpenSSLPath: string;
    /// <summary>Returns dynamic library filename suffixes, or an empty string in static builds.</summary>
    function GetSSLLibVersions: string;
    /// <summary>Sets the dynamic library directory; ignored in static builds.</summary>
    procedure SetOpenSSLPath(const Value: string);
    /// <summary>Returns the effective filename while ready, otherwise the configured filename.</summary>
    /// <remarks>Callbacks see the configured input, not the expanded effective filename.</remarks>
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
    /// <summary>Returns the loaded OpenSSL version text, or empty while not ready.</summary>
    function GetVersion: string;
    /// <summary>Returns the directory containing the effective ConfigFile, or empty while not ready.</summary>
    function GetConfigDirectory: string;
    /// <summary>Returns the compiled default module directory, or empty while not ready or unavailable.</summary>
    function GetModulesDirectory: string;
    /// <summary>Returns the OpenSSL 3 engine directory; empty on OpenSSL 4 or while not ready.</summary>
    function GetEnginesDirectory: string;

    /// <summary>Copied version text; reading metadata never initializes OpenSSL.</summary>
    property Version: string read GetVersion;
    /// <summary>Directory of the effective configuration filename, resolved during loading.</summary>
    /// <remarks>A discovered filename does not prove that the file exists or was applied.</remarks>
    property ConfigDirectory: string read GetConfigDirectory;
    /// <summary>Compiled default module directory, not configured provider filenames or OPENSSL_MODULES.</summary>
    property ModulesDirectory: string read GetModulesDirectory;
    /// <summary>Compiled engine directory on supported OpenSSL 3 builds; empty on OpenSSL 4.</summary>
    property EnginesDirectory: string read GetEnginesDirectory;

    /// <summary>Current stable readiness state; independent of library-handle presence.</summary>
    property State: TTaurusTLSLoaderState read GetState;

    /// <summary>Ordered filename suffixes used to find dynamic OpenSSL libraries.</summary>
    /// <remarks>
    ///   Entries use the platform directory-list delimiter (semicolon on Windows,
    ///   colon on POSIX). In dynamic builds, changes are rejected while loading,
    ///   ready, unloading, or holding a crypto handle. Assigning the stored value
    ///   does nothing. Static builds always return empty and ignore assignments.
    ///   Changing values after a failed load does not reset the failure state.
    /// </remarks>
    property SSLLibVersions: string read GetSSLLibVersions write SetSSLLibVersions;
    /// <summary>Directory searched for dynamic OpenSSL libraries.</summary>
    /// <remarks>
    ///   Nonempty values receive a trailing path delimiter. An empty value uses
    ///   the platform library search. In dynamic builds, changes are rejected while
    ///   loading, ready, unloading, or holding a crypto handle. Assigning the exact
    ///   stored value does nothing. Static builds return empty and ignore assignments.
    ///   Changing values after a failed load does not reset the failure state.
    /// </remarks>
    property OpenSSLPath: string read GetOpenSSLPath write SetOpenSSLPath;
    /// <summary>Explicit configuration filename, or the effective filename while loaded.</summary>
    /// <remarks>
    ///   Both models accept relative and Unicode paths. Load expands an explicit
    ///   path, checks that it names an existing file, and applies it to the default
    ///   OpenSSL context using UTF-8. Invalid paths and configuration load failures
    ///   raise exceptions. An empty value requests standard OpenSSL configuration
    ///   initialization and discovers its default filename. OpenSSL's first
    ///   initialization policy may persist across static load cycles or external
    ///   initialization; the discovered filename alone does not prove it was read.
    ///   Discovery can reflect a C-runtime environment different from Delphi's process environment.
    ///   Changes are rejected while loading, ready, unloading, or holding a crypto
    ///   handle. Assigning the exact configured input does nothing, including
    ///   during callbacks; that input can differ from the expanded ready filename.
    ///   Callbacks and inactive callers see the configured input. The effective
    ///   filename is exposed only after every load action succeeds. Unload and
    ///   rollback clear the effective filename and retain the configured input.
    ///   Changing the input after a failed load does not reset failure or permit a retry.
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

  /// <summary>
  ///   Header registration procedure that binds dynamic OpenSSL routine
  ///   addresses.
  /// </summary>
  /// <param name="ADllHandle">
  ///   The loaded crypto or SSL library handle.
  /// </param>
  /// <param name="LibVersion">
  ///   The numeric OpenSSL version shifted right by 12 bits for header binding.
  /// </param>
  /// <param name="AFailed">
  ///   Loader-owned list receiving symbol-binding diagnostics.
  /// </param>
  TOpenSSLLoadProc = procedure(const ADllHandle: TIdLibHandle;
    LibVersion: TIdC_UINT; const AFailed: TStringList);

  /// <summary>
  ///   Header cleanup procedure that resets dynamic procedural variables to
  ///   nil.
  /// </summary>
  TOpenSSLUnloadProc = procedure;

/// <summary>
///   Returns the singleton loader selected by OPENSSL_STATIC_LINK_MODEL.
/// </summary>
/// <returns>
///   The shared dynamic or static loader interface.
/// </returns>
/// <remarks>
///   Atomically creates the loader infrastructure if it is not yet available.
///   This does not load or initialize OpenSSL. Unit initialization and all
///   registration entry points use the same singleton publication path.
/// </remarks>
function GetOpenSSLLoader: IOpenSSLLoader;


/// <summary>
///   Registers a header symbol-binding procedure for dynamic loads.
/// </summary>
/// <param name="LoadProc">
///   Procedure that binds a header unit's procedural variables.
/// </param>
/// <param name="module_name">
///   Case-sensitive library selector: LibCrypto or LibSSL.
/// </param>
/// <remarks>
///   Call only from serialized unit initialization, before application threads
///   use the loader. Runtime header registration is unsupported. The loader
///   lock protects the registry; it does not make late symbol binding
///   supported. Static loading does not invoke these procedures because its
///   external routines are linked directly.
/// </remarks>
procedure Register_SSLLoader(LoadProc: TOpenSSLLoadProc; const module_name: string);

/// <summary>
///   Registers a dynamic symbol-reset procedure, run in reverse registration
///   order.
/// </summary>
/// <param name="UnloadProc">
///   Procedure that clears a header unit's procedural variables.
/// </param>
/// <remarks>
///   Register only from serialized unit initialization, alongside the header
///   loader. This registers cleanup; it does not perform cleanup at this call.
///   The procedure runs after lifecycle cleanup actions and before dynamic
///   library release. Stop loader use before unit finalization; registered
///   procedures and their code must remain valid until loader cleanup has
///   completed.
/// </remarks>
procedure Register_SSLUnloader(UnloadProc: TOpenSSLUnloadProc);

/// <summary>
///   Registers initialization and cleanup actions for both linking models.
/// </summary>
/// <param name="AActionProc">
///   Method whose object must remain valid while registered.
/// </param>
/// <remarks>
///   May be called from any thread. Calls serialize with lifecycle operations
///   and action registration/removal under the loader lock. An immediate
///   callback runs synchronously on the calling thread while that lock is held;
///   it must not wait for another thread that needs the loader lock. Actions
///   load in registration order and unload in reverse order. Registering while
///   ready invokes osaLoad immediately under the lifecycle lock. If it raises,
///   the registration is removed and the original exception propagates; the
///   failing callback owns cleanup of its partial initialization. Repeated Load
///   calls do not redispatch actions. Duplicates are independent registrations;
///   nil actions are ignored. Reentrant registration from load, unload or
///   immediate callbacks, and registration while failed, raises
///   ETaurusTLSLoaderError. Other threads wait for the current operation before
///   registration is checked against the resulting state. Registrations do not
///   retain callback objects.
/// </remarks>
procedure Register_SSLLoaderAction(const AActionProc: TTaurusTLSOnLoadAction);

/// <summary>
///   Removes the most recent matching lifecycle action registration.
/// </summary>
/// <remarks>
///   May be called from any thread, serialized under the same loader lock as
///   registration and lifecycle operations. Immediate cleanup runs
///   synchronously on the calling thread while that lock is held; it must not
///   wait for another thread that needs the loader lock. The caller must keep
///   the callback object alive until removal and any synchronous cleanup have
///   completed. Matching compares both method code and instance. Missing/nil
///   actions are ignored. While ready, osaUnload runs immediately while native
///   APIs remain callable. The registration is removed even if cleanup raises;
///   that exception propagates. Reentrant removal from load, unload or
///   immediate callbacks raises ETaurusTLSLoaderError. Other threads wait for
///   the current operation. Inactive/failed removal performs no callback.
/// </remarks>
procedure UnRegister_SSLLoaderAction(const AActionProc: TTaurusTLSOnLoadAction);

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IF NOT DECLARED(LoadLibFunction)}
  {$DEFINE LOADLIB_UNAVAIL}
  {$IFDEF LOADLIB_UNAVAIL}
/// <summary>Resolves a routine address from a loaded dynamic library handle.</summary>
function LoadLibFunction(const ALibHandle: TIdLibHandle; const AProcName: TIdLibFuncName): Pointer;
  {$ENDIF}
{$IFEND}
{$ENDIF}

type
  /// <summary>Platform groups; Windows settings distinguish 32-bit and 64-bit processes.</summary>
  /// <remarks>Entries describe deployment settings, not a promise of target/toolchain support.</remarks>
  TTaurusTLSPlatform = (tlpAndroid, tlpiOS, tlpMacOS, tlpLinux,
    tlpWindows32, tlpWindows64);

  /// <summary>
  ///   Component-local configuration for one platform group.
  /// </summary>
  TTaurusTLSPlatformSetting = class(TCollectionItem)
  private
    FDestroying: Boolean;
    FTarget: TTaurusTLSPlatform;
    FOpenSSLPath: string;
    FConfigFile: TFileName;
    FCustomSSLLibVersions: string;
    procedure CheckMutable;
    procedure SetTarget(const Value: TTaurusTLSPlatform);
    procedure SetOpenSSLPath(const Value: string);
    procedure SetConfigFile(const Value: TFileName);
    procedure SetCustomSSLLibVersions(const Value: string);
  protected
    function GetDisplayName: string; override;
    procedure SetCollection(Value: TCollection); override;
    procedure SetIndex(Value: Integer); override;
  public
    constructor Create(Collection: TCollection); override;
    destructor Destroy; override;
    procedure Assign(Source: TPersistent); override;
    /// <summary>
    ///   Resolves this item's suffixes without accessing or initializing
    ///   OpenSSL.
    /// </summary>
    function ResolveSSLLibVersions: string;
  published
    property Target: TTaurusTLSPlatform read FTarget write SetTarget nodefault;
    /// <summary>
    ///   Blank selects the loader/platform search; ignored in static builds.
    /// </summary>
    property OpenSSLPath: string read FOpenSSLPath write SetOpenSSLPath;
    /// <summary>
    ///   Blank selects standard OpenSSL configuration initialization.
    /// </summary>
    property ConfigFile: TFileName read FConfigFile write SetConfigFile;
    /// <summary>
    ///   Raw suffix list; blank selects defaults. A quoted empty candidate
    ///   requests an unversioned name.
    /// </summary>
    property CustomSSLLibVersions: string read FCustomSSLLibVersions write SetCustomSSLLibVersions;
  end;

  /// <summary>
  ///   Initially empty, owned collection of platform settings.
  /// </summary>
  TTaurusTLSPlatformSettings = class(TOwnedCollection)
  private
    FDestroying: Boolean;
    function IsLoading: Boolean;
    function NewTarget: TTaurusTLSPlatform;
    procedure CheckTargetAvailable(ATarget: TTaurusTLSPlatform;
      AItem: TTaurusTLSPlatformSetting);
    function GetItem(Index: Integer): TTaurusTLSPlatformSetting;
    procedure SetItem(Index: Integer; const Value: TTaurusTLSPlatformSetting);
  protected
    procedure Notify(Item: TCollectionItem; Action: Classes.TCollectionNotification); override;
  public
    destructor Destroy; override;
    procedure BeginUpdate; override;
    procedure Assign(Source: TPersistent); override;
    procedure CheckMutable;
    constructor Create(AOwner: TPersistent);
    function Add: TTaurusTLSPlatformSetting;
    function FindTarget(ATarget: TTaurusTLSPlatform): TTaurusTLSPlatformSetting;
    /// <summary>Rejects duplicate targets, including entries for other platforms.</summary>
    procedure Validate;
    property Items[Index: Integer]: TTaurusTLSPlatformSetting read GetItem write SetItem; default;
  end;

  /// <summary>Platform-aware component over the shared OpenSSL singleton.</summary>
  /// <remarks>
  ///   PlatformSettings are editable only in the designer and restored by streaming.
  ///   Runtime scalar properties delegate directly to the shared singleton.
  ///   Repeated Load calls preserve an already-ready runtime's configuration.
  ///   LoadOnStart loads after runtime streaming only. Programmatic instances
  ///   need explicit Load. Retire native consumers before global Unload.
  ///   Destruction releases the interface without unloading OpenSSL. Readiness
  ///   snapshots are not leases and do not protect against concurrent unloading.
  /// </remarks>
  TTaurusTLSLoader = class(TComponent)
  private
    FLoader: IOpenSSLLoader;
    FLoadOnStart: Boolean;
    FPlatformSettings: TTaurusTLSPlatformSettings;
    procedure SetPlatformSettings(const Value: TTaurusTLSPlatformSettings);
    procedure ApplyPlatformSettings;
    procedure CheckRuntimeLoading;
    function GetOpenSSLPath: string;
    function GetSSLLibVersions: string;
    function GetConfigFile: string;
    function GetVersion: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetConfigDirectory: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetModulesDirectory: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetEnginesDirectory: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetState: TTaurusTLSLoaderState; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetFailedToLoad: TStringList; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsLoaded: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetOpenSSLPath(const Value: string);
    procedure SetSSLLibVersions(const Value: string);
    procedure SetConfigFile(const Value: string);
  protected
    /// <summary>Loads after runtime streaming when LoadOnStart=True; False becomes an exception.</summary>
    procedure Loaded; override;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    /// <summary>Returns the compiled process target, independent of the designer host.</summary>
    class function CurrentTarget: TTaurusTLSPlatform; static;
    /// <summary>Loads the singleton; repeated successful calls are idempotent.</summary>
    /// <remarks>Rejects designer calls; preserves loader failures.</remarks>
    function Load: Boolean;
    /// <summary>Global cleanup/reset; retire all consumers first. No design-time guard.</summary>
    procedure Unload; {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Shared runtime configuration; changes follow the singleton's mutation rules.</summary>
    property OpenSSLPath: string read GetOpenSSLPath write SetOpenSSLPath;
    property SSLLibVersions: string read GetSSLLibVersions write SetSSLLibVersions;
    /// <summary>Shared configured input, or the effective filename while ready.</summary>
    property ConfigFile: string read GetConfigFile write SetConfigFile;
    /// <summary>True only after all singleton load actions complete; transitions report False.</summary>
    property IsLoaded: Boolean read GetIsLoaded;
    /// <summary>Atomic readiness snapshot; not a lease protecting native objects against Unload.</summary>
    property State: TTaurusTLSLoaderState read GetState;
    /// <summary>Cached shared OpenSSL version text; empty while not ready.</summary>
    property Version: string read GetVersion;
    /// <summary>Directory of the effective singleton configuration filename; empty while not ready.</summary>
    property ConfigDirectory: string read GetConfigDirectory;
    /// <summary>Compiled default module directory, not a configured module-search path.</summary>
    property ModulesDirectory: string read GetModulesDirectory;
    /// <summary>Compiled OpenSSL 3 engine directory; empty on OpenSSL 4 or while not ready.</summary>
    property EnginesDirectory: string read GetEnginesDirectory;
    /// <summary>Borrowed singleton diagnostics; do not free this list.</summary>
    property FailedToLoad: TStringList read GetFailedToLoad;
  published
    /// <summary>Published design-time settings, restored during runtime streaming; empty by default.</summary>
    /// <remarks>Runtime edits raise. The component owns the collection and its items.</remarks>
    property PlatformSettings: TTaurusTLSPlatformSettings read FPlatformSettings write SetPlatformSettings;
    /// <summary>Runtime streaming only; the constructor and property setters never load OpenSSL.</summary>
    property LoadOnStart: Boolean read FLoadOnStart write FLoadOnStart default True;
  end;

implementation

uses
  TypInfo,
{$IFDEF UNITTEST}
  TaurusTLSLoader.TestHooks,
{$ENDIF}
{$IFDEF HAS_UNIT_Generics_Collections}
  Generics.Collections,
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
  TaurusTLSHeaders_ssl;

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
  TOpenSSLMetadata = (omVersion, omConfigDirectory, omModulesDirectory, omEnginesDirectory);

  { TOpenSSLBaseLoader }

  /// <summary>
  ///   Abstract base loader providing synchronized state management, configuration
  ///   application, and action callback dispatching for all linking models.
  /// </summary>
  TOpenSSLBaseLoader = class(TInterfacedObject, IOpenSSLLoader)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} private
{$IFDEF FPC}
    class var FInstance: Pointer;
{$ELSE}
    class var FInstance: TOpenSSLBaseLoader;
{$ENDIF}
{$IFDEF HAS_UNIT_Generics_Collections}
    class var FLoadActions: TList<TTaurusTLSOnLoadAction>;
{$ELSE}
    class var FLoadActions: TMethodList;
{$ENDIF}
  private
    /// <summary>Atomically reads or publishes a completed candidate; nil only reads the slot.</summary>
    class function CompareExchangeInstance(const ACandidate: TOpenSSLBaseLoader): TOpenSSLBaseLoader; static; {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Returns the published singleton, releasing any losing candidate.</summary>
    class function EnsureInstance: TOpenSSLBaseLoader; static;
    class function GetInstance: IOpenSSLLoader; static; {$IFDEF USE_INLINE}inline; {$ENDIF}
    class procedure Initialize; static;
    class procedure Finalize; static;
    class procedure RegisterAction(const AActionProc: TTaurusTLSOnLoadAction); static;
    class procedure UnRegisterAction(const AActionProc: TTaurusTLSOnLoadAction); static;
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} protected
    /// <summary>Returns the shared loader lock owned by the published singleton.</summary>
    class function GetLoaderLock: TIdCriticalSection; static; {$IFDEF USE_INLINE}inline; {$ENDIF}
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} protected
    FLoaderLock: TIdCriticalSection;
    // Delphi's generic TInterlocked overloads require class types. Keep the
    // ordinal storage private; all reads/writes use typed atomic accessors.
    FState: Integer;
    FLastLoadActionIdx: NativeInt;
    FActionChangingInProgress: Boolean;
    FConfigFile: string;
    FEffectiveConfigFile: string;
    FMetadata: array[TOpenSSLMetadata] of string;
    procedure CaptureMetadata;
    procedure ClearMetadata;
    function GetMetadata(const AKind: TOpenSSLMetadata): string;
    /// <summary>Reads the internal lifecycle state atomically.</summary>
    function GetInternalState: TTaurusTLSLoaderStateAll; {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Publishes the internal lifecycle state atomically.</summary>
    procedure SetInternalState(const AState: TTaurusTLSLoaderStateAll); {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Performs cleanup while the caller holds the lifecycle lock.</summary>
    procedure UnloadInternal(const AResetFailState: Boolean);

// --- OpenSSL API Wrappers (Static vs Dynamic Bridge) ---
    /// <summary>Initializes OpenSSL directly in static builds or through an assigned dynamic routine.</summary>
    class function SslInitCrypto(opts: TIdC_UINT64; settings: pointer): TIdC_INT; static; {$IFDEF USE_INLINE}inline;{$ENDIF}
    /// <summary>Initializes libssl without reapplying default configuration.</summary>
    procedure InitializeSSL;
    /// <summary>Loads configuration into the supplied context; returns -1 if the dynamic routine is absent.</summary>
    class function SslModulesLoadFileEx(libctx: pointer; filename, appname: PIdAnsiChar; flags: TIdC_ULONG): TIdC_INT; static; {$IFDEF USE_INLINE}inline;{$ENDIF}
    /// <summary>Obtains an OpenSSL-allocated discovery filename; release it with SslFree.</summary>
    class function SslGet1DefaultConfigFile: PIdAnsiChar; static; {$IFDEF USE_INLINE}inline;{$ENDIF}
    /// <summary>Releases OpenSSL-owned memory through the matching linking model; accepts nil.</summary>
    class procedure SslFree(addr: Pointer); static; {$IFDEF USE_INLINE}inline;{$ENDIF}

// --- Method Pointer Helpers (DCC Unsafe Cast Warning Suppression) ---
    /// <summary>Checks both the code and instance pointers of a lifecycle action.</summary>
    class function IsActionAssigned(const AAction: TTaurusTLSOnLoadAction): Boolean; static; {$IFDEF USE_INLINE}inline;{$ENDIF}

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
    /// <summary>Applies explicit configuration or requests native default initialization and discovers its filename.</summary>
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
    function GetState: TTaurusTLSLoaderState; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetVersion: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetConfigDirectory: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetModulesDirectory: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetEnginesDirectory: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>True only when the common state is lsLoadedReady.</summary>
    function IsLoaded: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    /// <summary>Creates the loader lock and unloaded state without calling OpenSSL.</summary>
    constructor Create;
    /// <summary>Releases the loader lock.</summary>
    destructor Destroy; override;

    // Non-virtual template methods managing thread locking and circuit breakers
    /// <summary>Loads once under the lifecycle lock; repeated calls when ready return True without reinitializing.</summary>
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

class function TOpenSSLBaseLoader.GetLoaderLock: TIdCriticalSection;
begin
  Result := EnsureInstance.FLoaderLock;
end;

class procedure TOpenSSLBaseLoader.RegisterAction(const AActionProc: TTaurusTLSOnLoadAction);
var
  LInstance: TOpenSSLBaseLoader;
  LIndex: NativeInt;
begin
  LInstance := EnsureInstance;
  LInstance.FLoaderLock.Enter;
  try
    if LInstance.FActionChangingInProgress or
      not (LInstance.GetInternalState in [lsNotLoaded, lsLoadedReady]) then
      raise ETaurusTLSLoaderError.Create(RSOSSLLoaderActionRegistrationInactive);
    if not IsActionAssigned(AActionProc) then
      Exit;
    if FLoadActions = nil then
{$IFDEF HAS_UNIT_Generics_Collections}
      FLoadActions := TList<TTaurusTLSOnLoadAction>.Create;
{$ELSE}
      FLoadActions := TMethodList.Create;
{$ENDIF}
    LIndex := FLoadActions.Add(AActionProc);
    if LInstance.IsLoaded then
    begin
      LInstance.FActionChangingInProgress := True;
      try
        try
          AActionProc(osaLoad);
        except
          FLoadActions.Delete(LIndex);
          raise;
        end;
        LInstance.FLastLoadActionIdx := LIndex;
      finally
        LInstance.FActionChangingInProgress := False;
      end;
    end;
  finally
    LInstance.FLoaderLock.Leave;
  end;
end;

{$IFDEF DCC}{$WARN UNSAFE_CAST OFF}{$ENDIF}
class procedure TOpenSSLBaseLoader.UnRegisterAction(const AActionProc: TTaurusTLSOnLoadAction);
var
  LInstance: TOpenSSLBaseLoader;
  LIndex, I: NativeInt;
  LAction: TTaurusTLSOnLoadAction;
begin
  LInstance := EnsureInstance;
  LInstance.FLoaderLock.Enter;
  try
    if LInstance.FActionChangingInProgress or
      (LInstance.GetInternalState in [lsLoading, lsUnloading]) then
      raise ETaurusTLSLoaderError.Create(RSOSSLLoaderActionRegistrationInactive);
    if not IsActionAssigned(AActionProc) then
      Exit;
    LIndex := -1;
    if Assigned(FLoadActions) then
      for I := FLoadActions.Count - 1 downto 0 do
      begin
        LAction := FLoadActions[I];
        if (TMethod(LAction).Code = TMethod(AActionProc).Code) and
          (TMethod(LAction).Data = TMethod(AActionProc).Data) then
        begin
          LIndex := I;
          Break;
        end;
      end;
    if LIndex < 0 then
      Exit;
    LInstance.FActionChangingInProgress := True;
    try
      try
        if LInstance.IsLoaded then
          AActionProc(osaUnload);
      finally
        FLoadActions.Delete(LIndex);
        if LIndex <= LInstance.FLastLoadActionIdx then
          Dec(LInstance.FLastLoadActionIdx);
      end;
    finally
      LInstance.FActionChangingInProgress := False;
    end;
  finally
    LInstance.FLoaderLock.Leave;
  end;
end;
{$IFDEF DCC}{$WARN UNSAFE_CAST DEFAULT}{$ENDIF}

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
{$IFDEF UNITTEST}
  if Assigned(OnLoaderCandidateDestroyed) then
    OnLoaderCandidateDestroyed;
{$ENDIF}
  inherited Destroy;
end;

class function TOpenSSLBaseLoader.SslInitCrypto(opts: TIdC_UINT64;
  settings: pointer): TIdC_INT;
begin
{$IFDEF OPENSSL_STATIC_LINK_MODEL}
  Result := OPENSSL_init_crypto(opts, settings);
{$ELSE}
  if Assigned(OPENSSL_init_crypto) then
    Result := OPENSSL_init_crypto(opts, settings)
  else
    Result := 0;
{$ENDIF}
end;

procedure TOpenSSLBaseLoader.InitializeSSL;
begin
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  if not Assigned(OPENSSL_init_ssl) then
    raise ETaurusTLSOpenSSLInitFailed.Create(RSOSSLInitFailed);
{$ENDIF}
  if OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, nil) <> 1 then
    raise ETaurusTLSOpenSSLInitFailed.Create(RSOSSLInitFailed);
end;

procedure TOpenSSLBaseLoader.ClearMetadata;
var
  LKind: TOpenSSLMetadata;
begin
  for LKind := Low(TOpenSSLMetadata) to High(TOpenSSLMetadata) do
    FMetadata[LKind] := '';
end;

procedure TOpenSSLBaseLoader.CaptureMetadata;
begin
  FMetadata[omVersion] := UTF8ToString(OpenSSL_version(OPENSSL_VERSION_CONST));
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  if not Assigned(OPENSSL_info) or (GetFailedToLoad.IndexOf('OPENSSL_info') >= 0) then
    Exit;
{$ENDIF}
  FMetadata[omModulesDirectory] := UTF8ToString(OPENSSL_info(OPENSSL_INFO_MODULES_DIR));
  // OpenSSL 4 removed engine support; preserve the compatibility query as empty.
  if OpenSSL_version_num() < $40000000 then
    FMetadata[omEnginesDirectory] := UTF8ToString(OPENSSL_info(OPENSSL_INFO_ENGINES_DIR));
end;

function TOpenSSLBaseLoader.GetMetadata(const AKind: TOpenSSLMetadata): string;
begin
  FLoaderLock.Enter;
  try
    if IsLoaded then
      Result := FMetadata[AKind]
    else
      Result := '';
  finally
    FLoaderLock.Leave;
  end;
end;

function TOpenSSLBaseLoader.GetVersion: string;
begin
  Result := GetMetadata(omVersion);
end;

function TOpenSSLBaseLoader.GetConfigDirectory: string;
begin
  Result := GetMetadata(omConfigDirectory);
end;

function TOpenSSLBaseLoader.GetModulesDirectory: string;
begin
  Result := GetMetadata(omModulesDirectory);
end;

function TOpenSSLBaseLoader.GetEnginesDirectory: string;
begin
  Result := GetMetadata(omEnginesDirectory);
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


{$IFDEF DCC}
{$WARN UNSAFE_CAST DEFAULT}
{$ENDIF}

{$IFOPT R-}
  {$DEFINE TAURUSTLS_RESTORE_RANGECHECKS_OFF}
  {$R+}
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

{$IFDEF TAURUSTLS_RESTORE_RANGECHECKS_OFF}
  {$UNDEF TAURUSTLS_RESTORE_RANGECHECKS_OFF}
  {$R-}
{$ENDIF}

function TOpenSSLBaseLoader.GetState: TTaurusTLSLoaderState;
var
  LState: TTaurusTLSLoaderStateAll;
begin
  LState := GetInternalState;
  if not (LState in
    [Low(TTaurusTLSLoaderState)..High(TTaurusTLSLoaderState)]) then
    Result := lsNotLoaded
  else
    Result := LState;
end;

function TOpenSSLBaseLoader.IsLoaded: Boolean;
begin
  Result := GetState = lsLoadedReady;
end;

function TOpenSSLBaseLoader.Load: Boolean;
begin
  if GetInternalState = lsLoadedFailed then
    Exit(False);

  FLoaderLock.Enter;
  try
    if FActionChangingInProgress then
      raise ETaurusTLSLoaderError.CreateFmt(RSOSSLLoaderLifecycleInProgress, ['Load']);
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
    ClearMetadata;
    try
      Result := DoLoad;
      if Result then
        CaptureMetadata;
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
    FLoaderLock.Leave;
  end;
end;

procedure TOpenSSLBaseLoader.Unload;
begin
  Unload(True);
end;

procedure TOpenSSLBaseLoader.Unload(const AResetFailState: Boolean);
begin
  FLoaderLock.Enter;
  try
    if FActionChangingInProgress or (GetInternalState in [lsLoading, lsUnloading]) then
      raise ETaurusTLSLoaderError.CreateFmt(RSOSSLLoaderLifecycleInProgress, ['Unload']);
    UnloadInternal(AResetFailState);
  finally
    FLoaderLock.Leave;
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
    ClearMetadata;
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

    if SslInitCrypto(OPENSSL_INIT_NO_LOAD_CONFIG, nil) <> 1 then
      raise ETaurusTLSLoaderError.Create(RSOSSLInitCryptoFailed);

    if SslModulesLoadFileEx(nil, PIdAnsiChar(UTF8Encode(LNormalizedConfig)), nil, 0) <= 0 then
      ETaurusTLSConfigFileLoadError.RaiseException(
        Format(RSOSSLConfigFileLoadFailed, [LNormalizedConfig]));
  end
  else
  begin
    if SslInitCrypto(OPENSSL_INIT_LOAD_CONFIG, nil) <> 1 then
      raise ETaurusTLSLoaderError.Create(RSOSSLInitCryptoFailed);
    LDefaultConfig := SslGet1DefaultConfigFile();
    if Assigned(LDefaultConfig) then
    try
      LNormalizedConfig := UTF8ToString(LDefaultConfig);
    finally
      SslFree(LDefaultConfig);
    end;
  end;

  FEffectiveConfigFile := LNormalizedConfig;
  if LNormalizedConfig <> '' then
    FMetadata[omConfigDirectory] := ExtractFileDir(ExpandFileName(LNormalizedConfig));
end;

procedure TOpenSSLBaseLoader.DispatchLoadActions;
var
  I: Integer;
  LAction: TTaurusTLSOnLoadAction;
begin
  // The caller holds FLoaderLock; callbacks cannot change this list.
  if Assigned(FLoadActions) then
    for I := 0 to FLoadActions.Count - 1 do
    begin
      LAction := FLoadActions[I];
      if IsActionAssigned(LAction) then
      begin
        LAction(osaLoad);
        FLastLoadActionIdx := I;
      end;
    end;
end;

procedure TOpenSSLBaseLoader.RollbackLoadActions;
var
  I: NativeInt;
  LAction: TTaurusTLSOnLoadAction;
begin
  // The caller holds FLoaderLock until all callbacks and native cleanup finish.
  if (FLastLoadActionIdx >= 0) and Assigned(FLoadActions) then
    for I := FLastLoadActionIdx downto 0 do
    begin
      LAction := FLoadActions[I];
      if IsActionAssigned(LAction) then
      try
        LAction(osaUnload);
      except
      end;
    end;
  FLastLoadActionIdx := -1;
end;

function TOpenSSLBaseLoader.GetConfigFile: string;
begin
  FLoaderLock.Enter;
  try
    if IsLoaded then
      Result := FEffectiveConfigFile
    else
      Result := FConfigFile;
  finally
    FLoaderLock.Leave;
  end;
end;

procedure TOpenSSLBaseLoader.SetConfigFile(const Value: string);
begin
  FLoaderLock.Enter;
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
    FLoaderLock.Leave;
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
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} private
    FFailed: TStringList;
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} protected
    function DoLoad: Boolean; override;
    procedure DoUnload; override;
    function GetOpenSSLPath: string; override;
    procedure SetOpenSSLPath(const Value: string); override;
    function GetSSLLibVersions: string; override;
    procedure SetSSLLibVersions(const AValue: string); override;
    function GetFailedToLoad: TStringList; override;
  public
    constructor Create;
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
  InitializeSSL;

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
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} private
{$IFDEF HAS_UNIT_Generics_Collections}
    class var FCryptoLoaders: TList<TOpenSSLLoadProc>;
    class var FSSLLoaders: TList<TOpenSSLLoadProc>;
    class var FUnloaders: TList<TOpenSSLUnloadProc>;
{$ELSE}
    class var FCryptoLoaders: TList;
    class var FSSLLoaders: TList;
    class var FUnloaders: TList;
{$ENDIF}
  private
    class procedure RegisterHeaderLoader(LoadProc: TOpenSSLLoadProc;
      const module_name: string); static;
    class procedure RegisterHeaderUnloader(UnloadProc: TOpenSSLUnloadProc); static;
    class procedure ClearHeaderRegistrations; static;
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} private
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
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} protected
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
    constructor Create;
    destructor Destroy; override;
  end;

class procedure TOpenSSLDynamicLoader.RegisterHeaderLoader(LoadProc: TOpenSSLLoadProc; const module_name: string);
var
  LLoaderLock: TIdCriticalSection;
begin
  LLoaderLock := GetLoaderLock;
  LLoaderLock.Enter;
  try
    if FCryptoLoaders = nil then
{$IFDEF HAS_UNIT_Generics_Collections}
      FCryptoLoaders := TList<TOpenSSLLoadProc>.Create;
{$ELSE}
      FCryptoLoaders := TList.Create;
{$ENDIF}

    if FSSLLoaders = nil then
{$IFDEF HAS_UNIT_Generics_Collections}
      FSSLLoaders := TList<TOpenSSLLoadProc>.Create;
{$ELSE}
      FSSLLoaders := TList.Create;
{$ENDIF}

    if module_name = 'LibCrypto' then
      FCryptoLoaders.Add(LoadProc)
    else if module_name = 'LibSSL' then
      FSSLLoaders.Add(LoadProc)
    else
      raise ETaurusTLSError.CreateFmt(ROSUnrecognisedLibName, [module_name]);
  finally
    LLoaderLock.Leave;
  end;
end;

class procedure TOpenSSLDynamicLoader.RegisterHeaderUnloader(UnloadProc: TOpenSSLUnloadProc);
var
  LLoaderLock: TIdCriticalSection;
begin
  LLoaderLock := GetLoaderLock;
  LLoaderLock.Enter;
  try
    if FUnloaders = nil then
{$IFDEF HAS_UNIT_Generics_Collections}
      FUnloaders := TList<TOpenSSLUnloadProc>.Create;
{$ELSE}
      FUnloaders := TList.Create;
{$ENDIF}
    FUnloaders.Add(UnloadProc);
  finally
    LLoaderLock.Leave;
  end;
end;

class procedure TOpenSSLDynamicLoader.ClearHeaderRegistrations;
begin
  FreeAndNil(FCryptoLoaders);
  FreeAndNil(FSSLLoaders);
  FreeAndNil(FUnloaders);
end;

function DoLoadLibrary(const FullLibName: string): TIdLibHandle;
{$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := SysUtils.SafeLoadLibrary(FullLibName, {$IFDEF WINDOWS}SEM_FAILCRITICALERRORS{$ELSE}0{$ENDIF});
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
  OpenSSLPath := SysUtils.GetEnvironmentVariable(TaurusTLSLibraryPath);
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
  FLoaderLock.Enter;
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
    FLoaderLock.Leave;
  end;
end;

procedure TOpenSSLDynamicLoader.SetSSLLibVersions(const AValue: string);
begin
  FLoaderLock.Enter;
  try
    if AValue = FSSLLibVersions then
      Exit;

    if (GetInternalState in [lsLoading, lsUnloading, lsLoadedReady]) or IsActiveHandlePresent then
      raise ETaurusTLSConfigFilePathError.Create(RSOSSLConfigFileAlreadyLoaded);

    FSSLLibVersions := AValue;
  finally
    FLoaderLock.Leave;
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
    raise ETaurusTLSLoaderError.Create(RSOSSLCantGetSSLVersionString);

  LVersionPChar := LOpenSSL_version(OPENSSL_VERSION_CONST); // 0 = OPENSSL_VERSION
  if (not Assigned(LVersionPChar)) or (not IsOpenSSLPrefix(LVersionPChar)) then
    raise ETaurusTLSLoaderError.Create(RSOSSLUnsupportedCryptoLibrary);

  // 2. Numeric version check (supports OpenSSL 3.x and 4.x)
  LOpenSSL_version_num := LoadLibFunction(FLibCrypto, 'OpenSSL_version_num');

  if not Assigned(LOpenSSL_version_num) then
    raise ETaurusTLSLoaderError.Create(ROSSLCantGetSSLVersionNo);

  LSSLVersionNo := LOpenSSL_version_num();
  CheckOpenSSLVersion(LSSLVersionNo);

  Result := True;
end;

procedure TOpenSSLDynamicLoader.BindHeaderSymbols(const AVersionNo: TIdC_ULONG);
var
  I: Integer;
begin
  // DoLoad holds FLoaderLock while binding and running lifecycle actions.
  if Assigned(FCryptoLoaders) then
    for I := 0 to FCryptoLoaders.Count - 1 do
      TOpenSSLLoadProc(FCryptoLoaders[I])(FLibCrypto, AVersionNo, FFailed);
  if Assigned(FSSLLoaders) then
    for I := 0 to FSSLLoaders.Count - 1 do
      TOpenSSLLoadProc(FSSLLoaders[I])(FLibSSL, AVersionNo, FFailed);
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
      TOpenSSLUnloadProc(FUnloaders[i]);
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
  // DoUnload holds FLoaderLock until resetters finish and libraries are released.
  if Assigned(FUnloaders) then
    UnbindFrom(FUnloaders.Count - 1);
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
  LSSLVersionNo := LOpenSSL_version_num() shr 12;

  // 3. Bind function pointers from dynamic libraries
  BindHeaderSymbols(LSSLVersionNo);

  // 4. Apply explicit or default configuration (with all OpenSSL calls guarded)
  ApplyConfiguration;
  InitializeSSL;

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

class function TOpenSSLBaseLoader.CompareExchangeInstance(
  const ACandidate: TOpenSSLBaseLoader): TOpenSSLBaseLoader;
begin
{$IFDEF FPC}
  Result := TOpenSSLBaseLoader(System.InterlockedCompareExchange(
    FInstance, Pointer(ACandidate), nil));
{$ELSE}
  Result := TInterlocked.CompareExchange<TOpenSSLBaseLoader>(
    FInstance, ACandidate, nil);
{$ENDIF}
end;

{$IFDEF UNITTEST}
function AcquireLoaderForTest: IInterface;
begin
  Result := GetOpenSSLLoader;
end;
{$ENDIF}

class function TOpenSSLBaseLoader.EnsureInstance: TOpenSSLBaseLoader;
var
  LCandidate: TOpenSSLBaseLoader;
  LPublished: TOpenSSLBaseLoader;
begin
{$IFDEF UNITTEST}
  if Assigned(OnLoaderAccess) then
    OnLoaderAccess(AcquireLoaderForTest);
{$ENDIF}
  Result := CompareExchangeInstance(nil);
  if Assigned(Result) then
    Exit;

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
  LCandidate := TOpenSSLStaticLoader.Create;
{$ELSE}
  LCandidate := TOpenSSLDynamicLoader.Create;
{$ENDIF}
  // The atomic object slot owns one interface reference until unit finalization.
  // Acquire it before publication so another caller cannot release the owner.
  LCandidate._AddRef;
  try
{$IFDEF UNITTEST}
    if Assigned(OnLoaderCandidateReady) then
      OnLoaderCandidateReady;
{$ENDIF}
    LPublished := CompareExchangeInstance(LCandidate);
    if not Assigned(LPublished) then
    begin
      Result := LCandidate;
      LCandidate := nil; // Ownership transferred to the published slot.
    end
    else
      Result := LPublished;
  finally
    // A losing candidate owns only its own locks and diagnostics, never the registry.
    if Assigned(LCandidate) then
      LCandidate._Release;
  end;
end;

class function TOpenSSLBaseLoader.GetInstance: IOpenSSLLoader;
begin
  Result := EnsureInstance;
end;

class procedure TOpenSSLBaseLoader.Initialize;
begin
  // Preserve a singleton already published by early header registration.
  EnsureInstance;
end;

class procedure TOpenSSLBaseLoader.Finalize;
var
  LInstance: TOpenSSLBaseLoader;
begin
  // Keep the singleton published while cleanup actions can still query it.
  // Application threads must have stopped; registered callback owners must
  // remain valid until their cleanup action has run.
  LInstance := CompareExchangeInstance(nil);
  if Assigned(LInstance) then
  try
    LInstance.Unload;
  except
    // Unload attempts every cleanup stage; finalization must still release ownership.
  end;

{$IFDEF FPC}
  LInstance := TOpenSSLBaseLoader(System.InterlockedExchange(FInstance, Pointer(nil)));
{$ELSE}
  LInstance := TInterlocked.Exchange<TOpenSSLBaseLoader>(FInstance, nil);
{$ENDIF}
  if Assigned(LInstance) then
    LInstance._Release;
  FreeAndNil(FLoadActions);
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  TOpenSSLDynamicLoader.ClearHeaderRegistrations;
{$ENDIF}
end;

function GetOpenSSLLoader: IOpenSSLLoader;
begin
  Result := TOpenSSLBaseLoader.GetInstance;
end;

procedure Register_SSLLoader(LoadProc: TOpenSSLLoadProc; const module_name: string);
begin
  TOpenSSLBaseLoader.EnsureInstance;
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  TOpenSSLDynamicLoader.RegisterHeaderLoader(LoadProc, module_name);
{$ELSE}
  if (module_name <> 'LibCrypto') and (module_name <> 'LibSSL') then
    raise ETaurusTLSError.CreateFmt(ROSUnrecognisedLibName, [module_name]);
{$ENDIF}
end;

procedure Register_SSLUnloader(UnloadProc: TOpenSSLUnloadProc);
begin
  TOpenSSLBaseLoader.EnsureInstance;
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  TOpenSSLDynamicLoader.RegisterHeaderUnloader(UnloadProc);
{$ENDIF}
end;

procedure Register_SSLLoaderAction(const AActionProc: TTaurusTLSOnLoadAction);
begin
  TOpenSSLBaseLoader.RegisterAction(AActionProc);
end;

procedure UnRegister_SSLLoaderAction(const AActionProc: TTaurusTLSOnLoadAction);
begin
  TOpenSSLBaseLoader.UnRegisterAction(AActionProc);
end;

{ Platform configuration }

function TaurusTLSDefaultVersions(ATarget: TTaurusTLSPlatform): string;
begin
  case ATarget of
    tlpWindows32: Result := COpenSSLDefaultWin32Versions;
    tlpWindows64:
      {$IF DEFINED(WINDOWS) AND (DEFINED(CPUARM64) OR DEFINED(CPUAARCH64) OR DEFINED(ARM64EC))}
      Result := COpenSSLDefaultARM64Versions;
      {$ELSE}
      Result := COpenSSLDefaultWin64Versions;
      {$IFEND}
  else
    Result := COpenSSLDefaultPosixVersions;
  end;
end;

{ TTaurusTLSPlatformSetting }

procedure TTaurusTLSPlatformSetting.CheckMutable;
begin
  if Collection is TTaurusTLSPlatformSettings then
    TTaurusTLSPlatformSettings(Collection).CheckMutable
  else
    raise ETaurusTLSLoaderError.Create(RSOSSLPlatformSettingsDesignOnly);
end;

constructor TTaurusTLSPlatformSetting.Create(Collection: TCollection);
begin
  // Check before inherited attaches the item to its collection.
  if Collection is TTaurusTLSPlatformSettings then
    TTaurusTLSPlatformSettings(Collection).CheckMutable
  else
    raise ETaurusTLSLoaderError.Create(RSOSSLPlatformSettingsDesignOnly);
  // Preserve Windows32 for older streams that omitted Target.
  // Designer additions instead select an unused target before attachment.
  FTarget := TTaurusTLSPlatformSettings(Collection).NewTarget;
  inherited Create(Collection);
end;

destructor TTaurusTLSPlatformSetting.Destroy;
begin
  FDestroying := True;
  inherited Destroy;
end;

procedure TTaurusTLSPlatformSetting.SetCollection(Value: TCollection);
begin
  if not FDestroying then
  begin
    if Collection <> nil then
      CheckMutable;
    if Value is TTaurusTLSPlatformSettings then
    begin
      TTaurusTLSPlatformSettings(Value).CheckMutable;
      if not TTaurusTLSPlatformSettings(Value).IsLoading then
        TTaurusTLSPlatformSettings(Value).CheckTargetAvailable(FTarget, Self);
    end
    else if Value <> nil then
      raise ETaurusTLSLoaderError.Create(RSOSSLPlatformSettingsDesignOnly);
  end;
  inherited SetCollection(Value);
end;

procedure TTaurusTLSPlatformSetting.SetIndex(Value: Integer);
begin
  CheckMutable;
  inherited SetIndex(Value);
end;

function TTaurusTLSPlatformSetting.GetDisplayName: string;
begin
  Result := GetEnumName(TypeInfo(TTaurusTLSPlatform), Ord(FTarget));
end;

procedure TTaurusTLSPlatformSetting.Assign(Source: TPersistent);
var
  LSource: TTaurusTLSPlatformSetting;
begin
  CheckMutable;
  if Source is TTaurusTLSPlatformSetting then
  begin
    LSource := TTaurusTLSPlatformSetting(Source);
    TTaurusTLSPlatformSettings(Collection).CheckTargetAvailable(LSource.FTarget, Self);
    FTarget := LSource.FTarget;
    FOpenSSLPath := LSource.FOpenSSLPath;
    FConfigFile := LSource.FConfigFile;
    FCustomSSLLibVersions := LSource.FCustomSSLLibVersions;
    Changed(False);
  end
  else
    inherited Assign(Source);
end;

procedure TTaurusTLSPlatformSetting.SetTarget(const Value: TTaurusTLSPlatform);
begin
  CheckMutable;
  TTaurusTLSPlatformSettings(Collection).CheckTargetAvailable(Value, Self);
  if FTarget <> Value then
  begin
    FTarget := Value;
    Changed(False);
  end;
end;

procedure TTaurusTLSPlatformSetting.SetOpenSSLPath(const Value: string);
begin
  CheckMutable;
  if FOpenSSLPath <> Value then
  begin
    FOpenSSLPath := Value;
    Changed(False);
  end;
end;

procedure TTaurusTLSPlatformSetting.SetConfigFile(const Value: TFileName);
begin
  CheckMutable;
  if FConfigFile <> Value then
  begin
    FConfigFile := Value;
    Changed(False);
  end;
end;

procedure TTaurusTLSPlatformSetting.SetCustomSSLLibVersions(const Value: string);
begin
  CheckMutable;
  if FCustomSSLLibVersions <> Value then
  begin
    FCustomSSLLibVersions := Value;
    Changed(False);
  end;
end;

function TTaurusTLSPlatformSetting.ResolveSSLLibVersions: string;
begin
  Result := FCustomSSLLibVersions;
  if Result = '' then
    Result := TaurusTLSDefaultVersions(FTarget);
end;

{ TTaurusTLSPlatformSettings}

function TTaurusTLSPlatformSettings.IsLoading: Boolean;
var
  LOwner: TPersistent;
begin
  LOwner := GetOwner;
  Result := (LOwner is TComponent) and
    (csLoading in TComponent(LOwner).ComponentState);
end;

procedure TTaurusTLSPlatformSettings.CheckTargetAvailable(
  ATarget: TTaurusTLSPlatform; AItem: TTaurusTLSPlatformSetting);
var
  I: Integer;
begin
  for I := 0 to Count - 1 do
    if (Items[I] <> AItem) and (Items[I].Target = ATarget) then
      raise ETaurusTLSLoaderError.CreateFmt(RSOSSLDuplicatePlatformSetting,
        [GetEnumName(TypeInfo(TTaurusTLSPlatform), Ord(ATarget))]);
end;

function TTaurusTLSPlatformSettings.NewTarget: TTaurusTLSPlatform;
var
  LTarget: TTaurusTLSPlatform;
  LUsed: set of TTaurusTLSPlatform;
  I: Integer;
begin
  Result := tlpWindows32;
  if IsLoading then
    Exit;
  LUsed := [];
  for I := 0 to Count - 1 do
    Include(LUsed, Items[I].Target);
  if not (Result in LUsed) then
    Exit;
  for LTarget := Low(TTaurusTLSPlatform) to High(TTaurusTLSPlatform) do
    if not (LTarget in LUsed) then
    begin
      Result := LTarget;
      Exit;
    end;
  raise ETaurusTLSLoaderError.Create(RSOSSLPlatformSettingsFull);
end;

procedure TTaurusTLSPlatformSettings.CheckMutable;
var
  LOwner: TPersistent;
begin
  if FDestroying then
    Exit;
  LOwner := GetOwner;
  if (LOwner is TComponent) and
    ((csDesigning in TComponent(LOwner).ComponentState) or
     (csLoading in TComponent(LOwner).ComponentState)) then
    Exit;
  raise ETaurusTLSLoaderError.Create(RSOSSLPlatformSettingsDesignOnly);
end;

destructor TTaurusTLSPlatformSettings.Destroy;
begin
  FDestroying := True;
  inherited Destroy;
end;

procedure TTaurusTLSPlatformSettings.BeginUpdate;
begin
  // Clear, Assign and Delphi Sort enter here before changing any items.
  CheckMutable;
  inherited BeginUpdate;
end;

procedure TTaurusTLSPlatformSettings.Assign(Source: TPersistent);
begin
  CheckMutable;
  if Source = Self then
    Exit;
  if Source is TTaurusTLSPlatformSettings then
    TTaurusTLSPlatformSettings(Source).Validate;
  inherited Assign(Source);
end;

procedure TTaurusTLSPlatformSettings.Notify(Item: TCollectionItem;
  Action: Classes.TCollectionNotification);
begin
  // Delete notifies before calling Free. Never raise from an item destructor.
  if Action = Classes.cnDeleting then
    CheckMutable;
  inherited Notify(Item, Action);
end;

constructor TTaurusTLSPlatformSettings.Create(AOwner: TPersistent);
begin
  inherited Create(AOwner, TTaurusTLSPlatformSetting);
end;

function TTaurusTLSPlatformSettings.Add: TTaurusTLSPlatformSetting;
begin
  Result := TTaurusTLSPlatformSetting(inherited Add);
end;

function TTaurusTLSPlatformSettings.GetItem(Index: Integer): TTaurusTLSPlatformSetting;
begin
  Result := TTaurusTLSPlatformSetting(inherited Items[Index]);
end;

procedure TTaurusTLSPlatformSettings.SetItem(Index: Integer; const Value: TTaurusTLSPlatformSetting);
begin
  Items[Index].Assign(Value);
end;

procedure TTaurusTLSPlatformSettings.Validate;
var
  I: Integer;
  LSeen: set of TTaurusTLSPlatform;
begin
  LSeen := [];
  for I := 0 to Count - 1 do
  begin
    if Items[I].Target in LSeen then
      raise ETaurusTLSLoaderError.CreateFmt(RSOSSLDuplicatePlatformSetting,
        [Items[I].DisplayName]);
    Include(LSeen, Items[I].Target);
  end;
end;

function TTaurusTLSPlatformSettings.FindTarget(ATarget: TTaurusTLSPlatform): TTaurusTLSPlatformSetting;
var
  I: Integer;
begin
  Validate;
  Result := nil;
  for I := 0 to Count - 1 do
    if Items[I].Target = ATarget then
    begin
      Result := Items[I];
      Exit;
    end;
end;

{ TTaurusTLSLoader }

class function TTaurusTLSLoader.CurrentTarget: TTaurusTLSPlatform;
{$IF DEFINED(FPC) AND NOT DECLARED(TOSVersion)}
const
  LTargetOS = {$I %FPCTARGETOS%};
{$IFEND}
begin
{$IF DECLARED(TOSVersion)}
  case TOSVersion.Platform of
    TOSVersion.TPlatform.pfWindows:
      if SizeOf(Pointer) = 8 then
        Result := tlpWindows64
      else
        Result := tlpWindows32;
    TOSVersion.TPlatform.pfAndroid: Result := tlpAndroid;
    TOSVersion.TPlatform.pfiOS
      {$IFDEF FPC}, TOSVersion.TPlatform.pfIPhoneSim{$ENDIF}: Result := tlpiOS;
    TOSVersion.TPlatform.pfMacOS
      {$IFDEF FPC}, TOSVersion.TPlatform.pfDarwin{$ENDIF}: Result := tlpMacOS;
    {$IF DEFINED(FPC) OR DEFINED(VCL_10_2_OR_ABOVE)}
    TOSVersion.TPlatform.pfLinux: Result := tlpLinux;
    {$IFEND}
  else
    raise ETaurusTLSLoaderError.Create(RSOSSLUnsupportedComponentTarget);
  end;
{$ELSEIF DEFINED(FPC)}
  // Fallback for FPC RTLs without TOSVersion, including the tested 3.2.2 RTL.
  if SameText(LTargetOS, 'win32') or SameText(LTargetOS, 'win64') then
  begin
    if SizeOf(Pointer) = 8 then
      Result := tlpWindows64
    else
      Result := tlpWindows32;
  end
  else if SameText(LTargetOS, 'android') then
    Result := tlpAndroid
  else if SameText(LTargetOS, 'ios') or SameText(LTargetOS, 'iphonesim') then
    Result := tlpiOS
  else if SameText(LTargetOS, 'darwin') then
    Result := tlpMacOS
  else if SameText(LTargetOS, 'linux') then
    Result := tlpLinux
  else
    raise ETaurusTLSLoaderError.Create(RSOSSLUnsupportedComponentTarget);
{$ELSE}
  // Older Delphi/Kylix RTLs do not expose TOSVersion.
  {$IFDEF WINDOWS}
  if SizeOf(Pointer) = 8 then
    Result := tlpWindows64
  else
    Result := tlpWindows32;
  {$ELSE}
    {$IFDEF LINUX}
  Result := tlpLinux;
    {$ELSE}
  raise ETaurusTLSLoaderError.Create(RSOSSLUnsupportedComponentTarget);
    {$ENDIF}
  {$ENDIF}
{$IFEND}
end;

constructor TTaurusTLSLoader.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  FLoader := GetOpenSSLLoader;
  FPlatformSettings := TTaurusTLSPlatformSettings.Create(Self);
  FLoadOnStart := True;
end;

destructor TTaurusTLSLoader.Destroy;
begin
  FPlatformSettings.Free;
  inherited Destroy;
end;

procedure TTaurusTLSLoader.SetPlatformSettings(const Value: TTaurusTLSPlatformSettings);
begin
  FPlatformSettings.Assign(Value);
end;

procedure TTaurusTLSLoader.ApplyPlatformSettings;
var
  LSetting: TTaurusTLSPlatformSetting;
  LPath, LConfig, LVersions: string;
begin
  // A later component must not reconfigure a ready runtime or reset a failure.
  if FLoader.State <> lsNotLoaded then
    Exit;
  LPath := '';
  LConfig := '';
  LVersions := DefaultLibVersions;
  LSetting := FPlatformSettings.FindTarget(CurrentTarget);
  if LSetting <> nil then
  begin
    LPath := LSetting.OpenSSLPath;
    LConfig := LSetting.ConfigFile;
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    LVersions := LSetting.ResolveSSLLibVersions;
{$ENDIF}
  end;
  FLoader.OpenSSLPath := LPath;
  FLoader.SSLLibVersions := LVersions;
  FLoader.ConfigFile := LConfig;
end;

procedure TTaurusTLSLoader.Loaded;
begin
  inherited Loaded;
  // Validate even in the designer or when the shared runtime is already ready.
  FPlatformSettings.Validate;
  if csDesigning in ComponentState then
    Exit;
  ApplyPlatformSettings;
  if FLoadOnStart then
    if not Load then
      raise ETaurusTLSLoaderError.Create(RSOSSLCouldNotLoadSSLLibrary);
end;

procedure TTaurusTLSLoader.CheckRuntimeLoading;
begin
  if csDesigning in ComponentState then
    raise ETaurusTLSLoaderError.Create(RSOSSLDesignTimeLoad);
end;

function TTaurusTLSLoader.Load: Boolean;
begin
  CheckRuntimeLoading;
  Result := FLoader.Load;
end;

procedure TTaurusTLSLoader.Unload;
begin
  FLoader.Unload;
end;

function TTaurusTLSLoader.GetOpenSSLPath: string;
begin
  Result := FLoader.OpenSSLPath;
end;

function TTaurusTLSLoader.GetSSLLibVersions: string;
begin
  Result := FLoader.SSLLibVersions;
end;

function TTaurusTLSLoader.GetConfigFile: string;
begin
  Result := FLoader.ConfigFile;
end;

function TTaurusTLSLoader.GetVersion: string;
begin
  Result := FLoader.Version;
end;

function TTaurusTLSLoader.GetConfigDirectory: string;
begin
  Result := FLoader.ConfigDirectory;
end;

function TTaurusTLSLoader.GetModulesDirectory: string;
begin
  Result := FLoader.ModulesDirectory;
end;

function TTaurusTLSLoader.GetEnginesDirectory: string;
begin
  Result := FLoader.EnginesDirectory;
end;

function TTaurusTLSLoader.GetState: TTaurusTLSLoaderState;
begin
  Result := FLoader.State;
end;

function TTaurusTLSLoader.GetFailedToLoad: TStringList;
begin
  Result := FLoader.FailedToLoad;
end;

function TTaurusTLSLoader.GetIsLoaded: Boolean;
begin
  Result := FLoader.IsLoaded;
end;

procedure TTaurusTLSLoader.SetOpenSSLPath(const Value: string);
begin
  FLoader.OpenSSLPath := Value;
end;

procedure TTaurusTLSLoader.SetSSLLibVersions(const Value: string);
begin
  FLoader.SSLLibVersions := Value;
end;

procedure TTaurusTLSLoader.SetConfigFile(const Value: string);
begin
  FLoader.ConfigFile := Value;
end;


initialization
  TOpenSSLBaseLoader.Initialize;

finalization
  TOpenSSLBaseLoader.Finalize;
end.
