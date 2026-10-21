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
///   Functionality for loading the OpenSSL library including registration
///   mechanism for the TaurusTLSHeader_ units across dynamic and static models.
/// </summary>
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
  { IOpenSSLLoader }

  /// <summary>
  ///   Indicates OpenSSL library load action.
  /// </summary>
  TOpenSSLLoadAction = (
    /// <summary>OpenSSL library loaded.</summary>
    osaLoad,
    /// <summary>OpenSSL library is being unloaded.</summary>
    osaUnload);

  /// <summary>
  ///   Definition for the class instance event called by loader in OpenSSL
  ///   library loading or unloading.
  /// </summary>
  TTaurusTLSOnLoadAction = procedure(AAction: TOpenSSLLoadAction) of object;

  /// <summary>
  ///   Library Loader for TaurusTLS.
  /// </summary>
  IOpenSSLLoader = interface
    ['{BBB0F670-CC26-42BC-A9E0-33647361941A}']
    /// <summary>Property get function for OpenSSLPath.</summary>
    function GetOpenSSLPath: string;
    /// <summary>Property get function for SSLLibVersions.</summary>
    function GetSSLLibVersions: string;
    /// <summary>Property set procedure for OpenSSLPath.</summary>
    procedure SetOpenSSLPath(const Value: string);
    /// <summary>Returns the configured or active OpenSSL configuration filename.</summary>
    function GetConfigFile: string;
    /// <summary>Selects an optional OpenSSL configuration file before initialization.</summary>
    procedure SetConfigFile(const Value: string);
    /// <summary>Property get function for FailedToLoad.</summary>
    function GetFailedToLoad: TStringList;

    /// <summary>Loads the OpenSSL library.</summary>
    function Load: Boolean;
    /// <summary>Property set procedure for SSLLibVersions.</summary>
    procedure SetSSLLibVersions(const AValue: string);
    /// <summary>Unloads the OpenSSL library.</summary>
    procedure Unload; overload;
    /// <summary>Unloads the OpenSSL library, optionally resetting the failure state.</summary>
    procedure Unload(const AResetFailState: Boolean); overload;

    /// <summary>True if the OpenSSL library is loaded or False if not.</summary>
    function IsLoaded: Boolean;

    /// <summary>The version numbers for OpenSSL separated by ';'.</summary>
    property SSLLibVersions: string read GetSSLLibVersions write SetSSLLibVersions;
    /// <summary>The directory path where OpenSSL dynamic libraries reside.</summary>
    property OpenSSLPath: string read GetOpenSSLPath write SetOpenSSLPath;
    /// <summary>Optional OpenSSL configuration filename.</summary>
    property ConfigFile: string read GetConfigFile write SetConfigFile;
    /// <summary>Lists all functions that failed to load.</summary>
    property FailedToLoad: TStringList read GetFailedToLoad;
  end;

  /// <summary>
  ///   Definition for the loader procedure obtaining function addresses.
  /// </summary>
  TOpenSSLLoadProc = procedure(const ADllHandle: TIdLibHandle;
    LibVersion: TIdC_UINT; const AFailed: TStringList);

  /// <summary>
  ///   Definition for the unloader procedure resetting function addresses back to nil.
  /// </summary>
  TOpenSSLUnloadProc = procedure;

var
  /// <summary>
  ///   Thread-safe flag indicating initialization state.
  /// </summary>
  SSLIsLoaded: TIdThreadSafeBoolean = nil;

/// <summary>
///   Returns the singleton library loader interface.
/// </summary>
function GetOpenSSLLoader: IOpenSSLLoader;

/// <summary>
///   Registers a symbol loader procedure (LibCrypto / LibSSL).
/// </summary>
procedure Register_SSLLoader(LoadProc: TOpenSSLLoadProc; const module_name: string);

/// <summary>
///   Registers an unloader procedure resetting symbols to nil.
/// </summary>
procedure Register_SSLUnloader(UnloadProc: TOpenSSLUnloadProc);

/// <summary>
///   Registers a lifecycle action hook invoked after load and before unload.
/// </summary>
procedure Register_SSLLoaderAction(const AActionProc: TTaurusTLSOnLoadAction);

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IF NOT DECLARED(LoadLibFunction)}
  {$DEFINE LOADLIB_UNAVAIL}
  {$IFDEF LOADLIB_UNAVAIL}
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
  SysUtils;

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
    FLibraryLoaded: Boolean;
    FFailedToLoad: Boolean;
    FLastLoadActionIdx: NativeInt;
    FConfigFile: string;
    FEffectiveConfigFile: string;

// --- OpenSSL API Wrappers (Static vs Dynamic Bridge) ---
    class procedure SslInitCrypto(opts: TIdC_UINT64; settings: pointer); static; {$IFDEF USE_INLINE}inline;{$ENDIF}
    class function SslModulesLoadFileEx(libctx: pointer; filename, appname: PIdAnsiChar; flags: TIdC_ULONG): TIdC_INT; static; {$IFDEF USE_INLINE}inline;{$ENDIF}
    class function SslGet1DefaultConfigFile: PIdAnsiChar; static; {$IFDEF USE_INLINE}inline;{$ENDIF}
    class procedure SslFree(addr: Pointer); static; {$IFDEF USE_INLINE}inline;{$ENDIF}

// --- Method Pointer Helpers (DCC Unsafe Cast Warning Suppression) ---
    class function IsActionAssigned(const AAction: TTaurusTLSOnLoadAction): Boolean; static; {$IFDEF USE_INLINE}inline;{$ENDIF}
    class procedure ClearAction(var AAction: TTaurusTLSOnLoadAction); static; {$IFDEF USE_INLINE}inline;{$ENDIF}

    // --- Virtual Template Hooks ---
    function DoLoad: Boolean; virtual; abstract;
    procedure DoUnload; virtual; abstract;
    function NeedUnloadCleanup: Boolean; virtual;
    function IsActiveHandlePresent: Boolean; virtual;

    // --- Configuration and Lifecycle Helpers ---
    procedure ApplyConfiguration; virtual;
    procedure DispatchLoadActions; virtual;
    procedure RollbackLoadActions; virtual;
    function CheckOpenSSLVersion(const AVersionNo: TIdC_ULONG): Boolean; virtual;

    // --- IOpenSSLLoader Abstract/Virtual Property Accessors ---
    function GetOpenSSLPath: string; virtual; abstract;
    procedure SetOpenSSLPath(const Value: string); virtual; abstract;
    function GetSSLLibVersions: string; virtual; abstract;
    procedure SetSSLLibVersions(const AValue: string); virtual; abstract;
    function GetConfigFile: string; virtual;
    procedure SetConfigFile(const Value: string); virtual;
    function GetFailedToLoad: TStringList; virtual; abstract;
    function IsLoaded: Boolean; virtual; abstract;
  public
    constructor Create; virtual;
    destructor Destroy; override;

    // Non-virtual template methods managing thread locking and circuit breakers
    function Load: Boolean;
    procedure Unload; overload;
    procedure Unload(const AResetFailState: Boolean); overload;

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
  FLibraryLoaded := False;
  FFailedToLoad := False;
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

function TOpenSSLBaseLoader.Load: Boolean;
begin
  // 1. Fast circuit-breaker pre-check
  Result := not FFailedToLoad;
  if not Result then
    Exit;

  FLoaderLock.Acquire;
  try
    // 2. Re-verify circuit breaker and loaded state under lock
    Result := not FFailedToLoad;
    if not Result then
      Exit;

    if not IsLoaded then
    begin
      FLastLoadActionIdx := -1;
      try
        Result := DoLoad;
        if not Result then
        begin
          // Soft failure: trip circuit breaker and unwind
          Unload(False);
          Exit;
        end;
        FLibraryLoaded := True;
        Result := True;
      except
        // Hard failure: trip circuit breaker, unwind, and re-raise
        Unload(False);
        raise;
      end;
    end
    else
      Result := True;
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
    if IsLoaded or NeedUnloadCleanup then
    begin
      DoUnload;
      FEffectiveConfigFile := '';
    end;

    if AResetFailState then
    begin
      if Assigned(FailedToLoad) then
        FailedToLoad.Clear;
      FFailedToLoad := False;
    end
    else
      FFailedToLoad := True;

    FLibraryLoaded := False;
  finally
    FLoaderLock.Release;
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

    if IsLoaded or IsActiveHandlePresent then
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
    function IsLoaded: Boolean; override;
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

function TOpenSSLStaticLoader.IsLoaded: Boolean;
begin
  FLoaderLock.Acquire;
  try
    Result := FLibraryLoaded;
  finally
    FLoaderLock.Release;
  end;
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
  TOpenSSLDynamicLoader = class(TOpenSSLBaseLoader)
  strict private
    FLibCrypto: TIdLibHandle;
    FLibSSL: TIdLibHandle;
    FOpenSSLPath: string;
    FSSLLibVersions: string;
    FFailed: TStringList;

    function FindLibrary(const LibName, LibVersions: string): TIdLibHandle;
    function LoadAndVerifyLibraries: Boolean;
    procedure BindHeaderSymbols(const AVersionNo: TIdC_ULONG);
    procedure UnbindHeaderSymbols;
    procedure FreeDynamicLibraries;
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
    function IsLoaded: Boolean; override;
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

    if IsLoaded or IsActiveHandlePresent then
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

    if IsLoaded or IsActiveHandlePresent then
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

function TOpenSSLDynamicLoader.IsLoaded: Boolean;
begin
  FLoaderLock.Acquire;
  try
    Result := (FLibCrypto <> IdNilHandle);
  finally
    FLoaderLock.Release;
  end;
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
var
  i: Integer;
begin
  GRegistrationLock.Acquire;
  try
    if Assigned(GUnLoadList) then
      for i := GUnLoadList.Count - 1 downto 0 do
        TOpenSSLUnloadProc(GUnLoadList[i]);
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
  // 1. Roll back lifecycle actions while symbols and handles are still active
  RollbackLoadActions;

  // 2. Unbind symbols back to nil
  UnbindHeaderSymbols;

  // 3. Free OS dynamic library handles
  FreeDynamicLibraries;
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
