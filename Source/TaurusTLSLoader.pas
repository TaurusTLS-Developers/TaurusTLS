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
///   mechanism for the TaurusTLSHeader_ units.
/// </summary>
unit TaurusTLSLoader;

{$I TaurusTLSLinkDefines.inc}

interface

uses
  Classes, IdGlobal, IdCTypes, IdThreadSafe;

{$IF NOT DECLARED(TIdLibHandle)}
type
  {$IFDEF FPC}
  // TODO: use the THANDLE_(32|64|CPUBITS) defines in IdCompilerDefines.inc to decide
  // how to define TIdLibHandle when not using the DynLibs unit?
  TIdLibHandle = {DynLibs.TLibHandle}{$IFDEF WINDOWS}PtrUInt{$ELSE}PtrInt{$ENDIF};
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
  IdNilHandle = {DynLibs.NilHandle}{$IFDEF WINDOWS}PtrUInt(0){$ELSE}PtrInt(0){$ENDIF};
  {$ELSE}
  IdNilHandle = THandle(0);
  {$ENDIF}
{$IFEND}

type
  { IOpenSSLLoader }

  /// <summary>
  ///   Indicates OpenSSL library load action
  /// </summary>
  TOpenSSLLoadAction = (
    /// <summary>
    ///   OpenSSL Library loaded
    /// </summary>
    osaLoad,
    /// <summary>
    ///   OpenSSL Library is being unloaded
    /// </summary>
    osaUnload);
  /// <summary>
  ///   Definitiion for the class instance event called by loader in OpenSSL
  ///   library loading or unloading.
  /// </summary>
  /// <param name="AAction">
  ///   Indicates the action is executed.
  /// </param>
  /// <remarks>
  ///   The registered callbacks executed after OpenSSL library is loaded and
  ///   the OpenSSL routines registered or right before the OpenSSL routines
  ///   unregistered and the OpenSSL library is unloaded.
  /// </remarks>
  TTaurusTLSOnLoadAction = procedure(AAction: TOpenSSLLoadAction) of object;

  /// <summary>
  ///   Library Loader for TaurusTLS.
  /// </summary>
  IOpenSSLLoader = interface
    ['{BBB0F670-CC26-42BC-A9E0-33647361941A}']
    /// <summary>
    ///   Property get function for OpenSSLPath.
    /// </summary>
    function GetOpenSSLPath: string;
    /// <summary>
    ///   Property get function for SSLLibVersions.
    /// </summary>
    function GetSSLLibVersions: string;
    /// <summary>
    ///   Property set procedure for OpenSSLPath.
    /// </summary>
    procedure SetOpenSSLPath(const Value: string);
    /// <summary>
    ///   Property get function for FailedToLoad.
    /// </summary>
    function GetFailedToLoad: TStringList;

    /// <summary>
    ///   Loads the OpenSSL library.
    /// </summary>
    /// <returns>
    ///   True if loaded or already loaded. False if failed to load.
    /// </returns>
    function Load: Boolean;
    /// <summary>
    ///   Property set procedure for SSLLibVersions.
    /// </summary>
    procedure SetSSLLibVersions(const AValue: string);
    /// <summary>
    ///   Unloads the OpenSSL library.
    /// </summary>
    procedure Unload;

    /// <summary>
    ///   True if the OpenSSL library is loaded or False if it is not loaded.
    /// </summary>
    function IsLoaded: Boolean;

    /// <summary>
    ///   The version numbers for the OpenSSL library separated by ";"
    /// </summary>
    /// <value>
    ///   The version numbers for the OpenSSL library. separated by ";".
    /// </value>
    /// <remarks>
    ///   Leave this value to the default values unless you have an exotic
    ///   system.
    /// </remarks>
    property SSLLibVersions: string read GetSSLLibVersions
      write SetSSLLibVersions;
    /// <summary>
    ///   The path of the OpenSSL library.
    /// </summary>
    /// <value>
    ///   The path where the OpenSSL library should be loaded from. If empty,
    ///   the OpenSSL library is loaded from the operating system default
    ///   pathes.
    /// </value>
    property OpenSSLPath: string read GetOpenSSLPath write SetOpenSSLPath;
    /// <summary>
    ///   Lists alll of the functions that failed to load.
    /// </summary>
    /// <value>
    ///   The TStringList that lists the functions that failed to load.
    /// </value>
    property FailedToLoad: TStringList read GetFailedToLoad;
  end;

  /// <summary>
  ///   Definition for the Loader procedure. The procedure will obtain the
  ///   address of the functions in the header.
  /// </summary>
  /// <param name="ADllHandle">
  ///   The handle for the library where the function should be loaded from.
  /// </param>
  /// <param name="LibVersion">
  ///   The OpenSSL version in numerical form.
  /// </param>
  /// <param name="AFailed">
  ///   The TStringList for tracking which functions failed to load.
  /// </param>
  TOpenSSLLoadProc = procedure(const ADllHandle: TIdLibHandle;
    LibVersion: TIdC_UINT; const AFailed: TStringList);
  /// <summary>
  ///   Definition for the unloader procedure. This procedure will set the
  ///   address of the functions in the header back to nil.
  /// </summary>
  TOpenSSLUnloadProc = procedure;

var
  /// <summary>
  ///   Lock that serializes loading and unloading the OpenSSL libraries and
  ///   the providers. Its value is True after <see
  ///   cref="TaurusTLS|LoadOpenSSLLibrary" /> has initialized the libraries.
  /// </summary>
  SSLIsLoaded: TIdThreadSafeBoolean = nil;  //PALOFF - Created and freed objects

  /// <summary>
  ///   Creates the library loader interface if it was not already created.
  /// </summary>
  /// <returns>
  ///   Library loader for TaurusTLS.
  /// </returns>
function GetOpenSSLLoader: IOpenSSLLoader;

/// <summary>
///   Registers a loader procedure that is responsible for obtaining the address
///   of the functions
/// </summary>
/// <param name="LoadProc">
///   The procedure that will obtain the address of the functions in the header.
/// </param>
/// <param name="module_name">
///   The library that is loaded. Is either, "LibCrypto" or "LibSSL".
/// </param>
/// <remarks>
///   Developers should not directly call this procedure. The TaurusTLS OpenSSL
///   headers call this procedure.
/// </remarks>
procedure Register_SSLLoader(LoadProc: TOpenSSLLoadProc;
  const module_name: string);
/// <summary>
///   Regosters an unloader procedure that sets the function pointers to nil.
/// </summary>
/// <remarks>
///   Developers should not directly call this procedure. The TaurusTLS OpenSSL
///   headers call this procedure.
/// </remarks>
procedure Register_SSLUnloader(UnloadProc: TOpenSSLUnloadProc);

/// <summary>
///   Registers the class event hook that called after OpenSSL library loading
///   and before its unloading.
/// </summary>
/// <param name="AActionProc">
///   Event method that will be called on <see
///   cref="TaurusTLSLoader|IOpenSSLLoader" /> event. <br />
/// </param>
procedure Register_SSLLoaderAction(const AActionProc: TTaurusTLSOnLoadAction);

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IF NOT DECLARED( LoadLibFunction)}
//Have to do things this way because LoadLibFunction is now "declared" even though
//it's just a forward reference we intend to resolve.  Seen in Delphi 2009.
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
  TaurusTLS_ResourceStrings
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFDEF WINDOWS},  {$IFDEF VCL_XE2_OR_ABOVE}WinAPI.Windows {$ELSE}Windows{$ENDIF}{$ENDIF}
{$IFDEF FPC}, dynlibs{$ELSE}
  {$IFDEF VCL_2010_OR_ABOVE}, System.IOUtils
  {$ENDIF}
{$ENDIF}
  , TaurusTLSConsts
{$ENDIF}
  ,SysUtils;

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
    property Items[Index: NativeInt]: TTaurusTLSOnLoadAction
      read Get write Put; default;

  end;

{ TMethodList }

constructor TMethodList.Create;
begin
  FList:=TList.Create;
end;

destructor TMethodList.Destroy;
var
  i: NativeInt;

begin
  for i := 0 to FList.Count - 1 do
    ReleaseItem(FList[i]);

  FreeAndNil(FList);
  inherited;
end;

{$IFDEF DCC}{$WARN UNSAFE_CAST OFF}{$ENDIF}
{$IFDEF DCC}{$WARN UNSAFE_CODE OFF}{$ENDIF}

function TMethodList.Add(Item: TTaurusTLSOnLoadAction): NativeInt;
begin
  if Assigned(TMethod(Item).Code) and Assigned(TMethod(Item).Data) then
    Result:=FList.Add(NewItem(Item))
  else
    Result:=-1;
end;

procedure TMethodList.Delete(Index: NativeInt);
var
  lItem: PMethod;

begin
  if (Index >= 0) and (Index < Count) then
  begin
    lItem:=FList.Items[Index];
    try
      FList.Delete(Index);
    finally
       ReleaseItem(lItem);
    end;
  end;
end;

function TMethodList.GetCount: NativeInt;
begin
  Result:=FList.Count;
end;

function TMethodList.Get(Index: NativeInt): TTaurusTLSOnLoadAction;
var
  lItem: PMethod;

begin
  lItem:=FList[Index];
  if Assigned(lItem) then
  begin
    TMethod(Result).Code:=lItem^.Code;
    TMethod(Result).Data:=lItem^.Data;
  end
  else
  begin
    TMethod(Result).Code:=nil;
    TMethod(Result).Data:=nil;
  end
end;

procedure TMethodList.Put(Index: NativeInt; const Value: TTaurusTLSOnLoadAction);
var
  lItem: PMethod;

begin
  if Assigned(TMethod(Value).Code) and Assigned(TMethod(Value).Data) then
  begin
    lItem:=FList[Index];
    if Assigned(lItem) then
      ReleaseItem(lItem);
    FList[Index]:=NewItem(Value);
  end
  else
    Delete(Index);
end;

function TMethodList.NewItem(const AItem: TTaurusTLSOnLoadAction): PMethod;
begin
  Result:=nil;
  try
    New(Result);
    Result^.Code:=TMethod(AItem).Code;
    Result^.Data:=TMethod(AItem).Data;
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

{$IF not declared(NilHandle)}
const
  NilHandle: TIdLibHandle = 0;
{$IFEND}

var
  GOpenSSLLoader: IOpenSSLLoader = nil;
{$IFDEF HAS_UNIT_Generics_Collections}
  GLibCryptoLoadList: TList<TOpenSSLLoadProc> = nil;
  GLibSSLLoadList: TList<TOpenSSLLoadProc> = nil;
  GUnLoadList: TList<TOpenSSLUnloadProc> = nil;
  GOnLoadActionList: TList<TTaurusTLSOnLoadAction> = nil;
{$ELSE}
  GLibCryptoLoadList: TList = nil;  //PALOFF - Created and freed objects
  GLibSSLLoadList: TList = nil;  //PALOFF - Created and freed objects
  GUnLoadList: TList = nil;  //PALOFF - Created and freed objects
  GOnLoadActionList: TMethodList = nil;   //PALOFF - Created and freed objects
{$ENDIF}

function GetOpenSSLLoader: IOpenSSLLoader;
begin
  Result := GOpenSSLLoader;
end;

procedure Register_SSLLoader(LoadProc: TOpenSSLLoadProc;
  const module_name: string);
begin
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
    GLibCryptoLoadList.Add(@LoadProc)
  else if module_name = 'LibSSL' then
    GLibSSLLoadList.Add(@LoadProc)
  else
    raise ETaurusTLSError.CreateFmt(ROSUnrecognisedLibName, [module_name]);
end;

procedure Register_SSLUnloader(UnloadProc: TOpenSSLUnloadProc);
begin
  if GUnLoadList = nil then
{$IFDEF HAS_UNIT_Generics_Collections}
    GUnLoadList := TList<TOpenSSLUnloadProc>.Create;
{$ELSE}
    GUnLoadList := TList.Create;
{$ENDIF}
  GUnLoadList.Add(@UnloadProc);
end;

procedure Register_SSLLoaderAction(const AActionProc: TTaurusTLSOnLoadAction);
begin
  if GOnLoadActionList = nil then
{$IFDEF HAS_UNIT_Generics_Collections}
    GOnLoadActionList := TList<TTaurusTLSOnLoadAction>.Create;
{$ELSE}
    GOnLoadActionList := GOnLoadActionList.Create;
{$ENDIF}
  GOnLoadActionList.Add(AActionProc);
end;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF LOADLIB_UNAVAIL}
function LoadLibFunction(const ALibHandle: TIdLibHandle; const AProcName: TIdLibFuncName): Pointer;
begin
  Result := {$IFDEF WINDOWS} {$IFDEF VCL_XE2_OR_ABOVE}WinAPI.{$ENDIF}Windows.{$ENDIF}GetProcAddress(ALibHandle, PIdLibFuncNameChar(AProcName));
end;

{$ENDIF}

type

  { TOpenSSLLoader }

  TOpenSSLLoader = class(TInterfacedObject, IOpenSSLLoader)
{$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FLibCrypto: TIdLibHandle;
    FLibSSL: TIdLibHandle;
    FOpenSSLPath: string;
    FFailed: TStringList;  //PALOFF - Created and freed objects
    FSSLLibVersions: string;
    FLibraryLoaded: TIdThreadSafeBoolean;  //PALOFF - Created and freed objects
    FFailedToLoad: Boolean;
    function FindLibrary(const LibName, LibVersions: string): TIdLibHandle;
    function GetSSLLibVersions: string;
    procedure SetSSLLibVersions(const AValue: string);
    function GetOpenSSLPath: string;
    procedure SetOpenSSLPath(const Value: string);
    function GetFailedToLoad: TStringList;

  public
    constructor Create;
    destructor Destroy; override;

    function Load: Boolean;
    procedure Unload;
    function IsLoaded : Boolean;
    property OpenSSLPath: string read GetOpenSSLPath write SetOpenSSLPath;
    property FailedToLoad: TStringList read GetFailedToLoad;
  end;

  { TOpenSSLLoader }

constructor TOpenSSLLoader.Create;
begin
  inherited;
  FFailed := TStringList.Create();
  FLibraryLoaded := TIdThreadSafeBoolean.Create;
  FSSLLibVersions := DefaultLibVersions;
  OpenSSLPath := GetEnvironmentVariable(TaurusTLSLibraryPath)
end;

destructor TOpenSSLLoader.Destroy;
begin
  if FLibraryLoaded <> nil then
    FLibraryLoaded.Free;
  if FFailed <> nil then
    FFailed.Free;
  inherited;
end;

function DoLoadLibrary(const FullLibName: string): TIdLibHandle;
{$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := SafeLoadLibrary(FullLibName, {$IFDEF WINDOWS}SEM_FAILCRITICALERRORS
    {$ELSE} 0 {$ENDIF});
end;

{$IF NOT DECLARED(rpos)}
function RPos(Substr: string; S: string): Integer;
var
  i: Integer;
begin
  Result := 0;
  if ((Length(S) > 0) and (Length(Substr) > 0)) then
    if (Length(S) >= Length(Substr)) then
      for i:= (Length(S) - Length(Substr)) downto 1 do
        if (Copy(S, i, Length(Substr)) = Substr) then
        begin
          Result := i;
          Exit;
        end;
end;
{$IFEND}

Function TaurusTLSExtractFileNameWithoutExt(const libname:String) : String;
{$IFDEF USE_INLINE}inline; {$ENDIF}
Begin
  {$IFDEF VCL_2010_OR_ABOVE}
  Result := TPath.GetFileNameWithoutExtension(LibName);
  {$ELSE}
  if ExtractFileExt(libname) <> '' then
  begin
    Result := ExtractFilename(copy(libname,1,rpos(ExtractFileExt(libname),libname)-1))
  end
  else
  begin
    Result := ExtractFilename(libname);
  end;
  {$ENDIF}
End;

function TaurusTLSExtractFileExt(const LibName: String): String;
{$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  {$IFDEF VCL_2010_OR_ABOVE}
  Result := TPath.GetExtension(LibName);
  {$ELSE}
  Result := ExtractFileExt(LibName);
  {$ENDIF}
end;

function TOpenSSLLoader.FindLibrary(const LibName, LibVersions: string)
  : TIdLibHandle;
var
  LibVersionsList: TStringList;  //PALOFF - Created and freed objects
  i: integer;
  {$IFDEF OSX}
  LFileName, LExt: string; // <---- New local vars
  {$ENDIF}
begin
  { Important!!!

    Do not load something named libcrypt.dll because that will cause
    an access violation.  That is part of the LibreOpenSSL package. }
{$IFNDEF WINDOWS}
  Result := DoLoadLibrary(OpenSSLPath + LibName);
  if (Result = NilHandle) and (LibVersions <> '') then
  begin
{$ELSE}
  Result := NilHandle;
{$ENDIF}
  {$IFDEF OSX}
  LFileName := TaurusTLSExtractFileNameWithoutExt(LibName);
  LExt := TaurusTLSExtractFileExt(LibName);
  {$ENDIF}
  LibVersionsList := TStringList.Create;
  try
    LibVersionsList.Delimiter := DirListDelimiter;
    LibVersionsList.StrictDelimiter := true;
    LibVersionsList.DelimitedText := LibVersions; { Split list on delimiter }
    for i := 0 to LibVersionsList.Count - 1 do
    begin
      {$IFDEF OSX}
       // Complete filename based on version being embedded into the name, eg: libcrypto.3.dylib
      Result := DoLoadLibrary(OpenSSLPath + LFileName + LibVersionsList[i] + LExt);
      {$ELSE}
      // Complete filename based on version being the last part of the name, eg: libcrypto.so.3
      Result := DoLoadLibrary(OpenSSLPath + LibName + LibVersionsList[i]);
      {$ENDIF}
      if Result <> NilHandle then
        break;
    end;
  finally
    LibVersionsList.Free;
  end;
{$IFNDEF WINDOWS}
end;
{$ENDIF}
end;

function TOpenSSLLoader.Load: Boolean;
type
  TOpenSSL_version_num = function: TIdC_ULONG; cdecl;

var
  i: integer;
  LOpenSSL_version_num: TOpenSSL_version_num;
  LSSLVersionNo: TIdC_ULONG;

begin
  Result := not FFailedToLoad;
  if not Result then
    Exit;
  FLibraryLoaded.Lock();
  try
    if not FLibraryLoaded.Value then
    begin
      FLibCrypto := FindLibrary(CLibCryptoBase + LibSuffix, FSSLLibVersions);
      FLibSSL := FindLibrary(CLibSSLBase + LibSuffix, FSSLLibVersions);
      Result := not(FLibCrypto = IdNilHandle);
      if Result then
      begin
        Result := not(FLibSSL = IdNilHandle);
      end;
      if not Result then
        Exit;

      { Load Version number }
      LOpenSSL_version_num := LoadLibFunction(FLibCrypto, 'OpenSSL_version_num');
      if not assigned(LOpenSSL_version_num) then
        LOpenSSL_version_num := LoadLibFunction(FLibCrypto, 'SSLeay');
      if not assigned(LOpenSSL_version_num) then
        raise ETaurusTLSError.Create(ROSSLCantGetSSLVersionNo);

      LSSLVersionNo := LOpenSSL_version_num();
      if LSSLVersionNo < min_supported_ssl_version then
        raise ETaurusTLSError.CreateFmt(RSOSSUnsupportedVersion,
          [LSSLVersionNo]);

      LSSLVersionNo := LSSLVersionNo shr 12;

      for i := 0 to GLibCryptoLoadList.Count - 1 do
        TOpenSSLLoadProc(GLibCryptoLoadList[i])
          (FLibCrypto, LSSLVersionNo, FFailed);

      for i := 0 to GLibSSLLoadList.Count - 1 do
        TOpenSSLLoadProc(GLibSSLLoadList[i])(FLibSSL, LSSLVersionNo, FFailed);

      for i := 0 to GOnLoadActionList.Count - 1 do
        GOnLoadActionList[i](osaLoad);

    end;
    FLibraryLoaded.Value := true;
  finally
    FLibraryLoaded.Unlock();
  end;
end;

function TOpenSSLLoader.GetSSLLibVersions: string;
begin
  Result := FSSLLibVersions;
end;

procedure TOpenSSLLoader.SetSSLLibVersions(const AValue: string);
begin
  FSSLLibVersions := AValue;
end;

function TOpenSSLLoader.GetOpenSSLPath: string;
begin
  Result := FOpenSSLPath
end;

procedure TOpenSSLLoader.SetOpenSSLPath(const Value: string);
begin
  if Value = '' then
    FOpenSSLPath := ''
  else
    FOpenSSLPath := IncludeTrailingPathDelimiter(Value);
end;

function TOpenSSLLoader.GetFailedToLoad: TStringList;
begin
  Result := FFailed;
end;

function TOpenSSLLoader.IsLoaded: Boolean;
begin
  Result := FLibCrypto <> NilHandle;
end;

procedure TOpenSSLLoader.Unload;
var
  i: integer;
begin
  FLibraryLoaded.Lock();
  try
    if FLibraryLoaded.Value then
    begin
      for i := GOnLoadActionList.Count - 1 downto 0 do
        GOnLoadActionList[i](osaUnLoad);

      // Reverse order so that unloaders registered after the header units
      // run while the OpenSSL functions are still assigned.
      for i := GUnLoadList.Count - 1 downto 0 do
        TOpenSSLUnloadProc(GUnLoadList[i]);

      FFailed.Clear();

      if FLibSSL <> NilHandle then
        FreeLibrary(FLibSSL);
      if FLibCrypto <> NilHandle then
        FreeLibrary(FLibCrypto);
      FLibSSL := NilHandle;
      FLibCrypto := NilHandle;
    end;
    FFailedToLoad := false;
    FLibraryLoaded.Value := false;
  finally
    FLibraryLoaded.Unlock();
  end;
end;

{$ENDIF}

initialization

  Assert(SSLIsLoaded = nil);
  SSLIsLoaded := TIdThreadSafeBoolean.Create;
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  GOpenSSLLoader := TOpenSSLLoader.Create();
{$ENDIF}

finalization
  //IMPORTANT!!! Pointers should be set to nil just in case
  //the TaurusTLS library is being reloaded.
  FreeAndNil(GOnLoadActionList);
  FreeAndNil(GLibCryptoLoadList);
  FreeAndNil(GLibSSLLoadList);
  FreeAndNil(GUnLoadList);
  FreeAndNil(SSLIsLoaded);
end.

