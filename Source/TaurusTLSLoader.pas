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
  Classes, IdGlobal, IdCTypes;

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
    , TaurusTLSConsts,
  IdThreadSafe
{$ENDIF}
  ,SysUtils;

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
{$ELSE}
  GLibCryptoLoadList: TList = nil;
  GLibSSLLoadList: TList = nil;
  GUnLoadList: TList = nil;
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
    FFailed: TStringList;
    FSSLLibVersions: string;
    FLibraryLoaded: TIdThreadSafeBoolean;
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
  LibVersionsList: TStringList;
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
  OpenSSL_version_num: TOpenSSL_version_num;
  SSLVersionNo: TIdC_ULONG;

begin // FI:C101
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
      OpenSSL_version_num := LoadLibFunction(FLibCrypto, 'OpenSSL_version_num');
      if not assigned(OpenSSL_version_num) then
        OpenSSL_version_num := LoadLibFunction(FLibCrypto, 'SSLeay');
      if not assigned(OpenSSL_version_num) then
        raise ETaurusTLSError.Create(ROSSLCantGetSSLVersionNo);

      SSLVersionNo := OpenSSL_version_num();
      if SSLVersionNo < min_supported_ssl_version then
        raise ETaurusTLSError.CreateFmt(RSOSSUnsupportedVersion,
          [SSLVersionNo]);

      SSLVersionNo := SSLVersionNo shr 12;

      for i := 0 to GLibCryptoLoadList.Count - 1 do
        TOpenSSLLoadProc(GLibCryptoLoadList[i])
          (FLibCrypto, SSLVersionNo, FFailed);

      for i := 0 to GLibSSLLoadList.Count - 1 do
        TOpenSSLLoadProc(GLibSSLLoadList[i])(FLibSSL, SSLVersionNo, FFailed);

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
begin // FI:C101
  FLibraryLoaded.Lock();
  try
    if FLibraryLoaded.Value then
    begin
      for i := 0 to GUnLoadList.Count - 1 do
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

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  GOpenSSLLoader := TOpenSSLLoader.Create();
{$ENDIF}

finalization
  //IMPORTANT!!! Pointers should be set to nil just in case
  //the TaurusTLS library is being reloaded.
  if GLibCryptoLoadList <> nil then
  begin
    FreeAndNil(GLibCryptoLoadList);
  end;
  if GLibSSLLoadList <> nil then
  begin
    FreeAndNil(GLibSSLLoadList);
  end;
  if GUnLoadList <> nil then
  begin
    FreeAndNil(GUnLoadList);
  end;
end.
