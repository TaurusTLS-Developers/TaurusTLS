{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2024 - 2025 TaurusTLS Developers, All Rights Reserved       * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 – 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  * }
{ ****************************************************************************** }

{$I ..\Source\TaurusTLSCompilerDefines.inc}
{$I TaurusTLSUTCompilerDefines.inc}
/// <summary>
/// Utility classes to extend DUnitX functionality.
/// </summary>
unit TaurusTLS.UT.Utils;
{$I ..\Source\TaurusTLSLinkDefines.inc}

interface

uses
  System.SysUtils, System.Classes, TaurusTLSLoader;

type
  ///  <summary>
  ///  Wrapper for the <see cref="TaurusTLSLoader.IOpenSSLLoader" used by
  ///  TestFixtures derived from <see cref="TaurusTLS.UT.TestClassesTOsslTestBase" class.
  ///  </summary>
  TOsslLoader = class
  public const
    cEnvVarName = 'OPENSSL_PATH';
    cShortOptName = 'osp';
    cLongOptName = 'opensslpath';
  private class var
    FLoader: IOpenSSLLoader;
    FLoadCount: FixedUInt;
  private
    class procedure RegisterOptions; static;
    class function GetFromEnvVar: string; static;
    class procedure SetPath(const Value: string); static;
    class function GetPath: string; static;
    class function GetLoaded: boolean; static;
  public
    class constructor Create;
    class destructor Destroy;
    ///  <summary>
    ///  Tries to load Openssl library. Can be called multiple times.
    ///  <returns>
    ///  - True, if loaded successfully, or already loaded by another caller.
    ///  - False, if it coudn't load
    ///  </returns
    ///  </summary>
    class function Load: boolean; static;
    ///  <summary>
    ///  Tries to load Openssl library. Can be called multiple times.
    ///  <remarks>
    ///  Openssl Library is unloaded when equal number of calls to Load and Unload
    ///  has made.
    ///  </remarks>
    ///  </summary>
    class procedure Unload; static;

    ///  <summary>
    ///  Openssl library loading status.
    ///  <returns>
    ///  - True, if loaded already.
    ///  - False, if not loaded yet or exception happend during the load.
    ///  </returns
    ///  </summary>
    class property Loaded: boolean read GetLoaded;
    ///  <summary>
    ///  Allows to change path to the Openssl library folder
    ///  <remarks>
    ///  Path can be changed if Openssl library unloaded, otherwise exception is rised.
    ///  </remarks>
    ///  </summary>
    class property Path: string read GetPath write SetPath;
  end;

  {$IFDEF USE_FASTMM5}
  TFastMMDebugLog = class
  public const
    cEnvVarNameDll = 'FASTMM_DEBUG_DLL';
    cShortOptNameDll = 'fmd';
    cLongOptNameDll = 'fastmmdebugdll';

    cEnvVarEnable = 'FASTMM_LOG_ENABLEL';
    cShortOptEnable = 'fme';
    cLongOptEnable = 'fastmmlogenable';

    cEnvVarLogName = 'FASTMM_LOG_NAME';
    cShorOptLogName = 'fml';
    cLongOptLogName = 'fastmmlogname';
  private class var
    FDebudDLLName: string;
    FReportFileName: string;
    FActive: boolean;
    FInitialActive: boolean;
  private
    class procedure RegisterOptions; static;
    class function GetActive: boolean; static;
    class procedure SetActive(const Value: boolean); static;
    class function FinalizeFileName(APath, ADefaultFileName: string): string;
  public
    class constructor Create;
    class destructor Destroy;

    class property DebugModeActive: boolean read GetActive write SetActive;
  end;
  {$ENDIF}

  TTestEnumHelperRec<T> = record
    class function ToString(const AValue: T): string; static;
  end;

resourcestring
  rcOssLoaderHelp = 'Specify path to OpenSSL library folder';
  rcFastMMDebugEnableHelp = 'Enable or disable detailed memory leak';
  rcFastMMLogHelp = 'Memory leak report file name.';
{$IFDEF USE_FASTMM5}
  {$IFDEF WIN32}
  rcFastMMDllNamelHelp = 'Path to FastMM_FullDebugMode.dll';
  {$ENDIF}
  {$IFDEF WIN64}
  rcFastMMDllNamelHelp = 'Path to FastMM_FullDebugMode64.dll';
  {$ENDIF}
{$ENDIF}

implementation

uses
  {$IFDEF USE_FASTMM5}
  FastMM5,
  {$ENDIF}
  System.TypInfo, System.SyncObjs,
  DUnitX.CommandLine.Options;

{ TOsslLoader }

class constructor TOsslLoader.Create;
begin
  FLoader:=GetOpenSSLLoader;
  Path:=GetFromEnvVar;
  RegisterOptions;
end;

class destructor TOsslLoader.Destroy;
begin
  Unload;
end;

class function TOsslLoader.GetFromEnvVar: string;
begin
  Result:=GetEnvironmentVariable(cEnvVarName);
end;

class function TOsslLoader.GetLoaded: boolean;
begin
  Result:=FLoadCount > 0;
end;

class function TOsslLoader.Load: boolean;
begin
  Result:=Loaded;
  if Result then
  begin
    TInterlocked.Increment(FLoadCount);
    Exit(True);
  end;
  FLoader:=GetOpenSSLLoader;
  Result:=FLoader.Load;
  if Result then
    TInterlocked.Increment(FLoadCount);
end;

class procedure TOsslLoader.Unload;
var
  lLoadCount: cardinal;
  lSpinW: TSpinWait;

begin
  lSpinW.Reset;
  repeat
    lLoadCount:=FLoadCount;
    if lLoadCount = 0 then
      break;
    if TInterlocked.CompareExchange(FLoadCount, lLoadCount-1, lLoadCount) = lLoadCount then
      break;
    lSpinW.SpinCycle;
  until False;
  if lLoadCount > 0 then
    FLoader.Unload;
end;

class procedure TOsslLoader.RegisterOptions;
begin
  TOptionsRegistry.RegisterOption<string>(cLongOptName, cShortOptName,
    rcOssLoaderHelp,
    procedure(Value: string)
    begin
      Path:=Value;
    end
  );
end;

class function TOsslLoader.GetPath: string;
begin
  Result:=FLoader.OpenSSLPath;
end;

class procedure TOsslLoader.SetPath(const Value: string);
begin
  FLoader.OpenSSLPath:=Value;
end;

{$IFDEF USE_FASTMM5}

{ TFastMMDebugLoader }

class constructor TFastMMDebugLog.Create;
begin
  FDebudDLLName:=FinalizeFileName(GetEnvironmentVariable(cEnvVarNameDll),
    CFastMM_DefaultDebugSupportLibraryName);
  FReportFileName:=FinalizeFileName(GetEnvironmentVariable(cEnvVarLogName),
    FastMM_GetEventLogFilename);
  FActive:=not GetEnvironmentVariable(cEnvVarEnable).IsEmpty;
  RegisterOptions;
end;

class destructor TFastMMDebugLog.Destroy;
begin
  if (not FInitialActive) and DebugModeActive then
    DebugModeActive:=False;
end;

class function TFastMMDebugLog.FinalizeFileName(APath,
  ADefaultFileName: string): string;
begin
  if APath.IsEmpty then
    Exit(ADefaultFileName);
  if APath.EndsWith('\') then
    Exit(APath+ADefaultFileName);
  Result:=APath;
end;

class procedure TFastMMDebugLog.RegisterOptions;
begin
  TOptionsRegistry.RegisterOption<string>(cLongOptNameDll, cShortOptNameDll,
    rcFastMMDllNamelHelp,
    procedure(Value: string)
    begin
      FDebudDLLName:=Value;
    end
  );
  TOptionsRegistry.RegisterOption<boolean>(cShortOptEnable, cLongOptEnable,
    rcFastMMDebugEnableHelp,
    procedure(Value: boolean)
    begin
      FActive:=Value;
    end
  );
  TOptionsRegistry.RegisterOption<string>(cLongOptLogName, cShorOptLogName,
    rcFastMMLogHelp,
    procedure(Value: string)
    begin
      FDebudDLLName:=Value;
    end
  );
end;

class procedure TFastMMDebugLog.SetActive(const Value: boolean);
begin
  if Value <> DebugModeActive then
    if Value then
    begin
      FastMM_DebugSupportLibraryName:=PChar(FDebudDLLName);
      FastMM_SetEventLogFilename(PChar(FReportFileName));
      FastMM_EnterDebugMode;
    end
    else
      FastMM_ExitDebugMode;
end;

class function TFastMMDebugLog.GetActive: boolean;
begin
  Result:=FastMM_DebugModeActive;
end;

{$ENDIF}

{ TTestEnumHelperRec<T> }

class function TTestEnumHelperRec<T>.ToString(const AValue: T): string;
var
  lTI: PTypeInfo ;
  lValue: integer;

begin
  lTI:=TypeInfo(T);
  if Assigned(lTI) then
  begin
    if lTI^.Kind = tkEnumeration then
    begin
      case SizeOf(AValue) of
        1: lValue:=PByte(@AValue)^;
        2: lValue:=PWord(@AValue)^;
        4: lValue:=PInteger(@AValue)^;
      else
        raise EConvertError.CreateFmt(
          'Enumeration type ''%s'' has unsupported data size.', [lTI^.Name]);
      end;
      Result:=GetEnumName(lTI, lValue) // this type cast is safe
    end
    else
      raise EConvertError.CreateFmt(
        'Unable to get Value Name for non-enum type ''%s''.', [lTI^.Name]);
  end
  else
    raise EConvertError.Create('Unable to get type information.');
end;

end.
