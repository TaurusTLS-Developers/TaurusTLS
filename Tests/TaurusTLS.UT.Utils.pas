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
  System.SysUtils, System.Classes;

{$IFDEF USE_FASTMM5}
type
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

resourcestring
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
  DUnitX.CommandLine.Options;

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

end.
