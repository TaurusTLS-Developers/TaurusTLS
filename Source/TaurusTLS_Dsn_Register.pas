{******************************************************************************}
{*  TaurusTLS                                                                 *}
{*           https://github.com/JPeterMugaas/TaurusTLS                        *}
{*                                                                            *}
{*  Copyright (c) 2024 TaurusTLS Developers, All Rights Reserved              *}
{*                                                                            *}
{* Portions of this software are Copyright (c) 1993 – 2018,                   *}
{* Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  *}
{******************************************************************************}
unit TaurusTLS_Dsn_Register;

{$I TaurusTLSCompilerDefines.inc}
interface

uses
  Classes,
  {$IFDEF DOTNET}
  Borland.Vcl.Design.DesignIntF,
  Borland.Vcl.Design.DesignEditors
  {$ELSE}
    {$IFDEF FPC}
  PropEdits,
  ComponentEditors
    {$ELSE}
      {$IFDEF VCL_6_OR_ABOVE}
  DesignIntf,
  DesignEditors
      {$ELSE}
  Dsgnintf
      {$ENDIF}
    {$ENDIF}
  {$ENDIF}
  ;

{$IFDEF HAS_TSelectionEditor}
type
  TTaurusTLSSelectionEditor = class(TSelectionEditor)
  public
    procedure RequiresUnits(Proc: TGetStrProc); override;
  end;
{$ENDIF}

procedure Register;

implementation

uses
  TaurusTLS_Dsn_ResourceStrings, // for RSRegIndyIOHandlers in dclIndyCore package
  {$IFDEF DCC}
    {$IFDEF VCL_2005_OR_ABOVE}
  ToolsAPI,
  SysUtils,
    {$ENDIF}
  {$ENDIF}
  {$IFDEF WINDOWS}
  {$IFDEF VCL_XE2_OR_ABOVE}WinAPI.Windows{$ELSE}Windows{$ENDIF},
  {$ENDIF}
  {$IFDEF FPC}
  LResources,
  {$ENDIF}
  TaurusTLS,
  TaurusTLS_Unicode_Log;

{$IFNDEF FPC}
  {$IFDEF Borland}
  {$R ..\Source\TaurusTLS_Dsn_Register_16.dcr}
  {$ELSE}
  {$R ..\Source\TaurusTLS_Dsn_Register.dcr}
  {$ENDIF}
{$ENDIF}

{$IFDEF DCC}
  {$IFDEF VCL_2005_OR_ABOVE}
  {$I TaurusTLS_Vers.inc}
var
  AboutBoxServices: IOTAAboutBoxServices = nil;
  AboutBoxIndex: Integer = -1;

procedure RegisterAboutBox;
begin
  SplashScreenServices.AddPluginBitmap(
    gsTaurusTLSProductName +': v' + gsTaurusTLSVersion,
    LoadBitmap(HInstance, 'SPLASH'));
  if Supports(BorlandIDEServices, IOTAAboutBoxServices, AboutBoxServices) then
  begin
    AboutBoxIndex := AboutBoxServices.AddPluginInfo(
      gsTaurusTLSProductName + ' ' + gsTaurusTLSVersion,
      RSTaurusTLSDescription + sLineBreak + sLineBreak
        + RSCopyright + sLineBreak + sLineBreak
        + RSIndyPortionsOf + RSIndyPortionsOfTwo + sLineBreak
        + RSIndyRedistributionOf + sLineBreak + sLineBreak
        + RSDisclaimerCondOne + sLineBreak + slineBreak
        + RSDisclaimerCondTwo + sLineBreak + sLineBreak
        + RSIndyDisclaimer,
      LoadBitmap(HInstance,'SPLASH'),
      False,
      RSTAurusAboutBoxLicences);
  end;
end;

procedure UnregisterAboutBox;
begin
  if (AboutBoxIndex <> -1) and (AboutBoxServices <> nil) then
  begin
    AboutBoxServices.RemovePluginInfo(AboutBoxIndex);
  end;
end;
  {$ENDIF}
{$ENDIF}

{$IFDEF HAS_TSelectionEditor}

{TTaurusTLSSelectionEditor}

procedure TTaurusTLSSelectionEditor.RequiresUnits(Proc: TGetStrProc);
begin
  inherited RequiresUnits(Proc);
  //for new callback event
  Proc('IdCTypes'); {Do not localize}
  Proc('TaurusTLSHeaders_types'); {Do not localize}
  Proc('TaurusTLS_X509');  {Do not localize}
end;

{$ENDIF}

procedure Register;
begin
  RegisterComponents(RSTaurusTLS, [
    TTaurusTLSServerIOHandler,
    TTaurusTLSIOHandlerSocket,
    TTaurusTLSUnicodeLog
  ]);

  {$IFDEF HAS_TSelectionEditor}
  RegisterSelectionEditor(TTaurusTLSServerIOHandler, TTaurusTLSSelectionEditor);
  RegisterSelectionEditor(TTaurusTLSIOHandlerSocket, TTaurusTLSSelectionEditor);
  {$ENDIF}
end;

{$IFDEF DCC}
  {$IFDEF VCL_2005_OR_ABOVE}
initialization
  RegisterAboutBox;
finalization
  UnregisterAboutBox;
  {$ENDIF}
{$ENDIF}
{$IFDEF FPC}
initialization
{$I ..\Source\TaurusTLS_Dsn_Register.lrs}
{$ENDIF}

end.
