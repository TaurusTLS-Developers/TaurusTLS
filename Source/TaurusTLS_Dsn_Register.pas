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
//  PropEdits,
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
  TaurusTLS_Dsn_Const,
  TaurusTLS_Dsn_ResourceStrings, // for RSRegIndyIOHandlers in dclIndyCore package
  SysUtils,
  {$IF DEFINED(DCC) AND DEFINED(VCL_2010_OR_ABOVE)}
    {$IFDEF VCL_XE2_OR_ABOVE}
  System.Types, Vcl.Controls,
    {$ELSE}
  Types, Controls,
    {$ENDIF}
  TaurusTLSExceptionHandlers,
  {$IFEND}
  {$IFDEF DCC}
    {$IFDEF VCL_2005_OR_ABOVE}
  ToolsAPI,
    {$ENDIF}
  {$ENDIF}
  {$IFDEF WINDOWS}
  {$IFDEF VCL_XE2_OR_ABOVE}WinAPI.Windows{$ELSE}Windows{$ENDIF},
  {$ENDIF}
  {$IFDEF FPC}
  LResources,
  {$ENDIF}
  {$IFDEF FPC}
  PropEdits,
  {$ELSE}
    {$IFDEF VCL_6_OR_ABOVE}
  VCLEditors,
    {$ENDIF}
  {$ENDIF}
  TaurusTLS,
  TaurusTLSLoader,
  TaurusTLS_Unicode_Log;

{$IF DEFINED(DCC) AND DEFINED(VCL_2010_OR_ABOVE)}
type
  // Expected Object Inspector validation errors must bypass the IDE's incident
  // reporter. Keep the IDE exception class and translation in this package.
  ETaurusTLSDesignPropertyError = class(EDesignPropertyError);

  TTaurusTLSConfigFileProperty = class(TFileNameProperty)
  public
    procedure SetValue(const Value: string); override;
    procedure Edit; override;
  end;

  // Reimplement the message interface: the inherited checkbox MouseUp is not
  // virtual and writes through RTTI without calling SetValue.
  TTaurusTLSRequireConfigFileProperty = class(TBooleanProperty, ICustomPropertyMessage)
  public
    procedure SetValue(const Value: string); override;
    procedure Edit; override;
    procedure MouseUp(Button: TMouseButton; Shift: TShiftState; X, Y: Integer;
      InNameRect: Boolean; const ItemRect: TRect; var Handled: Boolean); reintroduce;
  end;

procedure TTaurusTLSConfigFileProperty.SetValue(const Value: string);
begin
  try
    inherited SetValue(Value);
  except
    on E: ETaurusTLSConfigFilePathError do
      raise ETaurusTLSDesignPropertyError.Create(E.Message);
  end;
end;

procedure TTaurusTLSConfigFileProperty.Edit;
begin
  try
    inherited Edit;
  except
    on E: ETaurusTLSConfigFilePathError do
      raise ETaurusTLSDesignPropertyError.Create(E.Message);
  end;
end;

procedure TTaurusTLSRequireConfigFileProperty.SetValue(const Value: string);
begin
  try
    inherited SetValue(Value);
  except
    on E: ETaurusTLSConfigFilePathError do
      raise ETaurusTLSDesignPropertyError.Create(E.Message);
  end;
end;

procedure TTaurusTLSRequireConfigFileProperty.Edit;
begin
  try
    inherited Edit;
  except
    on E: ETaurusTLSConfigFilePathError do
      raise ETaurusTLSDesignPropertyError.Create(E.Message);
  end;
end;

procedure TTaurusTLSRequireConfigFileProperty.MouseUp(Button: TMouseButton;
  Shift: TShiftState; X, Y: Integer; InNameRect: Boolean; const ItemRect: TRect;
  var Handled: Boolean);
begin
  try
    inherited MouseUp(Button, Shift, X, Y, InNameRect, ItemRect, Handled);
  except
    on E: ETaurusTLSConfigFilePathError do
    begin
      Handled := True;
      raise ETaurusTLSDesignPropertyError.Create(E.Message);
    end;
  end;
end;
{$IFEND}

{$IFDEF DCC}
  {$IFDEF VCL_2005_OR_ABOVE}
var
  AboutBoxServices: IOTAAboutBoxServices = nil;
  AboutBoxIndex: Integer = -1;

procedure RegisterAboutBox;
begin
  SplashScreenServices.AddPluginBitmap(
    gsTaurusTLSProductName +GetTaurusTLSVersion(': v', ''),
    LoadBitmap(HInstance, 'SPLASH'));
  if Supports(BorlandIDEServices, IOTAAboutBoxServices, AboutBoxServices) then
  begin
    AboutBoxIndex := AboutBoxServices.AddPluginInfo(
      gsTaurusTLSProductName + ' ' + gsTaurusTLSVersion,
      RSTaurusTLSDescription + sLineBreak + sLineBreak
        + RSCopyright + sLineBreak + sLineBreak
        + GetThirdPartyAcknowlegements(False),
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
    TTaurusTLSUnicodeLog,
    TTaurusTLSLoader
  ]);

  {$IFDEF HAS_TSelectionEditor}
  RegisterSelectionEditor(TTaurusTLSServerIOHandler, TTaurusTLSSelectionEditor);
  RegisterSelectionEditor(TTaurusTLSIOHandlerSocket, TTaurusTLSSelectionEditor);
  {$ENDIF}
  {$IFDEF FPC}
  RegisterPropertyEditor(TypeInfo(TFileName), TTaurusTLSPlatformSetting,
    'ConfigFile', TFileNamePropertyEditor);
  {$ELSE}
    {$IFDEF VCL_6_OR_ABOVE}
      {$IFDEF VCL_2010_OR_ABOVE}
  RegisterPropertyEditor(TypeInfo(TFileName), TTaurusTLSPlatformSetting,
    'ConfigFile', TTaurusTLSConfigFileProperty);
  RegisterPropertyEditor(TypeInfo(Boolean), TTaurusTLSPlatformSetting,
    'RequireConfigFile', TTaurusTLSRequireConfigFileProperty);
      {$ELSE}
  RegisterPropertyEditor(TypeInfo(TFileName), TTaurusTLSPlatformSetting,
    'ConfigFile', TFileNameProperty);
      {$ENDIF}
    {$ENDIF}
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
