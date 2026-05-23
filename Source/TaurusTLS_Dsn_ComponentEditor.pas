unit TaurusTLS_Dsn_ComponentEditor;

{$I TaurusTLSCompilerDefines.inc}
interface

uses
  {$IFDEF DOTNET}
  Borland.Vcl.Design.DesignIntF,
  Borland.Vcl.Design.DesignEditors
  {$ELSE}
    {$IFDEF FPC}
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

{$I TaurusTLS_Vers.inc}

type
  {$IFDEF FPC}
  TTaurusTLSComponentEditor = class(TDefaultComponentEditor)
  {$ELSE}
  TTaurusTLSComponentEditor = class(TDefaultEditor)
  {$ENDIF}
  public
    procedure ExecuteVerb(Index: Integer); override;
    function GetVerb(Index: Integer): string; override;
    function GetVerbCount: Integer; override;
  end;

procedure Register;

implementation
uses
  IdGlobal,
  TaurusTLS,
  TaurusTLS_Dsn_AboutDlg,
  TaurusTLS_Dsn_ResourceStrings,
  TaurusTLS_Unicode_Log;

procedure TTaurusTLSComponentEditor.ExecuteVerb(Index: Integer);
begin
  case Index of
    0 : AboutDlg(gsTaurusTLSVersion);
  end;
end;

function TTaurusTLSComponentEditor.GetVerb(Index: Integer): string;
begin
  case Index of
    0: Result := IndyFormat(RSAAboutMenuItemName, [gsTaurusTLSVersion]);
  end;
end;

function TTaurusTLSComponentEditor.GetVerbCount: Integer;
begin
  Result := 1;
end;

procedure Register;
begin
  RegisterComponentEditor(TTaurusTLSIOHandlerSocket, TTaurusTLSComponentEditor);
  RegisterComponentEditor(TTaurusTLSServerIOHandler, TTaurusTLSComponentEditor);
  RegisterComponentEditor(TTaurusTLSUnicodeLog, TTaurusTLSComponentEditor);
end;

end.
