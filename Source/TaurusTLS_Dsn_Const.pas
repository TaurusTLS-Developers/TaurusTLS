{******************************************************************************}
{*  TaurusTLS                                                                 *}
{*           https://github.com/JPeterMugaas/TaurusTLS                        *}
{*                                                                            *}
{*  Copyright (c) 2024 TaurusTLS Developers, All Rights Reserved              *}
{*                                                                            *}
{* Portions of this software are Copyright (c) 1993 – 2018,                   *}
{* Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  *}
{******************************************************************************}
unit TaurusTLS_Dsn_Const;

interface


{$I TaurusTLS_Vers.inc}

function GetTaurusTLSVersion(const APrefix, ASuffix: string): string;

function GetThirdPartyAcknowlegements(AAbout: boolean): string;

implementation

uses
  SysUtils,
  TaurusTLS_Dsn_ResourceStrings;

function GetTaurusTLSVersion(const APrefix, ASuffix: string): string;
begin
  Result:=Format(RSTaurusTLSVersion, [APrefix, gsTaurusTLSVersion, ASuffix]);
end;

function GetThirdPartyAcknowlegements(AAbout: boolean): string;
var
  lBreak: string;

begin
  if AAbout then
    lBreak:=sLineBreak
  else
    lBreak:='';

  Result:=Format(RSThirdPartyAcknowlegements, [lBreak]);
end;

end.
