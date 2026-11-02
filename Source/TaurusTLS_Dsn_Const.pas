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
