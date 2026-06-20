{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2026 TaurusTLS Developers, All Rights Reserved              * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 – 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  * }
{ ****************************************************************************** }
{$I TaurusTLSCompilerDefines.inc}

unit TaurusTLS2;

interface
{$I TaurusTLSLinkDefines.inc}

uses
{$IFDEF WINDOWS}
  WinAPI.Windows,
{$ENDIF}
  Classes,
  SysUtils,
  IdCTypes,
  IdGlobal,
  IdIOHandler,
  IdSocketHandle,
  IdThread,
  IdSSL,
  IdYarn,
  TaurusTLSHeaders_types,
  TaurusTLS_types,
  TaurusTLSExceptionHandlers,
  TaurusTLSFIPS {Ensure FIPS functions initialised},
  TaurusTLS,
  TaurusTLS_Sockets,
  TaurusTLS_X509;

type
  TTaurusTLSIOHandlerStoreAsset = class(TCollectionItem)
  public type
    TAssetKind = (akPath, akText, akBinary);
    TBinaryAsset = TArray<Byte>;

  private
    FKind: TAssetKind;
    FPath: TFileName;
    FText: TStrings;
    FBinary: TBinaryAsset;
    procedure SetText(const Value: TStrings);
  protected
    procedure AssignTo(Destination: TPersistent); override;
  public
    constructor Create(Collection: TCollection); override;
    destructor Destroy; override;
    property Binary: TBinaryAsset read FBinary write FBinary;
  published
    property Kind: TAssetKind read FKind write FKind;
    property Path: TFileName read FPath write FPath;
    property Text: TStrings read FText write SetText;
  end;

  TTaurusTLSIOHandlerStoreAssets = class(TOwnedCollection)
  private
    function GetAssetItem(Index: Integer): TTaurusTLSIOHandlerStoreAsset;
    procedure SetAssetItem(Index: Integer;
      const Value: TTaurusTLSIOHandlerStoreAsset);
  public
    constructor Create(AOwner: TPersistent);
    property Items[Index: Integer]: TTaurusTLSIOHandlerStoreAsset
      read GetAssetItem write SetAssetItem;
  end;

  TTaurusTLSIOHandlerTrustEmail = class(TCollectionItem)
  private
    FEmail: string;
    procedure SetEMail(const Value: string);
  public
    property EMail: string read FEmail write SetEMail;
  end;

  TTaurusTLSIOHandlerTrustEmails = class(TOwnedCollection)
  private
    function GetEmailItem(Index: Integer): TTaurusTLSIOHandlerTrustEmail;
    procedure SetEMailItem(Index: Integer;
      const Value: TTaurusTLSIOHandlerTrustEmail);
  public
    constructor Create(AOwner: TPersistent);
    property Items[Index: Integer]: TTaurusTLSIOHandlerTrustEmail
      read GetEmailItem write SetEMailItem;
  end;

  TTaurusTLSIOHandlerTrustIPAddress = class(TCollectionItem)
  private
    FIPAddress: string;
    procedure SetIPAddress(const Value: string);
  public
    property IPAddress: string read FIPAddress write SetIPAddress;
  end;

  TTaurusTLSIOHandlerTrustIPAddresses = class(TOwnedCollection)
  private
    function GetIPAddressItem(
      Index: Integer): TTaurusTLSIOHandlerTrustIPAddress;
    procedure SetIPAddressItem(Index: Integer;
      const Value: TTaurusTLSIOHandlerTrustIPAddress);
  public
    constructor Create(AOwner: TPersistent);
    property Items[Index: Integer]: TTaurusTLSIOHandlerTrustIPAddress
      read GetIPAddressItem write SetIPAddressItem;
  end;

  TTaurusTLSIOHandlerTrustFQDN = class(TCollectionItem)
  private
    FFqdn: string;
    procedure SetFqdn(const Value: string);
  public
    property Fqdn: string read FFqdn write SetFqdn;
  end;

  TTaurusTLSIOHandlerTrustFqdns = class(TOwnedCollection)
  private
    function GetFqdnItem(Index: Integer): TTaurusTLSIOHandlerTrustFQDN;
    procedure SetFgdnItem(Index: Integer;
      const Value: TTaurusTLSIOHandlerTrustFQDN);
  public
    constructor Create(AOwner: TPersistent);
    property Items[Index: Integer]: TTaurusTLSIOHandlerTrustFQDN
      read GetFqdnItem write SetFgdnItem;
  end;

  TTaurusTLSIOHandlerX509TrustConfig = class(TComponent)
  public const
    cVerifyDefault = [x509vfTrustedFirst];
    cInheritanceDefault = [x509ihfDefault];
    cTrust = trSslClient;
    cPurposeDefault = prpSslClient;
    cHostCheckDefault = [];
    cDepthDefault = 100;
    cSecurityLevelDefault = sb128;

  private
    FAssets: TTaurusTLSIOHandlerStoreAssets;
    FVerify: TTaurusTLSX509VerifyFlags;
    FInheritance: TTaurusTLSX509InheritanceFlags;
    FTrust: TTaurusTLSX509Trust;
    FPurpose: TTaurusTLSX509Purpose;
    FHostCheck: TTaurusTLSX509HostCheckFlags;
    FDepth: cardinal;
    FSecurityLevel: TTaurusTLSSecurityBits;
    FTime: TDateTime;
    FHostNames: TTaurusTLSIOHandlerTrustFqdns;
    FEmails: TTaurusTLSIOHandlerTrustEmails;
    FIPAddresses: TTaurusTLSIOHandlerTrustIPAddresses;
    procedure SetEmails(const Value: TTaurusTLSIOHandlerTrustEmails);
    procedure SetHostNames(const Value: TTaurusTLSIOHandlerTrustFqdns);
    procedure SetIPAddresses(const Value: TTaurusTLSIOHandlerTrustIPAddresses);
  public
    constructor Create(AOwner: TComponent); override;
  published
    property Assets: TTaurusTLSIOHandlerStoreAssets read FAssets write FAssets;
    property Verify: TTaurusTLSX509VerifyFlags read FVerify write FVerify
      default cVerifyDefault;
    property Inheritance: TTaurusTLSX509InheritanceFlags read FInheritance
      write FInheritance default cInheritanceDefault;
    property Trust: TTaurusTLSX509Trust read FTrust write FTrust default cTrust;
    property Purpose: TTaurusTLSX509Purpose read FPurpose write FPurpose
      default cPurposeDefault;
    property HostCheck: TTaurusTLSX509HostCheckFlags read FHostCheck
      write FHostCheck default cHostCheckDefault;
    property Depth: cardinal read FDepth write FDepth default cDepthDefault;
    property SecurityLevel: TTaurusTLSSecurityBits read FSecurityLevel
      write FSecurityLevel default cSecurityLevelDefault;
    property Time: TDateTime read FTime write FTime;
    property HostNames: TTaurusTLSIOHandlerTrustFqdns read FHostNames
      write SetHostNames;
    property Emails: TTaurusTLSIOHandlerTrustEmails read FEmails write SetEmails;
    property IPAddresses: TTaurusTLSIOHandlerTrustIPAddresses
      read FIPAddresses write SetIPAddresses;
  end;

// Just to test purposes
type
  TIOHandlerSocketTest = class(TComponent)
  private
    FTrust: TTaurusTLSIOHandlerX509TrustConfig;
    FClientCerts: TTaurusTLSIOHandlerStoreAssets;
    procedure SetClientCerts(const Value: TTaurusTLSIOHandlerStoreAssets);
    // Event handler fields are below
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
  published
    property Trust: TTaurusTLSIOHandlerX509TrustConfig read FTrust write FTrust;
    property ClientCerts: TTaurusTLSIOHandlerStoreAssets read FClientCerts
      write SetClientCerts;
    // Event handler properties are below
  end;

implementation


{ TTaurusTLSIOHandlerStoreAsset }

procedure TTaurusTLSIOHandlerStoreAsset.AssignTo(Destination: TPersistent);
var
  lDest: TTaurusTLSIOHandlerStoreAsset;

begin
  if Destination is TTaurusTLSIOHandlerStoreAsset then
  begin
    lDest:=TTaurusTLSIOHandlerStoreAsset(Destination);
    lDest.FKind:=FKind;
    case FKind of
    akPath:
      begin
        lDest.FPath:=FPath;
        lDest.FText.Clear;
        SetLength(lDest.FBinary, 0);
      end;
    akText:
      begin
        lDest.FPath:='';
        lDest.FText.Assign(FText);
        SetLength(lDest.FBinary, 0);
      end;
    akBinary:
      begin
        lDest.FPath:='';
        lDest.FText.Clear;
        lDest.FBinary:=FBinary;
      end;
    end;
  end
  else
  inherited;
end;

constructor TTaurusTLSIOHandlerStoreAsset.Create(Collection: TCollection);
begin
  inherited;
  FText:=TStringList.Create;
end;

destructor TTaurusTLSIOHandlerStoreAsset.Destroy;
begin
  FreeAndNil(FText);
  inherited;
end;

procedure TTaurusTLSIOHandlerStoreAsset.SetText(const Value: TStrings);
begin
  FText.Assign(Value);
end;

{ TTaurusTLSIOHandlerStoreAssets }

constructor TTaurusTLSIOHandlerStoreAssets.Create(AOwner: TPersistent);
begin
  inherited Create(AOwner, TTaurusTLSIOHandlerStoreAsset);
end;

function TTaurusTLSIOHandlerStoreAssets.GetAssetItem(
  Index: Integer): TTaurusTLSIOHandlerStoreAsset;
begin
  Result:=TTaurusTLSIOHandlerStoreAsset(inherited GetItem(Index));
end;

procedure TTaurusTLSIOHandlerStoreAssets.SetAssetItem(Index: Integer;
  const Value: TTaurusTLSIOHandlerStoreAsset);
begin
  SetItem(Index, Value);
end;

{ TTaurusTLSIOHandlerX509TrustConfig }

constructor TTaurusTLSIOHandlerX509TrustConfig.Create(AOwner: TComponent);
begin
  inherited;
  Name:=Format('%sTrustVerification', [AOwner.Name]);
  FAssets:=TTaurusTLSIOHandlerStoreAssets.Create(Self);
  FHostNames:=TTaurusTLSIOHandlerTrustFqdns.Create(Self);
  FEmails:=TTaurusTLSIOHandlerTrustEmails.Create(Self);
  FIPAddresses:=TTaurusTLSIOHandlerTrustIPAddresses.Create(Self);
  FVerify:=cVerifyDefault;
  FInheritance:=cInheritanceDefault;
  FTrust:=cTrust;
  FPurpose:=cPurposeDefault;
  FHostCheck:=cHostCheckDefault;
  FDepth:=cDepthDefault;
  FSecurityLevel:=cSecurityLevelDefault;
end;

procedure TTaurusTLSIOHandlerX509TrustConfig.SetEmails(const Value: TTaurusTLSIOHandlerTrustEmails);
begin
  FEmails.Assign(Value);
end;

procedure TTaurusTLSIOHandlerX509TrustConfig.SetHostNames(
  const Value: TTaurusTLSIOHandlerTrustFqdns);
begin
  FHostNames.Assign(Value);
end;

procedure TTaurusTLSIOHandlerX509TrustConfig.SetIPAddresses(
  const Value: TTaurusTLSIOHandlerTrustIPAddresses);
begin
  FIPAddresses.Assign(Value);
end;

{ TTest }

constructor TIOHandlerSocketTest.Create(AOwner: TComponent);
begin
  inherited;
  FTrust:=TTaurusTLSIOHandlerX509TrustConfig.Create(Self);
  FClientCerts:=TTaurusTLSIOHandlerStoreAssets.Create(Self)
end;

destructor TIOHandlerSocketTest.Destroy;
begin
//  FreeAndNil(FClientCerts);
//  FreeAndNil(FTrust);
  inherited;
end;

procedure TIOHandlerSocketTest.SetClientCerts(
  const Value: TTaurusTLSIOHandlerStoreAssets);
begin
  FClientCerts.Assign(Value);
end;

{ TTaurusTLSIOHandlerTrustEmail }

procedure TTaurusTLSIOHandlerTrustEmail.SetEMail(const Value: string);
begin
  { TODO : Add e-mail string format validation }
  FEmail := Value;
end;

{ TTaurusTLSIOHandlerTrustEmails }

constructor TTaurusTLSIOHandlerTrustEmails.Create(AOwner: TPersistent);
begin
  inherited Create(AOwner, TTaurusTLSIOHandlerTrustEmail);
end;

function TTaurusTLSIOHandlerTrustEmails.GetEmailItem(
  Index: Integer): TTaurusTLSIOHandlerTrustEmail;
begin
  Result:=TTaurusTLSIOHandlerTrustEmail(inherited GetItem(Index));
end;

procedure TTaurusTLSIOHandlerTrustEmails.SetEMailItem(Index: Integer;
  const Value: TTaurusTLSIOHandlerTrustEmail);
begin
  inherited SetItem(Index, Value);
end;

{ TTaurusTLSIOHandlerTrustIPAddress }

procedure TTaurusTLSIOHandlerTrustIPAddress.SetIPAddress(const Value: string);
begin
{ TODO : Add IP address string format validation }
  FIPAddress := Value;
end;

{ TTaurusTLSIOHandlerTrustIPAddresses }

constructor TTaurusTLSIOHandlerTrustIPAddresses.Create(AOwner: TPersistent);
begin
  inherited Create(AOwner, TTaurusTLSIOHandlerTrustIPAddress);
end;

function TTaurusTLSIOHandlerTrustIPAddresses.GetIPAddressItem(
  Index: Integer): TTaurusTLSIOHandlerTrustIPAddress;
begin
  Result:=TTaurusTLSIOHandlerTrustIPAddress(inherited GetItem(Index));
end;

procedure TTaurusTLSIOHandlerTrustIPAddresses.SetIPAddressItem(Index: Integer;
  const Value: TTaurusTLSIOHandlerTrustIPAddress);
begin
  inherited SetItem(Index, Value);
end;

{ TTaurusTLSIOHandlerTrustFQDN }

procedure TTaurusTLSIOHandlerTrustFQDN.SetFqdn(const Value: string);
begin
  { TODO : Add FQDN string format validation }
  FFqdn := Value;
end;

{ TTaurusTLSIOHandlerTrustFqdns }

constructor TTaurusTLSIOHandlerTrustFqdns.Create(AOwner: TPersistent);
begin
  inherited Create(AOwner, TTaurusTLSIOHandlerTrustFQDN);
end;

function TTaurusTLSIOHandlerTrustFqdns.GetFqdnItem(
  Index: Integer): TTaurusTLSIOHandlerTrustFQDN;
begin
  Result:=TTaurusTLSIOHandlerTrustFQDN(inherited GetItem(Index));
end;

procedure TTaurusTLSIOHandlerTrustFqdns.SetFgdnItem(Index: Integer;
  const Value: TTaurusTLSIOHandlerTrustFQDN);
begin
  inherited SetItem(Index, Value);
end;

end.
