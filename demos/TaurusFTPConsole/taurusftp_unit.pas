{$I TaurusTLSCompilerDefines.inc}
unit taurusftp_unit;

interface

uses
{$IFDEF UNIX}
{$IFDEF FPC}
  cthreads,
{$ENDIF}
{$ENDIF}
  Classes,
  SysUtils,
{$IFDEF FPC}
  CustApp,
{$ENDIF}
  {you can add units after this}
  {$IFDEF WINDOWS}
    {$IFDEF VCL_XE2_OR_ABOVE}
  WinAPI.Windows,
    {$ELSE}
  Windows,
    {$ENDIF}
  {$ENDIF}
  IdCTypes,
  IdCompressorZLib,
  IdExplicitTLSClientServerBase,
  IdFTP,
  IdFTPCommon,
  IdGlobal,
  IdZLibHeaders,
  TaurusTLS,
  TaurusTLS_X509,
  TaurusTLSHeaders_crypto,
  TaurusTLSHeaders_types,
  TaurusTLS_Unicode_Log;

type

  { TFTPApplication }

{$IFDEF FPC}
  TFTPApplication = class(TCustomApplication)
{$ELSE}
  TFTPApplication = class(TObject)
{$ENDIF}
  protected
    FFTP: TIdFTP;
    FComp: TIdCompressorZLib;
    FIO: TTaurusTLSIOHandlerSocket;
    FLog: TTaurusTLSUnicodeLog;
    function LoadValidConfig : Boolean;
    // log events
    procedure OnReceived(ASender: TComponent; const AData: string);
    procedure OnSent(ASender: TComponent; const AData: string);
    procedure OnSSLNegotiated(ASender: TTaurusTLSIOHandlerSocket);
    procedure OnDebugMsg(ASender: TObject; const AWrite: Boolean;
      AVersion: TTaurusMsgCBVer; AContentType: TIdC_INT; const buf: TIdBytes;
      SSL: PSSL);
    procedure DoOnVerifyError(ASender: TObject; ACertificate: TTaurusTLSX509;
      const AError: TIdC_LONG; const AMsg, ADescr: String; var VOk: Boolean);
    procedure Open;
    procedure CmdOpen(const ACmd: string);
    procedure CmdDir(const ACmd: string);
    procedure CmdPwd;
    procedure CmdCd(const ACmd: string);
    procedure CmdCdUp;
    procedure CmdPassive(const ACmd: string);
    procedure CmdMLSD(const ACmd: String);
    procedure CmdVerifyDepth(const ACmd : String);
    procedure CmdGet(const ACmd: string);
    procedure CmdPut(const ACmd: string);
    procedure CmdRename(const ACmd: string);
    procedure CmdDelete(const ACmd: string);
    procedure CmdRmdir(const ACmd: string);
    procedure CmdMkdir(const ACmd: string);
    procedure CmdLPwd;
    procedure CmdLCd(const ACmd: string);
    procedure CmdLDir(const ACmd: string);
    procedure CmdClose;
    procedure CmdHelp(const ACmd: string);
    procedure CmdStatus;
    procedure CmdDebugInfo;
    procedure CmdAbout;
    procedure CmdQuote(const ACmd: string);
    procedure CmdDebugTrace(const ACmd: string);
    procedure CmdSecurityLevel(const ACmd: string);
    procedure CmdSaveConfig;
    procedure CmdCertInfo;
    procedure DoCommands;
{$IFDEF FPC}
    procedure DoRun; override;
{$ELSE}
    procedure DoRun;
{$ENDIF}
  public
{$IFDEF FPC}
    constructor Create(TheOwner: TComponent); override;
{$ELSE}
    constructor Create;
{$ENDIF}
    destructor Destroy; override;
{$IFDEF FPC}
    procedure WriteHelp; virtual;
{$ENDIF}
  end;

implementation

uses
  IniFiles,
{$IFDEF VCL_2010_OR_ABOVE}
  System.IOUtils,
{$ENDIF}
  TaurusTLSHeaders_evp,
  TaurusTLSHeaders_ssl3,
  TaurusTLS_Utils,
  TaurusTLSLoader;

const
  Prog_Cmds: array of string = ['exit', 'quit', 'open', 'dir', 'pwd', 'cd',
    'cwd', 'cdup', 'passive', 'put', 'get', 'rename', 'ren', 'delete', 'del',
    'md', 'mkdir', 'rd', 'rmdir', 'lpwd', 'lcd', 'ldir', 'close', 'help', '?',
    'status', 'debug-info', 'about', 'quote', 'debug-trace', 'security-level',
    'save-config', 'cert-info', 'mlsd','verify-depth'];

function RightJustify(const AText: String; ALen: Integer): string;
{$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := '';
  if ALen > Length(AText) then
  begin
    Result := StringOfChar(' ', ALen - Length(AText)) + AText;
  end
  else
  begin
    Result := AText;
  end;
end;

procedure PrintRightJustifyIfTextNotEmpty(const ALine : String; const ALength : Integer;
   const ALineText : String);
{$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  if ALineText <> '' then
  begin
    WriteLn(RightJustify(ALine,ALength) + ' '+ALineText);
  end;
end;

function LeftJustify(const AText: String; ALen: Integer): string;
{$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := '';
  if ALen > Length(AText) then
  begin
    Result := AText + StringOfChar(' ', ALen - Length(AText));
  end
  else
  begin
    Result := AText;
  end;
end;

{$IFDEF WINDOWS}
function StdOutIsRedirected: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
var
  Mode: DWORD;
begin
  Result := not GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), Mode);
end;
{$ENDIF}

procedure WriteString(const S : String); {$IFDEF USE_INLINE}inline; {$ENDIF}
{$IFNDEF WINDOWS}
begin
  WriteLn(S);
{$ELSE}
var
  LDummy : DWORD;
  LConsole : THandle;
begin
  if StdOutIsRedirected then
  begin
    WriteLn(S);
  end
  else
  begin
    LConsole := GetStdHandle(STD_OUTPUT_HANDLE);
    WriteConsole(LConsole, PChar(S), Length(S),LDummy,nil);
  end;
{$ENDIF}
end;

procedure WriteLnString(const S : String);
begin
  WriteString(S);
  WriteString(sLineBreak);
end;

procedure ParseArgs(const AArgs: String; AStrings: TStrings);
var
{$IFNDEF USE_INLINE_VAR}
  LBuf, LArg: String;
{$ENDIF}
  LOpenQuote: Integer;
begin
  AStrings.BeginUpdate;
  try
    AStrings.Clear;
{$IFDEF USE_INLINE_VAR}
    var
      LBuf, LArg: String;
{$ENDIF}
    LBuf := AArgs;
    repeat
      LBuf := TrimLeft(LBuf);
      if LBuf = '' then
      begin
        Break;
      end;
      LOpenQuote := IndyPos('"', LBuf);
      if (LOpenQuote = 1) then
      begin
        Fetch(LBuf, '"');
        LArg := Fetch(LBuf, '"');
      end
      else
      begin
        LArg := TrimLeft(Fetch(LBuf));
      end;
      AStrings.Add(LArg);
    until False;
  finally
    AStrings.EndUpdate;
  end;
end;

function CreateAndGetCOnfigDir: String;
{$IFDEF USE_INLINE}inline; {$ENDIF}
begin
{$IFNDEF FPC}
  Result := TPath.GetHomePath() + TPath.DirectorySeparatorChar + 'taurustls' +
    TPath.DirectorySeparatorChar;
{$ELSE}
  Result := GetAppConfigDir(False);
{$ENDIF}
  if not DirectoryExists(Result) then
  begin
    SysUtils.CreateDir(Result);
  end;
end;


procedure SetHostAndIPVersion(const AHostName : String; AFTP : TIdFTP);
{$IFDEF USE_INLINE}inline; {$ENDIF}
{
We set the FTP host property in a roundabout way here so that we can
also handle where a hostname is set to an IPv6 address.
}
begin
  AFTP.Host := MakeCanonicalIPv6Address(AHostName);
  if AFTP.Host = '' then
  begin
    AFTP.Host := AHostName;
    AFTP.IPVersion := Id_IPv4;
  end
  else
  begin
    AFTP.IPVersion := Id_IPv6;
  end;
end;

{ TFTPApplication }

procedure TFTPApplication.OnDebugMsg(ASender: TObject; const AWrite: Boolean;
  AVersion: TTaurusMsgCBVer; AContentType: TIdC_INT; const buf: TIdBytes;
  SSL: PSSL);
{$IFNDEF USE_INLINE_VAR}
var
  LOutput: String;
{$ENDIF}
begin
{$IFDEF USE_INLINE_VAR}
  var
    LOutput: String;
{$ENDIF}
  if AWrite then
  begin
    LOutput := 'Read  - ';
  end
  else
  begin
    LOutput := 'Write - ';
  end;
  case AVersion of
    verSSL3Header:
      LOutput := LOutput + LeftJustify('SSL3', 9) + ' - ';
    verTLS1:
      LOutput := LOutput + LeftJustify('TLS1', 9) + ' - ';
    verTLS1_1:
      LOutput := LOutput + LeftJustify('TLS1.1', 9) + ' - ';
    verTLS1_2:
      LOutput := LOutput + LeftJustify('TLS1.2', 9) + ' - ';
    verTLS1_3:
      LOutput := LOutput + LeftJustify('TLS1.3', 9) + ' - ';
    verDTLS1:
      LOutput := LOutput + LeftJustify('DTLS1.1', 9) + ' - ';
    verDTLS1_2:
      LOutput := LOutput + LeftJustify('DTLS1.2', 9) + ' - ';
    verDTLSBadVer:
      LOutput := LOutput + LeftJustify('Bad DTLS', 9) + ' - ';
    verQUIC:
      LOutput := LOutput + LeftJustify('QUIC', 9) + ' - ';
    verTLSAny:
      LOutput := LOutput + LeftJustify('Any TLS', 9) + ' - ';
  end;
  case AContentType of
    SSL3_RT_CHANGE_CIPHER_SPEC:
      LOutput := LOutput + LeftJustify('Change Cipher Spec', 22) + ' - ';
    SSL3_RT_ALERT:
      LOutput := LOutput + LeftJustify('Alert', 22) + ' - ';
    SSL3_RT_HANDSHAKE:
      LOutput := LOutput + LeftJustify('Handshake', 22) + ' - ';
    SSL3_RT_APPLICATION_DATA:
      LOutput := LOutput + LeftJustify('Application Data', 22) + ' - ';
    DTLS1_RT_HEARTBEAT:
      LOutput := LOutput + LeftJustify('Heartbeat', 22) + ' - ';
    (* Pseudo content types to indicate additional parameters *)
    TLS1_RT_CRYPTO:
      LOutput := LOutput + LeftJustify('Crypto', 22) + ' - ';
    TLS1_RT_CRYPTO_PREMASTER:
      LOutput := LOutput + LeftJustify('Crypto Premaster', 22) + ' - ';
    TLS1_RT_CRYPTO_CLIENT_RANDOM:
      LOutput := LOutput + LeftJustify('Crypto Client Random', 22) + ' - ';
    TLS1_RT_CRYPTO_SERVER_RANDOM:
      LOutput := LOutput + LeftJustify('Crypto Server Random', 22) + ' - ';
    TLS1_RT_CRYPTO_MASTER:
      LOutput := LOutput + LeftJustify('Crypto Master', 22) + ' - ';
    // TLS1_RT_CRYPTO_READ:
    // LOutput := LOutput + LeftJustify('Crypto Read',22)+' - ';
    // TLS1_RT_CRYPTO_WRITE:
    // LOutput := LOutput + LeftJustify('Crypto Write',22)+' - ';
    TLS1_RT_CRYPTO_MAC:
      LOutput := LOutput + LeftJustify('Crypto MAC', 22) + ' - ';
    TLS1_RT_CRYPTO_KEY:
      LOutput := LOutput + LeftJustify('Crypto Key', 22) + ' - ';
    TLS1_RT_CRYPTO_IV:
      LOutput := LOutput + LeftJustify('Crypto IV', 22) + ' - ';
    TLS1_RT_CRYPTO_FIXED_IV:
      LOutput := LOutput + LeftJustify('Crypto Fixed IV', 22) + ' - ';

    (* Pseudo content types for SSL/TLS header info *)
    SSL3_RT_HEADER:
      LOutput := LOutput + LeftJustify('Header', 22) + ' - ';
    SSL3_RT_INNER_CONTENT_TYPE:
      if Length(buf) > 0 then
      begin
        LOutput := LOutput + LeftJustify('Inner Content Type ' +
          IntToHex(buf[0], 2), 22) + ' - ';
      end;
    // * Pseudo content types for QUIC */
    SSL3_RT_QUIC_DATAGRAM:
      LOutput := LOutput + LeftJustify('QUIC Datagram', 22) + ' - ';
    SSL3_RT_QUIC_PACKET:
      LOutput := LOutput + LeftJustify('QUIC Packet', 22) + ' - ';
    SSL3_RT_QUIC_FRAME_FULL:
      LOutput := LOutput + LeftJustify('QUIC Frame Full', 22) + ' - ';
    SSL3_RT_QUIC_FRAME_HEADER:
      LOutput := LOutput + LeftJustify('QUIC Frame Header', 22) + ' - ';
    SSL3_RT_QUIC_FRAME_PADDING:
      LOutput := LOutput + LeftJustify('QUIC Frame Padding', 22) + ' - ';
  end;
  LOutput := LOutput + RightJustify(IntToStr(Length(buf)), 10) + ' - ';
  LOutput := LOutput + ToHex(buf, 20, 0);
  WriteLn(LOutput);
end;

procedure TFTPApplication.OnReceived(ASender: TComponent;
  const AData: string);
begin
  WriteString(AData);
end;

procedure TFTPApplication.OnSent(ASender: TComponent;
  const AData: string);
begin
  if IndyPos('PASS ', AData) > 0 then
  begin
    WriteLn('PASS ***');
  end
  else
  begin
    WriteString(AData);
  end;
end;

procedure TFTPApplication.OnSSLNegotiated(ASender: TTaurusTLSIOHandlerSocket);
{$IFNDEF USE_INLINE_VAR}
var
  LStr: string;
{$ENDIF}
begin
  if Assigned(ASender.SSLSocket) then
  begin
{$IFDEF USE_INLINE_VAR}
    var
      LStr: string;
{$ENDIF}
    LStr := ASender.SSLSocket.SSLProtocolVersionStr;
    if LStr <> '' then
    begin
      WriteLn('       TLS Version: ' + LStr);
    end;
    if Assigned(ASender.SSLSocket.Cipher) then
    begin
      LStr := ASender.SSLSocket.Cipher.Name;
      if LStr <> '' then
      begin
        WriteLn('       Cipher Name: ' + LStr);
      end;
      LStr := ASender.SSLSocket.Cipher.Description;
      if LStr <> '' then
      begin
        WriteLn('Cipher Description: ' + Trim(LStr));
      end;
      LStr := ASender.SSLSocket.Cipher.Version;
      if LStr <> '' then
      begin
        WriteLn('    Cipher Version: ' + LStr);
      end;
      if ASender.SSLSocket.Cipher.Bits > 0 then
      begin
        WriteLn('       Cipher Bits: ' +
          IntToStr(ASender.SSLSocket.Cipher.Bits));
      end;
    end;
  end;
end;

procedure TFTPApplication.Open;
begin
  FFTP.Connect;
  if FFTP.IsCompressionSupported and FComp.IsReady then
  begin
    FFTP.TransferMode(dmDeflate);
  end;
end;

procedure TFTPApplication.CmdOpen(const ACmd: string);
var
  LCmdParams: TStrings;
begin
  LCmdParams := TStringList.Create;
  try
    ParseArgs(ACmd, LCmdParams);
    if LCmdParams.Count >= 3 then
    begin
      case IdGlobal.PosInStrArray(LCmdParams[0],
        ['ftp', 'ftps', 'ftpsi'], False) of
        0:
          begin
            FFTP.UseTLS := utNoTLSSupport;
            if LCmdParams.Count > 3 then
            begin
              SetHostAndIPVersion(LCmdParams[1],FFTP);
              FFTP.Username := LCmdParams[2];
              FFTP.Password := LCmdParams[3];
              Open;
            end
            else
            begin
              WriteLn('Syntax Error');
            end;
          end;
        1:
          begin
            FFTP.UseTLS := utUseExplicitTLS;
            FFTP.DataPortProtection := ftpdpsPrivate;
            if LCmdParams.Count > 3 then
            begin
              SetHostAndIPVersion(LCmdParams[1],FFTP);
              FFTP.Username := LCmdParams[2];
              FFTP.Password := LCmdParams[3];
              Open;
            end
            else
            begin
              WriteLn('Syntax Error');
            end;
          end;
        2:
          begin
            FFTP.UseTLS := utUseImplicitTLS;
            FFTP.DataPortProtection := ftpdpsPrivate;
            if LCmdParams.Count > 3 then
            begin
              SetHostAndIPVersion(LCmdParams[1],FFTP);
              FFTP.Username := LCmdParams[2];
              FFTP.Password := LCmdParams[3];
              Open;
            end
            else
            begin
              WriteLn('Syntax Error');
            end;
          end
      else
        begin
          FFTP.UseTLS := utNoTLSSupport;
          SetHostAndIPVersion(LCmdParams[0],FFTP);
          FFTP.Username := LCmdParams[1];
          FFTP.Password := LCmdParams[2];
          Open;
        end;
      end;
    end
    else
    begin
      WriteLn('Syntax Error');
    end;
  finally
    FreeAndNil(LCmdParams);
  end;
end;

procedure TFTPApplication.CmdDir(const ACmd: string);
var
  i: Integer;
  LDir: TStringList;
begin
  LDir := TStringList.Create;
  try
    ParseArgs(Trim(ACmd), LDir);
    if FFTP.Connected then
    begin
      if LDir.Count > 0 then
      begin
        FFTP.List(LDir[0]);
      end
      else
      begin
        FFTP.List;
      end;
      for i := 0 to FFTP.ListResult.Count - 1 do
      begin
        WriteLnString(FFTP.ListResult[i]);
      end;
    end
    else
    begin
      WriteLn('Must be connected to use this command');
    end;
  finally
    FreeAndNil(LDir);
  end;
end;

procedure TFTPApplication.CmdPwd;
begin
  if FFTP.Connected then
  begin
    FFTP.RetrieveCurrentDir;
  end
  else
  begin
    WriteLn('Must be connected to use this command');
  end;
end;

procedure TFTPApplication.CmdQuote(const ACmd: string);
begin
  if TrimLeft(ACmd) <> '' then
  begin
    if FFTP.Connected then
    begin
      FFTP.Quote(TrimLeft(ACmd));
    end
    else
    begin
      WriteLn('Must be connected to use this command');
    end;
  end
  else
  begin
    WriteLn('Syntax Error');
  end;
end;

procedure TFTPApplication.CmdAbout;
begin
  WriteLn('TaurusFTP Console Demo');
  WriteLn('Copyright (c) 2025 TaurusTLS Developers');
end;

procedure TFTPApplication.CmdCd(const ACmd: string);
var
  LDir: TStringList;
begin
  LDir := TStringList.Create;
  try
    ParseArgs(Trim(ACmd), LDir);
    if LDir.Count > 0 then
    begin
      if FFTP.Connected then
      begin
        FFTP.ChangeDir(LDir[0]);
      end
      else
      begin
        WriteLn('Must be connected to use this command');
      end;
    end
    else
    begin
      WriteLn('Syntax Error');
    end;
  finally
    FreeAndNil(LDir);
  end;
end;

procedure TFTPApplication.CmdCdUp;
begin
  if FFTP.Connected then
  begin
    FFTP.ChangeDirUp;
  end
  else
  begin
    WriteLn('Must be connected to use this command');
  end;
end;

procedure TFTPApplication.CmdCertInfo;
begin
  if Assigned(FIO.SSLSocket) and Assigned(FIO.SSLSocket.PeerCert) then
  begin
    WriteLn(FIO.SSLSocket.PeerCert.DisplayInfo.Text);
  end
  else
  begin
    WriteLn('Must be connected to a FTPS server.');
  end;
end;

procedure TFTPApplication.CmdPassive(const ACmd: string);
var
  LCmdParams: TStrings;
begin
  LCmdParams := TStringList.Create;
  try
    ParseArgs(ACmd, LCmdParams);
    if LCmdParams.Count > 0 then
    begin
      case PosInStrArray(LCmdParams[0], ['on', 'true', 'off', 'false'],
        False) of
        0, 1:
          FFTP.Passive := True;
        2, 3:
          FFTP.Passive := False;
      else
        begin
          FFTP.Passive := not FFTP.Passive;
        end;
      end;
    end
    else
    begin
      FFTP.Passive := not FFTP.Passive;
    end;
  finally
    FreeAndNil(LCmdParams);
  end;
  if FFTP.Passive then
  begin
    WriteLn('Passive: True');
  end
  else
  begin
    WriteLn('Passive: False');
  end;
end;

procedure TFTPApplication.CmdMLSD(const ACmd: String);
var
  LCmdParams: TStrings;
begin
  LCmdParams := TStringList.Create;
  try
    ParseArgs(ACmd, LCmdParams);
    if LCmdParams.Count > 0 then
    begin
      case PosInStrArray(LCmdParams[0], ['on', 'true', 'off', 'false'],
        False) of
        0, 1:
          FFTP.UseMLIS := True;
        2, 3:
          FFTP.UseMLIS := False;
      else
        begin
          FFTP.UseMLIS := not FFTP.UseMLIS;
        end;
      end;
    end
    else
    begin
      FFTP.UseMLIS := not FFTP.UseMLIS;
    end;
  finally
    FreeAndNil(LCmdParams);
  end;
  if FFTP.UseMLIS then
  begin
     WriteLn('MLSD: True (use MLSD for directory listing)');
  end
  else
  begin
     WriteLn('MLSD: False (use DIR for directory listing)');
  end;
end;

procedure TFTPApplication.CmdVerifyDepth(const ACmd : String);
var
  LCmdParams: TStrings;
begin
  LCmdParams := TStringList.Create;
  try
    ParseArgs(ACmd, LCmdParams);
    if LCmdParams.Count > 0 then
    begin
      if IdGlobal.IsNumeric(LCmdParams[0]) then
      begin
        FIO.SSLOptions.VerifyDepth := StrToInt(LCmdParams[0]);
      end;
    end
  finally
    FreeAndNil(LCmdParams);
  end;
  WriteLn('Verify Depth: '+IntToStr(FIO.SSLOptions.VerifyDepth));
end;

procedure TFTPApplication.CmdGet(const ACmd: string);
var
  LCmdParams: TStrings;
  LDestFile: TStream;
begin
  LCmdParams := TStringList.Create;
  try
    ParseArgs(ACmd, LCmdParams);
    if LCmdParams.Count > 0 then
    begin

      FFTP.TransferType := ftBinary;
      LDestFile := TFileStream.Create(LCmdParams[0], fmCreate);
      try
        FFTP.Get(ExtractFileName(LCmdParams[0]), LDestFile);
      finally
        FreeAndNil(LDestFile);
      end;
      FileSetDate(LCmdParams[0],
        DateTimeToFileDate(FFTP.FileDate(ExtractFileName(LCmdParams[0]))));
    end
    else
    begin
      WriteLn('Syntax Error');
    end;
  finally
    FreeAndNil(LCmdParams);
  end;
end;

procedure TFTPApplication.CmdPut(const ACmd: string);
var
  LSrcFile: TStream;
{$IFNDEF FPC}
  LDateTime: TDateTime;
{$ENDIF}
  LCmdParams: TStrings;
begin
  LCmdParams := TStringList.Create;
  try
    ParseArgs(ACmd, LCmdParams);
    if LCmdParams.Count > 0 then
    begin

      FFTP.TransferType := ftBinary;
      LSrcFile := TFileStream.Create(LCmdParams[0], fmOpenRead);
      try
        FFTP.Put(LSrcFile, ExtractFileName(LCmdParams[0]));
      finally
        FreeAndNil(LSrcFile);
      end;
{$IFDEF FPC}
      FFTP.SetModTime(ExtractFileName(LCmdParams[0]),
        FileDateToDateTime(FileAge(LCmdParams[0])));
{$ELSE}
      if FileAge(LCmdParams[0], LDateTime) then
      begin
        FFTP.SetModTime(ExtractFileName(LCmdParams[0]), LDateTime);
      end;
{$ENDIF}
    end
    else
    begin
      WriteLn('Syntax Error');
    end;
  finally
    FreeAndNil(LCmdParams);
  end;
end;

procedure TFTPApplication.CmdRename(const ACmd: string);
var
  LCmdParams: TStrings;
begin
  LCmdParams := TStringList.Create;
  try
    ParseArgs(ACmd, LCmdParams);
    if LCmdParams.Count > 1 then
    begin
      FFTP.Rename(LCmdParams[0], LCmdParams[1]);
    end
    else
    begin
      WriteLn('Syntax Error');
    end;
  finally
    FreeAndNil(LCmdParams);
  end;
end;

procedure TFTPApplication.CmdDebugInfo;
var
  i: Integer;
{$IFNDEF USE_INLINE_VAR}
  LVer: string;
{$ENDIF}
begin
{$IFNDEF FPC}
  WriteLn('Operating System: ' + TOSVersion.ToString);
  {$IFDEF VCL_12_OR_ABOVE}
  WriteLn('     RTL Version: ' + IntToStr(Hi(GetRTLVersion)) + '.' +
    IntToStr(Lo(GetRTLVersion)));
  WriteLn('Compiler Version: ' + IntToStr(Hi(GetCompilerVersion)) + '.' +
    IntToStr(Lo(GetCompilerVersion)));
  {$ENDIF}
{$ELSE}
  WriteLn('       Target OS: ', {$I %FPCTARGETOS%});
  WriteLn('      Target CPU: ', {$I %FPCTARGETCPU%});
{$ENDIF}
  WriteLn('    Indy Version: ' + gsIdVersion);
  {$IFDEF USE_INLINE_VAR}
  var
     LVer: string;
  {$ENDIF}
  LVer := OpenSSLVersion;
  begin
    if LVer <> '' then
    begin

      WriteLn(' OpenSSL Version: ' + LVer);
      PrintRightJustifyIfTextNotEmpty('Config Dir:', 20,OpenSSLDir);
      PrintRightJustifyIfTextNotEmpty('Modules Dir:', 20,OpenSSLModulesDir);
      PrintRightJustifyIfTextNotEmpty('Engines Dir:', 20,OpenSSLEnginesDir);

    end
    else
    begin
      WriteLn(' OpenSSL Version: OpenSSL NOT loaded.');
    end;
  end;
  if GetOpenSSLLoader.GetFailedToLoad.Count > 0 then
  begin
    WriteLn('  Failed To Load: ');
    for i := 0 to GetOpenSSLLoader.GetFailedToLoad.Count - 1 do
    begin
      WriteLn('     ' + GetOpenSSLLoader.GetFailedToLoad[i]);
    end;
  end;

  if IdZLibHeaders.Load then
  begin
    WriteLn('    ZLib Version: ' + zlibVersion());
  end
  else
  begin
    WriteLn('    ZLib Version: ZLIB not loaded');
  end;
end;

procedure TFTPApplication.CmdDebugTrace(const ACmd: string);
var
  LCmdParams: TStrings;
begin
  LCmdParams := TStringList.Create;
  try
    ParseArgs(ACmd, LCmdParams);
    if LCmdParams.Count > 0 then
    begin
      case PosInStrArray(LCmdParams[0], ['on', 'true', 'off', 'false'],
        False) of
        0, 1:
          FIO.OnDebugMessage := OnDebugMsg;

        2, 3:
          FIO.OnDebugMessage := nil;
      else
        begin
          if Assigned(FIO.OnDebugMessage) then
          begin
            FIO.OnDebugMessage := nil
          end
          else
          begin
            FIO.OnDebugMessage := OnDebugMsg;
          end;
        end;
      end;
    end
    else
    begin
      if Assigned(FIO.OnDebugMessage) then
      begin
        FIO.OnDebugMessage := nil
      end
      else
      begin
        FIO.OnDebugMessage := OnDebugMsg;
      end;
    end;
    if Assigned(FIO.OnDebugMessage) then
    begin
      WriteLn('Debug-trace: True');
    end
    else
    begin
      WriteLn('Debug-trace: False');
    end;
  finally
    FreeAndNil(LCmdParams);
  end;

end;

procedure TFTPApplication.CmdDelete(const ACmd: string);
var
  LCmdParams: TStrings;
begin
  LCmdParams := TStringList.Create;
  try
    ParseArgs(ACmd, LCmdParams);
    if LCmdParams.Count > 0 then
    begin
      FFTP.delete(LCmdParams[0]);
    end
    else
    begin
      WriteLn('Syntax Error');
    end;
  finally
    FreeAndNil(LCmdParams);
  end;
end;

procedure TFTPApplication.CmdRmdir(const ACmd: string);
var
  LCmdParams: TStrings;
begin
  LCmdParams := TStringList.Create;
  try
    ParseArgs(ACmd, LCmdParams);
    if LCmdParams.Count > 0 then
    begin
      FFTP.RemoveDir(LCmdParams[0]);
    end
    else
    begin
      WriteLn('Syntax Error');
    end;
  finally
    FreeAndNil(LCmdParams);
  end;
end;

procedure TFTPApplication.CmdSaveConfig;
var
  LIni: TIniFile;
begin
  LIni := TIniFile.Create(CreateAndGetCOnfigDir + 'taurusftp.ini');
  try
    LIni.WriteBool('debug', 'trace', Assigned(FIO.OnDebugMessage));
    LIni.WriteInteger('security', 'security_level',
      FIO.SSLOptions.SecurityLevel);
    LIni.WriteInteger('security','verify_depth',FIO.SSLOptions.VerifyDepth);
    LIni.WriteBool('ftp', 'passive', FFTP.Passive);
    LIni.WriteBool('ftp', 'use_MLSD', FFTP.UseMLIS);
    LIni.WriteString('certificate','public_key',FIO.ClientCert.PublicKey);
    LIni.WriteString('certificate','private_key',FIO.ClientCert.PrivateKey);
    LIni.WriteString('certificate','root_key',FIO.ClientCert.RootKey);
    LIni.WriteString('certificate','dh_params',FIO.ClientCert.DHParamsFile);
  finally
    FreeAndNil(LIni);
  end;
end;

procedure TFTPApplication.CmdSecurityLevel(const ACmd: string);
var
  LCmdParams: TStrings;
begin
  LCmdParams := TStringList.Create;
  try
    ParseArgs(ACmd, LCmdParams);
    if LCmdParams.Count > 0 then
    begin
      if PosInStrArray(LCmdParams[0], ['0', '1', '2', '3', '4', '5']) > -1 then
      begin
        FIO.SSLOptions.SecurityLevel := StrToInt(LCmdParams[0]);
      end;
    end;
  finally
    FreeAndNil(LCmdParams);
  end;
  Write('Security level is ');
  case FIO.SSLOptions.SecurityLevel of
    0:
      WriteLn('0. Everything is permitted. ');
    1:
      WriteLn('1. A minimum of 80 security bits is permitted.');
    2:
      WriteLn('2. A minimum of 112 security bits is permitted.');
    3:
      WriteLn('3. A minimum of 128 security bits is permitted.');
    4:
      WriteLn('4. A minimum of 192 security bits is permitted.');
    5:
      WriteLn('5. A minimum of 256 security bits is permitted.');
  end;
end;

procedure TFTPApplication.CmdStatus;
var
  LStr: TStrings;
begin
  LStr := TStringList.Create;
  try
    FFTP.Status(LStr);
    WriteLn(LStr.Text);
  finally
    FreeAndNil(LStr);
  end;
end;

procedure TFTPApplication.CmdMkdir(const ACmd: string);
var
  LCmdParams: TStrings;
begin
  LCmdParams := TStringList.Create;
  try
    ParseArgs(ACmd, LCmdParams);
    if LCmdParams.Count > 0 then
    begin
      FFTP.makedir(LCmdParams[0]);
    end
    else
    begin
      WriteLn('Syntax Error');
    end;
  finally
    FreeAndNil(LCmdParams);
  end;
end;

procedure TFTPApplication.CmdLPwd;
begin
  WriteLn('Local directory is ' + GetCurrentDir);
end;

procedure TFTPApplication.CmdLCd(const ACmd: string);
var
  LCmdParams: TStrings;
begin
  LCmdParams := TStringList.Create;
  try
    ParseArgs(ACmd, LCmdParams);
    if LCmdParams.Count > 0 then
    begin
      SetCurrentDir(LCmdParams[0]);
      WriteLn('Local directory now ' + GetCurrentDir);
    end
    else
    begin
      WriteLn('Syntax Error');
    end;
  finally
    FreeAndNil(LCmdParams);
  end;
end;

procedure TFTPApplication.CmdLDir(const ACmd: string);
var
  LRec: TSearchRec;
{$IFNDEF USE_INLINE_VAR}
  LSize: string;
  LMask: String;
{$ENDIF}
var
  LCmdParams: TStrings;
begin
  LCmdParams := TStringList.Create;
  try
    ParseArgs(ACmd, LCmdParams);
{$IFDEF USE_INLINE_VAR}
    var
      LMask: string;
{$ENDIF}
    if LCmdParams.Count > 0 then
    begin
      LMask := LCmdParams[0] + '*.*';
    end
    else
    begin
      LMask := '*.*';
    end;

    if FindFirst(LMask, faAnyFile, LRec) = 0 then
    begin
{$IFDEF USE_INLINE_VAR}
      var
        LSize: string;
{$ENDIF}
      repeat
        if LRec.Attr and faDirectory <> 0 then
        begin
          LSize := '<DIR>';
        end
        else
        begin
          LSize := IntToStr(LRec.Size);
        end;
        WriteLn(Format('%10s %10s %20s %s', [TimeToStr(LRec.TimeStamp),
          TimeToStr(LRec.TimeStamp), LSize, LRec.Name]));
      until FindNext(LRec) <> 0;
      {$IFDEF WINDOWS}
      SysUtils.
      {$ENDIF}
      FindClose(LRec);
    end;
  finally
    FreeAndNil(LCmdParams);
  end;
end;

procedure TFTPApplication.CmdClose;
begin
  FFTP.Disconnect;
end;

procedure PrintCmdHelp(const ACmd: array of string;
  const AHelpDescription: string; ASyntaxRef: string = '');
var
  i: Integer;
{$IFNDEF USE_INLINE_VAR}
  LCmds: string;
{$ENDIF}
begin
{$IFDEF USE_INLINE_VAR}
  var
    LCmds: string;
{$ENDIF}
  LCmds := '';
  for i := 0 to High(ACmd) do
  begin
    LCmds := LCmds + ' ' + ACmd[i];
  end;
  LCmds := TrimLeft(LCmds);
  WriteLn(LeftJustify(LCmds, 20) + ' - ' + AHelpDescription);
  if ASyntaxRef <> '' then
  begin
    WriteLn('');
    WriteLn('Command Syntax:');
    WriteLn('');
    WriteLn(ASyntaxRef);
  end;
end;

procedure TFTPApplication.CmdHelp(const ACmd: string);
{$IFNDEF USE_INLINE_VAR}
{$IFDEF FPC}
var
  LCmd, LSubcommand: AnsiString;
{$ELSE}
var
  LCmd, LSubcommand: String;
{$ENDIF}
{$ENDIF}
begin
{$IFDEF USE_INLINE_VAR}
  var
    LCmd, LSubcommand: String;
{$ENDIF}
  LCmd := Trim(ACmd);
  if LCmd = '' then
  begin
    PrintCmdHelp(['?', 'help'], 'Prints help screen or command syntax');
    PrintCmdHelp(['about'], 'Show Information about this program');
    PrintCmdHelp(['cd', 'cwd'], 'Change remote directory');
    PrintCmdHelp(['cdup'], 'Change remote directory up a level');
    PrintCmdHelp(['close'], 'Terminate ftp session');
    PrintCmdHelp(['debug-info'], 'Show debugging information');
    PrintCmdHelp(['del', 'delete'], 'Delete remote file');
    PrintCmdHelp(['dir'], 'List contents of remote directory');
    PrintCmdHelp(['exit', 'quit'], 'Terminate ftp session and exit');
    PrintCmdHelp(['get'], 'Receive file');
    PrintCmdHelp(['lcd'], 'Change local working directory');
    PrintCmdHelp(['ldir'], 'List contents of local directory');
    PrintCmdHelp(['lpwd'], 'Print local working directory');
    PrintCmdHelp(['mkdir'], 'Make directory on the remote machine');
    PrintCmdHelp(['open'], 'Connect to remote ftp');
    PrintCmdHelp(['passive'], 'Toggle use of passive transfer mode');
    PrintCmdHelp(['put'], 'Send one file');
    PrintCmdHelp(['pwd'], 'Print working directory on remote machine');
    PrintCmdHelp(['rd', 'rmdir'], 'Remove directory on the remote machine');
    PrintCmdHelp(['rename', 'ren'], 'Rename remote file');
    PrintCmdHelp(['status'], 'Show current status');
    PrintCmdHelp(['quote'], 'Send arbitrary ftp command');
    PrintCmdHelp(['debug-trace'], 'Show Debug TLS trace information');
    PrintCmdHelp(['security-level'], 'Show or set security level');
    PrintCmdHelp(['save-config'], 'Save configuration');
    PrintCmdHelp(['cert-info'], 'Show certificate information');
    PrintCmdHelp(['mlsd'], 'Toggle use of MLSD command');
    PrintCmdHelp(['verify-depth'],'Show or set certificate chain verify depth');
  end
  else
  begin
    LSubcommand := Fetch(LCmd);
    case IdGlobal.PosInStrArray(Fetch(LSubcommand), Prog_Cmds, False) of
      0, 1:
        begin
          PrintCmdHelp(['exit', 'quit'],
            'Terminate ftp session and exit', 'exit');
        end;
      2:
        begin
          PrintCmdHelp(['open'], 'Connect to remote ftp',
            'open [protocol] host username password');
          WriteLn('');
          WriteLn('the protocol value may be:');
          WriteLn('');
          WriteLn('ftp   - File Transfer Protocol');
          WriteLn('ftps  - File Transfer Protocol with TLS');
          WriteLn('ftpsi - File Transfer Protocol with Implicit TLS');
        end;
      3:
        begin
          PrintCmdHelp(['dir'], 'List contents of remote directory',
            'dir [remote_path]');
        end;
      4:
        begin
          PrintCmdHelp(['pwd'],
            'Print working directory on remote machine', 'pwd');
        end;
      5:
        begin
          PrintCmdHelp(['cd', 'cwd'], 'Change remote directory',
            'cd remote_path');
        end;
      7:
        begin
          PrintCmdHelp(['cdup'], 'Change remote directory up a level', 'cdup')
        end;
      8:
        begin
          PrintCmdHelp(['passive'], 'Toggle use of passive transfer mode',
            'passive [state]');
          WriteLn('');
          WriteLn('The state value may be one of these:');
          WriteLn('');
          WriteLn('on    - Passive mode on (use PASV/EPSV data transfers)');
          WriteLn('off   - Passive mode off (use PORT/EPRT data transfers)');
          WriteLn('true  - Passive mode on (use PASV/EPSV data transfers)');
          WriteLn('false - Passive mode off (use PORT/EPRT data transfers)');
        end;
      9:
        begin
          PrintCmdHelp(['put'], 'Send one file', 'put local_filename');
        end;
      10:
        begin
          PrintCmdHelp(['get'], 'Receive file', 'get local_filename');
        end;
      11, 12:
        begin
          PrintCmdHelp(['rename', 'ren'], 'Rename remote file',
            'rename old_filename new_filename');
        end;
      13, 14:
        begin
          PrintCmdHelp(['del', 'delete'], 'Delete remote file',
            'delete remote_filename');
        end;
      15, 16:
        begin
          PrintCmdHelp(['md', 'mkdir'], 'Make directory on the remote machine',
            'mkdir remote_dirname');
        end;
      17, 18:
        begin
          PrintCmdHelp(['rmdir', 'rd'],
            'Remove directory on the remote machine', 'rmdir remote_dirname');
        end;
      19:
        begin
          PrintCmdHelp(['lpwd'], 'Print local working directory', 'lpwd');
        end;
      20:
        begin
          PrintCmdHelp(['lcd'], 'Change local working directory',
            'lcd local_dirname');
        end;
      21:
        begin
          PrintCmdHelp(['ldir'], 'List contents of local directory',
            'ldir [local_path]');
        end;
      22:
        begin
          PrintCmdHelp(['close'], 'Terminate ftp session', 'close');
        end;
      23, 24:
        begin
          PrintCmdHelp(['?', 'help'], 'Prints help screen or command syntax',
            'help [command]');
        end;
      25:
        begin
          PrintCmdHelp(['status'], 'Show current status', 'status');
        end;
      26:
        begin
          PrintCmdHelp(['debug-info'], 'Show debugging information',
            'debug-info');
        end;
      27:
        begin
          PrintCmdHelp(['about'],
            'Show Information about this program', 'about');
        end;
      28:
        begin
          PrintCmdHelp(['quote'], 'Send arbitrary ftp command',
            'quote command');
        end;
      29:

        begin
          PrintCmdHelp(['debug-trace'], 'Show debug TLS trace information',
            'debug-trace [state]');
          WriteLn('');
          WriteLn('The state value may be one of these:');
          WriteLn('');
          WriteLn('on    - Turn on TLS debug trace information (extremely verbose)');
          WriteLn('off   - Turn off TLS debug trace information');
          WriteLn('true  - Turn on TLS debug trace information (extremely verbose)');
          WriteLn('false - Turn off TLS debug trace information');
        end;
      30:
        begin
          PrintCmdHelp(['security-level'], 'Show or set security level',
            'security-level [level]');
          WriteLn('');
          WriteLn('The level value may be one of these:');
          WriteLn('');
          WriteLn('0    - Everything is permitted. ');
          WriteLn('1    - A minimum of 80 security bits is permitted.');
          WriteLn('2    - A minimum of 112 security bits is permitted.');
          WriteLn('3    - A minimum of 128 security bits is permitted.');
          WriteLn('4    - A minimum of 192 security bits is permitted.');
          WriteLn('5    - A minimum of 256 security bits is permitted.');
        end;
      31:
        begin
          PrintCmdHelp(['save-config'], 'Save configuration', 'save-config');
        end;
      32:
        begin
          PrintCmdHelp(['cert-info'], 'Certificate information', 'cert-info');
        end;
      33:
        begin
          PrintCmdHelp(['mlsd'], 'Toggle use of MLSD command', 'mlsd [state]');
          WriteLn('');
          WriteLn('The state value may be one of these:');
          WriteLn('');
          WriteLn('on    - MLSD mode on (use MLSD command for directory listing)');
          WriteLn('off   - MLSD mode off (use DIR command for directory listing)');
          WriteLn('true  - MLSD mode on (use MLSD command for directory listing)');
          WriteLn('false - MLSD mode off (use DIR command for directory listing)');
        end;
      34:
        begin
          PrintCmdHelp(['verify-depth'],'Show or set the acceptable certificate chain verify depth'
            ,'verify-depth [verify depth]');
          WriteLn('');
          WriteLn('The verify depth value may be a valid number');
          WriteLn('');
          writeLn('The verify depth value should be at least 3 for most certificate'+sLineBreak +
            'validity chains on the Internet.');
        end;
    end;
  end;
end;

procedure TFTPApplication.DoCommands;
{$IFNDEF USE_INLINE_VAR}
{$IFDEF FPC}
var
  LCmd: AnsiString;
{$ELSE}
var
  LCmd: string;
{$ENDIF}
{$ENDIF}
begin
{$IFDEF USE_INLINE_VAR}
  var
    LCmd: string;
{$ENDIF}
  repeat
    Write('ftp: ');
    ReadLn(LCmd);
    try
      case IdGlobal.PosInStrArray(Fetch(LCmd), Prog_Cmds, False) of
        0, 1:
          // 'exit', 'quit'
          Break;
        2:
          // 'open',
          CmdOpen(LCmd);
        3:
          // 'dir',
          CmdDir(LCmd);
        4:
          // 'pwd',
          CmdPwd;
        5, 6:
          // 'cd', 'cwd',
          CmdCd(LCmd);
        7:
          // 'cdup',
          CmdCdUp;
        8:
          // 'passive',
          CmdPassive(LCmd);
        9:
          // 'put',
          CmdPut(LCmd);
        10:
          // 'get',
          CmdGet(LCmd);
        11, 12:
          // 'rename', 'ren',
          CmdRename(LCmd);
        13, 14:
          // 'delete', 'del',
          CmdDelete(LCmd);
        15, 16:
          // 'md', 'mkdir',
          CmdMkdir(LCmd);
        17, 18:
          // 'rd','rmdir',
          CmdRmdir(LCmd);
        19:
          // 'lpwd',
          CmdLPwd;
        20:
          // 'lcd',
          CmdLCd(LCmd);
        21:
          // 'ldir',
          CmdLDir(LCmd);
        22:
          // 'close',
          CmdClose;
        23, 24:
          // 'help', '?'];
          CmdHelp(LCmd);
        25:
          // 'status'
          CmdStatus;
        26:
          // 'debug-info'
          CmdDebugInfo;
        27:
          // 'about'
          CmdAbout;
        28:
          // 'quote'
          CmdQuote(LCmd);
        29:
          // 'debug-trace'
          CmdDebugTrace(LCmd);
        30:
          // 'security-level'
          CmdSecurityLevel(LCmd);
        31:
          // 'save-config'
          CmdSaveConfig;
        32:
          // 'cert-info'
          CmdCertInfo;
        33:
          // 'mlsd'
          CmdMLSD(LCmd);
        34:
          //'verify-depth'
          CmdVerifyDepth(LCmd);
      else
        WriteLn('Bad Command');
      end;
    except
      On E: Exception do
        WriteLn(E.Message);
    end;
  until False;
  CmdSaveConfig;
end;

procedure TFTPApplication.DoOnVerifyError(ASender: TObject;
  ACertificate: TTaurusTLSX509; const AError: TIdC_LONG;
  const AMsg, ADescr: String; var VOk: Boolean);
var
  LRsp: String;
begin
  WriteLn(ADescr);
  WriteLn('');
  WriteLn(ACertificate.DisplayInfo.Text);
  WriteLn('');
  Write('Accept this certificate?');
  ReadLn(LRsp);
  VOk := PosInStrArray(LRsp, ['Y', 'YES'], False) > -1;
end;

procedure TFTPApplication.DoRun;
{$IFDEF FPC}
var
  ErrorMsg: string;

begin
  // quick check parameters
  ErrorMsg := CheckOptions('h', 'help');
  if ErrorMsg <> '' then
  begin
    ShowException(Exception.Create(ErrorMsg));
    Terminate;
    Exit;
  end;

  // parse parameters
  if HasOption('h', 'help') then
  begin
    WriteHelp;
    Terminate;
    Exit;
  end;
{$ELSE}

begin
{$ENDIF}
  { add your program here }
  CmdAbout;
  DoCommands;
{$IFDEF FPC}
  // stop program loop
  Terminate;
{$ENDIF}
end;

function TFTPApplication.LoadValidConfig : Boolean;
var
  LIni: TIniFile;
  {$IFNDEF USE_INLINE_VAR}
  LPubkey, LPrivKey : String;
  {$ENDIF}
begin
  Result := True;
  LIni := TIniFile.Create(CreateAndGetCOnfigDir + 'taurusftp.ini');
  try
    if LIni.ReadBool('debug', 'trace', Assigned(FIO.OnDebugMessage)) then
    begin
      FIO.OnDebugMessage := OnDebugMsg;
    end
    else
    begin
      FIO.OnDebugMessage := nil;
    end;
    FIO.SSLOptions.SecurityLevel := LIni.ReadInteger('security',
      'security_level', FIO.SSLOptions.SecurityLevel);
{
IMPORTANT!!!

VerifyDeth should be at least 3 because most validity chains on the Internet
involve one root Certificate, one intermediate certificate, and the server or
leaf certificate.  You might want to set this higher for something more elaborate
but do not make it too lonmg.
}
    FIO.SSLOptions.VerifyDepth := LIni.ReadInteger('security','verify_depth',100);
    FFTP.Passive := LIni.ReadBool('ftp', 'passive', FFTP.Passive);
    FFTP.UseMLIS := LIni.ReadBool('ftp', 'use_MLSD', True);
    {$IFDEF USE_INLINE_VAR}
    var LPubkey, LPrivKey : String;
    {$ENDIF}
    LPubKey := LIni.ReadString('certificate','public_key','');
    LPrivKey := LIni.ReadString('certificate','private_key','');
    if (LPubKey <> '') and (LPrivKey <> '') then
    begin
       FIO.SSLOptions.VerifyMode := FIO.SSLOptions.VerifyMode + [];
       FIO.ClientCert.PublicKey := LPubKey;
       FIO.ClientCert.PrivateKey := LPrivKey;
       if not FileExists(LPubKey) then
       begin
         Result := False;
         WriteLn('Error:  public key, "'+LPubKey+'" does not exist');
       end;
       if Result and not FileExists(LPrivKey) then
       begin
         Result := False;
         WriteLn('Error:  private key, "'+LPrivKey+'" does not exist');
       end;
       FIO.ClientCert.RootKey := LIni.ReadString('certificate','root_key','');
       if Result and (FIO.ClientCert.RootKey <> '') and not FileExists(FIO.ClientCert.RootKey) then
       begin
         Result := False;
         WriteLn('Error:  root key, "'+LPrivKey+'" does not exist');
       end;
       FIO.ClientCert.DHParamsFile := LIni.ReadString('certificate','dh_params','');
       if Result and (FIO.ClientCert.DHParamsFile <> '') and not FileExists(FIO.ClientCert.RootKey) then
       begin
         Result := False;
         WriteLn('Error:  DH parameters, "'+LPrivKey+'" does not exist');
       end;
    end;
  finally
    FreeAndNil(LIni);
  end;
end;

{$IFDEF FPC}

constructor TFTPApplication.Create(TheOwner: TComponent);
begin
  inherited Create(TheOwner);
{$ELSE}

constructor TFTPApplication.Create;
begin
{$ENDIF}
  FFTP := TIdFTP.Create(nil);
  FComp := TIdCompressorZLib.Create(nil);
  FFTP.Compressor := FComp;
  FIO := TTaurusTLSIOHandlerSocket.Create(nil);
  FIO.OnSSLNegotiated := OnSSLNegotiated;
  FIO.OnVerifyError := DoOnVerifyError;
  FFTP.IOHandler := FIO;
  FFTP.Passive := True;
  FLog := TTaurusTLSUnicodeLog.Create(nil);
  FLog.OnReceived := OnReceived;
  FLog.OnSent := OnSent;
  FLog.Active := True;
  FIO.Intercept := FLog;
{$IFDEF FPC}
  StopOnException := True;
{$ENDIF}

end;

destructor TFTPApplication.Destroy;
begin
  if FFTP.Connected then
  begin
    FFTP.Disconnect;
  end;
  FreeAndNil(FLog);
  FreeAndNil(FIO);
  FreeAndNil(FComp);
  FreeAndNil(FFTP);
  inherited Destroy;
end;

{$IFDEF FPC}

procedure TFTPApplication.WriteHelp;
begin
  { add your help code here }
  WriteLn('Usage: ', ExeName, ' -h');
end;
{$ENDIF}

var
  Application: TFTPApplication;

initialization

{$IFDEF FPC}
  Application := TFTPApplication.Create(nil);
Application.Title := 'TaurusFTP Console';
Application.Run;
{$ELSE}
  Application := TFTPApplication.Create;
try
  if Application.LoadValidConfig then
  begin
  {$IFDEF WINDOWS}
    if (SetConsoleCP(CP_UTF8)) then
    begin
    end;
  {$ENDIF}
    Application.DoRun;
  end;
except
  on E: Exception do
  begin
    WriteLn(E.Message);
    ReadLn;
  end;
end;
{$ENDIF}
Application.Free;

end.
