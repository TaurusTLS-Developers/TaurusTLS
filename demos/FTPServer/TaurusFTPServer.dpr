program TaurusFTPServer;

{$APPTYPE CONSOLE}
{$R *.res}
{$I TaurusTLSCompilerDefines.inc}

uses
  IdFIPS,
  IdExplicitTLSClientServerBase,
  IdCompressorZLib,
  IdFTPCommon,
  IdFTPList,
  IdFTPListOutput,
  IdFTPServer,
  IdFTPServerContextBase,
  IdStack,
  IdSSL,
  TaurusTLS,
  System.Classes,
  System.IniFiles,
  System.IOUtils,
  System.Math,
  System.SysUtils,
  WinApi.Windows;

type
  TFTPServerApp = class(TObject)
{$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} private
    FCompressor: TIdCompressorZLib;
    FIOExplicit: TTaurusTLSServerIOHandler;
    FIOImplicit: TTaurusTLSServerIOHandler;
    FFTPServExplicit: TIdFTPServer;
    FFTPServImplicit: TIdFTPServer;
    procedure ioOnGetPasswordEx(ASender: TObject; var VPassword: String;
      const AIsWrite: Boolean; var VOk: Boolean);
    procedure ftpsrvOnHostCheck(ASender: TIdFTPServerContext;
      const AHost: String; var VAccepted: Boolean);
    procedure ftpsrvOnLogin(ASender: TIdFTPServerContext;
      const AUsername, APassword: string; var AAuthenticated: Boolean);
    procedure ftpsrvOnClient(ASender: TIdFTPServerContext; const AID: String);
    procedure ftpsrvOnList(ASender: TIdFTPServerContext;
      const APath: TIdFTPFileName; ADirectoryListing: TIdFTPListOutput;
      const ACmd: String; const ASwitches: String);
    procedure ftpsrvOnMLST(ASender: TIdFTPServerContext;
      const APath: TIdFTPFileName; ADirectoryListing: TIdFTPListOutput);
    procedure ftpsrvOnCWD(ASender: TIdFTPServerContext;
      var VDirectory: TIdFTPFileName);
    procedure ftpsrvOnMakeDirectory(ASender: TIdFTPServerContext;
      var VDirectory: TIdFTPFileName);
    procedure ftpsrvOnRemoveDirectory(ASender: TIdFTPServerContext;
      var VDirectory: TIdFTPFileName);
    procedure ftpsrvOnRenameFile(ASender: TIdFTPServerContext;
      const ARenameFromFile, ARenameToFile: TIdFTPFileName);
    procedure ftpsrvOnRetrieveFile(ASender: TIdFTPServerContext;
      const AFileName: TIdFTPFileName; var VStream: TStream);
    procedure ftpsrvOnStoreFile(ASender: TIdFTPServerContext;
      const AFileName: TIdFTPFileName; AAppend: Boolean; var VStream: TStream);
    procedure ftpsrvOnDeleteFile(ASender: TIdFTPServerContext;
      const APathName: TIdFTPFileName);
    procedure ftpsrvOnGetFileDate(ASender: TIdFTPServerContext;
      const AFileName: TIdFTPFileName; var VFileDate: TDateTime);
    procedure ftpsrvOnSetModFileDate(ASender: TIdFTPServerContext;
      const AFileName: TIdFTPFileName; var AFileTime: TDateTime);
    procedure ftpsrvOnSetCreationFileDate(ASender: TIdFTPServerContext;
      const AFileName: TIdFTPFileName; var AFileTime: TDateTime);
    procedure ftpsrvOnFileExistCheck(ASender: TIdFTPServerContext;
      const APathName: TIdFTPFileName; var VExist: Boolean);
    procedure ftpsrvOnGetFileSize(ASender: TIdFTPServerContext;
      const AFileName: TIdFTPFileName; var VFileSize: Int64);
    procedure ftpsrvOnSiteUTIME(ASender: TIdFTPServerContext;
      const AFileName: TIdFTPFileName; var VLastAccessTime, VLastModTime,
      VCreateDate: TDateTime; var VAUth: Boolean);
    function SetupDefaultFTPServer(AIni: TIniFile): TIdFTPServer;
    function SetupIOHandler(AIni: TIniFile): TTaurusTLSServerIOHandler;
  public
    constructor Create;
    destructor Destroy; override;
  end;

var
  app: TFTPServerApp;

function SetFileLastModifiedDateTime(const FileName: String;
  DateTime: TDateTime): Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := (FileName <> '') and FileExists(FileName);
  if Result then
  begin
    TFile.SetLastWriteTime(FileName, DateTime);
  end;
end;
{$IFNDEF VCL_12_OR_ABOVE}

function FileTime2DateTime(FileTime: TFileTime): TDateTime;
{$IFDEF USE_INLINE}inline; {$ENDIF}
var
  LocalFileTime: TFileTime;
  SystemTime: TSystemTime;
begin
  FileTimeToLocalFileTime(FileTime, LocalFileTime);
  FileTimeToSystemTime(LocalFileTime, SystemTime);
  Result := SystemTimeToDateTime(SystemTime);
end;
{$ENDIF}

function SetFileCreationDateTime(const FileName: String; DateTime: TDateTime)
  : Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := (FileName <> '') and FileExists(FileName);
  if Result then
  begin
    TFile.SetCreationTime(FileName, DateTime);
  end;
end;

function FTPPathToLocalPath(const APath: String; const AAnonymous: Boolean)
  : String; {$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  if AAnonymous then
  begin
    Result := StringReplace(System.IOUtils.TPath.GetSharedDocumentsPath + '\' +
      APath, '/', '\', [rfReplaceAll]);
  end
  else
  begin
    Result := StringReplace(System.IOUtils.TPath.GetDocumentsPath + '\' + APath,
      '/', '\', [rfReplaceAll]);
  end;
  Result := StringReplace(Result, '\\', '\', [rfReplaceAll]);
end;

procedure TSearchRecToFTPListItem(const ARec: TSearchRec;
  AFTPItem: TIdFTPListOutputItem; const AAnonymous: Boolean);
{$IFDEF USE_INLINE}inline; {$ENDIF}
var
  {$IFNDEF USE_INLINE_VAR}
  LUnixPerm: String;
  LMSLTPerm: String;
  {$ENDIF}
  LIsDir: Boolean;
begin
  AFTPItem.FileName := ARec.Name;
  LIsDir := (ARec.Attr and faDirectory) = faDirectory;
  if LIsDir then
  begin
    AFTPItem.ItemType := ditDirectory;
    AFTPItem.SizeAvail := false;
  end
  else
  begin
    AFTPItem.ItemType := ditFile;
  end;
  {$IFDEF USE_INLINE_VAR}
  var
    LUnixPerm, LMSLTPerm : String;
  {$ENDIF}
  if AAnonymous then
  begin
    LMSLTPerm := 'elr';
  end
  else
  begin
    LMSLTPerm := 'acdeflmprw';
  end;
  if ARec.Attr and faReadOnly = faReadOnly then
  begin
    LUnixPerm := 'r-';
    LMSLTPerm := StringReplace(LMSLTPerm, 'a', '', [rfReplaceAll]);
    // file may be APPE'd
    LMSLTPerm := StringReplace(LMSLTPerm, 'w', '', [rfReplaceAll]);
    // file may be STOR'ed
    LMSLTPerm := StringReplace(LMSLTPerm, 'p', '', [rfReplaceAll]);
    // dir may be RMD'ed
    LMSLTPerm := StringReplace(LMSLTPerm, 'm', '', [rfReplaceAll]);
    // dir may be MKD'ed
    LMSLTPerm := StringReplace(LMSLTPerm, 'f', '', [rfReplaceAll]);
    // file or dir may be RNFR'ed
    LMSLTPerm := StringReplace(LMSLTPerm, 'd', '', [rfReplaceAll]);
    // dir or file may be RMD'ed
    LMSLTPerm := StringReplace(LMSLTPerm, 'c', '', [rfReplaceAll]);
    // dir may be STOU'ed
    LMSLTPerm := StringReplace(LMSLTPerm, 'p', '', [rfReplaceAll]);
    // dir may be RMD'ed
  end
  else
  begin
    if AAnonymous then
    begin
      LUnixPerm := 'r-';
    end
    else
    begin
      LUnixPerm := 'rw';
    end;
  end;
  // x - execute bit - for directories, means that you can access it.
  if LIsDir then
  begin
    LUnixPerm := LUnixPerm + 'x';
    LMSLTPerm := StringReplace(LMSLTPerm, 'a', '', [rfReplaceAll]);
    // file may be APPE'd
    LMSLTPerm := StringReplace(LMSLTPerm, 'r', '', [rfReplaceAll]);
    // file may be RETR'ed
    LMSLTPerm := StringReplace(LMSLTPerm, 'w', '', [rfReplaceAll]);
    // file may be STOR'ed
  end
  else
  begin
    LUnixPerm := LUnixPerm + '-';
    LMSLTPerm := StringReplace(LMSLTPerm, 'e', '', [rfReplaceAll]);
    // dir may be CWD'ed
    LMSLTPerm := StringReplace(LMSLTPerm, 'l', '', [rfReplaceAll]);
    // dir may be LIST'ed
    LMSLTPerm := StringReplace(LMSLTPerm, 'm', '', [rfReplaceAll]);
    // dir may be MKD'ed
    LMSLTPerm := StringReplace(LMSLTPerm, 'p', '', [rfReplaceAll]);
    // dir may be RMD'ed
  end;
  AFTPItem.MLISTPermissions := LMSLTPerm;
  AFTPItem.UnixOwnerPermissions := LUnixPerm;
  AFTPItem.UnixGroupPermissions := LUnixPerm;
  AFTPItem.UnixOtherPermissions := LUnixPerm;
  AFTPItem.ModifiedDate := ARec.TimeStamp;
{$IFDEF VCL_12_OR_ABOVE}
  AFTPItem.LastAccessDate := ARec.LastAccessTime;
  AFTPItem.CreationDate := ARec.CreationTime;
{$ELSE}
{$WARN SYMBOL_PLATFORM OFF}
  AFTPItem.LastAccessDate := FileTime2DateTime(ARec.FindData.ftLastAccessTime);
  AFTPItem.CreationDate := FileTime2DateTime(ARec.FindData.ftCreationTime);
{$WARN SYMBOL_PLATFORM ON}
{$ENDIF}
  AFTPItem.Size := ARec.Size;
  AFTPItem.WinAttribs := Cardinal(ARec.Attr);
end;

procedure FileNotFound(const APathName: String); {$IFDEF USE_INLINE}inline;
{$ENDIF}
begin
  raise Exception.Create(APathName + ' not found');
end;

procedure PermissionDenied; {$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  raise Exception.Create('permission denied');
end;

{ TFTPServerApp }

function TFTPServerApp.SetupDefaultFTPServer(AIni: TIniFile): TIdFTPServer;
begin
  Result := TIdFTPServer.Create(nil);
  Result.Greeting.Text.Text := 'TaurusFTP Server..';
  Result.PASVBoundPortMin := AIni.ReadInteger('Server',
    'PASV_Bound_Port_Minimum', 0);
  Result.PASVBoundPortMax := AIni.ReadInteger('Server',
    'PASV_Bound_Port_Maximum', 0);
  Result.Compressor := FCompressor;
  { This must be set to 0 so PASV will work properly.  If left
    at its default, the data port will timeout doing PASV.  That
    is a serious thing since some FTP clients default to PASV or
    even will NOT support PORT transfers. }
  Result.DefaultDataPort := 0;
  // Make the special Unix value case-insensitive
  if AIni.ReadBool('Server', 'Unix_Emulation', True) then
  begin
    Result.DirFormat := ftpdfUnix;
  end
  else
  begin
    Result.DirFormat := ftpdfDOS;
  end;

  Result.FTPSecurityOptions.PasswordAttempts :=
    AIni.ReadInteger('Server', 'Password_Attempts', DEF_FTP_PASSWORDATTEMPTS);
  Result.FTPSecurityOptions.InvalidPassDelay :=
    AIni.ReadInteger('Server', 'Delay_On_Failed_Password_Attempt',
    DEF_FTP_INVALIDPASS_DELAY);
  Result.FTPSecurityOptions.NoReservedRangePORT :=
    AIni.ReadBool('Server', 'No_PORT_Requests_To_Ports_In_Reserved_Range',
    DEF_FTP_NO_RESERVED_PORTS);
  Result.FTPSecurityOptions.BlockAllPORTTransfers :=
    AIni.ReadBool('Server', 'Do_Not_Accept_PORT_Transfers',
    DEF_FTP_BLOCK_ALL_PORTS);
  Result.FTPSecurityOptions.DisableSYSTCommand :=
    AIni.ReadBool('Server', 'Disable_SYST_Command', DEF_FTP_DISABLE_SYST);
  Result.FTPSecurityOptions.DisableSTATCommand :=
    AIni.ReadBool('Server', 'Disable_STAT_Command', DEF_FTP_DISABLE_STAT);
  Result.FTPSecurityOptions.RequirePORTFromSameIP :=
    AIni.ReadBool('Server', 'Reqiore_PORT_Connection_From_Same_IP_Address',
    DEF_FTP_PORT_SAME_IP);
  Result.FTPSecurityOptions.RequirePASVFromSameIP :=
    AIni.ReadBool('Server', 'Require_PASV_Connection_From_Same_IP_Address',
    DEF_FTP_PASV_SAME_IP);
  Result.FTPSecurityOptions.PermitCCC := AIni.ReadBool('Server',
    'Permit_CCC_Clear_Command_Connection_In_TLS_FTP', DEF_FTP_PERMIT_CCC);

  Result.AllowAnonymousLogin := AIni.ReadBool('Server',
    'Allow_Anonymous_FTP', false);
  Result.MLSDFacts := [mlsdFileCreationTime, mlsdFileLastAccessTime,
    mlsdWin32Attributes, mlsdPerms];
  Result.OnHostCheck := ftpsrvOnHostCheck;
  Result.SupportXAUTH := AIni.ReadBool('Server', 'SupportXAUTH', false);
  Result.OnUserLogin := ftpsrvOnLogin;
  Result.OnClientID := ftpsrvOnClient;
  Result.PathProcessing := ftppDOS;
  Result.OnChangeDirectory := ftpsrvOnCWD;
  Result.OnMakeDirectory := ftpsrvOnMakeDirectory;
  Result.OnRemoveDirectory := ftpsrvOnRemoveDirectory;
  Result.OnListDirectory := ftpsrvOnList;
  Result.OnRenameFile := ftpsrvOnRenameFile;
  Result.OnRetrieveFile := ftpsrvOnRetrieveFile;
  Result.OnStoreFile := ftpsrvOnStoreFile;
  // OnCRCFile uses the same code as OnRetrieveFile
  if AIni.ReadBool('Server', 'Allow_File_Checksums', True) then
  begin
    Result.OnCRCFile := ftpsrvOnRetrieveFile;
  end;
  Result.OnDeleteFile := ftpsrvOnDeleteFile;
  Result.OnGetFileDate := ftpsrvOnGetFileDate;
  Result.OnFileExistCheck := ftpsrvOnFileExistCheck;
  Result.OnSetModifiedTime := ftpsrvOnSetModFileDate;
  Result.OnSetCreationTime := ftpsrvOnSetCreationFileDate;
  Result.OnSiteUTIME := ftpsrvOnSiteUTIME;
  Result.OnGetFileSize := ftpsrvOnGetFileSize;
  Result.OnMLST := ftpsrvOnMLST;
end;

function TFTPServerApp.SetupIOHandler(AIni: TIniFile)
  : TTaurusTLSServerIOHandler;
var
  LIni: TIniFile;
  LServers: TStringList;
  {$IFNDEF USE_INLINE_VAR}
  LPrivKey, LPubKey : String;
  {$ENDIF}
  LCert: TTaurusTLSX509File;
  i: Integer;
begin
  Result := TTaurusTLSServerIOHandler.Create(nil);
  Result.SSLOptions.MinTLSVersion := TLSv1_2;
  Result.DefaultCert.PublicKey := AIni.ReadString('Certificate',
    'CertificateFile', GetCurrentDir + '\localhost.crt');
  Result.DefaultCert.PrivateKey := AIni.ReadString('Certificate',
    'KeyFile', GetCurrentDir + '\localhost.key');
  Result.DefaultCert.RootKey := AIni.ReadString('Certificate',
    'RootCertFile', '');
  Result.DefaultCert.DHParamsFile := AIni.ReadString('Certificate',
    'DH_Parameters', '');
  LIni := TIniFile.Create(GetCurrentDir + '\virtual_servers.ini');
  try
    LServers := TStringList.Create;
    try
      LIni.ReadSections(LServers);
      {$IFDEF USE_INLINE_VAR}
      var LPrivKey, LPubKey : String;
      {$ENDIF}
      for i := 0 to LServers.Count - 1 do
      begin
        LPrivKey := LIni.ReadString(LServers[i], 'KeyFile', '');
        LPubKey := LIni.ReadString(LServers[i], 'CertificateFile', '');
        if (LPrivKey <> '') and (LPubKey <> '') then
        begin
          LCert := Result.Certificates.AddX509File;
          LCert.PrivateKey := LPrivKey;
          LCert.PublicKey := LPubKey;
          LCert.RootKey := LIni.ReadString(LServers[i], 'RootCertFile', '');
          LCert.DHParamsFile := LIni.ReadString(LServers[i], 'DH_Parameters','');
        end;
      end;

    finally
      FreeAndNil(LServers);
    end;
  finally
    FreeAndNil(LIni);
  end;

  Result.OnGetPassword := ioOnGetPasswordEx;
end;

constructor TFTPServerApp.Create;
var
  LIni: TIniFile;
begin
  inherited Create;
  if not FileExists(GetCurrentDir + '\server.ini') then
  begin

    LIni := TIniFile.Create(GetCurrentDir + '\server.ini');
    try
      LIni.WriteString('Certificate', 'CertificateFile',
        GetCurrentDir + '\ssl-cert.pem');
      LIni.WriteString('Certificate', 'KeyFile',
        GetCurrentDir + '\ssl-key.pem');
      LIni.WriteString('Certificate', 'RootCertFile', '');
      LIni.WriteString('Certificate', 'DH_Parameters', '');
      LIni.WriteString('Certificate', 'Password', '');

      LIni.WriteInteger('Server', 'PASV_Bound_Port_Minimum', 0);
      LIni.WriteInteger('Server', 'PASV_Bound_Port_Maximum', 0);

      LIni.WriteInteger('Server', 'Password_Attempts',
        DEF_FTP_PASSWORDATTEMPTS);
      LIni.WriteInteger('Server', 'Delay_On_Failed_Password_Attempt',
        DEF_FTP_INVALIDPASS_DELAY);
      LIni.WriteBool('Server', 'No_PORT_Requests_To_Ports_In_Reserved_Range',
        DEF_FTP_NO_RESERVED_PORTS);
      LIni.WriteBool('Server', 'Do_Not_Accept_PORT_Transfers',
        DEF_FTP_BLOCK_ALL_PORTS);
      LIni.WriteBool('Server', 'Disable_SYST_Command', DEF_FTP_DISABLE_SYST);
      LIni.WriteBool('Server', 'Disable_STAT_Command', DEF_FTP_DISABLE_STAT);
      LIni.WriteBool('Server', 'Reqiore_PORT_Connection_From_Same_IP_Address',
        DEF_FTP_PORT_SAME_IP);
      LIni.WriteBool('Server', 'Require_PASV_Connection_From_Same_IP_Address',
        DEF_FTP_PASV_SAME_IP);
      LIni.WriteBool('Server', 'Permit_CCC_Clear_Command_Connection_In_TLS_FTP',
        DEF_FTP_PERMIT_CCC);
      LIni.WriteBool('Server','Require_Client_Certificate',False);
      LIni.WriteBool('Server', 'Allow_Anonymous_FTP', false);
      LIni.WriteBool('Server', 'Allow_Compression', True);
      LIni.WriteBool('Server', 'Allow_File_Checksums', True);
      LIni.WriteBool('Server', 'Require_TLS', True);
      LIni.WriteBool('Server', 'SupportXAUTH', false);
      LIni.WriteBool('Server', 'Unix_Emulation', True);
      LIni.WriteBool('Server', 'ImplicitSSL', True);
    finally
      FreeAndNil(LIni);
    end;
  end;

  LIni := TIniFile.Create(GetCurrentDir + '\server.ini');
  try
    if LIni.ReadBool('Server', 'Allow_Compression', True) then
    begin
      FCompressor := TIdCompressorZLib.Create(nil);
    end
    else
    begin
      FCompressor := nil;
    end;

    // --handle explicit FTPS server.
    FFTPServExplicit := SetupDefaultFTPServer(LIni);
    FIOExplicit := SetupIOHandler(LIni);
    FFTPServExplicit.IOHandler := FIOExplicit;
    if LIni.ReadBool('Server', 'Require_TLS', True) then
    begin
      FFTPServExplicit.UseTLS := utUseRequireTLS;
    end
    else
    begin
      FFTPServExplicit.UseTLS := utUseExplicitTLS;
    end;
    if LIni.ReadBool('Server','Require_Client_Certificate',False)=True then
    begin
      FIOExplicit.SSLOptions.VerifyMode := [sslvrfPeer, sslvrfFailIfNoPeerCert];
      FIOExplicit.SSLOptions.VerifyDepth := 3;
    end;
    FFTPServExplicit.Active := True;
    WriteLn('FTP Default Data Port: ' + IntToStr(FFTPServExplicit.DefaultPort));

    // --handle implicit FTPS server.
    FFTPServImplicit := nil;
    if LIni.ReadBool('Server', 'ImplicitSSL', True) then
    begin
      FFTPServImplicit := SetupDefaultFTPServer(LIni);
      FIOImplicit := SetupIOHandler(LIni);
      FFTPServImplicit.IOHandler := FIOImplicit;
      FFTPServImplicit.DefaultPort := 990;
      FFTPServImplicit.UseTLS := utUseImplicitTLS;
      FIOImplicit.SSLOptions.VerifyMode := FIOExplicit.SSLOptions.VerifyMode;
      FIOImplicit.SSLOptions.VerifyDepth := FIOExplicit.SSLOptions.VerifyDepth;

      FFTPServImplicit.Active := True;
      WriteLn('Implicit FTPS Default Data Port: ' +
        IntToStr(FFTPServImplicit.DefaultPort));
    end;
  finally
    FreeAndNil(LIni)
  end;
end;

destructor TFTPServerApp.Destroy;
begin
  FreeAndNil(FFTPServImplicit);
  FreeAndNil(FIOImplicit);
  FreeAndNil(FFTPServExplicit);
  FreeAndNil(FIOExplicit);
  FreeAndNil(FFTPServImplicit);
  FreeAndNil(FIOImplicit);
  FreeAndNil(FCompressor);
  inherited;
end;

procedure TFTPServerApp.ftpsrvOnClient(ASender: TIdFTPServerContext;
  const AID: String);
begin
  { Intentionally left blank so that the server supports the CLNT command. }
end;

procedure TFTPServerApp.ftpsrvOnCWD(ASender: TIdFTPServerContext;
  var VDirectory: TIdFTPFileName);
begin
  if not DirectoryExists(FTPPathToLocalPath(VDirectory,
    ASender.UserType = utAnonymousUser)) then
  begin
    FileNotFound(VDirectory);
  end;
end;

procedure TFTPServerApp.ftpsrvOnDeleteFile(ASender: TIdFTPServerContext;
  const APathName: TIdFTPFileName);
begin
  if ASender.UserType = utAnonymousUser then
  begin
    PermissionDenied;
  end;

  if not System.SysUtils.DeleteFile(FTPPathToLocalPath(APathName,
    ASender.UserType = utAnonymousUser)) then
  begin
    FileNotFound(APathName);
  end;
end;

procedure TFTPServerApp.ftpsrvOnMakeDirectory(ASender: TIdFTPServerContext;
  var VDirectory: TIdFTPFileName);
begin
  if ASender.UserType = utAnonymousUser then
  begin
    PermissionDenied;
  end;
  if not CreateDir(FTPPathToLocalPath(VDirectory,
    ASender.UserType = utAnonymousUser)) then
  begin
    Raise Exception.Create('Can not create ' + VDirectory);
  end;
end;

procedure TFTPServerApp.ftpsrvOnRemoveDirectory(ASender: TIdFTPServerContext;
  var VDirectory: TIdFTPFileName);
begin
  if ASender.UserType = utAnonymousUser then
  begin
    PermissionDenied;
  end;
  if not System.SysUtils.RemoveDir(FTPPathToLocalPath(VDirectory,
    ASender.UserType = utAnonymousUser)) then
  begin
    FileNotFound(VDirectory);
  end;
end;

procedure TFTPServerApp.ftpsrvOnFileExistCheck(ASender: TIdFTPServerContext;
  const APathName: TIdFTPFileName; var VExist: Boolean);
begin
  VExist := FileExists(FTPPathToLocalPath(APathName,
    ASender.UserType = utAnonymousUser), false);
end;

procedure TFTPServerApp.ftpsrvOnGetFileDate(ASender: TIdFTPServerContext;
  const AFileName: TIdFTPFileName; var VFileDate: TDateTime);
var
  LF: TSearchRec;
begin
  // This is necessary because FileAge does not work with directories.
  if FindFirst(FTPPathToLocalPath(AFileName,
    ASender.UserType = utAnonymousUser), faAnyFile, LF) = 0 then
  begin
    VFileDate := LF.TimeStamp;
    System.SysUtils.FindClose(LF);
  end
  else
  begin
    FileNotFound(AFileName);
  end;
end;

procedure TFTPServerApp.ftpsrvOnGetFileSize(ASender: TIdFTPServerContext;
  const AFileName: TIdFTPFileName; var VFileSize: Int64);
var
  LFileEntry: TSearchRec;
begin
  if FindFirst(FTPPathToLocalPath(AFileName,
    ASender.UserType = utAnonymousUser), faAnyFile, LFileEntry) = 0 then
  begin
    VFileSize := LFileEntry.Size;
    System.SysUtils.FindClose(LFileEntry);
  end
  else
  begin
    FileNotFound(AFileName);
  end;
end;

procedure TFTPServerApp.ftpsrvOnHostCheck(ASender: TIdFTPServerContext;
  const AHost: String; var VAccepted: Boolean);
begin
  VAccepted := AHost = GStack.HostName;
  if not VAccepted then
  begin
    VAccepted := GStack.LocalAddresses.IndexOf(AHost) > -1;
  end;
end;

procedure TFTPServerApp.ftpsrvOnList(ASender: TIdFTPServerContext;
  const APath: TIdFTPFileName; ADirectoryListing: TIdFTPListOutput;
  const ACmd, ASwitches: String);
var
  LFTPFile: TIdFTPListOutputItem;
  LFileEntry: TSearchRec;

begin
  if FindFirst(FTPPathToLocalPath(APath + '*.*',
    ASender.UserType = utAnonymousUser), faAnyFile, LFileEntry) = 0 then
  begin
    repeat
      LFTPFile := ADirectoryListing.Add;
      TSearchRecToFTPListItem(LFileEntry, LFTPFile,
        ASender.UserType = utAnonymousUser);
    until FindNext(LFileEntry) <> 0;
    System.SysUtils.FindClose(LFileEntry);
  end
  else
  begin
    if FindFirst(FTPPathToLocalPath(APath, ASender.UserType = utAnonymousUser),
      faAnyFile, LFileEntry) = 0 then
    begin
      LFTPFile := ADirectoryListing.Add;
      TSearchRecToFTPListItem(LFileEntry, LFTPFile,
        ASender.UserType = utAnonymousUser);
      System.SysUtils.FindClose(LFileEntry);
    end
    else
    begin
      FileNotFound(APath);
    end;
  end;
end;

procedure TFTPServerApp.ftpsrvOnMLST(ASender: TIdFTPServerContext;
  const APath: TIdFTPFileName; ADirectoryListing: TIdFTPListOutput);
var
  LFTPFile: TIdFTPListOutputItem;
  LFileEntry: TSearchRec;
begin
  // Get info about a file
  if FindFirst(FTPPathToLocalPath(APath, ASender.UserType = utAnonymousUser),
    faAnyFile, LFileEntry) = 0 then
  begin
    LFTPFile := ADirectoryListing.Add;
    TSearchRecToFTPListItem(LFileEntry, LFTPFile,
      ASender.UserType = utAnonymousUser);
    System.SysUtils.FindClose(LFileEntry);
  end
  else
  begin
    FileNotFound(APath);
  end;
end;

procedure TFTPServerApp.ftpsrvOnRenameFile(ASender: TIdFTPServerContext;
  const ARenameFromFile, ARenameToFile: TIdFTPFileName);
begin
  if ASender.UserType = utAnonymousUser then
  begin
    PermissionDenied;
  end;
  if not RenameFile(FTPPathToLocalPath(ARenameFromFile,
    ASender.UserType = utAnonymousUser), FTPPathToLocalPath(ARenameToFile,
    ASender.UserType = utAnonymousUser)) then
  begin
    raise Exception.Create('Can not rename ' + ARenameFromFile + ' to ' +
      ARenameToFile);
  end;
end;

procedure TFTPServerApp.ftpsrvOnRetrieveFile(ASender: TIdFTPServerContext;
  const AFileName: TIdFTPFileName; var VStream: TStream);
begin
  try
    VStream := TFileStream.Create(FTPPathToLocalPath(AFileName,
      ASender.UserType = utAnonymousUser), fmOpenRead);
  except
    FileNotFound(AFileName);
  end;
end;

procedure TFTPServerApp.ftpsrvOnSetModFileDate(ASender: TIdFTPServerContext;
  const AFileName: TIdFTPFileName; var AFileTime: TDateTime);
begin
  if ASender.UserType = utAnonymousUser then
  begin
    PermissionDenied;
  end;
  if not SetFileLastModifiedDateTime(FTPPathToLocalPath(AFileName,
    ASender.UserType = utAnonymousUser), DateTimeToFileDate(AFileTime)) then
  begin
    FileNotFound(AFileName);
  end;
end;

procedure TFTPServerApp.ftpsrvOnSiteUTIME(ASender: TIdFTPServerContext;
  const AFileName: TIdFTPFileName; var VLastAccessTime, VLastModTime,
  VCreateDate: TDateTime; var VAUth: Boolean);
{$IFNDEF USE_INLINE_VAR}
var
  LPath: String;
{$ENDIF}
begin
  if ASender.UserType = utAnonymousUser then
  begin
    PermissionDenied;
  end;
  {$IFDEF USE_INLINE_VAR}
  var
     LPath: String;
  {$ENDIF}
  LPath := FTPPathToLocalPath(AFileName, ASender.UserType = utAnonymousUser);
  if IsZero(VLastAccessTime) then
  begin
    if (LPath <> '') and FileExists(LPath) then
    begin
      TFile.SetLastAccessTime(LPath, VLastAccessTime);
    end
    else
    begin
      FileNotFound(AFileName);
    end;
  end;
  if IsZero(VLastModTime) then
  begin
    if not SetFileLastModifiedDateTime(LPath, VLastModTime) then
    begin
      FileNotFound(AFileName);
    end;
  end;
  if IsZero(VCreateDate) then
  begin
    if not SetFileCreationDateTime(LPath, VCreateDate) then
    begin
      FileNotFound(AFileName);
    end;
  end;
end;

procedure TFTPServerApp.ftpsrvOnSetCreationFileDate
  (ASender: TIdFTPServerContext; const AFileName: TIdFTPFileName;
  var AFileTime: TDateTime);
begin
  if ASender.UserType = utAnonymousUser then
  begin
    PermissionDenied;
  end;
  if not SetFileCreationDateTime(FTPPathToLocalPath(AFileName,
    ASender.UserType = utAnonymousUser), AFileTime) then
  begin
    FileNotFound(AFileName);
  end;
end;

procedure TFTPServerApp.ftpsrvOnStoreFile(ASender: TIdFTPServerContext;
  const AFileName: TIdFTPFileName; AAppend: Boolean; var VStream: TStream);
begin
  if ASender.UserType = utAnonymousUser then
  begin
    PermissionDenied;
  end;
  try
    if AAppend then
    begin
      VStream := TFileStream.Create(FTPPathToLocalPath(AFileName,
        ASender.UserType = utAnonymousUser), fmOpenReadWrite);
      VStream.Seek(0, soFromEnd);
    end
    else
    begin
      VStream := TFileStream.Create(FTPPathToLocalPath(AFileName,
        ASender.UserType = utAnonymousUser), fmCreate);
    end;
  except
    raise Exception.Create('Can not upload ' + AFileName);
  end;
end;

procedure TFTPServerApp.ioOnGetPasswordEx(ASender: TObject;
  var VPassword: String; const AIsWrite: Boolean; var VOk: Boolean);
var
  LIni: TIniFile;
begin
  LIni := TIniFile.Create(GetCurrentDir + '\server.ini');
  try
    VPassword := LIni.ReadString('Certificate', 'Password', 'testinfg');
    VOk := True;
  finally
    FreeAndNil(LIni);
  end;
end;

procedure TFTPServerApp.ftpsrvOnLogin(ASender: TIdFTPServerContext;
  const AUsername, APassword: string; var AAuthenticated: Boolean);
var
  hToken: THandle;
begin
  if ASender.UserType = utNormalUser then
  begin
    // based on https://stackoverflow.com/questions/17064672/programmatical-log-in-by-providing-credentials
    AAuthenticated := LogonUser(PChar(AUsername), nil, PChar(APassword),
      LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, hToken);
    if AAuthenticated then
    begin
      AAuthenticated := ImpersonateLoggedOnUser(hToken);
    end;
    CloseHandle( hToken);
  end
  else
  begin
    AAuthenticated := True;
  end;
end;

begin
  //Done this way because an exception can be raised ducring the
  //FTPServerApp.Create
  try
    app := TFTPServerApp.Create;
    try
      try
        WriteLn(OpenSSLVersion);
        WriteLn('FTP Server App');
      except
        on E: Exception do
          WriteLn(E.ClassName, ': ', E.Message);
      end;
      ReadLn;
    finally
      FreeAndNil(app);
    end;
  except
    on E: Exception do
    begin
      WriteLn(E.ClassName, ': ', E.Message);
      ReadLn;
    end;
  end;
end.
