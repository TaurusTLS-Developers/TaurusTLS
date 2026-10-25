{ Shared implementation for the two isolated integration probes.
  Each program imports exactly one optional TaurusTLS adapter.
  Run in a fresh process. Arguments: -osp:<library directory>,
  --exit:Pause|Continue, and (FIPS-only) --missing-module.
  No FIPS module or external OpenSSL configuration is required.
  Detailed map files provide the linked-unit dependency evidence. }

procedure Require(ACondition: Boolean; const AMessage: string);
begin
  if not ACondition then
    raise Exception.Create(AMessage);
end;

function HexBytes(const ABytes: TIdBytes): string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to Length(ABytes) - 1 do
    Result := Result + IntToHex(ABytes[I], 2);
end;

var
  Loader: IOpenSSLLoader;
  ConfigDirectory, ConfigFile, LibraryPath, Argument, ConfigText: string;
  InitialGetMode: TGetFIPSMode;
  InitialNTLM: TNTLMGetNtChallengeResponse;
  I, Selected: Integer;
  MissingModule: Boolean;
{$IFDEF PROBE_NTLM_ONLY}
  Response, Challenge: TIdBytes;
{$ELSE}
  HashContext: TIdHashIntCtx;
  MACContext: TIdHMACIntCtx;
  Key: TIdBytes;
{$ENDIF}

begin
  Loader := nil;
  ConfigDirectory := '';
  try
    try
      MissingModule := False;
      LibraryPath := '';
      for I := 1 to ParamCount do
      begin
        Argument := ParamStr(I);
        if SameText(Copy(Argument, 1, 5), '-osp:') then
          LibraryPath := Copy(Argument, 6, MaxInt)
        else if SameText(Argument, '--missing-module') then
          MissingModule := True
        else if not ConsumeExitOption(Argument) then
          raise Exception.Create('Unknown argument: ' + Argument);
      end;
{$IFDEF PROBE_NTLM_ONLY}
      Require(not MissingModule, '--missing-module is a FIPS-only scenario');
{$ENDIF}
      Loader := GetOpenSSLLoader;
      Require(Loader.State = lsNotLoaded, 'Adapter initialized OpenSSL at startup');
      InitialGetMode := IdFIPS.GetFIPSMode;
      InitialNTLM := IdFIPS.NTLMGetNtChallengeResponse;
{$IFDEF PROBE_NTLM_ONLY}
      Require(not IdFIPS.LoadNTLMLibrary(), 'Inactive NTLM query must not load');
{$ELSE}
      Require(not IdFIPS.LoadHashLibrary(), 'Inactive hash query must not load');
      Require(not IdFIPS.GetFIPSMode(), 'Inactive FIPS mode must be false');
{$ENDIF}
      ConfigDirectory := TPath.Combine(TPath.GetTempPath, 'TaurusTLS.Isolation.' +
        TGUID.NewGuid.ToString);
      TDirectory.CreateDirectory(ConfigDirectory);
      ConfigFile := TPath.Combine(ConfigDirectory, 'openssl.cnf');
      ConfigText := 'config_diagnostics = 1' + sLineBreak +
        'openssl_conf = init' + sLineBreak +
        '[init]' + sLineBreak +
        'providers = providers' + sLineBreak +
        'alg_section = algorithms' + sLineBreak +
        '[providers]' + sLineBreak +
        'default = default_section' + sLineBreak;
{$IFNDEF PROBE_NTLM_ONLY}
      if MissingModule then
        ConfigText := ConfigText + 'fips = fips_section' + sLineBreak;
{$ENDIF}
      ConfigText := ConfigText +
        '[default_section]' + sLineBreak + 'activate = 1' + sLineBreak +
        '[algorithms]' + sLineBreak + 'default_properties =' + sLineBreak;
{$IFNDEF PROBE_NTLM_ONLY}
      if MissingModule then
        ConfigText := ConfigText + '[fips_section]' + sLineBreak +
          'module = "' + StringReplace(TPath.Combine(ConfigDirectory, 'missing-fips'),
            '\', '/', [rfReplaceAll]) + '"' + sLineBreak +
          'activate = 1' + sLineBreak;
{$ENDIF}
      TFile.WriteAllText(ConfigFile, ConfigText, TEncoding.UTF8);
      Loader.OpenSSLPath := LibraryPath;
      Loader.ConfigFile := ConfigFile;
{$IFNDEF PROBE_NTLM_ONLY}
      if MissingModule then
      begin
        try
          Loader.Load;
          raise Exception.Create('Missing configured FIPS module was accepted');
        except
          on E: ETaurusTLSConfigFileLoadError do
            Require(Loader.State = lsLoadedFailed, 'Config error did not publish failure');
        end;
        Require(not IdFIPS.GetFIPSMode(), 'Failed configuration reported FIPS mode');
        Require(not IdFIPS.LoadHashLibrary(), 'Failed config advertised hash readiness');
        Require(not Loader.Load, 'Failed retry must remain blocked');
        Loader.Unload;
        ConfigText := 'openssl_conf = init' + sLineBreak +
          '[init]' + sLineBreak + 'providers = providers' + sLineBreak +
          '[providers]' + sLineBreak + 'default = default_section' + sLineBreak +
          '[default_section]' + sLineBreak + 'activate = 1' + sLineBreak;
        TFile.WriteAllText(ConfigFile, ConfigText, TEncoding.UTF8);
      end;
{$ENDIF}
      Require(Loader.Load, 'Explicit Load failed');
      Require(@IdFIPS.GetFIPSMode = @InitialGetMode, 'Load replaced FIPS mode hook');
      Require(@IdFIPS.NTLMGetNtChallengeResponse = @InitialNTLM, 'Load replaced NTLM hook');
      Selected := EVP_default_properties_is_fips_enabled(nil);
      try
{$IFDEF PROBE_NTLM_ONLY}
        Require(IdFIPS.LoadNTLMLibrary(), 'Ready NTLM loading hook is false');
        Require(not IdFIPS.IsNTLMFuncsAvail(), 'Default-only config must not supply legacy NTLM');
        SetLength(Challenge, 8);
        try
          Response := IdFIPS.NTLMGetNtChallengeResponse('Password', Challenge);
          raise Exception.Create('Unavailable MD4/DES NT response was accepted');
        except
          on E: ETaurusTLSAlgorithmNotFound do
            Require(True, 'Expected missing-algorithm rejection');
        end;
        Require(@IdFIPS.GetFIPSMode = @InitialGetMode, 'NTLM changed independent FIPS hook');
{$ELSE}
        Require(IdFIPS.LoadHashLibrary(), 'Ready hash loading hook is false');
        Require(not IdFIPS.GetFIPSMode(), 'Default-only config reported FIPS mode');
        Require(not IdFIPS.SetFIPSMode(True), 'Setter changed configured policy');
        HashContext := IdFIPS.GetSHA256HashInst();
        IdFIPS.UpdateHashInst(HashContext, ToBytes('abc', IndyTextEncoding_ASCII));
        Require(HexBytes(IdFIPS.FinalHashInst(HashContext)) =
          'BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD',
          'SHA256 vector mismatch');
        SetLength(Key, 20);
        FillChar(Key[0], Length(Key), $0B);
        MACContext := IdFIPS.GetHMACSHA256HashInst(Key);
        IdFIPS.UpdateHMACInst(MACContext, ToBytes('Hi There', IndyTextEncoding_ASCII));
        Require(HexBytes(IdFIPS.FinalHMACInst(MACContext)) =
          'B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7',
          'HMAC vector mismatch');
        Require(EVP_default_properties_enable_fips(nil, 1) = 1, 'Test policy selection failed');
        Require(not IdFIPS.GetFIPSMode(), 'Selection without provider reported operational FIPS');
        Require(not IdFIPS.SetFIPSMode(False), 'Setter weakened selected policy');
        Require(not IdFIPS.IsSHA256HashIntfAvail(), 'Selected FIPS fell back to default digest');
        Require(not IdFIPS.IsHMACAvail(), 'Selected FIPS fell back to default HMAC');
{$ENDIF}
      finally
        EVP_default_properties_enable_fips(nil, Selected);
        ERR_clear_error;
      end;
      Loader.Unload;
      Require(@IdFIPS.GetFIPSMode = @InitialGetMode, 'Unload replaced FIPS mode hook');
      Require(@IdFIPS.NTLMGetNtChallengeResponse = @InitialNTLM, 'Unload replaced NTLM hook');
      Require(Loader.State = lsNotLoaded, 'Unload did not clear readiness');
      Writeln('PASS: isolated adapter hooks, config ownership and rejection paths');
    finally
      if Loader <> nil then
        Loader.Unload;
      Loader := nil;
      if (ConfigDirectory <> '') and TDirectory.Exists(ConfigDirectory) then
        TDirectory.Delete(ConfigDirectory, True);
    end;
  except
    on E: Exception do
    begin
      Writeln('FAIL: ', E.ClassName, ': ', E.Message);
      ExitCode := 1;
    end;
  end;
end.

