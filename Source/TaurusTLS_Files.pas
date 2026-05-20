{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2024 TaurusTLS Developers, All Rights Reserved              * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 – 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  * }
{ ****************************************************************************** }

{$I TaurusTLSCompilerDefines.inc}
/// <summary>
/// File routines for the TaurusTLS library.
/// </summary>
unit TaurusTLS_Files;

interface

{$I TaurusTLSLinkDefines.inc}

uses
  IdCTypes,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_x509;

const
  /// <summary>
  /// Maximum password length.
  /// </summary>
  MAX_SSL_PASSWORD_LENGTH = 128;

  /// <summary>
  /// Load a certificate in PEM format into an OpenSSL X509 Certificate Object.
  /// </summary>
  /// <param name="AFileName">
  /// The file to load the certificate from.
  /// </param>
  /// <returns>
  /// The OpenSSL X509 Certificate object.
  /// </returns>
function LoadCertificate(const AFileName: String): PX509;
/// <summary>
/// Load a pfx or .p12 certificate file into an OpenSSL SSL Context Object.
/// </summary>
/// <param name="ctx">
/// Context to load file into.
/// </param>
/// <param name="AFileName">
/// The certificate file to load.
/// </param>
/// <returns>
/// 1 if successful or 0 if failed.
/// </returns>
function TaurusTLS_SSL_CTX_use_certificate_file_PKCS12(ctx: PSSL_CTX;
  const AFileName: String): TIdC_INT;
/// <summary>
/// Load a .pfx or .p12 private key file into an OpenSSL SSL Context Object.
/// </summary>
/// <param name="ctx">
/// Context to load file into.
/// </param>
/// <param name="AFileName">
/// The private key file to load.
/// </param>
/// <returns>
/// 1 if successful or 0 if failed.
/// </returns>
function TaurusTLS_SSL_CTX_use_PrivateKey_file_PKCS12(ctx: PSSL_CTX;
  const AFileName: String): TIdC_INT;
/// <summary>
/// Load a private key into an OpenSSL Context Object.
/// </summary>
/// <param name="ctx">
/// Context to load file into.
/// </param>
/// <param name="AFileName">
/// Private Key file.
/// </param>
/// <param name="AType">
/// The format of the file. Usually one of the SSL_FILETYPE_ constants from
/// the TaurusTLSHeaders_ssl unit.
/// </param>
/// <returns>
/// Returns 1 if successful or 0 if failed.
/// </returns>
function TaurusTLS_SSL_CTX_use_PrivateKey_file(ctx: PSSL_CTX; const AFileName: String;
  AType: Integer): TIdC_INT;
/// <summary>
/// Load Root certificates into an OpenSSL SSL Context Object.
/// </summary>
/// <param name="ctx">
/// The Context where the root certificates should be loaded.
/// </param>
/// <param name="ACAFile">
/// Root certificate file.
/// </param>
/// <param name="ACAPath">
/// Directories where to load root certificates from separated by colons.
/// </param>
/// <returns>
/// 1 if successful or 0 if failed.
/// </returns>
function TaurusTLS_SSL_CTX_load_verify_locations(ctx: PSSL_CTX;
  const ACAFile, ACAPath: String): TIdC_INT;
/// <summary>
/// Loads a certificate chain from a PEM file into an OpenSSL SSL Context
/// Object.
/// </summary>
/// <param name="ctx">
/// The context where the certificate chain should be loaded.
/// </param>
/// <param name="AFileName">
/// The .PEM file containing the certificate chain.
/// </param>
/// <returns>
/// 1 if successful or 0 if failed.
/// </returns>
function TaurusTLS_SSL_CTX_use_certificate_chain_file(ctx: PSSL_CTX;
  const AFileName: String): TIdC_INT;
// const AFileName: String; AType: Integer): TIdC_INT;
/// <summary>
/// Load a list of client Certificate Authority names.
/// </summary>
/// <param name="AFileName">
/// The file to load the list from.
/// </param>
/// <returns>
/// The list of Certificate Authorities.
/// </returns>
function TaurusTLS_SSL_load_client_CA_file(const AFileName: String)
  : PSTACK_OF_X509_NAME;
/// <summary>
/// Loads a DH parameters file into an OpenSSL Context Object.
/// </summary>
/// <param name="ctx">
/// The context where the DH parameters should be loaded.
/// </param>
/// <param name="AFileName">
/// The file to load the DH parameters from.
/// </param>
/// <param name="AType">
/// The format of the file. Usually one of the SSL_FILETYPE_ constants from
/// the TaurusTLSHeaders_ssl unit.
/// </param>
/// <returns>
/// 1 if successful or 0 if failed.
/// </returns>
function TaurusTLS_SSL_CTX_use_DHparams_file(ctx: PSSL_CTX; const AFileName: String;
  AType: Integer): TIdC_INT;
/// <summary>
/// Load Root certificates into an OpenSSL SSL Context Object.
/// </summary>
/// <param name="ctx">
/// The Context where the root certificates should be loaded.
/// </param>
/// <param name="AFileName">
/// Root certificate file.
/// </param>
/// <param name="APathName">
/// Directories where to load root certificates from separated by colons.
/// </param>
/// <returns>
/// 1 if successful or 0 if failed.
/// </returns>
function TaurusTLS_X509_STORE_load_locations(ctx: PX509_STORE;
  const AFileName, APathName: String): TIdC_INT;

implementation

uses
  Classes,
  IdGlobal,
  SysUtils,
  {$IFDEF STRING_IS_UNICODE}
  TaurusTLS_Utils,
  {$ENDIF}
  TaurusTLSHeaders_asn1,
  TaurusTLSHeaders_bio,
  TaurusTLSHeaders_dh,
  TaurusTLSHeaders_err,
  TaurusTLSHeaders_evp,
  TaurusTLSHeaders_pem,
  TaurusTLSHeaders_pkcs12,
  TaurusTLSHeaders_ssl,
  TaurusTLSHeaders_sslerr,
  TaurusTLSHeaders_stack,
  TaurusTLSHeaders_x509_vfy;

// ** General certificate loading **//
function LoadCertificate(const AFileName: String): PX509;
var
  LM: TMemoryStream;   //PALOFF - Created and freed objects,  Local identifiers that possibly are set more than once without referencing in-between
  LB: PBIO;
begin
  LB:=nil;
  Result := nil;
  LM := TMemoryStream.Create;
  try
    LM.LoadFromFile(AFileName);
    LB := BIO_new_mem_buf(LM.Memory^, LM.Size);
    if Assigned(LB) then
    begin
      Result := PEM_read_bio_X509(LB, nil, nil, nil);
    end;
  finally
    BIO_free(LB); //PALOFF - Functions called as procedures
    FreeAndNil(LM);
  end;
end;
// *********************************//

function xname_cmp(const a, b: PPX509_NAME): TIdC_INT; cdecl;
begin
  Result := X509_NAME_cmp(a^, b^);
end;


// SSL_CTX_use_PrivateKey_file() and SSL_CTX_use_certificate_file() do not
// natively support PKCS12 certificates/keys, only PEM/ASN1, so load them
// manually...

function TaurusTLS_SSL_CTX_use_PrivateKey_file_PKCS12(ctx: PSSL_CTX;
  const AFileName: String): TIdC_INT;
var
  LM: TMemoryStream;   //PALOFF - Created and freed objects
  b: PBIO;
  LKey: PEVP_PKEY;
  LCert: PX509;
  LP12: PPKCS12;
  LCertChain: PSTACK_OF_X509;
  LPassword: array of TIdAnsiChar;
  Ldefault_passwd_cb: pem_password_cb;
begin
  Result := 0;
  LPassword := nil;
  LKey := nil;
  LCert := nil;
  LM := TMemoryStream.Create;    //PALOFF - Created and freed objects
  try
    LM.LoadFromFile(AFileName);
  except
    // Surpress exception here since it's going to be called by the OpenSSL .DLL
    // Follow the OpenSSL .DLL Error conventions.
    SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_SYS_LIB);
    LM.Free;
    Exit;
  end;

  try
    b := BIO_new_mem_buf(LM.Memory^, LM.Size);
    if not Assigned(b) then
    begin
      SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_BUF_LIB);
      Exit;
    end;
    try
      SetLength(LPassword, MAX_SSL_PASSWORD_LENGTH + 1);
      LPassword[MAX_SSL_PASSWORD_LENGTH] := TIdAnsiChar(0);
      Ldefault_passwd_cb := SSL_CTX_get_default_passwd_cb(ctx);
      if Assigned(Ldefault_passwd_cb) then
      begin
        if Ldefault_passwd_cb(@LPassword[0], MAX_SSL_PASSWORD_LENGTH, 0,
          SSL_CTX_get_default_passwd_cb_userdata(ctx)) <= 0 then
        begin
          ERR_set_error(ERR_LIB_PEM, PEM_R_BAD_PASSWORD_READ, nil);
          Exit;
        end;
      end
      else
      begin
        // We could call  PEM_def_callback(), but I'm not sure how well
        // that works with console apps or some GUI's.  Fail the call.
        ERR_set_error(ERR_LIB_PEM, PEM_R_BAD_PASSWORD_READ, nil);
        Exit;
      end;
      LP12 := d2i_PKCS12_bio(b, nil);
      if not Assigned(LP12) then
      begin
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_PKCS12_LIB);
        Exit;
      end;
      try
        LCertChain := nil;
        if PKCS12_parse(LP12, @LPassword[0], LKey, LCert, @LCertChain) <> 1 then
        begin
          SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_PKCS12_LIB);
          Exit;
        end;
        try
          Result := SSL_CTX_use_PrivateKey(ctx, LKey);
        finally
          if Assigned(LCertChain) then
          begin
            sk_pop_free(LCertChain, @X509_free);
          end;
          X509_free(LCert);
          EVP_PKEY_free(LKey);
        end;
      finally
        PKCS12_free(LP12);
      end;
    finally
      BIO_free(b);   //PALOFF - Functions called as procedures
    end;
  finally
    FreeAndNil(LM);
  end;
end;

function TaurusTLS_SSL_CTX_use_certificate_file_PKCS12(ctx: PSSL_CTX;
  const AFileName: String): TIdC_INT;
var
  LM: TMemoryStream;   //PALOFF - Created and freed objects
  Lb: PBIO;
  LCert: PX509;
  LP12: PPKCS12;
  LKey: PEVP_PKEY;
  LCertChain: PSTACK_OF_X509;
  LPassword: array of TIdAnsiChar;
  Ldefault_passwd_callback: pem_password_cb;
begin
  LPassword := nil;
  Result := 0;
  LKey := nil;
  LCert := nil;
  LM := TMemoryStream.Create;
  try
    LM.LoadFromFile(AFileName);
  except
    // Surpress exception here since it's going to be called by the OpenSSL .DLL
    // Follow the OpenSSL .DLL Error conventions.
    SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_SYS_LIB);
    LM.Free;
    Exit;
  end;

  try
    Lb := BIO_new_mem_buf(LM.Memory^, LM.Size);
    if not Assigned(Lb) then
    begin
      SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_BUF_LIB);
      Exit;
    end;
    try
      SetLength(LPassword, MAX_SSL_PASSWORD_LENGTH + 1);
      LPassword[MAX_SSL_PASSWORD_LENGTH] := TIdAnsiChar(0);
      Ldefault_passwd_callback := SSL_CTX_get_default_passwd_cb(ctx);
      if Assigned(Ldefault_passwd_callback) then
      begin
        if Ldefault_passwd_callback(@LPassword[0], MAX_SSL_PASSWORD_LENGTH, 0,
          SSL_CTX_get_default_passwd_cb_userdata(ctx)) <= 0 then
        begin
          ERR_set_error(ERR_LIB_PEM, PEM_R_BAD_PASSWORD_READ, nil);
          Exit;
        end;
      end
      else
      begin
        ERR_set_error(ERR_LIB_PEM, PEM_R_BAD_PASSWORD_READ, nil);
        Exit;
      end;
      LP12 := d2i_PKCS12_bio(Lb, nil);
      if not Assigned(LP12) then
      begin
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_PKCS12_LIB);
        Exit;
      end;
      try
        LCertChain := nil;
        if PKCS12_parse(LP12, @LPassword[0], LKey, LCert, @LCertChain) <> 1 then
        begin
          SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_PKCS12_LIB);
          Exit;
        end;
        try
          Result := SSL_CTX_use_certificate(ctx, LCert);
        finally
          if Assigned(LCertChain) then
          begin
            sk_pop_free(LCertChain, @X509_free);
          end;
          X509_free(LCert);
          EVP_PKEY_free(LKey);
        end;
      finally
        PKCS12_free(LP12);
      end;
    finally
      BIO_free(Lb);  //PALOFF - Functions called as procedures
    end;
  finally
    FreeAndNil(LM);
  end;
end;

{
  IMPORTANT!!!

  OpenSSL can not handle Unicode file names at all.  On Posix systems, UTF8 File
  names can be used with OpenSSL.  The Windows operating system does not accept
  UTF8 file names at all so we have our own routines that will handle Unicode
  filenames.   Most of this section of code is based on code in the OpenSSL .DLL
  which is copyrighted by the OpenSSL developers.  Some of it is translated into
  Pascal and made some modifications so that it will handle Unicode filenames.
}

{$IFDEF STRING_IS_UNICODE} { UCS-2 implied }
{$IFDEF WINDOWS}
function TaurusTLS_unicode_X509_load_cert_crl_file(ctx: PX509_LOOKUP;
  const AFileName: String; const _type: TIdC_INT): TIdC_INT; forward;
function TaurusTLS_unicode_X509_load_cert_file(ctx: PX509_LOOKUP;
  const AFileName: String; _type: TIdC_INT): TIdC_INT; forward;

{
  This is for some file lookup definitions for a LOOKUP method that
  uses Unicode filenames instead of ASCII or UTF8.  It is not meant
  to be portable at all.
}

function by_TaurusTLS_unicode_file_ctrl(ctx: PX509_LOOKUP; cmd: TIdC_INT;
  const argc: PAnsiChar; argl: TIdC_LONG; var ret: PAnsiChar): TIdC_INT; cdecl; //FI:O804 - method parameter is declared but never used.
{$IFNDEF USE_INLINE_VAR}
var
  LFileName: String;
{$ENDIF}
begin
  case cmd of
    X509_L_FILE_LOAD:
      begin
{$IFDEF USE_INLINE_VAR}
        var
          LFileName: String;
{$ENDIF}
          // Note that typecasting an AnsiChar as a WideChar below is normally a crazy
          // thing to do.  The thing is that the TaurusTLS API is based on PAnsiChar, and
          // we are writing this function just for Unicode filenames.  argc is actually
          // a PWideChar that has been coerced into a PAnsiChar so it can pass through
          // OpenSSL APIs...
        case argl of
          X509_FILETYPE_DEFAULT:
            begin
              LFileName := GetEnvironmentVariable
                (AnsiStringToString(X509_get_default_cert_file_env));
              if LFileName = '' then
              begin
                LFileName := AnsiStringToString(X509_get_default_cert_file);
              end;
              Result := Ord(TaurusTLS_unicode_X509_load_cert_crl_file(ctx, LFileName,
                X509_FILETYPE_PEM) <> 0);
              if Result = 0 then
              begin
                X509err(X509_F_BY_FILE_CTRL, X509_R_LOADING_DEFAULTS);
              end;
            end;
          X509_FILETYPE_PEM:
            begin
              LFileName := PWideChar(Pointer(argc));
              Result := Ord(TaurusTLS_unicode_X509_load_cert_crl_file(ctx, LFileName,
                X509_FILETYPE_PEM) <> 0);
            end;
        else
          LFileName := PWideChar(Pointer(argc));
          Result := Ord(TaurusTLS_unicode_X509_load_cert_file(ctx, LFileName,
            TIdC_INT(argl)) <> 0);
        end;
      end;
  else
    Result := 0;
  end;
end;

function TaurusTLS_unicode_X509_load_cert_file(ctx: PX509_LOOKUP;
  const AFileName: String; _type: TIdC_INT): TIdC_INT;
var
  LM: TMemoryStream;  //PALOFF - Created and freed objects
  Lin: PBIO;
  LX: PX509;
  i, count: Integer;
begin
  Result := 0;
  count := 0;

  if AFileName = '' then
  begin
    Result := 1;
    Exit;
  end;

  LM := TMemoryStream.Create;
  try
    LM.LoadFromFile(AFileName);
  except
    // Surpress exception here since it's going to be called by the OpenSSL .DLL
    // Follow the OpenSSL .DLL Error conventions.
    X509err(X509_F_X509_LOAD_CERT_FILE, ERR_R_SYS_LIB);
    LM.Free;
    Exit;
  end;

  try
    Lin := BIO_new_mem_buf(LM.Memory^, LM.Size);
    if not Assigned(Lin) then
    begin
      X509err(X509_F_X509_LOAD_CERT_FILE, ERR_R_SYS_LIB);
      Exit;
    end;
    try
      case _type of
        X509_FILETYPE_PEM:
          begin
            repeat
              LX := PEM_read_bio_X509_AUX(Lin, nil, nil, nil);
              if not Assigned(LX) then
              begin
                if (ERR_GET_REASON(ERR_peek_last_error()) = PEM_R_NO_START_LINE)
                  and (count > 0) then
                begin
                  ERR_clear_error();
                  Break;
                end
                else
                begin
                  X509err(X509_F_X509_LOAD_CERT_FILE, ERR_R_PEM_LIB);
                  Exit;
                end;
              end;
              i := X509_STORE_add_cert(X509_LOOKUP_get_store(ctx), LX);
              if i = 0 then
              begin
                Exit;
              end;
              Inc(count);
              X509_free(LX);
            until False; //PALOFF - Condition evaluates to constant value
            Result := count;
          end;
        X509_FILETYPE_ASN1:
          begin
            LX := d2i_X509_bio(Lin, nil);
            if not Assigned(LX) then
            begin
              X509err(X509_F_X509_LOAD_CERT_FILE, ERR_R_ASN1_LIB);
              Exit;
            end;
            i := X509_STORE_add_cert(X509_LOOKUP_get_store(ctx), LX);
            if i = 0 then
            begin
              Exit;
            end;
            Result := i;
          end;
      else
        X509err(X509_F_X509_LOAD_CERT_FILE, X509_R_BAD_X509_FILETYPE);
        Exit;
      end;
    finally
      BIO_free(Lin); //PALOFF - Functions called as procedures
    end;
  finally
    FreeAndNil(LM);
  end;
end;

function TaurusTLS_unicode_X509_load_cert_crl_file(ctx: PX509_LOOKUP;
  const AFileName: String; const _type: TIdC_INT): TIdC_INT;
var
  LM: TMemoryStream;          //PALOFF - Created and freed objects
  Linf: PSTACK_OF_X509_INFO;  //PALOFF - Local identifiers that possibly are set more than once without referencing in-between

  Litmp: PX509_INFO;
  Lin: PBIO;
  i, count: Integer;
begin
  Result := 0;
  count := 0;
  if _type <> X509_FILETYPE_PEM then
  begin
    Result := TaurusTLS_unicode_X509_load_cert_file(ctx, AFileName, _type);
    Exit;
  end;

  LM := TMemoryStream.Create;
  try
    LM.LoadFromFile(AFileName);
  except
    // Surpress exception here since it's going to be called by the OpenSSL .DLL
    // Follow the OpenSSL .DLL Error conventions.
    X509err(X509_F_X509_LOAD_CERT_CRL_FILE, ERR_R_SYS_LIB);
    LM.Free;
    Exit;
  end;

  try
    Lin := BIO_new_mem_buf(LM.Memory^, LM.Size);
    if not Assigned(Lin) then
    begin
      X509err(X509_F_X509_LOAD_CERT_CRL_FILE, ERR_R_SYS_LIB);
      Exit;
    end;
    try
      Linf := PEM_X509_INFO_read_bio(Lin, nil, nil, nil);
    finally
      BIO_free(Lin); //PALOFF - Functions called as procedures
    end;
  finally
    FreeAndNil(LM);
  end;
  if not Assigned(Linf) then
  begin
    X509err(X509_F_X509_LOAD_CERT_CRL_FILE, ERR_R_PEM_LIB);
    Exit;
  end;
  try
    for i := 0 to sk_X509_INFO_num(Linf) - 1 do
    begin
      Litmp := sk_X509_INFO_value(Linf, i);
      if Assigned(Litmp^.x509) then
      begin
        X509_STORE_add_cert(X509_LOOKUP_get_store(ctx), Litmp^.x509);
        Inc(count);
      end;
      if Assigned(Litmp^.crl) then
      begin
        X509_STORE_add_crl(X509_LOOKUP_get_store(ctx), Litmp^.crl);
        Inc(count);
      end;
    end;
  finally
    sk_X509_INFO_pop_free(Linf, @X509_INFO_free);
  end;
  Result := count;
end;

procedure TaurusTLS_SSL_load_client_CA_file_err(var VRes: PSTACK_OF_X509_NAME);
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  if Assigned(VRes) then
  begin
    sk_X509_NAME_pop_free(VRes, @X509_NAME_free);
    VRes := nil;
  end;
end;

function TaurusTLS_SSL_load_client_CA_file(const AFileName: String)
  : PSTACK_OF_X509_NAME;
var
  LM: TMemoryStream;    //PALOFF - Created and freed objects
  LB: PBIO;
  Lsk: PSTACK_OF_X509_NAME;
  LX: PX509;
  LXN, LXNDup: PX509_NAME;
  Failed: Boolean;
begin
  Result := nil;
  Failed := False;
  LX := nil;
  Lsk := sk_X509_NAME_new(@xname_cmp);
  if Assigned(Lsk) then
  begin
    try
      LM := TMemoryStream.Create;
      try
        LM.LoadFromFile(AFileName);
      except
        // Surpress exception here since it's going to be called by the OpenSSL .DLL
        // Follow the OpenSSL .DLL Error conventions.
        SSLerr(SSL_F_SSL_LOAD_CLIENT_CA_FILE, ERR_R_SYS_LIB);
        LM.Free;
        Exit;
      end;
      try
        LB := BIO_new_mem_buf(LM.Memory^, LM.Size);
        if Assigned(LB) then
        begin
          try
            try
              repeat
                LX := PEM_read_bio_X509(LB, nil, nil, nil);
                if LX = nil then
                begin
                  Break;
                end;
                if not Assigned(Result) then
                begin
                  Result := sk_X509_NAME_new_null;
                  if not Assigned(Result) then
                  begin
                    SSLerr(SSL_F_SSL_LOAD_CLIENT_CA_FILE, ERR_R_MALLOC_FAILURE);
                    Failed := True;
                    Exit;
                  end;
                end;
                LXN := X509_get_subject_name(LX);
                if not Assigned(LXN) then
                begin
                  // error
                  TaurusTLS_SSL_load_client_CA_file_err(Result);
                  Failed := True;
                  Exit;
                end;
                // * check for duplicates */
                LXNDup := X509_NAME_dup(LXN);
                if not Assigned(LXNDup) then
                begin
                  // error
                  TaurusTLS_SSL_load_client_CA_file_err(Result);
                  Failed := True;
                  Exit;
                end;
                if sk_X509_NAME_find(Lsk, LXNDup) >= 0 then
                begin
                  X509_NAME_free(LXNDup);
                end
                else
                begin
                  sk_X509_NAME_push(Lsk, LXNDup);
                  sk_X509_NAME_push(Result, LXNDup);
                end;
                X509_free(LX);
                LX := nil;
              until False;  //PALOFF - Condition evaluates to constant value
            finally
              if Assigned(LX) then
              begin
                X509_free(LX);
              end;
              if Failed and Assigned(Result) then
              begin
                sk_X509_NAME_pop_free(Result, @X509_NAME_free);
                Result := nil;
              end;
            end;
          finally
            BIO_free(LB); //PALOFF - Functions called as procedures
          end;
        end
        else
        begin
          SSLerr(SSL_F_SSL_LOAD_CLIENT_CA_FILE, ERR_R_MALLOC_FAILURE);
        end;
      finally
        FreeAndNil(LM);
      end;
    finally
      sk_X509_NAME_free(Lsk);
    end;
  end
  else
  begin
    SSLerr(SSL_F_SSL_LOAD_CLIENT_CA_FILE, ERR_R_MALLOC_FAILURE);
  end;
  if Assigned(Result) then
  begin
    ERR_clear_error;
  end;
end;

function TaurusTLS_SSL_CTX_use_PrivateKey_file(ctx: PSSL_CTX; const AFileName: String;
  AType: Integer): TIdC_INT;
var
  LM: TMemoryStream;     //PALOFF - Created and freed objects
  b: PBIO;
  LKey: PEVP_PKEY;
  j: TIdC_INT;
begin
  Result := 0;

  LM := TMemoryStream.Create;
  try
    LM.LoadFromFile(AFileName);
  except
    // Surpress exception here since it's going to be called by the OpenSSL .DLL
    // Follow the OpenSSL .DLL Error conventions.
    SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_SYS_LIB);
    LM.Free;
    Exit;
  end;

  try
    b := BIO_new_mem_buf(LM.Memory^, LM.Size);
    if not Assigned(b) then
    begin
      SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_BUF_LIB);
      Exit;
    end;
    try
      case AType of
        SSL_FILETYPE_PEM:
          begin
            j := ERR_R_PEM_LIB;
            LKey := PEM_read_bio_PrivateKey(b, nil,
              SSL_CTX_get_default_passwd_cb(ctx),
              SSL_CTX_get_default_passwd_cb_userdata(ctx));
          end;
        SSL_FILETYPE_ASN1:
          begin
            j := ERR_R_ASN1_LIB;
            LKey := d2i_PrivateKey_bio(b, nil);
          end;
      else
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, SSL_R_BAD_SSL_FILETYPE);
        Exit;
      end;
      if not Assigned(LKey) then
      begin
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, j);
        Exit;
      end;
      Result := SSL_CTX_use_PrivateKey(ctx, LKey);
      EVP_PKEY_free(LKey);
    finally
      BIO_free(b); //PALOFF - Functions called as procedures
    end;
  finally
    FreeAndNil(LM);
  end;
end;

function TaurusTLS_SSL_CTX_use_certificate_chain_file(ctx: PSSL_CTX;
  const AFileName: String): TIdC_INT;
var
  LM: TMemoryStream;  //PALOFF - Created and freed objects
  b: PBIO;
  LX: PX509;
  ca: PX509;
  r: TIdC_INT;
  LErr: TIdC_ULONG;
  LPasswordCallback: pem_password_cb;
  LUserData: Pointer;
begin
  Result := 0;

  ERR_clear_error(); // * clear error stack for
  // * SSL_CTX_use_certificate() */

  LM := TMemoryStream.Create;
  try
    LM.LoadFromFile(AFileName);
  except
    // Surpress exception here since it's going to be called by the OpenSSL .DLL
    // Follow the OpenSSL .DLL Error conventions.
    SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE, ERR_R_SYS_LIB);
    LM.Free;
    Exit;
  end;
  try
    b := BIO_new_mem_buf(LM.Memory^, LM.Size);
    if not Assigned(b) then
    begin
      SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_BUF_LIB);
      Exit;
    end;
    try
      LPasswordCallback := SSL_CTX_get_default_passwd_cb(ctx);
      LUserData := SSL_CTX_get_default_passwd_cb_userdata(ctx);
      LX := PEM_read_bio_X509_AUX(b, nil, LPasswordCallback, LUserData);
      if LX = nil then
      begin
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE, ERR_R_PEM_LIB);
      end
      else
      begin
        Result := SSL_CTX_use_certificate(ctx, LX);
        if ERR_peek_error() <> 0 then
        begin
          Result := 0; // * Key/certificate mismatch doesn't imply
          // * ret==0 ... */
        end;
        if Result <> 0 then
        begin
          SSL_CTX_clear_chain_certs(ctx);
          repeat
            ca := PEM_read_bio_X509(b, nil, LPasswordCallback, LUserData); //PALOFF - Common subexpression, consider elimination
            if ca = nil then
            begin
              Break;
            end;
            r := SSL_CTX_add0_chain_cert(ctx, ca);
            if r = 0 then
            begin
              X509_free(ca);
              Result := 0;
              Break;
              // goto end;
            end;
            // *
            // * Note that we must not free r if it was successfully added to
            // * the chain (while we must free the main certificate, since its
            // * reference count is increased by SSL_CTX_use_certificate).
            // */
          until False;  //PALOFF - Condition evaluates to constant value
          if ca <> nil then
          begin
            // * When the while loop ends, it's usually just EOF. */
            LErr := ERR_peek_last_error();
            if (ERR_GET_LIB(LErr) = ERR_LIB_PEM) and
              (ERR_GET_REASON(LErr) = PEM_R_NO_START_LINE) then
            begin
              ERR_clear_error();
            end
            else
            begin
              Result := 0; // * some real error */
            end;
          end;
        end;
        // err:
        if LX <> nil then
        begin
          X509_free(LX);
        end;
      end;
    finally
      BIO_free(b); //PALOFF - Functions called as procedures
    end;
  finally
    FreeAndNil(LM);
  end;
end;

function TaurusTLS_X509_STORE_load_locations(ctx: PX509_STORE;
  const AFileName, APathName: String): TIdC_INT;
var
  lookup: PX509_LOOKUP;
  method: PX509_LOOKUP_METHOD; { reference counted }
begin
  Result := 0;
  if AFileName <> '' then
  begin
    method := X509_LOOKUP_meth_new('Load file into cache');
    lookup := X509_STORE_add_lookup(ctx, method);
    if not Assigned(lookup) then
    begin
      Exit;
    end;
    X509_LOOKUP_meth_set_ctrl(method, @by_TaurusTLS_unicode_file_ctrl);
    // RLebeau: the PAnsiChar(Pointer(...)) cast below looks weird, but it is
    // intentional. X509_LOOKUP_load_file() takes a PAnsiChar as input, but
    // we are using Unicode strings here.  So casting the UnicodeString to a
    // raw Pointer and then passing that to X509_LOOKUP_load_file() as PAnsiChar.
    // TaurusTLS_unicode_X509_LOOKUP_file will cast it back to PWideChar for processing...
    if X509_LOOKUP_load_file(lookup, PAnsiChar(Pointer(AFileName)),
      X509_FILETYPE_PEM) <> 1 then
    begin
      Exit;
    end;
  end;
  if APathName <> '' then
  begin
    { TODO: Figure out how to do the hash dir lookup with a Unicode path. }
    if X509_STORE_load_locations(ctx, nil, PAnsiChar(AnsiString(APathName))) <> 1
    then
    begin
      Exit;
    end;
  end;
  if (AFileName = '') and (APathName = '') then
  begin
    Exit;
  end;
  Result := 1;
end;

function TaurusTLS_SSL_CTX_load_verify_locations(ctx: PSSL_CTX;
  const ACAFile, ACAPath: String): TIdC_INT;
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  Result := TaurusTLS_X509_STORE_load_locations(SSL_CTX_get_cert_store(ctx),
    ACAFile, ACAPath);
end;

function TaurusTLS_SSL_CTX_use_DHparams_file(ctx: PSSL_CTX; const AFileName: String;
  AType: Integer): TIdC_INT;
var
  LM: TMemoryStream;   //PALOFF - Created and freed objects
  b: PBIO;
  LDH: PDH;
  j: Integer;
begin
  Result := 0;

  LM := TMemoryStream.Create;
  try
    LM.LoadFromFile(AFileName);
  except
    // Surpress exception here since it's going to be called by the OpenSSL .DLL
    // Follow the OpenSSL .DLL Error conventions.
    SSLerr(SSL_F_SSL3_CTRL, ERR_R_SYS_LIB);
    LM.Free;
    Exit;
  end;

  try
    b := BIO_new_mem_buf(LM.Memory^, LM.Size);
    if not Assigned(b) then
    begin
      SSLerr(SSL_F_SSL3_CTRL, ERR_R_BUF_LIB);
      Exit;
    end;
    try
      case AType of
        SSL_FILETYPE_ASN1:
          begin
            j := ERR_R_ASN1_LIB;
            LDH := d2i_DHparams_bio(b, nil);
          end;
        SSL_FILETYPE_PEM:
          begin
            j := ERR_R_DH_LIB;
            LDH := PEM_read_bio_DHparams(b, nil,
              SSL_CTX_get_default_passwd_cb(ctx),
              SSL_CTX_get_default_passwd_cb_userdata(ctx));
          end
      else
        begin
          SSLerr(SSL_F_SSL3_CTRL, SSL_R_BAD_SSL_FILETYPE);
          Exit;
        end;
      end;
      if not Assigned(LDH) then
      begin
        SSLerr(SSL_F_SSL3_CTRL, j);
        Exit;
      end;
      Result := SSL_CTX_set_tmp_dh(ctx, LDH);
      DH_free(LDH);
    finally
      BIO_free(b); //PALOFF - Functions called as procedures
    end;
  finally
    FreeAndNil(LM);
  end;
end;

{$ENDIF} // WINDOWS

{$IFDEF UNIX}

function TaurusTLS_SSL_load_client_CA_file(const AFileName: String)
  : PSTACK_OF_X509_NAME;
{$IFDEF USE_MARSHALLED_PTRS}
var
  M: TMarshaller;
{$ENDIF}
begin
  Result := SSL_load_client_CA_file(
{$IFDEF USE_MARSHALLED_PTRS}
    M.AsUtf8(AFileName).ToPointer
{$ELSE}
    PAnsiChar(UTF8String(AFileName))  //PALOFF - Possible bad typecast -  [AFileName : UnicodeString cast to PAnsiChar]
{$ENDIF}
    );
end;

function TaurusTLS_SSL_CTX_use_PrivateKey_file(ctx: PSSL_CTX; const AFileName: String;
  AType: Integer): TIdC_INT;
{$IFDEF USE_INLINE} inline; {$ENDIF}
{$IFDEF USE_MARSHALLED_PTRS}
var
  M: TMarshaller;
{$ENDIF}
begin
  Result := SSL_CTX_use_PrivateKey_file(ctx,
{$IFDEF USE_MARSHALLED_PTRS}
    M.AsUtf8(AFileName).ToPointer
{$ELSE}
    PAnsiChar(UTF8String(AFileName))  //PALOFF - Possible bad typecast -  [AFileName : UnicodeString cast to PAnsiChar]
{$ENDIF}
    , AType);
end;

function TaurusTLS_SSL_CTX_use_certificate_chain_file(ctx: PSSL_CTX;
  const AFileName: String): TIdC_INT;
{$IFDEF USE_INLINE} inline; {$ENDIF}
{$IFDEF USE_MARSHALLED_PTRS}
var
  M: TMarshaller;
{$ENDIF}
begin
  Result := SSL_CTX_use_certificate_chain_file(ctx,
{$IFDEF USE_MARSHALLED_PTRS}
    M.AsUtf8(AFileName).ToPointer
{$ELSE}
    PAnsiChar(UTF8String(AFileName))  //PALOFF - Possible bad typecast -  [AFileName : UnicodeString cast to PAnsiChar]
{$ENDIF});
end;

{$IFDEF USE_MARSHALLED_PTRS}

function AsUtf8OrNil(var M: TMarshaller; const S: String): Pointer;
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  if S <> '' then
  begin
    Result := M.AsUtf8(S).ToPointer;
  end
  else
  begin
    Result := nil;
  end;
end;
{$ENDIF}

function TaurusTLS_X509_STORE_load_locations(ctx: PX509_STORE;
  const AFileName, APathName: String): TIdC_INT;
{$IFDEF USE_INLINE} inline; {$ENDIF}
{$IFDEF USE_MARSHALLED_PTRS}
var
  M: TMarshaller;
{$ENDIF}
begin
  // RLebeau 4/18/2010: X509_STORE_load_locations() expects nil pointers
  // for unused values, but casting a string directly to a PAnsiChar
  // always produces a non-nil pointer, which causes X509_STORE_load_locations()
  // to fail. Need to cast the string to an intermediate Pointer so the
  // PAnsiChar cast is applied to the raw data and thus can be nil...
  //
  // RLebeau 8/18/2017: TMarshaller also produces a non-nil TPtrWrapper for
  // an empty string, so need to handle nil specially with marshalled
  // strings as well...
  //
  Result := X509_STORE_load_locations(ctx,
{$IFDEF USE_MARSHALLED_PTRS}
    AsUtf8OrNil(M, AFileName), AsUtf8OrNil(M, APathName)
{$ELSE}
    PAnsiChar(Pointer(UTF8String(AFileName))), //PALOFF - Possible bad typecast - [AFileName : UnicodeString cast to PAnsiChar]
    PAnsiChar(Pointer(UTF8String(APathName)))  //PALOFF - Possible bad typecast - [APathName : UnicodeString cast to PAnsiChar]
{$ENDIF}
    );
end;

function TaurusTLS_SSL_CTX_load_verify_locations(ctx: PSSL_CTX;
  const ACAFile, ACAPath: String): TIdC_INT;
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  // RLebeau: why are we calling X509_STORE_load_locations() directly
  // instead of just calling SSL_CTX_load_verify_locations() with
  // UTF-8 input?

  // Result := SSL_CTX_load_verify_locations(ctx,
  // {$IFDEF USE_MARSHALLED_PTRS}
  // AsUtf8OrNl(ACAFile),
  // AsUtf8OrNil(ACAPath)
  // {$ELSE}
  // PAnsiChar(Pointer(UTF8String(ACAFile))),
  // PAnsiChar(Pointer(UTF8String(ACAPath)))
  // {$ENDIF}
  // );

  Result := TaurusTLS_X509_STORE_load_locations(SSL_CTX_get_cert_store(ctx),
    ACAFile, ACAPath);
end;

function TaurusTLS_SSL_CTX_use_DHparams_file(ctx: PSSL_CTX; const AFileName: String;
  AType: Integer): TIdC_INT;
var
  b: PBIO;
  LDH: PDH;
  j: Integer;
{$IFDEF USE_MARSHALLED_PTRS}
  M: TMarshaller;
{$ENDIF}
begin
  Result := 0;
  b := BIO_new_file(
{$IFDEF USE_MARSHALLED_PTRS}
    M.AsUtf8(AFileName).ToPointer
{$ELSE}
    PAnsiChar(UTF8String(AFileName))  //PALOFF - Possible bad typecast -  [AFileName : UnicodeString cast to PAnsiChar]
{$ENDIF}
    , 'r');
  if Assigned(b) then
  begin
    try
      case AType of
        SSL_FILETYPE_ASN1:
          begin
            j := ERR_R_ASN1_LIB;
            LDH := d2i_DHparams_bio(b, nil);
          end;
        SSL_FILETYPE_PEM:
          begin
            j := ERR_R_DH_LIB;
            LDH := PEM_read_bio_DHparams(b, nil,
              SSL_CTX_get_default_passwd_cb(ctx),
              SSL_CTX_get_default_passwd_cb_userdata(ctx));
          end
      else
        begin
          SSLerr(SSL_F_SSL3_CTRL, SSL_R_BAD_SSL_FILETYPE);
          Exit;
        end;
      end;
      if not Assigned(LDH) then
      begin
        SSLerr(SSL_F_SSL3_CTRL, j);
        Exit;
      end;
      Result := SSL_CTX_set_tmp_dh(ctx, LDH);
      DH_free(LDH);
    finally
      BIO_free(b);  //PALOFF - Functions called as procedures
    end;
  end;
end;

{$ENDIF} // UNIX

{$ELSE} // STRING_IS_UNICODE
{ this conditional section assumes that strings are UTF8 or perhaps use a codepage
  and the calls typically resolve to direct calls to TaurusTLS }

function TaurusTLS_SSL_load_client_CA_file(const AFileName: String)
  : PSTACK_OF_X509_NAME;
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  Result := SSL_load_client_CA_file(PAnsiChar(AFileName));
end;

function TaurusTLS_SSL_CTX_use_PrivateKey_file(ctx: PSSL_CTX; const AFileName: String;
  AType: Integer): TIdC_INT;
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  Result := SSL_CTX_use_PrivateKey_file(ctx, PAnsiChar(AFileName), AType);
end;

function TaurusTLS_SSL_CTX_use_certificate_chain_file(ctx: PSSL_CTX;
  const AFileName: String): TIdC_INT;
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  Result := SSL_CTX_use_certificate_chain_file(ctx, PAnsiChar(AFileName));
end;

function TaurusTLS_X509_STORE_load_locations(ctx: PX509_STORE;
  const AFileName, APathName: String): TIdC_INT;
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  // RLebeau 4/18/2010: X509_STORE_load_locations() expects nil pointers
  // for unused values, but casting a string directly to a PAnsiChar
  // always produces a non-nil pointer, which causes X509_STORE_load_locations()
  // to fail. Need to cast the string to an intermediate Pointer so the
  // PAnsiChar cast is applied to the raw data and thus can be nil...
  //
  Result := X509_STORE_load_locations(ctx, PAnsiChar(Pointer(AFileName)),
    PAnsiChar(Pointer(APathName)));
end;

function TaurusTLS_SSL_CTX_load_verify_locations(ctx: PSSL_CTX;
  const ACAFile, ACAPath: String): TIdC_INT;
begin
  // RLebeau 4/18/2010: X509_STORE_load_locations() expects nil pointers
  // for unused values, but casting a string directly to a PAnsiChar
  // always produces a non-nil pointer, which causes X509_STORE_load_locations()
  // to fail. Need to cast the string to an intermediate Pointer so the
  // PAnsiChar cast is applied to the raw data and thus can be nil...
  //
  Result := SSL_CTX_load_verify_locations(ctx, PAnsiChar(Pointer(ACAFile)),
    PAnsiChar(Pointer(ACAPath)));
end;

function TaurusTLS_SSL_CTX_use_DHparams_file(ctx: PSSL_CTX; const AFileName: String;
  AType: Integer): TIdC_INT;
var
  b: PBIO;
  LDH: PDH;
  j: Integer;
begin
  Result := 0;
  b := BIO_new_file(PAnsiChar(AFileName), 'r');
  if Assigned(b) then
  begin
    try
      case AType of
        SSL_FILETYPE_ASN1:
          begin
            j := ERR_R_ASN1_LIB;
            LDH := d2i_DHparams_bio(b, nil);
          end;
        SSL_FILETYPE_PEM:
          begin
            j := ERR_R_DH_LIB;
            LDH := PEM_read_bio_DHparams(b, nil,
              SSL_CTX_get_default_passwd_cb(ctx),
              SSL_CTX_get_default_passwd_cb_userdata(ctx));
          end
      else
        begin
          SSLerr(SSL_F_SSL3_CTRL, SSL_R_BAD_SSL_FILETYPE);
          Exit;
        end;
      end;
      if not Assigned(LDH) then
      begin
        SSLerr(SSL_F_SSL3_CTRL, j);
        Exit;
      end;
      Result := SSL_CTX_set_tmp_dh(ctx, LDH);
      DH_free(LDH);
    finally
      BIO_free(b); //PALOFF - Functions called as procedures
    end;
  end;
end;

{$ENDIF}

end.
