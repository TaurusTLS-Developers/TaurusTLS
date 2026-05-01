{******************************************************************************}
{*  TaurusTLS                                                                 *}
{*           https://github.com/JPeterMugaas/TaurusTLS                        *}
{*                                                                            *}
{*  Copyright (c) 2024 TaurusTLS Developers, All Rights Reserved              *}
{*                                                                            *}
{* Portions of this software are Copyright (c) 1993 – 2018,                   *}
{* Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  *}
{******************************************************************************}
{$I TaurusTLSCompilerDefines.inc}
/// <summary>
///   Exception classes for TaurusTLS.
/// </summary>
unit TaurusTLSExceptionHandlers;

interface

uses
  Classes, SysUtils, IdException, IdCTypes, TaurusTLSHeaders_types,
  TaurusTLS_Utils;

type
//moved from IdSSLTaurusTLS so we can use these classes in other places

  /// <summary>
  ///   Anscestor for all exceptions that are raised in TaurusTLS.
  /// </summary>
  ETaurusTLSError               = class(EIdException)
  public
    /// <summary>
    ///   Raises the exception class.
    /// </summary>
    /// <param name="AMsg">
    ///   The error message to display.
    /// </param>
    class procedure RaiseWithMessage(const AMsg : String);
    class procedure RaiseWithMessageFmt(const AMsg : String;
      AArgs: array of const);
  end;

  /// <summary>
  ///   Anscestor of exceptions that are raised when a LibSSL function fails.
  /// </summary>
  ETaurusTLSAPISSLError = class(ETaurusTLSError)
{$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} protected
    FErrorCode : TIdC_INT;
    FRetCode : TIdC_INT;
  public
    /// <summary>
    ///   Raises an instance of the class.
    /// </summary>
    /// <param name="ASSL">
    ///   The OpenSSL SSL Object where the failure occurred.
    /// </param>
    /// <param name="ARetCode">
    ///   The return code for the failure.
    /// </param>
    /// <param name="AMsg">
    ///   The error message to display.
    /// </param>
    class procedure RaiseException(ASSL: PSSL; const ARetCode : TIdC_INT; const AMsg : String = '');
    /// <summary>
    ///   Raises the exception class.
    /// </summary>
    /// <param name="AErrCode">
    ///   The error code for the failure.
    /// </param>
    /// <param name="ARetCode">
    ///   The return code for the failure.
    /// </param>
    /// <param name="AMsg">
    ///   The message to display.
    /// </param>
    class procedure RaiseExceptionCode(const AErrCode : TIdC_ULONG; ARetCode : TIdC_INT; const AMsg : String = '');
    /// <summary>
    ///   Error Code returned by the failure.
    /// </summary>
    property ErrorCode : TIdC_INT read FErrorCode;
    /// <summary>
    ///   The return code returned by the failure.
    /// </summary>
    property RetCode : TIdC_INT read FRetCode;
  end;

  /// <summary>
  ///   raised if the OPENSSL_init_ssl libSSL API call failed.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/master/man3/OPENSSL_init_ssl/">
  ///   OPENSSL_init_ssl
  /// </seealso>
  ETaurusTLSOpenSSLInitFailed = class(ETaurusTLSAPISSLError);

  ETaurusTLSUnderlyingCryptoError = class;

  /// <summary>
  ///   Anscestor of exceptions that are raised when a LibCrypto API call fails.
  /// </summary>
  ETaurusTLSAPICryptoError = class(ETaurusTLSError)
{$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} protected
    FErrorCode : TIdC_ULONG;
  public

    /// <summary>
    ///   Conditionally raises an exception if the result of an OpenSSL API call
    ///   &lt;&gt; 1 with the message provied by the AMsg parameter.
    /// </summary>
    /// <param name="AResult">
    ///   The result of an OpenSSL function.
    /// </param>
    /// <param name="AMsg">
    ///   The exception that is to be raised.
    /// </param>
    /// <param name="ARaiseException">
    ///   Set to true to raise the exception.
    /// </param>
    /// <returns>
    ///   True if the previous function succeded.
    /// </returns>
    class function CheckResult(AResult: TIdC_INT;
      const AMsg : String = ''; ARaiseException: boolean = True): boolean; static;

    /// <summary>
    ///   Conditionally raise exception if the result of an OpenSSL API call is
    ///   &lt;&gt; 1 with the message provied by the AMsg parameter.
    /// </summary>
    /// <param name="AResult">
    ///   The result of an OpenSSL function.
    /// </param>
    /// <param name="AMsg">
    ///   The exception that is to be raised.
    /// </param>
    /// <remarks>
    ///   This is just a handy wrapper for the CheckResult class function for
    ///   use in procedures to prevent warnings from code analysis.
    /// </remarks>
    class procedure RaiseIfError(AResult : TIdC_INT; const AMsg : String = ''); static;
    /// <summary>
    ///   Raises the exception class with an error code.
    /// </summary>
    /// <param name="AErrCode">
    ///   Error Code returned by the failure.
    /// </param>
    /// <param name="AMsg">
    ///   Message to display.
    /// </param>
    /// <exception cref="ETaurusTLSUnderlyingCryptoError">
    ///   If there was an underlying error.
    /// </exception>
    class procedure RaiseExceptionCode(const AErrCode : TIdC_ULONG; const AMsg : String = '');
    /// <summary>
    ///   Raises the exception class.
    /// </summary>
    /// <param name="AMsg">
    ///   Message to display.
    /// </param>
    class procedure RaiseException(const AMsg : String = '');
    /// <summary>
    ///   The error code from the failure.
    /// </summary>
    property ErrorCode : TIdC_ULONG read FErrorCode;
  end;

  /// <summary>
  ///   Raised if the X509_digest function failed.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.3/man3/X509_digest/">
  ///   X509_digest
  /// </seealso>
  ETaurusTLSX509DigestFailed = class(ETaurusTLSAPICryptoError);
  /// <summary>
  ///   Anscestor of exceptions that are raised when a DES_set_key API call fails.
  /// </summary>
  ETaurusTLSDesSetKeyError = class(ETaurusTLSAPICryptoError);

  /// <summary>
  ///   This is raised if the DES_set_key indicates that the parity of the key
  ///   is wrong.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/1.0.2/man3/des/">
  ///   DES_set_key
  /// </seealso>
  ETaurusTLSDesSetKeyWrongParity = class(ETaurusTLSDesSetKeyError);
  /// <summary>
  ///   This is raised if the DES_set_key indicates that the key is weal/
  /// </summary>
  /// <seealso href="https://docs.openssl.org/1.0.2/man3/des/">
  ///   DES_set_key
  /// </seealso>
  ETaurusTLSDesSetKeyWeakKey = class(ETaurusTLSDesSetKeyError);
  /// <summary>
  ///   Anscestor of exceptions that are raised when a LibCrypto API call fails.
  /// </summary>
  /// <summary>
  ///   Raised when there is an underlying error in the error Queue.
  /// </summary>
  ETaurusTLSUnderlyingCryptoError = class(ETaurusTLSAPICryptoError);

  /// <summary>
  ///   Anscestor of exceptions that are raised if an EVP_Digest* functions
  ///   fail.
  /// </summary>
  ETaurusTLSDigestError = class(ETaurusTLSAPICryptoError);
  /// <summary>
  ///   Raised when the EVP_MD_CTX_new function failed. <br />
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/EVP_DigestInit/">
  ///   EVP_MD_CTX_new
  /// </seealso>
  ETaurusTLSEVPMDCTXNew = class(ETaurusTLSDigestError);
  /// <summary>
  ///   Raised when the EVP_DigestFinal_ex function failed. <br />
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/EVP_DigestInit/">
  ///   EVP_DigestInit_ex
  /// </seealso>
  ETaurusTLSDigestFinalEx = class(ETaurusTLSDigestError);
  /// <summary>
  ///   Raised when the EVP_DigestInit_ex function failed.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/EVP_DigestInit/">
  ///   EVP_DigestInit_ex
  /// </seealso>
  ETaurusTLSDigestInitEx = class(ETaurusTLSDigestError);
  /// <summary>
  ///   Raised when the EVP_DigestUpdate function failed.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/EVP_DigestInit/">
  ///   EVP_DigestUpdate
  /// </seealso>
  ETaurusTLSDigestUpdate = class(ETaurusTLSDigestError);

  /// <summary>
  ///   Raised when a function failed to load and an attempt to call the
  ///   function is made.
  /// </summary>
  ETaurusTLSAPIFunctionNotPresent = class(ETaurusTLSError)
  public
    /// <summary>
    ///   Raises the ETaurusTLSAPIFunctionNotPresent exception.
    /// </summary>
    /// <param name="functionName">
    ///   The name of the function that was called.
    /// </param>
    class procedure RaiseException(const functionName: string);
  end;

  /// <summary>
  ///   Anscestor of exceptions that are raised if an HMAC* functions fails.
  /// </summary>
  ETaurusTLSHMACError = class(ETaurusTLSAPICryptoError);
  /// <summary>
  ///   Raised if the HMAC_CTX_new function failed.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/HMAC/">
  ///   HMAC_CTX_new
  /// </seealso>
  ETaurusTLSHMACCTXNew = class(ETaurusTLSHMACError);

  /// <summary>
  ///   Raised if the HMAC_Init_ex function failed.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/HMAC/">
  ///   HMAC_Init_ex
  /// </seealso>
  ETaurusTLSHMACInitEx = class(ETaurusTLSHMACError);
  /// <summary>
  ///   Raised if the HMAC_Update function failed.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/HMAC/">
  ///   HMAC_Update
  /// </seealso>
  ETaurusTLSHMACUpdate = class(ETaurusTLSHMACError);
  /// <summary>
  ///   Raised if the HMAC_Final function failed.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/HMAC/">
  ///   HMAC_Final
  /// </seealso>
  ETaurusTLSHMACFinal = class(ETaurusTLSHMACError);

  /// <summary>
  ///   Anscestor of exceptions that are raised if an EVP_CIPHER_* functions fails.
  /// </summary>
  ETaurusTLSEVPCipherError = class(ETaurusTLSAPICryptoError);
  /// <summary>
  ///   Raised if the EVP_CipherInit_ex function failed.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/1.0.2/man3/EVP_EncryptInit/">
  /// EVP_CipherInit_ex
  /// </seealso>
  ETaurusTLSEVPCipherInitEx = class(ETaurusTLSEVPCipherError);
  /// <summary>
  ///   Raised if the EVP_CipherUpdate function failed.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/EVP_EncryptInit/">
  ///  EVP_CipherUpdate
  /// </seealso>
  ETaurusTLSEVPCipherUpdate = class(ETaurusTLSEVPCipherError);
  /// <summary>
  ///   Raised if the EVP_CipherFinal_ex function failed.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/EVP_EncryptInit/">
  ///  EVP_CipherFinal_ex
  /// </seealso>
  ETaurusTLSEVPCipherFinalEx = class(ETaurusTLSEVPCipherError);

  /// <summary>
  ///   Anscestor of exceptions that are raised if an EVP_CIPHER_CTX_* functions fails.
  /// </summary>
  ETaurusTLSEVPCipherCTXError = class(ETaurusTLSAPICryptoError);
  /// <summary>
  ///   Raised if the EVP_CIPHER_CTX_new function failed.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/EVP_EncryptInit/">
  ///  EVP_CIPHER_CTX_new
  /// </seealso>
  EVPCipherCTXNew = class(ETaurusTLSEVPCipherCTXError);

implementation

uses IdGlobal, IdStack, IdResourceStringsProtocols,
   TaurusTLSHeaders_err, TaurusTLSHeaders_ssl,
   TaurusTLS_ResourceStrings;

function GetErrorMessage(const AErr : TIdC_ULONG) : String;
{$ifndef fpc}
{$IFDEF USE_INLINE} inline; {$ENDIF}
{$endif}
const
  sMaxErrMsg = 160;
var
  LErrMsg: array [0..sMaxErrMsg] of TIdAnsiChar;
  {$IFDEF USE_MARSHALLED_PTRS}
  LErrMsgPtr: TPtrWrapper;
  {$ENDIF}
begin
  {$ifdef fpc}
  Initialize(LErrMsg);
  {$else}
  FillChar(LErrMsg,sMaxErrMsg,0);
  {$endif}
  {$IFDEF USE_MARSHALLED_PTRS}
  LErrMsgPtr := TPtrWrapper.Create(@LErrMsg[0]);
  {$ENDIF}
  ERR_error_string_n(AErr,
    {$IFDEF USE_MARSHALLED_PTRS}
    LErrMsgPtr.ToPointer
    {$ELSE}
    LErrMsg
    {$ENDIF}, sMaxErrMsg);
  {$IFDEF USE_MARSHALLED_PTRS}
  Result := TMarshal.ReadStringAsAnsi(LErrMsgPtr);
  {$ELSE}
  Result := AnsiStringToString(LErrMsg);
  {$ENDIF}
end;

{ ETaurusTLSAPIFunctionNotPresent }

class procedure ETaurusTLSAPIFunctionNotPresent.RaiseException(const functionName: string);
begin
  raise ETaurusTLSAPIFunctionNotPresent.CreateFmt(ROSSLAPIFunctionNotPresent,[functionName]);
end;

{ ETaurusTLSAPICryptoError }
class function ETaurusTLSAPICryptoError.CheckResult(AResult: TIdC_INT;
  const AMsg : String = ''; ARaiseException: boolean = True): boolean;
begin
  Result := AResult = 1;
  if (not Result) and ARaiseException then
    RaiseException(AMsg);
end;

class procedure ETaurusTLSAPICryptoError.RaiseException(const AMsg : String = '');
  {$IFDEF USE_NORETURN}noreturn;{$ENDIF}
begin
  RaiseExceptionCode(ERR_get_error(), AMsg);
end;

class procedure ETaurusTLSAPICryptoError.RaiseExceptionCode(
  const AErrCode: TIdC_ULONG; const AMsg: String);
  {$IFDEF USE_NORETURN}noreturn;{$ENDIF}
var
  {$IFNDEF USE_INLINE_VAR}
  LMsg: String;
  LErrMsg : String;
  {$ENDIF}
  LException : ETaurusTLSAPICryptoError;   //PALOFF - Created and freed objects
begin
  {$IFDEF USE_INLINE_VAR}
  var LMsg, LErrMsg : String;
  {$ENDIF}
  LErrMsg :=  GetErrorMessage(AErrCode);
  if AMsg <> '' then begin
    LMsg := AMsg + sLineBreak + LErrMsg;
  end else begin
    LMsg := LErrMsg;
  end;
  LException := Create(LMsg);
  LException.FErrorCode := AErrCode;
  raise LException;
end;

class procedure ETaurusTLSAPICryptoError.RaiseIfError(AResult: TIdC_INT;
  const AMsg: String);
begin
  CheckResult(AResult, AMsg);  //PALOFF - Functions called as procedures
end;

{ ETaurusTLSAPISSLError }

class procedure ETaurusTLSAPISSLError.RaiseException(ASSL: PSSL; const ARetCode: TIdC_INT;
  const AMsg: String);
    {$IFDEF USE_NORETURN}noreturn;{$ENDIF}
begin
  RaiseExceptionCode(SSL_get_error(ASSL, ARetCode), ARetCode, AMsg);
end;

class procedure ETaurusTLSAPISSLError.RaiseExceptionCode(const AErrCode : TIdC_ULONG; ARetCode: TIdC_INT;
  const AMsg: String);
    {$IFDEF USE_NORETURN}noreturn;{$ENDIF}
var
  LErrQueue : TIdC_ULONG;
  LException : ETaurusTLSAPISSLError;  //PALOFF - Created and freed objects
  {$IFNDEF USE_INLINE_VAR}
  LErrStr : String;
  {$ENDIF}
begin
  {$IFDEF USE_INLINE_VAR}
  var LErrStr : String;
  {$ENDIF}
  if AMsg <> '' then begin
    LErrStr := AMsg + sLineBreak;
  end else begin
    LErrStr := '';
  end;
  case AErrCode of
    SSL_ERROR_SYSCALL :
    begin
      LErrQueue := ERR_get_error;
      if LErrQueue <> 0 then begin
        ETaurusTLSUnderlyingCryptoError.RaiseExceptionCode(LErrQueue, AMsg);
      end;
      if ARetCode = 0 then begin
        LException := Create(LErrStr + RSSSLEOFViolation);
        LException.FErrorCode := AErrCode;
        LException.FRetCode := ARetCode;
        raise LException;
      end;
      {Note that if LErrQueue returns 0 and ARetCode = -1, there probably
      is an error in the underlying socket so you should raise a socket error}
      if ARetCode = -1 then begin
        // TODO: catch the socket exception and re-raise it as the InnerException
        // for an ETaurusTLSAPISSLError exception...
        GStack.RaiseLastSocketError;
      end;
    end;
    SSL_ERROR_SSL : begin
      ETaurusTLSUnderlyingCryptoError.RaiseException(AMsg);
    end
  end;
  // everything else...
  LException := Create(LErrStr + GetErrorMessage(AErrCode));
  LException.FErrorCode := AErrCode;
  LException.FRetCode := ARetCode;
  raise LException;
end;

{ ETaurusTLSError }

class procedure ETaurusTLSError.RaiseWithMessage(const AMsg: String);
{$IFDEF USE_NORETURN}noreturn;{$ENDIF}
begin
  raise Create(AMsg);
end;

class procedure ETaurusTLSError.RaiseWithMessageFmt(const AMsg: String;
  AArgs: array of const);
begin
  raise CreateFmt(AMsg, AArgs);
end;

end.

