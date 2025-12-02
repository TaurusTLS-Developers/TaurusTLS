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
{
  Rev 1.41    22/02/2024 AWhyman
  a. Property SSLProtocolVersion added to TSocket. This returns the SSL/TLS protocol
  version that was negotiated when the session was created.

  b. SSL Headers now loaded using the OpenSSLLoader unit in order to support
  OpenSSL 3 and later.

  c. New property TOpenSSLSSLOptions.UseSystemRootCACertificateStore. Defaults to true.
  If true then SSL_CTX_set_default_verify_paths is called. This causes the
  certs in OPENSSLDIR/certs to be used for certificate verification

  d. Windows only: if OPENSSL_DONT_USE_WINDOWS_CERT_STORE not defined  and
  TOpenSSLSSLOptions.UseSystemRootCACertificateStore is true then
  Windows Root Certificate store is also loaded into SSL Context X.509 certificate store.

  e. Direct access to OpenSSL internal data structures (exposed in earlier versions,
  but now opaque (typically 1.1.1 onwards) now uses getter and setter functions
  provided by later versions of OpenSSL libraries with forwards compatibility
  functions (in appropriate SSL Header unit) used to provide getters and setters
  for earlier versions.

  f. New functions: OPenSSLVersion and OpenSSLDir. These are information access
  that return, respectively, the OpenSSL Version string and the OpenSSL Directory.

  Rev 1.40    03/11/2009 09:04:00  AWinkelsdorf
  Implemented fix for Vista+ SSL_Read and SSL_Write to allow connection
  timeout.

  Rev 1.39    16/02/2005 23:26:08  CCostelloe
  Changed OnVerifyPeer.  Breaks existing implementation of OnVerifyPeer.  See
  long comment near top of file.

  Rev 1.38    1/31/05 6:02:28 PM  RLebeau
  Updated _GetThreadId() callback to reflect changes in IdGlobal unit

  Rev 1.37    7/27/2004 1:54:26 AM  JPMugaas
  Now should use the Intercept property for sends.

  Rev 1.36    2004-05-18 21:38:36  Mattias
  Fixed unload bug

  Rev 1.35    2004-05-07 16:34:26  Mattias
  Implemented  OpenSSL locking callbacks

  Rev 1.34    27/04/2004 9:38:48  HHariri
  Added compiler directive so it works in BCB

  Rev 1.33    4/26/2004 12:41:10 AM  BGooijen
  Fixed WriteDirect

  Rev 1.32    2004.04.08 10:55:30 PM  czhower
  IOHandler changes.

  Rev 1.31    3/7/2004 9:02:58 PM  JPMugaas
  Fixed compiler warning about visibility.

  Rev 1.30    2004.03.07 11:46:40 AM  czhower
  Flushbuffer fix + other minor ones found

  Rev 1.29    2/7/2004 5:50:50 AM  JPMugaas
  Fixed Copyright.

  Rev 1.28    2/6/2004 3:45:56 PM  JPMugaas
  Only a start on NET porting.  This is not finished and will not compile on
  DotNET>

  Rev 1.27    2004.02.03 5:44:24 PM  czhower
  Name changes

  Rev 1.26    1/21/2004 4:03:48 PM  JPMugaas
  InitComponent

  Rev 1.25    1/14/2004 11:39:10 AM  JPMugaas
  Server IOHandler now works.  Accept was commented out.

  Rev 1.24    2003.11.29 10:19:28 AM  czhower
  Updated for core change to InputBuffer.

  Rev 1.23    10/21/2003 10:09:14 AM  JPMugaas
  Intercept enabled.

  Rev 1.22    10/21/2003 09:41:38 AM  JPMugaas
  Updated for new API.  Verified with TIdFTP with active and passive transfers
  as well as clear and protected data channels.

  Rev 1.21    10/21/2003 07:32:38 AM  JPMugaas
  Checked in what I have.  Porting still continues.

  Rev 1.20    10/17/2003 1:08:08 AM  DSiders
  Added localization comments.

  Rev 1.19    2003.10.12 6:36:44 PM  czhower
  Now compiles.

  Rev 1.18    9/19/2003 11:24:58 AM  JPMugaas
  Should compile.

  Rev 1.17    9/18/2003 10:20:32 AM  JPMugaas
  Updated for new API.

  Rev 1.16    2003.07.16 3:26:52 PM  czhower
  Fixed for a core change.

  Rev 1.15    6/30/2003 1:52:22 PM  BGooijen
  Changed for new buffer interface

  Rev 1.14    6/29/2003 5:42:02 PM  BGooijen
  fixed problem in TIdOpenSSLIOHandlerSocket.SetPassThrough that Henrick
  Hellstrom reported

  Rev 1.13    5/7/2003 7:13:00 PM  BGooijen
  changed Connected to BindingAllocated in ReadFromSource

  Rev 1.12    3/30/2003 12:16:40 AM  BGooijen
  bugfixed+ added MakeFTPSvrPort/MakeFTPSvrPasv

  Rev 1.11    3/14/2003 06:56:08 PM  JPMugaas
  Added a clone method to the SSLContext.

  Rev 1.10    3/14/2003 05:29:10 PM  JPMugaas
  Change to prevent an AV when shutting down the FTP Server.

  Rev 1.9    3/14/2003 10:00:38 PM  BGooijen
  Removed TIdServerIOHandlerSSLBase.PeerPassthrough, the ssl is now enabled in
  the server-protocol-files

  Rev 1.8    3/13/2003 11:55:38 AM  JPMugaas
  Updated registration framework to give more information.

  Rev 1.7    3/13/2003 11:07:14 AM  JPMugaas
  OpenSSL classes renamed.

  Rev 1.6    3/13/2003 10:28:16 AM  JPMugaas
  Forgot the reegistration - OOPS!!!

  Rev 1.5    3/13/2003 09:49:42 AM  JPMugaas
  Now uses an abstract SSL base class instead of OpenSSL so 3rd-party vendors
  can plug-in their products.

  Rev 1.4    3/13/2003 10:20:08 AM  BGooijen
  Server side fibers

  Rev 1.3    2003.02.25 3:56:22 AM  czhower

  Rev 1.2    2/5/2003 10:27:46 PM  BGooijen
  Fixed bug in OpenEncodedConnection

  Rev 1.1    2/4/2003 6:31:22 PM  BGooijen
  Fixed for Indy 10

  Rev 1.0    11/13/2002 08:01:24 AM  JPMugaas
}
/// <summary>
/// This unit contains the <see cref="TTaurusTLSIOHandlerSocket" /> and
/// <see cref="TTaurusTLSServerIOHandler" /> classes plus helper classes.
/// The <see cref="TaurusTLSFIPS" /> unit is registered meaning hash
/// support routines are called by Indy - Internet Direct.
/// </summary>
unit TaurusTLS;
{
  Author: Gregor Ibic (gregor.ibic@intelicom.si)
  Copyright: (c) Gregor Ibic, Intelicom d.o.o and Indy Working Group.
}

{
  Indy TaurusTLS now uses the standard TaurusTLS libraries
  for pre-compiled win32 dlls, see:
  http://www.openssl.org/related/binaries.html
  recommended v0.9.8a or later
}

{
  Important information concerning OnVerifyPeer:
  Rev 1.39 of February 2005 deliberately broke the OnVerifyPeer interface,
  which (obviously?) only affects programs that implemented that callback
  as part of the SSL negotiation.  Note that you really should always
  implement OnVerifyPeer, otherwise the certificate of the peer you are
  connecting to is NOT checked to ensure it is valid.

  Prior to this, if the SSL library detected a problem with a certificate
  or the Depth was insufficient (i.e. the "Ok" parameter in VerifyCallback
  is 0 / FALSE), then irrespective of whether your OnVerifyPeer returned True
  or False, the SSL connection would be deliberately failed.

  This created a problem in that even if there was only a very minor
  problem with one of the certificates in the chain (OnVerifyPeer is called
  once for each certificate in the certificate chain), which the user may
  have been happy to accept, the SSL negotiation would be failed.  However,
  changing the code to allow the SSL connection when a user returned True
  for OnVerifyPeer would have meant that existing code which depended on
  automatic rejection of invalid certificates would then be accepting
  invalid certificates, which would have been an unacceptable security
  change.

  Consequently, OnVerifyPeer was changed to deliberately break existing code
  by adding an AOk parameter.  To preserve the previous functionality, your
  OnVerifyPeer event should do "Result := AOk;".  If you wish to consider
  accepting certificates that the SSL library has considered invalid, then
  in your OnVerifyPeer, make sure you satisfy yourself that the certificate
  really is valid and then set Result to True.  In reality, in addition to
  checking AOk, you should always implement code that ensures you are only
  accepting certificates which are valid (at least from your point of view).

  Ciaran Costelloe, ccostelloe@flogas.ie
}
{
  RLebeau 1/12/2011: Breaking OnVerifyPeer event again, this time to add an
  additional AError parameter (patch courtesy of "jvlad", dmda@yandex.ru).
  This helps user code distinquish between Self-signed and invalid certificates.
}

interface

{$I TaurusTLSLinkDefines.inc}
{$IFDEF WINDOWS}
{$IFNDEF OPENSSL_DONT_USE_WINDOWS_CERT_STORE}
{$DEFINE USE_WINDOWS_CERT_STORE}
{$ENDIF}
{$ENDIF}
{$TYPEDADDRESS OFF}

uses
  // facilitate inlining only.
{$IFDEF WINDOWS}
  {$IFDEF VCL_XE2_OR_ABOVE}
  WinAPI.Windows,
  {$ELSE}
  Windows,
  {$ENDIF}
{$ENDIF}
  Classes,
  IdCTypes,
  IdGlobal,
  IdStackConsts,
  IdSocketHandle,
  IdComponent,
  IdIOHandler,
  IdGlobalProtocols,
  IdThread,
  IdIOHandlerSocket,
  IdSSL,
  IdYarn,
  SysUtils,
  TaurusTLSExceptionHandlers,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_ssl,
  TaurusTLSHeaders_ssl3,
  TaurusTLSHeaders_tls1,
  TaurusTLS_Utils,
  TaurusTLS_X509,
  TaurusTLSFIPS {Ensure FIPS functions initialised};

{$IF DECLARED(TIdSSLVersion)}

const
  /// <summary>
  /// SSL 2.0
  /// </summary>
  SSLv2 = sslvSSLv2;
  /// <summary>
  /// SSL 2.0 or 3.0
  /// </summary>
  SSLv23 = sslvSSLv23;
  /// <summary>
  /// SSL 3.0
  /// </summary>
  SSLv3 = sslvSSLv3;
  /// <summary>
  /// TLS 1.0
  /// </summary>
  TLSv1 = sslvTLSv1;
  /// <summary>
  /// TLS 1.1
  /// </summary>
  TLSv1_1 = sslvTLSv1_1;
  /// <summary>
  /// TLS 1.2
  /// </summary>
  TLSv1_2 = sslvTLSv1_2;
  /// <summary>
  /// TLS 1.3
  /// </summary>
  TLSv1_3 = sslvTLSv1_3;

type
  /// <summary>
  /// Type for specifying a version of the TLS Protocol.
  /// </summary>
  TTaurusTLSSSLVersion = TIdSSLVersion;
  /// <summary>
  /// Can be one of the following values<para>
  /// <c>sslmUnassigned</c> Initial default value
  /// </para>
  /// <para>
  /// <c>sslmClient</c> Use Client method
  /// </para>
  /// <para>
  /// <c>sslmServer</c> Use Server method
  /// </para>
  /// <para>
  /// <c>sslmBoth</c> Use Client/Server method
  /// </para>
  /// </summary>
  TTaurusTLSSSLMode = TIdSSLMode;
  /// <summary>
  /// Can be one of the following values<para>
  /// <c>sslCtxClient</c>
  /// </para>
  /// <para>
  /// <c>sslCtxServer</c>
  /// </para>
  /// </summary>
  TTaurusTLSCtxMode = TIdSSLCtxMode;
{$ELSE}

type
  /// <summary>Type for specifying a version of the TLS Protocol.</summary>
  TTaurusTLSSSLVersion = (
    /// <summary>SSL 2.0</summary>
    SSLv2,
    /// <summary>SSL 2.0 or 3.0</summary>
    SSLv23,
    /// <summary>SSL 3.0</summary>
    SSLv3,
    /// <summary>TLS 1.0</summary>
    TLSv1,
    /// <summary>TLS 1.1</summary>
    TLSv1_1,
    /// <summary>TLS 1.2</summary>
    TLSv1_2,
    /// <summary>TLS 1.3</summary>
    TLSv1_3);
  { May need to update constants below if adding to this set }
  /// <summary>
  /// Type that determines which OpenSSL method should be callled.
  /// </summary>
  TTaurusTLSSSLMode = (
    /// <summary>Initial default value</summary>
    sslmUnassigned,
    /// <summary>Use Client method</summary>
    sslmClient,
    /// <summary>Use Server method</summary>
    sslmServer,
    /// <summary>Use Client/Server method</summary>
    sslmBoth);

  /// <summary>Can be one of the following values
  /// <para><c>sslCtxClient</c></para>
  /// <para><c>sslCtxServer</c></para>
  /// </summary>
  TTaurusTLSCtxMode = (
    /// <summary>Client</summary>
    sslCtxClient,
    /// <summary>Server</summary>
    sslCtxServer);
{$IFEND}
  /// <summary>
  /// Type used to specify a peer verification value.
  /// </summary>
  TTaurusTLSVerifyMode = (
    /// <summary>
    /// For servers, send certificate. For clients, verify server certificate.
    /// </summary>
    sslvrfPeer,
    /// <summary>
    /// For servers, require client certificate
    /// </summary>
    sslvrfFailIfNoPeerCert,
    /// <summary>
    /// For servers, request client certificate only at initial handshake. Do
    /// not ask for certificate during renegotiation.
    /// </summary>
    sslvrfClientOnce,
    /// <summary>
    /// For servers, server will not send client certificate request during
    /// initial handshake. Send the request during the
    /// SSL_verify_client_post_handshake call.
    /// </summary>
    sslvrfPostHandshake);
  /// <summary>
  /// Controls the peer verification. Can contain the following:<para>
  /// <c>sslvrfPeer</c> For servers, send certificate. For clients, verify
  /// server certificate.
  /// </para>
  /// <para>
  /// <c>sslvrfFailIfNoPeerCert</c> For servers, require client certificate
  /// </para>
  /// <para>
  /// <c>sslvrfClientOnce</c> For servers, request client certificate only
  /// at initial handshake. Do not ask for certificate during renegotiation.
  /// </para>
  /// <para>
  /// <c>sslvrfPostHandshake</c> For servers, server will not send client
  /// certificate request during initial handshake. Send the request during
  /// the SSL_verify_client_post_handshake call.
  /// </para>
  /// </summary>
  TTaurusTLSVerifyModeSet = set of TTaurusTLSVerifyMode;
    /// <summary>
    ///   OpenSSL security level from <c>0</c> (permit anything) to <c>5</c>
    ///   (most restrictive). It may be one of the following values:<br />
    ///   <para>
    ///     <c>0</c> Permit anything This retains compatibility with previous
    ///     versions of OpenSSL.
    ///   </para>
    ///   <para>
    ///     <c>1</c> SSL 3.0 or later required. Cipher must have a minimum of 80
    ///     security bits. As a result RSA, DSA and DH keys shorter than 1024
    ///     bits and ECC keys shorter than 160 bits are prohibited. All export
    ///     cipher suites are prohibited since they all offer less than 80 bits
    ///     of security. Signatures using SHA1 and MD5 are also forbidden at
    ///     this level as they have less than 80 security bits.
    ///   </para>
    ///   <para>
    ///     <c>2</c> TLS 1.0 or later required. Cipher must have a minimum of
    ///     112 security bits. As a result RSA, DSA and DH keys shorter than
    ///     2048 bits and ECC keys shorter than 224 bits are prohibited. Any
    ///     cipher suite using RC4 is also prohibited. Compression is disabled.
    ///      <br />
    ///   </para>
    ///   <para>
    ///     <c>3</c> TLS 1.1 or later required. Cipher must have a minimum of
    ///     128 security bits. As a result RSA, DSA and DH keys shorter than
    ///     3072 bits and ECC keys shorter than 256 bits are prohibited. Cipher
    ///     suites not offering forward secrecy are prohibited. Compression is
    ///     disabled. Session tickets are disabled. <br />
    ///   </para>
    ///   <para>
    ///     <c>4</c> TLS 1.2 or later required. Cipher must have a minimum of
    ///     192 security bits. As a result RSA, DSA and DH keys shorter than
    ///     7680 bits and ECC keys shorter than 384 bits are prohibited. Cipher
    ///     suites not offering forward secrecy are prohibited. Compression is
    ///     disabled. Session tickets are disabled. <br />
    ///   </para>
    ///   <para>
    ///     <c>5</c> TLS 1.2 or later required. Cipher must have a minimum of
    ///     256 security bits. As a result RSA, DSA and DH keys shorter than
    ///     15360 bits and ECC keys shorter than 512 bits are prohibited. Cipher
    ///     suites not offering forward secrecy are prohibited. Compression is
    ///     disabled. Session tickets are disabled.
    ///   </para>
    /// </summary>
    /// <seealso
    /// href="https://docs.openssl.org/3.0/man3/SSL_CTX_set_security_level/#default-callback-behaviour">
    ///   default-callback-behaviour
    /// </seealso>
  TTaurusTLSSecurityLevel = 0 .. 5;

const
  /// <summary>
  /// The default value for the TSSLOptions.MinTLSVersion property
  /// </summary>
  DEF_MIN_TLSVERSION = TLSv1_2;
  /// <summary>
  /// The maximum TLS version supported by this library.
  /// </summary>
  MAX_SSLVERSION = TLSv1_3;
  /// <summary>
  /// The default value for TSLLOptions.SecurityLevel property.
  /// </summary>
  /// <seealso
  /// href="https://docs.openssl.org/3.0/man3/SSL_CTX_set_security_level/#default-callback-behaviour">
  /// default-callback-behaviour
  /// </seealso>
  DEF_SECURITY_LEVEL = 2;

  /// <summary>
  ///   The default value for TSSLOptions.VerifyDepth property.
  /// </summary>
  /// <seealso
  /// href="https://docs.openssl.org/1.0.2/man3/SSL_CTX_set_verify/#notes">
  ///   SSL_CTX_set_verify
  /// </seealso>
  DEFAULT_VERIFY_DEPTH = 100;
  /// <summary>
  /// The default value for TSLLOptions.VerifyHostname property.
  /// </summary>
  DEF_VERIFY_HOSTNAME = True;

type
  /// <summary>
  /// TLS version reported in the TOnDebugMessageEvent callback type.
  /// </summary>
  TTaurusMsgCBVer = (
    /// <summary>
    /// SSL 3.0 header
    /// </summary>
    verSSL3Header,
    /// <summary>
    /// TLS 1.0
    /// </summary>
    verTLS1,
    /// <summary>
    /// TLS 1.1
    /// </summary>
    verTLS1_1,
    /// <summary>
    /// TLS 1.2
    /// </summary>
    verTLS1_2,
    /// <summary>
    /// TLS 1.3
    /// </summary>
    verTLS1_3,
    /// <summary>
    /// DTLS 1.0
    /// </summary>
    verDTLS1,
    /// <summary>
    /// DTLS 1.2
    /// </summary>
    verDTLS1_2,
    /// <summary>
    /// DTLS Bad Version
    /// </summary>
    verDTLSBadVer,
    /// <summary>
    /// QUIC
    /// </summary>
    verQUIC,
    /// <summary>
    /// TLS Any Version
    /// </summary>
    verTLSAny);
  TTaurusTLSIOHandlerSocket = class;
  TTaurusTLSCipher = class;
  /// <summary>
  /// <see cref="TTaurusTLSIOHandlerSocket.OnDebugMessage" /> and <see
  /// cref="TTaurusTLSServerIOHandler.OnDebugMessage" /> events
  /// </summary>
  /// <param name="ASender">
  /// The object that triggers the event.
  /// </param>
  /// <param name="AWrite">
  /// True if packet was written. False if packet was read.
  /// </param>
  /// <param name="AVersion">
  /// TLS version of packet.
  /// </param>
  /// <param name="AContentType">
  /// Integer value may be one of the SSL3_RT_ and TLS1_RT_ content-type
  /// constants
  /// </param>
  /// <param name="buf">
  /// The contents of the packet.
  /// </param>
  /// <param name="SSL">
  /// The SSL object where the event occurred.
  /// </param>
  TOnDebugMessageEvent = procedure(ASender: TObject; const AWrite: Boolean;
    AVersion: TTaurusMsgCBVer; AContentType: TIdC_INT; const buf: TIdBytes;
    SSL: PSSL) of object;
  /// <summary>
  /// <see cref="TTaurusTLSIOHandlerSocket.OnStatusInfo" /> and <see
  /// cref="TTaurusTLSServerIOHandler.OnStatusInfo" /> events
  /// </summary>
  /// <param name="ASender">
  /// The object that triggers the event.
  /// </param>
  /// <param name="AsslSocket">
  /// The PSSL value associated with the event.
  /// </param>
  /// <param name="AWhere">
  /// A set of bitmasks that indicate where the event was called
  /// </param>
  /// <param name="Aret">
  /// A value indicating a particular message
  /// </param>
  /// <param name="AType">
  /// The AWhere value represented as a string
  /// </param>
  /// <param name="AMsg">
  /// The Aret value represented as a string
  /// </param>
  TOnStatusEvent = procedure(ASender: TObject; const AsslSocket: PSSL;
    const AWhere, Aret: TIdC_INT; const AType, AMsg: String) of object;
  /// <summary>
  /// <see cref="TTaurusTLSIOHandlerSocket.OnSecurityLevel" /> and <see
  /// cref="TTaurusTLSServerIOHandler.OnSecurityLevel" /> events
  /// </summary>
  /// <param name="ASender">
  /// The object that triggers the event.
  /// </param>
  /// <param name="AsslSocket">
  /// The SSL socket where the event occurred.
  /// </param>
  /// <param name="ACtx">
  /// The SSL_CTX object where the event occurred.
  /// </param>
  /// <param name="op">
  /// The operation expressed as an integer. This is one of the SSL_SECOP_*
  /// values.
  /// </param>
  /// <param name="bits">
  /// Number of security bits the cipher has.
  /// </param>
  /// <param name="ACipherNid">
  /// The Numeric Identifier (NID) of the cipher.
  /// </param>
  /// <param name="ACipher">
  /// The name of the cipher.
  /// </param>
  /// <param name="VAccepted">
  /// Return true if you will accept the connection attempt.
  /// </param>
  TOnSecurityLevelEvent = procedure(ASender: TObject; const AsslSocket: PSSL;
    ACtx: PSSL_CTX; op: TIdC_INT; bits: TIdC_INT; const ACipherNid: TIdC_INT;
    const ACipher: String; var VAccepted: Boolean) of object;
  /// <summary>
  /// <see cref="TTaurusTLSIOHandlerSocket.OnGetPassword" /> and <see
  /// cref="TTaurusTLSServerIOHandler.OnGetPassword" /> events
  /// </summary>
  /// <param name="ASender">
  /// The object that triggers the event.
  /// </param>
  /// <param name="VPassword">
  /// Return value indicating the password.
  /// </param>
  /// <param name="AIsWrite">
  /// True if the password is written/encrypted and typically the password is
  /// prompted for twice to prevent entry error.
  /// </param>
  /// <param name="VOk">
  /// Set this value to true if a password was retreived or false if password
  /// retreival failed (for example, the user clicked a cancel button).
  /// </param>
  TOnGetPasswordEvent = procedure(ASender: TObject; var VPassword: String;
    const AIsWrite: Boolean; var VOk: Boolean) of object;
  /// <summary>
  /// <see cref="TTaurusTLSIOHandlerSocket.OnVerifyError" /> and <see
  /// cref="TTaurusTLSServerIOHandler.OnVerifyError" /> events
  /// </summary>
  /// <param name="ASender">
  /// The object that triggers the event.
  /// </param>
  /// <param name="ACertificate">
  /// The certificate that raised the error
  /// </param>
  /// <param name="AError">
  /// The validation error code.
  /// </param>
  /// <param name="AMsg">
  /// The message string OpenSSL returned describing the failure breifly.
  /// </param>
  /// <param name="ADescr">
  /// A description of the failure in a long form for display to user in
  /// something such as a message-box.
  /// </param>
  /// <param name="VOk">
  /// Set to True if you wish the certificate to pass validation or False if
  /// you want it to fail validation.
  /// </param>
  TOnVerifyErrorEvent = procedure(ASender: TObject;
    ACertificate: TTaurusTLSX509; const AError: TIdC_LONG;
    const AMsg, ADescr: String; var VOk: Boolean) of object;
  /// <summary>
  /// <see cref="TTaurusTLSIOHandlerSocket.OnVerifyCallback" /> and <see
  /// cref="TTaurusTLSServerIOHandler.OnVerifyCallback" /> events
  /// </summary>
  /// <param name="ASender">
  /// The object that triggers the event (TTaurusTLSIOHandlerSocket or TTaurusTLSServerIOHandler).
  /// </param>
  /// <param name="APreverify_ok">
  /// Indicates whether the certificate at the current depth passed internal OpenSSL verification so far.
  /// 1 = passed, 0 = failed.
  /// </param>
  /// <param name="ACertificate">
  /// The current certificate being verified, wrapped in a TTaurusTLSX509 helper for easier inspection.
  /// </param>
  /// <param name="ADepth">
  /// The position of the certificate in the chain, where 0 is the peer/leaf certificate.
  /// </param>
  /// <param name="AError">
  /// The OpenSSL error code associated with this certificate, if any.
  /// </param>
  /// <param name="AMsg">
  /// The OpenSSL error string corresponding to AError.
  /// </param>
  /// <param name="ADescr">
  /// A descriptive message suitable for logging or display.
  /// </param>
  /// <param name="VContinue">
  /// Set to False to immediately terminate verification with failure.
  /// Set to True to allow verification to proceed.
  /// </param>
  TOnVerifyCallbackEvent = procedure(ASender: TObject;
    const APreverify_ok: TIdC_INT; ACertificate: TTaurusTLSX509;
    const ADepth: Integer; const AError: TIdC_LONG; const AMsg, ADescr: String;
    var VContinue: Boolean) of object;
  /// <summary>
  /// <see cref="TTaurusTLSIOHandlerSocket.OnBeforeConnect" />, <see
  /// cref="TTaurusTLSIOHandlerSocket.OnSSLNegotiated" />, and <see
  /// cref="TTaurusTLSServerIOHandler.OnSSLNegotiated" /> events
  /// </summary>
  /// <param name="ASender">
  /// The object that triggers the event.
  /// </param>
  TOnIOHandlerNotify = procedure(ASender: TTaurusTLSIOHandlerSocket) of object;

  TTaurusTLSContext = class;

  /// <summary>
  /// Object encapsolating published X509 Certificates.
  /// </summary>
  TTaurusTLSX509File = class(TCollectionItem)
{$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} protected
    FPublicKey: TFileName;
    FPrivateKey: TFileName;
    FRootKey: TFileName;
    fDHParamsFile: TFileName;
    fCtx: PSSL_CTX;
    fContext: TTaurusTLSContext;
    procedure AssignTo(Destination: TPersistent); override;
    function GetCtx: PSSL_CTX;
    function GetX509: PX509;
  public
    /// <summary>
    /// Creates a new TTaurus​TLSX509File object with Collection as the owner.
    /// </summary>
    constructor Create(Collection: TCollection); override;
    /// <summary>
    /// Frees resources and destroys the current instance.
    /// </summary>
    destructor Destroy; override;
    /// <summary>
    /// The OpenSSL SSL_CTX Object associated with this TTaurusTLSX509File
    /// </summary>
    property Context: TTaurusTLSContext read fContext write fContext;
    /// <summary>
    /// The OpenSSL SSL_CTX object for this certificate.
    /// </summary>
    property ctx: PSSL_CTX read GetCtx;
    /// <summary>
    /// The OpenSSL X509 object for this certificate.
    /// </summary>
    property x509: PX509 read GetX509;
  published
    /// <summary>
    /// Private Key file for certificate.
    /// </summary>
    property PrivateKey: TFileName read FPrivateKey write FPrivateKey;

    /// <summary>
    /// Public key file for the certificate.
    /// </summary>
    property PublicKey: TFileName read FPublicKey write FPublicKey;
    /// <summary>
    /// Public Root certificate chain file for the certificate.
    /// </summary>
    property RootKey: TFileName read FRootKey write FRootKey;
    /// <summary>
    /// DH Parameters file.
    /// </summary>
    property DHParamsFile: TFileName read fDHParamsFile write fDHParamsFile;
  end;

  /// <summary>
  /// A Collection of TTaurus​TLSX509File used to display and set
  /// certificate filenames.
  /// </summary>
  TTaurusTLSX509Files = class(TOwnedCollection)
{$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} protected
    function GetX509FilesItem(Index: Integer): TTaurusTLSX509File;
    procedure SetX509FilesItem(Index: Integer; const Value: TTaurusTLSX509File);
  public

    /// <summary>
    /// Creates a new TTaurus​TLSX509Files object with AOwner as the owner
    /// of the collection.
    /// </summary>
    /// <param name="AOwner">
    /// The owner of the collection being created.
    /// </param>
    constructor Create(AOwner: TPersistent);

    /// <summary>Use this method to add a new item to the collection.</summary>
    function AddX509File: TTaurusTLSX509File;

    /// <summary>
    /// Individual TTaurus​TLSX509File objects that the collection contains.
    /// </summary>
    property Items[Index: Integer]: TTaurusTLSX509File read GetX509FilesItem
      write SetX509FilesItem; default;

  end;

  { TTaurusTLSOptions }
  /// <summary>
  /// Class that provides properties that effect TLS.
  /// </summary>
  TTaurusTLSOptions = class(TPersistent)
{$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} protected
    FParent: TObject;
    fUseSystemRootCACertificateStore: Boolean;

    fMode: TTaurusTLSSSLMode;
    fMinTLSVersion: TTaurusTLSSSLVersion;
    fVerifyDepth: Integer;
    FSecurityLevel: TTaurusTLSSecurityLevel;
    fMethod: TTaurusTLSSSLVersion;
    fVerifyHostname: Boolean;
    fVerifyDirs: String;
    fCipherList: String;
    fVerifyMode: TTaurusTLSVerifyModeSet;
    procedure AssignTo(Destination: TPersistent); override;
    procedure SetMinTLSVersion(const AValue: TTaurusTLSSSLVersion);
    procedure SetSecurityLevel(const AValue: TTaurusTLSSecurityLevel);
  public
    /// <summary>
    /// Creates a new instance of TTaurusTLSOptions.
    /// </summary>
    constructor Create(AOwner: TObject);
    //
    /// <summary>
    /// The object that owns this TTaurusTLSOptions.
    /// </summary>
    /// <remarks>
    /// Should only be set by TaurusTLS itself.
    /// </remarks>
    property Parent: TObject read FParent write FParent;
    // procedure Assign(ASource: TPersistent); override;
  published
    /// <summary>
    /// The Minimum TLS version you will accept. The maximum TLS version that
    /// is accepted is TLS version 1.3.
    /// </summary>
    property MinTLSVersion: TTaurusTLSSSLVersion read fMinTLSVersion
      write fMinTLSVersion default DEF_MIN_TLSVERSION;
    /// <summary>
    ///   OpenSSL security level from <c>0</c> (permit anything) to <c>5</c>
    ///   (most restrictive). It may be one of the following values:<br />
    ///   <para>
    ///     <c>0</c> Permit anything This retains compatibility with previous
    ///     versions of OpenSSL.
    ///   </para>
    ///   <para>
    ///     <c>1</c> SSL 3.0 or later required. Cipher must have a minimum of 80
    ///     security bits. As a result RSA, DSA and DH keys shorter than 1024
    ///     bits and ECC keys shorter than 160 bits are prohibited. All export
    ///     cipher suites are prohibited since they all offer less than 80 bits
    ///     of security. Signatures using SHA1 and MD5 are also forbidden at
    ///     this level as they have less than 80 security bits.
    ///   </para>
    ///   <para>
    ///     <c>2</c> TLS 1.0 or later required. Cipher must have a minimum of
    ///     112 security bits. As a result RSA, DSA and DH keys shorter than
    ///     2048 bits and ECC keys shorter than 224 bits are prohibited. Any
    ///     cipher suite using RC4 is also prohibited. Compression is disabled.
    ///      <br />
    ///   </para>
    ///   <para>
    ///     <c>3</c> TLS 1.1 or later required. Cipher must have a minimum of
    ///     128 security bits. As a result RSA, DSA and DH keys shorter than
    ///     3072 bits and ECC keys shorter than 256 bits are prohibited. Cipher
    ///     suites not offering forward secrecy are prohibited. Compression is
    ///     disabled. Session tickets are disabled. <br />
    ///   </para>
    ///   <para>
    ///     <c>4</c> TLS 1.2 or later required. Cipher must have a minimum of
    ///     192 security bits. As a result RSA, DSA and DH keys shorter than
    ///     7680 bits and ECC keys shorter than 384 bits are prohibited. Cipher
    ///     suites not offering forward secrecy are prohibited. Compression is
    ///     disabled. Session tickets are disabled. <br />
    ///   </para>
    ///   <para>
    ///     <c>5</c> TLS 1.2 or later required. Cipher must have a minimum of
    ///     256 security bits. As a result RSA, DSA and DH keys shorter than
    ///     15360 bits and ECC keys shorter than 512 bits are prohibited. Cipher
    ///     suites not offering forward secrecy are prohibited. Compression is
    ///     disabled. Session tickets are disabled.
    ///   </para>
    /// </summary>
    /// <seealso
    /// href="https://docs.openssl.org/3.0/man3/SSL_CTX_set_security_level/#default-callback-behaviour">
    ///   default-callback-behaviour
    /// </seealso>
    property SecurityLevel: TTaurusTLSSecurityLevel read FSecurityLevel
      write SetSecurityLevel default DEF_SECURITY_LEVEL;
    /// <summary>
    /// Determines which OpenSSL method should be callled.
    /// </summary>
    property Mode: TTaurusTLSSSLMode read fMode write fMode;
    /// <summary>
    /// Controls the peer verification. Can contain the following:<para>
    /// <c>sslvrfPeer</c> For servers, send certificate. For clients, verify
    /// server certificate.
    /// </para>
    /// <para>
    /// <c>sslvrfFailIfNoPeerCert</c> For servers, require client
    /// certificate.
    /// </para>
    /// <para>
    /// <c>sslvrfClientOnce</c> For servers, request client certificate only
    /// at initial handshake. Do not ask for certificate during
    /// renegotiation.
    /// </para>
    /// <para>
    /// <c>sslvrfPostHandshake</c> For servers, server will not send client
    /// certificate request during initial handshake. Send the request
    /// during the SSL_verify_client_post_handshake call.
    /// </para>
    /// </summary>
    property VerifyMode: TTaurusTLSVerifyModeSet read fVerifyMode
      write fVerifyMode;
    /// <summary>
    /// The maximum depth for the certificate chain verification allowed.
    /// </summary>
    property VerifyDepth: Integer read fVerifyDepth write fVerifyDepth;
    // property VerifyFile: String read fVerifyFile write fVerifyFile;
    /// <summary>
    /// Directories where to load root certificates from separated by colons.
    /// </summary>
    /// <remarks>
    /// Only the PEM files in the directories are loaded.
    /// </remarks>
    property VerifyDirs: String read fVerifyDirs write fVerifyDirs;
    /// <summary>
    /// The peer certificate ( <see cref="TaurusTLS|TTaurusTLSSocket.PeerCert" />)
    /// subject's ( <see cref="TaurusTLS_X509|TTaurusTLSX509.Subject" />)
    /// common name ( <see cref="TaurusTLS_X509|TTaurusTLSX509Name.CommonName" />)
    /// must match the hostname provided to the TaurusTLS component.
    /// </summary>
    property VerifyHostname: Boolean read fVerifyHostname write fVerifyHostname
      default DEF_VERIFY_HOSTNAME;
    /// <summary>
    /// Use the system's ROOT and CA certificate stores to verify certificates.
    /// </summary>
    property UseSystemRootCACertificateStore: Boolean
      read fUseSystemRootCACertificateStore write fUseSystemRootCACertificateStore
      default True;
    /// <summary>
    /// The colon-separated (:) list of ciphersuits you wish to use or left
    /// empty to use the default ciphers. The list should only contain ciphers
    /// that were:<list type="bullet">
    /// <item>
    /// Were compiled into the OpenSSL library.
    /// </item>
    /// <item>
    /// Are availble for the particular security level you set with the
    /// <see cref="TaurusTLS|TTaurusTLSOptions.SecurityLevel" />
    /// property
    /// </item>
    /// <item>
    /// Are avaiable with the TLS version used in the session. That can be
    /// between the <see
    /// cref="TaurusTLS|TTaurusTLSOptions.MinTLSVersion" /> property
    /// and TLS 1.3.
    /// </item>
    /// </list>
    /// </summary>
    /// <seealso
    /// href="https://docs.openssl.org/3.1/man3/SSL_CTX_set_cipher_list/">
    /// SSL_CTX_set_cipher_list
    /// </seealso>
    property CipherList: String read fCipherList write fCipherList;
  end;

  /// <summary>
  /// The TLS Context encapsolated into an object. This object is for internal
  /// use only. You should not be using it directly.
  /// </summary>
  TTaurusTLSContext = class(TObject)
{$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} protected
    fUseSystemRootCACertificateStore: Boolean;
{$IFDEF USE_OBJECT_ARC}[Weak]
{$ENDIF} FParent: TObject;

    fMode: TTaurusTLSSSLMode;
    fsRootPublicKey, fsPublicKey, fsPrivateKey, fsDHParamsFile: String;
    fVerifyDepth: Integer;
    fVerifyMode: TTaurusTLSVerifyModeSet;
    FSecurityLevel: TTaurusTLSSecurityLevel;
    fMinTLSVersion: TTaurusTLSSSLVersion;

    // fVerifyFile: String;
    fVerifyDirs: String;
    fCipherList: String;
    fContext: PSSL_CTX;
    fStatusInfoOn: Boolean;
    fMessageCBOn: Boolean;
    fSecurityLevelCBOn: Boolean;
    // fPasswordRoutineOn: Boolean;
    fVerifyOn: Boolean;
    fSessionId: Integer;
    fVerifyHostname: Boolean;
{$IFDEF USE_WINDOWS_CERT_STORE}
    procedure LoadWindowsCertStore;
{$ENDIF}
    procedure SetSecurityLevel(const AValue: TTaurusTLSSecurityLevel);
    procedure DestroyContext;
    function GetSSLMethod: PSSL_METHOD;
    function GetVerifyMode: TTaurusTLSVerifyModeSet;
  public
    /// <summary>
    /// Creates a new instance of TTaurusTLSContext.
    /// </summary>
    constructor Create;
    /// <summary>
    /// Frees resources and destroys the current instance.
    /// </summary>
    destructor Destroy; override;
    /// <summary>
    /// Initializes this TTaurusTLSContext after the properties have been set.
    /// </summary>
    procedure InitContext(CtxMode: TTaurusTLSCtxMode);
    /// <summary>
    /// Makes a copy of this TTaurusTLSContext.
    /// </summary>
    function Clone: TTaurusTLSContext;

    /// <summary>
    /// The OpenSSL SSL_CTX Object associated with this TTaurusTLSContext
    /// </summary>
    property Context: PSSL_CTX read fContext;
    /// <summary>
    /// The object that owns this one.
    /// </summary>
    property Parent: TObject read FParent write FParent;
    /// <summary>
    /// Set to True to set the Message callback.
    /// </summary>
    property MessageCBOn: Boolean read fMessageCBOn write fMessageCBOn;
    /// <summary>
    /// Set to True to set the StatusInfo callback.
    /// </summary>
    property StatusInfoOn: Boolean read fStatusInfoOn write fStatusInfoOn;
    /// <summary>
    /// Set to True to set the Verify callback.
    /// </summary>
    property VerifyOn: Boolean read fVerifyOn write fVerifyOn;
    /// <summary>
    /// Set to true to set the SecurityLevel callback.
    /// </summary>
    property SecurityLevelCBOn: Boolean read fSecurityLevelCBOn
      write fSecurityLevelCBOn;
    // THese can't be published in a TObject without a compiler warning.
    // published
    /// <summary>
    /// The Minimum TLS version you will accept. The maximum TLS version that
    /// is accepted is TLS version 1.3.
    /// </summary>
    property MinTLSVersion: TTaurusTLSSSLVersion read fMinTLSVersion
      write fMinTLSVersion;
    /// <summary>
    /// Determines which OpenSSL method should be callled.
    /// </summary>
    property Mode: TTaurusTLSSSLMode read fMode write fMode;
    /// <summary>
    ///   OpenSSL security level from <c>0</c> (permit anything) to <c>5</c>
    ///   (most restrictive). It may be one of the following values:<br />
    ///   <para>
    ///     <c>0</c> Permit anything This retains compatibility with previous
    ///     versions of OpenSSL.
    ///   </para>
    ///   <para>
    ///     <c>1</c> SSL 3.0 or later required. Cipher must have a minimum of 80
    ///     security bits. As a result RSA, DSA and DH keys shorter than 1024
    ///     bits and ECC keys shorter than 160 bits are prohibited. All export
    ///     cipher suites are prohibited since they all offer less than 80 bits
    ///     of security. Signatures using SHA1 and MD5 are also forbidden at
    ///     this level as they have less than 80 security bits.
    ///   </para>
    ///   <para>
    ///     <c>2</c> TLS 1.0 or later required. Cipher must have a minimum of
    ///     112 security bits. As a result RSA, DSA and DH keys shorter than
    ///     2048 bits and ECC keys shorter than 224 bits are prohibited. Any
    ///     cipher suite using RC4 is also prohibited. Compression is disabled.
    ///      <br />
    ///   </para>
    ///   <para>
    ///     <c>3</c> TLS 1.1 or later required. Cipher must have a minimum of
    ///     128 security bits. As a result RSA, DSA and DH keys shorter than
    ///     3072 bits and ECC keys shorter than 256 bits are prohibited. Cipher
    ///     suites not offering forward secrecy are prohibited. Compression is
    ///     disabled. Session tickets are disabled. <br />
    ///   </para>
    ///   <para>
    ///     <c>4</c> TLS 1.2 or later required. Cipher must have a minimum of
    ///     192 security bits. As a result RSA, DSA and DH keys shorter than
    ///     7680 bits and ECC keys shorter than 384 bits are prohibited. Cipher
    ///     suites not offering forward secrecy are prohibited. Compression is
    ///     disabled. Session tickets are disabled. <br />
    ///   </para>
    ///   <para>
    ///     <c>5</c> TLS 1.2 or later required. Cipher must have a minimum of
    ///     256 security bits. As a result RSA, DSA and DH keys shorter than
    ///     15360 bits and ECC keys shorter than 512 bits are prohibited. Cipher
    ///     suites not offering forward secrecy are prohibited. Compression is
    ///     disabled. Session tickets are disabled.
    ///   </para>
    /// </summary>
    /// <seealso
    /// href="https://docs.openssl.org/3.0/man3/SSL_CTX_set_security_level/#default-callback-behaviour">
    ///   default-callback-behaviour
    /// </seealso>
    property SecurityLevel: TTaurusTLSSecurityLevel read FSecurityLevel
      write SetSecurityLevel;
    /// <summary>
    /// Root certificate file.
    /// </summary>
    property RootPublicKey: String read fsRootPublicKey write fsRootPublicKey;
    /// <summary>
    /// Client or Server certificate file.
    /// </summary>
    property PublicKey: String read fsPublicKey write fsPublicKey;
    /// <summary>
    /// The colon-separated (:) list of ciphersuits you wish to use or left
    /// empty to use the default ciphers. The list should only contain ciphers
    /// that were:<list type="bullet">
    /// <item>
    /// Were compiled into the OpenSSL library.
    /// </item>
    /// <item>
    /// Are availble for the particular security level you set with the
    /// <see cref="TaurusTLS|TTaurusTLSOptions.SecurityLevel" />
    /// property
    /// </item>
    /// <item>
    /// Are avaiable with the TLS version used in the session. That can be
    /// between the <see
    /// cref="TaurusTLS|TTaurusTLSOptions.MinTLSVersion" /> property
    /// and TLS 1.3.
    /// </item>
    /// </list>
    /// </summary>
    /// <seealso
    /// href="https://docs.openssl.org/3.1/man3/SSL_CTX_set_cipher_list/">
    /// SSL_CTX_set_cipher_list
    /// </seealso>
    property CipherList: String read fCipherList write fCipherList;
    /// <summary>
    /// Private Key file.
    /// </summary>
    property PrivateKey: String read fsPrivateKey write fsPrivateKey;
    /// <summary>
    /// DH Parameters file.
    /// </summary>
    property DHParamsFile: String read fsDHParamsFile write fsDHParamsFile;
    /// <summary>
    /// Use system's certificate store to verify certificates.
    /// </summary>
    property UseSystemRootCACertificateStore: Boolean
      read fUseSystemRootCACertificateStore write fUseSystemRootCACertificateStore;
    /// <summary>
    /// Directories where to load root certificates from separated by colons.
    /// </summary>
    /// <remarks>
    /// Only the PEM files in the directories are loaded.
    /// </remarks>
    property VerifyDirs: String read fVerifyDirs write fVerifyDirs;
    /// <summary>
    /// Controls the peer verification. Can contain the following:<para>
    /// <c>sslvrfPeer</c> For servers, send certificate. For clients, verify
    /// server certificate.
    /// </para>
    /// <para>
    /// <c>sslvrfFailIfNoPeerCert</c> For servers, require client
    /// certificate
    /// </para>
    /// <para>
    /// <c>sslvrfClientOnce</c> For servers, request client certificate only
    /// at initial handshake. Do not ask for certificate during
    /// renegotiation.
    /// </para>
    /// <para>
    /// <c>sslvrfPostHandshake</c> For servers, server will not send client
    /// certificate request during initial handshake. Send the request
    /// during the SSL_verify_client_post_handshake call.
    /// </para>
    /// </summary>
    property VerifyMode: TTaurusTLSVerifyModeSet read fVerifyMode
      write fVerifyMode;
    /// <summary>
    ///   The maximum depth for the certificate chain verification allowed.
    /// </summary>
    /// <remarks>
    ///   This value should be at least 3 since most certificate validity chains
    ///   are 3 certificates deep. Those certificatse usually are the root
    ///   certificate for the certificate authority, an intermediate certificate
    ///   for the certificate authority, and the server or leaf certificate.
    /// </remarks>
    property VerifyDepth: Integer read fVerifyDepth write fVerifyDepth
       default DEFAULT_VERIFY_DEPTH;
    /// <summary>
    /// Peer Certificate must match hostname
    /// </summary>
    property VerifyHostname: Boolean read fVerifyHostname write fVerifyHostname
       default DEF_VERIFY_HOSTNAME;
  end;

  /// <summary>
  ///   Read status of TLS Connection.
  /// </summary>
  TTaurusTLSReadStatus = (
    /// <summary>
    ///   if application data pending, or if it looks like we have disconnected
    /// </summary>
   sslDataAvailable,
    /// <summary>
   ///   try again later
   /// </summary>
   sslNoData,
   /// <summary>
   ///   if the connection has been shutdown
   /// </summary>
   sslEOF,
   /// <summary>
   ///   error state indicated
   /// </summary>
   sslUnrecoverableError);
  { TTaurusTLSSocket }
  /// <summary>
  /// Properties and methods for dealing with a TLS Socket.
  /// </summary>
  TTaurusTLSSocket = class(TObject)
{$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict {$ENDIF}protected
    fSession: PSSL_SESSION;
{$IFDEF USE_OBJECT_ARC}[Weak]
{$ENDIF} FParent: TObject;
    fPeerCert: TTaurusTLSX509;
    fSSL: PSSL;
    fSSLCipher: TTaurusTLSCipher;
    fSSLContext: TTaurusTLSContext;
    fHostName: String;
    fVerifyHostname: Boolean;
    function GetProtocolVersion: TTaurusTLSSSLVersion;
    function GetSSLProtocolVersionStr: string;
    function GetPeerCert: TTaurusTLSX509;

    function GetSSLCipher: TTaurusTLSCipher;
    function GetVerifyHostname: Boolean;
    procedure SetVerifyHostName(const Value: Boolean);
  public
    /// <summary>
    /// Creates a new instance of TTaurusTLSSocket.
    /// </summary>
    /// <param name="AParent">
    /// The TObject that will own the new instance.
    /// </param>
    constructor Create(AParent: TObject);
    /// <summary>
    /// Frees resources and destroys the current instance.
    /// </summary>
    destructor Destroy; override;
    /// <summary>
    /// Return an error code for the previous I/O operation.
    /// </summary>
    /// <param name="retCode">
    /// Return code from the previous function.
    /// </param>
    /// <returns>
    /// The error code
    /// </returns>
    function GetSSLError(retCode: Integer): Integer;
    /// <summary>
    /// Accept a TLS connection.
    /// </summary>
    /// <param name="pHandle">
    /// The connection to negotiate TLS with.
    /// </param>
    procedure Accept(const pHandle: TIdStackSocketHandle);
    /// <summary>
    /// Make a TLS connection.
    /// </summary>
    /// <param name="pHandle">
    /// The connection to negotiate TLS with.
    /// </param>
    procedure Connect(const pHandle: TIdStackSocketHandle);
    /// <summary>
    /// Encrypt bytes and send them to the peer.
    /// </summary>
    /// <param name="ABuffer">
    /// Buffer to encrypt and send.
    /// </param>
    /// <param name="AOffset">
    /// Offset into buffer.
    /// </param>
    /// <param name="ALength">
    /// number of bytes to send.
    /// </param>
    /// <returns>
    /// Number of bytes sent.
    /// </returns>
    function Send(const ABuffer: TIdBytes; const AOffset, ALength: TIdC_SIZET)
      : TIdC_SIZET;
    /// <summary>
    /// Receives bytes that after they have been decrypted.
    /// </summary>
    /// <param name="VBuffer">
    /// The buffer for bytes read
    /// </param>
    /// <returns>
    /// The number of bytes read.
    /// </returns>
    function Recv(var VBuffer: TIdBytes): TIdC_SIZET;
    /// <summary>
    ///   Checks the TLS Connection for data avilablity.
    /// </summary>
    /// <returns>
    ///   Read status of TLS Connection.
    /// </returns>
    function Readable: TTaurusTLSReadStatus;
    /// <summary>
    /// The Session ID as a string
    /// </summary>
    /// <returns>
    /// Session ID
    /// </returns>
    function GetSessionIDAsString: String;
    /// <summary>
    /// OpenSSL SSL object.
    /// </summary>
    property SSL: PSSL read fSSL;
    /// <summary>
    /// SSL Context for this connection.
    /// </summary>
    property SSLContext: TTaurusTLSContext read fSSLContext write fSSLContext;
    /// <summary>
    /// The TTaurusTLSIOHandlerSocket or TTaurusTLSServerIOHandler that owns
    /// this object.
    /// </summary>
    property Parent: TObject read FParent;
    /// <summary>
    /// The peer's certificate encapsolated in a <see cref="TTaurusTLSX509" /> object.
    /// </summary>
    property PeerCert: TTaurusTLSX509 read GetPeerCert;
    /// <summary>
    /// TLS Cipher information.
    /// </summary>
    property Cipher: TTaurusTLSCipher read GetSSLCipher;
    /// <summary>
    /// Name of peer you are connected to.
    /// </summary>
    /// <remarks>
    /// Used to verify that the Peer Certificate matches the HostName.
    /// </remarks>
    property HostName: String read fHostName write fHostName;
    /// <summary>
    /// TLS Protocol version in use.
    /// </summary>
    property SSLProtocolVersion: TTaurusTLSSSLVersion read GetProtocolVersion;
    /// <summary>
    /// TLS Protocol version in use as a string.
    /// </summary>
    property SSLProtocolVersionStr: string read GetSSLProtocolVersionStr;
    /// <summary>
    /// Peer Certificate must match hostname
    /// </summary>
    property VerifyHostname: Boolean read GetVerifyHostname
      write SetVerifyHostName;
  end;

  /// <summary>
  /// TTaurusTLSIOHandlerSocket and TTaurusTLSServerIOHandler common
  /// interface. This is here because both classes do not share a common
  /// anscestor. This bridges the gap.
  /// </summary>
  ITaurusTLSCallbackHelper = interface(IInterface)
    ['{F79BDC4C-4B26-446A-8EF1-9B0818321FAF}']
    /// <summary>
    /// Called when the Debug Message Callback is invoked.
    /// </summary>
    /// <param name="AWrite">
    /// True if packet was written. False if packet was read.
    /// </param>
    /// <param name="AVersion">
    /// TLS version of packet.
    /// </param>
    /// <param name="AContentType">
    /// Integer value may be one of the SSL3_RT_ and TLS1_RT_ content-type
    /// constants
    /// </param>
    /// <param name="buf">
    /// The contents of the packet.
    /// </param>
    /// <param name="SSL">
    /// The SSL object where the event occurred.
    /// </param>
    procedure DoOnDebugMessage(const AWrite: Boolean; AVersion: TTaurusMsgCBVer;
      AContentType: TIdC_INT; const buf: TIdBytes; SSL: PSSL);
    /// <summary>
    /// Called when the GetPassword callback is invoked.
    /// </summary>
    /// <param name="AIsWrite">
    /// True if the password is written/encrypted and typically the password
    /// is prompted for twice to prevent entry error.
    /// </param>
    /// <param name="VOk">
    /// Set this value to true if a password was retreived or false if password
    /// retreival failed (for example, the user clicked a cancel button).
    /// </param>
    /// <returns>
    /// The password the event handler returned.
    /// </returns>
    function GetPassword(const AIsWrite: Boolean; out VOk: Boolean): string;
    /// <summary>
    /// Called when the StatusInfo callback is invoked.
    /// </summary>
    /// <param name="ASSL">
    /// The PSSL value associated with the event.
    /// </param>
    /// <param name="AWhere">
    /// A set of bitmasks that indicate where the event was called
    /// </param>
    /// <param name="Aret">
    /// A value indicating a particular message
    /// </param>
    procedure StatusInfo(const ASSL: PSSL; AWhere, Aret: TIdC_INT);
    /// <summary>
    /// Called when the VerifyError callback is invoked.
    /// </summary>
    /// <param name="ACertificate">
    /// The certificate to be validated as a <see cref="TTaurusTLSX509" />
    /// </param>
    /// <param name="AError">
    /// The validation error if the certificate failed validation.
    /// </param>
    /// <returns>
    /// True if the certificate if you wish to accept the certificate or false
    /// if you wish to reject it.
    /// </returns>
    function VerifyError(ACertificate: TTaurusTLSX509;
      const AError: TIdC_LONG): Boolean;
    /// <summary>
    /// Handles certificate verification during the TLS handshake.
    /// Called once for each certificate in the chain to determine whether verification should continue.
    /// </summary>
    /// <param name="APreverify_ok">
    /// Indicates whether OpenSSL considers the current certificate valid at this stage:
    /// 1 = passed verification so far; 0 = failed verification.
    /// </param>
    /// <param name="ACertificate">
    /// The current certificate being verified, represented as a <c>TTaurusTLSX509</c> instance.
    /// </param>
    /// <param name="ADepth">
    /// The position of the certificate in the chain (0 = peer certificate, higher numbers = issuer certificates).
    /// </param>
    /// <param name="AError">
    /// The OpenSSL error code associated with this certificate if verification failed.
    /// </param>
    /// <param name="AMsg">
    /// The OpenSSL error message string corresponding to <c>AError</c>.
    /// </param>
    /// <param name="ADescr">
    /// A human-readable description of the verification error or status.
    /// </param>
    /// <param name="VContinue">
    /// Set this to <c>False</c> to stop verification immediately and fail the handshake.
    /// Leave as <c>True</c> to continue verification.
    /// </param>
    procedure VerifyCallback(const APreverify_ok: TIdC_INT;
      ACertificate: TTaurusTLSX509; const ADepth: Integer;
      const AError: TIdC_LONG; const AMsg, ADescr: String;
      var VContinue: Boolean);
    /// <summary>
    /// Called when the SecurityLevel callback is invoked.
    /// </summary>
    /// <param name="AsslSocket">
    /// The SSL socket where the event occurred.
    /// </param>
    /// <param name="ACtx">
    /// The SSL_CTX object where the event occurred.
    /// </param>
    /// <param name="op">
    /// The operation expressed as an integer. This is one of the SSL_SECOP_*
    /// values.
    /// </param>
    /// <param name="bits">
    /// Number of security bits the cipher has.
    /// </param>
    /// <param name="ACipherNid">
    /// The Numberic Identifier (NID) of the cipher.
    /// </param>
    /// <param name="VAccepted">
    /// Return true if you will accept the connection attempt.
    /// </param>
    procedure SecurityLevelCB(const AsslSocket: PSSL; ACtx: PSSL_CTX;
      const op, bits: TIdC_INT; const ACipherNid: TIdC_INT;
      out VAccepted: Boolean);
    /// <summary>
    /// Called to obtain this instance as a TTaurusTLSIOHandlerSocket.
    /// </summary>
    /// <returns>
    /// The object instance as a TTaurusTLSIOHandlerSocket or nil if this not
    /// a TTaurusTLSIOHandlerSocket.
    /// </returns>
    function GetIOHandlerSelf: TTaurusTLSIOHandlerSocket;
  end;

  /// <summary>
  /// TaurusTLS component that enables TLS in a TIdTCPClientCustom descendant.
  /// </summary>
  TTaurusTLSIOHandlerSocket = class(TIdSSLIOHandlerSocketBase,
    ITaurusTLSCallbackHelper)
{$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} protected
    fClientCert: TTaurusTLSX509File;
    fSSLContext: TTaurusTLSContext;
    fSSLOptions: TTaurusTLSOptions;
    fSSLSocket: TTaurusTLSSocket;
    // fPeerCert: TTaurusTLSX509;
    FOnDebugMessage: TOnDebugMessageEvent;
    FOnStatusInfo: TOnStatusEvent;
    fOnGetPassword: TOnGetPasswordEvent;
    fOnSecurityLevel: TOnSecurityLevelEvent;
    fOnVerifyError: TOnVerifyErrorEvent;
    // fSSLLayerClosed: Boolean;
    fOnBeforeConnect: TOnIOHandlerNotify;
    FOnSSLNegotiated: TOnIOHandlerNotify;
    fOnVerifyCallback: TOnVerifyCallbackEvent;
    //This needs to be private, not strict private
    //so we can set it in the clone method for FTP data
    //channel SNI.
    {$IFNDEF USE_STRICT_PRIVATE_PROTECTED} fHostname : String;{$ENDIF}
    // function GetPeerCert: TTaurusTLSX509;
    // procedure CreateSSLContext(axMode: TTaurusTLSSSLMode);
    //
    procedure SetPassThrough(const Value: Boolean); override;
    procedure DoVerifyError(Certificate: TTaurusTLSX509;
      const AError: TIdC_LONG; out VOk: Boolean);
    function RecvEnc(var VBuffer: TIdBytes): Integer; override;
    function SendEnc(const ABuffer: TIdBytes; const AOffset, ALength: Integer)
      : Integer; override;
    procedure Init;
    procedure OpenEncodedConnection;
    // some overrides from base classes
    procedure InitComponent; override;
    procedure ConnectClient; override;
    function CheckForError(ALastResult: Integer): Integer; override;
    procedure RaiseError(AError: Integer); override;

    { ITaurusTLSCallbackHelper }
    procedure DoOnDebugMessage(const AWrite: Boolean; AVersion: TTaurusMsgCBVer;
      AContentType: TIdC_INT; const buf: TIdBytes; SSL: PSSL);
    function GetPassword(const AIsWrite: Boolean; out VOk: Boolean): string;
    procedure StatusInfo(const AsslSocket: PSSL; AWhere, Aret: TIdC_INT);
    function VerifyError(ACertificate: TTaurusTLSX509;
      const AError: TIdC_LONG): Boolean;
    procedure VerifyCallback(const APreverify_ok: TIdC_INT;
      ACertificate: TTaurusTLSX509; const ADepth: Integer;
      const AError: TIdC_LONG; const AMsg, ADescr: String;
      var VContinue: Boolean);
    procedure SecurityLevelCB(const AsslSocket: PSSL; ACtx: PSSL_CTX;
      const op, bits: TIdC_INT; const ACipherNid: TIdC_INT;
      out VAccepted: Boolean);
    function GetIOHandlerSelf: TTaurusTLSIOHandlerSocket;
    //Rename to avoid warning about inherited methods.
    //It's probably best to have our own methods because some versions of
    //Indy available do not have these in the base class while others do.
    function TaurusGetProxyTargetHost: string;
    function TaurusGetURIHost: string;
    //This needs to be private, not strict private
    //so we can set it in the clone method for FTP data
    //channel SNI.
{$IFDEF USE_STRICT_PRIVATE_PROTECTED} private fHostname : String;{$ENDIF}
  public
    /// <summary>
    /// Frees resources and destroys the current instance.
    /// </summary>
    destructor Destroy; override;
    /// <summary>
    /// Called by Indy (Internet Direct) to make an IOHandler for TIdFTP
    /// data channel connection. The new IOHandler has similar properties
    /// except that <see cref="TaurusTLS|TTaurusTLSOptions.VerifyHostname">
    /// VerifyHostname</see> is false to prevent a certificate check that is
    /// likely to fail with the FTP data channel because the FTP PASV/EPSV
    /// command returns an IP address instead of a DNS hostname.
    /// </summary>
    /// <returns>
    /// The TTaurusTLSIOHandlerSocket that was created.
    /// </returns>
    /// <remarks>
    /// You should not call this directly.
    /// </remarks>
    function Clone: TIdSSLIOHandlerSocketBase; override;
    /// <summary>
    /// Called by Indy (Internet Direct) or this component and starts the TLS
    /// negotiation.
    /// </summary>
    /// <remarks>
    /// You should not call this directly.
    /// </remarks>
    procedure StartSSL; override;
    /// <summary>
    /// Called by Indy (Internet Direct) after a connection is accepted. This
    /// initiates the TLS handshake sequemce if Passthrough is False by
    /// calling the StartSSL method.
    /// </summary>
    /// <remarks>
    /// You should not call this directly.
    /// </remarks>
    procedure AfterAccept; override;
    /// <summary>
    /// Called by Indy (Internet Direct) and closes the Connection.
    /// </summary>
    /// <remarks>
    /// You should not call this directly.
    /// </remarks>
    procedure Close; override;
    /// <summary>
    /// Called by Indy (Internet Direct) and establishes the cconnection.
    /// </summary>
    /// <remarks>
    /// You should not call this directly.
    /// </remarks>
    procedure Open; override;
    /// <summary>
    /// Called by Indy. If the Passthrough property is False, the TLS
    /// connection is checked for pending decrypted data before calling the
    /// inherited Readable method.
    /// </summary>
    /// <param name="AMSec">
    /// The number of millaseconds to wait.
    /// </param>
    /// <returns>
    /// True if there was decrypted data or the inherited Readable method
    /// returned true.
    /// </returns>
    /// <remarks>
    /// You should not call this method directly.
    /// </remarks>
    function Readable(AMSec: Integer = IdTimeoutDefault): Boolean; override;
    /// <summary>
    /// Properties and methods for dealing with the TLS Connection.
    /// </summary>
    property SSLSocket: TTaurusTLSSocket read fSSLSocket write fSSLSocket;
    /// <summary>
    /// Occurs before TLS negotiation begins.
    /// </summary>
    /// <param name="ASender">
    /// The object that triggers the event.
    /// </param>
    property OnBeforeConnect: TOnIOHandlerNotify read fOnBeforeConnect
      write fOnBeforeConnect;
    /// <summary>
    /// The SSL Context for the TTaurusTLSIOHandlerSocket.
    /// </summary>
    /// <remarks>
    /// The SSL Context is for internal use only. You should not be using it
    /// directly.
    /// </remarks>
    property SSLContext: TTaurusTLSContext read fSSLContext write fSSLContext;
    /// <summary>
    /// Occurs when a TLS packet is read or sent.
    /// </summary>
    /// <param name="ASender">
    /// The object that triggers the event.
    /// </param>
    /// <param name="AWrite">
    /// True if packet was written. False if packet was read.
    /// </param>
    /// <param name="AVersion">
    /// TLS version of packet.
    /// </param>
    /// <param name="AContentType">
    /// Integer value may be one of the SSL3_RT_ and TLS1_RT_ content-type
    /// constants
    /// </param>
    /// <param name="buf">
    /// The contents of the packet.
    /// </param>
    /// <param name="SSL">
    /// The SSL object where the event occurred.
    /// </param>
    property OnDebugMessage: TOnDebugMessageEvent read FOnDebugMessage
      write FOnDebugMessage;
  published
    /// <summary>
    /// Client certificate to send to the TLS Server.
    /// </summary>
    property ClientCert: TTaurusTLSX509File read fClientCert;
    /// <summary>
    /// Occurs when TLS negotiation is concluded.
    /// </summary>
    /// <param name="ASender">
    /// The object that triggers the event.
    /// </param>
    property OnSSLNegotiated: TOnIOHandlerNotify read FOnSSLNegotiated
      write FOnSSLNegotiated;
    /// <summary>
    /// Properties that effect TLS.
    /// </summary>
    property SSLOptions: TTaurusTLSOptions read fSSLOptions write fSSLOptions;
    /// <summary>
    /// Occurs when there is a status message.
    /// </summary>
    /// <param name="ASender">
    /// The object that triggers the event.
    /// </param>
    /// <param name="AsslSocket">
    /// The PSSL value associated with the event.
    /// </param>
    /// <param name="AWhere">
    /// A set of bitmasks that indicate where the event was called
    /// </param>
    /// <param name="Aret">
    /// A value indicating a particular message
    /// </param>
    /// <param name="AType">
    /// The AWhere value represented as a string
    /// </param>
    /// <param name="AMsg">
    /// The Aret value represented as a string
    /// </param>
    property OnStatusInfo: TOnStatusEvent read FOnStatusInfo
      write FOnStatusInfo;
    /// <summary>
    /// Occurs when a password is required.
    /// </summary>
    /// <param name="ASender">
    /// The object that triggers the event.
    /// </param>
    /// <param name="VPassword">
    /// Return value indicating the password.
    /// </param>
    /// <param name="AIsWrite">
    /// True if the password is written/encrypted and typically the password
    /// is prompted for twice to prevent entry error.
    /// </param>
    /// <param name="VOk">
    /// Set this value to true if a password was retreived or false if password
    /// retreival failed (for example, the user clicked a cancel button).
    /// </param>
    property OnGetPassword: TOnGetPasswordEvent read fOnGetPassword
      write fOnGetPassword;
    /// <summary>
    /// Occurs when a connection attempt is made to a server and allows you to
    /// accept or reject a server based on your own criteria.
    /// </summary>
    /// <param name="ASender">
    /// The object that triggers the event.
    /// </param>
    /// <param name="AsslSocket">
    /// The SSL socket where the event occurred.
    /// </param>
    /// <param name="ACtx">
    /// The SSL_CTX object where the event occurred.
    /// </param>
    /// <param name="op">
    /// The operation expressed as an integer. This is one of the SSL_SECOP_*
    /// values.
    /// </param>
    /// <param name="bits">
    /// Number of security bits the cipher has.
    /// </param>
    /// <param name="ACipherNid">
    /// The Numeric Identifier (NID) of the cipher.
    /// </param>
    /// <param name="ACipher">
    /// The name of the cipher.
    /// </param>
    /// <param name="VAccepted">
    /// Return true if you will accept the connection attempt.
    /// </param>
    property OnSecurityLevel: TOnSecurityLevelEvent read fOnSecurityLevel
      write fOnSecurityLevel;
    /// <summary>
    /// Occurs when there is a certificate validation error.
    /// </summary>
    /// <param name="ASender">
    /// The object that triggers the event.
    /// </param>
    /// <param name="ACertificate">
    /// The certificate that raised the error
    /// </param>
    /// <param name="AError">
    /// The validation error code.
    /// </param>
    /// <param name="AMsg">
    /// The message string OpenSSL returned describing the failure breifly.
    /// </param>
    /// <param name="ADescr">
    /// A description of the failure in a long form for display to user in
    /// something such as a message-box.
    /// </param>
    /// <param name="VOk">
    /// Set to True if you wish the certificate to pass validation or False if
    /// you want it to fail validation.
    /// </param>
    property OnVerifyError: TOnVerifyErrorEvent read fOnVerifyError
      write fOnVerifyError;
    /// <summary>
    /// Occurs when a certificate in the TLS chain is being verified during the handshake.
    /// Use this event to inspect the intermediate result and current certificate
    /// and decide whether verification should continue.
    /// </summary>
    /// <param name="ASender">
    /// The object that triggers the event.
    /// </param>
    /// <param name="APreverify_ok">
    /// Indicates whether the certificate at the current depth passed internal OpenSSL verification so far.
    /// 1 = passed, 0 = failed.
    /// </param>
    /// <param name="ACertificate">
    /// The current certificate being verified, wrapped in a TTaurusTLSX509 helper for easier inspection.
    /// </param>
    /// <param name="ADepth">
    /// The position of the certificate in the chain, where 0 is the peer/leaf certificate.
    /// </param>
    /// <param name="AError">
    /// The OpenSSL error code associated with this certificate, if any.
    /// </param>
    /// <param name="AMsg">
    /// The OpenSSL error string corresponding to AError.
    /// </param>
    /// <param name="ADescr">
    /// A descriptive message suitable for logging or display.
    /// </param>
    /// <param name="VContinue">
    /// Set to False to immediately terminate verification with failure.
    /// Set to True to allow verification to proceed.
    /// </param>
    property OnVerifyCallback: TOnVerifyCallbackEvent read fOnVerifyCallback
      write fOnVerifyCallback;
  end;

  /// <summary>
  /// TaurusTLS component that enables TLS in a TIdCustomTCPServer descendant
  /// </summary>
  TTaurusTLSServerIOHandler = class(TIdServerIOHandlerSSLBase,
    ITaurusTLSCallbackHelper)
{$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} protected
    fCertificates: TTaurusTLSX509Files;
    fDefaultCert: TTaurusTLSX509File;
    fSSLOptions: TTaurusTLSOptions;
    fSSLContext: TTaurusTLSContext;
    FOnSSLNegotiated: TOnIOHandlerNotify;
    FOnStatusInfo: TOnStatusEvent;
    fOnSecurityLevel: TOnSecurityLevelEvent;
    fOnGetPassword: TOnGetPasswordEvent;
    FOnDebugMessage: TOnDebugMessageEvent;
    fOnVerifyError: TOnVerifyErrorEvent;
    fOnVerifyCallback: TOnVerifyCallbackEvent;
    //
    // procedure CreateSSLContext(axMode: TTaurusTLSSSLMode);
    // procedure CreateSSLContext;
    //
    procedure InitComponent; override;
    procedure SetCertificates(const AValue: TTaurusTLSX509Files);
    procedure InitCertContexts;
    { ITaurusTLSCallbackHelper }
    procedure DoOnDebugMessage(const AWrite: Boolean; AVersion: TTaurusMsgCBVer;
      AContentType: TIdC_INT; const buf: TIdBytes; SSL: PSSL);
    function GetPassword(const AIsWrite: Boolean; out VOk: Boolean): string;
    procedure StatusInfo(const AsslSocket: PSSL; AWhere, Aret: TIdC_INT);
    function VerifyError(ACertificate: TTaurusTLSX509;
      const AError: TIdC_LONG): Boolean;
    procedure VerifyCallback(const APreverify_ok: TIdC_INT;
      ACertificate: TTaurusTLSX509; const ADepth: Integer;
      const AError: TIdC_LONG; const AMsg, ADescr: String;
      var VContinue: Boolean);
    procedure SecurityLevelCB(const AsslSocket: PSSL; ACtx: PSSL_CTX;
      const op, bits: TIdC_INT; const ACipherNid: TIdC_INT;
      out VAccepted: Boolean);
    function GetIOHandlerSelf: TTaurusTLSIOHandlerSocket;
    function MakeDataChannelIOHandler: TTaurusTLSIOHandlerSocket;
  public
    /// <summary>
    /// Called by Indy (Internet Direct) and makes a TTaurusTLSContext for
    /// this TTaurusTLSServerIOHandler.
    /// </summary>
    /// <remarks>
    /// You should not call this method directly.
    /// </remarks>
    procedure Init; override;
    /// <summary>
    /// Called by Indy (Internet Direct) and destroys the TTaurusTLSContext
    /// for the TTaurusTLSServerIOHandler.
    /// </summary>
    procedure Shutdown; override;
{$I TaurusTLSUnusedParamOff.inc}
    // AListenerThread is a thread and not a yarn. Its the listener thread.
    /// <summary>
    /// Called by Indy (Internet Direct) when the server accepts a connection.
    /// </summary>
    /// <param name="ASocket">
    /// The server Biding that accepted the connection.
    /// </param>
    /// <param name="AListenerThread">
    /// The listening thread.
    /// </param>
    /// <param name="AYarn">
    /// The associated yarn.
    /// </param>
    /// <returns>
    /// The new IOHandler for the connection.
    /// </returns>
    /// <remarks>
    /// You should not call this method directly.
    /// </remarks>
    function Accept(ASocket: TIdSocketHandle; AListenerThread: TIdThread;
      AYarn: TIdYarn): TIdIOHandler; override;
{$I TaurusTLSUnusedParamOn.inc}
    // function Accept(ASocket: TIdSocketHandle; AThread: TIdThread) : TIdIOHandler;  override;
    /// <summary>
    /// Frees resources and destroys the current instance.
    /// </summary>
    destructor Destroy; override;
    /// <summary>
    /// Called by Indy (Internet Direct) to make a TTaurusTLSIOHandlerSocket
    /// with Passsthrough set to True.
    /// </summary>
    /// <returns>
    /// The TTaurusTLSIOHandlerSocket that was created.
    /// </returns>
    /// <remarks>
    /// You should not call this method directly.
    /// </remarks>
    function MakeClientIOHandler: TIdSSLIOHandlerSocketBase; override;
    /// <summary>
    /// Called by Indy (Internet Direct) to make a TTaurusTLSIOHandlerSocket
    /// for the TIdFTPServer's PORT connection.
    /// </summary>
    /// <returns>
    /// The TTaurusTLSIOHandlerSocket that was created.
    /// </returns>
    /// <remarks>
    /// You should not call this method directly.
    /// </remarks>
    function MakeFTPSvrPort: TIdSSLIOHandlerSocketBase; override;
    /// <summary>
    /// Called by Indy (Internet Direct) to make a TTaurusTLSIOHandlerSocket
    /// for the TIdFTPServer's PASV connection.
    /// </summary>
    /// <returns>
    /// The TTaurusTLSIOHandlerSocket that was created.
    /// </returns>
    /// <remarks>
    /// You should not call this method directly.
    /// </remarks>
    function MakeFTPSvrPasv: TIdSSLIOHandlerSocketBase; override;

    /// <summary>
    /// The SSL Context for the TTaurusTLSServerIOHandler.
    /// </summary>
    property SSLContext: TTaurusTLSContext read fSSLContext;
    /// <summary>
    /// Occurs when a TLS packet is read or sent.
    /// </summary>
    /// <param name="ASender">
    /// The object that triggers the event.
    /// </param>
    /// <param name="AWrite">
    /// True if packet was written. False if packet was read.
    /// </param>
    /// <param name="AVersion">
    /// TLS version of packet.
    /// </param>
    /// <param name="AContentType">
    /// Integer value may be one of the SSL3_RT_ and TLS1_RT_ content-type
    /// constants
    /// </param>
    /// <param name="buf">
    /// The contents of the packet.
    /// </param>
    /// <param name="SSL">
    /// The SSL object where the event occurred.
    /// </param>
    property OnDebugMessage: TOnDebugMessageEvent read FOnDebugMessage
      write FOnDebugMessage;
  published
    /// <summary>
    ///   Default Server Certificate to send to the client if a SNI (Server Name
    ///   Indicator) is not specified or if the <see
    ///   cref="TaurusTLS|TTaurusTLSServerIOHandler.Certificates" /> property
    ///   is empty.
    /// </summary>
    property DefaultCert: TTaurusTLSX509File read fDefaultCert;
    /// <summary>
    ///   Certificates for domains that the TLS Client may request from the
    ///   server through a SNI (Server Name Indicator).  Leave empty if you do
    ///   not wish to support SNI for virtual hosting.
    /// </summary>
    property Certificates: TTaurusTLSX509Files read fCertificates
      write SetCertificates;
    /// <summary>
    /// Properties that effect TLS.
    /// </summary>
    property SSLOptions: TTaurusTLSOptions read fSSLOptions write fSSLOptions;
    /// <summary>
    /// Occurs when TLS negotiation is concluded.
    /// </summary>
    /// <param name="ASender">
    /// The object that triggers the event.
    /// </param>
    property OnSSLNegotiated: TOnIOHandlerNotify read FOnSSLNegotiated
      write FOnSSLNegotiated;
    /// <summary>
    /// Occurs when there is a status message.
    /// </summary>
    /// <param name="ASender">
    /// The object that triggers the event.
    /// </param>
    /// <param name="AsslSocket">
    /// The PSSL value associated with the event.
    /// </param>
    /// <param name="AWhere">
    /// A set of bitmasks that indicate where the event was called
    /// </param>
    /// <param name="Aret">
    /// A value indicating a particular message
    /// </param>
    /// <param name="AType">
    /// The AWhere value represented as a string
    /// </param>
    /// <param name="AMsg">
    /// The Aret value represented as a string
    /// </param>
    property OnStatusInfo: TOnStatusEvent read FOnStatusInfo
      write FOnStatusInfo;
    /// <summary>
    /// Occurs when a password is required.
    /// </summary>
    /// <param name="ASender">
    /// The object that triggers the event.
    /// </param>
    /// <param name="VPassword">
    /// Return value indicating the password.
    /// </param>
    /// <param name="AIsWrite">
    /// True if the password is written/encrypted and typically the password
    /// is prompted for twice to prevent entry error.
    /// </param>
    /// <param name="VOk">
    /// Set this value to true if a password was retreived or false if password
    /// retreival failed (for example, the user clicked a cancel button).
    /// </param>
    property OnGetPassword: TOnGetPasswordEvent read fOnGetPassword
      write fOnGetPassword;
    /// <summary>
    /// Occurs when a connection attempt is made and allows you to accept or
    /// reject connection attempts based upon your own criteria.
    /// </summary>
    /// <param name="ASender">
    /// The object that triggers the event.
    /// </param>
    /// <param name="AsslSocket">
    /// The SSL socket where the event occurred.
    /// </param>
    /// <param name="ACtx">
    /// The SSL_CTX object where the event occurred.
    /// </param>
    /// <param name="op">
    /// The operation expressed as an integer. This is one of the SSL_SECOP_*
    /// values.
    /// </param>
    /// <param name="bits">
    /// Number of security bits the cipher has.
    /// </param>
    /// <param name="ACipherNid">
    /// The Numeric Identifier (NID) of the cipher.
    /// </param>
    /// <param name="ACipher">
    /// The name of the cipher.
    /// </param>
    /// <param name="VAccepted">
    /// Return true if you will accept the connection attempt.
    /// </param>
    property OnSecurityLevel: TOnSecurityLevelEvent read fOnSecurityLevel
      write fOnSecurityLevel;
    /// <summary>
    /// Occurs when a certificate is presented for validation.
    /// </summary>
    /// <param name="ASender">
    /// The object that triggers the event.
    /// </param>
    /// <param name="ACertificate">
    /// The certificate to be validated as a <see cref="TTaurusTLSX509" />
    /// </param>
    /// <param name="AError">
    /// The validation error if the certificate failed validation.
    /// </param>
    /// <param name="AMsg">
    /// The message string OpenSSL returned describing the failure breifly.
    /// </param>
    /// <param name="ADescr">
    /// A description of the failure in a long form for display to user in
    /// something such as a message-box.
    /// </param>
    /// <param name="VOk">
    /// Set to True if you wish the certificate to pass validation or False if
    /// you want it to fail validation.
    /// </param>
    property OnVerifyError: TOnVerifyErrorEvent read fOnVerifyError
      write fOnVerifyError;
    /// <summary>
    /// Occurs when a certificate in the TLS chain is being verified during the handshake.
    /// Use this event to inspect the intermediate result and current certificate
    /// and decide whether verification should continue.
    /// </summary>
    /// <param name="ASender">
    /// The object that triggers the event.
    /// </param>
    /// <param name="APreverify_ok">
    /// Indicates whether the certificate at the current depth passed internal OpenSSL verification so far.
    /// 1 = passed, 0 = failed.
    /// </param>
    /// <param name="ACertificate">
    /// The current certificate being verified, wrapped in a TTaurusTLSX509 helper for easier inspection.
    /// </param>
    /// <param name="ADepth">
    /// The position of the certificate in the chain, where 0 is the peer/leaf certificate.
    /// </param>
    /// <param name="AError">
    /// The OpenSSL error code associated with this certificate, if any.
    /// </param>
    /// <param name="AMsg">
    /// The OpenSSL error string corresponding to AError.
    /// </param>
    /// <param name="ADescr">
    /// A descriptive message suitable for logging or display.
    /// </param>
    /// <param name="VContinue">
    /// Set to False to immediately terminate verification with failure.
    /// Set to True to allow verification to proceed.
    /// </param>
    property OnVerifyCallback: TOnVerifyCallbackEvent read fOnVerifyCallback
      write fOnVerifyCallback;
  end;

  /// <summary>
  /// TLS Cipher information.
  /// </summary>
  TTaurusTLSCipher = class(TObject)
{$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} private
    fSSLSocket: TTaurusTLSSocket;
    fSSLCipher: PSSL_CIPHER;
    function GetSSLCipher: PSSL_CIPHER;
    function GetDescription: String;
    function GetName: String;
    function GetBits: Integer;
    function GetVersion: String;
  public
    /// <summary>
    /// Creates a new instance of TTaurusTLSCipher.
    /// </summary>
    /// <param name="AOwner">
    /// The TTaurusTLSSocket that owns the new instance.
    /// </param>
    constructor Create(AOwner: TTaurusTLSSocket);
    /// <summary>
    /// Frees resources and destroys the current instance.
    /// </summary>
    destructor Destroy; override;
    // These can't be published without a compiler warning.
    // published
    /// <summary>
    /// Description of cipher.
    /// </summary>
    property Description: String read GetDescription;
    /// <summary>
    /// Name of cipher.
    /// </summary>
    property Name: String read GetName;
    /// <summary>
    /// Number of bits in cipher.
    /// </summary>
    property bits: Integer read GetBits;
    /// <summary>
    /// Version of cipher.
    /// </summary>
    property Version: String read GetVersion;
  end;

  /// <summary>
  /// Raised if the OpenSSL library failed to load.
  /// </summary>
  ETaurusTLSCouldNotLoadSSLLibrary = class(ETaurusTLSError);
  /// <summary>
  /// Raised if the Mode property is sslmUnassigned when the GetSSLMethod is
  /// called.
  /// </summary>
  ETaurusTLSModeNotSet = class(ETaurusTLSError);
  /// <summary>
  /// Raised if the Session in TTaurusTLSSocket.GetProtocolVersion is nil.
  /// </summary>
  ETaurusTLSSessionCanNotBeNil = class(ETaurusTLSError);
  /// <summary>
  /// Raised if <c>SSL_SESSION_get_protocol_version</c> returned in invalid
  /// value.
  /// </summary>
  /// <seealso
  /// href="https://docs.openssl.org/3.0/man3/SSL_SESSION_get_protocol_version/">
  /// SSL_SESSION_get_protocol_version
  /// </seealso>
  ETaurusTLSInvalidSessionValue = class(ETaurusTLSError);

  /// <summary>
  /// Raised if <c>SSL_new</c> failed.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/SSL_new/">
  /// SSL_new
  /// </seealso>
  ETaurusTLSCreatingSessionError = class(ETaurusTLSError);
  /// <summary>
  /// Raised if <c>SSL_CTX_new_ex</c> failed.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/SSL_CTX_new/">
  /// SSL_CTX_new_ex
  /// </seealso>
  ETaurusTLSCreatingContextError = class(ETaurusTLSError);
  /// <summary>
  /// Raised if the Root Certificate files failed to load.
  /// </summary>
  ETaurusTLSLoadingRootCertError = class(ETaurusTLSError);
  /// <summary>
  /// Raised if the Certificate failed to load.
  /// </summary>
  ETaurusTLSLoadingCertError = class(ETaurusTLSError);
  /// <summary>
  /// Raised if the private key failed to load.
  /// </summary>
  ETaurusTLSLoadingKeyError = class(ETaurusTLSError);
  /// <summary>
  /// Raised if DH parameters file failed to load.
  /// </summary>
  ETaurusTLSLoadingDHParamsError = class(ETaurusTLSError);
  /// <summary>
  /// Raised if <c>SSL_CTX_set_cipher_list</c> failed.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/SSL_CTX_set_cipher_list/">
  /// SSL_CTX_set_cipher_list
  /// </seealso>
  ETaurusTLSSettingCipherError = class(ETaurusTLSError);

  /// <summary>
  /// Raised if <c>SSL_set_fd</c> failed.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/SSL_set_fd/">
  /// SSL_set_fd
  /// </seealso>
  ETaurusTLSFDSetError = class(ETaurusTLSAPISSLError);
  /// <summary>
  /// Raised if <c>SSL_set_app_data</c> failed.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/BIO_get_ex_new_index/">
  /// SSL_set_app_data
  /// </seealso>
  ETaurusTLSDataBindingError = class(ETaurusTLSAPISSLError);
  /// <summary>
  /// Raised if <c>SSL_accept</c> fails.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/SSL_accept/">
  /// SSL_accept
  /// </seealso>
  ETaurusTLSAcceptError = class(ETaurusTLSAPISSLError);
  /// <summary>
  /// Raised if the <c>SSL_Connect</c> fails.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/SSL_connect/">
  /// SSL_connect
  /// </seealso>
  ETaurusTLSConnectError = class(ETaurusTLSAPISSLError);
  /// <summary>
  /// Raised if certificate validation failed and the message breifly
  /// describes the failure.
  /// </summary>
  ETaurusTLSCertValidationError = class(ETaurusTLSError);
  /// <summary>
  /// Raised if <c>SSL_set_tlsext_host_name</c> failed.
  /// </summary>
  /// <seealso
  /// href="https://docs.openssl.org/master/man3/SSL_CTX_set_tlsext_servername_callback/#description">
  /// SSL_set_tlsext_host_name
  /// </seealso>
  ETaurusTLSSettingTLSHostNameError = class(ETaurusTLSAPISSLError);
  /// <summary>
  /// Raised if <c>SSL_CTX_set_min_proto_version</c> failed.
  /// </summary>
  /// <seealso
  /// href="https://docs.openssl.org/3.0/man3/SSL_CTX_set_min_proto_version/">
  /// SSL_CTX_set_max_proto_version
  /// </seealso>
  ETaurusTLSSettingMinProtocolError = class(ETaurusTLSError);
  /// <summary>
  /// Raised if <c>SSL_CTX_set_max_proto_version</c> failed.
  /// </summary>
  /// <seealso
  /// href="https://docs.openssl.org/3.0/man3/SSL_CTX_set_min_proto_version/">
  /// SSL_CTX_set_min_proto_version
  /// </seealso>
  ETaurusTLSSettingMaxProtocolError = class(ETaurusTLSError);
  /// <summary>
  /// Raised if <c>X509_STORE_add_cert</c> failed.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/master/man3/X509_STORE_add_cert/">
  /// X509_STORE_add_cert
  /// </seealso>
  ETaurusTLSCertNotAddedToStore = class(ETaurusTLSAPICryptoError);
  /// <summary>
  /// Raised if <c>SSL_copy_session_id</c> failed.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man7/ssl/">
  /// SSL_copy_session_id
  /// </seealso>
  ETaurusTLSSSLCopySessionId = class(ETaurusTLSError);
  /// <summary>
  /// Loads the OpenSSL libraries. This is ignored if OpenSSL is loaded by
  /// TaurusTLS statically.
  /// </summary>
  /// <returns>
  /// True if successful or False if it failed.
  /// </returns>
  /// <remarks>
  /// The OpenSSL library is only loaded once. If it is already loaded, True
  /// is returned. True is also returned if the library is statically loaded
  /// by TaurusTLS.
  /// </remarks>
function LoadOpenSSLLibrary: Boolean;
/// <summary>
/// Unloads the OpenSSL libaries. Called when the program terminates. Ignored
/// if TaurusTLS loaded the OpenSSL libraries statically.
/// </summary>
procedure UnLoadOpenSSLLibrary;

/// <summary>
/// The version of OpenSSL that was loaded.
/// </summary>
function OpenSSLVersion: string;
/// <summary>
/// The OpenSSL configuration directory.
/// </summary>
/// <returns>
/// The OpenSSL configuration directory. Do <b>NOT</b> assume that this is the directory
/// where the library is located. The library itslef is loaded based on the
/// operating system's defaults or the <see
/// cref="TaurusTLSLoader|GetOpenSSLLoader" />'s <see
/// cref="TaurusTLSLoader|IOpenSSLLoader.GetOpenSSLPath" /> property.
/// </returns>
function OpenSSLDir: string;   {$IFDEF USE_INLINE}inline; {$ENDIF}

/// <summary>
/// The default directory for OpenSSL dynamically loaded modules that are not engines.
/// </summary>
///  <returns>
///  The default directory for OpenSSL dynamically loaded modules that are not engines
///  or an empty string if this is not supported.
///  </returns>
function OpenSSLModulesDir : String;  {$IFDEF USE_INLINE}inline; {$ENDIF}
/// <summary>
/// The default directory for OpenSSL dynamically loaded engine modules.
/// </summary>
///  <returns>
///  he default directory for OpenSSL dynamically loaded engine modules or an
///  empty string if this is not supported.
///  </returns>
function OpenSSLEnginesDir : String; {$IFDEF USE_INLINE}inline; {$ENDIF}

implementation

uses
{$IFDEF HAS_UNIT_Generics_Collections}
  System.Generics.Collections,
{$ENDIF}
{$IFDEF USE_VCL_POSIX}
  Posix.SysTime,
  Posix.Time,
  Posix.Unistd,
{$ENDIF}
  IdFIPS,
  IdResourceStringsProtocols,
  TaurusTLS_ResourceStrings,
  IdStack,
  IdThreadSafe,
  IdCustomTransparentProxy,
{$IFDEF WINDOWS}
  IdIDN,
{$ENDIF}
  IdURI,
  SyncObjs,
  TaurusTLSHeaders_asn1,
  TaurusTLSHeaders_bn,
  TaurusTLSHeaders_x509_vfy,
  TaurusTLSHeaders_x509v3,
  TaurusTLSHeaders_pkcs12,
  TaurusTLSHeaders_sslerr,
  TaurusTLSHeaders_err,
  TaurusTLSHeaders_evp,
  TaurusTLSHeaders_bio,
  TaurusTLSHeaders_pem,
  TaurusTLSHeaders_stack,
  TaurusTLSHeaders_crypto,
  TaurusTLSHeaders_objects,
  TaurusTLSHeaders_x509,
  TaurusTLS_Files,
  TaurusTLSLoader;

type
  // TODO: TIdThreadSafeObjectList instead?
{$IFDEF HAS_GENERICS_TThreadList}
  TIdCriticalSectionThreadList = TThreadList<TIdCriticalSection>;
  TIdCriticalSectionList = TList<TIdCriticalSection>;
{$ELSE}
  // TODO: flesh out to match TThreadList<TIdCriticalSection> and TList<TIdCriticalSection> on non-Generics compilers
  TIdCriticalSectionThreadList = TThreadList;
  TIdCriticalSectionList = TList;
{$ENDIF}

var
  SSLIsLoaded: TIdThreadSafeBoolean = nil;
  LockInfoCB: TIdCriticalSection = nil;
  LockLevelCB: TIdCriticalSection = nil;
  LockPassCB: TIdCriticalSection = nil;
  LockVerifyCB: TIdCriticalSection = nil;
  Lock_SNI_CB: TIdCriticalSection = nil;
  CallbackLockList: TIdCriticalSectionThreadList = nil;

procedure GetStateVars(const SSLSocket: PSSL; const AWhere, Aret: TIdC_INT;
  out VTypeStr, VMsg: String);
{$IFDEF USE_INLINE}inline; {$ENDIF}
{$IFNDEF USE_INLINE_VAR}
var
  LState, LAlert: String;
{$ENDIF}
begin
{$IFDEF USE_INLINE_VAR}
  var
    LState, LAlert: String;
{$ENDIF}
  VTypeStr := '';
  VMsg := '';
  LState := AnsiStringToString(SSL_state_string_long(SSLSocket));
  LAlert := AnsiStringToString(SSL_alert_type_string_long(Aret));

  case AWhere of
    SSL_CB_ALERT:
      begin
        VTypeStr := IndyFormat(RSOSSLAlert, [SSL_alert_type_string_long(Aret)]);
        VMsg := LAlert;
      end;
    SSL_CB_READ_ALERT:
      begin
        VTypeStr := IndyFormat(RSOSSLReadAlert,
          [SSL_alert_type_string_long(Aret)]);
        VMsg := LAlert;
      end;
    SSL_CB_WRITE_ALERT:
      begin
        VTypeStr := IndyFormat(RSOSSLWriteAlert, [LAlert]);
        VMsg := AnsiStringToString(SSL_alert_desc_string_long(Aret));
      end;
    SSL_CB_ACCEPT_LOOP:
      begin
        VTypeStr := RSOSSLAcceptLoop;
        VMsg := LState;
      end;
    SSL_CB_ACCEPT_EXIT:
      begin
        if Aret < 0 then
        begin
          VTypeStr := RSOSSLAcceptError;
        end
        else
        begin
          if Aret = 0 then
          begin
            VTypeStr := RSOSSLAcceptFailed;
          end
          else
          begin
            VTypeStr := RSOSSLAcceptExit;
          end;
        end;
        VMsg := LState;
      end;
    SSL_CB_CONNECT_LOOP:
      begin
        VTypeStr := RSOSSLConnectLoop;
        VMsg := LState;
      end;
    SSL_CB_CONNECT_EXIT:
      begin
        if Aret < 0 then
        begin
          VTypeStr := RSOSSLConnectError;
        end
        else
        begin
          if Aret = 0 then
          begin
            VTypeStr := RSOSSLConnectFailed
          end
          else
          begin
            VTypeStr := RSOSSLConnectExit;
          end;
        end;
        VMsg := LState;
      end;
    SSL_CB_HANDSHAKE_START:
      begin
        VTypeStr := RSOSSLHandshakeStart;
        VMsg := LState;
      end;
    SSL_CB_HANDSHAKE_DONE:
      begin
        VTypeStr := RSOSSLHandshakeDone;
        VMsg := LState;
      end;
  end;
end;

{$I TaurusTLSUnusedParamOff.inc}

function g_VerifyCallback(const preverify_ok: TIdC_INT;
  x509_ctx: PX509_STORE_CTX): TIdC_INT cdecl;
var
  LErr: Integer;
  LSsl: PSSL;
  LSock: TTaurusTLSSocket;
  LContinue: Boolean;
  LX509_Cert: PX509;
  LCertificate: TTaurusTLSX509;
  LCertErr: TIdC_LONG;
{$IFNDEF USE_INLINE_VAR}
  LHelper: ITaurusTLSCallbackHelper;
{$ENDIF}
begin
  Result := 1;
  LContinue := True;
  // Preserve last error just in case TaurusTLS is using it and we do something that
  // clobers it.  CYA.
  LErr := GStack.WSGetLastError;
  try
    LSsl := X509_STORE_CTX_get_ex_data(x509_ctx,
      SSL_get_ex_data_X509_STORE_CTX_idx());
    if LSsl <> nil then
    begin
      LSock := TTaurusTLSSocket(SSL_get_app_data(LSsl));
      if LSock <> nil then
      begin
        LockVerifyCB.Enter;
        try
{$IFDEF USE_INLINE_VAR}
          var
            LHelper: ITaurusTLSCallbackHelper;
{$ENDIF}
          if Supports(LSock.Parent, ITaurusTLSCallbackHelper,
            IInterface(LHelper)) then
          begin
            LX509_Cert := X509_STORE_CTX_get_current_cert(x509_ctx);
            LCertErr := X509_STORE_CTX_get_error(x509_ctx);
            LCertificate := TTaurusTLSX509.Create(LX509_Cert, False);
            try
              LHelper.VerifyCallback(preverify_ok, LCertificate,
                X509_STORE_CTX_get_error_depth(x509_ctx), LCertErr,
                AnsiStringToString(X509_verify_cert_error_string(LCertErr)),
                CertErrorToLongDescr(LCertErr), LContinue);
            finally
              FreeAndNil(LCertificate);
            end;
            if not LContinue then
              Result := 0;
          end;
        finally
          LockVerifyCB.Leave;
        end;
      end;
    end;
  finally
    GStack.WSSetLastError(LErr);
  end;
end;

function g_SecurityLevelCallback(const s: PSSL; const ctx: PSSL_CTX;
  op: TIdC_INT; bits: TIdC_INT; nid: TIdC_INT; other: Pointer; ex: Pointer)
  : TIdC_INT; cdecl;
var
  LErr: Integer;
  LHelper: ITaurusTLSCallbackHelper;
  LRes: Boolean;

begin
  // Preserve last error just in case TaurusTLS is using it and we do something that
  // clobers it.  CYA.
  LErr := GStack.WSGetLastError;
  try
    LockLevelCB.Enter;
    try
      if Supports(TTaurusTLSContext(ex).Parent, ITaurusTLSCallbackHelper,
        IInterface(LHelper)) then
      begin
        LHelper.SecurityLevelCB(s, ctx, op, bits, nid, LRes);
      end
      else
      begin
        LRes := True;
      end;
      if LRes then
      begin
        Result := 1;
      end
      else
      begin
        Result := 0;
      end;
    finally
      LockLevelCB.Leave;
    end;
  finally
    GStack.WSSetLastError(LErr);
  end;
end;
{$I TaurusTLSUnusedParamOn.inc}

function g_PasswordCallback(buf: PIdAnsiChar; size: TIdC_INT; rwflag:
    TIdC_INT; userdata: Pointer): TIdC_INT; cdecl;
{$IFDEF USE_MARSHALLED_PTRS}
type
  TBytesPtr = ^TBytes;
{$ENDIF}
var
{$IFDEF STRING_IS_UNICODE}
{$IFNDEF USE_INLINE_VAR}
  LBPassword: TIdBytes;
{$ENDIF}
{$ELSE}
  LPassword: String;
{$ENDIF}
  LErr: Integer;
  LOk: Boolean;
  LHelper: ITaurusTLSCallbackHelper;
begin
  // Preserve last error just in case TaurusTLS is using it and we do something that
  // clobers it.  CYA.
  LErr := GStack.WSGetLastError;
  try
    LockPassCB.Enter;
    try
      FillChar(buf^, size, 0);
{$IFDEF USE_INLINE_VAR}
      var
        LBPassword: TIdBytes;
{$ENDIF}
      if Supports(TTaurusTLSContext(userdata).Parent, ITaurusTLSCallbackHelper,
        IInterface(LHelper)) then
      begin
{$IFDEF STRING_IS_UNICODE}
        LBPassword := IndyTextEncoding_OSDefault.GetBytes
          (LHelper.GetPassword(rwflag > 0, LOk));
        LHelper := nil;
        if Length(LBPassword) > 0 then
        begin
{$IFDEF USE_MARSHALLED_PTRS}
          TMarshal.Copy(TBytesPtr(@LBPassword)^, 0, TPtrWrapper.Create(buf),
            IndyMin(Length(LBPassword), size));
{$ELSE}
          Move(LBPassword[0], buf^, IndyMin(Length(LBPassword), size));
{$ENDIF}
        end;
        Result := Length(LBPassword);
{$ELSE}
{$IFDEF USE_INLINE_VAR}
        var
          LPassword: String;
{$ENDIF}
        LPassword := LHelper.GetPassword(rwflag > 0, LOk);
        LHelper := nil;
        StrPLCopy(buf, LPassword, size);
        Result := Length(LPassword);
{$ENDIF}
      end
      else
      begin
        LOk := False;
        Result := 0;
      end;
      buf[size - 1] := #0; // RLebeau: truncate the password if needed
      if not LOk then
      begin
        // indicate failure
        Result := -1;
      end;
    finally
      LockPassCB.Leave;
    end;
  finally
    GStack.WSSetLastError(LErr);
  end;
end;

procedure g_InfoCallback(const SSLSocket: PSSL; where, ret: TIdC_INT); cdecl;
var
  LErr: Integer;
  LHelper: ITaurusTLSCallbackHelper;
begin
  {
    You have to save the value of WSGetLastError as some Operating System API
    function calls will reset that value and we can't know what a programmer will
    do in this event.  We need the value of WSGetLastError so we can report
    an underlying socket error when the OpenSSL function returns.

    Keep LErr even if it is referenced once.
    JPM.
  }
  LErr := GStack.WSGetLastError;
  try
    LockInfoCB.Enter;
    try
      if Supports(TTaurusTLSSocket(SSL_get_app_data(SSLSocket)).Parent,
        ITaurusTLSCallbackHelper, LHelper) then
      begin
        LHelper.StatusInfo(SSLSocket, where, ret);
        LHelper := nil;
      end;
    finally
      LockInfoCB.Leave;
    end;
  finally
    GStack.WSSetLastError(LErr);
  end;
end;

procedure g_MsgCallback(write_p, Version, content_type: TIdC_INT; const buf;
  len: TIdC_SIZET; SSL: PSSL; arg: Pointer)cdecl;
var
  LErr: Integer;
  LHelper: ITaurusTLSCallbackHelper;
{$IFNDEF USE_INLINE_VAR}
  LBytes: TIdBytes;
{$ENDIF}
  LVer: TTaurusMsgCBVer;
begin
{$IFDEF fpc}
  LBytes := nil;
{$ENDIF}
  {
    You have to save the value of WSGetLastError as some Operating System API
    function calls will reset that value and we can't know what a programmer will
    do in this event.  We need the value of WSGetLastError so we can report
    an underlying socket error when the OpenSSL function returns.

    Keep LErr even if it is referenced once.
    JPM.
  }
  LErr := GStack.WSGetLastError;
  try
    LockVerifyCB.Enter;
    try
      if Supports(TTaurusTLSSocket(arg).Parent, ITaurusTLSCallbackHelper,
        IInterface(LHelper)) then
      begin
{$IFDEF USE_INLINE_VAR}
        var
          LBytes: TIdBytes;
{$ENDIF}
        LBytes := TaurusTLSRawToBytes(buf, len);
        case Version of
          SSL3_VERSION:
            LVer := verSSL3Header;
          TLS1_VERSION:
            LVer := verTLS1;
          TLS1_1_VERSION:
            LVer := verTLS1_1;
          TLS1_2_VERSION:
            LVer := verTLS1_2;
          TLS1_3_VERSION:
            LVer := verTLS1_3;
          DTLS1_VERSION:
            LVer := verDTLS1;
          DTLS1_2_VERSION:
            LVer := verDTLS1_2;
          DTLS1_BAD_VER:
            LVer := verDTLSBadVer;
          OSSL_QUIC1_VERSION:
            LVer := verQUIC;
        else
          LVer := verDTLSBadVer;
        end;
        LHelper.DoOnDebugMessage(write_p > 0, LVer, content_type, LBytes, SSL);
        LHelper := nil;
      end;
    finally
      LockVerifyCB.Leave;
    end;
  finally
    GStack.WSSetLastError(LErr);
  end;
end;

function g_tlsext_SNI_callback(SSL: PSSL; alert: PIdC_INT; arg: Pointer)
  : TIdC_INT; cdecl;
var
  LErr: Integer;
  i: Integer;
  LSSLIO: TTaurusTLSServerIOHandler;
  LX509: PX509;
{$IFNDEF USE_INLINE_VAR}
  LHostname: String;
  LBHost: TIdBytes;
{$ENDIF}
begin
  LErr := GStack.WSGetLastError;
  try
    // Default reply, do not acknowlege SNI and continue as if we didn't
    // receive a SNI.
    Result := SSL_TLSEXT_ERR_NOACK;
    Lock_SNI_CB.Enter;
    try
      if SSL <> nil then
      begin
        if arg <> nil then
        begin
          LSSLIO := TTaurusTLSServerIOHandler(arg);
{$IFDEF USE_INLINE_VAR}
          var
            LHostname: String;
{$ENDIF}
          LHostname := AnsiStringToString(SSL_get_servername(SSL,
            TLSEXT_NAMETYPE_host_name));
          if LHostname <> '' then
          begin
            // indicate a fatal alert for hostname not found.
            Result := SSL_TLSEXT_ERR_ALERT_FATAL;
{$IFDEF USE_INLINE_VAR}
            var
              LBHost: TIdBytes;
{$ENDIF}
            LBHost := ToBytes(LHostname);
            for i := 0 to LSSLIO.Certificates.Count - 1 do
            begin
              LX509 := LSSLIO.Certificates[i].x509;
              if X509_check_host(LX509, @LBHost[0], Length(LBHost), 0, nil) = 1
              then
              begin
                // switch certificate we send to the client and indicate success.
                SSL_set_SSL_CTX(SSL, LSSLIO.Certificates[i].ctx);
                Result := SSL_TLSEXT_ERR_OK;
                break;
              end;
            end;
            // try with the default cert if none was found.
            if Result <> SSL_TLSEXT_ERR_OK then
            begin
              LX509 := SSL_CTX_get0_certificate(LSSLIO.SSLContext.Context);
              if LX509 <> nil then
              begin
                if X509_check_host(LX509, @LBHost[0], Length(LBHost), 0, nil) = 1
                then
                begin
                  Result := SSL_TLSEXT_ERR_NOACK;
                end;
              end;
            end;
          end;
        end;
      end;
    finally
      Lock_SNI_CB.Leave;
    end;
  finally
    GStack.WSSetLastError(LErr);
  end;
end;

function TranslateInternalVerifyToSSL(Mode: TTaurusTLSVerifyModeSet): Integer;
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  Result := SSL_VERIFY_NONE;
  if sslvrfPeer in Mode then
  begin
    Result := Result or SSL_VERIFY_PEER;
    if sslvrfPostHandshake in Mode then
    begin
      Result := Result or SSL_VERIFY_POST_HANDSHAKE;
    end;
    if sslvrfFailIfNoPeerCert in Mode then
    begin
      Result := Result or SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    end;
    if sslvrfClientOnce in Mode then
    begin
      Result := Result or SSL_VERIFY_CLIENT_ONCE;
    end;
  end;

end;

{$IFDEF OPENSSL_SET_MEMORY_FUNCS}

function IdMalloc(num: UInt32): Pointer cdecl;
begin
  Result := AllocMem(num);
end;

function IdRealloc(address: Pointer; num: UInt32): Pointer cdecl;
begin
  Result := addr;
  ReallocMem(Result, num);
end;

procedure IdFree(address: Pointer)cdecl;
begin
  FreeMem(addr);
end;

procedure IdSslCryptoMallocInit;
// replaces the actual alloc routines
// this is useful if you are using a memory manager that can report on leaks
// at shutdown time.
var
  r: Integer;
begin
  r := CRYPTO_set_mem_functions(@IdMalloc, @IdRealloc, @IdFree);
  Assert(r <> 0);
end;
{$ENDIF}
{$IFNDEF WIN32_OR_WIN64}

procedure _threadid_func(id: PCRYPTO_THREADID)cdecl;
begin
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  if Assigned(CRYPTO_THREADID_set_numeric) then
{$ENDIF}
  begin
    CRYPTO_THREADID_set_numeric(id, TIdC_ULONG(CurrentThreadId));
  end;
end;

function _GetThreadID: TIdC_ULONG; cdecl;
begin
  // TODO: Verify how well this will work with fibers potentially running from
  // thread to thread or many on the same thread.
  Result := TIdC_ULONG(CurrentThreadId);
end;
{$ENDIF}
{$I TaurusTLSUnusedParamOff.inc}

procedure SslLockingCallback(Mode, n: TIdC_INT; Afile: PIdAnsiChar;
  line: TIdC_INT)cdecl;
var
  Lock: TIdCriticalSection;
  LList: TIdCriticalSectionList;
begin
  Assert(CallbackLockList <> nil);
  Lock := nil;

  LList := CallbackLockList.LockList;
  try
    if n < LList.Count then
    begin
      Lock := {$IFDEF HAS_GENERICS_TList}LList.Items[n]{$ELSE}TIdCriticalSection
        (LList.Items[n]){$ENDIF};
    end;
  finally
    CallbackLockList.UnlockList;
  end;
  Assert(Lock <> nil);
  if (Mode and CRYPTO_LOCK) = CRYPTO_LOCK then
  begin
    Lock.Acquire;
  end
  else
  begin
    Lock.Release;
  end;
end;
{$I TaurusTLSUnusedParamOn.inc}

procedure PrepareTaurusTLSLocking;
var
  i, cnt: Integer;
  Lock: TIdCriticalSection;
  LList: TIdCriticalSectionList;
begin
  LList := CallbackLockList.LockList;
  try
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    if Assigned(CRYPTO_num_locks) then
      cnt := CRYPTO_num_locks
    else
      cnt := 0;
{$ELSE}
    cnt := CRYPTO_num_locks;
{$ENDIF}
    for i := 0 to cnt - 1 do
    begin
      Lock := TIdCriticalSection.Create;
      try
        LList.Add(Lock);
      except
        Lock.Free;
        raise;
      end;
    end;
  finally
    CallbackLockList.UnlockList;
  end;
end;

{
  function RSACallback(sslSocket: PSSL; e: Integer; KeyLength: Integer):PRSA; cdecl;
  const
  RSA: PRSA = nil;
  var
  SSLSocket: TSSLWSocket;
  IdSSLSocket: TTaurusTLSSocket;
  begin
  IdSSLSocket := TTaurusTLSSocket(IdSslGetAppData(sslSocket));

  if Assigned(IdSSLSocket) then begin
  IdSSLSocket.TriggerSSLRSACallback(KeyLength);
  end;

  Result := RSA_generate_key(KeyLength, RSA_F4, @RSAProgressCallback, ssl);
  end;
}

function LoadOpenSSLLibrary: Boolean;
begin
  Assert(SSLIsLoaded <> nil);
  SSLIsLoaded.Lock;
  try
    if SSLIsLoaded.Value then
    begin
      Result := True;
      Exit;
    end;
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    Result := GetOpenSSLLoader.Load;
    if not Result then
      Exit;
{$ENDIF}
{$IFDEF OPENSSL_SET_MEMORY_FUNCS}
    // has to be done before anything that uses memory
    IdSslCryptoMallocInit;
{$ENDIF}
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS or
      OPENSSL_INIT_ADD_ALL_CIPHERS or OPENSSL_INIT_ADD_ALL_DIGESTS or
      OPENSSL_INIT_LOAD_CRYPTO_STRINGS or OPENSSL_INIT_LOAD_CONFIG or
      OPENSSL_INIT_ASYNC or OPENSSL_INIT_ENGINE_ALL_BUILTIN, nil);

    SSL_load_error_strings;
    // Create locking structures, we need them for callback routines
    Assert(LockInfoCB = nil);
    LockInfoCB := TIdCriticalSection.Create;
    LockLevelCB := TIdCriticalSection.Create;
    LockPassCB := TIdCriticalSection.Create;
    LockVerifyCB := TIdCriticalSection.Create;
    Lock_SNI_CB := TIdCriticalSection.Create;
    // Handle internal TaurusTLS locking
    CallbackLockList := TIdCriticalSectionThreadList.Create;
    PrepareTaurusTLSLocking;
    CRYPTO_set_locking_callback(@SslLockingCallback);
{$IFNDEF WIN32_OR_WIN64}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    if Assigned(CRYPTO_THREADID_set_callback) then
    begin
      CRYPTO_THREADID_set_callback(@_threadid_func);
    end
    else
    begin
      CRYPTO_set_id_callback(@_GetThreadID);
    end;
{$ELSE}
    CRYPTO_THREADID_set_callback(@_threadid_func);
{$ENDIF}
{$ENDIF}
    SSLIsLoaded.Value := True;
    Result := True;
  finally
    SSLIsLoaded.Unlock;
  end;

end;

procedure UnLoadOpenSSLLibrary;
{$IFNDEF USE_OBJECT_ARC}
var
  i: Integer;
  LList: TIdCriticalSectionList;
{$ENDIF}
begin
  SSLIsLoaded.Lock;
  try
    if SSLIsLoaded.Value then
    begin
      SSL_load_error_strings;
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
      if Assigned(CRYPTO_set_locking_callback) then
{$ENDIF}
        CRYPTO_set_locking_callback(nil);

      // <-- RLebeau: why is this here and not in IdSSLTaurusTLSHeaders.Unload()?
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
      GetOpenSSLLoader.Unload;
{$ENDIF}
      FreeAndNil(LockInfoCB);
      FreeAndNil(LockLevelCB);
      FreeAndNil(LockPassCB);
      FreeAndNil(LockVerifyCB);
      FreeAndNil(Lock_SNI_CB);
      if Assigned(CallbackLockList) then
      begin
{$IFDEF USE_OBJECT_ARC}
        CallbackLockList.Clear; // Items are auto-freed
{$ELSE}
        LList := CallbackLockList.LockList;

        begin
          try
            for i := 0 to LList.Count - 1 do
            begin
{$IFDEF HAS_GENERICS_TList}LList.Items[i]{$ELSE}TIdCriticalSection(LList.Items[i]){$ENDIF}.Free;
            end;
            LList.Clear;
          finally
            CallbackLockList.UnlockList;
          end;
        end;
{$ENDIF}
        FreeAndNil(CallbackLockList);
      end;
      SSLIsLoaded.Value := False;
    end;
  finally
    SSLIsLoaded.Unlock;
  end;
end;

function OpenSSLVersion: string;
begin
  Result := '';
  // RLebeau 9/7/2015: even if LoadOpenSSLLibrary() fails, _SSLeay_version()
  // might have been loaded OK before the failure occured. LoadOpenSSLLibrary()
  // does not unload ..
  if not LoadOpenSSLLibrary then
  begin
    // redundant but here to avoid PAL warning about functions called as procedures.
    Result := '';
  end;
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  if Assigned(SSLeay_version) then
  begin
{$ENDIF}
    Result := AnsiStringToString(SSLeay_version(SSLEAY_VERSION_CONST));
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  end;
{$ENDIF}
end;

function GetDirFromOpenSSLVerString(const AStr : String) : String;  {$IFDEF USE_INLINE}inline; {$ENDIF}
var i: Integer;
begin
  Result := AStr;
  { assumed format is 'OPENSSLDIR: "<dir>"' }
  i := Pos('"', Result);
  if i < 0 then
    Result := ''
  else
  begin
    Delete(Result, 1, i);
    i := Pos('"', Result);
    if i < 0 then
      Result := ''
    else
      Delete(Result, i, Length(Result) - i + 1);
  end;
end;

function OpenSSLEnginesDir : String;  {$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := '';
  if LoadOpenSSLLibrary then
  begin
    Result := AnsiStringToString(OPENSSL_info(OPENSSL_INFO_ENGINES_DIR));
    if Result = '' then
    begin
      Result := GetDirFromOpenSSLVerString(AnsiStringToString(SSLeay_version(OPENSSL_ENGINES_DIR)));
    end;
    {$IFDEF WINDOWS}
    Result := StringReplace(Result, '/','\',[rfReplaceAll]);
    {$ENDIF}
  end;
end;

function OpenSSLModulesDir : String;  {$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := '';
  if LoadOpenSSLLibrary then
  begin
    Result := AnsiStringToString(OPENSSL_info(OPENSSL_INFO_MODULES_DIR));
    {$IFDEF WINDOWS}
    Result := StringReplace(Result, '/','\',[rfReplaceAll]);
    {$ENDIF}
  end;
end;

function OpenSSLDir: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := '';
  if LoadOpenSSLLibrary then
  begin
    Result :=  AnsiStringToString(OPENSSL_info(OPENSSL_INFO_CONFIG_DIR));
    if Result = '' then
    begin
      Result := GetDirFromOpenSSLVerString(AnsiStringToString(SSLeay_version(OPENSSL_DIR)));
    end;
    {$IFDEF WINDOWS}
    Result := StringReplace(Result, '/','\',[rfReplaceAll]);
    {$ENDIF}
  end;
end;

{ TTaurusTLSX509File }

procedure TTaurusTLSX509File.AssignTo(Destination: TPersistent);
var
  LDest: TTaurusTLSX509File;
begin
  if Destination is TTaurusTLSX509File then
  begin
    LDest := Destination as TTaurusTLSX509File;
    LDest.PrivateKey := FPrivateKey;
    LDest.PublicKey := FPublicKey;
    LDest.RootKey := FRootKey;
    LDest.DHParamsFile := fDHParamsFile;
  end
  else
  begin
    inherited;
  end;
end;

constructor TTaurusTLSX509File.Create(Collection: TCollection);
begin
  inherited;
  fContext := nil;
end;

destructor TTaurusTLSX509File.Destroy;
begin
  FreeAndNil(fContext);
  inherited;
end;

function TTaurusTLSX509File.GetX509: PX509;
var
  LCtx: PSSL_CTX;
begin
  LCtx := ctx;
  if Assigned(LCtx) then
  begin
    Result := SSL_CTX_get0_certificate(LCtx);
  end
  else
  begin
    Result := nil;
  end;
end;

function TTaurusTLSX509File.GetCtx: PSSL_CTX;
begin
  Result := nil;
  if Assigned(fContext) then
  begin
    Result := fContext.Context;
  end;
end;

{ TTaurusTLSX509Files }

function TTaurusTLSX509Files.AddX509File: TTaurusTLSX509File;
begin
  Result := TTaurusTLSX509File(inherited Add);
end;

constructor TTaurusTLSX509Files.Create(AOwner: TPersistent);
begin
  inherited Create(AOwner, TTaurusTLSX509File);
end;

function TTaurusTLSX509Files.GetX509FilesItem(Index: Integer): TTaurusTLSX509File;
begin
  Result := TTaurusTLSX509File(inherited GetItem(Index));
end;

procedure TTaurusTLSX509Files.SetX509FilesItem(Index: Integer;
  const Value: TTaurusTLSX509File);
begin
  inherited SetItem(Index, Value);
end;

/// ///////////////////////////////////////////////////
// TTaurusTLSOptions
/// ////////////////////////////////////////////////////

constructor TTaurusTLSOptions.Create;
begin
  inherited Create;
  fMinTLSVersion := DEF_MIN_TLSVERSION;
  fUseSystemRootCACertificateStore := True;
  FSecurityLevel := DEF_SECURITY_LEVEL;
  fVerifyDepth := DEFAULT_VERIFY_DEPTH;
  fVerifyHostname := DEF_VERIFY_HOSTNAME;
end;

procedure TTaurusTLSOptions.SetMinTLSVersion(const AValue
  : TTaurusTLSSSLVersion);
begin
  fMinTLSVersion := AValue;
end;

procedure TTaurusTLSOptions.SetSecurityLevel(const AValue
  : TTaurusTLSSecurityLevel);
begin
  FSecurityLevel := AValue;
end;

procedure TTaurusTLSOptions.AssignTo(Destination: TPersistent);
var
  LDest: TTaurusTLSOptions;
begin
  if Destination is TTaurusTLSOptions then
  begin
    LDest := TTaurusTLSOptions(Destination);
    LDest.SecurityLevel := SecurityLevel;
    LDest.MinTLSVersion := MinTLSVersion;
    LDest.Mode := Mode;
    LDest.VerifyMode := VerifyMode;
    LDest.VerifyDepth := VerifyDepth;
    LDest.VerifyHostname := VerifyHostname;
    LDest.fUseSystemRootCACertificateStore := fUseSystemRootCACertificateStore;
    LDest.VerifyDirs := VerifyDirs;
    LDest.CipherList := CipherList;
  end
  else
  begin
    inherited AssignTo(Destination);
  end;
end;

{ TTaurusTLSServerIOHandler }

procedure TTaurusTLSServerIOHandler.InitComponent;
begin
  inherited InitComponent;
  fSSLOptions := TTaurusTLSOptions.Create(Self);
  fSSLOptions.Parent := Self;
  fDefaultCert := TTaurusTLSX509File.Create(nil);
  fCertificates := TTaurusTLSX509Files.Create(Self);
end;

destructor TTaurusTLSServerIOHandler.Destroy;
begin
  FreeAndNil(fCertificates);
  FreeAndNil(fDefaultCert);
  FreeAndNil(fSSLOptions);
  inherited Destroy;
end;

procedure TTaurusTLSServerIOHandler.DoOnDebugMessage(const AWrite: Boolean;
  AVersion: TTaurusMsgCBVer; AContentType: TIdC_INT; const buf: TIdBytes;
  SSL: PSSL);
begin
  if Assigned(FOnDebugMessage) then
  begin
    FOnDebugMessage(Self, AWrite, AVersion, AContentType, buf, SSL);
  end;
end;

procedure TTaurusTLSServerIOHandler.InitCertContexts;
var
  i: Integer;
  LContext: TTaurusTLSContext;
  LCertificate: TTaurusTLSX509File;
begin
  for i := 0 to Certificates.Count - 1 do
  begin
    LCertificate := Certificates[i];
    LContext := TTaurusTLSContext.Create;
    LContext.Parent := Self;
    LContext.PrivateKey := LCertificate.PrivateKey;
    LContext.PublicKey := LCertificate.PublicKey;
    LContext.RootPublicKey := LCertificate.RootKey;
    LContext.DHParamsFile := LCertificate.DHParamsFile;
    LCertificate.Context := LContext;
    LContext.VerifyDepth := SSLOptions.VerifyDepth;
    LContext.VerifyMode := SSLOptions.VerifyMode;
    LContext.UseSystemRootCACertificateStore :=
      SSLOptions.UseSystemRootCACertificateStore;
    LContext.VerifyHostname := SSLOptions.VerifyHostname;
    LContext.CipherList := SSLOptions.CipherList;
    LContext.VerifyOn := Assigned(fOnVerifyCallback);
    LContext.StatusInfoOn := Assigned(FOnStatusInfo);
    LContext.SecurityLevelCBOn := Assigned(fOnSecurityLevel);
    LContext.MessageCBOn := Assigned(FOnDebugMessage);
    LContext.MinTLSVersion := SSLOptions.MinTLSVersion;
    LContext.Mode := SSLOptions.Mode;
    LContext.SecurityLevel := SSLOptions.SecurityLevel;
    LContext.InitContext(sslCtxServer);
  end;
end;

procedure TTaurusTLSServerIOHandler.Init;
// see also TTaurusTLSIOHandlerSocket.Init
begin
  // ensure Init isn't called twice
  Assert(fSSLContext = nil);
  fSSLContext := TTaurusTLSContext.Create;
  fSSLContext.Parent := Self;
  fSSLContext.RootPublicKey := DefaultCert.RootKey;
  fSSLContext.PublicKey := DefaultCert.PublicKey;
  fSSLContext.PrivateKey := DefaultCert.PrivateKey;
  fSSLContext.DHParamsFile := DefaultCert.DHParamsFile;
  fSSLContext.VerifyDepth := SSLOptions.VerifyDepth;
  fSSLContext.VerifyMode := SSLOptions.VerifyMode;
  // fSSLContext.fVerifyFile := SSLOptions.fVerifyFile;
  fSSLContext.UseSystemRootCACertificateStore :=
    SSLOptions.UseSystemRootCACertificateStore;
  fSSLContext.VerifyDirs := SSLOptions.VerifyDirs;
  fSSLContext.VerifyHostname := SSLOptions.VerifyHostname;
  fSSLContext.CipherList := SSLOptions.CipherList;
  fSSLContext.VerifyOn := Assigned(fOnVerifyCallback);
  fSSLContext.StatusInfoOn := Assigned(FOnStatusInfo);
  fSSLContext.SecurityLevelCBOn := Assigned(fOnSecurityLevel);
  fSSLContext.MessageCBOn := Assigned(FOnDebugMessage);
  // fSSLContext.PasswordRoutineOn := Assigned(fOnGetPassword);
  fSSLContext.MinTLSVersion := SSLOptions.MinTLSVersion;
  fSSLContext.Mode := SSLOptions.Mode;
  fSSLContext.SecurityLevel := SSLOptions.SecurityLevel;
  fSSLContext.InitContext(sslCtxServer);
  // This must be after the Context is initialized so it does not AV.
  // It avs if the Context property is nil.
  if Certificates.Count > 0 then
  begin
    SSL_CTX_set_tlsext_servername_callback(fSSLContext.Context,
      g_tlsext_SNI_callback);
    SSL_CTX_set_tlsext_servername_arg(fSSLContext.Context, Self);
    InitCertContexts;
  end;
end;

{$I TaurusTLSUnusedParamOff.inc}

function TTaurusTLSServerIOHandler.Accept(ASocket: TIdSocketHandle;
  // This is a thread and not a yarn. Its the listener thread.
  AListenerThread: TIdThread; AYarn: TIdYarn): TIdIOHandler;
var
  LIO: TTaurusTLSIOHandlerSocket;
begin
  // using a custom scheduler, AYarn may be nil, so don't assert
  Assert(ASocket <> nil);
  Assert(fSSLContext <> nil);
  Assert(AListenerThread <> nil);

  Result := nil;
  LIO := TTaurusTLSIOHandlerSocket.Create(nil);
  try
    LIO.PassThrough := True;
    LIO.Open;
    while not AListenerThread.Stopped do
    begin
      if ASocket.Select(250) then
      begin
        if (not AListenerThread.Stopped) and LIO.Binding.Accept(ASocket.Handle)
        then
        begin
          LIO.SSLOptions.Assign(fSSLOptions);
          LIO.IsPeer := True;
          LIO.SSLSocket := TTaurusTLSSocket.Create(Self);
          LIO.SSLSocket.VerifyHostname := SSLOptions.VerifyHostname;
          LIO.SSLContext := fSSLContext;
          // TODO: to enable server-side SNI, we need to:
          // - Set up an additional SSL_CTX for each different certificate;
          // - Add a servername callback to each SSL_CTX using SSL_CTX_set_tlsext_servername_callback();
          // - In the callback, retrieve the client-supplied servername with
          // SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name). Figure out the right
          // SSL_CTX to go with that host name, then switch the SSL object to that
          // SSL_CTX with SSL_set_SSL_CTX().

          // RLebeau 2/1/2022: note, the following call is basically a no-op for TaurusTLS,
          // because PassThrough=True and fSSLContext are both assigned above, so there
          // is really nothing for TTaurusTLSIOHandlerSocket.Init() or
          // TTaurusTLSIOHandlerSocket.StartSSL() to do when called by
          // TTaurusTLSIOHandlerSocket.AfterAccept().  If anything, all this will
          // really do is update the Binding's IPVersion.  But, calling this is consistent
          // with other server Accept() implementations, so we should do it here, too...
          LIO.AfterAccept;

          Result := LIO;
          LIO := nil;
          break;
        end;
      end;
    end;
  finally
    FreeAndNil(LIO);
  end;
end;
{$I TaurusTLSUnusedParamOn.inc}

function TTaurusTLSServerIOHandler.MakeDataChannelIOHandler
  : TTaurusTLSIOHandlerSocket;

begin
  Result := TTaurusTLSIOHandlerSocket.Create(nil);
  try
    Result.PassThrough := True;
    Result.OnGetPassword := fOnGetPassword;
    Result.OnDebugMessage := FOnDebugMessage;
    Result.OnStatusInfo := FOnStatusInfo;
    Result.OnSSLNegotiated := FOnSSLNegotiated;
    Result.OnSecurityLevel := fOnSecurityLevel;
    Result.IsPeer := True; // RLebeau 1/24/2019: is this still needed now?
    Result.SSLOptions.Assign(SSLOptions);
  except
    Result.Free;
    raise;
  end;

end;

function TTaurusTLSServerIOHandler.MakeFTPSvrPasv: TIdSSLIOHandlerSocketBase;
var
  LIO: TTaurusTLSIOHandlerSocket;
begin
  LIO := MakeDataChannelIOHandler;
  if Assigned(LIO) then
  begin
    LIO.SSLOptions.Mode := sslmServer;
    LIO.SSLContext := SSLContext;
  end;
  Result := LIO;
end;

function TTaurusTLSServerIOHandler.MakeFTPSvrPort: TIdSSLIOHandlerSocketBase;
var
  LIO: TTaurusTLSIOHandlerSocket;
begin
  LIO := MakeDataChannelIOHandler;
  if Assigned(LIO) then
  begin
    LIO.SSLOptions.Mode := sslmClient; { doesn't really matter }
    LIO.SSLContext := SSLContext;
  end;
  Result := LIO;
end;

procedure TTaurusTLSServerIOHandler.Shutdown;
begin
  FreeAndNil(fSSLContext);
  inherited Shutdown;
end;

{ ITaurusTLSCallbackHelper }

function TTaurusTLSServerIOHandler.GetPassword(const AIsWrite: Boolean;
  out VOk: Boolean): string;
begin
  Result := '';
  VOk := False;
  if Assigned(fOnGetPassword) then
  begin
    fOnGetPassword(Self, Result, AIsWrite, VOk);
  end;
end;

procedure TTaurusTLSServerIOHandler.StatusInfo(const AsslSocket: PSSL;
  AWhere, Aret: TIdC_INT);
{$IFNDEF USE_INLINE_VAR}
var
  LType, LMsg: string;
{$ENDIF}
begin
  if Assigned(FOnStatusInfo) then
  begin
{$IFDEF USE_INLINE_VAR}
    var
      LType, LMsg: string;
{$ENDIF}
    GetStateVars(AsslSocket, AWhere, Aret, LType, LMsg);
    FOnStatusInfo(Self, AsslSocket, AWhere, Aret, LType, LMsg);
  end;
end;

procedure TTaurusTLSServerIOHandler.VerifyCallback(const APreverify_ok
  : TIdC_INT; ACertificate: TTaurusTLSX509; const ADepth: Integer;
  const AError: TIdC_LONG; const AMsg, ADescr: String; var VContinue: Boolean);
begin
  if Assigned(fOnVerifyCallback) then
  begin
    fOnVerifyCallback(Self, APreverify_ok, ACertificate, ADepth, AError, AMsg,
      ADescr, VContinue);
  end;
end;

function TTaurusTLSServerIOHandler.VerifyError(ACertificate: TTaurusTLSX509;
  const AError: TIdC_LONG): Boolean;
begin
  Result := False;
  if Assigned(fOnVerifyError) then
  begin
    fOnVerifyError(Self, ACertificate, AError,
      AnsiStringToString(X509_verify_cert_error_string(AError)),
      CertErrorToLongDescr(AError), Result);
  end;
end;

procedure TTaurusTLSServerIOHandler.SecurityLevelCB(const AsslSocket: PSSL;
  ACtx: PSSL_CTX; const op, bits: TIdC_INT; const ACipherNid: TIdC_INT;
  out VAccepted: Boolean);
begin
  VAccepted := False;
  if Assigned(fOnSecurityLevel) then
  begin
    fOnSecurityLevel(Self, AsslSocket, ACtx, op, bits, ACipherNid,
      AnsiStringToString(OBJ_nid2ln(ACipherNid)), VAccepted);
  end;

end;

procedure TTaurusTLSServerIOHandler.SetCertificates(const AValue
  : TTaurusTLSX509Files);
begin
  fCertificates.Assign(AValue);
end;

function TTaurusTLSServerIOHandler.GetIOHandlerSelf: TTaurusTLSIOHandlerSocket;
begin
  Result := nil;
end;

/// ////////////////////////////////////////////////////
// TTaurusTLSIOHandlerSocket
/// ////////////////////////////////////////////////////

function TTaurusTLSServerIOHandler.MakeClientIOHandler
  : TIdSSLIOHandlerSocketBase;
var
  LIO: TTaurusTLSIOHandlerSocket;
begin
  LIO := TTaurusTLSIOHandlerSocket.Create(nil);
  try
    LIO.PassThrough := True;
    // LIO.SSLOptions.Free;
    // LIO.SSLOptions := SSLOptions;
    // LIO.SSLContext := SSLContext;
    LIO.SSLOptions.Assign(SSLOptions);
    // LIO.SSLContext := SSLContext;
    LIO.SSLContext := nil;
    // SSLContext.Clone; // BGO: clone does not work, it must be either NIL, or SSLContext
    LIO.OnGetPassword := fOnGetPassword;
  except
    LIO.Free;
    raise;
  end;
  Result := LIO;
end;

{ TTaurusTLSIOHandlerSocket }

procedure TTaurusTLSIOHandlerSocket.InitComponent;
begin
  inherited InitComponent;
  IsPeer := False;
  fSSLOptions := TTaurusTLSOptions.Create(Self);
  fSSLOptions.Parent := Self;
  fClientCert := TTaurusTLSX509File.Create(nil);
  // fSSLLayerClosed := true;
  fSSLContext := nil;
  fHostname := '';
end;

destructor TTaurusTLSIOHandlerSocket.Destroy;
begin
  FreeAndNil(fClientCert);
  FreeAndNil(fSSLSocket);
  // we do not destroy these if their Parent is not Self
  // because these do not belong to us when we are in a server.
  if (fSSLContext <> nil) and (fSSLContext.Parent = Self) then
  begin
    FreeAndNil(fSSLContext);
  end;
  if (fSSLOptions <> nil) and (fSSLOptions.Parent = Self) then
  begin
    FreeAndNil(fSSLOptions);
  end;
  inherited Destroy;
end;

procedure TTaurusTLSIOHandlerSocket.ConnectClient;
var
  LPassThrough: Boolean;
begin
  // RLebeau: initialize TaurusTLS before connecting the socket...
  try
    Init;
  except
    on ETaurusTLSCouldNotLoadSSLLibrary do
    begin
      if not PassThrough then
        raise;
    end;
  end;
  // RLebeau 1/11/07: In case a proxy is being used, pass through
  // any data from the base class unencrypted when setting up that
  // connection.  We should do this anyway since SSL hasn't been
  // negotiated yet!
  // Save LPassThrough instead of "fixing" the "Local variable is referenced
  // only once" warning.
  LPassThrough := fPassThrough;
  fPassThrough := True;
  try
    inherited ConnectClient;
  finally
    fPassThrough := LPassThrough;
  end;
  if Assigned(fOnBeforeConnect) then
  begin
    fOnBeforeConnect(Self);
  end;
  // CreateSSLContext(sslmClient);
  // CreateSSLContext(SSLOptions.fMode);
  StartSSL;
end;

procedure TTaurusTLSIOHandlerSocket.StartSSL;
begin
  if not PassThrough then
  begin
    OpenEncodedConnection;
  end;
end;

procedure TTaurusTLSIOHandlerSocket.Close;
begin
  FreeAndNil(fSSLSocket);
  if fSSLContext <> nil then
  begin
    if fSSLContext.Parent = Self then
    begin
      FreeAndNil(fSSLContext);
    end
    else
    begin
      fSSLContext := nil;
    end;
  end;
  fHostname := '';
  inherited Close;
end;

procedure TTaurusTLSIOHandlerSocket.Open;
begin
  FOpened := False;
  inherited Open;
end;

function TTaurusTLSIOHandlerSocket.Readable
  (AMSec: Integer = IdTimeoutDefault): Boolean;
//From Tony WHyman - IndySecOpenSSL
begin
  repeat
    {Wait for data ready - or timer expiry}
    Result := inherited Readable(AMSec);
    {If the inherited Readable returns false then we have a timeout.
     Otherwise data is present but could be application or non-application data}
    if not Result then
      Exit;

    if (not fPassThrough) and (fSSLSocket <> nil) then
      Result := fSSLSocket.Readable in [sslDataAvailable,sslUnRecoverableError,sslEOF];
  until Result;
end;

procedure TTaurusTLSIOHandlerSocket.SetPassThrough(const Value: Boolean);
begin
  if fPassThrough <> Value then
  begin
    if not Value then
    begin
      if BindingAllocated then
      begin
        if Assigned(fSSLContext) then
        begin
          OpenEncodedConnection;
        end
        else
        begin
          raise ETaurusTLSCouldNotLoadSSLLibrary.Create
            (RSOSSLCouldNotLoadSSLLibrary);
        end;
      end;
    end
    else
    begin
      // RLebeau 8/16/2019: need to call SSL_shutdown() here if the SSL/TLS session is active.
      // This is for FTP when handling CCC and REIN commands. The SSL/TLS session needs to be
      // shutdown cleanly on both ends without closing the underlying socket connection because
      // it is going to be used for continued unsecure communications!
      if (fSSLSocket <> nil) and (fSSLSocket.SSL <> nil) then
      begin
        // if SSL_shutdown() returns 0, a "close notify" was sent to the peer and SSL_shutdown()
        // needs to be called again to receive the peer's "close notify" in response...
        if SSL_shutdown(fSSLSocket.SSL) = 0 then
        begin
          SSL_shutdown(fSSLSocket.SSL);
        end;
      end;
{$IFDEF WIN32_OR_WIN64}
      // begin bug fix
      if BindingAllocated and IndyCheckWindowsVersion(6) then
      begin
        // disables Vista+ SSL_Read and SSL_Write timeout fix
        Binding.SetSockOpt(Id_SOL_SOCKET, Id_SO_RCVTIMEO, 0);
        Binding.SetSockOpt(Id_SOL_SOCKET, Id_SO_SNDTIMEO, 0);
      end;
      // end bug fix
{$ENDIF}
    end;
    fPassThrough := Value;
  end;
end;

function TTaurusTLSIOHandlerSocket.RecvEnc(var VBuffer: TIdBytes): Integer;
begin
  Result := fSSLSocket.Recv(VBuffer);
end;

procedure TTaurusTLSIOHandlerSocket.SecurityLevelCB(const AsslSocket: PSSL;
  ACtx: PSSL_CTX; const op, bits: TIdC_INT; const ACipherNid: TIdC_INT;
  out VAccepted: Boolean);
begin
  VAccepted := False;
  if Assigned(fOnSecurityLevel) then
  begin
    fOnSecurityLevel(Self, AsslSocket, ACtx, op, bits, ACipherNid,
      AnsiStringToString(OBJ_nid2ln(ACipherNid)), VAccepted);
  end;
end;

function TTaurusTLSIOHandlerSocket.SendEnc(const ABuffer: TIdBytes;
  const AOffset, ALength: Integer): Integer;
begin
  // This can not be altered because it inherits from Indy.
  Result := fSSLSocket.Send(ABuffer, AOffset, ALength);
end;

procedure TTaurusTLSIOHandlerSocket.AfterAccept;
begin
  try
    inherited AfterAccept;
    // RLebeau: initialize TaurusTLS after accepting a client socket...
    try
      Init;
    except
      on ETaurusTLSCouldNotLoadSSLLibrary do
      begin
        if not PassThrough then
          raise;
      end;
    end;
    StartSSL;
  except
    Close;
    raise;
  end;
end;

procedure TTaurusTLSIOHandlerSocket.Init;
// see also TTaurusTLSServerIOHandler.Init
begin
  if not Assigned(fSSLContext) then
  begin
    fSSLContext := TTaurusTLSContext.Create;
    fSSLContext.Parent := Self;
    fSSLContext.PublicKey := ClientCert.PublicKey;
    fSSLContext.PrivateKey := ClientCert.PrivateKey;
    fSSLContext.RootPublicKey := ClientCert.RootKey;
    fSSLContext.DHParamsFile := ClientCert.DHParamsFile;
    fSSLContext.VerifyDepth := SSLOptions.VerifyDepth;
    fSSLContext.VerifyMode := SSLOptions.VerifyMode;
    fSSLContext.VerifyHostname := SSLOptions.VerifyHostname;
    // fSSLContext.fVerifyFile := SSLOptions.fVerifyFile;
    fSSLContext.UseSystemRootCACertificateStore :=
      SSLOptions.UseSystemRootCACertificateStore;
    fSSLContext.VerifyDirs := SSLOptions.VerifyDirs;
    fSSLContext.CipherList := SSLOptions.CipherList;
    fSSLContext.VerifyOn := Assigned(fOnVerifyCallback);
    fSSLContext.StatusInfoOn := Assigned(FOnStatusInfo);
    fSSLContext.SecurityLevelCBOn := Assigned(fOnSecurityLevel);
    fSSLContext.MessageCBOn := Assigned(FOnDebugMessage);

    // fSSLContext.PasswordRoutineOn := Assigned(fOnGetPassword);
    fSSLContext.MinTLSVersion := SSLOptions.MinTLSVersion;
    fSSLContext.Mode := SSLOptions.Mode;
    fSSLContext.SecurityLevel := SSLOptions.SecurityLevel;
    fSSLContext.InitContext(sslCtxClient);
  end;
end;

procedure TTaurusTLSIOHandlerSocket.DoOnDebugMessage(const AWrite: Boolean;
  AVersion: TTaurusMsgCBVer; AContentType: TIdC_INT; const buf: TIdBytes;
  SSL: PSSL);
begin
  if Assigned(FOnDebugMessage) then
  begin
    FOnDebugMessage(Self, AWrite, AVersion, AContentType, buf, SSL);
  end;
end;
// }

procedure TTaurusTLSIOHandlerSocket.DoVerifyError(Certificate: TTaurusTLSX509;
  const AError: TIdC_LONG; out VOk: Boolean);
begin
  VOk := True;
  if Assigned(fOnVerifyError) then
  begin
    fOnVerifyError(Self, Certificate, AError,
      AnsiStringToString(X509_verify_cert_error_string(AError)),
      CertErrorToLongDescr(AError), VOk);
  end;
end;

procedure TTaurusTLSIOHandlerSocket.OpenEncodedConnection;
var
{$IFDEF WIN32_OR_WIN64}
  LTimeout: Integer;
{$ENDIF}
  LMode: TTaurusTLSSSLMode;

begin
  Assert(Binding <> nil);
  if not Assigned(fSSLSocket) then
  begin
    fSSLSocket := TTaurusTLSSocket.Create(Self);
    fSSLSocket.VerifyHostname := SSLOptions.VerifyHostname;
  end;
  Assert(fSSLSocket.SSLContext = nil);
  fSSLSocket.SSLContext := fSSLContext;
{$IFDEF WIN32_OR_WIN64}
  // begin bug fix
  if IndyCheckWindowsVersion(6) then
  begin
    // Note: Fix needed to allow SSL_Read and SSL_Write to timeout under
    // Vista+ when connection is dropped
    LTimeout := FReadTimeOut;
    if LTimeout <= 0 then
    begin
      LTimeout := 30000; // 30 seconds
    end;
    Binding.SetSockOpt(Id_SOL_SOCKET, Id_SO_RCVTIMEO, LTimeout);
    Binding.SetSockOpt(Id_SOL_SOCKET, Id_SO_SNDTIMEO, LTimeout);
  end;
  // end bug fix
{$ENDIF}
  // RLebeau 7/2/2015: do not rely on IsPeer to decide whether to call Connect()
  // or Accept(). SSLContext.Mode controls whether a client or server method is
  // used to handle the connection, so that same value should be used here as well.
  // A user encountered a scenario where he needed to connect a TIdTCPClient to a
  // TCP server on a hardware device, but run the client's SSLIOHandler as an SSL
  // server because the device was initiating the SSL handshake as an SSL client.
  // IsPeer was not designed to handle that scenario.  Setting IsPeer to True
  // allowed Accept() to be called here, but at the cost of causing memory leaks
  // in TTaurusTLSIOHandlerSocket.Destroy() and TTaurusTLSIOHandlerSocket.Close()
  // in client components!  IsPeer is intended to be set to True only in server
  // components...
  LMode := fSSLContext.Mode;
  if not(LMode in [sslmClient, sslmServer]) then
  begin
    // Mode must be sslmBoth (or else TTaurusTLSContext.GetSSLMethod() would have
    // raised an exception), so just fall back to previous behavior for now,
    // until we can figure out a better way to handle this scenario...
    if IsPeer then
    begin
      LMode := sslmServer;
    end
    else
    begin
      LMode := sslmClient;
    end;
  end;
  if LMode = sslmClient then
  begin
    if fHostname = '' then
    begin
      fHostname := TaurusGetURIHost;
      if fHostname = '' then
      begin
        fHostname := TaurusGetProxyTargetHost;
        if fHostname = '' then
        begin
          fHostname := Host;
        end;
      end;
    end;
    fSSLSocket.HostName := fHostName;
    fSSLSocket.Connect(Binding.Handle);
  end
  else
  begin
    fSSLSocket.HostName := '';
    fSSLSocket.Accept(Binding.Handle);
  end;
  if Assigned(FOnSSLNegotiated) then
  begin
    FOnSSLNegotiated(Self);
  end;
  fPassThrough := False;
end;

// TODO: add an AOwner parameter
function TTaurusTLSIOHandlerSocket.Clone: TIdSSLIOHandlerSocketBase;
var
  LIO: TTaurusTLSIOHandlerSocket;
begin
  LIO := TTaurusTLSIOHandlerSocket.Create(nil);
  try
    LIO.fHostname := fHostname;
    LIO.SSLOptions.Assign(SSLOptions);
    LIO.OnStatusInfo := FOnStatusInfo;
    LIO.OnDebugMessage := FOnDebugMessage;
    LIO.OnGetPassword := fOnGetPassword;
    LIO.OnSSLNegotiated := OnSSLNegotiated;
    LIO.fSSLSocket := TTaurusTLSSocket.Create(Self);
    // For FTP Data channels, we do NOT want to Verify that the hostname
    // matches what's in the certificate because an IP address is passed
    // instead of a DNS hostname.  Such a check is likely to fail.
    LIO.SSLOptions.VerifyHostname := False;
    // We probably don't want to verify the certificate for the data channel
    // connection since that's negotiated in an encrypted control connection.
    LIO.OnVerifyError := nil;
  except
    LIO.Free;
    raise;
  end;
  Result := LIO;
end;

function TTaurusTLSIOHandlerSocket.CheckForError(ALastResult: Integer): Integer;
// var
// err: Integer;
begin
  if PassThrough then
  begin
    Result := inherited CheckForError(ALastResult);
  end
  else
  begin
    Result := fSSLSocket.GetSSLError(ALastResult);
    if Result = SSL_ERROR_NONE then
    begin
      Result := 0;
      Exit;
    end;
    if Result = SSL_ERROR_SYSCALL then
    begin
      Result := inherited CheckForError(Integer(Id_SOCKET_ERROR));
      Exit;
    end;
    ETaurusTLSAPISSLError.RaiseExceptionCode(Result, ALastResult, '');
  end;
end;

procedure TTaurusTLSIOHandlerSocket.RaiseError(AError: Integer);
begin
  if PassThrough or (AError = Id_WSAESHUTDOWN) or (AError = Id_WSAECONNABORTED)
    or (AError = Id_WSAECONNRESET) then
  begin
    inherited RaiseError(AError);
  end
  else
  begin
    ETaurusTLSAPISSLError.RaiseException(fSSLSocket.SSL, AError, '');
  end;
end;

{ ITaurusTLSCallbackHelper }

function TTaurusTLSIOHandlerSocket.GetPassword(const AIsWrite: Boolean;
  out VOk: Boolean): string;
begin
  Result := '';
  VOk := False;
  if Assigned(fOnGetPassword) then
  begin
    fOnGetPassword(Self, Result, AIsWrite, VOk);
  end;
end;

function TTaurusTLSIOHandlerSocket.TaurusGetProxyTargetHost: string;
var
  // under ARC, convert a weak reference to a strong reference before working with it
  LTransparentProxy, LNextTransparentProxy: TIdCustomTransparentProxy;
begin
  Result := '';
  // RLebeau: not reading from the property as it will create a
  // default Proxy object if one is not already assigned...
  LTransparentProxy := FTransparentProxy;
  if Assigned(LTransparentProxy) then
  begin
    if LTransparentProxy.Enabled then
    begin
      repeat
        LNextTransparentProxy := LTransparentProxy.ChainedProxy;
        if not Assigned(LNextTransparentProxy) then
          break;
        if not LNextTransparentProxy.Enabled then
          break;
        LTransparentProxy := LNextTransparentProxy;
      until False;
      Result := LTransparentProxy.Host;
    end;
  end;

end;

function TTaurusTLSIOHandlerSocket.TaurusGetURIHost: string;
var
  LURI: TIdURI;
begin
  Result := '';
  if URIToCheck <> '' then
  begin
    LURI := TIdURI.Create(URIToCheck);
    try
      Result := LURI.Host;
    finally
      LURI.Free;
    end;
  end;
end;

procedure TTaurusTLSIOHandlerSocket.StatusInfo(const AsslSocket: PSSL;
  AWhere, Aret: TIdC_INT);
{$IFNDEF USE_INLINE_VAR}
var
  LType, LMsg: string;
begin
{$ELSE}
begin
{$ENDIF}
  if Assigned(FOnStatusInfo) then
  begin
{$IFDEF USE_INLINE_VAR}
    var
      LType, LMsg: string;
{$ENDIF}
    GetStateVars(AsslSocket, AWhere, Aret, LType, LMsg);
    FOnStatusInfo(Self, AsslSocket, AWhere, Aret, LType, LMsg);
  end;
end;

procedure TTaurusTLSIOHandlerSocket.VerifyCallback(const APreverify_ok
  : TIdC_INT; ACertificate: TTaurusTLSX509; const ADepth: Integer;
  const AError: TIdC_LONG; const AMsg, ADescr: String; var VContinue: Boolean);
begin
  if Assigned(fOnVerifyCallback) then
  begin
    fOnVerifyCallback(Self, APreverify_ok, ACertificate, ADepth, AError, AMsg,
      ADescr, VContinue);
  end;
end;

function TTaurusTLSIOHandlerSocket.VerifyError(ACertificate: TTaurusTLSX509;
  const AError: TIdC_LONG): Boolean;
begin
  DoVerifyError(ACertificate, AError, Result);
end;

function TTaurusTLSIOHandlerSocket.GetIOHandlerSelf: TTaurusTLSIOHandlerSocket;
begin
  Result := Self;
end;

{ TTaurusTLSContext }

constructor TTaurusTLSContext.Create;
begin
  inherited Create;
  // an exception here probably means that you are using the wrong version
  // of the openssl libraries. refer to comments at the top of this file.
  if not LoadOpenSSLLibrary then
  begin
    raise ETaurusTLSCouldNotLoadSSLLibrary.Create(RSOSSLCouldNotLoadSSLLibrary);
  end;
  fVerifyMode := [];
  fMode := sslmUnassigned;
  fSessionId := 1;
  fUseSystemRootCACertificateStore := True;
end;

destructor TTaurusTLSContext.Destroy;
begin
  DestroyContext;
  inherited Destroy;
end;

{$IFDEF USE_WINDOWS_CERT_STORE}

const
  wincryptdll = 'crypt32.dll';
  RootStore = 'ROOT';
  CAStore = 'CA';

type
  HCERTSTORE = THandle;
{$IFDEF WIN64}
  HCRYPTPROV_LEGACY = PIdC_UINT64;
{$ELSE}
  HCRYPTPROV_LEGACY = PIdC_UINT32;
{$ENDIF}
  PCERT_INFO = Pointer; { don't need to know this structure }
  PCCERT_CONTEXT = ^CERT_CONTEXT;

  CERT_CONTEXT = record
    dwCertEncodingType: DWORD;
    pbCertEncoded: PByte;
    cbCertEncoded: DWORD;
    CertInfo: PCERT_INFO;
    certstore: HCERTSTORE;
  end;

{$IFDEF STRING_IS_ANSI}
{$EXTERNALSYM CertOpenSystemStoreA}

function CertOpenSystemStoreA(hProv: HCRYPTPROV_LEGACY;
  szSubsystemProtocol: PIdAnsiChar): HCERTSTORE; stdcall; external wincryptdll;
{$ELSE}
{$EXTERNALSYM CertOpenSystemStoreW}
function CertOpenSystemStoreW(hProv: HCRYPTPROV_LEGACY;
  szSubsystemProtocol: PCHar): HCERTSTORE; stdcall; external wincryptdll;
{$ENDIF}
{$EXTERNALSYM CertCloseStore}
function CertCloseStore(certstore: HCERTSTORE; dwFlags: DWORD): Boolean;
  stdcall; external wincryptdll;

{$EXTERNALSYM CertEnumCertificatesInStore}
function CertEnumCertificatesInStore(certstore: HCERTSTORE;
  pPrevCertContext: PCCERT_CONTEXT): PCCERT_CONTEXT; stdcall;
  external wincryptdll;

{ Copy Windows CA Certs to out cert store }

const
  SystemStores: array of string = [RootStore, CAStore];

procedure TTaurusTLSContext.LoadWindowsCertStore;
var
  LWinCertStore: HCERTSTORE;
  LX509Cert: PX509;
  Lcert_context: PCCERT_CONTEXT;
  LError: Integer;
  LSSLCertStore: PX509_STORE;
  i: Integer;
begin
  Lcert_context := nil;
  for i := Low(SystemStores) to High(SystemStores) do
  begin
{$IFDEF STRING_IS_ANSI}
    LWinCertStore := CertOpenSystemStoreA(nil, RootStore);
{$ELSE}
    LWinCertStore := CertOpenSystemStoreW(nil, PCHar(SystemStores[i]));
{$ENDIF}
    if LWinCertStore = 0 then
      Exit;

    LSSLCertStore := SSL_CTX_get_cert_store(fContext);
    try
      Lcert_context := CertEnumCertificatesInStore(LWinCertStore,
        Lcert_context);
      while Lcert_context <> nil do
      begin
        LX509Cert := d2i_X509(nil, @Lcert_context^.pbCertEncoded,
          Lcert_context^.cbCertEncoded);
        if LX509Cert <> nil then
        begin
          LError := X509_STORE_add_cert(LSSLCertStore, LX509Cert);
          // Ignore if cert already in store
          if (LError = 0) and
            (ERR_GET_REASON(ERR_get_error) <> X509_R_CERT_ALREADY_IN_HASH_TABLE)
          then
          begin
            ETaurusTLSCertNotAddedToStore.RaiseExceptionCode(LError,
              ROSCertificateNotAddedToStore);
          end;
          X509_free(LX509Cert);
        end;
        Lcert_context := CertEnumCertificatesInStore(LWinCertStore,
          Lcert_context);
      end;
    finally
      if not CertCloseStore(LWinCertStore, 0) then
      begin
        RaiseLastOSError;
      end;
    end;
  end;
end;
{$ENDIF}

procedure TTaurusTLSContext.DestroyContext;
begin
  if fContext <> nil then
  begin
    SSL_CTX_free(fContext);
    fContext := nil;
  end;
end;

procedure TTaurusTLSContext.InitContext(CtxMode: TTaurusTLSCtxMode);
const
  SSLProtoVersion: array [TTaurusTLSSSLVersion] of TIdC_LONG = (0, 0,
    SSL3_VERSION, { SSLv3 }
    TLS1_VERSION, { TLSv1 }
    TLS1_1_VERSION, { TLSv1_1 }
    TLS1_2_VERSION, { TLSv1_2 }
    TLS1_3_VERSION); { TLSv1_3 }

var
  LError: TIdC_INT;
  // pCAname: PSTACK_X509_NAME;
{$IFDEF USE_MARSHALLED_PTRS}
  M: TMarshaller;
{$ENDIF}
  LRes: Boolean;
  LFunc:  SSL_verify_cb;
begin
  // Destroy the context first
  DestroyContext;
  if fMode = sslmUnassigned then
  begin
    if CtxMode = sslCtxServer then
    begin
      fMode := sslmServer;
    end
    else
    begin
      fMode := sslmClient;
    end
  end;

  // create new SSL context
  fContext := SSL_CTX_new_ex(nil, nil, GetSSLMethod);
  if fContext = nil then
  begin
    ETaurusTLSCreatingContextError.RaiseWithMessage(RSSSLCreatingContextError);
  end;

  // set SSL Versions we will use
  if HasTLS_method then
  begin
    if SSL_CTX_set_min_proto_version(fContext,
      SSLProtoVersion[fMinTLSVersion]) = 0 then
    begin
      ETaurusTLSSettingMinProtocolError.RaiseWithMessage
        (RSOSSLMinProtocolError);
    end;
    // Maximum version is always TLS 1.3.
    if SSL_CTX_set_max_proto_version(fContext, TLS1_3_VERSION) = 0 then
    begin
      ETaurusTLSSettingMaxProtocolError.RaiseWithMessage
        (RSOSSLMaxProtocolError);
    end;
  end;
  SSL_CTX_set_mode(fContext, SSL_MODE_AUTO_RETRY);

  // set security level before loading certificates.
  SSL_CTX_set_security_level(fContext, FSecurityLevel);
  if SecurityLevelCBOn then
  begin
    SSL_CTX_set_security_callback(fContext, g_SecurityLevelCallback);
    SSL_CTX_set0_security_ex_data(fContext, Self);
  end;

  // assign a password lookup routine
  // if PasswordRoutineOn then begin
  SSL_CTX_set_default_passwd_cb(fContext, g_PasswordCallback);
  SSL_CTX_set_default_passwd_cb_userdata(fContext, Self);
  // end;
  if fUseSystemRootCACertificateStore then
  begin
{$IFDEF USE_WINDOWS_CERT_STORE}
    LoadWindowsCertStore;
{$ELSE}
    SSL_CTX_set_default_verify_paths(fContext);
{$ENDIF}
  end;
  // load key and certificate files
  if (RootPublicKey <> '') or (VerifyDirs <> '') then
  begin { Do not Localize }
    if not TaurusTLS_SSL_CTX_load_verify_locations(fContext, RootPublicKey,
      VerifyDirs) > 0 then
    begin
      ETaurusTLSLoadingRootCertError.RaiseWithMessage
        (RSSSLLoadingRootCertError);
    end;
  end;

  if PublicKey <> '' then
  begin { Do not Localize }

    if PosInStrArray(ExtractFileExt(PublicKey), ['.p12', '.pfx'], False) <> -1
    then
    begin
      LRes := TaurusTLS_SSL_CTX_use_certificate_file_PKCS12(fContext, PublicKey) > 0;
    end
    else
    begin
      // OpenSSL 1.0.2 has a new function, SSL_CTX_use_certificate_chain_file
      // that handles a chain of certificates in a PEM file.  That is prefered.
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
      LRes := TaurusTLS_SSL_CTX_use_certificate_chain_file(fContext, PublicKey) > 0;
{$ELSE}
      LRes := TaurusTLS_SSL_CTX_use_certificate_chain_file(fContext, PublicKey) > 0;
{$ENDIF}
    end;
    if not LRes then
    begin
      ETaurusTLSLoadingCertError.RaiseWithMessage(RSSSLLoadingCertError);
    end;
  end;

  if PrivateKey <> '' then
  begin { Do not Localize }
    if PosInStrArray(ExtractFileExt(PrivateKey), ['.p12', '.pfx'], False) <> -1
    then
    begin
      LRes := TaurusTLS_SSL_CTX_use_PrivateKey_file_PKCS12(fContext, PrivateKey) > 0;
    end
    else
    begin
      LRes := TaurusTLS_SSL_CTX_use_PrivateKey_file(fContext, PrivateKey,
        SSL_FILETYPE_PEM) > 0;
    end;
    if LRes then
    begin
      LRes := SSL_CTX_check_private_key(fContext) > 0;
    end;
    if not LRes then
    begin
      ETaurusTLSLoadingKeyError.RaiseWithMessage(RSSSLLoadingKeyError);
    end;
  end;
  if DHParamsFile <> '' then
  begin { Do not Localize }
    if not TaurusTLS_SSL_CTX_use_DHparams_file(fContext, fsDHParamsFile,
      SSL_FILETYPE_PEM) > 0 then
    begin
      ETaurusTLSLoadingDHParamsError.RaiseWithMessage
        (RSSSLLoadingDHParamsError);
    end;
  end;

  if StatusInfoOn then
  begin
    SSL_CTX_set_info_callback(fContext, g_InfoCallback);
  end;

  if MessageCBOn then
  begin
    SSL_CTX_set_msg_callback(fContext, g_MsgCallback);
    SSL_CTX_set_msg_callback_arg(fContext, Self);
  end;
  // if_SSL_CTX_set_tmp_rsa_callback(hSSLContext, @RSACallback);
  if fCipherList <> '' then
  begin { Do not Localize }
    LError := SSL_CTX_set_cipher_list(fContext,
{$IFDEF USE_MARSHALLED_PTRS}
      M.AsAnsi(fCipherList).ToPointer
{$ELSE}
      PAnsiChar(
{$IFDEF STRING_IS_ANSI}
      fCipherList
{$ELSE}
      AnsiString(fCipherList) // explicit cast to Ansi
{$ENDIF}
      )
{$ENDIF}
      );
  end
  else
  begin
    // RLebeau: don't override TaurusTLS's default.  As TaurusTLS evolves, the
    // SSL_DEFAULT_CIPHER_LIST constant defined in the C/C++ SDK may change,
    // while Indy's define of it might take some time to catch up.  We don't
    // want users using an older default with newer DLLs...
    (*
      error := SSL_CTX_set_cipher_list(fContext,
      {$IFDEF USE_MARSHALLED_PTRS}
      M.AsAnsi(SSL_DEFAULT_CIPHER_LIST).ToPointer
      {$ELSE}
      SSL_DEFAULT_CIPHER_LIST
      {$ENDIF}
      );
    *)
    LError := 1;
  end;
  if LError <= 0 then
  begin
    ETaurusTLSSettingCipherError.RaiseWithMessage(RSSSLSettingCipherError);
  end;
  if fVerifyMode <> [] then
  begin
    // SSL_CTX_set_default_verify_paths(fContext);
    if VerifyOn then
    begin
      LFunc := g_VerifyCallback;
    end
    else
    begin
      LFunc := nil;
    end;

    SSL_CTX_set_verify(fContext,
      TranslateInternalVerifyToSSL(fVerifyMode), LFunc);
    SSL_CTX_set_verify_depth(fContext, fVerifyDepth);
  end;

  if CtxMode = sslCtxServer then
  begin
    SSL_CTX_set_session_id_context(fContext, PByte(@fSessionId),
      SizeOf(fSessionId));
  end;
  // CA list
  if RootPublicKey <> '' then
  begin { Do not Localize }
    SSL_CTX_set_client_CA_list(fContext,
      TaurusTLS_SSL_load_client_CA_file(RootPublicKey));
  end

  // TODO: provide an event so users can apply their own settings as needed...
end;

procedure TTaurusTLSContext.SetSecurityLevel(const AValue
  : TTaurusTLSSecurityLevel);
begin
  FSecurityLevel := AValue;
end;

function TTaurusTLSContext.GetVerifyMode: TTaurusTLSVerifyModeSet;
begin
  Result := fVerifyMode;
end;
{
  function TTaurusTLSContext.LoadVerifyLocations(FileName: String; Dirs: String): Boolean;
  begin
  Result := False;

  if (Dirs <> '') or (FileName <> '') then begin
  if TaurusTLS_SSL_CTX_load_verify_locations(fContext, FileName, Dirs) <= 0 then begin
  raise EIdOSSLCouldNotLoadSSLLibrary.Create(RSOSSLCouldNotLoadSSLLibrary);
  end;
  end;

  Result := True;
  end;
}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

function SelectTLS1Method(const AMode: TTaurusTLSSSLMode): PSSL_METHOD;
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  Result := nil;
  case AMode of
    sslmServer:
      begin
        if Assigned(TLSv1_server_method) then
        begin
          Result := TLSv1_server_method();
        end;
      end;
    sslmClient:
      begin
        if Assigned(TLSv1_client_method) then
        begin
          Result := TLSv1_client_method();
        end;
      end;
  else
    if Assigned(TLSv1_method) then
    begin
      Result := TLSv1_method();
    end;
  end;
end;
{$ENDIF}

function TTaurusTLSContext.GetSSLMethod: PSSL_METHOD;
begin
  Result := nil;
  if fMode = sslmUnassigned then
  begin
    raise ETaurusTLSModeNotSet.Create(RSOSSLModeNotSet);
  end;
  { We are running with OpenSSL 1.1.1 or later. OpenSSL will negotiate the best
    available SSL/TLS version and there is not much that we can do to influence this.
    Hence, we ignore fMethod.

    Quoting from the OpenSSL man page:

    TLS_method(), TLS_server_method(), TLS_client_method()

    These are the general-purpose version-flexible SSL/TLS methods. The actual
    protocol version used will be negotiated to the highest version mutually
    supported by the client and the server. The supported protocols are SSLv3,
    TLSv1, TLSv1.1, TLSv1.2 and TLSv1.3. Applications should use these methods,
    and avoid the version-specific methods described below [e.g. SSLv2_method),
    which are deprecated.
  }
  case fMode of
    sslmClient:
      Result := TLS_client_method();

    sslmServer:
      Result := TLS_server_method();

    sslmBoth, sslmUnassigned:
      Result := TLS_Method();
  end;
end;

/// ///////////////////////////////////////////////////////////

function TTaurusTLSContext.Clone: TTaurusTLSContext;
begin
  Result := TTaurusTLSContext.Create;
  Result.StatusInfoOn := StatusInfoOn;
  // property PasswordRoutineOn: Boolean read fPasswordRoutineOn write fPasswordRoutineOn;
  Result.VerifyOn := VerifyOn;
  Result.MinTLSVersion := MinTLSVersion;
  Result.Mode := Mode;
  Result.RootPublicKey := RootPublicKey;
  Result.SecurityLevel := SecurityLevel;
  Result.PublicKey := PublicKey;
  Result.PrivateKey := PrivateKey;
  Result.VerifyMode := VerifyMode;
  Result.VerifyDepth := VerifyDepth;
  Result.VerifyHostname := VerifyHostname;
end;

{ TTaurusTLSSocket }

constructor TTaurusTLSSocket.Create(AParent: TObject);
begin
  inherited Create;
  FParent := AParent;
end;

destructor TTaurusTLSSocket.Destroy;
begin
  if fSession <> nil then
    SSL_SESSION_free(fSession);
  if fSSL <> nil then
  begin
    // TODO: should this be moved to TTaurusTLSContext instead?  Is this here
    // just to make sure the SSL shutdown does not log any messages?
    {
      if (fSSLContext <> nil) and (fSSLContext.StatusInfoOn) and
      (fSSLContext.fContext <> nil) then begin
      SSL_CTX_set_info_callback(fSSLContext.fContext, nil);
      end;
    }
    // SSL_set_shutdown(fSSL, SSL_SENT_SHUTDOWN);
    SSL_shutdown(fSSL);
    SSL_free(fSSL);
    fSSL := nil;
  end;
  FreeAndNil(fSSLCipher);
  FreeAndNil(fPeerCert);
  inherited Destroy;
end;

function TTaurusTLSSocket.GetSSLError(retCode: Integer): Integer;
begin
  // COMMENT!!!
  // I found out that SSL layer should not interpret errors, cause they will pop up
  // on the socket layer. Only thing that the SSL layer should consider is key
  // or protocol renegotiation. This is done by loop in read and write
  Result := SSL_get_error(fSSL, retCode);
end;

procedure TTaurusTLSSocket.Accept(const pHandle: TIdStackSocketHandle);

// Accept and Connect have a lot of duplicated code
var
  LRetCode: Integer;
  // LParentIO: TTaurusTLSIOHandlerSocket;
  // LHelper: ITaurusTLSCallbackHelper;
begin
  Assert(fSSL = nil);
  Assert(fSSLContext <> nil);
  fSSL := SSL_new(fSSLContext.Context);
  if fSSL = nil then
  begin
    raise ETaurusTLSCreatingSessionError.Create(RSSSLCreatingSessionError);
  end;
  LRetCode := SSL_set_app_data(fSSL, Self);
  if LRetCode <= 0 then
  begin
    ETaurusTLSDataBindingError.RaiseException(fSSL, LRetCode,
      RSSSLDataBindingError);
  end;
  // ignore warning about 64-bit value being passed to a 32bit parameter.
  // See: https://docs.openssl.org/3.0/man3/SSL_set_fd/#return-values
  LRetCode := SSL_set_fd(fSSL, pHandle);
  if LRetCode <= 0 then
  begin
    ETaurusTLSFDSetError.RaiseException(fSSL, LRetCode, RSSSLFDSetError);
  end;
  // RLebeau: if this socket's IOHandler was cloned, no need to reuse the
  // original IOHandler's active session ID, since this is a server socket
  // that generates its own sessions...
  //
  // RLebeau: is this actually true?  Should we be reusing the original
  // IOHandler's active session ID regardless of whether this is a client
  // or server socket? What about FTP in non-passive mode, for example?
  {
    if (LParentIO <> nil) and (LParentIO.fSSLSocket <> nil) and
    (LParentIO.fSSLSocket <> Self) then
    begin
    SSL_copy_session_id(fSSL, LParentIO.fSSLSocket.fSSL);
    end;
  }
  LRetCode := SSL_accept(fSSL);
  if LRetCode <= 0 then
  begin
    ETaurusTLSAcceptError.RaiseException(fSSL, LRetCode, RSSSLAcceptError);
  end;

  fSession := SSL_get1_session(fSSL);
end;

procedure TTaurusTLSSocket.Connect(const pHandle: TIdStackSocketHandle);
var
  LRetCode: Integer;
  LParentIO: TTaurusTLSIOHandlerSocket;
  LHelper: ITaurusTLSCallbackHelper;
  LVerifyResult: TIdC_LONG;
  Lpeercert: PX509;
  LCertificate: TTaurusTLSX509;
  LHostname: TBytes;

begin
  Assert(fSSL = nil);
  Assert(fSSLContext <> nil);
  if Supports(FParent, ITaurusTLSCallbackHelper, IInterface(LHelper)) then
  begin
    LParentIO := LHelper.GetIOHandlerSelf;
  end
  else
  begin
    LParentIO := nil;
  end;
  fSSL := SSL_new(fSSLContext.Context);
  if fSSL = nil then
  begin
    raise ETaurusTLSCreatingSessionError.Create(RSSSLCreatingSessionError);
  end;
  LRetCode := SSL_set_app_data(fSSL, Self);
  if LRetCode <= 0 then
  begin
    ETaurusTLSDataBindingError.RaiseException(fSSL, LRetCode,
      RSSSLDataBindingError);
  end;
  // ignore 64 value passed to 32bit parameter.
  // see: https://docs.openssl.org/3.0/man3/SSL_set_fd/#return-values
  LRetCode := SSL_set_fd(fSSL, pHandle);
  if LRetCode <= 0 then
  begin
    ETaurusTLSFDSetError.RaiseException(fSSL, LRetCode, RSSSLFDSetError);
  end;
  // RLebeau: if this socket's IOHandler was cloned, reuse the
  // original IOHandler's active session ID...
  if (LParentIO <> nil) and (LParentIO.SSLSocket <> nil) and
    (LParentIO.SSLSocket <> Self) then
  begin
    if SSL_copy_session_id(fSSL, LParentIO.SSLSocket.SSL) <> 1 then
    begin
      ETaurusTLSSSLCopySessionId.RaiseWithMessage(RSOSSLCopySessionIdError);
    end;
  end;
  {$IFNDEF WINDOWS}
  LHostname := BytesOf(fHostName + #0);
  {$ELSE}
  {In Windows 8.1 or later, getaddrinfo will by default, resolve IDN hostnames
  directly into IP Addresses.  We need to resolve Unicode IDN hostnames into
  punnycode hostnames.
  }
  if Assigned(IdnToAscii) then
  begin
    LHostname := BytesOf(IDNToPunnyCode(
      {$IFDEF STRING_IS_UNICODE}
      fHostName
      {$ELSE}
      TIdUnicodeString(fHostName) // explicit convert to Unicode
      {$ENDIF}) + #0);
  end
  else
  begin
    LHostname := BytesOf(fHostName + #0);
  end;
  {$ENDIF}
  // RFC 3546 states:
  // Literal IPv4 and IPv6 addresses are not permitted in "HostName".
  if (fHostName <> '') and (not IsValidIP(fHostName)) then
  begin
    { Delphi appears to need the extra AnsiString coerction. Otherwise, only the
      first character to the hostname is passed }
    LRetCode := SSL_set_tlsext_host_name(fSSL, @LHostname[0]);
    if LRetCode <= 0 then
    begin
      ETaurusTLSSettingTLSHostNameError.RaiseException(fSSL, LRetCode,
        RSSSLSettingTLSHostNameError_2);
    end;
  end;

  if fVerifyHostname then
  begin
    if fHostName <> '' then
    begin
      SSL_set_hostflags(fSSL, 0);
      LRetCode := SSL_set1_host(fSSL, @LHostname[0]);
      if LRetCode <= 0 then
      begin
        ETaurusTLSSettingTLSHostNameError.RaiseException(fSSL, LRetCode,
          RSSSLSettingTLSHostNameError_2);
      end;
    end;
  end;


  LRetCode := SSL_connect(fSSL);
  if LRetCode <= 0 then
  begin
    // TODO: if sslv23 is being used, but sslv23 is not being used on the
    // remote side, SSL_connect() will fail. In that case, before giving up,
    // try re-connecting using a version-specific method for each enabled
    // version, maybe one will succeed...
    ETaurusTLSConnectError.RaiseException(fSSL, LRetCode, RSSSLConnectError);
  end;
  fSession := SSL_get1_session(fSSL);
  // TODO: even if SSL_connect() returns success, the connection might
  // still be insecure if SSL_connect() detected that certificate validation
  // actually failed, but ignored it because SSL_VERIFY_PEER was disabled!
  // It would report such a failure via SSL_get_verify_result() instead of
  // returning an error code, so we should call SSL_get_verify_result() here
  // to make sure...

  Lpeercert := SSL_get_peer_certificate(fSSL);
  try
    if fSSLContext.VerifyHostname then
    begin
      LVerifyResult := SSL_get_verify_result(fSSL);
      if LVerifyResult <> X509_V_OK then
      begin
        if Supports(Parent, ITaurusTLSCallbackHelper, IInterface(LHelper)) then
        begin
          LCertificate := TTaurusTLSX509.Create(Lpeercert, False);
          try
            if not LHelper.VerifyError(LCertificate, LVerifyResult) then
            begin
              ETaurusTLSCertValidationError.RaiseWithMessage
                (AnsiStringToString(X509_verify_cert_error_string
                (LVerifyResult)));
            end;
          finally
            FreeAndNil(LCertificate);
          end;
        end;
      end;
    end;
  finally
    X509_free(Lpeercert);
  end;
end;

function TTaurusTLSSocket.Readable: TTaurusTLSReadStatus;
//From Tony WHyman - IndySecOpenSSL
var buf : byte;
    Lr: integer;
begin
  Result := sslNoData;
  {Confirm that there is application data to be read.}
  Lr := SSL_peek(fSSL, buf, 1);
  {Return DataAvailable if application data pending, or if it looks like we have disconnected,
          UnrecoverableError if error state indicates thus,
          EOF if the connection has been shutdown, or
          NoData otherwise => try again later}
  if Lr > 0 then
    Result := sslDataAvailable
  else
  begin
    case SSL_get_error(fSSL,Lr) of
      SSL_ERROR_SSL, SSL_ERROR_SYSCALL:
          if SSL_get_shutdown(fSSL) = SSL_RECEIVED_SHUTDOWN then
            Result := sslEOF
          else
            Result := sslUnrecoverableError;

      SSL_ERROR_ZERO_RETURN:
          if SSL_get_shutdown(fSSL) = SSL_RECEIVED_SHUTDOWN then
            Result := sslEOF;

      {anything else return the function default - sslNoData (yet)}
    end;
  end;
end;

function TTaurusTLSSocket.Recv(var VBuffer: TIdBytes): TIdC_SIZET;
var
  Lret, LErr: Integer;
  LRead: TIdC_SIZET;
begin
  Result := 0;
  repeat
    //The line below isn't needed but I want to avoid PAL warning about
    //unset variables.
    LRead := 0;
    Lret := SSL_read_ex(fSSL, VBuffer[0], Length(VBuffer), LRead);
    if Lret > 0 then
    begin
      Result := LRead;
      break;
    end;
    LErr := GetSSLError(Lret);
    if (LErr = SSL_ERROR_WANT_READ) or (LErr = SSL_ERROR_WANT_WRITE) then
    begin
      Continue;
    end;
    // From: Remy Lebeau
    // The error condition is first returned to the base IOHandler, which
    // handles disconnects and timeouts, then passed back down to the
    // SSLIOHandler (virtual CheckForError() method) to raise a TLS or
    // system exception.
    if LErr <> SSL_ERROR_ZERO_RETURN then
    begin
      Result := LRet;
    end;
    break;
  until False;
end;

function TTaurusTLSSocket.Send(const ABuffer: TIdBytes;
  const AOffset, ALength: TIdC_SIZET): TIdC_SIZET;
var
  Lret, LErr: Integer;
  LOffset, LLength, LWritten: TIdC_SIZET;
begin
  Result := 0;
  LOffset := AOffset;
  LLength := ALength;
  repeat
    //The line below isn't needed but I want to avoid PAL warning about
    //unset variables.
    LWritten := 0;
    Lret := SSL_write_ex(fSSL, ABuffer[LOffset], LLength, LWritten);
    if Lret > 0 then
    begin
      Result := Result + LWritten;
      LOffset := LOffset + LWritten;
      LLength := LLength - LWritten;
      if LLength < 1 then
      begin
        break;
      end;
      Continue;
    end;
    LErr := GetSSLError(Lret);
    if (LErr = SSL_ERROR_WANT_READ) or (LErr = SSL_ERROR_WANT_WRITE) then
    begin
      Continue;
    end;
    // From: Remy Lebeau
    // The error condition is first returned to the base IOHandler, which
    // handles disconnects and timeouts, then passed back down to the
    // SSLIOHandler (virtual CheckForError() method) to raise a TLS or
    // system exception.
    if LErr <> SSL_ERROR_ZERO_RETURN then
    begin
      Result := LRet;
    end;
    break;
  until False;
end;

procedure TTaurusTLSSocket.SetVerifyHostName(const Value: Boolean);
begin
  fVerifyHostname := Value;
end;

function TTaurusTLSSocket.GetProtocolVersion: TTaurusTLSSSLVersion;
begin
  if fSession = nil then
    raise ETaurusTLSSessionCanNotBeNil.Create(RSOSSSessionCanNotBeNul)
  else
    case SSL_SESSION_get_protocol_version(fSession) of
      SSL3_VERSION:
        Result := SSLv3;
      TLS1_VERSION:
        Result := TLSv1;
      TLS1_1_VERSION:
        Result := TLSv1_1;
      TLS1_2_VERSION:
        Result := TLSv1_2;
      TLS1_3_VERSION:
        Result := TLSv1_3;
    else
      Raise ETaurusTLSInvalidSessionValue.Create(RSOSSInvalidSessionValue);
    end;
end;

function TTaurusTLSSocket.GetSSLProtocolVersionStr: string;
begin
  case SSLProtocolVersion of
    SSLv23:
      Result := 'SSLv2 or SSLv3';
    SSLv2:
      Result := 'SSLv2';
    SSLv3:
      Result := 'SSLv3';
    TLSv1:
      Result := 'TLS';
    TLSv1_1:
      Result := 'TLSv1.1';
    TLSv1_2:
      Result := 'TLSv1.2';
    TLSv1_3:
      Result := 'TLSv1.3';
  end;
end;

function TTaurusTLSSocket.GetVerifyHostname: Boolean;
begin
  Result := fVerifyHostname;
end;

function TTaurusTLSSocket.GetPeerCert: TTaurusTLSX509;
var
  LX509: PX509;
begin
  if fPeerCert = nil then
  begin
    LX509 := SSL_get_peer_certificate(fSSL);
    if LX509 <> nil then
    begin
      fPeerCert := TTaurusTLSX509.Create(LX509, False);
    end;
  end;
  Result := fPeerCert;
end;

function TTaurusTLSSocket.GetSSLCipher: TTaurusTLSCipher;
begin
  if (fSSLCipher = nil) and (fSSL <> nil) then
  begin
    fSSLCipher := TTaurusTLSCipher.Create(Self);
  end;
  Result := fSSLCipher;
end;

function TTaurusTLSSocket.GetSessionIDAsString: String;
var
  LData: TTaurusTLSByteArray;
  i: TIdC_UINT;
  LDataPtr: PByte;
  pSession: PSSL_SESSION;
begin
  Result := ''; { Do not Localize }

  LData._Length := 0;
  LData.Data := nil;
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  if Assigned(SSL_get_session) and Assigned(SSL_SESSION_get_id) then
{$ENDIF}
  begin
    if fSSL <> nil then
    begin
      pSession := SSL_get_session(fSSL);
      if pSession <> nil then
      begin
        LData.Data := SSL_SESSION_get_id(pSession, @LData._Length);
      end;
    end;
  end;
  if LData._Length > 0 then
  begin
    for i := 0 to LData._Length - 1 do
    begin
      // RLebeau: not all Delphi versions support indexed access using PByte
      LDataPtr := LData.Data;
      Inc(LDataPtr, i);
      Result := Result + IndyFormat('%.2x', [LDataPtr^]); { do not localize }
    end;
  end;
end;

/// ////////////////////////////////////////////////////////////
// TTaurusTLSCipher
/// ////////////////////////////////////////////////////////////
constructor TTaurusTLSCipher.Create(AOwner: TTaurusTLSSocket);
begin
  inherited Create;
  fSSLSocket := AOwner;
  fSSLCipher := nil;
end;

destructor TTaurusTLSCipher.Destroy;
begin
  inherited Destroy;
end;

function TTaurusTLSCipher.GetDescription;
var
  buf: array [0 .. 1024] of TIdAnsiChar;
begin
  Result := AnsiStringToString(SSL_CIPHER_description(GetSSLCipher, @buf[0],
    SizeOf(buf) - 1));
end;

function TTaurusTLSCipher.GetName: String;
begin
  Result := AnsiStringToString(SSL_CIPHER_get_name(GetSSLCipher));
end;

function TTaurusTLSCipher.GetSSLCipher: PSSL_CIPHER;
begin
  if not Assigned(fSSLCipher) then
  begin
    fSSLCipher := SSL_get_current_cipher(fSSLSocket.SSL);
  end;
  Result := fSSLCipher;
end;

function TTaurusTLSCipher.GetBits: TIdC_INT;
begin
  Result := 0;
  SSL_CIPHER_get_bits(GetSSLCipher, Result);
end;

function TTaurusTLSCipher.GetVersion: String;
begin
  Result := AnsiStringToString(SSL_CIPHER_get_version(GetSSLCipher));
end;

{$I TaurusTLSSymbolDeprecatedOff.inc}

initialization

Assert(SSLIsLoaded = nil);
SSLIsLoaded := TIdThreadSafeBoolean.Create;

{$I TaurusTLSSymbolDeprecatedOff.inc}
RegisterSSL('TaurusTLS', 'TaurusTLS Developers', { do not localize }
  'Copyright ' + Char(169) + ' 2025'#10#13 + { do not localize }
  'TaurusTLS Developers. All rights reserved.', { do not localize }
  'Open SSL 1.1.1 and 3.x DLL Delphi and C++Builder interface',
  { do not localize }
  'https://github.com/JPeterMugaas/TaurusTLS'#10#13 + { do not localize }
  'Original Authors - J. Peter Mugaas and Tony Whyman', { do not localize }
  TTaurusTLSIOHandlerSocket, TTaurusTLSServerIOHandler);
{$I TaurusTLSSymbolDeprecatedOn.inc}
TTaurusTLSIOHandlerSocket.RegisterIOHandler;

finalization

// TODO: TTaurusTLSIOHandlerSocket.UnregisterIOHandler;
UnLoadOpenSSLLibrary;
// free the lock last as unload makes calls that use it
FreeAndNil(SSLIsLoaded);

end.
