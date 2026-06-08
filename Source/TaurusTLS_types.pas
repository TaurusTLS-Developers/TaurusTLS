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
///   Defines and implements common classes and interfaces used in the TaurusTLS
///   library.
/// </summary>
unit TaurusTLS_types;

interface

uses
  SysUtils,
  IdGlobal,
  IdCTypes,
  IdSSLOpenSSL,
  TaurusTLSHeaders_ssl,
  TaurusTLSHeaders_ssl3,
  TaurusTLSHeaders_tls1,
  TaurusTLSHeaders_X509,
  TaurusTLSHeaders_X509_vfy,
  TaurusTLSHeaders_X509v3,
  TaurusTLSExceptionHandlers;

type
{$IFDEF DCC}
  TStringArray = TArray<string>;
{$ENDIF}

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
    sslvrfPostHandshake
  );
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
  TTaurusTLSVerifyModes = set of TTaurusTLSVerifyMode;

  ETaurusTLSSecurityBits = class(ETaurusTLSError);

  TTaurusTLSSecurityBits = (sbZero, sb80, sb112, sb128, sb192, sb256);
  TTaurusTLSSecurityBitsHelper = record helper for TTaurusTLSSecurityBits
  private
    function GetAsInt: TIdC_INT; {$IFDEF USE_INLINE} inline;{$ENDIF}
    procedure SetAsInt(AValue: TIdC_INT); {$IFDEF USE_INLINE} inline;{$ENDIF}
  public
    property AsInt: TIdC_INT read GetAsInt write SetAsInt;
  end;

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

  TTaurusTLSSSLVersionHelper = record helper for TTaurusTLSSSLVersion
  public const
    cMapping: array[TTaurusTLSSSLVersion] of TIdC_LONG = (
      0, 0, SSL3_VERSION, TLS1_VERSION, TLS1_1_VERSION, TLS1_2_VERSION,
      TLS1_3_VERSION
    );

  private
    function GetAsInt: TIdC_LONG; {$IFDEF USE_INLINE} inline;{$ENDIF}
    procedure SetAsInt(AValue: TIdC_LONG); {$IFDEF USE_INLINE} inline;{$ENDIF}
  public
    property AsInt: TIdC_LONG read GetAsInt write SetAsInt;
  end;

  ETaurusTLSSSLVersion = class(ETaurusTLSError);

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


  TTaurusTLSCertificateVerifyFlag = (
    cvfPeer,
    cvfFailIfNoPeer,
    cvfCliOnce,
    cvfPostHandshake
  );

  TTaurusTLSCertificateVerifyFlags = set of TTaurusTLSCertificateVerifyFlag;
  TTaurusTLSCertificateVerifyFlagSet = record
  public const
    cVerifyNone = [];

  private const
    cMask = SSL_VERIFY_PEER or SSL_VERIFY_FAIL_IF_NO_PEER_CERT or
            SSL_VERIFY_CLIENT_ONCE or SSL_VERIFY_POST_HANDSHAKE;

  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FFlags: TTaurusTLSCertificateVerifyFlags;

    function GetAsInt: TIdC_INT; {$IFDEF USE_INLINE} inline;{$ENDIF}
    procedure SetAsInt(AValue: TIdC_INT); {$IFDEF USE_INLINE} inline;{$ENDIF}
    procedure SetFlags(AFlags: TTaurusTLSCertificateVerifyFlags);
      {$IFDEF USE_INLINE} inline;{$ENDIF}
  public
    class operator Implicit(AFlags: TTaurusTLSCertificateVerifyFlags): TTaurusTLSCertificateVerifyFlagSet;
    class operator Implicit(AFlags: TTaurusTLSCertificateVerifyFlagSet): TTaurusTLSCertificateVerifyFlags;
    class procedure Include(var AValue: TTaurusTLSCertificateVerifyFlagSet;
      AFlag: TTaurusTLSCertificateVerifyFlag); overload; static;
      {$IFDEF USE_INLINE} inline;{$ENDIF}
    procedure Include(AFlag: TTaurusTLSCertificateVerifyFlag); overload;
      {$IFDEF USE_INLINE} inline;{$ENDIF}
    class procedure Exclude(var AValue: TTaurusTLSCertificateVerifyFlagSet;
      AFlag: TTaurusTLSCertificateVerifyFlag); overload; static;
      {$IFDEF USE_INLINE} inline;{$ENDIF}
    procedure Exclude(AFlag: TTaurusTLSCertificateVerifyFlag); overload;
      {$IFDEF USE_INLINE} inline;{$ENDIF}
    property AsInt: TIdC_INT read GetAsInt write SetAsInt;
    property Flags: TTaurusTLSCertificateVerifyFlags read FFlags;
  end;

  ///  <summary>
  ///  Represents a single X.509 certificate verification flag,
  ///  corresponding to an OpenSSL X509_V_FLAG_* constant.
  ///  </summary>
  ///  <remarks>
  ///  The ordinal value of each enumeration member represents the bit
  ///  position (N) in the underlying integer flag set, where the actual
  ///  OpenSSL constant is 1 &lt;&lt; N. This design allows for seamless
  ///  typecasting to and from the integer bitmask.
  ///  </remarks>
  TTaurusTLSX509VerifyFlag = (
    x509vfCallBackIssuerCheck       = $00, // 1 shl $00 = X509_V_FLAG_CB_ISSUER_CHECK - Depricated
    x509vfCheckTime                 = $01, // 1 shl $01 = X509_V_FLAG_USE_CHECK_TIME
    x509vfCheckCrl                  = $02, // 1 shl $02 = X509_V_FLAG_CRL_CHECK
    x509vfCheckCrlAll               = $03, // 1 shl $03 = X509_V_FLAG_CRL_CHECK_ALL
    x509vfIgnoreCritical            = $04, // 1 shl $04 = X509_V_FLAG_IGNORE_CRITICAL
    x509vfStrict                    = $05, // 1 shl $05 = X509_V_FLAG_X509_STRICT
    x509vfAllowProxyCerts           = $06, // 1 shl $06 = X509_V_FLAG_ALLOW_PROXY_CERTS
    x509vfPolicyCheck               = $07, // 1 shl $07 = X509_V_FLAG_POLICY_CHECK
    x509vfExplicitPolicy            = $08, // 1 shl $08 = X509_V_FLAG_EXPLICIT_POLICY
    x509vfInhibitAny                = $09, // 1 shl $09 = X509_V_FLAG_INHIBIT_ANY
    x509vfInhibitMap                = $0A, // 1 shl $0A = X509_V_FLAG_INHIBIT_MAP
    x509vfNotifyPolicy              = $0B, // 1 shl $0B = X509_V_FLAG_NOTIFY_POLICY
    x509vfExtendCrlSupport          = $0C, // 1 shl $0C = X509_V_FLAG_EXTENDED_CRL_SUPPORT
    x509vfUseCrlDeltas              = $0D, // 1 shl $0D = X509_V_FLAG_USE_DELTAS
    x509vfCheckSelfSignSignitures   = $0E, // 1 shl $0E = X509_V_FLAG_CHECK_SS_SIGNATURE
    x509vfTrustedFirst              = $0F, // 1 shl $0F = X509_V_FLAG_TRUSTED_FIRST
    x509vfSuiteB128Only             = $10, // 1 shl $10 = X509_V_FLAG_SUITEB_128_LOS_ONLY
    x509vfSuiteB192                 = $11, // 1 shl $11 = X509_V_FLAG_SUITEB_192_LOS
    x509vfDummy                     = $12, // This flag is not defined in OpenSSL.
                                           // However it needs to avoid for Delphi Component designer AV
    // x509vfSuiteB128                         // X509_V_FLAG_SUITEB_128_LOS = X509_V_FLAG_SUITEB_128_LOS_ONLY + X509_V_FLAG_SUITEB_192_LOS
    x509vfPartialChain              = $13, // 1 shl $13 = X509_V_FLAG_PARTIAL_CHAIN
    x509vfNoAlternativeChain        = $14, // 1 shl $14 = X509_V_FLAG_NO_ALT_CHAINS
    x509vfNoCheckTime               = $15  // 1 shl $15 = X509_V_FLAG_NO_CHECK_TIME
  );

  ///  <summary>
  ///  Provides methods for converting a single TTaurusTLSX509VerifyFlag enumeration member
  ///  to and from its native C integer representation.
  ///  </summary>
  TTaurusTLSX509VerifyFlagHelper = record helper for TTaurusTLSX509VerifyFlag
  private
    function GetAsInt: TIdC_ULONG; {$IFDEF USE_INLINE}inline;{$ENDIF}
    procedure SetAsInt(Value: TIdC_ULONG); {$IFDEF USE_INLINE}inline;{$ENDIF}

  public
    ///  <summary>
    ///  Converts a single TTaurusTLSX509VerifyFlag enumeration member into its
    ///  corresponding OpenSSL integer flag value.
    ///  </summary>
    ///  <param name="Value">The enumeration member to convert.</param>
    ///  <returns>
    ///  The OpenSSL TIdC_ULONG (unsigned long) flag value.
    ///  </returns>
    class function ToInt(Value: TTaurusTLSX509VerifyFlag): TIdC_ULONG; static;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Converts an OpenSSL integer flag value into its corresponding
    ///  TTaurusTLSX509VerifyFlag enumeration member.
    ///  </summary>
    ///  <param name="Value">
    ///  The OpenSSL TIdC_ULONG value (must be an exact power of 2).
    ///  </param>
    ///  <returns>
    ///  The TTaurusTLSX509VerifyFlag member.
    ///  </returns>
    ///  <remarks>
    ///  This method validates that the input integer value is a single,
    ///  valid flag defined in TTaurusTLSX509VerifyFlag. If the value does not represent
    ///  exactly one valid flag bit, an EInvalidCast exception is raised.
    ///  </remarks>
    class function FromInt(Value: TIdC_ULONG): TTaurusTLSX509VerifyFlag; static;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Checks if the current TTaurusTLSX509VerifyFlag instance's integer value matches
    ///  the provided OpenSSL flag value.
    ///  </summary>
    ///  <param name="Value">
    ///  The OpenSSL TIdC_ULONG value to compare against.
    ///  </param>
    ///  <returns>
    ///  True if the values are equal.
    ///  </returns>
    function IsEqualTo(Value: TIdC_ULONG): boolean;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Gets or sets the corresponding OpenSSL integer flag value
    ///  (1 &lt;&lt; Ordinal).
    ///  </summary>
    ///  <remarks>
    ///  When writing (Set), the input value must be an exact match for one
    ///  defined flag bit; otherwise, an EInvalidCast exception is raised.
    ///  </remarks>
    property AsInt: TIdC_ULONG read GetAsInt write SetAsInt;
  end;

  ///  <summary>
  ///  Represents a set of X.509 verification flags, equivalent to the full
  ///  OpenSSL integer bitmask used by X509_VERIFY_PARAM_set_flags.
  ///  </summary>
  TTaurusTLSX509VerifyFlags = set of TTaurusTLSX509VerifyFlag;

  ///  <summary>
  ///  Provides methods for converting a TTaurusTLSX509VerifyFlags set to and
  ///  from its native C integer bitmask representation.
  ///  </summary>
  TTaurusTLSX509VerifyFlagsHelper = record helper for TTaurusTLSX509VerifyFlags
  private
    function GetAsInt: TIdC_ULONG; {$IFDEF USE_INLINE}inline;{$ENDIF}
    procedure SetAsInt(Value: TIdC_ULONG); {$IFDEF USE_INLINE}inline;{$ENDIF}
    procedure SetSafeAsInt(Value: TIdC_ULONG); {$IFDEF USE_INLINE}inline;{$ENDIF}

  public
    ///  <summary>
    ///  Converts the TTaurusTLSX509VerifyFlags set into a single OpenSSL TIdC_ULONG
    ///  integer bitmask.
    ///  </summary>
    ///  <param name="Value">The set of flags to convert.</param>
    ///  <returns>
    ///  The combined TIdC_ULONG bitmask value ready for OpenSSL functions.
    ///  </returns>
    class function ToInt(Value: TTaurusTLSX509VerifyFlags): TIdC_ULONG; static;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Converts an OpenSSL TIdC_ULONG integer bitmask into a
    ///  TTaurusTLSX509VerifyFlags set.
    ///  </summary>
    ///  <param name="Value">
    ///  The OpenSSL TIdC_ULONG bitmask containing flags.
    ///  </param>
    ///  <returns>
    ///  The resulting TTaurusTLSX509VerifyFlags set.
    ///  </returns>
    ///  <remarks>
    ///  This method validates that the input integer only contains bits
    ///  defined within the TTaurusTLSX509VerifyFlag enumeration range. If the value
    ///  contains any bits corresponding to undefined flags (internal OpenSSL
    ///  constants), an <see cref="EInvalidCast" /> exception is raised.
    ///  </remarks>
    class function FromInt(Value: TIdC_ULONG): TTaurusTLSX509VerifyFlags; static;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Converts an OpenSSL TIdC_ULONG integer bitmask into a
    ///  TTaurusTLSX509VerifyFlags set without strict validation.
    ///  </summary>
    ///  <param name="Value">
    ///  The OpenSSL TIdC_ULONG bitmask containing flags.
    ///  </param>
    ///  <returns>
    ///  The resulting TTaurusTLSX509VerifyFlags set, with undefined bits being ignored.
    ///  </returns>
    ///  <remarks>
    ///  This method is useful when dealing with values returned by OpenSSL
    ///  which may contain internal, undocumented, or non-public flags.
    ///  Any undefined bit is simply masked out and suppressed.
    ///  </remarks>
    class function SafeFromInt(Value: TIdC_ULONG): TTaurusTLSX509VerifyFlags; static;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Checks if the current TTaurusTLSX509VerifyFlags set, when converted to an
    ///  integer mask, exactly matches the provided OpenSSL flag value.
    ///  </summary>
    ///  <param name="Value">
    ///  The OpenSSL TIdC_ULONG value to compare against.
    ///  </param>
    ///  <returns>
    ///  True if the integer bitmasks are identical.
    ///  </returns>
    function IsEqualTo(Value: TIdC_ULONG): boolean;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Gets or sets the flags as an OpenSSL TIdC_ULONG integer bitmask.
    ///  </summary>
    ///  <remarks>
    ///  When writing (Set), the input value is strictly validated to
    ///  ensure only defined flags are present. If undefined bits are
    ///  found, an EInvalidCast exception is raised. To ignore undefined
    ///  bits, use <see cref="SafeAsInt" /> property.
    ///  </remarks>
    property AsInt: TIdC_ULONG read GetAsInt write SetAsInt;

    ///  <summary>
    ///  Gets or sets the corresponding OpenSSL integer flag value
    ///  (1 &lt;&lt; Ordinal).
    ///  </summary>
    ///  <remarks>
    ///  When writing (Set), the input value must represent exactly one
    ///  valid flag bit; otherwise, an <see cref="EInvalidCast" /> exception
    ///  is raised.
    ///  </remarks>
    property SafeAsInt: TIdC_ULONG read GetAsInt write SetSafeAsInt;
  end;

    ///  <summary>
    ///  Represents a single X.509 verification parameter inheritance flag,
    ///  corresponding to an OpenSSL X509_VP_FLAG_* constant.
    ///  </summary>
    ///  <remarks>
    ///  These flags control how verification parameters are inherited,
    ///  set, or reset within an OpenSSL verification context. The ordinal
    ///  value of each member represents the bit position (N) in the
    ///  underlying integer flag set, where the actual OpenSSL constant is
    ///  1 &lt;&lt; N.
    ///  </remarks>
    TTaurusTLSX509InheritanceFlag = (
      x509ihfDefault                  = $0, // 1 shl $0 = X509_VP_FLAG_DEFAULT
      x509ihfOverrite                 = $1, // 1 shl $1 = X509_VP_FLAG_OVERWRITE
      x509ihfReset                    = $2, // 1 shl $2 = X509_VP_FLAG_RESET_FLAGS
      x509ihfLocked                   = $3, // 1 shl $3 = X509_VP_FLAG_LOCKED
      x509ihfOnce                     = $4  // 1 shl $4 = X509_VP_FLAG_ONCE
    );


  ///  <summary>
  ///  Provides methods for converting a single TTaurusTLSX509InheritanceFlag
  ///  enumeration member to and from its native C integer representation.
  ///  </summary>
  TTaurusTLSX509InheritanceFlagHelper = record helper for TTaurusTLSX509InheritanceFlag
  private
    function GetAsInt: TIdC_UINT32; {$IFDEF USE_INLINE}inline;{$ENDIF}
    procedure SetAsInt(Value: TIdC_UINT32); {$IFDEF USE_INLINE}inline;{$ENDIF}
  public
    ///  <summary>
    ///  Converts a single TTaurusTLSX509InheritanceFlag member into its corresponding
    ///  OpenSSL integer flag value (1 &lt;&lt; Ordinal).
    ///  </summary>
    ///  <param name="Value">The enumeration member to convert.</param>
    ///  <returns>
    ///  The OpenSSL TIdC_UINT32 (unsigned 32-bit integer) flag value.
    ///  </returns>
    class function ToInt(Value: TTaurusTLSX509InheritanceFlag): TIdC_UINT32; static;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Converts an OpenSSL integer flag value into its corresponding
    ///  TTaurusTLSX509InheritanceFlag enumeration member.
    ///  </summary>
    ///  <param name="Value">
    ///  The OpenSSL TIdC_UINT32 value (must be an exact power of 2).
    ///  </param>
    ///  <returns>
    ///  The TTaurusTLSX509InheritanceFlag member.
    ///  </returns>
    ///  <remarks>
    ///  This method validates that the input integer value is a single,
    ///  valid flag defined in TTaurusTLSX509InheritanceFlag. If the value does not
    ///  represent exactly one valid flag bit, an <see cref="EInvalidCast" />
    ///  exception is raised.
    ///  </remarks>
    class function FromInt(Value: TIdC_UINT32): TTaurusTLSX509InheritanceFlag; static;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Checks if the current TTaurusTLSX509InheritanceFlag instance's integer value
    ///  matches the provided OpenSSL flag value.
    ///  </summary>
    ///  <param name="Value">
    ///  The OpenSSL TIdC_UINT32 value to compare against.
    ///  </param>
    ///  <returns>
    ///  True if the values are equal.
    ///  </returns>
    function IsEqualTo(Value: TIdC_UINT32): boolean;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Gets or sets the corresponding OpenSSL integer flag value
    ///  (1 &lt;&lt; Ordinal).
    ///  </summary>
    ///  <remarks>
    ///  When writing (Set), the input value must be an exact match for one
    ///  defined flag bit; otherwise, an EInvalidCast exception is raised.
    ///  </remarks>
    property AsInt: TIdC_UINT32 read GetAsInt write SetAsInt;
  end;

  ///  <summary>
  ///  Represents a set of X.509 verification parameter inheritance flags,
  ///  equivalent to the full OpenSSL integer bitmask.
  ///  </summary>
  TTaurusTLSX509InheritanceFlags = set of TTaurusTLSX509InheritanceFlag;

  ///  <summary>
  ///  Provides methods for converting a TTaurusTLSX509InheritanceFlags set to and
  ///  from its native C integer bitmask representation.
  ///  </summary>
  TTaurusTLSX509InheritanceFlagsHelper = record helper for TTaurusTLSX509InheritanceFlags
  private
    function GetAsInt: TIdC_UINT32; {$IFDEF USE_INLINE}inline;{$ENDIF}
    procedure SetAsInt(Value: TIdC_UINT32); {$IFDEF USE_INLINE}inline;{$ENDIF}
  public
    ///  <summary>
    ///  Converts the TTaurusTLSX509InheritanceFlags set into a single OpenSSL
    ///  TIdC_UINT32 integer bitmask.
    ///  </summary>
    ///  <param name="Value">The set of flags to convert.</param>
    ///  <returns>
    ///  The combined TIdC_UINT32 bitmask value ready for OpenSSL functions.
    ///  </returns>
    class function ToInt(Value: TTaurusTLSX509InheritanceFlags): TIdC_UINT32; static;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Converts an OpenSSL TIdC_UINT32 integer bitmask into a
    ///  TTaurusTLSX509InheritanceFlags set.
    ///  </summary>
    ///  <param name="Value">
    ///  The OpenSSL TIdC_UINT32 bitmask containing flags.
    ///  </param>
    ///  <returns>
    ///  The resulting TTaurusTLSX509InheritanceFlags set.
    ///  </returns>
    ///  <remarks>
    ///  This method validates that the input integer only contains bits
    ///  defined within
    ///  the <see cref="TTaurusTLSX509InheritanceFlag" />
    ///  enumeration range. If the value contains any extraneous bits, an
    ///  <see cref="EInvalidCast" /> exception is raised.
    ///  </remarks>
    class function FromInt(Value: TIdC_UINT32): TTaurusTLSX509InheritanceFlags; static;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Checks if the current TTaurusTLSX509InheritanceFlags set, when converted to an
    ///  integer mask, exactly matches the provided OpenSSL flag value.
    ///  </summary>
    ///  <param name="Value">
    ///  The OpenSSL TIdC_UINT32 value to compare against.
    ///  </param>
    ///  <returns>
    ///  True if the integer bitmasks are identical.
    ///  </returns>
    function IsEqualTo(Value: TIdC_UINT32): boolean;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    property AsInt: TIdC_UINT32 read GetAsInt write SetAsInt;
  end;

  ///  <summary>
  ///  Defines the acceptable trust settings for a certificate, corresponding
  ///  to OpenSSL X509_TRUST_* constants.
  ///  </summary>
  ///  <remarks>
  ///  These constants are used by the certificate store to determine if
  ///  a certificate is acceptable for a specific application usage (e.g.,
  ///  a client certificate, or a timestamping authority).
  ///  </remarks>
  TTaurusTLSX509Trust = (
    trDefault     = X509_TRUST_DEFAULT,
    trCompat      = X509_TRUST_COMPAT,
    trSslClient   = X509_TRUST_SSL_CLIENT,
    trSslServer   = X509_TRUST_SSL_SERVER,
    trEMail       = X509_TRUST_EMAIL,
    trObjectSign  = X509_TRUST_OBJECT_SIGN,
    trOspSign     = X509_TRUST_OCSP_SIGN,
    trOspReq      = X509_TRUST_OCSP_REQUEST,
    trTsa         = X509_TRUST_TSA
  );

  ///  <summary>
  ///  Provides methods for converting a TTaurusTLSX509Trust enumeration member to and
  ///  from its native C integer value.
  ///  </summary>
  TTaurusTLSX509TrustHelper = record helper for TTaurusTLSX509Trust
  private
    function GetAsInt: TIdC_Int; {$IFDEF USE_INLINE}inline;{$ENDIF}
    procedure SetAsInt(Value: TIdC_Int); {$IFDEF USE_INLINE}inline;{$ENDIF}
  public
    ///  <summary>
    ///  Converts a TTaurusTLSX509Trust member into its corresponding OpenSSL integer
    ///  constant value.
    ///  </summary>
    ///  <param name="Value">The enumeration member to convert.</param>
    ///  <returns>
    ///  The OpenSSL TIdC_Int value.
    ///  </returns>
    class function ToInt(Value: TTaurusTLSX509Trust): TIdC_Int; static;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Converts an OpenSSL integer value into its corresponding TTaurusTLSX509Trust
    ///  enumeration member.
    ///  </summary>
    ///  <param name="Value">
    ///  The OpenSSL TIdC_Int value.
    ///  </param>
    ///  <returns>
    ///  The TTaurusTLSX509Trust member.
    ///  </returns>
    ///  <remarks>
    ///  This method validates that the input integer value maps to one
    ///  of the explicitly defined
    ///  <see cref="TTaurusTLSX509Trust" /> constants. If no
    ///  corresponding constant is found, an <see cref="EInvalidCast" />
    ///  exception is raised.
    ///  </remarks>
    class function FromInt(Value: TIdC_Int): TTaurusTLSX509Trust; static;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Checks if the current TTaurusTLSX509Trust instance's integer value matches
    ///  the provided OpenSSL integer value.
    ///  </summary>
    ///  <param name="Value">
    ///  The OpenSSL TIdC_Int value to compare against.
    ///  </param>
    ///  <returns>
    ///  True if the values are equal.
    ///  </returns>
    function IsEqualTo(Value: TIdC_Int): boolean;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Gets or sets the corresponding OpenSSL integer constant value.
    ///  </summary>
    ///  <remarks>
    ///  This property maps the enumeration member to and from its native
    ///  OpenSSL integer constant. When writing, the input integer
    ///  must map exactly to one defined
    ///  <see cref="TTaurusTLSX509Trust" /> constant;
    ///  otherwise, an <see cref="EInvalidCast" /> exception is raised.
    ///  </remarks>
    property AsInt: TIdC_Int read GetAsInt write SetAsInt;
  end;

    ///  <summary>
    ///  Defines the certificate verification purpose, corresponding to
    ///  OpenSSL X509_PURPOSE_* constants.
    ///  </summary>
    ///  <remarks>
    ///  This is used in the certificate verification context to check key
    ///  usage and extended key usage constraints against the intended role
    ///  (e.g., SSL Server, SMIME Signing).
    ///  </remarks>
    TTaurusTLSX509Purpose = (
      prpDefaultAny     = 0, //X509_PURPOSE_DEFAULT_ANY
      prpSslClient      = X509_PURPOSE_SSL_CLIENT,
      prpSslServer      = X509_PURPOSE_SSL_SERVER,
      prpNsSSLServer    = X509_PURPOSE_NS_SSL_SERVER,
      prpSMimeSign      = X509_PURPOSE_SMIME_SIGN,
      prpSMimeEncrypt   = X509_PURPOSE_SMIME_ENCRYPT,
      prpCrlSign        = X509_PURPOSE_CRL_SIGN,
      prpAny            = X509_PURPOSE_ANY,
      prpOspHelper      = X509_PURPOSE_OCSP_HELPER,
      prpTimeStampSign  = X509_PURPOSE_TIMESTAMP_SIGN,
      prpCodeSign       = X509_PURPOSE_CODE_SIGN
    );

  ///  <summary>
  ///  Provides methods for converting a TTaurusTLSX509Purpose enumeration member to and
  ///  from its native C integer value.
  ///  </summary>
  TTaurusTLSX509PurposeHelper = record helper for TTaurusTLSX509Purpose
  private
    function GetAsInt: TIdC_Int; {$IFDEF USE_INLINE}inline;{$ENDIF}
    procedure SetAsInt(Value: TIdC_Int); {$IFDEF USE_INLINE}inline;{$ENDIF}
  public
    ///  <summary>
    ///  Converts a TTaurusTLSX509Purpose member into its corresponding OpenSSL integer
    ///  constant value.
    ///  </summary>
    ///  <param name="Value">The enumeration member to convert.</param>
    ///  <returns>
    ///  The OpenSSL TIdC_Int value.
    ///  </returns>
    class function ToInt(Value: TTaurusTLSX509Purpose): TIdC_Int; static;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Converts an OpenSSL integer value into its corresponding TTaurusTLSX509Purpose
    ///  enumeration member.
    ///  </summary>
    ///  <param name="Value">
    ///  The OpenSSL TIdC_Int value.
    ///  </param>
    ///  <returns>
    ///  The TTaurusTLSX509Purpose member.
    ///  </returns>
    ///  <remarks>
    ///  This method validates that the input integer value maps to one
    ///  of the explicitly defined
    ///  <see cref="TTaurusTLSX509Purpose" /> constants. If no
    ///  corresponding constant is found, an <see cref="EInvalidCast" />
    ///  exception is raised.
    ///  </remarks>
    class function FromInt(Value: TIdC_Int): TTaurusTLSX509Purpose; static;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Checks if the current TTaurusTLSX509Purpose instance's integer value matches
    ///  the provided OpenSSL integer value.
    ///  </summary>
    ///  <param name="Value">
    ///  The OpenSSL TIdC_Int value to compare against.
    ///  </param>
    ///  <returns>
    ///  True if the values are equal.
    ///  </returns>
    function IsEqualTo(Value: TIdC_Int): boolean;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Gets or sets the corresponding OpenSSL integer constant value.
    ///  </summary>
    ///  <remarks>
    ///  This property maps the enumeration member to and from its native
    ///  OpenSSL integer constant. When writing, the input integer
    ///  must map exactly to one defined
    ///  <see cref="TTaurusTLSX509Purpose" /> constant;
    ///  otherwise, an <see cref="EInvalidCast" /> exception is raised.
    ///  </remarks>
    property AsInt: TIdC_Int read GetAsInt write SetAsInt;
  end;

  ///  <summary>
  ///  Represents a single X.509 hostname checking flag, corresponding
  ///  to an OpenSSL X509_CHECK_FLAG_* constant.
  ///  </summary>
  ///  <remarks>
  ///  These flags modify the strictness and behavior of certificate
  ///  hostname verification (e.g., wildcard allowance, subject check).
  ///  The ordinal value of each member represents the bit position (N)
  ///  in the underlying integer flag set, where the actual OpenSSL
  ///  constant is 1 &lt;&lt; N.
  ///  </remarks>
  TTaurusTLSX509HostCheckFlag = (
    hckAlwaysChkSubj      = $0, // 1 shl $0 = X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT
    hckNoWildcard         = $1, // 1 shl $1 = X509_CHECK_FLAG_NO_WILDCARDS
    hckNoPartWildcard     = $2, // 1 shl $2 = X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS
    hckMultiLblWildcard   = $3, // 1 shl $3 = X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS
    hckSingleLblSubDomain = $4  // 1 shl $4 = X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS
  );

  ///  <summary>
  ///  Provides methods for converting a single TTaurusTLSX509HostCheckFlag
  ///  enumeration member to and from its native C integer representation.
  ///  </summary>
  TTaurusTLSX509HostCheckFlagHelper = record helper for TTaurusTLSX509HostCheckFlag
  private
    function GetAsInt: TIdC_UINT; {$IFDEF USE_INLINE}inline;{$ENDIF}
    procedure SetAsInt(Value: TIdC_UINT); {$IFDEF USE_INLINE}inline;{$ENDIF}
  public
    ///  <summary>
    ///  Converts a single TTaurusTLSX509HostCheckFlag member into its corresponding
    ///  OpenSSL integer flag value (1 &lt;&lt; Ordinal).
    ///  </summary>
    ///  <param name="Value">The enumeration member to convert.</param>
    ///  <returns>
    ///  The OpenSSL TIdC_UINT (unsigned integer) flag value.
    ///  </returns>
    class function ToInt(Value: TTaurusTLSX509HostCheckFlag): TIdC_UINT; static;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Converts an OpenSSL integer flag value into its corresponding
    ///  TTaurusTLSX509HostCheckFlag enumeration member.
    ///  </summary>
    ///  <param name="Value">
    ///  The OpenSSL TIdC_UINT value (must be an exact power of 2).
    ///  </param>
    ///  <returns>
    ///  The TTaurusTLSX509HostCheckFlag member.
    ///  </returns>
    ///  <remarks>
    ///  This method validates that the input integer value represents
    ///  exactly one valid flag bit. If the value does not represent
    ///  exactly one valid flag bit, an <see cref="EInvalidCast" />
    ///  exception is raised.
    ///  </remarks>
    class function FromInt(Value: TIdC_UINT): TTaurusTLSX509HostCheckFlag; static;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Checks if the current TTaurusTLSX509HostCheckFlag instance's integer value
    ///  matches the provided OpenSSL flag value.
    ///  </summary>
    ///  <param name="Value">
    ///  The OpenSSL TIdC_UINT value to compare against.
    ///  </param>
    ///  <returns>
    ///  True if the values are equal.
    ///  </returns>
    function IsEqualTo(Value: TIdC_UINT): boolean;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Gets or sets the corresponding OpenSSL integer flag value
    ///  (1 &lt;&lt; Ordinal).
    ///  </summary>
    ///  <remarks>
    ///  When writing (Set), the input value must represent exactly one
    ///  valid flag bit; otherwise, an <see cref="EInvalidCast" /> exception
    ///  is raised.
    ///  </remarks>
    property AsInt: TIdC_UINT read GetAsInt write SetAsInt;
  end;

  ///  <summary>
  ///  Represents a set of X.509 hostname checking flags, equivalent to
  ///  the full OpenSSL integer bitmask used in hostname verification.
  ///  </summary>
 TTaurusTLSX509HostCheckFlags = set of TTaurusTLSX509HostCheckFlag;

  ///  <summary>
  ///  Provides methods for converting a TTaurusTLSX509HostCheckFlags set to and
  ///  from its native C integer bitmask representation.
  ///  </summary>
 TTaurusTLSX509HostCheckFlagsHelper = record helper for TTaurusTLSX509HostCheckFlags
  private
    function GetAsInt: TIdC_UINT; {$IFDEF USE_INLINE}inline;{$ENDIF}
    procedure SetAsInt(Value: TIdC_UINT); {$IFDEF USE_INLINE}inline;{$ENDIF}
  public
    ///  <summary>
    ///  Converts the TTaurusTLSX509HostCheckFlags set into a single OpenSSL
    ///  TIdC_UINT integer bitmask.
    ///  </summary>
    ///  <param name="Value">The set of flags to convert.</param>
    ///  <returns>
    ///  The combined TIdC_UINT bitmask value ready for OpenSSL functions.
    ///  </returns>
    class function ToInt(Value: TTaurusTLSX509HostCheckFlags): TIdC_UINT; static;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Converts an OpenSSL TIdC_UINT integer bitmask into a
    ///  TTaurusTLSX509HostCheckFlags set.
    ///  </summary>
    ///  <param name="Value">
    ///  The OpenSSL TIdC_UINT bitmask containing flags.
    ///  </param>
    ///  <returns>
    ///  The resulting TTaurusTLSX509HostCheckFlags set.
    ///  </returns>
    ///  <remarks>
    ///  This method validates that the input integer only contains bits
    ///  defined within the
    ///  <see cref="TTaurusTLSX509HostCheckFlag" /> enumeration
    ///  range. If the value contains any extraneous bits, an
    ///  <see cref="EInvalidCast" /> exception is raised.
    ///  </remarks>
    class function FromInt(Value: TIdC_UINT): TTaurusTLSX509HostCheckFlags; static;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Checks if the current TTaurusTLSX509HostCheckFlags set, when converted to an
    ///  integer mask, exactly matches the provided OpenSSL flag value.
    ///  </summary>
    ///  <param name="Value">
    ///  The OpenSSL TIdC_UINT value to compare against.
    ///  </param>
    ///  <returns>
    ///  True if the integer bitmasks are identical.
    ///  </returns>
    function IsEqualTo(Value: TIdC_UINT): boolean;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Gets or sets the flags as an OpenSSL TIdC_UINT integer bitmask.
    ///  </summary>
    ///  <remarks>
    ///  When writing (Set), the input value must exclusively contain bits
    ///  defined by the set. If any extraneous bits are present, an
    ///  <see cref="EInvalidCast" /> exception is raised.
    ///  </remarks>
    property AsInt: TIdC_UINT read GetAsInt write SetAsInt;
 end;

const
  ///  <summary>
  ///  A bitmask containing the logical OR of all OpenSSL
  ///  X.509 verification flags (X509_V_FLAG_*).
  ///  </summary>
  ///  <remarks>
  ///  This mask is used internally to validate that an integer value
  ///  being converted to a <see cref="TTaurusTLSX509VerifyFlags" /> set contains
  ///  only bits corresponding to the defined <see cref="TTaurusTLSX509VerifyFlags" />
  ///  enumeration members.
  ///  </remarks>
  cX509vfMask = X509_V_FLAG_USE_CHECK_TIME or X509_V_FLAG_CRL_CHECK
    or X509_V_FLAG_CRL_CHECK_ALL or X509_V_FLAG_IGNORE_CRITICAL
    or X509_V_FLAG_X509_STRICT or X509_V_FLAG_ALLOW_PROXY_CERTS
    or X509_V_FLAG_POLICY_CHECK or X509_V_FLAG_EXPLICIT_POLICY
    or X509_V_FLAG_INHIBIT_ANY or X509_V_FLAG_INHIBIT_MAP
    or X509_V_FLAG_NOTIFY_POLICY or X509_V_FLAG_EXTENDED_CRL_SUPPORT
    or X509_V_FLAG_USE_DELTAS or X509_V_FLAG_CHECK_SS_SIGNATURE
    or X509_V_FLAG_TRUSTED_FIRST or X509_V_FLAG_SUITEB_128_LOS_ONLY
    or X509_V_FLAG_SUITEB_192_LOS or X509_V_FLAG_SUITEB_128_LOS
    or X509_V_FLAG_PARTIAL_CHAIN or X509_V_FLAG_NO_ALT_CHAINS
    or X509_V_FLAG_NO_CHECK_TIME;

  ///  <summary>
  ///  A bitmask containing the logical OR of all OpenSSL X.509
  ///  verification parameter inheritance flags (X509_VP_FLAG_*).
  ///  </summary>
  ///  <remarks>
  ///  This mask is used internally to ensure that a converted integer
  ///  value contains only bits defined in the
  ///  <see cref="TTaurusTLSX509InheritanceFlag" /> enumeration.
  ///  </remarks>
  cX509ihfMask = X509_VP_FLAG_DEFAULT or X509_VP_FLAG_OVERWRITE
    or X509_VP_FLAG_RESET_FLAGS or X509_VP_FLAG_LOCKED or X509_VP_FLAG_ONCE;

  ///  <summary>
  ///  A bitmask containing the logical OR of all OpenSSL X.509
  ///  hostname checking flags (X509_CHECK_FLAG_*).
  ///  </summary>
  ///  <remarks>
  ///  This mask is used internally to validate that an integer value
  ///  being converted to a <see cref="TTaurusTLSX509HostCheckFlags" /> set contains
  ///  only bits corresponding to the defined <see cref="TTaurusTLSX509HostCheckFlag" />
  ///  enumeration members.
  ///  </remarks>
  cX509hckMask = X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT
    or X509_CHECK_FLAG_NO_WILDCARDS or X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS
    or X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS or X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS;



implementation

uses
  TaurusTLS_ResourceStrings;

{ TTaurusTLSSecurityBitsHelper }

function TTaurusTLSSecurityBitsHelper.GetAsInt: TIdC_INT;
begin
  Result:=Ord(Self);
end;

procedure TTaurusTLSSecurityBitsHelper.SetAsInt(AValue: TIdC_INT);
begin
  if (AValue in [0..5]) then
    Self:=TTaurusTLSSecurityBits(AValue)
  else
    ETaurusTLSSecurityBits.RaiseWithMessageFmt(RMSG_SecurityBits_Convert_err,
      [AValue]);
end;

{ TTaurusTLSSSLVersionHelper }

function TTaurusTLSSSLVersionHelper.GetAsInt: TIdC_LONG;
begin
  Result:=cMapping[Self];
end;

procedure TTaurusTLSSSLVersionHelper.SetAsInt(AValue: TIdC_LONG);
var
  i: TTaurusTLSSSLVersion;

begin
  for i:=Low(TTaurusTLSSSLVersion) to High(TTaurusTLSSSLVersion) do
    if AValue = cMapping[i] then
    begin
      Self:=i;
      Exit;
    end;
  ETaurusTLSSSLVersion.RaiseWithMessageFmt(RMSG_SSLVersion_Convert_err, [AValue]);
end;

{ TTaurusTLSCertificateVerifyFlagSet }

procedure TTaurusTLSCertificateVerifyFlagSet.SetFlags(
  AFlags: TTaurusTLSCertificateVerifyFlags);
begin
  if (AFlags - [cvfPeer]) <> [] then
    System.Include(AFlags, cvfPeer);
  Self:=AFlags;
end;

function TTaurusTLSCertificateVerifyFlagSet.GetAsInt: TIdC_INT;
begin
  {$IF SizeOf(Self) = 1}
  Result:=Byte(Self);
  {$ELSEIF SizeOf(Self) = 2}
  Result:=Word(Self);
  {$ELSEIF SizeOf(Self) >= 4}
  Result:=Integer(Self);
  {$IFEND}
  Result:=Result and cMask;
end;

procedure TTaurusTLSCertificateVerifyFlagSet.SetAsInt(AValue: TIdC_INT);
var
  lFlags: TTaurusTLSCertificateVerifyFlags;

begin
  AValue:=AValue and cMask;
  {$IF SizeOf(Self) = 1}
  Byte(lFlags):=Byte(AValue);
  {$ELSEIF SizeOf(Self) = 2}
  Word(lFlags):=Word(AValue);
  {$ELSEIF SizeOf(Self) >= 4}
  Integer(lFlags):=Integer(AValue);
  {$IFEND}
  SetFlags(lFlags);
end;

class operator TTaurusTLSCertificateVerifyFlagSet.Implicit(
  AFlags: TTaurusTLSCertificateVerifyFlagSet): TTaurusTLSCertificateVerifyFlags;
begin
  Result:=AFlags.FFlags;
end;

class operator TTaurusTLSCertificateVerifyFlagSet.Implicit(
  AFlags: TTaurusTLSCertificateVerifyFlags): TTaurusTLSCertificateVerifyFlagSet;
begin
  Result.SetFlags(AFlags);
end;

procedure TTaurusTLSCertificateVerifyFlagSet.Exclude(
  AFlag: TTaurusTLSCertificateVerifyFlag);
var
  lFlags: TTaurusTLSCertificateVerifyFlags;

begin
  lFlags:=FFlags;
  System.Exclude(lFlags, AFlag);
  SetFlags(lFLags);
end;

class procedure TTaurusTLSCertificateVerifyFlagSet.Exclude(
  var AValue: TTaurusTLSCertificateVerifyFlagSet;
  AFlag: TTaurusTLSCertificateVerifyFlag);
begin
  AValue.Exclude(AFlag);
end;

procedure TTaurusTLSCertificateVerifyFlagSet.Include(
  AFlag: TTaurusTLSCertificateVerifyFlag);
var
  lFlags: TTaurusTLSCertificateVerifyFlags;

begin
  lFlags:=FFlags;
  System.Include(lFlags, AFlag);
  SetFlags(lFLags);
end;

class procedure TTaurusTLSCertificateVerifyFlagSet.Include(
  var AValue: TTaurusTLSCertificateVerifyFlagSet;
  AFlag: TTaurusTLSCertificateVerifyFlag);
begin
  AValue.Include(AFlag);
end;

{ TTaurusTLSX509VerifyFlagHelper }

function TTaurusTLSX509VerifyFlagHelper.GetAsInt: TIdC_ULONG;
begin
  Result:=ToInt(Self);
end;

procedure TTaurusTLSX509VerifyFlagHelper.SetAsInt(
  Value: TIdC_ULONG);
begin
  Self:=FromInt(Value);
end;

class function TTaurusTLSX509VerifyFlagHelper.ToInt(
  Value: TTaurusTLSX509VerifyFlag): TIdC_ULONG;
begin
  Result:=TIdC_ULONG(1 shl Ord(Value)) and cX509vfMask;
end;

class function TTaurusTLSX509VerifyFlagHelper.FromInt(
  Value: TIdC_ULONG): TTaurusTLSX509VerifyFlag;
var
  i: TIdC_ULONG;

begin
  // check if AVal in range of OpenSSL X509_V_FLAG_* constants
  // and a single bit is set.
  if (Value = 0) or ((Value and (Value-1)) <> 0)
    or ((Value or cX509vfMask) <> cX509vfMask) then
    raise EInvalidCast.Create('Invalid X509 Verify Flag.');
  i:=Ord(Low(TTaurusTLSX509VerifyFlag));
  while (1 shl i) < Value do
    Inc(i);
  Result:=TTaurusTLSX509VerifyFlag(i);
end;

function TTaurusTLSX509VerifyFlagHelper.IsEqualTo(
  Value: TIdC_ULONG): boolean;
begin
  Result:=Value = AsInt;
end;

{ TTaurusTLSX509VerifyParam.TTaurusTLSX509VerifyFlagsHelper }

function TTaurusTLSX509VerifyFlagsHelper.GetAsInt: TIdC_ULONG;
begin
  Result:=ToInt(Self);
end;

procedure TTaurusTLSX509VerifyFlagsHelper.SetAsInt(
  Value: TIdC_ULONG);
begin
  Self:=FromInt(Value);
end;

procedure TTaurusTLSX509VerifyFlagsHelper.SetSafeAsInt(
  Value: TIdC_ULONG);
begin
  Self:=SafeFromInt(Value);
end;

class function TTaurusTLSX509VerifyFlagsHelper.ToInt(
  Value: TTaurusTLSX509VerifyFlags): TIdC_ULONG;
begin
  Result:=(TIdC_ULONG((@Value)^) and cX509vfMask);
end;

class function TTaurusTLSX509VerifyFlagsHelper.FromInt(
  Value: TIdC_ULONG): TTaurusTLSX509VerifyFlags;
begin
  if (Value or cX509vfMask) <> cX509vfMask then
    raise EInvalidCast.Create('Invalid X509 Verify Flags.');
//{$I RangeCheck-OFF.inc}
  Result:=TTaurusTLSX509VerifyFlags((@Value)^);
//{$I RangeCheck-ON.inc}
end;

class function TTaurusTLSX509VerifyFlagsHelper.SafeFromInt(
  Value: TIdC_ULONG): TTaurusTLSX509VerifyFlags;
begin
  Value:=Value and cX509vfMask;
//{$I RangeCheck-OFF.inc}
  Result:=TTaurusTLSX509VerifyFlags((@Value)^);
//{$I RangeCheck-ON.inc}
end;

function TTaurusTLSX509VerifyFlagsHelper.IsEqualTo(
  Value: TIdC_ULONG): boolean;
begin
  Result:=Value = AsInt;
end;

{ TTaurusTLSX509InheritanceFlagHelper }

function TTaurusTLSX509InheritanceFlagHelper.GetAsInt: TIdC_UINT32;
begin
  Result:=ToInt(Self);
end;

procedure TTaurusTLSX509InheritanceFlagHelper.SetAsInt(
  Value: TIdC_UINT32);
begin
  Self:=FromInt(Value);
end;

class function TTaurusTLSX509InheritanceFlagHelper.ToInt(
  Value: TTaurusTLSX509InheritanceFlag): TIdC_UINT32;
begin
  Result:=TIdC_UINT32(1 shl Ord(Value)) and cX509ihfMask;
end;

class function TTaurusTLSX509InheritanceFlagHelper.FromInt(
  Value: TIdC_UINT32): TTaurusTLSX509InheritanceFlag;
var
  i: TIdC_UINT32;

begin
  // check if AVal in range of OpenSSL X509_VP_FLAG_* constants
  // and a single bit is set.
  if (Value = 0) or ((Value and (Value-1)) <> 0)
    or ((Value or cX509ihfMask) <> cX509ihfMask) then
    raise EInvalidCast.Create('Invalid X509 Inheritance Flag.');
  i:=Ord(Low(TTaurusTLSX509InheritanceFlag));
  while (1 shl i) < Value do
    Inc(i);
//{$I RangeCheck-OFF.inc}
  Result:=TTaurusTLSX509InheritanceFlag(i);
//{$I RangeCheck-ON.inc}
end;

function TTaurusTLSX509InheritanceFlagHelper.IsEqualTo(
  Value: TIdC_UINT32): boolean;
begin
  Result:=Value = AsInt;
end;

{ TTaurusTLSX509InheritanceFlagsHelper }

function TTaurusTLSX509InheritanceFlagsHelper.GetAsInt: TIdC_UINT32;
begin
  Result:=ToInt(Self);
end;

procedure TTaurusTLSX509InheritanceFlagsHelper.SetAsInt(
  Value: TIdC_UINT32);
begin
  Self:=FromInt(Value);
end;

class function TTaurusTLSX509InheritanceFlagsHelper.ToInt(
  Value: TTaurusTLSX509InheritanceFlags): TIdC_UINT32;
begin
  Result:=(TIdC_UINT32((@Value)^) and cX509ihfMask);
end;

class function TTaurusTLSX509InheritanceFlagsHelper.FromInt(
  Value: TIdC_UINT32): TTaurusTLSX509InheritanceFlags;
begin
  if (Value or cX509ihfMask) <> cX509ihfMask then
    raise EInvalidCast.Create('Invalid X509 Inheritance Flags.');
//{$I RangeCheck-OFF.inc}
  Result:=TTaurusTLSX509InheritanceFlags((@Value)^);
//{$I RangeCheck-ON.inc}
end;

function TTaurusTLSX509InheritanceFlagsHelper.IsEqualTo(
  Value: TIdC_UINT32): boolean;
begin
  Result:=Value = AsInt;
end;

{ TTaurusTLSX509Helper }

function TTaurusTLSX509TrustHelper.GetAsInt: TIdC_Int;
begin
  Result:=ToInt(Self);
end;

procedure TTaurusTLSX509TrustHelper.SetAsInt(
  Value: TIdC_Int);
begin
  Self:=FromInt(Value);
end;

class function TTaurusTLSX509TrustHelper.FromInt(
  Value: TIdC_Int): TTaurusTLSX509Trust;
begin
  if (Value < Ord(Low(TTaurusTLSX509Trust))) or (Value > Ord(High(TTaurusTLSX509Trust))) then
    raise EInvalidCast.Create('Invalid X509 Trust Flag.');
//{$I RangeCheck-OFF.inc}
  Result:=TTaurusTLSX509Trust(Value);
//{$I RangeCheck-ON.inc}
end;

class function TTaurusTLSX509TrustHelper.ToInt(
  Value: TTaurusTLSX509Trust): TIdC_Int;
begin
  Result:=Ord(Value);
end;

function TTaurusTLSX509TrustHelper.IsEqualTo(
  Value: TIdC_Int): boolean;
begin
  Result:=Value = AsInt;
end;

{ TTaurusTLSX509PurposeHelper }

function TTaurusTLSX509PurposeHelper.GetAsInt: TIdC_Int;
begin
  Result:=ToInt(Self);
end;

procedure TTaurusTLSX509PurposeHelper.SetAsInt(
  Value: TIdC_Int);
begin
  Self:=FromInt(Value);
end;

class function TTaurusTLSX509PurposeHelper.FromInt(
  Value: TIdC_Int): TTaurusTLSX509Purpose;
begin
  if (Value < Ord(Low(TTaurusTLSX509Purpose))) or (Value > Ord(High(TTaurusTLSX509Purpose))) then
    raise EInvalidCast.Create('Invalid X509 Trust Flag.');
//{$I RangeCheck-OFF.inc}
  Result:=TTaurusTLSX509Purpose(Value);
//{$I RangeCheck-ON.inc}
end;

class function TTaurusTLSX509PurposeHelper.ToInt(
  Value: TTaurusTLSX509Purpose): TIdC_Int;
begin
  Result:=Ord(Value);
end;

function TTaurusTLSX509PurposeHelper.IsEqualTo(
  Value: TIdC_Int): boolean;
begin
  Result:=Value = AsInt;
end;

{ TTaurusTLSX509HostCheckFlagHelper }

function TTaurusTLSX509HostCheckFlagHelper.GetAsInt: TIdC_UINT;
begin
  Result:=ToInt(Self);
end;

procedure TTaurusTLSX509HostCheckFlagHelper.SetAsInt(
  Value: TIdC_UINT);
begin
  Self:=FromInt(Value);
end;

class function TTaurusTLSX509HostCheckFlagHelper.FromInt(
  Value: TIdC_UINT): TTaurusTLSX509HostCheckFlag;
var
  i: TIdC_UINT;

begin
  // check if AVal in range of OpenSSL X509_CHECK_FLAG_* constants
  // and a single bit is set.
  if (Value = 0) or ((Value and (Value-1)) <> 0)
    or ((Value or cX509hckMask) <> cX509hckMask) then
    raise EInvalidCast.Create('Invalid X509 Host Check Verify Flag.');
  i:=Ord(Low(TTaurusTLSX509HostCheckFlag));
  while (1 shl i) < Value do
    Inc(i);
//{$I RangeCheck-OFF.inc}
  Result:=TTaurusTLSX509HostCheckFlag(i);
//{$I RangeCheck-ON.inc}
end;

class function TTaurusTLSX509HostCheckFlagHelper.ToInt(
  Value: TTaurusTLSX509HostCheckFlag): TIdC_UINT;
begin
  Result:=TIdC_UINT(1 shl Ord(Value));
end;

function TTaurusTLSX509HostCheckFlagHelper.IsEqualTo(
  Value: TIdC_UINT): boolean;
begin
  Result:=Value = AsInt;
end;

{ TTaurusTLSX509HostCheckFlagsHelper }

function TTaurusTLSX509HostCheckFlagsHelper.GetAsInt: TIdC_UINT;
begin
  Result:=ToInt(Self);
end;

procedure TTaurusTLSX509HostCheckFlagsHelper.SetAsInt(
  Value: TIdC_UINT);
begin
  Self:=FromInt(Value);
end;

class function TTaurusTLSX509HostCheckFlagsHelper.FromInt(
  Value: TIdC_UINT): TTaurusTLSX509HostCheckFlags;
begin
  // check if AVal in range of OpenSSL X509_CHECK_FLAG_* constants
  // and a single bit is set.
  if ((Value or cX509hckMask) <> cX509hckMask) then
    raise EInvalidCast.Create('Invalid X509 Host Check Verify Flags.');
//{$I RangeCheck-OFF.inc}
  Result:=TTaurusTLSX509HostCheckFlags((@Value)^);
//{$I RangeCheck-ON.inc}
end;

class function TTaurusTLSX509HostCheckFlagsHelper.ToInt(
  Value: TTaurusTLSX509HostCheckFlags): TIdC_UINT;
begin
  Result:=(TIdC_UINT((@Value)^) and cX509hckMask);
end;

function TTaurusTLSX509HostCheckFlagsHelper.IsEqualTo(
  Value: TIdC_UINT): boolean;
begin
  Result:=Value = AsInt;
end;

end.
