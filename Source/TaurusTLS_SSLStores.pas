{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2026 TaurusTLS Developers, All Rights Reserved              * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 - 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew - http://www.IndyProject.org/  * }
{ ****************************************************************************** }

{$I TaurusTLSCompilerDefines.inc}
/// <summary>
///   Declares set of classes and interfaces to operate with
///   <see href="https://docs.openssl.org/3.5/man3/X509_STORE_add_cert/#description">X509_STORE</see>
/// </summary>

unit TaurusTLS_SSLStores;
{$I TaurusTLSLinkDefines.inc}

interface

uses
  SysUtils,
  Classes,
  Generics.Collections,
  DateUtils,
  IdGlobal,
  IdCTypes,
  IdIpAddress,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_evp,
  TaurusTLSHeaders_pem,
  TaurusTLSHeaders_store,
  TaurusTLSHeaders_x509,
  TaurusTLSHeaders_x509v3,
  TaurusTLSHeaders_x509_vfy,
  TaurusTLSExceptionHandlers,
  TaurusTLS_types,
  TaurusTLS_BIO,
  TaurusTLS_SSLUi;

type
  ETaurusTLSX509StoreError = class(ETaurusTLSAPICryptoError);
  ETaurusTLSX509StoreThreadError = class(Exception);
  ETaurusTLSOSSLStoreError = class(ETaurusTLSAPICryptoError);

type
  ///  <summary>
  ///  Abstract base class providing an object-oriented interface for
  ///  managing certificate verification parameters.
  ///  </summary>
  ///  <remarks>
  ///  This class encapsulates all settings (flags, hostnames, IP address,
  ///  time, and depth) required for checking the validity and trust
  ///  of a certificate chain during an SSL/TLS handshake.
  ///  </remarks>
  TTaurusTLSCustomX509VerifyParam = class abstract
  public type
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
    TVerifyFlag = (
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
//      x509vfSuiteB128                         // X509_V_FLAG_SUITEB_128_LOS = X509_V_FLAG_SUITEB_128_LOS_ONLY + X509_V_FLAG_SUITEB_192_LOS
      x509vfPartialChain              = $13, // 1 shl $13 = X509_V_FLAG_PARTIAL_CHAIN
      x509vfNoAlternativeChain        = $14, // 1 shl $14 = X509_V_FLAG_NO_ALT_CHAINS
      x509vfNoCheckTime               = $15  // 1 shl $15 = X509_V_FLAG_NO_CHECK_TIME
    );

    ///  <summary>
    ///  Provides methods for converting a single TVerifyFlag enumeration member
    ///  to and from its native C integer representation.
    ///  </summary>
    TVerifyFlagHelper = record helper for TVerifyFlag
    private
      function GetAsInt: TIdC_ULONG; {$IFDEF USE_INLINE}inline;{$ENDIF}
      procedure SetAsInt(Value: TIdC_ULONG); {$IFDEF USE_INLINE}inline;{$ENDIF}

    public
      ///  <summary>
      ///  Converts a single TVerifyFlag enumeration member into its
      ///  corresponding OpenSSL integer flag value.
      ///  </summary>
      ///  <param name="Value">The enumeration member to convert.</param>
      ///  <returns>
      ///  The OpenSSL TIdC_ULONG (unsigned long) flag value.
      ///  </returns>
      class function ToInt(Value: TVerifyFlag): TIdC_ULONG; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Converts an OpenSSL integer flag value into its corresponding
      ///  TVerifyFlag enumeration member.
      ///  </summary>
      ///  <param name="Value">
      ///  The OpenSSL TIdC_ULONG value (must be an exact power of 2).
      ///  </param>
      ///  <returns>
      ///  The TVerifyFlag member.
      ///  </returns>
      ///  <remarks>
      ///  This method validates that the input integer value is a single,
      ///  valid flag defined in TVerifyFlag. If the value does not represent
      ///  exactly one valid flag bit, an EInvalidCast exception is raised.
      ///  </remarks>
      class function FromInt(Value: TIdC_ULONG): TVerifyFlag; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Checks if the current TVerifyFlag instance's integer value matches
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
    TVerifyFlags = set of TVerifyFlag;

    ///  <summary>
    ///  Provides methods for converting a TVerifyFlags set to and
    ///  from its native C integer bitmask representation.
    ///  </summary>
    TVerifyFlagsHelper = record helper for TVerifyFlags
    private
      function GetAsInt: TIdC_ULONG; {$IFDEF USE_INLINE}inline;{$ENDIF}
      procedure SetAsInt(Value: TIdC_ULONG); {$IFDEF USE_INLINE}inline;{$ENDIF}
      procedure SetSafeAsInt(Value: TIdC_ULONG); {$IFDEF USE_INLINE}inline;{$ENDIF}

    public
      ///  <summary>
      ///  Converts the TVerifyFlags set into a single OpenSSL TIdC_ULONG
      ///  integer bitmask.
      ///  </summary>
      ///  <param name="Value">The set of flags to convert.</param>
      ///  <returns>
      ///  The combined TIdC_ULONG bitmask value ready for OpenSSL functions.
      ///  </returns>
      class function ToInt(Value: TVerifyFlags): TIdC_ULONG; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Converts an OpenSSL TIdC_ULONG integer bitmask into a
      ///  TVerifyFlags set.
      ///  </summary>
      ///  <param name="Value">
      ///  The OpenSSL TIdC_ULONG bitmask containing flags.
      ///  </param>
      ///  <returns>
      ///  The resulting TVerifyFlags set.
      ///  </returns>
      ///  <remarks>
      ///  This method validates that the input integer only contains bits
      ///  defined within the TVerifyFlag enumeration range. If the value
      ///  contains any bits corresponding to undefined flags (internal OpenSSL
      ///  constants), an <see cref="EInvalidCast" /> exception is raised.
      ///  </remarks>
      class function FromInt(Value: TIdC_ULONG): TVerifyFlags; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Converts an OpenSSL TIdC_ULONG integer bitmask into a
      ///  TVerifyFlags set without strict validation.
      ///  </summary>
      ///  <param name="Value">
      ///  The OpenSSL TIdC_ULONG bitmask containing flags.
      ///  </param>
      ///  <returns>
      ///  The resulting TVerifyFlags set, with undefined bits being ignored.
      ///  </returns>
      ///  <remarks>
      ///  This method is useful when dealing with values returned by OpenSSL
      ///  which may contain internal, undocumented, or non-public flags.
      ///  Any undefined bit is simply masked out and suppressed.
      ///  </remarks>
      class function SafeFromInt(Value: TIdC_ULONG): TVerifyFlags; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Checks if the current TVerifyFlags set, when converted to an
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
    TInheritanceFlag = (
      x509ihfDefault                  = $0, // 1 shl $0 = X509_VP_FLAG_DEFAULT
      x509ihfOverrite                 = $1, // 1 shl $1 = X509_VP_FLAG_OVERWRITE
      x509ihfReset                    = $2, // 1 shl $2 = X509_VP_FLAG_RESET_FLAGS
      x509ihfLocked                   = $3, // 1 shl $3 = X509_VP_FLAG_LOCKED
      x509ihfOnce                     = $4  // 1 shl $4 = X509_VP_FLAG_ONCE
    );


    ///  <summary>
    ///  Provides methods for converting a single TInheritanceFlag
    ///  enumeration member to and from its native C integer representation.
    ///  </summary>
    TInheritanceFlagHelper = record helper for TInheritanceFlag
    private
      function GetAsInt: TIdC_UINT32; {$IFDEF USE_INLINE}inline;{$ENDIF}
      procedure SetAsInt(Value: TIdC_UINT32); {$IFDEF USE_INLINE}inline;{$ENDIF}
    public
      ///  <summary>
      ///  Converts a single TInheritanceFlag member into its corresponding
      ///  OpenSSL integer flag value (1 &lt;&lt; Ordinal).
      ///  </summary>
      ///  <param name="Value">The enumeration member to convert.</param>
      ///  <returns>
      ///  The OpenSSL TIdC_UINT32 (unsigned 32-bit integer) flag value.
      ///  </returns>
      class function ToInt(Value: TInheritanceFlag): TIdC_UINT32; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Converts an OpenSSL integer flag value into its corresponding
      ///  TInheritanceFlag enumeration member.
      ///  </summary>
      ///  <param name="Value">
      ///  The OpenSSL TIdC_UINT32 value (must be an exact power of 2).
      ///  </param>
      ///  <returns>
      ///  The TInheritanceFlag member.
      ///  </returns>
      ///  <remarks>
      ///  This method validates that the input integer value is a single,
      ///  valid flag defined in TInheritanceFlag. If the value does not
      ///  represent exactly one valid flag bit, an <see cref="EInvalidCast" />
      ///  exception is raised.
      ///  </remarks>
      class function FromInt(Value: TIdC_UINT32): TInheritanceFlag; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Checks if the current TInheritanceFlag instance's integer value
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
    TInheritanceFlags = set of TInheritanceFlag;

    ///  <summary>
    ///  Provides methods for converting a TInheritanceFlags set to and
    ///  from its native C integer bitmask representation.
    ///  </summary>
    TInheritanceFlagsHelper = record helper for TInheritanceFlags
    private
      function GetAsInt: TIdC_UINT32; {$IFDEF USE_INLINE}inline;{$ENDIF}
      procedure SetAsInt(Value: TIdC_UINT32); {$IFDEF USE_INLINE}inline;{$ENDIF}
    public
      ///  <summary>
      ///  Converts the TInheritanceFlags set into a single OpenSSL
      ///  TIdC_UINT32 integer bitmask.
      ///  </summary>
      ///  <param name="Value">The set of flags to convert.</param>
      ///  <returns>
      ///  The combined TIdC_UINT32 bitmask value ready for OpenSSL functions.
      ///  </returns>
      class function ToInt(Value: TInheritanceFlags): TIdC_UINT32; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Converts an OpenSSL TIdC_UINT32 integer bitmask into a
      ///  TInheritanceFlags set.
      ///  </summary>
      ///  <param name="Value">
      ///  The OpenSSL TIdC_UINT32 bitmask containing flags.
      ///  </param>
      ///  <returns>
      ///  The resulting TInheritanceFlags set.
      ///  </returns>
      ///  <remarks>
      ///  This method validates that the input integer only contains bits
      ///  defined within
      ///  the <see cref="TTaurusTLSCustomX509VerifyParam.TInheritanceFlag" />
      ///  enumeration range. If the value contains any extraneous bits, an
      ///  <see cref="EInvalidCast" /> exception is raised.
      ///  </remarks>
      class function FromInt(Value: TIdC_UINT32): TInheritanceFlags; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Checks if the current TInheritanceFlags set, when converted to an
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
    TTrust = (
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
    ///  Provides methods for converting a TTrust enumeration member to and
    ///  from its native C integer value.
    ///  </summary>
    TTrustHelper = record helper for TTrust
    private
      function GetAsInt: TIdC_Int; {$IFDEF USE_INLINE}inline;{$ENDIF}
      procedure SetAsInt(Value: TIdC_Int); {$IFDEF USE_INLINE}inline;{$ENDIF}
    public
      ///  <summary>
      ///  Converts a TTrust member into its corresponding OpenSSL integer
      ///  constant value.
      ///  </summary>
      ///  <param name="Value">The enumeration member to convert.</param>
      ///  <returns>
      ///  The OpenSSL TIdC_Int value.
      ///  </returns>
      class function ToInt(Value: TTrust): TIdC_Int; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Converts an OpenSSL integer value into its corresponding TTrust
      ///  enumeration member.
      ///  </summary>
      ///  <param name="Value">
      ///  The OpenSSL TIdC_Int value.
      ///  </param>
      ///  <returns>
      ///  The TTrust member.
      ///  </returns>
      ///  <remarks>
      ///  This method validates that the input integer value maps to one
      ///  of the explicitly defined
      ///  <see cref="TTaurusTLSCustomX509VerifyParam.TTrust" /> constants. If no
      ///  corresponding constant is found, an <see cref="EInvalidCast" />
      ///  exception is raised.
      ///  </remarks>
      class function FromInt(Value: TIdC_Int): TTrust; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Checks if the current TTrust instance's integer value matches
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
      ///  <see cref="TTaurusTLSCustomX509VerifyParam.TTrust" /> constant;
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
    TPurpose = (
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
    ///  Provides methods for converting a TPurpose enumeration member to and
    ///  from its native C integer value.
    ///  </summary>
    TPurposeHelper = record helper for TPurpose
    private
      function GetAsInt: TIdC_Int; {$IFDEF USE_INLINE}inline;{$ENDIF}
      procedure SetAsInt(Value: TIdC_Int); {$IFDEF USE_INLINE}inline;{$ENDIF}
    public
      ///  <summary>
      ///  Converts a TPurpose member into its corresponding OpenSSL integer
      ///  constant value.
      ///  </summary>
      ///  <param name="Value">The enumeration member to convert.</param>
      ///  <returns>
      ///  The OpenSSL TIdC_Int value.
      ///  </returns>
      class function ToInt(Value: TPurpose): TIdC_Int; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Converts an OpenSSL integer value into its corresponding TPurpose
      ///  enumeration member.
      ///  </summary>
      ///  <param name="Value">
      ///  The OpenSSL TIdC_Int value.
      ///  </param>
      ///  <returns>
      ///  The TPurpose member.
      ///  </returns>
      ///  <remarks>
      ///  This method validates that the input integer value maps to one
      ///  of the explicitly defined
      ///  <see cref="TTaurusTLSCustomX509VerifyParam.TPurpose" /> constants. If no
      ///  corresponding constant is found, an <see cref="EInvalidCast" />
      ///  exception is raised.
      ///  </remarks>
      class function FromInt(Value: TIdC_Int): TPurpose; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Checks if the current TPurpose instance's integer value matches
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
      ///  <see cref="TTaurusTLSCustomX509VerifyParam.TPurpose" /> constant;
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
    THostCheckFlag = (
      hckAlwaysChkSubj      = $0, // 1 shl $0 = X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT
      hckNoWildcard         = $1, // 1 shl $1 = X509_CHECK_FLAG_NO_WILDCARDS
      hckNoPartWildcard     = $2, // 1 shl $2 = X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS
      hckMultiLblWildcard   = $3, // 1 shl $3 = X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS
      hckSingleLblSubDomain = $4  // 1 shl $4 = X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS
    );

    ///  <summary>
    ///  Provides methods for converting a single THostCheckFlag
    ///  enumeration member to and from its native C integer representation.
    ///  </summary>
    THostCheckFlagHelper = record helper for THostCheckFlag
    private
      function GetAsInt: TIdC_UINT; {$IFDEF USE_INLINE}inline;{$ENDIF}
      procedure SetAsInt(Value: TIdC_UINT); {$IFDEF USE_INLINE}inline;{$ENDIF}
    public
      ///  <summary>
      ///  Converts a single THostCheckFlag member into its corresponding
      ///  OpenSSL integer flag value (1 &lt;&lt; Ordinal).
      ///  </summary>
      ///  <param name="Value">The enumeration member to convert.</param>
      ///  <returns>
      ///  The OpenSSL TIdC_UINT (unsigned integer) flag value.
      ///  </returns>
      class function ToInt(Value: THostCheckFlag): TIdC_UINT; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Converts an OpenSSL integer flag value into its corresponding
      ///  THostCheckFlag enumeration member.
      ///  </summary>
      ///  <param name="Value">
      ///  The OpenSSL TIdC_UINT value (must be an exact power of 2).
      ///  </param>
      ///  <returns>
      ///  The THostCheckFlag member.
      ///  </returns>
      ///  <remarks>
      ///  This method validates that the input integer value represents
      ///  exactly one valid flag bit. If the value does not represent
      ///  exactly one valid flag bit, an <see cref="EInvalidCast" />
      ///  exception is raised.
      ///  </remarks>
      class function FromInt(Value: TIdC_UINT): THostCheckFlag; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Checks if the current THostCheckFlag instance's integer value
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
   THostCheckFlags = set of THostCheckFlag;

    ///  <summary>
    ///  Provides methods for converting a THostCheckFlags set to and
    ///  from its native C integer bitmask representation.
    ///  </summary>
   THostCheckFlagsHelper = record helper for THostCheckFlags
    private
      function GetAsInt: TIdC_UINT; {$IFDEF USE_INLINE}inline;{$ENDIF}
      procedure SetAsInt(Value: TIdC_UINT); {$IFDEF USE_INLINE}inline;{$ENDIF}
    public
      ///  <summary>
      ///  Converts the THostCheckFlags set into a single OpenSSL
      ///  TIdC_UINT integer bitmask.
      ///  </summary>
      ///  <param name="Value">The set of flags to convert.</param>
      ///  <returns>
      ///  The combined TIdC_UINT bitmask value ready for OpenSSL functions.
      ///  </returns>
      class function ToInt(Value: THostCheckFlags): TIdC_UINT; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Converts an OpenSSL TIdC_UINT integer bitmask into a
      ///  THostCheckFlags set.
      ///  </summary>
      ///  <param name="Value">
      ///  The OpenSSL TIdC_UINT bitmask containing flags.
      ///  </param>
      ///  <returns>
      ///  The resulting THostCheckFlags set.
      ///  </returns>
      ///  <remarks>
      ///  This method validates that the input integer only contains bits
      ///  defined within the
      ///  <see cref="TTaurusTLSCustomX509VerifyParam.THostCheckFlag" /> enumeration
      ///  range. If the value contains any extraneous bits, an
      ///  <see cref="EInvalidCast" /> exception is raised.
      ///  </remarks>
      class function FromInt(Value: TIdC_UINT): THostCheckFlags; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Checks if the current THostCheckFlags set, when converted to an
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

  public const
    ///  <summary>
    ///  A bitmask containing the logical OR of all OpenSSL
    ///  X.509 verification flags (X509_V_FLAG_*).
    ///  </summary>
    ///  <remarks>
    ///  This mask is used internally to validate that an integer value
    ///  being converted to a <see cref="TVerifyFlags" /> set contains
    ///  only bits corresponding to the defined <see cref="TVerifyFlag" />
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
    ///  <see cref="TInheritanceFlag" /> enumeration.
    ///  </remarks>
    cX509ihfMask = X509_VP_FLAG_DEFAULT or X509_VP_FLAG_OVERWRITE
      or X509_VP_FLAG_RESET_FLAGS or X509_VP_FLAG_LOCKED or X509_VP_FLAG_ONCE;

    ///  <summary>
    ///  A bitmask containing the logical OR of all OpenSSL X.509
    ///  hostname checking flags (X509_CHECK_FLAG_*).
    ///  </summary>
    ///  <remarks>
    ///  This mask is used internally to validate that an integer value
    ///  being converted to a <see cref="THostCheckFlags" /> set contains
    ///  only bits corresponding to the defined <see cref="THostCheckFlag" />
    ///  enumeration members.
    ///  </remarks>
    cX509hckMask = X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT
      or X509_CHECK_FLAG_NO_WILDCARDS or X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS
      or X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS or X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS;

  private
    FParam: PX509_VERIFY_PARAM ;
    function GetVerifyFlags: TVerifyFlags;
    procedure SetVerifyFlags(const Value: TVerifyFlags);
    function GetInheritanceFlags: TInheritanceFlags;
    procedure SetInheritanceFlags(const Value: TInheritanceFlags);
    function GetDepht: TIdC_Int;
    procedure SetDepth(const Value: TIdC_Int);
    function GetAuthLevel: TTaurusTLSSecurityBits;
    procedure SetAuthLevel(const Value: TTaurusTLSSecurityBits);
    function GetTime: TDateTime;
    procedure SetTime(const Value: TDateTime);
    function GetHostCheckFlags: THostCheckFlags;
    procedure SetHostCheckFlags(const Value: THostCheckFlags);
    function GetPurpose: TPurpose;
    procedure SetPurpose(Value: TPurpose);

  protected
    ///  <summary>
    ///  Initializes instance using the native verification parameter
    ///  structure pointer.
    ///  </summary>
    ///  <param name="AParam">The native pointer to the structure.</param>
    constructor Create(AParam: PX509_VERIFY_PARAM);

    ///  <summary>
    ///  Provides direct access to the native verification parameter pointer.
    ///  </summary>
    property VfyParam: PX509_VERIFY_PARAM read FParam;
  public
    ///  <summary>
    ///  Retrieves the raw C-style string pointer to a hostname set for
    ///  verification.
    ///  </summary>
    ///  <param name="ANumber">Index of the hostname to retrieve.</param>
    ///  <returns>A PIdAnsiChar pointer to the string data.</returns>
    function GetHostRaw(ANumber: TIdC_Int): PIdAnsiChar;

    ///  <summary>
    ///  Retrieves a hostname stored for verification as an AnsiString.
    ///  </summary>
    ///  <param name="ANumber">Index of the hostname to retrieve.</param>
    function GetHostA(ANumber: TIdC_Int): RawByteString;

    ///  <summary>
    ///  Retrieves a hostname stored for verification as a Unicode string.
    ///  </summary>
    ///  <param name="ANumber">Index of the hostname to retrieve.</param>
    function GetHostW(ANumber: TIdC_Int): UnicodeString;

    ///  <summary>
    ///  Sets a single hostname for verification (AnsiString).
    ///  </summary>
    ///  <param name="Value">The hostname string.</param>
    ///  <remarks>
    ///  Method value clears hostnames list before setting new one.
    ///  Emtpy value <c>Value</c> keeps it empty.
    ///  </remarks>
    procedure SetHostA(Value: RawByteString);

    ///  <summary>
    ///  Sets a single hostname for verification (UnicodeString).
    ///  </summary>
    ///  <param name="Value">The hostname string.</param>
    ///  <remarks>
    ///  Method value clears hostnames list before setting new one.
    ///  Emtpy value <c>Value</c> keeps it empty.
    ///  </remarks>
    procedure SetHostW(Value: UnicodeString);

    ///  <summary>
    ///  Adds a hostname (AnsiString) to the list checked during
    ///  verification.
    ///  </summary>
    ///  <param name="Value">The hostname string.</param>
    procedure AddHostA(Value: RawByteString);

    ///  <summary>
    ///  Adds a hostname (UnicodeString) to the list checked during
    ///  verification.
    ///  </summary>
    ///  <param name="Value">The hostname string.</param>
    procedure AddHostW(Value: UnicodeString);

    ///  <summary>
    ///  Retrieves the PerName identity for application domain checks
    ///  as an AnsiString.
    ///  </summary>
    function GetPerNameA: RawByteString;

    ///  <summary>
    ///  Retrieves the PerName identity for application domain checks
    ///  as a Unicode string.
    ///  </summary>
    function GetPerNameW: UnicodeString;

    ///  <summary>
    ///  Retrieves the raw C-style string pointer to the email address set for
    ///  identity checking.
    ///  </summary>
    ///  <returns>A PIdAnsiChar pointer to the string data.</returns>
    function GetEmailRaw: PIdAnsiChar;

    ///  <summary>
    ///  Retrieves the expected email address as an Ansi or UTF8 string.
    ///  </summary>
    function GetEmailA: RawByteString;

    ///  <summary>
    ///  Retrieves the expected email address as a Unicode string.
    ///  </summary>
    function GetEmailW: UnicodeString;

    ///  <summary>
    ///  Sets the expected email address (Ansi or UTF8 String) for identity
    ///  checking.
    ///  </summary>
    ///  <param name="Value">The email address string.</param>
    procedure SetEMailA(Value: RawByteString);

    ///  <summary>
    ///  Sets the expected email address (UnicodeString) for identity
    ///  checking.
    ///  </summary>
    ///  <param name="Value">The email address string.</param>
    procedure SetEMailW(Value: UnicodeString);

    ///  <summary>
    ///  Sets the expected IP address using a TIdIPAddress record.
    ///  </summary>
    ///  <param name="Value">The IP address structure.</param>
    procedure SetIpAddress(Value: TIdIPAddress);

    ///  <summary>
    ///  Sets the expected IP address (AnsiString) for identity
    ///  checking.
    ///  </summary>
    ///  <param name="Value">The IP address string.</param>
    procedure SetIpAddressA(Value: RawByteString);

    ///  <summary>
    ///  Sets the expected IP address (UnicodeString) for identity
    ///  checking.
    ///  </summary>
    ///  <param name="Value">The IP address string.</param>
    procedure SetIpAddressW(Value: UnicodeString);

    ///  <summary>
    ///  Retrieves the expected IP address as an AnsiString.
    ///  </summary>
    function GetIpAddressA: RawByteString;

    ///  <summary>
    ///  Retrieves the expected IP address as a Unicode string.
    ///  </summary>
    function GetIpAddressW: UnicodeString;

    ///  <summary>
    ///  Gets or sets flags controlling certificate path validation
    ///  (e.g., CRL checking, policy enforcement).
    ///  </summary>
    property VerifyFlags: TVerifyFlags read GetVerifyFlags write SetVerifyFlags;

    ///  <summary>
    ///  Gets or sets flags controlling how verification parameters are
    ///  inherited or reset in subordinate contexts.
    ///  </summary>
    property InheritanceFlags: TInheritanceFlags read GetInheritanceFlags
      write SetInheritanceFlags;

    ///  <summary>
    ///  Gets or sets flags controlling the strictness of hostname and
    ///  IP address matching.
    ///  </summary>
    property HostCheckFlags: THostCheckFlags read GetHostCheckFlags
      write SetHostCheckFlags;

    ///  <summary>
    ///  Gets or sets the expected role or usage of the certificate
    ///  (e.g., SSL Server, SMIME Signing).
    ///  </summary>
    property Purpose: TPurpose read GetPurpose write SetPurpose;

    ///  <summary>
    ///  Gets or sets the maximum acceptable chain length for verification.
    ///  </summary>
    property Depth: TIdC_Int read GetDepht write SetDepth;

    ///  <summary>
    ///  Gets or sets the required security level (0-5) for key strength
    ///  and acceptable cryptography.
    ///  </summary>
    property AuthLevel: TTaurusTLSSecurityBits read GetAuthLevel write SetAuthLevel;

    ///  <summary>
    ///  Gets or sets the specific time used for certificate validity
    ///  checks (instead of the system time).
    ///  </summary>
    property Time: TDateTime read GetTime write SetTime;
{$IFDEF DCC}
    ///  <summary>
    ///  Retrieves the PerName identity string.
    ///  </summary>    property PerName: UnicodeString read GetPerNameW;
    property Host[i: TIdC_Int]: UnicodeString read GetHostW;

    ///  <summary>
    ///  Retrieves a hostname by index.
    ///  </summary>
    property Email: UnicodeString read GetEmailW;

    ///  <summary>
    ///  Retrieves the email address identity.
    ///  </summary>
    property IPAddress: UnicodeString read GetIpAddressW;
{$ENDIF}
{$IFDEF FPC}
    property PerName: UTF8String read GetPerNameA;
    property Host[i: TIdC_Int]: RawbyteString read GetHostA;
    property Email: RawbyteString read GetEmailA;
    property IPAddress: UnicodeString read GetIpAddressA;
{$ENDIF}
  end;

  ///  <summary>
  ///  Concrete class implementation that wraps and owns a native OpenSSL
  ///  X509_VERIFY_PARAM structure.
  ///  </summary>
  ///  <remarks>
  ///  This instance manages the full lifecycle of the verification
  ///  parameters, including allocation upon <see cref="Create" /> and
  ///  release upon <see cref="Destroy" />.
  ///  </remarks>
  TTaurusTLSX509VerifyParam = class(TTaurusTLSCustomX509VerifyParam)
  public
    ///  <summary>
    ///  Creates and initializes a new instance of the verification
    ///  parameters.
    ///  </summary>
    ///  <returns>A new <see cref="TTaurusTLSX509VerifyParam" /> instance.</returns>
    ///  <remarks>
    ///  This constructor allocates and initializes the underlying native
    ///  X509_VERIFY_PARAM structure using X509_VERIFY_PARAM_new().
    ///  </remarks>
    constructor Create;

    ///  <summary>
    ///  Destroys the instance and releases the underlying native
    ///  X509_VERIFY_PARAM structure.
    ///  </summary>
    destructor Destroy; override;
  end;

  ///  <summary>
  ///  A container class that loads, stores, and manages a collection of
  ///  cryptographic objects (certificates, keys, parameters, CRLs) obtained
  ///  from a single OSSL Store operation.
  ///  </summary>
  ///  <remarks>
  ///  This instance automatically opens the store, loads all objects
  ///  matching the filter into internal memory (via <see cref="TStoreItem" />),
  ///  and ensures their cleanup. The native OSSL Store Context is closed
  ///  immediately after loading completes, minimizing the time that
  ///  cryptographic objects (such as private keys) remain in memory
  ///  in open text form.
  ///  </remarks>
  TTaurusTLSOSSLStore = class
  public type
    ///  <summary>
    ///  Defines the type of cryptographic object contained within an
    ///  OSSL_STORE_INFO structure, corresponding to the OpenSSL types.
    ///  </summary>
    ///  <remarks>
    ///  This enumeration determines the type of data retrieved from an
    ///  OSSL Store stream (e.g., Certificate, Private Key, Parameters).
    ///  </remarks>
    TStoreInfoType = (
      /// <summary>No data type or unknown type.</summary>
      sitNone=0,

      ///  <summary>
      ///  The URI or path used to locate the cryptographic object (e.g., a file path).
      ///  </summary>
      sitName=1,

      ///  <summary>Parameters, e.g., DH parameters or EC group (EVP_PKEY).</summary>
      sitParams=2,

      ///  <summary>A public key (EVP_PKEY).</summary>
      sitPubKey=3,

      ///  <summary>A private key (EVP_PKEY).</summary>
      sitPrivKey=4,

      ///  <summary>An X.509 certificate (X509).</summary>
      sitCert=5,

      ///  <summary>A Certificate Revocation List (X509_CRL).</summary>
      sitCRL=6
    );

    ///  <summary>
    ///  Represents a set of possible cryptographic object types retrieved
    ///  from an OSSL Store.
    ///  </summary>
    TStoreInfoTypes = set of TStoreInfoType;

    ///  <summary>
    ///  Provides methods for extracting cryptographic objects and metadata
    ///  from a native OpenSSL OSSL_STORE_INFO structure.
    ///  </summary>
    ///  <remarks>
    ///  The OSSL_STORE_INFO structure acts as a temporary container for the
    ///  object retrieved during a single iteration of the OSSL Store stream.
    ///  </remarks>
    TStoreInfoHelper = record helper for POSSL_STORE_INFO
    public

      ///  <summary>
      ///  Retrieves the object type of the stored item.
      ///  </summary>
      ///  <param name="AInfo">The native OSSL_STORE_INFO instance.</param>
      ///  <returns>
      ///  The object type as <see cref="TTaurusTLSOSSLStore.TStoreInfoType" />.
      ///  </returns>
      class function GetType(AInfo: POSSL_STORE_INFO): TStoreInfoType; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Retrieves the raw C-style string pointer identifying the object type.
      ///  </summary>
      ///  <param name="AInfo">The native OSSL_STORE_INFO instance.</param>
      ///  <returns>A C-style string pointer to the type name (e.g., 'CERT').</returns>
      ///  <remarks>The returned pointer is internally managed and must not be freed.</remarks>
      class function GetTypeName(AInfo: POSSL_STORE_INFO): PIdAnsiChar; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Checks if the native OSSL_STORE_INFO pointer is valid (not nil).
      ///  </summary>
      ///  <param name="AInfo">The native OSSL_STORE_INFO instance.</param>
      ///  <returns>True if the pointer is not nil.</returns>
      class function IsExist(AInfo: POSSL_STORE_INFO): boolean; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Retrieves the raw C-style string pointer to the name/URI of the
      ///  stored object.
      ///  </summary>
      ///  <param name="AInfo">The native OSSL_STORE_INFO instance.</param>
      ///  <returns>A C-style string pointer to the name/URI.</returns>
      ///  <remarks>The returned pointer is internally managed and must not be freed.</remarks>
      class function GetName(AInfo: POSSL_STORE_INFO): PIdAnsiChar; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Retrieves the parameters structure (PEVP_PKEY)
      ///  that holds Key Material Parameters
      ///  </summary>
      ///  <param name="AInfo">The native OSSL_STORE_INFO instance.</param>
      ///  <returns>A pointer to the parameter set.</returns>
      ///  <remarks>No ownership is transferred. Do not free this pointer.</remarks>
      class function GetParams(AInfo: POSSL_STORE_INFO): PEVP_PKEY; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Retrieves the public key structure (<see cref="PEVP_PKEY" />).
      ///  </summary>
      ///  <returns>A pointer to the public key component.</returns>
      ///  <remarks>No ownership is transferred. Do not free this pointer.</remarks>
      class function GetPubKey(AInfo: POSSL_STORE_INFO): PEVP_PKEY; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Retrieves the private key structure (<see cref="PEVP_PKEY" />).
      ///  </summary>
      ///  <returns>A pointer to the private key component.</returns>
      ///  <remarks>No ownership is transferred. Do not free this pointer.</remarks>
      class function GetPrivKey(AInfo: POSSL_STORE_INFO): PEVP_PKEY; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Retrieves the certificate structure (PX509).
      ///  </summary>
      ///  <param name="AInfo">The native OSSL_STORE_INFO instance.</param>
      ///  <returns>A pointer to the certificate.</returns>
      ///  <remarks>No ownership is transferred. Do not free this pointer.</remarks>
      class function GetCert(AInfo: POSSL_STORE_INFO): PX509; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Retrieves the CRL structure (PX509_CRL).
      ///  </summary>
      ///  <param name="AInfo">The native OSSL_STORE_INFO instance.</param>
      ///  <returns>A pointer to the CRL.</returns>
      ///  <remarks>No ownership is transferred. Do not free this pointer.</remarks>
      class function GetCrl(AInfo: POSSL_STORE_INFO): PX509_CRL; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Retrieves the name/URI of the stored object as an AnsiString.
      ///  </summary>
      ///  <param name="AInfo">The native OSSL_STORE_INFO instance.</param>
      ///  <returns>The name/URI string.</returns>
      ///  <remarks>The memory for the resulting string is internally managed.</remarks>
      class function CloneNameA(AInfo: POSSL_STORE_INFO): RawByteString; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Retrieves the name/URI of the stored object as a Unicode string.
      ///  </summary>
      ///  <param name="AInfo">The native OSSL_STORE_INFO instance.</param>
      ///  <returns>The name/URI string.</returns>
      ///  <remarks>The memory for the resulting string is internally managed.</remarks>
      class function CloneNameW(AInfo: POSSL_STORE_INFO): UnicodeString; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Creates a new copy of the parameters structure (<see cref="PEVP_PKEY" />).
      ///  </summary>
      ///  <returns>A new pointer to the parameter set.</returns>
      ///  <remarks>Ownership is transferred. The caller must free the pointer
      ///  using EVP_PKEY_free or equivalent routine.</remarks>
      class function CloneParams(AInfo: POSSL_STORE_INFO): PEVP_PKEY; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Creates a new copy of the public key structure (<see cref="PEVP_PKEY" />).
      ///  </summary>
      ///  <returns>A new pointer to the public key component.</returns>
      ///  <remarks>Ownership is transferred. The caller must free the pointer
      ///  using EVP_PKEY_free or equivalent routine.</remarks>
      class function ClonePubKey(AInfo: POSSL_STORE_INFO): PEVP_PKEY; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Creates a new copy of the private key structure (<see cref="PEVP_PKEY" />).
      ///  </summary>
      ///  <returns>A new pointer to the private key component.</returns>
      ///  <remarks>Ownership is transferred. The caller must free the pointer
      ///  using EVP_PKEY_free or equivalent routine.</remarks>
      class function ClonePrivKey(AInfo: POSSL_STORE_INFO): PEVP_PKEY; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Creates a new copy of the certificate structure (PX509).
      ///  </summary>
      ///  <param name="AInfo">The native OSSL_STORE_INFO instance.</param>
      ///  <returns>A new pointer to the certificate.</returns>
      ///  <remarks>Ownership is transferred. The caller must free the pointer
      ///  using X509_free or equivalent routine.</remarks>
      class function CloneCert(AInfo: POSSL_STORE_INFO): PX509; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Creates a new copy of the CRL structure (PX509_CRL).
      ///  </summary>
      ///  <param name="AInfo">The native OSSL_STORE_INFO instance.</param>
      ///  <returns>A new pointer to the CRL.</returns>
      ///  <remarks>Ownership is transferred. The caller must free the pointer
      ///  using X509_CRL_free or equivalent routine.</remarks>
      class function CloneCrl(AInfo: POSSL_STORE_INFO): PX509_CRL; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Frees the native OSSL_STORE_INFO instance pointer.
      ///  </summary>
      ///  <param name="AInfo">The native OSSL_STORE_INFO pointer, which will be set to nil.</param>
      ///  <remarks>This should be called when finished with the temporary
      ///  information structure retrieved during store iteration.</remarks>
      class procedure Free(var AInfo: POSSL_STORE_INFO); static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}
    end;

    ///  <summary>
    ///  Provides methods for managing the native OpenSSL
    ///  OSSL_STORE_CTX instance lifecycle and stream operations.
    ///  </summary>
    ///  <remarks>
    ///  The OSSL Store Context (<see cref="POSSL_STORE_CTX" />) manages the
    ///  process of reading cryptographic objects from a URI or BIO.
    ///  </remarks>
    TOsslStoreCtxHelper = record helper for POSSL_STORE_CTX
    public

      ///  <summary>
      ///  Opens a new OSSL Store Context loading cryptographic objects (PEM, DER, etc.)
      ///  from supporting by OpenSSL URI (e.g., a file path).
      ///  </summary>
      ///  <param name="AUri">The C-style string pointer representing the URI.</param>
      ///  <param name="AUi">
      ///  An instance handling user interaction (e.g., password prompts).
      ///  </param>
      ///  <returns>
      ///  A new <see cref="POSSL_STORE_CTX" /> instance. Ownership is transferred.
      ///  </returns>
      class function Open(AUri: PIdAnsiChar; AUi: TTaurusTLSCustomOsslUi): POSSL_STORE_CTX;
        overload; static; {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Opens a new OSSL Store Context using a custom BIO interface
      ///  containing cryptographic objects (PEM, DER, etc.).
      ///  </summary>
      ///  <param name="ABio">The custom BIO interface instance.</param>
      ///  <param name="AUi">
      ///  An instance handling user interaction (e.g., password prompts).
      ///  </param>
      ///  <returns>
      ///  A new <see cref="POSSL_STORE_CTX" /> instance. Ownership is transferred.
      ///  </returns>
      class function Open(ABio: TTaurusTLSCustomBIO; AUi: TTaurusTLSCustomOsslUi): POSSL_STORE_CTX;
        overload; static; {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Closes and frees the native OSSL Store Context instance.
      ///  </summary>
      ///  <param name="ACtx">The <see cref="POSSL_STORE_CTX" /> instance to close.</param>
      ///  <remarks>
      ///  This method releases all internal resources associated with the
      ///  context.
      ///  </remarks>
      class procedure Close(ACtx: POSSL_STORE_CTX); overload; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Closes and frees the native OSSL Store Context instance.
      ///  </summary>
      procedure Close; overload; {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Checks if the store has reached the end-of-stream (EOF).
      ///  </summary>
      ///  <param name="ACtx">The <see cref="POSSL_STORE_CTX" /> instance.</param>
      ///  <returns>True if there are no more objects to load.</returns>
      class function Eof(ACtx: POSSL_STORE_CTX): boolean; overload; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Checks if this store context instance has reached the
      ///  end-of-stream (EOF).
      ///  </summary>
      ///  <returns>True if there are no more objects to load.</returns>
      function Eof: boolean; overload; {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Checks if an error occurred during the last store operation.
      ///  </summary>
      ///  <param name="ACtx">The <see cref="POSSL_STORE_CTX" /> instance.</param>
      ///  <returns>True if an error flag is set.</returns>
      class function IsLoadError(ACtx: POSSL_STORE_CTX): boolean; overload; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Checks if an error occurred during the last store operation
      ///  on this context instance.
      ///  </summary>
      ///  <returns>True if an error flag is set.</returns>
      function IsLoadError: boolean; overload; {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Attempts to load the next cryptographic object from the store.
      ///  </summary>
      ///  <param name="ACtx">The <see cref="POSSL_STORE_CTX" /> instance.</param>
      ///  <returns>
      ///  A pointer to the temporary <see cref="POSSL_STORE_INFO" /> instance
      ///  containing the loaded object, or nil on error or EOF.
      ///  </returns>
      ///  <remarks>
      ///  The returned object is temporary. Use methods from
      ///  <see cref="TTaurusTLSOSSLStore.TStoreInfoHelper" /> (e.g., CloneCert) to take ownership
      ///  of the payload.
      ///  </remarks>
      class function Load(ACtx: POSSL_STORE_CTX): POSSL_STORE_INFO; overload;
        static; {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Attempts to load the next cryptographic object from this store
      ///  context.
      ///  </summary>
      ///  <returns>
      ///  A pointer to the temporary <see cref="POSSL_STORE_INFO" /> instance
      ///  containing the loaded object, or nil on error or EOF.
      ///  </returns>
      function Load: POSSL_STORE_INFO; overload; {$IFDEF USE_INLINE}inline;{$ENDIF}
    end;

    ///  <summary>
    ///  Defines the range of valid cryptographic object types that can be
    ///  retrieved from an OSSL Store, excluding the "None" type.
    ///  </summary>
    TStoreItemType = sitName..sitCrl;

    ///  <summary>
    ///  Represents a set of valid cryptographic object types retrieved
    ///  from an OSSL Store.
    ///  </summary>
    TStoreItemTypes = set of TStoreItemType;

    ///  <summary>
    ///  Represents a single cryptographic object loaded from an OSSL Store,
    ///  providing persistent storage for the native pointer and associated
    ///  metadata.
    ///  </summary>
    ///  <remarks>
    ///  This class clones the cryptographic object payload from the
    ///  temporary <see cref="POSSL_STORE_INFO" /> container. Consequently,
    ///  this class takes ownership of the underlying native OpenSSL pointer
    ///  (e.g., <see cref="PEVP_PKEY" />, <see cref="PX509" />) and is
    ///  responsible for freeing it in its <see cref="Destroy" /> method.
    ///  </remarks>
    TStoreItem = class
    private type
      TItemData = record
      private
        FName: RawByteString; // managed type can't be used in variant part of the record.
        case FType: TStoreInfoType of
        sitParams,
        sitPubKey,
        sitPrivKey: (FPKey:   PEVP_PKEY);
        sitCert:    (FCert:     PX509);
        sitCrl:     (FCrl:      PX509_CRL);
      end;
    private
      FData: TItemData;
      function GetType: TStoreInfoType; {$IFDEF USE_INLINE}inline;{$ENDIF}
      function GetName: RawByteString; {$IFDEF USE_INLINE}inline;{$ENDIF}
      function GetParams: PEVP_PKEY; {$IFDEF USE_INLINE}inline;{$ENDIF}
      function GetPubKey: PEVP_PKEY;  {$IFDEF USE_INLINE}inline;{$ENDIF}
      function GetPrivKey: PEVP_PKEY; {$IFDEF USE_INLINE}inline;{$ENDIF}
      function GetCert: PX509; {$IFDEF USE_INLINE}inline;{$ENDIF}
      function GetCrl: PX509_CRL; {$IFDEF USE_INLINE}inline;{$ENDIF}
    public
      ///  <summary>
      ///  Creates a new store item by cloning the cryptographic object
      ///  from the provided OSSL_STORE_INFO.
      ///  </summary>
      ///  <param name="AInfo">
      ///  The temporary <see cref="POSSL_STORE_INFO" /> pointer returned
      ///  by OSSL_STORE_load.
      ///  </param>
      ///  <remarks>
      ///  The native object contained in AInfo is cloned and the new
      ///  pointer's ownership is taken by this instance.
      ///  </remarks>
      constructor Create(AInfo: POSSL_STORE_INFO); overload;

      ///  <summary>
      ///  Destroys the instance and frees the owned native OpenSSL pointer
      ///  (e.g., PEVP_PKEY, PX509) based on the stored item type.
      ///  </summary>
      destructor Destroy; override;

      ///  <summary>
      ///  Retrieves the type of cryptographic object stored in this item.
      ///  </summary>
      property &Type: TStoreInfoType read GetType;

      ///  <summary>
      ///  Retrieves the name or URI associated with the loaded object.
      ///  </summary>
      property Name: RawByteString read GetName;

      ///  <summary>
      ///  Retrieves the Key Material Parameters pointer, if the item is a
      ///  parameter set.
      ///  </summary>
      ///  <remarks>
      ///  The caller must not free this pointer. Check the <see cref="Type" />
      ///  property before accessing.
      ///  </remarks>
      property Params: PEVP_PKEY read GetParams;

      ///  <summary>
      ///  Retrieves the Public Key pointer, if the item is a public key.
      ///  </summary>
      ///  <remarks>
      ///  The caller must not free this pointer. Check the <see cref="Type" />
      ///  property before accessing.
      ///  </remarks>
      property PubKey: PEVP_PKEY read GetPubKey;

      ///  <summary>
      ///  Retrieves the Private Key pointer, if the item is a private key.
      ///  </summary>
      ///  <remarks>
      ///  The caller must not free this pointer. Check the <see cref="Type" />
      ///  property before accessing.
      ///  </remarks>
      property PrivKey: PEVP_PKEY read GetPrivKey;

      ///  <summary>
      ///  Retrieves the X.509 Certificate pointer, if the item is a certificate.
      ///  </summary>
      ///  <remarks>
      ///  The caller must not free this pointer. Check the <see cref="Type" />
      ///  property before accessing.
      ///  </remarks>
      property Cert: PX509 read GetCert;

      ///  <summary>
      ///  Retrieves the X.509 Certificate Revocation List (CRL) pointer.
      ///  </summary>
      ///  <remarks>
      ///  The caller must not free this pointer. Check the <see cref="Type" />
      ///  property before accessing.
      ///  </remarks>
      property Crl: PX509_CRL read GetCrl;
    end;

  public const
    ///  <summary>
    ///  Bitmask representing all valid, retrievable cryptographic object
    ///  types (Name, Params, Keys, Certs, CRLs).
    ///  </summary>
    cStoreAElementsAll = [sitName..sitCRL];

  private type
    TCounters = array [TStoreItemType] of TIdC_Uint;
    TListInfo = TObjectList<TStoreItem>;

  private
    FList: TListInfo;
    FCounters: TCounters;
    function GetCount(AType: TStoreItemType): TIdC_Uint;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

  protected
    ///  <summary>
    ///  Internal constructor used when the native OSSL_STORE_CTX is already
    ///  open. Performs the loading operation.
    ///  </summary>
    ///  <param name="ACtx">The pre-opened native OSSL Store Context pointer.</param>
    ///  <param name="ALoadFilter">
    ///  A set of <see cref="TStoreItemType" /> to filter which objects are
    ///  cloned and stored. Defaults to all types.
    ///  </param>
    constructor Create(ACtx: POSSL_STORE_CTX;
        ALoadFilter: TStoreItemTypes = cStoreAElementsAll); overload;

    ///  <summary>
    ///  Loads of objects from the native OpenSSL Store context and clone
    ///  them into the internal list.
    ///  </summary>
    ///  <param name="ACtx">The native OSSL Store Context pointer.</param>
    ///  <param name="ALoadFilter">The set of types to load.</param>
    procedure DoLoad(ACtx: POSSL_STORE_CTX; ALoadFilter: TStoreItemTypes);

  public
    ///  <summary>
    ///  Creates an instance by opening the store using an Ansi or UTF8
    ///  String URI.
    ///  </summary>
    ///  <param name="AUri">The URI (Ansi or UTF8 String).</param>
    ///  <param name="AUi">The User Interaction instance for password prompts.</param>
    ///  <param name="ALoadFilter">The set of types to load.</param>
    constructor Create(AUri: RawByteString; AUi: TTaurusTLSCustomOsslUi;
      ALoadFilter: TStoreItemTypes = cStoreAElementsAll); overload;

    ///  <summary>
    ///  Creates an instance by opening the store using a URI (UnicodeString).
    ///  </summary>
    ///  <param name="AUri">The URI (e.g., file path).</param>
    ///  <param name="AUi">The User Interaction instance for password prompts.</param>
    ///  <param name="ALoadFilter">The set of types to load.</param>
    constructor Create(AUri: UnicodeString; AUi: TTaurusTLSCustomOsslUi;
      ALoadFilter: TStoreItemTypes = cStoreAElementsAll); overload;

    /// <summary>
    ///   Creates an instance by opening the store from a memory using a <see
    ///   cref="TTaurusTLSCustomBIO" /> interface.
    /// </summary>
    /// <param name="ABio">
    ///   The BIO instance with the content that .
    /// </param>
    /// <param name="AUi">
    ///   The User Interaction instance for password prompts.
    /// </param>
    /// <param name="ALoadFilter">
    ///   The set of types to load.
    /// </param>
    constructor Create(ABio: TTaurusTLSCustomBIO; AUi: TTaurusTLSCustomOsslUi;
      ALoadFilter: TStoreItemTypes = cStoreAElementsAll); overload;

    ///  <summary>
    ///  Destroys the instance and frees all loaded
    ///  <see cref="TTaurusTLSOSSLStore.TStoreItem" /> objects
    ///  and their native OpenSSL payloads.
    ///  </summary>
    destructor Destroy; override;

    ///  <summary>
    ///  Retrieves the count of loaded cryptographic objects matching a
    ///  specific type.
    ///  </summary>
    ///  <param name="AType">The specific <see cref="TStoreItemType" /> to count.</param>
    ///  <returns>The number of items of the specified type.</returns>
    property Count[AType: TStoreItemType]: TIdC_Uint read GetCount;
  end;

  ///  <summary>
  ///  Provides iteration capabilities for accessing and processing
  ///  loaded cryptographic objects in a <see cref="TTaurusTLSOSSLStore" />
  ///  instance.
  ///  </summary>
  ///  <remarks>
  ///  This helper defines methods that return an enumerator, allowing the
  ///  store contents to be processed using a 'for in' loop.
  ///  </remarks>
  TTaurusTLSOSSLStoreHelper = class helper for TTaurusTLSOSSLStore
  public type

    ///  <summary>
    ///  Enumerator class for iterating over loaded
    ///  <see cref="TTaurusTLSOSSLStore.TStoreItem" /> objects,
    ///  optionally filtering by type.
    ///  </summary>
    TEnumerator = class
    private
      FEnum: TListInfo.TEnumerator;
      FFilter: TStoreItemTypes;
      FCurrent: TStoreItem;
    protected
      function GetCurrent: TStoreItem;
    public
      ///  <summary>
      ///  Creates the enumerator, initializing it with the internal list
      ///  and a set of types to include.
      ///  </summary>
      ///  <param name="AList">The internal TObjectList&lt;TStoreItem&gt;.</param>
      ///  <param name="AFilter">The set of types to iterate over.</param>
      constructor Create(AList: TListInfo; AFilter: TStoreItemTypes);

      ///  <summary>
      ///  Destroys the enumerator instance.
      ///  </summary>
      destructor Destroy; override;

      ///  <summary>
      ///  Standard method required for 'for in' loops; returns the enumerator itself.
      ///  </summary>
      function GetEnumerator: TEnumerator;

      ///  <summary>
      ///  Advances the enumerator to the next item matching the filter.
      ///  </summary>
      ///  <returns>True if the move was successful and <see cref="Current" /> is valid.</returns>
      function MoveNext: boolean;

      ///  <summary>
      ///  Retrieves the item at the enumerator's current position.
      ///  </summary>
      property Current: TStoreItem read GetCurrent;
    end;
  public
    ///  <summary>
    ///  Retrieves a new enumerator for iterating over ALL loaded items.
    ///  </summary>
    ///  <returns>A new <see cref="TEnumerator" /> instance.</returns>
    function GetEnumerator: TEnumerator; overload;

    ///  <summary>
    ///  Retrieves a new enumerator, filtered to iterate only over items
    ///  matching the specified types.
    ///  </summary>
    ///  <param name="AFilter">
    ///  The set of <see cref="TTaurusTLSOSSLStore.TStoreItemType" /> to include.
    ///  </param>
    ///  <returns>A new <see cref="TEnumerator" /> instance.</returns>
    function GetEnumerator(const AFilter: TTaurusTLSOSSLStore.TStoreItemTypes):
      TEnumerator; overload;
  end;

  ///  <summary>
  ///  Manages the OpenSSL X509 Certificate Trust Store, which acts as the
  ///  repository for trusted Root Certificates and Certificate Revocation Lists (CRLs).
  ///  </summary>
  ///  <remarks>
  ///  The trust store is necessary for certificate path validation. This instance
  ///  owns the native <see cref="PX509_STORE" /> pointer and provides integrated
  ///  management for verification parameters via the <see cref="VfyParam" /> property.
  ///  </remarks>
  TaurusTLS_X509Store = class
  public type
    ///  <summary>
    ///  Defines the range of X.509 objects that can be stored (Certificate and CRL).
    ///  </summary>
    TX509Element = sitCert..sitCRL;

    ///  <summary>
    ///  Represents a set of storable X.509 object types.
    ///  </summary>
    TX509Elements = set of TX509Element;

  public const
    ///  <summary>
    ///  Bitmask representing all storable X.509 object types (Certificates and CRLs).
    ///  </summary>
    cX509ElementsAll = [sitCert..sitCRL];

  protected type
    TVfyParam = class(TTaurusTLSCustomX509VerifyParam)
    public
      constructor Create(AStore: PX509_STORE);
    end;

  private
    FStore: PX509_STORE;
    FVfyParam: TTaurusTLSCustomX509VerifyParam;
    procedure SetParam(AVfyParam: TTaurusTLSCustomX509VerifyParam);
    function GetParam: TTaurusTLSCustomX509VerifyParam;
  protected
    ///  <summary>
    ///  Direct access to the native OpenSSL X509_STORE pointer.
    ///  </summary>
    ///  <remarks>The pointer is owned and managed by this instance.</remarks>
    property Store: PX509_STORE read FStore;
  public
    ///  <summary>
    ///  Creates an empty X.509 Trust Store instance, initializing the
    ///  native X509_STORE structure.
    ///  </summary>
    constructor Create; overload;

    ///  <summary>
    ///  Creates a store instance and initializes it by adding all
    ///  specified X.509 objects from an existing OSSL Store container.
    ///  </summary>
    ///  <param name="AStore">
    ///  The <see cref="TTaurusTLSOSSLStore" /> instance containing loaded objects.
    ///  </param>
    ///  <param name="AFilter">
    ///  The set of elements (<see cref="TX509Element" />) to add (Certificates and/or CRLs).
    ///  </param>
    constructor Create(AStore: TTaurusTLSOSSLStore; AFilter: TX509Elements);
      overload;

    ///  <summary>
    ///  Destroys the instance and releases the native X509_STORE structure
    ///  and its contents.
    ///  </summary>
    destructor Destroy; override;

    ///  <summary>
    ///  Adds a single certificate (PX509) to the trusted repository.
    ///  </summary>
    ///  <param name="ACert">The certificate pointer.</param>
    ///  <remarks>The store increments the certificate's reference count
    ///  and takes ownership of the pointer. Do not free the pointer after
    ///  adding it to the store.</remarks>
    procedure AddCert(ACert: PX509); {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Adds a single Certificate Revocation List (CRL) to the trusted repository.
    ///  </summary>
    ///  <param name="ACrl">The CRL pointer.</param>
    ///  <remarks>The store takes ownership of the pointer. Do not free the
    ///  pointer after adding it to the store.</remarks>
    procedure AddCrl(ACrl: PX509_CRL); {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Adds certificates and CRLs from an existing OSSL Store container
    ///  into this trust store.
    ///  </summary>
    ///  <param name="AStore">The <see cref="TTaurusTLSOSSLStore" /> instance.</param>
    ///  <param name="AFilter">The set of elements (<see cref="TX509Element" />) to add.</param>
    ///  <remarks>
    ///  Items are added cumulatively, preserving all previously existing
    ///  certificates and CRLs in the store.
    ///  </remarks>
    procedure AddFromStore(AStore: TTaurusTLSOSSLStore; AFilter: TX509Elements);
      overload;

    /// <summary>
    ///   Attaches <c>X509_STORE</c> to OpenSSL <c>SSL_CTX</c> object.
    /// </summary>
    /// <param name="ASSLCtx">
    ///   OpenSSL <c>SSL_CTX</c> object.
    /// </param>
    /// <remarks>
    ///   This method adds refernce count to the underlined <c>X509_STORE</c>
    ///   object. The TaurusTLS_X509Store can be freed safely after that.
    /// </remarks>
    procedure AttachToSSLCtx(ASSLCtx: PSSL_CTX); {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Provides access to the verification parameters used for validating
    ///  certificates against this trust store.
    ///  </summary>
    ///  <remarks>
    ///  This property returns the <see cref="TTaurusTLSCustomX509VerifyParam" />
    ///  instance that is internally integrated with the native X509_STORE.
    ///  </remarks>
    property VfyParam: TTaurusTLSCustomX509VerifyParam read GetParam write SetParam;
  end;

implementation

uses
  TaurusTLSHeaders_ssl,
  TaurusTLSHeaders_crypto,
  TaurusTLS_ResourceStrings;

{ TTaurusTLSCustomX509VerifyParam.TVerifyFlagHelper }

function TTaurusTLSCustomX509VerifyParam.TVerifyFlagHelper.GetAsInt: TIdC_ULONG;
begin
  Result:=ToInt(Self);
end;

procedure TTaurusTLSCustomX509VerifyParam.TVerifyFlagHelper.SetAsInt(
  Value: TIdC_ULONG);
begin
  Self:=FromInt(Value);
end;

class function TTaurusTLSCustomX509VerifyParam.TVerifyFlagHelper.ToInt(
  Value: TVerifyFlag): TIdC_ULONG;
begin
  Result:=TIdC_ULONG(1 shl Ord(Value)) and cX509vfMask;
end;

class function TTaurusTLSCustomX509VerifyParam.TVerifyFlagHelper.FromInt(
  Value: TIdC_ULONG): TVerifyFlag;
var
  i: TIdC_ULONG;

begin
  // check if AVal in range of OpenSSL X509_V_FLAG_* constants
  // and a single bit is set.
  if (Value = 0) or ((Value and (Value-1)) <> 0)
    or ((Value or cX509vfMask) <> cX509vfMask) then
    raise EInvalidCast.Create('Invalid X509 Verify Flag.');
  i:=Ord(Low(TVerifyFlag));
  while (1 shl i) < Value do
    Inc(i);
  Result:=TVerifyFlag(i);
end;

function TTaurusTLSCustomX509VerifyParam.TVerifyFlagHelper.IsEqualTo(
  Value: TIdC_ULONG): boolean;
begin
  Result:=Value = AsInt;
end;

{ TTaurusTLSX509VerifyParam.TVerifyFlagsHelper }

function TTaurusTLSCustomX509VerifyParam.TVerifyFlagsHelper.GetAsInt: TIdC_ULONG;
begin
  Result:=ToInt(Self);
end;

procedure TTaurusTLSCustomX509VerifyParam.TVerifyFlagsHelper.SetAsInt(
  Value: TIdC_ULONG);
begin
  Self:=FromInt(Value);
end;

procedure TTaurusTLSCustomX509VerifyParam.TVerifyFlagsHelper.SetSafeAsInt(
  Value: TIdC_ULONG);
begin
  Self:=SafeFromInt(Value);
end;

class function TTaurusTLSCustomX509VerifyParam.TVerifyFlagsHelper.ToInt(
  Value: TVerifyFlags): TIdC_ULONG;
begin
  Result:=(TIdC_ULONG((@Value)^) and cX509vfMask);
end;

class function TTaurusTLSCustomX509VerifyParam.TVerifyFlagsHelper.FromInt(
  Value: TIdC_ULONG): TVerifyFlags;
begin
  if (Value or cX509vfMask) <> cX509vfMask then
    raise EInvalidCast.Create('Invalid X509 Verify Flags.');
//{$I RangeCheck-OFF.inc}
  Result:=TVerifyFlags((@Value)^);
//{$I RangeCheck-ON.inc}
end;

class function TTaurusTLSCustomX509VerifyParam.TVerifyFlagsHelper.SafeFromInt(
  Value: TIdC_ULONG): TVerifyFlags;
begin
  Value:=Value and cX509vfMask;
//{$I RangeCheck-OFF.inc}
  Result:=TVerifyFlags((@Value)^);
//{$I RangeCheck-ON.inc}
end;

function TTaurusTLSCustomX509VerifyParam.TVerifyFlagsHelper.IsEqualTo(
  Value: TIdC_ULONG): boolean;
begin
  Result:=Value = AsInt;
end;

{ TTaurusTLSCustomX509VerifyParam.TInheritanceFlagHelper }

function TTaurusTLSCustomX509VerifyParam.TInheritanceFlagHelper.GetAsInt: TIdC_UINT32;
begin
  Result:=ToInt(Self);
end;

procedure TTaurusTLSCustomX509VerifyParam.TInheritanceFlagHelper.SetAsInt(
  Value: TIdC_UINT32);
begin
  Self:=FromInt(Value);
end;

class function TTaurusTLSCustomX509VerifyParam.TInheritanceFlagHelper.ToInt(
  Value: TInheritanceFlag): TIdC_UINT32;
begin
  Result:=TIdC_UINT32(1 shl Ord(Value)) and cX509ihfMask;
end;

class function TTaurusTLSCustomX509VerifyParam.TInheritanceFlagHelper.FromInt(
  Value: TIdC_UINT32): TInheritanceFlag;
var
  i: TIdC_UINT32;

begin
  // check if AVal in range of OpenSSL X509_VP_FLAG_* constants
  // and a single bit is set.
  if (Value = 0) or ((Value and (Value-1)) <> 0)
    or ((Value or cX509ihfMask) <> cX509ihfMask) then
    raise EInvalidCast.Create('Invalid X509 Inheritance Flag.');
  i:=Ord(Low(TInheritanceFlag));
  while (1 shl i) < Value do
    Inc(i);
//{$I RangeCheck-OFF.inc}
  Result:=TInheritanceFlag(i);
//{$I RangeCheck-ON.inc}
end;

function TTaurusTLSCustomX509VerifyParam.TInheritanceFlagHelper.IsEqualTo(
  Value: TIdC_UINT32): boolean;
begin
  Result:=Value = AsInt;
end;

{ TTaurusTLSCustomX509VerifyParam.TInheritanceFlagsHelper }

function TTaurusTLSCustomX509VerifyParam.TInheritanceFlagsHelper.GetAsInt: TIdC_UINT32;
begin
  Result:=ToInt(Self);
end;

procedure TTaurusTLSCustomX509VerifyParam.TInheritanceFlagsHelper.SetAsInt(
  Value: TIdC_UINT32);
begin
  Self:=FromInt(Value);
end;

class function TTaurusTLSCustomX509VerifyParam.TInheritanceFlagsHelper.ToInt(
  Value: TInheritanceFlags): TIdC_UINT32;
begin
  Result:=(TIdC_UINT32((@Value)^) and cX509ihfMask);
end;

class function TTaurusTLSCustomX509VerifyParam.TInheritanceFlagsHelper.FromInt(
  Value: TIdC_UINT32): TInheritanceFlags;
begin
  if (Value or cX509ihfMask) <> cX509ihfMask then
    raise EInvalidCast.Create('Invalid X509 Inheritance Flags.');
//{$I RangeCheck-OFF.inc}
  Result:=TInheritanceFlags((@Value)^);
//{$I RangeCheck-ON.inc}
end;

function TTaurusTLSCustomX509VerifyParam.TInheritanceFlagsHelper.IsEqualTo(
  Value: TIdC_UINT32): boolean;
begin
  Result:=Value = AsInt;
end;

{ TTaurusTLSCustomX509VerifyParam.TTrustHelper }

function TTaurusTLSCustomX509VerifyParam.TTrustHelper.GetAsInt: TIdC_Int;
begin
  Result:=ToInt(Self);
end;

procedure TTaurusTLSCustomX509VerifyParam.TTrustHelper.SetAsInt(
  Value: TIdC_Int);
begin
  Self:=FromInt(Value);
end;

class function TTaurusTLSCustomX509VerifyParam.TTrustHelper.FromInt(
  Value: TIdC_Int): TTrust;
begin
  if (Value < Ord(Low(TTrust))) or (Value > Ord(High(TTrust))) then
    raise EInvalidCast.Create('Invalid X509 Trust Flag.');
//{$I RangeCheck-OFF.inc}
  Result:=TTrust(Value);
//{$I RangeCheck-ON.inc}
end;

class function TTaurusTLSCustomX509VerifyParam.TTrustHelper.ToInt(
  Value: TTrust): TIdC_Int;
begin
  Result:=Ord(Value);
end;

function TTaurusTLSCustomX509VerifyParam.TTrustHelper.IsEqualTo(
  Value: TIdC_Int): boolean;
begin
  Result:=Value = AsInt;
end;

{ TTaurusTLSCustomX509VerifyParam.TPurposeHelper }

function TTaurusTLSCustomX509VerifyParam.TPurposeHelper.GetAsInt: TIdC_Int;
begin
  Result:=ToInt(Self);
end;

procedure TTaurusTLSCustomX509VerifyParam.TPurposeHelper.SetAsInt(
  Value: TIdC_Int);
begin
  Self:=FromInt(Value);
end;

class function TTaurusTLSCustomX509VerifyParam.TPurposeHelper.FromInt(
  Value: TIdC_Int): TPurpose;
begin
  if (Value < Ord(Low(TPurpose))) or (Value > Ord(High(TPurpose))) then
    raise EInvalidCast.Create('Invalid X509 Trust Flag.');
//{$I RangeCheck-OFF.inc}
  Result:=TPurpose(Value);
//{$I RangeCheck-ON.inc}
end;

class function TTaurusTLSCustomX509VerifyParam.TPurposeHelper.ToInt(
  Value: TPurpose): TIdC_Int;
begin
  Result:=Ord(Value);
end;

function TTaurusTLSCustomX509VerifyParam.TPurposeHelper.IsEqualTo(
  Value: TIdC_Int): boolean;
begin
  Result:=Value = AsInt;
end;

{ TTaurusTLSCustomX509VerifyParam.THostCheckFlagHelper }

function TTaurusTLSCustomX509VerifyParam.THostCheckFlagHelper.GetAsInt: TIdC_UINT;
begin
  Result:=ToInt(Self);
end;

procedure TTaurusTLSCustomX509VerifyParam.THostCheckFlagHelper.SetAsInt(
  Value: TIdC_UINT);
begin
  Self:=FromInt(Value);
end;

class function TTaurusTLSCustomX509VerifyParam.THostCheckFlagHelper.FromInt(
  Value: TIdC_UINT): THostCheckFlag;
var
  i: TIdC_UINT;

begin
  // check if AVal in range of OpenSSL X509_CHECK_FLAG_* constants
  // and a single bit is set.
  if (Value = 0) or ((Value and (Value-1)) <> 0)
    or ((Value or cX509hckMask) <> cX509hckMask) then
    raise EInvalidCast.Create('Invalid X509 Host Check Verify Flag.');
  i:=Ord(Low(THostCheckFlag));
  while (1 shl i) < Value do
    Inc(i);
//{$I RangeCheck-OFF.inc}
  Result:=THostCheckFlag(i);
//{$I RangeCheck-ON.inc}
end;

class function TTaurusTLSCustomX509VerifyParam.THostCheckFlagHelper.ToInt(
  Value: THostCheckFlag): TIdC_UINT;
begin
  Result:=TIdC_UINT(1 shl Ord(Value));
end;

function TTaurusTLSCustomX509VerifyParam.THostCheckFlagHelper.IsEqualTo(
  Value: TIdC_UINT): boolean;
begin
  Result:=Value = AsInt;
end;

{ TTaurusTLSCustomX509VerifyParam.THostCheckFlagsHelper }

function TTaurusTLSCustomX509VerifyParam.THostCheckFlagsHelper.GetAsInt: TIdC_UINT;
begin
  Result:=ToInt(Self);
end;

procedure TTaurusTLSCustomX509VerifyParam.THostCheckFlagsHelper.SetAsInt(
  Value: TIdC_UINT);
begin
  Self:=FromInt(Value);
end;

class function TTaurusTLSCustomX509VerifyParam.THostCheckFlagsHelper.FromInt(
  Value: TIdC_UINT): THostCheckFlags;
begin
  // check if AVal in range of OpenSSL X509_CHECK_FLAG_* constants
  // and a single bit is set.
  if ((Value or cX509hckMask) <> cX509hckMask) then
    raise EInvalidCast.Create('Invalid X509 Host Check Verify Flags.');
//{$I RangeCheck-OFF.inc}
  Result:=THostCheckFlags((@Value)^);
//{$I RangeCheck-ON.inc}
end;

class function TTaurusTLSCustomX509VerifyParam.THostCheckFlagsHelper.ToInt(
  Value: THostCheckFlags): TIdC_UINT;
begin
  Result:=(TIdC_UINT((@Value)^) and cX509hckMask);
end;

function TTaurusTLSCustomX509VerifyParam.THostCheckFlagsHelper.IsEqualTo(
  Value: TIdC_UINT): boolean;
begin
  Result:=Value = AsInt;
end;

{ TTaurusTLSCustomX509VerifyParam }

constructor TTaurusTLSCustomX509VerifyParam.Create(AParam: PX509_VERIFY_PARAM);
begin
  if not Assigned(AParam) then
    ETaurusTLSX509StoreError.RaiseWithMessage(RMSG_X509VfyParamNull_err);
  inherited Create;
  FParam:=AParam;
end;

function TTaurusTLSCustomX509VerifyParam.GetVerifyFlags: TVerifyFlags;
begin
  Result:=TVerifyFlags.FromInt(X509_VERIFY_PARAM_get_flags(FParam));
end;

procedure TTaurusTLSCustomX509VerifyParam.SetVerifyFlags(const Value: TVerifyFlags);
var
  lFlags, lClearFlags: TVerifyFlags;

begin
  lFlags:=VerifyFlags;
  if X509_VERIFY_PARAM_set_flags(FParam, Value.AsInt) <> 1 then
    ETaurusTLSX509StoreError.RaiseWithMessage(RMSG_X509VfyParamFlag_err);
  lClearFlags:=lFlags-Value;
  if lClearFlags <> [] then
    if X509_VERIFY_PARAM_clear_flags(FParam, lClearFlags.AsInt) <> 1 then
      ETaurusTLSX509StoreError.RaiseWithMessage(RMSG_X509VfyParamFlag_err);
end;

function TTaurusTLSCustomX509VerifyParam.GetInheritanceFlags: TInheritanceFlags;
begin
  Result:=TInheritanceFlags.FromInt(X509_VERIFY_PARAM_get_inh_flags(Fparam));
end;

procedure TTaurusTLSCustomX509VerifyParam.SetInheritanceFlags(
  const Value: TInheritanceFlags);
begin
  if X509_VERIFY_PARAM_set_inh_flags(FParam, Value.AsInt) <> 1 then
    ETaurusTLSX509StoreError.RaiseWithMessage(RMSG_X509VfyParamInhFlag_err);
end;

function TTaurusTLSCustomX509VerifyParam.GetDepht: TIdC_Int;
begin
  Result:=X509_VERIFY_PARAM_get_depth(FParam);
end;

procedure TTaurusTLSCustomX509VerifyParam.SetDepth(const Value: TIdC_Int);
begin
  X509_VERIFY_PARAM_set_depth(FParam, Value);
end;

function TTaurusTLSCustomX509VerifyParam.GetAuthLevel: TTaurusTLSSecurityBits;
begin
  Result.AsInt:=X509_VERIFY_PARAM_get_auth_level(FParam);
end;

procedure TTaurusTLSCustomX509VerifyParam.SetAuthLevel(const Value: TTaurusTLSSecurityBits);
begin
  X509_VERIFY_PARAM_set_auth_level(FParam, Value.AsInt);
end;

function TTaurusTLSCustomX509VerifyParam.GetTime: TDateTime;
begin
  Result:=UnixToDateTime(X509_VERIFY_PARAM_get_time(FParam), True);
end;

procedure TTaurusTLSCustomX509VerifyParam.SetTime(const Value: TDateTime);
begin
  X509_VERIFY_PARAM_set_time(FParam, DateTimeToUnix(Value, True));
end;

function TTaurusTLSCustomX509VerifyParam.GetHostCheckFlags: THostCheckFlags;
begin
  Result:=THostCheckFlags.FromInt(X509_VERIFY_PARAM_get_hostflags(FParam));
end;

procedure TTaurusTLSCustomX509VerifyParam.SetHostCheckFlags(
  const Value: THostCheckFlags);
begin
  X509_VERIFY_PARAM_set_hostflags(FParam, Value.AsInt);
end;

function TTaurusTLSCustomX509VerifyParam.GetHostRaw(
  ANumber: TIdC_Int): PIdAnsiChar;
begin
  Result:=X509_VERIFY_PARAM_get0_host(FParam, ANumber);
end;

function TTaurusTLSCustomX509VerifyParam.GetHostA(
  ANumber: TIdC_Int): RawByteString;
begin
  Result:=RawByteString(GetHostRaw(ANumber));
end;

function TTaurusTLSCustomX509VerifyParam.GetHostW(
  ANumber: TIdC_Int): UnicodeString;
begin
  Result:=UnicodeString(GetHostRaw(ANumber));
end;

procedure TTaurusTLSCustomX509VerifyParam.SetHostA(Value: RawByteString);
begin
  if X509_VERIFY_PARAM_set1_host(FParam, PIdAnsiChar(Value), 0) <> 1 then
    ETaurusTLSX509StoreError.RaiseWithMessage(RMSG_X509VfyHost_err);
end;

procedure TTaurusTLSCustomX509VerifyParam.SetHostW(Value: UnicodeString);
begin
  SetHostA(RawByteString(Value));
end;

procedure TTaurusTLSCustomX509VerifyParam.AddHostA(Value: RawByteString);
begin
  if Value = '' then
    Exit;
  if X509_VERIFY_PARAM_add1_host(FParam, PIdAnsiChar(Value), 0) <> 1 then
    ETaurusTLSX509StoreError.RaiseWithMessage(RMSG_X509VfyHost_err);
end;

procedure TTaurusTLSCustomX509VerifyParam.AddHostW(Value: UnicodeString);
begin
  AddHostA(RawByteString(Value));
end;

function TTaurusTLSCustomX509VerifyParam.GetPerNameA: RawByteString;
begin
  Result:=RawByteString(X509_VERIFY_PARAM_get0_peername(FParam));
end;

function TTaurusTLSCustomX509VerifyParam.GetPerNameW: UnicodeString;
begin
  Result:=UnicodeString(X509_VERIFY_PARAM_get0_peername(FParam));
end;

function TTaurusTLSCustomX509VerifyParam.GetEmailRaw: PIdAnsiChar;
begin
  Result:=X509_VERIFY_PARAM_get0_email(FParam);
end;

function TTaurusTLSCustomX509VerifyParam.GetEmailA: RawByteString;
begin
  Result:=RawByteString(GetEmailRaw);
end;

function TTaurusTLSCustomX509VerifyParam.GetEmailW: UnicodeString;
begin
  Result:=UnicodeString(GetEmailRaw);
end;

procedure TTaurusTLSCustomX509VerifyParam.SetEMailA(Value: RawByteString);
begin
  if X509_VERIFY_PARAM_set1_email(FParam, PIdAnsiChar(Value),
    Length(Value)) <> 1 then
    ETaurusTLSX509StoreError.RaiseWithMessage(RMSG_X509VfyEMail_err);
end;

procedure TTaurusTLSCustomX509VerifyParam.SetEMailW(Value: UnicodeString);
begin
  SetEMailA(RawByteString(Value));
end;

procedure TTaurusTLSCustomX509VerifyParam.SetIpAddress(Value: TIdIPAddress);
var
  lData: Pointer;
  lIpv4: UInt32;
  lSize: TIdC_SizeT;

begin
  lData:=nil;
  lSize:=0;
  case Value.AddrType of
  Id_IPv4:
    begin
      lIpv4:=Value.IPv4;
      lData:=@lIpv4;
      lSize:=SizeOf(lIpv4);
    end;
  Id_IPv6:
    begin
      lData:=@Value.IPv6;
      lSize:=SizeOf(Value.IPv6);
    end;
  end;
  if X509_VERIFY_PARAM_set1_ip(FParam, lData, lSize) <> 1 then
    ETaurusTLSX509StoreError.RaiseWithMessage(RMSG_X509VfyIPAddr_err);
end;

procedure TTaurusTLSCustomX509VerifyParam.SetIpAddressA(Value: RawByteString);
begin
  if X509_VERIFY_PARAM_set1_ip_asc(FParam, PIdAnsiChar(Value)) <> 1 then
    ETaurusTLSX509StoreError.RaiseWithMessage(RMSG_X509VfyIPAddr_err);
end;

procedure TTaurusTLSCustomX509VerifyParam.SetIpAddressW(Value: UnicodeString);
begin
  SetIpAddressA(RawByteString(Value));
end;

function TTaurusTLSCustomX509VerifyParam.GetIpAddressA: RawByteString;
var
  lResult: PIdAnsiChar;

begin
  lResult:=nil;
  try
    lResult:=X509_VERIFY_PARAM_get1_ip_asc(FParam);
    Result:=RawByteString(lResult);
  finally
    OPENSSL_free(lResult);
  end;
end;

function TTaurusTLSCustomX509VerifyParam.GetIpAddressW: UnicodeString;
var
  lResult: PIdAnsiChar;

begin
  lResult:=nil;
  try
    lResult:=X509_VERIFY_PARAM_get1_ip_asc(FParam);
    Result:=UnicodeString(lResult);
  finally
    OPENSSL_free(lResult);
  end;
end;

function TTaurusTLSCustomX509VerifyParam.GetPurpose: TPurpose;
begin
  Result:=TPurpose.FromInt(X509_VERIFY_PARAM_get_purpose(FParam));
end;

procedure TTaurusTLSCustomX509VerifyParam.SetPurpose(Value: TPurpose);
begin
  if X509_VERIFY_PARAM_set_purpose(FParam, Value.AsInt) <> 0 then
    ETaurusTLSX509StoreError.RaiseWithMessage(RMSG_X509VfyPurp_err);
end;

{ TTaurusTLSOSSLStore.TStoreInfoHelper }

class function TTaurusTLSOSSLStore.TStoreInfoHelper.GetType(AInfo:
    POSSL_STORE_INFO): TStoreInfoType;
begin
  Result:=TStoreInfoType(OSSL_STORE_INFO_get_type(AInfo));
end;

class function TTaurusTLSOSSLStore.TStoreInfoHelper.GetTypeName(
  AInfo: POSSL_STORE_INFO): PIdAnsiChar;
begin
  if IsExist(Ainfo) then
    Result:=OSSL_STORE_INFO_type_string(Ord(GetType(AInfo)))
  else
    Result:=nil;
end;

class function TTaurusTLSOSSLStore.TStoreInfoHelper.IsExist(
  AInfo: POSSL_STORE_INFO): boolean;
begin
  Result:=Assigned(AInfo);
end;

class function TTaurusTLSOSSLStore.TStoreInfoHelper.GetName(
  AInfo: POSSL_STORE_INFO): PIdAnsiChar;
begin
  if IsExist(AInfo) then
    Result:=OSSL_STORE_INFO_get0_NAME(AInfo)
  else
    Result:=nil;
end;

class function TTaurusTLSOSSLStore.TStoreInfoHelper.GetParams(
  AInfo: POSSL_STORE_INFO): PEVP_PKEY;
begin
  if IsExist(AInfo) then
    Result:=OSSL_STORE_INFO_get0_PARAMS(AInfo)
  else
    Result:=nil;
end;

class function TTaurusTLSOSSLStore.TStoreInfoHelper.GetPubKey(
  AInfo: POSSL_STORE_INFO): PEVP_PKEY;
begin
  if IsExist(AInfo) then
    Result:=OSSL_STORE_INFO_get0_PUBKEY(AInfo)
  else
    Result:=nil;
end;

class function TTaurusTLSOSSLStore.TStoreInfoHelper.GetPrivKey(
  AInfo: POSSL_STORE_INFO): PEVP_PKEY;
begin
  if IsExist(AInfo) then
    Result:=OSSL_STORE_INFO_get0_PKEY(AInfo)
  else
    Result:=nil;
end;

class function TTaurusTLSOSSLStore.TStoreInfoHelper.GetCert(
  AInfo: POSSL_STORE_INFO): PX509;
begin
  if IsExist(AInfo) then
    Result:=OSSL_STORE_INFO_get0_CERT(AInfo)
  else
    Result:=nil;
end;

class function TTaurusTLSOSSLStore.TStoreInfoHelper.GetCrl(
  AInfo: POSSL_STORE_INFO): PX509_CRL;
begin
  if IsExist(AInfo) then
    Result:=OSSL_STORE_INFO_get0_CRL(AInfo)
  else
    Result:=nil;
end;

class function TTaurusTLSOSSLStore.TStoreInfoHelper.CloneNameA(
  AInfo: POSSL_STORE_INFO): RawByteString;
begin
  Result:=AnsiString(GetName(AInfo));
end;

class function TTaurusTLSOSSLStore.TStoreInfoHelper.CloneNameW(
  AInfo: POSSL_STORE_INFO): UnicodeString;
begin
  Result:=UnicodeString(GetName(AInfo));
end;

class function TTaurusTLSOSSLStore.TStoreInfoHelper.CloneParams(AInfo:
    POSSL_STORE_INFO): PEVP_PKEY;
begin
  if IsExist(AInfo) then
    Result:=OSSL_STORE_INFO_get1_PARAMS(AInfo)
  else
    Result:=nil;
end;

class function TTaurusTLSOSSLStore.TStoreInfoHelper.ClonePubKey(
  AInfo: POSSL_STORE_INFO): PEVP_PKEY;
begin
  if IsExist(AInfo) then
    Result:=OSSL_STORE_INFO_get1_PUBKEY(AInfo)
  else
    Result:=nil;
end;

class function TTaurusTLSOSSLStore.TStoreInfoHelper.ClonePrivKey(
  AInfo: POSSL_STORE_INFO): PEVP_PKEY;
begin
  if IsExist(AInfo) then
    Result:=OSSL_STORE_INFO_get1_PKEY(AInfo)
  else
    Result:=nil;
end;

class function TTaurusTLSOSSLStore.TStoreInfoHelper.CloneCert(
  AInfo: POSSL_STORE_INFO): PX509;
begin
  if IsExist(AInfo) then
    Result:=OSSL_STORE_INFO_get1_CERT(AInfo)
  else
    Result:=nil;
end;

class function TTaurusTLSOSSLStore.TStoreInfoHelper.CloneCrl(
  AInfo: POSSL_STORE_INFO): PX509_CRL;
begin
  if IsExist(AInfo) then
    Result:=OSSL_STORE_INFO_get1_CRL(AInfo)
  else
    Result:=nil;
end;

class procedure TTaurusTLSOSSLStore.TStoreInfoHelper.Free(
  var AInfo: POSSL_STORE_INFO);
begin
  if IsExist(AInfo) then
    OSSL_STORE_INFO_free(AInfo);
  AInfo:=nil;
end;

{ TTaurusTLSOSSLStore.TOsslStoreCtxHelper }

class function TTaurusTLSOSSLStore.TOsslStoreCtxHelper.Open(AUri: PIdAnsiChar;
  AUi: TTaurusTLSCustomOsslUi): POSSL_STORE_CTX;
var
  lMeth: PUI_METHOD;

begin
  if Assigned(AUi) then
    lMeth:=AUi.UiMethod
  else
  begin
    AUi:=nil;
    lMeth:=nil;
  end;

  Result:=OSSL_STORE_open(PIdAnsiChar(AUri), lMeth, AUi, nil, nil);
end;

class function TTaurusTLSOSSLStore.TOsslStoreCtxHelper.Open(ABio: TTaurusTLSCustomBIO;
  AUi: TTaurusTLSCustomOsslUi): POSSL_STORE_CTX;
var
  lMeth: PUI_METHOD;

begin
  if not Assigned(ABio) then
    Exit (nil);

  if Assigned(AUi) then
    lMeth:=AUi.UiMethod
  else
  begin
    AUi:=nil;
    lMeth:=nil;
  end;

  Result:=OSSL_STORE_attach(ABio.BIO, nil, nil, nil, lMeth, AUi,
    nil, nil, nil);
end;

class procedure TTaurusTLSOSSLStore.TOsslStoreCtxHelper.Close(ACtx: POSSL_STORE_CTX);
begin
  OSSL_STORE_close(ACtx);
end;

procedure TTaurusTLSOSSLStore.TOsslStoreCtxHelper.Close;
begin
  Close(Self);
end;

class function TTaurusTLSOSSLStore.TOsslStoreCtxHelper.Eof(
  ACtx: POSSL_STORE_CTX): boolean;
begin
  Result:=OSSL_STORE_eof(ACtx) = 1;
end;

function TTaurusTLSOSSLStore.TOsslStoreCtxHelper.Eof: boolean;
begin
  Result:=Eof(Self);
end;

class function TTaurusTLSOSSLStore.TOsslStoreCtxHelper.IsLoadError(
  ACtx: POSSL_STORE_CTX): boolean;
begin
  Result:=OSSL_STORE_error(ACtx) = 1;
end;

function TTaurusTLSOSSLStore.TOsslStoreCtxHelper.IsLoadError: boolean;
begin
  Result:=IsLoadError(Self);
end;

class function TTaurusTLSOSSLStore.TOsslStoreCtxHelper.Load(
  ACtx: POSSL_STORE_CTX): POSSL_STORE_INFO;
begin
  Result:=OSSL_STORE_load(ACtx);
end;

function TTaurusTLSOSSLStore.TOsslStoreCtxHelper.Load: POSSL_STORE_INFO;
begin
  Result:=Load(Self);
end;

{ TTaurusTLSOSSLStore.TStoreItem }

constructor TTaurusTLSOSSLStore.TStoreItem.Create(AInfo: POSSL_STORE_INFO);
begin
  inherited Create;
  if Assigned(AInfo) then
    FData.FType:=POSSL_STORE_INFO.GetType(AInfo);
  case FData.FType of
    sitName:
      FData.FName:=POSSL_STORE_INFO.CloneNameA(AInfo);
    sitParams:
      FData.FPKey:=POSSL_STORE_INFO.CloneParams(AInfo);
    sitPubKey:
      FData.FPKey:=POSSL_STORE_INFO.ClonePubKey(AInfo);
    sitPrivKey:
      FData.FPKey:=POSSL_STORE_INFO.ClonePrivKey(AInfo);
    sitCert:
      FData.FCert:=POSSL_STORE_INFO.CloneCert(AInfo);
    sitCRL:
      FData.FCrl:=POSSL_STORE_INFO.CloneCrl(AInfo);
  end;
end;

destructor TTaurusTLSOSSLStore.TStoreItem.Destroy;
begin
  case FData.FType of
    sitParams, sitPubKey, sitPrivKey:
      EVP_PKEY_free(FData.FPKey);
    sitCert:
      X509_free(FData.FCert);
    sitCRL:
      X509_CRL_free(FData.FCrl);
  end;
  inherited;
end;

function TTaurusTLSOSSLStore.TStoreItem.GetType: TStoreInfoType;
begin
  Result:=FData.FType;
end;

function TTaurusTLSOSSLStore.TStoreItem.GetName: RawByteString;
begin
  Result:=FData.FName;
end;

function TTaurusTLSOSSLStore.TStoreItem.GetParams: PEVP_PKEY;
begin
  if FData.FType = sitParams then
    Result:=FData.FPKey
  else
    Result:=nil;
end;

function TTaurusTLSOSSLStore.TStoreItem.GetPubKey: PEVP_PKEY;
begin
  if FData.FType = sitPubKey then
    Result:=FData.FPKey
  else
    Result:=nil;
end;

function TTaurusTLSOSSLStore.TStoreItem.GetPrivKey: PEVP_PKEY;
begin
  if FData.FType = sitPrivKey then
    Result:=FData.FPKey
  else
    Result:=nil;
end;

function TTaurusTLSOSSLStore.TStoreItem.GetCert: PX509;
begin
  if FData.FType = sitCert then
    Result:=FData.FCert
  else
    Result:=nil;
end;

function TTaurusTLSOSSLStore.TStoreItem.GetCrl: PX509_CRL;
begin
  if FData.FType = sitCRL then
    Result:=FData.FCrl
  else
    Result:=nil;
end;

{ TTaurusTLSOSSLStore }

constructor TTaurusTLSOSSLStore.Create(ACtx: POSSL_STORE_CTX;
  ALoadFilter: TStoreItemTypes);
begin
  if not Assigned(ACtx) then
    ETaurusTLSOSSLStoreError.RaiseException(RMSG_OsslStoreInit_err);
  inherited Create;
  FList:=TListInfo.Create;
  DoLoad(ACtx, ALoadFilter);
  if OSSL_STORE_close(ACtx) <> 1 then
    ETaurusTLSOSSLStoreError.RaiseException(RMSG_OsslStoreClose_err);
end;

constructor TTaurusTLSOSSLStore.Create(AUri: RawByteString;
  AUi:TTaurusTLSCustomOsslUi; ALoadFilter: TStoreItemTypes);
var
  lCtx: POSSL_STORE_CTX;

begin
  lCtx:=POSSL_STORE_CTX.Open(PIdAnsiChar(AUri), AUi);
  Create(lCtx, ALoadFilter);
end;

constructor TTaurusTLSOSSLStore.Create(AUri: UnicodeString;
  AUi: TTaurusTLSCustomOsslUi; ALoadFilter: TStoreItemTypes);
begin
  Create(RawByteString(AUri), AUi, ALoadFilter);
end;

constructor TTaurusTLSOSSLStore.Create(ABio: TTaurusTLSCustomBIO;
  AUi: TTaurusTLSCustomOsslUi; ALoadFilter: TStoreItemTypes);
var
  lCtx: POSSL_STORE_CTX;

begin
  lCtx:=POSSL_STORE_CTX.Open(ABio, AUi);
  Create(lCtx, ALoadFilter);
end;

destructor TTaurusTLSOSSLStore.Destroy;
begin
  inherited;
  FreeAndNil(FList);
end;

function TTaurusTLSOSSLStore.GetCount(AType: TStoreItemType): TIdC_Uint;
begin
  Result:=FCounters[AType];
end;

procedure TTaurusTLSOSSLStore.DoLoad(ACtx: POSSL_STORE_CTX;
  ALoadFilter: TStoreItemTypes);
var
  lFilter: TStoreItemTypes;
  lInfo: POSSL_STORE_INFO;
  lItem: TStoreItem;

begin
  lFilter:=ALoadFilter;
  while not POSSL_STORE_CTX.Eof(ACtx) do
  begin
    lInfo:=POSSL_STORE_CTX.Load(ACtx);
    if not ((POSSL_STORE_INFO.IsExist(lInfo) and
      (POSSL_STORE_INFO.GetType(lInfo) in ALoadFilter))) then
      continue;
    try
      lItem:=TStoreItem.Create(lInfo);
      FList.Add(lItem);
      Inc(FCounters[lItem.&Type]);
    finally
      POSSL_STORE_INFO.Free(lInfo);
    end;
  end;
end;

{ TTaurusTLSOSSLStoreHelper.TEnumerator }

constructor TTaurusTLSOSSLStoreHelper.TEnumerator.Create(AList: TListInfo;
  AFilter: TStoreItemTypes);
begin
  FEnum:=AList.GetEnumerator;
  FFilter:=AFilter;
  FCurrent:=nil;
end;

destructor TTaurusTLSOSSLStoreHelper.TEnumerator.Destroy;
begin
  FreeAndNil(FEnum);
  inherited;
end;

function TTaurusTLSOSSLStoreHelper.TEnumerator.GetCurrent: TStoreItem;
begin
  Result:=FEnum.Current;
end;

function TTaurusTLSOSSLStoreHelper.TEnumerator.GetEnumerator: TEnumerator;
begin
  Result:=Self;
end;

function TTaurusTLSOSSLStoreHelper.TEnumerator.MoveNext: boolean;
begin
  Result:=False;
  while FEnum.MoveNext do
    if FEnum.Current.&Type in FFilter then
      Exit(True);
end;

{ TTaurusTLSOSSLStoreHelper }

function TTaurusTLSOSSLStoreHelper.GetEnumerator(
  const AFilter: TTaurusTLSOSSLStore.TStoreItemTypes): TEnumerator;
begin
  Result:=TEnumerator.Create(FList, AFilter);
end;

function TTaurusTLSOSSLStoreHelper.GetEnumerator: TEnumerator;
begin
  Result:=GetEnumerator(cStoreAElementsAll);
end;

{ TTaurusTLSX509VerifyParam }

constructor TTaurusTLSX509VerifyParam.Create;
begin
  inherited Create(X509_VERIFY_PARAM_new);
end;

destructor TTaurusTLSX509VerifyParam.Destroy;
begin
  X509_VERIFY_PARAM_free(FParam);
  inherited;
end;

{ TaurusTLS_X509Store.TVfyParam }

constructor TaurusTLS_X509Store.TVfyParam.Create(AStore: PX509_STORE);
begin
  inherited Create(X509_STORE_get0_param(AStore));
end;

{ TaurusTLS_X509Store }

constructor TaurusTLS_X509Store.Create;
begin
  FStore:=X509_STORE_new;
  if not Assigned(FStore) then
    ETaurusTLSX509StoreError.RaiseException(RMSG_X509StoreCreate_err);
  inherited;
end;

constructor TaurusTLS_X509Store.Create(AStore: TTaurusTLSOSSLStore;
  AFilter: TX509Elements);
begin
  Create;
  AddFromStore(AStore, AFilter);
end;

destructor TaurusTLS_X509Store.Destroy;
begin
  X509_STORE_free(FStore);
  inherited;
end;

procedure TaurusTLS_X509Store.AddFromStore(AStore: TTaurusTLSOSSLStore;
  AFilter: TX509Elements);
var
  lElement: TTaurusTLSOSSLStore.TStoreItem;

begin
  if not Assigned(AStore) then
    Exit;
  AFilter:=AFilter*cX509ElementsAll; //Only Certificates and CRLs can be added
  for lElement in AStore.GetEnumerator(AFilter) do
  begin
    case lElement.&Type of
    sitCert: AddCert(lElement.Cert);
    sitCrl:  AddCrl(lElement.GetCrl);
    end;
  end;
end;

procedure TaurusTLS_X509Store.AttachToSSLCtx(ASSLCtx: PSSL_CTX);
begin
  SSL_CTX_set1_cert_store(ASSLCtx, FStore);
end;

procedure TaurusTLS_X509Store.AddCert(ACert: PX509);
begin
  if X509_STORE_add_cert(FStore, ACert) <> 1 then
    ETaurusTLSX509StoreError.RaiseException(RMSG_X509StoreCertAdd_err);
end;

procedure TaurusTLS_X509Store.AddCrl(ACrl: PX509_CRL);
begin
  if X509_STORE_add_crl(FStore, ACrl) <> 1 then
    ETaurusTLSX509StoreError.RaiseException(RMSG_X509StoreCRLAdd_err);
end;

procedure TaurusTLS_X509Store.SetParam(
  AVfyParam: TTaurusTLSCustomX509VerifyParam);
begin
  if not Assigned(AVfyParam) then
    Exit;
  if X509_STORE_set1_param(FStore, AVfyParam.VfyParam) <> 1 then
    ETaurusTLSX509StoreError.RaiseException(RMSG_X509StoreSetVfyParam_err);
  // Reset internal params;
  FreeAndNil(FVfyParam);
end;

function TaurusTLS_X509Store.GetParam: TTaurusTLSCustomX509VerifyParam;
begin
  if not Assigned(FVfyParam) then
    FVfyParam:=TVfyParam.Create(FStore);
  Result:=FVfyParam;
end;

end.
