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
  private
    FParam: PX509_VERIFY_PARAM ;
    function GetVerifyFlags: TTaurusTLSX509VerifyFlags;
      {$IFDEF USE_INLINE}inline;{$ENDIF}
    procedure SetVerifyFlags(const Value: TTaurusTLSX509VerifyFlags);
      {$IFDEF USE_INLINE}inline;{$ENDIF}
    function GetInheritanceFlags: TTaurusTLSX509InheritanceFlags;
      {$IFDEF USE_INLINE}inline;{$ENDIF}
    procedure SetInheritanceFlags(const Value: TTaurusTLSX509InheritanceFlags);
      {$IFDEF USE_INLINE}inline;{$ENDIF}
    function GetDepht: TIdC_Int; {$IFDEF USE_INLINE}inline;{$ENDIF}
    procedure SetDepth(const Value: TIdC_Int); {$IFDEF USE_INLINE}inline;{$ENDIF}
    function GetSecurityBits: TTaurusTLSSecurityBits;
      {$IFDEF USE_INLINE}inline;{$ENDIF}
    procedure SetSecurityBits(const Value: TTaurusTLSSecurityBits);
      {$IFDEF USE_INLINE}inline;{$ENDIF}
    function GetTime: TDateTime; {$IFDEF USE_INLINE}inline;{$ENDIF}
    procedure SetTime(const Value: TDateTime); {$IFDEF USE_INLINE}inline;{$ENDIF}
    function GetHostCheckFlags: TTaurusTLSX509HostCheckFlags;
      {$IFDEF USE_INLINE}inline;{$ENDIF}
    procedure SetHostCheckFlags(const Value: TTaurusTLSX509HostCheckFlags);
      {$IFDEF USE_INLINE}inline;{$ENDIF}
    function GetPurpose: TTaurusTLSX509Purpose;
      {$IFDEF USE_INLINE}inline;{$ENDIF}
    procedure SetPurpose(Value: TTaurusTLSX509Purpose);
      {$IFDEF USE_INLINE}inline;{$ENDIF}

  protected
    ///  <summary>
    ///  Initializes instance using the native verification parameter
    ///  structure pointer.
    ///  </summary>
    ///  <param name="AParam">The native pointer to the structure.</param>
  {$IFDEF FPC}
    {$WARN 3018 off : Constructor should be public}
  {$ENDIF}
    constructor Create(AParam: PX509_VERIFY_PARAM);
  {$IFDEF FPC}
    {$WARN 3018 on : Constructor should be public}
  {$ENDIF}

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
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Retrieves a hostname stored for verification as an AnsiString.
    ///  </summary>
    ///  <param name="ANumber">Index of the hostname to retrieve.</param>
    function GetHostA(ANumber: TIdC_Int): RawByteString;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Retrieves a hostname stored for verification as a Unicode string.
    ///  </summary>
    ///  <param name="ANumber">Index of the hostname to retrieve.</param>
    function GetHostW(ANumber: TIdC_Int): UnicodeString;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Retrieves a hostname stored for verification.
    ///  </summary>
    ///  <param name="ANumber">Index of the hostname to retrieve.</param>
    function GetHost(ANumber: TIdC_Int): string;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Sets a single hostname for verification (AnsiString).
    ///  </summary>
    ///  <param name="Value">The hostname string.</param>
    ///  <remarks>
    ///  Method value clears hostnames list before setting new one.
    ///  Emtpy value <c>Value</c> keeps it empty.
    ///  </remarks>
    procedure SetHostRaw(Value: PIdAnsiChar);
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Sets a single hostname for verification (AnsiString).
    ///  </summary>
    ///  <param name="Value">The hostname string.</param>
    ///  <remarks>
    ///  Method value clears hostnames list before setting new one.
    ///  Emtpy value <c>Value</c> keeps it empty.
    ///  </remarks>
    procedure SetHostA(const Value: RawByteString);
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Sets a single hostname for verification (UnicodeString).
    ///  </summary>
    ///  <param name="Value">The hostname string.</param>
    ///  <remarks>
    ///  Method value clears hostnames list before setting new one.
    ///  Emtpy value <c>Value</c> keeps it empty.
    ///  </remarks>
    procedure SetHostW(const Value: UnicodeString);
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Sets a single hostname for verification.
    ///  </summary>
    ///  <param name="Value">The hostname string.</param>
    ///  <remarks>
    ///  Method value clears hostnames list before setting new one.
    ///  Emtpy value <c>Value</c> keeps it empty.
    ///  </remarks>
    procedure SetHost(const Value: string);
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Adds a hostname (AnsiString) to the list checked during
    ///  verification.
    ///  </summary>
    ///  <param name="Value">The hostname string.</param>
    procedure AddHostA(const Value: RawByteString);
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Adds a hostname (UnicodeString) to the list checked during
    ///  verification.
    ///  </summary>
    ///  <param name="Value">The hostname string.</param>
    procedure AddHostW(const Value: UnicodeString);
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Adds a hostname to the list checked during
    ///  verification.
    ///  </summary>
    ///  <param name="Value">The hostname string.</param>
    procedure AddHost(const Value: string);
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Removes all previously added hostnames addresses from the validation
    ///  </summary>
    procedure CleanHosts; {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Retrieves the PerName identity for application domain checks
    ///  as an AnsiString.
    ///  </summary>
    function GetPerNameA: RawByteString; {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Retrieves the PerName identity for application domain checks
    ///  as a Unicode string.
    ///  </summary>
    function GetPerNameW: UnicodeString; {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Retrieves the PerName identity for application domain checks
    ///  as a string.
    ///  </summary>
    function GetPerName: string; {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Retrieves the raw C-style string pointer to the email address set for
    ///  identity checking.
    ///  </summary>
    ///  <returns>A PIdAnsiChar pointer to the string data.</returns>
    function GetEmailRaw: PIdAnsiChar; {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Retrieves the expected email address as an Ansi or UTF8 string.
    ///  </summary>
    function GetEmailA: RawByteString; {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Retrieves the expected email address as a Unicode string.
    ///  </summary>
    function GetEmailW: UnicodeString; {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Retrieves the expected email address as a string.
    ///  </summary>
    function GetEmail: string; {$IFDEF USE_INLINE}inline;{$ENDIF}

    /// <summary>
    ///   Sets the expected email address for identity checking.
    /// </summary>
    /// <param name="Value">
    ///   The email address string.
    /// </param>
    /// <remarks>
    ///   All previously set or added email addresses are replaced with new
    ///   eamail address.
    /// </remarks>
    procedure SetEMailRaw(Value: PIdAnsiChar); {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Sets the expected email address (Ansi or UTF8 String) for identity
    ///  checking.
    ///  </summary>
    ///  <param name="Value">The email address string.</param>
    /// <remarks>
    ///   All previously set or added email addresses are replaced with new
    ///   eamail address.
    /// </remarks>
    procedure SetEMailA(const Value: RawByteString);
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Sets the expected email address (UnicodeString) for identity
    ///  checking.
    ///  </summary>
    ///  <param name="Value">The email address string.</param>
    /// <remarks>
    ///   All previously set or added email addresses are replaced with new
    ///   eamail address.
    /// </remarks>
    procedure SetEMailW(const Value: UnicodeString);
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Sets the expected email address for identity checking.
    ///  </summary>
    ///  <param name="Value">The email address string.</param>
    /// <remarks>
    ///   All previously set or added email addresses are replaced with new
    ///   eamail address.
    /// </remarks>
    procedure SetEMail(const Value: string);
      {$IFDEF USE_INLINE}inline;{$ENDIF}



    /// <summary>
    ///   Sets the expected email address for identity checking.
    /// </summary>
    /// <param name="Value">
    ///   The email address string.
    /// </param>
    /// <remarks>
    ///   All previously set or added email addresses are retained.
    ///   This method avalable only with OpenSSL 4.0 and higher.
    /// </remarks>
    procedure AddEMailRaw(Value: PIdAnsiChar); {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Sets the expected email address (Ansi or UTF8 String) for identity
    ///  checking.
    ///  </summary>
    ///  <param name="Value">The email address string.</param>
    /// <remarks>
    ///   All previously set or added email addresses are retained.
    ///   This method avalable only with OpenSSL 4.0 and higher.
    /// </remarks>
    procedure AddEMailA(const Value: RawByteString);
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Sets the expected email address (UnicodeString) for identity
    ///  checking.
    ///  </summary>
    ///  <param name="Value">The email address string.</param>
    /// <remarks>
    ///   All previously set or added email addresses are retained.
    ///   This method avalable only with OpenSSL 4.0 and higher.
    /// </remarks>
    procedure AddEMailW(const Value: UnicodeString);
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Sets the expected email address for identity checking.
    ///  </summary>
    ///  <param name="Value">The email address string.</param>
    /// <remarks>
    ///   All previously set or added email addresses are retained.
    ///   This method avalable only with OpenSSL 4.0 and higher.
    /// </remarks>
    procedure AddEMail(const Value: string);
      {$IFDEF USE_INLINE}inline;{$ENDIF}



    ///  <summary>
    ///  Removes all previously added email addresses from the validation
    ///  </summary>
    procedure CleanEMails; {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Sets the expected IP address using a TIdIPAddress record.
    ///  </summary>
    ///  <param name="Value">The IP address structure.</param>
    procedure SetIpAddressBinary(const Value: TIdIPAddress);
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Adds the IP address to the expected IP addresses list
    ///  using a TIdIPAddress record.
    ///  </summary>
    ///  <param name="Value">The IP address structure.</param>
    procedure AddIpAddressBinary(const Value: TIdIPAddress);
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Sets the expected IP address (PIdAnsiChar) for identity
    ///  checking.
    ///  </summary>
    ///  <param name="Value">The IP address string.</param>
    procedure SetIpAddressRaw(Value: PIdAnsiChar);
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Sets the expected IP address (AnsiString) for identity
    ///  checking.
    ///  </summary>
    ///  <param name="Value">The IP address string.</param>
    procedure SetIpAddressA(const Value: RawByteString);
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Sets the expected IP address (UnicodeString) for identity
    ///  checking.
    ///  </summary>
    ///  <param name="Value">The IP address string.</param>
    procedure SetIpAddressW(const Value: UnicodeString);
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Sets the expected IP address for identity checking.
    ///  </summary>
    ///  <param name="Value">The IP address string.</param>
    procedure SetIpAddress(const Value: string);
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Sets the expected IP address (PIdAnsiChar) for identity
    ///  checking.
    ///  </summary>
    ///  <param name="Value">The IP address string.</param>
    procedure AddIpAddressRaw(Value: PIdAnsiChar);
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Sets the expected IP address (AnsiString) for identity
    ///  checking.
    ///  </summary>
    ///  <param name="Value">The IP address string.</param>
    procedure AddIpAddressA(const Value: RawByteString);
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Sets the expected IP address (UnicodeString) for identity
    ///  checking.
    ///  </summary>
    ///  <param name="Value">The IP address string.</param>
    procedure AddIpAddressW(const Value: UnicodeString);
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Sets the expected IP address for identity checking.
    ///  </summary>
    ///  <param name="Value">The IP address string.</param>
    procedure AddIpAddress(const Value: string);
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Retrieves the expected IP address as an AnsiString.
    ///  </summary>
    function GetIpAddressA: RawByteString; {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Retrieves the expected IP address as a Unicode string.
    ///  </summary>
    function GetIpAddressW: UnicodeString; {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Retrieves the expected IP address as a string.
    ///  </summary>
    function GetIpAddress: string; {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Removes all previously added IP addresses from the validation
    ///  </summary>
    procedure CleanIPAddresses; {$IFDEF USE_INLINE}inline;{$ENDIF}

    procedure AttachToSSLCtx(ASSLCtx: PSSL_CTX); {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Gets or sets flags controlling certificate path validation
    ///  (e.g., CRL checking, policy enforcement).
    ///  </summary>
    property VerifyFlags: TTaurusTLSX509VerifyFlags read GetVerifyFlags
      write SetVerifyFlags;

    ///  <summary>
    ///  Gets or sets flags controlling how verification parameters are
    ///  inherited or reset in subordinate contexts.
    ///  </summary>
    property InheritanceFlags: TTaurusTLSX509InheritanceFlags
      read GetInheritanceFlags write SetInheritanceFlags;

    ///  <summary>
    ///  Gets or sets flags controlling the strictness of hostname and
    ///  IP address matching.
    ///  </summary>
    property HostCheckFlags: TTaurusTLSX509HostCheckFlags read GetHostCheckFlags
      write SetHostCheckFlags;

    ///  <summary>
    ///  Gets or sets the expected role or usage of the certificate
    ///  (e.g., SSL Server, SMIME Signing).
    ///  </summary>
    property Purpose: TTaurusTLSX509Purpose read GetPurpose write SetPurpose;

    ///  <summary>
    ///  Gets or sets the maximum acceptable chain length for verification.
    ///  </summary>
    property Depth: TIdC_INT read GetDepht write SetDepth;

    ///  <summary>
    ///  Gets or sets the required security level (0-5) for key strength
    ///  and acceptable cryptography.
    ///  </summary>
    property SecurityBits: TTaurusTLSSecurityBits read GetSecurityBits
      write SetSecurityBits;

    ///  <summary>
    ///  Gets or sets the specific time used for certificate validity
    ///  checks (instead of the system time).
    ///  </summary>
    property Time: TDateTime read GetTime write SetTime;
{$IFDEF DCC}
    ///  <summary>
    ///  Retrieves the PerName identity string.
    ///  </summary>    property PerName: UnicodeString read GetPerNameW;
    property PerName: string read GetPerNameW;

    ///  <summary>
    ///  Retrieves a hostname by index.
    ///  </summary>
    property Host[i: TIdC_Int]: UnicodeString read GetHostW;

    ///  <summary>
    ///  Retrieves the email address identity.
    ///  </summary>
    property Email: UnicodeString read GetEmailW;

    ///  <summary>
    ///  Retrieves the IP address identity.
    ///  </summary>
    property IPAddress: UnicodeString read GetIpAddressW;
{$ENDIF}
{$IFDEF FPC}
    property PerName: RawbyteString read GetPerNameA;
    property Host[i: TIdC_Int]: RawbyteString read GetHostA;
    property Email: RawbyteString read GetEmailA;
    property IPAddress: RawbyteString read GetIpAddressA;
{$ENDIF}
  end;

  ///  <summary>
  ///  Concrete class implementation that wraps a native OpenSSL
  ///  X509_VERIFY_PARAM structure holds by <c>SSL</c> or <c>SSL_CTX</c> instance.
  ///  </summary>
  ///  <remarks>
  ///  This instance does not manage the X509_VERIFY_PARAM structure
  ///  lifecycle as <c>SSL</c> or <c>SSL_CTX</c> instances does it do.
  ///  </remarks>
  TTaurusTLSX509VerifyParamSSL = class(TTaurusTLSCustomX509VerifyParam)
    constructor Create(AParam: PX509_VERIFY_PARAM); overload;
    constructor Create(ASSL: PSSL); overload;
    constructor Create(ASSLCtx: PSSL_CTX); overload;
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
    TStoreInfo = record
    private
      FInfo: POSSL_STORE_INFO;
    public
      constructor Create(const AInfo: POSSL_STORE_INFO);
      ///  <summary>
      ///  Retrieves the object type of the stored item.
      ///  </summary>
      ///  <param name="AInfo">The native OSSL_STORE_INFO instance.</param>
      ///  <returns>
      ///  The object type as <see cref="TTaurusTLSOSSLStore.TStoreInfoType" />.
      ///  </returns>
      class function GetType(AInfo: POSSL_STORE_INFO): TStoreInfoType;
        overload; static; {$IFDEF USE_INLINE}inline;{$ENDIF}
      function GetType: TStoreInfoType; overload;{$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Retrieves the raw C-style string pointer identifying the object type.
      ///  </summary>
      ///  <param name="AInfo">The native OSSL_STORE_INFO instance.</param>
      ///  <returns>A C-style string pointer to the type name (e.g., 'CERT').</returns>
      ///  <remarks>The returned pointer is internally managed and must not be freed.</remarks>
      class function GetTypeName(AInfo: POSSL_STORE_INFO): PIdAnsiChar;
        overload; static; {$IFDEF USE_INLINE}inline;{$ENDIF}
      function GetTypeName: PIdAnsiChar; overload;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Checks if the native OSSL_STORE_INFO pointer is valid (not nil).
      ///  </summary>
      ///  <param name="AInfo">The native OSSL_STORE_INFO instance.</param>
      ///  <returns>True if the pointer is not nil.</returns>
      class function IsExist(AInfo: POSSL_STORE_INFO): boolean; overload; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}
      function IsExist: boolean; overload; {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Retrieves the raw C-style string pointer to the name/URI of the
      ///  stored object.
      ///  </summary>
      ///  <param name="AInfo">The native OSSL_STORE_INFO instance.</param>
      ///  <returns>A C-style string pointer to the name/URI.</returns>
      ///  <remarks>The returned pointer is internally managed and must not be freed.</remarks>
      class function GetName(AInfo: POSSL_STORE_INFO): PIdAnsiChar;
        overload; static; {$IFDEF USE_INLINE}inline;{$ENDIF}
      function GetName: PIdAnsiChar; overload;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Retrieves the parameters structure (PEVP_PKEY)
      ///  that holds Key Material Parameters
      ///  </summary>
      ///  <param name="AInfo">The native OSSL_STORE_INFO instance.</param>
      ///  <returns>A pointer to the parameter set.</returns>
      ///  <remarks>No ownership is transferred. Do not free this pointer.</remarks>
      class function GetParams(AInfo: POSSL_STORE_INFO): PEVP_PKEY; overload;
        static; {$IFDEF USE_INLINE}inline;{$ENDIF}
      function GetParams: PEVP_PKEY; overload;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Retrieves the public key structure (<see cref="PEVP_PKEY" />).
      ///  </summary>
      ///  <returns>A pointer to the public key component.</returns>
      ///  <remarks>No ownership is transferred. Do not free this pointer.</remarks>
      class function GetPubKey(AInfo: POSSL_STORE_INFO): PEVP_PKEY;
        overload; static; {$IFDEF USE_INLINE}inline;{$ENDIF}
      function GetPubKey: PEVP_PKEY; overload;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Retrieves the private key structure (<see cref="PEVP_PKEY" />).
      ///  </summary>
      ///  <returns>A pointer to the private key component.</returns>
      ///  <remarks>No ownership is transferred. Do not free this pointer.</remarks>
      class function GetPrivKey(AInfo: POSSL_STORE_INFO): PEVP_PKEY; overload;
        static; {$IFDEF USE_INLINE}inline;{$ENDIF}
      function GetPrivKey: PEVP_PKEY; overload;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Retrieves the certificate structure (PX509).
      ///  </summary>
      ///  <param name="AInfo">The native OSSL_STORE_INFO instance.</param>
      ///  <returns>A pointer to the certificate.</returns>
      ///  <remarks>No ownership is transferred. Do not free this pointer.</remarks>
      class function GetCert(AInfo: POSSL_STORE_INFO): PX509; overload; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}
      function GetCert: PX509; overload; {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Retrieves the CRL structure (PX509_CRL).
      ///  </summary>
      ///  <param name="AInfo">The native OSSL_STORE_INFO instance.</param>
      ///  <returns>A pointer to the CRL.</returns>
      ///  <remarks>No ownership is transferred. Do not free this pointer.</remarks>
      class function GetCrl(AInfo: POSSL_STORE_INFO): PX509_CRL;
        overload; static; {$IFDEF USE_INLINE}inline;{$ENDIF}
      function GetCrl: PX509_CRL; overload;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Retrieves the name/URI of the stored object as an AnsiString.
      ///  </summary>
      ///  <param name="AInfo">The native OSSL_STORE_INFO instance.</param>
      ///  <returns>The name/URI string.</returns>
      ///  <remarks>The memory for the resulting string is internally managed.</remarks>
      class function CloneNameA(AInfo: POSSL_STORE_INFO): RawByteString;
        overload; static; {$IFDEF USE_INLINE}inline;{$ENDIF}
      function CloneNameA: RawByteString; overload;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Retrieves the name/URI of the stored object as a Unicode string.
      ///  </summary>
      ///  <param name="AInfo">The native OSSL_STORE_INFO instance.</param>
      ///  <returns>The name/URI string.</returns>
      ///  <remarks>The memory for the resulting string is internally managed.</remarks>
      class function CloneNameW(AInfo: POSSL_STORE_INFO): UnicodeString;
        overload; static; {$IFDEF USE_INLINE}inline;{$ENDIF}
      function CloneNameW: UnicodeString; overload;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Creates a new copy of the parameters structure (<see cref="PEVP_PKEY" />).
      ///  </summary>
      ///  <returns>A new pointer to the parameter set.</returns>
      ///  <remarks>Ownership is transferred. The caller must free the pointer
      ///  using EVP_PKEY_free or equivalent routine.</remarks>
      class function CloneParams(AInfo: POSSL_STORE_INFO): PEVP_PKEY;
        overload; static; {$IFDEF USE_INLINE}inline;{$ENDIF}
      function CloneParams: PEVP_PKEY; overload;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Creates a new copy of the public key structure (<see cref="PEVP_PKEY" />).
      ///  </summary>
      ///  <returns>A new pointer to the public key component.</returns>
      ///  <remarks>Ownership is transferred. The caller must free the pointer
      ///  using EVP_PKEY_free or equivalent routine.</remarks>
      class function ClonePubKey(AInfo: POSSL_STORE_INFO): PEVP_PKEY;
        overload; static; {$IFDEF USE_INLINE}inline;{$ENDIF}
      function ClonePubKey: PEVP_PKEY; overload;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Creates a new copy of the private key structure (<see cref="PEVP_PKEY" />).
      ///  </summary>
      ///  <returns>A new pointer to the private key component.</returns>
      ///  <remarks>Ownership is transferred. The caller must free the pointer
      ///  using EVP_PKEY_free or equivalent routine.</remarks>
      class function ClonePrivKey(AInfo: POSSL_STORE_INFO): PEVP_PKEY;
        overload; static; {$IFDEF USE_INLINE}inline;{$ENDIF}
      function ClonePrivKey: PEVP_PKEY; overload;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Creates a new copy of the certificate structure (PX509).
      ///  </summary>
      ///  <param name="AInfo">The native OSSL_STORE_INFO instance.</param>
      ///  <returns>A new pointer to the certificate.</returns>
      ///  <remarks>Ownership is transferred. The caller must free the pointer
      ///  using X509_free or equivalent routine.</remarks>
      class function CloneCert(AInfo: POSSL_STORE_INFO): PX509; overload; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}
      function CloneCert: PX509; overload; {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Creates a new copy of the CRL structure (PX509_CRL).
      ///  </summary>
      ///  <param name="AInfo">The native OSSL_STORE_INFO instance.</param>
      ///  <returns>A new pointer to the CRL.</returns>
      ///  <remarks>Ownership is transferred. The caller must free the pointer
      ///  using X509_CRL_free or equivalent routine.</remarks>
      class function CloneCrl(AInfo: POSSL_STORE_INFO): PX509_CRL; overload; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}
      function CloneCrl: PX509_CRL; overload;  {$IFDEF USE_INLINE}inline;{$ENDIF}

      ///  <summary>
      ///  Frees the native OSSL_STORE_INFO instance pointer.
      ///  </summary>
      ///  <param name="AInfo">The native OSSL_STORE_INFO pointer, which will be set to nil.</param>
      ///  <remarks>This should be called when finished with the temporary
      ///  information structure retrieved during store iteration.</remarks>
      class procedure Free(var AInfo: POSSL_STORE_INFO); overload; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}
      procedure Free; overload;
        {$IFDEF USE_INLINE}inline;{$ENDIF}

      property Info: POSSL_STORE_INFO read FInfo write FInfo;
    end;

    ///  <summary>
    ///  Provides methods for managing the native OpenSSL
    ///  OSSL_STORE_CTX instance lifecycle and stream operations.
    ///  </summary>
    ///  <remarks>
    ///  The OSSL Store Context (<see cref="POSSL_STORE_CTX" />) manages the
    ///  process of reading cryptographic objects from a URI or BIO.
    ///  </remarks>
    TStoreCtx = record
    private
      FCtx: POSSL_STORE_CTX;
    {$IFDEF FPC}
      {$WARN 3018 off : Constructor should be public}
    {$ENDIF}
      constructor Create(ACtx: POSSL_STORE_CTX); overload;
    {$IFDEF FPC}
      {$WARN 3018 on : Constructor should be public}
    {$ENDIF}

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
      constructor Create(AUri: PIdAnsiChar; AUi: TTaurusTLSCustomOsslUi); overload;

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
      constructor Create(ABio: TTaurusTLSCustomBIO; AUi: TTaurusTLSCustomOsslUi);
        overload;

      ///  <summary>
      ///  Closes and frees the native OSSL Store Context instance.
      ///  </summary>
      ///  <param name="ACtx">The <see cref="POSSL_STORE_CTX" /> instance to close.</param>
      ///  <remarks>
      ///  This method releases all internal resources associated with the
      ///  context.
      ///  </remarks>
      class procedure Close(var ACtx: POSSL_STORE_CTX); overload; static;
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

      class function IsExist(ACtx: POSSL_STORE_CTX): boolean; overload; static;
        {$IFDEF USE_INLINE}inline;{$ENDIF}
      function IsExist: boolean; overload; {$IFDEF USE_INLINE}inline;{$ENDIF}

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
      function Load: TStoreInfo; overload; {$IFDEF USE_INLINE}inline;{$ENDIF}

      property Ctx: POSSL_STORE_CTX read FCtx;
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
//      constructor Create(AInfo: POSSL_STORE_INFO); overload;
      constructor Create(const AInfo: TStoreInfo); overload;

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

  protected type
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
  {$IFDEF FPC}
    {$WARN 3018 off : Constructor should be public}
  {$ENDIF}
    constructor Create(const ACtx: TStoreCtx;
        ALoadFilter: TStoreItemTypes = cStoreAElementsAll); overload;
  {$IFDEF FPC}
    {$WARN 3018 off : Constructor should be public}
  {$ENDIF}

    ///  <summary>
    ///  Loads of objects from the native OpenSSL Store context and clone
    ///  them into the internal list.
    ///  </summary>
    ///  <param name="ACtx">The native OSSL Store Context pointer.</param>
    ///  <param name="ALoadFilter">The set of types to load.</param>
    procedure DoLoad(const ACtx: TStoreCtx; ALoadFilter: TStoreItemTypes);

  public
    ///  <summary>
    ///  Creates an instance by opening the store using an Ansi or UTF8
    ///  String URI.
    ///  </summary>
    ///  <param name="AUri">The URI (Ansi or UTF8 String).</param>
    ///  <param name="AUi">The User Interaction instance for password prompts.</param>
    ///  <param name="ALoadFilter">The set of types to load.</param>
    constructor Create(const AUri: RawByteString; AUi: TTaurusTLSCustomOsslUi;
      ALoadFilter: TStoreItemTypes = cStoreAElementsAll); overload;

    ///  <summary>
    ///  Creates an instance by opening the store using a URI (UnicodeString).
    ///  </summary>
    ///  <param name="AUri">The URI (e.g., file path).</param>
    ///  <param name="AUi">The User Interaction instance for password prompts.</param>
    ///  <param name="ALoadFilter">The set of types to load.</param>
    constructor Create(const AUri: UnicodeString; AUi: TTaurusTLSCustomOsslUi;
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
    {$IFDEF FPC}
    public type
      TListInfo = TTaurusTLSOSSLStore.TListInfo;
      TStoreItemTypes = TTaurusTLSOSSLStore.TStoreItemTypes;
      TStoreItem = TTaurusTLSOSSLStore.TStoreItem;
    {$ENDIF}
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
      {$IFDEF USE_INLINE}inline;{$ENDIF}
    function GetParam: TTaurusTLSCustomX509VerifyParam;
      {$IFDEF USE_INLINE}inline;{$ENDIF}
    function AppendFromLocationA(const AUri: RawByteString): boolean;
      {$IFDEF USE_INLINE}inline;{$ENDIF}
    function AppendFromLocationW(const AUri: UnicodeString): boolean;
      {$IFDEF USE_INLINE}inline;{$ENDIF}
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
    ///  Appends a single certificate (PX509) to the trusted repository.
    ///  </summary>
    ///  <param name="ACert">The certificate pointer.</param>
    ///  <remarks>The store increments the certificate's reference count
    ///  and takes ownership of the pointer. Do not free the pointer after
    ///  adding it to the store.</remarks>
    procedure AppendCert(ACert: PX509); {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Appends a single Certificate Revocation List (CRL) to the trusted repository.
    ///  </summary>
    ///  <param name="ACrl">The CRL pointer.</param>
    ///  <remarks>The store takes ownership of the pointer. Do not free the
    ///  pointer after adding it to the store.</remarks>
    procedure AppendCrl(ACrl: PX509_CRL); {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  Appends certificates and CRLs from an existing OSSL Store container
    ///  into this trust store.
    ///  </summary>
    ///  <param name="AStore">The <see cref="TTaurusTLSOSSLStore" /> instance.</param>
    ///  <param name="AFilter">The set of elements (<see cref="TX509Element" />) to add.</param>
    ///  <remarks>
    ///  Items are added cumulatively, preserving all previously existing
    ///  certificates and CRLs in the store.
    ///  </remarks>
    procedure AppendFromOsslStore(const AStore: TTaurusTLSOSSLStore; AFilter: TX509Elements);
      overload; {$IFDEF USE_INLINE}inline;{$ENDIF}

    /// <summary>
    ///   Appends a single or multiple Certificate(s) Certificate Revocation
    ///   List(s) (CRL) to the trusted repository from the <c>Uri.</c>
    /// </summary>
    /// <param name="AStore">
    ///   The <see cref="TTaurusTLSOSSLStore" /> instance.
    /// </param>
    /// <param name="AFilter">
    ///   The set of elements ( <see cref="TX509Element" />) to add.
    /// </param>
    /// <remarks>
    ///   <list type="bullet">
    ///     <item>
    ///       Items are added cumulatively, preserving all previously existing
    ///       certificates and CRLs in the store.
    ///     </item>
    ///     <item>
    ///       OpenSSL currently supports file:// location on all platforms and
    ///       org.openssl.winstore:// on Windows platforms.
    ///     </item>
    ///   </list>
    /// </remarks>
    procedure AppendFromLocation(const AUri: string); {$IFDEF USE_INLINE}inline;{$ENDIF}

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

{ TTaurusTLSCustomX509VerifyParam }

constructor TTaurusTLSCustomX509VerifyParam.Create(AParam: PX509_VERIFY_PARAM);
begin
  if not Assigned(AParam) then
    ETaurusTLSX509StoreError.RaiseWithMessage(RMSG_X509VfyParamNull_err);
  inherited Create;
  FParam:=AParam;
end;

function TTaurusTLSCustomX509VerifyParam.GetVerifyFlags: TTaurusTLSX509VerifyFlags;
begin
  Result:=TTaurusTLSX509VerifyFlags.FromInt(X509_VERIFY_PARAM_get_flags(FParam));
end;

procedure TTaurusTLSCustomX509VerifyParam.SetVerifyFlags(
  const Value: TTaurusTLSX509VerifyFlags);
var
  lFlags, lClearFlags: TTaurusTLSX509VerifyFlags;

begin
  lFlags:=VerifyFlags;
  if X509_VERIFY_PARAM_set_flags(FParam, Value.AsInt) <= 0 then
    ETaurusTLSX509StoreError.RaiseWithMessage(RMSG_X509VfyParamFlag_err);
  lClearFlags:=lFlags-Value;
  if lClearFlags <> [] then
    if X509_VERIFY_PARAM_clear_flags(FParam, lClearFlags.AsInt) <= 0 then
      ETaurusTLSX509StoreError.RaiseWithMessage(RMSG_X509VfyParamFlag_err);
end;

function TTaurusTLSCustomX509VerifyParam.GetInheritanceFlags: TTaurusTLSX509InheritanceFlags;
begin
  Result:=TTaurusTLSX509InheritanceFlags.FromInt(
    X509_VERIFY_PARAM_get_inh_flags(Fparam));
end;

procedure TTaurusTLSCustomX509VerifyParam.SetInheritanceFlags(
  const Value: TTaurusTLSX509InheritanceFlags);
begin
  if X509_VERIFY_PARAM_set_inh_flags(FParam, Value.AsInt) <= 0 then
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

{$IFDEF FPC}
{$WARN 5059 off : Function result variable does not seem to be initialized}
{$ENDIF}
function TTaurusTLSCustomX509VerifyParam.GetSecurityBits: TTaurusTLSSecurityBits;
begin
  Result.AsInt:=X509_VERIFY_PARAM_get_auth_level(FParam);
end;
{$IFDEF FPC}
{$WARN 5059 on : Function result variable does not seem to be initialized}
{$ENDIF}

procedure TTaurusTLSCustomX509VerifyParam.SetSecurityBits(
  const Value: TTaurusTLSSecurityBits);
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

function TTaurusTLSCustomX509VerifyParam.GetHostCheckFlags: TTaurusTLSX509HostCheckFlags;
begin
  Result:=TTaurusTLSX509HostCheckFlags.FromInt(
    X509_VERIFY_PARAM_get_hostflags(FParam));
end;

procedure TTaurusTLSCustomX509VerifyParam.SetHostCheckFlags(
  const Value: TTaurusTLSX509HostCheckFlags);
begin
  X509_VERIFY_PARAM_set_hostflags(FParam, Value.AsInt);
end;

function TTaurusTLSCustomX509VerifyParam.GetHostRaw(
  ANumber: TIdC_Int): PIdAnsiChar;
begin
  Result:=X509_VERIFY_PARAM_get0_host(FParam, ANumber);
end;

function TTaurusTLSCustomX509VerifyParam.GetHost(ANumber: TIdC_Int): string;
begin
{$IFDEF STRING_IS_UNICODE}
  Result:=GetHostW(ANumber);
{$ELSE}
  Result:=GetHostA(ANumber);
{$ENDIF}
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

procedure TTaurusTLSCustomX509VerifyParam.SetHostRaw(Value: PIdAnsiChar);
begin
  if X509_VERIFY_PARAM_set1_host(FParam, PIdAnsiChar(Value), 0) <= 0 then // PALOFF Possible bad typecast
    ETaurusTLSX509StoreError.RaiseWithMessage(RMSG_X509VfyHost_err);
end;

procedure TTaurusTLSCustomX509VerifyParam.SetHost(const Value: string);
begin
{$IFDEF STRING_IS_UNICODE}
  SetHostW(Value);
{$ELSE}
  SetHostA(Value);
{$ENDIF}
end;

procedure TTaurusTLSCustomX509VerifyParam.SetHostA(const Value: RawByteString);
begin
  SetHostRaw(PIdAnsiChar(Value));  // PALOFF Possible bad typecast
end;

procedure TTaurusTLSCustomX509VerifyParam.SetHostW(const Value: UnicodeString);
begin
  SetHostA(RawByteString(Value));
end;

procedure TTaurusTLSCustomX509VerifyParam.AddHost(const Value: string);
begin
{$IFDEF STRING_IS_UNICODE}
  AddHostW(Value);
{$ELSE}
  AddHostA(Value);
{$ENDIF}
end;

procedure TTaurusTLSCustomX509VerifyParam.AddHostA(const Value: RawByteString);
begin
  if Value = '' then
    Exit;
  if X509_VERIFY_PARAM_add1_host(FParam, PIdAnsiChar(Value), 0) <= 0 then  // PALOFF Possible bad typecast
    ETaurusTLSX509StoreError.RaiseWithMessage(RMSG_X509VfyHost_err);
end;

procedure TTaurusTLSCustomX509VerifyParam.AddHostW(const Value: UnicodeString);
begin
  AddHostA(RawByteString(Value));
end;

procedure TTaurusTLSCustomX509VerifyParam.AttachToSSLCtx(ASSLCtx: PSSL_CTX);
begin
  if SSL_CTX_set1_param(ASSLCtx, FParam) <= 0 then
    ETaurusTLSX509StoreError.RaiseWithMessage(RMSG_X509VfyAttachSSL_err);
end;

procedure TTaurusTLSCustomX509VerifyParam.CleanHosts;
begin
  if X509_VERIFY_PARAM_set1_host(FParam, nil, 0) <= 1 then
    ETaurusTLSX509StoreError.RaiseWithMessage(RMSG_X509VfyCleanHost_err);
end;

function TTaurusTLSCustomX509VerifyParam.GetPerName: string;
begin
{$IFDEF STRING_IS_UNICODE}
  Result:=GetPerNameW;
{$ELSE}
  Result:=GetPerNameA;
{$ENDIF}
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

function TTaurusTLSCustomX509VerifyParam.GetEmail: string;
begin
{$IFDEF STRING_IS_UNICODE}
  Result:=GetEmailW;
{$ELSE}
  Result:=GetEmailA;
{$ENDIF}
end;

function TTaurusTLSCustomX509VerifyParam.GetEmailA: RawByteString;
begin
  Result:=RawByteString(GetEmailRaw);
end;

function TTaurusTLSCustomX509VerifyParam.GetEmailW: UnicodeString;
begin
  Result:=UnicodeString(GetEmailRaw);
end;

procedure TTaurusTLSCustomX509VerifyParam.SetEMailRaw(Value: PIdAnsiChar);
begin
  if X509_VERIFY_PARAM_set1_email(FParam, Value, Length(Value)) <= 0 then
    ETaurusTLSX509StoreError.RaiseWithMessage(RMSG_X509VfyEMail_set_err);
end;

procedure TTaurusTLSCustomX509VerifyParam.SetEMail(const Value: string);
begin
{$IFDEF STRING_IS_UNICODE}
  SetEmailW(Value);
{$ELSE}
  SetEmailA(Value);
{$ENDIF}
end;

procedure TTaurusTLSCustomX509VerifyParam.SetEMailA(const Value: RawByteString);
begin
  SetEmailRaw(PIdAnsiChar(Value));  // PALOFF Possible bad typecast
end;

procedure TTaurusTLSCustomX509VerifyParam.SetEMailW(const Value: UnicodeString);
begin
  SetEMailA(RawByteString(Value));
end;

procedure TTaurusTLSCustomX509VerifyParam.AddEMailRaw(Value: PIdAnsiChar);
var
  lLen: TIdC_INT;
  lRes: boolean;

begin
  lLen:=Length(Value);
  lRes:=(X509_VERIFY_PARAM_add1_rfc822(FParam, Value, lLen) > 0);
  lRes:=lRes or (X509_VERIFY_PARAM_add1_smtputf8(FParam, Value, lLen) > 0);
  if not lRes then
    ETaurusTLSX509StoreError.RaiseWithMessage(RMSG_X509VfyEMail_add_err);
end;

procedure TTaurusTLSCustomX509VerifyParam.AddEMailA(const Value: RawByteString);
begin
  AddEMailRaw(PIdAnsiChar(Value));  // PALOFF Possible bad typecast
end;

procedure TTaurusTLSCustomX509VerifyParam.AddEMailW(const Value: UnicodeString);
begin
  AddEmailA(UTF8String(Value));
end;

procedure TTaurusTLSCustomX509VerifyParam.AddEMail(const Value: string);
begin
{$IFDEF STRING_IS_UNICODE}
  AddEmailW(Value);
{$ELSE}
  AddEmailA(Value);
{$ENDIF}
end;

procedure TTaurusTLSCustomX509VerifyParam.CleanEMails;
begin
  if X509_VERIFY_PARAM_set1_host(FParam, nil, 0) <= 0 then
    ETaurusTLSX509StoreError.RaiseWithMessage(RMSG_X509VfyCleanHost_err);
end;

procedure TTaurusTLSCustomX509VerifyParam.SetIpAddressBinary(
  const Value: TIdIPAddress);
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
  if X509_VERIFY_PARAM_set1_ip(FParam, lData, lSize) <= 0 then
    ETaurusTLSX509StoreError.RaiseWithMessage(RMSG_X509VfyIPAddr_set_err);
end;

procedure TTaurusTLSCustomX509VerifyParam.AddIpAddressBinary(
  const Value: TIdIPAddress);
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
  if X509_VERIFY_PARAM_add1_ip(FParam, lData, lSize) <= 0 then
    ETaurusTLSX509StoreError.RaiseWithMessage(RMSG_X509VfyIPAddr_add_err);
end;

procedure TTaurusTLSCustomX509VerifyParam.SetIpAddressRaw(Value: PIdAnsiChar);
begin
  if X509_VERIFY_PARAM_set1_ip_asc(FParam, PIdAnsiChar(Value)) <= 0 then  // PALOFF Possible bad typecast
    ETaurusTLSX509StoreError.RaiseWithMessage(RMSG_X509VfyIPAddr_set_err);
end;

procedure TTaurusTLSCustomX509VerifyParam.SetIpAddress(const Value: string);
begin
{$IFDEF STRING_IS_UNICODE}
  SetIpAddressW(Value);
{$ELSE}
  SetIpAddressA(Value);
{$ENDIF}
end;

procedure TTaurusTLSCustomX509VerifyParam.SetIpAddressA(const Value: RawByteString);
begin
  SetIpAddressRaw(PIdAnsiChar(Value)); // PALOFF Possible bad typecast
end;

procedure TTaurusTLSCustomX509VerifyParam.SetIpAddressW(const Value: UnicodeString);
begin
  SetIpAddressA(RawByteString(Value));
end;

procedure TTaurusTLSCustomX509VerifyParam.AddIpAddressRaw(Value: PIdAnsiChar);
begin
  if X509_VERIFY_PARAM_add1_ip_asc(FParam, PIdAnsiChar(Value)) <= 0 then // PALOFF Possible bad typecast
    ETaurusTLSX509StoreError.RaiseWithMessage(RMSG_X509VfyIPAddr_add_err);
end;

procedure TTaurusTLSCustomX509VerifyParam.AddIpAddressA(
  const Value: RawByteString);
begin
  AddIpAddressRaw(PIdAnsiChar(Value)); // PALOFF Possible bad typecast
end;

procedure TTaurusTLSCustomX509VerifyParam.AddIpAddressW(
  const Value: UnicodeString);
begin
  AddIpAddressA(RawByteString(Value));
end;

procedure TTaurusTLSCustomX509VerifyParam.AddIpAddress(const Value: string);
begin
{$IFDEF STRING_IS_UNICODE}
  AddIpAddressW(Value);
{$ELSE}
  AddIpAddressA(Value);
{$ENDIF}
end;

function TTaurusTLSCustomX509VerifyParam.GetIpAddress: string;
begin
{$IFDEF STRING_IS_UNICODE}
  Result:=GetIpAddressW;
{$ELSE}
  Result:=GetIpAddressA;
{$ENDIF}
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

procedure TTaurusTLSCustomX509VerifyParam.CleanIPAddresses;
begin
  if X509_VERIFY_PARAM_set1_ip_asc(FParam, nil) <= 0 then
    ETaurusTLSX509StoreError.RaiseWithMessage(RMSG_X509VfyClearIPAddr_err);
end;

function TTaurusTLSCustomX509VerifyParam.GetPurpose: TTaurusTLSX509Purpose;
begin
  Result:=TTaurusTLSX509Purpose.FromInt(X509_VERIFY_PARAM_get_purpose(FParam));
end;

procedure TTaurusTLSCustomX509VerifyParam.SetPurpose(
  Value: TTaurusTLSX509Purpose);
begin
  if X509_VERIFY_PARAM_set_purpose(FParam, Value.AsInt) <> 0 then
    ETaurusTLSX509StoreError.RaiseWithMessage(RMSG_X509VfyPurp_err);
end;

{ TTaurusTLSX509VerifyParamWrap }

constructor TTaurusTLSX509VerifyParamSSL.Create(AParam: PX509_VERIFY_PARAM);
begin
  inherited;
end;

constructor TTaurusTLSX509VerifyParamSSL.Create(ASSL: PSSL);
begin
  Create(SSL_get0_param(ASSL));
end;

constructor TTaurusTLSX509VerifyParamSSL.Create(ASSLCtx: PSSL_CTX);
begin
  Create(SSL_CTX_get0_param(ASSLCtx));
end;

{ TTaurusTLSOSSLStore.TStoreItem }

constructor TTaurusTLSOSSLStore.TStoreItem.Create(const AInfo: TStoreInfo);
begin
  inherited Create;
  if not AInfo.IsExist then
    FData.FType:=AInfo.GetType;
  case FData.FType of
    sitName:
      FData.FName:=AInfo.CloneNameA;
    sitParams:
      FData.FPKey:=AInfo.CloneParams;
    sitPubKey:
      FData.FPKey:=AInfo.ClonePubKey;
    sitPrivKey:
      FData.FPKey:=AInfo.ClonePrivKey;
    sitCert:
      FData.FCert:=AInfo.CloneCert;
    sitCRL:
      FData.FCrl:=AInfo.CloneCrl;
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

constructor TTaurusTLSOSSLStore.Create(const ACtx: TStoreCtx;
  ALoadFilter: TStoreItemTypes);
begin
  if not ACtx.IsExist then
    ETaurusTLSOSSLStoreError.RaiseException(RMSG_OsslStoreInit_err);
  try
    inherited Create;
    FList:=TListInfo.Create;
    DoLoad(ACtx, ALoadFilter);
  finally
    ACtx.Close;
  end;
end;

constructor TTaurusTLSOSSLStore.Create(const AUri: RawByteString;
  AUi:TTaurusTLSCustomOsslUi; ALoadFilter: TStoreItemTypes);
var
  lCtx: TStoreCtx;

begin
  lCtx:=TStoreCtx.Create(PIdAnsiChar(AUri), AUi); // PALOFF Possible bad typecast
  Create(lCtx, ALoadFilter);
end;

constructor TTaurusTLSOSSLStore.Create(const AUri: UnicodeString;
  AUi: TTaurusTLSCustomOsslUi; ALoadFilter: TStoreItemTypes);
begin
  Create(RawByteString(AUri), AUi, ALoadFilter);
end;

constructor TTaurusTLSOSSLStore.Create(ABio: TTaurusTLSCustomBIO;
  AUi: TTaurusTLSCustomOsslUi; ALoadFilter: TStoreItemTypes);
var
  lCtx: TStoreCtx;

begin
  lCtx:=TStoreCtx.Create(ABio, AUi);
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

procedure TTaurusTLSOSSLStore.DoLoad(const ACtx: TStoreCtx;
  ALoadFilter: TStoreItemTypes);
var
  lInfo: TStoreInfo;
  lItem: TStoreItem;

begin
  while not ACtx.Eof do
  begin
    lInfo:=Actx.Load;
    if not ((lInfo.IsExist and (lInfo.GetType in ALoadFilter))) then
      continue;
    try
      lItem:=TStoreItem.Create(lInfo);
      FList.Add(lItem);
      Inc(FCounters[lItem.&Type]);
    finally
      lInfo.Free;
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
    ETaurusTLSX509StoreError.RaiseWithMessage(RMSG_X509StoreCreate_err);
  inherited;
end;

constructor TaurusTLS_X509Store.Create(AStore: TTaurusTLSOSSLStore;
  AFilter: TX509Elements);
begin
  Create;
  AppendFromOsslStore(AStore, AFilter);
end;

destructor TaurusTLS_X509Store.Destroy;
begin
  X509_STORE_free(FStore);
  inherited;
end;

procedure TaurusTLS_X509Store.AppendFromLocation(const AUri: string);
begin
{$IFDEF DCC}
  if not AppendFromLocationW(AUri) then
    ETaurusTLSX509StoreError.RaiseWithMessageFmt(RMSG_X509LoadLocationCreate_err,
      [AUri]);
{$ENDIF}
{$IFDEF FPC}
  if not AppendFromLocationA(AUri) then
    ETaurusTLSX509StoreError.RaiseWithMessageFmt(RMSG_X509LoadLocationCreate_err,
      [AUri]);
{$ENDIF}
end;

function TaurusTLS_X509Store.AppendFromLocationA(const AUri: RawByteString): boolean;
begin
  Result:=X509_STORE_load_store(FStore, PIdAnsiChar(AUri)) > 0;  // PALOFF Possible bad typecast
end;

function TaurusTLS_X509Store.AppendFromLocationW(const AUri: UnicodeString): boolean;
begin
  Result:=AppendFromLocationA(RawByteString(AUri));
end;

procedure TaurusTLS_X509Store.AppendFromOsslStore(const AStore: TTaurusTLSOSSLStore;
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
    sitCert: AppendCert(lElement.Cert);
    sitCrl:  AppendCrl(lElement.GetCrl);
    end;
  end;
end;

procedure TaurusTLS_X509Store.AttachToSSLCtx(ASSLCtx: PSSL_CTX);
begin
  SSL_CTX_set1_cert_store(ASSLCtx, FStore);
end;

procedure TaurusTLS_X509Store.AppendCert(ACert: PX509);
begin
  if X509_STORE_add_cert(FStore, ACert) <= 0 then
    ETaurusTLSX509StoreError.RaiseException(RMSG_X509StoreCertAdd_err);
end;

procedure TaurusTLS_X509Store.AppendCrl(ACrl: PX509_CRL);
begin
  if X509_STORE_add_crl(FStore, ACrl) <= 0 then
    ETaurusTLSX509StoreError.RaiseException(RMSG_X509StoreCRLAdd_err);
end;

procedure TaurusTLS_X509Store.SetParam(
  AVfyParam: TTaurusTLSCustomX509VerifyParam);
begin
  if not Assigned(AVfyParam) then
    Exit;
  if X509_STORE_set1_param(FStore, AVfyParam.VfyParam) <= 0 then
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

{ TTaurusTLSOSSLStore.TStoreInfo }

constructor TTaurusTLSOSSLStore.TStoreInfo.Create(
  const AInfo: POSSL_STORE_INFO);
begin
  FInfo:=AInfo;
end;

procedure TTaurusTLSOSSLStore.TStoreInfo.Free;
begin
  Free(FInfo);
end;

class procedure TTaurusTLSOSSLStore.TStoreInfo.Free(
  var AInfo: POSSL_STORE_INFO);
begin
  if IsExist(AInfo) then
    OSSL_STORE_INFO_free(AInfo);
  AInfo:=nil;
end;

class function TTaurusTLSOSSLStore.TStoreInfo.CloneNameA(
  AInfo: POSSL_STORE_INFO): RawByteString;
begin
  Result:=AnsiString(GetName(AInfo));
end;

class function TTaurusTLSOSSLStore.TStoreInfo.CloneCert(
  AInfo: POSSL_STORE_INFO): PX509;
begin
  if IsExist(AInfo) then
    Result:=OSSL_STORE_INFO_get1_CERT(AInfo)
  else
    Result:=nil;
end;

function TTaurusTLSOSSLStore.TStoreInfo.CloneCert: PX509;
begin
  Result:=CloneCert(FInfo);
end;

class function TTaurusTLSOSSLStore.TStoreInfo.CloneCrl(
  AInfo: POSSL_STORE_INFO): PX509_CRL;
begin
  if IsExist(AInfo) then
    Result:=OSSL_STORE_INFO_get1_CRL(AInfo)
  else
    Result:=nil;
end;

function TTaurusTLSOSSLStore.TStoreInfo.CloneCrl: PX509_CRL;
begin
  Result:=CloneCrl(FInfo);
end;

function TTaurusTLSOSSLStore.TStoreInfo.CloneNameA: RawByteString;
begin
  Result:=CloneNameA(FInfo);
end;

class function TTaurusTLSOSSLStore.TStoreInfo.CloneNameW(
  AInfo: POSSL_STORE_INFO): UnicodeString;
begin
  Result:=UnicodeString(GetName(AInfo));
end;

function TTaurusTLSOSSLStore.TStoreInfo.CloneNameW: UnicodeString;
begin
  Result:=CloneNameW(FInfo);
end;

class function TTaurusTLSOSSLStore.TStoreInfo.CloneParams(
  AInfo: POSSL_STORE_INFO): PEVP_PKEY;
begin
  if IsExist(AInfo) then
    Result:=OSSL_STORE_INFO_get1_PARAMS(AInfo)
  else
    Result:=nil;
end;

function TTaurusTLSOSSLStore.TStoreInfo.CloneParams: PEVP_PKEY;
begin
  Result:=CloneParams(FInfo);
end;

class function TTaurusTLSOSSLStore.TStoreInfo.ClonePrivKey(
  AInfo: POSSL_STORE_INFO): PEVP_PKEY;
begin
  if IsExist(AInfo) then
    Result:=OSSL_STORE_INFO_get1_PKEY(AInfo)
  else
    Result:=nil;
end;

function TTaurusTLSOSSLStore.TStoreInfo.ClonePrivKey: PEVP_PKEY;
begin
  Result:=ClonePrivKey(FInfo);
end;

class function TTaurusTLSOSSLStore.TStoreInfo.ClonePubKey(
  AInfo: POSSL_STORE_INFO): PEVP_PKEY;
begin
  if IsExist(AInfo) then
    Result:=OSSL_STORE_INFO_get1_PUBKEY(AInfo)
  else
    Result:=nil;
end;

function TTaurusTLSOSSLStore.TStoreInfo.ClonePubKey: PEVP_PKEY;
begin
  Result:=ClonePubKey(FInfo);
end;

class function TTaurusTLSOSSLStore.TStoreInfo.GetType(
  AInfo: POSSL_STORE_INFO): TStoreInfoType;
begin
  Result:=TStoreInfoType(OSSL_STORE_INFO_get_type(AInfo));
end;

class function TTaurusTLSOSSLStore.TStoreInfo.GetName(
  AInfo: POSSL_STORE_INFO): PIdAnsiChar;
begin
  if IsExist(AInfo) then
    Result:=OSSL_STORE_INFO_get0_NAME(AInfo)
  else
    Result:=nil;
end;

class function TTaurusTLSOSSLStore.TStoreInfo.GetCert(
  AInfo: POSSL_STORE_INFO): PX509;
begin
  if IsExist(AInfo) then
    Result:=OSSL_STORE_INFO_get0_CERT(AInfo)
  else
    Result:=nil;
end;

function TTaurusTLSOSSLStore.TStoreInfo.GetCert: PX509;
begin
  Result:=GetCert(FInfo);
end;

class function TTaurusTLSOSSLStore.TStoreInfo.GetCrl(
  AInfo: POSSL_STORE_INFO): PX509_CRL;
begin
  if IsExist(AInfo) then
    Result:=OSSL_STORE_INFO_get0_CRL(AInfo)
  else
    Result:=nil;
end;

function TTaurusTLSOSSLStore.TStoreInfo.GetCrl: PX509_CRL;
begin
  Result:=GetCrl(FInfo);
end;

function TTaurusTLSOSSLStore.TStoreInfo.GetName: PIdAnsiChar;
begin
  Result:=GetName(FInfo);
end;

class function TTaurusTLSOSSLStore.TStoreInfo.GetParams(
  AInfo: POSSL_STORE_INFO): PEVP_PKEY;
begin
  if IsExist(AInfo) then
    Result:=OSSL_STORE_INFO_get0_PARAMS(AInfo)
  else
    Result:=nil;
end;

function TTaurusTLSOSSLStore.TStoreInfo.GetParams: PEVP_PKEY;
begin
  Result:=GetParams(FInfo);
end;

class function TTaurusTLSOSSLStore.TStoreInfo.GetPrivKey(
  AInfo: POSSL_STORE_INFO): PEVP_PKEY;
begin
  if IsExist(AInfo) then
    Result:=OSSL_STORE_INFO_get0_PKEY(AInfo)
  else
    Result:=nil;
end;

function TTaurusTLSOSSLStore.TStoreInfo.GetPrivKey: PEVP_PKEY;
begin
  Result:=GetPrivKey(FInfo);
end;

class function TTaurusTLSOSSLStore.TStoreInfo.GetPubKey(
  AInfo: POSSL_STORE_INFO): PEVP_PKEY;
begin
  if IsExist(AInfo) then
    Result:=OSSL_STORE_INFO_get0_PUBKEY(AInfo)
  else
    Result:=nil;
end;

function TTaurusTLSOSSLStore.TStoreInfo.GetPubKey: PEVP_PKEY;
begin
  Result:=GetPubKey(FInfo);
end;

function TTaurusTLSOSSLStore.TStoreInfo.GetType: TStoreInfoType;
begin
  Result:=GetType(FInfo);
end;

class function TTaurusTLSOSSLStore.TStoreInfo.GetTypeName(
  AInfo: POSSL_STORE_INFO): PIdAnsiChar;
begin
  if IsExist(Ainfo) then
    Result:=OSSL_STORE_INFO_type_string(Ord(GetType(AInfo)))
  else
    Result:=nil;
end;

function TTaurusTLSOSSLStore.TStoreInfo.GetTypeName: PIdAnsiChar;
begin
  Result:=GetTypeName(FInfo);
end;

class function TTaurusTLSOSSLStore.TStoreInfo.IsExist(
  AInfo: POSSL_STORE_INFO): boolean;
begin
  Result:=Assigned(AInfo);
end;

function TTaurusTLSOSSLStore.TStoreInfo.IsExist: boolean;
begin
  Result:=IsExist(FInfo);
end;

{ TTaurusTLSOSSLStore.TStoreCtx }

constructor TTaurusTLSOSSLStore.TStoreCtx.Create(ACtx: POSSL_STORE_CTX);
begin
  FCtx:=ACtx;
end;

constructor TTaurusTLSOSSLStore.TStoreCtx.Create(AUri: PIdAnsiChar;
  AUi: TTaurusTLSCustomOsslUi);
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

  Create(OSSL_STORE_open(PIdAnsiChar(AUri), lMeth, AUi, nil, nil)); // PALOFF Possible bad typecast
end;

constructor TTaurusTLSOSSLStore.TStoreCtx.Create(ABio: TTaurusTLSCustomBIO;
  AUi: TTaurusTLSCustomOsslUi);
var
  lMeth: PUI_METHOD;

begin
  if not Assigned(ABio) then
    Exit;

  if Assigned(AUi) then
    lMeth:=AUi.UiMethod
  else
  begin
    AUi:=nil;
    lMeth:=nil;
  end;

  Create(OSSL_STORE_attach(ABio.BIO, nil, nil, nil, lMeth, AUi,
    nil, nil, nil));
end;

class procedure TTaurusTLSOSSLStore.TStoreCtx.Close(var ACtx: POSSL_STORE_CTX);
begin
  if not Assigned(Actx) then
    Exit;
  OSSL_STORE_close(ACtx);
  ACtx:=nil;
end;

procedure TTaurusTLSOSSLStore.TStoreCtx.Close;
begin
  Close(FCtx);
end;

class function TTaurusTLSOSSLStore.TStoreCtx.Eof(
  ACtx: POSSL_STORE_CTX): boolean;
begin
  Result:=Assigned(ACtx) and (OSSL_STORE_eof(ACtx) = 1);
end;

function TTaurusTLSOSSLStore.TStoreCtx.Eof: boolean;
begin
  Result:=Eof(FCtx);
end;

class function TTaurusTLSOSSLStore.TStoreCtx.IsLoadError(
  ACtx: POSSL_STORE_CTX): boolean;
begin
  Result:=OSSL_STORE_error(ACtx) = 1;
end;

class function TTaurusTLSOSSLStore.TStoreCtx.IsExist(
  ACtx: POSSL_STORE_CTX): boolean;
begin
  Result:=Assigned(Actx);
end;

function TTaurusTLSOSSLStore.TStoreCtx.IsExist: boolean;
begin
  Result:=IsExist(FCtx);
end;

function TTaurusTLSOSSLStore.TStoreCtx.IsLoadError: boolean;
begin
  Result:=IsLoadError(FCtx);
end;

class function TTaurusTLSOSSLStore.TStoreCtx.Load(
  ACtx: POSSL_STORE_CTX): POSSL_STORE_INFO;
begin
  Result:=OSSL_STORE_load(ACtx);
end;

function TTaurusTLSOSSLStore.TStoreCtx.Load: TStoreInfo;
begin
  Result:=TStoreInfo.Create(Load(FCtx));
end;

end.
