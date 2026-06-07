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
    procedure SetVerifyFlags(const Value: TTaurusTLSX509VerifyFlags);
    function GetInheritanceFlags: TTaurusTLSX509InheritanceFlags;
    procedure SetInheritanceFlags(const Value: TTaurusTLSX509InheritanceFlags);
    function GetDepht: TIdC_Int;
    procedure SetDepth(const Value: TIdC_Int);
    function GetAuthLevel: TTaurusTLSSecurityBits;
    procedure SetAuthLevel(const Value: TTaurusTLSSecurityBits);
    function GetTime: TDateTime;
    procedure SetTime(const Value: TDateTime);
    function GetHostCheckFlags: TTaurusTLSX509HostCheckFlags;
    procedure SetHostCheckFlags(const Value: TTaurusTLSX509HostCheckFlags);
    function GetPurpose: TTaurusTLSX509Purpose;
    procedure SetPurpose(Value: TTaurusTLSX509Purpose);

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
      overload;

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
    procedure AppendFromLocation(AUri: string); {$IFDEF USE_INLINE}inline;{$ENDIF}

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
  if X509_VERIFY_PARAM_set_flags(FParam, Value.AsInt) <> 1 then
    ETaurusTLSX509StoreError.RaiseWithMessage(RMSG_X509VfyParamFlag_err);
  lClearFlags:=lFlags-Value;
  if lClearFlags <> [] then
    if X509_VERIFY_PARAM_clear_flags(FParam, lClearFlags.AsInt) <> 1 then
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

procedure TaurusTLS_X509Store.AppendFromLocation(AUri: string);
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
  Result:=X509_STORE_load_store(FStore, PANsiChar(AUri)) > 0;
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
  if X509_STORE_add_cert(FStore, ACert) <> 1 then
    ETaurusTLSX509StoreError.RaiseException(RMSG_X509StoreCertAdd_err);
end;

procedure TaurusTLS_X509Store.AppendCrl(ACrl: PX509_CRL);
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
