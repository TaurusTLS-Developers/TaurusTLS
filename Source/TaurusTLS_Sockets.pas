{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2026 TaurusTLS Developers, All Rights Reserved              * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 ? 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew ? http://www.IndyProject.org/  * }
{ ****************************************************************************** }
{$I TaurusTLSCompilerDefines.inc}

unit TaurusTLS_Sockets;
{$I TaurusTLSLinkDefines.inc}

interface

uses
  Classes,
  SysUtils,
{$IFDEF SIGPIPE_MASK}
  {$IFDEF FPC}
  BaseUnix,
  pthreads,
  {$ELSE}
  Posix.Signal,
  {$ENDIF}
{$ENDIF}
  Generics.Collections,
  IdCTypes,
  IdGlobal,
  IdComponent,
  IdStack,
  IdStackConsts,
  IdSocketHandle,
  IdGlobalProtocols,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_crypto,
  TaurusTLSHeaders_ech,
  TaurusTLSHeaders_ssl,
  TaurusTLSHeaders_ssl3,
  TaurusTLSHeaders_tls1,
  TaurusTLSHeaders_x509,
  TaurusTLSHeaders_x509_vfy,
  TaurusTLS_types,
  TaurusTLS_Utils,
  TaurusTLS_BIO,
  TaurusTLS_ECH,
  TaurusTLS_ECHStore,
  TaurusTLS_SSLStores,
  TaurusTLS_SSLUI,
  TaurusTLS_X509,
  TaurusTLSExceptionHandlers;

type
  /// <summary>
  ///   Base exception for errors occurring during context manipulation, such
  ///   as modifying a frozen <see cref="TTaurusTLSSslSocketCtx"/> instance or
  ///   setting invalid cipher lists, protocol versions, or fragment sizes.
  /// </summary>
  ETaurusTLSSslSocketCtxError = class(ETaurusTLSError);

  /// <summary>
  ///   Raised when compilation inside <see cref="TTaurusTLSSslSocketCtxBuilder"/>
  ///   fails due to missing requirements or invalid configuration states.
  /// </summary>
  ETaurusTLSSslSocketCtxBuildError = class(ETaurusTLSError);

  /// <summary>
  ///   Raised when an invalid or forbidden state transition is attempted
  ///   within the socket state machine lifecycle.
  /// </summary>
  ETaurusTLSSocketStateError = class(ETaurusTLSError);

  /// <summary>
  ///   Raised when allocating the native OpenSSL SSL session handle via
  ///   <c>SSL_new</c> fails during session initialization.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/SSL_new/">
  ///   SSL_new
  /// </seealso>
  ETaurusTLSSslSocketCreateError = class(ETaurusTLSAPICryptoError);

  /// <summary>
  ///   Raised when binding the physical OS socket descriptor to OpenSSL via
  ///   <c>SSL_set_fd</c> fails.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/SSL_set_fd/">
  ///   SSL_set_fd
  /// </seealso>
  ETaurusTLSSslSocketBindError = class(ETaurusTLSAPICryptoError);

  /// <summary>
  ///   Base exception class for errors occurring during active socket I/O
  ///   or handshake state transitions.
  /// </summary>
  ETaurusTLSSslSocketError = class(ETaurusTLSAPISSLError)
  public
    /// <summary>
    ///   Resolves the target socket state to transition to on this error.
    /// </summary>
    /// <returns>
    ///   The target <see cref="TTaurusTLSSslSocketState"/> enum value.
    /// </returns>
    class function TargetSocketState: TTaurusTLSSslSocketState; virtual;
  end;

  /// <summary>
  ///   Base exception representing an orderly or requested socket closure,
  ///   mapping the state machine transition to <c>seReleased</c>.
  /// </summary>
  ETaurusTLSSslSocketClose = class(ETaurusTLSSslSocketError)
  public
    /// <summary>
    ///   Resolves the target socket state to transition to on closure.
    /// </summary>
    /// <returns>
    ///   Returns <c>seReleased</c>.
    /// </returns>
    class function TargetSocketState: TTaurusTLSSslSocketState; override;
  end;

  /// <summary>
  ///   Raised when an unrecoverable TCP reset (RST) or EOF occurs during
  ///   active reading, writing, or handshaking (<c>SSL_ERROR_SYSCALL</c>).
  /// </summary>
  ETaurusTLSSslSocketConnectionReset = class(ETaurusTLSSslSocketClose);

  /// <summary>
  ///   Raised when post-handshake peer certificate validation fails.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/SSL_get_verify_result/">
  ///   SSL_get_verify_result
  /// </seealso>
  ETaurusTLSSslSocketCertValidationError = class(ETaurusTLSError)
  private
    FVerifyCode: TIdC_LONG;
  public
    /// <summary>
    ///   Initializes exception with the OpenSSL verification error code.
    /// </summary>
    /// <param name="AVerifyCode">
    ///   The OpenSSL X509 error code (e.g. <c>X509_V_ERR_CERT_HAS_EXPIRED</c>).
    /// </param>
    /// <param name="AMessage">
    ///   Descriptive text explaining the verification failure.
    /// </param>
    constructor Create(AVerifyCode: TIdC_LONG; const AMessage: string);

    /// <summary>
    ///   Helper method to instantiate and raise the exception with code.
    /// </summary>
    /// <param name="AVerifyCode">
    ///   The OpenSSL X509 error code.
    /// </param>
    /// <param name="AMessage">
    ///   Descriptive text explaining the verification failure.
    /// </param>
    class procedure RaiseErrorCode(AVerifyCode: TIdC_LONG;
      const AMessage: string);

    /// <summary>
    ///   The raw OpenSSL X.509 verification error code.
    /// </summary>
    property VerifyCode: TIdC_LONG read FVerifyCode;
  end;

  /// <summary>
  ///   Raised when binding the Delphi object instance to the native OpenSSL
  ///   handle via <c>SSL_set_app_data</c> or <c>SSL_CTX_set_app_data</c> fails.
  /// </summary>
  ETaurusTLSSslSocketDataBindingError = class(ETaurusTLSAPICryptoError);

  /// <summary>
  ///   Raised when client connection setup fails, such as attempting real ECH
  ///   mode on an IP address or missing the configuration snapshot.
  /// </summary>
  ETaurusTLSSslClientSocketSetupError = class(ETaurusTLSSslSocketError);

  /// <summary>
  ///   Raised when setting the SNI hostname or ECH server names fails via
  ///   <c>SSL_set_tlsext_host_name</c> or <c>SSL_ech_set1_server_names</c>.
  /// </summary>
  ETaurusTLSSslClientSocketHostNameError = class(ETaurusTLSAPISSLError);

  /// <summary>
  ///   Raised when OpenSSL encounters an unrecoverable protocol or
  ///   cryptographic error during <c>SSL_connect</c> or <c>SSL_accept</c>.
  /// </summary>
  ETaurusTLSHandshakeError = class(ETaurusTLSAPISSLError);

  /// <summary>
  ///   Raised when ECH mode is enabled, but the loaded OpenSSL library binary
  ///   lacks ECH support (e.g. running under OpenSSL 3.x).
  /// </summary>
  EECHNotSupported = class(ETaurusTLSError);

  /// <summary>
  ///   Raised when the server rejects the ECH key and provides no retry
  ///   configuration for key rotation.
  /// </summary>
  ETaurusTLSECHRejectedError = class(ETaurusTLSAPISSLError);

  /// <summary>
  ///   Raised when strict ECH mode is requested, but the server bypasses ECH
  ///   or lacks ECH support, indicating a potential downgrade attack.
  /// </summary>
  ETaurusTLSECHDowngradeError = class(ETaurusTLSAPISSLError);

  /// <summary>
  ///   Raised when ECH decryption completes, but the server certificate does
  ///   not match the inner decrypted SNI identity.
  /// </summary>
  ETaurusTLSECHBadNameError = class(ETaurusTLSAPISSLError);

  /// <summary>
  ///   Raised when an internal OpenSSL or protocol failure occurs during ECH
  ///   negotiation (<c>SSL_ECH_STATUS_FAILED</c> or <c>SSL_ECH_STATUS_BAD_CALL</c>).
  /// </summary>
  ETaurusTLSECHProtocolError = class(ETaurusTLSAPISSLError);

  /// <summary>
  ///   Raised when parsing or selecting an ALPN protocol value fails.
  /// </summary>
  ETaurusTLSAlpnResultError = class(ETaurusTLSError);

type
  /// <summary>
  ///   Governs the client-side wire transmission policy for SNI, GREASE, and ECH.
  /// </summary>
  TTaurusTLSSslClientSNIMode = (
    /// <summary>
    ///   No SNI extension sent on wire (RFC 3546 IP connect or suppression).
    /// </summary>
    csmDisabled,
    /// <summary>
    ///   Standard cleartext SNI (HostName or DefaultSNI override).
    /// </summary>
    csmStandardSNI,
    /// <summary>
    ///   Cleartext SNI (if domain) or No-SNI (if IP) + dummy ECH GREASE payload.
    /// </summary>
    csmECHGrease,
    /// <summary>
    ///   Bootstrapping: Probes for ECHConfig (omits private SNI, triggers retry
    ///   on response).
    /// </summary>
    csmECHGreaseDiscovery,
    /// <summary>
    ///   Strict ECH with decoy/public_name; fails on downgrade/bypass.
    /// </summary>
    csmECH,
    /// <summary>
    ///   Strict ECH with outer SNI omitted (no_outer = 1); fails on downgrade.
    /// </summary>
    csmECHNoOuter
  );

  /// <summary>
  ///   Bit-shift ordinal positions representing OpenSSL info callback flags
  ///   and status events (<c>SSL_CB_*</c> and <c>SSL_ST_*</c>).
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/SSL_CTX_set_info_callback/">
  ///   SSL_CTX_set_info_callback
  /// </seealso>
  TTaurusTLSSslStateFlag  = (
    /// <summary>Bit 0: Handshake loop iteration (<c>SSL_CB_LOOP</c>).</summary>
    stfLoop               = 0,    // 1 shl 0  = SSL_CB_LOOP
    /// <summary>Bit 1: Handshake exit point (<c>SSL_CB_EXIT</c>).</summary>
    stfExit               = 1,    // 1 shl 1  = SSL_CB_EXIT
    /// <summary>Bit 2: Read operation (<c>SSL_CB_READ</c>).</summary>
    stfRead               = 2,    // 1 shl 2  = SSL_CB_READ
    /// <summary>Bit 3: Write operation (<c>SSL_CB_WRITE</c>).</summary>
    stfWrite              = 3,    // 1 shl 3  = SSL_CB_WRITE
    /// <summary>Bit 4: Handshake start (<c>SSL_CB_HANDSHAKE_START</c>).</summary>
    stfHandShakeStart     = 4,    // 1 shl 4  = SSL_CB_HANDSHAKE_START
    /// <summary>Bit 5: Handshake finished (<c>SSL_CB_HANDSHAKE_DONE</c>).</summary>
    stfHandShakeDone      = 5,    // 1 shl 5  = SSL_CB_HANDSHAKE_DONE
    /// <summary>Bit 12: Client connection state (<c>SSL_ST_CONNECT</c>).</summary>
    stfConnect            = 12,   // 1 shl 12 = SSL_ST_CONNECT
    /// <summary>Bit 13: Server acceptance state (<c>SSL_ST_ACCEPT</c>).</summary>
    stfAccept             = 13,   // 1 shl 13 = SSL_ST_ACCEPT
    /// <summary>Bit 14: TLS alert received/sent (<c>SSL_ST_ALERT</c>).</summary>
    stfAlert              = 14    // 1 shl 14 = SSL_ST_ALERT
  );

  /// <summary>
  ///   Set representation of active OpenSSL state and callback flags.
  /// </summary>
  TTaurusTLSSslStateFlags = set of TTaurusTLSSslStateFlag;

  /// <summary>
  ///   Immutable snapshot structure encapsulating OpenSSL state information,
  ///   alert codes, and human-readable diagnostics from <c>SSL_info_callback</c>.
  /// </summary>
  TTaurusTLSSslState = record
  public const
    /// <summary>Lowest ordinal value of the lower flag range.</summary>
    cLowMin   = Ord(Low(TTaurusTLSSslStateFlag));
    /// <summary>Highest ordinal value of the lower flag range.</summary>
    cLowMax   = Ord(stfHandShakeDone);
    /// <summary>Lowest ordinal value of the higher flag range.</summary>
    cHighMin  = Ord(stfConnect);
    /// <summary>Highest ordinal value of the higher flag range.</summary>
    cHighMax  = Ord(High(TTaurusTLSSslStateFlag));

    /// <summary>
    ///   Bitmask for the lower active range (bits 0..5): Mask = $3F.
    /// </summary>
    cLowMask  = ((1 shl (cLowMax + 1)) - 1) - ((1 shl cLowMin) - 1);
    /// <summary>
    ///   Bitmask for the higher active range (bits 12..14): Mask = $7000.
    /// </summary>
    cHighMask = ((1 shl (cHighMax + 1)) - 1) - ((1 shl cHighMin) - 1);
    /// <summary>
    ///   Combined bitmask filtering active bits and ignoring the gap ($703F).
    /// </summary>
    cStateFlagsMask = cLowMask or cHighMask;

  private
    FStates: TIdC_INT;
    FCode: TIdC_INT;
    FSSL: PSSL;
    FStatusMessage: string;
    FAlertMessage: string;

    // property getters
    function GetIsAccept: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsAcceptExit: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsAcceptLoop: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsAlert: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsConnect: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsConnectExit: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsConnectLoop: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsExit: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsHandshakeDone: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsHandshakeStarts: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsInLoop: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsRead: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsReadAlert: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsWrite: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsWriteAlert: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetStateStatusMessage: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetAlertMessage: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetStateFlags: TTaurusTLSSslStateFlags; {$IFDEF USE_INLINE}inline; {$ENDIF}

    procedure Init(const ASSLStates, ACode: TIdC_INT; ASSL: PSSL);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure InitMessages; {$IFDEF USE_INLINE}inline; {$ENDIF}

  public
    /// <summary>
    ///   Initializes state record from a strongly-typed flag set.
    /// </summary>
    /// <param name="AStates">The active set of state flags.</param>
    /// <param name="ACode">The OpenSSL return/alert code.</param>
    /// <param name="ASSL">The active OpenSSL session pointer.</param>
    constructor Create(const AStates: TTaurusTLSSslStateFlags; const ACode: TIdC_INT;
      ASSL: PSSL); overload;

    /// <summary>
    ///   Initializes state record from raw OpenSSL callback integers.
    /// </summary>
    /// <param name="ASSLStates">The raw bitwise where/state value.</param>
    /// <param name="ACode">The OpenSSL return/alert code.</param>
    /// <param name="ASSL">The active OpenSSL session pointer.</param>
    constructor Create(const ASSLStates, ACode: TIdC_INT; ASSL: PSSL); overload;

    /// <summary>
    ///   Converts a flag set to its integer representation with gap masking.
    /// </summary>
    /// <param name="AValue">The set of flags to convert.</param>
    /// <returns>Integer bitmask value.</returns>
    class function ToInt(const AValue: TTaurusTLSSslStateFlags): TIdC_INT; static;
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>True if in client connection state (<c>stfConnect</c>).</summary>
    property IsConnect: boolean read GetIsConnect;
    /// <summary>True if in server acceptance state (<c>stfAccept</c>).</summary>
    property IsAccept: boolean read GetIsAccept;
    /// <summary>True if inside a handshake loop iteration (<c>stfLoop</c>).</summary>
    property IsInLoop: boolean read GetIsInLoop;
    /// <summary>True if exiting a handshake state (<c>stfExit</c>).</summary>
    property IsExit: boolean read GetIsExit;
    /// <summary>True if a TLS alert is signaled (<c>stfAlert</c>).</summary>
    property IsAlert: boolean read GetIsAlert;
    /// <summary>True if performing a read operation (<c>stfRead</c>).</summary>
    property IsRead: boolean read GetIsRead;
    /// <summary>True if performing a write operation (<c>stfWrite</c>).</summary>
    property IsWrite: boolean read GetIsWrite;
    /// <summary>True if the handshake is starting (<c>stfHandShakeStart</c>).</summary>
    property IsHandshakeStarts: boolean read GetIsHandshakeStarts;
    /// <summary>True if the handshake has completed (<c>stfHandShakeDone</c>).</summary>
    property IsHandshakeDone: boolean read GetIsHandshakeDone;
    /// <summary>True if an incoming TLS alert was received.</summary>
    property IsReadAlert: boolean read GetIsReadAlert;
    /// <summary>True if an outgoing TLS alert is being sent.</summary>
    property IsWriteAlert: boolean read GetIsWriteAlert;
    /// <summary>True if server is iterating inside the accept loop.</summary>
    property IsAcceptLoop: boolean read GetIsAcceptLoop;
    /// <summary>True if server has exited the accept state.</summary>
    property IsAcceptExit: boolean read GetIsAcceptExit;
    /// <summary>True if client is iterating inside the connect loop.</summary>
    property IsConnectLoop: boolean read GetIsConnectLoop;
    /// <summary>True if client has exited the connect state.</summary>
    property IsConnectExit: boolean read GetIsConnectExit;

    /// <summary>The strongly-typed set of active state flags.</summary>
    property StateFlags: TTaurusTLSSslStateFlags read GetStateFlags;
    /// <summary>The raw integer bitmask of active state flags.</summary>
    property StatesAsInt: TIdC_INT read FStates;
    /// <summary>The raw OpenSSL return/alert code.</summary>
    property ErrorCode: TIdC_INT read FCode;
    /// <summary>Human-readable description of the current status/action.</summary>
    property StateStatusMessage: string read GetStateStatusMessage;
    /// <summary>Detailed description of the active state or alert message.</summary>
    property AlertMessage: string read GetAlertMessage;
  end;

  /// <summary>
  ///   Encapsulates parameters passed to the OpenSSL security check callback
  ///   (<c>SSL_CTX_set_security_callback</c>) for custom cryptographic auditing.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/SSL_CTX_set_security_callback/">
  ///   SSL_CTX_set_security_callback
  /// </seealso>
  TTaurusTLSSecurityCheckState = record
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FOp: TIdC_INT;
    FBits: TTaurusTLSSecurityBits;
    FNid: TIdC_INT;
    FOther: Pointer;
    FCert: TTaurusTLSX509;

    function GetIsPeer: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsCipher: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsCurve: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsDH: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsPKey: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsSigAlg: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsCert: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetCertificate: TTaurusTLSX509; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetCipherName: string; {$IFDEF USE_INLINE}inline; {$ENDIF}

    function GetNidShortName: string;
    function GetNidLongName: string;
  private
    procedure Destroy; {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    /// <summary>
    ///   Initializes the security check state with raw OpenSSL parameters.
    /// </summary>
    /// <param name="AOp">Security operation identifier (<c>SSL_SECOP_*</c>).</param>
    /// <param name="ABits">Security bits required/provided.</param>
    /// <param name="ANid">Numerical Identifier of the cryptographic object.</param>
    /// <param name="AOther">Raw pointer to the object under evaluation.</param>
    constructor Create(AOp, ABits, ANid: TIdC_INT; AOther: Pointer);

    /// <summary>Raw OpenSSL security operation code (<c>SSL_SECOP_*</c>).</summary>
    property Op: TIdC_INT read FOp;
    /// <summary>Security strength level in bits.</summary>
    property Bits: TTaurusTLSSecurityBits read FBits;
    /// <summary>OpenSSL numerical identifier (NID) of the item.</summary>
    property Nid: TIdC_INT read FNid;
    /// <summary>Raw pointer to the object under evaluation (e.g. PX509).</summary>
    property Other: Pointer read FOther;
    /// <summary>Non-owning wrapper for the evaluated peer certificate.</summary>
    property Certificate: TTaurusTLSX509 read GetCertificate;

    /// <summary>True if evaluating peer parameters.</summary>
    property IsPeer: Boolean read GetIsPeer;
    /// <summary>True if evaluating a cipher suite.</summary>
    property IsCipher: Boolean read GetIsCipher;
    /// <summary>True if evaluating an elliptic curve.</summary>
    property IsCurve: Boolean read GetIsCurve;
    /// <summary>True if evaluating Diffie-Hellman parameters.</summary>
    property IsDH: Boolean read GetIsDH;
    /// <summary>True if evaluating a public/private key.</summary>
    property IsPKey: Boolean read GetIsPKey;
    /// <summary>True if evaluating a signature algorithm.</summary>
    property IsSigAlg: Boolean read GetIsSigAlg;
    /// <summary>True if evaluating an X.509 certificate.</summary>
    property IsCert: Boolean read GetIsCert;

    /// <summary>Short text name associated with the NID.</summary>
    property NidShortName: string read GetNidShortName;
    /// <summary>Long descriptive name associated with the NID.</summary>
    property NidLongName: string read GetNidLongName;
    /// <summary>Name of the cipher under evaluation, if applicable.</summary>
    property CipherName: string read GetCipherName;
  end;

  // SSL Socket support types and classes
type
  /// <summary>
  ///   Named cryptographic store specialized for loading trusted CA
  ///   certificates and Certificate Revocation Lists (CRLs) using the
  ///   OpenSSL <c>OSSL_STORE</c> architecture.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/OSSL_STORE_open/">
  ///   OSSL_STORE_open
  /// </seealso>
  TTaurusTLSTrustStore = class(TTaurusTLSOSSLStore)
  public const
    /// <summary>
    ///   Restricts store ingestion filter to certificates and CRL items only.
    /// </summary>
    cFilter = [sitCert, sitCRL];
  public type
    /// <summary>Alias for the OSSL_STORE item filter type set.</summary>
    TStoreItemTypes = TTaurusTLSOSSLStore.TStoreItemTypes;
  private
    FName: string;
  protected
    /// <summary>Sets the internal unique name for this store.</summary>
    /// <param name="AName">The store name string.</param>
    procedure SetName(const AName: string); {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    /// <summary>
    ///   Initializes a named trust store from a raw byte string URI.
    /// </summary>
    /// <param name="AName">Unique name identifying the store.</param>
    /// <param name="AUri">The URI path (e.g. file path, PKCS#11 URI).</param>
    /// <param name="AUiCtx">UI context handler for password prompts.</param>
    constructor Create(const AName: string; const AUri: RawByteString;
      AUiCtx: TTaurusTLS_UICtx); reintroduce; overload; {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>
    ///   Initializes a named trust store from a Unicode string URI.
    /// </summary>
    /// <param name="AName">Unique name identifying the store.</param>
    /// <param name="AUri">The URI path (e.g. file path, PKCS#11 URI).</param>
    /// <param name="AUiCtx">UI context handler for password prompts.</param>
    constructor Create(const AName: string; const AUri: UnicodeString;
      AUiCtx: TTaurusTLS_UICtx); reintroduce; overload; {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>
    ///   Initializes a named trust store from a custom OpenSSL BIO stream.
    /// </summary>
    /// <param name="AName">Unique name identifying the store.</param>
    /// <param name="ABio">The custom BIO stream interface wrapper.</param>
    /// <param name="AUiCtx">UI context handler for password prompts.</param>
    constructor Create(const AName: string; ABio: TTaurusTLSCustomBIO;
      AUiCtx: TTaurusTLS_UICtx); reintroduce; overload; {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>
    ///   Initializes a named trust store from an in-memory byte array.
    /// </summary>
    /// <param name="AName">Unique name identifying the store.</param>
    /// <param name="AUiCtx">UI context handler for password prompts.</param>
    /// <param name="AData">Byte array containing raw PEM/DER data.</param>
    constructor CreateMem(const AName: string; AUiCtx: TTaurusTLS_UICtx;
      const AData: TBytes); reintroduce; overload; {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>
    ///   Initializes a named trust store from an in-memory string buffer.
    /// </summary>
    /// <param name="AName">Unique name identifying the store.</param>
    /// <param name="AUiCtx">UI context handler for password prompts.</param>
    /// <param name="AData">String containing PEM-formatted data.</param>
    constructor CreateMem(const AName: string; AUiCtx: TTaurusTLS_UICtx;
      const AData: string); reintroduce; overload; {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>Unique name or identifier associated with this store.</summary>
    property Name: string read FName;
  end;

  /// <summary>
  ///   Dictionary collection managing multiple named <see
  ///   cref="TTaurusTLSTrustStore"/> instances and compiling them into a
  ///   consolidated native OpenSSL X.509 verification trust repository.
  /// </summary>
  TTaurusTLSTrustStores = class(TDictionary<string, TTaurusTLSTrustStore>)
  protected
    /// <summary>Validates that the store instance is not nil.</summary>
    /// <param name="AStore">The trust store instance to validate.</param>
    procedure CheckStore(const AStore: TTaurusTLSTrustStore);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    /// <summary>
    ///   Adds a named trust store to the collection, using its <see
    ///   cref="TTaurusTLSTrustStore.Name"/> property as the key.
    /// </summary>
    /// <param name="AValue">The trust store instance to add.</param>
    procedure Add(const AValue: TTaurusTLSTrustStore);
      reintroduce; {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>
    ///   Adds or updates a named trust store in the collection.
    /// </summary>
    /// <param name="AValue">The trust store instance to add or update.</param>
    procedure AddOrSetValue(const AValue: TTaurusTLSTrustStore);
      reintroduce; {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>
    ///   Attempts to add a named trust store without raising exceptions on
    ///   duplicate keys.
    /// </summary>
    /// <param name="AValue">The trust store instance to add.</param>
    /// <returns>True if the store was added successfully; False if duplicate.</returns>
    function TryAdd(const AValue: TTaurusTLSTrustStore): boolean;
      reintroduce; {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>
    ///   Compiles all certificates and CRLs from every registered trust store
    ///   into a single consolidated <see cref="TTaurusTLS_X509Store"/> object.
    /// </summary>
    /// <returns>
    ///   A new <see cref="TTaurusTLS_X509Store"/> instance. Caller takes
    ///   ownership.
    /// </returns>
    function BuildStore: TTaurusTLS_X509Store;
  end;

  // Forward declaration
  TTaurusTLSSslSocket = class;

// Event type declarations

  /// <summary>
  ///   Fired when OpenSSL evaluates security parameters (ciphers, key bits,
  ///   curves) via <c>SSL_CTX_set_security_callback</c>.
  /// </summary>
  /// <param name="ASender">
  ///   The parent IOHandler component initiating the connection.
  /// </param>
  /// <param name="ASocket">The active socket context instance.</param>
  /// <param name="AState">Encapsulates operation, bits, NID, and object.</param>
  /// <param name="AAccept">Set to True to permit; False to reject.</param>
  TTaurusTLSOnSecurityCheck = procedure(
    ASender: TObject;
    ASocket: TTaurusTLSSslSocket;
    const AState: TTaurusTLSSecurityCheckState;
    var AAccept: Boolean
  ) of object;

  (*
  /// <summary>
  ///   Unused legacy notification delegate.
  /// </summary>
  TTaurusTLSOnIOHandlerNotify = procedure(ASender: TObject;
    ASocket: TTaurusTLSSslSocket) of object;
  *)

  /// <summary>
  ///   Fired synchronously when the internal socket state machine transitions
  ///   between lifecycle states.
  /// </summary>
  /// <param name="ASender">The parent IOHandler component instance.</param>
  /// <param name="ASocket">The active socket context instance.</param>
  /// <param name="AOldState">The previous state enum value.</param>
  /// <param name="ANewState">The newly committed state enum value.</param>
  TTaurusTLSOnStateChange = procedure(ASender: TObject;
    ASocket: TTaurusTLSSslSocket; AOldState, ANewState: TTaurusTLSSslSocketState) of object;

  /// <summary>
  ///   Fired during OpenSSL info callback execution to report state transitions,
  ///   handshake loops, and alerts.
  /// </summary>
  /// <param name="ASender">The parent IOHandler component instance.</param>
  /// <param name="ASocket">The active socket context instance.</param>
  /// <param name="AState">
  ///   Immutable snapshot of OpenSSL state flags and message strings.
  /// </param>
  TTaurusTLSOnSSLStatusInfo = procedure(ASender: TObject;
    ASocket: TTaurusTLSSslSocket; const AState: TTaurusTLSSslState) of object;

  /// <summary>
  ///   Fired to emit diagnostic log messages from the state machine.
  /// </summary>
  /// <param name="ASender">The parent IOHandler component instance.</param>
  /// <param name="AMessage">The diagnostic text message.</param>
  TTaurusTLSOnDebugMessage = procedure(ASender: TObject;
    const AMessage: String) of object;

  /// <summary>
  ///   Fired post-handshake when peer certificate verification returns an
  ///   error, allowing dynamic application overrides.
  /// </summary>
  /// <param name="ASender">The parent IOHandler component instance.</param>
  /// <param name="ASocket">The active socket context instance.</param>
  /// <param name="ACertificate">Wrapper around the peer X.509 certificate.</param>
  /// <param name="AError">Encapsulates the OpenSSL error code.</param>
  /// <param name="ASuccess">Set to True to accept; False to fail.</param>
  TTaurusTLSOnPeerCertError = procedure(ASender: TObject;
    ASocket: TTaurusTLSSslSocket; ACertificate: TTaurusTLSX509;
    const AError: TTaurusTLSX509Error; var ASuccess: boolean) of object;

  /// <summary>
  ///   Fired during in-handshake certificate verification for each certificate
  ///   in the chain.
  /// </summary>
  /// <param name="ASender">The parent IOHandler component instance.</param>
  /// <param name="ASocket">The active socket context instance.</param>
  /// <param name="ACertValidator">Validator helper for the active chain.</param>
  /// <param name="ASuccess">True if OpenSSL verification succeeded.</param>
  /// <param name="AContinue">Set to False to terminate validation chain.</param>
  TTaurusTLSOnVerifyCallback = procedure(
    ASender: TObject; ASocket: TTaurusTLSSslSocket;
    ACertValidator: TTaurusTLSX509CertValidator;
    var ASuccess, AContinue: Boolean
  ) of object;

  /// <summary>
  ///   Fired when a server requests mutual TLS (mTLS) client credentials.
  /// </summary>
  /// <param name="ASender">The parent IOHandler component instance.</param>
  /// <param name="ASocket">The active socket context instance.</param>
  /// <param name="ACert">Out-parameter: Pointer to client certificate.</param>
  /// <param name="APKey">Out-parameter: Pointer to matching private key.</param>
  TTaurusTLSOnClientCertCallback = procedure(ASender: TObject;
    ASocket: TTaurusTLSSslSocket; var ACert: PX509; APKey: PEVP_PKEY
  ) of object;

  /// <summary>
  ///   Fired when OpenSSL emits internal ECH diagnostic log lines.
  /// </summary>
  /// <param name="ASender">The parent IOHandler component instance.</param>
  /// <param name="ASocket">The active socket context instance.</param>
  /// <param name="AECHLogStr">Raw C-string containing the log text.</param>
  TTaurusTLSOnECHLog = procedure(ASender: TObject;
    ASocket: TTaurusTLSSslSocket; const AECHLogStr: PAnsiChar) of object;

  /// <summary>
  ///   Fired when the server returns updated ECHConfigList keys via retry_configs.
  /// </summary>
  /// <param name="ASender">The parent IOHandler component instance.</param>
  /// <param name="ASocket">The active socket context instance.</param>
  /// <param name="AECHRetryConfig">Base64-encoded ECHConfigList string.</param>
  TTaurusTLSOnCliECHConfigRetry = procedure(ASender: TObject;
    ASocket: TTaurusTLSSslSocket; const AECHRetryConfig: string) of object;

  /// <summary>
  ///   Specifies the direction of a low-level TLS protocol message record.
  /// </summary>
  TTaurusTLSSslOp = (
    /// <summary>Message was received from the peer.</summary>
    sslOpRecvd,
    /// <summary>Message is being sent to the peer.</summary>
    sslOpSent
  );

  /// <summary>
  ///   Encapsulates low-level TLS record frames, alerts, and handshake messages
  ///   intercepted by <c>SSL_set_msg_callback</c>.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/SSL_set_msg_callback/">
  ///   SSL_set_msg_callback
  /// </seealso>
  TTaurusTLSSslMessage = record
  private
    FOp: TTaurusTLSSslOp;
    FVersion: TIdC_INT;
    FContentType: TIdC_INT;
    FBuf: PByte;
    FLen: TIdC_SIZET;
    function GetContentTypeStr: string;
    function GetIsPseudoType: Boolean;
    function GetVersion: TTaurusTLS2SslVersion; // PALOFF 'Function result not set'
    function GetMsgDescription: string;

  public
    /// <summary>
    ///   Initializes record from raw OpenSSL message callback parameters.
    /// </summary>
    /// <param name="AWriteP">0 for received; 1 for sent.</param>
    /// <param name="AVersion">Protocol version integer.</param>
    /// <param name="AContentType">TLS content type integer.</param>
    /// <param name="ABuf">Pointer to raw record buffer.</param>
    /// <param name="ALen">Length of the buffer in bytes.</param>
    constructor Create(AWriteP, AVersion, AContentType: TIdC_INT;
      ABuf: pointer; ALen: TIdC_SIZET);

    /// <summary>Copies the raw record buffer to a managed TIdBytes array.</summary>
    /// <returns>Managed byte array containing the raw message data.</returns>
    function ToBytes: TIdBytes;

    /// <summary>Indicates whether the message was sent or received.</summary>
    property Op: TTaurusTLSSslOp read FOp;
    /// <summary>Strongly-typed TLS protocol version of the record.</summary>
    property Version: TTaurusTLS2SslVersion read GetVersion;
    /// <summary>Raw OpenSSL version integer code.</summary>
    property VersionRaw: TIdC_INT read FVersion;
    /// <summary>Raw OpenSSL content type identifier.</summary>
    property ContentType: TIdC_INT read FContentType;
    /// <summary>Human-readable content type string.</summary>
    property ContentTypeStr: string read GetContentTypeStr;
    /// <summary>Detailed decoded description of the message content.</summary>
    property Description: string read GetMsgDescription;
    /// <summary>True if content type represents an internal pseudo-type.</summary>
    property IsPseudoType: Boolean read GetIsPseudoType;
    /// <summary>Direct pointer to the unmanaged message buffer.</summary>
    property Buffer: PByte read FBuf;
    /// <summary>Length of the message buffer in bytes.</summary>
    property Length: TIdC_SIZET read FLen;
  end;

  /// <summary>
  ///   Fired when a low-level TLS protocol message record is processed.
  /// </summary>
  /// <param name="ASender">The parent IOHandler component instance.</param>
  /// <param name="ASocket">The active socket context instance.</param>
  /// <param name="lMsg">Encapsulates the message type, version, and buffer.</param>
  TTaurusTLSOnSSLMessageCallback = procedure(ASender: TObject;
    ASocket: TTaurusTLSSslSocket; const lMsg: TTaurusTLSSslMessage) of object;

  /// <summary>
  ///   Fired when OpenSSL exports TLS secrets for debugging (Wireshark keylog).
  /// </summary>
  /// <param name="ASender">The parent IOHandler component instance.</param>
  /// <param name="ASocket">The active socket context instance.</param>
  /// <param name="ALine">Raw text line containing secret key material.</param>
  /// <remarks>
  ///   Consumers must write data immediately; memory is cleansed upon return.
  /// </remarks>
  TTaurusTLSOnKeyLog = procedure(ASender: TObject; ASocket: TTaurusTLSSslSocket;
    ALine: PIdAnsiChar) of object;

  /// <summary>
  ///   Fired on the server side when the client SNI is negotiated.
  /// </summary>
  /// <param name="ASender">The parent IOHandler component instance.</param>
  /// <param name="ASocket">The active socket context instance.</param>
  /// <param name="AAlert">Out-parameter: Set to TLS alert code on failure.</param>
  TTaurusTLSOnSniSelect = procedure(ASender: TObject;
    ASocket: TTaurusTLSSslSocket; var AAlert: TIdC_INT);

  /// <summary>
  ///   Maps return codes for the server-side ALPN selection callback.
  /// </summary>
  TTaurusTLSAlpnResult = (
    /// <summary>Protocol matched successfully (<c>SSL_TLSEXT_ERR_OK</c>).</summary>
    alpnSuccess       = SSL_TLSEXT_ERR_OK,
    /// <summary>Fatal alert generated (<c>SSL_TLSEXT_ERR_ALERT_FATAL</c>).</summary>
    alpnFatalAlert    = SSL_TLSEXT_ERR_ALERT_FATAL,
    /// <summary>Warning alert generated (<c>SSL_TLSEXT_ERR_ALERT_WARNING</c>).</summary>
    alpnWarningAlert  = SSL_TLSEXT_ERR_ALERT_WARNING,
    /// <summary>No mutually acceptable protocol (<c>SSL_TLSEXT_ERR_NOACK</c>).</summary>
    alpnNoAck         = SSL_TLSEXT_ERR_NOACK
  );

  /// <summary>
  ///   Record helper providing integer conversion for ALPN result enum.
  /// </summary>
  TTaurusTLSAlpnResultHelper = record helper for TTaurusTLSAlpnResult
  private
    function GetAsInt: TIdC_INT;
    procedure SetAsInt(AValue: TIdC_INT);
  public
    /// <summary>Initializes helper with the raw integer code.</summary>
    /// <param name="AValue">The OpenSSL integer return code.</param>
    constructor Create(AValue: TIdC_INT);
    /// <summary>Raw OpenSSL integer representation of the ALPN result.</summary>
    property AsInt: TIdC_INT read GetAsInt write SetAsInt;
  end;

  /// <summary>
  ///   Parses client-offered ALPN wire protocol buffers and manages server
  ///   protocol selection during the ALPN callback.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/SSL_CTX_set_alpn_select_cb/">
  ///   SSL_CTX_set_alpn_select_cb
  /// </seealso>
  TTaurusTLSAlpnSelector = record
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private type
    TAlpnPair = record
      FOffset: PIdC_UINT8;
      FValue: string;
    end;
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FOutProto: PIdC_UINT8;
    FOutLen: TIdC_UINT8;
    FInProtos: PIdC_UINT8;
    FInLen: TIdC_UINT;
    FResultValue: TTaurusTLSAlpnResult;

    FPairs: TArray<TAlpnPair>;

    function GetCount: TIdC_INT; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetValues(AItem: TIdC_INT): string;
  public
    /// <summary>
    ///   Parses the client's wire-format ALPN protocol list.
    /// </summary>
    /// <param name="AInProtos">Pointer to raw wire-format buffer.</param>
    /// <param name="AInLen">Length of the buffer in bytes.</param>
    constructor Create(AInProtos: PIdC_UINT8; AInLen: TIdC_UINT);

    /// <summary>Selects the offered protocol at the specified index.</summary>
    /// <param name="AItem">Zero-based index of the protocol to select.</param>
    procedure Select(AItem: TIdC_INT);

    /// <summary>Declines all offered protocols (<c>alpnNoAck</c>).</summary>
    procedure Abort; {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>Sets an explicit error or alert result.</summary>
    /// <param name="AValue">The ALPN result value to return.</param>
    procedure Error(AValue: TTaurusTLSAlpnResult); {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>Total number of protocols offered by the client.</summary>
    property Count: TIdC_INT read GetCount;
    /// <summary>Protocol string identifier at the specified index.</summary>
    property Values[AItem: TIdC_INT]: string read GetValues; default;
    /// <summary>The final ALPN negotiation result code.</summary>
    property ResultValue: TTaurusTLSAlpnResult read FResultValue;
    /// <summary>Pointer to the selected wire-format protocol string.</summary>
    property SelectedProto: PIdC_UINT8 read FOutProto;
    /// <summary>Length of the selected protocol string in bytes.</summary>
    property SelectedProtoLen: TIdC_UINT8 read FOutLen;
  end;

  /// <summary>
  ///   Fired on the server side to select an Application-Layer Protocol (ALPN).
  /// </summary>
  /// <param name="ASender">The parent IOHandler component instance.</param>
  /// <param name="ASocket">The active socket context instance.</param>
  /// <param name="AAlpnState">Selector encapsulating client protocol list.</param>
  TTaurusTLSOnAlpnSelect = procedure(ASender: TObject;
    ASocket: TTaurusTLSSslSocket; const AAlpnState: TTaurusTLSAlpnSelector);

  /// <summary>
  ///   Fired on the server side when a new TLS session ticket is created.
  /// </summary>
  /// <param name="ASender">The parent IOHandler component instance.</param>
  /// <param name="ASession">Pointer to the native OpenSSL session object.</param>
  /// <param name="AAccept">Set to True to take ownership; False otherwise.</param>
  TTaurusTLSOnSslSessionNew = procedure(ASender: TObject;
    const ASession: PSSL_SESSION; var AAccept: boolean);

  /// <summary>
  ///   Fired on the server side when a TLS session ticket is invalidated.
  /// </summary>
  /// <param name="ASender">The parent IOHandler component instance.</param>
  /// <param name="ACtx">The parent SSL context pointer.</param>
  /// <param name="ASession">Pointer to the removed session object.</param>
  TTaurusTLSOnSslSessionRemove = procedure(ASender: TObject;
    ACtx: PSSL_CTX; const ASession: PSSL_SESSION);

  TTaurusTLSSslSocketCtx = class;

  /// <summary>
  ///   Reference-counted lifetime interface managing the underlying <see
  ///   cref="TTaurusTLSSslSocketCtx"/> snapshot instance.
  /// </summary>
  ITaurusTLSSslSocketCtx = interface
  ['{DCD600F0-1D28-482D-A883-A563CFE0D6FC}']
    /// <summary>
    ///   Retrieves the underlying configuration context class instance.
    /// </summary>
    /// <returns>The <see cref="TTaurusTLSSslSocketCtx"/> pointer.</returns>
    function GetCtx: TTaurusTLSSslSocketCtx;

    /// <summary>
    ///   Direct class pointer to the immutable configuration snapshot.
    /// </summary>
    property Ctx: TTaurusTLSSslSocketCtx read GetCtx;
  end;

  /// <summary>
  ///   Operational and lifecycle state flags applied to a socket context.
  /// </summary>
  TaurusTLSSslSocketCtxFlag = (
    /// <summary>Context is frozen and immutable; modifications forbidden.</summary>
    slfFrozen,
    /// <summary>Context is configured for client-side socket operations.</summary>
    slfClient,
    /// <summary>Context is configured for server-peer socket operations.</summary>
    slfServer,
    /// <summary>Enforces certificate hostname and IP identity verification.</summary>
    slfVerifyHostname,
    /// <summary>Enables unidirectional close_notify session shutdown.</summary>
    slfUniDirectShutdown,
    /// <summary>Enables quiet shutdown without sending close_notify alerts.</summary>
    slfQuietShutdown,
    /// <summary>Enables OpenSSL read-ahead internal buffer optimization.</summary>
    slfReadAheadBuffering
  );

  /// <summary>
  ///   Set representing active context operational and lifecycle flags.
  /// </summary>
  TaurusTLSSslSocketCtxFlags = set of TaurusTLSSslSocketCtxFlag;

  /// <summary>
  ///   Record helper providing indexed boolean property accessors for <see
  ///   cref="TaurusTLSSslSocketCtxFlags"/>.
  /// </summary>
  TaurusTLSSslSocketCtxFlagsHelper = record helper for TaurusTLSSslSocketCtxFlags
  private
    function GetFlag(const AFlag: TaurusTLSSslSocketCtxFlag): boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    /// <summary>True if the context is frozen and cannot be modified.</summary>
    property IsFrozen: boolean index slfFrozen read GetFlag;
    /// <summary>True if the context is configured for a client socket.</summary>
    property IsClientSocket: boolean index slfClient read GetFlag;
    /// <summary>True if the context is configured for a server socket.</summary>
    property IsServerSocket: boolean index slfServer read GetFlag;
    /// <summary>True if peer certificate hostname verification is enabled.</summary>
    property VerifyHostName: boolean index slfVerifyHostname read GetFlag;
    /// <summary>True if unidirectional shutdown is enabled.</summary>
    property UniDirectShutdown: boolean index slfUniDirectShutdown read GetFlag;
    /// <summary>True if quiet shutdown is enabled.</summary>
    property QuietShutdown: boolean index slfQuietShutdown read GetFlag;
    /// <summary>True if OpenSSL read-ahead buffering is enabled.</summary>
    property ReadAheadBuffering: boolean index slfReadAheadBuffering read GetFlag;
  end;

  TTaurusTLSMetaX509VerifyParam = class;

  /// <summary>
  ///   Subrange defining valid maximum TLS record payload fragment sizes
  ///   (512 bytes up to the default maximum of 16384 bytes).
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/SSL_CTX_set_max_send_fragment/">
  ///   SSL_CTX_set_max_send_fragment
  /// </seealso>
  TTaurusTLSSslMaxSendFragment = 512.. SSL3_RT_MAX_PLAIN_LENGTH;

  /// <summary>
  ///   Abstract base class representing an immutable runtime configuration
  ///   snapshot and OpenSSL context holder for secure socket sessions.
  /// </summary>
  TTaurusTLSSslSocketCtx = class abstract(TInterfacedObject, ITaurusTLSSslSocketCtx)
  public const
    /// <summary>Default verification modes: peer validation enabled.</summary>
    cVerifyModesDef = [sslvrfPeer];
    /// <summary>
    ///   Default context options: compression disabled and middlebox
    ///   compatibility enabled.
    /// </summary>
    cDefaultCtxOptions = [sslOpNoCompression, sslOpEnableMiddleboxCompat];

  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    // For Event parameters
    FSender: TObject;
    FSSLCtx: PSSL_CTX;

    // Common fields
    FSession: PSSL_SESSION;
    FFlags: TaurusTLSSslSocketCtxFlags;
    FCertVerifyFlags: TTaurusTLSVerifyModeFlags;

    // Common Events Events (via SSL_CTX)
    FOnStateChange: TTaurusTLSOnStateChange;
    FOnPeerCertError: TTaurusTLSOnPeerCertError;

    // OpenSSL SSL callback events
    FOnVerifyCertificate: TTaurusTLSOnVerifyCallback;
    FOnSecurityCheck: TTaurusTLSOnSecurityCheck;
    FOnStatusInfo: TTaurusTLSOnSSLStatusInfo;
    FOnMessage: TTaurusTLSOnSSLMessageCallback;
    FOnKeyLog: TTaurusTLSOnKeyLog;

    // SSL_CTX callback method(s)
    class procedure CbCtxKeyLog(const ASSL: PSSL;
      const ALine: PIdAnsiChar); cdecl; static;

    // callback event assignment status flags
    function GetHasOnStatusInfo: boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetHasOnSecurityCheck: boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetHasOnVerifyCertificate: boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetHasOnMessage: boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetHasOnKeyLog: boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
  protected
    /// <summary>
    ///   Retrieves the underlying context instance for interface mapping.
    /// </summary>
    /// <returns>Self instance as <see cref="TTaurusTLSSslSocketCtx"/>.</returns>
    function GetCtx: TTaurusTLSSslSocketCtx; {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>
    ///   Resolves the Delphi context instance bound to an OpenSSL context.
    /// </summary>
    /// <param name="ACtx">The native OpenSSL context pointer.</param>
    /// <returns>
    ///   The bound <see cref="TTaurusTLSSslSocketCtx"/> instance.
    /// </returns>
    class function GetInstanceFromCtx(ACtx: PSSL_CTX): TTaurusTLSSslSocketCtx;
      static; {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>
    ///   Normalizes a domain string to lowercase for SNI matching.
    /// </summary>
    /// <param name="AValue">Raw hostname string to normalize.</param>
    /// <returns>Lowercase normalized raw string.</returns>
    class function NormalizeHostName(const AValue: RawByteString): RawByteString;
      static; {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>
    ///   Raises an exception if the context is frozen and cannot be modified.
    /// </summary>
    procedure CheckFrozen; {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>
    ///   Queries the status of a specific context configuration flag.
    /// </summary>
    /// <param name="AFlag">The flag enum to test.</param>
    /// <returns>True if the flag is set; False otherwise.</returns>
    function GetFlag(const AFlag: TaurusTLSSslSocketCtxFlag): boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>
    ///   Dispatches state machine transition events to the registered handler.
    /// </summary>
    /// <param name="ASocket">The active socket instance.</param>
    /// <param name="AOldState">Previous socket state.</param>
    /// <param name="ANewState">Committed socket state.</param>
    procedure DoOnStateChange(ASocket: TTaurusTLSSslSocket;
      AOldState, ANewState: TTaurusTLSSslSocketState); {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>
    ///   Dispatches post-handshake certificate error events to user code.
    /// </summary>
    /// <param name="ASocket">The active socket instance.</param>
    /// <param name="ACertificate">Peer X.509 certificate wrapper.</param>
    /// <param name="AError">OpenSSL verification error record.</param>
    /// <param name="ASuccess">Set to True to override and accept failure.</param>
    procedure DoOnPeerCertError(ASocket: TTaurusTLSSslSocket;
      ACertificate: TTaurusTLSX509; const AError: TTaurusTLSX509Error;
      var ASuccess: boolean); {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>
    ///   Bridges native certificate verification callbacks to Delphi handlers.
    /// </summary>
    /// <param name="ASocket">The active socket instance.</param>
    /// <param name="ACtx">OpenSSL store context pointer.</param>
    /// <param name="ASuccess">Verification status flag.</param>
    /// <param name="AContinue">Set to False to terminate validation chain.</param>
    procedure DoOnVerifyCertificate(ASocket: TTaurusTLSSslSocket;
      ACtx: PX509_STORE_CTX; var ASuccess, AContinue: boolean);
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>
    ///   Bridges OpenSSL security evaluation callbacks to Delphi handlers.
    /// </summary>
    /// <param name="ASocket">The active socket instance.</param>
    /// <param name="op">Security operation identifier.</param>
    /// <param name="bits">Security strength bits.</param>
    /// <param name="nid">Numerical identifier of the evaluated item.</param>
    /// <param name="other">Raw pointer to the evaluated object.</param>
    /// <param name="AAccept">Set to True to permit; False to reject.</param>
    procedure DoOnSecurityCheck(ASocket: TTaurusTLSSslSocket;
      op, bits, nid: TIdC_INT; other: pointer; var AAccept: boolean);

    /// <summary>
    ///   Bridges OpenSSL state info callbacks to Delphi status handlers.
    /// </summary>
    /// <param name="ASocket">The active socket instance.</param>
    /// <param name="AWhere">OpenSSL where/state bitmask.</param>
    /// <param name="ARet">OpenSSL return or alert code.</param>
    procedure DoOnStatusInfo(ASocket: TTaurusTLSSslSocket;
      AWhere, ARet: TIdC_INT); {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>
    ///   Bridges OpenSSL protocol message callbacks to Delphi handlers.
    /// </summary>
    /// <param name="ASocket">The active socket instance.</param>
    /// <param name="AWriteP">0 for read; 1 for write.</param>
    /// <param name="AVersion">TLS protocol version.</param>
    /// <param name="AContentType">TLS record content type.</param>
    /// <param name="ABuf">Pointer to raw record buffer.</param>
    /// <param name="ALen">Buffer length in bytes.</param>
    procedure DoOnMessage(ASocket: TTaurusTLSSslSocket;
      AWriteP, AVersion, AContentType: TIdC_INT;
      const ABuf: Pointer; ALen: TIdC_SIZET);

    /// <summary>
    ///   Dispatches raw TLS secret keylog lines for Wireshark decryption.
    /// </summary>
    /// <param name="ASocket">The active socket instance.</param>
    /// <param name="ALine">Raw text line containing secret key material.</param>
    procedure DoOnKeyLog(ASocket: TTaurusTLSSslSocket; ALine: PIdAnsiChar);

    /// <summary>True if a certificate verification event is assigned.</summary>
    property HasOnVerifyCertificate: boolean read GetHasOnVerifyCertificate;
    /// <summary>True if a security check event is assigned.</summary>
    property HasOnSecurityCheck: boolean read GetHasOnSecurityCheck;
    /// <summary>True if an SSL status info event is assigned.</summary>
    property HasOnStatusInfo: boolean read GetHasOnStatusInfo;
    /// <summary>True if an SSL message tracing event is assigned.</summary>
    property HasOnMessage: boolean read GetHasOnMessage;
    /// <summary>True if an SSL keylog event is assigned.</summary>
    property HasOnKeylog: boolean read GetHasOnKeyLog;

    /// <summary>Applies context operational flags fluently.</summary>
    function SetFlags(const AValue: TaurusTLSSslSocketCtxFlags): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Sets the minimum permitted TLS protocol version fluently.</summary>
    function SetMinTLSVersion(const AValue: TTaurusTLS2TlsVersion): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Sets the maximum permitted TLS protocol version fluently.</summary>
    function SetMaxTLSVersion(const AValue: TTaurusTLS2TlsVersion): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Applies OpenSSL context bitwise option flags fluently.</summary>
    function SetSSLCtxOptions(const AValue: TTaurusTLSSslOptionFlags): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Configures TLS 1.2 and earlier cipher list fluently.</summary>
    function SetCipherList(const AValue: string): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Configures TLS 1.3 cipher suites fluently.</summary>
    function SetCipherSuites(const AValue: string): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Configures allowed key exchange curve groups fluently.</summary>
    function SetKeXGroups(const AValue: string): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Configures allowed signature algorithms fluently.</summary>
    function SetSigAlgorithms(const AValue: string): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Configures peer certificate verification modes fluently.</summary>
    function SetVerifyModes(const AValue: TTaurusTLSVerifyModes): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Attaches custom X.509 verification parameters fluently.</summary>
    function SetVerifyParam(const AValue: TTaurusTLSCustomX509VerifyParam): TTaurusTLSSslSocketCtx;
      overload; {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Attaches compiled trusted CA store fluently.</summary>
    function SetTrustStore(const AValue: TTaurusTLS_X509Store): TTaurusTLSSslSocketCtx;
      overload; {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Sets maximum TLS record payload fragment size fluently.</summary>
    function SetMaxSendFragment(const AValue: TTaurusTLSSslMaxSendFragment): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>Assigns peer certificate error event handler fluently.</summary>
    function SetOnPeerCertError(const AValue: TTaurusTLSOnPeerCertError): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Assigns state change event handler fluently.</summary>
    function SetOnStateChange(const AValue: TTaurusTLSOnStateChange): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Assigns SSL status info event handler fluently.</summary>
    function SetOnStatusInfo(const AValue: TTaurusTLSOnSSLStatusInfo): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Assigns certificate verification event handler fluently.</summary>
    function SetOnVerifyCertificate(const AValue: TTaurusTLSOnVerifyCallback): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Assigns security check callback event handler fluently.</summary>
    function SetOnSecurityCheck(const AValue: TTaurusTLSOnSecurityCheck): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Assigns protocol message tracing event handler fluently.</summary>
    function SetOnMessage(const AValue: TTaurusTLSOnSSLMessageCallback): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Assigns TLS keylog export event handler fluently.</summary>
    function SetOnKeyLog(const AValue: TTaurusTLSOnKeyLog): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>
    ///   Initializes OpenSSL context parameters, options, and callbacks.
    /// </summary>
    procedure InitCtx; virtual;

    /// <summary>
    ///   Releases OpenSSL context callbacks and unbinds user data.
    /// </summary>
    procedure ReleaseCtx; virtual;

    /// <summary>
    ///   Marks the context snapshot as frozen and immutable.
    /// </summary>
    procedure DoFreeze;

    /// <summary>Active TLS session pointer for resumption.</summary>
    property Session: PSSL_SESSION read FSession write FSession;
    /// <summary>Set of active context operational flags.</summary>
    property Flags: TaurusTLSSslSocketCtxFlags read FFlags;
    /// <summary>Set of active certificate verification flags.</summary>
    property CertVerifyFlags: TTaurusTLSVerifyModeFlags read FCertVerifyFlags;
    /// <summary>True if peer hostname verification is enabled.</summary>
    property VerifyHostname: boolean index slfVerifyHostname read GetFlag;
    /// <summary>True if unidirectional shutdown is enabled.</summary>
    property UniDirectShutdown: boolean index slfUniDirectShutdown read GetFlag;
    /// <summary>True if quiet shutdown is enabled.</summary>
    property QuietShutdown: boolean index slfQuietShutdown read GetFlag;
    /// <summary>True if read-ahead buffering is enabled.</summary>
    property ReadAheadBuffering: boolean index slfReadAheadBuffering read GetFlag;

    /// <summary>Event fired synchronously on state machine transitions.</summary>
    property OnStateChange: TTaurusTLSOnStateChange read FOnStateChange;
    /// <summary>Event fired post-handshake on peer certificate errors.</summary>
    property OnPeerCertError: TTaurusTLSOnPeerCertError read FOnPeerCertError;
    /// <summary>Event fired during OpenSSL info callback execution.</summary>
    property OnStatusInfo: TTaurusTLSOnSSLStatusInfo read FOnStatusInfo;
    /// <summary>Event fired during in-handshake certificate verification.</summary>
    property OnVerifyCertificate: TTaurusTLSOnVerifyCallback
      read FOnVerifyCertificate;

  public
    /// <summary>
    ///   Initializes a new context snapshot instance.
    /// </summary>
    /// <param name="ASender">The parent component instance.</param>
    /// <param name="ATLSMeth">The OpenSSL protocol method pointer.</param>
    constructor Create(ASender: TObject; ATLSMeth: PSSL_METHOD);

    /// <summary>
    ///   Releases context resources and frees the native OpenSSL context.
    /// </summary>
    destructor Destroy; override;

    /// <summary>
    ///   Initializes the OpenSSL context and marks the snapshot as frozen.
    /// </summary>
    /// <returns>Self instance for method chaining.</returns>
    function FreezeCtx: TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>The parent component instance initiating the context.</summary>
    property Sender: TObject read FSender;

    /// <summary>Direct pointer to the underlying native OpenSSL context.</summary>
    property SSLCtx: PSSL_CTX read FSSLCtx;
  end;

  /// <summary>
  ///   Client-specific runtime configuration snapshot managing SNI routing,
  ///   ECH keys, domain identity resolution, and mTLS client credentials.
  /// </summary>
  TTaurusTLSSslClientSocketCtx = class(TTaurusTLSSslSocketCtx)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FHostname: RawByteString;
    FDefaultSNI: RawByteString;
    FSNIMode: TTaurusTLSSslClientSNIMode;
    FECHOuterSNI: RawByteString;
    FECHConfigList: RawByteString;
    FIdentity: RawByteString;
    FIdentityIP: boolean;
    FIdentityBuilt: boolean;

    // OpenSSL Callback to Event bridge(s)
    FOnClientCert: TTaurusTLSOnClientCertCallback;
    FOnECHLog: TTaurusTLSOnECHLog;
    FOnECHConfigRetry: TTaurusTLSOnCliECHConfigRetry;

    class function CbCliCert(ASSL: PSSL; var AX509: PX509;
      var APKey: PEVP_PKEY): TIdC_INT; static; cdecl;

    class function cbEchLog(ASSL: PSSL; const ALogStr: PAnsiChar): TIdC_UINT;
      static; cdecl;

    procedure ResetIdentity; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure BuildIdentity; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetDefaultSNI: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetECHOuterSNI: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetHostName: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetECHConfigList: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetECHConfigListRaw: RawByteString; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIdentity: RawByteString; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsIdentityIP: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetECHNoOuterVal: TIdC_INT; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetUseECH: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetUseGrease: Boolean;
    function GetECHOuterSNIRaw: RawByteString; {$IFDEF USE_INLINE}inline; {$ENDIF}

    function GetHasOnClientCert: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetOnECHLog: boolean;
    function GetHasOnECHRetry: boolean;
  protected
    /// <summary>
    ///   Initializes client context callbacks on the OpenSSL SSL_CTX.
    /// </summary>
    procedure InitCtx; override;

    /// <summary>
    ///   Releases client context callbacks from the OpenSSL SSL_CTX.
    /// </summary>
    procedure ReleaseCtx; override;

    /// <summary>Sets the primary target hostname fluently.</summary>
    function SetHostName(const AValue: string): TTaurusTLSSslClientSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Sets the fallback or override SNI hostname fluently.</summary>
    function SetDefaultSNI(const AValue: string): TTaurusTLSSslClientSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Sets the SNI and ECH wire transmission mode fluently.</summary>
    function SetSNIMode(const AValue: TTaurusTLSSslClientSNIMode): TTaurusTLSSslClientSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Sets the unencrypted outer decoy SNI fluently.</summary>
    function SetECHOuterSNI(const AValue: string): TTaurusTLSSslClientSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Sets the Base64-encoded ECHConfigList string fluently.</summary>
    function SetECHConfigList(const AValue: string): TTaurusTLSSslClientSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Sets the ECH retry configuration callback fluently.</summary>
    function SetOnECHConfigRetry(
      const AValue: TTaurusTLSOnCliECHConfigRetry): TTaurusTLSSslClientSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Sets the mTLS client certificate callback fluently.</summary>
    function SetOnClientCert(
      const AValue: TTaurusTLSOnClientCertCallback): TTaurusTLSSslClientSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Sets the internal ECH logging callback fluently.</summary>
    function SetOnECHLog(const AValue: TTaurusTLSOnECHLog): TTaurusTLSSslClientSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>
    ///   Dispatches client certificate requests to the registered handler.
    /// </summary>
    /// <param name="ASocket">The active socket instance.</param>
    /// <param name="ACert">Out-parameter: Selected client certificate.</param>
    /// <param name="APKey">Out-parameter: Matching private key.</param>
    procedure DoOnClientCertCallback(ASocket: TTaurusTLSSslSocket;
      var ACert: PX509; APKey: PEVP_PKEY);

    /// <summary>
    ///   Dispatches OpenSSL internal ECH diagnostic logs to user code.
    /// </summary>
    /// <param name="ASocket">The active socket instance.</param>
    /// <param name="ALogStr">Raw C-string containing the log line.</param>
    procedure DoOnECHLogCallback(ASocket: TTaurusTLSSslSocket;
      const ALogStr: PAnsiChar);

    /// <summary>
    ///   Dispatches ECH retry configuration notifications to user code.
    /// </summary>
    /// <param name="ASocket">The active socket instance.</param>
    /// <param name="AECHRetryConfig">Base64-encoded new ECHConfigList.</param>
    procedure DoOnECHConfigRetry(ASocket: TTaurusTLSSslSocket;
      const AECHRetryConfig: string);

  public
    /// <summary>True if a client certificate callback is assigned.</summary>
    property HasOnClientCert: boolean read GetHasOnClientCert;
    /// <summary>True if an ECH logging callback is assigned.</summary>
    property HasOnECHLog: boolean read GetOnECHLog;
    /// <summary>True if an ECH retry configuration callback is assigned.</summary>
    property HasOnECHRetry: boolean read GetHasOnECHRetry;

    /// <summary>Primary target hostname string.</summary>
    property HostName: string read GetHostName;
    /// <summary>Override SNI hostname string.</summary>
    property DefaultSNI: string read GetDefaultSNI;
    /// <summary>Active SNI and ECH wire transmission mode.</summary>
    property SNIMode: TTaurusTLSSslClientSNIMode read FSNIMode;
    /// <summary>Unencrypted outer decoy SNI string.</summary>
    property ECHOuterSNI: string read GetECHOuterSNI;
    /// <summary>Base64-encoded ECHConfigList key material string.</summary>
    property ECHConfigList: string read GetECHConfigList;

    /// <summary>
    ///   Resolved logical target domain name or IP used for certificate
    ///   verification and inner ECH encryption.
    /// </summary>
    property Identity: RawByteString read GetIdentity;

    /// <summary>True if the resolved identity is an IP literal address.</summary>
    property IsIdentityIP: boolean read GetIsIdentityIP;

    /// <summary>True if active mode requires real ECH encryption.</summary>
    property UseECH: Boolean read GetUseECH;

    /// <summary>True if active mode requires ECH GREASE probing.</summary>
    property UseGREASE: Boolean read GetUseGrease;

    /// <summary>
    ///   Returns 1 if the outer SNI extension must be omitted (<c>no_outer</c>);
    ///   otherwise 0.
    /// </summary>
    property ECHNoOuterVal: TIdC_INT read GetECHNoOuterVal;

    /// <summary>Raw byte representation of the primary hostname.</summary>
    property HostNameRaw: RawByteString read FHostname;
    /// <summary>Raw byte representation of the override SNI.</summary>
    property DefaultSNIRaw: RawByteString read FDefaultSNI;
    /// <summary>Raw byte representation of the outer decoy SNI.</summary>
    property ECHOuterSNIRaw: RawByteString read GetECHOuterSNIRaw;
    /// <summary>Raw byte representation of the ECHConfigList.</summary>
    property ECHConfigListRaw: RawByteString read GetECHConfigListRaw;
  end;

  /// <summary>
  ///   Server-peer runtime configuration snapshot managing server-side SNI
  ///   virtual hosting, ALPN selection, and session ticket caching.
  /// </summary>
  TTaurusTLSSslPeerCtx = class(TTaurusTLSSslSocketCtx)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FOnSniSelect: TTaurusTLSOnSniSelect;
    FOnAlpnSelect: TTaurusTLSOnAlpnSelect;
    FOnSslSessionNew: TTaurusTLSOnSslSessionNew;
    FOnSslSessionRemove: TTaurusTLSOnSslSessionRemove;
  private
    class function CbPeerSniSelect(ASSL: PSSL; var AAlert: Integer;
      AArg: Pointer): TIdC_INT; cdecl; static;
    class function CbPeerAlpnSelect(ASSL: PSSL; var AOut: PIdC_UINT8;
      var AOutLen: TIdC_UINT8; const AIn: PIdC_UINT8;
      AInLen: TIdC_UINT; AArgs: pointer): TIdC_INT; cdecl; static;
    class function CbPeerSslSessionNew(ASSL: PSSL; ASession: PSSL_SESSION): TIdC_INT;
      cdecl; static;
    class procedure CbPeerSslSessionRemove(ACtx: PSSL_CTX;
      ASession: PSSL_SESSION); cdecl; static;

    function GetHasOnPeerSniSelect: boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetHasOnPeerAlpnSelect: boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetHasOnPeerSslSessionNew: boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetHasOnPeerSslSessionRemove: boolean;

  protected
    /// <summary>
    ///   Initializes server-peer context callbacks on the OpenSSL SSL_CTX.
    /// </summary>
    procedure InitCtx; override;

    /// <summary>
    ///   Releases server-peer context callbacks from the OpenSSL SSL_CTX.
    /// </summary>
    procedure ReleaseCtx; override;

    /// <summary>
    ///   Dispatches server SNI selection events to user code.
    /// </summary>
    /// <param name="ASocket">The active socket instance.</param>
    /// <param name="AAlert">Out-parameter: TLS alert code on failure.</param>
    procedure DoOnPeerSniSelect(ASocket: TTaurusTLSSslSocket;
      var AAlert: TIdC_INT); {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>
    ///   Dispatches ALPN protocol selection negotiation to user code.
    /// </summary>
    /// <param name="ASocket">The active socket instance.</param>
    /// <param name="AOut">Out-parameter: Pointer to selected protocol.</param>
    /// <param name="AOutLen">Out-parameter: Length of selected protocol.</param>
    /// <param name="AIn">In-parameter: Raw client-offered protocol list.</param>
    /// <param name="AInLen">In-parameter: Length of offered list.</param>
    /// <param name="AResultValue">Out-parameter: ALPN negotiation result.</param>
    procedure DoOnAlpnSelect(ASocket: TTaurusTLSSslSocket;
      var AOut: PIdC_UINT8; var AOutLen: TIdC_UINT8; const AIn: PIdC_UINT8;
      const AInLen: TIdC_UINT; var AResultValue: TIdC_INT);
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>
    ///   Dispatches new TLS session ticket creation events for caching.
    /// </summary>
    /// <param name="ASocket">The active socket instance.</param>
    /// <param name="ASession">Pointer to the native OpenSSL session object.</param>
    /// <param name="AAccept">Set to True to take ownership; False otherwise.</param>
    procedure DoOnSSLSessionNew(ASocket: TTaurusTLSSslSocket;
      ASession: PSSL_SESSION; var AAccept: boolean);
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>
    ///   Dispatches TLS session ticket invalidation/removal events.
    /// </summary>
    /// <param name="ACtx">The parent SSL context pointer.</param>
    /// <param name="ASession">Pointer to the removed session object.</param>
    procedure DoOnSSLSessionRemove(ACtx: PSSL_CTX; ASession: PSSL_SESSION);
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>Event fired during server-side SNI negotiation.</summary>
    property OnSniSelect: TTaurusTLSOnSniSelect read FOnSniSelect;
    /// <summary>Event fired during server-side ALPN selection.</summary>
    property OnAlpnSelect: TTaurusTLSOnAlpnSelect read FOnAlpnSelect;
    /// <summary>Event fired when a new session ticket is created.</summary>
    property OnSSLSessionNew: TTaurusTLSOnSslSessionNew
      read FOnSslSessionNew;
    /// <summary>Event fired when a session ticket is invalidated.</summary>
    property OnSSLSessionRemove: TTaurusTLSOnSslSessionRemove
      read FOnSslSessionRemove;
  public
    /// <summary>True if an SNI selection event is assigned.</summary>
    property HasOnPeerSniSelect: boolean read GetHasOnPeerSniSelect;
    /// <summary>True if an ALPN selection event is assigned.</summary>
    property HasOnPeerAlpnSelect: boolean read GetHasOnPeerAlpnSelect;
    /// <summary>True if a new session creation event is assigned.</summary>
    property HasOnPeerSslSessionNew: boolean read GetHasOnPeerSslSessionNew;
    /// <summary>True if a session removal event is assigned.</summary>
    property HasOnPeerSslSessionRemove: boolean read GetHasOnPeerSslSessionRemove;
  end;

  TTaurusTLSSslSocketCtxBuilder = class;

  /// <summary>
  ///   Abstract base class for builder meta-fields, providing thread
  ///   synchronization and dirty-state propagation to the parent builder.
  /// </summary>
  TTaurusTLSBuilderCustomMetaField = class
  private
    FParent: TTaurusTLSSslSocketCtxBuilder;
  protected
    /// <summary>Enters parent builder's critical section lock.</summary>
    procedure Lock; {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Leaves parent builder's critical section lock.</summary>
    procedure Unlock; {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Marks parent builder dirty to trigger recompilation.</summary>
    procedure SetDirty; {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    /// <summary>Initializes meta-field with parent builder reference.</summary>
    /// <param name="AParent">The parent context builder instance.</param>
    constructor Create(AParent: TTaurusTLSSslSocketCtxBuilder);
    /// <summary>Reference to the parent context builder instance.</summary>
    property Parent: TTaurusTLSSslSocketCtxBuilder read FParent;
  end;

  /// <summary>
  ///   Builder meta-field staging X.509 verification parameters, depth limits,
  ///   flags, and target hostname/IP/email validation lists before compilation.
  /// </summary>
  TTaurusTLSMetaX509VerifyParam = class(TTaurusTLSBuilderCustomMetaField)
  protected type
    /// <summary>Identifiers for tracked non-default verify properties.</summary>
    TProperty = (vfDefSecurityBits, vfDefDepth, vfDefPurpose, vfDefTime,
      vfDefFlVerify, vfDefFlInheritance, vfDefFlHostCheck,
      vfDefHosts, vfDefIPAddresses, vfDefEmails);
    /// <summary>Set tracking which verify properties were customized.</summary>
    TNonDefaultProps = set of TProperty;

    { TODO :
      To implement concrete TStringList descendants
      with string format validations for host, IPAddress and EMail }
    THosts = TStringList;
    TIPAddresses = TStringList;
    TEmails = TStringList;

  private
    FProps: TNonDefaultProps; //set that indicates non-default property values
    FSecurityBits: TTaurusTLSSecurityBits;
    FDepth: TIdC_INT;
    FPurpose: TTaurusTLSX509Purpose;
    FTime: TDateTime;
    FVerifyFlags: TTaurusTLSX509VerifyFlags;
    FInheritanceFlags: TTaurusTLSX509InheritanceFlags;
    FHostCheckFlags: TTaurusTLSX509HostCheckFlags;
    FHosts: THosts;
    FIPAddresses: TIPAddresses;
    FEMails: TEmails;

  protected
    /// <summary>True if specified verify property was explicitly set.</summary>
    function IsPropSet(const AProp: TProperty): boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Marks specified property set and triggers dirty state.</summary>
    procedure SetDirty(const AProp: TProperty); reintroduce;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Clears non-default tracking flag for a property.</summary>
    procedure ResetProp(const AProp: TProperty); {$IFDEF USE_INLINE}inline; {$ENDIF}

    // Property Setters
    procedure SetSecurityBits(const AValue: TTaurusTLSSecurityBits);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetDepth(const AValue: TIdC_INT); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetPurpose(const AValue: TTaurusTLSX509Purpose);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetTime(const AValue: TDateTime); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetVerifyFlags(const AValue: TTaurusTLSX509VerifyFlags);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetInheritanceFlags(const AValue: TTaurusTLSX509InheritanceFlags);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetHostCheckFlags(const AValue: TTaurusTLSX509HostCheckFlags);
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>Appends a hostname string to the verification list.</summary>
    procedure AddHost(const AValue: string); {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Sets or updates a hostname string at the given index.</summary>
    procedure SetHost(const Item: TIdC_INT; const AValue: string);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Retrieves a hostname string at the given index.</summary>
    function GetHost(const Item: TIdC_INT): string;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Deletes a hostname string at the given index.</summary>
    procedure DeleteHost(const Item: TIdC_INT);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Retrieves total count of staged verification hostnames.</summary>
    function GetHostCount: TIdC_INT;
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>Appends an email address to the verification list.</summary>
    procedure AddEMail(const AValue: string); {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Sets or updates an email address at the given index.</summary>
    procedure SetEmail(const Item: TIdC_INT; const AValue: string);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Retrieves an email address at the given index.</summary>
    function GetEmail(const Item: TIdC_INT): string;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Deletes an email address at the given index.</summary>
    procedure DeleteEmail(const Item: TIdC_INT);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Retrieves total count of staged verification emails.</summary>
    function GetEmailCount: TIdC_INT;
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>Appends an IP address literal to the verification list.</summary>
    procedure AddIpAddress(const AValue: string); {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Sets or updates an IP address literal at the given index.</summary>
    procedure SetIpAddress(const Item: TIdC_INT; const AValue: string);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Retrieves an IP address literal at the given index.</summary>
    function GetIpAddress(const Item: TIdC_INT): string;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Deletes an IP address literal at the given index.</summary>
    procedure DeleteIpAddress(const Item: TIdC_INT);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Retrieves total count of staged verification IP addresses.</summary>
    function GetIpAddressCount: TIdC_INT;
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>Resets security bits setting to default.</summary>
    procedure ResetSecurityBits; {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Resets verification depth limit to default.</summary>
    procedure ResetDepth; {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Resets certificate purpose setting to default.</summary>
    procedure ResetPurspose; {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Resets verification time override to default.</summary>
    procedure ResetTime; {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Resets X.509 verification flags to default.</summary>
    procedure ResetVerifyFlags; {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Resets parameter inheritance flags to default.</summary>
    procedure ResetInheritanceFlags; {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Resets host checking flags to default.</summary>
    procedure ResetHostCheckFlags; {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Clears all staged verification hostnames.</summary>
    procedure ResetHosts; {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Clears all staged verification IP addresses.</summary>
    procedure ResetIPAddresses; {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Clears all staged verification email addresses.</summary>
    procedure ResetEMails; {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    /// <summary>Initializes meta-field with parent builder.</summary>
    /// <param name="AParent">The parent context builder instance.</param>
    constructor Create(AParent: TTaurusTLSSslSocketCtxBuilder); reintroduce;
    /// <summary>Frees internal string lists and releases resources.</summary>
    destructor Destroy; override;

    /// <summary>
    ///   Compiles staged parameters into a native OpenSSL verify parameter
    ///   wrapper instance.
    /// </summary>
    /// <returns>A new <see cref="TTaurusTLSX509VerifyParam"/> instance.</returns>
    function BuildParam: TTaurusTLSX509VerifyParam;

    /// <summary>True if security bits level was explicitly set.</summary>
    property IsSecurityBitsSet: boolean index vfDefSecurityBits read IsPropSet;
    /// <summary>True if verification depth limit was explicitly set.</summary>
    property IsDepthSet: boolean index vfDefDepth read IsPropSet;
    /// <summary>True if certificate purpose was explicitly set.</summary>
    property IsPurposeSet: boolean index vfDefPurpose read IsPropSet;
    /// <summary>True if verification time override was explicitly set.</summary>
    property IsTimeSet: boolean index vfDefTime read IsPropSet;
    /// <summary>True if verification flags were explicitly set.</summary>
    property IsVerifyFlagsSet: boolean index vfDefFlVerify read IsPropSet;
    /// <summary>True if inheritance flags were explicitly set.</summary>
    property IsInheritanceFlagsSet: boolean index vfDefFlInheritance read IsPropSet;
    /// <summary>True if host check flags were explicitly set.</summary>
    property IsHostCheckFlagsSet: boolean index vfDefFlHostCheck read IsPropSet;
    /// <summary>True if custom verification hostnames were added.</summary>
    property IsHostsSet: boolean index vfDefHosts read IsPropSet;
    /// <summary>True if custom verification IP addresses were added.</summary>
    property IsIPAddressesSet: boolean index vfDefIPAddresses read IsPropSet;
    /// <summary>True if custom verification emails were added.</summary>
    property IsEmailsSet: boolean index vfDefEmails read IsPropSet;

    /// <summary>Configured X.509 verification flags.</summary>
    property VerifyFlags: TTaurusTLSX509VerifyFlags read FVerifyFlags;
    /// <summary>Configured parameter inheritance flags.</summary>
    property InheritanceFlags: TTaurusTLSX509InheritanceFlags read FInheritanceFlags;
    /// <summary>Configured maximum verification chain depth.</summary>
    property Depth: TIdC_INT read FDepth;
    /// <summary>Configured required security bits strength.</summary>
    property SecurityBits: TTaurusTLSSecurityBits read FSecurityBits;
    /// <summary>Configured verification time override.</summary>
    property Time: TDateTime read FTime;
    /// <summary>Flags controlling strictness of hostname matching.</summary>
    property HostCheckFlags: TTaurusTLSX509HostCheckFlags read FHostCheckFlags
      write SetHostCheckFlags;
    /// <summary>Expected certificate purpose.</summary>
    property Purpose: TTaurusTLSX509Purpose read FPurpose;
    /// <summary>Staged verification hostname string at specified index.</summary>
    property Hosts[const Item: TIdC_INT]: string read GetHost; // PALOFF 'Array properties that are referenced/set within methods'
    /// <summary>Total count of staged verification hostnames.</summary>
    property HostCount: TIdC_INT read GetHostCount;
    /// <summary>Staged verification email address at specified index.</summary>
    property Emails[const Item: TIdC_INT]: string read GetEmail; // PALOFF 'Array properties that are referenced/set within methods'
    /// <summary>Total count of staged verification email addresses.</summary>
    property EmailCount: TIdC_INT read GetEmailCount;
    /// <summary>Staged verification IP address literal at index.</summary>
    property IpAddresses[const Item: TIdC_INT]: string read GetIpAddress; // PALOFF 'Array properties that are referenced/set within methods'
    /// <summary>Total count of staged verification IP addresses.</summary>
    property IpAddressCount: TIdC_INT read GetIpAddressCount;
  end;

  /// <summary>
  ///   Abstract base builder class managing thread-safe compilation of OpenSSL
  ///   contexts and generating immutable <see cref="ITaurusTLSSslSocketCtx"/>
  ///   snapshots.
  /// </summary>
  TTaurusTLSSslSocketCtxBuilder = class abstract
  private
    FLock: TIdCriticalSection;
    FTLSMeth: PSSL_METHOD;

    FSocketCtx: ITaurusTLSSslSocketCtx;
    FDirty: boolean;

    // TTaurusTLSSslSocketCtx fields
    FFlags: TaurusTLSSslSocketCtxFlags;
    FVerifyModes: TTaurusTLSVerifyModes;
    FSSLContextOptions: TTaurusTLSSslOptionFlags;

    // standalone SSL_CTX fields
    FMinTLSVersion: TTaurusTLS2TlsVersion;
    FMaxTLSVersion: TTaurusTLS2TlsVersion;
    FCipherList: string;
    FCipherSuites: string;
    FKeyExchangeGroups: string;
    FSigAlgorithms: string;

    // X509 Verify Params field
    FX509VerifyParam: TTaurusTLSMetaX509VerifyParam; // PALOFF 'Created and freed objects'
    // Trust Stores collection
    FTrustStores: TTaurusTLSTrustStores;

    // FineTuning
    FMaxSendFragment: TTaurusTLSSslMaxSendFragment;

    // Common Events Events (via SSL_CTX)
    FOnStateChange: TTaurusTLSOnStateChange;
    FOnPeerCertError: TTaurusTLSOnPeerCertError;

    // OpenSSL SSL callback events
    FOnVerifyCertificate: TTaurusTLSOnVerifyCallback;
    FOnSecurityCheck: TTaurusTLSOnSecurityCheck;
    FOnStatusInfo: TTaurusTLSOnSSLStatusInfo;
    FOnMessage: TTaurusTLSOnSSLMessageCallback;
    FOnKeyLog: TTaurusTLSOnKeyLog;

    // Property Setters
    function GetFlag(const AFlag: TaurusTLSSslSocketCtxFlag): boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetVerifyHostName: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetUniDirectShutdown: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetQuietShutdown: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetReadAheadBuffering: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetVerifyHostName(const AValue: boolean);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetUniDirectShutdown(const AValue: boolean);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetQuietShutdown(const AValue: boolean);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetReadAheadBuffering(const AValue: boolean);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetSSLContextOptions(const AValue: TTaurusTLSSslOptionFlags);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetMinTLSVersion(const AValue: TTaurusTLS2TlsVersion);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetMaxTLSVersion(const AValue: TTaurusTLS2TlsVersion);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetCipherList(const AValue: string);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetCipherSuites(const AValue: string);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetKeXGroups(const AValue: string);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetSigAlgorithms(const AValue: string);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetVerifyModes(const AValue: TTaurusTLSVerifyModes);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetTrustStores(AValue: TTaurusTLSTrustStores);
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    // Event setters
    procedure SetOnKeyLog(const AValue: TTaurusTLSOnKeyLog);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetOnMessage(const AValue: TTaurusTLSOnSSLMessageCallback);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetOnPeerCertError(const AValue: TTaurusTLSOnPeerCertError);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetOnSecurityCheck(const AValue: TTaurusTLSOnSecurityCheck);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetOnStateChange(const AValue: TTaurusTLSOnStateChange);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetOnStatusInfo(const AValue: TTaurusTLSOnSSLStatusInfo);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetOnVerifyCertificate(const AValue: TTaurusTLSOnVerifyCallback);
      {$IFDEF USE_INLINE}inline; {$ENDIF}

  protected
    /// <summary>Enters builder's internal critical section lock.</summary>
    procedure Lock; {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Leaves builder's internal critical section lock.</summary>
    procedure Unlock; {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Marks builder dirty to trigger context recompilation.</summary>
    procedure SetDirty; {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>Sets context operational flags thread-safely.</summary>
    procedure SetFlags(const AValue: TaurusTLSSslSocketCtxFlags);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Includes flags into active flag set thread-safely.</summary>
    function IncludeFlags(const AValue: TaurusTLSSslSocketCtxFlags): TaurusTLSSslSocketCtxFlags;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Excludes flags from active flag set thread-safely.</summary>
    function ExcludeFlags(const AValue: TaurusTLSSslSocketCtxFlags): TaurusTLSSslSocketCtxFlags;
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>Hook for subclasses to validate required parameters.</summary>
    procedure CheckRequirements; virtual;
    /// <summary>Factory method instantiating the specific context class.</summary>
    /// <param name="ASender">Parent component instance.</param>
    /// <returns>A new <see cref="TTaurusTLSSslSocketCtx"/> instance.</returns>
    function DoNewSocketCtx(ASender: TObject): TTaurusTLSSslSocketCtx; virtual; abstract;
    /// <summary>Populates context parameters and event bridges.</summary>
    /// <param name="ASender">Parent component instance.</param>
    /// <param name="ASocketCtx">Target context instance to configure.</param>
    /// <returns>The configured context instance.</returns>
    function DoBuild(ASender: TObject;
      ASocketCtx: TTaurusTLSSslSocketCtx): TTaurusTLSSslSocketCtx; virtual;

    /// <summary>The OpenSSL protocol method pointer for this builder.</summary>
    property TLSMeth: PSSL_METHOD read FTLSMeth;
  public
    /// <summary>Initializes builder with specified protocol method.</summary>
    /// <param name="ATLSMeth">The OpenSSL protocol method pointer.</param>
    constructor Create(ATLSMeth: PSSL_METHOD);
    /// <summary>Frees meta-fields, critical section, and resources.</summary>
    destructor Destroy; override;

    /// <summary>
    ///   Compiles parameters, options, and stores into a frozen, thread-safe
    ///   <see cref="ITaurusTLSSslSocketCtx"/> interface snapshot.
    /// </summary>
    /// <param name="ASender">Parent component requesting compilation.</param>
    /// <returns>Reference-counted context interface instance.</returns>
    function Build(ASender : TObject): ITaurusTLSSslSocketCtx; {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>True if builder configuration changed since last build.</summary>
    property IsDirty: boolean read FDirty;

    /// <summary>Meta-field configuring X.509 verification parameters.</summary>
    property X509VerifyParam: TTaurusTLSMetaX509VerifyParam read FX509VerifyParam;

    /// <summary>Collection of trusted CA stores used for verification.</summary>
    property TrustedStores: TTaurusTLSTrustStores write SetTrustStores;

    /// <summary>Bitwise OpenSSL context options (compression, middlebox).</summary>
    property SSLContextOptions: TTaurusTLSSslOptionFlags read FSSLContextOptions
      write SetSSLContextOptions;
    /// <summary>Minimum allowed TLS protocol version.</summary>
    property MinTLSVersion: TTaurusTLS2TlsVersion read FMinTLSVersion
      write SetMinTLSVersion;
    /// <summary>Maximum allowed TLS protocol version.</summary>
    property MaxTLSVersion: TTaurusTLS2TlsVersion read FMaxTLSVersion
      write SetMaxTLSVersion;
    /// <summary>TLS 1.2 and earlier cipher suite list.</summary>
    property CipherList: string read FCipherList write SetCipherList;
    /// <summary>TLS 1.3 cipher suite list.</summary>
    property CipherSuites: string read FCipherSuites write SetCipherSuites;
    /// <summary>Allowed Elliptic Curve key exchange groups list.</summary>
    property KeyExchangeGroups: string read FKeyExchangeGroups write SetKeXGroups;
    /// <summary>Allowed signature algorithms list.</summary>
    property SigAlgorithms: string read FSigAlgorithms write SetSigAlgorithms;
    /// <summary>Peer certificate verification mode flags.</summary>
    property VerifyModes: TTaurusTLSVerifyModes read FVerifyModes
      write SetVerifyModes;
    /// <summary>True to enforce peer hostname/IP identity validation.</summary>
    property VerifyHostName: boolean read GetVerifyHostName write SetVerifyHostName;
    /// <summary>True to enable unidirectional close_notify shutdown.</summary>
    property UniDirectShutdown: boolean read GetUniDirectShutdown
      write SetUniDirectShutdown;
    /// <summary>True to enable quiet shutdown without alerts.</summary>
    property QuietShutdown: boolean read GetQuietShutdown
      write SetQuietShutdown;
    /// <summary>True to enable OpenSSL read-ahead internal buffering.</summary>
    property ReadAheadBuffering: boolean read GetReadAheadBuffering
      write SetReadAheadBuffering;
    /// <summary>Active context operational flags set.</summary>
    property Flags: TaurusTLSSslSocketCtxFlags read FFlags;
    /// <summary>Maximum TLS record payload send fragment size.</summary>
    property MaxSendFragment: TTaurusTLSSslMaxSendFragment read FMaxSendFragment
      write FMaxSendFragment default SSL3_RT_MAX_PLAIN_LENGTH;

    /// <summary>Event fired on state machine lifecycle transitions.</summary>
    property OnStateChange: TTaurusTLSOnStateChange read FOnStateChange
      write SetOnStateChange;
    /// <summary>Event fired post-handshake on peer certificate errors.</summary>
    property OnPeerCertError: TTaurusTLSOnPeerCertError read FOnPeerCertError
      write SetOnPeerCertError;
    /// <summary>Event fired during OpenSSL info callback execution.</summary>
    property OnStatusInfo: TTaurusTLSOnSSLStatusInfo read FOnStatusInfo
      write SetOnStatusInfo;
    /// <summary>Event fired during in-handshake certificate verification.</summary>
    property OnVerifyCertificate: TTaurusTLSOnVerifyCallback read FOnVerifyCertificate
      write SetOnVerifyCertificate;
    /// <summary>Event fired during OpenSSL security check callback.</summary>
    property OnSecurityCheck: TTaurusTLSOnSecurityCheck read FOnSecurityCheck
      write SetOnSecurityCheck;
    /// <summary>Event fired when low-level protocol records are processed.</summary>
    property OnMessage: TTaurusTLSOnSSLMessageCallback read FOnMessage
      write SetOnMessage;
    /// <summary>Event fired when TLS secret key material is exported.</summary>
    property OnKeyLog: TTaurusTLSOnKeyLog read FOnKeyLog write SetOnKeyLog;
  end;

  /// <summary>
  ///   Specialized context builder compiling client-side OpenSSL contexts and
  ///   generating immutable <see cref="TTaurusTLSSslClientSocketCtx"/> instances.
  /// </summary>
  TTaurusTLSSslClientSocketCtxBuilder = class(TTaurusTLSSslSocketCtxBuilder)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FHostName: string;
    FDefaultSNI: string;
    FSNIMode: TTaurusTLSSslClientSNIMode;
    FECHOuterSNI: string;
    FECHConfigList: string;

    // Client-specific callbacks
    FOnClientCert: TTaurusTLSOnClientCertCallback;
    FOnECHLog: TTaurusTLSOnECHLog;
    FOnECHConfigRetry: TTaurusTLSOnCliECHConfigRetry;

    // Property Setters (Thread-safe, invoke SetDirty)
    procedure SetHostName(const AValue: string); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetDefaultSNI(const AValue: string); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetSNIMode(const AValue: TTaurusTLSSslClientSNIMode); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetECHOuterSNI(const AValue: string); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetECHConfigList(const AValue: string); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetOnClientCert(const AValue: TTaurusTLSOnClientCertCallback); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetOnECHLog(const AValue: TTaurusTLSOnECHLog); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetOnECHConfigRetry(const AValue: TTaurusTLSOnCliECHConfigRetry); {$IFDEF USE_INLINE}inline; {$ENDIF}
  protected
    /// <summary>Validates client-specific ECH and SNI requirements.</summary>
    procedure CheckRequirements; override;
    /// <summary>Instantiates a new client socket context instance.</summary>
    /// <param name="ASender">Parent component instance.</param>
    /// <returns>A new <see cref="TTaurusTLSSslClientSocketCtx"/> instance.</returns>
    function DoNewSocketCtx(ASender: TObject): TTaurusTLSSslSocketCtx; override;
    /// <summary>Populates client-specific SNI, ECH, and mTLS properties.</summary>
    /// <param name="ASender">Parent component instance.</param>
    /// <param name="ASocketCtx">Target context instance to configure.</param>
    /// <returns>The configured context instance.</returns>
    function DoBuild(ASender: TObject;
      ASocketCtx: TTaurusTLSSslSocketCtx): TTaurusTLSSslSocketCtx; override;
  public
    /// <summary>Initializes client builder with default TLS client method.</summary>
    constructor Create; reintroduce; overload;
    /// <summary>Initializes client builder with specified protocol method.</summary>
    /// <param name="ATLSMeth">The OpenSSL protocol method pointer.</param>
    constructor Create(ATLSMeth: PSSL_METHOD); reintroduce; overload;

    /// <summary>Primary target hostname string.</summary>
    property HostName: string read FHostName write SetHostName;
    /// <summary>Override SNI hostname string.</summary>
    property DefaultSNI: string read FDefaultSNI write SetDefaultSNI;
    /// <summary>Active SNI and ECH wire transmission mode.</summary>
    property SNIMode: TTaurusTLSSslClientSNIMode read FSNIMode write SetSNIMode;
    /// <summary>Unencrypted outer decoy SNI string.</summary>
    property ECHOuterSNI: string read FECHOuterSNI write SetECHOuterSNI;
    /// <summary>Base64-encoded ECHConfigList key material string.</summary>
    property ECHConfigList: string read FECHConfigList write SetECHConfigList;

    /// <summary>Event fired when server requests mTLS client credentials.</summary>
    property OnClientCert: TTaurusTLSOnClientCertCallback read FOnClientCert write SetOnClientCert;
    /// <summary>Event fired when OpenSSL emits internal ECH logs.</summary>
    property OnECHLog: TTaurusTLSOnECHLog read FOnECHLog write SetOnECHLog;
    /// <summary>Event fired when server returns ECH retry configurations.</summary>
    property OnECHConfigRetry: TTaurusTLSOnCliECHConfigRetry read FOnECHConfigRetry write SetOnECHConfigRetry;
  end;

  /// <summary>
  ///   Represents the cryptographic outcome of ECH processing for the active connection.
  /// </summary>
  TTaurusECHClientStatus = (
    /// <summary>ECH wasn't attempted or connection gracefully fell back to cleartext.</summary>
    echCliNone,
    /// <summary>ECH was accepted and decrypted by the server (Inner SNI active).</summary>
    echCliSuccess,
    /// <summary>ECH decryption failed on the server.</summary>
    echCliFailed,
    /// <summary>ECH failed, but new server public keys were recovered via retry_configs.</summary>
    echCliRetryConfig,
    /// <summary>ECH was not configured on this connection.</summary>
    echCliNotConfigured
  );

  /// <summary>
  ///   Universal socket engine managing secure connection lifecycles, I/O timeouts,
  ///   and state machine transitions across client and server roles.
  /// </summary>
  TTaurusTLSSslSocket = class
{$IFDEF SIGPIPE_MASK}
{ BUGFIX: Fixes issue #217 and #240 }
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict {$ENDIF}private class var
    /// <summary>
    ///   Masks POSIX SIGPIPE signal once per process on Linux targets.
    /// </summary>
    FSigSet: sigset_t;
{$ENDIF}

  public const
    /// <summary>Set of terminal states from which no forward transition is valid.</summary>
    cTerminalStates = [seReleased, seClosed, seError];
    /// <summary>Default maximum transition steps allowed per transition cycle.</summary>
    cDefaultTransitions = 8;

  protected type
    /// <summary>Specifies socket event select polling types.</summary>
    TSocketSelectKind = (sokRead, sokWrite, sokError);
    /// <summary>Set of socket event select polling types.</summary>
    TSocketSelectKinds = set of TSocketSelectKind;

  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
  {$IFDEF DCC}
    [Volatile]
  {$ENDIF}
    FState: TTaurusTLSSslSocketState;
    FSocketHandle: TIdStackSocketHandle;

    // The Dual-Track State Fields
    FContextIntf: ITaurusTLSSslSocketCtx;  // Holds reference count safely
    FCtx: TTaurusTLSSslSocketCtx;

    // Error Snapshot
    FLastSSLError: TIdC_INT;      // Result of SSL_get_error (e.g. SSL_ERROR_SSL, SSL_ERROR_SYSCALL)
    FLastRetCode: TIdC_INT;       // Return code of SSL_read_ex / SSL_write_ex (e.g. 0 or -1)
    FLastQueueError: TIdC_ULONG;  // Peeked OpenSSL queue error code (via ERR_peek_error)
    FLastSocketError: Integer;    // Captured OS socket error (via GStack.WSGetLastError)

    // SSL Session Resumption flag
    FIsSessionResumed: boolean;

    function GetPeerCertificate: TTaurusTLSX509;       // Fast class pointer

    // OpenSSL callback methods
    class procedure CbSslInfo(const ASSL: PSSL;
      AWhere, ARet: TIdC_INT); static; cdecl;
    class procedure CbSslMessage(AWriteP, AVersion,
      AContentType: TIdC_INT; const ABuf: pointer; ALen: TIdC_SIZET; ASSL: PSSL;
      AArg: Pointer); static; cdecl;
    class function CbSslVerify(const APreVerify: TIdC_INT;
      ACtx: PX509_STORE_CTX): TIdC_INT; static; cdecl;
    class function CbSslSecurityCheck(const ASSL: PSSL; const ACtx: PSSL_CTX;
      AOp, ABits, ANid: TIdC_INT; AOther, AEx: pointer): TIdC_INT; static; cdecl;
    class function CbSrvAlpnSelectCallback(ASSL: PSSL; var AOutProto: PIdAnsiChar;
      var AOutLen: TIdC_UINT8; const AInProtos: PIdAnsiChar;
      AInLen: TIdC_UINT; AArg: Pointer): TIdC_INT; static; cdecl;

    class function CheckForSocketEvent(ASocketHandle: TIdStackSocketHandle;
      AKind: TSocketSelectKinds; AMsec: integer): boolean; static;
      {$IFDEF USE_INLINE}inline; {$ENDIF}

{$IFDEF SIGPIPE_MASK}
{ BUGFIX: Fixes issue #217 and #240 }
    /// <summary>
    ///   Masks the POSIX SIGPIPE signal for the running thread.
    /// </summary>
    class procedure MaskSigPipe;  static; {$IFDEF USE_INLINE}inline; {$ENDIF}
{$ENDIF}

  protected
    /// <summary>Active native OpenSSL session structure pointer.</summary>
    FSSL: PSSL;
    /// <summary>Resolves Delphi socket instance from native SSL app_data.</summary>
    class function GetInstanceFromSSL(ASSL: PSSL): TTaurusTLSSslSocket; static;
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>Processes captured errors and raises appropriate exceptions.</summary>
    function CheckForError: Integer; overload; virtual;
    /// <summary>Captures OpenSSL queue and OS socket error snapshots.</summary>
    function GetLastError(ARetCode: Integer): Integer; overload;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Queries SSL_get_error and captures error state snapshot.</summary>
    function GetSSLError(ALastResult: Integer): Integer; overload;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Clears OpenSSL queue and resets captured error snapshot.</summary>
    procedure ClearError; {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>Allocates native SSL session and arms callbacks.</summary>
    function InitSSL: TTaurusTLSSslSocketState; virtual;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Registers connection-specific OpenSSL callback bridges.</summary>
    procedure InitSSLCallbacks; virtual;
    /// <summary>Configures connection-specific SNI, ECH, or routing parameters.</summary>
    procedure SetupConnection; virtual; abstract;
    /// <summary>Deallocates native SSL session and unbinds callbacks.</summary>
    function ReleaseSSL: TTaurusTLSSslSocketState; virtual;
    /// <summary>Unbinds connection-specific OpenSSL callback bridges.</summary>
    procedure ReleaseSSLCallbacks; virtual;
    /// <summary>Binds physical socket descriptor to OpenSSL session.</summary>
    function BindSocket: TTaurusTLSSslSocketState; {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>Polls OS socket handle for specified I/O select events.</summary>
    class function WaitForSocket(ASocketHandle: TIdStackSocketHandle;
      AKind: TSocketSelectKinds; AMsec: integer): boolean; static;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Waits for socket read readiness within timeout budget.</summary>
    function WaitForRead(AMsec: integer): boolean;  {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Waits for socket write readiness within timeout budget.</summary>
    function WaitForWrite(AMsec: integer): boolean;  {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>Drives the handshake loop until completion or terminal state.</summary>
    function DoHandshake: TTaurusTLSSslSocketState;
    /// <summary>Executes a single step of SSL_connect or SSL_accept.</summary>
    function DoHandshakeIteration: TTaurusTLSSslSocketState; virtual; abstract;
    /// <summary>Executes orderly TLS session close_notify shutdown.</summary>
    function DoShutdown: TTaurusTLSSslSocketState; virtual;

    // State machine
    /// <summary>Validates whether single-step transition is permitted.</summary>
    function IsValidTransition(ACurrent, ATarget: TTaurusTLSSslSocketState): Boolean; virtual;
    /// <summary>Asserts that current state is within expected active states.</summary>
    procedure CheckActiveState(const AExpectedStates: TTaurusTLSSslSocketStates);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Resolves immediate next step required to reach target state.</summary>
    function GetNextStepTarget(ACurrent,
      ATarget: TTaurusTLSSslSocketState): TTaurusTLSSslSocketState; virtual;
    /// <summary>Executes single step state initialization or cleanup.</summary>
    function DoTransitionTo(ATarget: TTaurusTLSSslSocketState): TTaurusTLSSslSocketState;
      virtual;
    /// <summary>Commits new state value without firing notifications.</summary>
    function DoSetState(ATarget: TTaurusTLSSslSocketState): boolean;
      overload; virtual;
    /// <summary>Commits new state value and optionally fires notifications.</summary>
    procedure DoSetState(ATarget: TTaurusTLSSslSocketState; ANotify: boolean);
      overload; {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Dispatches state change notifications to context handlers.</summary>
    procedure DoStateChangeNotify(ACurrent, ATarget: TTaurusTLSSslSocketState);
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>Physical OS socket descriptor handle.</summary>
    property SocketHandle: TIdStackSocketHandle read FSocketHandle write FSocketHandle;
    /// <summary>True if active connection successfully resumed a previous TLS session.</summary>
    property IsSessionResumed: boolean read FIsSessionResumed;
    /// <summary>Peer X.509 certificate wrapper instance.</summary>
    property PeerCertificate: TTaurusTLSX509 read GetPeerCertificate;
  public
{$IFDEF SIGPIPE_MASK}
{ BUGFIX: Fixes issue #217 and #240 }
    /// <summary>
    ///   Initializes the POSIX signal mask once at application startup.
    /// </summary>
    class constructor Create;
{$ENDIF}
    /// <summary>Initializes socket instance with a reference-counted context interface.</summary>
    /// <param name="AConfigIntf">The immutable context snapshot interface.</param>
    constructor Create(const AConfigIntf: ITaurusTLSSslSocketCtx); virtual;
    /// <summary>Destroys socket instance and releases OpenSSL session resources.</summary>
    destructor Destroy; override;

    /// <summary>Drives the state machine forward toward the requested target state.</summary>
    /// <param name="ATarget">Desired final state enum value.</param>
    /// <param name="ASteps">Maximum transition step budget before aborting.</param>
    procedure TransitionTo(ATarget: TTaurusTLSSslSocketState;
      ASteps: integer = cDefaultTransitions); virtual;

    /// <summary>Binds socket handle and drives state machine to established state.</summary>
    /// <param name="pHandle">The physical OS socket descriptor handle.</param>
    /// <returns>True if established successfully; False otherwise.</returns>
    function Connect(const pHandle: TIdStackSocketHandle): boolean; overload;
      virtual;
    /// <summary>Encrypts and sends application data buffer over active TLS session.</summary>
    function Send(const ABuffer: TIdBytes; const AOffset, ALength: TIdC_SIZET;
      const AMSec: Integer): Integer; {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Receives and decrypts application data from active TLS session.</summary>
    function Recv(var ABuffer: TIdBytes; const AMSec: Integer): Integer;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Polls whether decrypted application data is ready for reading.</summary>
    function Readable(AMsec: integer): boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    /// <summary>Initiates orderly session shutdown and state machine teardown.</summary>
    procedure Shutdown;
    /// <summary>Validates post-handshake peer certificate verification result.</summary>
    procedure CheckPeerCertificateValidationResult; {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>Direct pointer to active native OpenSSL session structure.</summary>
    property SSL: PSSL read FSSL;
    /// <summary>Current operational state of the socket state machine.</summary>
    property State: TTaurusTLSSslSocketState read FState;
    /// <summary>Direct class pointer to immutable configuration context snapshot.</summary>
    property Ctx: TTaurusTLSSslSocketCtx read FCtx;
  end;

  /// <summary>
  ///   Encapsulates and manages the reference-counted lifecycle of a native
  ///   OpenSSL <c>SSL_SESSION</c> handle for TLS session resumption.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/SSL_get1_session/">
  ///   SSL_get1_session
  /// </seealso>
  TTaurusTLSSslSession = class
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSession: PSSL_SESSION;
  public
    /// <summary>
    ///   Captures and increments the reference count of the active TLS
    ///   session from an established socket via <c>SSL_get1_session</c>.
    /// </summary>
    /// <param name="ASocket">The established socket instance.</param>
    constructor Create(ASocket: TTaurusTLSSslSocket);

    /// <summary>
    ///   Releases and frees the native <c>SSL_SESSION</c> handle via
    ///   <c>SSL_SESSION_free</c>.
    /// </summary>
    destructor Destroy; override;

    /// <summary>Pointer to the native OpenSSL session structure.</summary>
    property SSLSession: PSSL_SESSION read FSession;
  end;

  /// <summary>
  ///   Client-side socket engine managing outbound connection setup, SNI
  ///   routing, ECH encryption, and handshake execution.
  /// </summary>
  TTaurusTLSClientSocket = class(TTaurusTLSSslSocket)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSessionToResume: TTaurusTLSSslSession;
    FECHStatus: TTaurusECHClientStatus;
    function GetClientCtx: TTaurusTLSSslClientSocketCtx;
  protected
    /// <summary>Updates the internal ECH outcome status.</summary>
    /// <param name="AECHStatus">The new ECH status enum value.</param>
    procedure SetECHStatus(AECHStatus: TTaurusECHClientStatus);
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>
    ///   Configures client SNI, ECH server names, and session parameters.
    /// </summary>
    procedure SetupConnection; override;

    /// <summary>
    ///   Configures in-place hostname and IP validation targets on the
    ///   active OpenSSL session verification parameters.
    /// </summary>
    procedure SetupHostnameVerification; {$IFDEF USE_INLINE}inline; {$ENDIF}

    /// <summary>
    ///   Executes a single step of <c>SSL_connect</c>, handles ECH status
    ///   evaluations, and processes retry configurations.
    /// </summary>
    /// <returns>Next state machine target state.</returns>
    function DoHandshakeIteration: TTaurusTLSSslSocketState; override;

    /// <summary>
    ///   Executes client-side shutdown and cleans up session resumption state.
    /// </summary>
    /// <returns>Next state machine target state.</returns>
    function DoShutdown: TTaurusTLSSslSocketState; override;

    /// <summary>
    ///   Direct class pointer to the client-specific configuration snapshot.
    /// </summary>
    property ClientCtx: TTaurusTLSSslClientSocketCtx read GetClientCtx;
  public
    /// <summary>
    ///   Binds the socket handle, applies a session resumption ticket, and
    ///   drives the state machine to established state.
    /// </summary>
    /// <param name="pHandle">The physical OS socket descriptor handle.</param>
    /// <param name="ASessionToResume">The session resumption container.</param>
    /// <returns>True if established successfully; False otherwise.</returns>
    function Connect(const pHandle: TIdStackSocketHandle; //PALOFF "Redeclares ancestor member, or method in helped class/record"
      ASessionToResume: TTaurusTLSSslSession): boolean; overload;

    /// <summary>Negotiated ECH status outcome for this connection.</summary>
    property ECHStatus: TTaurusECHClientStatus read FECHStatus;
  end;

  /// <summary>
  ///   Server-peer socket engine managing inbound connection handshakes and
  ///   server-side session execution.
  /// </summary>
  TTaurusTLSPeerSocket = class(TTaurusTLSSslSocket)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
  end;

  // Global support routines

/// <summary>
///   Evaluates whether the loaded OpenSSL library version meets or exceeds
///   the specified version number.
/// </summary>
/// <param name="AVersion">The version numeric constant to compare.</param>
/// <returns>True if the library version is greater than or equal.</returns>
function IsOpenSSLVersion(const AVersion: TTaurusTLSOSSLVersion): boolean;
  {$IFDEF USE_INLINE} inline;{$ENDIF}

/// <summary>
///   Determines whether the loaded OpenSSL library supports Encrypted Client
///   Hello (OpenSSL 4.0+).
/// </summary>
/// <returns>True if ECH APIs are available in the loaded binary.</returns>
function IsECHSupported: boolean; {$IFDEF USE_INLINE} inline;{$ENDIF}

/// <summary>
///   Determines whether the loaded OpenSSL library supports multiple IP
///   addresses in verification parameters (OpenSSL 4.0+).
/// </summary>
/// <returns>True if multi-IP verification is supported.</returns>
function IsX509StoreMultiIPSupported: boolean; {$IFDEF USE_INLINE} inline;{$ENDIF}

/// <summary>
///   Determines whether the loaded OpenSSL library supports multiple email
///   addresses in verification parameters (OpenSSL 4.0+).
/// </summary>
/// <returns>True if multi-email verification is supported.</returns>
function IsX509StoreMultiEmailSupported: boolean; {$IFDEF USE_INLINE} inline;{$ENDIF}

implementation

uses
  SyncObjs,
{$IFDEF DCC}
  System.AnsiStrings,
{$ENDIF}
  DateUtils,
  TaurusTLSHeaders_err,
  TaurusTLSHeaders_sslerr,
  TaurusTLSHeaders_objects,
  TaurusTLS_ResourceStrings,
  IdAntifreezeBase,
  IdException,
  IdResourceStrings,
  IdResourceStringsProtocols
{$IFDEF MSWINDOWS}
  ,IdIDN // For IDNToPunnyCode
{$ENDIF}
  ;

const
  cVer40      = $40000000;
  cVerECH     = cVer40;
  cVerMIp     = cVer40;
  cVerMEmail  = cVer40;

function IsOpenSSLVersion(const AVersion: TTaurusTLSOSSLVersion): boolean;
begin
  Result:=OpenSSL_version_num >= AVersion;
end;

function IsECHSupported: boolean;
begin
  Result:=IsOpenSSLVersion(cVerECH);
end;

function IsX509StoreMultiIPSupported: boolean;
begin
  Result:=IsOpenSSLVersion(cVerMIp);
end;

function IsX509StoreMultiEmailSupported: boolean;
begin
  Result:=IsOpenSSLVersion(cVerMEmail);
end;


{ ETaurusTLSSslSocketError }

class function ETaurusTLSSslSocketError.TargetSocketState: TTaurusTLSSslSocketState;
begin
  Result:=seError;
end;

{ ETaurusTLSSslSocketClose }

class function ETaurusTLSSslSocketClose.TargetSocketState: TTaurusTLSSslSocketState;
begin
  Result:=seReleased;
end;

{ ETaurusTLSCertValidationError }

constructor ETaurusTLSSslSocketCertValidationError.Create(AVerifyCode: TIdC_LONG;
  const AMessage: string);
begin
  FVerifyCode:=AVerifyCode;
  inherited Create(AMessage);
end;

class procedure ETaurusTLSSslSocketCertValidationError.RaiseErrorCode(
  AVerifyCode: TIdC_LONG; const AMessage: string);
begin
  Raise ETaurusTLSSslSocketCertValidationError.Create(AVerifyCode, AMessage);
end;

{ TTaurusTLSSslState }

constructor TTaurusTLSSslState.Create(const ASSLStates, ACode: TIdC_INT;
  ASSL: PSSL);
begin
  Init(ASSLStates, ACode, ASSL);
end;

constructor TTaurusTLSSslState.Create(const AStates: TTaurusTLSSslStateFlags;
  const ACode: TIdC_INT; ASSL: PSSL);
begin
  Init(ToInt(AStates), ACode, ASSL);
end;

procedure TTaurusTLSSslState.Init(const ASSLStates, ACode: TIdC_INT; ASSL: PSSL);
begin
  FStates:=ASSLStates and cStateFlagsMask; // cleanup possible unknown flags
  FCode:=ACode;
  FSSL:=ASSL;
  InitMessages;
end;

procedure TTaurusTLSSslState.InitMessages;
var
  lStatusMessage, lAlertMessage: string;

begin
  FStatusMessage:='';
  FAlertMessage:='';
  lStatusMessage:=AnsiStringToString(SSL_state_string_long(FSSL));
  lAlertMessage:=AnsiStringToString(SSL_alert_type_string_long(FCode));

  case FStates of
    SSL_CB_ALERT:
      begin
        FStatusMessage:=IndyFormat(RSOSSLAlert, [SSL_alert_type_string_long(FCode)]);
        FAlertMessage:=lAlertMessage;
      end;
    SSL_CB_READ_ALERT:
      begin
        FStatusMessage:=IndyFormat(RSOSSLReadAlert,
          [SSL_alert_type_string_long(FCode)]);
        FAlertMessage:=lAlertMessage;
      end;
    SSL_CB_WRITE_ALERT:
      begin
        FStatusMessage:=IndyFormat(RSOSSLWriteAlert, [lAlertMessage]);
        FAlertMessage:=AnsiStringToString(SSL_alert_desc_string_long(FCode));
      end;
    SSL_CB_ACCEPT_LOOP:
      begin
        FStatusMessage:=RSOSSLAcceptLoop;
        FAlertMessage:=lStatusMessage;
      end;
    SSL_CB_ACCEPT_EXIT:
      begin
        if FCode < 0 then
        begin
          FStatusMessage:=RSOSSLAcceptError;
        end
        else
        begin
          if FCode = 0 then
          begin
            FStatusMessage:=RSOSSLAcceptFailed;
          end
          else
          begin
            FStatusMessage:=RSOSSLAcceptExit;
          end;
        end;
        FAlertMessage:=lStatusMessage;
      end;
    SSL_CB_CONNECT_LOOP:
      begin
        FStatusMessage:=RSOSSLConnectLoop;
        FAlertMessage:=lStatusMessage;
      end;
    SSL_CB_CONNECT_EXIT:
      begin
        if FCode < 0 then
        begin
          FStatusMessage:=RSOSSLConnectError;
        end
        else
        begin
          if FCode = 0 then
          begin
            FStatusMessage:=RSOSSLConnectFailed
          end
          else
          begin
            FStatusMessage:=RSOSSLConnectExit;
          end;
        end;
        FAlertMessage:=lStatusMessage;
      end;
    SSL_CB_HANDSHAKE_START:
      begin
        FStatusMessage:=RSOSSLHandshakeStart;
        FAlertMessage:=lStatusMessage;
      end;
    SSL_CB_HANDSHAKE_DONE:
      begin
        FStatusMessage:=RSOSSLHandshakeDone;
        FAlertMessage:=lStatusMessage;
      end;
  end;
end;

class function TTaurusTLSSslState.ToInt(
  const AValue: TTaurusTLSSslStateFlags): TIdC_INT;
begin
{$IF SizeOf(TTaurusTLSSslStateFlags) = 1}
  Result:=PIdC_INT8(@AValue)^ and cStateFlagsMask;
{$ELSEIF SizeOf(TTaurusTLSSslStateFlags) = 2}
  Result:=PIdC_INT16(@AValue)^ and cStateFlagsMask;
{$ELSEIF SizeOf(TTaurusTLSSslStateFlags) = 4}
  Result:=PIdC_INT(@AValue)^ and cStateFlagsMask;
{$IFEND}
end;

function TTaurusTLSSslState.GetIsConnect: boolean;
begin
  Result:=stfConnect in StateFlags;
end;

function TTaurusTLSSslState.GetIsAccept: boolean;
begin
  Result:=stfAccept in StateFlags;
end;

function TTaurusTLSSslState.GetIsInLoop: boolean;
begin
  Result:=stfLoop in StateFlags;
end;

function TTaurusTLSSslState.GetIsAlert: boolean;
begin
  Result:=stfAlert in StateFlags;
end;

function TTaurusTLSSslState.GetIsRead: boolean;
begin
  Result:=stfRead in StateFlags;
end;

function TTaurusTLSSslState.GetIsWrite: boolean;
begin
  Result:=stfWrite in StateFlags;
end;

function TTaurusTLSSslState.GetIsHandshakeStarts: boolean;
begin
  Result:=stfHandShakeStart in StateFlags;
end;

function TTaurusTLSSslState.GetIsHandshakeDone: boolean;
begin
  Result:=stfHandShakeDone in StateFlags;
end;

function TTaurusTLSSslState.GetIsReadAlert: boolean;
begin
  Result:=IsAlert and IsRead;
end;

function TTaurusTLSSslState.GetIsWriteAlert: boolean;
begin
  Result:=IsAlert and IsWrite;
end;

function TTaurusTLSSslState.GetIsAcceptLoop: boolean;
begin
  Result:=IsAccept and IsInLoop;
end;

function TTaurusTLSSslState.GetIsAcceptExit: boolean;
begin
  Result:=IsAccept and IsExit;
end;

function TTaurusTLSSslState.GetIsConnectLoop: boolean;
begin
  Result:=IsConnect and IsInLoop;
end;

function TTaurusTLSSslState.GetIsExit: boolean;
begin
  Result:=stfExit in StateFlags;
end;

function TTaurusTLSSslState.GetIsConnectExit: boolean;
begin
  Result:=IsConnect and IsExit;
end;

function TTaurusTLSSslState.GetStateFlags: TTaurusTLSSslStateFlags;
begin
{$IF SizeOf(TTaurusTLSSslStateFlags) = 1}
  PIdC_INT8(@Result)^:=FStates;
{$ELSEIF SizeOf(TTaurusTLSSslStateFlags) = 2}
  PIdC_INT16(@Result)^:=FStates;
{$ELSEIF SizeOf(TTaurusTLSSslStateFlags) = 4}
  PIdC_INT(@Result)^:=FStates;
{$IFEND}
end;

function TTaurusTLSSslState.GetAlertMessage: string;
begin
  if FAlertMessage = '' then
    InitMessages;
  Result:=FAlertMessage;
end;

function TTaurusTLSSslState.GetStateStatusMessage: string;
begin
  if FStatusMessage = '' then
    InitMessages;
  Result:=FStatusMessage;
end;

{ TTaurusTLSSecurityCheckState }

constructor TTaurusTLSSecurityCheckState.Create(AOp, ABits, ANid: TIdC_INT;
  AOther: Pointer);
begin
  FOp:=AOp;
  FBits.AsInt:=ABits;
  FNid:=ANid;
  FOther:=AOther;
  FCert:=nil;
end;

procedure TTaurusTLSSecurityCheckState.Destroy;
begin
  if Assigned(FCert) then
    FreeAndNil(FCert);
end;

function TTaurusTLSSecurityCheckState.GetIsPeer: Boolean;
begin
  Result:=(FOp and SSL_SECOP_PEER) <> 0;
end;

function TTaurusTLSSecurityCheckState.GetIsCipher: Boolean;
begin
  Result:=(FOp and SSL_SECOP_OTHER_TYPE) = SSL_SECOP_OTHER_CIPHER;
end;

function TTaurusTLSSecurityCheckState.GetIsCurve: Boolean;
begin
  Result:=(FOp and SSL_SECOP_OTHER_TYPE) = SSL_SECOP_OTHER_CURVE;
end;

function TTaurusTLSSecurityCheckState.GetIsDH: Boolean;
begin
  Result:=(FOp and SSL_SECOP_OTHER_TYPE) = SSL_SECOP_OTHER_DH;
end;

function TTaurusTLSSecurityCheckState.GetIsPKey: Boolean;
begin
  Result:=(FOp and SSL_SECOP_OTHER_TYPE) = SSL_SECOP_OTHER_PKEY;
end;

function TTaurusTLSSecurityCheckState.GetIsSigAlg: Boolean;
begin
  Result:=(FOp and SSL_SECOP_OTHER_TYPE) = SSL_SECOP_OTHER_SIGALG;
end;

function TTaurusTLSSecurityCheckState.GetIsCert: Boolean;
begin
  Result:=(FOp and SSL_SECOP_OTHER_TYPE) = SSL_SECOP_OTHER_CERT;
end;

function TTaurusTLSSecurityCheckState.GetNidShortName: string;
var
  lName: PIdAnsiChar;
begin
  Result:='';
  if FNid <> 0 then
  begin
    lName:=OBJ_nid2sn(FNid);
    if Assigned(lName) then
      Result:=AnsiStringToString(lName);
  end;
end;

function TTaurusTLSSecurityCheckState.GetNidLongName: string;
var
  lName: PIdAnsiChar;
begin
  Result:='';
  if FNid <> 0 then
  begin
    lName:=OBJ_nid2ln(FNid);
    if Assigned(lName) then
      Result:=AnsiStringToString(lName);
  end;
end;

function TTaurusTLSSecurityCheckState.GetCipherName: string;
var
  lName: PIdAnsiChar;
begin
  Result:='';
  // Verify that the payload is actually a cipher, and that the pointer is valid
  if IsCipher and Assigned(FOther) then
  begin
    lName:=SSL_CIPHER_get_name(FOther);
    if Assigned(lName) then
      Result:=AnsiStringToString(lName);
  end;
end;

function TTaurusTLSSecurityCheckState.GetCertificate: TTaurusTLSX509;
begin
  if Assigned(FCert) then
    Exit(FCert);

  Result:=nil;
  // Verify that the payload is actually a certificate, and that the pointer is valid
  if IsCert and Assigned(FOther) then
    // Instantiates a non-owning wrapper around the unmanaged X509 pointer.
    // The record instance takes takes ownership of this wrapper.
    // The OnSecurityLevel Event handler MUST NOT FREE the certificate instance.
    Result:=TTaurusTLSX509.Create(FOther, False);
  FCert:=Result;
end;

{ TTaurusTLSTrustStore }

constructor TTaurusTLSTrustStore.Create(const AName: string;
  const AUri: RawByteString; AUiCtx: TTaurusTLS_UICtx);
begin
  inherited Create(AUri, AUiCtx, cFilter);
  SetName(AName);
end;

constructor TTaurusTLSTrustStore.Create(const AName: string;
  const AUri: UnicodeString; AUiCtx: TTaurusTLS_UICtx);
begin
  inherited Create(AUri, AUiCtx, cFilter);
  SetName(AName);
end;

constructor TTaurusTLSTrustStore.Create(const AName: string;
  ABio: TTaurusTLSCustomBIO; AUiCtx: TTaurusTLS_UICtx);
begin
  inherited Create(ABio, AUiCtx, cFilter);
  SetName(AName);
end;

constructor TTaurusTLSTrustStore.CreateMem(const AName: string;
  AUiCtx: TTaurusTLS_UICtx; const AData: string);
var
  lBio: TTaurusTLSRawByteStringBIO; // PALOFF 'Created and freed objects'

begin
  lBio:=TTaurusTLSRawByteStringBIO.Create(RawByteString(AData)); // PALOFF 'TBytes cast to RawByteString' // Why PAL detects AData as  TBytes ???
  try
    Create(AName, lBio, AUiCtx);
  finally
    lBio.Free;
  end;
end;

constructor TTaurusTLSTrustStore.CreateMem(const AName: string;
  AUiCtx: TTaurusTLS_UICtx; const AData: TBytes);
var
  lBio: TTaurusTLSBytesBio;  // PALOFF 'Created and freed objects'

begin
  lBio:=TTaurusTLSBytesBio.Create(AData);
  try
    Create(AName, lBio, AUiCtx);
  finally
    lBio.Free;
  end;
end;

procedure TTaurusTLSTrustStore.SetName(const AName: string);
begin
  FName:=AName;
end;

{ TTaurusTLSTrustStores }

procedure TTaurusTLSTrustStores.CheckStore(const AStore: TTaurusTLSTrustStore);
begin
  Assert(Assigned(AStore), 'AStore must not be ''nil'' value.'); // Do not localize
end;

procedure TTaurusTLSTrustStores.Add(const AValue: TTaurusTLSTrustStore);
begin
  CheckStore(AValue);
  inherited Add(AValue.Name, AValue);
end;

procedure TTaurusTLSTrustStores.AddOrSetValue(
  const AValue: TTaurusTLSTrustStore);
begin
  CheckStore(AValue);
  inherited AddOrSetValue(AValue.Name, AValue);
end;

function TTaurusTLSTrustStores.TryAdd(
  const AValue: TTaurusTLSTrustStore): boolean;
begin
  CheckStore(AValue);
  {$IF Defined(DCC) and (CompilerVersion < 33.0)} // Delph 10.2 and below
  Result:=True;
  try
    inherited Add(AValue.Name, AValue)
  except
    Result:=False; // Do not re-raise the exception
  end;
  {$ELSE}
  Result:=inherited TryAdd(AValue.Name, AValue);
  {$IFEND}
end;

function TTaurusTLSTrustStores.BuildStore: TTaurusTLS_X509Store;
var
  lStorePair: TPair<string, TTaurusTLSTrustStore>;

begin
  Result:=TTaurusTLS_X509Store.Create;
  try
    for lStorePair in Self do
      Result.AppendFromOsslStore(lStorePair.Value, [sitCert, sitCRL]);
  except
    FreeAndNil(Result);
    raise;
  end;
end;

{ TTaurusTLSSslMessage }

constructor TTaurusTLSSslMessage.Create(AWriteP, AVersion,
  AContentType: TIdC_INT; ABuf: pointer; ALen: TIdC_SIZET);
begin
  FVersion:=AVersion;
  FContentType:=AContentType;
  FBuf:=ABuf;
  FLen:=ALen;
  if AWriteP = 0 then
    FOp:=sslOpRecvd
  else
    FOp:=sslOpSent;
end;

function TTaurusTLSSslMessage.GetContentTypeStr: string;
begin
  // Do not localize below
  case FContentType of
    // Standard TLS Record Types
    SSL3_RT_CHANGE_CIPHER_SPEC:    Result:='Change Cipher Spec';
    SSL3_RT_ALERT:                 Result:='Alert';
    SSL3_RT_HANDSHAKE:             Result:='Handshake';
    SSL3_RT_APPLICATION_DATA:      Result:='Application Data';

    // Record Header & Inner Decoys
    SSL3_RT_HEADER:                Result:='Record Header';
    SSL3_RT_INNER_CONTENT_TYPE:    Result:='Decrypted Inner Content Type';

    // QUIC Frame Tracing
    SSL3_RT_QUIC_DATAGRAM:         Result:='QUIC Datagram';
    SSL3_RT_QUIC_PACKET:           Result:='QUIC Packet';
    SSL3_RT_QUIC_FRAME_FULL:       Result:='QUIC Frame (Full)';
    SSL3_RT_QUIC_FRAME_HEADER:     Result:='QUIC Frame (Header)';
    SSL3_RT_QUIC_FRAME_PADDING:    Result:='QUIC Frame (Padding)';

    // Cryptographic Keys & Secrets Tracing
    TLS1_RT_CRYPTO_PREMASTER:      Result:='Crypto: Premaster Secret';
    TLS1_RT_CRYPTO_CLIENT_RANDOM:  Result:='Crypto: Client Random';
    TLS1_RT_CRYPTO_SERVER_RANDOM:  Result:='Crypto: Server Random';
    TLS1_RT_CRYPTO_MASTER:         Result:='Crypto: Master Secret';
    TLS1_RT_CRYPTO_MAC:            Result:='Crypto: MAC Key';
    TLS1_RT_CRYPTO_KEY:            Result:='Crypto: Encryption Key';
    TLS1_RT_CRYPTO_IV:             Result:='Crypto: Initialization Vector (IV)';
    TLS1_RT_CRYPTO_FIXED_IV:       Result:='Crypto: Fixed IV';
  else
    Result:='Unknown (0x' + IntToHex(FContentType, 2) + ')';
  end;end;

function TTaurusTLSSslMessage.GetIsPseudoType: Boolean;
begin
  Result:=FContentType >= SSL3_RT_HEADER;
end;

function TTaurusTLSSslMessage.GetMsgDescription: string;
var
  LAlertLevel: Byte;
  LAlertDesc: Byte;
  LLevelStr: string;
  LDescStr: string;
begin
  Result:='';

  if (FContentType = SSL3_RT_ALERT) and Assigned(FBuf) and (FLen >= 2) then
  begin
    LAlertLevel:=PByte(FBuf)^;
    LAlertDesc:=PByte(NativeUInt(FBuf) + 1)^;

    // 1. Resolve Alert Level using standard constants
    case LAlertLevel of
      SSL3_AL_WARNING: LLevelStr:='Warning';
      SSL3_AL_FATAL:   LLevelStr:='Fatal';
    else
      LLevelStr:=Format('Unknown Level (%d)', [LAlertLevel]);
    end;

    // 2. Resolve Alert Description natively from OpenSSL
    LDescStr:=AnsiStringToString(SSL_alert_desc_string_long(LAlertDesc));

    Result:=Format('Alert [Level: %s, Desc: %d (%s)]',
      [LLevelStr, LAlertDesc, LDescStr]);
  end
  else if (FContentType = SSL3_RT_INNER_CONTENT_TYPE) and (FLen > 0) and Assigned(FBuf) then
  begin
    // TLS 1.3 Decrypted Inner Content Type indicator
    Result:=Format('Decrypted Inner Type: %d', [PByte(FBuf)^]);
  end
  else if (FContentType = DTLS1_RT_HEARTBEAT) and (FLen > 0) and Assigned(FBuf) then
  begin
    // Heartbeat Protocol frame type (RFC 6520)
    case PByte(FBuf)^ of
      TLS1_HB_REQUEST:  Result:='Heartbeat Request';
      TLS1_HB_RESPONSE: Result:='Heartbeat Response';
    else
      Result:='Heartbeat Unknown';
    end;
  end;
end;

function TTaurusTLSSslMessage.GetVersion: TTaurusTLS2SslVersion;
begin
  Result.AsInt:=FVersion;  // PALOFF 'Function result not set'
end;

function TTaurusTLSSslMessage.ToBytes: TIdBytes;
begin
  if Assigned(FBuf) and (FLen > 0) then
  begin
    SetLength(Result, FLen);
    Move(FBuf^, Result[0], FLen);
  end
  else
    Result:=[];
end;

{ TTaurusTLSAlpnResultHelper }

constructor TTaurusTLSAlpnResultHelper.Create(AValue: TIdC_INT);
begin
  AsInt:=AValue;
end;

function TTaurusTLSAlpnResultHelper.GetAsInt: TIdC_INT;
begin
  Result:=Ord(Self);
end;

procedure TTaurusTLSAlpnResultHelper.SetAsInt(AValue: TIdC_INT);
begin
  { TODO : Make a ResourceString for Exception call }
  if not (AValue in [Ord(Low(TTaurusTLSAlpnResult))..Ord(High(TTaurusTLSAlpnResult))]) then
    ETaurusTLSAlpnResultError.RaiseWithMessageFmt(
      { TODO : To make ResourceString }
      'Invalid ALPN result value: %d.', [AValue]);
  Self:=TTaurusTLSAlpnResult(AValue);
end;

{ TTaurusTLSAlpnSelector }
// The conditional compilation option below is not supported on all Delphi versions
//{$IFOPT POINTERMATH OFF}
//  {$DEFINE ENABLE_POINTERMATH}
//  {$POINTERMATH ON}
//{$ENDIF}

// So we have to replace them with the simple defines
{$DEFINE ENABLE_POINTERMATH}
{$POINTERMATH ON}
constructor TTaurusTLSAlpnSelector.Create(AInProtos: PIdC_UINT8; AInLen: TIdC_UINT);
var
  lPair: TAlpnPair;
  lPos: PIdC_UINT8;
  lLen: TIdC_UINT8;
  lCount: TIdC_INT;

begin
  FOutProto:=nil;
  FOutLen:=0;
  FInProtos:=AInProtos;
  FInLen:=AInLen;
  FResultValue:=alpnFatalAlert;

  SetLength(FPairs, 0);
  if not (Assigned(AInProtos) and (AInLen > 0)) then
    Exit;

  SetLength(FPairs, AInLen); // making largest possible array, then shrink it.
  lPos:=AInProtos;
  lCount:=0;
  repeat
    lLen:=PIdC_UINT8(lPos)^;
    if lLen = 0 then
      ETaurusTLSAlpnResultError.RaiseWithMessage(
        { TODO : To make ResourceString }
        'ALPN Input list corrupted. Unexpected Zero Length element found.');

    Inc(lPos);
    lPair.FOffset:=lPos;
    if ((lPos-AInProtos)+lLen) > NativeInt(AInLen) then // Boundary check
      ETaurusTLSAlpnResultError.RaiseWithMessage(
        { TODO : To make ResourceString }
        'ALPN Input list corrupted. Element length is out input bounds.');

    SetString(lPair.FValue, PIdAnsiChar(lPos), lLen); // PALOFF PIdC_UINT8 cast to PIdAnsiChar
    FPairs[lCount]:=lPair;

    Inc(lCount);
    Inc(lPos, lLen);
  until (lPos-AInProtos) >= NativeInt(AInLen);

  SetLength(FPairs, lCount);
  FResultValue:=alpnNoAck;
end;
{$IFDEF ENABLE_POINTERMATH}
  {$UNDEF ENABLE_POINTERMATH}
  {$POINTERMATH OFF}
{$ENDIF}

procedure TTaurusTLSAlpnSelector.Abort;
begin
  FResultValue:=alpnNoAck;
end;

procedure TTaurusTLSAlpnSelector.Error(AValue: TTaurusTLSAlpnResult);
begin
  FResultValue:=AValue;
end;

function TTaurusTLSAlpnSelector.GetCount: TIdC_INT;
begin
  Result:=Length(FPairs);
end;

function TTaurusTLSAlpnSelector.GetValues(AItem: TIdC_INT): string;
begin
  Result:=FPairs[AItem].FValue;
end;

procedure TTaurusTLSAlpnSelector.Select(AItem: TIdC_INT);
var
  lPair: TAlpnPair;

begin
  if (AItem < 0) or (AItem > (Count-1)) then
    { TODO : To make ResourceString }
    raise ERangeError.CreateFmt('ALPN selection index out of range: %d.', [AItem]);

  lPair:=FPairs[AItem];
  FOutProto:=lPair.FOffset;
  FOutLen:=Length(lPair.FValue);
  FResultValue:=alpnSuccess;
end;

{ TaurusTLSSslSocketCtxFlagsHelper }

function TaurusTLSSslSocketCtxFlagsHelper.GetFlag(
  const AFlag: TaurusTLSSslSocketCtxFlag): boolean;
begin
  Result:=AFlag in Self;
end;

{ TTaurusTLSSslSocketCtxBuilder }

constructor TTaurusTLSSslSocketCtxBuilder.Create(ATLSMeth: PSSL_METHOD);
begin
  inherited Create;
  SetDirty;
  FTLSMeth:=ATLSMeth;
  FX509VerifyParam:=TTaurusTLSMetaX509VerifyParam.Create(Self);
end;

destructor TTaurusTLSSslSocketCtxBuilder.Destroy;
begin
  try
    Lock;
    FSocketCtx:=nil;
  finally
    Unlock;
    FreeAndNil(FLock);
  end;
  inherited;
end;

procedure TTaurusTLSSslSocketCtxBuilder.Lock;
begin
  FLock.Enter;
end;

procedure TTaurusTLSSslSocketCtxBuilder.Unlock;
begin
  FLock.Leave;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetDirty;
begin
  FDirty:=True;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetFlags(
  const AValue: TaurusTLSSslSocketCtxFlags);
begin
  if FFlags = AValue then
    Exit;

  Lock;
  try
    // Check it again it can be changed by other thread
    // between previous check and actual lock accurision
    if FFlags = AValue then
      Exit;
    FFlags:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

function TTaurusTLSSslSocketCtxBuilder.IncludeFlags(
  const AValue: TaurusTLSSslSocketCtxFlags): TaurusTLSSslSocketCtxFlags;
begin
  if (FFlags * AValue) = AValue then
    Exit(AValue);

  Lock;
  try
    // Check it again it can be changed by other thread
    // between previous check and actual lock accurision
    if (FFlags * AValue) = AValue then
      Exit(FFlags);
    Result:=FFlags+AValue;
    FFlags:=Result;
    SetDirty;
  finally
    Unlock;
  end;
end;

function TTaurusTLSSslSocketCtxBuilder.ExcludeFlags(
  const AValue: TaurusTLSSslSocketCtxFlags): TaurusTLSSslSocketCtxFlags;
begin
  if (FFlags * AValue) = [] then
    Exit(AValue);

  Lock;
  try
    // Check it again it can be changed by other thread
    // between previous check and actual lock accurision
    if (FFlags * AValue) = [] then
      Exit(FFlags);
    Result:=FFlags-AValue;
    FFlags:=Result;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetVerifyModes(
  const AValue: TTaurusTLSVerifyModes);
begin
  if FVerifyModes = AValue then
    Exit;

  Lock;
  try
    // Check it again it can be changed by other thread
    // between previous check and actual lock accurision
    if FVerifyModes = AValue then
      Exit;
    FVerifyModes:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetSSLContextOptions(
  const AValue: TTaurusTLSSslOptionFlags);
begin
  if FSSLContextOptions = AValue then
    Exit;

  Lock;
  try
    // Check it again it can be changed by other thread
    // between previous check and actual lock accurision
    if FSSLContextOptions = AValue then
      Exit;
    FSSLContextOptions:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetTrustStores(
  AValue: TTaurusTLSTrustStores);
begin
  if FTrustStores = AValue then
    Exit;

  Lock;
  try
    // Check it again it can be changed by other thread
    // between previous check and actual lock accurision
    if FTrustStores = AValue then
      Exit;
    FTrustStores:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetMinTLSVersion(
  const AValue: TTaurusTLS2TlsVersion);
begin
  if FMinTLSVersion = AValue then
    Exit;

  Lock;
  try
    // Check it again it can be changed by other thread
    // between previous check and actual lock accurision
    if FMinTLSVersion = AValue then
      Exit;
    FMinTLSVersion:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetMaxTLSVersion(
  const AValue: TTaurusTLS2TlsVersion);
begin
  if FMaxTLSVersion = AValue then
    Exit;

  Lock;
  try
    // Check it again it can be changed by other thread
    // between previous check and actual lock accurision
    if FMaxTLSVersion = AValue then
      Exit;
    FMaxTLSVersion:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetCipherList(const AValue: string);
begin
  if FCipherList = AValue then
    Exit;

  Lock;
  try
    // Check it again it can be changed by other thread
    // between previous check and actual lock accurision
    if FCipherList = AValue then
      Exit;
    FCipherList:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetCipherSuites(const AValue: string);
begin
  if FCipherSuites = AValue then
    Exit;

  Lock;
  try
    // Check it again it can be changed by other thread
    // between previous check and actual lock accurision
    if FCipherSuites = AValue then
      Exit;
    FCipherSuites:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetKeXGroups(const AValue: string);
begin
  if FKeyExchangeGroups = AValue then
    Exit;

  Lock;
  try
    // Check it again it can be changed by other thread
    // between previous check and actual lock accurision
    if FKeyExchangeGroups = AValue then
      Exit;
    FKeyExchangeGroups:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetSigAlgorithms(const AValue: string);
begin
  if FSigAlgorithms = AValue then
    Exit;

  Lock;
  try
    // Check it again it can be changed by other thread
    // between previous check and actual lock accurision
    if FSigAlgorithms = AValue then
      Exit;
    FSigAlgorithms:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetVerifyHostName(const AValue: boolean);
begin
  if AValue then
    IncludeFlags([slfVerifyHostname])  //PALOFF "Functions called as procedures"
  else
    ExcludeFlags([slfVerifyHostname]); //PALOFF "Functions called as procedures"
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetUniDirectShutdown(
  const AValue: boolean);
begin
  Lock;
  try
    if AValue then
    begin
      Include(FFlags, slfUniDirectShutdown);
      Exclude(FFlags, slfQuietShutdown);
    end
    else
      Exclude(FFlags, slfUniDirectShutdown);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetQuietShutdown(const AValue: boolean);
begin
  Lock;
  try
    if AValue then
    begin
      Include(FFlags, slfQuietShutdown);
      Exclude(FFlags, slfUniDirectShutdown);
    end
    else
      Exclude(FFlags, slfQuietShutdown);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetReadAheadBuffering(
  const AValue: boolean);
begin
  if AValue then
    IncludeFlags([slfReadAheadBuffering])  //PALOFF "Functions called as procedures"
  else
    ExcludeFlags([slfReadAheadBuffering]); //PALOFF "Functions called as procedures"
end;

function TTaurusTLSSslSocketCtxBuilder.GetFlag(
  const AFlag: TaurusTLSSslSocketCtxFlag): boolean;
begin
  Lock;
  try
    Result:=FFlags.GetFlag(AFlag);
  finally
    Unlock;
  end;
end;

function TTaurusTLSSslSocketCtxBuilder.GetQuietShutdown: boolean;
begin
  Result:=GetFlag(slfQuietShutdown);
end;

function TTaurusTLSSslSocketCtxBuilder.GetUniDirectShutdown: boolean;
begin
  Result:=GetFlag(slfUniDirectShutdown);
end;

function TTaurusTLSSslSocketCtxBuilder.GetVerifyHostName: boolean;
begin
  Result:=GetFlag(slfVerifyHostname);
end;

function TTaurusTLSSslSocketCtxBuilder.GetReadAheadBuffering: boolean;
begin
  Result:=GetFlag(slfReadAheadBuffering);
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetOnKeyLog(
  const AValue: TTaurusTLSOnKeyLog);
begin
  Lock;
  try
    if (TMethod(FOnKeyLog).Code = TMethod(AValue).Code) and
      (TMethod(FOnKeyLog).Data = TMethod(AValue).Data) then
      Exit;
    FOnKeyLog:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetOnMessage(
  const AValue: TTaurusTLSOnSSLMessageCallback);
begin
  Lock;
  try
    if (TMethod(FOnMessage).Code = TMethod(AValue).Code) and
      (TMethod(FOnMessage).Data = TMethod(AValue).Data) then
      Exit;
    FOnMessage:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetOnPeerCertError(
  const AValue: TTaurusTLSOnPeerCertError);
begin
  Lock;
  try
    if (TMethod(FOnPeerCertError).Code = TMethod(AValue).Code) and
      (TMethod(FOnPeerCertError).Data = TMethod(AValue).Data) then
      Exit;
    FOnPeerCertError:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetOnSecurityCheck(
  const AValue: TTaurusTLSOnSecurityCheck);
begin
  Lock;
  try
    if (TMethod(FOnSecurityCheck).Code = TMethod(AValue).Code) and
      (TMethod(FOnSecurityCheck).Data = TMethod(AValue).Data) then
      Exit;
    FOnSecurityCheck:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetOnStateChange(
  const AValue: TTaurusTLSOnStateChange);
begin
  Lock;
  try
    if (TMethod(FOnStateChange).Code = TMethod(AValue).Code) and
      (TMethod(FOnStateChange).Data = TMethod(AValue).Data) then
      Exit;
    FOnStateChange:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetOnStatusInfo(
  const AValue: TTaurusTLSOnSSLStatusInfo);
begin
  Lock;
  try
    if (TMethod(FOnStatusInfo).Code = TMethod(AValue).Code) and
      (TMethod(FOnStatusInfo).Data = TMethod(AValue).Data) then
      Exit;
    FOnStatusInfo:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetOnVerifyCertificate(
  const AValue: TTaurusTLSOnVerifyCallback);
begin
  Lock;
  try
    if (TMethod(FOnVerifyCertificate).Code = TMethod(AValue).Code) and
      (TMethod(FOnVerifyCertificate).Data = TMethod(AValue).Data) then
      Exit;
    FOnVerifyCertificate:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.CheckRequirements;
begin
// Do nothing. Descendant may implement own requirement check.
end; // PALOFF 'Empty begin/end-blocks'

function TTaurusTLSSslSocketCtxBuilder.DoBuild(ASender: TObject;
  ASocketCtx: TTaurusTLSSslSocketCtx): TTaurusTLSSslSocketCtx;
var
  lVerifyParam: TTaurusTLSX509VerifyParam; // PALOFF 'Created and freed objects'
  lTrustStore: TTaurusTLS_X509Store; // PALOFF 'Created and freed objects'

begin
  Assert(Assigned(ASender), '''ASender'' parameter must not be ''nil'' value.'); // Do not localize
  Assert(Assigned(ASocketCtx),
    '''ASocketCtx'' parameter must not be ''nil'' value.'); // Do not localize

  Result:=ASocketCtx;
  lVerifyParam:=nil;
  lTrustStore:=nil;
  try
    lVerifyParam:=FX509VerifyParam.BuildParam;
    lTrustStore:=FTrustStores.BuildStore;
    ASocketCtx
    // Set Context Parameters
      .SetFlags(FFlags)
      .SetMinTLSVersion(FMinTLSVersion)
      .SetMaxTLSVersion(FMaxTLSVersion)
      .SetCipherList(FCipherList)
      .SetCipherSuites(FCipherSuites)
      .SetKeXGroups(FKeyExchangeGroups)
      .SetSigAlgorithms(FSigAlgorithms)
      .SetVerifyModes(FVerifyModes)
      .SetMaxSendFragment(FMaxSendFragment)
      .SetSSLCtxOptions(FSSLContextOptions)
      .SetVerifyParam(lVerifyParam)
      .SetTrustStore(lTrustStore)
    // Set Context Events
      .SetOnStateChange(FOnStateChange)
      .SetOnPeerCertError(FOnPeerCertError)
      .SetOnVerifyCertificate(FOnVerifyCertificate)
      .SetOnSecurityCheck(FOnSecurityCheck)
      .SetOnStatusInfo(FOnStatusInfo)
      .SetOnMessage(FOnMessage)
      .SetOnKeyLog(FOnKeyLog); // PALOFF 'Functions called as procedures'
  finally
    lTrustStore.Free;
    lVerifyParam.Free;
  end;
end;

function TTaurusTLSSslSocketCtxBuilder.Build(ASender: TObject): ITaurusTLSSslSocketCtx;
var
  lSocketCtx: TTaurusTLSSslSocketCtx; // PALOFF 'Created and freed objects'

begin
  Result:=nil;
  Lock;
  try
    if (not IsDirty) and Assigned(FSocketCtx) then
      Exit(FSocketCtx);

    CheckRequirements;
    lSocketCtx:=DoNewSocketCtx(ASender);
    DoBuild(ASender, lSocketCtx);

      // The final SocketCTX configuration lock.
    lSocketCtx.FreezeCtx; //PALOFF "Functions called as procedures"
    Result:=lSocketCtx as ITaurusTLSSslSocketCtx; // PALOFF 'Mixing interface variables and objects'
    FSocketCtx:=Result;
  finally
    Unlock;
  end;
end;

{ TTaurusTLSSslClientSocketCtxBuilder }

constructor TTaurusTLSSslClientSocketCtxBuilder.Create;
begin
  Create(TLS_client_method());
end;

constructor TTaurusTLSSslClientSocketCtxBuilder.Create(ATLSMeth: PSSL_METHOD);
begin
  inherited Create(ATLSMeth);
  Include(FFlags, slfClient); // Default to client context role [1.2]
  FSNIMode := csmStandardSNI;
end;

procedure TTaurusTLSSslClientSocketCtxBuilder.SetHostName(const AValue: string);
begin
  if FHostName = AValue then
    Exit;

  Lock;
  try
    if FHostName = AValue then
      Exit;
    FHostName := AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslClientSocketCtxBuilder.SetDefaultSNI(const AValue: string);
begin
  if FDefaultSNI = AValue then
    Exit;

  Lock;
  try
    if FDefaultSNI = AValue then
      Exit;
    FDefaultSNI := AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslClientSocketCtxBuilder.SetSNIMode(
  const AValue: TTaurusTLSSslClientSNIMode);
begin
  if FSNIMode = AValue then
    Exit;

  Lock;
  try
    if FSNIMode = AValue then
      Exit;
    FSNIMode := AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslClientSocketCtxBuilder.SetECHOuterSNI(const AValue: string);
begin
  if FECHOuterSNI = AValue then
    Exit;

  Lock;
  try
    if FECHOuterSNI = AValue then
      Exit;
    FECHOuterSNI := AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslClientSocketCtxBuilder.SetECHConfigList(const AValue: string);
begin
  if FECHConfigList = AValue then
    Exit;

  Lock;
  try
    if FECHConfigList = AValue then
      Exit;
    FECHConfigList := AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslClientSocketCtxBuilder.SetOnClientCert(
  const AValue: TTaurusTLSOnClientCertCallback);
begin
  Lock;
  try
    if (TMethod(FOnClientCert).Code = TMethod(AValue).Code) and
       (TMethod(FOnClientCert).Data = TMethod(AValue).Data) then
      Exit;
    FOnClientCert := AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslClientSocketCtxBuilder.SetOnECHLog(
  const AValue: TTaurusTLSOnECHLog);
begin
  Lock;
  try
    if (TMethod(FOnECHLog).Code = TMethod(AValue).Code) and
       (TMethod(FOnECHLog).Data = TMethod(AValue).Data) then
      Exit;
    FOnECHLog := AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslClientSocketCtxBuilder.SetOnECHConfigRetry(
  const AValue: TTaurusTLSOnCliECHConfigRetry);
begin
  Lock;
  try
    if (TMethod(FOnECHConfigRetry).Code = TMethod(AValue).Code) and
       (TMethod(FOnECHConfigRetry).Data = TMethod(AValue).Data) then
      Exit;
    FOnECHConfigRetry := AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslClientSocketCtxBuilder.CheckRequirements;
begin
  inherited CheckRequirements;

  // 1. Strict ECH Validation: Cannot force ECH if OpenSSL library lacks ECH support
  if (FSNIMode in [csmECH, csmECHNoOuter]) and (not IsECHSupported) then
    { TODO : To make ResourceString }
    raise EECHNotSupported.Create('ECH mode is active, but the loaded OpenSSL library does not support ECH.');

  // 2. Strict ECH Configuration Guard: Cannot force ECH without a key list
  if (FSNIMode in [csmECH, csmECHNoOuter]) and (FECHConfigList = '') then
    { TODO : To make ResourceString }
    raise ETaurusTLSSslSocketCtxBuildError.Create('Real ECH mode requires an ECHConfigList.');
end;

function TTaurusTLSSslClientSocketCtxBuilder.DoNewSocketCtx(
  ASender: TObject): TTaurusTLSSslSocketCtx;
begin
  Result := TTaurusTLSSslClientSocketCtx.Create(ASender, TLSMeth);
end;

function TTaurusTLSSslClientSocketCtxBuilder.DoBuild(ASender: TObject;
  ASocketCtx: TTaurusTLSSslSocketCtx): TTaurusTLSSslSocketCtx;
begin
  // 1. Apply base parameters (Ciphers, trust stores, verify modes, base events)
  Result:=inherited DoBuild(ASender, ASocketCtx);

  // 2. Transfer client-specific SNI, ECH, and mTLS properties fluently
  (Result as TTaurusTLSSslClientSocketCtx)
    .SetHostName(FHostName)
    .SetDefaultSNI(FDefaultSNI)
    .SetSNIMode(FSNIMode)
    .SetECHOuterSNI(FECHOuterSNI)
    .SetECHConfigList(FECHConfigList)
    .SetOnClientCert(FOnClientCert)
    .SetOnECHLog(FOnECHLog)
    .SetOnECHConfigRetry(FOnECHConfigRetry);
end;

{ TTaurusTLSSslSocketCtx }

constructor TTaurusTLSSslSocketCtx.Create(ASender: TObject; ATLSMeth: PSSL_METHOD);
begin
  FSender:=ASender;
  FSSLCtx:=SSL_CTX_new(ATLSMeth);
  SetVerifyModes(cVerifyModesDef);   // PALOFF 'Functions called as procedures'
end;

destructor TTaurusTLSSslSocketCtx.Destroy;
begin
  ReleaseCtx;
  SSL_CTX_free(FSSLCtx);
  inherited;
end;

function TTaurusTLSSslSocketCtx.FreezeCtx: TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  InitCtx;
  DoFreeze;
end;

procedure TTaurusTLSSslSocketCtx.DoFreeze;
begin
  Include(FFlags, slfFrozen);
end;

class procedure TTaurusTLSSslSocketCtx.CbCtxKeyLog(const ASSL: PSSL;
  const ALine: PIdAnsiChar);
var
  lInstance: TTaurusTLSSslSocket;
  lConfig: TTaurusTLSSslSocketCtx;
  lErr: integer;

begin
  if not Assigned(ASSL) then // this shouldn't happen ever
    Exit;
  try
    lErr:=GStack.WSGetLastError;
    try
      lInstance:=TTaurusTLSSslSocket.GetInstanceFromSSL(ASSL);
      if not Assigned(lInstance) then
        Exit;

      lConfig:=lInstance.Ctx;
      if Assigned(lConfig) then
        lConfig.DoOnKeyLog(lInstance, ALine);
    finally
      GStack.WSSetLastError(lErr);
    end;
  except //PALOFF "Empty except-block"
    // We must not raise the exception to the OpenSSL stack
  end;
end;

procedure TTaurusTLSSslSocketCtx.CheckFrozen;
begin
  if FLags.IsFrozen then
    ETaurusTLSSslSocketCtxError.RaiseWithMessage(
      { TODO : To make ResourceString }
      'TTaurusTLSSslSocketCtx instance is frozen and cannot be modified.');
end;

procedure TTaurusTLSSslSocketCtx.DoOnKeyLog(ASocket: TTaurusTLSSslSocket;
  ALine: PIdAnsiChar);
begin
  if Assigned(FOnKeyLog) then
    FOnKeyLog(FSender, ASocket, ALine);
end;

procedure TTaurusTLSSslSocketCtx.DoOnMessage(ASocket: TTaurusTLSSslSocket;
  AWriteP, AVersion, AContentType: TIdC_INT; const ABuf: Pointer; ALen: TIdC_SIZET);
var
  lMsg: TTaurusTLSSslMessage; // PALOFF 'Created and freed objects'

begin
  if not Assigned(FOnMessage) then
    Exit;
  lMsg:=TTaurusTLSSslMessage.Create(AWriteP, AVersion, AContentType, ABuf, ALen);
  FOnMessage(FSender, ASocket, lMsg);
end;

procedure TTaurusTLSSslSocketCtx.DoOnPeerCertError(ASocket: TTaurusTLSSslSocket;
  ACertificate: TTaurusTLSX509; const AError: TTaurusTLSX509Error;
  var ASuccess: boolean);
begin
  if Assigned(FOnPeerCertError) and Assigned(ASocket) then
    FOnPeerCertError(FSender, ASocket, ACertificate, AError, ASuccess);
end;

procedure TTaurusTLSSslSocketCtx.DoOnStateChange(ASocket: TTaurusTLSSslSocket;
  AOldState, ANewState: TTaurusTLSSslSocketState);
begin
  if Assigned(FOnStateChange) then
    FOnStateChange(FSender, ASocket, AOldState, ANewState);
end;

procedure TTaurusTLSSslSocketCtx.DoOnStatusInfo(ASocket: TTaurusTLSSslSocket;
  AWhere, ARet: TIdC_INT);
var
  lState: TTaurusTLSSslState;

begin
  if not Assigned(FOnStatusInfo) then
    Exit;

  lState:=TTaurusTLSSslState.Create(AWhere, ARet, ASocket.SSL);
  FOnStatusInfo(FSender, ASocket, lState);
end;

procedure TTaurusTLSSslSocketCtx.DoOnVerifyCertificate(ASocket: TTaurusTLSSslSocket;
  ACtx: PX509_STORE_CTX; var ASuccess, AContinue: boolean);
var
  lValidator: TTaurusTLSX509CertValidator; // PALOFF 'Created and freed objects'

begin
  if not (Assigned(FOnVerifyCertificate) and Assigned(ACtx)) then
    Exit;

  lValidator:=TTaurusTLSX509CertValidator.Create(ACtx);
  try
    FOnVerifyCertificate(FSender, ASocket, lValidator, ASuccess, AContinue);
  finally
    lValidator.Free;
  end;
end;

procedure TTaurusTLSSslSocketCtx.DoOnSecurityCheck(ASocket: TTaurusTLSSslSocket;
  op, bits, nid: TIdC_INT; other: pointer; var AAccept: boolean);
var
  lState: TTaurusTLSSecurityCheckState;

begin
  if not Assigned(FOnSecurityCheck) then
    Exit;
  lState:=TTaurusTLSSecurityCheckState.Create(op,bits,nid, other);
  try
    FOnSecurityCheck(FSender, ASocket, lState, AAccept);
  finally
    lState.Destroy;
  end;
end;

function TTaurusTLSSslSocketCtx.GetHasOnStatusInfo: boolean;
begin
  Result:=Assigned(FOnStatusInfo);
end;

// ITaurusTLSSslSocketCtx
function TTaurusTLSSslSocketCtx.GetCtx: TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
end;

function TTaurusTLSSslSocketCtx.GetFlag(
  const AFlag: TaurusTLSSslSocketCtxFlag): boolean;
begin
  Result:=FFlags.GetFlag(AFlag);
end;

function TTaurusTLSSslSocketCtx.GetHasOnKeyLog: boolean;
begin
  Result:=Assigned(FOnKeyLog);
end;

function TTaurusTLSSslSocketCtx.GetHasOnMessage: boolean;
begin
  Result:=Assigned(FOnMessage);
end;

function TTaurusTLSSslSocketCtx.GetHasOnSecurityCheck: boolean;
begin
  Result:=Assigned(FOnSecurityCheck);
end;

function TTaurusTLSSslSocketCtx.GetHasOnVerifyCertificate: boolean;
begin
  Result:=Assigned(FOnVerifyCertificate);
end;

class function TTaurusTLSSslSocketCtx.GetInstanceFromCtx(
  ACtx: PSSL_CTX): TTaurusTLSSslSocketCtx;
var
  lResult: pointer;

begin
  Result:=nil;
  lResult:=SSL_CTX_get_app_data(ACtx);
  if Assigned(lResult) and (TObject(lResult) is TTaurusTLSSslSocketCtx) then // PALOFF 'Pointer cast to TObject'
    Result:=TTaurusTLSSslSocketCtx(lResult)
  else
    ETaurusTLSSslSocketDataBindingError.RaiseWithMessageFmt(
      { TODO : To make ResourceString }
      'SSL_CTX object %p is not bound to a valid TTaurusTLSSslSocketCtx instance.',
      [ACtx]);
end;

procedure TTaurusTLSSslSocketCtx.InitCtx;
var
  lBool: TIdC_INT;
  lErr: TIdC_INT;

begin
  // Disabling SSL_MODE_AUTO_RETRY
  SSL_CTX_clear_mode(SSLCtx, SSL_MODE_AUTO_RETRY);

  // Attach Self to the SSL_CTX
  lErr:=SSL_CTX_set_app_data(SSLCtx, Self);
  if lErr  <= 0 then
    { TODO : To make ResourceString }
    ETaurusTLSSslSocketDataBindingError.RaiseExceptionCode(lErr,
      'Unable to link TTaurusTLSSslSocketCtx instance with SSL_CTX object');

  if Flags.QuietShutdown then
    SSL_CTX_set_quiet_shutdown(SSLCtx, 1);

  if Flags.ReadAheadBuffering then
    lBool:=1
  else
    lBool:=0;
  SSL_CTX_set_read_ahead(SSLCtx, lBool);

  if HasOnKeylog then
    SSL_CTX_set_keylog_callback(SSLCtx, CbCtxKeyLog);
end;

procedure TTaurusTLSSslSocketCtx.ReleaseCtx;
begin
  try
    SSL_CTX_set_keylog_callback(SSLCtx, nil);
  finally
    SSL_CTX_set_app_data(SSLCtx, nil);
  end;
end;

class function TTaurusTLSSslSocketCtx.NormalizeHostName(
  const AValue: RawByteString): RawByteString;
begin
  { TODO : Implement lower-case IDNA conversion. }
{$IFDEF STRING_IS_UNICODE}
  Result:=System.AnsiStrings.LowerCase(AValue);
{$ELSE}
  Result:=LowerCase(AValue);
{$ENDIF}
end;

function TTaurusTLSSslSocketCtx.SetFlags(
  const AValue: TaurusTLSSslSocketCtxFlags): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  CheckFrozen;
  FFlags:=AValue;
end;

function TTaurusTLSSslSocketCtx.SetVerifyModes(
  const AValue: TTaurusTLSVerifyModes): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  CheckFrozen;
  FCertVerifyFlags.Flags:=AValue;
end;

function TTaurusTLSSslSocketCtx.SetSSLCtxOptions(
  const AValue: TTaurusTLSSslOptionFlags): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  if AValue = cDefaultCtxOptions then
    Exit;

  CheckFrozen;
  // Design time defaults: [sslOpNoCompression, sslOpEnableMiddleboxCompat]
  SSL_CTX_set_options(FSSLCtx, AValue.AsInt);
end;

function TTaurusTLSSslSocketCtx.SetCipherList(const AValue: string): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  if AValue = '' then
    Exit; // Use defaults

  CheckFrozen;
  if SSL_CTX_set_cipher_list(FSSLCtx, PIdAnsiChar(RawByteString(AValue))) <= 0 then  // PALOFF Possible bad typecast
    ETaurusTLSSslSocketCtxError.RaiseWithMessageFmt(
    { TODO : To make ResourceString }
      'Error setting cipher list ''%s'' to the SSL Context.', [AValue]);
end;

function TTaurusTLSSslSocketCtx.SetCipherSuites(const AValue: string): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  if AValue = '' then
    Exit; // Use defaults

  CheckFrozen;
  if SSL_CTX_set_ciphersuites(FSSLCtx, PIdAnsiChar(RawByteString(AValue))) <= 0 then // PALOFF Possible bad typecast
    ETaurusTLSSslSocketCtxError.RaiseWithMessageFmt(
    { TODO : To make ResourceString }
      'Error setting cipher suites ''%s'' to the SSL Context.', [AValue]);
end;

function TTaurusTLSSslSocketCtx.SetKeXGroups(const AValue: string): TTaurusTLSSslSocketCtx;
begin
  // Default value is 'DEFAULT'
  // #define DEFAULT_GROUP_NAME "DEFAULT"

  Result:=Self;
  CheckFrozen;
  if SSL_CTX_set1_groups_list(FSSLCtx, PIdAnsiChar(RawByteString(AValue))) <= 0 then // PALOFF Possible bad typecast
    ETaurusTLSSslSocketCtxError.RaiseWithMessageFmt(
    { TODO : To make ResourceString }
      'Error setting key exchange groups ''%s'' to the SSL Context.', [AValue]);
end;

function TTaurusTLSSslSocketCtx.SetSigAlgorithms(const AValue: string): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  if AValue = '' then
    Exit; // Use defaults

  CheckFrozen;
  if SSL_CTX_set1_sigalgs_list(FSSLCtx, PIdAnsiChar(RawByteString(AValue))) <= 0 then // PALOFF Possible bad typecast
    ETaurusTLSSslSocketCtxError.RaiseWithMessageFmt(
    { TODO : To make ResourceString }
      'Error setting signature algorithms ''%s'' to the SSL Context.', [AValue]);
end;

function TTaurusTLSSslSocketCtx.SetMinTLSVersion(
  const AValue: TTaurusTLS2TlsVersion): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  if AValue = svSSL_Default then
    Exit;

  CheckFrozen;
  if SSL_CTX_set_min_proto_version(FSSLCtx, AValue.AsInt) <= 0 then
    ETaurusTLSSslSocketCtxError.RaiseWithMessage(RSOSSLMinProtocolError);
end;

function TTaurusTLSSslSocketCtx.SetMaxSendFragment(
  const AValue: TTaurusTLSSslMaxSendFragment): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  CheckFrozen;
  if SSL_CTX_set_max_send_fragment(FSSLCtx, AValue) <= 0 then
    ETaurusTLSSslSocketCtxError.RaiseWithMessageFmt(
      { TODO : To make ResourceString }
      'Error setting max send fragment size %d to the SSL Context.', [AValue]
    );
end;

function TTaurusTLSSslSocketCtx.SetMaxTLSVersion(
  const AValue: TTaurusTLS2TlsVersion): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  if AValue = svSSL_Default then
    Exit;

  CheckFrozen;
  if SSL_CTX_set_max_proto_version(FSSLCtx, AValue.AsInt) <= 0 then
    ETaurusTLSSslSocketCtxError.RaiseWithMessage(RSOSSLMaxProtocolError);
end;

function TTaurusTLSSslSocketCtx.SetVerifyParam(
  const AValue: TTaurusTLSCustomX509VerifyParam): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  CheckFrozen;
  if Assigned(AValue) then
    AValue.AttachToSSLCtx(FSSLCtx);
end;

function TTaurusTLSSslSocketCtx.SetTrustStore(const AValue: TTaurusTLS_X509Store): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  if not Assigned(AValue) then
    Exit;

  CheckFrozen;
  AValue.AttachToSSLCtx(FSSLCtx);
end;

function TTaurusTLSSslSocketCtx.SetOnKeyLog(
  const AValue: TTaurusTLSOnKeyLog): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  if (TMethod(FOnKeyLog).Code = TMethod(AValue).Code) and
     (TMethod(FOnKeyLog).Data = TMethod(AValue).Data) then
    Exit;

  CheckFrozen;
  FOnKeyLog:=AValue;
end;

function TTaurusTLSSslSocketCtx.SetOnMessage(
  const AValue: TTaurusTLSOnSSLMessageCallback): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  if (TMethod(FOnMessage).Code = TMethod(AValue).Code) and
     (TMethod(FOnMessage).Data = TMethod(AValue).Data) then
    Exit;

  CheckFrozen;
  FOnMessage:=AValue;
end;

function TTaurusTLSSslSocketCtx.SetOnPeerCertError(
  const AValue: TTaurusTLSOnPeerCertError): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  if (TMethod(FOnPeerCertError).Code =TMethod(AValue).Code) and
     (TMethod(FOnPeerCertError).Data =TMethod(AValue).Data) then
    Exit;

  CheckFrozen;
  FOnPeerCertError:=AValue;
end;

function TTaurusTLSSslSocketCtx.SetOnSecurityCheck(
  const AValue: TTaurusTLSOnSecurityCheck): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  if (TMethod(FOnSecurityCheck).Code = TMethod(AValue).Code) and
     (TMethod(FOnSecurityCheck).Data = TMethod(AValue).Data) then
    Exit;

  CheckFrozen;
  FOnSecurityCheck:=AValue;
end;

function TTaurusTLSSslSocketCtx.SetOnStateChange(
  const AValue: TTaurusTLSOnStateChange): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  if (TMethod(FOnStateChange).Code = TMethod(AValue).Code) and
     (TMethod(FOnStateChange).Data = TMethod(AValue).Data) then
    Exit;

  CheckFrozen;
  FOnStateChange:=AValue;
end;

function TTaurusTLSSslSocketCtx.SetOnStatusInfo(
  const AValue: TTaurusTLSOnSSLStatusInfo): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  if (TMethod(FOnStatusInfo).Code = TMethod(AValue).Code) and
     (TMethod(FOnStatusInfo).Data = TMethod(AValue).Data) then
    Exit;

  CheckFrozen;
  FOnStatusInfo:=AValue;
end;

function TTaurusTLSSslSocketCtx.SetOnVerifyCertificate(
  const AValue: TTaurusTLSOnVerifyCallback): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  if (TMethod(FOnVerifyCertificate).Code = TMethod(AValue).Code) and
     (TMethod(FOnVerifyCertificate).Data = TMethod(AValue).Data) then
    Exit;

  CheckFrozen;
  FOnVerifyCertificate:=AValue;
end;

{ TTaurusTLSSslClientSocketCtx }

class function TTaurusTLSSslClientSocketCtx.CbCliCert(ASSL: PSSL; var AX509: PX509;
  var APKey: PEVP_PKEY): TIdC_INT;
var
  lInstance: TTaurusTLSSslSocket;
  lContext: TTaurusTLSSslClientSocketCtx;
  lErr: integer;

begin
  Result:=0;
  if not Assigned(ASSL) then // this shouldn't happen ever
    Exit;
  try
    lErr:=GStack.WSGetLastError;
    try
      lInstance:=TTaurusTLSSslSocket.GetInstanceFromSSL(ASSL);
      if not Assigned(lInstance) then
        Exit;

      lContext:=lInstance.Ctx as TTaurusTLSSslClientSocketCtx;
      if Assigned(lContext) then
      begin
        lContext.DoOnClientCertCallback(lInstance, AX509, APKey);
        if Assigned(AX509) and Assigned(APKey) then
          Result:=1;
      end;

    finally
      GStack.WSSetLastError(lErr);
    end;
  except
    Result:=-1;
  end;
end;

class function TTaurusTLSSslClientSocketCtx.cbEchLog(ASSL: PSSL;
  const ALogStr: PAnsiChar): TIdC_UINT;
var
  lInstance: TTaurusTLSSslSocket;
  lContext: TTaurusTLSSslClientSocketCtx;
  lErr: integer;

begin
  Result:=1;
  if not Assigned(ASSL) then // this shouldn't happen ever
    Exit;

  try
    lErr:=GStack.WSGetLastError;
    try
      lInstance:=TTaurusTLSSslSocket.GetInstanceFromSSL(ASSL);
      if not Assigned(lInstance) then
        Exit;

      lContext:=lInstance.Ctx as TTaurusTLSSslClientSocketCtx;
      if Assigned(lContext) then
        lContext.DoOnECHLogCallback(lInstance, ALogStr);

    finally
      GStack.WSSetLastError(lErr);
    end;
  except
    Result:=0;
  end;
end;

procedure TTaurusTLSSslClientSocketCtx.InitCtx;
begin
  inherited;
  if HasOnClientCert then
    SSL_CTX_set_client_cert_cb(SSLCtx, CbCliCert);

  if HasOnECHLog then
    SSL_CTX_ech_set_callback(SSLCtx, cbEchLog);
end;

procedure TTaurusTLSSslClientSocketCtx.ReleaseCtx;
begin
  try
    SSL_CTX_set_client_cert_cb(SSLCtx, nil);
  finally
    inherited;
  end;
end;

procedure TTaurusTLSSslClientSocketCtx.DoOnClientCertCallback(
  ASocket: TTaurusTLSSslSocket; var ACert: PX509; APKey: PEVP_PKEY);
begin
  if Assigned(FOnClientCert) then
    FOnClientCert(Sender, ASocket, ACert, APKey);
end;

procedure TTaurusTLSSslClientSocketCtx.DoOnECHConfigRetry(
  ASocket: TTaurusTLSSslSocket; const AECHRetryConfig: string);
begin
  if Assigned(FOnECHConfigRetry) then
    FOnECHConfigRetry(Sender, ASocket, AECHRetryConfig);
end;

procedure TTaurusTLSSslClientSocketCtx.DoOnECHLogCallback(ASocket: TTaurusTLSSslSocket;
  const ALogStr: PAnsiChar);
begin
  if Assigned(FOnECHLog) then
    FOnECHLog(Sender, ASocket, ALogStr);
end;

procedure TTaurusTLSSslClientSocketCtx.BuildIdentity;
begin
  if FIdentityBuilt then
    Exit;

  FIdentity:='';
  FIdentityIP:=False;

  // 1. Guard against completely uninitialized configurations
  if (FHostname = '') and (FDefaultSNI = '') and (FECHOuterSNI = '') then
  begin
    FIdentityBuilt:=True;
    Exit;
  end;

  // 2. DISCOVERY MODE:
  // - If explicit public decoy is set, verify against that decoy
  // - If NO decoy is set, Identity is empty (skip hostname check for this probe hop)
  if FSNIMode = csmECHGreaseDiscovery then
  begin
    FIdentity:=FECHOuterSNI; // If FECHOuterSNI = '', FIdentity remains ''
  end
  else
  begin
    if FDefaultSNI <> '' then
      FIdentity:=FDefaultSNI
    else
      FIdentity:=FHostname;
  end;

  // 3. Cryptographically check if the resolved identity is an IP address
  FIdentityIP:=(FIdentity <> '') and IsValidIP(string(FIdentity));
  FIdentityBuilt:=True;
end;

procedure TTaurusTLSSslClientSocketCtx.ResetIdentity;
begin
  FIdentityBuilt:=False;
end;

function TTaurusTLSSslClientSocketCtx.GetDefaultSNI: string;
begin
  Result:=string(FDefaultSNI);
end;

function TTaurusTLSSslClientSocketCtx.GetECHNoOuterVal: TIdC_INT;
begin
  if FSNIMode = csmECHNoOuter then
    Result:=1
  else
    Result:=0;
end;

function TTaurusTLSSslClientSocketCtx.GetECHOuterSNI: string;
begin
  Result:=string(FECHOuterSNI);
end;

function TTaurusTLSSslClientSocketCtx.GetECHOuterSNIRaw: RawByteString;
begin
  if FSNIMode in [csmECHGrease, csmECHGreaseDiscovery, csmECH] then
    Result:=FECHOuterSNI
  else
    Result:='';
end;

function TTaurusTLSSslClientSocketCtx.GetHasOnClientCert: boolean;
begin
  Result:=Assigned(FOnClientCert);
end;

function TTaurusTLSSslClientSocketCtx.GetHasOnECHRetry: boolean;
begin
  Result:=Assigned(FOnECHConfigRetry);
end;

function TTaurusTLSSslClientSocketCtx.GetOnECHLog: boolean;
begin
  Result:=Assigned(FOnECHLog);
end;

function TTaurusTLSSslClientSocketCtx.GetHostName: string;
begin
  Result:=string(FHostname);
end;

function TTaurusTLSSslClientSocketCtx.GetIdentity: RawByteString;
begin
  BuildIdentity;
  Result:=FIdentity;
end;

function TTaurusTLSSslClientSocketCtx.GetIsIdentityIP: boolean;
begin
  BuildIdentity;
  Result:=FIdentityIP;
end;

function TTaurusTLSSslClientSocketCtx.GetUseECH: Boolean;
begin
  Result:=FSNIMode in [csmECH, csmECHNoOuter];
end;

function TTaurusTLSSslClientSocketCtx.GetUseGrease: Boolean;
begin
  Result:=FSNIMode in [csmECHGrease, csmECHGreaseDiscovery];
end;

function TTaurusTLSSslClientSocketCtx.GetECHConfigList: string;
begin
  Result:=string(FECHConfigList);
end;

function TTaurusTLSSslClientSocketCtx.GetECHConfigListRaw: RawByteString;
begin
  // ECHConfigList is ONLY valid and active when real ECH is requested (csmECH, csmECHNoOuter).
  // For GREASE modes (csmECHGrease, csmECHGreaseDiscovery) and standard SNI, it is completely ignored
  if UseECH then
    Result:=FECHConfigList
  else
    Result:='';
end;

function TTaurusTLSSslClientSocketCtx.SetDefaultSNI(const AValue: string): TTaurusTLSSslClientSocketCtx;
var
  lValue: RawByteString;

begin
  Result:=Self;
  lValue:=NormalizeHostName(RawByteString(AValue)); // PALOFF 'UnicodeString cast to RawByteString'
  if FDefaultSNI = lValue then
    Exit;

  CheckFrozen;
  FDefaultSNI:=lValue;
  ResetIdentity;
end;

function TTaurusTLSSslClientSocketCtx.SetECHOuterSNI(const AValue: string): TTaurusTLSSslClientSocketCtx;
var
  lValue: RawByteString;

begin
  Result:=Self;
  lValue:=NormalizeHostName(RawByteString(AValue)); // PALOFF 'UnicodeString cast to RawByteString'
  if FECHOuterSNI = lValue then
    Exit;

  CheckFrozen;
  FECHOuterSNI:=lValue;
  ResetIdentity;
end;

function TTaurusTLSSslClientSocketCtx.SetHostName(const AValue: string): TTaurusTLSSslClientSocketCtx;
var
  lValue: RawByteString;

begin
  Result:=Self;
  lValue:=NormalizeHostName(RawByteString(AValue)); // PALOFF 'UnicodeString cast to RawByteString'
  if FHostname = lValue then
    Exit;

  CheckFrozen;
  FHostname:=lValue;
end;

function TTaurusTLSSslClientSocketCtx.SetOnClientCert(
  const AValue: TTaurusTLSOnClientCertCallback): TTaurusTLSSslClientSocketCtx;
begin
  Result:=Self;
  if (TMethod(FOnClientCert).Code = TMethod(AValue).Code) and
     (TMethod(FOnClientCert).Data = TMethod(AValue).Data) then
    Exit;

  CheckFrozen;
  FOnClientCert:=AValue;
end;

function TTaurusTLSSslClientSocketCtx.SetOnECHLog(
  const AValue: TTaurusTLSOnECHLog): TTaurusTLSSslClientSocketCtx;
begin
  Result:=Self;
  if (TMethod(FOnECHLog).Code = TMethod(AValue).Code) and
     (TMethod(FOnECHLog).Data = TMethod(AValue).Data) then
    Exit;

  CheckFrozen;
  FOnECHLog:=AValue;
end;

function TTaurusTLSSslClientSocketCtx.SetOnECHConfigRetry(
  const AValue: TTaurusTLSOnCliECHConfigRetry): TTaurusTLSSslClientSocketCtx;
begin
  Result:=Self;
  if (TMethod(FOnECHConfigRetry).Code = TMethod(AValue).Code) and
     (TMethod(FOnECHConfigRetry).Data = TMethod(AValue).Data) then
    Exit;

  CheckFrozen;
  FOnECHConfigRetry:=AValue;
end;

function TTaurusTLSSslClientSocketCtx.SetECHConfigList(const AValue: string): TTaurusTLSSslClientSocketCtx;
var
  lValue: RawByteString;

begin
  Result:=Self;
  lValue:=RawByteString(AValue); // PALOFF 'UnicodeString cast to RawByteString'
  if FECHConfigList = lValue then
    Exit;

  CheckFrozen;
  FECHConfigList:=lValue;
  ResetIdentity;
end;

function TTaurusTLSSslClientSocketCtx.SetSNIMode(
  const AValue: TTaurusTLSSslClientSNIMode): TTaurusTLSSslClientSocketCtx;
begin
  Result:=Self;
  if FSNIMode = AValue then
    Exit;

  CheckFrozen;
  FSNIMode:=AValue;
  ResetIdentity;
end;

{ TTaurusTLSSslPeerCtx }

class function TTaurusTLSSslPeerCtx.CbPeerAlpnSelect(ASSL: PSSL;
  var AOut: PIdC_UINT8; var AOutLen: TIdC_UINT8; const AIn: PIdC_UINT8;
  AInLen: TIdC_UINT; AArgs: pointer): TIdC_INT;
var
  lInstance: TTaurusTLSSslSocket;
  lConfig: TTaurusTLSSslPeerCtx;
  lErr: integer;

begin
  Result:=0;
  if not Assigned(ASSL) then // this shouldn't happen ever
    Exit;
  try
    lErr:=GStack.WSGetLastError;
    try
      lInstance:=TTaurusTLSSslSocket.GetInstanceFromSSL(ASSL);
      if not Assigned(lInstance) then
        Exit;

      lConfig:=lInstance.Ctx as TTaurusTLSSslPeerCtx;
      if Assigned(lConfig) then
        lConfig.DoOnAlpnSelect(lInstance, AOut, AOutLen,
          AIn, AInLen, Result);
    finally
      GStack.WSSetLastError(lErr);
    end;
  except
    Result:=0;
  end;
end;

class function TTaurusTLSSslPeerCtx.CbPeerSniSelect(ASSL: PSSL;
  var AAlert: Integer; AArg: Pointer): TIdC_INT;
var
  lInstance: TTaurusTLSSslSocket;
  lConfig: TTaurusTLSSslPeerCtx;
  lErr: integer;

begin
  Result:=0;
  if not Assigned(ASSL) then // this shouldn't happen ever
    Exit;
  try
    lErr:=GStack.WSGetLastError;
    try
      lInstance:=TTaurusTLSSslSocket.GetInstanceFromSSL(ASSL);
      if not Assigned(lInstance) then
        Exit;

      lConfig:=lInstance.Ctx as TTaurusTLSSslPeerCtx;
      if Assigned(lConfig) then
        lConfig.DoOnPeerSniSelect(lInstance, AAlert);

    finally
      GStack.WSSetLastError(lErr);
    end;
  except
    Result:=0;
  end;
end;

class function TTaurusTLSSslPeerCtx.CbPeerSslSessionNew(ASSL: PSSL;
  ASession: PSSL_SESSION): TIdC_INT;
var
  lInstance: TTaurusTLSSslSocket;
  lConfig: TTaurusTLSSslPeerCtx;
  lErr: integer;
  lResult: boolean;

begin
  Result:=1;
  lResult:=True;
  if not Assigned(ASSL) then // this shouldn't happen ever
    Exit;
  try
    lErr:=GStack.WSGetLastError;
    try
      lInstance:=TTaurusTLSSslSocket.GetInstanceFromSSL(ASSL);
      if not Assigned(lInstance) then
        Exit;

      lConfig:=lInstance.Ctx as TTaurusTLSSslPeerCtx;
      if Assigned(lConfig) then
        lConfig.DoOnSSLSessionNew(lInstance, ASession, lResult);

      if lResult then
        Result:=1
      else
        Result:=0;
    finally
      GStack.WSSetLastError(lErr);
    end;
  except
    Result:=0;
  end;
end;

class procedure TTaurusTLSSslPeerCtx.CbPeerSslSessionRemove(ACtx: PSSL_CTX;
  ASession: PSSL_SESSION);
var
  lConfig: TTaurusTLSSslPeerCtx;
  lErr: integer;

begin
  if not Assigned(ACtx) then // this shouldn't happen ever
    Exit;
  try
    lErr:=GStack.WSGetLastError;
    try
      lConfig:=GetInstanceFromCtx(ACtx) as TTaurusTLSSslPeerCtx;
      if Assigned(lConfig)then
        lConfig.DoOnSslSessionRemove(ACtx, ASession);
    finally
      GStack.WSSetLastError(lErr);
    end;
  except //PALOFF "Empty except-block"
    // We must not raise the exception to the OpenSSL stack
  end;
end;

function TTaurusTLSSslPeerCtx.GetHasOnPeerAlpnSelect: boolean;
begin
   Result:=Assigned(OnAlpnSelect);
end;

function TTaurusTLSSslPeerCtx.GetHasOnPeerSslSessionNew: boolean;
begin
   Result:=Assigned(OnSslSessionNew);
end;

function TTaurusTLSSslPeerCtx.GetHasOnPeerSslSessionRemove: boolean;
begin
   Result:=Assigned(OnSslSessionRemove);
end;

function TTaurusTLSSslPeerCtx.GetHasOnPeerSniSelect: boolean;
begin
  Result:=Assigned(OnSniSelect);
end;

procedure TTaurusTLSSslPeerCtx.DoOnAlpnSelect(
  ASocket: TTaurusTLSSslSocket; var AOut: PIdC_UINT8; var AOutLen: TIdC_UINT8;
  const AIn: PIdC_UINT8; const AInLen: TIdC_UINT; var AResultValue: TIdC_INT);
var
  lAlpnSelect: TTaurusTLSAlpnSelector;

begin
  if not (Assigned(ASocket) and Assigned(OnAlpnSelect)) then
    Exit;

  lAlpnSelect:=TTaurusTLSAlpnSelector.Create(AIn, AInLen);

  OnAlpnSelect(Sender, ASocket, lAlpnSelect);

  AResultValue:=lAlpnSelect.ResultValue.AsInt;
  AOut:=lAlpnSelect.SelectedProto;
  AOutLen:=lAlpnSelect.SelectedProtoLen;
end;

procedure TTaurusTLSSslPeerCtx.DoOnPeerSniSelect(
  ASocket: TTaurusTLSSslSocket; var AAlert: TIdC_INT);
begin
  if Assigned(ASocket) and Assigned(OnSniSelect) then
    OnSniSelect(Sender, ASocket, AAlert);
end;

procedure TTaurusTLSSslPeerCtx.DoOnSSLSessionNew(
  ASocket: TTaurusTLSSslSocket; ASession: PSSL_SESSION; var AAccept: boolean);
begin
  if Assigned(ASocket) and Assigned(ASession) then
    FOnSSLSessionNew(Sender, ASession, AAccept);
end;

procedure TTaurusTLSSslPeerCtx.DoOnSSLSessionRemove(
  ACtx: PSSL_CTX; ASession: PSSL_SESSION);
begin
  if Assigned(ACtx) and Assigned(ASession) then
    FOnSslSessionRemove(Sender, ACtx, ASession);
end;

procedure TTaurusTLSSslPeerCtx.InitCtx;
begin
  inherited;

  // Add callbacks
  if HasOnPeerSniSelect then
    SSL_CTX_set_tlsext_servername_callback(SSLCtx, CbPeerSniSelect);

  if HasOnPeerAlpnSelect then
    SSL_CTX_set_alpn_select_cb(SSLCtx, CbPeerAlpnSelect, nil);

  if HasOnPeerSslSessionNew then
    SSL_CTX_sess_set_new_cb(SSLCtx, CbPeerSslSessionNew);

  if HasOnPeerSslSessionRemove then
    SSL_CTX_sess_set_remove_cb(SSLCtx, CbPeerSslSessionRemove);
end;

procedure TTaurusTLSSslPeerCtx.ReleaseCtx;
begin
  // Remove callbacks
  try
    SSL_CTX_set_tlsext_servername_callback(SSLCtx, nil);
    SSL_CTX_set_alpn_select_cb(SSLCtx, nil, nil);
    SSL_CTX_sess_set_new_cb(SSLCtx, nil);
    SSL_CTX_sess_set_remove_cb(SSLCtx, nil);
  finally
    inherited;
  end;
end;

{ TTaurusTLSSslSocket }

{$IFDEF SIGPIPE_MASK}
{ BUGFIX: Fixes issue #217 and #240 }
class constructor TTaurusTLSSslSocket.Create;
begin
  // We initialize the FSigSet once to eliminate the variable setup in each thread.
{$IFDEF DCC}
  sigemptyset(FSigSet);
  sigaddset(FSigSet, SIGPIPE);
{$ELSE}
  FpsigEmptySet(FSigSet);
  FpSigAddSet(FSigSet, SIGPIPE);
{$ENDIF}
end;
{$ENDIF}

constructor TTaurusTLSSslSocket.Create(const AConfigIntf: ITaurusTLSSslSocketCtx);
begin
  Assert(Assigned(AConfigIntf), '''AConfigIntf'' should not be ''nil''.'); //Do not localize
  inherited Create;
  FSocketHandle:=Id_INVALID_SOCKET;
  FContextIntf:=AConfigIntf;
  FCtx:=AConfigIntf.Ctx; // PALOFF 'Mixing interface variables and objects' (Not sure why)
end;

destructor TTaurusTLSSslSocket.Destroy;
begin
  Shutdown;
  if not (FState in cTerminalStates) then
    TransitionTo(seReleased);

  inherited Destroy;
end;

{$IFDEF SIGPIPE_MASK}
{ BUGFIX: Fixes issue #217 and #240 }
class procedure TTaurusTLSSslSocket.MaskSigPipe;
begin
  pthread_sigmask(SIG_BLOCK, @FSigSet, nil);
end;
{$ENDIF}

function TTaurusTLSSslSocket.InitSSL: TTaurusTLSSslSocketState;
var
  lErr: TIdC_INT;

begin
  ClearError;
  CheckActiveState([seIdle]);

  // 1. Allocate the SSL session structure using the pinned context
  FSSL:=SSL_new(FCtx.SSLCtx);
  if not Assigned(FSSL) then
    ETaurusTLSSslSocketCreateError.RaiseExceptionCode(GetLastError(0),
      RSSSLCreatingSessionError);

  // 2. Bind the Delphi object instance to the SSL handle for callback routing
  lErr:=GetLastError(SSL_set_app_data(FSSL, Self));
  if lErr <= 0 then
    ETaurusTLSSslSocketDataBindingError.RaiseExceptionCode(lErr,
      RMSG_SslSocketSetAppData_err);

  // 3. Do Socket/Connection specific configuration (Virtual polymorphic hook)
  SetupConnection;

  // 4. Register the callback bridges
  InitSSLCallbacks;

  // 5. For Linux only: mask SIGPIPE signal for the current thread.
{$IFDEF SIGPIPE_MASK}
  MaskSigPipe;
{$ENDIF}
  Result:=seInitializing;
end;

function TTaurusTLSSslSocket.ReleaseSSL: TTaurusTLSSslSocketState;
begin
  ClearError;
  Result:=seReleased;
  if Assigned(FSSL) then
  try
    try
      ReleaseSSLCallbacks;
    except //PALOFF "Empty except-block"
      // We must not raise the exception to the OpenSSL stack
    end;
  finally
    SSL_set_app_data(FSSL, nil);
    SSL_free(FSSL);
    FSSL:=nil;
  end;
end;

function TTaurusTLSSslSocket.BindSocket: TTaurusTLSSslSocketState;
var
  lRet: TIdC_INT;

begin
  ClearError;
  Result:=seError;
  if Assigned(FSSL) and (FSocketHandle <> Id_INVALID_SOCKET) then
  begin
    lRet:=SSL_set_fd(FSSL, FSocketHandle);
    if GetLastError(lRet) <= 0 then
      ETaurusTLSSslSocketBindError.RaiseExceptionCode(lRet,
        RSSSLDataBindingError_2)
    else
      Result:=seHandshaking;
  end
end;

function TTaurusTLSSslSocket.DoHandshake: TTaurusTLSSslSocketState;
begin
  ClearError;
  CheckActiveState([seHandshaking]);

  repeat
    Result:=DoHandshakeIteration;
    if Result = seHandshaking then
    { TODO : IndySleep should be replaced with the smart cross-compiler "spin wait" call. }
      IndySleep(1)
  until Result <> seHandshaking;

  FIsSessionResumed:=Assigned(FSSL) and (Result in [seEstablished, seClosed]) and
    (SSL_session_reused(FSSL) > 0);
end;

function TTaurusTLSSslSocket.DoShutdown: TTaurusTLSSslSocketState;
var
  lRet, lErr: Integer;

begin
  if FState = seError then
    Exit(seError)
  else
    Result:=seClosed; // Default next step on successful close_notify exchange

  if not Assigned(FSSL) then
    Exit;

  ClearError;
  lRet:=SSL_shutdown(FSSL);

  // Handle first SSL_shutdown call
  if lRet < 0 then
  begin
    lErr:=GetSSLError(lRet); // Captures error snapshot automatically
    if lErr = SSL_ERROR_SYSCALL then
      Result:=seClosed // Hard socket disconnect
    else
      Result:=seError;  // OpenSSL protocol or cryptographic error
    Exit;
  end

  // lRet = 0 means close_notify sent, awaiting peer response.
  // Execute second call if bi-directional shutdown is required.
  else if (lRet = 0) and (not Ctx.Flags.UniDirectShutdown) then
  begin
    ERR_clear_error;
    SSL_shutdown(FSSL);
    Result:=seClosed
  end;
end;

procedure TTaurusTLSSslSocket.DoStateChangeNotify(ACurrent,
  ATarget: TTaurusTLSSslSocketState);
var
  lContext: TTaurusTLSSslSocketCtx;

begin
  lContext:=FCtx;
  if Assigned(lContext) then
    lContext.DoOnStateChange(Self, ACurrent, ATarget);
end;

function TTaurusTLSSslSocket.GetLastError(ARetCode: Integer): Integer;
begin
  FLastRetCode:=ARetCode;
  FLastSocketError:=GStack.WSGetLastError;

  // 1. Peek at the top error in OpenSSL's thread-local queue WITHOUT popping/clearing it
  Result:=ARetCode;
  FLastQueueError:= ERR_peek_error;

  // 2. Resolve High-Level SSL Error Code
  if Assigned(FSSL) then
  begin
    // If FSSL exists, query SSL_get_error for the high-level classification
    FLastSSLError:=SSL_get_error(FSSL, ARetCode);
  end
  else if FLastSocketError <> 0 then
  begin
    // If no OpenSSL queue error exists but an OS socket error was recorded
    FLastSSLError:=SSL_ERROR_SYSCALL;
  end
  else
    FLastSSLError:=SSL_ERROR_NONE;
end;

function TTaurusTLSSslSocket.GetSSLError(ALastResult: Integer): Integer;
begin
  FLastRetCode := ALastResult;

  // 1. SUCCESS PATH (ALastResult > 0)
  // OpenSSL guarantees SSL_get_error returns SSL_ERROR_NONE when ret > 0.
  if ALastResult > 0 then
  begin
    ClearError; // Reset all snapshot fields to clean state
    Result := SSL_ERROR_NONE;
    Exit;
  end;

  // 2. FAILURE / PENDING PATH (ALastResult <= 0)
  // Capture OS-level socket error at the exact microsecond of failure
  FLastSocketError := GStack.WSGetLastError;

  if Assigned(FSSL) then
  begin
    // Resolves ZERO_RETURN, SYSCALL, WANT_READ, WANT_WRITE, SSL_ERROR_SSL, etc.
    Result := SSL_get_error(FSSL, ALastResult);

    // Peeks at the top error in OpenSSL's C-queue without clearing it
    FLastQueueError := ERR_peek_error;
  end
  else
  begin
    Result := SSL_ERROR_SYSCALL;
    FLastQueueError := ERR_peek_error;
  end;

  FLastSSLError := Result;
end;

procedure TTaurusTLSSslSocket.CheckActiveState(
  const AExpectedStates: TTaurusTLSSslSocketStates);
begin
  if not (FState in AExpectedStates) then
     ETaurusTLSSocketStateError.RaiseWithMessageFmt(
      { TODO : To make ResourceString }
      'Invalid socket operation in the ''%s'' state.', [FState.AsString]);
end;

function TTaurusTLSSslSocket.GetNextStepTarget(ACurrent,
  ATarget: TTaurusTLSSslSocketState): TTaurusTLSSslSocketState;
begin
  if ACurrent in cTerminalStates then
    Exit(ACurrent);

  if ATarget in cTerminalStates then
  begin
    if (ACurrent = seEstablished) and (ATarget = seReleased) then
      Exit(seClosed)
    else
      Exit(ATarget);
  end;

  if ATarget <= ACurrent then
    Exit(ATarget); // Handled/rejected by IsValidTransition

  case ACurrent of
    seIdle:
      Result:=seInitializing; // Step 1 from Idle

    seInitializing:
      Result:=seInitialized;  // Step 2 from Initializing

    seInitialized:
      Result:=seHandshaking;  // Step 3 from Initialized

    seHandshaking:
      Result:=seEstablished;  // Step 4 from Handshaking

    seEstablished:
      Result:=seClosed;      // Step 5 from Established

    seClosed:
      Result:=seReleased;

    seReleased:
      Result:=seReleased;

  else
    Result:=seError;
  end;
end;

function TTaurusTLSSslSocket.IsValidTransition(ACurrent,
  ATarget: TTaurusTLSSslSocketState): Boolean;
begin
  // Global Panic State Rule: seError is valid from any state except Closed and itself
  if ATarget = seError then
    Exit((ACurrent <> seClosed) and (ACurrent <> seError));

  case ACurrent of
    seIdle:
      Result:=ATarget in ([seInitializing]+cTerminalStates);

    seInitializing:
      Result:=ATarget in ([seInitialized]+cTerminalStates);

    seInitialized:
      Result:=ATarget in ([seHandshaking]+cTerminalStates);

    seHandshaking:
      Result:=ATarget in ([seEstablished]+cTerminalStates);

    seEstablished:
      Result:=ATarget in ([seClosed]+cTerminalStates);

    seClosed:
      Result:=ATarget in cTerminalStates;

    seReleased, seError:
      Result:=False; // Terminal states cannot transition out
  else
    Result:=False;
  end;
end;

function TTaurusTLSSslSocket.DoSetState(ATarget: TTaurusTLSSslSocketState): boolean;
begin
  Result:=not (ATarget = FState);
  if Result then
    FState:=ATarget;
end;

procedure TTaurusTLSSslSocket.DoSetState(ATarget: TTaurusTLSSslSocketState;
  ANotify: boolean);
var
  lState: TTaurusTLSSslSocketState;

begin
  lState:=FState;
  if DoSetState(ATarget) and ANotify then
    DoStateChangeNotify(lState, ATarget);
end;

function TTaurusTLSSslSocket.DoTransitionTo(
  ATarget: TTaurusTLSSslSocketState): TTaurusTLSSslSocketState;
var
  lState: TTaurusTLSSslSocketState;

begin
  lState:=FState;
  Result:=ATarget;

  if FState = Result then
    Exit;

  case ATarget of
    seInitializing:
      Result:=InitSSL;

    seInitialized:
      begin
        CheckActiveState([seInitializing]);
        Result:=seInitialized;
      end;

    seHandshaking:
      Result:=BindSocket;

    seEstablished:
      Result:=DoHandshake; // Executes handshake loop; transitions to seEstablished on success

    seClosed:
      Result:=DoShutdown;

    seReleased, seError:
      if lState in [seInitialized..seClosed] then
        ReleaseSSL; //PALOFF "Functions called as procedures"

    else
      Result:=seError;
  end;
end;

procedure TTaurusTLSSslSocket.TransitionTo(ATarget: TTaurusTLSSslSocketState;
  ASteps: integer);
var
  lState, lNextState: TTaurusTLSSslSocketState;
  lSteps: integer;

begin
  // Exit if already in requested target state
  if FState = ATarget then
    Exit;

  lSteps:=ASteps;

  try
    repeat
      lState := FState;

      // Resolve the immediate next forward step required to reach ATarget
      lNextState := GetNextStepTarget(lState, ATarget);

      // Validate single-step feasibility using your exact IsValidTransition rules
      if not IsValidTransition(lState, lNextState) then
        { TODO : To make ResourceString }
        ETaurusTLSSocketStateError.RaiseWithMessageFmt(
          'Unable to transition Socket ''%s''''s state from ''%s'' to ''%s''.',
          [ClassName, lState.AsString, lNextState.AsString]);

      // Execute the single step
      lState:=DoTransitionTo(lNextState);

      // Update State and notify
      DoSetState(lState, True);

      // Infinite Loop / Stagnation Guard
      Dec(lSteps);
    until (FState in ([ATarget]+cTerminalStates)) or (lSteps <= 0);

    if lSteps <= 0 then
    begin
      ETaurusTLSSocketStateError.RaiseWithMessageFmt(
        'Infinite state transition loop detected on Socket ''%s'' at state ''%s''.',
        [ClassName, FState.AsString]);
    end;

  except
    on E: Exception do
    begin
      if E is EIdConnClosedGracefully then
        lState:=seReleased
      else
        lState:=seError;

      ReleaseSSL; //PALOFF "Functions called as procedures"
      DoSetState(lState, True);
      raise;
    end;
  end;
end;

class function TTaurusTLSSslSocket.CheckForSocketEvent(ASocketHandle: TIdStackSocketHandle;
      AKind: TSocketSelectKinds; AMsec: integer): boolean;
var
  lList: TIdSocketList;
  lReadList, lWriteList, lErrorList: TIdSocketList;

begin
  if ASocketHandle = INVALID_HANDLE_VALUE then
    raise EIdConnClosedGracefully.Create(RSConnectionClosedGracefully);

  lList:=TIdSocketList.CreateSocketList;
  lList.Add(ASocketHandle);
  try
    if sokRead in AKind then
      lReadList:=lList
    else
      lReadList:=nil;

    if sokWrite in AKind then
      lWriteList:=lList
    else
      lWriteList:=nil;

    if sokError in AKind then
      lErrorList:=lList
    else
      lErrorList:=nil;

    Result:=lList.Select(lReadList, lWriteList, lErrorList, AMsec);
  finally
    lList.Free;
  end;
end;

class function TTaurusTLSSslSocket.WaitForSocket(
  ASocketHandle: TIdStackSocketHandle; AKind: TSocketSelectKinds;
  AMsec: integer): boolean;
var
  lMSec: integer;

begin
  Result:=False;
  lMSec:=AMsec;

  if lMSec =IdTimeoutDefault then
    lMSec:=IdTimeoutInfinite;

  if TIdAntiFreezeBase.ShouldUse then
  begin
    if lMSec = IdTimeoutInfinite then
    begin
      repeat
        Result:=CheckForSocketEvent(ASocketHandle, AKind, GAntiFreeze.IdleTimeOut);
      until Result;
      Exit;
    end
    else
    while lMSec >= 0 do
    begin
      Result:=CheckForSocketEvent(ASocketHandle, AKind, GAntiFreeze.IdleTimeOut);
      if Result then
        Exit;
      Dec(lMSec, GAntiFreeze.IdleTimeOut);
    end
  end
  else
    Result:=CheckForSocketEvent(ASocketHandle, AKind, lMSec);
end;

function TTaurusTLSSslSocket.WaitForRead(AMsec: integer): boolean;
begin
  Result:=WaitForSocket(FSocketHandle, [sokRead], AMsec);
end;

function TTaurusTLSSslSocket.WaitForWrite(AMsec: integer): boolean;
begin
  Result:=WaitForSocket(FSocketHandle, [sokWrite], AMsec);
end;

function  TTaurusTLSSslSocket.Connect(const pHandle: TIdStackSocketHandle): boolean;
begin
  CheckActiveState([seIdle]);
  FSocketHandle := pHandle;
  TransitionTo(seEstablished);
  Result:=State = seEstablished;
end;

function TTaurusTLSSslSocket.CheckForError: Integer;
var
  lErrStr: string;

begin
  // 1. EARLY TERMINAL GUARD: Handle sockets that were already closed/erred
  // before the SSL stack executed or during an earlier teardown
  if FState in ([seClosed]+cTerminalStates) then
  begin
    if FLastSocketError <> 0 then
      GStack.RaiseSocketError(FLastSocketError) // Raises EIdSocketError with exact OS error
    else if FLastSSLError <> SSL_ERROR_NONE then
    begin
      lErrStr:=string(ERR_error_string(FLastQueueError, nil));
      ETaurusTLSAPISSLError.RaiseExceptionCode(FLastSSLError, FLastRetCode, lErrStr);
    end
    else
    begin
      // Fallback: Check Indy's GStack for any last socket error
      GStack.CheckForSocketError(Integer(Id_SOCKET_ERROR),
        [Id_WSAESHUTDOWN, Id_WSAECONNABORTED, Id_WSAECONNRESET, Id_WSAETIMEDOUT]);
    end;

    Exit(FLastSocketError);
  end;

  Result:=FLastSSLError;

  // 2. SSL Layer Reports No Error, but OS Socket Handle is Invalid
  if Result = SSL_ERROR_NONE then
  begin
    if FSocketHandle = Id_INVALID_SOCKET then
    begin
      TransitionTo(seClosed);
      { TODO : To make ResourceString }
      ETaurusTLSSslSocketConnectionReset.RaiseWithMessage(
        'Socket closed before SSL operation completed.');
    end;
    Exit(0); // Healthy session
  end;

  // 3. Handle OS-level Network Resets (SSL_ERROR_SYSCALL)
  if Result = SSL_ERROR_SYSCALL then
  begin
    TransitionTo(seReleased);
    if FLastSocketError <> 0 then
      GStack.RaiseSocketError(FLastSocketError)
    else
      Exit(GStack.CheckForSocketError(Integer(Id_SOCKET_ERROR),
        [Id_WSAESHUTDOWN, Id_WSAECONNABORTED, Id_WSAECONNRESET, Id_WSAETIMEDOUT]));
  end;

  // 4. Handle OpenSSL Protocol / Cryptographic Failures
  TransitionTo(seError);

  if FLastQueueError <> 0 then
    lErrStr:=string(ERR_error_string(FLastQueueError, nil))
  else
    { TODO : To make ResourceString }
    lErrStr:='Unspecified OpenSSL error.';

  ETaurusTLSAPISSLError.RaiseExceptionCode(Result, FLastRetCode, lErrStr);
end;

procedure TTaurusTLSSslSocket.CheckPeerCertificateValidationResult;
var
  lErr: TTaurusTLSX509Error;  // its a record type. No lErr.Free is required.
  lErrCode: TIdC_INT;
  lCert: TTaurusTLSX509; // PALOFF 'Created and freed objects'
  lSuccess: boolean;

begin
  if not Ctx.CertVerifyFlags.VerifyPeer then
    Exit;

  lCert:=nil;
  lErrCode:=SSL_get_verify_result(FSSL);
  lErr:=TTaurusTLSX509Error.Create(lErrCode);
  lSuccess:=lErrCode = X509_V_OK;
  if not lSuccess then
  try
    lCert:=GetPeerCertificate;
    Ctx.DoOnPeerCertError(Self, lCert, lErr, lSuccess);
  finally
    lCert.Free;
  end;
  if not lSuccess then
    ETaurusTLSSslSocketCertValidationError.RaiseErrorCode(lErrCode,
      lErr.ErrorShortDescription);
end;

procedure TTaurusTLSSslSocket.ClearError;
begin
  ERR_clear_error; // Clear OpenSSL's thread-local error queue

  // Reset local captured snapshot fields
  FLastSSLError := SSL_ERROR_NONE;
  FLastRetCode := 0;
  FLastQueueError := 0;
  FLastSocketError := 0;
end;

function TTaurusTLSSslSocket.Readable(AMsec: integer): boolean;
var
  lSW: TStopWatch;
  lTimeout: integer;
  lByte: byte;
  lRet, lErr: TIdC_INT;

begin
  Result:=False;

  if Assigned(FSSL) and (FState = seEstablished) then
  begin
    lSW:=TStopWatch.StartNew;
    lTimeout:=AMsec;

    repeat
      // 1. Check OpenSSL internal memory queue for decrypted application data
      if SSL_has_pending(FSSL) > 0 then
      begin
        Result:=True;
        Break; // Data ready; exit loop
      end;

      // 2. Check if the OS socket descriptor was closed
      if FSocketHandle = Id_INVALID_SOCKET then
      begin
        Result:=False;
        Break;
      end;

      if AMsec > 0 then
      begin
        lTimeout:=AMsec - Integer(lSW.ElapsedMilliseconds);
        if lTimeout <= 0 then
          Break; // Timeout budget exhausted
      end;

      if not WaitForRead(lTimeout) then
        Break;

      ClearError;

      // 3. Perform a non-destructive 1-byte peek
      lRet:=SSL_peek(FSSL, lByte, 1);
      if lRet > 0 then
      begin
        Result:=True;
        Break; // Application data is ready for Recv
      end;

      lErr:=GetSSLError(lRet);
      case lErr of
        SSL_ERROR_WANT_READ:
          // Suspend thread at OS level via select(). Exit loop if wait fails/times out
          if not WaitForRead(lTimeout) then
            Break; // Timeout budget exhausted

        SSL_ERROR_WANT_WRITE:
          if not WaitForWrite(lTimeout) then
            Break;

        {SSL_ERROR_ZERO_RETURN,} SSL_ERROR_SYSCALL, SSL_ERROR_SSL:
          begin
            // Disconnect or error state detected; set True so Indy invokes
            // Recv to handle graceful shutdown or raise exceptions cleanly.
            Result:=True;
            Break;
          end;
      else
        Break;
      end;

    until False; //PALOFF "Condition evaluates to constant value"
  end;
end;

function TTaurusTLSSslSocket.Recv(var ABuffer: TIdBytes;
  const AMSec: Integer): Integer;
var
  lResult: TIdC_SIZET;
  lLen, lRet, lErr: TIdC_INT;
  lTimeout: Integer;
  lIsTimeout: Boolean;
  lSW: TStopWatch;

begin
  lResult:=0;

  lLen:=Length(ABuffer);
  if lLen = 0 then
    Exit(0);

  CheckActiveState([seEstablished]);

  lIsTimeout:=False;
  lSW:=TStopWatch.StartNew;

  repeat
    ClearError;
    lRet:=SSL_read_ex(FSSL, ABuffer[0], Length(ABuffer), lResult);
    Result:=lResult;

    if lRet > 0 then
      Break;

    if AMSec <> IdTimeoutInfinite then
    begin
      lTimeout:=AMSec - Integer(lSW.ElapsedMilliseconds);
      lIsTimeout:=(lTimeout <= 0);
    end
    else
      lTimeout:=IdTimeoutInfinite;

    if lIsTimeout then
      Break;

    // Handle Non-Success / Pending / Error States
    lErr:=GetSSLError(lRet);
    case lErr of
      SSL_ERROR_WANT_READ:
        if SSL_has_pending(FSSL) > 0 then
          Continue // SSL has decoded or raw data in the buffer (Read Ahead is ON)
        else
          lIsTimeout:=not WaitForRead(lTimeout);

      SSL_ERROR_WANT_WRITE:
        lIsTimeout:=not WaitForWrite(lTimeout);

      else
        if lErr <> SSL_ERROR_ZERO_RETURN then
        begin
          Result:=lRet;
          Break;
        end;
    end;
  until lIsTimeout;
end;

function TTaurusTLSSslSocket.Send(const ABuffer: TIdBytes; const AOffset,
  ALength: TIdC_SIZET; const AMSec: Integer): Integer;
var
  lResult: TIdC_SIZET; // PALOFF "Variables that are referenced, but never set"
  lRet, lErr: TIdC_INT;
  lLen: TIdC_SIZET;
  lTimeout: Integer;
  lIsTimeout: boolean;
  lSW: TStopWatch;

begin
  Result:=0;
  lLen:=Length(ABuffer);
  if (ALength = 0) or (lLen = 0) then
    Exit;

  CheckActiveState([seEstablished]);

  lIsTimeOut:=False;
  lSW:=TStopWatch.StartNew;

  repeat
    ClearError;
    lRet:=SSL_write_ex(FSSL, ABuffer[AOffset], ALength, lResult);
    Result:=lResult;

    if lRet > 0 then
      Break;

    if AMSec <> IdTimeoutInfinite then
    begin
      lTimeout:=AMSec - Integer(lSW.ElapsedMilliseconds);
      lIsTimeout:=(lTimeout <= 0);
    end
    else
      lTimeout:=IdTimeoutInfinite;

    if lIsTimeout then
      Break;

    lErr:=GetSSLError(lRet);
    case lErr of
      SSL_ERROR_WANT_WRITE:
        lIsTimeout:=not WaitForWrite(lTimeout);

      SSL_ERROR_WANT_READ:
        lIsTimeout:=not WaitForRead(lTimeout);

      else
        if lErr <> SSL_ERROR_ZERO_RETURN then
        begin
          Result:=lRet;
          Break;
        end;
    end;
  until lIsTimeout;
end;

procedure TTaurusTLSSslSocket.Shutdown;
begin
  if FState = seEstablished then
  begin
    try
      // Initiates pipeline: seEstablished -> seClosing -> seClosed (or seError on failure)
      TransitionTo(seReleased);
    except
      on E: Exception do
      begin
        // If an exception escapes DoShutdown, force seError state and re-raise
        TransitionTo(seError);
        raise;
      end;
    end;
  end
  else if FState in [seInitialized, seHandshaking] then
  begin
    // For non-established connections being torn down, move directly to seClosed
    TransitionTo(seReleased);
  end;
end;

// callbacks

procedure TTaurusTLSSslSocket.InitSSLCallbacks;
var
  lCertCallback: function(const APreVerify: TIdC_INT;
      ACtx: PX509_STORE_CTX): TIdC_INT; cdecl;

begin
  if FCtx.HasOnStatusInfo then
    SSL_set_info_callback(FSSL, TTaurusTLSSslSocket.CbSslInfo);

  if FCtx.HasOnVerifyCertificate then
    lCertCallback:=TTaurusTLSSslSocket.CbSslVerify
  else
    lCertCallback:=nil;
  SSL_set_verify(FSSL, FCtx.CertVerifyFlags.AsInt, lCertCallback);


  if FCtx.HasOnSecurityCheck then
    SSL_set_security_callback(FSSL,
      TTaurusTLSSslSocket.CbSslSecurityCheck);

  if Ctx.HasOnMessage then
    SSL_set_msg_callback(FSSL,
      TTaurusTLSSslSocket.CbSslMessage);
end;

procedure TTaurusTLSSslSocket.ReleaseSSLCallbacks;
begin
  SSL_set_verify(FSSL, 0, nil);
  SSL_set_info_callback(FSSL, nil);
end;

class function TTaurusTLSSslSocket.GetInstanceFromSSL(ASSL: PSSL): TTaurusTLSSslSocket;
var
  lResult: pointer;

begin
  Result:=nil;
  lResult:=SSL_get_app_data(ASSL);
  if Assigned(lResult) and (TObject(lResult) is TTaurusTLSSslSocket) then // PALOFF 'Pointer cast to TObject'
    Result:=TTaurusTLSSslSocket(lResult)
  else
    { TODO : To make ResourceString }
    ETaurusTLSSslSocketDataBindingError.RaiseWithMessageFmt(
      'SSL object %p is not bound to a valid TTaurusTLSSslSocket instance.',
      [ASSL]);
end;

function TTaurusTLSSslSocket.GetPeerCertificate: TTaurusTLSX509;
var
  lX509: PX509;

begin
  Result:=nil;
  if State in [seHandshaking, seEstablished] then
  try
    lX509:=SSL_get1_peer_certificate(FSSL);
    if Assigned(lX509) then
      Result:=TTaurusTLSX509.Create(lX509, True);
  except
    FreeAndNil(Result);
  end;
end;

class function TTaurusTLSSslSocket.CbSrvAlpnSelectCallback(ASSL: PSSL;
  var AOutProto: PIdAnsiChar; var AOutLen: TIdC_UINT8;
  const AInProtos: PIdAnsiChar; AInLen: TIdC_UINT; AArg: Pointer): TIdC_INT;
var
  lInstance: TTaurusTLSSslSocket;
  lContext: TTaurusTLSSslSocketCtx;
  lErr: integer;

begin
  Result:=SSL_TLSEXT_ERR_NOACK;
  if not Assigned(ASSL) then // this shouldn't happen ever
    Exit;
  try
    lErr:=GStack.WSGetLastError;
    try
      lInstance:=GetInstanceFromSSL(ASSL);
      if not Assigned(lInstance) then
        Exit;

      lContext:=lInstance.FCtx;
      if Assigned(lContext) then
      { TODO : Call event handler here. }

    finally
      GStack.WSSetLastError(lErr);
    end;
  except
    Result:=SSL_TLSEXT_ERR_ALERT_FATAL;
  end;
end;

class procedure TTaurusTLSSslSocket.CbSSLInfo(const ASSL: PSSL; AWhere,
  ARet: TIdC_INT);
var
  lInstance: TTaurusTLSSslSocket;
  lContext: TTaurusTLSSslSocketCtx;
  lErr: integer;

begin
  if not Assigned(ASSL) then // this shouldn't happen ever
    Exit;
  try
    lErr:=GStack.WSGetLastError;
    try
      lInstance:=GetInstanceFromSSL(ASSL);
      if not Assigned(lInstance) then
        Exit;

      lContext:=lInstance.FCtx;
      if Assigned(lContext) then
        lContext.DoOnStatusInfo(lInstance, AWhere, ARet);
    finally
      GStack.WSSetLastError(lErr);
    end;
  except //PALOFF "Empty except-block"
    // We must not raise the exception to the OpenSSL stack
  end;
end;

class procedure TTaurusTLSSslSocket.CbSslMessage(AWriteP, AVersion,
  AContentType: TIdC_INT; const ABuf: pointer; ALen: TIdC_SIZET; ASSL: PSSL;
  AArg: Pointer);
var
  lErr: TIdC_INT;
  lInstance: TTaurusTLSSslSocket;
  lContext: TTaurusTLSSslSocketCtx;

begin
  if not Assigned(ASSL) then
    Exit;

  LErr:=GStack.WSGetLastError;
  try
    LInstance:=GetInstanceFromSSL(ASSL);
    if not Assigned(lInstance) then
      Exit;

    lContext:=lInstance.FCtx;
    if Assigned(lContext) then
      lContext.DoOnMessage(lInstance, AWriteP, AVersion, AContentType, ABuf, ALen);

  finally
    GStack.WSSetLastError(LErr);
  end;
end;

class function TTaurusTLSSslSocket.CbSslSecurityCheck(const ASSL: PSSL;
  const ACtx: PSSL_CTX; AOp, ABits, ANid: TIdC_INT; AOther, AEx: pointer): TIdC_INT;
var
  lErr: TIdC_INT;
  lResult: boolean;
  lInstance: TTaurusTLSSslSocket;
  lContext: TTaurusTLSSslSocketCtx;

begin
  Result:=1; //
  if not Assigned(ASSL) then
    Exit; // ssl parameter can be null if the SSL_CTX is changing before the
          // SSL object is allocated.

  try
    LErr:=GStack.WSGetLastError;
    try
      lInstance:=TTaurusTLSSslSocket(AEx);
        if not Assigned(lInstance) then
          Exit;

        lContext:=lInstance.FCtx;
        if not Assigned(lContext) then
          Exit;

        lResult:=False;
        lContext.DoOnSecurityCheck(lInstance, AOp, ABits, ANid, AOther, lResult);

        if lResult then
          Result:=1
        else
          Result:=0;
    finally
      GStack.WSSetLastError(LErr);
    end;
  except
    Result:=0; // Failed
  end;
end;

class function TTaurusTLSSslSocket.CbSslVerify(const APreVerify: TIdC_INT;
  ACtx: PX509_STORE_CTX): TIdC_INT;
var
  lInstance: TTaurusTLSSslSocket;
  lContext: TTaurusTLSSslSocketCtx;
  lSSL: PSSL;
  lErr: integer;
  lResult, lContinue: boolean;

begin
  Result:=APreVerify;

  if not Assigned(ACtx) then // this shouldn't happen ever
    Exit;

  try
    lErr:=GStack.WSGetLastError;
    try
      lSSL:=X509_STORE_CTX_get_ex_data(ACtx, SSL_get_ex_data_X509_STORE_CTX_idx());
      if not Assigned(lSSL) then
        Exit;

      lResult:=APreVerify = 1;
      lContinue:=True;

      lInstance:=GetInstanceFromSSL(lSSL);
      lContext:=lInstance.FCtx;
      if Assigned(lContext) then
      begin
        lContext.DoOnVerifyCertificate(lInstance, ACtx, lResult, lContinue);
        if lContinue then Result:=1 else Result:=0;
        if lResult then
          X509_STORE_CTX_set_error(ACtx, X509_V_OK);
      end;
    finally
      GStack.WSSetLastError(lErr);
    end;
  except
    Result:=0;
  end;
end;

{ TTaurusTLSSslSession }

constructor TTaurusTLSSslSession.Create(ASocket: TTaurusTLSSslSocket);
begin
  inherited Create;
  if Assigned(ASocket) and (ASocket.State in [seEstablished..seReleased]) and
    Assigned(ASocket.SSL) then
    FSession:=SSL_get1_session(ASocket.SSL)
  else
    FSession:=nil;
end;

destructor TTaurusTLSSslSession.Destroy;
begin
  SSL_SESSION_free(FSession);
  inherited;
end;

{ TTaurusTLSClientSocket }

function TTaurusTLSClientSocket.GetClientCtx: TTaurusTLSSslClientSocketCtx;
begin
  Result:=Ctx as TTaurusTLSSslClientSocketCtx;
end;

procedure TTaurusTLSClientSocket.SetECHStatus(AECHStatus: TTaurusECHClientStatus);
begin
  FECHStatus:=AECHStatus;
end;

procedure TTaurusTLSClientSocket.SetupConnection;
var
  lRetCode: TIdC_INT;
  lContext: TTaurusTLSSslClientSocketCtx;
  lECHOuterSNIRaw: RawByteString;
  lOuterSNI: PIdAnsiChar;
  lECHNoOuterVal: TIdC_INT;
  lECHStore: TTaurusTLSECHStore; //PALOFF "Created and freed objects"
  lIdentity: RawByteString;
  lIdentityPtr: PIdAnsiChar;

begin
  lContext:=ClientCtx;

  if not Assigned(lContext) then
    ETaurusTLSSslClientSocketSetupError.RaiseWithMessage(RSOSSLModeNotSet);

  lIdentity:=lContext.Identity;
  lIdentityPtr:=PIdAnsiChar(lIdentity);

  // 1. Session ticket for resumption
  if Assigned(FSessionToResume) then
    SSL_set_session(FSSL, FSessionToResume.SSLSession);

  SetECHStatus(echCliNotConfigured);

  // 2. Configure Hostname Verification (skips hostname check if Identity is empty)
  SetupHostnameVerification;

  // 3. SNI Mode & IP Literal Validation
  if lContext.SNIMode = csmDisabled then
    Exit;

  if lContext.IsIdentityIP then
  begin
    if lContext.UseECH then
      { TODO : To make ResourceString }
      ETaurusTLSSslClientSocketSetupError.RaiseWithMessageFmt(
        'Cannot configure real ECH mode for an IP address (%s). A domain name is required.',
        [string(lIdentity)]
      );

    if lContext.UseGREASE then
      SSL_set_options(FSSL, SSL_OP_ECH_GREASE);

    Exit; // IP literals never emit cleartext SNI
  end;

  // 4. Strict ECH Guard
  if lContext.UseECH and (lContext.ECHConfigListRaw = '') then
    { TODO : To make ResourceString }
    ETaurusTLSSslClientSocketSetupError.RaiseWithMessage(
      'ECH was forced, but no ECHConfigList was provided.');

  // 5. Real ECH Path (csmECH, csmECHNoOuter)
  if lContext.UseECH then
  begin
    lECHStore:=TTaurusTLSECHStore.Create; //PALOFF "Created and freed objects"
    try
      lECHStore.SetConfigList(lContext.ECHConfigListRaw);
      lECHStore.Attach(FSSL);
    finally
      lECHStore.Free;
    end;

    lECHOuterSNIRaw:=lContext.ECHOuterSNIRaw;
    lECHNoOuterVal:=lContext.ECHNoOuterVal;
    if (lECHNoOuterVal = 0) and (lECHOuterSNIRaw <> '') then
      lOuterSNI:=PIdAnsiChar(lECHOuterSNIRaw)
    else
      lOuterSNI:=nil;

    lRetCode:=SSL_ech_set1_server_names(FSSL, lIdentityPtr, lOuterSNI,
      lECHNoOuterVal);

    if lRetCode <= 0 then
      ETaurusTLSSslClientSocketHostNameError.RaiseException(
        FSSL, lRetCode, RMSG_SetECHHostNamesSetup_err);
  end
  // 6. Standard SNI or GREASE Path (csmStandardSNI, csmECHGrease, csmECHGreaseDiscovery)
  else
  begin
    // Enable GREASE on session if active
    if lContext.UseGREASE then
      SSL_set_options(FSSL, SSL_OP_ECH_GREASE);

    // Only send cleartext SNI if an Identity is populated (skips if Identity is empty in discovery)
    if lIdentity <> '' then
    begin
      lRetCode:=SSL_set_tlsext_host_name(FSSL, lIdentityPtr);
      if lRetCode <= 0 then
        ETaurusTLSSslClientSocketHostNameError.RaiseException(
          FSSL, lRetCode, RSSSLSettingTLSHostNameError_2);
    end;
  end;
end;

procedure TTaurusTLSClientSocket.SetupHostnameVerification;
var
  lParams: TTaurusTLSX509VerifyParamSSL; // PALOFF 'Created and freed objects'
  lTargetName: RawByteString;
  lContext: TTaurusTLSSslClientSocketCtx;
  lIsIP: Boolean;

begin
  lContext:=ClientCtx;
  if not lContext.VerifyHostname then
    Exit;

  // 1. Determine the logical identity and IP flag
  lTargetName:=lContext.Identity;
  if lTargetName = '' then
    Exit;

  // 2. Get the connection-specific verification parameters (cloned from SSL_CTX)
  lParams:=TTaurusTLSX509VerifyParamSSL.Create(FSSL);
  try

    lIsIP:=lContext.IsIdentityIP; // Use the pre-computed, cached property

    // 3. Bind the primary identity directly to the connection's parameter block.
    // This preserves all other inherited parameters (CRL flags, depth, etc.)
    if lIsIP then
      // IPv4/IPv6 Literal Validation
      lParams.SetIpAddressA(lTargetName)
    else
      // Standard DNS / Wildcard Validation
      lParams.AddHostA(lTargetName);
  finally
    lParams.Free;
  end;
end;

function TTaurusTLSClientSocket.Connect(const pHandle: TIdStackSocketHandle;
  ASessionToResume: TTaurusTLSSslSession): boolean;
begin
  FSessionToResume:=ASessionToResume;
  Result:=Connect(pHandle);
end;

function TTaurusTLSClientSocket.DoHandshakeIteration: TTaurusTLSSslSocketState;
var
  lRet, lErr: Integer;
  lContext: TTaurusTLSSslClientSocketCtx;

  procedure ProcessECHStatus(const ARet: Integer);
  var
    lStatus: TIdC_INT;
    lInner, lOuter: PIdAnsiChar;
    lECHConfigBuf: PByte;
    lECHConfigLen: NativeUInt;
    lNewConfigBase64: string;
  begin
    lInner:=nil;
    lOuter:=nil;
    try
      lStatus:=SSL_ech_get1_status(SSL, @lInner, @lOuter);

      case lStatus of
        // --- 1. Real ECH Succeeded ---
        SSL_ECH_STATUS_SUCCESS,
        SSL_ECH_STATUS_BACKEND:
          SetECHStatus(echCliSuccess);

        // --- 2. GREASE Succeeded over cleartext SNI ---
        SSL_ECH_STATUS_GREASE:
          SetECHStatus(echCliNone);

        // --- 3. Server returned retry_configs (stale key or GREASE probe response) ---
        SSL_ECH_STATUS_GREASE_ECH,
        SSL_ECH_STATUS_FAILED_ECH,
        SSL_ECH_STATUS_FAILED_ECH_BAD_NAME:
          begin
            if lContext.SNIMode = csmECHGrease then
            begin
              // Anti-ossification mode: ignore retry_configs and keep current connection [4]
              SetECHStatus(echCliNone);
            end
            else
            begin
              // Bootstrap (csmECHGreaseDiscovery) / Strict ECH (csmECH, csmECHNoOuter):
              // Extract keys, notify application, and close session for clean reconnect [1.1, 1.3.1]
              SetECHStatus(echCliFailed);
              lECHConfigBuf:=nil;
              lECHConfigLen:=0;

              if SSL_ech_get1_retry_config(SSL, @lECHConfigBuf, @lECHConfigLen) > 0 then
              begin
                try
                  if (lECHConfigBuf <> nil) and (lECHConfigLen > 0) then
                  begin
                    lNewConfigBase64 := EncodeConfigList(lECHConfigBuf, lECHConfigLen);
                    lContext.DoOnECHConfigRetry(Self, lNewConfigBase64);
                  end;
                finally
                  OPENSSL_free(lECHConfigBuf);
                end;

                SetECHStatus(echCliRetryConfig);
                Result := seClosed; // Signal clean close so IOHandler can reconnect with fresh ECH keys [1.3.1]
              end
              else
              begin
                { TODO : To make ResourceString }
                ETaurusTLSECHRejectedError.RaiseException(FSSL, ARet,
                  'ECH Handshake failed. The server rejected the key and provided no retry configuration.'
                );
              end;
            end;
          end;

        // --- 4. Server lacks ECH support (or was not configured/tried) ---
        SSL_ECH_STATUS_NOT_TRIED,
        SSL_ECH_STATUS_NOT_CONFIGURED:
          begin
            if lContext.UseECH then
            begin
              { TODO : To make ResourceString }
              ETaurusTLSECHDowngradeError.RaiseException(FSSL, ARet,
                'ECH Handshake bypassed. Possible downgrade attack or configuration mismatch.'
              );
            end
            else
            begin
              SetECHStatus(echCliNone);
              if ARet <= 0 then
                Result:=seClosed; // Signal clean close so IOHandler can reconnect with cleartext SNI
            end;
          end;

        // --- 5. Inner Server Name / Cert Mismatch ---
        SSL_ECH_STATUS_BAD_NAME:
          begin
            { TODO : To make ResourceString }
            ETaurusTLSECHBadNameError.RaiseException(FSSL, ARet,
              'ECH Handshake completed but the server certificate verification failed.'
            );
          end;

      else
        // Covers SSL_ECH_STATUS_FAILED (0), SSL_ECH_STATUS_BAD_CALL (-100), etc.
        if ARet <= 0 then
        begin
          { TODO : To make ResourceString }
          ETaurusTLSECHProtocolError.RaiseException(FSSL, ARet,
            'ECH Handshake failed due to an internal OpenSSL or protocol error.'
          );
        end;
      end;
    finally
      if Assigned(lInner) then
        OPENSSL_free(lInner);
      if Assigned(lOuter) then
        OPENSSL_free(lOuter);
    end;
  end;

begin
  lContext:=ClientCtx;
  ClearError;
  Result:=seError;

  lRet:=SSL_connect(SSL);

  if lRet > 0 then
  begin
    Result:=seEstablished;
    SetECHStatus(echCliNone);

    // Evaluate ECH/GREASE status if active
    if (lContext.UseECH or lContext.UseGREASE) and (not lContext.IsIdentityIP) then
      ProcessECHStatus(lRet);

    // Only validate certificate and cache session if handshake reached established state [1.1]
    if Result = seEstablished then
    begin
      CheckPeerCertificateValidationResult;
//      lContext.SetSessionToResume(SSL);
    end;
  end
  else
  begin
    lErr:=GetSSLError(lRet);
    case lErr of
      SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE:
        begin
          // Handshake in progress: signal caller to wait and retry
          Result:=seHandshaking;
        end;

      SSL_ERROR_SYSCALL:
        begin
          { TODO : To make ResourceString }
          ETaurusTLSSslSocketConnectionReset.RaiseException(
            FSSL, lErr, 'Handshake reset by peer.'
          );
        end;

      SSL_ERROR_SSL:
        begin
          // If ECH was active, evaluate OpenSSL ECH failure status codes centrally
          if (lContext.UseECH or lContext.UseGREASE) and (not lContext.IsIdentityIP) then
            ProcessECHStatus(lRet)
          else
            ETaurusTLSHandshakeError.RaiseExceptionCode(lErr, lRet, 'Fatal handshake error.');
        end;

    else
      ETaurusTLSHandshakeError.RaiseExceptionCode(lErr, lRet, 'Fatal handshake error.');
    end;
  end;
end;

function TTaurusTLSClientSocket.DoShutdown: TTaurusTLSSslSocketState;
begin
  try
    Result:=inherited DoShutdown;
  finally
    FreeAndNil(FSessionToResume);
  end;
end;

{ TTaurusTLSBuilderCustomMetaField }

constructor TTaurusTLSBuilderCustomMetaField.Create(
  AParent: TTaurusTLSSslSocketCtxBuilder);
begin
  Assert(Assigned(AParent), 'AParent must not be ''nil''.'); // Do not localize
  FParent:=AParent;
end;

procedure TTaurusTLSBuilderCustomMetaField.Lock;
begin
  Parent.Lock;
end;

procedure TTaurusTLSBuilderCustomMetaField.Unlock;
begin
  Parent.Unlock;
end;

procedure TTaurusTLSBuilderCustomMetaField.SetDirty;
begin
  Parent.SetDirty;
end;

{ TTaurusTLSMetaX509VerifyParam }

constructor TTaurusTLSMetaX509VerifyParam.Create(
  AParent: TTaurusTLSSslSocketCtxBuilder);
begin
  inherited Create(AParent);
  FHosts:=THosts.Create;
  FIpAddresses:=TIPAddresses.Create;
  FEmails:=TEmails.Create;
end;

destructor TTaurusTLSMetaX509VerifyParam.Destroy;
begin
  FreeAndNil(FHosts);
  FreeAndNil(FEmails);
  FreeAndNil(FIpAddresses);
  inherited;
end;

function TTaurusTLSMetaX509VerifyParam.IsPropSet(
  const AProp: TProperty): boolean;
begin
  Result:=AProp in FProps;
end;

function TTaurusTLSMetaX509VerifyParam.GetHost(
  const Item: TIdC_INT): string;
begin
  Lock;
  try
    Result:=FHosts[Item];
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.ResetProp(const AProp: TProperty);
begin
  Exclude(FProps, AProp);
  inherited SetDirty;
end;

procedure TTaurusTLSMetaX509VerifyParam.SetDirty(const AProp: TProperty);
begin
  Include(FProps, AProp);
  inherited SetDirty;
end;

function TTaurusTLSMetaX509VerifyParam.GetHostCount: TIdC_INT;
begin
  Lock;
  try
    Result:=FHosts.Count;
  finally
    Unlock;
  end;
end;

function TTaurusTLSMetaX509VerifyParam.GetEmail(
  const Item: TIdC_INT): string;
begin
  Lock;
  try
    Result:=FEmails[Item];
  finally
    Unlock;
  end;
end;

function TTaurusTLSMetaX509VerifyParam.GetEmailCount: TIdC_INT;
begin
  Lock;
  try
    Result:=FEmails.Count;
  finally
    Unlock;
  end;
end;

function TTaurusTLSMetaX509VerifyParam.GetIpAddress(
  const Item: TIdC_INT): string;
begin
  Lock;
  try
    Result:=FIpAddresses[Item];
  finally
    Unlock;
  end;
end;

function TTaurusTLSMetaX509VerifyParam.GetIpAddressCount: TIdC_INT;
begin
  Lock;
  try
    Result:=FIpAddresses.Count;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.SetDepth(
  const AValue: TIdC_INT);
begin
  if FDepth = AValue then
    Exit;
  Lock;
  try
    FDepth:=AValue;
    SetDirty(vfDefDepth);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.SetPurpose(
  const AValue: TTaurusTLSX509Purpose);
begin
  if FPurpose = AValue then
    Exit;
  Lock;
  try
    FPurpose:=AValue;
    SetDirty(vfDefPurpose);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.SetSecurityBits(
  const AValue: TTaurusTLSSecurityBits);
begin
  if FSecurityBits = AValue then
    Exit;
  Lock;
  try
    FSecurityBits:=AValue;
    SetDirty(vfDefSecurityBits);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.SetTime(
  const AValue: TDateTime);
begin
  if SameDateTime(FTime, AValue) then
    Exit;
  Lock;
  try
    FTime:=AValue;
    SetDirty(vfDefTime);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.SetVerifyFlags(
  const AValue: TTaurusTLSX509VerifyFlags);
begin
  if FVerifyFlags = AValue then
    Exit;
  Lock;
  try
    FVerifyFlags:=AValue;
    SetDirty(vfDefFlVerify);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.SetHostCheckFlags(
  const AValue: TTaurusTLSX509HostCheckFlags);
begin
  if FHostCheckFlags = AValue then
    Exit;
  Lock;
  try
    FHostCheckFlags:=AValue;
    SetDirty(vfDefFlHostCheck);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.SetInheritanceFlags(
  const AValue: TTaurusTLSX509InheritanceFlags);
begin
  if FInheritanceFlags = AValue then
    Exit;
  Lock;
  try
    FInheritanceFlags:=AValue;
    SetDirty(vfDefFlInheritance);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.AddHost(const AValue: string);
begin
  Lock;
  try
    FHosts.Add(AValue);
    SetDirty(vfDefHosts);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.SetHost(
  const Item: TIdC_INT; const AValue: string);
begin
  Lock;
  try
    if AValue = '' then
      FHosts.Delete(Item)
    else if Item > HostCount then
      FHosts.Add(AValue)
    else
      FHosts[Item]:=AValue;
    SetDirty(vfDefHosts);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.DeleteHost(
  const Item: TIdC_INT);
begin
  Lock;
  try
    FHosts.Delete(Item);
    SetDirty(vfDefHosts);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.AddEMail(const AValue: string);
begin
  Lock;
  try
    FEMails.Add(AValue);
    SetDirty(vfDefEmails);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.SetEmail(
  const Item: TIdC_INT; const AValue: string);
begin
  Lock;
  try
    if AValue = '' then
      FEmails.Delete(Item)
    else if Item > HostCount then
      FEMails.Add(AValue)
    else
      FEMails[Item]:=AValue;
    SetDirty(vfDefEmails);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.DeleteEmail(
  const Item: TIdC_INT);
begin
  Lock;
  try
    FEmails.Delete(Item);
    SetDirty(vfDefEmails);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.AddIpAddress(const AValue: string);
begin
  Lock;
  try
    FIPAddresses.Add(AValue);
    SetDirty(vfDefIPAddresses);
  finally
    Unlock;
  end;
end;

function TTaurusTLSMetaX509VerifyParam.BuildParam: TTaurusTLSX509VerifyParam;
var
  i, lHigh: integer;

begin
  Result:=TTaurusTLSX509VerifyParam.Create;
  try
    if IsSecurityBitsSet then
      Result.SecurityBits:=SecurityBits;

    if IsDepthSet then
      Result.Depth:=Depth;

    if IsPurposeSet then
      Result.Purpose:=Purpose;

    if IsTimeSet then
      Result.Time:=Time;

    if IsVerifyFlagsSet then
      Result.VerifyFlags:=VerifyFlags;

    if IsInheritanceFlagsSet then
      Result.InheritanceFlags:=InheritanceFlags;

    if IsHostCheckFlagsSet then
      Result.HostCheckFlags:=HostCheckFlags;

    // Add hosts
    if IsHostsSet then
      for i:=0 to HostCount-1 do
        Result.AddHost(Hosts[i]);

    // Add IP Address(es)
    if IsIPAddressesSet then
    begin
      lHigh:=IpAddressCount;
      if IsX509StoreMultiIPSupported then
      begin
        for i:=0 to IpAddressCount-1 do
          Result.AddIPAddress(IpAddresses[i]);
        end
        else if lHigh > 0 then
          Result.SetIpAddress(IpAddresses[0]);
    end;

    if IsEmailsSet then
    begin
      lHigh:=EmailCount;
      if IsX509StoreMultiEmailSupported  then
      begin
        for i:=0 to EmailCount-1 do
          Result.AddEmail(Emails[i]);
      end
      else if lHigh > 0 then
        Result.SetEMail(Emails[0])
    end;

  except
    FreeAndNil(Result);
    raise;
  end;

end;

procedure TTaurusTLSMetaX509VerifyParam.SetIpAddress(
  const Item: TIdC_INT; const AValue: string);
begin
  Lock;
  try
    if AValue = '' then
      FIPAddresses.Delete(Item)
    else if Item > HostCount then
      FIPAddresses.Add(AValue)
    else
      FIPAddresses[Item]:=AValue;
    SetDirty(vfDefIPAddresses);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.DeleteIpAddress(
  const Item: TIdC_INT);
begin
  Lock;
  try
    FIpAddresses.Delete(Item);
    SetDirty(vfDefIPAddresses);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.ResetDepth;
begin
  if not IsPropSet(vfDefDepth) then
    Exit;
  Lock;
  try
    ResetProp(vfDefDepth);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.ResetPurspose;
begin
  if not IsPropSet(vfDefPurpose) then
    Exit;
  Lock;
  try
    ResetProp(vfDefPurpose);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.ResetSecurityBits;
begin
  if not IsPropSet(vfDefSecurityBits) then
    Exit;
  Lock;
  try
    ResetProp(vfDefSecurityBits);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.ResetTime;
begin
  if not IsPropSet(vfDefTime) then
    Exit;
  Lock;
  try
    ResetProp(vfDefTime);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.ResetInheritanceFlags;
begin
  if not IsPropSet(vfDefFLInheritance) then
    Exit;
  Lock;
  try
    ResetProp(vfDefFLInheritance);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.ResetHostCheckFlags;
begin
  if not IsPropSet(vfDefFlHostCheck) then
    Exit;
  Lock;
  try
    ResetProp(vfDefFlHostCheck);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.ResetVerifyFlags;
begin
  if not IsPropSet(vfDefFlVerify) then
    Exit;
  Lock;
  try
    ResetProp(vfDefFlVerify);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.ResetHosts;
begin
  if not IsPropSet(vfDefHosts) then
    Exit;
  Lock;
  try
    ResetProp(vfDefHosts);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.ResetEMails;
begin
  if not IsPropSet(vfDefEmails) then
    Exit;
  Lock;
  try
    ResetProp(vfDefEmails);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.ResetIPAddresses;
begin
  if not IsPropSet(vfDefIPAddresses) then
    Exit;
  Lock;
  try
    ResetProp(vfDefIpAddresses);
  finally
    Unlock;
  end;
end;

end.
