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
///   X509 Certificate classes.
/// </summary>
unit TaurusTLS_X509;
{$I TaurusTLSLinkDefines.inc}

interface

uses
  IdCTypes,
  IdGlobal,
  IdGlobalProtocols,
  TaurusTLSHeaders_evp,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_x509,
  TaurusTLSHeaders_x509v3,
  TaurusTLS_Utils,
  Classes;

type
  /// <summary>
  ///   A 4-byte value for retreiving a value as 4 bytes, 2 words, an integer,
  ///   and as an unsigned integer.
  /// </summary>
  TTaurusTLSULong = packed record
    case Byte of
      0:
        (B1, B2, B3, B4: UInt8);
      1:
        (W1, W2: UInt16);
      2:
        (L1: Int32);
      3:
        (C1: UInt32);
  end;

  /// <summary>
  ///   A record that includes a length and pointer to bytes.
  /// </summary>
  TTaurusTLSByteArray = record
    _Length: TIdC_UINT;
    Data: PByte;
  end;

  TTaurusTLSX509 = class;

  /// <summary>
  ///   A X509 name encapsolated in an object for information.
  /// </summary>
  TTaurusTLSX509Name = class(TObject)
{$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    fX509Name: PX509_NAME;
    function GetStrByNID(const ANid: TIdC_INT): String; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetOneLine: String; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetHash: TTaurusTLSULong; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetHashAsString: String; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetCommonName: String; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetOrginization: String; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetUnit: String; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetEMail: String; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetCity: String; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetCountry: String; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetProvidence: String; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetStreetAddress: String; {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    /// <summary>
    ///   Creates a new instance of TTaurusTLSX509Name.
    /// </summary>
    /// <param name="aX509Name">
    ///   The associated OpenSSL X509_NAME object associated with the new
    ///   instance.
    /// </param>
    constructor Create(aX509Name: PX509_NAME);
    //
    /// <summary>
    ///   A hash of the X509 name.
    /// </summary>
    property Hash: TTaurusTLSULong read GetHash;
    /// <summary>
    ///   A hash of the X509 name as a hexidecimal string.
    /// </summary>
    property HashAsString: string read GetHashAsString;
    /// <summary>
    ///   Prints information about the X509 Name.
    /// </summary>
    property OneLine: string read GetOneLine;
    /// <summary>
    ///   Common name for X509 Name. Usuuually, this is the hostname but can be
    ///   an E-Mail address. TaurusTLS checks this value in the <see
    ///   cref="TaurusTLS_X509|TTaurusTLSX509.Subject" /> property to see that
    ///   it matches the hostname you specified for the connection if the <see
    ///   cref="TaurusTLS|TTaurusTLSOptions.VerifyHostname">VerifyHostname
    ///   </see> property is true.
    /// </summary>
    property CommonName: String read GetCommonName;
    /// <summary>
    ///   The name of the organization of the Common Name.
    /// </summary>
    property Organization: String read GetOrginization;
    /// <summary>
    ///   The organizational unit for the Common Name.
    /// </summary>
    property _Unit: String read GetUnit;
    /// <summary>
    ///   E-Mail address for the Common Name.
    /// </summary>
    property EMail: String read GetEMail;
    /// <summary>
    ///   Street Address for the Common Name.
    /// </summary>
    property StreetAddress: String read GetStreetAddress;
    /// <summary>
    ///   City, Town, or Village of the Common Name.
    /// </summary>
    property City: String read GetCity;
    /// <summary>
    ///   State or Providence of the Common Name.
    /// </summary>
    property Providence: String read GetProvidence;
    /// <summary>
    ///   The nation of the Common Name.
    /// </summary>
    property Country: String read GetCountry;
    //
    /// <summary>
    ///   The associated OpenSSL Object for the X509_NAME.
    /// </summary>
    property CertificateName: PX509_NAME read fX509Name;
  end;

  /// <summary>
  ///   The anscestor of most of the X509 Information objects.
  /// </summary>
  TTaurusTLSX509Info = class(TObject)
{$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    // Do not free this here because it belongs
    // to the X509 or something else.
    FX509: PX509;
  public

    /// <summary>
    ///   Constructor for TTaurus?TLSX509Info.
    /// </summary>
    /// <param name="aX509">
    ///   Associated OpenSSL X509 Object.
    /// </param>
    constructor Create(aX509: PX509); virtual;
    /// <summary>
    ///   The OpenSSL X509 object associated with this object.
    /// </summary>
    property Certificate: PX509 read FX509;
  end;

  /// <summary>
  ///   Fingerprint expressed using several different cryptographic hashing
  ///   algorithms.
  /// </summary>
  TTaurusTLSX509Fingerprints = class(TTaurusTLSX509Info)
{$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    function GetSHA224: TTaurusTLSLEVP_MD; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetSHA224AsString: String; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetSHA256: TTaurusTLSLEVP_MD; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetSHA256AsString: String; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetSHA384: TTaurusTLSLEVP_MD; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetSHA384AsString: String; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetSHA512: TTaurusTLSLEVP_MD; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetSHA512AsString: String; {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    { IMPORTANT!!!

      FIPS approves only these algorithms for hashing.
      SHA-224
      SHA-256
      SHA-384
      SHA-512

      http://csrc.nist.gov/CryptoToolkit/tkhash.html
    }
    /// <summary>
    ///   Fingerprint expressed as a binary SHA-224 checksum.
    /// </summary>
    property SHA224: TTaurusTLSLEVP_MD read GetSHA224;
    /// <summary>
    ///   Fingerpint expressed as a hexidecimal SHA-224 checksum.
    /// </summary>
    property SHA224AsString: String read GetSHA224AsString;
    /// <summary>
    ///   Fingerprint expressed as a binary SHA-256 checksum.
    /// </summary>
    property SHA256: TTaurusTLSLEVP_MD read GetSHA256;
    /// <summary>
    ///   Fingerprint expressed as a hexidecimal SHA-256 checksum.
    /// </summary>
    property SHA256AsString: String read GetSHA256AsString;
    /// <summary>
    ///   Fingerprint expressed as a binary SHA-384 checksum.
    /// </summary>
    property SHA384: TTaurusTLSLEVP_MD read GetSHA384;
    /// <summary>
    ///   Fingerprint expressed as a hexidecimal SHA-384 checksum.
    /// </summary>
    property SHA384AsString: String read GetSHA384AsString;
    /// <summary>
    ///   Fingerprint expressed as a binary SHA-512 checksum.
    /// </summary>
    property SHA512: TTaurusTLSLEVP_MD read GetSHA512;
    /// <summary>
    ///   Fingerprint expressed as a hexidecimal SHA-512 checksum.
    /// </summary>
    property SHA512AsString: String read GetSHA512AsString;
  end;

  /// <summary>
  ///   X509 Signature information.
  /// </summary>
  TTaurusTLSX509SigInfo = class(TTaurusTLSX509Info)
{$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    Fsig_alg: PX509_ALGOR;
    Fsignature: PASN1_BIT_STRING;
    function GetSignature: String; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetSigType: TIdC_INT; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetSigTypeAsString: String; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetAlgorithm: String; {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    /// <summary>
    ///   Creates a new instance of the object.
    /// </summary>
    /// <param name="aX509">
    ///   The OpenSSL X509 Certificate object associated with it.
    /// </param>
    constructor Create(aX509: PX509); override;
    /// <summary>
    ///   Signature expressed in hexidecimal.
    /// </summary>
    property Signature: String read GetSignature;
    /// <summary>
    ///   The Object Identifier (OID) for the signature's algorithm.
    /// </summary>
    property Algorithm: String read GetAlgorithm;
    /// <summary>
    ///   signature algorithm Numerical Identifier (NID) for the signature type.
    /// </summary>
    property SigType: TIdC_INT read GetSigType;
    /// <summary>
    ///   Signature type expressed as a string.
    /// </summary>
    property SigTypeAsString: String read GetSigTypeAsString;
  end;

  /// <summary>
  ///   Information about the X509 Public Key.
  /// </summary>
  TTaurusTLSX509PublicKey = class(TTaurusTLSX509Info)
{$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    function GetModulus: String; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetExponent: String; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetAlgorithm: String; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetBits: TIdC_INT; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetSize: TIdC_INT; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetSecurityBits: TIdC_INT; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetEncoding: String; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetEncodingSize: TIdC_INT; {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    /// <summary>
    ///   Algorithm for the X509 Public Key.
    /// </summary>
    property Algorithm: String read GetAlgorithm;
    /// <summary>
    ///   Number of bits in the signature algorithm.
    /// </summary>
    property Bits: TIdC_INT read GetBits;
    /// <summary>
    ///   Number of security bits in the algorithm.
    /// </summary>
    property SecurityBits: TIdC_INT read GetSecurityBits;
    /// <summary>
    ///   maximum suitable size for the output buffers for the algorithm.
    /// </summary>
    property Size: TIdC_INT read GetSize;
    /// <summary>
    ///   Public key encoding as a hexidecimal string.
    /// </summary>
    property Encoding: String read GetEncoding;
    /// <summary>
    ///   Size of the public key encoding.
    /// </summary>
    property EncodingSize: TIdC_INT read GetEncodingSize;
    /// <summary>
    ///   RSA Modulus expressed as a hexidecimal string.
    /// </summary>
    /// <remarks>
    ///   This may be empty if the public key is not a RSA key.
    /// </remarks>
    property Modulus: String read GetModulus;
    /// <summary>
    ///   RSA Exponent expressed as a hexidecimal string.
    /// </summary>
    /// <remarks>
    ///   This may be empty if the public key is not a RSA key.
    /// </remarks>
    property Exponent_: String read GetExponent;
  end;

  /// <summary>
  ///   X509 Certificate extensions list for internal use.
  /// </summary>
  TTaurusTLSX509Exts = class(TTaurusTLSX509Info)
{$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    // X509_get_ext
    function GetExtension(const AIndex: TIdC_INT): PX509_EXTENSION;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetExtensionByNid(const ANid: TIdC_INT): PX509_EXTENSION;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetCount: TIdC_INT; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetExtensionCritical(const AIndex: TIdC_INT): boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetExtensionName(const AIndex: TIdC_INT): string;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetExtensionValues(const AIndex: TIdC_INT): string;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    /// <summary>
    ///   OpenSSL X509 Extension object by numeric identifier (NID).
    /// </summary>
    /// <param name="ANid">
    ///   Numeric Identifier (NID) of the extension.
    /// </param>
    property ExtensionByNid[const ANid: TIdC_INT]: PX509_EXTENSION
      read GetExtensionByNid;
    /// <summary>
    ///   OpenSSL Extension object by position.
    /// </summary>
    property Extensions[const AIndex: TIdC_INT]: PX509_EXTENSION
      read GetExtension; default;
    /// <summary>
    ///   True if the extension is critical or False if it is not critical.
    /// </summary>
    /// <param name="AIndex">
    ///   Position of the extension in the list.
    /// </param>
    property ExtensionCritical[const AIndex: TIdC_INT]: boolean
      read GetExtensionCritical;
    /// <summary>
    ///   Extension name
    /// </summary>
    /// <param name="AIndex">
    ///   Position of the extension in the list.
    /// </param>
    property ExtensionName[const AIndex: TIdC_INT]: string
      read GetExtensionName;
    /// <summary>
    ///   Value of the extension expressed as a hexidecimal string.
    /// </summary>
    /// <param name="AIndex">
    ///   Position of the extension in the list.
    /// </param>
    property ExtensionValues[const AIndex: TIdC_INT]: string
      read GetExtensionValues;
    /// <summary>
    ///   Number of X509 Extensions in Certificcate.
    /// </summary>
    property Count: TIdC_INT read GetCount;
  end;

  /// <summary>
  ///   Authority Key ID information.
  /// </summary>
  TTaurusTLSX509AuthorityKeyID = class(TTaurusTLSX509Info)
{$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    function GetIssuer(const AIndex: TIdC_INT): String; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetKeyId: String; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetSerial: TIdC_INT64; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIssuerCount: TIdC_INT; {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    /// <summary>
    ///   authority key identifier.
    /// </summary>
    property KeyID: String read GetKeyId;
    /// <summary>
    ///   authority certificate serial number.
    /// </summary>
    property Serial: TIdC_INT64 read GetSerial;
    /// <summary>
    ///   Issuer name.
    /// </summary>
    /// <param name="AIndex">
    ///   Position of the issuer in the list.
    /// </param>
    property Issuer[const AIndex: TIdC_INT]: String read GetIssuer;
    /// <summary>
    ///   The number of issuers.
    /// </summary>
    property IssuerCount: TIdC_INT read GetIssuerCount;
  end;
  /// <summary>
  ///   Warnings from OpenSSL about the X509 Certificate. Such warnings
  ///   sometimes are reasons for rejecting the certificate.
  /// </summary>
  TTaurusTLSX509Warnings = class(TTaurusTLSX509Info)
{$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    function GetObsoleteV1: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetSelfSigned: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetSubjectAndIssuerMatch: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    /// <summary>
    ///   The certificate is an obsolete version 1 certificate.
    /// </summary>
    property ObsoleteV1: Boolean read GetObsoleteV1;
    /// <summary>
    ///   The certificate is self issued (that is subject and issuer names
    ///   match).
    /// </summary>
    property SelfSigned: Boolean read GetSelfSigned;
    /// <summary>
    ///   The subject and issuer names match and extension values imply it is
    ///   self signed.
    /// </summary>
    property SubjectAndIssuerMatch: Boolean read GetSubjectAndIssuerMatch;
  end;
  /// <summary>
  ///   Errors from OpenSSL about the X509 Certificate. Such certificates should
  ///   be rejected.
  /// </summary>
  TTaurusTLSX509Errors = class(TTaurusTLSX509Info)
{$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    function GetInvalidInconsistantValues: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetInvalidPolicy: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetUnhandledCriticalExtension: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetNoFingerprint: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    /// <summary>
    ///   Failed to compute the internal SHA1 hash value of the certificate or
    ///   CRL.
    /// </summary>
    property NoFingerprint: Boolean read GetNoFingerprint;
    /// <summary>
    ///   Some certificate extension values are invalid or inconsistent. The
    ///   certificate should be rejected.
    /// </summary>
    property InvalidInconsistantValues: Boolean
      read GetInvalidInconsistantValues;
    /// <summary>
    ///   The NID_certificate_policies certificate extension is invalid or
    ///   inconsistent. The certificate should be rejected.
    /// </summary>
    property InvalidPolicy: Boolean read GetInvalidPolicy;
    /// <summary>
    ///   The certificate contains an unhandled critical extension.
    /// </summary>
    property UnhandledCriticalExtension: Boolean
      read GetUnhandledCriticalExtension;
  end;

  /// <summary>
  ///   Encapsolation of X509 Alternative Subject Names.
  /// </summary>
  TTaurusTLSX509AltSubjectNames = class(TTaurusTLSX509Info)
{$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    FGeneralNames: PGENERAL_NAMES;
    procedure GetGeneralNames; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetItems(const AIndex: TIdC_INT): string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetItemsCount: TIdC_INT; {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    constructor Create(aX509: PX509); override;
    destructor Destroy; override;
    /// <summary>
    ///   Alternative Subject Name in list.
    /// </summary>
    /// <param name="AIndex">
    ///   Position of the Alternative Subject Name in the list.
    /// </param>
    property Items[const AIndex: TIdC_INT]: string read GetItems; default;
    /// <summary>
    ///   Number of Alternative Subject Names in list.
    /// </summary>
    property ItemsCount: TIdC_INT read GetItemsCount;
  end;
  /// <summary>
  ///   Type used to specify a Key Usage value.
  /// </summary>
  TTaurusTLSX509KeyUse = (
  /// <summary>
  ///   Digital signatures
  /// </summary>
    DigitalSignature,
  /// <summary>
  ///   Prove Integrety and ownership of data.
  /// </summary>
    NonRepudiation,
  /// <summary>
  ///   Encrypting a key
  /// </summary>
    KeyEncipherment,
  /// <summary>
  ///   Encrypting data
  /// </summary>
    DataEncipherment,
  /// <summary>
  ///   Can be used in a key agreement protocol
  /// </summary>
    KeyAgreement,
  /// <summary>
  ///   Certificate Signing
  /// </summary>
    CertSign,
  /// <summary>
  ///   Certificate Revocation List Signing
  /// </summary>
    CRLSign,
  /// <summary>
  ///   Encryption only.
  /// </summary>
    EncipherOnly,
  /// <summary>
  ///   Deciphering only.
  /// </summary>
    DecipherOnly);
  /// <summary>
  ///   Key Usage values. It can contain the following values:<para>
  ///     <c>DigitalSignature</c> - Digital signatures
  ///   </para>
  ///   <para>
  ///     <c>NonRepudiation</c> - proving the integrety and ownership of data.
  ///   </para>
  ///   <para>
  ///     <c>KeyEncipherment</c> - Encrypting a key
  ///   </para>
  ///   <para>
  ///     <c>DataEncipherment</c> - Encrypting data
  ///   </para>
  ///   <para>
  ///     <c>KeyAgreement</c> - can be used in a key agreement protocol
  ///   </para>
  ///   <para>
  ///     <c>CertSign</c> - Certificate Signing
  ///   </para>
  ///   <para>
  ///     <c>CRLSign</c> - Certificate Revocation List Signing
  ///   </para>
  ///   <para>
  ///     <c>EncipherOnly</c> - Encryption only.
  ///   </para>
  ///   <para>
  ///     <c>DecipherOnly</c> - Deciphering only. <br />
  ///   </para>
  /// </summary>
  TTaurusTLSX509KeyUsage = set of TTaurusTLSX509KeyUse;
  /// <summary>
  ///   Type used to specify an Extended Key Usage value.
  /// </summary>
  TTaurusTLSX509ExtKeyUse = (
  /// <summary>
  ///   Server
  /// </summary>
    Server,
  /// <summary>
  ///   Client
  /// </summary>
    Client,
  /// <summary>
  ///   Secure Multipurpose Internet Mail Extensions
  /// </summary>
    SMIME,
  /// <summary>
  ///   Code Signing
  /// </summary>
    CodeSign,
  /// <summary>
  ///   Online Certificate Status Protocol Signing
  /// </summary>
    OCSPSign,
  /// <summary>
  ///   Time Stamp
  /// </summary>
    TimeStamp,
  /// <summary>
  ///   Distributed version control
  /// </summary>
    DVCS,
  /// <summary>
  ///   Any Extended Key Usage
  /// </summary>
    AnyEKU);
  /// <summary>
  ///   Extended Key Usage. Can include the following values:<para>
  ///     <c>Server</c> - Server
  ///   </para>
  ///   <para>
  ///     <c>Client</c> - Client
  ///   </para>
  ///   <para>
  ///     S/MIME - Secure Multipurpose Internet Mail Extensions
  ///   </para>
  ///   <para>
  ///     <c>CodeSign</c> - Code Signing
  ///   </para>
  ///   <para>
  ///     <c>OCSPSign</c> - Online Certificate Status Protocol Signing
  ///   </para>
  ///   <para>
  ///     <c>TimeStamp</c> - time stamp
  ///   </para>
  ///   <para>
  ///     <c>DVCS</c> - Distributed version control
  ///   </para>
  ///   <para>
  ///     AnyEKU - Any Extended Key Usage <br />
  ///   </para>
  /// </summary>
  TTaurusTLSX509ExtKeyUsage = set of TTaurusTLSX509ExtKeyUse;

  /// <summary>
  ///   Am encapsolation of a X509 Certificate.
  /// </summary>
  TTaurusTLSX509 = class(TObject)
{$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    FErrors: TTaurusTLSX509Errors;
    FWarnings: TTaurusTLSX509Warnings;
    FExtensions: TTaurusTLSX509Exts;
    FFingerprints: TTaurusTLSX509Fingerprints;
    FSigInfo: TTaurusTLSX509SigInfo;
    FPublicKey: TTaurusTLSX509PublicKey;
    FCanFreeX509: Boolean;
    FX509: PX509;
    FSubject: TTaurusTLSX509Name;
    FIssuer: TTaurusTLSX509Name;
    FDisplayInfo: TStrings;
    FAuthorityKeyID: TTaurusTLSX509AuthorityKeyID;
    FAltSubjectNames: TTaurusTLSX509AltSubjectNames;
    function GetExtensionCount: TIdC_LONG; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetSubject: TTaurusTLSX509Name; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIssuer: TTaurusTLSX509Name; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetnotBefore: TDateTime; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetnotAfter: TDateTime; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetFingerprint: TTaurusTLSLEVP_MD; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetFingerprintAsString: String; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetSerialNumber: String; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetSigInfo: TTaurusTLSX509SigInfo; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetFingerprints: TTaurusTLSX509Fingerprints; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetAuthorityKeyID: TTaurusTLSX509AuthorityKeyID;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetErrors: TTaurusTLSX509Errors; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetWarnings: TTaurusTLSX509Warnings; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetAltSubjectNames: TTaurusTLSX509AltSubjectNames;
       {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetExtensions: TTaurusTLSX509Exts; {$IFDEF USE_INLINE}inline; {$ENDIF}

    function GetVersion: TIdC_LONG; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetDisplayInfo: TStrings;
    function GetSubjectKeyIdentifier: String; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetCertificateAuthorityFlag: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetExtensionName(const AIndex: TIdC_INT): string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetExtensionCritical(const AIndex: TIdC_INT): Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetExtensionValues(const AIndex: TIdC_INT): string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetKeyUsage: TTaurusTLSX509KeyUsage;
    function GetExtKeyUsage: TTaurusTLSX509ExtKeyUsage;

    function GetProxyPathLen: TIdC_LONG; {$IFDEF USE_INLINE}inline; {$ENDIF}

    class function X509ToTTaurusTLSX509Name(aX509: PX509_NAME): TTaurusTLSX509Name;
      static; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetHasBasicConstaints: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetCertificateAuthorityPathLen: TIdC_LONG; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetHasFreshestCRL: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}

    property Extensions: TTaurusTLSX509Exts read GetExtensions;
  public
    /// <summary>
    ///   Creates a new instance of TTaurusTLS.
    /// </summary>
    /// <param name="aX509">
    ///   The OpenSSL X509 object associated with the new instance.
    /// </param>
    /// <param name="aCanFreeX509">
    ///   True if the OpenSSL X509 Certificate object associated with the new
    ///   instance can be freed by the destructor.
    /// </param>
    Constructor Create(aX509: PX509; aCanFreeX509: Boolean = True);
    /// <summary>
    ///   Frees resources and destroys the current instance.
    /// </summary>
    Destructor Destroy; override;
    /// <summary>
    ///   The number of X509 certificate extensions.
    /// </summary>
    property ExtensionCount: TIdC_LONG read GetExtensionCount;
    /// <summary>
    ///   Numerical value of the Version feild in the certificate.
    /// </summary>
    property Version: TIdC_LONG read GetVersion;
    /// <summary>
    ///   Information about the certificate's signature.
    /// </summary>
    property SigInfo: TTaurusTLSX509SigInfo read GetSigInfo;
    /// <summary>
    ///   Fingerprints for certificate using various hashing algorithms.
    /// </summary>
    property Fingerprints: TTaurusTLSX509Fingerprints read GetFingerprints;
    /// <summary>
    ///   Certificate fingerprint in binary format.
    /// </summary>
    property Fingerprint: TTaurusTLSLEVP_MD read GetFingerprint;
    /// <summary>
    ///   Certificate Fingerprint expressed as a hexidecimal sequence.
    /// </summary>
    property FingerprintAsString: String read GetFingerprintAsString;
    /// <summary>
    ///   Subject name of the certificate. Usually, that is the hostname but
    ///   could also be an E-Mail address. If the <see
    ///   cref="TaurusTLS|TTaurusTLSOptions.VerifyHostname" /> is true,
    ///   TaurusTLS will check the Common Name ( <see
    ///   cref="TaurusTLS_X509|TTaurusTLSX509Name.CommonName" />) to see that it
    ///   matches the provided value.
    /// </summary>
    property Subject: TTaurusTLSX509Name read GetSubject;
    /// <summary>
    ///   Alternative Subject names.
    /// </summary>
    property AltSubjectNames: TTaurusTLSX509AltSubjectNames
      read GetAltSubjectNames;
    /// <summary>
    ///   Certificate issuer name.
    /// </summary>
    property Issuer: TTaurusTLSX509Name read GetIssuer;
    /// <summary>
    ///   Returns the notBefore feild of the certificate as a TDateTime.
    /// </summary>
    property notBefore: TDateTime read GetnotBefore;
    /// <summary>
    ///   Returns the notAfter feild of the certificate as a TDateTime.
    /// </summary>
    property notAfter: TDateTime read GetnotAfter;
    /// <summary>
    ///   Certificate's Serial Number expressed as hexidecimal string.
    /// </summary>
    property SerialNumber: string read GetSerialNumber;
    /// <summary>
    ///   Details about a certificate in a freeform manner. Use this information
    ///   in text-prompts about the certificate.
    /// </summary>
    property DisplayInfo: TStrings read GetDisplayInfo;

    /// <summary>
    ///   An OpenSSL X509 certificate object.
    /// </summary>
    property Certificate: PX509 read FX509;
    /// <summary>
    ///   Public key.
    /// </summary>
    property PublicKey: TTaurusTLSX509PublicKey read FPublicKey;
    /// <summary>
    ///   Subject key identifier expressed as a hexidecimal string.
    /// </summary>
    property SubjectKeyIdentifier: String read GetSubjectKeyIdentifier;
    /// <summary>
    ///   Certificate authority flag
    /// </summary>
    property CertificateAuthorityFlag: Boolean read GetCertificateAuthorityFlag;
    /// <summary>
    ///   Maximum Certificate Chain Length that may be issued by Certificate
    ///   Authority.
    /// </summary>
    /// <remarks>
    ///   This may be -1 if the certificate authority flag is not set.
    /// </remarks>
    property CertificateAuthorityPathLen: TIdC_LONG
      read GetCertificateAuthorityPathLen;
    /// <summary>
    ///   Extension name
    /// </summary>
    /// <param name="AIndex">
    ///   Position of the extension in the list.
    /// </param>
    property ExtensionName[const AIndex: TIdC_INT]: string
      read GetExtensionName;
    /// <summary>
    ///   True if the extension is critical or False if it is not critical.
    /// </summary>
    /// <param name="AIndex">
    ///   Position of the extension in the list.
    /// </param>
    property ExtensionCritical[const AIndex: TIdC_INT]: Boolean
      read GetExtensionCritical;
    /// <summary>
    ///   Value of the extension expressed as a hexidecimal string.
    /// </summary>
    /// <param name="AIndex">
    ///   Position of the extension in the list.
    /// </param>
    property ExtensionValues[const AIndex: TIdC_INT]: string
      read GetExtensionValues;
    /// <summary>
    ///   The certificate has the Freshest Certificate Revocation List (CRL)
    ///   extension.
    /// </summary>
    property HasFreshestCRL: Boolean read GetHasFreshestCRL;
    /// <summary>
    ///   The certificate has the Basic Constraints extension.
    /// </summary>
    property HasBasicConstraints: Boolean read GetHasBasicConstaints;
    /// <summary>
    ///   Authority Key Identifier.
    /// </summary>
    property AuthorityKeyID: TTaurusTLSX509AuthorityKeyID read GetAuthorityKeyID;
    /// <summary>
    ///   Key Usage X509 Extension information.
    /// </summary>
    property KeyUsage: TTaurusTLSX509KeyUsage read GetKeyUsage;
    /// <summary>
    ///   Extended Key Usage Exention information.
    /// </summary>
    property ExtendedKeyUsage: TTaurusTLSX509ExtKeyUsage read GetExtKeyUsage;
    /// <summary>
    ///   Proxy certificate path length
    /// </summary>
    /// <remark>
    ///   May be -1 if it is not a proxy certificate.
    /// </remark>
    property ProxyPathLen: TIdC_LONG read GetProxyPathLen;
    /// <summary>
    ///   Certificate errors.
    /// </summary>
    property Errors: TTaurusTLSX509Errors read GetErrors;
    /// <summary>
    ///   Certificate warnings.
    /// </summary>
    property Warnings: TTaurusTLSX509Warnings read GetWarnings;
  end;

implementation

uses
  IdFIPS,
  {$IFDEF WINDOWS}
  IdIDN,
  {$ENDIF}
  TaurusTLSHeaders_obj_mac,
  TaurusTLSHeaders_asn1,
  TaurusTLSHeaders_bio,
  TaurusTLSHeaders_bn,
  TaurusTLSHeaders_objects,
  TaurusTLSHeaders_rsa,
  TaurusTLSHeaders_x509_vfy,
  SysUtils;
/// ////////////////////////////////////////////////////////////
// X509 Certificate
/// ////////////////////////////////////////////////////////////

{ TTaurusTLSX509Name }

function TTaurusTLSX509Name.GetOneLine: String;
var
  LOneLine: array [0 .. 2048] of TIdAnsiChar;
  LPtr: PIdAnsiChar;
begin
  if fX509Name = nil then
  begin
    Result := ''; { Do not Localize }
  end
  else
  begin
    LPtr := X509_NAME_oneline(fX509Name, @LOneLine[0], SizeOf(LOneLine));
    Result := String(LPtr);
  end;
end;


function TTaurusTLSX509Name.GetStrByNID(const ANid: TIdC_INT): String;
var
  LBuffer: array [0 .. 2048] of TIdAnsiChar;
begin
  if fX509Name = nil then
  begin
    Result := ''; { Do not Localize }
  end
  else
  begin
    if X509_NAME_get_text_by_NID(fX509Name, ANid, @LBuffer[0], 256) > -1 then
    begin
      // PIdAnsiChar typecast is necessary to force the RTL
      // to read it as a PAnsiChar for conversion for a
      // string.
      Result := String(PIdAnsiChar(@LBuffer[0]));
    end
    else
    begin
      Result := '';
    end;
  end;
end;

function TTaurusTLSX509Name.GetCity: String;
begin
  Result := GetStrByNID(NID_localityName);
end;

function TTaurusTLSX509Name.GetCommonName: String;
begin
  {$IFDEF WINDOWS}
  if Assigned(IdnToUnicode) then
  begin
    Result := PunnyCodeToIDN(GetStrByNID(NID_commonName));
  end
  else
  begin
    Result := GetStrByNID(NID_commonName);
  end;
  {$ELSE}
  Result := GetStrByNID(NID_commonName);
  {$ENDIF}
end;

function TTaurusTLSX509Name.GetCountry: String;
begin
  Result := GetStrByNID(NID_countryName);
end;

function TTaurusTLSX509Name.GetEMail: String;
begin
{$IFDEF WINDOWS}
  if Assigned(IdnToUnicode) then
  begin
    Result := PunnyCodeToIDN(GetStrByNID(NID_pkcs9_emailAddress));
  end
  else
  begin
    Result := GetStrByNID(NID_pkcs9_emailAddress);
  end;
{$ELSE}
  Result := GetStrByNID(NID_pkcs9_emailAddress);
{$ENDIF}
end;

function TTaurusTLSX509Name.GetHash: TTaurusTLSULong;
begin
  {$ifdef fpc}
  Initialize(Result);
  if fX509Name <> nil then
  {$else}
  if fX509Name = nil then
  begin
    FillChar(Result, SizeOf(Result), 0)
  end
  else
  {$endif}
  begin
    Result.C1 := X509_NAME_hash(fX509Name);
  end;
end;

function TTaurusTLSX509Name.GetHashAsString: String;
begin
  Result := IndyFormat('%.8x', [Hash.L1]); { do not localize }
end;

function TTaurusTLSX509Name.GetOrginization: String;
begin
  Result := GetStrByNID(NID_organizationName);
end;

function TTaurusTLSX509Name.GetProvidence: String;
begin
  Result := GetStrByNID(NID_stateOrProvinceName);
end;


function TTaurusTLSX509Name.GetStreetAddress: String;
begin
  Result := GetStrByNID(NID_streetAddress);
end;

function TTaurusTLSX509Name.GetUnit: String;
begin
  Result := GetStrByNID(NID_organizationalUnitName);
end;

constructor TTaurusTLSX509Name.Create(aX509Name: PX509_NAME);
begin
  Inherited Create;
  fX509Name := aX509Name;
end;

/// ////////////////////////////////////////////////////////////
// X509 Certificate
/// ////////////////////////////////////////////////////////////

{ TTaurusTLSX509Info }

constructor TTaurusTLSX509Info.Create(aX509: PX509);
begin
  inherited Create;
  FX509 := aX509;
end;

{ TTaurusTLSX509Fingerprints }

function TTaurusTLSX509Fingerprints.GetSHA224: TTaurusTLSLEVP_MD;
begin
{$IFDEF OPENSSL_STATIC_LINK_MODEL}
  X509_digest(FX509, EVP_sha224, PByte(@Result.MD), Result._Length);
{$ELSE}
  if Assigned(EVP_sha224) then
  begin
    X509_digest(FX509, EVP_sha224, PByte(@Result.MD), Result._Length);
  end
  else
  begin
    FillChar(Result, SizeOf(Result), 0);
  end;
{$ENDIF}
end;

function TTaurusTLSX509Fingerprints.GetSHA224AsString: String;
begin
{$IFDEF OPENSSL_STATIC_LINK_MODEL}
  Result := MDAsString(SHA224);
{$ELSE}
  if Assigned(EVP_sha224) then
  begin
    Result := MDAsString(SHA224);
  end
  else
  begin
    Result := '';
  end;
{$ENDIF}
end;

function TTaurusTLSX509Fingerprints.GetSHA256: TTaurusTLSLEVP_MD;
begin
{$IFDEF OPENSSL_STATIC_LINK_MODEL}
  X509_digest(FX509, EVP_sha256, PByte(@Result.MD), Result._Length);
{$ELSE}
  if Assigned(EVP_sha256) then
  begin
    X509_digest(FX509, EVP_sha256, PByte(@Result.MD), Result._Length);
  end
  else
  begin
    FillChar(Result, SizeOf(Result), 0);
  end;
{$ENDIF}
end;

function TTaurusTLSX509Fingerprints.GetSHA256AsString: String;
begin
{$IFDEF OPENSSL_STATIC_LINK_MODEL}
  Result := MDAsString(SHA256);
{$ELSE}
  if Assigned(EVP_sha256) then
  begin
    Result := MDAsString(SHA256);
  end
  else
  begin
    Result := '';
  end;
{$ENDIF}
end;

function TTaurusTLSX509Fingerprints.GetSHA384: TTaurusTLSLEVP_MD;
begin
{$IFDEF OPENSSL_STATIC_LINK_MODEL}
  X509_digest(FX509, EVP_SHA384, PByte(@Result.MD), Result._Length);
{$ELSE}
  if Assigned(EVP_SHA384) then
  begin
    X509_digest(FX509, EVP_SHA384, PByte(@Result.MD), Result._Length);
  end
  else
  begin
    FillChar(Result, SizeOf(Result), 0);
  end;
{$ENDIF}
end;

function TTaurusTLSX509Fingerprints.GetSHA384AsString: String;
begin
{$IFDEF OPENSSL_STATIC_LINK_MODEL}
  Result := MDAsString(SHA384);
{$ELSE}
  if Assigned(EVP_SHA384) then
  begin
    Result := MDAsString(SHA384);
  end
  else
  begin
    Result := '';
  end;
{$ENDIF}
end;

function TTaurusTLSX509Fingerprints.GetSHA512: TTaurusTLSLEVP_MD;
begin
{$IFDEF OPENSSL_STATIC_LINK_MODEL}
  X509_digest(FX509, EVP_sha512, PByte(@Result.MD), Result._Length);
{$ELSE}
  if Assigned(EVP_sha512) then
  begin
    X509_digest(FX509, EVP_sha512, PByte(@Result.MD), Result._Length);
  end
  else
  begin
    FillChar(Result, SizeOf(Result), 0);
  end;
{$ENDIF}
end;

function TTaurusTLSX509Fingerprints.GetSHA512AsString: String;
begin
{$IFDEF OPENSSL_STATIC_LINK_MODEL}
  Result := MDAsString(SHA512);
{$ELSE}
  if Assigned(EVP_sha512) then
  begin
    Result := MDAsString(SHA512);
  end
  else
  begin
    Result := '';
  end;
{$ENDIF}
end;

{ TTaurusTLSX509SigInfo }

constructor TTaurusTLSX509SigInfo.Create(aX509: PX509);
begin
  inherited;
  Fsig_alg := nil;
  Fsignature := nil;
end;

function TTaurusTLSX509SigInfo.GetAlgorithm: String;
var
  lalgorithm: PASN1_OBJECT;
begin
  if not Assigned(Fsig_alg) then
  begin
    X509_get0_signature(Fsignature, Fsig_alg, FX509);
  end;
  lalgorithm := nil;
  X509_ALGOR_get0(@lalgorithm, nil, nil, Fsig_alg);
  Result := ASN1_OBJECT_ToStr(lalgorithm);
end;

function TTaurusTLSX509SigInfo.GetSignature: String;
begin
  if not Assigned(Fsignature) then
  begin
    X509_get0_signature(Fsignature, Fsig_alg, FX509);
  end;
  Result := BytesToHexString(Fsignature^.Data, Fsignature^._Length);
end;

function TTaurusTLSX509SigInfo.GetSigType: TIdC_INT;
begin
  Result := X509_get_signature_type(FX509);
end;

function TTaurusTLSX509SigInfo.GetSigTypeAsString: String;
begin
  Result := AnsiStringToString(OBJ_nid2ln(SigType));
end;

{ TTaurusTLSX509Exts }

function TTaurusTLSX509Exts.GetCount: TIdC_INT;
begin
  Result := X509_get_ext_count(FX509);
end;

function TTaurusTLSX509Exts.GetExtension(const AIndex: TIdC_INT)
  : PX509_EXTENSION;
begin
  Result := X509_get_ext(FX509, AIndex);
end;

function TTaurusTLSX509Exts.GetExtensionByNid(const ANid: TIdC_INT)
  : PX509_EXTENSION;
var
  LIdx: TIdC_INT;
begin
  LIdx := X509_get_ext_by_NID(FX509, ANid, -1);
  if LIdx > -1 then
  begin
    Result := X509_get_ext(FX509, LIdx);
  end
  else
  begin
    Result := nil;
  end;
end;

function TTaurusTLSX509Exts.GetExtensionCritical(
  const AIndex: TIdC_INT): boolean;
begin
  if AIndex < 0 then
    Result := False
  else
    Result := X509_EXTENSION_get_critical(X509_get_ext(FX509, AIndex)) > 0;
end;

function TTaurusTLSX509Exts.GetExtensionName(const AIndex: TIdC_INT): string;
begin
  if AIndex < 0 then
    Result := ''
  else
    Result := ASN1_OBJECT_ToStr(
      X509_EXTENSION_get_object(X509_get_ext(FX509, AIndex))
    );
end;

function TTaurusTLSX509Exts.GetExtensionValues(const AIndex: TIdC_INT): string;
begin
  if AIndex < 0 then
    Result := ''
  else
    Result := ASN1_STRING_ToHexStr(
      X509_EXTENSION_get_data(X509_get_ext(FX509, AIndex))
    );
end;

{ TTaurusTLSX509 }

constructor TTaurusTLSX509.Create(aX509: PX509; aCanFreeX509: Boolean = True);
begin
  inherited Create;
  FX509 := aX509;
  FCanFreeX509 := aCanFreeX509;
  FPublicKey := TTaurusTLSX509PublicKey.Create(FX509);
  // don't create following instances unless specifically requested.
  FExtensions := nil;
  FDisplayInfo := nil;
  FSubject := nil;
  FIssuer := nil;
  FAltSubjectNames := nil;
  FErrors := nil;
  FFingerprints := nil;
  FSigInfo := nil;
  FAuthorityKeyID := nil;
  FWarnings := nil;
end;

destructor TTaurusTLSX509.Destroy;
begin
  FreeAndNil(FWarnings);
  FreeAndNil(FAuthorityKeyID);
  FreeAndNil(FExtensions);
  FreeAndNil(FDisplayInfo);
  FreeAndNil(FSubject);
  FreeAndNil(FIssuer);
  FreeAndNil(FFingerprints);
  FreeAndNil(FSigInfo);
  FreeAndNil(FAltSubjectNames);
  FreeAndNil(FPublicKey);
  { If the X.509 certificate handle was obtained from a certificate
    store or from the SSL connection as a peer certificate, then DO NOT
    free it here!  The memory is owned by the OpenSSL library and will
    crash the library if TaurusTLS tries to free its private memory here }
  if FCanFreeX509 then
  begin
    X509_free(FX509);
  end;
  FreeAndNil(FErrors);
  inherited Destroy;
end;

function TTaurusTLSX509.GetSubjectKeyIdentifier: String;
begin
  Result := ASN1_STRING_ToHexStr(X509_get0_subject_key_id(FX509));
end;

function TTaurusTLSX509.GetAltSubjectNames: TTaurusTLSX509AltSubjectNames;
begin
  if not Assigned(FAltSubjectNames) then
    FAltSubjectNames:=TTaurusTLSX509AltSubjectNames.Create(FX509);
  Result:=FAltSubjectNames;
end;

function TTaurusTLSX509.GetAuthorityKeyID: TTaurusTLSX509AuthorityKeyID;
begin
  if not Assigned(FAuthorityKeyID) then
    FAuthorityKeyID:=TTaurusTLSX509AuthorityKeyID.Create(FX509);
  Result:=FAuthorityKeyID;
end;

function TTaurusTLSX509.GetCertificateAuthorityFlag: Boolean;
begin
  Result := (X509_get_extension_flags(FX509)) and EXFLAG_CA <> 0;
end;

function TTaurusTLSX509.GetCertificateAuthorityPathLen: TIdC_LONG;
begin
  if CertificateAuthorityFlag then
  begin
    Result := X509_get_pathlen(FX509);
  end
  else
  begin
    Result := -1;
  end;
end;

function TTaurusTLSX509.GetDisplayInfo: TStrings;
var
  LMem: PBIO;
  LLen: TIdC_INT;
  LBufPtr : Pointer;
//  LBufPtr: PIdAnsiChar;
begin
  if not Assigned(FDisplayInfo) then
  begin
    FDisplayInfo := TStringList.Create;
{$IFNDEF OPENSSL_NO_BIO}
    LMem := BIO_new(BIO_s_mem);
    if LMem <> nil then
    begin
      try
        if X509_print_ex(LMem, FX509, XN_FLAG_COMPAT, X509_FLAG_COMPAT) = 1 then
        begin
           //The line below isn't needed but I want to avoid PAL warning about
           //unset variables.
          LBufPtr := nil;
          LLen := BIO_get_mem_data(LMem, LBufPtr);
          if (LLen > 0) and (LBufPtr <> nil) then
          begin
            {$ifndef fpc}
            FDisplayInfo.Text := IndyTextEncoding_UTF8.GetString(
{$IFNDEF VCL_6_OR_ABOVE}
              // RLebeau: for some reason, Delphi 5 causes a "There is no overloaded
              // version of 'GetString' that can be called with these arguments" compiler
              // error if the PByte type-cast is used, even though GetString() actually
              // expects a PByte as input.  Must be a compiler bug, as it compiles fine
              // in Delphi 6.  So, converting to TIdBytes until I find a better solution...
              RawToBytes(LBufPtr*, LLen)
{$ELSE}
              @LBufPtr^, LLen
{$ENDIF}
              );
            {$else}
              FDisplayInfo.Text := BytesToString(RawToBytes(LBufPtr^, LLen));
            {$endif}
          end;
        end;
      finally
        BIO_free(LMem);
      end;
    end;
{$ENDIF}
  end;
  Result := FDisplayInfo;
end;

function TTaurusTLSX509.GetErrors: TTaurusTLSX509Errors;
begin
  if not Assigned(FErrors) then
    FErrors:=TTaurusTLSX509Errors.Create(FX509);
  Result:=FErrors;
end;

function TTaurusTLSX509.GetExtensionCount: TIdC_LONG;
begin
  Result := FExtensions.Count;
end;

function TTaurusTLSX509.GetExtensions: TTaurusTLSX509Exts;
begin
  if not Assigned(FExtensions) then
    FExtensions:=TTaurusTLSX509Exts.Create(FX509);
  Result:=FExtensions;
end;

function TTaurusTLSX509.GetExtensionCritical(const AIndex: TIdC_INT): Boolean;
begin
  Result:=Extensions.ExtensionCritical[AIndex];
end;

function TTaurusTLSX509.GetExtensionName(const AIndex: TIdC_INT): string;
begin
  Result:=Extensions.ExtensionName[AIndex];
end;

function TTaurusTLSX509.GetExtensionValues(const AIndex: TIdC_INT): string;
begin
  Result:=Extensions.ExtensionValues[AIndex];
end;

function TTaurusTLSX509.GetExtKeyUsage: TTaurusTLSX509ExtKeyUsage;
var
  LFlags: TIdC_UINT32;
begin
  Result := [];
  if (X509_get_extension_flags(FX509) and EXFLAG_XKUSAGE) <> 0 then
  begin
    LFlags := X509_get_extended_key_usage(FX509);
    if (LFlags and XKU_SSL_SERVER) <> 0 then
      Include(Result, Server);
    if (LFlags and XKU_SSL_CLIENT) <> 0 then
      Include(Result, Client);
    if (LFlags and XKU_SMIME) <> 0 then
      Include(Result,  SMIME);
    if (LFlags and XKU_CODE_SIGN) <> 0 then
      Include(Result, CodeSign);
    if (LFlags and XKU_OCSP_SIGN) <> 0 then
      Include(Result, OCSPSign);
    if (LFlags and XKU_TIMESTAMP) <> 0 then
      Include(Result, TimeStamp);
    if (LFlags and XKU_DVCS) <> 0 then
      Include(Result, DVCS);
    if (LFlags and XKU_ANYEKU) <> 0 then
      Include(Result, AnyEKU);
  end;
end;

function TTaurusTLSX509.GetKeyUsage: TTaurusTLSX509KeyUsage;
var
  LKeyUsage: TIdC_UINT32;
begin
  Result := [];
  if (X509_get_extension_flags(FX509) and EXFLAG_KUSAGE) <> 0 then
  begin
    LKeyUsage := X509_get_key_usage(FX509);
    if (LKeyUsage and KU_DIGITAL_SIGNATURE) <> 0 then
      Include(Result, DigitalSignature);
    if (LKeyUsage and KU_NON_REPUDIATION) <> 0 then
      Include(Result, NonRepudiation);
    if (LKeyUsage and KU_KEY_ENCIPHERMENT) <> 0 then
      Include(Result, DataEncipherment);
    if (LKeyUsage and KU_KEY_AGREEMENT) <> 0 then
      Include(Result, KeyAgreement);
    if (LKeyUsage and KU_KEY_CERT_SIGN) <> 0 then
      Include(Result, CertSign);
    if (LKeyUsage and KU_CRL_SIGN) <> 0 then
      Include(Result, CRLSign);
    if (LKeyUsage and KU_ENCIPHER_ONLY) <> 0 then
      Include(Result, EncipherOnly);
    if (LKeyUsage and KU_DECIPHER_ONLY) <> 0 then
      Include(Result, DecipherOnly);
  end;
end;

function TTaurusTLSX509.GetProxyPathLen: TIdC_LONG;
begin
  Result := -1;
  if (X509_get_extension_flags(FX509) and EXFLAG_PROXY) <> 0 then
  begin
    Result := X509_get_proxy_pathlen(FX509);
  end;
end;

function TTaurusTLSX509.GetSerialNumber: String;
var
  LSN: PASN1_INTEGER;
  LBN: PBIGNUM;
begin
  if FX509 <> nil then
  begin
    LSN := X509_get_serialNumber(FX509);
    LBN := ASN1_INTEGER_to_BN(LSN, nil);
    Result := AnsiStringToString(BN_bn2hex(LBN));
    bn_free(LBN);
  end
  else
  begin
    Result := '';
  end;
end;

function TTaurusTLSX509.GetSigInfo: TTaurusTLSX509SigInfo;
begin
  if not Assigned(FSigInfo) then
    FSigInfo:=TTaurusTLSX509SigInfo.Create(FX509);
  Result:=FSigInfo;
end;

function TTaurusTLSX509.GetVersion: TIdC_LONG;
begin
  Result := X509_get_version(FX509);
end;

function TTaurusTLSX509.GetWarnings: TTaurusTLSX509Warnings;
begin
  if not Assigned(FWarnings) then
    FWarnings:=TTaurusTLSX509Warnings.Create(FX509);
  Result:=FWarnings;
end;

class function TTaurusTLSX509.X509ToTTaurusTLSX509Name(aX509: PX509_NAME)
  : TTaurusTLSX509Name;

begin
  Result := nil;
  if Assigned(aX509) then
  begin
    Result := TTaurusTLSX509Name.Create(aX509);
  end;
end;

function TTaurusTLSX509.GetSubject: TTaurusTLSX509Name;
Begin
  if not Assigned(FSubject) then
  begin
    FSubject := X509ToTTaurusTLSX509Name(X509_get_subject_name(FX509));
  end;
  Result := FSubject;
end;

function TTaurusTLSX509.GetIssuer: TTaurusTLSX509Name;
begin
  if not Assigned(FIssuer) then
  begin
    FIssuer := X509ToTTaurusTLSX509Name(X509_get_issuer_name(FX509));
  End;
  Result := FIssuer;
end;

function TTaurusTLSX509.GetFingerprint: TTaurusTLSLEVP_MD;
begin
  X509_digest(FX509, EVP_md5, PByte(@Result.MD), Result._Length);
end;

function TTaurusTLSX509.GetFingerprintAsString: String;
begin
  Result := MDAsString(Fingerprint);
end;

function TTaurusTLSX509.GetFingerprints: TTaurusTLSX509Fingerprints;
begin
  if not Assigned(FFingerprints) then
    FFingerprints:=TTaurusTLSX509Fingerprints.Create(FX509);
  Result:=FFingerprints;
end;

function TTaurusTLSX509.GetHasBasicConstaints: Boolean;
begin
  Result := X509_get_extension_flags(Self.FX509) and
    EXFLAG_BCONS = EXFLAG_BCONS;
end;

function TTaurusTLSX509.GetHasFreshestCRL: Boolean;
begin
  Result := X509_get_extension_flags(Self.FX509) and
    EXFLAG_FRESHEST = EXFLAG_FRESHEST;
end;

function TTaurusTLSX509.GetnotBefore: TDateTime;
begin
  // This is a safe typecast since PASN1_UTCTIME and PASN1_TIME are really
  // pointers to ASN1 strings since ASN1_UTCTIME amd ASM1_TIME are ASN1_STRING.
  Result := ASN1TimeToDateTime(X509_get0_notBefore(FX509));
end;

function TTaurusTLSX509.GetnotAfter: TDateTime;
begin
  // This is a safe typecast since PASN1_UTCTIME and PASN1_TIME are really
  // pointers to ASN1 strings since ASN1_UTCTIME amd ASM1_TIME are ASN1_STRING.
  Result := ASN1TimeToDateTime(X509_get0_notAfter(FX509));
end;

{ TTaurusTLSX509PublicKey }

function TTaurusTLSX509PublicKey.GetAlgorithm: String;
var
  lalgorithm: PASN1_OBJECT;
begin
  if X509_PUBKEY_get0_param(@lalgorithm, nil, nil, nil,
    X509_get_X509_PUBKEY(FX509)) <> 0 then
  begin
    Result := ASN1_OBJECT_ToStr(lalgorithm);
  end
  else
  begin
    Result := '';
  end;
end;

function TTaurusTLSX509PublicKey.GetEncoding: String;
var
  LLen: TIdC_INT;
  LKey: array [0 .. 2048] of TIdAnsiChar;
begin
  if X509_PUBKEY_get0_param(nil, @LKey[0], @LLen, nil,
    X509_get_X509_PUBKEY(FX509)) <> 0 then
  begin
    Result := BytesToHexString(@LKey[0], LLen);
  end
  else
  begin
    Result := '';
  end;
end;

function TTaurusTLSX509PublicKey.GetEncodingSize: TIdC_INT;
var
  LKey: array [0 .. 2048] of TIdAnsiChar;
begin
  if X509_PUBKEY_get0_param(nil, @LKey[0], @Result, nil,
    X509_get_X509_PUBKEY(FX509)) <> 0 then
  begin
    Result := 0;
  end;
end;

function TTaurusTLSX509PublicKey.GetExponent: String;
var
  LKey: PEVP_PKEY;
  LBN: PBIGNUM;
begin
  Result := '';
  LKey := X509_PUBKEY_get0(X509_get_X509_PUBKEY(FX509));
  if EVP_PKEY_base_id(LKey) = EVP_PKEY_RSA then
  begin
    RSA_get0_key(EVP_PKEY_get0_RSA(LKey), nil, @LBN, nil);
    Result := AnsiStringToString(BN_bn2hex(LBN));
  end;
end;

function TTaurusTLSX509PublicKey.GetModulus: String;
var
  LKey: PEVP_PKEY;
  LBN: PBIGNUM;
begin
  Result := '';
  LKey := X509_PUBKEY_get0(X509_get_X509_PUBKEY(FX509));
  if EVP_PKEY_base_id(LKey) = EVP_PKEY_RSA then
  begin
    RSA_get0_key(EVP_PKEY_get0_RSA(LKey), @LBN, nil, nil);
    Result := AnsiStringToString(BN_bn2hex(LBN));
  end;
end;

function TTaurusTLSX509PublicKey.GetBits: TIdC_INT;
begin
  // no need to reference EVP_PKEY_get_bits.  The headers load that as an alternative.
  Result := EVP_PKEY_bits(X509_PUBKEY_get0(X509_get_X509_PUBKEY(FX509)));
end;

function TTaurusTLSX509PublicKey.GetSecurityBits: TIdC_INT;
begin
  /// / no need to reference EVP_PKEY_get_security_bits.  The headers load that as an alternative.
  Result := EVP_PKEY_security_bits
    (X509_PUBKEY_get0(X509_get_X509_PUBKEY(FX509)));
end;

function TTaurusTLSX509PublicKey.GetSize: TIdC_INT;
begin
  /// no need to reference EVP_PKEY_get_size.  The headers load it as an alternative.
  Result := EVP_PKEY_size(X509_PUBKEY_get0(X509_get_X509_PUBKEY(FX509)));
end;

{ TTaurusTLSX509AuthorityKeyID }

function TTaurusTLSX509AuthorityKeyID.GetIssuerCount: TIdC_INT;
var
  LGNs: PGENERAL_NAMES;
begin
  Result := 0;
  LGNs := X509_get0_authority_issuer(FX509);
  if Assigned(LGNs) then
  begin
    Result := sk_GENERAL_NAME_num(LGNs);
  end;
end;

function TTaurusTLSX509AuthorityKeyID.GetIssuer(const AIndex: TIdC_INT): String;
var
  LGNs: PGENERAL_NAMES;
  LG: PGENERAL_NAME;
begin
  Result := '';
  LGNs := X509_get0_authority_issuer(FX509);
  if Assigned(LGNs) then
  begin
    LG := sk_GENERAL_NAME_value(LGNs, AIndex);
    Result := GeneralNameToStr(LG);
  end;

end;

function TTaurusTLSX509AuthorityKeyID.GetKeyId: String;
begin
  Result := ASN1_STRING_ToHexStr
    (X509_get0_authority_key_id(FX509));
end;

function TTaurusTLSX509AuthorityKeyID.GetSerial: TIdC_INT64;
begin
  Result := 0;
  ASN1_INTEGER_get_int64(@Result, X509_get0_authority_serial(FX509));
end;

{ TTaurusTLSX509Warnings }

function TTaurusTLSX509Warnings.GetObsoleteV1: Boolean;
begin
  Result := (X509_get_extension_flags(FX509) and EXFLAG_V1) <> 0;
end;

function TTaurusTLSX509Warnings.GetSelfSigned: Boolean;
begin
  Result := (X509_get_extension_flags(FX509) and EXFLAG_SI) <> 0;
end;

function TTaurusTLSX509Warnings.GetSubjectAndIssuerMatch: Boolean;
begin
  Result := (X509_get_extension_flags(FX509) and EXFLAG_SS) <> 0;
end;

{ TTaurusTLSX509Errors }

function TTaurusTLSX509Errors.GetInvalidInconsistantValues: Boolean;
begin
  Result := (X509_get_extension_flags(FX509) and EXFLAG_INVALID) <> 0;
end;

function TTaurusTLSX509Errors.GetInvalidPolicy: Boolean;
begin
  Result := (X509_get_extension_flags(FX509) and EXFLAG_INVALID_POLICY) <> 0;
end;

function TTaurusTLSX509Errors.GetNoFingerprint: Boolean;
begin
  Result := (X509_get_extension_flags(FX509) and EXFLAG_NO_FINGERPRINT) <> 0;
end;

function TTaurusTLSX509Errors.GetUnhandledCriticalExtension: Boolean;
begin
  Result := (X509_get_extension_flags(FX509) and EXFLAG_CRITICAL) <> 0;
end;

{ TTaurusTLSX509AltSubjectNames }

constructor TTaurusTLSX509AltSubjectNames.Create(aX509: PX509);
begin
  inherited Create(aX509);
  FGeneralNames := nil;
end;

destructor TTaurusTLSX509AltSubjectNames.Destroy;
begin
  if Assigned(FGeneralNames) then
  begin
    GENERAL_NAMES_free(FGeneralNames);
  end;
  inherited;
end;

procedure TTaurusTLSX509AltSubjectNames.GetGeneralNames;
begin
  if not Assigned(FGeneralNames) then
  begin
    FGeneralNames := X509_get_ext_d2i(FX509, NID_subject_alt_name, nil, nil);
  end;
end;

function TTaurusTLSX509AltSubjectNames.GetItems(const AIndex: TIdC_INT): string;
var
  LGN: PGENERAL_NAME;
begin
  Result := '';
  GetGeneralNames;
  if Assigned(FGeneralNames) then
  begin
    LGN := sk_GENERAL_NAME_value(FGeneralNames, AIndex);
    Result := GeneralNameToStr(LGN);
  end;
end;

function TTaurusTLSX509AltSubjectNames.GetItemsCount: TIdC_INT;
begin
  Result := -1;
  GetGeneralNames;
  if Assigned(FGeneralNames) then
  begin
    Result := sk_GENERAL_NAME_num(FGeneralNames);
  end;
end;

end.
