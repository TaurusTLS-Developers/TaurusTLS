/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_ossl_typ.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_ossl_typ.h2pas
     and this file regenerated. TaurusTLSHeaders_ossl_typ.h2pas is distributed with the full Indy
     Distribution.
   *)
{$IFNDEF USE_OPENSSL}
  { error Should not compile if USE_OPENSSL is not defined!!!}
{$ENDIF}
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

unit TaurusTLSHeaders_types;

interface

{$I TaurusTLSLinkDefines.inc}

// Headers for OpenSSL 1.1.1
// ossl_typ.h


uses
  IdCTypes,
  IdGlobal;

type
{$IF NOT DECLARED(TIdC_SIZET)}
  {$IFDEF HAS_SIZE_T}
  TIdC_SIZET = size_t;
  {$ELSE}
    {$IFDEF HAS_PtrUInt}
  TIdC_SIZET = PtrUInt;
    {$ELSE}
      {$IFDEF CPU32}
  TIdC_SIZET = TIdC_UINT32;
      {$ENDIF}
      {$IFDEF CPU64}
  TIdC_SIZET = TIdC_UINT64;
      {$ENDIF}
    {$ENDIF}
  {$ENDIF}
{$IFEND}
{$IF NOT DECLARED(PIdC_SIZET)}
  {$IF DECLARED(PSIZE_T)}
  PIdC_SIZET = psize_t;
  {$ELSE}
  PIdC_SIZET = ^TIdC_SIZET;
  {$IFEND}
{$IFEND}
{$IF NOT DECLARED(TIdC_SSIZET)}
  {$IFDEF HAS_SSIZE_T}
  TIdC_SSIZET = ssize_t;
  {$ELSE}
    {$IFDEF HAS_PtrInt}
  TIdC_SSIZET = PtrInt;
    {$ELSE}
      {$IFDEF CPU32}
  TIdC_SSIZET = TIdC_INT32;
      {$ENDIF}
      {$IFDEF CPU64}
  TIdC_SSIZET = TIdC_INT64;
      {$ENDIF}
    {$ENDIF}
  {$ENDIF}
{$IFEND}
{$IF NOT DECLARED(PIdC_SSIZET)}
  {$IFDEF HAS_PSSIZE_T}
  // in ptypes.inc, pssize_t is missing, but pSSize is present, and it is defined as ^ssize_t...
  PIdC_SSIZET = {pssize_t}pSSize;
  {$ELSE}
  PIdC_SSIZET = ^TIdC_SSIZET;
  {$ENDIF}
{$IFEND}
{$IF NOT DECLARED(TIdC_TIMET)}
  {$IFDEF HAS_TIME_T}
  TIdC_TIMET = time_t;
  {$ELSE}
    {$IFDEF HAS_PtrInt}
  TIdC_TIMET = PtrInt;
    {$ELSE}
      {$IFDEF CPU32}
  TIdC_TIMET = TIdC_INT32;
      {$ENDIF}
      {$IFDEF CPU64}
  TIdC_TIMET = TIdC_INT64;
      {$ENDIF}
    {$ENDIF}
  {$ENDIF}
{$IFEND}
{$IF NOT DECLARED(PIdC_TIMET)}
  {$IFDEF HAS_PTIME_T}
  PIdC_TIMET = ptime_t;
  {$ELSE}
  PIdC_TIMET = ^TIdC_TIMET;
  {$ENDIF}
{$IFEND}
{$IF NOT DECLARED(PByte)}
  PByte = ^Byte;
{$IFEND}
{$IF NOT DECLARED(PPByte)}
    PPByte = ^PByte;
{$IFEND}
{$IF NOT DECLARED(PPPByte)}
  PPPByte = ^PPByte;
{$IFEND}
{$IF NOT DECLARED(PPIdC_INT)}
  PPIdC_INT = ^PIdC_INT;
{$IFEND}
{$IF NOT DECLARED(TIdAnsiChar)}
  TIdAnsiChar = AnsiChar;
{$IFEND}
{$IF NOT DECLARED(PIdAnsiChar)}
  PIdAnsiChar = PAnsiChar;
{$IFEND}
{$IF NOT DECLARED(PPIdAnsiChar)}
  {$IFDEF HAS_PPAnsiChar}
  PPIdAnsiChar = PPAnsiChar;
  {$ELSE}
  PPIdAnsiChar = ^PIdAnsiChar;
  {$ENDIF}
{$IFEND}
{$IF NOT DECLARED(PPPIdAnsiChar)}
  PPPIdAnsiChar = ^PPIdAnsiChar;
{$IFEND}

{$IF NOT DECLARED(TIdC_TM)}
  TIdC_TM = record
    tm_sec: TIdC_INT;         (* seconds,  range 0 to 59          *)
    tm_min: TIdC_INT;         (* minutes, range 0 to 59           *)
    tm_hour: TIdC_INT;        (* hours, range 0 to 23             *)
    tm_mday: TIdC_INT;        (* day of the month, range 1 to 31  *)
    tm_mon: TIdC_INT;         (* month, range 0 to 11             *)
    tm_year: TIdC_INT;        (* The number of years since 1900   *)
    tm_wday: TIdC_INT;        (* day of the week, range 0 to 6    *)
    tm_yday: TIdC_INT;        (* day in the year, range 0 to 365  *)
    tm_isdst: TIdC_INT;       (* daylight saving time             *)
    {$IFDEF LINUX}
    // xjikka 20260112 glibc struct tm extension:
    // ASN1_TIME_to_tm() writes a full glibc struct tm (tm_gmtoff, tm_zone).
    // Without these fields TIdC_TM is too small, causing stack corruption
    // (e.g. invalid X509 ValidFrom/ValidTo values) on Linux targets.
    // This is especially visible with FPC cross-compilation to Linux/ARM
    // (e.g. Raspberry Pi), where X509 ValidFrom/ValidTo values become invalid.
    tm_gmtoff: TIdC_LONG;  // seconds east of UTC
    tm_zone: PAnsiChar;    // timezone abbreviation
    {$ENDIF}
  end;
  PIdC_TM = ^TIdC_TM;
  PPIdC_TM = ^PIdC_TM;
  {$IFEND}
// moved from unit "asn1" to prevent circular references
  asn1_string_st = record
    _length: TIdC_INT;
    type_: TIdC_INT;
    data: PByte;
    (*
     * The value of the following field depends on the type being held.  It
     * is mostly being used for BIT_STRING so if the input data has a
     * non-zero 'unused bits' value, it will be handled correctly
     *)
    flags: TIdC_LONG;
  end;

  // moved from asn1
  ASN1_VALUE    = record end;
  PASN1_VALUE   = ^ASN1_VALUE;
  PPASN1_VALUE  = ^PASN1_VALUE;

  // moved from e_os2
  ossl_ssize_t = type {$IFDEF WIN64}TIdC_INT64{$ELSE}TIdC_INT{$ENDIF};

  ASN1_OBJECT   = record end;
  PASN1_OBJECT  = ^ASN1_OBJECT;
  PPASN1_OBJECT = ^PASN1_OBJECT;

  ASN1_INTEGER    = type asn1_string_st;
  PASN1_INTEGER   = ^ASN1_INTEGER;
  PPASN1_INTEGER  = ^PASN1_INTEGER;

  ASN1_ENUMERATED   = type asn1_string_st;
  PASN1_ENUMERATED  = ^ASN1_ENUMERATED;

  ASN1_BIT_STRING   = type asn1_string_st;
  PASN1_BIT_STRING  = ^ASN1_BIT_STRING;
  PPASN1_BIT_STRING = ^PASN1_BIT_STRING;

  ASN1_OCTET_STRING   = type asn1_string_st;
  PASN1_OCTET_STRING  = ^ASN1_OCTET_STRING;
  PPASN1_OCTET_STRING = ^PASN1_OCTET_STRING;

  ASN1_PRINTABLESTRING  = type asn1_string_st;
  PASN1_PRINTABLESTRING = ^ASN1_PRINTABLESTRING;

  ASN1_T61STRING  = type asn1_string_st;
  PASN1_T61STRING = ^ASN1_T61STRING;

  ASN1_IA5STRING  = type asn1_string_st;
  PASN1_IA5STRING = ^ASN1_IA5STRING;

  ASN1_GENERALSTRING  = type asn1_string_st;
  PASN1_GENERALSTRING = ^ASN1_GENERALSTRING;

  ASN1_UNIVERSALSTRING  = type asn1_string_st;
  PASN1_UNIVERSALSTRING = ^ASN1_UNIVERSALSTRING;

  ASN1_BMPSTRING  = type asn1_string_st;
  PASN1_BMPSTRING = ^ASN1_BMPSTRING;

  ASN1_UTCTIME    = type asn1_string_st;
  PASN1_UTCTIME   = ^ASN1_UTCTIME;
  PPASN1_UTCTIME  = ^PASN1_UTCTIME;

  ASN1_TIME   = type asn1_string_st;
  PASN1_TIME  = ^ASN1_TIME;
  PPASN1_TIME = ^PASN1_TIME;

  ASN1_GENERALIZEDTIME    = type asn1_string_st;
  PASN1_GENERALIZEDTIME   = ^ASN1_GENERALIZEDTIME;
  PPASN1_GENERALIZEDTIME  = ^PASN1_GENERALIZEDTIME;

  ASN1_VISIBLESTRING  = type asn1_string_st;
  PASN1_VISIBLESTRING = ^ASN1_VISIBLESTRING;

  ASN1_UTF8STRING   = type asn1_string_st;
  PASN1_UTF8STRING  = ^ASN1_UTF8STRING;

  ASN1_STRING   = type asn1_string_st;
  PASN1_STRING  = ^ASN1_STRING;
  PPASN1_STRING = ^PASN1_STRING;

  ASN1_BOOLEAN  = type TIdC_INT;
  PASN1_BOOLEAN = ^ASN1_BOOLEAN;

  ASN1_NULL   = type TIdC_INT;
  PASN1_NULL  = ^ASN1_NULL;

  ASN1_ITEM   = record end;
  PASN1_ITEM  = ^ASN1_ITEM;

  ASN1_PCTX   = record end;
  PASN1_PCTX = ^ASN1_PCTX;

  ASN1_SCTX   = record end;
  PASN1_SCTX  = ^ASN1_SCTX;

  BIO   = record end;
  PBIO  = ^BIO;
  PPBIO = ^PBIO;

  BIGNUM    = record end;
  PBIGNUM   = ^BIGNUM;
  PPBIGNUM  = ^PBIGNUM;

  BN_CTX  = record end;
  PBN_CTX = ^BN_CTX;

  BN_BLINDING   = record end;
  PBN_BLINDING  = ^BN_BLINDING;

  BN_MONT_CTX   = record end;
  PBN_MONT_CTX  = ^BN_MONT_CTX;

  BN_RECP_CTX   = record end;
  PBN_RECP_CTX  = ^BN_RECP_CTX;

  BN_GENCB    = record end;
  PBN_GENCB   = ^BN_GENCB;

  BUF_MEM   = record end;
  PBUF_MEM  = ^BUF_MEM;

  EVP_CIPHER    = record end;
  PEVP_CIPHER   = ^EVP_CIPHER;
  PPEVP_CIPHER  = ^PEVP_CIPHER;

  EVP_CIPHER_CTX  = record end;
  PEVP_CIPHER_CTX = ^EVP_CIPHER_CTX;

  EVP_MD    = record end;
  PEVP_MD   = ^EVP_MD;
  PPEVP_MD  = ^PEVP_MD;

  EVP_MD_CTX  = record end;
  PEVP_MD_CTX = ^EVP_MD_CTX;

  EVP_PKEY    = record end;
  PEVP_PKEY   = ^EVP_PKEY;
  PPEVP_PKEY  = ^PEVP_PKEY;

  EVP_SKEY    = record end;
  PEVP_SKEY   = ^EVP_SKEY;
  PPEVP_SKEY  = ^PEVP_SKEY;

  EVP_PKEY_ASN1_METHOD    = record end;
  PEVP_PKEY_ASN1_METHOD   = ^EVP_PKEY_ASN1_METHOD;
  PPEVP_PKEY_ASN1_METHOD  = ^PEVP_PKEY_ASN1_METHOD;

  EVP_PKEY_METHOD   = record end;
  PEVP_PKEY_METHOD  = ^EVP_PKEY_METHOD;
  PPEVP_PKEY_METHOD = ^PEVP_PKEY_METHOD;

  EVP_PKEY_CTX    = record end;
  PEVP_PKEY_CTX   = ^EVP_PKEY_CTX;
  PPEVP_PKEY_CTX  = ^PEVP_PKEY_CTX;

  EVP_ENCODE_CTX  = record end;
  PEVP_ENCODE_CTX = ^EVP_ENCODE_CTX;

  HMAC_CTX  = record end;
  PHMAC_CTX = ^HMAC_CTX;

  EVP_MAC   = record end;
  PEVP_MAC  = ^EVP_MAC;

  EVP_MAC_CTX   = record end;
  PEVP_MAC_CTX  = ^EVP_MAC_CTX;

  DH    = record end;
  PDH   = ^DH;
  PPDH  = ^PDH;

  DH_METHOD = record end;
  PDH_METHOD = ^DH_METHOD;

  DSA   = record end;
  PDSA  = ^DSA;
  PPDSA = ^PDSA;

  DSA_METHOD  = record end;
  PDSA_METHOD = ^DSA_METHOD;

  RSA   = record end;
  PRSA  = ^RSA;
  PPRSA = ^PRSA;

  RSA_METHOD  = record end;
  PRSA_METHOD = ^RSA_METHOD;

  EC_KEY    = record end;
  PEC_KEY   = ^EC_KEY;
  PPEC_KEY  = ^PEC_KEY;

  EC_KEY_METHOD   = record end;
  PEC_KEY_METHOD  = ^EC_KEY_METHOD;

  RAND_METHOD   = record end;
  PRAND_METHOD  = ^RAND_METHOD;

  RAND_DRBG   = record end;
  PRAND_DRBG  = ^RAND_DRBG;

  SSL_DANE  = record end;
  PSSL_DANE = ^SSL_DANE;

  X509    = record end;
  PX509   = ^X509;
  PPX509  = ^PX509;

  Stack_Of_X509   = record end;
  PStack_Of_X509  = ^Stack_Of_X509;
  PPStack_Of_X509 = ^PStack_Of_X509;

  X509_CRL    = record end;
  PX509_CRL   = ^X509_CRL;
  PPX509_CRL  = ^PX509_CRL;

  X509_CRL_METHOD   = record end;
  PX509_CRL_METHOD  = ^X509_CRL_METHOD;

  X509_REVOKED    = record end;
  PX509_REVOKED   = ^X509_REVOKED;
  PPX509_REVOKED  = ^PX509_REVOKED;

  X509_NAME   = record end;
  PX509_NAME  = ^X509_NAME;
  PPX509_NAME = ^PX509_NAME;

  X509_PUBKEY   = record end;
  PX509_PUBKEY  = ^X509_PUBKEY;
  PPX509_PUBKEY = ^PX509_PUBKEY;

  X509_STORE  = record end;
  PX509_STORE = ^X509_STORE;

  X509_STORE_CTX  = record end;
  PX509_STORE_CTX = ^X509_STORE_CTX;

  X509_OBJECT   = record end;
  PX509_OBJECT  = ^X509_OBJECT;

  X509_LOOKUP   = record end;
  PX509_LOOKUP  = ^X509_LOOKUP;

  X509_LOOKUP_METHOD  = record end;
  PX509_LOOKUP_METHOD = ^X509_LOOKUP_METHOD;

  X509_VERIFY_PARAM   = record end;
  PX509_VERIFY_PARAM  = ^X509_VERIFY_PARAM;

  X509_SIG_INFO   = record end;
  PX509_SIG_INFO  = ^X509_SIG_INFO;

  pkcs8_priv_key_info_st  = record end;
  PKCS8_PRIV_KEY_INFO     = ^pkcs8_priv_key_info_st;
  PPKCS8_PRIV_KEY_INFO    = ^PKCS8_PRIV_KEY_INFO;
  PPPKCS8_PRIV_KEY_INFO   = ^PPKCS8_PRIV_KEY_INFO;

// moved from x509 to prevent circular references
  X509_REQ    = record end; // X509_req_st
  PX509_REQ   = ^X509_REQ;
  PPX509_REQ  = ^PX509_REQ;

// moved from x509v3 to prevent circular references
  (* Context specific info *)
  v3_ext_ctx = record
    flags: TIdC_INT;
    issuer_cert: PX509;
    subject_cert: PX509;
    subject_req: PX509_REQ;
    crl: PX509_CRL;
    db_meth: Pointer; //PX509V3_CONF_METHOD;
    db: Pointer;
  (* Maybe more here *)
  end;

  X509V3_CTX  = record end;
  PX509V3_CTX = ^X509V3_CTX;

  CONF  = record end;
  PCONF = ^CONF;

  OPENSSL_INIT_SETTINGS   = record end;
  POPENSSL_INIT_SETTINGS  = ^OPENSSL_INIT_SETTINGS;

  UI  = record end;
  PUI = ^UI;

  UI_METHOD   = record end;
  PUI_METHOD = ^UI_METHOD;

  ENGINE    = record end;
  PENGINE   = ^ENGINE;
  PPENGINE  = ^PENGINE;

  SSL   = record end;
  PSSL  = ^SSL;

  SSL_CTX   = record end;
  PSSL_CTX  = ^SSL_CTX;
  PPSSL_CTX = ^PSSL_CTX;

  COMP_CTX    = record end;
  PCOMP_CTX = ^COMP_CTX;

  COMP_METHOD   = record end;
  PCOMP_METHOD  = ^COMP_METHOD;

  X509_POLICY_NODE  = record end;
  PX509_POLICY_NODE = ^X509_POLICY_NODE;

  X509_POLICY_LEVEL   = record end;
  PX509_POLICY_LEVEL  = ^X509_POLICY_LEVEL;

  X509_POLICY_TREE  = record end;
  PX509_POLICY_TREE = ^X509_POLICY_TREE;

  X509_POLICY_CACHE_st = record end;
  PX509_POLICY_CACHE = ^X509_POLICY_CACHE_st;

//  AUTHORITY_KEYID_st = type Pointer; // removed as not needed
//  AUTHORITY_KEYID = AUTHORITY_KEYID_st; replaced with dummy record
  AUTHORITY_KEYID   = record end;
  PAUTHORITY_KEYID  = ^AUTHORITY_KEYID;

  DIST_POINT  = record end;
  PDIST_POINT = ^DIST_POINT;

  ISSUING_DIST_POINT  = record end;
  PISSUING_DIST_POINT = ^ISSUING_DIST_POINT;

  NAME_CONSTRAINTS  = record end;
  PNAME_CONSTRAINTS = ^NAME_CONSTRAINTS;

  CRYPTO_EX_DATA  = record end;
  PCRYPTO_EX_DATA = ^CRYPTO_EX_DATA;

  OCSP_REQ_CTX  = record end;
  POCSP_REQ_CTX = ^OCSP_REQ_CTX;

  OCSP_RESPONSE   = record end;
  POCSP_RESPONSE  = ^OCSP_RESPONSE;

  OCSP_RESPID   = record end;
  POCSP_RESPID  = ^OCSP_RESPID;

  SCT   = record end;
  PSCT  = ^SCT;
  PPSCT = ^PSCT;

  SCT_CTX   = record end;
  PSCT_CTX  = ^SCT_CTX;

  CTLOG   = record end;
  PCTLOG  = ^CTLOG;
  PPCTLOG = ^PCTLOG;

  CTLOG_STORE   = record end;
  PCTLOG_STORE  = ^CTLOG_STORE;

  CT_POLICY_EVAL_CTX  = record end;
  PCT_POLICY_EVAL_CTX = ^CT_POLICY_EVAL_CTX;

  OSSL_STORE_INFO   = record end;
  POSSL_STORE_INFO  = ^OSSL_STORE_INFO;

  OSSL_STORE_SEARCH   = record end;
  POSSL_STORE_SEARCH  = ^OSSL_STORE_SEARCH;

  EVP_KDF   = record end;
  PEVP_KDF  = ^EVP_KDF;

  EVP_KDF_CTX   = record end;
  PEVP_KDF_CTX  = ^EVP_KDF_CTX;

// moved from unit "asn1" to prevent circular references'
const
  V_ASN1_UNIVERSAL = $00;
  V_ASN1_APPLICATION = $40;
  V_ASN1_CONTEXT_SPECIFIC = $80;
  V_ASN1_PRIVATE = $c0;

  V_ASN1_CONSTRUCTED = $20;
  V_ASN1_PRIMITIVE_TAG = $1f;
  V_ASN1_PRIMATIVE_TAG = V_ASN1_PRIMITIVE_TAG;

  V_ASN1_APP_CHOOSE = -2; (* let the recipient choose *)
  V_ASN1_OTHER = -3;      (* used in ASN1_TYPE *)
  V_ASN1_ANY = -4;        (* used in ASN1 template code *)

  V_ASN1_UNDEF = -1;
  V_ASN1_EOC =  0;
  V_ASN1_BOOLEAN = 1;
  V_ASN1_INTEGER = 2;
  V_ASN1_BIT_STRING = 3;
  V_ASN1_OCTET_STRING = 4;
  V_ASN1_NULL = 5;
  V_ASN1_OBJECT = 6;
  V_ASN1_OBJECT_DESCRIPTOR = 7;
  V_ASN1_EXTERNAL = 8;
  V_ASN1_REAL = 9;
  V_ASN1_ENUMERATED = 10;
  V_ASN1_UTF8STRING = 12;
  V_ASN1_SEQUENCE = 16;
  V_ASN1_SET = 17;
  V_ASN1_NUMERICSTRING = 18;
  V_ASN1_PRINTABLESTRING = 19;
  V_ASN1_T61STRING = 20;
  V_ASN1_TELETEXSTRING = 20;
  V_ASN1_VIDEOTEXSTRING = 21;
  V_ASN1_IA5STRING = 22;
  V_ASN1_UTCTIME = 23;
  V_ASN1_GENERALIZEDTIME = 24;
  V_ASN1_GRAPHICSTRING = 25;
  V_ASN1_ISO64STRING = 26;
  V_ASN1_VISIBLESTRING = 26;
  V_ASN1_GENERALSTRING = 27;
  V_ASN1_UNIVERSALSTRING = 28;
  V_ASN1_BMPSTRING = 30;

type
  asn1_type_st = record
    case type_: TIdC_INT of
//      (_ptr: PIdAnsichar);
      V_ASN1_BOOLEAN: (_boolean: ASN1_BOOLEAN);
//      (asn1_string: PASN1_STRING);
      V_ASN1_OBJECT: (object_: PASN1_OBJECT);
      V_ASN1_INTEGER: (_integer: PASN1_INTEGER);
      V_ASN1_ENUMERATED: (enumerated: PASN1_ENUMERATED);
      V_ASN1_BIT_STRING: (bit_string: PASN1_BIT_STRING);
      V_ASN1_OCTET_STRING: (octet_string: PASN1_OCTET_STRING);
      V_ASN1_PRINTABLESTRING: (printablestring: PASN1_PRINTABLESTRING);
      V_ASN1_T61STRING: (t61string: PASN1_T61STRING);
      V_ASN1_IA5STRING: (ia5string: PASN1_IA5STRING);
      V_ASN1_GENERALSTRING: (generalstring: PASN1_GENERALSTRING);
      V_ASN1_BMPSTRING: (bmpstring: PASN1_BMPSTRING);
      V_ASN1_UNIVERSALSTRING: (universalstring: PASN1_UNIVERSALSTRING);
      V_ASN1_UTCTIME: (utctime: PASN1_UTCTIME);
      V_ASN1_GENERALIZEDTIME: (generalizedtime: PASN1_GENERALIZEDTIME);
      V_ASN1_VISIBLESTRING: (visiblestring: PASN1_VISIBLESTRING);
      V_ASN1_UTF8STRING: (_utf8string: PASN1_UTF8STRING);
      (*
       * set and sequence are left complete and still contain the set or
       * sequence bytes
       *)
      V_ASN1_SET: (set_: PASN1_STRING);
      V_ASN1_SEQUENCE: (sequence: PASN1_STRING);
//      (asn1_value: PASN1_VALUE);

//      V_ASN1_UNDEF: ;
//      V_ASN1_EOC: ;
//      V_ASN1_NULL: ;
//      V_ASN1_OBJECT_DESCRIPTOR: ;
//      V_ASN1_EXTERNAL: ;
//      V_ASN1_REAL: ;
//      V_ASN1_NUMERICSTRING: ;
//      V_ASN1_TELETEXSTRING: ;
//      V_ASN1_VIDEOTEXSTRING: ;
//      V_ASN1_GRAPHICSTRING: ;
//      V_ASN1_ISO64STRING: ;
  end;
  ASN1_TYPE = asn1_type_st;
  PASN1_TYPE = ^ASN1_TYPE;
  PPASN1_TYPE = ^PASN1_TYPE;

// moved from unit "x509" to prevent circular references
  X509_algor_st = record
    algorithm: PASN1_OBJECT;
    parameter: PASN1_TYPE;
  end; (* X509_ALGOR *)

  X509_ALGOR = X509_algor_st;
  PX509_ALGOR = ^X509_ALGOR;
  PPX509_ALGOR = ^PX509_ALGOR;

//  i2d_of_void = type Pointer;
//  Pi2d_of_void = ^i2d_of_void;
  i2d_of_void = function(const data: Pointer; pp: PPIdAnsiChar): Pointer; cdecl;

//  d2i_of_void = type Pointer;
//  Pd2i_of_void = ^d2i_of_void;
  d2i_of_void = function(data: PPointer; pp: PPIdAnsiChar; length_: TIdC_Long): pointer;
    cdecl;

  {OSSL_LIB_CTX is defined in types.h from 3.0.0 onwards}
  //  typedef struct ossl_lib_ctx_st OSSL_LIB_CTX;
  OSSL_LIB_CTX  = record end;
  POSSL_LIB_CTX = ^OSSL_LIB_CTX;

  OSSL_ALGORITHM  = record end;
  POSSL_ALGORITHM = ^OSSL_ALGORITHM;

  OSSL_ENCODER  = record end;
  POSSL_ENCODER = ^OSSL_ENCODER;

  OSSL_ENCODER_CTX  = record end;
  POSSL_ENCODER_CTX = ^OSSL_ENCODER_CTX;

  OSSL_PROVIDER   = record end;
  POSSL_PROVIDER  = ^OSSL_PROVIDER;

  OSSL_DECODER  = record end;
  POSSL_DECODER = ^OSSL_DECODER;

  OSSL_DECODER_CTX  = record end;
  POSSL_DECODER_CTX = ^OSSL_DECODER_CTX;

//  OSSL_PARAM = record end;
//  POSSL_PARAM = ^OSSL_PARAM;
//  POSSL_PARAM_ARRAY = POSSL_PARAM; // declaration of "array of OSSL_PARAM"

  pem_password_cb = function(buf: PIdAnsiChar; size: TIdC_INT; rwflag: TIdC_INT; userdata: Pointer): TIdC_INT; cdecl;

implementation

end.
