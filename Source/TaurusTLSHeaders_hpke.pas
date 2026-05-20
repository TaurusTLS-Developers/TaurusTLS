/// <exclude />
{$I TaurusTLSCompilerDefines.inc}
{$I TaurusTLSLinkDefines.inc}
{$IFNDEF USE_OPENSSL}
  { error Should not compile if USE_OPENSSL is not defined!!!}
{$ENDIF}
{******************************************************************************}
{*  TaurusTLS                                                                 *}
{*           https://github.com/JPeterMugaas/TaurusTLS                        *}
{*                                                                            *}
{*  Copyright (c) 2026 TaurusTLS Developers, All Rights Reserved              *}
{*                                                                            *}
{* Portions of this software are Copyright (c) 1993 – 2018,                   *}
{* Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  *}
{******************************************************************************}

unit TaurusTLSHeaders_hpke;

interface
uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_types;

  {$MINENUMSIZE 4}

const
//* HPKE modes */
  OSSL_HPKE_MODE_BASE = 0; //* Base mode  */
  OSSL_HPKE_MODE_PSK = 1; //* Pre-shared key mode */
  OSSL_HPKE_MODE_AUTH  = 2; //* Authenticated mode */
  OSSL_HPKE_MODE_PSKAUTH = 3; //* PSK+authenticated mode */

{*
 * Max for ikm, psk, pskid, info and exporter contexts.
 * RFC9180, section 7.2.1 RECOMMENDS 64 octets but we have test vectors from
 * Appendix A.6.1 with a 66 octet IKM so we'll allow that.
 *}
  OSSL_HPKE_MAX_PARMLEN = 66;
  OSSL_HPKE_MIN_PSKLEN = 32;
  OSSL_HPKE_MAX_INFOLEN = 1024;

{*
 * The (16bit) HPKE algorithm ID IANA codepoints
 * If/when new IANA codepoints are added there are tables in
 * crypto/hpke/hpke_util.c that must also be updated.
 *}
  OSSL_HPKE_KEM_ID_RESERVED = $0000; //* not used */
  OSSL_HPKE_KEM_ID_P256 = $0010; //* NIST P-256 */
  OSSL_HPKE_KEM_ID_P384 = $0011; //* NIST P-384 */
  OSSL_HPKE_KEM_ID_P521 = $0012; //* NIST P-521 */
  OSSL_HPKE_KEM_ID_X25519 = $0020; //* Curve25519 */
  OSSL_HPKE_KEM_ID_X448 = $0021; //* Curve448 */

  OSSL_HPKE_KDF_ID_RESERVED = $0000; //* not used */
  OSSL_HPKE_KDF_ID_HKDF_SHA256 = $0001; //* HKDF-SHA256 */
  OSSL_HPKE_KDF_ID_HKDF_SHA384 = $0002; //* HKDF-SHA384 */
  OSSL_HPKE_KDF_ID_HKDF_SHA512 = $0003; //* HKDF-SHA512 */

  OSSL_HPKE_AEAD_ID_RESERVED = $0000; //* not used */
  OSSL_HPKE_AEAD_ID_AES_GCM_128 = $0001; //* AES-GCM-128 */
  OSSL_HPKE_AEAD_ID_AES_GCM_256 = $0002; //* AES-GCM-256 */
  OSSL_HPKE_AEAD_ID_CHACHA_POLY1305 = $0003; //* Chacha20-Poly1305 */
  OSSL_HPKE_AEAD_ID_EXPORTONLY = $FFFF; //* export-only fake ID */

//* strings for suite components */
  OSSL_HPKE_KEMSTR_P256 = 'P-256'; //* KEM id = $10 */
  OSSL_HPKE_KEMSTR_P384 = 'P-384'; //* KEM id = $11 */
  OSSL_HPKE_KEMSTR_P521 = 'P-521'; //* KEM id = $12 */
  OSSL_HPKE_KEMSTR_X25519 = 'X25519'; //* KEM id = $20 */
  OSSL_HPKE_KEMSTR_X448 = 'X448'; //* KEM id = $21 */
  OSSL_HPKE_KDFSTR_256 = 'hkdf-sha256'; //* KDF id 1 */
  OSSL_HPKE_KDFSTR_384 = 'hkdf-sha384'; //* KDF id 2 */
  OSSL_HPKE_KDFSTR_512 = 'hkdf-sha512'; //* KDF id 3 */
  OSSL_HPKE_AEADSTR_AES128GCM = 'aes-128-gcm'; //* AEAD id 1 */
  OSSL_HPKE_AEADSTR_AES256GCM = 'aes-256-gcm'; //* AEAD id 2 */
  OSSL_HPKE_AEADSTR_CP = 'chacha20-poly1305'; //* AEAD id 3 */
  OSSL_HPKE_AEADSTR_EXP = 'exporter'; //* AEAD id = $ff */

{*
 * Roles for use in creating an OSSL_HPKE_CTX, most
 * important use of this is to control nonce reuse.
 *}
  OSSL_HPKE_ROLE_SENDER = 0;
  OSSL_HPKE_ROLE_RECEIVER = 1;

type
  OSSL_HPKE_SUITE = record
    kem_id : TIdC_UINT16; //* Key Encapsulation Method id */
    kdf_id : TIdC_UINT16; //* Key Derivation Function id */
    aead_id : TIdC_UINT16; //* AEAD alg id */
  end;
  POSSL_HPKE_SUITE = ^OSSL_HPKE_SUITE;
  PPOSSL_HPKE_SUITE = ^POSSL_HPKE_SUITE;
  ossl_hpke_ctx_st = record end;
  OSSL_HPKE_CTX = ossl_hpke_ctx_st;
  POSSL_HPKE_CTX = ^OSSL_HPKE_CTX;
  PPOSSL_HPKE_CTX = ^POSSL_HPKE_CTX;

const
{$IFNDEF OPENSSL_NO_ECX}
  OSSL_HPKE_SUITE_DEFAULT: array[0..2] of Integer = (
    OSSL_HPKE_KEM_ID_X25519,
    OSSL_HPKE_KDF_ID_HKDF_SHA256,
    OSSL_HPKE_AEAD_ID_AES_GCM_128
  );
{$ELSE}
  OSSL_HPKE_SUITE_DEFAULT: array[0..2] of Integer = (
    OSSL_HPKE_KEM_ID_X25519,
    OSSL_HPKE_KDF_ID_HKDF_SHA256,
    OSSL_HPKE_AEAD_ID_AES_GCM_128
  );
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  OSSL_HPKE_CTX_new : function(mode : TIdC_INT; suite : OSSL_HPKE_SUITE; role : TIdC_INT;
    libctx : POSSL_LIB_CTX; const propq : PIdAnsiChar) : POSSL_HPKE_CTX; cdecl = nil;
  OSSL_HPKE_CTX_free : procedure(ctx : POSSL_HPKE_CTX); cdecl = nil;

 OSSL_HPKE_encap : function(ctx : POSSL_HPKE_CTX;
    enc : PByte; enclen : TIdC_SIZET;
    const pub : PByte; publen : TIdC_SIZET;
    const info : PByte; infolen : TIdC_SIZET) : TIdC_INT; cdecl = nil;
  OSSL_HPKE_seal : function(ctx : POSSL_HPKE_CTX;
    ct : PByte; ctlen : TIdC_SIZET;
    const aad : PByte; aadlen : TIdC_SIZET;
    const pt : PByte; ptlen : TIdC_SIZET) : TIdC_INT; cdecl = nil;

  OSSL_HPKE_keygen : function( suite : OSSL_HPKE_SUITE;
    pub : PByte; publen : PIdC_SIZET; priv : PPEVP_PKEY;
    const ikm : PByte; ikmlen : TIdC_SIZET;
    libctx : POSSL_LIB_CTX; const propq : PByte) : TIdC_INT; cdecl = nil;
  OSSL_HPKE_decap : function(ctx : POSSL_HPKE_CTX;
    const enc : PByte; enclen : TIdC_SIZET;
    recippriv : PEVP_PKEY;
    const info : PByte; infolen : TIdC_SIZET) : TIdC_INT; cdecl = nil;
  OSSL_HPKE_open : function(ctx : POSSL_HPKE_CTX;
    pt : PByte; ptlen : PIdC_SIZET;
    const aad : PByte; aadlen : TIdC_SIZET;
    const ct : PByte; ctlen : TIdC_SIZET) : TIdC_INT; cdecl = nil;

  OSSL_HPKE_export : function(ctx : OSSL_HPKE_CTX;
    secret : PByte;
    secretlen : TIdC_SIZET;
    const _label : PByte;
    labellen : TIdC_SIZET) : TIdC_INT; cdecl = nil;

  OSSL_HPKE_CTX_set1_authpriv : function(ctx : POSSL_HPKE_CTX; priv : PEVP_PKEY) : TIdC_INT; cdecl = nil;
  OSSL_HPKE_CTX_set1_authpub : function(ctx : POSSL_HPKE_CTX;
    const pub : PByte;
    publen : TIdC_SIZET) : TIdC_INT; cdecl = nil;
  OSSL_HPKE_CTX_set1_psk : function(ctx : POSSL_HPKE_CTX;
    const pskid : PByte;
    const psk : PByte; psklen : TIdC_SIZET) : TIdC_INT; cdecl = nil;

  OSSL_HPKE_CTX_set1_ikme : function(ctx : POSSL_HPKE_CTX;
    const ikme : PByte; ikmelen : TIdC_SIZET) : TIdC_INT;  cdecl = nil;

  OSSL_HPKE_CTX_set_seq : function (ctx : POSSL_HPKE_CTX; seq : TIdC_UINT64) : TIdC_INT; cdecl = nil;
  OSSL_HPKE_CTX_get_seq : function (ctx : POSSL_HPKE_CTX; seq : TIdC_UINT64) : TIdC_INT; cdecl = nil;

  OSSL_HPKE_suite_check : function( suite : OSSL_HPKE_SUITE) : TIdC_INT; cdecl = nil;
  OSSL_HPKE_get_grease_value : function(const suite_in : POSSL_HPKE_SUITE;
    suite : POSSL_HPKE_SUITE;
    enc : PByte; enclen : PIdC_SIZET;
    ct : PByte; ctlen : TIdC_SIZET;
    libctx : POSSL_LIB_CTX; const propq : PIdAnsiChar) : TIdC_INT; cdecl = nil;
  OSSL_HPKE_str2suite : function(const str_ : PIdAnsiChar; suite : POSSL_HPKE_SUITE) : TIdC_INT; cdecl = nil;
  OSSL_HPKE_get_ciphertext_size : function(suite : OSSL_HPKE_SUITE; clearlen : TIdC_SIZET) : TIdC_SIZET; cdecl = nil;
  OSSL_HPKE_get_public_encap_size : function(suite : OSSL_HPKE_SUITE) : TIdC_SIZET; cdecl = nil;
  OSSL_HPKE_get_recommended_ikmelen : function(suite : OSSL_HPKE_SUITE) : TIdC_SIZET; cdecl = nil;
{$ELSE}
  function OSSL_HPKE_CTX_new(mode : TIdC_INT; suite : OSSL_HPKE_SUITE; role : TIdC_INT;
    libctx : POSSL_LIB_CTX; const propq : PIdAnsiChar) : POSSL_HPKE_CTX cdecl; external CLibCrypto;
  procedure OSSL_HPKE_CTX_free(ctx : POSSL_HPKE_CTX) cdecl; external CLibCrypto;
  function OSSL_HPKE_encap(ctx : POSSL_HPKE_CTX;
    enc : PByte; enclen : TIdC_SIZET;
    const pub : PByte; publen : TIdC_SIZET;
    const info : PByte; infolen : TIdC_SIZET) : TIdC_INT cdecl; external CLibCrypto;
  function OSSL_HPKE_seal(ctx : POSSL_HPKE_CTX;
    ct : PByte; ctlen : TIdC_SIZET;
    const aad : PByte; aadlen : TIdC_SIZET;
    const pt : PByte; ptlen : TIdC_SIZET) : TIdC_INT cdecl; external CLibCrypto;

  function OSSL_HPKE_keygen( suite : OSSL_HPKE_SUITE;
    pub : PByte; publen : PIdC_SIZET; priv : PPEVP_PKEY;
    const ikm : PByte; ikmlen : TIdC_SIZET;
    libctx : POSSL_LIB_CTX; const propq : PByte) : TIdC_INT cdecl; external CLibCrypto;
  function OSSL_HPKE_decap(ctx : POSSL_HPKE_CTX;
    const enc : PByte; enclen : TIdC_SIZET;
    recippriv : PEVP_PKEY;
    const info : PByte; infolen : TIdC_SIZET) : TIdC_INT cdecl; external CLibCrypto;
  function OSSL_HPKE_open(ctx : POSSL_HPKE_CTX;
    pt : PByte; ptlen : PIdC_SIZET;
    const aad : PByte; aadlen : TIdC_SIZET;
    const ct : PByte; ctlen : TIdC_SIZET) : TIdC_INT cdecl; external CLibCrypto;

  function OSSL_HPKE_export(ctx : OSSL_HPKE_CTX;
    secret : PByte;
    secretlen : TIdC_SIZET;
    const _label : PByte;
    labellen : TIdC_SIZET) : TIdC_INT cdecl; external CLibCrypto;

  function OSSL_HPKE_CTX_set1_authpriv(ctx : POSSL_HPKE_CTX; priv : PEVP_PKEY) : TIdC_INT  cdecl; external CLibCrypto;
  function OSSL_HPKE_CTX_set1_authpub(ctx : POSSL_HPKE_CTX;
    const pub : PByte;
    publen : TIdC_SIZET) : TIdC_INT  cdecl; external CLibCrypto;
  function OSSL_HPKE_CTX_set1_psk(ctx : POSSL_HPKE_CTX;
    const pskid : PByte;
    const psk : PByte; psklen : TIdC_SIZET) : TIdC_INT cdecl; external CLibCrypto;

  function OSSL_HPKE_CTX_set1_ikme(ctx : POSSL_HPKE_CTX;
    const ikme : PByte; ikmelen : TIdC_SIZET) : TIdC_INT cdecl; external CLibCrypto;

  function OSSL_HPKE_CTX_set_seq(ctx : POSSL_HPKE_CTX; seq : TIdC_UINT64) : TIdC_INT cdecl; external CLibCrypto;
  function OSSL_HPKE_CTX_get_seq(ctx : POSSL_HPKE_CTX; seq : TIdC_UINT64) : TIdC_INT cdecl; external CLibCrypto;

  function OSSL_HPKE_suite_check( suite : OSSL_HPKE_SUITE) : TIdC_INT cdecl; external CLibCrypto;
  function OSSL_HPKE_get_grease_value(const suite_in : POSSL_HPKE_SUITE;
    suite : POSSL_HPKE_SUITE;
    enc : PByte; enclen : PIdC_SIZET;
    ct : PByte; ctlen : TIdC_SIZET;
    libctx : POSSL_LIB_CTX; const propq : PIdAnsiChar) : TIdC_INT cdecl; external CLibCrypto;
  function OSSL_HPKE_str2suite(const str_ : PIdAnsiChar; suite : POSSL_HPKE_SUITE) : TIdC_INT cdecl; external CLibCrypto;
  function OSSL_HPKE_get_ciphertext_size(suite : OSSL_HPKE_SUITE; clearlen : TIdC_SIZET) : TIdC_SIZET cdecl; external CLibCrypto;
  function OSSL_HPKE_get_public_encap_size(suite : OSSL_HPKE_SUITE) : TIdC_SIZET cdecl; external CLibCrypto;
  function OSSL_HPKE_get_recommended_ikmelen(suite : OSSL_HPKE_SUITE) : TIdC_SIZET cdecl; external CLibCrypto;

{$ENDIF}

implementation
  uses
    classes,
    TaurusTLSExceptionHandlers
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    ,TaurusTLSLoader
  {$ENDIF};

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
const
  OSSL_HPKE_CTX_new_procname = 'OSSL_HPKE_CTX_new';
  OSSL_HPKE_CTX_free_procname = 'OSSL_HPKE_CTX_free';
  OSSL_HPKE_encap_procname = 'OSSL_HPKE_encap';
  OSSL_HPKE_seal_procname = 'OSSL_HPKE_seal';
  OSSL_HPKE_keygen_procname = 'OSSL_HPKE_keygen';
  OSSL_HPKE_decap_procname = 'OSSL_HPKE_decap';
  OSSL_HPKE_open_procname = 'OSSL_HPKE_open';
  OSSL_HPKE_export_procname = 'OSSL_HPKE_export';
  OSSL_HPKE_CTX_set1_authpriv_procname = 'OSSL_HPKE_CTX_set1_authpriv';
  OSSL_HPKE_CTX_set1_authpub_procname = 'OSSL_HPKE_CTX_set1_authpub';
  OSSL_HPKE_CTX_set1_psk_procname = 'OSSL_HPKE_CTX_set1_psk';
  OSSL_HPKE_CTX_set1_ikme_procname = 'OSSL_HPKE_CTX_set1_ikme';
  OSSL_HPKE_CTX_set_seq_procname = 'OSSL_HPKE_CTX_set_seq';
  OSSL_HPKE_CTX_get_seq_procname = 'OSSL_HPKE_CTX_get_seq';
  OSSL_HPKE_suite_check_procname = 'OSSL_HPKE_suite_check';
  OSSL_HPKE_get_grease_value_procname = 'OSSL_HPKE_get_grease_value';
  OSSL_HPKE_str2suite_procname = 'OSSL_HPKE_str2suite';
  OSSL_HPKE_get_ciphertext_size_procname = 'OSSL_HPKE_get_ciphertext_size';
  OSSL_HPKE_get_public_encap_size_procname = 'OSSL_HPKE_get_public_encap_size';
  OSSL_HPKE_get_recommended_ikmelen_procname = 'OSSL_HPKE_get_recommended_ikmelen';

  OSSL_HPKE_CTX_new_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
  OSSL_HPKE_CTX_free_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
  OSSL_HPKE_encap_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
  OSSL_HPKE_seal_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
  OSSL_HPKE_keygen_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
  OSSL_HPKE_decap_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
  OSSL_HPKE_open_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
  OSSL_HPKE_export_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
  OSSL_HPKE_CTX_set1_authpriv_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
  OSSL_HPKE_CTX_set1_authpub_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
  OSSL_HPKE_CTX_set1_psk_introduced =  (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
  OSSL_HPKE_CTX_set1_ikme_introduced =  (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
  OSSL_HPKE_CTX_set_seq_introduced =  (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
  OSSL_HPKE_CTX_get_seq_introduced =  (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
  OSSL_HPKE_suite_check_introduced =  (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
  OSSL_HPKE_get_grease_value_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
  OSSL_HPKE_str2suite_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
  OSSL_HPKE_get_ciphertext_size_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
  OSSL_HPKE_get_public_encap_size_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
  OSSL_HPKE_get_recommended_ikmelen_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc}

function ERR_OSSL_HPKE_CTX_new(mode : TIdC_INT; suite : OSSL_HPKE_SUITE; role : TIdC_INT;
    libctx : POSSL_LIB_CTX; const propq : PIdAnsiChar) : POSSL_HPKE_CTX cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HPKE_CTX_new_procname);
end;

procedure ERR_OSSL_HPKE_CTX_free(ctx : POSSL_HPKE_CTX) cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HPKE_CTX_free_procname);
end;

function ERR_OSSL_HPKE_encap(ctx : POSSL_HPKE_CTX;
  enc : PByte; enclen : TIdC_SIZET;
  const pub : PByte; publen : TIdC_SIZET;
  const info : PByte; infolen : TIdC_SIZET) : TIdC_INT cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HPKE_encap_procname);
end;
function ERR_OSSL_HPKE_seal(ctx : POSSL_HPKE_CTX;
    ct : PByte; ctlen : TIdC_SIZET;
    const aad : PByte; aadlen : TIdC_SIZET;
    const pt : PByte; ptlen : TIdC_SIZET) : TIdC_INT cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HPKE_seal_procname);
end;

function ERR_OSSL_HPKE_keygen( suite : OSSL_HPKE_SUITE;
    pub : PByte; publen : PIdC_SIZET; priv : PPEVP_PKEY;
    const ikm : PByte; ikmlen : TIdC_SIZET;
    libctx : POSSL_LIB_CTX; const propq : PByte) : TIdC_INT cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HPKE_keygen_procname);
end;

function ERR_OSSL_HPKE_decap(ctx : POSSL_HPKE_CTX;
    const enc : PByte; enclen : TIdC_SIZET;
    recippriv : PEVP_PKEY;
    const info : PByte; infolen : TIdC_SIZET) : TIdC_INT cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HPKE_decap_procname);
end;

function ERR_OSSL_HPKE_open(ctx : POSSL_HPKE_CTX;
    pt : PByte; ptlen : PIdC_SIZET;
    const aad : PByte; aadlen : TIdC_SIZET;
    const ct : PByte; ctlen : TIdC_SIZET) : TIdC_INT cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HPKE_open_procname);
end;

function ERR_OSSL_HPKE_export(ctx : OSSL_HPKE_CTX;
    secret : PByte;
    secretlen : TIdC_SIZET;
    const _label : PByte;
    labellen : TIdC_SIZET) : TIdC_INT cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HPKE_export_procname);
end;

function ERR_OSSL_HPKE_CTX_set1_authpriv(ctx : POSSL_HPKE_CTX; priv : PEVP_PKEY) : TIdC_INT  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HPKE_CTX_set1_authpriv_procname);
end;

function ERR_OSSL_HPKE_CTX_set1_authpub(ctx : POSSL_HPKE_CTX;
    const pub : PByte;
    publen : TIdC_SIZET) : TIdC_INT  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HPKE_CTX_set1_authpub_procname);
end;

function ERR_OSSL_HPKE_CTX_set1_psk(ctx : POSSL_HPKE_CTX;
    const pskid : PByte;
    const psk : PByte; psklen : TIdC_SIZET) : TIdC_INT cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HPKE_CTX_set1_psk_procname);
end;

function ERR_OSSL_HPKE_CTX_set1_ikme(ctx : POSSL_HPKE_CTX;
    const ikme : PByte; ikmelen : TIdC_SIZET) : TIdC_INT cdecl;
begin
   ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HPKE_CTX_set1_ikme_procname);
end;

function ERR_OSSL_HPKE_CTX_set_seq(ctx : POSSL_HPKE_CTX; seq : TIdC_UINT64) : TIdC_INT cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HPKE_CTX_set_seq_procname);
end;

function ERR_OSSL_HPKE_CTX_get_seq(ctx : POSSL_HPKE_CTX; seq : TIdC_UINT64) : TIdC_INT cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HPKE_CTX_get_seq_procname);
end;

function ERR_OSSL_HPKE_suite_check( suite : OSSL_HPKE_SUITE) : TIdC_INT cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HPKE_suite_check_procname);
end;

function ERR_OSSL_HPKE_get_grease_value(const suite_in : POSSL_HPKE_SUITE;
    suite : POSSL_HPKE_SUITE;
    enc : PByte; enclen : PIdC_SIZET;
    ct : PByte; ctlen : TIdC_SIZET;
    libctx : POSSL_LIB_CTX; const propq : PIdAnsiChar) : TIdC_INT cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HPKE_get_grease_value_procname);
end;

function ERR_OSSL_HPKE_str2suite(const str_ : PIdAnsiChar; suite : POSSL_HPKE_SUITE) : TIdC_INT cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HPKE_str2suite_procname);
end;

function ERR_OSSL_HPKE_get_ciphertext_size(suite : OSSL_HPKE_SUITE; clearlen : TIdC_SIZET) : TIdC_SIZET cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HPKE_get_ciphertext_size_procname);
end;

function ERR_OSSL_HPKE_get_public_encap_size(suite : OSSL_HPKE_SUITE) : TIdC_SIZET cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HPKE_get_public_encap_size_procname);
end;

function ERR_OSSL_HPKE_get_recommended_ikmelen(suite : OSSL_HPKE_SUITE) : TIdC_SIZET cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HPKE_get_recommended_ikmelen_procname);
end;

  {$I TaurusTLSNoRetValOn.inc}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  OSSL_HPKE_CTX_new := LoadLibFunction(ADllHandle, OSSL_HPKE_CTX_new_procname);
  FuncLoadError := not assigned(OSSL_HPKE_CTX_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HPKE_CTX_new_allownil)}
    OSSL_HPKE_CTX_new := ERR_OSSL_HPKE_CTX_new;
    {$ifend}
    {$if declared(OSSL_HPKE_CTX_new_introduced)}
    if LibVersion < OSSL_HPKE_CTX_new_introduced then
    begin
      {$if declared(FC_OSSL_HPKE_CTX_new)}
      OSSL_HPKE_CTX_new := FC_OSSL_HPKE_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HPKE_CTX_new_removed)}
    if OSSL_HPKE_CTX_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HPKE_CTX_new)}
      OSSL_HPKE_CTX_new := _OSSL_HPKE_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HPKE_CTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HPKE_CTX_new');
    {$ifend}
  end;

  OSSL_HPKE_CTX_free := LoadLibFunction(ADllHandle, OSSL_HPKE_CTX_free_procname);
  FuncLoadError := not assigned(OSSL_HPKE_CTX_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HPKE_CTX_free_allownil)}
    OSSL_HPKE_CTX_free := ERR_OSSL_HPKE_CTX_free;
    {$ifend}
    {$if declared(OSSL_HPKE_CTX_free_introduced)}
    if LibVersion < OSSL_HPKE_CTX_free_introduced then
    begin
      {$if declared(FC_OSSL_HPKE_CTX_free)}
      OSSL_HPKE_CTX_free := FC_OSSL_HPKE_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HPKE_CTX_free_removed)}
    if OSSL_HPKE_CTX_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HPKE_CTX_free)}
      OSSL_HPKE_CTX_free := _OSSL_HPKE_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HPKE_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HPKE_CTX_free');
    {$ifend}
  end;

  OSSL_HPKE_encap := LoadLibFunction(ADllHandle, OSSL_HPKE_encap_procname);
  FuncLoadError := not assigned(OSSL_HPKE_encap);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HPKE_encap_allownil)}
    OSSL_HPKE_encap := ERR_OSSL_HPKE_encap;
    {$ifend}
    {$if declared(OSSL_HPKE_encap_introduced)}
    if LibVersion < OSSL_HPKE_encap_introduced then
    begin
      {$if declared(FC_OSSL_HPKE_encap)}
      OSSL_HPKE_encap := FC_OSSL_HPKE_encap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HPKE_encap_removed)}
    if OSSL_HPKE_encap_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HPKE_encap)}
      OSSL_HPKE_encap := _OSSL_HPKE_encap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HPKE_encap_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HPKE_encap');
    {$ifend}
  end;

  OSSL_HPKE_seal := LoadLibFunction(ADllHandle, OSSL_HPKE_seal_procname);
  FuncLoadError := not assigned(OSSL_HPKE_seal);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HPKE_seal_allownil)}
    OSSL_HPKE_seal := ERR_OSSL_HPKE_seal;
    {$ifend}
    {$if declared(OSSL_HPKE_seal_introduced)}
    if LibVersion < OSSL_HPKE_seal_introduced then
    begin
      {$if declared(FC_OSSL_HPKE_seal)}
      OSSL_HPKE_seal := FC_OSSL_HPKE_seal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HPKE_seal_removed)}
    if OSSL_HPKE_seal_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HPKE_seal)}
      OSSL_HPKE_seal := _OSSL_HPKE_seal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HPKE_seal_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HPKE_seal');
    {$ifend}
  end;

  OSSL_HPKE_keygen := LoadLibFunction(ADllHandle, OSSL_HPKE_keygen_procname);
  FuncLoadError := not assigned(OSSL_HPKE_keygen);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HPKE_keygen_allownil)}
    OSSL_HPKE_keygen := ERR_OSSL_HPKE_keygen;
    {$ifend}
    {$if declared(OSSL_HPKE_keygen_introduced)}
    if LibVersion < OSSL_HPKE_keygen_introduced then
    begin
      {$if declared(FC_OSSL_HPKE_keygen)}
      OSSL_HPKE_keygen := FC_OSSL_HPKE_keygen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HPKE_keygen_removed)}
    if OSSL_HPKE_keygen_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HPKE_keygen)}
      OSSL_HPKE_keygen := _OSSL_HPKE_keygen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HPKE_keygen_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HPKE_keygen');
    {$ifend}
  end;

  OSSL_HPKE_decap := LoadLibFunction(ADllHandle, OSSL_HPKE_decap_procname);
  FuncLoadError := not assigned(OSSL_HPKE_decap);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HPKE_decap_allownil)}
    OSSL_HPKE_decap := ERR_OSSL_HPKE_decap;
    {$ifend}
    {$if declared(OSSL_HPKE_decap_introduced)}
    if LibVersion < OSSL_HPKE_decap_introduced then
    begin
      {$if declared(FC_OSSL_HPKE_decap)}
      OSSL_HPKE_decap := FC_OSSL_HPKE_decap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HPKE_decap_removed)}
    if OSSL_HPKE_decap_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HPKE_decap)}
      OSSL_HPKE_decap := _OSSL_HPKE_decap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HPKE_decap_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HPKE_decap');
    {$ifend}
  end;

  OSSL_HPKE_open := LoadLibFunction(ADllHandle, OSSL_HPKE_open_procname);
  FuncLoadError := not assigned(OSSL_HPKE_open);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HPKE_open_allownil)}
    OSSL_HPKE_open := ERR_OSSL_HPKE_open;
    {$ifend}
    {$if declared(OSSL_HPKE_open_introduced)}
    if LibVersion < OSSL_HPKE_open_introduced then
    begin
      {$if declared(FC_OSSL_HPKE_open)}
      OSSL_HPKE_open := FC_OSSL_HPKE_open;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HPKE_open_removed)}
    if OSSL_HPKE_open_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HPKE_open)}
      OSSL_HPKE_open := _OSSL_HPKE_open;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HPKE_open_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HPKE_open');
    {$ifend}
  end;

  OSSL_HPKE_export := LoadLibFunction(ADllHandle, OSSL_HPKE_export_procname);
  FuncLoadError := not assigned(OSSL_HPKE_export);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HPKE_export_allownil)}
    OSSL_HPKE_export := ERR_OSSL_HPKE_export;
    {$ifend}
    {$if declared(OSSL_HPKE_export_introduced)}
    if LibVersion < OSSL_HPKE_export_introduced then
    begin
      {$if declared(FC_OSSL_HPKE_export)}
      OSSL_HPKE_export := FC_OSSL_HPKE_export;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HPKE_export_removed)}
    if OSSL_HPKE_export_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HPKE_export)}
      OSSL_HPKE_export := _OSSL_HPKE_export;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HPKE_export_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HPKE_export');
    {$ifend}
  end;

  OSSL_HPKE_CTX_set1_authpriv := LoadLibFunction(ADllHandle, OSSL_HPKE_CTX_set1_authpriv_procname);
  FuncLoadError := not assigned(OSSL_HPKE_CTX_set1_authpriv);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HPKE_CTX_set1_authpriv_allownil)}
    OSSL_HPKE_CTX_set1_authpriv := ERR_OSSL_HPKE_CTX_set1_authpriv;
    {$ifend}
    {$if declared(OSSL_HPKE_CTX_set1_authpriv_introduced)}
    if LibVersion < OSSL_HPKE_CTX_set1_authpriv_introduced then
    begin
      {$if declared(FC_OSSL_HPKE_CTX_set1_authpriv)}
      OSSL_HPKE_CTX_set1_authpriv := FC_OSSL_HPKE_CTX_set1_authpriv;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HPKE_CTX_set1_authpriv_removed)}
    if OSSL_HPKE_CTX_set1_authpriv_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HPKE_CTX_set1_authpriv)}
      OSSL_HPKE_CTX_set1_authpriv := _OSSL_HPKE_CTX_set1_authpriv;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HPKE_CTX_set1_authpriv_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HPKE_CTX_set1_authpriv');
    {$ifend}
  end;

  OSSL_HPKE_CTX_set1_authpub := LoadLibFunction(ADllHandle, OSSL_HPKE_CTX_set1_authpub_procname);
  FuncLoadError := not assigned(OSSL_HPKE_CTX_set1_authpub);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HPKE_CTX_set1_authpub_allownil)}
    OSSL_HPKE_CTX_set1_authpub := ERR_OSSL_HPKE_CTX_set1_authpub;
    {$ifend}
    {$if declared(OSSL_HPKE_CTX_set1_authpub_introduced)}
    if LibVersion < OSSL_HPKE_CTX_set1_authpub_introduced then
    begin
      {$if declared(FC_OSSL_HPKE_CTX_set1_authpub)}
      OSSL_HPKE_CTX_set1_authpub := FC_OSSL_HPKE_CTX_set1_authpub;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HPKE_CTX_set1_authpub_removed)}
    if OSSL_HPKE_CTX_set1_authpub_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HPKE_CTX_set1_authpub)}
      OSSL_HPKE_CTX_set1_authpub := _OSSL_HPKE_CTX_set1_authpub;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HPKE_CTX_set1_authpub_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HPKE_CTX_set1_authpub');
    {$ifend}
  end;

  OSSL_HPKE_CTX_set1_psk := LoadLibFunction(ADllHandle, OSSL_HPKE_CTX_set1_psk_procname);
  FuncLoadError := not assigned(OSSL_HPKE_CTX_set1_psk);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HPKE_CTX_set1_psk_allownil)}
    OSSL_HPKE_CTX_set1_psk := ERR_OSSL_HPKE_CTX_set1_psk;
    {$ifend}
    {$if declared(OSSL_HPKE_CTX_set1_psk_introduced)}
    if LibVersion < OSSL_HPKE_CTX_set1_psk_introduced then
    begin
      {$if declared(FC_OSSL_HPKE_CTX_set1_psk)}
      OSSL_HPKE_CTX_set1_psk := FC_OSSL_HPKE_CTX_set1_psk;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HPKE_CTX_set1_psk_removed)}
    if OSSL_HPKE_CTX_set1_psk_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HPKE_CTX_set1_psk)}
      OSSL_HPKE_CTX_set1_psk := _OSSL_HPKE_CTX_set1_psk;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HPKE_CTX_set1_psk_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HPKE_CTX_set1_psk');
    {$ifend}
  end;

  OSSL_HPKE_CTX_set1_ikme := LoadLibFunction(ADllHandle, OSSL_HPKE_CTX_set1_ikme_procname);
  FuncLoadError := not assigned(OSSL_HPKE_CTX_set1_ikme);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HPKE_CTX_set1_ikme_allownil)}
    OSSL_HPKE_CTX_set1_ikme := ERR_OSSL_HPKE_CTX_set1_ikme;
    {$ifend}
    {$if declared(OSSL_HPKE_CTX_set1_ikme_introduced)}
    if LibVersion < OSSL_HPKE_CTX_set1_ikme_introduced then
    begin
      {$if declared(FC_OSSL_HPKE_CTX_set1_ikme)}
      OSSL_HPKE_CTX_set1_ikme := FC_OSSL_HPKE_CTX_set1_ikme;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HPKE_CTX_set1_ikme_removed)}
    if OSSL_HPKE_CTX_set1_ikme_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HPKE_CTX_set1_ikme)}
      OSSL_HPKE_CTX_set1_ikme := _OSSL_HPKE_CTX_set1_ikme;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HPKE_CTX_set1_ikme_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HPKE_CTX_set1_ikme');
    {$ifend}
  end;

  OSSL_HPKE_CTX_set_seq := LoadLibFunction(ADllHandle, OSSL_HPKE_CTX_set_seq_procname);
  FuncLoadError := not assigned(OSSL_HPKE_CTX_set_seq);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HPKE_CTX_set_seq_allownil)}
    OSSL_HPKE_CTX_set_seq := ERR_OSSL_HPKE_CTX_set_seq;
    {$ifend}
    {$if declared(OSSL_HPKE_CTX_set_seq_introduced)}
    if LibVersion < OSSL_HPKE_CTX_set_seq_introduced then
    begin
      {$if declared(FC_OSSL_HPKE_CTX_set_seq)}
      OSSL_HPKE_CTX_set_seq := FC_OSSL_HPKE_CTX_set_seq;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HPKE_CTX_set_seq_removed)}
    if OSSL_HPKE_CTX_set_seq_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HPKE_CTX_set_seq)}
      OSSL_HPKE_CTX_set_seq := _OSSL_HPKE_CTX_set_seq;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HPKE_CTX_set_seq_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HPKE_CTX_set_seq');
    {$ifend}
  end;

  OSSL_HPKE_CTX_get_seq := LoadLibFunction(ADllHandle, OSSL_HPKE_CTX_get_seq_procname);
  FuncLoadError := not assigned(OSSL_HPKE_CTX_get_seq);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HPKE_CTX_get_seq_allownil)}
    OSSL_HPKE_CTX_get_seq := ERR_OSSL_HPKE_CTX_get_seq;
    {$ifend}
    {$if declared(OSSL_HPKE_CTX_get_seq_introduced)}
    if LibVersion < OSSL_HPKE_CTX_get_seq_introduced then
    begin
      {$if declared(FC_OSSL_HPKE_CTX_get_seq)}
      OSSL_HPKE_CTX_get_seq := FC_OSSL_HPKE_CTX_get_seq;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HPKE_CTX_get_seq_removed)}
    if OSSL_HPKE_CTX_get_seq_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HPKE_CTX_get_seq)}
      OSSL_HPKE_CTX_get_seq := _OSSL_HPKE_CTX_get_seq;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HPKE_CTX_get_seq_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HPKE_CTX_get_seq');
    {$ifend}
  end;

  OSSL_HPKE_suite_check := LoadLibFunction(ADllHandle, OSSL_HPKE_suite_check_procname);
  FuncLoadError := not assigned(OSSL_HPKE_suite_check);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HPKE_suite_check_allownil)}
    OSSL_HPKE_suite_check := ERR_OSSL_HPKE_suite_check;
    {$ifend}
    {$if declared(OSSL_HPKE_suite_check_introduced)}
    if LibVersion < OSSL_HPKE_suite_check_introduced then
    begin
      {$if declared(FC_OSSL_HPKE_suite_check)}
      OSSL_HPKE_suite_check := FC_OSSL_HPKE_suite_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HPKE_suite_check_removed)}
    if OSSL_HPKE_suite_check_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HPKE_suite_check)}
      OSSL_HPKE_suite_check := _OSSL_HPKE_suite_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HPKE_suite_check_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HPKE_suite_check');
    {$ifend}
  end;

  OSSL_HPKE_get_grease_value := LoadLibFunction(ADllHandle, OSSL_HPKE_get_grease_value_procname);
  FuncLoadError := not assigned(OSSL_HPKE_get_grease_value);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HPKE_get_grease_value_allownil)}
    OSSL_HPKE_get_grease_value := ERR_OSSL_HPKE_get_grease_value;
    {$ifend}
    {$if declared(OSSL_HPKE_get_grease_value_introduced)}
    if LibVersion < OSSL_HPKE_get_grease_value_introduced then
    begin
      {$if declared(FC_OSSL_HPKE_get_grease_value)}
      OSSL_HPKE_get_grease_value := FC_OSSL_HPKE_get_grease_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HPKE_get_grease_value_removed)}
    if OSSL_HPKE_get_grease_value_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HPKE_get_grease_value)}
      OSSL_HPKE_get_grease_value := _OSSL_HPKE_get_grease_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HPKE_get_grease_value_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HPKE_get_grease_value');
    {$ifend}
  end;

  OSSL_HPKE_str2suite := LoadLibFunction(ADllHandle, OSSL_HPKE_str2suite_procname);
  FuncLoadError := not assigned(OSSL_HPKE_str2suite);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HPKE_str2suite_allownil)}
    OSSL_HPKE_str2suite := ERR_OSSL_HPKE_str2suite;
    {$ifend}
    {$if declared(OSSL_HPKE_str2suite_introduced)}
    if LibVersion < OSSL_HPKE_str2suite_introduced then
    begin
      {$if declared(FC_OSSL_HPKE_str2suite)}
      OSSL_HPKE_str2suite := FC_OSSL_HPKE_str2suite;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HPKE_str2suite_removed)}
    if OSSL_HPKE_str2suite_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HPKE_str2suite)}
      OSSL_HPKE_str2suite := _OSSL_HPKE_str2suite;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HPKE_str2suite_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HPKE_str2suite');
    {$ifend}
  end;

  OSSL_HPKE_get_ciphertext_size := LoadLibFunction(ADllHandle, OSSL_HPKE_get_ciphertext_size_procname);
  FuncLoadError := not assigned(OSSL_HPKE_get_ciphertext_size);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HPKE_get_ciphertext_size_allownil)}
    OSSL_HPKE_get_ciphertext_size := ERR_OSSL_HPKE_get_ciphertext_size;
    {$ifend}
    {$if declared(OSSL_HPKE_get_ciphertext_size_introduced)}
    if LibVersion < OSSL_HPKE_get_ciphertext_size_introduced then
    begin
      {$if declared(FC_OSSL_HPKE_get_ciphertext_size)}
      OSSL_HPKE_get_ciphertext_size := FC_OSSL_HPKE_get_ciphertext_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HPKE_get_ciphertext_size_removed)}
    if OSSL_HPKE_get_ciphertext_size_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HPKE_get_ciphertext_size)}
      OSSL_HPKE_get_ciphertext_size := _OSSL_HPKE_get_ciphertext_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HPKE_get_ciphertext_size_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HPKE_get_ciphertext_size');
    {$ifend}
  end;

  OSSL_HPKE_get_public_encap_size := LoadLibFunction(ADllHandle, OSSL_HPKE_get_public_encap_size_procname);
  FuncLoadError := not assigned(OSSL_HPKE_get_public_encap_size);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HPKE_get_public_encap_size_allownil)}
    OSSL_HPKE_get_public_encap_size := ERR_OSSL_HPKE_get_public_encap_size;
    {$ifend}
    {$if declared(OSSL_HPKE_get_public_encap_size_introduced)}
    if LibVersion < OSSL_HPKE_get_public_encap_size_introduced then
    begin
      {$if declared(FC_OSSL_HPKE_get_public_encap_size)}
      OSSL_HPKE_get_public_encap_size := FC_OSSL_HPKE_get_public_encap_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HPKE_get_public_encap_size_removed)}
    if OSSL_HPKE_get_public_encap_size_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HPKE_get_public_encap_size)}
      OSSL_HPKE_get_public_encap_size := _OSSL_HPKE_get_public_encap_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HPKE_get_public_encap_size_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HPKE_get_public_encap_size');
    {$ifend}
  end;

  OSSL_HPKE_get_recommended_ikmelen := LoadLibFunction(ADllHandle, OSSL_HPKE_get_recommended_ikmelen_procname);
  FuncLoadError := not assigned(OSSL_HPKE_get_recommended_ikmelen);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HPKE_get_recommended_ikmelen_allownil)}
    OSSL_HPKE_get_recommended_ikmelen := ERR_OSSL_HPKE_get_recommended_ikmelen;
    {$ifend}
    {$if declared(OSSL_HPKE_get_recommended_ikmelen_introduced)}
    if LibVersion < OSSL_HPKE_get_recommended_ikmelen_introduced then
    begin
      {$if declared(FC_OSSL_HPKE_get_recommended_ikmelen)}
      OSSL_HPKE_get_recommended_ikmelen := FC_OSSL_HPKE_get_recommended_ikmelen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HPKE_get_recommended_ikmelen_removed)}
    if OSSL_HPKE_get_recommended_ikmelen_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HPKE_get_recommended_ikmelen)}
      OSSL_HPKE_get_recommended_ikmelen := _OSSL_HPKE_get_recommended_ikmelen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HPKE_get_recommended_ikmelen_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HPKE_get_recommended_ikmelen');
    {$ifend}
  end;
end;

procedure Unload;
begin
  OSSL_HPKE_CTX_new := nil;
  OSSL_HPKE_CTX_free := nil;
  OSSL_HPKE_encap := nil;
  OSSL_HPKE_seal := nil;
  OSSL_HPKE_keygen := nil;
  OSSL_HPKE_decap := nil;
  OSSL_HPKE_open := nil;
  OSSL_HPKE_export := nil;
  OSSL_HPKE_CTX_set1_authpriv := nil;
  OSSL_HPKE_CTX_set1_authpub := nil;
  OSSL_HPKE_CTX_set1_psk := nil;
  OSSL_HPKE_CTX_set1_ikme := nil;
  OSSL_HPKE_CTX_set_seq := nil;
  OSSL_HPKE_CTX_get_seq  := nil;
  OSSL_HPKE_suite_check := nil;
  OSSL_HPKE_get_grease_value := nil;
  OSSL_HPKE_str2suite := nil;
  OSSL_HPKE_get_ciphertext_size := nil;
  OSSL_HPKE_get_public_encap_size  := nil;
  OSSL_HPKE_get_recommended_ikmelen := nil;
end;
  {$ENDIF}
{$ELSE}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
