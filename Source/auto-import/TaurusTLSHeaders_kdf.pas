{$I TaurusTLSCompilerDefines.inc}
{$I TaurusTLSLinkDefines.inc}
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

unit TaurusTLSHeaders_kdf;

interface

uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_ossl_types,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_core;




// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // EVP_KDF_do_all_provided_fn_cb = procedure(kdf: PEVP_KDF; arg: Pointer); cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // EVP_KDF_names_do_all_fn_cb = procedure(name: PIdAnsiChar; data: Pointer); cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND = 0;
  EVP_KDF_HKDF_MODE_EXTRACT_ONLY = 1;
  EVP_KDF_HKDF_MODE_EXPAND_ONLY = 2;
  EVP_KDF_SSHKDF_TYPE_INITIAL_IV_CLI_TO_SRV = 65;
  EVP_KDF_SSHKDF_TYPE_INITIAL_IV_SRV_TO_CLI = 66;
  EVP_KDF_SSHKDF_TYPE_ENCRYPTION_KEY_CLI_TO_SRV = 67;
  EVP_KDF_SSHKDF_TYPE_ENCRYPTION_KEY_SRV_TO_CLI = 68;
  EVP_KDF_SSHKDF_TYPE_INTEGRITY_KEY_CLI_TO_SRV = 69;
  EVP_KDF_SSHKDF_TYPE_INTEGRITY_KEY_SRV_TO_CLI = 70;
  EVP_PKEY_CTRL_TLS_MD = (EVP_PKEY_ALG_CTRL);
  EVP_PKEY_CTRL_TLS_SECRET = (EVP_PKEY_ALG_CTRL+1);
  EVP_PKEY_CTRL_TLS_SEED = (EVP_PKEY_ALG_CTRL+2);
  EVP_PKEY_CTRL_HKDF_MD = (EVP_PKEY_ALG_CTRL+3);
  EVP_PKEY_CTRL_HKDF_SALT = (EVP_PKEY_ALG_CTRL+4);
  EVP_PKEY_CTRL_HKDF_KEY = (EVP_PKEY_ALG_CTRL+5);
  EVP_PKEY_CTRL_HKDF_INFO = (EVP_PKEY_ALG_CTRL+6);
  EVP_PKEY_CTRL_HKDF_MODE = (EVP_PKEY_ALG_CTRL+7);
  EVP_PKEY_CTRL_PASS = (EVP_PKEY_ALG_CTRL+8);
  EVP_PKEY_CTRL_SCRYPT_SALT = (EVP_PKEY_ALG_CTRL+9);
  EVP_PKEY_CTRL_SCRYPT_N = (EVP_PKEY_ALG_CTRL+10);
  EVP_PKEY_CTRL_SCRYPT_R = (EVP_PKEY_ALG_CTRL+11);
  EVP_PKEY_CTRL_SCRYPT_P = (EVP_PKEY_ALG_CTRL+12);
  EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES = (EVP_PKEY_ALG_CTRL+13);
  EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
  EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
  EVP_PKEY_HKDEF_MODE_EXPAND_ONLY = EVP_KDF_HKDF_MODE_EXPAND_ONLY;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  EVP_KDF_up_ref: function(kdf: PEVP_KDF): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_KDF_up_ref}

  EVP_KDF_free: procedure(kdf: PEVP_KDF); cdecl = nil;
  {$EXTERNALSYM EVP_KDF_free}

  EVP_KDF_fetch: function(libctx: POSSL_LIB_CTX; algorithm: PIdAnsiChar; properties: PIdAnsiChar): PEVP_KDF; cdecl = nil;
  {$EXTERNALSYM EVP_KDF_fetch}

  EVP_KDF_CTX_new: function(kdf: PEVP_KDF): PEVP_KDF_CTX; cdecl = nil;
  {$EXTERNALSYM EVP_KDF_CTX_new}

  EVP_KDF_CTX_free: procedure(ctx: PEVP_KDF_CTX); cdecl = nil;
  {$EXTERNALSYM EVP_KDF_CTX_free}

  EVP_KDF_CTX_dup: function(src: PEVP_KDF_CTX): PEVP_KDF_CTX; cdecl = nil;
  {$EXTERNALSYM EVP_KDF_CTX_dup}

  EVP_KDF_get0_description: function(kdf: PEVP_KDF): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM EVP_KDF_get0_description}

  EVP_KDF_is_a: function(kdf: PEVP_KDF; name: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_KDF_is_a}

  EVP_KDF_get0_name: function(kdf: PEVP_KDF): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM EVP_KDF_get0_name}

  EVP_KDF_get0_provider: function(kdf: PEVP_KDF): POSSL_PROVIDER; cdecl = nil;
  {$EXTERNALSYM EVP_KDF_get0_provider}

  EVP_KDF_CTX_kdf: function(ctx: PEVP_KDF_CTX): PEVP_KDF; cdecl = nil;
  {$EXTERNALSYM EVP_KDF_CTX_kdf}

  EVP_KDF_CTX_reset: procedure(ctx: PEVP_KDF_CTX); cdecl = nil;
  {$EXTERNALSYM EVP_KDF_CTX_reset}

  EVP_KDF_CTX_get_kdf_size: function(ctx: PEVP_KDF_CTX): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM EVP_KDF_CTX_get_kdf_size}

  EVP_KDF_derive: function(ctx: PEVP_KDF_CTX; key: PIdAnsiChar; keylen: TIdC_SIZET; params: POSSL_PARAM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_KDF_derive}

  EVP_KDF_CTX_set_SKEY: function(ctx: PEVP_KDF_CTX; key: PEVP_SKEY; paramname: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_KDF_CTX_set_SKEY}

  EVP_KDF_derive_SKEY: function(ctx: PEVP_KDF_CTX; mgmt: PEVP_SKEYMGMT; key_type: PIdAnsiChar; propquery: PIdAnsiChar; keylen: TIdC_SIZET; params: POSSL_PARAM): PEVP_SKEY; cdecl = nil;
  {$EXTERNALSYM EVP_KDF_derive_SKEY}

  EVP_KDF_get_params: function(kdf: PEVP_KDF; params: POSSL_PARAM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_KDF_get_params}

  EVP_KDF_CTX_get_params: function(ctx: PEVP_KDF_CTX; params: POSSL_PARAM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_KDF_CTX_get_params}

  EVP_KDF_CTX_set_params: function(ctx: PEVP_KDF_CTX; params: POSSL_PARAM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_KDF_CTX_set_params}

  EVP_KDF_gettable_params: function(kdf: PEVP_KDF): POSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM EVP_KDF_gettable_params}

  EVP_KDF_gettable_ctx_params: function(kdf: PEVP_KDF): POSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM EVP_KDF_gettable_ctx_params}

  EVP_KDF_settable_ctx_params: function(kdf: PEVP_KDF): POSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM EVP_KDF_settable_ctx_params}

  EVP_KDF_CTX_gettable_params: function(ctx: PEVP_KDF_CTX): POSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM EVP_KDF_CTX_gettable_params}

  EVP_KDF_CTX_settable_params: function(ctx: PEVP_KDF_CTX): POSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM EVP_KDF_CTX_settable_params}

  EVP_KDF_do_all_provided: procedure(libctx: POSSL_LIB_CTX; fn: TEVP_KDF_do_all_provided_fn_cb; arg: Pointer); cdecl = nil;
  {$EXTERNALSYM EVP_KDF_do_all_provided}

  EVP_KDF_names_do_all: function(kdf: PEVP_KDF; fn: TEVP_KDF_names_do_all_fn_cb; data: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_KDF_names_do_all}

  EVP_PKEY_CTX_set_tls1_prf_md: function(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_tls1_prf_md}

  EVP_PKEY_CTX_set1_tls1_prf_secret: function(pctx: PEVP_PKEY_CTX; sec: PIdAnsiChar; seclen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set1_tls1_prf_secret}

  EVP_PKEY_CTX_add1_tls1_prf_seed: function(pctx: PEVP_PKEY_CTX; seed: PIdAnsiChar; seedlen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_add1_tls1_prf_seed}

  EVP_PKEY_CTX_set_hkdf_md: function(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_hkdf_md}

  EVP_PKEY_CTX_set1_hkdf_salt: function(ctx: PEVP_PKEY_CTX; salt: PIdAnsiChar; saltlen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set1_hkdf_salt}

  EVP_PKEY_CTX_set1_hkdf_key: function(ctx: PEVP_PKEY_CTX; key: PIdAnsiChar; keylen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set1_hkdf_key}

  EVP_PKEY_CTX_add1_hkdf_info: function(ctx: PEVP_PKEY_CTX; info: PIdAnsiChar; infolen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_add1_hkdf_info}

  EVP_PKEY_CTX_set_hkdf_mode: function(ctx: PEVP_PKEY_CTX; mode: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_hkdf_mode}

  EVP_PKEY_CTX_set1_pbe_pass: function(ctx: PEVP_PKEY_CTX; pass: PIdAnsiChar; passlen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set1_pbe_pass}

  EVP_PKEY_CTX_set1_scrypt_salt: function(ctx: PEVP_PKEY_CTX; salt: PIdAnsiChar; saltlen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set1_scrypt_salt}

  EVP_PKEY_CTX_set_scrypt_N: function(ctx: PEVP_PKEY_CTX; n: TIdC_UINT64): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_scrypt_N}

  EVP_PKEY_CTX_set_scrypt_r: function(ctx: PEVP_PKEY_CTX; r: TIdC_UINT64): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_scrypt_r}

  EVP_PKEY_CTX_set_scrypt_p: function(ctx: PEVP_PKEY_CTX; p: TIdC_UINT64): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_scrypt_p}

  EVP_PKEY_CTX_set_scrypt_maxmem_bytes: function(ctx: PEVP_PKEY_CTX; maxmem_bytes: TIdC_UINT64): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_scrypt_maxmem_bytes}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function EVP_KDF_up_ref(kdf: PEVP_KDF): TIdC_INT; cdecl;
procedure EVP_KDF_free(kdf: PEVP_KDF); cdecl;
function EVP_KDF_fetch(libctx: POSSL_LIB_CTX; algorithm: PIdAnsiChar; properties: PIdAnsiChar): PEVP_KDF; cdecl;
function EVP_KDF_CTX_new(kdf: PEVP_KDF): PEVP_KDF_CTX; cdecl;
procedure EVP_KDF_CTX_free(ctx: PEVP_KDF_CTX); cdecl;
function EVP_KDF_CTX_dup(src: PEVP_KDF_CTX): PEVP_KDF_CTX; cdecl;
function EVP_KDF_get0_description(kdf: PEVP_KDF): PIdAnsiChar; cdecl;
function EVP_KDF_is_a(kdf: PEVP_KDF; name: PIdAnsiChar): TIdC_INT; cdecl;
function EVP_KDF_get0_name(kdf: PEVP_KDF): PIdAnsiChar; cdecl;
function EVP_KDF_get0_provider(kdf: PEVP_KDF): POSSL_PROVIDER; cdecl;
function EVP_KDF_CTX_kdf(ctx: PEVP_KDF_CTX): PEVP_KDF; cdecl;
procedure EVP_KDF_CTX_reset(ctx: PEVP_KDF_CTX); cdecl;
function EVP_KDF_CTX_get_kdf_size(ctx: PEVP_KDF_CTX): TIdC_SIZET; cdecl;
function EVP_KDF_derive(ctx: PEVP_KDF_CTX; key: PIdAnsiChar; keylen: TIdC_SIZET; params: POSSL_PARAM): TIdC_INT; cdecl;
function EVP_KDF_CTX_set_SKEY(ctx: PEVP_KDF_CTX; key: PEVP_SKEY; paramname: PIdAnsiChar): TIdC_INT; cdecl;
function EVP_KDF_derive_SKEY(ctx: PEVP_KDF_CTX; mgmt: PEVP_SKEYMGMT; key_type: PIdAnsiChar; propquery: PIdAnsiChar; keylen: TIdC_SIZET; params: POSSL_PARAM): PEVP_SKEY; cdecl;
function EVP_KDF_get_params(kdf: PEVP_KDF; params: POSSL_PARAM): TIdC_INT; cdecl;
function EVP_KDF_CTX_get_params(ctx: PEVP_KDF_CTX; params: POSSL_PARAM): TIdC_INT; cdecl;
function EVP_KDF_CTX_set_params(ctx: PEVP_KDF_CTX; params: POSSL_PARAM): TIdC_INT; cdecl;
function EVP_KDF_gettable_params(kdf: PEVP_KDF): POSSL_PARAM; cdecl;
function EVP_KDF_gettable_ctx_params(kdf: PEVP_KDF): POSSL_PARAM; cdecl;
function EVP_KDF_settable_ctx_params(kdf: PEVP_KDF): POSSL_PARAM; cdecl;
function EVP_KDF_CTX_gettable_params(ctx: PEVP_KDF_CTX): POSSL_PARAM; cdecl;
function EVP_KDF_CTX_settable_params(ctx: PEVP_KDF_CTX): POSSL_PARAM; cdecl;
procedure EVP_KDF_do_all_provided(libctx: POSSL_LIB_CTX; fn: TEVP_KDF_do_all_provided_fn_cb; arg: Pointer); cdecl;
function EVP_KDF_names_do_all(kdf: PEVP_KDF; fn: TEVP_KDF_names_do_all_fn_cb; data: Pointer): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_tls1_prf_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set1_tls1_prf_secret(pctx: PEVP_PKEY_CTX; sec: PIdAnsiChar; seclen: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_add1_tls1_prf_seed(pctx: PEVP_PKEY_CTX; seed: PIdAnsiChar; seedlen: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_hkdf_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set1_hkdf_salt(ctx: PEVP_PKEY_CTX; salt: PIdAnsiChar; saltlen: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set1_hkdf_key(ctx: PEVP_PKEY_CTX; key: PIdAnsiChar; keylen: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_add1_hkdf_info(ctx: PEVP_PKEY_CTX; info: PIdAnsiChar; infolen: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_hkdf_mode(ctx: PEVP_PKEY_CTX; mode: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set1_pbe_pass(ctx: PEVP_PKEY_CTX; pass: PIdAnsiChar; passlen: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set1_scrypt_salt(ctx: PEVP_PKEY_CTX; salt: PIdAnsiChar; saltlen: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_scrypt_N(ctx: PEVP_PKEY_CTX; n: TIdC_UINT64): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_scrypt_r(ctx: PEVP_PKEY_CTX; r: TIdC_UINT64): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_scrypt_p(ctx: PEVP_PKEY_CTX; p: TIdC_UINT64): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_scrypt_maxmem_bytes(ctx: PEVP_PKEY_CTX; maxmem_bytes: TIdC_UINT64): TIdC_INT; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// INLINE OR MACRO ROUTINES
// =============================================================================

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function EVP_PKEY_CTX_hkdf_mode(ctx: PEVP_PKEY_CTX; mode: TIdC_INT): TIdC_INT; cdecl;


implementation

uses
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  classes,
  TaurusTLSLoader,
  {$ENDIF}
  TaurusTLS_ResourceStrings,
  TaurusTLSExceptionHandlers;

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES IMPORTS
// =============================================================================

function EVP_KDF_up_ref(kdf: PEVP_KDF): TIdC_INT; cdecl external CLibCrypto name 'EVP_KDF_up_ref';
procedure EVP_KDF_free(kdf: PEVP_KDF); cdecl external CLibCrypto name 'EVP_KDF_free';
function EVP_KDF_fetch(libctx: POSSL_LIB_CTX; algorithm: PIdAnsiChar; properties: PIdAnsiChar): PEVP_KDF; cdecl external CLibCrypto name 'EVP_KDF_fetch';
function EVP_KDF_CTX_new(kdf: PEVP_KDF): PEVP_KDF_CTX; cdecl external CLibCrypto name 'EVP_KDF_CTX_new';
procedure EVP_KDF_CTX_free(ctx: PEVP_KDF_CTX); cdecl external CLibCrypto name 'EVP_KDF_CTX_free';
function EVP_KDF_CTX_dup(src: PEVP_KDF_CTX): PEVP_KDF_CTX; cdecl external CLibCrypto name 'EVP_KDF_CTX_dup';
function EVP_KDF_get0_description(kdf: PEVP_KDF): PIdAnsiChar; cdecl external CLibCrypto name 'EVP_KDF_get0_description';
function EVP_KDF_is_a(kdf: PEVP_KDF; name: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'EVP_KDF_is_a';
function EVP_KDF_get0_name(kdf: PEVP_KDF): PIdAnsiChar; cdecl external CLibCrypto name 'EVP_KDF_get0_name';
function EVP_KDF_get0_provider(kdf: PEVP_KDF): POSSL_PROVIDER; cdecl external CLibCrypto name 'EVP_KDF_get0_provider';
function EVP_KDF_CTX_kdf(ctx: PEVP_KDF_CTX): PEVP_KDF; cdecl external CLibCrypto name 'EVP_KDF_CTX_kdf';
procedure EVP_KDF_CTX_reset(ctx: PEVP_KDF_CTX); cdecl external CLibCrypto name 'EVP_KDF_CTX_reset';
function EVP_KDF_CTX_get_kdf_size(ctx: PEVP_KDF_CTX): TIdC_SIZET; cdecl external CLibCrypto name 'EVP_KDF_CTX_get_kdf_size';
function EVP_KDF_derive(ctx: PEVP_KDF_CTX; key: PIdAnsiChar; keylen: TIdC_SIZET; params: POSSL_PARAM): TIdC_INT; cdecl external CLibCrypto name 'EVP_KDF_derive';
function EVP_KDF_CTX_set_SKEY(ctx: PEVP_KDF_CTX; key: PEVP_SKEY; paramname: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'EVP_KDF_CTX_set_SKEY';
function EVP_KDF_derive_SKEY(ctx: PEVP_KDF_CTX; mgmt: PEVP_SKEYMGMT; key_type: PIdAnsiChar; propquery: PIdAnsiChar; keylen: TIdC_SIZET; params: POSSL_PARAM): PEVP_SKEY; cdecl external CLibCrypto name 'EVP_KDF_derive_SKEY';
function EVP_KDF_get_params(kdf: PEVP_KDF; params: POSSL_PARAM): TIdC_INT; cdecl external CLibCrypto name 'EVP_KDF_get_params';
function EVP_KDF_CTX_get_params(ctx: PEVP_KDF_CTX; params: POSSL_PARAM): TIdC_INT; cdecl external CLibCrypto name 'EVP_KDF_CTX_get_params';
function EVP_KDF_CTX_set_params(ctx: PEVP_KDF_CTX; params: POSSL_PARAM): TIdC_INT; cdecl external CLibCrypto name 'EVP_KDF_CTX_set_params';
function EVP_KDF_gettable_params(kdf: PEVP_KDF): POSSL_PARAM; cdecl external CLibCrypto name 'EVP_KDF_gettable_params';
function EVP_KDF_gettable_ctx_params(kdf: PEVP_KDF): POSSL_PARAM; cdecl external CLibCrypto name 'EVP_KDF_gettable_ctx_params';
function EVP_KDF_settable_ctx_params(kdf: PEVP_KDF): POSSL_PARAM; cdecl external CLibCrypto name 'EVP_KDF_settable_ctx_params';
function EVP_KDF_CTX_gettable_params(ctx: PEVP_KDF_CTX): POSSL_PARAM; cdecl external CLibCrypto name 'EVP_KDF_CTX_gettable_params';
function EVP_KDF_CTX_settable_params(ctx: PEVP_KDF_CTX): POSSL_PARAM; cdecl external CLibCrypto name 'EVP_KDF_CTX_settable_params';
procedure EVP_KDF_do_all_provided(libctx: POSSL_LIB_CTX; fn: TEVP_KDF_do_all_provided_fn_cb; arg: Pointer); cdecl external CLibCrypto name 'EVP_KDF_do_all_provided';
function EVP_KDF_names_do_all(kdf: PEVP_KDF; fn: TEVP_KDF_names_do_all_fn_cb; data: Pointer): TIdC_INT; cdecl external CLibCrypto name 'EVP_KDF_names_do_all';
function EVP_PKEY_CTX_set_tls1_prf_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_tls1_prf_md';
function EVP_PKEY_CTX_set1_tls1_prf_secret(pctx: PEVP_PKEY_CTX; sec: PIdAnsiChar; seclen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set1_tls1_prf_secret';
function EVP_PKEY_CTX_add1_tls1_prf_seed(pctx: PEVP_PKEY_CTX; seed: PIdAnsiChar; seedlen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_add1_tls1_prf_seed';
function EVP_PKEY_CTX_set_hkdf_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_hkdf_md';
function EVP_PKEY_CTX_set1_hkdf_salt(ctx: PEVP_PKEY_CTX; salt: PIdAnsiChar; saltlen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set1_hkdf_salt';
function EVP_PKEY_CTX_set1_hkdf_key(ctx: PEVP_PKEY_CTX; key: PIdAnsiChar; keylen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set1_hkdf_key';
function EVP_PKEY_CTX_add1_hkdf_info(ctx: PEVP_PKEY_CTX; info: PIdAnsiChar; infolen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_add1_hkdf_info';
function EVP_PKEY_CTX_set_hkdf_mode(ctx: PEVP_PKEY_CTX; mode: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_hkdf_mode';
function EVP_PKEY_CTX_set1_pbe_pass(ctx: PEVP_PKEY_CTX; pass: PIdAnsiChar; passlen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set1_pbe_pass';
function EVP_PKEY_CTX_set1_scrypt_salt(ctx: PEVP_PKEY_CTX; salt: PIdAnsiChar; saltlen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set1_scrypt_salt';
function EVP_PKEY_CTX_set_scrypt_N(ctx: PEVP_PKEY_CTX; n: TIdC_UINT64): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_scrypt_N';
function EVP_PKEY_CTX_set_scrypt_r(ctx: PEVP_PKEY_CTX; r: TIdC_UINT64): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_scrypt_r';
function EVP_PKEY_CTX_set_scrypt_p(ctx: PEVP_PKEY_CTX; p: TIdC_UINT64): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_scrypt_p';
function EVP_PKEY_CTX_set_scrypt_maxmem_bytes(ctx: PEVP_PKEY_CTX; maxmem_bytes: TIdC_UINT64): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_scrypt_maxmem_bytes';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  EVP_KDF_up_ref_procname = 'EVP_KDF_up_ref';
  EVP_KDF_up_ref_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_KDF_free_procname = 'EVP_KDF_free';
  EVP_KDF_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_KDF_fetch_procname = 'EVP_KDF_fetch';
  EVP_KDF_fetch_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_KDF_CTX_new_procname = 'EVP_KDF_CTX_new';
  EVP_KDF_CTX_new_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_KDF_CTX_free_procname = 'EVP_KDF_CTX_free';
  EVP_KDF_CTX_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_KDF_CTX_dup_procname = 'EVP_KDF_CTX_dup';
  EVP_KDF_CTX_dup_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_KDF_get0_description_procname = 'EVP_KDF_get0_description';
  EVP_KDF_get0_description_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_KDF_is_a_procname = 'EVP_KDF_is_a';
  EVP_KDF_is_a_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_KDF_get0_name_procname = 'EVP_KDF_get0_name';
  EVP_KDF_get0_name_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_KDF_get0_provider_procname = 'EVP_KDF_get0_provider';
  EVP_KDF_get0_provider_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_KDF_CTX_kdf_procname = 'EVP_KDF_CTX_kdf';
  EVP_KDF_CTX_kdf_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_KDF_CTX_reset_procname = 'EVP_KDF_CTX_reset';
  EVP_KDF_CTX_reset_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_KDF_CTX_get_kdf_size_procname = 'EVP_KDF_CTX_get_kdf_size';
  EVP_KDF_CTX_get_kdf_size_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_KDF_derive_procname = 'EVP_KDF_derive';
  EVP_KDF_derive_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_KDF_CTX_set_SKEY_procname = 'EVP_KDF_CTX_set_SKEY';
  EVP_KDF_CTX_set_SKEY_introduced = (byte(3) shl 8 or byte(6)) shl 8 or byte(0);

  EVP_KDF_derive_SKEY_procname = 'EVP_KDF_derive_SKEY';
  EVP_KDF_derive_SKEY_introduced = (byte(3) shl 8 or byte(6)) shl 8 or byte(0);

  EVP_KDF_get_params_procname = 'EVP_KDF_get_params';
  EVP_KDF_get_params_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_KDF_CTX_get_params_procname = 'EVP_KDF_CTX_get_params';
  EVP_KDF_CTX_get_params_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_KDF_CTX_set_params_procname = 'EVP_KDF_CTX_set_params';
  EVP_KDF_CTX_set_params_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_KDF_gettable_params_procname = 'EVP_KDF_gettable_params';
  EVP_KDF_gettable_params_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_KDF_gettable_ctx_params_procname = 'EVP_KDF_gettable_ctx_params';
  EVP_KDF_gettable_ctx_params_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_KDF_settable_ctx_params_procname = 'EVP_KDF_settable_ctx_params';
  EVP_KDF_settable_ctx_params_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_KDF_CTX_gettable_params_procname = 'EVP_KDF_CTX_gettable_params';
  EVP_KDF_CTX_gettable_params_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_KDF_CTX_settable_params_procname = 'EVP_KDF_CTX_settable_params';
  EVP_KDF_CTX_settable_params_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_KDF_do_all_provided_procname = 'EVP_KDF_do_all_provided';
  EVP_KDF_do_all_provided_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_KDF_names_do_all_procname = 'EVP_KDF_names_do_all';
  EVP_KDF_names_do_all_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_tls1_prf_md_procname = 'EVP_PKEY_CTX_set_tls1_prf_md';
  EVP_PKEY_CTX_set_tls1_prf_md_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set1_tls1_prf_secret_procname = 'EVP_PKEY_CTX_set1_tls1_prf_secret';
  EVP_PKEY_CTX_set1_tls1_prf_secret_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_add1_tls1_prf_seed_procname = 'EVP_PKEY_CTX_add1_tls1_prf_seed';
  EVP_PKEY_CTX_add1_tls1_prf_seed_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_hkdf_md_procname = 'EVP_PKEY_CTX_set_hkdf_md';
  EVP_PKEY_CTX_set_hkdf_md_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set1_hkdf_salt_procname = 'EVP_PKEY_CTX_set1_hkdf_salt';
  EVP_PKEY_CTX_set1_hkdf_salt_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set1_hkdf_key_procname = 'EVP_PKEY_CTX_set1_hkdf_key';
  EVP_PKEY_CTX_set1_hkdf_key_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_add1_hkdf_info_procname = 'EVP_PKEY_CTX_add1_hkdf_info';
  EVP_PKEY_CTX_add1_hkdf_info_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_hkdf_mode_procname = 'EVP_PKEY_CTX_set_hkdf_mode';
  EVP_PKEY_CTX_set_hkdf_mode_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set1_pbe_pass_procname = 'EVP_PKEY_CTX_set1_pbe_pass';
  EVP_PKEY_CTX_set1_pbe_pass_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set1_scrypt_salt_procname = 'EVP_PKEY_CTX_set1_scrypt_salt';
  EVP_PKEY_CTX_set1_scrypt_salt_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_scrypt_N_procname = 'EVP_PKEY_CTX_set_scrypt_N';
  EVP_PKEY_CTX_set_scrypt_N_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_scrypt_r_procname = 'EVP_PKEY_CTX_set_scrypt_r';
  EVP_PKEY_CTX_set_scrypt_r_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_scrypt_p_procname = 'EVP_PKEY_CTX_set_scrypt_p';
  EVP_PKEY_CTX_set_scrypt_p_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_scrypt_maxmem_bytes_procname = 'EVP_PKEY_CTX_set_scrypt_maxmem_bytes';
  EVP_PKEY_CTX_set_scrypt_maxmem_bytes_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

// =============================================================================
// INLINE/MACRO IMPLEMENTATIONS
// =============================================================================

function EVP_PKEY_CTX_hkdf_mode(ctx: PEVP_PKEY_CTX; mode: TIdC_INT): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    EVP_PKEY_CTX_hkdf_mode EVP_PKEY_CTX_set_hkdf_mode
  }
end;

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_EVP_KDF_up_ref(kdf: PEVP_KDF): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_KDF_up_ref_procname);
end;

procedure ERR_EVP_KDF_free(kdf: PEVP_KDF); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_KDF_free_procname);
end;

function ERR_EVP_KDF_fetch(libctx: POSSL_LIB_CTX; algorithm: PIdAnsiChar; properties: PIdAnsiChar): PEVP_KDF; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_KDF_fetch_procname);
end;

function ERR_EVP_KDF_CTX_new(kdf: PEVP_KDF): PEVP_KDF_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_KDF_CTX_new_procname);
end;

procedure ERR_EVP_KDF_CTX_free(ctx: PEVP_KDF_CTX); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_KDF_CTX_free_procname);
end;

function ERR_EVP_KDF_CTX_dup(src: PEVP_KDF_CTX): PEVP_KDF_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_KDF_CTX_dup_procname);
end;

function ERR_EVP_KDF_get0_description(kdf: PEVP_KDF): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_KDF_get0_description_procname);
end;

function ERR_EVP_KDF_is_a(kdf: PEVP_KDF; name: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_KDF_is_a_procname);
end;

function ERR_EVP_KDF_get0_name(kdf: PEVP_KDF): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_KDF_get0_name_procname);
end;

function ERR_EVP_KDF_get0_provider(kdf: PEVP_KDF): POSSL_PROVIDER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_KDF_get0_provider_procname);
end;

function ERR_EVP_KDF_CTX_kdf(ctx: PEVP_KDF_CTX): PEVP_KDF; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_KDF_CTX_kdf_procname);
end;

procedure ERR_EVP_KDF_CTX_reset(ctx: PEVP_KDF_CTX); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_KDF_CTX_reset_procname);
end;

function ERR_EVP_KDF_CTX_get_kdf_size(ctx: PEVP_KDF_CTX): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_KDF_CTX_get_kdf_size_procname);
end;

function ERR_EVP_KDF_derive(ctx: PEVP_KDF_CTX; key: PIdAnsiChar; keylen: TIdC_SIZET; params: POSSL_PARAM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_KDF_derive_procname);
end;

function ERR_EVP_KDF_CTX_set_SKEY(ctx: PEVP_KDF_CTX; key: PEVP_SKEY; paramname: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_KDF_CTX_set_SKEY_procname);
end;

function ERR_EVP_KDF_derive_SKEY(ctx: PEVP_KDF_CTX; mgmt: PEVP_SKEYMGMT; key_type: PIdAnsiChar; propquery: PIdAnsiChar; keylen: TIdC_SIZET; params: POSSL_PARAM): PEVP_SKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_KDF_derive_SKEY_procname);
end;

function ERR_EVP_KDF_get_params(kdf: PEVP_KDF; params: POSSL_PARAM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_KDF_get_params_procname);
end;

function ERR_EVP_KDF_CTX_get_params(ctx: PEVP_KDF_CTX; params: POSSL_PARAM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_KDF_CTX_get_params_procname);
end;

function ERR_EVP_KDF_CTX_set_params(ctx: PEVP_KDF_CTX; params: POSSL_PARAM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_KDF_CTX_set_params_procname);
end;

function ERR_EVP_KDF_gettable_params(kdf: PEVP_KDF): POSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_KDF_gettable_params_procname);
end;

function ERR_EVP_KDF_gettable_ctx_params(kdf: PEVP_KDF): POSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_KDF_gettable_ctx_params_procname);
end;

function ERR_EVP_KDF_settable_ctx_params(kdf: PEVP_KDF): POSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_KDF_settable_ctx_params_procname);
end;

function ERR_EVP_KDF_CTX_gettable_params(ctx: PEVP_KDF_CTX): POSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_KDF_CTX_gettable_params_procname);
end;

function ERR_EVP_KDF_CTX_settable_params(ctx: PEVP_KDF_CTX): POSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_KDF_CTX_settable_params_procname);
end;

procedure ERR_EVP_KDF_do_all_provided(libctx: POSSL_LIB_CTX; fn: TEVP_KDF_do_all_provided_fn_cb; arg: Pointer); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_KDF_do_all_provided_procname);
end;

function ERR_EVP_KDF_names_do_all(kdf: PEVP_KDF; fn: TEVP_KDF_names_do_all_fn_cb; data: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_KDF_names_do_all_procname);
end;

function ERR_EVP_PKEY_CTX_set_tls1_prf_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_tls1_prf_md_procname);
end;

function ERR_EVP_PKEY_CTX_set1_tls1_prf_secret(pctx: PEVP_PKEY_CTX; sec: PIdAnsiChar; seclen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set1_tls1_prf_secret_procname);
end;

function ERR_EVP_PKEY_CTX_add1_tls1_prf_seed(pctx: PEVP_PKEY_CTX; seed: PIdAnsiChar; seedlen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_add1_tls1_prf_seed_procname);
end;

function ERR_EVP_PKEY_CTX_set_hkdf_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_hkdf_md_procname);
end;

function ERR_EVP_PKEY_CTX_set1_hkdf_salt(ctx: PEVP_PKEY_CTX; salt: PIdAnsiChar; saltlen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set1_hkdf_salt_procname);
end;

function ERR_EVP_PKEY_CTX_set1_hkdf_key(ctx: PEVP_PKEY_CTX; key: PIdAnsiChar; keylen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set1_hkdf_key_procname);
end;

function ERR_EVP_PKEY_CTX_add1_hkdf_info(ctx: PEVP_PKEY_CTX; info: PIdAnsiChar; infolen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_add1_hkdf_info_procname);
end;

function ERR_EVP_PKEY_CTX_set_hkdf_mode(ctx: PEVP_PKEY_CTX; mode: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_hkdf_mode_procname);
end;

function ERR_EVP_PKEY_CTX_set1_pbe_pass(ctx: PEVP_PKEY_CTX; pass: PIdAnsiChar; passlen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set1_pbe_pass_procname);
end;

function ERR_EVP_PKEY_CTX_set1_scrypt_salt(ctx: PEVP_PKEY_CTX; salt: PIdAnsiChar; saltlen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set1_scrypt_salt_procname);
end;

function ERR_EVP_PKEY_CTX_set_scrypt_N(ctx: PEVP_PKEY_CTX; n: TIdC_UINT64): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_scrypt_N_procname);
end;

function ERR_EVP_PKEY_CTX_set_scrypt_r(ctx: PEVP_PKEY_CTX; r: TIdC_UINT64): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_scrypt_r_procname);
end;

function ERR_EVP_PKEY_CTX_set_scrypt_p(ctx: PEVP_PKEY_CTX; p: TIdC_UINT64): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_scrypt_p_procname);
end;

function ERR_EVP_PKEY_CTX_set_scrypt_maxmem_bytes(ctx: PEVP_PKEY_CTX; maxmem_bytes: TIdC_UINT64): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_scrypt_maxmem_bytes_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  EVP_KDF_up_ref := LoadLibFunction(ADllHandle, EVP_KDF_up_ref_procname);
  FuncLoadError := not assigned(EVP_KDF_up_ref);
  if FuncLoadError then
  begin
    {$if not defined(EVP_KDF_up_ref_allownil)}
    EVP_KDF_up_ref := ERR_EVP_KDF_up_ref;
    {$ifend}
    {$if declared(EVP_KDF_up_ref_introduced)}
    if LibVersion < EVP_KDF_up_ref_introduced then
    begin
      {$if declared(FC_EVP_KDF_up_ref)}
      EVP_KDF_up_ref := FC_EVP_KDF_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_KDF_up_ref_removed)}
    if EVP_KDF_up_ref_removed <= LibVersion then
    begin
      {$if declared(_EVP_KDF_up_ref)}
      EVP_KDF_up_ref := _EVP_KDF_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_KDF_up_ref_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_KDF_up_ref');
    {$ifend}
  end;
  
  EVP_KDF_free := LoadLibFunction(ADllHandle, EVP_KDF_free_procname);
  FuncLoadError := not assigned(EVP_KDF_free);
  if FuncLoadError then
  begin
    {$if not defined(EVP_KDF_free_allownil)}
    EVP_KDF_free := ERR_EVP_KDF_free;
    {$ifend}
    {$if declared(EVP_KDF_free_introduced)}
    if LibVersion < EVP_KDF_free_introduced then
    begin
      {$if declared(FC_EVP_KDF_free)}
      EVP_KDF_free := FC_EVP_KDF_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_KDF_free_removed)}
    if EVP_KDF_free_removed <= LibVersion then
    begin
      {$if declared(_EVP_KDF_free)}
      EVP_KDF_free := _EVP_KDF_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_KDF_free_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_KDF_free');
    {$ifend}
  end;
  
  EVP_KDF_fetch := LoadLibFunction(ADllHandle, EVP_KDF_fetch_procname);
  FuncLoadError := not assigned(EVP_KDF_fetch);
  if FuncLoadError then
  begin
    {$if not defined(EVP_KDF_fetch_allownil)}
    EVP_KDF_fetch := ERR_EVP_KDF_fetch;
    {$ifend}
    {$if declared(EVP_KDF_fetch_introduced)}
    if LibVersion < EVP_KDF_fetch_introduced then
    begin
      {$if declared(FC_EVP_KDF_fetch)}
      EVP_KDF_fetch := FC_EVP_KDF_fetch;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_KDF_fetch_removed)}
    if EVP_KDF_fetch_removed <= LibVersion then
    begin
      {$if declared(_EVP_KDF_fetch)}
      EVP_KDF_fetch := _EVP_KDF_fetch;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_KDF_fetch_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_KDF_fetch');
    {$ifend}
  end;
  
  EVP_KDF_CTX_new := LoadLibFunction(ADllHandle, EVP_KDF_CTX_new_procname);
  FuncLoadError := not assigned(EVP_KDF_CTX_new);
  if FuncLoadError then
  begin
    {$if not defined(EVP_KDF_CTX_new_allownil)}
    EVP_KDF_CTX_new := ERR_EVP_KDF_CTX_new;
    {$ifend}
    {$if declared(EVP_KDF_CTX_new_introduced)}
    if LibVersion < EVP_KDF_CTX_new_introduced then
    begin
      {$if declared(FC_EVP_KDF_CTX_new)}
      EVP_KDF_CTX_new := FC_EVP_KDF_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_KDF_CTX_new_removed)}
    if EVP_KDF_CTX_new_removed <= LibVersion then
    begin
      {$if declared(_EVP_KDF_CTX_new)}
      EVP_KDF_CTX_new := _EVP_KDF_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_KDF_CTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_KDF_CTX_new');
    {$ifend}
  end;
  
  EVP_KDF_CTX_free := LoadLibFunction(ADllHandle, EVP_KDF_CTX_free_procname);
  FuncLoadError := not assigned(EVP_KDF_CTX_free);
  if FuncLoadError then
  begin
    {$if not defined(EVP_KDF_CTX_free_allownil)}
    EVP_KDF_CTX_free := ERR_EVP_KDF_CTX_free;
    {$ifend}
    {$if declared(EVP_KDF_CTX_free_introduced)}
    if LibVersion < EVP_KDF_CTX_free_introduced then
    begin
      {$if declared(FC_EVP_KDF_CTX_free)}
      EVP_KDF_CTX_free := FC_EVP_KDF_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_KDF_CTX_free_removed)}
    if EVP_KDF_CTX_free_removed <= LibVersion then
    begin
      {$if declared(_EVP_KDF_CTX_free)}
      EVP_KDF_CTX_free := _EVP_KDF_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_KDF_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_KDF_CTX_free');
    {$ifend}
  end;
  
  EVP_KDF_CTX_dup := LoadLibFunction(ADllHandle, EVP_KDF_CTX_dup_procname);
  FuncLoadError := not assigned(EVP_KDF_CTX_dup);
  if FuncLoadError then
  begin
    {$if not defined(EVP_KDF_CTX_dup_allownil)}
    EVP_KDF_CTX_dup := ERR_EVP_KDF_CTX_dup;
    {$ifend}
    {$if declared(EVP_KDF_CTX_dup_introduced)}
    if LibVersion < EVP_KDF_CTX_dup_introduced then
    begin
      {$if declared(FC_EVP_KDF_CTX_dup)}
      EVP_KDF_CTX_dup := FC_EVP_KDF_CTX_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_KDF_CTX_dup_removed)}
    if EVP_KDF_CTX_dup_removed <= LibVersion then
    begin
      {$if declared(_EVP_KDF_CTX_dup)}
      EVP_KDF_CTX_dup := _EVP_KDF_CTX_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_KDF_CTX_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_KDF_CTX_dup');
    {$ifend}
  end;
  
  EVP_KDF_get0_description := LoadLibFunction(ADllHandle, EVP_KDF_get0_description_procname);
  FuncLoadError := not assigned(EVP_KDF_get0_description);
  if FuncLoadError then
  begin
    {$if not defined(EVP_KDF_get0_description_allownil)}
    EVP_KDF_get0_description := ERR_EVP_KDF_get0_description;
    {$ifend}
    {$if declared(EVP_KDF_get0_description_introduced)}
    if LibVersion < EVP_KDF_get0_description_introduced then
    begin
      {$if declared(FC_EVP_KDF_get0_description)}
      EVP_KDF_get0_description := FC_EVP_KDF_get0_description;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_KDF_get0_description_removed)}
    if EVP_KDF_get0_description_removed <= LibVersion then
    begin
      {$if declared(_EVP_KDF_get0_description)}
      EVP_KDF_get0_description := _EVP_KDF_get0_description;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_KDF_get0_description_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_KDF_get0_description');
    {$ifend}
  end;
  
  EVP_KDF_is_a := LoadLibFunction(ADllHandle, EVP_KDF_is_a_procname);
  FuncLoadError := not assigned(EVP_KDF_is_a);
  if FuncLoadError then
  begin
    {$if not defined(EVP_KDF_is_a_allownil)}
    EVP_KDF_is_a := ERR_EVP_KDF_is_a;
    {$ifend}
    {$if declared(EVP_KDF_is_a_introduced)}
    if LibVersion < EVP_KDF_is_a_introduced then
    begin
      {$if declared(FC_EVP_KDF_is_a)}
      EVP_KDF_is_a := FC_EVP_KDF_is_a;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_KDF_is_a_removed)}
    if EVP_KDF_is_a_removed <= LibVersion then
    begin
      {$if declared(_EVP_KDF_is_a)}
      EVP_KDF_is_a := _EVP_KDF_is_a;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_KDF_is_a_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_KDF_is_a');
    {$ifend}
  end;
  
  EVP_KDF_get0_name := LoadLibFunction(ADllHandle, EVP_KDF_get0_name_procname);
  FuncLoadError := not assigned(EVP_KDF_get0_name);
  if FuncLoadError then
  begin
    {$if not defined(EVP_KDF_get0_name_allownil)}
    EVP_KDF_get0_name := ERR_EVP_KDF_get0_name;
    {$ifend}
    {$if declared(EVP_KDF_get0_name_introduced)}
    if LibVersion < EVP_KDF_get0_name_introduced then
    begin
      {$if declared(FC_EVP_KDF_get0_name)}
      EVP_KDF_get0_name := FC_EVP_KDF_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_KDF_get0_name_removed)}
    if EVP_KDF_get0_name_removed <= LibVersion then
    begin
      {$if declared(_EVP_KDF_get0_name)}
      EVP_KDF_get0_name := _EVP_KDF_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_KDF_get0_name_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_KDF_get0_name');
    {$ifend}
  end;
  
  EVP_KDF_get0_provider := LoadLibFunction(ADllHandle, EVP_KDF_get0_provider_procname);
  FuncLoadError := not assigned(EVP_KDF_get0_provider);
  if FuncLoadError then
  begin
    {$if not defined(EVP_KDF_get0_provider_allownil)}
    EVP_KDF_get0_provider := ERR_EVP_KDF_get0_provider;
    {$ifend}
    {$if declared(EVP_KDF_get0_provider_introduced)}
    if LibVersion < EVP_KDF_get0_provider_introduced then
    begin
      {$if declared(FC_EVP_KDF_get0_provider)}
      EVP_KDF_get0_provider := FC_EVP_KDF_get0_provider;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_KDF_get0_provider_removed)}
    if EVP_KDF_get0_provider_removed <= LibVersion then
    begin
      {$if declared(_EVP_KDF_get0_provider)}
      EVP_KDF_get0_provider := _EVP_KDF_get0_provider;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_KDF_get0_provider_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_KDF_get0_provider');
    {$ifend}
  end;
  
  EVP_KDF_CTX_kdf := LoadLibFunction(ADllHandle, EVP_KDF_CTX_kdf_procname);
  FuncLoadError := not assigned(EVP_KDF_CTX_kdf);
  if FuncLoadError then
  begin
    {$if not defined(EVP_KDF_CTX_kdf_allownil)}
    EVP_KDF_CTX_kdf := ERR_EVP_KDF_CTX_kdf;
    {$ifend}
    {$if declared(EVP_KDF_CTX_kdf_introduced)}
    if LibVersion < EVP_KDF_CTX_kdf_introduced then
    begin
      {$if declared(FC_EVP_KDF_CTX_kdf)}
      EVP_KDF_CTX_kdf := FC_EVP_KDF_CTX_kdf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_KDF_CTX_kdf_removed)}
    if EVP_KDF_CTX_kdf_removed <= LibVersion then
    begin
      {$if declared(_EVP_KDF_CTX_kdf)}
      EVP_KDF_CTX_kdf := _EVP_KDF_CTX_kdf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_KDF_CTX_kdf_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_KDF_CTX_kdf');
    {$ifend}
  end;
  
  EVP_KDF_CTX_reset := LoadLibFunction(ADllHandle, EVP_KDF_CTX_reset_procname);
  FuncLoadError := not assigned(EVP_KDF_CTX_reset);
  if FuncLoadError then
  begin
    {$if not defined(EVP_KDF_CTX_reset_allownil)}
    EVP_KDF_CTX_reset := ERR_EVP_KDF_CTX_reset;
    {$ifend}
    {$if declared(EVP_KDF_CTX_reset_introduced)}
    if LibVersion < EVP_KDF_CTX_reset_introduced then
    begin
      {$if declared(FC_EVP_KDF_CTX_reset)}
      EVP_KDF_CTX_reset := FC_EVP_KDF_CTX_reset;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_KDF_CTX_reset_removed)}
    if EVP_KDF_CTX_reset_removed <= LibVersion then
    begin
      {$if declared(_EVP_KDF_CTX_reset)}
      EVP_KDF_CTX_reset := _EVP_KDF_CTX_reset;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_KDF_CTX_reset_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_KDF_CTX_reset');
    {$ifend}
  end;
  
  EVP_KDF_CTX_get_kdf_size := LoadLibFunction(ADllHandle, EVP_KDF_CTX_get_kdf_size_procname);
  FuncLoadError := not assigned(EVP_KDF_CTX_get_kdf_size);
  if FuncLoadError then
  begin
    {$if not defined(EVP_KDF_CTX_get_kdf_size_allownil)}
    EVP_KDF_CTX_get_kdf_size := ERR_EVP_KDF_CTX_get_kdf_size;
    {$ifend}
    {$if declared(EVP_KDF_CTX_get_kdf_size_introduced)}
    if LibVersion < EVP_KDF_CTX_get_kdf_size_introduced then
    begin
      {$if declared(FC_EVP_KDF_CTX_get_kdf_size)}
      EVP_KDF_CTX_get_kdf_size := FC_EVP_KDF_CTX_get_kdf_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_KDF_CTX_get_kdf_size_removed)}
    if EVP_KDF_CTX_get_kdf_size_removed <= LibVersion then
    begin
      {$if declared(_EVP_KDF_CTX_get_kdf_size)}
      EVP_KDF_CTX_get_kdf_size := _EVP_KDF_CTX_get_kdf_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_KDF_CTX_get_kdf_size_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_KDF_CTX_get_kdf_size');
    {$ifend}
  end;
  
  EVP_KDF_derive := LoadLibFunction(ADllHandle, EVP_KDF_derive_procname);
  FuncLoadError := not assigned(EVP_KDF_derive);
  if FuncLoadError then
  begin
    {$if not defined(EVP_KDF_derive_allownil)}
    EVP_KDF_derive := ERR_EVP_KDF_derive;
    {$ifend}
    {$if declared(EVP_KDF_derive_introduced)}
    if LibVersion < EVP_KDF_derive_introduced then
    begin
      {$if declared(FC_EVP_KDF_derive)}
      EVP_KDF_derive := FC_EVP_KDF_derive;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_KDF_derive_removed)}
    if EVP_KDF_derive_removed <= LibVersion then
    begin
      {$if declared(_EVP_KDF_derive)}
      EVP_KDF_derive := _EVP_KDF_derive;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_KDF_derive_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_KDF_derive');
    {$ifend}
  end;
  
  EVP_KDF_CTX_set_SKEY := LoadLibFunction(ADllHandle, EVP_KDF_CTX_set_SKEY_procname);
  FuncLoadError := not assigned(EVP_KDF_CTX_set_SKEY);
  if FuncLoadError then
  begin
    {$if not defined(EVP_KDF_CTX_set_SKEY_allownil)}
    EVP_KDF_CTX_set_SKEY := ERR_EVP_KDF_CTX_set_SKEY;
    {$ifend}
    {$if declared(EVP_KDF_CTX_set_SKEY_introduced)}
    if LibVersion < EVP_KDF_CTX_set_SKEY_introduced then
    begin
      {$if declared(FC_EVP_KDF_CTX_set_SKEY)}
      EVP_KDF_CTX_set_SKEY := FC_EVP_KDF_CTX_set_SKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_KDF_CTX_set_SKEY_removed)}
    if EVP_KDF_CTX_set_SKEY_removed <= LibVersion then
    begin
      {$if declared(_EVP_KDF_CTX_set_SKEY)}
      EVP_KDF_CTX_set_SKEY := _EVP_KDF_CTX_set_SKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_KDF_CTX_set_SKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_KDF_CTX_set_SKEY');
    {$ifend}
  end;
  
  EVP_KDF_derive_SKEY := LoadLibFunction(ADllHandle, EVP_KDF_derive_SKEY_procname);
  FuncLoadError := not assigned(EVP_KDF_derive_SKEY);
  if FuncLoadError then
  begin
    {$if not defined(EVP_KDF_derive_SKEY_allownil)}
    EVP_KDF_derive_SKEY := ERR_EVP_KDF_derive_SKEY;
    {$ifend}
    {$if declared(EVP_KDF_derive_SKEY_introduced)}
    if LibVersion < EVP_KDF_derive_SKEY_introduced then
    begin
      {$if declared(FC_EVP_KDF_derive_SKEY)}
      EVP_KDF_derive_SKEY := FC_EVP_KDF_derive_SKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_KDF_derive_SKEY_removed)}
    if EVP_KDF_derive_SKEY_removed <= LibVersion then
    begin
      {$if declared(_EVP_KDF_derive_SKEY)}
      EVP_KDF_derive_SKEY := _EVP_KDF_derive_SKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_KDF_derive_SKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_KDF_derive_SKEY');
    {$ifend}
  end;
  
  EVP_KDF_get_params := LoadLibFunction(ADllHandle, EVP_KDF_get_params_procname);
  FuncLoadError := not assigned(EVP_KDF_get_params);
  if FuncLoadError then
  begin
    {$if not defined(EVP_KDF_get_params_allownil)}
    EVP_KDF_get_params := ERR_EVP_KDF_get_params;
    {$ifend}
    {$if declared(EVP_KDF_get_params_introduced)}
    if LibVersion < EVP_KDF_get_params_introduced then
    begin
      {$if declared(FC_EVP_KDF_get_params)}
      EVP_KDF_get_params := FC_EVP_KDF_get_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_KDF_get_params_removed)}
    if EVP_KDF_get_params_removed <= LibVersion then
    begin
      {$if declared(_EVP_KDF_get_params)}
      EVP_KDF_get_params := _EVP_KDF_get_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_KDF_get_params_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_KDF_get_params');
    {$ifend}
  end;
  
  EVP_KDF_CTX_get_params := LoadLibFunction(ADllHandle, EVP_KDF_CTX_get_params_procname);
  FuncLoadError := not assigned(EVP_KDF_CTX_get_params);
  if FuncLoadError then
  begin
    {$if not defined(EVP_KDF_CTX_get_params_allownil)}
    EVP_KDF_CTX_get_params := ERR_EVP_KDF_CTX_get_params;
    {$ifend}
    {$if declared(EVP_KDF_CTX_get_params_introduced)}
    if LibVersion < EVP_KDF_CTX_get_params_introduced then
    begin
      {$if declared(FC_EVP_KDF_CTX_get_params)}
      EVP_KDF_CTX_get_params := FC_EVP_KDF_CTX_get_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_KDF_CTX_get_params_removed)}
    if EVP_KDF_CTX_get_params_removed <= LibVersion then
    begin
      {$if declared(_EVP_KDF_CTX_get_params)}
      EVP_KDF_CTX_get_params := _EVP_KDF_CTX_get_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_KDF_CTX_get_params_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_KDF_CTX_get_params');
    {$ifend}
  end;
  
  EVP_KDF_CTX_set_params := LoadLibFunction(ADllHandle, EVP_KDF_CTX_set_params_procname);
  FuncLoadError := not assigned(EVP_KDF_CTX_set_params);
  if FuncLoadError then
  begin
    {$if not defined(EVP_KDF_CTX_set_params_allownil)}
    EVP_KDF_CTX_set_params := ERR_EVP_KDF_CTX_set_params;
    {$ifend}
    {$if declared(EVP_KDF_CTX_set_params_introduced)}
    if LibVersion < EVP_KDF_CTX_set_params_introduced then
    begin
      {$if declared(FC_EVP_KDF_CTX_set_params)}
      EVP_KDF_CTX_set_params := FC_EVP_KDF_CTX_set_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_KDF_CTX_set_params_removed)}
    if EVP_KDF_CTX_set_params_removed <= LibVersion then
    begin
      {$if declared(_EVP_KDF_CTX_set_params)}
      EVP_KDF_CTX_set_params := _EVP_KDF_CTX_set_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_KDF_CTX_set_params_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_KDF_CTX_set_params');
    {$ifend}
  end;
  
  EVP_KDF_gettable_params := LoadLibFunction(ADllHandle, EVP_KDF_gettable_params_procname);
  FuncLoadError := not assigned(EVP_KDF_gettable_params);
  if FuncLoadError then
  begin
    {$if not defined(EVP_KDF_gettable_params_allownil)}
    EVP_KDF_gettable_params := ERR_EVP_KDF_gettable_params;
    {$ifend}
    {$if declared(EVP_KDF_gettable_params_introduced)}
    if LibVersion < EVP_KDF_gettable_params_introduced then
    begin
      {$if declared(FC_EVP_KDF_gettable_params)}
      EVP_KDF_gettable_params := FC_EVP_KDF_gettable_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_KDF_gettable_params_removed)}
    if EVP_KDF_gettable_params_removed <= LibVersion then
    begin
      {$if declared(_EVP_KDF_gettable_params)}
      EVP_KDF_gettable_params := _EVP_KDF_gettable_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_KDF_gettable_params_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_KDF_gettable_params');
    {$ifend}
  end;
  
  EVP_KDF_gettable_ctx_params := LoadLibFunction(ADllHandle, EVP_KDF_gettable_ctx_params_procname);
  FuncLoadError := not assigned(EVP_KDF_gettable_ctx_params);
  if FuncLoadError then
  begin
    {$if not defined(EVP_KDF_gettable_ctx_params_allownil)}
    EVP_KDF_gettable_ctx_params := ERR_EVP_KDF_gettable_ctx_params;
    {$ifend}
    {$if declared(EVP_KDF_gettable_ctx_params_introduced)}
    if LibVersion < EVP_KDF_gettable_ctx_params_introduced then
    begin
      {$if declared(FC_EVP_KDF_gettable_ctx_params)}
      EVP_KDF_gettable_ctx_params := FC_EVP_KDF_gettable_ctx_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_KDF_gettable_ctx_params_removed)}
    if EVP_KDF_gettable_ctx_params_removed <= LibVersion then
    begin
      {$if declared(_EVP_KDF_gettable_ctx_params)}
      EVP_KDF_gettable_ctx_params := _EVP_KDF_gettable_ctx_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_KDF_gettable_ctx_params_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_KDF_gettable_ctx_params');
    {$ifend}
  end;
  
  EVP_KDF_settable_ctx_params := LoadLibFunction(ADllHandle, EVP_KDF_settable_ctx_params_procname);
  FuncLoadError := not assigned(EVP_KDF_settable_ctx_params);
  if FuncLoadError then
  begin
    {$if not defined(EVP_KDF_settable_ctx_params_allownil)}
    EVP_KDF_settable_ctx_params := ERR_EVP_KDF_settable_ctx_params;
    {$ifend}
    {$if declared(EVP_KDF_settable_ctx_params_introduced)}
    if LibVersion < EVP_KDF_settable_ctx_params_introduced then
    begin
      {$if declared(FC_EVP_KDF_settable_ctx_params)}
      EVP_KDF_settable_ctx_params := FC_EVP_KDF_settable_ctx_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_KDF_settable_ctx_params_removed)}
    if EVP_KDF_settable_ctx_params_removed <= LibVersion then
    begin
      {$if declared(_EVP_KDF_settable_ctx_params)}
      EVP_KDF_settable_ctx_params := _EVP_KDF_settable_ctx_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_KDF_settable_ctx_params_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_KDF_settable_ctx_params');
    {$ifend}
  end;
  
  EVP_KDF_CTX_gettable_params := LoadLibFunction(ADllHandle, EVP_KDF_CTX_gettable_params_procname);
  FuncLoadError := not assigned(EVP_KDF_CTX_gettable_params);
  if FuncLoadError then
  begin
    {$if not defined(EVP_KDF_CTX_gettable_params_allownil)}
    EVP_KDF_CTX_gettable_params := ERR_EVP_KDF_CTX_gettable_params;
    {$ifend}
    {$if declared(EVP_KDF_CTX_gettable_params_introduced)}
    if LibVersion < EVP_KDF_CTX_gettable_params_introduced then
    begin
      {$if declared(FC_EVP_KDF_CTX_gettable_params)}
      EVP_KDF_CTX_gettable_params := FC_EVP_KDF_CTX_gettable_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_KDF_CTX_gettable_params_removed)}
    if EVP_KDF_CTX_gettable_params_removed <= LibVersion then
    begin
      {$if declared(_EVP_KDF_CTX_gettable_params)}
      EVP_KDF_CTX_gettable_params := _EVP_KDF_CTX_gettable_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_KDF_CTX_gettable_params_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_KDF_CTX_gettable_params');
    {$ifend}
  end;
  
  EVP_KDF_CTX_settable_params := LoadLibFunction(ADllHandle, EVP_KDF_CTX_settable_params_procname);
  FuncLoadError := not assigned(EVP_KDF_CTX_settable_params);
  if FuncLoadError then
  begin
    {$if not defined(EVP_KDF_CTX_settable_params_allownil)}
    EVP_KDF_CTX_settable_params := ERR_EVP_KDF_CTX_settable_params;
    {$ifend}
    {$if declared(EVP_KDF_CTX_settable_params_introduced)}
    if LibVersion < EVP_KDF_CTX_settable_params_introduced then
    begin
      {$if declared(FC_EVP_KDF_CTX_settable_params)}
      EVP_KDF_CTX_settable_params := FC_EVP_KDF_CTX_settable_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_KDF_CTX_settable_params_removed)}
    if EVP_KDF_CTX_settable_params_removed <= LibVersion then
    begin
      {$if declared(_EVP_KDF_CTX_settable_params)}
      EVP_KDF_CTX_settable_params := _EVP_KDF_CTX_settable_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_KDF_CTX_settable_params_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_KDF_CTX_settable_params');
    {$ifend}
  end;
  
  EVP_KDF_do_all_provided := LoadLibFunction(ADllHandle, EVP_KDF_do_all_provided_procname);
  FuncLoadError := not assigned(EVP_KDF_do_all_provided);
  if FuncLoadError then
  begin
    {$if not defined(EVP_KDF_do_all_provided_allownil)}
    EVP_KDF_do_all_provided := ERR_EVP_KDF_do_all_provided;
    {$ifend}
    {$if declared(EVP_KDF_do_all_provided_introduced)}
    if LibVersion < EVP_KDF_do_all_provided_introduced then
    begin
      {$if declared(FC_EVP_KDF_do_all_provided)}
      EVP_KDF_do_all_provided := FC_EVP_KDF_do_all_provided;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_KDF_do_all_provided_removed)}
    if EVP_KDF_do_all_provided_removed <= LibVersion then
    begin
      {$if declared(_EVP_KDF_do_all_provided)}
      EVP_KDF_do_all_provided := _EVP_KDF_do_all_provided;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_KDF_do_all_provided_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_KDF_do_all_provided');
    {$ifend}
  end;
  
  EVP_KDF_names_do_all := LoadLibFunction(ADllHandle, EVP_KDF_names_do_all_procname);
  FuncLoadError := not assigned(EVP_KDF_names_do_all);
  if FuncLoadError then
  begin
    {$if not defined(EVP_KDF_names_do_all_allownil)}
    EVP_KDF_names_do_all := ERR_EVP_KDF_names_do_all;
    {$ifend}
    {$if declared(EVP_KDF_names_do_all_introduced)}
    if LibVersion < EVP_KDF_names_do_all_introduced then
    begin
      {$if declared(FC_EVP_KDF_names_do_all)}
      EVP_KDF_names_do_all := FC_EVP_KDF_names_do_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_KDF_names_do_all_removed)}
    if EVP_KDF_names_do_all_removed <= LibVersion then
    begin
      {$if declared(_EVP_KDF_names_do_all)}
      EVP_KDF_names_do_all := _EVP_KDF_names_do_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_KDF_names_do_all_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_KDF_names_do_all');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_tls1_prf_md := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_tls1_prf_md_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_tls1_prf_md);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_tls1_prf_md_allownil)}
    EVP_PKEY_CTX_set_tls1_prf_md := ERR_EVP_PKEY_CTX_set_tls1_prf_md;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_tls1_prf_md_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_tls1_prf_md_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_tls1_prf_md)}
      EVP_PKEY_CTX_set_tls1_prf_md := FC_EVP_PKEY_CTX_set_tls1_prf_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_tls1_prf_md_removed)}
    if EVP_PKEY_CTX_set_tls1_prf_md_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_tls1_prf_md)}
      EVP_PKEY_CTX_set_tls1_prf_md := _EVP_PKEY_CTX_set_tls1_prf_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_tls1_prf_md_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_tls1_prf_md');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set1_tls1_prf_secret := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set1_tls1_prf_secret_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set1_tls1_prf_secret);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set1_tls1_prf_secret_allownil)}
    EVP_PKEY_CTX_set1_tls1_prf_secret := ERR_EVP_PKEY_CTX_set1_tls1_prf_secret;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set1_tls1_prf_secret_introduced)}
    if LibVersion < EVP_PKEY_CTX_set1_tls1_prf_secret_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set1_tls1_prf_secret)}
      EVP_PKEY_CTX_set1_tls1_prf_secret := FC_EVP_PKEY_CTX_set1_tls1_prf_secret;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set1_tls1_prf_secret_removed)}
    if EVP_PKEY_CTX_set1_tls1_prf_secret_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set1_tls1_prf_secret)}
      EVP_PKEY_CTX_set1_tls1_prf_secret := _EVP_PKEY_CTX_set1_tls1_prf_secret;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set1_tls1_prf_secret_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set1_tls1_prf_secret');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_add1_tls1_prf_seed := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_add1_tls1_prf_seed_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_add1_tls1_prf_seed);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_add1_tls1_prf_seed_allownil)}
    EVP_PKEY_CTX_add1_tls1_prf_seed := ERR_EVP_PKEY_CTX_add1_tls1_prf_seed;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_add1_tls1_prf_seed_introduced)}
    if LibVersion < EVP_PKEY_CTX_add1_tls1_prf_seed_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_add1_tls1_prf_seed)}
      EVP_PKEY_CTX_add1_tls1_prf_seed := FC_EVP_PKEY_CTX_add1_tls1_prf_seed;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_add1_tls1_prf_seed_removed)}
    if EVP_PKEY_CTX_add1_tls1_prf_seed_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_add1_tls1_prf_seed)}
      EVP_PKEY_CTX_add1_tls1_prf_seed := _EVP_PKEY_CTX_add1_tls1_prf_seed;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_add1_tls1_prf_seed_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_add1_tls1_prf_seed');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_hkdf_md := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_hkdf_md_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_hkdf_md);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_hkdf_md_allownil)}
    EVP_PKEY_CTX_set_hkdf_md := ERR_EVP_PKEY_CTX_set_hkdf_md;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_hkdf_md_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_hkdf_md_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_hkdf_md)}
      EVP_PKEY_CTX_set_hkdf_md := FC_EVP_PKEY_CTX_set_hkdf_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_hkdf_md_removed)}
    if EVP_PKEY_CTX_set_hkdf_md_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_hkdf_md)}
      EVP_PKEY_CTX_set_hkdf_md := _EVP_PKEY_CTX_set_hkdf_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_hkdf_md_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_hkdf_md');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set1_hkdf_salt := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set1_hkdf_salt_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set1_hkdf_salt);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set1_hkdf_salt_allownil)}
    EVP_PKEY_CTX_set1_hkdf_salt := ERR_EVP_PKEY_CTX_set1_hkdf_salt;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set1_hkdf_salt_introduced)}
    if LibVersion < EVP_PKEY_CTX_set1_hkdf_salt_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set1_hkdf_salt)}
      EVP_PKEY_CTX_set1_hkdf_salt := FC_EVP_PKEY_CTX_set1_hkdf_salt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set1_hkdf_salt_removed)}
    if EVP_PKEY_CTX_set1_hkdf_salt_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set1_hkdf_salt)}
      EVP_PKEY_CTX_set1_hkdf_salt := _EVP_PKEY_CTX_set1_hkdf_salt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set1_hkdf_salt_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set1_hkdf_salt');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set1_hkdf_key := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set1_hkdf_key_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set1_hkdf_key);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set1_hkdf_key_allownil)}
    EVP_PKEY_CTX_set1_hkdf_key := ERR_EVP_PKEY_CTX_set1_hkdf_key;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set1_hkdf_key_introduced)}
    if LibVersion < EVP_PKEY_CTX_set1_hkdf_key_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set1_hkdf_key)}
      EVP_PKEY_CTX_set1_hkdf_key := FC_EVP_PKEY_CTX_set1_hkdf_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set1_hkdf_key_removed)}
    if EVP_PKEY_CTX_set1_hkdf_key_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set1_hkdf_key)}
      EVP_PKEY_CTX_set1_hkdf_key := _EVP_PKEY_CTX_set1_hkdf_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set1_hkdf_key_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set1_hkdf_key');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_add1_hkdf_info := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_add1_hkdf_info_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_add1_hkdf_info);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_add1_hkdf_info_allownil)}
    EVP_PKEY_CTX_add1_hkdf_info := ERR_EVP_PKEY_CTX_add1_hkdf_info;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_add1_hkdf_info_introduced)}
    if LibVersion < EVP_PKEY_CTX_add1_hkdf_info_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_add1_hkdf_info)}
      EVP_PKEY_CTX_add1_hkdf_info := FC_EVP_PKEY_CTX_add1_hkdf_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_add1_hkdf_info_removed)}
    if EVP_PKEY_CTX_add1_hkdf_info_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_add1_hkdf_info)}
      EVP_PKEY_CTX_add1_hkdf_info := _EVP_PKEY_CTX_add1_hkdf_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_add1_hkdf_info_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_add1_hkdf_info');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_hkdf_mode := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_hkdf_mode_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_hkdf_mode);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_hkdf_mode_allownil)}
    EVP_PKEY_CTX_set_hkdf_mode := ERR_EVP_PKEY_CTX_set_hkdf_mode;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_hkdf_mode_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_hkdf_mode_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_hkdf_mode)}
      EVP_PKEY_CTX_set_hkdf_mode := FC_EVP_PKEY_CTX_set_hkdf_mode;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_hkdf_mode_removed)}
    if EVP_PKEY_CTX_set_hkdf_mode_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_hkdf_mode)}
      EVP_PKEY_CTX_set_hkdf_mode := _EVP_PKEY_CTX_set_hkdf_mode;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_hkdf_mode_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_hkdf_mode');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set1_pbe_pass := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set1_pbe_pass_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set1_pbe_pass);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set1_pbe_pass_allownil)}
    EVP_PKEY_CTX_set1_pbe_pass := ERR_EVP_PKEY_CTX_set1_pbe_pass;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set1_pbe_pass_introduced)}
    if LibVersion < EVP_PKEY_CTX_set1_pbe_pass_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set1_pbe_pass)}
      EVP_PKEY_CTX_set1_pbe_pass := FC_EVP_PKEY_CTX_set1_pbe_pass;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set1_pbe_pass_removed)}
    if EVP_PKEY_CTX_set1_pbe_pass_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set1_pbe_pass)}
      EVP_PKEY_CTX_set1_pbe_pass := _EVP_PKEY_CTX_set1_pbe_pass;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set1_pbe_pass_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set1_pbe_pass');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set1_scrypt_salt := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set1_scrypt_salt_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set1_scrypt_salt);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set1_scrypt_salt_allownil)}
    EVP_PKEY_CTX_set1_scrypt_salt := ERR_EVP_PKEY_CTX_set1_scrypt_salt;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set1_scrypt_salt_introduced)}
    if LibVersion < EVP_PKEY_CTX_set1_scrypt_salt_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set1_scrypt_salt)}
      EVP_PKEY_CTX_set1_scrypt_salt := FC_EVP_PKEY_CTX_set1_scrypt_salt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set1_scrypt_salt_removed)}
    if EVP_PKEY_CTX_set1_scrypt_salt_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set1_scrypt_salt)}
      EVP_PKEY_CTX_set1_scrypt_salt := _EVP_PKEY_CTX_set1_scrypt_salt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set1_scrypt_salt_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set1_scrypt_salt');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_scrypt_N := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_scrypt_N_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_scrypt_N);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_scrypt_N_allownil)}
    EVP_PKEY_CTX_set_scrypt_N := ERR_EVP_PKEY_CTX_set_scrypt_N;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_scrypt_N_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_scrypt_N_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_scrypt_N)}
      EVP_PKEY_CTX_set_scrypt_N := FC_EVP_PKEY_CTX_set_scrypt_N;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_scrypt_N_removed)}
    if EVP_PKEY_CTX_set_scrypt_N_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_scrypt_N)}
      EVP_PKEY_CTX_set_scrypt_N := _EVP_PKEY_CTX_set_scrypt_N;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_scrypt_N_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_scrypt_N');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_scrypt_r := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_scrypt_r_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_scrypt_r);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_scrypt_r_allownil)}
    EVP_PKEY_CTX_set_scrypt_r := ERR_EVP_PKEY_CTX_set_scrypt_r;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_scrypt_r_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_scrypt_r_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_scrypt_r)}
      EVP_PKEY_CTX_set_scrypt_r := FC_EVP_PKEY_CTX_set_scrypt_r;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_scrypt_r_removed)}
    if EVP_PKEY_CTX_set_scrypt_r_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_scrypt_r)}
      EVP_PKEY_CTX_set_scrypt_r := _EVP_PKEY_CTX_set_scrypt_r;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_scrypt_r_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_scrypt_r');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_scrypt_p := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_scrypt_p_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_scrypt_p);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_scrypt_p_allownil)}
    EVP_PKEY_CTX_set_scrypt_p := ERR_EVP_PKEY_CTX_set_scrypt_p;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_scrypt_p_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_scrypt_p_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_scrypt_p)}
      EVP_PKEY_CTX_set_scrypt_p := FC_EVP_PKEY_CTX_set_scrypt_p;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_scrypt_p_removed)}
    if EVP_PKEY_CTX_set_scrypt_p_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_scrypt_p)}
      EVP_PKEY_CTX_set_scrypt_p := _EVP_PKEY_CTX_set_scrypt_p;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_scrypt_p_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_scrypt_p');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_scrypt_maxmem_bytes := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_scrypt_maxmem_bytes_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_scrypt_maxmem_bytes);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_scrypt_maxmem_bytes_allownil)}
    EVP_PKEY_CTX_set_scrypt_maxmem_bytes := ERR_EVP_PKEY_CTX_set_scrypt_maxmem_bytes;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_scrypt_maxmem_bytes_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_scrypt_maxmem_bytes_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_scrypt_maxmem_bytes)}
      EVP_PKEY_CTX_set_scrypt_maxmem_bytes := FC_EVP_PKEY_CTX_set_scrypt_maxmem_bytes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_scrypt_maxmem_bytes_removed)}
    if EVP_PKEY_CTX_set_scrypt_maxmem_bytes_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_scrypt_maxmem_bytes)}
      EVP_PKEY_CTX_set_scrypt_maxmem_bytes := _EVP_PKEY_CTX_set_scrypt_maxmem_bytes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_scrypt_maxmem_bytes_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_scrypt_maxmem_bytes');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  EVP_KDF_up_ref := nil;
  EVP_KDF_free := nil;
  EVP_KDF_fetch := nil;
  EVP_KDF_CTX_new := nil;
  EVP_KDF_CTX_free := nil;
  EVP_KDF_CTX_dup := nil;
  EVP_KDF_get0_description := nil;
  EVP_KDF_is_a := nil;
  EVP_KDF_get0_name := nil;
  EVP_KDF_get0_provider := nil;
  EVP_KDF_CTX_kdf := nil;
  EVP_KDF_CTX_reset := nil;
  EVP_KDF_CTX_get_kdf_size := nil;
  EVP_KDF_derive := nil;
  EVP_KDF_CTX_set_SKEY := nil;
  EVP_KDF_derive_SKEY := nil;
  EVP_KDF_get_params := nil;
  EVP_KDF_CTX_get_params := nil;
  EVP_KDF_CTX_set_params := nil;
  EVP_KDF_gettable_params := nil;
  EVP_KDF_gettable_ctx_params := nil;
  EVP_KDF_settable_ctx_params := nil;
  EVP_KDF_CTX_gettable_params := nil;
  EVP_KDF_CTX_settable_params := nil;
  EVP_KDF_do_all_provided := nil;
  EVP_KDF_names_do_all := nil;
  EVP_PKEY_CTX_set_tls1_prf_md := nil;
  EVP_PKEY_CTX_set1_tls1_prf_secret := nil;
  EVP_PKEY_CTX_add1_tls1_prf_seed := nil;
  EVP_PKEY_CTX_set_hkdf_md := nil;
  EVP_PKEY_CTX_set1_hkdf_salt := nil;
  EVP_PKEY_CTX_set1_hkdf_key := nil;
  EVP_PKEY_CTX_add1_hkdf_info := nil;
  EVP_PKEY_CTX_set_hkdf_mode := nil;
  EVP_PKEY_CTX_set1_pbe_pass := nil;
  EVP_PKEY_CTX_set1_scrypt_salt := nil;
  EVP_PKEY_CTX_set_scrypt_N := nil;
  EVP_PKEY_CTX_set_scrypt_r := nil;
  EVP_PKEY_CTX_set_scrypt_p := nil;
  EVP_PKEY_CTX_set_scrypt_maxmem_bytes := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.