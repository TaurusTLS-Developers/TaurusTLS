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

unit TaurusTLSHeaders_modes;

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
// TYPE DECLARATIONS
// =============================================================================
type
  Pgcm128_context = ^Tgcm128_context;
  Tgcm128_context =   record end;
  {$EXTERNALSYM Pgcm128_context}

  Pccm128_context = ^Tccm128_context;
  Tccm128_context =   record end;
  {$EXTERNALSYM Pccm128_context}

  Pxts128_context = ^Txts128_context;
  Txts128_context =   record end;
  {$EXTERNALSYM Pxts128_context}

  Pocb128_context = ^Tocb128_context;
  Tocb128_context =   record end;
  {$EXTERNALSYM Pocb128_context}


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  Tblock128_f = procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; key: Pointer); cdecl;
  Tcbc128_f = procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; enc: TIdC_INT); cdecl;
  Tecb128_f = procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; enc: TIdC_INT); cdecl;
  Tctr128_f = procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; blocks: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar); cdecl;
  Tccm128_f = procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; blocks: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; cmac: PIdAnsiChar); cdecl;
  Tocb128_f = procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; blocks: TIdC_SIZET; key: Pointer; start_block_num: TIdC_SIZET; offset_i: PIdAnsiChar; L_: PPIdAnsiChar; checksum: PIdAnsiChar); cdecl;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  CRYPTO_cbc128_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; block: Tblock128_f); cdecl = nil;
  {$EXTERNALSYM CRYPTO_cbc128_encrypt}

  CRYPTO_cbc128_decrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; block: Tblock128_f); cdecl = nil;
  {$EXTERNALSYM CRYPTO_cbc128_decrypt}

  CRYPTO_ctr128_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; ecount_buf: PIdAnsiChar; num: PIdC_UINT; block: Tblock128_f); cdecl = nil;
  {$EXTERNALSYM CRYPTO_ctr128_encrypt}

  CRYPTO_ctr128_encrypt_ctr32: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; ecount_buf: PIdAnsiChar; num: PIdC_UINT; ctr: Tctr128_f); cdecl = nil;
  {$EXTERNALSYM CRYPTO_ctr128_encrypt_ctr32}

  CRYPTO_ofb128_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; num: PIdC_INT; block: Tblock128_f); cdecl = nil;
  {$EXTERNALSYM CRYPTO_ofb128_encrypt}

  CRYPTO_cfb128_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT; block: Tblock128_f); cdecl = nil;
  {$EXTERNALSYM CRYPTO_cfb128_encrypt}

  CRYPTO_cfb128_8_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT; block: Tblock128_f); cdecl = nil;
  {$EXTERNALSYM CRYPTO_cfb128_8_encrypt}

  CRYPTO_cfb128_1_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; bits: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT; block: Tblock128_f); cdecl = nil;
  {$EXTERNALSYM CRYPTO_cfb128_1_encrypt}

  CRYPTO_cts128_encrypt_block: function(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; block: Tblock128_f): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM CRYPTO_cts128_encrypt_block}

  CRYPTO_cts128_encrypt: function(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; cbc: Tcbc128_f): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM CRYPTO_cts128_encrypt}

  CRYPTO_cts128_decrypt_block: function(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; block: Tblock128_f): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM CRYPTO_cts128_decrypt_block}

  CRYPTO_cts128_decrypt: function(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; cbc: Tcbc128_f): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM CRYPTO_cts128_decrypt}

  CRYPTO_nistcts128_encrypt_block: function(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; block: Tblock128_f): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM CRYPTO_nistcts128_encrypt_block}

  CRYPTO_nistcts128_encrypt: function(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; cbc: Tcbc128_f): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM CRYPTO_nistcts128_encrypt}

  CRYPTO_nistcts128_decrypt_block: function(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; block: Tblock128_f): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM CRYPTO_nistcts128_decrypt_block}

  CRYPTO_nistcts128_decrypt: function(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; cbc: Tcbc128_f): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM CRYPTO_nistcts128_decrypt}

  CRYPTO_gcm128_new: function(key: Pointer; block: Tblock128_f): PGCM128_CONTEXT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_gcm128_new}

  CRYPTO_gcm128_init: procedure(ctx: PGCM128_CONTEXT; key: Pointer; block: Tblock128_f); cdecl = nil;
  {$EXTERNALSYM CRYPTO_gcm128_init}

  CRYPTO_gcm128_setiv: procedure(ctx: PGCM128_CONTEXT; iv: PIdAnsiChar; len: TIdC_SIZET); cdecl = nil;
  {$EXTERNALSYM CRYPTO_gcm128_setiv}

  CRYPTO_gcm128_aad: function(ctx: PGCM128_CONTEXT; aad: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_gcm128_aad}

  CRYPTO_gcm128_encrypt: function(ctx: PGCM128_CONTEXT; _in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_gcm128_encrypt}

  CRYPTO_gcm128_decrypt: function(ctx: PGCM128_CONTEXT; _in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_gcm128_decrypt}

  CRYPTO_gcm128_encrypt_ctr32: function(ctx: PGCM128_CONTEXT; _in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; stream: Tctr128_f): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_gcm128_encrypt_ctr32}

  CRYPTO_gcm128_decrypt_ctr32: function(ctx: PGCM128_CONTEXT; _in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; stream: Tctr128_f): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_gcm128_decrypt_ctr32}

  CRYPTO_gcm128_finish: function(ctx: PGCM128_CONTEXT; tag: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_gcm128_finish}

  CRYPTO_gcm128_tag: procedure(ctx: PGCM128_CONTEXT; tag: PIdAnsiChar; len: TIdC_SIZET); cdecl = nil;
  {$EXTERNALSYM CRYPTO_gcm128_tag}

  CRYPTO_gcm128_release: procedure(ctx: PGCM128_CONTEXT); cdecl = nil;
  {$EXTERNALSYM CRYPTO_gcm128_release}

  CRYPTO_ccm128_init: procedure(ctx: PCCM128_CONTEXT; M: TIdC_UINT; L: TIdC_UINT; key: Pointer; block: Tblock128_f); cdecl = nil;
  {$EXTERNALSYM CRYPTO_ccm128_init}

  CRYPTO_ccm128_setiv: function(ctx: PCCM128_CONTEXT; nonce: PIdAnsiChar; nlen: TIdC_SIZET; mlen: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_ccm128_setiv}

  CRYPTO_ccm128_aad: procedure(ctx: PCCM128_CONTEXT; aad: PIdAnsiChar; alen: TIdC_SIZET); cdecl = nil;
  {$EXTERNALSYM CRYPTO_ccm128_aad}

  CRYPTO_ccm128_encrypt: function(ctx: PCCM128_CONTEXT; inp: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_ccm128_encrypt}

  CRYPTO_ccm128_decrypt: function(ctx: PCCM128_CONTEXT; inp: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_ccm128_decrypt}

  CRYPTO_ccm128_encrypt_ccm64: function(ctx: PCCM128_CONTEXT; inp: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; stream: Tccm128_f): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_ccm128_encrypt_ccm64}

  CRYPTO_ccm128_decrypt_ccm64: function(ctx: PCCM128_CONTEXT; inp: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; stream: Tccm128_f): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_ccm128_decrypt_ccm64}

  CRYPTO_ccm128_tag: function(ctx: PCCM128_CONTEXT; tag: PIdAnsiChar; len: TIdC_SIZET): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM CRYPTO_ccm128_tag}

  CRYPTO_xts128_encrypt: function(ctx: PXTS128_CONTEXT; iv: PIdAnsiChar; inp: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; enc: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_xts128_encrypt}

  CRYPTO_128_wrap: function(key: Pointer; iv: PIdAnsiChar; _out: PIdAnsiChar; _in: PIdAnsiChar; inlen: TIdC_SIZET; block: Tblock128_f): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM CRYPTO_128_wrap}

  CRYPTO_128_unwrap: function(key: Pointer; iv: PIdAnsiChar; _out: PIdAnsiChar; _in: PIdAnsiChar; inlen: TIdC_SIZET; block: Tblock128_f): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM CRYPTO_128_unwrap}

  CRYPTO_128_wrap_pad: function(key: Pointer; icv: PIdAnsiChar; _out: PIdAnsiChar; _in: PIdAnsiChar; inlen: TIdC_SIZET; block: Tblock128_f): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM CRYPTO_128_wrap_pad}

  CRYPTO_128_unwrap_pad: function(key: Pointer; icv: PIdAnsiChar; _out: PIdAnsiChar; _in: PIdAnsiChar; inlen: TIdC_SIZET; block: Tblock128_f): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM CRYPTO_128_unwrap_pad}

  CRYPTO_ocb128_new: function(keyenc: Pointer; keydec: Pointer; encrypt: Tblock128_f; decrypt: Tblock128_f; stream: Tocb128_f): POCB128_CONTEXT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_ocb128_new}

  CRYPTO_ocb128_init: function(ctx: POCB128_CONTEXT; keyenc: Pointer; keydec: Pointer; encrypt: Tblock128_f; decrypt: Tblock128_f; stream: Tocb128_f): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_ocb128_init}

  CRYPTO_ocb128_copy_ctx: function(dest: POCB128_CONTEXT; src: POCB128_CONTEXT; keyenc: Pointer; keydec: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_ocb128_copy_ctx}

  CRYPTO_ocb128_setiv: function(ctx: POCB128_CONTEXT; iv: PIdAnsiChar; len: TIdC_SIZET; taglen: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_ocb128_setiv}

  CRYPTO_ocb128_aad: function(ctx: POCB128_CONTEXT; aad: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_ocb128_aad}

  CRYPTO_ocb128_encrypt: function(ctx: POCB128_CONTEXT; _in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_ocb128_encrypt}

  CRYPTO_ocb128_decrypt: function(ctx: POCB128_CONTEXT; _in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_ocb128_decrypt}

  CRYPTO_ocb128_finish: function(ctx: POCB128_CONTEXT; tag: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_ocb128_finish}

  CRYPTO_ocb128_tag: function(ctx: POCB128_CONTEXT; tag: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_ocb128_tag}

  CRYPTO_ocb128_cleanup: procedure(ctx: POCB128_CONTEXT); cdecl = nil;
  {$EXTERNALSYM CRYPTO_ocb128_cleanup}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

procedure CRYPTO_cbc128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; block: Tblock128_f); cdecl;
procedure CRYPTO_cbc128_decrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; block: Tblock128_f); cdecl;
procedure CRYPTO_ctr128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; ecount_buf: PIdAnsiChar; num: PIdC_UINT; block: Tblock128_f); cdecl;
procedure CRYPTO_ctr128_encrypt_ctr32(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; ecount_buf: PIdAnsiChar; num: PIdC_UINT; ctr: Tctr128_f); cdecl;
procedure CRYPTO_ofb128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; num: PIdC_INT; block: Tblock128_f); cdecl;
procedure CRYPTO_cfb128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT; block: Tblock128_f); cdecl;
procedure CRYPTO_cfb128_8_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT; block: Tblock128_f); cdecl;
procedure CRYPTO_cfb128_1_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; bits: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT; block: Tblock128_f); cdecl;
function CRYPTO_cts128_encrypt_block(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; block: Tblock128_f): TIdC_SIZET; cdecl;
function CRYPTO_cts128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; cbc: Tcbc128_f): TIdC_SIZET; cdecl;
function CRYPTO_cts128_decrypt_block(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; block: Tblock128_f): TIdC_SIZET; cdecl;
function CRYPTO_cts128_decrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; cbc: Tcbc128_f): TIdC_SIZET; cdecl;
function CRYPTO_nistcts128_encrypt_block(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; block: Tblock128_f): TIdC_SIZET; cdecl;
function CRYPTO_nistcts128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; cbc: Tcbc128_f): TIdC_SIZET; cdecl;
function CRYPTO_nistcts128_decrypt_block(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; block: Tblock128_f): TIdC_SIZET; cdecl;
function CRYPTO_nistcts128_decrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; cbc: Tcbc128_f): TIdC_SIZET; cdecl;
function CRYPTO_gcm128_new(key: Pointer; block: Tblock128_f): PGCM128_CONTEXT; cdecl;
procedure CRYPTO_gcm128_init(ctx: PGCM128_CONTEXT; key: Pointer; block: Tblock128_f); cdecl;
procedure CRYPTO_gcm128_setiv(ctx: PGCM128_CONTEXT; iv: PIdAnsiChar; len: TIdC_SIZET); cdecl;
function CRYPTO_gcm128_aad(ctx: PGCM128_CONTEXT; aad: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl;
function CRYPTO_gcm128_encrypt(ctx: PGCM128_CONTEXT; _in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl;
function CRYPTO_gcm128_decrypt(ctx: PGCM128_CONTEXT; _in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl;
function CRYPTO_gcm128_encrypt_ctr32(ctx: PGCM128_CONTEXT; _in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; stream: Tctr128_f): TIdC_INT; cdecl;
function CRYPTO_gcm128_decrypt_ctr32(ctx: PGCM128_CONTEXT; _in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; stream: Tctr128_f): TIdC_INT; cdecl;
function CRYPTO_gcm128_finish(ctx: PGCM128_CONTEXT; tag: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl;
procedure CRYPTO_gcm128_tag(ctx: PGCM128_CONTEXT; tag: PIdAnsiChar; len: TIdC_SIZET); cdecl;
procedure CRYPTO_gcm128_release(ctx: PGCM128_CONTEXT); cdecl;
procedure CRYPTO_ccm128_init(ctx: PCCM128_CONTEXT; M: TIdC_UINT; L: TIdC_UINT; key: Pointer; block: Tblock128_f); cdecl;
function CRYPTO_ccm128_setiv(ctx: PCCM128_CONTEXT; nonce: PIdAnsiChar; nlen: TIdC_SIZET; mlen: TIdC_SIZET): TIdC_INT; cdecl;
procedure CRYPTO_ccm128_aad(ctx: PCCM128_CONTEXT; aad: PIdAnsiChar; alen: TIdC_SIZET); cdecl;
function CRYPTO_ccm128_encrypt(ctx: PCCM128_CONTEXT; inp: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl;
function CRYPTO_ccm128_decrypt(ctx: PCCM128_CONTEXT; inp: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl;
function CRYPTO_ccm128_encrypt_ccm64(ctx: PCCM128_CONTEXT; inp: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; stream: Tccm128_f): TIdC_INT; cdecl;
function CRYPTO_ccm128_decrypt_ccm64(ctx: PCCM128_CONTEXT; inp: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; stream: Tccm128_f): TIdC_INT; cdecl;
function CRYPTO_ccm128_tag(ctx: PCCM128_CONTEXT; tag: PIdAnsiChar; len: TIdC_SIZET): TIdC_SIZET; cdecl;
function CRYPTO_xts128_encrypt(ctx: PXTS128_CONTEXT; iv: PIdAnsiChar; inp: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; enc: TIdC_INT): TIdC_INT; cdecl;
function CRYPTO_128_wrap(key: Pointer; iv: PIdAnsiChar; _out: PIdAnsiChar; _in: PIdAnsiChar; inlen: TIdC_SIZET; block: Tblock128_f): TIdC_SIZET; cdecl;
function CRYPTO_128_unwrap(key: Pointer; iv: PIdAnsiChar; _out: PIdAnsiChar; _in: PIdAnsiChar; inlen: TIdC_SIZET; block: Tblock128_f): TIdC_SIZET; cdecl;
function CRYPTO_128_wrap_pad(key: Pointer; icv: PIdAnsiChar; _out: PIdAnsiChar; _in: PIdAnsiChar; inlen: TIdC_SIZET; block: Tblock128_f): TIdC_SIZET; cdecl;
function CRYPTO_128_unwrap_pad(key: Pointer; icv: PIdAnsiChar; _out: PIdAnsiChar; _in: PIdAnsiChar; inlen: TIdC_SIZET; block: Tblock128_f): TIdC_SIZET; cdecl;
function CRYPTO_ocb128_new(keyenc: Pointer; keydec: Pointer; encrypt: Tblock128_f; decrypt: Tblock128_f; stream: Tocb128_f): POCB128_CONTEXT; cdecl;
function CRYPTO_ocb128_init(ctx: POCB128_CONTEXT; keyenc: Pointer; keydec: Pointer; encrypt: Tblock128_f; decrypt: Tblock128_f; stream: Tocb128_f): TIdC_INT; cdecl;
function CRYPTO_ocb128_copy_ctx(dest: POCB128_CONTEXT; src: POCB128_CONTEXT; keyenc: Pointer; keydec: Pointer): TIdC_INT; cdecl;
function CRYPTO_ocb128_setiv(ctx: POCB128_CONTEXT; iv: PIdAnsiChar; len: TIdC_SIZET; taglen: TIdC_SIZET): TIdC_INT; cdecl;
function CRYPTO_ocb128_aad(ctx: POCB128_CONTEXT; aad: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl;
function CRYPTO_ocb128_encrypt(ctx: POCB128_CONTEXT; _in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl;
function CRYPTO_ocb128_decrypt(ctx: POCB128_CONTEXT; _in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl;
function CRYPTO_ocb128_finish(ctx: POCB128_CONTEXT; tag: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl;
function CRYPTO_ocb128_tag(ctx: POCB128_CONTEXT; tag: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl;
procedure CRYPTO_ocb128_cleanup(ctx: POCB128_CONTEXT); cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

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

procedure CRYPTO_cbc128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; block: Tblock128_f); cdecl external CLibCrypto name 'CRYPTO_cbc128_encrypt';
procedure CRYPTO_cbc128_decrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; block: Tblock128_f); cdecl external CLibCrypto name 'CRYPTO_cbc128_decrypt';
procedure CRYPTO_ctr128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; ecount_buf: PIdAnsiChar; num: PIdC_UINT; block: Tblock128_f); cdecl external CLibCrypto name 'CRYPTO_ctr128_encrypt';
procedure CRYPTO_ctr128_encrypt_ctr32(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; ecount_buf: PIdAnsiChar; num: PIdC_UINT; ctr: Tctr128_f); cdecl external CLibCrypto name 'CRYPTO_ctr128_encrypt_ctr32';
procedure CRYPTO_ofb128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; num: PIdC_INT; block: Tblock128_f); cdecl external CLibCrypto name 'CRYPTO_ofb128_encrypt';
procedure CRYPTO_cfb128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT; block: Tblock128_f); cdecl external CLibCrypto name 'CRYPTO_cfb128_encrypt';
procedure CRYPTO_cfb128_8_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT; block: Tblock128_f); cdecl external CLibCrypto name 'CRYPTO_cfb128_8_encrypt';
procedure CRYPTO_cfb128_1_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; bits: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT; block: Tblock128_f); cdecl external CLibCrypto name 'CRYPTO_cfb128_1_encrypt';
function CRYPTO_cts128_encrypt_block(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; block: Tblock128_f): TIdC_SIZET; cdecl external CLibCrypto name 'CRYPTO_cts128_encrypt_block';
function CRYPTO_cts128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; cbc: Tcbc128_f): TIdC_SIZET; cdecl external CLibCrypto name 'CRYPTO_cts128_encrypt';
function CRYPTO_cts128_decrypt_block(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; block: Tblock128_f): TIdC_SIZET; cdecl external CLibCrypto name 'CRYPTO_cts128_decrypt_block';
function CRYPTO_cts128_decrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; cbc: Tcbc128_f): TIdC_SIZET; cdecl external CLibCrypto name 'CRYPTO_cts128_decrypt';
function CRYPTO_nistcts128_encrypt_block(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; block: Tblock128_f): TIdC_SIZET; cdecl external CLibCrypto name 'CRYPTO_nistcts128_encrypt_block';
function CRYPTO_nistcts128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; cbc: Tcbc128_f): TIdC_SIZET; cdecl external CLibCrypto name 'CRYPTO_nistcts128_encrypt';
function CRYPTO_nistcts128_decrypt_block(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; block: Tblock128_f): TIdC_SIZET; cdecl external CLibCrypto name 'CRYPTO_nistcts128_decrypt_block';
function CRYPTO_nistcts128_decrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; cbc: Tcbc128_f): TIdC_SIZET; cdecl external CLibCrypto name 'CRYPTO_nistcts128_decrypt';
function CRYPTO_gcm128_new(key: Pointer; block: Tblock128_f): PGCM128_CONTEXT; cdecl external CLibCrypto name 'CRYPTO_gcm128_new';
procedure CRYPTO_gcm128_init(ctx: PGCM128_CONTEXT; key: Pointer; block: Tblock128_f); cdecl external CLibCrypto name 'CRYPTO_gcm128_init';
procedure CRYPTO_gcm128_setiv(ctx: PGCM128_CONTEXT; iv: PIdAnsiChar; len: TIdC_SIZET); cdecl external CLibCrypto name 'CRYPTO_gcm128_setiv';
function CRYPTO_gcm128_aad(ctx: PGCM128_CONTEXT; aad: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_gcm128_aad';
function CRYPTO_gcm128_encrypt(ctx: PGCM128_CONTEXT; _in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_gcm128_encrypt';
function CRYPTO_gcm128_decrypt(ctx: PGCM128_CONTEXT; _in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_gcm128_decrypt';
function CRYPTO_gcm128_encrypt_ctr32(ctx: PGCM128_CONTEXT; _in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; stream: Tctr128_f): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_gcm128_encrypt_ctr32';
function CRYPTO_gcm128_decrypt_ctr32(ctx: PGCM128_CONTEXT; _in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; stream: Tctr128_f): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_gcm128_decrypt_ctr32';
function CRYPTO_gcm128_finish(ctx: PGCM128_CONTEXT; tag: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_gcm128_finish';
procedure CRYPTO_gcm128_tag(ctx: PGCM128_CONTEXT; tag: PIdAnsiChar; len: TIdC_SIZET); cdecl external CLibCrypto name 'CRYPTO_gcm128_tag';
procedure CRYPTO_gcm128_release(ctx: PGCM128_CONTEXT); cdecl external CLibCrypto name 'CRYPTO_gcm128_release';
procedure CRYPTO_ccm128_init(ctx: PCCM128_CONTEXT; M: TIdC_UINT; L: TIdC_UINT; key: Pointer; block: Tblock128_f); cdecl external CLibCrypto name 'CRYPTO_ccm128_init';
function CRYPTO_ccm128_setiv(ctx: PCCM128_CONTEXT; nonce: PIdAnsiChar; nlen: TIdC_SIZET; mlen: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_ccm128_setiv';
procedure CRYPTO_ccm128_aad(ctx: PCCM128_CONTEXT; aad: PIdAnsiChar; alen: TIdC_SIZET); cdecl external CLibCrypto name 'CRYPTO_ccm128_aad';
function CRYPTO_ccm128_encrypt(ctx: PCCM128_CONTEXT; inp: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_ccm128_encrypt';
function CRYPTO_ccm128_decrypt(ctx: PCCM128_CONTEXT; inp: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_ccm128_decrypt';
function CRYPTO_ccm128_encrypt_ccm64(ctx: PCCM128_CONTEXT; inp: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; stream: Tccm128_f): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_ccm128_encrypt_ccm64';
function CRYPTO_ccm128_decrypt_ccm64(ctx: PCCM128_CONTEXT; inp: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; stream: Tccm128_f): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_ccm128_decrypt_ccm64';
function CRYPTO_ccm128_tag(ctx: PCCM128_CONTEXT; tag: PIdAnsiChar; len: TIdC_SIZET): TIdC_SIZET; cdecl external CLibCrypto name 'CRYPTO_ccm128_tag';
function CRYPTO_xts128_encrypt(ctx: PXTS128_CONTEXT; iv: PIdAnsiChar; inp: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; enc: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_xts128_encrypt';
function CRYPTO_128_wrap(key: Pointer; iv: PIdAnsiChar; _out: PIdAnsiChar; _in: PIdAnsiChar; inlen: TIdC_SIZET; block: Tblock128_f): TIdC_SIZET; cdecl external CLibCrypto name 'CRYPTO_128_wrap';
function CRYPTO_128_unwrap(key: Pointer; iv: PIdAnsiChar; _out: PIdAnsiChar; _in: PIdAnsiChar; inlen: TIdC_SIZET; block: Tblock128_f): TIdC_SIZET; cdecl external CLibCrypto name 'CRYPTO_128_unwrap';
function CRYPTO_128_wrap_pad(key: Pointer; icv: PIdAnsiChar; _out: PIdAnsiChar; _in: PIdAnsiChar; inlen: TIdC_SIZET; block: Tblock128_f): TIdC_SIZET; cdecl external CLibCrypto name 'CRYPTO_128_wrap_pad';
function CRYPTO_128_unwrap_pad(key: Pointer; icv: PIdAnsiChar; _out: PIdAnsiChar; _in: PIdAnsiChar; inlen: TIdC_SIZET; block: Tblock128_f): TIdC_SIZET; cdecl external CLibCrypto name 'CRYPTO_128_unwrap_pad';
function CRYPTO_ocb128_new(keyenc: Pointer; keydec: Pointer; encrypt: Tblock128_f; decrypt: Tblock128_f; stream: Tocb128_f): POCB128_CONTEXT; cdecl external CLibCrypto name 'CRYPTO_ocb128_new';
function CRYPTO_ocb128_init(ctx: POCB128_CONTEXT; keyenc: Pointer; keydec: Pointer; encrypt: Tblock128_f; decrypt: Tblock128_f; stream: Tocb128_f): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_ocb128_init';
function CRYPTO_ocb128_copy_ctx(dest: POCB128_CONTEXT; src: POCB128_CONTEXT; keyenc: Pointer; keydec: Pointer): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_ocb128_copy_ctx';
function CRYPTO_ocb128_setiv(ctx: POCB128_CONTEXT; iv: PIdAnsiChar; len: TIdC_SIZET; taglen: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_ocb128_setiv';
function CRYPTO_ocb128_aad(ctx: POCB128_CONTEXT; aad: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_ocb128_aad';
function CRYPTO_ocb128_encrypt(ctx: POCB128_CONTEXT; _in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_ocb128_encrypt';
function CRYPTO_ocb128_decrypt(ctx: POCB128_CONTEXT; _in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_ocb128_decrypt';
function CRYPTO_ocb128_finish(ctx: POCB128_CONTEXT; tag: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_ocb128_finish';
function CRYPTO_ocb128_tag(ctx: POCB128_CONTEXT; tag: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_ocb128_tag';
procedure CRYPTO_ocb128_cleanup(ctx: POCB128_CONTEXT); cdecl external CLibCrypto name 'CRYPTO_ocb128_cleanup';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  CRYPTO_cbc128_encrypt_procname = 'CRYPTO_cbc128_encrypt';
  CRYPTO_cbc128_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_cbc128_decrypt_procname = 'CRYPTO_cbc128_decrypt';
  CRYPTO_cbc128_decrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_ctr128_encrypt_procname = 'CRYPTO_ctr128_encrypt';
  CRYPTO_ctr128_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_ctr128_encrypt_ctr32_procname = 'CRYPTO_ctr128_encrypt_ctr32';
  CRYPTO_ctr128_encrypt_ctr32_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_ofb128_encrypt_procname = 'CRYPTO_ofb128_encrypt';
  CRYPTO_ofb128_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_cfb128_encrypt_procname = 'CRYPTO_cfb128_encrypt';
  CRYPTO_cfb128_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_cfb128_8_encrypt_procname = 'CRYPTO_cfb128_8_encrypt';
  CRYPTO_cfb128_8_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_cfb128_1_encrypt_procname = 'CRYPTO_cfb128_1_encrypt';
  CRYPTO_cfb128_1_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_cts128_encrypt_block_procname = 'CRYPTO_cts128_encrypt_block';
  CRYPTO_cts128_encrypt_block_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_cts128_encrypt_procname = 'CRYPTO_cts128_encrypt';
  CRYPTO_cts128_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_cts128_decrypt_block_procname = 'CRYPTO_cts128_decrypt_block';
  CRYPTO_cts128_decrypt_block_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_cts128_decrypt_procname = 'CRYPTO_cts128_decrypt';
  CRYPTO_cts128_decrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_nistcts128_encrypt_block_procname = 'CRYPTO_nistcts128_encrypt_block';
  CRYPTO_nistcts128_encrypt_block_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_nistcts128_encrypt_procname = 'CRYPTO_nistcts128_encrypt';
  CRYPTO_nistcts128_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_nistcts128_decrypt_block_procname = 'CRYPTO_nistcts128_decrypt_block';
  CRYPTO_nistcts128_decrypt_block_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_nistcts128_decrypt_procname = 'CRYPTO_nistcts128_decrypt';
  CRYPTO_nistcts128_decrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_gcm128_new_procname = 'CRYPTO_gcm128_new';
  CRYPTO_gcm128_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_gcm128_init_procname = 'CRYPTO_gcm128_init';
  CRYPTO_gcm128_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_gcm128_setiv_procname = 'CRYPTO_gcm128_setiv';
  CRYPTO_gcm128_setiv_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_gcm128_aad_procname = 'CRYPTO_gcm128_aad';
  CRYPTO_gcm128_aad_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_gcm128_encrypt_procname = 'CRYPTO_gcm128_encrypt';
  CRYPTO_gcm128_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_gcm128_decrypt_procname = 'CRYPTO_gcm128_decrypt';
  CRYPTO_gcm128_decrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_gcm128_encrypt_ctr32_procname = 'CRYPTO_gcm128_encrypt_ctr32';
  CRYPTO_gcm128_encrypt_ctr32_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_gcm128_decrypt_ctr32_procname = 'CRYPTO_gcm128_decrypt_ctr32';
  CRYPTO_gcm128_decrypt_ctr32_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_gcm128_finish_procname = 'CRYPTO_gcm128_finish';
  CRYPTO_gcm128_finish_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_gcm128_tag_procname = 'CRYPTO_gcm128_tag';
  CRYPTO_gcm128_tag_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_gcm128_release_procname = 'CRYPTO_gcm128_release';
  CRYPTO_gcm128_release_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_ccm128_init_procname = 'CRYPTO_ccm128_init';
  CRYPTO_ccm128_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_ccm128_setiv_procname = 'CRYPTO_ccm128_setiv';
  CRYPTO_ccm128_setiv_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_ccm128_aad_procname = 'CRYPTO_ccm128_aad';
  CRYPTO_ccm128_aad_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_ccm128_encrypt_procname = 'CRYPTO_ccm128_encrypt';
  CRYPTO_ccm128_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_ccm128_decrypt_procname = 'CRYPTO_ccm128_decrypt';
  CRYPTO_ccm128_decrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_ccm128_encrypt_ccm64_procname = 'CRYPTO_ccm128_encrypt_ccm64';
  CRYPTO_ccm128_encrypt_ccm64_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_ccm128_decrypt_ccm64_procname = 'CRYPTO_ccm128_decrypt_ccm64';
  CRYPTO_ccm128_decrypt_ccm64_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_ccm128_tag_procname = 'CRYPTO_ccm128_tag';
  CRYPTO_ccm128_tag_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_xts128_encrypt_procname = 'CRYPTO_xts128_encrypt';
  CRYPTO_xts128_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_128_wrap_procname = 'CRYPTO_128_wrap';
  CRYPTO_128_wrap_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_128_unwrap_procname = 'CRYPTO_128_unwrap';
  CRYPTO_128_unwrap_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_128_wrap_pad_procname = 'CRYPTO_128_wrap_pad';
  CRYPTO_128_wrap_pad_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_128_unwrap_pad_procname = 'CRYPTO_128_unwrap_pad';
  CRYPTO_128_unwrap_pad_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_ocb128_new_procname = 'CRYPTO_ocb128_new';
  CRYPTO_ocb128_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_ocb128_init_procname = 'CRYPTO_ocb128_init';
  CRYPTO_ocb128_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_ocb128_copy_ctx_procname = 'CRYPTO_ocb128_copy_ctx';
  CRYPTO_ocb128_copy_ctx_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_ocb128_setiv_procname = 'CRYPTO_ocb128_setiv';
  CRYPTO_ocb128_setiv_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_ocb128_aad_procname = 'CRYPTO_ocb128_aad';
  CRYPTO_ocb128_aad_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_ocb128_encrypt_procname = 'CRYPTO_ocb128_encrypt';
  CRYPTO_ocb128_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_ocb128_decrypt_procname = 'CRYPTO_ocb128_decrypt';
  CRYPTO_ocb128_decrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_ocb128_finish_procname = 'CRYPTO_ocb128_finish';
  CRYPTO_ocb128_finish_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_ocb128_tag_procname = 'CRYPTO_ocb128_tag';
  CRYPTO_ocb128_tag_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_ocb128_cleanup_procname = 'CRYPTO_ocb128_cleanup';
  CRYPTO_ocb128_cleanup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

procedure ERR_CRYPTO_cbc128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; block: Tblock128_f); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_cbc128_encrypt_procname);
end;

procedure ERR_CRYPTO_cbc128_decrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; block: Tblock128_f); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_cbc128_decrypt_procname);
end;

procedure ERR_CRYPTO_ctr128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; ecount_buf: PIdAnsiChar; num: PIdC_UINT; block: Tblock128_f); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_ctr128_encrypt_procname);
end;

procedure ERR_CRYPTO_ctr128_encrypt_ctr32(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; ecount_buf: PIdAnsiChar; num: PIdC_UINT; ctr: Tctr128_f); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_ctr128_encrypt_ctr32_procname);
end;

procedure ERR_CRYPTO_ofb128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; num: PIdC_INT; block: Tblock128_f); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_ofb128_encrypt_procname);
end;

procedure ERR_CRYPTO_cfb128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT; block: Tblock128_f); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_cfb128_encrypt_procname);
end;

procedure ERR_CRYPTO_cfb128_8_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT; block: Tblock128_f); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_cfb128_8_encrypt_procname);
end;

procedure ERR_CRYPTO_cfb128_1_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; bits: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT; block: Tblock128_f); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_cfb128_1_encrypt_procname);
end;

function ERR_CRYPTO_cts128_encrypt_block(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; block: Tblock128_f): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_cts128_encrypt_block_procname);
end;

function ERR_CRYPTO_cts128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; cbc: Tcbc128_f): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_cts128_encrypt_procname);
end;

function ERR_CRYPTO_cts128_decrypt_block(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; block: Tblock128_f): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_cts128_decrypt_block_procname);
end;

function ERR_CRYPTO_cts128_decrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; cbc: Tcbc128_f): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_cts128_decrypt_procname);
end;

function ERR_CRYPTO_nistcts128_encrypt_block(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; block: Tblock128_f): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_nistcts128_encrypt_block_procname);
end;

function ERR_CRYPTO_nistcts128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; cbc: Tcbc128_f): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_nistcts128_encrypt_procname);
end;

function ERR_CRYPTO_nistcts128_decrypt_block(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; block: Tblock128_f): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_nistcts128_decrypt_block_procname);
end;

function ERR_CRYPTO_nistcts128_decrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; key: Pointer; ivec: PIdAnsiChar; cbc: Tcbc128_f): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_nistcts128_decrypt_procname);
end;

function ERR_CRYPTO_gcm128_new(key: Pointer; block: Tblock128_f): PGCM128_CONTEXT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_gcm128_new_procname);
end;

procedure ERR_CRYPTO_gcm128_init(ctx: PGCM128_CONTEXT; key: Pointer; block: Tblock128_f); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_gcm128_init_procname);
end;

procedure ERR_CRYPTO_gcm128_setiv(ctx: PGCM128_CONTEXT; iv: PIdAnsiChar; len: TIdC_SIZET); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_gcm128_setiv_procname);
end;

function ERR_CRYPTO_gcm128_aad(ctx: PGCM128_CONTEXT; aad: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_gcm128_aad_procname);
end;

function ERR_CRYPTO_gcm128_encrypt(ctx: PGCM128_CONTEXT; _in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_gcm128_encrypt_procname);
end;

function ERR_CRYPTO_gcm128_decrypt(ctx: PGCM128_CONTEXT; _in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_gcm128_decrypt_procname);
end;

function ERR_CRYPTO_gcm128_encrypt_ctr32(ctx: PGCM128_CONTEXT; _in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; stream: Tctr128_f): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_gcm128_encrypt_ctr32_procname);
end;

function ERR_CRYPTO_gcm128_decrypt_ctr32(ctx: PGCM128_CONTEXT; _in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; stream: Tctr128_f): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_gcm128_decrypt_ctr32_procname);
end;

function ERR_CRYPTO_gcm128_finish(ctx: PGCM128_CONTEXT; tag: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_gcm128_finish_procname);
end;

procedure ERR_CRYPTO_gcm128_tag(ctx: PGCM128_CONTEXT; tag: PIdAnsiChar; len: TIdC_SIZET); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_gcm128_tag_procname);
end;

procedure ERR_CRYPTO_gcm128_release(ctx: PGCM128_CONTEXT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_gcm128_release_procname);
end;

procedure ERR_CRYPTO_ccm128_init(ctx: PCCM128_CONTEXT; M: TIdC_UINT; L: TIdC_UINT; key: Pointer; block: Tblock128_f); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_ccm128_init_procname);
end;

function ERR_CRYPTO_ccm128_setiv(ctx: PCCM128_CONTEXT; nonce: PIdAnsiChar; nlen: TIdC_SIZET; mlen: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_ccm128_setiv_procname);
end;

procedure ERR_CRYPTO_ccm128_aad(ctx: PCCM128_CONTEXT; aad: PIdAnsiChar; alen: TIdC_SIZET); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_ccm128_aad_procname);
end;

function ERR_CRYPTO_ccm128_encrypt(ctx: PCCM128_CONTEXT; inp: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_ccm128_encrypt_procname);
end;

function ERR_CRYPTO_ccm128_decrypt(ctx: PCCM128_CONTEXT; inp: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_ccm128_decrypt_procname);
end;

function ERR_CRYPTO_ccm128_encrypt_ccm64(ctx: PCCM128_CONTEXT; inp: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; stream: Tccm128_f): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_ccm128_encrypt_ccm64_procname);
end;

function ERR_CRYPTO_ccm128_decrypt_ccm64(ctx: PCCM128_CONTEXT; inp: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; stream: Tccm128_f): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_ccm128_decrypt_ccm64_procname);
end;

function ERR_CRYPTO_ccm128_tag(ctx: PCCM128_CONTEXT; tag: PIdAnsiChar; len: TIdC_SIZET): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_ccm128_tag_procname);
end;

function ERR_CRYPTO_xts128_encrypt(ctx: PXTS128_CONTEXT; iv: PIdAnsiChar; inp: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; enc: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_xts128_encrypt_procname);
end;

function ERR_CRYPTO_128_wrap(key: Pointer; iv: PIdAnsiChar; _out: PIdAnsiChar; _in: PIdAnsiChar; inlen: TIdC_SIZET; block: Tblock128_f): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_128_wrap_procname);
end;

function ERR_CRYPTO_128_unwrap(key: Pointer; iv: PIdAnsiChar; _out: PIdAnsiChar; _in: PIdAnsiChar; inlen: TIdC_SIZET; block: Tblock128_f): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_128_unwrap_procname);
end;

function ERR_CRYPTO_128_wrap_pad(key: Pointer; icv: PIdAnsiChar; _out: PIdAnsiChar; _in: PIdAnsiChar; inlen: TIdC_SIZET; block: Tblock128_f): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_128_wrap_pad_procname);
end;

function ERR_CRYPTO_128_unwrap_pad(key: Pointer; icv: PIdAnsiChar; _out: PIdAnsiChar; _in: PIdAnsiChar; inlen: TIdC_SIZET; block: Tblock128_f): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_128_unwrap_pad_procname);
end;

function ERR_CRYPTO_ocb128_new(keyenc: Pointer; keydec: Pointer; encrypt: Tblock128_f; decrypt: Tblock128_f; stream: Tocb128_f): POCB128_CONTEXT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_ocb128_new_procname);
end;

function ERR_CRYPTO_ocb128_init(ctx: POCB128_CONTEXT; keyenc: Pointer; keydec: Pointer; encrypt: Tblock128_f; decrypt: Tblock128_f; stream: Tocb128_f): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_ocb128_init_procname);
end;

function ERR_CRYPTO_ocb128_copy_ctx(dest: POCB128_CONTEXT; src: POCB128_CONTEXT; keyenc: Pointer; keydec: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_ocb128_copy_ctx_procname);
end;

function ERR_CRYPTO_ocb128_setiv(ctx: POCB128_CONTEXT; iv: PIdAnsiChar; len: TIdC_SIZET; taglen: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_ocb128_setiv_procname);
end;

function ERR_CRYPTO_ocb128_aad(ctx: POCB128_CONTEXT; aad: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_ocb128_aad_procname);
end;

function ERR_CRYPTO_ocb128_encrypt(ctx: POCB128_CONTEXT; _in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_ocb128_encrypt_procname);
end;

function ERR_CRYPTO_ocb128_decrypt(ctx: POCB128_CONTEXT; _in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_ocb128_decrypt_procname);
end;

function ERR_CRYPTO_ocb128_finish(ctx: POCB128_CONTEXT; tag: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_ocb128_finish_procname);
end;

function ERR_CRYPTO_ocb128_tag(ctx: POCB128_CONTEXT; tag: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_ocb128_tag_procname);
end;

procedure ERR_CRYPTO_ocb128_cleanup(ctx: POCB128_CONTEXT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_ocb128_cleanup_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  CRYPTO_cbc128_encrypt := LoadLibFunction(ADllHandle, CRYPTO_cbc128_encrypt_procname);
  FuncLoadError := not assigned(CRYPTO_cbc128_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_cbc128_encrypt_allownil)}
    CRYPTO_cbc128_encrypt := ERR_CRYPTO_cbc128_encrypt;
    {$ifend}
    {$if declared(CRYPTO_cbc128_encrypt_introduced)}
    if LibVersion < CRYPTO_cbc128_encrypt_introduced then
    begin
      {$if declared(FC_CRYPTO_cbc128_encrypt)}
      CRYPTO_cbc128_encrypt := FC_CRYPTO_cbc128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_cbc128_encrypt_removed)}
    if CRYPTO_cbc128_encrypt_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_cbc128_encrypt)}
      CRYPTO_cbc128_encrypt := _CRYPTO_cbc128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_cbc128_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_cbc128_encrypt');
    {$ifend}
  end;
  
  CRYPTO_cbc128_decrypt := LoadLibFunction(ADllHandle, CRYPTO_cbc128_decrypt_procname);
  FuncLoadError := not assigned(CRYPTO_cbc128_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_cbc128_decrypt_allownil)}
    CRYPTO_cbc128_decrypt := ERR_CRYPTO_cbc128_decrypt;
    {$ifend}
    {$if declared(CRYPTO_cbc128_decrypt_introduced)}
    if LibVersion < CRYPTO_cbc128_decrypt_introduced then
    begin
      {$if declared(FC_CRYPTO_cbc128_decrypt)}
      CRYPTO_cbc128_decrypt := FC_CRYPTO_cbc128_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_cbc128_decrypt_removed)}
    if CRYPTO_cbc128_decrypt_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_cbc128_decrypt)}
      CRYPTO_cbc128_decrypt := _CRYPTO_cbc128_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_cbc128_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_cbc128_decrypt');
    {$ifend}
  end;
  
  CRYPTO_ctr128_encrypt := LoadLibFunction(ADllHandle, CRYPTO_ctr128_encrypt_procname);
  FuncLoadError := not assigned(CRYPTO_ctr128_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_ctr128_encrypt_allownil)}
    CRYPTO_ctr128_encrypt := ERR_CRYPTO_ctr128_encrypt;
    {$ifend}
    {$if declared(CRYPTO_ctr128_encrypt_introduced)}
    if LibVersion < CRYPTO_ctr128_encrypt_introduced then
    begin
      {$if declared(FC_CRYPTO_ctr128_encrypt)}
      CRYPTO_ctr128_encrypt := FC_CRYPTO_ctr128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_ctr128_encrypt_removed)}
    if CRYPTO_ctr128_encrypt_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_ctr128_encrypt)}
      CRYPTO_ctr128_encrypt := _CRYPTO_ctr128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_ctr128_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_ctr128_encrypt');
    {$ifend}
  end;
  
  CRYPTO_ctr128_encrypt_ctr32 := LoadLibFunction(ADllHandle, CRYPTO_ctr128_encrypt_ctr32_procname);
  FuncLoadError := not assigned(CRYPTO_ctr128_encrypt_ctr32);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_ctr128_encrypt_ctr32_allownil)}
    CRYPTO_ctr128_encrypt_ctr32 := ERR_CRYPTO_ctr128_encrypt_ctr32;
    {$ifend}
    {$if declared(CRYPTO_ctr128_encrypt_ctr32_introduced)}
    if LibVersion < CRYPTO_ctr128_encrypt_ctr32_introduced then
    begin
      {$if declared(FC_CRYPTO_ctr128_encrypt_ctr32)}
      CRYPTO_ctr128_encrypt_ctr32 := FC_CRYPTO_ctr128_encrypt_ctr32;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_ctr128_encrypt_ctr32_removed)}
    if CRYPTO_ctr128_encrypt_ctr32_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_ctr128_encrypt_ctr32)}
      CRYPTO_ctr128_encrypt_ctr32 := _CRYPTO_ctr128_encrypt_ctr32;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_ctr128_encrypt_ctr32_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_ctr128_encrypt_ctr32');
    {$ifend}
  end;
  
  CRYPTO_ofb128_encrypt := LoadLibFunction(ADllHandle, CRYPTO_ofb128_encrypt_procname);
  FuncLoadError := not assigned(CRYPTO_ofb128_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_ofb128_encrypt_allownil)}
    CRYPTO_ofb128_encrypt := ERR_CRYPTO_ofb128_encrypt;
    {$ifend}
    {$if declared(CRYPTO_ofb128_encrypt_introduced)}
    if LibVersion < CRYPTO_ofb128_encrypt_introduced then
    begin
      {$if declared(FC_CRYPTO_ofb128_encrypt)}
      CRYPTO_ofb128_encrypt := FC_CRYPTO_ofb128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_ofb128_encrypt_removed)}
    if CRYPTO_ofb128_encrypt_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_ofb128_encrypt)}
      CRYPTO_ofb128_encrypt := _CRYPTO_ofb128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_ofb128_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_ofb128_encrypt');
    {$ifend}
  end;
  
  CRYPTO_cfb128_encrypt := LoadLibFunction(ADllHandle, CRYPTO_cfb128_encrypt_procname);
  FuncLoadError := not assigned(CRYPTO_cfb128_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_cfb128_encrypt_allownil)}
    CRYPTO_cfb128_encrypt := ERR_CRYPTO_cfb128_encrypt;
    {$ifend}
    {$if declared(CRYPTO_cfb128_encrypt_introduced)}
    if LibVersion < CRYPTO_cfb128_encrypt_introduced then
    begin
      {$if declared(FC_CRYPTO_cfb128_encrypt)}
      CRYPTO_cfb128_encrypt := FC_CRYPTO_cfb128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_cfb128_encrypt_removed)}
    if CRYPTO_cfb128_encrypt_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_cfb128_encrypt)}
      CRYPTO_cfb128_encrypt := _CRYPTO_cfb128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_cfb128_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_cfb128_encrypt');
    {$ifend}
  end;
  
  CRYPTO_cfb128_8_encrypt := LoadLibFunction(ADllHandle, CRYPTO_cfb128_8_encrypt_procname);
  FuncLoadError := not assigned(CRYPTO_cfb128_8_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_cfb128_8_encrypt_allownil)}
    CRYPTO_cfb128_8_encrypt := ERR_CRYPTO_cfb128_8_encrypt;
    {$ifend}
    {$if declared(CRYPTO_cfb128_8_encrypt_introduced)}
    if LibVersion < CRYPTO_cfb128_8_encrypt_introduced then
    begin
      {$if declared(FC_CRYPTO_cfb128_8_encrypt)}
      CRYPTO_cfb128_8_encrypt := FC_CRYPTO_cfb128_8_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_cfb128_8_encrypt_removed)}
    if CRYPTO_cfb128_8_encrypt_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_cfb128_8_encrypt)}
      CRYPTO_cfb128_8_encrypt := _CRYPTO_cfb128_8_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_cfb128_8_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_cfb128_8_encrypt');
    {$ifend}
  end;
  
  CRYPTO_cfb128_1_encrypt := LoadLibFunction(ADllHandle, CRYPTO_cfb128_1_encrypt_procname);
  FuncLoadError := not assigned(CRYPTO_cfb128_1_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_cfb128_1_encrypt_allownil)}
    CRYPTO_cfb128_1_encrypt := ERR_CRYPTO_cfb128_1_encrypt;
    {$ifend}
    {$if declared(CRYPTO_cfb128_1_encrypt_introduced)}
    if LibVersion < CRYPTO_cfb128_1_encrypt_introduced then
    begin
      {$if declared(FC_CRYPTO_cfb128_1_encrypt)}
      CRYPTO_cfb128_1_encrypt := FC_CRYPTO_cfb128_1_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_cfb128_1_encrypt_removed)}
    if CRYPTO_cfb128_1_encrypt_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_cfb128_1_encrypt)}
      CRYPTO_cfb128_1_encrypt := _CRYPTO_cfb128_1_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_cfb128_1_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_cfb128_1_encrypt');
    {$ifend}
  end;
  
  CRYPTO_cts128_encrypt_block := LoadLibFunction(ADllHandle, CRYPTO_cts128_encrypt_block_procname);
  FuncLoadError := not assigned(CRYPTO_cts128_encrypt_block);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_cts128_encrypt_block_allownil)}
    CRYPTO_cts128_encrypt_block := ERR_CRYPTO_cts128_encrypt_block;
    {$ifend}
    {$if declared(CRYPTO_cts128_encrypt_block_introduced)}
    if LibVersion < CRYPTO_cts128_encrypt_block_introduced then
    begin
      {$if declared(FC_CRYPTO_cts128_encrypt_block)}
      CRYPTO_cts128_encrypt_block := FC_CRYPTO_cts128_encrypt_block;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_cts128_encrypt_block_removed)}
    if CRYPTO_cts128_encrypt_block_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_cts128_encrypt_block)}
      CRYPTO_cts128_encrypt_block := _CRYPTO_cts128_encrypt_block;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_cts128_encrypt_block_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_cts128_encrypt_block');
    {$ifend}
  end;
  
  CRYPTO_cts128_encrypt := LoadLibFunction(ADllHandle, CRYPTO_cts128_encrypt_procname);
  FuncLoadError := not assigned(CRYPTO_cts128_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_cts128_encrypt_allownil)}
    CRYPTO_cts128_encrypt := ERR_CRYPTO_cts128_encrypt;
    {$ifend}
    {$if declared(CRYPTO_cts128_encrypt_introduced)}
    if LibVersion < CRYPTO_cts128_encrypt_introduced then
    begin
      {$if declared(FC_CRYPTO_cts128_encrypt)}
      CRYPTO_cts128_encrypt := FC_CRYPTO_cts128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_cts128_encrypt_removed)}
    if CRYPTO_cts128_encrypt_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_cts128_encrypt)}
      CRYPTO_cts128_encrypt := _CRYPTO_cts128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_cts128_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_cts128_encrypt');
    {$ifend}
  end;
  
  CRYPTO_cts128_decrypt_block := LoadLibFunction(ADllHandle, CRYPTO_cts128_decrypt_block_procname);
  FuncLoadError := not assigned(CRYPTO_cts128_decrypt_block);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_cts128_decrypt_block_allownil)}
    CRYPTO_cts128_decrypt_block := ERR_CRYPTO_cts128_decrypt_block;
    {$ifend}
    {$if declared(CRYPTO_cts128_decrypt_block_introduced)}
    if LibVersion < CRYPTO_cts128_decrypt_block_introduced then
    begin
      {$if declared(FC_CRYPTO_cts128_decrypt_block)}
      CRYPTO_cts128_decrypt_block := FC_CRYPTO_cts128_decrypt_block;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_cts128_decrypt_block_removed)}
    if CRYPTO_cts128_decrypt_block_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_cts128_decrypt_block)}
      CRYPTO_cts128_decrypt_block := _CRYPTO_cts128_decrypt_block;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_cts128_decrypt_block_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_cts128_decrypt_block');
    {$ifend}
  end;
  
  CRYPTO_cts128_decrypt := LoadLibFunction(ADllHandle, CRYPTO_cts128_decrypt_procname);
  FuncLoadError := not assigned(CRYPTO_cts128_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_cts128_decrypt_allownil)}
    CRYPTO_cts128_decrypt := ERR_CRYPTO_cts128_decrypt;
    {$ifend}
    {$if declared(CRYPTO_cts128_decrypt_introduced)}
    if LibVersion < CRYPTO_cts128_decrypt_introduced then
    begin
      {$if declared(FC_CRYPTO_cts128_decrypt)}
      CRYPTO_cts128_decrypt := FC_CRYPTO_cts128_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_cts128_decrypt_removed)}
    if CRYPTO_cts128_decrypt_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_cts128_decrypt)}
      CRYPTO_cts128_decrypt := _CRYPTO_cts128_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_cts128_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_cts128_decrypt');
    {$ifend}
  end;
  
  CRYPTO_nistcts128_encrypt_block := LoadLibFunction(ADllHandle, CRYPTO_nistcts128_encrypt_block_procname);
  FuncLoadError := not assigned(CRYPTO_nistcts128_encrypt_block);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_nistcts128_encrypt_block_allownil)}
    CRYPTO_nistcts128_encrypt_block := ERR_CRYPTO_nistcts128_encrypt_block;
    {$ifend}
    {$if declared(CRYPTO_nistcts128_encrypt_block_introduced)}
    if LibVersion < CRYPTO_nistcts128_encrypt_block_introduced then
    begin
      {$if declared(FC_CRYPTO_nistcts128_encrypt_block)}
      CRYPTO_nistcts128_encrypt_block := FC_CRYPTO_nistcts128_encrypt_block;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_nistcts128_encrypt_block_removed)}
    if CRYPTO_nistcts128_encrypt_block_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_nistcts128_encrypt_block)}
      CRYPTO_nistcts128_encrypt_block := _CRYPTO_nistcts128_encrypt_block;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_nistcts128_encrypt_block_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_nistcts128_encrypt_block');
    {$ifend}
  end;
  
  CRYPTO_nistcts128_encrypt := LoadLibFunction(ADllHandle, CRYPTO_nistcts128_encrypt_procname);
  FuncLoadError := not assigned(CRYPTO_nistcts128_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_nistcts128_encrypt_allownil)}
    CRYPTO_nistcts128_encrypt := ERR_CRYPTO_nistcts128_encrypt;
    {$ifend}
    {$if declared(CRYPTO_nistcts128_encrypt_introduced)}
    if LibVersion < CRYPTO_nistcts128_encrypt_introduced then
    begin
      {$if declared(FC_CRYPTO_nistcts128_encrypt)}
      CRYPTO_nistcts128_encrypt := FC_CRYPTO_nistcts128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_nistcts128_encrypt_removed)}
    if CRYPTO_nistcts128_encrypt_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_nistcts128_encrypt)}
      CRYPTO_nistcts128_encrypt := _CRYPTO_nistcts128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_nistcts128_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_nistcts128_encrypt');
    {$ifend}
  end;
  
  CRYPTO_nistcts128_decrypt_block := LoadLibFunction(ADllHandle, CRYPTO_nistcts128_decrypt_block_procname);
  FuncLoadError := not assigned(CRYPTO_nistcts128_decrypt_block);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_nistcts128_decrypt_block_allownil)}
    CRYPTO_nistcts128_decrypt_block := ERR_CRYPTO_nistcts128_decrypt_block;
    {$ifend}
    {$if declared(CRYPTO_nistcts128_decrypt_block_introduced)}
    if LibVersion < CRYPTO_nistcts128_decrypt_block_introduced then
    begin
      {$if declared(FC_CRYPTO_nistcts128_decrypt_block)}
      CRYPTO_nistcts128_decrypt_block := FC_CRYPTO_nistcts128_decrypt_block;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_nistcts128_decrypt_block_removed)}
    if CRYPTO_nistcts128_decrypt_block_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_nistcts128_decrypt_block)}
      CRYPTO_nistcts128_decrypt_block := _CRYPTO_nistcts128_decrypt_block;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_nistcts128_decrypt_block_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_nistcts128_decrypt_block');
    {$ifend}
  end;
  
  CRYPTO_nistcts128_decrypt := LoadLibFunction(ADllHandle, CRYPTO_nistcts128_decrypt_procname);
  FuncLoadError := not assigned(CRYPTO_nistcts128_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_nistcts128_decrypt_allownil)}
    CRYPTO_nistcts128_decrypt := ERR_CRYPTO_nistcts128_decrypt;
    {$ifend}
    {$if declared(CRYPTO_nistcts128_decrypt_introduced)}
    if LibVersion < CRYPTO_nistcts128_decrypt_introduced then
    begin
      {$if declared(FC_CRYPTO_nistcts128_decrypt)}
      CRYPTO_nistcts128_decrypt := FC_CRYPTO_nistcts128_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_nistcts128_decrypt_removed)}
    if CRYPTO_nistcts128_decrypt_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_nistcts128_decrypt)}
      CRYPTO_nistcts128_decrypt := _CRYPTO_nistcts128_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_nistcts128_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_nistcts128_decrypt');
    {$ifend}
  end;
  
  CRYPTO_gcm128_new := LoadLibFunction(ADllHandle, CRYPTO_gcm128_new_procname);
  FuncLoadError := not assigned(CRYPTO_gcm128_new);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_gcm128_new_allownil)}
    CRYPTO_gcm128_new := ERR_CRYPTO_gcm128_new;
    {$ifend}
    {$if declared(CRYPTO_gcm128_new_introduced)}
    if LibVersion < CRYPTO_gcm128_new_introduced then
    begin
      {$if declared(FC_CRYPTO_gcm128_new)}
      CRYPTO_gcm128_new := FC_CRYPTO_gcm128_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_gcm128_new_removed)}
    if CRYPTO_gcm128_new_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_gcm128_new)}
      CRYPTO_gcm128_new := _CRYPTO_gcm128_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_gcm128_new_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_gcm128_new');
    {$ifend}
  end;
  
  CRYPTO_gcm128_init := LoadLibFunction(ADllHandle, CRYPTO_gcm128_init_procname);
  FuncLoadError := not assigned(CRYPTO_gcm128_init);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_gcm128_init_allownil)}
    CRYPTO_gcm128_init := ERR_CRYPTO_gcm128_init;
    {$ifend}
    {$if declared(CRYPTO_gcm128_init_introduced)}
    if LibVersion < CRYPTO_gcm128_init_introduced then
    begin
      {$if declared(FC_CRYPTO_gcm128_init)}
      CRYPTO_gcm128_init := FC_CRYPTO_gcm128_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_gcm128_init_removed)}
    if CRYPTO_gcm128_init_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_gcm128_init)}
      CRYPTO_gcm128_init := _CRYPTO_gcm128_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_gcm128_init_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_gcm128_init');
    {$ifend}
  end;
  
  CRYPTO_gcm128_setiv := LoadLibFunction(ADllHandle, CRYPTO_gcm128_setiv_procname);
  FuncLoadError := not assigned(CRYPTO_gcm128_setiv);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_gcm128_setiv_allownil)}
    CRYPTO_gcm128_setiv := ERR_CRYPTO_gcm128_setiv;
    {$ifend}
    {$if declared(CRYPTO_gcm128_setiv_introduced)}
    if LibVersion < CRYPTO_gcm128_setiv_introduced then
    begin
      {$if declared(FC_CRYPTO_gcm128_setiv)}
      CRYPTO_gcm128_setiv := FC_CRYPTO_gcm128_setiv;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_gcm128_setiv_removed)}
    if CRYPTO_gcm128_setiv_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_gcm128_setiv)}
      CRYPTO_gcm128_setiv := _CRYPTO_gcm128_setiv;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_gcm128_setiv_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_gcm128_setiv');
    {$ifend}
  end;
  
  CRYPTO_gcm128_aad := LoadLibFunction(ADllHandle, CRYPTO_gcm128_aad_procname);
  FuncLoadError := not assigned(CRYPTO_gcm128_aad);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_gcm128_aad_allownil)}
    CRYPTO_gcm128_aad := ERR_CRYPTO_gcm128_aad;
    {$ifend}
    {$if declared(CRYPTO_gcm128_aad_introduced)}
    if LibVersion < CRYPTO_gcm128_aad_introduced then
    begin
      {$if declared(FC_CRYPTO_gcm128_aad)}
      CRYPTO_gcm128_aad := FC_CRYPTO_gcm128_aad;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_gcm128_aad_removed)}
    if CRYPTO_gcm128_aad_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_gcm128_aad)}
      CRYPTO_gcm128_aad := _CRYPTO_gcm128_aad;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_gcm128_aad_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_gcm128_aad');
    {$ifend}
  end;
  
  CRYPTO_gcm128_encrypt := LoadLibFunction(ADllHandle, CRYPTO_gcm128_encrypt_procname);
  FuncLoadError := not assigned(CRYPTO_gcm128_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_gcm128_encrypt_allownil)}
    CRYPTO_gcm128_encrypt := ERR_CRYPTO_gcm128_encrypt;
    {$ifend}
    {$if declared(CRYPTO_gcm128_encrypt_introduced)}
    if LibVersion < CRYPTO_gcm128_encrypt_introduced then
    begin
      {$if declared(FC_CRYPTO_gcm128_encrypt)}
      CRYPTO_gcm128_encrypt := FC_CRYPTO_gcm128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_gcm128_encrypt_removed)}
    if CRYPTO_gcm128_encrypt_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_gcm128_encrypt)}
      CRYPTO_gcm128_encrypt := _CRYPTO_gcm128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_gcm128_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_gcm128_encrypt');
    {$ifend}
  end;
  
  CRYPTO_gcm128_decrypt := LoadLibFunction(ADllHandle, CRYPTO_gcm128_decrypt_procname);
  FuncLoadError := not assigned(CRYPTO_gcm128_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_gcm128_decrypt_allownil)}
    CRYPTO_gcm128_decrypt := ERR_CRYPTO_gcm128_decrypt;
    {$ifend}
    {$if declared(CRYPTO_gcm128_decrypt_introduced)}
    if LibVersion < CRYPTO_gcm128_decrypt_introduced then
    begin
      {$if declared(FC_CRYPTO_gcm128_decrypt)}
      CRYPTO_gcm128_decrypt := FC_CRYPTO_gcm128_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_gcm128_decrypt_removed)}
    if CRYPTO_gcm128_decrypt_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_gcm128_decrypt)}
      CRYPTO_gcm128_decrypt := _CRYPTO_gcm128_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_gcm128_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_gcm128_decrypt');
    {$ifend}
  end;
  
  CRYPTO_gcm128_encrypt_ctr32 := LoadLibFunction(ADllHandle, CRYPTO_gcm128_encrypt_ctr32_procname);
  FuncLoadError := not assigned(CRYPTO_gcm128_encrypt_ctr32);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_gcm128_encrypt_ctr32_allownil)}
    CRYPTO_gcm128_encrypt_ctr32 := ERR_CRYPTO_gcm128_encrypt_ctr32;
    {$ifend}
    {$if declared(CRYPTO_gcm128_encrypt_ctr32_introduced)}
    if LibVersion < CRYPTO_gcm128_encrypt_ctr32_introduced then
    begin
      {$if declared(FC_CRYPTO_gcm128_encrypt_ctr32)}
      CRYPTO_gcm128_encrypt_ctr32 := FC_CRYPTO_gcm128_encrypt_ctr32;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_gcm128_encrypt_ctr32_removed)}
    if CRYPTO_gcm128_encrypt_ctr32_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_gcm128_encrypt_ctr32)}
      CRYPTO_gcm128_encrypt_ctr32 := _CRYPTO_gcm128_encrypt_ctr32;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_gcm128_encrypt_ctr32_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_gcm128_encrypt_ctr32');
    {$ifend}
  end;
  
  CRYPTO_gcm128_decrypt_ctr32 := LoadLibFunction(ADllHandle, CRYPTO_gcm128_decrypt_ctr32_procname);
  FuncLoadError := not assigned(CRYPTO_gcm128_decrypt_ctr32);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_gcm128_decrypt_ctr32_allownil)}
    CRYPTO_gcm128_decrypt_ctr32 := ERR_CRYPTO_gcm128_decrypt_ctr32;
    {$ifend}
    {$if declared(CRYPTO_gcm128_decrypt_ctr32_introduced)}
    if LibVersion < CRYPTO_gcm128_decrypt_ctr32_introduced then
    begin
      {$if declared(FC_CRYPTO_gcm128_decrypt_ctr32)}
      CRYPTO_gcm128_decrypt_ctr32 := FC_CRYPTO_gcm128_decrypt_ctr32;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_gcm128_decrypt_ctr32_removed)}
    if CRYPTO_gcm128_decrypt_ctr32_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_gcm128_decrypt_ctr32)}
      CRYPTO_gcm128_decrypt_ctr32 := _CRYPTO_gcm128_decrypt_ctr32;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_gcm128_decrypt_ctr32_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_gcm128_decrypt_ctr32');
    {$ifend}
  end;
  
  CRYPTO_gcm128_finish := LoadLibFunction(ADllHandle, CRYPTO_gcm128_finish_procname);
  FuncLoadError := not assigned(CRYPTO_gcm128_finish);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_gcm128_finish_allownil)}
    CRYPTO_gcm128_finish := ERR_CRYPTO_gcm128_finish;
    {$ifend}
    {$if declared(CRYPTO_gcm128_finish_introduced)}
    if LibVersion < CRYPTO_gcm128_finish_introduced then
    begin
      {$if declared(FC_CRYPTO_gcm128_finish)}
      CRYPTO_gcm128_finish := FC_CRYPTO_gcm128_finish;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_gcm128_finish_removed)}
    if CRYPTO_gcm128_finish_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_gcm128_finish)}
      CRYPTO_gcm128_finish := _CRYPTO_gcm128_finish;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_gcm128_finish_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_gcm128_finish');
    {$ifend}
  end;
  
  CRYPTO_gcm128_tag := LoadLibFunction(ADllHandle, CRYPTO_gcm128_tag_procname);
  FuncLoadError := not assigned(CRYPTO_gcm128_tag);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_gcm128_tag_allownil)}
    CRYPTO_gcm128_tag := ERR_CRYPTO_gcm128_tag;
    {$ifend}
    {$if declared(CRYPTO_gcm128_tag_introduced)}
    if LibVersion < CRYPTO_gcm128_tag_introduced then
    begin
      {$if declared(FC_CRYPTO_gcm128_tag)}
      CRYPTO_gcm128_tag := FC_CRYPTO_gcm128_tag;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_gcm128_tag_removed)}
    if CRYPTO_gcm128_tag_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_gcm128_tag)}
      CRYPTO_gcm128_tag := _CRYPTO_gcm128_tag;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_gcm128_tag_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_gcm128_tag');
    {$ifend}
  end;
  
  CRYPTO_gcm128_release := LoadLibFunction(ADllHandle, CRYPTO_gcm128_release_procname);
  FuncLoadError := not assigned(CRYPTO_gcm128_release);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_gcm128_release_allownil)}
    CRYPTO_gcm128_release := ERR_CRYPTO_gcm128_release;
    {$ifend}
    {$if declared(CRYPTO_gcm128_release_introduced)}
    if LibVersion < CRYPTO_gcm128_release_introduced then
    begin
      {$if declared(FC_CRYPTO_gcm128_release)}
      CRYPTO_gcm128_release := FC_CRYPTO_gcm128_release;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_gcm128_release_removed)}
    if CRYPTO_gcm128_release_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_gcm128_release)}
      CRYPTO_gcm128_release := _CRYPTO_gcm128_release;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_gcm128_release_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_gcm128_release');
    {$ifend}
  end;
  
  CRYPTO_ccm128_init := LoadLibFunction(ADllHandle, CRYPTO_ccm128_init_procname);
  FuncLoadError := not assigned(CRYPTO_ccm128_init);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_ccm128_init_allownil)}
    CRYPTO_ccm128_init := ERR_CRYPTO_ccm128_init;
    {$ifend}
    {$if declared(CRYPTO_ccm128_init_introduced)}
    if LibVersion < CRYPTO_ccm128_init_introduced then
    begin
      {$if declared(FC_CRYPTO_ccm128_init)}
      CRYPTO_ccm128_init := FC_CRYPTO_ccm128_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_ccm128_init_removed)}
    if CRYPTO_ccm128_init_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_ccm128_init)}
      CRYPTO_ccm128_init := _CRYPTO_ccm128_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_ccm128_init_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_ccm128_init');
    {$ifend}
  end;
  
  CRYPTO_ccm128_setiv := LoadLibFunction(ADllHandle, CRYPTO_ccm128_setiv_procname);
  FuncLoadError := not assigned(CRYPTO_ccm128_setiv);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_ccm128_setiv_allownil)}
    CRYPTO_ccm128_setiv := ERR_CRYPTO_ccm128_setiv;
    {$ifend}
    {$if declared(CRYPTO_ccm128_setiv_introduced)}
    if LibVersion < CRYPTO_ccm128_setiv_introduced then
    begin
      {$if declared(FC_CRYPTO_ccm128_setiv)}
      CRYPTO_ccm128_setiv := FC_CRYPTO_ccm128_setiv;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_ccm128_setiv_removed)}
    if CRYPTO_ccm128_setiv_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_ccm128_setiv)}
      CRYPTO_ccm128_setiv := _CRYPTO_ccm128_setiv;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_ccm128_setiv_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_ccm128_setiv');
    {$ifend}
  end;
  
  CRYPTO_ccm128_aad := LoadLibFunction(ADllHandle, CRYPTO_ccm128_aad_procname);
  FuncLoadError := not assigned(CRYPTO_ccm128_aad);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_ccm128_aad_allownil)}
    CRYPTO_ccm128_aad := ERR_CRYPTO_ccm128_aad;
    {$ifend}
    {$if declared(CRYPTO_ccm128_aad_introduced)}
    if LibVersion < CRYPTO_ccm128_aad_introduced then
    begin
      {$if declared(FC_CRYPTO_ccm128_aad)}
      CRYPTO_ccm128_aad := FC_CRYPTO_ccm128_aad;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_ccm128_aad_removed)}
    if CRYPTO_ccm128_aad_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_ccm128_aad)}
      CRYPTO_ccm128_aad := _CRYPTO_ccm128_aad;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_ccm128_aad_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_ccm128_aad');
    {$ifend}
  end;
  
  CRYPTO_ccm128_encrypt := LoadLibFunction(ADllHandle, CRYPTO_ccm128_encrypt_procname);
  FuncLoadError := not assigned(CRYPTO_ccm128_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_ccm128_encrypt_allownil)}
    CRYPTO_ccm128_encrypt := ERR_CRYPTO_ccm128_encrypt;
    {$ifend}
    {$if declared(CRYPTO_ccm128_encrypt_introduced)}
    if LibVersion < CRYPTO_ccm128_encrypt_introduced then
    begin
      {$if declared(FC_CRYPTO_ccm128_encrypt)}
      CRYPTO_ccm128_encrypt := FC_CRYPTO_ccm128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_ccm128_encrypt_removed)}
    if CRYPTO_ccm128_encrypt_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_ccm128_encrypt)}
      CRYPTO_ccm128_encrypt := _CRYPTO_ccm128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_ccm128_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_ccm128_encrypt');
    {$ifend}
  end;
  
  CRYPTO_ccm128_decrypt := LoadLibFunction(ADllHandle, CRYPTO_ccm128_decrypt_procname);
  FuncLoadError := not assigned(CRYPTO_ccm128_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_ccm128_decrypt_allownil)}
    CRYPTO_ccm128_decrypt := ERR_CRYPTO_ccm128_decrypt;
    {$ifend}
    {$if declared(CRYPTO_ccm128_decrypt_introduced)}
    if LibVersion < CRYPTO_ccm128_decrypt_introduced then
    begin
      {$if declared(FC_CRYPTO_ccm128_decrypt)}
      CRYPTO_ccm128_decrypt := FC_CRYPTO_ccm128_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_ccm128_decrypt_removed)}
    if CRYPTO_ccm128_decrypt_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_ccm128_decrypt)}
      CRYPTO_ccm128_decrypt := _CRYPTO_ccm128_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_ccm128_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_ccm128_decrypt');
    {$ifend}
  end;
  
  CRYPTO_ccm128_encrypt_ccm64 := LoadLibFunction(ADllHandle, CRYPTO_ccm128_encrypt_ccm64_procname);
  FuncLoadError := not assigned(CRYPTO_ccm128_encrypt_ccm64);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_ccm128_encrypt_ccm64_allownil)}
    CRYPTO_ccm128_encrypt_ccm64 := ERR_CRYPTO_ccm128_encrypt_ccm64;
    {$ifend}
    {$if declared(CRYPTO_ccm128_encrypt_ccm64_introduced)}
    if LibVersion < CRYPTO_ccm128_encrypt_ccm64_introduced then
    begin
      {$if declared(FC_CRYPTO_ccm128_encrypt_ccm64)}
      CRYPTO_ccm128_encrypt_ccm64 := FC_CRYPTO_ccm128_encrypt_ccm64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_ccm128_encrypt_ccm64_removed)}
    if CRYPTO_ccm128_encrypt_ccm64_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_ccm128_encrypt_ccm64)}
      CRYPTO_ccm128_encrypt_ccm64 := _CRYPTO_ccm128_encrypt_ccm64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_ccm128_encrypt_ccm64_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_ccm128_encrypt_ccm64');
    {$ifend}
  end;
  
  CRYPTO_ccm128_decrypt_ccm64 := LoadLibFunction(ADllHandle, CRYPTO_ccm128_decrypt_ccm64_procname);
  FuncLoadError := not assigned(CRYPTO_ccm128_decrypt_ccm64);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_ccm128_decrypt_ccm64_allownil)}
    CRYPTO_ccm128_decrypt_ccm64 := ERR_CRYPTO_ccm128_decrypt_ccm64;
    {$ifend}
    {$if declared(CRYPTO_ccm128_decrypt_ccm64_introduced)}
    if LibVersion < CRYPTO_ccm128_decrypt_ccm64_introduced then
    begin
      {$if declared(FC_CRYPTO_ccm128_decrypt_ccm64)}
      CRYPTO_ccm128_decrypt_ccm64 := FC_CRYPTO_ccm128_decrypt_ccm64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_ccm128_decrypt_ccm64_removed)}
    if CRYPTO_ccm128_decrypt_ccm64_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_ccm128_decrypt_ccm64)}
      CRYPTO_ccm128_decrypt_ccm64 := _CRYPTO_ccm128_decrypt_ccm64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_ccm128_decrypt_ccm64_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_ccm128_decrypt_ccm64');
    {$ifend}
  end;
  
  CRYPTO_ccm128_tag := LoadLibFunction(ADllHandle, CRYPTO_ccm128_tag_procname);
  FuncLoadError := not assigned(CRYPTO_ccm128_tag);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_ccm128_tag_allownil)}
    CRYPTO_ccm128_tag := ERR_CRYPTO_ccm128_tag;
    {$ifend}
    {$if declared(CRYPTO_ccm128_tag_introduced)}
    if LibVersion < CRYPTO_ccm128_tag_introduced then
    begin
      {$if declared(FC_CRYPTO_ccm128_tag)}
      CRYPTO_ccm128_tag := FC_CRYPTO_ccm128_tag;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_ccm128_tag_removed)}
    if CRYPTO_ccm128_tag_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_ccm128_tag)}
      CRYPTO_ccm128_tag := _CRYPTO_ccm128_tag;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_ccm128_tag_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_ccm128_tag');
    {$ifend}
  end;
  
  CRYPTO_xts128_encrypt := LoadLibFunction(ADllHandle, CRYPTO_xts128_encrypt_procname);
  FuncLoadError := not assigned(CRYPTO_xts128_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_xts128_encrypt_allownil)}
    CRYPTO_xts128_encrypt := ERR_CRYPTO_xts128_encrypt;
    {$ifend}
    {$if declared(CRYPTO_xts128_encrypt_introduced)}
    if LibVersion < CRYPTO_xts128_encrypt_introduced then
    begin
      {$if declared(FC_CRYPTO_xts128_encrypt)}
      CRYPTO_xts128_encrypt := FC_CRYPTO_xts128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_xts128_encrypt_removed)}
    if CRYPTO_xts128_encrypt_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_xts128_encrypt)}
      CRYPTO_xts128_encrypt := _CRYPTO_xts128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_xts128_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_xts128_encrypt');
    {$ifend}
  end;
  
  CRYPTO_128_wrap := LoadLibFunction(ADllHandle, CRYPTO_128_wrap_procname);
  FuncLoadError := not assigned(CRYPTO_128_wrap);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_128_wrap_allownil)}
    CRYPTO_128_wrap := ERR_CRYPTO_128_wrap;
    {$ifend}
    {$if declared(CRYPTO_128_wrap_introduced)}
    if LibVersion < CRYPTO_128_wrap_introduced then
    begin
      {$if declared(FC_CRYPTO_128_wrap)}
      CRYPTO_128_wrap := FC_CRYPTO_128_wrap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_128_wrap_removed)}
    if CRYPTO_128_wrap_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_128_wrap)}
      CRYPTO_128_wrap := _CRYPTO_128_wrap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_128_wrap_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_128_wrap');
    {$ifend}
  end;
  
  CRYPTO_128_unwrap := LoadLibFunction(ADllHandle, CRYPTO_128_unwrap_procname);
  FuncLoadError := not assigned(CRYPTO_128_unwrap);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_128_unwrap_allownil)}
    CRYPTO_128_unwrap := ERR_CRYPTO_128_unwrap;
    {$ifend}
    {$if declared(CRYPTO_128_unwrap_introduced)}
    if LibVersion < CRYPTO_128_unwrap_introduced then
    begin
      {$if declared(FC_CRYPTO_128_unwrap)}
      CRYPTO_128_unwrap := FC_CRYPTO_128_unwrap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_128_unwrap_removed)}
    if CRYPTO_128_unwrap_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_128_unwrap)}
      CRYPTO_128_unwrap := _CRYPTO_128_unwrap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_128_unwrap_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_128_unwrap');
    {$ifend}
  end;
  
  CRYPTO_128_wrap_pad := LoadLibFunction(ADllHandle, CRYPTO_128_wrap_pad_procname);
  FuncLoadError := not assigned(CRYPTO_128_wrap_pad);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_128_wrap_pad_allownil)}
    CRYPTO_128_wrap_pad := ERR_CRYPTO_128_wrap_pad;
    {$ifend}
    {$if declared(CRYPTO_128_wrap_pad_introduced)}
    if LibVersion < CRYPTO_128_wrap_pad_introduced then
    begin
      {$if declared(FC_CRYPTO_128_wrap_pad)}
      CRYPTO_128_wrap_pad := FC_CRYPTO_128_wrap_pad;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_128_wrap_pad_removed)}
    if CRYPTO_128_wrap_pad_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_128_wrap_pad)}
      CRYPTO_128_wrap_pad := _CRYPTO_128_wrap_pad;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_128_wrap_pad_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_128_wrap_pad');
    {$ifend}
  end;
  
  CRYPTO_128_unwrap_pad := LoadLibFunction(ADllHandle, CRYPTO_128_unwrap_pad_procname);
  FuncLoadError := not assigned(CRYPTO_128_unwrap_pad);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_128_unwrap_pad_allownil)}
    CRYPTO_128_unwrap_pad := ERR_CRYPTO_128_unwrap_pad;
    {$ifend}
    {$if declared(CRYPTO_128_unwrap_pad_introduced)}
    if LibVersion < CRYPTO_128_unwrap_pad_introduced then
    begin
      {$if declared(FC_CRYPTO_128_unwrap_pad)}
      CRYPTO_128_unwrap_pad := FC_CRYPTO_128_unwrap_pad;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_128_unwrap_pad_removed)}
    if CRYPTO_128_unwrap_pad_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_128_unwrap_pad)}
      CRYPTO_128_unwrap_pad := _CRYPTO_128_unwrap_pad;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_128_unwrap_pad_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_128_unwrap_pad');
    {$ifend}
  end;
  
  CRYPTO_ocb128_new := LoadLibFunction(ADllHandle, CRYPTO_ocb128_new_procname);
  FuncLoadError := not assigned(CRYPTO_ocb128_new);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_ocb128_new_allownil)}
    CRYPTO_ocb128_new := ERR_CRYPTO_ocb128_new;
    {$ifend}
    {$if declared(CRYPTO_ocb128_new_introduced)}
    if LibVersion < CRYPTO_ocb128_new_introduced then
    begin
      {$if declared(FC_CRYPTO_ocb128_new)}
      CRYPTO_ocb128_new := FC_CRYPTO_ocb128_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_ocb128_new_removed)}
    if CRYPTO_ocb128_new_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_ocb128_new)}
      CRYPTO_ocb128_new := _CRYPTO_ocb128_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_ocb128_new_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_ocb128_new');
    {$ifend}
  end;
  
  CRYPTO_ocb128_init := LoadLibFunction(ADllHandle, CRYPTO_ocb128_init_procname);
  FuncLoadError := not assigned(CRYPTO_ocb128_init);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_ocb128_init_allownil)}
    CRYPTO_ocb128_init := ERR_CRYPTO_ocb128_init;
    {$ifend}
    {$if declared(CRYPTO_ocb128_init_introduced)}
    if LibVersion < CRYPTO_ocb128_init_introduced then
    begin
      {$if declared(FC_CRYPTO_ocb128_init)}
      CRYPTO_ocb128_init := FC_CRYPTO_ocb128_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_ocb128_init_removed)}
    if CRYPTO_ocb128_init_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_ocb128_init)}
      CRYPTO_ocb128_init := _CRYPTO_ocb128_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_ocb128_init_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_ocb128_init');
    {$ifend}
  end;
  
  CRYPTO_ocb128_copy_ctx := LoadLibFunction(ADllHandle, CRYPTO_ocb128_copy_ctx_procname);
  FuncLoadError := not assigned(CRYPTO_ocb128_copy_ctx);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_ocb128_copy_ctx_allownil)}
    CRYPTO_ocb128_copy_ctx := ERR_CRYPTO_ocb128_copy_ctx;
    {$ifend}
    {$if declared(CRYPTO_ocb128_copy_ctx_introduced)}
    if LibVersion < CRYPTO_ocb128_copy_ctx_introduced then
    begin
      {$if declared(FC_CRYPTO_ocb128_copy_ctx)}
      CRYPTO_ocb128_copy_ctx := FC_CRYPTO_ocb128_copy_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_ocb128_copy_ctx_removed)}
    if CRYPTO_ocb128_copy_ctx_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_ocb128_copy_ctx)}
      CRYPTO_ocb128_copy_ctx := _CRYPTO_ocb128_copy_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_ocb128_copy_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_ocb128_copy_ctx');
    {$ifend}
  end;
  
  CRYPTO_ocb128_setiv := LoadLibFunction(ADllHandle, CRYPTO_ocb128_setiv_procname);
  FuncLoadError := not assigned(CRYPTO_ocb128_setiv);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_ocb128_setiv_allownil)}
    CRYPTO_ocb128_setiv := ERR_CRYPTO_ocb128_setiv;
    {$ifend}
    {$if declared(CRYPTO_ocb128_setiv_introduced)}
    if LibVersion < CRYPTO_ocb128_setiv_introduced then
    begin
      {$if declared(FC_CRYPTO_ocb128_setiv)}
      CRYPTO_ocb128_setiv := FC_CRYPTO_ocb128_setiv;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_ocb128_setiv_removed)}
    if CRYPTO_ocb128_setiv_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_ocb128_setiv)}
      CRYPTO_ocb128_setiv := _CRYPTO_ocb128_setiv;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_ocb128_setiv_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_ocb128_setiv');
    {$ifend}
  end;
  
  CRYPTO_ocb128_aad := LoadLibFunction(ADllHandle, CRYPTO_ocb128_aad_procname);
  FuncLoadError := not assigned(CRYPTO_ocb128_aad);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_ocb128_aad_allownil)}
    CRYPTO_ocb128_aad := ERR_CRYPTO_ocb128_aad;
    {$ifend}
    {$if declared(CRYPTO_ocb128_aad_introduced)}
    if LibVersion < CRYPTO_ocb128_aad_introduced then
    begin
      {$if declared(FC_CRYPTO_ocb128_aad)}
      CRYPTO_ocb128_aad := FC_CRYPTO_ocb128_aad;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_ocb128_aad_removed)}
    if CRYPTO_ocb128_aad_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_ocb128_aad)}
      CRYPTO_ocb128_aad := _CRYPTO_ocb128_aad;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_ocb128_aad_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_ocb128_aad');
    {$ifend}
  end;
  
  CRYPTO_ocb128_encrypt := LoadLibFunction(ADllHandle, CRYPTO_ocb128_encrypt_procname);
  FuncLoadError := not assigned(CRYPTO_ocb128_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_ocb128_encrypt_allownil)}
    CRYPTO_ocb128_encrypt := ERR_CRYPTO_ocb128_encrypt;
    {$ifend}
    {$if declared(CRYPTO_ocb128_encrypt_introduced)}
    if LibVersion < CRYPTO_ocb128_encrypt_introduced then
    begin
      {$if declared(FC_CRYPTO_ocb128_encrypt)}
      CRYPTO_ocb128_encrypt := FC_CRYPTO_ocb128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_ocb128_encrypt_removed)}
    if CRYPTO_ocb128_encrypt_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_ocb128_encrypt)}
      CRYPTO_ocb128_encrypt := _CRYPTO_ocb128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_ocb128_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_ocb128_encrypt');
    {$ifend}
  end;
  
  CRYPTO_ocb128_decrypt := LoadLibFunction(ADllHandle, CRYPTO_ocb128_decrypt_procname);
  FuncLoadError := not assigned(CRYPTO_ocb128_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_ocb128_decrypt_allownil)}
    CRYPTO_ocb128_decrypt := ERR_CRYPTO_ocb128_decrypt;
    {$ifend}
    {$if declared(CRYPTO_ocb128_decrypt_introduced)}
    if LibVersion < CRYPTO_ocb128_decrypt_introduced then
    begin
      {$if declared(FC_CRYPTO_ocb128_decrypt)}
      CRYPTO_ocb128_decrypt := FC_CRYPTO_ocb128_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_ocb128_decrypt_removed)}
    if CRYPTO_ocb128_decrypt_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_ocb128_decrypt)}
      CRYPTO_ocb128_decrypt := _CRYPTO_ocb128_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_ocb128_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_ocb128_decrypt');
    {$ifend}
  end;
  
  CRYPTO_ocb128_finish := LoadLibFunction(ADllHandle, CRYPTO_ocb128_finish_procname);
  FuncLoadError := not assigned(CRYPTO_ocb128_finish);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_ocb128_finish_allownil)}
    CRYPTO_ocb128_finish := ERR_CRYPTO_ocb128_finish;
    {$ifend}
    {$if declared(CRYPTO_ocb128_finish_introduced)}
    if LibVersion < CRYPTO_ocb128_finish_introduced then
    begin
      {$if declared(FC_CRYPTO_ocb128_finish)}
      CRYPTO_ocb128_finish := FC_CRYPTO_ocb128_finish;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_ocb128_finish_removed)}
    if CRYPTO_ocb128_finish_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_ocb128_finish)}
      CRYPTO_ocb128_finish := _CRYPTO_ocb128_finish;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_ocb128_finish_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_ocb128_finish');
    {$ifend}
  end;
  
  CRYPTO_ocb128_tag := LoadLibFunction(ADllHandle, CRYPTO_ocb128_tag_procname);
  FuncLoadError := not assigned(CRYPTO_ocb128_tag);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_ocb128_tag_allownil)}
    CRYPTO_ocb128_tag := ERR_CRYPTO_ocb128_tag;
    {$ifend}
    {$if declared(CRYPTO_ocb128_tag_introduced)}
    if LibVersion < CRYPTO_ocb128_tag_introduced then
    begin
      {$if declared(FC_CRYPTO_ocb128_tag)}
      CRYPTO_ocb128_tag := FC_CRYPTO_ocb128_tag;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_ocb128_tag_removed)}
    if CRYPTO_ocb128_tag_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_ocb128_tag)}
      CRYPTO_ocb128_tag := _CRYPTO_ocb128_tag;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_ocb128_tag_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_ocb128_tag');
    {$ifend}
  end;
  
  CRYPTO_ocb128_cleanup := LoadLibFunction(ADllHandle, CRYPTO_ocb128_cleanup_procname);
  FuncLoadError := not assigned(CRYPTO_ocb128_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_ocb128_cleanup_allownil)}
    CRYPTO_ocb128_cleanup := ERR_CRYPTO_ocb128_cleanup;
    {$ifend}
    {$if declared(CRYPTO_ocb128_cleanup_introduced)}
    if LibVersion < CRYPTO_ocb128_cleanup_introduced then
    begin
      {$if declared(FC_CRYPTO_ocb128_cleanup)}
      CRYPTO_ocb128_cleanup := FC_CRYPTO_ocb128_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_ocb128_cleanup_removed)}
    if CRYPTO_ocb128_cleanup_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_ocb128_cleanup)}
      CRYPTO_ocb128_cleanup := _CRYPTO_ocb128_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_ocb128_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_ocb128_cleanup');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  CRYPTO_cbc128_encrypt := nil;
  CRYPTO_cbc128_decrypt := nil;
  CRYPTO_ctr128_encrypt := nil;
  CRYPTO_ctr128_encrypt_ctr32 := nil;
  CRYPTO_ofb128_encrypt := nil;
  CRYPTO_cfb128_encrypt := nil;
  CRYPTO_cfb128_8_encrypt := nil;
  CRYPTO_cfb128_1_encrypt := nil;
  CRYPTO_cts128_encrypt_block := nil;
  CRYPTO_cts128_encrypt := nil;
  CRYPTO_cts128_decrypt_block := nil;
  CRYPTO_cts128_decrypt := nil;
  CRYPTO_nistcts128_encrypt_block := nil;
  CRYPTO_nistcts128_encrypt := nil;
  CRYPTO_nistcts128_decrypt_block := nil;
  CRYPTO_nistcts128_decrypt := nil;
  CRYPTO_gcm128_new := nil;
  CRYPTO_gcm128_init := nil;
  CRYPTO_gcm128_setiv := nil;
  CRYPTO_gcm128_aad := nil;
  CRYPTO_gcm128_encrypt := nil;
  CRYPTO_gcm128_decrypt := nil;
  CRYPTO_gcm128_encrypt_ctr32 := nil;
  CRYPTO_gcm128_decrypt_ctr32 := nil;
  CRYPTO_gcm128_finish := nil;
  CRYPTO_gcm128_tag := nil;
  CRYPTO_gcm128_release := nil;
  CRYPTO_ccm128_init := nil;
  CRYPTO_ccm128_setiv := nil;
  CRYPTO_ccm128_aad := nil;
  CRYPTO_ccm128_encrypt := nil;
  CRYPTO_ccm128_decrypt := nil;
  CRYPTO_ccm128_encrypt_ccm64 := nil;
  CRYPTO_ccm128_decrypt_ccm64 := nil;
  CRYPTO_ccm128_tag := nil;
  CRYPTO_xts128_encrypt := nil;
  CRYPTO_128_wrap := nil;
  CRYPTO_128_unwrap := nil;
  CRYPTO_128_wrap_pad := nil;
  CRYPTO_128_unwrap_pad := nil;
  CRYPTO_ocb128_new := nil;
  CRYPTO_ocb128_init := nil;
  CRYPTO_ocb128_copy_ctx := nil;
  CRYPTO_ocb128_setiv := nil;
  CRYPTO_ocb128_aad := nil;
  CRYPTO_ocb128_encrypt := nil;
  CRYPTO_ocb128_decrypt := nil;
  CRYPTO_ocb128_finish := nil;
  CRYPTO_ocb128_tag := nil;
  CRYPTO_ocb128_cleanup := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.