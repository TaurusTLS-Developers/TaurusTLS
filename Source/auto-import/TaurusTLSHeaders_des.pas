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

unit TaurusTLSHeaders_des;

interface

uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_core;

// =============================================================================
// TYPE DECLARATIONS
// =============================================================================
type
  PDES_LONG = ^TDES_LONG;
  TDES_LONG = TIdC_UINT;
  {$EXTERNALSYM PDES_LONG}

  PDES_cblock = ^TDES_cblock;
  TDES_cblock = PIdAnsiChar;
  {$EXTERNALSYM PDES_cblock}

  Pconst_DES_cblock = ^Tconst_DES_cblock;
  Tconst_DES_cblock = PIdAnsiChar;
  {$EXTERNALSYM Pconst_DES_cblock}

  PDES_ks = ^TDES_ks;
  TDES_ks = record end;
  {$EXTERNALSYM PDES_ks}

  Punion (unnamed at /home/sasha/dev/openssl/include/openssl/des.h:43:5) = ^Tunion (unnamed at /home/sasha/dev/openssl/include/openssl/des.h:43:5);
  {$EXTERNALSYM Punion (unnamed at /home/sasha/dev/openssl/include/openssl/des.h:43:5)}

  PDES_key_schedule = ^TDES_key_schedule;
  TDES_key_schedule = TDES_ks;
  {$EXTERNALSYM PDES_key_schedule}


// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  DES_KEY_SZ = (sizeof(DES_cblock));
  DES_SCHEDULE_SZ = (sizeof(DES_key_schedule));
  DES_ENCRYPT = 1;
  DES_DECRYPT = 0;
  DES_CBC_MODE = 0;
  DES_PCBC_MODE = 1;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  DES_options: function: PIdAnsiChar; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_options}

  DES_ecb3_encrypt: procedure(input: Pconst_DES_cblock; output: PDES_cblock; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_ecb3_encrypt}

  DES_cbc_cksum: function(input: PIdAnsiChar; output: PDES_cblock; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: Pconst_DES_cblock): TDES_LONG; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_cbc_cksum}

  DES_cbc_encrypt: procedure(input: PIdAnsiChar; output: PIdAnsiChar; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_cbc_encrypt}

  DES_ncbc_encrypt: procedure(input: PIdAnsiChar; output: PIdAnsiChar; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_ncbc_encrypt}

  DES_xcbc_encrypt: procedure(input: PIdAnsiChar; output: PIdAnsiChar; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; inw: Pconst_DES_cblock; outw: Pconst_DES_cblock; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_xcbc_encrypt}

  DES_cfb_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; numbits: TIdC_INT; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_cfb_encrypt}

  DES_ecb_encrypt: procedure(input: Pconst_DES_cblock; output: PDES_cblock; ks: PDES_key_schedule; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_ecb_encrypt}

  DES_encrypt1: procedure(data: PDES_LONG; ks: PDES_key_schedule; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_encrypt1}

  DES_encrypt2: procedure(data: PDES_LONG; ks: PDES_key_schedule; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_encrypt2}

  DES_encrypt3: procedure(data: PDES_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_encrypt3}

  DES_decrypt3: procedure(data: PDES_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_decrypt3}

  DES_ede3_cbc_encrypt: procedure(input: PIdAnsiChar; output: PIdAnsiChar; length: TIdC_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_ede3_cbc_encrypt}

  DES_ede3_cfb64_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; num: PIdC_INT; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_ede3_cfb64_encrypt}

  DES_ede3_cfb_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; numbits: TIdC_INT; length: TIdC_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_ede3_cfb_encrypt}

  DES_ede3_ofb64_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; num: PIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_ede3_ofb64_encrypt}

  DES_fcrypt: function(buf: PIdAnsiChar; salt: PIdAnsiChar; ret: PIdAnsiChar): PIdAnsiChar; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_fcrypt}

  DES_crypt: function(buf: PIdAnsiChar; salt: PIdAnsiChar): PIdAnsiChar; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_crypt}

  DES_ofb_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; numbits: TIdC_INT; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_ofb_encrypt}

  DES_pcbc_encrypt: procedure(input: PIdAnsiChar; output: PIdAnsiChar; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_pcbc_encrypt}

  DES_quad_cksum: function(input: PIdAnsiChar; output: PDES_cblock; length: TIdC_LONG; out_count: TIdC_INT; seed: PDES_cblock): TDES_LONG; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_quad_cksum}

  DES_random_key: function(ret: PDES_cblock): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_random_key}

  DES_set_odd_parity: procedure(key: PDES_cblock); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_set_odd_parity}

  DES_check_key_parity: function(key: Pconst_DES_cblock): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_check_key_parity}

  DES_is_weak_key: function(key: Pconst_DES_cblock): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_is_weak_key}

  DES_set_key: function(key: Pconst_DES_cblock; schedule: PDES_key_schedule): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_set_key}

  DES_key_sched: function(key: Pconst_DES_cblock; schedule: PDES_key_schedule): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_key_sched}

  DES_set_key_checked: function(key: Pconst_DES_cblock; schedule: PDES_key_schedule): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_set_key_checked}

  DES_set_key_unchecked: procedure(key: Pconst_DES_cblock; schedule: PDES_key_schedule); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_set_key_unchecked}

  DES_string_to_key: procedure(str: PIdAnsiChar; key: PDES_cblock); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_string_to_key}

  DES_string_to_2keys: procedure(str: PIdAnsiChar; key1: PDES_cblock; key2: PDES_cblock); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_string_to_2keys}

  DES_cfb64_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; num: PIdC_INT; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_cfb64_encrypt}

  DES_ofb64_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; num: PIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DES_ofb64_encrypt}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function DES_options: PIdAnsiChar; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DES_ecb3_encrypt(input: Pconst_DES_cblock; output: PDES_cblock; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
function DES_cbc_cksum(input: PIdAnsiChar; output: PDES_cblock; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: Pconst_DES_cblock): TDES_LONG; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DES_cbc_encrypt(input: PIdAnsiChar; output: PIdAnsiChar; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DES_ncbc_encrypt(input: PIdAnsiChar; output: PIdAnsiChar; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DES_xcbc_encrypt(input: PIdAnsiChar; output: PIdAnsiChar; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; inw: Pconst_DES_cblock; outw: Pconst_DES_cblock; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DES_cfb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; numbits: TIdC_INT; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DES_ecb_encrypt(input: Pconst_DES_cblock; output: PDES_cblock; ks: PDES_key_schedule; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DES_encrypt1(data: PDES_LONG; ks: PDES_key_schedule; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DES_encrypt2(data: PDES_LONG; ks: PDES_key_schedule; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DES_encrypt3(data: PDES_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DES_decrypt3(data: PDES_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DES_ede3_cbc_encrypt(input: PIdAnsiChar; output: PIdAnsiChar; length: TIdC_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DES_ede3_cfb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; num: PIdC_INT; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DES_ede3_cfb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; numbits: TIdC_INT; length: TIdC_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DES_ede3_ofb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; num: PIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
function DES_fcrypt(buf: PIdAnsiChar; salt: PIdAnsiChar; ret: PIdAnsiChar): PIdAnsiChar; cdecl; deprecated 'In OpenSSL 3_0_0';
function DES_crypt(buf: PIdAnsiChar; salt: PIdAnsiChar): PIdAnsiChar; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DES_ofb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; numbits: TIdC_INT; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DES_pcbc_encrypt(input: PIdAnsiChar; output: PIdAnsiChar; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
function DES_quad_cksum(input: PIdAnsiChar; output: PDES_cblock; length: TIdC_LONG; out_count: TIdC_INT; seed: PDES_cblock): TDES_LONG; cdecl; deprecated 'In OpenSSL 3_0_0';
function DES_random_key(ret: PDES_cblock): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DES_set_odd_parity(key: PDES_cblock); cdecl; deprecated 'In OpenSSL 3_0_0';
function DES_check_key_parity(key: Pconst_DES_cblock): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DES_is_weak_key(key: Pconst_DES_cblock): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DES_set_key(key: Pconst_DES_cblock; schedule: PDES_key_schedule): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DES_key_sched(key: Pconst_DES_cblock; schedule: PDES_key_schedule): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DES_set_key_checked(key: Pconst_DES_cblock; schedule: PDES_key_schedule): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DES_set_key_unchecked(key: Pconst_DES_cblock; schedule: PDES_key_schedule); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DES_string_to_key(str: PIdAnsiChar; key: PDES_cblock); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DES_string_to_2keys(str: PIdAnsiChar; key1: PDES_cblock; key2: PDES_cblock); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DES_cfb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; num: PIdC_INT; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DES_ofb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; num: PIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// INLINE OR MACRO ROUTINES
// =============================================================================

function DES_ecb2_encrypt(i: Pointer; o: Pointer; k1: Pointer; k2: Pointer; e: Pointer): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0';
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function DES_ede2_cbc_encrypt(i: Pointer; o: Pointer; l: Pointer; k1: Pointer; k2: Pointer; iv: Pointer; e: Pointer): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0';
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function DES_ede2_cfb64_encrypt(i: Pointer; o: Pointer; l: Pointer; k1: Pointer; k2: Pointer; iv: Pointer; n: Pointer; e: Pointer): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0';
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function DES_ede2_ofb64_encrypt(i: Pointer; o: Pointer; l: Pointer; k1: Pointer; k2: Pointer; iv: Pointer; n: Pointer): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0';
  {$IFDEF USE_INLINE}inline; {$ENDIF}

procedure DES_fixup_key_parity(key: PDES_cblock); cdecl; deprecated 'In OpenSSL 3_0_0';
  {$IFDEF USE_INLINE}inline; {$ENDIF}


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

function DES_options: PIdAnsiChar; cdecl external CLibCrypto name 'DES_options';
procedure DES_ecb3_encrypt(input: Pconst_DES_cblock; output: PDES_cblock; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; enc: TIdC_INT); cdecl external CLibCrypto name 'DES_ecb3_encrypt';
function DES_cbc_cksum(input: PIdAnsiChar; output: PDES_cblock; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: Pconst_DES_cblock): TDES_LONG; cdecl external CLibCrypto name 'DES_cbc_cksum';
procedure DES_cbc_encrypt(input: PIdAnsiChar; output: PIdAnsiChar; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl external CLibCrypto name 'DES_cbc_encrypt';
procedure DES_ncbc_encrypt(input: PIdAnsiChar; output: PIdAnsiChar; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl external CLibCrypto name 'DES_ncbc_encrypt';
procedure DES_xcbc_encrypt(input: PIdAnsiChar; output: PIdAnsiChar; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; inw: Pconst_DES_cblock; outw: Pconst_DES_cblock; enc: TIdC_INT); cdecl external CLibCrypto name 'DES_xcbc_encrypt';
procedure DES_cfb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; numbits: TIdC_INT; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl external CLibCrypto name 'DES_cfb_encrypt';
procedure DES_ecb_encrypt(input: Pconst_DES_cblock; output: PDES_cblock; ks: PDES_key_schedule; enc: TIdC_INT); cdecl external CLibCrypto name 'DES_ecb_encrypt';
procedure DES_encrypt1(data: PDES_LONG; ks: PDES_key_schedule; enc: TIdC_INT); cdecl external CLibCrypto name 'DES_encrypt1';
procedure DES_encrypt2(data: PDES_LONG; ks: PDES_key_schedule; enc: TIdC_INT); cdecl external CLibCrypto name 'DES_encrypt2';
procedure DES_encrypt3(data: PDES_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule); cdecl external CLibCrypto name 'DES_encrypt3';
procedure DES_decrypt3(data: PDES_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule); cdecl external CLibCrypto name 'DES_decrypt3';
procedure DES_ede3_cbc_encrypt(input: PIdAnsiChar; output: PIdAnsiChar; length: TIdC_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl external CLibCrypto name 'DES_ede3_cbc_encrypt';
procedure DES_ede3_cfb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; num: PIdC_INT; enc: TIdC_INT); cdecl external CLibCrypto name 'DES_ede3_cfb64_encrypt';
procedure DES_ede3_cfb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; numbits: TIdC_INT; length: TIdC_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl external CLibCrypto name 'DES_ede3_cfb_encrypt';
procedure DES_ede3_ofb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; num: PIdC_INT); cdecl external CLibCrypto name 'DES_ede3_ofb64_encrypt';
function DES_fcrypt(buf: PIdAnsiChar; salt: PIdAnsiChar; ret: PIdAnsiChar): PIdAnsiChar; cdecl external CLibCrypto name 'DES_fcrypt';
function DES_crypt(buf: PIdAnsiChar; salt: PIdAnsiChar): PIdAnsiChar; cdecl external CLibCrypto name 'DES_crypt';
procedure DES_ofb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; numbits: TIdC_INT; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock); cdecl external CLibCrypto name 'DES_ofb_encrypt';
procedure DES_pcbc_encrypt(input: PIdAnsiChar; output: PIdAnsiChar; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl external CLibCrypto name 'DES_pcbc_encrypt';
function DES_quad_cksum(input: PIdAnsiChar; output: PDES_cblock; length: TIdC_LONG; out_count: TIdC_INT; seed: PDES_cblock): TDES_LONG; cdecl external CLibCrypto name 'DES_quad_cksum';
function DES_random_key(ret: PDES_cblock): TIdC_INT; cdecl external CLibCrypto name 'DES_random_key';
procedure DES_set_odd_parity(key: PDES_cblock); cdecl external CLibCrypto name 'DES_set_odd_parity';
function DES_check_key_parity(key: Pconst_DES_cblock): TIdC_INT; cdecl external CLibCrypto name 'DES_check_key_parity';
function DES_is_weak_key(key: Pconst_DES_cblock): TIdC_INT; cdecl external CLibCrypto name 'DES_is_weak_key';
function DES_set_key(key: Pconst_DES_cblock; schedule: PDES_key_schedule): TIdC_INT; cdecl external CLibCrypto name 'DES_set_key';
function DES_key_sched(key: Pconst_DES_cblock; schedule: PDES_key_schedule): TIdC_INT; cdecl external CLibCrypto name 'DES_key_sched';
function DES_set_key_checked(key: Pconst_DES_cblock; schedule: PDES_key_schedule): TIdC_INT; cdecl external CLibCrypto name 'DES_set_key_checked';
procedure DES_set_key_unchecked(key: Pconst_DES_cblock; schedule: PDES_key_schedule); cdecl external CLibCrypto name 'DES_set_key_unchecked';
procedure DES_string_to_key(str: PIdAnsiChar; key: PDES_cblock); cdecl external CLibCrypto name 'DES_string_to_key';
procedure DES_string_to_2keys(str: PIdAnsiChar; key1: PDES_cblock; key2: PDES_cblock); cdecl external CLibCrypto name 'DES_string_to_2keys';
procedure DES_cfb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; num: PIdC_INT; enc: TIdC_INT); cdecl external CLibCrypto name 'DES_cfb64_encrypt';
procedure DES_ofb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; num: PIdC_INT); cdecl external CLibCrypto name 'DES_ofb64_encrypt';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  DES_options_procname = 'DES_options';
  DES_options_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_options_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_ecb3_encrypt_procname = 'DES_ecb3_encrypt';
  DES_ecb3_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_ecb3_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_cbc_cksum_procname = 'DES_cbc_cksum';
  DES_cbc_cksum_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_cbc_cksum_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_cbc_encrypt_procname = 'DES_cbc_encrypt';
  DES_cbc_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_cbc_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_ncbc_encrypt_procname = 'DES_ncbc_encrypt';
  DES_ncbc_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_ncbc_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_xcbc_encrypt_procname = 'DES_xcbc_encrypt';
  DES_xcbc_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_xcbc_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_cfb_encrypt_procname = 'DES_cfb_encrypt';
  DES_cfb_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_cfb_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_ecb_encrypt_procname = 'DES_ecb_encrypt';
  DES_ecb_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_ecb_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_encrypt1_procname = 'DES_encrypt1';
  DES_encrypt1_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_encrypt1_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_encrypt2_procname = 'DES_encrypt2';
  DES_encrypt2_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_encrypt2_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_encrypt3_procname = 'DES_encrypt3';
  DES_encrypt3_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_encrypt3_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_decrypt3_procname = 'DES_decrypt3';
  DES_decrypt3_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_decrypt3_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_ede3_cbc_encrypt_procname = 'DES_ede3_cbc_encrypt';
  DES_ede3_cbc_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_ede3_cbc_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_ede3_cfb64_encrypt_procname = 'DES_ede3_cfb64_encrypt';
  DES_ede3_cfb64_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_ede3_cfb64_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_ede3_cfb_encrypt_procname = 'DES_ede3_cfb_encrypt';
  DES_ede3_cfb_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_ede3_cfb_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_ede3_ofb64_encrypt_procname = 'DES_ede3_ofb64_encrypt';
  DES_ede3_ofb64_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_ede3_ofb64_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_fcrypt_procname = 'DES_fcrypt';
  DES_fcrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_fcrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_crypt_procname = 'DES_crypt';
  DES_crypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_crypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_ofb_encrypt_procname = 'DES_ofb_encrypt';
  DES_ofb_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_ofb_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_pcbc_encrypt_procname = 'DES_pcbc_encrypt';
  DES_pcbc_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_pcbc_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_quad_cksum_procname = 'DES_quad_cksum';
  DES_quad_cksum_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_quad_cksum_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_random_key_procname = 'DES_random_key';
  DES_random_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_random_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_set_odd_parity_procname = 'DES_set_odd_parity';
  DES_set_odd_parity_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_set_odd_parity_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_check_key_parity_procname = 'DES_check_key_parity';
  DES_check_key_parity_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_check_key_parity_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_is_weak_key_procname = 'DES_is_weak_key';
  DES_is_weak_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_is_weak_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_set_key_procname = 'DES_set_key';
  DES_set_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_set_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_key_sched_procname = 'DES_key_sched';
  DES_key_sched_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_key_sched_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_set_key_checked_procname = 'DES_set_key_checked';
  DES_set_key_checked_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_set_key_checked_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_set_key_unchecked_procname = 'DES_set_key_unchecked';
  DES_set_key_unchecked_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_set_key_unchecked_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_string_to_key_procname = 'DES_string_to_key';
  DES_string_to_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_string_to_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_string_to_2keys_procname = 'DES_string_to_2keys';
  DES_string_to_2keys_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_string_to_2keys_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_cfb64_encrypt_procname = 'DES_cfb64_encrypt';
  DES_cfb64_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_cfb64_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DES_ofb64_encrypt_procname = 'DES_ofb64_encrypt';
  DES_ofb64_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DES_ofb64_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

// =============================================================================
// INLINE/MACRO IMPLEMENTATIONS
// =============================================================================

function DES_ecb2_encrypt(i: Pointer; o: Pointer; k1: Pointer; k2: Pointer; e: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    DES_ecb2_encrypt(i, o, k1, k2, e) \
    DES_ecb3_encrypt((i), (o), (k1), (k2), (k1), (e))
  }
end;

function DES_ede2_cbc_encrypt(i: Pointer; o: Pointer; l: Pointer; k1: Pointer; k2: Pointer; iv: Pointer; e: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    DES_ede2_cbc_encrypt(i, o, l, k1, k2, iv, e) \
    DES_ede3_cbc_encrypt((i), (o), (l), (k1), (k2), (k1), (iv), (e))
  }
end;

function DES_ede2_cfb64_encrypt(i: Pointer; o: Pointer; l: Pointer; k1: Pointer; k2: Pointer; iv: Pointer; n: Pointer; e: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    DES_ede2_cfb64_encrypt(i, o, l, k1, k2, iv, n, e) \
    DES_ede3_cfb64_encrypt((i), (o), (l), (k1), (k2), (k1), (iv), (n), (e))
  }
end;

function DES_ede2_ofb64_encrypt(i: Pointer; o: Pointer; l: Pointer; k1: Pointer; k2: Pointer; iv: Pointer; n: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    DES_ede2_ofb64_encrypt(i, o, l, k1, k2, iv, n) \
    DES_ede3_ofb64_encrypt((i), (o), (l), (k1), (k2), (k1), (iv), (n))
  }
end;

procedure DES_fixup_key_parity(key: PDES_cblock); cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    DES_fixup_key_parity DES_set_odd_parity
  }
end;

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_DES_options: PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_options_procname);
end;

procedure ERR_DES_ecb3_encrypt(input: Pconst_DES_cblock; output: PDES_cblock; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_ecb3_encrypt_procname);
end;

function ERR_DES_cbc_cksum(input: PIdAnsiChar; output: PDES_cblock; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: Pconst_DES_cblock): TDES_LONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_cbc_cksum_procname);
end;

procedure ERR_DES_cbc_encrypt(input: PIdAnsiChar; output: PIdAnsiChar; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_cbc_encrypt_procname);
end;

procedure ERR_DES_ncbc_encrypt(input: PIdAnsiChar; output: PIdAnsiChar; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_ncbc_encrypt_procname);
end;

procedure ERR_DES_xcbc_encrypt(input: PIdAnsiChar; output: PIdAnsiChar; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; inw: Pconst_DES_cblock; outw: Pconst_DES_cblock; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_xcbc_encrypt_procname);
end;

procedure ERR_DES_cfb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; numbits: TIdC_INT; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_cfb_encrypt_procname);
end;

procedure ERR_DES_ecb_encrypt(input: Pconst_DES_cblock; output: PDES_cblock; ks: PDES_key_schedule; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_ecb_encrypt_procname);
end;

procedure ERR_DES_encrypt1(data: PDES_LONG; ks: PDES_key_schedule; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_encrypt1_procname);
end;

procedure ERR_DES_encrypt2(data: PDES_LONG; ks: PDES_key_schedule; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_encrypt2_procname);
end;

procedure ERR_DES_encrypt3(data: PDES_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_encrypt3_procname);
end;

procedure ERR_DES_decrypt3(data: PDES_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_decrypt3_procname);
end;

procedure ERR_DES_ede3_cbc_encrypt(input: PIdAnsiChar; output: PIdAnsiChar; length: TIdC_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_ede3_cbc_encrypt_procname);
end;

procedure ERR_DES_ede3_cfb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; num: PIdC_INT; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_ede3_cfb64_encrypt_procname);
end;

procedure ERR_DES_ede3_cfb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; numbits: TIdC_INT; length: TIdC_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_ede3_cfb_encrypt_procname);
end;

procedure ERR_DES_ede3_ofb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; num: PIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_ede3_ofb64_encrypt_procname);
end;

function ERR_DES_fcrypt(buf: PIdAnsiChar; salt: PIdAnsiChar; ret: PIdAnsiChar): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_fcrypt_procname);
end;

function ERR_DES_crypt(buf: PIdAnsiChar; salt: PIdAnsiChar): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_crypt_procname);
end;

procedure ERR_DES_ofb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; numbits: TIdC_INT; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_ofb_encrypt_procname);
end;

procedure ERR_DES_pcbc_encrypt(input: PIdAnsiChar; output: PIdAnsiChar; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_pcbc_encrypt_procname);
end;

function ERR_DES_quad_cksum(input: PIdAnsiChar; output: PDES_cblock; length: TIdC_LONG; out_count: TIdC_INT; seed: PDES_cblock): TDES_LONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_quad_cksum_procname);
end;

function ERR_DES_random_key(ret: PDES_cblock): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_random_key_procname);
end;

procedure ERR_DES_set_odd_parity(key: PDES_cblock); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_set_odd_parity_procname);
end;

function ERR_DES_check_key_parity(key: Pconst_DES_cblock): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_check_key_parity_procname);
end;

function ERR_DES_is_weak_key(key: Pconst_DES_cblock): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_is_weak_key_procname);
end;

function ERR_DES_set_key(key: Pconst_DES_cblock; schedule: PDES_key_schedule): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_set_key_procname);
end;

function ERR_DES_key_sched(key: Pconst_DES_cblock; schedule: PDES_key_schedule): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_key_sched_procname);
end;

function ERR_DES_set_key_checked(key: Pconst_DES_cblock; schedule: PDES_key_schedule): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_set_key_checked_procname);
end;

procedure ERR_DES_set_key_unchecked(key: Pconst_DES_cblock; schedule: PDES_key_schedule); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_set_key_unchecked_procname);
end;

procedure ERR_DES_string_to_key(str: PIdAnsiChar; key: PDES_cblock); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_string_to_key_procname);
end;

procedure ERR_DES_string_to_2keys(str: PIdAnsiChar; key1: PDES_cblock; key2: PDES_cblock); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_string_to_2keys_procname);
end;

procedure ERR_DES_cfb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; num: PIdC_INT; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_cfb64_encrypt_procname);
end;

procedure ERR_DES_ofb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; num: PIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_ofb64_encrypt_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  DES_options := LoadLibFunction(ADllHandle, DES_options_procname);
  FuncLoadError := not assigned(DES_options);
  if FuncLoadError then
  begin
    {$if not defined(DES_options_allownil)}
    DES_options := ERR_DES_options;
    {$ifend}
    {$if declared(DES_options_introduced)}
    if LibVersion < DES_options_introduced then
    begin
      {$if declared(FC_DES_options)}
      DES_options := FC_DES_options;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_options_removed)}
    if DES_options_removed <= LibVersion then
    begin
      {$if declared(_DES_options)}
      DES_options := _DES_options;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_options_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_options');
    {$ifend}
  end;
  
  DES_ecb3_encrypt := LoadLibFunction(ADllHandle, DES_ecb3_encrypt_procname);
  FuncLoadError := not assigned(DES_ecb3_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_ecb3_encrypt_allownil)}
    DES_ecb3_encrypt := ERR_DES_ecb3_encrypt;
    {$ifend}
    {$if declared(DES_ecb3_encrypt_introduced)}
    if LibVersion < DES_ecb3_encrypt_introduced then
    begin
      {$if declared(FC_DES_ecb3_encrypt)}
      DES_ecb3_encrypt := FC_DES_ecb3_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_ecb3_encrypt_removed)}
    if DES_ecb3_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_ecb3_encrypt)}
      DES_ecb3_encrypt := _DES_ecb3_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_ecb3_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ecb3_encrypt');
    {$ifend}
  end;
  
  DES_cbc_cksum := LoadLibFunction(ADllHandle, DES_cbc_cksum_procname);
  FuncLoadError := not assigned(DES_cbc_cksum);
  if FuncLoadError then
  begin
    {$if not defined(DES_cbc_cksum_allownil)}
    DES_cbc_cksum := ERR_DES_cbc_cksum;
    {$ifend}
    {$if declared(DES_cbc_cksum_introduced)}
    if LibVersion < DES_cbc_cksum_introduced then
    begin
      {$if declared(FC_DES_cbc_cksum)}
      DES_cbc_cksum := FC_DES_cbc_cksum;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_cbc_cksum_removed)}
    if DES_cbc_cksum_removed <= LibVersion then
    begin
      {$if declared(_DES_cbc_cksum)}
      DES_cbc_cksum := _DES_cbc_cksum;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_cbc_cksum_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_cbc_cksum');
    {$ifend}
  end;
  
  DES_cbc_encrypt := LoadLibFunction(ADllHandle, DES_cbc_encrypt_procname);
  FuncLoadError := not assigned(DES_cbc_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_cbc_encrypt_allownil)}
    DES_cbc_encrypt := ERR_DES_cbc_encrypt;
    {$ifend}
    {$if declared(DES_cbc_encrypt_introduced)}
    if LibVersion < DES_cbc_encrypt_introduced then
    begin
      {$if declared(FC_DES_cbc_encrypt)}
      DES_cbc_encrypt := FC_DES_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_cbc_encrypt_removed)}
    if DES_cbc_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_cbc_encrypt)}
      DES_cbc_encrypt := _DES_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_cbc_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_cbc_encrypt');
    {$ifend}
  end;
  
  DES_ncbc_encrypt := LoadLibFunction(ADllHandle, DES_ncbc_encrypt_procname);
  FuncLoadError := not assigned(DES_ncbc_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_ncbc_encrypt_allownil)}
    DES_ncbc_encrypt := ERR_DES_ncbc_encrypt;
    {$ifend}
    {$if declared(DES_ncbc_encrypt_introduced)}
    if LibVersion < DES_ncbc_encrypt_introduced then
    begin
      {$if declared(FC_DES_ncbc_encrypt)}
      DES_ncbc_encrypt := FC_DES_ncbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_ncbc_encrypt_removed)}
    if DES_ncbc_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_ncbc_encrypt)}
      DES_ncbc_encrypt := _DES_ncbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_ncbc_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ncbc_encrypt');
    {$ifend}
  end;
  
  DES_xcbc_encrypt := LoadLibFunction(ADllHandle, DES_xcbc_encrypt_procname);
  FuncLoadError := not assigned(DES_xcbc_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_xcbc_encrypt_allownil)}
    DES_xcbc_encrypt := ERR_DES_xcbc_encrypt;
    {$ifend}
    {$if declared(DES_xcbc_encrypt_introduced)}
    if LibVersion < DES_xcbc_encrypt_introduced then
    begin
      {$if declared(FC_DES_xcbc_encrypt)}
      DES_xcbc_encrypt := FC_DES_xcbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_xcbc_encrypt_removed)}
    if DES_xcbc_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_xcbc_encrypt)}
      DES_xcbc_encrypt := _DES_xcbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_xcbc_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_xcbc_encrypt');
    {$ifend}
  end;
  
  DES_cfb_encrypt := LoadLibFunction(ADllHandle, DES_cfb_encrypt_procname);
  FuncLoadError := not assigned(DES_cfb_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_cfb_encrypt_allownil)}
    DES_cfb_encrypt := ERR_DES_cfb_encrypt;
    {$ifend}
    {$if declared(DES_cfb_encrypt_introduced)}
    if LibVersion < DES_cfb_encrypt_introduced then
    begin
      {$if declared(FC_DES_cfb_encrypt)}
      DES_cfb_encrypt := FC_DES_cfb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_cfb_encrypt_removed)}
    if DES_cfb_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_cfb_encrypt)}
      DES_cfb_encrypt := _DES_cfb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_cfb_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_cfb_encrypt');
    {$ifend}
  end;
  
  DES_ecb_encrypt := LoadLibFunction(ADllHandle, DES_ecb_encrypt_procname);
  FuncLoadError := not assigned(DES_ecb_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_ecb_encrypt_allownil)}
    DES_ecb_encrypt := ERR_DES_ecb_encrypt;
    {$ifend}
    {$if declared(DES_ecb_encrypt_introduced)}
    if LibVersion < DES_ecb_encrypt_introduced then
    begin
      {$if declared(FC_DES_ecb_encrypt)}
      DES_ecb_encrypt := FC_DES_ecb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_ecb_encrypt_removed)}
    if DES_ecb_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_ecb_encrypt)}
      DES_ecb_encrypt := _DES_ecb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_ecb_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ecb_encrypt');
    {$ifend}
  end;
  
  DES_encrypt1 := LoadLibFunction(ADllHandle, DES_encrypt1_procname);
  FuncLoadError := not assigned(DES_encrypt1);
  if FuncLoadError then
  begin
    {$if not defined(DES_encrypt1_allownil)}
    DES_encrypt1 := ERR_DES_encrypt1;
    {$ifend}
    {$if declared(DES_encrypt1_introduced)}
    if LibVersion < DES_encrypt1_introduced then
    begin
      {$if declared(FC_DES_encrypt1)}
      DES_encrypt1 := FC_DES_encrypt1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_encrypt1_removed)}
    if DES_encrypt1_removed <= LibVersion then
    begin
      {$if declared(_DES_encrypt1)}
      DES_encrypt1 := _DES_encrypt1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_encrypt1_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_encrypt1');
    {$ifend}
  end;
  
  DES_encrypt2 := LoadLibFunction(ADllHandle, DES_encrypt2_procname);
  FuncLoadError := not assigned(DES_encrypt2);
  if FuncLoadError then
  begin
    {$if not defined(DES_encrypt2_allownil)}
    DES_encrypt2 := ERR_DES_encrypt2;
    {$ifend}
    {$if declared(DES_encrypt2_introduced)}
    if LibVersion < DES_encrypt2_introduced then
    begin
      {$if declared(FC_DES_encrypt2)}
      DES_encrypt2 := FC_DES_encrypt2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_encrypt2_removed)}
    if DES_encrypt2_removed <= LibVersion then
    begin
      {$if declared(_DES_encrypt2)}
      DES_encrypt2 := _DES_encrypt2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_encrypt2_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_encrypt2');
    {$ifend}
  end;
  
  DES_encrypt3 := LoadLibFunction(ADllHandle, DES_encrypt3_procname);
  FuncLoadError := not assigned(DES_encrypt3);
  if FuncLoadError then
  begin
    {$if not defined(DES_encrypt3_allownil)}
    DES_encrypt3 := ERR_DES_encrypt3;
    {$ifend}
    {$if declared(DES_encrypt3_introduced)}
    if LibVersion < DES_encrypt3_introduced then
    begin
      {$if declared(FC_DES_encrypt3)}
      DES_encrypt3 := FC_DES_encrypt3;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_encrypt3_removed)}
    if DES_encrypt3_removed <= LibVersion then
    begin
      {$if declared(_DES_encrypt3)}
      DES_encrypt3 := _DES_encrypt3;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_encrypt3_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_encrypt3');
    {$ifend}
  end;
  
  DES_decrypt3 := LoadLibFunction(ADllHandle, DES_decrypt3_procname);
  FuncLoadError := not assigned(DES_decrypt3);
  if FuncLoadError then
  begin
    {$if not defined(DES_decrypt3_allownil)}
    DES_decrypt3 := ERR_DES_decrypt3;
    {$ifend}
    {$if declared(DES_decrypt3_introduced)}
    if LibVersion < DES_decrypt3_introduced then
    begin
      {$if declared(FC_DES_decrypt3)}
      DES_decrypt3 := FC_DES_decrypt3;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_decrypt3_removed)}
    if DES_decrypt3_removed <= LibVersion then
    begin
      {$if declared(_DES_decrypt3)}
      DES_decrypt3 := _DES_decrypt3;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_decrypt3_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_decrypt3');
    {$ifend}
  end;
  
  DES_ede3_cbc_encrypt := LoadLibFunction(ADllHandle, DES_ede3_cbc_encrypt_procname);
  FuncLoadError := not assigned(DES_ede3_cbc_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_ede3_cbc_encrypt_allownil)}
    DES_ede3_cbc_encrypt := ERR_DES_ede3_cbc_encrypt;
    {$ifend}
    {$if declared(DES_ede3_cbc_encrypt_introduced)}
    if LibVersion < DES_ede3_cbc_encrypt_introduced then
    begin
      {$if declared(FC_DES_ede3_cbc_encrypt)}
      DES_ede3_cbc_encrypt := FC_DES_ede3_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_ede3_cbc_encrypt_removed)}
    if DES_ede3_cbc_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_ede3_cbc_encrypt)}
      DES_ede3_cbc_encrypt := _DES_ede3_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_ede3_cbc_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ede3_cbc_encrypt');
    {$ifend}
  end;
  
  DES_ede3_cfb64_encrypt := LoadLibFunction(ADllHandle, DES_ede3_cfb64_encrypt_procname);
  FuncLoadError := not assigned(DES_ede3_cfb64_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_ede3_cfb64_encrypt_allownil)}
    DES_ede3_cfb64_encrypt := ERR_DES_ede3_cfb64_encrypt;
    {$ifend}
    {$if declared(DES_ede3_cfb64_encrypt_introduced)}
    if LibVersion < DES_ede3_cfb64_encrypt_introduced then
    begin
      {$if declared(FC_DES_ede3_cfb64_encrypt)}
      DES_ede3_cfb64_encrypt := FC_DES_ede3_cfb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_ede3_cfb64_encrypt_removed)}
    if DES_ede3_cfb64_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_ede3_cfb64_encrypt)}
      DES_ede3_cfb64_encrypt := _DES_ede3_cfb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_ede3_cfb64_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ede3_cfb64_encrypt');
    {$ifend}
  end;
  
  DES_ede3_cfb_encrypt := LoadLibFunction(ADllHandle, DES_ede3_cfb_encrypt_procname);
  FuncLoadError := not assigned(DES_ede3_cfb_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_ede3_cfb_encrypt_allownil)}
    DES_ede3_cfb_encrypt := ERR_DES_ede3_cfb_encrypt;
    {$ifend}
    {$if declared(DES_ede3_cfb_encrypt_introduced)}
    if LibVersion < DES_ede3_cfb_encrypt_introduced then
    begin
      {$if declared(FC_DES_ede3_cfb_encrypt)}
      DES_ede3_cfb_encrypt := FC_DES_ede3_cfb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_ede3_cfb_encrypt_removed)}
    if DES_ede3_cfb_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_ede3_cfb_encrypt)}
      DES_ede3_cfb_encrypt := _DES_ede3_cfb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_ede3_cfb_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ede3_cfb_encrypt');
    {$ifend}
  end;
  
  DES_ede3_ofb64_encrypt := LoadLibFunction(ADllHandle, DES_ede3_ofb64_encrypt_procname);
  FuncLoadError := not assigned(DES_ede3_ofb64_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_ede3_ofb64_encrypt_allownil)}
    DES_ede3_ofb64_encrypt := ERR_DES_ede3_ofb64_encrypt;
    {$ifend}
    {$if declared(DES_ede3_ofb64_encrypt_introduced)}
    if LibVersion < DES_ede3_ofb64_encrypt_introduced then
    begin
      {$if declared(FC_DES_ede3_ofb64_encrypt)}
      DES_ede3_ofb64_encrypt := FC_DES_ede3_ofb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_ede3_ofb64_encrypt_removed)}
    if DES_ede3_ofb64_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_ede3_ofb64_encrypt)}
      DES_ede3_ofb64_encrypt := _DES_ede3_ofb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_ede3_ofb64_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ede3_ofb64_encrypt');
    {$ifend}
  end;
  
  DES_fcrypt := LoadLibFunction(ADllHandle, DES_fcrypt_procname);
  FuncLoadError := not assigned(DES_fcrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_fcrypt_allownil)}
    DES_fcrypt := ERR_DES_fcrypt;
    {$ifend}
    {$if declared(DES_fcrypt_introduced)}
    if LibVersion < DES_fcrypt_introduced then
    begin
      {$if declared(FC_DES_fcrypt)}
      DES_fcrypt := FC_DES_fcrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_fcrypt_removed)}
    if DES_fcrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_fcrypt)}
      DES_fcrypt := _DES_fcrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_fcrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_fcrypt');
    {$ifend}
  end;
  
  DES_crypt := LoadLibFunction(ADllHandle, DES_crypt_procname);
  FuncLoadError := not assigned(DES_crypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_crypt_allownil)}
    DES_crypt := ERR_DES_crypt;
    {$ifend}
    {$if declared(DES_crypt_introduced)}
    if LibVersion < DES_crypt_introduced then
    begin
      {$if declared(FC_DES_crypt)}
      DES_crypt := FC_DES_crypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_crypt_removed)}
    if DES_crypt_removed <= LibVersion then
    begin
      {$if declared(_DES_crypt)}
      DES_crypt := _DES_crypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_crypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_crypt');
    {$ifend}
  end;
  
  DES_ofb_encrypt := LoadLibFunction(ADllHandle, DES_ofb_encrypt_procname);
  FuncLoadError := not assigned(DES_ofb_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_ofb_encrypt_allownil)}
    DES_ofb_encrypt := ERR_DES_ofb_encrypt;
    {$ifend}
    {$if declared(DES_ofb_encrypt_introduced)}
    if LibVersion < DES_ofb_encrypt_introduced then
    begin
      {$if declared(FC_DES_ofb_encrypt)}
      DES_ofb_encrypt := FC_DES_ofb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_ofb_encrypt_removed)}
    if DES_ofb_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_ofb_encrypt)}
      DES_ofb_encrypt := _DES_ofb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_ofb_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ofb_encrypt');
    {$ifend}
  end;
  
  DES_pcbc_encrypt := LoadLibFunction(ADllHandle, DES_pcbc_encrypt_procname);
  FuncLoadError := not assigned(DES_pcbc_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_pcbc_encrypt_allownil)}
    DES_pcbc_encrypt := ERR_DES_pcbc_encrypt;
    {$ifend}
    {$if declared(DES_pcbc_encrypt_introduced)}
    if LibVersion < DES_pcbc_encrypt_introduced then
    begin
      {$if declared(FC_DES_pcbc_encrypt)}
      DES_pcbc_encrypt := FC_DES_pcbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_pcbc_encrypt_removed)}
    if DES_pcbc_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_pcbc_encrypt)}
      DES_pcbc_encrypt := _DES_pcbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_pcbc_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_pcbc_encrypt');
    {$ifend}
  end;
  
  DES_quad_cksum := LoadLibFunction(ADllHandle, DES_quad_cksum_procname);
  FuncLoadError := not assigned(DES_quad_cksum);
  if FuncLoadError then
  begin
    {$if not defined(DES_quad_cksum_allownil)}
    DES_quad_cksum := ERR_DES_quad_cksum;
    {$ifend}
    {$if declared(DES_quad_cksum_introduced)}
    if LibVersion < DES_quad_cksum_introduced then
    begin
      {$if declared(FC_DES_quad_cksum)}
      DES_quad_cksum := FC_DES_quad_cksum;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_quad_cksum_removed)}
    if DES_quad_cksum_removed <= LibVersion then
    begin
      {$if declared(_DES_quad_cksum)}
      DES_quad_cksum := _DES_quad_cksum;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_quad_cksum_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_quad_cksum');
    {$ifend}
  end;
  
  DES_random_key := LoadLibFunction(ADllHandle, DES_random_key_procname);
  FuncLoadError := not assigned(DES_random_key);
  if FuncLoadError then
  begin
    {$if not defined(DES_random_key_allownil)}
    DES_random_key := ERR_DES_random_key;
    {$ifend}
    {$if declared(DES_random_key_introduced)}
    if LibVersion < DES_random_key_introduced then
    begin
      {$if declared(FC_DES_random_key)}
      DES_random_key := FC_DES_random_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_random_key_removed)}
    if DES_random_key_removed <= LibVersion then
    begin
      {$if declared(_DES_random_key)}
      DES_random_key := _DES_random_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_random_key_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_random_key');
    {$ifend}
  end;
  
  DES_set_odd_parity := LoadLibFunction(ADllHandle, DES_set_odd_parity_procname);
  FuncLoadError := not assigned(DES_set_odd_parity);
  if FuncLoadError then
  begin
    {$if not defined(DES_set_odd_parity_allownil)}
    DES_set_odd_parity := ERR_DES_set_odd_parity;
    {$ifend}
    {$if declared(DES_set_odd_parity_introduced)}
    if LibVersion < DES_set_odd_parity_introduced then
    begin
      {$if declared(FC_DES_set_odd_parity)}
      DES_set_odd_parity := FC_DES_set_odd_parity;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_set_odd_parity_removed)}
    if DES_set_odd_parity_removed <= LibVersion then
    begin
      {$if declared(_DES_set_odd_parity)}
      DES_set_odd_parity := _DES_set_odd_parity;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_set_odd_parity_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_set_odd_parity');
    {$ifend}
  end;
  
  DES_check_key_parity := LoadLibFunction(ADllHandle, DES_check_key_parity_procname);
  FuncLoadError := not assigned(DES_check_key_parity);
  if FuncLoadError then
  begin
    {$if not defined(DES_check_key_parity_allownil)}
    DES_check_key_parity := ERR_DES_check_key_parity;
    {$ifend}
    {$if declared(DES_check_key_parity_introduced)}
    if LibVersion < DES_check_key_parity_introduced then
    begin
      {$if declared(FC_DES_check_key_parity)}
      DES_check_key_parity := FC_DES_check_key_parity;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_check_key_parity_removed)}
    if DES_check_key_parity_removed <= LibVersion then
    begin
      {$if declared(_DES_check_key_parity)}
      DES_check_key_parity := _DES_check_key_parity;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_check_key_parity_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_check_key_parity');
    {$ifend}
  end;
  
  DES_is_weak_key := LoadLibFunction(ADllHandle, DES_is_weak_key_procname);
  FuncLoadError := not assigned(DES_is_weak_key);
  if FuncLoadError then
  begin
    {$if not defined(DES_is_weak_key_allownil)}
    DES_is_weak_key := ERR_DES_is_weak_key;
    {$ifend}
    {$if declared(DES_is_weak_key_introduced)}
    if LibVersion < DES_is_weak_key_introduced then
    begin
      {$if declared(FC_DES_is_weak_key)}
      DES_is_weak_key := FC_DES_is_weak_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_is_weak_key_removed)}
    if DES_is_weak_key_removed <= LibVersion then
    begin
      {$if declared(_DES_is_weak_key)}
      DES_is_weak_key := _DES_is_weak_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_is_weak_key_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_is_weak_key');
    {$ifend}
  end;
  
  DES_set_key := LoadLibFunction(ADllHandle, DES_set_key_procname);
  FuncLoadError := not assigned(DES_set_key);
  if FuncLoadError then
  begin
    {$if not defined(DES_set_key_allownil)}
    DES_set_key := ERR_DES_set_key;
    {$ifend}
    {$if declared(DES_set_key_introduced)}
    if LibVersion < DES_set_key_introduced then
    begin
      {$if declared(FC_DES_set_key)}
      DES_set_key := FC_DES_set_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_set_key_removed)}
    if DES_set_key_removed <= LibVersion then
    begin
      {$if declared(_DES_set_key)}
      DES_set_key := _DES_set_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_set_key_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_set_key');
    {$ifend}
  end;
  
  DES_key_sched := LoadLibFunction(ADllHandle, DES_key_sched_procname);
  FuncLoadError := not assigned(DES_key_sched);
  if FuncLoadError then
  begin
    {$if not defined(DES_key_sched_allownil)}
    DES_key_sched := ERR_DES_key_sched;
    {$ifend}
    {$if declared(DES_key_sched_introduced)}
    if LibVersion < DES_key_sched_introduced then
    begin
      {$if declared(FC_DES_key_sched)}
      DES_key_sched := FC_DES_key_sched;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_key_sched_removed)}
    if DES_key_sched_removed <= LibVersion then
    begin
      {$if declared(_DES_key_sched)}
      DES_key_sched := _DES_key_sched;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_key_sched_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_key_sched');
    {$ifend}
  end;
  
  DES_set_key_checked := LoadLibFunction(ADllHandle, DES_set_key_checked_procname);
  FuncLoadError := not assigned(DES_set_key_checked);
  if FuncLoadError then
  begin
    {$if not defined(DES_set_key_checked_allownil)}
    DES_set_key_checked := ERR_DES_set_key_checked;
    {$ifend}
    {$if declared(DES_set_key_checked_introduced)}
    if LibVersion < DES_set_key_checked_introduced then
    begin
      {$if declared(FC_DES_set_key_checked)}
      DES_set_key_checked := FC_DES_set_key_checked;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_set_key_checked_removed)}
    if DES_set_key_checked_removed <= LibVersion then
    begin
      {$if declared(_DES_set_key_checked)}
      DES_set_key_checked := _DES_set_key_checked;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_set_key_checked_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_set_key_checked');
    {$ifend}
  end;
  
  DES_set_key_unchecked := LoadLibFunction(ADllHandle, DES_set_key_unchecked_procname);
  FuncLoadError := not assigned(DES_set_key_unchecked);
  if FuncLoadError then
  begin
    {$if not defined(DES_set_key_unchecked_allownil)}
    DES_set_key_unchecked := ERR_DES_set_key_unchecked;
    {$ifend}
    {$if declared(DES_set_key_unchecked_introduced)}
    if LibVersion < DES_set_key_unchecked_introduced then
    begin
      {$if declared(FC_DES_set_key_unchecked)}
      DES_set_key_unchecked := FC_DES_set_key_unchecked;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_set_key_unchecked_removed)}
    if DES_set_key_unchecked_removed <= LibVersion then
    begin
      {$if declared(_DES_set_key_unchecked)}
      DES_set_key_unchecked := _DES_set_key_unchecked;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_set_key_unchecked_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_set_key_unchecked');
    {$ifend}
  end;
  
  DES_string_to_key := LoadLibFunction(ADllHandle, DES_string_to_key_procname);
  FuncLoadError := not assigned(DES_string_to_key);
  if FuncLoadError then
  begin
    {$if not defined(DES_string_to_key_allownil)}
    DES_string_to_key := ERR_DES_string_to_key;
    {$ifend}
    {$if declared(DES_string_to_key_introduced)}
    if LibVersion < DES_string_to_key_introduced then
    begin
      {$if declared(FC_DES_string_to_key)}
      DES_string_to_key := FC_DES_string_to_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_string_to_key_removed)}
    if DES_string_to_key_removed <= LibVersion then
    begin
      {$if declared(_DES_string_to_key)}
      DES_string_to_key := _DES_string_to_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_string_to_key_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_string_to_key');
    {$ifend}
  end;
  
  DES_string_to_2keys := LoadLibFunction(ADllHandle, DES_string_to_2keys_procname);
  FuncLoadError := not assigned(DES_string_to_2keys);
  if FuncLoadError then
  begin
    {$if not defined(DES_string_to_2keys_allownil)}
    DES_string_to_2keys := ERR_DES_string_to_2keys;
    {$ifend}
    {$if declared(DES_string_to_2keys_introduced)}
    if LibVersion < DES_string_to_2keys_introduced then
    begin
      {$if declared(FC_DES_string_to_2keys)}
      DES_string_to_2keys := FC_DES_string_to_2keys;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_string_to_2keys_removed)}
    if DES_string_to_2keys_removed <= LibVersion then
    begin
      {$if declared(_DES_string_to_2keys)}
      DES_string_to_2keys := _DES_string_to_2keys;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_string_to_2keys_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_string_to_2keys');
    {$ifend}
  end;
  
  DES_cfb64_encrypt := LoadLibFunction(ADllHandle, DES_cfb64_encrypt_procname);
  FuncLoadError := not assigned(DES_cfb64_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_cfb64_encrypt_allownil)}
    DES_cfb64_encrypt := ERR_DES_cfb64_encrypt;
    {$ifend}
    {$if declared(DES_cfb64_encrypt_introduced)}
    if LibVersion < DES_cfb64_encrypt_introduced then
    begin
      {$if declared(FC_DES_cfb64_encrypt)}
      DES_cfb64_encrypt := FC_DES_cfb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_cfb64_encrypt_removed)}
    if DES_cfb64_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_cfb64_encrypt)}
      DES_cfb64_encrypt := _DES_cfb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_cfb64_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_cfb64_encrypt');
    {$ifend}
  end;
  
  DES_ofb64_encrypt := LoadLibFunction(ADllHandle, DES_ofb64_encrypt_procname);
  FuncLoadError := not assigned(DES_ofb64_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(DES_ofb64_encrypt_allownil)}
    DES_ofb64_encrypt := ERR_DES_ofb64_encrypt;
    {$ifend}
    {$if declared(DES_ofb64_encrypt_introduced)}
    if LibVersion < DES_ofb64_encrypt_introduced then
    begin
      {$if declared(FC_DES_ofb64_encrypt)}
      DES_ofb64_encrypt := FC_DES_ofb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DES_ofb64_encrypt_removed)}
    if DES_ofb64_encrypt_removed <= LibVersion then
    begin
      {$if declared(_DES_ofb64_encrypt)}
      DES_ofb64_encrypt := _DES_ofb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DES_ofb64_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ofb64_encrypt');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  DES_options := nil;
  DES_ecb3_encrypt := nil;
  DES_cbc_cksum := nil;
  DES_cbc_encrypt := nil;
  DES_ncbc_encrypt := nil;
  DES_xcbc_encrypt := nil;
  DES_cfb_encrypt := nil;
  DES_ecb_encrypt := nil;
  DES_encrypt1 := nil;
  DES_encrypt2 := nil;
  DES_encrypt3 := nil;
  DES_decrypt3 := nil;
  DES_ede3_cbc_encrypt := nil;
  DES_ede3_cfb64_encrypt := nil;
  DES_ede3_cfb_encrypt := nil;
  DES_ede3_ofb64_encrypt := nil;
  DES_fcrypt := nil;
  DES_crypt := nil;
  DES_ofb_encrypt := nil;
  DES_pcbc_encrypt := nil;
  DES_quad_cksum := nil;
  DES_random_key := nil;
  DES_set_odd_parity := nil;
  DES_check_key_parity := nil;
  DES_is_weak_key := nil;
  DES_set_key := nil;
  DES_key_sched := nil;
  DES_set_key_checked := nil;
  DES_set_key_unchecked := nil;
  DES_string_to_key := nil;
  DES_string_to_2keys := nil;
  DES_cfb64_encrypt := nil;
  DES_ofb64_encrypt := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.