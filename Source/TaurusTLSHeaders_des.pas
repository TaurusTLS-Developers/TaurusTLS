/// <exclude />
(* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_des.h2pas
  It should not be modified directly. All changes should be made to TaurusTLSHeaders_des.h2pas
  and this file regenerated. TaurusTLSHeaders_des.h2pas is distributed with the full Indy
  Distribution.
*)

{$I TaurusTLSCompilerDefines.inc}
{$I TaurusTLSLinkDefines.inc}
{$IFNDEF USE_OPENSSL}
{ error Should not compile if USE_OPENSSL is not defined!!! }
{$ENDIF}
{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2024 TaurusTLS Developers, All Rights Reserved              * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 – 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  * }
{ ****************************************************************************** }
unit TaurusTLSHeaders_des;

interface

uses
  IdCTypes,
  IdGlobal
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  , TaurusTLSConsts
  {$ENDIF};

{
  Automatically converted by H2Pas 1.0.0 from des.h
  The following command line parameters were used:
  des.h
}

Type
  DES_LONG = type cardinal;
  Pconst_DES_cblock = ^const_DES_cblock;
  PDES_cblock = ^DES_cblock;
  PDES_key_schedule = ^DES_key_schedule;
  PDES_LONG = ^DES_LONG;

  DES_cblock = array [0 .. 7] of byte;
  { const }
  const_DES_cblock = array [0 .. 7] of byte;
  {
    * With "const", gcc 2.8.1 on Solaris thinks that DES_cblock * and
    * const_DES_cblock * are incompatible pointer types.
  }
  {
    * make sure things are correct size on machines with 8 byte longs
  }

  {$EXTERNALSYM DES_ks}
  DES_ks = record
    ks: array [0 .. 15] of record
    case longint of
    0: (cblock: DES_cblock);
    1: (deslong: array [0 .. 1] of DES_LONG);
    end;
  end;

  {$EXTERNALSYM DES_key_schedule}
  DES_key_schedule = DES_ks;

var
  {$EXTERNALSYM DES_check_key}
  DES_check_key: TIdC_INT;

const
  {$EXTERNALSYM DES_ENCRYPT}
  DES_ENCRYPT = 1;
  {$EXTERNALSYM DES_DECRYPT}
  DES_DECRYPT = 0;
  {$EXTERNALSYM DES_CBC_MODE}
  DES_CBC_MODE = 0;
  {$EXTERNALSYM DES_PCBC_MODE}
  DES_PCBC_MODE = 1;

  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

    The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
    files generated for C++. }

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

var
  {$EXTERNALSYM DES_ecb2_encrypt}
  DES_ecb2_encrypt: procedure(_input: Pconst_DES_cblock; _output: PDES_cblock;
    ks1: PDES_key_schedule; ks2: PDES_key_schedule; enc: TIdC_INT);
    cdecl = nil; { removed 1.0.0 }
  {$EXTERNALSYM DES_ede2_cbc_encrypt}
  DES_ede2_cbc_encrypt: procedure(_input: Pbyte; _output: Pbyte;
    _length: TIdC_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule;
    ivec: PDES_cblock; enc: TIdC_INT); cdecl = nil; { removed 1.0.0 }
  {$EXTERNALSYM DES_ede2_cfb64_encrypt}
  DES_ede2_cfb64_encrypt: procedure(in_: Pbyte; out_: Pbyte;
    _length: TIdC_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule;
    ivec: PDES_cblock; num: PIdC_INT; enc: TIdC_INT);
    cdecl = nil; { removed 1.0.0 }
  {$EXTERNALSYM DES_ede2_ofb64_encrypt}
  DES_ede2_ofb64_encrypt: procedure(in_: Pbyte; out_: Pbyte; _length: TIdC_LONG;
    ks1: PDES_key_schedule; ks2: PDES_key_schedule; ivec: PDES_cblock;
    num: PIdC_INT);  cdecl = nil; { removed 1.0.0 }

  (* Const before type ignored *)
  {$EXTERNALSYM DES_options}
  DES_options: function: PIdAnsiChar; cdecl = nil;

  {$EXTERNALSYM DES_ecb3_encrypt}
  DES_ecb3_encrypt: procedure(_input: Pconst_DES_cblock; _output: PDES_cblock;
    ks1: PDES_key_schedule; ks2: PDES_key_schedule;  ks3: PDES_key_schedule;
    enc: TIdC_INT); cdecl = nil;

   (* Const before type ignored *)
  {$EXTERNALSYM DES_cbc_cksum}
  DES_cbc_cksum: function(_input: Pbyte; _output: PDES_cblock; _length: TIdC_LONG;
    schedule: PDES_key_schedule; ivec: Pconst_DES_cblock): DES_LONG;
     cdecl = nil;

  { DES_cbc_encrypt does not update the IV!  Use DES_ncbc_encrypt instead. }
  (* Const before type ignored *)
  {$EXTERNALSYM DES_cbc_encrypt}
  DES_cbc_encrypt: procedure(_input: Pbyte; _output: Pbyte; _length: TIdC_LONG;
    schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl = nil;

  (* Const before type ignored *)
  {$EXTERNALSYM DES_ncbc_encrypt}
  DES_ncbc_encrypt: procedure(_input: Pbyte; _output: Pbyte; _length: TIdC_LONG;
    schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl = nil;

  (* Const before type ignored *)
  {$EXTERNALSYM DES_xcbc_encrypt}
  DES_xcbc_encrypt: procedure(_input: Pbyte; _output: Pbyte; _length: TIdC_LONG;
    schedule: PDES_key_schedule; ivec: PDES_cblock; inw: Pconst_DES_cblock; outw: Pconst_DES_cblock;
    enc: TIdC_INT); cdecl = nil;

  (* Const before type ignored *)
  {$EXTERNALSYM DES_cfb_encrypt}
  DES_cfb_encrypt: procedure(in_: Pbyte; out_: Pbyte; numbits: TIdC_INT;
    _length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock;
    enc: TIdC_INT); cdecl = nil;

  {$EXTERNALSYM DES_ecb_encrypt}
  DES_ecb_encrypt: procedure(_input: Pconst_DES_cblock; _output: PDES_cblock;
    ks: PDES_key_schedule; enc: TIdC_INT); cdecl = nil;
{
 * This is the DES encryption function that gets called by just about every
 * other DES routine in the library.  You should not use this function except
 * to implement 'modes' of DES.  I say this because the functions that call
 * this routine do the conversion from 'char *' to long, and this needs to be
 * done to make sure 'non-aligned' memory access do not occur.  The
 * characters are loaded 'little endian'. Data is a pointer to 2 unsigned
 * long's and ks is the DES_key_schedule to use.  enc, is non zero specifies
 * encryption, zero if decryption.
}
  {$EXTERNALSYM DES_encrypt1}
  DES_encrypt1: procedure(data: PDES_LONG; ks: PDES_key_schedule; enc: TIdC_INT);
    cdecl = nil;

{
 * This functions is the same as DES_encrypt1() except that the DES initial
 * permutation (IP) and final permutation (FP) have been left out.  As for
 * DES_encrypt1(), you should not use this function. It is used by the
 * routines in the library that implement triple DES. IP() DES_encrypt2()
 * DES_encrypt2() DES_encrypt2() FP() is the same as DES_encrypt1()
 * DES_encrypt1() DES_encrypt1() except faster :-).
}
  {$EXTERNALSYM DES_encrypt2}
   DES_encrypt2: procedure(data: PDES_LONG; ks: PDES_key_schedule;
     enc: TIdC_INT); cdecl = nil;

  {$EXTERNALSYM DES_encrypt3}
   DES_encrypt3: procedure(data: PDES_LONG; ks1: PDES_key_schedule;
     ks2: PDES_key_schedule; ks3: PDES_key_schedule); cdecl = nil;

  {$EXTERNALSYM DES_decrypt3}
   DES_decrypt3: procedure(data: PDES_LONG; ks1: PDES_key_schedule;
     ks2: PDES_key_schedule; ks3: PDES_key_schedule);  cdecl = nil;

  (* Const before type ignored *)
  {$EXTERNALSYM DES_ede3_cbc_encrypt}
  DES_ede3_cbc_encrypt: procedure(_input: Pbyte; _output: Pbyte;
      _length: TIdC_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule;
      ks3: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl = nil;

  (* Const before type ignored *)
  {$EXTERNALSYM DES_ede3_cfb64_encrypt}
  DES_ede3_cfb64_encrypt: procedure(in_: Pbyte; out_: Pbyte; _length: TIdC_LONG;
     ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule;
     ivec: PDES_cblock; num: PIdC_INT; enc: TIdC_INT);  cdecl = nil;

  (* Const before type ignored *)
  {$EXTERNALSYM DES_ede3_cfb_encrypt}
  DES_ede3_cfb_encrypt: procedure(in_: Pbyte; out_: Pbyte; numbits: TIdC_INT;
     _length: TIdC_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule;
      ks3: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl = nil;

  (* Const before type ignored *)
  {$EXTERNALSYM DES_ede3_ofb64_encrypt}
  DES_ede3_ofb64_encrypt: procedure(in_: Pbyte; out_: Pbyte; _length: TIdC_LONG;
     ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule;
     ivec: PDES_cblock; num: PIdC_INT); cdecl = nil;

  (* Const before type ignored *)
  (* Const before type ignored *)
  {$EXTERNALSYM DES_fcrypt}
  DES_fcrypt: function(buf: PIdAnsiChar; salt: PIdAnsiChar; ret: PIdAnsiChar)
      : PIdAnsiChar; cdecl = nil;

  (* Const before type ignored *)
  (* Const before type ignored *)
  {$EXTERNALSYM DES_crypt}
  DES_crypt: function(buf: PIdAnsiChar; salt: PIdAnsiChar): PIdAnsiChar;
     cdecl = nil;

   (* Const before type ignored *)
  {$EXTERNALSYM DES_ofb_encrypt}
  DES_ofb_encrypt: procedure(in_: Pbyte; out_: Pbyte;  numbits: TIdC_INT;
    _length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock);
    cdecl = nil;

   (* Const before type ignored *)
  {$EXTERNALSYM DES_pcbc_encrypt}
  DES_pcbc_encrypt:  procedure(_input: Pbyte; _output: Pbyte; _length: TIdC_LONG;
    schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl = nil;

   (* Const before type ignored *)
  {$EXTERNALSYM DES_quad_cksum}
  DES_quad_cksum:  function(_input: Pbyte; _output: PDES_cblock;
    _length: TIdC_LONG; out_count: TIdC_INT; seed: PDES_cblock) : DES_LONG;
    cdecl = nil;

  {$EXTERNALSYM DES_random_key}
  DES_random_key:  function(ret: PDES_cblock): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM DES_set_odd_parity}
  DES_set_odd_parity:  procedure(key: PDES_cblock);  cdecl = nil;

  {$EXTERNALSYM DES_check_key_parity}
  DES_check_key_parity: function(key: Pconst_DES_cblock) : TIdC_INT; cdecl = nil;

  {$EXTERNALSYM DES_is_weak_key}
  DES_is_weak_key: function(key: Pconst_DES_cblock) : TIdC_INT; cdecl = nil;

{
 * DES_set_key (= set_key = DES_key_sched = key_sched) calls
 * DES_set_key_checked if global variable DES_check_key is set,
 * DES_set_key_unchecked otherwise.
}
  {$EXTERNALSYM DES_set_key}
  DES_set_key: function(key: Pconst_DES_cblock;
    var schedule: DES_key_schedule) : TIdC_INT; cdecl = nil;

  {$EXTERNALSYM DES_key_sched}
  DES_key_sched: function(key: Pconst_DES_cblock;
    schedule: PDES_key_schedule): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM DES_set_key_checked}
  DES_set_key_checked: function(key: Pconst_DES_cblock;
    schedule: PDES_key_schedule): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM DES_set_key_unchecked}
  DES_set_key_unchecked: procedure(key: Pconst_DES_cblock;
    schedule: PDES_key_schedule); cdecl = nil;

  (* Const before type ignored *)
  {$EXTERNALSYM DES_string_to_key}
  DES_string_to_key: procedure(_str: PIdAnsiChar; key: PDES_cblock);  cdecl = nil;

   (* Const before type ignored *)
  {$EXTERNALSYM DES_string_to_2keys}
  DES_string_to_2keys: procedure(_str: PIdAnsiChar; key1: PDES_cblock;
    key2: PDES_cblock); cdecl = nil;

   (* Const before type ignored *)
  {$EXTERNALSYM DES_cfb64_encrypt}
  DES_cfb64_encrypt: procedure(in_: Pbyte; out_: Pbyte; _length: TIdC_LONG;
    schedule: PDES_key_schedule; ivec: PDES_cblock; num: PIdC_INT;
    enc: TIdC_INT);  cdecl = nil;

  (* Const before type ignored *)
  {$EXTERNALSYM DES_ofb64_encrypt}
  DES_ofb64_encrypt:  procedure(in_: Pbyte; out_: Pbyte; _length: TIdC_LONG;
    schedule: PDES_key_schedule;  ivec: PDES_cblock; num: PIdC_INT);
    cdecl = nil;

  {$EXTERNALSYM DES_fixup_key_parity}
  DES_fixup_key_parity:  procedure(key: PDES_cblock); cdecl = nil; { removed 1.0.0 }

{$ELSE}
  (* Const before type ignored *)
  {$EXTERNALSYM DES_options}
function DES_options: PIdAnsiChar cdecl; external CLibCrypto;

  {$EXTERNALSYM DES_ecb3_encrypt}
procedure DES_ecb3_encrypt(_input: Pconst_DES_cblock; _output: PDES_cblock;
  ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule;
  enc: TIdC_INT)cdecl; external CLibCrypto;

(* Const before type ignored *)
  {$EXTERNALSYM DES_cbc_cksum}
function DES_cbc_cksum(_input: Pbyte; _output: PDES_cblock; _length: TIdC_LONG;
  schedule: PDES_key_schedule; ivec: Pconst_DES_cblock): DES_LONG cdecl;
  external CLibCrypto;

{ DES_cbc_encrypt does not update the IV!  Use DES_ncbc_encrypt instead. }
(* Const before type ignored *)
  {$EXTERNALSYM DES_cbc_encrypt}
procedure DES_cbc_encrypt(_input: Pbyte; _output: Pbyte; _length: TIdC_LONG;
  schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT)cdecl;
  external CLibCrypto;

(* Const before type ignored *)
  {$EXTERNALSYM DES_ncbc_encrypt}
procedure DES_ncbc_encrypt(_input: Pbyte; _output: Pbyte; _length: TIdC_LONG;
  schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT)cdecl;
  external CLibCrypto;

(* Const before type ignored *)
  {$EXTERNALSYM DES_xcbc_encrypt}
procedure DES_xcbc_encrypt(_input: Pbyte; _output: Pbyte; _length: TIdC_LONG;
  schedule: PDES_key_schedule; ivec: PDES_cblock; inw: Pconst_DES_cblock;
  outw: Pconst_DES_cblock; enc: TIdC_INT)cdecl; external CLibCrypto;

(* Const before type ignored *)
  {$EXTERNALSYM DES_cfb_encrypt}
procedure DES_cfb_encrypt(in_: Pbyte; out_: Pbyte; numbits: TIdC_INT;
  _length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT)
  cdecl; external CLibCrypto;

  {$EXTERNALSYM DES_ecb_encrypt}
procedure DES_ecb_encrypt(_input: Pconst_DES_cblock; _output: PDES_cblock;
  ks: PDES_key_schedule; enc: TIdC_INT)cdecl; external CLibCrypto;
{
  * This is the DES encryption function that gets called by just about every
  * other DES routine in the library.  You should not use this function except
  * to implement 'modes' of DES.  I say this because the functions that call
  * this routine do the conversion from 'char *' to long, and this needs to be
  * done to make sure 'non-aligned' memory access do not occur.  The
  * characters are loaded 'little endian'. Data is a pointer to 2 unsigned
  * long's and ks is the DES_key_schedule to use.  enc, is non zero specifies
  * encryption, zero if decryption.
}
  {$EXTERNALSYM DES_encrypt1}
procedure DES_encrypt1(data: PDES_LONG; ks: PDES_key_schedule; enc: TIdC_INT)
  cdecl; external CLibCrypto;

{
  * This functions is the same as DES_encrypt1() except that the DES initial
  * permutation (IP) and final permutation (FP) have been left out.  As for
  * DES_encrypt1(), you should not use this function. It is used by the
  * routines in the library that implement triple DES. IP() DES_encrypt2()
  * DES_encrypt2() DES_encrypt2() FP() is the same as DES_encrypt1()
  * DES_encrypt1() DES_encrypt1() except faster :-).
}
  {$EXTERNALSYM DES_encrypt2}
procedure DES_encrypt2(data: PDES_LONG; ks: PDES_key_schedule; enc: TIdC_INT)
  cdecl; external CLibCrypto;

  {$EXTERNALSYM DES_encrypt3}
procedure DES_encrypt3(data: PDES_LONG; ks1: PDES_key_schedule;
  ks2: PDES_key_schedule; ks3: PDES_key_schedule)cdecl; external CLibCrypto;

  {$EXTERNALSYM DES_decrypt3}
procedure DES_decrypt3(data: PDES_LONG; ks1: PDES_key_schedule;
  ks2: PDES_key_schedule; ks3: PDES_key_schedule)cdecl; external CLibCrypto;

(* Const before type ignored *)
  {$EXTERNALSYM DES_ede3_cbc_encrypt}
procedure DES_ede3_cbc_encrypt(_input: Pbyte; _output: Pbyte; _length: TIdC_LONG;
  ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule;
  ivec: PDES_cblock; enc: TIdC_INT)cdecl; external CLibCrypto;

(* Const before type ignored *)
  {$EXTERNALSYM DES_ede3_cfb64_encrypt}
procedure DES_ede3_cfb64_encrypt(in_: Pbyte; out_: Pbyte; _length: TIdC_LONG;
  ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule;
  ivec: PDES_cblock; num: PIdC_INT; enc: TIdC_INT)cdecl; external CLibCrypto;

(* Const before type ignored *)
  {$EXTERNALSYM DES_ede3_cfb_encrypt}
procedure DES_ede3_cfb_encrypt(in_: Pbyte; out_: Pbyte; numbits: TIdC_INT;
  _length: TIdC_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule;
  ks3: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT)cdecl;
  external CLibCrypto;

(* Const before type ignored *)
  {$EXTERNALSYM DES_ede3_ofb64_encrypt}
procedure DES_ede3_ofb64_encrypt(in_: Pbyte; out_: Pbyte; _length: TIdC_LONG;
  ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule;
  ivec: PDES_cblock; num: PIdC_INT)cdecl; external CLibCrypto;

(* Const before type ignored *)
(* Const before type ignored *)
  {$EXTERNALSYM DES_fcrypt}
function DES_fcrypt(buf: PIdAnsiChar; salt: PIdAnsiChar; ret: PIdAnsiChar)
  : PIdAnsiChar cdecl; external CLibCrypto;

(* Const before type ignored *)
(* Const before type ignored *)
  {$EXTERNALSYM DES_crypt}
function DES_crypt(buf: PIdAnsiChar; salt: PIdAnsiChar): PIdAnsiChar cdecl;
  external CLibCrypto;

(* Const before type ignored *)
  {$EXTERNALSYM DES_ofb_encrypt}
procedure DES_ofb_encrypt(in_: Pbyte; out_: Pbyte; numbits: TIdC_INT;
  _length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock)cdecl;
  external CLibCrypto;

(* Const before type ignored *)
  {$EXTERNALSYM DES_pcbc_encrypt}
procedure DES_pcbc_encrypt(_input: Pbyte; _output: Pbyte; _length: TIdC_LONG;
  schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT)cdecl;
  external CLibCrypto;

(* Const before type ignored *)
  {$EXTERNALSYM DES_quad_cksum}
function DES_quad_cksum(_input: Pbyte; _output: PDES_cblock; _length: TIdC_LONG;
  out_count: TIdC_INT; seed: PDES_cblock): DES_LONG cdecl; external CLibCrypto;

  {$EXTERNALSYM DES_random_key}
function DES_random_key(ret: PDES_cblock): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM DES_set_odd_parity}
procedure DES_set_odd_parity(key: PDES_cblock)cdecl; external CLibCrypto;

  {$EXTERNALSYM DES_check_key_parity}
function DES_check_key_parity(key: Pconst_DES_cblock): TIdC_INT cdecl;
  external CLibCrypto;

  {$EXTERNALSYM DES_is_weak_key}
function DES_is_weak_key(key: Pconst_DES_cblock): TIdC_INT cdecl;
  external CLibCrypto;

{
  * DES_set_key (= set_key = DES_key_sched = key_sched) calls
  * DES_set_key_checked if global variable DES_check_key is set,
  * DES_set_key_unchecked otherwise.
}
  {$EXTERNALSYM DES_set_key}
function DES_set_key(key: Pconst_DES_cblock; var schedule: DES_key_schedule)
  : TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM DES_key_sched}
function DES_key_sched(key: Pconst_DES_cblock; schedule: PDES_key_schedule)
  : TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM DES_set_key_checked}
function DES_set_key_checked(key: Pconst_DES_cblock;
  schedule: PDES_key_schedule): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM DES_set_key_unchecked}
procedure DES_set_key_unchecked(key: Pconst_DES_cblock;
  schedule: PDES_key_schedule)cdecl; external CLibCrypto;

(* Const before type ignored *)
  {$EXTERNALSYM DES_string_to_key}
procedure DES_string_to_key(_str: PIdAnsiChar; key: PDES_cblock)cdecl;
  external CLibCrypto;

(* Const before type ignored *)
  {$EXTERNALSYM DES_string_to_2keys}
procedure DES_string_to_2keys(_str: PIdAnsiChar; key1: PDES_cblock;
  key2: PDES_cblock)cdecl; external CLibCrypto;

(* Const before type ignored *)
  {$EXTERNALSYM DES_cfb64_encrypt}
procedure DES_cfb64_encrypt(in_: Pbyte; out_: Pbyte; _length: TIdC_LONG;
  schedule: PDES_key_schedule; ivec: PDES_cblock; num: PIdC_INT; enc: TIdC_INT)
  cdecl; external CLibCrypto;

(* Const before type ignored *)
  {$EXTERNALSYM DES_ofb64_encrypt}
procedure DES_ofb64_encrypt(in_: Pbyte; out_: Pbyte; _length: TIdC_LONG;
  schedule: PDES_key_schedule; ivec: PDES_cblock; num: PIdC_INT)cdecl;
  external CLibCrypto;

  {$EXTERNALSYM DES_ecb2_encrypt}
procedure DES_ecb2_encrypt(_input: Pconst_DES_cblock; _output: PDES_cblock;
  ks1: PDES_key_schedule; ks2: PDES_key_schedule; enc: TIdC_INT);
{ removed 1.0.0 }
  {$EXTERNALSYM DES_ede2_cbc_encrypt}
  procedure DES_ede2_cbc_encrypt(_input: Pbyte; _output: Pbyte; _length: TIdC_LONG;
    ks1: PDES_key_schedule; ks2: PDES_key_schedule; ivec: PDES_cblock;
    enc: TIdC_INT); { removed 1.0.0 }
  {$EXTERNALSYM DES_ede2_cfb64_encrypt}
    procedure DES_ede2_cfb64_encrypt(in_: Pbyte; out_: Pbyte; _length: TIdC_LONG;
      ks1: PDES_key_schedule; ks2: PDES_key_schedule; ivec: PDES_cblock;
      num: PIdC_INT; enc: TIdC_INT); { removed 1.0.0 }
  {$EXTERNALSYM DES_ede2_ofb64_encrypt}
      procedure DES_ede2_ofb64_encrypt(in_: Pbyte; out_: Pbyte; _length: TIdC_LONG;
        ks1: PDES_key_schedule; ks2: PDES_key_schedule; ivec: PDES_cblock;
        num: PIdC_INT); { removed 1.0.0 }
  {$EXTERNALSYM DES_fixup_key_parity}
        procedure DES_fixup_key_parity(key: PDES_cblock); { removed 1.0.0 }
{$ENDIF}

implementation

uses
  classes,
  TaurusTLSExceptionHandlers
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    , TaurusTLSLoader
{$ENDIF};

const
  DES_ecb2_encrypt_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  DES_ede2_cbc_encrypt_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  DES_ede2_cfb64_encrypt_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  DES_ede2_ofb64_encrypt_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  DES_fixup_key_parity_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

const
  DES_ecb2_encrypt_procname = 'DES_ecb2_encrypt'; { removed 1.0.0 }
  DES_ede2_cbc_encrypt_procname = 'DES_ede2_cbc_encrypt'; { removed 1.0.0 }
  DES_ede2_cfb64_encrypt_procname = 'DES_ede2_cfb64_encrypt'; { removed 1.0.0 }
  DES_ede2_ofb64_encrypt_procname = 'DES_ede2_ofb64_encrypt'; { removed 1.0.0 }

  (* Const before type ignored *)
  DES_options_procname = 'DES_options';

  DES_ecb3_encrypt_procname = 'DES_ecb3_encrypt';

  (* Const before type ignored *)
  DES_cbc_cksum_procname = 'DES_cbc_cksum';

  { DES_cbc_encrypt does not update the IV!  Use DES_ncbc_encrypt instead. }
  (* Const before type ignored *)
  DES_cbc_encrypt_procname = 'DES_cbc_encrypt';

  (* Const before type ignored *)
  DES_ncbc_encrypt_procname = 'DES_ncbc_encrypt';

  (* Const before type ignored *)
  DES_xcbc_encrypt_procname = 'DES_xcbc_encrypt';

  (* Const before type ignored *)
  DES_cfb_encrypt_procname = 'DES_cfb_encrypt';

  DES_ecb_encrypt_procname = 'DES_ecb_encrypt';
  {
    * This is the DES encryption function that gets called by just about every
    * other DES routine in the library.  You should not use this function except
    * to implement 'modes' of DES.  I say this because the functions that call
    * this routine do the conversion from 'char *' to long, and this needs to be
    * done to make sure 'non-aligned' memory access do not occur.  The
    * characters are loaded 'little endian'. Data is a pointer to 2 unsigned
    * long's and ks is the DES_key_schedule to use.  enc, is non zero specifies
    * encryption, zero if decryption.
  }
  DES_encrypt1_procname = 'DES_encrypt1';

  {
    * This functions is the same as DES_encrypt1() except that the DES initial
    * permutation (IP) and final permutation (FP) have been left out.  As for
    * DES_encrypt1(), you should not use this function. It is used by the
    * routines in the library that implement triple DES. IP() DES_encrypt2()
    * DES_encrypt2() DES_encrypt2() FP() is the same as DES_encrypt1()
    * DES_encrypt1() DES_encrypt1() except faster :-).
  }
  DES_encrypt2_procname = 'DES_encrypt2';

  DES_encrypt3_procname = 'DES_encrypt3';

  DES_decrypt3_procname = 'DES_decrypt3';

  (* Const before type ignored *)
  DES_ede3_cbc_encrypt_procname = 'DES_ede3_cbc_encrypt';

  (* Const before type ignored *)
  DES_ede3_cfb64_encrypt_procname = 'DES_ede3_cfb64_encrypt';

  (* Const before type ignored *)
  DES_ede3_cfb_encrypt_procname = 'DES_ede3_cfb_encrypt';

  (* Const before type ignored *)
  DES_ede3_ofb64_encrypt_procname = 'DES_ede3_ofb64_encrypt';

  (* Const before type ignored *)
  (* Const before type ignored *)
  DES_fcrypt_procname = 'DES_fcrypt';

  (* Const before type ignored *)
  (* Const before type ignored *)
  DES_crypt_procname = 'DES_crypt';

  (* Const before type ignored *)
  DES_ofb_encrypt_procname = 'DES_ofb_encrypt';

  (* Const before type ignored *)
  DES_pcbc_encrypt_procname = 'DES_pcbc_encrypt';

  (* Const before type ignored *)
  DES_quad_cksum_procname = 'DES_quad_cksum';

  DES_random_key_procname = 'DES_random_key';

  DES_set_odd_parity_procname = 'DES_set_odd_parity';

  DES_check_key_parity_procname = 'DES_check_key_parity';

  DES_is_weak_key_procname = 'DES_is_weak_key';

  {
    * DES_set_key (= set_key = DES_key_sched = key_sched) calls
    * DES_set_key_checked if global variable DES_check_key is set,
    * DES_set_key_unchecked otherwise.
  }
  DES_set_key_procname = 'DES_set_key';

  DES_key_sched_procname = 'DES_key_sched';

  DES_set_key_checked_procname = 'DES_set_key_checked';

  DES_set_key_unchecked_procname = 'DES_set_key_unchecked';

  (* Const before type ignored *)
  DES_string_to_key_procname = 'DES_string_to_key';

  (* Const before type ignored *)
  DES_string_to_2keys_procname = 'DES_string_to_2keys';

  (* Const before type ignored *)
  DES_cfb64_encrypt_procname = 'DES_cfb64_encrypt';

  (* Const before type ignored *)
  DES_ofb64_encrypt_procname = 'DES_ofb64_encrypt';

  DES_fixup_key_parity_procname = 'DES_fixup_key_parity'; { removed 1.0.0 }

  {$IFNDEF _FIXINSIGHT_}
procedure _DES_ecb2_encrypt(_input: Pconst_DES_cblock; _output: PDES_cblock;
  ks1: PDES_key_schedule; ks2: PDES_key_schedule; enc: TIdC_INT); cdecl;
begin
  DES_ecb3_encrypt(_input, _output, ks1, ks2, ks1, enc);
end;

procedure _DES_ede2_cbc_encrypt(_input: Pbyte; _output: Pbyte; _length: TIdC_LONG;
  ks1: PDES_key_schedule; ks2: PDES_key_schedule; ivec: PDES_cblock;
  enc: TIdC_INT); cdecl;
begin
  DES_ede3_cbc_encrypt(_input, _output, _length, ks1, ks2, ks1, ivec, enc);
end;

procedure _DES_ede2_cfb64_encrypt(in_: Pbyte; out_: Pbyte; _length: TIdC_LONG;
  ks1: PDES_key_schedule; ks2: PDES_key_schedule; ivec: PDES_cblock;
  num: PIdC_INT; enc: TIdC_INT); cdecl;
begin
  DES_ede3_cfb64_encrypt(in_, out_, _length, ks1, ks2, ks1, ivec, num, enc);
end;

procedure _DES_ede2_ofb64_encrypt(in_: Pbyte; out_: Pbyte; _length: TIdC_LONG;
  ks1: PDES_key_schedule; ks2: PDES_key_schedule; ivec: PDES_cblock;
  num: PIdC_INT); cdecl;
begin
  DES_ede3_ofb64_encrypt(in_, out_, _length, ks1, ks2, ks1, ivec, num);
end;

procedure _DES_fixup_key_parity(key: PDES_cblock); cdecl;
begin
  DES_set_odd_parity(key);
end;

  {$I TaurusTLSNoRetValOff.inc} 

procedure ERR_DES_ecb2_encrypt(_input: Pconst_DES_cblock; _output: PDES_cblock;
  ks1: PDES_key_schedule; ks2: PDES_key_schedule; enc: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_ecb2_encrypt_procname);
end;

procedure ERR_DES_ede2_cbc_encrypt(_input: Pbyte; _output: Pbyte; _length: TIdC_LONG;
  ks1: PDES_key_schedule; ks2: PDES_key_schedule; ivec: PDES_cblock;
  enc: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_ede2_cbc_encrypt_procname);
end;

procedure ERR_DES_ede2_cfb64_encrypt(in_: Pbyte; out_: Pbyte; _length: TIdC_LONG;
  ks1: PDES_key_schedule; ks2: PDES_key_schedule; ivec: PDES_cblock;
  num: PIdC_INT; enc: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_ede2_cfb64_encrypt_procname);
end;

procedure ERR_DES_ede2_ofb64_encrypt(in_: Pbyte; out_: Pbyte; _length: TIdC_LONG;
  ks1: PDES_key_schedule; ks2: PDES_key_schedule; ivec: PDES_cblock;
  num: PIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_ede2_ofb64_encrypt_procname);
end;

(* Const before type ignored *)
function ERR_DES_options: PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_options_procname);
end;

procedure ERR_DES_ecb3_encrypt(_input: Pconst_DES_cblock; _output: PDES_cblock;
  ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule;
  enc: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_ecb3_encrypt_procname);
end;

(* Const before type ignored *)
function ERR_DES_cbc_cksum(_input: Pbyte; _output: PDES_cblock; _length: TIdC_LONG;
  schedule: PDES_key_schedule; ivec: Pconst_DES_cblock): DES_LONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_cbc_cksum_procname);
end;

{ DES_cbc_encrypt does not update the IV!  Use DES_ncbc_encrypt instead. }
(* Const before type ignored *)
procedure ERR_DES_cbc_encrypt(_input: Pbyte; _output: Pbyte; _length: TIdC_LONG;
  schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_cbc_encrypt_procname);
end;

(* Const before type ignored *)
procedure ERR_DES_ncbc_encrypt(_input: Pbyte; _output: Pbyte; _length: TIdC_LONG;
  schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_ncbc_encrypt_procname);
end;

(* Const before type ignored *)
procedure ERR_DES_xcbc_encrypt(_input: Pbyte; _output: Pbyte; _length: TIdC_LONG;
  schedule: PDES_key_schedule; ivec: PDES_cblock; inw: Pconst_DES_cblock;
  outw: Pconst_DES_cblock; enc: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_xcbc_encrypt_procname);
end;

(* Const before type ignored *)
procedure ERR_DES_cfb_encrypt(in_: Pbyte; out_: Pbyte; numbits: TIdC_INT;
  _length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock;
  enc: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_cfb_encrypt_procname);
end;

procedure ERR_DES_ecb_encrypt(_input: Pconst_DES_cblock; _output: PDES_cblock;
  ks: PDES_key_schedule; enc: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_ecb_encrypt_procname);
end;

{
  * This is the DES encryption function that gets called by just about every
  * other DES routine in the library.  You should not use this function except
  * to implement 'modes' of DES.  I say this because the functions that call
  * this routine do the conversion from 'char *' to long, and this needs to be
  * done to make sure 'non-aligned' memory access do not occur.  The
  * characters are loaded 'little endian'. Data is a pointer to 2 unsigned
  * long's and ks is the DES_key_schedule to use.  enc, is non zero specifies
  * encryption, zero if decryption.
}
procedure ERR_DES_encrypt1(data: PDES_LONG; ks: PDES_key_schedule;
  enc: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_encrypt1_procname);
end;

{
  * This functions is the same as DES_encrypt1() except that the DES initial
  * permutation (IP) and final permutation (FP) have been left out.  As for
  * DES_encrypt1(), you should not use this function. It is used by the
  * routines in the library that implement triple DES. IP() DES_encrypt2()
  * DES_encrypt2() DES_encrypt2() FP() is the same as DES_encrypt1()
  * DES_encrypt1() DES_encrypt1() except faster :-).
}
procedure ERR_DES_encrypt2(data: PDES_LONG; ks: PDES_key_schedule;
  enc: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_encrypt2_procname);
end;

procedure ERR_DES_encrypt3(data: PDES_LONG; ks1: PDES_key_schedule;
  ks2: PDES_key_schedule; ks3: PDES_key_schedule); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_encrypt3_procname);
end;

procedure ERR_DES_decrypt3(data: PDES_LONG; ks1: PDES_key_schedule;
  ks2: PDES_key_schedule; ks3: PDES_key_schedule); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_decrypt3_procname);
end;

(* Const before type ignored *)
procedure ERR_DES_ede3_cbc_encrypt(_input: Pbyte; _output: Pbyte; _length: TIdC_LONG;
  ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule;
  ivec: PDES_cblock; enc: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_ede3_cbc_encrypt_procname);
end;

(* Const before type ignored *)
procedure ERR_DES_ede3_cfb64_encrypt(in_: Pbyte; out_: Pbyte; _length: TIdC_LONG;
  ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule;
  ivec: PDES_cblock; num: PIdC_INT; enc: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_ede3_cfb64_encrypt_procname);
end;

(* Const before type ignored *)
procedure ERR_DES_ede3_cfb_encrypt(in_: Pbyte; out_: Pbyte; numbits: TIdC_INT;
  _length: TIdC_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule;
  ks3: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_ede3_cfb_encrypt_procname);
end;

(* Const before type ignored *)
procedure ERR_DES_ede3_ofb64_encrypt(in_: Pbyte; out_: Pbyte; _length: TIdC_LONG;
  ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule;
  ivec: PDES_cblock; num: PIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_ede3_ofb64_encrypt_procname);
end;

(* Const before type ignored *)
(* Const before type ignored *)
function ERR_DES_fcrypt(buf: PIdAnsiChar; salt: PIdAnsiChar; ret: PIdAnsiChar)
  : PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_fcrypt_procname);
end;

(* Const before type ignored *)
(* Const before type ignored *)
function ERR_DES_crypt(buf: PIdAnsiChar; salt: PIdAnsiChar): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_crypt_procname);
end;

(* Const before type ignored *)
procedure ERR_DES_ofb_encrypt(in_: Pbyte; out_: Pbyte; numbits: TIdC_INT;
  _length: TIdC_LONG; schedule: PDES_key_schedule; ivec: PDES_cblock); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_ofb_encrypt_procname);
end;

(* Const before type ignored *)
procedure ERR_DES_pcbc_encrypt(_input: Pbyte; _output: Pbyte; _length: TIdC_LONG;
  schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_pcbc_encrypt_procname);
end;

(* Const before type ignored *)
function ERR_DES_quad_cksum(_input: Pbyte; _output: PDES_cblock; _length: TIdC_LONG;
  out_count: TIdC_INT; seed: PDES_cblock): DES_LONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_quad_cksum_procname);
end;

function ERR_DES_random_key(ret: PDES_cblock): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_random_key_procname);
end;

procedure ERR_DES_set_odd_parity(key: PDES_cblock); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_set_odd_parity_procname);
end;

function ERR_DES_check_key_parity(key: Pconst_DES_cblock): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_check_key_parity_procname);
end;

function ERR_DES_is_weak_key(key: Pconst_DES_cblock): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_is_weak_key_procname);
end;

{
  * DES_set_key (= set_key = DES_key_sched = key_sched) calls
  * DES_set_key_checked if global variable DES_check_key is set,
  * DES_set_key_unchecked otherwise.
}
function ERR_DES_set_key(key: Pconst_DES_cblock; var schedule: DES_key_schedule)
  : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_set_key_procname);
end;

function ERR_DES_key_sched(key: Pconst_DES_cblock; schedule: PDES_key_schedule)
  : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_key_sched_procname);
end;

function ERR_DES_set_key_checked(key: Pconst_DES_cblock;
  schedule: PDES_key_schedule): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_set_key_checked_procname);
end;

procedure ERR_DES_set_key_unchecked(key: Pconst_DES_cblock;
  schedule: PDES_key_schedule); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_set_key_unchecked_procname);
end;

(* Const before type ignored *)
procedure ERR_DES_string_to_key(_str: PIdAnsiChar; key: PDES_cblock); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_string_to_key_procname);
end;

(* Const before type ignored *)
procedure ERR_DES_string_to_2keys(_str: PIdAnsiChar; key1: PDES_cblock;
  key2: PDES_cblock); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_string_to_2keys_procname);
end;

(* Const before type ignored *)
procedure ERR_DES_cfb64_encrypt(in_: Pbyte; out_: Pbyte; _length: TIdC_LONG;
  schedule: PDES_key_schedule; ivec: PDES_cblock; num: PIdC_INT; enc: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_cfb64_encrypt_procname);
end;

(* Const before type ignored *)
procedure ERR_DES_ofb64_encrypt(in_: Pbyte; out_: Pbyte; _length: TIdC_LONG;
  schedule: PDES_key_schedule; ivec: PDES_cblock; num: PIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_ofb64_encrypt_procname);
end;

procedure ERR_DES_fixup_key_parity(key: PDES_cblock); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DES_fixup_key_parity_procname);
end;

  {$I TaurusTLSNoRetValOn.inc}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);

var
  FuncLoadError: boolean;

begin
  DES_ecb2_encrypt := LoadLibFunction(ADllHandle, DES_ecb2_encrypt_procname);
  FuncLoadError := not assigned(DES_ecb2_encrypt);
  if FuncLoadError then
  begin
{$IF not defined(DES_ecb2_encrypt_allownil)}
    DES_ecb2_encrypt := ERR_DES_ecb2_encrypt;
{$IFEND}
{$IF declared(DES_ecb2_encrypt_introduced)}
    if LibVersion < DES_ecb2_encrypt_introduced then
    begin
{$IF declared(FC_DES_ecb2_encrypt)}
      DES_ecb2_encrypt := FC_DES_ecb2_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_ecb2_encrypt_removed)}
    if DES_ecb2_encrypt_removed <= LibVersion then
    begin
{$IF declared(_DES_ecb2_encrypt)}
      DES_ecb2_encrypt := _DES_ecb2_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_ecb2_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ecb2_encrypt');
{$IFEND}
  end;

  DES_ede2_cbc_encrypt := LoadLibFunction(ADllHandle,
    DES_ede2_cbc_encrypt_procname);
  FuncLoadError := not assigned(DES_ede2_cbc_encrypt);
  if FuncLoadError then
  begin
{$IF not defined(DES_ede2_cbc_encrypt_allownil)}
    DES_ede2_cbc_encrypt := ERR_DES_ede2_cbc_encrypt;
{$IFEND}
{$IF declared(DES_ede2_cbc_encrypt_introduced)}
    if LibVersion < DES_ede2_cbc_encrypt_introduced then
    begin
{$IF declared(FC_DES_ede2_cbc_encrypt)}
      DES_ede2_cbc_encrypt := FC_DES_ede2_cbc_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_ede2_cbc_encrypt_removed)}
    if DES_ede2_cbc_encrypt_removed <= LibVersion then
    begin
{$IF declared(_DES_ede2_cbc_encrypt)}
      DES_ede2_cbc_encrypt := _DES_ede2_cbc_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_ede2_cbc_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ede2_cbc_encrypt');
{$IFEND}
  end;

  DES_ede2_cfb64_encrypt := LoadLibFunction(ADllHandle,
    DES_ede2_cfb64_encrypt_procname);
  FuncLoadError := not assigned(DES_ede2_cfb64_encrypt);
  if FuncLoadError then
  begin
{$IF not defined(DES_ede2_cfb64_encrypt_allownil)}
    DES_ede2_cfb64_encrypt := ERR_DES_ede2_cfb64_encrypt;
{$IFEND}
{$IF declared(DES_ede2_cfb64_encrypt_introduced)}
    if LibVersion < DES_ede2_cfb64_encrypt_introduced then
    begin
{$IF declared(FC_DES_ede2_cfb64_encrypt)}
      DES_ede2_cfb64_encrypt := FC_DES_ede2_cfb64_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_ede2_cfb64_encrypt_removed)}
    if DES_ede2_cfb64_encrypt_removed <= LibVersion then
    begin
{$IF declared(_DES_ede2_cfb64_encrypt)}
      DES_ede2_cfb64_encrypt := _DES_ede2_cfb64_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_ede2_cfb64_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ede2_cfb64_encrypt');
{$IFEND}
  end;

  DES_ede2_ofb64_encrypt := LoadLibFunction(ADllHandle,
    DES_ede2_ofb64_encrypt_procname);
  FuncLoadError := not assigned(DES_ede2_ofb64_encrypt);
  if FuncLoadError then
  begin
{$IF not defined(DES_ede2_ofb64_encrypt_allownil)}
    DES_ede2_ofb64_encrypt := ERR_DES_ede2_ofb64_encrypt;
{$IFEND}
{$IF declared(DES_ede2_ofb64_encrypt_introduced)}
    if LibVersion < DES_ede2_ofb64_encrypt_introduced then
    begin
{$IF declared(FC_DES_ede2_ofb64_encrypt)}
      DES_ede2_ofb64_encrypt := FC_DES_ede2_ofb64_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_ede2_ofb64_encrypt_removed)}
    if DES_ede2_ofb64_encrypt_removed <= LibVersion then
    begin
{$IF declared(_DES_ede2_ofb64_encrypt)}
      DES_ede2_ofb64_encrypt := _DES_ede2_ofb64_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_ede2_ofb64_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ede2_ofb64_encrypt');
{$IFEND}
  end;

  DES_options := LoadLibFunction(ADllHandle, DES_options_procname);
  FuncLoadError := not assigned(DES_options);
  if FuncLoadError then
  begin
{$IF not defined(DES_options_allownil)}
    DES_options := ERR_DES_options;
{$IFEND}
{$IF declared(DES_options_introduced)}
    if LibVersion < DES_options_introduced then
    begin
{$IF declared(FC_DES_options)}
      DES_options := FC_DES_options;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_options_removed)}
    if DES_options_removed <= LibVersion then
    begin
{$IF declared(_DES_options)}
      DES_options := _DES_options;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_options_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_options');
{$IFEND}
  end;

  DES_ecb3_encrypt := LoadLibFunction(ADllHandle, DES_ecb3_encrypt_procname);
  FuncLoadError := not assigned(DES_ecb3_encrypt);
  if FuncLoadError then
  begin
{$IF not defined(DES_ecb3_encrypt_allownil)}
    DES_ecb3_encrypt := ERR_DES_ecb3_encrypt;
{$IFEND}
{$IF declared(DES_ecb3_encrypt_introduced)}
    if LibVersion < DES_ecb3_encrypt_introduced then
    begin
{$IF declared(FC_DES_ecb3_encrypt)}
      DES_ecb3_encrypt := FC_DES_ecb3_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_ecb3_encrypt_removed)}
    if DES_ecb3_encrypt_removed <= LibVersion then
    begin
{$IF declared(_DES_ecb3_encrypt)}
      DES_ecb3_encrypt := _DES_ecb3_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_ecb3_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ecb3_encrypt');
{$IFEND}
  end;

  DES_cbc_cksum := LoadLibFunction(ADllHandle, DES_cbc_cksum_procname);
  FuncLoadError := not assigned(DES_cbc_cksum);
  if FuncLoadError then
  begin
{$IF not defined(DES_cbc_cksum_allownil)}
    DES_cbc_cksum := ERR_DES_cbc_cksum;
{$IFEND}
{$IF declared(DES_cbc_cksum_introduced)}
    if LibVersion < DES_cbc_cksum_introduced then
    begin
{$IF declared(FC_DES_cbc_cksum)}
      DES_cbc_cksum := FC_DES_cbc_cksum;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_cbc_cksum_removed)}
    if DES_cbc_cksum_removed <= LibVersion then
    begin
{$IF declared(_DES_cbc_cksum)}
      DES_cbc_cksum := _DES_cbc_cksum;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_cbc_cksum_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_cbc_cksum');
{$IFEND}
  end;

  DES_cbc_encrypt := LoadLibFunction(ADllHandle, DES_cbc_encrypt_procname);
  FuncLoadError := not assigned(DES_cbc_encrypt);
  if FuncLoadError then
  begin
{$IF not defined(DES_cbc_encrypt_allownil)}
    DES_cbc_encrypt := ERR_DES_cbc_encrypt;
{$IFEND}
{$IF declared(DES_cbc_encrypt_introduced)}
    if LibVersion < DES_cbc_encrypt_introduced then
    begin
{$IF declared(FC_DES_cbc_encrypt)}
      DES_cbc_encrypt := FC_DES_cbc_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_cbc_encrypt_removed)}
    if DES_cbc_encrypt_removed <= LibVersion then
    begin
{$IF declared(_DES_cbc_encrypt)}
      DES_cbc_encrypt := _DES_cbc_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_cbc_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_cbc_encrypt');
{$IFEND}
  end;

  DES_ncbc_encrypt := LoadLibFunction(ADllHandle, DES_ncbc_encrypt_procname);
  FuncLoadError := not assigned(DES_ncbc_encrypt);
  if FuncLoadError then
  begin
{$IF not defined(DES_ncbc_encrypt_allownil)}
    DES_ncbc_encrypt := ERR_DES_ncbc_encrypt;
{$IFEND}
{$IF declared(DES_ncbc_encrypt_introduced)}
    if LibVersion < DES_ncbc_encrypt_introduced then
    begin
{$IF declared(FC_DES_ncbc_encrypt)}
      DES_ncbc_encrypt := FC_DES_ncbc_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_ncbc_encrypt_removed)}
    if DES_ncbc_encrypt_removed <= LibVersion then
    begin
{$IF declared(_DES_ncbc_encrypt)}
      DES_ncbc_encrypt := _DES_ncbc_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_ncbc_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ncbc_encrypt');
{$IFEND}
  end;

  DES_xcbc_encrypt := LoadLibFunction(ADllHandle, DES_xcbc_encrypt_procname);
  FuncLoadError := not assigned(DES_xcbc_encrypt);
  if FuncLoadError then
  begin
{$IF not defined(DES_xcbc_encrypt_allownil)}
    DES_xcbc_encrypt := ERR_DES_xcbc_encrypt;
{$IFEND}
{$IF declared(DES_xcbc_encrypt_introduced)}
    if LibVersion < DES_xcbc_encrypt_introduced then
    begin
{$IF declared(FC_DES_xcbc_encrypt)}
      DES_xcbc_encrypt := FC_DES_xcbc_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_xcbc_encrypt_removed)}
    if DES_xcbc_encrypt_removed <= LibVersion then
    begin
{$IF declared(_DES_xcbc_encrypt)}
      DES_xcbc_encrypt := _DES_xcbc_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_xcbc_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_xcbc_encrypt');
{$IFEND}
  end;

  DES_cfb_encrypt := LoadLibFunction(ADllHandle, DES_cfb_encrypt_procname);
  FuncLoadError := not assigned(DES_cfb_encrypt);
  if FuncLoadError then
  begin
{$IF not defined(DES_cfb_encrypt_allownil)}
    DES_cfb_encrypt := ERR_DES_cfb_encrypt;
{$IFEND}
{$IF declared(DES_cfb_encrypt_introduced)}
    if LibVersion < DES_cfb_encrypt_introduced then
    begin
{$IF declared(FC_DES_cfb_encrypt)}
      DES_cfb_encrypt := FC_DES_cfb_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_cfb_encrypt_removed)}
    if DES_cfb_encrypt_removed <= LibVersion then
    begin
{$IF declared(_DES_cfb_encrypt)}
      DES_cfb_encrypt := _DES_cfb_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_cfb_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_cfb_encrypt');
{$IFEND}
  end;

  DES_ecb_encrypt := LoadLibFunction(ADllHandle, DES_ecb_encrypt_procname);
  FuncLoadError := not assigned(DES_ecb_encrypt);
  if FuncLoadError then
  begin
{$IF not defined(DES_ecb_encrypt_allownil)}
    DES_ecb_encrypt := ERR_DES_ecb_encrypt;
{$IFEND}
{$IF declared(DES_ecb_encrypt_introduced)}
    if LibVersion < DES_ecb_encrypt_introduced then
    begin
{$IF declared(FC_DES_ecb_encrypt)}
      DES_ecb_encrypt := FC_DES_ecb_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_ecb_encrypt_removed)}
    if DES_ecb_encrypt_removed <= LibVersion then
    begin
{$IF declared(_DES_ecb_encrypt)}
      DES_ecb_encrypt := _DES_ecb_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_ecb_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ecb_encrypt');
{$IFEND}
  end;

  DES_encrypt1 := LoadLibFunction(ADllHandle, DES_encrypt1_procname);
  FuncLoadError := not assigned(DES_encrypt1);
  if FuncLoadError then
  begin
{$IF not defined(DES_encrypt1_allownil)}
    DES_encrypt1 := ERR_DES_encrypt1;
{$IFEND}
{$IF declared(DES_encrypt1_introduced)}
    if LibVersion < DES_encrypt1_introduced then
    begin
{$IF declared(FC_DES_encrypt1)}
      DES_encrypt1 := FC_DES_encrypt1;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_encrypt1_removed)}
    if DES_encrypt1_removed <= LibVersion then
    begin
{$IF declared(_DES_encrypt1)}
      DES_encrypt1 := _DES_encrypt1;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_encrypt1_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_encrypt1');
{$IFEND}
  end;

  DES_encrypt2 := LoadLibFunction(ADllHandle, DES_encrypt2_procname);
  FuncLoadError := not assigned(DES_encrypt2);
  if FuncLoadError then
  begin
{$IF not defined(DES_encrypt2_allownil)}
    DES_encrypt2 := ERR_DES_encrypt2;
{$IFEND}
{$IF declared(DES_encrypt2_introduced)}
    if LibVersion < DES_encrypt2_introduced then
    begin
{$IF declared(FC_DES_encrypt2)}
      DES_encrypt2 := FC_DES_encrypt2;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_encrypt2_removed)}
    if DES_encrypt2_removed <= LibVersion then
    begin
{$IF declared(_DES_encrypt2)}
      DES_encrypt2 := _DES_encrypt2;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_encrypt2_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_encrypt2');
{$IFEND}
  end;

  DES_encrypt3 := LoadLibFunction(ADllHandle, DES_encrypt3_procname);
  FuncLoadError := not assigned(DES_encrypt3);
  if FuncLoadError then
  begin
{$IF not defined(DES_encrypt3_allownil)}
    DES_encrypt3 := ERR_DES_encrypt3;
{$IFEND}
{$IF declared(DES_encrypt3_introduced)}
    if LibVersion < DES_encrypt3_introduced then
    begin
{$IF declared(FC_DES_encrypt3)}
      DES_encrypt3 := FC_DES_encrypt3;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_encrypt3_removed)}
    if DES_encrypt3_removed <= LibVersion then
    begin
{$IF declared(_DES_encrypt3)}
      DES_encrypt3 := _DES_encrypt3;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_encrypt3_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_encrypt3');
{$IFEND}
  end;

  DES_decrypt3 := LoadLibFunction(ADllHandle, DES_decrypt3_procname);
  FuncLoadError := not assigned(DES_decrypt3);
  if FuncLoadError then
  begin
{$IF not defined(DES_decrypt3_allownil)}
    DES_decrypt3 := ERR_DES_decrypt3;
{$IFEND}
{$IF declared(DES_decrypt3_introduced)}
    if LibVersion < DES_decrypt3_introduced then
    begin
{$IF declared(FC_DES_decrypt3)}
      DES_decrypt3 := FC_DES_decrypt3;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_decrypt3_removed)}
    if DES_decrypt3_removed <= LibVersion then
    begin
{$IF declared(_DES_decrypt3)}
      DES_decrypt3 := _DES_decrypt3;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_decrypt3_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_decrypt3');
{$IFEND}
  end;

  DES_ede3_cbc_encrypt := LoadLibFunction(ADllHandle,
    DES_ede3_cbc_encrypt_procname);
  FuncLoadError := not assigned(DES_ede3_cbc_encrypt);
  if FuncLoadError then
  begin
{$IF not defined(DES_ede3_cbc_encrypt_allownil)}
    DES_ede3_cbc_encrypt := ERR_DES_ede3_cbc_encrypt;
{$IFEND}
{$IF declared(DES_ede3_cbc_encrypt_introduced)}
    if LibVersion < DES_ede3_cbc_encrypt_introduced then
    begin
{$IF declared(FC_DES_ede3_cbc_encrypt)}
      DES_ede3_cbc_encrypt := FC_DES_ede3_cbc_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_ede3_cbc_encrypt_removed)}
    if DES_ede3_cbc_encrypt_removed <= LibVersion then
    begin
{$IF declared(_DES_ede3_cbc_encrypt)}
      DES_ede3_cbc_encrypt := _DES_ede3_cbc_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_ede3_cbc_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ede3_cbc_encrypt');
{$IFEND}
  end;

  DES_ede3_cfb64_encrypt := LoadLibFunction(ADllHandle,
    DES_ede3_cfb64_encrypt_procname);
  FuncLoadError := not assigned(DES_ede3_cfb64_encrypt);
  if FuncLoadError then
  begin
{$IF not defined(DES_ede3_cfb64_encrypt_allownil)}
    DES_ede3_cfb64_encrypt := ERR_DES_ede3_cfb64_encrypt;
{$IFEND}
{$IF declared(DES_ede3_cfb64_encrypt_introduced)}
    if LibVersion < DES_ede3_cfb64_encrypt_introduced then
    begin
{$IF declared(FC_DES_ede3_cfb64_encrypt)}
      DES_ede3_cfb64_encrypt := FC_DES_ede3_cfb64_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_ede3_cfb64_encrypt_removed)}
    if DES_ede3_cfb64_encrypt_removed <= LibVersion then
    begin
{$IF declared(_DES_ede3_cfb64_encrypt)}
      DES_ede3_cfb64_encrypt := _DES_ede3_cfb64_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_ede3_cfb64_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ede3_cfb64_encrypt');
{$IFEND}
  end;

  DES_ede3_cfb_encrypt := LoadLibFunction(ADllHandle,
    DES_ede3_cfb_encrypt_procname);
  FuncLoadError := not assigned(DES_ede3_cfb_encrypt);
  if FuncLoadError then
  begin
{$IF not defined(DES_ede3_cfb_encrypt_allownil)}
    DES_ede3_cfb_encrypt := ERR_DES_ede3_cfb_encrypt;
{$IFEND}
{$IF declared(DES_ede3_cfb_encrypt_introduced)}
    if LibVersion < DES_ede3_cfb_encrypt_introduced then
    begin
{$IF declared(FC_DES_ede3_cfb_encrypt)}
      DES_ede3_cfb_encrypt := FC_DES_ede3_cfb_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_ede3_cfb_encrypt_removed)}
    if DES_ede3_cfb_encrypt_removed <= LibVersion then
    begin
{$IF declared(_DES_ede3_cfb_encrypt)}
      DES_ede3_cfb_encrypt := _DES_ede3_cfb_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_ede3_cfb_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ede3_cfb_encrypt');
{$IFEND}
  end;

  DES_ede3_ofb64_encrypt := LoadLibFunction(ADllHandle,
    DES_ede3_ofb64_encrypt_procname);
  FuncLoadError := not assigned(DES_ede3_ofb64_encrypt);
  if FuncLoadError then
  begin
{$IF not defined(DES_ede3_ofb64_encrypt_allownil)}
    DES_ede3_ofb64_encrypt := ERR_DES_ede3_ofb64_encrypt;
{$IFEND}
{$IF declared(DES_ede3_ofb64_encrypt_introduced)}
    if LibVersion < DES_ede3_ofb64_encrypt_introduced then
    begin
{$IF declared(FC_DES_ede3_ofb64_encrypt)}
      DES_ede3_ofb64_encrypt := FC_DES_ede3_ofb64_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_ede3_ofb64_encrypt_removed)}
    if DES_ede3_ofb64_encrypt_removed <= LibVersion then
    begin
{$IF declared(_DES_ede3_ofb64_encrypt)}
      DES_ede3_ofb64_encrypt := _DES_ede3_ofb64_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_ede3_ofb64_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ede3_ofb64_encrypt');
{$IFEND}
  end;

  DES_fcrypt := LoadLibFunction(ADllHandle, DES_fcrypt_procname);
  FuncLoadError := not assigned(DES_fcrypt);
  if FuncLoadError then
  begin
{$IF not defined(DES_fcrypt_allownil)}
    DES_fcrypt := ERR_DES_fcrypt;
{$IFEND}
{$IF declared(DES_fcrypt_introduced)}
    if LibVersion < DES_fcrypt_introduced then
    begin
{$IF declared(FC_DES_fcrypt)}
      DES_fcrypt := FC_DES_fcrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_fcrypt_removed)}
    if DES_fcrypt_removed <= LibVersion then
    begin
{$IF declared(_DES_fcrypt)}
      DES_fcrypt := _DES_fcrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_fcrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_fcrypt');
{$IFEND}
  end;

  DES_crypt := LoadLibFunction(ADllHandle, DES_crypt_procname);
  FuncLoadError := not assigned(DES_crypt);
  if FuncLoadError then
  begin
{$IF not defined(DES_crypt_allownil)}
    DES_crypt := ERR_DES_crypt;
{$IFEND}
{$IF declared(DES_crypt_introduced)}
    if LibVersion < DES_crypt_introduced then
    begin
{$IF declared(FC_DES_crypt)}
      DES_crypt := FC_DES_crypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_crypt_removed)}
    if DES_crypt_removed <= LibVersion then
    begin
{$IF declared(_DES_crypt)}
      DES_crypt := _DES_crypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_crypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_crypt');
{$IFEND}
  end;

  DES_ofb_encrypt := LoadLibFunction(ADllHandle, DES_ofb_encrypt_procname);
  FuncLoadError := not assigned(DES_ofb_encrypt);
  if FuncLoadError then
  begin
{$IF not defined(DES_ofb_encrypt_allownil)}
    DES_ofb_encrypt := ERR_DES_ofb_encrypt;
{$IFEND}
{$IF declared(DES_ofb_encrypt_introduced)}
    if LibVersion < DES_ofb_encrypt_introduced then
    begin
{$IF declared(FC_DES_ofb_encrypt)}
      DES_ofb_encrypt := FC_DES_ofb_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_ofb_encrypt_removed)}
    if DES_ofb_encrypt_removed <= LibVersion then
    begin
{$IF declared(_DES_ofb_encrypt)}
      DES_ofb_encrypt := _DES_ofb_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_ofb_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ofb_encrypt');
{$IFEND}
  end;

  DES_pcbc_encrypt := LoadLibFunction(ADllHandle, DES_pcbc_encrypt_procname);
  FuncLoadError := not assigned(DES_pcbc_encrypt);
  if FuncLoadError then
  begin
{$IF not defined(DES_pcbc_encrypt_allownil)}
    DES_pcbc_encrypt := ERR_DES_pcbc_encrypt;
{$IFEND}
{$IF declared(DES_pcbc_encrypt_introduced)}
    if LibVersion < DES_pcbc_encrypt_introduced then
    begin
{$IF declared(FC_DES_pcbc_encrypt)}
      DES_pcbc_encrypt := FC_DES_pcbc_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_pcbc_encrypt_removed)}
    if DES_pcbc_encrypt_removed <= LibVersion then
    begin
{$IF declared(_DES_pcbc_encrypt)}
      DES_pcbc_encrypt := _DES_pcbc_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_pcbc_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_pcbc_encrypt');
{$IFEND}
  end;

  DES_quad_cksum := LoadLibFunction(ADllHandle, DES_quad_cksum_procname);
  FuncLoadError := not assigned(DES_quad_cksum);
  if FuncLoadError then
  begin
{$IF not defined(DES_quad_cksum_allownil)}
    DES_quad_cksum := ERR_DES_quad_cksum;
{$IFEND}
{$IF declared(DES_quad_cksum_introduced)}
    if LibVersion < DES_quad_cksum_introduced then
    begin
{$IF declared(FC_DES_quad_cksum)}
      DES_quad_cksum := FC_DES_quad_cksum;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_quad_cksum_removed)}
    if DES_quad_cksum_removed <= LibVersion then
    begin
{$IF declared(_DES_quad_cksum)}
      DES_quad_cksum := _DES_quad_cksum;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_quad_cksum_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_quad_cksum');
{$IFEND}
  end;

  DES_random_key := LoadLibFunction(ADllHandle, DES_random_key_procname);
  FuncLoadError := not assigned(DES_random_key);
  if FuncLoadError then
  begin
{$IF not defined(DES_random_key_allownil)}
    DES_random_key := ERR_DES_random_key;
{$IFEND}
{$IF declared(DES_random_key_introduced)}
    if LibVersion < DES_random_key_introduced then
    begin
{$IF declared(FC_DES_random_key)}
      DES_random_key := FC_DES_random_key;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_random_key_removed)}
    if DES_random_key_removed <= LibVersion then
    begin
{$IF declared(_DES_random_key)}
      DES_random_key := _DES_random_key;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_random_key_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_random_key');
{$IFEND}
  end;

  DES_set_odd_parity := LoadLibFunction(ADllHandle,
    DES_set_odd_parity_procname);
  FuncLoadError := not assigned(DES_set_odd_parity);
  if FuncLoadError then
  begin
{$IF not defined(DES_set_odd_parity_allownil)}
    DES_set_odd_parity := ERR_DES_set_odd_parity;
{$IFEND}
{$IF declared(DES_set_odd_parity_introduced)}
    if LibVersion < DES_set_odd_parity_introduced then
    begin
{$IF declared(FC_DES_set_odd_parity)}
      DES_set_odd_parity := FC_DES_set_odd_parity;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_set_odd_parity_removed)}
    if DES_set_odd_parity_removed <= LibVersion then
    begin
{$IF declared(_DES_set_odd_parity)}
      DES_set_odd_parity := _DES_set_odd_parity;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_set_odd_parity_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_set_odd_parity');
{$IFEND}
  end;

  DES_check_key_parity := LoadLibFunction(ADllHandle,
    DES_check_key_parity_procname);
  FuncLoadError := not assigned(DES_check_key_parity);
  if FuncLoadError then
  begin
{$IF not defined(DES_check_key_parity_allownil)}
    DES_check_key_parity := ERR_DES_check_key_parity;
{$IFEND}
{$IF declared(DES_check_key_parity_introduced)}
    if LibVersion < DES_check_key_parity_introduced then
    begin
{$IF declared(FC_DES_check_key_parity)}
      DES_check_key_parity := FC_DES_check_key_parity;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_check_key_parity_removed)}
    if DES_check_key_parity_removed <= LibVersion then
    begin
{$IF declared(_DES_check_key_parity)}
      DES_check_key_parity := _DES_check_key_parity;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_check_key_parity_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_check_key_parity');
{$IFEND}
  end;

  DES_is_weak_key := LoadLibFunction(ADllHandle, DES_is_weak_key_procname);
  FuncLoadError := not assigned(DES_is_weak_key);
  if FuncLoadError then
  begin
{$IF not defined(DES_is_weak_key_allownil)}
    DES_is_weak_key := ERR_DES_is_weak_key;
{$IFEND}
{$IF declared(DES_is_weak_key_introduced)}
    if LibVersion < DES_is_weak_key_introduced then
    begin
{$IF declared(FC_DES_is_weak_key)}
      DES_is_weak_key := FC_DES_is_weak_key;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_is_weak_key_removed)}
    if DES_is_weak_key_removed <= LibVersion then
    begin
{$IF declared(_DES_is_weak_key)}
      DES_is_weak_key := _DES_is_weak_key;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_is_weak_key_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_is_weak_key');
{$IFEND}
  end;

  DES_set_key := LoadLibFunction(ADllHandle, DES_set_key_procname);
  FuncLoadError := not assigned(DES_set_key);
  if FuncLoadError then
  begin
{$IF not defined(DES_set_key_allownil)}
    DES_set_key := ERR_DES_set_key;
{$IFEND}
{$IF declared(DES_set_key_introduced)}
    if LibVersion < DES_set_key_introduced then
    begin
{$IF declared(FC_DES_set_key)}
      DES_set_key := FC_DES_set_key;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_set_key_removed)}
    if DES_set_key_removed <= LibVersion then
    begin
{$IF declared(_DES_set_key)}
      DES_set_key := _DES_set_key;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_set_key_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_set_key');
{$IFEND}
  end;

  DES_key_sched := LoadLibFunction(ADllHandle, DES_key_sched_procname);
  FuncLoadError := not assigned(DES_key_sched);
  if FuncLoadError then
  begin
{$IF not defined(DES_key_sched_allownil)}
    DES_key_sched := ERR_DES_key_sched;
{$IFEND}
{$IF declared(DES_key_sched_introduced)}
    if LibVersion < DES_key_sched_introduced then
    begin
{$IF declared(FC_DES_key_sched)}
      DES_key_sched := FC_DES_key_sched;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_key_sched_removed)}
    if DES_key_sched_removed <= LibVersion then
    begin
{$IF declared(_DES_key_sched)}
      DES_key_sched := _DES_key_sched;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_key_sched_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_key_sched');
{$IFEND}
  end;

  DES_set_key_checked := LoadLibFunction(ADllHandle,
    DES_set_key_checked_procname);
  FuncLoadError := not assigned(DES_set_key_checked);
  if FuncLoadError then
  begin
{$IF not defined(DES_set_key_checked_allownil)}
    DES_set_key_checked := ERR_DES_set_key_checked;
{$IFEND}
{$IF declared(DES_set_key_checked_introduced)}
    if LibVersion < DES_set_key_checked_introduced then
    begin
{$IF declared(FC_DES_set_key_checked)}
      DES_set_key_checked := FC_DES_set_key_checked;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_set_key_checked_removed)}
    if DES_set_key_checked_removed <= LibVersion then
    begin
{$IF declared(_DES_set_key_checked)}
      DES_set_key_checked := _DES_set_key_checked;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_set_key_checked_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_set_key_checked');
{$IFEND}
  end;

  DES_set_key_unchecked := LoadLibFunction(ADllHandle,
    DES_set_key_unchecked_procname);
  FuncLoadError := not assigned(DES_set_key_unchecked);
  if FuncLoadError then
  begin
{$IF not defined(DES_set_key_unchecked_allownil)}
    DES_set_key_unchecked := ERR_DES_set_key_unchecked;
{$IFEND}
{$IF declared(DES_set_key_unchecked_introduced)}
    if LibVersion < DES_set_key_unchecked_introduced then
    begin
{$IF declared(FC_DES_set_key_unchecked)}
      DES_set_key_unchecked := FC_DES_set_key_unchecked;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_set_key_unchecked_removed)}
    if DES_set_key_unchecked_removed <= LibVersion then
    begin
{$IF declared(_DES_set_key_unchecked)}
      DES_set_key_unchecked := _DES_set_key_unchecked;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_set_key_unchecked_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_set_key_unchecked');
{$IFEND}
  end;

  DES_string_to_key := LoadLibFunction(ADllHandle, DES_string_to_key_procname);
  FuncLoadError := not assigned(DES_string_to_key);
  if FuncLoadError then
  begin
{$IF not defined(DES_string_to_key_allownil)}
    DES_string_to_key := ERR_DES_string_to_key;
{$IFEND}
{$IF declared(DES_string_to_key_introduced)}
    if LibVersion < DES_string_to_key_introduced then
    begin
{$IF declared(FC_DES_string_to_key)}
      DES_string_to_key := FC_DES_string_to_key;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_string_to_key_removed)}
    if DES_string_to_key_removed <= LibVersion then
    begin
{$IF declared(_DES_string_to_key)}
      DES_string_to_key := _DES_string_to_key;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_string_to_key_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_string_to_key');
{$IFEND}
  end;

  DES_string_to_2keys := LoadLibFunction(ADllHandle,
    DES_string_to_2keys_procname);
  FuncLoadError := not assigned(DES_string_to_2keys);
  if FuncLoadError then
  begin
{$IF not defined(DES_string_to_2keys_allownil)}
    DES_string_to_2keys := ERR_DES_string_to_2keys;
{$IFEND}
{$IF declared(DES_string_to_2keys_introduced)}
    if LibVersion < DES_string_to_2keys_introduced then
    begin
{$IF declared(FC_DES_string_to_2keys)}
      DES_string_to_2keys := FC_DES_string_to_2keys;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_string_to_2keys_removed)}
    if DES_string_to_2keys_removed <= LibVersion then
    begin
{$IF declared(_DES_string_to_2keys)}
      DES_string_to_2keys := _DES_string_to_2keys;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_string_to_2keys_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_string_to_2keys');
{$IFEND}
  end;

  DES_cfb64_encrypt := LoadLibFunction(ADllHandle, DES_cfb64_encrypt_procname);
  FuncLoadError := not assigned(DES_cfb64_encrypt);
  if FuncLoadError then
  begin
{$IF not defined(DES_cfb64_encrypt_allownil)}
    DES_cfb64_encrypt := ERR_DES_cfb64_encrypt;
{$IFEND}
{$IF declared(DES_cfb64_encrypt_introduced)}
    if LibVersion < DES_cfb64_encrypt_introduced then
    begin
{$IF declared(FC_DES_cfb64_encrypt)}
      DES_cfb64_encrypt := FC_DES_cfb64_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_cfb64_encrypt_removed)}
    if DES_cfb64_encrypt_removed <= LibVersion then
    begin
{$IF declared(_DES_cfb64_encrypt)}
      DES_cfb64_encrypt := _DES_cfb64_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_cfb64_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_cfb64_encrypt');
{$IFEND}
  end;

  DES_ofb64_encrypt := LoadLibFunction(ADllHandle, DES_ofb64_encrypt_procname);
  FuncLoadError := not assigned(DES_ofb64_encrypt);
  if FuncLoadError then
  begin
{$IF not defined(DES_ofb64_encrypt_allownil)}
    DES_ofb64_encrypt := ERR_DES_ofb64_encrypt;
{$IFEND}
{$IF declared(DES_ofb64_encrypt_introduced)}
    if LibVersion < DES_ofb64_encrypt_introduced then
    begin
{$IF declared(FC_DES_ofb64_encrypt)}
      DES_ofb64_encrypt := FC_DES_ofb64_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_ofb64_encrypt_removed)}
    if DES_ofb64_encrypt_removed <= LibVersion then
    begin
{$IF declared(_DES_ofb64_encrypt)}
      DES_ofb64_encrypt := _DES_ofb64_encrypt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_ofb64_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_ofb64_encrypt');
{$IFEND}
  end;

  DES_fixup_key_parity := LoadLibFunction(ADllHandle,
    DES_fixup_key_parity_procname);
  FuncLoadError := not assigned(DES_fixup_key_parity);
  if FuncLoadError then
  begin
{$IF not defined(DES_fixup_key_parity_allownil)}
    DES_fixup_key_parity := ERR_DES_fixup_key_parity;
{$IFEND}
{$IF declared(DES_fixup_key_parity_introduced)}
    if LibVersion < DES_fixup_key_parity_introduced then
    begin
{$IF declared(FC_DES_fixup_key_parity)}
      DES_fixup_key_parity := FC_DES_fixup_key_parity;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(DES_fixup_key_parity_removed)}
    if DES_fixup_key_parity_removed <= LibVersion then
    begin
{$IF declared(_DES_fixup_key_parity)}
      DES_fixup_key_parity := _DES_fixup_key_parity;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(DES_fixup_key_parity_allownil)}
    if FuncLoadError then
      AFailed.Add('DES_fixup_key_parity');
{$IFEND}
  end;

end;

procedure Unload;
begin
  DES_ecb2_encrypt := nil; { removed 1.0.0 }
  DES_ede2_cbc_encrypt := nil; { removed 1.0.0 }
  DES_ede2_cfb64_encrypt := nil; { removed 1.0.0 }
  DES_ede2_ofb64_encrypt := nil; { removed 1.0.0 }
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
  DES_fixup_key_parity := nil; { removed 1.0.0 }
end;
  {$ENDIF}
{$ELSE}

procedure DES_ecb2_encrypt(_input: Pconst_DES_cblock; _output: PDES_cblock;
  ks1: PDES_key_schedule; ks2: PDES_key_schedule; enc: TIdC_INT);
begin
  DES_ecb3_encrypt(_input, _output, ks1, ks2, ks1, enc);
end;

procedure DES_ede2_cbc_encrypt(_input: Pbyte; _output: Pbyte; _length: TIdC_LONG;
  ks1: PDES_key_schedule; ks2: PDES_key_schedule; ivec: PDES_cblock;
  enc: TIdC_INT);
begin
  DES_ede3_cbc_encrypt(_input, _output, _length, ks1, ks2, ks1, ivec, enc);
end;

procedure DES_ede2_cfb64_encrypt(in_: Pbyte; out_: Pbyte; _length: TIdC_LONG; //FI:C102 - Too many parameters
  ks1: PDES_key_schedule; ks2: PDES_key_schedule; ivec: PDES_cblock;
  num: PIdC_INT; enc: TIdC_INT);
begin
  DES_ede3_cfb64_encrypt(in_, out_, _length, ks1, ks2, ks1, ivec, num, enc);
end;

procedure DES_ede2_ofb64_encrypt(in_: Pbyte; out_: Pbyte; _length: TIdC_LONG;
  ks1: PDES_key_schedule; ks2: PDES_key_schedule; ivec: PDES_cblock;
  num: PIdC_INT);
begin
  DES_ede3_ofb64_encrypt(in_, out_, _length, ks1, ks2, ks1, ivec, num);
end;

procedure DES_fixup_key_parity(key: PDES_cblock);
begin
  DES_set_odd_parity(key);
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization

Register_SSLLoader(Load, 'LibCrypto');
Register_SSLUnloader(Unload);
{$ENDIF}

end.
