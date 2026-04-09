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

unit TaurusTLSHeaders_asn1;

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
  Pstack_st_X509_ALGOR = ^Tstack_st_X509_ALGOR;
  Tstack_st_X509_ALGOR = record end;
  {$EXTERNALSYM Pstack_st_X509_ALGOR}

  Pasn1_string_st = ^Tasn1_string_st;
  Tasn1_string_st = record end;
  {$EXTERNALSYM Pasn1_string_st}

  PASN1_ENCODING_st = ^TASN1_ENCODING_st;
  TASN1_ENCODING_st = record end;
  {$EXTERNALSYM PASN1_ENCODING_st}

  PASN1_ENCODING = ^TASN1_ENCODING;
  TASN1_ENCODING = TASN1_ENCODING_st;
  {$EXTERNALSYM PASN1_ENCODING}

  Pasn1_string_table_st = ^Tasn1_string_table_st;
  Tasn1_string_table_st = record end;
  {$EXTERNALSYM Pasn1_string_table_st}

  Pstack_st_ASN1_STRING_TABLE = ^Tstack_st_ASN1_STRING_TABLE;
  Tstack_st_ASN1_STRING_TABLE = record end;
  {$EXTERNALSYM Pstack_st_ASN1_STRING_TABLE}

  PASN1_TEMPLATE_st = ^TASN1_TEMPLATE_st;
  TASN1_TEMPLATE_st = record end;
  {$EXTERNALSYM PASN1_TEMPLATE_st}

  PASN1_TEMPLATE = ^TASN1_TEMPLATE;
  TASN1_TEMPLATE = TASN1_TEMPLATE_st;
  {$EXTERNALSYM PASN1_TEMPLATE}

  PASN1_TLC_st = ^TASN1_TLC_st;
  TASN1_TLC_st = record end;
  {$EXTERNALSYM PASN1_TLC_st}

  PASN1_TLC = ^TASN1_TLC;
  TASN1_TLC = TASN1_TLC_st;
  {$EXTERNALSYM PASN1_TLC}

  PASN1_VALUE_st = ^TASN1_VALUE_st;
  TASN1_VALUE_st = record end;
  {$EXTERNALSYM PASN1_VALUE_st}

  PASN1_VALUE = ^TASN1_VALUE;
  TASN1_VALUE = TASN1_VALUE_st;
  {$EXTERNALSYM PASN1_VALUE}

  Pasn1_type_st = ^Tasn1_type_st;
  Tasn1_type_st = record end;
  {$EXTERNALSYM Pasn1_type_st}

  Punion (unnamed at /home/sasha/dev/openssl/include/openssl/asn1.h:526:5) = ^Tunion (unnamed at /home/sasha/dev/openssl/include/openssl/asn1.h:526:5);
  {$EXTERNALSYM Punion (unnamed at /home/sasha/dev/openssl/include/openssl/asn1.h:526:5)}

  Pstack_st_ASN1_TYPE = ^Tstack_st_ASN1_TYPE;
  Tstack_st_ASN1_TYPE = record end;
  {$EXTERNALSYM Pstack_st_ASN1_TYPE}

  PASN1_SEQUENCE_ANY = ^TASN1_SEQUENCE_ANY;
  TASN1_SEQUENCE_ANY = Tstack_st_ASN1_TYPE;
  {$EXTERNALSYM PASN1_SEQUENCE_ANY}

  PBIT_STRING_BITNAME_st = ^TBIT_STRING_BITNAME_st;
  TBIT_STRING_BITNAME_st = record end;
  {$EXTERNALSYM PBIT_STRING_BITNAME_st}

  PBIT_STRING_BITNAME = ^TBIT_STRING_BITNAME;
  TBIT_STRING_BITNAME = TBIT_STRING_BITNAME_st;
  {$EXTERNALSYM PBIT_STRING_BITNAME}

  Pstack_st_ASN1_OBJECT = ^Tstack_st_ASN1_OBJECT;
  Tstack_st_ASN1_OBJECT = record end;
  {$EXTERNALSYM Pstack_st_ASN1_OBJECT}

  Pstack_st_ASN1_INTEGER = ^Tstack_st_ASN1_INTEGER;
  Tstack_st_ASN1_INTEGER = record end;
  {$EXTERNALSYM Pstack_st_ASN1_INTEGER}

  Pstack_st_ASN1_UTF8STRING = ^Tstack_st_ASN1_UTF8STRING;
  Tstack_st_ASN1_UTF8STRING = record end;
  {$EXTERNALSYM Pstack_st_ASN1_UTF8STRING}

  Pstack_st_ASN1_GENERALSTRING = ^Tstack_st_ASN1_GENERALSTRING;
  Tstack_st_ASN1_GENERALSTRING = record end;
  {$EXTERNALSYM Pstack_st_ASN1_GENERALSTRING}


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  Tsk_X509_ALGOR_compfunc_func_cb = function(arg1: PPX509_ALGOR; arg2: PPX509_ALGOR): TIdC_INT; cdecl;
  Tsk_X509_ALGOR_freefunc_func_cb = procedure(arg1: PX509_ALGOR); cdecl;
  Tsk_X509_ALGOR_copyfunc_func_cb = function(arg1: PX509_ALGOR): PX509_ALGOR; cdecl;
  Tsk_ASN1_STRING_TABLE_compfunc_func_cb = function(arg1: PPASN1_STRING_TABLE; arg2: PPASN1_STRING_TABLE): TIdC_INT; cdecl;
  Tsk_ASN1_STRING_TABLE_freefunc_func_cb = procedure(arg1: PASN1_STRING_TABLE); cdecl;
  Tsk_ASN1_STRING_TABLE_copyfunc_func_cb = function(arg1: PASN1_STRING_TABLE): PASN1_STRING_TABLE; cdecl;
  Td2i_of_void_func_cb = function(arg1: PPointer; arg2: PPIdAnsiChar; arg3: TIdC_LONG): Pointer; cdecl;
  Ti2d_of_void_func_cb = function(arg1: Pointer; arg2: PPIdAnsiChar): TIdC_INT; cdecl;
  TOSSL_i2d_of_void_ctx_func_cb = function(arg1: Pointer; arg2: PPIdAnsiChar; arg3: Pointer): TIdC_INT; cdecl;
  TASN1_ITEM_EXP_func_cb = function: PASN1_ITEM; cdecl;
  Tsk_ASN1_TYPE_compfunc_func_cb = function(arg1: PPASN1_TYPE; arg2: PPASN1_TYPE): TIdC_INT; cdecl;
  Tsk_ASN1_TYPE_freefunc_func_cb = procedure(arg1: PASN1_TYPE); cdecl;
  Tsk_ASN1_TYPE_copyfunc_func_cb = function(arg1: PASN1_TYPE): PASN1_TYPE; cdecl;
  Tsk_ASN1_OBJECT_compfunc_func_cb = function(arg1: PPASN1_OBJECT; arg2: PPASN1_OBJECT): TIdC_INT; cdecl;
  Tsk_ASN1_OBJECT_freefunc_func_cb = procedure(arg1: PASN1_OBJECT); cdecl;
  Tsk_ASN1_OBJECT_copyfunc_func_cb = function(arg1: PASN1_OBJECT): PASN1_OBJECT; cdecl;
  Tsk_ASN1_INTEGER_compfunc_func_cb = function(arg1: PPASN1_INTEGER; arg2: PPASN1_INTEGER): TIdC_INT; cdecl;
  Tsk_ASN1_INTEGER_freefunc_func_cb = procedure(arg1: PASN1_INTEGER); cdecl;
  Tsk_ASN1_INTEGER_copyfunc_func_cb = function(arg1: PASN1_INTEGER): PASN1_INTEGER; cdecl;
  TASN1_d2i_fp_xnew_cb = function: Pointer; cdecl;
  TASN1_SCTX_new_scan_cb_cb = function(arg1: PASN1_SCTX): TIdC_INT; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  V_ASN1_UNIVERSAL = $00;
  V_ASN1_APPLICATION = $40;
  V_ASN1_CONTEXT_SPECIFIC = $80;
  V_ASN1_PRIVATE = $c0;
  V_ASN1_CONSTRUCTED = $20;
  V_ASN1_PRIMITIVE_TAG = $1f;
  V_ASN1_PRIMATIVE_TAG = /*compat*/V_ASN1_PRIMITIVE_TAG;
  V_ASN1_APP_CHOOSE = -2;
  V_ASN1_OTHER = -3;
  V_ASN1_ANY = -4;
  V_ASN1_UNDEF = -1;
  V_ASN1_EOC = 0;
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
  V_ASN1_NEG = $100;
  V_ASN1_NEG_INTEGER = (2 or V_ASN1_NEG);
  V_ASN1_NEG_ENUMERATED = (10 or V_ASN1_NEG);
  B_ASN1_NUMERICSTRING = $0001;
  B_ASN1_PRINTABLESTRING = $0002;
  B_ASN1_T61STRING = $0004;
  B_ASN1_TELETEXSTRING = $0004;
  B_ASN1_VIDEOTEXSTRING = $0008;
  B_ASN1_IA5STRING = $0010;
  B_ASN1_GRAPHICSTRING = $0020;
  B_ASN1_ISO64STRING = $0040;
  B_ASN1_VISIBLESTRING = $0040;
  B_ASN1_GENERALSTRING = $0080;
  B_ASN1_UNIVERSALSTRING = $0100;
  B_ASN1_OCTET_STRING = $0200;
  B_ASN1_BIT_STRING = $0400;
  B_ASN1_BMPSTRING = $0800;
  B_ASN1_UNKNOWN = $1000;
  B_ASN1_UTF8STRING = $2000;
  B_ASN1_UTCTIME = $4000;
  B_ASN1_GENERALIZEDTIME = $8000;
  B_ASN1_SEQUENCE = $10000;
  MBSTRING_FLAG = $1000;
  MBSTRING_UTF8 = (MBSTRING_FLAG);
  MBSTRING_ASC = (MBSTRING_FLAG or 1);
  MBSTRING_BMP = (MBSTRING_FLAG or 2);
  MBSTRING_UNIV = (MBSTRING_FLAG or 4);
  SMIME_OLDMIME = $400;
  SMIME_CRLFEOL = $800;
  SMIME_STREAM = $1000;
  ASN1_STRING_FLAG_BITS_LEFT = $08;
  ASN1_STRING_FLAG_NDEF = $010;
  ASN1_STRING_FLAG_CONT = $020;
  ASN1_STRING_FLAG_MSTRING = $040;
  ASN1_STRING_FLAG_EMBED = $080;
  ASN1_STRING_FLAG_X509_TIME = $100;
  ASN1_LONG_UNDEF = $7fffffffL;
  STABLE_FLAGS_MALLOC = $01;
  STABLE_FLAGS_CLEAR = STABLE_FLAGS_MALLOC;
  STABLE_NO_MASK = $02;
  DIRSTRING_TYPE = (B_ASN1_PRINTABLESTRING or B_ASN1_T61STRING or B_ASN1_BMPSTRING or B_ASN1_UTF8STRING);
  PKCS9STRING_TYPE = (DIRSTRING_TYPE or B_ASN1_IA5STRING);
  ub_name = 32768;
  ub_common_name = 64;
  ub_locality_name = 128;
  ub_state_name = 128;
  ub_organization_name = 64;
  ub_organization_unit_name = 64;
  ub_title = 64;
  ub_email_address = 128;
  ASN1_STRFLGS_ESC_2253 = 1;
  ASN1_STRFLGS_ESC_CTRL = 2;
  ASN1_STRFLGS_ESC_MSB = 4;
  ASN1_DTFLGS_TYPE_MASK = $0FUL;
  ASN1_DTFLGS_RFC822 = $00;
  ASN1_DTFLGS_ISO8601 = $01;
  ASN1_STRFLGS_ESC_QUOTE = 8;
  CHARTYPE_PRINTABLESTRING = $10;
  CHARTYPE_FIRST_ESC_2253 = $20;
  CHARTYPE_LAST_ESC_2253 = $40;
  ASN1_STRFLGS_UTF8_CONVERT = $10;
  ASN1_STRFLGS_IGNORE_TYPE = $20;
  ASN1_STRFLGS_SHOW_TYPE = $40;
  ASN1_STRFLGS_DUMP_ALL = $80;
  ASN1_STRFLGS_DUMP_UNKNOWN = $100;
  ASN1_STRFLGS_DUMP_DER = $200;
  ASN1_STRFLGS_ESC_2254 = $400;
  ASN1_STRFLGS_RFC2253 = (ASN1_STRFLGS_ESC_2253 or ASN1_STRFLGS_ESC_CTRL or ASN1_STRFLGS_ESC_MSB or ASN1_STRFLGS_UTF8_CONVERT or ASN1_STRFLGS_DUMP_UNKNOWN or ASN1_STRFLGS_DUMP_DER);
  B_ASN1_TIME = B_ASN1_UTCTIME or B_ASN1_GENERALIZEDTIME;
  B_ASN1_PRINTABLE = B_ASN1_NUMERICSTRING or B_ASN1_PRINTABLESTRING or B_ASN1_T61STRING or B_ASN1_IA5STRING or B_ASN1_BIT_STRING or B_ASN1_UNIVERSALSTRING or B_ASN1_BMPSTRING or B_ASN1_UTF8STRING or B_ASN1_SEQUENCE or B_ASN1_UNKNOWN;
  B_ASN1_DIRECTORYSTRING = B_ASN1_PRINTABLESTRING or B_ASN1_TELETEXSTRING or B_ASN1_BMPSTRING or B_ASN1_UNIVERSALSTRING or B_ASN1_UTF8STRING;
  B_ASN1_DISPLAYTEXT = B_ASN1_IA5STRING or B_ASN1_VISIBLESTRING or B_ASN1_BMPSTRING or B_ASN1_UTF8STRING;
  ASN1_PCTX_FLAGS_SHOW_ABSENT = $001;
  ASN1_PCTX_FLAGS_SHOW_SEQUENCE = $002;
  ASN1_PCTX_FLAGS_SHOW_SSOF = $004;
  ASN1_PCTX_FLAGS_SHOW_TYPE = $008;
  ASN1_PCTX_FLAGS_NO_ANY_TYPE = $010;
  ASN1_PCTX_FLAGS_NO_MSTRING_TYPE = $020;
  ASN1_PCTX_FLAGS_NO_FIELD_NAME = $040;
  ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME = $080;
  ASN1_PCTX_FLAGS_NO_STRUCT_NAME = $100;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  d2i_ASN1_SEQUENCE_ANY: function(a: PPASN1_SEQUENCE_ANY; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_SEQUENCE_ANY; cdecl = nil;
  {$EXTERNALSYM d2i_ASN1_SEQUENCE_ANY}

  i2d_ASN1_SEQUENCE_ANY: function(a: PASN1_SEQUENCE_ANY; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_SEQUENCE_ANY}

  ASN1_SEQUENCE_ANY_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_SEQUENCE_ANY_it}

  d2i_ASN1_SET_ANY: function(a: PPASN1_SEQUENCE_ANY; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_SEQUENCE_ANY; cdecl = nil;
  {$EXTERNALSYM d2i_ASN1_SET_ANY}

  i2d_ASN1_SET_ANY: function(a: PASN1_SEQUENCE_ANY; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_SET_ANY}

  ASN1_SET_ANY_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_SET_ANY_it}

  ASN1_TYPE_new: function: PASN1_TYPE; cdecl = nil;
  {$EXTERNALSYM ASN1_TYPE_new}

  ASN1_TYPE_free: procedure(a: PASN1_TYPE); cdecl = nil;
  {$EXTERNALSYM ASN1_TYPE_free}

  d2i_ASN1_TYPE: function(a: PPASN1_TYPE; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_TYPE; cdecl = nil;
  {$EXTERNALSYM d2i_ASN1_TYPE}

  i2d_ASN1_TYPE: function(a: PASN1_TYPE; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_TYPE}

  ASN1_ANY_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_ANY_it}

  ASN1_TYPE_get: function(a: PASN1_TYPE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_TYPE_get}

  ASN1_TYPE_set: procedure(a: PASN1_TYPE; _type: TIdC_INT; value: Pointer); cdecl = nil;
  {$EXTERNALSYM ASN1_TYPE_set}

  ASN1_TYPE_set1: function(a: PASN1_TYPE; _type: TIdC_INT; value: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_TYPE_set1}

  ASN1_TYPE_cmp: function(a: PASN1_TYPE; b: PASN1_TYPE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_TYPE_cmp}

  ASN1_TYPE_pack_sequence: function(it: PASN1_ITEM; s: Pointer; t: PPASN1_TYPE): PASN1_TYPE; cdecl = nil;
  {$EXTERNALSYM ASN1_TYPE_pack_sequence}

  ASN1_TYPE_unpack_sequence: function(it: PASN1_ITEM; t: PASN1_TYPE): Pointer; cdecl = nil;
  {$EXTERNALSYM ASN1_TYPE_unpack_sequence}

  ASN1_OBJECT_new: function: PASN1_OBJECT; cdecl = nil;
  {$EXTERNALSYM ASN1_OBJECT_new}

  ASN1_OBJECT_free: procedure(a: PASN1_OBJECT); cdecl = nil;
  {$EXTERNALSYM ASN1_OBJECT_free}

  d2i_ASN1_OBJECT: function(a: PPASN1_OBJECT; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_OBJECT; cdecl = nil;
  {$EXTERNALSYM d2i_ASN1_OBJECT}

  i2d_ASN1_OBJECT: function(a: PASN1_OBJECT; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_OBJECT}

  ASN1_OBJECT_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_OBJECT_it}

  ASN1_STRING_new: function: PASN1_STRING; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_new}

  ASN1_STRING_free: procedure(a: PASN1_STRING); cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_free}

  ASN1_STRING_clear_free: procedure(a: PASN1_STRING); cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_clear_free}

  ASN1_STRING_copy: function(dst: PASN1_STRING; str: PASN1_STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_copy}

  ASN1_STRING_dup: function(a: PASN1_STRING): PASN1_STRING; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_dup}

  ASN1_STRING_type_new: function(_type: TIdC_INT): PASN1_STRING; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_type_new}

  ASN1_STRING_cmp: function(a: PASN1_STRING; b: PASN1_STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_cmp}

  ASN1_STRING_set: function(str: PASN1_STRING; data: Pointer; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_set}

  ASN1_STRING_set0: procedure(str: PASN1_STRING; data: Pointer; len: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_set0}

  ASN1_STRING_length: function(x: PASN1_STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_length}

  ASN1_STRING_length_set: procedure(x: PASN1_STRING; n: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ASN1_STRING_length_set}

  ASN1_STRING_type: function(x: PASN1_STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_type}

  ASN1_STRING_get0_data: function(x: PASN1_STRING): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_get0_data}

  ASN1_BIT_STRING_new: function: PASN1_BIT_STRING; cdecl = nil;
  {$EXTERNALSYM ASN1_BIT_STRING_new}

  ASN1_BIT_STRING_free: procedure(a: PASN1_BIT_STRING); cdecl = nil;
  {$EXTERNALSYM ASN1_BIT_STRING_free}

  d2i_ASN1_BIT_STRING: function(a: PPASN1_BIT_STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_BIT_STRING; cdecl = nil;
  {$EXTERNALSYM d2i_ASN1_BIT_STRING}

  i2d_ASN1_BIT_STRING: function(a: PASN1_BIT_STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_BIT_STRING}

  ASN1_BIT_STRING_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_BIT_STRING_it}

  ASN1_BIT_STRING_set: function(a: PASN1_BIT_STRING; d: PIdAnsiChar; length: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_BIT_STRING_set}

  ASN1_BIT_STRING_set_bit: function(a: PASN1_BIT_STRING; n: TIdC_INT; value: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_BIT_STRING_set_bit}

  ASN1_BIT_STRING_get_bit: function(a: PASN1_BIT_STRING; n: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_BIT_STRING_get_bit}

  ASN1_BIT_STRING_check: function(a: PASN1_BIT_STRING; flags: PIdAnsiChar; flags_len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_BIT_STRING_check}

  ASN1_BIT_STRING_name_print: function(_out: PBIO; bs: PASN1_BIT_STRING; tbl: PBIT_STRING_BITNAME; indent: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_BIT_STRING_name_print}

  ASN1_BIT_STRING_num_asc: function(name: PIdAnsiChar; tbl: PBIT_STRING_BITNAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_BIT_STRING_num_asc}

  ASN1_BIT_STRING_set_asc: function(bs: PASN1_BIT_STRING; name: PIdAnsiChar; value: TIdC_INT; tbl: PBIT_STRING_BITNAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_BIT_STRING_set_asc}

  ASN1_INTEGER_new: function: PASN1_INTEGER; cdecl = nil;
  {$EXTERNALSYM ASN1_INTEGER_new}

  ASN1_INTEGER_free: procedure(a: PASN1_INTEGER); cdecl = nil;
  {$EXTERNALSYM ASN1_INTEGER_free}

  d2i_ASN1_INTEGER: function(a: PPASN1_INTEGER; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_INTEGER; cdecl = nil;
  {$EXTERNALSYM d2i_ASN1_INTEGER}

  i2d_ASN1_INTEGER: function(a: PASN1_INTEGER; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_INTEGER}

  ASN1_INTEGER_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_INTEGER_it}

  d2i_ASN1_UINTEGER: function(a: PPASN1_INTEGER; pp: PPIdAnsiChar; length: TIdC_LONG): PASN1_INTEGER; cdecl = nil;
  {$EXTERNALSYM d2i_ASN1_UINTEGER}

  ASN1_INTEGER_dup: function(a: PASN1_INTEGER): PASN1_INTEGER; cdecl = nil;
  {$EXTERNALSYM ASN1_INTEGER_dup}

  ASN1_INTEGER_cmp: function(x: PASN1_INTEGER; y: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_INTEGER_cmp}

  ASN1_ENUMERATED_new: function: PASN1_ENUMERATED; cdecl = nil;
  {$EXTERNALSYM ASN1_ENUMERATED_new}

  ASN1_ENUMERATED_free: procedure(a: PASN1_ENUMERATED); cdecl = nil;
  {$EXTERNALSYM ASN1_ENUMERATED_free}

  d2i_ASN1_ENUMERATED: function(a: PPASN1_ENUMERATED; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_ENUMERATED; cdecl = nil;
  {$EXTERNALSYM d2i_ASN1_ENUMERATED}

  i2d_ASN1_ENUMERATED: function(a: PASN1_ENUMERATED; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_ENUMERATED}

  ASN1_ENUMERATED_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_ENUMERATED_it}

  ASN1_UTCTIME_check: function(a: PASN1_UTCTIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_UTCTIME_check}

  ASN1_UTCTIME_set: function(s: PASN1_UTCTIME; t: TIdC_TIME_T): PASN1_UTCTIME; cdecl = nil;
  {$EXTERNALSYM ASN1_UTCTIME_set}

  ASN1_UTCTIME_adj: function(s: PASN1_UTCTIME; t: TIdC_TIME_T; offset_day: TIdC_INT; offset_sec: TIdC_LONG): PASN1_UTCTIME; cdecl = nil;
  {$EXTERNALSYM ASN1_UTCTIME_adj}

  ASN1_UTCTIME_set_string: function(s: PASN1_UTCTIME; str: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_UTCTIME_set_string}

  ASN1_UTCTIME_cmp_time_t: function(s: PASN1_UTCTIME; t: TIdC_TIME_T): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_UTCTIME_cmp_time_t}

  ASN1_GENERALIZEDTIME_check: function(a: PASN1_GENERALIZEDTIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_GENERALIZEDTIME_check}

  ASN1_GENERALIZEDTIME_set: function(s: PASN1_GENERALIZEDTIME; t: TIdC_TIME_T): PASN1_GENERALIZEDTIME; cdecl = nil;
  {$EXTERNALSYM ASN1_GENERALIZEDTIME_set}

  ASN1_GENERALIZEDTIME_adj: function(s: PASN1_GENERALIZEDTIME; t: TIdC_TIME_T; offset_day: TIdC_INT; offset_sec: TIdC_LONG): PASN1_GENERALIZEDTIME; cdecl = nil;
  {$EXTERNALSYM ASN1_GENERALIZEDTIME_adj}

  ASN1_GENERALIZEDTIME_set_string: function(s: PASN1_GENERALIZEDTIME; str: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_GENERALIZEDTIME_set_string}

  ASN1_TIME_diff: function(pday: PIdC_INT; psec: PIdC_INT; from: PASN1_TIME; _to: PASN1_TIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_TIME_diff}

  ASN1_OCTET_STRING_new: function: PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM ASN1_OCTET_STRING_new}

  ASN1_OCTET_STRING_free: procedure(a: PASN1_OCTET_STRING); cdecl = nil;
  {$EXTERNALSYM ASN1_OCTET_STRING_free}

  d2i_ASN1_OCTET_STRING: function(a: PPASN1_OCTET_STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM d2i_ASN1_OCTET_STRING}

  i2d_ASN1_OCTET_STRING: function(a: PASN1_OCTET_STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_OCTET_STRING}

  ASN1_OCTET_STRING_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_OCTET_STRING_it}

  ASN1_OCTET_STRING_dup: function(a: PASN1_OCTET_STRING): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM ASN1_OCTET_STRING_dup}

  ASN1_OCTET_STRING_cmp: function(a: PASN1_OCTET_STRING; b: PASN1_OCTET_STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_OCTET_STRING_cmp}

  ASN1_OCTET_STRING_set: function(str: PASN1_OCTET_STRING; data: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_OCTET_STRING_set}

  ASN1_VISIBLESTRING_new: function: PASN1_VISIBLESTRING; cdecl = nil;
  {$EXTERNALSYM ASN1_VISIBLESTRING_new}

  ASN1_VISIBLESTRING_free: procedure(a: PASN1_VISIBLESTRING); cdecl = nil;
  {$EXTERNALSYM ASN1_VISIBLESTRING_free}

  d2i_ASN1_VISIBLESTRING: function(a: PPASN1_VISIBLESTRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_VISIBLESTRING; cdecl = nil;
  {$EXTERNALSYM d2i_ASN1_VISIBLESTRING}

  i2d_ASN1_VISIBLESTRING: function(a: PASN1_VISIBLESTRING; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_VISIBLESTRING}

  ASN1_VISIBLESTRING_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_VISIBLESTRING_it}

  ASN1_UNIVERSALSTRING_new: function: PASN1_UNIVERSALSTRING; cdecl = nil;
  {$EXTERNALSYM ASN1_UNIVERSALSTRING_new}

  ASN1_UNIVERSALSTRING_free: procedure(a: PASN1_UNIVERSALSTRING); cdecl = nil;
  {$EXTERNALSYM ASN1_UNIVERSALSTRING_free}

  d2i_ASN1_UNIVERSALSTRING: function(a: PPASN1_UNIVERSALSTRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_UNIVERSALSTRING; cdecl = nil;
  {$EXTERNALSYM d2i_ASN1_UNIVERSALSTRING}

  i2d_ASN1_UNIVERSALSTRING: function(a: PASN1_UNIVERSALSTRING; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_UNIVERSALSTRING}

  ASN1_UNIVERSALSTRING_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_UNIVERSALSTRING_it}

  ASN1_UTF8STRING_new: function: PASN1_UTF8STRING; cdecl = nil;
  {$EXTERNALSYM ASN1_UTF8STRING_new}

  ASN1_UTF8STRING_free: procedure(a: PASN1_UTF8STRING); cdecl = nil;
  {$EXTERNALSYM ASN1_UTF8STRING_free}

  d2i_ASN1_UTF8STRING: function(a: PPASN1_UTF8STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_UTF8STRING; cdecl = nil;
  {$EXTERNALSYM d2i_ASN1_UTF8STRING}

  i2d_ASN1_UTF8STRING: function(a: PASN1_UTF8STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_UTF8STRING}

  ASN1_UTF8STRING_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_UTF8STRING_it}

  ASN1_NULL_new: function: PASN1_NULL; cdecl = nil;
  {$EXTERNALSYM ASN1_NULL_new}

  ASN1_NULL_free: procedure(a: PASN1_NULL); cdecl = nil;
  {$EXTERNALSYM ASN1_NULL_free}

  d2i_ASN1_NULL: function(a: PPASN1_NULL; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_NULL; cdecl = nil;
  {$EXTERNALSYM d2i_ASN1_NULL}

  i2d_ASN1_NULL: function(a: PASN1_NULL; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_NULL}

  ASN1_NULL_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_NULL_it}

  ASN1_BMPSTRING_new: function: PASN1_BMPSTRING; cdecl = nil;
  {$EXTERNALSYM ASN1_BMPSTRING_new}

  ASN1_BMPSTRING_free: procedure(a: PASN1_BMPSTRING); cdecl = nil;
  {$EXTERNALSYM ASN1_BMPSTRING_free}

  d2i_ASN1_BMPSTRING: function(a: PPASN1_BMPSTRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_BMPSTRING; cdecl = nil;
  {$EXTERNALSYM d2i_ASN1_BMPSTRING}

  i2d_ASN1_BMPSTRING: function(a: PASN1_BMPSTRING; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_BMPSTRING}

  ASN1_BMPSTRING_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_BMPSTRING_it}

  UTF8_getc: function(str: PIdAnsiChar; len: TIdC_INT; val: PIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UTF8_getc}

  UTF8_putc: function(str: PIdAnsiChar; len: TIdC_INT; value: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UTF8_putc}

  ASN1_PRINTABLE_new: function: PASN1_STRING; cdecl = nil;
  {$EXTERNALSYM ASN1_PRINTABLE_new}

  ASN1_PRINTABLE_free: procedure(a: PASN1_STRING); cdecl = nil;
  {$EXTERNALSYM ASN1_PRINTABLE_free}

  d2i_ASN1_PRINTABLE: function(a: PPASN1_STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_STRING; cdecl = nil;
  {$EXTERNALSYM d2i_ASN1_PRINTABLE}

  i2d_ASN1_PRINTABLE: function(a: PASN1_STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_PRINTABLE}

  ASN1_PRINTABLE_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_PRINTABLE_it}

  DIRECTORYSTRING_new: function: PASN1_STRING; cdecl = nil;
  {$EXTERNALSYM DIRECTORYSTRING_new}

  DIRECTORYSTRING_free: procedure(a: PASN1_STRING); cdecl = nil;
  {$EXTERNALSYM DIRECTORYSTRING_free}

  d2i_DIRECTORYSTRING: function(a: PPASN1_STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_STRING; cdecl = nil;
  {$EXTERNALSYM d2i_DIRECTORYSTRING}

  i2d_DIRECTORYSTRING: function(a: PASN1_STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_DIRECTORYSTRING}

  DIRECTORYSTRING_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM DIRECTORYSTRING_it}

  DISPLAYTEXT_new: function: PASN1_STRING; cdecl = nil;
  {$EXTERNALSYM DISPLAYTEXT_new}

  DISPLAYTEXT_free: procedure(a: PASN1_STRING); cdecl = nil;
  {$EXTERNALSYM DISPLAYTEXT_free}

  d2i_DISPLAYTEXT: function(a: PPASN1_STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_STRING; cdecl = nil;
  {$EXTERNALSYM d2i_DISPLAYTEXT}

  i2d_DISPLAYTEXT: function(a: PASN1_STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_DISPLAYTEXT}

  DISPLAYTEXT_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM DISPLAYTEXT_it}

  ASN1_PRINTABLESTRING_new: function: PASN1_PRINTABLESTRING; cdecl = nil;
  {$EXTERNALSYM ASN1_PRINTABLESTRING_new}

  ASN1_PRINTABLESTRING_free: procedure(a: PASN1_PRINTABLESTRING); cdecl = nil;
  {$EXTERNALSYM ASN1_PRINTABLESTRING_free}

  d2i_ASN1_PRINTABLESTRING: function(a: PPASN1_PRINTABLESTRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_PRINTABLESTRING; cdecl = nil;
  {$EXTERNALSYM d2i_ASN1_PRINTABLESTRING}

  i2d_ASN1_PRINTABLESTRING: function(a: PASN1_PRINTABLESTRING; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_PRINTABLESTRING}

  ASN1_PRINTABLESTRING_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_PRINTABLESTRING_it}

  ASN1_T61STRING_new: function: PASN1_T61STRING; cdecl = nil;
  {$EXTERNALSYM ASN1_T61STRING_new}

  ASN1_T61STRING_free: procedure(a: PASN1_T61STRING); cdecl = nil;
  {$EXTERNALSYM ASN1_T61STRING_free}

  d2i_ASN1_T61STRING: function(a: PPASN1_T61STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_T61STRING; cdecl = nil;
  {$EXTERNALSYM d2i_ASN1_T61STRING}

  i2d_ASN1_T61STRING: function(a: PASN1_T61STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_T61STRING}

  ASN1_T61STRING_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_T61STRING_it}

  ASN1_IA5STRING_new: function: PASN1_IA5STRING; cdecl = nil;
  {$EXTERNALSYM ASN1_IA5STRING_new}

  ASN1_IA5STRING_free: procedure(a: PASN1_IA5STRING); cdecl = nil;
  {$EXTERNALSYM ASN1_IA5STRING_free}

  d2i_ASN1_IA5STRING: function(a: PPASN1_IA5STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_IA5STRING; cdecl = nil;
  {$EXTERNALSYM d2i_ASN1_IA5STRING}

  i2d_ASN1_IA5STRING: function(a: PASN1_IA5STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_IA5STRING}

  ASN1_IA5STRING_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_IA5STRING_it}

  ASN1_GENERALSTRING_new: function: PASN1_GENERALSTRING; cdecl = nil;
  {$EXTERNALSYM ASN1_GENERALSTRING_new}

  ASN1_GENERALSTRING_free: procedure(a: PASN1_GENERALSTRING); cdecl = nil;
  {$EXTERNALSYM ASN1_GENERALSTRING_free}

  d2i_ASN1_GENERALSTRING: function(a: PPASN1_GENERALSTRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_GENERALSTRING; cdecl = nil;
  {$EXTERNALSYM d2i_ASN1_GENERALSTRING}

  i2d_ASN1_GENERALSTRING: function(a: PASN1_GENERALSTRING; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_GENERALSTRING}

  ASN1_GENERALSTRING_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_GENERALSTRING_it}

  ASN1_UTCTIME_new: function: PASN1_UTCTIME; cdecl = nil;
  {$EXTERNALSYM ASN1_UTCTIME_new}

  ASN1_UTCTIME_free: procedure(a: PASN1_UTCTIME); cdecl = nil;
  {$EXTERNALSYM ASN1_UTCTIME_free}

  d2i_ASN1_UTCTIME: function(a: PPASN1_UTCTIME; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_UTCTIME; cdecl = nil;
  {$EXTERNALSYM d2i_ASN1_UTCTIME}

  i2d_ASN1_UTCTIME: function(a: PASN1_UTCTIME; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_UTCTIME}

  ASN1_UTCTIME_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_UTCTIME_it}

  ASN1_GENERALIZEDTIME_new: function: PASN1_GENERALIZEDTIME; cdecl = nil;
  {$EXTERNALSYM ASN1_GENERALIZEDTIME_new}

  ASN1_GENERALIZEDTIME_free: procedure(a: PASN1_GENERALIZEDTIME); cdecl = nil;
  {$EXTERNALSYM ASN1_GENERALIZEDTIME_free}

  d2i_ASN1_GENERALIZEDTIME: function(a: PPASN1_GENERALIZEDTIME; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_GENERALIZEDTIME; cdecl = nil;
  {$EXTERNALSYM d2i_ASN1_GENERALIZEDTIME}

  i2d_ASN1_GENERALIZEDTIME: function(a: PASN1_GENERALIZEDTIME; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_GENERALIZEDTIME}

  ASN1_GENERALIZEDTIME_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_GENERALIZEDTIME_it}

  ASN1_TIME_new: function: PASN1_TIME; cdecl = nil;
  {$EXTERNALSYM ASN1_TIME_new}

  ASN1_TIME_free: procedure(a: PASN1_TIME); cdecl = nil;
  {$EXTERNALSYM ASN1_TIME_free}

  d2i_ASN1_TIME: function(a: PPASN1_TIME; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_TIME; cdecl = nil;
  {$EXTERNALSYM d2i_ASN1_TIME}

  i2d_ASN1_TIME: function(a: PASN1_TIME; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_TIME}

  ASN1_TIME_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_TIME_it}

  ASN1_TIME_dup: function(a: PASN1_TIME): PASN1_TIME; cdecl = nil;
  {$EXTERNALSYM ASN1_TIME_dup}

  ASN1_UTCTIME_dup: function(a: PASN1_UTCTIME): PASN1_UTCTIME; cdecl = nil;
  {$EXTERNALSYM ASN1_UTCTIME_dup}

  ASN1_GENERALIZEDTIME_dup: function(a: PASN1_GENERALIZEDTIME): PASN1_GENERALIZEDTIME; cdecl = nil;
  {$EXTERNALSYM ASN1_GENERALIZEDTIME_dup}

  ASN1_OCTET_STRING_NDEF_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_OCTET_STRING_NDEF_it}

  ASN1_TIME_set: function(s: PASN1_TIME; t: TIdC_TIME_T): PASN1_TIME; cdecl = nil;
  {$EXTERNALSYM ASN1_TIME_set}

  ASN1_TIME_adj: function(s: PASN1_TIME; t: TIdC_TIME_T; offset_day: TIdC_INT; offset_sec: TIdC_LONG): PASN1_TIME; cdecl = nil;
  {$EXTERNALSYM ASN1_TIME_adj}

  ASN1_TIME_check: function(t: PASN1_TIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_TIME_check}

  ASN1_TIME_to_generalizedtime: function(t: PASN1_TIME; _out: PPASN1_GENERALIZEDTIME): PASN1_GENERALIZEDTIME; cdecl = nil;
  {$EXTERNALSYM ASN1_TIME_to_generalizedtime}

  ASN1_TIME_set_string: function(s: PASN1_TIME; str: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_TIME_set_string}

  ASN1_TIME_set_string_X509: function(s: PASN1_TIME; str: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_TIME_set_string_X509}

  ASN1_TIME_to_tm: function(s: PASN1_TIME; tm: Ptm): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_TIME_to_tm}

  ASN1_TIME_normalize: function(s: PASN1_TIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_TIME_normalize}

  ASN1_TIME_cmp_time_t: function(s: PASN1_TIME; t: TIdC_TIME_T): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_TIME_cmp_time_t}

  ASN1_TIME_compare: function(a: PASN1_TIME; b: PASN1_TIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_TIME_compare}

  i2a_ASN1_INTEGER: function(bp: PBIO; a: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2a_ASN1_INTEGER}

  a2i_ASN1_INTEGER: function(bp: PBIO; bs: PASN1_INTEGER; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM a2i_ASN1_INTEGER}

  i2a_ASN1_ENUMERATED: function(bp: PBIO; a: PASN1_ENUMERATED): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2a_ASN1_ENUMERATED}

  a2i_ASN1_ENUMERATED: function(bp: PBIO; bs: PASN1_ENUMERATED; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM a2i_ASN1_ENUMERATED}

  i2a_ASN1_OBJECT: function(bp: PBIO; a: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2a_ASN1_OBJECT}

  a2i_ASN1_STRING: function(bp: PBIO; bs: PASN1_STRING; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM a2i_ASN1_STRING}

  i2a_ASN1_STRING: function(bp: PBIO; a: PASN1_STRING; _type: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2a_ASN1_STRING}

  i2t_ASN1_OBJECT: function(buf: PIdAnsiChar; buf_len: TIdC_INT; a: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2t_ASN1_OBJECT}

  a2d_ASN1_OBJECT: function(_out: PIdAnsiChar; olen: TIdC_INT; buf: PIdAnsiChar; num: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM a2d_ASN1_OBJECT}

  ASN1_OBJECT_create: function(nid: TIdC_INT; data: PIdAnsiChar; len: TIdC_INT; sn: PIdAnsiChar; ln: PIdAnsiChar): PASN1_OBJECT; cdecl = nil;
  {$EXTERNALSYM ASN1_OBJECT_create}

  ASN1_INTEGER_get_int64: function(pr: PInt64; a: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_INTEGER_get_int64}

  ASN1_INTEGER_set_int64: function(a: PASN1_INTEGER; r: Int64): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_INTEGER_set_int64}

  ASN1_INTEGER_get_uint64: function(pr: PUInt64; a: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_INTEGER_get_uint64}

  ASN1_INTEGER_set_uint64: function(a: PASN1_INTEGER; r: UInt64): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_INTEGER_set_uint64}

  ASN1_INTEGER_set: function(a: PASN1_INTEGER; v: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_INTEGER_set}

  ASN1_INTEGER_get: function(a: PASN1_INTEGER): TIdC_LONG; cdecl = nil;
  {$EXTERNALSYM ASN1_INTEGER_get}

  BN_to_ASN1_INTEGER: function(bn: PBIGNUM; ai: PASN1_INTEGER): PASN1_INTEGER; cdecl = nil;
  {$EXTERNALSYM BN_to_ASN1_INTEGER}

  ASN1_INTEGER_to_BN: function(ai: PASN1_INTEGER; bn: PBIGNUM): PBIGNUM; cdecl = nil;
  {$EXTERNALSYM ASN1_INTEGER_to_BN}

  ASN1_ENUMERATED_get_int64: function(pr: PInt64; a: PASN1_ENUMERATED): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_ENUMERATED_get_int64}

  ASN1_ENUMERATED_set_int64: function(a: PASN1_ENUMERATED; r: Int64): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_ENUMERATED_set_int64}

  ASN1_ENUMERATED_set: function(a: PASN1_ENUMERATED; v: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_ENUMERATED_set}

  ASN1_ENUMERATED_get: function(a: PASN1_ENUMERATED): TIdC_LONG; cdecl = nil;
  {$EXTERNALSYM ASN1_ENUMERATED_get}

  BN_to_ASN1_ENUMERATED: function(bn: PBIGNUM; ai: PASN1_ENUMERATED): PASN1_ENUMERATED; cdecl = nil;
  {$EXTERNALSYM BN_to_ASN1_ENUMERATED}

  ASN1_ENUMERATED_to_BN: function(ai: PASN1_ENUMERATED; bn: PBIGNUM): PBIGNUM; cdecl = nil;
  {$EXTERNALSYM ASN1_ENUMERATED_to_BN}

  ASN1_PRINTABLE_type: function(s: PIdAnsiChar; max: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_PRINTABLE_type}

  ASN1_tag2bit: function(tag: TIdC_INT): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ASN1_tag2bit}

  ASN1_get_object: function(pp: PPIdAnsiChar; plength: PIdC_LONG; ptag: PIdC_INT; pclass: PIdC_INT; omax: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_get_object}

  ASN1_check_infinite_end: function(p: PPIdAnsiChar; len: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_check_infinite_end}

  ASN1_const_check_infinite_end: function(p: PPIdAnsiChar; len: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_const_check_infinite_end}

  ASN1_put_object: procedure(pp: PPIdAnsiChar; constructed: TIdC_INT; length: TIdC_INT; tag: TIdC_INT; xclass: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM ASN1_put_object}

  ASN1_put_eoc: function(pp: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_put_eoc}

  ASN1_object_size: function(constructed: TIdC_INT; length: TIdC_INT; tag: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_object_size}

  ASN1_dup: function(i2d: Ti2d_of_void_func_cb; d2i: Td2i_of_void_func_cb; x: Pointer): Pointer; cdecl = nil;
  {$EXTERNALSYM ASN1_dup}

  ASN1_item_dup: function(it: PASN1_ITEM; x: Pointer): Pointer; cdecl = nil;
  {$EXTERNALSYM ASN1_item_dup}

  ASN1_item_sign_ex: function(it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; id: PASN1_OCTET_STRING; pkey: PEVP_PKEY; md: PEVP_MD; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_item_sign_ex}

  ASN1_item_verify_ex: function(it: PASN1_ITEM; alg: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; id: PASN1_OCTET_STRING; pkey: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_item_verify_ex}

  ASN1_d2i_fp: function(xnew: TASN1_d2i_fp_xnew_cb; d2i: Td2i_of_void_func_cb; _in: PFILE; x: PPointer): Pointer; cdecl = nil;
  {$EXTERNALSYM ASN1_d2i_fp}

  ASN1_item_d2i_fp_ex: function(it: PASN1_ITEM; _in: PFILE; x: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): Pointer; cdecl = nil;
  {$EXTERNALSYM ASN1_item_d2i_fp_ex}

  ASN1_item_d2i_fp: function(it: PASN1_ITEM; _in: PFILE; x: Pointer): Pointer; cdecl = nil;
  {$EXTERNALSYM ASN1_item_d2i_fp}

  ASN1_i2d_fp: function(i2d: Ti2d_of_void_func_cb; _out: PFILE; x: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_i2d_fp}

  ASN1_item_i2d_fp: function(it: PASN1_ITEM; _out: PFILE; x: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_item_i2d_fp}

  ASN1_STRING_print_ex_fp: function(fp: PFILE; str: PASN1_STRING; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_print_ex_fp}

  ASN1_STRING_to_UTF8: function(_out: PPIdAnsiChar; _in: PASN1_STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_to_UTF8}

  ASN1_d2i_bio: function(xnew: TASN1_d2i_fp_xnew_cb; d2i: Td2i_of_void_func_cb; _in: PBIO; x: PPointer): Pointer; cdecl = nil;
  {$EXTERNALSYM ASN1_d2i_bio}

  ASN1_item_d2i_bio_ex: function(it: PASN1_ITEM; _in: PBIO; pval: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): Pointer; cdecl = nil;
  {$EXTERNALSYM ASN1_item_d2i_bio_ex}

  ASN1_item_d2i_bio: function(it: PASN1_ITEM; _in: PBIO; pval: Pointer): Pointer; cdecl = nil;
  {$EXTERNALSYM ASN1_item_d2i_bio}

  ASN1_i2d_bio: function(i2d: Ti2d_of_void_func_cb; _out: PBIO; x: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_i2d_bio}

  ASN1_item_i2d_bio: function(it: PASN1_ITEM; _out: PBIO; x: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_item_i2d_bio}

  ASN1_item_i2d_mem_bio: function(it: PASN1_ITEM; val: PASN1_VALUE): PBIO; cdecl = nil;
  {$EXTERNALSYM ASN1_item_i2d_mem_bio}

  ASN1_UTCTIME_print: function(fp: PBIO; a: PASN1_UTCTIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_UTCTIME_print}

  ASN1_GENERALIZEDTIME_print: function(fp: PBIO; a: PASN1_GENERALIZEDTIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_GENERALIZEDTIME_print}

  ASN1_TIME_print: function(bp: PBIO; tm: PASN1_TIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_TIME_print}

  ASN1_TIME_print_ex: function(bp: PBIO; tm: PASN1_TIME; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_TIME_print_ex}

  ASN1_STRING_print: function(bp: PBIO; v: PASN1_STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_print}

  ASN1_STRING_print_ex: function(_out: PBIO; str: PASN1_STRING; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_print_ex}

  ASN1_buf_print: function(bp: PBIO; buf: PIdAnsiChar; buflen: TIdC_SIZET; off: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_buf_print}

  ASN1_bn_print: function(bp: PBIO; number: PIdAnsiChar; num: PBIGNUM; buf: PIdAnsiChar; off: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_bn_print}

  ASN1_parse: function(bp: PBIO; pp: PIdAnsiChar; len: TIdC_LONG; indent: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_parse}

  ASN1_parse_dump: function(bp: PBIO; pp: PIdAnsiChar; len: TIdC_LONG; indent: TIdC_INT; dump: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_parse_dump}

  ASN1_tag2str: function(tag: TIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM ASN1_tag2str}

  ASN1_UNIVERSALSTRING_to_string: function(s: PASN1_UNIVERSALSTRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_UNIVERSALSTRING_to_string}

  ASN1_TYPE_set_octetstring: function(a: PASN1_TYPE; data: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_TYPE_set_octetstring}

  ASN1_TYPE_get_octetstring: function(a: PASN1_TYPE; data: PIdAnsiChar; max_len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_TYPE_get_octetstring}

  ASN1_TYPE_set_int_octetstring: function(a: PASN1_TYPE; num: TIdC_LONG; data: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_TYPE_set_int_octetstring}

  ASN1_TYPE_get_int_octetstring: function(a: PASN1_TYPE; num: PIdC_LONG; data: PIdAnsiChar; max_len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_TYPE_get_int_octetstring}

  ASN1_item_unpack: function(oct: PASN1_STRING; it: PASN1_ITEM): Pointer; cdecl = nil;
  {$EXTERNALSYM ASN1_item_unpack}

  ASN1_item_unpack_ex: function(oct: PASN1_STRING; it: PASN1_ITEM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): Pointer; cdecl = nil;
  {$EXTERNALSYM ASN1_item_unpack_ex}

  ASN1_item_pack: function(obj: Pointer; it: PASN1_ITEM; oct: PPASN1_OCTET_STRING): PASN1_STRING; cdecl = nil;
  {$EXTERNALSYM ASN1_item_pack}

  ASN1_STRING_set_default_mask: procedure(mask: TIdC_ULONG); cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_set_default_mask}

  ASN1_STRING_set_default_mask_asc: function(p: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_set_default_mask_asc}

  ASN1_STRING_get_default_mask: function: TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_get_default_mask}

  ASN1_mbstring_copy: function(_out: PPASN1_STRING; _in: PIdAnsiChar; len: TIdC_INT; inform: TIdC_INT; mask: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_mbstring_copy}

  ASN1_mbstring_ncopy: function(_out: PPASN1_STRING; _in: PIdAnsiChar; len: TIdC_INT; inform: TIdC_INT; mask: TIdC_ULONG; minsize: TIdC_LONG; maxsize: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_mbstring_ncopy}

  ASN1_STRING_set_by_NID: function(_out: PPASN1_STRING; _in: PIdAnsiChar; inlen: TIdC_INT; inform: TIdC_INT; nid: TIdC_INT): PASN1_STRING; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_set_by_NID}

  ASN1_STRING_TABLE_get: function(nid: TIdC_INT): PASN1_STRING_TABLE; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_TABLE_get}

  ASN1_STRING_TABLE_add: function(arg1: TIdC_INT; arg2: TIdC_LONG; arg3: TIdC_LONG; arg4: TIdC_ULONG; arg5: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_TABLE_add}

  ASN1_STRING_TABLE_cleanup: procedure; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_TABLE_cleanup}

  ASN1_item_new: function(it: PASN1_ITEM): PASN1_VALUE; cdecl = nil;
  {$EXTERNALSYM ASN1_item_new}

  ASN1_item_new_ex: function(it: PASN1_ITEM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PASN1_VALUE; cdecl = nil;
  {$EXTERNALSYM ASN1_item_new_ex}

  ASN1_item_free: procedure(val: PASN1_VALUE; it: PASN1_ITEM); cdecl = nil;
  {$EXTERNALSYM ASN1_item_free}

  ASN1_item_d2i_ex: function(val: PPASN1_VALUE; _in: PPIdAnsiChar; len: TIdC_LONG; it: PASN1_ITEM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PASN1_VALUE; cdecl = nil;
  {$EXTERNALSYM ASN1_item_d2i_ex}

  ASN1_item_d2i: function(val: PPASN1_VALUE; _in: PPIdAnsiChar; len: TIdC_LONG; it: PASN1_ITEM): PASN1_VALUE; cdecl = nil;
  {$EXTERNALSYM ASN1_item_d2i}

  ASN1_item_i2d: function(val: PASN1_VALUE; _out: PPIdAnsiChar; it: PASN1_ITEM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_item_i2d}

  ASN1_item_ndef_i2d: function(val: PASN1_VALUE; _out: PPIdAnsiChar; it: PASN1_ITEM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_item_ndef_i2d}

  ASN1_add_oid_module: procedure; cdecl = nil;
  {$EXTERNALSYM ASN1_add_oid_module}

  ASN1_add_stable_module: procedure; cdecl = nil;
  {$EXTERNALSYM ASN1_add_stable_module}

  ASN1_generate_nconf: function(str: PIdAnsiChar; nconf: PCONF): PASN1_TYPE; cdecl = nil;
  {$EXTERNALSYM ASN1_generate_nconf}

  ASN1_generate_v3: function(str: PIdAnsiChar; cnf: PX509V3_CTX): PASN1_TYPE; cdecl = nil;
  {$EXTERNALSYM ASN1_generate_v3}

  ASN1_str2mask: function(str: PIdAnsiChar; pmask: PIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_str2mask}

  ASN1_item_print: function(_out: PBIO; ifld: PASN1_VALUE; indent: TIdC_INT; it: PASN1_ITEM; pctx: PASN1_PCTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_item_print}

  ASN1_PCTX_new: function: PASN1_PCTX; cdecl = nil;
  {$EXTERNALSYM ASN1_PCTX_new}

  ASN1_PCTX_free: procedure(p: PASN1_PCTX); cdecl = nil;
  {$EXTERNALSYM ASN1_PCTX_free}

  ASN1_PCTX_get_flags: function(p: PASN1_PCTX): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ASN1_PCTX_get_flags}

  ASN1_PCTX_set_flags: procedure(p: PASN1_PCTX; flags: TIdC_ULONG); cdecl = nil;
  {$EXTERNALSYM ASN1_PCTX_set_flags}

  ASN1_PCTX_get_nm_flags: function(p: PASN1_PCTX): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ASN1_PCTX_get_nm_flags}

  ASN1_PCTX_set_nm_flags: procedure(p: PASN1_PCTX; flags: TIdC_ULONG); cdecl = nil;
  {$EXTERNALSYM ASN1_PCTX_set_nm_flags}

  ASN1_PCTX_get_cert_flags: function(p: PASN1_PCTX): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ASN1_PCTX_get_cert_flags}

  ASN1_PCTX_set_cert_flags: procedure(p: PASN1_PCTX; flags: TIdC_ULONG); cdecl = nil;
  {$EXTERNALSYM ASN1_PCTX_set_cert_flags}

  ASN1_PCTX_get_oid_flags: function(p: PASN1_PCTX): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ASN1_PCTX_get_oid_flags}

  ASN1_PCTX_set_oid_flags: procedure(p: PASN1_PCTX; flags: TIdC_ULONG); cdecl = nil;
  {$EXTERNALSYM ASN1_PCTX_set_oid_flags}

  ASN1_PCTX_get_str_flags: function(p: PASN1_PCTX): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ASN1_PCTX_get_str_flags}

  ASN1_PCTX_set_str_flags: procedure(p: PASN1_PCTX; flags: TIdC_ULONG); cdecl = nil;
  {$EXTERNALSYM ASN1_PCTX_set_str_flags}

  ASN1_SCTX_new: function(scan_cb: TASN1_SCTX_new_scan_cb_cb): PASN1_SCTX; cdecl = nil;
  {$EXTERNALSYM ASN1_SCTX_new}

  ASN1_SCTX_free: procedure(p: PASN1_SCTX); cdecl = nil;
  {$EXTERNALSYM ASN1_SCTX_free}

  ASN1_SCTX_get_item: function(p: PASN1_SCTX): PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_SCTX_get_item}

  ASN1_SCTX_get_template: function(p: PASN1_SCTX): PASN1_TEMPLATE; cdecl = nil;
  {$EXTERNALSYM ASN1_SCTX_get_template}

  ASN1_SCTX_get_flags: function(p: PASN1_SCTX): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ASN1_SCTX_get_flags}

  ASN1_SCTX_set_app_data: procedure(p: PASN1_SCTX; data: Pointer); cdecl = nil;
  {$EXTERNALSYM ASN1_SCTX_set_app_data}

  ASN1_SCTX_get_app_data: function(p: PASN1_SCTX): Pointer; cdecl = nil;
  {$EXTERNALSYM ASN1_SCTX_get_app_data}

  BIO_f_asn1: function: PBIO_METHOD; cdecl = nil;
  {$EXTERNALSYM BIO_f_asn1}

  BIO_new_NDEF: function(_out: PBIO; val: PASN1_VALUE; it: PASN1_ITEM): PBIO; cdecl = nil;
  {$EXTERNALSYM BIO_new_NDEF}

  i2d_ASN1_bio_stream: function(_out: PBIO; val: PASN1_VALUE; _in: PBIO; flags: TIdC_INT; it: PASN1_ITEM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_bio_stream}

  PEM_write_bio_ASN1_stream: function(_out: PBIO; val: PASN1_VALUE; _in: PBIO; flags: TIdC_INT; hdr: PIdAnsiChar; it: PASN1_ITEM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_bio_ASN1_stream}

  SMIME_write_ASN1: function(bio: PBIO; val: PASN1_VALUE; data: PBIO; flags: TIdC_INT; ctype_nid: TIdC_INT; econt_nid: TIdC_INT; mdalgs: Pstack_st_X509_ALGOR; it: PASN1_ITEM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SMIME_write_ASN1}

  SMIME_write_ASN1_ex: function(bio: PBIO; val: PASN1_VALUE; data: PBIO; flags: TIdC_INT; ctype_nid: TIdC_INT; econt_nid: TIdC_INT; mdalgs: Pstack_st_X509_ALGOR; it: PASN1_ITEM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SMIME_write_ASN1_ex}

  SMIME_read_ASN1: function(bio: PBIO; bcont: PPBIO; it: PASN1_ITEM): PASN1_VALUE; cdecl = nil;
  {$EXTERNALSYM SMIME_read_ASN1}

  SMIME_read_ASN1_ex: function(bio: PBIO; flags: TIdC_INT; bcont: PPBIO; it: PASN1_ITEM; x: PPASN1_VALUE; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PASN1_VALUE; cdecl = nil;
  {$EXTERNALSYM SMIME_read_ASN1_ex}

  SMIME_crlf_copy: function(_in: PBIO; _out: PBIO; flags: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SMIME_crlf_copy}

  SMIME_text: function(_in: PBIO; _out: PBIO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SMIME_text}

  ASN1_ITEM_lookup: function(name: PIdAnsiChar): PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_ITEM_lookup}

  ASN1_ITEM_get: function(i: TIdC_SIZET): PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_ITEM_get}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function d2i_ASN1_SEQUENCE_ANY(a: PPASN1_SEQUENCE_ANY; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_SEQUENCE_ANY; cdecl;
function i2d_ASN1_SEQUENCE_ANY(a: PASN1_SEQUENCE_ANY; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ASN1_SEQUENCE_ANY_it: PASN1_ITEM; cdecl;
function d2i_ASN1_SET_ANY(a: PPASN1_SEQUENCE_ANY; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_SEQUENCE_ANY; cdecl;
function i2d_ASN1_SET_ANY(a: PASN1_SEQUENCE_ANY; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ASN1_SET_ANY_it: PASN1_ITEM; cdecl;
function ASN1_TYPE_new: PASN1_TYPE; cdecl;
procedure ASN1_TYPE_free(a: PASN1_TYPE); cdecl;
function d2i_ASN1_TYPE(a: PPASN1_TYPE; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_TYPE; cdecl;
function i2d_ASN1_TYPE(a: PASN1_TYPE; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ASN1_ANY_it: PASN1_ITEM; cdecl;
function ASN1_TYPE_get(a: PASN1_TYPE): TIdC_INT; cdecl;
procedure ASN1_TYPE_set(a: PASN1_TYPE; _type: TIdC_INT; value: Pointer); cdecl;
function ASN1_TYPE_set1(a: PASN1_TYPE; _type: TIdC_INT; value: Pointer): TIdC_INT; cdecl;
function ASN1_TYPE_cmp(a: PASN1_TYPE; b: PASN1_TYPE): TIdC_INT; cdecl;
function ASN1_TYPE_pack_sequence(it: PASN1_ITEM; s: Pointer; t: PPASN1_TYPE): PASN1_TYPE; cdecl;
function ASN1_TYPE_unpack_sequence(it: PASN1_ITEM; t: PASN1_TYPE): Pointer; cdecl;
function ASN1_OBJECT_new: PASN1_OBJECT; cdecl;
procedure ASN1_OBJECT_free(a: PASN1_OBJECT); cdecl;
function d2i_ASN1_OBJECT(a: PPASN1_OBJECT; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_OBJECT; cdecl;
function i2d_ASN1_OBJECT(a: PASN1_OBJECT; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ASN1_OBJECT_it: PASN1_ITEM; cdecl;
function ASN1_STRING_new: PASN1_STRING; cdecl;
procedure ASN1_STRING_free(a: PASN1_STRING); cdecl;
procedure ASN1_STRING_clear_free(a: PASN1_STRING); cdecl;
function ASN1_STRING_copy(dst: PASN1_STRING; str: PASN1_STRING): TIdC_INT; cdecl;
function ASN1_STRING_dup(a: PASN1_STRING): PASN1_STRING; cdecl;
function ASN1_STRING_type_new(_type: TIdC_INT): PASN1_STRING; cdecl;
function ASN1_STRING_cmp(a: PASN1_STRING; b: PASN1_STRING): TIdC_INT; cdecl;
function ASN1_STRING_set(str: PASN1_STRING; data: Pointer; len: TIdC_INT): TIdC_INT; cdecl;
procedure ASN1_STRING_set0(str: PASN1_STRING; data: Pointer; len: TIdC_INT); cdecl;
function ASN1_STRING_length(x: PASN1_STRING): TIdC_INT; cdecl;
procedure ASN1_STRING_length_set(x: PASN1_STRING; n: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
function ASN1_STRING_type(x: PASN1_STRING): TIdC_INT; cdecl;
function ASN1_STRING_get0_data(x: PASN1_STRING): PIdAnsiChar; cdecl;
function ASN1_BIT_STRING_new: PASN1_BIT_STRING; cdecl;
procedure ASN1_BIT_STRING_free(a: PASN1_BIT_STRING); cdecl;
function d2i_ASN1_BIT_STRING(a: PPASN1_BIT_STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_BIT_STRING; cdecl;
function i2d_ASN1_BIT_STRING(a: PASN1_BIT_STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ASN1_BIT_STRING_it: PASN1_ITEM; cdecl;
function ASN1_BIT_STRING_set(a: PASN1_BIT_STRING; d: PIdAnsiChar; length: TIdC_INT): TIdC_INT; cdecl;
function ASN1_BIT_STRING_set_bit(a: PASN1_BIT_STRING; n: TIdC_INT; value: TIdC_INT): TIdC_INT; cdecl;
function ASN1_BIT_STRING_get_bit(a: PASN1_BIT_STRING; n: TIdC_INT): TIdC_INT; cdecl;
function ASN1_BIT_STRING_check(a: PASN1_BIT_STRING; flags: PIdAnsiChar; flags_len: TIdC_INT): TIdC_INT; cdecl;
function ASN1_BIT_STRING_name_print(_out: PBIO; bs: PASN1_BIT_STRING; tbl: PBIT_STRING_BITNAME; indent: TIdC_INT): TIdC_INT; cdecl;
function ASN1_BIT_STRING_num_asc(name: PIdAnsiChar; tbl: PBIT_STRING_BITNAME): TIdC_INT; cdecl;
function ASN1_BIT_STRING_set_asc(bs: PASN1_BIT_STRING; name: PIdAnsiChar; value: TIdC_INT; tbl: PBIT_STRING_BITNAME): TIdC_INT; cdecl;
function ASN1_INTEGER_new: PASN1_INTEGER; cdecl;
procedure ASN1_INTEGER_free(a: PASN1_INTEGER); cdecl;
function d2i_ASN1_INTEGER(a: PPASN1_INTEGER; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_INTEGER; cdecl;
function i2d_ASN1_INTEGER(a: PASN1_INTEGER; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ASN1_INTEGER_it: PASN1_ITEM; cdecl;
function d2i_ASN1_UINTEGER(a: PPASN1_INTEGER; pp: PPIdAnsiChar; length: TIdC_LONG): PASN1_INTEGER; cdecl;
function ASN1_INTEGER_dup(a: PASN1_INTEGER): PASN1_INTEGER; cdecl;
function ASN1_INTEGER_cmp(x: PASN1_INTEGER; y: PASN1_INTEGER): TIdC_INT; cdecl;
function ASN1_ENUMERATED_new: PASN1_ENUMERATED; cdecl;
procedure ASN1_ENUMERATED_free(a: PASN1_ENUMERATED); cdecl;
function d2i_ASN1_ENUMERATED(a: PPASN1_ENUMERATED; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_ENUMERATED; cdecl;
function i2d_ASN1_ENUMERATED(a: PASN1_ENUMERATED; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ASN1_ENUMERATED_it: PASN1_ITEM; cdecl;
function ASN1_UTCTIME_check(a: PASN1_UTCTIME): TIdC_INT; cdecl;
function ASN1_UTCTIME_set(s: PASN1_UTCTIME; t: TIdC_TIME_T): PASN1_UTCTIME; cdecl;
function ASN1_UTCTIME_adj(s: PASN1_UTCTIME; t: TIdC_TIME_T; offset_day: TIdC_INT; offset_sec: TIdC_LONG): PASN1_UTCTIME; cdecl;
function ASN1_UTCTIME_set_string(s: PASN1_UTCTIME; str: PIdAnsiChar): TIdC_INT; cdecl;
function ASN1_UTCTIME_cmp_time_t(s: PASN1_UTCTIME; t: TIdC_TIME_T): TIdC_INT; cdecl;
function ASN1_GENERALIZEDTIME_check(a: PASN1_GENERALIZEDTIME): TIdC_INT; cdecl;
function ASN1_GENERALIZEDTIME_set(s: PASN1_GENERALIZEDTIME; t: TIdC_TIME_T): PASN1_GENERALIZEDTIME; cdecl;
function ASN1_GENERALIZEDTIME_adj(s: PASN1_GENERALIZEDTIME; t: TIdC_TIME_T; offset_day: TIdC_INT; offset_sec: TIdC_LONG): PASN1_GENERALIZEDTIME; cdecl;
function ASN1_GENERALIZEDTIME_set_string(s: PASN1_GENERALIZEDTIME; str: PIdAnsiChar): TIdC_INT; cdecl;
function ASN1_TIME_diff(pday: PIdC_INT; psec: PIdC_INT; from: PASN1_TIME; _to: PASN1_TIME): TIdC_INT; cdecl;
function ASN1_OCTET_STRING_new: PASN1_OCTET_STRING; cdecl;
procedure ASN1_OCTET_STRING_free(a: PASN1_OCTET_STRING); cdecl;
function d2i_ASN1_OCTET_STRING(a: PPASN1_OCTET_STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_OCTET_STRING; cdecl;
function i2d_ASN1_OCTET_STRING(a: PASN1_OCTET_STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ASN1_OCTET_STRING_it: PASN1_ITEM; cdecl;
function ASN1_OCTET_STRING_dup(a: PASN1_OCTET_STRING): PASN1_OCTET_STRING; cdecl;
function ASN1_OCTET_STRING_cmp(a: PASN1_OCTET_STRING; b: PASN1_OCTET_STRING): TIdC_INT; cdecl;
function ASN1_OCTET_STRING_set(str: PASN1_OCTET_STRING; data: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
function ASN1_VISIBLESTRING_new: PASN1_VISIBLESTRING; cdecl;
procedure ASN1_VISIBLESTRING_free(a: PASN1_VISIBLESTRING); cdecl;
function d2i_ASN1_VISIBLESTRING(a: PPASN1_VISIBLESTRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_VISIBLESTRING; cdecl;
function i2d_ASN1_VISIBLESTRING(a: PASN1_VISIBLESTRING; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ASN1_VISIBLESTRING_it: PASN1_ITEM; cdecl;
function ASN1_UNIVERSALSTRING_new: PASN1_UNIVERSALSTRING; cdecl;
procedure ASN1_UNIVERSALSTRING_free(a: PASN1_UNIVERSALSTRING); cdecl;
function d2i_ASN1_UNIVERSALSTRING(a: PPASN1_UNIVERSALSTRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_UNIVERSALSTRING; cdecl;
function i2d_ASN1_UNIVERSALSTRING(a: PASN1_UNIVERSALSTRING; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ASN1_UNIVERSALSTRING_it: PASN1_ITEM; cdecl;
function ASN1_UTF8STRING_new: PASN1_UTF8STRING; cdecl;
procedure ASN1_UTF8STRING_free(a: PASN1_UTF8STRING); cdecl;
function d2i_ASN1_UTF8STRING(a: PPASN1_UTF8STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_UTF8STRING; cdecl;
function i2d_ASN1_UTF8STRING(a: PASN1_UTF8STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ASN1_UTF8STRING_it: PASN1_ITEM; cdecl;
function ASN1_NULL_new: PASN1_NULL; cdecl;
procedure ASN1_NULL_free(a: PASN1_NULL); cdecl;
function d2i_ASN1_NULL(a: PPASN1_NULL; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_NULL; cdecl;
function i2d_ASN1_NULL(a: PASN1_NULL; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ASN1_NULL_it: PASN1_ITEM; cdecl;
function ASN1_BMPSTRING_new: PASN1_BMPSTRING; cdecl;
procedure ASN1_BMPSTRING_free(a: PASN1_BMPSTRING); cdecl;
function d2i_ASN1_BMPSTRING(a: PPASN1_BMPSTRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_BMPSTRING; cdecl;
function i2d_ASN1_BMPSTRING(a: PASN1_BMPSTRING; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ASN1_BMPSTRING_it: PASN1_ITEM; cdecl;
function UTF8_getc(str: PIdAnsiChar; len: TIdC_INT; val: PIdC_ULONG): TIdC_INT; cdecl;
function UTF8_putc(str: PIdAnsiChar; len: TIdC_INT; value: TIdC_ULONG): TIdC_INT; cdecl;
function ASN1_PRINTABLE_new: PASN1_STRING; cdecl;
procedure ASN1_PRINTABLE_free(a: PASN1_STRING); cdecl;
function d2i_ASN1_PRINTABLE(a: PPASN1_STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_STRING; cdecl;
function i2d_ASN1_PRINTABLE(a: PASN1_STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ASN1_PRINTABLE_it: PASN1_ITEM; cdecl;
function DIRECTORYSTRING_new: PASN1_STRING; cdecl;
procedure DIRECTORYSTRING_free(a: PASN1_STRING); cdecl;
function d2i_DIRECTORYSTRING(a: PPASN1_STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_STRING; cdecl;
function i2d_DIRECTORYSTRING(a: PASN1_STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function DIRECTORYSTRING_it: PASN1_ITEM; cdecl;
function DISPLAYTEXT_new: PASN1_STRING; cdecl;
procedure DISPLAYTEXT_free(a: PASN1_STRING); cdecl;
function d2i_DISPLAYTEXT(a: PPASN1_STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_STRING; cdecl;
function i2d_DISPLAYTEXT(a: PASN1_STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function DISPLAYTEXT_it: PASN1_ITEM; cdecl;
function ASN1_PRINTABLESTRING_new: PASN1_PRINTABLESTRING; cdecl;
procedure ASN1_PRINTABLESTRING_free(a: PASN1_PRINTABLESTRING); cdecl;
function d2i_ASN1_PRINTABLESTRING(a: PPASN1_PRINTABLESTRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_PRINTABLESTRING; cdecl;
function i2d_ASN1_PRINTABLESTRING(a: PASN1_PRINTABLESTRING; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ASN1_PRINTABLESTRING_it: PASN1_ITEM; cdecl;
function ASN1_T61STRING_new: PASN1_T61STRING; cdecl;
procedure ASN1_T61STRING_free(a: PASN1_T61STRING); cdecl;
function d2i_ASN1_T61STRING(a: PPASN1_T61STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_T61STRING; cdecl;
function i2d_ASN1_T61STRING(a: PASN1_T61STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ASN1_T61STRING_it: PASN1_ITEM; cdecl;
function ASN1_IA5STRING_new: PASN1_IA5STRING; cdecl;
procedure ASN1_IA5STRING_free(a: PASN1_IA5STRING); cdecl;
function d2i_ASN1_IA5STRING(a: PPASN1_IA5STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_IA5STRING; cdecl;
function i2d_ASN1_IA5STRING(a: PASN1_IA5STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ASN1_IA5STRING_it: PASN1_ITEM; cdecl;
function ASN1_GENERALSTRING_new: PASN1_GENERALSTRING; cdecl;
procedure ASN1_GENERALSTRING_free(a: PASN1_GENERALSTRING); cdecl;
function d2i_ASN1_GENERALSTRING(a: PPASN1_GENERALSTRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_GENERALSTRING; cdecl;
function i2d_ASN1_GENERALSTRING(a: PASN1_GENERALSTRING; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ASN1_GENERALSTRING_it: PASN1_ITEM; cdecl;
function ASN1_UTCTIME_new: PASN1_UTCTIME; cdecl;
procedure ASN1_UTCTIME_free(a: PASN1_UTCTIME); cdecl;
function d2i_ASN1_UTCTIME(a: PPASN1_UTCTIME; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_UTCTIME; cdecl;
function i2d_ASN1_UTCTIME(a: PASN1_UTCTIME; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ASN1_UTCTIME_it: PASN1_ITEM; cdecl;
function ASN1_GENERALIZEDTIME_new: PASN1_GENERALIZEDTIME; cdecl;
procedure ASN1_GENERALIZEDTIME_free(a: PASN1_GENERALIZEDTIME); cdecl;
function d2i_ASN1_GENERALIZEDTIME(a: PPASN1_GENERALIZEDTIME; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_GENERALIZEDTIME; cdecl;
function i2d_ASN1_GENERALIZEDTIME(a: PASN1_GENERALIZEDTIME; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ASN1_GENERALIZEDTIME_it: PASN1_ITEM; cdecl;
function ASN1_TIME_new: PASN1_TIME; cdecl;
procedure ASN1_TIME_free(a: PASN1_TIME); cdecl;
function d2i_ASN1_TIME(a: PPASN1_TIME; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_TIME; cdecl;
function i2d_ASN1_TIME(a: PASN1_TIME; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ASN1_TIME_it: PASN1_ITEM; cdecl;
function ASN1_TIME_dup(a: PASN1_TIME): PASN1_TIME; cdecl;
function ASN1_UTCTIME_dup(a: PASN1_UTCTIME): PASN1_UTCTIME; cdecl;
function ASN1_GENERALIZEDTIME_dup(a: PASN1_GENERALIZEDTIME): PASN1_GENERALIZEDTIME; cdecl;
function ASN1_OCTET_STRING_NDEF_it: PASN1_ITEM; cdecl;
function ASN1_TIME_set(s: PASN1_TIME; t: TIdC_TIME_T): PASN1_TIME; cdecl;
function ASN1_TIME_adj(s: PASN1_TIME; t: TIdC_TIME_T; offset_day: TIdC_INT; offset_sec: TIdC_LONG): PASN1_TIME; cdecl;
function ASN1_TIME_check(t: PASN1_TIME): TIdC_INT; cdecl;
function ASN1_TIME_to_generalizedtime(t: PASN1_TIME; _out: PPASN1_GENERALIZEDTIME): PASN1_GENERALIZEDTIME; cdecl;
function ASN1_TIME_set_string(s: PASN1_TIME; str: PIdAnsiChar): TIdC_INT; cdecl;
function ASN1_TIME_set_string_X509(s: PASN1_TIME; str: PIdAnsiChar): TIdC_INT; cdecl;
function ASN1_TIME_to_tm(s: PASN1_TIME; tm: Ptm): TIdC_INT; cdecl;
function ASN1_TIME_normalize(s: PASN1_TIME): TIdC_INT; cdecl;
function ASN1_TIME_cmp_time_t(s: PASN1_TIME; t: TIdC_TIME_T): TIdC_INT; cdecl;
function ASN1_TIME_compare(a: PASN1_TIME; b: PASN1_TIME): TIdC_INT; cdecl;
function i2a_ASN1_INTEGER(bp: PBIO; a: PASN1_INTEGER): TIdC_INT; cdecl;
function a2i_ASN1_INTEGER(bp: PBIO; bs: PASN1_INTEGER; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT; cdecl;
function i2a_ASN1_ENUMERATED(bp: PBIO; a: PASN1_ENUMERATED): TIdC_INT; cdecl;
function a2i_ASN1_ENUMERATED(bp: PBIO; bs: PASN1_ENUMERATED; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT; cdecl;
function i2a_ASN1_OBJECT(bp: PBIO; a: PASN1_OBJECT): TIdC_INT; cdecl;
function a2i_ASN1_STRING(bp: PBIO; bs: PASN1_STRING; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT; cdecl;
function i2a_ASN1_STRING(bp: PBIO; a: PASN1_STRING; _type: TIdC_INT): TIdC_INT; cdecl;
function i2t_ASN1_OBJECT(buf: PIdAnsiChar; buf_len: TIdC_INT; a: PASN1_OBJECT): TIdC_INT; cdecl;
function a2d_ASN1_OBJECT(_out: PIdAnsiChar; olen: TIdC_INT; buf: PIdAnsiChar; num: TIdC_INT): TIdC_INT; cdecl;
function ASN1_OBJECT_create(nid: TIdC_INT; data: PIdAnsiChar; len: TIdC_INT; sn: PIdAnsiChar; ln: PIdAnsiChar): PASN1_OBJECT; cdecl;
function ASN1_INTEGER_get_int64(pr: PInt64; a: PASN1_INTEGER): TIdC_INT; cdecl;
function ASN1_INTEGER_set_int64(a: PASN1_INTEGER; r: Int64): TIdC_INT; cdecl;
function ASN1_INTEGER_get_uint64(pr: PUInt64; a: PASN1_INTEGER): TIdC_INT; cdecl;
function ASN1_INTEGER_set_uint64(a: PASN1_INTEGER; r: UInt64): TIdC_INT; cdecl;
function ASN1_INTEGER_set(a: PASN1_INTEGER; v: TIdC_LONG): TIdC_INT; cdecl;
function ASN1_INTEGER_get(a: PASN1_INTEGER): TIdC_LONG; cdecl;
function BN_to_ASN1_INTEGER(bn: PBIGNUM; ai: PASN1_INTEGER): PASN1_INTEGER; cdecl;
function ASN1_INTEGER_to_BN(ai: PASN1_INTEGER; bn: PBIGNUM): PBIGNUM; cdecl;
function ASN1_ENUMERATED_get_int64(pr: PInt64; a: PASN1_ENUMERATED): TIdC_INT; cdecl;
function ASN1_ENUMERATED_set_int64(a: PASN1_ENUMERATED; r: Int64): TIdC_INT; cdecl;
function ASN1_ENUMERATED_set(a: PASN1_ENUMERATED; v: TIdC_LONG): TIdC_INT; cdecl;
function ASN1_ENUMERATED_get(a: PASN1_ENUMERATED): TIdC_LONG; cdecl;
function BN_to_ASN1_ENUMERATED(bn: PBIGNUM; ai: PASN1_ENUMERATED): PASN1_ENUMERATED; cdecl;
function ASN1_ENUMERATED_to_BN(ai: PASN1_ENUMERATED; bn: PBIGNUM): PBIGNUM; cdecl;
function ASN1_PRINTABLE_type(s: PIdAnsiChar; max: TIdC_INT): TIdC_INT; cdecl;
function ASN1_tag2bit(tag: TIdC_INT): TIdC_ULONG; cdecl;
function ASN1_get_object(pp: PPIdAnsiChar; plength: PIdC_LONG; ptag: PIdC_INT; pclass: PIdC_INT; omax: TIdC_LONG): TIdC_INT; cdecl;
function ASN1_check_infinite_end(p: PPIdAnsiChar; len: TIdC_LONG): TIdC_INT; cdecl;
function ASN1_const_check_infinite_end(p: PPIdAnsiChar; len: TIdC_LONG): TIdC_INT; cdecl;
procedure ASN1_put_object(pp: PPIdAnsiChar; constructed: TIdC_INT; length: TIdC_INT; tag: TIdC_INT; xclass: TIdC_INT); cdecl;
function ASN1_put_eoc(pp: PPIdAnsiChar): TIdC_INT; cdecl;
function ASN1_object_size(constructed: TIdC_INT; length: TIdC_INT; tag: TIdC_INT): TIdC_INT; cdecl;
function ASN1_dup(i2d: Ti2d_of_void_func_cb; d2i: Td2i_of_void_func_cb; x: Pointer): Pointer; cdecl;
function ASN1_item_dup(it: PASN1_ITEM; x: Pointer): Pointer; cdecl;
function ASN1_item_sign_ex(it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; id: PASN1_OCTET_STRING; pkey: PEVP_PKEY; md: PEVP_MD; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
function ASN1_item_verify_ex(it: PASN1_ITEM; alg: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; id: PASN1_OCTET_STRING; pkey: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
function ASN1_d2i_fp(xnew: TASN1_d2i_fp_xnew_cb; d2i: Td2i_of_void_func_cb; _in: PFILE; x: PPointer): Pointer; cdecl;
function ASN1_item_d2i_fp_ex(it: PASN1_ITEM; _in: PFILE; x: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): Pointer; cdecl;
function ASN1_item_d2i_fp(it: PASN1_ITEM; _in: PFILE; x: Pointer): Pointer; cdecl;
function ASN1_i2d_fp(i2d: Ti2d_of_void_func_cb; _out: PFILE; x: Pointer): TIdC_INT; cdecl;
function ASN1_item_i2d_fp(it: PASN1_ITEM; _out: PFILE; x: Pointer): TIdC_INT; cdecl;
function ASN1_STRING_print_ex_fp(fp: PFILE; str: PASN1_STRING; flags: TIdC_ULONG): TIdC_INT; cdecl;
function ASN1_STRING_to_UTF8(_out: PPIdAnsiChar; _in: PASN1_STRING): TIdC_INT; cdecl;
function ASN1_d2i_bio(xnew: TASN1_d2i_fp_xnew_cb; d2i: Td2i_of_void_func_cb; _in: PBIO; x: PPointer): Pointer; cdecl;
function ASN1_item_d2i_bio_ex(it: PASN1_ITEM; _in: PBIO; pval: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): Pointer; cdecl;
function ASN1_item_d2i_bio(it: PASN1_ITEM; _in: PBIO; pval: Pointer): Pointer; cdecl;
function ASN1_i2d_bio(i2d: Ti2d_of_void_func_cb; _out: PBIO; x: Pointer): TIdC_INT; cdecl;
function ASN1_item_i2d_bio(it: PASN1_ITEM; _out: PBIO; x: Pointer): TIdC_INT; cdecl;
function ASN1_item_i2d_mem_bio(it: PASN1_ITEM; val: PASN1_VALUE): PBIO; cdecl;
function ASN1_UTCTIME_print(fp: PBIO; a: PASN1_UTCTIME): TIdC_INT; cdecl;
function ASN1_GENERALIZEDTIME_print(fp: PBIO; a: PASN1_GENERALIZEDTIME): TIdC_INT; cdecl;
function ASN1_TIME_print(bp: PBIO; tm: PASN1_TIME): TIdC_INT; cdecl;
function ASN1_TIME_print_ex(bp: PBIO; tm: PASN1_TIME; flags: TIdC_ULONG): TIdC_INT; cdecl;
function ASN1_STRING_print(bp: PBIO; v: PASN1_STRING): TIdC_INT; cdecl;
function ASN1_STRING_print_ex(_out: PBIO; str: PASN1_STRING; flags: TIdC_ULONG): TIdC_INT; cdecl;
function ASN1_buf_print(bp: PBIO; buf: PIdAnsiChar; buflen: TIdC_SIZET; off: TIdC_INT): TIdC_INT; cdecl;
function ASN1_bn_print(bp: PBIO; number: PIdAnsiChar; num: PBIGNUM; buf: PIdAnsiChar; off: TIdC_INT): TIdC_INT; cdecl;
function ASN1_parse(bp: PBIO; pp: PIdAnsiChar; len: TIdC_LONG; indent: TIdC_INT): TIdC_INT; cdecl;
function ASN1_parse_dump(bp: PBIO; pp: PIdAnsiChar; len: TIdC_LONG; indent: TIdC_INT; dump: TIdC_INT): TIdC_INT; cdecl;
function ASN1_tag2str(tag: TIdC_INT): PIdAnsiChar; cdecl;
function ASN1_UNIVERSALSTRING_to_string(s: PASN1_UNIVERSALSTRING): TIdC_INT; cdecl;
function ASN1_TYPE_set_octetstring(a: PASN1_TYPE; data: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
function ASN1_TYPE_get_octetstring(a: PASN1_TYPE; data: PIdAnsiChar; max_len: TIdC_INT): TIdC_INT; cdecl;
function ASN1_TYPE_set_int_octetstring(a: PASN1_TYPE; num: TIdC_LONG; data: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
function ASN1_TYPE_get_int_octetstring(a: PASN1_TYPE; num: PIdC_LONG; data: PIdAnsiChar; max_len: TIdC_INT): TIdC_INT; cdecl;
function ASN1_item_unpack(oct: PASN1_STRING; it: PASN1_ITEM): Pointer; cdecl;
function ASN1_item_unpack_ex(oct: PASN1_STRING; it: PASN1_ITEM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): Pointer; cdecl;
function ASN1_item_pack(obj: Pointer; it: PASN1_ITEM; oct: PPASN1_OCTET_STRING): PASN1_STRING; cdecl;
procedure ASN1_STRING_set_default_mask(mask: TIdC_ULONG); cdecl;
function ASN1_STRING_set_default_mask_asc(p: PIdAnsiChar): TIdC_INT; cdecl;
function ASN1_STRING_get_default_mask: TIdC_ULONG; cdecl;
function ASN1_mbstring_copy(_out: PPASN1_STRING; _in: PIdAnsiChar; len: TIdC_INT; inform: TIdC_INT; mask: TIdC_ULONG): TIdC_INT; cdecl;
function ASN1_mbstring_ncopy(_out: PPASN1_STRING; _in: PIdAnsiChar; len: TIdC_INT; inform: TIdC_INT; mask: TIdC_ULONG; minsize: TIdC_LONG; maxsize: TIdC_LONG): TIdC_INT; cdecl;
function ASN1_STRING_set_by_NID(_out: PPASN1_STRING; _in: PIdAnsiChar; inlen: TIdC_INT; inform: TIdC_INT; nid: TIdC_INT): PASN1_STRING; cdecl;
function ASN1_STRING_TABLE_get(nid: TIdC_INT): PASN1_STRING_TABLE; cdecl;
function ASN1_STRING_TABLE_add(arg1: TIdC_INT; arg2: TIdC_LONG; arg3: TIdC_LONG; arg4: TIdC_ULONG; arg5: TIdC_ULONG): TIdC_INT; cdecl;
procedure ASN1_STRING_TABLE_cleanup; cdecl;
function ASN1_item_new(it: PASN1_ITEM): PASN1_VALUE; cdecl;
function ASN1_item_new_ex(it: PASN1_ITEM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PASN1_VALUE; cdecl;
procedure ASN1_item_free(val: PASN1_VALUE; it: PASN1_ITEM); cdecl;
function ASN1_item_d2i_ex(val: PPASN1_VALUE; _in: PPIdAnsiChar; len: TIdC_LONG; it: PASN1_ITEM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PASN1_VALUE; cdecl;
function ASN1_item_d2i(val: PPASN1_VALUE; _in: PPIdAnsiChar; len: TIdC_LONG; it: PASN1_ITEM): PASN1_VALUE; cdecl;
function ASN1_item_i2d(val: PASN1_VALUE; _out: PPIdAnsiChar; it: PASN1_ITEM): TIdC_INT; cdecl;
function ASN1_item_ndef_i2d(val: PASN1_VALUE; _out: PPIdAnsiChar; it: PASN1_ITEM): TIdC_INT; cdecl;
procedure ASN1_add_oid_module; cdecl;
procedure ASN1_add_stable_module; cdecl;
function ASN1_generate_nconf(str: PIdAnsiChar; nconf: PCONF): PASN1_TYPE; cdecl;
function ASN1_generate_v3(str: PIdAnsiChar; cnf: PX509V3_CTX): PASN1_TYPE; cdecl;
function ASN1_str2mask(str: PIdAnsiChar; pmask: PIdC_ULONG): TIdC_INT; cdecl;
function ASN1_item_print(_out: PBIO; ifld: PASN1_VALUE; indent: TIdC_INT; it: PASN1_ITEM; pctx: PASN1_PCTX): TIdC_INT; cdecl;
function ASN1_PCTX_new: PASN1_PCTX; cdecl;
procedure ASN1_PCTX_free(p: PASN1_PCTX); cdecl;
function ASN1_PCTX_get_flags(p: PASN1_PCTX): TIdC_ULONG; cdecl;
procedure ASN1_PCTX_set_flags(p: PASN1_PCTX; flags: TIdC_ULONG); cdecl;
function ASN1_PCTX_get_nm_flags(p: PASN1_PCTX): TIdC_ULONG; cdecl;
procedure ASN1_PCTX_set_nm_flags(p: PASN1_PCTX; flags: TIdC_ULONG); cdecl;
function ASN1_PCTX_get_cert_flags(p: PASN1_PCTX): TIdC_ULONG; cdecl;
procedure ASN1_PCTX_set_cert_flags(p: PASN1_PCTX; flags: TIdC_ULONG); cdecl;
function ASN1_PCTX_get_oid_flags(p: PASN1_PCTX): TIdC_ULONG; cdecl;
procedure ASN1_PCTX_set_oid_flags(p: PASN1_PCTX; flags: TIdC_ULONG); cdecl;
function ASN1_PCTX_get_str_flags(p: PASN1_PCTX): TIdC_ULONG; cdecl;
procedure ASN1_PCTX_set_str_flags(p: PASN1_PCTX; flags: TIdC_ULONG); cdecl;
function ASN1_SCTX_new(scan_cb: TASN1_SCTX_new_scan_cb_cb): PASN1_SCTX; cdecl;
procedure ASN1_SCTX_free(p: PASN1_SCTX); cdecl;
function ASN1_SCTX_get_item(p: PASN1_SCTX): PASN1_ITEM; cdecl;
function ASN1_SCTX_get_template(p: PASN1_SCTX): PASN1_TEMPLATE; cdecl;
function ASN1_SCTX_get_flags(p: PASN1_SCTX): TIdC_ULONG; cdecl;
procedure ASN1_SCTX_set_app_data(p: PASN1_SCTX; data: Pointer); cdecl;
function ASN1_SCTX_get_app_data(p: PASN1_SCTX): Pointer; cdecl;
function BIO_f_asn1: PBIO_METHOD; cdecl;
function BIO_new_NDEF(_out: PBIO; val: PASN1_VALUE; it: PASN1_ITEM): PBIO; cdecl;
function i2d_ASN1_bio_stream(_out: PBIO; val: PASN1_VALUE; _in: PBIO; flags: TIdC_INT; it: PASN1_ITEM): TIdC_INT; cdecl;
function PEM_write_bio_ASN1_stream(_out: PBIO; val: PASN1_VALUE; _in: PBIO; flags: TIdC_INT; hdr: PIdAnsiChar; it: PASN1_ITEM): TIdC_INT; cdecl;
function SMIME_write_ASN1(bio: PBIO; val: PASN1_VALUE; data: PBIO; flags: TIdC_INT; ctype_nid: TIdC_INT; econt_nid: TIdC_INT; mdalgs: Pstack_st_X509_ALGOR; it: PASN1_ITEM): TIdC_INT; cdecl;
function SMIME_write_ASN1_ex(bio: PBIO; val: PASN1_VALUE; data: PBIO; flags: TIdC_INT; ctype_nid: TIdC_INT; econt_nid: TIdC_INT; mdalgs: Pstack_st_X509_ALGOR; it: PASN1_ITEM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
function SMIME_read_ASN1(bio: PBIO; bcont: PPBIO; it: PASN1_ITEM): PASN1_VALUE; cdecl;
function SMIME_read_ASN1_ex(bio: PBIO; flags: TIdC_INT; bcont: PPBIO; it: PASN1_ITEM; x: PPASN1_VALUE; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PASN1_VALUE; cdecl;
function SMIME_crlf_copy(_in: PBIO; _out: PBIO; flags: TIdC_INT): TIdC_INT; cdecl;
function SMIME_text(_in: PBIO; _out: PBIO): TIdC_INT; cdecl;
function ASN1_ITEM_lookup(name: PIdAnsiChar): PASN1_ITEM; cdecl;
function ASN1_ITEM_get(i: TIdC_SIZET): PASN1_ITEM; cdecl;
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

function d2i_ASN1_SEQUENCE_ANY(a: PPASN1_SEQUENCE_ANY; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_SEQUENCE_ANY; cdecl external CLibCrypto name 'd2i_ASN1_SEQUENCE_ANY';
function i2d_ASN1_SEQUENCE_ANY(a: PASN1_SEQUENCE_ANY; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ASN1_SEQUENCE_ANY';
function ASN1_SEQUENCE_ANY_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_SEQUENCE_ANY_it';
function d2i_ASN1_SET_ANY(a: PPASN1_SEQUENCE_ANY; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_SEQUENCE_ANY; cdecl external CLibCrypto name 'd2i_ASN1_SET_ANY';
function i2d_ASN1_SET_ANY(a: PASN1_SEQUENCE_ANY; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ASN1_SET_ANY';
function ASN1_SET_ANY_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_SET_ANY_it';
function ASN1_TYPE_new: PASN1_TYPE; cdecl external CLibCrypto name 'ASN1_TYPE_new';
procedure ASN1_TYPE_free(a: PASN1_TYPE); cdecl external CLibCrypto name 'ASN1_TYPE_free';
function d2i_ASN1_TYPE(a: PPASN1_TYPE; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_TYPE; cdecl external CLibCrypto name 'd2i_ASN1_TYPE';
function i2d_ASN1_TYPE(a: PASN1_TYPE; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ASN1_TYPE';
function ASN1_ANY_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_ANY_it';
function ASN1_TYPE_get(a: PASN1_TYPE): TIdC_INT; cdecl external CLibCrypto name 'ASN1_TYPE_get';
procedure ASN1_TYPE_set(a: PASN1_TYPE; _type: TIdC_INT; value: Pointer); cdecl external CLibCrypto name 'ASN1_TYPE_set';
function ASN1_TYPE_set1(a: PASN1_TYPE; _type: TIdC_INT; value: Pointer): TIdC_INT; cdecl external CLibCrypto name 'ASN1_TYPE_set1';
function ASN1_TYPE_cmp(a: PASN1_TYPE; b: PASN1_TYPE): TIdC_INT; cdecl external CLibCrypto name 'ASN1_TYPE_cmp';
function ASN1_TYPE_pack_sequence(it: PASN1_ITEM; s: Pointer; t: PPASN1_TYPE): PASN1_TYPE; cdecl external CLibCrypto name 'ASN1_TYPE_pack_sequence';
function ASN1_TYPE_unpack_sequence(it: PASN1_ITEM; t: PASN1_TYPE): Pointer; cdecl external CLibCrypto name 'ASN1_TYPE_unpack_sequence';
function ASN1_OBJECT_new: PASN1_OBJECT; cdecl external CLibCrypto name 'ASN1_OBJECT_new';
procedure ASN1_OBJECT_free(a: PASN1_OBJECT); cdecl external CLibCrypto name 'ASN1_OBJECT_free';
function d2i_ASN1_OBJECT(a: PPASN1_OBJECT; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_OBJECT; cdecl external CLibCrypto name 'd2i_ASN1_OBJECT';
function i2d_ASN1_OBJECT(a: PASN1_OBJECT; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ASN1_OBJECT';
function ASN1_OBJECT_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_OBJECT_it';
function ASN1_STRING_new: PASN1_STRING; cdecl external CLibCrypto name 'ASN1_STRING_new';
procedure ASN1_STRING_free(a: PASN1_STRING); cdecl external CLibCrypto name 'ASN1_STRING_free';
procedure ASN1_STRING_clear_free(a: PASN1_STRING); cdecl external CLibCrypto name 'ASN1_STRING_clear_free';
function ASN1_STRING_copy(dst: PASN1_STRING; str: PASN1_STRING): TIdC_INT; cdecl external CLibCrypto name 'ASN1_STRING_copy';
function ASN1_STRING_dup(a: PASN1_STRING): PASN1_STRING; cdecl external CLibCrypto name 'ASN1_STRING_dup';
function ASN1_STRING_type_new(_type: TIdC_INT): PASN1_STRING; cdecl external CLibCrypto name 'ASN1_STRING_type_new';
function ASN1_STRING_cmp(a: PASN1_STRING; b: PASN1_STRING): TIdC_INT; cdecl external CLibCrypto name 'ASN1_STRING_cmp';
function ASN1_STRING_set(str: PASN1_STRING; data: Pointer; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'ASN1_STRING_set';
procedure ASN1_STRING_set0(str: PASN1_STRING; data: Pointer; len: TIdC_INT); cdecl external CLibCrypto name 'ASN1_STRING_set0';
function ASN1_STRING_length(x: PASN1_STRING): TIdC_INT; cdecl external CLibCrypto name 'ASN1_STRING_length';
procedure ASN1_STRING_length_set(x: PASN1_STRING; n: TIdC_INT); cdecl external CLibCrypto name 'ASN1_STRING_length_set';
function ASN1_STRING_type(x: PASN1_STRING): TIdC_INT; cdecl external CLibCrypto name 'ASN1_STRING_type';
function ASN1_STRING_get0_data(x: PASN1_STRING): PIdAnsiChar; cdecl external CLibCrypto name 'ASN1_STRING_get0_data';
function ASN1_BIT_STRING_new: PASN1_BIT_STRING; cdecl external CLibCrypto name 'ASN1_BIT_STRING_new';
procedure ASN1_BIT_STRING_free(a: PASN1_BIT_STRING); cdecl external CLibCrypto name 'ASN1_BIT_STRING_free';
function d2i_ASN1_BIT_STRING(a: PPASN1_BIT_STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_BIT_STRING; cdecl external CLibCrypto name 'd2i_ASN1_BIT_STRING';
function i2d_ASN1_BIT_STRING(a: PASN1_BIT_STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ASN1_BIT_STRING';
function ASN1_BIT_STRING_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_BIT_STRING_it';
function ASN1_BIT_STRING_set(a: PASN1_BIT_STRING; d: PIdAnsiChar; length: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'ASN1_BIT_STRING_set';
function ASN1_BIT_STRING_set_bit(a: PASN1_BIT_STRING; n: TIdC_INT; value: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'ASN1_BIT_STRING_set_bit';
function ASN1_BIT_STRING_get_bit(a: PASN1_BIT_STRING; n: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'ASN1_BIT_STRING_get_bit';
function ASN1_BIT_STRING_check(a: PASN1_BIT_STRING; flags: PIdAnsiChar; flags_len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'ASN1_BIT_STRING_check';
function ASN1_BIT_STRING_name_print(_out: PBIO; bs: PASN1_BIT_STRING; tbl: PBIT_STRING_BITNAME; indent: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'ASN1_BIT_STRING_name_print';
function ASN1_BIT_STRING_num_asc(name: PIdAnsiChar; tbl: PBIT_STRING_BITNAME): TIdC_INT; cdecl external CLibCrypto name 'ASN1_BIT_STRING_num_asc';
function ASN1_BIT_STRING_set_asc(bs: PASN1_BIT_STRING; name: PIdAnsiChar; value: TIdC_INT; tbl: PBIT_STRING_BITNAME): TIdC_INT; cdecl external CLibCrypto name 'ASN1_BIT_STRING_set_asc';
function ASN1_INTEGER_new: PASN1_INTEGER; cdecl external CLibCrypto name 'ASN1_INTEGER_new';
procedure ASN1_INTEGER_free(a: PASN1_INTEGER); cdecl external CLibCrypto name 'ASN1_INTEGER_free';
function d2i_ASN1_INTEGER(a: PPASN1_INTEGER; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_INTEGER; cdecl external CLibCrypto name 'd2i_ASN1_INTEGER';
function i2d_ASN1_INTEGER(a: PASN1_INTEGER; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ASN1_INTEGER';
function ASN1_INTEGER_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_INTEGER_it';
function d2i_ASN1_UINTEGER(a: PPASN1_INTEGER; pp: PPIdAnsiChar; length: TIdC_LONG): PASN1_INTEGER; cdecl external CLibCrypto name 'd2i_ASN1_UINTEGER';
function ASN1_INTEGER_dup(a: PASN1_INTEGER): PASN1_INTEGER; cdecl external CLibCrypto name 'ASN1_INTEGER_dup';
function ASN1_INTEGER_cmp(x: PASN1_INTEGER; y: PASN1_INTEGER): TIdC_INT; cdecl external CLibCrypto name 'ASN1_INTEGER_cmp';
function ASN1_ENUMERATED_new: PASN1_ENUMERATED; cdecl external CLibCrypto name 'ASN1_ENUMERATED_new';
procedure ASN1_ENUMERATED_free(a: PASN1_ENUMERATED); cdecl external CLibCrypto name 'ASN1_ENUMERATED_free';
function d2i_ASN1_ENUMERATED(a: PPASN1_ENUMERATED; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_ENUMERATED; cdecl external CLibCrypto name 'd2i_ASN1_ENUMERATED';
function i2d_ASN1_ENUMERATED(a: PASN1_ENUMERATED; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ASN1_ENUMERATED';
function ASN1_ENUMERATED_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_ENUMERATED_it';
function ASN1_UTCTIME_check(a: PASN1_UTCTIME): TIdC_INT; cdecl external CLibCrypto name 'ASN1_UTCTIME_check';
function ASN1_UTCTIME_set(s: PASN1_UTCTIME; t: TIdC_TIME_T): PASN1_UTCTIME; cdecl external CLibCrypto name 'ASN1_UTCTIME_set';
function ASN1_UTCTIME_adj(s: PASN1_UTCTIME; t: TIdC_TIME_T; offset_day: TIdC_INT; offset_sec: TIdC_LONG): PASN1_UTCTIME; cdecl external CLibCrypto name 'ASN1_UTCTIME_adj';
function ASN1_UTCTIME_set_string(s: PASN1_UTCTIME; str: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'ASN1_UTCTIME_set_string';
function ASN1_UTCTIME_cmp_time_t(s: PASN1_UTCTIME; t: TIdC_TIME_T): TIdC_INT; cdecl external CLibCrypto name 'ASN1_UTCTIME_cmp_time_t';
function ASN1_GENERALIZEDTIME_check(a: PASN1_GENERALIZEDTIME): TIdC_INT; cdecl external CLibCrypto name 'ASN1_GENERALIZEDTIME_check';
function ASN1_GENERALIZEDTIME_set(s: PASN1_GENERALIZEDTIME; t: TIdC_TIME_T): PASN1_GENERALIZEDTIME; cdecl external CLibCrypto name 'ASN1_GENERALIZEDTIME_set';
function ASN1_GENERALIZEDTIME_adj(s: PASN1_GENERALIZEDTIME; t: TIdC_TIME_T; offset_day: TIdC_INT; offset_sec: TIdC_LONG): PASN1_GENERALIZEDTIME; cdecl external CLibCrypto name 'ASN1_GENERALIZEDTIME_adj';
function ASN1_GENERALIZEDTIME_set_string(s: PASN1_GENERALIZEDTIME; str: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'ASN1_GENERALIZEDTIME_set_string';
function ASN1_TIME_diff(pday: PIdC_INT; psec: PIdC_INT; from: PASN1_TIME; _to: PASN1_TIME): TIdC_INT; cdecl external CLibCrypto name 'ASN1_TIME_diff';
function ASN1_OCTET_STRING_new: PASN1_OCTET_STRING; cdecl external CLibCrypto name 'ASN1_OCTET_STRING_new';
procedure ASN1_OCTET_STRING_free(a: PASN1_OCTET_STRING); cdecl external CLibCrypto name 'ASN1_OCTET_STRING_free';
function d2i_ASN1_OCTET_STRING(a: PPASN1_OCTET_STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_OCTET_STRING; cdecl external CLibCrypto name 'd2i_ASN1_OCTET_STRING';
function i2d_ASN1_OCTET_STRING(a: PASN1_OCTET_STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ASN1_OCTET_STRING';
function ASN1_OCTET_STRING_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_OCTET_STRING_it';
function ASN1_OCTET_STRING_dup(a: PASN1_OCTET_STRING): PASN1_OCTET_STRING; cdecl external CLibCrypto name 'ASN1_OCTET_STRING_dup';
function ASN1_OCTET_STRING_cmp(a: PASN1_OCTET_STRING; b: PASN1_OCTET_STRING): TIdC_INT; cdecl external CLibCrypto name 'ASN1_OCTET_STRING_cmp';
function ASN1_OCTET_STRING_set(str: PASN1_OCTET_STRING; data: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'ASN1_OCTET_STRING_set';
function ASN1_VISIBLESTRING_new: PASN1_VISIBLESTRING; cdecl external CLibCrypto name 'ASN1_VISIBLESTRING_new';
procedure ASN1_VISIBLESTRING_free(a: PASN1_VISIBLESTRING); cdecl external CLibCrypto name 'ASN1_VISIBLESTRING_free';
function d2i_ASN1_VISIBLESTRING(a: PPASN1_VISIBLESTRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_VISIBLESTRING; cdecl external CLibCrypto name 'd2i_ASN1_VISIBLESTRING';
function i2d_ASN1_VISIBLESTRING(a: PASN1_VISIBLESTRING; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ASN1_VISIBLESTRING';
function ASN1_VISIBLESTRING_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_VISIBLESTRING_it';
function ASN1_UNIVERSALSTRING_new: PASN1_UNIVERSALSTRING; cdecl external CLibCrypto name 'ASN1_UNIVERSALSTRING_new';
procedure ASN1_UNIVERSALSTRING_free(a: PASN1_UNIVERSALSTRING); cdecl external CLibCrypto name 'ASN1_UNIVERSALSTRING_free';
function d2i_ASN1_UNIVERSALSTRING(a: PPASN1_UNIVERSALSTRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_UNIVERSALSTRING; cdecl external CLibCrypto name 'd2i_ASN1_UNIVERSALSTRING';
function i2d_ASN1_UNIVERSALSTRING(a: PASN1_UNIVERSALSTRING; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ASN1_UNIVERSALSTRING';
function ASN1_UNIVERSALSTRING_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_UNIVERSALSTRING_it';
function ASN1_UTF8STRING_new: PASN1_UTF8STRING; cdecl external CLibCrypto name 'ASN1_UTF8STRING_new';
procedure ASN1_UTF8STRING_free(a: PASN1_UTF8STRING); cdecl external CLibCrypto name 'ASN1_UTF8STRING_free';
function d2i_ASN1_UTF8STRING(a: PPASN1_UTF8STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_UTF8STRING; cdecl external CLibCrypto name 'd2i_ASN1_UTF8STRING';
function i2d_ASN1_UTF8STRING(a: PASN1_UTF8STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ASN1_UTF8STRING';
function ASN1_UTF8STRING_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_UTF8STRING_it';
function ASN1_NULL_new: PASN1_NULL; cdecl external CLibCrypto name 'ASN1_NULL_new';
procedure ASN1_NULL_free(a: PASN1_NULL); cdecl external CLibCrypto name 'ASN1_NULL_free';
function d2i_ASN1_NULL(a: PPASN1_NULL; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_NULL; cdecl external CLibCrypto name 'd2i_ASN1_NULL';
function i2d_ASN1_NULL(a: PASN1_NULL; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ASN1_NULL';
function ASN1_NULL_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_NULL_it';
function ASN1_BMPSTRING_new: PASN1_BMPSTRING; cdecl external CLibCrypto name 'ASN1_BMPSTRING_new';
procedure ASN1_BMPSTRING_free(a: PASN1_BMPSTRING); cdecl external CLibCrypto name 'ASN1_BMPSTRING_free';
function d2i_ASN1_BMPSTRING(a: PPASN1_BMPSTRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_BMPSTRING; cdecl external CLibCrypto name 'd2i_ASN1_BMPSTRING';
function i2d_ASN1_BMPSTRING(a: PASN1_BMPSTRING; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ASN1_BMPSTRING';
function ASN1_BMPSTRING_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_BMPSTRING_it';
function UTF8_getc(str: PIdAnsiChar; len: TIdC_INT; val: PIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'UTF8_getc';
function UTF8_putc(str: PIdAnsiChar; len: TIdC_INT; value: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'UTF8_putc';
function ASN1_PRINTABLE_new: PASN1_STRING; cdecl external CLibCrypto name 'ASN1_PRINTABLE_new';
procedure ASN1_PRINTABLE_free(a: PASN1_STRING); cdecl external CLibCrypto name 'ASN1_PRINTABLE_free';
function d2i_ASN1_PRINTABLE(a: PPASN1_STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_STRING; cdecl external CLibCrypto name 'd2i_ASN1_PRINTABLE';
function i2d_ASN1_PRINTABLE(a: PASN1_STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ASN1_PRINTABLE';
function ASN1_PRINTABLE_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_PRINTABLE_it';
function DIRECTORYSTRING_new: PASN1_STRING; cdecl external CLibCrypto name 'DIRECTORYSTRING_new';
procedure DIRECTORYSTRING_free(a: PASN1_STRING); cdecl external CLibCrypto name 'DIRECTORYSTRING_free';
function d2i_DIRECTORYSTRING(a: PPASN1_STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_STRING; cdecl external CLibCrypto name 'd2i_DIRECTORYSTRING';
function i2d_DIRECTORYSTRING(a: PASN1_STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_DIRECTORYSTRING';
function DIRECTORYSTRING_it: PASN1_ITEM; cdecl external CLibCrypto name 'DIRECTORYSTRING_it';
function DISPLAYTEXT_new: PASN1_STRING; cdecl external CLibCrypto name 'DISPLAYTEXT_new';
procedure DISPLAYTEXT_free(a: PASN1_STRING); cdecl external CLibCrypto name 'DISPLAYTEXT_free';
function d2i_DISPLAYTEXT(a: PPASN1_STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_STRING; cdecl external CLibCrypto name 'd2i_DISPLAYTEXT';
function i2d_DISPLAYTEXT(a: PASN1_STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_DISPLAYTEXT';
function DISPLAYTEXT_it: PASN1_ITEM; cdecl external CLibCrypto name 'DISPLAYTEXT_it';
function ASN1_PRINTABLESTRING_new: PASN1_PRINTABLESTRING; cdecl external CLibCrypto name 'ASN1_PRINTABLESTRING_new';
procedure ASN1_PRINTABLESTRING_free(a: PASN1_PRINTABLESTRING); cdecl external CLibCrypto name 'ASN1_PRINTABLESTRING_free';
function d2i_ASN1_PRINTABLESTRING(a: PPASN1_PRINTABLESTRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_PRINTABLESTRING; cdecl external CLibCrypto name 'd2i_ASN1_PRINTABLESTRING';
function i2d_ASN1_PRINTABLESTRING(a: PASN1_PRINTABLESTRING; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ASN1_PRINTABLESTRING';
function ASN1_PRINTABLESTRING_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_PRINTABLESTRING_it';
function ASN1_T61STRING_new: PASN1_T61STRING; cdecl external CLibCrypto name 'ASN1_T61STRING_new';
procedure ASN1_T61STRING_free(a: PASN1_T61STRING); cdecl external CLibCrypto name 'ASN1_T61STRING_free';
function d2i_ASN1_T61STRING(a: PPASN1_T61STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_T61STRING; cdecl external CLibCrypto name 'd2i_ASN1_T61STRING';
function i2d_ASN1_T61STRING(a: PASN1_T61STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ASN1_T61STRING';
function ASN1_T61STRING_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_T61STRING_it';
function ASN1_IA5STRING_new: PASN1_IA5STRING; cdecl external CLibCrypto name 'ASN1_IA5STRING_new';
procedure ASN1_IA5STRING_free(a: PASN1_IA5STRING); cdecl external CLibCrypto name 'ASN1_IA5STRING_free';
function d2i_ASN1_IA5STRING(a: PPASN1_IA5STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_IA5STRING; cdecl external CLibCrypto name 'd2i_ASN1_IA5STRING';
function i2d_ASN1_IA5STRING(a: PASN1_IA5STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ASN1_IA5STRING';
function ASN1_IA5STRING_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_IA5STRING_it';
function ASN1_GENERALSTRING_new: PASN1_GENERALSTRING; cdecl external CLibCrypto name 'ASN1_GENERALSTRING_new';
procedure ASN1_GENERALSTRING_free(a: PASN1_GENERALSTRING); cdecl external CLibCrypto name 'ASN1_GENERALSTRING_free';
function d2i_ASN1_GENERALSTRING(a: PPASN1_GENERALSTRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_GENERALSTRING; cdecl external CLibCrypto name 'd2i_ASN1_GENERALSTRING';
function i2d_ASN1_GENERALSTRING(a: PASN1_GENERALSTRING; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ASN1_GENERALSTRING';
function ASN1_GENERALSTRING_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_GENERALSTRING_it';
function ASN1_UTCTIME_new: PASN1_UTCTIME; cdecl external CLibCrypto name 'ASN1_UTCTIME_new';
procedure ASN1_UTCTIME_free(a: PASN1_UTCTIME); cdecl external CLibCrypto name 'ASN1_UTCTIME_free';
function d2i_ASN1_UTCTIME(a: PPASN1_UTCTIME; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_UTCTIME; cdecl external CLibCrypto name 'd2i_ASN1_UTCTIME';
function i2d_ASN1_UTCTIME(a: PASN1_UTCTIME; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ASN1_UTCTIME';
function ASN1_UTCTIME_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_UTCTIME_it';
function ASN1_GENERALIZEDTIME_new: PASN1_GENERALIZEDTIME; cdecl external CLibCrypto name 'ASN1_GENERALIZEDTIME_new';
procedure ASN1_GENERALIZEDTIME_free(a: PASN1_GENERALIZEDTIME); cdecl external CLibCrypto name 'ASN1_GENERALIZEDTIME_free';
function d2i_ASN1_GENERALIZEDTIME(a: PPASN1_GENERALIZEDTIME; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_GENERALIZEDTIME; cdecl external CLibCrypto name 'd2i_ASN1_GENERALIZEDTIME';
function i2d_ASN1_GENERALIZEDTIME(a: PASN1_GENERALIZEDTIME; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ASN1_GENERALIZEDTIME';
function ASN1_GENERALIZEDTIME_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_GENERALIZEDTIME_it';
function ASN1_TIME_new: PASN1_TIME; cdecl external CLibCrypto name 'ASN1_TIME_new';
procedure ASN1_TIME_free(a: PASN1_TIME); cdecl external CLibCrypto name 'ASN1_TIME_free';
function d2i_ASN1_TIME(a: PPASN1_TIME; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_TIME; cdecl external CLibCrypto name 'd2i_ASN1_TIME';
function i2d_ASN1_TIME(a: PASN1_TIME; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ASN1_TIME';
function ASN1_TIME_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_TIME_it';
function ASN1_TIME_dup(a: PASN1_TIME): PASN1_TIME; cdecl external CLibCrypto name 'ASN1_TIME_dup';
function ASN1_UTCTIME_dup(a: PASN1_UTCTIME): PASN1_UTCTIME; cdecl external CLibCrypto name 'ASN1_UTCTIME_dup';
function ASN1_GENERALIZEDTIME_dup(a: PASN1_GENERALIZEDTIME): PASN1_GENERALIZEDTIME; cdecl external CLibCrypto name 'ASN1_GENERALIZEDTIME_dup';
function ASN1_OCTET_STRING_NDEF_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_OCTET_STRING_NDEF_it';
function ASN1_TIME_set(s: PASN1_TIME; t: TIdC_TIME_T): PASN1_TIME; cdecl external CLibCrypto name 'ASN1_TIME_set';
function ASN1_TIME_adj(s: PASN1_TIME; t: TIdC_TIME_T; offset_day: TIdC_INT; offset_sec: TIdC_LONG): PASN1_TIME; cdecl external CLibCrypto name 'ASN1_TIME_adj';
function ASN1_TIME_check(t: PASN1_TIME): TIdC_INT; cdecl external CLibCrypto name 'ASN1_TIME_check';
function ASN1_TIME_to_generalizedtime(t: PASN1_TIME; _out: PPASN1_GENERALIZEDTIME): PASN1_GENERALIZEDTIME; cdecl external CLibCrypto name 'ASN1_TIME_to_generalizedtime';
function ASN1_TIME_set_string(s: PASN1_TIME; str: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'ASN1_TIME_set_string';
function ASN1_TIME_set_string_X509(s: PASN1_TIME; str: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'ASN1_TIME_set_string_X509';
function ASN1_TIME_to_tm(s: PASN1_TIME; tm: Ptm): TIdC_INT; cdecl external CLibCrypto name 'ASN1_TIME_to_tm';
function ASN1_TIME_normalize(s: PASN1_TIME): TIdC_INT; cdecl external CLibCrypto name 'ASN1_TIME_normalize';
function ASN1_TIME_cmp_time_t(s: PASN1_TIME; t: TIdC_TIME_T): TIdC_INT; cdecl external CLibCrypto name 'ASN1_TIME_cmp_time_t';
function ASN1_TIME_compare(a: PASN1_TIME; b: PASN1_TIME): TIdC_INT; cdecl external CLibCrypto name 'ASN1_TIME_compare';
function i2a_ASN1_INTEGER(bp: PBIO; a: PASN1_INTEGER): TIdC_INT; cdecl external CLibCrypto name 'i2a_ASN1_INTEGER';
function a2i_ASN1_INTEGER(bp: PBIO; bs: PASN1_INTEGER; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'a2i_ASN1_INTEGER';
function i2a_ASN1_ENUMERATED(bp: PBIO; a: PASN1_ENUMERATED): TIdC_INT; cdecl external CLibCrypto name 'i2a_ASN1_ENUMERATED';
function a2i_ASN1_ENUMERATED(bp: PBIO; bs: PASN1_ENUMERATED; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'a2i_ASN1_ENUMERATED';
function i2a_ASN1_OBJECT(bp: PBIO; a: PASN1_OBJECT): TIdC_INT; cdecl external CLibCrypto name 'i2a_ASN1_OBJECT';
function a2i_ASN1_STRING(bp: PBIO; bs: PASN1_STRING; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'a2i_ASN1_STRING';
function i2a_ASN1_STRING(bp: PBIO; a: PASN1_STRING; _type: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'i2a_ASN1_STRING';
function i2t_ASN1_OBJECT(buf: PIdAnsiChar; buf_len: TIdC_INT; a: PASN1_OBJECT): TIdC_INT; cdecl external CLibCrypto name 'i2t_ASN1_OBJECT';
function a2d_ASN1_OBJECT(_out: PIdAnsiChar; olen: TIdC_INT; buf: PIdAnsiChar; num: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'a2d_ASN1_OBJECT';
function ASN1_OBJECT_create(nid: TIdC_INT; data: PIdAnsiChar; len: TIdC_INT; sn: PIdAnsiChar; ln: PIdAnsiChar): PASN1_OBJECT; cdecl external CLibCrypto name 'ASN1_OBJECT_create';
function ASN1_INTEGER_get_int64(pr: PInt64; a: PASN1_INTEGER): TIdC_INT; cdecl external CLibCrypto name 'ASN1_INTEGER_get_int64';
function ASN1_INTEGER_set_int64(a: PASN1_INTEGER; r: Int64): TIdC_INT; cdecl external CLibCrypto name 'ASN1_INTEGER_set_int64';
function ASN1_INTEGER_get_uint64(pr: PUInt64; a: PASN1_INTEGER): TIdC_INT; cdecl external CLibCrypto name 'ASN1_INTEGER_get_uint64';
function ASN1_INTEGER_set_uint64(a: PASN1_INTEGER; r: UInt64): TIdC_INT; cdecl external CLibCrypto name 'ASN1_INTEGER_set_uint64';
function ASN1_INTEGER_set(a: PASN1_INTEGER; v: TIdC_LONG): TIdC_INT; cdecl external CLibCrypto name 'ASN1_INTEGER_set';
function ASN1_INTEGER_get(a: PASN1_INTEGER): TIdC_LONG; cdecl external CLibCrypto name 'ASN1_INTEGER_get';
function BN_to_ASN1_INTEGER(bn: PBIGNUM; ai: PASN1_INTEGER): PASN1_INTEGER; cdecl external CLibCrypto name 'BN_to_ASN1_INTEGER';
function ASN1_INTEGER_to_BN(ai: PASN1_INTEGER; bn: PBIGNUM): PBIGNUM; cdecl external CLibCrypto name 'ASN1_INTEGER_to_BN';
function ASN1_ENUMERATED_get_int64(pr: PInt64; a: PASN1_ENUMERATED): TIdC_INT; cdecl external CLibCrypto name 'ASN1_ENUMERATED_get_int64';
function ASN1_ENUMERATED_set_int64(a: PASN1_ENUMERATED; r: Int64): TIdC_INT; cdecl external CLibCrypto name 'ASN1_ENUMERATED_set_int64';
function ASN1_ENUMERATED_set(a: PASN1_ENUMERATED; v: TIdC_LONG): TIdC_INT; cdecl external CLibCrypto name 'ASN1_ENUMERATED_set';
function ASN1_ENUMERATED_get(a: PASN1_ENUMERATED): TIdC_LONG; cdecl external CLibCrypto name 'ASN1_ENUMERATED_get';
function BN_to_ASN1_ENUMERATED(bn: PBIGNUM; ai: PASN1_ENUMERATED): PASN1_ENUMERATED; cdecl external CLibCrypto name 'BN_to_ASN1_ENUMERATED';
function ASN1_ENUMERATED_to_BN(ai: PASN1_ENUMERATED; bn: PBIGNUM): PBIGNUM; cdecl external CLibCrypto name 'ASN1_ENUMERATED_to_BN';
function ASN1_PRINTABLE_type(s: PIdAnsiChar; max: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'ASN1_PRINTABLE_type';
function ASN1_tag2bit(tag: TIdC_INT): TIdC_ULONG; cdecl external CLibCrypto name 'ASN1_tag2bit';
function ASN1_get_object(pp: PPIdAnsiChar; plength: PIdC_LONG; ptag: PIdC_INT; pclass: PIdC_INT; omax: TIdC_LONG): TIdC_INT; cdecl external CLibCrypto name 'ASN1_get_object';
function ASN1_check_infinite_end(p: PPIdAnsiChar; len: TIdC_LONG): TIdC_INT; cdecl external CLibCrypto name 'ASN1_check_infinite_end';
function ASN1_const_check_infinite_end(p: PPIdAnsiChar; len: TIdC_LONG): TIdC_INT; cdecl external CLibCrypto name 'ASN1_const_check_infinite_end';
procedure ASN1_put_object(pp: PPIdAnsiChar; constructed: TIdC_INT; length: TIdC_INT; tag: TIdC_INT; xclass: TIdC_INT); cdecl external CLibCrypto name 'ASN1_put_object';
function ASN1_put_eoc(pp: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'ASN1_put_eoc';
function ASN1_object_size(constructed: TIdC_INT; length: TIdC_INT; tag: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'ASN1_object_size';
function ASN1_dup(i2d: Ti2d_of_void_func_cb; d2i: Td2i_of_void_func_cb; x: Pointer): Pointer; cdecl external CLibCrypto name 'ASN1_dup';
function ASN1_item_dup(it: PASN1_ITEM; x: Pointer): Pointer; cdecl external CLibCrypto name 'ASN1_item_dup';
function ASN1_item_sign_ex(it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; id: PASN1_OCTET_STRING; pkey: PEVP_PKEY; md: PEVP_MD; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'ASN1_item_sign_ex';
function ASN1_item_verify_ex(it: PASN1_ITEM; alg: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; id: PASN1_OCTET_STRING; pkey: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'ASN1_item_verify_ex';
function ASN1_d2i_fp(xnew: TASN1_d2i_fp_xnew_cb; d2i: Td2i_of_void_func_cb; _in: PFILE; x: PPointer): Pointer; cdecl external CLibCrypto name 'ASN1_d2i_fp';
function ASN1_item_d2i_fp_ex(it: PASN1_ITEM; _in: PFILE; x: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): Pointer; cdecl external CLibCrypto name 'ASN1_item_d2i_fp_ex';
function ASN1_item_d2i_fp(it: PASN1_ITEM; _in: PFILE; x: Pointer): Pointer; cdecl external CLibCrypto name 'ASN1_item_d2i_fp';
function ASN1_i2d_fp(i2d: Ti2d_of_void_func_cb; _out: PFILE; x: Pointer): TIdC_INT; cdecl external CLibCrypto name 'ASN1_i2d_fp';
function ASN1_item_i2d_fp(it: PASN1_ITEM; _out: PFILE; x: Pointer): TIdC_INT; cdecl external CLibCrypto name 'ASN1_item_i2d_fp';
function ASN1_STRING_print_ex_fp(fp: PFILE; str: PASN1_STRING; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'ASN1_STRING_print_ex_fp';
function ASN1_STRING_to_UTF8(_out: PPIdAnsiChar; _in: PASN1_STRING): TIdC_INT; cdecl external CLibCrypto name 'ASN1_STRING_to_UTF8';
function ASN1_d2i_bio(xnew: TASN1_d2i_fp_xnew_cb; d2i: Td2i_of_void_func_cb; _in: PBIO; x: PPointer): Pointer; cdecl external CLibCrypto name 'ASN1_d2i_bio';
function ASN1_item_d2i_bio_ex(it: PASN1_ITEM; _in: PBIO; pval: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): Pointer; cdecl external CLibCrypto name 'ASN1_item_d2i_bio_ex';
function ASN1_item_d2i_bio(it: PASN1_ITEM; _in: PBIO; pval: Pointer): Pointer; cdecl external CLibCrypto name 'ASN1_item_d2i_bio';
function ASN1_i2d_bio(i2d: Ti2d_of_void_func_cb; _out: PBIO; x: Pointer): TIdC_INT; cdecl external CLibCrypto name 'ASN1_i2d_bio';
function ASN1_item_i2d_bio(it: PASN1_ITEM; _out: PBIO; x: Pointer): TIdC_INT; cdecl external CLibCrypto name 'ASN1_item_i2d_bio';
function ASN1_item_i2d_mem_bio(it: PASN1_ITEM; val: PASN1_VALUE): PBIO; cdecl external CLibCrypto name 'ASN1_item_i2d_mem_bio';
function ASN1_UTCTIME_print(fp: PBIO; a: PASN1_UTCTIME): TIdC_INT; cdecl external CLibCrypto name 'ASN1_UTCTIME_print';
function ASN1_GENERALIZEDTIME_print(fp: PBIO; a: PASN1_GENERALIZEDTIME): TIdC_INT; cdecl external CLibCrypto name 'ASN1_GENERALIZEDTIME_print';
function ASN1_TIME_print(bp: PBIO; tm: PASN1_TIME): TIdC_INT; cdecl external CLibCrypto name 'ASN1_TIME_print';
function ASN1_TIME_print_ex(bp: PBIO; tm: PASN1_TIME; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'ASN1_TIME_print_ex';
function ASN1_STRING_print(bp: PBIO; v: PASN1_STRING): TIdC_INT; cdecl external CLibCrypto name 'ASN1_STRING_print';
function ASN1_STRING_print_ex(_out: PBIO; str: PASN1_STRING; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'ASN1_STRING_print_ex';
function ASN1_buf_print(bp: PBIO; buf: PIdAnsiChar; buflen: TIdC_SIZET; off: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'ASN1_buf_print';
function ASN1_bn_print(bp: PBIO; number: PIdAnsiChar; num: PBIGNUM; buf: PIdAnsiChar; off: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'ASN1_bn_print';
function ASN1_parse(bp: PBIO; pp: PIdAnsiChar; len: TIdC_LONG; indent: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'ASN1_parse';
function ASN1_parse_dump(bp: PBIO; pp: PIdAnsiChar; len: TIdC_LONG; indent: TIdC_INT; dump: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'ASN1_parse_dump';
function ASN1_tag2str(tag: TIdC_INT): PIdAnsiChar; cdecl external CLibCrypto name 'ASN1_tag2str';
function ASN1_UNIVERSALSTRING_to_string(s: PASN1_UNIVERSALSTRING): TIdC_INT; cdecl external CLibCrypto name 'ASN1_UNIVERSALSTRING_to_string';
function ASN1_TYPE_set_octetstring(a: PASN1_TYPE; data: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'ASN1_TYPE_set_octetstring';
function ASN1_TYPE_get_octetstring(a: PASN1_TYPE; data: PIdAnsiChar; max_len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'ASN1_TYPE_get_octetstring';
function ASN1_TYPE_set_int_octetstring(a: PASN1_TYPE; num: TIdC_LONG; data: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'ASN1_TYPE_set_int_octetstring';
function ASN1_TYPE_get_int_octetstring(a: PASN1_TYPE; num: PIdC_LONG; data: PIdAnsiChar; max_len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'ASN1_TYPE_get_int_octetstring';
function ASN1_item_unpack(oct: PASN1_STRING; it: PASN1_ITEM): Pointer; cdecl external CLibCrypto name 'ASN1_item_unpack';
function ASN1_item_unpack_ex(oct: PASN1_STRING; it: PASN1_ITEM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): Pointer; cdecl external CLibCrypto name 'ASN1_item_unpack_ex';
function ASN1_item_pack(obj: Pointer; it: PASN1_ITEM; oct: PPASN1_OCTET_STRING): PASN1_STRING; cdecl external CLibCrypto name 'ASN1_item_pack';
procedure ASN1_STRING_set_default_mask(mask: TIdC_ULONG); cdecl external CLibCrypto name 'ASN1_STRING_set_default_mask';
function ASN1_STRING_set_default_mask_asc(p: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'ASN1_STRING_set_default_mask_asc';
function ASN1_STRING_get_default_mask: TIdC_ULONG; cdecl external CLibCrypto name 'ASN1_STRING_get_default_mask';
function ASN1_mbstring_copy(_out: PPASN1_STRING; _in: PIdAnsiChar; len: TIdC_INT; inform: TIdC_INT; mask: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'ASN1_mbstring_copy';
function ASN1_mbstring_ncopy(_out: PPASN1_STRING; _in: PIdAnsiChar; len: TIdC_INT; inform: TIdC_INT; mask: TIdC_ULONG; minsize: TIdC_LONG; maxsize: TIdC_LONG): TIdC_INT; cdecl external CLibCrypto name 'ASN1_mbstring_ncopy';
function ASN1_STRING_set_by_NID(_out: PPASN1_STRING; _in: PIdAnsiChar; inlen: TIdC_INT; inform: TIdC_INT; nid: TIdC_INT): PASN1_STRING; cdecl external CLibCrypto name 'ASN1_STRING_set_by_NID';
function ASN1_STRING_TABLE_get(nid: TIdC_INT): PASN1_STRING_TABLE; cdecl external CLibCrypto name 'ASN1_STRING_TABLE_get';
function ASN1_STRING_TABLE_add(arg1: TIdC_INT; arg2: TIdC_LONG; arg3: TIdC_LONG; arg4: TIdC_ULONG; arg5: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'ASN1_STRING_TABLE_add';
procedure ASN1_STRING_TABLE_cleanup; cdecl external CLibCrypto name 'ASN1_STRING_TABLE_cleanup';
function ASN1_item_new(it: PASN1_ITEM): PASN1_VALUE; cdecl external CLibCrypto name 'ASN1_item_new';
function ASN1_item_new_ex(it: PASN1_ITEM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PASN1_VALUE; cdecl external CLibCrypto name 'ASN1_item_new_ex';
procedure ASN1_item_free(val: PASN1_VALUE; it: PASN1_ITEM); cdecl external CLibCrypto name 'ASN1_item_free';
function ASN1_item_d2i_ex(val: PPASN1_VALUE; _in: PPIdAnsiChar; len: TIdC_LONG; it: PASN1_ITEM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PASN1_VALUE; cdecl external CLibCrypto name 'ASN1_item_d2i_ex';
function ASN1_item_d2i(val: PPASN1_VALUE; _in: PPIdAnsiChar; len: TIdC_LONG; it: PASN1_ITEM): PASN1_VALUE; cdecl external CLibCrypto name 'ASN1_item_d2i';
function ASN1_item_i2d(val: PASN1_VALUE; _out: PPIdAnsiChar; it: PASN1_ITEM): TIdC_INT; cdecl external CLibCrypto name 'ASN1_item_i2d';
function ASN1_item_ndef_i2d(val: PASN1_VALUE; _out: PPIdAnsiChar; it: PASN1_ITEM): TIdC_INT; cdecl external CLibCrypto name 'ASN1_item_ndef_i2d';
procedure ASN1_add_oid_module; cdecl external CLibCrypto name 'ASN1_add_oid_module';
procedure ASN1_add_stable_module; cdecl external CLibCrypto name 'ASN1_add_stable_module';
function ASN1_generate_nconf(str: PIdAnsiChar; nconf: PCONF): PASN1_TYPE; cdecl external CLibCrypto name 'ASN1_generate_nconf';
function ASN1_generate_v3(str: PIdAnsiChar; cnf: PX509V3_CTX): PASN1_TYPE; cdecl external CLibCrypto name 'ASN1_generate_v3';
function ASN1_str2mask(str: PIdAnsiChar; pmask: PIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'ASN1_str2mask';
function ASN1_item_print(_out: PBIO; ifld: PASN1_VALUE; indent: TIdC_INT; it: PASN1_ITEM; pctx: PASN1_PCTX): TIdC_INT; cdecl external CLibCrypto name 'ASN1_item_print';
function ASN1_PCTX_new: PASN1_PCTX; cdecl external CLibCrypto name 'ASN1_PCTX_new';
procedure ASN1_PCTX_free(p: PASN1_PCTX); cdecl external CLibCrypto name 'ASN1_PCTX_free';
function ASN1_PCTX_get_flags(p: PASN1_PCTX): TIdC_ULONG; cdecl external CLibCrypto name 'ASN1_PCTX_get_flags';
procedure ASN1_PCTX_set_flags(p: PASN1_PCTX; flags: TIdC_ULONG); cdecl external CLibCrypto name 'ASN1_PCTX_set_flags';
function ASN1_PCTX_get_nm_flags(p: PASN1_PCTX): TIdC_ULONG; cdecl external CLibCrypto name 'ASN1_PCTX_get_nm_flags';
procedure ASN1_PCTX_set_nm_flags(p: PASN1_PCTX; flags: TIdC_ULONG); cdecl external CLibCrypto name 'ASN1_PCTX_set_nm_flags';
function ASN1_PCTX_get_cert_flags(p: PASN1_PCTX): TIdC_ULONG; cdecl external CLibCrypto name 'ASN1_PCTX_get_cert_flags';
procedure ASN1_PCTX_set_cert_flags(p: PASN1_PCTX; flags: TIdC_ULONG); cdecl external CLibCrypto name 'ASN1_PCTX_set_cert_flags';
function ASN1_PCTX_get_oid_flags(p: PASN1_PCTX): TIdC_ULONG; cdecl external CLibCrypto name 'ASN1_PCTX_get_oid_flags';
procedure ASN1_PCTX_set_oid_flags(p: PASN1_PCTX; flags: TIdC_ULONG); cdecl external CLibCrypto name 'ASN1_PCTX_set_oid_flags';
function ASN1_PCTX_get_str_flags(p: PASN1_PCTX): TIdC_ULONG; cdecl external CLibCrypto name 'ASN1_PCTX_get_str_flags';
procedure ASN1_PCTX_set_str_flags(p: PASN1_PCTX; flags: TIdC_ULONG); cdecl external CLibCrypto name 'ASN1_PCTX_set_str_flags';
function ASN1_SCTX_new(scan_cb: TASN1_SCTX_new_scan_cb_cb): PASN1_SCTX; cdecl external CLibCrypto name 'ASN1_SCTX_new';
procedure ASN1_SCTX_free(p: PASN1_SCTX); cdecl external CLibCrypto name 'ASN1_SCTX_free';
function ASN1_SCTX_get_item(p: PASN1_SCTX): PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_SCTX_get_item';
function ASN1_SCTX_get_template(p: PASN1_SCTX): PASN1_TEMPLATE; cdecl external CLibCrypto name 'ASN1_SCTX_get_template';
function ASN1_SCTX_get_flags(p: PASN1_SCTX): TIdC_ULONG; cdecl external CLibCrypto name 'ASN1_SCTX_get_flags';
procedure ASN1_SCTX_set_app_data(p: PASN1_SCTX; data: Pointer); cdecl external CLibCrypto name 'ASN1_SCTX_set_app_data';
function ASN1_SCTX_get_app_data(p: PASN1_SCTX): Pointer; cdecl external CLibCrypto name 'ASN1_SCTX_get_app_data';
function BIO_f_asn1: PBIO_METHOD; cdecl external CLibCrypto name 'BIO_f_asn1';
function BIO_new_NDEF(_out: PBIO; val: PASN1_VALUE; it: PASN1_ITEM): PBIO; cdecl external CLibCrypto name 'BIO_new_NDEF';
function i2d_ASN1_bio_stream(_out: PBIO; val: PASN1_VALUE; _in: PBIO; flags: TIdC_INT; it: PASN1_ITEM): TIdC_INT; cdecl external CLibCrypto name 'i2d_ASN1_bio_stream';
function PEM_write_bio_ASN1_stream(_out: PBIO; val: PASN1_VALUE; _in: PBIO; flags: TIdC_INT; hdr: PIdAnsiChar; it: PASN1_ITEM): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_ASN1_stream';
function SMIME_write_ASN1(bio: PBIO; val: PASN1_VALUE; data: PBIO; flags: TIdC_INT; ctype_nid: TIdC_INT; econt_nid: TIdC_INT; mdalgs: Pstack_st_X509_ALGOR; it: PASN1_ITEM): TIdC_INT; cdecl external CLibCrypto name 'SMIME_write_ASN1';
function SMIME_write_ASN1_ex(bio: PBIO; val: PASN1_VALUE; data: PBIO; flags: TIdC_INT; ctype_nid: TIdC_INT; econt_nid: TIdC_INT; mdalgs: Pstack_st_X509_ALGOR; it: PASN1_ITEM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'SMIME_write_ASN1_ex';
function SMIME_read_ASN1(bio: PBIO; bcont: PPBIO; it: PASN1_ITEM): PASN1_VALUE; cdecl external CLibCrypto name 'SMIME_read_ASN1';
function SMIME_read_ASN1_ex(bio: PBIO; flags: TIdC_INT; bcont: PPBIO; it: PASN1_ITEM; x: PPASN1_VALUE; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PASN1_VALUE; cdecl external CLibCrypto name 'SMIME_read_ASN1_ex';
function SMIME_crlf_copy(_in: PBIO; _out: PBIO; flags: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'SMIME_crlf_copy';
function SMIME_text(_in: PBIO; _out: PBIO): TIdC_INT; cdecl external CLibCrypto name 'SMIME_text';
function ASN1_ITEM_lookup(name: PIdAnsiChar): PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_ITEM_lookup';
function ASN1_ITEM_get(i: TIdC_SIZET): PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_ITEM_get';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  d2i_ASN1_SEQUENCE_ANY_procname = 'd2i_ASN1_SEQUENCE_ANY';
  d2i_ASN1_SEQUENCE_ANY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ASN1_SEQUENCE_ANY_procname = 'i2d_ASN1_SEQUENCE_ANY';
  i2d_ASN1_SEQUENCE_ANY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_SEQUENCE_ANY_it_procname = 'ASN1_SEQUENCE_ANY_it';
  ASN1_SEQUENCE_ANY_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ASN1_SET_ANY_procname = 'd2i_ASN1_SET_ANY';
  d2i_ASN1_SET_ANY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ASN1_SET_ANY_procname = 'i2d_ASN1_SET_ANY';
  i2d_ASN1_SET_ANY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_SET_ANY_it_procname = 'ASN1_SET_ANY_it';
  ASN1_SET_ANY_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_TYPE_new_procname = 'ASN1_TYPE_new';
  ASN1_TYPE_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_TYPE_free_procname = 'ASN1_TYPE_free';
  ASN1_TYPE_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ASN1_TYPE_procname = 'd2i_ASN1_TYPE';
  d2i_ASN1_TYPE_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ASN1_TYPE_procname = 'i2d_ASN1_TYPE';
  i2d_ASN1_TYPE_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_ANY_it_procname = 'ASN1_ANY_it';
  ASN1_ANY_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_TYPE_get_procname = 'ASN1_TYPE_get';
  ASN1_TYPE_get_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_TYPE_set_procname = 'ASN1_TYPE_set';
  ASN1_TYPE_set_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_TYPE_set1_procname = 'ASN1_TYPE_set1';
  ASN1_TYPE_set1_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_TYPE_cmp_procname = 'ASN1_TYPE_cmp';
  ASN1_TYPE_cmp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_TYPE_pack_sequence_procname = 'ASN1_TYPE_pack_sequence';
  ASN1_TYPE_pack_sequence_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_TYPE_unpack_sequence_procname = 'ASN1_TYPE_unpack_sequence';
  ASN1_TYPE_unpack_sequence_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_OBJECT_new_procname = 'ASN1_OBJECT_new';
  ASN1_OBJECT_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_OBJECT_free_procname = 'ASN1_OBJECT_free';
  ASN1_OBJECT_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ASN1_OBJECT_procname = 'd2i_ASN1_OBJECT';
  d2i_ASN1_OBJECT_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ASN1_OBJECT_procname = 'i2d_ASN1_OBJECT';
  i2d_ASN1_OBJECT_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_OBJECT_it_procname = 'ASN1_OBJECT_it';
  ASN1_OBJECT_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_STRING_new_procname = 'ASN1_STRING_new';
  ASN1_STRING_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_STRING_free_procname = 'ASN1_STRING_free';
  ASN1_STRING_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_STRING_clear_free_procname = 'ASN1_STRING_clear_free';
  ASN1_STRING_clear_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_STRING_copy_procname = 'ASN1_STRING_copy';
  ASN1_STRING_copy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_STRING_dup_procname = 'ASN1_STRING_dup';
  ASN1_STRING_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_STRING_type_new_procname = 'ASN1_STRING_type_new';
  ASN1_STRING_type_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_STRING_cmp_procname = 'ASN1_STRING_cmp';
  ASN1_STRING_cmp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_STRING_set_procname = 'ASN1_STRING_set';
  ASN1_STRING_set_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_STRING_set0_procname = 'ASN1_STRING_set0';
  ASN1_STRING_set0_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_STRING_length_procname = 'ASN1_STRING_length';
  ASN1_STRING_length_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_STRING_length_set_procname = 'ASN1_STRING_length_set';
  ASN1_STRING_length_set_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASN1_STRING_length_set_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ASN1_STRING_type_procname = 'ASN1_STRING_type';
  ASN1_STRING_type_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_STRING_get0_data_procname = 'ASN1_STRING_get0_data';
  ASN1_STRING_get0_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_BIT_STRING_new_procname = 'ASN1_BIT_STRING_new';
  ASN1_BIT_STRING_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_BIT_STRING_free_procname = 'ASN1_BIT_STRING_free';
  ASN1_BIT_STRING_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ASN1_BIT_STRING_procname = 'd2i_ASN1_BIT_STRING';
  d2i_ASN1_BIT_STRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ASN1_BIT_STRING_procname = 'i2d_ASN1_BIT_STRING';
  i2d_ASN1_BIT_STRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_BIT_STRING_it_procname = 'ASN1_BIT_STRING_it';
  ASN1_BIT_STRING_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_BIT_STRING_set_procname = 'ASN1_BIT_STRING_set';
  ASN1_BIT_STRING_set_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_BIT_STRING_set_bit_procname = 'ASN1_BIT_STRING_set_bit';
  ASN1_BIT_STRING_set_bit_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_BIT_STRING_get_bit_procname = 'ASN1_BIT_STRING_get_bit';
  ASN1_BIT_STRING_get_bit_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_BIT_STRING_check_procname = 'ASN1_BIT_STRING_check';
  ASN1_BIT_STRING_check_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_BIT_STRING_name_print_procname = 'ASN1_BIT_STRING_name_print';
  ASN1_BIT_STRING_name_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_BIT_STRING_num_asc_procname = 'ASN1_BIT_STRING_num_asc';
  ASN1_BIT_STRING_num_asc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_BIT_STRING_set_asc_procname = 'ASN1_BIT_STRING_set_asc';
  ASN1_BIT_STRING_set_asc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_INTEGER_new_procname = 'ASN1_INTEGER_new';
  ASN1_INTEGER_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_INTEGER_free_procname = 'ASN1_INTEGER_free';
  ASN1_INTEGER_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ASN1_INTEGER_procname = 'd2i_ASN1_INTEGER';
  d2i_ASN1_INTEGER_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ASN1_INTEGER_procname = 'i2d_ASN1_INTEGER';
  i2d_ASN1_INTEGER_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_INTEGER_it_procname = 'ASN1_INTEGER_it';
  ASN1_INTEGER_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ASN1_UINTEGER_procname = 'd2i_ASN1_UINTEGER';
  d2i_ASN1_UINTEGER_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_INTEGER_dup_procname = 'ASN1_INTEGER_dup';
  ASN1_INTEGER_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_INTEGER_cmp_procname = 'ASN1_INTEGER_cmp';
  ASN1_INTEGER_cmp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_ENUMERATED_new_procname = 'ASN1_ENUMERATED_new';
  ASN1_ENUMERATED_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_ENUMERATED_free_procname = 'ASN1_ENUMERATED_free';
  ASN1_ENUMERATED_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ASN1_ENUMERATED_procname = 'd2i_ASN1_ENUMERATED';
  d2i_ASN1_ENUMERATED_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ASN1_ENUMERATED_procname = 'i2d_ASN1_ENUMERATED';
  i2d_ASN1_ENUMERATED_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_ENUMERATED_it_procname = 'ASN1_ENUMERATED_it';
  ASN1_ENUMERATED_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_UTCTIME_check_procname = 'ASN1_UTCTIME_check';
  ASN1_UTCTIME_check_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_UTCTIME_set_procname = 'ASN1_UTCTIME_set';
  ASN1_UTCTIME_set_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_UTCTIME_adj_procname = 'ASN1_UTCTIME_adj';
  ASN1_UTCTIME_adj_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_UTCTIME_set_string_procname = 'ASN1_UTCTIME_set_string';
  ASN1_UTCTIME_set_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_UTCTIME_cmp_time_t_procname = 'ASN1_UTCTIME_cmp_time_t';
  ASN1_UTCTIME_cmp_time_t_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_GENERALIZEDTIME_check_procname = 'ASN1_GENERALIZEDTIME_check';
  ASN1_GENERALIZEDTIME_check_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_GENERALIZEDTIME_set_procname = 'ASN1_GENERALIZEDTIME_set';
  ASN1_GENERALIZEDTIME_set_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_GENERALIZEDTIME_adj_procname = 'ASN1_GENERALIZEDTIME_adj';
  ASN1_GENERALIZEDTIME_adj_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_GENERALIZEDTIME_set_string_procname = 'ASN1_GENERALIZEDTIME_set_string';
  ASN1_GENERALIZEDTIME_set_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_TIME_diff_procname = 'ASN1_TIME_diff';
  ASN1_TIME_diff_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_OCTET_STRING_new_procname = 'ASN1_OCTET_STRING_new';
  ASN1_OCTET_STRING_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_OCTET_STRING_free_procname = 'ASN1_OCTET_STRING_free';
  ASN1_OCTET_STRING_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ASN1_OCTET_STRING_procname = 'd2i_ASN1_OCTET_STRING';
  d2i_ASN1_OCTET_STRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ASN1_OCTET_STRING_procname = 'i2d_ASN1_OCTET_STRING';
  i2d_ASN1_OCTET_STRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_OCTET_STRING_it_procname = 'ASN1_OCTET_STRING_it';
  ASN1_OCTET_STRING_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_OCTET_STRING_dup_procname = 'ASN1_OCTET_STRING_dup';
  ASN1_OCTET_STRING_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_OCTET_STRING_cmp_procname = 'ASN1_OCTET_STRING_cmp';
  ASN1_OCTET_STRING_cmp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_OCTET_STRING_set_procname = 'ASN1_OCTET_STRING_set';
  ASN1_OCTET_STRING_set_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_VISIBLESTRING_new_procname = 'ASN1_VISIBLESTRING_new';
  ASN1_VISIBLESTRING_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_VISIBLESTRING_free_procname = 'ASN1_VISIBLESTRING_free';
  ASN1_VISIBLESTRING_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ASN1_VISIBLESTRING_procname = 'd2i_ASN1_VISIBLESTRING';
  d2i_ASN1_VISIBLESTRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ASN1_VISIBLESTRING_procname = 'i2d_ASN1_VISIBLESTRING';
  i2d_ASN1_VISIBLESTRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_VISIBLESTRING_it_procname = 'ASN1_VISIBLESTRING_it';
  ASN1_VISIBLESTRING_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_UNIVERSALSTRING_new_procname = 'ASN1_UNIVERSALSTRING_new';
  ASN1_UNIVERSALSTRING_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_UNIVERSALSTRING_free_procname = 'ASN1_UNIVERSALSTRING_free';
  ASN1_UNIVERSALSTRING_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ASN1_UNIVERSALSTRING_procname = 'd2i_ASN1_UNIVERSALSTRING';
  d2i_ASN1_UNIVERSALSTRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ASN1_UNIVERSALSTRING_procname = 'i2d_ASN1_UNIVERSALSTRING';
  i2d_ASN1_UNIVERSALSTRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_UNIVERSALSTRING_it_procname = 'ASN1_UNIVERSALSTRING_it';
  ASN1_UNIVERSALSTRING_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_UTF8STRING_new_procname = 'ASN1_UTF8STRING_new';
  ASN1_UTF8STRING_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_UTF8STRING_free_procname = 'ASN1_UTF8STRING_free';
  ASN1_UTF8STRING_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ASN1_UTF8STRING_procname = 'd2i_ASN1_UTF8STRING';
  d2i_ASN1_UTF8STRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ASN1_UTF8STRING_procname = 'i2d_ASN1_UTF8STRING';
  i2d_ASN1_UTF8STRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_UTF8STRING_it_procname = 'ASN1_UTF8STRING_it';
  ASN1_UTF8STRING_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_NULL_new_procname = 'ASN1_NULL_new';
  ASN1_NULL_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_NULL_free_procname = 'ASN1_NULL_free';
  ASN1_NULL_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ASN1_NULL_procname = 'd2i_ASN1_NULL';
  d2i_ASN1_NULL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ASN1_NULL_procname = 'i2d_ASN1_NULL';
  i2d_ASN1_NULL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_NULL_it_procname = 'ASN1_NULL_it';
  ASN1_NULL_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_BMPSTRING_new_procname = 'ASN1_BMPSTRING_new';
  ASN1_BMPSTRING_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_BMPSTRING_free_procname = 'ASN1_BMPSTRING_free';
  ASN1_BMPSTRING_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ASN1_BMPSTRING_procname = 'd2i_ASN1_BMPSTRING';
  d2i_ASN1_BMPSTRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ASN1_BMPSTRING_procname = 'i2d_ASN1_BMPSTRING';
  i2d_ASN1_BMPSTRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_BMPSTRING_it_procname = 'ASN1_BMPSTRING_it';
  ASN1_BMPSTRING_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UTF8_getc_procname = 'UTF8_getc';
  UTF8_getc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UTF8_putc_procname = 'UTF8_putc';
  UTF8_putc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_PRINTABLE_new_procname = 'ASN1_PRINTABLE_new';
  ASN1_PRINTABLE_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_PRINTABLE_free_procname = 'ASN1_PRINTABLE_free';
  ASN1_PRINTABLE_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ASN1_PRINTABLE_procname = 'd2i_ASN1_PRINTABLE';
  d2i_ASN1_PRINTABLE_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ASN1_PRINTABLE_procname = 'i2d_ASN1_PRINTABLE';
  i2d_ASN1_PRINTABLE_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_PRINTABLE_it_procname = 'ASN1_PRINTABLE_it';
  ASN1_PRINTABLE_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  DIRECTORYSTRING_new_procname = 'DIRECTORYSTRING_new';
  DIRECTORYSTRING_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  DIRECTORYSTRING_free_procname = 'DIRECTORYSTRING_free';
  DIRECTORYSTRING_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_DIRECTORYSTRING_procname = 'd2i_DIRECTORYSTRING';
  d2i_DIRECTORYSTRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_DIRECTORYSTRING_procname = 'i2d_DIRECTORYSTRING';
  i2d_DIRECTORYSTRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  DIRECTORYSTRING_it_procname = 'DIRECTORYSTRING_it';
  DIRECTORYSTRING_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  DISPLAYTEXT_new_procname = 'DISPLAYTEXT_new';
  DISPLAYTEXT_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  DISPLAYTEXT_free_procname = 'DISPLAYTEXT_free';
  DISPLAYTEXT_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_DISPLAYTEXT_procname = 'd2i_DISPLAYTEXT';
  d2i_DISPLAYTEXT_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_DISPLAYTEXT_procname = 'i2d_DISPLAYTEXT';
  i2d_DISPLAYTEXT_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  DISPLAYTEXT_it_procname = 'DISPLAYTEXT_it';
  DISPLAYTEXT_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_PRINTABLESTRING_new_procname = 'ASN1_PRINTABLESTRING_new';
  ASN1_PRINTABLESTRING_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_PRINTABLESTRING_free_procname = 'ASN1_PRINTABLESTRING_free';
  ASN1_PRINTABLESTRING_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ASN1_PRINTABLESTRING_procname = 'd2i_ASN1_PRINTABLESTRING';
  d2i_ASN1_PRINTABLESTRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ASN1_PRINTABLESTRING_procname = 'i2d_ASN1_PRINTABLESTRING';
  i2d_ASN1_PRINTABLESTRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_PRINTABLESTRING_it_procname = 'ASN1_PRINTABLESTRING_it';
  ASN1_PRINTABLESTRING_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_T61STRING_new_procname = 'ASN1_T61STRING_new';
  ASN1_T61STRING_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_T61STRING_free_procname = 'ASN1_T61STRING_free';
  ASN1_T61STRING_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ASN1_T61STRING_procname = 'd2i_ASN1_T61STRING';
  d2i_ASN1_T61STRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ASN1_T61STRING_procname = 'i2d_ASN1_T61STRING';
  i2d_ASN1_T61STRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_T61STRING_it_procname = 'ASN1_T61STRING_it';
  ASN1_T61STRING_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_IA5STRING_new_procname = 'ASN1_IA5STRING_new';
  ASN1_IA5STRING_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_IA5STRING_free_procname = 'ASN1_IA5STRING_free';
  ASN1_IA5STRING_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ASN1_IA5STRING_procname = 'd2i_ASN1_IA5STRING';
  d2i_ASN1_IA5STRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ASN1_IA5STRING_procname = 'i2d_ASN1_IA5STRING';
  i2d_ASN1_IA5STRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_IA5STRING_it_procname = 'ASN1_IA5STRING_it';
  ASN1_IA5STRING_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_GENERALSTRING_new_procname = 'ASN1_GENERALSTRING_new';
  ASN1_GENERALSTRING_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_GENERALSTRING_free_procname = 'ASN1_GENERALSTRING_free';
  ASN1_GENERALSTRING_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ASN1_GENERALSTRING_procname = 'd2i_ASN1_GENERALSTRING';
  d2i_ASN1_GENERALSTRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ASN1_GENERALSTRING_procname = 'i2d_ASN1_GENERALSTRING';
  i2d_ASN1_GENERALSTRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_GENERALSTRING_it_procname = 'ASN1_GENERALSTRING_it';
  ASN1_GENERALSTRING_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_UTCTIME_new_procname = 'ASN1_UTCTIME_new';
  ASN1_UTCTIME_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_UTCTIME_free_procname = 'ASN1_UTCTIME_free';
  ASN1_UTCTIME_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ASN1_UTCTIME_procname = 'd2i_ASN1_UTCTIME';
  d2i_ASN1_UTCTIME_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ASN1_UTCTIME_procname = 'i2d_ASN1_UTCTIME';
  i2d_ASN1_UTCTIME_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_UTCTIME_it_procname = 'ASN1_UTCTIME_it';
  ASN1_UTCTIME_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_GENERALIZEDTIME_new_procname = 'ASN1_GENERALIZEDTIME_new';
  ASN1_GENERALIZEDTIME_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_GENERALIZEDTIME_free_procname = 'ASN1_GENERALIZEDTIME_free';
  ASN1_GENERALIZEDTIME_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ASN1_GENERALIZEDTIME_procname = 'd2i_ASN1_GENERALIZEDTIME';
  d2i_ASN1_GENERALIZEDTIME_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ASN1_GENERALIZEDTIME_procname = 'i2d_ASN1_GENERALIZEDTIME';
  i2d_ASN1_GENERALIZEDTIME_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_GENERALIZEDTIME_it_procname = 'ASN1_GENERALIZEDTIME_it';
  ASN1_GENERALIZEDTIME_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_TIME_new_procname = 'ASN1_TIME_new';
  ASN1_TIME_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_TIME_free_procname = 'ASN1_TIME_free';
  ASN1_TIME_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ASN1_TIME_procname = 'd2i_ASN1_TIME';
  d2i_ASN1_TIME_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ASN1_TIME_procname = 'i2d_ASN1_TIME';
  i2d_ASN1_TIME_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_TIME_it_procname = 'ASN1_TIME_it';
  ASN1_TIME_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_TIME_dup_procname = 'ASN1_TIME_dup';
  ASN1_TIME_dup_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ASN1_UTCTIME_dup_procname = 'ASN1_UTCTIME_dup';
  ASN1_UTCTIME_dup_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ASN1_GENERALIZEDTIME_dup_procname = 'ASN1_GENERALIZEDTIME_dup';
  ASN1_GENERALIZEDTIME_dup_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ASN1_OCTET_STRING_NDEF_it_procname = 'ASN1_OCTET_STRING_NDEF_it';
  ASN1_OCTET_STRING_NDEF_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_TIME_set_procname = 'ASN1_TIME_set';
  ASN1_TIME_set_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_TIME_adj_procname = 'ASN1_TIME_adj';
  ASN1_TIME_adj_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_TIME_check_procname = 'ASN1_TIME_check';
  ASN1_TIME_check_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_TIME_to_generalizedtime_procname = 'ASN1_TIME_to_generalizedtime';
  ASN1_TIME_to_generalizedtime_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_TIME_set_string_procname = 'ASN1_TIME_set_string';
  ASN1_TIME_set_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_TIME_set_string_X509_procname = 'ASN1_TIME_set_string_X509';
  ASN1_TIME_set_string_X509_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ASN1_TIME_to_tm_procname = 'ASN1_TIME_to_tm';
  ASN1_TIME_to_tm_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ASN1_TIME_normalize_procname = 'ASN1_TIME_normalize';
  ASN1_TIME_normalize_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ASN1_TIME_cmp_time_t_procname = 'ASN1_TIME_cmp_time_t';
  ASN1_TIME_cmp_time_t_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ASN1_TIME_compare_procname = 'ASN1_TIME_compare';
  ASN1_TIME_compare_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  i2a_ASN1_INTEGER_procname = 'i2a_ASN1_INTEGER';
  i2a_ASN1_INTEGER_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  a2i_ASN1_INTEGER_procname = 'a2i_ASN1_INTEGER';
  a2i_ASN1_INTEGER_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2a_ASN1_ENUMERATED_procname = 'i2a_ASN1_ENUMERATED';
  i2a_ASN1_ENUMERATED_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  a2i_ASN1_ENUMERATED_procname = 'a2i_ASN1_ENUMERATED';
  a2i_ASN1_ENUMERATED_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2a_ASN1_OBJECT_procname = 'i2a_ASN1_OBJECT';
  i2a_ASN1_OBJECT_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  a2i_ASN1_STRING_procname = 'a2i_ASN1_STRING';
  a2i_ASN1_STRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2a_ASN1_STRING_procname = 'i2a_ASN1_STRING';
  i2a_ASN1_STRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2t_ASN1_OBJECT_procname = 'i2t_ASN1_OBJECT';
  i2t_ASN1_OBJECT_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  a2d_ASN1_OBJECT_procname = 'a2d_ASN1_OBJECT';
  a2d_ASN1_OBJECT_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_OBJECT_create_procname = 'ASN1_OBJECT_create';
  ASN1_OBJECT_create_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_INTEGER_get_int64_procname = 'ASN1_INTEGER_get_int64';
  ASN1_INTEGER_get_int64_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_INTEGER_set_int64_procname = 'ASN1_INTEGER_set_int64';
  ASN1_INTEGER_set_int64_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_INTEGER_get_uint64_procname = 'ASN1_INTEGER_get_uint64';
  ASN1_INTEGER_get_uint64_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_INTEGER_set_uint64_procname = 'ASN1_INTEGER_set_uint64';
  ASN1_INTEGER_set_uint64_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_INTEGER_set_procname = 'ASN1_INTEGER_set';
  ASN1_INTEGER_set_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_INTEGER_get_procname = 'ASN1_INTEGER_get';
  ASN1_INTEGER_get_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BN_to_ASN1_INTEGER_procname = 'BN_to_ASN1_INTEGER';
  BN_to_ASN1_INTEGER_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_INTEGER_to_BN_procname = 'ASN1_INTEGER_to_BN';
  ASN1_INTEGER_to_BN_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_ENUMERATED_get_int64_procname = 'ASN1_ENUMERATED_get_int64';
  ASN1_ENUMERATED_get_int64_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_ENUMERATED_set_int64_procname = 'ASN1_ENUMERATED_set_int64';
  ASN1_ENUMERATED_set_int64_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_ENUMERATED_set_procname = 'ASN1_ENUMERATED_set';
  ASN1_ENUMERATED_set_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_ENUMERATED_get_procname = 'ASN1_ENUMERATED_get';
  ASN1_ENUMERATED_get_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BN_to_ASN1_ENUMERATED_procname = 'BN_to_ASN1_ENUMERATED';
  BN_to_ASN1_ENUMERATED_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_ENUMERATED_to_BN_procname = 'ASN1_ENUMERATED_to_BN';
  ASN1_ENUMERATED_to_BN_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_PRINTABLE_type_procname = 'ASN1_PRINTABLE_type';
  ASN1_PRINTABLE_type_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_tag2bit_procname = 'ASN1_tag2bit';
  ASN1_tag2bit_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_get_object_procname = 'ASN1_get_object';
  ASN1_get_object_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_check_infinite_end_procname = 'ASN1_check_infinite_end';
  ASN1_check_infinite_end_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_const_check_infinite_end_procname = 'ASN1_const_check_infinite_end';
  ASN1_const_check_infinite_end_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_put_object_procname = 'ASN1_put_object';
  ASN1_put_object_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_put_eoc_procname = 'ASN1_put_eoc';
  ASN1_put_eoc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_object_size_procname = 'ASN1_object_size';
  ASN1_object_size_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_dup_procname = 'ASN1_dup';
  ASN1_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_item_dup_procname = 'ASN1_item_dup';
  ASN1_item_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_item_sign_ex_procname = 'ASN1_item_sign_ex';
  ASN1_item_sign_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ASN1_item_verify_ex_procname = 'ASN1_item_verify_ex';
  ASN1_item_verify_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ASN1_d2i_fp_procname = 'ASN1_d2i_fp';
  ASN1_d2i_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_item_d2i_fp_ex_procname = 'ASN1_item_d2i_fp_ex';
  ASN1_item_d2i_fp_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ASN1_item_d2i_fp_procname = 'ASN1_item_d2i_fp';
  ASN1_item_d2i_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_i2d_fp_procname = 'ASN1_i2d_fp';
  ASN1_i2d_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_item_i2d_fp_procname = 'ASN1_item_i2d_fp';
  ASN1_item_i2d_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_STRING_print_ex_fp_procname = 'ASN1_STRING_print_ex_fp';
  ASN1_STRING_print_ex_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_STRING_to_UTF8_procname = 'ASN1_STRING_to_UTF8';
  ASN1_STRING_to_UTF8_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_d2i_bio_procname = 'ASN1_d2i_bio';
  ASN1_d2i_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_item_d2i_bio_ex_procname = 'ASN1_item_d2i_bio_ex';
  ASN1_item_d2i_bio_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ASN1_item_d2i_bio_procname = 'ASN1_item_d2i_bio';
  ASN1_item_d2i_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_i2d_bio_procname = 'ASN1_i2d_bio';
  ASN1_i2d_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_item_i2d_bio_procname = 'ASN1_item_i2d_bio';
  ASN1_item_i2d_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_item_i2d_mem_bio_procname = 'ASN1_item_i2d_mem_bio';
  ASN1_item_i2d_mem_bio_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ASN1_UTCTIME_print_procname = 'ASN1_UTCTIME_print';
  ASN1_UTCTIME_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_GENERALIZEDTIME_print_procname = 'ASN1_GENERALIZEDTIME_print';
  ASN1_GENERALIZEDTIME_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_TIME_print_procname = 'ASN1_TIME_print';
  ASN1_TIME_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_TIME_print_ex_procname = 'ASN1_TIME_print_ex';
  ASN1_TIME_print_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ASN1_STRING_print_procname = 'ASN1_STRING_print';
  ASN1_STRING_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_STRING_print_ex_procname = 'ASN1_STRING_print_ex';
  ASN1_STRING_print_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_buf_print_procname = 'ASN1_buf_print';
  ASN1_buf_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_bn_print_procname = 'ASN1_bn_print';
  ASN1_bn_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_parse_procname = 'ASN1_parse';
  ASN1_parse_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_parse_dump_procname = 'ASN1_parse_dump';
  ASN1_parse_dump_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_tag2str_procname = 'ASN1_tag2str';
  ASN1_tag2str_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_UNIVERSALSTRING_to_string_procname = 'ASN1_UNIVERSALSTRING_to_string';
  ASN1_UNIVERSALSTRING_to_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_TYPE_set_octetstring_procname = 'ASN1_TYPE_set_octetstring';
  ASN1_TYPE_set_octetstring_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_TYPE_get_octetstring_procname = 'ASN1_TYPE_get_octetstring';
  ASN1_TYPE_get_octetstring_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_TYPE_set_int_octetstring_procname = 'ASN1_TYPE_set_int_octetstring';
  ASN1_TYPE_set_int_octetstring_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_TYPE_get_int_octetstring_procname = 'ASN1_TYPE_get_int_octetstring';
  ASN1_TYPE_get_int_octetstring_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_item_unpack_procname = 'ASN1_item_unpack';
  ASN1_item_unpack_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_item_unpack_ex_procname = 'ASN1_item_unpack_ex';
  ASN1_item_unpack_ex_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  ASN1_item_pack_procname = 'ASN1_item_pack';
  ASN1_item_pack_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_STRING_set_default_mask_procname = 'ASN1_STRING_set_default_mask';
  ASN1_STRING_set_default_mask_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_STRING_set_default_mask_asc_procname = 'ASN1_STRING_set_default_mask_asc';
  ASN1_STRING_set_default_mask_asc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_STRING_get_default_mask_procname = 'ASN1_STRING_get_default_mask';
  ASN1_STRING_get_default_mask_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_mbstring_copy_procname = 'ASN1_mbstring_copy';
  ASN1_mbstring_copy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_mbstring_ncopy_procname = 'ASN1_mbstring_ncopy';
  ASN1_mbstring_ncopy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_STRING_set_by_NID_procname = 'ASN1_STRING_set_by_NID';
  ASN1_STRING_set_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_STRING_TABLE_get_procname = 'ASN1_STRING_TABLE_get';
  ASN1_STRING_TABLE_get_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_STRING_TABLE_add_procname = 'ASN1_STRING_TABLE_add';
  ASN1_STRING_TABLE_add_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_STRING_TABLE_cleanup_procname = 'ASN1_STRING_TABLE_cleanup';
  ASN1_STRING_TABLE_cleanup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_item_new_procname = 'ASN1_item_new';
  ASN1_item_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_item_new_ex_procname = 'ASN1_item_new_ex';
  ASN1_item_new_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ASN1_item_free_procname = 'ASN1_item_free';
  ASN1_item_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_item_d2i_ex_procname = 'ASN1_item_d2i_ex';
  ASN1_item_d2i_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ASN1_item_d2i_procname = 'ASN1_item_d2i';
  ASN1_item_d2i_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_item_i2d_procname = 'ASN1_item_i2d';
  ASN1_item_i2d_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_item_ndef_i2d_procname = 'ASN1_item_ndef_i2d';
  ASN1_item_ndef_i2d_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_add_oid_module_procname = 'ASN1_add_oid_module';
  ASN1_add_oid_module_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_add_stable_module_procname = 'ASN1_add_stable_module';
  ASN1_add_stable_module_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_generate_nconf_procname = 'ASN1_generate_nconf';
  ASN1_generate_nconf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_generate_v3_procname = 'ASN1_generate_v3';
  ASN1_generate_v3_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_str2mask_procname = 'ASN1_str2mask';
  ASN1_str2mask_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_item_print_procname = 'ASN1_item_print';
  ASN1_item_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_PCTX_new_procname = 'ASN1_PCTX_new';
  ASN1_PCTX_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_PCTX_free_procname = 'ASN1_PCTX_free';
  ASN1_PCTX_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_PCTX_get_flags_procname = 'ASN1_PCTX_get_flags';
  ASN1_PCTX_get_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_PCTX_set_flags_procname = 'ASN1_PCTX_set_flags';
  ASN1_PCTX_set_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_PCTX_get_nm_flags_procname = 'ASN1_PCTX_get_nm_flags';
  ASN1_PCTX_get_nm_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_PCTX_set_nm_flags_procname = 'ASN1_PCTX_set_nm_flags';
  ASN1_PCTX_set_nm_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_PCTX_get_cert_flags_procname = 'ASN1_PCTX_get_cert_flags';
  ASN1_PCTX_get_cert_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_PCTX_set_cert_flags_procname = 'ASN1_PCTX_set_cert_flags';
  ASN1_PCTX_set_cert_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_PCTX_get_oid_flags_procname = 'ASN1_PCTX_get_oid_flags';
  ASN1_PCTX_get_oid_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_PCTX_set_oid_flags_procname = 'ASN1_PCTX_set_oid_flags';
  ASN1_PCTX_set_oid_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_PCTX_get_str_flags_procname = 'ASN1_PCTX_get_str_flags';
  ASN1_PCTX_get_str_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_PCTX_set_str_flags_procname = 'ASN1_PCTX_set_str_flags';
  ASN1_PCTX_set_str_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_SCTX_new_procname = 'ASN1_SCTX_new';
  ASN1_SCTX_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_SCTX_free_procname = 'ASN1_SCTX_free';
  ASN1_SCTX_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_SCTX_get_item_procname = 'ASN1_SCTX_get_item';
  ASN1_SCTX_get_item_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_SCTX_get_template_procname = 'ASN1_SCTX_get_template';
  ASN1_SCTX_get_template_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_SCTX_get_flags_procname = 'ASN1_SCTX_get_flags';
  ASN1_SCTX_get_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_SCTX_set_app_data_procname = 'ASN1_SCTX_set_app_data';
  ASN1_SCTX_set_app_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_SCTX_get_app_data_procname = 'ASN1_SCTX_get_app_data';
  ASN1_SCTX_get_app_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_f_asn1_procname = 'BIO_f_asn1';
  BIO_f_asn1_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_new_NDEF_procname = 'BIO_new_NDEF';
  BIO_new_NDEF_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ASN1_bio_stream_procname = 'i2d_ASN1_bio_stream';
  i2d_ASN1_bio_stream_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_bio_ASN1_stream_procname = 'PEM_write_bio_ASN1_stream';
  PEM_write_bio_ASN1_stream_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SMIME_write_ASN1_procname = 'SMIME_write_ASN1';
  SMIME_write_ASN1_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SMIME_write_ASN1_ex_procname = 'SMIME_write_ASN1_ex';
  SMIME_write_ASN1_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SMIME_read_ASN1_procname = 'SMIME_read_ASN1';
  SMIME_read_ASN1_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SMIME_read_ASN1_ex_procname = 'SMIME_read_ASN1_ex';
  SMIME_read_ASN1_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SMIME_crlf_copy_procname = 'SMIME_crlf_copy';
  SMIME_crlf_copy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SMIME_text_procname = 'SMIME_text';
  SMIME_text_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_ITEM_lookup_procname = 'ASN1_ITEM_lookup';
  ASN1_ITEM_lookup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ASN1_ITEM_get_procname = 'ASN1_ITEM_get';
  ASN1_ITEM_get_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_d2i_ASN1_SEQUENCE_ANY(a: PPASN1_SEQUENCE_ANY; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_SEQUENCE_ANY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_SEQUENCE_ANY_procname);
end;

function ERR_i2d_ASN1_SEQUENCE_ANY(a: PASN1_SEQUENCE_ANY; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_SEQUENCE_ANY_procname);
end;

function ERR_ASN1_SEQUENCE_ANY_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_SEQUENCE_ANY_it_procname);
end;

function ERR_d2i_ASN1_SET_ANY(a: PPASN1_SEQUENCE_ANY; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_SEQUENCE_ANY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_SET_ANY_procname);
end;

function ERR_i2d_ASN1_SET_ANY(a: PASN1_SEQUENCE_ANY; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_SET_ANY_procname);
end;

function ERR_ASN1_SET_ANY_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_SET_ANY_it_procname);
end;

function ERR_ASN1_TYPE_new: PASN1_TYPE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TYPE_new_procname);
end;

procedure ERR_ASN1_TYPE_free(a: PASN1_TYPE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TYPE_free_procname);
end;

function ERR_d2i_ASN1_TYPE(a: PPASN1_TYPE; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_TYPE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_TYPE_procname);
end;

function ERR_i2d_ASN1_TYPE(a: PASN1_TYPE; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_TYPE_procname);
end;

function ERR_ASN1_ANY_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_ANY_it_procname);
end;

function ERR_ASN1_TYPE_get(a: PASN1_TYPE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TYPE_get_procname);
end;

procedure ERR_ASN1_TYPE_set(a: PASN1_TYPE; _type: TIdC_INT; value: Pointer); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TYPE_set_procname);
end;

function ERR_ASN1_TYPE_set1(a: PASN1_TYPE; _type: TIdC_INT; value: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TYPE_set1_procname);
end;

function ERR_ASN1_TYPE_cmp(a: PASN1_TYPE; b: PASN1_TYPE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TYPE_cmp_procname);
end;

function ERR_ASN1_TYPE_pack_sequence(it: PASN1_ITEM; s: Pointer; t: PPASN1_TYPE): PASN1_TYPE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TYPE_pack_sequence_procname);
end;

function ERR_ASN1_TYPE_unpack_sequence(it: PASN1_ITEM; t: PASN1_TYPE): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TYPE_unpack_sequence_procname);
end;

function ERR_ASN1_OBJECT_new: PASN1_OBJECT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_OBJECT_new_procname);
end;

procedure ERR_ASN1_OBJECT_free(a: PASN1_OBJECT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_OBJECT_free_procname);
end;

function ERR_d2i_ASN1_OBJECT(a: PPASN1_OBJECT; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_OBJECT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_OBJECT_procname);
end;

function ERR_i2d_ASN1_OBJECT(a: PASN1_OBJECT; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_OBJECT_procname);
end;

function ERR_ASN1_OBJECT_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_OBJECT_it_procname);
end;

function ERR_ASN1_STRING_new: PASN1_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_new_procname);
end;

procedure ERR_ASN1_STRING_free(a: PASN1_STRING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_free_procname);
end;

procedure ERR_ASN1_STRING_clear_free(a: PASN1_STRING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_clear_free_procname);
end;

function ERR_ASN1_STRING_copy(dst: PASN1_STRING; str: PASN1_STRING): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_copy_procname);
end;

function ERR_ASN1_STRING_dup(a: PASN1_STRING): PASN1_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_dup_procname);
end;

function ERR_ASN1_STRING_type_new(_type: TIdC_INT): PASN1_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_type_new_procname);
end;

function ERR_ASN1_STRING_cmp(a: PASN1_STRING; b: PASN1_STRING): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_cmp_procname);
end;

function ERR_ASN1_STRING_set(str: PASN1_STRING; data: Pointer; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_set_procname);
end;

procedure ERR_ASN1_STRING_set0(str: PASN1_STRING; data: Pointer; len: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_set0_procname);
end;

function ERR_ASN1_STRING_length(x: PASN1_STRING): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_length_procname);
end;

procedure ERR_ASN1_STRING_length_set(x: PASN1_STRING; n: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_length_set_procname);
end;

function ERR_ASN1_STRING_type(x: PASN1_STRING): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_type_procname);
end;

function ERR_ASN1_STRING_get0_data(x: PASN1_STRING): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_get0_data_procname);
end;

function ERR_ASN1_BIT_STRING_new: PASN1_BIT_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_BIT_STRING_new_procname);
end;

procedure ERR_ASN1_BIT_STRING_free(a: PASN1_BIT_STRING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_BIT_STRING_free_procname);
end;

function ERR_d2i_ASN1_BIT_STRING(a: PPASN1_BIT_STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_BIT_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_BIT_STRING_procname);
end;

function ERR_i2d_ASN1_BIT_STRING(a: PASN1_BIT_STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_BIT_STRING_procname);
end;

function ERR_ASN1_BIT_STRING_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_BIT_STRING_it_procname);
end;

function ERR_ASN1_BIT_STRING_set(a: PASN1_BIT_STRING; d: PIdAnsiChar; length: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_BIT_STRING_set_procname);
end;

function ERR_ASN1_BIT_STRING_set_bit(a: PASN1_BIT_STRING; n: TIdC_INT; value: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_BIT_STRING_set_bit_procname);
end;

function ERR_ASN1_BIT_STRING_get_bit(a: PASN1_BIT_STRING; n: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_BIT_STRING_get_bit_procname);
end;

function ERR_ASN1_BIT_STRING_check(a: PASN1_BIT_STRING; flags: PIdAnsiChar; flags_len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_BIT_STRING_check_procname);
end;

function ERR_ASN1_BIT_STRING_name_print(_out: PBIO; bs: PASN1_BIT_STRING; tbl: PBIT_STRING_BITNAME; indent: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_BIT_STRING_name_print_procname);
end;

function ERR_ASN1_BIT_STRING_num_asc(name: PIdAnsiChar; tbl: PBIT_STRING_BITNAME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_BIT_STRING_num_asc_procname);
end;

function ERR_ASN1_BIT_STRING_set_asc(bs: PASN1_BIT_STRING; name: PIdAnsiChar; value: TIdC_INT; tbl: PBIT_STRING_BITNAME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_BIT_STRING_set_asc_procname);
end;

function ERR_ASN1_INTEGER_new: PASN1_INTEGER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_INTEGER_new_procname);
end;

procedure ERR_ASN1_INTEGER_free(a: PASN1_INTEGER); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_INTEGER_free_procname);
end;

function ERR_d2i_ASN1_INTEGER(a: PPASN1_INTEGER; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_INTEGER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_INTEGER_procname);
end;

function ERR_i2d_ASN1_INTEGER(a: PASN1_INTEGER; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_INTEGER_procname);
end;

function ERR_ASN1_INTEGER_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_INTEGER_it_procname);
end;

function ERR_d2i_ASN1_UINTEGER(a: PPASN1_INTEGER; pp: PPIdAnsiChar; length: TIdC_LONG): PASN1_INTEGER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_UINTEGER_procname);
end;

function ERR_ASN1_INTEGER_dup(a: PASN1_INTEGER): PASN1_INTEGER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_INTEGER_dup_procname);
end;

function ERR_ASN1_INTEGER_cmp(x: PASN1_INTEGER; y: PASN1_INTEGER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_INTEGER_cmp_procname);
end;

function ERR_ASN1_ENUMERATED_new: PASN1_ENUMERATED; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_ENUMERATED_new_procname);
end;

procedure ERR_ASN1_ENUMERATED_free(a: PASN1_ENUMERATED); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_ENUMERATED_free_procname);
end;

function ERR_d2i_ASN1_ENUMERATED(a: PPASN1_ENUMERATED; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_ENUMERATED; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_ENUMERATED_procname);
end;

function ERR_i2d_ASN1_ENUMERATED(a: PASN1_ENUMERATED; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_ENUMERATED_procname);
end;

function ERR_ASN1_ENUMERATED_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_ENUMERATED_it_procname);
end;

function ERR_ASN1_UTCTIME_check(a: PASN1_UTCTIME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_UTCTIME_check_procname);
end;

function ERR_ASN1_UTCTIME_set(s: PASN1_UTCTIME; t: TIdC_TIME_T): PASN1_UTCTIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_UTCTIME_set_procname);
end;

function ERR_ASN1_UTCTIME_adj(s: PASN1_UTCTIME; t: TIdC_TIME_T; offset_day: TIdC_INT; offset_sec: TIdC_LONG): PASN1_UTCTIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_UTCTIME_adj_procname);
end;

function ERR_ASN1_UTCTIME_set_string(s: PASN1_UTCTIME; str: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_UTCTIME_set_string_procname);
end;

function ERR_ASN1_UTCTIME_cmp_time_t(s: PASN1_UTCTIME; t: TIdC_TIME_T): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_UTCTIME_cmp_time_t_procname);
end;

function ERR_ASN1_GENERALIZEDTIME_check(a: PASN1_GENERALIZEDTIME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_GENERALIZEDTIME_check_procname);
end;

function ERR_ASN1_GENERALIZEDTIME_set(s: PASN1_GENERALIZEDTIME; t: TIdC_TIME_T): PASN1_GENERALIZEDTIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_GENERALIZEDTIME_set_procname);
end;

function ERR_ASN1_GENERALIZEDTIME_adj(s: PASN1_GENERALIZEDTIME; t: TIdC_TIME_T; offset_day: TIdC_INT; offset_sec: TIdC_LONG): PASN1_GENERALIZEDTIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_GENERALIZEDTIME_adj_procname);
end;

function ERR_ASN1_GENERALIZEDTIME_set_string(s: PASN1_GENERALIZEDTIME; str: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_GENERALIZEDTIME_set_string_procname);
end;

function ERR_ASN1_TIME_diff(pday: PIdC_INT; psec: PIdC_INT; from: PASN1_TIME; _to: PASN1_TIME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_diff_procname);
end;

function ERR_ASN1_OCTET_STRING_new: PASN1_OCTET_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_OCTET_STRING_new_procname);
end;

procedure ERR_ASN1_OCTET_STRING_free(a: PASN1_OCTET_STRING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_OCTET_STRING_free_procname);
end;

function ERR_d2i_ASN1_OCTET_STRING(a: PPASN1_OCTET_STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_OCTET_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_OCTET_STRING_procname);
end;

function ERR_i2d_ASN1_OCTET_STRING(a: PASN1_OCTET_STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_OCTET_STRING_procname);
end;

function ERR_ASN1_OCTET_STRING_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_OCTET_STRING_it_procname);
end;

function ERR_ASN1_OCTET_STRING_dup(a: PASN1_OCTET_STRING): PASN1_OCTET_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_OCTET_STRING_dup_procname);
end;

function ERR_ASN1_OCTET_STRING_cmp(a: PASN1_OCTET_STRING; b: PASN1_OCTET_STRING): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_OCTET_STRING_cmp_procname);
end;

function ERR_ASN1_OCTET_STRING_set(str: PASN1_OCTET_STRING; data: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_OCTET_STRING_set_procname);
end;

function ERR_ASN1_VISIBLESTRING_new: PASN1_VISIBLESTRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_VISIBLESTRING_new_procname);
end;

procedure ERR_ASN1_VISIBLESTRING_free(a: PASN1_VISIBLESTRING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_VISIBLESTRING_free_procname);
end;

function ERR_d2i_ASN1_VISIBLESTRING(a: PPASN1_VISIBLESTRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_VISIBLESTRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_VISIBLESTRING_procname);
end;

function ERR_i2d_ASN1_VISIBLESTRING(a: PASN1_VISIBLESTRING; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_VISIBLESTRING_procname);
end;

function ERR_ASN1_VISIBLESTRING_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_VISIBLESTRING_it_procname);
end;

function ERR_ASN1_UNIVERSALSTRING_new: PASN1_UNIVERSALSTRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_UNIVERSALSTRING_new_procname);
end;

procedure ERR_ASN1_UNIVERSALSTRING_free(a: PASN1_UNIVERSALSTRING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_UNIVERSALSTRING_free_procname);
end;

function ERR_d2i_ASN1_UNIVERSALSTRING(a: PPASN1_UNIVERSALSTRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_UNIVERSALSTRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_UNIVERSALSTRING_procname);
end;

function ERR_i2d_ASN1_UNIVERSALSTRING(a: PASN1_UNIVERSALSTRING; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_UNIVERSALSTRING_procname);
end;

function ERR_ASN1_UNIVERSALSTRING_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_UNIVERSALSTRING_it_procname);
end;

function ERR_ASN1_UTF8STRING_new: PASN1_UTF8STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_UTF8STRING_new_procname);
end;

procedure ERR_ASN1_UTF8STRING_free(a: PASN1_UTF8STRING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_UTF8STRING_free_procname);
end;

function ERR_d2i_ASN1_UTF8STRING(a: PPASN1_UTF8STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_UTF8STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_UTF8STRING_procname);
end;

function ERR_i2d_ASN1_UTF8STRING(a: PASN1_UTF8STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_UTF8STRING_procname);
end;

function ERR_ASN1_UTF8STRING_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_UTF8STRING_it_procname);
end;

function ERR_ASN1_NULL_new: PASN1_NULL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_NULL_new_procname);
end;

procedure ERR_ASN1_NULL_free(a: PASN1_NULL); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_NULL_free_procname);
end;

function ERR_d2i_ASN1_NULL(a: PPASN1_NULL; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_NULL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_NULL_procname);
end;

function ERR_i2d_ASN1_NULL(a: PASN1_NULL; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_NULL_procname);
end;

function ERR_ASN1_NULL_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_NULL_it_procname);
end;

function ERR_ASN1_BMPSTRING_new: PASN1_BMPSTRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_BMPSTRING_new_procname);
end;

procedure ERR_ASN1_BMPSTRING_free(a: PASN1_BMPSTRING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_BMPSTRING_free_procname);
end;

function ERR_d2i_ASN1_BMPSTRING(a: PPASN1_BMPSTRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_BMPSTRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_BMPSTRING_procname);
end;

function ERR_i2d_ASN1_BMPSTRING(a: PASN1_BMPSTRING; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_BMPSTRING_procname);
end;

function ERR_ASN1_BMPSTRING_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_BMPSTRING_it_procname);
end;

function ERR_UTF8_getc(str: PIdAnsiChar; len: TIdC_INT; val: PIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UTF8_getc_procname);
end;

function ERR_UTF8_putc(str: PIdAnsiChar; len: TIdC_INT; value: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UTF8_putc_procname);
end;

function ERR_ASN1_PRINTABLE_new: PASN1_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PRINTABLE_new_procname);
end;

procedure ERR_ASN1_PRINTABLE_free(a: PASN1_STRING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PRINTABLE_free_procname);
end;

function ERR_d2i_ASN1_PRINTABLE(a: PPASN1_STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_PRINTABLE_procname);
end;

function ERR_i2d_ASN1_PRINTABLE(a: PASN1_STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_PRINTABLE_procname);
end;

function ERR_ASN1_PRINTABLE_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PRINTABLE_it_procname);
end;

function ERR_DIRECTORYSTRING_new: PASN1_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DIRECTORYSTRING_new_procname);
end;

procedure ERR_DIRECTORYSTRING_free(a: PASN1_STRING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DIRECTORYSTRING_free_procname);
end;

function ERR_d2i_DIRECTORYSTRING(a: PPASN1_STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_DIRECTORYSTRING_procname);
end;

function ERR_i2d_DIRECTORYSTRING(a: PASN1_STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_DIRECTORYSTRING_procname);
end;

function ERR_DIRECTORYSTRING_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DIRECTORYSTRING_it_procname);
end;

function ERR_DISPLAYTEXT_new: PASN1_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DISPLAYTEXT_new_procname);
end;

procedure ERR_DISPLAYTEXT_free(a: PASN1_STRING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DISPLAYTEXT_free_procname);
end;

function ERR_d2i_DISPLAYTEXT(a: PPASN1_STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_DISPLAYTEXT_procname);
end;

function ERR_i2d_DISPLAYTEXT(a: PASN1_STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_DISPLAYTEXT_procname);
end;

function ERR_DISPLAYTEXT_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DISPLAYTEXT_it_procname);
end;

function ERR_ASN1_PRINTABLESTRING_new: PASN1_PRINTABLESTRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PRINTABLESTRING_new_procname);
end;

procedure ERR_ASN1_PRINTABLESTRING_free(a: PASN1_PRINTABLESTRING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PRINTABLESTRING_free_procname);
end;

function ERR_d2i_ASN1_PRINTABLESTRING(a: PPASN1_PRINTABLESTRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_PRINTABLESTRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_PRINTABLESTRING_procname);
end;

function ERR_i2d_ASN1_PRINTABLESTRING(a: PASN1_PRINTABLESTRING; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_PRINTABLESTRING_procname);
end;

function ERR_ASN1_PRINTABLESTRING_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PRINTABLESTRING_it_procname);
end;

function ERR_ASN1_T61STRING_new: PASN1_T61STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_T61STRING_new_procname);
end;

procedure ERR_ASN1_T61STRING_free(a: PASN1_T61STRING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_T61STRING_free_procname);
end;

function ERR_d2i_ASN1_T61STRING(a: PPASN1_T61STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_T61STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_T61STRING_procname);
end;

function ERR_i2d_ASN1_T61STRING(a: PASN1_T61STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_T61STRING_procname);
end;

function ERR_ASN1_T61STRING_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_T61STRING_it_procname);
end;

function ERR_ASN1_IA5STRING_new: PASN1_IA5STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_IA5STRING_new_procname);
end;

procedure ERR_ASN1_IA5STRING_free(a: PASN1_IA5STRING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_IA5STRING_free_procname);
end;

function ERR_d2i_ASN1_IA5STRING(a: PPASN1_IA5STRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_IA5STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_IA5STRING_procname);
end;

function ERR_i2d_ASN1_IA5STRING(a: PASN1_IA5STRING; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_IA5STRING_procname);
end;

function ERR_ASN1_IA5STRING_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_IA5STRING_it_procname);
end;

function ERR_ASN1_GENERALSTRING_new: PASN1_GENERALSTRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_GENERALSTRING_new_procname);
end;

procedure ERR_ASN1_GENERALSTRING_free(a: PASN1_GENERALSTRING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_GENERALSTRING_free_procname);
end;

function ERR_d2i_ASN1_GENERALSTRING(a: PPASN1_GENERALSTRING; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_GENERALSTRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_GENERALSTRING_procname);
end;

function ERR_i2d_ASN1_GENERALSTRING(a: PASN1_GENERALSTRING; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_GENERALSTRING_procname);
end;

function ERR_ASN1_GENERALSTRING_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_GENERALSTRING_it_procname);
end;

function ERR_ASN1_UTCTIME_new: PASN1_UTCTIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_UTCTIME_new_procname);
end;

procedure ERR_ASN1_UTCTIME_free(a: PASN1_UTCTIME); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_UTCTIME_free_procname);
end;

function ERR_d2i_ASN1_UTCTIME(a: PPASN1_UTCTIME; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_UTCTIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_UTCTIME_procname);
end;

function ERR_i2d_ASN1_UTCTIME(a: PASN1_UTCTIME; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_UTCTIME_procname);
end;

function ERR_ASN1_UTCTIME_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_UTCTIME_it_procname);
end;

function ERR_ASN1_GENERALIZEDTIME_new: PASN1_GENERALIZEDTIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_GENERALIZEDTIME_new_procname);
end;

procedure ERR_ASN1_GENERALIZEDTIME_free(a: PASN1_GENERALIZEDTIME); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_GENERALIZEDTIME_free_procname);
end;

function ERR_d2i_ASN1_GENERALIZEDTIME(a: PPASN1_GENERALIZEDTIME; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_GENERALIZEDTIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_GENERALIZEDTIME_procname);
end;

function ERR_i2d_ASN1_GENERALIZEDTIME(a: PASN1_GENERALIZEDTIME; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_GENERALIZEDTIME_procname);
end;

function ERR_ASN1_GENERALIZEDTIME_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_GENERALIZEDTIME_it_procname);
end;

function ERR_ASN1_TIME_new: PASN1_TIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_new_procname);
end;

procedure ERR_ASN1_TIME_free(a: PASN1_TIME); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_free_procname);
end;

function ERR_d2i_ASN1_TIME(a: PPASN1_TIME; _in: PPIdAnsiChar; len: TIdC_LONG): PASN1_TIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_TIME_procname);
end;

function ERR_i2d_ASN1_TIME(a: PASN1_TIME; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_TIME_procname);
end;

function ERR_ASN1_TIME_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_it_procname);
end;

function ERR_ASN1_TIME_dup(a: PASN1_TIME): PASN1_TIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_dup_procname);
end;

function ERR_ASN1_UTCTIME_dup(a: PASN1_UTCTIME): PASN1_UTCTIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_UTCTIME_dup_procname);
end;

function ERR_ASN1_GENERALIZEDTIME_dup(a: PASN1_GENERALIZEDTIME): PASN1_GENERALIZEDTIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_GENERALIZEDTIME_dup_procname);
end;

function ERR_ASN1_OCTET_STRING_NDEF_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_OCTET_STRING_NDEF_it_procname);
end;

function ERR_ASN1_TIME_set(s: PASN1_TIME; t: TIdC_TIME_T): PASN1_TIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_set_procname);
end;

function ERR_ASN1_TIME_adj(s: PASN1_TIME; t: TIdC_TIME_T; offset_day: TIdC_INT; offset_sec: TIdC_LONG): PASN1_TIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_adj_procname);
end;

function ERR_ASN1_TIME_check(t: PASN1_TIME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_check_procname);
end;

function ERR_ASN1_TIME_to_generalizedtime(t: PASN1_TIME; _out: PPASN1_GENERALIZEDTIME): PASN1_GENERALIZEDTIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_to_generalizedtime_procname);
end;

function ERR_ASN1_TIME_set_string(s: PASN1_TIME; str: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_set_string_procname);
end;

function ERR_ASN1_TIME_set_string_X509(s: PASN1_TIME; str: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_set_string_X509_procname);
end;

function ERR_ASN1_TIME_to_tm(s: PASN1_TIME; tm: Ptm): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_to_tm_procname);
end;

function ERR_ASN1_TIME_normalize(s: PASN1_TIME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_normalize_procname);
end;

function ERR_ASN1_TIME_cmp_time_t(s: PASN1_TIME; t: TIdC_TIME_T): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_cmp_time_t_procname);
end;

function ERR_ASN1_TIME_compare(a: PASN1_TIME; b: PASN1_TIME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_compare_procname);
end;

function ERR_i2a_ASN1_INTEGER(bp: PBIO; a: PASN1_INTEGER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2a_ASN1_INTEGER_procname);
end;

function ERR_a2i_ASN1_INTEGER(bp: PBIO; bs: PASN1_INTEGER; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(a2i_ASN1_INTEGER_procname);
end;

function ERR_i2a_ASN1_ENUMERATED(bp: PBIO; a: PASN1_ENUMERATED): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2a_ASN1_ENUMERATED_procname);
end;

function ERR_a2i_ASN1_ENUMERATED(bp: PBIO; bs: PASN1_ENUMERATED; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(a2i_ASN1_ENUMERATED_procname);
end;

function ERR_i2a_ASN1_OBJECT(bp: PBIO; a: PASN1_OBJECT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2a_ASN1_OBJECT_procname);
end;

function ERR_a2i_ASN1_STRING(bp: PBIO; bs: PASN1_STRING; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(a2i_ASN1_STRING_procname);
end;

function ERR_i2a_ASN1_STRING(bp: PBIO; a: PASN1_STRING; _type: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2a_ASN1_STRING_procname);
end;

function ERR_i2t_ASN1_OBJECT(buf: PIdAnsiChar; buf_len: TIdC_INT; a: PASN1_OBJECT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2t_ASN1_OBJECT_procname);
end;

function ERR_a2d_ASN1_OBJECT(_out: PIdAnsiChar; olen: TIdC_INT; buf: PIdAnsiChar; num: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(a2d_ASN1_OBJECT_procname);
end;

function ERR_ASN1_OBJECT_create(nid: TIdC_INT; data: PIdAnsiChar; len: TIdC_INT; sn: PIdAnsiChar; ln: PIdAnsiChar): PASN1_OBJECT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_OBJECT_create_procname);
end;

function ERR_ASN1_INTEGER_get_int64(pr: PInt64; a: PASN1_INTEGER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_INTEGER_get_int64_procname);
end;

function ERR_ASN1_INTEGER_set_int64(a: PASN1_INTEGER; r: Int64): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_INTEGER_set_int64_procname);
end;

function ERR_ASN1_INTEGER_get_uint64(pr: PUInt64; a: PASN1_INTEGER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_INTEGER_get_uint64_procname);
end;

function ERR_ASN1_INTEGER_set_uint64(a: PASN1_INTEGER; r: UInt64): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_INTEGER_set_uint64_procname);
end;

function ERR_ASN1_INTEGER_set(a: PASN1_INTEGER; v: TIdC_LONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_INTEGER_set_procname);
end;

function ERR_ASN1_INTEGER_get(a: PASN1_INTEGER): TIdC_LONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_INTEGER_get_procname);
end;

function ERR_BN_to_ASN1_INTEGER(bn: PBIGNUM; ai: PASN1_INTEGER): PASN1_INTEGER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BN_to_ASN1_INTEGER_procname);
end;

function ERR_ASN1_INTEGER_to_BN(ai: PASN1_INTEGER; bn: PBIGNUM): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_INTEGER_to_BN_procname);
end;

function ERR_ASN1_ENUMERATED_get_int64(pr: PInt64; a: PASN1_ENUMERATED): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_ENUMERATED_get_int64_procname);
end;

function ERR_ASN1_ENUMERATED_set_int64(a: PASN1_ENUMERATED; r: Int64): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_ENUMERATED_set_int64_procname);
end;

function ERR_ASN1_ENUMERATED_set(a: PASN1_ENUMERATED; v: TIdC_LONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_ENUMERATED_set_procname);
end;

function ERR_ASN1_ENUMERATED_get(a: PASN1_ENUMERATED): TIdC_LONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_ENUMERATED_get_procname);
end;

function ERR_BN_to_ASN1_ENUMERATED(bn: PBIGNUM; ai: PASN1_ENUMERATED): PASN1_ENUMERATED; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BN_to_ASN1_ENUMERATED_procname);
end;

function ERR_ASN1_ENUMERATED_to_BN(ai: PASN1_ENUMERATED; bn: PBIGNUM): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_ENUMERATED_to_BN_procname);
end;

function ERR_ASN1_PRINTABLE_type(s: PIdAnsiChar; max: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PRINTABLE_type_procname);
end;

function ERR_ASN1_tag2bit(tag: TIdC_INT): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_tag2bit_procname);
end;

function ERR_ASN1_get_object(pp: PPIdAnsiChar; plength: PIdC_LONG; ptag: PIdC_INT; pclass: PIdC_INT; omax: TIdC_LONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_get_object_procname);
end;

function ERR_ASN1_check_infinite_end(p: PPIdAnsiChar; len: TIdC_LONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_check_infinite_end_procname);
end;

function ERR_ASN1_const_check_infinite_end(p: PPIdAnsiChar; len: TIdC_LONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_const_check_infinite_end_procname);
end;

procedure ERR_ASN1_put_object(pp: PPIdAnsiChar; constructed: TIdC_INT; length: TIdC_INT; tag: TIdC_INT; xclass: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_put_object_procname);
end;

function ERR_ASN1_put_eoc(pp: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_put_eoc_procname);
end;

function ERR_ASN1_object_size(constructed: TIdC_INT; length: TIdC_INT; tag: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_object_size_procname);
end;

function ERR_ASN1_dup(i2d: Ti2d_of_void_func_cb; d2i: Td2i_of_void_func_cb; x: Pointer): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_dup_procname);
end;

function ERR_ASN1_item_dup(it: PASN1_ITEM; x: Pointer): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_dup_procname);
end;

function ERR_ASN1_item_sign_ex(it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; id: PASN1_OCTET_STRING; pkey: PEVP_PKEY; md: PEVP_MD; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_sign_ex_procname);
end;

function ERR_ASN1_item_verify_ex(it: PASN1_ITEM; alg: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; id: PASN1_OCTET_STRING; pkey: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_verify_ex_procname);
end;

function ERR_ASN1_d2i_fp(xnew: TASN1_d2i_fp_xnew_cb; d2i: Td2i_of_void_func_cb; _in: PFILE; x: PPointer): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_d2i_fp_procname);
end;

function ERR_ASN1_item_d2i_fp_ex(it: PASN1_ITEM; _in: PFILE; x: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_d2i_fp_ex_procname);
end;

function ERR_ASN1_item_d2i_fp(it: PASN1_ITEM; _in: PFILE; x: Pointer): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_d2i_fp_procname);
end;

function ERR_ASN1_i2d_fp(i2d: Ti2d_of_void_func_cb; _out: PFILE; x: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_i2d_fp_procname);
end;

function ERR_ASN1_item_i2d_fp(it: PASN1_ITEM; _out: PFILE; x: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_i2d_fp_procname);
end;

function ERR_ASN1_STRING_print_ex_fp(fp: PFILE; str: PASN1_STRING; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_print_ex_fp_procname);
end;

function ERR_ASN1_STRING_to_UTF8(_out: PPIdAnsiChar; _in: PASN1_STRING): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_to_UTF8_procname);
end;

function ERR_ASN1_d2i_bio(xnew: TASN1_d2i_fp_xnew_cb; d2i: Td2i_of_void_func_cb; _in: PBIO; x: PPointer): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_d2i_bio_procname);
end;

function ERR_ASN1_item_d2i_bio_ex(it: PASN1_ITEM; _in: PBIO; pval: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_d2i_bio_ex_procname);
end;

function ERR_ASN1_item_d2i_bio(it: PASN1_ITEM; _in: PBIO; pval: Pointer): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_d2i_bio_procname);
end;

function ERR_ASN1_i2d_bio(i2d: Ti2d_of_void_func_cb; _out: PBIO; x: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_i2d_bio_procname);
end;

function ERR_ASN1_item_i2d_bio(it: PASN1_ITEM; _out: PBIO; x: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_i2d_bio_procname);
end;

function ERR_ASN1_item_i2d_mem_bio(it: PASN1_ITEM; val: PASN1_VALUE): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_i2d_mem_bio_procname);
end;

function ERR_ASN1_UTCTIME_print(fp: PBIO; a: PASN1_UTCTIME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_UTCTIME_print_procname);
end;

function ERR_ASN1_GENERALIZEDTIME_print(fp: PBIO; a: PASN1_GENERALIZEDTIME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_GENERALIZEDTIME_print_procname);
end;

function ERR_ASN1_TIME_print(bp: PBIO; tm: PASN1_TIME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_print_procname);
end;

function ERR_ASN1_TIME_print_ex(bp: PBIO; tm: PASN1_TIME; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_print_ex_procname);
end;

function ERR_ASN1_STRING_print(bp: PBIO; v: PASN1_STRING): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_print_procname);
end;

function ERR_ASN1_STRING_print_ex(_out: PBIO; str: PASN1_STRING; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_print_ex_procname);
end;

function ERR_ASN1_buf_print(bp: PBIO; buf: PIdAnsiChar; buflen: TIdC_SIZET; off: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_buf_print_procname);
end;

function ERR_ASN1_bn_print(bp: PBIO; number: PIdAnsiChar; num: PBIGNUM; buf: PIdAnsiChar; off: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_bn_print_procname);
end;

function ERR_ASN1_parse(bp: PBIO; pp: PIdAnsiChar; len: TIdC_LONG; indent: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_parse_procname);
end;

function ERR_ASN1_parse_dump(bp: PBIO; pp: PIdAnsiChar; len: TIdC_LONG; indent: TIdC_INT; dump: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_parse_dump_procname);
end;

function ERR_ASN1_tag2str(tag: TIdC_INT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_tag2str_procname);
end;

function ERR_ASN1_UNIVERSALSTRING_to_string(s: PASN1_UNIVERSALSTRING): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_UNIVERSALSTRING_to_string_procname);
end;

function ERR_ASN1_TYPE_set_octetstring(a: PASN1_TYPE; data: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TYPE_set_octetstring_procname);
end;

function ERR_ASN1_TYPE_get_octetstring(a: PASN1_TYPE; data: PIdAnsiChar; max_len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TYPE_get_octetstring_procname);
end;

function ERR_ASN1_TYPE_set_int_octetstring(a: PASN1_TYPE; num: TIdC_LONG; data: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TYPE_set_int_octetstring_procname);
end;

function ERR_ASN1_TYPE_get_int_octetstring(a: PASN1_TYPE; num: PIdC_LONG; data: PIdAnsiChar; max_len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TYPE_get_int_octetstring_procname);
end;

function ERR_ASN1_item_unpack(oct: PASN1_STRING; it: PASN1_ITEM): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_unpack_procname);
end;

function ERR_ASN1_item_unpack_ex(oct: PASN1_STRING; it: PASN1_ITEM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_unpack_ex_procname);
end;

function ERR_ASN1_item_pack(obj: Pointer; it: PASN1_ITEM; oct: PPASN1_OCTET_STRING): PASN1_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_pack_procname);
end;

procedure ERR_ASN1_STRING_set_default_mask(mask: TIdC_ULONG); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_set_default_mask_procname);
end;

function ERR_ASN1_STRING_set_default_mask_asc(p: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_set_default_mask_asc_procname);
end;

function ERR_ASN1_STRING_get_default_mask: TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_get_default_mask_procname);
end;

function ERR_ASN1_mbstring_copy(_out: PPASN1_STRING; _in: PIdAnsiChar; len: TIdC_INT; inform: TIdC_INT; mask: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_mbstring_copy_procname);
end;

function ERR_ASN1_mbstring_ncopy(_out: PPASN1_STRING; _in: PIdAnsiChar; len: TIdC_INT; inform: TIdC_INT; mask: TIdC_ULONG; minsize: TIdC_LONG; maxsize: TIdC_LONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_mbstring_ncopy_procname);
end;

function ERR_ASN1_STRING_set_by_NID(_out: PPASN1_STRING; _in: PIdAnsiChar; inlen: TIdC_INT; inform: TIdC_INT; nid: TIdC_INT): PASN1_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_set_by_NID_procname);
end;

function ERR_ASN1_STRING_TABLE_get(nid: TIdC_INT): PASN1_STRING_TABLE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_TABLE_get_procname);
end;

function ERR_ASN1_STRING_TABLE_add(arg1: TIdC_INT; arg2: TIdC_LONG; arg3: TIdC_LONG; arg4: TIdC_ULONG; arg5: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_TABLE_add_procname);
end;

procedure ERR_ASN1_STRING_TABLE_cleanup; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_TABLE_cleanup_procname);
end;

function ERR_ASN1_item_new(it: PASN1_ITEM): PASN1_VALUE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_new_procname);
end;

function ERR_ASN1_item_new_ex(it: PASN1_ITEM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PASN1_VALUE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_new_ex_procname);
end;

procedure ERR_ASN1_item_free(val: PASN1_VALUE; it: PASN1_ITEM); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_free_procname);
end;

function ERR_ASN1_item_d2i_ex(val: PPASN1_VALUE; _in: PPIdAnsiChar; len: TIdC_LONG; it: PASN1_ITEM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PASN1_VALUE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_d2i_ex_procname);
end;

function ERR_ASN1_item_d2i(val: PPASN1_VALUE; _in: PPIdAnsiChar; len: TIdC_LONG; it: PASN1_ITEM): PASN1_VALUE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_d2i_procname);
end;

function ERR_ASN1_item_i2d(val: PASN1_VALUE; _out: PPIdAnsiChar; it: PASN1_ITEM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_i2d_procname);
end;

function ERR_ASN1_item_ndef_i2d(val: PASN1_VALUE; _out: PPIdAnsiChar; it: PASN1_ITEM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_ndef_i2d_procname);
end;

procedure ERR_ASN1_add_oid_module; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_add_oid_module_procname);
end;

procedure ERR_ASN1_add_stable_module; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_add_stable_module_procname);
end;

function ERR_ASN1_generate_nconf(str: PIdAnsiChar; nconf: PCONF): PASN1_TYPE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_generate_nconf_procname);
end;

function ERR_ASN1_generate_v3(str: PIdAnsiChar; cnf: PX509V3_CTX): PASN1_TYPE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_generate_v3_procname);
end;

function ERR_ASN1_str2mask(str: PIdAnsiChar; pmask: PIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_str2mask_procname);
end;

function ERR_ASN1_item_print(_out: PBIO; ifld: PASN1_VALUE; indent: TIdC_INT; it: PASN1_ITEM; pctx: PASN1_PCTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_print_procname);
end;

function ERR_ASN1_PCTX_new: PASN1_PCTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PCTX_new_procname);
end;

procedure ERR_ASN1_PCTX_free(p: PASN1_PCTX); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PCTX_free_procname);
end;

function ERR_ASN1_PCTX_get_flags(p: PASN1_PCTX): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PCTX_get_flags_procname);
end;

procedure ERR_ASN1_PCTX_set_flags(p: PASN1_PCTX; flags: TIdC_ULONG); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PCTX_set_flags_procname);
end;

function ERR_ASN1_PCTX_get_nm_flags(p: PASN1_PCTX): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PCTX_get_nm_flags_procname);
end;

procedure ERR_ASN1_PCTX_set_nm_flags(p: PASN1_PCTX; flags: TIdC_ULONG); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PCTX_set_nm_flags_procname);
end;

function ERR_ASN1_PCTX_get_cert_flags(p: PASN1_PCTX): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PCTX_get_cert_flags_procname);
end;

procedure ERR_ASN1_PCTX_set_cert_flags(p: PASN1_PCTX; flags: TIdC_ULONG); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PCTX_set_cert_flags_procname);
end;

function ERR_ASN1_PCTX_get_oid_flags(p: PASN1_PCTX): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PCTX_get_oid_flags_procname);
end;

procedure ERR_ASN1_PCTX_set_oid_flags(p: PASN1_PCTX; flags: TIdC_ULONG); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PCTX_set_oid_flags_procname);
end;

function ERR_ASN1_PCTX_get_str_flags(p: PASN1_PCTX): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PCTX_get_str_flags_procname);
end;

procedure ERR_ASN1_PCTX_set_str_flags(p: PASN1_PCTX; flags: TIdC_ULONG); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PCTX_set_str_flags_procname);
end;

function ERR_ASN1_SCTX_new(scan_cb: TASN1_SCTX_new_scan_cb_cb): PASN1_SCTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_SCTX_new_procname);
end;

procedure ERR_ASN1_SCTX_free(p: PASN1_SCTX); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_SCTX_free_procname);
end;

function ERR_ASN1_SCTX_get_item(p: PASN1_SCTX): PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_SCTX_get_item_procname);
end;

function ERR_ASN1_SCTX_get_template(p: PASN1_SCTX): PASN1_TEMPLATE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_SCTX_get_template_procname);
end;

function ERR_ASN1_SCTX_get_flags(p: PASN1_SCTX): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_SCTX_get_flags_procname);
end;

procedure ERR_ASN1_SCTX_set_app_data(p: PASN1_SCTX; data: Pointer); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_SCTX_set_app_data_procname);
end;

function ERR_ASN1_SCTX_get_app_data(p: PASN1_SCTX): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_SCTX_get_app_data_procname);
end;

function ERR_BIO_f_asn1: PBIO_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_f_asn1_procname);
end;

function ERR_BIO_new_NDEF(_out: PBIO; val: PASN1_VALUE; it: PASN1_ITEM): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_new_NDEF_procname);
end;

function ERR_i2d_ASN1_bio_stream(_out: PBIO; val: PASN1_VALUE; _in: PBIO; flags: TIdC_INT; it: PASN1_ITEM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_bio_stream_procname);
end;

function ERR_PEM_write_bio_ASN1_stream(_out: PBIO; val: PASN1_VALUE; _in: PBIO; flags: TIdC_INT; hdr: PIdAnsiChar; it: PASN1_ITEM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_ASN1_stream_procname);
end;

function ERR_SMIME_write_ASN1(bio: PBIO; val: PASN1_VALUE; data: PBIO; flags: TIdC_INT; ctype_nid: TIdC_INT; econt_nid: TIdC_INT; mdalgs: Pstack_st_X509_ALGOR; it: PASN1_ITEM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SMIME_write_ASN1_procname);
end;

function ERR_SMIME_write_ASN1_ex(bio: PBIO; val: PASN1_VALUE; data: PBIO; flags: TIdC_INT; ctype_nid: TIdC_INT; econt_nid: TIdC_INT; mdalgs: Pstack_st_X509_ALGOR; it: PASN1_ITEM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SMIME_write_ASN1_ex_procname);
end;

function ERR_SMIME_read_ASN1(bio: PBIO; bcont: PPBIO; it: PASN1_ITEM): PASN1_VALUE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SMIME_read_ASN1_procname);
end;

function ERR_SMIME_read_ASN1_ex(bio: PBIO; flags: TIdC_INT; bcont: PPBIO; it: PASN1_ITEM; x: PPASN1_VALUE; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PASN1_VALUE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SMIME_read_ASN1_ex_procname);
end;

function ERR_SMIME_crlf_copy(_in: PBIO; _out: PBIO; flags: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SMIME_crlf_copy_procname);
end;

function ERR_SMIME_text(_in: PBIO; _out: PBIO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SMIME_text_procname);
end;

function ERR_ASN1_ITEM_lookup(name: PIdAnsiChar): PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_ITEM_lookup_procname);
end;

function ERR_ASN1_ITEM_get(i: TIdC_SIZET): PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_ITEM_get_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  d2i_ASN1_SEQUENCE_ANY := LoadLibFunction(ADllHandle, d2i_ASN1_SEQUENCE_ANY_procname);
  FuncLoadError := not assigned(d2i_ASN1_SEQUENCE_ANY);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ASN1_SEQUENCE_ANY_allownil)}
    d2i_ASN1_SEQUENCE_ANY := ERR_d2i_ASN1_SEQUENCE_ANY;
    {$ifend}
    {$if declared(d2i_ASN1_SEQUENCE_ANY_introduced)}
    if LibVersion < d2i_ASN1_SEQUENCE_ANY_introduced then
    begin
      {$if declared(FC_d2i_ASN1_SEQUENCE_ANY)}
      d2i_ASN1_SEQUENCE_ANY := FC_d2i_ASN1_SEQUENCE_ANY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ASN1_SEQUENCE_ANY_removed)}
    if d2i_ASN1_SEQUENCE_ANY_removed <= LibVersion then
    begin
      {$if declared(_d2i_ASN1_SEQUENCE_ANY)}
      d2i_ASN1_SEQUENCE_ANY := _d2i_ASN1_SEQUENCE_ANY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ASN1_SEQUENCE_ANY_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ASN1_SEQUENCE_ANY');
    {$ifend}
  end;
  
  i2d_ASN1_SEQUENCE_ANY := LoadLibFunction(ADllHandle, i2d_ASN1_SEQUENCE_ANY_procname);
  FuncLoadError := not assigned(i2d_ASN1_SEQUENCE_ANY);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ASN1_SEQUENCE_ANY_allownil)}
    i2d_ASN1_SEQUENCE_ANY := ERR_i2d_ASN1_SEQUENCE_ANY;
    {$ifend}
    {$if declared(i2d_ASN1_SEQUENCE_ANY_introduced)}
    if LibVersion < i2d_ASN1_SEQUENCE_ANY_introduced then
    begin
      {$if declared(FC_i2d_ASN1_SEQUENCE_ANY)}
      i2d_ASN1_SEQUENCE_ANY := FC_i2d_ASN1_SEQUENCE_ANY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ASN1_SEQUENCE_ANY_removed)}
    if i2d_ASN1_SEQUENCE_ANY_removed <= LibVersion then
    begin
      {$if declared(_i2d_ASN1_SEQUENCE_ANY)}
      i2d_ASN1_SEQUENCE_ANY := _i2d_ASN1_SEQUENCE_ANY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ASN1_SEQUENCE_ANY_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ASN1_SEQUENCE_ANY');
    {$ifend}
  end;
  
  ASN1_SEQUENCE_ANY_it := LoadLibFunction(ADllHandle, ASN1_SEQUENCE_ANY_it_procname);
  FuncLoadError := not assigned(ASN1_SEQUENCE_ANY_it);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_SEQUENCE_ANY_it_allownil)}
    ASN1_SEQUENCE_ANY_it := ERR_ASN1_SEQUENCE_ANY_it;
    {$ifend}
    {$if declared(ASN1_SEQUENCE_ANY_it_introduced)}
    if LibVersion < ASN1_SEQUENCE_ANY_it_introduced then
    begin
      {$if declared(FC_ASN1_SEQUENCE_ANY_it)}
      ASN1_SEQUENCE_ANY_it := FC_ASN1_SEQUENCE_ANY_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_SEQUENCE_ANY_it_removed)}
    if ASN1_SEQUENCE_ANY_it_removed <= LibVersion then
    begin
      {$if declared(_ASN1_SEQUENCE_ANY_it)}
      ASN1_SEQUENCE_ANY_it := _ASN1_SEQUENCE_ANY_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_SEQUENCE_ANY_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_SEQUENCE_ANY_it');
    {$ifend}
  end;
  
  d2i_ASN1_SET_ANY := LoadLibFunction(ADllHandle, d2i_ASN1_SET_ANY_procname);
  FuncLoadError := not assigned(d2i_ASN1_SET_ANY);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ASN1_SET_ANY_allownil)}
    d2i_ASN1_SET_ANY := ERR_d2i_ASN1_SET_ANY;
    {$ifend}
    {$if declared(d2i_ASN1_SET_ANY_introduced)}
    if LibVersion < d2i_ASN1_SET_ANY_introduced then
    begin
      {$if declared(FC_d2i_ASN1_SET_ANY)}
      d2i_ASN1_SET_ANY := FC_d2i_ASN1_SET_ANY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ASN1_SET_ANY_removed)}
    if d2i_ASN1_SET_ANY_removed <= LibVersion then
    begin
      {$if declared(_d2i_ASN1_SET_ANY)}
      d2i_ASN1_SET_ANY := _d2i_ASN1_SET_ANY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ASN1_SET_ANY_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ASN1_SET_ANY');
    {$ifend}
  end;
  
  i2d_ASN1_SET_ANY := LoadLibFunction(ADllHandle, i2d_ASN1_SET_ANY_procname);
  FuncLoadError := not assigned(i2d_ASN1_SET_ANY);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ASN1_SET_ANY_allownil)}
    i2d_ASN1_SET_ANY := ERR_i2d_ASN1_SET_ANY;
    {$ifend}
    {$if declared(i2d_ASN1_SET_ANY_introduced)}
    if LibVersion < i2d_ASN1_SET_ANY_introduced then
    begin
      {$if declared(FC_i2d_ASN1_SET_ANY)}
      i2d_ASN1_SET_ANY := FC_i2d_ASN1_SET_ANY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ASN1_SET_ANY_removed)}
    if i2d_ASN1_SET_ANY_removed <= LibVersion then
    begin
      {$if declared(_i2d_ASN1_SET_ANY)}
      i2d_ASN1_SET_ANY := _i2d_ASN1_SET_ANY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ASN1_SET_ANY_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ASN1_SET_ANY');
    {$ifend}
  end;
  
  ASN1_SET_ANY_it := LoadLibFunction(ADllHandle, ASN1_SET_ANY_it_procname);
  FuncLoadError := not assigned(ASN1_SET_ANY_it);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_SET_ANY_it_allownil)}
    ASN1_SET_ANY_it := ERR_ASN1_SET_ANY_it;
    {$ifend}
    {$if declared(ASN1_SET_ANY_it_introduced)}
    if LibVersion < ASN1_SET_ANY_it_introduced then
    begin
      {$if declared(FC_ASN1_SET_ANY_it)}
      ASN1_SET_ANY_it := FC_ASN1_SET_ANY_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_SET_ANY_it_removed)}
    if ASN1_SET_ANY_it_removed <= LibVersion then
    begin
      {$if declared(_ASN1_SET_ANY_it)}
      ASN1_SET_ANY_it := _ASN1_SET_ANY_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_SET_ANY_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_SET_ANY_it');
    {$ifend}
  end;
  
  ASN1_TYPE_new := LoadLibFunction(ADllHandle, ASN1_TYPE_new_procname);
  FuncLoadError := not assigned(ASN1_TYPE_new);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TYPE_new_allownil)}
    ASN1_TYPE_new := ERR_ASN1_TYPE_new;
    {$ifend}
    {$if declared(ASN1_TYPE_new_introduced)}
    if LibVersion < ASN1_TYPE_new_introduced then
    begin
      {$if declared(FC_ASN1_TYPE_new)}
      ASN1_TYPE_new := FC_ASN1_TYPE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TYPE_new_removed)}
    if ASN1_TYPE_new_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TYPE_new)}
      ASN1_TYPE_new := _ASN1_TYPE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TYPE_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TYPE_new');
    {$ifend}
  end;
  
  ASN1_TYPE_free := LoadLibFunction(ADllHandle, ASN1_TYPE_free_procname);
  FuncLoadError := not assigned(ASN1_TYPE_free);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TYPE_free_allownil)}
    ASN1_TYPE_free := ERR_ASN1_TYPE_free;
    {$ifend}
    {$if declared(ASN1_TYPE_free_introduced)}
    if LibVersion < ASN1_TYPE_free_introduced then
    begin
      {$if declared(FC_ASN1_TYPE_free)}
      ASN1_TYPE_free := FC_ASN1_TYPE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TYPE_free_removed)}
    if ASN1_TYPE_free_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TYPE_free)}
      ASN1_TYPE_free := _ASN1_TYPE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TYPE_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TYPE_free');
    {$ifend}
  end;
  
  d2i_ASN1_TYPE := LoadLibFunction(ADllHandle, d2i_ASN1_TYPE_procname);
  FuncLoadError := not assigned(d2i_ASN1_TYPE);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ASN1_TYPE_allownil)}
    d2i_ASN1_TYPE := ERR_d2i_ASN1_TYPE;
    {$ifend}
    {$if declared(d2i_ASN1_TYPE_introduced)}
    if LibVersion < d2i_ASN1_TYPE_introduced then
    begin
      {$if declared(FC_d2i_ASN1_TYPE)}
      d2i_ASN1_TYPE := FC_d2i_ASN1_TYPE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ASN1_TYPE_removed)}
    if d2i_ASN1_TYPE_removed <= LibVersion then
    begin
      {$if declared(_d2i_ASN1_TYPE)}
      d2i_ASN1_TYPE := _d2i_ASN1_TYPE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ASN1_TYPE_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ASN1_TYPE');
    {$ifend}
  end;
  
  i2d_ASN1_TYPE := LoadLibFunction(ADllHandle, i2d_ASN1_TYPE_procname);
  FuncLoadError := not assigned(i2d_ASN1_TYPE);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ASN1_TYPE_allownil)}
    i2d_ASN1_TYPE := ERR_i2d_ASN1_TYPE;
    {$ifend}
    {$if declared(i2d_ASN1_TYPE_introduced)}
    if LibVersion < i2d_ASN1_TYPE_introduced then
    begin
      {$if declared(FC_i2d_ASN1_TYPE)}
      i2d_ASN1_TYPE := FC_i2d_ASN1_TYPE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ASN1_TYPE_removed)}
    if i2d_ASN1_TYPE_removed <= LibVersion then
    begin
      {$if declared(_i2d_ASN1_TYPE)}
      i2d_ASN1_TYPE := _i2d_ASN1_TYPE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ASN1_TYPE_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ASN1_TYPE');
    {$ifend}
  end;
  
  ASN1_ANY_it := LoadLibFunction(ADllHandle, ASN1_ANY_it_procname);
  FuncLoadError := not assigned(ASN1_ANY_it);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_ANY_it_allownil)}
    ASN1_ANY_it := ERR_ASN1_ANY_it;
    {$ifend}
    {$if declared(ASN1_ANY_it_introduced)}
    if LibVersion < ASN1_ANY_it_introduced then
    begin
      {$if declared(FC_ASN1_ANY_it)}
      ASN1_ANY_it := FC_ASN1_ANY_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_ANY_it_removed)}
    if ASN1_ANY_it_removed <= LibVersion then
    begin
      {$if declared(_ASN1_ANY_it)}
      ASN1_ANY_it := _ASN1_ANY_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_ANY_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_ANY_it');
    {$ifend}
  end;
  
  ASN1_TYPE_get := LoadLibFunction(ADllHandle, ASN1_TYPE_get_procname);
  FuncLoadError := not assigned(ASN1_TYPE_get);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TYPE_get_allownil)}
    ASN1_TYPE_get := ERR_ASN1_TYPE_get;
    {$ifend}
    {$if declared(ASN1_TYPE_get_introduced)}
    if LibVersion < ASN1_TYPE_get_introduced then
    begin
      {$if declared(FC_ASN1_TYPE_get)}
      ASN1_TYPE_get := FC_ASN1_TYPE_get;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TYPE_get_removed)}
    if ASN1_TYPE_get_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TYPE_get)}
      ASN1_TYPE_get := _ASN1_TYPE_get;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TYPE_get_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TYPE_get');
    {$ifend}
  end;
  
  ASN1_TYPE_set := LoadLibFunction(ADllHandle, ASN1_TYPE_set_procname);
  FuncLoadError := not assigned(ASN1_TYPE_set);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TYPE_set_allownil)}
    ASN1_TYPE_set := ERR_ASN1_TYPE_set;
    {$ifend}
    {$if declared(ASN1_TYPE_set_introduced)}
    if LibVersion < ASN1_TYPE_set_introduced then
    begin
      {$if declared(FC_ASN1_TYPE_set)}
      ASN1_TYPE_set := FC_ASN1_TYPE_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TYPE_set_removed)}
    if ASN1_TYPE_set_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TYPE_set)}
      ASN1_TYPE_set := _ASN1_TYPE_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TYPE_set_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TYPE_set');
    {$ifend}
  end;
  
  ASN1_TYPE_set1 := LoadLibFunction(ADllHandle, ASN1_TYPE_set1_procname);
  FuncLoadError := not assigned(ASN1_TYPE_set1);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TYPE_set1_allownil)}
    ASN1_TYPE_set1 := ERR_ASN1_TYPE_set1;
    {$ifend}
    {$if declared(ASN1_TYPE_set1_introduced)}
    if LibVersion < ASN1_TYPE_set1_introduced then
    begin
      {$if declared(FC_ASN1_TYPE_set1)}
      ASN1_TYPE_set1 := FC_ASN1_TYPE_set1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TYPE_set1_removed)}
    if ASN1_TYPE_set1_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TYPE_set1)}
      ASN1_TYPE_set1 := _ASN1_TYPE_set1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TYPE_set1_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TYPE_set1');
    {$ifend}
  end;
  
  ASN1_TYPE_cmp := LoadLibFunction(ADllHandle, ASN1_TYPE_cmp_procname);
  FuncLoadError := not assigned(ASN1_TYPE_cmp);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TYPE_cmp_allownil)}
    ASN1_TYPE_cmp := ERR_ASN1_TYPE_cmp;
    {$ifend}
    {$if declared(ASN1_TYPE_cmp_introduced)}
    if LibVersion < ASN1_TYPE_cmp_introduced then
    begin
      {$if declared(FC_ASN1_TYPE_cmp)}
      ASN1_TYPE_cmp := FC_ASN1_TYPE_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TYPE_cmp_removed)}
    if ASN1_TYPE_cmp_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TYPE_cmp)}
      ASN1_TYPE_cmp := _ASN1_TYPE_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TYPE_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TYPE_cmp');
    {$ifend}
  end;
  
  ASN1_TYPE_pack_sequence := LoadLibFunction(ADllHandle, ASN1_TYPE_pack_sequence_procname);
  FuncLoadError := not assigned(ASN1_TYPE_pack_sequence);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TYPE_pack_sequence_allownil)}
    ASN1_TYPE_pack_sequence := ERR_ASN1_TYPE_pack_sequence;
    {$ifend}
    {$if declared(ASN1_TYPE_pack_sequence_introduced)}
    if LibVersion < ASN1_TYPE_pack_sequence_introduced then
    begin
      {$if declared(FC_ASN1_TYPE_pack_sequence)}
      ASN1_TYPE_pack_sequence := FC_ASN1_TYPE_pack_sequence;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TYPE_pack_sequence_removed)}
    if ASN1_TYPE_pack_sequence_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TYPE_pack_sequence)}
      ASN1_TYPE_pack_sequence := _ASN1_TYPE_pack_sequence;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TYPE_pack_sequence_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TYPE_pack_sequence');
    {$ifend}
  end;
  
  ASN1_TYPE_unpack_sequence := LoadLibFunction(ADllHandle, ASN1_TYPE_unpack_sequence_procname);
  FuncLoadError := not assigned(ASN1_TYPE_unpack_sequence);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TYPE_unpack_sequence_allownil)}
    ASN1_TYPE_unpack_sequence := ERR_ASN1_TYPE_unpack_sequence;
    {$ifend}
    {$if declared(ASN1_TYPE_unpack_sequence_introduced)}
    if LibVersion < ASN1_TYPE_unpack_sequence_introduced then
    begin
      {$if declared(FC_ASN1_TYPE_unpack_sequence)}
      ASN1_TYPE_unpack_sequence := FC_ASN1_TYPE_unpack_sequence;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TYPE_unpack_sequence_removed)}
    if ASN1_TYPE_unpack_sequence_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TYPE_unpack_sequence)}
      ASN1_TYPE_unpack_sequence := _ASN1_TYPE_unpack_sequence;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TYPE_unpack_sequence_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TYPE_unpack_sequence');
    {$ifend}
  end;
  
  ASN1_OBJECT_new := LoadLibFunction(ADllHandle, ASN1_OBJECT_new_procname);
  FuncLoadError := not assigned(ASN1_OBJECT_new);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_OBJECT_new_allownil)}
    ASN1_OBJECT_new := ERR_ASN1_OBJECT_new;
    {$ifend}
    {$if declared(ASN1_OBJECT_new_introduced)}
    if LibVersion < ASN1_OBJECT_new_introduced then
    begin
      {$if declared(FC_ASN1_OBJECT_new)}
      ASN1_OBJECT_new := FC_ASN1_OBJECT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_OBJECT_new_removed)}
    if ASN1_OBJECT_new_removed <= LibVersion then
    begin
      {$if declared(_ASN1_OBJECT_new)}
      ASN1_OBJECT_new := _ASN1_OBJECT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_OBJECT_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_OBJECT_new');
    {$ifend}
  end;
  
  ASN1_OBJECT_free := LoadLibFunction(ADllHandle, ASN1_OBJECT_free_procname);
  FuncLoadError := not assigned(ASN1_OBJECT_free);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_OBJECT_free_allownil)}
    ASN1_OBJECT_free := ERR_ASN1_OBJECT_free;
    {$ifend}
    {$if declared(ASN1_OBJECT_free_introduced)}
    if LibVersion < ASN1_OBJECT_free_introduced then
    begin
      {$if declared(FC_ASN1_OBJECT_free)}
      ASN1_OBJECT_free := FC_ASN1_OBJECT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_OBJECT_free_removed)}
    if ASN1_OBJECT_free_removed <= LibVersion then
    begin
      {$if declared(_ASN1_OBJECT_free)}
      ASN1_OBJECT_free := _ASN1_OBJECT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_OBJECT_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_OBJECT_free');
    {$ifend}
  end;
  
  d2i_ASN1_OBJECT := LoadLibFunction(ADllHandle, d2i_ASN1_OBJECT_procname);
  FuncLoadError := not assigned(d2i_ASN1_OBJECT);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ASN1_OBJECT_allownil)}
    d2i_ASN1_OBJECT := ERR_d2i_ASN1_OBJECT;
    {$ifend}
    {$if declared(d2i_ASN1_OBJECT_introduced)}
    if LibVersion < d2i_ASN1_OBJECT_introduced then
    begin
      {$if declared(FC_d2i_ASN1_OBJECT)}
      d2i_ASN1_OBJECT := FC_d2i_ASN1_OBJECT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ASN1_OBJECT_removed)}
    if d2i_ASN1_OBJECT_removed <= LibVersion then
    begin
      {$if declared(_d2i_ASN1_OBJECT)}
      d2i_ASN1_OBJECT := _d2i_ASN1_OBJECT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ASN1_OBJECT_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ASN1_OBJECT');
    {$ifend}
  end;
  
  i2d_ASN1_OBJECT := LoadLibFunction(ADllHandle, i2d_ASN1_OBJECT_procname);
  FuncLoadError := not assigned(i2d_ASN1_OBJECT);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ASN1_OBJECT_allownil)}
    i2d_ASN1_OBJECT := ERR_i2d_ASN1_OBJECT;
    {$ifend}
    {$if declared(i2d_ASN1_OBJECT_introduced)}
    if LibVersion < i2d_ASN1_OBJECT_introduced then
    begin
      {$if declared(FC_i2d_ASN1_OBJECT)}
      i2d_ASN1_OBJECT := FC_i2d_ASN1_OBJECT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ASN1_OBJECT_removed)}
    if i2d_ASN1_OBJECT_removed <= LibVersion then
    begin
      {$if declared(_i2d_ASN1_OBJECT)}
      i2d_ASN1_OBJECT := _i2d_ASN1_OBJECT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ASN1_OBJECT_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ASN1_OBJECT');
    {$ifend}
  end;
  
  ASN1_OBJECT_it := LoadLibFunction(ADllHandle, ASN1_OBJECT_it_procname);
  FuncLoadError := not assigned(ASN1_OBJECT_it);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_OBJECT_it_allownil)}
    ASN1_OBJECT_it := ERR_ASN1_OBJECT_it;
    {$ifend}
    {$if declared(ASN1_OBJECT_it_introduced)}
    if LibVersion < ASN1_OBJECT_it_introduced then
    begin
      {$if declared(FC_ASN1_OBJECT_it)}
      ASN1_OBJECT_it := FC_ASN1_OBJECT_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_OBJECT_it_removed)}
    if ASN1_OBJECT_it_removed <= LibVersion then
    begin
      {$if declared(_ASN1_OBJECT_it)}
      ASN1_OBJECT_it := _ASN1_OBJECT_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_OBJECT_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_OBJECT_it');
    {$ifend}
  end;
  
  ASN1_STRING_new := LoadLibFunction(ADllHandle, ASN1_STRING_new_procname);
  FuncLoadError := not assigned(ASN1_STRING_new);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_STRING_new_allownil)}
    ASN1_STRING_new := ERR_ASN1_STRING_new;
    {$ifend}
    {$if declared(ASN1_STRING_new_introduced)}
    if LibVersion < ASN1_STRING_new_introduced then
    begin
      {$if declared(FC_ASN1_STRING_new)}
      ASN1_STRING_new := FC_ASN1_STRING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_STRING_new_removed)}
    if ASN1_STRING_new_removed <= LibVersion then
    begin
      {$if declared(_ASN1_STRING_new)}
      ASN1_STRING_new := _ASN1_STRING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_STRING_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_STRING_new');
    {$ifend}
  end;
  
  ASN1_STRING_free := LoadLibFunction(ADllHandle, ASN1_STRING_free_procname);
  FuncLoadError := not assigned(ASN1_STRING_free);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_STRING_free_allownil)}
    ASN1_STRING_free := ERR_ASN1_STRING_free;
    {$ifend}
    {$if declared(ASN1_STRING_free_introduced)}
    if LibVersion < ASN1_STRING_free_introduced then
    begin
      {$if declared(FC_ASN1_STRING_free)}
      ASN1_STRING_free := FC_ASN1_STRING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_STRING_free_removed)}
    if ASN1_STRING_free_removed <= LibVersion then
    begin
      {$if declared(_ASN1_STRING_free)}
      ASN1_STRING_free := _ASN1_STRING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_STRING_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_STRING_free');
    {$ifend}
  end;
  
  ASN1_STRING_clear_free := LoadLibFunction(ADllHandle, ASN1_STRING_clear_free_procname);
  FuncLoadError := not assigned(ASN1_STRING_clear_free);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_STRING_clear_free_allownil)}
    ASN1_STRING_clear_free := ERR_ASN1_STRING_clear_free;
    {$ifend}
    {$if declared(ASN1_STRING_clear_free_introduced)}
    if LibVersion < ASN1_STRING_clear_free_introduced then
    begin
      {$if declared(FC_ASN1_STRING_clear_free)}
      ASN1_STRING_clear_free := FC_ASN1_STRING_clear_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_STRING_clear_free_removed)}
    if ASN1_STRING_clear_free_removed <= LibVersion then
    begin
      {$if declared(_ASN1_STRING_clear_free)}
      ASN1_STRING_clear_free := _ASN1_STRING_clear_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_STRING_clear_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_STRING_clear_free');
    {$ifend}
  end;
  
  ASN1_STRING_copy := LoadLibFunction(ADllHandle, ASN1_STRING_copy_procname);
  FuncLoadError := not assigned(ASN1_STRING_copy);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_STRING_copy_allownil)}
    ASN1_STRING_copy := ERR_ASN1_STRING_copy;
    {$ifend}
    {$if declared(ASN1_STRING_copy_introduced)}
    if LibVersion < ASN1_STRING_copy_introduced then
    begin
      {$if declared(FC_ASN1_STRING_copy)}
      ASN1_STRING_copy := FC_ASN1_STRING_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_STRING_copy_removed)}
    if ASN1_STRING_copy_removed <= LibVersion then
    begin
      {$if declared(_ASN1_STRING_copy)}
      ASN1_STRING_copy := _ASN1_STRING_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_STRING_copy_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_STRING_copy');
    {$ifend}
  end;
  
  ASN1_STRING_dup := LoadLibFunction(ADllHandle, ASN1_STRING_dup_procname);
  FuncLoadError := not assigned(ASN1_STRING_dup);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_STRING_dup_allownil)}
    ASN1_STRING_dup := ERR_ASN1_STRING_dup;
    {$ifend}
    {$if declared(ASN1_STRING_dup_introduced)}
    if LibVersion < ASN1_STRING_dup_introduced then
    begin
      {$if declared(FC_ASN1_STRING_dup)}
      ASN1_STRING_dup := FC_ASN1_STRING_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_STRING_dup_removed)}
    if ASN1_STRING_dup_removed <= LibVersion then
    begin
      {$if declared(_ASN1_STRING_dup)}
      ASN1_STRING_dup := _ASN1_STRING_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_STRING_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_STRING_dup');
    {$ifend}
  end;
  
  ASN1_STRING_type_new := LoadLibFunction(ADllHandle, ASN1_STRING_type_new_procname);
  FuncLoadError := not assigned(ASN1_STRING_type_new);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_STRING_type_new_allownil)}
    ASN1_STRING_type_new := ERR_ASN1_STRING_type_new;
    {$ifend}
    {$if declared(ASN1_STRING_type_new_introduced)}
    if LibVersion < ASN1_STRING_type_new_introduced then
    begin
      {$if declared(FC_ASN1_STRING_type_new)}
      ASN1_STRING_type_new := FC_ASN1_STRING_type_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_STRING_type_new_removed)}
    if ASN1_STRING_type_new_removed <= LibVersion then
    begin
      {$if declared(_ASN1_STRING_type_new)}
      ASN1_STRING_type_new := _ASN1_STRING_type_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_STRING_type_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_STRING_type_new');
    {$ifend}
  end;
  
  ASN1_STRING_cmp := LoadLibFunction(ADllHandle, ASN1_STRING_cmp_procname);
  FuncLoadError := not assigned(ASN1_STRING_cmp);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_STRING_cmp_allownil)}
    ASN1_STRING_cmp := ERR_ASN1_STRING_cmp;
    {$ifend}
    {$if declared(ASN1_STRING_cmp_introduced)}
    if LibVersion < ASN1_STRING_cmp_introduced then
    begin
      {$if declared(FC_ASN1_STRING_cmp)}
      ASN1_STRING_cmp := FC_ASN1_STRING_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_STRING_cmp_removed)}
    if ASN1_STRING_cmp_removed <= LibVersion then
    begin
      {$if declared(_ASN1_STRING_cmp)}
      ASN1_STRING_cmp := _ASN1_STRING_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_STRING_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_STRING_cmp');
    {$ifend}
  end;
  
  ASN1_STRING_set := LoadLibFunction(ADllHandle, ASN1_STRING_set_procname);
  FuncLoadError := not assigned(ASN1_STRING_set);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_STRING_set_allownil)}
    ASN1_STRING_set := ERR_ASN1_STRING_set;
    {$ifend}
    {$if declared(ASN1_STRING_set_introduced)}
    if LibVersion < ASN1_STRING_set_introduced then
    begin
      {$if declared(FC_ASN1_STRING_set)}
      ASN1_STRING_set := FC_ASN1_STRING_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_STRING_set_removed)}
    if ASN1_STRING_set_removed <= LibVersion then
    begin
      {$if declared(_ASN1_STRING_set)}
      ASN1_STRING_set := _ASN1_STRING_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_STRING_set_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_STRING_set');
    {$ifend}
  end;
  
  ASN1_STRING_set0 := LoadLibFunction(ADllHandle, ASN1_STRING_set0_procname);
  FuncLoadError := not assigned(ASN1_STRING_set0);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_STRING_set0_allownil)}
    ASN1_STRING_set0 := ERR_ASN1_STRING_set0;
    {$ifend}
    {$if declared(ASN1_STRING_set0_introduced)}
    if LibVersion < ASN1_STRING_set0_introduced then
    begin
      {$if declared(FC_ASN1_STRING_set0)}
      ASN1_STRING_set0 := FC_ASN1_STRING_set0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_STRING_set0_removed)}
    if ASN1_STRING_set0_removed <= LibVersion then
    begin
      {$if declared(_ASN1_STRING_set0)}
      ASN1_STRING_set0 := _ASN1_STRING_set0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_STRING_set0_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_STRING_set0');
    {$ifend}
  end;
  
  ASN1_STRING_length := LoadLibFunction(ADllHandle, ASN1_STRING_length_procname);
  FuncLoadError := not assigned(ASN1_STRING_length);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_STRING_length_allownil)}
    ASN1_STRING_length := ERR_ASN1_STRING_length;
    {$ifend}
    {$if declared(ASN1_STRING_length_introduced)}
    if LibVersion < ASN1_STRING_length_introduced then
    begin
      {$if declared(FC_ASN1_STRING_length)}
      ASN1_STRING_length := FC_ASN1_STRING_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_STRING_length_removed)}
    if ASN1_STRING_length_removed <= LibVersion then
    begin
      {$if declared(_ASN1_STRING_length)}
      ASN1_STRING_length := _ASN1_STRING_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_STRING_length_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_STRING_length');
    {$ifend}
  end;
  
  ASN1_STRING_length_set := LoadLibFunction(ADllHandle, ASN1_STRING_length_set_procname);
  FuncLoadError := not assigned(ASN1_STRING_length_set);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_STRING_length_set_allownil)}
    ASN1_STRING_length_set := ERR_ASN1_STRING_length_set;
    {$ifend}
    {$if declared(ASN1_STRING_length_set_introduced)}
    if LibVersion < ASN1_STRING_length_set_introduced then
    begin
      {$if declared(FC_ASN1_STRING_length_set)}
      ASN1_STRING_length_set := FC_ASN1_STRING_length_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_STRING_length_set_removed)}
    if ASN1_STRING_length_set_removed <= LibVersion then
    begin
      {$if declared(_ASN1_STRING_length_set)}
      ASN1_STRING_length_set := _ASN1_STRING_length_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_STRING_length_set_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_STRING_length_set');
    {$ifend}
  end;
  
  ASN1_STRING_type := LoadLibFunction(ADllHandle, ASN1_STRING_type_procname);
  FuncLoadError := not assigned(ASN1_STRING_type);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_STRING_type_allownil)}
    ASN1_STRING_type := ERR_ASN1_STRING_type;
    {$ifend}
    {$if declared(ASN1_STRING_type_introduced)}
    if LibVersion < ASN1_STRING_type_introduced then
    begin
      {$if declared(FC_ASN1_STRING_type)}
      ASN1_STRING_type := FC_ASN1_STRING_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_STRING_type_removed)}
    if ASN1_STRING_type_removed <= LibVersion then
    begin
      {$if declared(_ASN1_STRING_type)}
      ASN1_STRING_type := _ASN1_STRING_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_STRING_type_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_STRING_type');
    {$ifend}
  end;
  
  
  ASN1_STRING_get0_data := LoadLibFunction(ADllHandle, ASN1_STRING_get0_data_procname);
  FuncLoadError := not assigned(ASN1_STRING_get0_data);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_STRING_get0_data_allownil)}
    ASN1_STRING_get0_data := ERR_ASN1_STRING_get0_data;
    {$ifend}
    {$if declared(ASN1_STRING_get0_data_introduced)}
    if LibVersion < ASN1_STRING_get0_data_introduced then
    begin
      {$if declared(FC_ASN1_STRING_get0_data)}
      ASN1_STRING_get0_data := FC_ASN1_STRING_get0_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_STRING_get0_data_removed)}
    if ASN1_STRING_get0_data_removed <= LibVersion then
    begin
      {$if declared(_ASN1_STRING_get0_data)}
      ASN1_STRING_get0_data := _ASN1_STRING_get0_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_STRING_get0_data_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_STRING_get0_data');
    {$ifend}
  end;
  
  ASN1_BIT_STRING_new := LoadLibFunction(ADllHandle, ASN1_BIT_STRING_new_procname);
  FuncLoadError := not assigned(ASN1_BIT_STRING_new);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_BIT_STRING_new_allownil)}
    ASN1_BIT_STRING_new := ERR_ASN1_BIT_STRING_new;
    {$ifend}
    {$if declared(ASN1_BIT_STRING_new_introduced)}
    if LibVersion < ASN1_BIT_STRING_new_introduced then
    begin
      {$if declared(FC_ASN1_BIT_STRING_new)}
      ASN1_BIT_STRING_new := FC_ASN1_BIT_STRING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_BIT_STRING_new_removed)}
    if ASN1_BIT_STRING_new_removed <= LibVersion then
    begin
      {$if declared(_ASN1_BIT_STRING_new)}
      ASN1_BIT_STRING_new := _ASN1_BIT_STRING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_BIT_STRING_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_BIT_STRING_new');
    {$ifend}
  end;
  
  ASN1_BIT_STRING_free := LoadLibFunction(ADllHandle, ASN1_BIT_STRING_free_procname);
  FuncLoadError := not assigned(ASN1_BIT_STRING_free);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_BIT_STRING_free_allownil)}
    ASN1_BIT_STRING_free := ERR_ASN1_BIT_STRING_free;
    {$ifend}
    {$if declared(ASN1_BIT_STRING_free_introduced)}
    if LibVersion < ASN1_BIT_STRING_free_introduced then
    begin
      {$if declared(FC_ASN1_BIT_STRING_free)}
      ASN1_BIT_STRING_free := FC_ASN1_BIT_STRING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_BIT_STRING_free_removed)}
    if ASN1_BIT_STRING_free_removed <= LibVersion then
    begin
      {$if declared(_ASN1_BIT_STRING_free)}
      ASN1_BIT_STRING_free := _ASN1_BIT_STRING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_BIT_STRING_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_BIT_STRING_free');
    {$ifend}
  end;
  
  d2i_ASN1_BIT_STRING := LoadLibFunction(ADllHandle, d2i_ASN1_BIT_STRING_procname);
  FuncLoadError := not assigned(d2i_ASN1_BIT_STRING);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ASN1_BIT_STRING_allownil)}
    d2i_ASN1_BIT_STRING := ERR_d2i_ASN1_BIT_STRING;
    {$ifend}
    {$if declared(d2i_ASN1_BIT_STRING_introduced)}
    if LibVersion < d2i_ASN1_BIT_STRING_introduced then
    begin
      {$if declared(FC_d2i_ASN1_BIT_STRING)}
      d2i_ASN1_BIT_STRING := FC_d2i_ASN1_BIT_STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ASN1_BIT_STRING_removed)}
    if d2i_ASN1_BIT_STRING_removed <= LibVersion then
    begin
      {$if declared(_d2i_ASN1_BIT_STRING)}
      d2i_ASN1_BIT_STRING := _d2i_ASN1_BIT_STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ASN1_BIT_STRING_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ASN1_BIT_STRING');
    {$ifend}
  end;
  
  i2d_ASN1_BIT_STRING := LoadLibFunction(ADllHandle, i2d_ASN1_BIT_STRING_procname);
  FuncLoadError := not assigned(i2d_ASN1_BIT_STRING);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ASN1_BIT_STRING_allownil)}
    i2d_ASN1_BIT_STRING := ERR_i2d_ASN1_BIT_STRING;
    {$ifend}
    {$if declared(i2d_ASN1_BIT_STRING_introduced)}
    if LibVersion < i2d_ASN1_BIT_STRING_introduced then
    begin
      {$if declared(FC_i2d_ASN1_BIT_STRING)}
      i2d_ASN1_BIT_STRING := FC_i2d_ASN1_BIT_STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ASN1_BIT_STRING_removed)}
    if i2d_ASN1_BIT_STRING_removed <= LibVersion then
    begin
      {$if declared(_i2d_ASN1_BIT_STRING)}
      i2d_ASN1_BIT_STRING := _i2d_ASN1_BIT_STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ASN1_BIT_STRING_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ASN1_BIT_STRING');
    {$ifend}
  end;
  
  ASN1_BIT_STRING_it := LoadLibFunction(ADllHandle, ASN1_BIT_STRING_it_procname);
  FuncLoadError := not assigned(ASN1_BIT_STRING_it);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_BIT_STRING_it_allownil)}
    ASN1_BIT_STRING_it := ERR_ASN1_BIT_STRING_it;
    {$ifend}
    {$if declared(ASN1_BIT_STRING_it_introduced)}
    if LibVersion < ASN1_BIT_STRING_it_introduced then
    begin
      {$if declared(FC_ASN1_BIT_STRING_it)}
      ASN1_BIT_STRING_it := FC_ASN1_BIT_STRING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_BIT_STRING_it_removed)}
    if ASN1_BIT_STRING_it_removed <= LibVersion then
    begin
      {$if declared(_ASN1_BIT_STRING_it)}
      ASN1_BIT_STRING_it := _ASN1_BIT_STRING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_BIT_STRING_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_BIT_STRING_it');
    {$ifend}
  end;
  
  ASN1_BIT_STRING_set := LoadLibFunction(ADllHandle, ASN1_BIT_STRING_set_procname);
  FuncLoadError := not assigned(ASN1_BIT_STRING_set);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_BIT_STRING_set_allownil)}
    ASN1_BIT_STRING_set := ERR_ASN1_BIT_STRING_set;
    {$ifend}
    {$if declared(ASN1_BIT_STRING_set_introduced)}
    if LibVersion < ASN1_BIT_STRING_set_introduced then
    begin
      {$if declared(FC_ASN1_BIT_STRING_set)}
      ASN1_BIT_STRING_set := FC_ASN1_BIT_STRING_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_BIT_STRING_set_removed)}
    if ASN1_BIT_STRING_set_removed <= LibVersion then
    begin
      {$if declared(_ASN1_BIT_STRING_set)}
      ASN1_BIT_STRING_set := _ASN1_BIT_STRING_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_BIT_STRING_set_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_BIT_STRING_set');
    {$ifend}
  end;
  
  ASN1_BIT_STRING_set_bit := LoadLibFunction(ADllHandle, ASN1_BIT_STRING_set_bit_procname);
  FuncLoadError := not assigned(ASN1_BIT_STRING_set_bit);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_BIT_STRING_set_bit_allownil)}
    ASN1_BIT_STRING_set_bit := ERR_ASN1_BIT_STRING_set_bit;
    {$ifend}
    {$if declared(ASN1_BIT_STRING_set_bit_introduced)}
    if LibVersion < ASN1_BIT_STRING_set_bit_introduced then
    begin
      {$if declared(FC_ASN1_BIT_STRING_set_bit)}
      ASN1_BIT_STRING_set_bit := FC_ASN1_BIT_STRING_set_bit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_BIT_STRING_set_bit_removed)}
    if ASN1_BIT_STRING_set_bit_removed <= LibVersion then
    begin
      {$if declared(_ASN1_BIT_STRING_set_bit)}
      ASN1_BIT_STRING_set_bit := _ASN1_BIT_STRING_set_bit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_BIT_STRING_set_bit_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_BIT_STRING_set_bit');
    {$ifend}
  end;
  
  ASN1_BIT_STRING_get_bit := LoadLibFunction(ADllHandle, ASN1_BIT_STRING_get_bit_procname);
  FuncLoadError := not assigned(ASN1_BIT_STRING_get_bit);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_BIT_STRING_get_bit_allownil)}
    ASN1_BIT_STRING_get_bit := ERR_ASN1_BIT_STRING_get_bit;
    {$ifend}
    {$if declared(ASN1_BIT_STRING_get_bit_introduced)}
    if LibVersion < ASN1_BIT_STRING_get_bit_introduced then
    begin
      {$if declared(FC_ASN1_BIT_STRING_get_bit)}
      ASN1_BIT_STRING_get_bit := FC_ASN1_BIT_STRING_get_bit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_BIT_STRING_get_bit_removed)}
    if ASN1_BIT_STRING_get_bit_removed <= LibVersion then
    begin
      {$if declared(_ASN1_BIT_STRING_get_bit)}
      ASN1_BIT_STRING_get_bit := _ASN1_BIT_STRING_get_bit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_BIT_STRING_get_bit_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_BIT_STRING_get_bit');
    {$ifend}
  end;
  
  ASN1_BIT_STRING_check := LoadLibFunction(ADllHandle, ASN1_BIT_STRING_check_procname);
  FuncLoadError := not assigned(ASN1_BIT_STRING_check);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_BIT_STRING_check_allownil)}
    ASN1_BIT_STRING_check := ERR_ASN1_BIT_STRING_check;
    {$ifend}
    {$if declared(ASN1_BIT_STRING_check_introduced)}
    if LibVersion < ASN1_BIT_STRING_check_introduced then
    begin
      {$if declared(FC_ASN1_BIT_STRING_check)}
      ASN1_BIT_STRING_check := FC_ASN1_BIT_STRING_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_BIT_STRING_check_removed)}
    if ASN1_BIT_STRING_check_removed <= LibVersion then
    begin
      {$if declared(_ASN1_BIT_STRING_check)}
      ASN1_BIT_STRING_check := _ASN1_BIT_STRING_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_BIT_STRING_check_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_BIT_STRING_check');
    {$ifend}
  end;
  
  ASN1_BIT_STRING_name_print := LoadLibFunction(ADllHandle, ASN1_BIT_STRING_name_print_procname);
  FuncLoadError := not assigned(ASN1_BIT_STRING_name_print);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_BIT_STRING_name_print_allownil)}
    ASN1_BIT_STRING_name_print := ERR_ASN1_BIT_STRING_name_print;
    {$ifend}
    {$if declared(ASN1_BIT_STRING_name_print_introduced)}
    if LibVersion < ASN1_BIT_STRING_name_print_introduced then
    begin
      {$if declared(FC_ASN1_BIT_STRING_name_print)}
      ASN1_BIT_STRING_name_print := FC_ASN1_BIT_STRING_name_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_BIT_STRING_name_print_removed)}
    if ASN1_BIT_STRING_name_print_removed <= LibVersion then
    begin
      {$if declared(_ASN1_BIT_STRING_name_print)}
      ASN1_BIT_STRING_name_print := _ASN1_BIT_STRING_name_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_BIT_STRING_name_print_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_BIT_STRING_name_print');
    {$ifend}
  end;
  
  ASN1_BIT_STRING_num_asc := LoadLibFunction(ADllHandle, ASN1_BIT_STRING_num_asc_procname);
  FuncLoadError := not assigned(ASN1_BIT_STRING_num_asc);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_BIT_STRING_num_asc_allownil)}
    ASN1_BIT_STRING_num_asc := ERR_ASN1_BIT_STRING_num_asc;
    {$ifend}
    {$if declared(ASN1_BIT_STRING_num_asc_introduced)}
    if LibVersion < ASN1_BIT_STRING_num_asc_introduced then
    begin
      {$if declared(FC_ASN1_BIT_STRING_num_asc)}
      ASN1_BIT_STRING_num_asc := FC_ASN1_BIT_STRING_num_asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_BIT_STRING_num_asc_removed)}
    if ASN1_BIT_STRING_num_asc_removed <= LibVersion then
    begin
      {$if declared(_ASN1_BIT_STRING_num_asc)}
      ASN1_BIT_STRING_num_asc := _ASN1_BIT_STRING_num_asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_BIT_STRING_num_asc_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_BIT_STRING_num_asc');
    {$ifend}
  end;
  
  ASN1_BIT_STRING_set_asc := LoadLibFunction(ADllHandle, ASN1_BIT_STRING_set_asc_procname);
  FuncLoadError := not assigned(ASN1_BIT_STRING_set_asc);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_BIT_STRING_set_asc_allownil)}
    ASN1_BIT_STRING_set_asc := ERR_ASN1_BIT_STRING_set_asc;
    {$ifend}
    {$if declared(ASN1_BIT_STRING_set_asc_introduced)}
    if LibVersion < ASN1_BIT_STRING_set_asc_introduced then
    begin
      {$if declared(FC_ASN1_BIT_STRING_set_asc)}
      ASN1_BIT_STRING_set_asc := FC_ASN1_BIT_STRING_set_asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_BIT_STRING_set_asc_removed)}
    if ASN1_BIT_STRING_set_asc_removed <= LibVersion then
    begin
      {$if declared(_ASN1_BIT_STRING_set_asc)}
      ASN1_BIT_STRING_set_asc := _ASN1_BIT_STRING_set_asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_BIT_STRING_set_asc_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_BIT_STRING_set_asc');
    {$ifend}
  end;
  
  ASN1_INTEGER_new := LoadLibFunction(ADllHandle, ASN1_INTEGER_new_procname);
  FuncLoadError := not assigned(ASN1_INTEGER_new);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_INTEGER_new_allownil)}
    ASN1_INTEGER_new := ERR_ASN1_INTEGER_new;
    {$ifend}
    {$if declared(ASN1_INTEGER_new_introduced)}
    if LibVersion < ASN1_INTEGER_new_introduced then
    begin
      {$if declared(FC_ASN1_INTEGER_new)}
      ASN1_INTEGER_new := FC_ASN1_INTEGER_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_INTEGER_new_removed)}
    if ASN1_INTEGER_new_removed <= LibVersion then
    begin
      {$if declared(_ASN1_INTEGER_new)}
      ASN1_INTEGER_new := _ASN1_INTEGER_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_INTEGER_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_INTEGER_new');
    {$ifend}
  end;
  
  ASN1_INTEGER_free := LoadLibFunction(ADllHandle, ASN1_INTEGER_free_procname);
  FuncLoadError := not assigned(ASN1_INTEGER_free);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_INTEGER_free_allownil)}
    ASN1_INTEGER_free := ERR_ASN1_INTEGER_free;
    {$ifend}
    {$if declared(ASN1_INTEGER_free_introduced)}
    if LibVersion < ASN1_INTEGER_free_introduced then
    begin
      {$if declared(FC_ASN1_INTEGER_free)}
      ASN1_INTEGER_free := FC_ASN1_INTEGER_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_INTEGER_free_removed)}
    if ASN1_INTEGER_free_removed <= LibVersion then
    begin
      {$if declared(_ASN1_INTEGER_free)}
      ASN1_INTEGER_free := _ASN1_INTEGER_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_INTEGER_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_INTEGER_free');
    {$ifend}
  end;
  
  d2i_ASN1_INTEGER := LoadLibFunction(ADllHandle, d2i_ASN1_INTEGER_procname);
  FuncLoadError := not assigned(d2i_ASN1_INTEGER);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ASN1_INTEGER_allownil)}
    d2i_ASN1_INTEGER := ERR_d2i_ASN1_INTEGER;
    {$ifend}
    {$if declared(d2i_ASN1_INTEGER_introduced)}
    if LibVersion < d2i_ASN1_INTEGER_introduced then
    begin
      {$if declared(FC_d2i_ASN1_INTEGER)}
      d2i_ASN1_INTEGER := FC_d2i_ASN1_INTEGER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ASN1_INTEGER_removed)}
    if d2i_ASN1_INTEGER_removed <= LibVersion then
    begin
      {$if declared(_d2i_ASN1_INTEGER)}
      d2i_ASN1_INTEGER := _d2i_ASN1_INTEGER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ASN1_INTEGER_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ASN1_INTEGER');
    {$ifend}
  end;
  
  i2d_ASN1_INTEGER := LoadLibFunction(ADllHandle, i2d_ASN1_INTEGER_procname);
  FuncLoadError := not assigned(i2d_ASN1_INTEGER);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ASN1_INTEGER_allownil)}
    i2d_ASN1_INTEGER := ERR_i2d_ASN1_INTEGER;
    {$ifend}
    {$if declared(i2d_ASN1_INTEGER_introduced)}
    if LibVersion < i2d_ASN1_INTEGER_introduced then
    begin
      {$if declared(FC_i2d_ASN1_INTEGER)}
      i2d_ASN1_INTEGER := FC_i2d_ASN1_INTEGER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ASN1_INTEGER_removed)}
    if i2d_ASN1_INTEGER_removed <= LibVersion then
    begin
      {$if declared(_i2d_ASN1_INTEGER)}
      i2d_ASN1_INTEGER := _i2d_ASN1_INTEGER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ASN1_INTEGER_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ASN1_INTEGER');
    {$ifend}
  end;
  
  ASN1_INTEGER_it := LoadLibFunction(ADllHandle, ASN1_INTEGER_it_procname);
  FuncLoadError := not assigned(ASN1_INTEGER_it);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_INTEGER_it_allownil)}
    ASN1_INTEGER_it := ERR_ASN1_INTEGER_it;
    {$ifend}
    {$if declared(ASN1_INTEGER_it_introduced)}
    if LibVersion < ASN1_INTEGER_it_introduced then
    begin
      {$if declared(FC_ASN1_INTEGER_it)}
      ASN1_INTEGER_it := FC_ASN1_INTEGER_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_INTEGER_it_removed)}
    if ASN1_INTEGER_it_removed <= LibVersion then
    begin
      {$if declared(_ASN1_INTEGER_it)}
      ASN1_INTEGER_it := _ASN1_INTEGER_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_INTEGER_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_INTEGER_it');
    {$ifend}
  end;
  
  d2i_ASN1_UINTEGER := LoadLibFunction(ADllHandle, d2i_ASN1_UINTEGER_procname);
  FuncLoadError := not assigned(d2i_ASN1_UINTEGER);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ASN1_UINTEGER_allownil)}
    d2i_ASN1_UINTEGER := ERR_d2i_ASN1_UINTEGER;
    {$ifend}
    {$if declared(d2i_ASN1_UINTEGER_introduced)}
    if LibVersion < d2i_ASN1_UINTEGER_introduced then
    begin
      {$if declared(FC_d2i_ASN1_UINTEGER)}
      d2i_ASN1_UINTEGER := FC_d2i_ASN1_UINTEGER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ASN1_UINTEGER_removed)}
    if d2i_ASN1_UINTEGER_removed <= LibVersion then
    begin
      {$if declared(_d2i_ASN1_UINTEGER)}
      d2i_ASN1_UINTEGER := _d2i_ASN1_UINTEGER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ASN1_UINTEGER_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ASN1_UINTEGER');
    {$ifend}
  end;
  
  ASN1_INTEGER_dup := LoadLibFunction(ADllHandle, ASN1_INTEGER_dup_procname);
  FuncLoadError := not assigned(ASN1_INTEGER_dup);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_INTEGER_dup_allownil)}
    ASN1_INTEGER_dup := ERR_ASN1_INTEGER_dup;
    {$ifend}
    {$if declared(ASN1_INTEGER_dup_introduced)}
    if LibVersion < ASN1_INTEGER_dup_introduced then
    begin
      {$if declared(FC_ASN1_INTEGER_dup)}
      ASN1_INTEGER_dup := FC_ASN1_INTEGER_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_INTEGER_dup_removed)}
    if ASN1_INTEGER_dup_removed <= LibVersion then
    begin
      {$if declared(_ASN1_INTEGER_dup)}
      ASN1_INTEGER_dup := _ASN1_INTEGER_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_INTEGER_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_INTEGER_dup');
    {$ifend}
  end;
  
  ASN1_INTEGER_cmp := LoadLibFunction(ADllHandle, ASN1_INTEGER_cmp_procname);
  FuncLoadError := not assigned(ASN1_INTEGER_cmp);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_INTEGER_cmp_allownil)}
    ASN1_INTEGER_cmp := ERR_ASN1_INTEGER_cmp;
    {$ifend}
    {$if declared(ASN1_INTEGER_cmp_introduced)}
    if LibVersion < ASN1_INTEGER_cmp_introduced then
    begin
      {$if declared(FC_ASN1_INTEGER_cmp)}
      ASN1_INTEGER_cmp := FC_ASN1_INTEGER_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_INTEGER_cmp_removed)}
    if ASN1_INTEGER_cmp_removed <= LibVersion then
    begin
      {$if declared(_ASN1_INTEGER_cmp)}
      ASN1_INTEGER_cmp := _ASN1_INTEGER_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_INTEGER_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_INTEGER_cmp');
    {$ifend}
  end;
  
  ASN1_ENUMERATED_new := LoadLibFunction(ADllHandle, ASN1_ENUMERATED_new_procname);
  FuncLoadError := not assigned(ASN1_ENUMERATED_new);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_ENUMERATED_new_allownil)}
    ASN1_ENUMERATED_new := ERR_ASN1_ENUMERATED_new;
    {$ifend}
    {$if declared(ASN1_ENUMERATED_new_introduced)}
    if LibVersion < ASN1_ENUMERATED_new_introduced then
    begin
      {$if declared(FC_ASN1_ENUMERATED_new)}
      ASN1_ENUMERATED_new := FC_ASN1_ENUMERATED_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_ENUMERATED_new_removed)}
    if ASN1_ENUMERATED_new_removed <= LibVersion then
    begin
      {$if declared(_ASN1_ENUMERATED_new)}
      ASN1_ENUMERATED_new := _ASN1_ENUMERATED_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_ENUMERATED_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_ENUMERATED_new');
    {$ifend}
  end;
  
  ASN1_ENUMERATED_free := LoadLibFunction(ADllHandle, ASN1_ENUMERATED_free_procname);
  FuncLoadError := not assigned(ASN1_ENUMERATED_free);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_ENUMERATED_free_allownil)}
    ASN1_ENUMERATED_free := ERR_ASN1_ENUMERATED_free;
    {$ifend}
    {$if declared(ASN1_ENUMERATED_free_introduced)}
    if LibVersion < ASN1_ENUMERATED_free_introduced then
    begin
      {$if declared(FC_ASN1_ENUMERATED_free)}
      ASN1_ENUMERATED_free := FC_ASN1_ENUMERATED_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_ENUMERATED_free_removed)}
    if ASN1_ENUMERATED_free_removed <= LibVersion then
    begin
      {$if declared(_ASN1_ENUMERATED_free)}
      ASN1_ENUMERATED_free := _ASN1_ENUMERATED_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_ENUMERATED_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_ENUMERATED_free');
    {$ifend}
  end;
  
  d2i_ASN1_ENUMERATED := LoadLibFunction(ADllHandle, d2i_ASN1_ENUMERATED_procname);
  FuncLoadError := not assigned(d2i_ASN1_ENUMERATED);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ASN1_ENUMERATED_allownil)}
    d2i_ASN1_ENUMERATED := ERR_d2i_ASN1_ENUMERATED;
    {$ifend}
    {$if declared(d2i_ASN1_ENUMERATED_introduced)}
    if LibVersion < d2i_ASN1_ENUMERATED_introduced then
    begin
      {$if declared(FC_d2i_ASN1_ENUMERATED)}
      d2i_ASN1_ENUMERATED := FC_d2i_ASN1_ENUMERATED;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ASN1_ENUMERATED_removed)}
    if d2i_ASN1_ENUMERATED_removed <= LibVersion then
    begin
      {$if declared(_d2i_ASN1_ENUMERATED)}
      d2i_ASN1_ENUMERATED := _d2i_ASN1_ENUMERATED;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ASN1_ENUMERATED_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ASN1_ENUMERATED');
    {$ifend}
  end;
  
  i2d_ASN1_ENUMERATED := LoadLibFunction(ADllHandle, i2d_ASN1_ENUMERATED_procname);
  FuncLoadError := not assigned(i2d_ASN1_ENUMERATED);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ASN1_ENUMERATED_allownil)}
    i2d_ASN1_ENUMERATED := ERR_i2d_ASN1_ENUMERATED;
    {$ifend}
    {$if declared(i2d_ASN1_ENUMERATED_introduced)}
    if LibVersion < i2d_ASN1_ENUMERATED_introduced then
    begin
      {$if declared(FC_i2d_ASN1_ENUMERATED)}
      i2d_ASN1_ENUMERATED := FC_i2d_ASN1_ENUMERATED;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ASN1_ENUMERATED_removed)}
    if i2d_ASN1_ENUMERATED_removed <= LibVersion then
    begin
      {$if declared(_i2d_ASN1_ENUMERATED)}
      i2d_ASN1_ENUMERATED := _i2d_ASN1_ENUMERATED;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ASN1_ENUMERATED_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ASN1_ENUMERATED');
    {$ifend}
  end;
  
  ASN1_ENUMERATED_it := LoadLibFunction(ADllHandle, ASN1_ENUMERATED_it_procname);
  FuncLoadError := not assigned(ASN1_ENUMERATED_it);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_ENUMERATED_it_allownil)}
    ASN1_ENUMERATED_it := ERR_ASN1_ENUMERATED_it;
    {$ifend}
    {$if declared(ASN1_ENUMERATED_it_introduced)}
    if LibVersion < ASN1_ENUMERATED_it_introduced then
    begin
      {$if declared(FC_ASN1_ENUMERATED_it)}
      ASN1_ENUMERATED_it := FC_ASN1_ENUMERATED_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_ENUMERATED_it_removed)}
    if ASN1_ENUMERATED_it_removed <= LibVersion then
    begin
      {$if declared(_ASN1_ENUMERATED_it)}
      ASN1_ENUMERATED_it := _ASN1_ENUMERATED_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_ENUMERATED_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_ENUMERATED_it');
    {$ifend}
  end;
  
  ASN1_UTCTIME_check := LoadLibFunction(ADllHandle, ASN1_UTCTIME_check_procname);
  FuncLoadError := not assigned(ASN1_UTCTIME_check);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_UTCTIME_check_allownil)}
    ASN1_UTCTIME_check := ERR_ASN1_UTCTIME_check;
    {$ifend}
    {$if declared(ASN1_UTCTIME_check_introduced)}
    if LibVersion < ASN1_UTCTIME_check_introduced then
    begin
      {$if declared(FC_ASN1_UTCTIME_check)}
      ASN1_UTCTIME_check := FC_ASN1_UTCTIME_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_UTCTIME_check_removed)}
    if ASN1_UTCTIME_check_removed <= LibVersion then
    begin
      {$if declared(_ASN1_UTCTIME_check)}
      ASN1_UTCTIME_check := _ASN1_UTCTIME_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_UTCTIME_check_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_UTCTIME_check');
    {$ifend}
  end;
  
  ASN1_UTCTIME_set := LoadLibFunction(ADllHandle, ASN1_UTCTIME_set_procname);
  FuncLoadError := not assigned(ASN1_UTCTIME_set);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_UTCTIME_set_allownil)}
    ASN1_UTCTIME_set := ERR_ASN1_UTCTIME_set;
    {$ifend}
    {$if declared(ASN1_UTCTIME_set_introduced)}
    if LibVersion < ASN1_UTCTIME_set_introduced then
    begin
      {$if declared(FC_ASN1_UTCTIME_set)}
      ASN1_UTCTIME_set := FC_ASN1_UTCTIME_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_UTCTIME_set_removed)}
    if ASN1_UTCTIME_set_removed <= LibVersion then
    begin
      {$if declared(_ASN1_UTCTIME_set)}
      ASN1_UTCTIME_set := _ASN1_UTCTIME_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_UTCTIME_set_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_UTCTIME_set');
    {$ifend}
  end;
  
  ASN1_UTCTIME_adj := LoadLibFunction(ADllHandle, ASN1_UTCTIME_adj_procname);
  FuncLoadError := not assigned(ASN1_UTCTIME_adj);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_UTCTIME_adj_allownil)}
    ASN1_UTCTIME_adj := ERR_ASN1_UTCTIME_adj;
    {$ifend}
    {$if declared(ASN1_UTCTIME_adj_introduced)}
    if LibVersion < ASN1_UTCTIME_adj_introduced then
    begin
      {$if declared(FC_ASN1_UTCTIME_adj)}
      ASN1_UTCTIME_adj := FC_ASN1_UTCTIME_adj;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_UTCTIME_adj_removed)}
    if ASN1_UTCTIME_adj_removed <= LibVersion then
    begin
      {$if declared(_ASN1_UTCTIME_adj)}
      ASN1_UTCTIME_adj := _ASN1_UTCTIME_adj;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_UTCTIME_adj_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_UTCTIME_adj');
    {$ifend}
  end;
  
  ASN1_UTCTIME_set_string := LoadLibFunction(ADllHandle, ASN1_UTCTIME_set_string_procname);
  FuncLoadError := not assigned(ASN1_UTCTIME_set_string);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_UTCTIME_set_string_allownil)}
    ASN1_UTCTIME_set_string := ERR_ASN1_UTCTIME_set_string;
    {$ifend}
    {$if declared(ASN1_UTCTIME_set_string_introduced)}
    if LibVersion < ASN1_UTCTIME_set_string_introduced then
    begin
      {$if declared(FC_ASN1_UTCTIME_set_string)}
      ASN1_UTCTIME_set_string := FC_ASN1_UTCTIME_set_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_UTCTIME_set_string_removed)}
    if ASN1_UTCTIME_set_string_removed <= LibVersion then
    begin
      {$if declared(_ASN1_UTCTIME_set_string)}
      ASN1_UTCTIME_set_string := _ASN1_UTCTIME_set_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_UTCTIME_set_string_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_UTCTIME_set_string');
    {$ifend}
  end;
  
  ASN1_UTCTIME_cmp_time_t := LoadLibFunction(ADllHandle, ASN1_UTCTIME_cmp_time_t_procname);
  FuncLoadError := not assigned(ASN1_UTCTIME_cmp_time_t);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_UTCTIME_cmp_time_t_allownil)}
    ASN1_UTCTIME_cmp_time_t := ERR_ASN1_UTCTIME_cmp_time_t;
    {$ifend}
    {$if declared(ASN1_UTCTIME_cmp_time_t_introduced)}
    if LibVersion < ASN1_UTCTIME_cmp_time_t_introduced then
    begin
      {$if declared(FC_ASN1_UTCTIME_cmp_time_t)}
      ASN1_UTCTIME_cmp_time_t := FC_ASN1_UTCTIME_cmp_time_t;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_UTCTIME_cmp_time_t_removed)}
    if ASN1_UTCTIME_cmp_time_t_removed <= LibVersion then
    begin
      {$if declared(_ASN1_UTCTIME_cmp_time_t)}
      ASN1_UTCTIME_cmp_time_t := _ASN1_UTCTIME_cmp_time_t;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_UTCTIME_cmp_time_t_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_UTCTIME_cmp_time_t');
    {$ifend}
  end;
  
  ASN1_GENERALIZEDTIME_check := LoadLibFunction(ADllHandle, ASN1_GENERALIZEDTIME_check_procname);
  FuncLoadError := not assigned(ASN1_GENERALIZEDTIME_check);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_GENERALIZEDTIME_check_allownil)}
    ASN1_GENERALIZEDTIME_check := ERR_ASN1_GENERALIZEDTIME_check;
    {$ifend}
    {$if declared(ASN1_GENERALIZEDTIME_check_introduced)}
    if LibVersion < ASN1_GENERALIZEDTIME_check_introduced then
    begin
      {$if declared(FC_ASN1_GENERALIZEDTIME_check)}
      ASN1_GENERALIZEDTIME_check := FC_ASN1_GENERALIZEDTIME_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_GENERALIZEDTIME_check_removed)}
    if ASN1_GENERALIZEDTIME_check_removed <= LibVersion then
    begin
      {$if declared(_ASN1_GENERALIZEDTIME_check)}
      ASN1_GENERALIZEDTIME_check := _ASN1_GENERALIZEDTIME_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_GENERALIZEDTIME_check_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_GENERALIZEDTIME_check');
    {$ifend}
  end;
  
  ASN1_GENERALIZEDTIME_set := LoadLibFunction(ADllHandle, ASN1_GENERALIZEDTIME_set_procname);
  FuncLoadError := not assigned(ASN1_GENERALIZEDTIME_set);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_GENERALIZEDTIME_set_allownil)}
    ASN1_GENERALIZEDTIME_set := ERR_ASN1_GENERALIZEDTIME_set;
    {$ifend}
    {$if declared(ASN1_GENERALIZEDTIME_set_introduced)}
    if LibVersion < ASN1_GENERALIZEDTIME_set_introduced then
    begin
      {$if declared(FC_ASN1_GENERALIZEDTIME_set)}
      ASN1_GENERALIZEDTIME_set := FC_ASN1_GENERALIZEDTIME_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_GENERALIZEDTIME_set_removed)}
    if ASN1_GENERALIZEDTIME_set_removed <= LibVersion then
    begin
      {$if declared(_ASN1_GENERALIZEDTIME_set)}
      ASN1_GENERALIZEDTIME_set := _ASN1_GENERALIZEDTIME_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_GENERALIZEDTIME_set_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_GENERALIZEDTIME_set');
    {$ifend}
  end;
  
  ASN1_GENERALIZEDTIME_adj := LoadLibFunction(ADllHandle, ASN1_GENERALIZEDTIME_adj_procname);
  FuncLoadError := not assigned(ASN1_GENERALIZEDTIME_adj);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_GENERALIZEDTIME_adj_allownil)}
    ASN1_GENERALIZEDTIME_adj := ERR_ASN1_GENERALIZEDTIME_adj;
    {$ifend}
    {$if declared(ASN1_GENERALIZEDTIME_adj_introduced)}
    if LibVersion < ASN1_GENERALIZEDTIME_adj_introduced then
    begin
      {$if declared(FC_ASN1_GENERALIZEDTIME_adj)}
      ASN1_GENERALIZEDTIME_adj := FC_ASN1_GENERALIZEDTIME_adj;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_GENERALIZEDTIME_adj_removed)}
    if ASN1_GENERALIZEDTIME_adj_removed <= LibVersion then
    begin
      {$if declared(_ASN1_GENERALIZEDTIME_adj)}
      ASN1_GENERALIZEDTIME_adj := _ASN1_GENERALIZEDTIME_adj;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_GENERALIZEDTIME_adj_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_GENERALIZEDTIME_adj');
    {$ifend}
  end;
  
  ASN1_GENERALIZEDTIME_set_string := LoadLibFunction(ADllHandle, ASN1_GENERALIZEDTIME_set_string_procname);
  FuncLoadError := not assigned(ASN1_GENERALIZEDTIME_set_string);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_GENERALIZEDTIME_set_string_allownil)}
    ASN1_GENERALIZEDTIME_set_string := ERR_ASN1_GENERALIZEDTIME_set_string;
    {$ifend}
    {$if declared(ASN1_GENERALIZEDTIME_set_string_introduced)}
    if LibVersion < ASN1_GENERALIZEDTIME_set_string_introduced then
    begin
      {$if declared(FC_ASN1_GENERALIZEDTIME_set_string)}
      ASN1_GENERALIZEDTIME_set_string := FC_ASN1_GENERALIZEDTIME_set_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_GENERALIZEDTIME_set_string_removed)}
    if ASN1_GENERALIZEDTIME_set_string_removed <= LibVersion then
    begin
      {$if declared(_ASN1_GENERALIZEDTIME_set_string)}
      ASN1_GENERALIZEDTIME_set_string := _ASN1_GENERALIZEDTIME_set_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_GENERALIZEDTIME_set_string_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_GENERALIZEDTIME_set_string');
    {$ifend}
  end;
  
  ASN1_TIME_diff := LoadLibFunction(ADllHandle, ASN1_TIME_diff_procname);
  FuncLoadError := not assigned(ASN1_TIME_diff);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TIME_diff_allownil)}
    ASN1_TIME_diff := ERR_ASN1_TIME_diff;
    {$ifend}
    {$if declared(ASN1_TIME_diff_introduced)}
    if LibVersion < ASN1_TIME_diff_introduced then
    begin
      {$if declared(FC_ASN1_TIME_diff)}
      ASN1_TIME_diff := FC_ASN1_TIME_diff;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TIME_diff_removed)}
    if ASN1_TIME_diff_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TIME_diff)}
      ASN1_TIME_diff := _ASN1_TIME_diff;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TIME_diff_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TIME_diff');
    {$ifend}
  end;
  
  ASN1_OCTET_STRING_new := LoadLibFunction(ADllHandle, ASN1_OCTET_STRING_new_procname);
  FuncLoadError := not assigned(ASN1_OCTET_STRING_new);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_OCTET_STRING_new_allownil)}
    ASN1_OCTET_STRING_new := ERR_ASN1_OCTET_STRING_new;
    {$ifend}
    {$if declared(ASN1_OCTET_STRING_new_introduced)}
    if LibVersion < ASN1_OCTET_STRING_new_introduced then
    begin
      {$if declared(FC_ASN1_OCTET_STRING_new)}
      ASN1_OCTET_STRING_new := FC_ASN1_OCTET_STRING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_OCTET_STRING_new_removed)}
    if ASN1_OCTET_STRING_new_removed <= LibVersion then
    begin
      {$if declared(_ASN1_OCTET_STRING_new)}
      ASN1_OCTET_STRING_new := _ASN1_OCTET_STRING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_OCTET_STRING_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_OCTET_STRING_new');
    {$ifend}
  end;
  
  ASN1_OCTET_STRING_free := LoadLibFunction(ADllHandle, ASN1_OCTET_STRING_free_procname);
  FuncLoadError := not assigned(ASN1_OCTET_STRING_free);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_OCTET_STRING_free_allownil)}
    ASN1_OCTET_STRING_free := ERR_ASN1_OCTET_STRING_free;
    {$ifend}
    {$if declared(ASN1_OCTET_STRING_free_introduced)}
    if LibVersion < ASN1_OCTET_STRING_free_introduced then
    begin
      {$if declared(FC_ASN1_OCTET_STRING_free)}
      ASN1_OCTET_STRING_free := FC_ASN1_OCTET_STRING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_OCTET_STRING_free_removed)}
    if ASN1_OCTET_STRING_free_removed <= LibVersion then
    begin
      {$if declared(_ASN1_OCTET_STRING_free)}
      ASN1_OCTET_STRING_free := _ASN1_OCTET_STRING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_OCTET_STRING_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_OCTET_STRING_free');
    {$ifend}
  end;
  
  d2i_ASN1_OCTET_STRING := LoadLibFunction(ADllHandle, d2i_ASN1_OCTET_STRING_procname);
  FuncLoadError := not assigned(d2i_ASN1_OCTET_STRING);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ASN1_OCTET_STRING_allownil)}
    d2i_ASN1_OCTET_STRING := ERR_d2i_ASN1_OCTET_STRING;
    {$ifend}
    {$if declared(d2i_ASN1_OCTET_STRING_introduced)}
    if LibVersion < d2i_ASN1_OCTET_STRING_introduced then
    begin
      {$if declared(FC_d2i_ASN1_OCTET_STRING)}
      d2i_ASN1_OCTET_STRING := FC_d2i_ASN1_OCTET_STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ASN1_OCTET_STRING_removed)}
    if d2i_ASN1_OCTET_STRING_removed <= LibVersion then
    begin
      {$if declared(_d2i_ASN1_OCTET_STRING)}
      d2i_ASN1_OCTET_STRING := _d2i_ASN1_OCTET_STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ASN1_OCTET_STRING_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ASN1_OCTET_STRING');
    {$ifend}
  end;
  
  i2d_ASN1_OCTET_STRING := LoadLibFunction(ADllHandle, i2d_ASN1_OCTET_STRING_procname);
  FuncLoadError := not assigned(i2d_ASN1_OCTET_STRING);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ASN1_OCTET_STRING_allownil)}
    i2d_ASN1_OCTET_STRING := ERR_i2d_ASN1_OCTET_STRING;
    {$ifend}
    {$if declared(i2d_ASN1_OCTET_STRING_introduced)}
    if LibVersion < i2d_ASN1_OCTET_STRING_introduced then
    begin
      {$if declared(FC_i2d_ASN1_OCTET_STRING)}
      i2d_ASN1_OCTET_STRING := FC_i2d_ASN1_OCTET_STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ASN1_OCTET_STRING_removed)}
    if i2d_ASN1_OCTET_STRING_removed <= LibVersion then
    begin
      {$if declared(_i2d_ASN1_OCTET_STRING)}
      i2d_ASN1_OCTET_STRING := _i2d_ASN1_OCTET_STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ASN1_OCTET_STRING_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ASN1_OCTET_STRING');
    {$ifend}
  end;
  
  ASN1_OCTET_STRING_it := LoadLibFunction(ADllHandle, ASN1_OCTET_STRING_it_procname);
  FuncLoadError := not assigned(ASN1_OCTET_STRING_it);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_OCTET_STRING_it_allownil)}
    ASN1_OCTET_STRING_it := ERR_ASN1_OCTET_STRING_it;
    {$ifend}
    {$if declared(ASN1_OCTET_STRING_it_introduced)}
    if LibVersion < ASN1_OCTET_STRING_it_introduced then
    begin
      {$if declared(FC_ASN1_OCTET_STRING_it)}
      ASN1_OCTET_STRING_it := FC_ASN1_OCTET_STRING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_OCTET_STRING_it_removed)}
    if ASN1_OCTET_STRING_it_removed <= LibVersion then
    begin
      {$if declared(_ASN1_OCTET_STRING_it)}
      ASN1_OCTET_STRING_it := _ASN1_OCTET_STRING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_OCTET_STRING_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_OCTET_STRING_it');
    {$ifend}
  end;
  
  ASN1_OCTET_STRING_dup := LoadLibFunction(ADllHandle, ASN1_OCTET_STRING_dup_procname);
  FuncLoadError := not assigned(ASN1_OCTET_STRING_dup);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_OCTET_STRING_dup_allownil)}
    ASN1_OCTET_STRING_dup := ERR_ASN1_OCTET_STRING_dup;
    {$ifend}
    {$if declared(ASN1_OCTET_STRING_dup_introduced)}
    if LibVersion < ASN1_OCTET_STRING_dup_introduced then
    begin
      {$if declared(FC_ASN1_OCTET_STRING_dup)}
      ASN1_OCTET_STRING_dup := FC_ASN1_OCTET_STRING_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_OCTET_STRING_dup_removed)}
    if ASN1_OCTET_STRING_dup_removed <= LibVersion then
    begin
      {$if declared(_ASN1_OCTET_STRING_dup)}
      ASN1_OCTET_STRING_dup := _ASN1_OCTET_STRING_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_OCTET_STRING_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_OCTET_STRING_dup');
    {$ifend}
  end;
  
  ASN1_OCTET_STRING_cmp := LoadLibFunction(ADllHandle, ASN1_OCTET_STRING_cmp_procname);
  FuncLoadError := not assigned(ASN1_OCTET_STRING_cmp);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_OCTET_STRING_cmp_allownil)}
    ASN1_OCTET_STRING_cmp := ERR_ASN1_OCTET_STRING_cmp;
    {$ifend}
    {$if declared(ASN1_OCTET_STRING_cmp_introduced)}
    if LibVersion < ASN1_OCTET_STRING_cmp_introduced then
    begin
      {$if declared(FC_ASN1_OCTET_STRING_cmp)}
      ASN1_OCTET_STRING_cmp := FC_ASN1_OCTET_STRING_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_OCTET_STRING_cmp_removed)}
    if ASN1_OCTET_STRING_cmp_removed <= LibVersion then
    begin
      {$if declared(_ASN1_OCTET_STRING_cmp)}
      ASN1_OCTET_STRING_cmp := _ASN1_OCTET_STRING_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_OCTET_STRING_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_OCTET_STRING_cmp');
    {$ifend}
  end;
  
  ASN1_OCTET_STRING_set := LoadLibFunction(ADllHandle, ASN1_OCTET_STRING_set_procname);
  FuncLoadError := not assigned(ASN1_OCTET_STRING_set);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_OCTET_STRING_set_allownil)}
    ASN1_OCTET_STRING_set := ERR_ASN1_OCTET_STRING_set;
    {$ifend}
    {$if declared(ASN1_OCTET_STRING_set_introduced)}
    if LibVersion < ASN1_OCTET_STRING_set_introduced then
    begin
      {$if declared(FC_ASN1_OCTET_STRING_set)}
      ASN1_OCTET_STRING_set := FC_ASN1_OCTET_STRING_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_OCTET_STRING_set_removed)}
    if ASN1_OCTET_STRING_set_removed <= LibVersion then
    begin
      {$if declared(_ASN1_OCTET_STRING_set)}
      ASN1_OCTET_STRING_set := _ASN1_OCTET_STRING_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_OCTET_STRING_set_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_OCTET_STRING_set');
    {$ifend}
  end;
  
  ASN1_VISIBLESTRING_new := LoadLibFunction(ADllHandle, ASN1_VISIBLESTRING_new_procname);
  FuncLoadError := not assigned(ASN1_VISIBLESTRING_new);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_VISIBLESTRING_new_allownil)}
    ASN1_VISIBLESTRING_new := ERR_ASN1_VISIBLESTRING_new;
    {$ifend}
    {$if declared(ASN1_VISIBLESTRING_new_introduced)}
    if LibVersion < ASN1_VISIBLESTRING_new_introduced then
    begin
      {$if declared(FC_ASN1_VISIBLESTRING_new)}
      ASN1_VISIBLESTRING_new := FC_ASN1_VISIBLESTRING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_VISIBLESTRING_new_removed)}
    if ASN1_VISIBLESTRING_new_removed <= LibVersion then
    begin
      {$if declared(_ASN1_VISIBLESTRING_new)}
      ASN1_VISIBLESTRING_new := _ASN1_VISIBLESTRING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_VISIBLESTRING_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_VISIBLESTRING_new');
    {$ifend}
  end;
  
  ASN1_VISIBLESTRING_free := LoadLibFunction(ADllHandle, ASN1_VISIBLESTRING_free_procname);
  FuncLoadError := not assigned(ASN1_VISIBLESTRING_free);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_VISIBLESTRING_free_allownil)}
    ASN1_VISIBLESTRING_free := ERR_ASN1_VISIBLESTRING_free;
    {$ifend}
    {$if declared(ASN1_VISIBLESTRING_free_introduced)}
    if LibVersion < ASN1_VISIBLESTRING_free_introduced then
    begin
      {$if declared(FC_ASN1_VISIBLESTRING_free)}
      ASN1_VISIBLESTRING_free := FC_ASN1_VISIBLESTRING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_VISIBLESTRING_free_removed)}
    if ASN1_VISIBLESTRING_free_removed <= LibVersion then
    begin
      {$if declared(_ASN1_VISIBLESTRING_free)}
      ASN1_VISIBLESTRING_free := _ASN1_VISIBLESTRING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_VISIBLESTRING_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_VISIBLESTRING_free');
    {$ifend}
  end;
  
  d2i_ASN1_VISIBLESTRING := LoadLibFunction(ADllHandle, d2i_ASN1_VISIBLESTRING_procname);
  FuncLoadError := not assigned(d2i_ASN1_VISIBLESTRING);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ASN1_VISIBLESTRING_allownil)}
    d2i_ASN1_VISIBLESTRING := ERR_d2i_ASN1_VISIBLESTRING;
    {$ifend}
    {$if declared(d2i_ASN1_VISIBLESTRING_introduced)}
    if LibVersion < d2i_ASN1_VISIBLESTRING_introduced then
    begin
      {$if declared(FC_d2i_ASN1_VISIBLESTRING)}
      d2i_ASN1_VISIBLESTRING := FC_d2i_ASN1_VISIBLESTRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ASN1_VISIBLESTRING_removed)}
    if d2i_ASN1_VISIBLESTRING_removed <= LibVersion then
    begin
      {$if declared(_d2i_ASN1_VISIBLESTRING)}
      d2i_ASN1_VISIBLESTRING := _d2i_ASN1_VISIBLESTRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ASN1_VISIBLESTRING_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ASN1_VISIBLESTRING');
    {$ifend}
  end;
  
  i2d_ASN1_VISIBLESTRING := LoadLibFunction(ADllHandle, i2d_ASN1_VISIBLESTRING_procname);
  FuncLoadError := not assigned(i2d_ASN1_VISIBLESTRING);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ASN1_VISIBLESTRING_allownil)}
    i2d_ASN1_VISIBLESTRING := ERR_i2d_ASN1_VISIBLESTRING;
    {$ifend}
    {$if declared(i2d_ASN1_VISIBLESTRING_introduced)}
    if LibVersion < i2d_ASN1_VISIBLESTRING_introduced then
    begin
      {$if declared(FC_i2d_ASN1_VISIBLESTRING)}
      i2d_ASN1_VISIBLESTRING := FC_i2d_ASN1_VISIBLESTRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ASN1_VISIBLESTRING_removed)}
    if i2d_ASN1_VISIBLESTRING_removed <= LibVersion then
    begin
      {$if declared(_i2d_ASN1_VISIBLESTRING)}
      i2d_ASN1_VISIBLESTRING := _i2d_ASN1_VISIBLESTRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ASN1_VISIBLESTRING_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ASN1_VISIBLESTRING');
    {$ifend}
  end;
  
  ASN1_VISIBLESTRING_it := LoadLibFunction(ADllHandle, ASN1_VISIBLESTRING_it_procname);
  FuncLoadError := not assigned(ASN1_VISIBLESTRING_it);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_VISIBLESTRING_it_allownil)}
    ASN1_VISIBLESTRING_it := ERR_ASN1_VISIBLESTRING_it;
    {$ifend}
    {$if declared(ASN1_VISIBLESTRING_it_introduced)}
    if LibVersion < ASN1_VISIBLESTRING_it_introduced then
    begin
      {$if declared(FC_ASN1_VISIBLESTRING_it)}
      ASN1_VISIBLESTRING_it := FC_ASN1_VISIBLESTRING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_VISIBLESTRING_it_removed)}
    if ASN1_VISIBLESTRING_it_removed <= LibVersion then
    begin
      {$if declared(_ASN1_VISIBLESTRING_it)}
      ASN1_VISIBLESTRING_it := _ASN1_VISIBLESTRING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_VISIBLESTRING_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_VISIBLESTRING_it');
    {$ifend}
  end;
  
  ASN1_UNIVERSALSTRING_new := LoadLibFunction(ADllHandle, ASN1_UNIVERSALSTRING_new_procname);
  FuncLoadError := not assigned(ASN1_UNIVERSALSTRING_new);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_UNIVERSALSTRING_new_allownil)}
    ASN1_UNIVERSALSTRING_new := ERR_ASN1_UNIVERSALSTRING_new;
    {$ifend}
    {$if declared(ASN1_UNIVERSALSTRING_new_introduced)}
    if LibVersion < ASN1_UNIVERSALSTRING_new_introduced then
    begin
      {$if declared(FC_ASN1_UNIVERSALSTRING_new)}
      ASN1_UNIVERSALSTRING_new := FC_ASN1_UNIVERSALSTRING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_UNIVERSALSTRING_new_removed)}
    if ASN1_UNIVERSALSTRING_new_removed <= LibVersion then
    begin
      {$if declared(_ASN1_UNIVERSALSTRING_new)}
      ASN1_UNIVERSALSTRING_new := _ASN1_UNIVERSALSTRING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_UNIVERSALSTRING_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_UNIVERSALSTRING_new');
    {$ifend}
  end;
  
  ASN1_UNIVERSALSTRING_free := LoadLibFunction(ADllHandle, ASN1_UNIVERSALSTRING_free_procname);
  FuncLoadError := not assigned(ASN1_UNIVERSALSTRING_free);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_UNIVERSALSTRING_free_allownil)}
    ASN1_UNIVERSALSTRING_free := ERR_ASN1_UNIVERSALSTRING_free;
    {$ifend}
    {$if declared(ASN1_UNIVERSALSTRING_free_introduced)}
    if LibVersion < ASN1_UNIVERSALSTRING_free_introduced then
    begin
      {$if declared(FC_ASN1_UNIVERSALSTRING_free)}
      ASN1_UNIVERSALSTRING_free := FC_ASN1_UNIVERSALSTRING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_UNIVERSALSTRING_free_removed)}
    if ASN1_UNIVERSALSTRING_free_removed <= LibVersion then
    begin
      {$if declared(_ASN1_UNIVERSALSTRING_free)}
      ASN1_UNIVERSALSTRING_free := _ASN1_UNIVERSALSTRING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_UNIVERSALSTRING_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_UNIVERSALSTRING_free');
    {$ifend}
  end;
  
  d2i_ASN1_UNIVERSALSTRING := LoadLibFunction(ADllHandle, d2i_ASN1_UNIVERSALSTRING_procname);
  FuncLoadError := not assigned(d2i_ASN1_UNIVERSALSTRING);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ASN1_UNIVERSALSTRING_allownil)}
    d2i_ASN1_UNIVERSALSTRING := ERR_d2i_ASN1_UNIVERSALSTRING;
    {$ifend}
    {$if declared(d2i_ASN1_UNIVERSALSTRING_introduced)}
    if LibVersion < d2i_ASN1_UNIVERSALSTRING_introduced then
    begin
      {$if declared(FC_d2i_ASN1_UNIVERSALSTRING)}
      d2i_ASN1_UNIVERSALSTRING := FC_d2i_ASN1_UNIVERSALSTRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ASN1_UNIVERSALSTRING_removed)}
    if d2i_ASN1_UNIVERSALSTRING_removed <= LibVersion then
    begin
      {$if declared(_d2i_ASN1_UNIVERSALSTRING)}
      d2i_ASN1_UNIVERSALSTRING := _d2i_ASN1_UNIVERSALSTRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ASN1_UNIVERSALSTRING_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ASN1_UNIVERSALSTRING');
    {$ifend}
  end;
  
  i2d_ASN1_UNIVERSALSTRING := LoadLibFunction(ADllHandle, i2d_ASN1_UNIVERSALSTRING_procname);
  FuncLoadError := not assigned(i2d_ASN1_UNIVERSALSTRING);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ASN1_UNIVERSALSTRING_allownil)}
    i2d_ASN1_UNIVERSALSTRING := ERR_i2d_ASN1_UNIVERSALSTRING;
    {$ifend}
    {$if declared(i2d_ASN1_UNIVERSALSTRING_introduced)}
    if LibVersion < i2d_ASN1_UNIVERSALSTRING_introduced then
    begin
      {$if declared(FC_i2d_ASN1_UNIVERSALSTRING)}
      i2d_ASN1_UNIVERSALSTRING := FC_i2d_ASN1_UNIVERSALSTRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ASN1_UNIVERSALSTRING_removed)}
    if i2d_ASN1_UNIVERSALSTRING_removed <= LibVersion then
    begin
      {$if declared(_i2d_ASN1_UNIVERSALSTRING)}
      i2d_ASN1_UNIVERSALSTRING := _i2d_ASN1_UNIVERSALSTRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ASN1_UNIVERSALSTRING_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ASN1_UNIVERSALSTRING');
    {$ifend}
  end;
  
  ASN1_UNIVERSALSTRING_it := LoadLibFunction(ADllHandle, ASN1_UNIVERSALSTRING_it_procname);
  FuncLoadError := not assigned(ASN1_UNIVERSALSTRING_it);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_UNIVERSALSTRING_it_allownil)}
    ASN1_UNIVERSALSTRING_it := ERR_ASN1_UNIVERSALSTRING_it;
    {$ifend}
    {$if declared(ASN1_UNIVERSALSTRING_it_introduced)}
    if LibVersion < ASN1_UNIVERSALSTRING_it_introduced then
    begin
      {$if declared(FC_ASN1_UNIVERSALSTRING_it)}
      ASN1_UNIVERSALSTRING_it := FC_ASN1_UNIVERSALSTRING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_UNIVERSALSTRING_it_removed)}
    if ASN1_UNIVERSALSTRING_it_removed <= LibVersion then
    begin
      {$if declared(_ASN1_UNIVERSALSTRING_it)}
      ASN1_UNIVERSALSTRING_it := _ASN1_UNIVERSALSTRING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_UNIVERSALSTRING_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_UNIVERSALSTRING_it');
    {$ifend}
  end;
  
  ASN1_UTF8STRING_new := LoadLibFunction(ADllHandle, ASN1_UTF8STRING_new_procname);
  FuncLoadError := not assigned(ASN1_UTF8STRING_new);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_UTF8STRING_new_allownil)}
    ASN1_UTF8STRING_new := ERR_ASN1_UTF8STRING_new;
    {$ifend}
    {$if declared(ASN1_UTF8STRING_new_introduced)}
    if LibVersion < ASN1_UTF8STRING_new_introduced then
    begin
      {$if declared(FC_ASN1_UTF8STRING_new)}
      ASN1_UTF8STRING_new := FC_ASN1_UTF8STRING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_UTF8STRING_new_removed)}
    if ASN1_UTF8STRING_new_removed <= LibVersion then
    begin
      {$if declared(_ASN1_UTF8STRING_new)}
      ASN1_UTF8STRING_new := _ASN1_UTF8STRING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_UTF8STRING_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_UTF8STRING_new');
    {$ifend}
  end;
  
  ASN1_UTF8STRING_free := LoadLibFunction(ADllHandle, ASN1_UTF8STRING_free_procname);
  FuncLoadError := not assigned(ASN1_UTF8STRING_free);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_UTF8STRING_free_allownil)}
    ASN1_UTF8STRING_free := ERR_ASN1_UTF8STRING_free;
    {$ifend}
    {$if declared(ASN1_UTF8STRING_free_introduced)}
    if LibVersion < ASN1_UTF8STRING_free_introduced then
    begin
      {$if declared(FC_ASN1_UTF8STRING_free)}
      ASN1_UTF8STRING_free := FC_ASN1_UTF8STRING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_UTF8STRING_free_removed)}
    if ASN1_UTF8STRING_free_removed <= LibVersion then
    begin
      {$if declared(_ASN1_UTF8STRING_free)}
      ASN1_UTF8STRING_free := _ASN1_UTF8STRING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_UTF8STRING_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_UTF8STRING_free');
    {$ifend}
  end;
  
  d2i_ASN1_UTF8STRING := LoadLibFunction(ADllHandle, d2i_ASN1_UTF8STRING_procname);
  FuncLoadError := not assigned(d2i_ASN1_UTF8STRING);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ASN1_UTF8STRING_allownil)}
    d2i_ASN1_UTF8STRING := ERR_d2i_ASN1_UTF8STRING;
    {$ifend}
    {$if declared(d2i_ASN1_UTF8STRING_introduced)}
    if LibVersion < d2i_ASN1_UTF8STRING_introduced then
    begin
      {$if declared(FC_d2i_ASN1_UTF8STRING)}
      d2i_ASN1_UTF8STRING := FC_d2i_ASN1_UTF8STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ASN1_UTF8STRING_removed)}
    if d2i_ASN1_UTF8STRING_removed <= LibVersion then
    begin
      {$if declared(_d2i_ASN1_UTF8STRING)}
      d2i_ASN1_UTF8STRING := _d2i_ASN1_UTF8STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ASN1_UTF8STRING_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ASN1_UTF8STRING');
    {$ifend}
  end;
  
  i2d_ASN1_UTF8STRING := LoadLibFunction(ADllHandle, i2d_ASN1_UTF8STRING_procname);
  FuncLoadError := not assigned(i2d_ASN1_UTF8STRING);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ASN1_UTF8STRING_allownil)}
    i2d_ASN1_UTF8STRING := ERR_i2d_ASN1_UTF8STRING;
    {$ifend}
    {$if declared(i2d_ASN1_UTF8STRING_introduced)}
    if LibVersion < i2d_ASN1_UTF8STRING_introduced then
    begin
      {$if declared(FC_i2d_ASN1_UTF8STRING)}
      i2d_ASN1_UTF8STRING := FC_i2d_ASN1_UTF8STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ASN1_UTF8STRING_removed)}
    if i2d_ASN1_UTF8STRING_removed <= LibVersion then
    begin
      {$if declared(_i2d_ASN1_UTF8STRING)}
      i2d_ASN1_UTF8STRING := _i2d_ASN1_UTF8STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ASN1_UTF8STRING_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ASN1_UTF8STRING');
    {$ifend}
  end;
  
  ASN1_UTF8STRING_it := LoadLibFunction(ADllHandle, ASN1_UTF8STRING_it_procname);
  FuncLoadError := not assigned(ASN1_UTF8STRING_it);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_UTF8STRING_it_allownil)}
    ASN1_UTF8STRING_it := ERR_ASN1_UTF8STRING_it;
    {$ifend}
    {$if declared(ASN1_UTF8STRING_it_introduced)}
    if LibVersion < ASN1_UTF8STRING_it_introduced then
    begin
      {$if declared(FC_ASN1_UTF8STRING_it)}
      ASN1_UTF8STRING_it := FC_ASN1_UTF8STRING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_UTF8STRING_it_removed)}
    if ASN1_UTF8STRING_it_removed <= LibVersion then
    begin
      {$if declared(_ASN1_UTF8STRING_it)}
      ASN1_UTF8STRING_it := _ASN1_UTF8STRING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_UTF8STRING_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_UTF8STRING_it');
    {$ifend}
  end;
  
  ASN1_NULL_new := LoadLibFunction(ADllHandle, ASN1_NULL_new_procname);
  FuncLoadError := not assigned(ASN1_NULL_new);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_NULL_new_allownil)}
    ASN1_NULL_new := ERR_ASN1_NULL_new;
    {$ifend}
    {$if declared(ASN1_NULL_new_introduced)}
    if LibVersion < ASN1_NULL_new_introduced then
    begin
      {$if declared(FC_ASN1_NULL_new)}
      ASN1_NULL_new := FC_ASN1_NULL_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_NULL_new_removed)}
    if ASN1_NULL_new_removed <= LibVersion then
    begin
      {$if declared(_ASN1_NULL_new)}
      ASN1_NULL_new := _ASN1_NULL_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_NULL_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_NULL_new');
    {$ifend}
  end;
  
  ASN1_NULL_free := LoadLibFunction(ADllHandle, ASN1_NULL_free_procname);
  FuncLoadError := not assigned(ASN1_NULL_free);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_NULL_free_allownil)}
    ASN1_NULL_free := ERR_ASN1_NULL_free;
    {$ifend}
    {$if declared(ASN1_NULL_free_introduced)}
    if LibVersion < ASN1_NULL_free_introduced then
    begin
      {$if declared(FC_ASN1_NULL_free)}
      ASN1_NULL_free := FC_ASN1_NULL_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_NULL_free_removed)}
    if ASN1_NULL_free_removed <= LibVersion then
    begin
      {$if declared(_ASN1_NULL_free)}
      ASN1_NULL_free := _ASN1_NULL_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_NULL_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_NULL_free');
    {$ifend}
  end;
  
  d2i_ASN1_NULL := LoadLibFunction(ADllHandle, d2i_ASN1_NULL_procname);
  FuncLoadError := not assigned(d2i_ASN1_NULL);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ASN1_NULL_allownil)}
    d2i_ASN1_NULL := ERR_d2i_ASN1_NULL;
    {$ifend}
    {$if declared(d2i_ASN1_NULL_introduced)}
    if LibVersion < d2i_ASN1_NULL_introduced then
    begin
      {$if declared(FC_d2i_ASN1_NULL)}
      d2i_ASN1_NULL := FC_d2i_ASN1_NULL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ASN1_NULL_removed)}
    if d2i_ASN1_NULL_removed <= LibVersion then
    begin
      {$if declared(_d2i_ASN1_NULL)}
      d2i_ASN1_NULL := _d2i_ASN1_NULL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ASN1_NULL_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ASN1_NULL');
    {$ifend}
  end;
  
  i2d_ASN1_NULL := LoadLibFunction(ADllHandle, i2d_ASN1_NULL_procname);
  FuncLoadError := not assigned(i2d_ASN1_NULL);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ASN1_NULL_allownil)}
    i2d_ASN1_NULL := ERR_i2d_ASN1_NULL;
    {$ifend}
    {$if declared(i2d_ASN1_NULL_introduced)}
    if LibVersion < i2d_ASN1_NULL_introduced then
    begin
      {$if declared(FC_i2d_ASN1_NULL)}
      i2d_ASN1_NULL := FC_i2d_ASN1_NULL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ASN1_NULL_removed)}
    if i2d_ASN1_NULL_removed <= LibVersion then
    begin
      {$if declared(_i2d_ASN1_NULL)}
      i2d_ASN1_NULL := _i2d_ASN1_NULL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ASN1_NULL_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ASN1_NULL');
    {$ifend}
  end;
  
  ASN1_NULL_it := LoadLibFunction(ADllHandle, ASN1_NULL_it_procname);
  FuncLoadError := not assigned(ASN1_NULL_it);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_NULL_it_allownil)}
    ASN1_NULL_it := ERR_ASN1_NULL_it;
    {$ifend}
    {$if declared(ASN1_NULL_it_introduced)}
    if LibVersion < ASN1_NULL_it_introduced then
    begin
      {$if declared(FC_ASN1_NULL_it)}
      ASN1_NULL_it := FC_ASN1_NULL_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_NULL_it_removed)}
    if ASN1_NULL_it_removed <= LibVersion then
    begin
      {$if declared(_ASN1_NULL_it)}
      ASN1_NULL_it := _ASN1_NULL_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_NULL_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_NULL_it');
    {$ifend}
  end;
  
  ASN1_BMPSTRING_new := LoadLibFunction(ADllHandle, ASN1_BMPSTRING_new_procname);
  FuncLoadError := not assigned(ASN1_BMPSTRING_new);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_BMPSTRING_new_allownil)}
    ASN1_BMPSTRING_new := ERR_ASN1_BMPSTRING_new;
    {$ifend}
    {$if declared(ASN1_BMPSTRING_new_introduced)}
    if LibVersion < ASN1_BMPSTRING_new_introduced then
    begin
      {$if declared(FC_ASN1_BMPSTRING_new)}
      ASN1_BMPSTRING_new := FC_ASN1_BMPSTRING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_BMPSTRING_new_removed)}
    if ASN1_BMPSTRING_new_removed <= LibVersion then
    begin
      {$if declared(_ASN1_BMPSTRING_new)}
      ASN1_BMPSTRING_new := _ASN1_BMPSTRING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_BMPSTRING_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_BMPSTRING_new');
    {$ifend}
  end;
  
  ASN1_BMPSTRING_free := LoadLibFunction(ADllHandle, ASN1_BMPSTRING_free_procname);
  FuncLoadError := not assigned(ASN1_BMPSTRING_free);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_BMPSTRING_free_allownil)}
    ASN1_BMPSTRING_free := ERR_ASN1_BMPSTRING_free;
    {$ifend}
    {$if declared(ASN1_BMPSTRING_free_introduced)}
    if LibVersion < ASN1_BMPSTRING_free_introduced then
    begin
      {$if declared(FC_ASN1_BMPSTRING_free)}
      ASN1_BMPSTRING_free := FC_ASN1_BMPSTRING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_BMPSTRING_free_removed)}
    if ASN1_BMPSTRING_free_removed <= LibVersion then
    begin
      {$if declared(_ASN1_BMPSTRING_free)}
      ASN1_BMPSTRING_free := _ASN1_BMPSTRING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_BMPSTRING_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_BMPSTRING_free');
    {$ifend}
  end;
  
  d2i_ASN1_BMPSTRING := LoadLibFunction(ADllHandle, d2i_ASN1_BMPSTRING_procname);
  FuncLoadError := not assigned(d2i_ASN1_BMPSTRING);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ASN1_BMPSTRING_allownil)}
    d2i_ASN1_BMPSTRING := ERR_d2i_ASN1_BMPSTRING;
    {$ifend}
    {$if declared(d2i_ASN1_BMPSTRING_introduced)}
    if LibVersion < d2i_ASN1_BMPSTRING_introduced then
    begin
      {$if declared(FC_d2i_ASN1_BMPSTRING)}
      d2i_ASN1_BMPSTRING := FC_d2i_ASN1_BMPSTRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ASN1_BMPSTRING_removed)}
    if d2i_ASN1_BMPSTRING_removed <= LibVersion then
    begin
      {$if declared(_d2i_ASN1_BMPSTRING)}
      d2i_ASN1_BMPSTRING := _d2i_ASN1_BMPSTRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ASN1_BMPSTRING_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ASN1_BMPSTRING');
    {$ifend}
  end;
  
  i2d_ASN1_BMPSTRING := LoadLibFunction(ADllHandle, i2d_ASN1_BMPSTRING_procname);
  FuncLoadError := not assigned(i2d_ASN1_BMPSTRING);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ASN1_BMPSTRING_allownil)}
    i2d_ASN1_BMPSTRING := ERR_i2d_ASN1_BMPSTRING;
    {$ifend}
    {$if declared(i2d_ASN1_BMPSTRING_introduced)}
    if LibVersion < i2d_ASN1_BMPSTRING_introduced then
    begin
      {$if declared(FC_i2d_ASN1_BMPSTRING)}
      i2d_ASN1_BMPSTRING := FC_i2d_ASN1_BMPSTRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ASN1_BMPSTRING_removed)}
    if i2d_ASN1_BMPSTRING_removed <= LibVersion then
    begin
      {$if declared(_i2d_ASN1_BMPSTRING)}
      i2d_ASN1_BMPSTRING := _i2d_ASN1_BMPSTRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ASN1_BMPSTRING_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ASN1_BMPSTRING');
    {$ifend}
  end;
  
  ASN1_BMPSTRING_it := LoadLibFunction(ADllHandle, ASN1_BMPSTRING_it_procname);
  FuncLoadError := not assigned(ASN1_BMPSTRING_it);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_BMPSTRING_it_allownil)}
    ASN1_BMPSTRING_it := ERR_ASN1_BMPSTRING_it;
    {$ifend}
    {$if declared(ASN1_BMPSTRING_it_introduced)}
    if LibVersion < ASN1_BMPSTRING_it_introduced then
    begin
      {$if declared(FC_ASN1_BMPSTRING_it)}
      ASN1_BMPSTRING_it := FC_ASN1_BMPSTRING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_BMPSTRING_it_removed)}
    if ASN1_BMPSTRING_it_removed <= LibVersion then
    begin
      {$if declared(_ASN1_BMPSTRING_it)}
      ASN1_BMPSTRING_it := _ASN1_BMPSTRING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_BMPSTRING_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_BMPSTRING_it');
    {$ifend}
  end;
  
  UTF8_getc := LoadLibFunction(ADllHandle, UTF8_getc_procname);
  FuncLoadError := not assigned(UTF8_getc);
  if FuncLoadError then
  begin
    {$if not defined(UTF8_getc_allownil)}
    UTF8_getc := ERR_UTF8_getc;
    {$ifend}
    {$if declared(UTF8_getc_introduced)}
    if LibVersion < UTF8_getc_introduced then
    begin
      {$if declared(FC_UTF8_getc)}
      UTF8_getc := FC_UTF8_getc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UTF8_getc_removed)}
    if UTF8_getc_removed <= LibVersion then
    begin
      {$if declared(_UTF8_getc)}
      UTF8_getc := _UTF8_getc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UTF8_getc_allownil)}
    if FuncLoadError then
      AFailed.Add('UTF8_getc');
    {$ifend}
  end;
  
  UTF8_putc := LoadLibFunction(ADllHandle, UTF8_putc_procname);
  FuncLoadError := not assigned(UTF8_putc);
  if FuncLoadError then
  begin
    {$if not defined(UTF8_putc_allownil)}
    UTF8_putc := ERR_UTF8_putc;
    {$ifend}
    {$if declared(UTF8_putc_introduced)}
    if LibVersion < UTF8_putc_introduced then
    begin
      {$if declared(FC_UTF8_putc)}
      UTF8_putc := FC_UTF8_putc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UTF8_putc_removed)}
    if UTF8_putc_removed <= LibVersion then
    begin
      {$if declared(_UTF8_putc)}
      UTF8_putc := _UTF8_putc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UTF8_putc_allownil)}
    if FuncLoadError then
      AFailed.Add('UTF8_putc');
    {$ifend}
  end;
  
  ASN1_PRINTABLE_new := LoadLibFunction(ADllHandle, ASN1_PRINTABLE_new_procname);
  FuncLoadError := not assigned(ASN1_PRINTABLE_new);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_PRINTABLE_new_allownil)}
    ASN1_PRINTABLE_new := ERR_ASN1_PRINTABLE_new;
    {$ifend}
    {$if declared(ASN1_PRINTABLE_new_introduced)}
    if LibVersion < ASN1_PRINTABLE_new_introduced then
    begin
      {$if declared(FC_ASN1_PRINTABLE_new)}
      ASN1_PRINTABLE_new := FC_ASN1_PRINTABLE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_PRINTABLE_new_removed)}
    if ASN1_PRINTABLE_new_removed <= LibVersion then
    begin
      {$if declared(_ASN1_PRINTABLE_new)}
      ASN1_PRINTABLE_new := _ASN1_PRINTABLE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_PRINTABLE_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_PRINTABLE_new');
    {$ifend}
  end;
  
  ASN1_PRINTABLE_free := LoadLibFunction(ADllHandle, ASN1_PRINTABLE_free_procname);
  FuncLoadError := not assigned(ASN1_PRINTABLE_free);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_PRINTABLE_free_allownil)}
    ASN1_PRINTABLE_free := ERR_ASN1_PRINTABLE_free;
    {$ifend}
    {$if declared(ASN1_PRINTABLE_free_introduced)}
    if LibVersion < ASN1_PRINTABLE_free_introduced then
    begin
      {$if declared(FC_ASN1_PRINTABLE_free)}
      ASN1_PRINTABLE_free := FC_ASN1_PRINTABLE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_PRINTABLE_free_removed)}
    if ASN1_PRINTABLE_free_removed <= LibVersion then
    begin
      {$if declared(_ASN1_PRINTABLE_free)}
      ASN1_PRINTABLE_free := _ASN1_PRINTABLE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_PRINTABLE_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_PRINTABLE_free');
    {$ifend}
  end;
  
  d2i_ASN1_PRINTABLE := LoadLibFunction(ADllHandle, d2i_ASN1_PRINTABLE_procname);
  FuncLoadError := not assigned(d2i_ASN1_PRINTABLE);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ASN1_PRINTABLE_allownil)}
    d2i_ASN1_PRINTABLE := ERR_d2i_ASN1_PRINTABLE;
    {$ifend}
    {$if declared(d2i_ASN1_PRINTABLE_introduced)}
    if LibVersion < d2i_ASN1_PRINTABLE_introduced then
    begin
      {$if declared(FC_d2i_ASN1_PRINTABLE)}
      d2i_ASN1_PRINTABLE := FC_d2i_ASN1_PRINTABLE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ASN1_PRINTABLE_removed)}
    if d2i_ASN1_PRINTABLE_removed <= LibVersion then
    begin
      {$if declared(_d2i_ASN1_PRINTABLE)}
      d2i_ASN1_PRINTABLE := _d2i_ASN1_PRINTABLE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ASN1_PRINTABLE_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ASN1_PRINTABLE');
    {$ifend}
  end;
  
  i2d_ASN1_PRINTABLE := LoadLibFunction(ADllHandle, i2d_ASN1_PRINTABLE_procname);
  FuncLoadError := not assigned(i2d_ASN1_PRINTABLE);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ASN1_PRINTABLE_allownil)}
    i2d_ASN1_PRINTABLE := ERR_i2d_ASN1_PRINTABLE;
    {$ifend}
    {$if declared(i2d_ASN1_PRINTABLE_introduced)}
    if LibVersion < i2d_ASN1_PRINTABLE_introduced then
    begin
      {$if declared(FC_i2d_ASN1_PRINTABLE)}
      i2d_ASN1_PRINTABLE := FC_i2d_ASN1_PRINTABLE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ASN1_PRINTABLE_removed)}
    if i2d_ASN1_PRINTABLE_removed <= LibVersion then
    begin
      {$if declared(_i2d_ASN1_PRINTABLE)}
      i2d_ASN1_PRINTABLE := _i2d_ASN1_PRINTABLE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ASN1_PRINTABLE_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ASN1_PRINTABLE');
    {$ifend}
  end;
  
  ASN1_PRINTABLE_it := LoadLibFunction(ADllHandle, ASN1_PRINTABLE_it_procname);
  FuncLoadError := not assigned(ASN1_PRINTABLE_it);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_PRINTABLE_it_allownil)}
    ASN1_PRINTABLE_it := ERR_ASN1_PRINTABLE_it;
    {$ifend}
    {$if declared(ASN1_PRINTABLE_it_introduced)}
    if LibVersion < ASN1_PRINTABLE_it_introduced then
    begin
      {$if declared(FC_ASN1_PRINTABLE_it)}
      ASN1_PRINTABLE_it := FC_ASN1_PRINTABLE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_PRINTABLE_it_removed)}
    if ASN1_PRINTABLE_it_removed <= LibVersion then
    begin
      {$if declared(_ASN1_PRINTABLE_it)}
      ASN1_PRINTABLE_it := _ASN1_PRINTABLE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_PRINTABLE_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_PRINTABLE_it');
    {$ifend}
  end;
  
  DIRECTORYSTRING_new := LoadLibFunction(ADllHandle, DIRECTORYSTRING_new_procname);
  FuncLoadError := not assigned(DIRECTORYSTRING_new);
  if FuncLoadError then
  begin
    {$if not defined(DIRECTORYSTRING_new_allownil)}
    DIRECTORYSTRING_new := ERR_DIRECTORYSTRING_new;
    {$ifend}
    {$if declared(DIRECTORYSTRING_new_introduced)}
    if LibVersion < DIRECTORYSTRING_new_introduced then
    begin
      {$if declared(FC_DIRECTORYSTRING_new)}
      DIRECTORYSTRING_new := FC_DIRECTORYSTRING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DIRECTORYSTRING_new_removed)}
    if DIRECTORYSTRING_new_removed <= LibVersion then
    begin
      {$if declared(_DIRECTORYSTRING_new)}
      DIRECTORYSTRING_new := _DIRECTORYSTRING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DIRECTORYSTRING_new_allownil)}
    if FuncLoadError then
      AFailed.Add('DIRECTORYSTRING_new');
    {$ifend}
  end;
  
  DIRECTORYSTRING_free := LoadLibFunction(ADllHandle, DIRECTORYSTRING_free_procname);
  FuncLoadError := not assigned(DIRECTORYSTRING_free);
  if FuncLoadError then
  begin
    {$if not defined(DIRECTORYSTRING_free_allownil)}
    DIRECTORYSTRING_free := ERR_DIRECTORYSTRING_free;
    {$ifend}
    {$if declared(DIRECTORYSTRING_free_introduced)}
    if LibVersion < DIRECTORYSTRING_free_introduced then
    begin
      {$if declared(FC_DIRECTORYSTRING_free)}
      DIRECTORYSTRING_free := FC_DIRECTORYSTRING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DIRECTORYSTRING_free_removed)}
    if DIRECTORYSTRING_free_removed <= LibVersion then
    begin
      {$if declared(_DIRECTORYSTRING_free)}
      DIRECTORYSTRING_free := _DIRECTORYSTRING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DIRECTORYSTRING_free_allownil)}
    if FuncLoadError then
      AFailed.Add('DIRECTORYSTRING_free');
    {$ifend}
  end;
  
  d2i_DIRECTORYSTRING := LoadLibFunction(ADllHandle, d2i_DIRECTORYSTRING_procname);
  FuncLoadError := not assigned(d2i_DIRECTORYSTRING);
  if FuncLoadError then
  begin
    {$if not defined(d2i_DIRECTORYSTRING_allownil)}
    d2i_DIRECTORYSTRING := ERR_d2i_DIRECTORYSTRING;
    {$ifend}
    {$if declared(d2i_DIRECTORYSTRING_introduced)}
    if LibVersion < d2i_DIRECTORYSTRING_introduced then
    begin
      {$if declared(FC_d2i_DIRECTORYSTRING)}
      d2i_DIRECTORYSTRING := FC_d2i_DIRECTORYSTRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_DIRECTORYSTRING_removed)}
    if d2i_DIRECTORYSTRING_removed <= LibVersion then
    begin
      {$if declared(_d2i_DIRECTORYSTRING)}
      d2i_DIRECTORYSTRING := _d2i_DIRECTORYSTRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_DIRECTORYSTRING_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_DIRECTORYSTRING');
    {$ifend}
  end;
  
  i2d_DIRECTORYSTRING := LoadLibFunction(ADllHandle, i2d_DIRECTORYSTRING_procname);
  FuncLoadError := not assigned(i2d_DIRECTORYSTRING);
  if FuncLoadError then
  begin
    {$if not defined(i2d_DIRECTORYSTRING_allownil)}
    i2d_DIRECTORYSTRING := ERR_i2d_DIRECTORYSTRING;
    {$ifend}
    {$if declared(i2d_DIRECTORYSTRING_introduced)}
    if LibVersion < i2d_DIRECTORYSTRING_introduced then
    begin
      {$if declared(FC_i2d_DIRECTORYSTRING)}
      i2d_DIRECTORYSTRING := FC_i2d_DIRECTORYSTRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_DIRECTORYSTRING_removed)}
    if i2d_DIRECTORYSTRING_removed <= LibVersion then
    begin
      {$if declared(_i2d_DIRECTORYSTRING)}
      i2d_DIRECTORYSTRING := _i2d_DIRECTORYSTRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_DIRECTORYSTRING_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_DIRECTORYSTRING');
    {$ifend}
  end;
  
  DIRECTORYSTRING_it := LoadLibFunction(ADllHandle, DIRECTORYSTRING_it_procname);
  FuncLoadError := not assigned(DIRECTORYSTRING_it);
  if FuncLoadError then
  begin
    {$if not defined(DIRECTORYSTRING_it_allownil)}
    DIRECTORYSTRING_it := ERR_DIRECTORYSTRING_it;
    {$ifend}
    {$if declared(DIRECTORYSTRING_it_introduced)}
    if LibVersion < DIRECTORYSTRING_it_introduced then
    begin
      {$if declared(FC_DIRECTORYSTRING_it)}
      DIRECTORYSTRING_it := FC_DIRECTORYSTRING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DIRECTORYSTRING_it_removed)}
    if DIRECTORYSTRING_it_removed <= LibVersion then
    begin
      {$if declared(_DIRECTORYSTRING_it)}
      DIRECTORYSTRING_it := _DIRECTORYSTRING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DIRECTORYSTRING_it_allownil)}
    if FuncLoadError then
      AFailed.Add('DIRECTORYSTRING_it');
    {$ifend}
  end;
  
  DISPLAYTEXT_new := LoadLibFunction(ADllHandle, DISPLAYTEXT_new_procname);
  FuncLoadError := not assigned(DISPLAYTEXT_new);
  if FuncLoadError then
  begin
    {$if not defined(DISPLAYTEXT_new_allownil)}
    DISPLAYTEXT_new := ERR_DISPLAYTEXT_new;
    {$ifend}
    {$if declared(DISPLAYTEXT_new_introduced)}
    if LibVersion < DISPLAYTEXT_new_introduced then
    begin
      {$if declared(FC_DISPLAYTEXT_new)}
      DISPLAYTEXT_new := FC_DISPLAYTEXT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DISPLAYTEXT_new_removed)}
    if DISPLAYTEXT_new_removed <= LibVersion then
    begin
      {$if declared(_DISPLAYTEXT_new)}
      DISPLAYTEXT_new := _DISPLAYTEXT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DISPLAYTEXT_new_allownil)}
    if FuncLoadError then
      AFailed.Add('DISPLAYTEXT_new');
    {$ifend}
  end;
  
  DISPLAYTEXT_free := LoadLibFunction(ADllHandle, DISPLAYTEXT_free_procname);
  FuncLoadError := not assigned(DISPLAYTEXT_free);
  if FuncLoadError then
  begin
    {$if not defined(DISPLAYTEXT_free_allownil)}
    DISPLAYTEXT_free := ERR_DISPLAYTEXT_free;
    {$ifend}
    {$if declared(DISPLAYTEXT_free_introduced)}
    if LibVersion < DISPLAYTEXT_free_introduced then
    begin
      {$if declared(FC_DISPLAYTEXT_free)}
      DISPLAYTEXT_free := FC_DISPLAYTEXT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DISPLAYTEXT_free_removed)}
    if DISPLAYTEXT_free_removed <= LibVersion then
    begin
      {$if declared(_DISPLAYTEXT_free)}
      DISPLAYTEXT_free := _DISPLAYTEXT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DISPLAYTEXT_free_allownil)}
    if FuncLoadError then
      AFailed.Add('DISPLAYTEXT_free');
    {$ifend}
  end;
  
  d2i_DISPLAYTEXT := LoadLibFunction(ADllHandle, d2i_DISPLAYTEXT_procname);
  FuncLoadError := not assigned(d2i_DISPLAYTEXT);
  if FuncLoadError then
  begin
    {$if not defined(d2i_DISPLAYTEXT_allownil)}
    d2i_DISPLAYTEXT := ERR_d2i_DISPLAYTEXT;
    {$ifend}
    {$if declared(d2i_DISPLAYTEXT_introduced)}
    if LibVersion < d2i_DISPLAYTEXT_introduced then
    begin
      {$if declared(FC_d2i_DISPLAYTEXT)}
      d2i_DISPLAYTEXT := FC_d2i_DISPLAYTEXT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_DISPLAYTEXT_removed)}
    if d2i_DISPLAYTEXT_removed <= LibVersion then
    begin
      {$if declared(_d2i_DISPLAYTEXT)}
      d2i_DISPLAYTEXT := _d2i_DISPLAYTEXT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_DISPLAYTEXT_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_DISPLAYTEXT');
    {$ifend}
  end;
  
  i2d_DISPLAYTEXT := LoadLibFunction(ADllHandle, i2d_DISPLAYTEXT_procname);
  FuncLoadError := not assigned(i2d_DISPLAYTEXT);
  if FuncLoadError then
  begin
    {$if not defined(i2d_DISPLAYTEXT_allownil)}
    i2d_DISPLAYTEXT := ERR_i2d_DISPLAYTEXT;
    {$ifend}
    {$if declared(i2d_DISPLAYTEXT_introduced)}
    if LibVersion < i2d_DISPLAYTEXT_introduced then
    begin
      {$if declared(FC_i2d_DISPLAYTEXT)}
      i2d_DISPLAYTEXT := FC_i2d_DISPLAYTEXT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_DISPLAYTEXT_removed)}
    if i2d_DISPLAYTEXT_removed <= LibVersion then
    begin
      {$if declared(_i2d_DISPLAYTEXT)}
      i2d_DISPLAYTEXT := _i2d_DISPLAYTEXT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_DISPLAYTEXT_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_DISPLAYTEXT');
    {$ifend}
  end;
  
  DISPLAYTEXT_it := LoadLibFunction(ADllHandle, DISPLAYTEXT_it_procname);
  FuncLoadError := not assigned(DISPLAYTEXT_it);
  if FuncLoadError then
  begin
    {$if not defined(DISPLAYTEXT_it_allownil)}
    DISPLAYTEXT_it := ERR_DISPLAYTEXT_it;
    {$ifend}
    {$if declared(DISPLAYTEXT_it_introduced)}
    if LibVersion < DISPLAYTEXT_it_introduced then
    begin
      {$if declared(FC_DISPLAYTEXT_it)}
      DISPLAYTEXT_it := FC_DISPLAYTEXT_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DISPLAYTEXT_it_removed)}
    if DISPLAYTEXT_it_removed <= LibVersion then
    begin
      {$if declared(_DISPLAYTEXT_it)}
      DISPLAYTEXT_it := _DISPLAYTEXT_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DISPLAYTEXT_it_allownil)}
    if FuncLoadError then
      AFailed.Add('DISPLAYTEXT_it');
    {$ifend}
  end;
  
  ASN1_PRINTABLESTRING_new := LoadLibFunction(ADllHandle, ASN1_PRINTABLESTRING_new_procname);
  FuncLoadError := not assigned(ASN1_PRINTABLESTRING_new);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_PRINTABLESTRING_new_allownil)}
    ASN1_PRINTABLESTRING_new := ERR_ASN1_PRINTABLESTRING_new;
    {$ifend}
    {$if declared(ASN1_PRINTABLESTRING_new_introduced)}
    if LibVersion < ASN1_PRINTABLESTRING_new_introduced then
    begin
      {$if declared(FC_ASN1_PRINTABLESTRING_new)}
      ASN1_PRINTABLESTRING_new := FC_ASN1_PRINTABLESTRING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_PRINTABLESTRING_new_removed)}
    if ASN1_PRINTABLESTRING_new_removed <= LibVersion then
    begin
      {$if declared(_ASN1_PRINTABLESTRING_new)}
      ASN1_PRINTABLESTRING_new := _ASN1_PRINTABLESTRING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_PRINTABLESTRING_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_PRINTABLESTRING_new');
    {$ifend}
  end;
  
  ASN1_PRINTABLESTRING_free := LoadLibFunction(ADllHandle, ASN1_PRINTABLESTRING_free_procname);
  FuncLoadError := not assigned(ASN1_PRINTABLESTRING_free);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_PRINTABLESTRING_free_allownil)}
    ASN1_PRINTABLESTRING_free := ERR_ASN1_PRINTABLESTRING_free;
    {$ifend}
    {$if declared(ASN1_PRINTABLESTRING_free_introduced)}
    if LibVersion < ASN1_PRINTABLESTRING_free_introduced then
    begin
      {$if declared(FC_ASN1_PRINTABLESTRING_free)}
      ASN1_PRINTABLESTRING_free := FC_ASN1_PRINTABLESTRING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_PRINTABLESTRING_free_removed)}
    if ASN1_PRINTABLESTRING_free_removed <= LibVersion then
    begin
      {$if declared(_ASN1_PRINTABLESTRING_free)}
      ASN1_PRINTABLESTRING_free := _ASN1_PRINTABLESTRING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_PRINTABLESTRING_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_PRINTABLESTRING_free');
    {$ifend}
  end;
  
  d2i_ASN1_PRINTABLESTRING := LoadLibFunction(ADllHandle, d2i_ASN1_PRINTABLESTRING_procname);
  FuncLoadError := not assigned(d2i_ASN1_PRINTABLESTRING);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ASN1_PRINTABLESTRING_allownil)}
    d2i_ASN1_PRINTABLESTRING := ERR_d2i_ASN1_PRINTABLESTRING;
    {$ifend}
    {$if declared(d2i_ASN1_PRINTABLESTRING_introduced)}
    if LibVersion < d2i_ASN1_PRINTABLESTRING_introduced then
    begin
      {$if declared(FC_d2i_ASN1_PRINTABLESTRING)}
      d2i_ASN1_PRINTABLESTRING := FC_d2i_ASN1_PRINTABLESTRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ASN1_PRINTABLESTRING_removed)}
    if d2i_ASN1_PRINTABLESTRING_removed <= LibVersion then
    begin
      {$if declared(_d2i_ASN1_PRINTABLESTRING)}
      d2i_ASN1_PRINTABLESTRING := _d2i_ASN1_PRINTABLESTRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ASN1_PRINTABLESTRING_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ASN1_PRINTABLESTRING');
    {$ifend}
  end;
  
  i2d_ASN1_PRINTABLESTRING := LoadLibFunction(ADllHandle, i2d_ASN1_PRINTABLESTRING_procname);
  FuncLoadError := not assigned(i2d_ASN1_PRINTABLESTRING);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ASN1_PRINTABLESTRING_allownil)}
    i2d_ASN1_PRINTABLESTRING := ERR_i2d_ASN1_PRINTABLESTRING;
    {$ifend}
    {$if declared(i2d_ASN1_PRINTABLESTRING_introduced)}
    if LibVersion < i2d_ASN1_PRINTABLESTRING_introduced then
    begin
      {$if declared(FC_i2d_ASN1_PRINTABLESTRING)}
      i2d_ASN1_PRINTABLESTRING := FC_i2d_ASN1_PRINTABLESTRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ASN1_PRINTABLESTRING_removed)}
    if i2d_ASN1_PRINTABLESTRING_removed <= LibVersion then
    begin
      {$if declared(_i2d_ASN1_PRINTABLESTRING)}
      i2d_ASN1_PRINTABLESTRING := _i2d_ASN1_PRINTABLESTRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ASN1_PRINTABLESTRING_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ASN1_PRINTABLESTRING');
    {$ifend}
  end;
  
  ASN1_PRINTABLESTRING_it := LoadLibFunction(ADllHandle, ASN1_PRINTABLESTRING_it_procname);
  FuncLoadError := not assigned(ASN1_PRINTABLESTRING_it);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_PRINTABLESTRING_it_allownil)}
    ASN1_PRINTABLESTRING_it := ERR_ASN1_PRINTABLESTRING_it;
    {$ifend}
    {$if declared(ASN1_PRINTABLESTRING_it_introduced)}
    if LibVersion < ASN1_PRINTABLESTRING_it_introduced then
    begin
      {$if declared(FC_ASN1_PRINTABLESTRING_it)}
      ASN1_PRINTABLESTRING_it := FC_ASN1_PRINTABLESTRING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_PRINTABLESTRING_it_removed)}
    if ASN1_PRINTABLESTRING_it_removed <= LibVersion then
    begin
      {$if declared(_ASN1_PRINTABLESTRING_it)}
      ASN1_PRINTABLESTRING_it := _ASN1_PRINTABLESTRING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_PRINTABLESTRING_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_PRINTABLESTRING_it');
    {$ifend}
  end;
  
  ASN1_T61STRING_new := LoadLibFunction(ADllHandle, ASN1_T61STRING_new_procname);
  FuncLoadError := not assigned(ASN1_T61STRING_new);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_T61STRING_new_allownil)}
    ASN1_T61STRING_new := ERR_ASN1_T61STRING_new;
    {$ifend}
    {$if declared(ASN1_T61STRING_new_introduced)}
    if LibVersion < ASN1_T61STRING_new_introduced then
    begin
      {$if declared(FC_ASN1_T61STRING_new)}
      ASN1_T61STRING_new := FC_ASN1_T61STRING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_T61STRING_new_removed)}
    if ASN1_T61STRING_new_removed <= LibVersion then
    begin
      {$if declared(_ASN1_T61STRING_new)}
      ASN1_T61STRING_new := _ASN1_T61STRING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_T61STRING_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_T61STRING_new');
    {$ifend}
  end;
  
  ASN1_T61STRING_free := LoadLibFunction(ADllHandle, ASN1_T61STRING_free_procname);
  FuncLoadError := not assigned(ASN1_T61STRING_free);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_T61STRING_free_allownil)}
    ASN1_T61STRING_free := ERR_ASN1_T61STRING_free;
    {$ifend}
    {$if declared(ASN1_T61STRING_free_introduced)}
    if LibVersion < ASN1_T61STRING_free_introduced then
    begin
      {$if declared(FC_ASN1_T61STRING_free)}
      ASN1_T61STRING_free := FC_ASN1_T61STRING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_T61STRING_free_removed)}
    if ASN1_T61STRING_free_removed <= LibVersion then
    begin
      {$if declared(_ASN1_T61STRING_free)}
      ASN1_T61STRING_free := _ASN1_T61STRING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_T61STRING_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_T61STRING_free');
    {$ifend}
  end;
  
  d2i_ASN1_T61STRING := LoadLibFunction(ADllHandle, d2i_ASN1_T61STRING_procname);
  FuncLoadError := not assigned(d2i_ASN1_T61STRING);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ASN1_T61STRING_allownil)}
    d2i_ASN1_T61STRING := ERR_d2i_ASN1_T61STRING;
    {$ifend}
    {$if declared(d2i_ASN1_T61STRING_introduced)}
    if LibVersion < d2i_ASN1_T61STRING_introduced then
    begin
      {$if declared(FC_d2i_ASN1_T61STRING)}
      d2i_ASN1_T61STRING := FC_d2i_ASN1_T61STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ASN1_T61STRING_removed)}
    if d2i_ASN1_T61STRING_removed <= LibVersion then
    begin
      {$if declared(_d2i_ASN1_T61STRING)}
      d2i_ASN1_T61STRING := _d2i_ASN1_T61STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ASN1_T61STRING_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ASN1_T61STRING');
    {$ifend}
  end;
  
  i2d_ASN1_T61STRING := LoadLibFunction(ADllHandle, i2d_ASN1_T61STRING_procname);
  FuncLoadError := not assigned(i2d_ASN1_T61STRING);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ASN1_T61STRING_allownil)}
    i2d_ASN1_T61STRING := ERR_i2d_ASN1_T61STRING;
    {$ifend}
    {$if declared(i2d_ASN1_T61STRING_introduced)}
    if LibVersion < i2d_ASN1_T61STRING_introduced then
    begin
      {$if declared(FC_i2d_ASN1_T61STRING)}
      i2d_ASN1_T61STRING := FC_i2d_ASN1_T61STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ASN1_T61STRING_removed)}
    if i2d_ASN1_T61STRING_removed <= LibVersion then
    begin
      {$if declared(_i2d_ASN1_T61STRING)}
      i2d_ASN1_T61STRING := _i2d_ASN1_T61STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ASN1_T61STRING_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ASN1_T61STRING');
    {$ifend}
  end;
  
  ASN1_T61STRING_it := LoadLibFunction(ADllHandle, ASN1_T61STRING_it_procname);
  FuncLoadError := not assigned(ASN1_T61STRING_it);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_T61STRING_it_allownil)}
    ASN1_T61STRING_it := ERR_ASN1_T61STRING_it;
    {$ifend}
    {$if declared(ASN1_T61STRING_it_introduced)}
    if LibVersion < ASN1_T61STRING_it_introduced then
    begin
      {$if declared(FC_ASN1_T61STRING_it)}
      ASN1_T61STRING_it := FC_ASN1_T61STRING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_T61STRING_it_removed)}
    if ASN1_T61STRING_it_removed <= LibVersion then
    begin
      {$if declared(_ASN1_T61STRING_it)}
      ASN1_T61STRING_it := _ASN1_T61STRING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_T61STRING_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_T61STRING_it');
    {$ifend}
  end;
  
  ASN1_IA5STRING_new := LoadLibFunction(ADllHandle, ASN1_IA5STRING_new_procname);
  FuncLoadError := not assigned(ASN1_IA5STRING_new);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_IA5STRING_new_allownil)}
    ASN1_IA5STRING_new := ERR_ASN1_IA5STRING_new;
    {$ifend}
    {$if declared(ASN1_IA5STRING_new_introduced)}
    if LibVersion < ASN1_IA5STRING_new_introduced then
    begin
      {$if declared(FC_ASN1_IA5STRING_new)}
      ASN1_IA5STRING_new := FC_ASN1_IA5STRING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_IA5STRING_new_removed)}
    if ASN1_IA5STRING_new_removed <= LibVersion then
    begin
      {$if declared(_ASN1_IA5STRING_new)}
      ASN1_IA5STRING_new := _ASN1_IA5STRING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_IA5STRING_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_IA5STRING_new');
    {$ifend}
  end;
  
  ASN1_IA5STRING_free := LoadLibFunction(ADllHandle, ASN1_IA5STRING_free_procname);
  FuncLoadError := not assigned(ASN1_IA5STRING_free);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_IA5STRING_free_allownil)}
    ASN1_IA5STRING_free := ERR_ASN1_IA5STRING_free;
    {$ifend}
    {$if declared(ASN1_IA5STRING_free_introduced)}
    if LibVersion < ASN1_IA5STRING_free_introduced then
    begin
      {$if declared(FC_ASN1_IA5STRING_free)}
      ASN1_IA5STRING_free := FC_ASN1_IA5STRING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_IA5STRING_free_removed)}
    if ASN1_IA5STRING_free_removed <= LibVersion then
    begin
      {$if declared(_ASN1_IA5STRING_free)}
      ASN1_IA5STRING_free := _ASN1_IA5STRING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_IA5STRING_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_IA5STRING_free');
    {$ifend}
  end;
  
  d2i_ASN1_IA5STRING := LoadLibFunction(ADllHandle, d2i_ASN1_IA5STRING_procname);
  FuncLoadError := not assigned(d2i_ASN1_IA5STRING);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ASN1_IA5STRING_allownil)}
    d2i_ASN1_IA5STRING := ERR_d2i_ASN1_IA5STRING;
    {$ifend}
    {$if declared(d2i_ASN1_IA5STRING_introduced)}
    if LibVersion < d2i_ASN1_IA5STRING_introduced then
    begin
      {$if declared(FC_d2i_ASN1_IA5STRING)}
      d2i_ASN1_IA5STRING := FC_d2i_ASN1_IA5STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ASN1_IA5STRING_removed)}
    if d2i_ASN1_IA5STRING_removed <= LibVersion then
    begin
      {$if declared(_d2i_ASN1_IA5STRING)}
      d2i_ASN1_IA5STRING := _d2i_ASN1_IA5STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ASN1_IA5STRING_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ASN1_IA5STRING');
    {$ifend}
  end;
  
  i2d_ASN1_IA5STRING := LoadLibFunction(ADllHandle, i2d_ASN1_IA5STRING_procname);
  FuncLoadError := not assigned(i2d_ASN1_IA5STRING);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ASN1_IA5STRING_allownil)}
    i2d_ASN1_IA5STRING := ERR_i2d_ASN1_IA5STRING;
    {$ifend}
    {$if declared(i2d_ASN1_IA5STRING_introduced)}
    if LibVersion < i2d_ASN1_IA5STRING_introduced then
    begin
      {$if declared(FC_i2d_ASN1_IA5STRING)}
      i2d_ASN1_IA5STRING := FC_i2d_ASN1_IA5STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ASN1_IA5STRING_removed)}
    if i2d_ASN1_IA5STRING_removed <= LibVersion then
    begin
      {$if declared(_i2d_ASN1_IA5STRING)}
      i2d_ASN1_IA5STRING := _i2d_ASN1_IA5STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ASN1_IA5STRING_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ASN1_IA5STRING');
    {$ifend}
  end;
  
  ASN1_IA5STRING_it := LoadLibFunction(ADllHandle, ASN1_IA5STRING_it_procname);
  FuncLoadError := not assigned(ASN1_IA5STRING_it);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_IA5STRING_it_allownil)}
    ASN1_IA5STRING_it := ERR_ASN1_IA5STRING_it;
    {$ifend}
    {$if declared(ASN1_IA5STRING_it_introduced)}
    if LibVersion < ASN1_IA5STRING_it_introduced then
    begin
      {$if declared(FC_ASN1_IA5STRING_it)}
      ASN1_IA5STRING_it := FC_ASN1_IA5STRING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_IA5STRING_it_removed)}
    if ASN1_IA5STRING_it_removed <= LibVersion then
    begin
      {$if declared(_ASN1_IA5STRING_it)}
      ASN1_IA5STRING_it := _ASN1_IA5STRING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_IA5STRING_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_IA5STRING_it');
    {$ifend}
  end;
  
  ASN1_GENERALSTRING_new := LoadLibFunction(ADllHandle, ASN1_GENERALSTRING_new_procname);
  FuncLoadError := not assigned(ASN1_GENERALSTRING_new);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_GENERALSTRING_new_allownil)}
    ASN1_GENERALSTRING_new := ERR_ASN1_GENERALSTRING_new;
    {$ifend}
    {$if declared(ASN1_GENERALSTRING_new_introduced)}
    if LibVersion < ASN1_GENERALSTRING_new_introduced then
    begin
      {$if declared(FC_ASN1_GENERALSTRING_new)}
      ASN1_GENERALSTRING_new := FC_ASN1_GENERALSTRING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_GENERALSTRING_new_removed)}
    if ASN1_GENERALSTRING_new_removed <= LibVersion then
    begin
      {$if declared(_ASN1_GENERALSTRING_new)}
      ASN1_GENERALSTRING_new := _ASN1_GENERALSTRING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_GENERALSTRING_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_GENERALSTRING_new');
    {$ifend}
  end;
  
  ASN1_GENERALSTRING_free := LoadLibFunction(ADllHandle, ASN1_GENERALSTRING_free_procname);
  FuncLoadError := not assigned(ASN1_GENERALSTRING_free);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_GENERALSTRING_free_allownil)}
    ASN1_GENERALSTRING_free := ERR_ASN1_GENERALSTRING_free;
    {$ifend}
    {$if declared(ASN1_GENERALSTRING_free_introduced)}
    if LibVersion < ASN1_GENERALSTRING_free_introduced then
    begin
      {$if declared(FC_ASN1_GENERALSTRING_free)}
      ASN1_GENERALSTRING_free := FC_ASN1_GENERALSTRING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_GENERALSTRING_free_removed)}
    if ASN1_GENERALSTRING_free_removed <= LibVersion then
    begin
      {$if declared(_ASN1_GENERALSTRING_free)}
      ASN1_GENERALSTRING_free := _ASN1_GENERALSTRING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_GENERALSTRING_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_GENERALSTRING_free');
    {$ifend}
  end;
  
  d2i_ASN1_GENERALSTRING := LoadLibFunction(ADllHandle, d2i_ASN1_GENERALSTRING_procname);
  FuncLoadError := not assigned(d2i_ASN1_GENERALSTRING);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ASN1_GENERALSTRING_allownil)}
    d2i_ASN1_GENERALSTRING := ERR_d2i_ASN1_GENERALSTRING;
    {$ifend}
    {$if declared(d2i_ASN1_GENERALSTRING_introduced)}
    if LibVersion < d2i_ASN1_GENERALSTRING_introduced then
    begin
      {$if declared(FC_d2i_ASN1_GENERALSTRING)}
      d2i_ASN1_GENERALSTRING := FC_d2i_ASN1_GENERALSTRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ASN1_GENERALSTRING_removed)}
    if d2i_ASN1_GENERALSTRING_removed <= LibVersion then
    begin
      {$if declared(_d2i_ASN1_GENERALSTRING)}
      d2i_ASN1_GENERALSTRING := _d2i_ASN1_GENERALSTRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ASN1_GENERALSTRING_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ASN1_GENERALSTRING');
    {$ifend}
  end;
  
  i2d_ASN1_GENERALSTRING := LoadLibFunction(ADllHandle, i2d_ASN1_GENERALSTRING_procname);
  FuncLoadError := not assigned(i2d_ASN1_GENERALSTRING);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ASN1_GENERALSTRING_allownil)}
    i2d_ASN1_GENERALSTRING := ERR_i2d_ASN1_GENERALSTRING;
    {$ifend}
    {$if declared(i2d_ASN1_GENERALSTRING_introduced)}
    if LibVersion < i2d_ASN1_GENERALSTRING_introduced then
    begin
      {$if declared(FC_i2d_ASN1_GENERALSTRING)}
      i2d_ASN1_GENERALSTRING := FC_i2d_ASN1_GENERALSTRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ASN1_GENERALSTRING_removed)}
    if i2d_ASN1_GENERALSTRING_removed <= LibVersion then
    begin
      {$if declared(_i2d_ASN1_GENERALSTRING)}
      i2d_ASN1_GENERALSTRING := _i2d_ASN1_GENERALSTRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ASN1_GENERALSTRING_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ASN1_GENERALSTRING');
    {$ifend}
  end;
  
  ASN1_GENERALSTRING_it := LoadLibFunction(ADllHandle, ASN1_GENERALSTRING_it_procname);
  FuncLoadError := not assigned(ASN1_GENERALSTRING_it);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_GENERALSTRING_it_allownil)}
    ASN1_GENERALSTRING_it := ERR_ASN1_GENERALSTRING_it;
    {$ifend}
    {$if declared(ASN1_GENERALSTRING_it_introduced)}
    if LibVersion < ASN1_GENERALSTRING_it_introduced then
    begin
      {$if declared(FC_ASN1_GENERALSTRING_it)}
      ASN1_GENERALSTRING_it := FC_ASN1_GENERALSTRING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_GENERALSTRING_it_removed)}
    if ASN1_GENERALSTRING_it_removed <= LibVersion then
    begin
      {$if declared(_ASN1_GENERALSTRING_it)}
      ASN1_GENERALSTRING_it := _ASN1_GENERALSTRING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_GENERALSTRING_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_GENERALSTRING_it');
    {$ifend}
  end;
  
  ASN1_UTCTIME_new := LoadLibFunction(ADllHandle, ASN1_UTCTIME_new_procname);
  FuncLoadError := not assigned(ASN1_UTCTIME_new);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_UTCTIME_new_allownil)}
    ASN1_UTCTIME_new := ERR_ASN1_UTCTIME_new;
    {$ifend}
    {$if declared(ASN1_UTCTIME_new_introduced)}
    if LibVersion < ASN1_UTCTIME_new_introduced then
    begin
      {$if declared(FC_ASN1_UTCTIME_new)}
      ASN1_UTCTIME_new := FC_ASN1_UTCTIME_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_UTCTIME_new_removed)}
    if ASN1_UTCTIME_new_removed <= LibVersion then
    begin
      {$if declared(_ASN1_UTCTIME_new)}
      ASN1_UTCTIME_new := _ASN1_UTCTIME_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_UTCTIME_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_UTCTIME_new');
    {$ifend}
  end;
  
  ASN1_UTCTIME_free := LoadLibFunction(ADllHandle, ASN1_UTCTIME_free_procname);
  FuncLoadError := not assigned(ASN1_UTCTIME_free);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_UTCTIME_free_allownil)}
    ASN1_UTCTIME_free := ERR_ASN1_UTCTIME_free;
    {$ifend}
    {$if declared(ASN1_UTCTIME_free_introduced)}
    if LibVersion < ASN1_UTCTIME_free_introduced then
    begin
      {$if declared(FC_ASN1_UTCTIME_free)}
      ASN1_UTCTIME_free := FC_ASN1_UTCTIME_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_UTCTIME_free_removed)}
    if ASN1_UTCTIME_free_removed <= LibVersion then
    begin
      {$if declared(_ASN1_UTCTIME_free)}
      ASN1_UTCTIME_free := _ASN1_UTCTIME_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_UTCTIME_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_UTCTIME_free');
    {$ifend}
  end;
  
  d2i_ASN1_UTCTIME := LoadLibFunction(ADllHandle, d2i_ASN1_UTCTIME_procname);
  FuncLoadError := not assigned(d2i_ASN1_UTCTIME);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ASN1_UTCTIME_allownil)}
    d2i_ASN1_UTCTIME := ERR_d2i_ASN1_UTCTIME;
    {$ifend}
    {$if declared(d2i_ASN1_UTCTIME_introduced)}
    if LibVersion < d2i_ASN1_UTCTIME_introduced then
    begin
      {$if declared(FC_d2i_ASN1_UTCTIME)}
      d2i_ASN1_UTCTIME := FC_d2i_ASN1_UTCTIME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ASN1_UTCTIME_removed)}
    if d2i_ASN1_UTCTIME_removed <= LibVersion then
    begin
      {$if declared(_d2i_ASN1_UTCTIME)}
      d2i_ASN1_UTCTIME := _d2i_ASN1_UTCTIME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ASN1_UTCTIME_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ASN1_UTCTIME');
    {$ifend}
  end;
  
  i2d_ASN1_UTCTIME := LoadLibFunction(ADllHandle, i2d_ASN1_UTCTIME_procname);
  FuncLoadError := not assigned(i2d_ASN1_UTCTIME);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ASN1_UTCTIME_allownil)}
    i2d_ASN1_UTCTIME := ERR_i2d_ASN1_UTCTIME;
    {$ifend}
    {$if declared(i2d_ASN1_UTCTIME_introduced)}
    if LibVersion < i2d_ASN1_UTCTIME_introduced then
    begin
      {$if declared(FC_i2d_ASN1_UTCTIME)}
      i2d_ASN1_UTCTIME := FC_i2d_ASN1_UTCTIME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ASN1_UTCTIME_removed)}
    if i2d_ASN1_UTCTIME_removed <= LibVersion then
    begin
      {$if declared(_i2d_ASN1_UTCTIME)}
      i2d_ASN1_UTCTIME := _i2d_ASN1_UTCTIME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ASN1_UTCTIME_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ASN1_UTCTIME');
    {$ifend}
  end;
  
  ASN1_UTCTIME_it := LoadLibFunction(ADllHandle, ASN1_UTCTIME_it_procname);
  FuncLoadError := not assigned(ASN1_UTCTIME_it);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_UTCTIME_it_allownil)}
    ASN1_UTCTIME_it := ERR_ASN1_UTCTIME_it;
    {$ifend}
    {$if declared(ASN1_UTCTIME_it_introduced)}
    if LibVersion < ASN1_UTCTIME_it_introduced then
    begin
      {$if declared(FC_ASN1_UTCTIME_it)}
      ASN1_UTCTIME_it := FC_ASN1_UTCTIME_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_UTCTIME_it_removed)}
    if ASN1_UTCTIME_it_removed <= LibVersion then
    begin
      {$if declared(_ASN1_UTCTIME_it)}
      ASN1_UTCTIME_it := _ASN1_UTCTIME_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_UTCTIME_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_UTCTIME_it');
    {$ifend}
  end;
  
  ASN1_GENERALIZEDTIME_new := LoadLibFunction(ADllHandle, ASN1_GENERALIZEDTIME_new_procname);
  FuncLoadError := not assigned(ASN1_GENERALIZEDTIME_new);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_GENERALIZEDTIME_new_allownil)}
    ASN1_GENERALIZEDTIME_new := ERR_ASN1_GENERALIZEDTIME_new;
    {$ifend}
    {$if declared(ASN1_GENERALIZEDTIME_new_introduced)}
    if LibVersion < ASN1_GENERALIZEDTIME_new_introduced then
    begin
      {$if declared(FC_ASN1_GENERALIZEDTIME_new)}
      ASN1_GENERALIZEDTIME_new := FC_ASN1_GENERALIZEDTIME_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_GENERALIZEDTIME_new_removed)}
    if ASN1_GENERALIZEDTIME_new_removed <= LibVersion then
    begin
      {$if declared(_ASN1_GENERALIZEDTIME_new)}
      ASN1_GENERALIZEDTIME_new := _ASN1_GENERALIZEDTIME_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_GENERALIZEDTIME_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_GENERALIZEDTIME_new');
    {$ifend}
  end;
  
  ASN1_GENERALIZEDTIME_free := LoadLibFunction(ADllHandle, ASN1_GENERALIZEDTIME_free_procname);
  FuncLoadError := not assigned(ASN1_GENERALIZEDTIME_free);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_GENERALIZEDTIME_free_allownil)}
    ASN1_GENERALIZEDTIME_free := ERR_ASN1_GENERALIZEDTIME_free;
    {$ifend}
    {$if declared(ASN1_GENERALIZEDTIME_free_introduced)}
    if LibVersion < ASN1_GENERALIZEDTIME_free_introduced then
    begin
      {$if declared(FC_ASN1_GENERALIZEDTIME_free)}
      ASN1_GENERALIZEDTIME_free := FC_ASN1_GENERALIZEDTIME_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_GENERALIZEDTIME_free_removed)}
    if ASN1_GENERALIZEDTIME_free_removed <= LibVersion then
    begin
      {$if declared(_ASN1_GENERALIZEDTIME_free)}
      ASN1_GENERALIZEDTIME_free := _ASN1_GENERALIZEDTIME_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_GENERALIZEDTIME_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_GENERALIZEDTIME_free');
    {$ifend}
  end;
  
  d2i_ASN1_GENERALIZEDTIME := LoadLibFunction(ADllHandle, d2i_ASN1_GENERALIZEDTIME_procname);
  FuncLoadError := not assigned(d2i_ASN1_GENERALIZEDTIME);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ASN1_GENERALIZEDTIME_allownil)}
    d2i_ASN1_GENERALIZEDTIME := ERR_d2i_ASN1_GENERALIZEDTIME;
    {$ifend}
    {$if declared(d2i_ASN1_GENERALIZEDTIME_introduced)}
    if LibVersion < d2i_ASN1_GENERALIZEDTIME_introduced then
    begin
      {$if declared(FC_d2i_ASN1_GENERALIZEDTIME)}
      d2i_ASN1_GENERALIZEDTIME := FC_d2i_ASN1_GENERALIZEDTIME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ASN1_GENERALIZEDTIME_removed)}
    if d2i_ASN1_GENERALIZEDTIME_removed <= LibVersion then
    begin
      {$if declared(_d2i_ASN1_GENERALIZEDTIME)}
      d2i_ASN1_GENERALIZEDTIME := _d2i_ASN1_GENERALIZEDTIME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ASN1_GENERALIZEDTIME_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ASN1_GENERALIZEDTIME');
    {$ifend}
  end;
  
  i2d_ASN1_GENERALIZEDTIME := LoadLibFunction(ADllHandle, i2d_ASN1_GENERALIZEDTIME_procname);
  FuncLoadError := not assigned(i2d_ASN1_GENERALIZEDTIME);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ASN1_GENERALIZEDTIME_allownil)}
    i2d_ASN1_GENERALIZEDTIME := ERR_i2d_ASN1_GENERALIZEDTIME;
    {$ifend}
    {$if declared(i2d_ASN1_GENERALIZEDTIME_introduced)}
    if LibVersion < i2d_ASN1_GENERALIZEDTIME_introduced then
    begin
      {$if declared(FC_i2d_ASN1_GENERALIZEDTIME)}
      i2d_ASN1_GENERALIZEDTIME := FC_i2d_ASN1_GENERALIZEDTIME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ASN1_GENERALIZEDTIME_removed)}
    if i2d_ASN1_GENERALIZEDTIME_removed <= LibVersion then
    begin
      {$if declared(_i2d_ASN1_GENERALIZEDTIME)}
      i2d_ASN1_GENERALIZEDTIME := _i2d_ASN1_GENERALIZEDTIME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ASN1_GENERALIZEDTIME_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ASN1_GENERALIZEDTIME');
    {$ifend}
  end;
  
  ASN1_GENERALIZEDTIME_it := LoadLibFunction(ADllHandle, ASN1_GENERALIZEDTIME_it_procname);
  FuncLoadError := not assigned(ASN1_GENERALIZEDTIME_it);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_GENERALIZEDTIME_it_allownil)}
    ASN1_GENERALIZEDTIME_it := ERR_ASN1_GENERALIZEDTIME_it;
    {$ifend}
    {$if declared(ASN1_GENERALIZEDTIME_it_introduced)}
    if LibVersion < ASN1_GENERALIZEDTIME_it_introduced then
    begin
      {$if declared(FC_ASN1_GENERALIZEDTIME_it)}
      ASN1_GENERALIZEDTIME_it := FC_ASN1_GENERALIZEDTIME_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_GENERALIZEDTIME_it_removed)}
    if ASN1_GENERALIZEDTIME_it_removed <= LibVersion then
    begin
      {$if declared(_ASN1_GENERALIZEDTIME_it)}
      ASN1_GENERALIZEDTIME_it := _ASN1_GENERALIZEDTIME_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_GENERALIZEDTIME_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_GENERALIZEDTIME_it');
    {$ifend}
  end;
  
  ASN1_TIME_new := LoadLibFunction(ADllHandle, ASN1_TIME_new_procname);
  FuncLoadError := not assigned(ASN1_TIME_new);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TIME_new_allownil)}
    ASN1_TIME_new := ERR_ASN1_TIME_new;
    {$ifend}
    {$if declared(ASN1_TIME_new_introduced)}
    if LibVersion < ASN1_TIME_new_introduced then
    begin
      {$if declared(FC_ASN1_TIME_new)}
      ASN1_TIME_new := FC_ASN1_TIME_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TIME_new_removed)}
    if ASN1_TIME_new_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TIME_new)}
      ASN1_TIME_new := _ASN1_TIME_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TIME_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TIME_new');
    {$ifend}
  end;
  
  ASN1_TIME_free := LoadLibFunction(ADllHandle, ASN1_TIME_free_procname);
  FuncLoadError := not assigned(ASN1_TIME_free);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TIME_free_allownil)}
    ASN1_TIME_free := ERR_ASN1_TIME_free;
    {$ifend}
    {$if declared(ASN1_TIME_free_introduced)}
    if LibVersion < ASN1_TIME_free_introduced then
    begin
      {$if declared(FC_ASN1_TIME_free)}
      ASN1_TIME_free := FC_ASN1_TIME_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TIME_free_removed)}
    if ASN1_TIME_free_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TIME_free)}
      ASN1_TIME_free := _ASN1_TIME_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TIME_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TIME_free');
    {$ifend}
  end;
  
  d2i_ASN1_TIME := LoadLibFunction(ADllHandle, d2i_ASN1_TIME_procname);
  FuncLoadError := not assigned(d2i_ASN1_TIME);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ASN1_TIME_allownil)}
    d2i_ASN1_TIME := ERR_d2i_ASN1_TIME;
    {$ifend}
    {$if declared(d2i_ASN1_TIME_introduced)}
    if LibVersion < d2i_ASN1_TIME_introduced then
    begin
      {$if declared(FC_d2i_ASN1_TIME)}
      d2i_ASN1_TIME := FC_d2i_ASN1_TIME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ASN1_TIME_removed)}
    if d2i_ASN1_TIME_removed <= LibVersion then
    begin
      {$if declared(_d2i_ASN1_TIME)}
      d2i_ASN1_TIME := _d2i_ASN1_TIME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ASN1_TIME_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ASN1_TIME');
    {$ifend}
  end;
  
  i2d_ASN1_TIME := LoadLibFunction(ADllHandle, i2d_ASN1_TIME_procname);
  FuncLoadError := not assigned(i2d_ASN1_TIME);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ASN1_TIME_allownil)}
    i2d_ASN1_TIME := ERR_i2d_ASN1_TIME;
    {$ifend}
    {$if declared(i2d_ASN1_TIME_introduced)}
    if LibVersion < i2d_ASN1_TIME_introduced then
    begin
      {$if declared(FC_i2d_ASN1_TIME)}
      i2d_ASN1_TIME := FC_i2d_ASN1_TIME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ASN1_TIME_removed)}
    if i2d_ASN1_TIME_removed <= LibVersion then
    begin
      {$if declared(_i2d_ASN1_TIME)}
      i2d_ASN1_TIME := _i2d_ASN1_TIME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ASN1_TIME_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ASN1_TIME');
    {$ifend}
  end;
  
  ASN1_TIME_it := LoadLibFunction(ADllHandle, ASN1_TIME_it_procname);
  FuncLoadError := not assigned(ASN1_TIME_it);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TIME_it_allownil)}
    ASN1_TIME_it := ERR_ASN1_TIME_it;
    {$ifend}
    {$if declared(ASN1_TIME_it_introduced)}
    if LibVersion < ASN1_TIME_it_introduced then
    begin
      {$if declared(FC_ASN1_TIME_it)}
      ASN1_TIME_it := FC_ASN1_TIME_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TIME_it_removed)}
    if ASN1_TIME_it_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TIME_it)}
      ASN1_TIME_it := _ASN1_TIME_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TIME_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TIME_it');
    {$ifend}
  end;
  
  ASN1_TIME_dup := LoadLibFunction(ADllHandle, ASN1_TIME_dup_procname);
  FuncLoadError := not assigned(ASN1_TIME_dup);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TIME_dup_allownil)}
    ASN1_TIME_dup := ERR_ASN1_TIME_dup;
    {$ifend}
    {$if declared(ASN1_TIME_dup_introduced)}
    if LibVersion < ASN1_TIME_dup_introduced then
    begin
      {$if declared(FC_ASN1_TIME_dup)}
      ASN1_TIME_dup := FC_ASN1_TIME_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TIME_dup_removed)}
    if ASN1_TIME_dup_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TIME_dup)}
      ASN1_TIME_dup := _ASN1_TIME_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TIME_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TIME_dup');
    {$ifend}
  end;
  
  ASN1_UTCTIME_dup := LoadLibFunction(ADllHandle, ASN1_UTCTIME_dup_procname);
  FuncLoadError := not assigned(ASN1_UTCTIME_dup);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_UTCTIME_dup_allownil)}
    ASN1_UTCTIME_dup := ERR_ASN1_UTCTIME_dup;
    {$ifend}
    {$if declared(ASN1_UTCTIME_dup_introduced)}
    if LibVersion < ASN1_UTCTIME_dup_introduced then
    begin
      {$if declared(FC_ASN1_UTCTIME_dup)}
      ASN1_UTCTIME_dup := FC_ASN1_UTCTIME_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_UTCTIME_dup_removed)}
    if ASN1_UTCTIME_dup_removed <= LibVersion then
    begin
      {$if declared(_ASN1_UTCTIME_dup)}
      ASN1_UTCTIME_dup := _ASN1_UTCTIME_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_UTCTIME_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_UTCTIME_dup');
    {$ifend}
  end;
  
  ASN1_GENERALIZEDTIME_dup := LoadLibFunction(ADllHandle, ASN1_GENERALIZEDTIME_dup_procname);
  FuncLoadError := not assigned(ASN1_GENERALIZEDTIME_dup);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_GENERALIZEDTIME_dup_allownil)}
    ASN1_GENERALIZEDTIME_dup := ERR_ASN1_GENERALIZEDTIME_dup;
    {$ifend}
    {$if declared(ASN1_GENERALIZEDTIME_dup_introduced)}
    if LibVersion < ASN1_GENERALIZEDTIME_dup_introduced then
    begin
      {$if declared(FC_ASN1_GENERALIZEDTIME_dup)}
      ASN1_GENERALIZEDTIME_dup := FC_ASN1_GENERALIZEDTIME_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_GENERALIZEDTIME_dup_removed)}
    if ASN1_GENERALIZEDTIME_dup_removed <= LibVersion then
    begin
      {$if declared(_ASN1_GENERALIZEDTIME_dup)}
      ASN1_GENERALIZEDTIME_dup := _ASN1_GENERALIZEDTIME_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_GENERALIZEDTIME_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_GENERALIZEDTIME_dup');
    {$ifend}
  end;
  
  ASN1_OCTET_STRING_NDEF_it := LoadLibFunction(ADllHandle, ASN1_OCTET_STRING_NDEF_it_procname);
  FuncLoadError := not assigned(ASN1_OCTET_STRING_NDEF_it);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_OCTET_STRING_NDEF_it_allownil)}
    ASN1_OCTET_STRING_NDEF_it := ERR_ASN1_OCTET_STRING_NDEF_it;
    {$ifend}
    {$if declared(ASN1_OCTET_STRING_NDEF_it_introduced)}
    if LibVersion < ASN1_OCTET_STRING_NDEF_it_introduced then
    begin
      {$if declared(FC_ASN1_OCTET_STRING_NDEF_it)}
      ASN1_OCTET_STRING_NDEF_it := FC_ASN1_OCTET_STRING_NDEF_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_OCTET_STRING_NDEF_it_removed)}
    if ASN1_OCTET_STRING_NDEF_it_removed <= LibVersion then
    begin
      {$if declared(_ASN1_OCTET_STRING_NDEF_it)}
      ASN1_OCTET_STRING_NDEF_it := _ASN1_OCTET_STRING_NDEF_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_OCTET_STRING_NDEF_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_OCTET_STRING_NDEF_it');
    {$ifend}
  end;
  
  ASN1_TIME_set := LoadLibFunction(ADllHandle, ASN1_TIME_set_procname);
  FuncLoadError := not assigned(ASN1_TIME_set);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TIME_set_allownil)}
    ASN1_TIME_set := ERR_ASN1_TIME_set;
    {$ifend}
    {$if declared(ASN1_TIME_set_introduced)}
    if LibVersion < ASN1_TIME_set_introduced then
    begin
      {$if declared(FC_ASN1_TIME_set)}
      ASN1_TIME_set := FC_ASN1_TIME_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TIME_set_removed)}
    if ASN1_TIME_set_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TIME_set)}
      ASN1_TIME_set := _ASN1_TIME_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TIME_set_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TIME_set');
    {$ifend}
  end;
  
  ASN1_TIME_adj := LoadLibFunction(ADllHandle, ASN1_TIME_adj_procname);
  FuncLoadError := not assigned(ASN1_TIME_adj);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TIME_adj_allownil)}
    ASN1_TIME_adj := ERR_ASN1_TIME_adj;
    {$ifend}
    {$if declared(ASN1_TIME_adj_introduced)}
    if LibVersion < ASN1_TIME_adj_introduced then
    begin
      {$if declared(FC_ASN1_TIME_adj)}
      ASN1_TIME_adj := FC_ASN1_TIME_adj;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TIME_adj_removed)}
    if ASN1_TIME_adj_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TIME_adj)}
      ASN1_TIME_adj := _ASN1_TIME_adj;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TIME_adj_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TIME_adj');
    {$ifend}
  end;
  
  ASN1_TIME_check := LoadLibFunction(ADllHandle, ASN1_TIME_check_procname);
  FuncLoadError := not assigned(ASN1_TIME_check);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TIME_check_allownil)}
    ASN1_TIME_check := ERR_ASN1_TIME_check;
    {$ifend}
    {$if declared(ASN1_TIME_check_introduced)}
    if LibVersion < ASN1_TIME_check_introduced then
    begin
      {$if declared(FC_ASN1_TIME_check)}
      ASN1_TIME_check := FC_ASN1_TIME_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TIME_check_removed)}
    if ASN1_TIME_check_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TIME_check)}
      ASN1_TIME_check := _ASN1_TIME_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TIME_check_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TIME_check');
    {$ifend}
  end;
  
  ASN1_TIME_to_generalizedtime := LoadLibFunction(ADllHandle, ASN1_TIME_to_generalizedtime_procname);
  FuncLoadError := not assigned(ASN1_TIME_to_generalizedtime);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TIME_to_generalizedtime_allownil)}
    ASN1_TIME_to_generalizedtime := ERR_ASN1_TIME_to_generalizedtime;
    {$ifend}
    {$if declared(ASN1_TIME_to_generalizedtime_introduced)}
    if LibVersion < ASN1_TIME_to_generalizedtime_introduced then
    begin
      {$if declared(FC_ASN1_TIME_to_generalizedtime)}
      ASN1_TIME_to_generalizedtime := FC_ASN1_TIME_to_generalizedtime;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TIME_to_generalizedtime_removed)}
    if ASN1_TIME_to_generalizedtime_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TIME_to_generalizedtime)}
      ASN1_TIME_to_generalizedtime := _ASN1_TIME_to_generalizedtime;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TIME_to_generalizedtime_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TIME_to_generalizedtime');
    {$ifend}
  end;
  
  ASN1_TIME_set_string := LoadLibFunction(ADllHandle, ASN1_TIME_set_string_procname);
  FuncLoadError := not assigned(ASN1_TIME_set_string);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TIME_set_string_allownil)}
    ASN1_TIME_set_string := ERR_ASN1_TIME_set_string;
    {$ifend}
    {$if declared(ASN1_TIME_set_string_introduced)}
    if LibVersion < ASN1_TIME_set_string_introduced then
    begin
      {$if declared(FC_ASN1_TIME_set_string)}
      ASN1_TIME_set_string := FC_ASN1_TIME_set_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TIME_set_string_removed)}
    if ASN1_TIME_set_string_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TIME_set_string)}
      ASN1_TIME_set_string := _ASN1_TIME_set_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TIME_set_string_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TIME_set_string');
    {$ifend}
  end;
  
  ASN1_TIME_set_string_X509 := LoadLibFunction(ADllHandle, ASN1_TIME_set_string_X509_procname);
  FuncLoadError := not assigned(ASN1_TIME_set_string_X509);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TIME_set_string_X509_allownil)}
    ASN1_TIME_set_string_X509 := ERR_ASN1_TIME_set_string_X509;
    {$ifend}
    {$if declared(ASN1_TIME_set_string_X509_introduced)}
    if LibVersion < ASN1_TIME_set_string_X509_introduced then
    begin
      {$if declared(FC_ASN1_TIME_set_string_X509)}
      ASN1_TIME_set_string_X509 := FC_ASN1_TIME_set_string_X509;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TIME_set_string_X509_removed)}
    if ASN1_TIME_set_string_X509_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TIME_set_string_X509)}
      ASN1_TIME_set_string_X509 := _ASN1_TIME_set_string_X509;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TIME_set_string_X509_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TIME_set_string_X509');
    {$ifend}
  end;
  
  ASN1_TIME_to_tm := LoadLibFunction(ADllHandle, ASN1_TIME_to_tm_procname);
  FuncLoadError := not assigned(ASN1_TIME_to_tm);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TIME_to_tm_allownil)}
    ASN1_TIME_to_tm := ERR_ASN1_TIME_to_tm;
    {$ifend}
    {$if declared(ASN1_TIME_to_tm_introduced)}
    if LibVersion < ASN1_TIME_to_tm_introduced then
    begin
      {$if declared(FC_ASN1_TIME_to_tm)}
      ASN1_TIME_to_tm := FC_ASN1_TIME_to_tm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TIME_to_tm_removed)}
    if ASN1_TIME_to_tm_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TIME_to_tm)}
      ASN1_TIME_to_tm := _ASN1_TIME_to_tm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TIME_to_tm_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TIME_to_tm');
    {$ifend}
  end;
  
  ASN1_TIME_normalize := LoadLibFunction(ADllHandle, ASN1_TIME_normalize_procname);
  FuncLoadError := not assigned(ASN1_TIME_normalize);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TIME_normalize_allownil)}
    ASN1_TIME_normalize := ERR_ASN1_TIME_normalize;
    {$ifend}
    {$if declared(ASN1_TIME_normalize_introduced)}
    if LibVersion < ASN1_TIME_normalize_introduced then
    begin
      {$if declared(FC_ASN1_TIME_normalize)}
      ASN1_TIME_normalize := FC_ASN1_TIME_normalize;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TIME_normalize_removed)}
    if ASN1_TIME_normalize_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TIME_normalize)}
      ASN1_TIME_normalize := _ASN1_TIME_normalize;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TIME_normalize_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TIME_normalize');
    {$ifend}
  end;
  
  ASN1_TIME_cmp_time_t := LoadLibFunction(ADllHandle, ASN1_TIME_cmp_time_t_procname);
  FuncLoadError := not assigned(ASN1_TIME_cmp_time_t);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TIME_cmp_time_t_allownil)}
    ASN1_TIME_cmp_time_t := ERR_ASN1_TIME_cmp_time_t;
    {$ifend}
    {$if declared(ASN1_TIME_cmp_time_t_introduced)}
    if LibVersion < ASN1_TIME_cmp_time_t_introduced then
    begin
      {$if declared(FC_ASN1_TIME_cmp_time_t)}
      ASN1_TIME_cmp_time_t := FC_ASN1_TIME_cmp_time_t;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TIME_cmp_time_t_removed)}
    if ASN1_TIME_cmp_time_t_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TIME_cmp_time_t)}
      ASN1_TIME_cmp_time_t := _ASN1_TIME_cmp_time_t;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TIME_cmp_time_t_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TIME_cmp_time_t');
    {$ifend}
  end;
  
  ASN1_TIME_compare := LoadLibFunction(ADllHandle, ASN1_TIME_compare_procname);
  FuncLoadError := not assigned(ASN1_TIME_compare);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TIME_compare_allownil)}
    ASN1_TIME_compare := ERR_ASN1_TIME_compare;
    {$ifend}
    {$if declared(ASN1_TIME_compare_introduced)}
    if LibVersion < ASN1_TIME_compare_introduced then
    begin
      {$if declared(FC_ASN1_TIME_compare)}
      ASN1_TIME_compare := FC_ASN1_TIME_compare;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TIME_compare_removed)}
    if ASN1_TIME_compare_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TIME_compare)}
      ASN1_TIME_compare := _ASN1_TIME_compare;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TIME_compare_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TIME_compare');
    {$ifend}
  end;
  
  i2a_ASN1_INTEGER := LoadLibFunction(ADllHandle, i2a_ASN1_INTEGER_procname);
  FuncLoadError := not assigned(i2a_ASN1_INTEGER);
  if FuncLoadError then
  begin
    {$if not defined(i2a_ASN1_INTEGER_allownil)}
    i2a_ASN1_INTEGER := ERR_i2a_ASN1_INTEGER;
    {$ifend}
    {$if declared(i2a_ASN1_INTEGER_introduced)}
    if LibVersion < i2a_ASN1_INTEGER_introduced then
    begin
      {$if declared(FC_i2a_ASN1_INTEGER)}
      i2a_ASN1_INTEGER := FC_i2a_ASN1_INTEGER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2a_ASN1_INTEGER_removed)}
    if i2a_ASN1_INTEGER_removed <= LibVersion then
    begin
      {$if declared(_i2a_ASN1_INTEGER)}
      i2a_ASN1_INTEGER := _i2a_ASN1_INTEGER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2a_ASN1_INTEGER_allownil)}
    if FuncLoadError then
      AFailed.Add('i2a_ASN1_INTEGER');
    {$ifend}
  end;
  
  a2i_ASN1_INTEGER := LoadLibFunction(ADllHandle, a2i_ASN1_INTEGER_procname);
  FuncLoadError := not assigned(a2i_ASN1_INTEGER);
  if FuncLoadError then
  begin
    {$if not defined(a2i_ASN1_INTEGER_allownil)}
    a2i_ASN1_INTEGER := ERR_a2i_ASN1_INTEGER;
    {$ifend}
    {$if declared(a2i_ASN1_INTEGER_introduced)}
    if LibVersion < a2i_ASN1_INTEGER_introduced then
    begin
      {$if declared(FC_a2i_ASN1_INTEGER)}
      a2i_ASN1_INTEGER := FC_a2i_ASN1_INTEGER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(a2i_ASN1_INTEGER_removed)}
    if a2i_ASN1_INTEGER_removed <= LibVersion then
    begin
      {$if declared(_a2i_ASN1_INTEGER)}
      a2i_ASN1_INTEGER := _a2i_ASN1_INTEGER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(a2i_ASN1_INTEGER_allownil)}
    if FuncLoadError then
      AFailed.Add('a2i_ASN1_INTEGER');
    {$ifend}
  end;
  
  i2a_ASN1_ENUMERATED := LoadLibFunction(ADllHandle, i2a_ASN1_ENUMERATED_procname);
  FuncLoadError := not assigned(i2a_ASN1_ENUMERATED);
  if FuncLoadError then
  begin
    {$if not defined(i2a_ASN1_ENUMERATED_allownil)}
    i2a_ASN1_ENUMERATED := ERR_i2a_ASN1_ENUMERATED;
    {$ifend}
    {$if declared(i2a_ASN1_ENUMERATED_introduced)}
    if LibVersion < i2a_ASN1_ENUMERATED_introduced then
    begin
      {$if declared(FC_i2a_ASN1_ENUMERATED)}
      i2a_ASN1_ENUMERATED := FC_i2a_ASN1_ENUMERATED;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2a_ASN1_ENUMERATED_removed)}
    if i2a_ASN1_ENUMERATED_removed <= LibVersion then
    begin
      {$if declared(_i2a_ASN1_ENUMERATED)}
      i2a_ASN1_ENUMERATED := _i2a_ASN1_ENUMERATED;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2a_ASN1_ENUMERATED_allownil)}
    if FuncLoadError then
      AFailed.Add('i2a_ASN1_ENUMERATED');
    {$ifend}
  end;
  
  a2i_ASN1_ENUMERATED := LoadLibFunction(ADllHandle, a2i_ASN1_ENUMERATED_procname);
  FuncLoadError := not assigned(a2i_ASN1_ENUMERATED);
  if FuncLoadError then
  begin
    {$if not defined(a2i_ASN1_ENUMERATED_allownil)}
    a2i_ASN1_ENUMERATED := ERR_a2i_ASN1_ENUMERATED;
    {$ifend}
    {$if declared(a2i_ASN1_ENUMERATED_introduced)}
    if LibVersion < a2i_ASN1_ENUMERATED_introduced then
    begin
      {$if declared(FC_a2i_ASN1_ENUMERATED)}
      a2i_ASN1_ENUMERATED := FC_a2i_ASN1_ENUMERATED;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(a2i_ASN1_ENUMERATED_removed)}
    if a2i_ASN1_ENUMERATED_removed <= LibVersion then
    begin
      {$if declared(_a2i_ASN1_ENUMERATED)}
      a2i_ASN1_ENUMERATED := _a2i_ASN1_ENUMERATED;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(a2i_ASN1_ENUMERATED_allownil)}
    if FuncLoadError then
      AFailed.Add('a2i_ASN1_ENUMERATED');
    {$ifend}
  end;
  
  i2a_ASN1_OBJECT := LoadLibFunction(ADllHandle, i2a_ASN1_OBJECT_procname);
  FuncLoadError := not assigned(i2a_ASN1_OBJECT);
  if FuncLoadError then
  begin
    {$if not defined(i2a_ASN1_OBJECT_allownil)}
    i2a_ASN1_OBJECT := ERR_i2a_ASN1_OBJECT;
    {$ifend}
    {$if declared(i2a_ASN1_OBJECT_introduced)}
    if LibVersion < i2a_ASN1_OBJECT_introduced then
    begin
      {$if declared(FC_i2a_ASN1_OBJECT)}
      i2a_ASN1_OBJECT := FC_i2a_ASN1_OBJECT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2a_ASN1_OBJECT_removed)}
    if i2a_ASN1_OBJECT_removed <= LibVersion then
    begin
      {$if declared(_i2a_ASN1_OBJECT)}
      i2a_ASN1_OBJECT := _i2a_ASN1_OBJECT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2a_ASN1_OBJECT_allownil)}
    if FuncLoadError then
      AFailed.Add('i2a_ASN1_OBJECT');
    {$ifend}
  end;
  
  a2i_ASN1_STRING := LoadLibFunction(ADllHandle, a2i_ASN1_STRING_procname);
  FuncLoadError := not assigned(a2i_ASN1_STRING);
  if FuncLoadError then
  begin
    {$if not defined(a2i_ASN1_STRING_allownil)}
    a2i_ASN1_STRING := ERR_a2i_ASN1_STRING;
    {$ifend}
    {$if declared(a2i_ASN1_STRING_introduced)}
    if LibVersion < a2i_ASN1_STRING_introduced then
    begin
      {$if declared(FC_a2i_ASN1_STRING)}
      a2i_ASN1_STRING := FC_a2i_ASN1_STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(a2i_ASN1_STRING_removed)}
    if a2i_ASN1_STRING_removed <= LibVersion then
    begin
      {$if declared(_a2i_ASN1_STRING)}
      a2i_ASN1_STRING := _a2i_ASN1_STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(a2i_ASN1_STRING_allownil)}
    if FuncLoadError then
      AFailed.Add('a2i_ASN1_STRING');
    {$ifend}
  end;
  
  i2a_ASN1_STRING := LoadLibFunction(ADllHandle, i2a_ASN1_STRING_procname);
  FuncLoadError := not assigned(i2a_ASN1_STRING);
  if FuncLoadError then
  begin
    {$if not defined(i2a_ASN1_STRING_allownil)}
    i2a_ASN1_STRING := ERR_i2a_ASN1_STRING;
    {$ifend}
    {$if declared(i2a_ASN1_STRING_introduced)}
    if LibVersion < i2a_ASN1_STRING_introduced then
    begin
      {$if declared(FC_i2a_ASN1_STRING)}
      i2a_ASN1_STRING := FC_i2a_ASN1_STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2a_ASN1_STRING_removed)}
    if i2a_ASN1_STRING_removed <= LibVersion then
    begin
      {$if declared(_i2a_ASN1_STRING)}
      i2a_ASN1_STRING := _i2a_ASN1_STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2a_ASN1_STRING_allownil)}
    if FuncLoadError then
      AFailed.Add('i2a_ASN1_STRING');
    {$ifend}
  end;
  
  i2t_ASN1_OBJECT := LoadLibFunction(ADllHandle, i2t_ASN1_OBJECT_procname);
  FuncLoadError := not assigned(i2t_ASN1_OBJECT);
  if FuncLoadError then
  begin
    {$if not defined(i2t_ASN1_OBJECT_allownil)}
    i2t_ASN1_OBJECT := ERR_i2t_ASN1_OBJECT;
    {$ifend}
    {$if declared(i2t_ASN1_OBJECT_introduced)}
    if LibVersion < i2t_ASN1_OBJECT_introduced then
    begin
      {$if declared(FC_i2t_ASN1_OBJECT)}
      i2t_ASN1_OBJECT := FC_i2t_ASN1_OBJECT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2t_ASN1_OBJECT_removed)}
    if i2t_ASN1_OBJECT_removed <= LibVersion then
    begin
      {$if declared(_i2t_ASN1_OBJECT)}
      i2t_ASN1_OBJECT := _i2t_ASN1_OBJECT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2t_ASN1_OBJECT_allownil)}
    if FuncLoadError then
      AFailed.Add('i2t_ASN1_OBJECT');
    {$ifend}
  end;
  
  a2d_ASN1_OBJECT := LoadLibFunction(ADllHandle, a2d_ASN1_OBJECT_procname);
  FuncLoadError := not assigned(a2d_ASN1_OBJECT);
  if FuncLoadError then
  begin
    {$if not defined(a2d_ASN1_OBJECT_allownil)}
    a2d_ASN1_OBJECT := ERR_a2d_ASN1_OBJECT;
    {$ifend}
    {$if declared(a2d_ASN1_OBJECT_introduced)}
    if LibVersion < a2d_ASN1_OBJECT_introduced then
    begin
      {$if declared(FC_a2d_ASN1_OBJECT)}
      a2d_ASN1_OBJECT := FC_a2d_ASN1_OBJECT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(a2d_ASN1_OBJECT_removed)}
    if a2d_ASN1_OBJECT_removed <= LibVersion then
    begin
      {$if declared(_a2d_ASN1_OBJECT)}
      a2d_ASN1_OBJECT := _a2d_ASN1_OBJECT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(a2d_ASN1_OBJECT_allownil)}
    if FuncLoadError then
      AFailed.Add('a2d_ASN1_OBJECT');
    {$ifend}
  end;
  
  ASN1_OBJECT_create := LoadLibFunction(ADllHandle, ASN1_OBJECT_create_procname);
  FuncLoadError := not assigned(ASN1_OBJECT_create);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_OBJECT_create_allownil)}
    ASN1_OBJECT_create := ERR_ASN1_OBJECT_create;
    {$ifend}
    {$if declared(ASN1_OBJECT_create_introduced)}
    if LibVersion < ASN1_OBJECT_create_introduced then
    begin
      {$if declared(FC_ASN1_OBJECT_create)}
      ASN1_OBJECT_create := FC_ASN1_OBJECT_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_OBJECT_create_removed)}
    if ASN1_OBJECT_create_removed <= LibVersion then
    begin
      {$if declared(_ASN1_OBJECT_create)}
      ASN1_OBJECT_create := _ASN1_OBJECT_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_OBJECT_create_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_OBJECT_create');
    {$ifend}
  end;
  
  ASN1_INTEGER_get_int64 := LoadLibFunction(ADllHandle, ASN1_INTEGER_get_int64_procname);
  FuncLoadError := not assigned(ASN1_INTEGER_get_int64);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_INTEGER_get_int64_allownil)}
    ASN1_INTEGER_get_int64 := ERR_ASN1_INTEGER_get_int64;
    {$ifend}
    {$if declared(ASN1_INTEGER_get_int64_introduced)}
    if LibVersion < ASN1_INTEGER_get_int64_introduced then
    begin
      {$if declared(FC_ASN1_INTEGER_get_int64)}
      ASN1_INTEGER_get_int64 := FC_ASN1_INTEGER_get_int64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_INTEGER_get_int64_removed)}
    if ASN1_INTEGER_get_int64_removed <= LibVersion then
    begin
      {$if declared(_ASN1_INTEGER_get_int64)}
      ASN1_INTEGER_get_int64 := _ASN1_INTEGER_get_int64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_INTEGER_get_int64_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_INTEGER_get_int64');
    {$ifend}
  end;
  
  ASN1_INTEGER_set_int64 := LoadLibFunction(ADllHandle, ASN1_INTEGER_set_int64_procname);
  FuncLoadError := not assigned(ASN1_INTEGER_set_int64);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_INTEGER_set_int64_allownil)}
    ASN1_INTEGER_set_int64 := ERR_ASN1_INTEGER_set_int64;
    {$ifend}
    {$if declared(ASN1_INTEGER_set_int64_introduced)}
    if LibVersion < ASN1_INTEGER_set_int64_introduced then
    begin
      {$if declared(FC_ASN1_INTEGER_set_int64)}
      ASN1_INTEGER_set_int64 := FC_ASN1_INTEGER_set_int64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_INTEGER_set_int64_removed)}
    if ASN1_INTEGER_set_int64_removed <= LibVersion then
    begin
      {$if declared(_ASN1_INTEGER_set_int64)}
      ASN1_INTEGER_set_int64 := _ASN1_INTEGER_set_int64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_INTEGER_set_int64_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_INTEGER_set_int64');
    {$ifend}
  end;
  
  ASN1_INTEGER_get_uint64 := LoadLibFunction(ADllHandle, ASN1_INTEGER_get_uint64_procname);
  FuncLoadError := not assigned(ASN1_INTEGER_get_uint64);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_INTEGER_get_uint64_allownil)}
    ASN1_INTEGER_get_uint64 := ERR_ASN1_INTEGER_get_uint64;
    {$ifend}
    {$if declared(ASN1_INTEGER_get_uint64_introduced)}
    if LibVersion < ASN1_INTEGER_get_uint64_introduced then
    begin
      {$if declared(FC_ASN1_INTEGER_get_uint64)}
      ASN1_INTEGER_get_uint64 := FC_ASN1_INTEGER_get_uint64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_INTEGER_get_uint64_removed)}
    if ASN1_INTEGER_get_uint64_removed <= LibVersion then
    begin
      {$if declared(_ASN1_INTEGER_get_uint64)}
      ASN1_INTEGER_get_uint64 := _ASN1_INTEGER_get_uint64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_INTEGER_get_uint64_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_INTEGER_get_uint64');
    {$ifend}
  end;
  
  ASN1_INTEGER_set_uint64 := LoadLibFunction(ADllHandle, ASN1_INTEGER_set_uint64_procname);
  FuncLoadError := not assigned(ASN1_INTEGER_set_uint64);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_INTEGER_set_uint64_allownil)}
    ASN1_INTEGER_set_uint64 := ERR_ASN1_INTEGER_set_uint64;
    {$ifend}
    {$if declared(ASN1_INTEGER_set_uint64_introduced)}
    if LibVersion < ASN1_INTEGER_set_uint64_introduced then
    begin
      {$if declared(FC_ASN1_INTEGER_set_uint64)}
      ASN1_INTEGER_set_uint64 := FC_ASN1_INTEGER_set_uint64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_INTEGER_set_uint64_removed)}
    if ASN1_INTEGER_set_uint64_removed <= LibVersion then
    begin
      {$if declared(_ASN1_INTEGER_set_uint64)}
      ASN1_INTEGER_set_uint64 := _ASN1_INTEGER_set_uint64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_INTEGER_set_uint64_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_INTEGER_set_uint64');
    {$ifend}
  end;
  
  ASN1_INTEGER_set := LoadLibFunction(ADllHandle, ASN1_INTEGER_set_procname);
  FuncLoadError := not assigned(ASN1_INTEGER_set);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_INTEGER_set_allownil)}
    ASN1_INTEGER_set := ERR_ASN1_INTEGER_set;
    {$ifend}
    {$if declared(ASN1_INTEGER_set_introduced)}
    if LibVersion < ASN1_INTEGER_set_introduced then
    begin
      {$if declared(FC_ASN1_INTEGER_set)}
      ASN1_INTEGER_set := FC_ASN1_INTEGER_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_INTEGER_set_removed)}
    if ASN1_INTEGER_set_removed <= LibVersion then
    begin
      {$if declared(_ASN1_INTEGER_set)}
      ASN1_INTEGER_set := _ASN1_INTEGER_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_INTEGER_set_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_INTEGER_set');
    {$ifend}
  end;
  
  ASN1_INTEGER_get := LoadLibFunction(ADllHandle, ASN1_INTEGER_get_procname);
  FuncLoadError := not assigned(ASN1_INTEGER_get);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_INTEGER_get_allownil)}
    ASN1_INTEGER_get := ERR_ASN1_INTEGER_get;
    {$ifend}
    {$if declared(ASN1_INTEGER_get_introduced)}
    if LibVersion < ASN1_INTEGER_get_introduced then
    begin
      {$if declared(FC_ASN1_INTEGER_get)}
      ASN1_INTEGER_get := FC_ASN1_INTEGER_get;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_INTEGER_get_removed)}
    if ASN1_INTEGER_get_removed <= LibVersion then
    begin
      {$if declared(_ASN1_INTEGER_get)}
      ASN1_INTEGER_get := _ASN1_INTEGER_get;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_INTEGER_get_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_INTEGER_get');
    {$ifend}
  end;
  
  BN_to_ASN1_INTEGER := LoadLibFunction(ADllHandle, BN_to_ASN1_INTEGER_procname);
  FuncLoadError := not assigned(BN_to_ASN1_INTEGER);
  if FuncLoadError then
  begin
    {$if not defined(BN_to_ASN1_INTEGER_allownil)}
    BN_to_ASN1_INTEGER := ERR_BN_to_ASN1_INTEGER;
    {$ifend}
    {$if declared(BN_to_ASN1_INTEGER_introduced)}
    if LibVersion < BN_to_ASN1_INTEGER_introduced then
    begin
      {$if declared(FC_BN_to_ASN1_INTEGER)}
      BN_to_ASN1_INTEGER := FC_BN_to_ASN1_INTEGER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_to_ASN1_INTEGER_removed)}
    if BN_to_ASN1_INTEGER_removed <= LibVersion then
    begin
      {$if declared(_BN_to_ASN1_INTEGER)}
      BN_to_ASN1_INTEGER := _BN_to_ASN1_INTEGER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_to_ASN1_INTEGER_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_to_ASN1_INTEGER');
    {$ifend}
  end;
  
  ASN1_INTEGER_to_BN := LoadLibFunction(ADllHandle, ASN1_INTEGER_to_BN_procname);
  FuncLoadError := not assigned(ASN1_INTEGER_to_BN);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_INTEGER_to_BN_allownil)}
    ASN1_INTEGER_to_BN := ERR_ASN1_INTEGER_to_BN;
    {$ifend}
    {$if declared(ASN1_INTEGER_to_BN_introduced)}
    if LibVersion < ASN1_INTEGER_to_BN_introduced then
    begin
      {$if declared(FC_ASN1_INTEGER_to_BN)}
      ASN1_INTEGER_to_BN := FC_ASN1_INTEGER_to_BN;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_INTEGER_to_BN_removed)}
    if ASN1_INTEGER_to_BN_removed <= LibVersion then
    begin
      {$if declared(_ASN1_INTEGER_to_BN)}
      ASN1_INTEGER_to_BN := _ASN1_INTEGER_to_BN;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_INTEGER_to_BN_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_INTEGER_to_BN');
    {$ifend}
  end;
  
  ASN1_ENUMERATED_get_int64 := LoadLibFunction(ADllHandle, ASN1_ENUMERATED_get_int64_procname);
  FuncLoadError := not assigned(ASN1_ENUMERATED_get_int64);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_ENUMERATED_get_int64_allownil)}
    ASN1_ENUMERATED_get_int64 := ERR_ASN1_ENUMERATED_get_int64;
    {$ifend}
    {$if declared(ASN1_ENUMERATED_get_int64_introduced)}
    if LibVersion < ASN1_ENUMERATED_get_int64_introduced then
    begin
      {$if declared(FC_ASN1_ENUMERATED_get_int64)}
      ASN1_ENUMERATED_get_int64 := FC_ASN1_ENUMERATED_get_int64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_ENUMERATED_get_int64_removed)}
    if ASN1_ENUMERATED_get_int64_removed <= LibVersion then
    begin
      {$if declared(_ASN1_ENUMERATED_get_int64)}
      ASN1_ENUMERATED_get_int64 := _ASN1_ENUMERATED_get_int64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_ENUMERATED_get_int64_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_ENUMERATED_get_int64');
    {$ifend}
  end;
  
  ASN1_ENUMERATED_set_int64 := LoadLibFunction(ADllHandle, ASN1_ENUMERATED_set_int64_procname);
  FuncLoadError := not assigned(ASN1_ENUMERATED_set_int64);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_ENUMERATED_set_int64_allownil)}
    ASN1_ENUMERATED_set_int64 := ERR_ASN1_ENUMERATED_set_int64;
    {$ifend}
    {$if declared(ASN1_ENUMERATED_set_int64_introduced)}
    if LibVersion < ASN1_ENUMERATED_set_int64_introduced then
    begin
      {$if declared(FC_ASN1_ENUMERATED_set_int64)}
      ASN1_ENUMERATED_set_int64 := FC_ASN1_ENUMERATED_set_int64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_ENUMERATED_set_int64_removed)}
    if ASN1_ENUMERATED_set_int64_removed <= LibVersion then
    begin
      {$if declared(_ASN1_ENUMERATED_set_int64)}
      ASN1_ENUMERATED_set_int64 := _ASN1_ENUMERATED_set_int64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_ENUMERATED_set_int64_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_ENUMERATED_set_int64');
    {$ifend}
  end;
  
  ASN1_ENUMERATED_set := LoadLibFunction(ADllHandle, ASN1_ENUMERATED_set_procname);
  FuncLoadError := not assigned(ASN1_ENUMERATED_set);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_ENUMERATED_set_allownil)}
    ASN1_ENUMERATED_set := ERR_ASN1_ENUMERATED_set;
    {$ifend}
    {$if declared(ASN1_ENUMERATED_set_introduced)}
    if LibVersion < ASN1_ENUMERATED_set_introduced then
    begin
      {$if declared(FC_ASN1_ENUMERATED_set)}
      ASN1_ENUMERATED_set := FC_ASN1_ENUMERATED_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_ENUMERATED_set_removed)}
    if ASN1_ENUMERATED_set_removed <= LibVersion then
    begin
      {$if declared(_ASN1_ENUMERATED_set)}
      ASN1_ENUMERATED_set := _ASN1_ENUMERATED_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_ENUMERATED_set_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_ENUMERATED_set');
    {$ifend}
  end;
  
  ASN1_ENUMERATED_get := LoadLibFunction(ADllHandle, ASN1_ENUMERATED_get_procname);
  FuncLoadError := not assigned(ASN1_ENUMERATED_get);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_ENUMERATED_get_allownil)}
    ASN1_ENUMERATED_get := ERR_ASN1_ENUMERATED_get;
    {$ifend}
    {$if declared(ASN1_ENUMERATED_get_introduced)}
    if LibVersion < ASN1_ENUMERATED_get_introduced then
    begin
      {$if declared(FC_ASN1_ENUMERATED_get)}
      ASN1_ENUMERATED_get := FC_ASN1_ENUMERATED_get;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_ENUMERATED_get_removed)}
    if ASN1_ENUMERATED_get_removed <= LibVersion then
    begin
      {$if declared(_ASN1_ENUMERATED_get)}
      ASN1_ENUMERATED_get := _ASN1_ENUMERATED_get;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_ENUMERATED_get_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_ENUMERATED_get');
    {$ifend}
  end;
  
  BN_to_ASN1_ENUMERATED := LoadLibFunction(ADllHandle, BN_to_ASN1_ENUMERATED_procname);
  FuncLoadError := not assigned(BN_to_ASN1_ENUMERATED);
  if FuncLoadError then
  begin
    {$if not defined(BN_to_ASN1_ENUMERATED_allownil)}
    BN_to_ASN1_ENUMERATED := ERR_BN_to_ASN1_ENUMERATED;
    {$ifend}
    {$if declared(BN_to_ASN1_ENUMERATED_introduced)}
    if LibVersion < BN_to_ASN1_ENUMERATED_introduced then
    begin
      {$if declared(FC_BN_to_ASN1_ENUMERATED)}
      BN_to_ASN1_ENUMERATED := FC_BN_to_ASN1_ENUMERATED;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BN_to_ASN1_ENUMERATED_removed)}
    if BN_to_ASN1_ENUMERATED_removed <= LibVersion then
    begin
      {$if declared(_BN_to_ASN1_ENUMERATED)}
      BN_to_ASN1_ENUMERATED := _BN_to_ASN1_ENUMERATED;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BN_to_ASN1_ENUMERATED_allownil)}
    if FuncLoadError then
      AFailed.Add('BN_to_ASN1_ENUMERATED');
    {$ifend}
  end;
  
  ASN1_ENUMERATED_to_BN := LoadLibFunction(ADllHandle, ASN1_ENUMERATED_to_BN_procname);
  FuncLoadError := not assigned(ASN1_ENUMERATED_to_BN);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_ENUMERATED_to_BN_allownil)}
    ASN1_ENUMERATED_to_BN := ERR_ASN1_ENUMERATED_to_BN;
    {$ifend}
    {$if declared(ASN1_ENUMERATED_to_BN_introduced)}
    if LibVersion < ASN1_ENUMERATED_to_BN_introduced then
    begin
      {$if declared(FC_ASN1_ENUMERATED_to_BN)}
      ASN1_ENUMERATED_to_BN := FC_ASN1_ENUMERATED_to_BN;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_ENUMERATED_to_BN_removed)}
    if ASN1_ENUMERATED_to_BN_removed <= LibVersion then
    begin
      {$if declared(_ASN1_ENUMERATED_to_BN)}
      ASN1_ENUMERATED_to_BN := _ASN1_ENUMERATED_to_BN;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_ENUMERATED_to_BN_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_ENUMERATED_to_BN');
    {$ifend}
  end;
  
  ASN1_PRINTABLE_type := LoadLibFunction(ADllHandle, ASN1_PRINTABLE_type_procname);
  FuncLoadError := not assigned(ASN1_PRINTABLE_type);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_PRINTABLE_type_allownil)}
    ASN1_PRINTABLE_type := ERR_ASN1_PRINTABLE_type;
    {$ifend}
    {$if declared(ASN1_PRINTABLE_type_introduced)}
    if LibVersion < ASN1_PRINTABLE_type_introduced then
    begin
      {$if declared(FC_ASN1_PRINTABLE_type)}
      ASN1_PRINTABLE_type := FC_ASN1_PRINTABLE_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_PRINTABLE_type_removed)}
    if ASN1_PRINTABLE_type_removed <= LibVersion then
    begin
      {$if declared(_ASN1_PRINTABLE_type)}
      ASN1_PRINTABLE_type := _ASN1_PRINTABLE_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_PRINTABLE_type_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_PRINTABLE_type');
    {$ifend}
  end;
  
  ASN1_tag2bit := LoadLibFunction(ADllHandle, ASN1_tag2bit_procname);
  FuncLoadError := not assigned(ASN1_tag2bit);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_tag2bit_allownil)}
    ASN1_tag2bit := ERR_ASN1_tag2bit;
    {$ifend}
    {$if declared(ASN1_tag2bit_introduced)}
    if LibVersion < ASN1_tag2bit_introduced then
    begin
      {$if declared(FC_ASN1_tag2bit)}
      ASN1_tag2bit := FC_ASN1_tag2bit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_tag2bit_removed)}
    if ASN1_tag2bit_removed <= LibVersion then
    begin
      {$if declared(_ASN1_tag2bit)}
      ASN1_tag2bit := _ASN1_tag2bit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_tag2bit_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_tag2bit');
    {$ifend}
  end;
  
  ASN1_get_object := LoadLibFunction(ADllHandle, ASN1_get_object_procname);
  FuncLoadError := not assigned(ASN1_get_object);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_get_object_allownil)}
    ASN1_get_object := ERR_ASN1_get_object;
    {$ifend}
    {$if declared(ASN1_get_object_introduced)}
    if LibVersion < ASN1_get_object_introduced then
    begin
      {$if declared(FC_ASN1_get_object)}
      ASN1_get_object := FC_ASN1_get_object;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_get_object_removed)}
    if ASN1_get_object_removed <= LibVersion then
    begin
      {$if declared(_ASN1_get_object)}
      ASN1_get_object := _ASN1_get_object;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_get_object_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_get_object');
    {$ifend}
  end;
  
  ASN1_check_infinite_end := LoadLibFunction(ADllHandle, ASN1_check_infinite_end_procname);
  FuncLoadError := not assigned(ASN1_check_infinite_end);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_check_infinite_end_allownil)}
    ASN1_check_infinite_end := ERR_ASN1_check_infinite_end;
    {$ifend}
    {$if declared(ASN1_check_infinite_end_introduced)}
    if LibVersion < ASN1_check_infinite_end_introduced then
    begin
      {$if declared(FC_ASN1_check_infinite_end)}
      ASN1_check_infinite_end := FC_ASN1_check_infinite_end;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_check_infinite_end_removed)}
    if ASN1_check_infinite_end_removed <= LibVersion then
    begin
      {$if declared(_ASN1_check_infinite_end)}
      ASN1_check_infinite_end := _ASN1_check_infinite_end;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_check_infinite_end_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_check_infinite_end');
    {$ifend}
  end;
  
  ASN1_const_check_infinite_end := LoadLibFunction(ADllHandle, ASN1_const_check_infinite_end_procname);
  FuncLoadError := not assigned(ASN1_const_check_infinite_end);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_const_check_infinite_end_allownil)}
    ASN1_const_check_infinite_end := ERR_ASN1_const_check_infinite_end;
    {$ifend}
    {$if declared(ASN1_const_check_infinite_end_introduced)}
    if LibVersion < ASN1_const_check_infinite_end_introduced then
    begin
      {$if declared(FC_ASN1_const_check_infinite_end)}
      ASN1_const_check_infinite_end := FC_ASN1_const_check_infinite_end;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_const_check_infinite_end_removed)}
    if ASN1_const_check_infinite_end_removed <= LibVersion then
    begin
      {$if declared(_ASN1_const_check_infinite_end)}
      ASN1_const_check_infinite_end := _ASN1_const_check_infinite_end;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_const_check_infinite_end_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_const_check_infinite_end');
    {$ifend}
  end;
  
  ASN1_put_object := LoadLibFunction(ADllHandle, ASN1_put_object_procname);
  FuncLoadError := not assigned(ASN1_put_object);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_put_object_allownil)}
    ASN1_put_object := ERR_ASN1_put_object;
    {$ifend}
    {$if declared(ASN1_put_object_introduced)}
    if LibVersion < ASN1_put_object_introduced then
    begin
      {$if declared(FC_ASN1_put_object)}
      ASN1_put_object := FC_ASN1_put_object;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_put_object_removed)}
    if ASN1_put_object_removed <= LibVersion then
    begin
      {$if declared(_ASN1_put_object)}
      ASN1_put_object := _ASN1_put_object;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_put_object_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_put_object');
    {$ifend}
  end;
  
  ASN1_put_eoc := LoadLibFunction(ADllHandle, ASN1_put_eoc_procname);
  FuncLoadError := not assigned(ASN1_put_eoc);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_put_eoc_allownil)}
    ASN1_put_eoc := ERR_ASN1_put_eoc;
    {$ifend}
    {$if declared(ASN1_put_eoc_introduced)}
    if LibVersion < ASN1_put_eoc_introduced then
    begin
      {$if declared(FC_ASN1_put_eoc)}
      ASN1_put_eoc := FC_ASN1_put_eoc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_put_eoc_removed)}
    if ASN1_put_eoc_removed <= LibVersion then
    begin
      {$if declared(_ASN1_put_eoc)}
      ASN1_put_eoc := _ASN1_put_eoc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_put_eoc_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_put_eoc');
    {$ifend}
  end;
  
  ASN1_object_size := LoadLibFunction(ADllHandle, ASN1_object_size_procname);
  FuncLoadError := not assigned(ASN1_object_size);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_object_size_allownil)}
    ASN1_object_size := ERR_ASN1_object_size;
    {$ifend}
    {$if declared(ASN1_object_size_introduced)}
    if LibVersion < ASN1_object_size_introduced then
    begin
      {$if declared(FC_ASN1_object_size)}
      ASN1_object_size := FC_ASN1_object_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_object_size_removed)}
    if ASN1_object_size_removed <= LibVersion then
    begin
      {$if declared(_ASN1_object_size)}
      ASN1_object_size := _ASN1_object_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_object_size_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_object_size');
    {$ifend}
  end;
  
  ASN1_dup := LoadLibFunction(ADllHandle, ASN1_dup_procname);
  FuncLoadError := not assigned(ASN1_dup);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_dup_allownil)}
    ASN1_dup := ERR_ASN1_dup;
    {$ifend}
    {$if declared(ASN1_dup_introduced)}
    if LibVersion < ASN1_dup_introduced then
    begin
      {$if declared(FC_ASN1_dup)}
      ASN1_dup := FC_ASN1_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_dup_removed)}
    if ASN1_dup_removed <= LibVersion then
    begin
      {$if declared(_ASN1_dup)}
      ASN1_dup := _ASN1_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_dup');
    {$ifend}
  end;
  
  ASN1_item_dup := LoadLibFunction(ADllHandle, ASN1_item_dup_procname);
  FuncLoadError := not assigned(ASN1_item_dup);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_dup_allownil)}
    ASN1_item_dup := ERR_ASN1_item_dup;
    {$ifend}
    {$if declared(ASN1_item_dup_introduced)}
    if LibVersion < ASN1_item_dup_introduced then
    begin
      {$if declared(FC_ASN1_item_dup)}
      ASN1_item_dup := FC_ASN1_item_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_dup_removed)}
    if ASN1_item_dup_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_dup)}
      ASN1_item_dup := _ASN1_item_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_dup');
    {$ifend}
  end;
  
  ASN1_item_sign_ex := LoadLibFunction(ADllHandle, ASN1_item_sign_ex_procname);
  FuncLoadError := not assigned(ASN1_item_sign_ex);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_sign_ex_allownil)}
    ASN1_item_sign_ex := ERR_ASN1_item_sign_ex;
    {$ifend}
    {$if declared(ASN1_item_sign_ex_introduced)}
    if LibVersion < ASN1_item_sign_ex_introduced then
    begin
      {$if declared(FC_ASN1_item_sign_ex)}
      ASN1_item_sign_ex := FC_ASN1_item_sign_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_sign_ex_removed)}
    if ASN1_item_sign_ex_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_sign_ex)}
      ASN1_item_sign_ex := _ASN1_item_sign_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_sign_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_sign_ex');
    {$ifend}
  end;
  
  ASN1_item_verify_ex := LoadLibFunction(ADllHandle, ASN1_item_verify_ex_procname);
  FuncLoadError := not assigned(ASN1_item_verify_ex);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_verify_ex_allownil)}
    ASN1_item_verify_ex := ERR_ASN1_item_verify_ex;
    {$ifend}
    {$if declared(ASN1_item_verify_ex_introduced)}
    if LibVersion < ASN1_item_verify_ex_introduced then
    begin
      {$if declared(FC_ASN1_item_verify_ex)}
      ASN1_item_verify_ex := FC_ASN1_item_verify_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_verify_ex_removed)}
    if ASN1_item_verify_ex_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_verify_ex)}
      ASN1_item_verify_ex := _ASN1_item_verify_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_verify_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_verify_ex');
    {$ifend}
  end;
  
  ASN1_d2i_fp := LoadLibFunction(ADllHandle, ASN1_d2i_fp_procname);
  FuncLoadError := not assigned(ASN1_d2i_fp);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_d2i_fp_allownil)}
    ASN1_d2i_fp := ERR_ASN1_d2i_fp;
    {$ifend}
    {$if declared(ASN1_d2i_fp_introduced)}
    if LibVersion < ASN1_d2i_fp_introduced then
    begin
      {$if declared(FC_ASN1_d2i_fp)}
      ASN1_d2i_fp := FC_ASN1_d2i_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_d2i_fp_removed)}
    if ASN1_d2i_fp_removed <= LibVersion then
    begin
      {$if declared(_ASN1_d2i_fp)}
      ASN1_d2i_fp := _ASN1_d2i_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_d2i_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_d2i_fp');
    {$ifend}
  end;
  
  ASN1_item_d2i_fp_ex := LoadLibFunction(ADllHandle, ASN1_item_d2i_fp_ex_procname);
  FuncLoadError := not assigned(ASN1_item_d2i_fp_ex);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_d2i_fp_ex_allownil)}
    ASN1_item_d2i_fp_ex := ERR_ASN1_item_d2i_fp_ex;
    {$ifend}
    {$if declared(ASN1_item_d2i_fp_ex_introduced)}
    if LibVersion < ASN1_item_d2i_fp_ex_introduced then
    begin
      {$if declared(FC_ASN1_item_d2i_fp_ex)}
      ASN1_item_d2i_fp_ex := FC_ASN1_item_d2i_fp_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_d2i_fp_ex_removed)}
    if ASN1_item_d2i_fp_ex_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_d2i_fp_ex)}
      ASN1_item_d2i_fp_ex := _ASN1_item_d2i_fp_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_d2i_fp_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_d2i_fp_ex');
    {$ifend}
  end;
  
  ASN1_item_d2i_fp := LoadLibFunction(ADllHandle, ASN1_item_d2i_fp_procname);
  FuncLoadError := not assigned(ASN1_item_d2i_fp);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_d2i_fp_allownil)}
    ASN1_item_d2i_fp := ERR_ASN1_item_d2i_fp;
    {$ifend}
    {$if declared(ASN1_item_d2i_fp_introduced)}
    if LibVersion < ASN1_item_d2i_fp_introduced then
    begin
      {$if declared(FC_ASN1_item_d2i_fp)}
      ASN1_item_d2i_fp := FC_ASN1_item_d2i_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_d2i_fp_removed)}
    if ASN1_item_d2i_fp_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_d2i_fp)}
      ASN1_item_d2i_fp := _ASN1_item_d2i_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_d2i_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_d2i_fp');
    {$ifend}
  end;
  
  ASN1_i2d_fp := LoadLibFunction(ADllHandle, ASN1_i2d_fp_procname);
  FuncLoadError := not assigned(ASN1_i2d_fp);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_i2d_fp_allownil)}
    ASN1_i2d_fp := ERR_ASN1_i2d_fp;
    {$ifend}
    {$if declared(ASN1_i2d_fp_introduced)}
    if LibVersion < ASN1_i2d_fp_introduced then
    begin
      {$if declared(FC_ASN1_i2d_fp)}
      ASN1_i2d_fp := FC_ASN1_i2d_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_i2d_fp_removed)}
    if ASN1_i2d_fp_removed <= LibVersion then
    begin
      {$if declared(_ASN1_i2d_fp)}
      ASN1_i2d_fp := _ASN1_i2d_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_i2d_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_i2d_fp');
    {$ifend}
  end;
  
  ASN1_item_i2d_fp := LoadLibFunction(ADllHandle, ASN1_item_i2d_fp_procname);
  FuncLoadError := not assigned(ASN1_item_i2d_fp);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_i2d_fp_allownil)}
    ASN1_item_i2d_fp := ERR_ASN1_item_i2d_fp;
    {$ifend}
    {$if declared(ASN1_item_i2d_fp_introduced)}
    if LibVersion < ASN1_item_i2d_fp_introduced then
    begin
      {$if declared(FC_ASN1_item_i2d_fp)}
      ASN1_item_i2d_fp := FC_ASN1_item_i2d_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_i2d_fp_removed)}
    if ASN1_item_i2d_fp_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_i2d_fp)}
      ASN1_item_i2d_fp := _ASN1_item_i2d_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_i2d_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_i2d_fp');
    {$ifend}
  end;
  
  ASN1_STRING_print_ex_fp := LoadLibFunction(ADllHandle, ASN1_STRING_print_ex_fp_procname);
  FuncLoadError := not assigned(ASN1_STRING_print_ex_fp);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_STRING_print_ex_fp_allownil)}
    ASN1_STRING_print_ex_fp := ERR_ASN1_STRING_print_ex_fp;
    {$ifend}
    {$if declared(ASN1_STRING_print_ex_fp_introduced)}
    if LibVersion < ASN1_STRING_print_ex_fp_introduced then
    begin
      {$if declared(FC_ASN1_STRING_print_ex_fp)}
      ASN1_STRING_print_ex_fp := FC_ASN1_STRING_print_ex_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_STRING_print_ex_fp_removed)}
    if ASN1_STRING_print_ex_fp_removed <= LibVersion then
    begin
      {$if declared(_ASN1_STRING_print_ex_fp)}
      ASN1_STRING_print_ex_fp := _ASN1_STRING_print_ex_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_STRING_print_ex_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_STRING_print_ex_fp');
    {$ifend}
  end;
  
  ASN1_STRING_to_UTF8 := LoadLibFunction(ADllHandle, ASN1_STRING_to_UTF8_procname);
  FuncLoadError := not assigned(ASN1_STRING_to_UTF8);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_STRING_to_UTF8_allownil)}
    ASN1_STRING_to_UTF8 := ERR_ASN1_STRING_to_UTF8;
    {$ifend}
    {$if declared(ASN1_STRING_to_UTF8_introduced)}
    if LibVersion < ASN1_STRING_to_UTF8_introduced then
    begin
      {$if declared(FC_ASN1_STRING_to_UTF8)}
      ASN1_STRING_to_UTF8 := FC_ASN1_STRING_to_UTF8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_STRING_to_UTF8_removed)}
    if ASN1_STRING_to_UTF8_removed <= LibVersion then
    begin
      {$if declared(_ASN1_STRING_to_UTF8)}
      ASN1_STRING_to_UTF8 := _ASN1_STRING_to_UTF8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_STRING_to_UTF8_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_STRING_to_UTF8');
    {$ifend}
  end;
  
  ASN1_d2i_bio := LoadLibFunction(ADllHandle, ASN1_d2i_bio_procname);
  FuncLoadError := not assigned(ASN1_d2i_bio);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_d2i_bio_allownil)}
    ASN1_d2i_bio := ERR_ASN1_d2i_bio;
    {$ifend}
    {$if declared(ASN1_d2i_bio_introduced)}
    if LibVersion < ASN1_d2i_bio_introduced then
    begin
      {$if declared(FC_ASN1_d2i_bio)}
      ASN1_d2i_bio := FC_ASN1_d2i_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_d2i_bio_removed)}
    if ASN1_d2i_bio_removed <= LibVersion then
    begin
      {$if declared(_ASN1_d2i_bio)}
      ASN1_d2i_bio := _ASN1_d2i_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_d2i_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_d2i_bio');
    {$ifend}
  end;
  
  ASN1_item_d2i_bio_ex := LoadLibFunction(ADllHandle, ASN1_item_d2i_bio_ex_procname);
  FuncLoadError := not assigned(ASN1_item_d2i_bio_ex);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_d2i_bio_ex_allownil)}
    ASN1_item_d2i_bio_ex := ERR_ASN1_item_d2i_bio_ex;
    {$ifend}
    {$if declared(ASN1_item_d2i_bio_ex_introduced)}
    if LibVersion < ASN1_item_d2i_bio_ex_introduced then
    begin
      {$if declared(FC_ASN1_item_d2i_bio_ex)}
      ASN1_item_d2i_bio_ex := FC_ASN1_item_d2i_bio_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_d2i_bio_ex_removed)}
    if ASN1_item_d2i_bio_ex_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_d2i_bio_ex)}
      ASN1_item_d2i_bio_ex := _ASN1_item_d2i_bio_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_d2i_bio_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_d2i_bio_ex');
    {$ifend}
  end;
  
  ASN1_item_d2i_bio := LoadLibFunction(ADllHandle, ASN1_item_d2i_bio_procname);
  FuncLoadError := not assigned(ASN1_item_d2i_bio);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_d2i_bio_allownil)}
    ASN1_item_d2i_bio := ERR_ASN1_item_d2i_bio;
    {$ifend}
    {$if declared(ASN1_item_d2i_bio_introduced)}
    if LibVersion < ASN1_item_d2i_bio_introduced then
    begin
      {$if declared(FC_ASN1_item_d2i_bio)}
      ASN1_item_d2i_bio := FC_ASN1_item_d2i_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_d2i_bio_removed)}
    if ASN1_item_d2i_bio_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_d2i_bio)}
      ASN1_item_d2i_bio := _ASN1_item_d2i_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_d2i_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_d2i_bio');
    {$ifend}
  end;
  
  ASN1_i2d_bio := LoadLibFunction(ADllHandle, ASN1_i2d_bio_procname);
  FuncLoadError := not assigned(ASN1_i2d_bio);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_i2d_bio_allownil)}
    ASN1_i2d_bio := ERR_ASN1_i2d_bio;
    {$ifend}
    {$if declared(ASN1_i2d_bio_introduced)}
    if LibVersion < ASN1_i2d_bio_introduced then
    begin
      {$if declared(FC_ASN1_i2d_bio)}
      ASN1_i2d_bio := FC_ASN1_i2d_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_i2d_bio_removed)}
    if ASN1_i2d_bio_removed <= LibVersion then
    begin
      {$if declared(_ASN1_i2d_bio)}
      ASN1_i2d_bio := _ASN1_i2d_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_i2d_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_i2d_bio');
    {$ifend}
  end;
  
  ASN1_item_i2d_bio := LoadLibFunction(ADllHandle, ASN1_item_i2d_bio_procname);
  FuncLoadError := not assigned(ASN1_item_i2d_bio);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_i2d_bio_allownil)}
    ASN1_item_i2d_bio := ERR_ASN1_item_i2d_bio;
    {$ifend}
    {$if declared(ASN1_item_i2d_bio_introduced)}
    if LibVersion < ASN1_item_i2d_bio_introduced then
    begin
      {$if declared(FC_ASN1_item_i2d_bio)}
      ASN1_item_i2d_bio := FC_ASN1_item_i2d_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_i2d_bio_removed)}
    if ASN1_item_i2d_bio_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_i2d_bio)}
      ASN1_item_i2d_bio := _ASN1_item_i2d_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_i2d_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_i2d_bio');
    {$ifend}
  end;
  
  ASN1_item_i2d_mem_bio := LoadLibFunction(ADllHandle, ASN1_item_i2d_mem_bio_procname);
  FuncLoadError := not assigned(ASN1_item_i2d_mem_bio);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_i2d_mem_bio_allownil)}
    ASN1_item_i2d_mem_bio := ERR_ASN1_item_i2d_mem_bio;
    {$ifend}
    {$if declared(ASN1_item_i2d_mem_bio_introduced)}
    if LibVersion < ASN1_item_i2d_mem_bio_introduced then
    begin
      {$if declared(FC_ASN1_item_i2d_mem_bio)}
      ASN1_item_i2d_mem_bio := FC_ASN1_item_i2d_mem_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_i2d_mem_bio_removed)}
    if ASN1_item_i2d_mem_bio_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_i2d_mem_bio)}
      ASN1_item_i2d_mem_bio := _ASN1_item_i2d_mem_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_i2d_mem_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_i2d_mem_bio');
    {$ifend}
  end;
  
  ASN1_UTCTIME_print := LoadLibFunction(ADllHandle, ASN1_UTCTIME_print_procname);
  FuncLoadError := not assigned(ASN1_UTCTIME_print);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_UTCTIME_print_allownil)}
    ASN1_UTCTIME_print := ERR_ASN1_UTCTIME_print;
    {$ifend}
    {$if declared(ASN1_UTCTIME_print_introduced)}
    if LibVersion < ASN1_UTCTIME_print_introduced then
    begin
      {$if declared(FC_ASN1_UTCTIME_print)}
      ASN1_UTCTIME_print := FC_ASN1_UTCTIME_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_UTCTIME_print_removed)}
    if ASN1_UTCTIME_print_removed <= LibVersion then
    begin
      {$if declared(_ASN1_UTCTIME_print)}
      ASN1_UTCTIME_print := _ASN1_UTCTIME_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_UTCTIME_print_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_UTCTIME_print');
    {$ifend}
  end;
  
  ASN1_GENERALIZEDTIME_print := LoadLibFunction(ADllHandle, ASN1_GENERALIZEDTIME_print_procname);
  FuncLoadError := not assigned(ASN1_GENERALIZEDTIME_print);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_GENERALIZEDTIME_print_allownil)}
    ASN1_GENERALIZEDTIME_print := ERR_ASN1_GENERALIZEDTIME_print;
    {$ifend}
    {$if declared(ASN1_GENERALIZEDTIME_print_introduced)}
    if LibVersion < ASN1_GENERALIZEDTIME_print_introduced then
    begin
      {$if declared(FC_ASN1_GENERALIZEDTIME_print)}
      ASN1_GENERALIZEDTIME_print := FC_ASN1_GENERALIZEDTIME_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_GENERALIZEDTIME_print_removed)}
    if ASN1_GENERALIZEDTIME_print_removed <= LibVersion then
    begin
      {$if declared(_ASN1_GENERALIZEDTIME_print)}
      ASN1_GENERALIZEDTIME_print := _ASN1_GENERALIZEDTIME_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_GENERALIZEDTIME_print_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_GENERALIZEDTIME_print');
    {$ifend}
  end;
  
  ASN1_TIME_print := LoadLibFunction(ADllHandle, ASN1_TIME_print_procname);
  FuncLoadError := not assigned(ASN1_TIME_print);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TIME_print_allownil)}
    ASN1_TIME_print := ERR_ASN1_TIME_print;
    {$ifend}
    {$if declared(ASN1_TIME_print_introduced)}
    if LibVersion < ASN1_TIME_print_introduced then
    begin
      {$if declared(FC_ASN1_TIME_print)}
      ASN1_TIME_print := FC_ASN1_TIME_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TIME_print_removed)}
    if ASN1_TIME_print_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TIME_print)}
      ASN1_TIME_print := _ASN1_TIME_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TIME_print_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TIME_print');
    {$ifend}
  end;
  
  ASN1_TIME_print_ex := LoadLibFunction(ADllHandle, ASN1_TIME_print_ex_procname);
  FuncLoadError := not assigned(ASN1_TIME_print_ex);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TIME_print_ex_allownil)}
    ASN1_TIME_print_ex := ERR_ASN1_TIME_print_ex;
    {$ifend}
    {$if declared(ASN1_TIME_print_ex_introduced)}
    if LibVersion < ASN1_TIME_print_ex_introduced then
    begin
      {$if declared(FC_ASN1_TIME_print_ex)}
      ASN1_TIME_print_ex := FC_ASN1_TIME_print_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TIME_print_ex_removed)}
    if ASN1_TIME_print_ex_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TIME_print_ex)}
      ASN1_TIME_print_ex := _ASN1_TIME_print_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TIME_print_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TIME_print_ex');
    {$ifend}
  end;
  
  ASN1_STRING_print := LoadLibFunction(ADllHandle, ASN1_STRING_print_procname);
  FuncLoadError := not assigned(ASN1_STRING_print);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_STRING_print_allownil)}
    ASN1_STRING_print := ERR_ASN1_STRING_print;
    {$ifend}
    {$if declared(ASN1_STRING_print_introduced)}
    if LibVersion < ASN1_STRING_print_introduced then
    begin
      {$if declared(FC_ASN1_STRING_print)}
      ASN1_STRING_print := FC_ASN1_STRING_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_STRING_print_removed)}
    if ASN1_STRING_print_removed <= LibVersion then
    begin
      {$if declared(_ASN1_STRING_print)}
      ASN1_STRING_print := _ASN1_STRING_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_STRING_print_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_STRING_print');
    {$ifend}
  end;
  
  ASN1_STRING_print_ex := LoadLibFunction(ADllHandle, ASN1_STRING_print_ex_procname);
  FuncLoadError := not assigned(ASN1_STRING_print_ex);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_STRING_print_ex_allownil)}
    ASN1_STRING_print_ex := ERR_ASN1_STRING_print_ex;
    {$ifend}
    {$if declared(ASN1_STRING_print_ex_introduced)}
    if LibVersion < ASN1_STRING_print_ex_introduced then
    begin
      {$if declared(FC_ASN1_STRING_print_ex)}
      ASN1_STRING_print_ex := FC_ASN1_STRING_print_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_STRING_print_ex_removed)}
    if ASN1_STRING_print_ex_removed <= LibVersion then
    begin
      {$if declared(_ASN1_STRING_print_ex)}
      ASN1_STRING_print_ex := _ASN1_STRING_print_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_STRING_print_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_STRING_print_ex');
    {$ifend}
  end;
  
  ASN1_buf_print := LoadLibFunction(ADllHandle, ASN1_buf_print_procname);
  FuncLoadError := not assigned(ASN1_buf_print);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_buf_print_allownil)}
    ASN1_buf_print := ERR_ASN1_buf_print;
    {$ifend}
    {$if declared(ASN1_buf_print_introduced)}
    if LibVersion < ASN1_buf_print_introduced then
    begin
      {$if declared(FC_ASN1_buf_print)}
      ASN1_buf_print := FC_ASN1_buf_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_buf_print_removed)}
    if ASN1_buf_print_removed <= LibVersion then
    begin
      {$if declared(_ASN1_buf_print)}
      ASN1_buf_print := _ASN1_buf_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_buf_print_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_buf_print');
    {$ifend}
  end;
  
  ASN1_bn_print := LoadLibFunction(ADllHandle, ASN1_bn_print_procname);
  FuncLoadError := not assigned(ASN1_bn_print);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_bn_print_allownil)}
    ASN1_bn_print := ERR_ASN1_bn_print;
    {$ifend}
    {$if declared(ASN1_bn_print_introduced)}
    if LibVersion < ASN1_bn_print_introduced then
    begin
      {$if declared(FC_ASN1_bn_print)}
      ASN1_bn_print := FC_ASN1_bn_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_bn_print_removed)}
    if ASN1_bn_print_removed <= LibVersion then
    begin
      {$if declared(_ASN1_bn_print)}
      ASN1_bn_print := _ASN1_bn_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_bn_print_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_bn_print');
    {$ifend}
  end;
  
  ASN1_parse := LoadLibFunction(ADllHandle, ASN1_parse_procname);
  FuncLoadError := not assigned(ASN1_parse);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_parse_allownil)}
    ASN1_parse := ERR_ASN1_parse;
    {$ifend}
    {$if declared(ASN1_parse_introduced)}
    if LibVersion < ASN1_parse_introduced then
    begin
      {$if declared(FC_ASN1_parse)}
      ASN1_parse := FC_ASN1_parse;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_parse_removed)}
    if ASN1_parse_removed <= LibVersion then
    begin
      {$if declared(_ASN1_parse)}
      ASN1_parse := _ASN1_parse;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_parse_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_parse');
    {$ifend}
  end;
  
  ASN1_parse_dump := LoadLibFunction(ADllHandle, ASN1_parse_dump_procname);
  FuncLoadError := not assigned(ASN1_parse_dump);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_parse_dump_allownil)}
    ASN1_parse_dump := ERR_ASN1_parse_dump;
    {$ifend}
    {$if declared(ASN1_parse_dump_introduced)}
    if LibVersion < ASN1_parse_dump_introduced then
    begin
      {$if declared(FC_ASN1_parse_dump)}
      ASN1_parse_dump := FC_ASN1_parse_dump;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_parse_dump_removed)}
    if ASN1_parse_dump_removed <= LibVersion then
    begin
      {$if declared(_ASN1_parse_dump)}
      ASN1_parse_dump := _ASN1_parse_dump;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_parse_dump_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_parse_dump');
    {$ifend}
  end;
  
  ASN1_tag2str := LoadLibFunction(ADllHandle, ASN1_tag2str_procname);
  FuncLoadError := not assigned(ASN1_tag2str);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_tag2str_allownil)}
    ASN1_tag2str := ERR_ASN1_tag2str;
    {$ifend}
    {$if declared(ASN1_tag2str_introduced)}
    if LibVersion < ASN1_tag2str_introduced then
    begin
      {$if declared(FC_ASN1_tag2str)}
      ASN1_tag2str := FC_ASN1_tag2str;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_tag2str_removed)}
    if ASN1_tag2str_removed <= LibVersion then
    begin
      {$if declared(_ASN1_tag2str)}
      ASN1_tag2str := _ASN1_tag2str;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_tag2str_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_tag2str');
    {$ifend}
  end;
  
  ASN1_UNIVERSALSTRING_to_string := LoadLibFunction(ADllHandle, ASN1_UNIVERSALSTRING_to_string_procname);
  FuncLoadError := not assigned(ASN1_UNIVERSALSTRING_to_string);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_UNIVERSALSTRING_to_string_allownil)}
    ASN1_UNIVERSALSTRING_to_string := ERR_ASN1_UNIVERSALSTRING_to_string;
    {$ifend}
    {$if declared(ASN1_UNIVERSALSTRING_to_string_introduced)}
    if LibVersion < ASN1_UNIVERSALSTRING_to_string_introduced then
    begin
      {$if declared(FC_ASN1_UNIVERSALSTRING_to_string)}
      ASN1_UNIVERSALSTRING_to_string := FC_ASN1_UNIVERSALSTRING_to_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_UNIVERSALSTRING_to_string_removed)}
    if ASN1_UNIVERSALSTRING_to_string_removed <= LibVersion then
    begin
      {$if declared(_ASN1_UNIVERSALSTRING_to_string)}
      ASN1_UNIVERSALSTRING_to_string := _ASN1_UNIVERSALSTRING_to_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_UNIVERSALSTRING_to_string_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_UNIVERSALSTRING_to_string');
    {$ifend}
  end;
  
  ASN1_TYPE_set_octetstring := LoadLibFunction(ADllHandle, ASN1_TYPE_set_octetstring_procname);
  FuncLoadError := not assigned(ASN1_TYPE_set_octetstring);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TYPE_set_octetstring_allownil)}
    ASN1_TYPE_set_octetstring := ERR_ASN1_TYPE_set_octetstring;
    {$ifend}
    {$if declared(ASN1_TYPE_set_octetstring_introduced)}
    if LibVersion < ASN1_TYPE_set_octetstring_introduced then
    begin
      {$if declared(FC_ASN1_TYPE_set_octetstring)}
      ASN1_TYPE_set_octetstring := FC_ASN1_TYPE_set_octetstring;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TYPE_set_octetstring_removed)}
    if ASN1_TYPE_set_octetstring_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TYPE_set_octetstring)}
      ASN1_TYPE_set_octetstring := _ASN1_TYPE_set_octetstring;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TYPE_set_octetstring_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TYPE_set_octetstring');
    {$ifend}
  end;
  
  ASN1_TYPE_get_octetstring := LoadLibFunction(ADllHandle, ASN1_TYPE_get_octetstring_procname);
  FuncLoadError := not assigned(ASN1_TYPE_get_octetstring);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TYPE_get_octetstring_allownil)}
    ASN1_TYPE_get_octetstring := ERR_ASN1_TYPE_get_octetstring;
    {$ifend}
    {$if declared(ASN1_TYPE_get_octetstring_introduced)}
    if LibVersion < ASN1_TYPE_get_octetstring_introduced then
    begin
      {$if declared(FC_ASN1_TYPE_get_octetstring)}
      ASN1_TYPE_get_octetstring := FC_ASN1_TYPE_get_octetstring;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TYPE_get_octetstring_removed)}
    if ASN1_TYPE_get_octetstring_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TYPE_get_octetstring)}
      ASN1_TYPE_get_octetstring := _ASN1_TYPE_get_octetstring;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TYPE_get_octetstring_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TYPE_get_octetstring');
    {$ifend}
  end;
  
  ASN1_TYPE_set_int_octetstring := LoadLibFunction(ADllHandle, ASN1_TYPE_set_int_octetstring_procname);
  FuncLoadError := not assigned(ASN1_TYPE_set_int_octetstring);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TYPE_set_int_octetstring_allownil)}
    ASN1_TYPE_set_int_octetstring := ERR_ASN1_TYPE_set_int_octetstring;
    {$ifend}
    {$if declared(ASN1_TYPE_set_int_octetstring_introduced)}
    if LibVersion < ASN1_TYPE_set_int_octetstring_introduced then
    begin
      {$if declared(FC_ASN1_TYPE_set_int_octetstring)}
      ASN1_TYPE_set_int_octetstring := FC_ASN1_TYPE_set_int_octetstring;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TYPE_set_int_octetstring_removed)}
    if ASN1_TYPE_set_int_octetstring_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TYPE_set_int_octetstring)}
      ASN1_TYPE_set_int_octetstring := _ASN1_TYPE_set_int_octetstring;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TYPE_set_int_octetstring_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TYPE_set_int_octetstring');
    {$ifend}
  end;
  
  ASN1_TYPE_get_int_octetstring := LoadLibFunction(ADllHandle, ASN1_TYPE_get_int_octetstring_procname);
  FuncLoadError := not assigned(ASN1_TYPE_get_int_octetstring);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TYPE_get_int_octetstring_allownil)}
    ASN1_TYPE_get_int_octetstring := ERR_ASN1_TYPE_get_int_octetstring;
    {$ifend}
    {$if declared(ASN1_TYPE_get_int_octetstring_introduced)}
    if LibVersion < ASN1_TYPE_get_int_octetstring_introduced then
    begin
      {$if declared(FC_ASN1_TYPE_get_int_octetstring)}
      ASN1_TYPE_get_int_octetstring := FC_ASN1_TYPE_get_int_octetstring;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TYPE_get_int_octetstring_removed)}
    if ASN1_TYPE_get_int_octetstring_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TYPE_get_int_octetstring)}
      ASN1_TYPE_get_int_octetstring := _ASN1_TYPE_get_int_octetstring;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TYPE_get_int_octetstring_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TYPE_get_int_octetstring');
    {$ifend}
  end;
  
  ASN1_item_unpack := LoadLibFunction(ADllHandle, ASN1_item_unpack_procname);
  FuncLoadError := not assigned(ASN1_item_unpack);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_unpack_allownil)}
    ASN1_item_unpack := ERR_ASN1_item_unpack;
    {$ifend}
    {$if declared(ASN1_item_unpack_introduced)}
    if LibVersion < ASN1_item_unpack_introduced then
    begin
      {$if declared(FC_ASN1_item_unpack)}
      ASN1_item_unpack := FC_ASN1_item_unpack;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_unpack_removed)}
    if ASN1_item_unpack_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_unpack)}
      ASN1_item_unpack := _ASN1_item_unpack;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_unpack_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_unpack');
    {$ifend}
  end;
  
  ASN1_item_unpack_ex := LoadLibFunction(ADllHandle, ASN1_item_unpack_ex_procname);
  FuncLoadError := not assigned(ASN1_item_unpack_ex);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_unpack_ex_allownil)}
    ASN1_item_unpack_ex := ERR_ASN1_item_unpack_ex;
    {$ifend}
    {$if declared(ASN1_item_unpack_ex_introduced)}
    if LibVersion < ASN1_item_unpack_ex_introduced then
    begin
      {$if declared(FC_ASN1_item_unpack_ex)}
      ASN1_item_unpack_ex := FC_ASN1_item_unpack_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_unpack_ex_removed)}
    if ASN1_item_unpack_ex_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_unpack_ex)}
      ASN1_item_unpack_ex := _ASN1_item_unpack_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_unpack_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_unpack_ex');
    {$ifend}
  end;
  
  ASN1_item_pack := LoadLibFunction(ADllHandle, ASN1_item_pack_procname);
  FuncLoadError := not assigned(ASN1_item_pack);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_pack_allownil)}
    ASN1_item_pack := ERR_ASN1_item_pack;
    {$ifend}
    {$if declared(ASN1_item_pack_introduced)}
    if LibVersion < ASN1_item_pack_introduced then
    begin
      {$if declared(FC_ASN1_item_pack)}
      ASN1_item_pack := FC_ASN1_item_pack;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_pack_removed)}
    if ASN1_item_pack_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_pack)}
      ASN1_item_pack := _ASN1_item_pack;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_pack_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_pack');
    {$ifend}
  end;
  
  ASN1_STRING_set_default_mask := LoadLibFunction(ADllHandle, ASN1_STRING_set_default_mask_procname);
  FuncLoadError := not assigned(ASN1_STRING_set_default_mask);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_STRING_set_default_mask_allownil)}
    ASN1_STRING_set_default_mask := ERR_ASN1_STRING_set_default_mask;
    {$ifend}
    {$if declared(ASN1_STRING_set_default_mask_introduced)}
    if LibVersion < ASN1_STRING_set_default_mask_introduced then
    begin
      {$if declared(FC_ASN1_STRING_set_default_mask)}
      ASN1_STRING_set_default_mask := FC_ASN1_STRING_set_default_mask;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_STRING_set_default_mask_removed)}
    if ASN1_STRING_set_default_mask_removed <= LibVersion then
    begin
      {$if declared(_ASN1_STRING_set_default_mask)}
      ASN1_STRING_set_default_mask := _ASN1_STRING_set_default_mask;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_STRING_set_default_mask_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_STRING_set_default_mask');
    {$ifend}
  end;
  
  ASN1_STRING_set_default_mask_asc := LoadLibFunction(ADllHandle, ASN1_STRING_set_default_mask_asc_procname);
  FuncLoadError := not assigned(ASN1_STRING_set_default_mask_asc);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_STRING_set_default_mask_asc_allownil)}
    ASN1_STRING_set_default_mask_asc := ERR_ASN1_STRING_set_default_mask_asc;
    {$ifend}
    {$if declared(ASN1_STRING_set_default_mask_asc_introduced)}
    if LibVersion < ASN1_STRING_set_default_mask_asc_introduced then
    begin
      {$if declared(FC_ASN1_STRING_set_default_mask_asc)}
      ASN1_STRING_set_default_mask_asc := FC_ASN1_STRING_set_default_mask_asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_STRING_set_default_mask_asc_removed)}
    if ASN1_STRING_set_default_mask_asc_removed <= LibVersion then
    begin
      {$if declared(_ASN1_STRING_set_default_mask_asc)}
      ASN1_STRING_set_default_mask_asc := _ASN1_STRING_set_default_mask_asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_STRING_set_default_mask_asc_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_STRING_set_default_mask_asc');
    {$ifend}
  end;
  
  ASN1_STRING_get_default_mask := LoadLibFunction(ADllHandle, ASN1_STRING_get_default_mask_procname);
  FuncLoadError := not assigned(ASN1_STRING_get_default_mask);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_STRING_get_default_mask_allownil)}
    ASN1_STRING_get_default_mask := ERR_ASN1_STRING_get_default_mask;
    {$ifend}
    {$if declared(ASN1_STRING_get_default_mask_introduced)}
    if LibVersion < ASN1_STRING_get_default_mask_introduced then
    begin
      {$if declared(FC_ASN1_STRING_get_default_mask)}
      ASN1_STRING_get_default_mask := FC_ASN1_STRING_get_default_mask;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_STRING_get_default_mask_removed)}
    if ASN1_STRING_get_default_mask_removed <= LibVersion then
    begin
      {$if declared(_ASN1_STRING_get_default_mask)}
      ASN1_STRING_get_default_mask := _ASN1_STRING_get_default_mask;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_STRING_get_default_mask_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_STRING_get_default_mask');
    {$ifend}
  end;
  
  ASN1_mbstring_copy := LoadLibFunction(ADllHandle, ASN1_mbstring_copy_procname);
  FuncLoadError := not assigned(ASN1_mbstring_copy);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_mbstring_copy_allownil)}
    ASN1_mbstring_copy := ERR_ASN1_mbstring_copy;
    {$ifend}
    {$if declared(ASN1_mbstring_copy_introduced)}
    if LibVersion < ASN1_mbstring_copy_introduced then
    begin
      {$if declared(FC_ASN1_mbstring_copy)}
      ASN1_mbstring_copy := FC_ASN1_mbstring_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_mbstring_copy_removed)}
    if ASN1_mbstring_copy_removed <= LibVersion then
    begin
      {$if declared(_ASN1_mbstring_copy)}
      ASN1_mbstring_copy := _ASN1_mbstring_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_mbstring_copy_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_mbstring_copy');
    {$ifend}
  end;
  
  ASN1_mbstring_ncopy := LoadLibFunction(ADllHandle, ASN1_mbstring_ncopy_procname);
  FuncLoadError := not assigned(ASN1_mbstring_ncopy);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_mbstring_ncopy_allownil)}
    ASN1_mbstring_ncopy := ERR_ASN1_mbstring_ncopy;
    {$ifend}
    {$if declared(ASN1_mbstring_ncopy_introduced)}
    if LibVersion < ASN1_mbstring_ncopy_introduced then
    begin
      {$if declared(FC_ASN1_mbstring_ncopy)}
      ASN1_mbstring_ncopy := FC_ASN1_mbstring_ncopy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_mbstring_ncopy_removed)}
    if ASN1_mbstring_ncopy_removed <= LibVersion then
    begin
      {$if declared(_ASN1_mbstring_ncopy)}
      ASN1_mbstring_ncopy := _ASN1_mbstring_ncopy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_mbstring_ncopy_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_mbstring_ncopy');
    {$ifend}
  end;
  
  ASN1_STRING_set_by_NID := LoadLibFunction(ADllHandle, ASN1_STRING_set_by_NID_procname);
  FuncLoadError := not assigned(ASN1_STRING_set_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_STRING_set_by_NID_allownil)}
    ASN1_STRING_set_by_NID := ERR_ASN1_STRING_set_by_NID;
    {$ifend}
    {$if declared(ASN1_STRING_set_by_NID_introduced)}
    if LibVersion < ASN1_STRING_set_by_NID_introduced then
    begin
      {$if declared(FC_ASN1_STRING_set_by_NID)}
      ASN1_STRING_set_by_NID := FC_ASN1_STRING_set_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_STRING_set_by_NID_removed)}
    if ASN1_STRING_set_by_NID_removed <= LibVersion then
    begin
      {$if declared(_ASN1_STRING_set_by_NID)}
      ASN1_STRING_set_by_NID := _ASN1_STRING_set_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_STRING_set_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_STRING_set_by_NID');
    {$ifend}
  end;
  
  ASN1_STRING_TABLE_get := LoadLibFunction(ADllHandle, ASN1_STRING_TABLE_get_procname);
  FuncLoadError := not assigned(ASN1_STRING_TABLE_get);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_STRING_TABLE_get_allownil)}
    ASN1_STRING_TABLE_get := ERR_ASN1_STRING_TABLE_get;
    {$ifend}
    {$if declared(ASN1_STRING_TABLE_get_introduced)}
    if LibVersion < ASN1_STRING_TABLE_get_introduced then
    begin
      {$if declared(FC_ASN1_STRING_TABLE_get)}
      ASN1_STRING_TABLE_get := FC_ASN1_STRING_TABLE_get;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_STRING_TABLE_get_removed)}
    if ASN1_STRING_TABLE_get_removed <= LibVersion then
    begin
      {$if declared(_ASN1_STRING_TABLE_get)}
      ASN1_STRING_TABLE_get := _ASN1_STRING_TABLE_get;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_STRING_TABLE_get_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_STRING_TABLE_get');
    {$ifend}
  end;
  
  ASN1_STRING_TABLE_add := LoadLibFunction(ADllHandle, ASN1_STRING_TABLE_add_procname);
  FuncLoadError := not assigned(ASN1_STRING_TABLE_add);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_STRING_TABLE_add_allownil)}
    ASN1_STRING_TABLE_add := ERR_ASN1_STRING_TABLE_add;
    {$ifend}
    {$if declared(ASN1_STRING_TABLE_add_introduced)}
    if LibVersion < ASN1_STRING_TABLE_add_introduced then
    begin
      {$if declared(FC_ASN1_STRING_TABLE_add)}
      ASN1_STRING_TABLE_add := FC_ASN1_STRING_TABLE_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_STRING_TABLE_add_removed)}
    if ASN1_STRING_TABLE_add_removed <= LibVersion then
    begin
      {$if declared(_ASN1_STRING_TABLE_add)}
      ASN1_STRING_TABLE_add := _ASN1_STRING_TABLE_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_STRING_TABLE_add_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_STRING_TABLE_add');
    {$ifend}
  end;
  
  ASN1_STRING_TABLE_cleanup := LoadLibFunction(ADllHandle, ASN1_STRING_TABLE_cleanup_procname);
  FuncLoadError := not assigned(ASN1_STRING_TABLE_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_STRING_TABLE_cleanup_allownil)}
    ASN1_STRING_TABLE_cleanup := ERR_ASN1_STRING_TABLE_cleanup;
    {$ifend}
    {$if declared(ASN1_STRING_TABLE_cleanup_introduced)}
    if LibVersion < ASN1_STRING_TABLE_cleanup_introduced then
    begin
      {$if declared(FC_ASN1_STRING_TABLE_cleanup)}
      ASN1_STRING_TABLE_cleanup := FC_ASN1_STRING_TABLE_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_STRING_TABLE_cleanup_removed)}
    if ASN1_STRING_TABLE_cleanup_removed <= LibVersion then
    begin
      {$if declared(_ASN1_STRING_TABLE_cleanup)}
      ASN1_STRING_TABLE_cleanup := _ASN1_STRING_TABLE_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_STRING_TABLE_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_STRING_TABLE_cleanup');
    {$ifend}
  end;
  
  ASN1_item_new := LoadLibFunction(ADllHandle, ASN1_item_new_procname);
  FuncLoadError := not assigned(ASN1_item_new);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_new_allownil)}
    ASN1_item_new := ERR_ASN1_item_new;
    {$ifend}
    {$if declared(ASN1_item_new_introduced)}
    if LibVersion < ASN1_item_new_introduced then
    begin
      {$if declared(FC_ASN1_item_new)}
      ASN1_item_new := FC_ASN1_item_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_new_removed)}
    if ASN1_item_new_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_new)}
      ASN1_item_new := _ASN1_item_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_new');
    {$ifend}
  end;
  
  ASN1_item_new_ex := LoadLibFunction(ADllHandle, ASN1_item_new_ex_procname);
  FuncLoadError := not assigned(ASN1_item_new_ex);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_new_ex_allownil)}
    ASN1_item_new_ex := ERR_ASN1_item_new_ex;
    {$ifend}
    {$if declared(ASN1_item_new_ex_introduced)}
    if LibVersion < ASN1_item_new_ex_introduced then
    begin
      {$if declared(FC_ASN1_item_new_ex)}
      ASN1_item_new_ex := FC_ASN1_item_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_new_ex_removed)}
    if ASN1_item_new_ex_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_new_ex)}
      ASN1_item_new_ex := _ASN1_item_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_new_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_new_ex');
    {$ifend}
  end;
  
  ASN1_item_free := LoadLibFunction(ADllHandle, ASN1_item_free_procname);
  FuncLoadError := not assigned(ASN1_item_free);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_free_allownil)}
    ASN1_item_free := ERR_ASN1_item_free;
    {$ifend}
    {$if declared(ASN1_item_free_introduced)}
    if LibVersion < ASN1_item_free_introduced then
    begin
      {$if declared(FC_ASN1_item_free)}
      ASN1_item_free := FC_ASN1_item_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_free_removed)}
    if ASN1_item_free_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_free)}
      ASN1_item_free := _ASN1_item_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_free');
    {$ifend}
  end;
  
  ASN1_item_d2i_ex := LoadLibFunction(ADllHandle, ASN1_item_d2i_ex_procname);
  FuncLoadError := not assigned(ASN1_item_d2i_ex);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_d2i_ex_allownil)}
    ASN1_item_d2i_ex := ERR_ASN1_item_d2i_ex;
    {$ifend}
    {$if declared(ASN1_item_d2i_ex_introduced)}
    if LibVersion < ASN1_item_d2i_ex_introduced then
    begin
      {$if declared(FC_ASN1_item_d2i_ex)}
      ASN1_item_d2i_ex := FC_ASN1_item_d2i_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_d2i_ex_removed)}
    if ASN1_item_d2i_ex_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_d2i_ex)}
      ASN1_item_d2i_ex := _ASN1_item_d2i_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_d2i_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_d2i_ex');
    {$ifend}
  end;
  
  ASN1_item_d2i := LoadLibFunction(ADllHandle, ASN1_item_d2i_procname);
  FuncLoadError := not assigned(ASN1_item_d2i);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_d2i_allownil)}
    ASN1_item_d2i := ERR_ASN1_item_d2i;
    {$ifend}
    {$if declared(ASN1_item_d2i_introduced)}
    if LibVersion < ASN1_item_d2i_introduced then
    begin
      {$if declared(FC_ASN1_item_d2i)}
      ASN1_item_d2i := FC_ASN1_item_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_d2i_removed)}
    if ASN1_item_d2i_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_d2i)}
      ASN1_item_d2i := _ASN1_item_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_d2i_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_d2i');
    {$ifend}
  end;
  
  ASN1_item_i2d := LoadLibFunction(ADllHandle, ASN1_item_i2d_procname);
  FuncLoadError := not assigned(ASN1_item_i2d);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_i2d_allownil)}
    ASN1_item_i2d := ERR_ASN1_item_i2d;
    {$ifend}
    {$if declared(ASN1_item_i2d_introduced)}
    if LibVersion < ASN1_item_i2d_introduced then
    begin
      {$if declared(FC_ASN1_item_i2d)}
      ASN1_item_i2d := FC_ASN1_item_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_i2d_removed)}
    if ASN1_item_i2d_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_i2d)}
      ASN1_item_i2d := _ASN1_item_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_i2d_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_i2d');
    {$ifend}
  end;
  
  ASN1_item_ndef_i2d := LoadLibFunction(ADllHandle, ASN1_item_ndef_i2d_procname);
  FuncLoadError := not assigned(ASN1_item_ndef_i2d);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_ndef_i2d_allownil)}
    ASN1_item_ndef_i2d := ERR_ASN1_item_ndef_i2d;
    {$ifend}
    {$if declared(ASN1_item_ndef_i2d_introduced)}
    if LibVersion < ASN1_item_ndef_i2d_introduced then
    begin
      {$if declared(FC_ASN1_item_ndef_i2d)}
      ASN1_item_ndef_i2d := FC_ASN1_item_ndef_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_ndef_i2d_removed)}
    if ASN1_item_ndef_i2d_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_ndef_i2d)}
      ASN1_item_ndef_i2d := _ASN1_item_ndef_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_ndef_i2d_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_ndef_i2d');
    {$ifend}
  end;
  
  ASN1_add_oid_module := LoadLibFunction(ADllHandle, ASN1_add_oid_module_procname);
  FuncLoadError := not assigned(ASN1_add_oid_module);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_add_oid_module_allownil)}
    ASN1_add_oid_module := ERR_ASN1_add_oid_module;
    {$ifend}
    {$if declared(ASN1_add_oid_module_introduced)}
    if LibVersion < ASN1_add_oid_module_introduced then
    begin
      {$if declared(FC_ASN1_add_oid_module)}
      ASN1_add_oid_module := FC_ASN1_add_oid_module;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_add_oid_module_removed)}
    if ASN1_add_oid_module_removed <= LibVersion then
    begin
      {$if declared(_ASN1_add_oid_module)}
      ASN1_add_oid_module := _ASN1_add_oid_module;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_add_oid_module_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_add_oid_module');
    {$ifend}
  end;
  
  ASN1_add_stable_module := LoadLibFunction(ADllHandle, ASN1_add_stable_module_procname);
  FuncLoadError := not assigned(ASN1_add_stable_module);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_add_stable_module_allownil)}
    ASN1_add_stable_module := ERR_ASN1_add_stable_module;
    {$ifend}
    {$if declared(ASN1_add_stable_module_introduced)}
    if LibVersion < ASN1_add_stable_module_introduced then
    begin
      {$if declared(FC_ASN1_add_stable_module)}
      ASN1_add_stable_module := FC_ASN1_add_stable_module;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_add_stable_module_removed)}
    if ASN1_add_stable_module_removed <= LibVersion then
    begin
      {$if declared(_ASN1_add_stable_module)}
      ASN1_add_stable_module := _ASN1_add_stable_module;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_add_stable_module_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_add_stable_module');
    {$ifend}
  end;
  
  ASN1_generate_nconf := LoadLibFunction(ADllHandle, ASN1_generate_nconf_procname);
  FuncLoadError := not assigned(ASN1_generate_nconf);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_generate_nconf_allownil)}
    ASN1_generate_nconf := ERR_ASN1_generate_nconf;
    {$ifend}
    {$if declared(ASN1_generate_nconf_introduced)}
    if LibVersion < ASN1_generate_nconf_introduced then
    begin
      {$if declared(FC_ASN1_generate_nconf)}
      ASN1_generate_nconf := FC_ASN1_generate_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_generate_nconf_removed)}
    if ASN1_generate_nconf_removed <= LibVersion then
    begin
      {$if declared(_ASN1_generate_nconf)}
      ASN1_generate_nconf := _ASN1_generate_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_generate_nconf_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_generate_nconf');
    {$ifend}
  end;
  
  ASN1_generate_v3 := LoadLibFunction(ADllHandle, ASN1_generate_v3_procname);
  FuncLoadError := not assigned(ASN1_generate_v3);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_generate_v3_allownil)}
    ASN1_generate_v3 := ERR_ASN1_generate_v3;
    {$ifend}
    {$if declared(ASN1_generate_v3_introduced)}
    if LibVersion < ASN1_generate_v3_introduced then
    begin
      {$if declared(FC_ASN1_generate_v3)}
      ASN1_generate_v3 := FC_ASN1_generate_v3;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_generate_v3_removed)}
    if ASN1_generate_v3_removed <= LibVersion then
    begin
      {$if declared(_ASN1_generate_v3)}
      ASN1_generate_v3 := _ASN1_generate_v3;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_generate_v3_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_generate_v3');
    {$ifend}
  end;
  
  ASN1_str2mask := LoadLibFunction(ADllHandle, ASN1_str2mask_procname);
  FuncLoadError := not assigned(ASN1_str2mask);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_str2mask_allownil)}
    ASN1_str2mask := ERR_ASN1_str2mask;
    {$ifend}
    {$if declared(ASN1_str2mask_introduced)}
    if LibVersion < ASN1_str2mask_introduced then
    begin
      {$if declared(FC_ASN1_str2mask)}
      ASN1_str2mask := FC_ASN1_str2mask;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_str2mask_removed)}
    if ASN1_str2mask_removed <= LibVersion then
    begin
      {$if declared(_ASN1_str2mask)}
      ASN1_str2mask := _ASN1_str2mask;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_str2mask_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_str2mask');
    {$ifend}
  end;
  
  ASN1_item_print := LoadLibFunction(ADllHandle, ASN1_item_print_procname);
  FuncLoadError := not assigned(ASN1_item_print);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_print_allownil)}
    ASN1_item_print := ERR_ASN1_item_print;
    {$ifend}
    {$if declared(ASN1_item_print_introduced)}
    if LibVersion < ASN1_item_print_introduced then
    begin
      {$if declared(FC_ASN1_item_print)}
      ASN1_item_print := FC_ASN1_item_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_print_removed)}
    if ASN1_item_print_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_print)}
      ASN1_item_print := _ASN1_item_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_print_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_print');
    {$ifend}
  end;
  
  ASN1_PCTX_new := LoadLibFunction(ADllHandle, ASN1_PCTX_new_procname);
  FuncLoadError := not assigned(ASN1_PCTX_new);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_PCTX_new_allownil)}
    ASN1_PCTX_new := ERR_ASN1_PCTX_new;
    {$ifend}
    {$if declared(ASN1_PCTX_new_introduced)}
    if LibVersion < ASN1_PCTX_new_introduced then
    begin
      {$if declared(FC_ASN1_PCTX_new)}
      ASN1_PCTX_new := FC_ASN1_PCTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_PCTX_new_removed)}
    if ASN1_PCTX_new_removed <= LibVersion then
    begin
      {$if declared(_ASN1_PCTX_new)}
      ASN1_PCTX_new := _ASN1_PCTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_PCTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_PCTX_new');
    {$ifend}
  end;
  
  ASN1_PCTX_free := LoadLibFunction(ADllHandle, ASN1_PCTX_free_procname);
  FuncLoadError := not assigned(ASN1_PCTX_free);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_PCTX_free_allownil)}
    ASN1_PCTX_free := ERR_ASN1_PCTX_free;
    {$ifend}
    {$if declared(ASN1_PCTX_free_introduced)}
    if LibVersion < ASN1_PCTX_free_introduced then
    begin
      {$if declared(FC_ASN1_PCTX_free)}
      ASN1_PCTX_free := FC_ASN1_PCTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_PCTX_free_removed)}
    if ASN1_PCTX_free_removed <= LibVersion then
    begin
      {$if declared(_ASN1_PCTX_free)}
      ASN1_PCTX_free := _ASN1_PCTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_PCTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_PCTX_free');
    {$ifend}
  end;
  
  ASN1_PCTX_get_flags := LoadLibFunction(ADllHandle, ASN1_PCTX_get_flags_procname);
  FuncLoadError := not assigned(ASN1_PCTX_get_flags);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_PCTX_get_flags_allownil)}
    ASN1_PCTX_get_flags := ERR_ASN1_PCTX_get_flags;
    {$ifend}
    {$if declared(ASN1_PCTX_get_flags_introduced)}
    if LibVersion < ASN1_PCTX_get_flags_introduced then
    begin
      {$if declared(FC_ASN1_PCTX_get_flags)}
      ASN1_PCTX_get_flags := FC_ASN1_PCTX_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_PCTX_get_flags_removed)}
    if ASN1_PCTX_get_flags_removed <= LibVersion then
    begin
      {$if declared(_ASN1_PCTX_get_flags)}
      ASN1_PCTX_get_flags := _ASN1_PCTX_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_PCTX_get_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_PCTX_get_flags');
    {$ifend}
  end;
  
  ASN1_PCTX_set_flags := LoadLibFunction(ADllHandle, ASN1_PCTX_set_flags_procname);
  FuncLoadError := not assigned(ASN1_PCTX_set_flags);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_PCTX_set_flags_allownil)}
    ASN1_PCTX_set_flags := ERR_ASN1_PCTX_set_flags;
    {$ifend}
    {$if declared(ASN1_PCTX_set_flags_introduced)}
    if LibVersion < ASN1_PCTX_set_flags_introduced then
    begin
      {$if declared(FC_ASN1_PCTX_set_flags)}
      ASN1_PCTX_set_flags := FC_ASN1_PCTX_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_PCTX_set_flags_removed)}
    if ASN1_PCTX_set_flags_removed <= LibVersion then
    begin
      {$if declared(_ASN1_PCTX_set_flags)}
      ASN1_PCTX_set_flags := _ASN1_PCTX_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_PCTX_set_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_PCTX_set_flags');
    {$ifend}
  end;
  
  ASN1_PCTX_get_nm_flags := LoadLibFunction(ADllHandle, ASN1_PCTX_get_nm_flags_procname);
  FuncLoadError := not assigned(ASN1_PCTX_get_nm_flags);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_PCTX_get_nm_flags_allownil)}
    ASN1_PCTX_get_nm_flags := ERR_ASN1_PCTX_get_nm_flags;
    {$ifend}
    {$if declared(ASN1_PCTX_get_nm_flags_introduced)}
    if LibVersion < ASN1_PCTX_get_nm_flags_introduced then
    begin
      {$if declared(FC_ASN1_PCTX_get_nm_flags)}
      ASN1_PCTX_get_nm_flags := FC_ASN1_PCTX_get_nm_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_PCTX_get_nm_flags_removed)}
    if ASN1_PCTX_get_nm_flags_removed <= LibVersion then
    begin
      {$if declared(_ASN1_PCTX_get_nm_flags)}
      ASN1_PCTX_get_nm_flags := _ASN1_PCTX_get_nm_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_PCTX_get_nm_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_PCTX_get_nm_flags');
    {$ifend}
  end;
  
  ASN1_PCTX_set_nm_flags := LoadLibFunction(ADllHandle, ASN1_PCTX_set_nm_flags_procname);
  FuncLoadError := not assigned(ASN1_PCTX_set_nm_flags);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_PCTX_set_nm_flags_allownil)}
    ASN1_PCTX_set_nm_flags := ERR_ASN1_PCTX_set_nm_flags;
    {$ifend}
    {$if declared(ASN1_PCTX_set_nm_flags_introduced)}
    if LibVersion < ASN1_PCTX_set_nm_flags_introduced then
    begin
      {$if declared(FC_ASN1_PCTX_set_nm_flags)}
      ASN1_PCTX_set_nm_flags := FC_ASN1_PCTX_set_nm_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_PCTX_set_nm_flags_removed)}
    if ASN1_PCTX_set_nm_flags_removed <= LibVersion then
    begin
      {$if declared(_ASN1_PCTX_set_nm_flags)}
      ASN1_PCTX_set_nm_flags := _ASN1_PCTX_set_nm_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_PCTX_set_nm_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_PCTX_set_nm_flags');
    {$ifend}
  end;
  
  ASN1_PCTX_get_cert_flags := LoadLibFunction(ADllHandle, ASN1_PCTX_get_cert_flags_procname);
  FuncLoadError := not assigned(ASN1_PCTX_get_cert_flags);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_PCTX_get_cert_flags_allownil)}
    ASN1_PCTX_get_cert_flags := ERR_ASN1_PCTX_get_cert_flags;
    {$ifend}
    {$if declared(ASN1_PCTX_get_cert_flags_introduced)}
    if LibVersion < ASN1_PCTX_get_cert_flags_introduced then
    begin
      {$if declared(FC_ASN1_PCTX_get_cert_flags)}
      ASN1_PCTX_get_cert_flags := FC_ASN1_PCTX_get_cert_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_PCTX_get_cert_flags_removed)}
    if ASN1_PCTX_get_cert_flags_removed <= LibVersion then
    begin
      {$if declared(_ASN1_PCTX_get_cert_flags)}
      ASN1_PCTX_get_cert_flags := _ASN1_PCTX_get_cert_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_PCTX_get_cert_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_PCTX_get_cert_flags');
    {$ifend}
  end;
  
  ASN1_PCTX_set_cert_flags := LoadLibFunction(ADllHandle, ASN1_PCTX_set_cert_flags_procname);
  FuncLoadError := not assigned(ASN1_PCTX_set_cert_flags);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_PCTX_set_cert_flags_allownil)}
    ASN1_PCTX_set_cert_flags := ERR_ASN1_PCTX_set_cert_flags;
    {$ifend}
    {$if declared(ASN1_PCTX_set_cert_flags_introduced)}
    if LibVersion < ASN1_PCTX_set_cert_flags_introduced then
    begin
      {$if declared(FC_ASN1_PCTX_set_cert_flags)}
      ASN1_PCTX_set_cert_flags := FC_ASN1_PCTX_set_cert_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_PCTX_set_cert_flags_removed)}
    if ASN1_PCTX_set_cert_flags_removed <= LibVersion then
    begin
      {$if declared(_ASN1_PCTX_set_cert_flags)}
      ASN1_PCTX_set_cert_flags := _ASN1_PCTX_set_cert_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_PCTX_set_cert_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_PCTX_set_cert_flags');
    {$ifend}
  end;
  
  ASN1_PCTX_get_oid_flags := LoadLibFunction(ADllHandle, ASN1_PCTX_get_oid_flags_procname);
  FuncLoadError := not assigned(ASN1_PCTX_get_oid_flags);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_PCTX_get_oid_flags_allownil)}
    ASN1_PCTX_get_oid_flags := ERR_ASN1_PCTX_get_oid_flags;
    {$ifend}
    {$if declared(ASN1_PCTX_get_oid_flags_introduced)}
    if LibVersion < ASN1_PCTX_get_oid_flags_introduced then
    begin
      {$if declared(FC_ASN1_PCTX_get_oid_flags)}
      ASN1_PCTX_get_oid_flags := FC_ASN1_PCTX_get_oid_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_PCTX_get_oid_flags_removed)}
    if ASN1_PCTX_get_oid_flags_removed <= LibVersion then
    begin
      {$if declared(_ASN1_PCTX_get_oid_flags)}
      ASN1_PCTX_get_oid_flags := _ASN1_PCTX_get_oid_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_PCTX_get_oid_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_PCTX_get_oid_flags');
    {$ifend}
  end;
  
  ASN1_PCTX_set_oid_flags := LoadLibFunction(ADllHandle, ASN1_PCTX_set_oid_flags_procname);
  FuncLoadError := not assigned(ASN1_PCTX_set_oid_flags);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_PCTX_set_oid_flags_allownil)}
    ASN1_PCTX_set_oid_flags := ERR_ASN1_PCTX_set_oid_flags;
    {$ifend}
    {$if declared(ASN1_PCTX_set_oid_flags_introduced)}
    if LibVersion < ASN1_PCTX_set_oid_flags_introduced then
    begin
      {$if declared(FC_ASN1_PCTX_set_oid_flags)}
      ASN1_PCTX_set_oid_flags := FC_ASN1_PCTX_set_oid_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_PCTX_set_oid_flags_removed)}
    if ASN1_PCTX_set_oid_flags_removed <= LibVersion then
    begin
      {$if declared(_ASN1_PCTX_set_oid_flags)}
      ASN1_PCTX_set_oid_flags := _ASN1_PCTX_set_oid_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_PCTX_set_oid_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_PCTX_set_oid_flags');
    {$ifend}
  end;
  
  ASN1_PCTX_get_str_flags := LoadLibFunction(ADllHandle, ASN1_PCTX_get_str_flags_procname);
  FuncLoadError := not assigned(ASN1_PCTX_get_str_flags);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_PCTX_get_str_flags_allownil)}
    ASN1_PCTX_get_str_flags := ERR_ASN1_PCTX_get_str_flags;
    {$ifend}
    {$if declared(ASN1_PCTX_get_str_flags_introduced)}
    if LibVersion < ASN1_PCTX_get_str_flags_introduced then
    begin
      {$if declared(FC_ASN1_PCTX_get_str_flags)}
      ASN1_PCTX_get_str_flags := FC_ASN1_PCTX_get_str_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_PCTX_get_str_flags_removed)}
    if ASN1_PCTX_get_str_flags_removed <= LibVersion then
    begin
      {$if declared(_ASN1_PCTX_get_str_flags)}
      ASN1_PCTX_get_str_flags := _ASN1_PCTX_get_str_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_PCTX_get_str_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_PCTX_get_str_flags');
    {$ifend}
  end;
  
  ASN1_PCTX_set_str_flags := LoadLibFunction(ADllHandle, ASN1_PCTX_set_str_flags_procname);
  FuncLoadError := not assigned(ASN1_PCTX_set_str_flags);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_PCTX_set_str_flags_allownil)}
    ASN1_PCTX_set_str_flags := ERR_ASN1_PCTX_set_str_flags;
    {$ifend}
    {$if declared(ASN1_PCTX_set_str_flags_introduced)}
    if LibVersion < ASN1_PCTX_set_str_flags_introduced then
    begin
      {$if declared(FC_ASN1_PCTX_set_str_flags)}
      ASN1_PCTX_set_str_flags := FC_ASN1_PCTX_set_str_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_PCTX_set_str_flags_removed)}
    if ASN1_PCTX_set_str_flags_removed <= LibVersion then
    begin
      {$if declared(_ASN1_PCTX_set_str_flags)}
      ASN1_PCTX_set_str_flags := _ASN1_PCTX_set_str_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_PCTX_set_str_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_PCTX_set_str_flags');
    {$ifend}
  end;
  
  ASN1_SCTX_new := LoadLibFunction(ADllHandle, ASN1_SCTX_new_procname);
  FuncLoadError := not assigned(ASN1_SCTX_new);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_SCTX_new_allownil)}
    ASN1_SCTX_new := ERR_ASN1_SCTX_new;
    {$ifend}
    {$if declared(ASN1_SCTX_new_introduced)}
    if LibVersion < ASN1_SCTX_new_introduced then
    begin
      {$if declared(FC_ASN1_SCTX_new)}
      ASN1_SCTX_new := FC_ASN1_SCTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_SCTX_new_removed)}
    if ASN1_SCTX_new_removed <= LibVersion then
    begin
      {$if declared(_ASN1_SCTX_new)}
      ASN1_SCTX_new := _ASN1_SCTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_SCTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_SCTX_new');
    {$ifend}
  end;
  
  ASN1_SCTX_free := LoadLibFunction(ADllHandle, ASN1_SCTX_free_procname);
  FuncLoadError := not assigned(ASN1_SCTX_free);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_SCTX_free_allownil)}
    ASN1_SCTX_free := ERR_ASN1_SCTX_free;
    {$ifend}
    {$if declared(ASN1_SCTX_free_introduced)}
    if LibVersion < ASN1_SCTX_free_introduced then
    begin
      {$if declared(FC_ASN1_SCTX_free)}
      ASN1_SCTX_free := FC_ASN1_SCTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_SCTX_free_removed)}
    if ASN1_SCTX_free_removed <= LibVersion then
    begin
      {$if declared(_ASN1_SCTX_free)}
      ASN1_SCTX_free := _ASN1_SCTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_SCTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_SCTX_free');
    {$ifend}
  end;
  
  ASN1_SCTX_get_item := LoadLibFunction(ADllHandle, ASN1_SCTX_get_item_procname);
  FuncLoadError := not assigned(ASN1_SCTX_get_item);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_SCTX_get_item_allownil)}
    ASN1_SCTX_get_item := ERR_ASN1_SCTX_get_item;
    {$ifend}
    {$if declared(ASN1_SCTX_get_item_introduced)}
    if LibVersion < ASN1_SCTX_get_item_introduced then
    begin
      {$if declared(FC_ASN1_SCTX_get_item)}
      ASN1_SCTX_get_item := FC_ASN1_SCTX_get_item;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_SCTX_get_item_removed)}
    if ASN1_SCTX_get_item_removed <= LibVersion then
    begin
      {$if declared(_ASN1_SCTX_get_item)}
      ASN1_SCTX_get_item := _ASN1_SCTX_get_item;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_SCTX_get_item_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_SCTX_get_item');
    {$ifend}
  end;
  
  ASN1_SCTX_get_template := LoadLibFunction(ADllHandle, ASN1_SCTX_get_template_procname);
  FuncLoadError := not assigned(ASN1_SCTX_get_template);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_SCTX_get_template_allownil)}
    ASN1_SCTX_get_template := ERR_ASN1_SCTX_get_template;
    {$ifend}
    {$if declared(ASN1_SCTX_get_template_introduced)}
    if LibVersion < ASN1_SCTX_get_template_introduced then
    begin
      {$if declared(FC_ASN1_SCTX_get_template)}
      ASN1_SCTX_get_template := FC_ASN1_SCTX_get_template;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_SCTX_get_template_removed)}
    if ASN1_SCTX_get_template_removed <= LibVersion then
    begin
      {$if declared(_ASN1_SCTX_get_template)}
      ASN1_SCTX_get_template := _ASN1_SCTX_get_template;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_SCTX_get_template_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_SCTX_get_template');
    {$ifend}
  end;
  
  ASN1_SCTX_get_flags := LoadLibFunction(ADllHandle, ASN1_SCTX_get_flags_procname);
  FuncLoadError := not assigned(ASN1_SCTX_get_flags);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_SCTX_get_flags_allownil)}
    ASN1_SCTX_get_flags := ERR_ASN1_SCTX_get_flags;
    {$ifend}
    {$if declared(ASN1_SCTX_get_flags_introduced)}
    if LibVersion < ASN1_SCTX_get_flags_introduced then
    begin
      {$if declared(FC_ASN1_SCTX_get_flags)}
      ASN1_SCTX_get_flags := FC_ASN1_SCTX_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_SCTX_get_flags_removed)}
    if ASN1_SCTX_get_flags_removed <= LibVersion then
    begin
      {$if declared(_ASN1_SCTX_get_flags)}
      ASN1_SCTX_get_flags := _ASN1_SCTX_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_SCTX_get_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_SCTX_get_flags');
    {$ifend}
  end;
  
  ASN1_SCTX_set_app_data := LoadLibFunction(ADllHandle, ASN1_SCTX_set_app_data_procname);
  FuncLoadError := not assigned(ASN1_SCTX_set_app_data);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_SCTX_set_app_data_allownil)}
    ASN1_SCTX_set_app_data := ERR_ASN1_SCTX_set_app_data;
    {$ifend}
    {$if declared(ASN1_SCTX_set_app_data_introduced)}
    if LibVersion < ASN1_SCTX_set_app_data_introduced then
    begin
      {$if declared(FC_ASN1_SCTX_set_app_data)}
      ASN1_SCTX_set_app_data := FC_ASN1_SCTX_set_app_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_SCTX_set_app_data_removed)}
    if ASN1_SCTX_set_app_data_removed <= LibVersion then
    begin
      {$if declared(_ASN1_SCTX_set_app_data)}
      ASN1_SCTX_set_app_data := _ASN1_SCTX_set_app_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_SCTX_set_app_data_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_SCTX_set_app_data');
    {$ifend}
  end;
  
  ASN1_SCTX_get_app_data := LoadLibFunction(ADllHandle, ASN1_SCTX_get_app_data_procname);
  FuncLoadError := not assigned(ASN1_SCTX_get_app_data);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_SCTX_get_app_data_allownil)}
    ASN1_SCTX_get_app_data := ERR_ASN1_SCTX_get_app_data;
    {$ifend}
    {$if declared(ASN1_SCTX_get_app_data_introduced)}
    if LibVersion < ASN1_SCTX_get_app_data_introduced then
    begin
      {$if declared(FC_ASN1_SCTX_get_app_data)}
      ASN1_SCTX_get_app_data := FC_ASN1_SCTX_get_app_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_SCTX_get_app_data_removed)}
    if ASN1_SCTX_get_app_data_removed <= LibVersion then
    begin
      {$if declared(_ASN1_SCTX_get_app_data)}
      ASN1_SCTX_get_app_data := _ASN1_SCTX_get_app_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_SCTX_get_app_data_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_SCTX_get_app_data');
    {$ifend}
  end;
  
  BIO_f_asn1 := LoadLibFunction(ADllHandle, BIO_f_asn1_procname);
  FuncLoadError := not assigned(BIO_f_asn1);
  if FuncLoadError then
  begin
    {$if not defined(BIO_f_asn1_allownil)}
    BIO_f_asn1 := ERR_BIO_f_asn1;
    {$ifend}
    {$if declared(BIO_f_asn1_introduced)}
    if LibVersion < BIO_f_asn1_introduced then
    begin
      {$if declared(FC_BIO_f_asn1)}
      BIO_f_asn1 := FC_BIO_f_asn1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_f_asn1_removed)}
    if BIO_f_asn1_removed <= LibVersion then
    begin
      {$if declared(_BIO_f_asn1)}
      BIO_f_asn1 := _BIO_f_asn1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_f_asn1_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_f_asn1');
    {$ifend}
  end;
  
  BIO_new_NDEF := LoadLibFunction(ADllHandle, BIO_new_NDEF_procname);
  FuncLoadError := not assigned(BIO_new_NDEF);
  if FuncLoadError then
  begin
    {$if not defined(BIO_new_NDEF_allownil)}
    BIO_new_NDEF := ERR_BIO_new_NDEF;
    {$ifend}
    {$if declared(BIO_new_NDEF_introduced)}
    if LibVersion < BIO_new_NDEF_introduced then
    begin
      {$if declared(FC_BIO_new_NDEF)}
      BIO_new_NDEF := FC_BIO_new_NDEF;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_new_NDEF_removed)}
    if BIO_new_NDEF_removed <= LibVersion then
    begin
      {$if declared(_BIO_new_NDEF)}
      BIO_new_NDEF := _BIO_new_NDEF;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_new_NDEF_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_new_NDEF');
    {$ifend}
  end;
  
  i2d_ASN1_bio_stream := LoadLibFunction(ADllHandle, i2d_ASN1_bio_stream_procname);
  FuncLoadError := not assigned(i2d_ASN1_bio_stream);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ASN1_bio_stream_allownil)}
    i2d_ASN1_bio_stream := ERR_i2d_ASN1_bio_stream;
    {$ifend}
    {$if declared(i2d_ASN1_bio_stream_introduced)}
    if LibVersion < i2d_ASN1_bio_stream_introduced then
    begin
      {$if declared(FC_i2d_ASN1_bio_stream)}
      i2d_ASN1_bio_stream := FC_i2d_ASN1_bio_stream;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ASN1_bio_stream_removed)}
    if i2d_ASN1_bio_stream_removed <= LibVersion then
    begin
      {$if declared(_i2d_ASN1_bio_stream)}
      i2d_ASN1_bio_stream := _i2d_ASN1_bio_stream;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ASN1_bio_stream_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ASN1_bio_stream');
    {$ifend}
  end;
  
  PEM_write_bio_ASN1_stream := LoadLibFunction(ADllHandle, PEM_write_bio_ASN1_stream_procname);
  FuncLoadError := not assigned(PEM_write_bio_ASN1_stream);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_ASN1_stream_allownil)}
    PEM_write_bio_ASN1_stream := ERR_PEM_write_bio_ASN1_stream;
    {$ifend}
    {$if declared(PEM_write_bio_ASN1_stream_introduced)}
    if LibVersion < PEM_write_bio_ASN1_stream_introduced then
    begin
      {$if declared(FC_PEM_write_bio_ASN1_stream)}
      PEM_write_bio_ASN1_stream := FC_PEM_write_bio_ASN1_stream;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_ASN1_stream_removed)}
    if PEM_write_bio_ASN1_stream_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_ASN1_stream)}
      PEM_write_bio_ASN1_stream := _PEM_write_bio_ASN1_stream;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_ASN1_stream_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_ASN1_stream');
    {$ifend}
  end;
  
  SMIME_write_ASN1 := LoadLibFunction(ADllHandle, SMIME_write_ASN1_procname);
  FuncLoadError := not assigned(SMIME_write_ASN1);
  if FuncLoadError then
  begin
    {$if not defined(SMIME_write_ASN1_allownil)}
    SMIME_write_ASN1 := ERR_SMIME_write_ASN1;
    {$ifend}
    {$if declared(SMIME_write_ASN1_introduced)}
    if LibVersion < SMIME_write_ASN1_introduced then
    begin
      {$if declared(FC_SMIME_write_ASN1)}
      SMIME_write_ASN1 := FC_SMIME_write_ASN1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SMIME_write_ASN1_removed)}
    if SMIME_write_ASN1_removed <= LibVersion then
    begin
      {$if declared(_SMIME_write_ASN1)}
      SMIME_write_ASN1 := _SMIME_write_ASN1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SMIME_write_ASN1_allownil)}
    if FuncLoadError then
      AFailed.Add('SMIME_write_ASN1');
    {$ifend}
  end;
  
  SMIME_write_ASN1_ex := LoadLibFunction(ADllHandle, SMIME_write_ASN1_ex_procname);
  FuncLoadError := not assigned(SMIME_write_ASN1_ex);
  if FuncLoadError then
  begin
    {$if not defined(SMIME_write_ASN1_ex_allownil)}
    SMIME_write_ASN1_ex := ERR_SMIME_write_ASN1_ex;
    {$ifend}
    {$if declared(SMIME_write_ASN1_ex_introduced)}
    if LibVersion < SMIME_write_ASN1_ex_introduced then
    begin
      {$if declared(FC_SMIME_write_ASN1_ex)}
      SMIME_write_ASN1_ex := FC_SMIME_write_ASN1_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SMIME_write_ASN1_ex_removed)}
    if SMIME_write_ASN1_ex_removed <= LibVersion then
    begin
      {$if declared(_SMIME_write_ASN1_ex)}
      SMIME_write_ASN1_ex := _SMIME_write_ASN1_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SMIME_write_ASN1_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('SMIME_write_ASN1_ex');
    {$ifend}
  end;
  
  SMIME_read_ASN1 := LoadLibFunction(ADllHandle, SMIME_read_ASN1_procname);
  FuncLoadError := not assigned(SMIME_read_ASN1);
  if FuncLoadError then
  begin
    {$if not defined(SMIME_read_ASN1_allownil)}
    SMIME_read_ASN1 := ERR_SMIME_read_ASN1;
    {$ifend}
    {$if declared(SMIME_read_ASN1_introduced)}
    if LibVersion < SMIME_read_ASN1_introduced then
    begin
      {$if declared(FC_SMIME_read_ASN1)}
      SMIME_read_ASN1 := FC_SMIME_read_ASN1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SMIME_read_ASN1_removed)}
    if SMIME_read_ASN1_removed <= LibVersion then
    begin
      {$if declared(_SMIME_read_ASN1)}
      SMIME_read_ASN1 := _SMIME_read_ASN1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SMIME_read_ASN1_allownil)}
    if FuncLoadError then
      AFailed.Add('SMIME_read_ASN1');
    {$ifend}
  end;
  
  SMIME_read_ASN1_ex := LoadLibFunction(ADllHandle, SMIME_read_ASN1_ex_procname);
  FuncLoadError := not assigned(SMIME_read_ASN1_ex);
  if FuncLoadError then
  begin
    {$if not defined(SMIME_read_ASN1_ex_allownil)}
    SMIME_read_ASN1_ex := ERR_SMIME_read_ASN1_ex;
    {$ifend}
    {$if declared(SMIME_read_ASN1_ex_introduced)}
    if LibVersion < SMIME_read_ASN1_ex_introduced then
    begin
      {$if declared(FC_SMIME_read_ASN1_ex)}
      SMIME_read_ASN1_ex := FC_SMIME_read_ASN1_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SMIME_read_ASN1_ex_removed)}
    if SMIME_read_ASN1_ex_removed <= LibVersion then
    begin
      {$if declared(_SMIME_read_ASN1_ex)}
      SMIME_read_ASN1_ex := _SMIME_read_ASN1_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SMIME_read_ASN1_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('SMIME_read_ASN1_ex');
    {$ifend}
  end;
  
  SMIME_crlf_copy := LoadLibFunction(ADllHandle, SMIME_crlf_copy_procname);
  FuncLoadError := not assigned(SMIME_crlf_copy);
  if FuncLoadError then
  begin
    {$if not defined(SMIME_crlf_copy_allownil)}
    SMIME_crlf_copy := ERR_SMIME_crlf_copy;
    {$ifend}
    {$if declared(SMIME_crlf_copy_introduced)}
    if LibVersion < SMIME_crlf_copy_introduced then
    begin
      {$if declared(FC_SMIME_crlf_copy)}
      SMIME_crlf_copy := FC_SMIME_crlf_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SMIME_crlf_copy_removed)}
    if SMIME_crlf_copy_removed <= LibVersion then
    begin
      {$if declared(_SMIME_crlf_copy)}
      SMIME_crlf_copy := _SMIME_crlf_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SMIME_crlf_copy_allownil)}
    if FuncLoadError then
      AFailed.Add('SMIME_crlf_copy');
    {$ifend}
  end;
  
  SMIME_text := LoadLibFunction(ADllHandle, SMIME_text_procname);
  FuncLoadError := not assigned(SMIME_text);
  if FuncLoadError then
  begin
    {$if not defined(SMIME_text_allownil)}
    SMIME_text := ERR_SMIME_text;
    {$ifend}
    {$if declared(SMIME_text_introduced)}
    if LibVersion < SMIME_text_introduced then
    begin
      {$if declared(FC_SMIME_text)}
      SMIME_text := FC_SMIME_text;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SMIME_text_removed)}
    if SMIME_text_removed <= LibVersion then
    begin
      {$if declared(_SMIME_text)}
      SMIME_text := _SMIME_text;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SMIME_text_allownil)}
    if FuncLoadError then
      AFailed.Add('SMIME_text');
    {$ifend}
  end;
  
  ASN1_ITEM_lookup := LoadLibFunction(ADllHandle, ASN1_ITEM_lookup_procname);
  FuncLoadError := not assigned(ASN1_ITEM_lookup);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_ITEM_lookup_allownil)}
    ASN1_ITEM_lookup := ERR_ASN1_ITEM_lookup;
    {$ifend}
    {$if declared(ASN1_ITEM_lookup_introduced)}
    if LibVersion < ASN1_ITEM_lookup_introduced then
    begin
      {$if declared(FC_ASN1_ITEM_lookup)}
      ASN1_ITEM_lookup := FC_ASN1_ITEM_lookup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_ITEM_lookup_removed)}
    if ASN1_ITEM_lookup_removed <= LibVersion then
    begin
      {$if declared(_ASN1_ITEM_lookup)}
      ASN1_ITEM_lookup := _ASN1_ITEM_lookup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_ITEM_lookup_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_ITEM_lookup');
    {$ifend}
  end;
  
  ASN1_ITEM_get := LoadLibFunction(ADllHandle, ASN1_ITEM_get_procname);
  FuncLoadError := not assigned(ASN1_ITEM_get);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_ITEM_get_allownil)}
    ASN1_ITEM_get := ERR_ASN1_ITEM_get;
    {$ifend}
    {$if declared(ASN1_ITEM_get_introduced)}
    if LibVersion < ASN1_ITEM_get_introduced then
    begin
      {$if declared(FC_ASN1_ITEM_get)}
      ASN1_ITEM_get := FC_ASN1_ITEM_get;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_ITEM_get_removed)}
    if ASN1_ITEM_get_removed <= LibVersion then
    begin
      {$if declared(_ASN1_ITEM_get)}
      ASN1_ITEM_get := _ASN1_ITEM_get;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_ITEM_get_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_ITEM_get');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  d2i_ASN1_SEQUENCE_ANY := nil;
  i2d_ASN1_SEQUENCE_ANY := nil;
  ASN1_SEQUENCE_ANY_it := nil;
  d2i_ASN1_SET_ANY := nil;
  i2d_ASN1_SET_ANY := nil;
  ASN1_SET_ANY_it := nil;
  ASN1_TYPE_new := nil;
  ASN1_TYPE_free := nil;
  d2i_ASN1_TYPE := nil;
  i2d_ASN1_TYPE := nil;
  ASN1_ANY_it := nil;
  ASN1_TYPE_get := nil;
  ASN1_TYPE_set := nil;
  ASN1_TYPE_set1 := nil;
  ASN1_TYPE_cmp := nil;
  ASN1_TYPE_pack_sequence := nil;
  ASN1_TYPE_unpack_sequence := nil;
  ASN1_OBJECT_new := nil;
  ASN1_OBJECT_free := nil;
  d2i_ASN1_OBJECT := nil;
  i2d_ASN1_OBJECT := nil;
  ASN1_OBJECT_it := nil;
  ASN1_STRING_new := nil;
  ASN1_STRING_free := nil;
  ASN1_STRING_clear_free := nil;
  ASN1_STRING_copy := nil;
  ASN1_STRING_dup := nil;
  ASN1_STRING_type_new := nil;
  ASN1_STRING_cmp := nil;
  ASN1_STRING_set := nil;
  ASN1_STRING_set0 := nil;
  ASN1_STRING_length := nil;
  ASN1_STRING_length_set := nil;
  ASN1_STRING_type := nil;
  ASN1_STRING_get0_data := nil;
  ASN1_BIT_STRING_new := nil;
  ASN1_BIT_STRING_free := nil;
  d2i_ASN1_BIT_STRING := nil;
  i2d_ASN1_BIT_STRING := nil;
  ASN1_BIT_STRING_it := nil;
  ASN1_BIT_STRING_set := nil;
  ASN1_BIT_STRING_set_bit := nil;
  ASN1_BIT_STRING_get_bit := nil;
  ASN1_BIT_STRING_check := nil;
  ASN1_BIT_STRING_name_print := nil;
  ASN1_BIT_STRING_num_asc := nil;
  ASN1_BIT_STRING_set_asc := nil;
  ASN1_INTEGER_new := nil;
  ASN1_INTEGER_free := nil;
  d2i_ASN1_INTEGER := nil;
  i2d_ASN1_INTEGER := nil;
  ASN1_INTEGER_it := nil;
  d2i_ASN1_UINTEGER := nil;
  ASN1_INTEGER_dup := nil;
  ASN1_INTEGER_cmp := nil;
  ASN1_ENUMERATED_new := nil;
  ASN1_ENUMERATED_free := nil;
  d2i_ASN1_ENUMERATED := nil;
  i2d_ASN1_ENUMERATED := nil;
  ASN1_ENUMERATED_it := nil;
  ASN1_UTCTIME_check := nil;
  ASN1_UTCTIME_set := nil;
  ASN1_UTCTIME_adj := nil;
  ASN1_UTCTIME_set_string := nil;
  ASN1_UTCTIME_cmp_time_t := nil;
  ASN1_GENERALIZEDTIME_check := nil;
  ASN1_GENERALIZEDTIME_set := nil;
  ASN1_GENERALIZEDTIME_adj := nil;
  ASN1_GENERALIZEDTIME_set_string := nil;
  ASN1_TIME_diff := nil;
  ASN1_OCTET_STRING_new := nil;
  ASN1_OCTET_STRING_free := nil;
  d2i_ASN1_OCTET_STRING := nil;
  i2d_ASN1_OCTET_STRING := nil;
  ASN1_OCTET_STRING_it := nil;
  ASN1_OCTET_STRING_dup := nil;
  ASN1_OCTET_STRING_cmp := nil;
  ASN1_OCTET_STRING_set := nil;
  ASN1_VISIBLESTRING_new := nil;
  ASN1_VISIBLESTRING_free := nil;
  d2i_ASN1_VISIBLESTRING := nil;
  i2d_ASN1_VISIBLESTRING := nil;
  ASN1_VISIBLESTRING_it := nil;
  ASN1_UNIVERSALSTRING_new := nil;
  ASN1_UNIVERSALSTRING_free := nil;
  d2i_ASN1_UNIVERSALSTRING := nil;
  i2d_ASN1_UNIVERSALSTRING := nil;
  ASN1_UNIVERSALSTRING_it := nil;
  ASN1_UTF8STRING_new := nil;
  ASN1_UTF8STRING_free := nil;
  d2i_ASN1_UTF8STRING := nil;
  i2d_ASN1_UTF8STRING := nil;
  ASN1_UTF8STRING_it := nil;
  ASN1_NULL_new := nil;
  ASN1_NULL_free := nil;
  d2i_ASN1_NULL := nil;
  i2d_ASN1_NULL := nil;
  ASN1_NULL_it := nil;
  ASN1_BMPSTRING_new := nil;
  ASN1_BMPSTRING_free := nil;
  d2i_ASN1_BMPSTRING := nil;
  i2d_ASN1_BMPSTRING := nil;
  ASN1_BMPSTRING_it := nil;
  UTF8_getc := nil;
  UTF8_putc := nil;
  ASN1_PRINTABLE_new := nil;
  ASN1_PRINTABLE_free := nil;
  d2i_ASN1_PRINTABLE := nil;
  i2d_ASN1_PRINTABLE := nil;
  ASN1_PRINTABLE_it := nil;
  DIRECTORYSTRING_new := nil;
  DIRECTORYSTRING_free := nil;
  d2i_DIRECTORYSTRING := nil;
  i2d_DIRECTORYSTRING := nil;
  DIRECTORYSTRING_it := nil;
  DISPLAYTEXT_new := nil;
  DISPLAYTEXT_free := nil;
  d2i_DISPLAYTEXT := nil;
  i2d_DISPLAYTEXT := nil;
  DISPLAYTEXT_it := nil;
  ASN1_PRINTABLESTRING_new := nil;
  ASN1_PRINTABLESTRING_free := nil;
  d2i_ASN1_PRINTABLESTRING := nil;
  i2d_ASN1_PRINTABLESTRING := nil;
  ASN1_PRINTABLESTRING_it := nil;
  ASN1_T61STRING_new := nil;
  ASN1_T61STRING_free := nil;
  d2i_ASN1_T61STRING := nil;
  i2d_ASN1_T61STRING := nil;
  ASN1_T61STRING_it := nil;
  ASN1_IA5STRING_new := nil;
  ASN1_IA5STRING_free := nil;
  d2i_ASN1_IA5STRING := nil;
  i2d_ASN1_IA5STRING := nil;
  ASN1_IA5STRING_it := nil;
  ASN1_GENERALSTRING_new := nil;
  ASN1_GENERALSTRING_free := nil;
  d2i_ASN1_GENERALSTRING := nil;
  i2d_ASN1_GENERALSTRING := nil;
  ASN1_GENERALSTRING_it := nil;
  ASN1_UTCTIME_new := nil;
  ASN1_UTCTIME_free := nil;
  d2i_ASN1_UTCTIME := nil;
  i2d_ASN1_UTCTIME := nil;
  ASN1_UTCTIME_it := nil;
  ASN1_GENERALIZEDTIME_new := nil;
  ASN1_GENERALIZEDTIME_free := nil;
  d2i_ASN1_GENERALIZEDTIME := nil;
  i2d_ASN1_GENERALIZEDTIME := nil;
  ASN1_GENERALIZEDTIME_it := nil;
  ASN1_TIME_new := nil;
  ASN1_TIME_free := nil;
  d2i_ASN1_TIME := nil;
  i2d_ASN1_TIME := nil;
  ASN1_TIME_it := nil;
  ASN1_TIME_dup := nil;
  ASN1_UTCTIME_dup := nil;
  ASN1_GENERALIZEDTIME_dup := nil;
  ASN1_OCTET_STRING_NDEF_it := nil;
  ASN1_TIME_set := nil;
  ASN1_TIME_adj := nil;
  ASN1_TIME_check := nil;
  ASN1_TIME_to_generalizedtime := nil;
  ASN1_TIME_set_string := nil;
  ASN1_TIME_set_string_X509 := nil;
  ASN1_TIME_to_tm := nil;
  ASN1_TIME_normalize := nil;
  ASN1_TIME_cmp_time_t := nil;
  ASN1_TIME_compare := nil;
  i2a_ASN1_INTEGER := nil;
  a2i_ASN1_INTEGER := nil;
  i2a_ASN1_ENUMERATED := nil;
  a2i_ASN1_ENUMERATED := nil;
  i2a_ASN1_OBJECT := nil;
  a2i_ASN1_STRING := nil;
  i2a_ASN1_STRING := nil;
  i2t_ASN1_OBJECT := nil;
  a2d_ASN1_OBJECT := nil;
  ASN1_OBJECT_create := nil;
  ASN1_INTEGER_get_int64 := nil;
  ASN1_INTEGER_set_int64 := nil;
  ASN1_INTEGER_get_uint64 := nil;
  ASN1_INTEGER_set_uint64 := nil;
  ASN1_INTEGER_set := nil;
  ASN1_INTEGER_get := nil;
  BN_to_ASN1_INTEGER := nil;
  ASN1_INTEGER_to_BN := nil;
  ASN1_ENUMERATED_get_int64 := nil;
  ASN1_ENUMERATED_set_int64 := nil;
  ASN1_ENUMERATED_set := nil;
  ASN1_ENUMERATED_get := nil;
  BN_to_ASN1_ENUMERATED := nil;
  ASN1_ENUMERATED_to_BN := nil;
  ASN1_PRINTABLE_type := nil;
  ASN1_tag2bit := nil;
  ASN1_get_object := nil;
  ASN1_check_infinite_end := nil;
  ASN1_const_check_infinite_end := nil;
  ASN1_put_object := nil;
  ASN1_put_eoc := nil;
  ASN1_object_size := nil;
  ASN1_dup := nil;
  ASN1_item_dup := nil;
  ASN1_item_sign_ex := nil;
  ASN1_item_verify_ex := nil;
  ASN1_d2i_fp := nil;
  ASN1_item_d2i_fp_ex := nil;
  ASN1_item_d2i_fp := nil;
  ASN1_i2d_fp := nil;
  ASN1_item_i2d_fp := nil;
  ASN1_STRING_print_ex_fp := nil;
  ASN1_STRING_to_UTF8 := nil;
  ASN1_d2i_bio := nil;
  ASN1_item_d2i_bio_ex := nil;
  ASN1_item_d2i_bio := nil;
  ASN1_i2d_bio := nil;
  ASN1_item_i2d_bio := nil;
  ASN1_item_i2d_mem_bio := nil;
  ASN1_UTCTIME_print := nil;
  ASN1_GENERALIZEDTIME_print := nil;
  ASN1_TIME_print := nil;
  ASN1_TIME_print_ex := nil;
  ASN1_STRING_print := nil;
  ASN1_STRING_print_ex := nil;
  ASN1_buf_print := nil;
  ASN1_bn_print := nil;
  ASN1_parse := nil;
  ASN1_parse_dump := nil;
  ASN1_tag2str := nil;
  ASN1_UNIVERSALSTRING_to_string := nil;
  ASN1_TYPE_set_octetstring := nil;
  ASN1_TYPE_get_octetstring := nil;
  ASN1_TYPE_set_int_octetstring := nil;
  ASN1_TYPE_get_int_octetstring := nil;
  ASN1_item_unpack := nil;
  ASN1_item_unpack_ex := nil;
  ASN1_item_pack := nil;
  ASN1_STRING_set_default_mask := nil;
  ASN1_STRING_set_default_mask_asc := nil;
  ASN1_STRING_get_default_mask := nil;
  ASN1_mbstring_copy := nil;
  ASN1_mbstring_ncopy := nil;
  ASN1_STRING_set_by_NID := nil;
  ASN1_STRING_TABLE_get := nil;
  ASN1_STRING_TABLE_add := nil;
  ASN1_STRING_TABLE_cleanup := nil;
  ASN1_item_new := nil;
  ASN1_item_new_ex := nil;
  ASN1_item_free := nil;
  ASN1_item_d2i_ex := nil;
  ASN1_item_d2i := nil;
  ASN1_item_i2d := nil;
  ASN1_item_ndef_i2d := nil;
  ASN1_add_oid_module := nil;
  ASN1_add_stable_module := nil;
  ASN1_generate_nconf := nil;
  ASN1_generate_v3 := nil;
  ASN1_str2mask := nil;
  ASN1_item_print := nil;
  ASN1_PCTX_new := nil;
  ASN1_PCTX_free := nil;
  ASN1_PCTX_get_flags := nil;
  ASN1_PCTX_set_flags := nil;
  ASN1_PCTX_get_nm_flags := nil;
  ASN1_PCTX_set_nm_flags := nil;
  ASN1_PCTX_get_cert_flags := nil;
  ASN1_PCTX_set_cert_flags := nil;
  ASN1_PCTX_get_oid_flags := nil;
  ASN1_PCTX_set_oid_flags := nil;
  ASN1_PCTX_get_str_flags := nil;
  ASN1_PCTX_set_str_flags := nil;
  ASN1_SCTX_new := nil;
  ASN1_SCTX_free := nil;
  ASN1_SCTX_get_item := nil;
  ASN1_SCTX_get_template := nil;
  ASN1_SCTX_get_flags := nil;
  ASN1_SCTX_set_app_data := nil;
  ASN1_SCTX_get_app_data := nil;
  BIO_f_asn1 := nil;
  BIO_new_NDEF := nil;
  i2d_ASN1_bio_stream := nil;
  PEM_write_bio_ASN1_stream := nil;
  SMIME_write_ASN1 := nil;
  SMIME_write_ASN1_ex := nil;
  SMIME_read_ASN1 := nil;
  SMIME_read_ASN1_ex := nil;
  SMIME_crlf_copy := nil;
  SMIME_text := nil;
  ASN1_ITEM_lookup := nil;
  ASN1_ITEM_get := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.