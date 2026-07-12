/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_asn1.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_asn1.h2pas
     and this file regenerated. TaurusTLSHeaders_asn1.h2pas is distributed with the full Indy
     Distribution.
   *)

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

// Headers for OpenSSL 1.1.1
// asn1.h


uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_asn1t,
  TaurusTLSHeaders_bio,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_stack;

{$MINENUMSIZE 4}

const
  (*
   * NB the constants below are used internally by ASN1_INTEGER
   * and ASN1_ENUMERATED to indicate the sign. They are *not* on
   * the wire tag values.
   *)

  {$EXTERNALSYM V_ASN1_NEG}
  V_ASN1_NEG = $100;
  {$EXTERNALSYM V_ASN1_NEG_INTEGER}
  V_ASN1_NEG_INTEGER = 2 or V_ASN1_NEG;
  {$EXTERNALSYM V_ASN1_NEG_ENUMERATED}
  V_ASN1_NEG_ENUMERATED = 10 or V_ASN1_NEG;

  (* For use with d2i_ASN1_type_bytes() *)
  {$EXTERNALSYM B_ASN1_NUMERICSTRING}
  B_ASN1_NUMERICSTRING = $0001;
  {$EXTERNALSYM B_ASN1_PRINTABLESTRING}
  B_ASN1_PRINTABLESTRING = $0002;
  {$EXTERNALSYM B_ASN1_T61STRING}
  B_ASN1_T61STRING = $0004;
  {$EXTERNALSYM B_ASN1_TELETEXSTRING}
  B_ASN1_TELETEXSTRING = $0004;
  {$EXTERNALSYM B_ASN1_VIDEOTEXSTRING}
  B_ASN1_VIDEOTEXSTRING = $0008;
  {$EXTERNALSYM B_ASN1_IA5STRING}
  B_ASN1_IA5STRING = $0010;
  {$EXTERNALSYM B_ASN1_GRAPHICSTRING}
  B_ASN1_GRAPHICSTRING = $0020;
  {$EXTERNALSYM B_ASN1_ISO64STRING}
  B_ASN1_ISO64STRING = $0040;
  {$EXTERNALSYM B_ASN1_VISIBLESTRING}
  B_ASN1_VISIBLESTRING = $0040;
  {$EXTERNALSYM B_ASN1_GENERALSTRING}
  B_ASN1_GENERALSTRING = $0080;
  {$EXTERNALSYM B_ASN1_UNIVERSALSTRING}
  B_ASN1_UNIVERSALSTRING = $0100;
  {$EXTERNALSYM B_ASN1_OCTET_STRING}
  B_ASN1_OCTET_STRING = $0200;
  {$EXTERNALSYM B_ASN1_BIT_STRING}
  B_ASN1_BIT_STRING = $0400;
  {$EXTERNALSYM B_ASN1_BMPSTRING}
  B_ASN1_BMPSTRING = $0800;
  {$EXTERNALSYM B_ASN1_UNKNOWN}
  B_ASN1_UNKNOWN = $1000;
  {$EXTERNALSYM B_ASN1_UTF8STRING}
  B_ASN1_UTF8STRING = $2000;
  {$EXTERNALSYM B_ASN1_UTCTIME}
  B_ASN1_UTCTIME = $4000;
  {$EXTERNALSYM B_ASN1_GENERALIZEDTIME}
  B_ASN1_GENERALIZEDTIME = $8000;
  {$EXTERNALSYM B_ASN1_SEQUENCE}
  B_ASN1_SEQUENCE = $10000;
 (* For use with ASN1_mbstring_copy() *)
  {$EXTERNALSYM MBSTRING_FLAG}
  MBSTRING_FLAG = $1000;
  {$EXTERNALSYM MBSTRING_UTF8}
  MBSTRING_UTF8 = MBSTRING_FLAG;
  {$EXTERNALSYM MBSTRING_ASC}
  MBSTRING_ASC = MBSTRING_FLAG or 1;
  {$EXTERNALSYM MBSTRING_BMP}
  MBSTRING_BMP = MBSTRING_FLAG or 2;
  {$EXTERNALSYM MBSTRING_UNIV}
  MBSTRING_UNIV = MBSTRING_FLAG or 4;
  {$EXTERNALSYM SMIME_OLDMIME}
  SMIME_OLDMIME = $400;
  {$EXTERNALSYM SMIME_CRLFEOL}
  SMIME_CRLFEOL = $800;
  {$EXTERNALSYM SMIME_STREAM}
  SMIME_STREAM = $1000;

{
These are now opaque in OpenSSL 4.0.
}
//  ASN1_STRING_FLAG_BITS_LEFT = $08;   (* Set if $07 has bits left value *)
  (*
   * This indicates that the ASN1_STRING is not a real value but just a place
   * holder for the location where indefinite length constructed data should be
   * inserted in the memory buffer
   *)
//  ASN1_STRING_FLAG_NDEF = $010;

  (*
   * This flag is used by the CMS code to indicate that a string is not
   * complete and is a place holder for content when it had all been accessed.
   * The flag will be reset when content has been written to it.
   *)

//  ASN1_STRING_FLAG_CONT = $020;
  (*
   * This flag is used by ASN1 code to indicate an ASN1_STRING is an MSTRING
   * type.
   *)
//  ASN1_STRING_FLAG_MSTRING = $040;
  (* String is embedded and only content should be freed *)
//  ASN1_STRING_FLAG_EMBED = $080;
  (* String should be parsed in RFC 5280's time format *)
  {$EXTERNALSYM ASN1_STRING_FLAG_X509_TIME}
  ASN1_STRING_FLAG_X509_TIME = $100;

  (* Used with ASN1 LONG type: if a long is set to this it is omitted *)
  {$EXTERNALSYM ASN1_LONG_UNDEF}
  ASN1_LONG_UNDEF = TIdC_LONG($7fffffff);

  {$EXTERNALSYM STABLE_FLAGS_MALLOC}
  STABLE_FLAGS_MALLOC = $01;
  (*
   * A zero passed to ASN1_STRING_TABLE_new_add for the flags is interpreted
   * as "don't change" and STABLE_FLAGS_MALLOC is always set. By setting
   * STABLE_FLAGS_MALLOC only we can clear the existing value. Use the alias
   * STABLE_FLAGS_CLEAR to reflect this.
   *)
  {$EXTERNALSYM STABLE_FLAGS_CLEAR}
  STABLE_FLAGS_CLEAR = STABLE_FLAGS_MALLOC;
  {$EXTERNALSYM STABLE_NO_MASK}
  STABLE_NO_MASK = $02;
  {$EXTERNALSYM DIRSTRING_TYPE}
  DIRSTRING_TYPE = B_ASN1_PRINTABLESTRING or B_ASN1_T61STRING or B_ASN1_BMPSTRING or B_ASN1_UTF8STRING;
  {$EXTERNALSYM PKCS9STRING_TYPE}
  PKCS9STRING_TYPE = DIRSTRING_TYPE or B_ASN1_IA5STRING;

  (* size limits: this stuff is taken straight from RFC2459 *)
  {$EXTERNALSYM ub_name}
  ub_name = 32768;
  {$EXTERNALSYM ub_common_name}
  ub_common_name = 64;
  {$EXTERNALSYM ub_locality_name}
  ub_locality_name = 128;
  {$EXTERNALSYM ub_state_name}
  ub_state_name = 128;
  {$EXTERNALSYM ub_organization_name}
  ub_organization_name = 64;
  {$EXTERNALSYM ub_organization_unit_name}
  ub_organization_unit_name = 64;
  {$EXTERNALSYM ub_title}
  ub_title = 64;
  {$EXTERNALSYM ub_email_address}
  ub_email_address = 128;

  (* Parameters used by ASN1_STRING_print_ex() *)

  (*
   * These determine which characters to escape: RFC2253 special characters,
   * control characters and MSB set characters
   *)
  {$EXTERNALSYM ASN1_STRFLGS_ESC_2253}
  ASN1_STRFLGS_ESC_2253 = 1;
  {$EXTERNALSYM ASN1_STRFLGS_ESC_CTRL}
  ASN1_STRFLGS_ESC_CTRL = 2;
  {$EXTERNALSYM ASN1_STRFLGS_ESC_MSB}
  ASN1_STRFLGS_ESC_MSB = 4;

  (*
   * This flag determines how we do escaping: normally RC2253 backslash only,
   * set this to use backslash and quote.
   *)

  {$EXTERNALSYM ASN1_STRFLGS_ESC_QUOTE}
  ASN1_STRFLGS_ESC_QUOTE = 8;

  (* These three flags are internal use only. *)

  (* Character is a valid PrintableString character *)
  {$EXTERNALSYM CHARTYPE_PRINTABLESTRING}
  CHARTYPE_PRINTABLESTRING = $10;
  (* Character needs escaping if it is the first character *)
  {$EXTERNALSYM CHARTYPE_FIRST_ESC_2253}
  CHARTYPE_FIRST_ESC_2253 = $20;
  (* Character needs escaping if it is the last character *)
  {$EXTERNALSYM CHARTYPE_LAST_ESC_2253}
  CHARTYPE_LAST_ESC_2253 = $40;

  (*
   * NB the internal flags are safely reused below by flags handled at the top
   * level.
   *)

  (*
   * If this is set we convert all character strings to UTF8 first
   *)

  {$EXTERNALSYM ASN1_STRFLGS_UTF8_CONVERT}
  ASN1_STRFLGS_UTF8_CONVERT = $10;

  (*
   * If this is set we don't attempt to interpret content: just assume all
   * strings are 1 byte per character. This will produce some pretty odd
   * looking output!
   *)

  {$EXTERNALSYM ASN1_STRFLGS_IGNORE_TYPE}
  ASN1_STRFLGS_IGNORE_TYPE = $20;

  (* If this is set we include the string type in the output *)
  {$EXTERNALSYM ASN1_STRFLGS_SHOW_TYPE}
  ASN1_STRFLGS_SHOW_TYPE = $40;

  (*
   * This determines which strings to display and which to 'dump' (hex dump of
   * content octets or DER encoding). We can only dump non character strings or
   * everything. If we don't dump 'unknown' they are interpreted as character
   * strings with 1 octet per character and are subject to the usual escaping
   * options.
   *)

  {$EXTERNALSYM ASN1_STRFLGS_DUMP_ALL}
  ASN1_STRFLGS_DUMP_ALL = $80;
  {$EXTERNALSYM ASN1_STRFLGS_DUMP_UNKNOWN}
  ASN1_STRFLGS_DUMP_UNKNOWN = $100;

  (*
   * These determine what 'dumping' does, we can dump the content octets or the
   * DER encoding: both use the RFC2253 #XXXXX notation.
   *)

  {$EXTERNALSYM ASN1_STRFLGS_DUMP_DER}
  ASN1_STRFLGS_DUMP_DER = $200;

  (*
   * This flag specifies that RC2254 escaping shall be performed.
   *)

  {$EXTERNALSYM ASN1_STRFLGS_ESC_2254}
  ASN1_STRFLGS_ESC_2254 = $400;

  (*
   * All the string flags consistent with RFC2253, escaping control characters
   * isn't essential in RFC2253 but it is advisable anyway.
   *)

  {$EXTERNALSYM ASN1_STRFLGS_RFC2253}
  ASN1_STRFLGS_RFC2253 = ASN1_STRFLGS_ESC_2253 or ASN1_STRFLGS_ESC_CTRL or
    ASN1_STRFLGS_ESC_MSB or ASN1_STRFLGS_UTF8_CONVERT or
    ASN1_STRFLGS_DUMP_UNKNOWN or ASN1_STRFLGS_DUMP_DER;

  {$EXTERNALSYM B_ASN1_TIME}
  B_ASN1_TIME = B_ASN1_UTCTIME or B_ASN1_GENERALIZEDTIME;

  {$EXTERNALSYM B_ASN1_PRINTABLE}
  B_ASN1_PRINTABLE = B_ASN1_NUMERICSTRING or B_ASN1_PRINTABLESTRING or
    B_ASN1_T61STRING or B_ASN1_IA5STRING or B_ASN1_BIT_STRING or
    B_ASN1_UNIVERSALSTRING or B_ASN1_BMPSTRING or B_ASN1_UTF8STRING or
    B_ASN1_SEQUENCE or B_ASN1_UNKNOWN;

  {$EXTERNALSYM B_ASN1_DIRECTORYSTRING}
  B_ASN1_DIRECTORYSTRING = B_ASN1_PRINTABLESTRING or B_ASN1_TELETEXSTRING or
    B_ASN1_BMPSTRING or B_ASN1_UNIVERSALSTRING or B_ASN1_UTF8STRING;

  {$EXTERNALSYM B_ASN1_DISPLAYTEXT}
  B_ASN1_DISPLAYTEXT = B_ASN1_IA5STRING or B_ASN1_VISIBLESTRING or
    B_ASN1_BMPSTRING or B_ASN1_UTF8STRING;

  (* ASN1 Print flags *)
  (* Indicate missing OPTIONAL fields *)
  {$EXTERNALSYM ASN1_PCTX_FLAGS_SHOW_ABSENT}
  ASN1_PCTX_FLAGS_SHOW_ABSENT = $001;
  (* Mark start and end of SEQUENCE *)
  {$EXTERNALSYM ASN1_PCTX_FLAGS_SHOW_SEQUENCE}
  ASN1_PCTX_FLAGS_SHOW_SEQUENCE = $002;
  (* Mark start and end of SEQUENCE/SET OF *)
  {$EXTERNALSYM ASN1_PCTX_FLAGS_SHOW_SSOF}
  ASN1_PCTX_FLAGS_SHOW_SSOF = $004;
  (* Show the ASN1 type of primitives *)
  {$EXTERNALSYM ASN1_PCTX_FLAGS_SHOW_TYPE}
  ASN1_PCTX_FLAGS_SHOW_TYPE = $008;
  (* Don't show ASN1 type of ANY *)
  {$EXTERNALSYM ASN1_PCTX_FLAGS_NO_ANY_TYPE}
  ASN1_PCTX_FLAGS_NO_ANY_TYPE = $010;
  (* Don't show ASN1 type of MSTRINGs *)
  {$EXTERNALSYM ASN1_PCTX_FLAGS_NO_MSTRING_TYPE}
  ASN1_PCTX_FLAGS_NO_MSTRING_TYPE = $020;
  (* Don't show field names in SEQUENCE *)
  {$EXTERNALSYM ASN1_PCTX_FLAGS_NO_FIELD_NAME}
  ASN1_PCTX_FLAGS_NO_FIELD_NAME = $040;
  (* Show structure names of each SEQUENCE field *)
  {$EXTERNALSYM ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME}
  ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME = $080;
  (* Don't show structure name even at top level *)
  {$EXTERNALSYM ASN1_PCTX_FLAGS_NO_STRUCT_NAME}
  ASN1_PCTX_FLAGS_NO_STRUCT_NAME = $100;

type
  {$EXTERNALSYM STACK_OF_ASN1_OBJECT}
  STACK_OF_ASN1_OBJECT = record end;
  {$EXTERNALSYM PSTACK_OF_ASN1_OBJECT}
  PSTACK_OF_ASN1_OBJECT = ^STACK_OF_ASN1_OBJECT;
  {$EXTERNALSYM STACK_OF_X509_ALGOR}
  STACK_OF_X509_ALGOR = record end;
  {$EXTERNALSYM PSTACK_OF_X509_ALGOR}
  PSTACK_OF_X509_ALGOR = ^STACK_OF_X509_ALGOR;
// Moved to ossl_type to prevent circular references
///(* This is the base type that holds just about everything :-) *)
//  asn1_string_st = record
//    _length: TIdC_int;
//    type_: TIdC_int;
//    data: PByte;
//    (*
//     * The value of the following field depends on the type being held.  It
//     * is mostly being used for BIT_STRING so if the input data has a
//     * non-zero 'unused bits' value, it will be handled correctly
//     *)
//    flags: TIdC_long;
//  end;

  {$EXTERNALSYM pxnew}
  pxnew = function: Pointer; cdecl;
  {$EXTERNALSYM pd2i_of_void}
  pd2i_of_void = function(val_out: PPointer; const der_in: PPByte; _length: TIdC_LONG): Pointer; cdecl;
  (*
   * ASN1_ENCODING structure: this is used to save the received encoding of an
   * ASN1 type. This is useful to get round problems with invalid encodings
   * which can break signatures.
   *)

  {$EXTERNALSYM ASN1_ENCODING_st}
  ASN1_ENCODING_st = record
    enc: PIdAnsiChar;           (* DER encoding *)
    len: TIdC_LONG;                     (* Length of encoding *)
    modified: TIdC_INT;                 (* set to 1 if 'enc' is invalid *)
  end;
  {$EXTERNALSYM ASN1_ENCODING}
  ASN1_ENCODING = ASN1_ENCODING_st;

  {$EXTERNALSYM asn1_string_table_st}
  asn1_string_table_st = record
    nid: TIdC_INT;
    minsize: TIdC_LONG;
    maxsize: TIdC_LONG;
    mask: TIdC_ULONG;
    flags: TIdC_ULONG;
  end;
  {$EXTERNALSYM ASN1_STRING_TABLE}
  ASN1_STRING_TABLE = asn1_string_table_st;
  {$EXTERNALSYM PASN1_STRING_TABLE}
  PASN1_STRING_TABLE = ^ASN1_STRING_TABLE;
  {$EXTERNALSYM STACK_OF_ASN1_STRING_TABLE}
  STACK_OF_ASN1_STRING_TABLE = record end;
  {$EXTERNALSYM PSTACK_OF_ASN1_STRING_TABLE}
  PSTACK_OF_ASN1_STRING_TABLE = ^STACK_OF_ASN1_STRING_TABLE;
// DEFINE_STACK_OF(ASN1_STRING_TABLE)

  (*                  !!!
   * Declarations for template structures: for full definitions see asn1t.h
   *)
  (* This is just an opaque pointer *)
// typedef struct ASN1_VALUE_st ASN1_VALUE;

  (* Declare ASN1 functions: the implement macro in in asn1t.h *)

//# define DECLARE_ASN1_FUNCTIONS(type) DECLARE_ASN1_FUNCTIONS_name(type, type)
//
//# define DECLARE_ASN1_ALLOC_FUNCTIONS(type) \
//        DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, type)
//
//# define DECLARE_ASN1_FUNCTIONS_name(type, name) \
//        DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, name) \
//        DECLARE_ASN1_ENCODE_FUNCTIONS(type, name, name)
//
//# define DECLARE_ASN1_FUNCTIONS_fname(type, itname, name) \
//        DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, name) \
//        DECLARE_ASN1_ENCODE_FUNCTIONS(type, itname, name)
//
//# define DECLARE_ASN1_ENCODE_FUNCTIONS(type, itname, name) \
//        type *d2i_##name(type **a, const unsigned char **in, long len); \
//        int i2d_##name(type *a, unsigned char **out); \
//        DECLARE_ASN1_ITEM(itname)
//
//# define DECLARE_ASN1_ENCODE_FUNCTIONS_const(type, name) \
//        type *d2i_##name(type **a, const unsigned char **in, long len); \
//        int i2d_##name(const type *a, unsigned char **out); \
//        DECLARE_ASN1_ITEM(name)
//
//# define DECLARE_ASN1_NDEF_FUNCTION(name) \
//        int i2d_##name##_NDEF(name *a, unsigned char **out);
//
//# define DECLARE_ASN1_FUNCTIONS_const(name) \
//        DECLARE_ASN1_ALLOC_FUNCTIONS(name) \
//        DECLARE_ASN1_ENCODE_FUNCTIONS_const(name, name)
//
//# define DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, name) \
//        type *name##_new(void); \
//        void name##_free(type *a);
//
//# define DECLARE_ASN1_PRINT_FUNCTION(stname) \
//        DECLARE_ASN1_PRINT_FUNCTION_fname(stname, stname)
//
//# define DECLARE_ASN1_PRINT_FUNCTION_fname(stname, fname) \
//        int fname##_print_ctx(BIO *out, stname *x, int indent, \
//                                         const ASN1_PCTX *pctx);
//
//# define D2I_OF(type) type *(*)(type **,const unsigned char **,long)
//# define I2D_OF(type) int (*)(type *,unsigned char **)
//# define I2D_OF_const(type) int (*)(const type *,unsigned char **)
//
//# define CHECKED_D2I_OF(type, d2i) \
//    ((d2i_of_void*) (1 ? d2i : ((D2I_OF(type))0)))
//# define CHECKED_I2D_OF(type, i2d) \
//    ((i2d_of_void*) (1 ? i2d : ((I2D_OF(type))0)))
//# define CHECKED_NEW_OF(type, xnew) \
//    ((void *(*)(void)) (1 ? xnew : ((type *(*)(void))0)))
//# define CHECKED_PTR_OF(type, p) \
//    ((void*) (1 ? p : (type*)0))
//# define CHECKED_PPTR_OF(type, p) \
//    ((void**) (1 ? p : (type**)0))
//
//# define TYPEDEF_D2I_OF(type) typedef type *d2i_of_##type(type **,const unsigned char **,long)
//# define TYPEDEF_I2D_OF(type) typedef int i2d_of_##type(type *,unsigned char **)
//# define TYPEDEF_D2I2D_OF(type) TYPEDEF_D2I_OF(type); TYPEDEF_I2D_OF(type)
//
//TYPEDEF_D2I2D_OF(void);

  (*-
   * The following macros and typedefs allow an ASN1_ITEM
   * to be embedded in a structure and referenced. Since
   * the ASN1_ITEM pointers need to be globally accessible
   * (possibly from shared libraries) they may exist in
   * different forms. On platforms that support it the
   * ASN1_ITEM structure itself will be globally exported.
   * Other platforms will export a function that returns
   * an ASN1_ITEM pointer.
   *
   * To handle both cases transparently the macros below
   * should be used instead of hard coding an ASN1_ITEM
   * pointer in a structure.
   *
   * The structure will look like this:
   *
   * typedef struct SOMETHING_st {
   *      ...
   *      ASN1_ITEM_EXP *iptr;
   *      ...
   * } SOMETHING;
   *
   * It would be initialised as e.g.:
   *
   * SOMETHING somevar = {...,ASN1_ITEM_ref(X509),...};
   *
   * and the actual pointer extracted with:
   *
   * const ASN1_ITEM *it = ASN1_ITEM_ptr(somevar.iptr);
   *
   * Finally an ASN1_ITEM pointer can be extracted from an
   * appropriate reference with: ASN1_ITEM_rptr(X509). This
   * would be used when a function takes an ASN1_ITEM * argument.
   *
   *)

// # ifndef OPENSSL_EXPORT_VAR_AS_FUNCTION

///(* ASN1_ITEM pointer exported type *)
//typedef const ASN1_ITEM ASN1_ITEM_EXP;
//
///(* Macro to obtain ASN1_ITEM pointer from exported type *)
//#  define ASN1_ITEM_ptr(iptr) (iptr)
//
// (* Macro to include ASN1_ITEM pointer from base type *)
//#  define ASN1_ITEM_ref(iptr) (&(iptr##_it))
//
//#  define ASN1_ITEM_rptr(ref) (&(ref##_it))
//
//#  define DECLARE_ASN1_ITEM(name) \
//        OPENSSL_EXTERN const ASN1_ITEM name##_it;
//
//# else

// (*
// * Platforms that can't easily handle shared global variables are declared as
// * functions returning ASN1_ITEM pointers.
// *)

///(* ASN1_ITEM pointer exported type *)
//typedef const ASN1_ITEM *ASN1_ITEM_EXP (void);
//
///(* Macro to obtain ASN1_ITEM pointer from exported type *)
//#  define ASN1_ITEM_ptr(iptr) (iptr())
//
///(* Macro to include ASN1_ITEM pointer from base type *)
//#  define ASN1_ITEM_ref(iptr) (iptr##_it)
//
//#  define ASN1_ITEM_rptr(ref) (ref##_it())
//
//#  define DECLARE_ASN1_ITEM(name) \
//        const ASN1_ITEM * name##_it(void);
//
//# endif

  {$EXTERNALSYM STACK_OF_ASN1_INTEGER}
  STACK_OF_ASN1_INTEGER = record end;
  {$EXTERNALSYM PSTACK_OF_ASN1_INTEGER}
  PSTACK_OF_ASN1_INTEGER = ^STACK_OF_ASN1_INTEGER;
  {$EXTERNALSYM STACK_OF_ASN1_GENERALSTRING}
  STACK_OF_ASN1_GENERALSTRING = record end;
  {$EXTERNALSYM PSTACK_OF_ASN1_GENERALSTRING}
  PSTACK_OF_ASN1_GENERALSTRING = ^STACK_OF_ASN1_GENERALSTRING;
  {$EXTERNALSYM STACK_OF_ASN1_UTF8STRING}
  STACK_OF_ASN1_UTF8STRING = record end;
  {$EXTERNALSYM PSTACK_OF_ASN1_UTF8STRING}
  PSTACK_OF_ASN1_UTF8STRING = ^STACK_OF_ASN1_UTF8STRING;
  {$EXTERNALSYM STACK_OF_ASN1_TYPE}
  STACK_OF_ASN1_TYPE = record end;
  {$EXTERNALSYM PSTACK_OF_ASN1_TYPE}
  PSTACK_OF_ASN1_TYPE = ^STACK_OF_ASN1_TYPE;
//
//typedef STACK_OF(ASN1_TYPE) ASN1_SEQUENCE_ANY;
//
//DECLARE_ASN1_ENCODE_FUNCTIONS_const(ASN1_SEQUENCE_ANY, ASN1_SEQUENCE_ANY)
//DECLARE_ASN1_ENCODE_FUNCTIONS_const(ASN1_SEQUENCE_ANY, ASN1_SET_ANY)

  (* This is used to contain a list of bit names *)

  {$EXTERNALSYM BIT_STRING_BITNAME_st}
  BIT_STRING_BITNAME_st = record
    bitnum: TIdC_INT;
    lname: PIdAnsiChar;
    sname: PIdAnsiChar;
  end;
  {$EXTERNALSYM BIT_STRING_BITNAME}
  BIT_STRING_BITNAME = BIT_STRING_BITNAME_st;
  {$EXTERNALSYM PBIT_STRING_BITNAME}
  PBIT_STRING_BITNAME = ^BIT_STRING_BITNAME;

//DECLARE_ASN1_FUNCTIONS(type) -->
//        type *name##_new(void); \
//        void name##_free(type *a);
//        type *d2i_##name(type **a, const unsigned char **in, long len); \
//        int i2d_##name(type *a, unsigned char **out); \
//#  define DECLARE_ASN1_ITEM(name) \
//        OPENSSL_EXTERN const ASN1_ITEM name##_it;

// DECLARE_ASN1_FUNCTIONS_fname(ASN1_TYPE, ASN1_ANY, ASN1_TYPE)
    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM ASN1_TYPE_get}
  ASN1_TYPE_get: function (const a: PASN1_TYPE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_TYPE_set}
  ASN1_TYPE_set: procedure (a: PASN1_TYPE; type_: TIdC_INT; value: Pointer); cdecl = nil;
  {$EXTERNALSYM ASN1_TYPE_set1}
  ASN1_TYPE_set1: function (a: PASN1_TYPE; type_: TIdC_INT; const value: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_TYPE_cmp}
  ASN1_TYPE_cmp: function (const a: PASN1_TYPE; const b: PASN1_TYPE): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM ASN1_TYPE_pack_sequence}
  ASN1_TYPE_pack_sequence: function (const it: PASN1_ITEM; s: Pointer; t: PPASN1_TYPE): PASN1_TYPE; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_TYPE_unpack_sequence}
  ASN1_TYPE_unpack_sequence: function (const it: PASN1_ITEM; const t: PASN1_TYPE): Pointer; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM ASN1_OBJECT_new}
  ASN1_OBJECT_new: function : PASN1_OBJECT; cdecl = nil;
  {$EXTERNALSYM ASN1_OBJECT_free}
  ASN1_OBJECT_free: procedure (a: PASN1_OBJECT); cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_OBJECT}
  i2d_ASN1_OBJECT: function (const a: PASN1_OBJECT; pp: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_ASN1_OBJECT}
  d2i_ASN1_OBJECT: function (a: PPASN1_OBJECT; const pp: PPByte; _length: TIdC_LONG): PASN1_OBJECT; cdecl = nil;

  {$EXTERNALSYM d2i_ASN1_BIT_STRING}
  d2i_ASN1_BIT_STRING : function(val_out : PPASN1_BIT_STRING; const der_in : PPIdAnsiChar; _length : TIdC_LONG) : PASN1_BIT_STRING cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_BIT_STRING}
  i2d_ASN1_BIT_STRING : function(val_in : PASN1_BIT_STRING; der_out : PPIdAnsiChar) : TIdC_long cdecl = nil;
  //DECLARE_ASN1_ITEM(ASN1_OBJECT)
  //
  //DEFINE_STACK_OF(ASN1_OBJECT)

  {$EXTERNALSYM ASN1_STRING_new}
  ASN1_STRING_new: function : PASN1_STRING; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_free}
  ASN1_STRING_free: procedure (a: PASN1_STRING); cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_clear_free}
  ASN1_STRING_clear_free: procedure (a: PASN1_STRING); cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_copy}
  ASN1_STRING_copy: function (dst: PASN1_STRING; const _str: PASN1_STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_dup}
  ASN1_STRING_dup: function (const a: PASN1_STRING): PASN1_STRING; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_type_new}
  ASN1_STRING_type_new: function (type_: TIdC_INT): PASN1_STRING; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_cmp}
  ASN1_STRING_cmp: function (const a: PASN1_STRING; const b: PASN1_STRING): TIdC_INT; cdecl = nil;

  (*
   * Since this is used to store all sorts of things, via macros, for now,
   * make its data void *
   *)
  {$EXTERNALSYM ASN1_STRING_set}
  ASN1_STRING_set: function (_str: PASN1_STRING; const data: Pointer; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_set0}
  ASN1_STRING_set0: procedure (_str: PASN1_STRING; data: Pointer; len: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_length}
  ASN1_STRING_length: function (const x: PASN1_STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_length_set}
  ASN1_STRING_length_set: procedure (x: PASN1_STRING; n: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_type}
  ASN1_STRING_type: function (const x: PASN1_STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_get0_data}
  ASN1_STRING_get0_data: function (const x: PASN1_STRING): PByte; cdecl = nil; {introduced 1.1.0}

  //DECLARE_ASN1_FUNCTIONS(ASN1_BIT_STRING)
  {$EXTERNALSYM ASN1_BIT_STRING_set}
  ASN1_BIT_STRING_set: function (a: PASN1_BIT_STRING; d: PByte; _length: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_BIT_STRING_set_bit}
  ASN1_BIT_STRING_set_bit: function (a: PASN1_BIT_STRING; n: TIdC_INT; value: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_BIT_STRING_get_bit}
  ASN1_BIT_STRING_get_bit: function (const a: PASN1_BIT_STRING; n: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_BIT_STRING_check}
  ASN1_BIT_STRING_check: function (const a: PASN1_BIT_STRING; const flags: PByte; flags_len: TIdC_INT): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM ASN1_BIT_STRING_name_print}
  ASN1_BIT_STRING_name_print: function (out_: PBIO; bs: PASN1_BIT_STRING; tbl: PBIT_STRING_BITNAME; indent: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_BIT_STRING_num_asc}
  ASN1_BIT_STRING_num_asc: function (const name: PIdAnsiChar; tbl: PBIT_STRING_BITNAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_BIT_STRING_set_asc}
  ASN1_BIT_STRING_set_asc: function (bs: PASN1_BIT_STRING; const name: PIdAnsiChar; value: TIdC_INT; tbl: PBIT_STRING_BITNAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_BIT_STRING_get_length}
  ASN1_BIT_STRING_get_length: function(abs_:  PASN1_BIT_STRING; _length : PIdC_SIZET; unused_bits : PIdC_INT) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_BIT_STRING_set1}
  ASN1_BIT_STRING_set1: function(abs_:  PASN1_BIT_STRING; data : PByte; _length : TIdC_SIZET; unused_bits : TIdC_INT) : TIdC_INT; cdecl = nil;

  {$EXTERNALSYM ASN1_INTEGER_new}
  ASN1_INTEGER_new: function : PASN1_INTEGER; cdecl = nil;
  {$EXTERNALSYM ASN1_INTEGER_free}
  ASN1_INTEGER_free: procedure (a: PASN1_INTEGER); cdecl = nil;
  {$EXTERNALSYM d2i_ASN1_INTEGER}
  d2i_ASN1_INTEGER: function (a: PPASN1_INTEGER; const in_: PPByte; len: TIdC_Long): PASN1_INTEGER; cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_INTEGER}
  i2d_ASN1_INTEGER: function (a: PASN1_INTEGER; out_: PPByte): TIdC_Int; cdecl = nil;

  {$EXTERNALSYM d2i_ASN1_UINTEGER}
  d2i_ASN1_UINTEGER: function (a: PPASN1_INTEGER; const pp: PPByte; _length: TIdC_LONG): PASN1_INTEGER; cdecl = nil;
  {$EXTERNALSYM ASN1_INTEGER_dup}
  ASN1_INTEGER_dup: function (const x: PASN1_INTEGER): PASN1_INTEGER; cdecl = nil;
  {$EXTERNALSYM ASN1_INTEGER_cmp}
  ASN1_INTEGER_cmp: function (const x: PASN1_INTEGER; const y: PASN1_INTEGER): TIdC_INT; cdecl = nil;

  // DECLARE_ASN1_FUNCTIONS(ASN1_ENUMERATED)

  {$EXTERNALSYM ASN1_UTCTIME_check}
  ASN1_UTCTIME_check: function (const a: PASN1_UTCTIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_UTCTIME_set}
  ASN1_UTCTIME_set: function (s: PASN1_UTCTIME; t: TIdC_TIMET): PASN1_UTCTIME; cdecl = nil;
  {$EXTERNALSYM ASN1_UTCTIME_adj}
  ASN1_UTCTIME_adj: function (s: PASN1_UTCTIME; t: TIdC_TIMET; offset_day: TIdC_INT; offset_sec: TIdC_LONG): PASN1_UTCTIME; cdecl = nil;
  {$EXTERNALSYM ASN1_UTCTIME_set_string}
  ASN1_UTCTIME_set_string: function (s: PASN1_UTCTIME; const _str: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_UTCTIME_cmp_time_t}
  ASN1_UTCTIME_cmp_time_t: function (const s: PASN1_UTCTIME; t: TIdC_TIMET): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM ASN1_GENERALIZEDTIME_check}
  ASN1_GENERALIZEDTIME_check: function (const a: PASN1_GENERALIZEDTIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_GENERALIZEDTIME_set}
  ASN1_GENERALIZEDTIME_set: function (s: PASN1_GENERALIZEDTIME; t: TIdC_TIMET): PASN1_GENERALIZEDTIME; cdecl = nil;
  {$EXTERNALSYM ASN1_GENERALIZEDTIME_adj}
  ASN1_GENERALIZEDTIME_adj: function (s: PASN1_GENERALIZEDTIME; t: TIdC_TIMET; offset_day: TIdC_INT; offset_sec: TIdC_LONG): PASN1_GENERALIZEDTIME; cdecl = nil;
  {$EXTERNALSYM ASN1_GENERALIZEDTIME_set_string}
  ASN1_GENERALIZEDTIME_set_string: function (s: pASN1_GENERALIZEDTIME; const _str: PIdAnsiChar): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM ASN1_TIME_diff}
  ASN1_TIME_diff: function (pday: PIdC_INT; psec: PIdC_INT; const from: PASN1_TIME; const to_: PASN1_TIME): TIdC_INT; cdecl = nil;

  // DECLARE_ASN1_FUNCTIONS(ASN1_OCTET_STRING)
  {$EXTERNALSYM ASN1_OCTET_STRING_dup}
  ASN1_OCTET_STRING_dup: function (const a: PASN1_OCTET_STRING): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM ASN1_OCTET_STRING_cmp}
  ASN1_OCTET_STRING_cmp: function (const a: PASN1_OCTET_STRING; const b: PASN1_OCTET_STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_OCTET_STRING_set}
  ASN1_OCTET_STRING_set: function (_str: PASN1_OCTET_STRING; const data: PByte; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_ASN1_OCTET_STRING}
  d2i_ASN1_OCTET_STRING : function(val_out : PPASN1_OCTET_STRING; der_in : PPIdAnsiChar; _length : TIdC_LONG) : PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_OCTET_STRING}
  i2d_ASN1_OCTET_STRING : function(val_in : PASN1_OCTET_STRING; der_out : PPIdAnsiChar) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_OCTET_STRING_free}
  ASN1_OCTET_STRING_free : procedure(a : PASN1_OCTET_STRING); cdecl = nil;
  //DECLARE_ASN1_FUNCTIONS(ASN1_VISIBLESTRING)
  //DECLARE_ASN1_FUNCTIONS(ASN1_UNIVERSALSTRING)
  //DECLARE_ASN1_FUNCTIONS(ASN1_UTF8STRING)
  //DECLARE_ASN1_FUNCTIONS(ASN1_NULL)
  //DECLARE_ASN1_FUNCTIONS(ASN1_BMPSTRING)

  {$EXTERNALSYM UTF8_getc}
  UTF8_getc: function (const _str: PByte; len: TIdC_INT; _val: PIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UTF8_putc}
  UTF8_putc: function (_str: PIdAnsiChar; len: TIdC_INT; value: TIdC_ULONG): TIdC_INT; cdecl = nil;

  //DECLARE_ASN1_FUNCTIONS_name(ASN1_STRING, ASN1_PRINTABLE)
  //
  //DECLARE_ASN1_FUNCTIONS_name(ASN1_STRING, DIRECTORYSTRING)
  //DECLARE_ASN1_FUNCTIONS_name(ASN1_STRING, DISPLAYTEXT)
  //DECLARE_ASN1_FUNCTIONS(ASN1_PRINTABLESTRING)
  //DECLARE_ASN1_FUNCTIONS(ASN1_T61STRING)
  //DECLARE_ASN1_FUNCTIONS(ASN1_IA5STRING)
  //DECLARE_ASN1_FUNCTIONS(ASN1_GENERALSTRING)

  {$EXTERNALSYM ASN1_UTCTIME_new}
  ASN1_UTCTIME_new: function : PASN1_UTCTIME; cdecl = nil;
  {$EXTERNALSYM ASN1_UTCTIME_free}
  ASN1_UTCTIME_free: procedure (a: PASN1_UTCTIME); cdecl = nil;
  {$EXTERNALSYM d2i_ASN1_UTCTIME}
  d2i_ASN1_UTCTIME: function (a: PPASN1_UTCTIME; const in_: PPByte; len: TIdC_LONG): PASN1_UTCTIME; cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_UTCTIME}
  i2d_ASN1_UTCTIME: function (a: PASN1_UTCTIME; out_: PPByte): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM ASN1_GENERALIZEDTIME_new}
  ASN1_GENERALIZEDTIME_new: function : PASN1_GENERALIZEDTIME; cdecl = nil;
  {$EXTERNALSYM ASN1_GENERALIZEDTIME_free}
  ASN1_GENERALIZEDTIME_free: procedure (a: PASN1_GENERALIZEDTIME); cdecl = nil;
  {$EXTERNALSYM d2i_ASN1_GENERALIZEDTIME}
  d2i_ASN1_GENERALIZEDTIME: function (a: PPASN1_GENERALIZEDTIME; const in_: PPByte; len: TIdC_LONG): PASN1_GENERALIZEDTIME; cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_GENERALIZEDTIME}
  i2d_ASN1_GENERALIZEDTIME: function (a: PASN1_GENERALIZEDTIME; out_: PPByte): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM ASN1_TIME_new}
  ASN1_TIME_new: function : PASN1_TIME; cdecl = nil;
  {$EXTERNALSYM ASN1_TIME_free}
  ASN1_TIME_free: procedure (a: PASN1_TIME); cdecl = nil;
  {$EXTERNALSYM d2i_ASN1_TIME}
  d2i_ASN1_TIME: function (a: PPASN1_TIME; const in_: PPByte; len: TIdC_LONG): PASN1_TIME; cdecl = nil;
  {$EXTERNALSYM i2d_ASN1_TIME}
  i2d_ASN1_TIME: function (a: PASN1_TIME; out_: PPByte): TIdC_INT; cdecl = nil;

  // DECLARE_ASN1_ITEM(ASN1_OCTET_STRING_NDEF)

  {$EXTERNALSYM ASN1_TIME_set}
  ASN1_TIME_set: function (s: PASN1_TIME; t: TIdC_TIMET): PASN1_TIME; cdecl = nil;
  {$EXTERNALSYM ASN1_TIME_adj}
  ASN1_TIME_adj: function (s: PASN1_TIME; t: TIdC_TIMET; offset_day: TIdC_INT; offset_sec: TIdC_LONG): PASN1_TIME; cdecl = nil;
  {$EXTERNALSYM ASN1_TIME_check}
  ASN1_TIME_check: function (const t: PASN1_TIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_TIME_to_generalizedtime}
  ASN1_TIME_to_generalizedtime: function (const t: PASN1_TIME; out_: PPASN1_GENERALIZEDTIME): PASN1_GENERALIZEDTIME; cdecl = nil;
  {$EXTERNALSYM ASN1_TIME_set_string}
  ASN1_TIME_set_string: function (s: PASN1_TIME; const _str: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_TIME_set_string_X509}
  ASN1_TIME_set_string_X509: function (s: PASN1_TIME; const _str: PIdAnsiChar): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_TIME_to_tm}
  ASN1_TIME_to_tm: function (const s: PASN1_TIME; tm: PIdC_TM): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_TIME_normalize}
  ASN1_TIME_normalize: function (s: PASN1_TIME): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_TIME_cmp_time_t}
  ASN1_TIME_cmp_time_t: function (const s: PASN1_TIME; t: TIdC_TIMET): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_TIME_compare}
  ASN1_TIME_compare: function (const a: PASN1_TIME; const b: PASN1_TIME): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM i2a_ASN1_INTEGER}
  i2a_ASN1_INTEGER: function (bp: PBIO; const a: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM a2i_ASN1_INTEGER}
  a2i_ASN1_INTEGER: function (bp: PBIO; bs: PASN1_INTEGER; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2a_ASN1_ENUMERATED}
  i2a_ASN1_ENUMERATED: function (bp: PBIO; const a: PASN1_ENUMERATED): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM a2i_ASN1_ENUMERATED}
  a2i_ASN1_ENUMERATED: function (bp: PBIO; bs: PASN1_ENUMERATED; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2a_ASN1_OBJECT}
  i2a_ASN1_OBJECT: function (bp: PBIO; const a: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM a2i_ASN1_STRING}
  a2i_ASN1_STRING: function (bp: PBIO; bs: PASN1_STRING; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2a_ASN1_STRING}
  i2a_ASN1_STRING: function (bp: PBIO; const a: PASN1_STRING; type_: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2t_ASN1_OBJECT}
  i2t_ASN1_OBJECT: function (buf: PIdAnsiChar; buf_len: TIdC_INT; const a: PASN1_OBJECT): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM a2d_ASN1_OBJECT}
  a2d_ASN1_OBJECT: function (out_: PByte; olen: TIdC_INT; const buf: PIdAnsiChar; num: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_OBJECT_create}
  ASN1_OBJECT_create: function (nid: TIdC_INT; data: PByte; len: TIdC_INT; const sn: PIdAnsiChar; const _ln: PIdAnsiChar): PASN1_OBJECT; cdecl = nil;

  {$EXTERNALSYM ASN1_INTEGER_get_int64}
  ASN1_INTEGER_get_int64: function (pr: PIdC_Int64; const a: PASN1_INTEGER): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_INTEGER_set_int64}
  ASN1_INTEGER_set_int64: function (a: PASN1_INTEGER; r: TIdC_Int64): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_INTEGER_get_uint64}
  ASN1_INTEGER_get_uint64: function (pr: PIdC_UInt64; const a: PASN1_INTEGER): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_INTEGER_set_uint64}
  ASN1_INTEGER_set_uint64: function (a: PASN1_INTEGER; r: TIdC_UInt64): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM ASN1_INTEGER_set}
  ASN1_INTEGER_set: function (a: PASN1_INTEGER; v: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_INTEGER_get}
  ASN1_INTEGER_get: function (const a: PASN1_INTEGER): TIdC_LONG; cdecl = nil;
  {$EXTERNALSYM BN_to_ASN1_INTEGER}
  BN_to_ASN1_INTEGER: function (const bn: PBIGNUM; ai: PASN1_INTEGER): PASN1_INTEGER; cdecl = nil;
  {$EXTERNALSYM ASN1_INTEGER_to_BN}
  ASN1_INTEGER_to_BN: function (const ai: PASN1_INTEGER; bn: PBIGNUM): PBIGNUM; cdecl = nil;

  {$EXTERNALSYM ASN1_ENUMERATED_get_int64}
  ASN1_ENUMERATED_get_int64: function (pr: PIdC_Int64; const a: PASN1_ENUMERATED): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_ENUMERATED_set_int64}
  ASN1_ENUMERATED_set_int64: function (a: PASN1_ENUMERATED; r: TIdC_Int64): TIdC_INT; cdecl = nil; {introduced 1.1.0}


  {$EXTERNALSYM ASN1_ENUMERATED_set}
  ASN1_ENUMERATED_set: function (a: PASN1_ENUMERATED; v: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_ENUMERATED_get}
  ASN1_ENUMERATED_get: function (const a: PASN1_ENUMERATED): TIdC_LONG; cdecl = nil;
  {$EXTERNALSYM BN_to_ASN1_ENUMERATED}
  BN_to_ASN1_ENUMERATED: function (const bn: PBIGNUM; ai: PASN1_ENUMERATED): PASN1_ENUMERATED; cdecl = nil;
  {$EXTERNALSYM ASN1_ENUMERATED_to_BN}
  ASN1_ENUMERATED_to_BN: function (const ai: PASN1_ENUMERATED; bn: PBIGNUM): PBIGNUM; cdecl = nil;

  (* General *)
  (* given a string, return the correct type, max is the maximum length *)
  {$EXTERNALSYM ASN1_PRINTABLE_type}
  ASN1_PRINTABLE_type: function (const s: PByte; max: TIdC_INT): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM ASN1_tag2bit}
  ASN1_tag2bit: function (tag: TIdC_INT): TIdC_ULONG; cdecl = nil;

  (* SPECIALS *)
  {$EXTERNALSYM ASN1_get_object}
  ASN1_get_object: function (const pp: PPByte; plength: PIdC_LONG; ptag: PIdC_INT; pclass: PIdC_INT; omax: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_check_infinite_end}
  ASN1_check_infinite_end: function (p: PPByte; len: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_const_check_infinite_end}
  ASN1_const_check_infinite_end: function (const p: PPByte; len: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_put_object}
  ASN1_put_object: procedure (pp: PPByte; constructed: TIdC_INT; _length: TIdC_INT; tag: TIdC_INT; xclass: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM ASN1_put_eoc}
  ASN1_put_eoc: function (pp: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_object_size}
  ASN1_object_size: function (constructed: TIdC_INT; _length: TIdC_INT; tag: TIdC_INT): TIdC_INT; cdecl = nil;

  (* Used to implement other functions *)
  //void *ASN1_dup(i2d_of_void *i2d, d2i_of_void *d2i, void *x);
  //
  //# define ASN1_dup_of(type,i2d,d2i,x) \
  //    ((type*)ASN1_dup(CHECKED_I2D_OF(type, i2d), \
  //                     CHECKED_D2I_OF(type, d2i), \
  //                     CHECKED_PTR_OF(type, x)))
  //
  //# define ASN1_dup_of_const(type,i2d,d2i,x) \
  //    ((type*)ASN1_dup(CHECKED_I2D_OF(const type, i2d), \
  //                     CHECKED_D2I_OF(type, d2i), \
  //                     CHECKED_PTR_OF(const type, x)))
  //
  {$EXTERNALSYM ASN1_item_dup}
  ASN1_item_dup: function (const it: PASN1_ITEM; x: Pointer): Pointer; cdecl = nil;

    (* ASN1 alloc/free macros for when a type is only used internally *)

  //# define M_ASN1_new_of(type) (type *)ASN1_item_new(ASN1_ITEM_rptr(type))
  //# define M_ASN1_free_of(x, type) \
  //                ASN1_item_free(CHECKED_PTR_OF(type, x), ASN1_ITEM_rptr(type))
  //
  //# ifndef OPENSSL_NO_STDIO
  //void *ASN1_d2i_fp(void *(*xnew) (void), d2i_of_void *d2i, FILE *in, void **x);

  //#  define ASN1_d2i_fp_of(type,xnew,d2i,in,x) \
  //    ((type*)ASN1_d2i_fp(CHECKED_NEW_OF(type, xnew), \
  //                        CHECKED_D2I_OF(type, d2i), \
  //                        in, \
  //                        CHECKED_PPTR_OF(type, x)))
  //
  //function ASN1_item_d2i_fp(const it: PASN1_ITEM; in_: PFILE; x: Pointer): Pointer;
  //function ASN1_i2d_fp(i2d: Pi2d_of_void; out_: PFILE; x: Pointer): TIdC_INT;
  //
  //#  define ASN1_i2d_fp_of(type,i2d,out,x) \
  //    (ASN1_i2d_fp(CHECKED_I2D_OF(type, i2d), \
  //                 out, \
  //                 CHECKED_PTR_OF(type, x)))
  //
  //#  define ASN1_i2d_fp_of_const(type,i2d,out,x) \
  //    (ASN1_i2d_fp(CHECKED_I2D_OF(const type, i2d), \
  //                 out, \
  //                 CHECKED_PTR_OF(const type, x)))
  //
  //function ASN1_item_i2d_fp(const it: PASN1_ITEM; out_: PFILE; x: Pointer): TIdC_INT;
  //function ASN1_STRING_print_ex_fp(&fp: PFILE; const _str: PASN1_STRING; flags: TIdC_ULONG): TIdC_INT;
  //# endif

  {$EXTERNALSYM ASN1_STRING_to_UTF8}
  ASN1_STRING_to_UTF8: function (out_: PPByte; const in_: PASN1_STRING): TIdC_INT; cdecl = nil;


  //#  define ASN1_d2i_bio_of(type,xnew,d2i,in,x) \
  //    ((type*)ASN1_d2i_bio( CHECKED_NEW_OF(type, xnew), \
  //                          CHECKED_D2I_OF(type, d2i), \
  //                          in, \
  //                          CHECKED_PPTR_OF(type, x)))

  {$EXTERNALSYM ASN1_d2i_bio}
  ASN1_d2i_bio: function(xnew: pxnew; d2i: pd2i_of_void; in_: PBIO; x: PPointer): Pointer; cdecl = nil;
  {$EXTERNALSYM ASN1_item_d2i_bio}
  ASN1_item_d2i_bio: function (const it: PASN1_ITEM; in_: PBIO; x: Pointer): Pointer; cdecl = nil;
  {$EXTERNALSYM ASN1_i2d_bio}
  ASN1_i2d_bio: function (i2d: i2d_of_void; out_: PBIO; x: PByte): TIdC_INT; cdecl = nil;

  //#  define ASN1_i2d_bio_of(type,i2d,out,x) \
  //    (ASN1_i2d_bio(CHECKED_I2D_OF(type, i2d), \
  //                  out, \
  //                  CHECKED_PTR_OF(type, x)))
  //
  //#  define ASN1_i2d_bio_of_const(type,i2d,out,x) \
  //    (ASN1_i2d_bio(CHECKED_I2D_OF(const type, i2d), \
  //                  out, \
  //                  CHECKED_PTR_OF(const type, x)))

  {$EXTERNALSYM ASN1_item_i2d_bio}
  ASN1_item_i2d_bio: function (const it: PASN1_ITEM; out_: PBIO; x: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_UTCTIME_print}
  ASN1_UTCTIME_print: function (fp: PBIO; const a: PASN1_UTCTIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_GENERALIZEDTIME_print}
  ASN1_GENERALIZEDTIME_print: function (fp: PBIO; const a: PASN1_GENERALIZEDTIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_TIME_print}
  ASN1_TIME_print: function (fp: PBIO; const a: PASN1_TIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_print}
  ASN1_STRING_print: function (bp: PBIO; const v: PASN1_STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_print_ex}
  ASN1_STRING_print_ex: function (out_: PBIO; const _str: PASN1_STRING; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_buf_print}
  ASN1_buf_print: function (bp: PBIO; const buf: PByte; buflen: TIdC_SIZET; off: TIdC_INT): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_bn_print}
  ASN1_bn_print: function (bp: PBIO; const number: PIdAnsiChar; const num: PBIGNUM; buf: PByte; off: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_parse}
  ASN1_parse: function (bp: PBIO; const pp: PByte; len: TIdC_LONG; indent: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_parse_dump}
  ASN1_parse_dump: function (bp: PPBIO; const pp: PByte; len: TIdC_LONG; indent: TIdC_INT; dump: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_tag2str}
  ASN1_tag2str: function (tag: TIdC_INT): PIdAnsiChar; cdecl = nil;

  (* Used to load and write Netscape format cert *)

  {$EXTERNALSYM ASN1_UNIVERSALSTRING_to_string}
  ASN1_UNIVERSALSTRING_to_string: function (s: PASN1_UNIVERSALSTRING): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM ASN1_TYPE_set_octetstring}
  ASN1_TYPE_set_octetstring: function (a: PASN1_TYPE; data: PByte; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_TYPE_get_octetstring}
  ASN1_TYPE_get_octetstring: function (const a: PASN1_TYPE; data: PByte; max_len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_TYPE_set_int_octetstring}
  ASN1_TYPE_set_int_octetstring: function (a: PASN1_TYPE; num: TIdC_LONG; data: PByte; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_TYPE_get_int_octetstring}
  ASN1_TYPE_get_int_octetstring: function (const a: PASN1_TYPE; num: PIdC_LONG; data: PByte; max_len: TIdC_INT): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM ASN1_item_unpack}
  ASN1_item_unpack: function (const oct: PASN1_STRING; const it: PASN1_ITEM): Pointer; cdecl = nil;

  {$EXTERNALSYM ASN1_item_pack}
  ASN1_item_pack: function (obj: Pointer; const it: PASN1_ITEM; oct: PPASN1_OCTET_STRING): PASN1_STRING; cdecl = nil;

  {$EXTERNALSYM ASN1_STRING_set_default_mask}
  ASN1_STRING_set_default_mask: procedure (mask: TIdC_ULONG); cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_set_default_mask_asc}
  ASN1_STRING_set_default_mask_asc: function (const p: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_get_default_mask}
  ASN1_STRING_get_default_mask: function : TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ASN1_mbstring_copy}
  ASN1_mbstring_copy: function (out_: PPASN1_STRING; const in_: PByte; len: TIdC_INT; inform: TIdC_INT; mask: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_mbstring_ncopy}
  ASN1_mbstring_ncopy: function (out_: PPASN1_STRING; const in_: PByte; len: TIdC_INT; inform: TIdC_INT; mask: TIdC_ULONG; minsize: TIdC_LONG; maxsize: TIdC_LONG): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM ASN1_STRING_set_by_NID}
  ASN1_STRING_set_by_NID: function (out_: PPASN1_STRING; const in_: PByte; inlen: TIdC_INT; inform: TIdC_INT; nid: TIdC_INT): PASN1_STRING; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_TABLE_get}
  ASN1_STRING_TABLE_get: function (nid: TIdC_INT): PASN1_STRING_TABLE; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_TABLE_add}
  ASN1_STRING_TABLE_add: function (v1: TIdC_INT; v2: TIdC_LONG; v3: TIdC_LONG; v4: TIdC_ULONG; v5: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_STRING_TABLE_cleanup}
  ASN1_STRING_TABLE_cleanup: procedure ; cdecl = nil;

  (* ASN1 template functions *)

  (* Old API compatible functions *)
  {$EXTERNALSYM ASN1_item_new}
  ASN1_item_new: function (const it: PASN1_ITEM): PASN1_VALUE; cdecl = nil;
  {$EXTERNALSYM ASN1_item_free}
  ASN1_item_free: procedure (_val: PASN1_VALUE; const it: PASN1_ITEM); cdecl = nil;
  {$EXTERNALSYM ASN1_item_d2i}
  ASN1_item_d2i: function (_val: PPASN1_VALUE; const in_: PPByte; len: TIdC_LONG; const it: PASN1_ITEM): PASN1_VALUE; cdecl = nil;
  {$EXTERNALSYM ASN1_item_i2d}
  ASN1_item_i2d: function (_val: PASN1_VALUE; out_: PPByte; const it: PASN1_ITEM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_item_ndef_i2d}
  ASN1_item_ndef_i2d: function (_val: PASN1_VALUE; out_: PPByte; const it: PASN1_ITEM): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM ASN1_add_oid_module}
  ASN1_add_oid_module: procedure ; cdecl = nil;
  {$EXTERNALSYM ASN1_add_stable_module}
  ASN1_add_stable_module: procedure ; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM ASN1_generate_nconf}
  ASN1_generate_nconf: function (const _str: PIdAnsiChar; nconf: PCONF): PASN1_TYPE; cdecl = nil;
  {$EXTERNALSYM ASN1_generate_v3}
  ASN1_generate_v3: function (const _str: PIdAnsiChar; cnf: PX509V3_CTX): PASN1_TYPE; cdecl = nil;
  {$EXTERNALSYM ASN1_str2mask}
  ASN1_str2mask: function (const _str: PByte; pmask: PIdC_ULONG): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM ASN1_item_print}
  ASN1_item_print: function (out_: PBIO; ifld: PASN1_VALUE; indent: TIdC_INT; const it: PASN1_ITEM; const pctx: PASN1_PCTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_PCTX_new}
  ASN1_PCTX_new: function : PASN1_PCTX; cdecl = nil;
  {$EXTERNALSYM ASN1_PCTX_free}
  ASN1_PCTX_free: procedure (p: PASN1_PCTX); cdecl = nil;
  {$EXTERNALSYM ASN1_PCTX_get_flags}
  ASN1_PCTX_get_flags: function (const p: PASN1_PCTX): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ASN1_PCTX_set_flags}
  ASN1_PCTX_set_flags: procedure (p: PASN1_PCTX; flags: TIdC_ULONG); cdecl = nil;
  {$EXTERNALSYM ASN1_PCTX_get_nm_flags}
  ASN1_PCTX_get_nm_flags: function (const p: PASN1_PCTX): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ASN1_PCTX_set_nm_flags}
  ASN1_PCTX_set_nm_flags: procedure (p: PASN1_PCTX; flags: TIdC_ULONG); cdecl = nil;
  {$EXTERNALSYM ASN1_PCTX_get_cert_flags}
  ASN1_PCTX_get_cert_flags: function (const p: PASN1_PCTX): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ASN1_PCTX_set_cert_flags}
  ASN1_PCTX_set_cert_flags: procedure (p: PASN1_PCTX; flags: TIdC_ULONG); cdecl = nil;
  {$EXTERNALSYM ASN1_PCTX_get_oid_flags}
  ASN1_PCTX_get_oid_flags: function (const p: PASN1_PCTX): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ASN1_PCTX_set_oid_flags}
  ASN1_PCTX_set_oid_flags: procedure (p: PASN1_PCTX; flags: TIdC_ULONG); cdecl = nil;
  {$EXTERNALSYM ASN1_PCTX_get_str_flags}
  ASN1_PCTX_get_str_flags: function (const p: PASN1_PCTX): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ASN1_PCTX_set_str_flags}
  ASN1_PCTX_set_str_flags: procedure (p: PASN1_PCTX; flags: TIdC_ULONG); cdecl = nil;

  //ASN1_SCTX *ASN1_SCTX_new(int (*scan_cb) (ASN1_SCTX *ctx));
  {$EXTERNALSYM ASN1_SCTX_free}
  ASN1_SCTX_free: procedure (p: PASN1_SCTX); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_SCTX_get_item}
  ASN1_SCTX_get_item: function (p: PASN1_SCTX): PASN1_ITEM; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_SCTX_get_template}
  ASN1_SCTX_get_template: function (p: PASN1_SCTX): PASN1_TEMPLATE; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_SCTX_get_flags}
  ASN1_SCTX_get_flags: function (p: PASN1_SCTX): TIdC_ULONG; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_SCTX_set_app_data}
  ASN1_SCTX_set_app_data: procedure (p: PASN1_SCTX; data: Pointer); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_SCTX_get_app_data}
  ASN1_SCTX_get_app_data: function (p: PASN1_SCTX): Pointer; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM BIO_f_asn1}
  BIO_f_asn1: function : PBIO_METHOD; cdecl = nil;

  {$EXTERNALSYM BIO_new_NDEF}
  BIO_new_NDEF: function (out_: PBIO; _val: PASN1_VALUE; const it: PASN1_ITEM): PBIO; cdecl = nil;

  {$EXTERNALSYM i2d_ASN1_bio_stream}
  i2d_ASN1_bio_stream: function (out_: PBIO; _val: PASN1_VALUE; in_: PBIO; flags: TIdC_INT; const it: PASN1_ITEM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_bio_ASN1_stream}
  PEM_write_bio_ASN1_stream: function (out_: PBIO; _val: PASN1_VALUE; in_: PBIO; flags: TIdC_INT; const hdr: PIdAnsiChar; const it: PASN1_ITEM): TIdC_INT; cdecl = nil;
  //function SMIME_write_ASN1(bio: PBIO; _val: PASN1_VALUE; data: PBIO; flags: TIdC_INT;
  //                     ctype_nid: TIdC_INT; econt_nid: TIdC_INT;
  //                     STACK_OF(X509_ALGOR) *mdalgs, const ASN1_ITEM *it): TIdC_INT;
  {$EXTERNALSYM SMIME_read_ASN1}
  SMIME_read_ASN1: function (bio: PBIO; bcont: PPBIO; const it: PASN1_ITEM): PASN1_VALUE; cdecl = nil;
  {$EXTERNALSYM SMIME_crlf_copy}
  SMIME_crlf_copy: function (in_: PBIO; out_: PBIO; flags: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SMIME_text}
  SMIME_text: function (in_: PBIO; out_: PBIO): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM ASN1_ITEM_lookup}
  ASN1_ITEM_lookup: function (const name: PIdAnsiChar): PASN1_ITEM; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_ITEM_get}
  ASN1_ITEM_get: function (i: TIdC_SIZET): PASN1_ITEM; cdecl = nil; {introduced 1.1.0}

{$ELSE}
  {$EXTERNALSYM ASN1_TYPE_get}
  function ASN1_TYPE_get(const a: PASN1_TYPE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_TYPE_set}
  procedure ASN1_TYPE_set(a: PASN1_TYPE; type_: TIdC_INT; value: Pointer) cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_TYPE_set1}
  function ASN1_TYPE_set1(a: PASN1_TYPE; type_: TIdC_INT; const value: Pointer): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_TYPE_cmp}
  function ASN1_TYPE_cmp(const a: PASN1_TYPE; const b: PASN1_TYPE): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM ASN1_TYPE_pack_sequence}
  function ASN1_TYPE_pack_sequence(const it: PASN1_ITEM; s: Pointer; t: PPASN1_TYPE): PASN1_TYPE cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_TYPE_unpack_sequence}
  function ASN1_TYPE_unpack_sequence(const it: PASN1_ITEM; const t: PASN1_TYPE): Pointer cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM ASN1_OBJECT_new}
  function ASN1_OBJECT_new: PASN1_OBJECT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_OBJECT_free}
  procedure ASN1_OBJECT_free(a: PASN1_OBJECT) cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_ASN1_OBJECT}
  function i2d_ASN1_OBJECT(const a: PASN1_OBJECT; pp: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_ASN1_OBJECT}
  function d2i_ASN1_OBJECT(a: PPASN1_OBJECT; const pp: PPByte; _length: TIdC_LONG): PASN1_OBJECT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_ASN1_BIT_STRING}
  function d2i_ASN1_BIT_STRING(val_out : PPASN1_BIT_STRING; const der_in : PPIdAnsiChar; _length : TIdC_LONG) : PASN1_BIT_STRING cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_ASN1_BIT_STRING}
  function i2d_ASN1_BIT_STRING(val_in : PASN1_BIT_STRING; der_out : PPIdAnsiChar) : TIdC_long cdecl; external CLibCrypto;

  //DECLARE_ASN1_ITEM(ASN1_OBJECT)
  //
  //DEFINE_STACK_OF(ASN1_OBJECT)

  {$EXTERNALSYM ASN1_STRING_new}
  function ASN1_STRING_new: PASN1_STRING cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_STRING_free}
  procedure ASN1_STRING_free(a: PASN1_STRING) cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_STRING_clear_free}
  procedure ASN1_STRING_clear_free(a: PASN1_STRING) cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_STRING_copy}
  function ASN1_STRING_copy(dst: PASN1_STRING; const _str: PASN1_STRING): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_STRING_dup}
  function ASN1_STRING_dup(const a: PASN1_STRING): PASN1_STRING cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_STRING_type_new}
  function ASN1_STRING_type_new(type_: TIdC_INT): PASN1_STRING cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_STRING_cmp}
  function ASN1_STRING_cmp(const a: PASN1_STRING; const b: PASN1_STRING): TIdC_INT cdecl; external CLibCrypto;

  (*
   * Since this is used to store all sorts of things, via macros, for now,
   * make its data void *
   *)
  {$EXTERNALSYM ASN1_STRING_set}
  function ASN1_STRING_set(_str: PASN1_STRING; const data: Pointer; len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_STRING_set0}
  procedure ASN1_STRING_set0(_str: PASN1_STRING; data: Pointer; len: TIdC_INT) cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_STRING_length}
  function ASN1_STRING_length(const x: PASN1_STRING): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_STRING_length_set}
  procedure ASN1_STRING_length_set(x: PASN1_STRING; n: TIdC_INT) cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_STRING_type}
  function ASN1_STRING_type(const x: PASN1_STRING): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_STRING_get0_data}
  function ASN1_STRING_get0_data(const x: PASN1_STRING): PByte cdecl; external CLibCrypto; {introduced 1.1.0}

  //DECLARE_ASN1_FUNCTIONS(ASN1_BIT_STRING)
  {$EXTERNALSYM ASN1_BIT_STRING_set}
  function ASN1_BIT_STRING_set(a: PASN1_BIT_STRING; d: PByte; _length: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_BIT_STRING_set_bit}
  function ASN1_BIT_STRING_set_bit(a: PASN1_BIT_STRING; n: TIdC_INT; value: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_BIT_STRING_get_bit}
  function ASN1_BIT_STRING_get_bit(const a: PASN1_BIT_STRING; n: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_BIT_STRING_check}
  function ASN1_BIT_STRING_check(const a: PASN1_BIT_STRING; const flags: PByte; flags_len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM ASN1_BIT_STRING_name_print}
  function ASN1_BIT_STRING_name_print(out_: PBIO; bs: PASN1_BIT_STRING; tbl: PBIT_STRING_BITNAME; indent: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_BIT_STRING_num_asc}
  function ASN1_BIT_STRING_num_asc(const name: PIdAnsiChar; tbl: PBIT_STRING_BITNAME): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_BIT_STRING_set_asc}
  function ASN1_BIT_STRING_set_asc(bs: PASN1_BIT_STRING; const name: PIdAnsiChar; value: TIdC_INT; tbl: PBIT_STRING_BITNAME): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_BIT_STRING_get_length}
  function ASN1_BIT_STRING_get_length(abs_:  PASN1_BIT_STRING; _length : PIdC_SIZET; unused_bits : PIdC_INT) : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_BIT_STRING_set1}
  function ASN1_BIT_STRING_set1(abs_:  PASN1_BIT_STRING; data : PByte; _length : TIdC_SIZET; unused_bits : TIdC_INT) : TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM ASN1_INTEGER_new}
  function ASN1_INTEGER_new: PASN1_INTEGER cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_INTEGER_free}
  procedure ASN1_INTEGER_free(a: PASN1_INTEGER) cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_ASN1_INTEGER}
  function d2i_ASN1_INTEGER(a: PPASN1_INTEGER; const in_: PPByte; len: TIdC_Long): PASN1_INTEGER cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_ASN1_INTEGER}
  function i2d_ASN1_INTEGER(a: PASN1_INTEGER; out_: PPByte): TIdC_Int cdecl; external CLibCrypto;

  {$EXTERNALSYM d2i_ASN1_UINTEGER}
  function d2i_ASN1_UINTEGER(a: PPASN1_INTEGER; const pp: PPByte; _length: TIdC_LONG): PASN1_INTEGER cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_INTEGER_dup}
  function ASN1_INTEGER_dup(const x: PASN1_INTEGER): PASN1_INTEGER cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_INTEGER_cmp}
  function ASN1_INTEGER_cmp(const x: PASN1_INTEGER; const y: PASN1_INTEGER): TIdC_INT cdecl; external CLibCrypto;

  // DECLARE_ASN1_FUNCTIONS(ASN1_ENUMERATED)

  {$EXTERNALSYM ASN1_UTCTIME_check}
  function ASN1_UTCTIME_check(const a: PASN1_UTCTIME): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_UTCTIME_set}
  function ASN1_UTCTIME_set(s: PASN1_UTCTIME; t: TIdC_TIMET): PASN1_UTCTIME cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_UTCTIME_adj}
  function ASN1_UTCTIME_adj(s: PASN1_UTCTIME; t: TIdC_TIMET; offset_day: TIdC_INT; offset_sec: TIdC_LONG): PASN1_UTCTIME cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_UTCTIME_set_string}
  function ASN1_UTCTIME_set_string(s: PASN1_UTCTIME; const _str: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_UTCTIME_cmp_time_t}
  function ASN1_UTCTIME_cmp_time_t(const s: PASN1_UTCTIME; t: TIdC_TIMET): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM ASN1_GENERALIZEDTIME_check}
  function ASN1_GENERALIZEDTIME_check(const a: PASN1_GENERALIZEDTIME): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_GENERALIZEDTIME_set}
  function ASN1_GENERALIZEDTIME_set(s: PASN1_GENERALIZEDTIME; t: TIdC_TIMET): PASN1_GENERALIZEDTIME cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_GENERALIZEDTIME_adj}
  function ASN1_GENERALIZEDTIME_adj(s: PASN1_GENERALIZEDTIME; t: TIdC_TIMET; offset_day: TIdC_INT; offset_sec: TIdC_LONG): PASN1_GENERALIZEDTIME cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_GENERALIZEDTIME_set_string}
  function ASN1_GENERALIZEDTIME_set_string(s: pASN1_GENERALIZEDTIME; const _str: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM ASN1_TIME_diff}
  function ASN1_TIME_diff(pday: PIdC_INT; psec: PIdC_INT; const from: PASN1_TIME; const to_: PASN1_TIME): TIdC_INT cdecl; external CLibCrypto;

  // DECLARE_ASN1_FUNCTIONS(ASN1_OCTET_STRING)
  {$EXTERNALSYM ASN1_OCTET_STRING_dup}
  function ASN1_OCTET_STRING_dup(const a: PASN1_OCTET_STRING): PASN1_OCTET_STRING cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_OCTET_STRING_cmp}
  function ASN1_OCTET_STRING_cmp(const a: PASN1_OCTET_STRING; const b: PASN1_OCTET_STRING): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_OCTET_STRING_set}
  function ASN1_OCTET_STRING_set(_str: PASN1_OCTET_STRING; const data: PByte; len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_ASN1_OCTET_STRING}
  function d2i_ASN1_OCTET_STRING(val_out : PPASN1_OCTET_STRING; der_in : PPIdAnsiChar; _length : TIdC_LONG) : PASN1_OCTET_STRING; cdecl;  external CLibCrypto;
  {$EXTERNALSYM i2d_ASN1_OCTET_STRING}
  function i2d_ASN1_OCTET_STRING(val_in : PASN1_OCTET_STRING; der_out : PPIdAnsiChar) : TIdC_INT; cdecl;  external CLibCrypto;
  {$EXTERNALSYM ASN1_OCTET_STRING_free}
  procedure ASN1_OCTET_STRING_free(a : PASN1_OCTET_STRING); cdecl;  external CLibCrypto;

  //DECLARE_ASN1_FUNCTIONS(ASN1_VISIBLESTRING)
  //DECLARE_ASN1_FUNCTIONS(ASN1_UNIVERSALSTRING)
  //DECLARE_ASN1_FUNCTIONS(ASN1_UTF8STRING)
  //DECLARE_ASN1_FUNCTIONS(ASN1_NULL)
  //DECLARE_ASN1_FUNCTIONS(ASN1_BMPSTRING)

  {$EXTERNALSYM UTF8_getc}
  function UTF8_getc(const _str: PByte; len: TIdC_INT; _val: PIdC_ULONG): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM UTF8_putc}
  function UTF8_putc(_str: PIdAnsiChar; len: TIdC_INT; value: TIdC_ULONG): TIdC_INT cdecl; external CLibCrypto;

  //DECLARE_ASN1_FUNCTIONS_name(ASN1_STRING, ASN1_PRINTABLE)
  //
  //DECLARE_ASN1_FUNCTIONS_name(ASN1_STRING, DIRECTORYSTRING)
  //DECLARE_ASN1_FUNCTIONS_name(ASN1_STRING, DISPLAYTEXT)
  //DECLARE_ASN1_FUNCTIONS(ASN1_PRINTABLESTRING)
  //DECLARE_ASN1_FUNCTIONS(ASN1_T61STRING)
  //DECLARE_ASN1_FUNCTIONS(ASN1_IA5STRING)
  //DECLARE_ASN1_FUNCTIONS(ASN1_GENERALSTRING)

  {$EXTERNALSYM ASN1_UTCTIME_new}
  function ASN1_UTCTIME_new: PASN1_UTCTIME cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_UTCTIME_free}
  procedure ASN1_UTCTIME_free(a: PASN1_UTCTIME) cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_ASN1_UTCTIME}
  function d2i_ASN1_UTCTIME(a: PPASN1_UTCTIME; const in_: PPByte; len: TIdC_LONG): PASN1_UTCTIME cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_ASN1_UTCTIME}
  function i2d_ASN1_UTCTIME(a: PASN1_UTCTIME; out_: PPByte): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM ASN1_GENERALIZEDTIME_new}
  function ASN1_GENERALIZEDTIME_new: PASN1_GENERALIZEDTIME cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_GENERALIZEDTIME_free}
  procedure ASN1_GENERALIZEDTIME_free(a: PASN1_GENERALIZEDTIME) cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_ASN1_GENERALIZEDTIME}
  function d2i_ASN1_GENERALIZEDTIME(a: PPASN1_GENERALIZEDTIME; const in_: PPByte; len: TIdC_LONG): PASN1_GENERALIZEDTIME cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_ASN1_GENERALIZEDTIME}
  function i2d_ASN1_GENERALIZEDTIME(a: PASN1_GENERALIZEDTIME; out_: PPByte): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM ASN1_TIME_new}
  function ASN1_TIME_new: PASN1_TIME cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_TIME_free}
  procedure ASN1_TIME_free(a: PASN1_TIME) cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_ASN1_TIME}
  function d2i_ASN1_TIME(a: PPASN1_TIME; const in_: PPByte; len: TIdC_LONG): PASN1_TIME cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_ASN1_TIME}
  function i2d_ASN1_TIME(a: PASN1_TIME; out_: PPByte): TIdC_INT cdecl; external CLibCrypto;

  // DECLARE_ASN1_ITEM(ASN1_OCTET_STRING_NDEF)

  {$EXTERNALSYM ASN1_TIME_set}
  function ASN1_TIME_set(s: PASN1_TIME; t: TIdC_TIMET): PASN1_TIME cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_TIME_adj}
  function ASN1_TIME_adj(s: PASN1_TIME; t: TIdC_TIMET; offset_day: TIdC_INT; offset_sec: TIdC_LONG): PASN1_TIME cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_TIME_check}
  function ASN1_TIME_check(const t: PASN1_TIME): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_TIME_to_generalizedtime}
  function ASN1_TIME_to_generalizedtime(const t: PASN1_TIME; out_: PPASN1_GENERALIZEDTIME): PASN1_GENERALIZEDTIME cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_TIME_set_string}
  function ASN1_TIME_set_string(s: PASN1_TIME; const _str: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_TIME_set_string_X509}
  function ASN1_TIME_set_string_X509(s: PASN1_TIME; const _str: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_TIME_to_tm}
  function ASN1_TIME_to_tm(const s: PASN1_TIME; tm: PIdC_TM): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_TIME_normalize}
  function ASN1_TIME_normalize(s: PASN1_TIME): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_TIME_cmp_time_t}
  function ASN1_TIME_cmp_time_t(const s: PASN1_TIME; t: TIdC_TIMET): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_TIME_compare}
  function ASN1_TIME_compare(const a: PASN1_TIME; const b: PASN1_TIME): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM i2a_ASN1_INTEGER}
  function i2a_ASN1_INTEGER(bp: PBIO; const a: PASN1_INTEGER): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM a2i_ASN1_INTEGER}
  function a2i_ASN1_INTEGER(bp: PBIO; bs: PASN1_INTEGER; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM i2a_ASN1_ENUMERATED}
  function i2a_ASN1_ENUMERATED(bp: PBIO; const a: PASN1_ENUMERATED): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM a2i_ASN1_ENUMERATED}
  function a2i_ASN1_ENUMERATED(bp: PBIO; bs: PASN1_ENUMERATED; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM i2a_ASN1_OBJECT}
  function i2a_ASN1_OBJECT(bp: PBIO; const a: PASN1_OBJECT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM a2i_ASN1_STRING}
  function a2i_ASN1_STRING(bp: PBIO; bs: PASN1_STRING; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM i2a_ASN1_STRING}
  function i2a_ASN1_STRING(bp: PBIO; const a: PASN1_STRING; type_: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM i2t_ASN1_OBJECT}
  function i2t_ASN1_OBJECT(buf: PIdAnsiChar; buf_len: TIdC_INT; const a: PASN1_OBJECT): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM a2d_ASN1_OBJECT}
  function a2d_ASN1_OBJECT(out_: PByte; olen: TIdC_INT; const buf: PIdAnsiChar; num: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_OBJECT_create}
  function ASN1_OBJECT_create(nid: TIdC_INT; data: PByte; len: TIdC_INT; const sn: PIdAnsiChar; const _ln: PIdAnsiChar): PASN1_OBJECT cdecl; external CLibCrypto;

  {$EXTERNALSYM ASN1_INTEGER_get_int64}
  function ASN1_INTEGER_get_int64(pr: PIdC_Int64; const a: PASN1_INTEGER): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_INTEGER_set_int64}
  function ASN1_INTEGER_set_int64(a: PASN1_INTEGER; r: TIdC_Int64): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_INTEGER_get_uint64}
  function ASN1_INTEGER_get_uint64(pr: PIdC_UInt64; const a: PASN1_INTEGER): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_INTEGER_set_uint64}
  function ASN1_INTEGER_set_uint64(a: PASN1_INTEGER; r: TIdC_UInt64): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM ASN1_INTEGER_set}
  function ASN1_INTEGER_set(a: PASN1_INTEGER; v: TIdC_LONG): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_INTEGER_get}
  function ASN1_INTEGER_get(const a: PASN1_INTEGER): TIdC_LONG cdecl; external CLibCrypto;
  {$EXTERNALSYM BN_to_ASN1_INTEGER}
  function BN_to_ASN1_INTEGER(const bn: PBIGNUM; ai: PASN1_INTEGER): PASN1_INTEGER cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_INTEGER_to_BN}
  function ASN1_INTEGER_to_BN(const ai: PASN1_INTEGER; bn: PBIGNUM): PBIGNUM cdecl; external CLibCrypto;

  {$EXTERNALSYM ASN1_ENUMERATED_get_int64}
  function ASN1_ENUMERATED_get_int64(pr: PIdC_Int64; const a: PASN1_ENUMERATED): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_ENUMERATED_set_int64}
  function ASN1_ENUMERATED_set_int64(a: PASN1_ENUMERATED; r: TIdC_Int64): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}


  {$EXTERNALSYM ASN1_ENUMERATED_set}
  function ASN1_ENUMERATED_set(a: PASN1_ENUMERATED; v: TIdC_LONG): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_ENUMERATED_get}
  function ASN1_ENUMERATED_get(const a: PASN1_ENUMERATED): TIdC_LONG cdecl; external CLibCrypto;
  {$EXTERNALSYM BN_to_ASN1_ENUMERATED}
  function BN_to_ASN1_ENUMERATED(const bn: PBIGNUM; ai: PASN1_ENUMERATED): PASN1_ENUMERATED cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_ENUMERATED_to_BN}
  function ASN1_ENUMERATED_to_BN(const ai: PASN1_ENUMERATED; bn: PBIGNUM): PBIGNUM cdecl; external CLibCrypto;

  (* General *)
  (* given a string, return the correct type, max is the maximum length *)
  {$EXTERNALSYM ASN1_PRINTABLE_type}
  function ASN1_PRINTABLE_type(const s: PByte; max: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM ASN1_tag2bit}
  function ASN1_tag2bit(tag: TIdC_INT): TIdC_ULONG cdecl; external CLibCrypto;

  (* SPECIALS *)
  {$EXTERNALSYM ASN1_get_object}
  function ASN1_get_object(const pp: PPByte; plength: PIdC_LONG; ptag: PIdC_INT; pclass: PIdC_INT; omax: TIdC_LONG): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_check_infinite_end}
  function ASN1_check_infinite_end(p: PPByte; len: TIdC_LONG): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_const_check_infinite_end}
  function ASN1_const_check_infinite_end(const p: PPByte; len: TIdC_LONG): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_put_object}
  procedure ASN1_put_object(pp: PPByte; constructed: TIdC_INT; _length: TIdC_INT; tag: TIdC_INT; xclass: TIdC_INT) cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_put_eoc}
  function ASN1_put_eoc(pp: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_object_size}
  function ASN1_object_size(constructed: TIdC_INT; _length: TIdC_INT; tag: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  (* Used to implement other functions *)
  //void *ASN1_dup(i2d_of_void *i2d, d2i_of_void *d2i, void *x);
  //
  //# define ASN1_dup_of(type,i2d,d2i,x) \
  //    ((type*)ASN1_dup(CHECKED_I2D_OF(type, i2d), \
  //                     CHECKED_D2I_OF(type, d2i), \
  //                     CHECKED_PTR_OF(type, x)))
  //
  //# define ASN1_dup_of_const(type,i2d,d2i,x) \
  //    ((type*)ASN1_dup(CHECKED_I2D_OF(const type, i2d), \
  //                     CHECKED_D2I_OF(type, d2i), \
  //                     CHECKED_PTR_OF(const type, x)))
  //
  {$EXTERNALSYM ASN1_item_dup}
  function ASN1_item_dup(const it: PASN1_ITEM; x: Pointer): Pointer cdecl; external CLibCrypto;

    (* ASN1 alloc/free macros for when a type is only used internally *)

  //# define M_ASN1_new_of(type) (type *)ASN1_item_new(ASN1_ITEM_rptr(type))
  //# define M_ASN1_free_of(x, type) \
  //                ASN1_item_free(CHECKED_PTR_OF(type, x), ASN1_ITEM_rptr(type))
  //
  //# ifndef OPENSSL_NO_STDIO
  //void *ASN1_d2i_fp(void *(*xnew) (void), d2i_of_void *d2i, FILE *in, void **x);

  //#  define ASN1_d2i_fp_of(type,xnew,d2i,in,x) \
  //    ((type*)ASN1_d2i_fp(CHECKED_NEW_OF(type, xnew), \
  //                        CHECKED_D2I_OF(type, d2i), \
  //                        in, \
  //                        CHECKED_PPTR_OF(type, x)))
  //
  //function ASN1_item_d2i_fp(const it: PASN1_ITEM; in_: PFILE; x: Pointer): Pointer;
  //function ASN1_i2d_fp(i2d: Pi2d_of_void; out_: PFILE; x: Pointer): TIdC_INT;
  //
  //#  define ASN1_i2d_fp_of(type,i2d,out,x) \
  //    (ASN1_i2d_fp(CHECKED_I2D_OF(type, i2d), \
  //                 out, \
  //                 CHECKED_PTR_OF(type, x)))
  //
  //#  define ASN1_i2d_fp_of_const(type,i2d,out,x) \
  //    (ASN1_i2d_fp(CHECKED_I2D_OF(const type, i2d), \
  //                 out, \
  //                 CHECKED_PTR_OF(const type, x)))
  //
  //function ASN1_item_i2d_fp(const it: PASN1_ITEM; out_: PFILE; x: Pointer): TIdC_INT;
  //function ASN1_STRING_print_ex_fp(&fp: PFILE; const _str: PASN1_STRING; flags: TIdC_ULONG): TIdC_INT;
  //# endif

  {$EXTERNALSYM ASN1_STRING_to_UTF8}
  function ASN1_STRING_to_UTF8(out_: PPByte; const in_: PASN1_STRING): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_d2i_bio}
  function ASN1_d2i_bio(xnew: pxnew; d2i: pd2i_of_void; in_: PBIO; x: PPointer): Pointer cdecl; external CLibCrypto;

  //#  define ASN1_d2i_bio_of(type,xnew,d2i,in,x) \
  //    ((type*)ASN1_d2i_bio( CHECKED_NEW_OF(type, xnew), \
  //                          CHECKED_D2I_OF(type, d2i), \
  //                          in, \
  //                          CHECKED_PPTR_OF(type, x)))

  {$EXTERNALSYM ASN1_item_d2i_bio}
  function ASN1_item_d2i_bio(const it: PASN1_ITEM; in_: PBIO; x: Pointer): Pointer cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_i2d_bio}
  function ASN1_i2d_bio(i2d: i2d_of_void; out_: PBIO; x: PByte): TIdC_INT cdecl; external CLibCrypto;

  //#  define ASN1_i2d_bio_of(type,i2d,out,x) \
  //    (ASN1_i2d_bio(CHECKED_I2D_OF(type, i2d), \
  //                  out, \
  //                  CHECKED_PTR_OF(type, x)))
  //
  //#  define ASN1_i2d_bio_of_const(type,i2d,out,x) \
  //    (ASN1_i2d_bio(CHECKED_I2D_OF(const type, i2d), \
  //                  out, \
  //                  CHECKED_PTR_OF(const type, x)))

  {$EXTERNALSYM ASN1_item_i2d_bio}
  function ASN1_item_i2d_bio(const it: PASN1_ITEM; out_: PBIO; x: Pointer): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_UTCTIME_print}
  function ASN1_UTCTIME_print(fp: PBIO; const a: PASN1_UTCTIME): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_GENERALIZEDTIME_print}
  function ASN1_GENERALIZEDTIME_print(fp: PBIO; const a: PASN1_GENERALIZEDTIME): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_TIME_print}
  function ASN1_TIME_print(fp: PBIO; const a: PASN1_TIME): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_STRING_print}
  function ASN1_STRING_print(bp: PBIO; const v: PASN1_STRING): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_STRING_print_ex}
  function ASN1_STRING_print_ex(out_: PBIO; const _str: PASN1_STRING; flags: TIdC_ULONG): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_buf_print}
  function ASN1_buf_print(bp: PBIO; const buf: PByte; buflen: TIdC_SIZET; off: TIdC_INT): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_bn_print}
  function ASN1_bn_print(bp: PBIO; const number: PIdAnsiChar; const num: PBIGNUM; buf: PByte; off: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_parse}
  function ASN1_parse(bp: PBIO; const pp: PByte; len: TIdC_LONG; indent: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_parse_dump}
  function ASN1_parse_dump(bp: PPBIO; const pp: PByte; len: TIdC_LONG; indent: TIdC_INT; dump: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_tag2str}
  function ASN1_tag2str(tag: TIdC_INT): PIdAnsiChar cdecl; external CLibCrypto;

  (* Used to load and write Netscape format cert *)

  {$EXTERNALSYM ASN1_UNIVERSALSTRING_to_string}
  function ASN1_UNIVERSALSTRING_to_string(s: PASN1_UNIVERSALSTRING): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM ASN1_TYPE_set_octetstring}
  function ASN1_TYPE_set_octetstring(a: PASN1_TYPE; data: PByte; len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_TYPE_get_octetstring}
  function ASN1_TYPE_get_octetstring(const a: PASN1_TYPE; data: PByte; max_len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_TYPE_set_int_octetstring}
  function ASN1_TYPE_set_int_octetstring(a: PASN1_TYPE; num: TIdC_LONG; data: PByte; len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_TYPE_get_int_octetstring}
  function ASN1_TYPE_get_int_octetstring(const a: PASN1_TYPE; num: PIdC_LONG; data: PByte; max_len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM ASN1_item_unpack}
  function ASN1_item_unpack(const oct: PASN1_STRING; const it: PASN1_ITEM): Pointer cdecl; external CLibCrypto;

  {$EXTERNALSYM ASN1_item_pack}
  function ASN1_item_pack(obj: Pointer; const it: PASN1_ITEM; oct: PPASN1_OCTET_STRING): PASN1_STRING cdecl; external CLibCrypto;

  {$EXTERNALSYM ASN1_STRING_set_default_mask}
  procedure ASN1_STRING_set_default_mask(mask: TIdC_ULONG) cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_STRING_set_default_mask_asc}
  function ASN1_STRING_set_default_mask_asc(const p: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_STRING_get_default_mask}
  function ASN1_STRING_get_default_mask: TIdC_ULONG cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_mbstring_copy}
  function ASN1_mbstring_copy(out_: PPASN1_STRING; const in_: PByte; len: TIdC_INT; inform: TIdC_INT; mask: TIdC_ULONG): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_mbstring_ncopy}
  function ASN1_mbstring_ncopy(out_: PPASN1_STRING; const in_: PByte; len: TIdC_INT; inform: TIdC_INT; mask: TIdC_ULONG; minsize: TIdC_LONG; maxsize: TIdC_LONG): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM ASN1_STRING_set_by_NID}
  function ASN1_STRING_set_by_NID(out_: PPASN1_STRING; const in_: PByte; inlen: TIdC_INT; inform: TIdC_INT; nid: TIdC_INT): PASN1_STRING cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_STRING_TABLE_get}
  function ASN1_STRING_TABLE_get(nid: TIdC_INT): PASN1_STRING_TABLE cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_STRING_TABLE_add}
  function ASN1_STRING_TABLE_add(v1: TIdC_INT; v2: TIdC_LONG; v3: TIdC_LONG; v4: TIdC_ULONG; v5: TIdC_ULONG): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_STRING_TABLE_cleanup}
  procedure ASN1_STRING_TABLE_cleanup cdecl; external CLibCrypto;

  (* ASN1 template functions *)

  (* Old API compatible functions *)
  {$EXTERNALSYM ASN1_item_new}
  function ASN1_item_new(const it: PASN1_ITEM): PASN1_VALUE cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_item_free}
  procedure ASN1_item_free(_val: PASN1_VALUE; const it: PASN1_ITEM) cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_item_d2i}
  function ASN1_item_d2i(_val: PPASN1_VALUE; const in_: PPByte; len: TIdC_LONG; const it: PASN1_ITEM): PASN1_VALUE cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_item_i2d}
  function ASN1_item_i2d(_val: PASN1_VALUE; out_: PPByte; const it: PASN1_ITEM): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_item_ndef_i2d}
  function ASN1_item_ndef_i2d(_val: PASN1_VALUE; out_: PPByte; const it: PASN1_ITEM): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM ASN1_add_oid_module}
  procedure ASN1_add_oid_module cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_add_stable_module}
  procedure ASN1_add_stable_module cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM ASN1_generate_nconf}
  function ASN1_generate_nconf(const _str: PIdAnsiChar; nconf: PCONF): PASN1_TYPE cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_generate_v3}
  function ASN1_generate_v3(const _str: PIdAnsiChar; cnf: PX509V3_CTX): PASN1_TYPE cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_str2mask}
  function ASN1_str2mask(const _str: PByte; pmask: PIdC_ULONG): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM ASN1_item_print}
  function ASN1_item_print(out_: PBIO; ifld: PASN1_VALUE; indent: TIdC_INT; const it: PASN1_ITEM; const pctx: PASN1_PCTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_PCTX_new}
  function ASN1_PCTX_new: PASN1_PCTX cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_PCTX_free}
  procedure ASN1_PCTX_free(p: PASN1_PCTX) cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_PCTX_get_flags}
  function ASN1_PCTX_get_flags(const p: PASN1_PCTX): TIdC_ULONG cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_PCTX_set_flags}
  procedure ASN1_PCTX_set_flags(p: PASN1_PCTX; flags: TIdC_ULONG) cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_PCTX_get_nm_flags}
  function ASN1_PCTX_get_nm_flags(const p: PASN1_PCTX): TIdC_ULONG cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_PCTX_set_nm_flags}
  procedure ASN1_PCTX_set_nm_flags(p: PASN1_PCTX; flags: TIdC_ULONG) cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_PCTX_get_cert_flags}
  function ASN1_PCTX_get_cert_flags(const p: PASN1_PCTX): TIdC_ULONG cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_PCTX_set_cert_flags}
  procedure ASN1_PCTX_set_cert_flags(p: PASN1_PCTX; flags: TIdC_ULONG) cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_PCTX_get_oid_flags}
  function ASN1_PCTX_get_oid_flags(const p: PASN1_PCTX): TIdC_ULONG cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_PCTX_set_oid_flags}
  procedure ASN1_PCTX_set_oid_flags(p: PASN1_PCTX; flags: TIdC_ULONG) cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_PCTX_get_str_flags}
  function ASN1_PCTX_get_str_flags(const p: PASN1_PCTX): TIdC_ULONG cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_PCTX_set_str_flags}
  procedure ASN1_PCTX_set_str_flags(p: PASN1_PCTX; flags: TIdC_ULONG) cdecl; external CLibCrypto;

  //ASN1_SCTX *ASN1_SCTX_new(int (*scan_cb) (ASN1_SCTX *ctx));
  {$EXTERNALSYM ASN1_SCTX_free}
  procedure ASN1_SCTX_free(p: PASN1_SCTX) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_SCTX_get_item}
  function ASN1_SCTX_get_item(p: PASN1_SCTX): PASN1_ITEM cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_SCTX_get_template}
  function ASN1_SCTX_get_template(p: PASN1_SCTX): PASN1_TEMPLATE cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_SCTX_get_flags}
  function ASN1_SCTX_get_flags(p: PASN1_SCTX): TIdC_ULONG cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_SCTX_set_app_data}
  procedure ASN1_SCTX_set_app_data(p: PASN1_SCTX; data: Pointer) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_SCTX_get_app_data}
  function ASN1_SCTX_get_app_data(p: PASN1_SCTX): Pointer cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM BIO_f_asn1}
  function BIO_f_asn1: PBIO_METHOD cdecl; external CLibCrypto;

  {$EXTERNALSYM BIO_new_NDEF}
  function BIO_new_NDEF(out_: PBIO; _val: PASN1_VALUE; const it: PASN1_ITEM): PBIO cdecl; external CLibCrypto;

  {$EXTERNALSYM i2d_ASN1_bio_stream}
  function i2d_ASN1_bio_stream(out_: PBIO; _val: PASN1_VALUE; in_: PBIO; flags: TIdC_INT; const it: PASN1_ITEM): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM PEM_write_bio_ASN1_stream}
  function PEM_write_bio_ASN1_stream(out_: PBIO; _val: PASN1_VALUE; in_: PBIO; flags: TIdC_INT; const hdr: PIdAnsiChar; const it: PASN1_ITEM): TIdC_INT cdecl; external CLibCrypto;
  //function SMIME_write_ASN1(bio: PBIO; _val: PASN1_VALUE; data: PBIO; flags: TIdC_INT;
  //                     ctype_nid: TIdC_INT; econt_nid: TIdC_INT;
  //                     STACK_OF(X509_ALGOR) *mdalgs, const ASN1_ITEM *it): TIdC_INT;
  {$EXTERNALSYM SMIME_read_ASN1}
  function SMIME_read_ASN1(bio: PBIO; bcont: PPBIO; const it: PASN1_ITEM): PASN1_VALUE cdecl; external CLibCrypto;
  {$EXTERNALSYM SMIME_crlf_copy}
  function SMIME_crlf_copy(in_: PBIO; out_: PBIO; flags: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM SMIME_text}
  function SMIME_text(in_: PBIO; out_: PBIO): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM ASN1_ITEM_lookup}
  function ASN1_ITEM_lookup(const name: PIdAnsiChar): PASN1_ITEM cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ASN1_ITEM_get}
  function ASN1_ITEM_get(i: TIdC_SIZET): PASN1_ITEM cdecl; external CLibCrypto; {introduced 1.1.0}

{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

type
  {$EXTERNALSYM Tsk_ASN1_OBJECT_new}
  Tsk_ASN1_OBJECT_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_ASN1_OBJECT cdecl;
  {$EXTERNALSYM Tsk_ASN1_OBJECT_new_null}
  Tsk_ASN1_OBJECT_new_null = function : PSTACK_OF_ASN1_OBJECT cdecl;
  {$EXTERNALSYM Tsk_ASN1_OBJECT_free}
  Tsk_ASN1_OBJECT_free = procedure(st : PSTACK_OF_ASN1_OBJECT) cdecl;
  {$EXTERNALSYM Tsk_ASN1_OBJECT_num}
  Tsk_ASN1_OBJECT_num = function (const sk : PSTACK_OF_ASN1_OBJECT) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_ASN1_OBJECT_value}
  Tsk_ASN1_OBJECT_value = function (const sk : PSTACK_OF_ASN1_OBJECT; i : TIdC_INT) : PASN1_OBJECT cdecl;
  {$EXTERNALSYM Tsk_ASN1_OBJECT_push}
  Tsk_ASN1_OBJECT_push = function (sk : PSTACK_OF_ASN1_OBJECT; st : PASN1_OBJECT) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_ASN1_OBJECT_dup}
  Tsk_ASN1_OBJECT_dup = function (sk : PSTACK_OF_ASN1_OBJECT) : PSTACK_OF_ASN1_OBJECT cdecl;
  {$EXTERNALSYM Tsk_ASN1_OBJECT_find}
  Tsk_ASN1_OBJECT_find = function (sk : PSTACK_OF_ASN1_OBJECT; _val : PASN1_OBJECT) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_ASN1_OBJECT_pop_free}
  Tsk_ASN1_OBJECT_pop_free = procedure (sk : PSTACK_OF_ASN1_OBJECT; func: TOPENSSL_sk_freefunc) cdecl;
  {$EXTERNALSYM Tsk_ASN1_INTEGER_new}
  Tsk_ASN1_INTEGER_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_ASN1_INTEGER cdecl;
  {$EXTERNALSYM Tsk_ASN1_INTEGER_new_null}
  Tsk_ASN1_INTEGER_new_null = function : PSTACK_OF_ASN1_INTEGER cdecl;
  {$EXTERNALSYM Tsk_ASN1_INTEGER_free}
  Tsk_ASN1_INTEGER_free = procedure(st : PSTACK_OF_ASN1_INTEGER) cdecl;
  {$EXTERNALSYM Tsk_ASN1_INTEGER_num}
  Tsk_ASN1_INTEGER_num = function (const sk : PSTACK_OF_ASN1_INTEGER) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_ASN1_INTEGER_value}
  Tsk_ASN1_INTEGER_value = function (const sk : PSTACK_OF_ASN1_INTEGER; i : TIdC_INT) : PASN1_INTEGER cdecl;
  {$EXTERNALSYM Tsk_ASN1_INTEGER_push}
  Tsk_ASN1_INTEGER_push = function (sk : PSTACK_OF_ASN1_INTEGER; st : PASN1_INTEGER) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_ASN1_INTEGER_dup}
  Tsk_ASN1_INTEGER_dup = function (sk : PSTACK_OF_ASN1_INTEGER) : PSTACK_OF_ASN1_INTEGER cdecl;
  {$EXTERNALSYM Tsk_ASN1_INTEGER_find}
  Tsk_ASN1_INTEGER_find = function (sk : PSTACK_OF_ASN1_INTEGER; _val : PASN1_INTEGER) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_ASN1_INTEGER_pop_free}
  Tsk_ASN1_INTEGER_pop_free = procedure (sk : PSTACK_OF_ASN1_INTEGER; func: TOPENSSL_sk_freefunc) cdecl;
  {$EXTERNALSYM Tsk_ASN1_GENERALSTRING_new}
  Tsk_ASN1_GENERALSTRING_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_ASN1_GENERALSTRING cdecl;
  {$EXTERNALSYM Tsk_ASN1_GENERALSTRING_new_null}
  Tsk_ASN1_GENERALSTRING_new_null = function : PSTACK_OF_ASN1_GENERALSTRING cdecl;
  {$EXTERNALSYM Tsk_ASN1_GENERALSTRING_free}
  Tsk_ASN1_GENERALSTRING_free = procedure(st : PSTACK_OF_ASN1_GENERALSTRING) cdecl;
  {$EXTERNALSYM Tsk_ASN1_GENERALSTRING_num}
  Tsk_ASN1_GENERALSTRING_num = function (const sk : PSTACK_OF_ASN1_GENERALSTRING) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_ASN1_GENERALSTRING_value}
  Tsk_ASN1_GENERALSTRING_value = function (const sk : PSTACK_OF_ASN1_GENERALSTRING; i : TIdC_INT) : PASN1_GENERALSTRING cdecl;
  {$EXTERNALSYM Tsk_ASN1_GENERALSTRING_push}
  Tsk_ASN1_GENERALSTRING_push = function (sk : PSTACK_OF_ASN1_GENERALSTRING; st : PASN1_GENERALSTRING) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_ASN1_GENERALSTRING_dup}
  Tsk_ASN1_GENERALSTRING_dup = function (sk : PSTACK_OF_ASN1_GENERALSTRING) : PSTACK_OF_ASN1_GENERALSTRING cdecl;
  {$EXTERNALSYM Tsk_ASN1_GENERALSTRING_find}
  Tsk_ASN1_GENERALSTRING_find = function (sk : PSTACK_OF_ASN1_GENERALSTRING; _val : PASN1_GENERALSTRING) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_ASN1_GENERALSTRING_pop_free}
  Tsk_ASN1_GENERALSTRING_pop_free = procedure (sk : PSTACK_OF_ASN1_GENERALSTRING; func: TOPENSSL_sk_freefunc) cdecl;
  {$EXTERNALSYM Tsk_ASN1_UTF8STRING_new}
  Tsk_ASN1_UTF8STRING_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_ASN1_UTF8STRING cdecl;
  {$EXTERNALSYM Tsk_ASN1_UTF8STRING_new_null}
  Tsk_ASN1_UTF8STRING_new_null = function : PSTACK_OF_ASN1_UTF8STRING cdecl;
  {$EXTERNALSYM Tsk_ASN1_UTF8STRING_free}
  Tsk_ASN1_UTF8STRING_free = procedure(st : PSTACK_OF_ASN1_UTF8STRING) cdecl;
  {$EXTERNALSYM Tsk_ASN1_UTF8STRING_num}
  Tsk_ASN1_UTF8STRING_num = function (const sk : PSTACK_OF_ASN1_UTF8STRING) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_ASN1_UTF8STRING_value}
  Tsk_ASN1_UTF8STRING_value = function (const sk : PSTACK_OF_ASN1_UTF8STRING; i : TIdC_INT) : PASN1_UTF8STRING cdecl;
  {$EXTERNALSYM Tsk_ASN1_UTF8STRING_push}
  Tsk_ASN1_UTF8STRING_push = function (sk : PSTACK_OF_ASN1_UTF8STRING; st : PASN1_UTF8STRING) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_ASN1_UTF8STRING_dup}
  Tsk_ASN1_UTF8STRING_dup = function (sk : PSTACK_OF_ASN1_UTF8STRING) : PSTACK_OF_ASN1_UTF8STRING cdecl;
  {$EXTERNALSYM Tsk_ASN1_UTF8STRING_find}
  Tsk_ASN1_UTF8STRING_find = function (sk : PSTACK_OF_ASN1_UTF8STRING; _val : PASN1_UTF8STRING) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_ASN1_UTF8STRING_pop_free}
  Tsk_ASN1_UTF8STRING_pop_free = procedure (sk : PSTACK_OF_ASN1_UTF8STRING; func: TOPENSSL_sk_freefunc) cdecl;
  {$EXTERNALSYM Tsk_ASN1_TYPE_new}
  Tsk_ASN1_TYPE_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_ASN1_TYPE cdecl;
  {$EXTERNALSYM Tsk_ASN1_TYPE_new_null}
  Tsk_ASN1_TYPE_new_null = function : PSTACK_OF_ASN1_TYPE cdecl;
  {$EXTERNALSYM Tsk_ASN1_TYPE_free}
  Tsk_ASN1_TYPE_free = procedure(st : PSTACK_OF_ASN1_TYPE) cdecl;
  {$EXTERNALSYM Tsk_ASN1_TYPE_num}
  Tsk_ASN1_TYPE_num = function (const sk : PSTACK_OF_ASN1_TYPE) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_ASN1_TYPE_value}
  Tsk_ASN1_TYPE_value = function (const sk : PSTACK_OF_ASN1_TYPE; i : TIdC_INT) : PASN1_TYPE cdecl;
  {$EXTERNALSYM Tsk_ASN1_TYPE_push}
  Tsk_ASN1_TYPE_push = function (sk : PSTACK_OF_ASN1_TYPE; st : PASN1_TYPE) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_ASN1_TYPE_dup}
  Tsk_ASN1_TYPE_dup = function (sk : PSTACK_OF_ASN1_TYPE) : PSTACK_OF_ASN1_TYPE cdecl;
  {$EXTERNALSYM Tsk_ASN1_TYPE_find}
  Tsk_ASN1_TYPE_find = function (sk : PSTACK_OF_ASN1_TYPE; _val : PASN1_TYPE) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_ASN1_TYPE_pop_free}
  Tsk_ASN1_TYPE_pop_free = procedure (sk : PSTACK_OF_ASN1_TYPE; func: TOPENSSL_sk_freefunc) cdecl;
  {$EXTERNALSYM Tsk_X509_ALGOR_new}
  Tsk_X509_ALGOR_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_X509_ALGOR cdecl;
  {$EXTERNALSYM Tsk_X509_ALGOR_new_null}
  Tsk_X509_ALGOR_new_null = function : PSTACK_OF_X509_ALGOR cdecl;
  {$EXTERNALSYM Tsk_X509_ALGOR_free}
  Tsk_X509_ALGOR_free = procedure(st : PSTACK_OF_X509_ALGOR) cdecl;
  {$EXTERNALSYM Tsk_X509_ALGOR_num}
  Tsk_X509_ALGOR_num = function (const sk : PSTACK_OF_X509_ALGOR) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_ALGOR_value}
  Tsk_X509_ALGOR_value = function (const sk : PSTACK_OF_X509_ALGOR; i : TIdC_INT) : PX509_ALGOR cdecl;
  {$EXTERNALSYM Tsk_X509_ALGOR_push}
  Tsk_X509_ALGOR_push = function (sk : PSTACK_OF_X509_ALGOR; st : PX509_ALGOR) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_ALGOR_dup}
  Tsk_X509_ALGOR_dup = function (sk : PSTACK_OF_X509_ALGOR) : PSTACK_OF_X509_ALGOR cdecl;
  {$EXTERNALSYM Tsk_X509_ALGOR_find}
  Tsk_X509_ALGOR_find = function (sk : PSTACK_OF_X509_ALGOR; _val : PX509_ALGOR) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_ALGOR_pop_free}
  Tsk_X509_ALGOR_pop_free = procedure (sk : PSTACK_OF_X509_ALGOR; func: TOPENSSL_sk_freefunc) cdecl;
  {$EXTERNALSYM Tsk_ASN1_STRING_TABLE_new}
  Tsk_ASN1_STRING_TABLE_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_ASN1_STRING_TABLE cdecl;
  {$EXTERNALSYM Tsk_ASN1_STRING_TABLE_new_null}
  Tsk_ASN1_STRING_TABLE_new_null = function : PSTACK_OF_ASN1_STRING_TABLE cdecl;
  {$EXTERNALSYM Tsk_ASN1_STRING_TABLE_free}
  Tsk_ASN1_STRING_TABLE_free = procedure(st : PSTACK_OF_ASN1_STRING_TABLE) cdecl;
  {$EXTERNALSYM Tsk_ASN1_STRING_TABLE_num}
  Tsk_ASN1_STRING_TABLE_num = function (const sk : PSTACK_OF_ASN1_STRING_TABLE) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_ASN1_STRING_TABLE_value}
  Tsk_ASN1_STRING_TABLE_value = function (const sk : PSTACK_OF_ASN1_STRING_TABLE; i : TIdC_INT) : PASN1_STRING_TABLE cdecl;
  {$EXTERNALSYM Tsk_ASN1_STRING_TABLE_push}
  Tsk_ASN1_STRING_TABLE_push = function (sk : PSTACK_OF_ASN1_STRING_TABLE; st : PASN1_STRING_TABLE) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_ASN1_STRING_TABLE_dup}
  Tsk_ASN1_STRING_TABLE_dup = function (sk : PSTACK_OF_ASN1_STRING_TABLE) : PSTACK_OF_ASN1_STRING_TABLE cdecl;
  {$EXTERNALSYM Tsk_ASN1_STRING_TABLE_find}
  Tsk_ASN1_STRING_TABLE_find = function (sk : PSTACK_OF_ASN1_STRING_TABLE; _val : PASN1_STRING_TABLE) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_ASN1_STRING_TABLE_pop_free}
  Tsk_ASN1_STRING_TABLE_pop_free = procedure (sk : PSTACK_OF_ASN1_STRING_TABLE; func: TOPENSSL_sk_freefunc) cdecl;

var
  {$EXTERNALSYM sk_ASN1_OBJECT_new}
  sk_ASN1_OBJECT_new: Tsk_ASN1_OBJECT_new = nil;
  {$EXTERNALSYM sk_ASN1_OBJECT_new_null}
  sk_ASN1_OBJECT_new_null : Tsk_ASN1_OBJECT_new_null = nil;
  {$EXTERNALSYM sk_ASN1_OBJECT_free}
  sk_ASN1_OBJECT_free : Tsk_ASN1_OBJECT_free = nil;
  {$EXTERNALSYM sk_ASN1_OBJECT_num}
  sk_ASN1_OBJECT_num : Tsk_ASN1_OBJECT_num = nil;
  {$EXTERNALSYM sk_ASN1_OBJECT_value}
  sk_ASN1_OBJECT_value : Tsk_ASN1_OBJECT_value = nil;
  {$EXTERNALSYM sk_ASN1_OBJECT_push}
  sk_ASN1_OBJECT_push : Tsk_ASN1_OBJECT_push = nil;
  {$EXTERNALSYM sk_ASN1_OBJECT_dup}
  sk_ASN1_OBJECT_dup : Tsk_ASN1_OBJECT_dup = nil;
  {$EXTERNALSYM sk_ASN1_OBJECT_find}
  sk_ASN1_OBJECT_find : Tsk_ASN1_OBJECT_find = nil;
  {$EXTERNALSYM sk_ASN1_OBJECT_pop_free}
  sk_ASN1_OBJECT_pop_free : Tsk_ASN1_OBJECT_pop_free = nil;
  {$EXTERNALSYM sk_ASN1_INTEGER_new}
  sk_ASN1_INTEGER_new: Tsk_ASN1_INTEGER_new = nil;
  {$EXTERNALSYM sk_ASN1_INTEGER_new_null}
  sk_ASN1_INTEGER_new_null : Tsk_ASN1_INTEGER_new_null = nil;
  {$EXTERNALSYM sk_ASN1_INTEGER_free}
  sk_ASN1_INTEGER_free : Tsk_ASN1_INTEGER_free = nil;
  {$EXTERNALSYM sk_ASN1_INTEGER_num}
  sk_ASN1_INTEGER_num : Tsk_ASN1_INTEGER_num = nil;
  {$EXTERNALSYM sk_ASN1_INTEGER_value}
  sk_ASN1_INTEGER_value : Tsk_ASN1_INTEGER_value = nil;
  {$EXTERNALSYM sk_ASN1_INTEGER_push}
  sk_ASN1_INTEGER_push : Tsk_ASN1_INTEGER_push = nil;
  {$EXTERNALSYM sk_ASN1_INTEGER_dup}
  sk_ASN1_INTEGER_dup : Tsk_ASN1_INTEGER_dup = nil;
  {$EXTERNALSYM sk_ASN1_INTEGER_find}
  sk_ASN1_INTEGER_find : Tsk_ASN1_INTEGER_find = nil;
  {$EXTERNALSYM sk_ASN1_INTEGER_pop_free}
  sk_ASN1_INTEGER_pop_free : Tsk_ASN1_INTEGER_pop_free = nil;
  {$EXTERNALSYM sk_ASN1_GENERALSTRING_new}
  sk_ASN1_GENERALSTRING_new: Tsk_ASN1_GENERALSTRING_new = nil;
  {$EXTERNALSYM sk_ASN1_GENERALSTRING_new_null}
  sk_ASN1_GENERALSTRING_new_null : Tsk_ASN1_GENERALSTRING_new_null = nil;
  {$EXTERNALSYM sk_ASN1_GENERALSTRING_free}
  sk_ASN1_GENERALSTRING_free : Tsk_ASN1_GENERALSTRING_free = nil;
  {$EXTERNALSYM sk_ASN1_GENERALSTRING_num}
  sk_ASN1_GENERALSTRING_num : Tsk_ASN1_GENERALSTRING_num = nil;
  {$EXTERNALSYM sk_ASN1_GENERALSTRING_value}
  sk_ASN1_GENERALSTRING_value : Tsk_ASN1_GENERALSTRING_value = nil;
  {$EXTERNALSYM sk_ASN1_GENERALSTRING_push}
  sk_ASN1_GENERALSTRING_push : Tsk_ASN1_GENERALSTRING_push = nil;
  {$EXTERNALSYM sk_ASN1_GENERALSTRING_dup}
  sk_ASN1_GENERALSTRING_dup : Tsk_ASN1_GENERALSTRING_dup = nil;
  {$EXTERNALSYM sk_ASN1_GENERALSTRING_find}
  sk_ASN1_GENERALSTRING_find : Tsk_ASN1_GENERALSTRING_find = nil;
  {$EXTERNALSYM sk_ASN1_GENERALSTRING_pop_free}
  sk_ASN1_GENERALSTRING_pop_free : Tsk_ASN1_GENERALSTRING_pop_free = nil;
  {$EXTERNALSYM sk_ASN1_UTF8STRING_new}
  sk_ASN1_UTF8STRING_new: Tsk_ASN1_UTF8STRING_new = nil;
  {$EXTERNALSYM sk_ASN1_UTF8STRING_new_null}
  sk_ASN1_UTF8STRING_new_null : Tsk_ASN1_UTF8STRING_new_null = nil;
  {$EXTERNALSYM sk_ASN1_UTF8STRING_free}
  sk_ASN1_UTF8STRING_free : Tsk_ASN1_UTF8STRING_free = nil;
  {$EXTERNALSYM sk_ASN1_UTF8STRING_num}
  sk_ASN1_UTF8STRING_num : Tsk_ASN1_UTF8STRING_num = nil;
  {$EXTERNALSYM sk_ASN1_UTF8STRING_value}
  sk_ASN1_UTF8STRING_value : Tsk_ASN1_UTF8STRING_value = nil;
  {$EXTERNALSYM sk_ASN1_UTF8STRING_push}
  sk_ASN1_UTF8STRING_push : Tsk_ASN1_UTF8STRING_push = nil;
  {$EXTERNALSYM sk_ASN1_UTF8STRING_dup}
  sk_ASN1_UTF8STRING_dup : Tsk_ASN1_UTF8STRING_dup = nil;
  {$EXTERNALSYM sk_ASN1_UTF8STRING_find}
  sk_ASN1_UTF8STRING_find : Tsk_ASN1_UTF8STRING_find = nil;
  {$EXTERNALSYM sk_ASN1_UTF8STRING_pop_free}
  sk_ASN1_UTF8STRING_pop_free : Tsk_ASN1_UTF8STRING_pop_free = nil;
  {$EXTERNALSYM sk_ASN1_TYPE_new}
  sk_ASN1_TYPE_new: Tsk_ASN1_TYPE_new = nil;
  {$EXTERNALSYM sk_ASN1_TYPE_new_null}
  sk_ASN1_TYPE_new_null : Tsk_ASN1_TYPE_new_null = nil;
  {$EXTERNALSYM sk_ASN1_TYPE_free}
  sk_ASN1_TYPE_free : Tsk_ASN1_TYPE_free = nil;
  {$EXTERNALSYM sk_ASN1_TYPE_num}
  sk_ASN1_TYPE_num : Tsk_ASN1_TYPE_num = nil;
  {$EXTERNALSYM sk_ASN1_TYPE_value}
  sk_ASN1_TYPE_value : Tsk_ASN1_TYPE_value = nil;
  {$EXTERNALSYM sk_ASN1_TYPE_push}
  sk_ASN1_TYPE_push : Tsk_ASN1_TYPE_push = nil;
  {$EXTERNALSYM sk_ASN1_TYPE_dup}
  sk_ASN1_TYPE_dup : Tsk_ASN1_TYPE_dup = nil;
  {$EXTERNALSYM sk_ASN1_TYPE_find}
  sk_ASN1_TYPE_find : Tsk_ASN1_TYPE_find = nil;
  {$EXTERNALSYM sk_ASN1_TYPE_pop_free}
  sk_ASN1_TYPE_pop_free : Tsk_ASN1_TYPE_pop_free = nil;
  {$EXTERNALSYM sk_X509_ALGOR_new}
  sk_X509_ALGOR_new: Tsk_X509_ALGOR_new = nil;
  {$EXTERNALSYM sk_X509_ALGOR_new_null}
  sk_X509_ALGOR_new_null : Tsk_X509_ALGOR_new_null = nil;
  {$EXTERNALSYM sk_X509_ALGOR_free}
  sk_X509_ALGOR_free : Tsk_X509_ALGOR_free = nil;
  {$EXTERNALSYM sk_X509_ALGOR_num}
  sk_X509_ALGOR_num : Tsk_X509_ALGOR_num = nil;
  {$EXTERNALSYM sk_X509_ALGOR_value}
  sk_X509_ALGOR_value : Tsk_X509_ALGOR_value = nil;
  {$EXTERNALSYM sk_X509_ALGOR_push}
  sk_X509_ALGOR_push : Tsk_X509_ALGOR_push = nil;
  {$EXTERNALSYM sk_X509_ALGOR_dup}
  sk_X509_ALGOR_dup : Tsk_X509_ALGOR_dup = nil;
  {$EXTERNALSYM sk_X509_ALGOR_find}
  sk_X509_ALGOR_find : Tsk_X509_ALGOR_find = nil;
  {$EXTERNALSYM sk_X509_ALGOR_pop_free}
  sk_X509_ALGOR_pop_free : Tsk_X509_ALGOR_pop_free = nil;
{$ELSE}
  {$EXTERNALSYM sk_ASN1_OBJECT_new}
  function sk_ASN1_OBJECT_new(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_ASN1_OBJECT cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_ASN1_OBJECT_new_null}
  function sk_ASN1_OBJECT_new_null : PSTACK_OF_ASN1_OBJECT cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_ASN1_OBJECT_free}
  procedure sk_ASN1_OBJECT_free(st : PSTACK_OF_ASN1_OBJECT) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_ASN1_OBJECT_num}
  function sk_ASN1_OBJECT_num (const sk : PSTACK_OF_ASN1_OBJECT) : TIdC_INT; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_ASN1_OBJECT_value}
  function sk_ASN1_OBJECT_value (const sk : PSTACK_OF_ASN1_OBJECT; i : TIdC_INT) : PASN1_OBJECT cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_ASN1_OBJECT_push}
  function sk_ASN1_OBJECT_push (sk : PSTACK_OF_ASN1_OBJECT; st : PX509_ALGOR) : TIdC_INT cdecl; external CLibCrypto  name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_ASN1_OBJECT_dup}
  function sk_ASN1_OBJECT_dup (sk : PSTACK_OF_ASN1_OBJECT) : PSTACK_OF_ASN1_OBJECT cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_ASN1_OBJECT_find}
  function sk_ASN1_OBJECT_find (sk : PSTACK_OF_ASN1_OBJECT; _val : PX509_ALGOR) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_ASN1_OBJECT_pop_free}
  procedure sk_ASN1_OBJECT_pop_free (sk : PSTACK_OF_ASN1_OBJECT; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';
  {$EXTERNALSYM sk_ASN1_INTEGER_new}
  function sk_ASN1_INTEGER_new(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_ASN1_INTEGER cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_ASN1_INTEGER_new_null}
  function sk_ASN1_INTEGER_new_null : PSTACK_OF_ASN1_INTEGER cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_ASN1_INTEGER_free}
  procedure sk_ASN1_INTEGER_free(st : PSTACK_OF_ASN1_INTEGER) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_ASN1_INTEGER_num}
  function sk_ASN1_INTEGER_num (const sk : PSTACK_OF_ASN1_INTEGER) : TIdC_INT; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_ASN1_INTEGER_value}
  function sk_ASN1_INTEGER_value (const sk : PSTACK_OF_ASN1_INTEGER; i : TIdC_INT) : PASN1_INTEGER cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_ASN1_INTEGER_push}
  function sk_ASN1_INTEGER_push (sk : PSTACK_OF_ASN1_INTEGER; st : PX509_ALGOR) : TIdC_INT cdecl; external CLibCrypto  name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_ASN1_INTEGER_dup}
  function sk_ASN1_INTEGER_dup (sk : PSTACK_OF_ASN1_INTEGER) : PSTACK_OF_ASN1_INTEGER cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_ASN1_INTEGER_find}
  function sk_ASN1_INTEGER_find (sk : PSTACK_OF_ASN1_INTEGER; _val : PX509_ALGOR) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_ASN1_INTEGER_pop_free}
  procedure sk_ASN1_INTEGER_pop_free (sk : PSTACK_OF_ASN1_INTEGER; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';
  {$EXTERNALSYM sk_ASN1_GENERALSTRING_new}
  function sk_ASN1_GENERALSTRING_new(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_ASN1_OBJECT cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_ASN1_GENERALSTRING_new_null}
  function sk_ASN1_GENERALSTRING_new_null : PSTACK_OF_ASN1_GENERALSTRING cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_ASN1_GENERALSTRING_free}
  procedure sk_ASN1_GENERALSTRING_free(st : PSTACK_OF_ASN1_GENERALSTRING) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_ASN1_GENERALSTRING_num}
  function sk_ASN1_GENERALSTRING_num (const sk : PSTACK_OF_ASN1_GENERALSTRING) : TIdC_INT; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_ASN1_GENERALSTRING_value}
  function sk_ASN1_GENERALSTRING_value (const sk :PSTACK_OF_ASN1_GENERALSTRING; i : TIdC_INT) : ASN1_GENERALSTRING cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_ASN1_GENERALSTRING_push}
  function sk_ASN1_GENERALSTRING_push (sk : PSTACK_OF_ASN1_GENERALSTRING; st : PX509_ALGOR) : TIdC_INT cdecl; external CLibCrypto  name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_ASN1_GENERALSTRING_dup}
  function sk_ASN1_GENERALSTRING_dup (sk : PSTACK_OF_ASN1_GENERALSTRING) : PSTACK_OF_ASN1_GENERALSTRING cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_ASN1_GENERALSTRING_find}
  function sk_ASN1_GENERALSTRING_find (sk : PSTACK_OF_ASN1_GENERALSTRING; _val : PX509_ALGOR) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_ASN1_GENERALSTRING_pop_free}
  procedure sk_ASN1_GENERALSTRING_pop_free (sk : PSTACK_OF_ASN1_GENERALSTRING; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';
  {$EXTERNALSYM sk_ASN1_UTF8STRING_new}
  function sk_ASN1_UTF8STRING_new(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_ASN1_UTF8STRING cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_ASN1_UTF8STRING_new_null}
  function sk_ASN1_UTF8STRING_new_null : PSTACK_OF_ASN1_UTF8STRING cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_ASN1_UTF8STRING_free}
  procedure sk_ASN1_UTF8STRING_free(st : PSTACK_OF_ASN1_UTF8STRING) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_ASN1_UTF8STRING_num}
  function sk_ASN1_UTF8STRING_num (const sk : PSTACK_OF_ASN1_UTF8STRING) : TIdC_INT; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_ASN1_UTF8STRING_value}
  function sk_ASN1_UTF8STRING_value (const sk : PSTACK_OF_ASN1_UTF8STRING; i : TIdC_INT) : PASN1_UTF8STRING cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_ASN1_UTF8STRING_push}
  function sk_ASN1_UTF8STRING_push (sk : PSTACK_OF_ASN1_UTF8STRING; st : PX509_ALGOR) : TIdC_INT cdecl; external CLibCrypto  name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_ASN1_UTF8STRING_dup}
  function sk_ASN1_UTF8STRING_dup (sk : PSTACK_OF_ASN1_UTF8STRING) : PSTACK_OF_ASN1_UTF8STRING cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_ASN1_UTF8STRING_find}
  function sk_ASN1_UTF8STRING_find (sk : PSTACK_OF_ASN1_UTF8STRING; _val : PX509_ALGOR) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_ASN1_UTF8STRING_pop_free}
  procedure sk_ASN1_UTF8STRING_pop_free (sk : PSTACK_OF_ASN1_UTF8STRING; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';
  {$EXTERNALSYM sk_ASN1_TYPE_new}
  function sk_ASN1_TYPE_new(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_ASN1_TYPE cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_ASN1_TYPE_new_null}
  function sk_ASN1_TYPE_new_null : PSTACK_OF_ASN1_TYPE cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_ASN1_TYPE_free}
  procedure sk_ASN1_TYPE_free(st : PSTACK_OF_ASN1_TYPE) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_ASN1_TYPE_num}
  function sk_ASN1_TYPE_num (const sk : PSTACK_OF_ASN1_TYPE) : TIdC_INT; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_ASN1_TYPE_value}
  function sk_ASN1_TYPE_value (const sk : PSTACK_OF_ASN1_TYPE; i : TIdC_INT) : PASN1_TYPE cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_ASN1_TYPE_push}
  function sk_ASN1_TYPE_push (sk : PSTACK_OF_ASN1_TYPE; st : PX509_ALGOR) : TIdC_INT cdecl; external CLibCrypto  name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_ASN1_TYPE_dup}
  function sk_ASN1_TYPE_dup (sk : PSTACK_OF_ASN1_TYPE) : PSTACK_OF_ASN1_TYPE cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_ASN1_TYPE_find}
  function sk_ASN1_TYPE_find (sk : PSTACK_OF_ASN1_TYPE; _val : PX509_ALGOR) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_ASN1_TYPE_pop_free}
  procedure sk_ASN1_TYPE_pop_free (sk : PSTACK_OF_ASN1_TYPE; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';
  {$EXTERNALSYM sk_X509_ALGOR_new}
  function sk_X509_ALGOR_new(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_X509_ALGOR cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_X509_ALGOR_new_null}
  function sk_X509_ALGOR_new_null : PSTACK_OF_X509_ALGOR cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_X509_ALGOR_free}
  procedure sk_X509_ALGOR_free(st : PSTACK_OF_X509_ALGOR) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_X509_ALGOR_num}
  function sk_X509_ALGOR_num (const sk : PSTACK_OF_X509_ALGOR) : TIdC_INT; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_X509_ALGOR_value}
  function sk_X509_ALGOR_value (const sk : PSTACK_OF_X509_ALGOR; i : TIdC_INT) : PX509_ALGOR cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_X509_ALGOR_push}
  function sk_X509_ALGOR_push (sk : PSTACK_OF_X509_ALGOR; st : PX509_ALGOR) : TIdC_INT cdecl; external CLibCrypto  name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_X509_ALGOR_dup}
  function sk_X509_ALGOR_dup (sk : PSTACK_OF_X509_ALGOR) : PSTACK_OF_X509_ALGOR cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_X509_ALGOR_find}
  function sk_X509_ALGOR_find (sk : PSTACK_OF_X509_ALGOR; _val : PX509_ALGOR) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_X509_ALGOR_pop_free}
  procedure sk_X509_ALGOR_pop_free (sk : PSTACK_OF_X509_ALGOR; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';
{$ENDIF}

implementation

  uses
    classes, 
    TaurusTLSExceptionHandlers
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    ,TaurusTLSLoader
  {$ENDIF};
  
const
  ASN1_TYPE_pack_sequence_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASN1_TYPE_unpack_sequence_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASN1_STRING_get0_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASN1_TIME_set_string_X509_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASN1_TIME_to_tm_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASN1_TIME_normalize_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASN1_TIME_cmp_time_t_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASN1_TIME_compare_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASN1_INTEGER_get_int64_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASN1_INTEGER_set_int64_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASN1_INTEGER_get_uint64_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASN1_INTEGER_set_uint64_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASN1_ENUMERATED_get_int64_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASN1_ENUMERATED_set_int64_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASN1_buf_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASN1_add_stable_module_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASN1_str2mask_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASN1_SCTX_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASN1_SCTX_get_item_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASN1_SCTX_get_template_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASN1_SCTX_get_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASN1_SCTX_set_app_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASN1_SCTX_get_app_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASN1_ITEM_lookup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASN1_ITEM_get_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
    //These two only appear in OpenSSL 4.0.0 even though they are documented
    //implying they were in earlier versions.
  ASN1_BIT_STRING_get_length_introduced = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  ASN1_BIT_STRING_set1_introduced = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
const
  ASN1_TYPE_get_procname = 'ASN1_TYPE_get';
  ASN1_TYPE_set_procname = 'ASN1_TYPE_set';
  ASN1_TYPE_set1_procname = 'ASN1_TYPE_set1';
  ASN1_TYPE_cmp_procname = 'ASN1_TYPE_cmp';

  ASN1_TYPE_pack_sequence_procname = 'ASN1_TYPE_pack_sequence'; {introduced 1.1.0}
  ASN1_TYPE_unpack_sequence_procname = 'ASN1_TYPE_unpack_sequence'; {introduced 1.1.0}

  ASN1_OBJECT_new_procname = 'ASN1_OBJECT_new';
  ASN1_OBJECT_free_procname = 'ASN1_OBJECT_free';
  i2d_ASN1_OBJECT_procname = 'i2d_ASN1_OBJECT';
  d2i_ASN1_OBJECT_procname = 'd2i_ASN1_OBJECT';
  d2i_ASN1_BIT_STRING_procname = 'd2i_ASN1_BIT_STRING';
  i2d_ASN1_BIT_STRING_procname = 'i2d_ASN1_BIT_STRING';

  //DECLARE_ASN1_ITEM(ASN1_OBJECT)
  //
  //DEFINE_STACK_OF(ASN1_OBJECT)

  ASN1_STRING_new_procname = 'ASN1_STRING_new';
  ASN1_STRING_free_procname = 'ASN1_STRING_free';
  ASN1_STRING_clear_free_procname = 'ASN1_STRING_clear_free';
  ASN1_STRING_copy_procname = 'ASN1_STRING_copy';
  ASN1_STRING_dup_procname = 'ASN1_STRING_dup';
  ASN1_STRING_type_new_procname = 'ASN1_STRING_type_new';
  ASN1_STRING_cmp_procname = 'ASN1_STRING_cmp';

  (*
   * Since this is used to store all sorts of things, via macros, for now,
   * make its data void *
   *)
  ASN1_STRING_set_procname = 'ASN1_STRING_set';
  ASN1_STRING_set0_procname = 'ASN1_STRING_set0';
  ASN1_STRING_length_procname = 'ASN1_STRING_length';
  ASN1_STRING_length_set_procname = 'ASN1_STRING_length_set';
  ASN1_STRING_type_procname = 'ASN1_STRING_type';
  ASN1_STRING_get0_data_procname = 'ASN1_STRING_get0_data'; {introduced 1.1.0}

  //DECLARE_ASN1_FUNCTIONS(ASN1_BIT_STRING)
  ASN1_BIT_STRING_set_procname = 'ASN1_BIT_STRING_set';
  ASN1_BIT_STRING_set_bit_procname = 'ASN1_BIT_STRING_set_bit';
  ASN1_BIT_STRING_get_bit_procname = 'ASN1_BIT_STRING_get_bit';
  ASN1_BIT_STRING_check_procname = 'ASN1_BIT_STRING_check';

  ASN1_BIT_STRING_name_print_procname = 'ASN1_BIT_STRING_name_print';
  ASN1_BIT_STRING_num_asc_procname = 'ASN1_BIT_STRING_num_asc';
  ASN1_BIT_STRING_set_asc_procname = 'ASN1_BIT_STRING_set_asc';
  ASN1_BIT_STRING_get_length_procname = 'ASN1_BIT_STRING_get_length';
  ASN1_BIT_STRING_set1_procname = 'ASN1_BIT_STRING_set1';

  ASN1_INTEGER_new_procname = 'ASN1_INTEGER_new';
  ASN1_INTEGER_free_procname = 'ASN1_INTEGER_free';
  d2i_ASN1_INTEGER_procname = 'd2i_ASN1_INTEGER';
  i2d_ASN1_INTEGER_procname = 'i2d_ASN1_INTEGER';

  d2i_ASN1_UINTEGER_procname = 'd2i_ASN1_UINTEGER';
  ASN1_INTEGER_dup_procname = 'ASN1_INTEGER_dup';
  ASN1_INTEGER_cmp_procname = 'ASN1_INTEGER_cmp';

  // DECLARE_ASN1_FUNCTIONS(ASN1_ENUMERATED)

  ASN1_UTCTIME_check_procname = 'ASN1_UTCTIME_check';
  ASN1_UTCTIME_set_procname = 'ASN1_UTCTIME_set';
  ASN1_UTCTIME_adj_procname = 'ASN1_UTCTIME_adj';
  ASN1_UTCTIME_set_string_procname = 'ASN1_UTCTIME_set_string';
  ASN1_UTCTIME_cmp_time_t_procname = 'ASN1_UTCTIME_cmp_time_t';

  ASN1_GENERALIZEDTIME_check_procname = 'ASN1_GENERALIZEDTIME_check';
  ASN1_GENERALIZEDTIME_set_procname = 'ASN1_GENERALIZEDTIME_set';
  ASN1_GENERALIZEDTIME_adj_procname = 'ASN1_GENERALIZEDTIME_adj';
  ASN1_GENERALIZEDTIME_set_string_procname = 'ASN1_GENERALIZEDTIME_set_string';

  ASN1_TIME_diff_procname = 'ASN1_TIME_diff';

  // DECLARE_ASN1_FUNCTIONS(ASN1_OCTET_STRING)
  ASN1_OCTET_STRING_dup_procname = 'ASN1_OCTET_STRING_dup';
  ASN1_OCTET_STRING_cmp_procname = 'ASN1_OCTET_STRING_cmp';
  ASN1_OCTET_STRING_set_procname = 'ASN1_OCTET_STRING_set';
  d2i_ASN1_OCTET_STRING_procname = 'd2i_ASN1_OCTET_STRING';
  i2d_ASN1_OCTET_STRING_procname = 'i2d_ASN1_OCTET_STRING';
  ASN1_OCTET_STRING_free_procname = 'ASN1_OCTET_STRING_free';

  //DECLARE_ASN1_FUNCTIONS(ASN1_VISIBLESTRING)
  //DECLARE_ASN1_FUNCTIONS(ASN1_UNIVERSALSTRING)
  //DECLARE_ASN1_FUNCTIONS(ASN1_UTF8STRING)
  //DECLARE_ASN1_FUNCTIONS(ASN1_NULL)
  //DECLARE_ASN1_FUNCTIONS(ASN1_BMPSTRING)

  UTF8_getc_procname = 'UTF8_getc';
  UTF8_putc_procname = 'UTF8_putc';

  //DECLARE_ASN1_FUNCTIONS_name(ASN1_STRING, ASN1_PRINTABLE)
  //
  //DECLARE_ASN1_FUNCTIONS_name(ASN1_STRING, DIRECTORYSTRING)
  //DECLARE_ASN1_FUNCTIONS_name(ASN1_STRING, DISPLAYTEXT)
  //DECLARE_ASN1_FUNCTIONS(ASN1_PRINTABLESTRING)
  //DECLARE_ASN1_FUNCTIONS(ASN1_T61STRING)
  //DECLARE_ASN1_FUNCTIONS(ASN1_IA5STRING)
  //DECLARE_ASN1_FUNCTIONS(ASN1_GENERALSTRING)

  ASN1_UTCTIME_new_procname = 'ASN1_UTCTIME_new';
  ASN1_UTCTIME_free_procname = 'ASN1_UTCTIME_free';
  d2i_ASN1_UTCTIME_procname = 'd2i_ASN1_UTCTIME';
  i2d_ASN1_UTCTIME_procname = 'i2d_ASN1_UTCTIME';

  ASN1_GENERALIZEDTIME_new_procname = 'ASN1_GENERALIZEDTIME_new';
  ASN1_GENERALIZEDTIME_free_procname = 'ASN1_GENERALIZEDTIME_free';
  d2i_ASN1_GENERALIZEDTIME_procname = 'd2i_ASN1_GENERALIZEDTIME';
  i2d_ASN1_GENERALIZEDTIME_procname = 'i2d_ASN1_GENERALIZEDTIME';

  ASN1_TIME_new_procname = 'ASN1_TIME_new';
  ASN1_TIME_free_procname = 'ASN1_TIME_free';
  d2i_ASN1_TIME_procname = 'd2i_ASN1_TIME';
  i2d_ASN1_TIME_procname = 'i2d_ASN1_TIME';

  // DECLARE_ASN1_ITEM(ASN1_OCTET_STRING_NDEF)

  ASN1_TIME_set_procname = 'ASN1_TIME_set';
  ASN1_TIME_adj_procname = 'ASN1_TIME_adj';
  ASN1_TIME_check_procname = 'ASN1_TIME_check';
  ASN1_TIME_to_generalizedtime_procname = 'ASN1_TIME_to_generalizedtime';
  ASN1_TIME_set_string_procname = 'ASN1_TIME_set_string';
  ASN1_TIME_set_string_X509_procname = 'ASN1_TIME_set_string_X509'; {introduced 1.1.0}
  ASN1_TIME_to_tm_procname = 'ASN1_TIME_to_tm'; {introduced 1.1.0}
  ASN1_TIME_normalize_procname = 'ASN1_TIME_normalize'; {introduced 1.1.0}
  ASN1_TIME_cmp_time_t_procname = 'ASN1_TIME_cmp_time_t'; {introduced 1.1.0}
  ASN1_TIME_compare_procname = 'ASN1_TIME_compare'; {introduced 1.1.0}

  i2a_ASN1_INTEGER_procname = 'i2a_ASN1_INTEGER';
  a2i_ASN1_INTEGER_procname = 'a2i_ASN1_INTEGER';
  i2a_ASN1_ENUMERATED_procname = 'i2a_ASN1_ENUMERATED';
  a2i_ASN1_ENUMERATED_procname = 'a2i_ASN1_ENUMERATED';
  i2a_ASN1_OBJECT_procname = 'i2a_ASN1_OBJECT';
  a2i_ASN1_STRING_procname = 'a2i_ASN1_STRING';
  i2a_ASN1_STRING_procname = 'i2a_ASN1_STRING';
  i2t_ASN1_OBJECT_procname = 'i2t_ASN1_OBJECT';

  a2d_ASN1_OBJECT_procname = 'a2d_ASN1_OBJECT';
  ASN1_OBJECT_create_procname = 'ASN1_OBJECT_create';

  ASN1_INTEGER_get_int64_procname = 'ASN1_INTEGER_get_int64'; {introduced 1.1.0}
  ASN1_INTEGER_set_int64_procname = 'ASN1_INTEGER_set_int64'; {introduced 1.1.0}
  ASN1_INTEGER_get_uint64_procname = 'ASN1_INTEGER_get_uint64'; {introduced 1.1.0}
  ASN1_INTEGER_set_uint64_procname = 'ASN1_INTEGER_set_uint64'; {introduced 1.1.0}

  ASN1_INTEGER_set_procname = 'ASN1_INTEGER_set';
  ASN1_INTEGER_get_procname = 'ASN1_INTEGER_get';
  BN_to_ASN1_INTEGER_procname = 'BN_to_ASN1_INTEGER';
  ASN1_INTEGER_to_BN_procname = 'ASN1_INTEGER_to_BN';

  ASN1_ENUMERATED_get_int64_procname = 'ASN1_ENUMERATED_get_int64'; {introduced 1.1.0}
  ASN1_ENUMERATED_set_int64_procname = 'ASN1_ENUMERATED_set_int64'; {introduced 1.1.0}


  ASN1_ENUMERATED_set_procname = 'ASN1_ENUMERATED_set';
  ASN1_ENUMERATED_get_procname = 'ASN1_ENUMERATED_get';
  BN_to_ASN1_ENUMERATED_procname = 'BN_to_ASN1_ENUMERATED';
  ASN1_ENUMERATED_to_BN_procname = 'ASN1_ENUMERATED_to_BN';

  (* General *)
  (* given a string, return the correct type, max is the maximum length *)
  ASN1_PRINTABLE_type_procname = 'ASN1_PRINTABLE_type';

  ASN1_tag2bit_procname = 'ASN1_tag2bit';

  (* SPECIALS *)
  ASN1_get_object_procname = 'ASN1_get_object';
  ASN1_check_infinite_end_procname = 'ASN1_check_infinite_end';
  ASN1_const_check_infinite_end_procname = 'ASN1_const_check_infinite_end';
  ASN1_put_object_procname = 'ASN1_put_object';
  ASN1_put_eoc_procname = 'ASN1_put_eoc';
  ASN1_object_size_procname = 'ASN1_object_size';

  (* Used to implement other functions *)
  //void *ASN1_dup(i2d_of_void *i2d, d2i_of_void *d2i, void *x);
  //
  //# define ASN1_dup_of(type,i2d,d2i,x) \
  //    ((type*)ASN1_dup(CHECKED_I2D_OF(type, i2d), \
  //                     CHECKED_D2I_OF(type, d2i), \
  //                     CHECKED_PTR_OF(type, x)))
  //
  //# define ASN1_dup_of_const(type,i2d,d2i,x) \
  //    ((type*)ASN1_dup(CHECKED_I2D_OF(const type, i2d), \
  //                     CHECKED_D2I_OF(type, d2i), \
  //                     CHECKED_PTR_OF(const type, x)))
  //
  ASN1_item_dup_procname = 'ASN1_item_dup';

    (* ASN1 alloc/free macros for when a type is only used internally *)

  //# define M_ASN1_new_of(type) (type *)ASN1_item_new(ASN1_ITEM_rptr(type))
  //# define M_ASN1_free_of(x, type) \
  //                ASN1_item_free(CHECKED_PTR_OF(type, x), ASN1_ITEM_rptr(type))
  //
  //# ifndef OPENSSL_NO_STDIO
  //void *ASN1_d2i_fp(void *(*xnew) (void), d2i_of_void *d2i, FILE *in, void **x);

  //#  define ASN1_d2i_fp_of(type,xnew,d2i,in,x) \
  //    ((type*)ASN1_d2i_fp(CHECKED_NEW_OF(type, xnew), \
  //                        CHECKED_D2I_OF(type, d2i), \
  //                        in, \
  //                        CHECKED_PPTR_OF(type, x)))
  //
  //function ASN1_item_d2i_fp(const it: PASN1_ITEM; in_: PFILE; x: Pointer): Pointer;
  //function ASN1_i2d_fp(i2d: Pi2d_of_void; out_: PFILE; x: Pointer): TIdC_INT;
  //
  //#  define ASN1_i2d_fp_of(type,i2d,out,x) \
  //    (ASN1_i2d_fp(CHECKED_I2D_OF(type, i2d), \
  //                 out, \
  //                 CHECKED_PTR_OF(type, x)))
  //
  //#  define ASN1_i2d_fp_of_const(type,i2d,out,x) \
  //    (ASN1_i2d_fp(CHECKED_I2D_OF(const type, i2d), \
  //                 out, \
  //                 CHECKED_PTR_OF(const type, x)))
  //
  //function ASN1_item_i2d_fp(const it: PASN1_ITEM; out_: PFILE; x: Pointer): TIdC_INT;
  //function ASN1_STRING_print_ex_fp(&fp: PFILE; const _str: PASN1_STRING; flags: TIdC_ULONG): TIdC_INT;
  //# endif

  ASN1_STRING_to_UTF8_procname = 'ASN1_STRING_to_UTF8';

  //void *ASN1_d2i_bio(void *(*xnew) (void), d2i_of_void *d2i, BIO *in, void **x);

  //#  define ASN1_d2i_bio_of(type,xnew,d2i,in,x) \
  //    ((type*)ASN1_d2i_bio( CHECKED_NEW_OF(type, xnew), \
  //                          CHECKED_D2I_OF(type, d2i), \
  //                          in, \
  //                          CHECKED_PPTR_OF(type, x)))

  ASN1_item_d2i_bio_procname = 'ASN1_item_d2i_bio';
  ASN1_i2d_bio_procname = 'ASN1_i2d_bio';

  //#  define ASN1_i2d_bio_of(type,i2d,out,x) \
  //    (ASN1_i2d_bio(CHECKED_I2D_OF(type, i2d), \
  //                  out, \
  //                  CHECKED_PTR_OF(type, x)))
  //
  //#  define ASN1_i2d_bio_of_const(type,i2d,out,x) \
  //    (ASN1_i2d_bio(CHECKED_I2D_OF(const type, i2d), \
  //                  out, \
  //                  CHECKED_PTR_OF(const type, x)))
  ASN1_d2i_bio_procname = 'ASN1_d2i_bio';
  ASN1_item_i2d_bio_procname = 'ASN1_item_i2d_bio';
  ASN1_UTCTIME_print_procname = 'ASN1_UTCTIME_print';
  ASN1_GENERALIZEDTIME_print_procname = 'ASN1_GENERALIZEDTIME_print';
  ASN1_TIME_print_procname = 'ASN1_TIME_print';
  ASN1_STRING_print_procname = 'ASN1_STRING_print';
  ASN1_STRING_print_ex_procname = 'ASN1_STRING_print_ex';
  ASN1_buf_print_procname = 'ASN1_buf_print'; {introduced 1.1.0}
  ASN1_bn_print_procname = 'ASN1_bn_print';
  ASN1_parse_procname = 'ASN1_parse';
  ASN1_parse_dump_procname = 'ASN1_parse_dump';
  ASN1_tag2str_procname = 'ASN1_tag2str';

  (* Used to load and write Netscape format cert *)

  ASN1_UNIVERSALSTRING_to_string_procname = 'ASN1_UNIVERSALSTRING_to_string';

  ASN1_TYPE_set_octetstring_procname = 'ASN1_TYPE_set_octetstring';
  ASN1_TYPE_get_octetstring_procname = 'ASN1_TYPE_get_octetstring';
  ASN1_TYPE_set_int_octetstring_procname = 'ASN1_TYPE_set_int_octetstring';
  ASN1_TYPE_get_int_octetstring_procname = 'ASN1_TYPE_get_int_octetstring';

  ASN1_item_unpack_procname = 'ASN1_item_unpack';

  ASN1_item_pack_procname = 'ASN1_item_pack';

  ASN1_STRING_set_default_mask_procname = 'ASN1_STRING_set_default_mask';
  ASN1_STRING_set_default_mask_asc_procname = 'ASN1_STRING_set_default_mask_asc';
  ASN1_STRING_get_default_mask_procname = 'ASN1_STRING_get_default_mask';
  ASN1_mbstring_copy_procname = 'ASN1_mbstring_copy';
  ASN1_mbstring_ncopy_procname = 'ASN1_mbstring_ncopy';

  ASN1_STRING_set_by_NID_procname = 'ASN1_STRING_set_by_NID';
  ASN1_STRING_TABLE_get_procname = 'ASN1_STRING_TABLE_get';
  ASN1_STRING_TABLE_add_procname = 'ASN1_STRING_TABLE_add';
  ASN1_STRING_TABLE_cleanup_procname = 'ASN1_STRING_TABLE_cleanup';

  (* ASN1 template functions *)

  (* Old API compatible functions *)
  ASN1_item_new_procname = 'ASN1_item_new';
  ASN1_item_free_procname = 'ASN1_item_free';
  ASN1_item_d2i_procname = 'ASN1_item_d2i';
  ASN1_item_i2d_procname = 'ASN1_item_i2d';
  ASN1_item_ndef_i2d_procname = 'ASN1_item_ndef_i2d';

  ASN1_add_oid_module_procname = 'ASN1_add_oid_module';
  ASN1_add_stable_module_procname = 'ASN1_add_stable_module'; {introduced 1.1.0}

  ASN1_generate_nconf_procname = 'ASN1_generate_nconf';
  ASN1_generate_v3_procname = 'ASN1_generate_v3';
  ASN1_str2mask_procname = 'ASN1_str2mask'; {introduced 1.1.0}

  ASN1_item_print_procname = 'ASN1_item_print';
  ASN1_PCTX_new_procname = 'ASN1_PCTX_new';
  ASN1_PCTX_free_procname = 'ASN1_PCTX_free';
  ASN1_PCTX_get_flags_procname = 'ASN1_PCTX_get_flags';
  ASN1_PCTX_set_flags_procname = 'ASN1_PCTX_set_flags';
  ASN1_PCTX_get_nm_flags_procname = 'ASN1_PCTX_get_nm_flags';
  ASN1_PCTX_set_nm_flags_procname = 'ASN1_PCTX_set_nm_flags';
  ASN1_PCTX_get_cert_flags_procname = 'ASN1_PCTX_get_cert_flags';
  ASN1_PCTX_set_cert_flags_procname = 'ASN1_PCTX_set_cert_flags';
  ASN1_PCTX_get_oid_flags_procname = 'ASN1_PCTX_get_oid_flags';
  ASN1_PCTX_set_oid_flags_procname = 'ASN1_PCTX_set_oid_flags';
  ASN1_PCTX_get_str_flags_procname = 'ASN1_PCTX_get_str_flags';
  ASN1_PCTX_set_str_flags_procname = 'ASN1_PCTX_set_str_flags';

  //ASN1_SCTX *ASN1_SCTX_new(int (*scan_cb) (ASN1_SCTX *ctx));
  ASN1_SCTX_free_procname = 'ASN1_SCTX_free'; {introduced 1.1.0}
  ASN1_SCTX_get_item_procname = 'ASN1_SCTX_get_item'; {introduced 1.1.0}
  ASN1_SCTX_get_template_procname = 'ASN1_SCTX_get_template'; {introduced 1.1.0}
  ASN1_SCTX_get_flags_procname = 'ASN1_SCTX_get_flags'; {introduced 1.1.0}
  ASN1_SCTX_set_app_data_procname = 'ASN1_SCTX_set_app_data'; {introduced 1.1.0}
  ASN1_SCTX_get_app_data_procname = 'ASN1_SCTX_get_app_data'; {introduced 1.1.0}

  BIO_f_asn1_procname = 'BIO_f_asn1';

  BIO_new_NDEF_procname = 'BIO_new_NDEF';

  i2d_ASN1_bio_stream_procname = 'i2d_ASN1_bio_stream';
  PEM_write_bio_ASN1_stream_procname = 'PEM_write_bio_ASN1_stream';
  //function SMIME_write_ASN1(bio: PBIO; _val: PASN1_VALUE; data: PBIO; flags: TIdC_INT;
  //                     ctype_nid: TIdC_INT; econt_nid: TIdC_INT;
  //                     STACK_OF(X509_ALGOR) *mdalgs, const ASN1_ITEM *it): TIdC_INT;
  SMIME_read_ASN1_procname = 'SMIME_read_ASN1';
  SMIME_crlf_copy_procname = 'SMIME_crlf_copy';
  SMIME_text_procname = 'SMIME_text';

  ASN1_ITEM_lookup_procname = 'ASN1_ITEM_lookup'; {introduced 1.1.0}
  ASN1_ITEM_get_procname = 'ASN1_ITEM_get'; {introduced 1.1.0}

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 
function  ERR_ASN1_TYPE_get(const a: PASN1_TYPE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TYPE_get_procname);
end;


procedure  ERR_ASN1_TYPE_set(a: PASN1_TYPE; type_: TIdC_INT; value: Pointer);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TYPE_set_procname);
end;


function  ERR_ASN1_TYPE_set1(a: PASN1_TYPE; type_: TIdC_INT; const value: Pointer): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TYPE_set1_procname);
end;


function  ERR_ASN1_TYPE_cmp(const a: PASN1_TYPE; const b: PASN1_TYPE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TYPE_cmp_procname);
end;



function  ERR_ASN1_TYPE_pack_sequence(const it: PASN1_ITEM; s: Pointer; t: PPASN1_TYPE): PASN1_TYPE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TYPE_pack_sequence_procname);
end;

 {introduced 1.1.0}
function  ERR_ASN1_TYPE_unpack_sequence(const it: PASN1_ITEM; const t: PASN1_TYPE): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TYPE_unpack_sequence_procname);
end;

 {introduced 1.1.0}

function  ERR_ASN1_OBJECT_new: PASN1_OBJECT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_OBJECT_new_procname);
end;


procedure  ERR_ASN1_OBJECT_free(a: PASN1_OBJECT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_OBJECT_free_procname);
end;


function  ERR_i2d_ASN1_OBJECT(const a: PASN1_OBJECT; pp: PPByte): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_OBJECT_procname);
end;


function  ERR_d2i_ASN1_OBJECT(a: PPASN1_OBJECT; const pp: PPByte; _length: TIdC_LONG): PASN1_OBJECT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_OBJECT_procname);
end;

function ERR_i2d_ASN1_BIT_STRING(val_in : PASN1_BIT_STRING; der_out : PPIdAnsiChar) : TIdC_long; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_BIT_STRING_procname);
end;

function ERR_d2i_ASN1_BIT_STRING(val_out : PPASN1_BIT_STRING;
  const der_in : PPIdAnsiChar; _length : TIdC_LONG) : PASN1_BIT_STRING; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_BIT_STRING_procname);
end;

  //DECLARE_ASN1_ITEM(ASN1_OBJECT)
  //
  //DEFINE_STACK_OF(ASN1_OBJECT)

function  ERR_ASN1_STRING_new: PASN1_STRING; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_new_procname);
end;


procedure  ERR_ASN1_STRING_free(a: PASN1_STRING); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_free_procname);
end;


procedure  ERR_ASN1_STRING_clear_free(a: PASN1_STRING); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_clear_free_procname);
end;


function  ERR_ASN1_STRING_copy(dst: PASN1_STRING; const _str: PASN1_STRING): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_copy_procname);
end;


function  ERR_ASN1_STRING_dup(const a: PASN1_STRING): PASN1_STRING; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_dup_procname);
end;


function  ERR_ASN1_STRING_type_new(type_: TIdC_INT): PASN1_STRING; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_type_new_procname);
end;


function  ERR_ASN1_STRING_cmp(const a: PASN1_STRING; const b: PASN1_STRING): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_cmp_procname);
end;



  (*
   * Since this is used to store all sorts of things, via macros, for now,
   * make its data void *
   *)
function  ERR_ASN1_STRING_set(_str: PASN1_STRING; const data: Pointer; len: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_set_procname);
end;


procedure  ERR_ASN1_STRING_set0(_str: PASN1_STRING; data: Pointer; len: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_set0_procname);
end;


function  ERR_ASN1_STRING_length(const x: PASN1_STRING): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_length_procname);
end;


procedure  ERR_ASN1_STRING_length_set(x: PASN1_STRING; n: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_length_set_procname);
end;


function  ERR_ASN1_STRING_type(const x: PASN1_STRING): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_type_procname);
end;


function  ERR_ASN1_STRING_get0_data(const x: PASN1_STRING): PByte; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_get0_data_procname);
end;

 {introduced 1.1.0}

  //DECLARE_ASN1_FUNCTIONS(ASN1_BIT_STRING)
function  ERR_ASN1_BIT_STRING_set(a: PASN1_BIT_STRING; d: PByte; _length: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_BIT_STRING_set_procname);
end;


function  ERR_ASN1_BIT_STRING_set_bit(a: PASN1_BIT_STRING; n: TIdC_INT; value: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_BIT_STRING_set_bit_procname);
end;


function  ERR_ASN1_BIT_STRING_get_bit(const a: PASN1_BIT_STRING; n: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_BIT_STRING_get_bit_procname);
end;


function  ERR_ASN1_BIT_STRING_check(const a: PASN1_BIT_STRING;
  const flags: PByte; flags_len: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_BIT_STRING_check_procname);
end;



function  ERR_ASN1_BIT_STRING_name_print(out_: PBIO; bs: PASN1_BIT_STRING; tbl: PBIT_STRING_BITNAME;
  indent: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_BIT_STRING_name_print_procname);
end;


function  ERR_ASN1_BIT_STRING_num_asc(const name: PIdAnsiChar; tbl: PBIT_STRING_BITNAME): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_BIT_STRING_num_asc_procname);
end;


function  ERR_ASN1_BIT_STRING_set_asc(bs: PASN1_BIT_STRING; const name: PIdAnsiChar;
  value: TIdC_INT; tbl: PBIT_STRING_BITNAME): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_BIT_STRING_set_asc_procname);
end;

function ERR_ASN1_BIT_STRING_get_length(abs_:  PASN1_BIT_STRING; _length : PIdC_SIZET; unused_bits : PIdC_INT) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_BIT_STRING_get_length_procname);
end;

function ERR_ASN1_BIT_STRING_set1(abs_:  PASN1_BIT_STRING; data : PByte; _length : TIdC_SIZET; unused_bits : TIdC_INT) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_BIT_STRING_set1_procname);
end;


function  ERR_ASN1_INTEGER_new: PASN1_INTEGER; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_INTEGER_new_procname);
end;


procedure  ERR_ASN1_INTEGER_free(a: PASN1_INTEGER); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_INTEGER_free_procname);
end;


function  ERR_d2i_ASN1_INTEGER(a: PPASN1_INTEGER; const in_: PPByte; len: TIdC_Long): PASN1_INTEGER; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_INTEGER_procname);
end;


function  ERR_i2d_ASN1_INTEGER(a: PASN1_INTEGER; out_: PPByte): TIdC_Int; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_INTEGER_procname);
end;



function  ERR_d2i_ASN1_UINTEGER(a: PPASN1_INTEGER; const pp: PPByte; _length: TIdC_LONG): PASN1_INTEGER; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_UINTEGER_procname);
end;


function  ERR_ASN1_INTEGER_dup(const x: PASN1_INTEGER): PASN1_INTEGER; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_INTEGER_dup_procname);
end;


function  ERR_ASN1_INTEGER_cmp(const x: PASN1_INTEGER; const y: PASN1_INTEGER): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_INTEGER_cmp_procname);
end;



  // DECLARE_ASN1_FUNCTIONS(ASN1_ENUMERATED)

function  ERR_ASN1_UTCTIME_check(const a: PASN1_UTCTIME): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_UTCTIME_check_procname);
end;


function  ERR_ASN1_UTCTIME_set(s: PASN1_UTCTIME; t: TIdC_TIMET): PASN1_UTCTIME; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_UTCTIME_set_procname);
end;


function  ERR_ASN1_UTCTIME_adj(s: PASN1_UTCTIME; t: TIdC_TIMET; offset_day: TIdC_INT;
  offset_sec: TIdC_LONG): PASN1_UTCTIME; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_UTCTIME_adj_procname);
end;


function  ERR_ASN1_UTCTIME_set_string(s: PASN1_UTCTIME; const _str: PIdAnsiChar): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_UTCTIME_set_string_procname);
end;


function  ERR_ASN1_UTCTIME_cmp_time_t(const s: PASN1_UTCTIME; t: TIdC_TIMET): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_UTCTIME_cmp_time_t_procname);
end;



function  ERR_ASN1_GENERALIZEDTIME_check(const a: PASN1_GENERALIZEDTIME): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_GENERALIZEDTIME_check_procname);
end;


function  ERR_ASN1_GENERALIZEDTIME_set(s: PASN1_GENERALIZEDTIME; t: TIdC_TIMET): PASN1_GENERALIZEDTIME; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_GENERALIZEDTIME_set_procname);
end;


function  ERR_ASN1_GENERALIZEDTIME_adj(s: PASN1_GENERALIZEDTIME; t: TIdC_TIMET;
  offset_day: TIdC_INT; offset_sec: TIdC_LONG): PASN1_GENERALIZEDTIME; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_GENERALIZEDTIME_adj_procname);
end;


function  ERR_ASN1_GENERALIZEDTIME_set_string(s: pASN1_GENERALIZEDTIME; const _str: PIdAnsiChar): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_GENERALIZEDTIME_set_string_procname);
end;



function  ERR_ASN1_TIME_diff(pday: PIdC_INT; psec: PIdC_INT; const from: PASN1_TIME;
  const to_: PASN1_TIME): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_diff_procname);
end;



  // DECLARE_ASN1_FUNCTIONS(ASN1_OCTET_STRING)
function  ERR_ASN1_OCTET_STRING_dup(const a: PASN1_OCTET_STRING): PASN1_OCTET_STRING; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_OCTET_STRING_dup_procname);
end;


function  ERR_ASN1_OCTET_STRING_cmp(const a: PASN1_OCTET_STRING; const b: PASN1_OCTET_STRING): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_OCTET_STRING_cmp_procname);
end;


function  ERR_ASN1_OCTET_STRING_set(_str: PASN1_OCTET_STRING; const data: PByte; len: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_OCTET_STRING_set_procname);
end;

function ERR_d2i_ASN1_OCTET_STRING(val_out : PPASN1_OCTET_STRING; der_in : PPIdAnsiChar;
  _length : TIdC_LONG) : PASN1_OCTET_STRING; cdecl;
begin
   ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_OCTET_STRING_procname);
end;

function ERR_i2d_ASN1_OCTET_STRING(val_in : PASN1_OCTET_STRING; der_out : PPIdAnsiChar) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_OCTET_STRING_procname);
end;

procedure ERR_ASN1_OCTET_STRING_free (a : PASN1_OCTET_STRING); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_OCTET_STRING_free_procname);
end;

  //DECLARE_ASN1_FUNCTIONS(ASN1_VISIBLESTRING)
  //DECLARE_ASN1_FUNCTIONS(ASN1_UNIVERSALSTRING)
  //DECLARE_ASN1_FUNCTIONS(ASN1_UTF8STRING)
  //DECLARE_ASN1_FUNCTIONS(ASN1_NULL)
  //DECLARE_ASN1_FUNCTIONS(ASN1_BMPSTRING)

function  ERR_UTF8_getc(const _str: PByte; len: TIdC_INT; _val: PIdC_ULONG): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UTF8_getc_procname);
end;


function  ERR_UTF8_putc(_str: PIdAnsiChar; len: TIdC_INT; value: TIdC_ULONG): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UTF8_putc_procname);
end;



  //DECLARE_ASN1_FUNCTIONS_name(ASN1_STRING, ASN1_PRINTABLE)
  //
  //DECLARE_ASN1_FUNCTIONS_name(ASN1_STRING, DIRECTORYSTRING)
  //DECLARE_ASN1_FUNCTIONS_name(ASN1_STRING, DISPLAYTEXT)
  //DECLARE_ASN1_FUNCTIONS(ASN1_PRINTABLESTRING)
  //DECLARE_ASN1_FUNCTIONS(ASN1_T61STRING)
  //DECLARE_ASN1_FUNCTIONS(ASN1_IA5STRING)
  //DECLARE_ASN1_FUNCTIONS(ASN1_GENERALSTRING)

function  ERR_ASN1_UTCTIME_new: PASN1_UTCTIME; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_UTCTIME_new_procname);
end;


procedure  ERR_ASN1_UTCTIME_free(a: PASN1_UTCTIME); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_UTCTIME_free_procname);
end;


function  ERR_d2i_ASN1_UTCTIME(a: PPASN1_UTCTIME; const in_: PPByte; len: TIdC_LONG): PASN1_UTCTIME; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_UTCTIME_procname);
end;


function  ERR_i2d_ASN1_UTCTIME(a: PASN1_UTCTIME; out_: PPByte): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_UTCTIME_procname);
end;



function  ERR_ASN1_GENERALIZEDTIME_new: PASN1_GENERALIZEDTIME; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_GENERALIZEDTIME_new_procname);
end;


procedure  ERR_ASN1_GENERALIZEDTIME_free(a: PASN1_GENERALIZEDTIME); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_GENERALIZEDTIME_free_procname);
end;


function  ERR_d2i_ASN1_GENERALIZEDTIME(a: PPASN1_GENERALIZEDTIME;
  const in_: PPByte; len: TIdC_LONG): PASN1_GENERALIZEDTIME; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_GENERALIZEDTIME_procname);
end;


function  ERR_i2d_ASN1_GENERALIZEDTIME(a: PASN1_GENERALIZEDTIME; out_: PPByte): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_GENERALIZEDTIME_procname);
end;



function  ERR_ASN1_TIME_new: PASN1_TIME; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_new_procname);
end;


procedure  ERR_ASN1_TIME_free(a: PASN1_TIME); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_free_procname);
end;


function  ERR_d2i_ASN1_TIME(a: PPASN1_TIME; const in_: PPByte; len: TIdC_LONG): PASN1_TIME; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASN1_TIME_procname);
end;


function  ERR_i2d_ASN1_TIME(a: PASN1_TIME; out_: PPByte): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_TIME_procname);
end;



  // DECLARE_ASN1_ITEM(ASN1_OCTET_STRING_NDEF)

function  ERR_ASN1_TIME_set(s: PASN1_TIME; t: TIdC_TIMET): PASN1_TIME; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_set_procname);
end;


function  ERR_ASN1_TIME_adj(s: PASN1_TIME; t: TIdC_TIMET; offset_day: TIdC_INT;
  offset_sec: TIdC_LONG): PASN1_TIME; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_adj_procname);
end;


function  ERR_ASN1_TIME_check(const t: PASN1_TIME): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_check_procname);
end;


function  ERR_ASN1_TIME_to_generalizedtime(const t: PASN1_TIME;
  out_: PPASN1_GENERALIZEDTIME): PASN1_GENERALIZEDTIME; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_to_generalizedtime_procname);
end;


function  ERR_ASN1_TIME_set_string(s: PASN1_TIME; const _str: PIdAnsiChar): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_set_string_procname);
end;


function  ERR_ASN1_TIME_set_string_X509(s: PASN1_TIME; const _str: PIdAnsiChar): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_set_string_X509_procname);
end;

 {introduced 1.1.0}
function  ERR_ASN1_TIME_to_tm(const s: PASN1_TIME; tm: PIdC_TM): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_to_tm_procname);
end;

 {introduced 1.1.0}
function  ERR_ASN1_TIME_normalize(s: PASN1_TIME): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_normalize_procname);
end;

 {introduced 1.1.0}
function  ERR_ASN1_TIME_cmp_time_t(const s: PASN1_TIME; t: TIdC_TIMET): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_cmp_time_t_procname);
end;

 {introduced 1.1.0}
function  ERR_ASN1_TIME_compare(const a: PASN1_TIME; const b: PASN1_TIME): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_compare_procname);
end;

 {introduced 1.1.0}

function  ERR_i2a_ASN1_INTEGER(bp: PBIO; const a: PASN1_INTEGER): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2a_ASN1_INTEGER_procname);
end;


function  ERR_a2i_ASN1_INTEGER(bp: PBIO; bs: PASN1_INTEGER; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(a2i_ASN1_INTEGER_procname);
end;


function  ERR_i2a_ASN1_ENUMERATED(bp: PBIO; const a: PASN1_ENUMERATED): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2a_ASN1_ENUMERATED_procname);
end;


function  ERR_a2i_ASN1_ENUMERATED(bp: PBIO; bs: PASN1_ENUMERATED; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(a2i_ASN1_ENUMERATED_procname);
end;


function  ERR_i2a_ASN1_OBJECT(bp: PBIO; const a: PASN1_OBJECT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2a_ASN1_OBJECT_procname);
end;


function  ERR_a2i_ASN1_STRING(bp: PBIO; bs: PASN1_STRING; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(a2i_ASN1_STRING_procname);
end;


function  ERR_i2a_ASN1_STRING(bp: PBIO; const a: PASN1_STRING; type_: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2a_ASN1_STRING_procname);
end;


function  ERR_i2t_ASN1_OBJECT(buf: PIdAnsiChar; buf_len: TIdC_INT; const a: PASN1_OBJECT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2t_ASN1_OBJECT_procname);
end;



function  ERR_a2d_ASN1_OBJECT(out_: PByte; olen: TIdC_INT; const buf: PIdAnsiChar; num: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(a2d_ASN1_OBJECT_procname);
end;


function  ERR_ASN1_OBJECT_create(nid: TIdC_INT; data: PByte; len: TIdC_INT;
  const sn: PIdAnsiChar; const _ln: PIdAnsiChar): PASN1_OBJECT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_OBJECT_create_procname);
end;


function  ERR_ASN1_INTEGER_get_int64(pr: PIdC_Int64; const a: PASN1_INTEGER): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_INTEGER_get_int64_procname);
end;

 {introduced 1.1.0}
function  ERR_ASN1_INTEGER_set_int64(a: PASN1_INTEGER; r: TIdC_Int64): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_INTEGER_set_int64_procname);
end;

 {introduced 1.1.0}
function  ERR_ASN1_INTEGER_get_uint64(pr: PIdC_UInt64; const a: PASN1_INTEGER): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_INTEGER_get_uint64_procname);
end;

 {introduced 1.1.0}
function  ERR_ASN1_INTEGER_set_uint64(a: PASN1_INTEGER; r: TIdC_UInt64): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_INTEGER_set_uint64_procname);
end;

 {introduced 1.1.0}

function  ERR_ASN1_INTEGER_set(a: PASN1_INTEGER; v: TIdC_LONG): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_INTEGER_set_procname);
end;


function  ERR_ASN1_INTEGER_get(const a: PASN1_INTEGER): TIdC_LONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_INTEGER_get_procname);
end;


function  ERR_BN_to_ASN1_INTEGER(const bn: PBIGNUM; ai: PASN1_INTEGER): PASN1_INTEGER; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BN_to_ASN1_INTEGER_procname);
end;


function  ERR_ASN1_INTEGER_to_BN(const ai: PASN1_INTEGER; bn: PBIGNUM): PBIGNUM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_INTEGER_to_BN_procname);
end;



function  ERR_ASN1_ENUMERATED_get_int64(pr: PIdC_Int64; const a: PASN1_ENUMERATED): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_ENUMERATED_get_int64_procname);
end;

 {introduced 1.1.0}
function  ERR_ASN1_ENUMERATED_set_int64(a: PASN1_ENUMERATED; r: TIdC_Int64): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_ENUMERATED_set_int64_procname);
end;

 {introduced 1.1.0}


function  ERR_ASN1_ENUMERATED_set(a: PASN1_ENUMERATED; v: TIdC_LONG): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_ENUMERATED_set_procname);
end;


function  ERR_ASN1_ENUMERATED_get(const a: PASN1_ENUMERATED): TIdC_LONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_ENUMERATED_get_procname);
end;


function  ERR_BN_to_ASN1_ENUMERATED(const bn: PBIGNUM; ai: PASN1_ENUMERATED): PASN1_ENUMERATED; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BN_to_ASN1_ENUMERATED_procname);
end;


function  ERR_ASN1_ENUMERATED_to_BN(const ai: PASN1_ENUMERATED; bn: PBIGNUM): PBIGNUM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_ENUMERATED_to_BN_procname);
end;



  (* General *)
  (* given a string, return the correct type, max is the maximum length *)
function  ERR_ASN1_PRINTABLE_type(const s: PByte; max: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PRINTABLE_type_procname);
end;



function  ERR_ASN1_tag2bit(tag: TIdC_INT): TIdC_ULONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_tag2bit_procname);
end;



  (* SPECIALS *)
function  ERR_ASN1_get_object(const pp: PPByte; plength: PIdC_LONG; ptag: PIdC_INT;
  pclass: PIdC_INT; omax: TIdC_LONG): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_get_object_procname);
end;


function  ERR_ASN1_check_infinite_end(p: PPByte; len: TIdC_LONG): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_check_infinite_end_procname);
end;


function  ERR_ASN1_const_check_infinite_end(const p: PPByte; len: TIdC_LONG): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_const_check_infinite_end_procname);
end;


procedure  ERR_ASN1_put_object(pp: PPByte; constructed: TIdC_INT; _length: TIdC_INT;
  tag: TIdC_INT; xclass: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_put_object_procname);
end;


function  ERR_ASN1_put_eoc(pp: PPByte): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_put_eoc_procname);
end;


function  ERR_ASN1_object_size(constructed: TIdC_INT; _length: TIdC_INT; tag: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_object_size_procname);
end;



  (* Used to implement other functions *)
  //void *ASN1_dup(i2d_of_void *i2d, d2i_of_void *d2i, void *x);
  //
  //# define ASN1_dup_of(type,i2d,d2i,x) \
  //    ((type*)ASN1_dup(CHECKED_I2D_OF(type, i2d), \
  //                     CHECKED_D2I_OF(type, d2i), \
  //                     CHECKED_PTR_OF(type, x)))
  //
  //# define ASN1_dup_of_const(type,i2d,d2i,x) \
  //    ((type*)ASN1_dup(CHECKED_I2D_OF(const type, i2d), \
  //                     CHECKED_D2I_OF(type, d2i), \
  //                     CHECKED_PTR_OF(const type, x)))
  //
function  ERR_ASN1_item_dup(const it: PASN1_ITEM; x: Pointer): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_dup_procname);
end;



    (* ASN1 alloc/free macros for when a type is only used internally *)

  //# define M_ASN1_new_of(type) (type *)ASN1_item_new(ASN1_ITEM_rptr(type))
  //# define M_ASN1_free_of(x, type) \
  //                ASN1_item_free(CHECKED_PTR_OF(type, x), ASN1_ITEM_rptr(type))
  //
  //# ifndef OPENSSL_NO_STDIO
  //void *ASN1_d2i_fp(void *(*xnew) (void), d2i_of_void *d2i, FILE *in, void **x);

  //#  define ASN1_d2i_fp_of(type,xnew,d2i,in,x) \
  //    ((type*)ASN1_d2i_fp(CHECKED_NEW_OF(type, xnew), \
  //                        CHECKED_D2I_OF(type, d2i), \
  //                        in, \
  //                        CHECKED_PPTR_OF(type, x)))
  //
  //function ASN1_item_d2i_fp(const it: PASN1_ITEM; in_: PFILE; x: Pointer): Pointer;
  //function ASN1_i2d_fp(i2d: Pi2d_of_void; out_: PFILE; x: Pointer): TIdC_INT;
  //
  //#  define ASN1_i2d_fp_of(type,i2d,out,x) \
  //    (ASN1_i2d_fp(CHECKED_I2D_OF(type, i2d), \
  //                 out, \
  //                 CHECKED_PTR_OF(type, x)))
  //
  //#  define ASN1_i2d_fp_of_const(type,i2d,out,x) \
  //    (ASN1_i2d_fp(CHECKED_I2D_OF(const type, i2d), \
  //                 out, \
  //                 CHECKED_PTR_OF(const type, x)))
  //
  //function ASN1_item_i2d_fp(const it: PASN1_ITEM; out_: PFILE; x: Pointer): TIdC_INT;
  //function ASN1_STRING_print_ex_fp(&fp: PFILE; const _str: PASN1_STRING; flags: TIdC_ULONG): TIdC_INT;
  //# endif

function  ERR_ASN1_STRING_to_UTF8(out_: PPByte; const in_: PASN1_STRING): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_to_UTF8_procname);
end;

function ERR_ASN1_d2i_bio(const it: PASN1_ITEM; in_: PBIO; x: Pointer): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_d2i_bio_procname);
end;

  //void *ASN1_d2i_bio(void *(*xnew) (void), d2i_of_void *d2i, BIO *in, void **x);

  //#  define ASN1_d2i_bio_of(type,xnew,d2i,in,x) \
  //    ((type*)ASN1_d2i_bio( CHECKED_NEW_OF(type, xnew), \
  //                          CHECKED_D2I_OF(type, d2i), \
  //                          in, \
  //                          CHECKED_PPTR_OF(type, x)))

function  ERR_ASN1_item_d2i_bio(const it: PASN1_ITEM; in_: PBIO; x: Pointer): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_d2i_bio_procname);
end;


function  ERR_ASN1_i2d_bio(i2d: i2d_of_void; out_: PBIO; x: PByte): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_i2d_bio_procname);
end;



  //#  define ASN1_i2d_bio_of(type,i2d,out,x) \
  //    (ASN1_i2d_bio(CHECKED_I2D_OF(type, i2d), \
  //                  out, \
  //                  CHECKED_PTR_OF(type, x)))
  //
  //#  define ASN1_i2d_bio_of_const(type,i2d,out,x) \
  //    (ASN1_i2d_bio(CHECKED_I2D_OF(const type, i2d), \
  //                  out, \
  //                  CHECKED_PTR_OF(const type, x)))

function  ERR_ASN1_item_i2d_bio(const it: PASN1_ITEM; out_: PBIO; x: Pointer): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_i2d_bio_procname);
end;


function  ERR_ASN1_UTCTIME_print(fp: PBIO; const a: PASN1_UTCTIME): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_UTCTIME_print_procname);
end;


function  ERR_ASN1_GENERALIZEDTIME_print(fp: PBIO; const a: PASN1_GENERALIZEDTIME): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_GENERALIZEDTIME_print_procname);
end;


function  ERR_ASN1_TIME_print(fp: PBIO; const a: PASN1_TIME): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TIME_print_procname);
end;


function  ERR_ASN1_STRING_print(bp: PBIO; const v: PASN1_STRING): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_print_procname);
end;


function  ERR_ASN1_STRING_print_ex(out_: PBIO; const _str: PASN1_STRING; flags: TIdC_ULONG): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_print_ex_procname);
end;


function  ERR_ASN1_buf_print(bp: PBIO; const buf: PByte; buflen: TIdC_SIZET; off: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_buf_print_procname);
end;

 {introduced 1.1.0}
function  ERR_ASN1_bn_print(bp: PBIO; const number: PIdAnsiChar; const num: PBIGNUM;
  buf: PByte; off: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_bn_print_procname);
end;


function  ERR_ASN1_parse(bp: PBIO; const pp: PByte; len: TIdC_LONG; indent: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_parse_procname);
end;


function  ERR_ASN1_parse_dump(bp: PPBIO; const pp: PByte; len: TIdC_LONG;
  indent: TIdC_INT; dump: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_parse_dump_procname);
end;


function  ERR_ASN1_tag2str(tag: TIdC_INT): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_tag2str_procname);
end;



  (* Used to load and write Netscape format cert *)

function  ERR_ASN1_UNIVERSALSTRING_to_string(s: PASN1_UNIVERSALSTRING): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_UNIVERSALSTRING_to_string_procname);
end;



function  ERR_ASN1_TYPE_set_octetstring(a: PASN1_TYPE; data: PByte; len: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TYPE_set_octetstring_procname);
end;


function  ERR_ASN1_TYPE_get_octetstring(const a: PASN1_TYPE; data: PByte; max_len: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TYPE_get_octetstring_procname);
end;


function  ERR_ASN1_TYPE_set_int_octetstring(a: PASN1_TYPE; num: TIdC_LONG;
  data: PByte; len: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TYPE_set_int_octetstring_procname);
end;


function  ERR_ASN1_TYPE_get_int_octetstring(const a: PASN1_TYPE; num: PIdC_LONG;
  data: PByte; max_len: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TYPE_get_int_octetstring_procname);
end;



function  ERR_ASN1_item_unpack(const oct: PASN1_STRING; const it: PASN1_ITEM): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_unpack_procname);
end;



function  ERR_ASN1_item_pack(obj: Pointer; const it: PASN1_ITEM; oct: PPASN1_OCTET_STRING): PASN1_STRING; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_pack_procname);
end;



procedure  ERR_ASN1_STRING_set_default_mask(mask: TIdC_ULONG); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_set_default_mask_procname);
end;


function  ERR_ASN1_STRING_set_default_mask_asc(const p: PIdAnsiChar): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_set_default_mask_asc_procname);
end;


function  ERR_ASN1_STRING_get_default_mask: TIdC_ULONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_get_default_mask_procname);
end;


function  ERR_ASN1_mbstring_copy(out_: PPASN1_STRING; const in_: PByte; len: TIdC_INT;
  inform: TIdC_INT; mask: TIdC_ULONG): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_mbstring_copy_procname);
end;


function  ERR_ASN1_mbstring_ncopy(out_: PPASN1_STRING; const in_: PByte; len: TIdC_INT;
  inform: TIdC_INT; mask: TIdC_ULONG; minsize: TIdC_LONG; maxsize: TIdC_LONG): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_mbstring_ncopy_procname);
end;



function  ERR_ASN1_STRING_set_by_NID(out_: PPASN1_STRING; const in_: PByte; inlen: TIdC_INT;
  inform: TIdC_INT; nid: TIdC_INT): PASN1_STRING; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_set_by_NID_procname);
end;


function  ERR_ASN1_STRING_TABLE_get(nid: TIdC_INT): PASN1_STRING_TABLE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_TABLE_get_procname);
end;


function  ERR_ASN1_STRING_TABLE_add(v1: TIdC_INT; v2: TIdC_LONG; v3: TIdC_LONG;
  v4: TIdC_ULONG; v5: TIdC_ULONG): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_TABLE_add_procname);
end;


procedure  ERR_ASN1_STRING_TABLE_cleanup; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_STRING_TABLE_cleanup_procname);
end;



  (* ASN1 template functions *)

  (* Old API compatible functions *)
function  ERR_ASN1_item_new(const it: PASN1_ITEM): PASN1_VALUE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_new_procname);
end;


procedure  ERR_ASN1_item_free(_val: PASN1_VALUE; const it: PASN1_ITEM); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_free_procname);
end;


function  ERR_ASN1_item_d2i(_val: PPASN1_VALUE; const in_: PPByte; len: TIdC_LONG;
  const it: PASN1_ITEM): PASN1_VALUE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_d2i_procname);
end;


function  ERR_ASN1_item_i2d(_val: PASN1_VALUE; out_: PPByte; const it: PASN1_ITEM): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_i2d_procname);
end;


function  ERR_ASN1_item_ndef_i2d(_val: PASN1_VALUE; out_: PPByte; const it: PASN1_ITEM): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_ndef_i2d_procname);
end;



procedure  ERR_ASN1_add_oid_module; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_add_oid_module_procname);
end;


procedure  ERR_ASN1_add_stable_module; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_add_stable_module_procname);
end;

 {introduced 1.1.0}

function  ERR_ASN1_generate_nconf(const _str: PIdAnsiChar; nconf: PCONF): PASN1_TYPE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_generate_nconf_procname);
end;


function  ERR_ASN1_generate_v3(const _str: PIdAnsiChar; cnf: PX509V3_CTX): PASN1_TYPE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_generate_v3_procname);
end;


function  ERR_ASN1_str2mask(const _str: PByte; pmask: PIdC_ULONG): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_str2mask_procname);
end;

 {introduced 1.1.0}

function  ERR_ASN1_item_print(out_: PBIO; ifld: PASN1_VALUE; indent: TIdC_INT;
  const it: PASN1_ITEM; const pctx: PASN1_PCTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_print_procname);
end;


function  ERR_ASN1_PCTX_new: PASN1_PCTX; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PCTX_new_procname);
end;


procedure  ERR_ASN1_PCTX_free(p: PASN1_PCTX); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PCTX_free_procname);
end;


function  ERR_ASN1_PCTX_get_flags(const p: PASN1_PCTX): TIdC_ULONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PCTX_get_flags_procname);
end;


procedure  ERR_ASN1_PCTX_set_flags(p: PASN1_PCTX; flags: TIdC_ULONG); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PCTX_set_flags_procname);
end;


function  ERR_ASN1_PCTX_get_nm_flags(const p: PASN1_PCTX): TIdC_ULONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PCTX_get_nm_flags_procname);
end;


procedure  ERR_ASN1_PCTX_set_nm_flags(p: PASN1_PCTX; flags: TIdC_ULONG); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PCTX_set_nm_flags_procname);
end;


function  ERR_ASN1_PCTX_get_cert_flags(const p: PASN1_PCTX): TIdC_ULONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PCTX_get_cert_flags_procname);
end;


procedure  ERR_ASN1_PCTX_set_cert_flags(p: PASN1_PCTX; flags: TIdC_ULONG); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PCTX_set_cert_flags_procname);
end;


function  ERR_ASN1_PCTX_get_oid_flags(const p: PASN1_PCTX): TIdC_ULONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PCTX_get_oid_flags_procname);
end;


procedure  ERR_ASN1_PCTX_set_oid_flags(p: PASN1_PCTX; flags: TIdC_ULONG); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PCTX_set_oid_flags_procname);
end;


function  ERR_ASN1_PCTX_get_str_flags(const p: PASN1_PCTX): TIdC_ULONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PCTX_get_str_flags_procname);
end;


procedure  ERR_ASN1_PCTX_set_str_flags(p: PASN1_PCTX; flags: TIdC_ULONG); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_PCTX_set_str_flags_procname);
end;



  //ASN1_SCTX *ASN1_SCTX_new(int (*scan_cb) (ASN1_SCTX *ctx));
procedure  ERR_ASN1_SCTX_free(p: PASN1_SCTX); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_SCTX_free_procname);
end;

 {introduced 1.1.0}
function  ERR_ASN1_SCTX_get_item(p: PASN1_SCTX): PASN1_ITEM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_SCTX_get_item_procname);
end;

 {introduced 1.1.0}
function  ERR_ASN1_SCTX_get_template(p: PASN1_SCTX): PASN1_TEMPLATE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_SCTX_get_template_procname);
end;

 {introduced 1.1.0}
function  ERR_ASN1_SCTX_get_flags(p: PASN1_SCTX): TIdC_ULONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_SCTX_get_flags_procname);
end;

 {introduced 1.1.0}
procedure  ERR_ASN1_SCTX_set_app_data(p: PASN1_SCTX; data: Pointer); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_SCTX_set_app_data_procname);
end;

 {introduced 1.1.0}
function  ERR_ASN1_SCTX_get_app_data(p: PASN1_SCTX): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_SCTX_get_app_data_procname);
end;

 {introduced 1.1.0}

function  ERR_BIO_f_asn1: PBIO_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_f_asn1_procname);
end;



function  ERR_BIO_new_NDEF(out_: PBIO; _val: PASN1_VALUE; const it: PASN1_ITEM): PBIO; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_new_NDEF_procname);
end;



function  ERR_i2d_ASN1_bio_stream(out_: PBIO; _val: PASN1_VALUE; in_: PBIO; flags: TIdC_INT;
  const it: PASN1_ITEM): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASN1_bio_stream_procname);
end;


function  ERR_PEM_write_bio_ASN1_stream(out_: PBIO; _val: PASN1_VALUE; in_: PBIO; flags: TIdC_INT;
  const hdr: PIdAnsiChar; const it: PASN1_ITEM): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_ASN1_stream_procname);
end;


  //function SMIME_write_ASN1(bio: PBIO; _val: PASN1_VALUE; data: PBIO; flags: TIdC_INT;
  //                     ctype_nid: TIdC_INT; econt_nid: TIdC_INT;
  //                     STACK_OF(X509_ALGOR) *mdalgs, const ASN1_ITEM *it): TIdC_INT;
function  ERR_SMIME_read_ASN1(bio: PBIO; bcont: PPBIO; const it: PASN1_ITEM): PASN1_VALUE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SMIME_read_ASN1_procname);
end;


function  ERR_SMIME_crlf_copy(in_: PBIO; out_: PBIO; flags: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SMIME_crlf_copy_procname);
end;


function  ERR_SMIME_text(in_: PBIO; out_: PBIO): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SMIME_text_procname);
end;



function  ERR_ASN1_ITEM_lookup(const name: PIdAnsiChar): PASN1_ITEM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_ITEM_lookup_procname);
end;

 {introduced 1.1.0}
function  ERR_ASN1_ITEM_get(i: TIdC_SIZET): PASN1_ITEM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_ITEM_get_procname);
end;

 {introduced 1.1.0}

  {$I TaurusTLSNoRetValOn.inc} 

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

  d2i_ASN1_BIT_STRING := LoadLibFunction(ADllHandle, d2i_ASN1_BIT_STRING_procname);
  FuncLoadError := not assigned(d2i_ASN1_BIT_STRING);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ASN1_OBJECT_allownil)}
    d2i_ASN1_BIT_STRING := ERR_d2i_ASN1_BIT_STRING;
    {$ifend}
    {$if declared(d2i_ASN1_OBJECT_introduced)}
    if LibVersion < d2i_ASN1_BIT_STRING_introduced then
    begin
      {$if declared(FC_d2i_ASN1_OBJECT)}
      d2i_ASN1_OBJECT := FC_d2i_ASN1_OBJECT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ASN1_BIT_STRING_removed)}
    if d2i_ASN1_BIT_STRING_removed <= LibVersion then
    begin
      {$if declared(_d2i_ASN1_OBJECT)}
      d2i_ASN1_BIT_STRING := d2i_ASN1_BIT_STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ASN1_OBJECT_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ASN1_OBJECT');
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
      d2i_ASN1_OBJECT := _d2i_ASN1_OBJECT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ASN1_BIT_STRING_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ASN1_BIT_STRING');
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

 {introduced 1.1.0}
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

  ASN1_BIT_STRING_get_length :=  LoadLibFunction(ADllHandle, ASN1_BIT_STRING_get_length_procname);
  FuncLoadError := not assigned(ASN1_BIT_STRING_get_length);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_BIT_STRING_get_length_allownil)}
    ASN1_BIT_STRING_get_length := ERR_ASN1_BIT_STRING_get_length;
    {$ifend}
    {$if declared(ASN1_BIT_STRING_get_length_introduced)}
    if LibVersion < ASN1_BIT_STRING_get_length_introduced then
    begin
      {$if declared(FC_ASN1_BIT_STRING_get_length)}
      ASN1_BIT_STRING_get_length := FC_ASN1_BIT_STRING_get_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_BIT_STRING_get_length_removed)}
    if ASN1_BIT_STRING_get_length_removed <= LibVersion then
    begin
      {$if declared(_ASN1_BIT_STRING_get_length)}
      ASN1_BIT_STRING_get_length := _ASN1_BIT_STRING_get_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_BIT_STRING_get_length_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_BIT_STRING_get_length');
    {$ifend}
  end;


  ASN1_BIT_STRING_set1 := LoadLibFunction(ADllHandle, ASN1_BIT_STRING_set1_procname);
  FuncLoadError := not assigned(ASN1_BIT_STRING_set1);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_BIT_STRING_set1_allownil)}
    ASN1_BIT_STRING_set1 := ERR_ASN1_BIT_STRING_set1;
    {$ifend}
    {$if declared(ASN1_BIT_STRING_set1_introduced)}
    if LibVersion < ASN1_BIT_STRING_set1_introduced then
    begin
      {$if declared(FC_ASN1_BIT_STRING_set1)}
      ASN1_BIT_STRING_set1 := FC_ASN1_BIT_STRING_set1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_BIT_STRING_set1_removed)}
    if ASN1_BIT_STRING_set1_removed <= LibVersion then
    begin
      {$if declared(_ASN1_BIT_STRING_set1)}
      ASN1_BIT_STRING_set1 := _ASN1_BIT_STRING_set1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_BIT_STRING_set1_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_BIT_STRING_set1');
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
      {$if declared(d2i_ASN1_OCTET_STRING)}
      d2i_ASN1_OCTET_STRING := FC_d2i_ASN1_OCTET_STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ASN1_OCTET_STRING_removed)}
    if UTF8_getc_removed <= LibVersion then
    begin
      {$if declared(_d2i_ASN1_OCTET_STRING)}
      d2i_ASN1_OCTET_STRING := d2i_ASN1_OCTET_STRING;
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
      {$if declared(i2d_ASN1_OCTET_STRING)}
      i2d_ASN1_OCTET_STRING := FC_i2d_ASN1_OCTET_STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ASN1_OCTET_STRING_removed)}
    if UTF8_getc_removed <= LibVersion then
    begin
      {$if declared(_i2d_ASN1_OCTET_STRING)}
      i2d_ASN1_OCTET_STRING := i2d_ASN1_OCTET_STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ASN1_OCTET_STRING_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ASN1_OCTET_STRING');
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
      {$if declared(ASN1_OCTET_STRING_free)}
      i2d_ASN1_OCTET_STRING := FC_ASN1_OCTET_STRING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_OCTET_STRING_free_removed)}
    if UTF8_getc_removed <= LibVersion then
    begin
      {$if declared(_ASN1_OCTET_STRING_free)}
      ASN1_OCTET_STRING_free := ASN1_OCTET_STRING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_OCTET_STRING_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_OCTET_STRING_free');
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

  ASN1_d2i_bio  := LoadLibFunction(ADllHandle, ASN1_d2i_bio_procname);
  FuncLoadError := not assigned(ASN1_d2i_bio);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_d2i_bio_allownil)}
    ASN1_item_d2i_bio := ERR_ASN1_d2i_bio;
    {$ifend}
    {$if declared(ASN1_d2i_bio_introduced)}
    if LibVersion < ASN1_d2i_bio_introduced then
    begin
      {$if declared(FC_ASN1_d2i_bio)}
      ASN1_item_d2i_bio := FC_ASN1_d2i_bio;
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
      AFailed.Add('ASN1_d2i_bio');
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

  {stack of macros}
  //ensure that the stack of functions ALWAYS load before they are assigned
  //through typecast procedureal pointers.
  LoadStackFunctions(ADllHandle,libVersion,AFailed);
  //Disable PAL warnings for Bad Typecast
  sk_ASN1_OBJECT_new :=  Tsk_ASN1_OBJECT_new(sk_new); //PALOFF
  sk_ASN1_OBJECT_new_null := Tsk_ASN1_OBJECT_new_null(sk_new_null);  //PALOFF
  sk_ASN1_OBJECT_free := Tsk_ASN1_OBJECT_free(sk_free);  //PALOFF
  sk_ASN1_OBJECT_num := Tsk_ASN1_OBJECT_num(sk_num);  //PALOFF
  sk_ASN1_OBJECT_value := Tsk_ASN1_OBJECT_value(sk_value); //PALOFF
  sk_ASN1_OBJECT_push := Tsk_ASN1_OBJECT_push(sk_push);  //PALOFF
  sk_ASN1_OBJECT_dup := Tsk_ASN1_OBJECT_dup(sk_dup);  //PALOFF
  sk_ASN1_OBJECT_find := Tsk_ASN1_OBJECT_find(sk_find); //PALOFF
  sk_ASN1_OBJECT_pop_free := Tsk_ASN1_OBJECT_pop_free(sk_pop_free); //PALOFF

   sk_ASN1_INTEGER_new := Tsk_ASN1_INTEGER_new(sk_new); //PALOFF
  sk_ASN1_INTEGER_new_null := Tsk_ASN1_INTEGER_new_null(sk_new_null); //PALOFF
  sk_ASN1_INTEGER_free := Tsk_ASN1_INTEGER_free(sk_free); //PALOFF
  sk_ASN1_INTEGER_num := Tsk_ASN1_INTEGER_num(sk_num); //PALOFF
  sk_ASN1_INTEGER_value := Tsk_ASN1_INTEGER_value(sk_value);  //PALOFF
  sk_ASN1_INTEGER_push := Tsk_ASN1_INTEGER_push(sk_push);  //PALOFF
  sk_ASN1_INTEGER_dup := Tsk_ASN1_INTEGER_dup(sk_dup);  //PALOFF
  sk_ASN1_INTEGER_find := Tsk_ASN1_INTEGER_find(sk_find);  //PALOFF
  sk_ASN1_INTEGER_pop_free := Tsk_ASN1_INTEGER_pop_free(sk_pop_free); //PALOFF
  sk_ASN1_GENERALSTRING_new := Tsk_ASN1_GENERALSTRING_new(sk_new); //PALOFF
  sk_ASN1_GENERALSTRING_new_null := Tsk_ASN1_GENERALSTRING_new_null( sk_new_null); //PALOFF
  sk_ASN1_GENERALSTRING_free := Tsk_ASN1_GENERALSTRING_free(sk_free); //PALOFF
  sk_ASN1_GENERALSTRING_num := Tsk_ASN1_GENERALSTRING_num(sk_num); //PALOFF
  sk_ASN1_GENERALSTRING_value := Tsk_ASN1_GENERALSTRING_value(sk_value);  //PALOFF
  sk_ASN1_GENERALSTRING_push := Tsk_ASN1_GENERALSTRING_push(sk_push); //PALOFF
  sk_ASN1_GENERALSTRING_dup := Tsk_ASN1_GENERALSTRING_dup(sk_dup);   //PALOFF
  sk_ASN1_GENERALSTRING_find := Tsk_ASN1_GENERALSTRING_find (sk_find);  //PALOFF
  sk_ASN1_GENERALSTRING_pop_free := Tsk_ASN1_GENERALSTRING_pop_free(sk_pop_free); //PALOFF

  sk_ASN1_UTF8STRING_new:= Tsk_ASN1_UTF8STRING_new ( sk_new);  //PALOFF
  sk_ASN1_UTF8STRING_new_null := Tsk_ASN1_UTF8STRING_new_null(sk_new_null);  //PALOFF
  sk_ASN1_UTF8STRING_free := Tsk_ASN1_UTF8STRING_free(sk_free); //PALOFF
  sk_ASN1_UTF8STRING_num := Tsk_ASN1_UTF8STRING_num(sk_num);  //PALOFF
  sk_ASN1_UTF8STRING_value := Tsk_ASN1_UTF8STRING_value(sk_value); //PALOFF
  sk_ASN1_UTF8STRING_push := Tsk_ASN1_UTF8STRING_push(sk_push);  //PALOFF
  sk_ASN1_UTF8STRING_dup := Tsk_ASN1_UTF8STRING_dup(sk_dup);   //PALOFF
  sk_ASN1_UTF8STRING_find := Tsk_ASN1_UTF8STRING_find( sk_find);  //PALOFF
  sk_ASN1_UTF8STRING_pop_free := Tsk_ASN1_UTF8STRING_pop_free(sk_pop_free); //PALOFF
  sk_ASN1_TYPE_new:= Tsk_ASN1_TYPE_new(sk_new); //PALOFF
  sk_ASN1_TYPE_new_null := Tsk_ASN1_TYPE_new_null(sk_new_null);  //PALOFF
  sk_ASN1_TYPE_free := Tsk_ASN1_TYPE_free(sk_free);  //PALOFF
  sk_ASN1_TYPE_num := Tsk_ASN1_TYPE_num(sk_num);  //PALOFF
  sk_ASN1_TYPE_value := Tsk_ASN1_TYPE_value(sk_value);  //PALOFF
  sk_ASN1_TYPE_push := Tsk_ASN1_TYPE_push(sk_push);  //PALOFF
  sk_ASN1_TYPE_dup := Tsk_ASN1_TYPE_dup(sk_dup);    //PALOFF
  sk_ASN1_TYPE_find := Tsk_ASN1_TYPE_find (sk_find);  //PALOFF
  sk_ASN1_TYPE_pop_free := Tsk_ASN1_TYPE_pop_free(sk_pop_free); //PALOFF
  sk_X509_ALGOR_new:= Tsk_X509_ALGOR_new( sk_new);  //PALOFF
  sk_X509_ALGOR_new_null := Tsk_X509_ALGOR_new_null(sk_new_null); //PALOFF
  sk_X509_ALGOR_free := Tsk_X509_ALGOR_free( sk_free); //PALOFF
  sk_X509_ALGOR_num := Tsk_X509_ALGOR_num( sk_num);  //PALOFF
  sk_X509_ALGOR_value := Tsk_X509_ALGOR_value( sk_value); //PALOFF
  sk_X509_ALGOR_push := Tsk_X509_ALGOR_push( sk_push); //PALOFF
  sk_X509_ALGOR_dup := Tsk_X509_ALGOR_dup( sk_dup);  //PALOFF
  sk_X509_ALGOR_find := Tsk_X509_ALGOR_find( sk_find); //PALOFF
  sk_X509_ALGOR_pop_free := Tsk_X509_ALGOR_pop_free( sk_pop_free); //PALOFF
end;

procedure Unload;
begin
  ASN1_TYPE_get := nil;
  ASN1_TYPE_set := nil;
  ASN1_TYPE_set1 := nil;
  ASN1_TYPE_cmp := nil;
  ASN1_TYPE_pack_sequence := nil; {introduced 1.1.0}
  ASN1_TYPE_unpack_sequence := nil; {introduced 1.1.0}
  ASN1_OBJECT_new := nil;
  ASN1_OBJECT_free := nil;
  i2d_ASN1_OBJECT := nil;
  d2i_ASN1_OBJECT := nil;
  i2d_ASN1_BIT_STRING := nil;
  d2i_ASN1_BIT_STRING := nil;
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
  ASN1_STRING_get0_data := nil; {introduced 1.1.0}
  ASN1_BIT_STRING_set := nil;
  ASN1_BIT_STRING_set_bit := nil;
  ASN1_BIT_STRING_get_bit := nil;
  ASN1_BIT_STRING_check := nil;
  ASN1_BIT_STRING_name_print := nil;
  ASN1_BIT_STRING_num_asc := nil;
  ASN1_BIT_STRING_set_asc := nil;
  ASN1_BIT_STRING_get_length := nil;
  ASN1_BIT_STRING_set1 := nil;
  ASN1_INTEGER_new := nil;
  ASN1_INTEGER_free := nil;
  d2i_ASN1_INTEGER := nil;
  i2d_ASN1_INTEGER := nil;
  d2i_ASN1_UINTEGER := nil;
  ASN1_INTEGER_dup := nil;
  ASN1_INTEGER_cmp := nil;
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
  ASN1_OCTET_STRING_dup := nil;
  ASN1_OCTET_STRING_cmp := nil;
  ASN1_OCTET_STRING_set := nil;
  d2i_ASN1_OCTET_STRING := nil;
  i2d_ASN1_OCTET_STRING := nil;
  ASN1_OCTET_STRING_free := nil;
  UTF8_getc := nil;
  UTF8_putc := nil;
  ASN1_UTCTIME_new := nil;
  ASN1_UTCTIME_free := nil;
  d2i_ASN1_UTCTIME := nil;
  i2d_ASN1_UTCTIME := nil;
  ASN1_GENERALIZEDTIME_new := nil;
  ASN1_GENERALIZEDTIME_free := nil;
  d2i_ASN1_GENERALIZEDTIME := nil;
  i2d_ASN1_GENERALIZEDTIME := nil;
  ASN1_TIME_new := nil;
  ASN1_TIME_free := nil;
  d2i_ASN1_TIME := nil;
  i2d_ASN1_TIME := nil;
  ASN1_TIME_set := nil;
  ASN1_TIME_adj := nil;
  ASN1_TIME_check := nil;
  ASN1_TIME_to_generalizedtime := nil;
  ASN1_TIME_set_string := nil;
  ASN1_TIME_set_string_X509 := nil; {introduced 1.1.0}
  ASN1_TIME_to_tm := nil; {introduced 1.1.0}
  ASN1_TIME_normalize := nil; {introduced 1.1.0}
  ASN1_TIME_cmp_time_t := nil; {introduced 1.1.0}
  ASN1_TIME_compare := nil; {introduced 1.1.0}
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
  ASN1_INTEGER_get_int64 := nil; {introduced 1.1.0}
  ASN1_INTEGER_set_int64 := nil; {introduced 1.1.0}
  ASN1_INTEGER_get_uint64 := nil; {introduced 1.1.0}
  ASN1_INTEGER_set_uint64 := nil; {introduced 1.1.0}
  ASN1_INTEGER_set := nil;
  ASN1_INTEGER_get := nil;
  BN_to_ASN1_INTEGER := nil;
  ASN1_INTEGER_to_BN := nil;
  ASN1_ENUMERATED_get_int64 := nil; {introduced 1.1.0}
  ASN1_ENUMERATED_set_int64 := nil; {introduced 1.1.0}
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
  ASN1_item_dup := nil;
  ASN1_STRING_to_UTF8 := nil;
  ASN1_item_d2i_bio := nil;
  ASN1_i2d_bio := nil;
  ASN1_item_i2d_bio := nil;
  ASN1_UTCTIME_print := nil;
  ASN1_GENERALIZEDTIME_print := nil;
  ASN1_TIME_print := nil;
  ASN1_STRING_print := nil;
  ASN1_STRING_print_ex := nil;
  ASN1_buf_print := nil; {introduced 1.1.0}
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
  ASN1_item_free := nil;
  ASN1_item_d2i := nil;
  ASN1_item_i2d := nil;
  ASN1_item_ndef_i2d := nil;
  ASN1_add_oid_module := nil;
  ASN1_add_stable_module := nil; {introduced 1.1.0}
  ASN1_generate_nconf := nil;
  ASN1_generate_v3 := nil;
  ASN1_str2mask := nil; {introduced 1.1.0}
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
  ASN1_SCTX_free := nil; {introduced 1.1.0}
  ASN1_SCTX_get_item := nil; {introduced 1.1.0}
  ASN1_SCTX_get_template := nil; {introduced 1.1.0}
  ASN1_SCTX_get_flags := nil; {introduced 1.1.0}
  ASN1_SCTX_set_app_data := nil; {introduced 1.1.0}
  ASN1_SCTX_get_app_data := nil; {introduced 1.1.0}
  BIO_f_asn1 := nil;
  BIO_new_NDEF := nil;
  i2d_ASN1_bio_stream := nil;
  PEM_write_bio_ASN1_stream := nil;
  SMIME_read_ASN1 := nil;
  SMIME_crlf_copy := nil;
  SMIME_text := nil;
  ASN1_ITEM_lookup := nil; {introduced 1.1.0}
  ASN1_ITEM_get := nil; {introduced 1.1.0}

  //stack of
  sk_ASN1_OBJECT_new:= nil;
  sk_ASN1_OBJECT_new_null := nil;
  sk_ASN1_OBJECT_free := nil;
  sk_ASN1_OBJECT_num := nil;
  sk_ASN1_OBJECT_value := nil;
  sk_ASN1_OBJECT_push := nil;
  sk_ASN1_OBJECT_dup := nil;
  sk_ASN1_OBJECT_find := nil;
  sk_ASN1_OBJECT_pop_free := nil;
  sk_ASN1_INTEGER_new:= nil;
  sk_ASN1_INTEGER_new_null := nil;
  sk_ASN1_INTEGER_free := nil;
  sk_ASN1_INTEGER_num := nil;
  sk_ASN1_INTEGER_value := nil;
  sk_ASN1_INTEGER_push := nil;
  sk_ASN1_INTEGER_dup := nil;
  sk_ASN1_INTEGER_find := nil;
  sk_ASN1_INTEGER_pop_free := nil;
  sk_ASN1_GENERALSTRING_new:= nil;
  sk_ASN1_GENERALSTRING_new_null := nil;
  sk_ASN1_GENERALSTRING_free := nil;
  sk_ASN1_GENERALSTRING_num := nil;
  sk_ASN1_GENERALSTRING_value := nil;
  sk_ASN1_GENERALSTRING_push := nil;
  sk_ASN1_GENERALSTRING_dup := nil;
  sk_ASN1_GENERALSTRING_find := nil;
  sk_ASN1_GENERALSTRING_pop_free := nil;
  sk_ASN1_UTF8STRING_new:= nil;
  sk_ASN1_UTF8STRING_new_null := nil;
  sk_ASN1_UTF8STRING_free := nil;
  sk_ASN1_UTF8STRING_num := nil;
  sk_ASN1_UTF8STRING_value := nil;
  sk_ASN1_UTF8STRING_push := nil;
  sk_ASN1_UTF8STRING_dup := nil;
  sk_ASN1_UTF8STRING_find := nil;
  sk_ASN1_UTF8STRING_pop_free := nil;
  sk_ASN1_TYPE_new:= nil;
  sk_ASN1_TYPE_new_null := nil;
  sk_ASN1_TYPE_free  := nil;
  sk_ASN1_TYPE_num  := nil;
  sk_ASN1_TYPE_value  := nil;
  sk_ASN1_TYPE_push  := nil;
  sk_ASN1_TYPE_dup  := nil;
  sk_ASN1_TYPE_find  := nil;
  sk_ASN1_TYPE_pop_free  := nil;
  sk_X509_ALGOR_new := nil;
  sk_X509_ALGOR_new_null  := nil;
  sk_X509_ALGOR_free  := nil;
  sk_X509_ALGOR_num  := nil;
  sk_X509_ALGOR_value  := nil;
  sk_X509_ALGOR_push  := nil;
  sk_X509_ALGOR_dup  := nil;
  sk_X509_ALGOR_find  := nil;
  sk_X509_ALGOR_pop_free  := nil;
end;
  {$ENDIF}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
