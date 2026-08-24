/// <exclude />
(* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_asyncerr.h2pas
  It should not be modified directly. All changes should be made to TaurusTLSHeaders_asyncerr.h2pas
  and this file regenerated. TaurusTLSHeaders_asyncerr.h2pas is distributed with the full Indy
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
unit TaurusTLSHeaders_openssl_encoder;

interface

uses
  IdCTypes,
  IdGlobal,
{$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
{$ENDIF}
  TaurusTLSHeaders_core,
  TaurusTLSHeaders_types;

type
  {$EXTERNALSYM OSSL_ENCODER_do_all_provided_fn}
  OSSL_ENCODER_do_all_provided_fn = procedure(encoder: POSSL_ENCODER;
    arg: Pointer); cdecl;
  {$EXTERNALSYM OSSL_ENCODER_names_do_all_fn}
  OSSL_ENCODER_names_do_all_fn = procedure(name: PIdAnsiChar;
    data: Pointer); cdecl;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

var
  {$EXTERNALSYM OSSL_ENCODER_fetch}
  OSSL_ENCODER_fetch: function(libctx: POSSL_LIB_CTX; name: PIdAnsiChar;
    properties: PIdAnsiChar): POSSL_ENCODER; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_up_ref}
  OSSL_ENCODER_up_ref: function(encoder: POSSL_ENCODER): TIdC_INT;  cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_free}
  OSSL_ENCODER_free: procedure(encoder: POSSL_ENCODER);  cdecl = nil;

  {$EXTERNALSYM OSSL_ENCODER_get0_provider}
  OSSL_ENCODER_get0_provider:  function(encoder: POSSL_ENCODER): POSSL_PROVIDER;
    cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_get0_properties}
  OSSL_ENCODER_get0_properties:  function(encoder: POSSL_ENCODER): PIdAnsiChar;
    cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_get0_name}
  OSSL_ENCODER_get0_name: function(kdf: POSSL_ENCODER): PIdAnsiChar;
    cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_get0_description}
  OSSL_ENCODER_get0_description: function(kdf: POSSL_ENCODER): PIdAnsiChar;
    cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_is_a}
  OSSL_ENCODER_is_a: function(encoder: POSSL_ENCODER; name: PIdAnsiChar): TIdC_INT;
    cdecl = nil;

  {$EXTERNALSYM OSSL_ENCODER_do_all_provided}
  OSSL_ENCODER_do_all_provided:  procedure(libctx: POSSL_LIB_CTX;
    fn: OSSL_ENCODER_do_all_provided_fn; arg: Pointer);  cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_names_do_all}
  OSSL_ENCODER_names_do_all:  function(encoder: POSSL_ENCODER;
    fn: OSSL_ENCODER_names_do_all_fn; data: Pointer): TIdC_INT;  cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_gettable_params}
  OSSL_ENCODER_gettable_params:  function(encoder: POSSL_ENCODER): POSSL_PARAM;
    cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_get_params}
  OSSL_ENCODER_get_params: function(encoder: POSSL_ENCODER;
     params: POSSL_PARAM_ARRAY): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM OSSL_ENCODER_settable_ctx_params}
  OSSL_ENCODER_settable_ctx_params: function(encoder : POSSL_ENCODER) :
    POSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_CTX_new}
  OSSL_ENCODER_CTX_new : function : POSSL_ENCODER_CTX;  cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_params}
  OSSL_ENCODER_CTX_set_params: function(ctx : POSSL_ENCODER_CTX;
    params : POSSL_PARAM_ARRAY) : TIdC_INT;  cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_CTX_free}
  OSSL_ENCODER_CTX_free : procedure(ctx : POSSL_ENCODER_CTX);  cdecl = nil;

//* Utilities that help set specific parameters */
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_passphrase}
  OSSL_ENCODER_CTX_set_passphrase : function (ctx : POSSL_ENCODER_CTX;
    kstr : PIdAnsiChar; klen : TIdC_SizeT) : TIdC_INT;  cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_pem_password_cb}
  OSSL_ENCODER_CTX_set_pem_password_cb : function (ctx : POSSL_ENCODER_CTX;
    cb : pem_password_cb; cbarg : Pointer) : TIdC_INT;  cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_passphrase_cb}
  OSSL_ENCODER_CTX_set_passphrase_cb : function (ctx : POSSL_ENCODER_CTX;
    cb : OSSL_PASSPHRASE_CALLBACK;
    cbarg : Pointer) : TIdC_INT;  cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_passphrase_ui}
  OSSL_ENCODER_CTX_set_passphrase_ui : function (ctx : POSSL_ENCODER_CTX;
    ui_method : PUI_METHOD; ui_data : Pointer) : TIdC_INT;  cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_cipher}
  OSSL_ENCODER_CTX_set_cipher : function (ctx : POSSL_ENCODER_CTX;
    cipher_name : PIdAnsiChar; propquery : PIdAnsiChar) : TIdC_INT;  cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_selection}
  OSSL_ENCODER_CTX_set_selection : function (ctx : POSSL_ENCODER_CTX;
     selection : TIdC_INT) : TIdC_INT;  cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_output_type}
  OSSL_ENCODER_CTX_set_output_type : function (ctx : POSSL_ENCODER_CTX;
     output_type : PIdAnsiChar) : TIdC_INT;  cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_output_structure}
  OSSL_ENCODER_CTX_set_output_structure : function (ctx : POSSL_ENCODER_CTX;
     output_structure : PIdAnsiChar) : TIdC_INT;  cdecl = nil;

  //* Utilities to output the object to encode */
  {$EXTERNALSYM OSSL_ENCODER_to_bio}
  OSSL_ENCODER_to_bio : function(ctx : POSSL_ENCODER_CTX; _out : PBIO)
    : TIdC_INT; cdecl = nil;
//#ifndef OPENSSL_NO_STDIO
//int OSSL_ENCODER_to_fp(OSSL_ENCODER_CTX *ctx, FILE *fp);
//#endif
  {$EXTERNALSYM OSSL_ENCODER_to_data}
  OSSL_ENCODER_to_data : function(ctx : POSSL_ENCODER_CTX; pdata : PPIdAnsiChar;
    pdata_len : PIdC_SIZET) : TIdC_INT; cdecl = nil;

{*
 * Create the OSSL_ENCODER_CTX with an associated type.  This will perform
 * an implicit OSSL_ENCODER_fetch(), suitable for the object of that type.
 * This is more useful than calling OSSL_ENCODER_CTX_new().
 *}
  {$EXTERNALSYM OSSL_ENCODER_CTX_new_for_pkey}
 OSSL_ENCODER_CTX_new_for_pkey : function(pkey : PEVP_PKEY;
   selection : TIdC_INT; output_type, output_struct, propquery : PIdAnsiChar)
   : POSSL_ENCODER_CTX; cdecl = nil;
{$ELSE}
  {$EXTERNALSYM OSSL_ENCODER_fetch}
function OSSL_ENCODER_fetch(libctx: POSSL_LIB_CTX; name: PIdAnsiChar;
  properties: PIdAnsiChar): POSSL_ENCODER cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_ENCODER_up_ref}
function OSSL_ENCODER_up_ref(encoder: POSSL_ENCODER): TIdC_INT cdecl;
  external CLibCrypto;
  {$EXTERNALSYM OSSL_ENCODER_free}
procedure OSSL_ENCODER_free(encoder: POSSL_ENCODER)cdecl; external CLibCrypto;

  {$EXTERNALSYM OSSL_ENCODER_get0_provider}
function OSSL_ENCODER_get0_provider(encoder: POSSL_ENCODER)
  : POSSL_PROVIDER cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_ENCODER_get0_properties}
function OSSL_ENCODER_get0_properties(encoder: POSSL_ENCODER)
  : PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_ENCODER_get0_name}
function OSSL_ENCODER_get0_name(kdf: POSSL_ENCODER): PIdAnsiChar cdecl;
  external CLibCrypto;
  {$EXTERNALSYM OSSL_ENCODER_get0_description}
function OSSL_ENCODER_get0_description(kdf: POSSL_ENCODER): PIdAnsiChar cdecl;
  external CLibCrypto;
  {$EXTERNALSYM OSSL_ENCODER_is_a}
function OSSL_ENCODER_is_a(encoder: POSSL_ENCODER; name: PIdAnsiChar)
  : TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM OSSL_ENCODER_do_all_provided}
procedure OSSL_ENCODER_do_all_provided(libctx: POSSL_LIB_CTX;
  fn: OSSL_ENCODER_do_all_provided_fn; arg: Pointer)cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_ENCODER_names_do_all}
function OSSL_ENCODER_names_do_all(encoder: POSSL_ENCODER;
  fn: OSSL_ENCODER_names_do_all_fn; data: Pointer): TIdC_INT cdecl;
  external CLibCrypto;
  {$EXTERNALSYM OSSL_ENCODER_gettable_params}
function OSSL_ENCODER_gettable_params(encoder: POSSL_ENCODER)
  : POSSL_PARAM cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_ENCODER_get_params}
function OSSL_ENCODER_get_params(encoder: POSSL_ENCODER;
  params: POSSL_PARAM_ARRAY): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM OSSL_ENCODER_settable_ctx_params}
function OSSL_ENCODER_settable_ctx_params(encoder : POSSL_ENCODER) :
  POSSL_PARAM cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_ENCODER_CTX_new}
function OSSL_ENCODER_CTX_new : POSSL_ENCODER_CTX cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_params}
function OSSL_ENCODER_CTX_set_params(ctx : POSSL_ENCODER_CTX;
  params : POSSL_PARAM_ARRAY) : TIdC_INT  cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_ENCODER_CTX_free}
procedure OSSL_ENCODER_CTX_free (ctx : POSSL_ENCODER_CTX)
  cdecl; external CLibCrypto;

  {$EXTERNALSYM OSSL_ENCODER_CTX_set_passphrase}
function OSSL_ENCODER_CTX_set_passphrase (ctx : POSSL_ENCODER_CTX;
  kstr : PIdAnsiChar; klen : TIdC_SizeT) : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_pem_password_cb}
function OSSL_ENCODER_CTX_set_pem_password_cb(ctx : POSSL_ENCODER_CTX;
    cb : pem_password_cb; cbarg : Pointer) : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_passphrase_cb}
function OSSL_ENCODER_CTX_set_passphrase_cb(ctx : POSSL_ENCODER_CTX;
    cb : OSSL_PASSPHRASE_CALLBACK;  cbarg : Pointer) : TIdC_INT cdecl;
    external CLibCrypto;
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_passphrase_ui}
function OSSL_ENCODER_CTX_set_passphrase_ui(ctx : POSSL_ENCODER_CTX;
    ui_method : PUI_METHOD; ui_data : Pointer) : TIdC_INT cdecl;
    external CLibCrypto;
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_cipher}
function OSSL_ENCODER_CTX_set_cipher(ctx : POSSL_ENCODER_CTX;
    cipher_name : PIdAnsiChar; propquery : PIdAnsiChar) : TIdC_INT cdecl;
     external CLibCrypto;
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_selection}
function OSSL_ENCODER_CTX_set_selection(ctx : POSSL_ENCODER_CTX;
     selection : TIdC_INT) : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_output_type}
function OSSL_ENCODER_CTX_set_output_type(ctx : POSSL_ENCODER_CTX;
     output_type : PIdAnsiChar) : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_output_structure}
function OSSL_ENCODER_CTX_set_output_structure(ctx : POSSL_ENCODER_CTX;
     output_structure : PIdAnsiChar) : TIdC_INT cdecl; external CLibCrypto;
  //* Utilities to output the object to encode */
  {$EXTERNALSYM OSSL_ENCODER_to_bio}
function OSSL_ENCODER_to_bio (ctx : POSSL_ENCODER_CTX; _out : PBIO)
    : TIdC_INT cdecl; external CLibCrypto;
//#ifndef OPENSSL_NO_STDIO
//int OSSL_ENCODER_to_fp(OSSL_ENCODER_CTX *ctx, FILE *fp);
//#endif
  {$EXTERNALSYM OSSL_ENCODER_to_data}
function OSSL_ENCODER_to_data(ctx : POSSL_ENCODER_CTX; pdata : PPIdAnsiChar;
    pdata_len : PIdC_SIZET) : TIdC_INT cdecl; external CLibCrypto;

{*
 * Create the OSSL_ENCODER_CTX with an associated type.  This will perform
 * an implicit OSSL_ENCODER_fetch(), suitable for the object of that type.
 * This is more useful than calling OSSL_ENCODER_CTX_new().
 *}
  {$EXTERNALSYM OSSL_ENCODER_CTX_new_for_pkey}
 function OSSL_ENCODER_CTX_new_for_pkey(pkey : PEVP_PKEY;
   selection : TIdC_INT; output_type, output_struct, propquery : PIdAnsiChar)
   : POSSL_ENCODER_CTX  cdecl; external CLibCrypto;

{$ENDIF}

implementation

uses
  classes,
  TaurusTLSExceptionHandlers
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    , TaurusTLSLoader
{$ENDIF};

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

const
  OSSL_ENCODER_fetch_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_ENCODER_up_ref_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_ENCODER_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_ENCODER_get0_provider_introduced = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
  OSSL_ENCODER_get0_properties_introduced = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
  OSSL_ENCODER_get0_name_introduced = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
  OSSL_ENCODER_get0_description_introduced = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
  OSSL_ENCODER_is_a_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_ENCODER_do_all_provided_introduced = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
  OSSL_ENCODER_names_do_all_introduced = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
  OSSL_ENCODER_gettable_params_introduced = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
  OSSL_ENCODER_get_params_introduced = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
  OSSL_ENCODER_settable_ctx_params_introduced = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
  OSSL_ENCODER_CTX_new_introduced = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
  OSSL_ENCODER_CTX_set_params_introduced = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
  OSSL_ENCODER_CTX_free_introduced = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);

  OSSL_ENCODER_CTX_set_passphrase_introduced  = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
  OSSL_ENCODER_CTX_set_pem_password_cb_introduced = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
  OSSL_ENCODER_CTX_set_passphrase_cb_introduced  = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
  OSSL_ENCODER_CTX_set_passphrase_ui_introduced = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
  OSSL_ENCODER_CTX_set_cipher_introduced  = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
  OSSL_ENCODER_CTX_set_selection_introduced  = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
  OSSL_ENCODER_CTX_set_output_type_introduced  = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
  OSSL_ENCODER_CTX_set_output_structure_introduced  = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);

   OSSL_ENCODER_to_bio_introduced  = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
//#ifndef OPENSSL_NO_STDIO
//int OSSL_ENCODER_to_fp(OSSL_ENCODER_CTX *ctx, FILE *fp);
//#endif
   OSSL_ENCODER_to_data_introduced  = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
   OSSL_ENCODER_CTX_new_for_pkey_introduced  = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
const
  OSSL_ENCODER_fetch_procname = 'OSSL_ENCODER_fetch';
  OSSL_ENCODER_up_ref_procname = 'OSSL_ENCODER_up_ref';
  OSSL_ENCODER_free_procname = 'OSSL_ENCODER_free';

  OSSL_ENCODER_get0_provider_procname = 'OSSL_ENCODER_get0_provider';
  OSSL_ENCODER_get0_properties_procname = 'OSSL_ENCODER_get0_properties';
  OSSL_ENCODER_get0_name_procname = 'OSSL_ENCODER_get0_name';
  OSSL_ENCODER_get0_description_procname = 'OSSL_ENCODER_get0_description';
  OSSL_ENCODER_is_a_procname = 'OSSL_ENCODER_is_a';

  OSSL_ENCODER_do_all_provided_procname = 'OSSL_ENCODER_do_all_provided';
  OSSL_ENCODER_names_do_all_procname = 'OSSL_ENCODER_names_do_all';
  OSSL_ENCODER_gettable_params_procname = 'OSSL_ENCODER_gettable_params';
  OSSL_ENCODER_get_params_procname = 'OSSL_ENCODER_get_params';

  OSSL_ENCODER_settable_ctx_params_procname = 'OSSL_ENCODER_settable_ctx_params';
  OSSL_ENCODER_CTX_new_procname = 'OSSL_ENCODER_CTX_new';
  OSSL_ENCODER_CTX_set_params_procname = 'OSSL_ENCODER_CTX_set_params';
  OSSL_ENCODER_CTX_free_procname = 'OSSL_ENCODER_CTX_free';

  OSSL_ENCODER_CTX_set_passphrase_procname = 'OSSL_ENCODER_CTX_set_passphrase';
  OSSL_ENCODER_CTX_set_pem_password_cb_procname =
    'OSSL_ENCODER_CTX_set_pem_password_cb';
  OSSL_ENCODER_CTX_set_passphrase_cb_procname =
    'OSSL_ENCODER_CTX_set_passphrase_cb';
  OSSL_ENCODER_CTX_set_passphrase_ui_procname =
    'OSSL_ENCODER_CTX_set_passphrase_ui';
  OSSL_ENCODER_CTX_set_cipher_procname = 'OSSL_ENCODER_CTX_set_cipher';
  OSSL_ENCODER_CTX_set_selection_procname = 'OSSL_ENCODER_CTX_set_selection';
  OSSL_ENCODER_CTX_set_output_type_procname =
    'OSSL_ENCODER_CTX_set_output_type';
  OSSL_ENCODER_CTX_set_output_structure_procname =
    'OSSL_ENCODER_CTX_set_output_structure';

  OSSL_ENCODER_to_bio_procname = 'OSSL_ENCODER_to_bio';
//#ifndef OPENSSL_NO_STDIO
//int OSSL_ENCODER_to_fp(OSSL_ENCODER_CTX *ctx, FILE *fp);
//#endif
  OSSL_ENCODER_to_data_procname = 'OSSL_ENCODER_to_data';

  OSSL_ENCODER_CTX_new_for_pkey_procname = 'OSSL_ENCODER_CTX_new_for_pkey';

  {$IFNDEF _FIXINSIGHT_}
{$I TaurusTLSNoRetValOff.inc}

function ERR_OSSL_ENCODER_fetch(libctx: POSSL_LIB_CTX; name: PIdAnsiChar;
  properties: PIdAnsiChar): POSSL_ENCODER; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_fetch_procname);
end;

function ERR_OSSL_ENCODER_up_ref(encoder: POSSL_ENCODER): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_up_ref_procname);
end;

procedure ERR_OSSL_ENCODER_free(encoder: POSSL_ENCODER); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_free_procname);
end;

function ERR_OSSL_ENCODER_get0_provider(encoder: POSSL_ENCODER): POSSL_PROVIDER; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (OSSL_ENCODER_get0_provider_procname);
end;

function ERR_OSSL_ENCODER_get0_properties(encoder: POSSL_ENCODER): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (OSSL_ENCODER_get0_properties_procname);
end;

function ERR_OSSL_ENCODER_get0_name(kdf: POSSL_ENCODER): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (OSSL_ENCODER_get0_name_procname);
end;

function ERR_OSSL_ENCODER_get0_description(kdf: POSSL_ENCODER): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (OSSL_ENCODER_get0_description_procname);
end;

function ERR_OSSL_ENCODER_is_a(encoder: POSSL_ENCODER; name: PIdAnsiChar)
  : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_is_a_procname);
end;

procedure ERR_OSSL_ENCODER_do_all_provided(libctx: POSSL_LIB_CTX;
  fn: OSSL_ENCODER_do_all_provided_fn; arg: Pointer); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (OSSL_ENCODER_do_all_provided_procname);
end;

function ERR_OSSL_ENCODER_names_do_all(encoder: POSSL_ENCODER;
  fn: OSSL_ENCODER_names_do_all_fn; data: Pointer): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (OSSL_ENCODER_names_do_all_procname);
end;

function ERR_OSSL_ENCODER_gettable_params(encoder: POSSL_ENCODER): POSSL_PARAM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (OSSL_ENCODER_gettable_params_procname);
end;

function ERR_OSSL_ENCODER_get_params(encoder: POSSL_ENCODER;
  params: POSSL_PARAM_ARRAY): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (OSSL_ENCODER_get_params_procname);
end;

function ERR_OSSL_ENCODER_settable_ctx_params(encoder : POSSL_ENCODER) :
  POSSL_PARAM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (OSSL_ENCODER_get_params_procname);
end;

function ERR_OSSL_ENCODER_CTX_new : POSSL_ENCODER_CTX; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (OSSL_ENCODER_get_params_procname);
end;

function ERR_OSSL_ENCODER_CTX_set_params(ctx : POSSL_ENCODER_CTX;
  params : POSSL_PARAM_ARRAY) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (OSSL_ENCODER_get_params_procname);
end;

procedure ERR_OSSL_ENCODER_CTX_free (ctx : POSSL_ENCODER_CTX); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (OSSL_ENCODER_get_params_procname);
end;

function ERR_OSSL_ENCODER_CTX_set_passphrase (ctx : POSSL_ENCODER_CTX;
  kstr : PIdAnsiChar; klen : TIdC_SizeT) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (OSSL_ENCODER_CTX_set_passphrase_procname);
end;

function ERR_OSSL_ENCODER_CTX_set_pem_password_cb(ctx : POSSL_ENCODER_CTX;
    cb : pem_password_cb; cbarg : Pointer) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (OSSL_ENCODER_CTX_set_pem_password_cb_procname);
end;

function ERR_OSSL_ENCODER_CTX_set_passphrase_cb(ctx : POSSL_ENCODER_CTX;
    cb : OSSL_PASSPHRASE_CALLBACK;
    cbarg : Pointer) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (OSSL_ENCODER_CTX_set_passphrase_cb_procname);
end;

function ERR_OSSL_ENCODER_CTX_set_passphrase_ui(ctx : POSSL_ENCODER_CTX;
    ui_method : PUI_METHOD; ui_data : Pointer) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (OSSL_ENCODER_CTX_set_passphrase_ui_procname);
end;

function ERR_OSSL_ENCODER_CTX_set_cipher(ctx : POSSL_ENCODER_CTX;
    cipher_name : PIdAnsiChar; propquery : PIdAnsiChar) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (OSSL_ENCODER_CTX_set_cipher_procname);
end;

function ERR_OSSL_ENCODER_CTX_set_selection(ctx : POSSL_ENCODER_CTX;
     selection : TIdC_INT) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (OSSL_ENCODER_CTX_set_selection_procname);
end;

function ERR_OSSL_ENCODER_CTX_set_output_type(ctx : POSSL_ENCODER_CTX;
     output_type : PIdAnsiChar) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (OSSL_ENCODER_CTX_set_output_type_procname);
end;

function ERR_OSSL_ENCODER_CTX_set_output_structure(ctx : POSSL_ENCODER_CTX;
     output_structure : PIdAnsiChar) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (OSSL_ENCODER_CTX_set_output_structure_procname);
end;

  //* Utilities to output the object to encode */
function ERR_OSSL_ENCODER_to_bio (ctx : POSSL_ENCODER_CTX; _out : PBIO)
    : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (OSSL_ENCODER_to_bio_procname);
end;

//#ifndef OPENSSL_NO_STDIO
//int OSSL_ENCODER_to_fp(OSSL_ENCODER_CTX *ctx, FILE *fp);
//#endif

function ERR_OSSL_ENCODER_to_data(ctx : POSSL_ENCODER_CTX; pdata : PPIdAnsiChar;
    pdata_len : PIdC_SIZET) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (OSSL_ENCODER_to_data_procname);
end;

{*
 * Create the OSSL_ENCODER_CTX with an associated type.  This will perform
 * an implicit OSSL_ENCODER_fetch(), suitable for the object of that type.
 * This is more useful than calling OSSL_ENCODER_CTX_new().
 *}
function ERR_OSSL_ENCODER_CTX_new_for_pkey(pkey : PEVP_PKEY;
   selection : TIdC_INT; output_type, output_struct, propquery : PIdAnsiChar)
   : POSSL_ENCODER_CTX; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (OSSL_ENCODER_CTX_new_for_pkey_procname);
end;

{$I TaurusTLSNoRetValOn.inc}
{$I TaurusTLSUnusedParamOff.inc}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);

var
  FuncLoadError: boolean;

begin
  OSSL_ENCODER_fetch := LoadLibFunction(ADllHandle,
    OSSL_ENCODER_fetch_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_fetch);
  if FuncLoadError then
  begin
{$IF not defined(OSSL_ENCODER_fetch_allownil)}
    OSSL_ENCODER_fetch := ERR_OSSL_ENCODER_fetch;
{$IFEND}
{$IF declared(OSSL_ENCODER_fetch_introduced)}
    if LibVersion < OSSL_ENCODER_fetch_introduced then
    begin
{$IF declared(FC_OSSL_ENCODER_fetch)}
      OSSL_ENCODER_fetch := FC_OSSL_ENCODER_fetch;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(OSSL_ENCODER_fetch_removed)}
    if OSSL_ENCODER_fetch_removed <= LibVersion then
    begin
{$IF declared(_OSSL_ENCODER_fetch)}
      OSSL_ENCODER_fetch := _OSSL_ENCODER_fetch;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(OSSL_ENCODER_fetch_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_fetch');
{$IFEND}
  end;

  OSSL_ENCODER_up_ref := LoadLibFunction(ADllHandle,
    OSSL_ENCODER_up_ref_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_up_ref);
  if FuncLoadError then
  begin
{$IF not defined(OSSL_ENCODER_up_ref_allownil)}
    OSSL_ENCODER_up_ref := ERR_OSSL_ENCODER_up_ref;
{$IFEND}
{$IF declared(OSSL_ENCODER_up_ref_introduced)}
    if LibVersion < OSSL_ENCODER_up_ref_introduced then
    begin
{$IF declared(FC_OSSL_ENCODER_up_ref)}
      OSSL_ENCODER_up_ref := FC_OSSL_ENCODER_up_ref;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(OSSL_ENCODER_up_ref_removed)}
    if OSSL_ENCODER_up_ref_removed <= LibVersion then
    begin
{$IF declared(_OSSL_ENCODER_up_ref)}
      OSSL_ENCODER_up_ref := _OSSL_ENCODER_up_ref;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(OSSL_ENCODER_up_ref_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_up_ref');
{$IFEND}
  end;

  OSSL_ENCODER_free := LoadLibFunction(ADllHandle, OSSL_ENCODER_free_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_free);
  if FuncLoadError then
  begin
{$IF not defined(OSSL_ENCODER_free_allownil)}
    OSSL_ENCODER_free := ERR_OSSL_ENCODER_free;
{$IFEND}
{$IF declared(OSSL_ENCODER_free_introduced)}
    if LibVersion < OSSL_ENCODER_free_introduced then
    begin
{$IF declared(FC_OSSL_ENCODER_free)}
      OSSL_ENCODER_free := FC_OSSL_ENCODER_free;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(OSSL_ENCODER_free_removed)}
    if OSSL_ENCODER_free_removed <= LibVersion then
    begin
{$IF declared(_OSSL_ENCODER_free)}
      OSSL_ENCODER_free := _OSSL_ENCODER_free;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(OSSL_ENCODER_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_free');
{$IFEND}
  end;

  OSSL_ENCODER_get0_provider := LoadLibFunction(ADllHandle,
    OSSL_ENCODER_get0_provider_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_get0_provider);
  if FuncLoadError then
  begin
{$IF not defined(OSSL_ENCODER_get0_provider_allownil)}
    OSSL_ENCODER_get0_provider := ERR_OSSL_ENCODER_get0_provider;
{$IFEND}
{$IF declared(OSSL_ENCODER_get0_provider_introduced)}
    if LibVersion < OSSL_ENCODER_get0_provider_introduced then
    begin
{$IF declared(FC_OSSL_ENCODER_get0_provider)}
      OSSL_ENCODER_get0_provider := FC_OSSL_ENCODER_get0_provider;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(OSSL_ENCODER_get0_provider_removed)}
    if OSSL_ENCODER_get0_provider_removed <= LibVersion then
    begin
{$IF declared(_OSSL_ENCODER_get0_provider)}
      OSSL_ENCODER_get0_provider := _OSSL_ENCODER_get0_provider;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(OSSL_ENCODER_get0_provider_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_get0_provider');
{$IFEND}
  end;

  OSSL_ENCODER_get0_properties := LoadLibFunction(ADllHandle,
    OSSL_ENCODER_get0_properties_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_get0_properties);
  if FuncLoadError then
  begin
{$IF not defined(OSSL_ENCODER_get0_properties_allownil)}
    OSSL_ENCODER_get0_properties := ERR_OSSL_ENCODER_get0_properties;
{$IFEND}
{$IF declared(OSSL_ENCODER_get0_properties_introduced)}
    if LibVersion < OSSL_ENCODER_get0_properties_introduced then
    begin
{$IF declared(FC_OSSL_ENCODER_get0_properties)}
      OSSL_ENCODER_get0_properties := FC_OSSL_ENCODER_get0_properties;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(OSSL_ENCODER_get0_properties_removed)}
    if OSSL_ENCODER_get0_properties_removed <= LibVersion then
    begin
{$IF declared(_OSSL_ENCODER_get0_properties)}
      OSSL_ENCODER_get0_properties := _OSSL_ENCODER_get0_properties;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(OSSL_ENCODER_get0_properties_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_get0_properties');
{$IFEND}
  end;

  OSSL_ENCODER_get0_name := LoadLibFunction(ADllHandle,
    OSSL_ENCODER_get0_name_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_get0_name);
  if FuncLoadError then
  begin
{$IF not defined(OSSL_ENCODER_get0_name_allownil)}
    OSSL_ENCODER_get0_name := ERR_OSSL_ENCODER_get0_name;
{$IFEND}
{$IF declared(OSSL_ENCODER_get0_name_introduced)}
    if LibVersion < OSSL_ENCODER_get0_name_introduced then
    begin
{$IF declared(FC_OSSL_ENCODER_get0_name)}
      OSSL_ENCODER_get0_name := FC_OSSL_ENCODER_get0_name;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(OSSL_ENCODER_get0_name_removed)}
    if OSSL_ENCODER_get0_name_removed <= LibVersion then
    begin
{$IF declared(_OSSL_ENCODER_get0_name)}
      OSSL_ENCODER_get0_name := _OSSL_ENCODER_get0_name;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(OSSL_ENCODER_get0_name_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_get0_name');
{$IFEND}
  end;

  OSSL_ENCODER_get0_description := LoadLibFunction(ADllHandle,
    OSSL_ENCODER_get0_description_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_get0_description);
  if FuncLoadError then
  begin
{$IF not defined(OSSL_ENCODER_get0_description_allownil)}
    OSSL_ENCODER_get0_description := ERR_OSSL_ENCODER_get0_description;
{$IFEND}
{$IF declared(OSSL_ENCODER_get0_description_introduced)}
    if LibVersion < OSSL_ENCODER_get0_description_introduced then
    begin
{$IF declared(FC_OSSL_ENCODER_get0_description)}
      OSSL_ENCODER_get0_description := FC_OSSL_ENCODER_get0_description;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(OSSL_ENCODER_get0_description_removed)}
    if OSSL_ENCODER_get0_description_removed <= LibVersion then
    begin
{$IF declared(_OSSL_ENCODER_get0_description)}
      OSSL_ENCODER_get0_description := _OSSL_ENCODER_get0_description;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(OSSL_ENCODER_get0_description_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_get0_description');
{$IFEND}
  end;

  OSSL_ENCODER_is_a := LoadLibFunction(ADllHandle, OSSL_ENCODER_is_a_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_is_a);
  if FuncLoadError then
  begin
{$IF not defined(OSSL_ENCODER_is_a_allownil)}
    OSSL_ENCODER_is_a := ERR_OSSL_ENCODER_is_a;
{$IFEND}
{$IF declared(OSSL_ENCODER_is_a_introduced)}
    if LibVersion < OSSL_ENCODER_is_a_introduced then
    begin
{$IF declared(FC_OSSL_ENCODER_is_a)}
      OSSL_ENCODER_is_a := FC_OSSL_ENCODER_is_a;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(OSSL_ENCODER_is_a_removed)}
    if OSSL_ENCODER_is_a_removed <= LibVersion then
    begin
{$IF declared(_OSSL_ENCODER_is_a)}
      OSSL_ENCODER_is_a := _OSSL_ENCODER_is_a;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(OSSL_ENCODER_is_a_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_is_a');
{$IFEND}
  end;

  OSSL_ENCODER_do_all_provided := LoadLibFunction(ADllHandle,
    OSSL_ENCODER_do_all_provided_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_do_all_provided);
  if FuncLoadError then
  begin
{$IF not defined(OSSL_ENCODER_do_all_provided_allownil)}
    OSSL_ENCODER_do_all_provided := ERR_OSSL_ENCODER_do_all_provided;
{$IFEND}
{$IF declared(OSSL_ENCODER_do_all_provided_introduced)}
    if LibVersion < OSSL_ENCODER_do_all_provided_introduced then
    begin
{$IF declared(FC_OSSL_ENCODER_do_all_provided)}
      OSSL_ENCODER_do_all_provided := FC_OSSL_ENCODER_do_all_provided;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(OSSL_ENCODER_do_all_provided_removed)}
    if OSSL_ENCODER_do_all_provided_removed <= LibVersion then
    begin
{$IF declared(_OSSL_ENCODER_do_all_provided)}
      OSSL_ENCODER_do_all_provided := _OSSL_ENCODER_do_all_provided;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(OSSL_ENCODER_do_all_provided_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_do_all_provided');
{$IFEND}
  end;

  OSSL_ENCODER_names_do_all := LoadLibFunction(ADllHandle,
    OSSL_ENCODER_names_do_all_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_names_do_all);
  if FuncLoadError then
  begin
{$IF not defined(OSSL_ENCODER_names_do_all_allownil)}
    OSSL_ENCODER_names_do_all := ERR_OSSL_ENCODER_names_do_all;
{$IFEND}
{$IF declared(OSSL_ENCODER_names_do_all_introduced)}
    if LibVersion < OSSL_ENCODER_names_do_all_introduced then
    begin
{$IF declared(FC_OSSL_ENCODER_names_do_all)}
      OSSL_ENCODER_names_do_all := FC_OSSL_ENCODER_names_do_all;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(OSSL_ENCODER_names_do_all_removed)}
    if OSSL_ENCODER_names_do_all_removed <= LibVersion then
    begin
{$IF declared(_OSSL_ENCODER_names_do_all)}
      OSSL_ENCODER_names_do_all := _OSSL_ENCODER_names_do_all;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(OSSL_ENCODER_names_do_all_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_names_do_all');
{$IFEND}
  end;

  OSSL_ENCODER_gettable_params := LoadLibFunction(ADllHandle,
    OSSL_ENCODER_gettable_params_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_gettable_params);
  if FuncLoadError then
  begin
{$IF not defined(OSSL_ENCODER_gettable_params_allownil)}
    OSSL_ENCODER_gettable_params := ERR_OSSL_ENCODER_gettable_params;
{$IFEND}
{$IF declared(OSSL_ENCODER_gettable_params_introduced)}
    if LibVersion < OSSL_ENCODER_gettable_params_introduced then
    begin
{$IF declared(FC_OSSL_ENCODER_gettable_params)}
      OSSL_ENCODER_gettable_params := FC_OSSL_ENCODER_gettable_params;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(OSSL_ENCODER_gettable_params_removed)}
    if OSSL_ENCODER_gettable_params_removed <= LibVersion then
    begin
{$IF declared(_OSSL_ENCODER_gettable_params)}
      OSSL_ENCODER_gettable_params := _OSSL_ENCODER_gettable_params;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(OSSL_ENCODER_gettable_params_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_gettable_params');
{$IFEND}
  end;

  OSSL_ENCODER_get_params := LoadLibFunction(ADllHandle,
    OSSL_ENCODER_get_params_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_get_params);
  if FuncLoadError then
  begin
{$IF not defined(OSSL_ENCODER_get_params_allownil)}
    OSSL_ENCODER_get_params := ERR_OSSL_ENCODER_get_params;
{$IFEND}
{$IF declared(OSSL_ENCODER_get_params_introduced)}
    if LibVersion < OSSL_ENCODER_get_params_introduced then
    begin
{$IF declared(FC_OSSL_ENCODER_get_params)}
      OSSL_ENCODER_get_params := FC_OSSL_ENCODER_get_params;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(OSSL_ENCODER_get_params_removed)}
    if OSSL_ENCODER_get_params_removed <= LibVersion then
    begin
{$IF declared(_OSSL_ENCODER_get_params)}
      OSSL_ENCODER_get_params := _OSSL_ENCODER_get_params;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(OSSL_ENCODER_get_params_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_get_params');
{$IFEND}
  end;

  OSSL_ENCODER_settable_ctx_params := LoadLibFunction(ADllHandle,
    OSSL_ENCODER_settable_ctx_params_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_settable_ctx_params);
  if FuncLoadError then
  begin
{$IF not defined(OSSL_ENCODER_settable_ctx_params_allownil)}
    OSSL_ENCODER_settable_ctx_params := ERR_OSSL_ENCODER_settable_ctx_params;
{$IFEND}
{$IF declared(OSSL_ENCODER_settable_ctx_params_introduced)}
    if LibVersion < OSSL_ENCODER_settable_ctx_params_introduced then
    begin
{$IF declared(FC_OSSL_ENCODER_settable_ctx_params)}
      OSSL_ENCODER_settable_ctx_params := FC_OSSL_ENCODER_settable_ctx_params;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(OSSL_ENCODER_settable_ctx_params_removed)}
    if OSSL_ENCODER_settable_ctx_params_removed <= LibVersion then
    begin
{$IF declared(_OSSL_ENCODER_settable_ctx_params)}
      OSSL_ENCODER_settable_ctx_params := _OSSL_ENCODER_settable_ctx_params;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(OSSL_ENCODER_settable_ctx_params_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_settable_ctx_params');
{$IFEND}
  end;

  OSSL_ENCODER_CTX_new := LoadLibFunction(ADllHandle,
    OSSL_ENCODER_CTX_new_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_new);
  if FuncLoadError then
  begin
{$IF not defined(OSSL_ENCODER_CTX_new_allownil)}
    OSSL_ENCODER_CTX_new := ERR_OSSL_ENCODER_CTX_new;
{$IFEND}
{$IF declared(OSSL_ENCODER_CTX_new_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_new_introduced then
    begin
{$IF declared(FC_OSSL_ENCODER_CTX_new)}
      OSSL_ENCODER_CTX_new := FC_OSSL_ENCODER_CTX_new;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(OSSL_ENCODER_CTX_new_removed)}
    if OSSL_ENCODER_CTX_new_removed <= LibVersion then
    begin
{$IF declared(_OSSL_ENCODER_CTX_new)}
      OSSL_ENCODER_CTX_new := _OSSL_ENCODER_CTX_new;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(OSSL_ENCODER_CTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_new');
{$IFEND}
  end;

  OSSL_ENCODER_CTX_set_params := LoadLibFunction(ADllHandle,
    OSSL_ENCODER_CTX_set_params_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_set_params);
  if FuncLoadError then
  begin
{$IF not defined(OSSL_ENCODER_CTX_set_params_allownil)}
    OSSL_ENCODER_CTX_set_params := ERR_OSSL_ENCODER_CTX_set_params;
{$IFEND}
{$IF declared(OSSL_ENCODER_CTX_set_params_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_set_params_introduced then
    begin
{$IF declared(FC_OSSL_ENCODER_CTX_set_params)}
      OSSL_ENCODER_CTX_set_params := FC_OSSL_ENCODER_CTX_set_params;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(OSSL_ENCODER_CTX_set_params_removed)}
    if OSSL_ENCODER_CTX_set_params_removed <= LibVersion then
    begin
{$IF declared(_OSSL_ENCODER_CTX_set_params)}
      OSSL_ENCODER_CTX_set_params := _OSSL_ENCODER_CTX_set_params;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(OSSL_ENCODER_CTX_set_params_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_set_params');
{$IFEND}
  end;

  OSSL_ENCODER_CTX_free := LoadLibFunction(ADllHandle,
    OSSL_ENCODER_CTX_free_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_free);
  if FuncLoadError then
  begin
{$IF not defined(OSSL_ENCODER_CTX_free_allownil)}
    OSSL_ENCODER_CTX_free := ERR_OSSL_ENCODER_CTX_free;
{$IFEND}
{$IF declared(OSSL_ENCODER_CTX_free_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_free_introduced then
    begin
{$IF declared(FC_OSSL_ENCODER_CTX_free)}
      OSSL_ENCODER_CTX_free := FC_OSSL_ENCODER_CTX_free;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(OSSL_ENCODER_CTX_free_removed)}
    if OSSL_ENCODER_CTX_free_removed <= LibVersion then
    begin
{$IF declared(_OSSL_ENCODER_CTX_free)}
      OSSL_ENCODER_CTX_free := _OSSL_ENCODER_CTX_free;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(OSSL_ENCODER_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_free');
{$IFEND}
  end;


  OSSL_ENCODER_CTX_set_passphrase := LoadLibFunction(ADllHandle,
    OSSL_ENCODER_CTX_set_passphrase_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_set_passphrase);
  if FuncLoadError then
  begin
{$IF not defined(OSSL_ENCODER_CTX_set_passphrase_allownil)}
    OSSL_ENCODER_CTX_set_passphrase := ERR_OSSL_ENCODER_CTX_set_passphrase;
{$IFEND}
{$IF declared(OSSL_ENCODER_CTX_set_passphrase_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_set_passphrase_introduced then
    begin
{$IF declared(FC_OSSL_ENCODER_CTX_set_passphrase)}
      OSSL_ENCODER_CTX_set_passphrase := FC_OSSL_ENCODER_CTX_set_passphrase;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(OSSL_ENCODER_CTX_set_passphrase_removed)}
    if OSSL_ENCODER_CTX_set_passphrase_removed <= LibVersion then
    begin
{$IF declared(_OSSL_ENCODER_CTX_set_passphrase)}
      OSSL_ENCODER_CTX_set_passphrase := _OSSL_ENCODER_CTX_set_passphrase;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(OSSL_ENCODER_CTX_set_passphrase_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_set_passphrase');
{$IFEND}
  end;

  OSSL_ENCODER_CTX_set_pem_password_cb := LoadLibFunction(ADllHandle,
    OSSL_ENCODER_CTX_set_pem_password_cb_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_set_pem_password_cb);
  if FuncLoadError then
  begin
{$IF not defined(OSSL_ENCODER_CTX_set_pem_password_cb_allownil)}
    OSSL_ENCODER_CTX_set_pem_password_cb := ERR_OSSL_ENCODER_CTX_set_pem_password_cb;
{$IFEND}
{$IF declared(OSSL_ENCODER_CTX_set_pem_password_cb_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_set_pem_password_cb_introduced then
    begin
{$IF declared(FC_OSSL_ENCODER_CTX_set_pem_password_cb)}
      OSSL_ENCODER_CTX_set_pem_password_cb := FC_OSSL_ENCODER_CTX_set_pem_password_cb;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(OSSL_ENCODER_CTX_set_pem_password_cb_removed)}
    if OSSL_ENCODER_CTX_set_pem_password_cb_removed <= LibVersion then
    begin
{$IF declared(_OSSL_ENCODER_CTX_set_pem_password_cb)}
      OSSL_ENCODER_CTX_set_pem_password_cb := _OSSL_ENCODER_CTX_set_pem_password_cb;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(OSSL_ENCODER_CTX_set_pem_password_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_set_pem_password_cb');
{$IFEND}
  end;

  OSSL_ENCODER_CTX_set_passphrase_cb := LoadLibFunction(ADllHandle,
    OSSL_ENCODER_CTX_set_passphrase_cb_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_set_passphrase_cb);
  if FuncLoadError then
  begin
{$IF not defined(OSSL_ENCODER_CTX_set_passphrase_cb_allownil)}
    OSSL_ENCODER_CTX_set_passphrase_cb := ERR_OSSL_ENCODER_CTX_set_passphrase_cb;
{$IFEND}
{$IF declared(OSSL_ENCODER_CTX_set_passphrase_cb_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_set_passphrase_cb_introduced then
    begin
{$IF declared(FC_OSSL_ENCODER_CTX_set_passphrase_cb)}
      OSSL_ENCODER_CTX_set_passphrase_cb := FC_OSSL_ENCODER_CTX_set_passphrase_cb;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(OSSL_ENCODER_CTX_set_passphrase_cb_removed)}
    if OSSL_ENCODER_CTX_set_passphrase_cb_removed <= LibVersion then
    begin
{$IF declared(_OSSL_ENCODER_CTX_set_passphrase_cb)}
      OSSL_ENCODER_CTX_set_passphrase_cb := _OSSL_ENCODER_CTX_set_passphrase_cb;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(OSSL_ENCODER_CTX_set_passphrase_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_set_passphrase_cb');
{$IFEND}
  end;

  OSSL_ENCODER_CTX_set_passphrase_ui := LoadLibFunction(ADllHandle,
    OSSL_ENCODER_CTX_set_passphrase_ui_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_set_passphrase_ui);
  if FuncLoadError then
  begin
{$IF not defined(OSSL_ENCODER_CTX_set_passphrase_ui_allownil)}
    OSSL_ENCODER_CTX_set_passphrase_ui := ERR_OSSL_ENCODER_CTX_set_passphrase_ui;
{$IFEND}
{$IF declared(OSSL_ENCODER_CTX_set_passphrase_ui_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_set_passphrase_ui_introduced then
    begin
{$IF declared(FC_OSSL_ENCODER_CTX_set_passphrase_ui)}
      OSSL_ENCODER_CTX_set_passphrase_ui := FC_OSSL_ENCODER_CTX_set_passphrase_ui;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(OSSL_ENCODER_CTX_set_passphrase_ui_removed)}
    if OSSL_ENCODER_CTX_set_passphrase_ui_removed <= LibVersion then
    begin
{$IF declared(_OSSL_ENCODER_CTX_set_passphrase_ui)}
      OSSL_ENCODER_CTX_set_passphrase_ui := _OSSL_ENCODER_CTX_set_passphrase_ui;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(OSSL_ENCODER_CTX_set_passphrase_ui_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_set_passphrase_ui');
{$IFEND}
  end;

  OSSL_ENCODER_CTX_set_cipher := LoadLibFunction(ADllHandle,
    OSSL_ENCODER_CTX_set_cipher_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_set_cipher);
  if FuncLoadError then
  begin
{$IF not defined(OSSL_ENCODER_CTX_set_cipher_allownil)}
    OSSL_ENCODER_CTX_set_cipher := ERR_OSSL_ENCODER_CTX_set_cipher;
{$IFEND}
{$IF declared(OSSL_ENCODER_CTX_set_cipher_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_set_cipher_introduced then
    begin
{$IF declared(FC_OSSL_ENCODER_CTX_set_cipher)}
      OSSL_ENCODER_CTX_set_cipher := FC_OSSL_ENCODER_CTX_set_cipher;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(OSSL_ENCODER_CTX_set_cipher_removed)}
    if OSSL_ENCODER_CTX_set_cipher_removed <= LibVersion then
    begin
{$IF declared(_OSSL_ENCODER_CTX_set_cipher)}
      OSSL_ENCODER_CTX_set_cipher := _OSSL_ENCODER_CTX_set_cipher;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(OSSL_ENCODER_CTX_set_cipher_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_set_cipher');
{$IFEND}
  end;

  OSSL_ENCODER_CTX_set_selection := LoadLibFunction(ADllHandle,
    OSSL_ENCODER_CTX_set_selection_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_set_selection);
  if FuncLoadError then
  begin
{$IF not defined(OSSL_ENCODER_CTX_set_selection_allownil)}
    OSSL_ENCODER_CTX_set_selection := ERR_OSSL_ENCODER_CTX_set_selection;
{$IFEND}
{$IF declared(OSSL_ENCODER_CTX_set_selection_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_set_selection_introduced then
    begin
{$IF declared(FC_OSSL_ENCODER_CTX_set_selection)}
      OSSL_ENCODER_CTX_set_selection := FC_OSSL_ENCODER_CTX_set_selection;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(OSSL_ENCODER_CTX_set_selection_removed)}
    if OSSL_ENCODER_CTX_set_selection_removed <= LibVersion then
    begin
{$IF declared(_OSSL_ENCODER_CTX_set_selection)}
      OSSL_ENCODER_CTX_set_selection := _OSSL_ENCODER_CTX_set_selection;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(OSSL_ENCODER_CTX_set_selection_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_set_selection');
{$IFEND}
  end;

  OSSL_ENCODER_CTX_set_output_type := LoadLibFunction(ADllHandle,
    OSSL_ENCODER_CTX_set_output_type_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_set_output_type);
  if FuncLoadError then
  begin
{$IF not defined(OSSL_ENCODER_CTX_set_output_type_allownil)}
    OSSL_ENCODER_CTX_set_output_type := ERR_OSSL_ENCODER_CTX_set_output_type;
{$IFEND}
{$IF declared(OSSL_ENCODER_CTX_set_output_type_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_set_output_type_introduced then
    begin
{$IF declared(FC_OSSL_ENCODER_CTX_set_output_type)}
      OSSL_ENCODER_CTX_set_output_type := FC_OSSL_ENCODER_CTX_set_output_type;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(OSSL_ENCODER_CTX_set_output_type_removed)}
    if OSSL_ENCODER_CTX_set_output_type_removed <= LibVersion then
    begin
{$IF declared(_OSSL_ENCODER_CTX_set_output_type)}
      OSSL_ENCODER_CTX_set_output_type := _OSSL_ENCODER_CTX_set_output_type;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(OSSL_ENCODER_CTX_set_output_type_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_set_output_type');
{$IFEND}
  end;

  OSSL_ENCODER_CTX_set_output_structure := LoadLibFunction(ADllHandle,
    OSSL_ENCODER_CTX_set_output_structure_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_set_output_structure);
  if FuncLoadError then
  begin
{$IF not defined(OSSL_ENCODER_CTX_set_output_structure_allownil)}
    OSSL_ENCODER_CTX_set_output_structure := ERR_OSSL_ENCODER_CTX_set_output_structure;
{$IFEND}
{$IF declared(OSSL_ENCODER_CTX_set_output_structure_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_set_output_structure_introduced then
    begin
{$IF declared(FC_OSSL_ENCODER_CTX_set_output_structure)}
      OSSL_ENCODER_CTX_set_output_structure := FC_OSSL_ENCODER_CTX_set_output_structure;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(OSSL_ENCODER_CTX_set_output_structure_removed)}
    if OSSL_ENCODER_CTX_set_output_structure_removed <= LibVersion then
    begin
{$IF declared(_OSSL_ENCODER_CTX_set_output_structure)}
      OSSL_ENCODER_CTX_set_output_structure := _OSSL_ENCODER_CTX_set_output_structure;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(OSSL_ENCODER_CTX_set_output_structure_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_set_output_structure');
{$IFEND}
  end;

  OSSL_ENCODER_to_bio := LoadLibFunction(ADllHandle,
    OSSL_ENCODER_to_bio_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_to_bio);
  if FuncLoadError then
  begin
{$IF not defined(OSSL_ENCODER_to_bio_allownil)}
    OSSL_ENCODER_to_bio := ERR_OSSL_ENCODER_to_bio;
{$IFEND}
{$IF declared(OSSL_ENCODER_to_bio_introduced)}
    if LibVersion < OSSL_ENCODER_to_bio_introduced then
    begin
{$IF declared(FC_OSSL_ENCODER_to_bio)}
      OSSL_ENCODER_to_bio := FC_OSSL_ENCODER_to_bio;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(OSSL_ENCODER_to_bio_removed)}
    if OSSL_ENCODER_to_bio_removed <= LibVersion then
    begin
{$IF declared(_OSSL_ENCODER_to_bio)}
      OSSL_ENCODER_to_bio := _OSSL_ENCODER_to_bio;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(OSSL_ENCODER_to_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_to_bio');
{$IFEND}
  end;

  OSSL_ENCODER_to_data := LoadLibFunction(ADllHandle,
    OSSL_ENCODER_to_data_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_to_data);
  if FuncLoadError then
  begin
{$IF not defined(OSSL_ENCODER_to_data_allownil)}
    OSSL_ENCODER_to_data := ERR_OSSL_ENCODER_to_data;
{$IFEND}
{$IF declared(OSSL_ENCODER_to_data_introduced)}
    if LibVersion < OSSL_ENCODER_to_data_introduced then
    begin
{$IF declared(FC_OSSL_ENCODER_to_data)}
      OSSL_ENCODER_to_data := FC_OSSL_ENCODER_to_data;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(OSSL_ENCODER_to_data_removed)}
    if OSSL_ENCODER_to_data_removed <= LibVersion then
    begin
{$IF declared(_OSSL_ENCODER_to_data)}
      OSSL_ENCODER_to_data := _OSSL_ENCODER_to_data;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(OSSL_ENCODER_to_data_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_to_data');
{$IFEND}
  end;

  OSSL_ENCODER_CTX_new_for_pkey := LoadLibFunction(ADllHandle,
    OSSL_ENCODER_CTX_new_for_pkey_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_new_for_pkey);
  if FuncLoadError then
  begin
{$IF not defined(OSSL_ENCODER_CTX_new_for_pkey_allownil)}
    OSSL_ENCODER_CTX_new_for_pkey := ERR_OSSL_ENCODER_CTX_new_for_pkey;
{$IFEND}
{$IF declared(OSSL_ENCODER_CTX_new_for_pkey_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_new_for_pkey_introduced then
    begin
{$IF declared(FC_OSSL_ENCODER_CTX_new_for_pkey)}
      OSSL_ENCODER_CTX_new_for_pkey := FC_OSSL_ENCODER_CTX_new_for_pkey;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(OSSL_ENCODER_CTX_new_for_pkey_removed)}
    if OSSL_ENCODER_CTX_new_for_pkey_removed <= LibVersion then
    begin
{$IF declared(_OSSL_ENCODER_CTX_new_for_pkey)}
      OSSL_ENCODER_CTX_new_for_pkey := _OSSL_ENCODER_CTX_new_for_pkey;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(OSSL_ENCODER_CTX_new_for_pkey_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_new_for_pkey');
{$IFEND}
  end;

end;

{$I TaurusTLSUnusedParamOn.inc}

procedure Unload;
begin
  OSSL_ENCODER_fetch := nil;
  OSSL_ENCODER_up_ref := nil;
  OSSL_ENCODER_free := nil;

  OSSL_ENCODER_get0_provider := nil;
  OSSL_ENCODER_get0_properties := nil;
  OSSL_ENCODER_get0_name := nil;
  OSSL_ENCODER_get0_description := nil;
  OSSL_ENCODER_is_a := nil;

  OSSL_ENCODER_do_all_provided := nil;
  OSSL_ENCODER_names_do_all := nil;
  OSSL_ENCODER_gettable_params := nil;
  OSSL_ENCODER_get_params := nil;

  OSSL_ENCODER_CTX_set_passphrase := nil;
  OSSL_ENCODER_CTX_set_pem_password_cb := nil;
  OSSL_ENCODER_CTX_set_passphrase_cb := nil;
  OSSL_ENCODER_CTX_set_passphrase_ui := nil;
  OSSL_ENCODER_CTX_set_cipher := nil;
  OSSL_ENCODER_CTX_set_selection := nil;
  OSSL_ENCODER_CTX_set_output_type := nil;
  OSSL_ENCODER_CTX_set_output_structure := nil;

  OSSL_ENCODER_to_bio := nil;
  OSSL_ENCODER_to_data := nil;
end;
  {$ENDIF}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

initialization

Register_SSLLoader(Load, 'LibCrypto');
Register_SSLUnloader(Unload);
{$ENDIF}

end.
