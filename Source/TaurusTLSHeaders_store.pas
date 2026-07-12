/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_async.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_async.h2pas
     and this file regenerated. TaurusTLSHeaders_async.h2pas is distributed with the full Indy
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
unit TaurusTLSHeaders_store;

interface
{$I TaurusTLSUnusedUnitOff.inc}
uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_core;

type
  {$EXTERNALSYM OSSL_STORE_CTX}
  OSSL_STORE_CTX  = record end;
  {$EXTERNALSYM POSSL_STORE_CTX}
  POSSL_STORE_CTX  = ^OSSL_STORE_CTX;
  {$EXTERNALSYM PPOSSL_STORE_CTX}
  PPOSSL_STORE_CTX = ^POSSL_STORE_CTX;
  {$EXTERNALSYM OSSL_STORE_LOADER}
  OSSL_STORE_LOADER = record end;
  {$EXTERNALSYM POSSL_STORE_LOADER}
  POSSL_STORE_LOADER = ^OSSL_STORE_LOADER;
  {$EXTERNALSYM PPOSSL_STORE_LOADER}
  PPOSSL_STORE_LOADER = ^POSSL_STORE_LOADER;

{*
 * Typedef for the OSSL_STORE_INFO post processing callback.  This can be used
 * to massage the given OSSL_STORE_INFO, or to drop it entirely (by returning
 * NULL).
 *}
  {$EXTERNALSYM OSSL_STORE_post_process_info_fn}
  OSSL_STORE_post_process_info_fn = function(arg1 : POSSL_STORE_INFO;
      arg2 : Pointer): POSSL_STORE_INFO cdecl;
  {$EXTERNALSYM OSSL_STORE_LOADER_do_all_provided_fn}
  OSSL_STORE_LOADER_do_all_provided_fn = procedure(loader: POSSL_STORE_LOADER; arg: Pointer); cdecl;
  {$EXTERNALSYM OSSL_STORE_LOADER_names_do_all_fn}
  OSSL_STORE_LOADER_names_do_all_fn = procedure(const name: PIdAnsiChar; data: Pointer); cdecl;

const

{*
 * Types of data that can be ossl_stored in a OSSL_STORE_INFO.
 * OSSL_STORE_INFO_NAME is typically found when getting a listing of
 * available "files" / "tokens" / what have you.
 *}
  {$EXTERNALSYM OSSL_STORE_INFO_NAME}
  OSSL_STORE_INFO_NAME          = 1;   //* char * */
  {$EXTERNALSYM OSSL_STORE_INFO_PARAMS}
  OSSL_STORE_INFO_PARAMS        = 2;   //* EVP_PKEY * */
  {$EXTERNALSYM OSSL_STORE_INFO_PUBKEY}
  OSSL_STORE_INFO_PUBKEY        = 3;   //* EVP_PKEY * */
  {$EXTERNALSYM OSSL_STORE_INFO_PKEY}
  OSSL_STORE_INFO_PKEY          = 4;   //* EVP_PKEY * */
  {$EXTERNALSYM OSSL_STORE_INFO_CERT}
  OSSL_STORE_INFO_CERT          = 5;   //* X509 * */
  {$EXTERNALSYM OSSL_STORE_INFO_CRL}
  OSSL_STORE_INFO_CRL           = 6;   //* X509_CRL * */

//* OSSL_STORE search types */
  {$EXTERNALSYM d_OSSL_STORE_SEARCH_BY_NAME}
  d_OSSL_STORE_SEARCH_BY_NAME             = 1; //* subject in certs, issuer in CRLs */
  {$EXTERNALSYM d_OSSL_STORE_SEARCH_BY_ISSUER_SERIAL}
  d_OSSL_STORE_SEARCH_BY_ISSUER_SERIAL    = 2;
  {$EXTERNALSYM d_OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT}
  d_OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT  = 3;
  {$EXTERNALSYM d_OSSL_STORE_SEARCH_BY_ALIAS}
  d_OSSL_STORE_SEARCH_BY_ALIAS            = 4;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
{*
 * Open a channel given a URI.  The given UI method will be used any time the
 * loader needs extra input, for example when a password or pin is needed, and
 * will be passed the same user data every time it's needed in this context.
 *
 * Returns a context reference which represents the channel to communicate
 * through.
 *}
  {$EXTERNALSYM OSSL_STORE_open}
 OSSL_STORE_open : function (const uri : PIdAnsiChar; const ui_method : PUI_METHOD;
                ui_data : Pointer;
                post_process : OSSL_STORE_post_process_info_fn;
                post_process_data : Pointer) : POSSL_STORE_CTX cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM OSSL_STORE_open_ex}
  OSSL_STORE_open_ex : function(const uri : PIdAnsiChar; libctx : POSSL_LIB_CTX; const propq : PIdAnsiChar;
                   const ui_method : PUI_METHOD; ui_data : Pointer;
                   const params : POSSL_PARAM_ARRAY;
                   post_process : OSSL_STORE_post_process_info_fn;
                   post_process_data : Pointer) : POSSL_STORE_CTX cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_load}
  OSSL_STORE_load : function(ctx : POSSL_STORE_CTX) : POSSL_STORE_INFO cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_delete}
  OSSL_STORE_delete : function(const uri : PIdAnsiChar; libctx : POSSL_LIB_CTX; const propq : PIdAnsiChar;
                      const ui_method : PUI_METHOD; ui_data : Pointer;
                      const  params : POSSL_PARAM_ARRAY) : TIdC_INT cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_eof}
  OSSL_STORE_eof : function(ctx : POSSL_STORE_CTX) : TIdC_INT cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_error}
  OSSL_STORE_error: function(ctx : POSSL_STORE_CTX) : TIdC_INT cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_close}
  OSSL_STORE_close : function(ctx : POSSL_STORE_CTX) : TIdC_INT cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_attach}
  OSSL_STORE_attach : function(bio : PBIO; const scheme : PIdAnsiChar;
                             libctx : POSSL_LIB_CTX; const propq : PIdAnsiChar;
                             const ui_method : PUI_METHOD; ui_data : Pointer;
                             const  params : POSSL_PARAM_ARRAY;
                             post_process : OSSL_STORE_post_process_info_fn;
                             post_process_data : Pointer) : POSSL_STORE_CTX cdecl = nil;

{/*
 * Functions to generate OSSL_STORE_INFOs, one function for each type we
 * support having in them, as well as a generic constructor.
 *
 * In all cases, ownership of the object is transferred to the OSSL_STORE_INFO
 * and will therefore be freed when the OSSL_STORE_INFO is freed.
 *}
  {$EXTERNALSYM OSSL_STORE_INFO_new}
  OSSL_STORE_INFO_new : function(type_ : TIdC_INT; data : Pointer) : POSSL_STORE_INFO cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_new_NAME}
  OSSL_STORE_INFO_new_NAME : function(name : PIdAnsiChar) : POSSL_STORE_INFO cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_set0_NAME_description}
  OSSL_STORE_INFO_set0_NAME_description : function(info : POSSL_STORE_INFO; desc : PIdAnsiChar) : TIdC_INT cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_new_PARAMS}
  OSSL_STORE_INFO_new_PARAMS : function(params : PEVP_PKEY) : POSSL_STORE_INFO cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_new_PUBKEY}
  OSSL_STORE_INFO_new_PUBKEY : function(pubkey : PEVP_PKEY) : POSSL_STORE_INFO cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_new_PKEY}
  OSSL_STORE_INFO_new_PKEY : function(pkey : PEVP_PKEY) : POSSL_STORE_INFO cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_new_CERT}
  OSSL_STORE_INFO_new_CERT : function(x509 : PX509) : POSSL_STORE_INFO cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_new_CRL}
  OSSL_STORE_INFO_new_CRL : function(crl : PX509_CRL) : POSSL_STORE_INFO cdecl = nil;

  {$EXTERNALSYM OSSL_STORE_INFO_get_type}
  OSSL_STORE_INFO_get_type : function(const info : POSSL_STORE_INFO) : TIdC_INT  cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get0_data}
  OSSL_STORE_INFO_get0_data : function(type_ : TIdC_INT; const info : POSSL_STORE_INFO) : Pointer cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get0_NAME}
  OSSL_STORE_INFO_get0_NAME : function(const info : POSSL_STORE_INFO) : PIdAnsiChar cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get1_NAME}
  OSSL_STORE_INFO_get1_NAME : function(const info : POSSL_STORE_INFO) : PIdAnsiChar cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get0_NAME_description}
  OSSL_STORE_INFO_get0_NAME_description : function(const info : POSSL_STORE_INFO) : PIdAnsiChar cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get1_NAME_description}
  OSSL_STORE_INFO_get1_NAME_description : function(const info : POSSL_STORE_INFO) : PIdAnsiChar cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get0_PARAMS}
  OSSL_STORE_INFO_get0_PARAMS : function(const info : POSSL_STORE_INFO) : PEVP_PKEY cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get1_PARAMS}
  OSSL_STORE_INFO_get1_PARAMS : function(const info  : POSSL_STORE_INFO) : PEVP_PKEY  cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get0_PUBKEY}
  OSSL_STORE_INFO_get0_PUBKEY : function(const info : POSSL_STORE_INFO) : PEVP_PKEY  cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get1_PUBKEY}
  OSSL_STORE_INFO_get1_PUBKEY : function(const info  : POSSL_STORE_INFO) : PEVP_PKEY  cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get0_PKEY}
  OSSL_STORE_INFO_get0_PKEY : function(const info  : POSSL_STORE_INFO) : PEVP_PKEY cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get1_PKEY}
  OSSL_STORE_INFO_get1_PKEY : function(const info  : POSSL_STORE_INFO) : PEVP_PKEY  cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get0_CERT}
  OSSL_STORE_INFO_get0_CERT : function(const info : POSSL_STORE_INFO) : PX509  cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get1_CERT}
  OSSL_STORE_INFO_get1_CERT : function(const info : POSSL_STORE_INFO) : PX509  cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get0_CRL}
  OSSL_STORE_INFO_get0_CRL : function(const info : POSSL_STORE_INFO) : PX509_CRL  cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get1_CRL}
  OSSL_STORE_INFO_get1_CRL : function(const info : POSSL_STORE_INFO) : PX509_CRL  cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_type_string}
  OSSL_STORE_INFO_type_string : function(type_ : TIdC_INT) : PIdAnsiChar cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_free}
  OSSL_STORE_INFO_free : procedure(info : POSSL_STORE_INFO) cdecl = nil;

//* To check what search types the scheme handler supports */
  {$EXTERNALSYM OSSL_STORE_supports_search}
  OSSL_STORE_supports_search : function(ctx : POSSL_STORE_CTX; search_type : TIdC_INT) : TIdC_INT cdecl = nil;


//* Search term constructors */
{*
 * The input is considered to be owned by the caller, and must therefore
 * remain present throughout the lifetime of the returned OSSL_STORE_SEARCH
 *}
  {$EXTERNALSYM OSSL_STORE_SEARCH_by_name}
  OSSL_STORE_SEARCH_by_name : function(name : PX509_NAME) : POSSL_STORE_SEARCH; cdecl = nil;
  OSSL_STORE_SEARCH_by_issuer_serial : function(name : PX509_NAME;
    const serial : PASN1_INTEGER) : POSSL_STORE_SEARCH  cdecl = nil;
  OSSL_STORE_SEARCH_by_key_fingerprint : function(const digest : PEVP_MD;
    const bytes : PIdAnsiChar; len : TIdC_SIZET) : POSSL_STORE_SEARCH  cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_SEARCH_by_alias}
  OSSL_STORE_SEARCH_by_alias : function(const alias : PIdAnsiChar) : POSSL_STORE_SEARCH  cdecl = nil;

//* Search term destructor */
  {$EXTERNALSYM OSSL_STORE_SEARCH_free}
  OSSL_STORE_SEARCH_free : procedure(search : POSSL_STORE_SEARCH) cdecl = nil;

//* Search term accessors */
  {$EXTERNALSYM OSSL_STORE_SEARCH_get_type}
  OSSL_STORE_SEARCH_get_type : function(const criterion : POSSL_STORE_SEARCH) : TIdC_INT  cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_SEARCH_get0_name}
  OSSL_STORE_SEARCH_get0_name : function(const criterion : POSSL_STORE_SEARCH) : PX509_NAME  cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_SEARCH_get0_serial}
  OSSL_STORE_SEARCH_get0_serial : function(const criterion : POSSL_STORE_SEARCH) : PASN1_INTEGER  cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_SEARCH_get0_bytes}
  OSSL_STORE_SEARCH_get0_bytes : function(const criterion : POSSL_STORE_SEARCH; var length_ : TIdC_SIZET) : PByte  cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_SEARCH_get0_string}
  OSSL_STORE_SEARCH_get0_string : function(const  criterion : POSSL_STORE_SEARCH) : PIdAnsiChar  cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_SEARCH_get0_digest}
  OSSL_STORE_SEARCH_get0_digest : function(const  criterion : POSSL_STORE_SEARCH) : PEVP_MD  cdecl = nil;

{*
 * Add search criterion and expected return type (which can be unspecified)
 * to the loading channel.  This MUST happen before the first OSSL_STORE_load().
 *}
  {$EXTERNALSYM OSSL_STORE_expect}
 OSSL_STORE_expect : function(ctx : POSSL_STORE_CTX; expected_type : TIdC_INT) : TIdC_INT cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_find}
 OSSL_STORE_find : function(ctx : POSSL_STORE_CTX; const  search : POSSL_STORE_SEARCH) : TIdC_INT cdecl = nil;

{*-
 *  Function to fetch a loader and extract data from it
 *  ---------------------------------------------------
 *}
 {$EXTERNALSYM OSSL_STORE_LOADER_fetch}
 OSSL_STORE_LOADER_fetch : function(libctx : POSSL_LIB_CTX;
    const scheme, properties : PIdAnsiChar) : POSSL_STORE_LOADER cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_LOADER_up_ref}
 OSSL_STORE_LOADER_up_ref : function(loader : POSSL_STORE_LOADER) : TIdC_INT cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_LOADER_free}
 OSSL_STORE_LOADER_free : procedure(loader : POSSL_STORE_LOADER) cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_LOADER_get0_provider}
  OSSL_STORE_LOADER_get0_provider : function(const loader : POSSL_STORE_LOADER) : POSSL_PROVIDER cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_LOADER_get0_properties}
 OSSL_STORE_LOADER_get0_properties : function(const loader : POSSL_STORE_LOADER) : PIdAnsiChar cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_LOADER_get0_description}
 OSSL_STORE_LOADER_get0_description : function(const loader : POSSL_STORE_LOADER) : PIdAnsiChar  cdecl = nil;
 {$EXTERNALSYM OSSL_STORE_LOADER_is_a}
 OSSL_STORE_LOADER_is_a : function(const loader : POSSL_STORE_LOADER;
                           const scheme : PIdAnsiChar) : TIdC_INT  cdecl = nil;
 {$EXTERNALSYM OSSL_STORE_LOADER_do_all_provided}
 OSSL_STORE_LOADER_do_all_provided : procedure(libctx : POSSL_LIB_CTX;
                                       fn : OSSL_STORE_LOADER_do_all_provided_fn;
                                       arg : Pointer)  cdecl = nil;
 {$EXTERNALSYM OSSL_STORE_LOADER_names_do_all}
 OSSL_STORE_LOADER_names_do_all : function(const loader : POSSL_STORE_LOADER;
                                   fn : OSSL_STORE_LOADER_names_do_all_fn;
                                   data : Pointer) : TIdC_INT  cdecl = nil;
{$ELSE}
{*
 * Open a channel given a URI.  The given UI method will be used any time the
 * loader needs extra input, for example when a password or pin is needed, and
 * will be passed the same user data every time it's needed in this context.
 *
 * Returns a context reference which represents the channel to communicate
 * through.
 *}

  {$EXTERNALSYM OSSL_STORE_open}
 function OSSL_STORE_open(const uri : PIdAnsiChar; const ui_method : PUI_METHOD;
                ui_data : Pointer;
                post_process : OSSL_STORE_post_process_info_fn;
                post_process_data : Pointer) : POSSL_STORE_CTX cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM OSSL_STORE_open_ex}
  function OSSL_STORE_open_ex(const uri : PIdAnsiChar; libctx : POSSL_LIB_CTX; const propq : PIdAnsiChar;
                   const ui_method : PUI_METHOD; ui_data : Pointer;
                   const params : POSSL_PARAM_ARRAY;
                   post_process : OSSL_STORE_post_process_info_fn;
                   post_process_data : Pointer) : POSSL_STORE_CTX cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_load}
  function OSSL_STORE_load(ctx : POSSL_STORE_CTX) : POSSL_STORE_INFO cdecl; external CLibCrypto;

  {$EXTERNALSYM OSSL_STORE_delete}
  function OSSL_STORE_delete(const uri : PIdAnsiChar; libctx : POSSL_LIB_CTX; const propq : PIdAnsiChar;
                      const ui_method : PUI_METHOD; ui_data : Pointer;
                      const  params : POSSL_PARAM_ARRAY) : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_eof}
  function OSSL_STORE_eof(ctx : POSSL_STORE_CTX) : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_error}
  function OSSL_STORE_error(ctx : POSSL_STORE_CTX) : TIdC_INT  cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_close}
  function OSSL_STORE_close(ctx : POSSL_STORE_CTX) : TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM OSSL_STORE_attach}
  function OSSL_STORE_attach(bio : PBIO; const scheme : PIdAnsiChar;
                             libctx : POSSL_LIB_CTX; const propq : PIdAnsiChar;
                             const ui_method : PUI_METHOD; ui_data : Pointer;
                             const  params : POSSL_PARAM_ARRAY;
                             post_process : OSSL_STORE_post_process_info_fn;
                             post_process_data : Pointer) : POSSL_STORE_CTX cdecl; external CLibCrypto;

{/*
 * Functions to generate OSSL_STORE_INFOs, one function for each type we
 * support having in them, as well as a generic constructor.
 *
 * In all cases, ownership of the object is transferred to the OSSL_STORE_INFO
 * and will therefore be freed when the OSSL_STORE_INFO is freed.
 *}
  {$EXTERNALSYM OSSL_STORE_INFO_new}
  function OSSL_STORE_INFO_new(type_ : TIdC_INT; data : Pointer) : POSSL_STORE_INFO cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_INFO_new_NAME}
  function OSSL_STORE_INFO_new_NAME(name : PIdAnsiChar) : POSSL_STORE_INFO cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_INFO_set0_NAME_description}
  function OSSL_STORE_INFO_set0_NAME_description(info : POSSL_STORE_INFO; desc : PIdAnsiChar) : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_INFO_new_PARAMS}
  function OSSL_STORE_INFO_new_PARAMS(params : PEVP_PKEY) : POSSL_STORE_INFO cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_INFO_new_PUBKEY}
  function OSSL_STORE_INFO_new_PUBKEY(pubkey : PEVP_PKEY) : POSSL_STORE_INFO cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_INFO_new_PKEY}
  function OSSL_STORE_INFO_new_PKEY(pkey : PEVP_PKEY) : POSSL_STORE_INFO cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_INFO_new_CERT}
  function OSSL_STORE_INFO_new_CERT(x509 : PX509) : POSSL_STORE_INFO cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_INFO_new_CRL}
  function OSSL_STORE_INFO_new_CRL(crl : PX509_CRL) : POSSL_STORE_INFO cdecl; external CLibCrypto;
{*
 * Functions to try to extract data from a OSSL_STORE_INFO.
 *}
  {$EXTERNALSYM OSSL_STORE_INFO_get_type}
  function OSSL_STORE_INFO_get_type(const info : POSSL_STORE_INFO) : TIdC_INT  cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_INFO_get0_data}
  function OSSL_STORE_INFO_get0_data(type_ : TIdC_INT; const info : POSSL_STORE_INFO) : Pointer cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_INFO_get0_NAME}
  function OSSL_STORE_INFO_get0_NAME(const info : POSSL_STORE_INFO) : PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_INFO_get1_NAME}
  function OSSL_STORE_INFO_get1_NAME(const info : POSSL_STORE_INFO) : PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_INFO_get0_NAME_description}
  function OSSL_STORE_INFO_get0_NAME_description(const info : POSSL_STORE_INFO) : PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_INFO_get1_NAME_description}
  function OSSL_STORE_INFO_get1_NAME_description(const info : POSSL_STORE_INFO) : PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_INFO_get0_PARAMS}
  function OSSL_STORE_INFO_get0_PARAMS(const info : POSSL_STORE_INFO) : PEVP_PKEY cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_INFO_get1_PARAMS}
  function OSSL_STORE_INFO_get1_PARAMS(const info  : POSSL_STORE_INFO) : PEVP_PKEY cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_INFO_get0_PUBKEY}
  function OSSL_STORE_INFO_get0_PUBKEY(const info : POSSL_STORE_INFO) : PEVP_PKEY cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_INFO_get1_PUBKEY}
  function OSSL_STORE_INFO_get1_PUBKEY(const info  : POSSL_STORE_INFO) : PEVP_PKEY cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_INFO_get0_PKEY}
  function OSSL_STORE_INFO_get0_PKEY(const info  : POSSL_STORE_INFO) : PEVP_PKEY cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_INFO_get1_PKEY}
  function OSSL_STORE_INFO_get1_PKEY(const info  : POSSL_STORE_INFO) : PEVP_PKEY cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_INFO_get0_CERT}
  function OSSL_STORE_INFO_get0_CERT(const info : POSSL_STORE_INFO) : PX509 cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_INFO_get1_CERT}
  function OSSL_STORE_INFO_get1_CERT(const info : POSSL_STORE_INFO) : PX509 cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_INFO_get0_CRL}
  function OSSL_STORE_INFO_get0_CRL(const info : POSSL_STORE_INFO) : PX509_CRL cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_INFO_get1_CRL}
  function OSSL_STORE_INFO_get1_CRL(const info : POSSL_STORE_INFO) : PX509_CRL cdecl; external CLibCrypto;

  {$EXTERNALSYM OSSL_STORE_INFO_type_string}
  function OSSL_STORE_INFO_type_string(type_ : TIdC_INT) : PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_INFO_free}
  procedure OSSL_STORE_INFO_free(info : POSSL_STORE_INFO) cdecl; external CLibCrypto;

//* To check what search types the scheme handler supports */
  {$EXTERNALSYM OSSL_STORE_supports_search}
  function OSSL_STORE_supports_search(ctx : POSSL_STORE_CTX; search_type : TIdC_INT) : TIdC_INT cdecl; external CLibCrypto;


//* Search term constructors */
{*
 * The input is considered to be owned by the caller, and must therefore
 * remain present throughout the lifetime of the returned OSSL_STORE_SEARCH
 *}
  {$EXTERNALSYM OSSL_STORE_SEARCH_by_name}
  function OSSL_STORE_SEARCH_by_name(name : PX509_NAME) : POSSL_STORE_SEARCH; cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_SEARCH_by_issuer_serial}
  function OSSL_STORE_SEARCH_by_issuer_serial(name : PX509_NAME;
    const serial : PASN1_INTEGER) : POSSL_STORE_SEARCH cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_SEARCH_by_key_fingerprint}
  function OSSL_STORE_SEARCH_by_key_fingerprint(const digest : PEVP_MD;
    const bytes : PIdAnsiChar; len : TIdC_SIZET) : POSSL_STORE_SEARCH cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_SEARCH_by_alias}
  function OSSL_STORE_SEARCH_by_alias(const alias : PIdAnsiChar) : POSSL_STORE_SEARCH cdecl; external CLibCrypto;

//* Search term destructor */
  {$EXTERNALSYM OSSL_STORE_SEARCH_free}
  procedure OSSL_STORE_SEARCH_free(search : POSSL_STORE_SEARCH)  cdecl; external CLibCrypto;

//* Search term accessors */
  {$EXTERNALSYM OSSL_STORE_SEARCH_get_type}
  function OSSL_STORE_SEARCH_get_type(const criterion : POSSL_STORE_SEARCH) : TIdC_INT   cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_SEARCH_get0_name}
  function OSSL_STORE_SEARCH_get0_name(const criterion : POSSL_STORE_SEARCH) : PX509_NAME   cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_SEARCH_get0_serial}
  function OSSL_STORE_SEARCH_get0_serial(const criterion : POSSL_STORE_SEARCH) : PASN1_INTEGER  cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_SEARCH_get0_bytes}
  function OSSL_STORE_SEARCH_get0_bytes(const criterion : POSSL_STORE_SEARCH; var length_ : TIdC_SIZET) : PByte   cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_SEARCH_get0_string}
  function OSSL_STORE_SEARCH_get0_string(const  criterion : POSSL_STORE_SEARCH) : PIdAnsiChar  cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_SEARCH_get0_digest}
  function OSSL_STORE_SEARCH_get0_digest(const  criterion : POSSL_STORE_SEARCH) : PEVP_MD   cdecl; external CLibCrypto;

{*
 * Add search criterion and expected return type (which can be unspecified)
 * to the loading channel.  This MUST happen before the first OSSL_STORE_load().
 *}
  {$EXTERNALSYM OSSL_STORE_expect}
 function OSSL_STORE_expect(ctx : POSSL_STORE_CTX; expected_type : TIdC_INT) : TIdC_INT  cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_find}
 function OSSL_STORE_find(ctx : POSSL_STORE_CTX; const  search : POSSL_STORE_SEARCH) : TIdC_INT  cdecl; external CLibCrypto;
{*-
 *  Function to fetch a loader and extract data from it
 *  ---------------------------------------------------
 *}
  {$EXTERNALSYM OSSL_STORE_LOADER_fetch}
 function OSSL_STORE_LOADER_fetch(libctx : POSSL_LIB_CTX;
    const scheme, properties : PIdAnsiChar) : POSSL_STORE_LOADER   cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_LOADER_up_ref}
 function OSSL_STORE_LOADER_up_ref(loader : POSSL_STORE_LOADER) : TIdC_INT  cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_LOADER_free}
 procedure OSSL_STORE_LOADER_free(loader : POSSL_STORE_LOADER)  cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_LOADER_get0_provider}
 function OSSL_STORE_LOADER_get0_provider(const loader : POSSL_STORE_LOADER) : POSSL_PROVIDER  cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_LOADER_get0_properties}
 function OSSL_STORE_LOADER_get0_properties(const loader : POSSL_STORE_LOADER) : PIdAnsiChar  cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_LOADER_get0_description}
 function OSSL_STORE_LOADER_get0_description(const loader : POSSL_STORE_LOADER) : PIdAnsiChar  cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_LOADER_is_a}
 function OSSL_STORE_LOADER_is_a(const loader : POSSL_STORE_LOADER;
                           const scheme : PIdAnsiChar) : TIdC_INT  cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_LOADER_do_all_provided}
procedure OSSL_STORE_LOADER_do_all_provided(libctx : POSSL_LIB_CTX;
                                       fn : OSSL_STORE_LOADER_do_all_provided_fn;
                                       arg : Pointer)  cdecl; external CLibCrypto;
  {$EXTERNALSYM OSSL_STORE_LOADER_names_do_all}
function OSSL_STORE_LOADER_names_do_all(const loader : POSSL_STORE_LOADER;
                                   fn : OSSL_STORE_LOADER_names_do_all_fn;
                                   data : Pointer) : TIdC_INT  cdecl; external CLibCrypto;
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
  OSSL_STORE_open_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_open_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_STORE_close_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_load_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_delete_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
  OSSL_STORE_eof_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_error_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_attach_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_STORE_INFO_set0_NAME_description_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_INFO_new_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_INFO_new_PARAMS_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_INFO_new_PUBKEY_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_INFO_new_PKEY_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_INFO_new_CERT_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_INFO_new_CRL_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OSSL_STORE_INFO_get_typeL_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_INFO_get0_data_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_INFO_get0_NAME_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_INFO_get1_NAME_introduced =  (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_STORE_INFO_get0_NAME_description_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_INFO_get1_NAME_description_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_INFO_get0_PARAMS_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_INFO_get1_PARAMS_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_INFO_get0_PUBKEY_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_INFO_get1_PUBKEY_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_INFO_get0_PKEY_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_INFO_get1_PKEY_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_INFO_get0_CERT_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_INFO_get1_CERT_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_INFO_get0_CRL_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_INFO_get1_CRL_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_INFO_type_string_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_INFO_free_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OSSL_STORE_supports_search_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_SEARCH_by_name_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_SEARCH_by_issuer_serial_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_SEARCH_by_key_fingerprint_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_SEARCH_by_alias_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_SEARCH_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OSSL_STORE_SEARCH_get_type_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_SEARCH_get0_name_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_SEARCH_get0_bytes_introduced =  (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_SEARCH_get0_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_SEARCH_get0_digest_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OSSL_STORE_expect_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_find_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_LOADER_fetch_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_STORE_LOADER_up_ref_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_STORE_LOADER_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OSSL_STORE_LOADER_get0_provider_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_STORE_LOADER_get0_properties_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_STORE_LOADER_get0_description_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_STORE_LOADER_is_a_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_STORE_LOADER_do_all_provided_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_STORE_LOADER_names_do_all_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

const
  OSSL_STORE_open_procname = 'OSSL_STORE_open';
  OSSL_STORE_open_ex_procname = 'OSSL_STORE_open_ex';
  OSSL_STORE_close_procname = 'OSSL_STORE_close';
  OSSL_STORE_load_procname = 'OSSL_STORE_load';
  OSSL_STORE_delete_procname = 'OSSL_STORE_delete';
  OSSL_STORE_eof_procname = 'OSSL_STORE_eof';
  OSSL_STORE_error_procname = 'OSSL_STORE_error';

  OSSL_STORE_attach_procname = 'OSSL_STORE_attach';

  OSSL_STORE_INFO_new_procname = 'OSSL_STORE_INFO_new';
  OSSL_STORE_INFO_new_NAME_procname = 'OSSL_STORE_INFO_new_NAME';
  OSSL_STORE_INFO_set0_NAME_description_procname = 'OSSL_STORE_INFO_set0_NAME_description';
  OSSL_STORE_INFO_new_PARAMS_procname = 'OSSL_STORE_INFO_new_PARAMS';
  OSSL_STORE_INFO_new_PUBKEY_procname = 'OSSL_STORE_INFO_new_PUBKEY';
  OSSL_STORE_INFO_new_PKEY_procname = 'OSSL_STORE_INFO_new_PKEY';
  OSSL_STORE_INFO_new_CERT_procname = 'OSSL_STORE_INFO_new_CERT';
  OSSL_STORE_INFO_new_CRL_procname = 'OSSL_STORE_INFO_new_CRL';
  OSSL_STORE_INFO_get_type_procname = 'OSSL_STORE_INFO_get_type';
  OSSL_STORE_INFO_get0_data_procname = 'OSSL_STORE_INFO_get0_data';
  OSSL_STORE_INFO_get0_NAME_procname = 'OSSL_STORE_INFO_get0_NAME';
  OSSL_STORE_INFO_get1_NAME_procname = 'OSSL_STORE_INFO_get1_NAME';
  OSSL_STORE_INFO_get0_NAME_description_procname = 'OSSL_STORE_INFO_get0_NAME_description';
  OSSL_STORE_INFO_get1_NAME_description_procname = 'OSSL_STORE_INFO_get1_NAME_description';
  OSSL_STORE_INFO_get0_PARAMS_procname = 'OSSL_STORE_INFO_get0_PARAMS';
  OSSL_STORE_INFO_get1_PARAMS_procname = 'OSSL_STORE_INFO_get1_PARAMS';
  OSSL_STORE_INFO_get0_PUBKEY_procname = 'OSSL_STORE_INFO_get0_PUBKEY';
  OSSL_STORE_INFO_get1_PUBKEY_procname = 'OSSL_STORE_INFO_get1_PUBKEY';
  OSSL_STORE_INFO_get0_PKEY_procname = 'OSSL_STORE_INFO_get0_PKEY';
  OSSL_STORE_INFO_get1_PKEY_procname = 'OSSL_STORE_INFO_get1_PKEY';
  OSSL_STORE_INFO_get0_CERT_procname = 'OSSL_STORE_INFO_get0_CERT';
  OSSL_STORE_INFO_get1_CERT_procname = 'OSSL_STORE_INFO_get1_CERT';
  OSSL_STORE_INFO_get0_CRL_procname = 'OSSL_STORE_INFO_get0_CRL';
  OSSL_STORE_INFO_get1_CRL_procname = 'OSSL_STORE_INFO_get1_CRL';
  OSSL_STORE_INFO_type_string_procname = 'OSSL_STORE_INFO_type_string';
  OSSL_STORE_INFO_free_procname = 'OSSL_STORE_INFO_free';
  OSSL_STORE_supports_search_procname = 'OSSL_STORE_supports_search';
  OSSL_STORE_SEARCH_by_name_procname = 'OSSL_STORE_SEARCH_by_name';
  OSSL_STORE_SEARCH_by_issuer_serial_procname = 'OSSL_STORE_SEARCH_by_issuer_serial';
  OSSL_STORE_SEARCH_by_key_fingerprint_procname = 'OSSL_STORE_SEARCH_by_key_fingerprint';
  OSSL_STORE_SEARCH_by_alias_procname = 'OSSL_STORE_SEARCH_by_alias';
  OSSL_STORE_SEARCH_free_procname = 'OSSL_STORE_SEARCH_free';
  OSSL_STORE_SEARCH_get_type_procname = 'OSSL_STORE_SEARCH_get_type';
  OSSL_STORE_SEARCH_get0_name_procname = 'OSSL_STORE_SEARCH_get0_name';
  OSSL_STORE_SEARCH_get0_serial_procname = 'OSSL_STORE_SEARCH_get0_serial';
  OSSL_STORE_SEARCH_get0_bytes_procname = 'OSSL_STORE_SEARCH_get0_bytes';
  OSSL_STORE_SEARCH_get0_string_procname = 'OSSL_STORE_SEARCH_get0_string';
  OSSL_STORE_SEARCH_get0_digest_procname = 'OSSL_STORE_SEARCH_get0_digest';
  OSSL_STORE_expect_procname = 'OSSL_STORE_expect';
  OSSL_STORE_find_procname = 'OSSL_STORE_find';
  OSSL_STORE_LOADER_fetch_procname = 'OSSL_STORE_LOADER_fetch';
  OSSL_STORE_LOADER_up_ref_procname = 'OSSL_STORE_LOADER_up_ref';
  OSSL_STORE_LOADER_free_procname = 'OSSL_STORE_LOADER_free';
  OSSL_STORE_LOADER_get0_provider_procname = 'OSSL_STORE_LOADER_get0_provider';
  OSSL_STORE_LOADER_get0_properties_procname = 'OSSL_STORE_LOADER_get0_properties';
  OSSL_STORE_LOADER_get0_description_procname = 'OSSL_STORE_LOADER_get0_description';
  OSSL_STORE_LOADER_is_a_procname = 'OSSL_STORE_LOADER_is_a';
  OSSL_STORE_LOADER_do_all_provided_procname = 'OSSL_STORE_LOADER_do_all_provided';
  OSSL_STORE_LOADER_names_do_all_procname = 'OSSL_STORE_LOADER_names_do_all';

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc}

function ERR_OSSL_STORE_open(const uri : PIdAnsiChar; const ui_method : PUI_METHOD;
                ui_data : Pointer;
                post_process : OSSL_STORE_post_process_info_fn;
                post_process_data : Pointer) : POSSL_STORE_CTX; {introduced 1.1.0} cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_open_procname);
end;

function ERR_OSSL_STORE_open_ex(const uri : PIdAnsiChar; libctx : POSSL_LIB_CTX; const propq : PIdAnsiChar;
                   const ui_method : PUI_METHOD; ui_data : Pointer;
                   const params : POSSL_PARAM_ARRAY;
                   post_process : OSSL_STORE_post_process_info_fn;
                   post_process_data : Pointer) : POSSL_STORE_CTX; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_open_ex_procname);
end;

function ERR_OSSL_STORE_close(ctx : POSSL_STORE_CTX) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_close_procname);
end;

function ERR_OSSL_STORE_load(ctx : POSSL_STORE_CTX) : POSSL_STORE_INFO; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_load_procname);
end;

function ERR_OSSL_STORE_delete(const uri : PIdAnsiChar; libctx : POSSL_LIB_CTX; const propq : PIdAnsiChar;
                      const ui_method : PUI_METHOD; ui_data : Pointer;
                      const  params : POSSL_PARAM_ARRAY) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_delete_procname);
end;

function ERR_OSSL_STORE_eof(ctx : POSSL_STORE_CTX) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_eof_procname);
end;

function ERR_OSSL_STORE_error(ctx : POSSL_STORE_CTX) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_error_procname);
end;

function ERR_OSSL_STORE_attach(bio : PBIO; const scheme : PIdAnsiChar;
                             libctx : POSSL_LIB_CTX; const propq : PIdAnsiChar;
                             const ui_method : PUI_METHOD; ui_data : Pointer;
                             const  params : POSSL_PARAM_ARRAY;
                             post_process : OSSL_STORE_post_process_info_fn;
                             post_process_data : Pointer) : POSSL_STORE_CTX; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_attach_procname);
end;

function ERR_OSSL_STORE_INFO_new(type_ : TIdC_INT; data : Pointer) : POSSL_STORE_INFO; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_new_procname);
end;

function ERR_OSSL_STORE_INFO_new_NAME(name : PIdAnsiChar) : POSSL_STORE_INFO; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_new_NAME_procname);
end;

function ERR_OSSL_STORE_INFO_set0_NAME_description(info : POSSL_STORE_INFO; desc : PIdAnsiChar) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_set0_NAME_description_procname);
end;

function ERR_OSSL_STORE_INFO_new_PARAMS(params : PEVP_PKEY) : POSSL_STORE_INFO; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_new_PARAMS_procname);
end;

function ERR_OSSL_STORE_INFO_new_PUBKEY(pubkey : PEVP_PKEY) : POSSL_STORE_INFO; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_new_PUBKEY_procname);
end;

function ERR_OSSL_STORE_INFO_new_PKEY(pkey : PEVP_PKEY) : POSSL_STORE_INFO; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_new_PKEY_procname);
end;

function ERR_OSSL_STORE_INFO_new_CERT(x509 : PX509) : POSSL_STORE_INFO; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_new_CERT_procname);
end;

function ERR_OSSL_STORE_INFO_new_CRL(crl : PX509_CRL) : POSSL_STORE_INFO; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_new_CRL_procname);
end;

function ERR_OSSL_STORE_INFO_get_type(const info : POSSL_STORE_INFO) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get_type_procname);
end;

function ERR_OSSL_STORE_INFO_get0_data(type_ : TIdC_INT; const info : POSSL_STORE_INFO) : Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get0_data_procname);
end;

function ERR_OSSL_STORE_INFO_get0_NAME(const info : POSSL_STORE_INFO) : PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get0_NAME_procname);
end;

function ERR_OSSL_STORE_INFO_get1_NAME(const info : POSSL_STORE_INFO) : PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get1_NAME_procname);
end;

function ERR_OSSL_STORE_INFO_get0_NAME_description(const info : POSSL_STORE_INFO) : PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get0_NAME_description_procname);
end;

function ERR_OSSL_STORE_INFO_get1_NAME_description(const info : POSSL_STORE_INFO) : PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get1_NAME_description_procname);
end;

function ERR_OSSL_STORE_INFO_get0_PARAMS(const info : POSSL_STORE_INFO) : PEVP_PKEY; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get0_PARAMS_procname);
end;

function ERR_OSSL_STORE_INFO_get1_PARAMS(const info  : POSSL_STORE_INFO) : PEVP_PKEY; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get1_PARAMS_procname);
end;

function ERR_OSSL_STORE_INFO_get0_PUBKEY(const info : POSSL_STORE_INFO) : PEVP_PKEY; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get0_PUBKEY_procname);
end;
  function ERR_OSSL_STORE_INFO_get1_PUBKEY(const info  : POSSL_STORE_INFO) : PEVP_PKEY; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get1_PUBKEY_procname);
end;

function ERR_OSSL_STORE_INFO_get0_PKEY(const info  : POSSL_STORE_INFO) : PEVP_PKEY; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get0_PKEY_procname);
end;

function ERR_OSSL_STORE_INFO_get1_PKEY(const info  : POSSL_STORE_INFO) : PEVP_PKEY; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get1_PKEY_procname);
end;

function ERR_OSSL_STORE_INFO_get0_CERT(const info : POSSL_STORE_INFO) : PX509; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get0_CERT_procname);
end;

function ERR_OSSL_STORE_INFO_get1_CERT(const info : POSSL_STORE_INFO) : PX509; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get1_CERT_procname);
end;

function ERR_OSSL_STORE_INFO_get0_CRL(const info : POSSL_STORE_INFO) : PX509_CRL; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get0_CRL_procname);
end;

function ERR_OSSL_STORE_INFO_get1_CRL(const info : POSSL_STORE_INFO) : PX509_CRL; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get1_CRL_procname);
end;

function ERR_OSSL_STORE_INFO_type_string(type_ : TIdC_INT) : PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_type_string_procname);
end;

procedure ERR_OSSL_STORE_INFO_free(info : POSSL_STORE_INFO); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_free_procname);
end;

function ERR_OSSL_STORE_supports_search(ctx : POSSL_STORE_CTX; search_type : TIdC_INT) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_supports_search_procname);
end;

function ERR_OSSL_STORE_SEARCH_by_name(name : PX509_NAME) : POSSL_STORE_SEARCH; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_SEARCH_by_name_procname);
end;

function ERR_OSSL_STORE_SEARCH_by_issuer_serial(name : PX509_NAME;
    const serial : PASN1_INTEGER) : POSSL_STORE_SEARCH; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_SEARCH_by_issuer_serial_procname);
end;

function ERR_OSSL_STORE_SEARCH_by_key_fingerprint(const digest : PEVP_MD;
    const bytes : PIdAnsiChar; len : TIdC_SIZET) : POSSL_STORE_SEARCH; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_SEARCH_by_key_fingerprint_procname);
end;

function ERR_OSSL_STORE_SEARCH_by_alias(const alias : PIdAnsiChar) : POSSL_STORE_SEARCH; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_SEARCH_by_alias_procname);
end;

procedure ERR_OSSL_STORE_SEARCH_free(search : POSSL_STORE_SEARCH); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_SEARCH_free_procname);
end;

//* Search term accessors */
function ERR_OSSL_STORE_SEARCH_get_type(const criterion : POSSL_STORE_SEARCH) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_SEARCH_get_type_procname);
end;

function ERR_OSSL_STORE_SEARCH_get0_name(const criterion : POSSL_STORE_SEARCH) : PX509_NAME; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_SEARCH_get0_name_procname);
end;

function ERR_OSSL_STORE_SEARCH_get0_serial(const criterion : POSSL_STORE_SEARCH) : PASN1_INTEGER; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_SEARCH_get0_serial_procname);
end;

function ERR_OSSL_STORE_SEARCH_get0_bytes(const criterion : POSSL_STORE_SEARCH; var length_ : TIdC_SIZET) : PByte; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_SEARCH_get0_bytes_procname);
end;

function ERR_OSSL_STORE_SEARCH_get0_string(const  criterion : POSSL_STORE_SEARCH) : PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_SEARCH_get0_string_procname);
end;

function ERR_OSSL_STORE_SEARCH_get0_digest(const  criterion : POSSL_STORE_SEARCH) : PEVP_MD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_SEARCH_get0_digest_procname);
end;

function ERR_OSSL_STORE_expect(ctx : POSSL_STORE_CTX; expected_type : TIdC_INT) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_expect_procname);
end;

function ERR_OSSL_STORE_find(ctx : POSSL_STORE_CTX; const  search : POSSL_STORE_SEARCH) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_find_procname);
end;

function ERR_OSSL_STORE_LOADER_fetch(libctx : POSSL_LIB_CTX;
    const scheme, properties : PIdAnsiChar) : POSSL_STORE_LOADER; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException( OSSL_STORE_LOADER_fetch_procname);
end;

function ERR_OSSL_STORE_LOADER_up_ref(loader : POSSL_STORE_LOADER) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_up_ref_procname);
end;

procedure ERR_OSSL_STORE_LOADER_free(loader : POSSL_STORE_LOADER); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_free_procname);
end;

function ERR_OSSL_STORE_LOADER_get0_provider(const loader : POSSL_STORE_LOADER) : POSSL_PROVIDER; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_get0_provider_procname);
end;

function ERR_OSSL_STORE_LOADER_get0_properties(const loader : POSSL_STORE_LOADER) : PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_get0_properties_procname);
end;

function ERR_OSSL_STORE_LOADER_get0_description(const loader : POSSL_STORE_LOADER) : PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_get0_description_procname);
end;
function ERR_OSSL_STORE_LOADER_is_a(const loader : POSSL_STORE_LOADER;
                           const scheme : PIdAnsiChar) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException( OSSL_STORE_LOADER_is_a_procname);
end;
procedure ERR_OSSL_STORE_LOADER_do_all_provided(libctx : POSSL_LIB_CTX;
                                       fn : OSSL_STORE_LOADER_do_all_provided_fn;
                                       arg : Pointer); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_do_all_provided_procname);
end;
function ERR_OSSL_STORE_LOADER_names_do_all(const loader : POSSL_STORE_LOADER;
                                   fn : OSSL_STORE_LOADER_names_do_all_fn;
                                   data : Pointer) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException( OSSL_STORE_LOADER_names_do_all_procname);
end;


 {$I TaurusTLSNoRetValOn.inc}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  OSSL_STORE_open := LoadLibFunction(ADllHandle, OSSL_STORE_open_procname);
  FuncLoadError := not assigned(OSSL_STORE_open);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_open_allownil)}
    OSSL_STORE_open := ERR_OSSL_STORE_open;
    {$ifend}
    {$if declared(OSSL_STORE_open_introduced)}
    if LibVersion < OSSL_STORE_open_introduced then
    begin
      {$if declared(FC_OSSL_STORE_open)}
      OSSL_STORE_open := FC_OSSL_STORE_open;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_open_removed)}
    if OSSL_STORE_open_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_open)}
      OSSL_STORE_open := _OSSL_STORE_open;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_open_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_open');
    {$ifend}
  end;

  OSSL_STORE_open_ex := LoadLibFunction(ADllHandle, OSSL_STORE_open_ex_procname);
  FuncLoadError := not assigned(OSSL_STORE_open_ex);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_open_ex_allownil)}
    OSSL_STORE_open_ex := ERR_OSSL_STORE_open_ex;
    {$ifend}
    {$if declared(OSSL_STORE_open_ex_introduced)}
    if LibVersion < OSSL_STORE_open_ex_introduced then
    begin
      {$if declared(FC_OSSL_STORE_open_ex)}
      OSSL_STORE_open_ex := FC_OSSL_STORE_open_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_open_ex_removed)}
    if OSSL_STORE_open_ex_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_open_ex)}
      OSSL_STORE_open_ex := _OSSL_STORE_open_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_open_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_open_ex');
    {$ifend}
  end;

  OSSL_STORE_close := LoadLibFunction(ADllHandle, OSSL_STORE_close_procname);
  FuncLoadError := not assigned(OSSL_STORE_close);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_close_allownil)}
    OSSL_STORE_close := ERR_OSSL_STORE_close;
    {$ifend}
    {$if declared(OSSL_STORE_close_introduced)}
    if LibVersion < OSSL_STORE_close_introduced then
    begin
      {$if declared(FC_OSSL_STORE_close)}
      OSSL_STORE_close := FC_OSSL_STORE_close;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_close_removed)}
    if OSSL_STORE_close_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_close)}
      OSSL_STORE_close := _OSSL_STORE_close;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_close_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_close');
    {$ifend}
  end;

  OSSL_STORE_load := LoadLibFunction(ADllHandle, OSSL_STORE_load_procname);
  FuncLoadError := not assigned(OSSL_STORE_load);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_load_allownil)}
    OSSL_STORE_load := ERR_OSSL_STORE_load;
    {$ifend}
    {$if declared(OSSL_STORE_load_introduced)}
    if LibVersion < OSSL_STORE_load_introduced then
    begin
      {$if declared(FC_OSSL_STORE_load)}
      OSSL_STORE_load := FC_OSSL_STORE_load;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_load_removed)}
    if OSSL_STORE_load_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_load)}
      OSSL_STORE_load := _OSSL_STORE_load;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_load_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_load');
    {$ifend}
  end;

  OSSL_STORE_delete := LoadLibFunction(ADllHandle, OSSL_STORE_delete_procname);
  FuncLoadError := not assigned(OSSL_STORE_delete);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_delete_allownil)}
    OSSL_STORE_delete := ERR_OSSL_STORE_delete;
    {$ifend}
    {$if declared(OSSL_STORE_delete_introduced)}
    if LibVersion < OSSL_STORE_delete_introduced then
    begin
      {$if declared(FC_OSSL_STORE_delete)}
      OSSL_STORE_delete := FC_OSSL_STORE_delete;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_delete_removed)}
    if OSSL_STORE_delete_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_delete)}
      OSSL_STORE_delete := _OSSL_STORE_delete;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_delete_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_delete');
    {$ifend}
  end;

  OSSL_STORE_eof := LoadLibFunction(ADllHandle, OSSL_STORE_eof_procname);
  FuncLoadError := not assigned(OSSL_STORE_eof);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_eof_allownil)}
    OSSL_STORE_eof := ERR_OSSL_STORE_eof;
    {$ifend}
    {$if declared(OSSL_STORE_eof_introduced)}
    if LibVersion < OSSL_STORE_eof_introduced then
    begin
      {$if declared(FC_OSSL_STORE_eof)}
      OSSL_STORE_eof := FC_OSSL_STORE_eof;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_eof_removed)}
    if OSSL_STORE_eof_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_eof)}
      OSSL_STORE_eof := _OSSL_STORE_eof;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_eof_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_eof');
    {$ifend}
  end;

  OSSL_STORE_error := LoadLibFunction(ADllHandle, OSSL_STORE_error_procname);
  FuncLoadError := not assigned(OSSL_STORE_error);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_error_allownil)}
    OSSL_STORE_error := ERR_OSSL_STORE_error;
    {$ifend}
    {$if declared(OSSL_STORE_error_introduced)}
    if LibVersion < OSSL_STORE_error_introduced then
    begin
      {$if declared(FC_OSSL_STORE_error)}
      OSSL_STORE_error := FC_OSSL_STORE_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_error_removed)}
    if OSSL_STORE_error_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_error)}
      OSSL_STORE_error := _OSSL_STORE_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_error_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_error');
    {$ifend}
  end;

  OSSL_STORE_attach := LoadLibFunction(ADllHandle, OSSL_STORE_attach_procname);
  FuncLoadError := not assigned(OSSL_STORE_attach);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_attach_allownil)}
    OSSL_STORE_attach := ERR_OSSL_STORE_attach;
    {$ifend}
    {$if declared(OSSL_STORE_attach_introduced)}
    if LibVersion < OSSL_STORE_attach_introduced then
    begin
      {$if declared(FC_OSSL_STORE_attach)}
      OSSL_STORE_attach := FC_OSSL_STORE_attach;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_attach_removed)}
    if OSSL_STORE_attach_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_attach)}
      OSSL_STORE_attach := _OSSL_STORE_attach;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_attach_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_attach');
    {$ifend}
  end;

  OSSL_STORE_INFO_new := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_new_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_new_allownil)}
    OSSL_STORE_INFO_new := ERR_OSSL_STORE_INFO_new;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_new_introduced)}
    if LibVersion < OSSL_STORE_INFO_new_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_new)}
      OSSL_STORE_INFO_new := FC_OSSL_STORE_INFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_new_removed)}
    if OSSL_STORE_INFO_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_new)}
      OSSL_STORE_INFO_new := _OSSL_STORE_INFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_new');
    {$ifend}
  end;

  OSSL_STORE_INFO_new_NAME := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_new_NAME_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_new_NAME);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_new_NAME_allownil)}
    OSSL_STORE_INFO_new_NAME := ERR_OSSL_STORE_INFO_new_NAME;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_new_NAME_introduced)}
    if LibVersion < OSSL_STORE_INFO_new_NAME_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_new_NAME)}
      OSSL_STORE_INFO_new_NAME := FC_OSSL_STORE_INFO_new_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_new_NAME_removed)}
    if OSSL_STORE_INFO_new_NAME_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_new_NAME)}
      OSSL_STORE_INFO_new_NAME := _OSSL_STORE_INFO_new_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_new_NAME_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_new_NAME');
    {$ifend}
  end;

  OSSL_STORE_INFO_set0_NAME_description := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_set0_NAME_description_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_set0_NAME_description);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_set0_NAME_description_allownil)}
    OSSL_STORE_INFO_set0_NAME_description := ERR_OSSL_STORE_INFO_set0_NAME_description;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_set0_NAME_description_introduced)}
    if LibVersion < OSSL_STORE_INFO_set0_NAME_description_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_set0_NAME_description)}
      OSSL_STORE_INFO_set0_NAME_description := FC_OSSL_STORE_INFO_set0_NAME_description;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_set0_NAME_description_removed)}
    if OSSL_STORE_INFO_set0_NAME_description_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_set0_NAME_description)}
      OSSL_STORE_INFO_set0_NAME_description := _OSSL_STORE_INFO_set0_NAME_description;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_set0_NAME_description_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_set0_NAME_description');
    {$ifend}
  end;

  OSSL_STORE_INFO_new_PARAMS := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_new_PARAMS_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_new_PARAMS);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_new_PARAMS_allownil)}
    OSSL_STORE_INFO_new_PARAMS := ERR_OSSL_STORE_INFO_new_PARAMS;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_new_PARAMS_introduced)}
    if LibVersion < OSSL_STORE_INFO_new_PARAMS_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_new_PARAMS)}
      OSSL_STORE_INFO_new_PARAMS := FC_OSSL_STORE_INFO_new_PARAMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_new_PARAMS_removed)}
    if OSSL_STORE_INFO_new_PARAMS_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_new_PARAMS)}
      OSSL_STORE_INFO_new_PARAMS := _OSSL_STORE_INFO_new_PARAMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_new_PARAMS_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_new_PARAMS');
    {$ifend}
  end;

  OSSL_STORE_INFO_new_PUBKEY := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_new_PUBKEY_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_new_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_new_PUBKEY_allownil)}
    OSSL_STORE_INFO_new_PUBKEY := ERR_OSSL_STORE_INFO_new_PUBKEY;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_new_PUBKEY_introduced)}
    if LibVersion < OSSL_STORE_INFO_new_PUBKEY_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_new_PUBKEY)}
      OSSL_STORE_INFO_new_PUBKEY := FC_OSSL_STORE_INFO_new_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_new_PUBKEY_removed)}
    if OSSL_STORE_INFO_new_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_new_PUBKEY)}
      OSSL_STORE_INFO_new_PUBKEY := _OSSL_STORE_INFO_new_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_new_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_new_PUBKEY');
    {$ifend}
  end;

  OSSL_STORE_INFO_new_PKEY := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_new_PKEY_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_new_PKEY);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_new_PKEY_allownil)}
    OSSL_STORE_INFO_new_PKEY := ERR_OSSL_STORE_INFO_new_PKEY;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_new_PKEY_introduced)}
    if LibVersion < OSSL_STORE_INFO_new_PKEY_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_new_PKEY)}
      OSSL_STORE_INFO_new_PKEY := FC_OSSL_STORE_INFO_new_PKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_new_PKEY_removed)}
    if OSSL_STORE_INFO_new_PKEY_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_new_PKEY)}
      OSSL_STORE_INFO_new_PKEY := _OSSL_STORE_INFO_new_PKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_new_PKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_new_PKEY');
    {$ifend}
  end;

  OSSL_STORE_INFO_new_CERT := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_new_CERT_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_new_CERT);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_new_CERT_allownil)}
    OSSL_STORE_INFO_new_CERT := ERR_OSSL_STORE_INFO_new_CERT;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_new_CERT_introduced)}
    if LibVersion < OSSL_STORE_INFO_new_CERT_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_new_CERT)}
      OSSL_STORE_INFO_new_CERT := FC_OSSL_STORE_INFO_new_CERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_new_CERT_removed)}
    if OSSL_STORE_INFO_new_CERT_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_new_CERT)}
      OSSL_STORE_INFO_new_CERT := _OSSL_STORE_INFO_new_CERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_new_CERT_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_new_CERT');
    {$ifend}
  end;

  OSSL_STORE_INFO_new_CRL := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_new_CRL_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_new_CRL);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_new_CRL_allownil)}
    OSSL_STORE_INFO_new_CRL := ERR_OSSL_STORE_INFO_new_CRL;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_new_CRL_introduced)}
    if LibVersion < OSSL_STORE_INFO_new_CRL_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_new_CRL)}
      OSSL_STORE_INFO_new_CRL := FC_OSSL_STORE_INFO_new_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_new_CRL_removed)}
    if OSSL_STORE_INFO_new_CRL_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_new_CRL)}
      OSSL_STORE_INFO_new_CRL := _OSSL_STORE_INFO_new_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_new_CRL_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_new_CRL');
    {$ifend}
  end;

  OSSL_STORE_INFO_get_type := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get_type_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get_type);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get_type_allownil)}
    OSSL_STORE_INFO_get_type := ERR_OSSL_STORE_INFO_get_type;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get_type_introduced)}
    if LibVersion < OSSL_STORE_INFO_get_type_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get_type)}
      OSSL_STORE_INFO_get_type := FC_OSSL_STORE_INFO_get_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get_type_removed)}
    if OSSL_STORE_INFO_get_type_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get_type)}
      OSSL_STORE_INFO_get_type := _OSSL_STORE_INFO_get_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get_type_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get_type');
    {$ifend}
  end;

  OSSL_STORE_INFO_get0_data := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get0_data_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get0_data);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get0_data_allownil)}
    OSSL_STORE_INFO_get0_data := ERR_OSSL_STORE_INFO_get0_data;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_data_introduced)}
    if LibVersion < OSSL_STORE_INFO_get0_data_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get0_data)}
      OSSL_STORE_INFO_get0_data := FC_OSSL_STORE_INFO_get0_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_data_removed)}
    if OSSL_STORE_INFO_get0_data_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get0_data)}
      OSSL_STORE_INFO_get0_data := _OSSL_STORE_INFO_get0_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get0_data_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get0_data');
    {$ifend}
  end;

  OSSL_STORE_INFO_get0_NAME := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get0_NAME_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get0_NAME);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get0_NAME_allownil)}
    OSSL_STORE_INFO_get0_NAME := ERR_OSSL_STORE_INFO_get0_NAME;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_NAME_introduced)}
    if LibVersion < OSSL_STORE_INFO_get0_NAME_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get0_NAME)}
      OSSL_STORE_INFO_get0_NAME := FC_OSSL_STORE_INFO_get0_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_NAME_removed)}
    if OSSL_STORE_INFO_get0_NAME_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get0_NAME)}
      OSSL_STORE_INFO_get0_NAME := _OSSL_STORE_INFO_get0_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get0_NAME_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get0_NAME');
    {$ifend}
  end;

  OSSL_STORE_INFO_get1_NAME := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get1_NAME_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get1_NAME);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get1_NAME_allownil)}
    OSSL_STORE_INFO_get1_NAME := ERR_OSSL_STORE_INFO_get1_NAME;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get1_NAME_introduced)}
    if LibVersion < OSSL_STORE_INFO_get1_NAME_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get1_NAME)}
      OSSL_STORE_INFO_get1_NAME := FC_OSSL_STORE_INFO_get1_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get1_NAME_removed)}
    if OSSL_STORE_INFO_get1_NAME_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get1_NAME)}
      OSSL_STORE_INFO_get1_NAME := _OSSL_STORE_INFO_get1_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get1_NAME_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get1_NAME');
    {$ifend}
  end;

  OSSL_STORE_INFO_get0_NAME_description := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get0_NAME_description_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get0_NAME_description);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get0_NAME_description_allownil)}
    OSSL_STORE_INFO_get0_NAME_description := ERR_OSSL_STORE_INFO_get0_NAME_description;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_NAME_description_introduced)}
    if LibVersion < OSSL_STORE_INFO_get0_NAME_description_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get0_NAME_description)}
      OSSL_STORE_INFO_get0_NAME_description := FC_OSSL_STORE_INFO_get0_NAME_description;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_NAME_description_removed)}
    if OSSL_STORE_INFO_get0_NAME_description_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get0_NAME_description)}
      OSSL_STORE_INFO_get0_NAME_description := _OSSL_STORE_INFO_get0_NAME_description;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get0_NAME_description_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get0_NAME_description');
    {$ifend}
  end;

  OSSL_STORE_INFO_get1_NAME_description := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get1_NAME_description_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get1_NAME_description);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get1_NAME_description_allownil)}
    OSSL_STORE_INFO_get1_NAME_description := ERR_OSSL_STORE_INFO_get1_NAME_description;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get1_NAME_description_introduced)}
    if LibVersion < OSSL_STORE_INFO_get1_NAME_description_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get1_NAME_description)}
      OSSL_STORE_INFO_get1_NAME_description := FC_OSSL_STORE_INFO_get1_NAME_description;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get1_NAME_description_removed)}
    if OSSL_STORE_INFO_get1_NAME_description_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get1_NAME_description)}
      OSSL_STORE_INFO_get1_NAME_description := _OSSL_STORE_INFO_get1_NAME_description;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get1_NAME_description_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get1_NAME_description');
    {$ifend}
  end;

  OSSL_STORE_INFO_get0_PARAMS := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get0_PARAMS_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get0_PARAMS);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get0_PARAMS_allownil)}
    OSSL_STORE_INFO_get0_PARAMS := ERR_OSSL_STORE_INFO_get0_PARAMS;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_PARAMS_introduced)}
    if LibVersion < OSSL_STORE_INFO_get0_PARAMS_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get0_PARAMS)}
      OSSL_STORE_INFO_get0_PARAMS := FC_OSSL_STORE_INFO_get0_PARAMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_PARAMS_removed)}
    if OSSL_STORE_INFO_get0_PARAMS_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get0_PARAMS)}
      OSSL_STORE_INFO_get0_PARAMS := _OSSL_STORE_INFO_get0_PARAMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get0_PARAMS_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get0_PARAMS');
    {$ifend}
  end;

  OSSL_STORE_INFO_get1_PARAMS := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get1_PARAMS_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get1_PARAMS);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get1_PARAMS_allownil)}
    OSSL_STORE_INFO_get1_PARAMS := ERR_OSSL_STORE_INFO_get1_PARAMS;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get1_PARAMS_introduced)}
    if LibVersion < OSSL_STORE_INFO_get1_PARAMS_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get1_PARAMS)}
      OSSL_STORE_INFO_get1_PARAMS := FC_OSSL_STORE_INFO_get1_PARAMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get1_PARAMS_removed)}
    if OSSL_STORE_INFO_get1_PARAMS_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get1_PARAMS)}
      OSSL_STORE_INFO_get1_PARAMS := _OSSL_STORE_INFO_get1_PARAMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get1_PARAMS_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get1_PARAMS');
    {$ifend}
  end;

  OSSL_STORE_INFO_get0_PUBKEY := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get0_PUBKEY_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get0_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get0_PUBKEY_allownil)}
    OSSL_STORE_INFO_get0_PUBKEY := ERR_OSSL_STORE_INFO_get0_PUBKEY;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_PUBKEY_introduced)}
    if LibVersion < OSSL_STORE_INFO_get0_PUBKEY_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get0_PUBKEY)}
      OSSL_STORE_INFO_get0_PUBKEY := FC_OSSL_STORE_INFO_get0_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_PUBKEY_removed)}
    if OSSL_STORE_INFO_get0_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get0_PUBKEY)}
      OSSL_STORE_INFO_get0_PUBKEY := _OSSL_STORE_INFO_get0_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get0_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get0_PUBKEY');
    {$ifend}
  end;

  OSSL_STORE_INFO_get1_PUBKEY := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get1_PUBKEY_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get1_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get1_PUBKEY_allownil)}
    OSSL_STORE_INFO_get1_PUBKEY := ERR_OSSL_STORE_INFO_get1_PUBKEY;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get1_PUBKEY_introduced)}
    if LibVersion < OSSL_STORE_INFO_get1_PUBKEY_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get1_PUBKEY)}
      OSSL_STORE_INFO_get1_PUBKEY := FC_OSSL_STORE_INFO_get1_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get1_PUBKEY_removed)}
    if OSSL_STORE_INFO_get1_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get1_PUBKEY)}
      OSSL_STORE_INFO_get1_PUBKEY := _OSSL_STORE_INFO_get1_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get1_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get1_PUBKEY');
    {$ifend}
  end;

  OSSL_STORE_INFO_get0_PKEY := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get0_PKEY_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get0_PKEY);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get0_PKEY_allownil)}
    OSSL_STORE_INFO_get0_PKEY := ERR_OSSL_STORE_INFO_get0_PKEY;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_PKEY_introduced)}
    if LibVersion < OSSL_STORE_INFO_get0_PKEY_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get0_PKEY)}
      OSSL_STORE_INFO_get0_PKEY := FC_OSSL_STORE_INFO_get0_PKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_PKEY_removed)}
    if OSSL_STORE_INFO_get0_PKEY_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get0_PKEY)}
      OSSL_STORE_INFO_get0_PKEY := _OSSL_STORE_INFO_get0_PKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get0_PKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get0_PKEY');
    {$ifend}
  end;

  OSSL_STORE_INFO_get1_PKEY := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get1_PKEY_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get1_PKEY);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get1_PKEY_allownil)}
    OSSL_STORE_INFO_get1_PKEY := ERR_OSSL_STORE_INFO_get1_PKEY;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get1_PKEY_introduced)}
    if LibVersion < OSSL_STORE_INFO_get1_PKEY_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get1_PKEY)}
      OSSL_STORE_INFO_get1_PKEY := FC_OSSL_STORE_INFO_get1_PKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get1_PKEY_removed)}
    if OSSL_STORE_INFO_get1_PKEY_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get1_PKEY)}
      OSSL_STORE_INFO_get1_PKEY := _OSSL_STORE_INFO_get1_PKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get1_PKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get1_PKEY');
    {$ifend}
  end;

  OSSL_STORE_INFO_get0_CERT := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get0_CERT_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get0_CERT);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get0_CERT_allownil)}
    OSSL_STORE_INFO_get0_CERT := ERR_OSSL_STORE_INFO_get0_CERT;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_CERT_introduced)}
    if LibVersion < OSSL_STORE_INFO_get0_CERT_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get0_CERT)}
      OSSL_STORE_INFO_get0_CERT := FC_OSSL_STORE_INFO_get0_CERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_CERT_removed)}
    if OSSL_STORE_INFO_get0_CERT_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get0_CERT)}
      OSSL_STORE_INFO_get0_CERT := _OSSL_STORE_INFO_get0_CERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get0_CERT_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get0_CERT');
    {$ifend}
  end;

  OSSL_STORE_INFO_get1_CERT := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get1_CERT_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get1_CERT);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get1_CERT_allownil)}
    OSSL_STORE_INFO_get1_CERT := ERR_OSSL_STORE_INFO_get1_CERT;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get1_CERT_introduced)}
    if LibVersion < OSSL_STORE_INFO_get1_CERT_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get1_CERT)}
      OSSL_STORE_INFO_get1_CERT := FC_OSSL_STORE_INFO_get1_CERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get1_CERT_removed)}
    if OSSL_STORE_INFO_get1_CERT_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get1_CERT)}
      OSSL_STORE_INFO_get1_CERT := _OSSL_STORE_INFO_get1_CERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get1_CERT_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get1_CERT');
    {$ifend}
  end;

  OSSL_STORE_INFO_get0_CRL := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get0_CRL_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get0_CRL);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get0_CRL_allownil)}
    OSSL_STORE_INFO_get0_CRL := ERR_OSSL_STORE_INFO_get0_CRL;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_CRL_introduced)}
    if LibVersion < OSSL_STORE_INFO_get0_CRL_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get0_CRL)}
      OSSL_STORE_INFO_get0_CRL := FC_OSSL_STORE_INFO_get0_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_CRL_removed)}
    if OSSL_STORE_INFO_get0_CRL_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get0_CRL)}
      OSSL_STORE_INFO_get0_CRL := _OSSL_STORE_INFO_get0_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get0_CRL_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get0_CRL');
    {$ifend}
  end;
    OSSL_STORE_INFO_get1_CRL := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get1_CRL_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get1_CRL);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get1_CRL_allownil)}
    OSSL_STORE_INFO_get1_CRL := ERR_OSSL_STORE_INFO_get1_CRL;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get1_CRL_introduced)}
    if LibVersion < OSSL_STORE_INFO_get1_CRL_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get1_CRL)}
      OSSL_STORE_INFO_get1_CRL := FC_OSSL_STORE_INFO_get1_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get1_CRL_removed)}
    if OSSL_STORE_INFO_get1_CRL_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get1_CRL)}
      OSSL_STORE_INFO_get1_CRL := _OSSL_STORE_INFO_get1_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get1_CRL_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get1_CRL');
    {$ifend}
  end;

  OSSL_STORE_INFO_type_string := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_type_string_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_type_string);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_type_string_allownil)}
    OSSL_STORE_INFO_type_string := ERR_OSSL_STORE_INFO_type_string;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_type_string_introduced)}
    if LibVersion < OSSL_STORE_INFO_type_string_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_type_string)}
      OSSL_STORE_INFO_type_string := FC_OSSL_STORE_INFO_type_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_type_string_removed)}
    if OSSL_STORE_INFO_type_string_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_type_string)}
      OSSL_STORE_INFO_type_string := _OSSL_STORE_INFO_type_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_type_string_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_type_string');
    {$ifend}
  end;

  OSSL_STORE_INFO_free := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_free_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_free_allownil)}
    OSSL_STORE_INFO_free := ERR_OSSL_STORE_INFO_free;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_free_introduced)}
    if LibVersion < OSSL_STORE_INFO_free_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_free)}
      OSSL_STORE_INFO_free := FC_OSSL_STORE_INFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_free_removed)}
    if OSSL_STORE_INFO_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_free)}
      OSSL_STORE_INFO_free := _OSSL_STORE_INFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_free');
    {$ifend}
  end;
  //=====================================================

  OSSL_STORE_supports_search := LoadLibFunction(ADllHandle, OSSL_STORE_supports_search_procname);
  FuncLoadError := not assigned(OSSL_STORE_supports_search);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_supports_search_allownil)}
    OSSL_STORE_supports_search := ERR_OSSL_STORE_supports_search;
    {$ifend}
    {$if declared(OSSL_STORE_supports_search_introduced)}
    if LibVersion < OSSL_STORE_supports_search_introduced then
    begin
      {$if declared(FC_OSSL_STORE_supports_search)}
      OSSL_STORE_supports_search := FC_OSSL_STORE_supports_search;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_supports_search_removed)}
    if OSSL_STORE_supports_search_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_supports_search)}
      OSSL_STORE_supports_search := _OSSL_STORE_supports_search;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_supports_search_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_supports_search');
    {$ifend}
  end;

  OSSL_STORE_SEARCH_by_name := LoadLibFunction(ADllHandle, OSSL_STORE_SEARCH_by_name_procname);
  FuncLoadError := not assigned(OSSL_STORE_SEARCH_by_name);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_SEARCH_by_name_allownil)}
    OSSL_STORE_SEARCH_by_name := ERR_OSSL_STORE_SEARCH_by_name;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_by_name_introduced)}
    if LibVersion < OSSL_STORE_SEARCH_by_name_introduced then
    begin
      {$if declared(FC_OSSL_STORE_SEARCH_by_name)}
      OSSL_STORE_SEARCH_by_name := FC_OSSL_STORE_SEARCH_by_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_by_name_removed)}
    if OSSL_STORE_SEARCH_by_name_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_SEARCH_by_name)}
      OSSL_STORE_SEARCH_by_name := _OSSL_STORE_SEARCH_by_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_SEARCH_by_name_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_SEARCH_by_name');
    {$ifend}
  end;

  OSSL_STORE_SEARCH_by_issuer_serial := LoadLibFunction(ADllHandle, OSSL_STORE_SEARCH_by_issuer_serial_procname);
  FuncLoadError := not assigned(OSSL_STORE_SEARCH_by_issuer_serial);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_SEARCH_by_issuer_serial_allownil)}
    OSSL_STORE_SEARCH_by_issuer_serial := ERR_OSSL_STORE_SEARCH_by_issuer_serial;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_by_issuer_serial_introduced)}
    if LibVersion < OSSL_STORE_SEARCH_by_issuer_serial_introduced then
    begin
      {$if declared(FC_OSSL_STORE_SEARCH_by_issuer_serial)}
      OSSL_STORE_SEARCH_by_issuer_serial := FC_OSSL_STORE_SEARCH_by_issuer_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_by_issuer_serial_removed)}
    if OSSL_STORE_SEARCH_by_issuer_serial_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_SEARCH_by_issuer_serial)}
      OSSL_STORE_SEARCH_by_issuer_serial := _OSSL_STORE_SEARCH_by_issuer_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_SEARCH_by_issuer_serial_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_SEARCH_by_issuer_serial');
    {$ifend}
  end;

  OSSL_STORE_SEARCH_by_key_fingerprint := LoadLibFunction(ADllHandle, OSSL_STORE_SEARCH_by_key_fingerprint_procname);
  FuncLoadError := not assigned(OSSL_STORE_SEARCH_by_key_fingerprint);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_SEARCH_by_key_fingerprint_allownil)}
    OSSL_STORE_SEARCH_by_key_fingerprint := ERR_OSSL_STORE_SEARCH_by_key_fingerprint;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_by_key_fingerprint_introduced)}
    if LibVersion < OSSL_STORE_SEARCH_by_key_fingerprint_introduced then
    begin
      {$if declared(FC_OSSL_STORE_SEARCH_by_key_fingerprint)}
      OSSL_STORE_SEARCH_by_key_fingerprint := FC_OSSL_STORE_SEARCH_by_key_fingerprint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_by_key_fingerprint_removed)}
    if OSSL_STORE_SEARCH_by_key_fingerprint_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_SEARCH_by_key_fingerprint)}
      OSSL_STORE_SEARCH_by_key_fingerprint := _OSSL_STORE_SEARCH_by_key_fingerprint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_SEARCH_by_key_fingerprint_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_SEARCH_by_key_fingerprint');
    {$ifend}
  end;

  OSSL_STORE_SEARCH_by_alias := LoadLibFunction(ADllHandle, OSSL_STORE_SEARCH_by_alias_procname);
  FuncLoadError := not assigned(OSSL_STORE_SEARCH_by_alias);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_SEARCH_by_alias_allownil)}
    OSSL_STORE_SEARCH_by_alias := ERR_OSSL_STORE_SEARCH_by_alias;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_by_alias_introduced)}
    if LibVersion < OSSL_STORE_SEARCH_by_alias_introduced then
    begin
      {$if declared(FC_OSSL_STORE_SEARCH_by_alias)}
      OSSL_STORE_SEARCH_by_alias := FC_OSSL_STORE_SEARCH_by_alias;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_by_alias_removed)}
    if OSSL_STORE_SEARCH_by_alias_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_SEARCH_by_alias)}
      OSSL_STORE_SEARCH_by_alias := _OSSL_STORE_SEARCH_by_alias;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_SEARCH_by_alias_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_SEARCH_by_alias');
    {$ifend}
  end;

  OSSL_STORE_SEARCH_free := LoadLibFunction(ADllHandle, OSSL_STORE_SEARCH_free_procname);
  FuncLoadError := not assigned(OSSL_STORE_SEARCH_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_SEARCH_free_allownil)}
    OSSL_STORE_SEARCH_free := ERR_OSSL_STORE_SEARCH_free;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_free_introduced)}
    if LibVersion < OSSL_STORE_SEARCH_free_introduced then
    begin
      {$if declared(FC_OSSL_STORE_SEARCH_free)}
      OSSL_STORE_SEARCH_free := FC_OSSL_STORE_SEARCH_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_free_removed)}
    if OSSL_STORE_SEARCH_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_SEARCH_free)}
      OSSL_STORE_SEARCH_free := _OSSL_STORE_SEARCH_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_SEARCH_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_SEARCH_free');
    {$ifend}
  end;

    OSSL_STORE_SEARCH_get_type := LoadLibFunction(ADllHandle, OSSL_STORE_SEARCH_get_type_procname);
  FuncLoadError := not assigned(OSSL_STORE_SEARCH_get_type);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_SEARCH_get_type_allownil)}
    OSSL_STORE_SEARCH_get_type := ERR_OSSL_STORE_SEARCH_get_type;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_get_type_introduced)}
    if LibVersion < OSSL_STORE_SEARCH_get_type_introduced then
    begin
      {$if declared(FC_OSSL_STORE_SEARCH_get_type)}
      OSSL_STORE_SEARCH_get_type := FC_OSSL_STORE_SEARCH_get_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_get_type_removed)}
    if OSSL_STORE_SEARCH_get_type_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_SEARCH_get_type)}
      OSSL_STORE_SEARCH_get_type := _OSSL_STORE_SEARCH_get_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_SEARCH_get_type_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_SEARCH_get_type');
    {$ifend}
  end;

    OSSL_STORE_SEARCH_get0_name := LoadLibFunction(ADllHandle, OSSL_STORE_SEARCH_get0_name_procname);
  FuncLoadError := not assigned(OSSL_STORE_SEARCH_get0_name);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_SEARCH_get0_name_allownil)}
    OSSL_STORE_SEARCH_get0_name := ERR_OSSL_STORE_SEARCH_get0_name;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_get0_name_introduced)}
    if LibVersion < OSSL_STORE_SEARCH_get0_name_introduced then
    begin
      {$if declared(FC_OSSL_STORE_SEARCH_get0_name)}
      OSSL_STORE_SEARCH_get0_name := FC_OSSL_STORE_SEARCH_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_get0_name_removed)}
    if OSSL_STORE_SEARCH_get0_name_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_SEARCH_get0_name)}
      OSSL_STORE_SEARCH_get0_name := _OSSL_STORE_SEARCH_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_SEARCH_get0_name_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_SEARCH_get0_name');
    {$ifend}
  end;

    OSSL_STORE_SEARCH_get0_serial := LoadLibFunction(ADllHandle, OSSL_STORE_SEARCH_get0_serial_procname);
  FuncLoadError := not assigned(OSSL_STORE_SEARCH_get0_serial);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_SEARCH_get0_serial_allownil)}
    OSSL_STORE_SEARCH_get0_serial := ERR_OSSL_STORE_SEARCH_get0_serial;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_get0_serial_introduced)}
    if LibVersion < OSSL_STORE_SEARCH_get0_serial_introduced then
    begin
      {$if declared(FC_OSSL_STORE_SEARCH_get0_serial)}
      OSSL_STORE_SEARCH_get0_serial := FC_OSSL_STORE_SEARCH_get0_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_get0_serial_removed)}
    if OSSL_STORE_SEARCH_get0_serial_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_SEARCH_get0_serial)}
      OSSL_STORE_SEARCH_get0_serial := _OSSL_STORE_SEARCH_get0_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_SEARCH_get0_serial_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_SEARCH_get0_serial');
    {$ifend}
  end;

    OSSL_STORE_SEARCH_get0_bytes := LoadLibFunction(ADllHandle, OSSL_STORE_SEARCH_get0_bytes_procname);
  FuncLoadError := not assigned(OSSL_STORE_SEARCH_get0_bytes);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_SEARCH_get0_bytes_allownil)}
    OSSL_STORE_SEARCH_get0_bytes := ERR_OSSL_STORE_SEARCH_get0_bytes;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_get0_bytes_introduced)}
    if LibVersion < OSSL_STORE_SEARCH_get0_bytes_introduced then
    begin
      {$if declared(FC_OSSL_STORE_SEARCH_get0_bytes)}
      OSSL_STORE_SEARCH_get0_bytes := FC_OSSL_STORE_SEARCH_get0_bytes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_get0_bytes_removed)}
    if OSSL_STORE_SEARCH_get0_bytes_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_SEARCH_get0_bytes)}
      OSSL_STORE_SEARCH_get0_bytes := _OSSL_STORE_SEARCH_get0_bytes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_SEARCH_get0_bytes_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_SEARCH_get0_bytes');
    {$ifend}
  end;

    OSSL_STORE_SEARCH_get0_string := LoadLibFunction(ADllHandle, OSSL_STORE_SEARCH_get0_string_procname);
  FuncLoadError := not assigned(OSSL_STORE_SEARCH_get0_string);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_SEARCH_get0_string_allownil)}
    OSSL_STORE_SEARCH_get0_string := ERR_OSSL_STORE_SEARCH_get0_string;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_get0_string_introduced)}
    if LibVersion < OSSL_STORE_SEARCH_get0_string_introduced then
    begin
      {$if declared(FC_OSSL_STORE_SEARCH_get0_string)}
      OSSL_STORE_SEARCH_get0_string := FC_OSSL_STORE_SEARCH_get0_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_get0_string_removed)}
    if OSSL_STORE_SEARCH_get0_string_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_SEARCH_get0_string)}
      OSSL_STORE_SEARCH_get0_string := _OSSL_STORE_SEARCH_get0_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_SEARCH_get0_string_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_SEARCH_get0_string');
    {$ifend}
  end;

    OSSL_STORE_SEARCH_get0_digest := LoadLibFunction(ADllHandle, OSSL_STORE_SEARCH_get0_digest_procname);
  FuncLoadError := not assigned(OSSL_STORE_SEARCH_get0_digest);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_SEARCH_get0_digest_allownil)}
    OSSL_STORE_SEARCH_get0_digest := ERR_OSSL_STORE_SEARCH_get0_digest;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_get0_digest_introduced)}
    if LibVersion < OSSL_STORE_SEARCH_get0_digest_introduced then
    begin
      {$if declared(FC_OSSL_STORE_SEARCH_get0_digest)}
      OSSL_STORE_SEARCH_get0_digest := FC_OSSL_STORE_SEARCH_get0_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_get0_digest_removed)}
    if OSSL_STORE_SEARCH_get0_digest_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_SEARCH_get0_digest)}
      OSSL_STORE_SEARCH_get0_digest := _OSSL_STORE_SEARCH_get0_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_SEARCH_get0_digest_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_SEARCH_get0_digest');
    {$ifend}
  end;

  OSSL_STORE_expect := LoadLibFunction(ADllHandle, OSSL_STORE_expect_procname);
  FuncLoadError := not assigned(OSSL_STORE_expect);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_expect_allownil)}
    OSSL_STORE_expect := ERR_OSSL_STORE_expect;
    {$ifend}
    {$if declared(OSSL_STORE_expect_introduced)}
    if LibVersion < OSSL_STORE_expect_introduced then
    begin
      {$if declared(FC_OSSL_STORE_expect)}
      OSSL_STORE_expect := FC_OSSL_STORE_expect;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_expect_removed)}
    if OSSL_STORE_expect_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_expect)}
      OSSL_STORE_expect := _OSSL_STORE_expect;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_expect_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_expect');
    {$ifend}
  end;

  OSSL_STORE_find := LoadLibFunction(ADllHandle, OSSL_STORE_find_procname);
  FuncLoadError := not assigned(OSSL_STORE_find);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_find_allownil)}
    OSSL_STORE_find := ERR_OSSL_STORE_find;
    {$ifend}
    {$if declared(OSSL_STORE_find_introduced)}
    if LibVersion < OSSL_STORE_find_introduced then
    begin
      {$if declared(FC_OSSL_STORE_find)}
      OSSL_STORE_find := FC_OSSL_STORE_find;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_find_removed)}
    if OSSL_STORE_find_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_find)}
      OSSL_STORE_find := _OSSL_STORE_find;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_find_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_find');
    {$ifend}
  end;
//================

  OSSL_STORE_LOADER_fetch := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_fetch_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_fetch);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_fetch_allownil)}
    OSSL_STORE_LOADER_fetch := ERR_OSSL_STORE_LOADER_fetch;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_fetch_introduced)}
    if LibVersion < OSSL_STORE_LOADER_fetch_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_fetch)}
      OSSL_STORE_LOADER_fetch := FC_OSSL_STORE_LOADER_fetch;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_fetch_removed)}
    if OSSL_STORE_LOADER_fetch_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_fetch)}
      OSSL_STORE_LOADER_fetch := _OSSL_STORE_LOADER_fetch;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_fetch_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_fetch');
    {$ifend}
  end;

  OSSL_STORE_LOADER_up_ref := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_up_ref_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_up_ref);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_up_ref_allownil)}
    OSSL_STORE_LOADER_up_ref := ERR_OSSL_STORE_LOADER_up_ref;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_up_ref_introduced)}
    if LibVersion < OSSL_STORE_LOADER_up_ref_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_up_ref)}
      OSSL_STORE_LOADER_up_ref := FC_OSSL_STORE_LOADER_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_up_ref_removed)}
    if OSSL_STORE_LOADER_up_ref_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_up_ref)}
      OSSL_STORE_LOADER_up_ref := _OSSL_STORE_LOADER_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_up_ref_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_up_ref');
    {$ifend}
  end;

  OSSL_STORE_LOADER_free := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_free_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_free_allownil)}
    OSSL_STORE_LOADER_free := ERR_OSSL_STORE_LOADER_free;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_free_introduced)}
    if LibVersion < OSSL_STORE_LOADER_free_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_free)}
      OSSL_STORE_LOADER_free := FC_OSSL_STORE_LOADER_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_free_removed)}
    if OSSL_STORE_LOADER_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_free)}
      OSSL_STORE_LOADER_free := _OSSL_STORE_LOADER_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_free');
    {$ifend}
  end;

  OSSL_STORE_LOADER_get0_provider := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_get0_provider_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_get0_provider);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_get0_provider_allownil)}
    OSSL_STORE_LOADER_get0_provider := ERR_OSSL_STORE_LOADER_get0_provider;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_get0_provider_introduced)}
    if LibVersion < OSSL_STORE_LOADER_get0_provider_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_get0_provider)}
      OSSL_STORE_LOADER_get0_provider := FC_OSSL_STORE_LOADER_get0_provider;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_get0_provider_removed)}
    if OSSL_STORE_LOADER_get0_provider_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_get0_provider)}
      OSSL_STORE_LOADER_get0_provider := _OSSL_STORE_LOADER_get0_provider;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_get0_provider_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_get0_provider');
    {$ifend}
  end;

  OSSL_STORE_LOADER_get0_properties := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_get0_properties_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_get0_properties);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_get0_properties_allownil)}
    OSSL_STORE_LOADER_get0_properties := ERR_OSSL_STORE_LOADER_get0_properties;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_get0_properties_introduced)}
    if LibVersion < OSSL_STORE_LOADER_get0_properties_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_get0_properties)}
      OSSL_STORE_LOADER_get0_properties := FC_OSSL_STORE_LOADER_get0_properties;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_get0_properties_removed)}
    if OSSL_STORE_LOADER_get0_properties_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_get0_properties)}
      OSSL_STORE_LOADER_get0_properties := _OSSL_STORE_LOADER_get0_properties;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_get0_properties_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_get0_properties');
    {$ifend}
  end;

  OSSL_STORE_LOADER_get0_description := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_get0_description_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_get0_description);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_get0_description_allownil)}
    OSSL_STORE_LOADER_get0_description := ERR_OSSL_STORE_LOADER_get0_description;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_get0_description_introduced)}
    if LibVersion < OSSL_STORE_LOADER_get0_description_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_get0_description)}
      OSSL_STORE_LOADER_get0_description := FC_OSSL_STORE_LOADER_get0_description;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_get0_description_removed)}
    if OSSL_STORE_LOADER_get0_description_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_get0_description)}
      OSSL_STORE_LOADER_get0_description := _OSSL_STORE_LOADER_get0_description;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_get0_description_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_get0_description');
    {$ifend}
  end;

  OSSL_STORE_LOADER_is_a := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_is_a_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_is_a);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_is_a_allownil)}
    OSSL_STORE_LOADER_is_a := ERR_OSSL_STORE_LOADER_is_a;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_is_a_introduced)}
    if LibVersion < OSSL_STORE_LOADER_is_a_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_is_a)}
      OSSL_STORE_LOADER_is_a := FC_OSSL_STORE_LOADER_is_a;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_is_a_removed)}
    if OSSL_STORE_LOADER_is_a_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_is_a)}
      OSSL_STORE_LOADER_is_a := _OSSL_STORE_LOADER_is_a;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_is_a_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_is_a');
    {$ifend}
  end;

  OSSL_STORE_LOADER_do_all_provided := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_do_all_provided_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_do_all_provided);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_do_all_provided_allownil)}
    OSSL_STORE_LOADER_do_all_provided := ERR_OSSL_STORE_LOADER_do_all_provided;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_do_all_provided_introduced)}
    if LibVersion < OSSL_STORE_LOADER_do_all_provided_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_do_all_provided)}
      OSSL_STORE_LOADER_do_all_provided := FC_OSSL_STORE_LOADER_do_all_provided;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_do_all_provided_removed)}
    if OSSL_STORE_LOADER_do_all_provided_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_do_all_provided)}
      OSSL_STORE_LOADER_do_all_provided := _OSSL_STORE_LOADER_do_all_provided;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_do_all_provided_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_do_all_provided');
    {$ifend}
  end;

  OSSL_STORE_LOADER_names_do_all := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_names_do_all_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_names_do_all);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_names_do_all_allownil)}
    OSSL_STORE_LOADER_names_do_all := ERR_OSSL_STORE_LOADER_names_do_all;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_names_do_all_introduced)}
    if LibVersion < OSSL_STORE_LOADER_names_do_all_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_names_do_all)}
      OSSL_STORE_LOADER_names_do_all := FC_OSSL_STORE_LOADER_names_do_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_names_do_all_removed)}
    if OSSL_STORE_LOADER_names_do_all_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_names_do_all)}
      OSSL_STORE_LOADER_names_do_all := _OSSL_STORE_LOADER_names_do_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_names_do_all_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_names_do_all');
    {$ifend}
  end;
end;

procedure Unload;
begin
  OSSL_STORE_open := nil;
  OSSL_STORE_open_ex := nil;
  OSSL_STORE_load := nil;
  OSSL_STORE_delete := nil;
  OSSL_STORE_eof := nil;
  OSSL_STORE_error := nil;
  OSSL_STORE_close := nil;
  OSSL_STORE_attach := nil;

  OSSL_STORE_INFO_new := nil;
  OSSL_STORE_INFO_new_NAME := nil;
  OSSL_STORE_INFO_set0_NAME_description := nil;
  OSSL_STORE_INFO_new_PARAMS := nil;
  OSSL_STORE_INFO_new_PUBKEY := nil;
  OSSL_STORE_INFO_new_PKEY := nil;
  OSSL_STORE_INFO_new_CERT := nil;
  OSSL_STORE_INFO_new_CRL := nil;

  OSSL_STORE_INFO_get_type := nil;
  OSSL_STORE_INFO_get0_data   := nil;
  OSSL_STORE_INFO_get0_NAME  := nil;
  OSSL_STORE_INFO_get1_NAME  := nil;
  OSSL_STORE_INFO_get0_NAME_description := nil;
  OSSL_STORE_INFO_get1_NAME_description := nil;
  OSSL_STORE_INFO_get0_PARAMS := nil;

  OSSL_STORE_INFO_get1_PARAMS := nil;
  OSSL_STORE_INFO_get0_PUBKEY := nil;
  OSSL_STORE_INFO_get1_PUBKEY := nil;
  OSSL_STORE_INFO_get0_PKEY := nil;
  OSSL_STORE_INFO_get1_PKEY := nil;
  OSSL_STORE_INFO_get0_CERT := nil;

  OSSL_STORE_INFO_get1_CERT := nil;
  OSSL_STORE_INFO_get0_CRL := nil;
  OSSL_STORE_INFO_get1_CRL := nil;
  OSSL_STORE_INFO_type_string := nil;
  OSSL_STORE_INFO_free := nil;
  OSSL_STORE_supports_search := nil;
  OSSL_STORE_SEARCH_by_name  := nil;
  OSSL_STORE_SEARCH_by_issuer_serial  := nil;
  OSSL_STORE_SEARCH_by_key_fingerprint := nil;
  OSSL_STORE_SEARCH_by_alias  := nil;
  OSSL_STORE_SEARCH_free := nil;
  OSSL_STORE_SEARCH_get_type  := nil;
  OSSL_STORE_SEARCH_get0_name := nil;
  OSSL_STORE_SEARCH_get0_serial := nil;
  OSSL_STORE_SEARCH_get0_bytes  := nil;
  OSSL_STORE_SEARCH_get0_string := nil;
  OSSL_STORE_SEARCH_get0_digest  := nil;
  OSSL_STORE_expect  := nil;
  OSSL_STORE_find := nil;
  OSSL_STORE_LOADER_fetch := nil;
  OSSL_STORE_LOADER_up_ref := nil;
  OSSL_STORE_LOADER_free := nil;
  OSSL_STORE_LOADER_get0_provider := nil;
  OSSL_STORE_LOADER_get0_properties := nil;
  OSSL_STORE_LOADER_get0_description := nil;
  OSSL_STORE_LOADER_is_a := nil;
  OSSL_STORE_LOADER_do_all_provided := nil;
  OSSL_STORE_LOADER_names_do_all := nil;

end;
  {$ENDIF}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
