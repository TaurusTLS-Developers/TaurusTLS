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
{*  Copyright (c) 2024 TaurusTLS Developers, All Rights Reserved              *}
{*                                                                            *}
{* Portions of this software are Copyright (c) 1993 – 2018,                   *}
{* Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  *}
{******************************************************************************}

unit TaurusTLSHeaders_ech;

interface
uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_hpke,
  TaurusTLSHeaders_types;

  {$MINENUMSIZE 4}

const
{*
 * Some externally visible limits - most used for sanity checks that could be
 * bigger if needed, but that work for now
 *}
  OSSL_ECH_MAX_PAYLOAD_LEN = 1500; //* max ECH ciphertext to en/decode */
  OSSL_ECH_MIN_ECHCONFIG_LEN = 32; //* min for all encodings */
  OSSL_ECH_MAX_ECHCONFIG_LEN = 1500; //* max for all encodings */
  OSSL_ECH_MAX_ECHCONFIGEXT_LEN = 512; //* ECHConfig extension max */
  OSSL_ECH_MAX_MAXNAMELEN = 255; //* ECHConfig max for max name length */
  OSSL_ECH_MAX_PUBLICNAME = 255; //* max ECHConfig public name length */
  OSSL_ECH_MAX_ALPNLEN = 255; //* max alpn length */
  OSSL_ECH_OUTERS_MAX = 20; //* max extensions we compress via outer-exts */
  OSSL_ECH_ALLEXTS_MAX = 32; //* max total number of extension we allow */

{*
 * ECH version. We only support RFC 9849 as of now.  As/if new ECHConfig
 * versions are added, those will be noted here.
 *}
  OSSL_ECH_RFC9849_VERSION = $fe0d; //* official ECHConfig version */
//* latest version from an RFC */
  OSSL_ECH_CURRENT_VERSION = OSSL_ECH_RFC9849_VERSION;

//* Return codes from SSL_ech_get1_status */
  SSL_ECH_STATUS_BACKEND = 4; //* ECH backend: saw an ech_is_inner */
  SSL_ECH_STATUS_GREASE_ECH = 3; //* GREASEd and got an ECH in return */
  SSL_ECH_STATUS_GREASE = 2; //* ECH GREASE happened  */
  SSL_ECH_STATUS_SUCCESS = 1; //* Success */
  SSL_ECH_STATUS_FAILED = 0; //* Some internal or protocol error */
  SSL_ECH_STATUS_BAD_CALL = -100; //* Some in/out arguments were NULL */
  SSL_ECH_STATUS_NOT_TRIED = -101; //* ECH wasn't attempted  */
  SSL_ECH_STATUS_BAD_NAME = -102; //* ECH ok but server cert bad */
  SSL_ECH_STATUS_NOT_CONFIGURED = -103; //* ECH wasn't configured */
  SSL_ECH_STATUS_FAILED_ECH = -105; //* Tried, failed, got an ECH, from a good name */
  SSL_ECH_STATUS_FAILED_ECH_BAD_NAME = -106; //* Tried, failed, got an ECH, from a bad name */

//* if a caller wants to index the last entry in the store */
  OSSL_ECHSTORE_LAST = -1;
//* if a caller wants all entries in the store, e.g. to print public values */
  OSSL_ECHSTORE_ALL = -2;

//* Values for the for_retry inputs */
  OSSL_ECH_FOR_RETRY = 1;
  OSSL_ECH_NO_RETRY = 0;

type
  SSL_ech_cb_func = function(s : PSSL; const str_ : PIdAnsiChar) : TIdC_UINT; cdecl;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  OSSL_ECHSTORE_new : function(libctx : POSSL_LIB_CTX; const propq : PIdAnsichar) : POSSL_ECHSTORE ; cdecl = nil;
  OSSL_ECHSTORE_free : procedure(es : POSSL_ECHSTORE) ; cdecl = nil;
  OSSL_ECHSTORE_new_config : function(es : POSSL_ECHSTORE;
    echversion : TIdC_UINT16; max_name_length : TIdC_UINT8;
    const public_name : PIdAnsiChar;  suite : OSSL_HPKE_SUITE) : TIdC_INT ; cdecl = nil;
  OSSL_ECHSTORE_write_pem : function(es : POSSL_ECHSTORE; index : TIdC_INT; _out : PBIO) : TIdC_INT ; cdecl = nil;
  OSSL_ECHSTORE_read_echconfiglist : function(es : POSSL_ECHSTORE; _in : PBIO) : TIdC_INT ; cdecl = nil;
  OSSL_ECHSTORE_get1_info : function(es : POSSL_ECHSTORE; index : TIdC_INT; loaded_secs : PIdC_TIMET;
    public_name, echconfig : PPIdAnsiChar;
    has_private, for_retry : PIdC_INT) : TIdC_INT ; cdecl = nil;
  OSSL_ECHSTORE_downselect : function(es : POSSL_ECHSTORE; index : TIdC_INT) : TIdC_INT ; cdecl = nil;
  OSSL_ECHSTORE_set1_key_and_read_pem : function(es : POSSL_ECHSTORE; priv : PEVP_PKEY;
    _in : PBIO; for_retry : TIdC_INT) : TIdC_INT ; cdecl = nil;
  OSSL_ECHSTORE_read_pem : function(es : POSSL_ECHSTORE; _in : PBIO; for_retry : TIdC_INT) : TIdC_INT ; cdecl = nil;
  OSSL_ECHSTORE_num_entries : function(const es : POSSL_ECHSTORE; numentries : TIdC_INT) : TIdC_INT ; cdecl = nil;
  OSSL_ECHSTORE_num_keys : function(es : POSSL_ECHSTORE; numkeys : PIdC_INT) : TIdC_INT ; cdecl = nil;
  OSSL_ECHSTORE_flush_keys : function(es : POSSL_ECHSTORE; age : TIdC_TIMET) : TIdC_INT ; cdecl = nil;

{*
 * APIs relating OSSL_ECHSTORE to SSL/SSL_CTX
 *}
  SSL_CTX_set1_echstore : function(ctx : PSSL_CTX; es : POSSL_ECHSTORE) : TIdC_INT ; cdecl = nil;
  SSL_set1_echstore : function(s : PSSL; es : POSSL_ECHSTORE) : TIdC_INT ; cdecl = nil;

  SSL_CTX_get1_echstore : function(const ctx : PSSL_CTX) : POSSL_ECHSTORE ; cdecl = nil;
  SSL_get1_echstore : function(const s : PSSL) : POSSL_ECHSTORE ; cdecl = nil;

  SSL_ech_set1_server_names : function(s : PSSL; const inner_name,
    outer_name : PIdAnsiChar; no_outer : TIdC_INT) : TIdC_INT ; cdecl = nil;
  SSL_ech_set1_outer_server_name : function(s : PSSL; const outer_name : PIdAnsiChar; no_outer : TIdC_INT) : TIdC_INT ; cdecl = nil;
{*
 * Note that this function returns 1 for success and 0 for error. This
 * contrasts with SSL_set1_alpn_protos() which (unusually for OpenSSL)
 * returns 0 for success and 1 on error.
 *}
  SSL_ech_set1_outer_alpn_protos : function(s : PSSL; const protos : PByte;
    const protos_len : TIdC_SIZET) : TIdC_INT ; cdecl = nil;

  SSL_ech_get1_status : function(s : PSSL; inner_sni, outer_sni : PPIdAnsiChar) : TIdC_INT ; cdecl = nil;
  SSL_ech_set1_grease_suite : function(s : PSSL; const suite : PIdAnsiChar) : TIdC_INT ; cdecl = nil;
  SSL_ech_set_grease_type : function(s : PSSL;  _type : TIdC_UINT16) : TIdC_INT ; cdecl = nil;
  SSL_ech_set_callback : procedure(s : PSSL;  f : SSL_ech_cb_func) ; cdecl = nil;
  SSL_ech_get1_retry_config : function(s : PSSL; ec : PPByte;  eclen : PIdC_SIZET) : TIdC_INT ; cdecl = nil;

{*
 * Note that this function returns 1 for success and 0 for error. This
 * contrasts with SSL_set1_alpn_protos() which (unusually for OpenSSL)
 * returns 0 for success and 1 on error.
 *}
  SSL_CTX_ech_set1_outer_alpn_protos : function(s : PSSL_CTX; const protos : PByte;
    const protos_len : TIdC_SIZET) : TIdC_INT ; cdecl = nil;
  SSL_CTX_ech_set_callback : procedure(ctx : PSSL_CTX;  f : SSL_ech_cb_func) ; cdecl = nil;
  SSL_set1_ech_config_list : function(ssl : PSSL; const ecl : PIdC_UINT8; ecl_len : TIdC_SIZET) : TIdC_INT; cdecl = nil;

{$ELSE}
  function OSSL_ECHSTORE_new(libctx : POSSL_LIB_CTX; const propq : PIdAnsichar) : POSSL_ECHSTORE cdecl; external CLibSSL;
  procedure OSSL_ECHSTORE_free(es : POSSL_ECHSTORE) cdecl; external CLibSSL;
  function OSSL_ECHSTORE_new_config(es : POSSL_ECHSTORE;
    echversion : TIdC_UINT16; max_name_length : TIdC_UINT8;
    const public_name : PIdAnsiChar;  suite : OSSL_HPKE_SUITE) : TIdC_INT cdecl; external CLibSSL;
  function OSSL_ECHSTORE_write_pem(es : POSSL_ECHSTORE; index : TIdC_INT; _out : PBIO) : TIdC_INT  cdecl; external CLibSSL;
  function OSSL_ECHSTORE_read_echconfiglist(es : POSSL_ECHSTORE; _in : PBIO) : TIdC_INT cdecl; external CLibSSL;
  function OSSL_ECHSTORE_get1_info(es : POSSL_ECHSTORE; index : TIdC_INT; loaded_secs : PIdC_TIMET;
    public_name, echconfig : PPIdAnsiChar;
    has_private, for_retry : PIdC_INT) : TIdC_INT cdecl; external CLibSSL;
  function OSSL_ECHSTORE_downselect(es : POSSL_ECHSTORE; index : TIdC_INT) : TIdC_INT cdecl; external CLibSSL;
  function OSSL_ECHSTORE_set1_key_and_read_pem(es : POSSL_ECHSTORE; priv : PEVP_PKEY;
    _in : PBIO; for_retry : TIdC_INT) : TIdC_INT cdecl; external CLibSSL;
  function OSSL_ECHSTORE_read_pem(es : POSSL_ECHSTORE; _in : PBIO; for_retry : TIdC_INT) : TIdC_INT  cdecl; external CLibSSL;
  function OSSL_ECHSTORE_num_entries(const es : POSSL_ECHSTORE; numentries : TIdC_INT) : TIdC_INT  cdecl; external CLibSSL;
  function OSSL_ECHSTORE_num_keys(es : POSSL_ECHSTORE; numkeys : PIdC_INT) : TIdC_INT cdecl; external CLibSSL;
  function OSSL_ECHSTORE_flush_keys(es : POSSL_ECHSTORE; age : TIdC_TIMET) : TIdC_INT  cdecl; external CLibSSL;

{*
 * APIs relating OSSL_ECHSTORE to SSL/SSL_CTX
 *}
  function SSL_CTX_set1_echstore(ctx : PSSL_CTX; es : POSSL_ECHSTORE) : TIdC_INT  cdecl; external CLibSSL;
  function SSL_set1_echstore(s : PSSL; es : POSSL_ECHSTORE) : TIdC_INT  cdecl; external CLibSSL;

  function SSL_CTX_get1_echstore(const ctx : PSSL_CTX) : POSSL_ECHSTORE  cdecl; external CLibSSL;
  function SSL_get1_echstore(const s : PSSL) : POSSL_ECHSTORE  cdecl; external CLibSSL;

  function SSL_ech_set1_server_names(s : PSSL; const inner_name,
    outer_name : PIdAnsiChar; no_outer : TIdC_INT) : TIdC_INT  cdecl; external CLibSSL;
  function SSL_ech_set1_outer_server_name(s : PSSL; const outer_name : PIdAnsiChar; no_outer : TIdC_INT) : TIdC_INT  cdecl; external CLibSSL;
{*
 * Note that this function returns 1 for success and 0 for error. This
 * contrasts with SSL_set1_alpn_protos() which (unusually for OpenSSL)
 * returns 0 for success and 1 on error.
 *}
  function SSL_ech_set1_outer_alpn_protos(s : PSSL; const protos : PByte;
    const protos_len : TIdC_SIZET) : TIdC_INT  cdecl; external CLibSSL;

  function SSL_ech_get1_status(s : PSSL; inner_sni, outer_sni : PPIdAnsiChar) : TIdC_INT  cdecl; external CLibSSL;
  function SSL_ech_set1_grease_suite(s : PSSL; const suite : PIdAnsiChar) : TIdC_INT  cdecl; external CLibSSL;
  function SSL_ech_set_grease_type(s : PSSL;  _type : TIdC_UINT16) : TIdC_INT  cdecl; external CLibSSL;
  procedure SSL_ech_set_callback(s : PSSL;  f : SSL_ech_cb_func)  cdecl; external CLibSSL;
  function SSL_ech_get1_retry_config(s : PSSL; ec : PPByte;  eclen : PIdC_SIZET) : TIdC_INT  cdecl; external CLibSSL;

{*
 * Note that this function returns 1 for success and 0 for error. This
 * contrasts with SSL_set1_alpn_protos() which (unusually for OpenSSL)
 * returns 0 for success and 1 on error.
 *}
  function SSL_CTX_ech_set1_outer_alpn_protos(s : PSSL_CTX; const protos : PByte;
    const protos_len : TIdC_SIZET) : TIdC_INT  cdecl; external CLibSSL;
  procedure SSL_CTX_ech_set_callback(ctx : PSSL_CTX;  f : SSL_ech_cb_func)  cdecl; external CLibSSL;
  function SSL_set1_ech_config_list(ssl : PSSL; const ecl : PIdC_UINT8; ecl_len : TIdC_SIZET) : TIdC_INT cdecl; external CLibSSL;

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
  OSSL_ECHSTORE_new_procname = 'OSSL_ECHSTORE_new';
  OSSL_ECHSTORE_free_procname = 'OSSL_ECHSTORE_free';
  OSSL_ECHSTORE_new_config_procname = 'OSSL_ECHSTORE_new_config';
  OSSL_ECHSTORE_write_pem_procname = 'OSSL_ECHSTORE_write_pem';
  OSSL_ECHSTORE_read_echconfiglist_procname = 'OSSL_ECHSTORE_read_echconfiglist';
  OSSL_ECHSTORE_get1_info_procname = 'OSSL_ECHSTORE_get1_info';
  OSSL_ECHSTORE_downselect_procname = 'OSSL_ECHSTORE_downselect';
  OSSL_ECHSTORE_set1_key_and_read_pem_procname = 'OSSL_ECHSTORE_set1_key_and_read_pem';
  OSSL_ECHSTORE_read_pem_procname = 'OSSL_ECHSTORE_read_pem';
  OSSL_ECHSTORE_num_entries_procname = 'OSSL_ECHSTORE_num_entries';
  OSSL_ECHSTORE_num_keys_procname = 'OSSL_ECHSTORE_num_keys';
  OSSL_ECHSTORE_flush_keys_procname = 'OSSL_ECHSTORE_flush_keys';
  SSL_CTX_set1_echstore_procname = 'SSL_CTX_set1_echstore';
  SSL_set1_echstore_procname = 'SSL_set1_echstore';
  SSL_CTX_get1_echstore_procname = 'SSL_CTX_get1_echstore';
  SSL_get1_echstore_procname = 'SSL_get1_echstore';
  SSL_ech_set1_server_names_procname = 'SSL_ech_set1_server_names';
  SSL_ech_set1_outer_server_name_procname = 'SSL_ech_set1_outer_server_name';
  SSL_ech_set1_outer_alpn_protos_procname = 'SSL_ech_set1_outer_alpn_protos';
  SSL_ech_get1_status_procname = 'SSL_ech_get1_status';
  SSL_ech_set1_grease_suite_procname = 'SSL_ech_set1_grease_suite';
  SSL_ech_set_grease_type_procname = 'SSL_ech_set_grease_type';
  SSL_ech_set_callback_procname = 'SSL_ech_set_callback';
  SSL_ech_get1_retry_config_procname = 'SSL_ech_get1_retry_config';
  SSL_CTX_ech_set1_outer_alpn_protos_procname = 'SSL_CTX_ech_set1_outer_alpn_protos';
  SSL_CTX_ech_set_callback_procname = 'SSL_CTX_ech_set_callback';
  SSL_set1_ech_config_list_procname = 'SSL_set1_ech_config_list';

  ECH_introduced =  (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_ECHSTORE_new_introduced = ECH_introduced;
  OSSL_ECHSTORE_free_introduced = ECH_introduced;
  OSSL_ECHSTORE_new_config_introduced = ECH_introduced;
  OSSL_ECHSTORE_write_pem_introduced = ECH_introduced;
  OSSL_ECHSTORE_read_echconfiglist_introduced = ECH_introduced;
  OSSL_ECHSTORE_get1_info_introduced = ECH_introduced;
  OSSL_ECHSTORE_downselect_introduced = ECH_introduced;
  OSSL_ECHSTORE_set1_key_and_read_pem_introduced = ECH_introduced;
  ECHSTORE_read_pem_introduced = ECH_introduced;
  OSSL_ECHSTORE_num_entries_introduced = ECH_introduced;
  OSSL_ECHSTORE_num_keys_introduced = ECH_introduced;
  OSSL_ECHSTORE_flush_keys_introduced = ECH_introduced;
  SSL_CTX_set1_echstore_introduced = ECH_introduced;
  SSL_set1_echstore_introduced = ECH_introduced;
  SSL_CTX_get1_echstore_introduced = ECH_introduced;
  SSL_get1_echstore_introduced = ECH_introduced;
  SSL_ech_set1_server_names_introduced = ECH_introduced;
  SSL_ech_set1_outer_server_name_introduced = ECH_introduced;
  SSL_ech_set1_outer_alpn_protos_introduced = ECH_introduced;
  SSL_ech_get1_status_introduced = ECH_introduced;
  SSL_ech_set1_grease_suite_introduced = ECH_introduced;
  SSL_ech_set_grease_type_introduced = ECH_introduced;
  SSL_ech_set_callback_introduced = ECH_introduced;
  SSL_ech_get1_retry_config_introduced = ECH_introduced;
  SSL_CTX_ech_set1_outer_alpn_protos_introduced = ECH_introduced;
  SSL_CTX_ech_set_callback_introduced = ECH_introduced;
  SSL_set1_ech_config_list_introduced = ECH_introduced;

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc}
function ERR_OSSL_ECHSTORE_new(libctx : POSSL_LIB_CTX; const propq : PIdAnsichar) : POSSL_ECHSTORE cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ECHSTORE_new_procname);
end;

procedure ERR_OSSL_ECHSTORE_free(es : POSSL_ECHSTORE) cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ECHSTORE_free_procname);
end;

function ERR_OSSL_ECHSTORE_new_config(es : POSSL_ECHSTORE;
    echversion : TIdC_UINT16; max_name_length : TIdC_UINT8;
    const public_name : PIdAnsiChar;  suite : OSSL_HPKE_SUITE) : TIdC_INT cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ECHSTORE_new_config_procname);
end;

function ERR_OSSL_ECHSTORE_write_pem(es : POSSL_ECHSTORE; index : TIdC_INT; _out : PBIO) : TIdC_INT  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ECHSTORE_write_pem_procname);
end;

function ERR_OSSL_ECHSTORE_read_echconfiglist(es : POSSL_ECHSTORE; _in : PBIO) : TIdC_INT cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ECHSTORE_read_echconfiglist_procname);
end;

function ERR_OSSL_ECHSTORE_get1_info(es : POSSL_ECHSTORE; index : TIdC_INT; loaded_secs : PIdC_TIMET;
    public_name, echconfig : PPIdAnsiChar;
    has_private, for_retry : PIdC_INT) : TIdC_INT cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ECHSTORE_get1_info_procname);
end;

function ERR_OSSL_ECHSTORE_downselect(es : POSSL_ECHSTORE; index : TIdC_INT) : TIdC_INT cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ECHSTORE_downselect_procname);
end;

function ERR_OSSL_ECHSTORE_set1_key_and_read_pem(es : POSSL_ECHSTORE; priv : PEVP_PKEY;
    _in : PBIO; for_retry : TIdC_INT) : TIdC_INT cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ECHSTORE_set1_key_and_read_pem_procname);
end;

function ERR_OSSL_ECHSTORE_read_pem(es : POSSL_ECHSTORE; _in : PBIO; for_retry : TIdC_INT) : TIdC_INT  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ECHSTORE_read_pem_procname);
end;

function ERR_OSSL_ECHSTORE_num_entries(const es : POSSL_ECHSTORE; numentries : TIdC_INT) : TIdC_INT  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ECHSTORE_num_entries_procname);
end;

function ERR_OSSL_ECHSTORE_num_keys(es : POSSL_ECHSTORE; numkeys : PIdC_INT) : TIdC_INT cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ECHSTORE_num_keys_procname);
end;

function ERR_OSSL_ECHSTORE_flush_keys(es : POSSL_ECHSTORE; age : TIdC_TIMET) : TIdC_INT  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ECHSTORE_flush_keys_procname);
end;
{*
 * APIs relating OSSL_ECHSTORE to SSL/SSL_CTX
 *}
function ERR_SSL_CTX_set1_echstore(ctx : PSSL_CTX; es : POSSL_ECHSTORE) : TIdC_INT  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SSL_CTX_set1_echstore_procname);
end;

function ERR_SSL_set1_echstore(s : PSSL; es : POSSL_ECHSTORE) : TIdC_INT  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SSL_set1_echstore_procname);

end;

function ERR_SSL_CTX_get1_echstore(const ctx : PSSL_CTX) : POSSL_ECHSTORE  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SSL_CTX_get1_echstore_procname);
end;

function ERR_SSL_get1_echstore(const s : PSSL) : POSSL_ECHSTORE  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SSL_get1_echstore_procname);
end;

function ERR_SSL_ech_set1_server_names(s : PSSL; const inner_name,
    outer_name : PIdAnsiChar; no_outer : TIdC_INT) : TIdC_INT  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SSL_ech_set1_server_names_procname);
end;

function ERR_SSL_ech_set1_outer_server_name(s : PSSL; const outer_name : PIdAnsiChar; no_outer : TIdC_INT) : TIdC_INT  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SSL_ech_set1_outer_server_name_procname);
end;
{*
 * Note that this function returns 1 for success and 0 for error. This
 * contrasts with SSL_set1_alpn_protos() which (unusually for OpenSSL)
 * returns 0 for success and 1 on error.
 *}
function ERR_SSL_ech_set1_outer_alpn_protos(s : PSSL; const protos : PByte;
    const protos_len : TIdC_SIZET) : TIdC_INT  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SSL_ech_set1_outer_alpn_protos_procname);
end;

function ERR_SSL_ech_get1_status(s : PSSL; inner_sni, outer_sni : PPIdAnsiChar) : TIdC_INT  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SSL_ech_get1_status_procname);
end;

function ERR_SSL_ech_set1_grease_suite(s : PSSL; const suite : PIdAnsiChar) : TIdC_INT  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SSL_ech_set1_grease_suite_procname);
end;

function ERR_SSL_ech_set_grease_type(s : PSSL;  _type : TIdC_UINT16) : TIdC_INT  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SSL_ech_set_grease_type_procname);
end;

procedure ERR_SSL_ech_set_callback(s : PSSL;  f : SSL_ech_cb_func)  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SSL_ech_set_callback_procname);
end;

function ERR_SSL_ech_get1_retry_config(s : PSSL; ec : PPByte;  eclen : PIdC_SIZET) : TIdC_INT  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SSL_ech_get1_retry_config_procname);

end;
{*
 * Note that this function returns 1 for success and 0 for error. This
 * contrasts with SSL_set1_alpn_protos() which (unusually for OpenSSL)
 * returns 0 for success and 1 on error.
 *}
function ERR_SSL_CTX_ech_set1_outer_alpn_protos(s : PSSL_CTX; const protos : PByte;
    const protos_len : TIdC_SIZET) : TIdC_INT  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SSL_CTX_ech_set1_outer_alpn_protos_procname);
end;

procedure ERR_SSL_CTX_ech_set_callback(ctx : PSSL_CTX;  f : SSL_ech_cb_func)  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SSL_CTX_ech_set_callback_procname);
end;

function ERR_SSL_set1_ech_config_list(ssl : PSSL; const ecl : PIdC_UINT8; ecl_len : TIdC_SIZET) : TIdC_INT cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SSL_set1_ech_config_list_procname);
end;
  {$I TaurusTLSNoRetValOn.inc}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  OSSL_ECHSTORE_new := LoadLibFunction(ADllHandle, OSSL_ECHSTORE_new_procname);
  FuncLoadError := not assigned(OSSL_ECHSTORE_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ECHSTORE_new_allownil)}
    OSSL_ECHSTORE_new := ERR_OSSL_ECHSTORE_new;
    {$ifend}
    {$if declared(OSSL_ECHSTORE_new_introduced)}
    if LibVersion < OSSL_ECHSTORE_new_introduced then
    begin
      {$if declared(FC_OSSL_ECHSTORE_new)}
      OSSL_ECHSTORE_new := FC_OSSL_ECHSTORE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ECHSTORE_new_removed)}
    if OSSL_ECHSTORE_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ECHSTORE_new)}
      OSSL_ECHSTORE_new := _OSSL_ECHSTORE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ECHSTORE_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ECHSTORE_new');
    {$ifend}
  end;

  OSSL_ECHSTORE_free := LoadLibFunction(ADllHandle, OSSL_ECHSTORE_free_procname);
  FuncLoadError := not assigned(OSSL_ECHSTORE_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ECHSTORE_free_allownil)}
    OSSL_ECHSTORE_free := ERR_OSSL_ECHSTORE_free;
    {$ifend}
    {$if declared(OSSL_ECHSTORE_free_introduced)}
    if LibVersion < OSSL_ECHSTORE_free_introduced then
    begin
      {$if declared(FC_OSSL_ECHSTORE_free)}
      OSSL_ECHSTORE_free := FC_OSSL_ECHSTORE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ECHSTORE_free_removed)}
    if OSSL_ECHSTORE_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ECHSTORE_free)}
      OSSL_ECHSTORE_free := _OSSL_ECHSTORE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ECHSTORE_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ECHSTORE_free');
    {$ifend}
  end;

  OSSL_ECHSTORE_new_config := LoadLibFunction(ADllHandle, OSSL_ECHSTORE_new_config_procname);
  FuncLoadError := not assigned(OSSL_ECHSTORE_new_config);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ECHSTORE_new_config_allownil)}
    OSSL_ECHSTORE_new_config := ERR_OSSL_ECHSTORE_new_config;
    {$ifend}
    {$if declared(OSSL_ECHSTORE_new_config_introduced)}
    if LibVersion < OSSL_ECHSTORE_new_config_introduced then
    begin
      {$if declared(FC_OSSL_ECHSTORE_new_config)}
      OSSL_ECHSTORE_new_config := FC_OSSL_ECHSTORE_new_config;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ECHSTORE_new_config_removed)}
    if OSSL_ECHSTORE_new_config_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ECHSTORE_new_config)}
      OSSL_ECHSTORE_new_config := _OSSL_ECHSTORE_new_config;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ECHSTORE_new_config_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ECHSTORE_new_config');
    {$ifend}
  end;

  OSSL_ECHSTORE_write_pem := LoadLibFunction(ADllHandle, OSSL_ECHSTORE_write_pem_procname);
  FuncLoadError := not assigned(OSSL_ECHSTORE_write_pem);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ECHSTORE_write_pem_allownil)}
    OSSL_ECHSTORE_write_pem := ERR_OSSL_ECHSTORE_write_pem;
    {$ifend}
    {$if declared(OSSL_ECHSTORE_write_pem_introduced)}
    if LibVersion < OSSL_ECHSTORE_write_pem_introduced then
    begin
      {$if declared(FC_OSSL_ECHSTORE_write_pem)}
      OSSL_ECHSTORE_write_pem := FC_OSSL_ECHSTORE_write_pem;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ECHSTORE_write_pem_removed)}
    if OSSL_ECHSTORE_write_pem_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ECHSTORE_write_pem)}
      OSSL_ECHSTORE_write_pem := _OSSL_ECHSTORE_write_pem;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ECHSTORE_write_pem_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ECHSTORE_write_pem');
    {$ifend}
  end;

  OSSL_ECHSTORE_read_echconfiglist := LoadLibFunction(ADllHandle, OSSL_ECHSTORE_read_echconfiglist_procname);
  FuncLoadError := not assigned(OSSL_ECHSTORE_read_echconfiglist);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ECHSTORE_read_echconfiglist_allownil)}
    OSSL_ECHSTORE_read_echconfiglist := ERR_OSSL_ECHSTORE_read_echconfiglist;
    {$ifend}
    {$if declared(OSSL_ECHSTORE_read_echconfiglist_introduced)}
    if LibVersion < OSSL_ECHSTORE_read_echconfiglist_introduced then
    begin
      {$if declared(FC_OSSL_ECHSTORE_read_echconfiglist)}
      OSSL_ECHSTORE_read_echconfiglist := FC_OSSL_ECHSTORE_read_echconfiglist;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ECHSTORE_read_echconfiglist_removed)}
    if OSSL_ECHSTORE_read_echconfiglist_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ECHSTORE_read_echconfiglist)}
      OSSL_ECHSTORE_read_echconfiglist := _OSSL_ECHSTORE_read_echconfiglist;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ECHSTORE_read_echconfiglist_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ECHSTORE_read_echconfiglist');
    {$ifend}
  end;

  OSSL_ECHSTORE_get1_info := LoadLibFunction(ADllHandle, OSSL_ECHSTORE_get1_info_procname);
  FuncLoadError := not assigned(OSSL_ECHSTORE_get1_info);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ECHSTORE_get1_info_allownil)}
    OSSL_ECHSTORE_get1_info := ERR_OSSL_ECHSTORE_get1_info;
    {$ifend}
    {$if declared(OSSL_ECHSTORE_get1_info_introduced)}
    if LibVersion < OSSL_ECHSTORE_get1_info_introduced then
    begin
      {$if declared(FC_OSSL_ECHSTORE_get1_info)}
      OSSL_ECHSTORE_get1_info := FC_OSSL_ECHSTORE_get1_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ECHSTORE_get1_info_removed)}
    if OSSL_ECHSTORE_get1_info_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ECHSTORE_get1_info)}
      OSSL_ECHSTORE_get1_info := _OSSL_ECHSTORE_get1_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ECHSTORE_get1_info_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ECHSTORE_get1_info');
    {$ifend}
  end;

  OSSL_ECHSTORE_downselect := LoadLibFunction(ADllHandle, OSSL_ECHSTORE_downselect_procname);
  FuncLoadError := not assigned(OSSL_ECHSTORE_downselect);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ECHSTORE_downselect_allownil)}
    OSSL_ECHSTORE_downselect := ERR_OSSL_ECHSTORE_downselect;
    {$ifend}
    {$if declared(OSSL_ECHSTORE_downselect_introduced)}
    if LibVersion < OSSL_ECHSTORE_downselect_introduced then
    begin
      {$if declared(FC_OSSL_ECHSTORE_downselect)}
      OSSL_ECHSTORE_downselect := FC_OSSL_ECHSTORE_downselect;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ECHSTORE_downselect_removed)}
    if OSSL_ECHSTORE_downselect_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ECHSTORE_downselect)}
      OSSL_ECHSTORE_downselect := _OSSL_ECHSTORE_downselect;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ECHSTORE_downselect_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ECHSTORE_downselect');
    {$ifend}
  end;

  OSSL_ECHSTORE_set1_key_and_read_pem := LoadLibFunction(ADllHandle, OSSL_ECHSTORE_set1_key_and_read_pem_procname);
  FuncLoadError := not assigned(OSSL_ECHSTORE_set1_key_and_read_pem);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ECHSTORE_set1_key_and_read_pem_allownil)}
    OSSL_ECHSTORE_set1_key_and_read_pem := ERR_OSSL_ECHSTORE_set1_key_and_read_pem;
    {$ifend}
    {$if declared(OSSL_ECHSTORE_set1_key_and_read_pem_introduced)}
    if LibVersion < OSSL_ECHSTORE_set1_key_and_read_pem_introduced then
    begin
      {$if declared(FC_OSSL_ECHSTORE_set1_key_and_read_pem)}
      OSSL_ECHSTORE_set1_key_and_read_pem := FC_OSSL_ECHSTORE_set1_key_and_read_pem;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ECHSTORE_set1_key_and_read_pem_removed)}
    if OSSL_ECHSTORE_set1_key_and_read_pem_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ECHSTORE_set1_key_and_read_pem)}
      OSSL_ECHSTORE_set1_key_and_read_pem := _OSSL_ECHSTORE_set1_key_and_read_pem;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ECHSTORE_set1_key_and_read_pem_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ECHSTORE_set1_key_and_read_pem');
    {$ifend}
  end;

  OSSL_ECHSTORE_read_pem := LoadLibFunction(ADllHandle, OSSL_ECHSTORE_read_pem_procname);
  FuncLoadError := not assigned(OSSL_ECHSTORE_read_pem);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ECHSTORE_read_pem_allownil)}
    OSSL_ECHSTORE_read_pem := ERR_OSSL_ECHSTORE_read_pem;
    {$ifend}
    {$if declared(OSSL_ECHSTORE_read_pem_introduced)}
    if LibVersion < OSSL_ECHSTORE_read_pem_introduced then
    begin
      {$if declared(FC_OSSL_ECHSTORE_read_pem)}
      OSSL_ECHSTORE_read_pem := FC_OSSL_ECHSTORE_read_pem;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ECHSTORE_read_pem_removed)}
    if OSSL_ECHSTORE_read_pem_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ECHSTORE_read_pem)}
      OSSL_ECHSTORE_read_pem := _OSSL_ECHSTORE_read_pem;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ECHSTORE_read_pem_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ECHSTORE_read_pem');
    {$ifend}
  end;

  OSSL_ECHSTORE_num_entries := LoadLibFunction(ADllHandle, OSSL_ECHSTORE_num_entries_procname);
  FuncLoadError := not assigned(OSSL_ECHSTORE_num_entries);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ECHSTORE_num_entries_allownil)}
    OSSL_ECHSTORE_num_entries := ERR_OSSL_ECHSTORE_num_entries;
    {$ifend}
    {$if declared(OSSL_ECHSTORE_num_entries_introduced)}
    if LibVersion < OSSL_ECHSTORE_num_entries_introduced then
    begin
      {$if declared(FC_OSSL_ECHSTORE_num_entries)}
      OSSL_ECHSTORE_num_entries := FC_OSSL_ECHSTORE_num_entries;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ECHSTORE_num_entries_removed)}
    if OSSL_ECHSTORE_num_entries_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ECHSTORE_num_entries)}
      OSSL_ECHSTORE_num_entries := _OSSL_ECHSTORE_num_entries;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ECHSTORE_num_entries_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ECHSTORE_num_entries');
    {$ifend}
  end;

  OSSL_ECHSTORE_num_keys := LoadLibFunction(ADllHandle, OSSL_ECHSTORE_num_keys_procname);
  FuncLoadError := not assigned(OSSL_ECHSTORE_num_keys);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ECHSTORE_num_keys_allownil)}
    OSSL_ECHSTORE_num_keys := ERR_OSSL_ECHSTORE_num_keys;
    {$ifend}
    {$if declared(OSSL_ECHSTORE_num_keys_introduced)}
    if LibVersion < OSSL_ECHSTORE_num_keys_introduced then
    begin
      {$if declared(FC_OSSL_ECHSTORE_num_keys)}
      OSSL_ECHSTORE_num_keys := FC_OSSL_ECHSTORE_num_keys;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ECHSTORE_num_keys_removed)}
    if OSSL_ECHSTORE_num_keys_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ECHSTORE_num_keys)}
      OSSL_ECHSTORE_num_keys := _OSSL_ECHSTORE_num_keys;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ECHSTORE_num_keys_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ECHSTORE_num_keys');
    {$ifend}
  end;

  OSSL_ECHSTORE_flush_keys := LoadLibFunction(ADllHandle, OSSL_ECHSTORE_flush_keys_procname);
  FuncLoadError := not assigned(OSSL_ECHSTORE_flush_keys);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ECHSTORE_flush_keys_allownil)}
    OSSL_ECHSTORE_flush_keys := ERR_OSSL_ECHSTORE_flush_keys;
    {$ifend}
    {$if declared(OSSL_ECHSTORE_flush_keys_introduced)}
    if LibVersion < OSSL_ECHSTORE_flush_keys_introduced then
    begin
      {$if declared(FC_OSSL_ECHSTORE_flush_keys)}
      OSSL_ECHSTORE_flush_keys := FC_OSSL_ECHSTORE_flush_keys;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ECHSTORE_flush_keys_removed)}
    if OSSL_ECHSTORE_flush_keys_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ECHSTORE_flush_keys)}
      OSSL_ECHSTORE_flush_keys := _OSSL_ECHSTORE_flush_keys;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ECHSTORE_flush_keys_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ECHSTORE_flush_keys');
    {$ifend}
  end;

  SSL_CTX_set1_echstore := LoadLibFunction(ADllHandle, SSL_CTX_set1_echstore_procname);
  FuncLoadError := not assigned(SSL_CTX_set1_echstore);
  if FuncLoadError then
  begin
    {$if not defined(SSL_CTX_set1_echstore_allownil)}
    SSL_CTX_set1_echstore := ERR_SSL_CTX_set1_echstore;
    {$ifend}
    {$if declared(SSL_CTX_set1_echstore_introduced)}
    if LibVersion < SSL_CTX_set1_echstore_introduced then
    begin
      {$if declared(FC_SSL_CTX_set1_echstore)}
      SSL_CTX_set1_echstore := FC_SSL_CTX_set1_echstore;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SSL_CTX_set1_echstore_removed)}
    if SSL_CTX_set1_echstore_removed <= LibVersion then
    begin
      {$if declared(_SSL_CTX_set1_echstore)}
      SSL_CTX_set1_echstore := _SSL_CTX_set1_echstore;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SSL_CTX_set1_echstore_allownil)}
    if FuncLoadError then
      AFailed.Add('SSL_CTX_set1_echstore');
    {$ifend}
  end;

  SSL_CTX_get1_echstore := LoadLibFunction(ADllHandle, SSL_CTX_get1_echstore_procname);
  FuncLoadError := not assigned(SSL_CTX_get1_echstore);
  if FuncLoadError then
  begin
    {$if not defined(SSL_CTX_get1_echstore_allownil)}
    SSL_CTX_get1_echstore := ERR_SSL_CTX_get1_echstore;
    {$ifend}
    {$if declared(SSL_CTX_get1_echstore_introduced)}
    if LibVersion < SSL_CTX_get1_echstore_introduced then
    begin
      {$if declared(FC_SSL_CTX_get1_echstore)}
      SSL_CTX_get1_echstore := FC_SSL_CTX_get1_echstore;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SSL_CTX_get1_echstore_removed)}
    if SSL_CTX_get1_echstore_removed <= LibVersion then
    begin
      {$if declared(_SSL_CTX_get1_echstore)}
      SSL_CTX_get1_echstore := _SSL_CTX_get1_echstore;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SSL_CTX_get1_echstore_allownil)}
    if FuncLoadError then
      AFailed.Add('SSL_CTX_get1_echstore');
    {$ifend}
  end;

  SSL_get1_echstore := LoadLibFunction(ADllHandle, SSL_get1_echstore_procname);
  FuncLoadError := not assigned(SSL_get1_echstore);
  if FuncLoadError then
  begin
    {$if not defined(SSL_get1_echstore_allownil)}
    SSL_get1_echstore := ERR_SSL_get1_echstore;
    {$ifend}
    {$if declared(SSL_get1_echstore_introduced)}
    if LibVersion < SSL_get1_echstore_introduced then
    begin
      {$if declared(FC_SSL_get1_echstore)}
      SSL_get1_echstore := FC_SSL_get1_echstore;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SSL_get1_echstore_removed)}
    if SSL_get1_echstore_removed <= LibVersion then
    begin
      {$if declared(_SSL_get1_echstore)}
      SSL_get1_echstore := _SSL_get1_echstore;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SSL_get1_echstore_allownil)}
    if FuncLoadError then
      AFailed.Add('SSL_get1_echstore');
    {$ifend}
  end;

  SSL_ech_set1_server_names := LoadLibFunction(ADllHandle, SSL_ech_set1_server_names_procname);
  FuncLoadError := not assigned(SSL_ech_set1_server_names);
  if FuncLoadError then
  begin
    {$if not defined(SSL_ech_set1_server_names_allownil)}
    SSL_ech_set1_server_names := ERR_SSL_ech_set1_server_names;
    {$ifend}
    {$if declared(SSL_ech_set1_server_names_introduced)}
    if LibVersion < SSL_ech_set1_server_names_introduced then
    begin
      {$if declared(FC_SSL_ech_set1_server_names)}
      SSL_ech_set1_server_names := FC_SSL_ech_set1_server_names;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SSL_ech_set1_server_names_removed)}
    if SSL_ech_set1_server_names_removed <= LibVersion then
    begin
      {$if declared(_SSL_ech_set1_server_names)}
      SSL_ech_set1_server_names := _SSL_ech_set1_server_names;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SSL_ech_set1_server_names_allownil)}
    if FuncLoadError then
      AFailed.Add('SSL_ech_set1_server_names');
    {$ifend}
  end;

  SSL_ech_set1_outer_server_name := LoadLibFunction(ADllHandle, SSL_ech_set1_outer_server_name_procname);
  FuncLoadError := not assigned(SSL_ech_set1_outer_server_name);
  if FuncLoadError then
  begin
    {$if not defined(SSL_ech_set1_outer_server_name_allownil)}
    SSL_ech_set1_outer_server_name := ERR_SSL_ech_set1_outer_server_name;
    {$ifend}
    {$if declared(SSL_ech_set1_outer_server_name_introduced)}
    if LibVersion < SSL_ech_set1_outer_server_name_introduced then
    begin
      {$if declared(FC_SSL_ech_set1_outer_server_name)}
      SSL_ech_set1_outer_server_name := FC_SSL_ech_set1_outer_server_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SSL_ech_set1_outer_server_name_removed)}
    if SSL_ech_set1_outer_server_name_removed <= LibVersion then
    begin
      {$if declared(_SSL_ech_set1_outer_server_name)}
      SSL_ech_set1_outer_server_name := _SSL_ech_set1_outer_server_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SSL_ech_set1_outer_server_name_allownil)}
    if FuncLoadError then
      AFailed.Add('SSL_ech_set1_outer_server_name');
    {$ifend}
  end;

  SSL_ech_set1_outer_alpn_protos := LoadLibFunction(ADllHandle, SSL_ech_set1_outer_alpn_protos_procname);
  FuncLoadError := not assigned(SSL_ech_set1_outer_alpn_protos);
  if FuncLoadError then
  begin
    {$if not defined(SSL_ech_set1_outer_alpn_protos_allownil)}
    SSL_ech_set1_outer_alpn_protos := ERR_SSL_ech_set1_outer_alpn_protos;
    {$ifend}
    {$if declared(SSL_ech_set1_outer_alpn_protos_introduced)}
    if LibVersion < SSL_ech_set1_outer_alpn_protos_introduced then
    begin
      {$if declared(FC_SSL_ech_set1_outer_alpn_protos)}
      SSL_ech_set1_outer_alpn_protos := FC_SSL_ech_set1_outer_alpn_protos;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SSL_ech_set1_outer_alpn_protos_removed)}
    if SSL_ech_set1_outer_alpn_protos_removed <= LibVersion then
    begin
      {$if declared(_SSL_ech_set1_outer_alpn_protos)}
      SSL_ech_set1_outer_alpn_protos := _SSL_ech_set1_outer_alpn_protos;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SSL_ech_set1_outer_alpn_protos_allownil)}
    if FuncLoadError then
      AFailed.Add('SSL_ech_set1_outer_alpn_protos');
    {$ifend}
  end;

  SSL_ech_get1_status := LoadLibFunction(ADllHandle, SSL_ech_get1_status_procname);
  FuncLoadError := not assigned(SSL_ech_get1_status);
  if FuncLoadError then
  begin
    {$if not defined(SSL_ech_get1_status_allownil)}
    SSL_ech_get1_status := ERR_SSL_ech_get1_status;
    {$ifend}
    {$if declared(SSL_ech_get1_status_introduced)}
    if LibVersion < SSL_ech_get1_status_introduced then
    begin
      {$if declared(FC_SSL_ech_get1_status)}
      SSL_ech_get1_status := FC_SSL_ech_get1_status;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SSL_ech_get1_status_removed)}
    if SSL_ech_get1_status_removed <= LibVersion then
    begin
      {$if declared(_SSL_ech_get1_status)}
      SSL_ech_get1_status := _SSL_ech_get1_status;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SSL_ech_get1_status_allownil)}
    if FuncLoadError then
      AFailed.Add('SSL_ech_get1_status');
    {$ifend}
  end;

  SSL_ech_set1_grease_suite := LoadLibFunction(ADllHandle, SSL_ech_set1_grease_suite_procname);
  FuncLoadError := not assigned(SSL_ech_set1_grease_suite);
  if FuncLoadError then
  begin
    {$if not defined(SSL_ech_set1_grease_suite_allownil)}
    SSL_ech_set1_grease_suite := ERR_SSL_ech_set1_grease_suite;
    {$ifend}
    {$if declared(SSL_ech_set1_grease_suite_introduced)}
    if LibVersion < SSL_ech_set1_grease_suite_introduced then
    begin
      {$if declared(FC_SSL_ech_set1_grease_suite)}
      SSL_ech_set1_grease_suite := FC_SSL_ech_set1_grease_suite;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SSL_ech_set1_grease_suite_removed)}
    if SSL_ech_set1_grease_suite_removed <= LibVersion then
    begin
      {$if declared(_SSL_ech_set1_grease_suite)}
      SSL_ech_set1_grease_suite := _SSL_ech_set1_grease_suite;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SSL_ech_set1_grease_suite_allownil)}
    if FuncLoadError then
      AFailed.Add('SSL_ech_set1_grease_suite');
    {$ifend}
  end;

  SSL_ech_set_grease_type := LoadLibFunction(ADllHandle, SSL_ech_set_grease_type_procname);
  FuncLoadError := not assigned(SSL_ech_set_grease_type);
  if FuncLoadError then
  begin
    {$if not defined(SSL_ech_set_grease_type_allownil)}
    SSL_ech_set_grease_type := ERR_SSL_ech_set_grease_type;
    {$ifend}
    {$if declared(SSL_ech_set_grease_type_introduced)}
    if LibVersion < SSL_ech_set_grease_type_introduced then
    begin
      {$if declared(FC_SSL_ech_set_grease_type)}
      SSL_ech_set_grease_type := FC_SSL_ech_set_grease_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SSL_ech_set_grease_type_removed)}
    if SSL_ech_set_grease_type_removed <= LibVersion then
    begin
      {$if declared(_SSL_ech_set_grease_type)}
      SSL_ech_set_grease_type := _SSL_ech_set_grease_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SSL_ech_set_grease_type_allownil)}
    if FuncLoadError then
      AFailed.Add('SSL_ech_set_grease_type');
    {$ifend}
  end;

  SSL_ech_set_callback := LoadLibFunction(ADllHandle, SSL_ech_set_callback_procname);
  FuncLoadError := not assigned(SSL_ech_set_callback);
  if FuncLoadError then
  begin
    {$if not defined(SSL_ech_set_callback_allownil)}
    SSL_ech_set_callback := ERR_SSL_ech_set_callback;
    {$ifend}
    {$if declared(SSL_ech_set_callback_introduced)}
    if LibVersion < SSL_ech_set_callback_introduced then
    begin
      {$if declared(FC_SSL_ech_set_callback)}
      SSL_ech_set_callback := FC_SSL_ech_set_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SSL_ech_set_callback_removed)}
    if SSL_ech_set_callback_removed <= LibVersion then
    begin
      {$if declared(_SSL_ech_set_callback)}
      SSL_ech_set_callback := _SSL_ech_set_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SSL_ech_set_callback_allownil)}
    if FuncLoadError then
      AFailed.Add('SSL_ech_set_callback');
    {$ifend}
  end;

  SSL_ech_get1_retry_config := LoadLibFunction(ADllHandle, SSL_ech_get1_retry_config_procname);
  FuncLoadError := not assigned(SSL_ech_get1_retry_config);
  if FuncLoadError then
  begin
    {$if not defined(SSL_ech_get1_retry_config_allownil)}
    SSL_ech_get1_retry_config := ERR_SSL_ech_get1_retry_config;
    {$ifend}
    {$if declared(SSL_ech_get1_retry_config_introduced)}
    if LibVersion < SSL_ech_get1_retry_config_introduced then
    begin
      {$if declared(FC_SSL_ech_get1_retry_config)}
      SSL_ech_get1_retry_config := FC_SSL_ech_get1_retry_config;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SSL_ech_get1_retry_config_removed)}
    if SSL_ech_get1_retry_config_removed <= LibVersion then
    begin
      {$if declared(_SSL_ech_get1_retry_config)}
      SSL_ech_get1_retry_config := _SSL_ech_get1_retry_config;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SSL_ech_get1_retry_config_allownil)}
    if FuncLoadError then
      AFailed.Add('SSL_ech_get1_retry_config');
    {$ifend}
  end;

  SSL_CTX_ech_set1_outer_alpn_protos := LoadLibFunction(ADllHandle, SSL_CTX_ech_set1_outer_alpn_protos_procname);
  FuncLoadError := not assigned(SSL_CTX_ech_set1_outer_alpn_protos);
  if FuncLoadError then
  begin
    {$if not defined(SSL_CTX_ech_set1_outer_alpn_protos_allownil)}
    SSL_CTX_ech_set1_outer_alpn_protos := ERR_SSL_CTX_ech_set1_outer_alpn_protos;
    {$ifend}
    {$if declared(SSL_CTX_ech_set1_outer_alpn_protos_introduced)}
    if LibVersion < SSL_CTX_ech_set1_outer_alpn_protos_introduced then
    begin
      {$if declared(FC_SSL_CTX_ech_set1_outer_alpn_protos)}
      SSL_CTX_ech_set1_outer_alpn_protos := FC_SSL_CTX_ech_set1_outer_alpn_protos;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SSL_CTX_ech_set1_outer_alpn_protos_removed)}
    if SSL_CTX_ech_set1_outer_alpn_protos_removed <= LibVersion then
    begin
      {$if declared(_SSL_CTX_ech_set1_outer_alpn_protos)}
      SSL_CTX_ech_set1_outer_alpn_protos := _SSL_CTX_ech_set1_outer_alpn_protos;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SSL_CTX_ech_set1_outer_alpn_protos_allownil)}
    if FuncLoadError then
      AFailed.Add('SSL_CTX_ech_set1_outer_alpn_protos');
    {$ifend}
  end;

  SSL_CTX_ech_set_callback := LoadLibFunction(ADllHandle, SSL_CTX_ech_set_callback_procname);
  FuncLoadError := not assigned(SSL_CTX_ech_set_callback);
  if FuncLoadError then
  begin
    {$if not defined(SSL_CTX_ech_set_callback_allownil)}
    SSL_CTX_ech_set_callback := ERR_SSL_CTX_ech_set_callback;
    {$ifend}
    {$if declared(SSL_CTX_ech_set_callback_introduced)}
    if LibVersion < SSL_CTX_ech_set_callback_introduced then
    begin
      {$if declared(FC_SSL_CTX_ech_set_callback)}
      SSL_CTX_ech_set_callback := FC_SSL_CTX_ech_set_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SSL_CTX_ech_set_callback_removed)}
    if SSL_CTX_ech_set_callback_removed <= LibVersion then
    begin
      {$if declared(_SSL_CTX_ech_set_callback)}
      SSL_CTX_ech_set_callback := _SSL_CTX_ech_set_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SSL_CTX_ech_set_callback_allownil)}
    if FuncLoadError then
      AFailed.Add('SSL_CTX_ech_set_callback');
    {$ifend}
  end;

  SSL_set1_ech_config_list := LoadLibFunction(ADllHandle, SSL_set1_ech_config_list_procname);
  FuncLoadError := not assigned(SSL_set1_ech_config_list);
  if FuncLoadError then
  begin
    {$if not defined(SSL_set1_ech_config_list_allownil)}
    SSL_set1_ech_config_list := ERR_SSL_set1_ech_config_list;
    {$ifend}
    {$if declared(SSL_set1_ech_config_list_introduced)}
    if LibVersion < SSL_set1_ech_config_list_introduced then
    begin
      {$if declared(FC_SSL_set1_ech_config_list)}
      SSL_set1_ech_config_list := FC_SSL_set1_ech_config_list;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SSL_set1_ech_config_list_removed)}
    if SSL_set1_ech_config_list_removed <= LibVersion then
    begin
      {$if declared(_SSL_set1_ech_config_list)}
      SSL_set1_ech_config_list := _SSL_set1_ech_config_list;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SSL_set1_ech_config_list_allownil)}
    if FuncLoadError then
      AFailed.Add('SSL_set1_ech_config_list');
    {$ifend}
  end;
end;

procedure Unload;
begin
  OSSL_ECHSTORE_new := nil;
  OSSL_ECHSTORE_free := nil;
  OSSL_ECHSTORE_new_config := nil;
  OSSL_ECHSTORE_write_pem  := nil;
  OSSL_ECHSTORE_read_echconfiglist := nil;
  OSSL_ECHSTORE_get1_info := nil;
  OSSL_ECHSTORE_downselect  := nil;
  OSSL_ECHSTORE_set1_key_and_read_pem := nil;
  OSSL_ECHSTORE_read_pem := nil;
  OSSL_ECHSTORE_num_entries := nil;
  OSSL_ECHSTORE_num_keys := nil;
  OSSL_ECHSTORE_flush_keys  := nil;
  SSL_CTX_set1_echstore  := nil;
  SSL_set1_echstore  := nil;
  SSL_CTX_get1_echstore  := nil;
  SSL_get1_echstore  := nil;
  SSL_ech_set1_server_names := nil;
  SSL_ech_set1_outer_server_name := nil;
  SSL_ech_set1_outer_alpn_protos  := nil;
  SSL_ech_get1_status := nil;
  SSL_ech_set1_grease_suite  := nil;
  SSL_ech_set_grease_type  := nil;
  SSL_ech_set_callback  := nil;
  SSL_ech_get1_retry_config := nil;
  SSL_CTX_ech_set1_outer_alpn_protos  := nil;
  SSL_CTX_ech_set_callback := nil;
  SSL_set1_ech_config_list := nil;
end;
  {$ENDIF}
{$ELSE}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibSSL');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
