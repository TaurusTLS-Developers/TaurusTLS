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

unit TaurusTLSHeaders_ossl_types;

interface

uses
  IdCTypes,
  IdGlobal;



// =============================================================================
// TYPE DECLARATIONS
// =============================================================================
type
  Pasn1_string_st = ^Tasn1_string_st;
  Tasn1_string_st =   record
    length: TIdC_INT;
    _type: TIdC_INT;
    data: PIdAnsiChar;
    flags: TIdC_LONG;
  end;
  {$EXTERNALSYM Pasn1_string_st}

  PCONF_VALUE = ^TCONF_VALUE;
  TCONF_VALUE =   record
    section: PIdAnsiChar;
    name: PIdAnsiChar;
    value: PIdAnsiChar;
  end;
  {$EXTERNALSYM PCONF_VALUE}

  { TODO 1 -cID Needs manual mapping (Union or complex type) : Review it and update. }
  // DEFINE_LHASH_OF_INTERNAL(CONF_VALUE)

  Possl_core_handle_st = ^Tossl_core_handle_st;
  Tossl_core_handle_st =   record end;
  {$EXTERNALSYM Possl_core_handle_st}

  Possl_dispatch_st = ^Tossl_dispatch_st;
  Tossl_dispatch_st =   record
    function_id: TIdC_INT;
    _function: TOSSL_CORE_BIO_func_cb;
  end;
  {$EXTERNALSYM Possl_dispatch_st}

  Possl_param_st = ^Tossl_param_st;
  Tossl_param_st =   record
    key: PIdAnsiChar;
    data_type: TIdC_UINT;
    data: Pointer;
    data_size: TIdC_SIZET;
    return_size: TIdC_SIZET;
  end;
  {$EXTERNALSYM Possl_param_st}

  Prsa_st = ^Trsa_st;
  Trsa_st =   record end;
  {$EXTERNALSYM Prsa_st}

  Pdsa_st = ^Tdsa_st;
  Tdsa_st =   record end;
  {$EXTERNALSYM Pdsa_st}

  Pdh_st = ^Tdh_st;
  Tdh_st =   record end;
  {$EXTERNALSYM Pdh_st}

  Pec_key_st = ^Tec_key_st;
  Tec_key_st =   record end;
  {$EXTERNALSYM Pec_key_st}

  { TODO 1 -cID Needs manual mapping (Union or complex type) : Review it and update. }
  // DEFINE_LHASH_OF_INTERNAL(OPENSSL_STRING)

  Pstack_st_X509_ATTRIBUTE = ^Tstack_st_X509_ATTRIBUTE;
  Tstack_st_X509_ATTRIBUTE =   record end;
  {$EXTERNALSYM Pstack_st_X509_ATTRIBUTE}

  Pstack_st_X509 = ^Tstack_st_X509;
  Tstack_st_X509 =   record end;
  {$EXTERNALSYM Pstack_st_X509}

  Pstack_st_X509_CRL = ^Tstack_st_X509_CRL;
  Tstack_st_X509_CRL =   record end;
  {$EXTERNALSYM Pstack_st_X509_CRL}

  { TODO 1 -cID Collision detected : Review it and update. }
  // struct asn1_string_st

  Pbio_st = ^Tbio_st;
  Tbio_st =   record end;
  {$EXTERNALSYM Pbio_st}

  Pbignum_st = ^Tbignum_st;
  Tbignum_st =   record end;
  {$EXTERNALSYM Pbignum_st}

  Pbignum_ctx = ^Tbignum_ctx;
  Tbignum_ctx =   record end;
  {$EXTERNALSYM Pbignum_ctx}

  Pbn_mont_ctx_st = ^Tbn_mont_ctx_st;
  Tbn_mont_ctx_st =   record end;
  {$EXTERNALSYM Pbn_mont_ctx_st}

  Pbn_gencb_st = ^Tbn_gencb_st;
  Tbn_gencb_st =   record end;
  {$EXTERNALSYM Pbn_gencb_st}

  Pevp_pkey_st = ^Tevp_pkey_st;
  Tevp_pkey_st =   record end;
  {$EXTERNALSYM Pevp_pkey_st}

  { TODO 1 -cID Collision detected : Review it and update. }
  // struct dh_st

  { TODO 1 -cID Collision detected : Review it and update. }
  // struct dsa_st

  { TODO 1 -cID Collision detected : Review it and update. }
  // struct rsa_st

  { TODO 1 -cID Collision detected : Review it and update. }
  // struct ec_key_st

  Pssl_st = ^Tssl_st;
  Tssl_st =   record end;
  {$EXTERNALSYM Pssl_st}

  Pssl_ctx_st = ^Tssl_ctx_st;
  Tssl_ctx_st =   record end;
  {$EXTERNALSYM Pssl_ctx_st}

  Possl_store_info_st = ^Tossl_store_info_st;
  Tossl_store_info_st =   record end;
  {$EXTERNALSYM Possl_store_info_st}

  { TODO 1 -cID Collision detected : Review it and update. }
  // struct ossl_dispatch_st

  { TODO 1 -cID Collision detected : Review it and update. }
  // struct ossl_param_st

  Pstack_st_POLICYQUALINFO = ^Tstack_st_POLICYQUALINFO;
  Tstack_st_POLICYQUALINFO =   record end;
  {$EXTERNALSYM Pstack_st_POLICYQUALINFO}


implementation

end.