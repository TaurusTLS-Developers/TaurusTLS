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

unit TaurusTLSHeaders_crmf;

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
  Possl_crmf_encryptedvalue_st = ^Tossl_crmf_encryptedvalue_st;
  Tossl_crmf_encryptedvalue_st =   record end;
  {$EXTERNALSYM Possl_crmf_encryptedvalue_st}

  Possl_crmf_encryptedkey_st = ^Tossl_crmf_encryptedkey_st;
  Tossl_crmf_encryptedkey_st =   record end;
  {$EXTERNALSYM Possl_crmf_encryptedkey_st}

  Possl_crmf_msg_st = ^Tossl_crmf_msg_st;
  Tossl_crmf_msg_st =   record end;
  {$EXTERNALSYM Possl_crmf_msg_st}

  Possl_crmf_attributetypeandvalue_st = ^Tossl_crmf_attributetypeandvalue_st;
  Tossl_crmf_attributetypeandvalue_st =   record end;
  {$EXTERNALSYM Possl_crmf_attributetypeandvalue_st}

  Possl_crmf_pbmparameter_st = ^Tossl_crmf_pbmparameter_st;
  Tossl_crmf_pbmparameter_st =   record end;
  {$EXTERNALSYM Possl_crmf_pbmparameter_st}

  Possl_crmf_poposigningkey_st = ^Tossl_crmf_poposigningkey_st;
  Tossl_crmf_poposigningkey_st =   record end;
  {$EXTERNALSYM Possl_crmf_poposigningkey_st}

  Possl_crmf_certrequest_st = ^Tossl_crmf_certrequest_st;
  Tossl_crmf_certrequest_st =   record end;
  {$EXTERNALSYM Possl_crmf_certrequest_st}

  Possl_crmf_certid_st = ^Tossl_crmf_certid_st;
  Tossl_crmf_certid_st =   record end;
  {$EXTERNALSYM Possl_crmf_certid_st}

  Possl_crmf_pkipublicationinfo_st = ^Tossl_crmf_pkipublicationinfo_st;
  Tossl_crmf_pkipublicationinfo_st =   record end;
  {$EXTERNALSYM Possl_crmf_pkipublicationinfo_st}

  Possl_crmf_singlepubinfo_st = ^Tossl_crmf_singlepubinfo_st;
  Tossl_crmf_singlepubinfo_st =   record end;
  {$EXTERNALSYM Possl_crmf_singlepubinfo_st}

  Possl_crmf_certtemplate_st = ^Tossl_crmf_certtemplate_st;
  Tossl_crmf_certtemplate_st =   record end;
  {$EXTERNALSYM Possl_crmf_certtemplate_st}

  Possl_crmf_optionalvalidity_st = ^Tossl_crmf_optionalvalidity_st;
  Tossl_crmf_optionalvalidity_st =   record end;
  {$EXTERNALSYM Possl_crmf_optionalvalidity_st}


// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  OSSL_CRMF_POPOPRIVKEY_THISMESSAGE = 0;
  OSSL_CRMF_POPOPRIVKEY_SUBSEQUENTMESSAGE = 1;
  OSSL_CRMF_POPOPRIVKEY_DHMAC = 2;
  OSSL_CRMF_POPOPRIVKEY_AGREEMAC = 3;
  OSSL_CRMF_POPOPRIVKEY_ENCRYPTEDKEY = 4;
  OSSL_CRMF_SUBSEQUENTMESSAGE_ENCRCERT = 0;
  OSSL_CRMF_SUBSEQUENTMESSAGE_CHALLENGERESP = 1;
  OSSL_CRMF_PUB_METHOD_DONTCARE = 0;
  OSSL_CRMF_PUB_METHOD_X500 = 1;
  OSSL_CRMF_PUB_METHOD_WEB = 2;
  OSSL_CRMF_PUB_METHOD_LDAP = 3;
  OSSL_CRMF_PUB_ACTION_DONTPUBLISH = 0;
  OSSL_CRMF_PUB_ACTION_PLEASEPUBLISH = 1;
  OSSL_CRMF_POPO_NONE = -1;
  OSSL_CRMF_POPO_RAVERIFIED = 0;
  OSSL_CRMF_POPO_SIGNATURE = 1;
  OSSL_CRMF_POPO_KEYENC = 2;
  OSSL_CRMF_POPO_KEYAGREE = 3;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  OSSL_CRMF_ENCRYPTEDVALUE_new: function: POSSL_CRMF_ENCRYPTEDVALUE; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_ENCRYPTEDVALUE_new}

  OSSL_CRMF_ENCRYPTEDVALUE_free: procedure(a: POSSL_CRMF_ENCRYPTEDVALUE); cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_ENCRYPTEDVALUE_free}

  d2i_OSSL_CRMF_ENCRYPTEDVALUE: function(a: PPOSSL_CRMF_ENCRYPTEDVALUE; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_ENCRYPTEDVALUE; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_CRMF_ENCRYPTEDVALUE}

  i2d_OSSL_CRMF_ENCRYPTEDVALUE: function(a: POSSL_CRMF_ENCRYPTEDVALUE; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_CRMF_ENCRYPTEDVALUE}

  OSSL_CRMF_ENCRYPTEDVALUE_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_ENCRYPTEDVALUE_it}

  OSSL_CRMF_ENCRYPTEDKEY_new: function: POSSL_CRMF_ENCRYPTEDKEY; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_ENCRYPTEDKEY_new}

  OSSL_CRMF_ENCRYPTEDKEY_free: procedure(a: POSSL_CRMF_ENCRYPTEDKEY); cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_ENCRYPTEDKEY_free}

  d2i_OSSL_CRMF_ENCRYPTEDKEY: function(a: PPOSSL_CRMF_ENCRYPTEDKEY; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_ENCRYPTEDKEY; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_CRMF_ENCRYPTEDKEY}

  i2d_OSSL_CRMF_ENCRYPTEDKEY: function(a: POSSL_CRMF_ENCRYPTEDKEY; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_CRMF_ENCRYPTEDKEY}

  OSSL_CRMF_ENCRYPTEDKEY_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_ENCRYPTEDKEY_it}

  OSSL_CRMF_MSG_new: function: POSSL_CRMF_MSG; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_new}

  OSSL_CRMF_MSG_free: procedure(a: POSSL_CRMF_MSG); cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_free}

  d2i_OSSL_CRMF_MSG: function(a: PPOSSL_CRMF_MSG; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_MSG; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_CRMF_MSG}

  i2d_OSSL_CRMF_MSG: function(a: POSSL_CRMF_MSG; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_CRMF_MSG}

  OSSL_CRMF_MSG_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_it}

  OSSL_CRMF_MSG_dup: function(a: POSSL_CRMF_MSG): POSSL_CRMF_MSG; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_dup}

  OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free: procedure(v: POSSL_CRMF_ATTRIBUTETYPEANDVALUE); cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free}

  OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup: function(a: POSSL_CRMF_ATTRIBUTETYPEANDVALUE): POSSL_CRMF_ATTRIBUTETYPEANDVALUE; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup}

  OSSL_CRMF_PBMPARAMETER_new: function: POSSL_CRMF_PBMPARAMETER; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_PBMPARAMETER_new}

  OSSL_CRMF_PBMPARAMETER_free: procedure(a: POSSL_CRMF_PBMPARAMETER); cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_PBMPARAMETER_free}

  d2i_OSSL_CRMF_PBMPARAMETER: function(a: PPOSSL_CRMF_PBMPARAMETER; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_PBMPARAMETER; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_CRMF_PBMPARAMETER}

  i2d_OSSL_CRMF_PBMPARAMETER: function(a: POSSL_CRMF_PBMPARAMETER; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_CRMF_PBMPARAMETER}

  OSSL_CRMF_PBMPARAMETER_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_PBMPARAMETER_it}

  OSSL_CRMF_CERTID_new: function: POSSL_CRMF_CERTID; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_CERTID_new}

  OSSL_CRMF_CERTID_free: procedure(a: POSSL_CRMF_CERTID); cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_CERTID_free}

  d2i_OSSL_CRMF_CERTID: function(a: PPOSSL_CRMF_CERTID; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_CERTID; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_CRMF_CERTID}

  i2d_OSSL_CRMF_CERTID: function(a: POSSL_CRMF_CERTID; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_CRMF_CERTID}

  OSSL_CRMF_CERTID_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_CERTID_it}

  OSSL_CRMF_CERTID_dup: function(a: POSSL_CRMF_CERTID): POSSL_CRMF_CERTID; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_CERTID_dup}

  OSSL_CRMF_PKIPUBLICATIONINFO_new: function: POSSL_CRMF_PKIPUBLICATIONINFO; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_PKIPUBLICATIONINFO_new}

  OSSL_CRMF_PKIPUBLICATIONINFO_free: procedure(a: POSSL_CRMF_PKIPUBLICATIONINFO); cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_PKIPUBLICATIONINFO_free}

  d2i_OSSL_CRMF_PKIPUBLICATIONINFO: function(a: PPOSSL_CRMF_PKIPUBLICATIONINFO; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_PKIPUBLICATIONINFO; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_CRMF_PKIPUBLICATIONINFO}

  i2d_OSSL_CRMF_PKIPUBLICATIONINFO: function(a: POSSL_CRMF_PKIPUBLICATIONINFO; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_CRMF_PKIPUBLICATIONINFO}

  OSSL_CRMF_PKIPUBLICATIONINFO_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_PKIPUBLICATIONINFO_it}

  OSSL_CRMF_SINGLEPUBINFO_new: function: POSSL_CRMF_SINGLEPUBINFO; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_SINGLEPUBINFO_new}

  OSSL_CRMF_SINGLEPUBINFO_free: procedure(a: POSSL_CRMF_SINGLEPUBINFO); cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_SINGLEPUBINFO_free}

  d2i_OSSL_CRMF_SINGLEPUBINFO: function(a: PPOSSL_CRMF_SINGLEPUBINFO; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_SINGLEPUBINFO; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_CRMF_SINGLEPUBINFO}

  i2d_OSSL_CRMF_SINGLEPUBINFO: function(a: POSSL_CRMF_SINGLEPUBINFO; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_CRMF_SINGLEPUBINFO}

  OSSL_CRMF_SINGLEPUBINFO_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_SINGLEPUBINFO_it}

  OSSL_CRMF_CERTTEMPLATE_new: function: POSSL_CRMF_CERTTEMPLATE; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_CERTTEMPLATE_new}

  OSSL_CRMF_CERTTEMPLATE_free: procedure(a: POSSL_CRMF_CERTTEMPLATE); cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_CERTTEMPLATE_free}

  d2i_OSSL_CRMF_CERTTEMPLATE: function(a: PPOSSL_CRMF_CERTTEMPLATE; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_CERTTEMPLATE; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_CRMF_CERTTEMPLATE}

  i2d_OSSL_CRMF_CERTTEMPLATE: function(a: POSSL_CRMF_CERTTEMPLATE; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_CRMF_CERTTEMPLATE}

  OSSL_CRMF_CERTTEMPLATE_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_CERTTEMPLATE_it}

  OSSL_CRMF_CERTTEMPLATE_dup: function(a: POSSL_CRMF_CERTTEMPLATE): POSSL_CRMF_CERTTEMPLATE; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_CERTTEMPLATE_dup}

  OSSL_CRMF_MSGS_new: function: POSSL_CRMF_MSGS; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSGS_new}

  OSSL_CRMF_MSGS_free: procedure(a: POSSL_CRMF_MSGS); cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSGS_free}

  d2i_OSSL_CRMF_MSGS: function(a: PPOSSL_CRMF_MSGS; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_MSGS; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_CRMF_MSGS}

  i2d_OSSL_CRMF_MSGS: function(a: POSSL_CRMF_MSGS; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_CRMF_MSGS}

  OSSL_CRMF_MSGS_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSGS_it}

  OSSL_CRMF_pbmp_new: function(libctx: POSSL_LIB_CTX; slen: TIdC_SIZET; owfnid: TIdC_INT; itercnt: TIdC_SIZET; macnid: TIdC_INT): POSSL_CRMF_PBMPARAMETER; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_pbmp_new}

  OSSL_CRMF_pbm_new: function(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; pbmp: POSSL_CRMF_PBMPARAMETER; msg: PIdAnsiChar; msglen: TIdC_SIZET; sec: PIdAnsiChar; seclen: TIdC_SIZET; mac: PPIdAnsiChar; maclen: PIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_pbm_new}

  OSSL_CRMF_MSG_set1_regCtrl_regToken: function(msg: POSSL_CRMF_MSG; tok: PASN1_UTF8STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_set1_regCtrl_regToken}

  OSSL_CRMF_MSG_get0_regCtrl_regToken: function(msg: POSSL_CRMF_MSG): PASN1_UTF8STRING; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_get0_regCtrl_regToken}

  OSSL_CRMF_MSG_set1_regCtrl_authenticator: function(msg: POSSL_CRMF_MSG; auth: PASN1_UTF8STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_set1_regCtrl_authenticator}

  OSSL_CRMF_MSG_get0_regCtrl_authenticator: function(msg: POSSL_CRMF_MSG): PASN1_UTF8STRING; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_get0_regCtrl_authenticator}

  OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo: function(pi: POSSL_CRMF_PKIPUBLICATIONINFO; spi: POSSL_CRMF_SINGLEPUBINFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo}

  OSSL_CRMF_MSG_set0_SinglePubInfo: function(spi: POSSL_CRMF_SINGLEPUBINFO; method: TIdC_INT; nm: PGENERAL_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_set0_SinglePubInfo}

  OSSL_CRMF_MSG_set_PKIPublicationInfo_action: function(pi: POSSL_CRMF_PKIPUBLICATIONINFO; action: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_set_PKIPublicationInfo_action}

  OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo: function(msg: POSSL_CRMF_MSG; pi: POSSL_CRMF_PKIPUBLICATIONINFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo}

  OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo: function(msg: POSSL_CRMF_MSG): POSSL_CRMF_PKIPUBLICATIONINFO; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo}

  OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey: function(msg: POSSL_CRMF_MSG; pubkey: PX509_PUBKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey}

  OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey: function(msg: POSSL_CRMF_MSG): PX509_PUBKEY; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey}

  OSSL_CRMF_MSG_set1_regCtrl_oldCertID: function(msg: POSSL_CRMF_MSG; cid: POSSL_CRMF_CERTID): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_set1_regCtrl_oldCertID}

  OSSL_CRMF_MSG_get0_regCtrl_oldCertID: function(msg: POSSL_CRMF_MSG): POSSL_CRMF_CERTID; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_get0_regCtrl_oldCertID}

  OSSL_CRMF_CERTID_gen: function(issuer: PX509_NAME; serial: PASN1_INTEGER): POSSL_CRMF_CERTID; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_CERTID_gen}

  OSSL_CRMF_MSG_set1_regInfo_utf8Pairs: function(msg: POSSL_CRMF_MSG; utf8pairs: PASN1_UTF8STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_set1_regInfo_utf8Pairs}

  OSSL_CRMF_MSG_get0_regInfo_utf8Pairs: function(msg: POSSL_CRMF_MSG): PASN1_UTF8STRING; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_get0_regInfo_utf8Pairs}

  OSSL_CRMF_MSG_set1_regInfo_certReq: function(msg: POSSL_CRMF_MSG; cr: POSSL_CRMF_CERTREQUEST): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_set1_regInfo_certReq}

  OSSL_CRMF_MSG_get0_regInfo_certReq: function(msg: POSSL_CRMF_MSG): POSSL_CRMF_CERTREQUEST; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_get0_regInfo_certReq}

  OSSL_CRMF_MSG_set0_validity: function(crm: POSSL_CRMF_MSG; notBefore: PASN1_TIME; notAfter: PASN1_TIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_set0_validity}

  OSSL_CRMF_MSG_set_certReqId: function(crm: POSSL_CRMF_MSG; rid: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_set_certReqId}

  OSSL_CRMF_MSG_get_certReqId: function(crm: POSSL_CRMF_MSG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_get_certReqId}

  OSSL_CRMF_MSG_set0_extensions: function(crm: POSSL_CRMF_MSG; exts: PX509_EXTENSIONS): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_set0_extensions}

  OSSL_CRMF_MSG_push0_extension: function(crm: POSSL_CRMF_MSG; ext: PX509_EXTENSION): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_push0_extension}

  OSSL_CRMF_MSG_create_popo: function(meth: TIdC_INT; crm: POSSL_CRMF_MSG; pkey: PEVP_PKEY; digest: PEVP_MD; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_create_popo}

  OSSL_CRMF_MSGS_verify_popo: function(reqs: POSSL_CRMF_MSGS; rid: TIdC_INT; acceptRAVerified: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSGS_verify_popo}

  OSSL_CRMF_MSG_get0_tmpl: function(crm: POSSL_CRMF_MSG): POSSL_CRMF_CERTTEMPLATE; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_get0_tmpl}

  OSSL_CRMF_CERTTEMPLATE_get0_publicKey: function(tmpl: POSSL_CRMF_CERTTEMPLATE): PX509_PUBKEY; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_CERTTEMPLATE_get0_publicKey}

  OSSL_CRMF_CERTTEMPLATE_get0_subject: function(tmpl: POSSL_CRMF_CERTTEMPLATE): PX509_NAME; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_CERTTEMPLATE_get0_subject}

  OSSL_CRMF_CERTTEMPLATE_get0_issuer: function(tmpl: POSSL_CRMF_CERTTEMPLATE): PX509_NAME; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_CERTTEMPLATE_get0_issuer}

  OSSL_CRMF_CERTTEMPLATE_get0_serialNumber: function(tmpl: POSSL_CRMF_CERTTEMPLATE): PASN1_INTEGER; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_CERTTEMPLATE_get0_serialNumber}

  OSSL_CRMF_CERTTEMPLATE_get0_extensions: function(tmpl: POSSL_CRMF_CERTTEMPLATE): PX509_EXTENSIONS; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_CERTTEMPLATE_get0_extensions}

  OSSL_CRMF_CERTID_get0_issuer: function(cid: POSSL_CRMF_CERTID): PX509_NAME; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_CERTID_get0_issuer}

  OSSL_CRMF_CERTID_get0_serialNumber: function(cid: POSSL_CRMF_CERTID): PASN1_INTEGER; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_CERTID_get0_serialNumber}

  OSSL_CRMF_CERTTEMPLATE_fill: function(tmpl: POSSL_CRMF_CERTTEMPLATE; pubkey: PEVP_PKEY; subject: PX509_NAME; issuer: PX509_NAME; serial: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_CERTTEMPLATE_fill}

  OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert: function(ecert: POSSL_CRMF_ENCRYPTEDVALUE; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; pkey: PEVP_PKEY): PX509; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert}

  OSSL_CRMF_ENCRYPTEDKEY_get1_encCert: function(ecert: POSSL_CRMF_ENCRYPTEDKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; pkey: PEVP_PKEY; flags: TIdC_UINT): PX509; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_ENCRYPTEDKEY_get1_encCert}

  OSSL_CRMF_ENCRYPTEDVALUE_decrypt: function(enc: POSSL_CRMF_ENCRYPTEDVALUE; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; pkey: PEVP_PKEY; outlen: PIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_ENCRYPTEDVALUE_decrypt}

  OSSL_CRMF_ENCRYPTEDKEY_get1_pkey: function(encryptedKey: POSSL_CRMF_ENCRYPTEDKEY; ts: PX509_STORE; extra: Pstack_st_X509; pkey: PEVP_PKEY; cert: PX509; secret: PASN1_OCTET_STRING; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_ENCRYPTEDKEY_get1_pkey}

  OSSL_CRMF_MSG_centralkeygen_requested: function(crm: POSSL_CRMF_MSG; p10cr: PX509_REQ): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_MSG_centralkeygen_requested}

  OSSL_CRMF_ENCRYPTEDKEY_init_envdata: function(envdata: PCMS_EnvelopedData): POSSL_CRMF_ENCRYPTEDKEY; cdecl = nil;
  {$EXTERNALSYM OSSL_CRMF_ENCRYPTEDKEY_init_envdata}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function OSSL_CRMF_ENCRYPTEDVALUE_new: POSSL_CRMF_ENCRYPTEDVALUE; cdecl;
procedure OSSL_CRMF_ENCRYPTEDVALUE_free(a: POSSL_CRMF_ENCRYPTEDVALUE); cdecl;
function d2i_OSSL_CRMF_ENCRYPTEDVALUE(a: PPOSSL_CRMF_ENCRYPTEDVALUE; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_ENCRYPTEDVALUE; cdecl;
function i2d_OSSL_CRMF_ENCRYPTEDVALUE(a: POSSL_CRMF_ENCRYPTEDVALUE; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_CRMF_ENCRYPTEDVALUE_it: PASN1_ITEM; cdecl;
function OSSL_CRMF_ENCRYPTEDKEY_new: POSSL_CRMF_ENCRYPTEDKEY; cdecl;
procedure OSSL_CRMF_ENCRYPTEDKEY_free(a: POSSL_CRMF_ENCRYPTEDKEY); cdecl;
function d2i_OSSL_CRMF_ENCRYPTEDKEY(a: PPOSSL_CRMF_ENCRYPTEDKEY; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_ENCRYPTEDKEY; cdecl;
function i2d_OSSL_CRMF_ENCRYPTEDKEY(a: POSSL_CRMF_ENCRYPTEDKEY; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_CRMF_ENCRYPTEDKEY_it: PASN1_ITEM; cdecl;
function OSSL_CRMF_MSG_new: POSSL_CRMF_MSG; cdecl;
procedure OSSL_CRMF_MSG_free(a: POSSL_CRMF_MSG); cdecl;
function d2i_OSSL_CRMF_MSG(a: PPOSSL_CRMF_MSG; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_MSG; cdecl;
function i2d_OSSL_CRMF_MSG(a: POSSL_CRMF_MSG; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_CRMF_MSG_it: PASN1_ITEM; cdecl;
function OSSL_CRMF_MSG_dup(a: POSSL_CRMF_MSG): POSSL_CRMF_MSG; cdecl;
procedure OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free(v: POSSL_CRMF_ATTRIBUTETYPEANDVALUE); cdecl;
function OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup(a: POSSL_CRMF_ATTRIBUTETYPEANDVALUE): POSSL_CRMF_ATTRIBUTETYPEANDVALUE; cdecl;
function OSSL_CRMF_PBMPARAMETER_new: POSSL_CRMF_PBMPARAMETER; cdecl;
procedure OSSL_CRMF_PBMPARAMETER_free(a: POSSL_CRMF_PBMPARAMETER); cdecl;
function d2i_OSSL_CRMF_PBMPARAMETER(a: PPOSSL_CRMF_PBMPARAMETER; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_PBMPARAMETER; cdecl;
function i2d_OSSL_CRMF_PBMPARAMETER(a: POSSL_CRMF_PBMPARAMETER; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_CRMF_PBMPARAMETER_it: PASN1_ITEM; cdecl;
function OSSL_CRMF_CERTID_new: POSSL_CRMF_CERTID; cdecl;
procedure OSSL_CRMF_CERTID_free(a: POSSL_CRMF_CERTID); cdecl;
function d2i_OSSL_CRMF_CERTID(a: PPOSSL_CRMF_CERTID; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_CERTID; cdecl;
function i2d_OSSL_CRMF_CERTID(a: POSSL_CRMF_CERTID; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_CRMF_CERTID_it: PASN1_ITEM; cdecl;
function OSSL_CRMF_CERTID_dup(a: POSSL_CRMF_CERTID): POSSL_CRMF_CERTID; cdecl;
function OSSL_CRMF_PKIPUBLICATIONINFO_new: POSSL_CRMF_PKIPUBLICATIONINFO; cdecl;
procedure OSSL_CRMF_PKIPUBLICATIONINFO_free(a: POSSL_CRMF_PKIPUBLICATIONINFO); cdecl;
function d2i_OSSL_CRMF_PKIPUBLICATIONINFO(a: PPOSSL_CRMF_PKIPUBLICATIONINFO; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_PKIPUBLICATIONINFO; cdecl;
function i2d_OSSL_CRMF_PKIPUBLICATIONINFO(a: POSSL_CRMF_PKIPUBLICATIONINFO; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_CRMF_PKIPUBLICATIONINFO_it: PASN1_ITEM; cdecl;
function OSSL_CRMF_SINGLEPUBINFO_new: POSSL_CRMF_SINGLEPUBINFO; cdecl;
procedure OSSL_CRMF_SINGLEPUBINFO_free(a: POSSL_CRMF_SINGLEPUBINFO); cdecl;
function d2i_OSSL_CRMF_SINGLEPUBINFO(a: PPOSSL_CRMF_SINGLEPUBINFO; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_SINGLEPUBINFO; cdecl;
function i2d_OSSL_CRMF_SINGLEPUBINFO(a: POSSL_CRMF_SINGLEPUBINFO; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_CRMF_SINGLEPUBINFO_it: PASN1_ITEM; cdecl;
function OSSL_CRMF_CERTTEMPLATE_new: POSSL_CRMF_CERTTEMPLATE; cdecl;
procedure OSSL_CRMF_CERTTEMPLATE_free(a: POSSL_CRMF_CERTTEMPLATE); cdecl;
function d2i_OSSL_CRMF_CERTTEMPLATE(a: PPOSSL_CRMF_CERTTEMPLATE; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_CERTTEMPLATE; cdecl;
function i2d_OSSL_CRMF_CERTTEMPLATE(a: POSSL_CRMF_CERTTEMPLATE; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_CRMF_CERTTEMPLATE_it: PASN1_ITEM; cdecl;
function OSSL_CRMF_CERTTEMPLATE_dup(a: POSSL_CRMF_CERTTEMPLATE): POSSL_CRMF_CERTTEMPLATE; cdecl;
function OSSL_CRMF_MSGS_new: POSSL_CRMF_MSGS; cdecl;
procedure OSSL_CRMF_MSGS_free(a: POSSL_CRMF_MSGS); cdecl;
function d2i_OSSL_CRMF_MSGS(a: PPOSSL_CRMF_MSGS; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_MSGS; cdecl;
function i2d_OSSL_CRMF_MSGS(a: POSSL_CRMF_MSGS; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_CRMF_MSGS_it: PASN1_ITEM; cdecl;
function OSSL_CRMF_pbmp_new(libctx: POSSL_LIB_CTX; slen: TIdC_SIZET; owfnid: TIdC_INT; itercnt: TIdC_SIZET; macnid: TIdC_INT): POSSL_CRMF_PBMPARAMETER; cdecl;
function OSSL_CRMF_pbm_new(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; pbmp: POSSL_CRMF_PBMPARAMETER; msg: PIdAnsiChar; msglen: TIdC_SIZET; sec: PIdAnsiChar; seclen: TIdC_SIZET; mac: PPIdAnsiChar; maclen: PIdC_SIZET): TIdC_INT; cdecl;
function OSSL_CRMF_MSG_set1_regCtrl_regToken(msg: POSSL_CRMF_MSG; tok: PASN1_UTF8STRING): TIdC_INT; cdecl;
function OSSL_CRMF_MSG_get0_regCtrl_regToken(msg: POSSL_CRMF_MSG): PASN1_UTF8STRING; cdecl;
function OSSL_CRMF_MSG_set1_regCtrl_authenticator(msg: POSSL_CRMF_MSG; auth: PASN1_UTF8STRING): TIdC_INT; cdecl;
function OSSL_CRMF_MSG_get0_regCtrl_authenticator(msg: POSSL_CRMF_MSG): PASN1_UTF8STRING; cdecl;
function OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo(pi: POSSL_CRMF_PKIPUBLICATIONINFO; spi: POSSL_CRMF_SINGLEPUBINFO): TIdC_INT; cdecl;
function OSSL_CRMF_MSG_set0_SinglePubInfo(spi: POSSL_CRMF_SINGLEPUBINFO; method: TIdC_INT; nm: PGENERAL_NAME): TIdC_INT; cdecl;
function OSSL_CRMF_MSG_set_PKIPublicationInfo_action(pi: POSSL_CRMF_PKIPUBLICATIONINFO; action: TIdC_INT): TIdC_INT; cdecl;
function OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo(msg: POSSL_CRMF_MSG; pi: POSSL_CRMF_PKIPUBLICATIONINFO): TIdC_INT; cdecl;
function OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo(msg: POSSL_CRMF_MSG): POSSL_CRMF_PKIPUBLICATIONINFO; cdecl;
function OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey(msg: POSSL_CRMF_MSG; pubkey: PX509_PUBKEY): TIdC_INT; cdecl;
function OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey(msg: POSSL_CRMF_MSG): PX509_PUBKEY; cdecl;
function OSSL_CRMF_MSG_set1_regCtrl_oldCertID(msg: POSSL_CRMF_MSG; cid: POSSL_CRMF_CERTID): TIdC_INT; cdecl;
function OSSL_CRMF_MSG_get0_regCtrl_oldCertID(msg: POSSL_CRMF_MSG): POSSL_CRMF_CERTID; cdecl;
function OSSL_CRMF_CERTID_gen(issuer: PX509_NAME; serial: PASN1_INTEGER): POSSL_CRMF_CERTID; cdecl;
function OSSL_CRMF_MSG_set1_regInfo_utf8Pairs(msg: POSSL_CRMF_MSG; utf8pairs: PASN1_UTF8STRING): TIdC_INT; cdecl;
function OSSL_CRMF_MSG_get0_regInfo_utf8Pairs(msg: POSSL_CRMF_MSG): PASN1_UTF8STRING; cdecl;
function OSSL_CRMF_MSG_set1_regInfo_certReq(msg: POSSL_CRMF_MSG; cr: POSSL_CRMF_CERTREQUEST): TIdC_INT; cdecl;
function OSSL_CRMF_MSG_get0_regInfo_certReq(msg: POSSL_CRMF_MSG): POSSL_CRMF_CERTREQUEST; cdecl;
function OSSL_CRMF_MSG_set0_validity(crm: POSSL_CRMF_MSG; notBefore: PASN1_TIME; notAfter: PASN1_TIME): TIdC_INT; cdecl;
function OSSL_CRMF_MSG_set_certReqId(crm: POSSL_CRMF_MSG; rid: TIdC_INT): TIdC_INT; cdecl;
function OSSL_CRMF_MSG_get_certReqId(crm: POSSL_CRMF_MSG): TIdC_INT; cdecl;
function OSSL_CRMF_MSG_set0_extensions(crm: POSSL_CRMF_MSG; exts: PX509_EXTENSIONS): TIdC_INT; cdecl;
function OSSL_CRMF_MSG_push0_extension(crm: POSSL_CRMF_MSG; ext: PX509_EXTENSION): TIdC_INT; cdecl;
function OSSL_CRMF_MSG_create_popo(meth: TIdC_INT; crm: POSSL_CRMF_MSG; pkey: PEVP_PKEY; digest: PEVP_MD; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
function OSSL_CRMF_MSGS_verify_popo(reqs: POSSL_CRMF_MSGS; rid: TIdC_INT; acceptRAVerified: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
function OSSL_CRMF_MSG_get0_tmpl(crm: POSSL_CRMF_MSG): POSSL_CRMF_CERTTEMPLATE; cdecl;
function OSSL_CRMF_CERTTEMPLATE_get0_publicKey(tmpl: POSSL_CRMF_CERTTEMPLATE): PX509_PUBKEY; cdecl;
function OSSL_CRMF_CERTTEMPLATE_get0_subject(tmpl: POSSL_CRMF_CERTTEMPLATE): PX509_NAME; cdecl;
function OSSL_CRMF_CERTTEMPLATE_get0_issuer(tmpl: POSSL_CRMF_CERTTEMPLATE): PX509_NAME; cdecl;
function OSSL_CRMF_CERTTEMPLATE_get0_serialNumber(tmpl: POSSL_CRMF_CERTTEMPLATE): PASN1_INTEGER; cdecl;
function OSSL_CRMF_CERTTEMPLATE_get0_extensions(tmpl: POSSL_CRMF_CERTTEMPLATE): PX509_EXTENSIONS; cdecl;
function OSSL_CRMF_CERTID_get0_issuer(cid: POSSL_CRMF_CERTID): PX509_NAME; cdecl;
function OSSL_CRMF_CERTID_get0_serialNumber(cid: POSSL_CRMF_CERTID): PASN1_INTEGER; cdecl;
function OSSL_CRMF_CERTTEMPLATE_fill(tmpl: POSSL_CRMF_CERTTEMPLATE; pubkey: PEVP_PKEY; subject: PX509_NAME; issuer: PX509_NAME; serial: PASN1_INTEGER): TIdC_INT; cdecl;
function OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert(ecert: POSSL_CRMF_ENCRYPTEDVALUE; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; pkey: PEVP_PKEY): PX509; cdecl;
function OSSL_CRMF_ENCRYPTEDKEY_get1_encCert(ecert: POSSL_CRMF_ENCRYPTEDKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; pkey: PEVP_PKEY; flags: TIdC_UINT): PX509; cdecl;
function OSSL_CRMF_ENCRYPTEDVALUE_decrypt(enc: POSSL_CRMF_ENCRYPTEDVALUE; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; pkey: PEVP_PKEY; outlen: PIdC_INT): PIdAnsiChar; cdecl;
function OSSL_CRMF_ENCRYPTEDKEY_get1_pkey(encryptedKey: POSSL_CRMF_ENCRYPTEDKEY; ts: PX509_STORE; extra: Pstack_st_X509; pkey: PEVP_PKEY; cert: PX509; secret: PASN1_OCTET_STRING; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl;
function OSSL_CRMF_MSG_centralkeygen_requested(crm: POSSL_CRMF_MSG; p10cr: PX509_REQ): TIdC_INT; cdecl;
function OSSL_CRMF_ENCRYPTEDKEY_init_envdata(envdata: PCMS_EnvelopedData): POSSL_CRMF_ENCRYPTEDKEY; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// OPENSSL STACK DEFINITIONS
// =============================================================================
type
  { TODO 1 -copenssl stack OSSL_CRMF_MSG definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_OSSL_CRMF_MSG = Pointer;
  {$EXTERNALSYM PSTACK_OF_OSSL_CRMF_MSG}

  { Original Stack Macros for OSSL_CRMF_MSG:
    SKM_DEFINE_STACK_OF_INTERNAL(OSSL_CRMF_MSG, OSSL_CRMF_MSG, OSSL_CRMF_MSG)
    sk_OSSL_CRMF_MSG_num(sk) OPENSSL_sk_num(ossl_check_const_OSSL_CRMF_MSG_sk_type(sk))
    sk_OSSL_CRMF_MSG_value(sk, idx) ((OSSL_CRMF_MSG *)OPENSSL_sk_value(ossl_check_const_OSSL_CRMF_MSG_sk_type(sk), (idx)))
    sk_OSSL_CRMF_MSG_new(cmp) ((STACK_OF(OSSL_CRMF_MSG) *)OPENSSL_sk_new(ossl_check_OSSL_CRMF_MSG_compfunc_type(cmp)))
    sk_OSSL_CRMF_MSG_new_null() ((STACK_OF(OSSL_CRMF_MSG) *)OPENSSL_sk_new_null())
    sk_OSSL_CRMF_MSG_new_reserve(cmp, n) ((STACK_OF(OSSL_CRMF_MSG) *)OPENSSL_sk_new_reserve(ossl_check_OSSL_CRMF_MSG_compfunc_type(cmp), (n)))
    sk_OSSL_CRMF_MSG_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_OSSL_CRMF_MSG_sk_type(sk), (n))
    sk_OSSL_CRMF_MSG_free(sk) OPENSSL_sk_free(ossl_check_OSSL_CRMF_MSG_sk_type(sk))
    sk_OSSL_CRMF_MSG_zero(sk) OPENSSL_sk_zero(ossl_check_OSSL_CRMF_MSG_sk_type(sk))
    sk_OSSL_CRMF_MSG_delete(sk, i) ((OSSL_CRMF_MSG *)OPENSSL_sk_delete(ossl_check_OSSL_CRMF_MSG_sk_type(sk), (i)))
    sk_OSSL_CRMF_MSG_delete_ptr(sk, ptr) ((OSSL_CRMF_MSG *)OPENSSL_sk_delete_ptr(ossl_check_OSSL_CRMF_MSG_sk_type(sk), ossl_check_OSSL_CRMF_MSG_type(ptr)))
    sk_OSSL_CRMF_MSG_push(sk, ptr) OPENSSL_sk_push(ossl_check_OSSL_CRMF_MSG_sk_type(sk), ossl_check_OSSL_CRMF_MSG_type(ptr))
    sk_OSSL_CRMF_MSG_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_OSSL_CRMF_MSG_sk_type(sk), ossl_check_OSSL_CRMF_MSG_type(ptr))
    sk_OSSL_CRMF_MSG_pop(sk) ((OSSL_CRMF_MSG *)OPENSSL_sk_pop(ossl_check_OSSL_CRMF_MSG_sk_type(sk)))
    sk_OSSL_CRMF_MSG_shift(sk) ((OSSL_CRMF_MSG *)OPENSSL_sk_shift(ossl_check_OSSL_CRMF_MSG_sk_type(sk)))
    sk_OSSL_CRMF_MSG_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_OSSL_CRMF_MSG_sk_type(sk), ossl_check_OSSL_CRMF_MSG_freefunc_type(freefunc))
    sk_OSSL_CRMF_MSG_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_OSSL_CRMF_MSG_sk_type(sk), ossl_check_OSSL_CRMF_MSG_type(ptr), (idx))
    sk_OSSL_CRMF_MSG_set(sk, idx, ptr) ((OSSL_CRMF_MSG *)OPENSSL_sk_set(ossl_check_OSSL_CRMF_MSG_sk_type(sk), (idx), ossl_check_OSSL_CRMF_MSG_type(ptr)))
    sk_OSSL_CRMF_MSG_find(sk, ptr) OPENSSL_sk_find(ossl_check_OSSL_CRMF_MSG_sk_type(sk), ossl_check_OSSL_CRMF_MSG_type(ptr))
    sk_OSSL_CRMF_MSG_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_OSSL_CRMF_MSG_sk_type(sk), ossl_check_OSSL_CRMF_MSG_type(ptr))
    sk_OSSL_CRMF_MSG_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_OSSL_CRMF_MSG_sk_type(sk), ossl_check_OSSL_CRMF_MSG_type(ptr), pnum)
    sk_OSSL_CRMF_MSG_sort(sk) OPENSSL_sk_sort(ossl_check_OSSL_CRMF_MSG_sk_type(sk))
    sk_OSSL_CRMF_MSG_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_OSSL_CRMF_MSG_sk_type(sk))
    sk_OSSL_CRMF_MSG_dup(sk) ((STACK_OF(OSSL_CRMF_MSG) *)OPENSSL_sk_dup(ossl_check_const_OSSL_CRMF_MSG_sk_type(sk)))
    sk_OSSL_CRMF_MSG_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(OSSL_CRMF_MSG) *)OPENSSL_sk_deep_copy(ossl_check_const_OSSL_CRMF_MSG_sk_type(sk), ossl_check_OSSL_CRMF_MSG_copyfunc_type(copyfunc), ossl_check_OSSL_CRMF_MSG_freefunc_type(freefunc)))
    sk_OSSL_CRMF_MSG_set_cmp_func(sk, cmp) ((sk_OSSL_CRMF_MSG_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_OSSL_CRMF_MSG_sk_type(sk), ossl_check_OSSL_CRMF_MSG_compfunc_type(cmp)))
  }

  { TODO 1 -copenssl stack OSSL_CRMF_ATTRIBUTETYPEANDVALUE definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_OSSL_CRMF_ATTRIBUTETYPEANDVALUE = Pointer;
  {$EXTERNALSYM PSTACK_OF_OSSL_CRMF_ATTRIBUTETYPEANDVALUE}

  { Original Stack Macros for OSSL_CRMF_ATTRIBUTETYPEANDVALUE:
    SKM_DEFINE_STACK_OF_INTERNAL(OSSL_CRMF_ATTRIBUTETYPEANDVALUE, OSSL_CRMF_ATTRIBUTETYPEANDVALUE, OSSL_CRMF_ATTRIBUTETYPEANDVALUE)
    sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_num(sk) OPENSSL_sk_num(ossl_check_const_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_sk_type(sk))
    sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_value(sk, idx) ((OSSL_CRMF_ATTRIBUTETYPEANDVALUE *)OPENSSL_sk_value(ossl_check_const_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_sk_type(sk), (idx)))
    sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_new(cmp) ((STACK_OF(OSSL_CRMF_ATTRIBUTETYPEANDVALUE) *)OPENSSL_sk_new(ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_compfunc_type(cmp)))
    sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_new_null() ((STACK_OF(OSSL_CRMF_ATTRIBUTETYPEANDVALUE) *)OPENSSL_sk_new_null())
    sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_new_reserve(cmp, n) ((STACK_OF(OSSL_CRMF_ATTRIBUTETYPEANDVALUE) *)OPENSSL_sk_new_reserve(ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_compfunc_type(cmp), (n)))
    sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_sk_type(sk), (n))
    sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free(sk) OPENSSL_sk_free(ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_sk_type(sk))
    sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_zero(sk) OPENSSL_sk_zero(ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_sk_type(sk))
    sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_delete(sk, i) ((OSSL_CRMF_ATTRIBUTETYPEANDVALUE *)OPENSSL_sk_delete(ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_sk_type(sk), (i)))
    sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_delete_ptr(sk, ptr) ((OSSL_CRMF_ATTRIBUTETYPEANDVALUE *)OPENSSL_sk_delete_ptr(ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_sk_type(sk), ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_type(ptr)))
    sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_push(sk, ptr) OPENSSL_sk_push(ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_sk_type(sk), ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_type(ptr))
    sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_sk_type(sk), ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_type(ptr))
    sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_pop(sk) ((OSSL_CRMF_ATTRIBUTETYPEANDVALUE *)OPENSSL_sk_pop(ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_sk_type(sk)))
    sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_shift(sk) ((OSSL_CRMF_ATTRIBUTETYPEANDVALUE *)OPENSSL_sk_shift(ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_sk_type(sk)))
    sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_sk_type(sk), ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_freefunc_type(freefunc))
    sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_sk_type(sk), ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_type(ptr), (idx))
    sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_set(sk, idx, ptr) ((OSSL_CRMF_ATTRIBUTETYPEANDVALUE *)OPENSSL_sk_set(ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_sk_type(sk), (idx), ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_type(ptr)))
    sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_find(sk, ptr) OPENSSL_sk_find(ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_sk_type(sk), ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_type(ptr))
    sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_sk_type(sk), ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_type(ptr))
    sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_sk_type(sk), ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_type(ptr), pnum)
    sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_sort(sk) OPENSSL_sk_sort(ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_sk_type(sk))
    sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_sk_type(sk))
    sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup(sk) ((STACK_OF(OSSL_CRMF_ATTRIBUTETYPEANDVALUE) *)OPENSSL_sk_dup(ossl_check_const_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_sk_type(sk)))
    sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(OSSL_CRMF_ATTRIBUTETYPEANDVALUE) *)OPENSSL_sk_deep_copy(ossl_check_const_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_sk_type(sk), ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_copyfunc_type(copyfunc), ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_freefunc_type(freefunc)))
    sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_set_cmp_func(sk, cmp) ((sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_sk_type(sk), ossl_check_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_compfunc_type(cmp)))
  }

  { TODO 1 -copenssl stack OSSL_CRMF_CERTID definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_OSSL_CRMF_CERTID = Pointer;
  {$EXTERNALSYM PSTACK_OF_OSSL_CRMF_CERTID}

  { Original Stack Macros for OSSL_CRMF_CERTID:
    SKM_DEFINE_STACK_OF_INTERNAL(OSSL_CRMF_CERTID, OSSL_CRMF_CERTID, OSSL_CRMF_CERTID)
    sk_OSSL_CRMF_CERTID_num(sk) OPENSSL_sk_num(ossl_check_const_OSSL_CRMF_CERTID_sk_type(sk))
    sk_OSSL_CRMF_CERTID_value(sk, idx) ((OSSL_CRMF_CERTID *)OPENSSL_sk_value(ossl_check_const_OSSL_CRMF_CERTID_sk_type(sk), (idx)))
    sk_OSSL_CRMF_CERTID_new(cmp) ((STACK_OF(OSSL_CRMF_CERTID) *)OPENSSL_sk_new(ossl_check_OSSL_CRMF_CERTID_compfunc_type(cmp)))
    sk_OSSL_CRMF_CERTID_new_null() ((STACK_OF(OSSL_CRMF_CERTID) *)OPENSSL_sk_new_null())
    sk_OSSL_CRMF_CERTID_new_reserve(cmp, n) ((STACK_OF(OSSL_CRMF_CERTID) *)OPENSSL_sk_new_reserve(ossl_check_OSSL_CRMF_CERTID_compfunc_type(cmp), (n)))
    sk_OSSL_CRMF_CERTID_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_OSSL_CRMF_CERTID_sk_type(sk), (n))
    sk_OSSL_CRMF_CERTID_free(sk) OPENSSL_sk_free(ossl_check_OSSL_CRMF_CERTID_sk_type(sk))
    sk_OSSL_CRMF_CERTID_zero(sk) OPENSSL_sk_zero(ossl_check_OSSL_CRMF_CERTID_sk_type(sk))
    sk_OSSL_CRMF_CERTID_delete(sk, i) ((OSSL_CRMF_CERTID *)OPENSSL_sk_delete(ossl_check_OSSL_CRMF_CERTID_sk_type(sk), (i)))
    sk_OSSL_CRMF_CERTID_delete_ptr(sk, ptr) ((OSSL_CRMF_CERTID *)OPENSSL_sk_delete_ptr(ossl_check_OSSL_CRMF_CERTID_sk_type(sk), ossl_check_OSSL_CRMF_CERTID_type(ptr)))
    sk_OSSL_CRMF_CERTID_push(sk, ptr) OPENSSL_sk_push(ossl_check_OSSL_CRMF_CERTID_sk_type(sk), ossl_check_OSSL_CRMF_CERTID_type(ptr))
    sk_OSSL_CRMF_CERTID_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_OSSL_CRMF_CERTID_sk_type(sk), ossl_check_OSSL_CRMF_CERTID_type(ptr))
    sk_OSSL_CRMF_CERTID_pop(sk) ((OSSL_CRMF_CERTID *)OPENSSL_sk_pop(ossl_check_OSSL_CRMF_CERTID_sk_type(sk)))
    sk_OSSL_CRMF_CERTID_shift(sk) ((OSSL_CRMF_CERTID *)OPENSSL_sk_shift(ossl_check_OSSL_CRMF_CERTID_sk_type(sk)))
    sk_OSSL_CRMF_CERTID_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_OSSL_CRMF_CERTID_sk_type(sk), ossl_check_OSSL_CRMF_CERTID_freefunc_type(freefunc))
    sk_OSSL_CRMF_CERTID_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_OSSL_CRMF_CERTID_sk_type(sk), ossl_check_OSSL_CRMF_CERTID_type(ptr), (idx))
    sk_OSSL_CRMF_CERTID_set(sk, idx, ptr) ((OSSL_CRMF_CERTID *)OPENSSL_sk_set(ossl_check_OSSL_CRMF_CERTID_sk_type(sk), (idx), ossl_check_OSSL_CRMF_CERTID_type(ptr)))
    sk_OSSL_CRMF_CERTID_find(sk, ptr) OPENSSL_sk_find(ossl_check_OSSL_CRMF_CERTID_sk_type(sk), ossl_check_OSSL_CRMF_CERTID_type(ptr))
    sk_OSSL_CRMF_CERTID_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_OSSL_CRMF_CERTID_sk_type(sk), ossl_check_OSSL_CRMF_CERTID_type(ptr))
    sk_OSSL_CRMF_CERTID_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_OSSL_CRMF_CERTID_sk_type(sk), ossl_check_OSSL_CRMF_CERTID_type(ptr), pnum)
    sk_OSSL_CRMF_CERTID_sort(sk) OPENSSL_sk_sort(ossl_check_OSSL_CRMF_CERTID_sk_type(sk))
    sk_OSSL_CRMF_CERTID_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_OSSL_CRMF_CERTID_sk_type(sk))
    sk_OSSL_CRMF_CERTID_dup(sk) ((STACK_OF(OSSL_CRMF_CERTID) *)OPENSSL_sk_dup(ossl_check_const_OSSL_CRMF_CERTID_sk_type(sk)))
    sk_OSSL_CRMF_CERTID_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(OSSL_CRMF_CERTID) *)OPENSSL_sk_deep_copy(ossl_check_const_OSSL_CRMF_CERTID_sk_type(sk), ossl_check_OSSL_CRMF_CERTID_copyfunc_type(copyfunc), ossl_check_OSSL_CRMF_CERTID_freefunc_type(freefunc)))
    sk_OSSL_CRMF_CERTID_set_cmp_func(sk, cmp) ((sk_OSSL_CRMF_CERTID_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_OSSL_CRMF_CERTID_sk_type(sk), ossl_check_OSSL_CRMF_CERTID_compfunc_type(cmp)))
  }


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

function OSSL_CRMF_ENCRYPTEDVALUE_new: POSSL_CRMF_ENCRYPTEDVALUE; cdecl external CLibCrypto name 'OSSL_CRMF_ENCRYPTEDVALUE_new';
procedure OSSL_CRMF_ENCRYPTEDVALUE_free(a: POSSL_CRMF_ENCRYPTEDVALUE); cdecl external CLibCrypto name 'OSSL_CRMF_ENCRYPTEDVALUE_free';
function d2i_OSSL_CRMF_ENCRYPTEDVALUE(a: PPOSSL_CRMF_ENCRYPTEDVALUE; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_ENCRYPTEDVALUE; cdecl external CLibCrypto name 'd2i_OSSL_CRMF_ENCRYPTEDVALUE';
function i2d_OSSL_CRMF_ENCRYPTEDVALUE(a: POSSL_CRMF_ENCRYPTEDVALUE; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_CRMF_ENCRYPTEDVALUE';
function OSSL_CRMF_ENCRYPTEDVALUE_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_CRMF_ENCRYPTEDVALUE_it';
function OSSL_CRMF_ENCRYPTEDKEY_new: POSSL_CRMF_ENCRYPTEDKEY; cdecl external CLibCrypto name 'OSSL_CRMF_ENCRYPTEDKEY_new';
procedure OSSL_CRMF_ENCRYPTEDKEY_free(a: POSSL_CRMF_ENCRYPTEDKEY); cdecl external CLibCrypto name 'OSSL_CRMF_ENCRYPTEDKEY_free';
function d2i_OSSL_CRMF_ENCRYPTEDKEY(a: PPOSSL_CRMF_ENCRYPTEDKEY; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_ENCRYPTEDKEY; cdecl external CLibCrypto name 'd2i_OSSL_CRMF_ENCRYPTEDKEY';
function i2d_OSSL_CRMF_ENCRYPTEDKEY(a: POSSL_CRMF_ENCRYPTEDKEY; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_CRMF_ENCRYPTEDKEY';
function OSSL_CRMF_ENCRYPTEDKEY_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_CRMF_ENCRYPTEDKEY_it';
function OSSL_CRMF_MSG_new: POSSL_CRMF_MSG; cdecl external CLibCrypto name 'OSSL_CRMF_MSG_new';
procedure OSSL_CRMF_MSG_free(a: POSSL_CRMF_MSG); cdecl external CLibCrypto name 'OSSL_CRMF_MSG_free';
function d2i_OSSL_CRMF_MSG(a: PPOSSL_CRMF_MSG; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_MSG; cdecl external CLibCrypto name 'd2i_OSSL_CRMF_MSG';
function i2d_OSSL_CRMF_MSG(a: POSSL_CRMF_MSG; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_CRMF_MSG';
function OSSL_CRMF_MSG_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_CRMF_MSG_it';
function OSSL_CRMF_MSG_dup(a: POSSL_CRMF_MSG): POSSL_CRMF_MSG; cdecl external CLibCrypto name 'OSSL_CRMF_MSG_dup';
procedure OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free(v: POSSL_CRMF_ATTRIBUTETYPEANDVALUE); cdecl external CLibCrypto name 'OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free';
function OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup(a: POSSL_CRMF_ATTRIBUTETYPEANDVALUE): POSSL_CRMF_ATTRIBUTETYPEANDVALUE; cdecl external CLibCrypto name 'OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup';
function OSSL_CRMF_PBMPARAMETER_new: POSSL_CRMF_PBMPARAMETER; cdecl external CLibCrypto name 'OSSL_CRMF_PBMPARAMETER_new';
procedure OSSL_CRMF_PBMPARAMETER_free(a: POSSL_CRMF_PBMPARAMETER); cdecl external CLibCrypto name 'OSSL_CRMF_PBMPARAMETER_free';
function d2i_OSSL_CRMF_PBMPARAMETER(a: PPOSSL_CRMF_PBMPARAMETER; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_PBMPARAMETER; cdecl external CLibCrypto name 'd2i_OSSL_CRMF_PBMPARAMETER';
function i2d_OSSL_CRMF_PBMPARAMETER(a: POSSL_CRMF_PBMPARAMETER; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_CRMF_PBMPARAMETER';
function OSSL_CRMF_PBMPARAMETER_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_CRMF_PBMPARAMETER_it';
function OSSL_CRMF_CERTID_new: POSSL_CRMF_CERTID; cdecl external CLibCrypto name 'OSSL_CRMF_CERTID_new';
procedure OSSL_CRMF_CERTID_free(a: POSSL_CRMF_CERTID); cdecl external CLibCrypto name 'OSSL_CRMF_CERTID_free';
function d2i_OSSL_CRMF_CERTID(a: PPOSSL_CRMF_CERTID; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_CERTID; cdecl external CLibCrypto name 'd2i_OSSL_CRMF_CERTID';
function i2d_OSSL_CRMF_CERTID(a: POSSL_CRMF_CERTID; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_CRMF_CERTID';
function OSSL_CRMF_CERTID_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_CRMF_CERTID_it';
function OSSL_CRMF_CERTID_dup(a: POSSL_CRMF_CERTID): POSSL_CRMF_CERTID; cdecl external CLibCrypto name 'OSSL_CRMF_CERTID_dup';
function OSSL_CRMF_PKIPUBLICATIONINFO_new: POSSL_CRMF_PKIPUBLICATIONINFO; cdecl external CLibCrypto name 'OSSL_CRMF_PKIPUBLICATIONINFO_new';
procedure OSSL_CRMF_PKIPUBLICATIONINFO_free(a: POSSL_CRMF_PKIPUBLICATIONINFO); cdecl external CLibCrypto name 'OSSL_CRMF_PKIPUBLICATIONINFO_free';
function d2i_OSSL_CRMF_PKIPUBLICATIONINFO(a: PPOSSL_CRMF_PKIPUBLICATIONINFO; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_PKIPUBLICATIONINFO; cdecl external CLibCrypto name 'd2i_OSSL_CRMF_PKIPUBLICATIONINFO';
function i2d_OSSL_CRMF_PKIPUBLICATIONINFO(a: POSSL_CRMF_PKIPUBLICATIONINFO; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_CRMF_PKIPUBLICATIONINFO';
function OSSL_CRMF_PKIPUBLICATIONINFO_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_CRMF_PKIPUBLICATIONINFO_it';
function OSSL_CRMF_SINGLEPUBINFO_new: POSSL_CRMF_SINGLEPUBINFO; cdecl external CLibCrypto name 'OSSL_CRMF_SINGLEPUBINFO_new';
procedure OSSL_CRMF_SINGLEPUBINFO_free(a: POSSL_CRMF_SINGLEPUBINFO); cdecl external CLibCrypto name 'OSSL_CRMF_SINGLEPUBINFO_free';
function d2i_OSSL_CRMF_SINGLEPUBINFO(a: PPOSSL_CRMF_SINGLEPUBINFO; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_SINGLEPUBINFO; cdecl external CLibCrypto name 'd2i_OSSL_CRMF_SINGLEPUBINFO';
function i2d_OSSL_CRMF_SINGLEPUBINFO(a: POSSL_CRMF_SINGLEPUBINFO; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_CRMF_SINGLEPUBINFO';
function OSSL_CRMF_SINGLEPUBINFO_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_CRMF_SINGLEPUBINFO_it';
function OSSL_CRMF_CERTTEMPLATE_new: POSSL_CRMF_CERTTEMPLATE; cdecl external CLibCrypto name 'OSSL_CRMF_CERTTEMPLATE_new';
procedure OSSL_CRMF_CERTTEMPLATE_free(a: POSSL_CRMF_CERTTEMPLATE); cdecl external CLibCrypto name 'OSSL_CRMF_CERTTEMPLATE_free';
function d2i_OSSL_CRMF_CERTTEMPLATE(a: PPOSSL_CRMF_CERTTEMPLATE; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_CERTTEMPLATE; cdecl external CLibCrypto name 'd2i_OSSL_CRMF_CERTTEMPLATE';
function i2d_OSSL_CRMF_CERTTEMPLATE(a: POSSL_CRMF_CERTTEMPLATE; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_CRMF_CERTTEMPLATE';
function OSSL_CRMF_CERTTEMPLATE_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_CRMF_CERTTEMPLATE_it';
function OSSL_CRMF_CERTTEMPLATE_dup(a: POSSL_CRMF_CERTTEMPLATE): POSSL_CRMF_CERTTEMPLATE; cdecl external CLibCrypto name 'OSSL_CRMF_CERTTEMPLATE_dup';
function OSSL_CRMF_MSGS_new: POSSL_CRMF_MSGS; cdecl external CLibCrypto name 'OSSL_CRMF_MSGS_new';
procedure OSSL_CRMF_MSGS_free(a: POSSL_CRMF_MSGS); cdecl external CLibCrypto name 'OSSL_CRMF_MSGS_free';
function d2i_OSSL_CRMF_MSGS(a: PPOSSL_CRMF_MSGS; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_MSGS; cdecl external CLibCrypto name 'd2i_OSSL_CRMF_MSGS';
function i2d_OSSL_CRMF_MSGS(a: POSSL_CRMF_MSGS; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_CRMF_MSGS';
function OSSL_CRMF_MSGS_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_CRMF_MSGS_it';
function OSSL_CRMF_pbmp_new(libctx: POSSL_LIB_CTX; slen: TIdC_SIZET; owfnid: TIdC_INT; itercnt: TIdC_SIZET; macnid: TIdC_INT): POSSL_CRMF_PBMPARAMETER; cdecl external CLibCrypto name 'OSSL_CRMF_pbmp_new';
function OSSL_CRMF_pbm_new(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; pbmp: POSSL_CRMF_PBMPARAMETER; msg: PIdAnsiChar; msglen: TIdC_SIZET; sec: PIdAnsiChar; seclen: TIdC_SIZET; mac: PPIdAnsiChar; maclen: PIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CRMF_pbm_new';
function OSSL_CRMF_MSG_set1_regCtrl_regToken(msg: POSSL_CRMF_MSG; tok: PASN1_UTF8STRING): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CRMF_MSG_set1_regCtrl_regToken';
function OSSL_CRMF_MSG_get0_regCtrl_regToken(msg: POSSL_CRMF_MSG): PASN1_UTF8STRING; cdecl external CLibCrypto name 'OSSL_CRMF_MSG_get0_regCtrl_regToken';
function OSSL_CRMF_MSG_set1_regCtrl_authenticator(msg: POSSL_CRMF_MSG; auth: PASN1_UTF8STRING): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CRMF_MSG_set1_regCtrl_authenticator';
function OSSL_CRMF_MSG_get0_regCtrl_authenticator(msg: POSSL_CRMF_MSG): PASN1_UTF8STRING; cdecl external CLibCrypto name 'OSSL_CRMF_MSG_get0_regCtrl_authenticator';
function OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo(pi: POSSL_CRMF_PKIPUBLICATIONINFO; spi: POSSL_CRMF_SINGLEPUBINFO): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo';
function OSSL_CRMF_MSG_set0_SinglePubInfo(spi: POSSL_CRMF_SINGLEPUBINFO; method: TIdC_INT; nm: PGENERAL_NAME): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CRMF_MSG_set0_SinglePubInfo';
function OSSL_CRMF_MSG_set_PKIPublicationInfo_action(pi: POSSL_CRMF_PKIPUBLICATIONINFO; action: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CRMF_MSG_set_PKIPublicationInfo_action';
function OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo(msg: POSSL_CRMF_MSG; pi: POSSL_CRMF_PKIPUBLICATIONINFO): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo';
function OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo(msg: POSSL_CRMF_MSG): POSSL_CRMF_PKIPUBLICATIONINFO; cdecl external CLibCrypto name 'OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo';
function OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey(msg: POSSL_CRMF_MSG; pubkey: PX509_PUBKEY): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey';
function OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey(msg: POSSL_CRMF_MSG): PX509_PUBKEY; cdecl external CLibCrypto name 'OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey';
function OSSL_CRMF_MSG_set1_regCtrl_oldCertID(msg: POSSL_CRMF_MSG; cid: POSSL_CRMF_CERTID): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CRMF_MSG_set1_regCtrl_oldCertID';
function OSSL_CRMF_MSG_get0_regCtrl_oldCertID(msg: POSSL_CRMF_MSG): POSSL_CRMF_CERTID; cdecl external CLibCrypto name 'OSSL_CRMF_MSG_get0_regCtrl_oldCertID';
function OSSL_CRMF_CERTID_gen(issuer: PX509_NAME; serial: PASN1_INTEGER): POSSL_CRMF_CERTID; cdecl external CLibCrypto name 'OSSL_CRMF_CERTID_gen';
function OSSL_CRMF_MSG_set1_regInfo_utf8Pairs(msg: POSSL_CRMF_MSG; utf8pairs: PASN1_UTF8STRING): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CRMF_MSG_set1_regInfo_utf8Pairs';
function OSSL_CRMF_MSG_get0_regInfo_utf8Pairs(msg: POSSL_CRMF_MSG): PASN1_UTF8STRING; cdecl external CLibCrypto name 'OSSL_CRMF_MSG_get0_regInfo_utf8Pairs';
function OSSL_CRMF_MSG_set1_regInfo_certReq(msg: POSSL_CRMF_MSG; cr: POSSL_CRMF_CERTREQUEST): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CRMF_MSG_set1_regInfo_certReq';
function OSSL_CRMF_MSG_get0_regInfo_certReq(msg: POSSL_CRMF_MSG): POSSL_CRMF_CERTREQUEST; cdecl external CLibCrypto name 'OSSL_CRMF_MSG_get0_regInfo_certReq';
function OSSL_CRMF_MSG_set0_validity(crm: POSSL_CRMF_MSG; notBefore: PASN1_TIME; notAfter: PASN1_TIME): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CRMF_MSG_set0_validity';
function OSSL_CRMF_MSG_set_certReqId(crm: POSSL_CRMF_MSG; rid: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CRMF_MSG_set_certReqId';
function OSSL_CRMF_MSG_get_certReqId(crm: POSSL_CRMF_MSG): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CRMF_MSG_get_certReqId';
function OSSL_CRMF_MSG_set0_extensions(crm: POSSL_CRMF_MSG; exts: PX509_EXTENSIONS): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CRMF_MSG_set0_extensions';
function OSSL_CRMF_MSG_push0_extension(crm: POSSL_CRMF_MSG; ext: PX509_EXTENSION): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CRMF_MSG_push0_extension';
function OSSL_CRMF_MSG_create_popo(meth: TIdC_INT; crm: POSSL_CRMF_MSG; pkey: PEVP_PKEY; digest: PEVP_MD; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CRMF_MSG_create_popo';
function OSSL_CRMF_MSGS_verify_popo(reqs: POSSL_CRMF_MSGS; rid: TIdC_INT; acceptRAVerified: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CRMF_MSGS_verify_popo';
function OSSL_CRMF_MSG_get0_tmpl(crm: POSSL_CRMF_MSG): POSSL_CRMF_CERTTEMPLATE; cdecl external CLibCrypto name 'OSSL_CRMF_MSG_get0_tmpl';
function OSSL_CRMF_CERTTEMPLATE_get0_publicKey(tmpl: POSSL_CRMF_CERTTEMPLATE): PX509_PUBKEY; cdecl external CLibCrypto name 'OSSL_CRMF_CERTTEMPLATE_get0_publicKey';
function OSSL_CRMF_CERTTEMPLATE_get0_subject(tmpl: POSSL_CRMF_CERTTEMPLATE): PX509_NAME; cdecl external CLibCrypto name 'OSSL_CRMF_CERTTEMPLATE_get0_subject';
function OSSL_CRMF_CERTTEMPLATE_get0_issuer(tmpl: POSSL_CRMF_CERTTEMPLATE): PX509_NAME; cdecl external CLibCrypto name 'OSSL_CRMF_CERTTEMPLATE_get0_issuer';
function OSSL_CRMF_CERTTEMPLATE_get0_serialNumber(tmpl: POSSL_CRMF_CERTTEMPLATE): PASN1_INTEGER; cdecl external CLibCrypto name 'OSSL_CRMF_CERTTEMPLATE_get0_serialNumber';
function OSSL_CRMF_CERTTEMPLATE_get0_extensions(tmpl: POSSL_CRMF_CERTTEMPLATE): PX509_EXTENSIONS; cdecl external CLibCrypto name 'OSSL_CRMF_CERTTEMPLATE_get0_extensions';
function OSSL_CRMF_CERTID_get0_issuer(cid: POSSL_CRMF_CERTID): PX509_NAME; cdecl external CLibCrypto name 'OSSL_CRMF_CERTID_get0_issuer';
function OSSL_CRMF_CERTID_get0_serialNumber(cid: POSSL_CRMF_CERTID): PASN1_INTEGER; cdecl external CLibCrypto name 'OSSL_CRMF_CERTID_get0_serialNumber';
function OSSL_CRMF_CERTTEMPLATE_fill(tmpl: POSSL_CRMF_CERTTEMPLATE; pubkey: PEVP_PKEY; subject: PX509_NAME; issuer: PX509_NAME; serial: PASN1_INTEGER): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CRMF_CERTTEMPLATE_fill';
function OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert(ecert: POSSL_CRMF_ENCRYPTEDVALUE; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; pkey: PEVP_PKEY): PX509; cdecl external CLibCrypto name 'OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert';
function OSSL_CRMF_ENCRYPTEDKEY_get1_encCert(ecert: POSSL_CRMF_ENCRYPTEDKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; pkey: PEVP_PKEY; flags: TIdC_UINT): PX509; cdecl external CLibCrypto name 'OSSL_CRMF_ENCRYPTEDKEY_get1_encCert';
function OSSL_CRMF_ENCRYPTEDVALUE_decrypt(enc: POSSL_CRMF_ENCRYPTEDVALUE; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; pkey: PEVP_PKEY; outlen: PIdC_INT): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_CRMF_ENCRYPTEDVALUE_decrypt';
function OSSL_CRMF_ENCRYPTEDKEY_get1_pkey(encryptedKey: POSSL_CRMF_ENCRYPTEDKEY; ts: PX509_STORE; extra: Pstack_st_X509; pkey: PEVP_PKEY; cert: PX509; secret: PASN1_OCTET_STRING; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl external CLibCrypto name 'OSSL_CRMF_ENCRYPTEDKEY_get1_pkey';
function OSSL_CRMF_MSG_centralkeygen_requested(crm: POSSL_CRMF_MSG; p10cr: PX509_REQ): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CRMF_MSG_centralkeygen_requested';
function OSSL_CRMF_ENCRYPTEDKEY_init_envdata(envdata: PCMS_EnvelopedData): POSSL_CRMF_ENCRYPTEDKEY; cdecl external CLibCrypto name 'OSSL_CRMF_ENCRYPTEDKEY_init_envdata';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  OSSL_CRMF_ENCRYPTEDVALUE_new_procname = 'OSSL_CRMF_ENCRYPTEDVALUE_new';
  OSSL_CRMF_ENCRYPTEDVALUE_new_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_ENCRYPTEDVALUE_free_procname = 'OSSL_CRMF_ENCRYPTEDVALUE_free';
  OSSL_CRMF_ENCRYPTEDVALUE_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_OSSL_CRMF_ENCRYPTEDVALUE_procname = 'd2i_OSSL_CRMF_ENCRYPTEDVALUE';
  d2i_OSSL_CRMF_ENCRYPTEDVALUE_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_OSSL_CRMF_ENCRYPTEDVALUE_procname = 'i2d_OSSL_CRMF_ENCRYPTEDVALUE';
  i2d_OSSL_CRMF_ENCRYPTEDVALUE_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_ENCRYPTEDVALUE_it_procname = 'OSSL_CRMF_ENCRYPTEDVALUE_it';
  OSSL_CRMF_ENCRYPTEDVALUE_it_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_ENCRYPTEDKEY_new_procname = 'OSSL_CRMF_ENCRYPTEDKEY_new';
  OSSL_CRMF_ENCRYPTEDKEY_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_CRMF_ENCRYPTEDKEY_free_procname = 'OSSL_CRMF_ENCRYPTEDKEY_free';
  OSSL_CRMF_ENCRYPTEDKEY_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_CRMF_ENCRYPTEDKEY_procname = 'd2i_OSSL_CRMF_ENCRYPTEDKEY';
  d2i_OSSL_CRMF_ENCRYPTEDKEY_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_CRMF_ENCRYPTEDKEY_procname = 'i2d_OSSL_CRMF_ENCRYPTEDKEY';
  i2d_OSSL_CRMF_ENCRYPTEDKEY_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_CRMF_ENCRYPTEDKEY_it_procname = 'OSSL_CRMF_ENCRYPTEDKEY_it';
  OSSL_CRMF_ENCRYPTEDKEY_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_CRMF_MSG_new_procname = 'OSSL_CRMF_MSG_new';
  OSSL_CRMF_MSG_new_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSG_free_procname = 'OSSL_CRMF_MSG_free';
  OSSL_CRMF_MSG_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_OSSL_CRMF_MSG_procname = 'd2i_OSSL_CRMF_MSG';
  d2i_OSSL_CRMF_MSG_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_OSSL_CRMF_MSG_procname = 'i2d_OSSL_CRMF_MSG';
  i2d_OSSL_CRMF_MSG_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSG_it_procname = 'OSSL_CRMF_MSG_it';
  OSSL_CRMF_MSG_it_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSG_dup_procname = 'OSSL_CRMF_MSG_dup';
  OSSL_CRMF_MSG_dup_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free_procname = 'OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free';
  OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup_procname = 'OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup';
  OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_CRMF_PBMPARAMETER_new_procname = 'OSSL_CRMF_PBMPARAMETER_new';
  OSSL_CRMF_PBMPARAMETER_new_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_PBMPARAMETER_free_procname = 'OSSL_CRMF_PBMPARAMETER_free';
  OSSL_CRMF_PBMPARAMETER_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_OSSL_CRMF_PBMPARAMETER_procname = 'd2i_OSSL_CRMF_PBMPARAMETER';
  d2i_OSSL_CRMF_PBMPARAMETER_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_OSSL_CRMF_PBMPARAMETER_procname = 'i2d_OSSL_CRMF_PBMPARAMETER';
  i2d_OSSL_CRMF_PBMPARAMETER_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_PBMPARAMETER_it_procname = 'OSSL_CRMF_PBMPARAMETER_it';
  OSSL_CRMF_PBMPARAMETER_it_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_CERTID_new_procname = 'OSSL_CRMF_CERTID_new';
  OSSL_CRMF_CERTID_new_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_CERTID_free_procname = 'OSSL_CRMF_CERTID_free';
  OSSL_CRMF_CERTID_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_OSSL_CRMF_CERTID_procname = 'd2i_OSSL_CRMF_CERTID';
  d2i_OSSL_CRMF_CERTID_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_OSSL_CRMF_CERTID_procname = 'i2d_OSSL_CRMF_CERTID';
  i2d_OSSL_CRMF_CERTID_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_CERTID_it_procname = 'OSSL_CRMF_CERTID_it';
  OSSL_CRMF_CERTID_it_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_CERTID_dup_procname = 'OSSL_CRMF_CERTID_dup';
  OSSL_CRMF_CERTID_dup_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_PKIPUBLICATIONINFO_new_procname = 'OSSL_CRMF_PKIPUBLICATIONINFO_new';
  OSSL_CRMF_PKIPUBLICATIONINFO_new_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_PKIPUBLICATIONINFO_free_procname = 'OSSL_CRMF_PKIPUBLICATIONINFO_free';
  OSSL_CRMF_PKIPUBLICATIONINFO_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_OSSL_CRMF_PKIPUBLICATIONINFO_procname = 'd2i_OSSL_CRMF_PKIPUBLICATIONINFO';
  d2i_OSSL_CRMF_PKIPUBLICATIONINFO_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_OSSL_CRMF_PKIPUBLICATIONINFO_procname = 'i2d_OSSL_CRMF_PKIPUBLICATIONINFO';
  i2d_OSSL_CRMF_PKIPUBLICATIONINFO_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_PKIPUBLICATIONINFO_it_procname = 'OSSL_CRMF_PKIPUBLICATIONINFO_it';
  OSSL_CRMF_PKIPUBLICATIONINFO_it_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_SINGLEPUBINFO_new_procname = 'OSSL_CRMF_SINGLEPUBINFO_new';
  OSSL_CRMF_SINGLEPUBINFO_new_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_SINGLEPUBINFO_free_procname = 'OSSL_CRMF_SINGLEPUBINFO_free';
  OSSL_CRMF_SINGLEPUBINFO_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_OSSL_CRMF_SINGLEPUBINFO_procname = 'd2i_OSSL_CRMF_SINGLEPUBINFO';
  d2i_OSSL_CRMF_SINGLEPUBINFO_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_OSSL_CRMF_SINGLEPUBINFO_procname = 'i2d_OSSL_CRMF_SINGLEPUBINFO';
  i2d_OSSL_CRMF_SINGLEPUBINFO_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_SINGLEPUBINFO_it_procname = 'OSSL_CRMF_SINGLEPUBINFO_it';
  OSSL_CRMF_SINGLEPUBINFO_it_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_CERTTEMPLATE_new_procname = 'OSSL_CRMF_CERTTEMPLATE_new';
  OSSL_CRMF_CERTTEMPLATE_new_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_CERTTEMPLATE_free_procname = 'OSSL_CRMF_CERTTEMPLATE_free';
  OSSL_CRMF_CERTTEMPLATE_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_OSSL_CRMF_CERTTEMPLATE_procname = 'd2i_OSSL_CRMF_CERTTEMPLATE';
  d2i_OSSL_CRMF_CERTTEMPLATE_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_OSSL_CRMF_CERTTEMPLATE_procname = 'i2d_OSSL_CRMF_CERTTEMPLATE';
  i2d_OSSL_CRMF_CERTTEMPLATE_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_CERTTEMPLATE_it_procname = 'OSSL_CRMF_CERTTEMPLATE_it';
  OSSL_CRMF_CERTTEMPLATE_it_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_CERTTEMPLATE_dup_procname = 'OSSL_CRMF_CERTTEMPLATE_dup';
  OSSL_CRMF_CERTTEMPLATE_dup_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_CRMF_MSGS_new_procname = 'OSSL_CRMF_MSGS_new';
  OSSL_CRMF_MSGS_new_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSGS_free_procname = 'OSSL_CRMF_MSGS_free';
  OSSL_CRMF_MSGS_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_OSSL_CRMF_MSGS_procname = 'd2i_OSSL_CRMF_MSGS';
  d2i_OSSL_CRMF_MSGS_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_OSSL_CRMF_MSGS_procname = 'i2d_OSSL_CRMF_MSGS';
  i2d_OSSL_CRMF_MSGS_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSGS_it_procname = 'OSSL_CRMF_MSGS_it';
  OSSL_CRMF_MSGS_it_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_pbmp_new_procname = 'OSSL_CRMF_pbmp_new';
  OSSL_CRMF_pbmp_new_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_pbm_new_procname = 'OSSL_CRMF_pbm_new';
  OSSL_CRMF_pbm_new_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSG_set1_regCtrl_regToken_procname = 'OSSL_CRMF_MSG_set1_regCtrl_regToken';
  OSSL_CRMF_MSG_set1_regCtrl_regToken_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSG_get0_regCtrl_regToken_procname = 'OSSL_CRMF_MSG_get0_regCtrl_regToken';
  OSSL_CRMF_MSG_get0_regCtrl_regToken_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSG_set1_regCtrl_authenticator_procname = 'OSSL_CRMF_MSG_set1_regCtrl_authenticator';
  OSSL_CRMF_MSG_set1_regCtrl_authenticator_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSG_get0_regCtrl_authenticator_procname = 'OSSL_CRMF_MSG_get0_regCtrl_authenticator';
  OSSL_CRMF_MSG_get0_regCtrl_authenticator_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo_procname = 'OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo';
  OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSG_set0_SinglePubInfo_procname = 'OSSL_CRMF_MSG_set0_SinglePubInfo';
  OSSL_CRMF_MSG_set0_SinglePubInfo_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSG_set_PKIPublicationInfo_action_procname = 'OSSL_CRMF_MSG_set_PKIPublicationInfo_action';
  OSSL_CRMF_MSG_set_PKIPublicationInfo_action_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo_procname = 'OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo';
  OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo_procname = 'OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo';
  OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey_procname = 'OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey';
  OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey_procname = 'OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey';
  OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSG_set1_regCtrl_oldCertID_procname = 'OSSL_CRMF_MSG_set1_regCtrl_oldCertID';
  OSSL_CRMF_MSG_set1_regCtrl_oldCertID_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSG_get0_regCtrl_oldCertID_procname = 'OSSL_CRMF_MSG_get0_regCtrl_oldCertID';
  OSSL_CRMF_MSG_get0_regCtrl_oldCertID_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_CERTID_gen_procname = 'OSSL_CRMF_CERTID_gen';
  OSSL_CRMF_CERTID_gen_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSG_set1_regInfo_utf8Pairs_procname = 'OSSL_CRMF_MSG_set1_regInfo_utf8Pairs';
  OSSL_CRMF_MSG_set1_regInfo_utf8Pairs_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSG_get0_regInfo_utf8Pairs_procname = 'OSSL_CRMF_MSG_get0_regInfo_utf8Pairs';
  OSSL_CRMF_MSG_get0_regInfo_utf8Pairs_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSG_set1_regInfo_certReq_procname = 'OSSL_CRMF_MSG_set1_regInfo_certReq';
  OSSL_CRMF_MSG_set1_regInfo_certReq_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSG_get0_regInfo_certReq_procname = 'OSSL_CRMF_MSG_get0_regInfo_certReq';
  OSSL_CRMF_MSG_get0_regInfo_certReq_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSG_set0_validity_procname = 'OSSL_CRMF_MSG_set0_validity';
  OSSL_CRMF_MSG_set0_validity_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSG_set_certReqId_procname = 'OSSL_CRMF_MSG_set_certReqId';
  OSSL_CRMF_MSG_set_certReqId_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSG_get_certReqId_procname = 'OSSL_CRMF_MSG_get_certReqId';
  OSSL_CRMF_MSG_get_certReqId_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSG_set0_extensions_procname = 'OSSL_CRMF_MSG_set0_extensions';
  OSSL_CRMF_MSG_set0_extensions_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSG_push0_extension_procname = 'OSSL_CRMF_MSG_push0_extension';
  OSSL_CRMF_MSG_push0_extension_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSG_create_popo_procname = 'OSSL_CRMF_MSG_create_popo';
  OSSL_CRMF_MSG_create_popo_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSGS_verify_popo_procname = 'OSSL_CRMF_MSGS_verify_popo';
  OSSL_CRMF_MSGS_verify_popo_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_MSG_get0_tmpl_procname = 'OSSL_CRMF_MSG_get0_tmpl';
  OSSL_CRMF_MSG_get0_tmpl_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_CERTTEMPLATE_get0_publicKey_procname = 'OSSL_CRMF_CERTTEMPLATE_get0_publicKey';
  OSSL_CRMF_CERTTEMPLATE_get0_publicKey_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  OSSL_CRMF_CERTTEMPLATE_get0_subject_procname = 'OSSL_CRMF_CERTTEMPLATE_get0_subject';
  OSSL_CRMF_CERTTEMPLATE_get0_subject_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_CERTTEMPLATE_get0_issuer_procname = 'OSSL_CRMF_CERTTEMPLATE_get0_issuer';
  OSSL_CRMF_CERTTEMPLATE_get0_issuer_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_CERTTEMPLATE_get0_serialNumber_procname = 'OSSL_CRMF_CERTTEMPLATE_get0_serialNumber';
  OSSL_CRMF_CERTTEMPLATE_get0_serialNumber_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_CERTTEMPLATE_get0_extensions_procname = 'OSSL_CRMF_CERTTEMPLATE_get0_extensions';
  OSSL_CRMF_CERTTEMPLATE_get0_extensions_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_CERTID_get0_issuer_procname = 'OSSL_CRMF_CERTID_get0_issuer';
  OSSL_CRMF_CERTID_get0_issuer_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_CERTID_get0_serialNumber_procname = 'OSSL_CRMF_CERTID_get0_serialNumber';
  OSSL_CRMF_CERTID_get0_serialNumber_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_CERTTEMPLATE_fill_procname = 'OSSL_CRMF_CERTTEMPLATE_fill';
  OSSL_CRMF_CERTTEMPLATE_fill_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert_procname = 'OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert';
  OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CRMF_ENCRYPTEDKEY_get1_encCert_procname = 'OSSL_CRMF_ENCRYPTEDKEY_get1_encCert';
  OSSL_CRMF_ENCRYPTEDKEY_get1_encCert_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_CRMF_ENCRYPTEDVALUE_decrypt_procname = 'OSSL_CRMF_ENCRYPTEDVALUE_decrypt';
  OSSL_CRMF_ENCRYPTEDVALUE_decrypt_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_CRMF_ENCRYPTEDKEY_get1_pkey_procname = 'OSSL_CRMF_ENCRYPTEDKEY_get1_pkey';
  OSSL_CRMF_ENCRYPTEDKEY_get1_pkey_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_CRMF_MSG_centralkeygen_requested_procname = 'OSSL_CRMF_MSG_centralkeygen_requested';
  OSSL_CRMF_MSG_centralkeygen_requested_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_CRMF_ENCRYPTEDKEY_init_envdata_procname = 'OSSL_CRMF_ENCRYPTEDKEY_init_envdata';
  OSSL_CRMF_ENCRYPTEDKEY_init_envdata_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_OSSL_CRMF_ENCRYPTEDVALUE_new: POSSL_CRMF_ENCRYPTEDVALUE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_ENCRYPTEDVALUE_new_procname);
end;

procedure ERR_OSSL_CRMF_ENCRYPTEDVALUE_free(a: POSSL_CRMF_ENCRYPTEDVALUE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_ENCRYPTEDVALUE_free_procname);
end;

function ERR_d2i_OSSL_CRMF_ENCRYPTEDVALUE(a: PPOSSL_CRMF_ENCRYPTEDVALUE; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_ENCRYPTEDVALUE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_CRMF_ENCRYPTEDVALUE_procname);
end;

function ERR_i2d_OSSL_CRMF_ENCRYPTEDVALUE(a: POSSL_CRMF_ENCRYPTEDVALUE; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_CRMF_ENCRYPTEDVALUE_procname);
end;

function ERR_OSSL_CRMF_ENCRYPTEDVALUE_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_ENCRYPTEDVALUE_it_procname);
end;

function ERR_OSSL_CRMF_ENCRYPTEDKEY_new: POSSL_CRMF_ENCRYPTEDKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_ENCRYPTEDKEY_new_procname);
end;

procedure ERR_OSSL_CRMF_ENCRYPTEDKEY_free(a: POSSL_CRMF_ENCRYPTEDKEY); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_ENCRYPTEDKEY_free_procname);
end;

function ERR_d2i_OSSL_CRMF_ENCRYPTEDKEY(a: PPOSSL_CRMF_ENCRYPTEDKEY; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_ENCRYPTEDKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_CRMF_ENCRYPTEDKEY_procname);
end;

function ERR_i2d_OSSL_CRMF_ENCRYPTEDKEY(a: POSSL_CRMF_ENCRYPTEDKEY; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_CRMF_ENCRYPTEDKEY_procname);
end;

function ERR_OSSL_CRMF_ENCRYPTEDKEY_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_ENCRYPTEDKEY_it_procname);
end;

function ERR_OSSL_CRMF_MSG_new: POSSL_CRMF_MSG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_new_procname);
end;

procedure ERR_OSSL_CRMF_MSG_free(a: POSSL_CRMF_MSG); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_free_procname);
end;

function ERR_d2i_OSSL_CRMF_MSG(a: PPOSSL_CRMF_MSG; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_MSG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_CRMF_MSG_procname);
end;

function ERR_i2d_OSSL_CRMF_MSG(a: POSSL_CRMF_MSG; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_CRMF_MSG_procname);
end;

function ERR_OSSL_CRMF_MSG_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_it_procname);
end;

function ERR_OSSL_CRMF_MSG_dup(a: POSSL_CRMF_MSG): POSSL_CRMF_MSG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_dup_procname);
end;

procedure ERR_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free(v: POSSL_CRMF_ATTRIBUTETYPEANDVALUE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free_procname);
end;

function ERR_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup(a: POSSL_CRMF_ATTRIBUTETYPEANDVALUE): POSSL_CRMF_ATTRIBUTETYPEANDVALUE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup_procname);
end;

function ERR_OSSL_CRMF_PBMPARAMETER_new: POSSL_CRMF_PBMPARAMETER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_PBMPARAMETER_new_procname);
end;

procedure ERR_OSSL_CRMF_PBMPARAMETER_free(a: POSSL_CRMF_PBMPARAMETER); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_PBMPARAMETER_free_procname);
end;

function ERR_d2i_OSSL_CRMF_PBMPARAMETER(a: PPOSSL_CRMF_PBMPARAMETER; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_PBMPARAMETER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_CRMF_PBMPARAMETER_procname);
end;

function ERR_i2d_OSSL_CRMF_PBMPARAMETER(a: POSSL_CRMF_PBMPARAMETER; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_CRMF_PBMPARAMETER_procname);
end;

function ERR_OSSL_CRMF_PBMPARAMETER_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_PBMPARAMETER_it_procname);
end;

function ERR_OSSL_CRMF_CERTID_new: POSSL_CRMF_CERTID; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_CERTID_new_procname);
end;

procedure ERR_OSSL_CRMF_CERTID_free(a: POSSL_CRMF_CERTID); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_CERTID_free_procname);
end;

function ERR_d2i_OSSL_CRMF_CERTID(a: PPOSSL_CRMF_CERTID; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_CERTID; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_CRMF_CERTID_procname);
end;

function ERR_i2d_OSSL_CRMF_CERTID(a: POSSL_CRMF_CERTID; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_CRMF_CERTID_procname);
end;

function ERR_OSSL_CRMF_CERTID_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_CERTID_it_procname);
end;

function ERR_OSSL_CRMF_CERTID_dup(a: POSSL_CRMF_CERTID): POSSL_CRMF_CERTID; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_CERTID_dup_procname);
end;

function ERR_OSSL_CRMF_PKIPUBLICATIONINFO_new: POSSL_CRMF_PKIPUBLICATIONINFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_PKIPUBLICATIONINFO_new_procname);
end;

procedure ERR_OSSL_CRMF_PKIPUBLICATIONINFO_free(a: POSSL_CRMF_PKIPUBLICATIONINFO); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_PKIPUBLICATIONINFO_free_procname);
end;

function ERR_d2i_OSSL_CRMF_PKIPUBLICATIONINFO(a: PPOSSL_CRMF_PKIPUBLICATIONINFO; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_PKIPUBLICATIONINFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_CRMF_PKIPUBLICATIONINFO_procname);
end;

function ERR_i2d_OSSL_CRMF_PKIPUBLICATIONINFO(a: POSSL_CRMF_PKIPUBLICATIONINFO; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_CRMF_PKIPUBLICATIONINFO_procname);
end;

function ERR_OSSL_CRMF_PKIPUBLICATIONINFO_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_PKIPUBLICATIONINFO_it_procname);
end;

function ERR_OSSL_CRMF_SINGLEPUBINFO_new: POSSL_CRMF_SINGLEPUBINFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_SINGLEPUBINFO_new_procname);
end;

procedure ERR_OSSL_CRMF_SINGLEPUBINFO_free(a: POSSL_CRMF_SINGLEPUBINFO); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_SINGLEPUBINFO_free_procname);
end;

function ERR_d2i_OSSL_CRMF_SINGLEPUBINFO(a: PPOSSL_CRMF_SINGLEPUBINFO; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_SINGLEPUBINFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_CRMF_SINGLEPUBINFO_procname);
end;

function ERR_i2d_OSSL_CRMF_SINGLEPUBINFO(a: POSSL_CRMF_SINGLEPUBINFO; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_CRMF_SINGLEPUBINFO_procname);
end;

function ERR_OSSL_CRMF_SINGLEPUBINFO_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_SINGLEPUBINFO_it_procname);
end;

function ERR_OSSL_CRMF_CERTTEMPLATE_new: POSSL_CRMF_CERTTEMPLATE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_CERTTEMPLATE_new_procname);
end;

procedure ERR_OSSL_CRMF_CERTTEMPLATE_free(a: POSSL_CRMF_CERTTEMPLATE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_CERTTEMPLATE_free_procname);
end;

function ERR_d2i_OSSL_CRMF_CERTTEMPLATE(a: PPOSSL_CRMF_CERTTEMPLATE; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_CERTTEMPLATE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_CRMF_CERTTEMPLATE_procname);
end;

function ERR_i2d_OSSL_CRMF_CERTTEMPLATE(a: POSSL_CRMF_CERTTEMPLATE; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_CRMF_CERTTEMPLATE_procname);
end;

function ERR_OSSL_CRMF_CERTTEMPLATE_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_CERTTEMPLATE_it_procname);
end;

function ERR_OSSL_CRMF_CERTTEMPLATE_dup(a: POSSL_CRMF_CERTTEMPLATE): POSSL_CRMF_CERTTEMPLATE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_CERTTEMPLATE_dup_procname);
end;

function ERR_OSSL_CRMF_MSGS_new: POSSL_CRMF_MSGS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSGS_new_procname);
end;

procedure ERR_OSSL_CRMF_MSGS_free(a: POSSL_CRMF_MSGS); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSGS_free_procname);
end;

function ERR_d2i_OSSL_CRMF_MSGS(a: PPOSSL_CRMF_MSGS; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CRMF_MSGS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_CRMF_MSGS_procname);
end;

function ERR_i2d_OSSL_CRMF_MSGS(a: POSSL_CRMF_MSGS; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_CRMF_MSGS_procname);
end;

function ERR_OSSL_CRMF_MSGS_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSGS_it_procname);
end;

function ERR_OSSL_CRMF_pbmp_new(libctx: POSSL_LIB_CTX; slen: TIdC_SIZET; owfnid: TIdC_INT; itercnt: TIdC_SIZET; macnid: TIdC_INT): POSSL_CRMF_PBMPARAMETER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_pbmp_new_procname);
end;

function ERR_OSSL_CRMF_pbm_new(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; pbmp: POSSL_CRMF_PBMPARAMETER; msg: PIdAnsiChar; msglen: TIdC_SIZET; sec: PIdAnsiChar; seclen: TIdC_SIZET; mac: PPIdAnsiChar; maclen: PIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_pbm_new_procname);
end;

function ERR_OSSL_CRMF_MSG_set1_regCtrl_regToken(msg: POSSL_CRMF_MSG; tok: PASN1_UTF8STRING): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_set1_regCtrl_regToken_procname);
end;

function ERR_OSSL_CRMF_MSG_get0_regCtrl_regToken(msg: POSSL_CRMF_MSG): PASN1_UTF8STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_get0_regCtrl_regToken_procname);
end;

function ERR_OSSL_CRMF_MSG_set1_regCtrl_authenticator(msg: POSSL_CRMF_MSG; auth: PASN1_UTF8STRING): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_set1_regCtrl_authenticator_procname);
end;

function ERR_OSSL_CRMF_MSG_get0_regCtrl_authenticator(msg: POSSL_CRMF_MSG): PASN1_UTF8STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_get0_regCtrl_authenticator_procname);
end;

function ERR_OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo(pi: POSSL_CRMF_PKIPUBLICATIONINFO; spi: POSSL_CRMF_SINGLEPUBINFO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo_procname);
end;

function ERR_OSSL_CRMF_MSG_set0_SinglePubInfo(spi: POSSL_CRMF_SINGLEPUBINFO; method: TIdC_INT; nm: PGENERAL_NAME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_set0_SinglePubInfo_procname);
end;

function ERR_OSSL_CRMF_MSG_set_PKIPublicationInfo_action(pi: POSSL_CRMF_PKIPUBLICATIONINFO; action: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_set_PKIPublicationInfo_action_procname);
end;

function ERR_OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo(msg: POSSL_CRMF_MSG; pi: POSSL_CRMF_PKIPUBLICATIONINFO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo_procname);
end;

function ERR_OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo(msg: POSSL_CRMF_MSG): POSSL_CRMF_PKIPUBLICATIONINFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo_procname);
end;

function ERR_OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey(msg: POSSL_CRMF_MSG; pubkey: PX509_PUBKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey_procname);
end;

function ERR_OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey(msg: POSSL_CRMF_MSG): PX509_PUBKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey_procname);
end;

function ERR_OSSL_CRMF_MSG_set1_regCtrl_oldCertID(msg: POSSL_CRMF_MSG; cid: POSSL_CRMF_CERTID): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_set1_regCtrl_oldCertID_procname);
end;

function ERR_OSSL_CRMF_MSG_get0_regCtrl_oldCertID(msg: POSSL_CRMF_MSG): POSSL_CRMF_CERTID; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_get0_regCtrl_oldCertID_procname);
end;

function ERR_OSSL_CRMF_CERTID_gen(issuer: PX509_NAME; serial: PASN1_INTEGER): POSSL_CRMF_CERTID; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_CERTID_gen_procname);
end;

function ERR_OSSL_CRMF_MSG_set1_regInfo_utf8Pairs(msg: POSSL_CRMF_MSG; utf8pairs: PASN1_UTF8STRING): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_set1_regInfo_utf8Pairs_procname);
end;

function ERR_OSSL_CRMF_MSG_get0_regInfo_utf8Pairs(msg: POSSL_CRMF_MSG): PASN1_UTF8STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_get0_regInfo_utf8Pairs_procname);
end;

function ERR_OSSL_CRMF_MSG_set1_regInfo_certReq(msg: POSSL_CRMF_MSG; cr: POSSL_CRMF_CERTREQUEST): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_set1_regInfo_certReq_procname);
end;

function ERR_OSSL_CRMF_MSG_get0_regInfo_certReq(msg: POSSL_CRMF_MSG): POSSL_CRMF_CERTREQUEST; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_get0_regInfo_certReq_procname);
end;

function ERR_OSSL_CRMF_MSG_set0_validity(crm: POSSL_CRMF_MSG; notBefore: PASN1_TIME; notAfter: PASN1_TIME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_set0_validity_procname);
end;

function ERR_OSSL_CRMF_MSG_set_certReqId(crm: POSSL_CRMF_MSG; rid: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_set_certReqId_procname);
end;

function ERR_OSSL_CRMF_MSG_get_certReqId(crm: POSSL_CRMF_MSG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_get_certReqId_procname);
end;

function ERR_OSSL_CRMF_MSG_set0_extensions(crm: POSSL_CRMF_MSG; exts: PX509_EXTENSIONS): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_set0_extensions_procname);
end;

function ERR_OSSL_CRMF_MSG_push0_extension(crm: POSSL_CRMF_MSG; ext: PX509_EXTENSION): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_push0_extension_procname);
end;

function ERR_OSSL_CRMF_MSG_create_popo(meth: TIdC_INT; crm: POSSL_CRMF_MSG; pkey: PEVP_PKEY; digest: PEVP_MD; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_create_popo_procname);
end;

function ERR_OSSL_CRMF_MSGS_verify_popo(reqs: POSSL_CRMF_MSGS; rid: TIdC_INT; acceptRAVerified: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSGS_verify_popo_procname);
end;

function ERR_OSSL_CRMF_MSG_get0_tmpl(crm: POSSL_CRMF_MSG): POSSL_CRMF_CERTTEMPLATE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_get0_tmpl_procname);
end;

function ERR_OSSL_CRMF_CERTTEMPLATE_get0_publicKey(tmpl: POSSL_CRMF_CERTTEMPLATE): PX509_PUBKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_CERTTEMPLATE_get0_publicKey_procname);
end;

function ERR_OSSL_CRMF_CERTTEMPLATE_get0_subject(tmpl: POSSL_CRMF_CERTTEMPLATE): PX509_NAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_CERTTEMPLATE_get0_subject_procname);
end;

function ERR_OSSL_CRMF_CERTTEMPLATE_get0_issuer(tmpl: POSSL_CRMF_CERTTEMPLATE): PX509_NAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_CERTTEMPLATE_get0_issuer_procname);
end;

function ERR_OSSL_CRMF_CERTTEMPLATE_get0_serialNumber(tmpl: POSSL_CRMF_CERTTEMPLATE): PASN1_INTEGER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_CERTTEMPLATE_get0_serialNumber_procname);
end;

function ERR_OSSL_CRMF_CERTTEMPLATE_get0_extensions(tmpl: POSSL_CRMF_CERTTEMPLATE): PX509_EXTENSIONS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_CERTTEMPLATE_get0_extensions_procname);
end;

function ERR_OSSL_CRMF_CERTID_get0_issuer(cid: POSSL_CRMF_CERTID): PX509_NAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_CERTID_get0_issuer_procname);
end;

function ERR_OSSL_CRMF_CERTID_get0_serialNumber(cid: POSSL_CRMF_CERTID): PASN1_INTEGER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_CERTID_get0_serialNumber_procname);
end;

function ERR_OSSL_CRMF_CERTTEMPLATE_fill(tmpl: POSSL_CRMF_CERTTEMPLATE; pubkey: PEVP_PKEY; subject: PX509_NAME; issuer: PX509_NAME; serial: PASN1_INTEGER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_CERTTEMPLATE_fill_procname);
end;

function ERR_OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert(ecert: POSSL_CRMF_ENCRYPTEDVALUE; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; pkey: PEVP_PKEY): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert_procname);
end;

function ERR_OSSL_CRMF_ENCRYPTEDKEY_get1_encCert(ecert: POSSL_CRMF_ENCRYPTEDKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; pkey: PEVP_PKEY; flags: TIdC_UINT): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_ENCRYPTEDKEY_get1_encCert_procname);
end;

function ERR_OSSL_CRMF_ENCRYPTEDVALUE_decrypt(enc: POSSL_CRMF_ENCRYPTEDVALUE; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; pkey: PEVP_PKEY; outlen: PIdC_INT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_ENCRYPTEDVALUE_decrypt_procname);
end;

function ERR_OSSL_CRMF_ENCRYPTEDKEY_get1_pkey(encryptedKey: POSSL_CRMF_ENCRYPTEDKEY; ts: PX509_STORE; extra: Pstack_st_X509; pkey: PEVP_PKEY; cert: PX509; secret: PASN1_OCTET_STRING; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_ENCRYPTEDKEY_get1_pkey_procname);
end;

function ERR_OSSL_CRMF_MSG_centralkeygen_requested(crm: POSSL_CRMF_MSG; p10cr: PX509_REQ): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_MSG_centralkeygen_requested_procname);
end;

function ERR_OSSL_CRMF_ENCRYPTEDKEY_init_envdata(envdata: PCMS_EnvelopedData): POSSL_CRMF_ENCRYPTEDKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CRMF_ENCRYPTEDKEY_init_envdata_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  OSSL_CRMF_ENCRYPTEDVALUE_new := LoadLibFunction(ADllHandle, OSSL_CRMF_ENCRYPTEDVALUE_new_procname);
  FuncLoadError := not assigned(OSSL_CRMF_ENCRYPTEDVALUE_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_ENCRYPTEDVALUE_new_allownil)}
    OSSL_CRMF_ENCRYPTEDVALUE_new := ERR_OSSL_CRMF_ENCRYPTEDVALUE_new;
    {$ifend}
    {$if declared(OSSL_CRMF_ENCRYPTEDVALUE_new_introduced)}
    if LibVersion < OSSL_CRMF_ENCRYPTEDVALUE_new_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_ENCRYPTEDVALUE_new)}
      OSSL_CRMF_ENCRYPTEDVALUE_new := FC_OSSL_CRMF_ENCRYPTEDVALUE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_ENCRYPTEDVALUE_new_removed)}
    if OSSL_CRMF_ENCRYPTEDVALUE_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_ENCRYPTEDVALUE_new)}
      OSSL_CRMF_ENCRYPTEDVALUE_new := _OSSL_CRMF_ENCRYPTEDVALUE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_ENCRYPTEDVALUE_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_ENCRYPTEDVALUE_new');
    {$ifend}
  end;
  
  OSSL_CRMF_ENCRYPTEDVALUE_free := LoadLibFunction(ADllHandle, OSSL_CRMF_ENCRYPTEDVALUE_free_procname);
  FuncLoadError := not assigned(OSSL_CRMF_ENCRYPTEDVALUE_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_ENCRYPTEDVALUE_free_allownil)}
    OSSL_CRMF_ENCRYPTEDVALUE_free := ERR_OSSL_CRMF_ENCRYPTEDVALUE_free;
    {$ifend}
    {$if declared(OSSL_CRMF_ENCRYPTEDVALUE_free_introduced)}
    if LibVersion < OSSL_CRMF_ENCRYPTEDVALUE_free_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_ENCRYPTEDVALUE_free)}
      OSSL_CRMF_ENCRYPTEDVALUE_free := FC_OSSL_CRMF_ENCRYPTEDVALUE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_ENCRYPTEDVALUE_free_removed)}
    if OSSL_CRMF_ENCRYPTEDVALUE_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_ENCRYPTEDVALUE_free)}
      OSSL_CRMF_ENCRYPTEDVALUE_free := _OSSL_CRMF_ENCRYPTEDVALUE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_ENCRYPTEDVALUE_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_ENCRYPTEDVALUE_free');
    {$ifend}
  end;
  
  d2i_OSSL_CRMF_ENCRYPTEDVALUE := LoadLibFunction(ADllHandle, d2i_OSSL_CRMF_ENCRYPTEDVALUE_procname);
  FuncLoadError := not assigned(d2i_OSSL_CRMF_ENCRYPTEDVALUE);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_CRMF_ENCRYPTEDVALUE_allownil)}
    d2i_OSSL_CRMF_ENCRYPTEDVALUE := ERR_d2i_OSSL_CRMF_ENCRYPTEDVALUE;
    {$ifend}
    {$if declared(d2i_OSSL_CRMF_ENCRYPTEDVALUE_introduced)}
    if LibVersion < d2i_OSSL_CRMF_ENCRYPTEDVALUE_introduced then
    begin
      {$if declared(FC_d2i_OSSL_CRMF_ENCRYPTEDVALUE)}
      d2i_OSSL_CRMF_ENCRYPTEDVALUE := FC_d2i_OSSL_CRMF_ENCRYPTEDVALUE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_CRMF_ENCRYPTEDVALUE_removed)}
    if d2i_OSSL_CRMF_ENCRYPTEDVALUE_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_CRMF_ENCRYPTEDVALUE)}
      d2i_OSSL_CRMF_ENCRYPTEDVALUE := _d2i_OSSL_CRMF_ENCRYPTEDVALUE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_CRMF_ENCRYPTEDVALUE_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_CRMF_ENCRYPTEDVALUE');
    {$ifend}
  end;
  
  i2d_OSSL_CRMF_ENCRYPTEDVALUE := LoadLibFunction(ADllHandle, i2d_OSSL_CRMF_ENCRYPTEDVALUE_procname);
  FuncLoadError := not assigned(i2d_OSSL_CRMF_ENCRYPTEDVALUE);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_CRMF_ENCRYPTEDVALUE_allownil)}
    i2d_OSSL_CRMF_ENCRYPTEDVALUE := ERR_i2d_OSSL_CRMF_ENCRYPTEDVALUE;
    {$ifend}
    {$if declared(i2d_OSSL_CRMF_ENCRYPTEDVALUE_introduced)}
    if LibVersion < i2d_OSSL_CRMF_ENCRYPTEDVALUE_introduced then
    begin
      {$if declared(FC_i2d_OSSL_CRMF_ENCRYPTEDVALUE)}
      i2d_OSSL_CRMF_ENCRYPTEDVALUE := FC_i2d_OSSL_CRMF_ENCRYPTEDVALUE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_CRMF_ENCRYPTEDVALUE_removed)}
    if i2d_OSSL_CRMF_ENCRYPTEDVALUE_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_CRMF_ENCRYPTEDVALUE)}
      i2d_OSSL_CRMF_ENCRYPTEDVALUE := _i2d_OSSL_CRMF_ENCRYPTEDVALUE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_CRMF_ENCRYPTEDVALUE_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_CRMF_ENCRYPTEDVALUE');
    {$ifend}
  end;
  
  OSSL_CRMF_ENCRYPTEDVALUE_it := LoadLibFunction(ADllHandle, OSSL_CRMF_ENCRYPTEDVALUE_it_procname);
  FuncLoadError := not assigned(OSSL_CRMF_ENCRYPTEDVALUE_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_ENCRYPTEDVALUE_it_allownil)}
    OSSL_CRMF_ENCRYPTEDVALUE_it := ERR_OSSL_CRMF_ENCRYPTEDVALUE_it;
    {$ifend}
    {$if declared(OSSL_CRMF_ENCRYPTEDVALUE_it_introduced)}
    if LibVersion < OSSL_CRMF_ENCRYPTEDVALUE_it_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_ENCRYPTEDVALUE_it)}
      OSSL_CRMF_ENCRYPTEDVALUE_it := FC_OSSL_CRMF_ENCRYPTEDVALUE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_ENCRYPTEDVALUE_it_removed)}
    if OSSL_CRMF_ENCRYPTEDVALUE_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_ENCRYPTEDVALUE_it)}
      OSSL_CRMF_ENCRYPTEDVALUE_it := _OSSL_CRMF_ENCRYPTEDVALUE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_ENCRYPTEDVALUE_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_ENCRYPTEDVALUE_it');
    {$ifend}
  end;
  
  OSSL_CRMF_ENCRYPTEDKEY_new := LoadLibFunction(ADllHandle, OSSL_CRMF_ENCRYPTEDKEY_new_procname);
  FuncLoadError := not assigned(OSSL_CRMF_ENCRYPTEDKEY_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_ENCRYPTEDKEY_new_allownil)}
    OSSL_CRMF_ENCRYPTEDKEY_new := ERR_OSSL_CRMF_ENCRYPTEDKEY_new;
    {$ifend}
    {$if declared(OSSL_CRMF_ENCRYPTEDKEY_new_introduced)}
    if LibVersion < OSSL_CRMF_ENCRYPTEDKEY_new_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_ENCRYPTEDKEY_new)}
      OSSL_CRMF_ENCRYPTEDKEY_new := FC_OSSL_CRMF_ENCRYPTEDKEY_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_ENCRYPTEDKEY_new_removed)}
    if OSSL_CRMF_ENCRYPTEDKEY_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_ENCRYPTEDKEY_new)}
      OSSL_CRMF_ENCRYPTEDKEY_new := _OSSL_CRMF_ENCRYPTEDKEY_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_ENCRYPTEDKEY_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_ENCRYPTEDKEY_new');
    {$ifend}
  end;
  
  OSSL_CRMF_ENCRYPTEDKEY_free := LoadLibFunction(ADllHandle, OSSL_CRMF_ENCRYPTEDKEY_free_procname);
  FuncLoadError := not assigned(OSSL_CRMF_ENCRYPTEDKEY_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_ENCRYPTEDKEY_free_allownil)}
    OSSL_CRMF_ENCRYPTEDKEY_free := ERR_OSSL_CRMF_ENCRYPTEDKEY_free;
    {$ifend}
    {$if declared(OSSL_CRMF_ENCRYPTEDKEY_free_introduced)}
    if LibVersion < OSSL_CRMF_ENCRYPTEDKEY_free_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_ENCRYPTEDKEY_free)}
      OSSL_CRMF_ENCRYPTEDKEY_free := FC_OSSL_CRMF_ENCRYPTEDKEY_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_ENCRYPTEDKEY_free_removed)}
    if OSSL_CRMF_ENCRYPTEDKEY_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_ENCRYPTEDKEY_free)}
      OSSL_CRMF_ENCRYPTEDKEY_free := _OSSL_CRMF_ENCRYPTEDKEY_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_ENCRYPTEDKEY_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_ENCRYPTEDKEY_free');
    {$ifend}
  end;
  
  d2i_OSSL_CRMF_ENCRYPTEDKEY := LoadLibFunction(ADllHandle, d2i_OSSL_CRMF_ENCRYPTEDKEY_procname);
  FuncLoadError := not assigned(d2i_OSSL_CRMF_ENCRYPTEDKEY);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_CRMF_ENCRYPTEDKEY_allownil)}
    d2i_OSSL_CRMF_ENCRYPTEDKEY := ERR_d2i_OSSL_CRMF_ENCRYPTEDKEY;
    {$ifend}
    {$if declared(d2i_OSSL_CRMF_ENCRYPTEDKEY_introduced)}
    if LibVersion < d2i_OSSL_CRMF_ENCRYPTEDKEY_introduced then
    begin
      {$if declared(FC_d2i_OSSL_CRMF_ENCRYPTEDKEY)}
      d2i_OSSL_CRMF_ENCRYPTEDKEY := FC_d2i_OSSL_CRMF_ENCRYPTEDKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_CRMF_ENCRYPTEDKEY_removed)}
    if d2i_OSSL_CRMF_ENCRYPTEDKEY_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_CRMF_ENCRYPTEDKEY)}
      d2i_OSSL_CRMF_ENCRYPTEDKEY := _d2i_OSSL_CRMF_ENCRYPTEDKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_CRMF_ENCRYPTEDKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_CRMF_ENCRYPTEDKEY');
    {$ifend}
  end;
  
  i2d_OSSL_CRMF_ENCRYPTEDKEY := LoadLibFunction(ADllHandle, i2d_OSSL_CRMF_ENCRYPTEDKEY_procname);
  FuncLoadError := not assigned(i2d_OSSL_CRMF_ENCRYPTEDKEY);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_CRMF_ENCRYPTEDKEY_allownil)}
    i2d_OSSL_CRMF_ENCRYPTEDKEY := ERR_i2d_OSSL_CRMF_ENCRYPTEDKEY;
    {$ifend}
    {$if declared(i2d_OSSL_CRMF_ENCRYPTEDKEY_introduced)}
    if LibVersion < i2d_OSSL_CRMF_ENCRYPTEDKEY_introduced then
    begin
      {$if declared(FC_i2d_OSSL_CRMF_ENCRYPTEDKEY)}
      i2d_OSSL_CRMF_ENCRYPTEDKEY := FC_i2d_OSSL_CRMF_ENCRYPTEDKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_CRMF_ENCRYPTEDKEY_removed)}
    if i2d_OSSL_CRMF_ENCRYPTEDKEY_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_CRMF_ENCRYPTEDKEY)}
      i2d_OSSL_CRMF_ENCRYPTEDKEY := _i2d_OSSL_CRMF_ENCRYPTEDKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_CRMF_ENCRYPTEDKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_CRMF_ENCRYPTEDKEY');
    {$ifend}
  end;
  
  OSSL_CRMF_ENCRYPTEDKEY_it := LoadLibFunction(ADllHandle, OSSL_CRMF_ENCRYPTEDKEY_it_procname);
  FuncLoadError := not assigned(OSSL_CRMF_ENCRYPTEDKEY_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_ENCRYPTEDKEY_it_allownil)}
    OSSL_CRMF_ENCRYPTEDKEY_it := ERR_OSSL_CRMF_ENCRYPTEDKEY_it;
    {$ifend}
    {$if declared(OSSL_CRMF_ENCRYPTEDKEY_it_introduced)}
    if LibVersion < OSSL_CRMF_ENCRYPTEDKEY_it_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_ENCRYPTEDKEY_it)}
      OSSL_CRMF_ENCRYPTEDKEY_it := FC_OSSL_CRMF_ENCRYPTEDKEY_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_ENCRYPTEDKEY_it_removed)}
    if OSSL_CRMF_ENCRYPTEDKEY_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_ENCRYPTEDKEY_it)}
      OSSL_CRMF_ENCRYPTEDKEY_it := _OSSL_CRMF_ENCRYPTEDKEY_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_ENCRYPTEDKEY_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_ENCRYPTEDKEY_it');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_new := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_new_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_new_allownil)}
    OSSL_CRMF_MSG_new := ERR_OSSL_CRMF_MSG_new;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_new_introduced)}
    if LibVersion < OSSL_CRMF_MSG_new_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_new)}
      OSSL_CRMF_MSG_new := FC_OSSL_CRMF_MSG_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_new_removed)}
    if OSSL_CRMF_MSG_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_new)}
      OSSL_CRMF_MSG_new := _OSSL_CRMF_MSG_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_new');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_free := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_free_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_free_allownil)}
    OSSL_CRMF_MSG_free := ERR_OSSL_CRMF_MSG_free;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_free_introduced)}
    if LibVersion < OSSL_CRMF_MSG_free_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_free)}
      OSSL_CRMF_MSG_free := FC_OSSL_CRMF_MSG_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_free_removed)}
    if OSSL_CRMF_MSG_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_free)}
      OSSL_CRMF_MSG_free := _OSSL_CRMF_MSG_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_free');
    {$ifend}
  end;
  
  d2i_OSSL_CRMF_MSG := LoadLibFunction(ADllHandle, d2i_OSSL_CRMF_MSG_procname);
  FuncLoadError := not assigned(d2i_OSSL_CRMF_MSG);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_CRMF_MSG_allownil)}
    d2i_OSSL_CRMF_MSG := ERR_d2i_OSSL_CRMF_MSG;
    {$ifend}
    {$if declared(d2i_OSSL_CRMF_MSG_introduced)}
    if LibVersion < d2i_OSSL_CRMF_MSG_introduced then
    begin
      {$if declared(FC_d2i_OSSL_CRMF_MSG)}
      d2i_OSSL_CRMF_MSG := FC_d2i_OSSL_CRMF_MSG;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_CRMF_MSG_removed)}
    if d2i_OSSL_CRMF_MSG_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_CRMF_MSG)}
      d2i_OSSL_CRMF_MSG := _d2i_OSSL_CRMF_MSG;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_CRMF_MSG_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_CRMF_MSG');
    {$ifend}
  end;
  
  i2d_OSSL_CRMF_MSG := LoadLibFunction(ADllHandle, i2d_OSSL_CRMF_MSG_procname);
  FuncLoadError := not assigned(i2d_OSSL_CRMF_MSG);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_CRMF_MSG_allownil)}
    i2d_OSSL_CRMF_MSG := ERR_i2d_OSSL_CRMF_MSG;
    {$ifend}
    {$if declared(i2d_OSSL_CRMF_MSG_introduced)}
    if LibVersion < i2d_OSSL_CRMF_MSG_introduced then
    begin
      {$if declared(FC_i2d_OSSL_CRMF_MSG)}
      i2d_OSSL_CRMF_MSG := FC_i2d_OSSL_CRMF_MSG;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_CRMF_MSG_removed)}
    if i2d_OSSL_CRMF_MSG_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_CRMF_MSG)}
      i2d_OSSL_CRMF_MSG := _i2d_OSSL_CRMF_MSG;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_CRMF_MSG_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_CRMF_MSG');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_it := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_it_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_it_allownil)}
    OSSL_CRMF_MSG_it := ERR_OSSL_CRMF_MSG_it;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_it_introduced)}
    if LibVersion < OSSL_CRMF_MSG_it_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_it)}
      OSSL_CRMF_MSG_it := FC_OSSL_CRMF_MSG_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_it_removed)}
    if OSSL_CRMF_MSG_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_it)}
      OSSL_CRMF_MSG_it := _OSSL_CRMF_MSG_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_it');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_dup := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_dup_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_dup);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_dup_allownil)}
    OSSL_CRMF_MSG_dup := ERR_OSSL_CRMF_MSG_dup;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_dup_introduced)}
    if LibVersion < OSSL_CRMF_MSG_dup_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_dup)}
      OSSL_CRMF_MSG_dup := FC_OSSL_CRMF_MSG_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_dup_removed)}
    if OSSL_CRMF_MSG_dup_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_dup)}
      OSSL_CRMF_MSG_dup := _OSSL_CRMF_MSG_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_dup');
    {$ifend}
  end;
  
  OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free := LoadLibFunction(ADllHandle, OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free_procname);
  FuncLoadError := not assigned(OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free_allownil)}
    OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free := ERR_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free;
    {$ifend}
    {$if declared(OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free_introduced)}
    if LibVersion < OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free)}
      OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free := FC_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free_removed)}
    if OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free)}
      OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free := _OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free');
    {$ifend}
  end;
  
  OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup := LoadLibFunction(ADllHandle, OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup_procname);
  FuncLoadError := not assigned(OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup_allownil)}
    OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup := ERR_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup;
    {$ifend}
    {$if declared(OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup_introduced)}
    if LibVersion < OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup)}
      OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup := FC_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup_removed)}
    if OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup)}
      OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup := _OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup');
    {$ifend}
  end;
  
  OSSL_CRMF_PBMPARAMETER_new := LoadLibFunction(ADllHandle, OSSL_CRMF_PBMPARAMETER_new_procname);
  FuncLoadError := not assigned(OSSL_CRMF_PBMPARAMETER_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_PBMPARAMETER_new_allownil)}
    OSSL_CRMF_PBMPARAMETER_new := ERR_OSSL_CRMF_PBMPARAMETER_new;
    {$ifend}
    {$if declared(OSSL_CRMF_PBMPARAMETER_new_introduced)}
    if LibVersion < OSSL_CRMF_PBMPARAMETER_new_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_PBMPARAMETER_new)}
      OSSL_CRMF_PBMPARAMETER_new := FC_OSSL_CRMF_PBMPARAMETER_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_PBMPARAMETER_new_removed)}
    if OSSL_CRMF_PBMPARAMETER_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_PBMPARAMETER_new)}
      OSSL_CRMF_PBMPARAMETER_new := _OSSL_CRMF_PBMPARAMETER_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_PBMPARAMETER_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_PBMPARAMETER_new');
    {$ifend}
  end;
  
  OSSL_CRMF_PBMPARAMETER_free := LoadLibFunction(ADllHandle, OSSL_CRMF_PBMPARAMETER_free_procname);
  FuncLoadError := not assigned(OSSL_CRMF_PBMPARAMETER_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_PBMPARAMETER_free_allownil)}
    OSSL_CRMF_PBMPARAMETER_free := ERR_OSSL_CRMF_PBMPARAMETER_free;
    {$ifend}
    {$if declared(OSSL_CRMF_PBMPARAMETER_free_introduced)}
    if LibVersion < OSSL_CRMF_PBMPARAMETER_free_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_PBMPARAMETER_free)}
      OSSL_CRMF_PBMPARAMETER_free := FC_OSSL_CRMF_PBMPARAMETER_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_PBMPARAMETER_free_removed)}
    if OSSL_CRMF_PBMPARAMETER_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_PBMPARAMETER_free)}
      OSSL_CRMF_PBMPARAMETER_free := _OSSL_CRMF_PBMPARAMETER_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_PBMPARAMETER_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_PBMPARAMETER_free');
    {$ifend}
  end;
  
  d2i_OSSL_CRMF_PBMPARAMETER := LoadLibFunction(ADllHandle, d2i_OSSL_CRMF_PBMPARAMETER_procname);
  FuncLoadError := not assigned(d2i_OSSL_CRMF_PBMPARAMETER);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_CRMF_PBMPARAMETER_allownil)}
    d2i_OSSL_CRMF_PBMPARAMETER := ERR_d2i_OSSL_CRMF_PBMPARAMETER;
    {$ifend}
    {$if declared(d2i_OSSL_CRMF_PBMPARAMETER_introduced)}
    if LibVersion < d2i_OSSL_CRMF_PBMPARAMETER_introduced then
    begin
      {$if declared(FC_d2i_OSSL_CRMF_PBMPARAMETER)}
      d2i_OSSL_CRMF_PBMPARAMETER := FC_d2i_OSSL_CRMF_PBMPARAMETER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_CRMF_PBMPARAMETER_removed)}
    if d2i_OSSL_CRMF_PBMPARAMETER_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_CRMF_PBMPARAMETER)}
      d2i_OSSL_CRMF_PBMPARAMETER := _d2i_OSSL_CRMF_PBMPARAMETER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_CRMF_PBMPARAMETER_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_CRMF_PBMPARAMETER');
    {$ifend}
  end;
  
  i2d_OSSL_CRMF_PBMPARAMETER := LoadLibFunction(ADllHandle, i2d_OSSL_CRMF_PBMPARAMETER_procname);
  FuncLoadError := not assigned(i2d_OSSL_CRMF_PBMPARAMETER);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_CRMF_PBMPARAMETER_allownil)}
    i2d_OSSL_CRMF_PBMPARAMETER := ERR_i2d_OSSL_CRMF_PBMPARAMETER;
    {$ifend}
    {$if declared(i2d_OSSL_CRMF_PBMPARAMETER_introduced)}
    if LibVersion < i2d_OSSL_CRMF_PBMPARAMETER_introduced then
    begin
      {$if declared(FC_i2d_OSSL_CRMF_PBMPARAMETER)}
      i2d_OSSL_CRMF_PBMPARAMETER := FC_i2d_OSSL_CRMF_PBMPARAMETER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_CRMF_PBMPARAMETER_removed)}
    if i2d_OSSL_CRMF_PBMPARAMETER_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_CRMF_PBMPARAMETER)}
      i2d_OSSL_CRMF_PBMPARAMETER := _i2d_OSSL_CRMF_PBMPARAMETER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_CRMF_PBMPARAMETER_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_CRMF_PBMPARAMETER');
    {$ifend}
  end;
  
  OSSL_CRMF_PBMPARAMETER_it := LoadLibFunction(ADllHandle, OSSL_CRMF_PBMPARAMETER_it_procname);
  FuncLoadError := not assigned(OSSL_CRMF_PBMPARAMETER_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_PBMPARAMETER_it_allownil)}
    OSSL_CRMF_PBMPARAMETER_it := ERR_OSSL_CRMF_PBMPARAMETER_it;
    {$ifend}
    {$if declared(OSSL_CRMF_PBMPARAMETER_it_introduced)}
    if LibVersion < OSSL_CRMF_PBMPARAMETER_it_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_PBMPARAMETER_it)}
      OSSL_CRMF_PBMPARAMETER_it := FC_OSSL_CRMF_PBMPARAMETER_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_PBMPARAMETER_it_removed)}
    if OSSL_CRMF_PBMPARAMETER_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_PBMPARAMETER_it)}
      OSSL_CRMF_PBMPARAMETER_it := _OSSL_CRMF_PBMPARAMETER_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_PBMPARAMETER_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_PBMPARAMETER_it');
    {$ifend}
  end;
  
  OSSL_CRMF_CERTID_new := LoadLibFunction(ADllHandle, OSSL_CRMF_CERTID_new_procname);
  FuncLoadError := not assigned(OSSL_CRMF_CERTID_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_CERTID_new_allownil)}
    OSSL_CRMF_CERTID_new := ERR_OSSL_CRMF_CERTID_new;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTID_new_introduced)}
    if LibVersion < OSSL_CRMF_CERTID_new_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_CERTID_new)}
      OSSL_CRMF_CERTID_new := FC_OSSL_CRMF_CERTID_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTID_new_removed)}
    if OSSL_CRMF_CERTID_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_CERTID_new)}
      OSSL_CRMF_CERTID_new := _OSSL_CRMF_CERTID_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_CERTID_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_CERTID_new');
    {$ifend}
  end;
  
  OSSL_CRMF_CERTID_free := LoadLibFunction(ADllHandle, OSSL_CRMF_CERTID_free_procname);
  FuncLoadError := not assigned(OSSL_CRMF_CERTID_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_CERTID_free_allownil)}
    OSSL_CRMF_CERTID_free := ERR_OSSL_CRMF_CERTID_free;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTID_free_introduced)}
    if LibVersion < OSSL_CRMF_CERTID_free_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_CERTID_free)}
      OSSL_CRMF_CERTID_free := FC_OSSL_CRMF_CERTID_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTID_free_removed)}
    if OSSL_CRMF_CERTID_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_CERTID_free)}
      OSSL_CRMF_CERTID_free := _OSSL_CRMF_CERTID_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_CERTID_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_CERTID_free');
    {$ifend}
  end;
  
  d2i_OSSL_CRMF_CERTID := LoadLibFunction(ADllHandle, d2i_OSSL_CRMF_CERTID_procname);
  FuncLoadError := not assigned(d2i_OSSL_CRMF_CERTID);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_CRMF_CERTID_allownil)}
    d2i_OSSL_CRMF_CERTID := ERR_d2i_OSSL_CRMF_CERTID;
    {$ifend}
    {$if declared(d2i_OSSL_CRMF_CERTID_introduced)}
    if LibVersion < d2i_OSSL_CRMF_CERTID_introduced then
    begin
      {$if declared(FC_d2i_OSSL_CRMF_CERTID)}
      d2i_OSSL_CRMF_CERTID := FC_d2i_OSSL_CRMF_CERTID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_CRMF_CERTID_removed)}
    if d2i_OSSL_CRMF_CERTID_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_CRMF_CERTID)}
      d2i_OSSL_CRMF_CERTID := _d2i_OSSL_CRMF_CERTID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_CRMF_CERTID_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_CRMF_CERTID');
    {$ifend}
  end;
  
  i2d_OSSL_CRMF_CERTID := LoadLibFunction(ADllHandle, i2d_OSSL_CRMF_CERTID_procname);
  FuncLoadError := not assigned(i2d_OSSL_CRMF_CERTID);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_CRMF_CERTID_allownil)}
    i2d_OSSL_CRMF_CERTID := ERR_i2d_OSSL_CRMF_CERTID;
    {$ifend}
    {$if declared(i2d_OSSL_CRMF_CERTID_introduced)}
    if LibVersion < i2d_OSSL_CRMF_CERTID_introduced then
    begin
      {$if declared(FC_i2d_OSSL_CRMF_CERTID)}
      i2d_OSSL_CRMF_CERTID := FC_i2d_OSSL_CRMF_CERTID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_CRMF_CERTID_removed)}
    if i2d_OSSL_CRMF_CERTID_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_CRMF_CERTID)}
      i2d_OSSL_CRMF_CERTID := _i2d_OSSL_CRMF_CERTID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_CRMF_CERTID_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_CRMF_CERTID');
    {$ifend}
  end;
  
  OSSL_CRMF_CERTID_it := LoadLibFunction(ADllHandle, OSSL_CRMF_CERTID_it_procname);
  FuncLoadError := not assigned(OSSL_CRMF_CERTID_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_CERTID_it_allownil)}
    OSSL_CRMF_CERTID_it := ERR_OSSL_CRMF_CERTID_it;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTID_it_introduced)}
    if LibVersion < OSSL_CRMF_CERTID_it_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_CERTID_it)}
      OSSL_CRMF_CERTID_it := FC_OSSL_CRMF_CERTID_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTID_it_removed)}
    if OSSL_CRMF_CERTID_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_CERTID_it)}
      OSSL_CRMF_CERTID_it := _OSSL_CRMF_CERTID_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_CERTID_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_CERTID_it');
    {$ifend}
  end;
  
  OSSL_CRMF_CERTID_dup := LoadLibFunction(ADllHandle, OSSL_CRMF_CERTID_dup_procname);
  FuncLoadError := not assigned(OSSL_CRMF_CERTID_dup);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_CERTID_dup_allownil)}
    OSSL_CRMF_CERTID_dup := ERR_OSSL_CRMF_CERTID_dup;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTID_dup_introduced)}
    if LibVersion < OSSL_CRMF_CERTID_dup_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_CERTID_dup)}
      OSSL_CRMF_CERTID_dup := FC_OSSL_CRMF_CERTID_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTID_dup_removed)}
    if OSSL_CRMF_CERTID_dup_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_CERTID_dup)}
      OSSL_CRMF_CERTID_dup := _OSSL_CRMF_CERTID_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_CERTID_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_CERTID_dup');
    {$ifend}
  end;
  
  OSSL_CRMF_PKIPUBLICATIONINFO_new := LoadLibFunction(ADllHandle, OSSL_CRMF_PKIPUBLICATIONINFO_new_procname);
  FuncLoadError := not assigned(OSSL_CRMF_PKIPUBLICATIONINFO_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_PKIPUBLICATIONINFO_new_allownil)}
    OSSL_CRMF_PKIPUBLICATIONINFO_new := ERR_OSSL_CRMF_PKIPUBLICATIONINFO_new;
    {$ifend}
    {$if declared(OSSL_CRMF_PKIPUBLICATIONINFO_new_introduced)}
    if LibVersion < OSSL_CRMF_PKIPUBLICATIONINFO_new_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_PKIPUBLICATIONINFO_new)}
      OSSL_CRMF_PKIPUBLICATIONINFO_new := FC_OSSL_CRMF_PKIPUBLICATIONINFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_PKIPUBLICATIONINFO_new_removed)}
    if OSSL_CRMF_PKIPUBLICATIONINFO_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_PKIPUBLICATIONINFO_new)}
      OSSL_CRMF_PKIPUBLICATIONINFO_new := _OSSL_CRMF_PKIPUBLICATIONINFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_PKIPUBLICATIONINFO_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_PKIPUBLICATIONINFO_new');
    {$ifend}
  end;
  
  OSSL_CRMF_PKIPUBLICATIONINFO_free := LoadLibFunction(ADllHandle, OSSL_CRMF_PKIPUBLICATIONINFO_free_procname);
  FuncLoadError := not assigned(OSSL_CRMF_PKIPUBLICATIONINFO_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_PKIPUBLICATIONINFO_free_allownil)}
    OSSL_CRMF_PKIPUBLICATIONINFO_free := ERR_OSSL_CRMF_PKIPUBLICATIONINFO_free;
    {$ifend}
    {$if declared(OSSL_CRMF_PKIPUBLICATIONINFO_free_introduced)}
    if LibVersion < OSSL_CRMF_PKIPUBLICATIONINFO_free_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_PKIPUBLICATIONINFO_free)}
      OSSL_CRMF_PKIPUBLICATIONINFO_free := FC_OSSL_CRMF_PKIPUBLICATIONINFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_PKIPUBLICATIONINFO_free_removed)}
    if OSSL_CRMF_PKIPUBLICATIONINFO_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_PKIPUBLICATIONINFO_free)}
      OSSL_CRMF_PKIPUBLICATIONINFO_free := _OSSL_CRMF_PKIPUBLICATIONINFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_PKIPUBLICATIONINFO_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_PKIPUBLICATIONINFO_free');
    {$ifend}
  end;
  
  d2i_OSSL_CRMF_PKIPUBLICATIONINFO := LoadLibFunction(ADllHandle, d2i_OSSL_CRMF_PKIPUBLICATIONINFO_procname);
  FuncLoadError := not assigned(d2i_OSSL_CRMF_PKIPUBLICATIONINFO);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_CRMF_PKIPUBLICATIONINFO_allownil)}
    d2i_OSSL_CRMF_PKIPUBLICATIONINFO := ERR_d2i_OSSL_CRMF_PKIPUBLICATIONINFO;
    {$ifend}
    {$if declared(d2i_OSSL_CRMF_PKIPUBLICATIONINFO_introduced)}
    if LibVersion < d2i_OSSL_CRMF_PKIPUBLICATIONINFO_introduced then
    begin
      {$if declared(FC_d2i_OSSL_CRMF_PKIPUBLICATIONINFO)}
      d2i_OSSL_CRMF_PKIPUBLICATIONINFO := FC_d2i_OSSL_CRMF_PKIPUBLICATIONINFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_CRMF_PKIPUBLICATIONINFO_removed)}
    if d2i_OSSL_CRMF_PKIPUBLICATIONINFO_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_CRMF_PKIPUBLICATIONINFO)}
      d2i_OSSL_CRMF_PKIPUBLICATIONINFO := _d2i_OSSL_CRMF_PKIPUBLICATIONINFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_CRMF_PKIPUBLICATIONINFO_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_CRMF_PKIPUBLICATIONINFO');
    {$ifend}
  end;
  
  i2d_OSSL_CRMF_PKIPUBLICATIONINFO := LoadLibFunction(ADllHandle, i2d_OSSL_CRMF_PKIPUBLICATIONINFO_procname);
  FuncLoadError := not assigned(i2d_OSSL_CRMF_PKIPUBLICATIONINFO);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_CRMF_PKIPUBLICATIONINFO_allownil)}
    i2d_OSSL_CRMF_PKIPUBLICATIONINFO := ERR_i2d_OSSL_CRMF_PKIPUBLICATIONINFO;
    {$ifend}
    {$if declared(i2d_OSSL_CRMF_PKIPUBLICATIONINFO_introduced)}
    if LibVersion < i2d_OSSL_CRMF_PKIPUBLICATIONINFO_introduced then
    begin
      {$if declared(FC_i2d_OSSL_CRMF_PKIPUBLICATIONINFO)}
      i2d_OSSL_CRMF_PKIPUBLICATIONINFO := FC_i2d_OSSL_CRMF_PKIPUBLICATIONINFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_CRMF_PKIPUBLICATIONINFO_removed)}
    if i2d_OSSL_CRMF_PKIPUBLICATIONINFO_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_CRMF_PKIPUBLICATIONINFO)}
      i2d_OSSL_CRMF_PKIPUBLICATIONINFO := _i2d_OSSL_CRMF_PKIPUBLICATIONINFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_CRMF_PKIPUBLICATIONINFO_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_CRMF_PKIPUBLICATIONINFO');
    {$ifend}
  end;
  
  OSSL_CRMF_PKIPUBLICATIONINFO_it := LoadLibFunction(ADllHandle, OSSL_CRMF_PKIPUBLICATIONINFO_it_procname);
  FuncLoadError := not assigned(OSSL_CRMF_PKIPUBLICATIONINFO_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_PKIPUBLICATIONINFO_it_allownil)}
    OSSL_CRMF_PKIPUBLICATIONINFO_it := ERR_OSSL_CRMF_PKIPUBLICATIONINFO_it;
    {$ifend}
    {$if declared(OSSL_CRMF_PKIPUBLICATIONINFO_it_introduced)}
    if LibVersion < OSSL_CRMF_PKIPUBLICATIONINFO_it_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_PKIPUBLICATIONINFO_it)}
      OSSL_CRMF_PKIPUBLICATIONINFO_it := FC_OSSL_CRMF_PKIPUBLICATIONINFO_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_PKIPUBLICATIONINFO_it_removed)}
    if OSSL_CRMF_PKIPUBLICATIONINFO_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_PKIPUBLICATIONINFO_it)}
      OSSL_CRMF_PKIPUBLICATIONINFO_it := _OSSL_CRMF_PKIPUBLICATIONINFO_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_PKIPUBLICATIONINFO_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_PKIPUBLICATIONINFO_it');
    {$ifend}
  end;
  
  OSSL_CRMF_SINGLEPUBINFO_new := LoadLibFunction(ADllHandle, OSSL_CRMF_SINGLEPUBINFO_new_procname);
  FuncLoadError := not assigned(OSSL_CRMF_SINGLEPUBINFO_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_SINGLEPUBINFO_new_allownil)}
    OSSL_CRMF_SINGLEPUBINFO_new := ERR_OSSL_CRMF_SINGLEPUBINFO_new;
    {$ifend}
    {$if declared(OSSL_CRMF_SINGLEPUBINFO_new_introduced)}
    if LibVersion < OSSL_CRMF_SINGLEPUBINFO_new_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_SINGLEPUBINFO_new)}
      OSSL_CRMF_SINGLEPUBINFO_new := FC_OSSL_CRMF_SINGLEPUBINFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_SINGLEPUBINFO_new_removed)}
    if OSSL_CRMF_SINGLEPUBINFO_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_SINGLEPUBINFO_new)}
      OSSL_CRMF_SINGLEPUBINFO_new := _OSSL_CRMF_SINGLEPUBINFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_SINGLEPUBINFO_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_SINGLEPUBINFO_new');
    {$ifend}
  end;
  
  OSSL_CRMF_SINGLEPUBINFO_free := LoadLibFunction(ADllHandle, OSSL_CRMF_SINGLEPUBINFO_free_procname);
  FuncLoadError := not assigned(OSSL_CRMF_SINGLEPUBINFO_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_SINGLEPUBINFO_free_allownil)}
    OSSL_CRMF_SINGLEPUBINFO_free := ERR_OSSL_CRMF_SINGLEPUBINFO_free;
    {$ifend}
    {$if declared(OSSL_CRMF_SINGLEPUBINFO_free_introduced)}
    if LibVersion < OSSL_CRMF_SINGLEPUBINFO_free_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_SINGLEPUBINFO_free)}
      OSSL_CRMF_SINGLEPUBINFO_free := FC_OSSL_CRMF_SINGLEPUBINFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_SINGLEPUBINFO_free_removed)}
    if OSSL_CRMF_SINGLEPUBINFO_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_SINGLEPUBINFO_free)}
      OSSL_CRMF_SINGLEPUBINFO_free := _OSSL_CRMF_SINGLEPUBINFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_SINGLEPUBINFO_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_SINGLEPUBINFO_free');
    {$ifend}
  end;
  
  d2i_OSSL_CRMF_SINGLEPUBINFO := LoadLibFunction(ADllHandle, d2i_OSSL_CRMF_SINGLEPUBINFO_procname);
  FuncLoadError := not assigned(d2i_OSSL_CRMF_SINGLEPUBINFO);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_CRMF_SINGLEPUBINFO_allownil)}
    d2i_OSSL_CRMF_SINGLEPUBINFO := ERR_d2i_OSSL_CRMF_SINGLEPUBINFO;
    {$ifend}
    {$if declared(d2i_OSSL_CRMF_SINGLEPUBINFO_introduced)}
    if LibVersion < d2i_OSSL_CRMF_SINGLEPUBINFO_introduced then
    begin
      {$if declared(FC_d2i_OSSL_CRMF_SINGLEPUBINFO)}
      d2i_OSSL_CRMF_SINGLEPUBINFO := FC_d2i_OSSL_CRMF_SINGLEPUBINFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_CRMF_SINGLEPUBINFO_removed)}
    if d2i_OSSL_CRMF_SINGLEPUBINFO_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_CRMF_SINGLEPUBINFO)}
      d2i_OSSL_CRMF_SINGLEPUBINFO := _d2i_OSSL_CRMF_SINGLEPUBINFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_CRMF_SINGLEPUBINFO_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_CRMF_SINGLEPUBINFO');
    {$ifend}
  end;
  
  i2d_OSSL_CRMF_SINGLEPUBINFO := LoadLibFunction(ADllHandle, i2d_OSSL_CRMF_SINGLEPUBINFO_procname);
  FuncLoadError := not assigned(i2d_OSSL_CRMF_SINGLEPUBINFO);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_CRMF_SINGLEPUBINFO_allownil)}
    i2d_OSSL_CRMF_SINGLEPUBINFO := ERR_i2d_OSSL_CRMF_SINGLEPUBINFO;
    {$ifend}
    {$if declared(i2d_OSSL_CRMF_SINGLEPUBINFO_introduced)}
    if LibVersion < i2d_OSSL_CRMF_SINGLEPUBINFO_introduced then
    begin
      {$if declared(FC_i2d_OSSL_CRMF_SINGLEPUBINFO)}
      i2d_OSSL_CRMF_SINGLEPUBINFO := FC_i2d_OSSL_CRMF_SINGLEPUBINFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_CRMF_SINGLEPUBINFO_removed)}
    if i2d_OSSL_CRMF_SINGLEPUBINFO_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_CRMF_SINGLEPUBINFO)}
      i2d_OSSL_CRMF_SINGLEPUBINFO := _i2d_OSSL_CRMF_SINGLEPUBINFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_CRMF_SINGLEPUBINFO_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_CRMF_SINGLEPUBINFO');
    {$ifend}
  end;
  
  OSSL_CRMF_SINGLEPUBINFO_it := LoadLibFunction(ADllHandle, OSSL_CRMF_SINGLEPUBINFO_it_procname);
  FuncLoadError := not assigned(OSSL_CRMF_SINGLEPUBINFO_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_SINGLEPUBINFO_it_allownil)}
    OSSL_CRMF_SINGLEPUBINFO_it := ERR_OSSL_CRMF_SINGLEPUBINFO_it;
    {$ifend}
    {$if declared(OSSL_CRMF_SINGLEPUBINFO_it_introduced)}
    if LibVersion < OSSL_CRMF_SINGLEPUBINFO_it_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_SINGLEPUBINFO_it)}
      OSSL_CRMF_SINGLEPUBINFO_it := FC_OSSL_CRMF_SINGLEPUBINFO_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_SINGLEPUBINFO_it_removed)}
    if OSSL_CRMF_SINGLEPUBINFO_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_SINGLEPUBINFO_it)}
      OSSL_CRMF_SINGLEPUBINFO_it := _OSSL_CRMF_SINGLEPUBINFO_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_SINGLEPUBINFO_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_SINGLEPUBINFO_it');
    {$ifend}
  end;
  
  OSSL_CRMF_CERTTEMPLATE_new := LoadLibFunction(ADllHandle, OSSL_CRMF_CERTTEMPLATE_new_procname);
  FuncLoadError := not assigned(OSSL_CRMF_CERTTEMPLATE_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_CERTTEMPLATE_new_allownil)}
    OSSL_CRMF_CERTTEMPLATE_new := ERR_OSSL_CRMF_CERTTEMPLATE_new;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTTEMPLATE_new_introduced)}
    if LibVersion < OSSL_CRMF_CERTTEMPLATE_new_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_CERTTEMPLATE_new)}
      OSSL_CRMF_CERTTEMPLATE_new := FC_OSSL_CRMF_CERTTEMPLATE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTTEMPLATE_new_removed)}
    if OSSL_CRMF_CERTTEMPLATE_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_CERTTEMPLATE_new)}
      OSSL_CRMF_CERTTEMPLATE_new := _OSSL_CRMF_CERTTEMPLATE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_CERTTEMPLATE_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_CERTTEMPLATE_new');
    {$ifend}
  end;
  
  OSSL_CRMF_CERTTEMPLATE_free := LoadLibFunction(ADllHandle, OSSL_CRMF_CERTTEMPLATE_free_procname);
  FuncLoadError := not assigned(OSSL_CRMF_CERTTEMPLATE_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_CERTTEMPLATE_free_allownil)}
    OSSL_CRMF_CERTTEMPLATE_free := ERR_OSSL_CRMF_CERTTEMPLATE_free;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTTEMPLATE_free_introduced)}
    if LibVersion < OSSL_CRMF_CERTTEMPLATE_free_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_CERTTEMPLATE_free)}
      OSSL_CRMF_CERTTEMPLATE_free := FC_OSSL_CRMF_CERTTEMPLATE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTTEMPLATE_free_removed)}
    if OSSL_CRMF_CERTTEMPLATE_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_CERTTEMPLATE_free)}
      OSSL_CRMF_CERTTEMPLATE_free := _OSSL_CRMF_CERTTEMPLATE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_CERTTEMPLATE_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_CERTTEMPLATE_free');
    {$ifend}
  end;
  
  d2i_OSSL_CRMF_CERTTEMPLATE := LoadLibFunction(ADllHandle, d2i_OSSL_CRMF_CERTTEMPLATE_procname);
  FuncLoadError := not assigned(d2i_OSSL_CRMF_CERTTEMPLATE);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_CRMF_CERTTEMPLATE_allownil)}
    d2i_OSSL_CRMF_CERTTEMPLATE := ERR_d2i_OSSL_CRMF_CERTTEMPLATE;
    {$ifend}
    {$if declared(d2i_OSSL_CRMF_CERTTEMPLATE_introduced)}
    if LibVersion < d2i_OSSL_CRMF_CERTTEMPLATE_introduced then
    begin
      {$if declared(FC_d2i_OSSL_CRMF_CERTTEMPLATE)}
      d2i_OSSL_CRMF_CERTTEMPLATE := FC_d2i_OSSL_CRMF_CERTTEMPLATE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_CRMF_CERTTEMPLATE_removed)}
    if d2i_OSSL_CRMF_CERTTEMPLATE_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_CRMF_CERTTEMPLATE)}
      d2i_OSSL_CRMF_CERTTEMPLATE := _d2i_OSSL_CRMF_CERTTEMPLATE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_CRMF_CERTTEMPLATE_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_CRMF_CERTTEMPLATE');
    {$ifend}
  end;
  
  i2d_OSSL_CRMF_CERTTEMPLATE := LoadLibFunction(ADllHandle, i2d_OSSL_CRMF_CERTTEMPLATE_procname);
  FuncLoadError := not assigned(i2d_OSSL_CRMF_CERTTEMPLATE);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_CRMF_CERTTEMPLATE_allownil)}
    i2d_OSSL_CRMF_CERTTEMPLATE := ERR_i2d_OSSL_CRMF_CERTTEMPLATE;
    {$ifend}
    {$if declared(i2d_OSSL_CRMF_CERTTEMPLATE_introduced)}
    if LibVersion < i2d_OSSL_CRMF_CERTTEMPLATE_introduced then
    begin
      {$if declared(FC_i2d_OSSL_CRMF_CERTTEMPLATE)}
      i2d_OSSL_CRMF_CERTTEMPLATE := FC_i2d_OSSL_CRMF_CERTTEMPLATE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_CRMF_CERTTEMPLATE_removed)}
    if i2d_OSSL_CRMF_CERTTEMPLATE_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_CRMF_CERTTEMPLATE)}
      i2d_OSSL_CRMF_CERTTEMPLATE := _i2d_OSSL_CRMF_CERTTEMPLATE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_CRMF_CERTTEMPLATE_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_CRMF_CERTTEMPLATE');
    {$ifend}
  end;
  
  OSSL_CRMF_CERTTEMPLATE_it := LoadLibFunction(ADllHandle, OSSL_CRMF_CERTTEMPLATE_it_procname);
  FuncLoadError := not assigned(OSSL_CRMF_CERTTEMPLATE_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_CERTTEMPLATE_it_allownil)}
    OSSL_CRMF_CERTTEMPLATE_it := ERR_OSSL_CRMF_CERTTEMPLATE_it;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTTEMPLATE_it_introduced)}
    if LibVersion < OSSL_CRMF_CERTTEMPLATE_it_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_CERTTEMPLATE_it)}
      OSSL_CRMF_CERTTEMPLATE_it := FC_OSSL_CRMF_CERTTEMPLATE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTTEMPLATE_it_removed)}
    if OSSL_CRMF_CERTTEMPLATE_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_CERTTEMPLATE_it)}
      OSSL_CRMF_CERTTEMPLATE_it := _OSSL_CRMF_CERTTEMPLATE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_CERTTEMPLATE_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_CERTTEMPLATE_it');
    {$ifend}
  end;
  
  OSSL_CRMF_CERTTEMPLATE_dup := LoadLibFunction(ADllHandle, OSSL_CRMF_CERTTEMPLATE_dup_procname);
  FuncLoadError := not assigned(OSSL_CRMF_CERTTEMPLATE_dup);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_CERTTEMPLATE_dup_allownil)}
    OSSL_CRMF_CERTTEMPLATE_dup := ERR_OSSL_CRMF_CERTTEMPLATE_dup;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTTEMPLATE_dup_introduced)}
    if LibVersion < OSSL_CRMF_CERTTEMPLATE_dup_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_CERTTEMPLATE_dup)}
      OSSL_CRMF_CERTTEMPLATE_dup := FC_OSSL_CRMF_CERTTEMPLATE_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTTEMPLATE_dup_removed)}
    if OSSL_CRMF_CERTTEMPLATE_dup_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_CERTTEMPLATE_dup)}
      OSSL_CRMF_CERTTEMPLATE_dup := _OSSL_CRMF_CERTTEMPLATE_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_CERTTEMPLATE_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_CERTTEMPLATE_dup');
    {$ifend}
  end;
  
  OSSL_CRMF_MSGS_new := LoadLibFunction(ADllHandle, OSSL_CRMF_MSGS_new_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSGS_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSGS_new_allownil)}
    OSSL_CRMF_MSGS_new := ERR_OSSL_CRMF_MSGS_new;
    {$ifend}
    {$if declared(OSSL_CRMF_MSGS_new_introduced)}
    if LibVersion < OSSL_CRMF_MSGS_new_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSGS_new)}
      OSSL_CRMF_MSGS_new := FC_OSSL_CRMF_MSGS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSGS_new_removed)}
    if OSSL_CRMF_MSGS_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSGS_new)}
      OSSL_CRMF_MSGS_new := _OSSL_CRMF_MSGS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSGS_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSGS_new');
    {$ifend}
  end;
  
  OSSL_CRMF_MSGS_free := LoadLibFunction(ADllHandle, OSSL_CRMF_MSGS_free_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSGS_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSGS_free_allownil)}
    OSSL_CRMF_MSGS_free := ERR_OSSL_CRMF_MSGS_free;
    {$ifend}
    {$if declared(OSSL_CRMF_MSGS_free_introduced)}
    if LibVersion < OSSL_CRMF_MSGS_free_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSGS_free)}
      OSSL_CRMF_MSGS_free := FC_OSSL_CRMF_MSGS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSGS_free_removed)}
    if OSSL_CRMF_MSGS_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSGS_free)}
      OSSL_CRMF_MSGS_free := _OSSL_CRMF_MSGS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSGS_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSGS_free');
    {$ifend}
  end;
  
  d2i_OSSL_CRMF_MSGS := LoadLibFunction(ADllHandle, d2i_OSSL_CRMF_MSGS_procname);
  FuncLoadError := not assigned(d2i_OSSL_CRMF_MSGS);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_CRMF_MSGS_allownil)}
    d2i_OSSL_CRMF_MSGS := ERR_d2i_OSSL_CRMF_MSGS;
    {$ifend}
    {$if declared(d2i_OSSL_CRMF_MSGS_introduced)}
    if LibVersion < d2i_OSSL_CRMF_MSGS_introduced then
    begin
      {$if declared(FC_d2i_OSSL_CRMF_MSGS)}
      d2i_OSSL_CRMF_MSGS := FC_d2i_OSSL_CRMF_MSGS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_CRMF_MSGS_removed)}
    if d2i_OSSL_CRMF_MSGS_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_CRMF_MSGS)}
      d2i_OSSL_CRMF_MSGS := _d2i_OSSL_CRMF_MSGS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_CRMF_MSGS_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_CRMF_MSGS');
    {$ifend}
  end;
  
  i2d_OSSL_CRMF_MSGS := LoadLibFunction(ADllHandle, i2d_OSSL_CRMF_MSGS_procname);
  FuncLoadError := not assigned(i2d_OSSL_CRMF_MSGS);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_CRMF_MSGS_allownil)}
    i2d_OSSL_CRMF_MSGS := ERR_i2d_OSSL_CRMF_MSGS;
    {$ifend}
    {$if declared(i2d_OSSL_CRMF_MSGS_introduced)}
    if LibVersion < i2d_OSSL_CRMF_MSGS_introduced then
    begin
      {$if declared(FC_i2d_OSSL_CRMF_MSGS)}
      i2d_OSSL_CRMF_MSGS := FC_i2d_OSSL_CRMF_MSGS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_CRMF_MSGS_removed)}
    if i2d_OSSL_CRMF_MSGS_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_CRMF_MSGS)}
      i2d_OSSL_CRMF_MSGS := _i2d_OSSL_CRMF_MSGS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_CRMF_MSGS_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_CRMF_MSGS');
    {$ifend}
  end;
  
  OSSL_CRMF_MSGS_it := LoadLibFunction(ADllHandle, OSSL_CRMF_MSGS_it_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSGS_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSGS_it_allownil)}
    OSSL_CRMF_MSGS_it := ERR_OSSL_CRMF_MSGS_it;
    {$ifend}
    {$if declared(OSSL_CRMF_MSGS_it_introduced)}
    if LibVersion < OSSL_CRMF_MSGS_it_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSGS_it)}
      OSSL_CRMF_MSGS_it := FC_OSSL_CRMF_MSGS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSGS_it_removed)}
    if OSSL_CRMF_MSGS_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSGS_it)}
      OSSL_CRMF_MSGS_it := _OSSL_CRMF_MSGS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSGS_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSGS_it');
    {$ifend}
  end;
  
  OSSL_CRMF_pbmp_new := LoadLibFunction(ADllHandle, OSSL_CRMF_pbmp_new_procname);
  FuncLoadError := not assigned(OSSL_CRMF_pbmp_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_pbmp_new_allownil)}
    OSSL_CRMF_pbmp_new := ERR_OSSL_CRMF_pbmp_new;
    {$ifend}
    {$if declared(OSSL_CRMF_pbmp_new_introduced)}
    if LibVersion < OSSL_CRMF_pbmp_new_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_pbmp_new)}
      OSSL_CRMF_pbmp_new := FC_OSSL_CRMF_pbmp_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_pbmp_new_removed)}
    if OSSL_CRMF_pbmp_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_pbmp_new)}
      OSSL_CRMF_pbmp_new := _OSSL_CRMF_pbmp_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_pbmp_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_pbmp_new');
    {$ifend}
  end;
  
  OSSL_CRMF_pbm_new := LoadLibFunction(ADllHandle, OSSL_CRMF_pbm_new_procname);
  FuncLoadError := not assigned(OSSL_CRMF_pbm_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_pbm_new_allownil)}
    OSSL_CRMF_pbm_new := ERR_OSSL_CRMF_pbm_new;
    {$ifend}
    {$if declared(OSSL_CRMF_pbm_new_introduced)}
    if LibVersion < OSSL_CRMF_pbm_new_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_pbm_new)}
      OSSL_CRMF_pbm_new := FC_OSSL_CRMF_pbm_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_pbm_new_removed)}
    if OSSL_CRMF_pbm_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_pbm_new)}
      OSSL_CRMF_pbm_new := _OSSL_CRMF_pbm_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_pbm_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_pbm_new');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_set1_regCtrl_regToken := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_set1_regCtrl_regToken_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_set1_regCtrl_regToken);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_set1_regCtrl_regToken_allownil)}
    OSSL_CRMF_MSG_set1_regCtrl_regToken := ERR_OSSL_CRMF_MSG_set1_regCtrl_regToken;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_set1_regCtrl_regToken_introduced)}
    if LibVersion < OSSL_CRMF_MSG_set1_regCtrl_regToken_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_set1_regCtrl_regToken)}
      OSSL_CRMF_MSG_set1_regCtrl_regToken := FC_OSSL_CRMF_MSG_set1_regCtrl_regToken;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_set1_regCtrl_regToken_removed)}
    if OSSL_CRMF_MSG_set1_regCtrl_regToken_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_set1_regCtrl_regToken)}
      OSSL_CRMF_MSG_set1_regCtrl_regToken := _OSSL_CRMF_MSG_set1_regCtrl_regToken;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_set1_regCtrl_regToken_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_set1_regCtrl_regToken');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_get0_regCtrl_regToken := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_get0_regCtrl_regToken_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_get0_regCtrl_regToken);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_get0_regCtrl_regToken_allownil)}
    OSSL_CRMF_MSG_get0_regCtrl_regToken := ERR_OSSL_CRMF_MSG_get0_regCtrl_regToken;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_get0_regCtrl_regToken_introduced)}
    if LibVersion < OSSL_CRMF_MSG_get0_regCtrl_regToken_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_get0_regCtrl_regToken)}
      OSSL_CRMF_MSG_get0_regCtrl_regToken := FC_OSSL_CRMF_MSG_get0_regCtrl_regToken;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_get0_regCtrl_regToken_removed)}
    if OSSL_CRMF_MSG_get0_regCtrl_regToken_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_get0_regCtrl_regToken)}
      OSSL_CRMF_MSG_get0_regCtrl_regToken := _OSSL_CRMF_MSG_get0_regCtrl_regToken;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_get0_regCtrl_regToken_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_get0_regCtrl_regToken');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_set1_regCtrl_authenticator := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_set1_regCtrl_authenticator_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_set1_regCtrl_authenticator);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_set1_regCtrl_authenticator_allownil)}
    OSSL_CRMF_MSG_set1_regCtrl_authenticator := ERR_OSSL_CRMF_MSG_set1_regCtrl_authenticator;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_set1_regCtrl_authenticator_introduced)}
    if LibVersion < OSSL_CRMF_MSG_set1_regCtrl_authenticator_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_set1_regCtrl_authenticator)}
      OSSL_CRMF_MSG_set1_regCtrl_authenticator := FC_OSSL_CRMF_MSG_set1_regCtrl_authenticator;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_set1_regCtrl_authenticator_removed)}
    if OSSL_CRMF_MSG_set1_regCtrl_authenticator_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_set1_regCtrl_authenticator)}
      OSSL_CRMF_MSG_set1_regCtrl_authenticator := _OSSL_CRMF_MSG_set1_regCtrl_authenticator;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_set1_regCtrl_authenticator_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_set1_regCtrl_authenticator');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_get0_regCtrl_authenticator := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_get0_regCtrl_authenticator_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_get0_regCtrl_authenticator);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_get0_regCtrl_authenticator_allownil)}
    OSSL_CRMF_MSG_get0_regCtrl_authenticator := ERR_OSSL_CRMF_MSG_get0_regCtrl_authenticator;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_get0_regCtrl_authenticator_introduced)}
    if LibVersion < OSSL_CRMF_MSG_get0_regCtrl_authenticator_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_get0_regCtrl_authenticator)}
      OSSL_CRMF_MSG_get0_regCtrl_authenticator := FC_OSSL_CRMF_MSG_get0_regCtrl_authenticator;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_get0_regCtrl_authenticator_removed)}
    if OSSL_CRMF_MSG_get0_regCtrl_authenticator_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_get0_regCtrl_authenticator)}
      OSSL_CRMF_MSG_get0_regCtrl_authenticator := _OSSL_CRMF_MSG_get0_regCtrl_authenticator;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_get0_regCtrl_authenticator_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_get0_regCtrl_authenticator');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo_allownil)}
    OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo := ERR_OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo_introduced)}
    if LibVersion < OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo)}
      OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo := FC_OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo_removed)}
    if OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo)}
      OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo := _OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_set0_SinglePubInfo := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_set0_SinglePubInfo_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_set0_SinglePubInfo);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_set0_SinglePubInfo_allownil)}
    OSSL_CRMF_MSG_set0_SinglePubInfo := ERR_OSSL_CRMF_MSG_set0_SinglePubInfo;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_set0_SinglePubInfo_introduced)}
    if LibVersion < OSSL_CRMF_MSG_set0_SinglePubInfo_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_set0_SinglePubInfo)}
      OSSL_CRMF_MSG_set0_SinglePubInfo := FC_OSSL_CRMF_MSG_set0_SinglePubInfo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_set0_SinglePubInfo_removed)}
    if OSSL_CRMF_MSG_set0_SinglePubInfo_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_set0_SinglePubInfo)}
      OSSL_CRMF_MSG_set0_SinglePubInfo := _OSSL_CRMF_MSG_set0_SinglePubInfo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_set0_SinglePubInfo_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_set0_SinglePubInfo');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_set_PKIPublicationInfo_action := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_set_PKIPublicationInfo_action_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_set_PKIPublicationInfo_action);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_set_PKIPublicationInfo_action_allownil)}
    OSSL_CRMF_MSG_set_PKIPublicationInfo_action := ERR_OSSL_CRMF_MSG_set_PKIPublicationInfo_action;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_set_PKIPublicationInfo_action_introduced)}
    if LibVersion < OSSL_CRMF_MSG_set_PKIPublicationInfo_action_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_set_PKIPublicationInfo_action)}
      OSSL_CRMF_MSG_set_PKIPublicationInfo_action := FC_OSSL_CRMF_MSG_set_PKIPublicationInfo_action;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_set_PKIPublicationInfo_action_removed)}
    if OSSL_CRMF_MSG_set_PKIPublicationInfo_action_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_set_PKIPublicationInfo_action)}
      OSSL_CRMF_MSG_set_PKIPublicationInfo_action := _OSSL_CRMF_MSG_set_PKIPublicationInfo_action;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_set_PKIPublicationInfo_action_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_set_PKIPublicationInfo_action');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo_allownil)}
    OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo := ERR_OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo_introduced)}
    if LibVersion < OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo)}
      OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo := FC_OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo_removed)}
    if OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo)}
      OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo := _OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo_allownil)}
    OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo := ERR_OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo_introduced)}
    if LibVersion < OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo)}
      OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo := FC_OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo_removed)}
    if OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo)}
      OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo := _OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey_allownil)}
    OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey := ERR_OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey_introduced)}
    if LibVersion < OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey)}
      OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey := FC_OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey_removed)}
    if OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey)}
      OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey := _OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey_allownil)}
    OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey := ERR_OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey_introduced)}
    if LibVersion < OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey)}
      OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey := FC_OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey_removed)}
    if OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey)}
      OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey := _OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_set1_regCtrl_oldCertID := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_set1_regCtrl_oldCertID_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_set1_regCtrl_oldCertID);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_set1_regCtrl_oldCertID_allownil)}
    OSSL_CRMF_MSG_set1_regCtrl_oldCertID := ERR_OSSL_CRMF_MSG_set1_regCtrl_oldCertID;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_set1_regCtrl_oldCertID_introduced)}
    if LibVersion < OSSL_CRMF_MSG_set1_regCtrl_oldCertID_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_set1_regCtrl_oldCertID)}
      OSSL_CRMF_MSG_set1_regCtrl_oldCertID := FC_OSSL_CRMF_MSG_set1_regCtrl_oldCertID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_set1_regCtrl_oldCertID_removed)}
    if OSSL_CRMF_MSG_set1_regCtrl_oldCertID_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_set1_regCtrl_oldCertID)}
      OSSL_CRMF_MSG_set1_regCtrl_oldCertID := _OSSL_CRMF_MSG_set1_regCtrl_oldCertID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_set1_regCtrl_oldCertID_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_set1_regCtrl_oldCertID');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_get0_regCtrl_oldCertID := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_get0_regCtrl_oldCertID_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_get0_regCtrl_oldCertID);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_get0_regCtrl_oldCertID_allownil)}
    OSSL_CRMF_MSG_get0_regCtrl_oldCertID := ERR_OSSL_CRMF_MSG_get0_regCtrl_oldCertID;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_get0_regCtrl_oldCertID_introduced)}
    if LibVersion < OSSL_CRMF_MSG_get0_regCtrl_oldCertID_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_get0_regCtrl_oldCertID)}
      OSSL_CRMF_MSG_get0_regCtrl_oldCertID := FC_OSSL_CRMF_MSG_get0_regCtrl_oldCertID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_get0_regCtrl_oldCertID_removed)}
    if OSSL_CRMF_MSG_get0_regCtrl_oldCertID_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_get0_regCtrl_oldCertID)}
      OSSL_CRMF_MSG_get0_regCtrl_oldCertID := _OSSL_CRMF_MSG_get0_regCtrl_oldCertID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_get0_regCtrl_oldCertID_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_get0_regCtrl_oldCertID');
    {$ifend}
  end;
  
  OSSL_CRMF_CERTID_gen := LoadLibFunction(ADllHandle, OSSL_CRMF_CERTID_gen_procname);
  FuncLoadError := not assigned(OSSL_CRMF_CERTID_gen);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_CERTID_gen_allownil)}
    OSSL_CRMF_CERTID_gen := ERR_OSSL_CRMF_CERTID_gen;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTID_gen_introduced)}
    if LibVersion < OSSL_CRMF_CERTID_gen_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_CERTID_gen)}
      OSSL_CRMF_CERTID_gen := FC_OSSL_CRMF_CERTID_gen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTID_gen_removed)}
    if OSSL_CRMF_CERTID_gen_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_CERTID_gen)}
      OSSL_CRMF_CERTID_gen := _OSSL_CRMF_CERTID_gen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_CERTID_gen_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_CERTID_gen');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_set1_regInfo_utf8Pairs := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_set1_regInfo_utf8Pairs_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_set1_regInfo_utf8Pairs);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_set1_regInfo_utf8Pairs_allownil)}
    OSSL_CRMF_MSG_set1_regInfo_utf8Pairs := ERR_OSSL_CRMF_MSG_set1_regInfo_utf8Pairs;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_set1_regInfo_utf8Pairs_introduced)}
    if LibVersion < OSSL_CRMF_MSG_set1_regInfo_utf8Pairs_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_set1_regInfo_utf8Pairs)}
      OSSL_CRMF_MSG_set1_regInfo_utf8Pairs := FC_OSSL_CRMF_MSG_set1_regInfo_utf8Pairs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_set1_regInfo_utf8Pairs_removed)}
    if OSSL_CRMF_MSG_set1_regInfo_utf8Pairs_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_set1_regInfo_utf8Pairs)}
      OSSL_CRMF_MSG_set1_regInfo_utf8Pairs := _OSSL_CRMF_MSG_set1_regInfo_utf8Pairs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_set1_regInfo_utf8Pairs_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_set1_regInfo_utf8Pairs');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_get0_regInfo_utf8Pairs := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_get0_regInfo_utf8Pairs_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_get0_regInfo_utf8Pairs);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_get0_regInfo_utf8Pairs_allownil)}
    OSSL_CRMF_MSG_get0_regInfo_utf8Pairs := ERR_OSSL_CRMF_MSG_get0_regInfo_utf8Pairs;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_get0_regInfo_utf8Pairs_introduced)}
    if LibVersion < OSSL_CRMF_MSG_get0_regInfo_utf8Pairs_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_get0_regInfo_utf8Pairs)}
      OSSL_CRMF_MSG_get0_regInfo_utf8Pairs := FC_OSSL_CRMF_MSG_get0_regInfo_utf8Pairs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_get0_regInfo_utf8Pairs_removed)}
    if OSSL_CRMF_MSG_get0_regInfo_utf8Pairs_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_get0_regInfo_utf8Pairs)}
      OSSL_CRMF_MSG_get0_regInfo_utf8Pairs := _OSSL_CRMF_MSG_get0_regInfo_utf8Pairs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_get0_regInfo_utf8Pairs_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_get0_regInfo_utf8Pairs');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_set1_regInfo_certReq := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_set1_regInfo_certReq_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_set1_regInfo_certReq);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_set1_regInfo_certReq_allownil)}
    OSSL_CRMF_MSG_set1_regInfo_certReq := ERR_OSSL_CRMF_MSG_set1_regInfo_certReq;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_set1_regInfo_certReq_introduced)}
    if LibVersion < OSSL_CRMF_MSG_set1_regInfo_certReq_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_set1_regInfo_certReq)}
      OSSL_CRMF_MSG_set1_regInfo_certReq := FC_OSSL_CRMF_MSG_set1_regInfo_certReq;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_set1_regInfo_certReq_removed)}
    if OSSL_CRMF_MSG_set1_regInfo_certReq_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_set1_regInfo_certReq)}
      OSSL_CRMF_MSG_set1_regInfo_certReq := _OSSL_CRMF_MSG_set1_regInfo_certReq;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_set1_regInfo_certReq_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_set1_regInfo_certReq');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_get0_regInfo_certReq := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_get0_regInfo_certReq_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_get0_regInfo_certReq);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_get0_regInfo_certReq_allownil)}
    OSSL_CRMF_MSG_get0_regInfo_certReq := ERR_OSSL_CRMF_MSG_get0_regInfo_certReq;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_get0_regInfo_certReq_introduced)}
    if LibVersion < OSSL_CRMF_MSG_get0_regInfo_certReq_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_get0_regInfo_certReq)}
      OSSL_CRMF_MSG_get0_regInfo_certReq := FC_OSSL_CRMF_MSG_get0_regInfo_certReq;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_get0_regInfo_certReq_removed)}
    if OSSL_CRMF_MSG_get0_regInfo_certReq_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_get0_regInfo_certReq)}
      OSSL_CRMF_MSG_get0_regInfo_certReq := _OSSL_CRMF_MSG_get0_regInfo_certReq;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_get0_regInfo_certReq_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_get0_regInfo_certReq');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_set0_validity := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_set0_validity_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_set0_validity);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_set0_validity_allownil)}
    OSSL_CRMF_MSG_set0_validity := ERR_OSSL_CRMF_MSG_set0_validity;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_set0_validity_introduced)}
    if LibVersion < OSSL_CRMF_MSG_set0_validity_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_set0_validity)}
      OSSL_CRMF_MSG_set0_validity := FC_OSSL_CRMF_MSG_set0_validity;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_set0_validity_removed)}
    if OSSL_CRMF_MSG_set0_validity_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_set0_validity)}
      OSSL_CRMF_MSG_set0_validity := _OSSL_CRMF_MSG_set0_validity;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_set0_validity_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_set0_validity');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_set_certReqId := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_set_certReqId_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_set_certReqId);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_set_certReqId_allownil)}
    OSSL_CRMF_MSG_set_certReqId := ERR_OSSL_CRMF_MSG_set_certReqId;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_set_certReqId_introduced)}
    if LibVersion < OSSL_CRMF_MSG_set_certReqId_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_set_certReqId)}
      OSSL_CRMF_MSG_set_certReqId := FC_OSSL_CRMF_MSG_set_certReqId;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_set_certReqId_removed)}
    if OSSL_CRMF_MSG_set_certReqId_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_set_certReqId)}
      OSSL_CRMF_MSG_set_certReqId := _OSSL_CRMF_MSG_set_certReqId;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_set_certReqId_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_set_certReqId');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_get_certReqId := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_get_certReqId_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_get_certReqId);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_get_certReqId_allownil)}
    OSSL_CRMF_MSG_get_certReqId := ERR_OSSL_CRMF_MSG_get_certReqId;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_get_certReqId_introduced)}
    if LibVersion < OSSL_CRMF_MSG_get_certReqId_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_get_certReqId)}
      OSSL_CRMF_MSG_get_certReqId := FC_OSSL_CRMF_MSG_get_certReqId;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_get_certReqId_removed)}
    if OSSL_CRMF_MSG_get_certReqId_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_get_certReqId)}
      OSSL_CRMF_MSG_get_certReqId := _OSSL_CRMF_MSG_get_certReqId;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_get_certReqId_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_get_certReqId');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_set0_extensions := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_set0_extensions_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_set0_extensions);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_set0_extensions_allownil)}
    OSSL_CRMF_MSG_set0_extensions := ERR_OSSL_CRMF_MSG_set0_extensions;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_set0_extensions_introduced)}
    if LibVersion < OSSL_CRMF_MSG_set0_extensions_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_set0_extensions)}
      OSSL_CRMF_MSG_set0_extensions := FC_OSSL_CRMF_MSG_set0_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_set0_extensions_removed)}
    if OSSL_CRMF_MSG_set0_extensions_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_set0_extensions)}
      OSSL_CRMF_MSG_set0_extensions := _OSSL_CRMF_MSG_set0_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_set0_extensions_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_set0_extensions');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_push0_extension := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_push0_extension_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_push0_extension);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_push0_extension_allownil)}
    OSSL_CRMF_MSG_push0_extension := ERR_OSSL_CRMF_MSG_push0_extension;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_push0_extension_introduced)}
    if LibVersion < OSSL_CRMF_MSG_push0_extension_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_push0_extension)}
      OSSL_CRMF_MSG_push0_extension := FC_OSSL_CRMF_MSG_push0_extension;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_push0_extension_removed)}
    if OSSL_CRMF_MSG_push0_extension_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_push0_extension)}
      OSSL_CRMF_MSG_push0_extension := _OSSL_CRMF_MSG_push0_extension;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_push0_extension_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_push0_extension');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_create_popo := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_create_popo_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_create_popo);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_create_popo_allownil)}
    OSSL_CRMF_MSG_create_popo := ERR_OSSL_CRMF_MSG_create_popo;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_create_popo_introduced)}
    if LibVersion < OSSL_CRMF_MSG_create_popo_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_create_popo)}
      OSSL_CRMF_MSG_create_popo := FC_OSSL_CRMF_MSG_create_popo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_create_popo_removed)}
    if OSSL_CRMF_MSG_create_popo_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_create_popo)}
      OSSL_CRMF_MSG_create_popo := _OSSL_CRMF_MSG_create_popo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_create_popo_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_create_popo');
    {$ifend}
  end;
  
  OSSL_CRMF_MSGS_verify_popo := LoadLibFunction(ADllHandle, OSSL_CRMF_MSGS_verify_popo_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSGS_verify_popo);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSGS_verify_popo_allownil)}
    OSSL_CRMF_MSGS_verify_popo := ERR_OSSL_CRMF_MSGS_verify_popo;
    {$ifend}
    {$if declared(OSSL_CRMF_MSGS_verify_popo_introduced)}
    if LibVersion < OSSL_CRMF_MSGS_verify_popo_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSGS_verify_popo)}
      OSSL_CRMF_MSGS_verify_popo := FC_OSSL_CRMF_MSGS_verify_popo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSGS_verify_popo_removed)}
    if OSSL_CRMF_MSGS_verify_popo_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSGS_verify_popo)}
      OSSL_CRMF_MSGS_verify_popo := _OSSL_CRMF_MSGS_verify_popo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSGS_verify_popo_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSGS_verify_popo');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_get0_tmpl := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_get0_tmpl_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_get0_tmpl);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_get0_tmpl_allownil)}
    OSSL_CRMF_MSG_get0_tmpl := ERR_OSSL_CRMF_MSG_get0_tmpl;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_get0_tmpl_introduced)}
    if LibVersion < OSSL_CRMF_MSG_get0_tmpl_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_get0_tmpl)}
      OSSL_CRMF_MSG_get0_tmpl := FC_OSSL_CRMF_MSG_get0_tmpl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_get0_tmpl_removed)}
    if OSSL_CRMF_MSG_get0_tmpl_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_get0_tmpl)}
      OSSL_CRMF_MSG_get0_tmpl := _OSSL_CRMF_MSG_get0_tmpl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_get0_tmpl_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_get0_tmpl');
    {$ifend}
  end;
  
  OSSL_CRMF_CERTTEMPLATE_get0_publicKey := LoadLibFunction(ADllHandle, OSSL_CRMF_CERTTEMPLATE_get0_publicKey_procname);
  FuncLoadError := not assigned(OSSL_CRMF_CERTTEMPLATE_get0_publicKey);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_CERTTEMPLATE_get0_publicKey_allownil)}
    OSSL_CRMF_CERTTEMPLATE_get0_publicKey := ERR_OSSL_CRMF_CERTTEMPLATE_get0_publicKey;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTTEMPLATE_get0_publicKey_introduced)}
    if LibVersion < OSSL_CRMF_CERTTEMPLATE_get0_publicKey_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_CERTTEMPLATE_get0_publicKey)}
      OSSL_CRMF_CERTTEMPLATE_get0_publicKey := FC_OSSL_CRMF_CERTTEMPLATE_get0_publicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTTEMPLATE_get0_publicKey_removed)}
    if OSSL_CRMF_CERTTEMPLATE_get0_publicKey_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_CERTTEMPLATE_get0_publicKey)}
      OSSL_CRMF_CERTTEMPLATE_get0_publicKey := _OSSL_CRMF_CERTTEMPLATE_get0_publicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_CERTTEMPLATE_get0_publicKey_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_CERTTEMPLATE_get0_publicKey');
    {$ifend}
  end;
  
  OSSL_CRMF_CERTTEMPLATE_get0_subject := LoadLibFunction(ADllHandle, OSSL_CRMF_CERTTEMPLATE_get0_subject_procname);
  FuncLoadError := not assigned(OSSL_CRMF_CERTTEMPLATE_get0_subject);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_CERTTEMPLATE_get0_subject_allownil)}
    OSSL_CRMF_CERTTEMPLATE_get0_subject := ERR_OSSL_CRMF_CERTTEMPLATE_get0_subject;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTTEMPLATE_get0_subject_introduced)}
    if LibVersion < OSSL_CRMF_CERTTEMPLATE_get0_subject_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_CERTTEMPLATE_get0_subject)}
      OSSL_CRMF_CERTTEMPLATE_get0_subject := FC_OSSL_CRMF_CERTTEMPLATE_get0_subject;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTTEMPLATE_get0_subject_removed)}
    if OSSL_CRMF_CERTTEMPLATE_get0_subject_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_CERTTEMPLATE_get0_subject)}
      OSSL_CRMF_CERTTEMPLATE_get0_subject := _OSSL_CRMF_CERTTEMPLATE_get0_subject;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_CERTTEMPLATE_get0_subject_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_CERTTEMPLATE_get0_subject');
    {$ifend}
  end;
  
  OSSL_CRMF_CERTTEMPLATE_get0_issuer := LoadLibFunction(ADllHandle, OSSL_CRMF_CERTTEMPLATE_get0_issuer_procname);
  FuncLoadError := not assigned(OSSL_CRMF_CERTTEMPLATE_get0_issuer);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_CERTTEMPLATE_get0_issuer_allownil)}
    OSSL_CRMF_CERTTEMPLATE_get0_issuer := ERR_OSSL_CRMF_CERTTEMPLATE_get0_issuer;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTTEMPLATE_get0_issuer_introduced)}
    if LibVersion < OSSL_CRMF_CERTTEMPLATE_get0_issuer_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_CERTTEMPLATE_get0_issuer)}
      OSSL_CRMF_CERTTEMPLATE_get0_issuer := FC_OSSL_CRMF_CERTTEMPLATE_get0_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTTEMPLATE_get0_issuer_removed)}
    if OSSL_CRMF_CERTTEMPLATE_get0_issuer_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_CERTTEMPLATE_get0_issuer)}
      OSSL_CRMF_CERTTEMPLATE_get0_issuer := _OSSL_CRMF_CERTTEMPLATE_get0_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_CERTTEMPLATE_get0_issuer_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_CERTTEMPLATE_get0_issuer');
    {$ifend}
  end;
  
  OSSL_CRMF_CERTTEMPLATE_get0_serialNumber := LoadLibFunction(ADllHandle, OSSL_CRMF_CERTTEMPLATE_get0_serialNumber_procname);
  FuncLoadError := not assigned(OSSL_CRMF_CERTTEMPLATE_get0_serialNumber);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_CERTTEMPLATE_get0_serialNumber_allownil)}
    OSSL_CRMF_CERTTEMPLATE_get0_serialNumber := ERR_OSSL_CRMF_CERTTEMPLATE_get0_serialNumber;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTTEMPLATE_get0_serialNumber_introduced)}
    if LibVersion < OSSL_CRMF_CERTTEMPLATE_get0_serialNumber_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_CERTTEMPLATE_get0_serialNumber)}
      OSSL_CRMF_CERTTEMPLATE_get0_serialNumber := FC_OSSL_CRMF_CERTTEMPLATE_get0_serialNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTTEMPLATE_get0_serialNumber_removed)}
    if OSSL_CRMF_CERTTEMPLATE_get0_serialNumber_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_CERTTEMPLATE_get0_serialNumber)}
      OSSL_CRMF_CERTTEMPLATE_get0_serialNumber := _OSSL_CRMF_CERTTEMPLATE_get0_serialNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_CERTTEMPLATE_get0_serialNumber_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_CERTTEMPLATE_get0_serialNumber');
    {$ifend}
  end;
  
  OSSL_CRMF_CERTTEMPLATE_get0_extensions := LoadLibFunction(ADllHandle, OSSL_CRMF_CERTTEMPLATE_get0_extensions_procname);
  FuncLoadError := not assigned(OSSL_CRMF_CERTTEMPLATE_get0_extensions);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_CERTTEMPLATE_get0_extensions_allownil)}
    OSSL_CRMF_CERTTEMPLATE_get0_extensions := ERR_OSSL_CRMF_CERTTEMPLATE_get0_extensions;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTTEMPLATE_get0_extensions_introduced)}
    if LibVersion < OSSL_CRMF_CERTTEMPLATE_get0_extensions_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_CERTTEMPLATE_get0_extensions)}
      OSSL_CRMF_CERTTEMPLATE_get0_extensions := FC_OSSL_CRMF_CERTTEMPLATE_get0_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTTEMPLATE_get0_extensions_removed)}
    if OSSL_CRMF_CERTTEMPLATE_get0_extensions_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_CERTTEMPLATE_get0_extensions)}
      OSSL_CRMF_CERTTEMPLATE_get0_extensions := _OSSL_CRMF_CERTTEMPLATE_get0_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_CERTTEMPLATE_get0_extensions_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_CERTTEMPLATE_get0_extensions');
    {$ifend}
  end;
  
  OSSL_CRMF_CERTID_get0_issuer := LoadLibFunction(ADllHandle, OSSL_CRMF_CERTID_get0_issuer_procname);
  FuncLoadError := not assigned(OSSL_CRMF_CERTID_get0_issuer);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_CERTID_get0_issuer_allownil)}
    OSSL_CRMF_CERTID_get0_issuer := ERR_OSSL_CRMF_CERTID_get0_issuer;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTID_get0_issuer_introduced)}
    if LibVersion < OSSL_CRMF_CERTID_get0_issuer_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_CERTID_get0_issuer)}
      OSSL_CRMF_CERTID_get0_issuer := FC_OSSL_CRMF_CERTID_get0_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTID_get0_issuer_removed)}
    if OSSL_CRMF_CERTID_get0_issuer_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_CERTID_get0_issuer)}
      OSSL_CRMF_CERTID_get0_issuer := _OSSL_CRMF_CERTID_get0_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_CERTID_get0_issuer_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_CERTID_get0_issuer');
    {$ifend}
  end;
  
  OSSL_CRMF_CERTID_get0_serialNumber := LoadLibFunction(ADllHandle, OSSL_CRMF_CERTID_get0_serialNumber_procname);
  FuncLoadError := not assigned(OSSL_CRMF_CERTID_get0_serialNumber);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_CERTID_get0_serialNumber_allownil)}
    OSSL_CRMF_CERTID_get0_serialNumber := ERR_OSSL_CRMF_CERTID_get0_serialNumber;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTID_get0_serialNumber_introduced)}
    if LibVersion < OSSL_CRMF_CERTID_get0_serialNumber_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_CERTID_get0_serialNumber)}
      OSSL_CRMF_CERTID_get0_serialNumber := FC_OSSL_CRMF_CERTID_get0_serialNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTID_get0_serialNumber_removed)}
    if OSSL_CRMF_CERTID_get0_serialNumber_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_CERTID_get0_serialNumber)}
      OSSL_CRMF_CERTID_get0_serialNumber := _OSSL_CRMF_CERTID_get0_serialNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_CERTID_get0_serialNumber_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_CERTID_get0_serialNumber');
    {$ifend}
  end;
  
  OSSL_CRMF_CERTTEMPLATE_fill := LoadLibFunction(ADllHandle, OSSL_CRMF_CERTTEMPLATE_fill_procname);
  FuncLoadError := not assigned(OSSL_CRMF_CERTTEMPLATE_fill);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_CERTTEMPLATE_fill_allownil)}
    OSSL_CRMF_CERTTEMPLATE_fill := ERR_OSSL_CRMF_CERTTEMPLATE_fill;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTTEMPLATE_fill_introduced)}
    if LibVersion < OSSL_CRMF_CERTTEMPLATE_fill_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_CERTTEMPLATE_fill)}
      OSSL_CRMF_CERTTEMPLATE_fill := FC_OSSL_CRMF_CERTTEMPLATE_fill;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_CERTTEMPLATE_fill_removed)}
    if OSSL_CRMF_CERTTEMPLATE_fill_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_CERTTEMPLATE_fill)}
      OSSL_CRMF_CERTTEMPLATE_fill := _OSSL_CRMF_CERTTEMPLATE_fill;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_CERTTEMPLATE_fill_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_CERTTEMPLATE_fill');
    {$ifend}
  end;
  
  OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert := LoadLibFunction(ADllHandle, OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert_procname);
  FuncLoadError := not assigned(OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert_allownil)}
    OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert := ERR_OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert;
    {$ifend}
    {$if declared(OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert_introduced)}
    if LibVersion < OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert)}
      OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert := FC_OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert_removed)}
    if OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert)}
      OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert := _OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert');
    {$ifend}
  end;
  
  OSSL_CRMF_ENCRYPTEDKEY_get1_encCert := LoadLibFunction(ADllHandle, OSSL_CRMF_ENCRYPTEDKEY_get1_encCert_procname);
  FuncLoadError := not assigned(OSSL_CRMF_ENCRYPTEDKEY_get1_encCert);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_ENCRYPTEDKEY_get1_encCert_allownil)}
    OSSL_CRMF_ENCRYPTEDKEY_get1_encCert := ERR_OSSL_CRMF_ENCRYPTEDKEY_get1_encCert;
    {$ifend}
    {$if declared(OSSL_CRMF_ENCRYPTEDKEY_get1_encCert_introduced)}
    if LibVersion < OSSL_CRMF_ENCRYPTEDKEY_get1_encCert_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_ENCRYPTEDKEY_get1_encCert)}
      OSSL_CRMF_ENCRYPTEDKEY_get1_encCert := FC_OSSL_CRMF_ENCRYPTEDKEY_get1_encCert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_ENCRYPTEDKEY_get1_encCert_removed)}
    if OSSL_CRMF_ENCRYPTEDKEY_get1_encCert_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_ENCRYPTEDKEY_get1_encCert)}
      OSSL_CRMF_ENCRYPTEDKEY_get1_encCert := _OSSL_CRMF_ENCRYPTEDKEY_get1_encCert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_ENCRYPTEDKEY_get1_encCert_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_ENCRYPTEDKEY_get1_encCert');
    {$ifend}
  end;
  
  OSSL_CRMF_ENCRYPTEDVALUE_decrypt := LoadLibFunction(ADllHandle, OSSL_CRMF_ENCRYPTEDVALUE_decrypt_procname);
  FuncLoadError := not assigned(OSSL_CRMF_ENCRYPTEDVALUE_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_ENCRYPTEDVALUE_decrypt_allownil)}
    OSSL_CRMF_ENCRYPTEDVALUE_decrypt := ERR_OSSL_CRMF_ENCRYPTEDVALUE_decrypt;
    {$ifend}
    {$if declared(OSSL_CRMF_ENCRYPTEDVALUE_decrypt_introduced)}
    if LibVersion < OSSL_CRMF_ENCRYPTEDVALUE_decrypt_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_ENCRYPTEDVALUE_decrypt)}
      OSSL_CRMF_ENCRYPTEDVALUE_decrypt := FC_OSSL_CRMF_ENCRYPTEDVALUE_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_ENCRYPTEDVALUE_decrypt_removed)}
    if OSSL_CRMF_ENCRYPTEDVALUE_decrypt_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_ENCRYPTEDVALUE_decrypt)}
      OSSL_CRMF_ENCRYPTEDVALUE_decrypt := _OSSL_CRMF_ENCRYPTEDVALUE_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_ENCRYPTEDVALUE_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_ENCRYPTEDVALUE_decrypt');
    {$ifend}
  end;
  
  OSSL_CRMF_ENCRYPTEDKEY_get1_pkey := LoadLibFunction(ADllHandle, OSSL_CRMF_ENCRYPTEDKEY_get1_pkey_procname);
  FuncLoadError := not assigned(OSSL_CRMF_ENCRYPTEDKEY_get1_pkey);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_ENCRYPTEDKEY_get1_pkey_allownil)}
    OSSL_CRMF_ENCRYPTEDKEY_get1_pkey := ERR_OSSL_CRMF_ENCRYPTEDKEY_get1_pkey;
    {$ifend}
    {$if declared(OSSL_CRMF_ENCRYPTEDKEY_get1_pkey_introduced)}
    if LibVersion < OSSL_CRMF_ENCRYPTEDKEY_get1_pkey_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_ENCRYPTEDKEY_get1_pkey)}
      OSSL_CRMF_ENCRYPTEDKEY_get1_pkey := FC_OSSL_CRMF_ENCRYPTEDKEY_get1_pkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_ENCRYPTEDKEY_get1_pkey_removed)}
    if OSSL_CRMF_ENCRYPTEDKEY_get1_pkey_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_ENCRYPTEDKEY_get1_pkey)}
      OSSL_CRMF_ENCRYPTEDKEY_get1_pkey := _OSSL_CRMF_ENCRYPTEDKEY_get1_pkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_ENCRYPTEDKEY_get1_pkey_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_ENCRYPTEDKEY_get1_pkey');
    {$ifend}
  end;
  
  OSSL_CRMF_MSG_centralkeygen_requested := LoadLibFunction(ADllHandle, OSSL_CRMF_MSG_centralkeygen_requested_procname);
  FuncLoadError := not assigned(OSSL_CRMF_MSG_centralkeygen_requested);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_MSG_centralkeygen_requested_allownil)}
    OSSL_CRMF_MSG_centralkeygen_requested := ERR_OSSL_CRMF_MSG_centralkeygen_requested;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_centralkeygen_requested_introduced)}
    if LibVersion < OSSL_CRMF_MSG_centralkeygen_requested_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_MSG_centralkeygen_requested)}
      OSSL_CRMF_MSG_centralkeygen_requested := FC_OSSL_CRMF_MSG_centralkeygen_requested;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_MSG_centralkeygen_requested_removed)}
    if OSSL_CRMF_MSG_centralkeygen_requested_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_MSG_centralkeygen_requested)}
      OSSL_CRMF_MSG_centralkeygen_requested := _OSSL_CRMF_MSG_centralkeygen_requested;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_MSG_centralkeygen_requested_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_MSG_centralkeygen_requested');
    {$ifend}
  end;
  
  OSSL_CRMF_ENCRYPTEDKEY_init_envdata := LoadLibFunction(ADllHandle, OSSL_CRMF_ENCRYPTEDKEY_init_envdata_procname);
  FuncLoadError := not assigned(OSSL_CRMF_ENCRYPTEDKEY_init_envdata);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CRMF_ENCRYPTEDKEY_init_envdata_allownil)}
    OSSL_CRMF_ENCRYPTEDKEY_init_envdata := ERR_OSSL_CRMF_ENCRYPTEDKEY_init_envdata;
    {$ifend}
    {$if declared(OSSL_CRMF_ENCRYPTEDKEY_init_envdata_introduced)}
    if LibVersion < OSSL_CRMF_ENCRYPTEDKEY_init_envdata_introduced then
    begin
      {$if declared(FC_OSSL_CRMF_ENCRYPTEDKEY_init_envdata)}
      OSSL_CRMF_ENCRYPTEDKEY_init_envdata := FC_OSSL_CRMF_ENCRYPTEDKEY_init_envdata;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CRMF_ENCRYPTEDKEY_init_envdata_removed)}
    if OSSL_CRMF_ENCRYPTEDKEY_init_envdata_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CRMF_ENCRYPTEDKEY_init_envdata)}
      OSSL_CRMF_ENCRYPTEDKEY_init_envdata := _OSSL_CRMF_ENCRYPTEDKEY_init_envdata;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CRMF_ENCRYPTEDKEY_init_envdata_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CRMF_ENCRYPTEDKEY_init_envdata');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  OSSL_CRMF_ENCRYPTEDVALUE_new := nil;
  OSSL_CRMF_ENCRYPTEDVALUE_free := nil;
  d2i_OSSL_CRMF_ENCRYPTEDVALUE := nil;
  i2d_OSSL_CRMF_ENCRYPTEDVALUE := nil;
  OSSL_CRMF_ENCRYPTEDVALUE_it := nil;
  OSSL_CRMF_ENCRYPTEDKEY_new := nil;
  OSSL_CRMF_ENCRYPTEDKEY_free := nil;
  d2i_OSSL_CRMF_ENCRYPTEDKEY := nil;
  i2d_OSSL_CRMF_ENCRYPTEDKEY := nil;
  OSSL_CRMF_ENCRYPTEDKEY_it := nil;
  OSSL_CRMF_MSG_new := nil;
  OSSL_CRMF_MSG_free := nil;
  d2i_OSSL_CRMF_MSG := nil;
  i2d_OSSL_CRMF_MSG := nil;
  OSSL_CRMF_MSG_it := nil;
  OSSL_CRMF_MSG_dup := nil;
  OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free := nil;
  OSSL_CRMF_ATTRIBUTETYPEANDVALUE_dup := nil;
  OSSL_CRMF_PBMPARAMETER_new := nil;
  OSSL_CRMF_PBMPARAMETER_free := nil;
  d2i_OSSL_CRMF_PBMPARAMETER := nil;
  i2d_OSSL_CRMF_PBMPARAMETER := nil;
  OSSL_CRMF_PBMPARAMETER_it := nil;
  OSSL_CRMF_CERTID_new := nil;
  OSSL_CRMF_CERTID_free := nil;
  d2i_OSSL_CRMF_CERTID := nil;
  i2d_OSSL_CRMF_CERTID := nil;
  OSSL_CRMF_CERTID_it := nil;
  OSSL_CRMF_CERTID_dup := nil;
  OSSL_CRMF_PKIPUBLICATIONINFO_new := nil;
  OSSL_CRMF_PKIPUBLICATIONINFO_free := nil;
  d2i_OSSL_CRMF_PKIPUBLICATIONINFO := nil;
  i2d_OSSL_CRMF_PKIPUBLICATIONINFO := nil;
  OSSL_CRMF_PKIPUBLICATIONINFO_it := nil;
  OSSL_CRMF_SINGLEPUBINFO_new := nil;
  OSSL_CRMF_SINGLEPUBINFO_free := nil;
  d2i_OSSL_CRMF_SINGLEPUBINFO := nil;
  i2d_OSSL_CRMF_SINGLEPUBINFO := nil;
  OSSL_CRMF_SINGLEPUBINFO_it := nil;
  OSSL_CRMF_CERTTEMPLATE_new := nil;
  OSSL_CRMF_CERTTEMPLATE_free := nil;
  d2i_OSSL_CRMF_CERTTEMPLATE := nil;
  i2d_OSSL_CRMF_CERTTEMPLATE := nil;
  OSSL_CRMF_CERTTEMPLATE_it := nil;
  OSSL_CRMF_CERTTEMPLATE_dup := nil;
  OSSL_CRMF_MSGS_new := nil;
  OSSL_CRMF_MSGS_free := nil;
  d2i_OSSL_CRMF_MSGS := nil;
  i2d_OSSL_CRMF_MSGS := nil;
  OSSL_CRMF_MSGS_it := nil;
  OSSL_CRMF_pbmp_new := nil;
  OSSL_CRMF_pbm_new := nil;
  OSSL_CRMF_MSG_set1_regCtrl_regToken := nil;
  OSSL_CRMF_MSG_get0_regCtrl_regToken := nil;
  OSSL_CRMF_MSG_set1_regCtrl_authenticator := nil;
  OSSL_CRMF_MSG_get0_regCtrl_authenticator := nil;
  OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo := nil;
  OSSL_CRMF_MSG_set0_SinglePubInfo := nil;
  OSSL_CRMF_MSG_set_PKIPublicationInfo_action := nil;
  OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo := nil;
  OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo := nil;
  OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey := nil;
  OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey := nil;
  OSSL_CRMF_MSG_set1_regCtrl_oldCertID := nil;
  OSSL_CRMF_MSG_get0_regCtrl_oldCertID := nil;
  OSSL_CRMF_CERTID_gen := nil;
  OSSL_CRMF_MSG_set1_regInfo_utf8Pairs := nil;
  OSSL_CRMF_MSG_get0_regInfo_utf8Pairs := nil;
  OSSL_CRMF_MSG_set1_regInfo_certReq := nil;
  OSSL_CRMF_MSG_get0_regInfo_certReq := nil;
  OSSL_CRMF_MSG_set0_validity := nil;
  OSSL_CRMF_MSG_set_certReqId := nil;
  OSSL_CRMF_MSG_get_certReqId := nil;
  OSSL_CRMF_MSG_set0_extensions := nil;
  OSSL_CRMF_MSG_push0_extension := nil;
  OSSL_CRMF_MSG_create_popo := nil;
  OSSL_CRMF_MSGS_verify_popo := nil;
  OSSL_CRMF_MSG_get0_tmpl := nil;
  OSSL_CRMF_CERTTEMPLATE_get0_publicKey := nil;
  OSSL_CRMF_CERTTEMPLATE_get0_subject := nil;
  OSSL_CRMF_CERTTEMPLATE_get0_issuer := nil;
  OSSL_CRMF_CERTTEMPLATE_get0_serialNumber := nil;
  OSSL_CRMF_CERTTEMPLATE_get0_extensions := nil;
  OSSL_CRMF_CERTID_get0_issuer := nil;
  OSSL_CRMF_CERTID_get0_serialNumber := nil;
  OSSL_CRMF_CERTTEMPLATE_fill := nil;
  OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert := nil;
  OSSL_CRMF_ENCRYPTEDKEY_get1_encCert := nil;
  OSSL_CRMF_ENCRYPTEDVALUE_decrypt := nil;
  OSSL_CRMF_ENCRYPTEDKEY_get1_pkey := nil;
  OSSL_CRMF_MSG_centralkeygen_requested := nil;
  OSSL_CRMF_ENCRYPTEDKEY_init_envdata := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.