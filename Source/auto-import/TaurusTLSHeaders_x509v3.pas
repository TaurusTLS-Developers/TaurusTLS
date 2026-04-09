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

unit TaurusTLSHeaders_x509v3;

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
  Pv3_ext_method = ^Tv3_ext_method;
  Tv3_ext_method = record end;
  {$EXTERNALSYM Pv3_ext_method}

  Pv3_ext_ctx = ^Tv3_ext_ctx;
  Tv3_ext_ctx = record end;
  {$EXTERNALSYM Pv3_ext_ctx}

  PX509V3_CONF_METHOD_st = ^TX509V3_CONF_METHOD_st;
  TX509V3_CONF_METHOD_st = record end;
  {$EXTERNALSYM PX509V3_CONF_METHOD_st}

  PX509V3_CONF_METHOD = ^TX509V3_CONF_METHOD;
  TX509V3_CONF_METHOD = TX509V3_CONF_METHOD_st;
  {$EXTERNALSYM PX509V3_CONF_METHOD}

  PX509V3_EXT_METHOD = ^TX509V3_EXT_METHOD;
  TX509V3_EXT_METHOD = Tv3_ext_method;
  {$EXTERNALSYM PX509V3_EXT_METHOD}

  Pstack_st_X509V3_EXT_METHOD = ^Tstack_st_X509V3_EXT_METHOD;
  Tstack_st_X509V3_EXT_METHOD = record end;
  {$EXTERNALSYM Pstack_st_X509V3_EXT_METHOD}

  PENUMERATED_NAMES = ^TENUMERATED_NAMES;
  TENUMERATED_NAMES = TBIT_STRING_BITNAME;
  {$EXTERNALSYM PENUMERATED_NAMES}

  PBASIC_CONSTRAINTS_st = ^TBASIC_CONSTRAINTS_st;
  TBASIC_CONSTRAINTS_st = record end;
  {$EXTERNALSYM PBASIC_CONSTRAINTS_st}

  PBASIC_CONSTRAINTS = ^TBASIC_CONSTRAINTS;
  TBASIC_CONSTRAINTS = TBASIC_CONSTRAINTS_st;
  {$EXTERNALSYM PBASIC_CONSTRAINTS}

  POSSL_BASIC_ATTR_CONSTRAINTS_st = ^TOSSL_BASIC_ATTR_CONSTRAINTS_st;
  TOSSL_BASIC_ATTR_CONSTRAINTS_st = record end;
  {$EXTERNALSYM POSSL_BASIC_ATTR_CONSTRAINTS_st}

  POSSL_BASIC_ATTR_CONSTRAINTS = ^TOSSL_BASIC_ATTR_CONSTRAINTS;
  TOSSL_BASIC_ATTR_CONSTRAINTS = TOSSL_BASIC_ATTR_CONSTRAINTS_st;
  {$EXTERNALSYM POSSL_BASIC_ATTR_CONSTRAINTS}

  PPKEY_USAGE_PERIOD_st = ^TPKEY_USAGE_PERIOD_st;
  TPKEY_USAGE_PERIOD_st = record end;
  {$EXTERNALSYM PPKEY_USAGE_PERIOD_st}

  PPKEY_USAGE_PERIOD = ^TPKEY_USAGE_PERIOD;
  TPKEY_USAGE_PERIOD = TPKEY_USAGE_PERIOD_st;
  {$EXTERNALSYM PPKEY_USAGE_PERIOD}

  PotherName_st = ^TotherName_st;
  TotherName_st = record end;
  {$EXTERNALSYM PotherName_st}

  POTHERNAME = ^TOTHERNAME;
  TOTHERNAME = TotherName_st;
  {$EXTERNALSYM POTHERNAME}

  PEDIPartyName_st = ^TEDIPartyName_st;
  TEDIPartyName_st = record end;
  {$EXTERNALSYM PEDIPartyName_st}

  PEDIPARTYNAME = ^TEDIPARTYNAME;
  TEDIPARTYNAME = TEDIPartyName_st;
  {$EXTERNALSYM PEDIPARTYNAME}

  PGENERAL_NAME_st = ^TGENERAL_NAME_st;
  TGENERAL_NAME_st = record end;
  {$EXTERNALSYM PGENERAL_NAME_st}

  Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:186:5) = ^Tunion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:186:5);
  {$EXTERNALSYM Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:186:5)}

  PGENERAL_NAME = ^TGENERAL_NAME;
  TGENERAL_NAME = TGENERAL_NAME_st;
  {$EXTERNALSYM PGENERAL_NAME}

  PACCESS_DESCRIPTION_st = ^TACCESS_DESCRIPTION_st;
  TACCESS_DESCRIPTION_st = record end;
  {$EXTERNALSYM PACCESS_DESCRIPTION_st}

  PACCESS_DESCRIPTION = ^TACCESS_DESCRIPTION;
  TACCESS_DESCRIPTION = TACCESS_DESCRIPTION_st;
  {$EXTERNALSYM PACCESS_DESCRIPTION}

  Pstack_st_ACCESS_DESCRIPTION = ^Tstack_st_ACCESS_DESCRIPTION;
  Tstack_st_ACCESS_DESCRIPTION = record end;
  {$EXTERNALSYM Pstack_st_ACCESS_DESCRIPTION}

  Pstack_st_GENERAL_NAME = ^Tstack_st_GENERAL_NAME;
  Tstack_st_GENERAL_NAME = record end;
  {$EXTERNALSYM Pstack_st_GENERAL_NAME}

  PAUTHORITY_INFO_ACCESS = ^TAUTHORITY_INFO_ACCESS;
  TAUTHORITY_INFO_ACCESS = Tstack_st_ACCESS_DESCRIPTION;
  {$EXTERNALSYM PAUTHORITY_INFO_ACCESS}

  PEXTENDED_KEY_USAGE = ^TEXTENDED_KEY_USAGE;
  TEXTENDED_KEY_USAGE = Tstack_st_ASN1_OBJECT;
  {$EXTERNALSYM PEXTENDED_KEY_USAGE}

  PLS_FEATURE = ^TLS_FEATURE;
  TLS_FEATURE = Tstack_st_ASN1_INTEGER;
  {$EXTERNALSYM PLS_FEATURE}

  PGENERAL_NAMES = ^TGENERAL_NAMES;
  TGENERAL_NAMES = Tstack_st_GENERAL_NAME;
  {$EXTERNALSYM PGENERAL_NAMES}

  Pstack_st_GENERAL_NAMES = ^Tstack_st_GENERAL_NAMES;
  Tstack_st_GENERAL_NAMES = record end;
  {$EXTERNALSYM Pstack_st_GENERAL_NAMES}

  PDIST_POINT_NAME_st = ^TDIST_POINT_NAME_st;
  TDIST_POINT_NAME_st = record end;
  {$EXTERNALSYM PDIST_POINT_NAME_st}

  Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:307:5) = ^Tunion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:307:5);
  {$EXTERNALSYM Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:307:5)}

  PDIST_POINT_NAME = ^TDIST_POINT_NAME;
  TDIST_POINT_NAME = TDIST_POINT_NAME_st;
  {$EXTERNALSYM PDIST_POINT_NAME}

  PDIST_POINT_st = ^TDIST_POINT_st;
  TDIST_POINT_st = record end;
  {$EXTERNALSYM PDIST_POINT_st}

  Pstack_st_DIST_POINT = ^Tstack_st_DIST_POINT;
  Tstack_st_DIST_POINT = record end;
  {$EXTERNALSYM Pstack_st_DIST_POINT}

  PCRL_DIST_POINTS = ^TCRL_DIST_POINTS;
  TCRL_DIST_POINTS = Tstack_st_DIST_POINT;
  {$EXTERNALSYM PCRL_DIST_POINTS}

  PAUTHORITY_KEYID_st = ^TAUTHORITY_KEYID_st;
  TAUTHORITY_KEYID_st = record end;
  {$EXTERNALSYM PAUTHORITY_KEYID_st}

  PSXNET_ID_st = ^TSXNET_ID_st;
  TSXNET_ID_st = record end;
  {$EXTERNALSYM PSXNET_ID_st}

  PSXNETID = ^TSXNETID;
  TSXNETID = TSXNET_ID_st;
  {$EXTERNALSYM PSXNETID}

  Pstack_st_SXNETID = ^Tstack_st_SXNETID;
  Tstack_st_SXNETID = record end;
  {$EXTERNALSYM Pstack_st_SXNETID}

  PSXNET_st = ^TSXNET_st;
  TSXNET_st = record end;
  {$EXTERNALSYM PSXNET_st}

  PSXNET = ^TSXNET;
  TSXNET = TSXNET_st;
  {$EXTERNALSYM PSXNET}

  PISSUER_SIGN_TOOL_st = ^TISSUER_SIGN_TOOL_st;
  TISSUER_SIGN_TOOL_st = record end;
  {$EXTERNALSYM PISSUER_SIGN_TOOL_st}

  PISSUER_SIGN_TOOL = ^TISSUER_SIGN_TOOL;
  TISSUER_SIGN_TOOL = TISSUER_SIGN_TOOL_st;
  {$EXTERNALSYM PISSUER_SIGN_TOOL}

  PNOTICEREF_st = ^TNOTICEREF_st;
  TNOTICEREF_st = record end;
  {$EXTERNALSYM PNOTICEREF_st}

  PNOTICEREF = ^TNOTICEREF;
  TNOTICEREF = TNOTICEREF_st;
  {$EXTERNALSYM PNOTICEREF}

  PUSERNOTICE_st = ^TUSERNOTICE_st;
  TUSERNOTICE_st = record end;
  {$EXTERNALSYM PUSERNOTICE_st}

  PUSERNOTICE = ^TUSERNOTICE;
  TUSERNOTICE = TUSERNOTICE_st;
  {$EXTERNALSYM PUSERNOTICE}

  PPOLICYQUALINFO_st = ^TPOLICYQUALINFO_st;
  TPOLICYQUALINFO_st = record end;
  {$EXTERNALSYM PPOLICYQUALINFO_st}

  Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:436:5) = ^Tunion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:436:5);
  {$EXTERNALSYM Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:436:5)}

  PPOLICYQUALINFO = ^TPOLICYQUALINFO;
  TPOLICYQUALINFO = TPOLICYQUALINFO_st;
  {$EXTERNALSYM PPOLICYQUALINFO}

  Pstack_st_POLICYQUALINFO = ^Tstack_st_POLICYQUALINFO;
  Tstack_st_POLICYQUALINFO = record end;
  {$EXTERNALSYM Pstack_st_POLICYQUALINFO}

  PPOLICYINFO_st = ^TPOLICYINFO_st;
  TPOLICYINFO_st = record end;
  {$EXTERNALSYM PPOLICYINFO_st}

  PPOLICYINFO = ^TPOLICYINFO;
  TPOLICYINFO = TPOLICYINFO_st;
  {$EXTERNALSYM PPOLICYINFO}

  Pstack_st_POLICYINFO = ^Tstack_st_POLICYINFO;
  Tstack_st_POLICYINFO = record end;
  {$EXTERNALSYM Pstack_st_POLICYINFO}

  PCERTIFICATEPOLICIES = ^TCERTIFICATEPOLICIES;
  TCERTIFICATEPOLICIES = Tstack_st_POLICYINFO;
  {$EXTERNALSYM PCERTIFICATEPOLICIES}

  PPOLICY_MAPPING_st = ^TPOLICY_MAPPING_st;
  TPOLICY_MAPPING_st = record end;
  {$EXTERNALSYM PPOLICY_MAPPING_st}

  PPOLICY_MAPPING = ^TPOLICY_MAPPING;
  TPOLICY_MAPPING = TPOLICY_MAPPING_st;
  {$EXTERNALSYM PPOLICY_MAPPING}

  Pstack_st_POLICY_MAPPING = ^Tstack_st_POLICY_MAPPING;
  Tstack_st_POLICY_MAPPING = record end;
  {$EXTERNALSYM Pstack_st_POLICY_MAPPING}

  PPOLICY_MAPPINGS = ^TPOLICY_MAPPINGS;
  TPOLICY_MAPPINGS = Tstack_st_POLICY_MAPPING;
  {$EXTERNALSYM PPOLICY_MAPPINGS}

  PGENERAL_SUBTREE_st = ^TGENERAL_SUBTREE_st;
  TGENERAL_SUBTREE_st = record end;
  {$EXTERNALSYM PGENERAL_SUBTREE_st}

  PGENERAL_SUBTREE = ^TGENERAL_SUBTREE;
  TGENERAL_SUBTREE = TGENERAL_SUBTREE_st;
  {$EXTERNALSYM PGENERAL_SUBTREE}

  Pstack_st_GENERAL_SUBTREE = ^Tstack_st_GENERAL_SUBTREE;
  Tstack_st_GENERAL_SUBTREE = record end;
  {$EXTERNALSYM Pstack_st_GENERAL_SUBTREE}

  PNAME_CONSTRAINTS_st = ^TNAME_CONSTRAINTS_st;
  TNAME_CONSTRAINTS_st = record end;
  {$EXTERNALSYM PNAME_CONSTRAINTS_st}

  PPOLICY_CONSTRAINTS_st = ^TPOLICY_CONSTRAINTS_st;
  TPOLICY_CONSTRAINTS_st = record end;
  {$EXTERNALSYM PPOLICY_CONSTRAINTS_st}

  PPOLICY_CONSTRAINTS = ^TPOLICY_CONSTRAINTS;
  TPOLICY_CONSTRAINTS = TPOLICY_CONSTRAINTS_st;
  {$EXTERNALSYM PPOLICY_CONSTRAINTS}

  PPROXY_POLICY_st = ^TPROXY_POLICY_st;
  TPROXY_POLICY_st = record end;
  {$EXTERNALSYM PPROXY_POLICY_st}

  PPROXY_POLICY = ^TPROXY_POLICY;
  TPROXY_POLICY = TPROXY_POLICY_st;
  {$EXTERNALSYM PPROXY_POLICY}

  PPROXY_CERT_INFO_EXTENSION_st = ^TPROXY_CERT_INFO_EXTENSION_st;
  TPROXY_CERT_INFO_EXTENSION_st = record end;
  {$EXTERNALSYM PPROXY_CERT_INFO_EXTENSION_st}

  PPROXY_CERT_INFO_EXTENSION = ^TPROXY_CERT_INFO_EXTENSION;
  TPROXY_CERT_INFO_EXTENSION = TPROXY_CERT_INFO_EXTENSION_st;
  {$EXTERNALSYM PPROXY_CERT_INFO_EXTENSION}

  PISSUING_DIST_POINT_st = ^TISSUING_DIST_POINT_st;
  TISSUING_DIST_POINT_st = record end;
  {$EXTERNALSYM PISSUING_DIST_POINT_st}

  Px509_purpose_st = ^Tx509_purpose_st;
  Tx509_purpose_st = record end;
  {$EXTERNALSYM Px509_purpose_st}

  PX509_PURPOSE = ^TX509_PURPOSE;
  TX509_PURPOSE = Tx509_purpose_st;
  {$EXTERNALSYM PX509_PURPOSE}

  Pstack_st_X509_PURPOSE = ^Tstack_st_X509_PURPOSE;
  Tstack_st_X509_PURPOSE = record end;
  {$EXTERNALSYM Pstack_st_X509_PURPOSE}

  Pstack_st_X509_POLICY_NODE = ^Tstack_st_X509_POLICY_NODE;
  Tstack_st_X509_POLICY_NODE = record end;
  {$EXTERNALSYM Pstack_st_X509_POLICY_NODE}

  PASRange_st = ^TASRange_st;
  TASRange_st = record end;
  {$EXTERNALSYM PASRange_st}

  PASRange = ^TASRange;
  TASRange = TASRange_st;
  {$EXTERNALSYM PASRange}

  PASIdOrRange_st = ^TASIdOrRange_st;
  TASIdOrRange_st = record end;
  {$EXTERNALSYM PASIdOrRange_st}

  Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1126:5) = ^Tunion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1126:5);
  {$EXTERNALSYM Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1126:5)}

  PASIdOrRange = ^TASIdOrRange;
  TASIdOrRange = TASIdOrRange_st;
  {$EXTERNALSYM PASIdOrRange}

  Pstack_st_ASIdOrRange = ^Tstack_st_ASIdOrRange;
  Tstack_st_ASIdOrRange = record end;
  {$EXTERNALSYM Pstack_st_ASIdOrRange}

  PASIdOrRanges = ^TASIdOrRanges;
  TASIdOrRanges = Tstack_st_ASIdOrRange;
  {$EXTERNALSYM PASIdOrRanges}

  PASIdentifierChoice_st = ^TASIdentifierChoice_st;
  TASIdentifierChoice_st = record end;
  {$EXTERNALSYM PASIdentifierChoice_st}

  Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1169:5) = ^Tunion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1169:5);
  {$EXTERNALSYM Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1169:5)}

  PASIdentifierChoice = ^TASIdentifierChoice;
  TASIdentifierChoice = TASIdentifierChoice_st;
  {$EXTERNALSYM PASIdentifierChoice}

  PASIdentifiers_st = ^TASIdentifiers_st;
  TASIdentifiers_st = record end;
  {$EXTERNALSYM PASIdentifiers_st}

  PASIdentifiers = ^TASIdentifiers;
  TASIdentifiers = TASIdentifiers_st;
  {$EXTERNALSYM PASIdentifiers}

  PIPAddressRange_st = ^TIPAddressRange_st;
  TIPAddressRange_st = record end;
  {$EXTERNALSYM PIPAddressRange_st}

  PIPAddressRange = ^TIPAddressRange;
  TIPAddressRange = TIPAddressRange_st;
  {$EXTERNALSYM PIPAddressRange}

  PIPAddressOrRange_st = ^TIPAddressOrRange_st;
  TIPAddressOrRange_st = record end;
  {$EXTERNALSYM PIPAddressOrRange_st}

  Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1193:5) = ^Tunion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1193:5);
  {$EXTERNALSYM Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1193:5)}

  PIPAddressOrRange = ^TIPAddressOrRange;
  TIPAddressOrRange = TIPAddressOrRange_st;
  {$EXTERNALSYM PIPAddressOrRange}

  Pstack_st_IPAddressOrRange = ^Tstack_st_IPAddressOrRange;
  Tstack_st_IPAddressOrRange = record end;
  {$EXTERNALSYM Pstack_st_IPAddressOrRange}

  PIPAddressOrRanges = ^TIPAddressOrRanges;
  TIPAddressOrRanges = Tstack_st_IPAddressOrRange;
  {$EXTERNALSYM PIPAddressOrRanges}

  PIPAddressChoice_st = ^TIPAddressChoice_st;
  TIPAddressChoice_st = record end;
  {$EXTERNALSYM PIPAddressChoice_st}

  Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1236:5) = ^Tunion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1236:5);
  {$EXTERNALSYM Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1236:5)}

  PIPAddressChoice = ^TIPAddressChoice;
  TIPAddressChoice = TIPAddressChoice_st;
  {$EXTERNALSYM PIPAddressChoice}

  PIPAddressFamily_st = ^TIPAddressFamily_st;
  TIPAddressFamily_st = record end;
  {$EXTERNALSYM PIPAddressFamily_st}

  PIPAddressFamily = ^TIPAddressFamily;
  TIPAddressFamily = TIPAddressFamily_st;
  {$EXTERNALSYM PIPAddressFamily}

  Pstack_st_IPAddressFamily = ^Tstack_st_IPAddressFamily;
  Tstack_st_IPAddressFamily = record end;
  {$EXTERNALSYM Pstack_st_IPAddressFamily}

  PIPAddrBlocks = ^TIPAddrBlocks;
  TIPAddrBlocks = Tstack_st_IPAddressFamily;
  {$EXTERNALSYM PIPAddrBlocks}

  Pstack_st_ASN1_STRING = ^Tstack_st_ASN1_STRING;
  Tstack_st_ASN1_STRING = record end;
  {$EXTERNALSYM Pstack_st_ASN1_STRING}

  PNamingAuthority_st = ^TNamingAuthority_st;
  TNamingAuthority_st = record end;
  {$EXTERNALSYM PNamingAuthority_st}

  PNAMING_AUTHORITY = ^TNAMING_AUTHORITY;
  TNAMING_AUTHORITY = TNamingAuthority_st;
  {$EXTERNALSYM PNAMING_AUTHORITY}

  PProfessionInfo_st = ^TProfessionInfo_st;
  TProfessionInfo_st = record end;
  {$EXTERNALSYM PProfessionInfo_st}

  PPROFESSION_INFO = ^TPROFESSION_INFO;
  TPROFESSION_INFO = TProfessionInfo_st;
  {$EXTERNALSYM PPROFESSION_INFO}

  PAdmissions_st = ^TAdmissions_st;
  TAdmissions_st = record end;
  {$EXTERNALSYM PAdmissions_st}

  PADMISSIONS = ^TADMISSIONS;
  TADMISSIONS = TAdmissions_st;
  {$EXTERNALSYM PADMISSIONS}

  PAdmissionSyntax_st = ^TAdmissionSyntax_st;
  TAdmissionSyntax_st = record end;
  {$EXTERNALSYM PAdmissionSyntax_st}

  PADMISSION_SYNTAX = ^TADMISSION_SYNTAX;
  TADMISSION_SYNTAX = TAdmissionSyntax_st;
  {$EXTERNALSYM PADMISSION_SYNTAX}

  Pstack_st_PROFESSION_INFO = ^Tstack_st_PROFESSION_INFO;
  Tstack_st_PROFESSION_INFO = record end;
  {$EXTERNALSYM Pstack_st_PROFESSION_INFO}

  Pstack_st_ADMISSIONS = ^Tstack_st_ADMISSIONS;
  Tstack_st_ADMISSIONS = record end;
  {$EXTERNALSYM Pstack_st_ADMISSIONS}

  PPROFESSION_INFOS = ^TPROFESSION_INFOS;
  TPROFESSION_INFOS = Tstack_st_PROFESSION_INFO;
  {$EXTERNALSYM PPROFESSION_INFOS}

  POSSL_ATTRIBUTES_SYNTAX = ^TOSSL_ATTRIBUTES_SYNTAX;
  TOSSL_ATTRIBUTES_SYNTAX = Tstack_st_X509_ATTRIBUTE;
  {$EXTERNALSYM POSSL_ATTRIBUTES_SYNTAX}

  Pstack_st_USERNOTICE = ^Tstack_st_USERNOTICE;
  Tstack_st_USERNOTICE = record end;
  {$EXTERNALSYM Pstack_st_USERNOTICE}

  POSSL_USER_NOTICE_SYNTAX = ^TOSSL_USER_NOTICE_SYNTAX;
  TOSSL_USER_NOTICE_SYNTAX = Tstack_st_USERNOTICE;
  {$EXTERNALSYM POSSL_USER_NOTICE_SYNTAX}

  POSSL_ROLE_SPEC_CERT_ID_st = ^TOSSL_ROLE_SPEC_CERT_ID_st;
  TOSSL_ROLE_SPEC_CERT_ID_st = record end;
  {$EXTERNALSYM POSSL_ROLE_SPEC_CERT_ID_st}

  POSSL_ROLE_SPEC_CERT_ID = ^TOSSL_ROLE_SPEC_CERT_ID;
  TOSSL_ROLE_SPEC_CERT_ID = TOSSL_ROLE_SPEC_CERT_ID_st;
  {$EXTERNALSYM POSSL_ROLE_SPEC_CERT_ID}

  Pstack_st_OSSL_ROLE_SPEC_CERT_ID = ^Tstack_st_OSSL_ROLE_SPEC_CERT_ID;
  Tstack_st_OSSL_ROLE_SPEC_CERT_ID = record end;
  {$EXTERNALSYM Pstack_st_OSSL_ROLE_SPEC_CERT_ID}

  POSSL_ROLE_SPEC_CERT_ID_SYNTAX = ^TOSSL_ROLE_SPEC_CERT_ID_SYNTAX;
  TOSSL_ROLE_SPEC_CERT_ID_SYNTAX = Tstack_st_OSSL_ROLE_SPEC_CERT_ID;
  {$EXTERNALSYM POSSL_ROLE_SPEC_CERT_ID_SYNTAX}

  POSSL_HASH_st = ^TOSSL_HASH_st;
  TOSSL_HASH_st = record end;
  {$EXTERNALSYM POSSL_HASH_st}

  POSSL_HASH = ^TOSSL_HASH;
  TOSSL_HASH = TOSSL_HASH_st;
  {$EXTERNALSYM POSSL_HASH}

  POSSL_INFO_SYNTAX_POINTER_st = ^TOSSL_INFO_SYNTAX_POINTER_st;
  TOSSL_INFO_SYNTAX_POINTER_st = record end;
  {$EXTERNALSYM POSSL_INFO_SYNTAX_POINTER_st}

  POSSL_INFO_SYNTAX_POINTER = ^TOSSL_INFO_SYNTAX_POINTER;
  TOSSL_INFO_SYNTAX_POINTER = TOSSL_INFO_SYNTAX_POINTER_st;
  {$EXTERNALSYM POSSL_INFO_SYNTAX_POINTER}

  POSSL_INFO_SYNTAX_st = ^TOSSL_INFO_SYNTAX_st;
  TOSSL_INFO_SYNTAX_st = record end;
  {$EXTERNALSYM POSSL_INFO_SYNTAX_st}

  Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1590:5) = ^Tunion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1590:5);
  {$EXTERNALSYM Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1590:5)}

  POSSL_INFO_SYNTAX = ^TOSSL_INFO_SYNTAX;
  TOSSL_INFO_SYNTAX = TOSSL_INFO_SYNTAX_st;
  {$EXTERNALSYM POSSL_INFO_SYNTAX}

  POSSL_PRIVILEGE_POLICY_ID_st = ^TOSSL_PRIVILEGE_POLICY_ID_st;
  TOSSL_PRIVILEGE_POLICY_ID_st = record end;
  {$EXTERNALSYM POSSL_PRIVILEGE_POLICY_ID_st}

  POSSL_PRIVILEGE_POLICY_ID = ^TOSSL_PRIVILEGE_POLICY_ID;
  TOSSL_PRIVILEGE_POLICY_ID = TOSSL_PRIVILEGE_POLICY_ID_st;
  {$EXTERNALSYM POSSL_PRIVILEGE_POLICY_ID}

  POSSL_ATTRIBUTE_DESCRIPTOR_st = ^TOSSL_ATTRIBUTE_DESCRIPTOR_st;
  TOSSL_ATTRIBUTE_DESCRIPTOR_st = record end;
  {$EXTERNALSYM POSSL_ATTRIBUTE_DESCRIPTOR_st}

  POSSL_ATTRIBUTE_DESCRIPTOR = ^TOSSL_ATTRIBUTE_DESCRIPTOR;
  TOSSL_ATTRIBUTE_DESCRIPTOR = TOSSL_ATTRIBUTE_DESCRIPTOR_st;
  {$EXTERNALSYM POSSL_ATTRIBUTE_DESCRIPTOR}

  POSSL_TIME_SPEC_ABSOLUTE_st = ^TOSSL_TIME_SPEC_ABSOLUTE_st;
  TOSSL_TIME_SPEC_ABSOLUTE_st = record end;
  {$EXTERNALSYM POSSL_TIME_SPEC_ABSOLUTE_st}

  POSSL_TIME_SPEC_ABSOLUTE = ^TOSSL_TIME_SPEC_ABSOLUTE;
  TOSSL_TIME_SPEC_ABSOLUTE = TOSSL_TIME_SPEC_ABSOLUTE_st;
  {$EXTERNALSYM POSSL_TIME_SPEC_ABSOLUTE}

  POSSL_DAY_TIME_st = ^TOSSL_DAY_TIME_st;
  TOSSL_DAY_TIME_st = record end;
  {$EXTERNALSYM POSSL_DAY_TIME_st}

  POSSL_DAY_TIME = ^TOSSL_DAY_TIME;
  TOSSL_DAY_TIME = TOSSL_DAY_TIME_st;
  {$EXTERNALSYM POSSL_DAY_TIME}

  POSSL_DAY_TIME_BAND_st = ^TOSSL_DAY_TIME_BAND_st;
  TOSSL_DAY_TIME_BAND_st = record end;
  {$EXTERNALSYM POSSL_DAY_TIME_BAND_st}

  POSSL_DAY_TIME_BAND = ^TOSSL_DAY_TIME_BAND;
  TOSSL_DAY_TIME_BAND = TOSSL_DAY_TIME_BAND_st;
  {$EXTERNALSYM POSSL_DAY_TIME_BAND}

  POSSL_NAMED_DAY_st = ^TOSSL_NAMED_DAY_st;
  TOSSL_NAMED_DAY_st = record end;
  {$EXTERNALSYM POSSL_NAMED_DAY_st}

  Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1650:5) = ^Tunion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1650:5);
  {$EXTERNALSYM Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1650:5)}

  POSSL_NAMED_DAY = ^TOSSL_NAMED_DAY;
  TOSSL_NAMED_DAY = TOSSL_NAMED_DAY_st;
  {$EXTERNALSYM POSSL_NAMED_DAY}

  POSSL_TIME_SPEC_X_DAY_OF_st = ^TOSSL_TIME_SPEC_X_DAY_OF_st;
  TOSSL_TIME_SPEC_X_DAY_OF_st = record end;
  {$EXTERNALSYM POSSL_TIME_SPEC_X_DAY_OF_st}

  Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1664:5) = ^Tunion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1664:5);
  {$EXTERNALSYM Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1664:5)}

  POSSL_TIME_SPEC_X_DAY_OF = ^TOSSL_TIME_SPEC_X_DAY_OF;
  TOSSL_TIME_SPEC_X_DAY_OF = TOSSL_TIME_SPEC_X_DAY_OF_st;
  {$EXTERNALSYM POSSL_TIME_SPEC_X_DAY_OF}

  POSSL_TIME_SPEC_DAY_st = ^TOSSL_TIME_SPEC_DAY_st;
  TOSSL_TIME_SPEC_DAY_st = record end;
  {$EXTERNALSYM POSSL_TIME_SPEC_DAY_st}

  Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1693:5) = ^Tunion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1693:5);
  {$EXTERNALSYM Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1693:5)}

  POSSL_TIME_SPEC_DAY = ^TOSSL_TIME_SPEC_DAY;
  TOSSL_TIME_SPEC_DAY = TOSSL_TIME_SPEC_DAY_st;
  {$EXTERNALSYM POSSL_TIME_SPEC_DAY}

  POSSL_TIME_SPEC_WEEKS_st = ^TOSSL_TIME_SPEC_WEEKS_st;
  TOSSL_TIME_SPEC_WEEKS_st = record end;
  {$EXTERNALSYM POSSL_TIME_SPEC_WEEKS_st}

  Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1711:5) = ^Tunion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1711:5);
  {$EXTERNALSYM Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1711:5)}

  POSSL_TIME_SPEC_WEEKS = ^TOSSL_TIME_SPEC_WEEKS;
  TOSSL_TIME_SPEC_WEEKS = TOSSL_TIME_SPEC_WEEKS_st;
  {$EXTERNALSYM POSSL_TIME_SPEC_WEEKS}

  POSSL_TIME_SPEC_MONTH_st = ^TOSSL_TIME_SPEC_MONTH_st;
  TOSSL_TIME_SPEC_MONTH_st = record end;
  {$EXTERNALSYM POSSL_TIME_SPEC_MONTH_st}

  Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1748:5) = ^Tunion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1748:5);
  {$EXTERNALSYM Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1748:5)}

  POSSL_TIME_SPEC_MONTH = ^TOSSL_TIME_SPEC_MONTH;
  TOSSL_TIME_SPEC_MONTH = TOSSL_TIME_SPEC_MONTH_st;
  {$EXTERNALSYM POSSL_TIME_SPEC_MONTH}

  POSSL_TIME_PERIOD_st = ^TOSSL_TIME_PERIOD_st;
  TOSSL_TIME_PERIOD_st = record end;
  {$EXTERNALSYM POSSL_TIME_PERIOD_st}

  Pstack_st_OSSL_DAY_TIME_BAND = ^Tstack_st_OSSL_DAY_TIME_BAND;
  Tstack_st_OSSL_DAY_TIME_BAND = record end;
  {$EXTERNALSYM Pstack_st_OSSL_DAY_TIME_BAND}

  POSSL_TIME_PERIOD = ^TOSSL_TIME_PERIOD;
  TOSSL_TIME_PERIOD = TOSSL_TIME_PERIOD_st;
  {$EXTERNALSYM POSSL_TIME_PERIOD}

  POSSL_TIME_SPEC_TIME_st = ^TOSSL_TIME_SPEC_TIME_st;
  TOSSL_TIME_SPEC_TIME_st = record end;
  {$EXTERNALSYM POSSL_TIME_SPEC_TIME_st}

  Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1768:5) = ^Tunion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1768:5);
  {$EXTERNALSYM Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1768:5)}

  Pstack_st_OSSL_TIME_PERIOD = ^Tstack_st_OSSL_TIME_PERIOD;
  Tstack_st_OSSL_TIME_PERIOD = record end;
  {$EXTERNALSYM Pstack_st_OSSL_TIME_PERIOD}

  POSSL_TIME_SPEC_TIME = ^TOSSL_TIME_SPEC_TIME;
  TOSSL_TIME_SPEC_TIME = TOSSL_TIME_SPEC_TIME_st;
  {$EXTERNALSYM POSSL_TIME_SPEC_TIME}

  POSSL_TIME_SPEC_st = ^TOSSL_TIME_SPEC_st;
  TOSSL_TIME_SPEC_st = record end;
  {$EXTERNALSYM POSSL_TIME_SPEC_st}

  POSSL_TIME_SPEC = ^TOSSL_TIME_SPEC;
  TOSSL_TIME_SPEC = TOSSL_TIME_SPEC_st;
  {$EXTERNALSYM POSSL_TIME_SPEC}

  Patav_st = ^Tatav_st;
  Tatav_st = record end;
  {$EXTERNALSYM Patav_st}

  POSSL_ATAV = ^TOSSL_ATAV;
  TOSSL_ATAV = Tatav_st;
  {$EXTERNALSYM POSSL_ATAV}

  PATTRIBUTE_TYPE_MAPPING_st = ^TATTRIBUTE_TYPE_MAPPING_st;
  TATTRIBUTE_TYPE_MAPPING_st = record end;
  {$EXTERNALSYM PATTRIBUTE_TYPE_MAPPING_st}

  POSSL_ATTRIBUTE_TYPE_MAPPING = ^TOSSL_ATTRIBUTE_TYPE_MAPPING;
  TOSSL_ATTRIBUTE_TYPE_MAPPING = TATTRIBUTE_TYPE_MAPPING_st;
  {$EXTERNALSYM POSSL_ATTRIBUTE_TYPE_MAPPING}

  PATTRIBUTE_VALUE_MAPPING_st = ^TATTRIBUTE_VALUE_MAPPING_st;
  TATTRIBUTE_VALUE_MAPPING_st = record end;
  {$EXTERNALSYM PATTRIBUTE_VALUE_MAPPING_st}

  POSSL_ATTRIBUTE_VALUE_MAPPING = ^TOSSL_ATTRIBUTE_VALUE_MAPPING;
  TOSSL_ATTRIBUTE_VALUE_MAPPING = TATTRIBUTE_VALUE_MAPPING_st;
  {$EXTERNALSYM POSSL_ATTRIBUTE_VALUE_MAPPING}

  PATTRIBUTE_MAPPING_st = ^TATTRIBUTE_MAPPING_st;
  TATTRIBUTE_MAPPING_st = record end;
  {$EXTERNALSYM PATTRIBUTE_MAPPING_st}

  Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1873:5) = ^Tunion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1873:5);
  {$EXTERNALSYM Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1873:5)}

  POSSL_ATTRIBUTE_MAPPING = ^TOSSL_ATTRIBUTE_MAPPING;
  TOSSL_ATTRIBUTE_MAPPING = TATTRIBUTE_MAPPING_st;
  {$EXTERNALSYM POSSL_ATTRIBUTE_MAPPING}

  Pstack_st_OSSL_ATTRIBUTE_MAPPING = ^Tstack_st_OSSL_ATTRIBUTE_MAPPING;
  Tstack_st_OSSL_ATTRIBUTE_MAPPING = record end;
  {$EXTERNALSYM Pstack_st_OSSL_ATTRIBUTE_MAPPING}

  POSSL_ATTRIBUTE_MAPPINGS = ^TOSSL_ATTRIBUTE_MAPPINGS;
  TOSSL_ATTRIBUTE_MAPPINGS = Tstack_st_OSSL_ATTRIBUTE_MAPPING;
  {$EXTERNALSYM POSSL_ATTRIBUTE_MAPPINGS}

  PALLOWED_ATTRIBUTES_CHOICE_st = ^TALLOWED_ATTRIBUTES_CHOICE_st;
  TALLOWED_ATTRIBUTES_CHOICE_st = record end;
  {$EXTERNALSYM PALLOWED_ATTRIBUTES_CHOICE_st}

  Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1921:5) = ^Tunion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1921:5);
  {$EXTERNALSYM Punion (unnamed at /home/sasha/dev/openssl/include/openssl/x509v3.h:1921:5)}

  POSSL_ALLOWED_ATTRIBUTES_CHOICE = ^TOSSL_ALLOWED_ATTRIBUTES_CHOICE;
  TOSSL_ALLOWED_ATTRIBUTES_CHOICE = TALLOWED_ATTRIBUTES_CHOICE_st;
  {$EXTERNALSYM POSSL_ALLOWED_ATTRIBUTES_CHOICE}

  PALLOWED_ATTRIBUTES_ITEM_st = ^TALLOWED_ATTRIBUTES_ITEM_st;
  TALLOWED_ATTRIBUTES_ITEM_st = record end;
  {$EXTERNALSYM PALLOWED_ATTRIBUTES_ITEM_st}

  Pstack_st_OSSL_ALLOWED_ATTRIBUTES_CHOICE = ^Tstack_st_OSSL_ALLOWED_ATTRIBUTES_CHOICE;
  Tstack_st_OSSL_ALLOWED_ATTRIBUTES_CHOICE = record end;
  {$EXTERNALSYM Pstack_st_OSSL_ALLOWED_ATTRIBUTES_CHOICE}

  POSSL_ALLOWED_ATTRIBUTES_ITEM = ^TOSSL_ALLOWED_ATTRIBUTES_ITEM;
  TOSSL_ALLOWED_ATTRIBUTES_ITEM = TALLOWED_ATTRIBUTES_ITEM_st;
  {$EXTERNALSYM POSSL_ALLOWED_ATTRIBUTES_ITEM}

  Pstack_st_OSSL_ALLOWED_ATTRIBUTES_ITEM = ^Tstack_st_OSSL_ALLOWED_ATTRIBUTES_ITEM;
  Tstack_st_OSSL_ALLOWED_ATTRIBUTES_ITEM = record end;
  {$EXTERNALSYM Pstack_st_OSSL_ALLOWED_ATTRIBUTES_ITEM}

  POSSL_ALLOWED_ATTRIBUTES_SYNTAX = ^TOSSL_ALLOWED_ATTRIBUTES_SYNTAX;
  TOSSL_ALLOWED_ATTRIBUTES_SYNTAX = Tstack_st_OSSL_ALLOWED_ATTRIBUTES_ITEM;
  {$EXTERNALSYM POSSL_ALLOWED_ATTRIBUTES_SYNTAX}

  PAA_DIST_POINT_st = ^TAA_DIST_POINT_st;
  TAA_DIST_POINT_st = record end;
  {$EXTERNALSYM PAA_DIST_POINT_st}

  POSSL_AA_DIST_POINT = ^TOSSL_AA_DIST_POINT;
  TOSSL_AA_DIST_POINT = TAA_DIST_POINT_st;
  {$EXTERNALSYM POSSL_AA_DIST_POINT}


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  TX509V3_EXT_NEW_func_cb = function: Pointer; cdecl;
  TX509V3_EXT_FREE_func_cb = procedure(arg1: Pointer); cdecl;
  TX509V3_EXT_D2I_func_cb = function(arg1: Pointer; arg2: PPIdAnsiChar; arg3: TIdC_LONG): Pointer; cdecl;
  TX509V3_EXT_I2D_func_cb = function(arg1: Pointer; arg2: PPIdAnsiChar): TIdC_INT; cdecl;
  TX509V3_EXT_I2V_func_cb = function(arg1: Pv3_ext_method; arg2: Pointer; arg3: Pstack_st_CONF_VALUE): Pstack_st_CONF_VALUE; cdecl;
  TX509V3_EXT_V2I_func_cb = function(arg1: Pv3_ext_method; arg2: Pv3_ext_ctx; arg3: Pstack_st_CONF_VALUE): Pointer; cdecl;
  TX509V3_EXT_I2S_func_cb = function(arg1: Pv3_ext_method; arg2: Pointer): PIdAnsiChar; cdecl;
  TX509V3_EXT_S2I_func_cb = function(arg1: Pv3_ext_method; arg2: Pv3_ext_ctx; arg3: PIdAnsiChar): Pointer; cdecl;
  TX509V3_EXT_I2R_func_cb = function(arg1: Pv3_ext_method; arg2: Pointer; arg3: PBIO; arg4: TIdC_INT): TIdC_INT; cdecl;
  Tsk_X509V3_EXT_METHOD_compfunc_func_cb = function(arg1: PPX509V3_EXT_METHOD; arg2: PPX509V3_EXT_METHOD): TIdC_INT; cdecl;
  Tsk_X509V3_EXT_METHOD_freefunc_func_cb = procedure(arg1: PX509V3_EXT_METHOD); cdecl;
  Tsk_X509V3_EXT_METHOD_copyfunc_func_cb = function(arg1: PX509V3_EXT_METHOD): PX509V3_EXT_METHOD; cdecl;
  Tsk_ACCESS_DESCRIPTION_compfunc_func_cb = function(arg1: PPACCESS_DESCRIPTION; arg2: PPACCESS_DESCRIPTION): TIdC_INT; cdecl;
  Tsk_ACCESS_DESCRIPTION_freefunc_func_cb = procedure(arg1: PACCESS_DESCRIPTION); cdecl;
  Tsk_ACCESS_DESCRIPTION_copyfunc_func_cb = function(arg1: PACCESS_DESCRIPTION): PACCESS_DESCRIPTION; cdecl;
  Tsk_GENERAL_NAME_compfunc_func_cb = function(arg1: PPGENERAL_NAME; arg2: PPGENERAL_NAME): TIdC_INT; cdecl;
  Tsk_GENERAL_NAME_freefunc_func_cb = procedure(arg1: PGENERAL_NAME); cdecl;
  Tsk_GENERAL_NAME_copyfunc_func_cb = function(arg1: PGENERAL_NAME): PGENERAL_NAME; cdecl;
  Tsk_GENERAL_NAMES_compfunc_func_cb = function(arg1: PPGENERAL_NAMES; arg2: PPGENERAL_NAMES): TIdC_INT; cdecl;
  Tsk_GENERAL_NAMES_freefunc_func_cb = procedure(arg1: PGENERAL_NAMES); cdecl;
  Tsk_GENERAL_NAMES_copyfunc_func_cb = function(arg1: PGENERAL_NAMES): PGENERAL_NAMES; cdecl;
  Tsk_DIST_POINT_compfunc_func_cb = function(arg1: PPDIST_POINT; arg2: PPDIST_POINT): TIdC_INT; cdecl;
  Tsk_DIST_POINT_freefunc_func_cb = procedure(arg1: PDIST_POINT); cdecl;
  Tsk_DIST_POINT_copyfunc_func_cb = function(arg1: PDIST_POINT): PDIST_POINT; cdecl;
  Tsk_SXNETID_compfunc_func_cb = function(arg1: PPSXNETID; arg2: PPSXNETID): TIdC_INT; cdecl;
  Tsk_SXNETID_freefunc_func_cb = procedure(arg1: PSXNETID); cdecl;
  Tsk_SXNETID_copyfunc_func_cb = function(arg1: PSXNETID): PSXNETID; cdecl;
  Tsk_POLICYQUALINFO_compfunc_func_cb = function(arg1: PPPOLICYQUALINFO; arg2: PPPOLICYQUALINFO): TIdC_INT; cdecl;
  Tsk_POLICYQUALINFO_freefunc_func_cb = procedure(arg1: PPOLICYQUALINFO); cdecl;
  Tsk_POLICYQUALINFO_copyfunc_func_cb = function(arg1: PPOLICYQUALINFO): PPOLICYQUALINFO; cdecl;
  Tsk_POLICYINFO_compfunc_func_cb = function(arg1: PPPOLICYINFO; arg2: PPPOLICYINFO): TIdC_INT; cdecl;
  Tsk_POLICYINFO_freefunc_func_cb = procedure(arg1: PPOLICYINFO); cdecl;
  Tsk_POLICYINFO_copyfunc_func_cb = function(arg1: PPOLICYINFO): PPOLICYINFO; cdecl;
  Tsk_POLICY_MAPPING_compfunc_func_cb = function(arg1: PPPOLICY_MAPPING; arg2: PPPOLICY_MAPPING): TIdC_INT; cdecl;
  Tsk_POLICY_MAPPING_freefunc_func_cb = procedure(arg1: PPOLICY_MAPPING); cdecl;
  Tsk_POLICY_MAPPING_copyfunc_func_cb = function(arg1: PPOLICY_MAPPING): PPOLICY_MAPPING; cdecl;
  Tsk_GENERAL_SUBTREE_compfunc_func_cb = function(arg1: PPGENERAL_SUBTREE; arg2: PPGENERAL_SUBTREE): TIdC_INT; cdecl;
  Tsk_GENERAL_SUBTREE_freefunc_func_cb = procedure(arg1: PGENERAL_SUBTREE); cdecl;
  Tsk_GENERAL_SUBTREE_copyfunc_func_cb = function(arg1: PGENERAL_SUBTREE): PGENERAL_SUBTREE; cdecl;
  Tsk_X509_PURPOSE_compfunc_func_cb = function(arg1: PPX509_PURPOSE; arg2: PPX509_PURPOSE): TIdC_INT; cdecl;
  Tsk_X509_PURPOSE_freefunc_func_cb = procedure(arg1: PX509_PURPOSE); cdecl;
  Tsk_X509_PURPOSE_copyfunc_func_cb = function(arg1: PX509_PURPOSE): PX509_PURPOSE; cdecl;
  TX509_PURPOSE_add_ck_cb = function(arg1: PX509_PURPOSE; arg2: PX509; arg3: TIdC_INT): TIdC_INT; cdecl;
  Tsk_X509_POLICY_NODE_compfunc_func_cb = function(arg1: PPX509_POLICY_NODE; arg2: PPX509_POLICY_NODE): TIdC_INT; cdecl;
  Tsk_X509_POLICY_NODE_freefunc_func_cb = procedure(arg1: PX509_POLICY_NODE); cdecl;
  Tsk_X509_POLICY_NODE_copyfunc_func_cb = function(arg1: PX509_POLICY_NODE): PX509_POLICY_NODE; cdecl;
  Tsk_ASIdOrRange_compfunc_func_cb = function(arg1: PPASIdOrRange; arg2: PPASIdOrRange): TIdC_INT; cdecl;
  Tsk_ASIdOrRange_freefunc_func_cb = procedure(arg1: PASIdOrRange); cdecl;
  Tsk_ASIdOrRange_copyfunc_func_cb = function(arg1: PASIdOrRange): PASIdOrRange; cdecl;
  Tsk_IPAddressOrRange_compfunc_func_cb = function(arg1: PPIPAddressOrRange; arg2: PPIPAddressOrRange): TIdC_INT; cdecl;
  Tsk_IPAddressOrRange_freefunc_func_cb = procedure(arg1: PIPAddressOrRange); cdecl;
  Tsk_IPAddressOrRange_copyfunc_func_cb = function(arg1: PIPAddressOrRange): PIPAddressOrRange; cdecl;
  Tsk_IPAddressFamily_compfunc_func_cb = function(arg1: PPIPAddressFamily; arg2: PPIPAddressFamily): TIdC_INT; cdecl;
  Tsk_IPAddressFamily_freefunc_func_cb = procedure(arg1: PIPAddressFamily); cdecl;
  Tsk_IPAddressFamily_copyfunc_func_cb = function(arg1: PIPAddressFamily): PIPAddressFamily; cdecl;
  Tsk_ASN1_STRING_compfunc_func_cb = function(arg1: PPASN1_STRING; arg2: PPASN1_STRING): TIdC_INT; cdecl;
  Tsk_ASN1_STRING_freefunc_func_cb = procedure(arg1: PASN1_STRING); cdecl;
  Tsk_ASN1_STRING_copyfunc_func_cb = function(arg1: PASN1_STRING): PASN1_STRING; cdecl;
  Tsk_PROFESSION_INFO_compfunc_func_cb = function(arg1: PPPROFESSION_INFO; arg2: PPPROFESSION_INFO): TIdC_INT; cdecl;
  Tsk_PROFESSION_INFO_freefunc_func_cb = procedure(arg1: PPROFESSION_INFO); cdecl;
  Tsk_PROFESSION_INFO_copyfunc_func_cb = function(arg1: PPROFESSION_INFO): PPROFESSION_INFO; cdecl;
  Tsk_ADMISSIONS_compfunc_func_cb = function(arg1: PPADMISSIONS; arg2: PPADMISSIONS): TIdC_INT; cdecl;
  Tsk_ADMISSIONS_freefunc_func_cb = procedure(arg1: PADMISSIONS); cdecl;
  Tsk_ADMISSIONS_copyfunc_func_cb = function(arg1: PADMISSIONS): PADMISSIONS; cdecl;
  Tsk_USERNOTICE_compfunc_func_cb = function(arg1: PPUSERNOTICE; arg2: PPUSERNOTICE): TIdC_INT; cdecl;
  Tsk_USERNOTICE_freefunc_func_cb = procedure(arg1: PUSERNOTICE); cdecl;
  Tsk_USERNOTICE_copyfunc_func_cb = function(arg1: PUSERNOTICE): PUSERNOTICE; cdecl;
  Tsk_OSSL_ROLE_SPEC_CERT_ID_compfunc_func_cb = function(arg1: PPOSSL_ROLE_SPEC_CERT_ID; arg2: PPOSSL_ROLE_SPEC_CERT_ID): TIdC_INT; cdecl;
  Tsk_OSSL_ROLE_SPEC_CERT_ID_freefunc_func_cb = procedure(arg1: POSSL_ROLE_SPEC_CERT_ID); cdecl;
  Tsk_OSSL_ROLE_SPEC_CERT_ID_copyfunc_func_cb = function(arg1: POSSL_ROLE_SPEC_CERT_ID): POSSL_ROLE_SPEC_CERT_ID; cdecl;
  Tsk_OSSL_TIME_PERIOD_compfunc_func_cb = function(arg1: PPOSSL_TIME_PERIOD; arg2: PPOSSL_TIME_PERIOD): TIdC_INT; cdecl;
  Tsk_OSSL_TIME_PERIOD_freefunc_func_cb = procedure(arg1: POSSL_TIME_PERIOD); cdecl;
  Tsk_OSSL_TIME_PERIOD_copyfunc_func_cb = function(arg1: POSSL_TIME_PERIOD): POSSL_TIME_PERIOD; cdecl;
  Tsk_OSSL_DAY_TIME_BAND_compfunc_func_cb = function(arg1: PPOSSL_DAY_TIME_BAND; arg2: PPOSSL_DAY_TIME_BAND): TIdC_INT; cdecl;
  Tsk_OSSL_DAY_TIME_BAND_freefunc_func_cb = procedure(arg1: POSSL_DAY_TIME_BAND); cdecl;
  Tsk_OSSL_DAY_TIME_BAND_copyfunc_func_cb = function(arg1: POSSL_DAY_TIME_BAND): POSSL_DAY_TIME_BAND; cdecl;
  Tsk_OSSL_ATTRIBUTE_MAPPING_compfunc_func_cb = function(arg1: PPOSSL_ATTRIBUTE_MAPPING; arg2: PPOSSL_ATTRIBUTE_MAPPING): TIdC_INT; cdecl;
  Tsk_OSSL_ATTRIBUTE_MAPPING_freefunc_func_cb = procedure(arg1: POSSL_ATTRIBUTE_MAPPING); cdecl;
  Tsk_OSSL_ATTRIBUTE_MAPPING_copyfunc_func_cb = function(arg1: POSSL_ATTRIBUTE_MAPPING): POSSL_ATTRIBUTE_MAPPING; cdecl;
  Tsk_OSSL_ALLOWED_ATTRIBUTES_CHOICE_compfunc_func_cb = function(arg1: PPOSSL_ALLOWED_ATTRIBUTES_CHOICE; arg2: PPOSSL_ALLOWED_ATTRIBUTES_CHOICE): TIdC_INT; cdecl;
  Tsk_OSSL_ALLOWED_ATTRIBUTES_CHOICE_freefunc_func_cb = procedure(arg1: POSSL_ALLOWED_ATTRIBUTES_CHOICE); cdecl;
  Tsk_OSSL_ALLOWED_ATTRIBUTES_CHOICE_copyfunc_func_cb = function(arg1: POSSL_ALLOWED_ATTRIBUTES_CHOICE): POSSL_ALLOWED_ATTRIBUTES_CHOICE; cdecl;
  Tsk_OSSL_ALLOWED_ATTRIBUTES_ITEM_compfunc_func_cb = function(arg1: PPOSSL_ALLOWED_ATTRIBUTES_ITEM; arg2: PPOSSL_ALLOWED_ATTRIBUTES_ITEM): TIdC_INT; cdecl;
  Tsk_OSSL_ALLOWED_ATTRIBUTES_ITEM_freefunc_func_cb = procedure(arg1: POSSL_ALLOWED_ATTRIBUTES_ITEM); cdecl;
  Tsk_OSSL_ALLOWED_ATTRIBUTES_ITEM_copyfunc_func_cb = function(arg1: POSSL_ALLOWED_ATTRIBUTES_ITEM): POSSL_ALLOWED_ATTRIBUTES_ITEM; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  X509V3_CTX_TEST = $1;
  CTX_TEST = X509V3_CTX_TEST;
  X509V3_CTX_REPLACE = $2;
  X509V3_EXT_DYNAMIC = $1;
  X509V3_EXT_CTX_DEP = $2;
  X509V3_EXT_MULTILINE = $4;
  GEN_OTHERNAME = 0;
  GEN_EMAIL = 1;
  GEN_DNS = 2;
  GEN_X400 = 3;
  GEN_DIRNAME = 4;
  GEN_EDIPARTY = 5;
  GEN_URI = 6;
  GEN_IPADD = 7;
  GEN_RID = 8;
  CRLDP_ALL_REASONS = $807f;
  CRL_REASON_NONE = -1;
  CRL_REASON_UNSPECIFIED = 0;
  CRL_REASON_KEY_COMPROMISE = 1;
  CRL_REASON_CA_COMPROMISE = 2;
  CRL_REASON_AFFILIATION_CHANGED = 3;
  CRL_REASON_SUPERSEDED = 4;
  CRL_REASON_CESSATION_OF_OPERATION = 5;
  CRL_REASON_CERTIFICATE_HOLD = 6;
  CRL_REASON_REMOVE_FROM_CRL = 8;
  CRL_REASON_PRIVILEGE_WITHDRAWN = 9;
  CRL_REASON_AA_COMPROMISE = 10;
  IDP_PRESENT = $1;
  IDP_INVALID = $2;
  IDP_ONLYUSER = $4;
  IDP_ONLYCA = $8;
  IDP_ONLYATTR = $10;
  IDP_INDIRECT = $20;
  IDP_REASONS = $40;
  EXT_END = {-1,0,0,0,0,0,0,0,0,0,0,0,0,0};
  EXFLAG_BCONS = $1;
  EXFLAG_KUSAGE = $2;
  EXFLAG_XKUSAGE = $4;
  EXFLAG_NSCERT = $8;
  EXFLAG_CA = $10;
  EXFLAG_SI = $20;
  EXFLAG_V1 = $40;
  EXFLAG_INVALID = $80;
  EXFLAG_SET = $100;
  EXFLAG_CRITICAL = $200;
  EXFLAG_PROXY = $400;
  EXFLAG_INVALID_POLICY = $800;
  EXFLAG_FRESHEST = $1000;
  EXFLAG_SS = $2000;
  EXFLAG_BCONS_CRITICAL = $10000;
  EXFLAG_AKID_CRITICAL = $20000;
  EXFLAG_SKID_CRITICAL = $40000;
  EXFLAG_SAN_CRITICAL = $80000;
  EXFLAG_NO_FINGERPRINT = $100000;
  KU_DIGITAL_SIGNATURE = X509v3_KU_DIGITAL_SIGNATURE;
  KU_NON_REPUDIATION = X509v3_KU_NON_REPUDIATION;
  KU_KEY_ENCIPHERMENT = X509v3_KU_KEY_ENCIPHERMENT;
  KU_DATA_ENCIPHERMENT = X509v3_KU_DATA_ENCIPHERMENT;
  KU_KEY_AGREEMENT = X509v3_KU_KEY_AGREEMENT;
  KU_KEY_CERT_SIGN = X509v3_KU_KEY_CERT_SIGN;
  KU_CRL_SIGN = X509v3_KU_CRL_SIGN;
  KU_ENCIPHER_ONLY = X509v3_KU_ENCIPHER_ONLY;
  KU_DECIPHER_ONLY = X509v3_KU_DECIPHER_ONLY;
  NS_SSL_CLIENT = $80;
  NS_SSL_SERVER = $40;
  NS_SMIME = $20;
  NS_OBJSIGN = $10;
  NS_SSL_CA = $04;
  NS_SMIME_CA = $02;
  NS_OBJSIGN_CA = $01;
  NS_ANY_CA = (NS_SSL_CA or NS_SMIME_CA or NS_OBJSIGN_CA);
  XKU_SSL_SERVER = $1;
  XKU_SSL_CLIENT = $2;
  XKU_SMIME = $4;
  XKU_CODE_SIGN = $8;
  XKU_SGC = $10;
  XKU_OCSP_SIGN = $20;
  XKU_TIMESTAMP = $40;
  XKU_DVCS = $80;
  XKU_ANYEKU = $100;
  X509_PURPOSE_DYNAMIC = $1;
  X509_PURPOSE_DYNAMIC_NAME = $2;
  X509_PURPOSE_DEFAULT_ANY = 0;
  X509_PURPOSE_SSL_CLIENT = 1;
  X509_PURPOSE_SSL_SERVER = 2;
  X509_PURPOSE_NS_SSL_SERVER = 3;
  X509_PURPOSE_SMIME_SIGN = 4;
  X509_PURPOSE_SMIME_ENCRYPT = 5;
  X509_PURPOSE_CRL_SIGN = 6;
  X509_PURPOSE_ANY = 7;
  X509_PURPOSE_OCSP_HELPER = 8;
  X509_PURPOSE_TIMESTAMP_SIGN = 9;
  X509_PURPOSE_CODE_SIGN = 10;
  X509_PURPOSE_MIN = 1;
  X509_PURPOSE_MAX = 10;
  X509V3_EXT_UNKNOWN_MASK = ($fL shl 16);
  X509V3_EXT_DEFAULT = 0;
  X509V3_EXT_ERROR_UNKNOWN = (1 shl 16);
  X509V3_EXT_PARSE_UNKNOWN = (2 shl 16);
  X509V3_EXT_DUMP_UNKNOWN = (3 shl 16);
  X509V3_ADD_OP_MASK = $fL;
  X509V3_ADD_DEFAULT = 0;
  X509V3_ADD_APPEND = 1;
  X509V3_ADD_REPLACE = 2;
  X509V3_ADD_REPLACE_EXISTING = 3;
  X509V3_ADD_KEEP_EXISTING = 4;
  X509V3_ADD_DELETE = 5;
  X509V3_ADD_SILENT = $10;
  hex_to_string = OPENSSL_buf2hexstr;
  string_to_hex = OPENSSL_hexstr2buf;
  X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT = $1;
  X509_CHECK_FLAG_NO_WILDCARDS = $2;
  X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS = $4;
  X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS = $8;
  X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS = $10;
  X509_CHECK_FLAG_NEVER_CHECK_SUBJECT = $20;
  _X509_CHECK_FLAG_DOT_SUBDOMAINS = $8000;
  ASIdOrRange_id = 0;
  ASIdOrRange_range = 1;
  ASIdentifierChoice_inherit = 0;
  ASIdentifierChoice_asIdsOrRanges = 1;
  IPAddressOrRange_addressPrefix = 0;
  IPAddressOrRange_addressRange = 1;
  IPAddressChoice_inherit = 0;
  IPAddressChoice_addressesOrRanges = 1;
  V3_ASID_ASNUM = 0;
  V3_ASID_RDI = 1;
  IANA_AFI_IPV4 = 1;
  IANA_AFI_IPV6 = 2;
  OSSL_INFO_SYNTAX_TYPE_CONTENT = 0;
  OSSL_INFO_SYNTAX_TYPE_POINTER = 1;
  OSSL_NAMED_DAY_TYPE_INT = 0;
  OSSL_NAMED_DAY_TYPE_BIT = 1;
  OSSL_NAMED_DAY_INT_SUN = 1;
  OSSL_NAMED_DAY_INT_MON = 2;
  OSSL_NAMED_DAY_INT_TUE = 3;
  OSSL_NAMED_DAY_INT_WED = 4;
  OSSL_NAMED_DAY_INT_THU = 5;
  OSSL_NAMED_DAY_INT_FRI = 6;
  OSSL_NAMED_DAY_INT_SAT = 7;
  OSSL_NAMED_DAY_BIT_SUN = 0;
  OSSL_NAMED_DAY_BIT_MON = 1;
  OSSL_NAMED_DAY_BIT_TUE = 2;
  OSSL_NAMED_DAY_BIT_WED = 3;
  OSSL_NAMED_DAY_BIT_THU = 4;
  OSSL_NAMED_DAY_BIT_FRI = 5;
  OSSL_NAMED_DAY_BIT_SAT = 6;
  OSSL_TIME_SPEC_X_DAY_OF_FIRST = 0;
  OSSL_TIME_SPEC_X_DAY_OF_SECOND = 1;
  OSSL_TIME_SPEC_X_DAY_OF_THIRD = 2;
  OSSL_TIME_SPEC_X_DAY_OF_FOURTH = 3;
  OSSL_TIME_SPEC_X_DAY_OF_FIFTH = 4;
  OSSL_TIME_SPEC_DAY_TYPE_INT = 0;
  OSSL_TIME_SPEC_DAY_TYPE_BIT = 1;
  OSSL_TIME_SPEC_DAY_TYPE_DAY_OF = 2;
  OSSL_TIME_SPEC_DAY_BIT_SUN = 0;
  OSSL_TIME_SPEC_DAY_BIT_MON = 1;
  OSSL_TIME_SPEC_DAY_BIT_TUE = 2;
  OSSL_TIME_SPEC_DAY_BIT_WED = 3;
  OSSL_TIME_SPEC_DAY_BIT_THU = 4;
  OSSL_TIME_SPEC_DAY_BIT_FRI = 5;
  OSSL_TIME_SPEC_DAY_BIT_SAT = 6;
  OSSL_TIME_SPEC_DAY_INT_SUN = 1;
  OSSL_TIME_SPEC_DAY_INT_MON = 2;
  OSSL_TIME_SPEC_DAY_INT_TUE = 3;
  OSSL_TIME_SPEC_DAY_INT_WED = 4;
  OSSL_TIME_SPEC_DAY_INT_THU = 5;
  OSSL_TIME_SPEC_DAY_INT_FRI = 6;
  OSSL_TIME_SPEC_DAY_INT_SAT = 7;
  OSSL_TIME_SPEC_WEEKS_TYPE_ALL = 0;
  OSSL_TIME_SPEC_WEEKS_TYPE_INT = 1;
  OSSL_TIME_SPEC_WEEKS_TYPE_BIT = 2;
  OSSL_TIME_SPEC_BIT_WEEKS_1 = 0;
  OSSL_TIME_SPEC_BIT_WEEKS_2 = 1;
  OSSL_TIME_SPEC_BIT_WEEKS_3 = 2;
  OSSL_TIME_SPEC_BIT_WEEKS_4 = 3;
  OSSL_TIME_SPEC_BIT_WEEKS_5 = 4;
  OSSL_TIME_SPEC_MONTH_TYPE_ALL = 0;
  OSSL_TIME_SPEC_MONTH_TYPE_INT = 1;
  OSSL_TIME_SPEC_MONTH_TYPE_BIT = 2;
  OSSL_TIME_SPEC_INT_MONTH_JAN = 1;
  OSSL_TIME_SPEC_INT_MONTH_FEB = 2;
  OSSL_TIME_SPEC_INT_MONTH_MAR = 3;
  OSSL_TIME_SPEC_INT_MONTH_APR = 4;
  OSSL_TIME_SPEC_INT_MONTH_MAY = 5;
  OSSL_TIME_SPEC_INT_MONTH_JUN = 6;
  OSSL_TIME_SPEC_INT_MONTH_JUL = 7;
  OSSL_TIME_SPEC_INT_MONTH_AUG = 8;
  OSSL_TIME_SPEC_INT_MONTH_SEP = 9;
  OSSL_TIME_SPEC_INT_MONTH_OCT = 10;
  OSSL_TIME_SPEC_INT_MONTH_NOV = 11;
  OSSL_TIME_SPEC_INT_MONTH_DEC = 12;
  OSSL_TIME_SPEC_BIT_MONTH_JAN = 0;
  OSSL_TIME_SPEC_BIT_MONTH_FEB = 1;
  OSSL_TIME_SPEC_BIT_MONTH_MAR = 2;
  OSSL_TIME_SPEC_BIT_MONTH_APR = 3;
  OSSL_TIME_SPEC_BIT_MONTH_MAY = 4;
  OSSL_TIME_SPEC_BIT_MONTH_JUN = 5;
  OSSL_TIME_SPEC_BIT_MONTH_JUL = 6;
  OSSL_TIME_SPEC_BIT_MONTH_AUG = 7;
  OSSL_TIME_SPEC_BIT_MONTH_SEP = 8;
  OSSL_TIME_SPEC_BIT_MONTH_OCT = 9;
  OSSL_TIME_SPEC_BIT_MONTH_NOV = 10;
  OSSL_TIME_SPEC_BIT_MONTH_DEC = 11;
  OSSL_TIME_SPEC_TIME_TYPE_ABSOLUTE = 0;
  OSSL_TIME_SPEC_TIME_TYPE_PERIODIC = 1;
  OSSL_ATTR_MAP_TYPE = 0;
  OSSL_ATTR_MAP_VALUE = 1;
  OSSL_AAA_ATTRIBUTE_TYPE = 0;
  OSSL_AAA_ATTRIBUTE_VALUES = 1;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  GENERAL_NAME_set1_X509_NAME: function(tgt: PPGENERAL_NAME; src: PX509_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM GENERAL_NAME_set1_X509_NAME}

  DIST_POINT_NAME_dup: function(a: PDIST_POINT_NAME): PDIST_POINT_NAME; cdecl = nil;
  {$EXTERNALSYM DIST_POINT_NAME_dup}

  PROXY_POLICY_new: function: PPROXY_POLICY; cdecl = nil;
  {$EXTERNALSYM PROXY_POLICY_new}

  PROXY_POLICY_free: procedure(a: PPROXY_POLICY); cdecl = nil;
  {$EXTERNALSYM PROXY_POLICY_free}

  d2i_PROXY_POLICY: function(a: PPPROXY_POLICY; _in: PPIdAnsiChar; len: TIdC_LONG): PPROXY_POLICY; cdecl = nil;
  {$EXTERNALSYM d2i_PROXY_POLICY}

  i2d_PROXY_POLICY: function(a: PPROXY_POLICY; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PROXY_POLICY}

  PROXY_POLICY_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM PROXY_POLICY_it}

  PROXY_CERT_INFO_EXTENSION_new: function: PPROXY_CERT_INFO_EXTENSION; cdecl = nil;
  {$EXTERNALSYM PROXY_CERT_INFO_EXTENSION_new}

  PROXY_CERT_INFO_EXTENSION_free: procedure(a: PPROXY_CERT_INFO_EXTENSION); cdecl = nil;
  {$EXTERNALSYM PROXY_CERT_INFO_EXTENSION_free}

  d2i_PROXY_CERT_INFO_EXTENSION: function(a: PPPROXY_CERT_INFO_EXTENSION; _in: PPIdAnsiChar; len: TIdC_LONG): PPROXY_CERT_INFO_EXTENSION; cdecl = nil;
  {$EXTERNALSYM d2i_PROXY_CERT_INFO_EXTENSION}

  i2d_PROXY_CERT_INFO_EXTENSION: function(a: PPROXY_CERT_INFO_EXTENSION; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PROXY_CERT_INFO_EXTENSION}

  PROXY_CERT_INFO_EXTENSION_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM PROXY_CERT_INFO_EXTENSION_it}

  BASIC_CONSTRAINTS_new: function: PBASIC_CONSTRAINTS; cdecl = nil;
  {$EXTERNALSYM BASIC_CONSTRAINTS_new}

  BASIC_CONSTRAINTS_free: procedure(a: PBASIC_CONSTRAINTS); cdecl = nil;
  {$EXTERNALSYM BASIC_CONSTRAINTS_free}

  d2i_BASIC_CONSTRAINTS: function(a: PPBASIC_CONSTRAINTS; _in: PPIdAnsiChar; len: TIdC_LONG): PBASIC_CONSTRAINTS; cdecl = nil;
  {$EXTERNALSYM d2i_BASIC_CONSTRAINTS}

  i2d_BASIC_CONSTRAINTS: function(a: PBASIC_CONSTRAINTS; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_BASIC_CONSTRAINTS}

  BASIC_CONSTRAINTS_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM BASIC_CONSTRAINTS_it}

  OSSL_BASIC_ATTR_CONSTRAINTS_new: function: POSSL_BASIC_ATTR_CONSTRAINTS; cdecl = nil;
  {$EXTERNALSYM OSSL_BASIC_ATTR_CONSTRAINTS_new}

  OSSL_BASIC_ATTR_CONSTRAINTS_free: procedure(a: POSSL_BASIC_ATTR_CONSTRAINTS); cdecl = nil;
  {$EXTERNALSYM OSSL_BASIC_ATTR_CONSTRAINTS_free}

  d2i_OSSL_BASIC_ATTR_CONSTRAINTS: function(a: PPOSSL_BASIC_ATTR_CONSTRAINTS; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_BASIC_ATTR_CONSTRAINTS; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_BASIC_ATTR_CONSTRAINTS}

  i2d_OSSL_BASIC_ATTR_CONSTRAINTS: function(a: POSSL_BASIC_ATTR_CONSTRAINTS; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_BASIC_ATTR_CONSTRAINTS}

  OSSL_BASIC_ATTR_CONSTRAINTS_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_BASIC_ATTR_CONSTRAINTS_it}

  SXNET_new: function: PSXNET; cdecl = nil;
  {$EXTERNALSYM SXNET_new}

  SXNET_free: procedure(a: PSXNET); cdecl = nil;
  {$EXTERNALSYM SXNET_free}

  d2i_SXNET: function(a: PPSXNET; _in: PPIdAnsiChar; len: TIdC_LONG): PSXNET; cdecl = nil;
  {$EXTERNALSYM d2i_SXNET}

  i2d_SXNET: function(a: PSXNET; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_SXNET}

  SXNET_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM SXNET_it}

  SXNETID_new: function: PSXNETID; cdecl = nil;
  {$EXTERNALSYM SXNETID_new}

  SXNETID_free: procedure(a: PSXNETID); cdecl = nil;
  {$EXTERNALSYM SXNETID_free}

  d2i_SXNETID: function(a: PPSXNETID; _in: PPIdAnsiChar; len: TIdC_LONG): PSXNETID; cdecl = nil;
  {$EXTERNALSYM d2i_SXNETID}

  i2d_SXNETID: function(a: PSXNETID; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_SXNETID}

  SXNETID_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM SXNETID_it}

  ISSUER_SIGN_TOOL_new: function: PISSUER_SIGN_TOOL; cdecl = nil;
  {$EXTERNALSYM ISSUER_SIGN_TOOL_new}

  ISSUER_SIGN_TOOL_free: procedure(a: PISSUER_SIGN_TOOL); cdecl = nil;
  {$EXTERNALSYM ISSUER_SIGN_TOOL_free}

  d2i_ISSUER_SIGN_TOOL: function(a: PPISSUER_SIGN_TOOL; _in: PPIdAnsiChar; len: TIdC_LONG): PISSUER_SIGN_TOOL; cdecl = nil;
  {$EXTERNALSYM d2i_ISSUER_SIGN_TOOL}

  i2d_ISSUER_SIGN_TOOL: function(a: PISSUER_SIGN_TOOL; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ISSUER_SIGN_TOOL}

  ISSUER_SIGN_TOOL_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ISSUER_SIGN_TOOL_it}

  SXNET_add_id_asc: function(psx: PPSXNET; zone: PIdAnsiChar; user: PIdAnsiChar; userlen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SXNET_add_id_asc}

  SXNET_add_id_ulong: function(psx: PPSXNET; lzone: TIdC_ULONG; user: PIdAnsiChar; userlen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SXNET_add_id_ulong}

  SXNET_add_id_INTEGER: function(psx: PPSXNET; izone: PASN1_INTEGER; user: PIdAnsiChar; userlen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SXNET_add_id_INTEGER}

  SXNET_get_id_asc: function(sx: PSXNET; zone: PIdAnsiChar): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM SXNET_get_id_asc}

  SXNET_get_id_ulong: function(sx: PSXNET; lzone: TIdC_ULONG): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM SXNET_get_id_ulong}

  SXNET_get_id_INTEGER: function(sx: PSXNET; zone: PASN1_INTEGER): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM SXNET_get_id_INTEGER}

  AUTHORITY_KEYID_new: function: PAUTHORITY_KEYID; cdecl = nil;
  {$EXTERNALSYM AUTHORITY_KEYID_new}

  AUTHORITY_KEYID_free: procedure(a: PAUTHORITY_KEYID); cdecl = nil;
  {$EXTERNALSYM AUTHORITY_KEYID_free}

  d2i_AUTHORITY_KEYID: function(a: PPAUTHORITY_KEYID; _in: PPIdAnsiChar; len: TIdC_LONG): PAUTHORITY_KEYID; cdecl = nil;
  {$EXTERNALSYM d2i_AUTHORITY_KEYID}

  i2d_AUTHORITY_KEYID: function(a: PAUTHORITY_KEYID; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_AUTHORITY_KEYID}

  AUTHORITY_KEYID_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM AUTHORITY_KEYID_it}

  PKEY_USAGE_PERIOD_new: function: PPKEY_USAGE_PERIOD; cdecl = nil;
  {$EXTERNALSYM PKEY_USAGE_PERIOD_new}

  PKEY_USAGE_PERIOD_free: procedure(a: PPKEY_USAGE_PERIOD); cdecl = nil;
  {$EXTERNALSYM PKEY_USAGE_PERIOD_free}

  d2i_PKEY_USAGE_PERIOD: function(a: PPPKEY_USAGE_PERIOD; _in: PPIdAnsiChar; len: TIdC_LONG): PPKEY_USAGE_PERIOD; cdecl = nil;
  {$EXTERNALSYM d2i_PKEY_USAGE_PERIOD}

  i2d_PKEY_USAGE_PERIOD: function(a: PPKEY_USAGE_PERIOD; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKEY_USAGE_PERIOD}

  PKEY_USAGE_PERIOD_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM PKEY_USAGE_PERIOD_it}

  GENERAL_NAME_new: function: PGENERAL_NAME; cdecl = nil;
  {$EXTERNALSYM GENERAL_NAME_new}

  GENERAL_NAME_free: procedure(a: PGENERAL_NAME); cdecl = nil;
  {$EXTERNALSYM GENERAL_NAME_free}

  d2i_GENERAL_NAME: function(a: PPGENERAL_NAME; _in: PPIdAnsiChar; len: TIdC_LONG): PGENERAL_NAME; cdecl = nil;
  {$EXTERNALSYM d2i_GENERAL_NAME}

  i2d_GENERAL_NAME: function(a: PGENERAL_NAME; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_GENERAL_NAME}

  GENERAL_NAME_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM GENERAL_NAME_it}

  GENERAL_NAME_dup: function(a: PGENERAL_NAME): PGENERAL_NAME; cdecl = nil;
  {$EXTERNALSYM GENERAL_NAME_dup}

  GENERAL_NAME_cmp: function(a: PGENERAL_NAME; b: PGENERAL_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM GENERAL_NAME_cmp}

  v2i_ASN1_BIT_STRING: function(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; nval: Pstack_st_CONF_VALUE): PASN1_BIT_STRING; cdecl = nil;
  {$EXTERNALSYM v2i_ASN1_BIT_STRING}

  i2v_ASN1_BIT_STRING: function(method: PX509V3_EXT_METHOD; bits: PASN1_BIT_STRING; extlist: Pstack_st_CONF_VALUE): Pstack_st_CONF_VALUE; cdecl = nil;
  {$EXTERNALSYM i2v_ASN1_BIT_STRING}

  i2s_ASN1_IA5STRING: function(method: PX509V3_EXT_METHOD; ia5: PASN1_IA5STRING): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM i2s_ASN1_IA5STRING}

  s2i_ASN1_IA5STRING: function(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; str: PIdAnsiChar): PASN1_IA5STRING; cdecl = nil;
  {$EXTERNALSYM s2i_ASN1_IA5STRING}

  i2s_ASN1_UTF8STRING: function(method: PX509V3_EXT_METHOD; utf8: PASN1_UTF8STRING): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM i2s_ASN1_UTF8STRING}

  s2i_ASN1_UTF8STRING: function(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; str: PIdAnsiChar): PASN1_UTF8STRING; cdecl = nil;
  {$EXTERNALSYM s2i_ASN1_UTF8STRING}

  i2v_GENERAL_NAME: function(method: PX509V3_EXT_METHOD; gen: PGENERAL_NAME; ret: Pstack_st_CONF_VALUE): Pstack_st_CONF_VALUE; cdecl = nil;
  {$EXTERNALSYM i2v_GENERAL_NAME}

  GENERAL_NAME_print: function(_out: PBIO; gen: PGENERAL_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM GENERAL_NAME_print}

  GENERAL_NAMES_new: function: PGENERAL_NAMES; cdecl = nil;
  {$EXTERNALSYM GENERAL_NAMES_new}

  GENERAL_NAMES_free: procedure(a: PGENERAL_NAMES); cdecl = nil;
  {$EXTERNALSYM GENERAL_NAMES_free}

  d2i_GENERAL_NAMES: function(a: PPGENERAL_NAMES; _in: PPIdAnsiChar; len: TIdC_LONG): PGENERAL_NAMES; cdecl = nil;
  {$EXTERNALSYM d2i_GENERAL_NAMES}

  i2d_GENERAL_NAMES: function(a: PGENERAL_NAMES; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_GENERAL_NAMES}

  GENERAL_NAMES_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM GENERAL_NAMES_it}

  i2v_GENERAL_NAMES: function(method: PX509V3_EXT_METHOD; gen: PGENERAL_NAMES; extlist: Pstack_st_CONF_VALUE): Pstack_st_CONF_VALUE; cdecl = nil;
  {$EXTERNALSYM i2v_GENERAL_NAMES}

  v2i_GENERAL_NAMES: function(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; nval: Pstack_st_CONF_VALUE): PGENERAL_NAMES; cdecl = nil;
  {$EXTERNALSYM v2i_GENERAL_NAMES}

  OTHERNAME_new: function: POTHERNAME; cdecl = nil;
  {$EXTERNALSYM OTHERNAME_new}

  OTHERNAME_free: procedure(a: POTHERNAME); cdecl = nil;
  {$EXTERNALSYM OTHERNAME_free}

  d2i_OTHERNAME: function(a: PPOTHERNAME; _in: PPIdAnsiChar; len: TIdC_LONG): POTHERNAME; cdecl = nil;
  {$EXTERNALSYM d2i_OTHERNAME}

  i2d_OTHERNAME: function(a: POTHERNAME; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OTHERNAME}

  OTHERNAME_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OTHERNAME_it}

  EDIPARTYNAME_new: function: PEDIPARTYNAME; cdecl = nil;
  {$EXTERNALSYM EDIPARTYNAME_new}

  EDIPARTYNAME_free: procedure(a: PEDIPARTYNAME); cdecl = nil;
  {$EXTERNALSYM EDIPARTYNAME_free}

  d2i_EDIPARTYNAME: function(a: PPEDIPARTYNAME; _in: PPIdAnsiChar; len: TIdC_LONG): PEDIPARTYNAME; cdecl = nil;
  {$EXTERNALSYM d2i_EDIPARTYNAME}

  i2d_EDIPARTYNAME: function(a: PEDIPARTYNAME; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_EDIPARTYNAME}

  EDIPARTYNAME_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM EDIPARTYNAME_it}

  OTHERNAME_cmp: function(a: POTHERNAME; b: POTHERNAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OTHERNAME_cmp}

  GENERAL_NAME_set0_value: procedure(a: PGENERAL_NAME; _type: TIdC_INT; value: Pointer); cdecl = nil;
  {$EXTERNALSYM GENERAL_NAME_set0_value}

  GENERAL_NAME_get0_value: function(a: PGENERAL_NAME; ptype: PIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM GENERAL_NAME_get0_value}

  GENERAL_NAME_set0_othername: function(gen: PGENERAL_NAME; oid: PASN1_OBJECT; value: PASN1_TYPE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM GENERAL_NAME_set0_othername}

  GENERAL_NAME_get0_otherName: function(gen: PGENERAL_NAME; poid: PPASN1_OBJECT; pvalue: PPASN1_TYPE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM GENERAL_NAME_get0_otherName}

  i2s_ASN1_OCTET_STRING: function(method: PX509V3_EXT_METHOD; ia5: PASN1_OCTET_STRING): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM i2s_ASN1_OCTET_STRING}

  s2i_ASN1_OCTET_STRING: function(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; str: PIdAnsiChar): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM s2i_ASN1_OCTET_STRING}

  EXTENDED_KEY_USAGE_new: function: PEXTENDED_KEY_USAGE; cdecl = nil;
  {$EXTERNALSYM EXTENDED_KEY_USAGE_new}

  EXTENDED_KEY_USAGE_free: procedure(a: PEXTENDED_KEY_USAGE); cdecl = nil;
  {$EXTERNALSYM EXTENDED_KEY_USAGE_free}

  d2i_EXTENDED_KEY_USAGE: function(a: PPEXTENDED_KEY_USAGE; _in: PPIdAnsiChar; len: TIdC_LONG): PEXTENDED_KEY_USAGE; cdecl = nil;
  {$EXTERNALSYM d2i_EXTENDED_KEY_USAGE}

  i2d_EXTENDED_KEY_USAGE: function(a: PEXTENDED_KEY_USAGE; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_EXTENDED_KEY_USAGE}

  EXTENDED_KEY_USAGE_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM EXTENDED_KEY_USAGE_it}

  i2a_ACCESS_DESCRIPTION: function(bp: PBIO; a: PACCESS_DESCRIPTION): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2a_ACCESS_DESCRIPTION}

  TLS_FEATURE_new: function: PLS_FEATURE; cdecl = nil;
  {$EXTERNALSYM TLS_FEATURE_new}

  TLS_FEATURE_free: procedure(a: PLS_FEATURE); cdecl = nil;
  {$EXTERNALSYM TLS_FEATURE_free}

  CERTIFICATEPOLICIES_new: function: PCERTIFICATEPOLICIES; cdecl = nil;
  {$EXTERNALSYM CERTIFICATEPOLICIES_new}

  CERTIFICATEPOLICIES_free: procedure(a: PCERTIFICATEPOLICIES); cdecl = nil;
  {$EXTERNALSYM CERTIFICATEPOLICIES_free}

  d2i_CERTIFICATEPOLICIES: function(a: PPCERTIFICATEPOLICIES; _in: PPIdAnsiChar; len: TIdC_LONG): PCERTIFICATEPOLICIES; cdecl = nil;
  {$EXTERNALSYM d2i_CERTIFICATEPOLICIES}

  i2d_CERTIFICATEPOLICIES: function(a: PCERTIFICATEPOLICIES; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_CERTIFICATEPOLICIES}

  CERTIFICATEPOLICIES_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM CERTIFICATEPOLICIES_it}

  POLICYINFO_new: function: PPOLICYINFO; cdecl = nil;
  {$EXTERNALSYM POLICYINFO_new}

  POLICYINFO_free: procedure(a: PPOLICYINFO); cdecl = nil;
  {$EXTERNALSYM POLICYINFO_free}

  d2i_POLICYINFO: function(a: PPPOLICYINFO; _in: PPIdAnsiChar; len: TIdC_LONG): PPOLICYINFO; cdecl = nil;
  {$EXTERNALSYM d2i_POLICYINFO}

  i2d_POLICYINFO: function(a: PPOLICYINFO; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_POLICYINFO}

  POLICYINFO_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM POLICYINFO_it}

  POLICYQUALINFO_new: function: PPOLICYQUALINFO; cdecl = nil;
  {$EXTERNALSYM POLICYQUALINFO_new}

  POLICYQUALINFO_free: procedure(a: PPOLICYQUALINFO); cdecl = nil;
  {$EXTERNALSYM POLICYQUALINFO_free}

  d2i_POLICYQUALINFO: function(a: PPPOLICYQUALINFO; _in: PPIdAnsiChar; len: TIdC_LONG): PPOLICYQUALINFO; cdecl = nil;
  {$EXTERNALSYM d2i_POLICYQUALINFO}

  i2d_POLICYQUALINFO: function(a: PPOLICYQUALINFO; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_POLICYQUALINFO}

  POLICYQUALINFO_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM POLICYQUALINFO_it}

  USERNOTICE_new: function: PUSERNOTICE; cdecl = nil;
  {$EXTERNALSYM USERNOTICE_new}

  USERNOTICE_free: procedure(a: PUSERNOTICE); cdecl = nil;
  {$EXTERNALSYM USERNOTICE_free}

  d2i_USERNOTICE: function(a: PPUSERNOTICE; _in: PPIdAnsiChar; len: TIdC_LONG): PUSERNOTICE; cdecl = nil;
  {$EXTERNALSYM d2i_USERNOTICE}

  i2d_USERNOTICE: function(a: PUSERNOTICE; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_USERNOTICE}

  USERNOTICE_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM USERNOTICE_it}

  NOTICEREF_new: function: PNOTICEREF; cdecl = nil;
  {$EXTERNALSYM NOTICEREF_new}

  NOTICEREF_free: procedure(a: PNOTICEREF); cdecl = nil;
  {$EXTERNALSYM NOTICEREF_free}

  d2i_NOTICEREF: function(a: PPNOTICEREF; _in: PPIdAnsiChar; len: TIdC_LONG): PNOTICEREF; cdecl = nil;
  {$EXTERNALSYM d2i_NOTICEREF}

  i2d_NOTICEREF: function(a: PNOTICEREF; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_NOTICEREF}

  NOTICEREF_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM NOTICEREF_it}

  CRL_DIST_POINTS_new: function: PCRL_DIST_POINTS; cdecl = nil;
  {$EXTERNALSYM CRL_DIST_POINTS_new}

  CRL_DIST_POINTS_free: procedure(a: PCRL_DIST_POINTS); cdecl = nil;
  {$EXTERNALSYM CRL_DIST_POINTS_free}

  d2i_CRL_DIST_POINTS: function(a: PPCRL_DIST_POINTS; _in: PPIdAnsiChar; len: TIdC_LONG): PCRL_DIST_POINTS; cdecl = nil;
  {$EXTERNALSYM d2i_CRL_DIST_POINTS}

  i2d_CRL_DIST_POINTS: function(a: PCRL_DIST_POINTS; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_CRL_DIST_POINTS}

  CRL_DIST_POINTS_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM CRL_DIST_POINTS_it}

  DIST_POINT_new: function: PDIST_POINT; cdecl = nil;
  {$EXTERNALSYM DIST_POINT_new}

  DIST_POINT_free: procedure(a: PDIST_POINT); cdecl = nil;
  {$EXTERNALSYM DIST_POINT_free}

  d2i_DIST_POINT: function(a: PPDIST_POINT; _in: PPIdAnsiChar; len: TIdC_LONG): PDIST_POINT; cdecl = nil;
  {$EXTERNALSYM d2i_DIST_POINT}

  i2d_DIST_POINT: function(a: PDIST_POINT; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_DIST_POINT}

  DIST_POINT_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM DIST_POINT_it}

  DIST_POINT_NAME_new: function: PDIST_POINT_NAME; cdecl = nil;
  {$EXTERNALSYM DIST_POINT_NAME_new}

  DIST_POINT_NAME_free: procedure(a: PDIST_POINT_NAME); cdecl = nil;
  {$EXTERNALSYM DIST_POINT_NAME_free}

  d2i_DIST_POINT_NAME: function(a: PPDIST_POINT_NAME; _in: PPIdAnsiChar; len: TIdC_LONG): PDIST_POINT_NAME; cdecl = nil;
  {$EXTERNALSYM d2i_DIST_POINT_NAME}

  i2d_DIST_POINT_NAME: function(a: PDIST_POINT_NAME; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_DIST_POINT_NAME}

  DIST_POINT_NAME_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM DIST_POINT_NAME_it}

  ISSUING_DIST_POINT_new: function: PISSUING_DIST_POINT; cdecl = nil;
  {$EXTERNALSYM ISSUING_DIST_POINT_new}

  ISSUING_DIST_POINT_free: procedure(a: PISSUING_DIST_POINT); cdecl = nil;
  {$EXTERNALSYM ISSUING_DIST_POINT_free}

  d2i_ISSUING_DIST_POINT: function(a: PPISSUING_DIST_POINT; _in: PPIdAnsiChar; len: TIdC_LONG): PISSUING_DIST_POINT; cdecl = nil;
  {$EXTERNALSYM d2i_ISSUING_DIST_POINT}

  i2d_ISSUING_DIST_POINT: function(a: PISSUING_DIST_POINT; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ISSUING_DIST_POINT}

  ISSUING_DIST_POINT_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ISSUING_DIST_POINT_it}

  DIST_POINT_set_dpname: function(dpn: PDIST_POINT_NAME; iname: PX509_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DIST_POINT_set_dpname}

  NAME_CONSTRAINTS_check: function(x: PX509; nc: PNAME_CONSTRAINTS): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM NAME_CONSTRAINTS_check}

  NAME_CONSTRAINTS_check_CN: function(x: PX509; nc: PNAME_CONSTRAINTS): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM NAME_CONSTRAINTS_check_CN}

  ACCESS_DESCRIPTION_new: function: PACCESS_DESCRIPTION; cdecl = nil;
  {$EXTERNALSYM ACCESS_DESCRIPTION_new}

  ACCESS_DESCRIPTION_free: procedure(a: PACCESS_DESCRIPTION); cdecl = nil;
  {$EXTERNALSYM ACCESS_DESCRIPTION_free}

  d2i_ACCESS_DESCRIPTION: function(a: PPACCESS_DESCRIPTION; _in: PPIdAnsiChar; len: TIdC_LONG): PACCESS_DESCRIPTION; cdecl = nil;
  {$EXTERNALSYM d2i_ACCESS_DESCRIPTION}

  i2d_ACCESS_DESCRIPTION: function(a: PACCESS_DESCRIPTION; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ACCESS_DESCRIPTION}

  ACCESS_DESCRIPTION_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ACCESS_DESCRIPTION_it}

  AUTHORITY_INFO_ACCESS_new: function: PAUTHORITY_INFO_ACCESS; cdecl = nil;
  {$EXTERNALSYM AUTHORITY_INFO_ACCESS_new}

  AUTHORITY_INFO_ACCESS_free: procedure(a: PAUTHORITY_INFO_ACCESS); cdecl = nil;
  {$EXTERNALSYM AUTHORITY_INFO_ACCESS_free}

  d2i_AUTHORITY_INFO_ACCESS: function(a: PPAUTHORITY_INFO_ACCESS; _in: PPIdAnsiChar; len: TIdC_LONG): PAUTHORITY_INFO_ACCESS; cdecl = nil;
  {$EXTERNALSYM d2i_AUTHORITY_INFO_ACCESS}

  i2d_AUTHORITY_INFO_ACCESS: function(a: PAUTHORITY_INFO_ACCESS; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_AUTHORITY_INFO_ACCESS}

  AUTHORITY_INFO_ACCESS_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM AUTHORITY_INFO_ACCESS_it}

  POLICY_MAPPING_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM POLICY_MAPPING_it}

  POLICY_MAPPING_new: function: PPOLICY_MAPPING; cdecl = nil;
  {$EXTERNALSYM POLICY_MAPPING_new}

  POLICY_MAPPING_free: procedure(a: PPOLICY_MAPPING); cdecl = nil;
  {$EXTERNALSYM POLICY_MAPPING_free}

  POLICY_MAPPINGS_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM POLICY_MAPPINGS_it}

  GENERAL_SUBTREE_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM GENERAL_SUBTREE_it}

  GENERAL_SUBTREE_new: function: PGENERAL_SUBTREE; cdecl = nil;
  {$EXTERNALSYM GENERAL_SUBTREE_new}

  GENERAL_SUBTREE_free: procedure(a: PGENERAL_SUBTREE); cdecl = nil;
  {$EXTERNALSYM GENERAL_SUBTREE_free}

  NAME_CONSTRAINTS_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM NAME_CONSTRAINTS_it}

  NAME_CONSTRAINTS_new: function: PNAME_CONSTRAINTS; cdecl = nil;
  {$EXTERNALSYM NAME_CONSTRAINTS_new}

  NAME_CONSTRAINTS_free: procedure(a: PNAME_CONSTRAINTS); cdecl = nil;
  {$EXTERNALSYM NAME_CONSTRAINTS_free}

  POLICY_CONSTRAINTS_new: function: PPOLICY_CONSTRAINTS; cdecl = nil;
  {$EXTERNALSYM POLICY_CONSTRAINTS_new}

  POLICY_CONSTRAINTS_free: procedure(a: PPOLICY_CONSTRAINTS); cdecl = nil;
  {$EXTERNALSYM POLICY_CONSTRAINTS_free}

  POLICY_CONSTRAINTS_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM POLICY_CONSTRAINTS_it}

  a2i_GENERAL_NAME: function(_out: PGENERAL_NAME; method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; gen_type: TIdC_INT; value: PIdAnsiChar; is_nc: TIdC_INT): PGENERAL_NAME; cdecl = nil;
  {$EXTERNALSYM a2i_GENERAL_NAME}

  v2i_GENERAL_NAME: function(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; cnf: PCONF_VALUE): PGENERAL_NAME; cdecl = nil;
  {$EXTERNALSYM v2i_GENERAL_NAME}

  v2i_GENERAL_NAME_ex: function(_out: PGENERAL_NAME; method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; cnf: PCONF_VALUE; is_nc: TIdC_INT): PGENERAL_NAME; cdecl = nil;
  {$EXTERNALSYM v2i_GENERAL_NAME_ex}

  X509V3_conf_free: procedure(val: PCONF_VALUE); cdecl = nil;
  {$EXTERNALSYM X509V3_conf_free}

  X509V3_EXT_nconf_nid: function(conf: PCONF; ctx: PX509V3_CTX; ext_nid: TIdC_INT; value: PIdAnsiChar): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509V3_EXT_nconf_nid}

  X509V3_EXT_nconf: function(conf: PCONF; ctx: PX509V3_CTX; name: PIdAnsiChar; value: PIdAnsiChar): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509V3_EXT_nconf}

  X509V3_EXT_add_nconf_sk: function(conf: PCONF; ctx: PX509V3_CTX; section: PIdAnsiChar; sk: PPstack_st_X509_EXTENSION): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509V3_EXT_add_nconf_sk}

  X509V3_EXT_add_nconf: function(conf: PCONF; ctx: PX509V3_CTX; section: PIdAnsiChar; cert: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509V3_EXT_add_nconf}

  X509V3_EXT_REQ_add_nconf: function(conf: PCONF; ctx: PX509V3_CTX; section: PIdAnsiChar; req: PX509_REQ): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509V3_EXT_REQ_add_nconf}

  X509V3_EXT_CRL_add_nconf: function(conf: PCONF; ctx: PX509V3_CTX; section: PIdAnsiChar; crl: PX509_CRL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509V3_EXT_CRL_add_nconf}

  X509V3_EXT_conf_nid: function(conf: Plhash_st_CONF_VALUE; ctx: PX509V3_CTX; ext_nid: TIdC_INT; value: PIdAnsiChar): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509V3_EXT_conf_nid}

  X509V3_EXT_conf: function(conf: Plhash_st_CONF_VALUE; ctx: PX509V3_CTX; name: PIdAnsiChar; value: PIdAnsiChar): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509V3_EXT_conf}

  X509V3_EXT_add_conf: function(conf: Plhash_st_CONF_VALUE; ctx: PX509V3_CTX; section: PIdAnsiChar; cert: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509V3_EXT_add_conf}

  X509V3_EXT_REQ_add_conf: function(conf: Plhash_st_CONF_VALUE; ctx: PX509V3_CTX; section: PIdAnsiChar; req: PX509_REQ): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509V3_EXT_REQ_add_conf}

  X509V3_EXT_CRL_add_conf: function(conf: Plhash_st_CONF_VALUE; ctx: PX509V3_CTX; section: PIdAnsiChar; crl: PX509_CRL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509V3_EXT_CRL_add_conf}

  X509V3_add_value_bool_nf: function(name: PIdAnsiChar; asn1_bool: TIdC_INT; extlist: PPstack_st_CONF_VALUE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509V3_add_value_bool_nf}

  X509V3_get_value_bool: function(value: PCONF_VALUE; asn1_bool: PIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509V3_get_value_bool}

  X509V3_get_value_int: function(value: PCONF_VALUE; aint: PPASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509V3_get_value_int}

  X509V3_set_nconf: procedure(ctx: PX509V3_CTX; conf: PCONF); cdecl = nil;
  {$EXTERNALSYM X509V3_set_nconf}

  X509V3_set_conf_lhash: procedure(ctx: PX509V3_CTX; lhash: Plhash_st_CONF_VALUE); cdecl = nil;
  {$EXTERNALSYM X509V3_set_conf_lhash}

  X509V3_get_string: function(ctx: PX509V3_CTX; name: PIdAnsiChar; section: PIdAnsiChar): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM X509V3_get_string}

  X509V3_get_section: function(ctx: PX509V3_CTX; section: PIdAnsiChar): Pstack_st_CONF_VALUE; cdecl = nil;
  {$EXTERNALSYM X509V3_get_section}

  X509V3_string_free: procedure(ctx: PX509V3_CTX; str: PIdAnsiChar); cdecl = nil;
  {$EXTERNALSYM X509V3_string_free}

  X509V3_section_free: procedure(ctx: PX509V3_CTX; section: Pstack_st_CONF_VALUE); cdecl = nil;
  {$EXTERNALSYM X509V3_section_free}

  X509V3_set_ctx: procedure(ctx: PX509V3_CTX; issuer: PX509; subject: PX509; req: PX509_REQ; crl: PX509_CRL; flags: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM X509V3_set_ctx}

  X509V3_set_issuer_pkey: function(ctx: PX509V3_CTX; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509V3_set_issuer_pkey}

  X509V3_add_value: function(name: PIdAnsiChar; value: PIdAnsiChar; extlist: PPstack_st_CONF_VALUE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509V3_add_value}

  X509V3_add_value_uchar: function(name: PIdAnsiChar; value: PIdAnsiChar; extlist: PPstack_st_CONF_VALUE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509V3_add_value_uchar}

  X509V3_add_value_bool: function(name: PIdAnsiChar; asn1_bool: TIdC_INT; extlist: PPstack_st_CONF_VALUE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509V3_add_value_bool}

  X509V3_add_value_int: function(name: PIdAnsiChar; aint: PASN1_INTEGER; extlist: PPstack_st_CONF_VALUE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509V3_add_value_int}

  i2s_ASN1_INTEGER: function(meth: PX509V3_EXT_METHOD; aint: PASN1_INTEGER): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM i2s_ASN1_INTEGER}

  s2i_ASN1_INTEGER: function(meth: PX509V3_EXT_METHOD; value: PIdAnsiChar): PASN1_INTEGER; cdecl = nil;
  {$EXTERNALSYM s2i_ASN1_INTEGER}

  i2s_ASN1_ENUMERATED: function(meth: PX509V3_EXT_METHOD; aint: PASN1_ENUMERATED): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM i2s_ASN1_ENUMERATED}

  i2s_ASN1_ENUMERATED_TABLE: function(meth: PX509V3_EXT_METHOD; aint: PASN1_ENUMERATED): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM i2s_ASN1_ENUMERATED_TABLE}

  X509V3_EXT_add: function(ext: PX509V3_EXT_METHOD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509V3_EXT_add}

  X509V3_EXT_add_list: function(extlist: PX509V3_EXT_METHOD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509V3_EXT_add_list}

  X509V3_EXT_add_alias: function(nid_to: TIdC_INT; nid_from: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509V3_EXT_add_alias}

  X509V3_EXT_cleanup: procedure; cdecl = nil;
  {$EXTERNALSYM X509V3_EXT_cleanup}

  X509V3_EXT_get: function(ext: PX509_EXTENSION): PX509V3_EXT_METHOD; cdecl = nil;
  {$EXTERNALSYM X509V3_EXT_get}

  X509V3_EXT_get_nid: function(nid: TIdC_INT): PX509V3_EXT_METHOD; cdecl = nil;
  {$EXTERNALSYM X509V3_EXT_get_nid}

  X509V3_add_standard_extensions: function: TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509V3_add_standard_extensions}

  X509V3_parse_list: function(line: PIdAnsiChar): Pstack_st_CONF_VALUE; cdecl = nil;
  {$EXTERNALSYM X509V3_parse_list}

  X509V3_EXT_d2i: function(ext: PX509_EXTENSION): Pointer; cdecl = nil;
  {$EXTERNALSYM X509V3_EXT_d2i}

  X509V3_get_d2i: function(x: Pstack_st_X509_EXTENSION; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM X509V3_get_d2i}

  X509V3_EXT_i2d: function(ext_nid: TIdC_INT; crit: TIdC_INT; ext_struc: Pointer): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509V3_EXT_i2d}

  X509V3_add1_i2d: function(x: PPstack_st_X509_EXTENSION; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509V3_add1_i2d}

  X509V3_EXT_val_prn: procedure(_out: PBIO; val: Pstack_st_CONF_VALUE; indent: TIdC_INT; ml: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM X509V3_EXT_val_prn}

  X509V3_EXT_print: function(_out: PBIO; ext: PX509_EXTENSION; flag: TIdC_ULONG; indent: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509V3_EXT_print}

  X509V3_EXT_print_fp: function(_out: PFILE; ext: PX509_EXTENSION; flag: TIdC_INT; indent: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509V3_EXT_print_fp}

  X509V3_extensions_print: function(_out: PBIO; title: PIdAnsiChar; exts: Pstack_st_X509_EXTENSION; flag: TIdC_ULONG; indent: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509V3_extensions_print}

  X509_check_ca: function(x: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_check_ca}

  X509_check_purpose: function(x: PX509; id: TIdC_INT; ca: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_check_purpose}

  X509_supported_extension: function(ex: PX509_EXTENSION): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_supported_extension}

  X509_check_issued: function(issuer: PX509; subject: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_check_issued}

  X509_check_akid: function(issuer: PX509; akid: PAUTHORITY_KEYID): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_check_akid}

  X509_set_proxy_flag: procedure(x: PX509); cdecl = nil;
  {$EXTERNALSYM X509_set_proxy_flag}

  X509_set_proxy_pathlen: procedure(x: PX509; l: TIdC_LONG); cdecl = nil;
  {$EXTERNALSYM X509_set_proxy_pathlen}

  X509_get_proxy_pathlen: function(x: PX509): TIdC_LONG; cdecl = nil;
  {$EXTERNALSYM X509_get_proxy_pathlen}

  X509_get_extension_flags: function(x: PX509): UInt32; cdecl = nil;
  {$EXTERNALSYM X509_get_extension_flags}

  X509_get_key_usage: function(x: PX509): UInt32; cdecl = nil;
  {$EXTERNALSYM X509_get_key_usage}

  X509_get_extended_key_usage: function(x: PX509): UInt32; cdecl = nil;
  {$EXTERNALSYM X509_get_extended_key_usage}

  X509_get0_subject_key_id: function(x: PX509): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM X509_get0_subject_key_id}

  X509_get0_authority_key_id: function(x: PX509): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM X509_get0_authority_key_id}

  X509_get0_authority_issuer: function(x: PX509): PGENERAL_NAMES; cdecl = nil;
  {$EXTERNALSYM X509_get0_authority_issuer}

  X509_get0_authority_serial: function(x: PX509): PASN1_INTEGER; cdecl = nil;
  {$EXTERNALSYM X509_get0_authority_serial}

  X509_PURPOSE_get_count: function: TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_PURPOSE_get_count}

  X509_PURPOSE_get_unused_id: function(libctx: POSSL_LIB_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_PURPOSE_get_unused_id}

  X509_PURPOSE_get_by_sname: function(sname: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_PURPOSE_get_by_sname}

  X509_PURPOSE_get_by_id: function(id: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_PURPOSE_get_by_id}

  X509_PURPOSE_add: function(id: TIdC_INT; trust: TIdC_INT; flags: TIdC_INT; ck: TX509_PURPOSE_add_ck_cb; name: PIdAnsiChar; sname: PIdAnsiChar; arg: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_PURPOSE_add}

  X509_PURPOSE_cleanup: procedure; cdecl = nil;
  {$EXTERNALSYM X509_PURPOSE_cleanup}

  X509_PURPOSE_get0: function(idx: TIdC_INT): PX509_PURPOSE; cdecl = nil;
  {$EXTERNALSYM X509_PURPOSE_get0}

  X509_PURPOSE_get_id: function(arg1: PX509_PURPOSE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_PURPOSE_get_id}

  X509_PURPOSE_get0_name: function(xp: PX509_PURPOSE): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM X509_PURPOSE_get0_name}

  X509_PURPOSE_get0_sname: function(xp: PX509_PURPOSE): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM X509_PURPOSE_get0_sname}

  X509_PURPOSE_get_trust: function(xp: PX509_PURPOSE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_PURPOSE_get_trust}

  X509_PURPOSE_set: function(p: PIdC_INT; purpose: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_PURPOSE_set}

  X509_get1_email: function(x: PX509): Pstack_st_OPENSSL_STRING; cdecl = nil;
  {$EXTERNALSYM X509_get1_email}

  X509_REQ_get1_email: function(x: PX509_REQ): Pstack_st_OPENSSL_STRING; cdecl = nil;
  {$EXTERNALSYM X509_REQ_get1_email}

  X509_email_free: procedure(sk: Pstack_st_OPENSSL_STRING); cdecl = nil;
  {$EXTERNALSYM X509_email_free}

  X509_get1_ocsp: function(x: PX509): Pstack_st_OPENSSL_STRING; cdecl = nil;
  {$EXTERNALSYM X509_get1_ocsp}

  X509_check_host: function(x: PX509; chk: PIdAnsiChar; chklen: TIdC_SIZET; flags: TIdC_UINT; peername: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_check_host}

  X509_check_email: function(x: PX509; chk: PIdAnsiChar; chklen: TIdC_SIZET; flags: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_check_email}

  X509_check_ip: function(x: PX509; chk: PIdAnsiChar; chklen: TIdC_SIZET; flags: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_check_ip}

  X509_check_ip_asc: function(x: PX509; ipasc: PIdAnsiChar; flags: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_check_ip_asc}

  a2i_IPADDRESS: function(ipasc: PIdAnsiChar): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM a2i_IPADDRESS}

  a2i_IPADDRESS_NC: function(ipasc: PIdAnsiChar): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM a2i_IPADDRESS_NC}

  X509V3_NAME_from_section: function(nm: PX509_NAME; dn_sk: Pstack_st_CONF_VALUE; chtype: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509V3_NAME_from_section}

  X509_POLICY_NODE_print: procedure(_out: PBIO; node: PX509_POLICY_NODE; indent: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM X509_POLICY_NODE_print}

  ASRange_new: function: PASRange; cdecl = nil;
  {$EXTERNALSYM ASRange_new}

  ASRange_free: procedure(a: PASRange); cdecl = nil;
  {$EXTERNALSYM ASRange_free}

  d2i_ASRange: function(a: PPASRange; _in: PPIdAnsiChar; len: TIdC_LONG): PASRange; cdecl = nil;
  {$EXTERNALSYM d2i_ASRange}

  i2d_ASRange: function(a: PASRange; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ASRange}

  ASRange_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASRange_it}

  ASIdOrRange_new: function: PASIdOrRange; cdecl = nil;
  {$EXTERNALSYM ASIdOrRange_new}

  ASIdOrRange_free: procedure(a: PASIdOrRange); cdecl = nil;
  {$EXTERNALSYM ASIdOrRange_free}

  d2i_ASIdOrRange: function(a: PPASIdOrRange; _in: PPIdAnsiChar; len: TIdC_LONG): PASIdOrRange; cdecl = nil;
  {$EXTERNALSYM d2i_ASIdOrRange}

  i2d_ASIdOrRange: function(a: PASIdOrRange; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ASIdOrRange}

  ASIdOrRange_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASIdOrRange_it}

  ASIdentifierChoice_new: function: PASIdentifierChoice; cdecl = nil;
  {$EXTERNALSYM ASIdentifierChoice_new}

  ASIdentifierChoice_free: procedure(a: PASIdentifierChoice); cdecl = nil;
  {$EXTERNALSYM ASIdentifierChoice_free}

  d2i_ASIdentifierChoice: function(a: PPASIdentifierChoice; _in: PPIdAnsiChar; len: TIdC_LONG): PASIdentifierChoice; cdecl = nil;
  {$EXTERNALSYM d2i_ASIdentifierChoice}

  i2d_ASIdentifierChoice: function(a: PASIdentifierChoice; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ASIdentifierChoice}

  ASIdentifierChoice_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASIdentifierChoice_it}

  ASIdentifiers_new: function: PASIdentifiers; cdecl = nil;
  {$EXTERNALSYM ASIdentifiers_new}

  ASIdentifiers_free: procedure(a: PASIdentifiers); cdecl = nil;
  {$EXTERNALSYM ASIdentifiers_free}

  d2i_ASIdentifiers: function(a: PPASIdentifiers; _in: PPIdAnsiChar; len: TIdC_LONG): PASIdentifiers; cdecl = nil;
  {$EXTERNALSYM d2i_ASIdentifiers}

  i2d_ASIdentifiers: function(a: PASIdentifiers; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ASIdentifiers}

  ASIdentifiers_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASIdentifiers_it}

  IPAddressRange_new: function: PIPAddressRange; cdecl = nil;
  {$EXTERNALSYM IPAddressRange_new}

  IPAddressRange_free: procedure(a: PIPAddressRange); cdecl = nil;
  {$EXTERNALSYM IPAddressRange_free}

  d2i_IPAddressRange: function(a: PPIPAddressRange; _in: PPIdAnsiChar; len: TIdC_LONG): PIPAddressRange; cdecl = nil;
  {$EXTERNALSYM d2i_IPAddressRange}

  i2d_IPAddressRange: function(a: PIPAddressRange; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_IPAddressRange}

  IPAddressRange_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM IPAddressRange_it}

  IPAddressOrRange_new: function: PIPAddressOrRange; cdecl = nil;
  {$EXTERNALSYM IPAddressOrRange_new}

  IPAddressOrRange_free: procedure(a: PIPAddressOrRange); cdecl = nil;
  {$EXTERNALSYM IPAddressOrRange_free}

  d2i_IPAddressOrRange: function(a: PPIPAddressOrRange; _in: PPIdAnsiChar; len: TIdC_LONG): PIPAddressOrRange; cdecl = nil;
  {$EXTERNALSYM d2i_IPAddressOrRange}

  i2d_IPAddressOrRange: function(a: PIPAddressOrRange; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_IPAddressOrRange}

  IPAddressOrRange_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM IPAddressOrRange_it}

  IPAddressChoice_new: function: PIPAddressChoice; cdecl = nil;
  {$EXTERNALSYM IPAddressChoice_new}

  IPAddressChoice_free: procedure(a: PIPAddressChoice); cdecl = nil;
  {$EXTERNALSYM IPAddressChoice_free}

  d2i_IPAddressChoice: function(a: PPIPAddressChoice; _in: PPIdAnsiChar; len: TIdC_LONG): PIPAddressChoice; cdecl = nil;
  {$EXTERNALSYM d2i_IPAddressChoice}

  i2d_IPAddressChoice: function(a: PIPAddressChoice; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_IPAddressChoice}

  IPAddressChoice_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM IPAddressChoice_it}

  IPAddressFamily_new: function: PIPAddressFamily; cdecl = nil;
  {$EXTERNALSYM IPAddressFamily_new}

  IPAddressFamily_free: procedure(a: PIPAddressFamily); cdecl = nil;
  {$EXTERNALSYM IPAddressFamily_free}

  d2i_IPAddressFamily: function(a: PPIPAddressFamily; _in: PPIdAnsiChar; len: TIdC_LONG): PIPAddressFamily; cdecl = nil;
  {$EXTERNALSYM d2i_IPAddressFamily}

  i2d_IPAddressFamily: function(a: PIPAddressFamily; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_IPAddressFamily}

  IPAddressFamily_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM IPAddressFamily_it}

  X509v3_asid_add_inherit: function(asid: PASIdentifiers; which: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509v3_asid_add_inherit}

  X509v3_asid_add_id_or_range: function(asid: PASIdentifiers; which: TIdC_INT; min: PASN1_INTEGER; max: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509v3_asid_add_id_or_range}

  X509v3_addr_add_inherit: function(addr: PIPAddrBlocks; afi: TIdC_UINT; safi: PIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509v3_addr_add_inherit}

  X509v3_addr_add_prefix: function(addr: PIPAddrBlocks; afi: TIdC_UINT; safi: PIdC_UINT; a: PIdAnsiChar; prefixlen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509v3_addr_add_prefix}

  X509v3_addr_add_range: function(addr: PIPAddrBlocks; afi: TIdC_UINT; safi: PIdC_UINT; min: PIdAnsiChar; max: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509v3_addr_add_range}

  X509v3_addr_get_afi: function(f: PIPAddressFamily): TIdC_UINT; cdecl = nil;
  {$EXTERNALSYM X509v3_addr_get_afi}

  X509v3_addr_get_range: function(aor: PIPAddressOrRange; afi: TIdC_UINT; min: PIdAnsiChar; max: PIdAnsiChar; length: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509v3_addr_get_range}

  X509v3_asid_is_canonical: function(asid: PASIdentifiers): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509v3_asid_is_canonical}

  X509v3_addr_is_canonical: function(addr: PIPAddrBlocks): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509v3_addr_is_canonical}

  X509v3_asid_canonize: function(asid: PASIdentifiers): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509v3_asid_canonize}

  X509v3_addr_canonize: function(addr: PIPAddrBlocks): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509v3_addr_canonize}

  X509v3_asid_inherits: function(asid: PASIdentifiers): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509v3_asid_inherits}

  X509v3_addr_inherits: function(addr: PIPAddrBlocks): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509v3_addr_inherits}

  X509v3_asid_subset: function(a: PASIdentifiers; b: PASIdentifiers): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509v3_asid_subset}

  X509v3_addr_subset: function(a: PIPAddrBlocks; b: PIPAddrBlocks): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509v3_addr_subset}

  X509v3_asid_validate_path: function(arg1: PX509_STORE_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509v3_asid_validate_path}

  X509v3_addr_validate_path: function(arg1: PX509_STORE_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509v3_addr_validate_path}

  X509v3_asid_validate_resource_set: function(chain: Pstack_st_X509; ext: PASIdentifiers; allow_inheritance: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509v3_asid_validate_resource_set}

  X509v3_addr_validate_resource_set: function(chain: Pstack_st_X509; ext: PIPAddrBlocks; allow_inheritance: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509v3_addr_validate_resource_set}

  NAMING_AUTHORITY_new: function: PNAMING_AUTHORITY; cdecl = nil;
  {$EXTERNALSYM NAMING_AUTHORITY_new}

  NAMING_AUTHORITY_free: procedure(a: PNAMING_AUTHORITY); cdecl = nil;
  {$EXTERNALSYM NAMING_AUTHORITY_free}

  d2i_NAMING_AUTHORITY: function(a: PPNAMING_AUTHORITY; _in: PPIdAnsiChar; len: TIdC_LONG): PNAMING_AUTHORITY; cdecl = nil;
  {$EXTERNALSYM d2i_NAMING_AUTHORITY}

  i2d_NAMING_AUTHORITY: function(a: PNAMING_AUTHORITY; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_NAMING_AUTHORITY}

  NAMING_AUTHORITY_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM NAMING_AUTHORITY_it}

  PROFESSION_INFO_new: function: PPROFESSION_INFO; cdecl = nil;
  {$EXTERNALSYM PROFESSION_INFO_new}

  PROFESSION_INFO_free: procedure(a: PPROFESSION_INFO); cdecl = nil;
  {$EXTERNALSYM PROFESSION_INFO_free}

  d2i_PROFESSION_INFO: function(a: PPPROFESSION_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PPROFESSION_INFO; cdecl = nil;
  {$EXTERNALSYM d2i_PROFESSION_INFO}

  i2d_PROFESSION_INFO: function(a: PPROFESSION_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PROFESSION_INFO}

  PROFESSION_INFO_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM PROFESSION_INFO_it}

  ADMISSIONS_new: function: PADMISSIONS; cdecl = nil;
  {$EXTERNALSYM ADMISSIONS_new}

  ADMISSIONS_free: procedure(a: PADMISSIONS); cdecl = nil;
  {$EXTERNALSYM ADMISSIONS_free}

  d2i_ADMISSIONS: function(a: PPADMISSIONS; _in: PPIdAnsiChar; len: TIdC_LONG): PADMISSIONS; cdecl = nil;
  {$EXTERNALSYM d2i_ADMISSIONS}

  i2d_ADMISSIONS: function(a: PADMISSIONS; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ADMISSIONS}

  ADMISSIONS_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ADMISSIONS_it}

  ADMISSION_SYNTAX_new: function: PADMISSION_SYNTAX; cdecl = nil;
  {$EXTERNALSYM ADMISSION_SYNTAX_new}

  ADMISSION_SYNTAX_free: procedure(a: PADMISSION_SYNTAX); cdecl = nil;
  {$EXTERNALSYM ADMISSION_SYNTAX_free}

  d2i_ADMISSION_SYNTAX: function(a: PPADMISSION_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): PADMISSION_SYNTAX; cdecl = nil;
  {$EXTERNALSYM d2i_ADMISSION_SYNTAX}

  i2d_ADMISSION_SYNTAX: function(a: PADMISSION_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ADMISSION_SYNTAX}

  ADMISSION_SYNTAX_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ADMISSION_SYNTAX_it}

  NAMING_AUTHORITY_get0_authorityId: function(n: PNAMING_AUTHORITY): PASN1_OBJECT; cdecl = nil;
  {$EXTERNALSYM NAMING_AUTHORITY_get0_authorityId}

  NAMING_AUTHORITY_get0_authorityURL: function(n: PNAMING_AUTHORITY): PASN1_IA5STRING; cdecl = nil;
  {$EXTERNALSYM NAMING_AUTHORITY_get0_authorityURL}

  NAMING_AUTHORITY_get0_authorityText: function(n: PNAMING_AUTHORITY): PASN1_STRING; cdecl = nil;
  {$EXTERNALSYM NAMING_AUTHORITY_get0_authorityText}

  NAMING_AUTHORITY_set0_authorityId: procedure(n: PNAMING_AUTHORITY; namingAuthorityId: PASN1_OBJECT); cdecl = nil;
  {$EXTERNALSYM NAMING_AUTHORITY_set0_authorityId}

  NAMING_AUTHORITY_set0_authorityURL: procedure(n: PNAMING_AUTHORITY; namingAuthorityUrl: PASN1_IA5STRING); cdecl = nil;
  {$EXTERNALSYM NAMING_AUTHORITY_set0_authorityURL}

  NAMING_AUTHORITY_set0_authorityText: procedure(n: PNAMING_AUTHORITY; namingAuthorityText: PASN1_STRING); cdecl = nil;
  {$EXTERNALSYM NAMING_AUTHORITY_set0_authorityText}

  ADMISSION_SYNTAX_get0_admissionAuthority: function(_as: PADMISSION_SYNTAX): PGENERAL_NAME; cdecl = nil;
  {$EXTERNALSYM ADMISSION_SYNTAX_get0_admissionAuthority}

  ADMISSION_SYNTAX_set0_admissionAuthority: procedure(_as: PADMISSION_SYNTAX; aa: PGENERAL_NAME); cdecl = nil;
  {$EXTERNALSYM ADMISSION_SYNTAX_set0_admissionAuthority}

  ADMISSION_SYNTAX_get0_contentsOfAdmissions: function(_as: PADMISSION_SYNTAX): Pstack_st_ADMISSIONS; cdecl = nil;
  {$EXTERNALSYM ADMISSION_SYNTAX_get0_contentsOfAdmissions}

  ADMISSION_SYNTAX_set0_contentsOfAdmissions: procedure(_as: PADMISSION_SYNTAX; a: Pstack_st_ADMISSIONS); cdecl = nil;
  {$EXTERNALSYM ADMISSION_SYNTAX_set0_contentsOfAdmissions}

  ADMISSIONS_get0_admissionAuthority: function(a: PADMISSIONS): PGENERAL_NAME; cdecl = nil;
  {$EXTERNALSYM ADMISSIONS_get0_admissionAuthority}

  ADMISSIONS_set0_admissionAuthority: procedure(a: PADMISSIONS; aa: PGENERAL_NAME); cdecl = nil;
  {$EXTERNALSYM ADMISSIONS_set0_admissionAuthority}

  ADMISSIONS_get0_namingAuthority: function(a: PADMISSIONS): PNAMING_AUTHORITY; cdecl = nil;
  {$EXTERNALSYM ADMISSIONS_get0_namingAuthority}

  ADMISSIONS_set0_namingAuthority: procedure(a: PADMISSIONS; na: PNAMING_AUTHORITY); cdecl = nil;
  {$EXTERNALSYM ADMISSIONS_set0_namingAuthority}

  ADMISSIONS_get0_professionInfos: function(a: PADMISSIONS): PPROFESSION_INFOS; cdecl = nil;
  {$EXTERNALSYM ADMISSIONS_get0_professionInfos}

  ADMISSIONS_set0_professionInfos: procedure(a: PADMISSIONS; pi: PPROFESSION_INFOS); cdecl = nil;
  {$EXTERNALSYM ADMISSIONS_set0_professionInfos}

  PROFESSION_INFO_get0_addProfessionInfo: function(pi: PPROFESSION_INFO): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM PROFESSION_INFO_get0_addProfessionInfo}

  PROFESSION_INFO_set0_addProfessionInfo: procedure(pi: PPROFESSION_INFO; aos: PASN1_OCTET_STRING); cdecl = nil;
  {$EXTERNALSYM PROFESSION_INFO_set0_addProfessionInfo}

  PROFESSION_INFO_get0_namingAuthority: function(pi: PPROFESSION_INFO): PNAMING_AUTHORITY; cdecl = nil;
  {$EXTERNALSYM PROFESSION_INFO_get0_namingAuthority}

  PROFESSION_INFO_set0_namingAuthority: procedure(pi: PPROFESSION_INFO; na: PNAMING_AUTHORITY); cdecl = nil;
  {$EXTERNALSYM PROFESSION_INFO_set0_namingAuthority}

  PROFESSION_INFO_get0_professionItems: function(pi: PPROFESSION_INFO): Pstack_st_ASN1_STRING; cdecl = nil;
  {$EXTERNALSYM PROFESSION_INFO_get0_professionItems}

  PROFESSION_INFO_set0_professionItems: procedure(pi: PPROFESSION_INFO; _as: Pstack_st_ASN1_STRING); cdecl = nil;
  {$EXTERNALSYM PROFESSION_INFO_set0_professionItems}

  PROFESSION_INFO_get0_professionOIDs: function(pi: PPROFESSION_INFO): Pstack_st_ASN1_OBJECT; cdecl = nil;
  {$EXTERNALSYM PROFESSION_INFO_get0_professionOIDs}

  PROFESSION_INFO_set0_professionOIDs: procedure(pi: PPROFESSION_INFO; po: Pstack_st_ASN1_OBJECT); cdecl = nil;
  {$EXTERNALSYM PROFESSION_INFO_set0_professionOIDs}

  PROFESSION_INFO_get0_registrationNumber: function(pi: PPROFESSION_INFO): PASN1_PRINTABLESTRING; cdecl = nil;
  {$EXTERNALSYM PROFESSION_INFO_get0_registrationNumber}

  PROFESSION_INFO_set0_registrationNumber: procedure(pi: PPROFESSION_INFO; rn: PASN1_PRINTABLESTRING); cdecl = nil;
  {$EXTERNALSYM PROFESSION_INFO_set0_registrationNumber}

  OSSL_GENERAL_NAMES_print: function(_out: PBIO; gens: PGENERAL_NAMES; indent: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_GENERAL_NAMES_print}

  OSSL_ATTRIBUTES_SYNTAX_new: function: POSSL_ATTRIBUTES_SYNTAX; cdecl = nil;
  {$EXTERNALSYM OSSL_ATTRIBUTES_SYNTAX_new}

  OSSL_ATTRIBUTES_SYNTAX_free: procedure(a: POSSL_ATTRIBUTES_SYNTAX); cdecl = nil;
  {$EXTERNALSYM OSSL_ATTRIBUTES_SYNTAX_free}

  d2i_OSSL_ATTRIBUTES_SYNTAX: function(a: PPOSSL_ATTRIBUTES_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ATTRIBUTES_SYNTAX; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_ATTRIBUTES_SYNTAX}

  i2d_OSSL_ATTRIBUTES_SYNTAX: function(a: POSSL_ATTRIBUTES_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_ATTRIBUTES_SYNTAX}

  OSSL_ATTRIBUTES_SYNTAX_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_ATTRIBUTES_SYNTAX_it}

  OSSL_USER_NOTICE_SYNTAX_new: function: POSSL_USER_NOTICE_SYNTAX; cdecl = nil;
  {$EXTERNALSYM OSSL_USER_NOTICE_SYNTAX_new}

  OSSL_USER_NOTICE_SYNTAX_free: procedure(a: POSSL_USER_NOTICE_SYNTAX); cdecl = nil;
  {$EXTERNALSYM OSSL_USER_NOTICE_SYNTAX_free}

  d2i_OSSL_USER_NOTICE_SYNTAX: function(a: PPOSSL_USER_NOTICE_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_USER_NOTICE_SYNTAX; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_USER_NOTICE_SYNTAX}

  i2d_OSSL_USER_NOTICE_SYNTAX: function(a: POSSL_USER_NOTICE_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_USER_NOTICE_SYNTAX}

  OSSL_USER_NOTICE_SYNTAX_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_USER_NOTICE_SYNTAX_it}

  OSSL_ROLE_SPEC_CERT_ID_new: function: POSSL_ROLE_SPEC_CERT_ID; cdecl = nil;
  {$EXTERNALSYM OSSL_ROLE_SPEC_CERT_ID_new}

  OSSL_ROLE_SPEC_CERT_ID_free: procedure(a: POSSL_ROLE_SPEC_CERT_ID); cdecl = nil;
  {$EXTERNALSYM OSSL_ROLE_SPEC_CERT_ID_free}

  d2i_OSSL_ROLE_SPEC_CERT_ID: function(a: PPOSSL_ROLE_SPEC_CERT_ID; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ROLE_SPEC_CERT_ID; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_ROLE_SPEC_CERT_ID}

  i2d_OSSL_ROLE_SPEC_CERT_ID: function(a: POSSL_ROLE_SPEC_CERT_ID; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_ROLE_SPEC_CERT_ID}

  OSSL_ROLE_SPEC_CERT_ID_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_ROLE_SPEC_CERT_ID_it}

  OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new: function: POSSL_ROLE_SPEC_CERT_ID_SYNTAX; cdecl = nil;
  {$EXTERNALSYM OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new}

  OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free: procedure(a: POSSL_ROLE_SPEC_CERT_ID_SYNTAX); cdecl = nil;
  {$EXTERNALSYM OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free}

  d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX: function(a: PPOSSL_ROLE_SPEC_CERT_ID_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ROLE_SPEC_CERT_ID_SYNTAX; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX}

  i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX: function(a: POSSL_ROLE_SPEC_CERT_ID_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX}

  OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it}

  OSSL_HASH_new: function: POSSL_HASH; cdecl = nil;
  {$EXTERNALSYM OSSL_HASH_new}

  OSSL_HASH_free: procedure(a: POSSL_HASH); cdecl = nil;
  {$EXTERNALSYM OSSL_HASH_free}

  d2i_OSSL_HASH: function(a: PPOSSL_HASH; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_HASH; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_HASH}

  i2d_OSSL_HASH: function(a: POSSL_HASH; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_HASH}

  OSSL_HASH_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_HASH_it}

  OSSL_INFO_SYNTAX_new: function: POSSL_INFO_SYNTAX; cdecl = nil;
  {$EXTERNALSYM OSSL_INFO_SYNTAX_new}

  OSSL_INFO_SYNTAX_free: procedure(a: POSSL_INFO_SYNTAX); cdecl = nil;
  {$EXTERNALSYM OSSL_INFO_SYNTAX_free}

  d2i_OSSL_INFO_SYNTAX: function(a: PPOSSL_INFO_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_INFO_SYNTAX; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_INFO_SYNTAX}

  i2d_OSSL_INFO_SYNTAX: function(a: POSSL_INFO_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_INFO_SYNTAX}

  OSSL_INFO_SYNTAX_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_INFO_SYNTAX_it}

  OSSL_INFO_SYNTAX_POINTER_new: function: POSSL_INFO_SYNTAX_POINTER; cdecl = nil;
  {$EXTERNALSYM OSSL_INFO_SYNTAX_POINTER_new}

  OSSL_INFO_SYNTAX_POINTER_free: procedure(a: POSSL_INFO_SYNTAX_POINTER); cdecl = nil;
  {$EXTERNALSYM OSSL_INFO_SYNTAX_POINTER_free}

  d2i_OSSL_INFO_SYNTAX_POINTER: function(a: PPOSSL_INFO_SYNTAX_POINTER; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_INFO_SYNTAX_POINTER; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_INFO_SYNTAX_POINTER}

  i2d_OSSL_INFO_SYNTAX_POINTER: function(a: POSSL_INFO_SYNTAX_POINTER; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_INFO_SYNTAX_POINTER}

  OSSL_INFO_SYNTAX_POINTER_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_INFO_SYNTAX_POINTER_it}

  OSSL_PRIVILEGE_POLICY_ID_new: function: POSSL_PRIVILEGE_POLICY_ID; cdecl = nil;
  {$EXTERNALSYM OSSL_PRIVILEGE_POLICY_ID_new}

  OSSL_PRIVILEGE_POLICY_ID_free: procedure(a: POSSL_PRIVILEGE_POLICY_ID); cdecl = nil;
  {$EXTERNALSYM OSSL_PRIVILEGE_POLICY_ID_free}

  d2i_OSSL_PRIVILEGE_POLICY_ID: function(a: PPOSSL_PRIVILEGE_POLICY_ID; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_PRIVILEGE_POLICY_ID; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_PRIVILEGE_POLICY_ID}

  i2d_OSSL_PRIVILEGE_POLICY_ID: function(a: POSSL_PRIVILEGE_POLICY_ID; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_PRIVILEGE_POLICY_ID}

  OSSL_PRIVILEGE_POLICY_ID_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_PRIVILEGE_POLICY_ID_it}

  OSSL_ATTRIBUTE_DESCRIPTOR_new: function: POSSL_ATTRIBUTE_DESCRIPTOR; cdecl = nil;
  {$EXTERNALSYM OSSL_ATTRIBUTE_DESCRIPTOR_new}

  OSSL_ATTRIBUTE_DESCRIPTOR_free: procedure(a: POSSL_ATTRIBUTE_DESCRIPTOR); cdecl = nil;
  {$EXTERNALSYM OSSL_ATTRIBUTE_DESCRIPTOR_free}

  d2i_OSSL_ATTRIBUTE_DESCRIPTOR: function(a: PPOSSL_ATTRIBUTE_DESCRIPTOR; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ATTRIBUTE_DESCRIPTOR; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_ATTRIBUTE_DESCRIPTOR}

  i2d_OSSL_ATTRIBUTE_DESCRIPTOR: function(a: POSSL_ATTRIBUTE_DESCRIPTOR; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_ATTRIBUTE_DESCRIPTOR}

  OSSL_ATTRIBUTE_DESCRIPTOR_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_ATTRIBUTE_DESCRIPTOR_it}

  OSSL_DAY_TIME_new: function: POSSL_DAY_TIME; cdecl = nil;
  {$EXTERNALSYM OSSL_DAY_TIME_new}

  OSSL_DAY_TIME_free: procedure(a: POSSL_DAY_TIME); cdecl = nil;
  {$EXTERNALSYM OSSL_DAY_TIME_free}

  d2i_OSSL_DAY_TIME: function(a: PPOSSL_DAY_TIME; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_DAY_TIME; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_DAY_TIME}

  i2d_OSSL_DAY_TIME: function(a: POSSL_DAY_TIME; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_DAY_TIME}

  OSSL_DAY_TIME_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_DAY_TIME_it}

  OSSL_DAY_TIME_BAND_new: function: POSSL_DAY_TIME_BAND; cdecl = nil;
  {$EXTERNALSYM OSSL_DAY_TIME_BAND_new}

  OSSL_DAY_TIME_BAND_free: procedure(a: POSSL_DAY_TIME_BAND); cdecl = nil;
  {$EXTERNALSYM OSSL_DAY_TIME_BAND_free}

  d2i_OSSL_DAY_TIME_BAND: function(a: PPOSSL_DAY_TIME_BAND; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_DAY_TIME_BAND; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_DAY_TIME_BAND}

  i2d_OSSL_DAY_TIME_BAND: function(a: POSSL_DAY_TIME_BAND; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_DAY_TIME_BAND}

  OSSL_DAY_TIME_BAND_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_DAY_TIME_BAND_it}

  OSSL_TIME_SPEC_DAY_new: function: POSSL_TIME_SPEC_DAY; cdecl = nil;
  {$EXTERNALSYM OSSL_TIME_SPEC_DAY_new}

  OSSL_TIME_SPEC_DAY_free: procedure(a: POSSL_TIME_SPEC_DAY); cdecl = nil;
  {$EXTERNALSYM OSSL_TIME_SPEC_DAY_free}

  d2i_OSSL_TIME_SPEC_DAY: function(a: PPOSSL_TIME_SPEC_DAY; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_SPEC_DAY; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_TIME_SPEC_DAY}

  i2d_OSSL_TIME_SPEC_DAY: function(a: POSSL_TIME_SPEC_DAY; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_TIME_SPEC_DAY}

  OSSL_TIME_SPEC_DAY_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_TIME_SPEC_DAY_it}

  OSSL_TIME_SPEC_WEEKS_new: function: POSSL_TIME_SPEC_WEEKS; cdecl = nil;
  {$EXTERNALSYM OSSL_TIME_SPEC_WEEKS_new}

  OSSL_TIME_SPEC_WEEKS_free: procedure(a: POSSL_TIME_SPEC_WEEKS); cdecl = nil;
  {$EXTERNALSYM OSSL_TIME_SPEC_WEEKS_free}

  d2i_OSSL_TIME_SPEC_WEEKS: function(a: PPOSSL_TIME_SPEC_WEEKS; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_SPEC_WEEKS; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_TIME_SPEC_WEEKS}

  i2d_OSSL_TIME_SPEC_WEEKS: function(a: POSSL_TIME_SPEC_WEEKS; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_TIME_SPEC_WEEKS}

  OSSL_TIME_SPEC_WEEKS_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_TIME_SPEC_WEEKS_it}

  OSSL_TIME_SPEC_MONTH_new: function: POSSL_TIME_SPEC_MONTH; cdecl = nil;
  {$EXTERNALSYM OSSL_TIME_SPEC_MONTH_new}

  OSSL_TIME_SPEC_MONTH_free: procedure(a: POSSL_TIME_SPEC_MONTH); cdecl = nil;
  {$EXTERNALSYM OSSL_TIME_SPEC_MONTH_free}

  d2i_OSSL_TIME_SPEC_MONTH: function(a: PPOSSL_TIME_SPEC_MONTH; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_SPEC_MONTH; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_TIME_SPEC_MONTH}

  i2d_OSSL_TIME_SPEC_MONTH: function(a: POSSL_TIME_SPEC_MONTH; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_TIME_SPEC_MONTH}

  OSSL_TIME_SPEC_MONTH_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_TIME_SPEC_MONTH_it}

  OSSL_NAMED_DAY_new: function: POSSL_NAMED_DAY; cdecl = nil;
  {$EXTERNALSYM OSSL_NAMED_DAY_new}

  OSSL_NAMED_DAY_free: procedure(a: POSSL_NAMED_DAY); cdecl = nil;
  {$EXTERNALSYM OSSL_NAMED_DAY_free}

  d2i_OSSL_NAMED_DAY: function(a: PPOSSL_NAMED_DAY; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_NAMED_DAY; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_NAMED_DAY}

  i2d_OSSL_NAMED_DAY: function(a: POSSL_NAMED_DAY; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_NAMED_DAY}

  OSSL_NAMED_DAY_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_NAMED_DAY_it}

  OSSL_TIME_SPEC_X_DAY_OF_new: function: POSSL_TIME_SPEC_X_DAY_OF; cdecl = nil;
  {$EXTERNALSYM OSSL_TIME_SPEC_X_DAY_OF_new}

  OSSL_TIME_SPEC_X_DAY_OF_free: procedure(a: POSSL_TIME_SPEC_X_DAY_OF); cdecl = nil;
  {$EXTERNALSYM OSSL_TIME_SPEC_X_DAY_OF_free}

  d2i_OSSL_TIME_SPEC_X_DAY_OF: function(a: PPOSSL_TIME_SPEC_X_DAY_OF; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_SPEC_X_DAY_OF; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_TIME_SPEC_X_DAY_OF}

  i2d_OSSL_TIME_SPEC_X_DAY_OF: function(a: POSSL_TIME_SPEC_X_DAY_OF; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_TIME_SPEC_X_DAY_OF}

  OSSL_TIME_SPEC_X_DAY_OF_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_TIME_SPEC_X_DAY_OF_it}

  OSSL_TIME_SPEC_ABSOLUTE_new: function: POSSL_TIME_SPEC_ABSOLUTE; cdecl = nil;
  {$EXTERNALSYM OSSL_TIME_SPEC_ABSOLUTE_new}

  OSSL_TIME_SPEC_ABSOLUTE_free: procedure(a: POSSL_TIME_SPEC_ABSOLUTE); cdecl = nil;
  {$EXTERNALSYM OSSL_TIME_SPEC_ABSOLUTE_free}

  d2i_OSSL_TIME_SPEC_ABSOLUTE: function(a: PPOSSL_TIME_SPEC_ABSOLUTE; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_SPEC_ABSOLUTE; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_TIME_SPEC_ABSOLUTE}

  i2d_OSSL_TIME_SPEC_ABSOLUTE: function(a: POSSL_TIME_SPEC_ABSOLUTE; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_TIME_SPEC_ABSOLUTE}

  OSSL_TIME_SPEC_ABSOLUTE_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_TIME_SPEC_ABSOLUTE_it}

  OSSL_TIME_SPEC_TIME_new: function: POSSL_TIME_SPEC_TIME; cdecl = nil;
  {$EXTERNALSYM OSSL_TIME_SPEC_TIME_new}

  OSSL_TIME_SPEC_TIME_free: procedure(a: POSSL_TIME_SPEC_TIME); cdecl = nil;
  {$EXTERNALSYM OSSL_TIME_SPEC_TIME_free}

  d2i_OSSL_TIME_SPEC_TIME: function(a: PPOSSL_TIME_SPEC_TIME; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_SPEC_TIME; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_TIME_SPEC_TIME}

  i2d_OSSL_TIME_SPEC_TIME: function(a: POSSL_TIME_SPEC_TIME; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_TIME_SPEC_TIME}

  OSSL_TIME_SPEC_TIME_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_TIME_SPEC_TIME_it}

  OSSL_TIME_SPEC_new: function: POSSL_TIME_SPEC; cdecl = nil;
  {$EXTERNALSYM OSSL_TIME_SPEC_new}

  OSSL_TIME_SPEC_free: procedure(a: POSSL_TIME_SPEC); cdecl = nil;
  {$EXTERNALSYM OSSL_TIME_SPEC_free}

  d2i_OSSL_TIME_SPEC: function(a: PPOSSL_TIME_SPEC; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_SPEC; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_TIME_SPEC}

  i2d_OSSL_TIME_SPEC: function(a: POSSL_TIME_SPEC; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_TIME_SPEC}

  OSSL_TIME_SPEC_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_TIME_SPEC_it}

  OSSL_TIME_PERIOD_new: function: POSSL_TIME_PERIOD; cdecl = nil;
  {$EXTERNALSYM OSSL_TIME_PERIOD_new}

  OSSL_TIME_PERIOD_free: procedure(a: POSSL_TIME_PERIOD); cdecl = nil;
  {$EXTERNALSYM OSSL_TIME_PERIOD_free}

  d2i_OSSL_TIME_PERIOD: function(a: PPOSSL_TIME_PERIOD; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_PERIOD; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_TIME_PERIOD}

  i2d_OSSL_TIME_PERIOD: function(a: POSSL_TIME_PERIOD; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_TIME_PERIOD}

  OSSL_TIME_PERIOD_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_TIME_PERIOD_it}

  OSSL_ATAV_new: function: POSSL_ATAV; cdecl = nil;
  {$EXTERNALSYM OSSL_ATAV_new}

  OSSL_ATAV_free: procedure(a: POSSL_ATAV); cdecl = nil;
  {$EXTERNALSYM OSSL_ATAV_free}

  d2i_OSSL_ATAV: function(a: PPOSSL_ATAV; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ATAV; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_ATAV}

  i2d_OSSL_ATAV: function(a: POSSL_ATAV; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_ATAV}

  OSSL_ATAV_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_ATAV_it}

  OSSL_ATTRIBUTE_TYPE_MAPPING_new: function: POSSL_ATTRIBUTE_TYPE_MAPPING; cdecl = nil;
  {$EXTERNALSYM OSSL_ATTRIBUTE_TYPE_MAPPING_new}

  OSSL_ATTRIBUTE_TYPE_MAPPING_free: procedure(a: POSSL_ATTRIBUTE_TYPE_MAPPING); cdecl = nil;
  {$EXTERNALSYM OSSL_ATTRIBUTE_TYPE_MAPPING_free}

  d2i_OSSL_ATTRIBUTE_TYPE_MAPPING: function(a: PPOSSL_ATTRIBUTE_TYPE_MAPPING; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ATTRIBUTE_TYPE_MAPPING; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_ATTRIBUTE_TYPE_MAPPING}

  i2d_OSSL_ATTRIBUTE_TYPE_MAPPING: function(a: POSSL_ATTRIBUTE_TYPE_MAPPING; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_ATTRIBUTE_TYPE_MAPPING}

  OSSL_ATTRIBUTE_TYPE_MAPPING_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_ATTRIBUTE_TYPE_MAPPING_it}

  OSSL_ATTRIBUTE_VALUE_MAPPING_new: function: POSSL_ATTRIBUTE_VALUE_MAPPING; cdecl = nil;
  {$EXTERNALSYM OSSL_ATTRIBUTE_VALUE_MAPPING_new}

  OSSL_ATTRIBUTE_VALUE_MAPPING_free: procedure(a: POSSL_ATTRIBUTE_VALUE_MAPPING); cdecl = nil;
  {$EXTERNALSYM OSSL_ATTRIBUTE_VALUE_MAPPING_free}

  d2i_OSSL_ATTRIBUTE_VALUE_MAPPING: function(a: PPOSSL_ATTRIBUTE_VALUE_MAPPING; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ATTRIBUTE_VALUE_MAPPING; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_ATTRIBUTE_VALUE_MAPPING}

  i2d_OSSL_ATTRIBUTE_VALUE_MAPPING: function(a: POSSL_ATTRIBUTE_VALUE_MAPPING; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_ATTRIBUTE_VALUE_MAPPING}

  OSSL_ATTRIBUTE_VALUE_MAPPING_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_ATTRIBUTE_VALUE_MAPPING_it}

  OSSL_ATTRIBUTE_MAPPING_new: function: POSSL_ATTRIBUTE_MAPPING; cdecl = nil;
  {$EXTERNALSYM OSSL_ATTRIBUTE_MAPPING_new}

  OSSL_ATTRIBUTE_MAPPING_free: procedure(a: POSSL_ATTRIBUTE_MAPPING); cdecl = nil;
  {$EXTERNALSYM OSSL_ATTRIBUTE_MAPPING_free}

  d2i_OSSL_ATTRIBUTE_MAPPING: function(a: PPOSSL_ATTRIBUTE_MAPPING; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ATTRIBUTE_MAPPING; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_ATTRIBUTE_MAPPING}

  i2d_OSSL_ATTRIBUTE_MAPPING: function(a: POSSL_ATTRIBUTE_MAPPING; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_ATTRIBUTE_MAPPING}

  OSSL_ATTRIBUTE_MAPPING_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_ATTRIBUTE_MAPPING_it}

  OSSL_ATTRIBUTE_MAPPINGS_new: function: POSSL_ATTRIBUTE_MAPPINGS; cdecl = nil;
  {$EXTERNALSYM OSSL_ATTRIBUTE_MAPPINGS_new}

  OSSL_ATTRIBUTE_MAPPINGS_free: procedure(a: POSSL_ATTRIBUTE_MAPPINGS); cdecl = nil;
  {$EXTERNALSYM OSSL_ATTRIBUTE_MAPPINGS_free}

  d2i_OSSL_ATTRIBUTE_MAPPINGS: function(a: PPOSSL_ATTRIBUTE_MAPPINGS; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ATTRIBUTE_MAPPINGS; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_ATTRIBUTE_MAPPINGS}

  i2d_OSSL_ATTRIBUTE_MAPPINGS: function(a: POSSL_ATTRIBUTE_MAPPINGS; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_ATTRIBUTE_MAPPINGS}

  OSSL_ATTRIBUTE_MAPPINGS_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_ATTRIBUTE_MAPPINGS_it}

  OSSL_ALLOWED_ATTRIBUTES_CHOICE_new: function: POSSL_ALLOWED_ATTRIBUTES_CHOICE; cdecl = nil;
  {$EXTERNALSYM OSSL_ALLOWED_ATTRIBUTES_CHOICE_new}

  OSSL_ALLOWED_ATTRIBUTES_CHOICE_free: procedure(a: POSSL_ALLOWED_ATTRIBUTES_CHOICE); cdecl = nil;
  {$EXTERNALSYM OSSL_ALLOWED_ATTRIBUTES_CHOICE_free}

  d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE: function(a: PPOSSL_ALLOWED_ATTRIBUTES_CHOICE; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ALLOWED_ATTRIBUTES_CHOICE; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE}

  i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE: function(a: POSSL_ALLOWED_ATTRIBUTES_CHOICE; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE}

  OSSL_ALLOWED_ATTRIBUTES_CHOICE_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_ALLOWED_ATTRIBUTES_CHOICE_it}

  OSSL_ALLOWED_ATTRIBUTES_ITEM_new: function: POSSL_ALLOWED_ATTRIBUTES_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_ALLOWED_ATTRIBUTES_ITEM_new}

  OSSL_ALLOWED_ATTRIBUTES_ITEM_free: procedure(a: POSSL_ALLOWED_ATTRIBUTES_ITEM); cdecl = nil;
  {$EXTERNALSYM OSSL_ALLOWED_ATTRIBUTES_ITEM_free}

  d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM: function(a: PPOSSL_ALLOWED_ATTRIBUTES_ITEM; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ALLOWED_ATTRIBUTES_ITEM; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM}

  i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM: function(a: POSSL_ALLOWED_ATTRIBUTES_ITEM; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM}

  OSSL_ALLOWED_ATTRIBUTES_ITEM_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_ALLOWED_ATTRIBUTES_ITEM_it}

  OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new: function: POSSL_ALLOWED_ATTRIBUTES_SYNTAX; cdecl = nil;
  {$EXTERNALSYM OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new}

  OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free: procedure(a: POSSL_ALLOWED_ATTRIBUTES_SYNTAX); cdecl = nil;
  {$EXTERNALSYM OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free}

  d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX: function(a: PPOSSL_ALLOWED_ATTRIBUTES_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ALLOWED_ATTRIBUTES_SYNTAX; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX}

  i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX: function(a: POSSL_ALLOWED_ATTRIBUTES_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX}

  OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it}

  OSSL_AA_DIST_POINT_new: function: POSSL_AA_DIST_POINT; cdecl = nil;
  {$EXTERNALSYM OSSL_AA_DIST_POINT_new}

  OSSL_AA_DIST_POINT_free: procedure(a: POSSL_AA_DIST_POINT); cdecl = nil;
  {$EXTERNALSYM OSSL_AA_DIST_POINT_free}

  d2i_OSSL_AA_DIST_POINT: function(a: PPOSSL_AA_DIST_POINT; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_AA_DIST_POINT; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_AA_DIST_POINT}

  i2d_OSSL_AA_DIST_POINT: function(a: POSSL_AA_DIST_POINT; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_AA_DIST_POINT}

  OSSL_AA_DIST_POINT_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_AA_DIST_POINT_it}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function GENERAL_NAME_set1_X509_NAME(tgt: PPGENERAL_NAME; src: PX509_NAME): TIdC_INT; cdecl;
function DIST_POINT_NAME_dup(a: PDIST_POINT_NAME): PDIST_POINT_NAME; cdecl;
function PROXY_POLICY_new: PPROXY_POLICY; cdecl;
procedure PROXY_POLICY_free(a: PPROXY_POLICY); cdecl;
function d2i_PROXY_POLICY(a: PPPROXY_POLICY; _in: PPIdAnsiChar; len: TIdC_LONG): PPROXY_POLICY; cdecl;
function i2d_PROXY_POLICY(a: PPROXY_POLICY; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function PROXY_POLICY_it: PASN1_ITEM; cdecl;
function PROXY_CERT_INFO_EXTENSION_new: PPROXY_CERT_INFO_EXTENSION; cdecl;
procedure PROXY_CERT_INFO_EXTENSION_free(a: PPROXY_CERT_INFO_EXTENSION); cdecl;
function d2i_PROXY_CERT_INFO_EXTENSION(a: PPPROXY_CERT_INFO_EXTENSION; _in: PPIdAnsiChar; len: TIdC_LONG): PPROXY_CERT_INFO_EXTENSION; cdecl;
function i2d_PROXY_CERT_INFO_EXTENSION(a: PPROXY_CERT_INFO_EXTENSION; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function PROXY_CERT_INFO_EXTENSION_it: PASN1_ITEM; cdecl;
function BASIC_CONSTRAINTS_new: PBASIC_CONSTRAINTS; cdecl;
procedure BASIC_CONSTRAINTS_free(a: PBASIC_CONSTRAINTS); cdecl;
function d2i_BASIC_CONSTRAINTS(a: PPBASIC_CONSTRAINTS; _in: PPIdAnsiChar; len: TIdC_LONG): PBASIC_CONSTRAINTS; cdecl;
function i2d_BASIC_CONSTRAINTS(a: PBASIC_CONSTRAINTS; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function BASIC_CONSTRAINTS_it: PASN1_ITEM; cdecl;
function OSSL_BASIC_ATTR_CONSTRAINTS_new: POSSL_BASIC_ATTR_CONSTRAINTS; cdecl;
procedure OSSL_BASIC_ATTR_CONSTRAINTS_free(a: POSSL_BASIC_ATTR_CONSTRAINTS); cdecl;
function d2i_OSSL_BASIC_ATTR_CONSTRAINTS(a: PPOSSL_BASIC_ATTR_CONSTRAINTS; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_BASIC_ATTR_CONSTRAINTS; cdecl;
function i2d_OSSL_BASIC_ATTR_CONSTRAINTS(a: POSSL_BASIC_ATTR_CONSTRAINTS; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_BASIC_ATTR_CONSTRAINTS_it: PASN1_ITEM; cdecl;
function SXNET_new: PSXNET; cdecl;
procedure SXNET_free(a: PSXNET); cdecl;
function d2i_SXNET(a: PPSXNET; _in: PPIdAnsiChar; len: TIdC_LONG): PSXNET; cdecl;
function i2d_SXNET(a: PSXNET; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function SXNET_it: PASN1_ITEM; cdecl;
function SXNETID_new: PSXNETID; cdecl;
procedure SXNETID_free(a: PSXNETID); cdecl;
function d2i_SXNETID(a: PPSXNETID; _in: PPIdAnsiChar; len: TIdC_LONG): PSXNETID; cdecl;
function i2d_SXNETID(a: PSXNETID; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function SXNETID_it: PASN1_ITEM; cdecl;
function ISSUER_SIGN_TOOL_new: PISSUER_SIGN_TOOL; cdecl;
procedure ISSUER_SIGN_TOOL_free(a: PISSUER_SIGN_TOOL); cdecl;
function d2i_ISSUER_SIGN_TOOL(a: PPISSUER_SIGN_TOOL; _in: PPIdAnsiChar; len: TIdC_LONG): PISSUER_SIGN_TOOL; cdecl;
function i2d_ISSUER_SIGN_TOOL(a: PISSUER_SIGN_TOOL; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ISSUER_SIGN_TOOL_it: PASN1_ITEM; cdecl;
function SXNET_add_id_asc(psx: PPSXNET; zone: PIdAnsiChar; user: PIdAnsiChar; userlen: TIdC_INT): TIdC_INT; cdecl;
function SXNET_add_id_ulong(psx: PPSXNET; lzone: TIdC_ULONG; user: PIdAnsiChar; userlen: TIdC_INT): TIdC_INT; cdecl;
function SXNET_add_id_INTEGER(psx: PPSXNET; izone: PASN1_INTEGER; user: PIdAnsiChar; userlen: TIdC_INT): TIdC_INT; cdecl;
function SXNET_get_id_asc(sx: PSXNET; zone: PIdAnsiChar): PASN1_OCTET_STRING; cdecl;
function SXNET_get_id_ulong(sx: PSXNET; lzone: TIdC_ULONG): PASN1_OCTET_STRING; cdecl;
function SXNET_get_id_INTEGER(sx: PSXNET; zone: PASN1_INTEGER): PASN1_OCTET_STRING; cdecl;
function AUTHORITY_KEYID_new: PAUTHORITY_KEYID; cdecl;
procedure AUTHORITY_KEYID_free(a: PAUTHORITY_KEYID); cdecl;
function d2i_AUTHORITY_KEYID(a: PPAUTHORITY_KEYID; _in: PPIdAnsiChar; len: TIdC_LONG): PAUTHORITY_KEYID; cdecl;
function i2d_AUTHORITY_KEYID(a: PAUTHORITY_KEYID; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function AUTHORITY_KEYID_it: PASN1_ITEM; cdecl;
function PKEY_USAGE_PERIOD_new: PPKEY_USAGE_PERIOD; cdecl;
procedure PKEY_USAGE_PERIOD_free(a: PPKEY_USAGE_PERIOD); cdecl;
function d2i_PKEY_USAGE_PERIOD(a: PPPKEY_USAGE_PERIOD; _in: PPIdAnsiChar; len: TIdC_LONG): PPKEY_USAGE_PERIOD; cdecl;
function i2d_PKEY_USAGE_PERIOD(a: PPKEY_USAGE_PERIOD; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function PKEY_USAGE_PERIOD_it: PASN1_ITEM; cdecl;
function GENERAL_NAME_new: PGENERAL_NAME; cdecl;
procedure GENERAL_NAME_free(a: PGENERAL_NAME); cdecl;
function d2i_GENERAL_NAME(a: PPGENERAL_NAME; _in: PPIdAnsiChar; len: TIdC_LONG): PGENERAL_NAME; cdecl;
function i2d_GENERAL_NAME(a: PGENERAL_NAME; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function GENERAL_NAME_it: PASN1_ITEM; cdecl;
function GENERAL_NAME_dup(a: PGENERAL_NAME): PGENERAL_NAME; cdecl;
function GENERAL_NAME_cmp(a: PGENERAL_NAME; b: PGENERAL_NAME): TIdC_INT; cdecl;
function v2i_ASN1_BIT_STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; nval: Pstack_st_CONF_VALUE): PASN1_BIT_STRING; cdecl;
function i2v_ASN1_BIT_STRING(method: PX509V3_EXT_METHOD; bits: PASN1_BIT_STRING; extlist: Pstack_st_CONF_VALUE): Pstack_st_CONF_VALUE; cdecl;
function i2s_ASN1_IA5STRING(method: PX509V3_EXT_METHOD; ia5: PASN1_IA5STRING): PIdAnsiChar; cdecl;
function s2i_ASN1_IA5STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; str: PIdAnsiChar): PASN1_IA5STRING; cdecl;
function i2s_ASN1_UTF8STRING(method: PX509V3_EXT_METHOD; utf8: PASN1_UTF8STRING): PIdAnsiChar; cdecl;
function s2i_ASN1_UTF8STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; str: PIdAnsiChar): PASN1_UTF8STRING; cdecl;
function i2v_GENERAL_NAME(method: PX509V3_EXT_METHOD; gen: PGENERAL_NAME; ret: Pstack_st_CONF_VALUE): Pstack_st_CONF_VALUE; cdecl;
function GENERAL_NAME_print(_out: PBIO; gen: PGENERAL_NAME): TIdC_INT; cdecl;
function GENERAL_NAMES_new: PGENERAL_NAMES; cdecl;
procedure GENERAL_NAMES_free(a: PGENERAL_NAMES); cdecl;
function d2i_GENERAL_NAMES(a: PPGENERAL_NAMES; _in: PPIdAnsiChar; len: TIdC_LONG): PGENERAL_NAMES; cdecl;
function i2d_GENERAL_NAMES(a: PGENERAL_NAMES; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function GENERAL_NAMES_it: PASN1_ITEM; cdecl;
function i2v_GENERAL_NAMES(method: PX509V3_EXT_METHOD; gen: PGENERAL_NAMES; extlist: Pstack_st_CONF_VALUE): Pstack_st_CONF_VALUE; cdecl;
function v2i_GENERAL_NAMES(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; nval: Pstack_st_CONF_VALUE): PGENERAL_NAMES; cdecl;
function OTHERNAME_new: POTHERNAME; cdecl;
procedure OTHERNAME_free(a: POTHERNAME); cdecl;
function d2i_OTHERNAME(a: PPOTHERNAME; _in: PPIdAnsiChar; len: TIdC_LONG): POTHERNAME; cdecl;
function i2d_OTHERNAME(a: POTHERNAME; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OTHERNAME_it: PASN1_ITEM; cdecl;
function EDIPARTYNAME_new: PEDIPARTYNAME; cdecl;
procedure EDIPARTYNAME_free(a: PEDIPARTYNAME); cdecl;
function d2i_EDIPARTYNAME(a: PPEDIPARTYNAME; _in: PPIdAnsiChar; len: TIdC_LONG): PEDIPARTYNAME; cdecl;
function i2d_EDIPARTYNAME(a: PEDIPARTYNAME; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function EDIPARTYNAME_it: PASN1_ITEM; cdecl;
function OTHERNAME_cmp(a: POTHERNAME; b: POTHERNAME): TIdC_INT; cdecl;
procedure GENERAL_NAME_set0_value(a: PGENERAL_NAME; _type: TIdC_INT; value: Pointer); cdecl;
function GENERAL_NAME_get0_value(a: PGENERAL_NAME; ptype: PIdC_INT): Pointer; cdecl;
function GENERAL_NAME_set0_othername(gen: PGENERAL_NAME; oid: PASN1_OBJECT; value: PASN1_TYPE): TIdC_INT; cdecl;
function GENERAL_NAME_get0_otherName(gen: PGENERAL_NAME; poid: PPASN1_OBJECT; pvalue: PPASN1_TYPE): TIdC_INT; cdecl;
function i2s_ASN1_OCTET_STRING(method: PX509V3_EXT_METHOD; ia5: PASN1_OCTET_STRING): PIdAnsiChar; cdecl;
function s2i_ASN1_OCTET_STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; str: PIdAnsiChar): PASN1_OCTET_STRING; cdecl;
function EXTENDED_KEY_USAGE_new: PEXTENDED_KEY_USAGE; cdecl;
procedure EXTENDED_KEY_USAGE_free(a: PEXTENDED_KEY_USAGE); cdecl;
function d2i_EXTENDED_KEY_USAGE(a: PPEXTENDED_KEY_USAGE; _in: PPIdAnsiChar; len: TIdC_LONG): PEXTENDED_KEY_USAGE; cdecl;
function i2d_EXTENDED_KEY_USAGE(a: PEXTENDED_KEY_USAGE; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function EXTENDED_KEY_USAGE_it: PASN1_ITEM; cdecl;
function i2a_ACCESS_DESCRIPTION(bp: PBIO; a: PACCESS_DESCRIPTION): TIdC_INT; cdecl;
function TLS_FEATURE_new: PLS_FEATURE; cdecl;
procedure TLS_FEATURE_free(a: PLS_FEATURE); cdecl;
function CERTIFICATEPOLICIES_new: PCERTIFICATEPOLICIES; cdecl;
procedure CERTIFICATEPOLICIES_free(a: PCERTIFICATEPOLICIES); cdecl;
function d2i_CERTIFICATEPOLICIES(a: PPCERTIFICATEPOLICIES; _in: PPIdAnsiChar; len: TIdC_LONG): PCERTIFICATEPOLICIES; cdecl;
function i2d_CERTIFICATEPOLICIES(a: PCERTIFICATEPOLICIES; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function CERTIFICATEPOLICIES_it: PASN1_ITEM; cdecl;
function POLICYINFO_new: PPOLICYINFO; cdecl;
procedure POLICYINFO_free(a: PPOLICYINFO); cdecl;
function d2i_POLICYINFO(a: PPPOLICYINFO; _in: PPIdAnsiChar; len: TIdC_LONG): PPOLICYINFO; cdecl;
function i2d_POLICYINFO(a: PPOLICYINFO; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function POLICYINFO_it: PASN1_ITEM; cdecl;
function POLICYQUALINFO_new: PPOLICYQUALINFO; cdecl;
procedure POLICYQUALINFO_free(a: PPOLICYQUALINFO); cdecl;
function d2i_POLICYQUALINFO(a: PPPOLICYQUALINFO; _in: PPIdAnsiChar; len: TIdC_LONG): PPOLICYQUALINFO; cdecl;
function i2d_POLICYQUALINFO(a: PPOLICYQUALINFO; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function POLICYQUALINFO_it: PASN1_ITEM; cdecl;
function USERNOTICE_new: PUSERNOTICE; cdecl;
procedure USERNOTICE_free(a: PUSERNOTICE); cdecl;
function d2i_USERNOTICE(a: PPUSERNOTICE; _in: PPIdAnsiChar; len: TIdC_LONG): PUSERNOTICE; cdecl;
function i2d_USERNOTICE(a: PUSERNOTICE; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function USERNOTICE_it: PASN1_ITEM; cdecl;
function NOTICEREF_new: PNOTICEREF; cdecl;
procedure NOTICEREF_free(a: PNOTICEREF); cdecl;
function d2i_NOTICEREF(a: PPNOTICEREF; _in: PPIdAnsiChar; len: TIdC_LONG): PNOTICEREF; cdecl;
function i2d_NOTICEREF(a: PNOTICEREF; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function NOTICEREF_it: PASN1_ITEM; cdecl;
function CRL_DIST_POINTS_new: PCRL_DIST_POINTS; cdecl;
procedure CRL_DIST_POINTS_free(a: PCRL_DIST_POINTS); cdecl;
function d2i_CRL_DIST_POINTS(a: PPCRL_DIST_POINTS; _in: PPIdAnsiChar; len: TIdC_LONG): PCRL_DIST_POINTS; cdecl;
function i2d_CRL_DIST_POINTS(a: PCRL_DIST_POINTS; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function CRL_DIST_POINTS_it: PASN1_ITEM; cdecl;
function DIST_POINT_new: PDIST_POINT; cdecl;
procedure DIST_POINT_free(a: PDIST_POINT); cdecl;
function d2i_DIST_POINT(a: PPDIST_POINT; _in: PPIdAnsiChar; len: TIdC_LONG): PDIST_POINT; cdecl;
function i2d_DIST_POINT(a: PDIST_POINT; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function DIST_POINT_it: PASN1_ITEM; cdecl;
function DIST_POINT_NAME_new: PDIST_POINT_NAME; cdecl;
procedure DIST_POINT_NAME_free(a: PDIST_POINT_NAME); cdecl;
function d2i_DIST_POINT_NAME(a: PPDIST_POINT_NAME; _in: PPIdAnsiChar; len: TIdC_LONG): PDIST_POINT_NAME; cdecl;
function i2d_DIST_POINT_NAME(a: PDIST_POINT_NAME; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function DIST_POINT_NAME_it: PASN1_ITEM; cdecl;
function ISSUING_DIST_POINT_new: PISSUING_DIST_POINT; cdecl;
procedure ISSUING_DIST_POINT_free(a: PISSUING_DIST_POINT); cdecl;
function d2i_ISSUING_DIST_POINT(a: PPISSUING_DIST_POINT; _in: PPIdAnsiChar; len: TIdC_LONG): PISSUING_DIST_POINT; cdecl;
function i2d_ISSUING_DIST_POINT(a: PISSUING_DIST_POINT; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ISSUING_DIST_POINT_it: PASN1_ITEM; cdecl;
function DIST_POINT_set_dpname(dpn: PDIST_POINT_NAME; iname: PX509_NAME): TIdC_INT; cdecl;
function NAME_CONSTRAINTS_check(x: PX509; nc: PNAME_CONSTRAINTS): TIdC_INT; cdecl;
function NAME_CONSTRAINTS_check_CN(x: PX509; nc: PNAME_CONSTRAINTS): TIdC_INT; cdecl;
function ACCESS_DESCRIPTION_new: PACCESS_DESCRIPTION; cdecl;
procedure ACCESS_DESCRIPTION_free(a: PACCESS_DESCRIPTION); cdecl;
function d2i_ACCESS_DESCRIPTION(a: PPACCESS_DESCRIPTION; _in: PPIdAnsiChar; len: TIdC_LONG): PACCESS_DESCRIPTION; cdecl;
function i2d_ACCESS_DESCRIPTION(a: PACCESS_DESCRIPTION; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ACCESS_DESCRIPTION_it: PASN1_ITEM; cdecl;
function AUTHORITY_INFO_ACCESS_new: PAUTHORITY_INFO_ACCESS; cdecl;
procedure AUTHORITY_INFO_ACCESS_free(a: PAUTHORITY_INFO_ACCESS); cdecl;
function d2i_AUTHORITY_INFO_ACCESS(a: PPAUTHORITY_INFO_ACCESS; _in: PPIdAnsiChar; len: TIdC_LONG): PAUTHORITY_INFO_ACCESS; cdecl;
function i2d_AUTHORITY_INFO_ACCESS(a: PAUTHORITY_INFO_ACCESS; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function AUTHORITY_INFO_ACCESS_it: PASN1_ITEM; cdecl;
function POLICY_MAPPING_it: PASN1_ITEM; cdecl;
function POLICY_MAPPING_new: PPOLICY_MAPPING; cdecl;
procedure POLICY_MAPPING_free(a: PPOLICY_MAPPING); cdecl;
function POLICY_MAPPINGS_it: PASN1_ITEM; cdecl;
function GENERAL_SUBTREE_it: PASN1_ITEM; cdecl;
function GENERAL_SUBTREE_new: PGENERAL_SUBTREE; cdecl;
procedure GENERAL_SUBTREE_free(a: PGENERAL_SUBTREE); cdecl;
function NAME_CONSTRAINTS_it: PASN1_ITEM; cdecl;
function NAME_CONSTRAINTS_new: PNAME_CONSTRAINTS; cdecl;
procedure NAME_CONSTRAINTS_free(a: PNAME_CONSTRAINTS); cdecl;
function POLICY_CONSTRAINTS_new: PPOLICY_CONSTRAINTS; cdecl;
procedure POLICY_CONSTRAINTS_free(a: PPOLICY_CONSTRAINTS); cdecl;
function POLICY_CONSTRAINTS_it: PASN1_ITEM; cdecl;
function a2i_GENERAL_NAME(_out: PGENERAL_NAME; method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; gen_type: TIdC_INT; value: PIdAnsiChar; is_nc: TIdC_INT): PGENERAL_NAME; cdecl;
function v2i_GENERAL_NAME(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; cnf: PCONF_VALUE): PGENERAL_NAME; cdecl;
function v2i_GENERAL_NAME_ex(_out: PGENERAL_NAME; method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; cnf: PCONF_VALUE; is_nc: TIdC_INT): PGENERAL_NAME; cdecl;
procedure X509V3_conf_free(val: PCONF_VALUE); cdecl;
function X509V3_EXT_nconf_nid(conf: PCONF; ctx: PX509V3_CTX; ext_nid: TIdC_INT; value: PIdAnsiChar): PX509_EXTENSION; cdecl;
function X509V3_EXT_nconf(conf: PCONF; ctx: PX509V3_CTX; name: PIdAnsiChar; value: PIdAnsiChar): PX509_EXTENSION; cdecl;
function X509V3_EXT_add_nconf_sk(conf: PCONF; ctx: PX509V3_CTX; section: PIdAnsiChar; sk: PPstack_st_X509_EXTENSION): TIdC_INT; cdecl;
function X509V3_EXT_add_nconf(conf: PCONF; ctx: PX509V3_CTX; section: PIdAnsiChar; cert: PX509): TIdC_INT; cdecl;
function X509V3_EXT_REQ_add_nconf(conf: PCONF; ctx: PX509V3_CTX; section: PIdAnsiChar; req: PX509_REQ): TIdC_INT; cdecl;
function X509V3_EXT_CRL_add_nconf(conf: PCONF; ctx: PX509V3_CTX; section: PIdAnsiChar; crl: PX509_CRL): TIdC_INT; cdecl;
function X509V3_EXT_conf_nid(conf: Plhash_st_CONF_VALUE; ctx: PX509V3_CTX; ext_nid: TIdC_INT; value: PIdAnsiChar): PX509_EXTENSION; cdecl;
function X509V3_EXT_conf(conf: Plhash_st_CONF_VALUE; ctx: PX509V3_CTX; name: PIdAnsiChar; value: PIdAnsiChar): PX509_EXTENSION; cdecl;
function X509V3_EXT_add_conf(conf: Plhash_st_CONF_VALUE; ctx: PX509V3_CTX; section: PIdAnsiChar; cert: PX509): TIdC_INT; cdecl;
function X509V3_EXT_REQ_add_conf(conf: Plhash_st_CONF_VALUE; ctx: PX509V3_CTX; section: PIdAnsiChar; req: PX509_REQ): TIdC_INT; cdecl;
function X509V3_EXT_CRL_add_conf(conf: Plhash_st_CONF_VALUE; ctx: PX509V3_CTX; section: PIdAnsiChar; crl: PX509_CRL): TIdC_INT; cdecl;
function X509V3_add_value_bool_nf(name: PIdAnsiChar; asn1_bool: TIdC_INT; extlist: PPstack_st_CONF_VALUE): TIdC_INT; cdecl;
function X509V3_get_value_bool(value: PCONF_VALUE; asn1_bool: PIdC_INT): TIdC_INT; cdecl;
function X509V3_get_value_int(value: PCONF_VALUE; aint: PPASN1_INTEGER): TIdC_INT; cdecl;
procedure X509V3_set_nconf(ctx: PX509V3_CTX; conf: PCONF); cdecl;
procedure X509V3_set_conf_lhash(ctx: PX509V3_CTX; lhash: Plhash_st_CONF_VALUE); cdecl;
function X509V3_get_string(ctx: PX509V3_CTX; name: PIdAnsiChar; section: PIdAnsiChar): PIdAnsiChar; cdecl;
function X509V3_get_section(ctx: PX509V3_CTX; section: PIdAnsiChar): Pstack_st_CONF_VALUE; cdecl;
procedure X509V3_string_free(ctx: PX509V3_CTX; str: PIdAnsiChar); cdecl;
procedure X509V3_section_free(ctx: PX509V3_CTX; section: Pstack_st_CONF_VALUE); cdecl;
procedure X509V3_set_ctx(ctx: PX509V3_CTX; issuer: PX509; subject: PX509; req: PX509_REQ; crl: PX509_CRL; flags: TIdC_INT); cdecl;
function X509V3_set_issuer_pkey(ctx: PX509V3_CTX; pkey: PEVP_PKEY): TIdC_INT; cdecl;
function X509V3_add_value(name: PIdAnsiChar; value: PIdAnsiChar; extlist: PPstack_st_CONF_VALUE): TIdC_INT; cdecl;
function X509V3_add_value_uchar(name: PIdAnsiChar; value: PIdAnsiChar; extlist: PPstack_st_CONF_VALUE): TIdC_INT; cdecl;
function X509V3_add_value_bool(name: PIdAnsiChar; asn1_bool: TIdC_INT; extlist: PPstack_st_CONF_VALUE): TIdC_INT; cdecl;
function X509V3_add_value_int(name: PIdAnsiChar; aint: PASN1_INTEGER; extlist: PPstack_st_CONF_VALUE): TIdC_INT; cdecl;
function i2s_ASN1_INTEGER(meth: PX509V3_EXT_METHOD; aint: PASN1_INTEGER): PIdAnsiChar; cdecl;
function s2i_ASN1_INTEGER(meth: PX509V3_EXT_METHOD; value: PIdAnsiChar): PASN1_INTEGER; cdecl;
function i2s_ASN1_ENUMERATED(meth: PX509V3_EXT_METHOD; aint: PASN1_ENUMERATED): PIdAnsiChar; cdecl;
function i2s_ASN1_ENUMERATED_TABLE(meth: PX509V3_EXT_METHOD; aint: PASN1_ENUMERATED): PIdAnsiChar; cdecl;
function X509V3_EXT_add(ext: PX509V3_EXT_METHOD): TIdC_INT; cdecl;
function X509V3_EXT_add_list(extlist: PX509V3_EXT_METHOD): TIdC_INT; cdecl;
function X509V3_EXT_add_alias(nid_to: TIdC_INT; nid_from: TIdC_INT): TIdC_INT; cdecl;
procedure X509V3_EXT_cleanup; cdecl;
function X509V3_EXT_get(ext: PX509_EXTENSION): PX509V3_EXT_METHOD; cdecl;
function X509V3_EXT_get_nid(nid: TIdC_INT): PX509V3_EXT_METHOD; cdecl;
function X509V3_add_standard_extensions: TIdC_INT; cdecl;
function X509V3_parse_list(line: PIdAnsiChar): Pstack_st_CONF_VALUE; cdecl;
function X509V3_EXT_d2i(ext: PX509_EXTENSION): Pointer; cdecl;
function X509V3_get_d2i(x: Pstack_st_X509_EXTENSION; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl;
function X509V3_EXT_i2d(ext_nid: TIdC_INT; crit: TIdC_INT; ext_struc: Pointer): PX509_EXTENSION; cdecl;
function X509V3_add1_i2d(x: PPstack_st_X509_EXTENSION; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl;
procedure X509V3_EXT_val_prn(_out: PBIO; val: Pstack_st_CONF_VALUE; indent: TIdC_INT; ml: TIdC_INT); cdecl;
function X509V3_EXT_print(_out: PBIO; ext: PX509_EXTENSION; flag: TIdC_ULONG; indent: TIdC_INT): TIdC_INT; cdecl;
function X509V3_EXT_print_fp(_out: PFILE; ext: PX509_EXTENSION; flag: TIdC_INT; indent: TIdC_INT): TIdC_INT; cdecl;
function X509V3_extensions_print(_out: PBIO; title: PIdAnsiChar; exts: Pstack_st_X509_EXTENSION; flag: TIdC_ULONG; indent: TIdC_INT): TIdC_INT; cdecl;
function X509_check_ca(x: PX509): TIdC_INT; cdecl;
function X509_check_purpose(x: PX509; id: TIdC_INT; ca: TIdC_INT): TIdC_INT; cdecl;
function X509_supported_extension(ex: PX509_EXTENSION): TIdC_INT; cdecl;
function X509_check_issued(issuer: PX509; subject: PX509): TIdC_INT; cdecl;
function X509_check_akid(issuer: PX509; akid: PAUTHORITY_KEYID): TIdC_INT; cdecl;
procedure X509_set_proxy_flag(x: PX509); cdecl;
procedure X509_set_proxy_pathlen(x: PX509; l: TIdC_LONG); cdecl;
function X509_get_proxy_pathlen(x: PX509): TIdC_LONG; cdecl;
function X509_get_extension_flags(x: PX509): UInt32; cdecl;
function X509_get_key_usage(x: PX509): UInt32; cdecl;
function X509_get_extended_key_usage(x: PX509): UInt32; cdecl;
function X509_get0_subject_key_id(x: PX509): PASN1_OCTET_STRING; cdecl;
function X509_get0_authority_key_id(x: PX509): PASN1_OCTET_STRING; cdecl;
function X509_get0_authority_issuer(x: PX509): PGENERAL_NAMES; cdecl;
function X509_get0_authority_serial(x: PX509): PASN1_INTEGER; cdecl;
function X509_PURPOSE_get_count: TIdC_INT; cdecl;
function X509_PURPOSE_get_unused_id(libctx: POSSL_LIB_CTX): TIdC_INT; cdecl;
function X509_PURPOSE_get_by_sname(sname: PIdAnsiChar): TIdC_INT; cdecl;
function X509_PURPOSE_get_by_id(id: TIdC_INT): TIdC_INT; cdecl;
function X509_PURPOSE_add(id: TIdC_INT; trust: TIdC_INT; flags: TIdC_INT; ck: TX509_PURPOSE_add_ck_cb; name: PIdAnsiChar; sname: PIdAnsiChar; arg: Pointer): TIdC_INT; cdecl;
procedure X509_PURPOSE_cleanup; cdecl;
function X509_PURPOSE_get0(idx: TIdC_INT): PX509_PURPOSE; cdecl;
function X509_PURPOSE_get_id(arg1: PX509_PURPOSE): TIdC_INT; cdecl;
function X509_PURPOSE_get0_name(xp: PX509_PURPOSE): PIdAnsiChar; cdecl;
function X509_PURPOSE_get0_sname(xp: PX509_PURPOSE): PIdAnsiChar; cdecl;
function X509_PURPOSE_get_trust(xp: PX509_PURPOSE): TIdC_INT; cdecl;
function X509_PURPOSE_set(p: PIdC_INT; purpose: TIdC_INT): TIdC_INT; cdecl;
function X509_get1_email(x: PX509): Pstack_st_OPENSSL_STRING; cdecl;
function X509_REQ_get1_email(x: PX509_REQ): Pstack_st_OPENSSL_STRING; cdecl;
procedure X509_email_free(sk: Pstack_st_OPENSSL_STRING); cdecl;
function X509_get1_ocsp(x: PX509): Pstack_st_OPENSSL_STRING; cdecl;
function X509_check_host(x: PX509; chk: PIdAnsiChar; chklen: TIdC_SIZET; flags: TIdC_UINT; peername: PPIdAnsiChar): TIdC_INT; cdecl;
function X509_check_email(x: PX509; chk: PIdAnsiChar; chklen: TIdC_SIZET; flags: TIdC_UINT): TIdC_INT; cdecl;
function X509_check_ip(x: PX509; chk: PIdAnsiChar; chklen: TIdC_SIZET; flags: TIdC_UINT): TIdC_INT; cdecl;
function X509_check_ip_asc(x: PX509; ipasc: PIdAnsiChar; flags: TIdC_UINT): TIdC_INT; cdecl;
function a2i_IPADDRESS(ipasc: PIdAnsiChar): PASN1_OCTET_STRING; cdecl;
function a2i_IPADDRESS_NC(ipasc: PIdAnsiChar): PASN1_OCTET_STRING; cdecl;
function X509V3_NAME_from_section(nm: PX509_NAME; dn_sk: Pstack_st_CONF_VALUE; chtype: TIdC_ULONG): TIdC_INT; cdecl;
procedure X509_POLICY_NODE_print(_out: PBIO; node: PX509_POLICY_NODE; indent: TIdC_INT); cdecl;
function ASRange_new: PASRange; cdecl;
procedure ASRange_free(a: PASRange); cdecl;
function d2i_ASRange(a: PPASRange; _in: PPIdAnsiChar; len: TIdC_LONG): PASRange; cdecl;
function i2d_ASRange(a: PASRange; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ASRange_it: PASN1_ITEM; cdecl;
function ASIdOrRange_new: PASIdOrRange; cdecl;
procedure ASIdOrRange_free(a: PASIdOrRange); cdecl;
function d2i_ASIdOrRange(a: PPASIdOrRange; _in: PPIdAnsiChar; len: TIdC_LONG): PASIdOrRange; cdecl;
function i2d_ASIdOrRange(a: PASIdOrRange; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ASIdOrRange_it: PASN1_ITEM; cdecl;
function ASIdentifierChoice_new: PASIdentifierChoice; cdecl;
procedure ASIdentifierChoice_free(a: PASIdentifierChoice); cdecl;
function d2i_ASIdentifierChoice(a: PPASIdentifierChoice; _in: PPIdAnsiChar; len: TIdC_LONG): PASIdentifierChoice; cdecl;
function i2d_ASIdentifierChoice(a: PASIdentifierChoice; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ASIdentifierChoice_it: PASN1_ITEM; cdecl;
function ASIdentifiers_new: PASIdentifiers; cdecl;
procedure ASIdentifiers_free(a: PASIdentifiers); cdecl;
function d2i_ASIdentifiers(a: PPASIdentifiers; _in: PPIdAnsiChar; len: TIdC_LONG): PASIdentifiers; cdecl;
function i2d_ASIdentifiers(a: PASIdentifiers; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ASIdentifiers_it: PASN1_ITEM; cdecl;
function IPAddressRange_new: PIPAddressRange; cdecl;
procedure IPAddressRange_free(a: PIPAddressRange); cdecl;
function d2i_IPAddressRange(a: PPIPAddressRange; _in: PPIdAnsiChar; len: TIdC_LONG): PIPAddressRange; cdecl;
function i2d_IPAddressRange(a: PIPAddressRange; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function IPAddressRange_it: PASN1_ITEM; cdecl;
function IPAddressOrRange_new: PIPAddressOrRange; cdecl;
procedure IPAddressOrRange_free(a: PIPAddressOrRange); cdecl;
function d2i_IPAddressOrRange(a: PPIPAddressOrRange; _in: PPIdAnsiChar; len: TIdC_LONG): PIPAddressOrRange; cdecl;
function i2d_IPAddressOrRange(a: PIPAddressOrRange; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function IPAddressOrRange_it: PASN1_ITEM; cdecl;
function IPAddressChoice_new: PIPAddressChoice; cdecl;
procedure IPAddressChoice_free(a: PIPAddressChoice); cdecl;
function d2i_IPAddressChoice(a: PPIPAddressChoice; _in: PPIdAnsiChar; len: TIdC_LONG): PIPAddressChoice; cdecl;
function i2d_IPAddressChoice(a: PIPAddressChoice; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function IPAddressChoice_it: PASN1_ITEM; cdecl;
function IPAddressFamily_new: PIPAddressFamily; cdecl;
procedure IPAddressFamily_free(a: PIPAddressFamily); cdecl;
function d2i_IPAddressFamily(a: PPIPAddressFamily; _in: PPIdAnsiChar; len: TIdC_LONG): PIPAddressFamily; cdecl;
function i2d_IPAddressFamily(a: PIPAddressFamily; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function IPAddressFamily_it: PASN1_ITEM; cdecl;
function X509v3_asid_add_inherit(asid: PASIdentifiers; which: TIdC_INT): TIdC_INT; cdecl;
function X509v3_asid_add_id_or_range(asid: PASIdentifiers; which: TIdC_INT; min: PASN1_INTEGER; max: PASN1_INTEGER): TIdC_INT; cdecl;
function X509v3_addr_add_inherit(addr: PIPAddrBlocks; afi: TIdC_UINT; safi: PIdC_UINT): TIdC_INT; cdecl;
function X509v3_addr_add_prefix(addr: PIPAddrBlocks; afi: TIdC_UINT; safi: PIdC_UINT; a: PIdAnsiChar; prefixlen: TIdC_INT): TIdC_INT; cdecl;
function X509v3_addr_add_range(addr: PIPAddrBlocks; afi: TIdC_UINT; safi: PIdC_UINT; min: PIdAnsiChar; max: PIdAnsiChar): TIdC_INT; cdecl;
function X509v3_addr_get_afi(f: PIPAddressFamily): TIdC_UINT; cdecl;
function X509v3_addr_get_range(aor: PIPAddressOrRange; afi: TIdC_UINT; min: PIdAnsiChar; max: PIdAnsiChar; length: TIdC_INT): TIdC_INT; cdecl;
function X509v3_asid_is_canonical(asid: PASIdentifiers): TIdC_INT; cdecl;
function X509v3_addr_is_canonical(addr: PIPAddrBlocks): TIdC_INT; cdecl;
function X509v3_asid_canonize(asid: PASIdentifiers): TIdC_INT; cdecl;
function X509v3_addr_canonize(addr: PIPAddrBlocks): TIdC_INT; cdecl;
function X509v3_asid_inherits(asid: PASIdentifiers): TIdC_INT; cdecl;
function X509v3_addr_inherits(addr: PIPAddrBlocks): TIdC_INT; cdecl;
function X509v3_asid_subset(a: PASIdentifiers; b: PASIdentifiers): TIdC_INT; cdecl;
function X509v3_addr_subset(a: PIPAddrBlocks; b: PIPAddrBlocks): TIdC_INT; cdecl;
function X509v3_asid_validate_path(arg1: PX509_STORE_CTX): TIdC_INT; cdecl;
function X509v3_addr_validate_path(arg1: PX509_STORE_CTX): TIdC_INT; cdecl;
function X509v3_asid_validate_resource_set(chain: Pstack_st_X509; ext: PASIdentifiers; allow_inheritance: TIdC_INT): TIdC_INT; cdecl;
function X509v3_addr_validate_resource_set(chain: Pstack_st_X509; ext: PIPAddrBlocks; allow_inheritance: TIdC_INT): TIdC_INT; cdecl;
function NAMING_AUTHORITY_new: PNAMING_AUTHORITY; cdecl;
procedure NAMING_AUTHORITY_free(a: PNAMING_AUTHORITY); cdecl;
function d2i_NAMING_AUTHORITY(a: PPNAMING_AUTHORITY; _in: PPIdAnsiChar; len: TIdC_LONG): PNAMING_AUTHORITY; cdecl;
function i2d_NAMING_AUTHORITY(a: PNAMING_AUTHORITY; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function NAMING_AUTHORITY_it: PASN1_ITEM; cdecl;
function PROFESSION_INFO_new: PPROFESSION_INFO; cdecl;
procedure PROFESSION_INFO_free(a: PPROFESSION_INFO); cdecl;
function d2i_PROFESSION_INFO(a: PPPROFESSION_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PPROFESSION_INFO; cdecl;
function i2d_PROFESSION_INFO(a: PPROFESSION_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function PROFESSION_INFO_it: PASN1_ITEM; cdecl;
function ADMISSIONS_new: PADMISSIONS; cdecl;
procedure ADMISSIONS_free(a: PADMISSIONS); cdecl;
function d2i_ADMISSIONS(a: PPADMISSIONS; _in: PPIdAnsiChar; len: TIdC_LONG): PADMISSIONS; cdecl;
function i2d_ADMISSIONS(a: PADMISSIONS; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ADMISSIONS_it: PASN1_ITEM; cdecl;
function ADMISSION_SYNTAX_new: PADMISSION_SYNTAX; cdecl;
procedure ADMISSION_SYNTAX_free(a: PADMISSION_SYNTAX); cdecl;
function d2i_ADMISSION_SYNTAX(a: PPADMISSION_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): PADMISSION_SYNTAX; cdecl;
function i2d_ADMISSION_SYNTAX(a: PADMISSION_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ADMISSION_SYNTAX_it: PASN1_ITEM; cdecl;
function NAMING_AUTHORITY_get0_authorityId(n: PNAMING_AUTHORITY): PASN1_OBJECT; cdecl;
function NAMING_AUTHORITY_get0_authorityURL(n: PNAMING_AUTHORITY): PASN1_IA5STRING; cdecl;
function NAMING_AUTHORITY_get0_authorityText(n: PNAMING_AUTHORITY): PASN1_STRING; cdecl;
procedure NAMING_AUTHORITY_set0_authorityId(n: PNAMING_AUTHORITY; namingAuthorityId: PASN1_OBJECT); cdecl;
procedure NAMING_AUTHORITY_set0_authorityURL(n: PNAMING_AUTHORITY; namingAuthorityUrl: PASN1_IA5STRING); cdecl;
procedure NAMING_AUTHORITY_set0_authorityText(n: PNAMING_AUTHORITY; namingAuthorityText: PASN1_STRING); cdecl;
function ADMISSION_SYNTAX_get0_admissionAuthority(_as: PADMISSION_SYNTAX): PGENERAL_NAME; cdecl;
procedure ADMISSION_SYNTAX_set0_admissionAuthority(_as: PADMISSION_SYNTAX; aa: PGENERAL_NAME); cdecl;
function ADMISSION_SYNTAX_get0_contentsOfAdmissions(_as: PADMISSION_SYNTAX): Pstack_st_ADMISSIONS; cdecl;
procedure ADMISSION_SYNTAX_set0_contentsOfAdmissions(_as: PADMISSION_SYNTAX; a: Pstack_st_ADMISSIONS); cdecl;
function ADMISSIONS_get0_admissionAuthority(a: PADMISSIONS): PGENERAL_NAME; cdecl;
procedure ADMISSIONS_set0_admissionAuthority(a: PADMISSIONS; aa: PGENERAL_NAME); cdecl;
function ADMISSIONS_get0_namingAuthority(a: PADMISSIONS): PNAMING_AUTHORITY; cdecl;
procedure ADMISSIONS_set0_namingAuthority(a: PADMISSIONS; na: PNAMING_AUTHORITY); cdecl;
function ADMISSIONS_get0_professionInfos(a: PADMISSIONS): PPROFESSION_INFOS; cdecl;
procedure ADMISSIONS_set0_professionInfos(a: PADMISSIONS; pi: PPROFESSION_INFOS); cdecl;
function PROFESSION_INFO_get0_addProfessionInfo(pi: PPROFESSION_INFO): PASN1_OCTET_STRING; cdecl;
procedure PROFESSION_INFO_set0_addProfessionInfo(pi: PPROFESSION_INFO; aos: PASN1_OCTET_STRING); cdecl;
function PROFESSION_INFO_get0_namingAuthority(pi: PPROFESSION_INFO): PNAMING_AUTHORITY; cdecl;
procedure PROFESSION_INFO_set0_namingAuthority(pi: PPROFESSION_INFO; na: PNAMING_AUTHORITY); cdecl;
function PROFESSION_INFO_get0_professionItems(pi: PPROFESSION_INFO): Pstack_st_ASN1_STRING; cdecl;
procedure PROFESSION_INFO_set0_professionItems(pi: PPROFESSION_INFO; _as: Pstack_st_ASN1_STRING); cdecl;
function PROFESSION_INFO_get0_professionOIDs(pi: PPROFESSION_INFO): Pstack_st_ASN1_OBJECT; cdecl;
procedure PROFESSION_INFO_set0_professionOIDs(pi: PPROFESSION_INFO; po: Pstack_st_ASN1_OBJECT); cdecl;
function PROFESSION_INFO_get0_registrationNumber(pi: PPROFESSION_INFO): PASN1_PRINTABLESTRING; cdecl;
procedure PROFESSION_INFO_set0_registrationNumber(pi: PPROFESSION_INFO; rn: PASN1_PRINTABLESTRING); cdecl;
function OSSL_GENERAL_NAMES_print(_out: PBIO; gens: PGENERAL_NAMES; indent: TIdC_INT): TIdC_INT; cdecl;
function OSSL_ATTRIBUTES_SYNTAX_new: POSSL_ATTRIBUTES_SYNTAX; cdecl;
procedure OSSL_ATTRIBUTES_SYNTAX_free(a: POSSL_ATTRIBUTES_SYNTAX); cdecl;
function d2i_OSSL_ATTRIBUTES_SYNTAX(a: PPOSSL_ATTRIBUTES_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ATTRIBUTES_SYNTAX; cdecl;
function i2d_OSSL_ATTRIBUTES_SYNTAX(a: POSSL_ATTRIBUTES_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_ATTRIBUTES_SYNTAX_it: PASN1_ITEM; cdecl;
function OSSL_USER_NOTICE_SYNTAX_new: POSSL_USER_NOTICE_SYNTAX; cdecl;
procedure OSSL_USER_NOTICE_SYNTAX_free(a: POSSL_USER_NOTICE_SYNTAX); cdecl;
function d2i_OSSL_USER_NOTICE_SYNTAX(a: PPOSSL_USER_NOTICE_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_USER_NOTICE_SYNTAX; cdecl;
function i2d_OSSL_USER_NOTICE_SYNTAX(a: POSSL_USER_NOTICE_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_USER_NOTICE_SYNTAX_it: PASN1_ITEM; cdecl;
function OSSL_ROLE_SPEC_CERT_ID_new: POSSL_ROLE_SPEC_CERT_ID; cdecl;
procedure OSSL_ROLE_SPEC_CERT_ID_free(a: POSSL_ROLE_SPEC_CERT_ID); cdecl;
function d2i_OSSL_ROLE_SPEC_CERT_ID(a: PPOSSL_ROLE_SPEC_CERT_ID; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ROLE_SPEC_CERT_ID; cdecl;
function i2d_OSSL_ROLE_SPEC_CERT_ID(a: POSSL_ROLE_SPEC_CERT_ID; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_ROLE_SPEC_CERT_ID_it: PASN1_ITEM; cdecl;
function OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new: POSSL_ROLE_SPEC_CERT_ID_SYNTAX; cdecl;
procedure OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free(a: POSSL_ROLE_SPEC_CERT_ID_SYNTAX); cdecl;
function d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX(a: PPOSSL_ROLE_SPEC_CERT_ID_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ROLE_SPEC_CERT_ID_SYNTAX; cdecl;
function i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX(a: POSSL_ROLE_SPEC_CERT_ID_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it: PASN1_ITEM; cdecl;
function OSSL_HASH_new: POSSL_HASH; cdecl;
procedure OSSL_HASH_free(a: POSSL_HASH); cdecl;
function d2i_OSSL_HASH(a: PPOSSL_HASH; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_HASH; cdecl;
function i2d_OSSL_HASH(a: POSSL_HASH; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_HASH_it: PASN1_ITEM; cdecl;
function OSSL_INFO_SYNTAX_new: POSSL_INFO_SYNTAX; cdecl;
procedure OSSL_INFO_SYNTAX_free(a: POSSL_INFO_SYNTAX); cdecl;
function d2i_OSSL_INFO_SYNTAX(a: PPOSSL_INFO_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_INFO_SYNTAX; cdecl;
function i2d_OSSL_INFO_SYNTAX(a: POSSL_INFO_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_INFO_SYNTAX_it: PASN1_ITEM; cdecl;
function OSSL_INFO_SYNTAX_POINTER_new: POSSL_INFO_SYNTAX_POINTER; cdecl;
procedure OSSL_INFO_SYNTAX_POINTER_free(a: POSSL_INFO_SYNTAX_POINTER); cdecl;
function d2i_OSSL_INFO_SYNTAX_POINTER(a: PPOSSL_INFO_SYNTAX_POINTER; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_INFO_SYNTAX_POINTER; cdecl;
function i2d_OSSL_INFO_SYNTAX_POINTER(a: POSSL_INFO_SYNTAX_POINTER; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_INFO_SYNTAX_POINTER_it: PASN1_ITEM; cdecl;
function OSSL_PRIVILEGE_POLICY_ID_new: POSSL_PRIVILEGE_POLICY_ID; cdecl;
procedure OSSL_PRIVILEGE_POLICY_ID_free(a: POSSL_PRIVILEGE_POLICY_ID); cdecl;
function d2i_OSSL_PRIVILEGE_POLICY_ID(a: PPOSSL_PRIVILEGE_POLICY_ID; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_PRIVILEGE_POLICY_ID; cdecl;
function i2d_OSSL_PRIVILEGE_POLICY_ID(a: POSSL_PRIVILEGE_POLICY_ID; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_PRIVILEGE_POLICY_ID_it: PASN1_ITEM; cdecl;
function OSSL_ATTRIBUTE_DESCRIPTOR_new: POSSL_ATTRIBUTE_DESCRIPTOR; cdecl;
procedure OSSL_ATTRIBUTE_DESCRIPTOR_free(a: POSSL_ATTRIBUTE_DESCRIPTOR); cdecl;
function d2i_OSSL_ATTRIBUTE_DESCRIPTOR(a: PPOSSL_ATTRIBUTE_DESCRIPTOR; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ATTRIBUTE_DESCRIPTOR; cdecl;
function i2d_OSSL_ATTRIBUTE_DESCRIPTOR(a: POSSL_ATTRIBUTE_DESCRIPTOR; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_ATTRIBUTE_DESCRIPTOR_it: PASN1_ITEM; cdecl;
function OSSL_DAY_TIME_new: POSSL_DAY_TIME; cdecl;
procedure OSSL_DAY_TIME_free(a: POSSL_DAY_TIME); cdecl;
function d2i_OSSL_DAY_TIME(a: PPOSSL_DAY_TIME; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_DAY_TIME; cdecl;
function i2d_OSSL_DAY_TIME(a: POSSL_DAY_TIME; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_DAY_TIME_it: PASN1_ITEM; cdecl;
function OSSL_DAY_TIME_BAND_new: POSSL_DAY_TIME_BAND; cdecl;
procedure OSSL_DAY_TIME_BAND_free(a: POSSL_DAY_TIME_BAND); cdecl;
function d2i_OSSL_DAY_TIME_BAND(a: PPOSSL_DAY_TIME_BAND; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_DAY_TIME_BAND; cdecl;
function i2d_OSSL_DAY_TIME_BAND(a: POSSL_DAY_TIME_BAND; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_DAY_TIME_BAND_it: PASN1_ITEM; cdecl;
function OSSL_TIME_SPEC_DAY_new: POSSL_TIME_SPEC_DAY; cdecl;
procedure OSSL_TIME_SPEC_DAY_free(a: POSSL_TIME_SPEC_DAY); cdecl;
function d2i_OSSL_TIME_SPEC_DAY(a: PPOSSL_TIME_SPEC_DAY; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_SPEC_DAY; cdecl;
function i2d_OSSL_TIME_SPEC_DAY(a: POSSL_TIME_SPEC_DAY; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_TIME_SPEC_DAY_it: PASN1_ITEM; cdecl;
function OSSL_TIME_SPEC_WEEKS_new: POSSL_TIME_SPEC_WEEKS; cdecl;
procedure OSSL_TIME_SPEC_WEEKS_free(a: POSSL_TIME_SPEC_WEEKS); cdecl;
function d2i_OSSL_TIME_SPEC_WEEKS(a: PPOSSL_TIME_SPEC_WEEKS; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_SPEC_WEEKS; cdecl;
function i2d_OSSL_TIME_SPEC_WEEKS(a: POSSL_TIME_SPEC_WEEKS; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_TIME_SPEC_WEEKS_it: PASN1_ITEM; cdecl;
function OSSL_TIME_SPEC_MONTH_new: POSSL_TIME_SPEC_MONTH; cdecl;
procedure OSSL_TIME_SPEC_MONTH_free(a: POSSL_TIME_SPEC_MONTH); cdecl;
function d2i_OSSL_TIME_SPEC_MONTH(a: PPOSSL_TIME_SPEC_MONTH; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_SPEC_MONTH; cdecl;
function i2d_OSSL_TIME_SPEC_MONTH(a: POSSL_TIME_SPEC_MONTH; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_TIME_SPEC_MONTH_it: PASN1_ITEM; cdecl;
function OSSL_NAMED_DAY_new: POSSL_NAMED_DAY; cdecl;
procedure OSSL_NAMED_DAY_free(a: POSSL_NAMED_DAY); cdecl;
function d2i_OSSL_NAMED_DAY(a: PPOSSL_NAMED_DAY; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_NAMED_DAY; cdecl;
function i2d_OSSL_NAMED_DAY(a: POSSL_NAMED_DAY; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_NAMED_DAY_it: PASN1_ITEM; cdecl;
function OSSL_TIME_SPEC_X_DAY_OF_new: POSSL_TIME_SPEC_X_DAY_OF; cdecl;
procedure OSSL_TIME_SPEC_X_DAY_OF_free(a: POSSL_TIME_SPEC_X_DAY_OF); cdecl;
function d2i_OSSL_TIME_SPEC_X_DAY_OF(a: PPOSSL_TIME_SPEC_X_DAY_OF; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_SPEC_X_DAY_OF; cdecl;
function i2d_OSSL_TIME_SPEC_X_DAY_OF(a: POSSL_TIME_SPEC_X_DAY_OF; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_TIME_SPEC_X_DAY_OF_it: PASN1_ITEM; cdecl;
function OSSL_TIME_SPEC_ABSOLUTE_new: POSSL_TIME_SPEC_ABSOLUTE; cdecl;
procedure OSSL_TIME_SPEC_ABSOLUTE_free(a: POSSL_TIME_SPEC_ABSOLUTE); cdecl;
function d2i_OSSL_TIME_SPEC_ABSOLUTE(a: PPOSSL_TIME_SPEC_ABSOLUTE; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_SPEC_ABSOLUTE; cdecl;
function i2d_OSSL_TIME_SPEC_ABSOLUTE(a: POSSL_TIME_SPEC_ABSOLUTE; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_TIME_SPEC_ABSOLUTE_it: PASN1_ITEM; cdecl;
function OSSL_TIME_SPEC_TIME_new: POSSL_TIME_SPEC_TIME; cdecl;
procedure OSSL_TIME_SPEC_TIME_free(a: POSSL_TIME_SPEC_TIME); cdecl;
function d2i_OSSL_TIME_SPEC_TIME(a: PPOSSL_TIME_SPEC_TIME; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_SPEC_TIME; cdecl;
function i2d_OSSL_TIME_SPEC_TIME(a: POSSL_TIME_SPEC_TIME; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_TIME_SPEC_TIME_it: PASN1_ITEM; cdecl;
function OSSL_TIME_SPEC_new: POSSL_TIME_SPEC; cdecl;
procedure OSSL_TIME_SPEC_free(a: POSSL_TIME_SPEC); cdecl;
function d2i_OSSL_TIME_SPEC(a: PPOSSL_TIME_SPEC; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_SPEC; cdecl;
function i2d_OSSL_TIME_SPEC(a: POSSL_TIME_SPEC; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_TIME_SPEC_it: PASN1_ITEM; cdecl;
function OSSL_TIME_PERIOD_new: POSSL_TIME_PERIOD; cdecl;
procedure OSSL_TIME_PERIOD_free(a: POSSL_TIME_PERIOD); cdecl;
function d2i_OSSL_TIME_PERIOD(a: PPOSSL_TIME_PERIOD; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_PERIOD; cdecl;
function i2d_OSSL_TIME_PERIOD(a: POSSL_TIME_PERIOD; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_TIME_PERIOD_it: PASN1_ITEM; cdecl;
function OSSL_ATAV_new: POSSL_ATAV; cdecl;
procedure OSSL_ATAV_free(a: POSSL_ATAV); cdecl;
function d2i_OSSL_ATAV(a: PPOSSL_ATAV; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ATAV; cdecl;
function i2d_OSSL_ATAV(a: POSSL_ATAV; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_ATAV_it: PASN1_ITEM; cdecl;
function OSSL_ATTRIBUTE_TYPE_MAPPING_new: POSSL_ATTRIBUTE_TYPE_MAPPING; cdecl;
procedure OSSL_ATTRIBUTE_TYPE_MAPPING_free(a: POSSL_ATTRIBUTE_TYPE_MAPPING); cdecl;
function d2i_OSSL_ATTRIBUTE_TYPE_MAPPING(a: PPOSSL_ATTRIBUTE_TYPE_MAPPING; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ATTRIBUTE_TYPE_MAPPING; cdecl;
function i2d_OSSL_ATTRIBUTE_TYPE_MAPPING(a: POSSL_ATTRIBUTE_TYPE_MAPPING; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_ATTRIBUTE_TYPE_MAPPING_it: PASN1_ITEM; cdecl;
function OSSL_ATTRIBUTE_VALUE_MAPPING_new: POSSL_ATTRIBUTE_VALUE_MAPPING; cdecl;
procedure OSSL_ATTRIBUTE_VALUE_MAPPING_free(a: POSSL_ATTRIBUTE_VALUE_MAPPING); cdecl;
function d2i_OSSL_ATTRIBUTE_VALUE_MAPPING(a: PPOSSL_ATTRIBUTE_VALUE_MAPPING; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ATTRIBUTE_VALUE_MAPPING; cdecl;
function i2d_OSSL_ATTRIBUTE_VALUE_MAPPING(a: POSSL_ATTRIBUTE_VALUE_MAPPING; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_ATTRIBUTE_VALUE_MAPPING_it: PASN1_ITEM; cdecl;
function OSSL_ATTRIBUTE_MAPPING_new: POSSL_ATTRIBUTE_MAPPING; cdecl;
procedure OSSL_ATTRIBUTE_MAPPING_free(a: POSSL_ATTRIBUTE_MAPPING); cdecl;
function d2i_OSSL_ATTRIBUTE_MAPPING(a: PPOSSL_ATTRIBUTE_MAPPING; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ATTRIBUTE_MAPPING; cdecl;
function i2d_OSSL_ATTRIBUTE_MAPPING(a: POSSL_ATTRIBUTE_MAPPING; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_ATTRIBUTE_MAPPING_it: PASN1_ITEM; cdecl;
function OSSL_ATTRIBUTE_MAPPINGS_new: POSSL_ATTRIBUTE_MAPPINGS; cdecl;
procedure OSSL_ATTRIBUTE_MAPPINGS_free(a: POSSL_ATTRIBUTE_MAPPINGS); cdecl;
function d2i_OSSL_ATTRIBUTE_MAPPINGS(a: PPOSSL_ATTRIBUTE_MAPPINGS; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ATTRIBUTE_MAPPINGS; cdecl;
function i2d_OSSL_ATTRIBUTE_MAPPINGS(a: POSSL_ATTRIBUTE_MAPPINGS; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_ATTRIBUTE_MAPPINGS_it: PASN1_ITEM; cdecl;
function OSSL_ALLOWED_ATTRIBUTES_CHOICE_new: POSSL_ALLOWED_ATTRIBUTES_CHOICE; cdecl;
procedure OSSL_ALLOWED_ATTRIBUTES_CHOICE_free(a: POSSL_ALLOWED_ATTRIBUTES_CHOICE); cdecl;
function d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE(a: PPOSSL_ALLOWED_ATTRIBUTES_CHOICE; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ALLOWED_ATTRIBUTES_CHOICE; cdecl;
function i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE(a: POSSL_ALLOWED_ATTRIBUTES_CHOICE; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_ALLOWED_ATTRIBUTES_CHOICE_it: PASN1_ITEM; cdecl;
function OSSL_ALLOWED_ATTRIBUTES_ITEM_new: POSSL_ALLOWED_ATTRIBUTES_ITEM; cdecl;
procedure OSSL_ALLOWED_ATTRIBUTES_ITEM_free(a: POSSL_ALLOWED_ATTRIBUTES_ITEM); cdecl;
function d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM(a: PPOSSL_ALLOWED_ATTRIBUTES_ITEM; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ALLOWED_ATTRIBUTES_ITEM; cdecl;
function i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM(a: POSSL_ALLOWED_ATTRIBUTES_ITEM; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_ALLOWED_ATTRIBUTES_ITEM_it: PASN1_ITEM; cdecl;
function OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new: POSSL_ALLOWED_ATTRIBUTES_SYNTAX; cdecl;
procedure OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free(a: POSSL_ALLOWED_ATTRIBUTES_SYNTAX); cdecl;
function d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX(a: PPOSSL_ALLOWED_ATTRIBUTES_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ALLOWED_ATTRIBUTES_SYNTAX; cdecl;
function i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX(a: POSSL_ALLOWED_ATTRIBUTES_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it: PASN1_ITEM; cdecl;
function OSSL_AA_DIST_POINT_new: POSSL_AA_DIST_POINT; cdecl;
procedure OSSL_AA_DIST_POINT_free(a: POSSL_AA_DIST_POINT); cdecl;
function d2i_OSSL_AA_DIST_POINT(a: PPOSSL_AA_DIST_POINT; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_AA_DIST_POINT; cdecl;
function i2d_OSSL_AA_DIST_POINT(a: POSSL_AA_DIST_POINT; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_AA_DIST_POINT_it: PASN1_ITEM; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// INLINE OR MACRO ROUTINES
// =============================================================================

function EXT_UTF8STRING(nid: Pointer): TIdC_INT; cdecl;
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

function GENERAL_NAME_set1_X509_NAME(tgt: PPGENERAL_NAME; src: PX509_NAME): TIdC_INT; cdecl external CLibCrypto name 'GENERAL_NAME_set1_X509_NAME';
function DIST_POINT_NAME_dup(a: PDIST_POINT_NAME): PDIST_POINT_NAME; cdecl external CLibCrypto name 'DIST_POINT_NAME_dup';
function PROXY_POLICY_new: PPROXY_POLICY; cdecl external CLibCrypto name 'PROXY_POLICY_new';
procedure PROXY_POLICY_free(a: PPROXY_POLICY); cdecl external CLibCrypto name 'PROXY_POLICY_free';
function d2i_PROXY_POLICY(a: PPPROXY_POLICY; _in: PPIdAnsiChar; len: TIdC_LONG): PPROXY_POLICY; cdecl external CLibCrypto name 'd2i_PROXY_POLICY';
function i2d_PROXY_POLICY(a: PPROXY_POLICY; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_PROXY_POLICY';
function PROXY_POLICY_it: PASN1_ITEM; cdecl external CLibCrypto name 'PROXY_POLICY_it';
function PROXY_CERT_INFO_EXTENSION_new: PPROXY_CERT_INFO_EXTENSION; cdecl external CLibCrypto name 'PROXY_CERT_INFO_EXTENSION_new';
procedure PROXY_CERT_INFO_EXTENSION_free(a: PPROXY_CERT_INFO_EXTENSION); cdecl external CLibCrypto name 'PROXY_CERT_INFO_EXTENSION_free';
function d2i_PROXY_CERT_INFO_EXTENSION(a: PPPROXY_CERT_INFO_EXTENSION; _in: PPIdAnsiChar; len: TIdC_LONG): PPROXY_CERT_INFO_EXTENSION; cdecl external CLibCrypto name 'd2i_PROXY_CERT_INFO_EXTENSION';
function i2d_PROXY_CERT_INFO_EXTENSION(a: PPROXY_CERT_INFO_EXTENSION; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_PROXY_CERT_INFO_EXTENSION';
function PROXY_CERT_INFO_EXTENSION_it: PASN1_ITEM; cdecl external CLibCrypto name 'PROXY_CERT_INFO_EXTENSION_it';
function BASIC_CONSTRAINTS_new: PBASIC_CONSTRAINTS; cdecl external CLibCrypto name 'BASIC_CONSTRAINTS_new';
procedure BASIC_CONSTRAINTS_free(a: PBASIC_CONSTRAINTS); cdecl external CLibCrypto name 'BASIC_CONSTRAINTS_free';
function d2i_BASIC_CONSTRAINTS(a: PPBASIC_CONSTRAINTS; _in: PPIdAnsiChar; len: TIdC_LONG): PBASIC_CONSTRAINTS; cdecl external CLibCrypto name 'd2i_BASIC_CONSTRAINTS';
function i2d_BASIC_CONSTRAINTS(a: PBASIC_CONSTRAINTS; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_BASIC_CONSTRAINTS';
function BASIC_CONSTRAINTS_it: PASN1_ITEM; cdecl external CLibCrypto name 'BASIC_CONSTRAINTS_it';
function OSSL_BASIC_ATTR_CONSTRAINTS_new: POSSL_BASIC_ATTR_CONSTRAINTS; cdecl external CLibCrypto name 'OSSL_BASIC_ATTR_CONSTRAINTS_new';
procedure OSSL_BASIC_ATTR_CONSTRAINTS_free(a: POSSL_BASIC_ATTR_CONSTRAINTS); cdecl external CLibCrypto name 'OSSL_BASIC_ATTR_CONSTRAINTS_free';
function d2i_OSSL_BASIC_ATTR_CONSTRAINTS(a: PPOSSL_BASIC_ATTR_CONSTRAINTS; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_BASIC_ATTR_CONSTRAINTS; cdecl external CLibCrypto name 'd2i_OSSL_BASIC_ATTR_CONSTRAINTS';
function i2d_OSSL_BASIC_ATTR_CONSTRAINTS(a: POSSL_BASIC_ATTR_CONSTRAINTS; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_BASIC_ATTR_CONSTRAINTS';
function OSSL_BASIC_ATTR_CONSTRAINTS_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_BASIC_ATTR_CONSTRAINTS_it';
function SXNET_new: PSXNET; cdecl external CLibCrypto name 'SXNET_new';
procedure SXNET_free(a: PSXNET); cdecl external CLibCrypto name 'SXNET_free';
function d2i_SXNET(a: PPSXNET; _in: PPIdAnsiChar; len: TIdC_LONG): PSXNET; cdecl external CLibCrypto name 'd2i_SXNET';
function i2d_SXNET(a: PSXNET; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_SXNET';
function SXNET_it: PASN1_ITEM; cdecl external CLibCrypto name 'SXNET_it';
function SXNETID_new: PSXNETID; cdecl external CLibCrypto name 'SXNETID_new';
procedure SXNETID_free(a: PSXNETID); cdecl external CLibCrypto name 'SXNETID_free';
function d2i_SXNETID(a: PPSXNETID; _in: PPIdAnsiChar; len: TIdC_LONG): PSXNETID; cdecl external CLibCrypto name 'd2i_SXNETID';
function i2d_SXNETID(a: PSXNETID; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_SXNETID';
function SXNETID_it: PASN1_ITEM; cdecl external CLibCrypto name 'SXNETID_it';
function ISSUER_SIGN_TOOL_new: PISSUER_SIGN_TOOL; cdecl external CLibCrypto name 'ISSUER_SIGN_TOOL_new';
procedure ISSUER_SIGN_TOOL_free(a: PISSUER_SIGN_TOOL); cdecl external CLibCrypto name 'ISSUER_SIGN_TOOL_free';
function d2i_ISSUER_SIGN_TOOL(a: PPISSUER_SIGN_TOOL; _in: PPIdAnsiChar; len: TIdC_LONG): PISSUER_SIGN_TOOL; cdecl external CLibCrypto name 'd2i_ISSUER_SIGN_TOOL';
function i2d_ISSUER_SIGN_TOOL(a: PISSUER_SIGN_TOOL; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ISSUER_SIGN_TOOL';
function ISSUER_SIGN_TOOL_it: PASN1_ITEM; cdecl external CLibCrypto name 'ISSUER_SIGN_TOOL_it';
function SXNET_add_id_asc(psx: PPSXNET; zone: PIdAnsiChar; user: PIdAnsiChar; userlen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'SXNET_add_id_asc';
function SXNET_add_id_ulong(psx: PPSXNET; lzone: TIdC_ULONG; user: PIdAnsiChar; userlen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'SXNET_add_id_ulong';
function SXNET_add_id_INTEGER(psx: PPSXNET; izone: PASN1_INTEGER; user: PIdAnsiChar; userlen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'SXNET_add_id_INTEGER';
function SXNET_get_id_asc(sx: PSXNET; zone: PIdAnsiChar): PASN1_OCTET_STRING; cdecl external CLibCrypto name 'SXNET_get_id_asc';
function SXNET_get_id_ulong(sx: PSXNET; lzone: TIdC_ULONG): PASN1_OCTET_STRING; cdecl external CLibCrypto name 'SXNET_get_id_ulong';
function SXNET_get_id_INTEGER(sx: PSXNET; zone: PASN1_INTEGER): PASN1_OCTET_STRING; cdecl external CLibCrypto name 'SXNET_get_id_INTEGER';
function AUTHORITY_KEYID_new: PAUTHORITY_KEYID; cdecl external CLibCrypto name 'AUTHORITY_KEYID_new';
procedure AUTHORITY_KEYID_free(a: PAUTHORITY_KEYID); cdecl external CLibCrypto name 'AUTHORITY_KEYID_free';
function d2i_AUTHORITY_KEYID(a: PPAUTHORITY_KEYID; _in: PPIdAnsiChar; len: TIdC_LONG): PAUTHORITY_KEYID; cdecl external CLibCrypto name 'd2i_AUTHORITY_KEYID';
function i2d_AUTHORITY_KEYID(a: PAUTHORITY_KEYID; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_AUTHORITY_KEYID';
function AUTHORITY_KEYID_it: PASN1_ITEM; cdecl external CLibCrypto name 'AUTHORITY_KEYID_it';
function PKEY_USAGE_PERIOD_new: PPKEY_USAGE_PERIOD; cdecl external CLibCrypto name 'PKEY_USAGE_PERIOD_new';
procedure PKEY_USAGE_PERIOD_free(a: PPKEY_USAGE_PERIOD); cdecl external CLibCrypto name 'PKEY_USAGE_PERIOD_free';
function d2i_PKEY_USAGE_PERIOD(a: PPPKEY_USAGE_PERIOD; _in: PPIdAnsiChar; len: TIdC_LONG): PPKEY_USAGE_PERIOD; cdecl external CLibCrypto name 'd2i_PKEY_USAGE_PERIOD';
function i2d_PKEY_USAGE_PERIOD(a: PPKEY_USAGE_PERIOD; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKEY_USAGE_PERIOD';
function PKEY_USAGE_PERIOD_it: PASN1_ITEM; cdecl external CLibCrypto name 'PKEY_USAGE_PERIOD_it';
function GENERAL_NAME_new: PGENERAL_NAME; cdecl external CLibCrypto name 'GENERAL_NAME_new';
procedure GENERAL_NAME_free(a: PGENERAL_NAME); cdecl external CLibCrypto name 'GENERAL_NAME_free';
function d2i_GENERAL_NAME(a: PPGENERAL_NAME; _in: PPIdAnsiChar; len: TIdC_LONG): PGENERAL_NAME; cdecl external CLibCrypto name 'd2i_GENERAL_NAME';
function i2d_GENERAL_NAME(a: PGENERAL_NAME; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_GENERAL_NAME';
function GENERAL_NAME_it: PASN1_ITEM; cdecl external CLibCrypto name 'GENERAL_NAME_it';
function GENERAL_NAME_dup(a: PGENERAL_NAME): PGENERAL_NAME; cdecl external CLibCrypto name 'GENERAL_NAME_dup';
function GENERAL_NAME_cmp(a: PGENERAL_NAME; b: PGENERAL_NAME): TIdC_INT; cdecl external CLibCrypto name 'GENERAL_NAME_cmp';
function v2i_ASN1_BIT_STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; nval: Pstack_st_CONF_VALUE): PASN1_BIT_STRING; cdecl external CLibCrypto name 'v2i_ASN1_BIT_STRING';
function i2v_ASN1_BIT_STRING(method: PX509V3_EXT_METHOD; bits: PASN1_BIT_STRING; extlist: Pstack_st_CONF_VALUE): Pstack_st_CONF_VALUE; cdecl external CLibCrypto name 'i2v_ASN1_BIT_STRING';
function i2s_ASN1_IA5STRING(method: PX509V3_EXT_METHOD; ia5: PASN1_IA5STRING): PIdAnsiChar; cdecl external CLibCrypto name 'i2s_ASN1_IA5STRING';
function s2i_ASN1_IA5STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; str: PIdAnsiChar): PASN1_IA5STRING; cdecl external CLibCrypto name 's2i_ASN1_IA5STRING';
function i2s_ASN1_UTF8STRING(method: PX509V3_EXT_METHOD; utf8: PASN1_UTF8STRING): PIdAnsiChar; cdecl external CLibCrypto name 'i2s_ASN1_UTF8STRING';
function s2i_ASN1_UTF8STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; str: PIdAnsiChar): PASN1_UTF8STRING; cdecl external CLibCrypto name 's2i_ASN1_UTF8STRING';
function i2v_GENERAL_NAME(method: PX509V3_EXT_METHOD; gen: PGENERAL_NAME; ret: Pstack_st_CONF_VALUE): Pstack_st_CONF_VALUE; cdecl external CLibCrypto name 'i2v_GENERAL_NAME';
function GENERAL_NAME_print(_out: PBIO; gen: PGENERAL_NAME): TIdC_INT; cdecl external CLibCrypto name 'GENERAL_NAME_print';
function GENERAL_NAMES_new: PGENERAL_NAMES; cdecl external CLibCrypto name 'GENERAL_NAMES_new';
procedure GENERAL_NAMES_free(a: PGENERAL_NAMES); cdecl external CLibCrypto name 'GENERAL_NAMES_free';
function d2i_GENERAL_NAMES(a: PPGENERAL_NAMES; _in: PPIdAnsiChar; len: TIdC_LONG): PGENERAL_NAMES; cdecl external CLibCrypto name 'd2i_GENERAL_NAMES';
function i2d_GENERAL_NAMES(a: PGENERAL_NAMES; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_GENERAL_NAMES';
function GENERAL_NAMES_it: PASN1_ITEM; cdecl external CLibCrypto name 'GENERAL_NAMES_it';
function i2v_GENERAL_NAMES(method: PX509V3_EXT_METHOD; gen: PGENERAL_NAMES; extlist: Pstack_st_CONF_VALUE): Pstack_st_CONF_VALUE; cdecl external CLibCrypto name 'i2v_GENERAL_NAMES';
function v2i_GENERAL_NAMES(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; nval: Pstack_st_CONF_VALUE): PGENERAL_NAMES; cdecl external CLibCrypto name 'v2i_GENERAL_NAMES';
function OTHERNAME_new: POTHERNAME; cdecl external CLibCrypto name 'OTHERNAME_new';
procedure OTHERNAME_free(a: POTHERNAME); cdecl external CLibCrypto name 'OTHERNAME_free';
function d2i_OTHERNAME(a: PPOTHERNAME; _in: PPIdAnsiChar; len: TIdC_LONG): POTHERNAME; cdecl external CLibCrypto name 'd2i_OTHERNAME';
function i2d_OTHERNAME(a: POTHERNAME; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OTHERNAME';
function OTHERNAME_it: PASN1_ITEM; cdecl external CLibCrypto name 'OTHERNAME_it';
function EDIPARTYNAME_new: PEDIPARTYNAME; cdecl external CLibCrypto name 'EDIPARTYNAME_new';
procedure EDIPARTYNAME_free(a: PEDIPARTYNAME); cdecl external CLibCrypto name 'EDIPARTYNAME_free';
function d2i_EDIPARTYNAME(a: PPEDIPARTYNAME; _in: PPIdAnsiChar; len: TIdC_LONG): PEDIPARTYNAME; cdecl external CLibCrypto name 'd2i_EDIPARTYNAME';
function i2d_EDIPARTYNAME(a: PEDIPARTYNAME; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_EDIPARTYNAME';
function EDIPARTYNAME_it: PASN1_ITEM; cdecl external CLibCrypto name 'EDIPARTYNAME_it';
function OTHERNAME_cmp(a: POTHERNAME; b: POTHERNAME): TIdC_INT; cdecl external CLibCrypto name 'OTHERNAME_cmp';
procedure GENERAL_NAME_set0_value(a: PGENERAL_NAME; _type: TIdC_INT; value: Pointer); cdecl external CLibCrypto name 'GENERAL_NAME_set0_value';
function GENERAL_NAME_get0_value(a: PGENERAL_NAME; ptype: PIdC_INT): Pointer; cdecl external CLibCrypto name 'GENERAL_NAME_get0_value';
function GENERAL_NAME_set0_othername(gen: PGENERAL_NAME; oid: PASN1_OBJECT; value: PASN1_TYPE): TIdC_INT; cdecl external CLibCrypto name 'GENERAL_NAME_set0_othername';
function GENERAL_NAME_get0_otherName(gen: PGENERAL_NAME; poid: PPASN1_OBJECT; pvalue: PPASN1_TYPE): TIdC_INT; cdecl external CLibCrypto name 'GENERAL_NAME_get0_otherName';
function i2s_ASN1_OCTET_STRING(method: PX509V3_EXT_METHOD; ia5: PASN1_OCTET_STRING): PIdAnsiChar; cdecl external CLibCrypto name 'i2s_ASN1_OCTET_STRING';
function s2i_ASN1_OCTET_STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; str: PIdAnsiChar): PASN1_OCTET_STRING; cdecl external CLibCrypto name 's2i_ASN1_OCTET_STRING';
function EXTENDED_KEY_USAGE_new: PEXTENDED_KEY_USAGE; cdecl external CLibCrypto name 'EXTENDED_KEY_USAGE_new';
procedure EXTENDED_KEY_USAGE_free(a: PEXTENDED_KEY_USAGE); cdecl external CLibCrypto name 'EXTENDED_KEY_USAGE_free';
function d2i_EXTENDED_KEY_USAGE(a: PPEXTENDED_KEY_USAGE; _in: PPIdAnsiChar; len: TIdC_LONG): PEXTENDED_KEY_USAGE; cdecl external CLibCrypto name 'd2i_EXTENDED_KEY_USAGE';
function i2d_EXTENDED_KEY_USAGE(a: PEXTENDED_KEY_USAGE; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_EXTENDED_KEY_USAGE';
function EXTENDED_KEY_USAGE_it: PASN1_ITEM; cdecl external CLibCrypto name 'EXTENDED_KEY_USAGE_it';
function i2a_ACCESS_DESCRIPTION(bp: PBIO; a: PACCESS_DESCRIPTION): TIdC_INT; cdecl external CLibCrypto name 'i2a_ACCESS_DESCRIPTION';
function TLS_FEATURE_new: PLS_FEATURE; cdecl external CLibCrypto name 'TLS_FEATURE_new';
procedure TLS_FEATURE_free(a: PLS_FEATURE); cdecl external CLibCrypto name 'TLS_FEATURE_free';
function CERTIFICATEPOLICIES_new: PCERTIFICATEPOLICIES; cdecl external CLibCrypto name 'CERTIFICATEPOLICIES_new';
procedure CERTIFICATEPOLICIES_free(a: PCERTIFICATEPOLICIES); cdecl external CLibCrypto name 'CERTIFICATEPOLICIES_free';
function d2i_CERTIFICATEPOLICIES(a: PPCERTIFICATEPOLICIES; _in: PPIdAnsiChar; len: TIdC_LONG): PCERTIFICATEPOLICIES; cdecl external CLibCrypto name 'd2i_CERTIFICATEPOLICIES';
function i2d_CERTIFICATEPOLICIES(a: PCERTIFICATEPOLICIES; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_CERTIFICATEPOLICIES';
function CERTIFICATEPOLICIES_it: PASN1_ITEM; cdecl external CLibCrypto name 'CERTIFICATEPOLICIES_it';
function POLICYINFO_new: PPOLICYINFO; cdecl external CLibCrypto name 'POLICYINFO_new';
procedure POLICYINFO_free(a: PPOLICYINFO); cdecl external CLibCrypto name 'POLICYINFO_free';
function d2i_POLICYINFO(a: PPPOLICYINFO; _in: PPIdAnsiChar; len: TIdC_LONG): PPOLICYINFO; cdecl external CLibCrypto name 'd2i_POLICYINFO';
function i2d_POLICYINFO(a: PPOLICYINFO; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_POLICYINFO';
function POLICYINFO_it: PASN1_ITEM; cdecl external CLibCrypto name 'POLICYINFO_it';
function POLICYQUALINFO_new: PPOLICYQUALINFO; cdecl external CLibCrypto name 'POLICYQUALINFO_new';
procedure POLICYQUALINFO_free(a: PPOLICYQUALINFO); cdecl external CLibCrypto name 'POLICYQUALINFO_free';
function d2i_POLICYQUALINFO(a: PPPOLICYQUALINFO; _in: PPIdAnsiChar; len: TIdC_LONG): PPOLICYQUALINFO; cdecl external CLibCrypto name 'd2i_POLICYQUALINFO';
function i2d_POLICYQUALINFO(a: PPOLICYQUALINFO; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_POLICYQUALINFO';
function POLICYQUALINFO_it: PASN1_ITEM; cdecl external CLibCrypto name 'POLICYQUALINFO_it';
function USERNOTICE_new: PUSERNOTICE; cdecl external CLibCrypto name 'USERNOTICE_new';
procedure USERNOTICE_free(a: PUSERNOTICE); cdecl external CLibCrypto name 'USERNOTICE_free';
function d2i_USERNOTICE(a: PPUSERNOTICE; _in: PPIdAnsiChar; len: TIdC_LONG): PUSERNOTICE; cdecl external CLibCrypto name 'd2i_USERNOTICE';
function i2d_USERNOTICE(a: PUSERNOTICE; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_USERNOTICE';
function USERNOTICE_it: PASN1_ITEM; cdecl external CLibCrypto name 'USERNOTICE_it';
function NOTICEREF_new: PNOTICEREF; cdecl external CLibCrypto name 'NOTICEREF_new';
procedure NOTICEREF_free(a: PNOTICEREF); cdecl external CLibCrypto name 'NOTICEREF_free';
function d2i_NOTICEREF(a: PPNOTICEREF; _in: PPIdAnsiChar; len: TIdC_LONG): PNOTICEREF; cdecl external CLibCrypto name 'd2i_NOTICEREF';
function i2d_NOTICEREF(a: PNOTICEREF; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_NOTICEREF';
function NOTICEREF_it: PASN1_ITEM; cdecl external CLibCrypto name 'NOTICEREF_it';
function CRL_DIST_POINTS_new: PCRL_DIST_POINTS; cdecl external CLibCrypto name 'CRL_DIST_POINTS_new';
procedure CRL_DIST_POINTS_free(a: PCRL_DIST_POINTS); cdecl external CLibCrypto name 'CRL_DIST_POINTS_free';
function d2i_CRL_DIST_POINTS(a: PPCRL_DIST_POINTS; _in: PPIdAnsiChar; len: TIdC_LONG): PCRL_DIST_POINTS; cdecl external CLibCrypto name 'd2i_CRL_DIST_POINTS';
function i2d_CRL_DIST_POINTS(a: PCRL_DIST_POINTS; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_CRL_DIST_POINTS';
function CRL_DIST_POINTS_it: PASN1_ITEM; cdecl external CLibCrypto name 'CRL_DIST_POINTS_it';
function DIST_POINT_new: PDIST_POINT; cdecl external CLibCrypto name 'DIST_POINT_new';
procedure DIST_POINT_free(a: PDIST_POINT); cdecl external CLibCrypto name 'DIST_POINT_free';
function d2i_DIST_POINT(a: PPDIST_POINT; _in: PPIdAnsiChar; len: TIdC_LONG): PDIST_POINT; cdecl external CLibCrypto name 'd2i_DIST_POINT';
function i2d_DIST_POINT(a: PDIST_POINT; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_DIST_POINT';
function DIST_POINT_it: PASN1_ITEM; cdecl external CLibCrypto name 'DIST_POINT_it';
function DIST_POINT_NAME_new: PDIST_POINT_NAME; cdecl external CLibCrypto name 'DIST_POINT_NAME_new';
procedure DIST_POINT_NAME_free(a: PDIST_POINT_NAME); cdecl external CLibCrypto name 'DIST_POINT_NAME_free';
function d2i_DIST_POINT_NAME(a: PPDIST_POINT_NAME; _in: PPIdAnsiChar; len: TIdC_LONG): PDIST_POINT_NAME; cdecl external CLibCrypto name 'd2i_DIST_POINT_NAME';
function i2d_DIST_POINT_NAME(a: PDIST_POINT_NAME; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_DIST_POINT_NAME';
function DIST_POINT_NAME_it: PASN1_ITEM; cdecl external CLibCrypto name 'DIST_POINT_NAME_it';
function ISSUING_DIST_POINT_new: PISSUING_DIST_POINT; cdecl external CLibCrypto name 'ISSUING_DIST_POINT_new';
procedure ISSUING_DIST_POINT_free(a: PISSUING_DIST_POINT); cdecl external CLibCrypto name 'ISSUING_DIST_POINT_free';
function d2i_ISSUING_DIST_POINT(a: PPISSUING_DIST_POINT; _in: PPIdAnsiChar; len: TIdC_LONG): PISSUING_DIST_POINT; cdecl external CLibCrypto name 'd2i_ISSUING_DIST_POINT';
function i2d_ISSUING_DIST_POINT(a: PISSUING_DIST_POINT; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ISSUING_DIST_POINT';
function ISSUING_DIST_POINT_it: PASN1_ITEM; cdecl external CLibCrypto name 'ISSUING_DIST_POINT_it';
function DIST_POINT_set_dpname(dpn: PDIST_POINT_NAME; iname: PX509_NAME): TIdC_INT; cdecl external CLibCrypto name 'DIST_POINT_set_dpname';
function NAME_CONSTRAINTS_check(x: PX509; nc: PNAME_CONSTRAINTS): TIdC_INT; cdecl external CLibCrypto name 'NAME_CONSTRAINTS_check';
function NAME_CONSTRAINTS_check_CN(x: PX509; nc: PNAME_CONSTRAINTS): TIdC_INT; cdecl external CLibCrypto name 'NAME_CONSTRAINTS_check_CN';
function ACCESS_DESCRIPTION_new: PACCESS_DESCRIPTION; cdecl external CLibCrypto name 'ACCESS_DESCRIPTION_new';
procedure ACCESS_DESCRIPTION_free(a: PACCESS_DESCRIPTION); cdecl external CLibCrypto name 'ACCESS_DESCRIPTION_free';
function d2i_ACCESS_DESCRIPTION(a: PPACCESS_DESCRIPTION; _in: PPIdAnsiChar; len: TIdC_LONG): PACCESS_DESCRIPTION; cdecl external CLibCrypto name 'd2i_ACCESS_DESCRIPTION';
function i2d_ACCESS_DESCRIPTION(a: PACCESS_DESCRIPTION; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ACCESS_DESCRIPTION';
function ACCESS_DESCRIPTION_it: PASN1_ITEM; cdecl external CLibCrypto name 'ACCESS_DESCRIPTION_it';
function AUTHORITY_INFO_ACCESS_new: PAUTHORITY_INFO_ACCESS; cdecl external CLibCrypto name 'AUTHORITY_INFO_ACCESS_new';
procedure AUTHORITY_INFO_ACCESS_free(a: PAUTHORITY_INFO_ACCESS); cdecl external CLibCrypto name 'AUTHORITY_INFO_ACCESS_free';
function d2i_AUTHORITY_INFO_ACCESS(a: PPAUTHORITY_INFO_ACCESS; _in: PPIdAnsiChar; len: TIdC_LONG): PAUTHORITY_INFO_ACCESS; cdecl external CLibCrypto name 'd2i_AUTHORITY_INFO_ACCESS';
function i2d_AUTHORITY_INFO_ACCESS(a: PAUTHORITY_INFO_ACCESS; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_AUTHORITY_INFO_ACCESS';
function AUTHORITY_INFO_ACCESS_it: PASN1_ITEM; cdecl external CLibCrypto name 'AUTHORITY_INFO_ACCESS_it';
function POLICY_MAPPING_it: PASN1_ITEM; cdecl external CLibCrypto name 'POLICY_MAPPING_it';
function POLICY_MAPPING_new: PPOLICY_MAPPING; cdecl external CLibCrypto name 'POLICY_MAPPING_new';
procedure POLICY_MAPPING_free(a: PPOLICY_MAPPING); cdecl external CLibCrypto name 'POLICY_MAPPING_free';
function POLICY_MAPPINGS_it: PASN1_ITEM; cdecl external CLibCrypto name 'POLICY_MAPPINGS_it';
function GENERAL_SUBTREE_it: PASN1_ITEM; cdecl external CLibCrypto name 'GENERAL_SUBTREE_it';
function GENERAL_SUBTREE_new: PGENERAL_SUBTREE; cdecl external CLibCrypto name 'GENERAL_SUBTREE_new';
procedure GENERAL_SUBTREE_free(a: PGENERAL_SUBTREE); cdecl external CLibCrypto name 'GENERAL_SUBTREE_free';
function NAME_CONSTRAINTS_it: PASN1_ITEM; cdecl external CLibCrypto name 'NAME_CONSTRAINTS_it';
function NAME_CONSTRAINTS_new: PNAME_CONSTRAINTS; cdecl external CLibCrypto name 'NAME_CONSTRAINTS_new';
procedure NAME_CONSTRAINTS_free(a: PNAME_CONSTRAINTS); cdecl external CLibCrypto name 'NAME_CONSTRAINTS_free';
function POLICY_CONSTRAINTS_new: PPOLICY_CONSTRAINTS; cdecl external CLibCrypto name 'POLICY_CONSTRAINTS_new';
procedure POLICY_CONSTRAINTS_free(a: PPOLICY_CONSTRAINTS); cdecl external CLibCrypto name 'POLICY_CONSTRAINTS_free';
function POLICY_CONSTRAINTS_it: PASN1_ITEM; cdecl external CLibCrypto name 'POLICY_CONSTRAINTS_it';
function a2i_GENERAL_NAME(_out: PGENERAL_NAME; method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; gen_type: TIdC_INT; value: PIdAnsiChar; is_nc: TIdC_INT): PGENERAL_NAME; cdecl external CLibCrypto name 'a2i_GENERAL_NAME';
function v2i_GENERAL_NAME(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; cnf: PCONF_VALUE): PGENERAL_NAME; cdecl external CLibCrypto name 'v2i_GENERAL_NAME';
function v2i_GENERAL_NAME_ex(_out: PGENERAL_NAME; method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; cnf: PCONF_VALUE; is_nc: TIdC_INT): PGENERAL_NAME; cdecl external CLibCrypto name 'v2i_GENERAL_NAME_ex';
procedure X509V3_conf_free(val: PCONF_VALUE); cdecl external CLibCrypto name 'X509V3_conf_free';
function X509V3_EXT_nconf_nid(conf: PCONF; ctx: PX509V3_CTX; ext_nid: TIdC_INT; value: PIdAnsiChar): PX509_EXTENSION; cdecl external CLibCrypto name 'X509V3_EXT_nconf_nid';
function X509V3_EXT_nconf(conf: PCONF; ctx: PX509V3_CTX; name: PIdAnsiChar; value: PIdAnsiChar): PX509_EXTENSION; cdecl external CLibCrypto name 'X509V3_EXT_nconf';
function X509V3_EXT_add_nconf_sk(conf: PCONF; ctx: PX509V3_CTX; section: PIdAnsiChar; sk: PPstack_st_X509_EXTENSION): TIdC_INT; cdecl external CLibCrypto name 'X509V3_EXT_add_nconf_sk';
function X509V3_EXT_add_nconf(conf: PCONF; ctx: PX509V3_CTX; section: PIdAnsiChar; cert: PX509): TIdC_INT; cdecl external CLibCrypto name 'X509V3_EXT_add_nconf';
function X509V3_EXT_REQ_add_nconf(conf: PCONF; ctx: PX509V3_CTX; section: PIdAnsiChar; req: PX509_REQ): TIdC_INT; cdecl external CLibCrypto name 'X509V3_EXT_REQ_add_nconf';
function X509V3_EXT_CRL_add_nconf(conf: PCONF; ctx: PX509V3_CTX; section: PIdAnsiChar; crl: PX509_CRL): TIdC_INT; cdecl external CLibCrypto name 'X509V3_EXT_CRL_add_nconf';
function X509V3_EXT_conf_nid(conf: Plhash_st_CONF_VALUE; ctx: PX509V3_CTX; ext_nid: TIdC_INT; value: PIdAnsiChar): PX509_EXTENSION; cdecl external CLibCrypto name 'X509V3_EXT_conf_nid';
function X509V3_EXT_conf(conf: Plhash_st_CONF_VALUE; ctx: PX509V3_CTX; name: PIdAnsiChar; value: PIdAnsiChar): PX509_EXTENSION; cdecl external CLibCrypto name 'X509V3_EXT_conf';
function X509V3_EXT_add_conf(conf: Plhash_st_CONF_VALUE; ctx: PX509V3_CTX; section: PIdAnsiChar; cert: PX509): TIdC_INT; cdecl external CLibCrypto name 'X509V3_EXT_add_conf';
function X509V3_EXT_REQ_add_conf(conf: Plhash_st_CONF_VALUE; ctx: PX509V3_CTX; section: PIdAnsiChar; req: PX509_REQ): TIdC_INT; cdecl external CLibCrypto name 'X509V3_EXT_REQ_add_conf';
function X509V3_EXT_CRL_add_conf(conf: Plhash_st_CONF_VALUE; ctx: PX509V3_CTX; section: PIdAnsiChar; crl: PX509_CRL): TIdC_INT; cdecl external CLibCrypto name 'X509V3_EXT_CRL_add_conf';
function X509V3_add_value_bool_nf(name: PIdAnsiChar; asn1_bool: TIdC_INT; extlist: PPstack_st_CONF_VALUE): TIdC_INT; cdecl external CLibCrypto name 'X509V3_add_value_bool_nf';
function X509V3_get_value_bool(value: PCONF_VALUE; asn1_bool: PIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509V3_get_value_bool';
function X509V3_get_value_int(value: PCONF_VALUE; aint: PPASN1_INTEGER): TIdC_INT; cdecl external CLibCrypto name 'X509V3_get_value_int';
procedure X509V3_set_nconf(ctx: PX509V3_CTX; conf: PCONF); cdecl external CLibCrypto name 'X509V3_set_nconf';
procedure X509V3_set_conf_lhash(ctx: PX509V3_CTX; lhash: Plhash_st_CONF_VALUE); cdecl external CLibCrypto name 'X509V3_set_conf_lhash';
function X509V3_get_string(ctx: PX509V3_CTX; name: PIdAnsiChar; section: PIdAnsiChar): PIdAnsiChar; cdecl external CLibCrypto name 'X509V3_get_string';
function X509V3_get_section(ctx: PX509V3_CTX; section: PIdAnsiChar): Pstack_st_CONF_VALUE; cdecl external CLibCrypto name 'X509V3_get_section';
procedure X509V3_string_free(ctx: PX509V3_CTX; str: PIdAnsiChar); cdecl external CLibCrypto name 'X509V3_string_free';
procedure X509V3_section_free(ctx: PX509V3_CTX; section: Pstack_st_CONF_VALUE); cdecl external CLibCrypto name 'X509V3_section_free';
procedure X509V3_set_ctx(ctx: PX509V3_CTX; issuer: PX509; subject: PX509; req: PX509_REQ; crl: PX509_CRL; flags: TIdC_INT); cdecl external CLibCrypto name 'X509V3_set_ctx';
function X509V3_set_issuer_pkey(ctx: PX509V3_CTX; pkey: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'X509V3_set_issuer_pkey';
function X509V3_add_value(name: PIdAnsiChar; value: PIdAnsiChar; extlist: PPstack_st_CONF_VALUE): TIdC_INT; cdecl external CLibCrypto name 'X509V3_add_value';
function X509V3_add_value_uchar(name: PIdAnsiChar; value: PIdAnsiChar; extlist: PPstack_st_CONF_VALUE): TIdC_INT; cdecl external CLibCrypto name 'X509V3_add_value_uchar';
function X509V3_add_value_bool(name: PIdAnsiChar; asn1_bool: TIdC_INT; extlist: PPstack_st_CONF_VALUE): TIdC_INT; cdecl external CLibCrypto name 'X509V3_add_value_bool';
function X509V3_add_value_int(name: PIdAnsiChar; aint: PASN1_INTEGER; extlist: PPstack_st_CONF_VALUE): TIdC_INT; cdecl external CLibCrypto name 'X509V3_add_value_int';
function i2s_ASN1_INTEGER(meth: PX509V3_EXT_METHOD; aint: PASN1_INTEGER): PIdAnsiChar; cdecl external CLibCrypto name 'i2s_ASN1_INTEGER';
function s2i_ASN1_INTEGER(meth: PX509V3_EXT_METHOD; value: PIdAnsiChar): PASN1_INTEGER; cdecl external CLibCrypto name 's2i_ASN1_INTEGER';
function i2s_ASN1_ENUMERATED(meth: PX509V3_EXT_METHOD; aint: PASN1_ENUMERATED): PIdAnsiChar; cdecl external CLibCrypto name 'i2s_ASN1_ENUMERATED';
function i2s_ASN1_ENUMERATED_TABLE(meth: PX509V3_EXT_METHOD; aint: PASN1_ENUMERATED): PIdAnsiChar; cdecl external CLibCrypto name 'i2s_ASN1_ENUMERATED_TABLE';
function X509V3_EXT_add(ext: PX509V3_EXT_METHOD): TIdC_INT; cdecl external CLibCrypto name 'X509V3_EXT_add';
function X509V3_EXT_add_list(extlist: PX509V3_EXT_METHOD): TIdC_INT; cdecl external CLibCrypto name 'X509V3_EXT_add_list';
function X509V3_EXT_add_alias(nid_to: TIdC_INT; nid_from: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509V3_EXT_add_alias';
procedure X509V3_EXT_cleanup; cdecl external CLibCrypto name 'X509V3_EXT_cleanup';
function X509V3_EXT_get(ext: PX509_EXTENSION): PX509V3_EXT_METHOD; cdecl external CLibCrypto name 'X509V3_EXT_get';
function X509V3_EXT_get_nid(nid: TIdC_INT): PX509V3_EXT_METHOD; cdecl external CLibCrypto name 'X509V3_EXT_get_nid';
function X509V3_add_standard_extensions: TIdC_INT; cdecl external CLibCrypto name 'X509V3_add_standard_extensions';
function X509V3_parse_list(line: PIdAnsiChar): Pstack_st_CONF_VALUE; cdecl external CLibCrypto name 'X509V3_parse_list';
function X509V3_EXT_d2i(ext: PX509_EXTENSION): Pointer; cdecl external CLibCrypto name 'X509V3_EXT_d2i';
function X509V3_get_d2i(x: Pstack_st_X509_EXTENSION; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl external CLibCrypto name 'X509V3_get_d2i';
function X509V3_EXT_i2d(ext_nid: TIdC_INT; crit: TIdC_INT; ext_struc: Pointer): PX509_EXTENSION; cdecl external CLibCrypto name 'X509V3_EXT_i2d';
function X509V3_add1_i2d(x: PPstack_st_X509_EXTENSION; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'X509V3_add1_i2d';
procedure X509V3_EXT_val_prn(_out: PBIO; val: Pstack_st_CONF_VALUE; indent: TIdC_INT; ml: TIdC_INT); cdecl external CLibCrypto name 'X509V3_EXT_val_prn';
function X509V3_EXT_print(_out: PBIO; ext: PX509_EXTENSION; flag: TIdC_ULONG; indent: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509V3_EXT_print';
function X509V3_EXT_print_fp(_out: PFILE; ext: PX509_EXTENSION; flag: TIdC_INT; indent: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509V3_EXT_print_fp';
function X509V3_extensions_print(_out: PBIO; title: PIdAnsiChar; exts: Pstack_st_X509_EXTENSION; flag: TIdC_ULONG; indent: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509V3_extensions_print';
function X509_check_ca(x: PX509): TIdC_INT; cdecl external CLibCrypto name 'X509_check_ca';
function X509_check_purpose(x: PX509; id: TIdC_INT; ca: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_check_purpose';
function X509_supported_extension(ex: PX509_EXTENSION): TIdC_INT; cdecl external CLibCrypto name 'X509_supported_extension';
function X509_check_issued(issuer: PX509; subject: PX509): TIdC_INT; cdecl external CLibCrypto name 'X509_check_issued';
function X509_check_akid(issuer: PX509; akid: PAUTHORITY_KEYID): TIdC_INT; cdecl external CLibCrypto name 'X509_check_akid';
procedure X509_set_proxy_flag(x: PX509); cdecl external CLibCrypto name 'X509_set_proxy_flag';
procedure X509_set_proxy_pathlen(x: PX509; l: TIdC_LONG); cdecl external CLibCrypto name 'X509_set_proxy_pathlen';
function X509_get_proxy_pathlen(x: PX509): TIdC_LONG; cdecl external CLibCrypto name 'X509_get_proxy_pathlen';
function X509_get_extension_flags(x: PX509): UInt32; cdecl external CLibCrypto name 'X509_get_extension_flags';
function X509_get_key_usage(x: PX509): UInt32; cdecl external CLibCrypto name 'X509_get_key_usage';
function X509_get_extended_key_usage(x: PX509): UInt32; cdecl external CLibCrypto name 'X509_get_extended_key_usage';
function X509_get0_subject_key_id(x: PX509): PASN1_OCTET_STRING; cdecl external CLibCrypto name 'X509_get0_subject_key_id';
function X509_get0_authority_key_id(x: PX509): PASN1_OCTET_STRING; cdecl external CLibCrypto name 'X509_get0_authority_key_id';
function X509_get0_authority_issuer(x: PX509): PGENERAL_NAMES; cdecl external CLibCrypto name 'X509_get0_authority_issuer';
function X509_get0_authority_serial(x: PX509): PASN1_INTEGER; cdecl external CLibCrypto name 'X509_get0_authority_serial';
function X509_PURPOSE_get_count: TIdC_INT; cdecl external CLibCrypto name 'X509_PURPOSE_get_count';
function X509_PURPOSE_get_unused_id(libctx: POSSL_LIB_CTX): TIdC_INT; cdecl external CLibCrypto name 'X509_PURPOSE_get_unused_id';
function X509_PURPOSE_get_by_sname(sname: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'X509_PURPOSE_get_by_sname';
function X509_PURPOSE_get_by_id(id: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_PURPOSE_get_by_id';
function X509_PURPOSE_add(id: TIdC_INT; trust: TIdC_INT; flags: TIdC_INT; ck: TX509_PURPOSE_add_ck_cb; name: PIdAnsiChar; sname: PIdAnsiChar; arg: Pointer): TIdC_INT; cdecl external CLibCrypto name 'X509_PURPOSE_add';
procedure X509_PURPOSE_cleanup; cdecl external CLibCrypto name 'X509_PURPOSE_cleanup';
function X509_PURPOSE_get0(idx: TIdC_INT): PX509_PURPOSE; cdecl external CLibCrypto name 'X509_PURPOSE_get0';
function X509_PURPOSE_get_id(arg1: PX509_PURPOSE): TIdC_INT; cdecl external CLibCrypto name 'X509_PURPOSE_get_id';
function X509_PURPOSE_get0_name(xp: PX509_PURPOSE): PIdAnsiChar; cdecl external CLibCrypto name 'X509_PURPOSE_get0_name';
function X509_PURPOSE_get0_sname(xp: PX509_PURPOSE): PIdAnsiChar; cdecl external CLibCrypto name 'X509_PURPOSE_get0_sname';
function X509_PURPOSE_get_trust(xp: PX509_PURPOSE): TIdC_INT; cdecl external CLibCrypto name 'X509_PURPOSE_get_trust';
function X509_PURPOSE_set(p: PIdC_INT; purpose: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_PURPOSE_set';
function X509_get1_email(x: PX509): Pstack_st_OPENSSL_STRING; cdecl external CLibCrypto name 'X509_get1_email';
function X509_REQ_get1_email(x: PX509_REQ): Pstack_st_OPENSSL_STRING; cdecl external CLibCrypto name 'X509_REQ_get1_email';
procedure X509_email_free(sk: Pstack_st_OPENSSL_STRING); cdecl external CLibCrypto name 'X509_email_free';
function X509_get1_ocsp(x: PX509): Pstack_st_OPENSSL_STRING; cdecl external CLibCrypto name 'X509_get1_ocsp';
function X509_check_host(x: PX509; chk: PIdAnsiChar; chklen: TIdC_SIZET; flags: TIdC_UINT; peername: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'X509_check_host';
function X509_check_email(x: PX509; chk: PIdAnsiChar; chklen: TIdC_SIZET; flags: TIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'X509_check_email';
function X509_check_ip(x: PX509; chk: PIdAnsiChar; chklen: TIdC_SIZET; flags: TIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'X509_check_ip';
function X509_check_ip_asc(x: PX509; ipasc: PIdAnsiChar; flags: TIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'X509_check_ip_asc';
function a2i_IPADDRESS(ipasc: PIdAnsiChar): PASN1_OCTET_STRING; cdecl external CLibCrypto name 'a2i_IPADDRESS';
function a2i_IPADDRESS_NC(ipasc: PIdAnsiChar): PASN1_OCTET_STRING; cdecl external CLibCrypto name 'a2i_IPADDRESS_NC';
function X509V3_NAME_from_section(nm: PX509_NAME; dn_sk: Pstack_st_CONF_VALUE; chtype: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'X509V3_NAME_from_section';
procedure X509_POLICY_NODE_print(_out: PBIO; node: PX509_POLICY_NODE; indent: TIdC_INT); cdecl external CLibCrypto name 'X509_POLICY_NODE_print';
function ASRange_new: PASRange; cdecl external CLibCrypto name 'ASRange_new';
procedure ASRange_free(a: PASRange); cdecl external CLibCrypto name 'ASRange_free';
function d2i_ASRange(a: PPASRange; _in: PPIdAnsiChar; len: TIdC_LONG): PASRange; cdecl external CLibCrypto name 'd2i_ASRange';
function i2d_ASRange(a: PASRange; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ASRange';
function ASRange_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASRange_it';
function ASIdOrRange_new: PASIdOrRange; cdecl external CLibCrypto name 'ASIdOrRange_new';
procedure ASIdOrRange_free(a: PASIdOrRange); cdecl external CLibCrypto name 'ASIdOrRange_free';
function d2i_ASIdOrRange(a: PPASIdOrRange; _in: PPIdAnsiChar; len: TIdC_LONG): PASIdOrRange; cdecl external CLibCrypto name 'd2i_ASIdOrRange';
function i2d_ASIdOrRange(a: PASIdOrRange; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ASIdOrRange';
function ASIdOrRange_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASIdOrRange_it';
function ASIdentifierChoice_new: PASIdentifierChoice; cdecl external CLibCrypto name 'ASIdentifierChoice_new';
procedure ASIdentifierChoice_free(a: PASIdentifierChoice); cdecl external CLibCrypto name 'ASIdentifierChoice_free';
function d2i_ASIdentifierChoice(a: PPASIdentifierChoice; _in: PPIdAnsiChar; len: TIdC_LONG): PASIdentifierChoice; cdecl external CLibCrypto name 'd2i_ASIdentifierChoice';
function i2d_ASIdentifierChoice(a: PASIdentifierChoice; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ASIdentifierChoice';
function ASIdentifierChoice_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASIdentifierChoice_it';
function ASIdentifiers_new: PASIdentifiers; cdecl external CLibCrypto name 'ASIdentifiers_new';
procedure ASIdentifiers_free(a: PASIdentifiers); cdecl external CLibCrypto name 'ASIdentifiers_free';
function d2i_ASIdentifiers(a: PPASIdentifiers; _in: PPIdAnsiChar; len: TIdC_LONG): PASIdentifiers; cdecl external CLibCrypto name 'd2i_ASIdentifiers';
function i2d_ASIdentifiers(a: PASIdentifiers; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ASIdentifiers';
function ASIdentifiers_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASIdentifiers_it';
function IPAddressRange_new: PIPAddressRange; cdecl external CLibCrypto name 'IPAddressRange_new';
procedure IPAddressRange_free(a: PIPAddressRange); cdecl external CLibCrypto name 'IPAddressRange_free';
function d2i_IPAddressRange(a: PPIPAddressRange; _in: PPIdAnsiChar; len: TIdC_LONG): PIPAddressRange; cdecl external CLibCrypto name 'd2i_IPAddressRange';
function i2d_IPAddressRange(a: PIPAddressRange; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_IPAddressRange';
function IPAddressRange_it: PASN1_ITEM; cdecl external CLibCrypto name 'IPAddressRange_it';
function IPAddressOrRange_new: PIPAddressOrRange; cdecl external CLibCrypto name 'IPAddressOrRange_new';
procedure IPAddressOrRange_free(a: PIPAddressOrRange); cdecl external CLibCrypto name 'IPAddressOrRange_free';
function d2i_IPAddressOrRange(a: PPIPAddressOrRange; _in: PPIdAnsiChar; len: TIdC_LONG): PIPAddressOrRange; cdecl external CLibCrypto name 'd2i_IPAddressOrRange';
function i2d_IPAddressOrRange(a: PIPAddressOrRange; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_IPAddressOrRange';
function IPAddressOrRange_it: PASN1_ITEM; cdecl external CLibCrypto name 'IPAddressOrRange_it';
function IPAddressChoice_new: PIPAddressChoice; cdecl external CLibCrypto name 'IPAddressChoice_new';
procedure IPAddressChoice_free(a: PIPAddressChoice); cdecl external CLibCrypto name 'IPAddressChoice_free';
function d2i_IPAddressChoice(a: PPIPAddressChoice; _in: PPIdAnsiChar; len: TIdC_LONG): PIPAddressChoice; cdecl external CLibCrypto name 'd2i_IPAddressChoice';
function i2d_IPAddressChoice(a: PIPAddressChoice; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_IPAddressChoice';
function IPAddressChoice_it: PASN1_ITEM; cdecl external CLibCrypto name 'IPAddressChoice_it';
function IPAddressFamily_new: PIPAddressFamily; cdecl external CLibCrypto name 'IPAddressFamily_new';
procedure IPAddressFamily_free(a: PIPAddressFamily); cdecl external CLibCrypto name 'IPAddressFamily_free';
function d2i_IPAddressFamily(a: PPIPAddressFamily; _in: PPIdAnsiChar; len: TIdC_LONG): PIPAddressFamily; cdecl external CLibCrypto name 'd2i_IPAddressFamily';
function i2d_IPAddressFamily(a: PIPAddressFamily; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_IPAddressFamily';
function IPAddressFamily_it: PASN1_ITEM; cdecl external CLibCrypto name 'IPAddressFamily_it';
function X509v3_asid_add_inherit(asid: PASIdentifiers; which: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509v3_asid_add_inherit';
function X509v3_asid_add_id_or_range(asid: PASIdentifiers; which: TIdC_INT; min: PASN1_INTEGER; max: PASN1_INTEGER): TIdC_INT; cdecl external CLibCrypto name 'X509v3_asid_add_id_or_range';
function X509v3_addr_add_inherit(addr: PIPAddrBlocks; afi: TIdC_UINT; safi: PIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'X509v3_addr_add_inherit';
function X509v3_addr_add_prefix(addr: PIPAddrBlocks; afi: TIdC_UINT; safi: PIdC_UINT; a: PIdAnsiChar; prefixlen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509v3_addr_add_prefix';
function X509v3_addr_add_range(addr: PIPAddrBlocks; afi: TIdC_UINT; safi: PIdC_UINT; min: PIdAnsiChar; max: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'X509v3_addr_add_range';
function X509v3_addr_get_afi(f: PIPAddressFamily): TIdC_UINT; cdecl external CLibCrypto name 'X509v3_addr_get_afi';
function X509v3_addr_get_range(aor: PIPAddressOrRange; afi: TIdC_UINT; min: PIdAnsiChar; max: PIdAnsiChar; length: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509v3_addr_get_range';
function X509v3_asid_is_canonical(asid: PASIdentifiers): TIdC_INT; cdecl external CLibCrypto name 'X509v3_asid_is_canonical';
function X509v3_addr_is_canonical(addr: PIPAddrBlocks): TIdC_INT; cdecl external CLibCrypto name 'X509v3_addr_is_canonical';
function X509v3_asid_canonize(asid: PASIdentifiers): TIdC_INT; cdecl external CLibCrypto name 'X509v3_asid_canonize';
function X509v3_addr_canonize(addr: PIPAddrBlocks): TIdC_INT; cdecl external CLibCrypto name 'X509v3_addr_canonize';
function X509v3_asid_inherits(asid: PASIdentifiers): TIdC_INT; cdecl external CLibCrypto name 'X509v3_asid_inherits';
function X509v3_addr_inherits(addr: PIPAddrBlocks): TIdC_INT; cdecl external CLibCrypto name 'X509v3_addr_inherits';
function X509v3_asid_subset(a: PASIdentifiers; b: PASIdentifiers): TIdC_INT; cdecl external CLibCrypto name 'X509v3_asid_subset';
function X509v3_addr_subset(a: PIPAddrBlocks; b: PIPAddrBlocks): TIdC_INT; cdecl external CLibCrypto name 'X509v3_addr_subset';
function X509v3_asid_validate_path(arg1: PX509_STORE_CTX): TIdC_INT; cdecl external CLibCrypto name 'X509v3_asid_validate_path';
function X509v3_addr_validate_path(arg1: PX509_STORE_CTX): TIdC_INT; cdecl external CLibCrypto name 'X509v3_addr_validate_path';
function X509v3_asid_validate_resource_set(chain: Pstack_st_X509; ext: PASIdentifiers; allow_inheritance: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509v3_asid_validate_resource_set';
function X509v3_addr_validate_resource_set(chain: Pstack_st_X509; ext: PIPAddrBlocks; allow_inheritance: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509v3_addr_validate_resource_set';
function NAMING_AUTHORITY_new: PNAMING_AUTHORITY; cdecl external CLibCrypto name 'NAMING_AUTHORITY_new';
procedure NAMING_AUTHORITY_free(a: PNAMING_AUTHORITY); cdecl external CLibCrypto name 'NAMING_AUTHORITY_free';
function d2i_NAMING_AUTHORITY(a: PPNAMING_AUTHORITY; _in: PPIdAnsiChar; len: TIdC_LONG): PNAMING_AUTHORITY; cdecl external CLibCrypto name 'd2i_NAMING_AUTHORITY';
function i2d_NAMING_AUTHORITY(a: PNAMING_AUTHORITY; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_NAMING_AUTHORITY';
function NAMING_AUTHORITY_it: PASN1_ITEM; cdecl external CLibCrypto name 'NAMING_AUTHORITY_it';
function PROFESSION_INFO_new: PPROFESSION_INFO; cdecl external CLibCrypto name 'PROFESSION_INFO_new';
procedure PROFESSION_INFO_free(a: PPROFESSION_INFO); cdecl external CLibCrypto name 'PROFESSION_INFO_free';
function d2i_PROFESSION_INFO(a: PPPROFESSION_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PPROFESSION_INFO; cdecl external CLibCrypto name 'd2i_PROFESSION_INFO';
function i2d_PROFESSION_INFO(a: PPROFESSION_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_PROFESSION_INFO';
function PROFESSION_INFO_it: PASN1_ITEM; cdecl external CLibCrypto name 'PROFESSION_INFO_it';
function ADMISSIONS_new: PADMISSIONS; cdecl external CLibCrypto name 'ADMISSIONS_new';
procedure ADMISSIONS_free(a: PADMISSIONS); cdecl external CLibCrypto name 'ADMISSIONS_free';
function d2i_ADMISSIONS(a: PPADMISSIONS; _in: PPIdAnsiChar; len: TIdC_LONG): PADMISSIONS; cdecl external CLibCrypto name 'd2i_ADMISSIONS';
function i2d_ADMISSIONS(a: PADMISSIONS; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ADMISSIONS';
function ADMISSIONS_it: PASN1_ITEM; cdecl external CLibCrypto name 'ADMISSIONS_it';
function ADMISSION_SYNTAX_new: PADMISSION_SYNTAX; cdecl external CLibCrypto name 'ADMISSION_SYNTAX_new';
procedure ADMISSION_SYNTAX_free(a: PADMISSION_SYNTAX); cdecl external CLibCrypto name 'ADMISSION_SYNTAX_free';
function d2i_ADMISSION_SYNTAX(a: PPADMISSION_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): PADMISSION_SYNTAX; cdecl external CLibCrypto name 'd2i_ADMISSION_SYNTAX';
function i2d_ADMISSION_SYNTAX(a: PADMISSION_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ADMISSION_SYNTAX';
function ADMISSION_SYNTAX_it: PASN1_ITEM; cdecl external CLibCrypto name 'ADMISSION_SYNTAX_it';
function NAMING_AUTHORITY_get0_authorityId(n: PNAMING_AUTHORITY): PASN1_OBJECT; cdecl external CLibCrypto name 'NAMING_AUTHORITY_get0_authorityId';
function NAMING_AUTHORITY_get0_authorityURL(n: PNAMING_AUTHORITY): PASN1_IA5STRING; cdecl external CLibCrypto name 'NAMING_AUTHORITY_get0_authorityURL';
function NAMING_AUTHORITY_get0_authorityText(n: PNAMING_AUTHORITY): PASN1_STRING; cdecl external CLibCrypto name 'NAMING_AUTHORITY_get0_authorityText';
procedure NAMING_AUTHORITY_set0_authorityId(n: PNAMING_AUTHORITY; namingAuthorityId: PASN1_OBJECT); cdecl external CLibCrypto name 'NAMING_AUTHORITY_set0_authorityId';
procedure NAMING_AUTHORITY_set0_authorityURL(n: PNAMING_AUTHORITY; namingAuthorityUrl: PASN1_IA5STRING); cdecl external CLibCrypto name 'NAMING_AUTHORITY_set0_authorityURL';
procedure NAMING_AUTHORITY_set0_authorityText(n: PNAMING_AUTHORITY; namingAuthorityText: PASN1_STRING); cdecl external CLibCrypto name 'NAMING_AUTHORITY_set0_authorityText';
function ADMISSION_SYNTAX_get0_admissionAuthority(_as: PADMISSION_SYNTAX): PGENERAL_NAME; cdecl external CLibCrypto name 'ADMISSION_SYNTAX_get0_admissionAuthority';
procedure ADMISSION_SYNTAX_set0_admissionAuthority(_as: PADMISSION_SYNTAX; aa: PGENERAL_NAME); cdecl external CLibCrypto name 'ADMISSION_SYNTAX_set0_admissionAuthority';
function ADMISSION_SYNTAX_get0_contentsOfAdmissions(_as: PADMISSION_SYNTAX): Pstack_st_ADMISSIONS; cdecl external CLibCrypto name 'ADMISSION_SYNTAX_get0_contentsOfAdmissions';
procedure ADMISSION_SYNTAX_set0_contentsOfAdmissions(_as: PADMISSION_SYNTAX; a: Pstack_st_ADMISSIONS); cdecl external CLibCrypto name 'ADMISSION_SYNTAX_set0_contentsOfAdmissions';
function ADMISSIONS_get0_admissionAuthority(a: PADMISSIONS): PGENERAL_NAME; cdecl external CLibCrypto name 'ADMISSIONS_get0_admissionAuthority';
procedure ADMISSIONS_set0_admissionAuthority(a: PADMISSIONS; aa: PGENERAL_NAME); cdecl external CLibCrypto name 'ADMISSIONS_set0_admissionAuthority';
function ADMISSIONS_get0_namingAuthority(a: PADMISSIONS): PNAMING_AUTHORITY; cdecl external CLibCrypto name 'ADMISSIONS_get0_namingAuthority';
procedure ADMISSIONS_set0_namingAuthority(a: PADMISSIONS; na: PNAMING_AUTHORITY); cdecl external CLibCrypto name 'ADMISSIONS_set0_namingAuthority';
function ADMISSIONS_get0_professionInfos(a: PADMISSIONS): PPROFESSION_INFOS; cdecl external CLibCrypto name 'ADMISSIONS_get0_professionInfos';
procedure ADMISSIONS_set0_professionInfos(a: PADMISSIONS; pi: PPROFESSION_INFOS); cdecl external CLibCrypto name 'ADMISSIONS_set0_professionInfos';
function PROFESSION_INFO_get0_addProfessionInfo(pi: PPROFESSION_INFO): PASN1_OCTET_STRING; cdecl external CLibCrypto name 'PROFESSION_INFO_get0_addProfessionInfo';
procedure PROFESSION_INFO_set0_addProfessionInfo(pi: PPROFESSION_INFO; aos: PASN1_OCTET_STRING); cdecl external CLibCrypto name 'PROFESSION_INFO_set0_addProfessionInfo';
function PROFESSION_INFO_get0_namingAuthority(pi: PPROFESSION_INFO): PNAMING_AUTHORITY; cdecl external CLibCrypto name 'PROFESSION_INFO_get0_namingAuthority';
procedure PROFESSION_INFO_set0_namingAuthority(pi: PPROFESSION_INFO; na: PNAMING_AUTHORITY); cdecl external CLibCrypto name 'PROFESSION_INFO_set0_namingAuthority';
function PROFESSION_INFO_get0_professionItems(pi: PPROFESSION_INFO): Pstack_st_ASN1_STRING; cdecl external CLibCrypto name 'PROFESSION_INFO_get0_professionItems';
procedure PROFESSION_INFO_set0_professionItems(pi: PPROFESSION_INFO; _as: Pstack_st_ASN1_STRING); cdecl external CLibCrypto name 'PROFESSION_INFO_set0_professionItems';
function PROFESSION_INFO_get0_professionOIDs(pi: PPROFESSION_INFO): Pstack_st_ASN1_OBJECT; cdecl external CLibCrypto name 'PROFESSION_INFO_get0_professionOIDs';
procedure PROFESSION_INFO_set0_professionOIDs(pi: PPROFESSION_INFO; po: Pstack_st_ASN1_OBJECT); cdecl external CLibCrypto name 'PROFESSION_INFO_set0_professionOIDs';
function PROFESSION_INFO_get0_registrationNumber(pi: PPROFESSION_INFO): PASN1_PRINTABLESTRING; cdecl external CLibCrypto name 'PROFESSION_INFO_get0_registrationNumber';
procedure PROFESSION_INFO_set0_registrationNumber(pi: PPROFESSION_INFO; rn: PASN1_PRINTABLESTRING); cdecl external CLibCrypto name 'PROFESSION_INFO_set0_registrationNumber';
function OSSL_GENERAL_NAMES_print(_out: PBIO; gens: PGENERAL_NAMES; indent: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_GENERAL_NAMES_print';
function OSSL_ATTRIBUTES_SYNTAX_new: POSSL_ATTRIBUTES_SYNTAX; cdecl external CLibCrypto name 'OSSL_ATTRIBUTES_SYNTAX_new';
procedure OSSL_ATTRIBUTES_SYNTAX_free(a: POSSL_ATTRIBUTES_SYNTAX); cdecl external CLibCrypto name 'OSSL_ATTRIBUTES_SYNTAX_free';
function d2i_OSSL_ATTRIBUTES_SYNTAX(a: PPOSSL_ATTRIBUTES_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ATTRIBUTES_SYNTAX; cdecl external CLibCrypto name 'd2i_OSSL_ATTRIBUTES_SYNTAX';
function i2d_OSSL_ATTRIBUTES_SYNTAX(a: POSSL_ATTRIBUTES_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_ATTRIBUTES_SYNTAX';
function OSSL_ATTRIBUTES_SYNTAX_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_ATTRIBUTES_SYNTAX_it';
function OSSL_USER_NOTICE_SYNTAX_new: POSSL_USER_NOTICE_SYNTAX; cdecl external CLibCrypto name 'OSSL_USER_NOTICE_SYNTAX_new';
procedure OSSL_USER_NOTICE_SYNTAX_free(a: POSSL_USER_NOTICE_SYNTAX); cdecl external CLibCrypto name 'OSSL_USER_NOTICE_SYNTAX_free';
function d2i_OSSL_USER_NOTICE_SYNTAX(a: PPOSSL_USER_NOTICE_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_USER_NOTICE_SYNTAX; cdecl external CLibCrypto name 'd2i_OSSL_USER_NOTICE_SYNTAX';
function i2d_OSSL_USER_NOTICE_SYNTAX(a: POSSL_USER_NOTICE_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_USER_NOTICE_SYNTAX';
function OSSL_USER_NOTICE_SYNTAX_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_USER_NOTICE_SYNTAX_it';
function OSSL_ROLE_SPEC_CERT_ID_new: POSSL_ROLE_SPEC_CERT_ID; cdecl external CLibCrypto name 'OSSL_ROLE_SPEC_CERT_ID_new';
procedure OSSL_ROLE_SPEC_CERT_ID_free(a: POSSL_ROLE_SPEC_CERT_ID); cdecl external CLibCrypto name 'OSSL_ROLE_SPEC_CERT_ID_free';
function d2i_OSSL_ROLE_SPEC_CERT_ID(a: PPOSSL_ROLE_SPEC_CERT_ID; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ROLE_SPEC_CERT_ID; cdecl external CLibCrypto name 'd2i_OSSL_ROLE_SPEC_CERT_ID';
function i2d_OSSL_ROLE_SPEC_CERT_ID(a: POSSL_ROLE_SPEC_CERT_ID; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_ROLE_SPEC_CERT_ID';
function OSSL_ROLE_SPEC_CERT_ID_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_ROLE_SPEC_CERT_ID_it';
function OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new: POSSL_ROLE_SPEC_CERT_ID_SYNTAX; cdecl external CLibCrypto name 'OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new';
procedure OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free(a: POSSL_ROLE_SPEC_CERT_ID_SYNTAX); cdecl external CLibCrypto name 'OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free';
function d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX(a: PPOSSL_ROLE_SPEC_CERT_ID_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ROLE_SPEC_CERT_ID_SYNTAX; cdecl external CLibCrypto name 'd2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX';
function i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX(a: POSSL_ROLE_SPEC_CERT_ID_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX';
function OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it';
function OSSL_HASH_new: POSSL_HASH; cdecl external CLibCrypto name 'OSSL_HASH_new';
procedure OSSL_HASH_free(a: POSSL_HASH); cdecl external CLibCrypto name 'OSSL_HASH_free';
function d2i_OSSL_HASH(a: PPOSSL_HASH; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_HASH; cdecl external CLibCrypto name 'd2i_OSSL_HASH';
function i2d_OSSL_HASH(a: POSSL_HASH; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_HASH';
function OSSL_HASH_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_HASH_it';
function OSSL_INFO_SYNTAX_new: POSSL_INFO_SYNTAX; cdecl external CLibCrypto name 'OSSL_INFO_SYNTAX_new';
procedure OSSL_INFO_SYNTAX_free(a: POSSL_INFO_SYNTAX); cdecl external CLibCrypto name 'OSSL_INFO_SYNTAX_free';
function d2i_OSSL_INFO_SYNTAX(a: PPOSSL_INFO_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_INFO_SYNTAX; cdecl external CLibCrypto name 'd2i_OSSL_INFO_SYNTAX';
function i2d_OSSL_INFO_SYNTAX(a: POSSL_INFO_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_INFO_SYNTAX';
function OSSL_INFO_SYNTAX_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_INFO_SYNTAX_it';
function OSSL_INFO_SYNTAX_POINTER_new: POSSL_INFO_SYNTAX_POINTER; cdecl external CLibCrypto name 'OSSL_INFO_SYNTAX_POINTER_new';
procedure OSSL_INFO_SYNTAX_POINTER_free(a: POSSL_INFO_SYNTAX_POINTER); cdecl external CLibCrypto name 'OSSL_INFO_SYNTAX_POINTER_free';
function d2i_OSSL_INFO_SYNTAX_POINTER(a: PPOSSL_INFO_SYNTAX_POINTER; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_INFO_SYNTAX_POINTER; cdecl external CLibCrypto name 'd2i_OSSL_INFO_SYNTAX_POINTER';
function i2d_OSSL_INFO_SYNTAX_POINTER(a: POSSL_INFO_SYNTAX_POINTER; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_INFO_SYNTAX_POINTER';
function OSSL_INFO_SYNTAX_POINTER_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_INFO_SYNTAX_POINTER_it';
function OSSL_PRIVILEGE_POLICY_ID_new: POSSL_PRIVILEGE_POLICY_ID; cdecl external CLibCrypto name 'OSSL_PRIVILEGE_POLICY_ID_new';
procedure OSSL_PRIVILEGE_POLICY_ID_free(a: POSSL_PRIVILEGE_POLICY_ID); cdecl external CLibCrypto name 'OSSL_PRIVILEGE_POLICY_ID_free';
function d2i_OSSL_PRIVILEGE_POLICY_ID(a: PPOSSL_PRIVILEGE_POLICY_ID; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_PRIVILEGE_POLICY_ID; cdecl external CLibCrypto name 'd2i_OSSL_PRIVILEGE_POLICY_ID';
function i2d_OSSL_PRIVILEGE_POLICY_ID(a: POSSL_PRIVILEGE_POLICY_ID; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_PRIVILEGE_POLICY_ID';
function OSSL_PRIVILEGE_POLICY_ID_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_PRIVILEGE_POLICY_ID_it';
function OSSL_ATTRIBUTE_DESCRIPTOR_new: POSSL_ATTRIBUTE_DESCRIPTOR; cdecl external CLibCrypto name 'OSSL_ATTRIBUTE_DESCRIPTOR_new';
procedure OSSL_ATTRIBUTE_DESCRIPTOR_free(a: POSSL_ATTRIBUTE_DESCRIPTOR); cdecl external CLibCrypto name 'OSSL_ATTRIBUTE_DESCRIPTOR_free';
function d2i_OSSL_ATTRIBUTE_DESCRIPTOR(a: PPOSSL_ATTRIBUTE_DESCRIPTOR; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ATTRIBUTE_DESCRIPTOR; cdecl external CLibCrypto name 'd2i_OSSL_ATTRIBUTE_DESCRIPTOR';
function i2d_OSSL_ATTRIBUTE_DESCRIPTOR(a: POSSL_ATTRIBUTE_DESCRIPTOR; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_ATTRIBUTE_DESCRIPTOR';
function OSSL_ATTRIBUTE_DESCRIPTOR_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_ATTRIBUTE_DESCRIPTOR_it';
function OSSL_DAY_TIME_new: POSSL_DAY_TIME; cdecl external CLibCrypto name 'OSSL_DAY_TIME_new';
procedure OSSL_DAY_TIME_free(a: POSSL_DAY_TIME); cdecl external CLibCrypto name 'OSSL_DAY_TIME_free';
function d2i_OSSL_DAY_TIME(a: PPOSSL_DAY_TIME; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_DAY_TIME; cdecl external CLibCrypto name 'd2i_OSSL_DAY_TIME';
function i2d_OSSL_DAY_TIME(a: POSSL_DAY_TIME; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_DAY_TIME';
function OSSL_DAY_TIME_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_DAY_TIME_it';
function OSSL_DAY_TIME_BAND_new: POSSL_DAY_TIME_BAND; cdecl external CLibCrypto name 'OSSL_DAY_TIME_BAND_new';
procedure OSSL_DAY_TIME_BAND_free(a: POSSL_DAY_TIME_BAND); cdecl external CLibCrypto name 'OSSL_DAY_TIME_BAND_free';
function d2i_OSSL_DAY_TIME_BAND(a: PPOSSL_DAY_TIME_BAND; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_DAY_TIME_BAND; cdecl external CLibCrypto name 'd2i_OSSL_DAY_TIME_BAND';
function i2d_OSSL_DAY_TIME_BAND(a: POSSL_DAY_TIME_BAND; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_DAY_TIME_BAND';
function OSSL_DAY_TIME_BAND_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_DAY_TIME_BAND_it';
function OSSL_TIME_SPEC_DAY_new: POSSL_TIME_SPEC_DAY; cdecl external CLibCrypto name 'OSSL_TIME_SPEC_DAY_new';
procedure OSSL_TIME_SPEC_DAY_free(a: POSSL_TIME_SPEC_DAY); cdecl external CLibCrypto name 'OSSL_TIME_SPEC_DAY_free';
function d2i_OSSL_TIME_SPEC_DAY(a: PPOSSL_TIME_SPEC_DAY; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_SPEC_DAY; cdecl external CLibCrypto name 'd2i_OSSL_TIME_SPEC_DAY';
function i2d_OSSL_TIME_SPEC_DAY(a: POSSL_TIME_SPEC_DAY; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_TIME_SPEC_DAY';
function OSSL_TIME_SPEC_DAY_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_TIME_SPEC_DAY_it';
function OSSL_TIME_SPEC_WEEKS_new: POSSL_TIME_SPEC_WEEKS; cdecl external CLibCrypto name 'OSSL_TIME_SPEC_WEEKS_new';
procedure OSSL_TIME_SPEC_WEEKS_free(a: POSSL_TIME_SPEC_WEEKS); cdecl external CLibCrypto name 'OSSL_TIME_SPEC_WEEKS_free';
function d2i_OSSL_TIME_SPEC_WEEKS(a: PPOSSL_TIME_SPEC_WEEKS; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_SPEC_WEEKS; cdecl external CLibCrypto name 'd2i_OSSL_TIME_SPEC_WEEKS';
function i2d_OSSL_TIME_SPEC_WEEKS(a: POSSL_TIME_SPEC_WEEKS; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_TIME_SPEC_WEEKS';
function OSSL_TIME_SPEC_WEEKS_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_TIME_SPEC_WEEKS_it';
function OSSL_TIME_SPEC_MONTH_new: POSSL_TIME_SPEC_MONTH; cdecl external CLibCrypto name 'OSSL_TIME_SPEC_MONTH_new';
procedure OSSL_TIME_SPEC_MONTH_free(a: POSSL_TIME_SPEC_MONTH); cdecl external CLibCrypto name 'OSSL_TIME_SPEC_MONTH_free';
function d2i_OSSL_TIME_SPEC_MONTH(a: PPOSSL_TIME_SPEC_MONTH; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_SPEC_MONTH; cdecl external CLibCrypto name 'd2i_OSSL_TIME_SPEC_MONTH';
function i2d_OSSL_TIME_SPEC_MONTH(a: POSSL_TIME_SPEC_MONTH; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_TIME_SPEC_MONTH';
function OSSL_TIME_SPEC_MONTH_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_TIME_SPEC_MONTH_it';
function OSSL_NAMED_DAY_new: POSSL_NAMED_DAY; cdecl external CLibCrypto name 'OSSL_NAMED_DAY_new';
procedure OSSL_NAMED_DAY_free(a: POSSL_NAMED_DAY); cdecl external CLibCrypto name 'OSSL_NAMED_DAY_free';
function d2i_OSSL_NAMED_DAY(a: PPOSSL_NAMED_DAY; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_NAMED_DAY; cdecl external CLibCrypto name 'd2i_OSSL_NAMED_DAY';
function i2d_OSSL_NAMED_DAY(a: POSSL_NAMED_DAY; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_NAMED_DAY';
function OSSL_NAMED_DAY_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_NAMED_DAY_it';
function OSSL_TIME_SPEC_X_DAY_OF_new: POSSL_TIME_SPEC_X_DAY_OF; cdecl external CLibCrypto name 'OSSL_TIME_SPEC_X_DAY_OF_new';
procedure OSSL_TIME_SPEC_X_DAY_OF_free(a: POSSL_TIME_SPEC_X_DAY_OF); cdecl external CLibCrypto name 'OSSL_TIME_SPEC_X_DAY_OF_free';
function d2i_OSSL_TIME_SPEC_X_DAY_OF(a: PPOSSL_TIME_SPEC_X_DAY_OF; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_SPEC_X_DAY_OF; cdecl external CLibCrypto name 'd2i_OSSL_TIME_SPEC_X_DAY_OF';
function i2d_OSSL_TIME_SPEC_X_DAY_OF(a: POSSL_TIME_SPEC_X_DAY_OF; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_TIME_SPEC_X_DAY_OF';
function OSSL_TIME_SPEC_X_DAY_OF_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_TIME_SPEC_X_DAY_OF_it';
function OSSL_TIME_SPEC_ABSOLUTE_new: POSSL_TIME_SPEC_ABSOLUTE; cdecl external CLibCrypto name 'OSSL_TIME_SPEC_ABSOLUTE_new';
procedure OSSL_TIME_SPEC_ABSOLUTE_free(a: POSSL_TIME_SPEC_ABSOLUTE); cdecl external CLibCrypto name 'OSSL_TIME_SPEC_ABSOLUTE_free';
function d2i_OSSL_TIME_SPEC_ABSOLUTE(a: PPOSSL_TIME_SPEC_ABSOLUTE; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_SPEC_ABSOLUTE; cdecl external CLibCrypto name 'd2i_OSSL_TIME_SPEC_ABSOLUTE';
function i2d_OSSL_TIME_SPEC_ABSOLUTE(a: POSSL_TIME_SPEC_ABSOLUTE; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_TIME_SPEC_ABSOLUTE';
function OSSL_TIME_SPEC_ABSOLUTE_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_TIME_SPEC_ABSOLUTE_it';
function OSSL_TIME_SPEC_TIME_new: POSSL_TIME_SPEC_TIME; cdecl external CLibCrypto name 'OSSL_TIME_SPEC_TIME_new';
procedure OSSL_TIME_SPEC_TIME_free(a: POSSL_TIME_SPEC_TIME); cdecl external CLibCrypto name 'OSSL_TIME_SPEC_TIME_free';
function d2i_OSSL_TIME_SPEC_TIME(a: PPOSSL_TIME_SPEC_TIME; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_SPEC_TIME; cdecl external CLibCrypto name 'd2i_OSSL_TIME_SPEC_TIME';
function i2d_OSSL_TIME_SPEC_TIME(a: POSSL_TIME_SPEC_TIME; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_TIME_SPEC_TIME';
function OSSL_TIME_SPEC_TIME_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_TIME_SPEC_TIME_it';
function OSSL_TIME_SPEC_new: POSSL_TIME_SPEC; cdecl external CLibCrypto name 'OSSL_TIME_SPEC_new';
procedure OSSL_TIME_SPEC_free(a: POSSL_TIME_SPEC); cdecl external CLibCrypto name 'OSSL_TIME_SPEC_free';
function d2i_OSSL_TIME_SPEC(a: PPOSSL_TIME_SPEC; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_SPEC; cdecl external CLibCrypto name 'd2i_OSSL_TIME_SPEC';
function i2d_OSSL_TIME_SPEC(a: POSSL_TIME_SPEC; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_TIME_SPEC';
function OSSL_TIME_SPEC_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_TIME_SPEC_it';
function OSSL_TIME_PERIOD_new: POSSL_TIME_PERIOD; cdecl external CLibCrypto name 'OSSL_TIME_PERIOD_new';
procedure OSSL_TIME_PERIOD_free(a: POSSL_TIME_PERIOD); cdecl external CLibCrypto name 'OSSL_TIME_PERIOD_free';
function d2i_OSSL_TIME_PERIOD(a: PPOSSL_TIME_PERIOD; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_PERIOD; cdecl external CLibCrypto name 'd2i_OSSL_TIME_PERIOD';
function i2d_OSSL_TIME_PERIOD(a: POSSL_TIME_PERIOD; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_TIME_PERIOD';
function OSSL_TIME_PERIOD_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_TIME_PERIOD_it';
function OSSL_ATAV_new: POSSL_ATAV; cdecl external CLibCrypto name 'OSSL_ATAV_new';
procedure OSSL_ATAV_free(a: POSSL_ATAV); cdecl external CLibCrypto name 'OSSL_ATAV_free';
function d2i_OSSL_ATAV(a: PPOSSL_ATAV; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ATAV; cdecl external CLibCrypto name 'd2i_OSSL_ATAV';
function i2d_OSSL_ATAV(a: POSSL_ATAV; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_ATAV';
function OSSL_ATAV_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_ATAV_it';
function OSSL_ATTRIBUTE_TYPE_MAPPING_new: POSSL_ATTRIBUTE_TYPE_MAPPING; cdecl external CLibCrypto name 'OSSL_ATTRIBUTE_TYPE_MAPPING_new';
procedure OSSL_ATTRIBUTE_TYPE_MAPPING_free(a: POSSL_ATTRIBUTE_TYPE_MAPPING); cdecl external CLibCrypto name 'OSSL_ATTRIBUTE_TYPE_MAPPING_free';
function d2i_OSSL_ATTRIBUTE_TYPE_MAPPING(a: PPOSSL_ATTRIBUTE_TYPE_MAPPING; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ATTRIBUTE_TYPE_MAPPING; cdecl external CLibCrypto name 'd2i_OSSL_ATTRIBUTE_TYPE_MAPPING';
function i2d_OSSL_ATTRIBUTE_TYPE_MAPPING(a: POSSL_ATTRIBUTE_TYPE_MAPPING; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_ATTRIBUTE_TYPE_MAPPING';
function OSSL_ATTRIBUTE_TYPE_MAPPING_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_ATTRIBUTE_TYPE_MAPPING_it';
function OSSL_ATTRIBUTE_VALUE_MAPPING_new: POSSL_ATTRIBUTE_VALUE_MAPPING; cdecl external CLibCrypto name 'OSSL_ATTRIBUTE_VALUE_MAPPING_new';
procedure OSSL_ATTRIBUTE_VALUE_MAPPING_free(a: POSSL_ATTRIBUTE_VALUE_MAPPING); cdecl external CLibCrypto name 'OSSL_ATTRIBUTE_VALUE_MAPPING_free';
function d2i_OSSL_ATTRIBUTE_VALUE_MAPPING(a: PPOSSL_ATTRIBUTE_VALUE_MAPPING; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ATTRIBUTE_VALUE_MAPPING; cdecl external CLibCrypto name 'd2i_OSSL_ATTRIBUTE_VALUE_MAPPING';
function i2d_OSSL_ATTRIBUTE_VALUE_MAPPING(a: POSSL_ATTRIBUTE_VALUE_MAPPING; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_ATTRIBUTE_VALUE_MAPPING';
function OSSL_ATTRIBUTE_VALUE_MAPPING_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_ATTRIBUTE_VALUE_MAPPING_it';
function OSSL_ATTRIBUTE_MAPPING_new: POSSL_ATTRIBUTE_MAPPING; cdecl external CLibCrypto name 'OSSL_ATTRIBUTE_MAPPING_new';
procedure OSSL_ATTRIBUTE_MAPPING_free(a: POSSL_ATTRIBUTE_MAPPING); cdecl external CLibCrypto name 'OSSL_ATTRIBUTE_MAPPING_free';
function d2i_OSSL_ATTRIBUTE_MAPPING(a: PPOSSL_ATTRIBUTE_MAPPING; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ATTRIBUTE_MAPPING; cdecl external CLibCrypto name 'd2i_OSSL_ATTRIBUTE_MAPPING';
function i2d_OSSL_ATTRIBUTE_MAPPING(a: POSSL_ATTRIBUTE_MAPPING; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_ATTRIBUTE_MAPPING';
function OSSL_ATTRIBUTE_MAPPING_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_ATTRIBUTE_MAPPING_it';
function OSSL_ATTRIBUTE_MAPPINGS_new: POSSL_ATTRIBUTE_MAPPINGS; cdecl external CLibCrypto name 'OSSL_ATTRIBUTE_MAPPINGS_new';
procedure OSSL_ATTRIBUTE_MAPPINGS_free(a: POSSL_ATTRIBUTE_MAPPINGS); cdecl external CLibCrypto name 'OSSL_ATTRIBUTE_MAPPINGS_free';
function d2i_OSSL_ATTRIBUTE_MAPPINGS(a: PPOSSL_ATTRIBUTE_MAPPINGS; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ATTRIBUTE_MAPPINGS; cdecl external CLibCrypto name 'd2i_OSSL_ATTRIBUTE_MAPPINGS';
function i2d_OSSL_ATTRIBUTE_MAPPINGS(a: POSSL_ATTRIBUTE_MAPPINGS; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_ATTRIBUTE_MAPPINGS';
function OSSL_ATTRIBUTE_MAPPINGS_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_ATTRIBUTE_MAPPINGS_it';
function OSSL_ALLOWED_ATTRIBUTES_CHOICE_new: POSSL_ALLOWED_ATTRIBUTES_CHOICE; cdecl external CLibCrypto name 'OSSL_ALLOWED_ATTRIBUTES_CHOICE_new';
procedure OSSL_ALLOWED_ATTRIBUTES_CHOICE_free(a: POSSL_ALLOWED_ATTRIBUTES_CHOICE); cdecl external CLibCrypto name 'OSSL_ALLOWED_ATTRIBUTES_CHOICE_free';
function d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE(a: PPOSSL_ALLOWED_ATTRIBUTES_CHOICE; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ALLOWED_ATTRIBUTES_CHOICE; cdecl external CLibCrypto name 'd2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE';
function i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE(a: POSSL_ALLOWED_ATTRIBUTES_CHOICE; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE';
function OSSL_ALLOWED_ATTRIBUTES_CHOICE_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_ALLOWED_ATTRIBUTES_CHOICE_it';
function OSSL_ALLOWED_ATTRIBUTES_ITEM_new: POSSL_ALLOWED_ATTRIBUTES_ITEM; cdecl external CLibCrypto name 'OSSL_ALLOWED_ATTRIBUTES_ITEM_new';
procedure OSSL_ALLOWED_ATTRIBUTES_ITEM_free(a: POSSL_ALLOWED_ATTRIBUTES_ITEM); cdecl external CLibCrypto name 'OSSL_ALLOWED_ATTRIBUTES_ITEM_free';
function d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM(a: PPOSSL_ALLOWED_ATTRIBUTES_ITEM; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ALLOWED_ATTRIBUTES_ITEM; cdecl external CLibCrypto name 'd2i_OSSL_ALLOWED_ATTRIBUTES_ITEM';
function i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM(a: POSSL_ALLOWED_ATTRIBUTES_ITEM; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM';
function OSSL_ALLOWED_ATTRIBUTES_ITEM_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_ALLOWED_ATTRIBUTES_ITEM_it';
function OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new: POSSL_ALLOWED_ATTRIBUTES_SYNTAX; cdecl external CLibCrypto name 'OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new';
procedure OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free(a: POSSL_ALLOWED_ATTRIBUTES_SYNTAX); cdecl external CLibCrypto name 'OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free';
function d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX(a: PPOSSL_ALLOWED_ATTRIBUTES_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ALLOWED_ATTRIBUTES_SYNTAX; cdecl external CLibCrypto name 'd2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX';
function i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX(a: POSSL_ALLOWED_ATTRIBUTES_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX';
function OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it';
function OSSL_AA_DIST_POINT_new: POSSL_AA_DIST_POINT; cdecl external CLibCrypto name 'OSSL_AA_DIST_POINT_new';
procedure OSSL_AA_DIST_POINT_free(a: POSSL_AA_DIST_POINT); cdecl external CLibCrypto name 'OSSL_AA_DIST_POINT_free';
function d2i_OSSL_AA_DIST_POINT(a: PPOSSL_AA_DIST_POINT; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_AA_DIST_POINT; cdecl external CLibCrypto name 'd2i_OSSL_AA_DIST_POINT';
function i2d_OSSL_AA_DIST_POINT(a: POSSL_AA_DIST_POINT; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_AA_DIST_POINT';
function OSSL_AA_DIST_POINT_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_AA_DIST_POINT_it';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  GENERAL_NAME_set1_X509_NAME_procname = 'GENERAL_NAME_set1_X509_NAME';
  GENERAL_NAME_set1_X509_NAME_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  DIST_POINT_NAME_dup_procname = 'DIST_POINT_NAME_dup';
  DIST_POINT_NAME_dup_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  PROXY_POLICY_new_procname = 'PROXY_POLICY_new';
  PROXY_POLICY_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PROXY_POLICY_free_procname = 'PROXY_POLICY_free';
  PROXY_POLICY_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PROXY_POLICY_procname = 'd2i_PROXY_POLICY';
  d2i_PROXY_POLICY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PROXY_POLICY_procname = 'i2d_PROXY_POLICY';
  i2d_PROXY_POLICY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PROXY_POLICY_it_procname = 'PROXY_POLICY_it';
  PROXY_POLICY_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PROXY_CERT_INFO_EXTENSION_new_procname = 'PROXY_CERT_INFO_EXTENSION_new';
  PROXY_CERT_INFO_EXTENSION_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PROXY_CERT_INFO_EXTENSION_free_procname = 'PROXY_CERT_INFO_EXTENSION_free';
  PROXY_CERT_INFO_EXTENSION_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PROXY_CERT_INFO_EXTENSION_procname = 'd2i_PROXY_CERT_INFO_EXTENSION';
  d2i_PROXY_CERT_INFO_EXTENSION_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PROXY_CERT_INFO_EXTENSION_procname = 'i2d_PROXY_CERT_INFO_EXTENSION';
  i2d_PROXY_CERT_INFO_EXTENSION_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PROXY_CERT_INFO_EXTENSION_it_procname = 'PROXY_CERT_INFO_EXTENSION_it';
  PROXY_CERT_INFO_EXTENSION_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BASIC_CONSTRAINTS_new_procname = 'BASIC_CONSTRAINTS_new';
  BASIC_CONSTRAINTS_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BASIC_CONSTRAINTS_free_procname = 'BASIC_CONSTRAINTS_free';
  BASIC_CONSTRAINTS_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_BASIC_CONSTRAINTS_procname = 'd2i_BASIC_CONSTRAINTS';
  d2i_BASIC_CONSTRAINTS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_BASIC_CONSTRAINTS_procname = 'i2d_BASIC_CONSTRAINTS';
  i2d_BASIC_CONSTRAINTS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BASIC_CONSTRAINTS_it_procname = 'BASIC_CONSTRAINTS_it';
  BASIC_CONSTRAINTS_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OSSL_BASIC_ATTR_CONSTRAINTS_new_procname = 'OSSL_BASIC_ATTR_CONSTRAINTS_new';
  OSSL_BASIC_ATTR_CONSTRAINTS_new_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_BASIC_ATTR_CONSTRAINTS_free_procname = 'OSSL_BASIC_ATTR_CONSTRAINTS_free';
  OSSL_BASIC_ATTR_CONSTRAINTS_free_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  d2i_OSSL_BASIC_ATTR_CONSTRAINTS_procname = 'd2i_OSSL_BASIC_ATTR_CONSTRAINTS';
  d2i_OSSL_BASIC_ATTR_CONSTRAINTS_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  i2d_OSSL_BASIC_ATTR_CONSTRAINTS_procname = 'i2d_OSSL_BASIC_ATTR_CONSTRAINTS';
  i2d_OSSL_BASIC_ATTR_CONSTRAINTS_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_BASIC_ATTR_CONSTRAINTS_it_procname = 'OSSL_BASIC_ATTR_CONSTRAINTS_it';
  OSSL_BASIC_ATTR_CONSTRAINTS_it_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  SXNET_new_procname = 'SXNET_new';
  SXNET_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SXNET_free_procname = 'SXNET_free';
  SXNET_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_SXNET_procname = 'd2i_SXNET';
  d2i_SXNET_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_SXNET_procname = 'i2d_SXNET';
  i2d_SXNET_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SXNET_it_procname = 'SXNET_it';
  SXNET_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SXNETID_new_procname = 'SXNETID_new';
  SXNETID_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SXNETID_free_procname = 'SXNETID_free';
  SXNETID_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_SXNETID_procname = 'd2i_SXNETID';
  d2i_SXNETID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_SXNETID_procname = 'i2d_SXNETID';
  i2d_SXNETID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SXNETID_it_procname = 'SXNETID_it';
  SXNETID_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ISSUER_SIGN_TOOL_new_procname = 'ISSUER_SIGN_TOOL_new';
  ISSUER_SIGN_TOOL_new_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ISSUER_SIGN_TOOL_free_procname = 'ISSUER_SIGN_TOOL_free';
  ISSUER_SIGN_TOOL_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_ISSUER_SIGN_TOOL_procname = 'd2i_ISSUER_SIGN_TOOL';
  d2i_ISSUER_SIGN_TOOL_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_ISSUER_SIGN_TOOL_procname = 'i2d_ISSUER_SIGN_TOOL';
  i2d_ISSUER_SIGN_TOOL_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ISSUER_SIGN_TOOL_it_procname = 'ISSUER_SIGN_TOOL_it';
  ISSUER_SIGN_TOOL_it_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SXNET_add_id_asc_procname = 'SXNET_add_id_asc';
  SXNET_add_id_asc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SXNET_add_id_ulong_procname = 'SXNET_add_id_ulong';
  SXNET_add_id_ulong_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SXNET_add_id_INTEGER_procname = 'SXNET_add_id_INTEGER';
  SXNET_add_id_INTEGER_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SXNET_get_id_asc_procname = 'SXNET_get_id_asc';
  SXNET_get_id_asc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SXNET_get_id_ulong_procname = 'SXNET_get_id_ulong';
  SXNET_get_id_ulong_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SXNET_get_id_INTEGER_procname = 'SXNET_get_id_INTEGER';
  SXNET_get_id_INTEGER_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  AUTHORITY_KEYID_new_procname = 'AUTHORITY_KEYID_new';
  AUTHORITY_KEYID_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  AUTHORITY_KEYID_free_procname = 'AUTHORITY_KEYID_free';
  AUTHORITY_KEYID_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_AUTHORITY_KEYID_procname = 'd2i_AUTHORITY_KEYID';
  d2i_AUTHORITY_KEYID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_AUTHORITY_KEYID_procname = 'i2d_AUTHORITY_KEYID';
  i2d_AUTHORITY_KEYID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  AUTHORITY_KEYID_it_procname = 'AUTHORITY_KEYID_it';
  AUTHORITY_KEYID_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKEY_USAGE_PERIOD_new_procname = 'PKEY_USAGE_PERIOD_new';
  PKEY_USAGE_PERIOD_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKEY_USAGE_PERIOD_free_procname = 'PKEY_USAGE_PERIOD_free';
  PKEY_USAGE_PERIOD_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PKEY_USAGE_PERIOD_procname = 'd2i_PKEY_USAGE_PERIOD';
  d2i_PKEY_USAGE_PERIOD_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKEY_USAGE_PERIOD_procname = 'i2d_PKEY_USAGE_PERIOD';
  i2d_PKEY_USAGE_PERIOD_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKEY_USAGE_PERIOD_it_procname = 'PKEY_USAGE_PERIOD_it';
  PKEY_USAGE_PERIOD_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  GENERAL_NAME_new_procname = 'GENERAL_NAME_new';
  GENERAL_NAME_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  GENERAL_NAME_free_procname = 'GENERAL_NAME_free';
  GENERAL_NAME_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_GENERAL_NAME_procname = 'd2i_GENERAL_NAME';
  d2i_GENERAL_NAME_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_GENERAL_NAME_procname = 'i2d_GENERAL_NAME';
  i2d_GENERAL_NAME_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  GENERAL_NAME_it_procname = 'GENERAL_NAME_it';
  GENERAL_NAME_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  GENERAL_NAME_dup_procname = 'GENERAL_NAME_dup';
  GENERAL_NAME_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  GENERAL_NAME_cmp_procname = 'GENERAL_NAME_cmp';
  GENERAL_NAME_cmp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  v2i_ASN1_BIT_STRING_procname = 'v2i_ASN1_BIT_STRING';
  v2i_ASN1_BIT_STRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2v_ASN1_BIT_STRING_procname = 'i2v_ASN1_BIT_STRING';
  i2v_ASN1_BIT_STRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2s_ASN1_IA5STRING_procname = 'i2s_ASN1_IA5STRING';
  i2s_ASN1_IA5STRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  s2i_ASN1_IA5STRING_procname = 's2i_ASN1_IA5STRING';
  s2i_ASN1_IA5STRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2s_ASN1_UTF8STRING_procname = 'i2s_ASN1_UTF8STRING';
  i2s_ASN1_UTF8STRING_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  s2i_ASN1_UTF8STRING_procname = 's2i_ASN1_UTF8STRING';
  s2i_ASN1_UTF8STRING_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2v_GENERAL_NAME_procname = 'i2v_GENERAL_NAME';
  i2v_GENERAL_NAME_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  GENERAL_NAME_print_procname = 'GENERAL_NAME_print';
  GENERAL_NAME_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  GENERAL_NAMES_new_procname = 'GENERAL_NAMES_new';
  GENERAL_NAMES_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  GENERAL_NAMES_free_procname = 'GENERAL_NAMES_free';
  GENERAL_NAMES_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_GENERAL_NAMES_procname = 'd2i_GENERAL_NAMES';
  d2i_GENERAL_NAMES_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_GENERAL_NAMES_procname = 'i2d_GENERAL_NAMES';
  i2d_GENERAL_NAMES_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  GENERAL_NAMES_it_procname = 'GENERAL_NAMES_it';
  GENERAL_NAMES_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2v_GENERAL_NAMES_procname = 'i2v_GENERAL_NAMES';
  i2v_GENERAL_NAMES_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  v2i_GENERAL_NAMES_procname = 'v2i_GENERAL_NAMES';
  v2i_GENERAL_NAMES_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OTHERNAME_new_procname = 'OTHERNAME_new';
  OTHERNAME_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OTHERNAME_free_procname = 'OTHERNAME_free';
  OTHERNAME_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_OTHERNAME_procname = 'd2i_OTHERNAME';
  d2i_OTHERNAME_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_OTHERNAME_procname = 'i2d_OTHERNAME';
  i2d_OTHERNAME_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OTHERNAME_it_procname = 'OTHERNAME_it';
  OTHERNAME_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EDIPARTYNAME_new_procname = 'EDIPARTYNAME_new';
  EDIPARTYNAME_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EDIPARTYNAME_free_procname = 'EDIPARTYNAME_free';
  EDIPARTYNAME_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_EDIPARTYNAME_procname = 'd2i_EDIPARTYNAME';
  d2i_EDIPARTYNAME_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_EDIPARTYNAME_procname = 'i2d_EDIPARTYNAME';
  i2d_EDIPARTYNAME_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EDIPARTYNAME_it_procname = 'EDIPARTYNAME_it';
  EDIPARTYNAME_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OTHERNAME_cmp_procname = 'OTHERNAME_cmp';
  OTHERNAME_cmp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  GENERAL_NAME_set0_value_procname = 'GENERAL_NAME_set0_value';
  GENERAL_NAME_set0_value_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  GENERAL_NAME_get0_value_procname = 'GENERAL_NAME_get0_value';
  GENERAL_NAME_get0_value_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  GENERAL_NAME_set0_othername_procname = 'GENERAL_NAME_set0_othername';
  GENERAL_NAME_set0_othername_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  GENERAL_NAME_get0_otherName_procname = 'GENERAL_NAME_get0_otherName';
  GENERAL_NAME_get0_otherName_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2s_ASN1_OCTET_STRING_procname = 'i2s_ASN1_OCTET_STRING';
  i2s_ASN1_OCTET_STRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  s2i_ASN1_OCTET_STRING_procname = 's2i_ASN1_OCTET_STRING';
  s2i_ASN1_OCTET_STRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EXTENDED_KEY_USAGE_new_procname = 'EXTENDED_KEY_USAGE_new';
  EXTENDED_KEY_USAGE_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EXTENDED_KEY_USAGE_free_procname = 'EXTENDED_KEY_USAGE_free';
  EXTENDED_KEY_USAGE_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_EXTENDED_KEY_USAGE_procname = 'd2i_EXTENDED_KEY_USAGE';
  d2i_EXTENDED_KEY_USAGE_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_EXTENDED_KEY_USAGE_procname = 'i2d_EXTENDED_KEY_USAGE';
  i2d_EXTENDED_KEY_USAGE_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EXTENDED_KEY_USAGE_it_procname = 'EXTENDED_KEY_USAGE_it';
  EXTENDED_KEY_USAGE_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2a_ACCESS_DESCRIPTION_procname = 'i2a_ACCESS_DESCRIPTION';
  i2a_ACCESS_DESCRIPTION_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TLS_FEATURE_new_procname = 'TLS_FEATURE_new';
  TLS_FEATURE_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TLS_FEATURE_free_procname = 'TLS_FEATURE_free';
  TLS_FEATURE_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CERTIFICATEPOLICIES_new_procname = 'CERTIFICATEPOLICIES_new';
  CERTIFICATEPOLICIES_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CERTIFICATEPOLICIES_free_procname = 'CERTIFICATEPOLICIES_free';
  CERTIFICATEPOLICIES_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_CERTIFICATEPOLICIES_procname = 'd2i_CERTIFICATEPOLICIES';
  d2i_CERTIFICATEPOLICIES_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_CERTIFICATEPOLICIES_procname = 'i2d_CERTIFICATEPOLICIES';
  i2d_CERTIFICATEPOLICIES_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CERTIFICATEPOLICIES_it_procname = 'CERTIFICATEPOLICIES_it';
  CERTIFICATEPOLICIES_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  POLICYINFO_new_procname = 'POLICYINFO_new';
  POLICYINFO_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  POLICYINFO_free_procname = 'POLICYINFO_free';
  POLICYINFO_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_POLICYINFO_procname = 'd2i_POLICYINFO';
  d2i_POLICYINFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_POLICYINFO_procname = 'i2d_POLICYINFO';
  i2d_POLICYINFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  POLICYINFO_it_procname = 'POLICYINFO_it';
  POLICYINFO_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  POLICYQUALINFO_new_procname = 'POLICYQUALINFO_new';
  POLICYQUALINFO_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  POLICYQUALINFO_free_procname = 'POLICYQUALINFO_free';
  POLICYQUALINFO_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_POLICYQUALINFO_procname = 'd2i_POLICYQUALINFO';
  d2i_POLICYQUALINFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_POLICYQUALINFO_procname = 'i2d_POLICYQUALINFO';
  i2d_POLICYQUALINFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  POLICYQUALINFO_it_procname = 'POLICYQUALINFO_it';
  POLICYQUALINFO_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  USERNOTICE_new_procname = 'USERNOTICE_new';
  USERNOTICE_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  USERNOTICE_free_procname = 'USERNOTICE_free';
  USERNOTICE_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_USERNOTICE_procname = 'd2i_USERNOTICE';
  d2i_USERNOTICE_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_USERNOTICE_procname = 'i2d_USERNOTICE';
  i2d_USERNOTICE_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  USERNOTICE_it_procname = 'USERNOTICE_it';
  USERNOTICE_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NOTICEREF_new_procname = 'NOTICEREF_new';
  NOTICEREF_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NOTICEREF_free_procname = 'NOTICEREF_free';
  NOTICEREF_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_NOTICEREF_procname = 'd2i_NOTICEREF';
  d2i_NOTICEREF_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_NOTICEREF_procname = 'i2d_NOTICEREF';
  i2d_NOTICEREF_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NOTICEREF_it_procname = 'NOTICEREF_it';
  NOTICEREF_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRL_DIST_POINTS_new_procname = 'CRL_DIST_POINTS_new';
  CRL_DIST_POINTS_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRL_DIST_POINTS_free_procname = 'CRL_DIST_POINTS_free';
  CRL_DIST_POINTS_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_CRL_DIST_POINTS_procname = 'd2i_CRL_DIST_POINTS';
  d2i_CRL_DIST_POINTS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_CRL_DIST_POINTS_procname = 'i2d_CRL_DIST_POINTS';
  i2d_CRL_DIST_POINTS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRL_DIST_POINTS_it_procname = 'CRL_DIST_POINTS_it';
  CRL_DIST_POINTS_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  DIST_POINT_new_procname = 'DIST_POINT_new';
  DIST_POINT_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  DIST_POINT_free_procname = 'DIST_POINT_free';
  DIST_POINT_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_DIST_POINT_procname = 'd2i_DIST_POINT';
  d2i_DIST_POINT_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_DIST_POINT_procname = 'i2d_DIST_POINT';
  i2d_DIST_POINT_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  DIST_POINT_it_procname = 'DIST_POINT_it';
  DIST_POINT_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  DIST_POINT_NAME_new_procname = 'DIST_POINT_NAME_new';
  DIST_POINT_NAME_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  DIST_POINT_NAME_free_procname = 'DIST_POINT_NAME_free';
  DIST_POINT_NAME_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_DIST_POINT_NAME_procname = 'd2i_DIST_POINT_NAME';
  d2i_DIST_POINT_NAME_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_DIST_POINT_NAME_procname = 'i2d_DIST_POINT_NAME';
  i2d_DIST_POINT_NAME_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  DIST_POINT_NAME_it_procname = 'DIST_POINT_NAME_it';
  DIST_POINT_NAME_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ISSUING_DIST_POINT_new_procname = 'ISSUING_DIST_POINT_new';
  ISSUING_DIST_POINT_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ISSUING_DIST_POINT_free_procname = 'ISSUING_DIST_POINT_free';
  ISSUING_DIST_POINT_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ISSUING_DIST_POINT_procname = 'd2i_ISSUING_DIST_POINT';
  d2i_ISSUING_DIST_POINT_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ISSUING_DIST_POINT_procname = 'i2d_ISSUING_DIST_POINT';
  i2d_ISSUING_DIST_POINT_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ISSUING_DIST_POINT_it_procname = 'ISSUING_DIST_POINT_it';
  ISSUING_DIST_POINT_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  DIST_POINT_set_dpname_procname = 'DIST_POINT_set_dpname';
  DIST_POINT_set_dpname_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NAME_CONSTRAINTS_check_procname = 'NAME_CONSTRAINTS_check';
  NAME_CONSTRAINTS_check_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NAME_CONSTRAINTS_check_CN_procname = 'NAME_CONSTRAINTS_check_CN';
  NAME_CONSTRAINTS_check_CN_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ACCESS_DESCRIPTION_new_procname = 'ACCESS_DESCRIPTION_new';
  ACCESS_DESCRIPTION_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ACCESS_DESCRIPTION_free_procname = 'ACCESS_DESCRIPTION_free';
  ACCESS_DESCRIPTION_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ACCESS_DESCRIPTION_procname = 'd2i_ACCESS_DESCRIPTION';
  d2i_ACCESS_DESCRIPTION_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ACCESS_DESCRIPTION_procname = 'i2d_ACCESS_DESCRIPTION';
  i2d_ACCESS_DESCRIPTION_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ACCESS_DESCRIPTION_it_procname = 'ACCESS_DESCRIPTION_it';
  ACCESS_DESCRIPTION_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  AUTHORITY_INFO_ACCESS_new_procname = 'AUTHORITY_INFO_ACCESS_new';
  AUTHORITY_INFO_ACCESS_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  AUTHORITY_INFO_ACCESS_free_procname = 'AUTHORITY_INFO_ACCESS_free';
  AUTHORITY_INFO_ACCESS_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_AUTHORITY_INFO_ACCESS_procname = 'd2i_AUTHORITY_INFO_ACCESS';
  d2i_AUTHORITY_INFO_ACCESS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_AUTHORITY_INFO_ACCESS_procname = 'i2d_AUTHORITY_INFO_ACCESS';
  i2d_AUTHORITY_INFO_ACCESS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  AUTHORITY_INFO_ACCESS_it_procname = 'AUTHORITY_INFO_ACCESS_it';
  AUTHORITY_INFO_ACCESS_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  POLICY_MAPPING_it_procname = 'POLICY_MAPPING_it';
  POLICY_MAPPING_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  POLICY_MAPPING_new_procname = 'POLICY_MAPPING_new';
  POLICY_MAPPING_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  POLICY_MAPPING_free_procname = 'POLICY_MAPPING_free';
  POLICY_MAPPING_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  POLICY_MAPPINGS_it_procname = 'POLICY_MAPPINGS_it';
  POLICY_MAPPINGS_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  GENERAL_SUBTREE_it_procname = 'GENERAL_SUBTREE_it';
  GENERAL_SUBTREE_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  GENERAL_SUBTREE_new_procname = 'GENERAL_SUBTREE_new';
  GENERAL_SUBTREE_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  GENERAL_SUBTREE_free_procname = 'GENERAL_SUBTREE_free';
  GENERAL_SUBTREE_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NAME_CONSTRAINTS_it_procname = 'NAME_CONSTRAINTS_it';
  NAME_CONSTRAINTS_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NAME_CONSTRAINTS_new_procname = 'NAME_CONSTRAINTS_new';
  NAME_CONSTRAINTS_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NAME_CONSTRAINTS_free_procname = 'NAME_CONSTRAINTS_free';
  NAME_CONSTRAINTS_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  POLICY_CONSTRAINTS_new_procname = 'POLICY_CONSTRAINTS_new';
  POLICY_CONSTRAINTS_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  POLICY_CONSTRAINTS_free_procname = 'POLICY_CONSTRAINTS_free';
  POLICY_CONSTRAINTS_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  POLICY_CONSTRAINTS_it_procname = 'POLICY_CONSTRAINTS_it';
  POLICY_CONSTRAINTS_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  a2i_GENERAL_NAME_procname = 'a2i_GENERAL_NAME';
  a2i_GENERAL_NAME_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  v2i_GENERAL_NAME_procname = 'v2i_GENERAL_NAME';
  v2i_GENERAL_NAME_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  v2i_GENERAL_NAME_ex_procname = 'v2i_GENERAL_NAME_ex';
  v2i_GENERAL_NAME_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_conf_free_procname = 'X509V3_conf_free';
  X509V3_conf_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_EXT_nconf_nid_procname = 'X509V3_EXT_nconf_nid';
  X509V3_EXT_nconf_nid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_EXT_nconf_procname = 'X509V3_EXT_nconf';
  X509V3_EXT_nconf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_EXT_add_nconf_sk_procname = 'X509V3_EXT_add_nconf_sk';
  X509V3_EXT_add_nconf_sk_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_EXT_add_nconf_procname = 'X509V3_EXT_add_nconf';
  X509V3_EXT_add_nconf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_EXT_REQ_add_nconf_procname = 'X509V3_EXT_REQ_add_nconf';
  X509V3_EXT_REQ_add_nconf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_EXT_CRL_add_nconf_procname = 'X509V3_EXT_CRL_add_nconf';
  X509V3_EXT_CRL_add_nconf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_EXT_conf_nid_procname = 'X509V3_EXT_conf_nid';
  X509V3_EXT_conf_nid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_EXT_conf_procname = 'X509V3_EXT_conf';
  X509V3_EXT_conf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_EXT_add_conf_procname = 'X509V3_EXT_add_conf';
  X509V3_EXT_add_conf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_EXT_REQ_add_conf_procname = 'X509V3_EXT_REQ_add_conf';
  X509V3_EXT_REQ_add_conf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_EXT_CRL_add_conf_procname = 'X509V3_EXT_CRL_add_conf';
  X509V3_EXT_CRL_add_conf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_add_value_bool_nf_procname = 'X509V3_add_value_bool_nf';
  X509V3_add_value_bool_nf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_get_value_bool_procname = 'X509V3_get_value_bool';
  X509V3_get_value_bool_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_get_value_int_procname = 'X509V3_get_value_int';
  X509V3_get_value_int_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_set_nconf_procname = 'X509V3_set_nconf';
  X509V3_set_nconf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_set_conf_lhash_procname = 'X509V3_set_conf_lhash';
  X509V3_set_conf_lhash_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_get_string_procname = 'X509V3_get_string';
  X509V3_get_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_get_section_procname = 'X509V3_get_section';
  X509V3_get_section_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_string_free_procname = 'X509V3_string_free';
  X509V3_string_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_section_free_procname = 'X509V3_section_free';
  X509V3_section_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_set_ctx_procname = 'X509V3_set_ctx';
  X509V3_set_ctx_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_set_issuer_pkey_procname = 'X509V3_set_issuer_pkey';
  X509V3_set_issuer_pkey_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509V3_add_value_procname = 'X509V3_add_value';
  X509V3_add_value_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_add_value_uchar_procname = 'X509V3_add_value_uchar';
  X509V3_add_value_uchar_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_add_value_bool_procname = 'X509V3_add_value_bool';
  X509V3_add_value_bool_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_add_value_int_procname = 'X509V3_add_value_int';
  X509V3_add_value_int_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2s_ASN1_INTEGER_procname = 'i2s_ASN1_INTEGER';
  i2s_ASN1_INTEGER_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  s2i_ASN1_INTEGER_procname = 's2i_ASN1_INTEGER';
  s2i_ASN1_INTEGER_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2s_ASN1_ENUMERATED_procname = 'i2s_ASN1_ENUMERATED';
  i2s_ASN1_ENUMERATED_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2s_ASN1_ENUMERATED_TABLE_procname = 'i2s_ASN1_ENUMERATED_TABLE';
  i2s_ASN1_ENUMERATED_TABLE_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_EXT_add_procname = 'X509V3_EXT_add';
  X509V3_EXT_add_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_EXT_add_list_procname = 'X509V3_EXT_add_list';
  X509V3_EXT_add_list_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_EXT_add_alias_procname = 'X509V3_EXT_add_alias';
  X509V3_EXT_add_alias_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_EXT_cleanup_procname = 'X509V3_EXT_cleanup';
  X509V3_EXT_cleanup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_EXT_get_procname = 'X509V3_EXT_get';
  X509V3_EXT_get_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_EXT_get_nid_procname = 'X509V3_EXT_get_nid';
  X509V3_EXT_get_nid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_add_standard_extensions_procname = 'X509V3_add_standard_extensions';
  X509V3_add_standard_extensions_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_parse_list_procname = 'X509V3_parse_list';
  X509V3_parse_list_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_EXT_d2i_procname = 'X509V3_EXT_d2i';
  X509V3_EXT_d2i_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_get_d2i_procname = 'X509V3_get_d2i';
  X509V3_get_d2i_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_EXT_i2d_procname = 'X509V3_EXT_i2d';
  X509V3_EXT_i2d_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_add1_i2d_procname = 'X509V3_add1_i2d';
  X509V3_add1_i2d_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_EXT_val_prn_procname = 'X509V3_EXT_val_prn';
  X509V3_EXT_val_prn_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_EXT_print_procname = 'X509V3_EXT_print';
  X509V3_EXT_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_EXT_print_fp_procname = 'X509V3_EXT_print_fp';
  X509V3_EXT_print_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_extensions_print_procname = 'X509V3_extensions_print';
  X509V3_extensions_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_check_ca_procname = 'X509_check_ca';
  X509_check_ca_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_check_purpose_procname = 'X509_check_purpose';
  X509_check_purpose_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_supported_extension_procname = 'X509_supported_extension';
  X509_supported_extension_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_check_issued_procname = 'X509_check_issued';
  X509_check_issued_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_check_akid_procname = 'X509_check_akid';
  X509_check_akid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_set_proxy_flag_procname = 'X509_set_proxy_flag';
  X509_set_proxy_flag_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_set_proxy_pathlen_procname = 'X509_set_proxy_pathlen';
  X509_set_proxy_pathlen_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get_proxy_pathlen_procname = 'X509_get_proxy_pathlen';
  X509_get_proxy_pathlen_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get_extension_flags_procname = 'X509_get_extension_flags';
  X509_get_extension_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get_key_usage_procname = 'X509_get_key_usage';
  X509_get_key_usage_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get_extended_key_usage_procname = 'X509_get_extended_key_usage';
  X509_get_extended_key_usage_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get0_subject_key_id_procname = 'X509_get0_subject_key_id';
  X509_get0_subject_key_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get0_authority_key_id_procname = 'X509_get0_authority_key_id';
  X509_get0_authority_key_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0h);

  X509_get0_authority_issuer_procname = 'X509_get0_authority_issuer';
  X509_get0_authority_issuer_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1d);

  X509_get0_authority_serial_procname = 'X509_get0_authority_serial';
  X509_get0_authority_serial_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1d);

  X509_PURPOSE_get_count_procname = 'X509_PURPOSE_get_count';
  X509_PURPOSE_get_count_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_PURPOSE_get_unused_id_procname = 'X509_PURPOSE_get_unused_id';
  X509_PURPOSE_get_unused_id_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  X509_PURPOSE_get_by_sname_procname = 'X509_PURPOSE_get_by_sname';
  X509_PURPOSE_get_by_sname_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_PURPOSE_get_by_id_procname = 'X509_PURPOSE_get_by_id';
  X509_PURPOSE_get_by_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_PURPOSE_add_procname = 'X509_PURPOSE_add';
  X509_PURPOSE_add_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_PURPOSE_cleanup_procname = 'X509_PURPOSE_cleanup';
  X509_PURPOSE_cleanup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_PURPOSE_get0_procname = 'X509_PURPOSE_get0';
  X509_PURPOSE_get0_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_PURPOSE_get_id_procname = 'X509_PURPOSE_get_id';
  X509_PURPOSE_get_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_PURPOSE_get0_name_procname = 'X509_PURPOSE_get0_name';
  X509_PURPOSE_get0_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_PURPOSE_get0_sname_procname = 'X509_PURPOSE_get0_sname';
  X509_PURPOSE_get0_sname_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_PURPOSE_get_trust_procname = 'X509_PURPOSE_get_trust';
  X509_PURPOSE_get_trust_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_PURPOSE_set_procname = 'X509_PURPOSE_set';
  X509_PURPOSE_set_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get1_email_procname = 'X509_get1_email';
  X509_get1_email_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_get1_email_procname = 'X509_REQ_get1_email';
  X509_REQ_get1_email_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_email_free_procname = 'X509_email_free';
  X509_email_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get1_ocsp_procname = 'X509_get1_ocsp';
  X509_get1_ocsp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_check_host_procname = 'X509_check_host';
  X509_check_host_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_check_email_procname = 'X509_check_email';
  X509_check_email_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_check_ip_procname = 'X509_check_ip';
  X509_check_ip_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_check_ip_asc_procname = 'X509_check_ip_asc';
  X509_check_ip_asc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  a2i_IPADDRESS_procname = 'a2i_IPADDRESS';
  a2i_IPADDRESS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  a2i_IPADDRESS_NC_procname = 'a2i_IPADDRESS_NC';
  a2i_IPADDRESS_NC_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509V3_NAME_from_section_procname = 'X509V3_NAME_from_section';
  X509V3_NAME_from_section_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_POLICY_NODE_print_procname = 'X509_POLICY_NODE_print';
  X509_POLICY_NODE_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASRange_new_procname = 'ASRange_new';
  ASRange_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASRange_free_procname = 'ASRange_free';
  ASRange_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ASRange_procname = 'd2i_ASRange';
  d2i_ASRange_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ASRange_procname = 'i2d_ASRange';
  i2d_ASRange_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASRange_it_procname = 'ASRange_it';
  ASRange_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASIdOrRange_new_procname = 'ASIdOrRange_new';
  ASIdOrRange_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASIdOrRange_free_procname = 'ASIdOrRange_free';
  ASIdOrRange_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ASIdOrRange_procname = 'd2i_ASIdOrRange';
  d2i_ASIdOrRange_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ASIdOrRange_procname = 'i2d_ASIdOrRange';
  i2d_ASIdOrRange_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASIdOrRange_it_procname = 'ASIdOrRange_it';
  ASIdOrRange_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASIdentifierChoice_new_procname = 'ASIdentifierChoice_new';
  ASIdentifierChoice_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASIdentifierChoice_free_procname = 'ASIdentifierChoice_free';
  ASIdentifierChoice_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ASIdentifierChoice_procname = 'd2i_ASIdentifierChoice';
  d2i_ASIdentifierChoice_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ASIdentifierChoice_procname = 'i2d_ASIdentifierChoice';
  i2d_ASIdentifierChoice_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASIdentifierChoice_it_procname = 'ASIdentifierChoice_it';
  ASIdentifierChoice_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASIdentifiers_new_procname = 'ASIdentifiers_new';
  ASIdentifiers_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASIdentifiers_free_procname = 'ASIdentifiers_free';
  ASIdentifiers_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ASIdentifiers_procname = 'd2i_ASIdentifiers';
  d2i_ASIdentifiers_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ASIdentifiers_procname = 'i2d_ASIdentifiers';
  i2d_ASIdentifiers_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASIdentifiers_it_procname = 'ASIdentifiers_it';
  ASIdentifiers_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  IPAddressRange_new_procname = 'IPAddressRange_new';
  IPAddressRange_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  IPAddressRange_free_procname = 'IPAddressRange_free';
  IPAddressRange_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_IPAddressRange_procname = 'd2i_IPAddressRange';
  d2i_IPAddressRange_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_IPAddressRange_procname = 'i2d_IPAddressRange';
  i2d_IPAddressRange_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  IPAddressRange_it_procname = 'IPAddressRange_it';
  IPAddressRange_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  IPAddressOrRange_new_procname = 'IPAddressOrRange_new';
  IPAddressOrRange_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  IPAddressOrRange_free_procname = 'IPAddressOrRange_free';
  IPAddressOrRange_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_IPAddressOrRange_procname = 'd2i_IPAddressOrRange';
  d2i_IPAddressOrRange_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_IPAddressOrRange_procname = 'i2d_IPAddressOrRange';
  i2d_IPAddressOrRange_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  IPAddressOrRange_it_procname = 'IPAddressOrRange_it';
  IPAddressOrRange_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  IPAddressChoice_new_procname = 'IPAddressChoice_new';
  IPAddressChoice_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  IPAddressChoice_free_procname = 'IPAddressChoice_free';
  IPAddressChoice_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_IPAddressChoice_procname = 'd2i_IPAddressChoice';
  d2i_IPAddressChoice_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_IPAddressChoice_procname = 'i2d_IPAddressChoice';
  i2d_IPAddressChoice_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  IPAddressChoice_it_procname = 'IPAddressChoice_it';
  IPAddressChoice_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  IPAddressFamily_new_procname = 'IPAddressFamily_new';
  IPAddressFamily_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  IPAddressFamily_free_procname = 'IPAddressFamily_free';
  IPAddressFamily_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_IPAddressFamily_procname = 'd2i_IPAddressFamily';
  d2i_IPAddressFamily_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_IPAddressFamily_procname = 'i2d_IPAddressFamily';
  i2d_IPAddressFamily_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  IPAddressFamily_it_procname = 'IPAddressFamily_it';
  IPAddressFamily_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509v3_asid_add_inherit_procname = 'X509v3_asid_add_inherit';
  X509v3_asid_add_inherit_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509v3_asid_add_id_or_range_procname = 'X509v3_asid_add_id_or_range';
  X509v3_asid_add_id_or_range_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509v3_addr_add_inherit_procname = 'X509v3_addr_add_inherit';
  X509v3_addr_add_inherit_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509v3_addr_add_prefix_procname = 'X509v3_addr_add_prefix';
  X509v3_addr_add_prefix_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509v3_addr_add_range_procname = 'X509v3_addr_add_range';
  X509v3_addr_add_range_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509v3_addr_get_afi_procname = 'X509v3_addr_get_afi';
  X509v3_addr_get_afi_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509v3_addr_get_range_procname = 'X509v3_addr_get_range';
  X509v3_addr_get_range_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509v3_asid_is_canonical_procname = 'X509v3_asid_is_canonical';
  X509v3_asid_is_canonical_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509v3_addr_is_canonical_procname = 'X509v3_addr_is_canonical';
  X509v3_addr_is_canonical_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509v3_asid_canonize_procname = 'X509v3_asid_canonize';
  X509v3_asid_canonize_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509v3_addr_canonize_procname = 'X509v3_addr_canonize';
  X509v3_addr_canonize_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509v3_asid_inherits_procname = 'X509v3_asid_inherits';
  X509v3_asid_inherits_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509v3_addr_inherits_procname = 'X509v3_addr_inherits';
  X509v3_addr_inherits_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509v3_asid_subset_procname = 'X509v3_asid_subset';
  X509v3_asid_subset_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509v3_addr_subset_procname = 'X509v3_addr_subset';
  X509v3_addr_subset_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509v3_asid_validate_path_procname = 'X509v3_asid_validate_path';
  X509v3_asid_validate_path_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509v3_addr_validate_path_procname = 'X509v3_addr_validate_path';
  X509v3_addr_validate_path_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509v3_asid_validate_resource_set_procname = 'X509v3_asid_validate_resource_set';
  X509v3_asid_validate_resource_set_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509v3_addr_validate_resource_set_procname = 'X509v3_addr_validate_resource_set';
  X509v3_addr_validate_resource_set_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NAMING_AUTHORITY_new_procname = 'NAMING_AUTHORITY_new';
  NAMING_AUTHORITY_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  NAMING_AUTHORITY_free_procname = 'NAMING_AUTHORITY_free';
  NAMING_AUTHORITY_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  d2i_NAMING_AUTHORITY_procname = 'd2i_NAMING_AUTHORITY';
  d2i_NAMING_AUTHORITY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  i2d_NAMING_AUTHORITY_procname = 'i2d_NAMING_AUTHORITY';
  i2d_NAMING_AUTHORITY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  NAMING_AUTHORITY_it_procname = 'NAMING_AUTHORITY_it';
  NAMING_AUTHORITY_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  PROFESSION_INFO_new_procname = 'PROFESSION_INFO_new';
  PROFESSION_INFO_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  PROFESSION_INFO_free_procname = 'PROFESSION_INFO_free';
  PROFESSION_INFO_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  d2i_PROFESSION_INFO_procname = 'd2i_PROFESSION_INFO';
  d2i_PROFESSION_INFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  i2d_PROFESSION_INFO_procname = 'i2d_PROFESSION_INFO';
  i2d_PROFESSION_INFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  PROFESSION_INFO_it_procname = 'PROFESSION_INFO_it';
  PROFESSION_INFO_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ADMISSIONS_new_procname = 'ADMISSIONS_new';
  ADMISSIONS_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ADMISSIONS_free_procname = 'ADMISSIONS_free';
  ADMISSIONS_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  d2i_ADMISSIONS_procname = 'd2i_ADMISSIONS';
  d2i_ADMISSIONS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  i2d_ADMISSIONS_procname = 'i2d_ADMISSIONS';
  i2d_ADMISSIONS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ADMISSIONS_it_procname = 'ADMISSIONS_it';
  ADMISSIONS_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ADMISSION_SYNTAX_new_procname = 'ADMISSION_SYNTAX_new';
  ADMISSION_SYNTAX_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ADMISSION_SYNTAX_free_procname = 'ADMISSION_SYNTAX_free';
  ADMISSION_SYNTAX_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  d2i_ADMISSION_SYNTAX_procname = 'd2i_ADMISSION_SYNTAX';
  d2i_ADMISSION_SYNTAX_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  i2d_ADMISSION_SYNTAX_procname = 'i2d_ADMISSION_SYNTAX';
  i2d_ADMISSION_SYNTAX_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ADMISSION_SYNTAX_it_procname = 'ADMISSION_SYNTAX_it';
  ADMISSION_SYNTAX_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  NAMING_AUTHORITY_get0_authorityId_procname = 'NAMING_AUTHORITY_get0_authorityId';
  NAMING_AUTHORITY_get0_authorityId_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  NAMING_AUTHORITY_get0_authorityURL_procname = 'NAMING_AUTHORITY_get0_authorityURL';
  NAMING_AUTHORITY_get0_authorityURL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  NAMING_AUTHORITY_get0_authorityText_procname = 'NAMING_AUTHORITY_get0_authorityText';
  NAMING_AUTHORITY_get0_authorityText_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  NAMING_AUTHORITY_set0_authorityId_procname = 'NAMING_AUTHORITY_set0_authorityId';
  NAMING_AUTHORITY_set0_authorityId_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  NAMING_AUTHORITY_set0_authorityURL_procname = 'NAMING_AUTHORITY_set0_authorityURL';
  NAMING_AUTHORITY_set0_authorityURL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  NAMING_AUTHORITY_set0_authorityText_procname = 'NAMING_AUTHORITY_set0_authorityText';
  NAMING_AUTHORITY_set0_authorityText_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ADMISSION_SYNTAX_get0_admissionAuthority_procname = 'ADMISSION_SYNTAX_get0_admissionAuthority';
  ADMISSION_SYNTAX_get0_admissionAuthority_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ADMISSION_SYNTAX_set0_admissionAuthority_procname = 'ADMISSION_SYNTAX_set0_admissionAuthority';
  ADMISSION_SYNTAX_set0_admissionAuthority_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ADMISSION_SYNTAX_get0_contentsOfAdmissions_procname = 'ADMISSION_SYNTAX_get0_contentsOfAdmissions';
  ADMISSION_SYNTAX_get0_contentsOfAdmissions_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ADMISSION_SYNTAX_set0_contentsOfAdmissions_procname = 'ADMISSION_SYNTAX_set0_contentsOfAdmissions';
  ADMISSION_SYNTAX_set0_contentsOfAdmissions_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ADMISSIONS_get0_admissionAuthority_procname = 'ADMISSIONS_get0_admissionAuthority';
  ADMISSIONS_get0_admissionAuthority_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ADMISSIONS_set0_admissionAuthority_procname = 'ADMISSIONS_set0_admissionAuthority';
  ADMISSIONS_set0_admissionAuthority_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ADMISSIONS_get0_namingAuthority_procname = 'ADMISSIONS_get0_namingAuthority';
  ADMISSIONS_get0_namingAuthority_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ADMISSIONS_set0_namingAuthority_procname = 'ADMISSIONS_set0_namingAuthority';
  ADMISSIONS_set0_namingAuthority_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ADMISSIONS_get0_professionInfos_procname = 'ADMISSIONS_get0_professionInfos';
  ADMISSIONS_get0_professionInfos_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ADMISSIONS_set0_professionInfos_procname = 'ADMISSIONS_set0_professionInfos';
  ADMISSIONS_set0_professionInfos_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  PROFESSION_INFO_get0_addProfessionInfo_procname = 'PROFESSION_INFO_get0_addProfessionInfo';
  PROFESSION_INFO_get0_addProfessionInfo_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  PROFESSION_INFO_set0_addProfessionInfo_procname = 'PROFESSION_INFO_set0_addProfessionInfo';
  PROFESSION_INFO_set0_addProfessionInfo_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  PROFESSION_INFO_get0_namingAuthority_procname = 'PROFESSION_INFO_get0_namingAuthority';
  PROFESSION_INFO_get0_namingAuthority_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  PROFESSION_INFO_set0_namingAuthority_procname = 'PROFESSION_INFO_set0_namingAuthority';
  PROFESSION_INFO_set0_namingAuthority_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  PROFESSION_INFO_get0_professionItems_procname = 'PROFESSION_INFO_get0_professionItems';
  PROFESSION_INFO_get0_professionItems_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  PROFESSION_INFO_set0_professionItems_procname = 'PROFESSION_INFO_set0_professionItems';
  PROFESSION_INFO_set0_professionItems_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  PROFESSION_INFO_get0_professionOIDs_procname = 'PROFESSION_INFO_get0_professionOIDs';
  PROFESSION_INFO_get0_professionOIDs_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  PROFESSION_INFO_set0_professionOIDs_procname = 'PROFESSION_INFO_set0_professionOIDs';
  PROFESSION_INFO_set0_professionOIDs_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  PROFESSION_INFO_get0_registrationNumber_procname = 'PROFESSION_INFO_get0_registrationNumber';
  PROFESSION_INFO_get0_registrationNumber_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  PROFESSION_INFO_set0_registrationNumber_procname = 'PROFESSION_INFO_set0_registrationNumber';
  PROFESSION_INFO_set0_registrationNumber_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_GENERAL_NAMES_print_procname = 'OSSL_GENERAL_NAMES_print';
  OSSL_GENERAL_NAMES_print_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_ATTRIBUTES_SYNTAX_new_procname = 'OSSL_ATTRIBUTES_SYNTAX_new';
  OSSL_ATTRIBUTES_SYNTAX_new_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_ATTRIBUTES_SYNTAX_free_procname = 'OSSL_ATTRIBUTES_SYNTAX_free';
  OSSL_ATTRIBUTES_SYNTAX_free_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  d2i_OSSL_ATTRIBUTES_SYNTAX_procname = 'd2i_OSSL_ATTRIBUTES_SYNTAX';
  d2i_OSSL_ATTRIBUTES_SYNTAX_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  i2d_OSSL_ATTRIBUTES_SYNTAX_procname = 'i2d_OSSL_ATTRIBUTES_SYNTAX';
  i2d_OSSL_ATTRIBUTES_SYNTAX_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_ATTRIBUTES_SYNTAX_it_procname = 'OSSL_ATTRIBUTES_SYNTAX_it';
  OSSL_ATTRIBUTES_SYNTAX_it_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_USER_NOTICE_SYNTAX_new_procname = 'OSSL_USER_NOTICE_SYNTAX_new';
  OSSL_USER_NOTICE_SYNTAX_new_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_USER_NOTICE_SYNTAX_free_procname = 'OSSL_USER_NOTICE_SYNTAX_free';
  OSSL_USER_NOTICE_SYNTAX_free_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  d2i_OSSL_USER_NOTICE_SYNTAX_procname = 'd2i_OSSL_USER_NOTICE_SYNTAX';
  d2i_OSSL_USER_NOTICE_SYNTAX_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  i2d_OSSL_USER_NOTICE_SYNTAX_procname = 'i2d_OSSL_USER_NOTICE_SYNTAX';
  i2d_OSSL_USER_NOTICE_SYNTAX_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_USER_NOTICE_SYNTAX_it_procname = 'OSSL_USER_NOTICE_SYNTAX_it';
  OSSL_USER_NOTICE_SYNTAX_it_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_ROLE_SPEC_CERT_ID_new_procname = 'OSSL_ROLE_SPEC_CERT_ID_new';
  OSSL_ROLE_SPEC_CERT_ID_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ROLE_SPEC_CERT_ID_free_procname = 'OSSL_ROLE_SPEC_CERT_ID_free';
  OSSL_ROLE_SPEC_CERT_ID_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_ROLE_SPEC_CERT_ID_procname = 'd2i_OSSL_ROLE_SPEC_CERT_ID';
  d2i_OSSL_ROLE_SPEC_CERT_ID_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_ROLE_SPEC_CERT_ID_procname = 'i2d_OSSL_ROLE_SPEC_CERT_ID';
  i2d_OSSL_ROLE_SPEC_CERT_ID_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ROLE_SPEC_CERT_ID_it_procname = 'OSSL_ROLE_SPEC_CERT_ID_it';
  OSSL_ROLE_SPEC_CERT_ID_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new_procname = 'OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new';
  OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free_procname = 'OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free';
  OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_procname = 'd2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX';
  d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_procname = 'i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX';
  i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it_procname = 'OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it';
  OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_HASH_new_procname = 'OSSL_HASH_new';
  OSSL_HASH_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_HASH_free_procname = 'OSSL_HASH_free';
  OSSL_HASH_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_HASH_procname = 'd2i_OSSL_HASH';
  d2i_OSSL_HASH_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_HASH_procname = 'i2d_OSSL_HASH';
  i2d_OSSL_HASH_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_HASH_it_procname = 'OSSL_HASH_it';
  OSSL_HASH_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_INFO_SYNTAX_new_procname = 'OSSL_INFO_SYNTAX_new';
  OSSL_INFO_SYNTAX_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_INFO_SYNTAX_free_procname = 'OSSL_INFO_SYNTAX_free';
  OSSL_INFO_SYNTAX_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_INFO_SYNTAX_procname = 'd2i_OSSL_INFO_SYNTAX';
  d2i_OSSL_INFO_SYNTAX_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_INFO_SYNTAX_procname = 'i2d_OSSL_INFO_SYNTAX';
  i2d_OSSL_INFO_SYNTAX_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_INFO_SYNTAX_it_procname = 'OSSL_INFO_SYNTAX_it';
  OSSL_INFO_SYNTAX_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_INFO_SYNTAX_POINTER_new_procname = 'OSSL_INFO_SYNTAX_POINTER_new';
  OSSL_INFO_SYNTAX_POINTER_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_INFO_SYNTAX_POINTER_free_procname = 'OSSL_INFO_SYNTAX_POINTER_free';
  OSSL_INFO_SYNTAX_POINTER_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_INFO_SYNTAX_POINTER_procname = 'd2i_OSSL_INFO_SYNTAX_POINTER';
  d2i_OSSL_INFO_SYNTAX_POINTER_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_INFO_SYNTAX_POINTER_procname = 'i2d_OSSL_INFO_SYNTAX_POINTER';
  i2d_OSSL_INFO_SYNTAX_POINTER_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_INFO_SYNTAX_POINTER_it_procname = 'OSSL_INFO_SYNTAX_POINTER_it';
  OSSL_INFO_SYNTAX_POINTER_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_PRIVILEGE_POLICY_ID_new_procname = 'OSSL_PRIVILEGE_POLICY_ID_new';
  OSSL_PRIVILEGE_POLICY_ID_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_PRIVILEGE_POLICY_ID_free_procname = 'OSSL_PRIVILEGE_POLICY_ID_free';
  OSSL_PRIVILEGE_POLICY_ID_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_PRIVILEGE_POLICY_ID_procname = 'd2i_OSSL_PRIVILEGE_POLICY_ID';
  d2i_OSSL_PRIVILEGE_POLICY_ID_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_PRIVILEGE_POLICY_ID_procname = 'i2d_OSSL_PRIVILEGE_POLICY_ID';
  i2d_OSSL_PRIVILEGE_POLICY_ID_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_PRIVILEGE_POLICY_ID_it_procname = 'OSSL_PRIVILEGE_POLICY_ID_it';
  OSSL_PRIVILEGE_POLICY_ID_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ATTRIBUTE_DESCRIPTOR_new_procname = 'OSSL_ATTRIBUTE_DESCRIPTOR_new';
  OSSL_ATTRIBUTE_DESCRIPTOR_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ATTRIBUTE_DESCRIPTOR_free_procname = 'OSSL_ATTRIBUTE_DESCRIPTOR_free';
  OSSL_ATTRIBUTE_DESCRIPTOR_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_ATTRIBUTE_DESCRIPTOR_procname = 'd2i_OSSL_ATTRIBUTE_DESCRIPTOR';
  d2i_OSSL_ATTRIBUTE_DESCRIPTOR_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_ATTRIBUTE_DESCRIPTOR_procname = 'i2d_OSSL_ATTRIBUTE_DESCRIPTOR';
  i2d_OSSL_ATTRIBUTE_DESCRIPTOR_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ATTRIBUTE_DESCRIPTOR_it_procname = 'OSSL_ATTRIBUTE_DESCRIPTOR_it';
  OSSL_ATTRIBUTE_DESCRIPTOR_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_DAY_TIME_new_procname = 'OSSL_DAY_TIME_new';
  OSSL_DAY_TIME_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_DAY_TIME_free_procname = 'OSSL_DAY_TIME_free';
  OSSL_DAY_TIME_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_DAY_TIME_procname = 'd2i_OSSL_DAY_TIME';
  d2i_OSSL_DAY_TIME_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_DAY_TIME_procname = 'i2d_OSSL_DAY_TIME';
  i2d_OSSL_DAY_TIME_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_DAY_TIME_it_procname = 'OSSL_DAY_TIME_it';
  OSSL_DAY_TIME_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_DAY_TIME_BAND_new_procname = 'OSSL_DAY_TIME_BAND_new';
  OSSL_DAY_TIME_BAND_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_DAY_TIME_BAND_free_procname = 'OSSL_DAY_TIME_BAND_free';
  OSSL_DAY_TIME_BAND_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_DAY_TIME_BAND_procname = 'd2i_OSSL_DAY_TIME_BAND';
  d2i_OSSL_DAY_TIME_BAND_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_DAY_TIME_BAND_procname = 'i2d_OSSL_DAY_TIME_BAND';
  i2d_OSSL_DAY_TIME_BAND_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_DAY_TIME_BAND_it_procname = 'OSSL_DAY_TIME_BAND_it';
  OSSL_DAY_TIME_BAND_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_TIME_SPEC_DAY_new_procname = 'OSSL_TIME_SPEC_DAY_new';
  OSSL_TIME_SPEC_DAY_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_TIME_SPEC_DAY_free_procname = 'OSSL_TIME_SPEC_DAY_free';
  OSSL_TIME_SPEC_DAY_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_TIME_SPEC_DAY_procname = 'd2i_OSSL_TIME_SPEC_DAY';
  d2i_OSSL_TIME_SPEC_DAY_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_TIME_SPEC_DAY_procname = 'i2d_OSSL_TIME_SPEC_DAY';
  i2d_OSSL_TIME_SPEC_DAY_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_TIME_SPEC_DAY_it_procname = 'OSSL_TIME_SPEC_DAY_it';
  OSSL_TIME_SPEC_DAY_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_TIME_SPEC_WEEKS_new_procname = 'OSSL_TIME_SPEC_WEEKS_new';
  OSSL_TIME_SPEC_WEEKS_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_TIME_SPEC_WEEKS_free_procname = 'OSSL_TIME_SPEC_WEEKS_free';
  OSSL_TIME_SPEC_WEEKS_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_TIME_SPEC_WEEKS_procname = 'd2i_OSSL_TIME_SPEC_WEEKS';
  d2i_OSSL_TIME_SPEC_WEEKS_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_TIME_SPEC_WEEKS_procname = 'i2d_OSSL_TIME_SPEC_WEEKS';
  i2d_OSSL_TIME_SPEC_WEEKS_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_TIME_SPEC_WEEKS_it_procname = 'OSSL_TIME_SPEC_WEEKS_it';
  OSSL_TIME_SPEC_WEEKS_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_TIME_SPEC_MONTH_new_procname = 'OSSL_TIME_SPEC_MONTH_new';
  OSSL_TIME_SPEC_MONTH_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_TIME_SPEC_MONTH_free_procname = 'OSSL_TIME_SPEC_MONTH_free';
  OSSL_TIME_SPEC_MONTH_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_TIME_SPEC_MONTH_procname = 'd2i_OSSL_TIME_SPEC_MONTH';
  d2i_OSSL_TIME_SPEC_MONTH_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_TIME_SPEC_MONTH_procname = 'i2d_OSSL_TIME_SPEC_MONTH';
  i2d_OSSL_TIME_SPEC_MONTH_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_TIME_SPEC_MONTH_it_procname = 'OSSL_TIME_SPEC_MONTH_it';
  OSSL_TIME_SPEC_MONTH_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_NAMED_DAY_new_procname = 'OSSL_NAMED_DAY_new';
  OSSL_NAMED_DAY_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_NAMED_DAY_free_procname = 'OSSL_NAMED_DAY_free';
  OSSL_NAMED_DAY_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_NAMED_DAY_procname = 'd2i_OSSL_NAMED_DAY';
  d2i_OSSL_NAMED_DAY_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_NAMED_DAY_procname = 'i2d_OSSL_NAMED_DAY';
  i2d_OSSL_NAMED_DAY_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_NAMED_DAY_it_procname = 'OSSL_NAMED_DAY_it';
  OSSL_NAMED_DAY_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_TIME_SPEC_X_DAY_OF_new_procname = 'OSSL_TIME_SPEC_X_DAY_OF_new';
  OSSL_TIME_SPEC_X_DAY_OF_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_TIME_SPEC_X_DAY_OF_free_procname = 'OSSL_TIME_SPEC_X_DAY_OF_free';
  OSSL_TIME_SPEC_X_DAY_OF_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_TIME_SPEC_X_DAY_OF_procname = 'd2i_OSSL_TIME_SPEC_X_DAY_OF';
  d2i_OSSL_TIME_SPEC_X_DAY_OF_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_TIME_SPEC_X_DAY_OF_procname = 'i2d_OSSL_TIME_SPEC_X_DAY_OF';
  i2d_OSSL_TIME_SPEC_X_DAY_OF_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_TIME_SPEC_X_DAY_OF_it_procname = 'OSSL_TIME_SPEC_X_DAY_OF_it';
  OSSL_TIME_SPEC_X_DAY_OF_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_TIME_SPEC_ABSOLUTE_new_procname = 'OSSL_TIME_SPEC_ABSOLUTE_new';
  OSSL_TIME_SPEC_ABSOLUTE_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_TIME_SPEC_ABSOLUTE_free_procname = 'OSSL_TIME_SPEC_ABSOLUTE_free';
  OSSL_TIME_SPEC_ABSOLUTE_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_TIME_SPEC_ABSOLUTE_procname = 'd2i_OSSL_TIME_SPEC_ABSOLUTE';
  d2i_OSSL_TIME_SPEC_ABSOLUTE_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_TIME_SPEC_ABSOLUTE_procname = 'i2d_OSSL_TIME_SPEC_ABSOLUTE';
  i2d_OSSL_TIME_SPEC_ABSOLUTE_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_TIME_SPEC_ABSOLUTE_it_procname = 'OSSL_TIME_SPEC_ABSOLUTE_it';
  OSSL_TIME_SPEC_ABSOLUTE_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_TIME_SPEC_TIME_new_procname = 'OSSL_TIME_SPEC_TIME_new';
  OSSL_TIME_SPEC_TIME_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_TIME_SPEC_TIME_free_procname = 'OSSL_TIME_SPEC_TIME_free';
  OSSL_TIME_SPEC_TIME_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_TIME_SPEC_TIME_procname = 'd2i_OSSL_TIME_SPEC_TIME';
  d2i_OSSL_TIME_SPEC_TIME_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_TIME_SPEC_TIME_procname = 'i2d_OSSL_TIME_SPEC_TIME';
  i2d_OSSL_TIME_SPEC_TIME_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_TIME_SPEC_TIME_it_procname = 'OSSL_TIME_SPEC_TIME_it';
  OSSL_TIME_SPEC_TIME_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_TIME_SPEC_new_procname = 'OSSL_TIME_SPEC_new';
  OSSL_TIME_SPEC_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_TIME_SPEC_free_procname = 'OSSL_TIME_SPEC_free';
  OSSL_TIME_SPEC_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_TIME_SPEC_procname = 'd2i_OSSL_TIME_SPEC';
  d2i_OSSL_TIME_SPEC_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_TIME_SPEC_procname = 'i2d_OSSL_TIME_SPEC';
  i2d_OSSL_TIME_SPEC_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_TIME_SPEC_it_procname = 'OSSL_TIME_SPEC_it';
  OSSL_TIME_SPEC_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_TIME_PERIOD_new_procname = 'OSSL_TIME_PERIOD_new';
  OSSL_TIME_PERIOD_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_TIME_PERIOD_free_procname = 'OSSL_TIME_PERIOD_free';
  OSSL_TIME_PERIOD_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_TIME_PERIOD_procname = 'd2i_OSSL_TIME_PERIOD';
  d2i_OSSL_TIME_PERIOD_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_TIME_PERIOD_procname = 'i2d_OSSL_TIME_PERIOD';
  i2d_OSSL_TIME_PERIOD_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_TIME_PERIOD_it_procname = 'OSSL_TIME_PERIOD_it';
  OSSL_TIME_PERIOD_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ATAV_new_procname = 'OSSL_ATAV_new';
  OSSL_ATAV_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ATAV_free_procname = 'OSSL_ATAV_free';
  OSSL_ATAV_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_ATAV_procname = 'd2i_OSSL_ATAV';
  d2i_OSSL_ATAV_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_ATAV_procname = 'i2d_OSSL_ATAV';
  i2d_OSSL_ATAV_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ATAV_it_procname = 'OSSL_ATAV_it';
  OSSL_ATAV_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ATTRIBUTE_TYPE_MAPPING_new_procname = 'OSSL_ATTRIBUTE_TYPE_MAPPING_new';
  OSSL_ATTRIBUTE_TYPE_MAPPING_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ATTRIBUTE_TYPE_MAPPING_free_procname = 'OSSL_ATTRIBUTE_TYPE_MAPPING_free';
  OSSL_ATTRIBUTE_TYPE_MAPPING_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_ATTRIBUTE_TYPE_MAPPING_procname = 'd2i_OSSL_ATTRIBUTE_TYPE_MAPPING';
  d2i_OSSL_ATTRIBUTE_TYPE_MAPPING_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_ATTRIBUTE_TYPE_MAPPING_procname = 'i2d_OSSL_ATTRIBUTE_TYPE_MAPPING';
  i2d_OSSL_ATTRIBUTE_TYPE_MAPPING_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ATTRIBUTE_TYPE_MAPPING_it_procname = 'OSSL_ATTRIBUTE_TYPE_MAPPING_it';
  OSSL_ATTRIBUTE_TYPE_MAPPING_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ATTRIBUTE_VALUE_MAPPING_new_procname = 'OSSL_ATTRIBUTE_VALUE_MAPPING_new';
  OSSL_ATTRIBUTE_VALUE_MAPPING_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ATTRIBUTE_VALUE_MAPPING_free_procname = 'OSSL_ATTRIBUTE_VALUE_MAPPING_free';
  OSSL_ATTRIBUTE_VALUE_MAPPING_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_ATTRIBUTE_VALUE_MAPPING_procname = 'd2i_OSSL_ATTRIBUTE_VALUE_MAPPING';
  d2i_OSSL_ATTRIBUTE_VALUE_MAPPING_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_ATTRIBUTE_VALUE_MAPPING_procname = 'i2d_OSSL_ATTRIBUTE_VALUE_MAPPING';
  i2d_OSSL_ATTRIBUTE_VALUE_MAPPING_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ATTRIBUTE_VALUE_MAPPING_it_procname = 'OSSL_ATTRIBUTE_VALUE_MAPPING_it';
  OSSL_ATTRIBUTE_VALUE_MAPPING_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ATTRIBUTE_MAPPING_new_procname = 'OSSL_ATTRIBUTE_MAPPING_new';
  OSSL_ATTRIBUTE_MAPPING_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ATTRIBUTE_MAPPING_free_procname = 'OSSL_ATTRIBUTE_MAPPING_free';
  OSSL_ATTRIBUTE_MAPPING_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_ATTRIBUTE_MAPPING_procname = 'd2i_OSSL_ATTRIBUTE_MAPPING';
  d2i_OSSL_ATTRIBUTE_MAPPING_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_ATTRIBUTE_MAPPING_procname = 'i2d_OSSL_ATTRIBUTE_MAPPING';
  i2d_OSSL_ATTRIBUTE_MAPPING_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ATTRIBUTE_MAPPING_it_procname = 'OSSL_ATTRIBUTE_MAPPING_it';
  OSSL_ATTRIBUTE_MAPPING_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ATTRIBUTE_MAPPINGS_new_procname = 'OSSL_ATTRIBUTE_MAPPINGS_new';
  OSSL_ATTRIBUTE_MAPPINGS_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ATTRIBUTE_MAPPINGS_free_procname = 'OSSL_ATTRIBUTE_MAPPINGS_free';
  OSSL_ATTRIBUTE_MAPPINGS_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_ATTRIBUTE_MAPPINGS_procname = 'd2i_OSSL_ATTRIBUTE_MAPPINGS';
  d2i_OSSL_ATTRIBUTE_MAPPINGS_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_ATTRIBUTE_MAPPINGS_procname = 'i2d_OSSL_ATTRIBUTE_MAPPINGS';
  i2d_OSSL_ATTRIBUTE_MAPPINGS_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ATTRIBUTE_MAPPINGS_it_procname = 'OSSL_ATTRIBUTE_MAPPINGS_it';
  OSSL_ATTRIBUTE_MAPPINGS_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ALLOWED_ATTRIBUTES_CHOICE_new_procname = 'OSSL_ALLOWED_ATTRIBUTES_CHOICE_new';
  OSSL_ALLOWED_ATTRIBUTES_CHOICE_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ALLOWED_ATTRIBUTES_CHOICE_free_procname = 'OSSL_ALLOWED_ATTRIBUTES_CHOICE_free';
  OSSL_ALLOWED_ATTRIBUTES_CHOICE_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE_procname = 'd2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE';
  d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE_procname = 'i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE';
  i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ALLOWED_ATTRIBUTES_CHOICE_it_procname = 'OSSL_ALLOWED_ATTRIBUTES_CHOICE_it';
  OSSL_ALLOWED_ATTRIBUTES_CHOICE_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ALLOWED_ATTRIBUTES_ITEM_new_procname = 'OSSL_ALLOWED_ATTRIBUTES_ITEM_new';
  OSSL_ALLOWED_ATTRIBUTES_ITEM_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ALLOWED_ATTRIBUTES_ITEM_free_procname = 'OSSL_ALLOWED_ATTRIBUTES_ITEM_free';
  OSSL_ALLOWED_ATTRIBUTES_ITEM_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM_procname = 'd2i_OSSL_ALLOWED_ATTRIBUTES_ITEM';
  d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM_procname = 'i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM';
  i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ALLOWED_ATTRIBUTES_ITEM_it_procname = 'OSSL_ALLOWED_ATTRIBUTES_ITEM_it';
  OSSL_ALLOWED_ATTRIBUTES_ITEM_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new_procname = 'OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new';
  OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free_procname = 'OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free';
  OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_procname = 'd2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX';
  d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_procname = 'i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX';
  i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it_procname = 'OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it';
  OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_AA_DIST_POINT_new_procname = 'OSSL_AA_DIST_POINT_new';
  OSSL_AA_DIST_POINT_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_AA_DIST_POINT_free_procname = 'OSSL_AA_DIST_POINT_free';
  OSSL_AA_DIST_POINT_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_AA_DIST_POINT_procname = 'd2i_OSSL_AA_DIST_POINT';
  d2i_OSSL_AA_DIST_POINT_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_AA_DIST_POINT_procname = 'i2d_OSSL_AA_DIST_POINT';
  i2d_OSSL_AA_DIST_POINT_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_AA_DIST_POINT_it_procname = 'OSSL_AA_DIST_POINT_it';
  OSSL_AA_DIST_POINT_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

// =============================================================================
// INLINE/MACRO IMPLEMENTATIONS
// =============================================================================

function EXT_UTF8STRING(nid: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    EXT_UTF8STRING(nid) { nid, 0, ASN1_ITEM_ref(ASN1_UTF8STRING), \
    0, 0, 0, 0,                                                       \
    (X509V3_EXT_I2S)i2s_ASN1_UTF8STRING,                              \
    (X509V3_EXT_S2I)s2i_ASN1_UTF8STRING,                              \
    0, 0, 0, 0,                                                       \
    NULL }
  }
end;

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_GENERAL_NAME_set1_X509_NAME(tgt: PPGENERAL_NAME; src: PX509_NAME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(GENERAL_NAME_set1_X509_NAME_procname);
end;

function ERR_DIST_POINT_NAME_dup(a: PDIST_POINT_NAME): PDIST_POINT_NAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DIST_POINT_NAME_dup_procname);
end;

function ERR_PROXY_POLICY_new: PPROXY_POLICY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PROXY_POLICY_new_procname);
end;

procedure ERR_PROXY_POLICY_free(a: PPROXY_POLICY); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PROXY_POLICY_free_procname);
end;

function ERR_d2i_PROXY_POLICY(a: PPPROXY_POLICY; _in: PPIdAnsiChar; len: TIdC_LONG): PPROXY_POLICY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PROXY_POLICY_procname);
end;

function ERR_i2d_PROXY_POLICY(a: PPROXY_POLICY; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PROXY_POLICY_procname);
end;

function ERR_PROXY_POLICY_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PROXY_POLICY_it_procname);
end;

function ERR_PROXY_CERT_INFO_EXTENSION_new: PPROXY_CERT_INFO_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PROXY_CERT_INFO_EXTENSION_new_procname);
end;

procedure ERR_PROXY_CERT_INFO_EXTENSION_free(a: PPROXY_CERT_INFO_EXTENSION); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PROXY_CERT_INFO_EXTENSION_free_procname);
end;

function ERR_d2i_PROXY_CERT_INFO_EXTENSION(a: PPPROXY_CERT_INFO_EXTENSION; _in: PPIdAnsiChar; len: TIdC_LONG): PPROXY_CERT_INFO_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PROXY_CERT_INFO_EXTENSION_procname);
end;

function ERR_i2d_PROXY_CERT_INFO_EXTENSION(a: PPROXY_CERT_INFO_EXTENSION; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PROXY_CERT_INFO_EXTENSION_procname);
end;

function ERR_PROXY_CERT_INFO_EXTENSION_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PROXY_CERT_INFO_EXTENSION_it_procname);
end;

function ERR_BASIC_CONSTRAINTS_new: PBASIC_CONSTRAINTS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BASIC_CONSTRAINTS_new_procname);
end;

procedure ERR_BASIC_CONSTRAINTS_free(a: PBASIC_CONSTRAINTS); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BASIC_CONSTRAINTS_free_procname);
end;

function ERR_d2i_BASIC_CONSTRAINTS(a: PPBASIC_CONSTRAINTS; _in: PPIdAnsiChar; len: TIdC_LONG): PBASIC_CONSTRAINTS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_BASIC_CONSTRAINTS_procname);
end;

function ERR_i2d_BASIC_CONSTRAINTS(a: PBASIC_CONSTRAINTS; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_BASIC_CONSTRAINTS_procname);
end;

function ERR_BASIC_CONSTRAINTS_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BASIC_CONSTRAINTS_it_procname);
end;

function ERR_OSSL_BASIC_ATTR_CONSTRAINTS_new: POSSL_BASIC_ATTR_CONSTRAINTS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_BASIC_ATTR_CONSTRAINTS_new_procname);
end;

procedure ERR_OSSL_BASIC_ATTR_CONSTRAINTS_free(a: POSSL_BASIC_ATTR_CONSTRAINTS); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_BASIC_ATTR_CONSTRAINTS_free_procname);
end;

function ERR_d2i_OSSL_BASIC_ATTR_CONSTRAINTS(a: PPOSSL_BASIC_ATTR_CONSTRAINTS; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_BASIC_ATTR_CONSTRAINTS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_BASIC_ATTR_CONSTRAINTS_procname);
end;

function ERR_i2d_OSSL_BASIC_ATTR_CONSTRAINTS(a: POSSL_BASIC_ATTR_CONSTRAINTS; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_BASIC_ATTR_CONSTRAINTS_procname);
end;

function ERR_OSSL_BASIC_ATTR_CONSTRAINTS_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_BASIC_ATTR_CONSTRAINTS_it_procname);
end;

function ERR_SXNET_new: PSXNET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SXNET_new_procname);
end;

procedure ERR_SXNET_free(a: PSXNET); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SXNET_free_procname);
end;

function ERR_d2i_SXNET(a: PPSXNET; _in: PPIdAnsiChar; len: TIdC_LONG): PSXNET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_SXNET_procname);
end;

function ERR_i2d_SXNET(a: PSXNET; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_SXNET_procname);
end;

function ERR_SXNET_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SXNET_it_procname);
end;

function ERR_SXNETID_new: PSXNETID; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SXNETID_new_procname);
end;

procedure ERR_SXNETID_free(a: PSXNETID); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SXNETID_free_procname);
end;

function ERR_d2i_SXNETID(a: PPSXNETID; _in: PPIdAnsiChar; len: TIdC_LONG): PSXNETID; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_SXNETID_procname);
end;

function ERR_i2d_SXNETID(a: PSXNETID; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_SXNETID_procname);
end;

function ERR_SXNETID_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SXNETID_it_procname);
end;

function ERR_ISSUER_SIGN_TOOL_new: PISSUER_SIGN_TOOL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ISSUER_SIGN_TOOL_new_procname);
end;

procedure ERR_ISSUER_SIGN_TOOL_free(a: PISSUER_SIGN_TOOL); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ISSUER_SIGN_TOOL_free_procname);
end;

function ERR_d2i_ISSUER_SIGN_TOOL(a: PPISSUER_SIGN_TOOL; _in: PPIdAnsiChar; len: TIdC_LONG): PISSUER_SIGN_TOOL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ISSUER_SIGN_TOOL_procname);
end;

function ERR_i2d_ISSUER_SIGN_TOOL(a: PISSUER_SIGN_TOOL; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ISSUER_SIGN_TOOL_procname);
end;

function ERR_ISSUER_SIGN_TOOL_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ISSUER_SIGN_TOOL_it_procname);
end;

function ERR_SXNET_add_id_asc(psx: PPSXNET; zone: PIdAnsiChar; user: PIdAnsiChar; userlen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SXNET_add_id_asc_procname);
end;

function ERR_SXNET_add_id_ulong(psx: PPSXNET; lzone: TIdC_ULONG; user: PIdAnsiChar; userlen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SXNET_add_id_ulong_procname);
end;

function ERR_SXNET_add_id_INTEGER(psx: PPSXNET; izone: PASN1_INTEGER; user: PIdAnsiChar; userlen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SXNET_add_id_INTEGER_procname);
end;

function ERR_SXNET_get_id_asc(sx: PSXNET; zone: PIdAnsiChar): PASN1_OCTET_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SXNET_get_id_asc_procname);
end;

function ERR_SXNET_get_id_ulong(sx: PSXNET; lzone: TIdC_ULONG): PASN1_OCTET_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SXNET_get_id_ulong_procname);
end;

function ERR_SXNET_get_id_INTEGER(sx: PSXNET; zone: PASN1_INTEGER): PASN1_OCTET_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SXNET_get_id_INTEGER_procname);
end;

function ERR_AUTHORITY_KEYID_new: PAUTHORITY_KEYID; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(AUTHORITY_KEYID_new_procname);
end;

procedure ERR_AUTHORITY_KEYID_free(a: PAUTHORITY_KEYID); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(AUTHORITY_KEYID_free_procname);
end;

function ERR_d2i_AUTHORITY_KEYID(a: PPAUTHORITY_KEYID; _in: PPIdAnsiChar; len: TIdC_LONG): PAUTHORITY_KEYID; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_AUTHORITY_KEYID_procname);
end;

function ERR_i2d_AUTHORITY_KEYID(a: PAUTHORITY_KEYID; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_AUTHORITY_KEYID_procname);
end;

function ERR_AUTHORITY_KEYID_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(AUTHORITY_KEYID_it_procname);
end;

function ERR_PKEY_USAGE_PERIOD_new: PPKEY_USAGE_PERIOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKEY_USAGE_PERIOD_new_procname);
end;

procedure ERR_PKEY_USAGE_PERIOD_free(a: PPKEY_USAGE_PERIOD); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKEY_USAGE_PERIOD_free_procname);
end;

function ERR_d2i_PKEY_USAGE_PERIOD(a: PPPKEY_USAGE_PERIOD; _in: PPIdAnsiChar; len: TIdC_LONG): PPKEY_USAGE_PERIOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKEY_USAGE_PERIOD_procname);
end;

function ERR_i2d_PKEY_USAGE_PERIOD(a: PPKEY_USAGE_PERIOD; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKEY_USAGE_PERIOD_procname);
end;

function ERR_PKEY_USAGE_PERIOD_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKEY_USAGE_PERIOD_it_procname);
end;

function ERR_GENERAL_NAME_new: PGENERAL_NAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(GENERAL_NAME_new_procname);
end;

procedure ERR_GENERAL_NAME_free(a: PGENERAL_NAME); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(GENERAL_NAME_free_procname);
end;

function ERR_d2i_GENERAL_NAME(a: PPGENERAL_NAME; _in: PPIdAnsiChar; len: TIdC_LONG): PGENERAL_NAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_GENERAL_NAME_procname);
end;

function ERR_i2d_GENERAL_NAME(a: PGENERAL_NAME; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_GENERAL_NAME_procname);
end;

function ERR_GENERAL_NAME_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(GENERAL_NAME_it_procname);
end;

function ERR_GENERAL_NAME_dup(a: PGENERAL_NAME): PGENERAL_NAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(GENERAL_NAME_dup_procname);
end;

function ERR_GENERAL_NAME_cmp(a: PGENERAL_NAME; b: PGENERAL_NAME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(GENERAL_NAME_cmp_procname);
end;

function ERR_v2i_ASN1_BIT_STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; nval: Pstack_st_CONF_VALUE): PASN1_BIT_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(v2i_ASN1_BIT_STRING_procname);
end;

function ERR_i2v_ASN1_BIT_STRING(method: PX509V3_EXT_METHOD; bits: PASN1_BIT_STRING; extlist: Pstack_st_CONF_VALUE): Pstack_st_CONF_VALUE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2v_ASN1_BIT_STRING_procname);
end;

function ERR_i2s_ASN1_IA5STRING(method: PX509V3_EXT_METHOD; ia5: PASN1_IA5STRING): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2s_ASN1_IA5STRING_procname);
end;

function ERR_s2i_ASN1_IA5STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; str: PIdAnsiChar): PASN1_IA5STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(s2i_ASN1_IA5STRING_procname);
end;

function ERR_i2s_ASN1_UTF8STRING(method: PX509V3_EXT_METHOD; utf8: PASN1_UTF8STRING): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2s_ASN1_UTF8STRING_procname);
end;

function ERR_s2i_ASN1_UTF8STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; str: PIdAnsiChar): PASN1_UTF8STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(s2i_ASN1_UTF8STRING_procname);
end;

function ERR_i2v_GENERAL_NAME(method: PX509V3_EXT_METHOD; gen: PGENERAL_NAME; ret: Pstack_st_CONF_VALUE): Pstack_st_CONF_VALUE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2v_GENERAL_NAME_procname);
end;

function ERR_GENERAL_NAME_print(_out: PBIO; gen: PGENERAL_NAME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(GENERAL_NAME_print_procname);
end;

function ERR_GENERAL_NAMES_new: PGENERAL_NAMES; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(GENERAL_NAMES_new_procname);
end;

procedure ERR_GENERAL_NAMES_free(a: PGENERAL_NAMES); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(GENERAL_NAMES_free_procname);
end;

function ERR_d2i_GENERAL_NAMES(a: PPGENERAL_NAMES; _in: PPIdAnsiChar; len: TIdC_LONG): PGENERAL_NAMES; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_GENERAL_NAMES_procname);
end;

function ERR_i2d_GENERAL_NAMES(a: PGENERAL_NAMES; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_GENERAL_NAMES_procname);
end;

function ERR_GENERAL_NAMES_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(GENERAL_NAMES_it_procname);
end;

function ERR_i2v_GENERAL_NAMES(method: PX509V3_EXT_METHOD; gen: PGENERAL_NAMES; extlist: Pstack_st_CONF_VALUE): Pstack_st_CONF_VALUE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2v_GENERAL_NAMES_procname);
end;

function ERR_v2i_GENERAL_NAMES(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; nval: Pstack_st_CONF_VALUE): PGENERAL_NAMES; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(v2i_GENERAL_NAMES_procname);
end;

function ERR_OTHERNAME_new: POTHERNAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OTHERNAME_new_procname);
end;

procedure ERR_OTHERNAME_free(a: POTHERNAME); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OTHERNAME_free_procname);
end;

function ERR_d2i_OTHERNAME(a: PPOTHERNAME; _in: PPIdAnsiChar; len: TIdC_LONG): POTHERNAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OTHERNAME_procname);
end;

function ERR_i2d_OTHERNAME(a: POTHERNAME; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OTHERNAME_procname);
end;

function ERR_OTHERNAME_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OTHERNAME_it_procname);
end;

function ERR_EDIPARTYNAME_new: PEDIPARTYNAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EDIPARTYNAME_new_procname);
end;

procedure ERR_EDIPARTYNAME_free(a: PEDIPARTYNAME); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EDIPARTYNAME_free_procname);
end;

function ERR_d2i_EDIPARTYNAME(a: PPEDIPARTYNAME; _in: PPIdAnsiChar; len: TIdC_LONG): PEDIPARTYNAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_EDIPARTYNAME_procname);
end;

function ERR_i2d_EDIPARTYNAME(a: PEDIPARTYNAME; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_EDIPARTYNAME_procname);
end;

function ERR_EDIPARTYNAME_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EDIPARTYNAME_it_procname);
end;

function ERR_OTHERNAME_cmp(a: POTHERNAME; b: POTHERNAME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OTHERNAME_cmp_procname);
end;

procedure ERR_GENERAL_NAME_set0_value(a: PGENERAL_NAME; _type: TIdC_INT; value: Pointer); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(GENERAL_NAME_set0_value_procname);
end;

function ERR_GENERAL_NAME_get0_value(a: PGENERAL_NAME; ptype: PIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(GENERAL_NAME_get0_value_procname);
end;

function ERR_GENERAL_NAME_set0_othername(gen: PGENERAL_NAME; oid: PASN1_OBJECT; value: PASN1_TYPE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(GENERAL_NAME_set0_othername_procname);
end;

function ERR_GENERAL_NAME_get0_otherName(gen: PGENERAL_NAME; poid: PPASN1_OBJECT; pvalue: PPASN1_TYPE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(GENERAL_NAME_get0_otherName_procname);
end;

function ERR_i2s_ASN1_OCTET_STRING(method: PX509V3_EXT_METHOD; ia5: PASN1_OCTET_STRING): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2s_ASN1_OCTET_STRING_procname);
end;

function ERR_s2i_ASN1_OCTET_STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; str: PIdAnsiChar): PASN1_OCTET_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(s2i_ASN1_OCTET_STRING_procname);
end;

function ERR_EXTENDED_KEY_USAGE_new: PEXTENDED_KEY_USAGE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EXTENDED_KEY_USAGE_new_procname);
end;

procedure ERR_EXTENDED_KEY_USAGE_free(a: PEXTENDED_KEY_USAGE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EXTENDED_KEY_USAGE_free_procname);
end;

function ERR_d2i_EXTENDED_KEY_USAGE(a: PPEXTENDED_KEY_USAGE; _in: PPIdAnsiChar; len: TIdC_LONG): PEXTENDED_KEY_USAGE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_EXTENDED_KEY_USAGE_procname);
end;

function ERR_i2d_EXTENDED_KEY_USAGE(a: PEXTENDED_KEY_USAGE; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_EXTENDED_KEY_USAGE_procname);
end;

function ERR_EXTENDED_KEY_USAGE_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EXTENDED_KEY_USAGE_it_procname);
end;

function ERR_i2a_ACCESS_DESCRIPTION(bp: PBIO; a: PACCESS_DESCRIPTION): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2a_ACCESS_DESCRIPTION_procname);
end;

function ERR_TLS_FEATURE_new: PLS_FEATURE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TLS_FEATURE_new_procname);
end;

procedure ERR_TLS_FEATURE_free(a: PLS_FEATURE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TLS_FEATURE_free_procname);
end;

function ERR_CERTIFICATEPOLICIES_new: PCERTIFICATEPOLICIES; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CERTIFICATEPOLICIES_new_procname);
end;

procedure ERR_CERTIFICATEPOLICIES_free(a: PCERTIFICATEPOLICIES); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CERTIFICATEPOLICIES_free_procname);
end;

function ERR_d2i_CERTIFICATEPOLICIES(a: PPCERTIFICATEPOLICIES; _in: PPIdAnsiChar; len: TIdC_LONG): PCERTIFICATEPOLICIES; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_CERTIFICATEPOLICIES_procname);
end;

function ERR_i2d_CERTIFICATEPOLICIES(a: PCERTIFICATEPOLICIES; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_CERTIFICATEPOLICIES_procname);
end;

function ERR_CERTIFICATEPOLICIES_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CERTIFICATEPOLICIES_it_procname);
end;

function ERR_POLICYINFO_new: PPOLICYINFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(POLICYINFO_new_procname);
end;

procedure ERR_POLICYINFO_free(a: PPOLICYINFO); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(POLICYINFO_free_procname);
end;

function ERR_d2i_POLICYINFO(a: PPPOLICYINFO; _in: PPIdAnsiChar; len: TIdC_LONG): PPOLICYINFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_POLICYINFO_procname);
end;

function ERR_i2d_POLICYINFO(a: PPOLICYINFO; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_POLICYINFO_procname);
end;

function ERR_POLICYINFO_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(POLICYINFO_it_procname);
end;

function ERR_POLICYQUALINFO_new: PPOLICYQUALINFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(POLICYQUALINFO_new_procname);
end;

procedure ERR_POLICYQUALINFO_free(a: PPOLICYQUALINFO); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(POLICYQUALINFO_free_procname);
end;

function ERR_d2i_POLICYQUALINFO(a: PPPOLICYQUALINFO; _in: PPIdAnsiChar; len: TIdC_LONG): PPOLICYQUALINFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_POLICYQUALINFO_procname);
end;

function ERR_i2d_POLICYQUALINFO(a: PPOLICYQUALINFO; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_POLICYQUALINFO_procname);
end;

function ERR_POLICYQUALINFO_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(POLICYQUALINFO_it_procname);
end;

function ERR_USERNOTICE_new: PUSERNOTICE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(USERNOTICE_new_procname);
end;

procedure ERR_USERNOTICE_free(a: PUSERNOTICE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(USERNOTICE_free_procname);
end;

function ERR_d2i_USERNOTICE(a: PPUSERNOTICE; _in: PPIdAnsiChar; len: TIdC_LONG): PUSERNOTICE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_USERNOTICE_procname);
end;

function ERR_i2d_USERNOTICE(a: PUSERNOTICE; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_USERNOTICE_procname);
end;

function ERR_USERNOTICE_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(USERNOTICE_it_procname);
end;

function ERR_NOTICEREF_new: PNOTICEREF; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NOTICEREF_new_procname);
end;

procedure ERR_NOTICEREF_free(a: PNOTICEREF); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NOTICEREF_free_procname);
end;

function ERR_d2i_NOTICEREF(a: PPNOTICEREF; _in: PPIdAnsiChar; len: TIdC_LONG): PNOTICEREF; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_NOTICEREF_procname);
end;

function ERR_i2d_NOTICEREF(a: PNOTICEREF; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_NOTICEREF_procname);
end;

function ERR_NOTICEREF_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NOTICEREF_it_procname);
end;

function ERR_CRL_DIST_POINTS_new: PCRL_DIST_POINTS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRL_DIST_POINTS_new_procname);
end;

procedure ERR_CRL_DIST_POINTS_free(a: PCRL_DIST_POINTS); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRL_DIST_POINTS_free_procname);
end;

function ERR_d2i_CRL_DIST_POINTS(a: PPCRL_DIST_POINTS; _in: PPIdAnsiChar; len: TIdC_LONG): PCRL_DIST_POINTS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_CRL_DIST_POINTS_procname);
end;

function ERR_i2d_CRL_DIST_POINTS(a: PCRL_DIST_POINTS; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_CRL_DIST_POINTS_procname);
end;

function ERR_CRL_DIST_POINTS_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRL_DIST_POINTS_it_procname);
end;

function ERR_DIST_POINT_new: PDIST_POINT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DIST_POINT_new_procname);
end;

procedure ERR_DIST_POINT_free(a: PDIST_POINT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DIST_POINT_free_procname);
end;

function ERR_d2i_DIST_POINT(a: PPDIST_POINT; _in: PPIdAnsiChar; len: TIdC_LONG): PDIST_POINT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_DIST_POINT_procname);
end;

function ERR_i2d_DIST_POINT(a: PDIST_POINT; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_DIST_POINT_procname);
end;

function ERR_DIST_POINT_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DIST_POINT_it_procname);
end;

function ERR_DIST_POINT_NAME_new: PDIST_POINT_NAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DIST_POINT_NAME_new_procname);
end;

procedure ERR_DIST_POINT_NAME_free(a: PDIST_POINT_NAME); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DIST_POINT_NAME_free_procname);
end;

function ERR_d2i_DIST_POINT_NAME(a: PPDIST_POINT_NAME; _in: PPIdAnsiChar; len: TIdC_LONG): PDIST_POINT_NAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_DIST_POINT_NAME_procname);
end;

function ERR_i2d_DIST_POINT_NAME(a: PDIST_POINT_NAME; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_DIST_POINT_NAME_procname);
end;

function ERR_DIST_POINT_NAME_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DIST_POINT_NAME_it_procname);
end;

function ERR_ISSUING_DIST_POINT_new: PISSUING_DIST_POINT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ISSUING_DIST_POINT_new_procname);
end;

procedure ERR_ISSUING_DIST_POINT_free(a: PISSUING_DIST_POINT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ISSUING_DIST_POINT_free_procname);
end;

function ERR_d2i_ISSUING_DIST_POINT(a: PPISSUING_DIST_POINT; _in: PPIdAnsiChar; len: TIdC_LONG): PISSUING_DIST_POINT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ISSUING_DIST_POINT_procname);
end;

function ERR_i2d_ISSUING_DIST_POINT(a: PISSUING_DIST_POINT; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ISSUING_DIST_POINT_procname);
end;

function ERR_ISSUING_DIST_POINT_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ISSUING_DIST_POINT_it_procname);
end;

function ERR_DIST_POINT_set_dpname(dpn: PDIST_POINT_NAME; iname: PX509_NAME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DIST_POINT_set_dpname_procname);
end;

function ERR_NAME_CONSTRAINTS_check(x: PX509; nc: PNAME_CONSTRAINTS): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NAME_CONSTRAINTS_check_procname);
end;

function ERR_NAME_CONSTRAINTS_check_CN(x: PX509; nc: PNAME_CONSTRAINTS): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NAME_CONSTRAINTS_check_CN_procname);
end;

function ERR_ACCESS_DESCRIPTION_new: PACCESS_DESCRIPTION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ACCESS_DESCRIPTION_new_procname);
end;

procedure ERR_ACCESS_DESCRIPTION_free(a: PACCESS_DESCRIPTION); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ACCESS_DESCRIPTION_free_procname);
end;

function ERR_d2i_ACCESS_DESCRIPTION(a: PPACCESS_DESCRIPTION; _in: PPIdAnsiChar; len: TIdC_LONG): PACCESS_DESCRIPTION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ACCESS_DESCRIPTION_procname);
end;

function ERR_i2d_ACCESS_DESCRIPTION(a: PACCESS_DESCRIPTION; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ACCESS_DESCRIPTION_procname);
end;

function ERR_ACCESS_DESCRIPTION_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ACCESS_DESCRIPTION_it_procname);
end;

function ERR_AUTHORITY_INFO_ACCESS_new: PAUTHORITY_INFO_ACCESS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(AUTHORITY_INFO_ACCESS_new_procname);
end;

procedure ERR_AUTHORITY_INFO_ACCESS_free(a: PAUTHORITY_INFO_ACCESS); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(AUTHORITY_INFO_ACCESS_free_procname);
end;

function ERR_d2i_AUTHORITY_INFO_ACCESS(a: PPAUTHORITY_INFO_ACCESS; _in: PPIdAnsiChar; len: TIdC_LONG): PAUTHORITY_INFO_ACCESS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_AUTHORITY_INFO_ACCESS_procname);
end;

function ERR_i2d_AUTHORITY_INFO_ACCESS(a: PAUTHORITY_INFO_ACCESS; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_AUTHORITY_INFO_ACCESS_procname);
end;

function ERR_AUTHORITY_INFO_ACCESS_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(AUTHORITY_INFO_ACCESS_it_procname);
end;

function ERR_POLICY_MAPPING_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(POLICY_MAPPING_it_procname);
end;

function ERR_POLICY_MAPPING_new: PPOLICY_MAPPING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(POLICY_MAPPING_new_procname);
end;

procedure ERR_POLICY_MAPPING_free(a: PPOLICY_MAPPING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(POLICY_MAPPING_free_procname);
end;

function ERR_POLICY_MAPPINGS_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(POLICY_MAPPINGS_it_procname);
end;

function ERR_GENERAL_SUBTREE_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(GENERAL_SUBTREE_it_procname);
end;

function ERR_GENERAL_SUBTREE_new: PGENERAL_SUBTREE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(GENERAL_SUBTREE_new_procname);
end;

procedure ERR_GENERAL_SUBTREE_free(a: PGENERAL_SUBTREE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(GENERAL_SUBTREE_free_procname);
end;

function ERR_NAME_CONSTRAINTS_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NAME_CONSTRAINTS_it_procname);
end;

function ERR_NAME_CONSTRAINTS_new: PNAME_CONSTRAINTS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NAME_CONSTRAINTS_new_procname);
end;

procedure ERR_NAME_CONSTRAINTS_free(a: PNAME_CONSTRAINTS); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NAME_CONSTRAINTS_free_procname);
end;

function ERR_POLICY_CONSTRAINTS_new: PPOLICY_CONSTRAINTS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(POLICY_CONSTRAINTS_new_procname);
end;

procedure ERR_POLICY_CONSTRAINTS_free(a: PPOLICY_CONSTRAINTS); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(POLICY_CONSTRAINTS_free_procname);
end;

function ERR_POLICY_CONSTRAINTS_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(POLICY_CONSTRAINTS_it_procname);
end;

function ERR_a2i_GENERAL_NAME(_out: PGENERAL_NAME; method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; gen_type: TIdC_INT; value: PIdAnsiChar; is_nc: TIdC_INT): PGENERAL_NAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(a2i_GENERAL_NAME_procname);
end;

function ERR_v2i_GENERAL_NAME(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; cnf: PCONF_VALUE): PGENERAL_NAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(v2i_GENERAL_NAME_procname);
end;

function ERR_v2i_GENERAL_NAME_ex(_out: PGENERAL_NAME; method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; cnf: PCONF_VALUE; is_nc: TIdC_INT): PGENERAL_NAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(v2i_GENERAL_NAME_ex_procname);
end;

procedure ERR_X509V3_conf_free(val: PCONF_VALUE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_conf_free_procname);
end;

function ERR_X509V3_EXT_nconf_nid(conf: PCONF; ctx: PX509V3_CTX; ext_nid: TIdC_INT; value: PIdAnsiChar): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_nconf_nid_procname);
end;

function ERR_X509V3_EXT_nconf(conf: PCONF; ctx: PX509V3_CTX; name: PIdAnsiChar; value: PIdAnsiChar): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_nconf_procname);
end;

function ERR_X509V3_EXT_add_nconf_sk(conf: PCONF; ctx: PX509V3_CTX; section: PIdAnsiChar; sk: PPstack_st_X509_EXTENSION): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_add_nconf_sk_procname);
end;

function ERR_X509V3_EXT_add_nconf(conf: PCONF; ctx: PX509V3_CTX; section: PIdAnsiChar; cert: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_add_nconf_procname);
end;

function ERR_X509V3_EXT_REQ_add_nconf(conf: PCONF; ctx: PX509V3_CTX; section: PIdAnsiChar; req: PX509_REQ): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_REQ_add_nconf_procname);
end;

function ERR_X509V3_EXT_CRL_add_nconf(conf: PCONF; ctx: PX509V3_CTX; section: PIdAnsiChar; crl: PX509_CRL): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_CRL_add_nconf_procname);
end;

function ERR_X509V3_EXT_conf_nid(conf: Plhash_st_CONF_VALUE; ctx: PX509V3_CTX; ext_nid: TIdC_INT; value: PIdAnsiChar): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_conf_nid_procname);
end;

function ERR_X509V3_EXT_conf(conf: Plhash_st_CONF_VALUE; ctx: PX509V3_CTX; name: PIdAnsiChar; value: PIdAnsiChar): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_conf_procname);
end;

function ERR_X509V3_EXT_add_conf(conf: Plhash_st_CONF_VALUE; ctx: PX509V3_CTX; section: PIdAnsiChar; cert: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_add_conf_procname);
end;

function ERR_X509V3_EXT_REQ_add_conf(conf: Plhash_st_CONF_VALUE; ctx: PX509V3_CTX; section: PIdAnsiChar; req: PX509_REQ): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_REQ_add_conf_procname);
end;

function ERR_X509V3_EXT_CRL_add_conf(conf: Plhash_st_CONF_VALUE; ctx: PX509V3_CTX; section: PIdAnsiChar; crl: PX509_CRL): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_CRL_add_conf_procname);
end;

function ERR_X509V3_add_value_bool_nf(name: PIdAnsiChar; asn1_bool: TIdC_INT; extlist: PPstack_st_CONF_VALUE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_add_value_bool_nf_procname);
end;

function ERR_X509V3_get_value_bool(value: PCONF_VALUE; asn1_bool: PIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_get_value_bool_procname);
end;

function ERR_X509V3_get_value_int(value: PCONF_VALUE; aint: PPASN1_INTEGER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_get_value_int_procname);
end;

procedure ERR_X509V3_set_nconf(ctx: PX509V3_CTX; conf: PCONF); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_set_nconf_procname);
end;

procedure ERR_X509V3_set_conf_lhash(ctx: PX509V3_CTX; lhash: Plhash_st_CONF_VALUE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_set_conf_lhash_procname);
end;

function ERR_X509V3_get_string(ctx: PX509V3_CTX; name: PIdAnsiChar; section: PIdAnsiChar): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_get_string_procname);
end;

function ERR_X509V3_get_section(ctx: PX509V3_CTX; section: PIdAnsiChar): Pstack_st_CONF_VALUE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_get_section_procname);
end;

procedure ERR_X509V3_string_free(ctx: PX509V3_CTX; str: PIdAnsiChar); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_string_free_procname);
end;

procedure ERR_X509V3_section_free(ctx: PX509V3_CTX; section: Pstack_st_CONF_VALUE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_section_free_procname);
end;

procedure ERR_X509V3_set_ctx(ctx: PX509V3_CTX; issuer: PX509; subject: PX509; req: PX509_REQ; crl: PX509_CRL; flags: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_set_ctx_procname);
end;

function ERR_X509V3_set_issuer_pkey(ctx: PX509V3_CTX; pkey: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_set_issuer_pkey_procname);
end;

function ERR_X509V3_add_value(name: PIdAnsiChar; value: PIdAnsiChar; extlist: PPstack_st_CONF_VALUE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_add_value_procname);
end;

function ERR_X509V3_add_value_uchar(name: PIdAnsiChar; value: PIdAnsiChar; extlist: PPstack_st_CONF_VALUE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_add_value_uchar_procname);
end;

function ERR_X509V3_add_value_bool(name: PIdAnsiChar; asn1_bool: TIdC_INT; extlist: PPstack_st_CONF_VALUE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_add_value_bool_procname);
end;

function ERR_X509V3_add_value_int(name: PIdAnsiChar; aint: PASN1_INTEGER; extlist: PPstack_st_CONF_VALUE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_add_value_int_procname);
end;

function ERR_i2s_ASN1_INTEGER(meth: PX509V3_EXT_METHOD; aint: PASN1_INTEGER): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2s_ASN1_INTEGER_procname);
end;

function ERR_s2i_ASN1_INTEGER(meth: PX509V3_EXT_METHOD; value: PIdAnsiChar): PASN1_INTEGER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(s2i_ASN1_INTEGER_procname);
end;

function ERR_i2s_ASN1_ENUMERATED(meth: PX509V3_EXT_METHOD; aint: PASN1_ENUMERATED): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2s_ASN1_ENUMERATED_procname);
end;

function ERR_i2s_ASN1_ENUMERATED_TABLE(meth: PX509V3_EXT_METHOD; aint: PASN1_ENUMERATED): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2s_ASN1_ENUMERATED_TABLE_procname);
end;

function ERR_X509V3_EXT_add(ext: PX509V3_EXT_METHOD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_add_procname);
end;

function ERR_X509V3_EXT_add_list(extlist: PX509V3_EXT_METHOD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_add_list_procname);
end;

function ERR_X509V3_EXT_add_alias(nid_to: TIdC_INT; nid_from: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_add_alias_procname);
end;

procedure ERR_X509V3_EXT_cleanup; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_cleanup_procname);
end;

function ERR_X509V3_EXT_get(ext: PX509_EXTENSION): PX509V3_EXT_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_get_procname);
end;

function ERR_X509V3_EXT_get_nid(nid: TIdC_INT): PX509V3_EXT_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_get_nid_procname);
end;

function ERR_X509V3_add_standard_extensions: TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_add_standard_extensions_procname);
end;

function ERR_X509V3_parse_list(line: PIdAnsiChar): Pstack_st_CONF_VALUE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_parse_list_procname);
end;

function ERR_X509V3_EXT_d2i(ext: PX509_EXTENSION): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_d2i_procname);
end;

function ERR_X509V3_get_d2i(x: Pstack_st_X509_EXTENSION; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_get_d2i_procname);
end;

function ERR_X509V3_EXT_i2d(ext_nid: TIdC_INT; crit: TIdC_INT; ext_struc: Pointer): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_i2d_procname);
end;

function ERR_X509V3_add1_i2d(x: PPstack_st_X509_EXTENSION; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_add1_i2d_procname);
end;

procedure ERR_X509V3_EXT_val_prn(_out: PBIO; val: Pstack_st_CONF_VALUE; indent: TIdC_INT; ml: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_val_prn_procname);
end;

function ERR_X509V3_EXT_print(_out: PBIO; ext: PX509_EXTENSION; flag: TIdC_ULONG; indent: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_print_procname);
end;

function ERR_X509V3_EXT_print_fp(_out: PFILE; ext: PX509_EXTENSION; flag: TIdC_INT; indent: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_print_fp_procname);
end;

function ERR_X509V3_extensions_print(_out: PBIO; title: PIdAnsiChar; exts: Pstack_st_X509_EXTENSION; flag: TIdC_ULONG; indent: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_extensions_print_procname);
end;

function ERR_X509_check_ca(x: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_check_ca_procname);
end;

function ERR_X509_check_purpose(x: PX509; id: TIdC_INT; ca: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_check_purpose_procname);
end;

function ERR_X509_supported_extension(ex: PX509_EXTENSION): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_supported_extension_procname);
end;

function ERR_X509_check_issued(issuer: PX509; subject: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_check_issued_procname);
end;

function ERR_X509_check_akid(issuer: PX509; akid: PAUTHORITY_KEYID): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_check_akid_procname);
end;

procedure ERR_X509_set_proxy_flag(x: PX509); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_set_proxy_flag_procname);
end;

procedure ERR_X509_set_proxy_pathlen(x: PX509; l: TIdC_LONG); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_set_proxy_pathlen_procname);
end;

function ERR_X509_get_proxy_pathlen(x: PX509): TIdC_LONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_proxy_pathlen_procname);
end;

function ERR_X509_get_extension_flags(x: PX509): UInt32; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_extension_flags_procname);
end;

function ERR_X509_get_key_usage(x: PX509): UInt32; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_key_usage_procname);
end;

function ERR_X509_get_extended_key_usage(x: PX509): UInt32; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_extended_key_usage_procname);
end;

function ERR_X509_get0_subject_key_id(x: PX509): PASN1_OCTET_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get0_subject_key_id_procname);
end;

function ERR_X509_get0_authority_key_id(x: PX509): PASN1_OCTET_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get0_authority_key_id_procname);
end;

function ERR_X509_get0_authority_issuer(x: PX509): PGENERAL_NAMES; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get0_authority_issuer_procname);
end;

function ERR_X509_get0_authority_serial(x: PX509): PASN1_INTEGER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get0_authority_serial_procname);
end;

function ERR_X509_PURPOSE_get_count: TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PURPOSE_get_count_procname);
end;

function ERR_X509_PURPOSE_get_unused_id(libctx: POSSL_LIB_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PURPOSE_get_unused_id_procname);
end;

function ERR_X509_PURPOSE_get_by_sname(sname: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PURPOSE_get_by_sname_procname);
end;

function ERR_X509_PURPOSE_get_by_id(id: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PURPOSE_get_by_id_procname);
end;

function ERR_X509_PURPOSE_add(id: TIdC_INT; trust: TIdC_INT; flags: TIdC_INT; ck: TX509_PURPOSE_add_ck_cb; name: PIdAnsiChar; sname: PIdAnsiChar; arg: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PURPOSE_add_procname);
end;

procedure ERR_X509_PURPOSE_cleanup; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PURPOSE_cleanup_procname);
end;

function ERR_X509_PURPOSE_get0(idx: TIdC_INT): PX509_PURPOSE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PURPOSE_get0_procname);
end;

function ERR_X509_PURPOSE_get_id(arg1: PX509_PURPOSE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PURPOSE_get_id_procname);
end;

function ERR_X509_PURPOSE_get0_name(xp: PX509_PURPOSE): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PURPOSE_get0_name_procname);
end;

function ERR_X509_PURPOSE_get0_sname(xp: PX509_PURPOSE): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PURPOSE_get0_sname_procname);
end;

function ERR_X509_PURPOSE_get_trust(xp: PX509_PURPOSE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PURPOSE_get_trust_procname);
end;

function ERR_X509_PURPOSE_set(p: PIdC_INT; purpose: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PURPOSE_set_procname);
end;

function ERR_X509_get1_email(x: PX509): Pstack_st_OPENSSL_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get1_email_procname);
end;

function ERR_X509_REQ_get1_email(x: PX509_REQ): Pstack_st_OPENSSL_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get1_email_procname);
end;

procedure ERR_X509_email_free(sk: Pstack_st_OPENSSL_STRING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_email_free_procname);
end;

function ERR_X509_get1_ocsp(x: PX509): Pstack_st_OPENSSL_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get1_ocsp_procname);
end;

function ERR_X509_check_host(x: PX509; chk: PIdAnsiChar; chklen: TIdC_SIZET; flags: TIdC_UINT; peername: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_check_host_procname);
end;

function ERR_X509_check_email(x: PX509; chk: PIdAnsiChar; chklen: TIdC_SIZET; flags: TIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_check_email_procname);
end;

function ERR_X509_check_ip(x: PX509; chk: PIdAnsiChar; chklen: TIdC_SIZET; flags: TIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_check_ip_procname);
end;

function ERR_X509_check_ip_asc(x: PX509; ipasc: PIdAnsiChar; flags: TIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_check_ip_asc_procname);
end;

function ERR_a2i_IPADDRESS(ipasc: PIdAnsiChar): PASN1_OCTET_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(a2i_IPADDRESS_procname);
end;

function ERR_a2i_IPADDRESS_NC(ipasc: PIdAnsiChar): PASN1_OCTET_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(a2i_IPADDRESS_NC_procname);
end;

function ERR_X509V3_NAME_from_section(nm: PX509_NAME; dn_sk: Pstack_st_CONF_VALUE; chtype: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_NAME_from_section_procname);
end;

procedure ERR_X509_POLICY_NODE_print(_out: PBIO; node: PX509_POLICY_NODE; indent: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_POLICY_NODE_print_procname);
end;

function ERR_ASRange_new: PASRange; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASRange_new_procname);
end;

procedure ERR_ASRange_free(a: PASRange); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASRange_free_procname);
end;

function ERR_d2i_ASRange(a: PPASRange; _in: PPIdAnsiChar; len: TIdC_LONG): PASRange; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASRange_procname);
end;

function ERR_i2d_ASRange(a: PASRange; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASRange_procname);
end;

function ERR_ASRange_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASRange_it_procname);
end;

function ERR_ASIdOrRange_new: PASIdOrRange; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASIdOrRange_new_procname);
end;

procedure ERR_ASIdOrRange_free(a: PASIdOrRange); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASIdOrRange_free_procname);
end;

function ERR_d2i_ASIdOrRange(a: PPASIdOrRange; _in: PPIdAnsiChar; len: TIdC_LONG): PASIdOrRange; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASIdOrRange_procname);
end;

function ERR_i2d_ASIdOrRange(a: PASIdOrRange; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASIdOrRange_procname);
end;

function ERR_ASIdOrRange_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASIdOrRange_it_procname);
end;

function ERR_ASIdentifierChoice_new: PASIdentifierChoice; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASIdentifierChoice_new_procname);
end;

procedure ERR_ASIdentifierChoice_free(a: PASIdentifierChoice); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASIdentifierChoice_free_procname);
end;

function ERR_d2i_ASIdentifierChoice(a: PPASIdentifierChoice; _in: PPIdAnsiChar; len: TIdC_LONG): PASIdentifierChoice; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASIdentifierChoice_procname);
end;

function ERR_i2d_ASIdentifierChoice(a: PASIdentifierChoice; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASIdentifierChoice_procname);
end;

function ERR_ASIdentifierChoice_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASIdentifierChoice_it_procname);
end;

function ERR_ASIdentifiers_new: PASIdentifiers; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASIdentifiers_new_procname);
end;

procedure ERR_ASIdentifiers_free(a: PASIdentifiers); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASIdentifiers_free_procname);
end;

function ERR_d2i_ASIdentifiers(a: PPASIdentifiers; _in: PPIdAnsiChar; len: TIdC_LONG): PASIdentifiers; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ASIdentifiers_procname);
end;

function ERR_i2d_ASIdentifiers(a: PASIdentifiers; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ASIdentifiers_procname);
end;

function ERR_ASIdentifiers_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASIdentifiers_it_procname);
end;

function ERR_IPAddressRange_new: PIPAddressRange; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(IPAddressRange_new_procname);
end;

procedure ERR_IPAddressRange_free(a: PIPAddressRange); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(IPAddressRange_free_procname);
end;

function ERR_d2i_IPAddressRange(a: PPIPAddressRange; _in: PPIdAnsiChar; len: TIdC_LONG): PIPAddressRange; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_IPAddressRange_procname);
end;

function ERR_i2d_IPAddressRange(a: PIPAddressRange; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_IPAddressRange_procname);
end;

function ERR_IPAddressRange_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(IPAddressRange_it_procname);
end;

function ERR_IPAddressOrRange_new: PIPAddressOrRange; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(IPAddressOrRange_new_procname);
end;

procedure ERR_IPAddressOrRange_free(a: PIPAddressOrRange); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(IPAddressOrRange_free_procname);
end;

function ERR_d2i_IPAddressOrRange(a: PPIPAddressOrRange; _in: PPIdAnsiChar; len: TIdC_LONG): PIPAddressOrRange; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_IPAddressOrRange_procname);
end;

function ERR_i2d_IPAddressOrRange(a: PIPAddressOrRange; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_IPAddressOrRange_procname);
end;

function ERR_IPAddressOrRange_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(IPAddressOrRange_it_procname);
end;

function ERR_IPAddressChoice_new: PIPAddressChoice; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(IPAddressChoice_new_procname);
end;

procedure ERR_IPAddressChoice_free(a: PIPAddressChoice); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(IPAddressChoice_free_procname);
end;

function ERR_d2i_IPAddressChoice(a: PPIPAddressChoice; _in: PPIdAnsiChar; len: TIdC_LONG): PIPAddressChoice; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_IPAddressChoice_procname);
end;

function ERR_i2d_IPAddressChoice(a: PIPAddressChoice; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_IPAddressChoice_procname);
end;

function ERR_IPAddressChoice_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(IPAddressChoice_it_procname);
end;

function ERR_IPAddressFamily_new: PIPAddressFamily; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(IPAddressFamily_new_procname);
end;

procedure ERR_IPAddressFamily_free(a: PIPAddressFamily); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(IPAddressFamily_free_procname);
end;

function ERR_d2i_IPAddressFamily(a: PPIPAddressFamily; _in: PPIdAnsiChar; len: TIdC_LONG): PIPAddressFamily; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_IPAddressFamily_procname);
end;

function ERR_i2d_IPAddressFamily(a: PIPAddressFamily; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_IPAddressFamily_procname);
end;

function ERR_IPAddressFamily_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(IPAddressFamily_it_procname);
end;

function ERR_X509v3_asid_add_inherit(asid: PASIdentifiers; which: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_asid_add_inherit_procname);
end;

function ERR_X509v3_asid_add_id_or_range(asid: PASIdentifiers; which: TIdC_INT; min: PASN1_INTEGER; max: PASN1_INTEGER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_asid_add_id_or_range_procname);
end;

function ERR_X509v3_addr_add_inherit(addr: PIPAddrBlocks; afi: TIdC_UINT; safi: PIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_addr_add_inherit_procname);
end;

function ERR_X509v3_addr_add_prefix(addr: PIPAddrBlocks; afi: TIdC_UINT; safi: PIdC_UINT; a: PIdAnsiChar; prefixlen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_addr_add_prefix_procname);
end;

function ERR_X509v3_addr_add_range(addr: PIPAddrBlocks; afi: TIdC_UINT; safi: PIdC_UINT; min: PIdAnsiChar; max: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_addr_add_range_procname);
end;

function ERR_X509v3_addr_get_afi(f: PIPAddressFamily): TIdC_UINT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_addr_get_afi_procname);
end;

function ERR_X509v3_addr_get_range(aor: PIPAddressOrRange; afi: TIdC_UINT; min: PIdAnsiChar; max: PIdAnsiChar; length: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_addr_get_range_procname);
end;

function ERR_X509v3_asid_is_canonical(asid: PASIdentifiers): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_asid_is_canonical_procname);
end;

function ERR_X509v3_addr_is_canonical(addr: PIPAddrBlocks): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_addr_is_canonical_procname);
end;

function ERR_X509v3_asid_canonize(asid: PASIdentifiers): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_asid_canonize_procname);
end;

function ERR_X509v3_addr_canonize(addr: PIPAddrBlocks): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_addr_canonize_procname);
end;

function ERR_X509v3_asid_inherits(asid: PASIdentifiers): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_asid_inherits_procname);
end;

function ERR_X509v3_addr_inherits(addr: PIPAddrBlocks): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_addr_inherits_procname);
end;

function ERR_X509v3_asid_subset(a: PASIdentifiers; b: PASIdentifiers): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_asid_subset_procname);
end;

function ERR_X509v3_addr_subset(a: PIPAddrBlocks; b: PIPAddrBlocks): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_addr_subset_procname);
end;

function ERR_X509v3_asid_validate_path(arg1: PX509_STORE_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_asid_validate_path_procname);
end;

function ERR_X509v3_addr_validate_path(arg1: PX509_STORE_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_addr_validate_path_procname);
end;

function ERR_X509v3_asid_validate_resource_set(chain: Pstack_st_X509; ext: PASIdentifiers; allow_inheritance: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_asid_validate_resource_set_procname);
end;

function ERR_X509v3_addr_validate_resource_set(chain: Pstack_st_X509; ext: PIPAddrBlocks; allow_inheritance: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_addr_validate_resource_set_procname);
end;

function ERR_NAMING_AUTHORITY_new: PNAMING_AUTHORITY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NAMING_AUTHORITY_new_procname);
end;

procedure ERR_NAMING_AUTHORITY_free(a: PNAMING_AUTHORITY); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NAMING_AUTHORITY_free_procname);
end;

function ERR_d2i_NAMING_AUTHORITY(a: PPNAMING_AUTHORITY; _in: PPIdAnsiChar; len: TIdC_LONG): PNAMING_AUTHORITY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_NAMING_AUTHORITY_procname);
end;

function ERR_i2d_NAMING_AUTHORITY(a: PNAMING_AUTHORITY; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_NAMING_AUTHORITY_procname);
end;

function ERR_NAMING_AUTHORITY_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NAMING_AUTHORITY_it_procname);
end;

function ERR_PROFESSION_INFO_new: PPROFESSION_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PROFESSION_INFO_new_procname);
end;

procedure ERR_PROFESSION_INFO_free(a: PPROFESSION_INFO); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PROFESSION_INFO_free_procname);
end;

function ERR_d2i_PROFESSION_INFO(a: PPPROFESSION_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PPROFESSION_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PROFESSION_INFO_procname);
end;

function ERR_i2d_PROFESSION_INFO(a: PPROFESSION_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PROFESSION_INFO_procname);
end;

function ERR_PROFESSION_INFO_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PROFESSION_INFO_it_procname);
end;

function ERR_ADMISSIONS_new: PADMISSIONS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ADMISSIONS_new_procname);
end;

procedure ERR_ADMISSIONS_free(a: PADMISSIONS); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ADMISSIONS_free_procname);
end;

function ERR_d2i_ADMISSIONS(a: PPADMISSIONS; _in: PPIdAnsiChar; len: TIdC_LONG): PADMISSIONS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ADMISSIONS_procname);
end;

function ERR_i2d_ADMISSIONS(a: PADMISSIONS; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ADMISSIONS_procname);
end;

function ERR_ADMISSIONS_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ADMISSIONS_it_procname);
end;

function ERR_ADMISSION_SYNTAX_new: PADMISSION_SYNTAX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ADMISSION_SYNTAX_new_procname);
end;

procedure ERR_ADMISSION_SYNTAX_free(a: PADMISSION_SYNTAX); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ADMISSION_SYNTAX_free_procname);
end;

function ERR_d2i_ADMISSION_SYNTAX(a: PPADMISSION_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): PADMISSION_SYNTAX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ADMISSION_SYNTAX_procname);
end;

function ERR_i2d_ADMISSION_SYNTAX(a: PADMISSION_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ADMISSION_SYNTAX_procname);
end;

function ERR_ADMISSION_SYNTAX_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ADMISSION_SYNTAX_it_procname);
end;

function ERR_NAMING_AUTHORITY_get0_authorityId(n: PNAMING_AUTHORITY): PASN1_OBJECT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NAMING_AUTHORITY_get0_authorityId_procname);
end;

function ERR_NAMING_AUTHORITY_get0_authorityURL(n: PNAMING_AUTHORITY): PASN1_IA5STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NAMING_AUTHORITY_get0_authorityURL_procname);
end;

function ERR_NAMING_AUTHORITY_get0_authorityText(n: PNAMING_AUTHORITY): PASN1_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NAMING_AUTHORITY_get0_authorityText_procname);
end;

procedure ERR_NAMING_AUTHORITY_set0_authorityId(n: PNAMING_AUTHORITY; namingAuthorityId: PASN1_OBJECT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NAMING_AUTHORITY_set0_authorityId_procname);
end;

procedure ERR_NAMING_AUTHORITY_set0_authorityURL(n: PNAMING_AUTHORITY; namingAuthorityUrl: PASN1_IA5STRING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NAMING_AUTHORITY_set0_authorityURL_procname);
end;

procedure ERR_NAMING_AUTHORITY_set0_authorityText(n: PNAMING_AUTHORITY; namingAuthorityText: PASN1_STRING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NAMING_AUTHORITY_set0_authorityText_procname);
end;

function ERR_ADMISSION_SYNTAX_get0_admissionAuthority(_as: PADMISSION_SYNTAX): PGENERAL_NAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ADMISSION_SYNTAX_get0_admissionAuthority_procname);
end;

procedure ERR_ADMISSION_SYNTAX_set0_admissionAuthority(_as: PADMISSION_SYNTAX; aa: PGENERAL_NAME); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ADMISSION_SYNTAX_set0_admissionAuthority_procname);
end;

function ERR_ADMISSION_SYNTAX_get0_contentsOfAdmissions(_as: PADMISSION_SYNTAX): Pstack_st_ADMISSIONS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ADMISSION_SYNTAX_get0_contentsOfAdmissions_procname);
end;

procedure ERR_ADMISSION_SYNTAX_set0_contentsOfAdmissions(_as: PADMISSION_SYNTAX; a: Pstack_st_ADMISSIONS); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ADMISSION_SYNTAX_set0_contentsOfAdmissions_procname);
end;

function ERR_ADMISSIONS_get0_admissionAuthority(a: PADMISSIONS): PGENERAL_NAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ADMISSIONS_get0_admissionAuthority_procname);
end;

procedure ERR_ADMISSIONS_set0_admissionAuthority(a: PADMISSIONS; aa: PGENERAL_NAME); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ADMISSIONS_set0_admissionAuthority_procname);
end;

function ERR_ADMISSIONS_get0_namingAuthority(a: PADMISSIONS): PNAMING_AUTHORITY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ADMISSIONS_get0_namingAuthority_procname);
end;

procedure ERR_ADMISSIONS_set0_namingAuthority(a: PADMISSIONS; na: PNAMING_AUTHORITY); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ADMISSIONS_set0_namingAuthority_procname);
end;

function ERR_ADMISSIONS_get0_professionInfos(a: PADMISSIONS): PPROFESSION_INFOS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ADMISSIONS_get0_professionInfos_procname);
end;

procedure ERR_ADMISSIONS_set0_professionInfos(a: PADMISSIONS; pi: PPROFESSION_INFOS); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ADMISSIONS_set0_professionInfos_procname);
end;

function ERR_PROFESSION_INFO_get0_addProfessionInfo(pi: PPROFESSION_INFO): PASN1_OCTET_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PROFESSION_INFO_get0_addProfessionInfo_procname);
end;

procedure ERR_PROFESSION_INFO_set0_addProfessionInfo(pi: PPROFESSION_INFO; aos: PASN1_OCTET_STRING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PROFESSION_INFO_set0_addProfessionInfo_procname);
end;

function ERR_PROFESSION_INFO_get0_namingAuthority(pi: PPROFESSION_INFO): PNAMING_AUTHORITY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PROFESSION_INFO_get0_namingAuthority_procname);
end;

procedure ERR_PROFESSION_INFO_set0_namingAuthority(pi: PPROFESSION_INFO; na: PNAMING_AUTHORITY); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PROFESSION_INFO_set0_namingAuthority_procname);
end;

function ERR_PROFESSION_INFO_get0_professionItems(pi: PPROFESSION_INFO): Pstack_st_ASN1_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PROFESSION_INFO_get0_professionItems_procname);
end;

procedure ERR_PROFESSION_INFO_set0_professionItems(pi: PPROFESSION_INFO; _as: Pstack_st_ASN1_STRING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PROFESSION_INFO_set0_professionItems_procname);
end;

function ERR_PROFESSION_INFO_get0_professionOIDs(pi: PPROFESSION_INFO): Pstack_st_ASN1_OBJECT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PROFESSION_INFO_get0_professionOIDs_procname);
end;

procedure ERR_PROFESSION_INFO_set0_professionOIDs(pi: PPROFESSION_INFO; po: Pstack_st_ASN1_OBJECT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PROFESSION_INFO_set0_professionOIDs_procname);
end;

function ERR_PROFESSION_INFO_get0_registrationNumber(pi: PPROFESSION_INFO): PASN1_PRINTABLESTRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PROFESSION_INFO_get0_registrationNumber_procname);
end;

procedure ERR_PROFESSION_INFO_set0_registrationNumber(pi: PPROFESSION_INFO; rn: PASN1_PRINTABLESTRING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PROFESSION_INFO_set0_registrationNumber_procname);
end;

function ERR_OSSL_GENERAL_NAMES_print(_out: PBIO; gens: PGENERAL_NAMES; indent: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_GENERAL_NAMES_print_procname);
end;

function ERR_OSSL_ATTRIBUTES_SYNTAX_new: POSSL_ATTRIBUTES_SYNTAX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ATTRIBUTES_SYNTAX_new_procname);
end;

procedure ERR_OSSL_ATTRIBUTES_SYNTAX_free(a: POSSL_ATTRIBUTES_SYNTAX); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ATTRIBUTES_SYNTAX_free_procname);
end;

function ERR_d2i_OSSL_ATTRIBUTES_SYNTAX(a: PPOSSL_ATTRIBUTES_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ATTRIBUTES_SYNTAX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_ATTRIBUTES_SYNTAX_procname);
end;

function ERR_i2d_OSSL_ATTRIBUTES_SYNTAX(a: POSSL_ATTRIBUTES_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_ATTRIBUTES_SYNTAX_procname);
end;

function ERR_OSSL_ATTRIBUTES_SYNTAX_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ATTRIBUTES_SYNTAX_it_procname);
end;

function ERR_OSSL_USER_NOTICE_SYNTAX_new: POSSL_USER_NOTICE_SYNTAX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_USER_NOTICE_SYNTAX_new_procname);
end;

procedure ERR_OSSL_USER_NOTICE_SYNTAX_free(a: POSSL_USER_NOTICE_SYNTAX); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_USER_NOTICE_SYNTAX_free_procname);
end;

function ERR_d2i_OSSL_USER_NOTICE_SYNTAX(a: PPOSSL_USER_NOTICE_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_USER_NOTICE_SYNTAX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_USER_NOTICE_SYNTAX_procname);
end;

function ERR_i2d_OSSL_USER_NOTICE_SYNTAX(a: POSSL_USER_NOTICE_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_USER_NOTICE_SYNTAX_procname);
end;

function ERR_OSSL_USER_NOTICE_SYNTAX_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_USER_NOTICE_SYNTAX_it_procname);
end;

function ERR_OSSL_ROLE_SPEC_CERT_ID_new: POSSL_ROLE_SPEC_CERT_ID; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ROLE_SPEC_CERT_ID_new_procname);
end;

procedure ERR_OSSL_ROLE_SPEC_CERT_ID_free(a: POSSL_ROLE_SPEC_CERT_ID); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ROLE_SPEC_CERT_ID_free_procname);
end;

function ERR_d2i_OSSL_ROLE_SPEC_CERT_ID(a: PPOSSL_ROLE_SPEC_CERT_ID; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ROLE_SPEC_CERT_ID; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_ROLE_SPEC_CERT_ID_procname);
end;

function ERR_i2d_OSSL_ROLE_SPEC_CERT_ID(a: POSSL_ROLE_SPEC_CERT_ID; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_ROLE_SPEC_CERT_ID_procname);
end;

function ERR_OSSL_ROLE_SPEC_CERT_ID_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ROLE_SPEC_CERT_ID_it_procname);
end;

function ERR_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new: POSSL_ROLE_SPEC_CERT_ID_SYNTAX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new_procname);
end;

procedure ERR_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free(a: POSSL_ROLE_SPEC_CERT_ID_SYNTAX); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free_procname);
end;

function ERR_d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX(a: PPOSSL_ROLE_SPEC_CERT_ID_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ROLE_SPEC_CERT_ID_SYNTAX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_procname);
end;

function ERR_i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX(a: POSSL_ROLE_SPEC_CERT_ID_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_procname);
end;

function ERR_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it_procname);
end;

function ERR_OSSL_HASH_new: POSSL_HASH; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HASH_new_procname);
end;

procedure ERR_OSSL_HASH_free(a: POSSL_HASH); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HASH_free_procname);
end;

function ERR_d2i_OSSL_HASH(a: PPOSSL_HASH; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_HASH; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_HASH_procname);
end;

function ERR_i2d_OSSL_HASH(a: POSSL_HASH; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_HASH_procname);
end;

function ERR_OSSL_HASH_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HASH_it_procname);
end;

function ERR_OSSL_INFO_SYNTAX_new: POSSL_INFO_SYNTAX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_INFO_SYNTAX_new_procname);
end;

procedure ERR_OSSL_INFO_SYNTAX_free(a: POSSL_INFO_SYNTAX); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_INFO_SYNTAX_free_procname);
end;

function ERR_d2i_OSSL_INFO_SYNTAX(a: PPOSSL_INFO_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_INFO_SYNTAX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_INFO_SYNTAX_procname);
end;

function ERR_i2d_OSSL_INFO_SYNTAX(a: POSSL_INFO_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_INFO_SYNTAX_procname);
end;

function ERR_OSSL_INFO_SYNTAX_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_INFO_SYNTAX_it_procname);
end;

function ERR_OSSL_INFO_SYNTAX_POINTER_new: POSSL_INFO_SYNTAX_POINTER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_INFO_SYNTAX_POINTER_new_procname);
end;

procedure ERR_OSSL_INFO_SYNTAX_POINTER_free(a: POSSL_INFO_SYNTAX_POINTER); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_INFO_SYNTAX_POINTER_free_procname);
end;

function ERR_d2i_OSSL_INFO_SYNTAX_POINTER(a: PPOSSL_INFO_SYNTAX_POINTER; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_INFO_SYNTAX_POINTER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_INFO_SYNTAX_POINTER_procname);
end;

function ERR_i2d_OSSL_INFO_SYNTAX_POINTER(a: POSSL_INFO_SYNTAX_POINTER; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_INFO_SYNTAX_POINTER_procname);
end;

function ERR_OSSL_INFO_SYNTAX_POINTER_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_INFO_SYNTAX_POINTER_it_procname);
end;

function ERR_OSSL_PRIVILEGE_POLICY_ID_new: POSSL_PRIVILEGE_POLICY_ID; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PRIVILEGE_POLICY_ID_new_procname);
end;

procedure ERR_OSSL_PRIVILEGE_POLICY_ID_free(a: POSSL_PRIVILEGE_POLICY_ID); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PRIVILEGE_POLICY_ID_free_procname);
end;

function ERR_d2i_OSSL_PRIVILEGE_POLICY_ID(a: PPOSSL_PRIVILEGE_POLICY_ID; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_PRIVILEGE_POLICY_ID; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_PRIVILEGE_POLICY_ID_procname);
end;

function ERR_i2d_OSSL_PRIVILEGE_POLICY_ID(a: POSSL_PRIVILEGE_POLICY_ID; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_PRIVILEGE_POLICY_ID_procname);
end;

function ERR_OSSL_PRIVILEGE_POLICY_ID_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PRIVILEGE_POLICY_ID_it_procname);
end;

function ERR_OSSL_ATTRIBUTE_DESCRIPTOR_new: POSSL_ATTRIBUTE_DESCRIPTOR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ATTRIBUTE_DESCRIPTOR_new_procname);
end;

procedure ERR_OSSL_ATTRIBUTE_DESCRIPTOR_free(a: POSSL_ATTRIBUTE_DESCRIPTOR); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ATTRIBUTE_DESCRIPTOR_free_procname);
end;

function ERR_d2i_OSSL_ATTRIBUTE_DESCRIPTOR(a: PPOSSL_ATTRIBUTE_DESCRIPTOR; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ATTRIBUTE_DESCRIPTOR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_ATTRIBUTE_DESCRIPTOR_procname);
end;

function ERR_i2d_OSSL_ATTRIBUTE_DESCRIPTOR(a: POSSL_ATTRIBUTE_DESCRIPTOR; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_ATTRIBUTE_DESCRIPTOR_procname);
end;

function ERR_OSSL_ATTRIBUTE_DESCRIPTOR_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ATTRIBUTE_DESCRIPTOR_it_procname);
end;

function ERR_OSSL_DAY_TIME_new: POSSL_DAY_TIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DAY_TIME_new_procname);
end;

procedure ERR_OSSL_DAY_TIME_free(a: POSSL_DAY_TIME); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DAY_TIME_free_procname);
end;

function ERR_d2i_OSSL_DAY_TIME(a: PPOSSL_DAY_TIME; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_DAY_TIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_DAY_TIME_procname);
end;

function ERR_i2d_OSSL_DAY_TIME(a: POSSL_DAY_TIME; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_DAY_TIME_procname);
end;

function ERR_OSSL_DAY_TIME_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DAY_TIME_it_procname);
end;

function ERR_OSSL_DAY_TIME_BAND_new: POSSL_DAY_TIME_BAND; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DAY_TIME_BAND_new_procname);
end;

procedure ERR_OSSL_DAY_TIME_BAND_free(a: POSSL_DAY_TIME_BAND); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DAY_TIME_BAND_free_procname);
end;

function ERR_d2i_OSSL_DAY_TIME_BAND(a: PPOSSL_DAY_TIME_BAND; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_DAY_TIME_BAND; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_DAY_TIME_BAND_procname);
end;

function ERR_i2d_OSSL_DAY_TIME_BAND(a: POSSL_DAY_TIME_BAND; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_DAY_TIME_BAND_procname);
end;

function ERR_OSSL_DAY_TIME_BAND_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DAY_TIME_BAND_it_procname);
end;

function ERR_OSSL_TIME_SPEC_DAY_new: POSSL_TIME_SPEC_DAY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TIME_SPEC_DAY_new_procname);
end;

procedure ERR_OSSL_TIME_SPEC_DAY_free(a: POSSL_TIME_SPEC_DAY); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TIME_SPEC_DAY_free_procname);
end;

function ERR_d2i_OSSL_TIME_SPEC_DAY(a: PPOSSL_TIME_SPEC_DAY; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_SPEC_DAY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_TIME_SPEC_DAY_procname);
end;

function ERR_i2d_OSSL_TIME_SPEC_DAY(a: POSSL_TIME_SPEC_DAY; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_TIME_SPEC_DAY_procname);
end;

function ERR_OSSL_TIME_SPEC_DAY_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TIME_SPEC_DAY_it_procname);
end;

function ERR_OSSL_TIME_SPEC_WEEKS_new: POSSL_TIME_SPEC_WEEKS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TIME_SPEC_WEEKS_new_procname);
end;

procedure ERR_OSSL_TIME_SPEC_WEEKS_free(a: POSSL_TIME_SPEC_WEEKS); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TIME_SPEC_WEEKS_free_procname);
end;

function ERR_d2i_OSSL_TIME_SPEC_WEEKS(a: PPOSSL_TIME_SPEC_WEEKS; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_SPEC_WEEKS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_TIME_SPEC_WEEKS_procname);
end;

function ERR_i2d_OSSL_TIME_SPEC_WEEKS(a: POSSL_TIME_SPEC_WEEKS; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_TIME_SPEC_WEEKS_procname);
end;

function ERR_OSSL_TIME_SPEC_WEEKS_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TIME_SPEC_WEEKS_it_procname);
end;

function ERR_OSSL_TIME_SPEC_MONTH_new: POSSL_TIME_SPEC_MONTH; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TIME_SPEC_MONTH_new_procname);
end;

procedure ERR_OSSL_TIME_SPEC_MONTH_free(a: POSSL_TIME_SPEC_MONTH); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TIME_SPEC_MONTH_free_procname);
end;

function ERR_d2i_OSSL_TIME_SPEC_MONTH(a: PPOSSL_TIME_SPEC_MONTH; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_SPEC_MONTH; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_TIME_SPEC_MONTH_procname);
end;

function ERR_i2d_OSSL_TIME_SPEC_MONTH(a: POSSL_TIME_SPEC_MONTH; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_TIME_SPEC_MONTH_procname);
end;

function ERR_OSSL_TIME_SPEC_MONTH_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TIME_SPEC_MONTH_it_procname);
end;

function ERR_OSSL_NAMED_DAY_new: POSSL_NAMED_DAY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_NAMED_DAY_new_procname);
end;

procedure ERR_OSSL_NAMED_DAY_free(a: POSSL_NAMED_DAY); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_NAMED_DAY_free_procname);
end;

function ERR_d2i_OSSL_NAMED_DAY(a: PPOSSL_NAMED_DAY; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_NAMED_DAY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_NAMED_DAY_procname);
end;

function ERR_i2d_OSSL_NAMED_DAY(a: POSSL_NAMED_DAY; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_NAMED_DAY_procname);
end;

function ERR_OSSL_NAMED_DAY_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_NAMED_DAY_it_procname);
end;

function ERR_OSSL_TIME_SPEC_X_DAY_OF_new: POSSL_TIME_SPEC_X_DAY_OF; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TIME_SPEC_X_DAY_OF_new_procname);
end;

procedure ERR_OSSL_TIME_SPEC_X_DAY_OF_free(a: POSSL_TIME_SPEC_X_DAY_OF); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TIME_SPEC_X_DAY_OF_free_procname);
end;

function ERR_d2i_OSSL_TIME_SPEC_X_DAY_OF(a: PPOSSL_TIME_SPEC_X_DAY_OF; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_SPEC_X_DAY_OF; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_TIME_SPEC_X_DAY_OF_procname);
end;

function ERR_i2d_OSSL_TIME_SPEC_X_DAY_OF(a: POSSL_TIME_SPEC_X_DAY_OF; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_TIME_SPEC_X_DAY_OF_procname);
end;

function ERR_OSSL_TIME_SPEC_X_DAY_OF_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TIME_SPEC_X_DAY_OF_it_procname);
end;

function ERR_OSSL_TIME_SPEC_ABSOLUTE_new: POSSL_TIME_SPEC_ABSOLUTE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TIME_SPEC_ABSOLUTE_new_procname);
end;

procedure ERR_OSSL_TIME_SPEC_ABSOLUTE_free(a: POSSL_TIME_SPEC_ABSOLUTE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TIME_SPEC_ABSOLUTE_free_procname);
end;

function ERR_d2i_OSSL_TIME_SPEC_ABSOLUTE(a: PPOSSL_TIME_SPEC_ABSOLUTE; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_SPEC_ABSOLUTE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_TIME_SPEC_ABSOLUTE_procname);
end;

function ERR_i2d_OSSL_TIME_SPEC_ABSOLUTE(a: POSSL_TIME_SPEC_ABSOLUTE; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_TIME_SPEC_ABSOLUTE_procname);
end;

function ERR_OSSL_TIME_SPEC_ABSOLUTE_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TIME_SPEC_ABSOLUTE_it_procname);
end;

function ERR_OSSL_TIME_SPEC_TIME_new: POSSL_TIME_SPEC_TIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TIME_SPEC_TIME_new_procname);
end;

procedure ERR_OSSL_TIME_SPEC_TIME_free(a: POSSL_TIME_SPEC_TIME); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TIME_SPEC_TIME_free_procname);
end;

function ERR_d2i_OSSL_TIME_SPEC_TIME(a: PPOSSL_TIME_SPEC_TIME; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_SPEC_TIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_TIME_SPEC_TIME_procname);
end;

function ERR_i2d_OSSL_TIME_SPEC_TIME(a: POSSL_TIME_SPEC_TIME; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_TIME_SPEC_TIME_procname);
end;

function ERR_OSSL_TIME_SPEC_TIME_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TIME_SPEC_TIME_it_procname);
end;

function ERR_OSSL_TIME_SPEC_new: POSSL_TIME_SPEC; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TIME_SPEC_new_procname);
end;

procedure ERR_OSSL_TIME_SPEC_free(a: POSSL_TIME_SPEC); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TIME_SPEC_free_procname);
end;

function ERR_d2i_OSSL_TIME_SPEC(a: PPOSSL_TIME_SPEC; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_SPEC; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_TIME_SPEC_procname);
end;

function ERR_i2d_OSSL_TIME_SPEC(a: POSSL_TIME_SPEC; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_TIME_SPEC_procname);
end;

function ERR_OSSL_TIME_SPEC_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TIME_SPEC_it_procname);
end;

function ERR_OSSL_TIME_PERIOD_new: POSSL_TIME_PERIOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TIME_PERIOD_new_procname);
end;

procedure ERR_OSSL_TIME_PERIOD_free(a: POSSL_TIME_PERIOD); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TIME_PERIOD_free_procname);
end;

function ERR_d2i_OSSL_TIME_PERIOD(a: PPOSSL_TIME_PERIOD; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TIME_PERIOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_TIME_PERIOD_procname);
end;

function ERR_i2d_OSSL_TIME_PERIOD(a: POSSL_TIME_PERIOD; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_TIME_PERIOD_procname);
end;

function ERR_OSSL_TIME_PERIOD_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TIME_PERIOD_it_procname);
end;

function ERR_OSSL_ATAV_new: POSSL_ATAV; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ATAV_new_procname);
end;

procedure ERR_OSSL_ATAV_free(a: POSSL_ATAV); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ATAV_free_procname);
end;

function ERR_d2i_OSSL_ATAV(a: PPOSSL_ATAV; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ATAV; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_ATAV_procname);
end;

function ERR_i2d_OSSL_ATAV(a: POSSL_ATAV; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_ATAV_procname);
end;

function ERR_OSSL_ATAV_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ATAV_it_procname);
end;

function ERR_OSSL_ATTRIBUTE_TYPE_MAPPING_new: POSSL_ATTRIBUTE_TYPE_MAPPING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ATTRIBUTE_TYPE_MAPPING_new_procname);
end;

procedure ERR_OSSL_ATTRIBUTE_TYPE_MAPPING_free(a: POSSL_ATTRIBUTE_TYPE_MAPPING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ATTRIBUTE_TYPE_MAPPING_free_procname);
end;

function ERR_d2i_OSSL_ATTRIBUTE_TYPE_MAPPING(a: PPOSSL_ATTRIBUTE_TYPE_MAPPING; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ATTRIBUTE_TYPE_MAPPING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_ATTRIBUTE_TYPE_MAPPING_procname);
end;

function ERR_i2d_OSSL_ATTRIBUTE_TYPE_MAPPING(a: POSSL_ATTRIBUTE_TYPE_MAPPING; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_ATTRIBUTE_TYPE_MAPPING_procname);
end;

function ERR_OSSL_ATTRIBUTE_TYPE_MAPPING_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ATTRIBUTE_TYPE_MAPPING_it_procname);
end;

function ERR_OSSL_ATTRIBUTE_VALUE_MAPPING_new: POSSL_ATTRIBUTE_VALUE_MAPPING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ATTRIBUTE_VALUE_MAPPING_new_procname);
end;

procedure ERR_OSSL_ATTRIBUTE_VALUE_MAPPING_free(a: POSSL_ATTRIBUTE_VALUE_MAPPING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ATTRIBUTE_VALUE_MAPPING_free_procname);
end;

function ERR_d2i_OSSL_ATTRIBUTE_VALUE_MAPPING(a: PPOSSL_ATTRIBUTE_VALUE_MAPPING; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ATTRIBUTE_VALUE_MAPPING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_ATTRIBUTE_VALUE_MAPPING_procname);
end;

function ERR_i2d_OSSL_ATTRIBUTE_VALUE_MAPPING(a: POSSL_ATTRIBUTE_VALUE_MAPPING; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_ATTRIBUTE_VALUE_MAPPING_procname);
end;

function ERR_OSSL_ATTRIBUTE_VALUE_MAPPING_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ATTRIBUTE_VALUE_MAPPING_it_procname);
end;

function ERR_OSSL_ATTRIBUTE_MAPPING_new: POSSL_ATTRIBUTE_MAPPING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ATTRIBUTE_MAPPING_new_procname);
end;

procedure ERR_OSSL_ATTRIBUTE_MAPPING_free(a: POSSL_ATTRIBUTE_MAPPING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ATTRIBUTE_MAPPING_free_procname);
end;

function ERR_d2i_OSSL_ATTRIBUTE_MAPPING(a: PPOSSL_ATTRIBUTE_MAPPING; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ATTRIBUTE_MAPPING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_ATTRIBUTE_MAPPING_procname);
end;

function ERR_i2d_OSSL_ATTRIBUTE_MAPPING(a: POSSL_ATTRIBUTE_MAPPING; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_ATTRIBUTE_MAPPING_procname);
end;

function ERR_OSSL_ATTRIBUTE_MAPPING_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ATTRIBUTE_MAPPING_it_procname);
end;

function ERR_OSSL_ATTRIBUTE_MAPPINGS_new: POSSL_ATTRIBUTE_MAPPINGS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ATTRIBUTE_MAPPINGS_new_procname);
end;

procedure ERR_OSSL_ATTRIBUTE_MAPPINGS_free(a: POSSL_ATTRIBUTE_MAPPINGS); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ATTRIBUTE_MAPPINGS_free_procname);
end;

function ERR_d2i_OSSL_ATTRIBUTE_MAPPINGS(a: PPOSSL_ATTRIBUTE_MAPPINGS; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ATTRIBUTE_MAPPINGS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_ATTRIBUTE_MAPPINGS_procname);
end;

function ERR_i2d_OSSL_ATTRIBUTE_MAPPINGS(a: POSSL_ATTRIBUTE_MAPPINGS; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_ATTRIBUTE_MAPPINGS_procname);
end;

function ERR_OSSL_ATTRIBUTE_MAPPINGS_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ATTRIBUTE_MAPPINGS_it_procname);
end;

function ERR_OSSL_ALLOWED_ATTRIBUTES_CHOICE_new: POSSL_ALLOWED_ATTRIBUTES_CHOICE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ALLOWED_ATTRIBUTES_CHOICE_new_procname);
end;

procedure ERR_OSSL_ALLOWED_ATTRIBUTES_CHOICE_free(a: POSSL_ALLOWED_ATTRIBUTES_CHOICE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ALLOWED_ATTRIBUTES_CHOICE_free_procname);
end;

function ERR_d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE(a: PPOSSL_ALLOWED_ATTRIBUTES_CHOICE; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ALLOWED_ATTRIBUTES_CHOICE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE_procname);
end;

function ERR_i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE(a: POSSL_ALLOWED_ATTRIBUTES_CHOICE; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE_procname);
end;

function ERR_OSSL_ALLOWED_ATTRIBUTES_CHOICE_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ALLOWED_ATTRIBUTES_CHOICE_it_procname);
end;

function ERR_OSSL_ALLOWED_ATTRIBUTES_ITEM_new: POSSL_ALLOWED_ATTRIBUTES_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ALLOWED_ATTRIBUTES_ITEM_new_procname);
end;

procedure ERR_OSSL_ALLOWED_ATTRIBUTES_ITEM_free(a: POSSL_ALLOWED_ATTRIBUTES_ITEM); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ALLOWED_ATTRIBUTES_ITEM_free_procname);
end;

function ERR_d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM(a: PPOSSL_ALLOWED_ATTRIBUTES_ITEM; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ALLOWED_ATTRIBUTES_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM_procname);
end;

function ERR_i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM(a: POSSL_ALLOWED_ATTRIBUTES_ITEM; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM_procname);
end;

function ERR_OSSL_ALLOWED_ATTRIBUTES_ITEM_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ALLOWED_ATTRIBUTES_ITEM_it_procname);
end;

function ERR_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new: POSSL_ALLOWED_ATTRIBUTES_SYNTAX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new_procname);
end;

procedure ERR_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free(a: POSSL_ALLOWED_ATTRIBUTES_SYNTAX); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free_procname);
end;

function ERR_d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX(a: PPOSSL_ALLOWED_ATTRIBUTES_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_ALLOWED_ATTRIBUTES_SYNTAX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_procname);
end;

function ERR_i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX(a: POSSL_ALLOWED_ATTRIBUTES_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_procname);
end;

function ERR_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it_procname);
end;

function ERR_OSSL_AA_DIST_POINT_new: POSSL_AA_DIST_POINT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_AA_DIST_POINT_new_procname);
end;

procedure ERR_OSSL_AA_DIST_POINT_free(a: POSSL_AA_DIST_POINT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_AA_DIST_POINT_free_procname);
end;

function ERR_d2i_OSSL_AA_DIST_POINT(a: PPOSSL_AA_DIST_POINT; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_AA_DIST_POINT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_AA_DIST_POINT_procname);
end;

function ERR_i2d_OSSL_AA_DIST_POINT(a: POSSL_AA_DIST_POINT; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_AA_DIST_POINT_procname);
end;

function ERR_OSSL_AA_DIST_POINT_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_AA_DIST_POINT_it_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  GENERAL_NAME_set1_X509_NAME := LoadLibFunction(ADllHandle, GENERAL_NAME_set1_X509_NAME_procname);
  FuncLoadError := not assigned(GENERAL_NAME_set1_X509_NAME);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_NAME_set1_X509_NAME_allownil)}
    GENERAL_NAME_set1_X509_NAME := ERR_GENERAL_NAME_set1_X509_NAME;
    {$ifend}
    {$if declared(GENERAL_NAME_set1_X509_NAME_introduced)}
    if LibVersion < GENERAL_NAME_set1_X509_NAME_introduced then
    begin
      {$if declared(FC_GENERAL_NAME_set1_X509_NAME)}
      GENERAL_NAME_set1_X509_NAME := FC_GENERAL_NAME_set1_X509_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_NAME_set1_X509_NAME_removed)}
    if GENERAL_NAME_set1_X509_NAME_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_NAME_set1_X509_NAME)}
      GENERAL_NAME_set1_X509_NAME := _GENERAL_NAME_set1_X509_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_NAME_set1_X509_NAME_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_NAME_set1_X509_NAME');
    {$ifend}
  end;
  
  DIST_POINT_NAME_dup := LoadLibFunction(ADllHandle, DIST_POINT_NAME_dup_procname);
  FuncLoadError := not assigned(DIST_POINT_NAME_dup);
  if FuncLoadError then
  begin
    {$if not defined(DIST_POINT_NAME_dup_allownil)}
    DIST_POINT_NAME_dup := ERR_DIST_POINT_NAME_dup;
    {$ifend}
    {$if declared(DIST_POINT_NAME_dup_introduced)}
    if LibVersion < DIST_POINT_NAME_dup_introduced then
    begin
      {$if declared(FC_DIST_POINT_NAME_dup)}
      DIST_POINT_NAME_dup := FC_DIST_POINT_NAME_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DIST_POINT_NAME_dup_removed)}
    if DIST_POINT_NAME_dup_removed <= LibVersion then
    begin
      {$if declared(_DIST_POINT_NAME_dup)}
      DIST_POINT_NAME_dup := _DIST_POINT_NAME_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DIST_POINT_NAME_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('DIST_POINT_NAME_dup');
    {$ifend}
  end;
  
  PROXY_POLICY_new := LoadLibFunction(ADllHandle, PROXY_POLICY_new_procname);
  FuncLoadError := not assigned(PROXY_POLICY_new);
  if FuncLoadError then
  begin
    {$if not defined(PROXY_POLICY_new_allownil)}
    PROXY_POLICY_new := ERR_PROXY_POLICY_new;
    {$ifend}
    {$if declared(PROXY_POLICY_new_introduced)}
    if LibVersion < PROXY_POLICY_new_introduced then
    begin
      {$if declared(FC_PROXY_POLICY_new)}
      PROXY_POLICY_new := FC_PROXY_POLICY_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROXY_POLICY_new_removed)}
    if PROXY_POLICY_new_removed <= LibVersion then
    begin
      {$if declared(_PROXY_POLICY_new)}
      PROXY_POLICY_new := _PROXY_POLICY_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROXY_POLICY_new_allownil)}
    if FuncLoadError then
      AFailed.Add('PROXY_POLICY_new');
    {$ifend}
  end;
  
  PROXY_POLICY_free := LoadLibFunction(ADllHandle, PROXY_POLICY_free_procname);
  FuncLoadError := not assigned(PROXY_POLICY_free);
  if FuncLoadError then
  begin
    {$if not defined(PROXY_POLICY_free_allownil)}
    PROXY_POLICY_free := ERR_PROXY_POLICY_free;
    {$ifend}
    {$if declared(PROXY_POLICY_free_introduced)}
    if LibVersion < PROXY_POLICY_free_introduced then
    begin
      {$if declared(FC_PROXY_POLICY_free)}
      PROXY_POLICY_free := FC_PROXY_POLICY_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROXY_POLICY_free_removed)}
    if PROXY_POLICY_free_removed <= LibVersion then
    begin
      {$if declared(_PROXY_POLICY_free)}
      PROXY_POLICY_free := _PROXY_POLICY_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROXY_POLICY_free_allownil)}
    if FuncLoadError then
      AFailed.Add('PROXY_POLICY_free');
    {$ifend}
  end;
  
  d2i_PROXY_POLICY := LoadLibFunction(ADllHandle, d2i_PROXY_POLICY_procname);
  FuncLoadError := not assigned(d2i_PROXY_POLICY);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PROXY_POLICY_allownil)}
    d2i_PROXY_POLICY := ERR_d2i_PROXY_POLICY;
    {$ifend}
    {$if declared(d2i_PROXY_POLICY_introduced)}
    if LibVersion < d2i_PROXY_POLICY_introduced then
    begin
      {$if declared(FC_d2i_PROXY_POLICY)}
      d2i_PROXY_POLICY := FC_d2i_PROXY_POLICY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PROXY_POLICY_removed)}
    if d2i_PROXY_POLICY_removed <= LibVersion then
    begin
      {$if declared(_d2i_PROXY_POLICY)}
      d2i_PROXY_POLICY := _d2i_PROXY_POLICY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PROXY_POLICY_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PROXY_POLICY');
    {$ifend}
  end;
  
  i2d_PROXY_POLICY := LoadLibFunction(ADllHandle, i2d_PROXY_POLICY_procname);
  FuncLoadError := not assigned(i2d_PROXY_POLICY);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PROXY_POLICY_allownil)}
    i2d_PROXY_POLICY := ERR_i2d_PROXY_POLICY;
    {$ifend}
    {$if declared(i2d_PROXY_POLICY_introduced)}
    if LibVersion < i2d_PROXY_POLICY_introduced then
    begin
      {$if declared(FC_i2d_PROXY_POLICY)}
      i2d_PROXY_POLICY := FC_i2d_PROXY_POLICY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PROXY_POLICY_removed)}
    if i2d_PROXY_POLICY_removed <= LibVersion then
    begin
      {$if declared(_i2d_PROXY_POLICY)}
      i2d_PROXY_POLICY := _i2d_PROXY_POLICY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PROXY_POLICY_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PROXY_POLICY');
    {$ifend}
  end;
  
  PROXY_POLICY_it := LoadLibFunction(ADllHandle, PROXY_POLICY_it_procname);
  FuncLoadError := not assigned(PROXY_POLICY_it);
  if FuncLoadError then
  begin
    {$if not defined(PROXY_POLICY_it_allownil)}
    PROXY_POLICY_it := ERR_PROXY_POLICY_it;
    {$ifend}
    {$if declared(PROXY_POLICY_it_introduced)}
    if LibVersion < PROXY_POLICY_it_introduced then
    begin
      {$if declared(FC_PROXY_POLICY_it)}
      PROXY_POLICY_it := FC_PROXY_POLICY_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROXY_POLICY_it_removed)}
    if PROXY_POLICY_it_removed <= LibVersion then
    begin
      {$if declared(_PROXY_POLICY_it)}
      PROXY_POLICY_it := _PROXY_POLICY_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROXY_POLICY_it_allownil)}
    if FuncLoadError then
      AFailed.Add('PROXY_POLICY_it');
    {$ifend}
  end;
  
  PROXY_CERT_INFO_EXTENSION_new := LoadLibFunction(ADllHandle, PROXY_CERT_INFO_EXTENSION_new_procname);
  FuncLoadError := not assigned(PROXY_CERT_INFO_EXTENSION_new);
  if FuncLoadError then
  begin
    {$if not defined(PROXY_CERT_INFO_EXTENSION_new_allownil)}
    PROXY_CERT_INFO_EXTENSION_new := ERR_PROXY_CERT_INFO_EXTENSION_new;
    {$ifend}
    {$if declared(PROXY_CERT_INFO_EXTENSION_new_introduced)}
    if LibVersion < PROXY_CERT_INFO_EXTENSION_new_introduced then
    begin
      {$if declared(FC_PROXY_CERT_INFO_EXTENSION_new)}
      PROXY_CERT_INFO_EXTENSION_new := FC_PROXY_CERT_INFO_EXTENSION_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROXY_CERT_INFO_EXTENSION_new_removed)}
    if PROXY_CERT_INFO_EXTENSION_new_removed <= LibVersion then
    begin
      {$if declared(_PROXY_CERT_INFO_EXTENSION_new)}
      PROXY_CERT_INFO_EXTENSION_new := _PROXY_CERT_INFO_EXTENSION_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROXY_CERT_INFO_EXTENSION_new_allownil)}
    if FuncLoadError then
      AFailed.Add('PROXY_CERT_INFO_EXTENSION_new');
    {$ifend}
  end;
  
  PROXY_CERT_INFO_EXTENSION_free := LoadLibFunction(ADllHandle, PROXY_CERT_INFO_EXTENSION_free_procname);
  FuncLoadError := not assigned(PROXY_CERT_INFO_EXTENSION_free);
  if FuncLoadError then
  begin
    {$if not defined(PROXY_CERT_INFO_EXTENSION_free_allownil)}
    PROXY_CERT_INFO_EXTENSION_free := ERR_PROXY_CERT_INFO_EXTENSION_free;
    {$ifend}
    {$if declared(PROXY_CERT_INFO_EXTENSION_free_introduced)}
    if LibVersion < PROXY_CERT_INFO_EXTENSION_free_introduced then
    begin
      {$if declared(FC_PROXY_CERT_INFO_EXTENSION_free)}
      PROXY_CERT_INFO_EXTENSION_free := FC_PROXY_CERT_INFO_EXTENSION_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROXY_CERT_INFO_EXTENSION_free_removed)}
    if PROXY_CERT_INFO_EXTENSION_free_removed <= LibVersion then
    begin
      {$if declared(_PROXY_CERT_INFO_EXTENSION_free)}
      PROXY_CERT_INFO_EXTENSION_free := _PROXY_CERT_INFO_EXTENSION_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROXY_CERT_INFO_EXTENSION_free_allownil)}
    if FuncLoadError then
      AFailed.Add('PROXY_CERT_INFO_EXTENSION_free');
    {$ifend}
  end;
  
  d2i_PROXY_CERT_INFO_EXTENSION := LoadLibFunction(ADllHandle, d2i_PROXY_CERT_INFO_EXTENSION_procname);
  FuncLoadError := not assigned(d2i_PROXY_CERT_INFO_EXTENSION);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PROXY_CERT_INFO_EXTENSION_allownil)}
    d2i_PROXY_CERT_INFO_EXTENSION := ERR_d2i_PROXY_CERT_INFO_EXTENSION;
    {$ifend}
    {$if declared(d2i_PROXY_CERT_INFO_EXTENSION_introduced)}
    if LibVersion < d2i_PROXY_CERT_INFO_EXTENSION_introduced then
    begin
      {$if declared(FC_d2i_PROXY_CERT_INFO_EXTENSION)}
      d2i_PROXY_CERT_INFO_EXTENSION := FC_d2i_PROXY_CERT_INFO_EXTENSION;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PROXY_CERT_INFO_EXTENSION_removed)}
    if d2i_PROXY_CERT_INFO_EXTENSION_removed <= LibVersion then
    begin
      {$if declared(_d2i_PROXY_CERT_INFO_EXTENSION)}
      d2i_PROXY_CERT_INFO_EXTENSION := _d2i_PROXY_CERT_INFO_EXTENSION;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PROXY_CERT_INFO_EXTENSION_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PROXY_CERT_INFO_EXTENSION');
    {$ifend}
  end;
  
  i2d_PROXY_CERT_INFO_EXTENSION := LoadLibFunction(ADllHandle, i2d_PROXY_CERT_INFO_EXTENSION_procname);
  FuncLoadError := not assigned(i2d_PROXY_CERT_INFO_EXTENSION);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PROXY_CERT_INFO_EXTENSION_allownil)}
    i2d_PROXY_CERT_INFO_EXTENSION := ERR_i2d_PROXY_CERT_INFO_EXTENSION;
    {$ifend}
    {$if declared(i2d_PROXY_CERT_INFO_EXTENSION_introduced)}
    if LibVersion < i2d_PROXY_CERT_INFO_EXTENSION_introduced then
    begin
      {$if declared(FC_i2d_PROXY_CERT_INFO_EXTENSION)}
      i2d_PROXY_CERT_INFO_EXTENSION := FC_i2d_PROXY_CERT_INFO_EXTENSION;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PROXY_CERT_INFO_EXTENSION_removed)}
    if i2d_PROXY_CERT_INFO_EXTENSION_removed <= LibVersion then
    begin
      {$if declared(_i2d_PROXY_CERT_INFO_EXTENSION)}
      i2d_PROXY_CERT_INFO_EXTENSION := _i2d_PROXY_CERT_INFO_EXTENSION;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PROXY_CERT_INFO_EXTENSION_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PROXY_CERT_INFO_EXTENSION');
    {$ifend}
  end;
  
  PROXY_CERT_INFO_EXTENSION_it := LoadLibFunction(ADllHandle, PROXY_CERT_INFO_EXTENSION_it_procname);
  FuncLoadError := not assigned(PROXY_CERT_INFO_EXTENSION_it);
  if FuncLoadError then
  begin
    {$if not defined(PROXY_CERT_INFO_EXTENSION_it_allownil)}
    PROXY_CERT_INFO_EXTENSION_it := ERR_PROXY_CERT_INFO_EXTENSION_it;
    {$ifend}
    {$if declared(PROXY_CERT_INFO_EXTENSION_it_introduced)}
    if LibVersion < PROXY_CERT_INFO_EXTENSION_it_introduced then
    begin
      {$if declared(FC_PROXY_CERT_INFO_EXTENSION_it)}
      PROXY_CERT_INFO_EXTENSION_it := FC_PROXY_CERT_INFO_EXTENSION_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROXY_CERT_INFO_EXTENSION_it_removed)}
    if PROXY_CERT_INFO_EXTENSION_it_removed <= LibVersion then
    begin
      {$if declared(_PROXY_CERT_INFO_EXTENSION_it)}
      PROXY_CERT_INFO_EXTENSION_it := _PROXY_CERT_INFO_EXTENSION_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROXY_CERT_INFO_EXTENSION_it_allownil)}
    if FuncLoadError then
      AFailed.Add('PROXY_CERT_INFO_EXTENSION_it');
    {$ifend}
  end;
  
  BASIC_CONSTRAINTS_new := LoadLibFunction(ADllHandle, BASIC_CONSTRAINTS_new_procname);
  FuncLoadError := not assigned(BASIC_CONSTRAINTS_new);
  if FuncLoadError then
  begin
    {$if not defined(BASIC_CONSTRAINTS_new_allownil)}
    BASIC_CONSTRAINTS_new := ERR_BASIC_CONSTRAINTS_new;
    {$ifend}
    {$if declared(BASIC_CONSTRAINTS_new_introduced)}
    if LibVersion < BASIC_CONSTRAINTS_new_introduced then
    begin
      {$if declared(FC_BASIC_CONSTRAINTS_new)}
      BASIC_CONSTRAINTS_new := FC_BASIC_CONSTRAINTS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BASIC_CONSTRAINTS_new_removed)}
    if BASIC_CONSTRAINTS_new_removed <= LibVersion then
    begin
      {$if declared(_BASIC_CONSTRAINTS_new)}
      BASIC_CONSTRAINTS_new := _BASIC_CONSTRAINTS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BASIC_CONSTRAINTS_new_allownil)}
    if FuncLoadError then
      AFailed.Add('BASIC_CONSTRAINTS_new');
    {$ifend}
  end;
  
  BASIC_CONSTRAINTS_free := LoadLibFunction(ADllHandle, BASIC_CONSTRAINTS_free_procname);
  FuncLoadError := not assigned(BASIC_CONSTRAINTS_free);
  if FuncLoadError then
  begin
    {$if not defined(BASIC_CONSTRAINTS_free_allownil)}
    BASIC_CONSTRAINTS_free := ERR_BASIC_CONSTRAINTS_free;
    {$ifend}
    {$if declared(BASIC_CONSTRAINTS_free_introduced)}
    if LibVersion < BASIC_CONSTRAINTS_free_introduced then
    begin
      {$if declared(FC_BASIC_CONSTRAINTS_free)}
      BASIC_CONSTRAINTS_free := FC_BASIC_CONSTRAINTS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BASIC_CONSTRAINTS_free_removed)}
    if BASIC_CONSTRAINTS_free_removed <= LibVersion then
    begin
      {$if declared(_BASIC_CONSTRAINTS_free)}
      BASIC_CONSTRAINTS_free := _BASIC_CONSTRAINTS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BASIC_CONSTRAINTS_free_allownil)}
    if FuncLoadError then
      AFailed.Add('BASIC_CONSTRAINTS_free');
    {$ifend}
  end;
  
  d2i_BASIC_CONSTRAINTS := LoadLibFunction(ADllHandle, d2i_BASIC_CONSTRAINTS_procname);
  FuncLoadError := not assigned(d2i_BASIC_CONSTRAINTS);
  if FuncLoadError then
  begin
    {$if not defined(d2i_BASIC_CONSTRAINTS_allownil)}
    d2i_BASIC_CONSTRAINTS := ERR_d2i_BASIC_CONSTRAINTS;
    {$ifend}
    {$if declared(d2i_BASIC_CONSTRAINTS_introduced)}
    if LibVersion < d2i_BASIC_CONSTRAINTS_introduced then
    begin
      {$if declared(FC_d2i_BASIC_CONSTRAINTS)}
      d2i_BASIC_CONSTRAINTS := FC_d2i_BASIC_CONSTRAINTS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_BASIC_CONSTRAINTS_removed)}
    if d2i_BASIC_CONSTRAINTS_removed <= LibVersion then
    begin
      {$if declared(_d2i_BASIC_CONSTRAINTS)}
      d2i_BASIC_CONSTRAINTS := _d2i_BASIC_CONSTRAINTS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_BASIC_CONSTRAINTS_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_BASIC_CONSTRAINTS');
    {$ifend}
  end;
  
  i2d_BASIC_CONSTRAINTS := LoadLibFunction(ADllHandle, i2d_BASIC_CONSTRAINTS_procname);
  FuncLoadError := not assigned(i2d_BASIC_CONSTRAINTS);
  if FuncLoadError then
  begin
    {$if not defined(i2d_BASIC_CONSTRAINTS_allownil)}
    i2d_BASIC_CONSTRAINTS := ERR_i2d_BASIC_CONSTRAINTS;
    {$ifend}
    {$if declared(i2d_BASIC_CONSTRAINTS_introduced)}
    if LibVersion < i2d_BASIC_CONSTRAINTS_introduced then
    begin
      {$if declared(FC_i2d_BASIC_CONSTRAINTS)}
      i2d_BASIC_CONSTRAINTS := FC_i2d_BASIC_CONSTRAINTS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_BASIC_CONSTRAINTS_removed)}
    if i2d_BASIC_CONSTRAINTS_removed <= LibVersion then
    begin
      {$if declared(_i2d_BASIC_CONSTRAINTS)}
      i2d_BASIC_CONSTRAINTS := _i2d_BASIC_CONSTRAINTS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_BASIC_CONSTRAINTS_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_BASIC_CONSTRAINTS');
    {$ifend}
  end;
  
  BASIC_CONSTRAINTS_it := LoadLibFunction(ADllHandle, BASIC_CONSTRAINTS_it_procname);
  FuncLoadError := not assigned(BASIC_CONSTRAINTS_it);
  if FuncLoadError then
  begin
    {$if not defined(BASIC_CONSTRAINTS_it_allownil)}
    BASIC_CONSTRAINTS_it := ERR_BASIC_CONSTRAINTS_it;
    {$ifend}
    {$if declared(BASIC_CONSTRAINTS_it_introduced)}
    if LibVersion < BASIC_CONSTRAINTS_it_introduced then
    begin
      {$if declared(FC_BASIC_CONSTRAINTS_it)}
      BASIC_CONSTRAINTS_it := FC_BASIC_CONSTRAINTS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BASIC_CONSTRAINTS_it_removed)}
    if BASIC_CONSTRAINTS_it_removed <= LibVersion then
    begin
      {$if declared(_BASIC_CONSTRAINTS_it)}
      BASIC_CONSTRAINTS_it := _BASIC_CONSTRAINTS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BASIC_CONSTRAINTS_it_allownil)}
    if FuncLoadError then
      AFailed.Add('BASIC_CONSTRAINTS_it');
    {$ifend}
  end;
  
  OSSL_BASIC_ATTR_CONSTRAINTS_new := LoadLibFunction(ADllHandle, OSSL_BASIC_ATTR_CONSTRAINTS_new_procname);
  FuncLoadError := not assigned(OSSL_BASIC_ATTR_CONSTRAINTS_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_BASIC_ATTR_CONSTRAINTS_new_allownil)}
    OSSL_BASIC_ATTR_CONSTRAINTS_new := ERR_OSSL_BASIC_ATTR_CONSTRAINTS_new;
    {$ifend}
    {$if declared(OSSL_BASIC_ATTR_CONSTRAINTS_new_introduced)}
    if LibVersion < OSSL_BASIC_ATTR_CONSTRAINTS_new_introduced then
    begin
      {$if declared(FC_OSSL_BASIC_ATTR_CONSTRAINTS_new)}
      OSSL_BASIC_ATTR_CONSTRAINTS_new := FC_OSSL_BASIC_ATTR_CONSTRAINTS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_BASIC_ATTR_CONSTRAINTS_new_removed)}
    if OSSL_BASIC_ATTR_CONSTRAINTS_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_BASIC_ATTR_CONSTRAINTS_new)}
      OSSL_BASIC_ATTR_CONSTRAINTS_new := _OSSL_BASIC_ATTR_CONSTRAINTS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_BASIC_ATTR_CONSTRAINTS_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_BASIC_ATTR_CONSTRAINTS_new');
    {$ifend}
  end;
  
  OSSL_BASIC_ATTR_CONSTRAINTS_free := LoadLibFunction(ADllHandle, OSSL_BASIC_ATTR_CONSTRAINTS_free_procname);
  FuncLoadError := not assigned(OSSL_BASIC_ATTR_CONSTRAINTS_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_BASIC_ATTR_CONSTRAINTS_free_allownil)}
    OSSL_BASIC_ATTR_CONSTRAINTS_free := ERR_OSSL_BASIC_ATTR_CONSTRAINTS_free;
    {$ifend}
    {$if declared(OSSL_BASIC_ATTR_CONSTRAINTS_free_introduced)}
    if LibVersion < OSSL_BASIC_ATTR_CONSTRAINTS_free_introduced then
    begin
      {$if declared(FC_OSSL_BASIC_ATTR_CONSTRAINTS_free)}
      OSSL_BASIC_ATTR_CONSTRAINTS_free := FC_OSSL_BASIC_ATTR_CONSTRAINTS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_BASIC_ATTR_CONSTRAINTS_free_removed)}
    if OSSL_BASIC_ATTR_CONSTRAINTS_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_BASIC_ATTR_CONSTRAINTS_free)}
      OSSL_BASIC_ATTR_CONSTRAINTS_free := _OSSL_BASIC_ATTR_CONSTRAINTS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_BASIC_ATTR_CONSTRAINTS_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_BASIC_ATTR_CONSTRAINTS_free');
    {$ifend}
  end;
  
  d2i_OSSL_BASIC_ATTR_CONSTRAINTS := LoadLibFunction(ADllHandle, d2i_OSSL_BASIC_ATTR_CONSTRAINTS_procname);
  FuncLoadError := not assigned(d2i_OSSL_BASIC_ATTR_CONSTRAINTS);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_BASIC_ATTR_CONSTRAINTS_allownil)}
    d2i_OSSL_BASIC_ATTR_CONSTRAINTS := ERR_d2i_OSSL_BASIC_ATTR_CONSTRAINTS;
    {$ifend}
    {$if declared(d2i_OSSL_BASIC_ATTR_CONSTRAINTS_introduced)}
    if LibVersion < d2i_OSSL_BASIC_ATTR_CONSTRAINTS_introduced then
    begin
      {$if declared(FC_d2i_OSSL_BASIC_ATTR_CONSTRAINTS)}
      d2i_OSSL_BASIC_ATTR_CONSTRAINTS := FC_d2i_OSSL_BASIC_ATTR_CONSTRAINTS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_BASIC_ATTR_CONSTRAINTS_removed)}
    if d2i_OSSL_BASIC_ATTR_CONSTRAINTS_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_BASIC_ATTR_CONSTRAINTS)}
      d2i_OSSL_BASIC_ATTR_CONSTRAINTS := _d2i_OSSL_BASIC_ATTR_CONSTRAINTS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_BASIC_ATTR_CONSTRAINTS_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_BASIC_ATTR_CONSTRAINTS');
    {$ifend}
  end;
  
  i2d_OSSL_BASIC_ATTR_CONSTRAINTS := LoadLibFunction(ADllHandle, i2d_OSSL_BASIC_ATTR_CONSTRAINTS_procname);
  FuncLoadError := not assigned(i2d_OSSL_BASIC_ATTR_CONSTRAINTS);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_BASIC_ATTR_CONSTRAINTS_allownil)}
    i2d_OSSL_BASIC_ATTR_CONSTRAINTS := ERR_i2d_OSSL_BASIC_ATTR_CONSTRAINTS;
    {$ifend}
    {$if declared(i2d_OSSL_BASIC_ATTR_CONSTRAINTS_introduced)}
    if LibVersion < i2d_OSSL_BASIC_ATTR_CONSTRAINTS_introduced then
    begin
      {$if declared(FC_i2d_OSSL_BASIC_ATTR_CONSTRAINTS)}
      i2d_OSSL_BASIC_ATTR_CONSTRAINTS := FC_i2d_OSSL_BASIC_ATTR_CONSTRAINTS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_BASIC_ATTR_CONSTRAINTS_removed)}
    if i2d_OSSL_BASIC_ATTR_CONSTRAINTS_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_BASIC_ATTR_CONSTRAINTS)}
      i2d_OSSL_BASIC_ATTR_CONSTRAINTS := _i2d_OSSL_BASIC_ATTR_CONSTRAINTS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_BASIC_ATTR_CONSTRAINTS_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_BASIC_ATTR_CONSTRAINTS');
    {$ifend}
  end;
  
  OSSL_BASIC_ATTR_CONSTRAINTS_it := LoadLibFunction(ADllHandle, OSSL_BASIC_ATTR_CONSTRAINTS_it_procname);
  FuncLoadError := not assigned(OSSL_BASIC_ATTR_CONSTRAINTS_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_BASIC_ATTR_CONSTRAINTS_it_allownil)}
    OSSL_BASIC_ATTR_CONSTRAINTS_it := ERR_OSSL_BASIC_ATTR_CONSTRAINTS_it;
    {$ifend}
    {$if declared(OSSL_BASIC_ATTR_CONSTRAINTS_it_introduced)}
    if LibVersion < OSSL_BASIC_ATTR_CONSTRAINTS_it_introduced then
    begin
      {$if declared(FC_OSSL_BASIC_ATTR_CONSTRAINTS_it)}
      OSSL_BASIC_ATTR_CONSTRAINTS_it := FC_OSSL_BASIC_ATTR_CONSTRAINTS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_BASIC_ATTR_CONSTRAINTS_it_removed)}
    if OSSL_BASIC_ATTR_CONSTRAINTS_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_BASIC_ATTR_CONSTRAINTS_it)}
      OSSL_BASIC_ATTR_CONSTRAINTS_it := _OSSL_BASIC_ATTR_CONSTRAINTS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_BASIC_ATTR_CONSTRAINTS_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_BASIC_ATTR_CONSTRAINTS_it');
    {$ifend}
  end;
  
  SXNET_new := LoadLibFunction(ADllHandle, SXNET_new_procname);
  FuncLoadError := not assigned(SXNET_new);
  if FuncLoadError then
  begin
    {$if not defined(SXNET_new_allownil)}
    SXNET_new := ERR_SXNET_new;
    {$ifend}
    {$if declared(SXNET_new_introduced)}
    if LibVersion < SXNET_new_introduced then
    begin
      {$if declared(FC_SXNET_new)}
      SXNET_new := FC_SXNET_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SXNET_new_removed)}
    if SXNET_new_removed <= LibVersion then
    begin
      {$if declared(_SXNET_new)}
      SXNET_new := _SXNET_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SXNET_new_allownil)}
    if FuncLoadError then
      AFailed.Add('SXNET_new');
    {$ifend}
  end;
  
  SXNET_free := LoadLibFunction(ADllHandle, SXNET_free_procname);
  FuncLoadError := not assigned(SXNET_free);
  if FuncLoadError then
  begin
    {$if not defined(SXNET_free_allownil)}
    SXNET_free := ERR_SXNET_free;
    {$ifend}
    {$if declared(SXNET_free_introduced)}
    if LibVersion < SXNET_free_introduced then
    begin
      {$if declared(FC_SXNET_free)}
      SXNET_free := FC_SXNET_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SXNET_free_removed)}
    if SXNET_free_removed <= LibVersion then
    begin
      {$if declared(_SXNET_free)}
      SXNET_free := _SXNET_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SXNET_free_allownil)}
    if FuncLoadError then
      AFailed.Add('SXNET_free');
    {$ifend}
  end;
  
  d2i_SXNET := LoadLibFunction(ADllHandle, d2i_SXNET_procname);
  FuncLoadError := not assigned(d2i_SXNET);
  if FuncLoadError then
  begin
    {$if not defined(d2i_SXNET_allownil)}
    d2i_SXNET := ERR_d2i_SXNET;
    {$ifend}
    {$if declared(d2i_SXNET_introduced)}
    if LibVersion < d2i_SXNET_introduced then
    begin
      {$if declared(FC_d2i_SXNET)}
      d2i_SXNET := FC_d2i_SXNET;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_SXNET_removed)}
    if d2i_SXNET_removed <= LibVersion then
    begin
      {$if declared(_d2i_SXNET)}
      d2i_SXNET := _d2i_SXNET;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_SXNET_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_SXNET');
    {$ifend}
  end;
  
  i2d_SXNET := LoadLibFunction(ADllHandle, i2d_SXNET_procname);
  FuncLoadError := not assigned(i2d_SXNET);
  if FuncLoadError then
  begin
    {$if not defined(i2d_SXNET_allownil)}
    i2d_SXNET := ERR_i2d_SXNET;
    {$ifend}
    {$if declared(i2d_SXNET_introduced)}
    if LibVersion < i2d_SXNET_introduced then
    begin
      {$if declared(FC_i2d_SXNET)}
      i2d_SXNET := FC_i2d_SXNET;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_SXNET_removed)}
    if i2d_SXNET_removed <= LibVersion then
    begin
      {$if declared(_i2d_SXNET)}
      i2d_SXNET := _i2d_SXNET;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_SXNET_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_SXNET');
    {$ifend}
  end;
  
  SXNET_it := LoadLibFunction(ADllHandle, SXNET_it_procname);
  FuncLoadError := not assigned(SXNET_it);
  if FuncLoadError then
  begin
    {$if not defined(SXNET_it_allownil)}
    SXNET_it := ERR_SXNET_it;
    {$ifend}
    {$if declared(SXNET_it_introduced)}
    if LibVersion < SXNET_it_introduced then
    begin
      {$if declared(FC_SXNET_it)}
      SXNET_it := FC_SXNET_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SXNET_it_removed)}
    if SXNET_it_removed <= LibVersion then
    begin
      {$if declared(_SXNET_it)}
      SXNET_it := _SXNET_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SXNET_it_allownil)}
    if FuncLoadError then
      AFailed.Add('SXNET_it');
    {$ifend}
  end;
  
  SXNETID_new := LoadLibFunction(ADllHandle, SXNETID_new_procname);
  FuncLoadError := not assigned(SXNETID_new);
  if FuncLoadError then
  begin
    {$if not defined(SXNETID_new_allownil)}
    SXNETID_new := ERR_SXNETID_new;
    {$ifend}
    {$if declared(SXNETID_new_introduced)}
    if LibVersion < SXNETID_new_introduced then
    begin
      {$if declared(FC_SXNETID_new)}
      SXNETID_new := FC_SXNETID_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SXNETID_new_removed)}
    if SXNETID_new_removed <= LibVersion then
    begin
      {$if declared(_SXNETID_new)}
      SXNETID_new := _SXNETID_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SXNETID_new_allownil)}
    if FuncLoadError then
      AFailed.Add('SXNETID_new');
    {$ifend}
  end;
  
  SXNETID_free := LoadLibFunction(ADllHandle, SXNETID_free_procname);
  FuncLoadError := not assigned(SXNETID_free);
  if FuncLoadError then
  begin
    {$if not defined(SXNETID_free_allownil)}
    SXNETID_free := ERR_SXNETID_free;
    {$ifend}
    {$if declared(SXNETID_free_introduced)}
    if LibVersion < SXNETID_free_introduced then
    begin
      {$if declared(FC_SXNETID_free)}
      SXNETID_free := FC_SXNETID_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SXNETID_free_removed)}
    if SXNETID_free_removed <= LibVersion then
    begin
      {$if declared(_SXNETID_free)}
      SXNETID_free := _SXNETID_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SXNETID_free_allownil)}
    if FuncLoadError then
      AFailed.Add('SXNETID_free');
    {$ifend}
  end;
  
  d2i_SXNETID := LoadLibFunction(ADllHandle, d2i_SXNETID_procname);
  FuncLoadError := not assigned(d2i_SXNETID);
  if FuncLoadError then
  begin
    {$if not defined(d2i_SXNETID_allownil)}
    d2i_SXNETID := ERR_d2i_SXNETID;
    {$ifend}
    {$if declared(d2i_SXNETID_introduced)}
    if LibVersion < d2i_SXNETID_introduced then
    begin
      {$if declared(FC_d2i_SXNETID)}
      d2i_SXNETID := FC_d2i_SXNETID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_SXNETID_removed)}
    if d2i_SXNETID_removed <= LibVersion then
    begin
      {$if declared(_d2i_SXNETID)}
      d2i_SXNETID := _d2i_SXNETID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_SXNETID_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_SXNETID');
    {$ifend}
  end;
  
  i2d_SXNETID := LoadLibFunction(ADllHandle, i2d_SXNETID_procname);
  FuncLoadError := not assigned(i2d_SXNETID);
  if FuncLoadError then
  begin
    {$if not defined(i2d_SXNETID_allownil)}
    i2d_SXNETID := ERR_i2d_SXNETID;
    {$ifend}
    {$if declared(i2d_SXNETID_introduced)}
    if LibVersion < i2d_SXNETID_introduced then
    begin
      {$if declared(FC_i2d_SXNETID)}
      i2d_SXNETID := FC_i2d_SXNETID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_SXNETID_removed)}
    if i2d_SXNETID_removed <= LibVersion then
    begin
      {$if declared(_i2d_SXNETID)}
      i2d_SXNETID := _i2d_SXNETID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_SXNETID_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_SXNETID');
    {$ifend}
  end;
  
  SXNETID_it := LoadLibFunction(ADllHandle, SXNETID_it_procname);
  FuncLoadError := not assigned(SXNETID_it);
  if FuncLoadError then
  begin
    {$if not defined(SXNETID_it_allownil)}
    SXNETID_it := ERR_SXNETID_it;
    {$ifend}
    {$if declared(SXNETID_it_introduced)}
    if LibVersion < SXNETID_it_introduced then
    begin
      {$if declared(FC_SXNETID_it)}
      SXNETID_it := FC_SXNETID_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SXNETID_it_removed)}
    if SXNETID_it_removed <= LibVersion then
    begin
      {$if declared(_SXNETID_it)}
      SXNETID_it := _SXNETID_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SXNETID_it_allownil)}
    if FuncLoadError then
      AFailed.Add('SXNETID_it');
    {$ifend}
  end;
  
  ISSUER_SIGN_TOOL_new := LoadLibFunction(ADllHandle, ISSUER_SIGN_TOOL_new_procname);
  FuncLoadError := not assigned(ISSUER_SIGN_TOOL_new);
  if FuncLoadError then
  begin
    {$if not defined(ISSUER_SIGN_TOOL_new_allownil)}
    ISSUER_SIGN_TOOL_new := ERR_ISSUER_SIGN_TOOL_new;
    {$ifend}
    {$if declared(ISSUER_SIGN_TOOL_new_introduced)}
    if LibVersion < ISSUER_SIGN_TOOL_new_introduced then
    begin
      {$if declared(FC_ISSUER_SIGN_TOOL_new)}
      ISSUER_SIGN_TOOL_new := FC_ISSUER_SIGN_TOOL_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ISSUER_SIGN_TOOL_new_removed)}
    if ISSUER_SIGN_TOOL_new_removed <= LibVersion then
    begin
      {$if declared(_ISSUER_SIGN_TOOL_new)}
      ISSUER_SIGN_TOOL_new := _ISSUER_SIGN_TOOL_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ISSUER_SIGN_TOOL_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ISSUER_SIGN_TOOL_new');
    {$ifend}
  end;
  
  ISSUER_SIGN_TOOL_free := LoadLibFunction(ADllHandle, ISSUER_SIGN_TOOL_free_procname);
  FuncLoadError := not assigned(ISSUER_SIGN_TOOL_free);
  if FuncLoadError then
  begin
    {$if not defined(ISSUER_SIGN_TOOL_free_allownil)}
    ISSUER_SIGN_TOOL_free := ERR_ISSUER_SIGN_TOOL_free;
    {$ifend}
    {$if declared(ISSUER_SIGN_TOOL_free_introduced)}
    if LibVersion < ISSUER_SIGN_TOOL_free_introduced then
    begin
      {$if declared(FC_ISSUER_SIGN_TOOL_free)}
      ISSUER_SIGN_TOOL_free := FC_ISSUER_SIGN_TOOL_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ISSUER_SIGN_TOOL_free_removed)}
    if ISSUER_SIGN_TOOL_free_removed <= LibVersion then
    begin
      {$if declared(_ISSUER_SIGN_TOOL_free)}
      ISSUER_SIGN_TOOL_free := _ISSUER_SIGN_TOOL_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ISSUER_SIGN_TOOL_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ISSUER_SIGN_TOOL_free');
    {$ifend}
  end;
  
  d2i_ISSUER_SIGN_TOOL := LoadLibFunction(ADllHandle, d2i_ISSUER_SIGN_TOOL_procname);
  FuncLoadError := not assigned(d2i_ISSUER_SIGN_TOOL);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ISSUER_SIGN_TOOL_allownil)}
    d2i_ISSUER_SIGN_TOOL := ERR_d2i_ISSUER_SIGN_TOOL;
    {$ifend}
    {$if declared(d2i_ISSUER_SIGN_TOOL_introduced)}
    if LibVersion < d2i_ISSUER_SIGN_TOOL_introduced then
    begin
      {$if declared(FC_d2i_ISSUER_SIGN_TOOL)}
      d2i_ISSUER_SIGN_TOOL := FC_d2i_ISSUER_SIGN_TOOL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ISSUER_SIGN_TOOL_removed)}
    if d2i_ISSUER_SIGN_TOOL_removed <= LibVersion then
    begin
      {$if declared(_d2i_ISSUER_SIGN_TOOL)}
      d2i_ISSUER_SIGN_TOOL := _d2i_ISSUER_SIGN_TOOL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ISSUER_SIGN_TOOL_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ISSUER_SIGN_TOOL');
    {$ifend}
  end;
  
  i2d_ISSUER_SIGN_TOOL := LoadLibFunction(ADllHandle, i2d_ISSUER_SIGN_TOOL_procname);
  FuncLoadError := not assigned(i2d_ISSUER_SIGN_TOOL);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ISSUER_SIGN_TOOL_allownil)}
    i2d_ISSUER_SIGN_TOOL := ERR_i2d_ISSUER_SIGN_TOOL;
    {$ifend}
    {$if declared(i2d_ISSUER_SIGN_TOOL_introduced)}
    if LibVersion < i2d_ISSUER_SIGN_TOOL_introduced then
    begin
      {$if declared(FC_i2d_ISSUER_SIGN_TOOL)}
      i2d_ISSUER_SIGN_TOOL := FC_i2d_ISSUER_SIGN_TOOL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ISSUER_SIGN_TOOL_removed)}
    if i2d_ISSUER_SIGN_TOOL_removed <= LibVersion then
    begin
      {$if declared(_i2d_ISSUER_SIGN_TOOL)}
      i2d_ISSUER_SIGN_TOOL := _i2d_ISSUER_SIGN_TOOL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ISSUER_SIGN_TOOL_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ISSUER_SIGN_TOOL');
    {$ifend}
  end;
  
  ISSUER_SIGN_TOOL_it := LoadLibFunction(ADllHandle, ISSUER_SIGN_TOOL_it_procname);
  FuncLoadError := not assigned(ISSUER_SIGN_TOOL_it);
  if FuncLoadError then
  begin
    {$if not defined(ISSUER_SIGN_TOOL_it_allownil)}
    ISSUER_SIGN_TOOL_it := ERR_ISSUER_SIGN_TOOL_it;
    {$ifend}
    {$if declared(ISSUER_SIGN_TOOL_it_introduced)}
    if LibVersion < ISSUER_SIGN_TOOL_it_introduced then
    begin
      {$if declared(FC_ISSUER_SIGN_TOOL_it)}
      ISSUER_SIGN_TOOL_it := FC_ISSUER_SIGN_TOOL_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ISSUER_SIGN_TOOL_it_removed)}
    if ISSUER_SIGN_TOOL_it_removed <= LibVersion then
    begin
      {$if declared(_ISSUER_SIGN_TOOL_it)}
      ISSUER_SIGN_TOOL_it := _ISSUER_SIGN_TOOL_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ISSUER_SIGN_TOOL_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ISSUER_SIGN_TOOL_it');
    {$ifend}
  end;
  
  SXNET_add_id_asc := LoadLibFunction(ADllHandle, SXNET_add_id_asc_procname);
  FuncLoadError := not assigned(SXNET_add_id_asc);
  if FuncLoadError then
  begin
    {$if not defined(SXNET_add_id_asc_allownil)}
    SXNET_add_id_asc := ERR_SXNET_add_id_asc;
    {$ifend}
    {$if declared(SXNET_add_id_asc_introduced)}
    if LibVersion < SXNET_add_id_asc_introduced then
    begin
      {$if declared(FC_SXNET_add_id_asc)}
      SXNET_add_id_asc := FC_SXNET_add_id_asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SXNET_add_id_asc_removed)}
    if SXNET_add_id_asc_removed <= LibVersion then
    begin
      {$if declared(_SXNET_add_id_asc)}
      SXNET_add_id_asc := _SXNET_add_id_asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SXNET_add_id_asc_allownil)}
    if FuncLoadError then
      AFailed.Add('SXNET_add_id_asc');
    {$ifend}
  end;
  
  SXNET_add_id_ulong := LoadLibFunction(ADllHandle, SXNET_add_id_ulong_procname);
  FuncLoadError := not assigned(SXNET_add_id_ulong);
  if FuncLoadError then
  begin
    {$if not defined(SXNET_add_id_ulong_allownil)}
    SXNET_add_id_ulong := ERR_SXNET_add_id_ulong;
    {$ifend}
    {$if declared(SXNET_add_id_ulong_introduced)}
    if LibVersion < SXNET_add_id_ulong_introduced then
    begin
      {$if declared(FC_SXNET_add_id_ulong)}
      SXNET_add_id_ulong := FC_SXNET_add_id_ulong;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SXNET_add_id_ulong_removed)}
    if SXNET_add_id_ulong_removed <= LibVersion then
    begin
      {$if declared(_SXNET_add_id_ulong)}
      SXNET_add_id_ulong := _SXNET_add_id_ulong;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SXNET_add_id_ulong_allownil)}
    if FuncLoadError then
      AFailed.Add('SXNET_add_id_ulong');
    {$ifend}
  end;
  
  SXNET_add_id_INTEGER := LoadLibFunction(ADllHandle, SXNET_add_id_INTEGER_procname);
  FuncLoadError := not assigned(SXNET_add_id_INTEGER);
  if FuncLoadError then
  begin
    {$if not defined(SXNET_add_id_INTEGER_allownil)}
    SXNET_add_id_INTEGER := ERR_SXNET_add_id_INTEGER;
    {$ifend}
    {$if declared(SXNET_add_id_INTEGER_introduced)}
    if LibVersion < SXNET_add_id_INTEGER_introduced then
    begin
      {$if declared(FC_SXNET_add_id_INTEGER)}
      SXNET_add_id_INTEGER := FC_SXNET_add_id_INTEGER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SXNET_add_id_INTEGER_removed)}
    if SXNET_add_id_INTEGER_removed <= LibVersion then
    begin
      {$if declared(_SXNET_add_id_INTEGER)}
      SXNET_add_id_INTEGER := _SXNET_add_id_INTEGER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SXNET_add_id_INTEGER_allownil)}
    if FuncLoadError then
      AFailed.Add('SXNET_add_id_INTEGER');
    {$ifend}
  end;
  
  SXNET_get_id_asc := LoadLibFunction(ADllHandle, SXNET_get_id_asc_procname);
  FuncLoadError := not assigned(SXNET_get_id_asc);
  if FuncLoadError then
  begin
    {$if not defined(SXNET_get_id_asc_allownil)}
    SXNET_get_id_asc := ERR_SXNET_get_id_asc;
    {$ifend}
    {$if declared(SXNET_get_id_asc_introduced)}
    if LibVersion < SXNET_get_id_asc_introduced then
    begin
      {$if declared(FC_SXNET_get_id_asc)}
      SXNET_get_id_asc := FC_SXNET_get_id_asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SXNET_get_id_asc_removed)}
    if SXNET_get_id_asc_removed <= LibVersion then
    begin
      {$if declared(_SXNET_get_id_asc)}
      SXNET_get_id_asc := _SXNET_get_id_asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SXNET_get_id_asc_allownil)}
    if FuncLoadError then
      AFailed.Add('SXNET_get_id_asc');
    {$ifend}
  end;
  
  SXNET_get_id_ulong := LoadLibFunction(ADllHandle, SXNET_get_id_ulong_procname);
  FuncLoadError := not assigned(SXNET_get_id_ulong);
  if FuncLoadError then
  begin
    {$if not defined(SXNET_get_id_ulong_allownil)}
    SXNET_get_id_ulong := ERR_SXNET_get_id_ulong;
    {$ifend}
    {$if declared(SXNET_get_id_ulong_introduced)}
    if LibVersion < SXNET_get_id_ulong_introduced then
    begin
      {$if declared(FC_SXNET_get_id_ulong)}
      SXNET_get_id_ulong := FC_SXNET_get_id_ulong;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SXNET_get_id_ulong_removed)}
    if SXNET_get_id_ulong_removed <= LibVersion then
    begin
      {$if declared(_SXNET_get_id_ulong)}
      SXNET_get_id_ulong := _SXNET_get_id_ulong;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SXNET_get_id_ulong_allownil)}
    if FuncLoadError then
      AFailed.Add('SXNET_get_id_ulong');
    {$ifend}
  end;
  
  SXNET_get_id_INTEGER := LoadLibFunction(ADllHandle, SXNET_get_id_INTEGER_procname);
  FuncLoadError := not assigned(SXNET_get_id_INTEGER);
  if FuncLoadError then
  begin
    {$if not defined(SXNET_get_id_INTEGER_allownil)}
    SXNET_get_id_INTEGER := ERR_SXNET_get_id_INTEGER;
    {$ifend}
    {$if declared(SXNET_get_id_INTEGER_introduced)}
    if LibVersion < SXNET_get_id_INTEGER_introduced then
    begin
      {$if declared(FC_SXNET_get_id_INTEGER)}
      SXNET_get_id_INTEGER := FC_SXNET_get_id_INTEGER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SXNET_get_id_INTEGER_removed)}
    if SXNET_get_id_INTEGER_removed <= LibVersion then
    begin
      {$if declared(_SXNET_get_id_INTEGER)}
      SXNET_get_id_INTEGER := _SXNET_get_id_INTEGER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SXNET_get_id_INTEGER_allownil)}
    if FuncLoadError then
      AFailed.Add('SXNET_get_id_INTEGER');
    {$ifend}
  end;
  
  AUTHORITY_KEYID_new := LoadLibFunction(ADllHandle, AUTHORITY_KEYID_new_procname);
  FuncLoadError := not assigned(AUTHORITY_KEYID_new);
  if FuncLoadError then
  begin
    {$if not defined(AUTHORITY_KEYID_new_allownil)}
    AUTHORITY_KEYID_new := ERR_AUTHORITY_KEYID_new;
    {$ifend}
    {$if declared(AUTHORITY_KEYID_new_introduced)}
    if LibVersion < AUTHORITY_KEYID_new_introduced then
    begin
      {$if declared(FC_AUTHORITY_KEYID_new)}
      AUTHORITY_KEYID_new := FC_AUTHORITY_KEYID_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AUTHORITY_KEYID_new_removed)}
    if AUTHORITY_KEYID_new_removed <= LibVersion then
    begin
      {$if declared(_AUTHORITY_KEYID_new)}
      AUTHORITY_KEYID_new := _AUTHORITY_KEYID_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AUTHORITY_KEYID_new_allownil)}
    if FuncLoadError then
      AFailed.Add('AUTHORITY_KEYID_new');
    {$ifend}
  end;
  
  AUTHORITY_KEYID_free := LoadLibFunction(ADllHandle, AUTHORITY_KEYID_free_procname);
  FuncLoadError := not assigned(AUTHORITY_KEYID_free);
  if FuncLoadError then
  begin
    {$if not defined(AUTHORITY_KEYID_free_allownil)}
    AUTHORITY_KEYID_free := ERR_AUTHORITY_KEYID_free;
    {$ifend}
    {$if declared(AUTHORITY_KEYID_free_introduced)}
    if LibVersion < AUTHORITY_KEYID_free_introduced then
    begin
      {$if declared(FC_AUTHORITY_KEYID_free)}
      AUTHORITY_KEYID_free := FC_AUTHORITY_KEYID_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AUTHORITY_KEYID_free_removed)}
    if AUTHORITY_KEYID_free_removed <= LibVersion then
    begin
      {$if declared(_AUTHORITY_KEYID_free)}
      AUTHORITY_KEYID_free := _AUTHORITY_KEYID_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AUTHORITY_KEYID_free_allownil)}
    if FuncLoadError then
      AFailed.Add('AUTHORITY_KEYID_free');
    {$ifend}
  end;
  
  d2i_AUTHORITY_KEYID := LoadLibFunction(ADllHandle, d2i_AUTHORITY_KEYID_procname);
  FuncLoadError := not assigned(d2i_AUTHORITY_KEYID);
  if FuncLoadError then
  begin
    {$if not defined(d2i_AUTHORITY_KEYID_allownil)}
    d2i_AUTHORITY_KEYID := ERR_d2i_AUTHORITY_KEYID;
    {$ifend}
    {$if declared(d2i_AUTHORITY_KEYID_introduced)}
    if LibVersion < d2i_AUTHORITY_KEYID_introduced then
    begin
      {$if declared(FC_d2i_AUTHORITY_KEYID)}
      d2i_AUTHORITY_KEYID := FC_d2i_AUTHORITY_KEYID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_AUTHORITY_KEYID_removed)}
    if d2i_AUTHORITY_KEYID_removed <= LibVersion then
    begin
      {$if declared(_d2i_AUTHORITY_KEYID)}
      d2i_AUTHORITY_KEYID := _d2i_AUTHORITY_KEYID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_AUTHORITY_KEYID_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_AUTHORITY_KEYID');
    {$ifend}
  end;
  
  i2d_AUTHORITY_KEYID := LoadLibFunction(ADllHandle, i2d_AUTHORITY_KEYID_procname);
  FuncLoadError := not assigned(i2d_AUTHORITY_KEYID);
  if FuncLoadError then
  begin
    {$if not defined(i2d_AUTHORITY_KEYID_allownil)}
    i2d_AUTHORITY_KEYID := ERR_i2d_AUTHORITY_KEYID;
    {$ifend}
    {$if declared(i2d_AUTHORITY_KEYID_introduced)}
    if LibVersion < i2d_AUTHORITY_KEYID_introduced then
    begin
      {$if declared(FC_i2d_AUTHORITY_KEYID)}
      i2d_AUTHORITY_KEYID := FC_i2d_AUTHORITY_KEYID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_AUTHORITY_KEYID_removed)}
    if i2d_AUTHORITY_KEYID_removed <= LibVersion then
    begin
      {$if declared(_i2d_AUTHORITY_KEYID)}
      i2d_AUTHORITY_KEYID := _i2d_AUTHORITY_KEYID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_AUTHORITY_KEYID_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_AUTHORITY_KEYID');
    {$ifend}
  end;
  
  AUTHORITY_KEYID_it := LoadLibFunction(ADllHandle, AUTHORITY_KEYID_it_procname);
  FuncLoadError := not assigned(AUTHORITY_KEYID_it);
  if FuncLoadError then
  begin
    {$if not defined(AUTHORITY_KEYID_it_allownil)}
    AUTHORITY_KEYID_it := ERR_AUTHORITY_KEYID_it;
    {$ifend}
    {$if declared(AUTHORITY_KEYID_it_introduced)}
    if LibVersion < AUTHORITY_KEYID_it_introduced then
    begin
      {$if declared(FC_AUTHORITY_KEYID_it)}
      AUTHORITY_KEYID_it := FC_AUTHORITY_KEYID_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AUTHORITY_KEYID_it_removed)}
    if AUTHORITY_KEYID_it_removed <= LibVersion then
    begin
      {$if declared(_AUTHORITY_KEYID_it)}
      AUTHORITY_KEYID_it := _AUTHORITY_KEYID_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AUTHORITY_KEYID_it_allownil)}
    if FuncLoadError then
      AFailed.Add('AUTHORITY_KEYID_it');
    {$ifend}
  end;
  
  PKEY_USAGE_PERIOD_new := LoadLibFunction(ADllHandle, PKEY_USAGE_PERIOD_new_procname);
  FuncLoadError := not assigned(PKEY_USAGE_PERIOD_new);
  if FuncLoadError then
  begin
    {$if not defined(PKEY_USAGE_PERIOD_new_allownil)}
    PKEY_USAGE_PERIOD_new := ERR_PKEY_USAGE_PERIOD_new;
    {$ifend}
    {$if declared(PKEY_USAGE_PERIOD_new_introduced)}
    if LibVersion < PKEY_USAGE_PERIOD_new_introduced then
    begin
      {$if declared(FC_PKEY_USAGE_PERIOD_new)}
      PKEY_USAGE_PERIOD_new := FC_PKEY_USAGE_PERIOD_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKEY_USAGE_PERIOD_new_removed)}
    if PKEY_USAGE_PERIOD_new_removed <= LibVersion then
    begin
      {$if declared(_PKEY_USAGE_PERIOD_new)}
      PKEY_USAGE_PERIOD_new := _PKEY_USAGE_PERIOD_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKEY_USAGE_PERIOD_new_allownil)}
    if FuncLoadError then
      AFailed.Add('PKEY_USAGE_PERIOD_new');
    {$ifend}
  end;
  
  PKEY_USAGE_PERIOD_free := LoadLibFunction(ADllHandle, PKEY_USAGE_PERIOD_free_procname);
  FuncLoadError := not assigned(PKEY_USAGE_PERIOD_free);
  if FuncLoadError then
  begin
    {$if not defined(PKEY_USAGE_PERIOD_free_allownil)}
    PKEY_USAGE_PERIOD_free := ERR_PKEY_USAGE_PERIOD_free;
    {$ifend}
    {$if declared(PKEY_USAGE_PERIOD_free_introduced)}
    if LibVersion < PKEY_USAGE_PERIOD_free_introduced then
    begin
      {$if declared(FC_PKEY_USAGE_PERIOD_free)}
      PKEY_USAGE_PERIOD_free := FC_PKEY_USAGE_PERIOD_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKEY_USAGE_PERIOD_free_removed)}
    if PKEY_USAGE_PERIOD_free_removed <= LibVersion then
    begin
      {$if declared(_PKEY_USAGE_PERIOD_free)}
      PKEY_USAGE_PERIOD_free := _PKEY_USAGE_PERIOD_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKEY_USAGE_PERIOD_free_allownil)}
    if FuncLoadError then
      AFailed.Add('PKEY_USAGE_PERIOD_free');
    {$ifend}
  end;
  
  d2i_PKEY_USAGE_PERIOD := LoadLibFunction(ADllHandle, d2i_PKEY_USAGE_PERIOD_procname);
  FuncLoadError := not assigned(d2i_PKEY_USAGE_PERIOD);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PKEY_USAGE_PERIOD_allownil)}
    d2i_PKEY_USAGE_PERIOD := ERR_d2i_PKEY_USAGE_PERIOD;
    {$ifend}
    {$if declared(d2i_PKEY_USAGE_PERIOD_introduced)}
    if LibVersion < d2i_PKEY_USAGE_PERIOD_introduced then
    begin
      {$if declared(FC_d2i_PKEY_USAGE_PERIOD)}
      d2i_PKEY_USAGE_PERIOD := FC_d2i_PKEY_USAGE_PERIOD;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PKEY_USAGE_PERIOD_removed)}
    if d2i_PKEY_USAGE_PERIOD_removed <= LibVersion then
    begin
      {$if declared(_d2i_PKEY_USAGE_PERIOD)}
      d2i_PKEY_USAGE_PERIOD := _d2i_PKEY_USAGE_PERIOD;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PKEY_USAGE_PERIOD_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PKEY_USAGE_PERIOD');
    {$ifend}
  end;
  
  i2d_PKEY_USAGE_PERIOD := LoadLibFunction(ADllHandle, i2d_PKEY_USAGE_PERIOD_procname);
  FuncLoadError := not assigned(i2d_PKEY_USAGE_PERIOD);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKEY_USAGE_PERIOD_allownil)}
    i2d_PKEY_USAGE_PERIOD := ERR_i2d_PKEY_USAGE_PERIOD;
    {$ifend}
    {$if declared(i2d_PKEY_USAGE_PERIOD_introduced)}
    if LibVersion < i2d_PKEY_USAGE_PERIOD_introduced then
    begin
      {$if declared(FC_i2d_PKEY_USAGE_PERIOD)}
      i2d_PKEY_USAGE_PERIOD := FC_i2d_PKEY_USAGE_PERIOD;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKEY_USAGE_PERIOD_removed)}
    if i2d_PKEY_USAGE_PERIOD_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKEY_USAGE_PERIOD)}
      i2d_PKEY_USAGE_PERIOD := _i2d_PKEY_USAGE_PERIOD;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKEY_USAGE_PERIOD_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKEY_USAGE_PERIOD');
    {$ifend}
  end;
  
  PKEY_USAGE_PERIOD_it := LoadLibFunction(ADllHandle, PKEY_USAGE_PERIOD_it_procname);
  FuncLoadError := not assigned(PKEY_USAGE_PERIOD_it);
  if FuncLoadError then
  begin
    {$if not defined(PKEY_USAGE_PERIOD_it_allownil)}
    PKEY_USAGE_PERIOD_it := ERR_PKEY_USAGE_PERIOD_it;
    {$ifend}
    {$if declared(PKEY_USAGE_PERIOD_it_introduced)}
    if LibVersion < PKEY_USAGE_PERIOD_it_introduced then
    begin
      {$if declared(FC_PKEY_USAGE_PERIOD_it)}
      PKEY_USAGE_PERIOD_it := FC_PKEY_USAGE_PERIOD_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKEY_USAGE_PERIOD_it_removed)}
    if PKEY_USAGE_PERIOD_it_removed <= LibVersion then
    begin
      {$if declared(_PKEY_USAGE_PERIOD_it)}
      PKEY_USAGE_PERIOD_it := _PKEY_USAGE_PERIOD_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKEY_USAGE_PERIOD_it_allownil)}
    if FuncLoadError then
      AFailed.Add('PKEY_USAGE_PERIOD_it');
    {$ifend}
  end;
  
  GENERAL_NAME_new := LoadLibFunction(ADllHandle, GENERAL_NAME_new_procname);
  FuncLoadError := not assigned(GENERAL_NAME_new);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_NAME_new_allownil)}
    GENERAL_NAME_new := ERR_GENERAL_NAME_new;
    {$ifend}
    {$if declared(GENERAL_NAME_new_introduced)}
    if LibVersion < GENERAL_NAME_new_introduced then
    begin
      {$if declared(FC_GENERAL_NAME_new)}
      GENERAL_NAME_new := FC_GENERAL_NAME_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_NAME_new_removed)}
    if GENERAL_NAME_new_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_NAME_new)}
      GENERAL_NAME_new := _GENERAL_NAME_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_NAME_new_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_NAME_new');
    {$ifend}
  end;
  
  GENERAL_NAME_free := LoadLibFunction(ADllHandle, GENERAL_NAME_free_procname);
  FuncLoadError := not assigned(GENERAL_NAME_free);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_NAME_free_allownil)}
    GENERAL_NAME_free := ERR_GENERAL_NAME_free;
    {$ifend}
    {$if declared(GENERAL_NAME_free_introduced)}
    if LibVersion < GENERAL_NAME_free_introduced then
    begin
      {$if declared(FC_GENERAL_NAME_free)}
      GENERAL_NAME_free := FC_GENERAL_NAME_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_NAME_free_removed)}
    if GENERAL_NAME_free_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_NAME_free)}
      GENERAL_NAME_free := _GENERAL_NAME_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_NAME_free_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_NAME_free');
    {$ifend}
  end;
  
  d2i_GENERAL_NAME := LoadLibFunction(ADllHandle, d2i_GENERAL_NAME_procname);
  FuncLoadError := not assigned(d2i_GENERAL_NAME);
  if FuncLoadError then
  begin
    {$if not defined(d2i_GENERAL_NAME_allownil)}
    d2i_GENERAL_NAME := ERR_d2i_GENERAL_NAME;
    {$ifend}
    {$if declared(d2i_GENERAL_NAME_introduced)}
    if LibVersion < d2i_GENERAL_NAME_introduced then
    begin
      {$if declared(FC_d2i_GENERAL_NAME)}
      d2i_GENERAL_NAME := FC_d2i_GENERAL_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_GENERAL_NAME_removed)}
    if d2i_GENERAL_NAME_removed <= LibVersion then
    begin
      {$if declared(_d2i_GENERAL_NAME)}
      d2i_GENERAL_NAME := _d2i_GENERAL_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_GENERAL_NAME_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_GENERAL_NAME');
    {$ifend}
  end;
  
  i2d_GENERAL_NAME := LoadLibFunction(ADllHandle, i2d_GENERAL_NAME_procname);
  FuncLoadError := not assigned(i2d_GENERAL_NAME);
  if FuncLoadError then
  begin
    {$if not defined(i2d_GENERAL_NAME_allownil)}
    i2d_GENERAL_NAME := ERR_i2d_GENERAL_NAME;
    {$ifend}
    {$if declared(i2d_GENERAL_NAME_introduced)}
    if LibVersion < i2d_GENERAL_NAME_introduced then
    begin
      {$if declared(FC_i2d_GENERAL_NAME)}
      i2d_GENERAL_NAME := FC_i2d_GENERAL_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_GENERAL_NAME_removed)}
    if i2d_GENERAL_NAME_removed <= LibVersion then
    begin
      {$if declared(_i2d_GENERAL_NAME)}
      i2d_GENERAL_NAME := _i2d_GENERAL_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_GENERAL_NAME_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_GENERAL_NAME');
    {$ifend}
  end;
  
  GENERAL_NAME_it := LoadLibFunction(ADllHandle, GENERAL_NAME_it_procname);
  FuncLoadError := not assigned(GENERAL_NAME_it);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_NAME_it_allownil)}
    GENERAL_NAME_it := ERR_GENERAL_NAME_it;
    {$ifend}
    {$if declared(GENERAL_NAME_it_introduced)}
    if LibVersion < GENERAL_NAME_it_introduced then
    begin
      {$if declared(FC_GENERAL_NAME_it)}
      GENERAL_NAME_it := FC_GENERAL_NAME_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_NAME_it_removed)}
    if GENERAL_NAME_it_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_NAME_it)}
      GENERAL_NAME_it := _GENERAL_NAME_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_NAME_it_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_NAME_it');
    {$ifend}
  end;
  
  GENERAL_NAME_dup := LoadLibFunction(ADllHandle, GENERAL_NAME_dup_procname);
  FuncLoadError := not assigned(GENERAL_NAME_dup);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_NAME_dup_allownil)}
    GENERAL_NAME_dup := ERR_GENERAL_NAME_dup;
    {$ifend}
    {$if declared(GENERAL_NAME_dup_introduced)}
    if LibVersion < GENERAL_NAME_dup_introduced then
    begin
      {$if declared(FC_GENERAL_NAME_dup)}
      GENERAL_NAME_dup := FC_GENERAL_NAME_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_NAME_dup_removed)}
    if GENERAL_NAME_dup_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_NAME_dup)}
      GENERAL_NAME_dup := _GENERAL_NAME_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_NAME_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_NAME_dup');
    {$ifend}
  end;
  
  GENERAL_NAME_cmp := LoadLibFunction(ADllHandle, GENERAL_NAME_cmp_procname);
  FuncLoadError := not assigned(GENERAL_NAME_cmp);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_NAME_cmp_allownil)}
    GENERAL_NAME_cmp := ERR_GENERAL_NAME_cmp;
    {$ifend}
    {$if declared(GENERAL_NAME_cmp_introduced)}
    if LibVersion < GENERAL_NAME_cmp_introduced then
    begin
      {$if declared(FC_GENERAL_NAME_cmp)}
      GENERAL_NAME_cmp := FC_GENERAL_NAME_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_NAME_cmp_removed)}
    if GENERAL_NAME_cmp_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_NAME_cmp)}
      GENERAL_NAME_cmp := _GENERAL_NAME_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_NAME_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_NAME_cmp');
    {$ifend}
  end;
  
  v2i_ASN1_BIT_STRING := LoadLibFunction(ADllHandle, v2i_ASN1_BIT_STRING_procname);
  FuncLoadError := not assigned(v2i_ASN1_BIT_STRING);
  if FuncLoadError then
  begin
    {$if not defined(v2i_ASN1_BIT_STRING_allownil)}
    v2i_ASN1_BIT_STRING := ERR_v2i_ASN1_BIT_STRING;
    {$ifend}
    {$if declared(v2i_ASN1_BIT_STRING_introduced)}
    if LibVersion < v2i_ASN1_BIT_STRING_introduced then
    begin
      {$if declared(FC_v2i_ASN1_BIT_STRING)}
      v2i_ASN1_BIT_STRING := FC_v2i_ASN1_BIT_STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(v2i_ASN1_BIT_STRING_removed)}
    if v2i_ASN1_BIT_STRING_removed <= LibVersion then
    begin
      {$if declared(_v2i_ASN1_BIT_STRING)}
      v2i_ASN1_BIT_STRING := _v2i_ASN1_BIT_STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(v2i_ASN1_BIT_STRING_allownil)}
    if FuncLoadError then
      AFailed.Add('v2i_ASN1_BIT_STRING');
    {$ifend}
  end;
  
  i2v_ASN1_BIT_STRING := LoadLibFunction(ADllHandle, i2v_ASN1_BIT_STRING_procname);
  FuncLoadError := not assigned(i2v_ASN1_BIT_STRING);
  if FuncLoadError then
  begin
    {$if not defined(i2v_ASN1_BIT_STRING_allownil)}
    i2v_ASN1_BIT_STRING := ERR_i2v_ASN1_BIT_STRING;
    {$ifend}
    {$if declared(i2v_ASN1_BIT_STRING_introduced)}
    if LibVersion < i2v_ASN1_BIT_STRING_introduced then
    begin
      {$if declared(FC_i2v_ASN1_BIT_STRING)}
      i2v_ASN1_BIT_STRING := FC_i2v_ASN1_BIT_STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2v_ASN1_BIT_STRING_removed)}
    if i2v_ASN1_BIT_STRING_removed <= LibVersion then
    begin
      {$if declared(_i2v_ASN1_BIT_STRING)}
      i2v_ASN1_BIT_STRING := _i2v_ASN1_BIT_STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2v_ASN1_BIT_STRING_allownil)}
    if FuncLoadError then
      AFailed.Add('i2v_ASN1_BIT_STRING');
    {$ifend}
  end;
  
  i2s_ASN1_IA5STRING := LoadLibFunction(ADllHandle, i2s_ASN1_IA5STRING_procname);
  FuncLoadError := not assigned(i2s_ASN1_IA5STRING);
  if FuncLoadError then
  begin
    {$if not defined(i2s_ASN1_IA5STRING_allownil)}
    i2s_ASN1_IA5STRING := ERR_i2s_ASN1_IA5STRING;
    {$ifend}
    {$if declared(i2s_ASN1_IA5STRING_introduced)}
    if LibVersion < i2s_ASN1_IA5STRING_introduced then
    begin
      {$if declared(FC_i2s_ASN1_IA5STRING)}
      i2s_ASN1_IA5STRING := FC_i2s_ASN1_IA5STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2s_ASN1_IA5STRING_removed)}
    if i2s_ASN1_IA5STRING_removed <= LibVersion then
    begin
      {$if declared(_i2s_ASN1_IA5STRING)}
      i2s_ASN1_IA5STRING := _i2s_ASN1_IA5STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2s_ASN1_IA5STRING_allownil)}
    if FuncLoadError then
      AFailed.Add('i2s_ASN1_IA5STRING');
    {$ifend}
  end;
  
  s2i_ASN1_IA5STRING := LoadLibFunction(ADllHandle, s2i_ASN1_IA5STRING_procname);
  FuncLoadError := not assigned(s2i_ASN1_IA5STRING);
  if FuncLoadError then
  begin
    {$if not defined(s2i_ASN1_IA5STRING_allownil)}
    s2i_ASN1_IA5STRING := ERR_s2i_ASN1_IA5STRING;
    {$ifend}
    {$if declared(s2i_ASN1_IA5STRING_introduced)}
    if LibVersion < s2i_ASN1_IA5STRING_introduced then
    begin
      {$if declared(FC_s2i_ASN1_IA5STRING)}
      s2i_ASN1_IA5STRING := FC_s2i_ASN1_IA5STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(s2i_ASN1_IA5STRING_removed)}
    if s2i_ASN1_IA5STRING_removed <= LibVersion then
    begin
      {$if declared(_s2i_ASN1_IA5STRING)}
      s2i_ASN1_IA5STRING := _s2i_ASN1_IA5STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(s2i_ASN1_IA5STRING_allownil)}
    if FuncLoadError then
      AFailed.Add('s2i_ASN1_IA5STRING');
    {$ifend}
  end;
  
  i2s_ASN1_UTF8STRING := LoadLibFunction(ADllHandle, i2s_ASN1_UTF8STRING_procname);
  FuncLoadError := not assigned(i2s_ASN1_UTF8STRING);
  if FuncLoadError then
  begin
    {$if not defined(i2s_ASN1_UTF8STRING_allownil)}
    i2s_ASN1_UTF8STRING := ERR_i2s_ASN1_UTF8STRING;
    {$ifend}
    {$if declared(i2s_ASN1_UTF8STRING_introduced)}
    if LibVersion < i2s_ASN1_UTF8STRING_introduced then
    begin
      {$if declared(FC_i2s_ASN1_UTF8STRING)}
      i2s_ASN1_UTF8STRING := FC_i2s_ASN1_UTF8STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2s_ASN1_UTF8STRING_removed)}
    if i2s_ASN1_UTF8STRING_removed <= LibVersion then
    begin
      {$if declared(_i2s_ASN1_UTF8STRING)}
      i2s_ASN1_UTF8STRING := _i2s_ASN1_UTF8STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2s_ASN1_UTF8STRING_allownil)}
    if FuncLoadError then
      AFailed.Add('i2s_ASN1_UTF8STRING');
    {$ifend}
  end;
  
  s2i_ASN1_UTF8STRING := LoadLibFunction(ADllHandle, s2i_ASN1_UTF8STRING_procname);
  FuncLoadError := not assigned(s2i_ASN1_UTF8STRING);
  if FuncLoadError then
  begin
    {$if not defined(s2i_ASN1_UTF8STRING_allownil)}
    s2i_ASN1_UTF8STRING := ERR_s2i_ASN1_UTF8STRING;
    {$ifend}
    {$if declared(s2i_ASN1_UTF8STRING_introduced)}
    if LibVersion < s2i_ASN1_UTF8STRING_introduced then
    begin
      {$if declared(FC_s2i_ASN1_UTF8STRING)}
      s2i_ASN1_UTF8STRING := FC_s2i_ASN1_UTF8STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(s2i_ASN1_UTF8STRING_removed)}
    if s2i_ASN1_UTF8STRING_removed <= LibVersion then
    begin
      {$if declared(_s2i_ASN1_UTF8STRING)}
      s2i_ASN1_UTF8STRING := _s2i_ASN1_UTF8STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(s2i_ASN1_UTF8STRING_allownil)}
    if FuncLoadError then
      AFailed.Add('s2i_ASN1_UTF8STRING');
    {$ifend}
  end;
  
  i2v_GENERAL_NAME := LoadLibFunction(ADllHandle, i2v_GENERAL_NAME_procname);
  FuncLoadError := not assigned(i2v_GENERAL_NAME);
  if FuncLoadError then
  begin
    {$if not defined(i2v_GENERAL_NAME_allownil)}
    i2v_GENERAL_NAME := ERR_i2v_GENERAL_NAME;
    {$ifend}
    {$if declared(i2v_GENERAL_NAME_introduced)}
    if LibVersion < i2v_GENERAL_NAME_introduced then
    begin
      {$if declared(FC_i2v_GENERAL_NAME)}
      i2v_GENERAL_NAME := FC_i2v_GENERAL_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2v_GENERAL_NAME_removed)}
    if i2v_GENERAL_NAME_removed <= LibVersion then
    begin
      {$if declared(_i2v_GENERAL_NAME)}
      i2v_GENERAL_NAME := _i2v_GENERAL_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2v_GENERAL_NAME_allownil)}
    if FuncLoadError then
      AFailed.Add('i2v_GENERAL_NAME');
    {$ifend}
  end;
  
  GENERAL_NAME_print := LoadLibFunction(ADllHandle, GENERAL_NAME_print_procname);
  FuncLoadError := not assigned(GENERAL_NAME_print);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_NAME_print_allownil)}
    GENERAL_NAME_print := ERR_GENERAL_NAME_print;
    {$ifend}
    {$if declared(GENERAL_NAME_print_introduced)}
    if LibVersion < GENERAL_NAME_print_introduced then
    begin
      {$if declared(FC_GENERAL_NAME_print)}
      GENERAL_NAME_print := FC_GENERAL_NAME_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_NAME_print_removed)}
    if GENERAL_NAME_print_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_NAME_print)}
      GENERAL_NAME_print := _GENERAL_NAME_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_NAME_print_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_NAME_print');
    {$ifend}
  end;
  
  GENERAL_NAMES_new := LoadLibFunction(ADllHandle, GENERAL_NAMES_new_procname);
  FuncLoadError := not assigned(GENERAL_NAMES_new);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_NAMES_new_allownil)}
    GENERAL_NAMES_new := ERR_GENERAL_NAMES_new;
    {$ifend}
    {$if declared(GENERAL_NAMES_new_introduced)}
    if LibVersion < GENERAL_NAMES_new_introduced then
    begin
      {$if declared(FC_GENERAL_NAMES_new)}
      GENERAL_NAMES_new := FC_GENERAL_NAMES_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_NAMES_new_removed)}
    if GENERAL_NAMES_new_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_NAMES_new)}
      GENERAL_NAMES_new := _GENERAL_NAMES_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_NAMES_new_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_NAMES_new');
    {$ifend}
  end;
  
  GENERAL_NAMES_free := LoadLibFunction(ADllHandle, GENERAL_NAMES_free_procname);
  FuncLoadError := not assigned(GENERAL_NAMES_free);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_NAMES_free_allownil)}
    GENERAL_NAMES_free := ERR_GENERAL_NAMES_free;
    {$ifend}
    {$if declared(GENERAL_NAMES_free_introduced)}
    if LibVersion < GENERAL_NAMES_free_introduced then
    begin
      {$if declared(FC_GENERAL_NAMES_free)}
      GENERAL_NAMES_free := FC_GENERAL_NAMES_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_NAMES_free_removed)}
    if GENERAL_NAMES_free_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_NAMES_free)}
      GENERAL_NAMES_free := _GENERAL_NAMES_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_NAMES_free_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_NAMES_free');
    {$ifend}
  end;
  
  d2i_GENERAL_NAMES := LoadLibFunction(ADllHandle, d2i_GENERAL_NAMES_procname);
  FuncLoadError := not assigned(d2i_GENERAL_NAMES);
  if FuncLoadError then
  begin
    {$if not defined(d2i_GENERAL_NAMES_allownil)}
    d2i_GENERAL_NAMES := ERR_d2i_GENERAL_NAMES;
    {$ifend}
    {$if declared(d2i_GENERAL_NAMES_introduced)}
    if LibVersion < d2i_GENERAL_NAMES_introduced then
    begin
      {$if declared(FC_d2i_GENERAL_NAMES)}
      d2i_GENERAL_NAMES := FC_d2i_GENERAL_NAMES;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_GENERAL_NAMES_removed)}
    if d2i_GENERAL_NAMES_removed <= LibVersion then
    begin
      {$if declared(_d2i_GENERAL_NAMES)}
      d2i_GENERAL_NAMES := _d2i_GENERAL_NAMES;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_GENERAL_NAMES_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_GENERAL_NAMES');
    {$ifend}
  end;
  
  i2d_GENERAL_NAMES := LoadLibFunction(ADllHandle, i2d_GENERAL_NAMES_procname);
  FuncLoadError := not assigned(i2d_GENERAL_NAMES);
  if FuncLoadError then
  begin
    {$if not defined(i2d_GENERAL_NAMES_allownil)}
    i2d_GENERAL_NAMES := ERR_i2d_GENERAL_NAMES;
    {$ifend}
    {$if declared(i2d_GENERAL_NAMES_introduced)}
    if LibVersion < i2d_GENERAL_NAMES_introduced then
    begin
      {$if declared(FC_i2d_GENERAL_NAMES)}
      i2d_GENERAL_NAMES := FC_i2d_GENERAL_NAMES;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_GENERAL_NAMES_removed)}
    if i2d_GENERAL_NAMES_removed <= LibVersion then
    begin
      {$if declared(_i2d_GENERAL_NAMES)}
      i2d_GENERAL_NAMES := _i2d_GENERAL_NAMES;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_GENERAL_NAMES_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_GENERAL_NAMES');
    {$ifend}
  end;
  
  GENERAL_NAMES_it := LoadLibFunction(ADllHandle, GENERAL_NAMES_it_procname);
  FuncLoadError := not assigned(GENERAL_NAMES_it);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_NAMES_it_allownil)}
    GENERAL_NAMES_it := ERR_GENERAL_NAMES_it;
    {$ifend}
    {$if declared(GENERAL_NAMES_it_introduced)}
    if LibVersion < GENERAL_NAMES_it_introduced then
    begin
      {$if declared(FC_GENERAL_NAMES_it)}
      GENERAL_NAMES_it := FC_GENERAL_NAMES_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_NAMES_it_removed)}
    if GENERAL_NAMES_it_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_NAMES_it)}
      GENERAL_NAMES_it := _GENERAL_NAMES_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_NAMES_it_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_NAMES_it');
    {$ifend}
  end;
  
  i2v_GENERAL_NAMES := LoadLibFunction(ADllHandle, i2v_GENERAL_NAMES_procname);
  FuncLoadError := not assigned(i2v_GENERAL_NAMES);
  if FuncLoadError then
  begin
    {$if not defined(i2v_GENERAL_NAMES_allownil)}
    i2v_GENERAL_NAMES := ERR_i2v_GENERAL_NAMES;
    {$ifend}
    {$if declared(i2v_GENERAL_NAMES_introduced)}
    if LibVersion < i2v_GENERAL_NAMES_introduced then
    begin
      {$if declared(FC_i2v_GENERAL_NAMES)}
      i2v_GENERAL_NAMES := FC_i2v_GENERAL_NAMES;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2v_GENERAL_NAMES_removed)}
    if i2v_GENERAL_NAMES_removed <= LibVersion then
    begin
      {$if declared(_i2v_GENERAL_NAMES)}
      i2v_GENERAL_NAMES := _i2v_GENERAL_NAMES;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2v_GENERAL_NAMES_allownil)}
    if FuncLoadError then
      AFailed.Add('i2v_GENERAL_NAMES');
    {$ifend}
  end;
  
  v2i_GENERAL_NAMES := LoadLibFunction(ADllHandle, v2i_GENERAL_NAMES_procname);
  FuncLoadError := not assigned(v2i_GENERAL_NAMES);
  if FuncLoadError then
  begin
    {$if not defined(v2i_GENERAL_NAMES_allownil)}
    v2i_GENERAL_NAMES := ERR_v2i_GENERAL_NAMES;
    {$ifend}
    {$if declared(v2i_GENERAL_NAMES_introduced)}
    if LibVersion < v2i_GENERAL_NAMES_introduced then
    begin
      {$if declared(FC_v2i_GENERAL_NAMES)}
      v2i_GENERAL_NAMES := FC_v2i_GENERAL_NAMES;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(v2i_GENERAL_NAMES_removed)}
    if v2i_GENERAL_NAMES_removed <= LibVersion then
    begin
      {$if declared(_v2i_GENERAL_NAMES)}
      v2i_GENERAL_NAMES := _v2i_GENERAL_NAMES;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(v2i_GENERAL_NAMES_allownil)}
    if FuncLoadError then
      AFailed.Add('v2i_GENERAL_NAMES');
    {$ifend}
  end;
  
  OTHERNAME_new := LoadLibFunction(ADllHandle, OTHERNAME_new_procname);
  FuncLoadError := not assigned(OTHERNAME_new);
  if FuncLoadError then
  begin
    {$if not defined(OTHERNAME_new_allownil)}
    OTHERNAME_new := ERR_OTHERNAME_new;
    {$ifend}
    {$if declared(OTHERNAME_new_introduced)}
    if LibVersion < OTHERNAME_new_introduced then
    begin
      {$if declared(FC_OTHERNAME_new)}
      OTHERNAME_new := FC_OTHERNAME_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OTHERNAME_new_removed)}
    if OTHERNAME_new_removed <= LibVersion then
    begin
      {$if declared(_OTHERNAME_new)}
      OTHERNAME_new := _OTHERNAME_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OTHERNAME_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OTHERNAME_new');
    {$ifend}
  end;
  
  OTHERNAME_free := LoadLibFunction(ADllHandle, OTHERNAME_free_procname);
  FuncLoadError := not assigned(OTHERNAME_free);
  if FuncLoadError then
  begin
    {$if not defined(OTHERNAME_free_allownil)}
    OTHERNAME_free := ERR_OTHERNAME_free;
    {$ifend}
    {$if declared(OTHERNAME_free_introduced)}
    if LibVersion < OTHERNAME_free_introduced then
    begin
      {$if declared(FC_OTHERNAME_free)}
      OTHERNAME_free := FC_OTHERNAME_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OTHERNAME_free_removed)}
    if OTHERNAME_free_removed <= LibVersion then
    begin
      {$if declared(_OTHERNAME_free)}
      OTHERNAME_free := _OTHERNAME_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OTHERNAME_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OTHERNAME_free');
    {$ifend}
  end;
  
  d2i_OTHERNAME := LoadLibFunction(ADllHandle, d2i_OTHERNAME_procname);
  FuncLoadError := not assigned(d2i_OTHERNAME);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OTHERNAME_allownil)}
    d2i_OTHERNAME := ERR_d2i_OTHERNAME;
    {$ifend}
    {$if declared(d2i_OTHERNAME_introduced)}
    if LibVersion < d2i_OTHERNAME_introduced then
    begin
      {$if declared(FC_d2i_OTHERNAME)}
      d2i_OTHERNAME := FC_d2i_OTHERNAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OTHERNAME_removed)}
    if d2i_OTHERNAME_removed <= LibVersion then
    begin
      {$if declared(_d2i_OTHERNAME)}
      d2i_OTHERNAME := _d2i_OTHERNAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OTHERNAME_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OTHERNAME');
    {$ifend}
  end;
  
  i2d_OTHERNAME := LoadLibFunction(ADllHandle, i2d_OTHERNAME_procname);
  FuncLoadError := not assigned(i2d_OTHERNAME);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OTHERNAME_allownil)}
    i2d_OTHERNAME := ERR_i2d_OTHERNAME;
    {$ifend}
    {$if declared(i2d_OTHERNAME_introduced)}
    if LibVersion < i2d_OTHERNAME_introduced then
    begin
      {$if declared(FC_i2d_OTHERNAME)}
      i2d_OTHERNAME := FC_i2d_OTHERNAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OTHERNAME_removed)}
    if i2d_OTHERNAME_removed <= LibVersion then
    begin
      {$if declared(_i2d_OTHERNAME)}
      i2d_OTHERNAME := _i2d_OTHERNAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OTHERNAME_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OTHERNAME');
    {$ifend}
  end;
  
  OTHERNAME_it := LoadLibFunction(ADllHandle, OTHERNAME_it_procname);
  FuncLoadError := not assigned(OTHERNAME_it);
  if FuncLoadError then
  begin
    {$if not defined(OTHERNAME_it_allownil)}
    OTHERNAME_it := ERR_OTHERNAME_it;
    {$ifend}
    {$if declared(OTHERNAME_it_introduced)}
    if LibVersion < OTHERNAME_it_introduced then
    begin
      {$if declared(FC_OTHERNAME_it)}
      OTHERNAME_it := FC_OTHERNAME_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OTHERNAME_it_removed)}
    if OTHERNAME_it_removed <= LibVersion then
    begin
      {$if declared(_OTHERNAME_it)}
      OTHERNAME_it := _OTHERNAME_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OTHERNAME_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OTHERNAME_it');
    {$ifend}
  end;
  
  EDIPARTYNAME_new := LoadLibFunction(ADllHandle, EDIPARTYNAME_new_procname);
  FuncLoadError := not assigned(EDIPARTYNAME_new);
  if FuncLoadError then
  begin
    {$if not defined(EDIPARTYNAME_new_allownil)}
    EDIPARTYNAME_new := ERR_EDIPARTYNAME_new;
    {$ifend}
    {$if declared(EDIPARTYNAME_new_introduced)}
    if LibVersion < EDIPARTYNAME_new_introduced then
    begin
      {$if declared(FC_EDIPARTYNAME_new)}
      EDIPARTYNAME_new := FC_EDIPARTYNAME_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EDIPARTYNAME_new_removed)}
    if EDIPARTYNAME_new_removed <= LibVersion then
    begin
      {$if declared(_EDIPARTYNAME_new)}
      EDIPARTYNAME_new := _EDIPARTYNAME_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EDIPARTYNAME_new_allownil)}
    if FuncLoadError then
      AFailed.Add('EDIPARTYNAME_new');
    {$ifend}
  end;
  
  EDIPARTYNAME_free := LoadLibFunction(ADllHandle, EDIPARTYNAME_free_procname);
  FuncLoadError := not assigned(EDIPARTYNAME_free);
  if FuncLoadError then
  begin
    {$if not defined(EDIPARTYNAME_free_allownil)}
    EDIPARTYNAME_free := ERR_EDIPARTYNAME_free;
    {$ifend}
    {$if declared(EDIPARTYNAME_free_introduced)}
    if LibVersion < EDIPARTYNAME_free_introduced then
    begin
      {$if declared(FC_EDIPARTYNAME_free)}
      EDIPARTYNAME_free := FC_EDIPARTYNAME_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EDIPARTYNAME_free_removed)}
    if EDIPARTYNAME_free_removed <= LibVersion then
    begin
      {$if declared(_EDIPARTYNAME_free)}
      EDIPARTYNAME_free := _EDIPARTYNAME_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EDIPARTYNAME_free_allownil)}
    if FuncLoadError then
      AFailed.Add('EDIPARTYNAME_free');
    {$ifend}
  end;
  
  d2i_EDIPARTYNAME := LoadLibFunction(ADllHandle, d2i_EDIPARTYNAME_procname);
  FuncLoadError := not assigned(d2i_EDIPARTYNAME);
  if FuncLoadError then
  begin
    {$if not defined(d2i_EDIPARTYNAME_allownil)}
    d2i_EDIPARTYNAME := ERR_d2i_EDIPARTYNAME;
    {$ifend}
    {$if declared(d2i_EDIPARTYNAME_introduced)}
    if LibVersion < d2i_EDIPARTYNAME_introduced then
    begin
      {$if declared(FC_d2i_EDIPARTYNAME)}
      d2i_EDIPARTYNAME := FC_d2i_EDIPARTYNAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_EDIPARTYNAME_removed)}
    if d2i_EDIPARTYNAME_removed <= LibVersion then
    begin
      {$if declared(_d2i_EDIPARTYNAME)}
      d2i_EDIPARTYNAME := _d2i_EDIPARTYNAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_EDIPARTYNAME_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_EDIPARTYNAME');
    {$ifend}
  end;
  
  i2d_EDIPARTYNAME := LoadLibFunction(ADllHandle, i2d_EDIPARTYNAME_procname);
  FuncLoadError := not assigned(i2d_EDIPARTYNAME);
  if FuncLoadError then
  begin
    {$if not defined(i2d_EDIPARTYNAME_allownil)}
    i2d_EDIPARTYNAME := ERR_i2d_EDIPARTYNAME;
    {$ifend}
    {$if declared(i2d_EDIPARTYNAME_introduced)}
    if LibVersion < i2d_EDIPARTYNAME_introduced then
    begin
      {$if declared(FC_i2d_EDIPARTYNAME)}
      i2d_EDIPARTYNAME := FC_i2d_EDIPARTYNAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_EDIPARTYNAME_removed)}
    if i2d_EDIPARTYNAME_removed <= LibVersion then
    begin
      {$if declared(_i2d_EDIPARTYNAME)}
      i2d_EDIPARTYNAME := _i2d_EDIPARTYNAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_EDIPARTYNAME_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_EDIPARTYNAME');
    {$ifend}
  end;
  
  EDIPARTYNAME_it := LoadLibFunction(ADllHandle, EDIPARTYNAME_it_procname);
  FuncLoadError := not assigned(EDIPARTYNAME_it);
  if FuncLoadError then
  begin
    {$if not defined(EDIPARTYNAME_it_allownil)}
    EDIPARTYNAME_it := ERR_EDIPARTYNAME_it;
    {$ifend}
    {$if declared(EDIPARTYNAME_it_introduced)}
    if LibVersion < EDIPARTYNAME_it_introduced then
    begin
      {$if declared(FC_EDIPARTYNAME_it)}
      EDIPARTYNAME_it := FC_EDIPARTYNAME_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EDIPARTYNAME_it_removed)}
    if EDIPARTYNAME_it_removed <= LibVersion then
    begin
      {$if declared(_EDIPARTYNAME_it)}
      EDIPARTYNAME_it := _EDIPARTYNAME_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EDIPARTYNAME_it_allownil)}
    if FuncLoadError then
      AFailed.Add('EDIPARTYNAME_it');
    {$ifend}
  end;
  
  OTHERNAME_cmp := LoadLibFunction(ADllHandle, OTHERNAME_cmp_procname);
  FuncLoadError := not assigned(OTHERNAME_cmp);
  if FuncLoadError then
  begin
    {$if not defined(OTHERNAME_cmp_allownil)}
    OTHERNAME_cmp := ERR_OTHERNAME_cmp;
    {$ifend}
    {$if declared(OTHERNAME_cmp_introduced)}
    if LibVersion < OTHERNAME_cmp_introduced then
    begin
      {$if declared(FC_OTHERNAME_cmp)}
      OTHERNAME_cmp := FC_OTHERNAME_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OTHERNAME_cmp_removed)}
    if OTHERNAME_cmp_removed <= LibVersion then
    begin
      {$if declared(_OTHERNAME_cmp)}
      OTHERNAME_cmp := _OTHERNAME_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OTHERNAME_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('OTHERNAME_cmp');
    {$ifend}
  end;
  
  GENERAL_NAME_set0_value := LoadLibFunction(ADllHandle, GENERAL_NAME_set0_value_procname);
  FuncLoadError := not assigned(GENERAL_NAME_set0_value);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_NAME_set0_value_allownil)}
    GENERAL_NAME_set0_value := ERR_GENERAL_NAME_set0_value;
    {$ifend}
    {$if declared(GENERAL_NAME_set0_value_introduced)}
    if LibVersion < GENERAL_NAME_set0_value_introduced then
    begin
      {$if declared(FC_GENERAL_NAME_set0_value)}
      GENERAL_NAME_set0_value := FC_GENERAL_NAME_set0_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_NAME_set0_value_removed)}
    if GENERAL_NAME_set0_value_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_NAME_set0_value)}
      GENERAL_NAME_set0_value := _GENERAL_NAME_set0_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_NAME_set0_value_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_NAME_set0_value');
    {$ifend}
  end;
  
  GENERAL_NAME_get0_value := LoadLibFunction(ADllHandle, GENERAL_NAME_get0_value_procname);
  FuncLoadError := not assigned(GENERAL_NAME_get0_value);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_NAME_get0_value_allownil)}
    GENERAL_NAME_get0_value := ERR_GENERAL_NAME_get0_value;
    {$ifend}
    {$if declared(GENERAL_NAME_get0_value_introduced)}
    if LibVersion < GENERAL_NAME_get0_value_introduced then
    begin
      {$if declared(FC_GENERAL_NAME_get0_value)}
      GENERAL_NAME_get0_value := FC_GENERAL_NAME_get0_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_NAME_get0_value_removed)}
    if GENERAL_NAME_get0_value_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_NAME_get0_value)}
      GENERAL_NAME_get0_value := _GENERAL_NAME_get0_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_NAME_get0_value_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_NAME_get0_value');
    {$ifend}
  end;
  
  GENERAL_NAME_set0_othername := LoadLibFunction(ADllHandle, GENERAL_NAME_set0_othername_procname);
  FuncLoadError := not assigned(GENERAL_NAME_set0_othername);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_NAME_set0_othername_allownil)}
    GENERAL_NAME_set0_othername := ERR_GENERAL_NAME_set0_othername;
    {$ifend}
    {$if declared(GENERAL_NAME_set0_othername_introduced)}
    if LibVersion < GENERAL_NAME_set0_othername_introduced then
    begin
      {$if declared(FC_GENERAL_NAME_set0_othername)}
      GENERAL_NAME_set0_othername := FC_GENERAL_NAME_set0_othername;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_NAME_set0_othername_removed)}
    if GENERAL_NAME_set0_othername_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_NAME_set0_othername)}
      GENERAL_NAME_set0_othername := _GENERAL_NAME_set0_othername;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_NAME_set0_othername_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_NAME_set0_othername');
    {$ifend}
  end;
  
  GENERAL_NAME_get0_otherName := LoadLibFunction(ADllHandle, GENERAL_NAME_get0_otherName_procname);
  FuncLoadError := not assigned(GENERAL_NAME_get0_otherName);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_NAME_get0_otherName_allownil)}
    GENERAL_NAME_get0_otherName := ERR_GENERAL_NAME_get0_otherName;
    {$ifend}
    {$if declared(GENERAL_NAME_get0_otherName_introduced)}
    if LibVersion < GENERAL_NAME_get0_otherName_introduced then
    begin
      {$if declared(FC_GENERAL_NAME_get0_otherName)}
      GENERAL_NAME_get0_otherName := FC_GENERAL_NAME_get0_otherName;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_NAME_get0_otherName_removed)}
    if GENERAL_NAME_get0_otherName_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_NAME_get0_otherName)}
      GENERAL_NAME_get0_otherName := _GENERAL_NAME_get0_otherName;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_NAME_get0_otherName_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_NAME_get0_otherName');
    {$ifend}
  end;
  
  i2s_ASN1_OCTET_STRING := LoadLibFunction(ADllHandle, i2s_ASN1_OCTET_STRING_procname);
  FuncLoadError := not assigned(i2s_ASN1_OCTET_STRING);
  if FuncLoadError then
  begin
    {$if not defined(i2s_ASN1_OCTET_STRING_allownil)}
    i2s_ASN1_OCTET_STRING := ERR_i2s_ASN1_OCTET_STRING;
    {$ifend}
    {$if declared(i2s_ASN1_OCTET_STRING_introduced)}
    if LibVersion < i2s_ASN1_OCTET_STRING_introduced then
    begin
      {$if declared(FC_i2s_ASN1_OCTET_STRING)}
      i2s_ASN1_OCTET_STRING := FC_i2s_ASN1_OCTET_STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2s_ASN1_OCTET_STRING_removed)}
    if i2s_ASN1_OCTET_STRING_removed <= LibVersion then
    begin
      {$if declared(_i2s_ASN1_OCTET_STRING)}
      i2s_ASN1_OCTET_STRING := _i2s_ASN1_OCTET_STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2s_ASN1_OCTET_STRING_allownil)}
    if FuncLoadError then
      AFailed.Add('i2s_ASN1_OCTET_STRING');
    {$ifend}
  end;
  
  s2i_ASN1_OCTET_STRING := LoadLibFunction(ADllHandle, s2i_ASN1_OCTET_STRING_procname);
  FuncLoadError := not assigned(s2i_ASN1_OCTET_STRING);
  if FuncLoadError then
  begin
    {$if not defined(s2i_ASN1_OCTET_STRING_allownil)}
    s2i_ASN1_OCTET_STRING := ERR_s2i_ASN1_OCTET_STRING;
    {$ifend}
    {$if declared(s2i_ASN1_OCTET_STRING_introduced)}
    if LibVersion < s2i_ASN1_OCTET_STRING_introduced then
    begin
      {$if declared(FC_s2i_ASN1_OCTET_STRING)}
      s2i_ASN1_OCTET_STRING := FC_s2i_ASN1_OCTET_STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(s2i_ASN1_OCTET_STRING_removed)}
    if s2i_ASN1_OCTET_STRING_removed <= LibVersion then
    begin
      {$if declared(_s2i_ASN1_OCTET_STRING)}
      s2i_ASN1_OCTET_STRING := _s2i_ASN1_OCTET_STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(s2i_ASN1_OCTET_STRING_allownil)}
    if FuncLoadError then
      AFailed.Add('s2i_ASN1_OCTET_STRING');
    {$ifend}
  end;
  
  EXTENDED_KEY_USAGE_new := LoadLibFunction(ADllHandle, EXTENDED_KEY_USAGE_new_procname);
  FuncLoadError := not assigned(EXTENDED_KEY_USAGE_new);
  if FuncLoadError then
  begin
    {$if not defined(EXTENDED_KEY_USAGE_new_allownil)}
    EXTENDED_KEY_USAGE_new := ERR_EXTENDED_KEY_USAGE_new;
    {$ifend}
    {$if declared(EXTENDED_KEY_USAGE_new_introduced)}
    if LibVersion < EXTENDED_KEY_USAGE_new_introduced then
    begin
      {$if declared(FC_EXTENDED_KEY_USAGE_new)}
      EXTENDED_KEY_USAGE_new := FC_EXTENDED_KEY_USAGE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EXTENDED_KEY_USAGE_new_removed)}
    if EXTENDED_KEY_USAGE_new_removed <= LibVersion then
    begin
      {$if declared(_EXTENDED_KEY_USAGE_new)}
      EXTENDED_KEY_USAGE_new := _EXTENDED_KEY_USAGE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EXTENDED_KEY_USAGE_new_allownil)}
    if FuncLoadError then
      AFailed.Add('EXTENDED_KEY_USAGE_new');
    {$ifend}
  end;
  
  EXTENDED_KEY_USAGE_free := LoadLibFunction(ADllHandle, EXTENDED_KEY_USAGE_free_procname);
  FuncLoadError := not assigned(EXTENDED_KEY_USAGE_free);
  if FuncLoadError then
  begin
    {$if not defined(EXTENDED_KEY_USAGE_free_allownil)}
    EXTENDED_KEY_USAGE_free := ERR_EXTENDED_KEY_USAGE_free;
    {$ifend}
    {$if declared(EXTENDED_KEY_USAGE_free_introduced)}
    if LibVersion < EXTENDED_KEY_USAGE_free_introduced then
    begin
      {$if declared(FC_EXTENDED_KEY_USAGE_free)}
      EXTENDED_KEY_USAGE_free := FC_EXTENDED_KEY_USAGE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EXTENDED_KEY_USAGE_free_removed)}
    if EXTENDED_KEY_USAGE_free_removed <= LibVersion then
    begin
      {$if declared(_EXTENDED_KEY_USAGE_free)}
      EXTENDED_KEY_USAGE_free := _EXTENDED_KEY_USAGE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EXTENDED_KEY_USAGE_free_allownil)}
    if FuncLoadError then
      AFailed.Add('EXTENDED_KEY_USAGE_free');
    {$ifend}
  end;
  
  d2i_EXTENDED_KEY_USAGE := LoadLibFunction(ADllHandle, d2i_EXTENDED_KEY_USAGE_procname);
  FuncLoadError := not assigned(d2i_EXTENDED_KEY_USAGE);
  if FuncLoadError then
  begin
    {$if not defined(d2i_EXTENDED_KEY_USAGE_allownil)}
    d2i_EXTENDED_KEY_USAGE := ERR_d2i_EXTENDED_KEY_USAGE;
    {$ifend}
    {$if declared(d2i_EXTENDED_KEY_USAGE_introduced)}
    if LibVersion < d2i_EXTENDED_KEY_USAGE_introduced then
    begin
      {$if declared(FC_d2i_EXTENDED_KEY_USAGE)}
      d2i_EXTENDED_KEY_USAGE := FC_d2i_EXTENDED_KEY_USAGE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_EXTENDED_KEY_USAGE_removed)}
    if d2i_EXTENDED_KEY_USAGE_removed <= LibVersion then
    begin
      {$if declared(_d2i_EXTENDED_KEY_USAGE)}
      d2i_EXTENDED_KEY_USAGE := _d2i_EXTENDED_KEY_USAGE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_EXTENDED_KEY_USAGE_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_EXTENDED_KEY_USAGE');
    {$ifend}
  end;
  
  i2d_EXTENDED_KEY_USAGE := LoadLibFunction(ADllHandle, i2d_EXTENDED_KEY_USAGE_procname);
  FuncLoadError := not assigned(i2d_EXTENDED_KEY_USAGE);
  if FuncLoadError then
  begin
    {$if not defined(i2d_EXTENDED_KEY_USAGE_allownil)}
    i2d_EXTENDED_KEY_USAGE := ERR_i2d_EXTENDED_KEY_USAGE;
    {$ifend}
    {$if declared(i2d_EXTENDED_KEY_USAGE_introduced)}
    if LibVersion < i2d_EXTENDED_KEY_USAGE_introduced then
    begin
      {$if declared(FC_i2d_EXTENDED_KEY_USAGE)}
      i2d_EXTENDED_KEY_USAGE := FC_i2d_EXTENDED_KEY_USAGE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_EXTENDED_KEY_USAGE_removed)}
    if i2d_EXTENDED_KEY_USAGE_removed <= LibVersion then
    begin
      {$if declared(_i2d_EXTENDED_KEY_USAGE)}
      i2d_EXTENDED_KEY_USAGE := _i2d_EXTENDED_KEY_USAGE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_EXTENDED_KEY_USAGE_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_EXTENDED_KEY_USAGE');
    {$ifend}
  end;
  
  EXTENDED_KEY_USAGE_it := LoadLibFunction(ADllHandle, EXTENDED_KEY_USAGE_it_procname);
  FuncLoadError := not assigned(EXTENDED_KEY_USAGE_it);
  if FuncLoadError then
  begin
    {$if not defined(EXTENDED_KEY_USAGE_it_allownil)}
    EXTENDED_KEY_USAGE_it := ERR_EXTENDED_KEY_USAGE_it;
    {$ifend}
    {$if declared(EXTENDED_KEY_USAGE_it_introduced)}
    if LibVersion < EXTENDED_KEY_USAGE_it_introduced then
    begin
      {$if declared(FC_EXTENDED_KEY_USAGE_it)}
      EXTENDED_KEY_USAGE_it := FC_EXTENDED_KEY_USAGE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EXTENDED_KEY_USAGE_it_removed)}
    if EXTENDED_KEY_USAGE_it_removed <= LibVersion then
    begin
      {$if declared(_EXTENDED_KEY_USAGE_it)}
      EXTENDED_KEY_USAGE_it := _EXTENDED_KEY_USAGE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EXTENDED_KEY_USAGE_it_allownil)}
    if FuncLoadError then
      AFailed.Add('EXTENDED_KEY_USAGE_it');
    {$ifend}
  end;
  
  i2a_ACCESS_DESCRIPTION := LoadLibFunction(ADllHandle, i2a_ACCESS_DESCRIPTION_procname);
  FuncLoadError := not assigned(i2a_ACCESS_DESCRIPTION);
  if FuncLoadError then
  begin
    {$if not defined(i2a_ACCESS_DESCRIPTION_allownil)}
    i2a_ACCESS_DESCRIPTION := ERR_i2a_ACCESS_DESCRIPTION;
    {$ifend}
    {$if declared(i2a_ACCESS_DESCRIPTION_introduced)}
    if LibVersion < i2a_ACCESS_DESCRIPTION_introduced then
    begin
      {$if declared(FC_i2a_ACCESS_DESCRIPTION)}
      i2a_ACCESS_DESCRIPTION := FC_i2a_ACCESS_DESCRIPTION;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2a_ACCESS_DESCRIPTION_removed)}
    if i2a_ACCESS_DESCRIPTION_removed <= LibVersion then
    begin
      {$if declared(_i2a_ACCESS_DESCRIPTION)}
      i2a_ACCESS_DESCRIPTION := _i2a_ACCESS_DESCRIPTION;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2a_ACCESS_DESCRIPTION_allownil)}
    if FuncLoadError then
      AFailed.Add('i2a_ACCESS_DESCRIPTION');
    {$ifend}
  end;
  
  TLS_FEATURE_new := LoadLibFunction(ADllHandle, TLS_FEATURE_new_procname);
  FuncLoadError := not assigned(TLS_FEATURE_new);
  if FuncLoadError then
  begin
    {$if not defined(TLS_FEATURE_new_allownil)}
    TLS_FEATURE_new := ERR_TLS_FEATURE_new;
    {$ifend}
    {$if declared(TLS_FEATURE_new_introduced)}
    if LibVersion < TLS_FEATURE_new_introduced then
    begin
      {$if declared(FC_TLS_FEATURE_new)}
      TLS_FEATURE_new := FC_TLS_FEATURE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TLS_FEATURE_new_removed)}
    if TLS_FEATURE_new_removed <= LibVersion then
    begin
      {$if declared(_TLS_FEATURE_new)}
      TLS_FEATURE_new := _TLS_FEATURE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TLS_FEATURE_new_allownil)}
    if FuncLoadError then
      AFailed.Add('TLS_FEATURE_new');
    {$ifend}
  end;
  
  TLS_FEATURE_free := LoadLibFunction(ADllHandle, TLS_FEATURE_free_procname);
  FuncLoadError := not assigned(TLS_FEATURE_free);
  if FuncLoadError then
  begin
    {$if not defined(TLS_FEATURE_free_allownil)}
    TLS_FEATURE_free := ERR_TLS_FEATURE_free;
    {$ifend}
    {$if declared(TLS_FEATURE_free_introduced)}
    if LibVersion < TLS_FEATURE_free_introduced then
    begin
      {$if declared(FC_TLS_FEATURE_free)}
      TLS_FEATURE_free := FC_TLS_FEATURE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TLS_FEATURE_free_removed)}
    if TLS_FEATURE_free_removed <= LibVersion then
    begin
      {$if declared(_TLS_FEATURE_free)}
      TLS_FEATURE_free := _TLS_FEATURE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TLS_FEATURE_free_allownil)}
    if FuncLoadError then
      AFailed.Add('TLS_FEATURE_free');
    {$ifend}
  end;
  
  CERTIFICATEPOLICIES_new := LoadLibFunction(ADllHandle, CERTIFICATEPOLICIES_new_procname);
  FuncLoadError := not assigned(CERTIFICATEPOLICIES_new);
  if FuncLoadError then
  begin
    {$if not defined(CERTIFICATEPOLICIES_new_allownil)}
    CERTIFICATEPOLICIES_new := ERR_CERTIFICATEPOLICIES_new;
    {$ifend}
    {$if declared(CERTIFICATEPOLICIES_new_introduced)}
    if LibVersion < CERTIFICATEPOLICIES_new_introduced then
    begin
      {$if declared(FC_CERTIFICATEPOLICIES_new)}
      CERTIFICATEPOLICIES_new := FC_CERTIFICATEPOLICIES_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CERTIFICATEPOLICIES_new_removed)}
    if CERTIFICATEPOLICIES_new_removed <= LibVersion then
    begin
      {$if declared(_CERTIFICATEPOLICIES_new)}
      CERTIFICATEPOLICIES_new := _CERTIFICATEPOLICIES_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CERTIFICATEPOLICIES_new_allownil)}
    if FuncLoadError then
      AFailed.Add('CERTIFICATEPOLICIES_new');
    {$ifend}
  end;
  
  CERTIFICATEPOLICIES_free := LoadLibFunction(ADllHandle, CERTIFICATEPOLICIES_free_procname);
  FuncLoadError := not assigned(CERTIFICATEPOLICIES_free);
  if FuncLoadError then
  begin
    {$if not defined(CERTIFICATEPOLICIES_free_allownil)}
    CERTIFICATEPOLICIES_free := ERR_CERTIFICATEPOLICIES_free;
    {$ifend}
    {$if declared(CERTIFICATEPOLICIES_free_introduced)}
    if LibVersion < CERTIFICATEPOLICIES_free_introduced then
    begin
      {$if declared(FC_CERTIFICATEPOLICIES_free)}
      CERTIFICATEPOLICIES_free := FC_CERTIFICATEPOLICIES_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CERTIFICATEPOLICIES_free_removed)}
    if CERTIFICATEPOLICIES_free_removed <= LibVersion then
    begin
      {$if declared(_CERTIFICATEPOLICIES_free)}
      CERTIFICATEPOLICIES_free := _CERTIFICATEPOLICIES_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CERTIFICATEPOLICIES_free_allownil)}
    if FuncLoadError then
      AFailed.Add('CERTIFICATEPOLICIES_free');
    {$ifend}
  end;
  
  d2i_CERTIFICATEPOLICIES := LoadLibFunction(ADllHandle, d2i_CERTIFICATEPOLICIES_procname);
  FuncLoadError := not assigned(d2i_CERTIFICATEPOLICIES);
  if FuncLoadError then
  begin
    {$if not defined(d2i_CERTIFICATEPOLICIES_allownil)}
    d2i_CERTIFICATEPOLICIES := ERR_d2i_CERTIFICATEPOLICIES;
    {$ifend}
    {$if declared(d2i_CERTIFICATEPOLICIES_introduced)}
    if LibVersion < d2i_CERTIFICATEPOLICIES_introduced then
    begin
      {$if declared(FC_d2i_CERTIFICATEPOLICIES)}
      d2i_CERTIFICATEPOLICIES := FC_d2i_CERTIFICATEPOLICIES;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_CERTIFICATEPOLICIES_removed)}
    if d2i_CERTIFICATEPOLICIES_removed <= LibVersion then
    begin
      {$if declared(_d2i_CERTIFICATEPOLICIES)}
      d2i_CERTIFICATEPOLICIES := _d2i_CERTIFICATEPOLICIES;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_CERTIFICATEPOLICIES_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_CERTIFICATEPOLICIES');
    {$ifend}
  end;
  
  i2d_CERTIFICATEPOLICIES := LoadLibFunction(ADllHandle, i2d_CERTIFICATEPOLICIES_procname);
  FuncLoadError := not assigned(i2d_CERTIFICATEPOLICIES);
  if FuncLoadError then
  begin
    {$if not defined(i2d_CERTIFICATEPOLICIES_allownil)}
    i2d_CERTIFICATEPOLICIES := ERR_i2d_CERTIFICATEPOLICIES;
    {$ifend}
    {$if declared(i2d_CERTIFICATEPOLICIES_introduced)}
    if LibVersion < i2d_CERTIFICATEPOLICIES_introduced then
    begin
      {$if declared(FC_i2d_CERTIFICATEPOLICIES)}
      i2d_CERTIFICATEPOLICIES := FC_i2d_CERTIFICATEPOLICIES;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_CERTIFICATEPOLICIES_removed)}
    if i2d_CERTIFICATEPOLICIES_removed <= LibVersion then
    begin
      {$if declared(_i2d_CERTIFICATEPOLICIES)}
      i2d_CERTIFICATEPOLICIES := _i2d_CERTIFICATEPOLICIES;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_CERTIFICATEPOLICIES_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_CERTIFICATEPOLICIES');
    {$ifend}
  end;
  
  CERTIFICATEPOLICIES_it := LoadLibFunction(ADllHandle, CERTIFICATEPOLICIES_it_procname);
  FuncLoadError := not assigned(CERTIFICATEPOLICIES_it);
  if FuncLoadError then
  begin
    {$if not defined(CERTIFICATEPOLICIES_it_allownil)}
    CERTIFICATEPOLICIES_it := ERR_CERTIFICATEPOLICIES_it;
    {$ifend}
    {$if declared(CERTIFICATEPOLICIES_it_introduced)}
    if LibVersion < CERTIFICATEPOLICIES_it_introduced then
    begin
      {$if declared(FC_CERTIFICATEPOLICIES_it)}
      CERTIFICATEPOLICIES_it := FC_CERTIFICATEPOLICIES_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CERTIFICATEPOLICIES_it_removed)}
    if CERTIFICATEPOLICIES_it_removed <= LibVersion then
    begin
      {$if declared(_CERTIFICATEPOLICIES_it)}
      CERTIFICATEPOLICIES_it := _CERTIFICATEPOLICIES_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CERTIFICATEPOLICIES_it_allownil)}
    if FuncLoadError then
      AFailed.Add('CERTIFICATEPOLICIES_it');
    {$ifend}
  end;
  
  POLICYINFO_new := LoadLibFunction(ADllHandle, POLICYINFO_new_procname);
  FuncLoadError := not assigned(POLICYINFO_new);
  if FuncLoadError then
  begin
    {$if not defined(POLICYINFO_new_allownil)}
    POLICYINFO_new := ERR_POLICYINFO_new;
    {$ifend}
    {$if declared(POLICYINFO_new_introduced)}
    if LibVersion < POLICYINFO_new_introduced then
    begin
      {$if declared(FC_POLICYINFO_new)}
      POLICYINFO_new := FC_POLICYINFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(POLICYINFO_new_removed)}
    if POLICYINFO_new_removed <= LibVersion then
    begin
      {$if declared(_POLICYINFO_new)}
      POLICYINFO_new := _POLICYINFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(POLICYINFO_new_allownil)}
    if FuncLoadError then
      AFailed.Add('POLICYINFO_new');
    {$ifend}
  end;
  
  POLICYINFO_free := LoadLibFunction(ADllHandle, POLICYINFO_free_procname);
  FuncLoadError := not assigned(POLICYINFO_free);
  if FuncLoadError then
  begin
    {$if not defined(POLICYINFO_free_allownil)}
    POLICYINFO_free := ERR_POLICYINFO_free;
    {$ifend}
    {$if declared(POLICYINFO_free_introduced)}
    if LibVersion < POLICYINFO_free_introduced then
    begin
      {$if declared(FC_POLICYINFO_free)}
      POLICYINFO_free := FC_POLICYINFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(POLICYINFO_free_removed)}
    if POLICYINFO_free_removed <= LibVersion then
    begin
      {$if declared(_POLICYINFO_free)}
      POLICYINFO_free := _POLICYINFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(POLICYINFO_free_allownil)}
    if FuncLoadError then
      AFailed.Add('POLICYINFO_free');
    {$ifend}
  end;
  
  d2i_POLICYINFO := LoadLibFunction(ADllHandle, d2i_POLICYINFO_procname);
  FuncLoadError := not assigned(d2i_POLICYINFO);
  if FuncLoadError then
  begin
    {$if not defined(d2i_POLICYINFO_allownil)}
    d2i_POLICYINFO := ERR_d2i_POLICYINFO;
    {$ifend}
    {$if declared(d2i_POLICYINFO_introduced)}
    if LibVersion < d2i_POLICYINFO_introduced then
    begin
      {$if declared(FC_d2i_POLICYINFO)}
      d2i_POLICYINFO := FC_d2i_POLICYINFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_POLICYINFO_removed)}
    if d2i_POLICYINFO_removed <= LibVersion then
    begin
      {$if declared(_d2i_POLICYINFO)}
      d2i_POLICYINFO := _d2i_POLICYINFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_POLICYINFO_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_POLICYINFO');
    {$ifend}
  end;
  
  i2d_POLICYINFO := LoadLibFunction(ADllHandle, i2d_POLICYINFO_procname);
  FuncLoadError := not assigned(i2d_POLICYINFO);
  if FuncLoadError then
  begin
    {$if not defined(i2d_POLICYINFO_allownil)}
    i2d_POLICYINFO := ERR_i2d_POLICYINFO;
    {$ifend}
    {$if declared(i2d_POLICYINFO_introduced)}
    if LibVersion < i2d_POLICYINFO_introduced then
    begin
      {$if declared(FC_i2d_POLICYINFO)}
      i2d_POLICYINFO := FC_i2d_POLICYINFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_POLICYINFO_removed)}
    if i2d_POLICYINFO_removed <= LibVersion then
    begin
      {$if declared(_i2d_POLICYINFO)}
      i2d_POLICYINFO := _i2d_POLICYINFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_POLICYINFO_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_POLICYINFO');
    {$ifend}
  end;
  
  POLICYINFO_it := LoadLibFunction(ADllHandle, POLICYINFO_it_procname);
  FuncLoadError := not assigned(POLICYINFO_it);
  if FuncLoadError then
  begin
    {$if not defined(POLICYINFO_it_allownil)}
    POLICYINFO_it := ERR_POLICYINFO_it;
    {$ifend}
    {$if declared(POLICYINFO_it_introduced)}
    if LibVersion < POLICYINFO_it_introduced then
    begin
      {$if declared(FC_POLICYINFO_it)}
      POLICYINFO_it := FC_POLICYINFO_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(POLICYINFO_it_removed)}
    if POLICYINFO_it_removed <= LibVersion then
    begin
      {$if declared(_POLICYINFO_it)}
      POLICYINFO_it := _POLICYINFO_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(POLICYINFO_it_allownil)}
    if FuncLoadError then
      AFailed.Add('POLICYINFO_it');
    {$ifend}
  end;
  
  POLICYQUALINFO_new := LoadLibFunction(ADllHandle, POLICYQUALINFO_new_procname);
  FuncLoadError := not assigned(POLICYQUALINFO_new);
  if FuncLoadError then
  begin
    {$if not defined(POLICYQUALINFO_new_allownil)}
    POLICYQUALINFO_new := ERR_POLICYQUALINFO_new;
    {$ifend}
    {$if declared(POLICYQUALINFO_new_introduced)}
    if LibVersion < POLICYQUALINFO_new_introduced then
    begin
      {$if declared(FC_POLICYQUALINFO_new)}
      POLICYQUALINFO_new := FC_POLICYQUALINFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(POLICYQUALINFO_new_removed)}
    if POLICYQUALINFO_new_removed <= LibVersion then
    begin
      {$if declared(_POLICYQUALINFO_new)}
      POLICYQUALINFO_new := _POLICYQUALINFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(POLICYQUALINFO_new_allownil)}
    if FuncLoadError then
      AFailed.Add('POLICYQUALINFO_new');
    {$ifend}
  end;
  
  POLICYQUALINFO_free := LoadLibFunction(ADllHandle, POLICYQUALINFO_free_procname);
  FuncLoadError := not assigned(POLICYQUALINFO_free);
  if FuncLoadError then
  begin
    {$if not defined(POLICYQUALINFO_free_allownil)}
    POLICYQUALINFO_free := ERR_POLICYQUALINFO_free;
    {$ifend}
    {$if declared(POLICYQUALINFO_free_introduced)}
    if LibVersion < POLICYQUALINFO_free_introduced then
    begin
      {$if declared(FC_POLICYQUALINFO_free)}
      POLICYQUALINFO_free := FC_POLICYQUALINFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(POLICYQUALINFO_free_removed)}
    if POLICYQUALINFO_free_removed <= LibVersion then
    begin
      {$if declared(_POLICYQUALINFO_free)}
      POLICYQUALINFO_free := _POLICYQUALINFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(POLICYQUALINFO_free_allownil)}
    if FuncLoadError then
      AFailed.Add('POLICYQUALINFO_free');
    {$ifend}
  end;
  
  d2i_POLICYQUALINFO := LoadLibFunction(ADllHandle, d2i_POLICYQUALINFO_procname);
  FuncLoadError := not assigned(d2i_POLICYQUALINFO);
  if FuncLoadError then
  begin
    {$if not defined(d2i_POLICYQUALINFO_allownil)}
    d2i_POLICYQUALINFO := ERR_d2i_POLICYQUALINFO;
    {$ifend}
    {$if declared(d2i_POLICYQUALINFO_introduced)}
    if LibVersion < d2i_POLICYQUALINFO_introduced then
    begin
      {$if declared(FC_d2i_POLICYQUALINFO)}
      d2i_POLICYQUALINFO := FC_d2i_POLICYQUALINFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_POLICYQUALINFO_removed)}
    if d2i_POLICYQUALINFO_removed <= LibVersion then
    begin
      {$if declared(_d2i_POLICYQUALINFO)}
      d2i_POLICYQUALINFO := _d2i_POLICYQUALINFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_POLICYQUALINFO_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_POLICYQUALINFO');
    {$ifend}
  end;
  
  i2d_POLICYQUALINFO := LoadLibFunction(ADllHandle, i2d_POLICYQUALINFO_procname);
  FuncLoadError := not assigned(i2d_POLICYQUALINFO);
  if FuncLoadError then
  begin
    {$if not defined(i2d_POLICYQUALINFO_allownil)}
    i2d_POLICYQUALINFO := ERR_i2d_POLICYQUALINFO;
    {$ifend}
    {$if declared(i2d_POLICYQUALINFO_introduced)}
    if LibVersion < i2d_POLICYQUALINFO_introduced then
    begin
      {$if declared(FC_i2d_POLICYQUALINFO)}
      i2d_POLICYQUALINFO := FC_i2d_POLICYQUALINFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_POLICYQUALINFO_removed)}
    if i2d_POLICYQUALINFO_removed <= LibVersion then
    begin
      {$if declared(_i2d_POLICYQUALINFO)}
      i2d_POLICYQUALINFO := _i2d_POLICYQUALINFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_POLICYQUALINFO_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_POLICYQUALINFO');
    {$ifend}
  end;
  
  POLICYQUALINFO_it := LoadLibFunction(ADllHandle, POLICYQUALINFO_it_procname);
  FuncLoadError := not assigned(POLICYQUALINFO_it);
  if FuncLoadError then
  begin
    {$if not defined(POLICYQUALINFO_it_allownil)}
    POLICYQUALINFO_it := ERR_POLICYQUALINFO_it;
    {$ifend}
    {$if declared(POLICYQUALINFO_it_introduced)}
    if LibVersion < POLICYQUALINFO_it_introduced then
    begin
      {$if declared(FC_POLICYQUALINFO_it)}
      POLICYQUALINFO_it := FC_POLICYQUALINFO_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(POLICYQUALINFO_it_removed)}
    if POLICYQUALINFO_it_removed <= LibVersion then
    begin
      {$if declared(_POLICYQUALINFO_it)}
      POLICYQUALINFO_it := _POLICYQUALINFO_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(POLICYQUALINFO_it_allownil)}
    if FuncLoadError then
      AFailed.Add('POLICYQUALINFO_it');
    {$ifend}
  end;
  
  USERNOTICE_new := LoadLibFunction(ADllHandle, USERNOTICE_new_procname);
  FuncLoadError := not assigned(USERNOTICE_new);
  if FuncLoadError then
  begin
    {$if not defined(USERNOTICE_new_allownil)}
    USERNOTICE_new := ERR_USERNOTICE_new;
    {$ifend}
    {$if declared(USERNOTICE_new_introduced)}
    if LibVersion < USERNOTICE_new_introduced then
    begin
      {$if declared(FC_USERNOTICE_new)}
      USERNOTICE_new := FC_USERNOTICE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(USERNOTICE_new_removed)}
    if USERNOTICE_new_removed <= LibVersion then
    begin
      {$if declared(_USERNOTICE_new)}
      USERNOTICE_new := _USERNOTICE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(USERNOTICE_new_allownil)}
    if FuncLoadError then
      AFailed.Add('USERNOTICE_new');
    {$ifend}
  end;
  
  USERNOTICE_free := LoadLibFunction(ADllHandle, USERNOTICE_free_procname);
  FuncLoadError := not assigned(USERNOTICE_free);
  if FuncLoadError then
  begin
    {$if not defined(USERNOTICE_free_allownil)}
    USERNOTICE_free := ERR_USERNOTICE_free;
    {$ifend}
    {$if declared(USERNOTICE_free_introduced)}
    if LibVersion < USERNOTICE_free_introduced then
    begin
      {$if declared(FC_USERNOTICE_free)}
      USERNOTICE_free := FC_USERNOTICE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(USERNOTICE_free_removed)}
    if USERNOTICE_free_removed <= LibVersion then
    begin
      {$if declared(_USERNOTICE_free)}
      USERNOTICE_free := _USERNOTICE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(USERNOTICE_free_allownil)}
    if FuncLoadError then
      AFailed.Add('USERNOTICE_free');
    {$ifend}
  end;
  
  d2i_USERNOTICE := LoadLibFunction(ADllHandle, d2i_USERNOTICE_procname);
  FuncLoadError := not assigned(d2i_USERNOTICE);
  if FuncLoadError then
  begin
    {$if not defined(d2i_USERNOTICE_allownil)}
    d2i_USERNOTICE := ERR_d2i_USERNOTICE;
    {$ifend}
    {$if declared(d2i_USERNOTICE_introduced)}
    if LibVersion < d2i_USERNOTICE_introduced then
    begin
      {$if declared(FC_d2i_USERNOTICE)}
      d2i_USERNOTICE := FC_d2i_USERNOTICE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_USERNOTICE_removed)}
    if d2i_USERNOTICE_removed <= LibVersion then
    begin
      {$if declared(_d2i_USERNOTICE)}
      d2i_USERNOTICE := _d2i_USERNOTICE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_USERNOTICE_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_USERNOTICE');
    {$ifend}
  end;
  
  i2d_USERNOTICE := LoadLibFunction(ADllHandle, i2d_USERNOTICE_procname);
  FuncLoadError := not assigned(i2d_USERNOTICE);
  if FuncLoadError then
  begin
    {$if not defined(i2d_USERNOTICE_allownil)}
    i2d_USERNOTICE := ERR_i2d_USERNOTICE;
    {$ifend}
    {$if declared(i2d_USERNOTICE_introduced)}
    if LibVersion < i2d_USERNOTICE_introduced then
    begin
      {$if declared(FC_i2d_USERNOTICE)}
      i2d_USERNOTICE := FC_i2d_USERNOTICE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_USERNOTICE_removed)}
    if i2d_USERNOTICE_removed <= LibVersion then
    begin
      {$if declared(_i2d_USERNOTICE)}
      i2d_USERNOTICE := _i2d_USERNOTICE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_USERNOTICE_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_USERNOTICE');
    {$ifend}
  end;
  
  USERNOTICE_it := LoadLibFunction(ADllHandle, USERNOTICE_it_procname);
  FuncLoadError := not assigned(USERNOTICE_it);
  if FuncLoadError then
  begin
    {$if not defined(USERNOTICE_it_allownil)}
    USERNOTICE_it := ERR_USERNOTICE_it;
    {$ifend}
    {$if declared(USERNOTICE_it_introduced)}
    if LibVersion < USERNOTICE_it_introduced then
    begin
      {$if declared(FC_USERNOTICE_it)}
      USERNOTICE_it := FC_USERNOTICE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(USERNOTICE_it_removed)}
    if USERNOTICE_it_removed <= LibVersion then
    begin
      {$if declared(_USERNOTICE_it)}
      USERNOTICE_it := _USERNOTICE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(USERNOTICE_it_allownil)}
    if FuncLoadError then
      AFailed.Add('USERNOTICE_it');
    {$ifend}
  end;
  
  NOTICEREF_new := LoadLibFunction(ADllHandle, NOTICEREF_new_procname);
  FuncLoadError := not assigned(NOTICEREF_new);
  if FuncLoadError then
  begin
    {$if not defined(NOTICEREF_new_allownil)}
    NOTICEREF_new := ERR_NOTICEREF_new;
    {$ifend}
    {$if declared(NOTICEREF_new_introduced)}
    if LibVersion < NOTICEREF_new_introduced then
    begin
      {$if declared(FC_NOTICEREF_new)}
      NOTICEREF_new := FC_NOTICEREF_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NOTICEREF_new_removed)}
    if NOTICEREF_new_removed <= LibVersion then
    begin
      {$if declared(_NOTICEREF_new)}
      NOTICEREF_new := _NOTICEREF_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NOTICEREF_new_allownil)}
    if FuncLoadError then
      AFailed.Add('NOTICEREF_new');
    {$ifend}
  end;
  
  NOTICEREF_free := LoadLibFunction(ADllHandle, NOTICEREF_free_procname);
  FuncLoadError := not assigned(NOTICEREF_free);
  if FuncLoadError then
  begin
    {$if not defined(NOTICEREF_free_allownil)}
    NOTICEREF_free := ERR_NOTICEREF_free;
    {$ifend}
    {$if declared(NOTICEREF_free_introduced)}
    if LibVersion < NOTICEREF_free_introduced then
    begin
      {$if declared(FC_NOTICEREF_free)}
      NOTICEREF_free := FC_NOTICEREF_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NOTICEREF_free_removed)}
    if NOTICEREF_free_removed <= LibVersion then
    begin
      {$if declared(_NOTICEREF_free)}
      NOTICEREF_free := _NOTICEREF_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NOTICEREF_free_allownil)}
    if FuncLoadError then
      AFailed.Add('NOTICEREF_free');
    {$ifend}
  end;
  
  d2i_NOTICEREF := LoadLibFunction(ADllHandle, d2i_NOTICEREF_procname);
  FuncLoadError := not assigned(d2i_NOTICEREF);
  if FuncLoadError then
  begin
    {$if not defined(d2i_NOTICEREF_allownil)}
    d2i_NOTICEREF := ERR_d2i_NOTICEREF;
    {$ifend}
    {$if declared(d2i_NOTICEREF_introduced)}
    if LibVersion < d2i_NOTICEREF_introduced then
    begin
      {$if declared(FC_d2i_NOTICEREF)}
      d2i_NOTICEREF := FC_d2i_NOTICEREF;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_NOTICEREF_removed)}
    if d2i_NOTICEREF_removed <= LibVersion then
    begin
      {$if declared(_d2i_NOTICEREF)}
      d2i_NOTICEREF := _d2i_NOTICEREF;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_NOTICEREF_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_NOTICEREF');
    {$ifend}
  end;
  
  i2d_NOTICEREF := LoadLibFunction(ADllHandle, i2d_NOTICEREF_procname);
  FuncLoadError := not assigned(i2d_NOTICEREF);
  if FuncLoadError then
  begin
    {$if not defined(i2d_NOTICEREF_allownil)}
    i2d_NOTICEREF := ERR_i2d_NOTICEREF;
    {$ifend}
    {$if declared(i2d_NOTICEREF_introduced)}
    if LibVersion < i2d_NOTICEREF_introduced then
    begin
      {$if declared(FC_i2d_NOTICEREF)}
      i2d_NOTICEREF := FC_i2d_NOTICEREF;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_NOTICEREF_removed)}
    if i2d_NOTICEREF_removed <= LibVersion then
    begin
      {$if declared(_i2d_NOTICEREF)}
      i2d_NOTICEREF := _i2d_NOTICEREF;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_NOTICEREF_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_NOTICEREF');
    {$ifend}
  end;
  
  NOTICEREF_it := LoadLibFunction(ADllHandle, NOTICEREF_it_procname);
  FuncLoadError := not assigned(NOTICEREF_it);
  if FuncLoadError then
  begin
    {$if not defined(NOTICEREF_it_allownil)}
    NOTICEREF_it := ERR_NOTICEREF_it;
    {$ifend}
    {$if declared(NOTICEREF_it_introduced)}
    if LibVersion < NOTICEREF_it_introduced then
    begin
      {$if declared(FC_NOTICEREF_it)}
      NOTICEREF_it := FC_NOTICEREF_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NOTICEREF_it_removed)}
    if NOTICEREF_it_removed <= LibVersion then
    begin
      {$if declared(_NOTICEREF_it)}
      NOTICEREF_it := _NOTICEREF_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NOTICEREF_it_allownil)}
    if FuncLoadError then
      AFailed.Add('NOTICEREF_it');
    {$ifend}
  end;
  
  CRL_DIST_POINTS_new := LoadLibFunction(ADllHandle, CRL_DIST_POINTS_new_procname);
  FuncLoadError := not assigned(CRL_DIST_POINTS_new);
  if FuncLoadError then
  begin
    {$if not defined(CRL_DIST_POINTS_new_allownil)}
    CRL_DIST_POINTS_new := ERR_CRL_DIST_POINTS_new;
    {$ifend}
    {$if declared(CRL_DIST_POINTS_new_introduced)}
    if LibVersion < CRL_DIST_POINTS_new_introduced then
    begin
      {$if declared(FC_CRL_DIST_POINTS_new)}
      CRL_DIST_POINTS_new := FC_CRL_DIST_POINTS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRL_DIST_POINTS_new_removed)}
    if CRL_DIST_POINTS_new_removed <= LibVersion then
    begin
      {$if declared(_CRL_DIST_POINTS_new)}
      CRL_DIST_POINTS_new := _CRL_DIST_POINTS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRL_DIST_POINTS_new_allownil)}
    if FuncLoadError then
      AFailed.Add('CRL_DIST_POINTS_new');
    {$ifend}
  end;
  
  CRL_DIST_POINTS_free := LoadLibFunction(ADllHandle, CRL_DIST_POINTS_free_procname);
  FuncLoadError := not assigned(CRL_DIST_POINTS_free);
  if FuncLoadError then
  begin
    {$if not defined(CRL_DIST_POINTS_free_allownil)}
    CRL_DIST_POINTS_free := ERR_CRL_DIST_POINTS_free;
    {$ifend}
    {$if declared(CRL_DIST_POINTS_free_introduced)}
    if LibVersion < CRL_DIST_POINTS_free_introduced then
    begin
      {$if declared(FC_CRL_DIST_POINTS_free)}
      CRL_DIST_POINTS_free := FC_CRL_DIST_POINTS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRL_DIST_POINTS_free_removed)}
    if CRL_DIST_POINTS_free_removed <= LibVersion then
    begin
      {$if declared(_CRL_DIST_POINTS_free)}
      CRL_DIST_POINTS_free := _CRL_DIST_POINTS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRL_DIST_POINTS_free_allownil)}
    if FuncLoadError then
      AFailed.Add('CRL_DIST_POINTS_free');
    {$ifend}
  end;
  
  d2i_CRL_DIST_POINTS := LoadLibFunction(ADllHandle, d2i_CRL_DIST_POINTS_procname);
  FuncLoadError := not assigned(d2i_CRL_DIST_POINTS);
  if FuncLoadError then
  begin
    {$if not defined(d2i_CRL_DIST_POINTS_allownil)}
    d2i_CRL_DIST_POINTS := ERR_d2i_CRL_DIST_POINTS;
    {$ifend}
    {$if declared(d2i_CRL_DIST_POINTS_introduced)}
    if LibVersion < d2i_CRL_DIST_POINTS_introduced then
    begin
      {$if declared(FC_d2i_CRL_DIST_POINTS)}
      d2i_CRL_DIST_POINTS := FC_d2i_CRL_DIST_POINTS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_CRL_DIST_POINTS_removed)}
    if d2i_CRL_DIST_POINTS_removed <= LibVersion then
    begin
      {$if declared(_d2i_CRL_DIST_POINTS)}
      d2i_CRL_DIST_POINTS := _d2i_CRL_DIST_POINTS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_CRL_DIST_POINTS_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_CRL_DIST_POINTS');
    {$ifend}
  end;
  
  i2d_CRL_DIST_POINTS := LoadLibFunction(ADllHandle, i2d_CRL_DIST_POINTS_procname);
  FuncLoadError := not assigned(i2d_CRL_DIST_POINTS);
  if FuncLoadError then
  begin
    {$if not defined(i2d_CRL_DIST_POINTS_allownil)}
    i2d_CRL_DIST_POINTS := ERR_i2d_CRL_DIST_POINTS;
    {$ifend}
    {$if declared(i2d_CRL_DIST_POINTS_introduced)}
    if LibVersion < i2d_CRL_DIST_POINTS_introduced then
    begin
      {$if declared(FC_i2d_CRL_DIST_POINTS)}
      i2d_CRL_DIST_POINTS := FC_i2d_CRL_DIST_POINTS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_CRL_DIST_POINTS_removed)}
    if i2d_CRL_DIST_POINTS_removed <= LibVersion then
    begin
      {$if declared(_i2d_CRL_DIST_POINTS)}
      i2d_CRL_DIST_POINTS := _i2d_CRL_DIST_POINTS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_CRL_DIST_POINTS_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_CRL_DIST_POINTS');
    {$ifend}
  end;
  
  CRL_DIST_POINTS_it := LoadLibFunction(ADllHandle, CRL_DIST_POINTS_it_procname);
  FuncLoadError := not assigned(CRL_DIST_POINTS_it);
  if FuncLoadError then
  begin
    {$if not defined(CRL_DIST_POINTS_it_allownil)}
    CRL_DIST_POINTS_it := ERR_CRL_DIST_POINTS_it;
    {$ifend}
    {$if declared(CRL_DIST_POINTS_it_introduced)}
    if LibVersion < CRL_DIST_POINTS_it_introduced then
    begin
      {$if declared(FC_CRL_DIST_POINTS_it)}
      CRL_DIST_POINTS_it := FC_CRL_DIST_POINTS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRL_DIST_POINTS_it_removed)}
    if CRL_DIST_POINTS_it_removed <= LibVersion then
    begin
      {$if declared(_CRL_DIST_POINTS_it)}
      CRL_DIST_POINTS_it := _CRL_DIST_POINTS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRL_DIST_POINTS_it_allownil)}
    if FuncLoadError then
      AFailed.Add('CRL_DIST_POINTS_it');
    {$ifend}
  end;
  
  DIST_POINT_new := LoadLibFunction(ADllHandle, DIST_POINT_new_procname);
  FuncLoadError := not assigned(DIST_POINT_new);
  if FuncLoadError then
  begin
    {$if not defined(DIST_POINT_new_allownil)}
    DIST_POINT_new := ERR_DIST_POINT_new;
    {$ifend}
    {$if declared(DIST_POINT_new_introduced)}
    if LibVersion < DIST_POINT_new_introduced then
    begin
      {$if declared(FC_DIST_POINT_new)}
      DIST_POINT_new := FC_DIST_POINT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DIST_POINT_new_removed)}
    if DIST_POINT_new_removed <= LibVersion then
    begin
      {$if declared(_DIST_POINT_new)}
      DIST_POINT_new := _DIST_POINT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DIST_POINT_new_allownil)}
    if FuncLoadError then
      AFailed.Add('DIST_POINT_new');
    {$ifend}
  end;
  
  DIST_POINT_free := LoadLibFunction(ADllHandle, DIST_POINT_free_procname);
  FuncLoadError := not assigned(DIST_POINT_free);
  if FuncLoadError then
  begin
    {$if not defined(DIST_POINT_free_allownil)}
    DIST_POINT_free := ERR_DIST_POINT_free;
    {$ifend}
    {$if declared(DIST_POINT_free_introduced)}
    if LibVersion < DIST_POINT_free_introduced then
    begin
      {$if declared(FC_DIST_POINT_free)}
      DIST_POINT_free := FC_DIST_POINT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DIST_POINT_free_removed)}
    if DIST_POINT_free_removed <= LibVersion then
    begin
      {$if declared(_DIST_POINT_free)}
      DIST_POINT_free := _DIST_POINT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DIST_POINT_free_allownil)}
    if FuncLoadError then
      AFailed.Add('DIST_POINT_free');
    {$ifend}
  end;
  
  d2i_DIST_POINT := LoadLibFunction(ADllHandle, d2i_DIST_POINT_procname);
  FuncLoadError := not assigned(d2i_DIST_POINT);
  if FuncLoadError then
  begin
    {$if not defined(d2i_DIST_POINT_allownil)}
    d2i_DIST_POINT := ERR_d2i_DIST_POINT;
    {$ifend}
    {$if declared(d2i_DIST_POINT_introduced)}
    if LibVersion < d2i_DIST_POINT_introduced then
    begin
      {$if declared(FC_d2i_DIST_POINT)}
      d2i_DIST_POINT := FC_d2i_DIST_POINT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_DIST_POINT_removed)}
    if d2i_DIST_POINT_removed <= LibVersion then
    begin
      {$if declared(_d2i_DIST_POINT)}
      d2i_DIST_POINT := _d2i_DIST_POINT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_DIST_POINT_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_DIST_POINT');
    {$ifend}
  end;
  
  i2d_DIST_POINT := LoadLibFunction(ADllHandle, i2d_DIST_POINT_procname);
  FuncLoadError := not assigned(i2d_DIST_POINT);
  if FuncLoadError then
  begin
    {$if not defined(i2d_DIST_POINT_allownil)}
    i2d_DIST_POINT := ERR_i2d_DIST_POINT;
    {$ifend}
    {$if declared(i2d_DIST_POINT_introduced)}
    if LibVersion < i2d_DIST_POINT_introduced then
    begin
      {$if declared(FC_i2d_DIST_POINT)}
      i2d_DIST_POINT := FC_i2d_DIST_POINT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_DIST_POINT_removed)}
    if i2d_DIST_POINT_removed <= LibVersion then
    begin
      {$if declared(_i2d_DIST_POINT)}
      i2d_DIST_POINT := _i2d_DIST_POINT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_DIST_POINT_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_DIST_POINT');
    {$ifend}
  end;
  
  DIST_POINT_it := LoadLibFunction(ADllHandle, DIST_POINT_it_procname);
  FuncLoadError := not assigned(DIST_POINT_it);
  if FuncLoadError then
  begin
    {$if not defined(DIST_POINT_it_allownil)}
    DIST_POINT_it := ERR_DIST_POINT_it;
    {$ifend}
    {$if declared(DIST_POINT_it_introduced)}
    if LibVersion < DIST_POINT_it_introduced then
    begin
      {$if declared(FC_DIST_POINT_it)}
      DIST_POINT_it := FC_DIST_POINT_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DIST_POINT_it_removed)}
    if DIST_POINT_it_removed <= LibVersion then
    begin
      {$if declared(_DIST_POINT_it)}
      DIST_POINT_it := _DIST_POINT_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DIST_POINT_it_allownil)}
    if FuncLoadError then
      AFailed.Add('DIST_POINT_it');
    {$ifend}
  end;
  
  DIST_POINT_NAME_new := LoadLibFunction(ADllHandle, DIST_POINT_NAME_new_procname);
  FuncLoadError := not assigned(DIST_POINT_NAME_new);
  if FuncLoadError then
  begin
    {$if not defined(DIST_POINT_NAME_new_allownil)}
    DIST_POINT_NAME_new := ERR_DIST_POINT_NAME_new;
    {$ifend}
    {$if declared(DIST_POINT_NAME_new_introduced)}
    if LibVersion < DIST_POINT_NAME_new_introduced then
    begin
      {$if declared(FC_DIST_POINT_NAME_new)}
      DIST_POINT_NAME_new := FC_DIST_POINT_NAME_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DIST_POINT_NAME_new_removed)}
    if DIST_POINT_NAME_new_removed <= LibVersion then
    begin
      {$if declared(_DIST_POINT_NAME_new)}
      DIST_POINT_NAME_new := _DIST_POINT_NAME_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DIST_POINT_NAME_new_allownil)}
    if FuncLoadError then
      AFailed.Add('DIST_POINT_NAME_new');
    {$ifend}
  end;
  
  DIST_POINT_NAME_free := LoadLibFunction(ADllHandle, DIST_POINT_NAME_free_procname);
  FuncLoadError := not assigned(DIST_POINT_NAME_free);
  if FuncLoadError then
  begin
    {$if not defined(DIST_POINT_NAME_free_allownil)}
    DIST_POINT_NAME_free := ERR_DIST_POINT_NAME_free;
    {$ifend}
    {$if declared(DIST_POINT_NAME_free_introduced)}
    if LibVersion < DIST_POINT_NAME_free_introduced then
    begin
      {$if declared(FC_DIST_POINT_NAME_free)}
      DIST_POINT_NAME_free := FC_DIST_POINT_NAME_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DIST_POINT_NAME_free_removed)}
    if DIST_POINT_NAME_free_removed <= LibVersion then
    begin
      {$if declared(_DIST_POINT_NAME_free)}
      DIST_POINT_NAME_free := _DIST_POINT_NAME_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DIST_POINT_NAME_free_allownil)}
    if FuncLoadError then
      AFailed.Add('DIST_POINT_NAME_free');
    {$ifend}
  end;
  
  d2i_DIST_POINT_NAME := LoadLibFunction(ADllHandle, d2i_DIST_POINT_NAME_procname);
  FuncLoadError := not assigned(d2i_DIST_POINT_NAME);
  if FuncLoadError then
  begin
    {$if not defined(d2i_DIST_POINT_NAME_allownil)}
    d2i_DIST_POINT_NAME := ERR_d2i_DIST_POINT_NAME;
    {$ifend}
    {$if declared(d2i_DIST_POINT_NAME_introduced)}
    if LibVersion < d2i_DIST_POINT_NAME_introduced then
    begin
      {$if declared(FC_d2i_DIST_POINT_NAME)}
      d2i_DIST_POINT_NAME := FC_d2i_DIST_POINT_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_DIST_POINT_NAME_removed)}
    if d2i_DIST_POINT_NAME_removed <= LibVersion then
    begin
      {$if declared(_d2i_DIST_POINT_NAME)}
      d2i_DIST_POINT_NAME := _d2i_DIST_POINT_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_DIST_POINT_NAME_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_DIST_POINT_NAME');
    {$ifend}
  end;
  
  i2d_DIST_POINT_NAME := LoadLibFunction(ADllHandle, i2d_DIST_POINT_NAME_procname);
  FuncLoadError := not assigned(i2d_DIST_POINT_NAME);
  if FuncLoadError then
  begin
    {$if not defined(i2d_DIST_POINT_NAME_allownil)}
    i2d_DIST_POINT_NAME := ERR_i2d_DIST_POINT_NAME;
    {$ifend}
    {$if declared(i2d_DIST_POINT_NAME_introduced)}
    if LibVersion < i2d_DIST_POINT_NAME_introduced then
    begin
      {$if declared(FC_i2d_DIST_POINT_NAME)}
      i2d_DIST_POINT_NAME := FC_i2d_DIST_POINT_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_DIST_POINT_NAME_removed)}
    if i2d_DIST_POINT_NAME_removed <= LibVersion then
    begin
      {$if declared(_i2d_DIST_POINT_NAME)}
      i2d_DIST_POINT_NAME := _i2d_DIST_POINT_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_DIST_POINT_NAME_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_DIST_POINT_NAME');
    {$ifend}
  end;
  
  DIST_POINT_NAME_it := LoadLibFunction(ADllHandle, DIST_POINT_NAME_it_procname);
  FuncLoadError := not assigned(DIST_POINT_NAME_it);
  if FuncLoadError then
  begin
    {$if not defined(DIST_POINT_NAME_it_allownil)}
    DIST_POINT_NAME_it := ERR_DIST_POINT_NAME_it;
    {$ifend}
    {$if declared(DIST_POINT_NAME_it_introduced)}
    if LibVersion < DIST_POINT_NAME_it_introduced then
    begin
      {$if declared(FC_DIST_POINT_NAME_it)}
      DIST_POINT_NAME_it := FC_DIST_POINT_NAME_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DIST_POINT_NAME_it_removed)}
    if DIST_POINT_NAME_it_removed <= LibVersion then
    begin
      {$if declared(_DIST_POINT_NAME_it)}
      DIST_POINT_NAME_it := _DIST_POINT_NAME_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DIST_POINT_NAME_it_allownil)}
    if FuncLoadError then
      AFailed.Add('DIST_POINT_NAME_it');
    {$ifend}
  end;
  
  ISSUING_DIST_POINT_new := LoadLibFunction(ADllHandle, ISSUING_DIST_POINT_new_procname);
  FuncLoadError := not assigned(ISSUING_DIST_POINT_new);
  if FuncLoadError then
  begin
    {$if not defined(ISSUING_DIST_POINT_new_allownil)}
    ISSUING_DIST_POINT_new := ERR_ISSUING_DIST_POINT_new;
    {$ifend}
    {$if declared(ISSUING_DIST_POINT_new_introduced)}
    if LibVersion < ISSUING_DIST_POINT_new_introduced then
    begin
      {$if declared(FC_ISSUING_DIST_POINT_new)}
      ISSUING_DIST_POINT_new := FC_ISSUING_DIST_POINT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ISSUING_DIST_POINT_new_removed)}
    if ISSUING_DIST_POINT_new_removed <= LibVersion then
    begin
      {$if declared(_ISSUING_DIST_POINT_new)}
      ISSUING_DIST_POINT_new := _ISSUING_DIST_POINT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ISSUING_DIST_POINT_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ISSUING_DIST_POINT_new');
    {$ifend}
  end;
  
  ISSUING_DIST_POINT_free := LoadLibFunction(ADllHandle, ISSUING_DIST_POINT_free_procname);
  FuncLoadError := not assigned(ISSUING_DIST_POINT_free);
  if FuncLoadError then
  begin
    {$if not defined(ISSUING_DIST_POINT_free_allownil)}
    ISSUING_DIST_POINT_free := ERR_ISSUING_DIST_POINT_free;
    {$ifend}
    {$if declared(ISSUING_DIST_POINT_free_introduced)}
    if LibVersion < ISSUING_DIST_POINT_free_introduced then
    begin
      {$if declared(FC_ISSUING_DIST_POINT_free)}
      ISSUING_DIST_POINT_free := FC_ISSUING_DIST_POINT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ISSUING_DIST_POINT_free_removed)}
    if ISSUING_DIST_POINT_free_removed <= LibVersion then
    begin
      {$if declared(_ISSUING_DIST_POINT_free)}
      ISSUING_DIST_POINT_free := _ISSUING_DIST_POINT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ISSUING_DIST_POINT_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ISSUING_DIST_POINT_free');
    {$ifend}
  end;
  
  d2i_ISSUING_DIST_POINT := LoadLibFunction(ADllHandle, d2i_ISSUING_DIST_POINT_procname);
  FuncLoadError := not assigned(d2i_ISSUING_DIST_POINT);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ISSUING_DIST_POINT_allownil)}
    d2i_ISSUING_DIST_POINT := ERR_d2i_ISSUING_DIST_POINT;
    {$ifend}
    {$if declared(d2i_ISSUING_DIST_POINT_introduced)}
    if LibVersion < d2i_ISSUING_DIST_POINT_introduced then
    begin
      {$if declared(FC_d2i_ISSUING_DIST_POINT)}
      d2i_ISSUING_DIST_POINT := FC_d2i_ISSUING_DIST_POINT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ISSUING_DIST_POINT_removed)}
    if d2i_ISSUING_DIST_POINT_removed <= LibVersion then
    begin
      {$if declared(_d2i_ISSUING_DIST_POINT)}
      d2i_ISSUING_DIST_POINT := _d2i_ISSUING_DIST_POINT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ISSUING_DIST_POINT_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ISSUING_DIST_POINT');
    {$ifend}
  end;
  
  i2d_ISSUING_DIST_POINT := LoadLibFunction(ADllHandle, i2d_ISSUING_DIST_POINT_procname);
  FuncLoadError := not assigned(i2d_ISSUING_DIST_POINT);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ISSUING_DIST_POINT_allownil)}
    i2d_ISSUING_DIST_POINT := ERR_i2d_ISSUING_DIST_POINT;
    {$ifend}
    {$if declared(i2d_ISSUING_DIST_POINT_introduced)}
    if LibVersion < i2d_ISSUING_DIST_POINT_introduced then
    begin
      {$if declared(FC_i2d_ISSUING_DIST_POINT)}
      i2d_ISSUING_DIST_POINT := FC_i2d_ISSUING_DIST_POINT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ISSUING_DIST_POINT_removed)}
    if i2d_ISSUING_DIST_POINT_removed <= LibVersion then
    begin
      {$if declared(_i2d_ISSUING_DIST_POINT)}
      i2d_ISSUING_DIST_POINT := _i2d_ISSUING_DIST_POINT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ISSUING_DIST_POINT_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ISSUING_DIST_POINT');
    {$ifend}
  end;
  
  ISSUING_DIST_POINT_it := LoadLibFunction(ADllHandle, ISSUING_DIST_POINT_it_procname);
  FuncLoadError := not assigned(ISSUING_DIST_POINT_it);
  if FuncLoadError then
  begin
    {$if not defined(ISSUING_DIST_POINT_it_allownil)}
    ISSUING_DIST_POINT_it := ERR_ISSUING_DIST_POINT_it;
    {$ifend}
    {$if declared(ISSUING_DIST_POINT_it_introduced)}
    if LibVersion < ISSUING_DIST_POINT_it_introduced then
    begin
      {$if declared(FC_ISSUING_DIST_POINT_it)}
      ISSUING_DIST_POINT_it := FC_ISSUING_DIST_POINT_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ISSUING_DIST_POINT_it_removed)}
    if ISSUING_DIST_POINT_it_removed <= LibVersion then
    begin
      {$if declared(_ISSUING_DIST_POINT_it)}
      ISSUING_DIST_POINT_it := _ISSUING_DIST_POINT_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ISSUING_DIST_POINT_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ISSUING_DIST_POINT_it');
    {$ifend}
  end;
  
  DIST_POINT_set_dpname := LoadLibFunction(ADllHandle, DIST_POINT_set_dpname_procname);
  FuncLoadError := not assigned(DIST_POINT_set_dpname);
  if FuncLoadError then
  begin
    {$if not defined(DIST_POINT_set_dpname_allownil)}
    DIST_POINT_set_dpname := ERR_DIST_POINT_set_dpname;
    {$ifend}
    {$if declared(DIST_POINT_set_dpname_introduced)}
    if LibVersion < DIST_POINT_set_dpname_introduced then
    begin
      {$if declared(FC_DIST_POINT_set_dpname)}
      DIST_POINT_set_dpname := FC_DIST_POINT_set_dpname;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DIST_POINT_set_dpname_removed)}
    if DIST_POINT_set_dpname_removed <= LibVersion then
    begin
      {$if declared(_DIST_POINT_set_dpname)}
      DIST_POINT_set_dpname := _DIST_POINT_set_dpname;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DIST_POINT_set_dpname_allownil)}
    if FuncLoadError then
      AFailed.Add('DIST_POINT_set_dpname');
    {$ifend}
  end;
  
  NAME_CONSTRAINTS_check := LoadLibFunction(ADllHandle, NAME_CONSTRAINTS_check_procname);
  FuncLoadError := not assigned(NAME_CONSTRAINTS_check);
  if FuncLoadError then
  begin
    {$if not defined(NAME_CONSTRAINTS_check_allownil)}
    NAME_CONSTRAINTS_check := ERR_NAME_CONSTRAINTS_check;
    {$ifend}
    {$if declared(NAME_CONSTRAINTS_check_introduced)}
    if LibVersion < NAME_CONSTRAINTS_check_introduced then
    begin
      {$if declared(FC_NAME_CONSTRAINTS_check)}
      NAME_CONSTRAINTS_check := FC_NAME_CONSTRAINTS_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAME_CONSTRAINTS_check_removed)}
    if NAME_CONSTRAINTS_check_removed <= LibVersion then
    begin
      {$if declared(_NAME_CONSTRAINTS_check)}
      NAME_CONSTRAINTS_check := _NAME_CONSTRAINTS_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAME_CONSTRAINTS_check_allownil)}
    if FuncLoadError then
      AFailed.Add('NAME_CONSTRAINTS_check');
    {$ifend}
  end;
  
  NAME_CONSTRAINTS_check_CN := LoadLibFunction(ADllHandle, NAME_CONSTRAINTS_check_CN_procname);
  FuncLoadError := not assigned(NAME_CONSTRAINTS_check_CN);
  if FuncLoadError then
  begin
    {$if not defined(NAME_CONSTRAINTS_check_CN_allownil)}
    NAME_CONSTRAINTS_check_CN := ERR_NAME_CONSTRAINTS_check_CN;
    {$ifend}
    {$if declared(NAME_CONSTRAINTS_check_CN_introduced)}
    if LibVersion < NAME_CONSTRAINTS_check_CN_introduced then
    begin
      {$if declared(FC_NAME_CONSTRAINTS_check_CN)}
      NAME_CONSTRAINTS_check_CN := FC_NAME_CONSTRAINTS_check_CN;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAME_CONSTRAINTS_check_CN_removed)}
    if NAME_CONSTRAINTS_check_CN_removed <= LibVersion then
    begin
      {$if declared(_NAME_CONSTRAINTS_check_CN)}
      NAME_CONSTRAINTS_check_CN := _NAME_CONSTRAINTS_check_CN;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAME_CONSTRAINTS_check_CN_allownil)}
    if FuncLoadError then
      AFailed.Add('NAME_CONSTRAINTS_check_CN');
    {$ifend}
  end;
  
  ACCESS_DESCRIPTION_new := LoadLibFunction(ADllHandle, ACCESS_DESCRIPTION_new_procname);
  FuncLoadError := not assigned(ACCESS_DESCRIPTION_new);
  if FuncLoadError then
  begin
    {$if not defined(ACCESS_DESCRIPTION_new_allownil)}
    ACCESS_DESCRIPTION_new := ERR_ACCESS_DESCRIPTION_new;
    {$ifend}
    {$if declared(ACCESS_DESCRIPTION_new_introduced)}
    if LibVersion < ACCESS_DESCRIPTION_new_introduced then
    begin
      {$if declared(FC_ACCESS_DESCRIPTION_new)}
      ACCESS_DESCRIPTION_new := FC_ACCESS_DESCRIPTION_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ACCESS_DESCRIPTION_new_removed)}
    if ACCESS_DESCRIPTION_new_removed <= LibVersion then
    begin
      {$if declared(_ACCESS_DESCRIPTION_new)}
      ACCESS_DESCRIPTION_new := _ACCESS_DESCRIPTION_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ACCESS_DESCRIPTION_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ACCESS_DESCRIPTION_new');
    {$ifend}
  end;
  
  ACCESS_DESCRIPTION_free := LoadLibFunction(ADllHandle, ACCESS_DESCRIPTION_free_procname);
  FuncLoadError := not assigned(ACCESS_DESCRIPTION_free);
  if FuncLoadError then
  begin
    {$if not defined(ACCESS_DESCRIPTION_free_allownil)}
    ACCESS_DESCRIPTION_free := ERR_ACCESS_DESCRIPTION_free;
    {$ifend}
    {$if declared(ACCESS_DESCRIPTION_free_introduced)}
    if LibVersion < ACCESS_DESCRIPTION_free_introduced then
    begin
      {$if declared(FC_ACCESS_DESCRIPTION_free)}
      ACCESS_DESCRIPTION_free := FC_ACCESS_DESCRIPTION_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ACCESS_DESCRIPTION_free_removed)}
    if ACCESS_DESCRIPTION_free_removed <= LibVersion then
    begin
      {$if declared(_ACCESS_DESCRIPTION_free)}
      ACCESS_DESCRIPTION_free := _ACCESS_DESCRIPTION_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ACCESS_DESCRIPTION_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ACCESS_DESCRIPTION_free');
    {$ifend}
  end;
  
  d2i_ACCESS_DESCRIPTION := LoadLibFunction(ADllHandle, d2i_ACCESS_DESCRIPTION_procname);
  FuncLoadError := not assigned(d2i_ACCESS_DESCRIPTION);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ACCESS_DESCRIPTION_allownil)}
    d2i_ACCESS_DESCRIPTION := ERR_d2i_ACCESS_DESCRIPTION;
    {$ifend}
    {$if declared(d2i_ACCESS_DESCRIPTION_introduced)}
    if LibVersion < d2i_ACCESS_DESCRIPTION_introduced then
    begin
      {$if declared(FC_d2i_ACCESS_DESCRIPTION)}
      d2i_ACCESS_DESCRIPTION := FC_d2i_ACCESS_DESCRIPTION;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ACCESS_DESCRIPTION_removed)}
    if d2i_ACCESS_DESCRIPTION_removed <= LibVersion then
    begin
      {$if declared(_d2i_ACCESS_DESCRIPTION)}
      d2i_ACCESS_DESCRIPTION := _d2i_ACCESS_DESCRIPTION;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ACCESS_DESCRIPTION_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ACCESS_DESCRIPTION');
    {$ifend}
  end;
  
  i2d_ACCESS_DESCRIPTION := LoadLibFunction(ADllHandle, i2d_ACCESS_DESCRIPTION_procname);
  FuncLoadError := not assigned(i2d_ACCESS_DESCRIPTION);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ACCESS_DESCRIPTION_allownil)}
    i2d_ACCESS_DESCRIPTION := ERR_i2d_ACCESS_DESCRIPTION;
    {$ifend}
    {$if declared(i2d_ACCESS_DESCRIPTION_introduced)}
    if LibVersion < i2d_ACCESS_DESCRIPTION_introduced then
    begin
      {$if declared(FC_i2d_ACCESS_DESCRIPTION)}
      i2d_ACCESS_DESCRIPTION := FC_i2d_ACCESS_DESCRIPTION;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ACCESS_DESCRIPTION_removed)}
    if i2d_ACCESS_DESCRIPTION_removed <= LibVersion then
    begin
      {$if declared(_i2d_ACCESS_DESCRIPTION)}
      i2d_ACCESS_DESCRIPTION := _i2d_ACCESS_DESCRIPTION;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ACCESS_DESCRIPTION_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ACCESS_DESCRIPTION');
    {$ifend}
  end;
  
  ACCESS_DESCRIPTION_it := LoadLibFunction(ADllHandle, ACCESS_DESCRIPTION_it_procname);
  FuncLoadError := not assigned(ACCESS_DESCRIPTION_it);
  if FuncLoadError then
  begin
    {$if not defined(ACCESS_DESCRIPTION_it_allownil)}
    ACCESS_DESCRIPTION_it := ERR_ACCESS_DESCRIPTION_it;
    {$ifend}
    {$if declared(ACCESS_DESCRIPTION_it_introduced)}
    if LibVersion < ACCESS_DESCRIPTION_it_introduced then
    begin
      {$if declared(FC_ACCESS_DESCRIPTION_it)}
      ACCESS_DESCRIPTION_it := FC_ACCESS_DESCRIPTION_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ACCESS_DESCRIPTION_it_removed)}
    if ACCESS_DESCRIPTION_it_removed <= LibVersion then
    begin
      {$if declared(_ACCESS_DESCRIPTION_it)}
      ACCESS_DESCRIPTION_it := _ACCESS_DESCRIPTION_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ACCESS_DESCRIPTION_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ACCESS_DESCRIPTION_it');
    {$ifend}
  end;
  
  AUTHORITY_INFO_ACCESS_new := LoadLibFunction(ADllHandle, AUTHORITY_INFO_ACCESS_new_procname);
  FuncLoadError := not assigned(AUTHORITY_INFO_ACCESS_new);
  if FuncLoadError then
  begin
    {$if not defined(AUTHORITY_INFO_ACCESS_new_allownil)}
    AUTHORITY_INFO_ACCESS_new := ERR_AUTHORITY_INFO_ACCESS_new;
    {$ifend}
    {$if declared(AUTHORITY_INFO_ACCESS_new_introduced)}
    if LibVersion < AUTHORITY_INFO_ACCESS_new_introduced then
    begin
      {$if declared(FC_AUTHORITY_INFO_ACCESS_new)}
      AUTHORITY_INFO_ACCESS_new := FC_AUTHORITY_INFO_ACCESS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AUTHORITY_INFO_ACCESS_new_removed)}
    if AUTHORITY_INFO_ACCESS_new_removed <= LibVersion then
    begin
      {$if declared(_AUTHORITY_INFO_ACCESS_new)}
      AUTHORITY_INFO_ACCESS_new := _AUTHORITY_INFO_ACCESS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AUTHORITY_INFO_ACCESS_new_allownil)}
    if FuncLoadError then
      AFailed.Add('AUTHORITY_INFO_ACCESS_new');
    {$ifend}
  end;
  
  AUTHORITY_INFO_ACCESS_free := LoadLibFunction(ADllHandle, AUTHORITY_INFO_ACCESS_free_procname);
  FuncLoadError := not assigned(AUTHORITY_INFO_ACCESS_free);
  if FuncLoadError then
  begin
    {$if not defined(AUTHORITY_INFO_ACCESS_free_allownil)}
    AUTHORITY_INFO_ACCESS_free := ERR_AUTHORITY_INFO_ACCESS_free;
    {$ifend}
    {$if declared(AUTHORITY_INFO_ACCESS_free_introduced)}
    if LibVersion < AUTHORITY_INFO_ACCESS_free_introduced then
    begin
      {$if declared(FC_AUTHORITY_INFO_ACCESS_free)}
      AUTHORITY_INFO_ACCESS_free := FC_AUTHORITY_INFO_ACCESS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AUTHORITY_INFO_ACCESS_free_removed)}
    if AUTHORITY_INFO_ACCESS_free_removed <= LibVersion then
    begin
      {$if declared(_AUTHORITY_INFO_ACCESS_free)}
      AUTHORITY_INFO_ACCESS_free := _AUTHORITY_INFO_ACCESS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AUTHORITY_INFO_ACCESS_free_allownil)}
    if FuncLoadError then
      AFailed.Add('AUTHORITY_INFO_ACCESS_free');
    {$ifend}
  end;
  
  d2i_AUTHORITY_INFO_ACCESS := LoadLibFunction(ADllHandle, d2i_AUTHORITY_INFO_ACCESS_procname);
  FuncLoadError := not assigned(d2i_AUTHORITY_INFO_ACCESS);
  if FuncLoadError then
  begin
    {$if not defined(d2i_AUTHORITY_INFO_ACCESS_allownil)}
    d2i_AUTHORITY_INFO_ACCESS := ERR_d2i_AUTHORITY_INFO_ACCESS;
    {$ifend}
    {$if declared(d2i_AUTHORITY_INFO_ACCESS_introduced)}
    if LibVersion < d2i_AUTHORITY_INFO_ACCESS_introduced then
    begin
      {$if declared(FC_d2i_AUTHORITY_INFO_ACCESS)}
      d2i_AUTHORITY_INFO_ACCESS := FC_d2i_AUTHORITY_INFO_ACCESS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_AUTHORITY_INFO_ACCESS_removed)}
    if d2i_AUTHORITY_INFO_ACCESS_removed <= LibVersion then
    begin
      {$if declared(_d2i_AUTHORITY_INFO_ACCESS)}
      d2i_AUTHORITY_INFO_ACCESS := _d2i_AUTHORITY_INFO_ACCESS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_AUTHORITY_INFO_ACCESS_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_AUTHORITY_INFO_ACCESS');
    {$ifend}
  end;
  
  i2d_AUTHORITY_INFO_ACCESS := LoadLibFunction(ADllHandle, i2d_AUTHORITY_INFO_ACCESS_procname);
  FuncLoadError := not assigned(i2d_AUTHORITY_INFO_ACCESS);
  if FuncLoadError then
  begin
    {$if not defined(i2d_AUTHORITY_INFO_ACCESS_allownil)}
    i2d_AUTHORITY_INFO_ACCESS := ERR_i2d_AUTHORITY_INFO_ACCESS;
    {$ifend}
    {$if declared(i2d_AUTHORITY_INFO_ACCESS_introduced)}
    if LibVersion < i2d_AUTHORITY_INFO_ACCESS_introduced then
    begin
      {$if declared(FC_i2d_AUTHORITY_INFO_ACCESS)}
      i2d_AUTHORITY_INFO_ACCESS := FC_i2d_AUTHORITY_INFO_ACCESS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_AUTHORITY_INFO_ACCESS_removed)}
    if i2d_AUTHORITY_INFO_ACCESS_removed <= LibVersion then
    begin
      {$if declared(_i2d_AUTHORITY_INFO_ACCESS)}
      i2d_AUTHORITY_INFO_ACCESS := _i2d_AUTHORITY_INFO_ACCESS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_AUTHORITY_INFO_ACCESS_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_AUTHORITY_INFO_ACCESS');
    {$ifend}
  end;
  
  AUTHORITY_INFO_ACCESS_it := LoadLibFunction(ADllHandle, AUTHORITY_INFO_ACCESS_it_procname);
  FuncLoadError := not assigned(AUTHORITY_INFO_ACCESS_it);
  if FuncLoadError then
  begin
    {$if not defined(AUTHORITY_INFO_ACCESS_it_allownil)}
    AUTHORITY_INFO_ACCESS_it := ERR_AUTHORITY_INFO_ACCESS_it;
    {$ifend}
    {$if declared(AUTHORITY_INFO_ACCESS_it_introduced)}
    if LibVersion < AUTHORITY_INFO_ACCESS_it_introduced then
    begin
      {$if declared(FC_AUTHORITY_INFO_ACCESS_it)}
      AUTHORITY_INFO_ACCESS_it := FC_AUTHORITY_INFO_ACCESS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AUTHORITY_INFO_ACCESS_it_removed)}
    if AUTHORITY_INFO_ACCESS_it_removed <= LibVersion then
    begin
      {$if declared(_AUTHORITY_INFO_ACCESS_it)}
      AUTHORITY_INFO_ACCESS_it := _AUTHORITY_INFO_ACCESS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AUTHORITY_INFO_ACCESS_it_allownil)}
    if FuncLoadError then
      AFailed.Add('AUTHORITY_INFO_ACCESS_it');
    {$ifend}
  end;
  
  POLICY_MAPPING_it := LoadLibFunction(ADllHandle, POLICY_MAPPING_it_procname);
  FuncLoadError := not assigned(POLICY_MAPPING_it);
  if FuncLoadError then
  begin
    {$if not defined(POLICY_MAPPING_it_allownil)}
    POLICY_MAPPING_it := ERR_POLICY_MAPPING_it;
    {$ifend}
    {$if declared(POLICY_MAPPING_it_introduced)}
    if LibVersion < POLICY_MAPPING_it_introduced then
    begin
      {$if declared(FC_POLICY_MAPPING_it)}
      POLICY_MAPPING_it := FC_POLICY_MAPPING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(POLICY_MAPPING_it_removed)}
    if POLICY_MAPPING_it_removed <= LibVersion then
    begin
      {$if declared(_POLICY_MAPPING_it)}
      POLICY_MAPPING_it := _POLICY_MAPPING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(POLICY_MAPPING_it_allownil)}
    if FuncLoadError then
      AFailed.Add('POLICY_MAPPING_it');
    {$ifend}
  end;
  
  POLICY_MAPPING_new := LoadLibFunction(ADllHandle, POLICY_MAPPING_new_procname);
  FuncLoadError := not assigned(POLICY_MAPPING_new);
  if FuncLoadError then
  begin
    {$if not defined(POLICY_MAPPING_new_allownil)}
    POLICY_MAPPING_new := ERR_POLICY_MAPPING_new;
    {$ifend}
    {$if declared(POLICY_MAPPING_new_introduced)}
    if LibVersion < POLICY_MAPPING_new_introduced then
    begin
      {$if declared(FC_POLICY_MAPPING_new)}
      POLICY_MAPPING_new := FC_POLICY_MAPPING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(POLICY_MAPPING_new_removed)}
    if POLICY_MAPPING_new_removed <= LibVersion then
    begin
      {$if declared(_POLICY_MAPPING_new)}
      POLICY_MAPPING_new := _POLICY_MAPPING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(POLICY_MAPPING_new_allownil)}
    if FuncLoadError then
      AFailed.Add('POLICY_MAPPING_new');
    {$ifend}
  end;
  
  POLICY_MAPPING_free := LoadLibFunction(ADllHandle, POLICY_MAPPING_free_procname);
  FuncLoadError := not assigned(POLICY_MAPPING_free);
  if FuncLoadError then
  begin
    {$if not defined(POLICY_MAPPING_free_allownil)}
    POLICY_MAPPING_free := ERR_POLICY_MAPPING_free;
    {$ifend}
    {$if declared(POLICY_MAPPING_free_introduced)}
    if LibVersion < POLICY_MAPPING_free_introduced then
    begin
      {$if declared(FC_POLICY_MAPPING_free)}
      POLICY_MAPPING_free := FC_POLICY_MAPPING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(POLICY_MAPPING_free_removed)}
    if POLICY_MAPPING_free_removed <= LibVersion then
    begin
      {$if declared(_POLICY_MAPPING_free)}
      POLICY_MAPPING_free := _POLICY_MAPPING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(POLICY_MAPPING_free_allownil)}
    if FuncLoadError then
      AFailed.Add('POLICY_MAPPING_free');
    {$ifend}
  end;
  
  POLICY_MAPPINGS_it := LoadLibFunction(ADllHandle, POLICY_MAPPINGS_it_procname);
  FuncLoadError := not assigned(POLICY_MAPPINGS_it);
  if FuncLoadError then
  begin
    {$if not defined(POLICY_MAPPINGS_it_allownil)}
    POLICY_MAPPINGS_it := ERR_POLICY_MAPPINGS_it;
    {$ifend}
    {$if declared(POLICY_MAPPINGS_it_introduced)}
    if LibVersion < POLICY_MAPPINGS_it_introduced then
    begin
      {$if declared(FC_POLICY_MAPPINGS_it)}
      POLICY_MAPPINGS_it := FC_POLICY_MAPPINGS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(POLICY_MAPPINGS_it_removed)}
    if POLICY_MAPPINGS_it_removed <= LibVersion then
    begin
      {$if declared(_POLICY_MAPPINGS_it)}
      POLICY_MAPPINGS_it := _POLICY_MAPPINGS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(POLICY_MAPPINGS_it_allownil)}
    if FuncLoadError then
      AFailed.Add('POLICY_MAPPINGS_it');
    {$ifend}
  end;
  
  GENERAL_SUBTREE_it := LoadLibFunction(ADllHandle, GENERAL_SUBTREE_it_procname);
  FuncLoadError := not assigned(GENERAL_SUBTREE_it);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_SUBTREE_it_allownil)}
    GENERAL_SUBTREE_it := ERR_GENERAL_SUBTREE_it;
    {$ifend}
    {$if declared(GENERAL_SUBTREE_it_introduced)}
    if LibVersion < GENERAL_SUBTREE_it_introduced then
    begin
      {$if declared(FC_GENERAL_SUBTREE_it)}
      GENERAL_SUBTREE_it := FC_GENERAL_SUBTREE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_SUBTREE_it_removed)}
    if GENERAL_SUBTREE_it_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_SUBTREE_it)}
      GENERAL_SUBTREE_it := _GENERAL_SUBTREE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_SUBTREE_it_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_SUBTREE_it');
    {$ifend}
  end;
  
  GENERAL_SUBTREE_new := LoadLibFunction(ADllHandle, GENERAL_SUBTREE_new_procname);
  FuncLoadError := not assigned(GENERAL_SUBTREE_new);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_SUBTREE_new_allownil)}
    GENERAL_SUBTREE_new := ERR_GENERAL_SUBTREE_new;
    {$ifend}
    {$if declared(GENERAL_SUBTREE_new_introduced)}
    if LibVersion < GENERAL_SUBTREE_new_introduced then
    begin
      {$if declared(FC_GENERAL_SUBTREE_new)}
      GENERAL_SUBTREE_new := FC_GENERAL_SUBTREE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_SUBTREE_new_removed)}
    if GENERAL_SUBTREE_new_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_SUBTREE_new)}
      GENERAL_SUBTREE_new := _GENERAL_SUBTREE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_SUBTREE_new_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_SUBTREE_new');
    {$ifend}
  end;
  
  GENERAL_SUBTREE_free := LoadLibFunction(ADllHandle, GENERAL_SUBTREE_free_procname);
  FuncLoadError := not assigned(GENERAL_SUBTREE_free);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_SUBTREE_free_allownil)}
    GENERAL_SUBTREE_free := ERR_GENERAL_SUBTREE_free;
    {$ifend}
    {$if declared(GENERAL_SUBTREE_free_introduced)}
    if LibVersion < GENERAL_SUBTREE_free_introduced then
    begin
      {$if declared(FC_GENERAL_SUBTREE_free)}
      GENERAL_SUBTREE_free := FC_GENERAL_SUBTREE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_SUBTREE_free_removed)}
    if GENERAL_SUBTREE_free_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_SUBTREE_free)}
      GENERAL_SUBTREE_free := _GENERAL_SUBTREE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_SUBTREE_free_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_SUBTREE_free');
    {$ifend}
  end;
  
  NAME_CONSTRAINTS_it := LoadLibFunction(ADllHandle, NAME_CONSTRAINTS_it_procname);
  FuncLoadError := not assigned(NAME_CONSTRAINTS_it);
  if FuncLoadError then
  begin
    {$if not defined(NAME_CONSTRAINTS_it_allownil)}
    NAME_CONSTRAINTS_it := ERR_NAME_CONSTRAINTS_it;
    {$ifend}
    {$if declared(NAME_CONSTRAINTS_it_introduced)}
    if LibVersion < NAME_CONSTRAINTS_it_introduced then
    begin
      {$if declared(FC_NAME_CONSTRAINTS_it)}
      NAME_CONSTRAINTS_it := FC_NAME_CONSTRAINTS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAME_CONSTRAINTS_it_removed)}
    if NAME_CONSTRAINTS_it_removed <= LibVersion then
    begin
      {$if declared(_NAME_CONSTRAINTS_it)}
      NAME_CONSTRAINTS_it := _NAME_CONSTRAINTS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAME_CONSTRAINTS_it_allownil)}
    if FuncLoadError then
      AFailed.Add('NAME_CONSTRAINTS_it');
    {$ifend}
  end;
  
  NAME_CONSTRAINTS_new := LoadLibFunction(ADllHandle, NAME_CONSTRAINTS_new_procname);
  FuncLoadError := not assigned(NAME_CONSTRAINTS_new);
  if FuncLoadError then
  begin
    {$if not defined(NAME_CONSTRAINTS_new_allownil)}
    NAME_CONSTRAINTS_new := ERR_NAME_CONSTRAINTS_new;
    {$ifend}
    {$if declared(NAME_CONSTRAINTS_new_introduced)}
    if LibVersion < NAME_CONSTRAINTS_new_introduced then
    begin
      {$if declared(FC_NAME_CONSTRAINTS_new)}
      NAME_CONSTRAINTS_new := FC_NAME_CONSTRAINTS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAME_CONSTRAINTS_new_removed)}
    if NAME_CONSTRAINTS_new_removed <= LibVersion then
    begin
      {$if declared(_NAME_CONSTRAINTS_new)}
      NAME_CONSTRAINTS_new := _NAME_CONSTRAINTS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAME_CONSTRAINTS_new_allownil)}
    if FuncLoadError then
      AFailed.Add('NAME_CONSTRAINTS_new');
    {$ifend}
  end;
  
  NAME_CONSTRAINTS_free := LoadLibFunction(ADllHandle, NAME_CONSTRAINTS_free_procname);
  FuncLoadError := not assigned(NAME_CONSTRAINTS_free);
  if FuncLoadError then
  begin
    {$if not defined(NAME_CONSTRAINTS_free_allownil)}
    NAME_CONSTRAINTS_free := ERR_NAME_CONSTRAINTS_free;
    {$ifend}
    {$if declared(NAME_CONSTRAINTS_free_introduced)}
    if LibVersion < NAME_CONSTRAINTS_free_introduced then
    begin
      {$if declared(FC_NAME_CONSTRAINTS_free)}
      NAME_CONSTRAINTS_free := FC_NAME_CONSTRAINTS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAME_CONSTRAINTS_free_removed)}
    if NAME_CONSTRAINTS_free_removed <= LibVersion then
    begin
      {$if declared(_NAME_CONSTRAINTS_free)}
      NAME_CONSTRAINTS_free := _NAME_CONSTRAINTS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAME_CONSTRAINTS_free_allownil)}
    if FuncLoadError then
      AFailed.Add('NAME_CONSTRAINTS_free');
    {$ifend}
  end;
  
  POLICY_CONSTRAINTS_new := LoadLibFunction(ADllHandle, POLICY_CONSTRAINTS_new_procname);
  FuncLoadError := not assigned(POLICY_CONSTRAINTS_new);
  if FuncLoadError then
  begin
    {$if not defined(POLICY_CONSTRAINTS_new_allownil)}
    POLICY_CONSTRAINTS_new := ERR_POLICY_CONSTRAINTS_new;
    {$ifend}
    {$if declared(POLICY_CONSTRAINTS_new_introduced)}
    if LibVersion < POLICY_CONSTRAINTS_new_introduced then
    begin
      {$if declared(FC_POLICY_CONSTRAINTS_new)}
      POLICY_CONSTRAINTS_new := FC_POLICY_CONSTRAINTS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(POLICY_CONSTRAINTS_new_removed)}
    if POLICY_CONSTRAINTS_new_removed <= LibVersion then
    begin
      {$if declared(_POLICY_CONSTRAINTS_new)}
      POLICY_CONSTRAINTS_new := _POLICY_CONSTRAINTS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(POLICY_CONSTRAINTS_new_allownil)}
    if FuncLoadError then
      AFailed.Add('POLICY_CONSTRAINTS_new');
    {$ifend}
  end;
  
  POLICY_CONSTRAINTS_free := LoadLibFunction(ADllHandle, POLICY_CONSTRAINTS_free_procname);
  FuncLoadError := not assigned(POLICY_CONSTRAINTS_free);
  if FuncLoadError then
  begin
    {$if not defined(POLICY_CONSTRAINTS_free_allownil)}
    POLICY_CONSTRAINTS_free := ERR_POLICY_CONSTRAINTS_free;
    {$ifend}
    {$if declared(POLICY_CONSTRAINTS_free_introduced)}
    if LibVersion < POLICY_CONSTRAINTS_free_introduced then
    begin
      {$if declared(FC_POLICY_CONSTRAINTS_free)}
      POLICY_CONSTRAINTS_free := FC_POLICY_CONSTRAINTS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(POLICY_CONSTRAINTS_free_removed)}
    if POLICY_CONSTRAINTS_free_removed <= LibVersion then
    begin
      {$if declared(_POLICY_CONSTRAINTS_free)}
      POLICY_CONSTRAINTS_free := _POLICY_CONSTRAINTS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(POLICY_CONSTRAINTS_free_allownil)}
    if FuncLoadError then
      AFailed.Add('POLICY_CONSTRAINTS_free');
    {$ifend}
  end;
  
  POLICY_CONSTRAINTS_it := LoadLibFunction(ADllHandle, POLICY_CONSTRAINTS_it_procname);
  FuncLoadError := not assigned(POLICY_CONSTRAINTS_it);
  if FuncLoadError then
  begin
    {$if not defined(POLICY_CONSTRAINTS_it_allownil)}
    POLICY_CONSTRAINTS_it := ERR_POLICY_CONSTRAINTS_it;
    {$ifend}
    {$if declared(POLICY_CONSTRAINTS_it_introduced)}
    if LibVersion < POLICY_CONSTRAINTS_it_introduced then
    begin
      {$if declared(FC_POLICY_CONSTRAINTS_it)}
      POLICY_CONSTRAINTS_it := FC_POLICY_CONSTRAINTS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(POLICY_CONSTRAINTS_it_removed)}
    if POLICY_CONSTRAINTS_it_removed <= LibVersion then
    begin
      {$if declared(_POLICY_CONSTRAINTS_it)}
      POLICY_CONSTRAINTS_it := _POLICY_CONSTRAINTS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(POLICY_CONSTRAINTS_it_allownil)}
    if FuncLoadError then
      AFailed.Add('POLICY_CONSTRAINTS_it');
    {$ifend}
  end;
  
  a2i_GENERAL_NAME := LoadLibFunction(ADllHandle, a2i_GENERAL_NAME_procname);
  FuncLoadError := not assigned(a2i_GENERAL_NAME);
  if FuncLoadError then
  begin
    {$if not defined(a2i_GENERAL_NAME_allownil)}
    a2i_GENERAL_NAME := ERR_a2i_GENERAL_NAME;
    {$ifend}
    {$if declared(a2i_GENERAL_NAME_introduced)}
    if LibVersion < a2i_GENERAL_NAME_introduced then
    begin
      {$if declared(FC_a2i_GENERAL_NAME)}
      a2i_GENERAL_NAME := FC_a2i_GENERAL_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(a2i_GENERAL_NAME_removed)}
    if a2i_GENERAL_NAME_removed <= LibVersion then
    begin
      {$if declared(_a2i_GENERAL_NAME)}
      a2i_GENERAL_NAME := _a2i_GENERAL_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(a2i_GENERAL_NAME_allownil)}
    if FuncLoadError then
      AFailed.Add('a2i_GENERAL_NAME');
    {$ifend}
  end;
  
  v2i_GENERAL_NAME := LoadLibFunction(ADllHandle, v2i_GENERAL_NAME_procname);
  FuncLoadError := not assigned(v2i_GENERAL_NAME);
  if FuncLoadError then
  begin
    {$if not defined(v2i_GENERAL_NAME_allownil)}
    v2i_GENERAL_NAME := ERR_v2i_GENERAL_NAME;
    {$ifend}
    {$if declared(v2i_GENERAL_NAME_introduced)}
    if LibVersion < v2i_GENERAL_NAME_introduced then
    begin
      {$if declared(FC_v2i_GENERAL_NAME)}
      v2i_GENERAL_NAME := FC_v2i_GENERAL_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(v2i_GENERAL_NAME_removed)}
    if v2i_GENERAL_NAME_removed <= LibVersion then
    begin
      {$if declared(_v2i_GENERAL_NAME)}
      v2i_GENERAL_NAME := _v2i_GENERAL_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(v2i_GENERAL_NAME_allownil)}
    if FuncLoadError then
      AFailed.Add('v2i_GENERAL_NAME');
    {$ifend}
  end;
  
  v2i_GENERAL_NAME_ex := LoadLibFunction(ADllHandle, v2i_GENERAL_NAME_ex_procname);
  FuncLoadError := not assigned(v2i_GENERAL_NAME_ex);
  if FuncLoadError then
  begin
    {$if not defined(v2i_GENERAL_NAME_ex_allownil)}
    v2i_GENERAL_NAME_ex := ERR_v2i_GENERAL_NAME_ex;
    {$ifend}
    {$if declared(v2i_GENERAL_NAME_ex_introduced)}
    if LibVersion < v2i_GENERAL_NAME_ex_introduced then
    begin
      {$if declared(FC_v2i_GENERAL_NAME_ex)}
      v2i_GENERAL_NAME_ex := FC_v2i_GENERAL_NAME_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(v2i_GENERAL_NAME_ex_removed)}
    if v2i_GENERAL_NAME_ex_removed <= LibVersion then
    begin
      {$if declared(_v2i_GENERAL_NAME_ex)}
      v2i_GENERAL_NAME_ex := _v2i_GENERAL_NAME_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(v2i_GENERAL_NAME_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('v2i_GENERAL_NAME_ex');
    {$ifend}
  end;
  
  X509V3_conf_free := LoadLibFunction(ADllHandle, X509V3_conf_free_procname);
  FuncLoadError := not assigned(X509V3_conf_free);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_conf_free_allownil)}
    X509V3_conf_free := ERR_X509V3_conf_free;
    {$ifend}
    {$if declared(X509V3_conf_free_introduced)}
    if LibVersion < X509V3_conf_free_introduced then
    begin
      {$if declared(FC_X509V3_conf_free)}
      X509V3_conf_free := FC_X509V3_conf_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_conf_free_removed)}
    if X509V3_conf_free_removed <= LibVersion then
    begin
      {$if declared(_X509V3_conf_free)}
      X509V3_conf_free := _X509V3_conf_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_conf_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_conf_free');
    {$ifend}
  end;
  
  X509V3_EXT_nconf_nid := LoadLibFunction(ADllHandle, X509V3_EXT_nconf_nid_procname);
  FuncLoadError := not assigned(X509V3_EXT_nconf_nid);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_nconf_nid_allownil)}
    X509V3_EXT_nconf_nid := ERR_X509V3_EXT_nconf_nid;
    {$ifend}
    {$if declared(X509V3_EXT_nconf_nid_introduced)}
    if LibVersion < X509V3_EXT_nconf_nid_introduced then
    begin
      {$if declared(FC_X509V3_EXT_nconf_nid)}
      X509V3_EXT_nconf_nid := FC_X509V3_EXT_nconf_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_nconf_nid_removed)}
    if X509V3_EXT_nconf_nid_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_nconf_nid)}
      X509V3_EXT_nconf_nid := _X509V3_EXT_nconf_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_nconf_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_nconf_nid');
    {$ifend}
  end;
  
  X509V3_EXT_nconf := LoadLibFunction(ADllHandle, X509V3_EXT_nconf_procname);
  FuncLoadError := not assigned(X509V3_EXT_nconf);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_nconf_allownil)}
    X509V3_EXT_nconf := ERR_X509V3_EXT_nconf;
    {$ifend}
    {$if declared(X509V3_EXT_nconf_introduced)}
    if LibVersion < X509V3_EXT_nconf_introduced then
    begin
      {$if declared(FC_X509V3_EXT_nconf)}
      X509V3_EXT_nconf := FC_X509V3_EXT_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_nconf_removed)}
    if X509V3_EXT_nconf_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_nconf)}
      X509V3_EXT_nconf := _X509V3_EXT_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_nconf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_nconf');
    {$ifend}
  end;
  
  X509V3_EXT_add_nconf_sk := LoadLibFunction(ADllHandle, X509V3_EXT_add_nconf_sk_procname);
  FuncLoadError := not assigned(X509V3_EXT_add_nconf_sk);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_add_nconf_sk_allownil)}
    X509V3_EXT_add_nconf_sk := ERR_X509V3_EXT_add_nconf_sk;
    {$ifend}
    {$if declared(X509V3_EXT_add_nconf_sk_introduced)}
    if LibVersion < X509V3_EXT_add_nconf_sk_introduced then
    begin
      {$if declared(FC_X509V3_EXT_add_nconf_sk)}
      X509V3_EXT_add_nconf_sk := FC_X509V3_EXT_add_nconf_sk;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_add_nconf_sk_removed)}
    if X509V3_EXT_add_nconf_sk_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_add_nconf_sk)}
      X509V3_EXT_add_nconf_sk := _X509V3_EXT_add_nconf_sk;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_add_nconf_sk_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_add_nconf_sk');
    {$ifend}
  end;
  
  X509V3_EXT_add_nconf := LoadLibFunction(ADllHandle, X509V3_EXT_add_nconf_procname);
  FuncLoadError := not assigned(X509V3_EXT_add_nconf);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_add_nconf_allownil)}
    X509V3_EXT_add_nconf := ERR_X509V3_EXT_add_nconf;
    {$ifend}
    {$if declared(X509V3_EXT_add_nconf_introduced)}
    if LibVersion < X509V3_EXT_add_nconf_introduced then
    begin
      {$if declared(FC_X509V3_EXT_add_nconf)}
      X509V3_EXT_add_nconf := FC_X509V3_EXT_add_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_add_nconf_removed)}
    if X509V3_EXT_add_nconf_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_add_nconf)}
      X509V3_EXT_add_nconf := _X509V3_EXT_add_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_add_nconf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_add_nconf');
    {$ifend}
  end;
  
  X509V3_EXT_REQ_add_nconf := LoadLibFunction(ADllHandle, X509V3_EXT_REQ_add_nconf_procname);
  FuncLoadError := not assigned(X509V3_EXT_REQ_add_nconf);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_REQ_add_nconf_allownil)}
    X509V3_EXT_REQ_add_nconf := ERR_X509V3_EXT_REQ_add_nconf;
    {$ifend}
    {$if declared(X509V3_EXT_REQ_add_nconf_introduced)}
    if LibVersion < X509V3_EXT_REQ_add_nconf_introduced then
    begin
      {$if declared(FC_X509V3_EXT_REQ_add_nconf)}
      X509V3_EXT_REQ_add_nconf := FC_X509V3_EXT_REQ_add_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_REQ_add_nconf_removed)}
    if X509V3_EXT_REQ_add_nconf_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_REQ_add_nconf)}
      X509V3_EXT_REQ_add_nconf := _X509V3_EXT_REQ_add_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_REQ_add_nconf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_REQ_add_nconf');
    {$ifend}
  end;
  
  X509V3_EXT_CRL_add_nconf := LoadLibFunction(ADllHandle, X509V3_EXT_CRL_add_nconf_procname);
  FuncLoadError := not assigned(X509V3_EXT_CRL_add_nconf);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_CRL_add_nconf_allownil)}
    X509V3_EXT_CRL_add_nconf := ERR_X509V3_EXT_CRL_add_nconf;
    {$ifend}
    {$if declared(X509V3_EXT_CRL_add_nconf_introduced)}
    if LibVersion < X509V3_EXT_CRL_add_nconf_introduced then
    begin
      {$if declared(FC_X509V3_EXT_CRL_add_nconf)}
      X509V3_EXT_CRL_add_nconf := FC_X509V3_EXT_CRL_add_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_CRL_add_nconf_removed)}
    if X509V3_EXT_CRL_add_nconf_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_CRL_add_nconf)}
      X509V3_EXT_CRL_add_nconf := _X509V3_EXT_CRL_add_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_CRL_add_nconf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_CRL_add_nconf');
    {$ifend}
  end;
  
  X509V3_EXT_conf_nid := LoadLibFunction(ADllHandle, X509V3_EXT_conf_nid_procname);
  FuncLoadError := not assigned(X509V3_EXT_conf_nid);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_conf_nid_allownil)}
    X509V3_EXT_conf_nid := ERR_X509V3_EXT_conf_nid;
    {$ifend}
    {$if declared(X509V3_EXT_conf_nid_introduced)}
    if LibVersion < X509V3_EXT_conf_nid_introduced then
    begin
      {$if declared(FC_X509V3_EXT_conf_nid)}
      X509V3_EXT_conf_nid := FC_X509V3_EXT_conf_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_conf_nid_removed)}
    if X509V3_EXT_conf_nid_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_conf_nid)}
      X509V3_EXT_conf_nid := _X509V3_EXT_conf_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_conf_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_conf_nid');
    {$ifend}
  end;
  
  X509V3_EXT_conf := LoadLibFunction(ADllHandle, X509V3_EXT_conf_procname);
  FuncLoadError := not assigned(X509V3_EXT_conf);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_conf_allownil)}
    X509V3_EXT_conf := ERR_X509V3_EXT_conf;
    {$ifend}
    {$if declared(X509V3_EXT_conf_introduced)}
    if LibVersion < X509V3_EXT_conf_introduced then
    begin
      {$if declared(FC_X509V3_EXT_conf)}
      X509V3_EXT_conf := FC_X509V3_EXT_conf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_conf_removed)}
    if X509V3_EXT_conf_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_conf)}
      X509V3_EXT_conf := _X509V3_EXT_conf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_conf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_conf');
    {$ifend}
  end;
  
  X509V3_EXT_add_conf := LoadLibFunction(ADllHandle, X509V3_EXT_add_conf_procname);
  FuncLoadError := not assigned(X509V3_EXT_add_conf);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_add_conf_allownil)}
    X509V3_EXT_add_conf := ERR_X509V3_EXT_add_conf;
    {$ifend}
    {$if declared(X509V3_EXT_add_conf_introduced)}
    if LibVersion < X509V3_EXT_add_conf_introduced then
    begin
      {$if declared(FC_X509V3_EXT_add_conf)}
      X509V3_EXT_add_conf := FC_X509V3_EXT_add_conf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_add_conf_removed)}
    if X509V3_EXT_add_conf_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_add_conf)}
      X509V3_EXT_add_conf := _X509V3_EXT_add_conf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_add_conf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_add_conf');
    {$ifend}
  end;
  
  X509V3_EXT_REQ_add_conf := LoadLibFunction(ADllHandle, X509V3_EXT_REQ_add_conf_procname);
  FuncLoadError := not assigned(X509V3_EXT_REQ_add_conf);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_REQ_add_conf_allownil)}
    X509V3_EXT_REQ_add_conf := ERR_X509V3_EXT_REQ_add_conf;
    {$ifend}
    {$if declared(X509V3_EXT_REQ_add_conf_introduced)}
    if LibVersion < X509V3_EXT_REQ_add_conf_introduced then
    begin
      {$if declared(FC_X509V3_EXT_REQ_add_conf)}
      X509V3_EXT_REQ_add_conf := FC_X509V3_EXT_REQ_add_conf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_REQ_add_conf_removed)}
    if X509V3_EXT_REQ_add_conf_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_REQ_add_conf)}
      X509V3_EXT_REQ_add_conf := _X509V3_EXT_REQ_add_conf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_REQ_add_conf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_REQ_add_conf');
    {$ifend}
  end;
  
  X509V3_EXT_CRL_add_conf := LoadLibFunction(ADllHandle, X509V3_EXT_CRL_add_conf_procname);
  FuncLoadError := not assigned(X509V3_EXT_CRL_add_conf);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_CRL_add_conf_allownil)}
    X509V3_EXT_CRL_add_conf := ERR_X509V3_EXT_CRL_add_conf;
    {$ifend}
    {$if declared(X509V3_EXT_CRL_add_conf_introduced)}
    if LibVersion < X509V3_EXT_CRL_add_conf_introduced then
    begin
      {$if declared(FC_X509V3_EXT_CRL_add_conf)}
      X509V3_EXT_CRL_add_conf := FC_X509V3_EXT_CRL_add_conf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_CRL_add_conf_removed)}
    if X509V3_EXT_CRL_add_conf_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_CRL_add_conf)}
      X509V3_EXT_CRL_add_conf := _X509V3_EXT_CRL_add_conf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_CRL_add_conf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_CRL_add_conf');
    {$ifend}
  end;
  
  X509V3_add_value_bool_nf := LoadLibFunction(ADllHandle, X509V3_add_value_bool_nf_procname);
  FuncLoadError := not assigned(X509V3_add_value_bool_nf);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_add_value_bool_nf_allownil)}
    X509V3_add_value_bool_nf := ERR_X509V3_add_value_bool_nf;
    {$ifend}
    {$if declared(X509V3_add_value_bool_nf_introduced)}
    if LibVersion < X509V3_add_value_bool_nf_introduced then
    begin
      {$if declared(FC_X509V3_add_value_bool_nf)}
      X509V3_add_value_bool_nf := FC_X509V3_add_value_bool_nf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_add_value_bool_nf_removed)}
    if X509V3_add_value_bool_nf_removed <= LibVersion then
    begin
      {$if declared(_X509V3_add_value_bool_nf)}
      X509V3_add_value_bool_nf := _X509V3_add_value_bool_nf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_add_value_bool_nf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_add_value_bool_nf');
    {$ifend}
  end;
  
  X509V3_get_value_bool := LoadLibFunction(ADllHandle, X509V3_get_value_bool_procname);
  FuncLoadError := not assigned(X509V3_get_value_bool);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_get_value_bool_allownil)}
    X509V3_get_value_bool := ERR_X509V3_get_value_bool;
    {$ifend}
    {$if declared(X509V3_get_value_bool_introduced)}
    if LibVersion < X509V3_get_value_bool_introduced then
    begin
      {$if declared(FC_X509V3_get_value_bool)}
      X509V3_get_value_bool := FC_X509V3_get_value_bool;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_get_value_bool_removed)}
    if X509V3_get_value_bool_removed <= LibVersion then
    begin
      {$if declared(_X509V3_get_value_bool)}
      X509V3_get_value_bool := _X509V3_get_value_bool;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_get_value_bool_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_get_value_bool');
    {$ifend}
  end;
  
  X509V3_get_value_int := LoadLibFunction(ADllHandle, X509V3_get_value_int_procname);
  FuncLoadError := not assigned(X509V3_get_value_int);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_get_value_int_allownil)}
    X509V3_get_value_int := ERR_X509V3_get_value_int;
    {$ifend}
    {$if declared(X509V3_get_value_int_introduced)}
    if LibVersion < X509V3_get_value_int_introduced then
    begin
      {$if declared(FC_X509V3_get_value_int)}
      X509V3_get_value_int := FC_X509V3_get_value_int;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_get_value_int_removed)}
    if X509V3_get_value_int_removed <= LibVersion then
    begin
      {$if declared(_X509V3_get_value_int)}
      X509V3_get_value_int := _X509V3_get_value_int;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_get_value_int_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_get_value_int');
    {$ifend}
  end;
  
  X509V3_set_nconf := LoadLibFunction(ADllHandle, X509V3_set_nconf_procname);
  FuncLoadError := not assigned(X509V3_set_nconf);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_set_nconf_allownil)}
    X509V3_set_nconf := ERR_X509V3_set_nconf;
    {$ifend}
    {$if declared(X509V3_set_nconf_introduced)}
    if LibVersion < X509V3_set_nconf_introduced then
    begin
      {$if declared(FC_X509V3_set_nconf)}
      X509V3_set_nconf := FC_X509V3_set_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_set_nconf_removed)}
    if X509V3_set_nconf_removed <= LibVersion then
    begin
      {$if declared(_X509V3_set_nconf)}
      X509V3_set_nconf := _X509V3_set_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_set_nconf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_set_nconf');
    {$ifend}
  end;
  
  X509V3_set_conf_lhash := LoadLibFunction(ADllHandle, X509V3_set_conf_lhash_procname);
  FuncLoadError := not assigned(X509V3_set_conf_lhash);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_set_conf_lhash_allownil)}
    X509V3_set_conf_lhash := ERR_X509V3_set_conf_lhash;
    {$ifend}
    {$if declared(X509V3_set_conf_lhash_introduced)}
    if LibVersion < X509V3_set_conf_lhash_introduced then
    begin
      {$if declared(FC_X509V3_set_conf_lhash)}
      X509V3_set_conf_lhash := FC_X509V3_set_conf_lhash;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_set_conf_lhash_removed)}
    if X509V3_set_conf_lhash_removed <= LibVersion then
    begin
      {$if declared(_X509V3_set_conf_lhash)}
      X509V3_set_conf_lhash := _X509V3_set_conf_lhash;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_set_conf_lhash_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_set_conf_lhash');
    {$ifend}
  end;
  
  X509V3_get_string := LoadLibFunction(ADllHandle, X509V3_get_string_procname);
  FuncLoadError := not assigned(X509V3_get_string);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_get_string_allownil)}
    X509V3_get_string := ERR_X509V3_get_string;
    {$ifend}
    {$if declared(X509V3_get_string_introduced)}
    if LibVersion < X509V3_get_string_introduced then
    begin
      {$if declared(FC_X509V3_get_string)}
      X509V3_get_string := FC_X509V3_get_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_get_string_removed)}
    if X509V3_get_string_removed <= LibVersion then
    begin
      {$if declared(_X509V3_get_string)}
      X509V3_get_string := _X509V3_get_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_get_string_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_get_string');
    {$ifend}
  end;
  
  X509V3_get_section := LoadLibFunction(ADllHandle, X509V3_get_section_procname);
  FuncLoadError := not assigned(X509V3_get_section);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_get_section_allownil)}
    X509V3_get_section := ERR_X509V3_get_section;
    {$ifend}
    {$if declared(X509V3_get_section_introduced)}
    if LibVersion < X509V3_get_section_introduced then
    begin
      {$if declared(FC_X509V3_get_section)}
      X509V3_get_section := FC_X509V3_get_section;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_get_section_removed)}
    if X509V3_get_section_removed <= LibVersion then
    begin
      {$if declared(_X509V3_get_section)}
      X509V3_get_section := _X509V3_get_section;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_get_section_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_get_section');
    {$ifend}
  end;
  
  X509V3_string_free := LoadLibFunction(ADllHandle, X509V3_string_free_procname);
  FuncLoadError := not assigned(X509V3_string_free);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_string_free_allownil)}
    X509V3_string_free := ERR_X509V3_string_free;
    {$ifend}
    {$if declared(X509V3_string_free_introduced)}
    if LibVersion < X509V3_string_free_introduced then
    begin
      {$if declared(FC_X509V3_string_free)}
      X509V3_string_free := FC_X509V3_string_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_string_free_removed)}
    if X509V3_string_free_removed <= LibVersion then
    begin
      {$if declared(_X509V3_string_free)}
      X509V3_string_free := _X509V3_string_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_string_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_string_free');
    {$ifend}
  end;
  
  X509V3_section_free := LoadLibFunction(ADllHandle, X509V3_section_free_procname);
  FuncLoadError := not assigned(X509V3_section_free);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_section_free_allownil)}
    X509V3_section_free := ERR_X509V3_section_free;
    {$ifend}
    {$if declared(X509V3_section_free_introduced)}
    if LibVersion < X509V3_section_free_introduced then
    begin
      {$if declared(FC_X509V3_section_free)}
      X509V3_section_free := FC_X509V3_section_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_section_free_removed)}
    if X509V3_section_free_removed <= LibVersion then
    begin
      {$if declared(_X509V3_section_free)}
      X509V3_section_free := _X509V3_section_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_section_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_section_free');
    {$ifend}
  end;
  
  X509V3_set_ctx := LoadLibFunction(ADllHandle, X509V3_set_ctx_procname);
  FuncLoadError := not assigned(X509V3_set_ctx);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_set_ctx_allownil)}
    X509V3_set_ctx := ERR_X509V3_set_ctx;
    {$ifend}
    {$if declared(X509V3_set_ctx_introduced)}
    if LibVersion < X509V3_set_ctx_introduced then
    begin
      {$if declared(FC_X509V3_set_ctx)}
      X509V3_set_ctx := FC_X509V3_set_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_set_ctx_removed)}
    if X509V3_set_ctx_removed <= LibVersion then
    begin
      {$if declared(_X509V3_set_ctx)}
      X509V3_set_ctx := _X509V3_set_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_set_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_set_ctx');
    {$ifend}
  end;
  
  X509V3_set_issuer_pkey := LoadLibFunction(ADllHandle, X509V3_set_issuer_pkey_procname);
  FuncLoadError := not assigned(X509V3_set_issuer_pkey);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_set_issuer_pkey_allownil)}
    X509V3_set_issuer_pkey := ERR_X509V3_set_issuer_pkey;
    {$ifend}
    {$if declared(X509V3_set_issuer_pkey_introduced)}
    if LibVersion < X509V3_set_issuer_pkey_introduced then
    begin
      {$if declared(FC_X509V3_set_issuer_pkey)}
      X509V3_set_issuer_pkey := FC_X509V3_set_issuer_pkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_set_issuer_pkey_removed)}
    if X509V3_set_issuer_pkey_removed <= LibVersion then
    begin
      {$if declared(_X509V3_set_issuer_pkey)}
      X509V3_set_issuer_pkey := _X509V3_set_issuer_pkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_set_issuer_pkey_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_set_issuer_pkey');
    {$ifend}
  end;
  
  X509V3_add_value := LoadLibFunction(ADllHandle, X509V3_add_value_procname);
  FuncLoadError := not assigned(X509V3_add_value);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_add_value_allownil)}
    X509V3_add_value := ERR_X509V3_add_value;
    {$ifend}
    {$if declared(X509V3_add_value_introduced)}
    if LibVersion < X509V3_add_value_introduced then
    begin
      {$if declared(FC_X509V3_add_value)}
      X509V3_add_value := FC_X509V3_add_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_add_value_removed)}
    if X509V3_add_value_removed <= LibVersion then
    begin
      {$if declared(_X509V3_add_value)}
      X509V3_add_value := _X509V3_add_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_add_value_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_add_value');
    {$ifend}
  end;
  
  X509V3_add_value_uchar := LoadLibFunction(ADllHandle, X509V3_add_value_uchar_procname);
  FuncLoadError := not assigned(X509V3_add_value_uchar);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_add_value_uchar_allownil)}
    X509V3_add_value_uchar := ERR_X509V3_add_value_uchar;
    {$ifend}
    {$if declared(X509V3_add_value_uchar_introduced)}
    if LibVersion < X509V3_add_value_uchar_introduced then
    begin
      {$if declared(FC_X509V3_add_value_uchar)}
      X509V3_add_value_uchar := FC_X509V3_add_value_uchar;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_add_value_uchar_removed)}
    if X509V3_add_value_uchar_removed <= LibVersion then
    begin
      {$if declared(_X509V3_add_value_uchar)}
      X509V3_add_value_uchar := _X509V3_add_value_uchar;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_add_value_uchar_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_add_value_uchar');
    {$ifend}
  end;
  
  X509V3_add_value_bool := LoadLibFunction(ADllHandle, X509V3_add_value_bool_procname);
  FuncLoadError := not assigned(X509V3_add_value_bool);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_add_value_bool_allownil)}
    X509V3_add_value_bool := ERR_X509V3_add_value_bool;
    {$ifend}
    {$if declared(X509V3_add_value_bool_introduced)}
    if LibVersion < X509V3_add_value_bool_introduced then
    begin
      {$if declared(FC_X509V3_add_value_bool)}
      X509V3_add_value_bool := FC_X509V3_add_value_bool;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_add_value_bool_removed)}
    if X509V3_add_value_bool_removed <= LibVersion then
    begin
      {$if declared(_X509V3_add_value_bool)}
      X509V3_add_value_bool := _X509V3_add_value_bool;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_add_value_bool_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_add_value_bool');
    {$ifend}
  end;
  
  X509V3_add_value_int := LoadLibFunction(ADllHandle, X509V3_add_value_int_procname);
  FuncLoadError := not assigned(X509V3_add_value_int);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_add_value_int_allownil)}
    X509V3_add_value_int := ERR_X509V3_add_value_int;
    {$ifend}
    {$if declared(X509V3_add_value_int_introduced)}
    if LibVersion < X509V3_add_value_int_introduced then
    begin
      {$if declared(FC_X509V3_add_value_int)}
      X509V3_add_value_int := FC_X509V3_add_value_int;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_add_value_int_removed)}
    if X509V3_add_value_int_removed <= LibVersion then
    begin
      {$if declared(_X509V3_add_value_int)}
      X509V3_add_value_int := _X509V3_add_value_int;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_add_value_int_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_add_value_int');
    {$ifend}
  end;
  
  i2s_ASN1_INTEGER := LoadLibFunction(ADllHandle, i2s_ASN1_INTEGER_procname);
  FuncLoadError := not assigned(i2s_ASN1_INTEGER);
  if FuncLoadError then
  begin
    {$if not defined(i2s_ASN1_INTEGER_allownil)}
    i2s_ASN1_INTEGER := ERR_i2s_ASN1_INTEGER;
    {$ifend}
    {$if declared(i2s_ASN1_INTEGER_introduced)}
    if LibVersion < i2s_ASN1_INTEGER_introduced then
    begin
      {$if declared(FC_i2s_ASN1_INTEGER)}
      i2s_ASN1_INTEGER := FC_i2s_ASN1_INTEGER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2s_ASN1_INTEGER_removed)}
    if i2s_ASN1_INTEGER_removed <= LibVersion then
    begin
      {$if declared(_i2s_ASN1_INTEGER)}
      i2s_ASN1_INTEGER := _i2s_ASN1_INTEGER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2s_ASN1_INTEGER_allownil)}
    if FuncLoadError then
      AFailed.Add('i2s_ASN1_INTEGER');
    {$ifend}
  end;
  
  s2i_ASN1_INTEGER := LoadLibFunction(ADllHandle, s2i_ASN1_INTEGER_procname);
  FuncLoadError := not assigned(s2i_ASN1_INTEGER);
  if FuncLoadError then
  begin
    {$if not defined(s2i_ASN1_INTEGER_allownil)}
    s2i_ASN1_INTEGER := ERR_s2i_ASN1_INTEGER;
    {$ifend}
    {$if declared(s2i_ASN1_INTEGER_introduced)}
    if LibVersion < s2i_ASN1_INTEGER_introduced then
    begin
      {$if declared(FC_s2i_ASN1_INTEGER)}
      s2i_ASN1_INTEGER := FC_s2i_ASN1_INTEGER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(s2i_ASN1_INTEGER_removed)}
    if s2i_ASN1_INTEGER_removed <= LibVersion then
    begin
      {$if declared(_s2i_ASN1_INTEGER)}
      s2i_ASN1_INTEGER := _s2i_ASN1_INTEGER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(s2i_ASN1_INTEGER_allownil)}
    if FuncLoadError then
      AFailed.Add('s2i_ASN1_INTEGER');
    {$ifend}
  end;
  
  i2s_ASN1_ENUMERATED := LoadLibFunction(ADllHandle, i2s_ASN1_ENUMERATED_procname);
  FuncLoadError := not assigned(i2s_ASN1_ENUMERATED);
  if FuncLoadError then
  begin
    {$if not defined(i2s_ASN1_ENUMERATED_allownil)}
    i2s_ASN1_ENUMERATED := ERR_i2s_ASN1_ENUMERATED;
    {$ifend}
    {$if declared(i2s_ASN1_ENUMERATED_introduced)}
    if LibVersion < i2s_ASN1_ENUMERATED_introduced then
    begin
      {$if declared(FC_i2s_ASN1_ENUMERATED)}
      i2s_ASN1_ENUMERATED := FC_i2s_ASN1_ENUMERATED;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2s_ASN1_ENUMERATED_removed)}
    if i2s_ASN1_ENUMERATED_removed <= LibVersion then
    begin
      {$if declared(_i2s_ASN1_ENUMERATED)}
      i2s_ASN1_ENUMERATED := _i2s_ASN1_ENUMERATED;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2s_ASN1_ENUMERATED_allownil)}
    if FuncLoadError then
      AFailed.Add('i2s_ASN1_ENUMERATED');
    {$ifend}
  end;
  
  i2s_ASN1_ENUMERATED_TABLE := LoadLibFunction(ADllHandle, i2s_ASN1_ENUMERATED_TABLE_procname);
  FuncLoadError := not assigned(i2s_ASN1_ENUMERATED_TABLE);
  if FuncLoadError then
  begin
    {$if not defined(i2s_ASN1_ENUMERATED_TABLE_allownil)}
    i2s_ASN1_ENUMERATED_TABLE := ERR_i2s_ASN1_ENUMERATED_TABLE;
    {$ifend}
    {$if declared(i2s_ASN1_ENUMERATED_TABLE_introduced)}
    if LibVersion < i2s_ASN1_ENUMERATED_TABLE_introduced then
    begin
      {$if declared(FC_i2s_ASN1_ENUMERATED_TABLE)}
      i2s_ASN1_ENUMERATED_TABLE := FC_i2s_ASN1_ENUMERATED_TABLE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2s_ASN1_ENUMERATED_TABLE_removed)}
    if i2s_ASN1_ENUMERATED_TABLE_removed <= LibVersion then
    begin
      {$if declared(_i2s_ASN1_ENUMERATED_TABLE)}
      i2s_ASN1_ENUMERATED_TABLE := _i2s_ASN1_ENUMERATED_TABLE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2s_ASN1_ENUMERATED_TABLE_allownil)}
    if FuncLoadError then
      AFailed.Add('i2s_ASN1_ENUMERATED_TABLE');
    {$ifend}
  end;
  
  X509V3_EXT_add := LoadLibFunction(ADllHandle, X509V3_EXT_add_procname);
  FuncLoadError := not assigned(X509V3_EXT_add);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_add_allownil)}
    X509V3_EXT_add := ERR_X509V3_EXT_add;
    {$ifend}
    {$if declared(X509V3_EXT_add_introduced)}
    if LibVersion < X509V3_EXT_add_introduced then
    begin
      {$if declared(FC_X509V3_EXT_add)}
      X509V3_EXT_add := FC_X509V3_EXT_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_add_removed)}
    if X509V3_EXT_add_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_add)}
      X509V3_EXT_add := _X509V3_EXT_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_add_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_add');
    {$ifend}
  end;
  
  X509V3_EXT_add_list := LoadLibFunction(ADllHandle, X509V3_EXT_add_list_procname);
  FuncLoadError := not assigned(X509V3_EXT_add_list);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_add_list_allownil)}
    X509V3_EXT_add_list := ERR_X509V3_EXT_add_list;
    {$ifend}
    {$if declared(X509V3_EXT_add_list_introduced)}
    if LibVersion < X509V3_EXT_add_list_introduced then
    begin
      {$if declared(FC_X509V3_EXT_add_list)}
      X509V3_EXT_add_list := FC_X509V3_EXT_add_list;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_add_list_removed)}
    if X509V3_EXT_add_list_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_add_list)}
      X509V3_EXT_add_list := _X509V3_EXT_add_list;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_add_list_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_add_list');
    {$ifend}
  end;
  
  X509V3_EXT_add_alias := LoadLibFunction(ADllHandle, X509V3_EXT_add_alias_procname);
  FuncLoadError := not assigned(X509V3_EXT_add_alias);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_add_alias_allownil)}
    X509V3_EXT_add_alias := ERR_X509V3_EXT_add_alias;
    {$ifend}
    {$if declared(X509V3_EXT_add_alias_introduced)}
    if LibVersion < X509V3_EXT_add_alias_introduced then
    begin
      {$if declared(FC_X509V3_EXT_add_alias)}
      X509V3_EXT_add_alias := FC_X509V3_EXT_add_alias;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_add_alias_removed)}
    if X509V3_EXT_add_alias_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_add_alias)}
      X509V3_EXT_add_alias := _X509V3_EXT_add_alias;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_add_alias_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_add_alias');
    {$ifend}
  end;
  
  X509V3_EXT_cleanup := LoadLibFunction(ADllHandle, X509V3_EXT_cleanup_procname);
  FuncLoadError := not assigned(X509V3_EXT_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_cleanup_allownil)}
    X509V3_EXT_cleanup := ERR_X509V3_EXT_cleanup;
    {$ifend}
    {$if declared(X509V3_EXT_cleanup_introduced)}
    if LibVersion < X509V3_EXT_cleanup_introduced then
    begin
      {$if declared(FC_X509V3_EXT_cleanup)}
      X509V3_EXT_cleanup := FC_X509V3_EXT_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_cleanup_removed)}
    if X509V3_EXT_cleanup_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_cleanup)}
      X509V3_EXT_cleanup := _X509V3_EXT_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_cleanup');
    {$ifend}
  end;
  
  X509V3_EXT_get := LoadLibFunction(ADllHandle, X509V3_EXT_get_procname);
  FuncLoadError := not assigned(X509V3_EXT_get);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_get_allownil)}
    X509V3_EXT_get := ERR_X509V3_EXT_get;
    {$ifend}
    {$if declared(X509V3_EXT_get_introduced)}
    if LibVersion < X509V3_EXT_get_introduced then
    begin
      {$if declared(FC_X509V3_EXT_get)}
      X509V3_EXT_get := FC_X509V3_EXT_get;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_get_removed)}
    if X509V3_EXT_get_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_get)}
      X509V3_EXT_get := _X509V3_EXT_get;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_get_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_get');
    {$ifend}
  end;
  
  X509V3_EXT_get_nid := LoadLibFunction(ADllHandle, X509V3_EXT_get_nid_procname);
  FuncLoadError := not assigned(X509V3_EXT_get_nid);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_get_nid_allownil)}
    X509V3_EXT_get_nid := ERR_X509V3_EXT_get_nid;
    {$ifend}
    {$if declared(X509V3_EXT_get_nid_introduced)}
    if LibVersion < X509V3_EXT_get_nid_introduced then
    begin
      {$if declared(FC_X509V3_EXT_get_nid)}
      X509V3_EXT_get_nid := FC_X509V3_EXT_get_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_get_nid_removed)}
    if X509V3_EXT_get_nid_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_get_nid)}
      X509V3_EXT_get_nid := _X509V3_EXT_get_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_get_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_get_nid');
    {$ifend}
  end;
  
  X509V3_add_standard_extensions := LoadLibFunction(ADllHandle, X509V3_add_standard_extensions_procname);
  FuncLoadError := not assigned(X509V3_add_standard_extensions);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_add_standard_extensions_allownil)}
    X509V3_add_standard_extensions := ERR_X509V3_add_standard_extensions;
    {$ifend}
    {$if declared(X509V3_add_standard_extensions_introduced)}
    if LibVersion < X509V3_add_standard_extensions_introduced then
    begin
      {$if declared(FC_X509V3_add_standard_extensions)}
      X509V3_add_standard_extensions := FC_X509V3_add_standard_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_add_standard_extensions_removed)}
    if X509V3_add_standard_extensions_removed <= LibVersion then
    begin
      {$if declared(_X509V3_add_standard_extensions)}
      X509V3_add_standard_extensions := _X509V3_add_standard_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_add_standard_extensions_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_add_standard_extensions');
    {$ifend}
  end;
  
  X509V3_parse_list := LoadLibFunction(ADllHandle, X509V3_parse_list_procname);
  FuncLoadError := not assigned(X509V3_parse_list);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_parse_list_allownil)}
    X509V3_parse_list := ERR_X509V3_parse_list;
    {$ifend}
    {$if declared(X509V3_parse_list_introduced)}
    if LibVersion < X509V3_parse_list_introduced then
    begin
      {$if declared(FC_X509V3_parse_list)}
      X509V3_parse_list := FC_X509V3_parse_list;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_parse_list_removed)}
    if X509V3_parse_list_removed <= LibVersion then
    begin
      {$if declared(_X509V3_parse_list)}
      X509V3_parse_list := _X509V3_parse_list;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_parse_list_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_parse_list');
    {$ifend}
  end;
  
  X509V3_EXT_d2i := LoadLibFunction(ADllHandle, X509V3_EXT_d2i_procname);
  FuncLoadError := not assigned(X509V3_EXT_d2i);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_d2i_allownil)}
    X509V3_EXT_d2i := ERR_X509V3_EXT_d2i;
    {$ifend}
    {$if declared(X509V3_EXT_d2i_introduced)}
    if LibVersion < X509V3_EXT_d2i_introduced then
    begin
      {$if declared(FC_X509V3_EXT_d2i)}
      X509V3_EXT_d2i := FC_X509V3_EXT_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_d2i_removed)}
    if X509V3_EXT_d2i_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_d2i)}
      X509V3_EXT_d2i := _X509V3_EXT_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_d2i_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_d2i');
    {$ifend}
  end;
  
  X509V3_get_d2i := LoadLibFunction(ADllHandle, X509V3_get_d2i_procname);
  FuncLoadError := not assigned(X509V3_get_d2i);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_get_d2i_allownil)}
    X509V3_get_d2i := ERR_X509V3_get_d2i;
    {$ifend}
    {$if declared(X509V3_get_d2i_introduced)}
    if LibVersion < X509V3_get_d2i_introduced then
    begin
      {$if declared(FC_X509V3_get_d2i)}
      X509V3_get_d2i := FC_X509V3_get_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_get_d2i_removed)}
    if X509V3_get_d2i_removed <= LibVersion then
    begin
      {$if declared(_X509V3_get_d2i)}
      X509V3_get_d2i := _X509V3_get_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_get_d2i_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_get_d2i');
    {$ifend}
  end;
  
  X509V3_EXT_i2d := LoadLibFunction(ADllHandle, X509V3_EXT_i2d_procname);
  FuncLoadError := not assigned(X509V3_EXT_i2d);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_i2d_allownil)}
    X509V3_EXT_i2d := ERR_X509V3_EXT_i2d;
    {$ifend}
    {$if declared(X509V3_EXT_i2d_introduced)}
    if LibVersion < X509V3_EXT_i2d_introduced then
    begin
      {$if declared(FC_X509V3_EXT_i2d)}
      X509V3_EXT_i2d := FC_X509V3_EXT_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_i2d_removed)}
    if X509V3_EXT_i2d_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_i2d)}
      X509V3_EXT_i2d := _X509V3_EXT_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_i2d_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_i2d');
    {$ifend}
  end;
  
  X509V3_add1_i2d := LoadLibFunction(ADllHandle, X509V3_add1_i2d_procname);
  FuncLoadError := not assigned(X509V3_add1_i2d);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_add1_i2d_allownil)}
    X509V3_add1_i2d := ERR_X509V3_add1_i2d;
    {$ifend}
    {$if declared(X509V3_add1_i2d_introduced)}
    if LibVersion < X509V3_add1_i2d_introduced then
    begin
      {$if declared(FC_X509V3_add1_i2d)}
      X509V3_add1_i2d := FC_X509V3_add1_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_add1_i2d_removed)}
    if X509V3_add1_i2d_removed <= LibVersion then
    begin
      {$if declared(_X509V3_add1_i2d)}
      X509V3_add1_i2d := _X509V3_add1_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_add1_i2d_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_add1_i2d');
    {$ifend}
  end;
  
  X509V3_EXT_val_prn := LoadLibFunction(ADllHandle, X509V3_EXT_val_prn_procname);
  FuncLoadError := not assigned(X509V3_EXT_val_prn);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_val_prn_allownil)}
    X509V3_EXT_val_prn := ERR_X509V3_EXT_val_prn;
    {$ifend}
    {$if declared(X509V3_EXT_val_prn_introduced)}
    if LibVersion < X509V3_EXT_val_prn_introduced then
    begin
      {$if declared(FC_X509V3_EXT_val_prn)}
      X509V3_EXT_val_prn := FC_X509V3_EXT_val_prn;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_val_prn_removed)}
    if X509V3_EXT_val_prn_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_val_prn)}
      X509V3_EXT_val_prn := _X509V3_EXT_val_prn;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_val_prn_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_val_prn');
    {$ifend}
  end;
  
  X509V3_EXT_print := LoadLibFunction(ADllHandle, X509V3_EXT_print_procname);
  FuncLoadError := not assigned(X509V3_EXT_print);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_print_allownil)}
    X509V3_EXT_print := ERR_X509V3_EXT_print;
    {$ifend}
    {$if declared(X509V3_EXT_print_introduced)}
    if LibVersion < X509V3_EXT_print_introduced then
    begin
      {$if declared(FC_X509V3_EXT_print)}
      X509V3_EXT_print := FC_X509V3_EXT_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_print_removed)}
    if X509V3_EXT_print_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_print)}
      X509V3_EXT_print := _X509V3_EXT_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_print_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_print');
    {$ifend}
  end;
  
  X509V3_EXT_print_fp := LoadLibFunction(ADllHandle, X509V3_EXT_print_fp_procname);
  FuncLoadError := not assigned(X509V3_EXT_print_fp);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_print_fp_allownil)}
    X509V3_EXT_print_fp := ERR_X509V3_EXT_print_fp;
    {$ifend}
    {$if declared(X509V3_EXT_print_fp_introduced)}
    if LibVersion < X509V3_EXT_print_fp_introduced then
    begin
      {$if declared(FC_X509V3_EXT_print_fp)}
      X509V3_EXT_print_fp := FC_X509V3_EXT_print_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_print_fp_removed)}
    if X509V3_EXT_print_fp_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_print_fp)}
      X509V3_EXT_print_fp := _X509V3_EXT_print_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_print_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_print_fp');
    {$ifend}
  end;
  
  X509V3_extensions_print := LoadLibFunction(ADllHandle, X509V3_extensions_print_procname);
  FuncLoadError := not assigned(X509V3_extensions_print);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_extensions_print_allownil)}
    X509V3_extensions_print := ERR_X509V3_extensions_print;
    {$ifend}
    {$if declared(X509V3_extensions_print_introduced)}
    if LibVersion < X509V3_extensions_print_introduced then
    begin
      {$if declared(FC_X509V3_extensions_print)}
      X509V3_extensions_print := FC_X509V3_extensions_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_extensions_print_removed)}
    if X509V3_extensions_print_removed <= LibVersion then
    begin
      {$if declared(_X509V3_extensions_print)}
      X509V3_extensions_print := _X509V3_extensions_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_extensions_print_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_extensions_print');
    {$ifend}
  end;
  
  X509_check_ca := LoadLibFunction(ADllHandle, X509_check_ca_procname);
  FuncLoadError := not assigned(X509_check_ca);
  if FuncLoadError then
  begin
    {$if not defined(X509_check_ca_allownil)}
    X509_check_ca := ERR_X509_check_ca;
    {$ifend}
    {$if declared(X509_check_ca_introduced)}
    if LibVersion < X509_check_ca_introduced then
    begin
      {$if declared(FC_X509_check_ca)}
      X509_check_ca := FC_X509_check_ca;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_check_ca_removed)}
    if X509_check_ca_removed <= LibVersion then
    begin
      {$if declared(_X509_check_ca)}
      X509_check_ca := _X509_check_ca;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_check_ca_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_check_ca');
    {$ifend}
  end;
  
  X509_check_purpose := LoadLibFunction(ADllHandle, X509_check_purpose_procname);
  FuncLoadError := not assigned(X509_check_purpose);
  if FuncLoadError then
  begin
    {$if not defined(X509_check_purpose_allownil)}
    X509_check_purpose := ERR_X509_check_purpose;
    {$ifend}
    {$if declared(X509_check_purpose_introduced)}
    if LibVersion < X509_check_purpose_introduced then
    begin
      {$if declared(FC_X509_check_purpose)}
      X509_check_purpose := FC_X509_check_purpose;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_check_purpose_removed)}
    if X509_check_purpose_removed <= LibVersion then
    begin
      {$if declared(_X509_check_purpose)}
      X509_check_purpose := _X509_check_purpose;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_check_purpose_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_check_purpose');
    {$ifend}
  end;
  
  X509_supported_extension := LoadLibFunction(ADllHandle, X509_supported_extension_procname);
  FuncLoadError := not assigned(X509_supported_extension);
  if FuncLoadError then
  begin
    {$if not defined(X509_supported_extension_allownil)}
    X509_supported_extension := ERR_X509_supported_extension;
    {$ifend}
    {$if declared(X509_supported_extension_introduced)}
    if LibVersion < X509_supported_extension_introduced then
    begin
      {$if declared(FC_X509_supported_extension)}
      X509_supported_extension := FC_X509_supported_extension;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_supported_extension_removed)}
    if X509_supported_extension_removed <= LibVersion then
    begin
      {$if declared(_X509_supported_extension)}
      X509_supported_extension := _X509_supported_extension;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_supported_extension_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_supported_extension');
    {$ifend}
  end;
  
  X509_check_issued := LoadLibFunction(ADllHandle, X509_check_issued_procname);
  FuncLoadError := not assigned(X509_check_issued);
  if FuncLoadError then
  begin
    {$if not defined(X509_check_issued_allownil)}
    X509_check_issued := ERR_X509_check_issued;
    {$ifend}
    {$if declared(X509_check_issued_introduced)}
    if LibVersion < X509_check_issued_introduced then
    begin
      {$if declared(FC_X509_check_issued)}
      X509_check_issued := FC_X509_check_issued;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_check_issued_removed)}
    if X509_check_issued_removed <= LibVersion then
    begin
      {$if declared(_X509_check_issued)}
      X509_check_issued := _X509_check_issued;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_check_issued_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_check_issued');
    {$ifend}
  end;
  
  X509_check_akid := LoadLibFunction(ADllHandle, X509_check_akid_procname);
  FuncLoadError := not assigned(X509_check_akid);
  if FuncLoadError then
  begin
    {$if not defined(X509_check_akid_allownil)}
    X509_check_akid := ERR_X509_check_akid;
    {$ifend}
    {$if declared(X509_check_akid_introduced)}
    if LibVersion < X509_check_akid_introduced then
    begin
      {$if declared(FC_X509_check_akid)}
      X509_check_akid := FC_X509_check_akid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_check_akid_removed)}
    if X509_check_akid_removed <= LibVersion then
    begin
      {$if declared(_X509_check_akid)}
      X509_check_akid := _X509_check_akid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_check_akid_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_check_akid');
    {$ifend}
  end;
  
  X509_set_proxy_flag := LoadLibFunction(ADllHandle, X509_set_proxy_flag_procname);
  FuncLoadError := not assigned(X509_set_proxy_flag);
  if FuncLoadError then
  begin
    {$if not defined(X509_set_proxy_flag_allownil)}
    X509_set_proxy_flag := ERR_X509_set_proxy_flag;
    {$ifend}
    {$if declared(X509_set_proxy_flag_introduced)}
    if LibVersion < X509_set_proxy_flag_introduced then
    begin
      {$if declared(FC_X509_set_proxy_flag)}
      X509_set_proxy_flag := FC_X509_set_proxy_flag;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_set_proxy_flag_removed)}
    if X509_set_proxy_flag_removed <= LibVersion then
    begin
      {$if declared(_X509_set_proxy_flag)}
      X509_set_proxy_flag := _X509_set_proxy_flag;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_set_proxy_flag_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_set_proxy_flag');
    {$ifend}
  end;
  
  X509_set_proxy_pathlen := LoadLibFunction(ADllHandle, X509_set_proxy_pathlen_procname);
  FuncLoadError := not assigned(X509_set_proxy_pathlen);
  if FuncLoadError then
  begin
    {$if not defined(X509_set_proxy_pathlen_allownil)}
    X509_set_proxy_pathlen := ERR_X509_set_proxy_pathlen;
    {$ifend}
    {$if declared(X509_set_proxy_pathlen_introduced)}
    if LibVersion < X509_set_proxy_pathlen_introduced then
    begin
      {$if declared(FC_X509_set_proxy_pathlen)}
      X509_set_proxy_pathlen := FC_X509_set_proxy_pathlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_set_proxy_pathlen_removed)}
    if X509_set_proxy_pathlen_removed <= LibVersion then
    begin
      {$if declared(_X509_set_proxy_pathlen)}
      X509_set_proxy_pathlen := _X509_set_proxy_pathlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_set_proxy_pathlen_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_set_proxy_pathlen');
    {$ifend}
  end;
  
  X509_get_proxy_pathlen := LoadLibFunction(ADllHandle, X509_get_proxy_pathlen_procname);
  FuncLoadError := not assigned(X509_get_proxy_pathlen);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_proxy_pathlen_allownil)}
    X509_get_proxy_pathlen := ERR_X509_get_proxy_pathlen;
    {$ifend}
    {$if declared(X509_get_proxy_pathlen_introduced)}
    if LibVersion < X509_get_proxy_pathlen_introduced then
    begin
      {$if declared(FC_X509_get_proxy_pathlen)}
      X509_get_proxy_pathlen := FC_X509_get_proxy_pathlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_proxy_pathlen_removed)}
    if X509_get_proxy_pathlen_removed <= LibVersion then
    begin
      {$if declared(_X509_get_proxy_pathlen)}
      X509_get_proxy_pathlen := _X509_get_proxy_pathlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_proxy_pathlen_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_proxy_pathlen');
    {$ifend}
  end;
  
  X509_get_extension_flags := LoadLibFunction(ADllHandle, X509_get_extension_flags_procname);
  FuncLoadError := not assigned(X509_get_extension_flags);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_extension_flags_allownil)}
    X509_get_extension_flags := ERR_X509_get_extension_flags;
    {$ifend}
    {$if declared(X509_get_extension_flags_introduced)}
    if LibVersion < X509_get_extension_flags_introduced then
    begin
      {$if declared(FC_X509_get_extension_flags)}
      X509_get_extension_flags := FC_X509_get_extension_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_extension_flags_removed)}
    if X509_get_extension_flags_removed <= LibVersion then
    begin
      {$if declared(_X509_get_extension_flags)}
      X509_get_extension_flags := _X509_get_extension_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_extension_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_extension_flags');
    {$ifend}
  end;
  
  X509_get_key_usage := LoadLibFunction(ADllHandle, X509_get_key_usage_procname);
  FuncLoadError := not assigned(X509_get_key_usage);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_key_usage_allownil)}
    X509_get_key_usage := ERR_X509_get_key_usage;
    {$ifend}
    {$if declared(X509_get_key_usage_introduced)}
    if LibVersion < X509_get_key_usage_introduced then
    begin
      {$if declared(FC_X509_get_key_usage)}
      X509_get_key_usage := FC_X509_get_key_usage;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_key_usage_removed)}
    if X509_get_key_usage_removed <= LibVersion then
    begin
      {$if declared(_X509_get_key_usage)}
      X509_get_key_usage := _X509_get_key_usage;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_key_usage_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_key_usage');
    {$ifend}
  end;
  
  X509_get_extended_key_usage := LoadLibFunction(ADllHandle, X509_get_extended_key_usage_procname);
  FuncLoadError := not assigned(X509_get_extended_key_usage);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_extended_key_usage_allownil)}
    X509_get_extended_key_usage := ERR_X509_get_extended_key_usage;
    {$ifend}
    {$if declared(X509_get_extended_key_usage_introduced)}
    if LibVersion < X509_get_extended_key_usage_introduced then
    begin
      {$if declared(FC_X509_get_extended_key_usage)}
      X509_get_extended_key_usage := FC_X509_get_extended_key_usage;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_extended_key_usage_removed)}
    if X509_get_extended_key_usage_removed <= LibVersion then
    begin
      {$if declared(_X509_get_extended_key_usage)}
      X509_get_extended_key_usage := _X509_get_extended_key_usage;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_extended_key_usage_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_extended_key_usage');
    {$ifend}
  end;
  
  X509_get0_subject_key_id := LoadLibFunction(ADllHandle, X509_get0_subject_key_id_procname);
  FuncLoadError := not assigned(X509_get0_subject_key_id);
  if FuncLoadError then
  begin
    {$if not defined(X509_get0_subject_key_id_allownil)}
    X509_get0_subject_key_id := ERR_X509_get0_subject_key_id;
    {$ifend}
    {$if declared(X509_get0_subject_key_id_introduced)}
    if LibVersion < X509_get0_subject_key_id_introduced then
    begin
      {$if declared(FC_X509_get0_subject_key_id)}
      X509_get0_subject_key_id := FC_X509_get0_subject_key_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get0_subject_key_id_removed)}
    if X509_get0_subject_key_id_removed <= LibVersion then
    begin
      {$if declared(_X509_get0_subject_key_id)}
      X509_get0_subject_key_id := _X509_get0_subject_key_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get0_subject_key_id_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get0_subject_key_id');
    {$ifend}
  end;
  
  X509_get0_authority_key_id := LoadLibFunction(ADllHandle, X509_get0_authority_key_id_procname);
  FuncLoadError := not assigned(X509_get0_authority_key_id);
  if FuncLoadError then
  begin
    {$if not defined(X509_get0_authority_key_id_allownil)}
    X509_get0_authority_key_id := ERR_X509_get0_authority_key_id;
    {$ifend}
    {$if declared(X509_get0_authority_key_id_introduced)}
    if LibVersion < X509_get0_authority_key_id_introduced then
    begin
      {$if declared(FC_X509_get0_authority_key_id)}
      X509_get0_authority_key_id := FC_X509_get0_authority_key_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get0_authority_key_id_removed)}
    if X509_get0_authority_key_id_removed <= LibVersion then
    begin
      {$if declared(_X509_get0_authority_key_id)}
      X509_get0_authority_key_id := _X509_get0_authority_key_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get0_authority_key_id_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get0_authority_key_id');
    {$ifend}
  end;
  
  X509_get0_authority_issuer := LoadLibFunction(ADllHandle, X509_get0_authority_issuer_procname);
  FuncLoadError := not assigned(X509_get0_authority_issuer);
  if FuncLoadError then
  begin
    {$if not defined(X509_get0_authority_issuer_allownil)}
    X509_get0_authority_issuer := ERR_X509_get0_authority_issuer;
    {$ifend}
    {$if declared(X509_get0_authority_issuer_introduced)}
    if LibVersion < X509_get0_authority_issuer_introduced then
    begin
      {$if declared(FC_X509_get0_authority_issuer)}
      X509_get0_authority_issuer := FC_X509_get0_authority_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get0_authority_issuer_removed)}
    if X509_get0_authority_issuer_removed <= LibVersion then
    begin
      {$if declared(_X509_get0_authority_issuer)}
      X509_get0_authority_issuer := _X509_get0_authority_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get0_authority_issuer_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get0_authority_issuer');
    {$ifend}
  end;
  
  X509_get0_authority_serial := LoadLibFunction(ADllHandle, X509_get0_authority_serial_procname);
  FuncLoadError := not assigned(X509_get0_authority_serial);
  if FuncLoadError then
  begin
    {$if not defined(X509_get0_authority_serial_allownil)}
    X509_get0_authority_serial := ERR_X509_get0_authority_serial;
    {$ifend}
    {$if declared(X509_get0_authority_serial_introduced)}
    if LibVersion < X509_get0_authority_serial_introduced then
    begin
      {$if declared(FC_X509_get0_authority_serial)}
      X509_get0_authority_serial := FC_X509_get0_authority_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get0_authority_serial_removed)}
    if X509_get0_authority_serial_removed <= LibVersion then
    begin
      {$if declared(_X509_get0_authority_serial)}
      X509_get0_authority_serial := _X509_get0_authority_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get0_authority_serial_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get0_authority_serial');
    {$ifend}
  end;
  
  X509_PURPOSE_get_count := LoadLibFunction(ADllHandle, X509_PURPOSE_get_count_procname);
  FuncLoadError := not assigned(X509_PURPOSE_get_count);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_get_count_allownil)}
    X509_PURPOSE_get_count := ERR_X509_PURPOSE_get_count;
    {$ifend}
    {$if declared(X509_PURPOSE_get_count_introduced)}
    if LibVersion < X509_PURPOSE_get_count_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_get_count)}
      X509_PURPOSE_get_count := FC_X509_PURPOSE_get_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_get_count_removed)}
    if X509_PURPOSE_get_count_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_get_count)}
      X509_PURPOSE_get_count := _X509_PURPOSE_get_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_get_count_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_get_count');
    {$ifend}
  end;
  
  X509_PURPOSE_get_unused_id := LoadLibFunction(ADllHandle, X509_PURPOSE_get_unused_id_procname);
  FuncLoadError := not assigned(X509_PURPOSE_get_unused_id);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_get_unused_id_allownil)}
    X509_PURPOSE_get_unused_id := ERR_X509_PURPOSE_get_unused_id;
    {$ifend}
    {$if declared(X509_PURPOSE_get_unused_id_introduced)}
    if LibVersion < X509_PURPOSE_get_unused_id_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_get_unused_id)}
      X509_PURPOSE_get_unused_id := FC_X509_PURPOSE_get_unused_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_get_unused_id_removed)}
    if X509_PURPOSE_get_unused_id_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_get_unused_id)}
      X509_PURPOSE_get_unused_id := _X509_PURPOSE_get_unused_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_get_unused_id_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_get_unused_id');
    {$ifend}
  end;
  
  X509_PURPOSE_get_by_sname := LoadLibFunction(ADllHandle, X509_PURPOSE_get_by_sname_procname);
  FuncLoadError := not assigned(X509_PURPOSE_get_by_sname);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_get_by_sname_allownil)}
    X509_PURPOSE_get_by_sname := ERR_X509_PURPOSE_get_by_sname;
    {$ifend}
    {$if declared(X509_PURPOSE_get_by_sname_introduced)}
    if LibVersion < X509_PURPOSE_get_by_sname_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_get_by_sname)}
      X509_PURPOSE_get_by_sname := FC_X509_PURPOSE_get_by_sname;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_get_by_sname_removed)}
    if X509_PURPOSE_get_by_sname_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_get_by_sname)}
      X509_PURPOSE_get_by_sname := _X509_PURPOSE_get_by_sname;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_get_by_sname_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_get_by_sname');
    {$ifend}
  end;
  
  X509_PURPOSE_get_by_id := LoadLibFunction(ADllHandle, X509_PURPOSE_get_by_id_procname);
  FuncLoadError := not assigned(X509_PURPOSE_get_by_id);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_get_by_id_allownil)}
    X509_PURPOSE_get_by_id := ERR_X509_PURPOSE_get_by_id;
    {$ifend}
    {$if declared(X509_PURPOSE_get_by_id_introduced)}
    if LibVersion < X509_PURPOSE_get_by_id_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_get_by_id)}
      X509_PURPOSE_get_by_id := FC_X509_PURPOSE_get_by_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_get_by_id_removed)}
    if X509_PURPOSE_get_by_id_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_get_by_id)}
      X509_PURPOSE_get_by_id := _X509_PURPOSE_get_by_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_get_by_id_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_get_by_id');
    {$ifend}
  end;
  
  X509_PURPOSE_add := LoadLibFunction(ADllHandle, X509_PURPOSE_add_procname);
  FuncLoadError := not assigned(X509_PURPOSE_add);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_add_allownil)}
    X509_PURPOSE_add := ERR_X509_PURPOSE_add;
    {$ifend}
    {$if declared(X509_PURPOSE_add_introduced)}
    if LibVersion < X509_PURPOSE_add_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_add)}
      X509_PURPOSE_add := FC_X509_PURPOSE_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_add_removed)}
    if X509_PURPOSE_add_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_add)}
      X509_PURPOSE_add := _X509_PURPOSE_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_add_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_add');
    {$ifend}
  end;
  
  X509_PURPOSE_cleanup := LoadLibFunction(ADllHandle, X509_PURPOSE_cleanup_procname);
  FuncLoadError := not assigned(X509_PURPOSE_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_cleanup_allownil)}
    X509_PURPOSE_cleanup := ERR_X509_PURPOSE_cleanup;
    {$ifend}
    {$if declared(X509_PURPOSE_cleanup_introduced)}
    if LibVersion < X509_PURPOSE_cleanup_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_cleanup)}
      X509_PURPOSE_cleanup := FC_X509_PURPOSE_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_cleanup_removed)}
    if X509_PURPOSE_cleanup_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_cleanup)}
      X509_PURPOSE_cleanup := _X509_PURPOSE_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_cleanup');
    {$ifend}
  end;
  
  X509_PURPOSE_get0 := LoadLibFunction(ADllHandle, X509_PURPOSE_get0_procname);
  FuncLoadError := not assigned(X509_PURPOSE_get0);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_get0_allownil)}
    X509_PURPOSE_get0 := ERR_X509_PURPOSE_get0;
    {$ifend}
    {$if declared(X509_PURPOSE_get0_introduced)}
    if LibVersion < X509_PURPOSE_get0_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_get0)}
      X509_PURPOSE_get0 := FC_X509_PURPOSE_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_get0_removed)}
    if X509_PURPOSE_get0_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_get0)}
      X509_PURPOSE_get0 := _X509_PURPOSE_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_get0_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_get0');
    {$ifend}
  end;
  
  X509_PURPOSE_get_id := LoadLibFunction(ADllHandle, X509_PURPOSE_get_id_procname);
  FuncLoadError := not assigned(X509_PURPOSE_get_id);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_get_id_allownil)}
    X509_PURPOSE_get_id := ERR_X509_PURPOSE_get_id;
    {$ifend}
    {$if declared(X509_PURPOSE_get_id_introduced)}
    if LibVersion < X509_PURPOSE_get_id_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_get_id)}
      X509_PURPOSE_get_id := FC_X509_PURPOSE_get_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_get_id_removed)}
    if X509_PURPOSE_get_id_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_get_id)}
      X509_PURPOSE_get_id := _X509_PURPOSE_get_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_get_id_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_get_id');
    {$ifend}
  end;
  
  X509_PURPOSE_get0_name := LoadLibFunction(ADllHandle, X509_PURPOSE_get0_name_procname);
  FuncLoadError := not assigned(X509_PURPOSE_get0_name);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_get0_name_allownil)}
    X509_PURPOSE_get0_name := ERR_X509_PURPOSE_get0_name;
    {$ifend}
    {$if declared(X509_PURPOSE_get0_name_introduced)}
    if LibVersion < X509_PURPOSE_get0_name_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_get0_name)}
      X509_PURPOSE_get0_name := FC_X509_PURPOSE_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_get0_name_removed)}
    if X509_PURPOSE_get0_name_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_get0_name)}
      X509_PURPOSE_get0_name := _X509_PURPOSE_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_get0_name_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_get0_name');
    {$ifend}
  end;
  
  X509_PURPOSE_get0_sname := LoadLibFunction(ADllHandle, X509_PURPOSE_get0_sname_procname);
  FuncLoadError := not assigned(X509_PURPOSE_get0_sname);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_get0_sname_allownil)}
    X509_PURPOSE_get0_sname := ERR_X509_PURPOSE_get0_sname;
    {$ifend}
    {$if declared(X509_PURPOSE_get0_sname_introduced)}
    if LibVersion < X509_PURPOSE_get0_sname_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_get0_sname)}
      X509_PURPOSE_get0_sname := FC_X509_PURPOSE_get0_sname;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_get0_sname_removed)}
    if X509_PURPOSE_get0_sname_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_get0_sname)}
      X509_PURPOSE_get0_sname := _X509_PURPOSE_get0_sname;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_get0_sname_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_get0_sname');
    {$ifend}
  end;
  
  X509_PURPOSE_get_trust := LoadLibFunction(ADllHandle, X509_PURPOSE_get_trust_procname);
  FuncLoadError := not assigned(X509_PURPOSE_get_trust);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_get_trust_allownil)}
    X509_PURPOSE_get_trust := ERR_X509_PURPOSE_get_trust;
    {$ifend}
    {$if declared(X509_PURPOSE_get_trust_introduced)}
    if LibVersion < X509_PURPOSE_get_trust_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_get_trust)}
      X509_PURPOSE_get_trust := FC_X509_PURPOSE_get_trust;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_get_trust_removed)}
    if X509_PURPOSE_get_trust_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_get_trust)}
      X509_PURPOSE_get_trust := _X509_PURPOSE_get_trust;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_get_trust_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_get_trust');
    {$ifend}
  end;
  
  X509_PURPOSE_set := LoadLibFunction(ADllHandle, X509_PURPOSE_set_procname);
  FuncLoadError := not assigned(X509_PURPOSE_set);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_set_allownil)}
    X509_PURPOSE_set := ERR_X509_PURPOSE_set;
    {$ifend}
    {$if declared(X509_PURPOSE_set_introduced)}
    if LibVersion < X509_PURPOSE_set_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_set)}
      X509_PURPOSE_set := FC_X509_PURPOSE_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_set_removed)}
    if X509_PURPOSE_set_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_set)}
      X509_PURPOSE_set := _X509_PURPOSE_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_set_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_set');
    {$ifend}
  end;
  
  X509_get1_email := LoadLibFunction(ADllHandle, X509_get1_email_procname);
  FuncLoadError := not assigned(X509_get1_email);
  if FuncLoadError then
  begin
    {$if not defined(X509_get1_email_allownil)}
    X509_get1_email := ERR_X509_get1_email;
    {$ifend}
    {$if declared(X509_get1_email_introduced)}
    if LibVersion < X509_get1_email_introduced then
    begin
      {$if declared(FC_X509_get1_email)}
      X509_get1_email := FC_X509_get1_email;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get1_email_removed)}
    if X509_get1_email_removed <= LibVersion then
    begin
      {$if declared(_X509_get1_email)}
      X509_get1_email := _X509_get1_email;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get1_email_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get1_email');
    {$ifend}
  end;
  
  X509_REQ_get1_email := LoadLibFunction(ADllHandle, X509_REQ_get1_email_procname);
  FuncLoadError := not assigned(X509_REQ_get1_email);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_get1_email_allownil)}
    X509_REQ_get1_email := ERR_X509_REQ_get1_email;
    {$ifend}
    {$if declared(X509_REQ_get1_email_introduced)}
    if LibVersion < X509_REQ_get1_email_introduced then
    begin
      {$if declared(FC_X509_REQ_get1_email)}
      X509_REQ_get1_email := FC_X509_REQ_get1_email;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_get1_email_removed)}
    if X509_REQ_get1_email_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_get1_email)}
      X509_REQ_get1_email := _X509_REQ_get1_email;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_get1_email_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_get1_email');
    {$ifend}
  end;
  
  X509_email_free := LoadLibFunction(ADllHandle, X509_email_free_procname);
  FuncLoadError := not assigned(X509_email_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_email_free_allownil)}
    X509_email_free := ERR_X509_email_free;
    {$ifend}
    {$if declared(X509_email_free_introduced)}
    if LibVersion < X509_email_free_introduced then
    begin
      {$if declared(FC_X509_email_free)}
      X509_email_free := FC_X509_email_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_email_free_removed)}
    if X509_email_free_removed <= LibVersion then
    begin
      {$if declared(_X509_email_free)}
      X509_email_free := _X509_email_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_email_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_email_free');
    {$ifend}
  end;
  
  X509_get1_ocsp := LoadLibFunction(ADllHandle, X509_get1_ocsp_procname);
  FuncLoadError := not assigned(X509_get1_ocsp);
  if FuncLoadError then
  begin
    {$if not defined(X509_get1_ocsp_allownil)}
    X509_get1_ocsp := ERR_X509_get1_ocsp;
    {$ifend}
    {$if declared(X509_get1_ocsp_introduced)}
    if LibVersion < X509_get1_ocsp_introduced then
    begin
      {$if declared(FC_X509_get1_ocsp)}
      X509_get1_ocsp := FC_X509_get1_ocsp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get1_ocsp_removed)}
    if X509_get1_ocsp_removed <= LibVersion then
    begin
      {$if declared(_X509_get1_ocsp)}
      X509_get1_ocsp := _X509_get1_ocsp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get1_ocsp_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get1_ocsp');
    {$ifend}
  end;
  
  X509_check_host := LoadLibFunction(ADllHandle, X509_check_host_procname);
  FuncLoadError := not assigned(X509_check_host);
  if FuncLoadError then
  begin
    {$if not defined(X509_check_host_allownil)}
    X509_check_host := ERR_X509_check_host;
    {$ifend}
    {$if declared(X509_check_host_introduced)}
    if LibVersion < X509_check_host_introduced then
    begin
      {$if declared(FC_X509_check_host)}
      X509_check_host := FC_X509_check_host;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_check_host_removed)}
    if X509_check_host_removed <= LibVersion then
    begin
      {$if declared(_X509_check_host)}
      X509_check_host := _X509_check_host;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_check_host_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_check_host');
    {$ifend}
  end;
  
  X509_check_email := LoadLibFunction(ADllHandle, X509_check_email_procname);
  FuncLoadError := not assigned(X509_check_email);
  if FuncLoadError then
  begin
    {$if not defined(X509_check_email_allownil)}
    X509_check_email := ERR_X509_check_email;
    {$ifend}
    {$if declared(X509_check_email_introduced)}
    if LibVersion < X509_check_email_introduced then
    begin
      {$if declared(FC_X509_check_email)}
      X509_check_email := FC_X509_check_email;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_check_email_removed)}
    if X509_check_email_removed <= LibVersion then
    begin
      {$if declared(_X509_check_email)}
      X509_check_email := _X509_check_email;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_check_email_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_check_email');
    {$ifend}
  end;
  
  X509_check_ip := LoadLibFunction(ADllHandle, X509_check_ip_procname);
  FuncLoadError := not assigned(X509_check_ip);
  if FuncLoadError then
  begin
    {$if not defined(X509_check_ip_allownil)}
    X509_check_ip := ERR_X509_check_ip;
    {$ifend}
    {$if declared(X509_check_ip_introduced)}
    if LibVersion < X509_check_ip_introduced then
    begin
      {$if declared(FC_X509_check_ip)}
      X509_check_ip := FC_X509_check_ip;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_check_ip_removed)}
    if X509_check_ip_removed <= LibVersion then
    begin
      {$if declared(_X509_check_ip)}
      X509_check_ip := _X509_check_ip;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_check_ip_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_check_ip');
    {$ifend}
  end;
  
  X509_check_ip_asc := LoadLibFunction(ADllHandle, X509_check_ip_asc_procname);
  FuncLoadError := not assigned(X509_check_ip_asc);
  if FuncLoadError then
  begin
    {$if not defined(X509_check_ip_asc_allownil)}
    X509_check_ip_asc := ERR_X509_check_ip_asc;
    {$ifend}
    {$if declared(X509_check_ip_asc_introduced)}
    if LibVersion < X509_check_ip_asc_introduced then
    begin
      {$if declared(FC_X509_check_ip_asc)}
      X509_check_ip_asc := FC_X509_check_ip_asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_check_ip_asc_removed)}
    if X509_check_ip_asc_removed <= LibVersion then
    begin
      {$if declared(_X509_check_ip_asc)}
      X509_check_ip_asc := _X509_check_ip_asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_check_ip_asc_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_check_ip_asc');
    {$ifend}
  end;
  
  a2i_IPADDRESS := LoadLibFunction(ADllHandle, a2i_IPADDRESS_procname);
  FuncLoadError := not assigned(a2i_IPADDRESS);
  if FuncLoadError then
  begin
    {$if not defined(a2i_IPADDRESS_allownil)}
    a2i_IPADDRESS := ERR_a2i_IPADDRESS;
    {$ifend}
    {$if declared(a2i_IPADDRESS_introduced)}
    if LibVersion < a2i_IPADDRESS_introduced then
    begin
      {$if declared(FC_a2i_IPADDRESS)}
      a2i_IPADDRESS := FC_a2i_IPADDRESS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(a2i_IPADDRESS_removed)}
    if a2i_IPADDRESS_removed <= LibVersion then
    begin
      {$if declared(_a2i_IPADDRESS)}
      a2i_IPADDRESS := _a2i_IPADDRESS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(a2i_IPADDRESS_allownil)}
    if FuncLoadError then
      AFailed.Add('a2i_IPADDRESS');
    {$ifend}
  end;
  
  a2i_IPADDRESS_NC := LoadLibFunction(ADllHandle, a2i_IPADDRESS_NC_procname);
  FuncLoadError := not assigned(a2i_IPADDRESS_NC);
  if FuncLoadError then
  begin
    {$if not defined(a2i_IPADDRESS_NC_allownil)}
    a2i_IPADDRESS_NC := ERR_a2i_IPADDRESS_NC;
    {$ifend}
    {$if declared(a2i_IPADDRESS_NC_introduced)}
    if LibVersion < a2i_IPADDRESS_NC_introduced then
    begin
      {$if declared(FC_a2i_IPADDRESS_NC)}
      a2i_IPADDRESS_NC := FC_a2i_IPADDRESS_NC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(a2i_IPADDRESS_NC_removed)}
    if a2i_IPADDRESS_NC_removed <= LibVersion then
    begin
      {$if declared(_a2i_IPADDRESS_NC)}
      a2i_IPADDRESS_NC := _a2i_IPADDRESS_NC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(a2i_IPADDRESS_NC_allownil)}
    if FuncLoadError then
      AFailed.Add('a2i_IPADDRESS_NC');
    {$ifend}
  end;
  
  X509V3_NAME_from_section := LoadLibFunction(ADllHandle, X509V3_NAME_from_section_procname);
  FuncLoadError := not assigned(X509V3_NAME_from_section);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_NAME_from_section_allownil)}
    X509V3_NAME_from_section := ERR_X509V3_NAME_from_section;
    {$ifend}
    {$if declared(X509V3_NAME_from_section_introduced)}
    if LibVersion < X509V3_NAME_from_section_introduced then
    begin
      {$if declared(FC_X509V3_NAME_from_section)}
      X509V3_NAME_from_section := FC_X509V3_NAME_from_section;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_NAME_from_section_removed)}
    if X509V3_NAME_from_section_removed <= LibVersion then
    begin
      {$if declared(_X509V3_NAME_from_section)}
      X509V3_NAME_from_section := _X509V3_NAME_from_section;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_NAME_from_section_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_NAME_from_section');
    {$ifend}
  end;
  
  X509_POLICY_NODE_print := LoadLibFunction(ADllHandle, X509_POLICY_NODE_print_procname);
  FuncLoadError := not assigned(X509_POLICY_NODE_print);
  if FuncLoadError then
  begin
    {$if not defined(X509_POLICY_NODE_print_allownil)}
    X509_POLICY_NODE_print := ERR_X509_POLICY_NODE_print;
    {$ifend}
    {$if declared(X509_POLICY_NODE_print_introduced)}
    if LibVersion < X509_POLICY_NODE_print_introduced then
    begin
      {$if declared(FC_X509_POLICY_NODE_print)}
      X509_POLICY_NODE_print := FC_X509_POLICY_NODE_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_POLICY_NODE_print_removed)}
    if X509_POLICY_NODE_print_removed <= LibVersion then
    begin
      {$if declared(_X509_POLICY_NODE_print)}
      X509_POLICY_NODE_print := _X509_POLICY_NODE_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_POLICY_NODE_print_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_POLICY_NODE_print');
    {$ifend}
  end;
  
  ASRange_new := LoadLibFunction(ADllHandle, ASRange_new_procname);
  FuncLoadError := not assigned(ASRange_new);
  if FuncLoadError then
  begin
    {$if not defined(ASRange_new_allownil)}
    ASRange_new := ERR_ASRange_new;
    {$ifend}
    {$if declared(ASRange_new_introduced)}
    if LibVersion < ASRange_new_introduced then
    begin
      {$if declared(FC_ASRange_new)}
      ASRange_new := FC_ASRange_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASRange_new_removed)}
    if ASRange_new_removed <= LibVersion then
    begin
      {$if declared(_ASRange_new)}
      ASRange_new := _ASRange_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASRange_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASRange_new');
    {$ifend}
  end;
  
  ASRange_free := LoadLibFunction(ADllHandle, ASRange_free_procname);
  FuncLoadError := not assigned(ASRange_free);
  if FuncLoadError then
  begin
    {$if not defined(ASRange_free_allownil)}
    ASRange_free := ERR_ASRange_free;
    {$ifend}
    {$if declared(ASRange_free_introduced)}
    if LibVersion < ASRange_free_introduced then
    begin
      {$if declared(FC_ASRange_free)}
      ASRange_free := FC_ASRange_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASRange_free_removed)}
    if ASRange_free_removed <= LibVersion then
    begin
      {$if declared(_ASRange_free)}
      ASRange_free := _ASRange_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASRange_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASRange_free');
    {$ifend}
  end;
  
  d2i_ASRange := LoadLibFunction(ADllHandle, d2i_ASRange_procname);
  FuncLoadError := not assigned(d2i_ASRange);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ASRange_allownil)}
    d2i_ASRange := ERR_d2i_ASRange;
    {$ifend}
    {$if declared(d2i_ASRange_introduced)}
    if LibVersion < d2i_ASRange_introduced then
    begin
      {$if declared(FC_d2i_ASRange)}
      d2i_ASRange := FC_d2i_ASRange;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ASRange_removed)}
    if d2i_ASRange_removed <= LibVersion then
    begin
      {$if declared(_d2i_ASRange)}
      d2i_ASRange := _d2i_ASRange;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ASRange_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ASRange');
    {$ifend}
  end;
  
  i2d_ASRange := LoadLibFunction(ADllHandle, i2d_ASRange_procname);
  FuncLoadError := not assigned(i2d_ASRange);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ASRange_allownil)}
    i2d_ASRange := ERR_i2d_ASRange;
    {$ifend}
    {$if declared(i2d_ASRange_introduced)}
    if LibVersion < i2d_ASRange_introduced then
    begin
      {$if declared(FC_i2d_ASRange)}
      i2d_ASRange := FC_i2d_ASRange;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ASRange_removed)}
    if i2d_ASRange_removed <= LibVersion then
    begin
      {$if declared(_i2d_ASRange)}
      i2d_ASRange := _i2d_ASRange;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ASRange_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ASRange');
    {$ifend}
  end;
  
  ASRange_it := LoadLibFunction(ADllHandle, ASRange_it_procname);
  FuncLoadError := not assigned(ASRange_it);
  if FuncLoadError then
  begin
    {$if not defined(ASRange_it_allownil)}
    ASRange_it := ERR_ASRange_it;
    {$ifend}
    {$if declared(ASRange_it_introduced)}
    if LibVersion < ASRange_it_introduced then
    begin
      {$if declared(FC_ASRange_it)}
      ASRange_it := FC_ASRange_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASRange_it_removed)}
    if ASRange_it_removed <= LibVersion then
    begin
      {$if declared(_ASRange_it)}
      ASRange_it := _ASRange_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASRange_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASRange_it');
    {$ifend}
  end;
  
  ASIdOrRange_new := LoadLibFunction(ADllHandle, ASIdOrRange_new_procname);
  FuncLoadError := not assigned(ASIdOrRange_new);
  if FuncLoadError then
  begin
    {$if not defined(ASIdOrRange_new_allownil)}
    ASIdOrRange_new := ERR_ASIdOrRange_new;
    {$ifend}
    {$if declared(ASIdOrRange_new_introduced)}
    if LibVersion < ASIdOrRange_new_introduced then
    begin
      {$if declared(FC_ASIdOrRange_new)}
      ASIdOrRange_new := FC_ASIdOrRange_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASIdOrRange_new_removed)}
    if ASIdOrRange_new_removed <= LibVersion then
    begin
      {$if declared(_ASIdOrRange_new)}
      ASIdOrRange_new := _ASIdOrRange_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASIdOrRange_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASIdOrRange_new');
    {$ifend}
  end;
  
  ASIdOrRange_free := LoadLibFunction(ADllHandle, ASIdOrRange_free_procname);
  FuncLoadError := not assigned(ASIdOrRange_free);
  if FuncLoadError then
  begin
    {$if not defined(ASIdOrRange_free_allownil)}
    ASIdOrRange_free := ERR_ASIdOrRange_free;
    {$ifend}
    {$if declared(ASIdOrRange_free_introduced)}
    if LibVersion < ASIdOrRange_free_introduced then
    begin
      {$if declared(FC_ASIdOrRange_free)}
      ASIdOrRange_free := FC_ASIdOrRange_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASIdOrRange_free_removed)}
    if ASIdOrRange_free_removed <= LibVersion then
    begin
      {$if declared(_ASIdOrRange_free)}
      ASIdOrRange_free := _ASIdOrRange_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASIdOrRange_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASIdOrRange_free');
    {$ifend}
  end;
  
  d2i_ASIdOrRange := LoadLibFunction(ADllHandle, d2i_ASIdOrRange_procname);
  FuncLoadError := not assigned(d2i_ASIdOrRange);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ASIdOrRange_allownil)}
    d2i_ASIdOrRange := ERR_d2i_ASIdOrRange;
    {$ifend}
    {$if declared(d2i_ASIdOrRange_introduced)}
    if LibVersion < d2i_ASIdOrRange_introduced then
    begin
      {$if declared(FC_d2i_ASIdOrRange)}
      d2i_ASIdOrRange := FC_d2i_ASIdOrRange;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ASIdOrRange_removed)}
    if d2i_ASIdOrRange_removed <= LibVersion then
    begin
      {$if declared(_d2i_ASIdOrRange)}
      d2i_ASIdOrRange := _d2i_ASIdOrRange;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ASIdOrRange_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ASIdOrRange');
    {$ifend}
  end;
  
  i2d_ASIdOrRange := LoadLibFunction(ADllHandle, i2d_ASIdOrRange_procname);
  FuncLoadError := not assigned(i2d_ASIdOrRange);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ASIdOrRange_allownil)}
    i2d_ASIdOrRange := ERR_i2d_ASIdOrRange;
    {$ifend}
    {$if declared(i2d_ASIdOrRange_introduced)}
    if LibVersion < i2d_ASIdOrRange_introduced then
    begin
      {$if declared(FC_i2d_ASIdOrRange)}
      i2d_ASIdOrRange := FC_i2d_ASIdOrRange;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ASIdOrRange_removed)}
    if i2d_ASIdOrRange_removed <= LibVersion then
    begin
      {$if declared(_i2d_ASIdOrRange)}
      i2d_ASIdOrRange := _i2d_ASIdOrRange;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ASIdOrRange_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ASIdOrRange');
    {$ifend}
  end;
  
  ASIdOrRange_it := LoadLibFunction(ADllHandle, ASIdOrRange_it_procname);
  FuncLoadError := not assigned(ASIdOrRange_it);
  if FuncLoadError then
  begin
    {$if not defined(ASIdOrRange_it_allownil)}
    ASIdOrRange_it := ERR_ASIdOrRange_it;
    {$ifend}
    {$if declared(ASIdOrRange_it_introduced)}
    if LibVersion < ASIdOrRange_it_introduced then
    begin
      {$if declared(FC_ASIdOrRange_it)}
      ASIdOrRange_it := FC_ASIdOrRange_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASIdOrRange_it_removed)}
    if ASIdOrRange_it_removed <= LibVersion then
    begin
      {$if declared(_ASIdOrRange_it)}
      ASIdOrRange_it := _ASIdOrRange_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASIdOrRange_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASIdOrRange_it');
    {$ifend}
  end;
  
  ASIdentifierChoice_new := LoadLibFunction(ADllHandle, ASIdentifierChoice_new_procname);
  FuncLoadError := not assigned(ASIdentifierChoice_new);
  if FuncLoadError then
  begin
    {$if not defined(ASIdentifierChoice_new_allownil)}
    ASIdentifierChoice_new := ERR_ASIdentifierChoice_new;
    {$ifend}
    {$if declared(ASIdentifierChoice_new_introduced)}
    if LibVersion < ASIdentifierChoice_new_introduced then
    begin
      {$if declared(FC_ASIdentifierChoice_new)}
      ASIdentifierChoice_new := FC_ASIdentifierChoice_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASIdentifierChoice_new_removed)}
    if ASIdentifierChoice_new_removed <= LibVersion then
    begin
      {$if declared(_ASIdentifierChoice_new)}
      ASIdentifierChoice_new := _ASIdentifierChoice_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASIdentifierChoice_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASIdentifierChoice_new');
    {$ifend}
  end;
  
  ASIdentifierChoice_free := LoadLibFunction(ADllHandle, ASIdentifierChoice_free_procname);
  FuncLoadError := not assigned(ASIdentifierChoice_free);
  if FuncLoadError then
  begin
    {$if not defined(ASIdentifierChoice_free_allownil)}
    ASIdentifierChoice_free := ERR_ASIdentifierChoice_free;
    {$ifend}
    {$if declared(ASIdentifierChoice_free_introduced)}
    if LibVersion < ASIdentifierChoice_free_introduced then
    begin
      {$if declared(FC_ASIdentifierChoice_free)}
      ASIdentifierChoice_free := FC_ASIdentifierChoice_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASIdentifierChoice_free_removed)}
    if ASIdentifierChoice_free_removed <= LibVersion then
    begin
      {$if declared(_ASIdentifierChoice_free)}
      ASIdentifierChoice_free := _ASIdentifierChoice_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASIdentifierChoice_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASIdentifierChoice_free');
    {$ifend}
  end;
  
  d2i_ASIdentifierChoice := LoadLibFunction(ADllHandle, d2i_ASIdentifierChoice_procname);
  FuncLoadError := not assigned(d2i_ASIdentifierChoice);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ASIdentifierChoice_allownil)}
    d2i_ASIdentifierChoice := ERR_d2i_ASIdentifierChoice;
    {$ifend}
    {$if declared(d2i_ASIdentifierChoice_introduced)}
    if LibVersion < d2i_ASIdentifierChoice_introduced then
    begin
      {$if declared(FC_d2i_ASIdentifierChoice)}
      d2i_ASIdentifierChoice := FC_d2i_ASIdentifierChoice;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ASIdentifierChoice_removed)}
    if d2i_ASIdentifierChoice_removed <= LibVersion then
    begin
      {$if declared(_d2i_ASIdentifierChoice)}
      d2i_ASIdentifierChoice := _d2i_ASIdentifierChoice;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ASIdentifierChoice_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ASIdentifierChoice');
    {$ifend}
  end;
  
  i2d_ASIdentifierChoice := LoadLibFunction(ADllHandle, i2d_ASIdentifierChoice_procname);
  FuncLoadError := not assigned(i2d_ASIdentifierChoice);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ASIdentifierChoice_allownil)}
    i2d_ASIdentifierChoice := ERR_i2d_ASIdentifierChoice;
    {$ifend}
    {$if declared(i2d_ASIdentifierChoice_introduced)}
    if LibVersion < i2d_ASIdentifierChoice_introduced then
    begin
      {$if declared(FC_i2d_ASIdentifierChoice)}
      i2d_ASIdentifierChoice := FC_i2d_ASIdentifierChoice;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ASIdentifierChoice_removed)}
    if i2d_ASIdentifierChoice_removed <= LibVersion then
    begin
      {$if declared(_i2d_ASIdentifierChoice)}
      i2d_ASIdentifierChoice := _i2d_ASIdentifierChoice;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ASIdentifierChoice_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ASIdentifierChoice');
    {$ifend}
  end;
  
  ASIdentifierChoice_it := LoadLibFunction(ADllHandle, ASIdentifierChoice_it_procname);
  FuncLoadError := not assigned(ASIdentifierChoice_it);
  if FuncLoadError then
  begin
    {$if not defined(ASIdentifierChoice_it_allownil)}
    ASIdentifierChoice_it := ERR_ASIdentifierChoice_it;
    {$ifend}
    {$if declared(ASIdentifierChoice_it_introduced)}
    if LibVersion < ASIdentifierChoice_it_introduced then
    begin
      {$if declared(FC_ASIdentifierChoice_it)}
      ASIdentifierChoice_it := FC_ASIdentifierChoice_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASIdentifierChoice_it_removed)}
    if ASIdentifierChoice_it_removed <= LibVersion then
    begin
      {$if declared(_ASIdentifierChoice_it)}
      ASIdentifierChoice_it := _ASIdentifierChoice_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASIdentifierChoice_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASIdentifierChoice_it');
    {$ifend}
  end;
  
  ASIdentifiers_new := LoadLibFunction(ADllHandle, ASIdentifiers_new_procname);
  FuncLoadError := not assigned(ASIdentifiers_new);
  if FuncLoadError then
  begin
    {$if not defined(ASIdentifiers_new_allownil)}
    ASIdentifiers_new := ERR_ASIdentifiers_new;
    {$ifend}
    {$if declared(ASIdentifiers_new_introduced)}
    if LibVersion < ASIdentifiers_new_introduced then
    begin
      {$if declared(FC_ASIdentifiers_new)}
      ASIdentifiers_new := FC_ASIdentifiers_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASIdentifiers_new_removed)}
    if ASIdentifiers_new_removed <= LibVersion then
    begin
      {$if declared(_ASIdentifiers_new)}
      ASIdentifiers_new := _ASIdentifiers_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASIdentifiers_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASIdentifiers_new');
    {$ifend}
  end;
  
  ASIdentifiers_free := LoadLibFunction(ADllHandle, ASIdentifiers_free_procname);
  FuncLoadError := not assigned(ASIdentifiers_free);
  if FuncLoadError then
  begin
    {$if not defined(ASIdentifiers_free_allownil)}
    ASIdentifiers_free := ERR_ASIdentifiers_free;
    {$ifend}
    {$if declared(ASIdentifiers_free_introduced)}
    if LibVersion < ASIdentifiers_free_introduced then
    begin
      {$if declared(FC_ASIdentifiers_free)}
      ASIdentifiers_free := FC_ASIdentifiers_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASIdentifiers_free_removed)}
    if ASIdentifiers_free_removed <= LibVersion then
    begin
      {$if declared(_ASIdentifiers_free)}
      ASIdentifiers_free := _ASIdentifiers_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASIdentifiers_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASIdentifiers_free');
    {$ifend}
  end;
  
  d2i_ASIdentifiers := LoadLibFunction(ADllHandle, d2i_ASIdentifiers_procname);
  FuncLoadError := not assigned(d2i_ASIdentifiers);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ASIdentifiers_allownil)}
    d2i_ASIdentifiers := ERR_d2i_ASIdentifiers;
    {$ifend}
    {$if declared(d2i_ASIdentifiers_introduced)}
    if LibVersion < d2i_ASIdentifiers_introduced then
    begin
      {$if declared(FC_d2i_ASIdentifiers)}
      d2i_ASIdentifiers := FC_d2i_ASIdentifiers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ASIdentifiers_removed)}
    if d2i_ASIdentifiers_removed <= LibVersion then
    begin
      {$if declared(_d2i_ASIdentifiers)}
      d2i_ASIdentifiers := _d2i_ASIdentifiers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ASIdentifiers_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ASIdentifiers');
    {$ifend}
  end;
  
  i2d_ASIdentifiers := LoadLibFunction(ADllHandle, i2d_ASIdentifiers_procname);
  FuncLoadError := not assigned(i2d_ASIdentifiers);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ASIdentifiers_allownil)}
    i2d_ASIdentifiers := ERR_i2d_ASIdentifiers;
    {$ifend}
    {$if declared(i2d_ASIdentifiers_introduced)}
    if LibVersion < i2d_ASIdentifiers_introduced then
    begin
      {$if declared(FC_i2d_ASIdentifiers)}
      i2d_ASIdentifiers := FC_i2d_ASIdentifiers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ASIdentifiers_removed)}
    if i2d_ASIdentifiers_removed <= LibVersion then
    begin
      {$if declared(_i2d_ASIdentifiers)}
      i2d_ASIdentifiers := _i2d_ASIdentifiers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ASIdentifiers_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ASIdentifiers');
    {$ifend}
  end;
  
  ASIdentifiers_it := LoadLibFunction(ADllHandle, ASIdentifiers_it_procname);
  FuncLoadError := not assigned(ASIdentifiers_it);
  if FuncLoadError then
  begin
    {$if not defined(ASIdentifiers_it_allownil)}
    ASIdentifiers_it := ERR_ASIdentifiers_it;
    {$ifend}
    {$if declared(ASIdentifiers_it_introduced)}
    if LibVersion < ASIdentifiers_it_introduced then
    begin
      {$if declared(FC_ASIdentifiers_it)}
      ASIdentifiers_it := FC_ASIdentifiers_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASIdentifiers_it_removed)}
    if ASIdentifiers_it_removed <= LibVersion then
    begin
      {$if declared(_ASIdentifiers_it)}
      ASIdentifiers_it := _ASIdentifiers_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASIdentifiers_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASIdentifiers_it');
    {$ifend}
  end;
  
  IPAddressRange_new := LoadLibFunction(ADllHandle, IPAddressRange_new_procname);
  FuncLoadError := not assigned(IPAddressRange_new);
  if FuncLoadError then
  begin
    {$if not defined(IPAddressRange_new_allownil)}
    IPAddressRange_new := ERR_IPAddressRange_new;
    {$ifend}
    {$if declared(IPAddressRange_new_introduced)}
    if LibVersion < IPAddressRange_new_introduced then
    begin
      {$if declared(FC_IPAddressRange_new)}
      IPAddressRange_new := FC_IPAddressRange_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(IPAddressRange_new_removed)}
    if IPAddressRange_new_removed <= LibVersion then
    begin
      {$if declared(_IPAddressRange_new)}
      IPAddressRange_new := _IPAddressRange_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(IPAddressRange_new_allownil)}
    if FuncLoadError then
      AFailed.Add('IPAddressRange_new');
    {$ifend}
  end;
  
  IPAddressRange_free := LoadLibFunction(ADllHandle, IPAddressRange_free_procname);
  FuncLoadError := not assigned(IPAddressRange_free);
  if FuncLoadError then
  begin
    {$if not defined(IPAddressRange_free_allownil)}
    IPAddressRange_free := ERR_IPAddressRange_free;
    {$ifend}
    {$if declared(IPAddressRange_free_introduced)}
    if LibVersion < IPAddressRange_free_introduced then
    begin
      {$if declared(FC_IPAddressRange_free)}
      IPAddressRange_free := FC_IPAddressRange_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(IPAddressRange_free_removed)}
    if IPAddressRange_free_removed <= LibVersion then
    begin
      {$if declared(_IPAddressRange_free)}
      IPAddressRange_free := _IPAddressRange_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(IPAddressRange_free_allownil)}
    if FuncLoadError then
      AFailed.Add('IPAddressRange_free');
    {$ifend}
  end;
  
  d2i_IPAddressRange := LoadLibFunction(ADllHandle, d2i_IPAddressRange_procname);
  FuncLoadError := not assigned(d2i_IPAddressRange);
  if FuncLoadError then
  begin
    {$if not defined(d2i_IPAddressRange_allownil)}
    d2i_IPAddressRange := ERR_d2i_IPAddressRange;
    {$ifend}
    {$if declared(d2i_IPAddressRange_introduced)}
    if LibVersion < d2i_IPAddressRange_introduced then
    begin
      {$if declared(FC_d2i_IPAddressRange)}
      d2i_IPAddressRange := FC_d2i_IPAddressRange;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_IPAddressRange_removed)}
    if d2i_IPAddressRange_removed <= LibVersion then
    begin
      {$if declared(_d2i_IPAddressRange)}
      d2i_IPAddressRange := _d2i_IPAddressRange;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_IPAddressRange_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_IPAddressRange');
    {$ifend}
  end;
  
  i2d_IPAddressRange := LoadLibFunction(ADllHandle, i2d_IPAddressRange_procname);
  FuncLoadError := not assigned(i2d_IPAddressRange);
  if FuncLoadError then
  begin
    {$if not defined(i2d_IPAddressRange_allownil)}
    i2d_IPAddressRange := ERR_i2d_IPAddressRange;
    {$ifend}
    {$if declared(i2d_IPAddressRange_introduced)}
    if LibVersion < i2d_IPAddressRange_introduced then
    begin
      {$if declared(FC_i2d_IPAddressRange)}
      i2d_IPAddressRange := FC_i2d_IPAddressRange;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_IPAddressRange_removed)}
    if i2d_IPAddressRange_removed <= LibVersion then
    begin
      {$if declared(_i2d_IPAddressRange)}
      i2d_IPAddressRange := _i2d_IPAddressRange;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_IPAddressRange_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_IPAddressRange');
    {$ifend}
  end;
  
  IPAddressRange_it := LoadLibFunction(ADllHandle, IPAddressRange_it_procname);
  FuncLoadError := not assigned(IPAddressRange_it);
  if FuncLoadError then
  begin
    {$if not defined(IPAddressRange_it_allownil)}
    IPAddressRange_it := ERR_IPAddressRange_it;
    {$ifend}
    {$if declared(IPAddressRange_it_introduced)}
    if LibVersion < IPAddressRange_it_introduced then
    begin
      {$if declared(FC_IPAddressRange_it)}
      IPAddressRange_it := FC_IPAddressRange_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(IPAddressRange_it_removed)}
    if IPAddressRange_it_removed <= LibVersion then
    begin
      {$if declared(_IPAddressRange_it)}
      IPAddressRange_it := _IPAddressRange_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(IPAddressRange_it_allownil)}
    if FuncLoadError then
      AFailed.Add('IPAddressRange_it');
    {$ifend}
  end;
  
  IPAddressOrRange_new := LoadLibFunction(ADllHandle, IPAddressOrRange_new_procname);
  FuncLoadError := not assigned(IPAddressOrRange_new);
  if FuncLoadError then
  begin
    {$if not defined(IPAddressOrRange_new_allownil)}
    IPAddressOrRange_new := ERR_IPAddressOrRange_new;
    {$ifend}
    {$if declared(IPAddressOrRange_new_introduced)}
    if LibVersion < IPAddressOrRange_new_introduced then
    begin
      {$if declared(FC_IPAddressOrRange_new)}
      IPAddressOrRange_new := FC_IPAddressOrRange_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(IPAddressOrRange_new_removed)}
    if IPAddressOrRange_new_removed <= LibVersion then
    begin
      {$if declared(_IPAddressOrRange_new)}
      IPAddressOrRange_new := _IPAddressOrRange_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(IPAddressOrRange_new_allownil)}
    if FuncLoadError then
      AFailed.Add('IPAddressOrRange_new');
    {$ifend}
  end;
  
  IPAddressOrRange_free := LoadLibFunction(ADllHandle, IPAddressOrRange_free_procname);
  FuncLoadError := not assigned(IPAddressOrRange_free);
  if FuncLoadError then
  begin
    {$if not defined(IPAddressOrRange_free_allownil)}
    IPAddressOrRange_free := ERR_IPAddressOrRange_free;
    {$ifend}
    {$if declared(IPAddressOrRange_free_introduced)}
    if LibVersion < IPAddressOrRange_free_introduced then
    begin
      {$if declared(FC_IPAddressOrRange_free)}
      IPAddressOrRange_free := FC_IPAddressOrRange_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(IPAddressOrRange_free_removed)}
    if IPAddressOrRange_free_removed <= LibVersion then
    begin
      {$if declared(_IPAddressOrRange_free)}
      IPAddressOrRange_free := _IPAddressOrRange_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(IPAddressOrRange_free_allownil)}
    if FuncLoadError then
      AFailed.Add('IPAddressOrRange_free');
    {$ifend}
  end;
  
  d2i_IPAddressOrRange := LoadLibFunction(ADllHandle, d2i_IPAddressOrRange_procname);
  FuncLoadError := not assigned(d2i_IPAddressOrRange);
  if FuncLoadError then
  begin
    {$if not defined(d2i_IPAddressOrRange_allownil)}
    d2i_IPAddressOrRange := ERR_d2i_IPAddressOrRange;
    {$ifend}
    {$if declared(d2i_IPAddressOrRange_introduced)}
    if LibVersion < d2i_IPAddressOrRange_introduced then
    begin
      {$if declared(FC_d2i_IPAddressOrRange)}
      d2i_IPAddressOrRange := FC_d2i_IPAddressOrRange;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_IPAddressOrRange_removed)}
    if d2i_IPAddressOrRange_removed <= LibVersion then
    begin
      {$if declared(_d2i_IPAddressOrRange)}
      d2i_IPAddressOrRange := _d2i_IPAddressOrRange;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_IPAddressOrRange_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_IPAddressOrRange');
    {$ifend}
  end;
  
  i2d_IPAddressOrRange := LoadLibFunction(ADllHandle, i2d_IPAddressOrRange_procname);
  FuncLoadError := not assigned(i2d_IPAddressOrRange);
  if FuncLoadError then
  begin
    {$if not defined(i2d_IPAddressOrRange_allownil)}
    i2d_IPAddressOrRange := ERR_i2d_IPAddressOrRange;
    {$ifend}
    {$if declared(i2d_IPAddressOrRange_introduced)}
    if LibVersion < i2d_IPAddressOrRange_introduced then
    begin
      {$if declared(FC_i2d_IPAddressOrRange)}
      i2d_IPAddressOrRange := FC_i2d_IPAddressOrRange;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_IPAddressOrRange_removed)}
    if i2d_IPAddressOrRange_removed <= LibVersion then
    begin
      {$if declared(_i2d_IPAddressOrRange)}
      i2d_IPAddressOrRange := _i2d_IPAddressOrRange;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_IPAddressOrRange_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_IPAddressOrRange');
    {$ifend}
  end;
  
  IPAddressOrRange_it := LoadLibFunction(ADllHandle, IPAddressOrRange_it_procname);
  FuncLoadError := not assigned(IPAddressOrRange_it);
  if FuncLoadError then
  begin
    {$if not defined(IPAddressOrRange_it_allownil)}
    IPAddressOrRange_it := ERR_IPAddressOrRange_it;
    {$ifend}
    {$if declared(IPAddressOrRange_it_introduced)}
    if LibVersion < IPAddressOrRange_it_introduced then
    begin
      {$if declared(FC_IPAddressOrRange_it)}
      IPAddressOrRange_it := FC_IPAddressOrRange_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(IPAddressOrRange_it_removed)}
    if IPAddressOrRange_it_removed <= LibVersion then
    begin
      {$if declared(_IPAddressOrRange_it)}
      IPAddressOrRange_it := _IPAddressOrRange_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(IPAddressOrRange_it_allownil)}
    if FuncLoadError then
      AFailed.Add('IPAddressOrRange_it');
    {$ifend}
  end;
  
  IPAddressChoice_new := LoadLibFunction(ADllHandle, IPAddressChoice_new_procname);
  FuncLoadError := not assigned(IPAddressChoice_new);
  if FuncLoadError then
  begin
    {$if not defined(IPAddressChoice_new_allownil)}
    IPAddressChoice_new := ERR_IPAddressChoice_new;
    {$ifend}
    {$if declared(IPAddressChoice_new_introduced)}
    if LibVersion < IPAddressChoice_new_introduced then
    begin
      {$if declared(FC_IPAddressChoice_new)}
      IPAddressChoice_new := FC_IPAddressChoice_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(IPAddressChoice_new_removed)}
    if IPAddressChoice_new_removed <= LibVersion then
    begin
      {$if declared(_IPAddressChoice_new)}
      IPAddressChoice_new := _IPAddressChoice_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(IPAddressChoice_new_allownil)}
    if FuncLoadError then
      AFailed.Add('IPAddressChoice_new');
    {$ifend}
  end;
  
  IPAddressChoice_free := LoadLibFunction(ADllHandle, IPAddressChoice_free_procname);
  FuncLoadError := not assigned(IPAddressChoice_free);
  if FuncLoadError then
  begin
    {$if not defined(IPAddressChoice_free_allownil)}
    IPAddressChoice_free := ERR_IPAddressChoice_free;
    {$ifend}
    {$if declared(IPAddressChoice_free_introduced)}
    if LibVersion < IPAddressChoice_free_introduced then
    begin
      {$if declared(FC_IPAddressChoice_free)}
      IPAddressChoice_free := FC_IPAddressChoice_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(IPAddressChoice_free_removed)}
    if IPAddressChoice_free_removed <= LibVersion then
    begin
      {$if declared(_IPAddressChoice_free)}
      IPAddressChoice_free := _IPAddressChoice_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(IPAddressChoice_free_allownil)}
    if FuncLoadError then
      AFailed.Add('IPAddressChoice_free');
    {$ifend}
  end;
  
  d2i_IPAddressChoice := LoadLibFunction(ADllHandle, d2i_IPAddressChoice_procname);
  FuncLoadError := not assigned(d2i_IPAddressChoice);
  if FuncLoadError then
  begin
    {$if not defined(d2i_IPAddressChoice_allownil)}
    d2i_IPAddressChoice := ERR_d2i_IPAddressChoice;
    {$ifend}
    {$if declared(d2i_IPAddressChoice_introduced)}
    if LibVersion < d2i_IPAddressChoice_introduced then
    begin
      {$if declared(FC_d2i_IPAddressChoice)}
      d2i_IPAddressChoice := FC_d2i_IPAddressChoice;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_IPAddressChoice_removed)}
    if d2i_IPAddressChoice_removed <= LibVersion then
    begin
      {$if declared(_d2i_IPAddressChoice)}
      d2i_IPAddressChoice := _d2i_IPAddressChoice;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_IPAddressChoice_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_IPAddressChoice');
    {$ifend}
  end;
  
  i2d_IPAddressChoice := LoadLibFunction(ADllHandle, i2d_IPAddressChoice_procname);
  FuncLoadError := not assigned(i2d_IPAddressChoice);
  if FuncLoadError then
  begin
    {$if not defined(i2d_IPAddressChoice_allownil)}
    i2d_IPAddressChoice := ERR_i2d_IPAddressChoice;
    {$ifend}
    {$if declared(i2d_IPAddressChoice_introduced)}
    if LibVersion < i2d_IPAddressChoice_introduced then
    begin
      {$if declared(FC_i2d_IPAddressChoice)}
      i2d_IPAddressChoice := FC_i2d_IPAddressChoice;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_IPAddressChoice_removed)}
    if i2d_IPAddressChoice_removed <= LibVersion then
    begin
      {$if declared(_i2d_IPAddressChoice)}
      i2d_IPAddressChoice := _i2d_IPAddressChoice;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_IPAddressChoice_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_IPAddressChoice');
    {$ifend}
  end;
  
  IPAddressChoice_it := LoadLibFunction(ADllHandle, IPAddressChoice_it_procname);
  FuncLoadError := not assigned(IPAddressChoice_it);
  if FuncLoadError then
  begin
    {$if not defined(IPAddressChoice_it_allownil)}
    IPAddressChoice_it := ERR_IPAddressChoice_it;
    {$ifend}
    {$if declared(IPAddressChoice_it_introduced)}
    if LibVersion < IPAddressChoice_it_introduced then
    begin
      {$if declared(FC_IPAddressChoice_it)}
      IPAddressChoice_it := FC_IPAddressChoice_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(IPAddressChoice_it_removed)}
    if IPAddressChoice_it_removed <= LibVersion then
    begin
      {$if declared(_IPAddressChoice_it)}
      IPAddressChoice_it := _IPAddressChoice_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(IPAddressChoice_it_allownil)}
    if FuncLoadError then
      AFailed.Add('IPAddressChoice_it');
    {$ifend}
  end;
  
  IPAddressFamily_new := LoadLibFunction(ADllHandle, IPAddressFamily_new_procname);
  FuncLoadError := not assigned(IPAddressFamily_new);
  if FuncLoadError then
  begin
    {$if not defined(IPAddressFamily_new_allownil)}
    IPAddressFamily_new := ERR_IPAddressFamily_new;
    {$ifend}
    {$if declared(IPAddressFamily_new_introduced)}
    if LibVersion < IPAddressFamily_new_introduced then
    begin
      {$if declared(FC_IPAddressFamily_new)}
      IPAddressFamily_new := FC_IPAddressFamily_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(IPAddressFamily_new_removed)}
    if IPAddressFamily_new_removed <= LibVersion then
    begin
      {$if declared(_IPAddressFamily_new)}
      IPAddressFamily_new := _IPAddressFamily_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(IPAddressFamily_new_allownil)}
    if FuncLoadError then
      AFailed.Add('IPAddressFamily_new');
    {$ifend}
  end;
  
  IPAddressFamily_free := LoadLibFunction(ADllHandle, IPAddressFamily_free_procname);
  FuncLoadError := not assigned(IPAddressFamily_free);
  if FuncLoadError then
  begin
    {$if not defined(IPAddressFamily_free_allownil)}
    IPAddressFamily_free := ERR_IPAddressFamily_free;
    {$ifend}
    {$if declared(IPAddressFamily_free_introduced)}
    if LibVersion < IPAddressFamily_free_introduced then
    begin
      {$if declared(FC_IPAddressFamily_free)}
      IPAddressFamily_free := FC_IPAddressFamily_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(IPAddressFamily_free_removed)}
    if IPAddressFamily_free_removed <= LibVersion then
    begin
      {$if declared(_IPAddressFamily_free)}
      IPAddressFamily_free := _IPAddressFamily_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(IPAddressFamily_free_allownil)}
    if FuncLoadError then
      AFailed.Add('IPAddressFamily_free');
    {$ifend}
  end;
  
  d2i_IPAddressFamily := LoadLibFunction(ADllHandle, d2i_IPAddressFamily_procname);
  FuncLoadError := not assigned(d2i_IPAddressFamily);
  if FuncLoadError then
  begin
    {$if not defined(d2i_IPAddressFamily_allownil)}
    d2i_IPAddressFamily := ERR_d2i_IPAddressFamily;
    {$ifend}
    {$if declared(d2i_IPAddressFamily_introduced)}
    if LibVersion < d2i_IPAddressFamily_introduced then
    begin
      {$if declared(FC_d2i_IPAddressFamily)}
      d2i_IPAddressFamily := FC_d2i_IPAddressFamily;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_IPAddressFamily_removed)}
    if d2i_IPAddressFamily_removed <= LibVersion then
    begin
      {$if declared(_d2i_IPAddressFamily)}
      d2i_IPAddressFamily := _d2i_IPAddressFamily;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_IPAddressFamily_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_IPAddressFamily');
    {$ifend}
  end;
  
  i2d_IPAddressFamily := LoadLibFunction(ADllHandle, i2d_IPAddressFamily_procname);
  FuncLoadError := not assigned(i2d_IPAddressFamily);
  if FuncLoadError then
  begin
    {$if not defined(i2d_IPAddressFamily_allownil)}
    i2d_IPAddressFamily := ERR_i2d_IPAddressFamily;
    {$ifend}
    {$if declared(i2d_IPAddressFamily_introduced)}
    if LibVersion < i2d_IPAddressFamily_introduced then
    begin
      {$if declared(FC_i2d_IPAddressFamily)}
      i2d_IPAddressFamily := FC_i2d_IPAddressFamily;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_IPAddressFamily_removed)}
    if i2d_IPAddressFamily_removed <= LibVersion then
    begin
      {$if declared(_i2d_IPAddressFamily)}
      i2d_IPAddressFamily := _i2d_IPAddressFamily;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_IPAddressFamily_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_IPAddressFamily');
    {$ifend}
  end;
  
  IPAddressFamily_it := LoadLibFunction(ADllHandle, IPAddressFamily_it_procname);
  FuncLoadError := not assigned(IPAddressFamily_it);
  if FuncLoadError then
  begin
    {$if not defined(IPAddressFamily_it_allownil)}
    IPAddressFamily_it := ERR_IPAddressFamily_it;
    {$ifend}
    {$if declared(IPAddressFamily_it_introduced)}
    if LibVersion < IPAddressFamily_it_introduced then
    begin
      {$if declared(FC_IPAddressFamily_it)}
      IPAddressFamily_it := FC_IPAddressFamily_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(IPAddressFamily_it_removed)}
    if IPAddressFamily_it_removed <= LibVersion then
    begin
      {$if declared(_IPAddressFamily_it)}
      IPAddressFamily_it := _IPAddressFamily_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(IPAddressFamily_it_allownil)}
    if FuncLoadError then
      AFailed.Add('IPAddressFamily_it');
    {$ifend}
  end;
  
  X509v3_asid_add_inherit := LoadLibFunction(ADllHandle, X509v3_asid_add_inherit_procname);
  FuncLoadError := not assigned(X509v3_asid_add_inherit);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_asid_add_inherit_allownil)}
    X509v3_asid_add_inherit := ERR_X509v3_asid_add_inherit;
    {$ifend}
    {$if declared(X509v3_asid_add_inherit_introduced)}
    if LibVersion < X509v3_asid_add_inherit_introduced then
    begin
      {$if declared(FC_X509v3_asid_add_inherit)}
      X509v3_asid_add_inherit := FC_X509v3_asid_add_inherit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_asid_add_inherit_removed)}
    if X509v3_asid_add_inherit_removed <= LibVersion then
    begin
      {$if declared(_X509v3_asid_add_inherit)}
      X509v3_asid_add_inherit := _X509v3_asid_add_inherit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_asid_add_inherit_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_asid_add_inherit');
    {$ifend}
  end;
  
  X509v3_asid_add_id_or_range := LoadLibFunction(ADllHandle, X509v3_asid_add_id_or_range_procname);
  FuncLoadError := not assigned(X509v3_asid_add_id_or_range);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_asid_add_id_or_range_allownil)}
    X509v3_asid_add_id_or_range := ERR_X509v3_asid_add_id_or_range;
    {$ifend}
    {$if declared(X509v3_asid_add_id_or_range_introduced)}
    if LibVersion < X509v3_asid_add_id_or_range_introduced then
    begin
      {$if declared(FC_X509v3_asid_add_id_or_range)}
      X509v3_asid_add_id_or_range := FC_X509v3_asid_add_id_or_range;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_asid_add_id_or_range_removed)}
    if X509v3_asid_add_id_or_range_removed <= LibVersion then
    begin
      {$if declared(_X509v3_asid_add_id_or_range)}
      X509v3_asid_add_id_or_range := _X509v3_asid_add_id_or_range;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_asid_add_id_or_range_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_asid_add_id_or_range');
    {$ifend}
  end;
  
  X509v3_addr_add_inherit := LoadLibFunction(ADllHandle, X509v3_addr_add_inherit_procname);
  FuncLoadError := not assigned(X509v3_addr_add_inherit);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_addr_add_inherit_allownil)}
    X509v3_addr_add_inherit := ERR_X509v3_addr_add_inherit;
    {$ifend}
    {$if declared(X509v3_addr_add_inherit_introduced)}
    if LibVersion < X509v3_addr_add_inherit_introduced then
    begin
      {$if declared(FC_X509v3_addr_add_inherit)}
      X509v3_addr_add_inherit := FC_X509v3_addr_add_inherit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_addr_add_inherit_removed)}
    if X509v3_addr_add_inherit_removed <= LibVersion then
    begin
      {$if declared(_X509v3_addr_add_inherit)}
      X509v3_addr_add_inherit := _X509v3_addr_add_inherit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_addr_add_inherit_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_addr_add_inherit');
    {$ifend}
  end;
  
  X509v3_addr_add_prefix := LoadLibFunction(ADllHandle, X509v3_addr_add_prefix_procname);
  FuncLoadError := not assigned(X509v3_addr_add_prefix);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_addr_add_prefix_allownil)}
    X509v3_addr_add_prefix := ERR_X509v3_addr_add_prefix;
    {$ifend}
    {$if declared(X509v3_addr_add_prefix_introduced)}
    if LibVersion < X509v3_addr_add_prefix_introduced then
    begin
      {$if declared(FC_X509v3_addr_add_prefix)}
      X509v3_addr_add_prefix := FC_X509v3_addr_add_prefix;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_addr_add_prefix_removed)}
    if X509v3_addr_add_prefix_removed <= LibVersion then
    begin
      {$if declared(_X509v3_addr_add_prefix)}
      X509v3_addr_add_prefix := _X509v3_addr_add_prefix;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_addr_add_prefix_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_addr_add_prefix');
    {$ifend}
  end;
  
  X509v3_addr_add_range := LoadLibFunction(ADllHandle, X509v3_addr_add_range_procname);
  FuncLoadError := not assigned(X509v3_addr_add_range);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_addr_add_range_allownil)}
    X509v3_addr_add_range := ERR_X509v3_addr_add_range;
    {$ifend}
    {$if declared(X509v3_addr_add_range_introduced)}
    if LibVersion < X509v3_addr_add_range_introduced then
    begin
      {$if declared(FC_X509v3_addr_add_range)}
      X509v3_addr_add_range := FC_X509v3_addr_add_range;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_addr_add_range_removed)}
    if X509v3_addr_add_range_removed <= LibVersion then
    begin
      {$if declared(_X509v3_addr_add_range)}
      X509v3_addr_add_range := _X509v3_addr_add_range;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_addr_add_range_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_addr_add_range');
    {$ifend}
  end;
  
  X509v3_addr_get_afi := LoadLibFunction(ADllHandle, X509v3_addr_get_afi_procname);
  FuncLoadError := not assigned(X509v3_addr_get_afi);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_addr_get_afi_allownil)}
    X509v3_addr_get_afi := ERR_X509v3_addr_get_afi;
    {$ifend}
    {$if declared(X509v3_addr_get_afi_introduced)}
    if LibVersion < X509v3_addr_get_afi_introduced then
    begin
      {$if declared(FC_X509v3_addr_get_afi)}
      X509v3_addr_get_afi := FC_X509v3_addr_get_afi;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_addr_get_afi_removed)}
    if X509v3_addr_get_afi_removed <= LibVersion then
    begin
      {$if declared(_X509v3_addr_get_afi)}
      X509v3_addr_get_afi := _X509v3_addr_get_afi;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_addr_get_afi_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_addr_get_afi');
    {$ifend}
  end;
  
  X509v3_addr_get_range := LoadLibFunction(ADllHandle, X509v3_addr_get_range_procname);
  FuncLoadError := not assigned(X509v3_addr_get_range);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_addr_get_range_allownil)}
    X509v3_addr_get_range := ERR_X509v3_addr_get_range;
    {$ifend}
    {$if declared(X509v3_addr_get_range_introduced)}
    if LibVersion < X509v3_addr_get_range_introduced then
    begin
      {$if declared(FC_X509v3_addr_get_range)}
      X509v3_addr_get_range := FC_X509v3_addr_get_range;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_addr_get_range_removed)}
    if X509v3_addr_get_range_removed <= LibVersion then
    begin
      {$if declared(_X509v3_addr_get_range)}
      X509v3_addr_get_range := _X509v3_addr_get_range;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_addr_get_range_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_addr_get_range');
    {$ifend}
  end;
  
  X509v3_asid_is_canonical := LoadLibFunction(ADllHandle, X509v3_asid_is_canonical_procname);
  FuncLoadError := not assigned(X509v3_asid_is_canonical);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_asid_is_canonical_allownil)}
    X509v3_asid_is_canonical := ERR_X509v3_asid_is_canonical;
    {$ifend}
    {$if declared(X509v3_asid_is_canonical_introduced)}
    if LibVersion < X509v3_asid_is_canonical_introduced then
    begin
      {$if declared(FC_X509v3_asid_is_canonical)}
      X509v3_asid_is_canonical := FC_X509v3_asid_is_canonical;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_asid_is_canonical_removed)}
    if X509v3_asid_is_canonical_removed <= LibVersion then
    begin
      {$if declared(_X509v3_asid_is_canonical)}
      X509v3_asid_is_canonical := _X509v3_asid_is_canonical;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_asid_is_canonical_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_asid_is_canonical');
    {$ifend}
  end;
  
  X509v3_addr_is_canonical := LoadLibFunction(ADllHandle, X509v3_addr_is_canonical_procname);
  FuncLoadError := not assigned(X509v3_addr_is_canonical);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_addr_is_canonical_allownil)}
    X509v3_addr_is_canonical := ERR_X509v3_addr_is_canonical;
    {$ifend}
    {$if declared(X509v3_addr_is_canonical_introduced)}
    if LibVersion < X509v3_addr_is_canonical_introduced then
    begin
      {$if declared(FC_X509v3_addr_is_canonical)}
      X509v3_addr_is_canonical := FC_X509v3_addr_is_canonical;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_addr_is_canonical_removed)}
    if X509v3_addr_is_canonical_removed <= LibVersion then
    begin
      {$if declared(_X509v3_addr_is_canonical)}
      X509v3_addr_is_canonical := _X509v3_addr_is_canonical;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_addr_is_canonical_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_addr_is_canonical');
    {$ifend}
  end;
  
  X509v3_asid_canonize := LoadLibFunction(ADllHandle, X509v3_asid_canonize_procname);
  FuncLoadError := not assigned(X509v3_asid_canonize);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_asid_canonize_allownil)}
    X509v3_asid_canonize := ERR_X509v3_asid_canonize;
    {$ifend}
    {$if declared(X509v3_asid_canonize_introduced)}
    if LibVersion < X509v3_asid_canonize_introduced then
    begin
      {$if declared(FC_X509v3_asid_canonize)}
      X509v3_asid_canonize := FC_X509v3_asid_canonize;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_asid_canonize_removed)}
    if X509v3_asid_canonize_removed <= LibVersion then
    begin
      {$if declared(_X509v3_asid_canonize)}
      X509v3_asid_canonize := _X509v3_asid_canonize;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_asid_canonize_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_asid_canonize');
    {$ifend}
  end;
  
  X509v3_addr_canonize := LoadLibFunction(ADllHandle, X509v3_addr_canonize_procname);
  FuncLoadError := not assigned(X509v3_addr_canonize);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_addr_canonize_allownil)}
    X509v3_addr_canonize := ERR_X509v3_addr_canonize;
    {$ifend}
    {$if declared(X509v3_addr_canonize_introduced)}
    if LibVersion < X509v3_addr_canonize_introduced then
    begin
      {$if declared(FC_X509v3_addr_canonize)}
      X509v3_addr_canonize := FC_X509v3_addr_canonize;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_addr_canonize_removed)}
    if X509v3_addr_canonize_removed <= LibVersion then
    begin
      {$if declared(_X509v3_addr_canonize)}
      X509v3_addr_canonize := _X509v3_addr_canonize;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_addr_canonize_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_addr_canonize');
    {$ifend}
  end;
  
  X509v3_asid_inherits := LoadLibFunction(ADllHandle, X509v3_asid_inherits_procname);
  FuncLoadError := not assigned(X509v3_asid_inherits);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_asid_inherits_allownil)}
    X509v3_asid_inherits := ERR_X509v3_asid_inherits;
    {$ifend}
    {$if declared(X509v3_asid_inherits_introduced)}
    if LibVersion < X509v3_asid_inherits_introduced then
    begin
      {$if declared(FC_X509v3_asid_inherits)}
      X509v3_asid_inherits := FC_X509v3_asid_inherits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_asid_inherits_removed)}
    if X509v3_asid_inherits_removed <= LibVersion then
    begin
      {$if declared(_X509v3_asid_inherits)}
      X509v3_asid_inherits := _X509v3_asid_inherits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_asid_inherits_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_asid_inherits');
    {$ifend}
  end;
  
  X509v3_addr_inherits := LoadLibFunction(ADllHandle, X509v3_addr_inherits_procname);
  FuncLoadError := not assigned(X509v3_addr_inherits);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_addr_inherits_allownil)}
    X509v3_addr_inherits := ERR_X509v3_addr_inherits;
    {$ifend}
    {$if declared(X509v3_addr_inherits_introduced)}
    if LibVersion < X509v3_addr_inherits_introduced then
    begin
      {$if declared(FC_X509v3_addr_inherits)}
      X509v3_addr_inherits := FC_X509v3_addr_inherits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_addr_inherits_removed)}
    if X509v3_addr_inherits_removed <= LibVersion then
    begin
      {$if declared(_X509v3_addr_inherits)}
      X509v3_addr_inherits := _X509v3_addr_inherits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_addr_inherits_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_addr_inherits');
    {$ifend}
  end;
  
  X509v3_asid_subset := LoadLibFunction(ADllHandle, X509v3_asid_subset_procname);
  FuncLoadError := not assigned(X509v3_asid_subset);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_asid_subset_allownil)}
    X509v3_asid_subset := ERR_X509v3_asid_subset;
    {$ifend}
    {$if declared(X509v3_asid_subset_introduced)}
    if LibVersion < X509v3_asid_subset_introduced then
    begin
      {$if declared(FC_X509v3_asid_subset)}
      X509v3_asid_subset := FC_X509v3_asid_subset;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_asid_subset_removed)}
    if X509v3_asid_subset_removed <= LibVersion then
    begin
      {$if declared(_X509v3_asid_subset)}
      X509v3_asid_subset := _X509v3_asid_subset;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_asid_subset_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_asid_subset');
    {$ifend}
  end;
  
  X509v3_addr_subset := LoadLibFunction(ADllHandle, X509v3_addr_subset_procname);
  FuncLoadError := not assigned(X509v3_addr_subset);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_addr_subset_allownil)}
    X509v3_addr_subset := ERR_X509v3_addr_subset;
    {$ifend}
    {$if declared(X509v3_addr_subset_introduced)}
    if LibVersion < X509v3_addr_subset_introduced then
    begin
      {$if declared(FC_X509v3_addr_subset)}
      X509v3_addr_subset := FC_X509v3_addr_subset;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_addr_subset_removed)}
    if X509v3_addr_subset_removed <= LibVersion then
    begin
      {$if declared(_X509v3_addr_subset)}
      X509v3_addr_subset := _X509v3_addr_subset;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_addr_subset_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_addr_subset');
    {$ifend}
  end;
  
  X509v3_asid_validate_path := LoadLibFunction(ADllHandle, X509v3_asid_validate_path_procname);
  FuncLoadError := not assigned(X509v3_asid_validate_path);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_asid_validate_path_allownil)}
    X509v3_asid_validate_path := ERR_X509v3_asid_validate_path;
    {$ifend}
    {$if declared(X509v3_asid_validate_path_introduced)}
    if LibVersion < X509v3_asid_validate_path_introduced then
    begin
      {$if declared(FC_X509v3_asid_validate_path)}
      X509v3_asid_validate_path := FC_X509v3_asid_validate_path;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_asid_validate_path_removed)}
    if X509v3_asid_validate_path_removed <= LibVersion then
    begin
      {$if declared(_X509v3_asid_validate_path)}
      X509v3_asid_validate_path := _X509v3_asid_validate_path;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_asid_validate_path_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_asid_validate_path');
    {$ifend}
  end;
  
  X509v3_addr_validate_path := LoadLibFunction(ADllHandle, X509v3_addr_validate_path_procname);
  FuncLoadError := not assigned(X509v3_addr_validate_path);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_addr_validate_path_allownil)}
    X509v3_addr_validate_path := ERR_X509v3_addr_validate_path;
    {$ifend}
    {$if declared(X509v3_addr_validate_path_introduced)}
    if LibVersion < X509v3_addr_validate_path_introduced then
    begin
      {$if declared(FC_X509v3_addr_validate_path)}
      X509v3_addr_validate_path := FC_X509v3_addr_validate_path;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_addr_validate_path_removed)}
    if X509v3_addr_validate_path_removed <= LibVersion then
    begin
      {$if declared(_X509v3_addr_validate_path)}
      X509v3_addr_validate_path := _X509v3_addr_validate_path;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_addr_validate_path_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_addr_validate_path');
    {$ifend}
  end;
  
  X509v3_asid_validate_resource_set := LoadLibFunction(ADllHandle, X509v3_asid_validate_resource_set_procname);
  FuncLoadError := not assigned(X509v3_asid_validate_resource_set);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_asid_validate_resource_set_allownil)}
    X509v3_asid_validate_resource_set := ERR_X509v3_asid_validate_resource_set;
    {$ifend}
    {$if declared(X509v3_asid_validate_resource_set_introduced)}
    if LibVersion < X509v3_asid_validate_resource_set_introduced then
    begin
      {$if declared(FC_X509v3_asid_validate_resource_set)}
      X509v3_asid_validate_resource_set := FC_X509v3_asid_validate_resource_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_asid_validate_resource_set_removed)}
    if X509v3_asid_validate_resource_set_removed <= LibVersion then
    begin
      {$if declared(_X509v3_asid_validate_resource_set)}
      X509v3_asid_validate_resource_set := _X509v3_asid_validate_resource_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_asid_validate_resource_set_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_asid_validate_resource_set');
    {$ifend}
  end;
  
  X509v3_addr_validate_resource_set := LoadLibFunction(ADllHandle, X509v3_addr_validate_resource_set_procname);
  FuncLoadError := not assigned(X509v3_addr_validate_resource_set);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_addr_validate_resource_set_allownil)}
    X509v3_addr_validate_resource_set := ERR_X509v3_addr_validate_resource_set;
    {$ifend}
    {$if declared(X509v3_addr_validate_resource_set_introduced)}
    if LibVersion < X509v3_addr_validate_resource_set_introduced then
    begin
      {$if declared(FC_X509v3_addr_validate_resource_set)}
      X509v3_addr_validate_resource_set := FC_X509v3_addr_validate_resource_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_addr_validate_resource_set_removed)}
    if X509v3_addr_validate_resource_set_removed <= LibVersion then
    begin
      {$if declared(_X509v3_addr_validate_resource_set)}
      X509v3_addr_validate_resource_set := _X509v3_addr_validate_resource_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_addr_validate_resource_set_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_addr_validate_resource_set');
    {$ifend}
  end;
  
  NAMING_AUTHORITY_new := LoadLibFunction(ADllHandle, NAMING_AUTHORITY_new_procname);
  FuncLoadError := not assigned(NAMING_AUTHORITY_new);
  if FuncLoadError then
  begin
    {$if not defined(NAMING_AUTHORITY_new_allownil)}
    NAMING_AUTHORITY_new := ERR_NAMING_AUTHORITY_new;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_new_introduced)}
    if LibVersion < NAMING_AUTHORITY_new_introduced then
    begin
      {$if declared(FC_NAMING_AUTHORITY_new)}
      NAMING_AUTHORITY_new := FC_NAMING_AUTHORITY_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_new_removed)}
    if NAMING_AUTHORITY_new_removed <= LibVersion then
    begin
      {$if declared(_NAMING_AUTHORITY_new)}
      NAMING_AUTHORITY_new := _NAMING_AUTHORITY_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAMING_AUTHORITY_new_allownil)}
    if FuncLoadError then
      AFailed.Add('NAMING_AUTHORITY_new');
    {$ifend}
  end;
  
  NAMING_AUTHORITY_free := LoadLibFunction(ADllHandle, NAMING_AUTHORITY_free_procname);
  FuncLoadError := not assigned(NAMING_AUTHORITY_free);
  if FuncLoadError then
  begin
    {$if not defined(NAMING_AUTHORITY_free_allownil)}
    NAMING_AUTHORITY_free := ERR_NAMING_AUTHORITY_free;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_free_introduced)}
    if LibVersion < NAMING_AUTHORITY_free_introduced then
    begin
      {$if declared(FC_NAMING_AUTHORITY_free)}
      NAMING_AUTHORITY_free := FC_NAMING_AUTHORITY_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_free_removed)}
    if NAMING_AUTHORITY_free_removed <= LibVersion then
    begin
      {$if declared(_NAMING_AUTHORITY_free)}
      NAMING_AUTHORITY_free := _NAMING_AUTHORITY_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAMING_AUTHORITY_free_allownil)}
    if FuncLoadError then
      AFailed.Add('NAMING_AUTHORITY_free');
    {$ifend}
  end;
  
  d2i_NAMING_AUTHORITY := LoadLibFunction(ADllHandle, d2i_NAMING_AUTHORITY_procname);
  FuncLoadError := not assigned(d2i_NAMING_AUTHORITY);
  if FuncLoadError then
  begin
    {$if not defined(d2i_NAMING_AUTHORITY_allownil)}
    d2i_NAMING_AUTHORITY := ERR_d2i_NAMING_AUTHORITY;
    {$ifend}
    {$if declared(d2i_NAMING_AUTHORITY_introduced)}
    if LibVersion < d2i_NAMING_AUTHORITY_introduced then
    begin
      {$if declared(FC_d2i_NAMING_AUTHORITY)}
      d2i_NAMING_AUTHORITY := FC_d2i_NAMING_AUTHORITY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_NAMING_AUTHORITY_removed)}
    if d2i_NAMING_AUTHORITY_removed <= LibVersion then
    begin
      {$if declared(_d2i_NAMING_AUTHORITY)}
      d2i_NAMING_AUTHORITY := _d2i_NAMING_AUTHORITY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_NAMING_AUTHORITY_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_NAMING_AUTHORITY');
    {$ifend}
  end;
  
  i2d_NAMING_AUTHORITY := LoadLibFunction(ADllHandle, i2d_NAMING_AUTHORITY_procname);
  FuncLoadError := not assigned(i2d_NAMING_AUTHORITY);
  if FuncLoadError then
  begin
    {$if not defined(i2d_NAMING_AUTHORITY_allownil)}
    i2d_NAMING_AUTHORITY := ERR_i2d_NAMING_AUTHORITY;
    {$ifend}
    {$if declared(i2d_NAMING_AUTHORITY_introduced)}
    if LibVersion < i2d_NAMING_AUTHORITY_introduced then
    begin
      {$if declared(FC_i2d_NAMING_AUTHORITY)}
      i2d_NAMING_AUTHORITY := FC_i2d_NAMING_AUTHORITY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_NAMING_AUTHORITY_removed)}
    if i2d_NAMING_AUTHORITY_removed <= LibVersion then
    begin
      {$if declared(_i2d_NAMING_AUTHORITY)}
      i2d_NAMING_AUTHORITY := _i2d_NAMING_AUTHORITY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_NAMING_AUTHORITY_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_NAMING_AUTHORITY');
    {$ifend}
  end;
  
  NAMING_AUTHORITY_it := LoadLibFunction(ADllHandle, NAMING_AUTHORITY_it_procname);
  FuncLoadError := not assigned(NAMING_AUTHORITY_it);
  if FuncLoadError then
  begin
    {$if not defined(NAMING_AUTHORITY_it_allownil)}
    NAMING_AUTHORITY_it := ERR_NAMING_AUTHORITY_it;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_it_introduced)}
    if LibVersion < NAMING_AUTHORITY_it_introduced then
    begin
      {$if declared(FC_NAMING_AUTHORITY_it)}
      NAMING_AUTHORITY_it := FC_NAMING_AUTHORITY_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_it_removed)}
    if NAMING_AUTHORITY_it_removed <= LibVersion then
    begin
      {$if declared(_NAMING_AUTHORITY_it)}
      NAMING_AUTHORITY_it := _NAMING_AUTHORITY_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAMING_AUTHORITY_it_allownil)}
    if FuncLoadError then
      AFailed.Add('NAMING_AUTHORITY_it');
    {$ifend}
  end;
  
  PROFESSION_INFO_new := LoadLibFunction(ADllHandle, PROFESSION_INFO_new_procname);
  FuncLoadError := not assigned(PROFESSION_INFO_new);
  if FuncLoadError then
  begin
    {$if not defined(PROFESSION_INFO_new_allownil)}
    PROFESSION_INFO_new := ERR_PROFESSION_INFO_new;
    {$ifend}
    {$if declared(PROFESSION_INFO_new_introduced)}
    if LibVersion < PROFESSION_INFO_new_introduced then
    begin
      {$if declared(FC_PROFESSION_INFO_new)}
      PROFESSION_INFO_new := FC_PROFESSION_INFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROFESSION_INFO_new_removed)}
    if PROFESSION_INFO_new_removed <= LibVersion then
    begin
      {$if declared(_PROFESSION_INFO_new)}
      PROFESSION_INFO_new := _PROFESSION_INFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROFESSION_INFO_new_allownil)}
    if FuncLoadError then
      AFailed.Add('PROFESSION_INFO_new');
    {$ifend}
  end;
  
  PROFESSION_INFO_free := LoadLibFunction(ADllHandle, PROFESSION_INFO_free_procname);
  FuncLoadError := not assigned(PROFESSION_INFO_free);
  if FuncLoadError then
  begin
    {$if not defined(PROFESSION_INFO_free_allownil)}
    PROFESSION_INFO_free := ERR_PROFESSION_INFO_free;
    {$ifend}
    {$if declared(PROFESSION_INFO_free_introduced)}
    if LibVersion < PROFESSION_INFO_free_introduced then
    begin
      {$if declared(FC_PROFESSION_INFO_free)}
      PROFESSION_INFO_free := FC_PROFESSION_INFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROFESSION_INFO_free_removed)}
    if PROFESSION_INFO_free_removed <= LibVersion then
    begin
      {$if declared(_PROFESSION_INFO_free)}
      PROFESSION_INFO_free := _PROFESSION_INFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROFESSION_INFO_free_allownil)}
    if FuncLoadError then
      AFailed.Add('PROFESSION_INFO_free');
    {$ifend}
  end;
  
  d2i_PROFESSION_INFO := LoadLibFunction(ADllHandle, d2i_PROFESSION_INFO_procname);
  FuncLoadError := not assigned(d2i_PROFESSION_INFO);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PROFESSION_INFO_allownil)}
    d2i_PROFESSION_INFO := ERR_d2i_PROFESSION_INFO;
    {$ifend}
    {$if declared(d2i_PROFESSION_INFO_introduced)}
    if LibVersion < d2i_PROFESSION_INFO_introduced then
    begin
      {$if declared(FC_d2i_PROFESSION_INFO)}
      d2i_PROFESSION_INFO := FC_d2i_PROFESSION_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PROFESSION_INFO_removed)}
    if d2i_PROFESSION_INFO_removed <= LibVersion then
    begin
      {$if declared(_d2i_PROFESSION_INFO)}
      d2i_PROFESSION_INFO := _d2i_PROFESSION_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PROFESSION_INFO_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PROFESSION_INFO');
    {$ifend}
  end;
  
  i2d_PROFESSION_INFO := LoadLibFunction(ADllHandle, i2d_PROFESSION_INFO_procname);
  FuncLoadError := not assigned(i2d_PROFESSION_INFO);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PROFESSION_INFO_allownil)}
    i2d_PROFESSION_INFO := ERR_i2d_PROFESSION_INFO;
    {$ifend}
    {$if declared(i2d_PROFESSION_INFO_introduced)}
    if LibVersion < i2d_PROFESSION_INFO_introduced then
    begin
      {$if declared(FC_i2d_PROFESSION_INFO)}
      i2d_PROFESSION_INFO := FC_i2d_PROFESSION_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PROFESSION_INFO_removed)}
    if i2d_PROFESSION_INFO_removed <= LibVersion then
    begin
      {$if declared(_i2d_PROFESSION_INFO)}
      i2d_PROFESSION_INFO := _i2d_PROFESSION_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PROFESSION_INFO_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PROFESSION_INFO');
    {$ifend}
  end;
  
  PROFESSION_INFO_it := LoadLibFunction(ADllHandle, PROFESSION_INFO_it_procname);
  FuncLoadError := not assigned(PROFESSION_INFO_it);
  if FuncLoadError then
  begin
    {$if not defined(PROFESSION_INFO_it_allownil)}
    PROFESSION_INFO_it := ERR_PROFESSION_INFO_it;
    {$ifend}
    {$if declared(PROFESSION_INFO_it_introduced)}
    if LibVersion < PROFESSION_INFO_it_introduced then
    begin
      {$if declared(FC_PROFESSION_INFO_it)}
      PROFESSION_INFO_it := FC_PROFESSION_INFO_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROFESSION_INFO_it_removed)}
    if PROFESSION_INFO_it_removed <= LibVersion then
    begin
      {$if declared(_PROFESSION_INFO_it)}
      PROFESSION_INFO_it := _PROFESSION_INFO_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROFESSION_INFO_it_allownil)}
    if FuncLoadError then
      AFailed.Add('PROFESSION_INFO_it');
    {$ifend}
  end;
  
  ADMISSIONS_new := LoadLibFunction(ADllHandle, ADMISSIONS_new_procname);
  FuncLoadError := not assigned(ADMISSIONS_new);
  if FuncLoadError then
  begin
    {$if not defined(ADMISSIONS_new_allownil)}
    ADMISSIONS_new := ERR_ADMISSIONS_new;
    {$ifend}
    {$if declared(ADMISSIONS_new_introduced)}
    if LibVersion < ADMISSIONS_new_introduced then
    begin
      {$if declared(FC_ADMISSIONS_new)}
      ADMISSIONS_new := FC_ADMISSIONS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ADMISSIONS_new_removed)}
    if ADMISSIONS_new_removed <= LibVersion then
    begin
      {$if declared(_ADMISSIONS_new)}
      ADMISSIONS_new := _ADMISSIONS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ADMISSIONS_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ADMISSIONS_new');
    {$ifend}
  end;
  
  ADMISSIONS_free := LoadLibFunction(ADllHandle, ADMISSIONS_free_procname);
  FuncLoadError := not assigned(ADMISSIONS_free);
  if FuncLoadError then
  begin
    {$if not defined(ADMISSIONS_free_allownil)}
    ADMISSIONS_free := ERR_ADMISSIONS_free;
    {$ifend}
    {$if declared(ADMISSIONS_free_introduced)}
    if LibVersion < ADMISSIONS_free_introduced then
    begin
      {$if declared(FC_ADMISSIONS_free)}
      ADMISSIONS_free := FC_ADMISSIONS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ADMISSIONS_free_removed)}
    if ADMISSIONS_free_removed <= LibVersion then
    begin
      {$if declared(_ADMISSIONS_free)}
      ADMISSIONS_free := _ADMISSIONS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ADMISSIONS_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ADMISSIONS_free');
    {$ifend}
  end;
  
  d2i_ADMISSIONS := LoadLibFunction(ADllHandle, d2i_ADMISSIONS_procname);
  FuncLoadError := not assigned(d2i_ADMISSIONS);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ADMISSIONS_allownil)}
    d2i_ADMISSIONS := ERR_d2i_ADMISSIONS;
    {$ifend}
    {$if declared(d2i_ADMISSIONS_introduced)}
    if LibVersion < d2i_ADMISSIONS_introduced then
    begin
      {$if declared(FC_d2i_ADMISSIONS)}
      d2i_ADMISSIONS := FC_d2i_ADMISSIONS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ADMISSIONS_removed)}
    if d2i_ADMISSIONS_removed <= LibVersion then
    begin
      {$if declared(_d2i_ADMISSIONS)}
      d2i_ADMISSIONS := _d2i_ADMISSIONS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ADMISSIONS_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ADMISSIONS');
    {$ifend}
  end;
  
  i2d_ADMISSIONS := LoadLibFunction(ADllHandle, i2d_ADMISSIONS_procname);
  FuncLoadError := not assigned(i2d_ADMISSIONS);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ADMISSIONS_allownil)}
    i2d_ADMISSIONS := ERR_i2d_ADMISSIONS;
    {$ifend}
    {$if declared(i2d_ADMISSIONS_introduced)}
    if LibVersion < i2d_ADMISSIONS_introduced then
    begin
      {$if declared(FC_i2d_ADMISSIONS)}
      i2d_ADMISSIONS := FC_i2d_ADMISSIONS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ADMISSIONS_removed)}
    if i2d_ADMISSIONS_removed <= LibVersion then
    begin
      {$if declared(_i2d_ADMISSIONS)}
      i2d_ADMISSIONS := _i2d_ADMISSIONS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ADMISSIONS_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ADMISSIONS');
    {$ifend}
  end;
  
  ADMISSIONS_it := LoadLibFunction(ADllHandle, ADMISSIONS_it_procname);
  FuncLoadError := not assigned(ADMISSIONS_it);
  if FuncLoadError then
  begin
    {$if not defined(ADMISSIONS_it_allownil)}
    ADMISSIONS_it := ERR_ADMISSIONS_it;
    {$ifend}
    {$if declared(ADMISSIONS_it_introduced)}
    if LibVersion < ADMISSIONS_it_introduced then
    begin
      {$if declared(FC_ADMISSIONS_it)}
      ADMISSIONS_it := FC_ADMISSIONS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ADMISSIONS_it_removed)}
    if ADMISSIONS_it_removed <= LibVersion then
    begin
      {$if declared(_ADMISSIONS_it)}
      ADMISSIONS_it := _ADMISSIONS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ADMISSIONS_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ADMISSIONS_it');
    {$ifend}
  end;
  
  ADMISSION_SYNTAX_new := LoadLibFunction(ADllHandle, ADMISSION_SYNTAX_new_procname);
  FuncLoadError := not assigned(ADMISSION_SYNTAX_new);
  if FuncLoadError then
  begin
    {$if not defined(ADMISSION_SYNTAX_new_allownil)}
    ADMISSION_SYNTAX_new := ERR_ADMISSION_SYNTAX_new;
    {$ifend}
    {$if declared(ADMISSION_SYNTAX_new_introduced)}
    if LibVersion < ADMISSION_SYNTAX_new_introduced then
    begin
      {$if declared(FC_ADMISSION_SYNTAX_new)}
      ADMISSION_SYNTAX_new := FC_ADMISSION_SYNTAX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ADMISSION_SYNTAX_new_removed)}
    if ADMISSION_SYNTAX_new_removed <= LibVersion then
    begin
      {$if declared(_ADMISSION_SYNTAX_new)}
      ADMISSION_SYNTAX_new := _ADMISSION_SYNTAX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ADMISSION_SYNTAX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ADMISSION_SYNTAX_new');
    {$ifend}
  end;
  
  ADMISSION_SYNTAX_free := LoadLibFunction(ADllHandle, ADMISSION_SYNTAX_free_procname);
  FuncLoadError := not assigned(ADMISSION_SYNTAX_free);
  if FuncLoadError then
  begin
    {$if not defined(ADMISSION_SYNTAX_free_allownil)}
    ADMISSION_SYNTAX_free := ERR_ADMISSION_SYNTAX_free;
    {$ifend}
    {$if declared(ADMISSION_SYNTAX_free_introduced)}
    if LibVersion < ADMISSION_SYNTAX_free_introduced then
    begin
      {$if declared(FC_ADMISSION_SYNTAX_free)}
      ADMISSION_SYNTAX_free := FC_ADMISSION_SYNTAX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ADMISSION_SYNTAX_free_removed)}
    if ADMISSION_SYNTAX_free_removed <= LibVersion then
    begin
      {$if declared(_ADMISSION_SYNTAX_free)}
      ADMISSION_SYNTAX_free := _ADMISSION_SYNTAX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ADMISSION_SYNTAX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ADMISSION_SYNTAX_free');
    {$ifend}
  end;
  
  d2i_ADMISSION_SYNTAX := LoadLibFunction(ADllHandle, d2i_ADMISSION_SYNTAX_procname);
  FuncLoadError := not assigned(d2i_ADMISSION_SYNTAX);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ADMISSION_SYNTAX_allownil)}
    d2i_ADMISSION_SYNTAX := ERR_d2i_ADMISSION_SYNTAX;
    {$ifend}
    {$if declared(d2i_ADMISSION_SYNTAX_introduced)}
    if LibVersion < d2i_ADMISSION_SYNTAX_introduced then
    begin
      {$if declared(FC_d2i_ADMISSION_SYNTAX)}
      d2i_ADMISSION_SYNTAX := FC_d2i_ADMISSION_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ADMISSION_SYNTAX_removed)}
    if d2i_ADMISSION_SYNTAX_removed <= LibVersion then
    begin
      {$if declared(_d2i_ADMISSION_SYNTAX)}
      d2i_ADMISSION_SYNTAX := _d2i_ADMISSION_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ADMISSION_SYNTAX_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ADMISSION_SYNTAX');
    {$ifend}
  end;
  
  i2d_ADMISSION_SYNTAX := LoadLibFunction(ADllHandle, i2d_ADMISSION_SYNTAX_procname);
  FuncLoadError := not assigned(i2d_ADMISSION_SYNTAX);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ADMISSION_SYNTAX_allownil)}
    i2d_ADMISSION_SYNTAX := ERR_i2d_ADMISSION_SYNTAX;
    {$ifend}
    {$if declared(i2d_ADMISSION_SYNTAX_introduced)}
    if LibVersion < i2d_ADMISSION_SYNTAX_introduced then
    begin
      {$if declared(FC_i2d_ADMISSION_SYNTAX)}
      i2d_ADMISSION_SYNTAX := FC_i2d_ADMISSION_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ADMISSION_SYNTAX_removed)}
    if i2d_ADMISSION_SYNTAX_removed <= LibVersion then
    begin
      {$if declared(_i2d_ADMISSION_SYNTAX)}
      i2d_ADMISSION_SYNTAX := _i2d_ADMISSION_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ADMISSION_SYNTAX_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ADMISSION_SYNTAX');
    {$ifend}
  end;
  
  ADMISSION_SYNTAX_it := LoadLibFunction(ADllHandle, ADMISSION_SYNTAX_it_procname);
  FuncLoadError := not assigned(ADMISSION_SYNTAX_it);
  if FuncLoadError then
  begin
    {$if not defined(ADMISSION_SYNTAX_it_allownil)}
    ADMISSION_SYNTAX_it := ERR_ADMISSION_SYNTAX_it;
    {$ifend}
    {$if declared(ADMISSION_SYNTAX_it_introduced)}
    if LibVersion < ADMISSION_SYNTAX_it_introduced then
    begin
      {$if declared(FC_ADMISSION_SYNTAX_it)}
      ADMISSION_SYNTAX_it := FC_ADMISSION_SYNTAX_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ADMISSION_SYNTAX_it_removed)}
    if ADMISSION_SYNTAX_it_removed <= LibVersion then
    begin
      {$if declared(_ADMISSION_SYNTAX_it)}
      ADMISSION_SYNTAX_it := _ADMISSION_SYNTAX_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ADMISSION_SYNTAX_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ADMISSION_SYNTAX_it');
    {$ifend}
  end;
  
  NAMING_AUTHORITY_get0_authorityId := LoadLibFunction(ADllHandle, NAMING_AUTHORITY_get0_authorityId_procname);
  FuncLoadError := not assigned(NAMING_AUTHORITY_get0_authorityId);
  if FuncLoadError then
  begin
    {$if not defined(NAMING_AUTHORITY_get0_authorityId_allownil)}
    NAMING_AUTHORITY_get0_authorityId := ERR_NAMING_AUTHORITY_get0_authorityId;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_get0_authorityId_introduced)}
    if LibVersion < NAMING_AUTHORITY_get0_authorityId_introduced then
    begin
      {$if declared(FC_NAMING_AUTHORITY_get0_authorityId)}
      NAMING_AUTHORITY_get0_authorityId := FC_NAMING_AUTHORITY_get0_authorityId;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_get0_authorityId_removed)}
    if NAMING_AUTHORITY_get0_authorityId_removed <= LibVersion then
    begin
      {$if declared(_NAMING_AUTHORITY_get0_authorityId)}
      NAMING_AUTHORITY_get0_authorityId := _NAMING_AUTHORITY_get0_authorityId;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAMING_AUTHORITY_get0_authorityId_allownil)}
    if FuncLoadError then
      AFailed.Add('NAMING_AUTHORITY_get0_authorityId');
    {$ifend}
  end;
  
  NAMING_AUTHORITY_get0_authorityURL := LoadLibFunction(ADllHandle, NAMING_AUTHORITY_get0_authorityURL_procname);
  FuncLoadError := not assigned(NAMING_AUTHORITY_get0_authorityURL);
  if FuncLoadError then
  begin
    {$if not defined(NAMING_AUTHORITY_get0_authorityURL_allownil)}
    NAMING_AUTHORITY_get0_authorityURL := ERR_NAMING_AUTHORITY_get0_authorityURL;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_get0_authorityURL_introduced)}
    if LibVersion < NAMING_AUTHORITY_get0_authorityURL_introduced then
    begin
      {$if declared(FC_NAMING_AUTHORITY_get0_authorityURL)}
      NAMING_AUTHORITY_get0_authorityURL := FC_NAMING_AUTHORITY_get0_authorityURL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_get0_authorityURL_removed)}
    if NAMING_AUTHORITY_get0_authorityURL_removed <= LibVersion then
    begin
      {$if declared(_NAMING_AUTHORITY_get0_authorityURL)}
      NAMING_AUTHORITY_get0_authorityURL := _NAMING_AUTHORITY_get0_authorityURL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAMING_AUTHORITY_get0_authorityURL_allownil)}
    if FuncLoadError then
      AFailed.Add('NAMING_AUTHORITY_get0_authorityURL');
    {$ifend}
  end;
  
  NAMING_AUTHORITY_get0_authorityText := LoadLibFunction(ADllHandle, NAMING_AUTHORITY_get0_authorityText_procname);
  FuncLoadError := not assigned(NAMING_AUTHORITY_get0_authorityText);
  if FuncLoadError then
  begin
    {$if not defined(NAMING_AUTHORITY_get0_authorityText_allownil)}
    NAMING_AUTHORITY_get0_authorityText := ERR_NAMING_AUTHORITY_get0_authorityText;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_get0_authorityText_introduced)}
    if LibVersion < NAMING_AUTHORITY_get0_authorityText_introduced then
    begin
      {$if declared(FC_NAMING_AUTHORITY_get0_authorityText)}
      NAMING_AUTHORITY_get0_authorityText := FC_NAMING_AUTHORITY_get0_authorityText;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_get0_authorityText_removed)}
    if NAMING_AUTHORITY_get0_authorityText_removed <= LibVersion then
    begin
      {$if declared(_NAMING_AUTHORITY_get0_authorityText)}
      NAMING_AUTHORITY_get0_authorityText := _NAMING_AUTHORITY_get0_authorityText;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAMING_AUTHORITY_get0_authorityText_allownil)}
    if FuncLoadError then
      AFailed.Add('NAMING_AUTHORITY_get0_authorityText');
    {$ifend}
  end;
  
  NAMING_AUTHORITY_set0_authorityId := LoadLibFunction(ADllHandle, NAMING_AUTHORITY_set0_authorityId_procname);
  FuncLoadError := not assigned(NAMING_AUTHORITY_set0_authorityId);
  if FuncLoadError then
  begin
    {$if not defined(NAMING_AUTHORITY_set0_authorityId_allownil)}
    NAMING_AUTHORITY_set0_authorityId := ERR_NAMING_AUTHORITY_set0_authorityId;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_set0_authorityId_introduced)}
    if LibVersion < NAMING_AUTHORITY_set0_authorityId_introduced then
    begin
      {$if declared(FC_NAMING_AUTHORITY_set0_authorityId)}
      NAMING_AUTHORITY_set0_authorityId := FC_NAMING_AUTHORITY_set0_authorityId;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_set0_authorityId_removed)}
    if NAMING_AUTHORITY_set0_authorityId_removed <= LibVersion then
    begin
      {$if declared(_NAMING_AUTHORITY_set0_authorityId)}
      NAMING_AUTHORITY_set0_authorityId := _NAMING_AUTHORITY_set0_authorityId;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAMING_AUTHORITY_set0_authorityId_allownil)}
    if FuncLoadError then
      AFailed.Add('NAMING_AUTHORITY_set0_authorityId');
    {$ifend}
  end;
  
  NAMING_AUTHORITY_set0_authorityURL := LoadLibFunction(ADllHandle, NAMING_AUTHORITY_set0_authorityURL_procname);
  FuncLoadError := not assigned(NAMING_AUTHORITY_set0_authorityURL);
  if FuncLoadError then
  begin
    {$if not defined(NAMING_AUTHORITY_set0_authorityURL_allownil)}
    NAMING_AUTHORITY_set0_authorityURL := ERR_NAMING_AUTHORITY_set0_authorityURL;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_set0_authorityURL_introduced)}
    if LibVersion < NAMING_AUTHORITY_set0_authorityURL_introduced then
    begin
      {$if declared(FC_NAMING_AUTHORITY_set0_authorityURL)}
      NAMING_AUTHORITY_set0_authorityURL := FC_NAMING_AUTHORITY_set0_authorityURL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_set0_authorityURL_removed)}
    if NAMING_AUTHORITY_set0_authorityURL_removed <= LibVersion then
    begin
      {$if declared(_NAMING_AUTHORITY_set0_authorityURL)}
      NAMING_AUTHORITY_set0_authorityURL := _NAMING_AUTHORITY_set0_authorityURL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAMING_AUTHORITY_set0_authorityURL_allownil)}
    if FuncLoadError then
      AFailed.Add('NAMING_AUTHORITY_set0_authorityURL');
    {$ifend}
  end;
  
  NAMING_AUTHORITY_set0_authorityText := LoadLibFunction(ADllHandle, NAMING_AUTHORITY_set0_authorityText_procname);
  FuncLoadError := not assigned(NAMING_AUTHORITY_set0_authorityText);
  if FuncLoadError then
  begin
    {$if not defined(NAMING_AUTHORITY_set0_authorityText_allownil)}
    NAMING_AUTHORITY_set0_authorityText := ERR_NAMING_AUTHORITY_set0_authorityText;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_set0_authorityText_introduced)}
    if LibVersion < NAMING_AUTHORITY_set0_authorityText_introduced then
    begin
      {$if declared(FC_NAMING_AUTHORITY_set0_authorityText)}
      NAMING_AUTHORITY_set0_authorityText := FC_NAMING_AUTHORITY_set0_authorityText;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_set0_authorityText_removed)}
    if NAMING_AUTHORITY_set0_authorityText_removed <= LibVersion then
    begin
      {$if declared(_NAMING_AUTHORITY_set0_authorityText)}
      NAMING_AUTHORITY_set0_authorityText := _NAMING_AUTHORITY_set0_authorityText;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAMING_AUTHORITY_set0_authorityText_allownil)}
    if FuncLoadError then
      AFailed.Add('NAMING_AUTHORITY_set0_authorityText');
    {$ifend}
  end;
  
  ADMISSION_SYNTAX_get0_admissionAuthority := LoadLibFunction(ADllHandle, ADMISSION_SYNTAX_get0_admissionAuthority_procname);
  FuncLoadError := not assigned(ADMISSION_SYNTAX_get0_admissionAuthority);
  if FuncLoadError then
  begin
    {$if not defined(ADMISSION_SYNTAX_get0_admissionAuthority_allownil)}
    ADMISSION_SYNTAX_get0_admissionAuthority := ERR_ADMISSION_SYNTAX_get0_admissionAuthority;
    {$ifend}
    {$if declared(ADMISSION_SYNTAX_get0_admissionAuthority_introduced)}
    if LibVersion < ADMISSION_SYNTAX_get0_admissionAuthority_introduced then
    begin
      {$if declared(FC_ADMISSION_SYNTAX_get0_admissionAuthority)}
      ADMISSION_SYNTAX_get0_admissionAuthority := FC_ADMISSION_SYNTAX_get0_admissionAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ADMISSION_SYNTAX_get0_admissionAuthority_removed)}
    if ADMISSION_SYNTAX_get0_admissionAuthority_removed <= LibVersion then
    begin
      {$if declared(_ADMISSION_SYNTAX_get0_admissionAuthority)}
      ADMISSION_SYNTAX_get0_admissionAuthority := _ADMISSION_SYNTAX_get0_admissionAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ADMISSION_SYNTAX_get0_admissionAuthority_allownil)}
    if FuncLoadError then
      AFailed.Add('ADMISSION_SYNTAX_get0_admissionAuthority');
    {$ifend}
  end;
  
  ADMISSION_SYNTAX_set0_admissionAuthority := LoadLibFunction(ADllHandle, ADMISSION_SYNTAX_set0_admissionAuthority_procname);
  FuncLoadError := not assigned(ADMISSION_SYNTAX_set0_admissionAuthority);
  if FuncLoadError then
  begin
    {$if not defined(ADMISSION_SYNTAX_set0_admissionAuthority_allownil)}
    ADMISSION_SYNTAX_set0_admissionAuthority := ERR_ADMISSION_SYNTAX_set0_admissionAuthority;
    {$ifend}
    {$if declared(ADMISSION_SYNTAX_set0_admissionAuthority_introduced)}
    if LibVersion < ADMISSION_SYNTAX_set0_admissionAuthority_introduced then
    begin
      {$if declared(FC_ADMISSION_SYNTAX_set0_admissionAuthority)}
      ADMISSION_SYNTAX_set0_admissionAuthority := FC_ADMISSION_SYNTAX_set0_admissionAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ADMISSION_SYNTAX_set0_admissionAuthority_removed)}
    if ADMISSION_SYNTAX_set0_admissionAuthority_removed <= LibVersion then
    begin
      {$if declared(_ADMISSION_SYNTAX_set0_admissionAuthority)}
      ADMISSION_SYNTAX_set0_admissionAuthority := _ADMISSION_SYNTAX_set0_admissionAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ADMISSION_SYNTAX_set0_admissionAuthority_allownil)}
    if FuncLoadError then
      AFailed.Add('ADMISSION_SYNTAX_set0_admissionAuthority');
    {$ifend}
  end;
  
  ADMISSION_SYNTAX_get0_contentsOfAdmissions := LoadLibFunction(ADllHandle, ADMISSION_SYNTAX_get0_contentsOfAdmissions_procname);
  FuncLoadError := not assigned(ADMISSION_SYNTAX_get0_contentsOfAdmissions);
  if FuncLoadError then
  begin
    {$if not defined(ADMISSION_SYNTAX_get0_contentsOfAdmissions_allownil)}
    ADMISSION_SYNTAX_get0_contentsOfAdmissions := ERR_ADMISSION_SYNTAX_get0_contentsOfAdmissions;
    {$ifend}
    {$if declared(ADMISSION_SYNTAX_get0_contentsOfAdmissions_introduced)}
    if LibVersion < ADMISSION_SYNTAX_get0_contentsOfAdmissions_introduced then
    begin
      {$if declared(FC_ADMISSION_SYNTAX_get0_contentsOfAdmissions)}
      ADMISSION_SYNTAX_get0_contentsOfAdmissions := FC_ADMISSION_SYNTAX_get0_contentsOfAdmissions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ADMISSION_SYNTAX_get0_contentsOfAdmissions_removed)}
    if ADMISSION_SYNTAX_get0_contentsOfAdmissions_removed <= LibVersion then
    begin
      {$if declared(_ADMISSION_SYNTAX_get0_contentsOfAdmissions)}
      ADMISSION_SYNTAX_get0_contentsOfAdmissions := _ADMISSION_SYNTAX_get0_contentsOfAdmissions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ADMISSION_SYNTAX_get0_contentsOfAdmissions_allownil)}
    if FuncLoadError then
      AFailed.Add('ADMISSION_SYNTAX_get0_contentsOfAdmissions');
    {$ifend}
  end;
  
  ADMISSION_SYNTAX_set0_contentsOfAdmissions := LoadLibFunction(ADllHandle, ADMISSION_SYNTAX_set0_contentsOfAdmissions_procname);
  FuncLoadError := not assigned(ADMISSION_SYNTAX_set0_contentsOfAdmissions);
  if FuncLoadError then
  begin
    {$if not defined(ADMISSION_SYNTAX_set0_contentsOfAdmissions_allownil)}
    ADMISSION_SYNTAX_set0_contentsOfAdmissions := ERR_ADMISSION_SYNTAX_set0_contentsOfAdmissions;
    {$ifend}
    {$if declared(ADMISSION_SYNTAX_set0_contentsOfAdmissions_introduced)}
    if LibVersion < ADMISSION_SYNTAX_set0_contentsOfAdmissions_introduced then
    begin
      {$if declared(FC_ADMISSION_SYNTAX_set0_contentsOfAdmissions)}
      ADMISSION_SYNTAX_set0_contentsOfAdmissions := FC_ADMISSION_SYNTAX_set0_contentsOfAdmissions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ADMISSION_SYNTAX_set0_contentsOfAdmissions_removed)}
    if ADMISSION_SYNTAX_set0_contentsOfAdmissions_removed <= LibVersion then
    begin
      {$if declared(_ADMISSION_SYNTAX_set0_contentsOfAdmissions)}
      ADMISSION_SYNTAX_set0_contentsOfAdmissions := _ADMISSION_SYNTAX_set0_contentsOfAdmissions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ADMISSION_SYNTAX_set0_contentsOfAdmissions_allownil)}
    if FuncLoadError then
      AFailed.Add('ADMISSION_SYNTAX_set0_contentsOfAdmissions');
    {$ifend}
  end;
  
  ADMISSIONS_get0_admissionAuthority := LoadLibFunction(ADllHandle, ADMISSIONS_get0_admissionAuthority_procname);
  FuncLoadError := not assigned(ADMISSIONS_get0_admissionAuthority);
  if FuncLoadError then
  begin
    {$if not defined(ADMISSIONS_get0_admissionAuthority_allownil)}
    ADMISSIONS_get0_admissionAuthority := ERR_ADMISSIONS_get0_admissionAuthority;
    {$ifend}
    {$if declared(ADMISSIONS_get0_admissionAuthority_introduced)}
    if LibVersion < ADMISSIONS_get0_admissionAuthority_introduced then
    begin
      {$if declared(FC_ADMISSIONS_get0_admissionAuthority)}
      ADMISSIONS_get0_admissionAuthority := FC_ADMISSIONS_get0_admissionAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ADMISSIONS_get0_admissionAuthority_removed)}
    if ADMISSIONS_get0_admissionAuthority_removed <= LibVersion then
    begin
      {$if declared(_ADMISSIONS_get0_admissionAuthority)}
      ADMISSIONS_get0_admissionAuthority := _ADMISSIONS_get0_admissionAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ADMISSIONS_get0_admissionAuthority_allownil)}
    if FuncLoadError then
      AFailed.Add('ADMISSIONS_get0_admissionAuthority');
    {$ifend}
  end;
  
  ADMISSIONS_set0_admissionAuthority := LoadLibFunction(ADllHandle, ADMISSIONS_set0_admissionAuthority_procname);
  FuncLoadError := not assigned(ADMISSIONS_set0_admissionAuthority);
  if FuncLoadError then
  begin
    {$if not defined(ADMISSIONS_set0_admissionAuthority_allownil)}
    ADMISSIONS_set0_admissionAuthority := ERR_ADMISSIONS_set0_admissionAuthority;
    {$ifend}
    {$if declared(ADMISSIONS_set0_admissionAuthority_introduced)}
    if LibVersion < ADMISSIONS_set0_admissionAuthority_introduced then
    begin
      {$if declared(FC_ADMISSIONS_set0_admissionAuthority)}
      ADMISSIONS_set0_admissionAuthority := FC_ADMISSIONS_set0_admissionAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ADMISSIONS_set0_admissionAuthority_removed)}
    if ADMISSIONS_set0_admissionAuthority_removed <= LibVersion then
    begin
      {$if declared(_ADMISSIONS_set0_admissionAuthority)}
      ADMISSIONS_set0_admissionAuthority := _ADMISSIONS_set0_admissionAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ADMISSIONS_set0_admissionAuthority_allownil)}
    if FuncLoadError then
      AFailed.Add('ADMISSIONS_set0_admissionAuthority');
    {$ifend}
  end;
  
  ADMISSIONS_get0_namingAuthority := LoadLibFunction(ADllHandle, ADMISSIONS_get0_namingAuthority_procname);
  FuncLoadError := not assigned(ADMISSIONS_get0_namingAuthority);
  if FuncLoadError then
  begin
    {$if not defined(ADMISSIONS_get0_namingAuthority_allownil)}
    ADMISSIONS_get0_namingAuthority := ERR_ADMISSIONS_get0_namingAuthority;
    {$ifend}
    {$if declared(ADMISSIONS_get0_namingAuthority_introduced)}
    if LibVersion < ADMISSIONS_get0_namingAuthority_introduced then
    begin
      {$if declared(FC_ADMISSIONS_get0_namingAuthority)}
      ADMISSIONS_get0_namingAuthority := FC_ADMISSIONS_get0_namingAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ADMISSIONS_get0_namingAuthority_removed)}
    if ADMISSIONS_get0_namingAuthority_removed <= LibVersion then
    begin
      {$if declared(_ADMISSIONS_get0_namingAuthority)}
      ADMISSIONS_get0_namingAuthority := _ADMISSIONS_get0_namingAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ADMISSIONS_get0_namingAuthority_allownil)}
    if FuncLoadError then
      AFailed.Add('ADMISSIONS_get0_namingAuthority');
    {$ifend}
  end;
  
  ADMISSIONS_set0_namingAuthority := LoadLibFunction(ADllHandle, ADMISSIONS_set0_namingAuthority_procname);
  FuncLoadError := not assigned(ADMISSIONS_set0_namingAuthority);
  if FuncLoadError then
  begin
    {$if not defined(ADMISSIONS_set0_namingAuthority_allownil)}
    ADMISSIONS_set0_namingAuthority := ERR_ADMISSIONS_set0_namingAuthority;
    {$ifend}
    {$if declared(ADMISSIONS_set0_namingAuthority_introduced)}
    if LibVersion < ADMISSIONS_set0_namingAuthority_introduced then
    begin
      {$if declared(FC_ADMISSIONS_set0_namingAuthority)}
      ADMISSIONS_set0_namingAuthority := FC_ADMISSIONS_set0_namingAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ADMISSIONS_set0_namingAuthority_removed)}
    if ADMISSIONS_set0_namingAuthority_removed <= LibVersion then
    begin
      {$if declared(_ADMISSIONS_set0_namingAuthority)}
      ADMISSIONS_set0_namingAuthority := _ADMISSIONS_set0_namingAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ADMISSIONS_set0_namingAuthority_allownil)}
    if FuncLoadError then
      AFailed.Add('ADMISSIONS_set0_namingAuthority');
    {$ifend}
  end;
  
  ADMISSIONS_get0_professionInfos := LoadLibFunction(ADllHandle, ADMISSIONS_get0_professionInfos_procname);
  FuncLoadError := not assigned(ADMISSIONS_get0_professionInfos);
  if FuncLoadError then
  begin
    {$if not defined(ADMISSIONS_get0_professionInfos_allownil)}
    ADMISSIONS_get0_professionInfos := ERR_ADMISSIONS_get0_professionInfos;
    {$ifend}
    {$if declared(ADMISSIONS_get0_professionInfos_introduced)}
    if LibVersion < ADMISSIONS_get0_professionInfos_introduced then
    begin
      {$if declared(FC_ADMISSIONS_get0_professionInfos)}
      ADMISSIONS_get0_professionInfos := FC_ADMISSIONS_get0_professionInfos;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ADMISSIONS_get0_professionInfos_removed)}
    if ADMISSIONS_get0_professionInfos_removed <= LibVersion then
    begin
      {$if declared(_ADMISSIONS_get0_professionInfos)}
      ADMISSIONS_get0_professionInfos := _ADMISSIONS_get0_professionInfos;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ADMISSIONS_get0_professionInfos_allownil)}
    if FuncLoadError then
      AFailed.Add('ADMISSIONS_get0_professionInfos');
    {$ifend}
  end;
  
  ADMISSIONS_set0_professionInfos := LoadLibFunction(ADllHandle, ADMISSIONS_set0_professionInfos_procname);
  FuncLoadError := not assigned(ADMISSIONS_set0_professionInfos);
  if FuncLoadError then
  begin
    {$if not defined(ADMISSIONS_set0_professionInfos_allownil)}
    ADMISSIONS_set0_professionInfos := ERR_ADMISSIONS_set0_professionInfos;
    {$ifend}
    {$if declared(ADMISSIONS_set0_professionInfos_introduced)}
    if LibVersion < ADMISSIONS_set0_professionInfos_introduced then
    begin
      {$if declared(FC_ADMISSIONS_set0_professionInfos)}
      ADMISSIONS_set0_professionInfos := FC_ADMISSIONS_set0_professionInfos;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ADMISSIONS_set0_professionInfos_removed)}
    if ADMISSIONS_set0_professionInfos_removed <= LibVersion then
    begin
      {$if declared(_ADMISSIONS_set0_professionInfos)}
      ADMISSIONS_set0_professionInfos := _ADMISSIONS_set0_professionInfos;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ADMISSIONS_set0_professionInfos_allownil)}
    if FuncLoadError then
      AFailed.Add('ADMISSIONS_set0_professionInfos');
    {$ifend}
  end;
  
  PROFESSION_INFO_get0_addProfessionInfo := LoadLibFunction(ADllHandle, PROFESSION_INFO_get0_addProfessionInfo_procname);
  FuncLoadError := not assigned(PROFESSION_INFO_get0_addProfessionInfo);
  if FuncLoadError then
  begin
    {$if not defined(PROFESSION_INFO_get0_addProfessionInfo_allownil)}
    PROFESSION_INFO_get0_addProfessionInfo := ERR_PROFESSION_INFO_get0_addProfessionInfo;
    {$ifend}
    {$if declared(PROFESSION_INFO_get0_addProfessionInfo_introduced)}
    if LibVersion < PROFESSION_INFO_get0_addProfessionInfo_introduced then
    begin
      {$if declared(FC_PROFESSION_INFO_get0_addProfessionInfo)}
      PROFESSION_INFO_get0_addProfessionInfo := FC_PROFESSION_INFO_get0_addProfessionInfo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROFESSION_INFO_get0_addProfessionInfo_removed)}
    if PROFESSION_INFO_get0_addProfessionInfo_removed <= LibVersion then
    begin
      {$if declared(_PROFESSION_INFO_get0_addProfessionInfo)}
      PROFESSION_INFO_get0_addProfessionInfo := _PROFESSION_INFO_get0_addProfessionInfo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROFESSION_INFO_get0_addProfessionInfo_allownil)}
    if FuncLoadError then
      AFailed.Add('PROFESSION_INFO_get0_addProfessionInfo');
    {$ifend}
  end;
  
  PROFESSION_INFO_set0_addProfessionInfo := LoadLibFunction(ADllHandle, PROFESSION_INFO_set0_addProfessionInfo_procname);
  FuncLoadError := not assigned(PROFESSION_INFO_set0_addProfessionInfo);
  if FuncLoadError then
  begin
    {$if not defined(PROFESSION_INFO_set0_addProfessionInfo_allownil)}
    PROFESSION_INFO_set0_addProfessionInfo := ERR_PROFESSION_INFO_set0_addProfessionInfo;
    {$ifend}
    {$if declared(PROFESSION_INFO_set0_addProfessionInfo_introduced)}
    if LibVersion < PROFESSION_INFO_set0_addProfessionInfo_introduced then
    begin
      {$if declared(FC_PROFESSION_INFO_set0_addProfessionInfo)}
      PROFESSION_INFO_set0_addProfessionInfo := FC_PROFESSION_INFO_set0_addProfessionInfo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROFESSION_INFO_set0_addProfessionInfo_removed)}
    if PROFESSION_INFO_set0_addProfessionInfo_removed <= LibVersion then
    begin
      {$if declared(_PROFESSION_INFO_set0_addProfessionInfo)}
      PROFESSION_INFO_set0_addProfessionInfo := _PROFESSION_INFO_set0_addProfessionInfo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROFESSION_INFO_set0_addProfessionInfo_allownil)}
    if FuncLoadError then
      AFailed.Add('PROFESSION_INFO_set0_addProfessionInfo');
    {$ifend}
  end;
  
  PROFESSION_INFO_get0_namingAuthority := LoadLibFunction(ADllHandle, PROFESSION_INFO_get0_namingAuthority_procname);
  FuncLoadError := not assigned(PROFESSION_INFO_get0_namingAuthority);
  if FuncLoadError then
  begin
    {$if not defined(PROFESSION_INFO_get0_namingAuthority_allownil)}
    PROFESSION_INFO_get0_namingAuthority := ERR_PROFESSION_INFO_get0_namingAuthority;
    {$ifend}
    {$if declared(PROFESSION_INFO_get0_namingAuthority_introduced)}
    if LibVersion < PROFESSION_INFO_get0_namingAuthority_introduced then
    begin
      {$if declared(FC_PROFESSION_INFO_get0_namingAuthority)}
      PROFESSION_INFO_get0_namingAuthority := FC_PROFESSION_INFO_get0_namingAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROFESSION_INFO_get0_namingAuthority_removed)}
    if PROFESSION_INFO_get0_namingAuthority_removed <= LibVersion then
    begin
      {$if declared(_PROFESSION_INFO_get0_namingAuthority)}
      PROFESSION_INFO_get0_namingAuthority := _PROFESSION_INFO_get0_namingAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROFESSION_INFO_get0_namingAuthority_allownil)}
    if FuncLoadError then
      AFailed.Add('PROFESSION_INFO_get0_namingAuthority');
    {$ifend}
  end;
  
  PROFESSION_INFO_set0_namingAuthority := LoadLibFunction(ADllHandle, PROFESSION_INFO_set0_namingAuthority_procname);
  FuncLoadError := not assigned(PROFESSION_INFO_set0_namingAuthority);
  if FuncLoadError then
  begin
    {$if not defined(PROFESSION_INFO_set0_namingAuthority_allownil)}
    PROFESSION_INFO_set0_namingAuthority := ERR_PROFESSION_INFO_set0_namingAuthority;
    {$ifend}
    {$if declared(PROFESSION_INFO_set0_namingAuthority_introduced)}
    if LibVersion < PROFESSION_INFO_set0_namingAuthority_introduced then
    begin
      {$if declared(FC_PROFESSION_INFO_set0_namingAuthority)}
      PROFESSION_INFO_set0_namingAuthority := FC_PROFESSION_INFO_set0_namingAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROFESSION_INFO_set0_namingAuthority_removed)}
    if PROFESSION_INFO_set0_namingAuthority_removed <= LibVersion then
    begin
      {$if declared(_PROFESSION_INFO_set0_namingAuthority)}
      PROFESSION_INFO_set0_namingAuthority := _PROFESSION_INFO_set0_namingAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROFESSION_INFO_set0_namingAuthority_allownil)}
    if FuncLoadError then
      AFailed.Add('PROFESSION_INFO_set0_namingAuthority');
    {$ifend}
  end;
  
  PROFESSION_INFO_get0_professionItems := LoadLibFunction(ADllHandle, PROFESSION_INFO_get0_professionItems_procname);
  FuncLoadError := not assigned(PROFESSION_INFO_get0_professionItems);
  if FuncLoadError then
  begin
    {$if not defined(PROFESSION_INFO_get0_professionItems_allownil)}
    PROFESSION_INFO_get0_professionItems := ERR_PROFESSION_INFO_get0_professionItems;
    {$ifend}
    {$if declared(PROFESSION_INFO_get0_professionItems_introduced)}
    if LibVersion < PROFESSION_INFO_get0_professionItems_introduced then
    begin
      {$if declared(FC_PROFESSION_INFO_get0_professionItems)}
      PROFESSION_INFO_get0_professionItems := FC_PROFESSION_INFO_get0_professionItems;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROFESSION_INFO_get0_professionItems_removed)}
    if PROFESSION_INFO_get0_professionItems_removed <= LibVersion then
    begin
      {$if declared(_PROFESSION_INFO_get0_professionItems)}
      PROFESSION_INFO_get0_professionItems := _PROFESSION_INFO_get0_professionItems;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROFESSION_INFO_get0_professionItems_allownil)}
    if FuncLoadError then
      AFailed.Add('PROFESSION_INFO_get0_professionItems');
    {$ifend}
  end;
  
  PROFESSION_INFO_set0_professionItems := LoadLibFunction(ADllHandle, PROFESSION_INFO_set0_professionItems_procname);
  FuncLoadError := not assigned(PROFESSION_INFO_set0_professionItems);
  if FuncLoadError then
  begin
    {$if not defined(PROFESSION_INFO_set0_professionItems_allownil)}
    PROFESSION_INFO_set0_professionItems := ERR_PROFESSION_INFO_set0_professionItems;
    {$ifend}
    {$if declared(PROFESSION_INFO_set0_professionItems_introduced)}
    if LibVersion < PROFESSION_INFO_set0_professionItems_introduced then
    begin
      {$if declared(FC_PROFESSION_INFO_set0_professionItems)}
      PROFESSION_INFO_set0_professionItems := FC_PROFESSION_INFO_set0_professionItems;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROFESSION_INFO_set0_professionItems_removed)}
    if PROFESSION_INFO_set0_professionItems_removed <= LibVersion then
    begin
      {$if declared(_PROFESSION_INFO_set0_professionItems)}
      PROFESSION_INFO_set0_professionItems := _PROFESSION_INFO_set0_professionItems;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROFESSION_INFO_set0_professionItems_allownil)}
    if FuncLoadError then
      AFailed.Add('PROFESSION_INFO_set0_professionItems');
    {$ifend}
  end;
  
  PROFESSION_INFO_get0_professionOIDs := LoadLibFunction(ADllHandle, PROFESSION_INFO_get0_professionOIDs_procname);
  FuncLoadError := not assigned(PROFESSION_INFO_get0_professionOIDs);
  if FuncLoadError then
  begin
    {$if not defined(PROFESSION_INFO_get0_professionOIDs_allownil)}
    PROFESSION_INFO_get0_professionOIDs := ERR_PROFESSION_INFO_get0_professionOIDs;
    {$ifend}
    {$if declared(PROFESSION_INFO_get0_professionOIDs_introduced)}
    if LibVersion < PROFESSION_INFO_get0_professionOIDs_introduced then
    begin
      {$if declared(FC_PROFESSION_INFO_get0_professionOIDs)}
      PROFESSION_INFO_get0_professionOIDs := FC_PROFESSION_INFO_get0_professionOIDs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROFESSION_INFO_get0_professionOIDs_removed)}
    if PROFESSION_INFO_get0_professionOIDs_removed <= LibVersion then
    begin
      {$if declared(_PROFESSION_INFO_get0_professionOIDs)}
      PROFESSION_INFO_get0_professionOIDs := _PROFESSION_INFO_get0_professionOIDs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROFESSION_INFO_get0_professionOIDs_allownil)}
    if FuncLoadError then
      AFailed.Add('PROFESSION_INFO_get0_professionOIDs');
    {$ifend}
  end;
  
  PROFESSION_INFO_set0_professionOIDs := LoadLibFunction(ADllHandle, PROFESSION_INFO_set0_professionOIDs_procname);
  FuncLoadError := not assigned(PROFESSION_INFO_set0_professionOIDs);
  if FuncLoadError then
  begin
    {$if not defined(PROFESSION_INFO_set0_professionOIDs_allownil)}
    PROFESSION_INFO_set0_professionOIDs := ERR_PROFESSION_INFO_set0_professionOIDs;
    {$ifend}
    {$if declared(PROFESSION_INFO_set0_professionOIDs_introduced)}
    if LibVersion < PROFESSION_INFO_set0_professionOIDs_introduced then
    begin
      {$if declared(FC_PROFESSION_INFO_set0_professionOIDs)}
      PROFESSION_INFO_set0_professionOIDs := FC_PROFESSION_INFO_set0_professionOIDs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROFESSION_INFO_set0_professionOIDs_removed)}
    if PROFESSION_INFO_set0_professionOIDs_removed <= LibVersion then
    begin
      {$if declared(_PROFESSION_INFO_set0_professionOIDs)}
      PROFESSION_INFO_set0_professionOIDs := _PROFESSION_INFO_set0_professionOIDs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROFESSION_INFO_set0_professionOIDs_allownil)}
    if FuncLoadError then
      AFailed.Add('PROFESSION_INFO_set0_professionOIDs');
    {$ifend}
  end;
  
  PROFESSION_INFO_get0_registrationNumber := LoadLibFunction(ADllHandle, PROFESSION_INFO_get0_registrationNumber_procname);
  FuncLoadError := not assigned(PROFESSION_INFO_get0_registrationNumber);
  if FuncLoadError then
  begin
    {$if not defined(PROFESSION_INFO_get0_registrationNumber_allownil)}
    PROFESSION_INFO_get0_registrationNumber := ERR_PROFESSION_INFO_get0_registrationNumber;
    {$ifend}
    {$if declared(PROFESSION_INFO_get0_registrationNumber_introduced)}
    if LibVersion < PROFESSION_INFO_get0_registrationNumber_introduced then
    begin
      {$if declared(FC_PROFESSION_INFO_get0_registrationNumber)}
      PROFESSION_INFO_get0_registrationNumber := FC_PROFESSION_INFO_get0_registrationNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROFESSION_INFO_get0_registrationNumber_removed)}
    if PROFESSION_INFO_get0_registrationNumber_removed <= LibVersion then
    begin
      {$if declared(_PROFESSION_INFO_get0_registrationNumber)}
      PROFESSION_INFO_get0_registrationNumber := _PROFESSION_INFO_get0_registrationNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROFESSION_INFO_get0_registrationNumber_allownil)}
    if FuncLoadError then
      AFailed.Add('PROFESSION_INFO_get0_registrationNumber');
    {$ifend}
  end;
  
  PROFESSION_INFO_set0_registrationNumber := LoadLibFunction(ADllHandle, PROFESSION_INFO_set0_registrationNumber_procname);
  FuncLoadError := not assigned(PROFESSION_INFO_set0_registrationNumber);
  if FuncLoadError then
  begin
    {$if not defined(PROFESSION_INFO_set0_registrationNumber_allownil)}
    PROFESSION_INFO_set0_registrationNumber := ERR_PROFESSION_INFO_set0_registrationNumber;
    {$ifend}
    {$if declared(PROFESSION_INFO_set0_registrationNumber_introduced)}
    if LibVersion < PROFESSION_INFO_set0_registrationNumber_introduced then
    begin
      {$if declared(FC_PROFESSION_INFO_set0_registrationNumber)}
      PROFESSION_INFO_set0_registrationNumber := FC_PROFESSION_INFO_set0_registrationNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROFESSION_INFO_set0_registrationNumber_removed)}
    if PROFESSION_INFO_set0_registrationNumber_removed <= LibVersion then
    begin
      {$if declared(_PROFESSION_INFO_set0_registrationNumber)}
      PROFESSION_INFO_set0_registrationNumber := _PROFESSION_INFO_set0_registrationNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROFESSION_INFO_set0_registrationNumber_allownil)}
    if FuncLoadError then
      AFailed.Add('PROFESSION_INFO_set0_registrationNumber');
    {$ifend}
  end;
  
  OSSL_GENERAL_NAMES_print := LoadLibFunction(ADllHandle, OSSL_GENERAL_NAMES_print_procname);
  FuncLoadError := not assigned(OSSL_GENERAL_NAMES_print);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_GENERAL_NAMES_print_allownil)}
    OSSL_GENERAL_NAMES_print := ERR_OSSL_GENERAL_NAMES_print;
    {$ifend}
    {$if declared(OSSL_GENERAL_NAMES_print_introduced)}
    if LibVersion < OSSL_GENERAL_NAMES_print_introduced then
    begin
      {$if declared(FC_OSSL_GENERAL_NAMES_print)}
      OSSL_GENERAL_NAMES_print := FC_OSSL_GENERAL_NAMES_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_GENERAL_NAMES_print_removed)}
    if OSSL_GENERAL_NAMES_print_removed <= LibVersion then
    begin
      {$if declared(_OSSL_GENERAL_NAMES_print)}
      OSSL_GENERAL_NAMES_print := _OSSL_GENERAL_NAMES_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_GENERAL_NAMES_print_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_GENERAL_NAMES_print');
    {$ifend}
  end;
  
  OSSL_ATTRIBUTES_SYNTAX_new := LoadLibFunction(ADllHandle, OSSL_ATTRIBUTES_SYNTAX_new_procname);
  FuncLoadError := not assigned(OSSL_ATTRIBUTES_SYNTAX_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ATTRIBUTES_SYNTAX_new_allownil)}
    OSSL_ATTRIBUTES_SYNTAX_new := ERR_OSSL_ATTRIBUTES_SYNTAX_new;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTES_SYNTAX_new_introduced)}
    if LibVersion < OSSL_ATTRIBUTES_SYNTAX_new_introduced then
    begin
      {$if declared(FC_OSSL_ATTRIBUTES_SYNTAX_new)}
      OSSL_ATTRIBUTES_SYNTAX_new := FC_OSSL_ATTRIBUTES_SYNTAX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTES_SYNTAX_new_removed)}
    if OSSL_ATTRIBUTES_SYNTAX_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ATTRIBUTES_SYNTAX_new)}
      OSSL_ATTRIBUTES_SYNTAX_new := _OSSL_ATTRIBUTES_SYNTAX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ATTRIBUTES_SYNTAX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ATTRIBUTES_SYNTAX_new');
    {$ifend}
  end;
  
  OSSL_ATTRIBUTES_SYNTAX_free := LoadLibFunction(ADllHandle, OSSL_ATTRIBUTES_SYNTAX_free_procname);
  FuncLoadError := not assigned(OSSL_ATTRIBUTES_SYNTAX_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ATTRIBUTES_SYNTAX_free_allownil)}
    OSSL_ATTRIBUTES_SYNTAX_free := ERR_OSSL_ATTRIBUTES_SYNTAX_free;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTES_SYNTAX_free_introduced)}
    if LibVersion < OSSL_ATTRIBUTES_SYNTAX_free_introduced then
    begin
      {$if declared(FC_OSSL_ATTRIBUTES_SYNTAX_free)}
      OSSL_ATTRIBUTES_SYNTAX_free := FC_OSSL_ATTRIBUTES_SYNTAX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTES_SYNTAX_free_removed)}
    if OSSL_ATTRIBUTES_SYNTAX_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ATTRIBUTES_SYNTAX_free)}
      OSSL_ATTRIBUTES_SYNTAX_free := _OSSL_ATTRIBUTES_SYNTAX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ATTRIBUTES_SYNTAX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ATTRIBUTES_SYNTAX_free');
    {$ifend}
  end;
  
  d2i_OSSL_ATTRIBUTES_SYNTAX := LoadLibFunction(ADllHandle, d2i_OSSL_ATTRIBUTES_SYNTAX_procname);
  FuncLoadError := not assigned(d2i_OSSL_ATTRIBUTES_SYNTAX);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_ATTRIBUTES_SYNTAX_allownil)}
    d2i_OSSL_ATTRIBUTES_SYNTAX := ERR_d2i_OSSL_ATTRIBUTES_SYNTAX;
    {$ifend}
    {$if declared(d2i_OSSL_ATTRIBUTES_SYNTAX_introduced)}
    if LibVersion < d2i_OSSL_ATTRIBUTES_SYNTAX_introduced then
    begin
      {$if declared(FC_d2i_OSSL_ATTRIBUTES_SYNTAX)}
      d2i_OSSL_ATTRIBUTES_SYNTAX := FC_d2i_OSSL_ATTRIBUTES_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_ATTRIBUTES_SYNTAX_removed)}
    if d2i_OSSL_ATTRIBUTES_SYNTAX_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_ATTRIBUTES_SYNTAX)}
      d2i_OSSL_ATTRIBUTES_SYNTAX := _d2i_OSSL_ATTRIBUTES_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_ATTRIBUTES_SYNTAX_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_ATTRIBUTES_SYNTAX');
    {$ifend}
  end;
  
  i2d_OSSL_ATTRIBUTES_SYNTAX := LoadLibFunction(ADllHandle, i2d_OSSL_ATTRIBUTES_SYNTAX_procname);
  FuncLoadError := not assigned(i2d_OSSL_ATTRIBUTES_SYNTAX);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_ATTRIBUTES_SYNTAX_allownil)}
    i2d_OSSL_ATTRIBUTES_SYNTAX := ERR_i2d_OSSL_ATTRIBUTES_SYNTAX;
    {$ifend}
    {$if declared(i2d_OSSL_ATTRIBUTES_SYNTAX_introduced)}
    if LibVersion < i2d_OSSL_ATTRIBUTES_SYNTAX_introduced then
    begin
      {$if declared(FC_i2d_OSSL_ATTRIBUTES_SYNTAX)}
      i2d_OSSL_ATTRIBUTES_SYNTAX := FC_i2d_OSSL_ATTRIBUTES_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_ATTRIBUTES_SYNTAX_removed)}
    if i2d_OSSL_ATTRIBUTES_SYNTAX_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_ATTRIBUTES_SYNTAX)}
      i2d_OSSL_ATTRIBUTES_SYNTAX := _i2d_OSSL_ATTRIBUTES_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_ATTRIBUTES_SYNTAX_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_ATTRIBUTES_SYNTAX');
    {$ifend}
  end;
  
  OSSL_ATTRIBUTES_SYNTAX_it := LoadLibFunction(ADllHandle, OSSL_ATTRIBUTES_SYNTAX_it_procname);
  FuncLoadError := not assigned(OSSL_ATTRIBUTES_SYNTAX_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ATTRIBUTES_SYNTAX_it_allownil)}
    OSSL_ATTRIBUTES_SYNTAX_it := ERR_OSSL_ATTRIBUTES_SYNTAX_it;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTES_SYNTAX_it_introduced)}
    if LibVersion < OSSL_ATTRIBUTES_SYNTAX_it_introduced then
    begin
      {$if declared(FC_OSSL_ATTRIBUTES_SYNTAX_it)}
      OSSL_ATTRIBUTES_SYNTAX_it := FC_OSSL_ATTRIBUTES_SYNTAX_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTES_SYNTAX_it_removed)}
    if OSSL_ATTRIBUTES_SYNTAX_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ATTRIBUTES_SYNTAX_it)}
      OSSL_ATTRIBUTES_SYNTAX_it := _OSSL_ATTRIBUTES_SYNTAX_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ATTRIBUTES_SYNTAX_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ATTRIBUTES_SYNTAX_it');
    {$ifend}
  end;
  
  OSSL_USER_NOTICE_SYNTAX_new := LoadLibFunction(ADllHandle, OSSL_USER_NOTICE_SYNTAX_new_procname);
  FuncLoadError := not assigned(OSSL_USER_NOTICE_SYNTAX_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_USER_NOTICE_SYNTAX_new_allownil)}
    OSSL_USER_NOTICE_SYNTAX_new := ERR_OSSL_USER_NOTICE_SYNTAX_new;
    {$ifend}
    {$if declared(OSSL_USER_NOTICE_SYNTAX_new_introduced)}
    if LibVersion < OSSL_USER_NOTICE_SYNTAX_new_introduced then
    begin
      {$if declared(FC_OSSL_USER_NOTICE_SYNTAX_new)}
      OSSL_USER_NOTICE_SYNTAX_new := FC_OSSL_USER_NOTICE_SYNTAX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_USER_NOTICE_SYNTAX_new_removed)}
    if OSSL_USER_NOTICE_SYNTAX_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_USER_NOTICE_SYNTAX_new)}
      OSSL_USER_NOTICE_SYNTAX_new := _OSSL_USER_NOTICE_SYNTAX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_USER_NOTICE_SYNTAX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_USER_NOTICE_SYNTAX_new');
    {$ifend}
  end;
  
  OSSL_USER_NOTICE_SYNTAX_free := LoadLibFunction(ADllHandle, OSSL_USER_NOTICE_SYNTAX_free_procname);
  FuncLoadError := not assigned(OSSL_USER_NOTICE_SYNTAX_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_USER_NOTICE_SYNTAX_free_allownil)}
    OSSL_USER_NOTICE_SYNTAX_free := ERR_OSSL_USER_NOTICE_SYNTAX_free;
    {$ifend}
    {$if declared(OSSL_USER_NOTICE_SYNTAX_free_introduced)}
    if LibVersion < OSSL_USER_NOTICE_SYNTAX_free_introduced then
    begin
      {$if declared(FC_OSSL_USER_NOTICE_SYNTAX_free)}
      OSSL_USER_NOTICE_SYNTAX_free := FC_OSSL_USER_NOTICE_SYNTAX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_USER_NOTICE_SYNTAX_free_removed)}
    if OSSL_USER_NOTICE_SYNTAX_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_USER_NOTICE_SYNTAX_free)}
      OSSL_USER_NOTICE_SYNTAX_free := _OSSL_USER_NOTICE_SYNTAX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_USER_NOTICE_SYNTAX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_USER_NOTICE_SYNTAX_free');
    {$ifend}
  end;
  
  d2i_OSSL_USER_NOTICE_SYNTAX := LoadLibFunction(ADllHandle, d2i_OSSL_USER_NOTICE_SYNTAX_procname);
  FuncLoadError := not assigned(d2i_OSSL_USER_NOTICE_SYNTAX);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_USER_NOTICE_SYNTAX_allownil)}
    d2i_OSSL_USER_NOTICE_SYNTAX := ERR_d2i_OSSL_USER_NOTICE_SYNTAX;
    {$ifend}
    {$if declared(d2i_OSSL_USER_NOTICE_SYNTAX_introduced)}
    if LibVersion < d2i_OSSL_USER_NOTICE_SYNTAX_introduced then
    begin
      {$if declared(FC_d2i_OSSL_USER_NOTICE_SYNTAX)}
      d2i_OSSL_USER_NOTICE_SYNTAX := FC_d2i_OSSL_USER_NOTICE_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_USER_NOTICE_SYNTAX_removed)}
    if d2i_OSSL_USER_NOTICE_SYNTAX_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_USER_NOTICE_SYNTAX)}
      d2i_OSSL_USER_NOTICE_SYNTAX := _d2i_OSSL_USER_NOTICE_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_USER_NOTICE_SYNTAX_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_USER_NOTICE_SYNTAX');
    {$ifend}
  end;
  
  i2d_OSSL_USER_NOTICE_SYNTAX := LoadLibFunction(ADllHandle, i2d_OSSL_USER_NOTICE_SYNTAX_procname);
  FuncLoadError := not assigned(i2d_OSSL_USER_NOTICE_SYNTAX);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_USER_NOTICE_SYNTAX_allownil)}
    i2d_OSSL_USER_NOTICE_SYNTAX := ERR_i2d_OSSL_USER_NOTICE_SYNTAX;
    {$ifend}
    {$if declared(i2d_OSSL_USER_NOTICE_SYNTAX_introduced)}
    if LibVersion < i2d_OSSL_USER_NOTICE_SYNTAX_introduced then
    begin
      {$if declared(FC_i2d_OSSL_USER_NOTICE_SYNTAX)}
      i2d_OSSL_USER_NOTICE_SYNTAX := FC_i2d_OSSL_USER_NOTICE_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_USER_NOTICE_SYNTAX_removed)}
    if i2d_OSSL_USER_NOTICE_SYNTAX_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_USER_NOTICE_SYNTAX)}
      i2d_OSSL_USER_NOTICE_SYNTAX := _i2d_OSSL_USER_NOTICE_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_USER_NOTICE_SYNTAX_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_USER_NOTICE_SYNTAX');
    {$ifend}
  end;
  
  OSSL_USER_NOTICE_SYNTAX_it := LoadLibFunction(ADllHandle, OSSL_USER_NOTICE_SYNTAX_it_procname);
  FuncLoadError := not assigned(OSSL_USER_NOTICE_SYNTAX_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_USER_NOTICE_SYNTAX_it_allownil)}
    OSSL_USER_NOTICE_SYNTAX_it := ERR_OSSL_USER_NOTICE_SYNTAX_it;
    {$ifend}
    {$if declared(OSSL_USER_NOTICE_SYNTAX_it_introduced)}
    if LibVersion < OSSL_USER_NOTICE_SYNTAX_it_introduced then
    begin
      {$if declared(FC_OSSL_USER_NOTICE_SYNTAX_it)}
      OSSL_USER_NOTICE_SYNTAX_it := FC_OSSL_USER_NOTICE_SYNTAX_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_USER_NOTICE_SYNTAX_it_removed)}
    if OSSL_USER_NOTICE_SYNTAX_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_USER_NOTICE_SYNTAX_it)}
      OSSL_USER_NOTICE_SYNTAX_it := _OSSL_USER_NOTICE_SYNTAX_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_USER_NOTICE_SYNTAX_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_USER_NOTICE_SYNTAX_it');
    {$ifend}
  end;
  
  OSSL_ROLE_SPEC_CERT_ID_new := LoadLibFunction(ADllHandle, OSSL_ROLE_SPEC_CERT_ID_new_procname);
  FuncLoadError := not assigned(OSSL_ROLE_SPEC_CERT_ID_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ROLE_SPEC_CERT_ID_new_allownil)}
    OSSL_ROLE_SPEC_CERT_ID_new := ERR_OSSL_ROLE_SPEC_CERT_ID_new;
    {$ifend}
    {$if declared(OSSL_ROLE_SPEC_CERT_ID_new_introduced)}
    if LibVersion < OSSL_ROLE_SPEC_CERT_ID_new_introduced then
    begin
      {$if declared(FC_OSSL_ROLE_SPEC_CERT_ID_new)}
      OSSL_ROLE_SPEC_CERT_ID_new := FC_OSSL_ROLE_SPEC_CERT_ID_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ROLE_SPEC_CERT_ID_new_removed)}
    if OSSL_ROLE_SPEC_CERT_ID_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ROLE_SPEC_CERT_ID_new)}
      OSSL_ROLE_SPEC_CERT_ID_new := _OSSL_ROLE_SPEC_CERT_ID_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ROLE_SPEC_CERT_ID_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ROLE_SPEC_CERT_ID_new');
    {$ifend}
  end;
  
  OSSL_ROLE_SPEC_CERT_ID_free := LoadLibFunction(ADllHandle, OSSL_ROLE_SPEC_CERT_ID_free_procname);
  FuncLoadError := not assigned(OSSL_ROLE_SPEC_CERT_ID_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ROLE_SPEC_CERT_ID_free_allownil)}
    OSSL_ROLE_SPEC_CERT_ID_free := ERR_OSSL_ROLE_SPEC_CERT_ID_free;
    {$ifend}
    {$if declared(OSSL_ROLE_SPEC_CERT_ID_free_introduced)}
    if LibVersion < OSSL_ROLE_SPEC_CERT_ID_free_introduced then
    begin
      {$if declared(FC_OSSL_ROLE_SPEC_CERT_ID_free)}
      OSSL_ROLE_SPEC_CERT_ID_free := FC_OSSL_ROLE_SPEC_CERT_ID_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ROLE_SPEC_CERT_ID_free_removed)}
    if OSSL_ROLE_SPEC_CERT_ID_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ROLE_SPEC_CERT_ID_free)}
      OSSL_ROLE_SPEC_CERT_ID_free := _OSSL_ROLE_SPEC_CERT_ID_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ROLE_SPEC_CERT_ID_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ROLE_SPEC_CERT_ID_free');
    {$ifend}
  end;
  
  d2i_OSSL_ROLE_SPEC_CERT_ID := LoadLibFunction(ADllHandle, d2i_OSSL_ROLE_SPEC_CERT_ID_procname);
  FuncLoadError := not assigned(d2i_OSSL_ROLE_SPEC_CERT_ID);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_ROLE_SPEC_CERT_ID_allownil)}
    d2i_OSSL_ROLE_SPEC_CERT_ID := ERR_d2i_OSSL_ROLE_SPEC_CERT_ID;
    {$ifend}
    {$if declared(d2i_OSSL_ROLE_SPEC_CERT_ID_introduced)}
    if LibVersion < d2i_OSSL_ROLE_SPEC_CERT_ID_introduced then
    begin
      {$if declared(FC_d2i_OSSL_ROLE_SPEC_CERT_ID)}
      d2i_OSSL_ROLE_SPEC_CERT_ID := FC_d2i_OSSL_ROLE_SPEC_CERT_ID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_ROLE_SPEC_CERT_ID_removed)}
    if d2i_OSSL_ROLE_SPEC_CERT_ID_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_ROLE_SPEC_CERT_ID)}
      d2i_OSSL_ROLE_SPEC_CERT_ID := _d2i_OSSL_ROLE_SPEC_CERT_ID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_ROLE_SPEC_CERT_ID_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_ROLE_SPEC_CERT_ID');
    {$ifend}
  end;
  
  i2d_OSSL_ROLE_SPEC_CERT_ID := LoadLibFunction(ADllHandle, i2d_OSSL_ROLE_SPEC_CERT_ID_procname);
  FuncLoadError := not assigned(i2d_OSSL_ROLE_SPEC_CERT_ID);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_ROLE_SPEC_CERT_ID_allownil)}
    i2d_OSSL_ROLE_SPEC_CERT_ID := ERR_i2d_OSSL_ROLE_SPEC_CERT_ID;
    {$ifend}
    {$if declared(i2d_OSSL_ROLE_SPEC_CERT_ID_introduced)}
    if LibVersion < i2d_OSSL_ROLE_SPEC_CERT_ID_introduced then
    begin
      {$if declared(FC_i2d_OSSL_ROLE_SPEC_CERT_ID)}
      i2d_OSSL_ROLE_SPEC_CERT_ID := FC_i2d_OSSL_ROLE_SPEC_CERT_ID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_ROLE_SPEC_CERT_ID_removed)}
    if i2d_OSSL_ROLE_SPEC_CERT_ID_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_ROLE_SPEC_CERT_ID)}
      i2d_OSSL_ROLE_SPEC_CERT_ID := _i2d_OSSL_ROLE_SPEC_CERT_ID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_ROLE_SPEC_CERT_ID_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_ROLE_SPEC_CERT_ID');
    {$ifend}
  end;
  
  OSSL_ROLE_SPEC_CERT_ID_it := LoadLibFunction(ADllHandle, OSSL_ROLE_SPEC_CERT_ID_it_procname);
  FuncLoadError := not assigned(OSSL_ROLE_SPEC_CERT_ID_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ROLE_SPEC_CERT_ID_it_allownil)}
    OSSL_ROLE_SPEC_CERT_ID_it := ERR_OSSL_ROLE_SPEC_CERT_ID_it;
    {$ifend}
    {$if declared(OSSL_ROLE_SPEC_CERT_ID_it_introduced)}
    if LibVersion < OSSL_ROLE_SPEC_CERT_ID_it_introduced then
    begin
      {$if declared(FC_OSSL_ROLE_SPEC_CERT_ID_it)}
      OSSL_ROLE_SPEC_CERT_ID_it := FC_OSSL_ROLE_SPEC_CERT_ID_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ROLE_SPEC_CERT_ID_it_removed)}
    if OSSL_ROLE_SPEC_CERT_ID_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ROLE_SPEC_CERT_ID_it)}
      OSSL_ROLE_SPEC_CERT_ID_it := _OSSL_ROLE_SPEC_CERT_ID_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ROLE_SPEC_CERT_ID_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ROLE_SPEC_CERT_ID_it');
    {$ifend}
  end;
  
  OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new := LoadLibFunction(ADllHandle, OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new_procname);
  FuncLoadError := not assigned(OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new_allownil)}
    OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new := ERR_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new;
    {$ifend}
    {$if declared(OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new_introduced)}
    if LibVersion < OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new_introduced then
    begin
      {$if declared(FC_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new)}
      OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new := FC_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new_removed)}
    if OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new)}
      OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new := _OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new');
    {$ifend}
  end;
  
  OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free := LoadLibFunction(ADllHandle, OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free_procname);
  FuncLoadError := not assigned(OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free_allownil)}
    OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free := ERR_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free;
    {$ifend}
    {$if declared(OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free_introduced)}
    if LibVersion < OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free_introduced then
    begin
      {$if declared(FC_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free)}
      OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free := FC_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free_removed)}
    if OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free)}
      OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free := _OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free');
    {$ifend}
  end;
  
  d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX := LoadLibFunction(ADllHandle, d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_procname);
  FuncLoadError := not assigned(d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_allownil)}
    d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX := ERR_d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX;
    {$ifend}
    {$if declared(d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_introduced)}
    if LibVersion < d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_introduced then
    begin
      {$if declared(FC_d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX)}
      d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX := FC_d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_removed)}
    if d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX)}
      d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX := _d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX');
    {$ifend}
  end;
  
  i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX := LoadLibFunction(ADllHandle, i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_procname);
  FuncLoadError := not assigned(i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_allownil)}
    i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX := ERR_i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX;
    {$ifend}
    {$if declared(i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_introduced)}
    if LibVersion < i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_introduced then
    begin
      {$if declared(FC_i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX)}
      i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX := FC_i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_removed)}
    if i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX)}
      i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX := _i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX');
    {$ifend}
  end;
  
  OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it := LoadLibFunction(ADllHandle, OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it_procname);
  FuncLoadError := not assigned(OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it_allownil)}
    OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it := ERR_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it;
    {$ifend}
    {$if declared(OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it_introduced)}
    if LibVersion < OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it_introduced then
    begin
      {$if declared(FC_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it)}
      OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it := FC_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it_removed)}
    if OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it)}
      OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it := _OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it');
    {$ifend}
  end;
  
  OSSL_HASH_new := LoadLibFunction(ADllHandle, OSSL_HASH_new_procname);
  FuncLoadError := not assigned(OSSL_HASH_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HASH_new_allownil)}
    OSSL_HASH_new := ERR_OSSL_HASH_new;
    {$ifend}
    {$if declared(OSSL_HASH_new_introduced)}
    if LibVersion < OSSL_HASH_new_introduced then
    begin
      {$if declared(FC_OSSL_HASH_new)}
      OSSL_HASH_new := FC_OSSL_HASH_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HASH_new_removed)}
    if OSSL_HASH_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HASH_new)}
      OSSL_HASH_new := _OSSL_HASH_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HASH_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HASH_new');
    {$ifend}
  end;
  
  OSSL_HASH_free := LoadLibFunction(ADllHandle, OSSL_HASH_free_procname);
  FuncLoadError := not assigned(OSSL_HASH_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HASH_free_allownil)}
    OSSL_HASH_free := ERR_OSSL_HASH_free;
    {$ifend}
    {$if declared(OSSL_HASH_free_introduced)}
    if LibVersion < OSSL_HASH_free_introduced then
    begin
      {$if declared(FC_OSSL_HASH_free)}
      OSSL_HASH_free := FC_OSSL_HASH_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HASH_free_removed)}
    if OSSL_HASH_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HASH_free)}
      OSSL_HASH_free := _OSSL_HASH_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HASH_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HASH_free');
    {$ifend}
  end;
  
  d2i_OSSL_HASH := LoadLibFunction(ADllHandle, d2i_OSSL_HASH_procname);
  FuncLoadError := not assigned(d2i_OSSL_HASH);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_HASH_allownil)}
    d2i_OSSL_HASH := ERR_d2i_OSSL_HASH;
    {$ifend}
    {$if declared(d2i_OSSL_HASH_introduced)}
    if LibVersion < d2i_OSSL_HASH_introduced then
    begin
      {$if declared(FC_d2i_OSSL_HASH)}
      d2i_OSSL_HASH := FC_d2i_OSSL_HASH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_HASH_removed)}
    if d2i_OSSL_HASH_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_HASH)}
      d2i_OSSL_HASH := _d2i_OSSL_HASH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_HASH_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_HASH');
    {$ifend}
  end;
  
  i2d_OSSL_HASH := LoadLibFunction(ADllHandle, i2d_OSSL_HASH_procname);
  FuncLoadError := not assigned(i2d_OSSL_HASH);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_HASH_allownil)}
    i2d_OSSL_HASH := ERR_i2d_OSSL_HASH;
    {$ifend}
    {$if declared(i2d_OSSL_HASH_introduced)}
    if LibVersion < i2d_OSSL_HASH_introduced then
    begin
      {$if declared(FC_i2d_OSSL_HASH)}
      i2d_OSSL_HASH := FC_i2d_OSSL_HASH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_HASH_removed)}
    if i2d_OSSL_HASH_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_HASH)}
      i2d_OSSL_HASH := _i2d_OSSL_HASH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_HASH_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_HASH');
    {$ifend}
  end;
  
  OSSL_HASH_it := LoadLibFunction(ADllHandle, OSSL_HASH_it_procname);
  FuncLoadError := not assigned(OSSL_HASH_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HASH_it_allownil)}
    OSSL_HASH_it := ERR_OSSL_HASH_it;
    {$ifend}
    {$if declared(OSSL_HASH_it_introduced)}
    if LibVersion < OSSL_HASH_it_introduced then
    begin
      {$if declared(FC_OSSL_HASH_it)}
      OSSL_HASH_it := FC_OSSL_HASH_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HASH_it_removed)}
    if OSSL_HASH_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HASH_it)}
      OSSL_HASH_it := _OSSL_HASH_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HASH_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HASH_it');
    {$ifend}
  end;
  
  OSSL_INFO_SYNTAX_new := LoadLibFunction(ADllHandle, OSSL_INFO_SYNTAX_new_procname);
  FuncLoadError := not assigned(OSSL_INFO_SYNTAX_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_INFO_SYNTAX_new_allownil)}
    OSSL_INFO_SYNTAX_new := ERR_OSSL_INFO_SYNTAX_new;
    {$ifend}
    {$if declared(OSSL_INFO_SYNTAX_new_introduced)}
    if LibVersion < OSSL_INFO_SYNTAX_new_introduced then
    begin
      {$if declared(FC_OSSL_INFO_SYNTAX_new)}
      OSSL_INFO_SYNTAX_new := FC_OSSL_INFO_SYNTAX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_INFO_SYNTAX_new_removed)}
    if OSSL_INFO_SYNTAX_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_INFO_SYNTAX_new)}
      OSSL_INFO_SYNTAX_new := _OSSL_INFO_SYNTAX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_INFO_SYNTAX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_INFO_SYNTAX_new');
    {$ifend}
  end;
  
  OSSL_INFO_SYNTAX_free := LoadLibFunction(ADllHandle, OSSL_INFO_SYNTAX_free_procname);
  FuncLoadError := not assigned(OSSL_INFO_SYNTAX_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_INFO_SYNTAX_free_allownil)}
    OSSL_INFO_SYNTAX_free := ERR_OSSL_INFO_SYNTAX_free;
    {$ifend}
    {$if declared(OSSL_INFO_SYNTAX_free_introduced)}
    if LibVersion < OSSL_INFO_SYNTAX_free_introduced then
    begin
      {$if declared(FC_OSSL_INFO_SYNTAX_free)}
      OSSL_INFO_SYNTAX_free := FC_OSSL_INFO_SYNTAX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_INFO_SYNTAX_free_removed)}
    if OSSL_INFO_SYNTAX_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_INFO_SYNTAX_free)}
      OSSL_INFO_SYNTAX_free := _OSSL_INFO_SYNTAX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_INFO_SYNTAX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_INFO_SYNTAX_free');
    {$ifend}
  end;
  
  d2i_OSSL_INFO_SYNTAX := LoadLibFunction(ADllHandle, d2i_OSSL_INFO_SYNTAX_procname);
  FuncLoadError := not assigned(d2i_OSSL_INFO_SYNTAX);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_INFO_SYNTAX_allownil)}
    d2i_OSSL_INFO_SYNTAX := ERR_d2i_OSSL_INFO_SYNTAX;
    {$ifend}
    {$if declared(d2i_OSSL_INFO_SYNTAX_introduced)}
    if LibVersion < d2i_OSSL_INFO_SYNTAX_introduced then
    begin
      {$if declared(FC_d2i_OSSL_INFO_SYNTAX)}
      d2i_OSSL_INFO_SYNTAX := FC_d2i_OSSL_INFO_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_INFO_SYNTAX_removed)}
    if d2i_OSSL_INFO_SYNTAX_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_INFO_SYNTAX)}
      d2i_OSSL_INFO_SYNTAX := _d2i_OSSL_INFO_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_INFO_SYNTAX_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_INFO_SYNTAX');
    {$ifend}
  end;
  
  i2d_OSSL_INFO_SYNTAX := LoadLibFunction(ADllHandle, i2d_OSSL_INFO_SYNTAX_procname);
  FuncLoadError := not assigned(i2d_OSSL_INFO_SYNTAX);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_INFO_SYNTAX_allownil)}
    i2d_OSSL_INFO_SYNTAX := ERR_i2d_OSSL_INFO_SYNTAX;
    {$ifend}
    {$if declared(i2d_OSSL_INFO_SYNTAX_introduced)}
    if LibVersion < i2d_OSSL_INFO_SYNTAX_introduced then
    begin
      {$if declared(FC_i2d_OSSL_INFO_SYNTAX)}
      i2d_OSSL_INFO_SYNTAX := FC_i2d_OSSL_INFO_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_INFO_SYNTAX_removed)}
    if i2d_OSSL_INFO_SYNTAX_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_INFO_SYNTAX)}
      i2d_OSSL_INFO_SYNTAX := _i2d_OSSL_INFO_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_INFO_SYNTAX_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_INFO_SYNTAX');
    {$ifend}
  end;
  
  OSSL_INFO_SYNTAX_it := LoadLibFunction(ADllHandle, OSSL_INFO_SYNTAX_it_procname);
  FuncLoadError := not assigned(OSSL_INFO_SYNTAX_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_INFO_SYNTAX_it_allownil)}
    OSSL_INFO_SYNTAX_it := ERR_OSSL_INFO_SYNTAX_it;
    {$ifend}
    {$if declared(OSSL_INFO_SYNTAX_it_introduced)}
    if LibVersion < OSSL_INFO_SYNTAX_it_introduced then
    begin
      {$if declared(FC_OSSL_INFO_SYNTAX_it)}
      OSSL_INFO_SYNTAX_it := FC_OSSL_INFO_SYNTAX_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_INFO_SYNTAX_it_removed)}
    if OSSL_INFO_SYNTAX_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_INFO_SYNTAX_it)}
      OSSL_INFO_SYNTAX_it := _OSSL_INFO_SYNTAX_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_INFO_SYNTAX_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_INFO_SYNTAX_it');
    {$ifend}
  end;
  
  OSSL_INFO_SYNTAX_POINTER_new := LoadLibFunction(ADllHandle, OSSL_INFO_SYNTAX_POINTER_new_procname);
  FuncLoadError := not assigned(OSSL_INFO_SYNTAX_POINTER_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_INFO_SYNTAX_POINTER_new_allownil)}
    OSSL_INFO_SYNTAX_POINTER_new := ERR_OSSL_INFO_SYNTAX_POINTER_new;
    {$ifend}
    {$if declared(OSSL_INFO_SYNTAX_POINTER_new_introduced)}
    if LibVersion < OSSL_INFO_SYNTAX_POINTER_new_introduced then
    begin
      {$if declared(FC_OSSL_INFO_SYNTAX_POINTER_new)}
      OSSL_INFO_SYNTAX_POINTER_new := FC_OSSL_INFO_SYNTAX_POINTER_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_INFO_SYNTAX_POINTER_new_removed)}
    if OSSL_INFO_SYNTAX_POINTER_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_INFO_SYNTAX_POINTER_new)}
      OSSL_INFO_SYNTAX_POINTER_new := _OSSL_INFO_SYNTAX_POINTER_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_INFO_SYNTAX_POINTER_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_INFO_SYNTAX_POINTER_new');
    {$ifend}
  end;
  
  OSSL_INFO_SYNTAX_POINTER_free := LoadLibFunction(ADllHandle, OSSL_INFO_SYNTAX_POINTER_free_procname);
  FuncLoadError := not assigned(OSSL_INFO_SYNTAX_POINTER_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_INFO_SYNTAX_POINTER_free_allownil)}
    OSSL_INFO_SYNTAX_POINTER_free := ERR_OSSL_INFO_SYNTAX_POINTER_free;
    {$ifend}
    {$if declared(OSSL_INFO_SYNTAX_POINTER_free_introduced)}
    if LibVersion < OSSL_INFO_SYNTAX_POINTER_free_introduced then
    begin
      {$if declared(FC_OSSL_INFO_SYNTAX_POINTER_free)}
      OSSL_INFO_SYNTAX_POINTER_free := FC_OSSL_INFO_SYNTAX_POINTER_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_INFO_SYNTAX_POINTER_free_removed)}
    if OSSL_INFO_SYNTAX_POINTER_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_INFO_SYNTAX_POINTER_free)}
      OSSL_INFO_SYNTAX_POINTER_free := _OSSL_INFO_SYNTAX_POINTER_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_INFO_SYNTAX_POINTER_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_INFO_SYNTAX_POINTER_free');
    {$ifend}
  end;
  
  d2i_OSSL_INFO_SYNTAX_POINTER := LoadLibFunction(ADllHandle, d2i_OSSL_INFO_SYNTAX_POINTER_procname);
  FuncLoadError := not assigned(d2i_OSSL_INFO_SYNTAX_POINTER);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_INFO_SYNTAX_POINTER_allownil)}
    d2i_OSSL_INFO_SYNTAX_POINTER := ERR_d2i_OSSL_INFO_SYNTAX_POINTER;
    {$ifend}
    {$if declared(d2i_OSSL_INFO_SYNTAX_POINTER_introduced)}
    if LibVersion < d2i_OSSL_INFO_SYNTAX_POINTER_introduced then
    begin
      {$if declared(FC_d2i_OSSL_INFO_SYNTAX_POINTER)}
      d2i_OSSL_INFO_SYNTAX_POINTER := FC_d2i_OSSL_INFO_SYNTAX_POINTER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_INFO_SYNTAX_POINTER_removed)}
    if d2i_OSSL_INFO_SYNTAX_POINTER_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_INFO_SYNTAX_POINTER)}
      d2i_OSSL_INFO_SYNTAX_POINTER := _d2i_OSSL_INFO_SYNTAX_POINTER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_INFO_SYNTAX_POINTER_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_INFO_SYNTAX_POINTER');
    {$ifend}
  end;
  
  i2d_OSSL_INFO_SYNTAX_POINTER := LoadLibFunction(ADllHandle, i2d_OSSL_INFO_SYNTAX_POINTER_procname);
  FuncLoadError := not assigned(i2d_OSSL_INFO_SYNTAX_POINTER);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_INFO_SYNTAX_POINTER_allownil)}
    i2d_OSSL_INFO_SYNTAX_POINTER := ERR_i2d_OSSL_INFO_SYNTAX_POINTER;
    {$ifend}
    {$if declared(i2d_OSSL_INFO_SYNTAX_POINTER_introduced)}
    if LibVersion < i2d_OSSL_INFO_SYNTAX_POINTER_introduced then
    begin
      {$if declared(FC_i2d_OSSL_INFO_SYNTAX_POINTER)}
      i2d_OSSL_INFO_SYNTAX_POINTER := FC_i2d_OSSL_INFO_SYNTAX_POINTER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_INFO_SYNTAX_POINTER_removed)}
    if i2d_OSSL_INFO_SYNTAX_POINTER_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_INFO_SYNTAX_POINTER)}
      i2d_OSSL_INFO_SYNTAX_POINTER := _i2d_OSSL_INFO_SYNTAX_POINTER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_INFO_SYNTAX_POINTER_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_INFO_SYNTAX_POINTER');
    {$ifend}
  end;
  
  OSSL_INFO_SYNTAX_POINTER_it := LoadLibFunction(ADllHandle, OSSL_INFO_SYNTAX_POINTER_it_procname);
  FuncLoadError := not assigned(OSSL_INFO_SYNTAX_POINTER_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_INFO_SYNTAX_POINTER_it_allownil)}
    OSSL_INFO_SYNTAX_POINTER_it := ERR_OSSL_INFO_SYNTAX_POINTER_it;
    {$ifend}
    {$if declared(OSSL_INFO_SYNTAX_POINTER_it_introduced)}
    if LibVersion < OSSL_INFO_SYNTAX_POINTER_it_introduced then
    begin
      {$if declared(FC_OSSL_INFO_SYNTAX_POINTER_it)}
      OSSL_INFO_SYNTAX_POINTER_it := FC_OSSL_INFO_SYNTAX_POINTER_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_INFO_SYNTAX_POINTER_it_removed)}
    if OSSL_INFO_SYNTAX_POINTER_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_INFO_SYNTAX_POINTER_it)}
      OSSL_INFO_SYNTAX_POINTER_it := _OSSL_INFO_SYNTAX_POINTER_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_INFO_SYNTAX_POINTER_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_INFO_SYNTAX_POINTER_it');
    {$ifend}
  end;
  
  OSSL_PRIVILEGE_POLICY_ID_new := LoadLibFunction(ADllHandle, OSSL_PRIVILEGE_POLICY_ID_new_procname);
  FuncLoadError := not assigned(OSSL_PRIVILEGE_POLICY_ID_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PRIVILEGE_POLICY_ID_new_allownil)}
    OSSL_PRIVILEGE_POLICY_ID_new := ERR_OSSL_PRIVILEGE_POLICY_ID_new;
    {$ifend}
    {$if declared(OSSL_PRIVILEGE_POLICY_ID_new_introduced)}
    if LibVersion < OSSL_PRIVILEGE_POLICY_ID_new_introduced then
    begin
      {$if declared(FC_OSSL_PRIVILEGE_POLICY_ID_new)}
      OSSL_PRIVILEGE_POLICY_ID_new := FC_OSSL_PRIVILEGE_POLICY_ID_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PRIVILEGE_POLICY_ID_new_removed)}
    if OSSL_PRIVILEGE_POLICY_ID_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PRIVILEGE_POLICY_ID_new)}
      OSSL_PRIVILEGE_POLICY_ID_new := _OSSL_PRIVILEGE_POLICY_ID_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PRIVILEGE_POLICY_ID_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PRIVILEGE_POLICY_ID_new');
    {$ifend}
  end;
  
  OSSL_PRIVILEGE_POLICY_ID_free := LoadLibFunction(ADllHandle, OSSL_PRIVILEGE_POLICY_ID_free_procname);
  FuncLoadError := not assigned(OSSL_PRIVILEGE_POLICY_ID_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PRIVILEGE_POLICY_ID_free_allownil)}
    OSSL_PRIVILEGE_POLICY_ID_free := ERR_OSSL_PRIVILEGE_POLICY_ID_free;
    {$ifend}
    {$if declared(OSSL_PRIVILEGE_POLICY_ID_free_introduced)}
    if LibVersion < OSSL_PRIVILEGE_POLICY_ID_free_introduced then
    begin
      {$if declared(FC_OSSL_PRIVILEGE_POLICY_ID_free)}
      OSSL_PRIVILEGE_POLICY_ID_free := FC_OSSL_PRIVILEGE_POLICY_ID_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PRIVILEGE_POLICY_ID_free_removed)}
    if OSSL_PRIVILEGE_POLICY_ID_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PRIVILEGE_POLICY_ID_free)}
      OSSL_PRIVILEGE_POLICY_ID_free := _OSSL_PRIVILEGE_POLICY_ID_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PRIVILEGE_POLICY_ID_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PRIVILEGE_POLICY_ID_free');
    {$ifend}
  end;
  
  d2i_OSSL_PRIVILEGE_POLICY_ID := LoadLibFunction(ADllHandle, d2i_OSSL_PRIVILEGE_POLICY_ID_procname);
  FuncLoadError := not assigned(d2i_OSSL_PRIVILEGE_POLICY_ID);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_PRIVILEGE_POLICY_ID_allownil)}
    d2i_OSSL_PRIVILEGE_POLICY_ID := ERR_d2i_OSSL_PRIVILEGE_POLICY_ID;
    {$ifend}
    {$if declared(d2i_OSSL_PRIVILEGE_POLICY_ID_introduced)}
    if LibVersion < d2i_OSSL_PRIVILEGE_POLICY_ID_introduced then
    begin
      {$if declared(FC_d2i_OSSL_PRIVILEGE_POLICY_ID)}
      d2i_OSSL_PRIVILEGE_POLICY_ID := FC_d2i_OSSL_PRIVILEGE_POLICY_ID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_PRIVILEGE_POLICY_ID_removed)}
    if d2i_OSSL_PRIVILEGE_POLICY_ID_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_PRIVILEGE_POLICY_ID)}
      d2i_OSSL_PRIVILEGE_POLICY_ID := _d2i_OSSL_PRIVILEGE_POLICY_ID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_PRIVILEGE_POLICY_ID_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_PRIVILEGE_POLICY_ID');
    {$ifend}
  end;
  
  i2d_OSSL_PRIVILEGE_POLICY_ID := LoadLibFunction(ADllHandle, i2d_OSSL_PRIVILEGE_POLICY_ID_procname);
  FuncLoadError := not assigned(i2d_OSSL_PRIVILEGE_POLICY_ID);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_PRIVILEGE_POLICY_ID_allownil)}
    i2d_OSSL_PRIVILEGE_POLICY_ID := ERR_i2d_OSSL_PRIVILEGE_POLICY_ID;
    {$ifend}
    {$if declared(i2d_OSSL_PRIVILEGE_POLICY_ID_introduced)}
    if LibVersion < i2d_OSSL_PRIVILEGE_POLICY_ID_introduced then
    begin
      {$if declared(FC_i2d_OSSL_PRIVILEGE_POLICY_ID)}
      i2d_OSSL_PRIVILEGE_POLICY_ID := FC_i2d_OSSL_PRIVILEGE_POLICY_ID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_PRIVILEGE_POLICY_ID_removed)}
    if i2d_OSSL_PRIVILEGE_POLICY_ID_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_PRIVILEGE_POLICY_ID)}
      i2d_OSSL_PRIVILEGE_POLICY_ID := _i2d_OSSL_PRIVILEGE_POLICY_ID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_PRIVILEGE_POLICY_ID_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_PRIVILEGE_POLICY_ID');
    {$ifend}
  end;
  
  OSSL_PRIVILEGE_POLICY_ID_it := LoadLibFunction(ADllHandle, OSSL_PRIVILEGE_POLICY_ID_it_procname);
  FuncLoadError := not assigned(OSSL_PRIVILEGE_POLICY_ID_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PRIVILEGE_POLICY_ID_it_allownil)}
    OSSL_PRIVILEGE_POLICY_ID_it := ERR_OSSL_PRIVILEGE_POLICY_ID_it;
    {$ifend}
    {$if declared(OSSL_PRIVILEGE_POLICY_ID_it_introduced)}
    if LibVersion < OSSL_PRIVILEGE_POLICY_ID_it_introduced then
    begin
      {$if declared(FC_OSSL_PRIVILEGE_POLICY_ID_it)}
      OSSL_PRIVILEGE_POLICY_ID_it := FC_OSSL_PRIVILEGE_POLICY_ID_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PRIVILEGE_POLICY_ID_it_removed)}
    if OSSL_PRIVILEGE_POLICY_ID_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PRIVILEGE_POLICY_ID_it)}
      OSSL_PRIVILEGE_POLICY_ID_it := _OSSL_PRIVILEGE_POLICY_ID_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PRIVILEGE_POLICY_ID_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PRIVILEGE_POLICY_ID_it');
    {$ifend}
  end;
  
  OSSL_ATTRIBUTE_DESCRIPTOR_new := LoadLibFunction(ADllHandle, OSSL_ATTRIBUTE_DESCRIPTOR_new_procname);
  FuncLoadError := not assigned(OSSL_ATTRIBUTE_DESCRIPTOR_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ATTRIBUTE_DESCRIPTOR_new_allownil)}
    OSSL_ATTRIBUTE_DESCRIPTOR_new := ERR_OSSL_ATTRIBUTE_DESCRIPTOR_new;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_DESCRIPTOR_new_introduced)}
    if LibVersion < OSSL_ATTRIBUTE_DESCRIPTOR_new_introduced then
    begin
      {$if declared(FC_OSSL_ATTRIBUTE_DESCRIPTOR_new)}
      OSSL_ATTRIBUTE_DESCRIPTOR_new := FC_OSSL_ATTRIBUTE_DESCRIPTOR_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_DESCRIPTOR_new_removed)}
    if OSSL_ATTRIBUTE_DESCRIPTOR_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ATTRIBUTE_DESCRIPTOR_new)}
      OSSL_ATTRIBUTE_DESCRIPTOR_new := _OSSL_ATTRIBUTE_DESCRIPTOR_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ATTRIBUTE_DESCRIPTOR_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ATTRIBUTE_DESCRIPTOR_new');
    {$ifend}
  end;
  
  OSSL_ATTRIBUTE_DESCRIPTOR_free := LoadLibFunction(ADllHandle, OSSL_ATTRIBUTE_DESCRIPTOR_free_procname);
  FuncLoadError := not assigned(OSSL_ATTRIBUTE_DESCRIPTOR_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ATTRIBUTE_DESCRIPTOR_free_allownil)}
    OSSL_ATTRIBUTE_DESCRIPTOR_free := ERR_OSSL_ATTRIBUTE_DESCRIPTOR_free;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_DESCRIPTOR_free_introduced)}
    if LibVersion < OSSL_ATTRIBUTE_DESCRIPTOR_free_introduced then
    begin
      {$if declared(FC_OSSL_ATTRIBUTE_DESCRIPTOR_free)}
      OSSL_ATTRIBUTE_DESCRIPTOR_free := FC_OSSL_ATTRIBUTE_DESCRIPTOR_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_DESCRIPTOR_free_removed)}
    if OSSL_ATTRIBUTE_DESCRIPTOR_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ATTRIBUTE_DESCRIPTOR_free)}
      OSSL_ATTRIBUTE_DESCRIPTOR_free := _OSSL_ATTRIBUTE_DESCRIPTOR_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ATTRIBUTE_DESCRIPTOR_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ATTRIBUTE_DESCRIPTOR_free');
    {$ifend}
  end;
  
  d2i_OSSL_ATTRIBUTE_DESCRIPTOR := LoadLibFunction(ADllHandle, d2i_OSSL_ATTRIBUTE_DESCRIPTOR_procname);
  FuncLoadError := not assigned(d2i_OSSL_ATTRIBUTE_DESCRIPTOR);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_ATTRIBUTE_DESCRIPTOR_allownil)}
    d2i_OSSL_ATTRIBUTE_DESCRIPTOR := ERR_d2i_OSSL_ATTRIBUTE_DESCRIPTOR;
    {$ifend}
    {$if declared(d2i_OSSL_ATTRIBUTE_DESCRIPTOR_introduced)}
    if LibVersion < d2i_OSSL_ATTRIBUTE_DESCRIPTOR_introduced then
    begin
      {$if declared(FC_d2i_OSSL_ATTRIBUTE_DESCRIPTOR)}
      d2i_OSSL_ATTRIBUTE_DESCRIPTOR := FC_d2i_OSSL_ATTRIBUTE_DESCRIPTOR;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_ATTRIBUTE_DESCRIPTOR_removed)}
    if d2i_OSSL_ATTRIBUTE_DESCRIPTOR_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_ATTRIBUTE_DESCRIPTOR)}
      d2i_OSSL_ATTRIBUTE_DESCRIPTOR := _d2i_OSSL_ATTRIBUTE_DESCRIPTOR;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_ATTRIBUTE_DESCRIPTOR_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_ATTRIBUTE_DESCRIPTOR');
    {$ifend}
  end;
  
  i2d_OSSL_ATTRIBUTE_DESCRIPTOR := LoadLibFunction(ADllHandle, i2d_OSSL_ATTRIBUTE_DESCRIPTOR_procname);
  FuncLoadError := not assigned(i2d_OSSL_ATTRIBUTE_DESCRIPTOR);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_ATTRIBUTE_DESCRIPTOR_allownil)}
    i2d_OSSL_ATTRIBUTE_DESCRIPTOR := ERR_i2d_OSSL_ATTRIBUTE_DESCRIPTOR;
    {$ifend}
    {$if declared(i2d_OSSL_ATTRIBUTE_DESCRIPTOR_introduced)}
    if LibVersion < i2d_OSSL_ATTRIBUTE_DESCRIPTOR_introduced then
    begin
      {$if declared(FC_i2d_OSSL_ATTRIBUTE_DESCRIPTOR)}
      i2d_OSSL_ATTRIBUTE_DESCRIPTOR := FC_i2d_OSSL_ATTRIBUTE_DESCRIPTOR;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_ATTRIBUTE_DESCRIPTOR_removed)}
    if i2d_OSSL_ATTRIBUTE_DESCRIPTOR_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_ATTRIBUTE_DESCRIPTOR)}
      i2d_OSSL_ATTRIBUTE_DESCRIPTOR := _i2d_OSSL_ATTRIBUTE_DESCRIPTOR;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_ATTRIBUTE_DESCRIPTOR_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_ATTRIBUTE_DESCRIPTOR');
    {$ifend}
  end;
  
  OSSL_ATTRIBUTE_DESCRIPTOR_it := LoadLibFunction(ADllHandle, OSSL_ATTRIBUTE_DESCRIPTOR_it_procname);
  FuncLoadError := not assigned(OSSL_ATTRIBUTE_DESCRIPTOR_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ATTRIBUTE_DESCRIPTOR_it_allownil)}
    OSSL_ATTRIBUTE_DESCRIPTOR_it := ERR_OSSL_ATTRIBUTE_DESCRIPTOR_it;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_DESCRIPTOR_it_introduced)}
    if LibVersion < OSSL_ATTRIBUTE_DESCRIPTOR_it_introduced then
    begin
      {$if declared(FC_OSSL_ATTRIBUTE_DESCRIPTOR_it)}
      OSSL_ATTRIBUTE_DESCRIPTOR_it := FC_OSSL_ATTRIBUTE_DESCRIPTOR_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_DESCRIPTOR_it_removed)}
    if OSSL_ATTRIBUTE_DESCRIPTOR_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ATTRIBUTE_DESCRIPTOR_it)}
      OSSL_ATTRIBUTE_DESCRIPTOR_it := _OSSL_ATTRIBUTE_DESCRIPTOR_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ATTRIBUTE_DESCRIPTOR_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ATTRIBUTE_DESCRIPTOR_it');
    {$ifend}
  end;
  
  OSSL_DAY_TIME_new := LoadLibFunction(ADllHandle, OSSL_DAY_TIME_new_procname);
  FuncLoadError := not assigned(OSSL_DAY_TIME_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DAY_TIME_new_allownil)}
    OSSL_DAY_TIME_new := ERR_OSSL_DAY_TIME_new;
    {$ifend}
    {$if declared(OSSL_DAY_TIME_new_introduced)}
    if LibVersion < OSSL_DAY_TIME_new_introduced then
    begin
      {$if declared(FC_OSSL_DAY_TIME_new)}
      OSSL_DAY_TIME_new := FC_OSSL_DAY_TIME_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DAY_TIME_new_removed)}
    if OSSL_DAY_TIME_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DAY_TIME_new)}
      OSSL_DAY_TIME_new := _OSSL_DAY_TIME_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DAY_TIME_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DAY_TIME_new');
    {$ifend}
  end;
  
  OSSL_DAY_TIME_free := LoadLibFunction(ADllHandle, OSSL_DAY_TIME_free_procname);
  FuncLoadError := not assigned(OSSL_DAY_TIME_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DAY_TIME_free_allownil)}
    OSSL_DAY_TIME_free := ERR_OSSL_DAY_TIME_free;
    {$ifend}
    {$if declared(OSSL_DAY_TIME_free_introduced)}
    if LibVersion < OSSL_DAY_TIME_free_introduced then
    begin
      {$if declared(FC_OSSL_DAY_TIME_free)}
      OSSL_DAY_TIME_free := FC_OSSL_DAY_TIME_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DAY_TIME_free_removed)}
    if OSSL_DAY_TIME_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DAY_TIME_free)}
      OSSL_DAY_TIME_free := _OSSL_DAY_TIME_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DAY_TIME_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DAY_TIME_free');
    {$ifend}
  end;
  
  d2i_OSSL_DAY_TIME := LoadLibFunction(ADllHandle, d2i_OSSL_DAY_TIME_procname);
  FuncLoadError := not assigned(d2i_OSSL_DAY_TIME);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_DAY_TIME_allownil)}
    d2i_OSSL_DAY_TIME := ERR_d2i_OSSL_DAY_TIME;
    {$ifend}
    {$if declared(d2i_OSSL_DAY_TIME_introduced)}
    if LibVersion < d2i_OSSL_DAY_TIME_introduced then
    begin
      {$if declared(FC_d2i_OSSL_DAY_TIME)}
      d2i_OSSL_DAY_TIME := FC_d2i_OSSL_DAY_TIME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_DAY_TIME_removed)}
    if d2i_OSSL_DAY_TIME_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_DAY_TIME)}
      d2i_OSSL_DAY_TIME := _d2i_OSSL_DAY_TIME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_DAY_TIME_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_DAY_TIME');
    {$ifend}
  end;
  
  i2d_OSSL_DAY_TIME := LoadLibFunction(ADllHandle, i2d_OSSL_DAY_TIME_procname);
  FuncLoadError := not assigned(i2d_OSSL_DAY_TIME);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_DAY_TIME_allownil)}
    i2d_OSSL_DAY_TIME := ERR_i2d_OSSL_DAY_TIME;
    {$ifend}
    {$if declared(i2d_OSSL_DAY_TIME_introduced)}
    if LibVersion < i2d_OSSL_DAY_TIME_introduced then
    begin
      {$if declared(FC_i2d_OSSL_DAY_TIME)}
      i2d_OSSL_DAY_TIME := FC_i2d_OSSL_DAY_TIME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_DAY_TIME_removed)}
    if i2d_OSSL_DAY_TIME_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_DAY_TIME)}
      i2d_OSSL_DAY_TIME := _i2d_OSSL_DAY_TIME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_DAY_TIME_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_DAY_TIME');
    {$ifend}
  end;
  
  OSSL_DAY_TIME_it := LoadLibFunction(ADllHandle, OSSL_DAY_TIME_it_procname);
  FuncLoadError := not assigned(OSSL_DAY_TIME_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DAY_TIME_it_allownil)}
    OSSL_DAY_TIME_it := ERR_OSSL_DAY_TIME_it;
    {$ifend}
    {$if declared(OSSL_DAY_TIME_it_introduced)}
    if LibVersion < OSSL_DAY_TIME_it_introduced then
    begin
      {$if declared(FC_OSSL_DAY_TIME_it)}
      OSSL_DAY_TIME_it := FC_OSSL_DAY_TIME_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DAY_TIME_it_removed)}
    if OSSL_DAY_TIME_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DAY_TIME_it)}
      OSSL_DAY_TIME_it := _OSSL_DAY_TIME_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DAY_TIME_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DAY_TIME_it');
    {$ifend}
  end;
  
  OSSL_DAY_TIME_BAND_new := LoadLibFunction(ADllHandle, OSSL_DAY_TIME_BAND_new_procname);
  FuncLoadError := not assigned(OSSL_DAY_TIME_BAND_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DAY_TIME_BAND_new_allownil)}
    OSSL_DAY_TIME_BAND_new := ERR_OSSL_DAY_TIME_BAND_new;
    {$ifend}
    {$if declared(OSSL_DAY_TIME_BAND_new_introduced)}
    if LibVersion < OSSL_DAY_TIME_BAND_new_introduced then
    begin
      {$if declared(FC_OSSL_DAY_TIME_BAND_new)}
      OSSL_DAY_TIME_BAND_new := FC_OSSL_DAY_TIME_BAND_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DAY_TIME_BAND_new_removed)}
    if OSSL_DAY_TIME_BAND_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DAY_TIME_BAND_new)}
      OSSL_DAY_TIME_BAND_new := _OSSL_DAY_TIME_BAND_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DAY_TIME_BAND_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DAY_TIME_BAND_new');
    {$ifend}
  end;
  
  OSSL_DAY_TIME_BAND_free := LoadLibFunction(ADllHandle, OSSL_DAY_TIME_BAND_free_procname);
  FuncLoadError := not assigned(OSSL_DAY_TIME_BAND_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DAY_TIME_BAND_free_allownil)}
    OSSL_DAY_TIME_BAND_free := ERR_OSSL_DAY_TIME_BAND_free;
    {$ifend}
    {$if declared(OSSL_DAY_TIME_BAND_free_introduced)}
    if LibVersion < OSSL_DAY_TIME_BAND_free_introduced then
    begin
      {$if declared(FC_OSSL_DAY_TIME_BAND_free)}
      OSSL_DAY_TIME_BAND_free := FC_OSSL_DAY_TIME_BAND_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DAY_TIME_BAND_free_removed)}
    if OSSL_DAY_TIME_BAND_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DAY_TIME_BAND_free)}
      OSSL_DAY_TIME_BAND_free := _OSSL_DAY_TIME_BAND_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DAY_TIME_BAND_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DAY_TIME_BAND_free');
    {$ifend}
  end;
  
  d2i_OSSL_DAY_TIME_BAND := LoadLibFunction(ADllHandle, d2i_OSSL_DAY_TIME_BAND_procname);
  FuncLoadError := not assigned(d2i_OSSL_DAY_TIME_BAND);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_DAY_TIME_BAND_allownil)}
    d2i_OSSL_DAY_TIME_BAND := ERR_d2i_OSSL_DAY_TIME_BAND;
    {$ifend}
    {$if declared(d2i_OSSL_DAY_TIME_BAND_introduced)}
    if LibVersion < d2i_OSSL_DAY_TIME_BAND_introduced then
    begin
      {$if declared(FC_d2i_OSSL_DAY_TIME_BAND)}
      d2i_OSSL_DAY_TIME_BAND := FC_d2i_OSSL_DAY_TIME_BAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_DAY_TIME_BAND_removed)}
    if d2i_OSSL_DAY_TIME_BAND_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_DAY_TIME_BAND)}
      d2i_OSSL_DAY_TIME_BAND := _d2i_OSSL_DAY_TIME_BAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_DAY_TIME_BAND_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_DAY_TIME_BAND');
    {$ifend}
  end;
  
  i2d_OSSL_DAY_TIME_BAND := LoadLibFunction(ADllHandle, i2d_OSSL_DAY_TIME_BAND_procname);
  FuncLoadError := not assigned(i2d_OSSL_DAY_TIME_BAND);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_DAY_TIME_BAND_allownil)}
    i2d_OSSL_DAY_TIME_BAND := ERR_i2d_OSSL_DAY_TIME_BAND;
    {$ifend}
    {$if declared(i2d_OSSL_DAY_TIME_BAND_introduced)}
    if LibVersion < i2d_OSSL_DAY_TIME_BAND_introduced then
    begin
      {$if declared(FC_i2d_OSSL_DAY_TIME_BAND)}
      i2d_OSSL_DAY_TIME_BAND := FC_i2d_OSSL_DAY_TIME_BAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_DAY_TIME_BAND_removed)}
    if i2d_OSSL_DAY_TIME_BAND_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_DAY_TIME_BAND)}
      i2d_OSSL_DAY_TIME_BAND := _i2d_OSSL_DAY_TIME_BAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_DAY_TIME_BAND_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_DAY_TIME_BAND');
    {$ifend}
  end;
  
  OSSL_DAY_TIME_BAND_it := LoadLibFunction(ADllHandle, OSSL_DAY_TIME_BAND_it_procname);
  FuncLoadError := not assigned(OSSL_DAY_TIME_BAND_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DAY_TIME_BAND_it_allownil)}
    OSSL_DAY_TIME_BAND_it := ERR_OSSL_DAY_TIME_BAND_it;
    {$ifend}
    {$if declared(OSSL_DAY_TIME_BAND_it_introduced)}
    if LibVersion < OSSL_DAY_TIME_BAND_it_introduced then
    begin
      {$if declared(FC_OSSL_DAY_TIME_BAND_it)}
      OSSL_DAY_TIME_BAND_it := FC_OSSL_DAY_TIME_BAND_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DAY_TIME_BAND_it_removed)}
    if OSSL_DAY_TIME_BAND_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DAY_TIME_BAND_it)}
      OSSL_DAY_TIME_BAND_it := _OSSL_DAY_TIME_BAND_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DAY_TIME_BAND_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DAY_TIME_BAND_it');
    {$ifend}
  end;
  
  OSSL_TIME_SPEC_DAY_new := LoadLibFunction(ADllHandle, OSSL_TIME_SPEC_DAY_new_procname);
  FuncLoadError := not assigned(OSSL_TIME_SPEC_DAY_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TIME_SPEC_DAY_new_allownil)}
    OSSL_TIME_SPEC_DAY_new := ERR_OSSL_TIME_SPEC_DAY_new;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_DAY_new_introduced)}
    if LibVersion < OSSL_TIME_SPEC_DAY_new_introduced then
    begin
      {$if declared(FC_OSSL_TIME_SPEC_DAY_new)}
      OSSL_TIME_SPEC_DAY_new := FC_OSSL_TIME_SPEC_DAY_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_DAY_new_removed)}
    if OSSL_TIME_SPEC_DAY_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TIME_SPEC_DAY_new)}
      OSSL_TIME_SPEC_DAY_new := _OSSL_TIME_SPEC_DAY_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TIME_SPEC_DAY_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TIME_SPEC_DAY_new');
    {$ifend}
  end;
  
  OSSL_TIME_SPEC_DAY_free := LoadLibFunction(ADllHandle, OSSL_TIME_SPEC_DAY_free_procname);
  FuncLoadError := not assigned(OSSL_TIME_SPEC_DAY_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TIME_SPEC_DAY_free_allownil)}
    OSSL_TIME_SPEC_DAY_free := ERR_OSSL_TIME_SPEC_DAY_free;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_DAY_free_introduced)}
    if LibVersion < OSSL_TIME_SPEC_DAY_free_introduced then
    begin
      {$if declared(FC_OSSL_TIME_SPEC_DAY_free)}
      OSSL_TIME_SPEC_DAY_free := FC_OSSL_TIME_SPEC_DAY_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_DAY_free_removed)}
    if OSSL_TIME_SPEC_DAY_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TIME_SPEC_DAY_free)}
      OSSL_TIME_SPEC_DAY_free := _OSSL_TIME_SPEC_DAY_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TIME_SPEC_DAY_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TIME_SPEC_DAY_free');
    {$ifend}
  end;
  
  d2i_OSSL_TIME_SPEC_DAY := LoadLibFunction(ADllHandle, d2i_OSSL_TIME_SPEC_DAY_procname);
  FuncLoadError := not assigned(d2i_OSSL_TIME_SPEC_DAY);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_TIME_SPEC_DAY_allownil)}
    d2i_OSSL_TIME_SPEC_DAY := ERR_d2i_OSSL_TIME_SPEC_DAY;
    {$ifend}
    {$if declared(d2i_OSSL_TIME_SPEC_DAY_introduced)}
    if LibVersion < d2i_OSSL_TIME_SPEC_DAY_introduced then
    begin
      {$if declared(FC_d2i_OSSL_TIME_SPEC_DAY)}
      d2i_OSSL_TIME_SPEC_DAY := FC_d2i_OSSL_TIME_SPEC_DAY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_TIME_SPEC_DAY_removed)}
    if d2i_OSSL_TIME_SPEC_DAY_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_TIME_SPEC_DAY)}
      d2i_OSSL_TIME_SPEC_DAY := _d2i_OSSL_TIME_SPEC_DAY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_TIME_SPEC_DAY_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_TIME_SPEC_DAY');
    {$ifend}
  end;
  
  i2d_OSSL_TIME_SPEC_DAY := LoadLibFunction(ADllHandle, i2d_OSSL_TIME_SPEC_DAY_procname);
  FuncLoadError := not assigned(i2d_OSSL_TIME_SPEC_DAY);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_TIME_SPEC_DAY_allownil)}
    i2d_OSSL_TIME_SPEC_DAY := ERR_i2d_OSSL_TIME_SPEC_DAY;
    {$ifend}
    {$if declared(i2d_OSSL_TIME_SPEC_DAY_introduced)}
    if LibVersion < i2d_OSSL_TIME_SPEC_DAY_introduced then
    begin
      {$if declared(FC_i2d_OSSL_TIME_SPEC_DAY)}
      i2d_OSSL_TIME_SPEC_DAY := FC_i2d_OSSL_TIME_SPEC_DAY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_TIME_SPEC_DAY_removed)}
    if i2d_OSSL_TIME_SPEC_DAY_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_TIME_SPEC_DAY)}
      i2d_OSSL_TIME_SPEC_DAY := _i2d_OSSL_TIME_SPEC_DAY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_TIME_SPEC_DAY_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_TIME_SPEC_DAY');
    {$ifend}
  end;
  
  OSSL_TIME_SPEC_DAY_it := LoadLibFunction(ADllHandle, OSSL_TIME_SPEC_DAY_it_procname);
  FuncLoadError := not assigned(OSSL_TIME_SPEC_DAY_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TIME_SPEC_DAY_it_allownil)}
    OSSL_TIME_SPEC_DAY_it := ERR_OSSL_TIME_SPEC_DAY_it;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_DAY_it_introduced)}
    if LibVersion < OSSL_TIME_SPEC_DAY_it_introduced then
    begin
      {$if declared(FC_OSSL_TIME_SPEC_DAY_it)}
      OSSL_TIME_SPEC_DAY_it := FC_OSSL_TIME_SPEC_DAY_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_DAY_it_removed)}
    if OSSL_TIME_SPEC_DAY_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TIME_SPEC_DAY_it)}
      OSSL_TIME_SPEC_DAY_it := _OSSL_TIME_SPEC_DAY_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TIME_SPEC_DAY_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TIME_SPEC_DAY_it');
    {$ifend}
  end;
  
  OSSL_TIME_SPEC_WEEKS_new := LoadLibFunction(ADllHandle, OSSL_TIME_SPEC_WEEKS_new_procname);
  FuncLoadError := not assigned(OSSL_TIME_SPEC_WEEKS_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TIME_SPEC_WEEKS_new_allownil)}
    OSSL_TIME_SPEC_WEEKS_new := ERR_OSSL_TIME_SPEC_WEEKS_new;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_WEEKS_new_introduced)}
    if LibVersion < OSSL_TIME_SPEC_WEEKS_new_introduced then
    begin
      {$if declared(FC_OSSL_TIME_SPEC_WEEKS_new)}
      OSSL_TIME_SPEC_WEEKS_new := FC_OSSL_TIME_SPEC_WEEKS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_WEEKS_new_removed)}
    if OSSL_TIME_SPEC_WEEKS_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TIME_SPEC_WEEKS_new)}
      OSSL_TIME_SPEC_WEEKS_new := _OSSL_TIME_SPEC_WEEKS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TIME_SPEC_WEEKS_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TIME_SPEC_WEEKS_new');
    {$ifend}
  end;
  
  OSSL_TIME_SPEC_WEEKS_free := LoadLibFunction(ADllHandle, OSSL_TIME_SPEC_WEEKS_free_procname);
  FuncLoadError := not assigned(OSSL_TIME_SPEC_WEEKS_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TIME_SPEC_WEEKS_free_allownil)}
    OSSL_TIME_SPEC_WEEKS_free := ERR_OSSL_TIME_SPEC_WEEKS_free;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_WEEKS_free_introduced)}
    if LibVersion < OSSL_TIME_SPEC_WEEKS_free_introduced then
    begin
      {$if declared(FC_OSSL_TIME_SPEC_WEEKS_free)}
      OSSL_TIME_SPEC_WEEKS_free := FC_OSSL_TIME_SPEC_WEEKS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_WEEKS_free_removed)}
    if OSSL_TIME_SPEC_WEEKS_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TIME_SPEC_WEEKS_free)}
      OSSL_TIME_SPEC_WEEKS_free := _OSSL_TIME_SPEC_WEEKS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TIME_SPEC_WEEKS_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TIME_SPEC_WEEKS_free');
    {$ifend}
  end;
  
  d2i_OSSL_TIME_SPEC_WEEKS := LoadLibFunction(ADllHandle, d2i_OSSL_TIME_SPEC_WEEKS_procname);
  FuncLoadError := not assigned(d2i_OSSL_TIME_SPEC_WEEKS);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_TIME_SPEC_WEEKS_allownil)}
    d2i_OSSL_TIME_SPEC_WEEKS := ERR_d2i_OSSL_TIME_SPEC_WEEKS;
    {$ifend}
    {$if declared(d2i_OSSL_TIME_SPEC_WEEKS_introduced)}
    if LibVersion < d2i_OSSL_TIME_SPEC_WEEKS_introduced then
    begin
      {$if declared(FC_d2i_OSSL_TIME_SPEC_WEEKS)}
      d2i_OSSL_TIME_SPEC_WEEKS := FC_d2i_OSSL_TIME_SPEC_WEEKS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_TIME_SPEC_WEEKS_removed)}
    if d2i_OSSL_TIME_SPEC_WEEKS_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_TIME_SPEC_WEEKS)}
      d2i_OSSL_TIME_SPEC_WEEKS := _d2i_OSSL_TIME_SPEC_WEEKS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_TIME_SPEC_WEEKS_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_TIME_SPEC_WEEKS');
    {$ifend}
  end;
  
  i2d_OSSL_TIME_SPEC_WEEKS := LoadLibFunction(ADllHandle, i2d_OSSL_TIME_SPEC_WEEKS_procname);
  FuncLoadError := not assigned(i2d_OSSL_TIME_SPEC_WEEKS);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_TIME_SPEC_WEEKS_allownil)}
    i2d_OSSL_TIME_SPEC_WEEKS := ERR_i2d_OSSL_TIME_SPEC_WEEKS;
    {$ifend}
    {$if declared(i2d_OSSL_TIME_SPEC_WEEKS_introduced)}
    if LibVersion < i2d_OSSL_TIME_SPEC_WEEKS_introduced then
    begin
      {$if declared(FC_i2d_OSSL_TIME_SPEC_WEEKS)}
      i2d_OSSL_TIME_SPEC_WEEKS := FC_i2d_OSSL_TIME_SPEC_WEEKS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_TIME_SPEC_WEEKS_removed)}
    if i2d_OSSL_TIME_SPEC_WEEKS_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_TIME_SPEC_WEEKS)}
      i2d_OSSL_TIME_SPEC_WEEKS := _i2d_OSSL_TIME_SPEC_WEEKS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_TIME_SPEC_WEEKS_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_TIME_SPEC_WEEKS');
    {$ifend}
  end;
  
  OSSL_TIME_SPEC_WEEKS_it := LoadLibFunction(ADllHandle, OSSL_TIME_SPEC_WEEKS_it_procname);
  FuncLoadError := not assigned(OSSL_TIME_SPEC_WEEKS_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TIME_SPEC_WEEKS_it_allownil)}
    OSSL_TIME_SPEC_WEEKS_it := ERR_OSSL_TIME_SPEC_WEEKS_it;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_WEEKS_it_introduced)}
    if LibVersion < OSSL_TIME_SPEC_WEEKS_it_introduced then
    begin
      {$if declared(FC_OSSL_TIME_SPEC_WEEKS_it)}
      OSSL_TIME_SPEC_WEEKS_it := FC_OSSL_TIME_SPEC_WEEKS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_WEEKS_it_removed)}
    if OSSL_TIME_SPEC_WEEKS_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TIME_SPEC_WEEKS_it)}
      OSSL_TIME_SPEC_WEEKS_it := _OSSL_TIME_SPEC_WEEKS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TIME_SPEC_WEEKS_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TIME_SPEC_WEEKS_it');
    {$ifend}
  end;
  
  OSSL_TIME_SPEC_MONTH_new := LoadLibFunction(ADllHandle, OSSL_TIME_SPEC_MONTH_new_procname);
  FuncLoadError := not assigned(OSSL_TIME_SPEC_MONTH_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TIME_SPEC_MONTH_new_allownil)}
    OSSL_TIME_SPEC_MONTH_new := ERR_OSSL_TIME_SPEC_MONTH_new;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_MONTH_new_introduced)}
    if LibVersion < OSSL_TIME_SPEC_MONTH_new_introduced then
    begin
      {$if declared(FC_OSSL_TIME_SPEC_MONTH_new)}
      OSSL_TIME_SPEC_MONTH_new := FC_OSSL_TIME_SPEC_MONTH_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_MONTH_new_removed)}
    if OSSL_TIME_SPEC_MONTH_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TIME_SPEC_MONTH_new)}
      OSSL_TIME_SPEC_MONTH_new := _OSSL_TIME_SPEC_MONTH_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TIME_SPEC_MONTH_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TIME_SPEC_MONTH_new');
    {$ifend}
  end;
  
  OSSL_TIME_SPEC_MONTH_free := LoadLibFunction(ADllHandle, OSSL_TIME_SPEC_MONTH_free_procname);
  FuncLoadError := not assigned(OSSL_TIME_SPEC_MONTH_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TIME_SPEC_MONTH_free_allownil)}
    OSSL_TIME_SPEC_MONTH_free := ERR_OSSL_TIME_SPEC_MONTH_free;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_MONTH_free_introduced)}
    if LibVersion < OSSL_TIME_SPEC_MONTH_free_introduced then
    begin
      {$if declared(FC_OSSL_TIME_SPEC_MONTH_free)}
      OSSL_TIME_SPEC_MONTH_free := FC_OSSL_TIME_SPEC_MONTH_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_MONTH_free_removed)}
    if OSSL_TIME_SPEC_MONTH_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TIME_SPEC_MONTH_free)}
      OSSL_TIME_SPEC_MONTH_free := _OSSL_TIME_SPEC_MONTH_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TIME_SPEC_MONTH_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TIME_SPEC_MONTH_free');
    {$ifend}
  end;
  
  d2i_OSSL_TIME_SPEC_MONTH := LoadLibFunction(ADllHandle, d2i_OSSL_TIME_SPEC_MONTH_procname);
  FuncLoadError := not assigned(d2i_OSSL_TIME_SPEC_MONTH);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_TIME_SPEC_MONTH_allownil)}
    d2i_OSSL_TIME_SPEC_MONTH := ERR_d2i_OSSL_TIME_SPEC_MONTH;
    {$ifend}
    {$if declared(d2i_OSSL_TIME_SPEC_MONTH_introduced)}
    if LibVersion < d2i_OSSL_TIME_SPEC_MONTH_introduced then
    begin
      {$if declared(FC_d2i_OSSL_TIME_SPEC_MONTH)}
      d2i_OSSL_TIME_SPEC_MONTH := FC_d2i_OSSL_TIME_SPEC_MONTH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_TIME_SPEC_MONTH_removed)}
    if d2i_OSSL_TIME_SPEC_MONTH_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_TIME_SPEC_MONTH)}
      d2i_OSSL_TIME_SPEC_MONTH := _d2i_OSSL_TIME_SPEC_MONTH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_TIME_SPEC_MONTH_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_TIME_SPEC_MONTH');
    {$ifend}
  end;
  
  i2d_OSSL_TIME_SPEC_MONTH := LoadLibFunction(ADllHandle, i2d_OSSL_TIME_SPEC_MONTH_procname);
  FuncLoadError := not assigned(i2d_OSSL_TIME_SPEC_MONTH);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_TIME_SPEC_MONTH_allownil)}
    i2d_OSSL_TIME_SPEC_MONTH := ERR_i2d_OSSL_TIME_SPEC_MONTH;
    {$ifend}
    {$if declared(i2d_OSSL_TIME_SPEC_MONTH_introduced)}
    if LibVersion < i2d_OSSL_TIME_SPEC_MONTH_introduced then
    begin
      {$if declared(FC_i2d_OSSL_TIME_SPEC_MONTH)}
      i2d_OSSL_TIME_SPEC_MONTH := FC_i2d_OSSL_TIME_SPEC_MONTH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_TIME_SPEC_MONTH_removed)}
    if i2d_OSSL_TIME_SPEC_MONTH_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_TIME_SPEC_MONTH)}
      i2d_OSSL_TIME_SPEC_MONTH := _i2d_OSSL_TIME_SPEC_MONTH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_TIME_SPEC_MONTH_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_TIME_SPEC_MONTH');
    {$ifend}
  end;
  
  OSSL_TIME_SPEC_MONTH_it := LoadLibFunction(ADllHandle, OSSL_TIME_SPEC_MONTH_it_procname);
  FuncLoadError := not assigned(OSSL_TIME_SPEC_MONTH_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TIME_SPEC_MONTH_it_allownil)}
    OSSL_TIME_SPEC_MONTH_it := ERR_OSSL_TIME_SPEC_MONTH_it;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_MONTH_it_introduced)}
    if LibVersion < OSSL_TIME_SPEC_MONTH_it_introduced then
    begin
      {$if declared(FC_OSSL_TIME_SPEC_MONTH_it)}
      OSSL_TIME_SPEC_MONTH_it := FC_OSSL_TIME_SPEC_MONTH_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_MONTH_it_removed)}
    if OSSL_TIME_SPEC_MONTH_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TIME_SPEC_MONTH_it)}
      OSSL_TIME_SPEC_MONTH_it := _OSSL_TIME_SPEC_MONTH_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TIME_SPEC_MONTH_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TIME_SPEC_MONTH_it');
    {$ifend}
  end;
  
  OSSL_NAMED_DAY_new := LoadLibFunction(ADllHandle, OSSL_NAMED_DAY_new_procname);
  FuncLoadError := not assigned(OSSL_NAMED_DAY_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_NAMED_DAY_new_allownil)}
    OSSL_NAMED_DAY_new := ERR_OSSL_NAMED_DAY_new;
    {$ifend}
    {$if declared(OSSL_NAMED_DAY_new_introduced)}
    if LibVersion < OSSL_NAMED_DAY_new_introduced then
    begin
      {$if declared(FC_OSSL_NAMED_DAY_new)}
      OSSL_NAMED_DAY_new := FC_OSSL_NAMED_DAY_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_NAMED_DAY_new_removed)}
    if OSSL_NAMED_DAY_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_NAMED_DAY_new)}
      OSSL_NAMED_DAY_new := _OSSL_NAMED_DAY_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_NAMED_DAY_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_NAMED_DAY_new');
    {$ifend}
  end;
  
  OSSL_NAMED_DAY_free := LoadLibFunction(ADllHandle, OSSL_NAMED_DAY_free_procname);
  FuncLoadError := not assigned(OSSL_NAMED_DAY_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_NAMED_DAY_free_allownil)}
    OSSL_NAMED_DAY_free := ERR_OSSL_NAMED_DAY_free;
    {$ifend}
    {$if declared(OSSL_NAMED_DAY_free_introduced)}
    if LibVersion < OSSL_NAMED_DAY_free_introduced then
    begin
      {$if declared(FC_OSSL_NAMED_DAY_free)}
      OSSL_NAMED_DAY_free := FC_OSSL_NAMED_DAY_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_NAMED_DAY_free_removed)}
    if OSSL_NAMED_DAY_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_NAMED_DAY_free)}
      OSSL_NAMED_DAY_free := _OSSL_NAMED_DAY_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_NAMED_DAY_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_NAMED_DAY_free');
    {$ifend}
  end;
  
  d2i_OSSL_NAMED_DAY := LoadLibFunction(ADllHandle, d2i_OSSL_NAMED_DAY_procname);
  FuncLoadError := not assigned(d2i_OSSL_NAMED_DAY);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_NAMED_DAY_allownil)}
    d2i_OSSL_NAMED_DAY := ERR_d2i_OSSL_NAMED_DAY;
    {$ifend}
    {$if declared(d2i_OSSL_NAMED_DAY_introduced)}
    if LibVersion < d2i_OSSL_NAMED_DAY_introduced then
    begin
      {$if declared(FC_d2i_OSSL_NAMED_DAY)}
      d2i_OSSL_NAMED_DAY := FC_d2i_OSSL_NAMED_DAY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_NAMED_DAY_removed)}
    if d2i_OSSL_NAMED_DAY_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_NAMED_DAY)}
      d2i_OSSL_NAMED_DAY := _d2i_OSSL_NAMED_DAY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_NAMED_DAY_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_NAMED_DAY');
    {$ifend}
  end;
  
  i2d_OSSL_NAMED_DAY := LoadLibFunction(ADllHandle, i2d_OSSL_NAMED_DAY_procname);
  FuncLoadError := not assigned(i2d_OSSL_NAMED_DAY);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_NAMED_DAY_allownil)}
    i2d_OSSL_NAMED_DAY := ERR_i2d_OSSL_NAMED_DAY;
    {$ifend}
    {$if declared(i2d_OSSL_NAMED_DAY_introduced)}
    if LibVersion < i2d_OSSL_NAMED_DAY_introduced then
    begin
      {$if declared(FC_i2d_OSSL_NAMED_DAY)}
      i2d_OSSL_NAMED_DAY := FC_i2d_OSSL_NAMED_DAY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_NAMED_DAY_removed)}
    if i2d_OSSL_NAMED_DAY_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_NAMED_DAY)}
      i2d_OSSL_NAMED_DAY := _i2d_OSSL_NAMED_DAY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_NAMED_DAY_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_NAMED_DAY');
    {$ifend}
  end;
  
  OSSL_NAMED_DAY_it := LoadLibFunction(ADllHandle, OSSL_NAMED_DAY_it_procname);
  FuncLoadError := not assigned(OSSL_NAMED_DAY_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_NAMED_DAY_it_allownil)}
    OSSL_NAMED_DAY_it := ERR_OSSL_NAMED_DAY_it;
    {$ifend}
    {$if declared(OSSL_NAMED_DAY_it_introduced)}
    if LibVersion < OSSL_NAMED_DAY_it_introduced then
    begin
      {$if declared(FC_OSSL_NAMED_DAY_it)}
      OSSL_NAMED_DAY_it := FC_OSSL_NAMED_DAY_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_NAMED_DAY_it_removed)}
    if OSSL_NAMED_DAY_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_NAMED_DAY_it)}
      OSSL_NAMED_DAY_it := _OSSL_NAMED_DAY_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_NAMED_DAY_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_NAMED_DAY_it');
    {$ifend}
  end;
  
  OSSL_TIME_SPEC_X_DAY_OF_new := LoadLibFunction(ADllHandle, OSSL_TIME_SPEC_X_DAY_OF_new_procname);
  FuncLoadError := not assigned(OSSL_TIME_SPEC_X_DAY_OF_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TIME_SPEC_X_DAY_OF_new_allownil)}
    OSSL_TIME_SPEC_X_DAY_OF_new := ERR_OSSL_TIME_SPEC_X_DAY_OF_new;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_X_DAY_OF_new_introduced)}
    if LibVersion < OSSL_TIME_SPEC_X_DAY_OF_new_introduced then
    begin
      {$if declared(FC_OSSL_TIME_SPEC_X_DAY_OF_new)}
      OSSL_TIME_SPEC_X_DAY_OF_new := FC_OSSL_TIME_SPEC_X_DAY_OF_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_X_DAY_OF_new_removed)}
    if OSSL_TIME_SPEC_X_DAY_OF_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TIME_SPEC_X_DAY_OF_new)}
      OSSL_TIME_SPEC_X_DAY_OF_new := _OSSL_TIME_SPEC_X_DAY_OF_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TIME_SPEC_X_DAY_OF_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TIME_SPEC_X_DAY_OF_new');
    {$ifend}
  end;
  
  OSSL_TIME_SPEC_X_DAY_OF_free := LoadLibFunction(ADllHandle, OSSL_TIME_SPEC_X_DAY_OF_free_procname);
  FuncLoadError := not assigned(OSSL_TIME_SPEC_X_DAY_OF_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TIME_SPEC_X_DAY_OF_free_allownil)}
    OSSL_TIME_SPEC_X_DAY_OF_free := ERR_OSSL_TIME_SPEC_X_DAY_OF_free;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_X_DAY_OF_free_introduced)}
    if LibVersion < OSSL_TIME_SPEC_X_DAY_OF_free_introduced then
    begin
      {$if declared(FC_OSSL_TIME_SPEC_X_DAY_OF_free)}
      OSSL_TIME_SPEC_X_DAY_OF_free := FC_OSSL_TIME_SPEC_X_DAY_OF_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_X_DAY_OF_free_removed)}
    if OSSL_TIME_SPEC_X_DAY_OF_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TIME_SPEC_X_DAY_OF_free)}
      OSSL_TIME_SPEC_X_DAY_OF_free := _OSSL_TIME_SPEC_X_DAY_OF_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TIME_SPEC_X_DAY_OF_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TIME_SPEC_X_DAY_OF_free');
    {$ifend}
  end;
  
  d2i_OSSL_TIME_SPEC_X_DAY_OF := LoadLibFunction(ADllHandle, d2i_OSSL_TIME_SPEC_X_DAY_OF_procname);
  FuncLoadError := not assigned(d2i_OSSL_TIME_SPEC_X_DAY_OF);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_TIME_SPEC_X_DAY_OF_allownil)}
    d2i_OSSL_TIME_SPEC_X_DAY_OF := ERR_d2i_OSSL_TIME_SPEC_X_DAY_OF;
    {$ifend}
    {$if declared(d2i_OSSL_TIME_SPEC_X_DAY_OF_introduced)}
    if LibVersion < d2i_OSSL_TIME_SPEC_X_DAY_OF_introduced then
    begin
      {$if declared(FC_d2i_OSSL_TIME_SPEC_X_DAY_OF)}
      d2i_OSSL_TIME_SPEC_X_DAY_OF := FC_d2i_OSSL_TIME_SPEC_X_DAY_OF;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_TIME_SPEC_X_DAY_OF_removed)}
    if d2i_OSSL_TIME_SPEC_X_DAY_OF_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_TIME_SPEC_X_DAY_OF)}
      d2i_OSSL_TIME_SPEC_X_DAY_OF := _d2i_OSSL_TIME_SPEC_X_DAY_OF;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_TIME_SPEC_X_DAY_OF_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_TIME_SPEC_X_DAY_OF');
    {$ifend}
  end;
  
  i2d_OSSL_TIME_SPEC_X_DAY_OF := LoadLibFunction(ADllHandle, i2d_OSSL_TIME_SPEC_X_DAY_OF_procname);
  FuncLoadError := not assigned(i2d_OSSL_TIME_SPEC_X_DAY_OF);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_TIME_SPEC_X_DAY_OF_allownil)}
    i2d_OSSL_TIME_SPEC_X_DAY_OF := ERR_i2d_OSSL_TIME_SPEC_X_DAY_OF;
    {$ifend}
    {$if declared(i2d_OSSL_TIME_SPEC_X_DAY_OF_introduced)}
    if LibVersion < i2d_OSSL_TIME_SPEC_X_DAY_OF_introduced then
    begin
      {$if declared(FC_i2d_OSSL_TIME_SPEC_X_DAY_OF)}
      i2d_OSSL_TIME_SPEC_X_DAY_OF := FC_i2d_OSSL_TIME_SPEC_X_DAY_OF;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_TIME_SPEC_X_DAY_OF_removed)}
    if i2d_OSSL_TIME_SPEC_X_DAY_OF_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_TIME_SPEC_X_DAY_OF)}
      i2d_OSSL_TIME_SPEC_X_DAY_OF := _i2d_OSSL_TIME_SPEC_X_DAY_OF;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_TIME_SPEC_X_DAY_OF_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_TIME_SPEC_X_DAY_OF');
    {$ifend}
  end;
  
  OSSL_TIME_SPEC_X_DAY_OF_it := LoadLibFunction(ADllHandle, OSSL_TIME_SPEC_X_DAY_OF_it_procname);
  FuncLoadError := not assigned(OSSL_TIME_SPEC_X_DAY_OF_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TIME_SPEC_X_DAY_OF_it_allownil)}
    OSSL_TIME_SPEC_X_DAY_OF_it := ERR_OSSL_TIME_SPEC_X_DAY_OF_it;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_X_DAY_OF_it_introduced)}
    if LibVersion < OSSL_TIME_SPEC_X_DAY_OF_it_introduced then
    begin
      {$if declared(FC_OSSL_TIME_SPEC_X_DAY_OF_it)}
      OSSL_TIME_SPEC_X_DAY_OF_it := FC_OSSL_TIME_SPEC_X_DAY_OF_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_X_DAY_OF_it_removed)}
    if OSSL_TIME_SPEC_X_DAY_OF_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TIME_SPEC_X_DAY_OF_it)}
      OSSL_TIME_SPEC_X_DAY_OF_it := _OSSL_TIME_SPEC_X_DAY_OF_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TIME_SPEC_X_DAY_OF_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TIME_SPEC_X_DAY_OF_it');
    {$ifend}
  end;
  
  OSSL_TIME_SPEC_ABSOLUTE_new := LoadLibFunction(ADllHandle, OSSL_TIME_SPEC_ABSOLUTE_new_procname);
  FuncLoadError := not assigned(OSSL_TIME_SPEC_ABSOLUTE_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TIME_SPEC_ABSOLUTE_new_allownil)}
    OSSL_TIME_SPEC_ABSOLUTE_new := ERR_OSSL_TIME_SPEC_ABSOLUTE_new;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_ABSOLUTE_new_introduced)}
    if LibVersion < OSSL_TIME_SPEC_ABSOLUTE_new_introduced then
    begin
      {$if declared(FC_OSSL_TIME_SPEC_ABSOLUTE_new)}
      OSSL_TIME_SPEC_ABSOLUTE_new := FC_OSSL_TIME_SPEC_ABSOLUTE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_ABSOLUTE_new_removed)}
    if OSSL_TIME_SPEC_ABSOLUTE_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TIME_SPEC_ABSOLUTE_new)}
      OSSL_TIME_SPEC_ABSOLUTE_new := _OSSL_TIME_SPEC_ABSOLUTE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TIME_SPEC_ABSOLUTE_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TIME_SPEC_ABSOLUTE_new');
    {$ifend}
  end;
  
  OSSL_TIME_SPEC_ABSOLUTE_free := LoadLibFunction(ADllHandle, OSSL_TIME_SPEC_ABSOLUTE_free_procname);
  FuncLoadError := not assigned(OSSL_TIME_SPEC_ABSOLUTE_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TIME_SPEC_ABSOLUTE_free_allownil)}
    OSSL_TIME_SPEC_ABSOLUTE_free := ERR_OSSL_TIME_SPEC_ABSOLUTE_free;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_ABSOLUTE_free_introduced)}
    if LibVersion < OSSL_TIME_SPEC_ABSOLUTE_free_introduced then
    begin
      {$if declared(FC_OSSL_TIME_SPEC_ABSOLUTE_free)}
      OSSL_TIME_SPEC_ABSOLUTE_free := FC_OSSL_TIME_SPEC_ABSOLUTE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_ABSOLUTE_free_removed)}
    if OSSL_TIME_SPEC_ABSOLUTE_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TIME_SPEC_ABSOLUTE_free)}
      OSSL_TIME_SPEC_ABSOLUTE_free := _OSSL_TIME_SPEC_ABSOLUTE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TIME_SPEC_ABSOLUTE_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TIME_SPEC_ABSOLUTE_free');
    {$ifend}
  end;
  
  d2i_OSSL_TIME_SPEC_ABSOLUTE := LoadLibFunction(ADllHandle, d2i_OSSL_TIME_SPEC_ABSOLUTE_procname);
  FuncLoadError := not assigned(d2i_OSSL_TIME_SPEC_ABSOLUTE);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_TIME_SPEC_ABSOLUTE_allownil)}
    d2i_OSSL_TIME_SPEC_ABSOLUTE := ERR_d2i_OSSL_TIME_SPEC_ABSOLUTE;
    {$ifend}
    {$if declared(d2i_OSSL_TIME_SPEC_ABSOLUTE_introduced)}
    if LibVersion < d2i_OSSL_TIME_SPEC_ABSOLUTE_introduced then
    begin
      {$if declared(FC_d2i_OSSL_TIME_SPEC_ABSOLUTE)}
      d2i_OSSL_TIME_SPEC_ABSOLUTE := FC_d2i_OSSL_TIME_SPEC_ABSOLUTE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_TIME_SPEC_ABSOLUTE_removed)}
    if d2i_OSSL_TIME_SPEC_ABSOLUTE_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_TIME_SPEC_ABSOLUTE)}
      d2i_OSSL_TIME_SPEC_ABSOLUTE := _d2i_OSSL_TIME_SPEC_ABSOLUTE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_TIME_SPEC_ABSOLUTE_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_TIME_SPEC_ABSOLUTE');
    {$ifend}
  end;
  
  i2d_OSSL_TIME_SPEC_ABSOLUTE := LoadLibFunction(ADllHandle, i2d_OSSL_TIME_SPEC_ABSOLUTE_procname);
  FuncLoadError := not assigned(i2d_OSSL_TIME_SPEC_ABSOLUTE);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_TIME_SPEC_ABSOLUTE_allownil)}
    i2d_OSSL_TIME_SPEC_ABSOLUTE := ERR_i2d_OSSL_TIME_SPEC_ABSOLUTE;
    {$ifend}
    {$if declared(i2d_OSSL_TIME_SPEC_ABSOLUTE_introduced)}
    if LibVersion < i2d_OSSL_TIME_SPEC_ABSOLUTE_introduced then
    begin
      {$if declared(FC_i2d_OSSL_TIME_SPEC_ABSOLUTE)}
      i2d_OSSL_TIME_SPEC_ABSOLUTE := FC_i2d_OSSL_TIME_SPEC_ABSOLUTE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_TIME_SPEC_ABSOLUTE_removed)}
    if i2d_OSSL_TIME_SPEC_ABSOLUTE_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_TIME_SPEC_ABSOLUTE)}
      i2d_OSSL_TIME_SPEC_ABSOLUTE := _i2d_OSSL_TIME_SPEC_ABSOLUTE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_TIME_SPEC_ABSOLUTE_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_TIME_SPEC_ABSOLUTE');
    {$ifend}
  end;
  
  OSSL_TIME_SPEC_ABSOLUTE_it := LoadLibFunction(ADllHandle, OSSL_TIME_SPEC_ABSOLUTE_it_procname);
  FuncLoadError := not assigned(OSSL_TIME_SPEC_ABSOLUTE_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TIME_SPEC_ABSOLUTE_it_allownil)}
    OSSL_TIME_SPEC_ABSOLUTE_it := ERR_OSSL_TIME_SPEC_ABSOLUTE_it;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_ABSOLUTE_it_introduced)}
    if LibVersion < OSSL_TIME_SPEC_ABSOLUTE_it_introduced then
    begin
      {$if declared(FC_OSSL_TIME_SPEC_ABSOLUTE_it)}
      OSSL_TIME_SPEC_ABSOLUTE_it := FC_OSSL_TIME_SPEC_ABSOLUTE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_ABSOLUTE_it_removed)}
    if OSSL_TIME_SPEC_ABSOLUTE_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TIME_SPEC_ABSOLUTE_it)}
      OSSL_TIME_SPEC_ABSOLUTE_it := _OSSL_TIME_SPEC_ABSOLUTE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TIME_SPEC_ABSOLUTE_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TIME_SPEC_ABSOLUTE_it');
    {$ifend}
  end;
  
  OSSL_TIME_SPEC_TIME_new := LoadLibFunction(ADllHandle, OSSL_TIME_SPEC_TIME_new_procname);
  FuncLoadError := not assigned(OSSL_TIME_SPEC_TIME_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TIME_SPEC_TIME_new_allownil)}
    OSSL_TIME_SPEC_TIME_new := ERR_OSSL_TIME_SPEC_TIME_new;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_TIME_new_introduced)}
    if LibVersion < OSSL_TIME_SPEC_TIME_new_introduced then
    begin
      {$if declared(FC_OSSL_TIME_SPEC_TIME_new)}
      OSSL_TIME_SPEC_TIME_new := FC_OSSL_TIME_SPEC_TIME_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_TIME_new_removed)}
    if OSSL_TIME_SPEC_TIME_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TIME_SPEC_TIME_new)}
      OSSL_TIME_SPEC_TIME_new := _OSSL_TIME_SPEC_TIME_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TIME_SPEC_TIME_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TIME_SPEC_TIME_new');
    {$ifend}
  end;
  
  OSSL_TIME_SPEC_TIME_free := LoadLibFunction(ADllHandle, OSSL_TIME_SPEC_TIME_free_procname);
  FuncLoadError := not assigned(OSSL_TIME_SPEC_TIME_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TIME_SPEC_TIME_free_allownil)}
    OSSL_TIME_SPEC_TIME_free := ERR_OSSL_TIME_SPEC_TIME_free;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_TIME_free_introduced)}
    if LibVersion < OSSL_TIME_SPEC_TIME_free_introduced then
    begin
      {$if declared(FC_OSSL_TIME_SPEC_TIME_free)}
      OSSL_TIME_SPEC_TIME_free := FC_OSSL_TIME_SPEC_TIME_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_TIME_free_removed)}
    if OSSL_TIME_SPEC_TIME_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TIME_SPEC_TIME_free)}
      OSSL_TIME_SPEC_TIME_free := _OSSL_TIME_SPEC_TIME_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TIME_SPEC_TIME_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TIME_SPEC_TIME_free');
    {$ifend}
  end;
  
  d2i_OSSL_TIME_SPEC_TIME := LoadLibFunction(ADllHandle, d2i_OSSL_TIME_SPEC_TIME_procname);
  FuncLoadError := not assigned(d2i_OSSL_TIME_SPEC_TIME);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_TIME_SPEC_TIME_allownil)}
    d2i_OSSL_TIME_SPEC_TIME := ERR_d2i_OSSL_TIME_SPEC_TIME;
    {$ifend}
    {$if declared(d2i_OSSL_TIME_SPEC_TIME_introduced)}
    if LibVersion < d2i_OSSL_TIME_SPEC_TIME_introduced then
    begin
      {$if declared(FC_d2i_OSSL_TIME_SPEC_TIME)}
      d2i_OSSL_TIME_SPEC_TIME := FC_d2i_OSSL_TIME_SPEC_TIME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_TIME_SPEC_TIME_removed)}
    if d2i_OSSL_TIME_SPEC_TIME_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_TIME_SPEC_TIME)}
      d2i_OSSL_TIME_SPEC_TIME := _d2i_OSSL_TIME_SPEC_TIME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_TIME_SPEC_TIME_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_TIME_SPEC_TIME');
    {$ifend}
  end;
  
  i2d_OSSL_TIME_SPEC_TIME := LoadLibFunction(ADllHandle, i2d_OSSL_TIME_SPEC_TIME_procname);
  FuncLoadError := not assigned(i2d_OSSL_TIME_SPEC_TIME);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_TIME_SPEC_TIME_allownil)}
    i2d_OSSL_TIME_SPEC_TIME := ERR_i2d_OSSL_TIME_SPEC_TIME;
    {$ifend}
    {$if declared(i2d_OSSL_TIME_SPEC_TIME_introduced)}
    if LibVersion < i2d_OSSL_TIME_SPEC_TIME_introduced then
    begin
      {$if declared(FC_i2d_OSSL_TIME_SPEC_TIME)}
      i2d_OSSL_TIME_SPEC_TIME := FC_i2d_OSSL_TIME_SPEC_TIME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_TIME_SPEC_TIME_removed)}
    if i2d_OSSL_TIME_SPEC_TIME_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_TIME_SPEC_TIME)}
      i2d_OSSL_TIME_SPEC_TIME := _i2d_OSSL_TIME_SPEC_TIME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_TIME_SPEC_TIME_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_TIME_SPEC_TIME');
    {$ifend}
  end;
  
  OSSL_TIME_SPEC_TIME_it := LoadLibFunction(ADllHandle, OSSL_TIME_SPEC_TIME_it_procname);
  FuncLoadError := not assigned(OSSL_TIME_SPEC_TIME_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TIME_SPEC_TIME_it_allownil)}
    OSSL_TIME_SPEC_TIME_it := ERR_OSSL_TIME_SPEC_TIME_it;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_TIME_it_introduced)}
    if LibVersion < OSSL_TIME_SPEC_TIME_it_introduced then
    begin
      {$if declared(FC_OSSL_TIME_SPEC_TIME_it)}
      OSSL_TIME_SPEC_TIME_it := FC_OSSL_TIME_SPEC_TIME_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_TIME_it_removed)}
    if OSSL_TIME_SPEC_TIME_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TIME_SPEC_TIME_it)}
      OSSL_TIME_SPEC_TIME_it := _OSSL_TIME_SPEC_TIME_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TIME_SPEC_TIME_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TIME_SPEC_TIME_it');
    {$ifend}
  end;
  
  OSSL_TIME_SPEC_new := LoadLibFunction(ADllHandle, OSSL_TIME_SPEC_new_procname);
  FuncLoadError := not assigned(OSSL_TIME_SPEC_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TIME_SPEC_new_allownil)}
    OSSL_TIME_SPEC_new := ERR_OSSL_TIME_SPEC_new;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_new_introduced)}
    if LibVersion < OSSL_TIME_SPEC_new_introduced then
    begin
      {$if declared(FC_OSSL_TIME_SPEC_new)}
      OSSL_TIME_SPEC_new := FC_OSSL_TIME_SPEC_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_new_removed)}
    if OSSL_TIME_SPEC_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TIME_SPEC_new)}
      OSSL_TIME_SPEC_new := _OSSL_TIME_SPEC_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TIME_SPEC_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TIME_SPEC_new');
    {$ifend}
  end;
  
  OSSL_TIME_SPEC_free := LoadLibFunction(ADllHandle, OSSL_TIME_SPEC_free_procname);
  FuncLoadError := not assigned(OSSL_TIME_SPEC_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TIME_SPEC_free_allownil)}
    OSSL_TIME_SPEC_free := ERR_OSSL_TIME_SPEC_free;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_free_introduced)}
    if LibVersion < OSSL_TIME_SPEC_free_introduced then
    begin
      {$if declared(FC_OSSL_TIME_SPEC_free)}
      OSSL_TIME_SPEC_free := FC_OSSL_TIME_SPEC_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_free_removed)}
    if OSSL_TIME_SPEC_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TIME_SPEC_free)}
      OSSL_TIME_SPEC_free := _OSSL_TIME_SPEC_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TIME_SPEC_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TIME_SPEC_free');
    {$ifend}
  end;
  
  d2i_OSSL_TIME_SPEC := LoadLibFunction(ADllHandle, d2i_OSSL_TIME_SPEC_procname);
  FuncLoadError := not assigned(d2i_OSSL_TIME_SPEC);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_TIME_SPEC_allownil)}
    d2i_OSSL_TIME_SPEC := ERR_d2i_OSSL_TIME_SPEC;
    {$ifend}
    {$if declared(d2i_OSSL_TIME_SPEC_introduced)}
    if LibVersion < d2i_OSSL_TIME_SPEC_introduced then
    begin
      {$if declared(FC_d2i_OSSL_TIME_SPEC)}
      d2i_OSSL_TIME_SPEC := FC_d2i_OSSL_TIME_SPEC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_TIME_SPEC_removed)}
    if d2i_OSSL_TIME_SPEC_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_TIME_SPEC)}
      d2i_OSSL_TIME_SPEC := _d2i_OSSL_TIME_SPEC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_TIME_SPEC_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_TIME_SPEC');
    {$ifend}
  end;
  
  i2d_OSSL_TIME_SPEC := LoadLibFunction(ADllHandle, i2d_OSSL_TIME_SPEC_procname);
  FuncLoadError := not assigned(i2d_OSSL_TIME_SPEC);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_TIME_SPEC_allownil)}
    i2d_OSSL_TIME_SPEC := ERR_i2d_OSSL_TIME_SPEC;
    {$ifend}
    {$if declared(i2d_OSSL_TIME_SPEC_introduced)}
    if LibVersion < i2d_OSSL_TIME_SPEC_introduced then
    begin
      {$if declared(FC_i2d_OSSL_TIME_SPEC)}
      i2d_OSSL_TIME_SPEC := FC_i2d_OSSL_TIME_SPEC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_TIME_SPEC_removed)}
    if i2d_OSSL_TIME_SPEC_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_TIME_SPEC)}
      i2d_OSSL_TIME_SPEC := _i2d_OSSL_TIME_SPEC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_TIME_SPEC_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_TIME_SPEC');
    {$ifend}
  end;
  
  OSSL_TIME_SPEC_it := LoadLibFunction(ADllHandle, OSSL_TIME_SPEC_it_procname);
  FuncLoadError := not assigned(OSSL_TIME_SPEC_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TIME_SPEC_it_allownil)}
    OSSL_TIME_SPEC_it := ERR_OSSL_TIME_SPEC_it;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_it_introduced)}
    if LibVersion < OSSL_TIME_SPEC_it_introduced then
    begin
      {$if declared(FC_OSSL_TIME_SPEC_it)}
      OSSL_TIME_SPEC_it := FC_OSSL_TIME_SPEC_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TIME_SPEC_it_removed)}
    if OSSL_TIME_SPEC_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TIME_SPEC_it)}
      OSSL_TIME_SPEC_it := _OSSL_TIME_SPEC_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TIME_SPEC_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TIME_SPEC_it');
    {$ifend}
  end;
  
  OSSL_TIME_PERIOD_new := LoadLibFunction(ADllHandle, OSSL_TIME_PERIOD_new_procname);
  FuncLoadError := not assigned(OSSL_TIME_PERIOD_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TIME_PERIOD_new_allownil)}
    OSSL_TIME_PERIOD_new := ERR_OSSL_TIME_PERIOD_new;
    {$ifend}
    {$if declared(OSSL_TIME_PERIOD_new_introduced)}
    if LibVersion < OSSL_TIME_PERIOD_new_introduced then
    begin
      {$if declared(FC_OSSL_TIME_PERIOD_new)}
      OSSL_TIME_PERIOD_new := FC_OSSL_TIME_PERIOD_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TIME_PERIOD_new_removed)}
    if OSSL_TIME_PERIOD_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TIME_PERIOD_new)}
      OSSL_TIME_PERIOD_new := _OSSL_TIME_PERIOD_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TIME_PERIOD_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TIME_PERIOD_new');
    {$ifend}
  end;
  
  OSSL_TIME_PERIOD_free := LoadLibFunction(ADllHandle, OSSL_TIME_PERIOD_free_procname);
  FuncLoadError := not assigned(OSSL_TIME_PERIOD_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TIME_PERIOD_free_allownil)}
    OSSL_TIME_PERIOD_free := ERR_OSSL_TIME_PERIOD_free;
    {$ifend}
    {$if declared(OSSL_TIME_PERIOD_free_introduced)}
    if LibVersion < OSSL_TIME_PERIOD_free_introduced then
    begin
      {$if declared(FC_OSSL_TIME_PERIOD_free)}
      OSSL_TIME_PERIOD_free := FC_OSSL_TIME_PERIOD_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TIME_PERIOD_free_removed)}
    if OSSL_TIME_PERIOD_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TIME_PERIOD_free)}
      OSSL_TIME_PERIOD_free := _OSSL_TIME_PERIOD_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TIME_PERIOD_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TIME_PERIOD_free');
    {$ifend}
  end;
  
  d2i_OSSL_TIME_PERIOD := LoadLibFunction(ADllHandle, d2i_OSSL_TIME_PERIOD_procname);
  FuncLoadError := not assigned(d2i_OSSL_TIME_PERIOD);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_TIME_PERIOD_allownil)}
    d2i_OSSL_TIME_PERIOD := ERR_d2i_OSSL_TIME_PERIOD;
    {$ifend}
    {$if declared(d2i_OSSL_TIME_PERIOD_introduced)}
    if LibVersion < d2i_OSSL_TIME_PERIOD_introduced then
    begin
      {$if declared(FC_d2i_OSSL_TIME_PERIOD)}
      d2i_OSSL_TIME_PERIOD := FC_d2i_OSSL_TIME_PERIOD;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_TIME_PERIOD_removed)}
    if d2i_OSSL_TIME_PERIOD_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_TIME_PERIOD)}
      d2i_OSSL_TIME_PERIOD := _d2i_OSSL_TIME_PERIOD;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_TIME_PERIOD_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_TIME_PERIOD');
    {$ifend}
  end;
  
  i2d_OSSL_TIME_PERIOD := LoadLibFunction(ADllHandle, i2d_OSSL_TIME_PERIOD_procname);
  FuncLoadError := not assigned(i2d_OSSL_TIME_PERIOD);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_TIME_PERIOD_allownil)}
    i2d_OSSL_TIME_PERIOD := ERR_i2d_OSSL_TIME_PERIOD;
    {$ifend}
    {$if declared(i2d_OSSL_TIME_PERIOD_introduced)}
    if LibVersion < i2d_OSSL_TIME_PERIOD_introduced then
    begin
      {$if declared(FC_i2d_OSSL_TIME_PERIOD)}
      i2d_OSSL_TIME_PERIOD := FC_i2d_OSSL_TIME_PERIOD;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_TIME_PERIOD_removed)}
    if i2d_OSSL_TIME_PERIOD_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_TIME_PERIOD)}
      i2d_OSSL_TIME_PERIOD := _i2d_OSSL_TIME_PERIOD;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_TIME_PERIOD_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_TIME_PERIOD');
    {$ifend}
  end;
  
  OSSL_TIME_PERIOD_it := LoadLibFunction(ADllHandle, OSSL_TIME_PERIOD_it_procname);
  FuncLoadError := not assigned(OSSL_TIME_PERIOD_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TIME_PERIOD_it_allownil)}
    OSSL_TIME_PERIOD_it := ERR_OSSL_TIME_PERIOD_it;
    {$ifend}
    {$if declared(OSSL_TIME_PERIOD_it_introduced)}
    if LibVersion < OSSL_TIME_PERIOD_it_introduced then
    begin
      {$if declared(FC_OSSL_TIME_PERIOD_it)}
      OSSL_TIME_PERIOD_it := FC_OSSL_TIME_PERIOD_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TIME_PERIOD_it_removed)}
    if OSSL_TIME_PERIOD_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TIME_PERIOD_it)}
      OSSL_TIME_PERIOD_it := _OSSL_TIME_PERIOD_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TIME_PERIOD_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TIME_PERIOD_it');
    {$ifend}
  end;
  
  OSSL_ATAV_new := LoadLibFunction(ADllHandle, OSSL_ATAV_new_procname);
  FuncLoadError := not assigned(OSSL_ATAV_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ATAV_new_allownil)}
    OSSL_ATAV_new := ERR_OSSL_ATAV_new;
    {$ifend}
    {$if declared(OSSL_ATAV_new_introduced)}
    if LibVersion < OSSL_ATAV_new_introduced then
    begin
      {$if declared(FC_OSSL_ATAV_new)}
      OSSL_ATAV_new := FC_OSSL_ATAV_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ATAV_new_removed)}
    if OSSL_ATAV_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ATAV_new)}
      OSSL_ATAV_new := _OSSL_ATAV_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ATAV_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ATAV_new');
    {$ifend}
  end;
  
  OSSL_ATAV_free := LoadLibFunction(ADllHandle, OSSL_ATAV_free_procname);
  FuncLoadError := not assigned(OSSL_ATAV_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ATAV_free_allownil)}
    OSSL_ATAV_free := ERR_OSSL_ATAV_free;
    {$ifend}
    {$if declared(OSSL_ATAV_free_introduced)}
    if LibVersion < OSSL_ATAV_free_introduced then
    begin
      {$if declared(FC_OSSL_ATAV_free)}
      OSSL_ATAV_free := FC_OSSL_ATAV_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ATAV_free_removed)}
    if OSSL_ATAV_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ATAV_free)}
      OSSL_ATAV_free := _OSSL_ATAV_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ATAV_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ATAV_free');
    {$ifend}
  end;
  
  d2i_OSSL_ATAV := LoadLibFunction(ADllHandle, d2i_OSSL_ATAV_procname);
  FuncLoadError := not assigned(d2i_OSSL_ATAV);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_ATAV_allownil)}
    d2i_OSSL_ATAV := ERR_d2i_OSSL_ATAV;
    {$ifend}
    {$if declared(d2i_OSSL_ATAV_introduced)}
    if LibVersion < d2i_OSSL_ATAV_introduced then
    begin
      {$if declared(FC_d2i_OSSL_ATAV)}
      d2i_OSSL_ATAV := FC_d2i_OSSL_ATAV;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_ATAV_removed)}
    if d2i_OSSL_ATAV_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_ATAV)}
      d2i_OSSL_ATAV := _d2i_OSSL_ATAV;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_ATAV_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_ATAV');
    {$ifend}
  end;
  
  i2d_OSSL_ATAV := LoadLibFunction(ADllHandle, i2d_OSSL_ATAV_procname);
  FuncLoadError := not assigned(i2d_OSSL_ATAV);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_ATAV_allownil)}
    i2d_OSSL_ATAV := ERR_i2d_OSSL_ATAV;
    {$ifend}
    {$if declared(i2d_OSSL_ATAV_introduced)}
    if LibVersion < i2d_OSSL_ATAV_introduced then
    begin
      {$if declared(FC_i2d_OSSL_ATAV)}
      i2d_OSSL_ATAV := FC_i2d_OSSL_ATAV;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_ATAV_removed)}
    if i2d_OSSL_ATAV_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_ATAV)}
      i2d_OSSL_ATAV := _i2d_OSSL_ATAV;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_ATAV_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_ATAV');
    {$ifend}
  end;
  
  OSSL_ATAV_it := LoadLibFunction(ADllHandle, OSSL_ATAV_it_procname);
  FuncLoadError := not assigned(OSSL_ATAV_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ATAV_it_allownil)}
    OSSL_ATAV_it := ERR_OSSL_ATAV_it;
    {$ifend}
    {$if declared(OSSL_ATAV_it_introduced)}
    if LibVersion < OSSL_ATAV_it_introduced then
    begin
      {$if declared(FC_OSSL_ATAV_it)}
      OSSL_ATAV_it := FC_OSSL_ATAV_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ATAV_it_removed)}
    if OSSL_ATAV_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ATAV_it)}
      OSSL_ATAV_it := _OSSL_ATAV_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ATAV_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ATAV_it');
    {$ifend}
  end;
  
  OSSL_ATTRIBUTE_TYPE_MAPPING_new := LoadLibFunction(ADllHandle, OSSL_ATTRIBUTE_TYPE_MAPPING_new_procname);
  FuncLoadError := not assigned(OSSL_ATTRIBUTE_TYPE_MAPPING_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ATTRIBUTE_TYPE_MAPPING_new_allownil)}
    OSSL_ATTRIBUTE_TYPE_MAPPING_new := ERR_OSSL_ATTRIBUTE_TYPE_MAPPING_new;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_TYPE_MAPPING_new_introduced)}
    if LibVersion < OSSL_ATTRIBUTE_TYPE_MAPPING_new_introduced then
    begin
      {$if declared(FC_OSSL_ATTRIBUTE_TYPE_MAPPING_new)}
      OSSL_ATTRIBUTE_TYPE_MAPPING_new := FC_OSSL_ATTRIBUTE_TYPE_MAPPING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_TYPE_MAPPING_new_removed)}
    if OSSL_ATTRIBUTE_TYPE_MAPPING_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ATTRIBUTE_TYPE_MAPPING_new)}
      OSSL_ATTRIBUTE_TYPE_MAPPING_new := _OSSL_ATTRIBUTE_TYPE_MAPPING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ATTRIBUTE_TYPE_MAPPING_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ATTRIBUTE_TYPE_MAPPING_new');
    {$ifend}
  end;
  
  OSSL_ATTRIBUTE_TYPE_MAPPING_free := LoadLibFunction(ADllHandle, OSSL_ATTRIBUTE_TYPE_MAPPING_free_procname);
  FuncLoadError := not assigned(OSSL_ATTRIBUTE_TYPE_MAPPING_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ATTRIBUTE_TYPE_MAPPING_free_allownil)}
    OSSL_ATTRIBUTE_TYPE_MAPPING_free := ERR_OSSL_ATTRIBUTE_TYPE_MAPPING_free;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_TYPE_MAPPING_free_introduced)}
    if LibVersion < OSSL_ATTRIBUTE_TYPE_MAPPING_free_introduced then
    begin
      {$if declared(FC_OSSL_ATTRIBUTE_TYPE_MAPPING_free)}
      OSSL_ATTRIBUTE_TYPE_MAPPING_free := FC_OSSL_ATTRIBUTE_TYPE_MAPPING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_TYPE_MAPPING_free_removed)}
    if OSSL_ATTRIBUTE_TYPE_MAPPING_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ATTRIBUTE_TYPE_MAPPING_free)}
      OSSL_ATTRIBUTE_TYPE_MAPPING_free := _OSSL_ATTRIBUTE_TYPE_MAPPING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ATTRIBUTE_TYPE_MAPPING_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ATTRIBUTE_TYPE_MAPPING_free');
    {$ifend}
  end;
  
  d2i_OSSL_ATTRIBUTE_TYPE_MAPPING := LoadLibFunction(ADllHandle, d2i_OSSL_ATTRIBUTE_TYPE_MAPPING_procname);
  FuncLoadError := not assigned(d2i_OSSL_ATTRIBUTE_TYPE_MAPPING);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_ATTRIBUTE_TYPE_MAPPING_allownil)}
    d2i_OSSL_ATTRIBUTE_TYPE_MAPPING := ERR_d2i_OSSL_ATTRIBUTE_TYPE_MAPPING;
    {$ifend}
    {$if declared(d2i_OSSL_ATTRIBUTE_TYPE_MAPPING_introduced)}
    if LibVersion < d2i_OSSL_ATTRIBUTE_TYPE_MAPPING_introduced then
    begin
      {$if declared(FC_d2i_OSSL_ATTRIBUTE_TYPE_MAPPING)}
      d2i_OSSL_ATTRIBUTE_TYPE_MAPPING := FC_d2i_OSSL_ATTRIBUTE_TYPE_MAPPING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_ATTRIBUTE_TYPE_MAPPING_removed)}
    if d2i_OSSL_ATTRIBUTE_TYPE_MAPPING_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_ATTRIBUTE_TYPE_MAPPING)}
      d2i_OSSL_ATTRIBUTE_TYPE_MAPPING := _d2i_OSSL_ATTRIBUTE_TYPE_MAPPING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_ATTRIBUTE_TYPE_MAPPING_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_ATTRIBUTE_TYPE_MAPPING');
    {$ifend}
  end;
  
  i2d_OSSL_ATTRIBUTE_TYPE_MAPPING := LoadLibFunction(ADllHandle, i2d_OSSL_ATTRIBUTE_TYPE_MAPPING_procname);
  FuncLoadError := not assigned(i2d_OSSL_ATTRIBUTE_TYPE_MAPPING);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_ATTRIBUTE_TYPE_MAPPING_allownil)}
    i2d_OSSL_ATTRIBUTE_TYPE_MAPPING := ERR_i2d_OSSL_ATTRIBUTE_TYPE_MAPPING;
    {$ifend}
    {$if declared(i2d_OSSL_ATTRIBUTE_TYPE_MAPPING_introduced)}
    if LibVersion < i2d_OSSL_ATTRIBUTE_TYPE_MAPPING_introduced then
    begin
      {$if declared(FC_i2d_OSSL_ATTRIBUTE_TYPE_MAPPING)}
      i2d_OSSL_ATTRIBUTE_TYPE_MAPPING := FC_i2d_OSSL_ATTRIBUTE_TYPE_MAPPING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_ATTRIBUTE_TYPE_MAPPING_removed)}
    if i2d_OSSL_ATTRIBUTE_TYPE_MAPPING_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_ATTRIBUTE_TYPE_MAPPING)}
      i2d_OSSL_ATTRIBUTE_TYPE_MAPPING := _i2d_OSSL_ATTRIBUTE_TYPE_MAPPING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_ATTRIBUTE_TYPE_MAPPING_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_ATTRIBUTE_TYPE_MAPPING');
    {$ifend}
  end;
  
  OSSL_ATTRIBUTE_TYPE_MAPPING_it := LoadLibFunction(ADllHandle, OSSL_ATTRIBUTE_TYPE_MAPPING_it_procname);
  FuncLoadError := not assigned(OSSL_ATTRIBUTE_TYPE_MAPPING_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ATTRIBUTE_TYPE_MAPPING_it_allownil)}
    OSSL_ATTRIBUTE_TYPE_MAPPING_it := ERR_OSSL_ATTRIBUTE_TYPE_MAPPING_it;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_TYPE_MAPPING_it_introduced)}
    if LibVersion < OSSL_ATTRIBUTE_TYPE_MAPPING_it_introduced then
    begin
      {$if declared(FC_OSSL_ATTRIBUTE_TYPE_MAPPING_it)}
      OSSL_ATTRIBUTE_TYPE_MAPPING_it := FC_OSSL_ATTRIBUTE_TYPE_MAPPING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_TYPE_MAPPING_it_removed)}
    if OSSL_ATTRIBUTE_TYPE_MAPPING_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ATTRIBUTE_TYPE_MAPPING_it)}
      OSSL_ATTRIBUTE_TYPE_MAPPING_it := _OSSL_ATTRIBUTE_TYPE_MAPPING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ATTRIBUTE_TYPE_MAPPING_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ATTRIBUTE_TYPE_MAPPING_it');
    {$ifend}
  end;
  
  OSSL_ATTRIBUTE_VALUE_MAPPING_new := LoadLibFunction(ADllHandle, OSSL_ATTRIBUTE_VALUE_MAPPING_new_procname);
  FuncLoadError := not assigned(OSSL_ATTRIBUTE_VALUE_MAPPING_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ATTRIBUTE_VALUE_MAPPING_new_allownil)}
    OSSL_ATTRIBUTE_VALUE_MAPPING_new := ERR_OSSL_ATTRIBUTE_VALUE_MAPPING_new;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_VALUE_MAPPING_new_introduced)}
    if LibVersion < OSSL_ATTRIBUTE_VALUE_MAPPING_new_introduced then
    begin
      {$if declared(FC_OSSL_ATTRIBUTE_VALUE_MAPPING_new)}
      OSSL_ATTRIBUTE_VALUE_MAPPING_new := FC_OSSL_ATTRIBUTE_VALUE_MAPPING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_VALUE_MAPPING_new_removed)}
    if OSSL_ATTRIBUTE_VALUE_MAPPING_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ATTRIBUTE_VALUE_MAPPING_new)}
      OSSL_ATTRIBUTE_VALUE_MAPPING_new := _OSSL_ATTRIBUTE_VALUE_MAPPING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ATTRIBUTE_VALUE_MAPPING_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ATTRIBUTE_VALUE_MAPPING_new');
    {$ifend}
  end;
  
  OSSL_ATTRIBUTE_VALUE_MAPPING_free := LoadLibFunction(ADllHandle, OSSL_ATTRIBUTE_VALUE_MAPPING_free_procname);
  FuncLoadError := not assigned(OSSL_ATTRIBUTE_VALUE_MAPPING_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ATTRIBUTE_VALUE_MAPPING_free_allownil)}
    OSSL_ATTRIBUTE_VALUE_MAPPING_free := ERR_OSSL_ATTRIBUTE_VALUE_MAPPING_free;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_VALUE_MAPPING_free_introduced)}
    if LibVersion < OSSL_ATTRIBUTE_VALUE_MAPPING_free_introduced then
    begin
      {$if declared(FC_OSSL_ATTRIBUTE_VALUE_MAPPING_free)}
      OSSL_ATTRIBUTE_VALUE_MAPPING_free := FC_OSSL_ATTRIBUTE_VALUE_MAPPING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_VALUE_MAPPING_free_removed)}
    if OSSL_ATTRIBUTE_VALUE_MAPPING_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ATTRIBUTE_VALUE_MAPPING_free)}
      OSSL_ATTRIBUTE_VALUE_MAPPING_free := _OSSL_ATTRIBUTE_VALUE_MAPPING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ATTRIBUTE_VALUE_MAPPING_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ATTRIBUTE_VALUE_MAPPING_free');
    {$ifend}
  end;
  
  d2i_OSSL_ATTRIBUTE_VALUE_MAPPING := LoadLibFunction(ADllHandle, d2i_OSSL_ATTRIBUTE_VALUE_MAPPING_procname);
  FuncLoadError := not assigned(d2i_OSSL_ATTRIBUTE_VALUE_MAPPING);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_ATTRIBUTE_VALUE_MAPPING_allownil)}
    d2i_OSSL_ATTRIBUTE_VALUE_MAPPING := ERR_d2i_OSSL_ATTRIBUTE_VALUE_MAPPING;
    {$ifend}
    {$if declared(d2i_OSSL_ATTRIBUTE_VALUE_MAPPING_introduced)}
    if LibVersion < d2i_OSSL_ATTRIBUTE_VALUE_MAPPING_introduced then
    begin
      {$if declared(FC_d2i_OSSL_ATTRIBUTE_VALUE_MAPPING)}
      d2i_OSSL_ATTRIBUTE_VALUE_MAPPING := FC_d2i_OSSL_ATTRIBUTE_VALUE_MAPPING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_ATTRIBUTE_VALUE_MAPPING_removed)}
    if d2i_OSSL_ATTRIBUTE_VALUE_MAPPING_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_ATTRIBUTE_VALUE_MAPPING)}
      d2i_OSSL_ATTRIBUTE_VALUE_MAPPING := _d2i_OSSL_ATTRIBUTE_VALUE_MAPPING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_ATTRIBUTE_VALUE_MAPPING_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_ATTRIBUTE_VALUE_MAPPING');
    {$ifend}
  end;
  
  i2d_OSSL_ATTRIBUTE_VALUE_MAPPING := LoadLibFunction(ADllHandle, i2d_OSSL_ATTRIBUTE_VALUE_MAPPING_procname);
  FuncLoadError := not assigned(i2d_OSSL_ATTRIBUTE_VALUE_MAPPING);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_ATTRIBUTE_VALUE_MAPPING_allownil)}
    i2d_OSSL_ATTRIBUTE_VALUE_MAPPING := ERR_i2d_OSSL_ATTRIBUTE_VALUE_MAPPING;
    {$ifend}
    {$if declared(i2d_OSSL_ATTRIBUTE_VALUE_MAPPING_introduced)}
    if LibVersion < i2d_OSSL_ATTRIBUTE_VALUE_MAPPING_introduced then
    begin
      {$if declared(FC_i2d_OSSL_ATTRIBUTE_VALUE_MAPPING)}
      i2d_OSSL_ATTRIBUTE_VALUE_MAPPING := FC_i2d_OSSL_ATTRIBUTE_VALUE_MAPPING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_ATTRIBUTE_VALUE_MAPPING_removed)}
    if i2d_OSSL_ATTRIBUTE_VALUE_MAPPING_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_ATTRIBUTE_VALUE_MAPPING)}
      i2d_OSSL_ATTRIBUTE_VALUE_MAPPING := _i2d_OSSL_ATTRIBUTE_VALUE_MAPPING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_ATTRIBUTE_VALUE_MAPPING_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_ATTRIBUTE_VALUE_MAPPING');
    {$ifend}
  end;
  
  OSSL_ATTRIBUTE_VALUE_MAPPING_it := LoadLibFunction(ADllHandle, OSSL_ATTRIBUTE_VALUE_MAPPING_it_procname);
  FuncLoadError := not assigned(OSSL_ATTRIBUTE_VALUE_MAPPING_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ATTRIBUTE_VALUE_MAPPING_it_allownil)}
    OSSL_ATTRIBUTE_VALUE_MAPPING_it := ERR_OSSL_ATTRIBUTE_VALUE_MAPPING_it;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_VALUE_MAPPING_it_introduced)}
    if LibVersion < OSSL_ATTRIBUTE_VALUE_MAPPING_it_introduced then
    begin
      {$if declared(FC_OSSL_ATTRIBUTE_VALUE_MAPPING_it)}
      OSSL_ATTRIBUTE_VALUE_MAPPING_it := FC_OSSL_ATTRIBUTE_VALUE_MAPPING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_VALUE_MAPPING_it_removed)}
    if OSSL_ATTRIBUTE_VALUE_MAPPING_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ATTRIBUTE_VALUE_MAPPING_it)}
      OSSL_ATTRIBUTE_VALUE_MAPPING_it := _OSSL_ATTRIBUTE_VALUE_MAPPING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ATTRIBUTE_VALUE_MAPPING_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ATTRIBUTE_VALUE_MAPPING_it');
    {$ifend}
  end;
  
  OSSL_ATTRIBUTE_MAPPING_new := LoadLibFunction(ADllHandle, OSSL_ATTRIBUTE_MAPPING_new_procname);
  FuncLoadError := not assigned(OSSL_ATTRIBUTE_MAPPING_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ATTRIBUTE_MAPPING_new_allownil)}
    OSSL_ATTRIBUTE_MAPPING_new := ERR_OSSL_ATTRIBUTE_MAPPING_new;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_MAPPING_new_introduced)}
    if LibVersion < OSSL_ATTRIBUTE_MAPPING_new_introduced then
    begin
      {$if declared(FC_OSSL_ATTRIBUTE_MAPPING_new)}
      OSSL_ATTRIBUTE_MAPPING_new := FC_OSSL_ATTRIBUTE_MAPPING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_MAPPING_new_removed)}
    if OSSL_ATTRIBUTE_MAPPING_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ATTRIBUTE_MAPPING_new)}
      OSSL_ATTRIBUTE_MAPPING_new := _OSSL_ATTRIBUTE_MAPPING_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ATTRIBUTE_MAPPING_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ATTRIBUTE_MAPPING_new');
    {$ifend}
  end;
  
  OSSL_ATTRIBUTE_MAPPING_free := LoadLibFunction(ADllHandle, OSSL_ATTRIBUTE_MAPPING_free_procname);
  FuncLoadError := not assigned(OSSL_ATTRIBUTE_MAPPING_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ATTRIBUTE_MAPPING_free_allownil)}
    OSSL_ATTRIBUTE_MAPPING_free := ERR_OSSL_ATTRIBUTE_MAPPING_free;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_MAPPING_free_introduced)}
    if LibVersion < OSSL_ATTRIBUTE_MAPPING_free_introduced then
    begin
      {$if declared(FC_OSSL_ATTRIBUTE_MAPPING_free)}
      OSSL_ATTRIBUTE_MAPPING_free := FC_OSSL_ATTRIBUTE_MAPPING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_MAPPING_free_removed)}
    if OSSL_ATTRIBUTE_MAPPING_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ATTRIBUTE_MAPPING_free)}
      OSSL_ATTRIBUTE_MAPPING_free := _OSSL_ATTRIBUTE_MAPPING_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ATTRIBUTE_MAPPING_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ATTRIBUTE_MAPPING_free');
    {$ifend}
  end;
  
  d2i_OSSL_ATTRIBUTE_MAPPING := LoadLibFunction(ADllHandle, d2i_OSSL_ATTRIBUTE_MAPPING_procname);
  FuncLoadError := not assigned(d2i_OSSL_ATTRIBUTE_MAPPING);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_ATTRIBUTE_MAPPING_allownil)}
    d2i_OSSL_ATTRIBUTE_MAPPING := ERR_d2i_OSSL_ATTRIBUTE_MAPPING;
    {$ifend}
    {$if declared(d2i_OSSL_ATTRIBUTE_MAPPING_introduced)}
    if LibVersion < d2i_OSSL_ATTRIBUTE_MAPPING_introduced then
    begin
      {$if declared(FC_d2i_OSSL_ATTRIBUTE_MAPPING)}
      d2i_OSSL_ATTRIBUTE_MAPPING := FC_d2i_OSSL_ATTRIBUTE_MAPPING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_ATTRIBUTE_MAPPING_removed)}
    if d2i_OSSL_ATTRIBUTE_MAPPING_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_ATTRIBUTE_MAPPING)}
      d2i_OSSL_ATTRIBUTE_MAPPING := _d2i_OSSL_ATTRIBUTE_MAPPING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_ATTRIBUTE_MAPPING_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_ATTRIBUTE_MAPPING');
    {$ifend}
  end;
  
  i2d_OSSL_ATTRIBUTE_MAPPING := LoadLibFunction(ADllHandle, i2d_OSSL_ATTRIBUTE_MAPPING_procname);
  FuncLoadError := not assigned(i2d_OSSL_ATTRIBUTE_MAPPING);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_ATTRIBUTE_MAPPING_allownil)}
    i2d_OSSL_ATTRIBUTE_MAPPING := ERR_i2d_OSSL_ATTRIBUTE_MAPPING;
    {$ifend}
    {$if declared(i2d_OSSL_ATTRIBUTE_MAPPING_introduced)}
    if LibVersion < i2d_OSSL_ATTRIBUTE_MAPPING_introduced then
    begin
      {$if declared(FC_i2d_OSSL_ATTRIBUTE_MAPPING)}
      i2d_OSSL_ATTRIBUTE_MAPPING := FC_i2d_OSSL_ATTRIBUTE_MAPPING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_ATTRIBUTE_MAPPING_removed)}
    if i2d_OSSL_ATTRIBUTE_MAPPING_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_ATTRIBUTE_MAPPING)}
      i2d_OSSL_ATTRIBUTE_MAPPING := _i2d_OSSL_ATTRIBUTE_MAPPING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_ATTRIBUTE_MAPPING_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_ATTRIBUTE_MAPPING');
    {$ifend}
  end;
  
  OSSL_ATTRIBUTE_MAPPING_it := LoadLibFunction(ADllHandle, OSSL_ATTRIBUTE_MAPPING_it_procname);
  FuncLoadError := not assigned(OSSL_ATTRIBUTE_MAPPING_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ATTRIBUTE_MAPPING_it_allownil)}
    OSSL_ATTRIBUTE_MAPPING_it := ERR_OSSL_ATTRIBUTE_MAPPING_it;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_MAPPING_it_introduced)}
    if LibVersion < OSSL_ATTRIBUTE_MAPPING_it_introduced then
    begin
      {$if declared(FC_OSSL_ATTRIBUTE_MAPPING_it)}
      OSSL_ATTRIBUTE_MAPPING_it := FC_OSSL_ATTRIBUTE_MAPPING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_MAPPING_it_removed)}
    if OSSL_ATTRIBUTE_MAPPING_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ATTRIBUTE_MAPPING_it)}
      OSSL_ATTRIBUTE_MAPPING_it := _OSSL_ATTRIBUTE_MAPPING_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ATTRIBUTE_MAPPING_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ATTRIBUTE_MAPPING_it');
    {$ifend}
  end;
  
  OSSL_ATTRIBUTE_MAPPINGS_new := LoadLibFunction(ADllHandle, OSSL_ATTRIBUTE_MAPPINGS_new_procname);
  FuncLoadError := not assigned(OSSL_ATTRIBUTE_MAPPINGS_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ATTRIBUTE_MAPPINGS_new_allownil)}
    OSSL_ATTRIBUTE_MAPPINGS_new := ERR_OSSL_ATTRIBUTE_MAPPINGS_new;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_MAPPINGS_new_introduced)}
    if LibVersion < OSSL_ATTRIBUTE_MAPPINGS_new_introduced then
    begin
      {$if declared(FC_OSSL_ATTRIBUTE_MAPPINGS_new)}
      OSSL_ATTRIBUTE_MAPPINGS_new := FC_OSSL_ATTRIBUTE_MAPPINGS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_MAPPINGS_new_removed)}
    if OSSL_ATTRIBUTE_MAPPINGS_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ATTRIBUTE_MAPPINGS_new)}
      OSSL_ATTRIBUTE_MAPPINGS_new := _OSSL_ATTRIBUTE_MAPPINGS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ATTRIBUTE_MAPPINGS_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ATTRIBUTE_MAPPINGS_new');
    {$ifend}
  end;
  
  OSSL_ATTRIBUTE_MAPPINGS_free := LoadLibFunction(ADllHandle, OSSL_ATTRIBUTE_MAPPINGS_free_procname);
  FuncLoadError := not assigned(OSSL_ATTRIBUTE_MAPPINGS_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ATTRIBUTE_MAPPINGS_free_allownil)}
    OSSL_ATTRIBUTE_MAPPINGS_free := ERR_OSSL_ATTRIBUTE_MAPPINGS_free;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_MAPPINGS_free_introduced)}
    if LibVersion < OSSL_ATTRIBUTE_MAPPINGS_free_introduced then
    begin
      {$if declared(FC_OSSL_ATTRIBUTE_MAPPINGS_free)}
      OSSL_ATTRIBUTE_MAPPINGS_free := FC_OSSL_ATTRIBUTE_MAPPINGS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_MAPPINGS_free_removed)}
    if OSSL_ATTRIBUTE_MAPPINGS_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ATTRIBUTE_MAPPINGS_free)}
      OSSL_ATTRIBUTE_MAPPINGS_free := _OSSL_ATTRIBUTE_MAPPINGS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ATTRIBUTE_MAPPINGS_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ATTRIBUTE_MAPPINGS_free');
    {$ifend}
  end;
  
  d2i_OSSL_ATTRIBUTE_MAPPINGS := LoadLibFunction(ADllHandle, d2i_OSSL_ATTRIBUTE_MAPPINGS_procname);
  FuncLoadError := not assigned(d2i_OSSL_ATTRIBUTE_MAPPINGS);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_ATTRIBUTE_MAPPINGS_allownil)}
    d2i_OSSL_ATTRIBUTE_MAPPINGS := ERR_d2i_OSSL_ATTRIBUTE_MAPPINGS;
    {$ifend}
    {$if declared(d2i_OSSL_ATTRIBUTE_MAPPINGS_introduced)}
    if LibVersion < d2i_OSSL_ATTRIBUTE_MAPPINGS_introduced then
    begin
      {$if declared(FC_d2i_OSSL_ATTRIBUTE_MAPPINGS)}
      d2i_OSSL_ATTRIBUTE_MAPPINGS := FC_d2i_OSSL_ATTRIBUTE_MAPPINGS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_ATTRIBUTE_MAPPINGS_removed)}
    if d2i_OSSL_ATTRIBUTE_MAPPINGS_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_ATTRIBUTE_MAPPINGS)}
      d2i_OSSL_ATTRIBUTE_MAPPINGS := _d2i_OSSL_ATTRIBUTE_MAPPINGS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_ATTRIBUTE_MAPPINGS_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_ATTRIBUTE_MAPPINGS');
    {$ifend}
  end;
  
  i2d_OSSL_ATTRIBUTE_MAPPINGS := LoadLibFunction(ADllHandle, i2d_OSSL_ATTRIBUTE_MAPPINGS_procname);
  FuncLoadError := not assigned(i2d_OSSL_ATTRIBUTE_MAPPINGS);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_ATTRIBUTE_MAPPINGS_allownil)}
    i2d_OSSL_ATTRIBUTE_MAPPINGS := ERR_i2d_OSSL_ATTRIBUTE_MAPPINGS;
    {$ifend}
    {$if declared(i2d_OSSL_ATTRIBUTE_MAPPINGS_introduced)}
    if LibVersion < i2d_OSSL_ATTRIBUTE_MAPPINGS_introduced then
    begin
      {$if declared(FC_i2d_OSSL_ATTRIBUTE_MAPPINGS)}
      i2d_OSSL_ATTRIBUTE_MAPPINGS := FC_i2d_OSSL_ATTRIBUTE_MAPPINGS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_ATTRIBUTE_MAPPINGS_removed)}
    if i2d_OSSL_ATTRIBUTE_MAPPINGS_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_ATTRIBUTE_MAPPINGS)}
      i2d_OSSL_ATTRIBUTE_MAPPINGS := _i2d_OSSL_ATTRIBUTE_MAPPINGS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_ATTRIBUTE_MAPPINGS_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_ATTRIBUTE_MAPPINGS');
    {$ifend}
  end;
  
  OSSL_ATTRIBUTE_MAPPINGS_it := LoadLibFunction(ADllHandle, OSSL_ATTRIBUTE_MAPPINGS_it_procname);
  FuncLoadError := not assigned(OSSL_ATTRIBUTE_MAPPINGS_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ATTRIBUTE_MAPPINGS_it_allownil)}
    OSSL_ATTRIBUTE_MAPPINGS_it := ERR_OSSL_ATTRIBUTE_MAPPINGS_it;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_MAPPINGS_it_introduced)}
    if LibVersion < OSSL_ATTRIBUTE_MAPPINGS_it_introduced then
    begin
      {$if declared(FC_OSSL_ATTRIBUTE_MAPPINGS_it)}
      OSSL_ATTRIBUTE_MAPPINGS_it := FC_OSSL_ATTRIBUTE_MAPPINGS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ATTRIBUTE_MAPPINGS_it_removed)}
    if OSSL_ATTRIBUTE_MAPPINGS_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ATTRIBUTE_MAPPINGS_it)}
      OSSL_ATTRIBUTE_MAPPINGS_it := _OSSL_ATTRIBUTE_MAPPINGS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ATTRIBUTE_MAPPINGS_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ATTRIBUTE_MAPPINGS_it');
    {$ifend}
  end;
  
  OSSL_ALLOWED_ATTRIBUTES_CHOICE_new := LoadLibFunction(ADllHandle, OSSL_ALLOWED_ATTRIBUTES_CHOICE_new_procname);
  FuncLoadError := not assigned(OSSL_ALLOWED_ATTRIBUTES_CHOICE_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ALLOWED_ATTRIBUTES_CHOICE_new_allownil)}
    OSSL_ALLOWED_ATTRIBUTES_CHOICE_new := ERR_OSSL_ALLOWED_ATTRIBUTES_CHOICE_new;
    {$ifend}
    {$if declared(OSSL_ALLOWED_ATTRIBUTES_CHOICE_new_introduced)}
    if LibVersion < OSSL_ALLOWED_ATTRIBUTES_CHOICE_new_introduced then
    begin
      {$if declared(FC_OSSL_ALLOWED_ATTRIBUTES_CHOICE_new)}
      OSSL_ALLOWED_ATTRIBUTES_CHOICE_new := FC_OSSL_ALLOWED_ATTRIBUTES_CHOICE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ALLOWED_ATTRIBUTES_CHOICE_new_removed)}
    if OSSL_ALLOWED_ATTRIBUTES_CHOICE_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ALLOWED_ATTRIBUTES_CHOICE_new)}
      OSSL_ALLOWED_ATTRIBUTES_CHOICE_new := _OSSL_ALLOWED_ATTRIBUTES_CHOICE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ALLOWED_ATTRIBUTES_CHOICE_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ALLOWED_ATTRIBUTES_CHOICE_new');
    {$ifend}
  end;
  
  OSSL_ALLOWED_ATTRIBUTES_CHOICE_free := LoadLibFunction(ADllHandle, OSSL_ALLOWED_ATTRIBUTES_CHOICE_free_procname);
  FuncLoadError := not assigned(OSSL_ALLOWED_ATTRIBUTES_CHOICE_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ALLOWED_ATTRIBUTES_CHOICE_free_allownil)}
    OSSL_ALLOWED_ATTRIBUTES_CHOICE_free := ERR_OSSL_ALLOWED_ATTRIBUTES_CHOICE_free;
    {$ifend}
    {$if declared(OSSL_ALLOWED_ATTRIBUTES_CHOICE_free_introduced)}
    if LibVersion < OSSL_ALLOWED_ATTRIBUTES_CHOICE_free_introduced then
    begin
      {$if declared(FC_OSSL_ALLOWED_ATTRIBUTES_CHOICE_free)}
      OSSL_ALLOWED_ATTRIBUTES_CHOICE_free := FC_OSSL_ALLOWED_ATTRIBUTES_CHOICE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ALLOWED_ATTRIBUTES_CHOICE_free_removed)}
    if OSSL_ALLOWED_ATTRIBUTES_CHOICE_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ALLOWED_ATTRIBUTES_CHOICE_free)}
      OSSL_ALLOWED_ATTRIBUTES_CHOICE_free := _OSSL_ALLOWED_ATTRIBUTES_CHOICE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ALLOWED_ATTRIBUTES_CHOICE_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ALLOWED_ATTRIBUTES_CHOICE_free');
    {$ifend}
  end;
  
  d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE := LoadLibFunction(ADllHandle, d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE_procname);
  FuncLoadError := not assigned(d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE_allownil)}
    d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE := ERR_d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE;
    {$ifend}
    {$if declared(d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE_introduced)}
    if LibVersion < d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE_introduced then
    begin
      {$if declared(FC_d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE)}
      d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE := FC_d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE_removed)}
    if d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE)}
      d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE := _d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE');
    {$ifend}
  end;
  
  i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE := LoadLibFunction(ADllHandle, i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE_procname);
  FuncLoadError := not assigned(i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE_allownil)}
    i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE := ERR_i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE;
    {$ifend}
    {$if declared(i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE_introduced)}
    if LibVersion < i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE_introduced then
    begin
      {$if declared(FC_i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE)}
      i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE := FC_i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE_removed)}
    if i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE)}
      i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE := _i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE');
    {$ifend}
  end;
  
  OSSL_ALLOWED_ATTRIBUTES_CHOICE_it := LoadLibFunction(ADllHandle, OSSL_ALLOWED_ATTRIBUTES_CHOICE_it_procname);
  FuncLoadError := not assigned(OSSL_ALLOWED_ATTRIBUTES_CHOICE_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ALLOWED_ATTRIBUTES_CHOICE_it_allownil)}
    OSSL_ALLOWED_ATTRIBUTES_CHOICE_it := ERR_OSSL_ALLOWED_ATTRIBUTES_CHOICE_it;
    {$ifend}
    {$if declared(OSSL_ALLOWED_ATTRIBUTES_CHOICE_it_introduced)}
    if LibVersion < OSSL_ALLOWED_ATTRIBUTES_CHOICE_it_introduced then
    begin
      {$if declared(FC_OSSL_ALLOWED_ATTRIBUTES_CHOICE_it)}
      OSSL_ALLOWED_ATTRIBUTES_CHOICE_it := FC_OSSL_ALLOWED_ATTRIBUTES_CHOICE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ALLOWED_ATTRIBUTES_CHOICE_it_removed)}
    if OSSL_ALLOWED_ATTRIBUTES_CHOICE_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ALLOWED_ATTRIBUTES_CHOICE_it)}
      OSSL_ALLOWED_ATTRIBUTES_CHOICE_it := _OSSL_ALLOWED_ATTRIBUTES_CHOICE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ALLOWED_ATTRIBUTES_CHOICE_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ALLOWED_ATTRIBUTES_CHOICE_it');
    {$ifend}
  end;
  
  OSSL_ALLOWED_ATTRIBUTES_ITEM_new := LoadLibFunction(ADllHandle, OSSL_ALLOWED_ATTRIBUTES_ITEM_new_procname);
  FuncLoadError := not assigned(OSSL_ALLOWED_ATTRIBUTES_ITEM_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ALLOWED_ATTRIBUTES_ITEM_new_allownil)}
    OSSL_ALLOWED_ATTRIBUTES_ITEM_new := ERR_OSSL_ALLOWED_ATTRIBUTES_ITEM_new;
    {$ifend}
    {$if declared(OSSL_ALLOWED_ATTRIBUTES_ITEM_new_introduced)}
    if LibVersion < OSSL_ALLOWED_ATTRIBUTES_ITEM_new_introduced then
    begin
      {$if declared(FC_OSSL_ALLOWED_ATTRIBUTES_ITEM_new)}
      OSSL_ALLOWED_ATTRIBUTES_ITEM_new := FC_OSSL_ALLOWED_ATTRIBUTES_ITEM_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ALLOWED_ATTRIBUTES_ITEM_new_removed)}
    if OSSL_ALLOWED_ATTRIBUTES_ITEM_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ALLOWED_ATTRIBUTES_ITEM_new)}
      OSSL_ALLOWED_ATTRIBUTES_ITEM_new := _OSSL_ALLOWED_ATTRIBUTES_ITEM_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ALLOWED_ATTRIBUTES_ITEM_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ALLOWED_ATTRIBUTES_ITEM_new');
    {$ifend}
  end;
  
  OSSL_ALLOWED_ATTRIBUTES_ITEM_free := LoadLibFunction(ADllHandle, OSSL_ALLOWED_ATTRIBUTES_ITEM_free_procname);
  FuncLoadError := not assigned(OSSL_ALLOWED_ATTRIBUTES_ITEM_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ALLOWED_ATTRIBUTES_ITEM_free_allownil)}
    OSSL_ALLOWED_ATTRIBUTES_ITEM_free := ERR_OSSL_ALLOWED_ATTRIBUTES_ITEM_free;
    {$ifend}
    {$if declared(OSSL_ALLOWED_ATTRIBUTES_ITEM_free_introduced)}
    if LibVersion < OSSL_ALLOWED_ATTRIBUTES_ITEM_free_introduced then
    begin
      {$if declared(FC_OSSL_ALLOWED_ATTRIBUTES_ITEM_free)}
      OSSL_ALLOWED_ATTRIBUTES_ITEM_free := FC_OSSL_ALLOWED_ATTRIBUTES_ITEM_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ALLOWED_ATTRIBUTES_ITEM_free_removed)}
    if OSSL_ALLOWED_ATTRIBUTES_ITEM_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ALLOWED_ATTRIBUTES_ITEM_free)}
      OSSL_ALLOWED_ATTRIBUTES_ITEM_free := _OSSL_ALLOWED_ATTRIBUTES_ITEM_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ALLOWED_ATTRIBUTES_ITEM_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ALLOWED_ATTRIBUTES_ITEM_free');
    {$ifend}
  end;
  
  d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM := LoadLibFunction(ADllHandle, d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM_procname);
  FuncLoadError := not assigned(d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM_allownil)}
    d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM := ERR_d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM;
    {$ifend}
    {$if declared(d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM_introduced)}
    if LibVersion < d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM_introduced then
    begin
      {$if declared(FC_d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM)}
      d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM := FC_d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM_removed)}
    if d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM)}
      d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM := _d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM');
    {$ifend}
  end;
  
  i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM := LoadLibFunction(ADllHandle, i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM_procname);
  FuncLoadError := not assigned(i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM_allownil)}
    i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM := ERR_i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM;
    {$ifend}
    {$if declared(i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM_introduced)}
    if LibVersion < i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM_introduced then
    begin
      {$if declared(FC_i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM)}
      i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM := FC_i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM_removed)}
    if i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM)}
      i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM := _i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM');
    {$ifend}
  end;
  
  OSSL_ALLOWED_ATTRIBUTES_ITEM_it := LoadLibFunction(ADllHandle, OSSL_ALLOWED_ATTRIBUTES_ITEM_it_procname);
  FuncLoadError := not assigned(OSSL_ALLOWED_ATTRIBUTES_ITEM_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ALLOWED_ATTRIBUTES_ITEM_it_allownil)}
    OSSL_ALLOWED_ATTRIBUTES_ITEM_it := ERR_OSSL_ALLOWED_ATTRIBUTES_ITEM_it;
    {$ifend}
    {$if declared(OSSL_ALLOWED_ATTRIBUTES_ITEM_it_introduced)}
    if LibVersion < OSSL_ALLOWED_ATTRIBUTES_ITEM_it_introduced then
    begin
      {$if declared(FC_OSSL_ALLOWED_ATTRIBUTES_ITEM_it)}
      OSSL_ALLOWED_ATTRIBUTES_ITEM_it := FC_OSSL_ALLOWED_ATTRIBUTES_ITEM_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ALLOWED_ATTRIBUTES_ITEM_it_removed)}
    if OSSL_ALLOWED_ATTRIBUTES_ITEM_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ALLOWED_ATTRIBUTES_ITEM_it)}
      OSSL_ALLOWED_ATTRIBUTES_ITEM_it := _OSSL_ALLOWED_ATTRIBUTES_ITEM_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ALLOWED_ATTRIBUTES_ITEM_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ALLOWED_ATTRIBUTES_ITEM_it');
    {$ifend}
  end;
  
  OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new := LoadLibFunction(ADllHandle, OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new_procname);
  FuncLoadError := not assigned(OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new_allownil)}
    OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new := ERR_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new;
    {$ifend}
    {$if declared(OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new_introduced)}
    if LibVersion < OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new_introduced then
    begin
      {$if declared(FC_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new)}
      OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new := FC_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new_removed)}
    if OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new)}
      OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new := _OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new');
    {$ifend}
  end;
  
  OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free := LoadLibFunction(ADllHandle, OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free_procname);
  FuncLoadError := not assigned(OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free_allownil)}
    OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free := ERR_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free;
    {$ifend}
    {$if declared(OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free_introduced)}
    if LibVersion < OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free_introduced then
    begin
      {$if declared(FC_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free)}
      OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free := FC_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free_removed)}
    if OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free)}
      OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free := _OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free');
    {$ifend}
  end;
  
  d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX := LoadLibFunction(ADllHandle, d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_procname);
  FuncLoadError := not assigned(d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_allownil)}
    d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX := ERR_d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX;
    {$ifend}
    {$if declared(d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_introduced)}
    if LibVersion < d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_introduced then
    begin
      {$if declared(FC_d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX)}
      d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX := FC_d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_removed)}
    if d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX)}
      d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX := _d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX');
    {$ifend}
  end;
  
  i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX := LoadLibFunction(ADllHandle, i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_procname);
  FuncLoadError := not assigned(i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_allownil)}
    i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX := ERR_i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX;
    {$ifend}
    {$if declared(i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_introduced)}
    if LibVersion < i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_introduced then
    begin
      {$if declared(FC_i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX)}
      i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX := FC_i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_removed)}
    if i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX)}
      i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX := _i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX');
    {$ifend}
  end;
  
  OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it := LoadLibFunction(ADllHandle, OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it_procname);
  FuncLoadError := not assigned(OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it_allownil)}
    OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it := ERR_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it;
    {$ifend}
    {$if declared(OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it_introduced)}
    if LibVersion < OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it_introduced then
    begin
      {$if declared(FC_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it)}
      OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it := FC_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it_removed)}
    if OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it)}
      OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it := _OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it');
    {$ifend}
  end;
  
  OSSL_AA_DIST_POINT_new := LoadLibFunction(ADllHandle, OSSL_AA_DIST_POINT_new_procname);
  FuncLoadError := not assigned(OSSL_AA_DIST_POINT_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_AA_DIST_POINT_new_allownil)}
    OSSL_AA_DIST_POINT_new := ERR_OSSL_AA_DIST_POINT_new;
    {$ifend}
    {$if declared(OSSL_AA_DIST_POINT_new_introduced)}
    if LibVersion < OSSL_AA_DIST_POINT_new_introduced then
    begin
      {$if declared(FC_OSSL_AA_DIST_POINT_new)}
      OSSL_AA_DIST_POINT_new := FC_OSSL_AA_DIST_POINT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_AA_DIST_POINT_new_removed)}
    if OSSL_AA_DIST_POINT_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_AA_DIST_POINT_new)}
      OSSL_AA_DIST_POINT_new := _OSSL_AA_DIST_POINT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_AA_DIST_POINT_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_AA_DIST_POINT_new');
    {$ifend}
  end;
  
  OSSL_AA_DIST_POINT_free := LoadLibFunction(ADllHandle, OSSL_AA_DIST_POINT_free_procname);
  FuncLoadError := not assigned(OSSL_AA_DIST_POINT_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_AA_DIST_POINT_free_allownil)}
    OSSL_AA_DIST_POINT_free := ERR_OSSL_AA_DIST_POINT_free;
    {$ifend}
    {$if declared(OSSL_AA_DIST_POINT_free_introduced)}
    if LibVersion < OSSL_AA_DIST_POINT_free_introduced then
    begin
      {$if declared(FC_OSSL_AA_DIST_POINT_free)}
      OSSL_AA_DIST_POINT_free := FC_OSSL_AA_DIST_POINT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_AA_DIST_POINT_free_removed)}
    if OSSL_AA_DIST_POINT_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_AA_DIST_POINT_free)}
      OSSL_AA_DIST_POINT_free := _OSSL_AA_DIST_POINT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_AA_DIST_POINT_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_AA_DIST_POINT_free');
    {$ifend}
  end;
  
  d2i_OSSL_AA_DIST_POINT := LoadLibFunction(ADllHandle, d2i_OSSL_AA_DIST_POINT_procname);
  FuncLoadError := not assigned(d2i_OSSL_AA_DIST_POINT);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_AA_DIST_POINT_allownil)}
    d2i_OSSL_AA_DIST_POINT := ERR_d2i_OSSL_AA_DIST_POINT;
    {$ifend}
    {$if declared(d2i_OSSL_AA_DIST_POINT_introduced)}
    if LibVersion < d2i_OSSL_AA_DIST_POINT_introduced then
    begin
      {$if declared(FC_d2i_OSSL_AA_DIST_POINT)}
      d2i_OSSL_AA_DIST_POINT := FC_d2i_OSSL_AA_DIST_POINT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_AA_DIST_POINT_removed)}
    if d2i_OSSL_AA_DIST_POINT_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_AA_DIST_POINT)}
      d2i_OSSL_AA_DIST_POINT := _d2i_OSSL_AA_DIST_POINT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_AA_DIST_POINT_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_AA_DIST_POINT');
    {$ifend}
  end;
  
  i2d_OSSL_AA_DIST_POINT := LoadLibFunction(ADllHandle, i2d_OSSL_AA_DIST_POINT_procname);
  FuncLoadError := not assigned(i2d_OSSL_AA_DIST_POINT);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_AA_DIST_POINT_allownil)}
    i2d_OSSL_AA_DIST_POINT := ERR_i2d_OSSL_AA_DIST_POINT;
    {$ifend}
    {$if declared(i2d_OSSL_AA_DIST_POINT_introduced)}
    if LibVersion < i2d_OSSL_AA_DIST_POINT_introduced then
    begin
      {$if declared(FC_i2d_OSSL_AA_DIST_POINT)}
      i2d_OSSL_AA_DIST_POINT := FC_i2d_OSSL_AA_DIST_POINT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_AA_DIST_POINT_removed)}
    if i2d_OSSL_AA_DIST_POINT_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_AA_DIST_POINT)}
      i2d_OSSL_AA_DIST_POINT := _i2d_OSSL_AA_DIST_POINT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_AA_DIST_POINT_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_AA_DIST_POINT');
    {$ifend}
  end;
  
  OSSL_AA_DIST_POINT_it := LoadLibFunction(ADllHandle, OSSL_AA_DIST_POINT_it_procname);
  FuncLoadError := not assigned(OSSL_AA_DIST_POINT_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_AA_DIST_POINT_it_allownil)}
    OSSL_AA_DIST_POINT_it := ERR_OSSL_AA_DIST_POINT_it;
    {$ifend}
    {$if declared(OSSL_AA_DIST_POINT_it_introduced)}
    if LibVersion < OSSL_AA_DIST_POINT_it_introduced then
    begin
      {$if declared(FC_OSSL_AA_DIST_POINT_it)}
      OSSL_AA_DIST_POINT_it := FC_OSSL_AA_DIST_POINT_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_AA_DIST_POINT_it_removed)}
    if OSSL_AA_DIST_POINT_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_AA_DIST_POINT_it)}
      OSSL_AA_DIST_POINT_it := _OSSL_AA_DIST_POINT_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_AA_DIST_POINT_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_AA_DIST_POINT_it');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  GENERAL_NAME_set1_X509_NAME := nil;
  DIST_POINT_NAME_dup := nil;
  PROXY_POLICY_new := nil;
  PROXY_POLICY_free := nil;
  d2i_PROXY_POLICY := nil;
  i2d_PROXY_POLICY := nil;
  PROXY_POLICY_it := nil;
  PROXY_CERT_INFO_EXTENSION_new := nil;
  PROXY_CERT_INFO_EXTENSION_free := nil;
  d2i_PROXY_CERT_INFO_EXTENSION := nil;
  i2d_PROXY_CERT_INFO_EXTENSION := nil;
  PROXY_CERT_INFO_EXTENSION_it := nil;
  BASIC_CONSTRAINTS_new := nil;
  BASIC_CONSTRAINTS_free := nil;
  d2i_BASIC_CONSTRAINTS := nil;
  i2d_BASIC_CONSTRAINTS := nil;
  BASIC_CONSTRAINTS_it := nil;
  OSSL_BASIC_ATTR_CONSTRAINTS_new := nil;
  OSSL_BASIC_ATTR_CONSTRAINTS_free := nil;
  d2i_OSSL_BASIC_ATTR_CONSTRAINTS := nil;
  i2d_OSSL_BASIC_ATTR_CONSTRAINTS := nil;
  OSSL_BASIC_ATTR_CONSTRAINTS_it := nil;
  SXNET_new := nil;
  SXNET_free := nil;
  d2i_SXNET := nil;
  i2d_SXNET := nil;
  SXNET_it := nil;
  SXNETID_new := nil;
  SXNETID_free := nil;
  d2i_SXNETID := nil;
  i2d_SXNETID := nil;
  SXNETID_it := nil;
  ISSUER_SIGN_TOOL_new := nil;
  ISSUER_SIGN_TOOL_free := nil;
  d2i_ISSUER_SIGN_TOOL := nil;
  i2d_ISSUER_SIGN_TOOL := nil;
  ISSUER_SIGN_TOOL_it := nil;
  SXNET_add_id_asc := nil;
  SXNET_add_id_ulong := nil;
  SXNET_add_id_INTEGER := nil;
  SXNET_get_id_asc := nil;
  SXNET_get_id_ulong := nil;
  SXNET_get_id_INTEGER := nil;
  AUTHORITY_KEYID_new := nil;
  AUTHORITY_KEYID_free := nil;
  d2i_AUTHORITY_KEYID := nil;
  i2d_AUTHORITY_KEYID := nil;
  AUTHORITY_KEYID_it := nil;
  PKEY_USAGE_PERIOD_new := nil;
  PKEY_USAGE_PERIOD_free := nil;
  d2i_PKEY_USAGE_PERIOD := nil;
  i2d_PKEY_USAGE_PERIOD := nil;
  PKEY_USAGE_PERIOD_it := nil;
  GENERAL_NAME_new := nil;
  GENERAL_NAME_free := nil;
  d2i_GENERAL_NAME := nil;
  i2d_GENERAL_NAME := nil;
  GENERAL_NAME_it := nil;
  GENERAL_NAME_dup := nil;
  GENERAL_NAME_cmp := nil;
  v2i_ASN1_BIT_STRING := nil;
  i2v_ASN1_BIT_STRING := nil;
  i2s_ASN1_IA5STRING := nil;
  s2i_ASN1_IA5STRING := nil;
  i2s_ASN1_UTF8STRING := nil;
  s2i_ASN1_UTF8STRING := nil;
  i2v_GENERAL_NAME := nil;
  GENERAL_NAME_print := nil;
  GENERAL_NAMES_new := nil;
  GENERAL_NAMES_free := nil;
  d2i_GENERAL_NAMES := nil;
  i2d_GENERAL_NAMES := nil;
  GENERAL_NAMES_it := nil;
  i2v_GENERAL_NAMES := nil;
  v2i_GENERAL_NAMES := nil;
  OTHERNAME_new := nil;
  OTHERNAME_free := nil;
  d2i_OTHERNAME := nil;
  i2d_OTHERNAME := nil;
  OTHERNAME_it := nil;
  EDIPARTYNAME_new := nil;
  EDIPARTYNAME_free := nil;
  d2i_EDIPARTYNAME := nil;
  i2d_EDIPARTYNAME := nil;
  EDIPARTYNAME_it := nil;
  OTHERNAME_cmp := nil;
  GENERAL_NAME_set0_value := nil;
  GENERAL_NAME_get0_value := nil;
  GENERAL_NAME_set0_othername := nil;
  GENERAL_NAME_get0_otherName := nil;
  i2s_ASN1_OCTET_STRING := nil;
  s2i_ASN1_OCTET_STRING := nil;
  EXTENDED_KEY_USAGE_new := nil;
  EXTENDED_KEY_USAGE_free := nil;
  d2i_EXTENDED_KEY_USAGE := nil;
  i2d_EXTENDED_KEY_USAGE := nil;
  EXTENDED_KEY_USAGE_it := nil;
  i2a_ACCESS_DESCRIPTION := nil;
  TLS_FEATURE_new := nil;
  TLS_FEATURE_free := nil;
  CERTIFICATEPOLICIES_new := nil;
  CERTIFICATEPOLICIES_free := nil;
  d2i_CERTIFICATEPOLICIES := nil;
  i2d_CERTIFICATEPOLICIES := nil;
  CERTIFICATEPOLICIES_it := nil;
  POLICYINFO_new := nil;
  POLICYINFO_free := nil;
  d2i_POLICYINFO := nil;
  i2d_POLICYINFO := nil;
  POLICYINFO_it := nil;
  POLICYQUALINFO_new := nil;
  POLICYQUALINFO_free := nil;
  d2i_POLICYQUALINFO := nil;
  i2d_POLICYQUALINFO := nil;
  POLICYQUALINFO_it := nil;
  USERNOTICE_new := nil;
  USERNOTICE_free := nil;
  d2i_USERNOTICE := nil;
  i2d_USERNOTICE := nil;
  USERNOTICE_it := nil;
  NOTICEREF_new := nil;
  NOTICEREF_free := nil;
  d2i_NOTICEREF := nil;
  i2d_NOTICEREF := nil;
  NOTICEREF_it := nil;
  CRL_DIST_POINTS_new := nil;
  CRL_DIST_POINTS_free := nil;
  d2i_CRL_DIST_POINTS := nil;
  i2d_CRL_DIST_POINTS := nil;
  CRL_DIST_POINTS_it := nil;
  DIST_POINT_new := nil;
  DIST_POINT_free := nil;
  d2i_DIST_POINT := nil;
  i2d_DIST_POINT := nil;
  DIST_POINT_it := nil;
  DIST_POINT_NAME_new := nil;
  DIST_POINT_NAME_free := nil;
  d2i_DIST_POINT_NAME := nil;
  i2d_DIST_POINT_NAME := nil;
  DIST_POINT_NAME_it := nil;
  ISSUING_DIST_POINT_new := nil;
  ISSUING_DIST_POINT_free := nil;
  d2i_ISSUING_DIST_POINT := nil;
  i2d_ISSUING_DIST_POINT := nil;
  ISSUING_DIST_POINT_it := nil;
  DIST_POINT_set_dpname := nil;
  NAME_CONSTRAINTS_check := nil;
  NAME_CONSTRAINTS_check_CN := nil;
  ACCESS_DESCRIPTION_new := nil;
  ACCESS_DESCRIPTION_free := nil;
  d2i_ACCESS_DESCRIPTION := nil;
  i2d_ACCESS_DESCRIPTION := nil;
  ACCESS_DESCRIPTION_it := nil;
  AUTHORITY_INFO_ACCESS_new := nil;
  AUTHORITY_INFO_ACCESS_free := nil;
  d2i_AUTHORITY_INFO_ACCESS := nil;
  i2d_AUTHORITY_INFO_ACCESS := nil;
  AUTHORITY_INFO_ACCESS_it := nil;
  POLICY_MAPPING_it := nil;
  POLICY_MAPPING_new := nil;
  POLICY_MAPPING_free := nil;
  POLICY_MAPPINGS_it := nil;
  GENERAL_SUBTREE_it := nil;
  GENERAL_SUBTREE_new := nil;
  GENERAL_SUBTREE_free := nil;
  NAME_CONSTRAINTS_it := nil;
  NAME_CONSTRAINTS_new := nil;
  NAME_CONSTRAINTS_free := nil;
  POLICY_CONSTRAINTS_new := nil;
  POLICY_CONSTRAINTS_free := nil;
  POLICY_CONSTRAINTS_it := nil;
  a2i_GENERAL_NAME := nil;
  v2i_GENERAL_NAME := nil;
  v2i_GENERAL_NAME_ex := nil;
  X509V3_conf_free := nil;
  X509V3_EXT_nconf_nid := nil;
  X509V3_EXT_nconf := nil;
  X509V3_EXT_add_nconf_sk := nil;
  X509V3_EXT_add_nconf := nil;
  X509V3_EXT_REQ_add_nconf := nil;
  X509V3_EXT_CRL_add_nconf := nil;
  X509V3_EXT_conf_nid := nil;
  X509V3_EXT_conf := nil;
  X509V3_EXT_add_conf := nil;
  X509V3_EXT_REQ_add_conf := nil;
  X509V3_EXT_CRL_add_conf := nil;
  X509V3_add_value_bool_nf := nil;
  X509V3_get_value_bool := nil;
  X509V3_get_value_int := nil;
  X509V3_set_nconf := nil;
  X509V3_set_conf_lhash := nil;
  X509V3_get_string := nil;
  X509V3_get_section := nil;
  X509V3_string_free := nil;
  X509V3_section_free := nil;
  X509V3_set_ctx := nil;
  X509V3_set_issuer_pkey := nil;
  X509V3_add_value := nil;
  X509V3_add_value_uchar := nil;
  X509V3_add_value_bool := nil;
  X509V3_add_value_int := nil;
  i2s_ASN1_INTEGER := nil;
  s2i_ASN1_INTEGER := nil;
  i2s_ASN1_ENUMERATED := nil;
  i2s_ASN1_ENUMERATED_TABLE := nil;
  X509V3_EXT_add := nil;
  X509V3_EXT_add_list := nil;
  X509V3_EXT_add_alias := nil;
  X509V3_EXT_cleanup := nil;
  X509V3_EXT_get := nil;
  X509V3_EXT_get_nid := nil;
  X509V3_add_standard_extensions := nil;
  X509V3_parse_list := nil;
  X509V3_EXT_d2i := nil;
  X509V3_get_d2i := nil;
  X509V3_EXT_i2d := nil;
  X509V3_add1_i2d := nil;
  X509V3_EXT_val_prn := nil;
  X509V3_EXT_print := nil;
  X509V3_EXT_print_fp := nil;
  X509V3_extensions_print := nil;
  X509_check_ca := nil;
  X509_check_purpose := nil;
  X509_supported_extension := nil;
  X509_check_issued := nil;
  X509_check_akid := nil;
  X509_set_proxy_flag := nil;
  X509_set_proxy_pathlen := nil;
  X509_get_proxy_pathlen := nil;
  X509_get_extension_flags := nil;
  X509_get_key_usage := nil;
  X509_get_extended_key_usage := nil;
  X509_get0_subject_key_id := nil;
  X509_get0_authority_key_id := nil;
  X509_get0_authority_issuer := nil;
  X509_get0_authority_serial := nil;
  X509_PURPOSE_get_count := nil;
  X509_PURPOSE_get_unused_id := nil;
  X509_PURPOSE_get_by_sname := nil;
  X509_PURPOSE_get_by_id := nil;
  X509_PURPOSE_add := nil;
  X509_PURPOSE_cleanup := nil;
  X509_PURPOSE_get0 := nil;
  X509_PURPOSE_get_id := nil;
  X509_PURPOSE_get0_name := nil;
  X509_PURPOSE_get0_sname := nil;
  X509_PURPOSE_get_trust := nil;
  X509_PURPOSE_set := nil;
  X509_get1_email := nil;
  X509_REQ_get1_email := nil;
  X509_email_free := nil;
  X509_get1_ocsp := nil;
  X509_check_host := nil;
  X509_check_email := nil;
  X509_check_ip := nil;
  X509_check_ip_asc := nil;
  a2i_IPADDRESS := nil;
  a2i_IPADDRESS_NC := nil;
  X509V3_NAME_from_section := nil;
  X509_POLICY_NODE_print := nil;
  ASRange_new := nil;
  ASRange_free := nil;
  d2i_ASRange := nil;
  i2d_ASRange := nil;
  ASRange_it := nil;
  ASIdOrRange_new := nil;
  ASIdOrRange_free := nil;
  d2i_ASIdOrRange := nil;
  i2d_ASIdOrRange := nil;
  ASIdOrRange_it := nil;
  ASIdentifierChoice_new := nil;
  ASIdentifierChoice_free := nil;
  d2i_ASIdentifierChoice := nil;
  i2d_ASIdentifierChoice := nil;
  ASIdentifierChoice_it := nil;
  ASIdentifiers_new := nil;
  ASIdentifiers_free := nil;
  d2i_ASIdentifiers := nil;
  i2d_ASIdentifiers := nil;
  ASIdentifiers_it := nil;
  IPAddressRange_new := nil;
  IPAddressRange_free := nil;
  d2i_IPAddressRange := nil;
  i2d_IPAddressRange := nil;
  IPAddressRange_it := nil;
  IPAddressOrRange_new := nil;
  IPAddressOrRange_free := nil;
  d2i_IPAddressOrRange := nil;
  i2d_IPAddressOrRange := nil;
  IPAddressOrRange_it := nil;
  IPAddressChoice_new := nil;
  IPAddressChoice_free := nil;
  d2i_IPAddressChoice := nil;
  i2d_IPAddressChoice := nil;
  IPAddressChoice_it := nil;
  IPAddressFamily_new := nil;
  IPAddressFamily_free := nil;
  d2i_IPAddressFamily := nil;
  i2d_IPAddressFamily := nil;
  IPAddressFamily_it := nil;
  X509v3_asid_add_inherit := nil;
  X509v3_asid_add_id_or_range := nil;
  X509v3_addr_add_inherit := nil;
  X509v3_addr_add_prefix := nil;
  X509v3_addr_add_range := nil;
  X509v3_addr_get_afi := nil;
  X509v3_addr_get_range := nil;
  X509v3_asid_is_canonical := nil;
  X509v3_addr_is_canonical := nil;
  X509v3_asid_canonize := nil;
  X509v3_addr_canonize := nil;
  X509v3_asid_inherits := nil;
  X509v3_addr_inherits := nil;
  X509v3_asid_subset := nil;
  X509v3_addr_subset := nil;
  X509v3_asid_validate_path := nil;
  X509v3_addr_validate_path := nil;
  X509v3_asid_validate_resource_set := nil;
  X509v3_addr_validate_resource_set := nil;
  NAMING_AUTHORITY_new := nil;
  NAMING_AUTHORITY_free := nil;
  d2i_NAMING_AUTHORITY := nil;
  i2d_NAMING_AUTHORITY := nil;
  NAMING_AUTHORITY_it := nil;
  PROFESSION_INFO_new := nil;
  PROFESSION_INFO_free := nil;
  d2i_PROFESSION_INFO := nil;
  i2d_PROFESSION_INFO := nil;
  PROFESSION_INFO_it := nil;
  ADMISSIONS_new := nil;
  ADMISSIONS_free := nil;
  d2i_ADMISSIONS := nil;
  i2d_ADMISSIONS := nil;
  ADMISSIONS_it := nil;
  ADMISSION_SYNTAX_new := nil;
  ADMISSION_SYNTAX_free := nil;
  d2i_ADMISSION_SYNTAX := nil;
  i2d_ADMISSION_SYNTAX := nil;
  ADMISSION_SYNTAX_it := nil;
  NAMING_AUTHORITY_get0_authorityId := nil;
  NAMING_AUTHORITY_get0_authorityURL := nil;
  NAMING_AUTHORITY_get0_authorityText := nil;
  NAMING_AUTHORITY_set0_authorityId := nil;
  NAMING_AUTHORITY_set0_authorityURL := nil;
  NAMING_AUTHORITY_set0_authorityText := nil;
  ADMISSION_SYNTAX_get0_admissionAuthority := nil;
  ADMISSION_SYNTAX_set0_admissionAuthority := nil;
  ADMISSION_SYNTAX_get0_contentsOfAdmissions := nil;
  ADMISSION_SYNTAX_set0_contentsOfAdmissions := nil;
  ADMISSIONS_get0_admissionAuthority := nil;
  ADMISSIONS_set0_admissionAuthority := nil;
  ADMISSIONS_get0_namingAuthority := nil;
  ADMISSIONS_set0_namingAuthority := nil;
  ADMISSIONS_get0_professionInfos := nil;
  ADMISSIONS_set0_professionInfos := nil;
  PROFESSION_INFO_get0_addProfessionInfo := nil;
  PROFESSION_INFO_set0_addProfessionInfo := nil;
  PROFESSION_INFO_get0_namingAuthority := nil;
  PROFESSION_INFO_set0_namingAuthority := nil;
  PROFESSION_INFO_get0_professionItems := nil;
  PROFESSION_INFO_set0_professionItems := nil;
  PROFESSION_INFO_get0_professionOIDs := nil;
  PROFESSION_INFO_set0_professionOIDs := nil;
  PROFESSION_INFO_get0_registrationNumber := nil;
  PROFESSION_INFO_set0_registrationNumber := nil;
  OSSL_GENERAL_NAMES_print := nil;
  OSSL_ATTRIBUTES_SYNTAX_new := nil;
  OSSL_ATTRIBUTES_SYNTAX_free := nil;
  d2i_OSSL_ATTRIBUTES_SYNTAX := nil;
  i2d_OSSL_ATTRIBUTES_SYNTAX := nil;
  OSSL_ATTRIBUTES_SYNTAX_it := nil;
  OSSL_USER_NOTICE_SYNTAX_new := nil;
  OSSL_USER_NOTICE_SYNTAX_free := nil;
  d2i_OSSL_USER_NOTICE_SYNTAX := nil;
  i2d_OSSL_USER_NOTICE_SYNTAX := nil;
  OSSL_USER_NOTICE_SYNTAX_it := nil;
  OSSL_ROLE_SPEC_CERT_ID_new := nil;
  OSSL_ROLE_SPEC_CERT_ID_free := nil;
  d2i_OSSL_ROLE_SPEC_CERT_ID := nil;
  i2d_OSSL_ROLE_SPEC_CERT_ID := nil;
  OSSL_ROLE_SPEC_CERT_ID_it := nil;
  OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new := nil;
  OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free := nil;
  d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX := nil;
  i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX := nil;
  OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it := nil;
  OSSL_HASH_new := nil;
  OSSL_HASH_free := nil;
  d2i_OSSL_HASH := nil;
  i2d_OSSL_HASH := nil;
  OSSL_HASH_it := nil;
  OSSL_INFO_SYNTAX_new := nil;
  OSSL_INFO_SYNTAX_free := nil;
  d2i_OSSL_INFO_SYNTAX := nil;
  i2d_OSSL_INFO_SYNTAX := nil;
  OSSL_INFO_SYNTAX_it := nil;
  OSSL_INFO_SYNTAX_POINTER_new := nil;
  OSSL_INFO_SYNTAX_POINTER_free := nil;
  d2i_OSSL_INFO_SYNTAX_POINTER := nil;
  i2d_OSSL_INFO_SYNTAX_POINTER := nil;
  OSSL_INFO_SYNTAX_POINTER_it := nil;
  OSSL_PRIVILEGE_POLICY_ID_new := nil;
  OSSL_PRIVILEGE_POLICY_ID_free := nil;
  d2i_OSSL_PRIVILEGE_POLICY_ID := nil;
  i2d_OSSL_PRIVILEGE_POLICY_ID := nil;
  OSSL_PRIVILEGE_POLICY_ID_it := nil;
  OSSL_ATTRIBUTE_DESCRIPTOR_new := nil;
  OSSL_ATTRIBUTE_DESCRIPTOR_free := nil;
  d2i_OSSL_ATTRIBUTE_DESCRIPTOR := nil;
  i2d_OSSL_ATTRIBUTE_DESCRIPTOR := nil;
  OSSL_ATTRIBUTE_DESCRIPTOR_it := nil;
  OSSL_DAY_TIME_new := nil;
  OSSL_DAY_TIME_free := nil;
  d2i_OSSL_DAY_TIME := nil;
  i2d_OSSL_DAY_TIME := nil;
  OSSL_DAY_TIME_it := nil;
  OSSL_DAY_TIME_BAND_new := nil;
  OSSL_DAY_TIME_BAND_free := nil;
  d2i_OSSL_DAY_TIME_BAND := nil;
  i2d_OSSL_DAY_TIME_BAND := nil;
  OSSL_DAY_TIME_BAND_it := nil;
  OSSL_TIME_SPEC_DAY_new := nil;
  OSSL_TIME_SPEC_DAY_free := nil;
  d2i_OSSL_TIME_SPEC_DAY := nil;
  i2d_OSSL_TIME_SPEC_DAY := nil;
  OSSL_TIME_SPEC_DAY_it := nil;
  OSSL_TIME_SPEC_WEEKS_new := nil;
  OSSL_TIME_SPEC_WEEKS_free := nil;
  d2i_OSSL_TIME_SPEC_WEEKS := nil;
  i2d_OSSL_TIME_SPEC_WEEKS := nil;
  OSSL_TIME_SPEC_WEEKS_it := nil;
  OSSL_TIME_SPEC_MONTH_new := nil;
  OSSL_TIME_SPEC_MONTH_free := nil;
  d2i_OSSL_TIME_SPEC_MONTH := nil;
  i2d_OSSL_TIME_SPEC_MONTH := nil;
  OSSL_TIME_SPEC_MONTH_it := nil;
  OSSL_NAMED_DAY_new := nil;
  OSSL_NAMED_DAY_free := nil;
  d2i_OSSL_NAMED_DAY := nil;
  i2d_OSSL_NAMED_DAY := nil;
  OSSL_NAMED_DAY_it := nil;
  OSSL_TIME_SPEC_X_DAY_OF_new := nil;
  OSSL_TIME_SPEC_X_DAY_OF_free := nil;
  d2i_OSSL_TIME_SPEC_X_DAY_OF := nil;
  i2d_OSSL_TIME_SPEC_X_DAY_OF := nil;
  OSSL_TIME_SPEC_X_DAY_OF_it := nil;
  OSSL_TIME_SPEC_ABSOLUTE_new := nil;
  OSSL_TIME_SPEC_ABSOLUTE_free := nil;
  d2i_OSSL_TIME_SPEC_ABSOLUTE := nil;
  i2d_OSSL_TIME_SPEC_ABSOLUTE := nil;
  OSSL_TIME_SPEC_ABSOLUTE_it := nil;
  OSSL_TIME_SPEC_TIME_new := nil;
  OSSL_TIME_SPEC_TIME_free := nil;
  d2i_OSSL_TIME_SPEC_TIME := nil;
  i2d_OSSL_TIME_SPEC_TIME := nil;
  OSSL_TIME_SPEC_TIME_it := nil;
  OSSL_TIME_SPEC_new := nil;
  OSSL_TIME_SPEC_free := nil;
  d2i_OSSL_TIME_SPEC := nil;
  i2d_OSSL_TIME_SPEC := nil;
  OSSL_TIME_SPEC_it := nil;
  OSSL_TIME_PERIOD_new := nil;
  OSSL_TIME_PERIOD_free := nil;
  d2i_OSSL_TIME_PERIOD := nil;
  i2d_OSSL_TIME_PERIOD := nil;
  OSSL_TIME_PERIOD_it := nil;
  OSSL_ATAV_new := nil;
  OSSL_ATAV_free := nil;
  d2i_OSSL_ATAV := nil;
  i2d_OSSL_ATAV := nil;
  OSSL_ATAV_it := nil;
  OSSL_ATTRIBUTE_TYPE_MAPPING_new := nil;
  OSSL_ATTRIBUTE_TYPE_MAPPING_free := nil;
  d2i_OSSL_ATTRIBUTE_TYPE_MAPPING := nil;
  i2d_OSSL_ATTRIBUTE_TYPE_MAPPING := nil;
  OSSL_ATTRIBUTE_TYPE_MAPPING_it := nil;
  OSSL_ATTRIBUTE_VALUE_MAPPING_new := nil;
  OSSL_ATTRIBUTE_VALUE_MAPPING_free := nil;
  d2i_OSSL_ATTRIBUTE_VALUE_MAPPING := nil;
  i2d_OSSL_ATTRIBUTE_VALUE_MAPPING := nil;
  OSSL_ATTRIBUTE_VALUE_MAPPING_it := nil;
  OSSL_ATTRIBUTE_MAPPING_new := nil;
  OSSL_ATTRIBUTE_MAPPING_free := nil;
  d2i_OSSL_ATTRIBUTE_MAPPING := nil;
  i2d_OSSL_ATTRIBUTE_MAPPING := nil;
  OSSL_ATTRIBUTE_MAPPING_it := nil;
  OSSL_ATTRIBUTE_MAPPINGS_new := nil;
  OSSL_ATTRIBUTE_MAPPINGS_free := nil;
  d2i_OSSL_ATTRIBUTE_MAPPINGS := nil;
  i2d_OSSL_ATTRIBUTE_MAPPINGS := nil;
  OSSL_ATTRIBUTE_MAPPINGS_it := nil;
  OSSL_ALLOWED_ATTRIBUTES_CHOICE_new := nil;
  OSSL_ALLOWED_ATTRIBUTES_CHOICE_free := nil;
  d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE := nil;
  i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE := nil;
  OSSL_ALLOWED_ATTRIBUTES_CHOICE_it := nil;
  OSSL_ALLOWED_ATTRIBUTES_ITEM_new := nil;
  OSSL_ALLOWED_ATTRIBUTES_ITEM_free := nil;
  d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM := nil;
  i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM := nil;
  OSSL_ALLOWED_ATTRIBUTES_ITEM_it := nil;
  OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new := nil;
  OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free := nil;
  d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX := nil;
  i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX := nil;
  OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it := nil;
  OSSL_AA_DIST_POINT_new := nil;
  OSSL_AA_DIST_POINT_free := nil;
  d2i_OSSL_AA_DIST_POINT := nil;
  i2d_OSSL_AA_DIST_POINT := nil;
  OSSL_AA_DIST_POINT_it := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.