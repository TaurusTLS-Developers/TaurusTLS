/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_obj_mac.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_obj_mac.h2pas
     and this file regenerated. TaurusTLSHeaders_obj_mac.h2pas is distributed with the full Indy
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

unit TaurusTLSHeaders_obj_mac;

interface

// Headers for OpenSSL 1.1.1
// obj_mac.h


const
  {$EXTERNALSYM SN_undef}
  SN_undef = 'UNDEF';
  {$EXTERNALSYM LN_undef}
  LN_undef = 'undefined';
  {$EXTERNALSYM NID_undef}
  NID_undef = 0;

  {$EXTERNALSYM SN_itu_t}
  SN_itu_t = 'ITU-T';
  {$EXTERNALSYM LN_itu_t}
  LN_itu_t = 'itu-t';
  {$EXTERNALSYM NID_itu_t}
  NID_itu_t = 645;

  {$EXTERNALSYM NID_ccitt}
  NID_ccitt = 404;

  {$EXTERNALSYM SN_iso}
  SN_iso = 'ISO';
  {$EXTERNALSYM LN_iso}
  LN_iso = 'iso';
  {$EXTERNALSYM NID_iso}
  NID_iso = 181;

  {$EXTERNALSYM SN_joint_iso_itu_t}
  SN_joint_iso_itu_t = 'JOINT-ISO-ITU-T';
  {$EXTERNALSYM LN_joint_iso_itu_t}
  LN_joint_iso_itu_t = 'joint-iso-itu-t';
  {$EXTERNALSYM NID_joint_iso_itu_t}
  NID_joint_iso_itu_t = 646;

  {$EXTERNALSYM NID_joint_iso_ccitt}
  NID_joint_iso_ccitt = 393;

  {$EXTERNALSYM SN_member_body}
  SN_member_body = 'member-body';
  {$EXTERNALSYM LN_member_body}
  LN_member_body = 'ISO Member Body';
  {$EXTERNALSYM NID_member_body}
  NID_member_body = 182;

  {$EXTERNALSYM SN_identified_organization}
  SN_identified_organization = 'identified-organization';
  {$EXTERNALSYM NID_identified_organization}
  NID_identified_organization = 676;

  {$EXTERNALSYM SN_hmac_md5}
  SN_hmac_md5 = 'HMAC-MD5';
  {$EXTERNALSYM LN_hmac_md5}
  LN_hmac_md5 = 'hmac-md5';
  {$EXTERNALSYM NID_hmac_md5}
  NID_hmac_md5 = 780;

  {$EXTERNALSYM SN_hmac_sha1}
  SN_hmac_sha1 = 'HMAC-SHA1';
  {$EXTERNALSYM LN_hmac_sha1}
  LN_hmac_sha1 = 'hmac-sha1';
  {$EXTERNALSYM NID_hmac_sha1}
  NID_hmac_sha1 = 781;

  {$EXTERNALSYM SN_x509ExtAdmission}
  SN_x509ExtAdmission = 'x509ExtAdmission';
  {$EXTERNALSYM LN_x509ExtAdmission}
  LN_x509ExtAdmission = 'Professional Information or basis for Admission';
  {$EXTERNALSYM NID_x509ExtAdmission}
  NID_x509ExtAdmission = 1093;

  {$EXTERNALSYM SN_certicom_arc}
  SN_certicom_arc = 'certicom-arc';
  {$EXTERNALSYM NID_certicom_arc}
  NID_certicom_arc = 677;

  {$EXTERNALSYM SN_ieee}
  SN_ieee = 'ieee';
  {$EXTERNALSYM NID_ieee}
  NID_ieee = 1170;

  {$EXTERNALSYM SN_ieee_siswg}
  SN_ieee_siswg = 'ieee-siswg';
  {$EXTERNALSYM LN_ieee_siswg}
  LN_ieee_siswg = 'IEEE Security in Storage Working Group';
  {$EXTERNALSYM NID_ieee_siswg}
  NID_ieee_siswg = 1171;

  {$EXTERNALSYM SN_international_organizations}
  SN_international_organizations = 'international-organizations';
  {$EXTERNALSYM LN_international_organizations}
  LN_international_organizations = 'International Organizations';
  {$EXTERNALSYM NID_international_organizations}
  NID_international_organizations = 647;

  {$EXTERNALSYM SN_wap}
  SN_wap = 'wap';
  {$EXTERNALSYM NID_wap}
  NID_wap = 678;

  {$EXTERNALSYM SN_wap_wsg}
  SN_wap_wsg = 'wap-wsg';
  {$EXTERNALSYM NID_wap_wsg}
  NID_wap_wsg = 679;

  {$EXTERNALSYM SN_selected_attribute_types}
  SN_selected_attribute_types = 'selected-attribute-types';
  {$EXTERNALSYM LN_selected_attribute_types}
  LN_selected_attribute_types = 'Selected Attribute Types';
  {$EXTERNALSYM NID_selected_attribute_types}
  NID_selected_attribute_types = 394;

  {$EXTERNALSYM SN_clearance}
  SN_clearance = 'clearance';
  {$EXTERNALSYM NID_clearance}
  NID_clearance = 395;

  {$EXTERNALSYM SN_ISO_US}
  SN_ISO_US = 'ISO-US';
  {$EXTERNALSYM LN_ISO_US}
  LN_ISO_US = 'ISO US Member Body';
  {$EXTERNALSYM NID_ISO_US}
  NID_ISO_US = 183;

  {$EXTERNALSYM SN_X9_57}
  SN_X9_57 = 'X9-57';
  {$EXTERNALSYM LN_X9_57}
  LN_X9_57 = 'X9.57';
  {$EXTERNALSYM NID_X9_57}
  NID_X9_57 = 184;

  {$EXTERNALSYM SN_X9cm}
  SN_X9cm = 'X9cm';
  {$EXTERNALSYM LN_X9cm}
  LN_X9cm = 'X9.57 CM ?';
  {$EXTERNALSYM NID_X9cm}
  NID_X9cm = 185;

  {$EXTERNALSYM SN_ISO_CN}
  SN_ISO_CN = 'ISO-CN';
  {$EXTERNALSYM LN_ISO_CN}
  LN_ISO_CN = 'ISO CN Member Body';
  {$EXTERNALSYM NID_ISO_CN}
  NID_ISO_CN = 1140;

  {$EXTERNALSYM SN_oscca}
  SN_oscca = 'oscca';
  {$EXTERNALSYM NID_oscca}
  NID_oscca = 1141;

  {$EXTERNALSYM SN_sm_scheme}
  SN_sm_scheme = 'sm-scheme';
  {$EXTERNALSYM NID_sm_scheme}
  NID_sm_scheme = 1142;

  {$EXTERNALSYM SN_dsa}
  SN_dsa = 'DSA';
  {$EXTERNALSYM LN_dsa}
  LN_dsa = 'dsaEncryption';
  {$EXTERNALSYM NID_dsa}
  NID_dsa = 116;

  {$EXTERNALSYM SN_dsaWithSHA1}
  SN_dsaWithSHA1 = 'DSA-SHA1';
  {$EXTERNALSYM LN_dsaWithSHA1}
  LN_dsaWithSHA1 = 'dsaWithSHA1';
  {$EXTERNALSYM NID_dsaWithSHA1}
  NID_dsaWithSHA1 = 113;

  {$EXTERNALSYM SN_ansi_X9_62}
  SN_ansi_X9_62 = 'ansi-X9-62';
  {$EXTERNALSYM LN_ansi_X9_62}
  LN_ansi_X9_62 = 'ANSI X9.62';
  {$EXTERNALSYM NID_ansi_X9_62}
  NID_ansi_X9_62 = 405;

  {$EXTERNALSYM SN_X9_62_prime_field}
  SN_X9_62_prime_field = 'prime-field';
  {$EXTERNALSYM NID_X9_62_prime_field}
  NID_X9_62_prime_field = 406;

  {$EXTERNALSYM SN_X9_62_characteristic_two_field}
  SN_X9_62_characteristic_two_field = 'characteristic-two-field';
  {$EXTERNALSYM NID_X9_62_characteristic_two_field}
  NID_X9_62_characteristic_two_field = 407;

  {$EXTERNALSYM SN_X9_62_id_characteristic_two_basis}
  SN_X9_62_id_characteristic_two_basis = 'id-characteristic-two-basis';
  {$EXTERNALSYM NID_X9_62_id_characteristic_two_basis}
  NID_X9_62_id_characteristic_two_basis = 680;

  {$EXTERNALSYM SN_X9_62_onBasis}
  SN_X9_62_onBasis = 'onBasis';
  {$EXTERNALSYM NID_X9_62_onBasis}
  NID_X9_62_onBasis = 681;

  {$EXTERNALSYM SN_X9_62_tpBasis}
  SN_X9_62_tpBasis = 'tpBasis';
  {$EXTERNALSYM NID_X9_62_tpBasis}
  NID_X9_62_tpBasis = 682;

  {$EXTERNALSYM SN_X9_62_ppBasis}
  SN_X9_62_ppBasis = 'ppBasis';
  {$EXTERNALSYM NID_X9_62_ppBasis}
  NID_X9_62_ppBasis = 683;

  {$EXTERNALSYM SN_X9_62_id_ecPublicKey}
  SN_X9_62_id_ecPublicKey = 'id-ecPublicKey';
  {$EXTERNALSYM NID_X9_62_id_ecPublicKey}
  NID_X9_62_id_ecPublicKey = 408;

  {$EXTERNALSYM SN_X9_62_c2pnb163v1}
  SN_X9_62_c2pnb163v1 = 'c2pnb163v1';
  {$EXTERNALSYM NID_X9_62_c2pnb163v1}
  NID_X9_62_c2pnb163v1 = 684;

  {$EXTERNALSYM SN_X9_62_c2pnb163v2}
  SN_X9_62_c2pnb163v2 = 'c2pnb163v2';
  {$EXTERNALSYM NID_X9_62_c2pnb163v2}
  NID_X9_62_c2pnb163v2 = 685;

  {$EXTERNALSYM SN_X9_62_c2pnb163v3}
  SN_X9_62_c2pnb163v3 = 'c2pnb163v3';
  {$EXTERNALSYM NID_X9_62_c2pnb163v3}
  NID_X9_62_c2pnb163v3 = 686;

  {$EXTERNALSYM SN_X9_62_c2pnb176v1}
  SN_X9_62_c2pnb176v1 = 'c2pnb176v1';
  {$EXTERNALSYM NID_X9_62_c2pnb176v1}
  NID_X9_62_c2pnb176v1 = 687;

  {$EXTERNALSYM SN_X9_62_c2tnb191v1}
  SN_X9_62_c2tnb191v1 = 'c2tnb191v1';
  {$EXTERNALSYM NID_X9_62_c2tnb191v1}
  NID_X9_62_c2tnb191v1 = 688;

  {$EXTERNALSYM SN_X9_62_c2tnb191v2}
  SN_X9_62_c2tnb191v2 = 'c2tnb191v2';
  {$EXTERNALSYM NID_X9_62_c2tnb191v2}
  NID_X9_62_c2tnb191v2 = 689;

  {$EXTERNALSYM SN_X9_62_c2tnb191v3}
  SN_X9_62_c2tnb191v3 = 'c2tnb191v3';
  {$EXTERNALSYM NID_X9_62_c2tnb191v3}
  NID_X9_62_c2tnb191v3 = 690;

  {$EXTERNALSYM SN_X9_62_c2onb191v4}
  SN_X9_62_c2onb191v4 = 'c2onb191v4';
  {$EXTERNALSYM NID_X9_62_c2onb191v4}
  NID_X9_62_c2onb191v4 = 691;

  {$EXTERNALSYM SN_X9_62_c2onb191v5}
  SN_X9_62_c2onb191v5 = 'c2onb191v5';
  {$EXTERNALSYM NID_X9_62_c2onb191v5}
  NID_X9_62_c2onb191v5 = 692;

  {$EXTERNALSYM SN_X9_62_c2pnb208w1}
  SN_X9_62_c2pnb208w1 = 'c2pnb208w1';
  {$EXTERNALSYM NID_X9_62_c2pnb208w1}
  NID_X9_62_c2pnb208w1 = 693;

  {$EXTERNALSYM SN_X9_62_c2tnb239v1}
  SN_X9_62_c2tnb239v1 = 'c2tnb239v1';
  {$EXTERNALSYM NID_X9_62_c2tnb239v1}
  NID_X9_62_c2tnb239v1 = 694;

  {$EXTERNALSYM SN_X9_62_c2tnb239v2}
  SN_X9_62_c2tnb239v2 = 'c2tnb239v2';
  {$EXTERNALSYM NID_X9_62_c2tnb239v2}
  NID_X9_62_c2tnb239v2 = 695;

  {$EXTERNALSYM SN_X9_62_c2tnb239v3}
  SN_X9_62_c2tnb239v3 = 'c2tnb239v3';
  {$EXTERNALSYM NID_X9_62_c2tnb239v3}
  NID_X9_62_c2tnb239v3 = 696;

  {$EXTERNALSYM SN_X9_62_c2onb239v4}
  SN_X9_62_c2onb239v4 = 'c2onb239v4';
  {$EXTERNALSYM NID_X9_62_c2onb239v4}
  NID_X9_62_c2onb239v4 = 697;

  {$EXTERNALSYM SN_X9_62_c2onb239v5}
  SN_X9_62_c2onb239v5 = 'c2onb239v5';
  {$EXTERNALSYM NID_X9_62_c2onb239v5}
  NID_X9_62_c2onb239v5 = 698;

  {$EXTERNALSYM SN_X9_62_c2pnb272w1}
  SN_X9_62_c2pnb272w1 = 'c2pnb272w1';
  {$EXTERNALSYM NID_X9_62_c2pnb272w1}
  NID_X9_62_c2pnb272w1 = 699;

  {$EXTERNALSYM SN_X9_62_c2pnb304w1}
  SN_X9_62_c2pnb304w1 = 'c2pnb304w1';
  {$EXTERNALSYM NID_X9_62_c2pnb304w1}
  NID_X9_62_c2pnb304w1 = 700;

  {$EXTERNALSYM SN_X9_62_c2tnb359v1}
  SN_X9_62_c2tnb359v1 = 'c2tnb359v1';
  {$EXTERNALSYM NID_X9_62_c2tnb359v1}
  NID_X9_62_c2tnb359v1 = 701;

  {$EXTERNALSYM SN_X9_62_c2pnb368w1}
  SN_X9_62_c2pnb368w1 = 'c2pnb368w1';
  {$EXTERNALSYM NID_X9_62_c2pnb368w1}
  NID_X9_62_c2pnb368w1 = 702;

  {$EXTERNALSYM SN_X9_62_c2tnb431r1}
  SN_X9_62_c2tnb431r1 = 'c2tnb431r1';
  {$EXTERNALSYM NID_X9_62_c2tnb431r1}
  NID_X9_62_c2tnb431r1 = 703;

  {$EXTERNALSYM SN_X9_62_prime192v1}
  SN_X9_62_prime192v1 = 'prime192v1';
  {$EXTERNALSYM NID_X9_62_prime192v1}
  NID_X9_62_prime192v1 = 409;

  {$EXTERNALSYM SN_X9_62_prime192v2}
  SN_X9_62_prime192v2 = 'prime192v2';
  {$EXTERNALSYM NID_X9_62_prime192v2}
  NID_X9_62_prime192v2 = 410;

  {$EXTERNALSYM SN_X9_62_prime192v3}
  SN_X9_62_prime192v3 = 'prime192v3';
  {$EXTERNALSYM NID_X9_62_prime192v3}
  NID_X9_62_prime192v3 = 411;

  {$EXTERNALSYM SN_X9_62_prime239v1}
  SN_X9_62_prime239v1 = 'prime239v1';
  {$EXTERNALSYM NID_X9_62_prime239v1}
  NID_X9_62_prime239v1 = 412;

  {$EXTERNALSYM SN_X9_62_prime239v2}
  SN_X9_62_prime239v2 = 'prime239v2';
  {$EXTERNALSYM NID_X9_62_prime239v2}
  NID_X9_62_prime239v2 = 413;

  {$EXTERNALSYM SN_X9_62_prime239v3}
  SN_X9_62_prime239v3 = 'prime239v3';
  {$EXTERNALSYM NID_X9_62_prime239v3}
  NID_X9_62_prime239v3 = 414;

  {$EXTERNALSYM SN_X9_62_prime256v1}
  SN_X9_62_prime256v1 = 'prime256v1';
  {$EXTERNALSYM NID_X9_62_prime256v1}
  NID_X9_62_prime256v1 = 415;

  {$EXTERNALSYM SN_ecdsa_with_SHA1}
  SN_ecdsa_with_SHA1 = 'ecdsa-with-SHA1';
  {$EXTERNALSYM NID_ecdsa_with_SHA1}
  NID_ecdsa_with_SHA1 = 416;

  {$EXTERNALSYM SN_ecdsa_with_Recommended}
  SN_ecdsa_with_Recommended = 'ecdsa-with-Recommended';
  {$EXTERNALSYM NID_ecdsa_with_Recommended}
  NID_ecdsa_with_Recommended = 791;

  {$EXTERNALSYM SN_ecdsa_with_Specified}
  SN_ecdsa_with_Specified = 'ecdsa-with-Specified';
  {$EXTERNALSYM NID_ecdsa_with_Specified}
  NID_ecdsa_with_Specified = 792;

  {$EXTERNALSYM SN_ecdsa_with_SHA224}
  SN_ecdsa_with_SHA224 = 'ecdsa-with-SHA224';
  {$EXTERNALSYM NID_ecdsa_with_SHA224}
  NID_ecdsa_with_SHA224 = 793;

  {$EXTERNALSYM SN_ecdsa_with_SHA256}
  SN_ecdsa_with_SHA256 = 'ecdsa-with-SHA256';
  {$EXTERNALSYM NID_ecdsa_with_SHA256}
  NID_ecdsa_with_SHA256 = 794;

  {$EXTERNALSYM SN_ecdsa_with_SHA384}
  SN_ecdsa_with_SHA384 = 'ecdsa-with-SHA384';
  {$EXTERNALSYM NID_ecdsa_with_SHA384}
  NID_ecdsa_with_SHA384 = 795;

  {$EXTERNALSYM SN_ecdsa_with_SHA512}
  SN_ecdsa_with_SHA512 = 'ecdsa-with-SHA512';
  {$EXTERNALSYM NID_ecdsa_with_SHA512}
  NID_ecdsa_with_SHA512 = 796;

  {$EXTERNALSYM SN_secp112r1}
  SN_secp112r1 = 'secp112r1';
  {$EXTERNALSYM NID_secp112r1}
  NID_secp112r1 = 704;

  {$EXTERNALSYM SN_secp112r2}
  SN_secp112r2 = 'secp112r2';
  {$EXTERNALSYM NID_secp112r2}
  NID_secp112r2 = 705;

  {$EXTERNALSYM SN_secp128r1}
  SN_secp128r1 = 'secp128r1';
  {$EXTERNALSYM NID_secp128r1}
  NID_secp128r1 = 706;

  {$EXTERNALSYM SN_secp128r2}
  SN_secp128r2 = 'secp128r2';
  {$EXTERNALSYM NID_secp128r2}
  NID_secp128r2 = 707;

  {$EXTERNALSYM SN_secp160k1}
  SN_secp160k1 = 'secp160k1';
  {$EXTERNALSYM NID_secp160k1}
  NID_secp160k1 = 708;

  {$EXTERNALSYM SN_secp160r1}
  SN_secp160r1 = 'secp160r1';
  {$EXTERNALSYM NID_secp160r1}
  NID_secp160r1 = 709;

  {$EXTERNALSYM SN_secp160r2}
  SN_secp160r2 = 'secp160r2';
  {$EXTERNALSYM NID_secp160r2}
  NID_secp160r2 = 710;

  {$EXTERNALSYM SN_secp192k1}
  SN_secp192k1 = 'secp192k1';
  {$EXTERNALSYM NID_secp192k1}
  NID_secp192k1 = 711;

  {$EXTERNALSYM SN_secp224k1}
  SN_secp224k1 = 'secp224k1';
  {$EXTERNALSYM NID_secp224k1}
  NID_secp224k1 = 712;

  {$EXTERNALSYM SN_secp224r1}
  SN_secp224r1 = 'secp224r1';
  {$EXTERNALSYM NID_secp224r1}
  NID_secp224r1 = 713;

  {$EXTERNALSYM SN_secp256k1}
  SN_secp256k1 = 'secp256k1';
  {$EXTERNALSYM NID_secp256k1}
  NID_secp256k1 = 714;

  {$EXTERNALSYM SN_secp384r1}
  SN_secp384r1 = 'secp384r1';
  {$EXTERNALSYM NID_secp384r1}
  NID_secp384r1 = 715;

  {$EXTERNALSYM SN_secp521r1}
  SN_secp521r1 = 'secp521r1';
  {$EXTERNALSYM NID_secp521r1}
  NID_secp521r1 = 716;

  {$EXTERNALSYM SN_sect113r1}
  SN_sect113r1 = 'sect113r1';
  {$EXTERNALSYM NID_sect113r1}
  NID_sect113r1 = 717;

  {$EXTERNALSYM SN_sect113r2}
  SN_sect113r2 = 'sect113r2';
  {$EXTERNALSYM NID_sect113r2}
  NID_sect113r2 = 718;

  {$EXTERNALSYM SN_sect131r1}
  SN_sect131r1 = 'sect131r1';
  {$EXTERNALSYM NID_sect131r1}
  NID_sect131r1 = 719;

  {$EXTERNALSYM SN_sect131r2}
  SN_sect131r2 = 'sect131r2';
  {$EXTERNALSYM NID_sect131r2}
  NID_sect131r2 = 720;

  {$EXTERNALSYM SN_sect163k1}
  SN_sect163k1 = 'sect163k1';
  {$EXTERNALSYM NID_sect163k1}
  NID_sect163k1 = 721;

  {$EXTERNALSYM SN_sect163r1}
  SN_sect163r1 = 'sect163r1';
  {$EXTERNALSYM NID_sect163r1}
  NID_sect163r1 = 722;

  {$EXTERNALSYM SN_sect163r2}
  SN_sect163r2 = 'sect163r2';
  {$EXTERNALSYM NID_sect163r2}
  NID_sect163r2 = 723;

  {$EXTERNALSYM SN_sect193r1}
  SN_sect193r1 = 'sect193r1';
  {$EXTERNALSYM NID_sect193r1}
  NID_sect193r1 = 724;

  {$EXTERNALSYM SN_sect193r2}
  SN_sect193r2 = 'sect193r2';
  {$EXTERNALSYM NID_sect193r2}
  NID_sect193r2 = 725;

  {$EXTERNALSYM SN_sect233k1}
  SN_sect233k1 = 'sect233k1';
  {$EXTERNALSYM NID_sect233k1}
  NID_sect233k1 = 726;

  {$EXTERNALSYM SN_sect233r1}
  SN_sect233r1 = 'sect233r1';
  {$EXTERNALSYM NID_sect233r1}
  NID_sect233r1 = 727;

  {$EXTERNALSYM SN_sect239k1}
  SN_sect239k1 = 'sect239k1';
  {$EXTERNALSYM NID_sect239k1}
  NID_sect239k1 = 728;

  {$EXTERNALSYM SN_sect283k1}
  SN_sect283k1 = 'sect283k1';
  {$EXTERNALSYM NID_sect283k1}
  NID_sect283k1 = 729;

  {$EXTERNALSYM SN_sect283r1}
  SN_sect283r1 = 'sect283r1';
  {$EXTERNALSYM NID_sect283r1}
  NID_sect283r1 = 730;

  {$EXTERNALSYM SN_sect409k1}
  SN_sect409k1 = 'sect409k1';
  {$EXTERNALSYM NID_sect409k1}
  NID_sect409k1 = 731;

  {$EXTERNALSYM SN_sect409r1}
  SN_sect409r1 = 'sect409r1';
  {$EXTERNALSYM NID_sect409r1}
  NID_sect409r1 = 732;

  {$EXTERNALSYM SN_sect571k1}
  SN_sect571k1 = 'sect571k1';
  {$EXTERNALSYM NID_sect571k1}
  NID_sect571k1 = 733;

  {$EXTERNALSYM SN_sect571r1}
  SN_sect571r1 = 'sect571r1';
  {$EXTERNALSYM NID_sect571r1}
  NID_sect571r1 = 734;

  {$EXTERNALSYM SN_wap_wsg_idm_ecid_wtls1}
  SN_wap_wsg_idm_ecid_wtls1 = 'wap-wsg-idm-ecid-wtls1';
  {$EXTERNALSYM NID_wap_wsg_idm_ecid_wtls1}
  NID_wap_wsg_idm_ecid_wtls1 = 735;

  {$EXTERNALSYM SN_wap_wsg_idm_ecid_wtls3}
  SN_wap_wsg_idm_ecid_wtls3 = 'wap-wsg-idm-ecid-wtls3';
  {$EXTERNALSYM NID_wap_wsg_idm_ecid_wtls3}
  NID_wap_wsg_idm_ecid_wtls3 = 736;

  {$EXTERNALSYM SN_wap_wsg_idm_ecid_wtls4}
  SN_wap_wsg_idm_ecid_wtls4 = 'wap-wsg-idm-ecid-wtls4';
  {$EXTERNALSYM NID_wap_wsg_idm_ecid_wtls4}
  NID_wap_wsg_idm_ecid_wtls4 = 737;

  {$EXTERNALSYM SN_wap_wsg_idm_ecid_wtls5}
  SN_wap_wsg_idm_ecid_wtls5 = 'wap-wsg-idm-ecid-wtls5';
  {$EXTERNALSYM NID_wap_wsg_idm_ecid_wtls5}
  NID_wap_wsg_idm_ecid_wtls5 = 738;

  {$EXTERNALSYM SN_wap_wsg_idm_ecid_wtls6}
  SN_wap_wsg_idm_ecid_wtls6 = 'wap-wsg-idm-ecid-wtls6';
  {$EXTERNALSYM NID_wap_wsg_idm_ecid_wtls6}
  NID_wap_wsg_idm_ecid_wtls6 = 739;

  {$EXTERNALSYM SN_wap_wsg_idm_ecid_wtls7}
  SN_wap_wsg_idm_ecid_wtls7 = 'wap-wsg-idm-ecid-wtls7';
  {$EXTERNALSYM NID_wap_wsg_idm_ecid_wtls7}
  NID_wap_wsg_idm_ecid_wtls7 = 740;

  {$EXTERNALSYM SN_wap_wsg_idm_ecid_wtls8}
  SN_wap_wsg_idm_ecid_wtls8 = 'wap-wsg-idm-ecid-wtls8';
  {$EXTERNALSYM NID_wap_wsg_idm_ecid_wtls8}
  NID_wap_wsg_idm_ecid_wtls8 = 741;

  {$EXTERNALSYM SN_wap_wsg_idm_ecid_wtls9}
  SN_wap_wsg_idm_ecid_wtls9 = 'wap-wsg-idm-ecid-wtls9';
  {$EXTERNALSYM NID_wap_wsg_idm_ecid_wtls9}
  NID_wap_wsg_idm_ecid_wtls9 = 742;

  {$EXTERNALSYM SN_wap_wsg_idm_ecid_wtls10}
  SN_wap_wsg_idm_ecid_wtls10 = 'wap-wsg-idm-ecid-wtls10';
  {$EXTERNALSYM NID_wap_wsg_idm_ecid_wtls10}
  NID_wap_wsg_idm_ecid_wtls10 = 743;

  {$EXTERNALSYM SN_wap_wsg_idm_ecid_wtls11}
  SN_wap_wsg_idm_ecid_wtls11 = 'wap-wsg-idm-ecid-wtls11';
  {$EXTERNALSYM NID_wap_wsg_idm_ecid_wtls11}
  NID_wap_wsg_idm_ecid_wtls11 = 744;

  {$EXTERNALSYM SN_wap_wsg_idm_ecid_wtls12}
  SN_wap_wsg_idm_ecid_wtls12 = 'wap-wsg-idm-ecid-wtls12';
  {$EXTERNALSYM NID_wap_wsg_idm_ecid_wtls12}
  NID_wap_wsg_idm_ecid_wtls12 = 745;

  {$EXTERNALSYM SN_cast5_cbc}
  SN_cast5_cbc = 'CAST5-CBC';
  {$EXTERNALSYM LN_cast5_cbc}
  LN_cast5_cbc = 'cast5-cbc';
  {$EXTERNALSYM NID_cast5_cbc}
  NID_cast5_cbc = 108;

  {$EXTERNALSYM SN_cast5_ecb}
  SN_cast5_ecb = 'CAST5-ECB';
  {$EXTERNALSYM LN_cast5_ecb}
  LN_cast5_ecb = 'cast5-ecb';
  {$EXTERNALSYM NID_cast5_ecb}
  NID_cast5_ecb = 109;

  {$EXTERNALSYM SN_cast5_cfb64}
  SN_cast5_cfb64 = 'CAST5-CFB';
  {$EXTERNALSYM LN_cast5_cfb64}
  LN_cast5_cfb64 = 'cast5-cfb';
  {$EXTERNALSYM NID_cast5_cfb64}
  NID_cast5_cfb64 = 110;

  {$EXTERNALSYM SN_cast5_ofb64}
  SN_cast5_ofb64 = 'CAST5-OFB';
  {$EXTERNALSYM LN_cast5_ofb64}
  LN_cast5_ofb64 = 'cast5-ofb';
  {$EXTERNALSYM NID_cast5_ofb64}
  NID_cast5_ofb64 = 111;

  {$EXTERNALSYM LN_pbeWithMD5AndCast5_CBC}
  LN_pbeWithMD5AndCast5_CBC = 'pbeWithMD5AndCast5CBC';
  {$EXTERNALSYM NID_pbeWithMD5AndCast5_CBC}
  NID_pbeWithMD5AndCast5_CBC = 112;

  {$EXTERNALSYM SN_id_PasswordBasedMAC}
  SN_id_PasswordBasedMAC = 'id-PasswordBasedMAC';
  {$EXTERNALSYM LN_id_PasswordBasedMAC}
  LN_id_PasswordBasedMAC = 'password based MAC';
  {$EXTERNALSYM NID_id_PasswordBasedMAC}
  NID_id_PasswordBasedMAC = 782;

  {$EXTERNALSYM SN_id_DHBasedMac}
  SN_id_DHBasedMac = 'id-DHBasedMac';
  {$EXTERNALSYM LN_id_DHBasedMac}
  LN_id_DHBasedMac = 'Diffie-Hellman based MAC';
  {$EXTERNALSYM NID_id_DHBasedMac}
  NID_id_DHBasedMac = 783;

  {$EXTERNALSYM SN_rsadsi}
  SN_rsadsi = 'rsadsi';
  {$EXTERNALSYM LN_rsadsi}
  LN_rsadsi = 'RSA Data Security; Inc.';
  {$EXTERNALSYM NID_rsadsi}
  NID_rsadsi = 1;

  {$EXTERNALSYM SN_pkcs}
  SN_pkcs = 'pkcs';
  {$EXTERNALSYM LN_pkcs}
  LN_pkcs = 'RSA Data Security; Inc. PKCS';
  {$EXTERNALSYM NID_pkcs}
  NID_pkcs = 2;

  {$EXTERNALSYM SN_pkcs1}
  SN_pkcs1 = 'pkcs1';
  {$EXTERNALSYM NID_pkcs1}
  NID_pkcs1 = 186;

  {$EXTERNALSYM LN_rsaEncryption}
  LN_rsaEncryption = 'rsaEncryption';
  {$EXTERNALSYM NID_rsaEncryption}
  NID_rsaEncryption = 6;

  {$EXTERNALSYM SN_md2WithRSAEncryption}
  SN_md2WithRSAEncryption = 'RSA-MD2';
  {$EXTERNALSYM LN_md2WithRSAEncryption}
  LN_md2WithRSAEncryption = 'md2WithRSAEncryption';
  {$EXTERNALSYM NID_md2WithRSAEncryption}
  NID_md2WithRSAEncryption = 7;

  {$EXTERNALSYM SN_md4WithRSAEncryption}
  SN_md4WithRSAEncryption = 'RSA-MD4';
  {$EXTERNALSYM LN_md4WithRSAEncryption}
  LN_md4WithRSAEncryption = 'md4WithRSAEncryption';
  {$EXTERNALSYM NID_md4WithRSAEncryption}
  NID_md4WithRSAEncryption = 396;

  {$EXTERNALSYM SN_md5WithRSAEncryption}
  SN_md5WithRSAEncryption = 'RSA-MD5';
  {$EXTERNALSYM LN_md5WithRSAEncryption}
  LN_md5WithRSAEncryption = 'md5WithRSAEncryption';
  {$EXTERNALSYM NID_md5WithRSAEncryption}
  NID_md5WithRSAEncryption = 8;

  {$EXTERNALSYM SN_sha1WithRSAEncryption}
  SN_sha1WithRSAEncryption = 'RSA-SHA1';
  {$EXTERNALSYM LN_sha1WithRSAEncryption}
  LN_sha1WithRSAEncryption = 'sha1WithRSAEncryption';
  {$EXTERNALSYM NID_sha1WithRSAEncryption}
  NID_sha1WithRSAEncryption = 65;

  {$EXTERNALSYM SN_rsaesOaep}
  SN_rsaesOaep = 'RSAES-OAEP';
  {$EXTERNALSYM LN_rsaesOaep}
  LN_rsaesOaep = 'rsaesOaep';
  {$EXTERNALSYM NID_rsaesOaep}
  NID_rsaesOaep = 919;

  {$EXTERNALSYM SN_mgf1}
  SN_mgf1 = 'MGF1';
  {$EXTERNALSYM LN_mgf1}
  LN_mgf1 = 'mgf1';
  {$EXTERNALSYM NID_mgf1}
  NID_mgf1 = 911;

  {$EXTERNALSYM SN_pSpecified}
  SN_pSpecified = 'PSPECIFIED';
  {$EXTERNALSYM LN_pSpecified}
  LN_pSpecified = 'pSpecified';
  {$EXTERNALSYM NID_pSpecified}
  NID_pSpecified = 935;

  {$EXTERNALSYM SN_rsassaPss}
  SN_rsassaPss = 'RSASSA-PSS';
  {$EXTERNALSYM LN_rsassaPss}
  LN_rsassaPss = 'rsassaPss';
  {$EXTERNALSYM NID_rsassaPss}
  NID_rsassaPss = 912;

  {$EXTERNALSYM SN_sha256WithRSAEncryption}
  SN_sha256WithRSAEncryption = 'RSA-SHA256';
  {$EXTERNALSYM LN_sha256WithRSAEncryption}
  LN_sha256WithRSAEncryption = 'sha256WithRSAEncryption';
  {$EXTERNALSYM NID_sha256WithRSAEncryption}
  NID_sha256WithRSAEncryption = 668;

  {$EXTERNALSYM SN_sha384WithRSAEncryption}
  SN_sha384WithRSAEncryption = 'RSA-SHA384';
  {$EXTERNALSYM LN_sha384WithRSAEncryption}
  LN_sha384WithRSAEncryption = 'sha384WithRSAEncryption';
  {$EXTERNALSYM NID_sha384WithRSAEncryption}
  NID_sha384WithRSAEncryption = 669;

  {$EXTERNALSYM SN_sha512WithRSAEncryption}
  SN_sha512WithRSAEncryption = 'RSA-SHA512';
  {$EXTERNALSYM LN_sha512WithRSAEncryption}
  LN_sha512WithRSAEncryption = 'sha512WithRSAEncryption';
  {$EXTERNALSYM NID_sha512WithRSAEncryption}
  NID_sha512WithRSAEncryption = 670;

  {$EXTERNALSYM SN_sha224WithRSAEncryption}
  SN_sha224WithRSAEncryption = 'RSA-SHA224';
  {$EXTERNALSYM LN_sha224WithRSAEncryption}
  LN_sha224WithRSAEncryption = 'sha224WithRSAEncryption';
  {$EXTERNALSYM NID_sha224WithRSAEncryption}
  NID_sha224WithRSAEncryption = 671;

  {$EXTERNALSYM SN_sha512_224WithRSAEncryption}
  SN_sha512_224WithRSAEncryption = 'RSA-SHA512/224';
  {$EXTERNALSYM LN_sha512_224WithRSAEncryption}
  LN_sha512_224WithRSAEncryption = 'sha512-224WithRSAEncryption';
  {$EXTERNALSYM NID_sha512_224WithRSAEncryption}
  NID_sha512_224WithRSAEncryption = 1145;

  {$EXTERNALSYM SN_sha512_256WithRSAEncryption}
  SN_sha512_256WithRSAEncryption = 'RSA-SHA512/256';
  {$EXTERNALSYM LN_sha512_256WithRSAEncryption}
  LN_sha512_256WithRSAEncryption = 'sha512-256WithRSAEncryption';
  {$EXTERNALSYM NID_sha512_256WithRSAEncryption}
  NID_sha512_256WithRSAEncryption = 1146;

  {$EXTERNALSYM SN_pkcs3}
  SN_pkcs3 = 'pkcs3';
  {$EXTERNALSYM NID_pkcs3}
  NID_pkcs3 = 27;

  {$EXTERNALSYM LN_dhKeyAgreement}
  LN_dhKeyAgreement = 'dhKeyAgreement';
  {$EXTERNALSYM NID_dhKeyAgreement}
  NID_dhKeyAgreement = 28;

  {$EXTERNALSYM SN_pkcs5}
  SN_pkcs5 = 'pkcs5';
  {$EXTERNALSYM NID_pkcs5}
  NID_pkcs5 = 187;

  {$EXTERNALSYM SN_pbeWithMD2AndDES_CBC}
  SN_pbeWithMD2AndDES_CBC = 'PBE-MD2-DES';
  {$EXTERNALSYM LN_pbeWithMD2AndDES_CBC}
  LN_pbeWithMD2AndDES_CBC = 'pbeWithMD2AndDES-CBC';
  {$EXTERNALSYM NID_pbeWithMD2AndDES_CBC}
  NID_pbeWithMD2AndDES_CBC = 9;

  {$EXTERNALSYM SN_pbeWithMD5AndDES_CBC}
  SN_pbeWithMD5AndDES_CBC = 'PBE-MD5-DES';
  {$EXTERNALSYM LN_pbeWithMD5AndDES_CBC}
  LN_pbeWithMD5AndDES_CBC = 'pbeWithMD5AndDES-CBC';
  {$EXTERNALSYM NID_pbeWithMD5AndDES_CBC}
  NID_pbeWithMD5AndDES_CBC = 10;

  {$EXTERNALSYM SN_pbeWithMD2AndRC2_CBC}
  SN_pbeWithMD2AndRC2_CBC = 'PBE-MD2-RC2-64';
  {$EXTERNALSYM LN_pbeWithMD2AndRC2_CBC}
  LN_pbeWithMD2AndRC2_CBC = 'pbeWithMD2AndRC2-CBC';
  {$EXTERNALSYM NID_pbeWithMD2AndRC2_CBC}
  NID_pbeWithMD2AndRC2_CBC = 168;

  {$EXTERNALSYM SN_pbeWithMD5AndRC2_CBC}
  SN_pbeWithMD5AndRC2_CBC = 'PBE-MD5-RC2-64';
  {$EXTERNALSYM LN_pbeWithMD5AndRC2_CBC}
  LN_pbeWithMD5AndRC2_CBC = 'pbeWithMD5AndRC2-CBC';
  {$EXTERNALSYM NID_pbeWithMD5AndRC2_CBC}
  NID_pbeWithMD5AndRC2_CBC = 169;

  {$EXTERNALSYM SN_pbeWithSHA1AndDES_CBC}
  SN_pbeWithSHA1AndDES_CBC = 'PBE-SHA1-DES';
  {$EXTERNALSYM LN_pbeWithSHA1AndDES_CBC}
  LN_pbeWithSHA1AndDES_CBC = 'pbeWithSHA1AndDES-CBC';
  {$EXTERNALSYM NID_pbeWithSHA1AndDES_CBC}
  NID_pbeWithSHA1AndDES_CBC = 170;

  {$EXTERNALSYM SN_pbeWithSHA1AndRC2_CBC}
  SN_pbeWithSHA1AndRC2_CBC = 'PBE-SHA1-RC2-64';
  {$EXTERNALSYM LN_pbeWithSHA1AndRC2_CBC}
  LN_pbeWithSHA1AndRC2_CBC = 'pbeWithSHA1AndRC2-CBC';
  {$EXTERNALSYM NID_pbeWithSHA1AndRC2_CBC}
  NID_pbeWithSHA1AndRC2_CBC = 68;

  {$EXTERNALSYM LN_id_pbkdf2}
  LN_id_pbkdf2 = 'PBKDF2';
  {$EXTERNALSYM NID_id_pbkdf2}
  NID_id_pbkdf2 = 69;

  {$EXTERNALSYM LN_pbes2}
  LN_pbes2 = 'PBES2';
  {$EXTERNALSYM NID_pbes2}
  NID_pbes2 = 161;

  {$EXTERNALSYM LN_pbmac1}
  LN_pbmac1 = 'PBMAC1';
  {$EXTERNALSYM NID_pbmac1}
  NID_pbmac1 = 162;

  {$EXTERNALSYM SN_pkcs7}
  SN_pkcs7 = 'pkcs7';
  {$EXTERNALSYM NID_pkcs7}
  NID_pkcs7 = 20;

  {$EXTERNALSYM LN_pkcs7_data}
  LN_pkcs7_data = 'pkcs7-data';
  {$EXTERNALSYM NID_pkcs7_data}
  NID_pkcs7_data = 21;

  {$EXTERNALSYM LN_pkcs7_signed}
  LN_pkcs7_signed = 'pkcs7-signedData';
  {$EXTERNALSYM NID_pkcs7_signed}
  NID_pkcs7_signed = 22;

  {$EXTERNALSYM LN_pkcs7_enveloped}
  LN_pkcs7_enveloped = 'pkcs7-envelopedData';
  {$EXTERNALSYM NID_pkcs7_enveloped}
  NID_pkcs7_enveloped = 23;

  {$EXTERNALSYM LN_pkcs7_signedAndEnveloped}
  LN_pkcs7_signedAndEnveloped = 'pkcs7-signedAndEnvelopedData';
  {$EXTERNALSYM NID_pkcs7_signedAndEnveloped}
  NID_pkcs7_signedAndEnveloped = 24;

  {$EXTERNALSYM LN_pkcs7_digest}
  LN_pkcs7_digest = 'pkcs7-digestData';
  {$EXTERNALSYM NID_pkcs7_digest}
  NID_pkcs7_digest = 25;

  {$EXTERNALSYM LN_pkcs7_encrypted}
  LN_pkcs7_encrypted = 'pkcs7-encryptedData';
  {$EXTERNALSYM NID_pkcs7_encrypted}
  NID_pkcs7_encrypted = 26;

  {$EXTERNALSYM SN_pkcs9}
  SN_pkcs9 = 'pkcs9';
  {$EXTERNALSYM NID_pkcs9}
  NID_pkcs9 = 47;

  {$EXTERNALSYM LN_pkcs9_emailAddress}
  LN_pkcs9_emailAddress = 'emailAddress';
  {$EXTERNALSYM NID_pkcs9_emailAddress}
  NID_pkcs9_emailAddress = 48;

  {$EXTERNALSYM LN_pkcs9_unstructuredName}
  LN_pkcs9_unstructuredName = 'unstructuredName';
  {$EXTERNALSYM NID_pkcs9_unstructuredName}
  NID_pkcs9_unstructuredName = 49;

  {$EXTERNALSYM LN_pkcs9_contentType}
  LN_pkcs9_contentType = 'contentType';
  {$EXTERNALSYM NID_pkcs9_contentType}
  NID_pkcs9_contentType = 50;

  {$EXTERNALSYM LN_pkcs9_messageDigest}
  LN_pkcs9_messageDigest = 'messageDigest';
  {$EXTERNALSYM NID_pkcs9_messageDigest}
  NID_pkcs9_messageDigest = 51;

  {$EXTERNALSYM LN_pkcs9_signingTime}
  LN_pkcs9_signingTime = 'signingTime';
  {$EXTERNALSYM NID_pkcs9_signingTime}
  NID_pkcs9_signingTime = 52;

  {$EXTERNALSYM LN_pkcs9_countersignature}
  LN_pkcs9_countersignature = 'countersignature';
  {$EXTERNALSYM NID_pkcs9_countersignature}
  NID_pkcs9_countersignature = 53;

  {$EXTERNALSYM LN_pkcs9_challengePassword}
  LN_pkcs9_challengePassword = 'challengePassword';
  {$EXTERNALSYM NID_pkcs9_challengePassword}
  NID_pkcs9_challengePassword = 54;

  {$EXTERNALSYM LN_pkcs9_unstructuredAddress}
  LN_pkcs9_unstructuredAddress = 'unstructuredAddress';
  {$EXTERNALSYM NID_pkcs9_unstructuredAddress}
  NID_pkcs9_unstructuredAddress = 55;

  {$EXTERNALSYM LN_pkcs9_extCertAttributes}
  LN_pkcs9_extCertAttributes = 'extendedCertificateAttributes';
  {$EXTERNALSYM NID_pkcs9_extCertAttributes}
  NID_pkcs9_extCertAttributes = 56;

  {$EXTERNALSYM SN_ext_req}
  SN_ext_req = 'extReq';
  {$EXTERNALSYM LN_ext_req}
  LN_ext_req = 'Extension Request';
  {$EXTERNALSYM NID_ext_req}
  NID_ext_req = 172;

  {$EXTERNALSYM SN_SMIMECapabilities}
  SN_SMIMECapabilities = 'SMIME-CAPS';
  {$EXTERNALSYM LN_SMIMECapabilities}
  LN_SMIMECapabilities = 'S/MIME Capabilities';
  {$EXTERNALSYM NID_SMIMECapabilities}
  NID_SMIMECapabilities = 167;

  {$EXTERNALSYM SN_SMIME}
  SN_SMIME = 'SMIME';
  {$EXTERNALSYM LN_SMIME}
  LN_SMIME = 'S/MIME';
  {$EXTERNALSYM NID_SMIME}
  NID_SMIME = 188;

  {$EXTERNALSYM SN_id_smime_mod}
  SN_id_smime_mod = 'id-smime-mod';
  {$EXTERNALSYM NID_id_smime_mod}
  NID_id_smime_mod = 189;

  {$EXTERNALSYM SN_id_smime_ct}
  SN_id_smime_ct = 'id-smime-ct';
  {$EXTERNALSYM NID_id_smime_ct}
  NID_id_smime_ct = 190;

  {$EXTERNALSYM SN_id_smime_aa}
  SN_id_smime_aa = 'id-smime-aa';
  {$EXTERNALSYM NID_id_smime_aa}
  NID_id_smime_aa = 191;

  {$EXTERNALSYM SN_id_smime_alg}
  SN_id_smime_alg = 'id-smime-alg';
  {$EXTERNALSYM NID_id_smime_alg}
  NID_id_smime_alg = 192;

  {$EXTERNALSYM SN_id_smime_cd}
  SN_id_smime_cd = 'id-smime-cd';
  {$EXTERNALSYM NID_id_smime_cd}
  NID_id_smime_cd = 193;

  {$EXTERNALSYM SN_id_smime_spq}
  SN_id_smime_spq = 'id-smime-spq';
  {$EXTERNALSYM NID_id_smime_spq}
  NID_id_smime_spq = 194;

  {$EXTERNALSYM SN_id_smime_cti}
  SN_id_smime_cti = 'id-smime-cti';
  {$EXTERNALSYM NID_id_smime_cti}
  NID_id_smime_cti = 195;

  {$EXTERNALSYM SN_id_smime_mod_cms}
  SN_id_smime_mod_cms = 'id-smime-mod-cms';
  {$EXTERNALSYM NID_id_smime_mod_cms}
  NID_id_smime_mod_cms = 196;

  {$EXTERNALSYM SN_id_smime_mod_ess}
  SN_id_smime_mod_ess = 'id-smime-mod-ess';
  {$EXTERNALSYM NID_id_smime_mod_ess}
  NID_id_smime_mod_ess = 197;

  {$EXTERNALSYM SN_id_smime_mod_oid}
  SN_id_smime_mod_oid = 'id-smime-mod-oid';
  {$EXTERNALSYM NID_id_smime_mod_oid}
  NID_id_smime_mod_oid = 198;

  {$EXTERNALSYM SN_id_smime_mod_msg_v3}
  SN_id_smime_mod_msg_v3 = 'id-smime-mod-msg-v3';
  {$EXTERNALSYM NID_id_smime_mod_msg_v3}
  NID_id_smime_mod_msg_v3 = 199;

  {$EXTERNALSYM SN_id_smime_mod_ets_eSignature_88}
  SN_id_smime_mod_ets_eSignature_88 = 'id-smime-mod-ets-eSignature-88';
  {$EXTERNALSYM NID_id_smime_mod_ets_eSignature_88}
  NID_id_smime_mod_ets_eSignature_88 = 200;

  {$EXTERNALSYM SN_id_smime_mod_ets_eSignature_97}
  SN_id_smime_mod_ets_eSignature_97 = 'id-smime-mod-ets-eSignature-97';
  {$EXTERNALSYM NID_id_smime_mod_ets_eSignature_97}
  NID_id_smime_mod_ets_eSignature_97 = 201;

  {$EXTERNALSYM SN_id_smime_mod_ets_eSigPolicy_88}
  SN_id_smime_mod_ets_eSigPolicy_88 = 'id-smime-mod-ets-eSigPolicy-88';
  {$EXTERNALSYM NID_id_smime_mod_ets_eSigPolicy_88}
  NID_id_smime_mod_ets_eSigPolicy_88 = 202;

  {$EXTERNALSYM SN_id_smime_mod_ets_eSigPolicy_97}
  SN_id_smime_mod_ets_eSigPolicy_97 = 'id-smime-mod-ets-eSigPolicy-97';
  {$EXTERNALSYM NID_id_smime_mod_ets_eSigPolicy_97}
  NID_id_smime_mod_ets_eSigPolicy_97 = 203;

  {$EXTERNALSYM SN_id_smime_ct_receipt}
  SN_id_smime_ct_receipt = 'id-smime-ct-receipt';
  {$EXTERNALSYM NID_id_smime_ct_receipt}
  NID_id_smime_ct_receipt = 204;

  {$EXTERNALSYM SN_id_smime_ct_authData}
  SN_id_smime_ct_authData = 'id-smime-ct-authData';
  {$EXTERNALSYM NID_id_smime_ct_authData}
  NID_id_smime_ct_authData = 205;

  {$EXTERNALSYM SN_id_smime_ct_publishCert}
  SN_id_smime_ct_publishCert = 'id-smime-ct-publishCert';
  {$EXTERNALSYM NID_id_smime_ct_publishCert}
  NID_id_smime_ct_publishCert = 206;

  {$EXTERNALSYM SN_id_smime_ct_TSTInfo}
  SN_id_smime_ct_TSTInfo = 'id-smime-ct-TSTInfo';
  {$EXTERNALSYM NID_id_smime_ct_TSTInfo}
  NID_id_smime_ct_TSTInfo = 207;

  {$EXTERNALSYM SN_id_smime_ct_TDTInfo}
  SN_id_smime_ct_TDTInfo = 'id-smime-ct-TDTInfo';
  {$EXTERNALSYM NID_id_smime_ct_TDTInfo}
  NID_id_smime_ct_TDTInfo = 208;

  {$EXTERNALSYM SN_id_smime_ct_contentInfo}
  SN_id_smime_ct_contentInfo = 'id-smime-ct-contentInfo';
  {$EXTERNALSYM NID_id_smime_ct_contentInfo}
  NID_id_smime_ct_contentInfo = 209;

  {$EXTERNALSYM SN_id_smime_ct_DVCSRequestData}
  SN_id_smime_ct_DVCSRequestData = 'id-smime-ct-DVCSRequestData';
  {$EXTERNALSYM NID_id_smime_ct_DVCSRequestData}
  NID_id_smime_ct_DVCSRequestData = 210;

  {$EXTERNALSYM SN_id_smime_ct_DVCSResponseData}
  SN_id_smime_ct_DVCSResponseData = 'id-smime-ct-DVCSResponseData';
  {$EXTERNALSYM NID_id_smime_ct_DVCSResponseData}
  NID_id_smime_ct_DVCSResponseData = 211;

  {$EXTERNALSYM SN_id_smime_ct_compressedData}
  SN_id_smime_ct_compressedData = 'id-smime-ct-compressedData';
  {$EXTERNALSYM NID_id_smime_ct_compressedData}
  NID_id_smime_ct_compressedData = 786;

  {$EXTERNALSYM SN_id_smime_ct_contentCollection}
  SN_id_smime_ct_contentCollection = 'id-smime-ct-contentCollection';
  {$EXTERNALSYM NID_id_smime_ct_contentCollection}
  NID_id_smime_ct_contentCollection = 1058;

  {$EXTERNALSYM SN_id_smime_ct_authEnvelopedData}
  SN_id_smime_ct_authEnvelopedData = 'id-smime-ct-authEnvelopedData';
  {$EXTERNALSYM NID_id_smime_ct_authEnvelopedData}
  NID_id_smime_ct_authEnvelopedData = 1059;

  {$EXTERNALSYM SN_id_ct_asciiTextWithCRLF}
  SN_id_ct_asciiTextWithCRLF = 'id-ct-asciiTextWithCRLF';
  {$EXTERNALSYM NID_id_ct_asciiTextWithCRLF}
  NID_id_ct_asciiTextWithCRLF = 787;

  {$EXTERNALSYM SN_id_ct_xml}
  SN_id_ct_xml = 'id-ct-xml';
  {$EXTERNALSYM NID_id_ct_xml}
  NID_id_ct_xml = 1060;

  {$EXTERNALSYM SN_id_smime_aa_receiptRequest}
  SN_id_smime_aa_receiptRequest = 'id-smime-aa-receiptRequest';
  {$EXTERNALSYM NID_id_smime_aa_receiptRequest}
  NID_id_smime_aa_receiptRequest = 212;

  {$EXTERNALSYM SN_id_smime_aa_securityLabel}
  SN_id_smime_aa_securityLabel = 'id-smime-aa-securityLabel';
  {$EXTERNALSYM NID_id_smime_aa_securityLabel}
  NID_id_smime_aa_securityLabel = 213;

  {$EXTERNALSYM SN_id_smime_aa_mlExpandHistory}
  SN_id_smime_aa_mlExpandHistory = 'id-smime-aa-mlExpandHistory';
  {$EXTERNALSYM NID_id_smime_aa_mlExpandHistory}
  NID_id_smime_aa_mlExpandHistory = 214;

  {$EXTERNALSYM SN_id_smime_aa_contentHint}
  SN_id_smime_aa_contentHint = 'id-smime-aa-contentHint';
  {$EXTERNALSYM NID_id_smime_aa_contentHint}
  NID_id_smime_aa_contentHint = 215;

  {$EXTERNALSYM SN_id_smime_aa_msgSigDigest}
  SN_id_smime_aa_msgSigDigest = 'id-smime-aa-msgSigDigest';
  {$EXTERNALSYM NID_id_smime_aa_msgSigDigest}
  NID_id_smime_aa_msgSigDigest = 216;

  {$EXTERNALSYM SN_id_smime_aa_encapContentType}
  SN_id_smime_aa_encapContentType = 'id-smime-aa-encapContentType';
  {$EXTERNALSYM NID_id_smime_aa_encapContentType}
  NID_id_smime_aa_encapContentType = 217;

  {$EXTERNALSYM SN_id_smime_aa_contentIdentifier}
  SN_id_smime_aa_contentIdentifier = 'id-smime-aa-contentIdentifier';
  {$EXTERNALSYM NID_id_smime_aa_contentIdentifier}
  NID_id_smime_aa_contentIdentifier = 218;

  {$EXTERNALSYM SN_id_smime_aa_macValue}
  SN_id_smime_aa_macValue = 'id-smime-aa-macValue';
  {$EXTERNALSYM NID_id_smime_aa_macValue}
  NID_id_smime_aa_macValue = 219;

  {$EXTERNALSYM SN_id_smime_aa_equivalentLabels}
  SN_id_smime_aa_equivalentLabels = 'id-smime-aa-equivalentLabels';
  {$EXTERNALSYM NID_id_smime_aa_equivalentLabels}
  NID_id_smime_aa_equivalentLabels = 220;

  {$EXTERNALSYM SN_id_smime_aa_contentReference}
  SN_id_smime_aa_contentReference = 'id-smime-aa-contentReference';
  {$EXTERNALSYM NID_id_smime_aa_contentReference}
  NID_id_smime_aa_contentReference = 221;

  {$EXTERNALSYM SN_id_smime_aa_encrypKeyPref}
  SN_id_smime_aa_encrypKeyPref = 'id-smime-aa-encrypKeyPref';
  {$EXTERNALSYM NID_id_smime_aa_encrypKeyPref}
  NID_id_smime_aa_encrypKeyPref = 222;

  {$EXTERNALSYM SN_id_smime_aa_signingCertificate}
  SN_id_smime_aa_signingCertificate = 'id-smime-aa-signingCertificate';
  {$EXTERNALSYM NID_id_smime_aa_signingCertificate}
  NID_id_smime_aa_signingCertificate = 223;

  {$EXTERNALSYM SN_id_smime_aa_smimeEncryptCerts}
  SN_id_smime_aa_smimeEncryptCerts = 'id-smime-aa-smimeEncryptCerts';
  {$EXTERNALSYM NID_id_smime_aa_smimeEncryptCerts}
  NID_id_smime_aa_smimeEncryptCerts = 224;

  {$EXTERNALSYM SN_id_smime_aa_timeStampToken}
  SN_id_smime_aa_timeStampToken = 'id-smime-aa-timeStampToken';
  {$EXTERNALSYM NID_id_smime_aa_timeStampToken}
  NID_id_smime_aa_timeStampToken = 225;

  {$EXTERNALSYM SN_id_smime_aa_ets_sigPolicyId}
  SN_id_smime_aa_ets_sigPolicyId = 'id-smime-aa-ets-sigPolicyId';
  {$EXTERNALSYM NID_id_smime_aa_ets_sigPolicyId}
  NID_id_smime_aa_ets_sigPolicyId = 226;

  {$EXTERNALSYM SN_id_smime_aa_ets_commitmentType}
  SN_id_smime_aa_ets_commitmentType = 'id-smime-aa-ets-commitmentType';
  {$EXTERNALSYM NID_id_smime_aa_ets_commitmentType}
  NID_id_smime_aa_ets_commitmentType = 227;

  {$EXTERNALSYM SN_id_smime_aa_ets_signerLocation}
  SN_id_smime_aa_ets_signerLocation = 'id-smime-aa-ets-signerLocation';
  {$EXTERNALSYM NID_id_smime_aa_ets_signerLocation}
  NID_id_smime_aa_ets_signerLocation = 228;

  {$EXTERNALSYM SN_id_smime_aa_ets_signerAttr}
  SN_id_smime_aa_ets_signerAttr = 'id-smime-aa-ets-signerAttr';
  {$EXTERNALSYM NID_id_smime_aa_ets_signerAttr}
  NID_id_smime_aa_ets_signerAttr = 229;

  {$EXTERNALSYM SN_id_smime_aa_ets_otherSigCert}
  SN_id_smime_aa_ets_otherSigCert = 'id-smime-aa-ets-otherSigCert';
  {$EXTERNALSYM NID_id_smime_aa_ets_otherSigCert}
  NID_id_smime_aa_ets_otherSigCert = 230;

  {$EXTERNALSYM SN_id_smime_aa_ets_contentTimestamp}
  SN_id_smime_aa_ets_contentTimestamp = 'id-smime-aa-ets-contentTimestamp';
  {$EXTERNALSYM NID_id_smime_aa_ets_contentTimestamp}
  NID_id_smime_aa_ets_contentTimestamp = 231;

  {$EXTERNALSYM SN_id_smime_aa_ets_CertificateRefs}
  SN_id_smime_aa_ets_CertificateRefs = 'id-smime-aa-ets-CertificateRefs';
  {$EXTERNALSYM NID_id_smime_aa_ets_CertificateRefs}
  NID_id_smime_aa_ets_CertificateRefs = 232;

  {$EXTERNALSYM SN_id_smime_aa_ets_RevocationRefs}
  SN_id_smime_aa_ets_RevocationRefs = 'id-smime-aa-ets-RevocationRefs';
  {$EXTERNALSYM NID_id_smime_aa_ets_RevocationRefs}
  NID_id_smime_aa_ets_RevocationRefs = 233;

  {$EXTERNALSYM SN_id_smime_aa_ets_certValues}
  SN_id_smime_aa_ets_certValues = 'id-smime-aa-ets-certValues';
  {$EXTERNALSYM NID_id_smime_aa_ets_certValues}
  NID_id_smime_aa_ets_certValues = 234;

  {$EXTERNALSYM SN_id_smime_aa_ets_revocationValues}
  SN_id_smime_aa_ets_revocationValues = 'id-smime-aa-ets-revocationValues';
  {$EXTERNALSYM NID_id_smime_aa_ets_revocationValues}
  NID_id_smime_aa_ets_revocationValues = 235;

  {$EXTERNALSYM SN_id_smime_aa_ets_escTimeStamp}
  SN_id_smime_aa_ets_escTimeStamp = 'id-smime-aa-ets-escTimeStamp';
  {$EXTERNALSYM NID_id_smime_aa_ets_escTimeStamp}
  NID_id_smime_aa_ets_escTimeStamp = 236;

  {$EXTERNALSYM SN_id_smime_aa_ets_certCRLTimestamp}
  SN_id_smime_aa_ets_certCRLTimestamp = 'id-smime-aa-ets-certCRLTimestamp';
  {$EXTERNALSYM NID_id_smime_aa_ets_certCRLTimestamp}
  NID_id_smime_aa_ets_certCRLTimestamp = 237;

  {$EXTERNALSYM SN_id_smime_aa_ets_archiveTimeStamp}
  SN_id_smime_aa_ets_archiveTimeStamp = 'id-smime-aa-ets-archiveTimeStamp';
  {$EXTERNALSYM NID_id_smime_aa_ets_archiveTimeStamp}
  NID_id_smime_aa_ets_archiveTimeStamp = 238;

  {$EXTERNALSYM SN_id_smime_aa_signatureType}
  SN_id_smime_aa_signatureType = 'id-smime-aa-signatureType';
  {$EXTERNALSYM NID_id_smime_aa_signatureType}
  NID_id_smime_aa_signatureType = 239;

  {$EXTERNALSYM SN_id_smime_aa_dvcs_dvc}
  SN_id_smime_aa_dvcs_dvc = 'id-smime-aa-dvcs-dvc';
  {$EXTERNALSYM NID_id_smime_aa_dvcs_dvc}
  NID_id_smime_aa_dvcs_dvc = 240;

  {$EXTERNALSYM SN_id_smime_aa_signingCertificateV2}
  SN_id_smime_aa_signingCertificateV2 = 'id-smime-aa-signingCertificateV2';
  {$EXTERNALSYM NID_id_smime_aa_signingCertificateV2}
  NID_id_smime_aa_signingCertificateV2 = 1086;

  {$EXTERNALSYM SN_id_smime_alg_ESDHwith3DES}
  SN_id_smime_alg_ESDHwith3DES = 'id-smime-alg-ESDHwith3DES';
  {$EXTERNALSYM NID_id_smime_alg_ESDHwith3DES}
  NID_id_smime_alg_ESDHwith3DES = 241;

  {$EXTERNALSYM SN_id_smime_alg_ESDHwithRC2}
  SN_id_smime_alg_ESDHwithRC2 = 'id-smime-alg-ESDHwithRC2';
  {$EXTERNALSYM NID_id_smime_alg_ESDHwithRC2}
  NID_id_smime_alg_ESDHwithRC2 = 242;

  {$EXTERNALSYM SN_id_smime_alg_3DESwrap}
  SN_id_smime_alg_3DESwrap = 'id-smime-alg-3DESwrap';
  {$EXTERNALSYM NID_id_smime_alg_3DESwrap}
  NID_id_smime_alg_3DESwrap = 243;

  {$EXTERNALSYM SN_id_smime_alg_RC2wrap}
  SN_id_smime_alg_RC2wrap = 'id-smime-alg-RC2wrap';
  {$EXTERNALSYM NID_id_smime_alg_RC2wrap}
  NID_id_smime_alg_RC2wrap = 244;

  {$EXTERNALSYM SN_id_smime_alg_ESDH}
  SN_id_smime_alg_ESDH = 'id-smime-alg-ESDH';
  {$EXTERNALSYM NID_id_smime_alg_ESDH}
  NID_id_smime_alg_ESDH = 245;

  {$EXTERNALSYM SN_id_smime_alg_CMS3DESwrap}
  SN_id_smime_alg_CMS3DESwrap = 'id-smime-alg-CMS3DESwrap';
  {$EXTERNALSYM NID_id_smime_alg_CMS3DESwrap}
  NID_id_smime_alg_CMS3DESwrap = 246;

  {$EXTERNALSYM SN_id_smime_alg_CMSRC2wrap}
  SN_id_smime_alg_CMSRC2wrap = 'id-smime-alg-CMSRC2wrap';
  {$EXTERNALSYM NID_id_smime_alg_CMSRC2wrap}
  NID_id_smime_alg_CMSRC2wrap = 247;

  {$EXTERNALSYM SN_id_alg_PWRI_KEK}
  SN_id_alg_PWRI_KEK = 'id-alg-PWRI-KEK';
  {$EXTERNALSYM NID_id_alg_PWRI_KEK}
  NID_id_alg_PWRI_KEK = 893;

  {$EXTERNALSYM SN_id_smime_cd_ldap}
  SN_id_smime_cd_ldap = 'id-smime-cd-ldap';
  {$EXTERNALSYM NID_id_smime_cd_ldap}
  NID_id_smime_cd_ldap = 248;

  {$EXTERNALSYM SN_id_smime_spq_ets_sqt_uri}
  SN_id_smime_spq_ets_sqt_uri = 'id-smime-spq-ets-sqt-uri';
  {$EXTERNALSYM NID_id_smime_spq_ets_sqt_uri}
  NID_id_smime_spq_ets_sqt_uri = 249;

  {$EXTERNALSYM SN_id_smime_spq_ets_sqt_unotice}
  SN_id_smime_spq_ets_sqt_unotice = 'id-smime-spq-ets-sqt-unotice';
  {$EXTERNALSYM NID_id_smime_spq_ets_sqt_unotice}
  NID_id_smime_spq_ets_sqt_unotice = 250;

  {$EXTERNALSYM SN_id_smime_cti_ets_proofOfOrigin}
  SN_id_smime_cti_ets_proofOfOrigin = 'id-smime-cti-ets-proofOfOrigin';
  {$EXTERNALSYM NID_id_smime_cti_ets_proofOfOrigin}
  NID_id_smime_cti_ets_proofOfOrigin = 251;

  {$EXTERNALSYM SN_id_smime_cti_ets_proofOfReceipt}
  SN_id_smime_cti_ets_proofOfReceipt = 'id-smime-cti-ets-proofOfReceipt';
  {$EXTERNALSYM NID_id_smime_cti_ets_proofOfReceipt}
  NID_id_smime_cti_ets_proofOfReceipt = 252;

  {$EXTERNALSYM SN_id_smime_cti_ets_proofOfDelivery}
  SN_id_smime_cti_ets_proofOfDelivery = 'id-smime-cti-ets-proofOfDelivery';
  {$EXTERNALSYM NID_id_smime_cti_ets_proofOfDelivery}
  NID_id_smime_cti_ets_proofOfDelivery = 253;

  {$EXTERNALSYM SN_id_smime_cti_ets_proofOfSender}
  SN_id_smime_cti_ets_proofOfSender = 'id-smime-cti-ets-proofOfSender';
  {$EXTERNALSYM NID_id_smime_cti_ets_proofOfSender}
  NID_id_smime_cti_ets_proofOfSender = 254;

  {$EXTERNALSYM SN_id_smime_cti_ets_proofOfApproval}
  SN_id_smime_cti_ets_proofOfApproval = 'id-smime-cti-ets-proofOfApproval';
  {$EXTERNALSYM NID_id_smime_cti_ets_proofOfApproval}
  NID_id_smime_cti_ets_proofOfApproval = 255;

  {$EXTERNALSYM SN_id_smime_cti_ets_proofOfCreation}
  SN_id_smime_cti_ets_proofOfCreation = 'id-smime-cti-ets-proofOfCreation';
  {$EXTERNALSYM NID_id_smime_cti_ets_proofOfCreation}
  NID_id_smime_cti_ets_proofOfCreation = 256;

  {$EXTERNALSYM LN_friendlyName}
  LN_friendlyName = 'friendlyName';
  {$EXTERNALSYM NID_friendlyName}
  NID_friendlyName = 156;

  {$EXTERNALSYM LN_localKeyID}
  LN_localKeyID = 'localKeyID';
  {$EXTERNALSYM NID_localKeyID}
  NID_localKeyID = 157;

  {$EXTERNALSYM SN_ms_csp_name}
  SN_ms_csp_name = 'CSPName';
  {$EXTERNALSYM LN_ms_csp_name}
  LN_ms_csp_name = 'Microsoft CSP Name';
  {$EXTERNALSYM NID_ms_csp_name}
  NID_ms_csp_name = 417;

  {$EXTERNALSYM SN_LocalKeySet}
  SN_LocalKeySet = 'LocalKeySet';
  {$EXTERNALSYM LN_LocalKeySet}
  LN_LocalKeySet = 'Microsoft Local Key set';
  {$EXTERNALSYM NID_LocalKeySet}
  NID_LocalKeySet = 856;

  {$EXTERNALSYM LN_x509Certificate}
  LN_x509Certificate = 'x509Certificate';
  {$EXTERNALSYM NID_x509Certificate}
  NID_x509Certificate = 158;

  {$EXTERNALSYM LN_sdsiCertificate}
  LN_sdsiCertificate = 'sdsiCertificate';
  {$EXTERNALSYM NID_sdsiCertificate}
  NID_sdsiCertificate = 159;

  {$EXTERNALSYM LN_x509Crl}
  LN_x509Crl = 'x509Crl';
  {$EXTERNALSYM NID_x509Crl}
  NID_x509Crl = 160;

  {$EXTERNALSYM SN_pbe_WithSHA1And128BitRC4}
  SN_pbe_WithSHA1And128BitRC4 = 'PBE-SHA1-RC4-128';
  {$EXTERNALSYM LN_pbe_WithSHA1And128BitRC4}
  LN_pbe_WithSHA1And128BitRC4 = 'pbeWithSHA1And128BitRC4';
  {$EXTERNALSYM NID_pbe_WithSHA1And128BitRC4}
  NID_pbe_WithSHA1And128BitRC4 = 144;

  {$EXTERNALSYM SN_pbe_WithSHA1And40BitRC4}
  SN_pbe_WithSHA1And40BitRC4 = 'PBE-SHA1-RC4-40';
  {$EXTERNALSYM LN_pbe_WithSHA1And40BitRC4}
  LN_pbe_WithSHA1And40BitRC4 = 'pbeWithSHA1And40BitRC4';
  {$EXTERNALSYM NID_pbe_WithSHA1And40BitRC4}
  NID_pbe_WithSHA1And40BitRC4 = 145;

  {$EXTERNALSYM SN_pbe_WithSHA1And3_Key_TripleDES_CBC}
  SN_pbe_WithSHA1And3_Key_TripleDES_CBC = 'PBE-SHA1-3DES';
  {$EXTERNALSYM LN_pbe_WithSHA1And3_Key_TripleDES_CBC}
  LN_pbe_WithSHA1And3_Key_TripleDES_CBC = 'pbeWithSHA1And3-KeyTripleDES-CBC';
  {$EXTERNALSYM NID_pbe_WithSHA1And3_Key_TripleDES_CBC}
  NID_pbe_WithSHA1And3_Key_TripleDES_CBC = 146;

  {$EXTERNALSYM SN_pbe_WithSHA1And2_Key_TripleDES_CBC}
  SN_pbe_WithSHA1And2_Key_TripleDES_CBC = 'PBE-SHA1-2DES';
  {$EXTERNALSYM LN_pbe_WithSHA1And2_Key_TripleDES_CBC}
  LN_pbe_WithSHA1And2_Key_TripleDES_CBC = 'pbeWithSHA1And2-KeyTripleDES-CBC';
  {$EXTERNALSYM NID_pbe_WithSHA1And2_Key_TripleDES_CBC}
  NID_pbe_WithSHA1And2_Key_TripleDES_CBC = 147;

  {$EXTERNALSYM SN_pbe_WithSHA1And128BitRC2_CBC}
  SN_pbe_WithSHA1And128BitRC2_CBC = 'PBE-SHA1-RC2-128';
  {$EXTERNALSYM LN_pbe_WithSHA1And128BitRC2_CBC}
  LN_pbe_WithSHA1And128BitRC2_CBC = 'pbeWithSHA1And128BitRC2-CBC';
  {$EXTERNALSYM NID_pbe_WithSHA1And128BitRC2_CBC}
  NID_pbe_WithSHA1And128BitRC2_CBC = 148;

  {$EXTERNALSYM SN_pbe_WithSHA1And40BitRC2_CBC}
  SN_pbe_WithSHA1And40BitRC2_CBC = 'PBE-SHA1-RC2-40';
  {$EXTERNALSYM LN_pbe_WithSHA1And40BitRC2_CBC}
  LN_pbe_WithSHA1And40BitRC2_CBC = 'pbeWithSHA1And40BitRC2-CBC';
  {$EXTERNALSYM NID_pbe_WithSHA1And40BitRC2_CBC}
  NID_pbe_WithSHA1And40BitRC2_CBC = 149;

  {$EXTERNALSYM LN_keyBag}
  LN_keyBag = 'keyBag';
  {$EXTERNALSYM NID_keyBag}
  NID_keyBag = 150;

  {$EXTERNALSYM LN_pkcs8ShroudedKeyBag}
  LN_pkcs8ShroudedKeyBag = 'pkcs8ShroudedKeyBag';
  {$EXTERNALSYM NID_pkcs8ShroudedKeyBag}
  NID_pkcs8ShroudedKeyBag = 151;

  {$EXTERNALSYM LN_certBag}
  LN_certBag = 'certBag';
  {$EXTERNALSYM NID_certBag}
  NID_certBag = 152;

  {$EXTERNALSYM LN_crlBag}
  LN_crlBag = 'crlBag';
  {$EXTERNALSYM NID_crlBag}
  NID_crlBag = 153;

  {$EXTERNALSYM LN_secretBag}
  LN_secretBag = 'secretBag';
  {$EXTERNALSYM NID_secretBag}
  NID_secretBag = 154;

  {$EXTERNALSYM LN_safeContentsBag}
  LN_safeContentsBag = 'safeContentsBag';
  {$EXTERNALSYM NID_safeContentsBag}
  NID_safeContentsBag = 155;

  {$EXTERNALSYM SN_md2}
  SN_md2 = 'MD2';
  {$EXTERNALSYM LN_md2}
  LN_md2 = 'md2';
  {$EXTERNALSYM NID_md2}
  NID_md2 = 3;

  {$EXTERNALSYM SN_md4}
  SN_md4 = 'MD4';
  {$EXTERNALSYM LN_md4}
  LN_md4 = 'md4';
  {$EXTERNALSYM NID_md4}
  NID_md4 = 257;

  {$EXTERNALSYM SN_md5}
  SN_md5 = 'MD5';
  {$EXTERNALSYM LN_md5}
  LN_md5 = 'md5';
  {$EXTERNALSYM NID_md5}
  NID_md5 = 4;

  {$EXTERNALSYM SN_md5_sha1}
  SN_md5_sha1 = 'MD5-SHA1';
  {$EXTERNALSYM LN_md5_sha1}
  LN_md5_sha1 = 'md5-sha1';
  {$EXTERNALSYM NID_md5_sha1}
  NID_md5_sha1 = 114;

  {$EXTERNALSYM LN_hmacWithMD5}
  LN_hmacWithMD5 = 'hmacWithMD5';
  {$EXTERNALSYM NID_hmacWithMD5}
  NID_hmacWithMD5 = 797;

  {$EXTERNALSYM LN_hmacWithSHA1}
  LN_hmacWithSHA1 = 'hmacWithSHA1';
  {$EXTERNALSYM NID_hmacWithSHA1}
  NID_hmacWithSHA1 = 163;

  {$EXTERNALSYM SN_sm2}
  SN_sm2 = 'SM2';
  {$EXTERNALSYM LN_sm2}
  LN_sm2 = 'sm2';
  {$EXTERNALSYM NID_sm2}
  NID_sm2 = 1172;

  {$EXTERNALSYM SN_sm3}
  SN_sm3 = 'SM3';
  {$EXTERNALSYM LN_sm3}
  LN_sm3 = 'sm3';
  {$EXTERNALSYM NID_sm3}
  NID_sm3 = 1143;

  {$EXTERNALSYM SN_sm3WithRSAEncryption}
  SN_sm3WithRSAEncryption = 'RSA-SM3';
  {$EXTERNALSYM LN_sm3WithRSAEncryption}
  LN_sm3WithRSAEncryption = 'sm3WithRSAEncryption';
  {$EXTERNALSYM NID_sm3WithRSAEncryption}
  NID_sm3WithRSAEncryption = 1144;

  {$EXTERNALSYM LN_hmacWithSHA224}
  LN_hmacWithSHA224 = 'hmacWithSHA224';
  {$EXTERNALSYM NID_hmacWithSHA224}
  NID_hmacWithSHA224 = 798;

  {$EXTERNALSYM LN_hmacWithSHA256}
  LN_hmacWithSHA256 = 'hmacWithSHA256';
  {$EXTERNALSYM NID_hmacWithSHA256}
  NID_hmacWithSHA256 = 799;

  {$EXTERNALSYM LN_hmacWithSHA384}
  LN_hmacWithSHA384 = 'hmacWithSHA384';
  {$EXTERNALSYM NID_hmacWithSHA384}
  NID_hmacWithSHA384 = 800;

  {$EXTERNALSYM LN_hmacWithSHA512}
  LN_hmacWithSHA512 = 'hmacWithSHA512';
  {$EXTERNALSYM NID_hmacWithSHA512}
  NID_hmacWithSHA512 = 801;

  {$EXTERNALSYM LN_hmacWithSHA512_224}
  LN_hmacWithSHA512_224 = 'hmacWithSHA512-224';
  {$EXTERNALSYM NID_hmacWithSHA512_224}
  NID_hmacWithSHA512_224 = 1193;

  {$EXTERNALSYM LN_hmacWithSHA512_256}
  LN_hmacWithSHA512_256 = 'hmacWithSHA512-256';
  {$EXTERNALSYM NID_hmacWithSHA512_256}
  NID_hmacWithSHA512_256 = 1194;

  {$EXTERNALSYM SN_rc2_cbc}
  SN_rc2_cbc = 'RC2-CBC';
  {$EXTERNALSYM LN_rc2_cbc}
  LN_rc2_cbc = 'rc2-cbc';
  {$EXTERNALSYM NID_rc2_cbc}
  NID_rc2_cbc = 37;

  {$EXTERNALSYM SN_rc2_ecb}
  SN_rc2_ecb = 'RC2-ECB';
  {$EXTERNALSYM LN_rc2_ecb}
  LN_rc2_ecb = 'rc2-ecb';
  {$EXTERNALSYM NID_rc2_ecb}
  NID_rc2_ecb = 38;

  {$EXTERNALSYM SN_rc2_cfb64}
  SN_rc2_cfb64 = 'RC2-CFB';
  {$EXTERNALSYM LN_rc2_cfb64}
  LN_rc2_cfb64 = 'rc2-cfb';
  {$EXTERNALSYM NID_rc2_cfb64}
  NID_rc2_cfb64 = 39;

  {$EXTERNALSYM SN_rc2_ofb64}
  SN_rc2_ofb64 = 'RC2-OFB';
  {$EXTERNALSYM LN_rc2_ofb64}
  LN_rc2_ofb64 = 'rc2-ofb';
  {$EXTERNALSYM NID_rc2_ofb64}
  NID_rc2_ofb64 = 40;

  {$EXTERNALSYM SN_rc2_40_cbc}
  SN_rc2_40_cbc = 'RC2-40-CBC';
  {$EXTERNALSYM LN_rc2_40_cbc}
  LN_rc2_40_cbc = 'rc2-40-cbc';
  {$EXTERNALSYM NID_rc2_40_cbc}
  NID_rc2_40_cbc = 98;

  {$EXTERNALSYM SN_rc2_64_cbc}
  SN_rc2_64_cbc = 'RC2-64-CBC';
  {$EXTERNALSYM LN_rc2_64_cbc}
  LN_rc2_64_cbc = 'rc2-64-cbc';
  {$EXTERNALSYM NID_rc2_64_cbc}
  NID_rc2_64_cbc = 166;

  {$EXTERNALSYM SN_rc4}
  SN_rc4 = 'RC4';
  {$EXTERNALSYM LN_rc4}
  LN_rc4 = 'rc4';
  {$EXTERNALSYM NID_rc4}
  NID_rc4 = 5;

  {$EXTERNALSYM SN_rc4_40}
  SN_rc4_40 = 'RC4-40';
  {$EXTERNALSYM LN_rc4_40}
  LN_rc4_40 = 'rc4-40';
  {$EXTERNALSYM NID_rc4_40}
  NID_rc4_40 = 97;

  {$EXTERNALSYM SN_des_ede3_cbc}
  SN_des_ede3_cbc = 'DES-EDE3-CBC';
  {$EXTERNALSYM LN_des_ede3_cbc}
  LN_des_ede3_cbc = 'des-ede3-cbc';
  {$EXTERNALSYM NID_des_ede3_cbc}
  NID_des_ede3_cbc = 44;

  {$EXTERNALSYM SN_rc5_cbc}
  SN_rc5_cbc = 'RC5-CBC';
  {$EXTERNALSYM LN_rc5_cbc}
  LN_rc5_cbc = 'rc5-cbc';
  {$EXTERNALSYM NID_rc5_cbc}
  NID_rc5_cbc = 120;

  {$EXTERNALSYM SN_rc5_ecb}
  SN_rc5_ecb = 'RC5-ECB';
  {$EXTERNALSYM LN_rc5_ecb}
  LN_rc5_ecb = 'rc5-ecb';
  {$EXTERNALSYM NID_rc5_ecb}
  NID_rc5_ecb = 121;

  {$EXTERNALSYM SN_rc5_cfb64}
  SN_rc5_cfb64 = 'RC5-CFB';
  {$EXTERNALSYM LN_rc5_cfb64}
  LN_rc5_cfb64 = 'rc5-cfb';
  {$EXTERNALSYM NID_rc5_cfb64}
  NID_rc5_cfb64 = 122;

  {$EXTERNALSYM SN_rc5_ofb64}
  SN_rc5_ofb64 = 'RC5-OFB';
  {$EXTERNALSYM LN_rc5_ofb64}
  LN_rc5_ofb64 = 'rc5-ofb';
  {$EXTERNALSYM NID_rc5_ofb64}
  NID_rc5_ofb64 = 123;

  {$EXTERNALSYM SN_ms_ext_req}
  SN_ms_ext_req = 'msExtReq';
  {$EXTERNALSYM LN_ms_ext_req}
  LN_ms_ext_req = 'Microsoft Extension Request';
  {$EXTERNALSYM NID_ms_ext_req}
  NID_ms_ext_req = 171;

  {$EXTERNALSYM SN_ms_code_ind}
  SN_ms_code_ind = 'msCodeInd';
  {$EXTERNALSYM LN_ms_code_ind}
  LN_ms_code_ind = 'Microsoft Individual Code Signing';
  {$EXTERNALSYM NID_ms_code_ind}
  NID_ms_code_ind = 134;

  {$EXTERNALSYM SN_ms_code_com}
  SN_ms_code_com = 'msCodeCom';
  {$EXTERNALSYM LN_ms_code_com}
  LN_ms_code_com = 'Microsoft Commercial Code Signing';
  {$EXTERNALSYM NID_ms_code_com}
  NID_ms_code_com = 135;

  {$EXTERNALSYM SN_ms_ctl_sign}
  SN_ms_ctl_sign = 'msCTLSign';
  {$EXTERNALSYM LN_ms_ctl_sign}
  LN_ms_ctl_sign = 'Microsoft Trust List Signing';
  {$EXTERNALSYM NID_ms_ctl_sign}
  NID_ms_ctl_sign = 136;

  {$EXTERNALSYM SN_ms_sgc}
  SN_ms_sgc = 'msSGC';
  {$EXTERNALSYM LN_ms_sgc}
  LN_ms_sgc = 'Microsoft Server Gated Crypto';
  {$EXTERNALSYM NID_ms_sgc}
  NID_ms_sgc = 137;

  {$EXTERNALSYM SN_ms_efs}
  SN_ms_efs = 'msEFS';
  {$EXTERNALSYM LN_ms_efs}
  LN_ms_efs = 'Microsoft Encrypted File System';
  {$EXTERNALSYM NID_ms_efs}
  NID_ms_efs = 138;

  {$EXTERNALSYM SN_ms_smartcard_login}
  SN_ms_smartcard_login = 'msSmartcardLogin';
  {$EXTERNALSYM LN_ms_smartcard_login}
  LN_ms_smartcard_login = 'Microsoft Smartcard Login';
  {$EXTERNALSYM NID_ms_smartcard_login}
  NID_ms_smartcard_login = 648;

  {$EXTERNALSYM SN_ms_upn}
  SN_ms_upn = 'msUPN';
  {$EXTERNALSYM LN_ms_upn}
  LN_ms_upn = 'Microsoft User Principal Name';
  {$EXTERNALSYM NID_ms_upn}
  NID_ms_upn = 649;

  {$EXTERNALSYM SN_idea_cbc}
  SN_idea_cbc = 'IDEA-CBC';
  {$EXTERNALSYM LN_idea_cbc}
  LN_idea_cbc = 'idea-cbc';
  {$EXTERNALSYM NID_idea_cbc}
  NID_idea_cbc = 34;

  {$EXTERNALSYM SN_idea_ecb}
  SN_idea_ecb = 'IDEA-ECB';
  {$EXTERNALSYM LN_idea_ecb}
  LN_idea_ecb = 'idea-ecb';
  {$EXTERNALSYM NID_idea_ecb}
  NID_idea_ecb = 36;

  {$EXTERNALSYM SN_idea_cfb64}
  SN_idea_cfb64 = 'IDEA-CFB';
  {$EXTERNALSYM LN_idea_cfb64}
  LN_idea_cfb64 = 'idea-cfb';
  {$EXTERNALSYM NID_idea_cfb64}
  NID_idea_cfb64 = 35;

  {$EXTERNALSYM SN_idea_ofb64}
  SN_idea_ofb64 = 'IDEA-OFB';
  {$EXTERNALSYM LN_idea_ofb64}
  LN_idea_ofb64 = 'idea-ofb';
  {$EXTERNALSYM NID_idea_ofb64}
  NID_idea_ofb64 = 46;

  {$EXTERNALSYM SN_bf_cbc}
  SN_bf_cbc = 'BF-CBC';
  {$EXTERNALSYM LN_bf_cbc}
  LN_bf_cbc = 'bf-cbc';
  {$EXTERNALSYM NID_bf_cbc}
  NID_bf_cbc = 91;

  {$EXTERNALSYM SN_bf_ecb}
  SN_bf_ecb = 'BF-ECB';
  {$EXTERNALSYM LN_bf_ecb}
  LN_bf_ecb = 'bf-ecb';
  {$EXTERNALSYM NID_bf_ecb}
  NID_bf_ecb = 92;

  {$EXTERNALSYM SN_bf_cfb64}
  SN_bf_cfb64 = 'BF-CFB';
  {$EXTERNALSYM LN_bf_cfb64}
  LN_bf_cfb64 = 'bf-cfb';
  {$EXTERNALSYM NID_bf_cfb64}
  NID_bf_cfb64 = 93;

  {$EXTERNALSYM SN_bf_ofb64}
  SN_bf_ofb64 = 'BF-OFB';
  {$EXTERNALSYM LN_bf_ofb64}
  LN_bf_ofb64 = 'bf-ofb';
  {$EXTERNALSYM NID_bf_ofb64}
  NID_bf_ofb64 = 94;

  {$EXTERNALSYM SN_id_pkix}
  SN_id_pkix = 'PKIX';
  {$EXTERNALSYM NID_id_pkix}
  NID_id_pkix = 127;

  {$EXTERNALSYM SN_id_pkix_mod}
  SN_id_pkix_mod = 'id-pkix-mod';
  {$EXTERNALSYM NID_id_pkix_mod}
  NID_id_pkix_mod = 258;

  {$EXTERNALSYM SN_id_pe}
  SN_id_pe = 'id-pe';
  {$EXTERNALSYM NID_id_pe}
  NID_id_pe = 175;

  {$EXTERNALSYM SN_id_qt}
  SN_id_qt = 'id-qt';
  {$EXTERNALSYM NID_id_qt}
  NID_id_qt = 259;

  {$EXTERNALSYM SN_id_kp}
  SN_id_kp = 'id-kp';
  {$EXTERNALSYM NID_id_kp}
  NID_id_kp = 128;

  {$EXTERNALSYM SN_id_it}
  SN_id_it = 'id-it';
  {$EXTERNALSYM NID_id_it}
  NID_id_it = 260;

  {$EXTERNALSYM SN_id_pkip}
  SN_id_pkip = 'id-pkip';
  {$EXTERNALSYM NID_id_pkip}
  NID_id_pkip = 261;

  {$EXTERNALSYM SN_id_alg}
  SN_id_alg = 'id-alg';
  {$EXTERNALSYM NID_id_alg}
  NID_id_alg = 262;

  {$EXTERNALSYM SN_id_cmc}
  SN_id_cmc = 'id-cmc';
  {$EXTERNALSYM NID_id_cmc}
  NID_id_cmc = 263;

  {$EXTERNALSYM SN_id_on}
  SN_id_on = 'id-on';
  {$EXTERNALSYM NID_id_on}
  NID_id_on = 264;

  {$EXTERNALSYM SN_id_pda}
  SN_id_pda = 'id-pda';
  {$EXTERNALSYM NID_id_pda}
  NID_id_pda = 265;

  {$EXTERNALSYM SN_id_aca}
  SN_id_aca = 'id-aca';
  {$EXTERNALSYM NID_id_aca}
  NID_id_aca = 266;

  {$EXTERNALSYM SN_id_qcs}
  SN_id_qcs = 'id-qcs';
  {$EXTERNALSYM NID_id_qcs}
  NID_id_qcs = 267;

  {$EXTERNALSYM SN_id_cct}
  SN_id_cct = 'id-cct';
  {$EXTERNALSYM NID_id_cct}
  NID_id_cct = 268;

  {$EXTERNALSYM SN_id_ppl}
  SN_id_ppl = 'id-ppl';
  {$EXTERNALSYM NID_id_ppl}
  NID_id_ppl = 662;

  {$EXTERNALSYM SN_id_ad}
  SN_id_ad = 'id-ad';
  {$EXTERNALSYM NID_id_ad}
  NID_id_ad = 176;

  {$EXTERNALSYM SN_id_pkix1_explicit_88}
  SN_id_pkix1_explicit_88 = 'id-pkix1-explicit-88';
  {$EXTERNALSYM NID_id_pkix1_explicit_88}
  NID_id_pkix1_explicit_88 = 269;

  {$EXTERNALSYM SN_id_pkix1_implicit_88}
  SN_id_pkix1_implicit_88 = 'id-pkix1-implicit-88';
  {$EXTERNALSYM NID_id_pkix1_implicit_88}
  NID_id_pkix1_implicit_88 = 270;

  {$EXTERNALSYM SN_id_pkix1_explicit_93}
  SN_id_pkix1_explicit_93 = 'id-pkix1-explicit-93';
  {$EXTERNALSYM NID_id_pkix1_explicit_93}
  NID_id_pkix1_explicit_93 = 271;

  {$EXTERNALSYM SN_id_pkix1_implicit_93}
  SN_id_pkix1_implicit_93 = 'id-pkix1-implicit-93';
  {$EXTERNALSYM NID_id_pkix1_implicit_93}
  NID_id_pkix1_implicit_93 = 272;

  {$EXTERNALSYM SN_id_mod_crmf}
  SN_id_mod_crmf = 'id-mod-crmf';
  {$EXTERNALSYM NID_id_mod_crmf}
  NID_id_mod_crmf = 273;

  {$EXTERNALSYM SN_id_mod_cmc}
  SN_id_mod_cmc = 'id-mod-cmc';
  {$EXTERNALSYM NID_id_mod_cmc}
  NID_id_mod_cmc = 274;

  {$EXTERNALSYM SN_id_mod_kea_profile_88}
  SN_id_mod_kea_profile_88 = 'id-mod-kea-profile-88';
  {$EXTERNALSYM NID_id_mod_kea_profile_88}
  NID_id_mod_kea_profile_88 = 275;

  {$EXTERNALSYM SN_id_mod_kea_profile_93}
  SN_id_mod_kea_profile_93 = 'id-mod-kea-profile-93';
  {$EXTERNALSYM NID_id_mod_kea_profile_93}
  NID_id_mod_kea_profile_93 = 276;

  {$EXTERNALSYM SN_id_mod_cmp}
  SN_id_mod_cmp = 'id-mod-cmp';
  {$EXTERNALSYM NID_id_mod_cmp}
  NID_id_mod_cmp = 277;

  {$EXTERNALSYM SN_id_mod_qualified_cert_88}
  SN_id_mod_qualified_cert_88 = 'id-mod-qualified-cert-88';
  {$EXTERNALSYM NID_id_mod_qualified_cert_88}
  NID_id_mod_qualified_cert_88 = 278;

  {$EXTERNALSYM SN_id_mod_qualified_cert_93}
  SN_id_mod_qualified_cert_93 = 'id-mod-qualified-cert-93';
  {$EXTERNALSYM NID_id_mod_qualified_cert_93}
  NID_id_mod_qualified_cert_93 = 279;

  {$EXTERNALSYM SN_id_mod_attribute_cert}
  SN_id_mod_attribute_cert = 'id-mod-attribute-cert';
  {$EXTERNALSYM NID_id_mod_attribute_cert}
  NID_id_mod_attribute_cert = 280;

  {$EXTERNALSYM SN_id_mod_timestamp_protocol}
  SN_id_mod_timestamp_protocol = 'id-mod-timestamp-protocol';
  {$EXTERNALSYM NID_id_mod_timestamp_protocol}
  NID_id_mod_timestamp_protocol = 281;

  {$EXTERNALSYM SN_id_mod_ocsp}
  SN_id_mod_ocsp = 'id-mod-ocsp';
  {$EXTERNALSYM NID_id_mod_ocsp}
  NID_id_mod_ocsp = 282;

  {$EXTERNALSYM SN_id_mod_dvcs}
  SN_id_mod_dvcs = 'id-mod-dvcs';
  {$EXTERNALSYM NID_id_mod_dvcs}
  NID_id_mod_dvcs = 283;

  {$EXTERNALSYM SN_id_mod_cmp2000}
  SN_id_mod_cmp2000 = 'id-mod-cmp2000';
  {$EXTERNALSYM NID_id_mod_cmp2000}
  NID_id_mod_cmp2000 = 284;

  {$EXTERNALSYM SN_info_access}
  SN_info_access = 'authorityInfoAccess';
  {$EXTERNALSYM LN_info_access}
  LN_info_access = 'Authority Information Access';
  {$EXTERNALSYM NID_info_access}
  NID_info_access = 177;

  {$EXTERNALSYM SN_biometricInfo}
  SN_biometricInfo = 'biometricInfo';
  {$EXTERNALSYM LN_biometricInfo}
  LN_biometricInfo = 'Biometric Info';
  {$EXTERNALSYM NID_biometricInfo}
  NID_biometricInfo = 285;

  {$EXTERNALSYM SN_qcStatements}
  SN_qcStatements = 'qcStatements';
  {$EXTERNALSYM NID_qcStatements}
  NID_qcStatements = 286;

  {$EXTERNALSYM SN_ac_auditEntity}
  SN_ac_auditEntity = 'ac-auditEntity';
  {$EXTERNALSYM NID_ac_auditEntity}
  NID_ac_auditEntity = 287;

  {$EXTERNALSYM SN_ac_targeting}
  SN_ac_targeting = 'ac-targeting';
  {$EXTERNALSYM NID_ac_targeting}
  NID_ac_targeting = 288;

  {$EXTERNALSYM SN_aaControls}
  SN_aaControls = 'aaControls';
  {$EXTERNALSYM NID_aaControls}
  NID_aaControls = 289;

  {$EXTERNALSYM SN_sbgp_ipAddrBlock}
  SN_sbgp_ipAddrBlock = 'sbgp-ipAddrBlock';
  {$EXTERNALSYM NID_sbgp_ipAddrBlock}
  NID_sbgp_ipAddrBlock = 290;

  {$EXTERNALSYM SN_sbgp_autonomousSysNum}
  SN_sbgp_autonomousSysNum = 'sbgp-autonomousSysNum';
  {$EXTERNALSYM NID_sbgp_autonomousSysNum}
  NID_sbgp_autonomousSysNum = 291;

  {$EXTERNALSYM SN_sbgp_routerIdentifier}
  SN_sbgp_routerIdentifier = 'sbgp-routerIdentifier';
  {$EXTERNALSYM NID_sbgp_routerIdentifier}
  NID_sbgp_routerIdentifier = 292;

  {$EXTERNALSYM SN_ac_proxying}
  SN_ac_proxying = 'ac-proxying';
  {$EXTERNALSYM NID_ac_proxying}
  NID_ac_proxying = 397;

  {$EXTERNALSYM SN_sinfo_access}
  SN_sinfo_access = 'subjectInfoAccess';
  {$EXTERNALSYM LN_sinfo_access}
  LN_sinfo_access = 'Subject Information Access';
  {$EXTERNALSYM NID_sinfo_access}
  NID_sinfo_access = 398;

  {$EXTERNALSYM SN_proxyCertInfo}
  SN_proxyCertInfo = 'proxyCertInfo';
  {$EXTERNALSYM LN_proxyCertInfo}
  LN_proxyCertInfo = 'Proxy Certificate Information';
  {$EXTERNALSYM NID_proxyCertInfo}
  NID_proxyCertInfo = 663;

  {$EXTERNALSYM SN_tlsfeature}
  SN_tlsfeature = 'tlsfeature';
  {$EXTERNALSYM LN_tlsfeature}
  LN_tlsfeature = 'TLS Feature';
  {$EXTERNALSYM NID_tlsfeature}
  NID_tlsfeature = 1020;

  {$EXTERNALSYM SN_id_qt_cps}
  SN_id_qt_cps = 'id-qt-cps';
  {$EXTERNALSYM LN_id_qt_cps}
  LN_id_qt_cps = 'Policy Qualifier CPS';
  {$EXTERNALSYM NID_id_qt_cps}
  NID_id_qt_cps = 164;

  {$EXTERNALSYM SN_id_qt_unotice}
  SN_id_qt_unotice = 'id-qt-unotice';
  {$EXTERNALSYM LN_id_qt_unotice}
  LN_id_qt_unotice = 'Policy Qualifier User Notice';
  {$EXTERNALSYM NID_id_qt_unotice}
  NID_id_qt_unotice = 165;

  {$EXTERNALSYM SN_textNotice}
  SN_textNotice = 'textNotice';
  {$EXTERNALSYM NID_textNotice}
  NID_textNotice = 293;

  {$EXTERNALSYM SN_server_auth}
  SN_server_auth = 'serverAuth';
  {$EXTERNALSYM LN_server_auth}
  LN_server_auth = 'TLS Web Server Authentication';
  {$EXTERNALSYM NID_server_auth}
  NID_server_auth = 129;

  {$EXTERNALSYM SN_client_auth}
  SN_client_auth = 'clientAuth';
  {$EXTERNALSYM LN_client_auth}
  LN_client_auth = 'TLS Web Client Authentication';
  {$EXTERNALSYM NID_client_auth}
  NID_client_auth = 130;

  {$EXTERNALSYM SN_code_sign}
  SN_code_sign = 'codeSigning';
  {$EXTERNALSYM LN_code_sign}
  LN_code_sign = 'Code Signing';
  {$EXTERNALSYM NID_code_sign}
  NID_code_sign = 131;

  {$EXTERNALSYM SN_email_protect}
  SN_email_protect = 'emailProtection';
  {$EXTERNALSYM LN_email_protect}
  LN_email_protect = 'E-mail Protection';
  {$EXTERNALSYM NID_email_protect}
  NID_email_protect = 132;

  {$EXTERNALSYM SN_ipsecEndSystem}
  SN_ipsecEndSystem = 'ipsecEndSystem';
  {$EXTERNALSYM LN_ipsecEndSystem}
  LN_ipsecEndSystem = 'IPSec End System';
  {$EXTERNALSYM NID_ipsecEndSystem}
  NID_ipsecEndSystem = 294;

  {$EXTERNALSYM SN_ipsecTunnel}
  SN_ipsecTunnel = 'ipsecTunnel';
  {$EXTERNALSYM LN_ipsecTunnel}
  LN_ipsecTunnel = 'IPSec Tunnel';
  {$EXTERNALSYM NID_ipsecTunnel}
  NID_ipsecTunnel = 295;

  {$EXTERNALSYM SN_ipsecUser}
  SN_ipsecUser = 'ipsecUser';
  {$EXTERNALSYM LN_ipsecUser}
  LN_ipsecUser = 'IPSec User';
  {$EXTERNALSYM NID_ipsecUser}
  NID_ipsecUser = 296;

  {$EXTERNALSYM SN_time_stamp}
  SN_time_stamp = 'timeStamping';
  {$EXTERNALSYM LN_time_stamp}
  LN_time_stamp = 'Time Stamping';
  {$EXTERNALSYM NID_time_stamp}
  NID_time_stamp = 133;

  {$EXTERNALSYM SN_OCSP_sign}
  SN_OCSP_sign = 'OCSPSigning';
  {$EXTERNALSYM LN_OCSP_sign}
  LN_OCSP_sign = 'OCSP Signing';
  {$EXTERNALSYM NID_OCSP_sign}
  NID_OCSP_sign = 180;

  {$EXTERNALSYM SN_dvcs}
  SN_dvcs = 'DVCS';
  {$EXTERNALSYM LN_dvcs}
  LN_dvcs = 'dvcs';
  {$EXTERNALSYM NID_dvcs}
  NID_dvcs = 297;

  {$EXTERNALSYM SN_ipsec_IKE}
  SN_ipsec_IKE = 'ipsecIKE';
  {$EXTERNALSYM LN_ipsec_IKE}
  LN_ipsec_IKE = 'ipsec Internet Key Exchange';
  {$EXTERNALSYM NID_ipsec_IKE}
  NID_ipsec_IKE = 1022;

  {$EXTERNALSYM SN_capwapAC}
  SN_capwapAC = 'capwapAC';
  {$EXTERNALSYM LN_capwapAC}
  LN_capwapAC = 'Ctrl/provision WAP Access';
  {$EXTERNALSYM NID_capwapAC}
  NID_capwapAC = 1023;

  {$EXTERNALSYM SN_capwapWTP}
  SN_capwapWTP = 'capwapWTP';
  {$EXTERNALSYM LN_capwapWTP}
  LN_capwapWTP = 'Ctrl/Provision WAP Termination';
  {$EXTERNALSYM NID_capwapWTP}
  NID_capwapWTP = 1024;

  {$EXTERNALSYM SN_sshClient}
  SN_sshClient = 'secureShellClient';
  {$EXTERNALSYM LN_sshClient}
  LN_sshClient = 'SSH Client';
  {$EXTERNALSYM NID_sshClient}
  NID_sshClient = 1025;

  {$EXTERNALSYM SN_sshServer}
  SN_sshServer = 'secureShellServer';
  {$EXTERNALSYM LN_sshServer}
  LN_sshServer = 'SSH Server';
  {$EXTERNALSYM NID_sshServer}
  NID_sshServer = 1026;

  {$EXTERNALSYM SN_sendRouter}
  SN_sendRouter = 'sendRouter';
  {$EXTERNALSYM LN_sendRouter}
  LN_sendRouter = 'Send Router';
  {$EXTERNALSYM NID_sendRouter}
  NID_sendRouter = 1027;

  {$EXTERNALSYM SN_sendProxiedRouter}
  SN_sendProxiedRouter = 'sendProxiedRouter';
  {$EXTERNALSYM LN_sendProxiedRouter}
  LN_sendProxiedRouter = 'Send Proxied Router';
  {$EXTERNALSYM NID_sendProxiedRouter}
  NID_sendProxiedRouter = 1028;

  {$EXTERNALSYM SN_sendOwner}
  SN_sendOwner = 'sendOwner';
  {$EXTERNALSYM LN_sendOwner}
  LN_sendOwner = 'Send Owner';
  {$EXTERNALSYM NID_sendOwner}
  NID_sendOwner = 1029;

  {$EXTERNALSYM SN_sendProxiedOwner}
  SN_sendProxiedOwner = 'sendProxiedOwner';
  {$EXTERNALSYM LN_sendProxiedOwner}
  LN_sendProxiedOwner = 'Send Proxied Owner';
  {$EXTERNALSYM NID_sendProxiedOwner}
  NID_sendProxiedOwner = 1030;

  {$EXTERNALSYM SN_cmcCA}
  SN_cmcCA = 'cmcCA';
  {$EXTERNALSYM LN_cmcCA}
  LN_cmcCA = 'CMC Certificate Authority';
  {$EXTERNALSYM NID_cmcCA}
  NID_cmcCA = 1131;

  {$EXTERNALSYM SN_cmcRA}
  SN_cmcRA = 'cmcRA';
  {$EXTERNALSYM LN_cmcRA}
  LN_cmcRA = 'CMC Registration Authority';
  {$EXTERNALSYM NID_cmcRA}
  NID_cmcRA = 1132;

  {$EXTERNALSYM SN_id_it_caProtEncCert}
  SN_id_it_caProtEncCert = 'id-it-caProtEncCert';
  {$EXTERNALSYM NID_id_it_caProtEncCert}
  NID_id_it_caProtEncCert = 298;

  {$EXTERNALSYM SN_id_it_signKeyPairTypes}
  SN_id_it_signKeyPairTypes = 'id-it-signKeyPairTypes';
  {$EXTERNALSYM NID_id_it_signKeyPairTypes}
  NID_id_it_signKeyPairTypes = 299;

  {$EXTERNALSYM SN_id_it_encKeyPairTypes}
  SN_id_it_encKeyPairTypes = 'id-it-encKeyPairTypes';
  {$EXTERNALSYM NID_id_it_encKeyPairTypes}
  NID_id_it_encKeyPairTypes = 300;

  {$EXTERNALSYM SN_id_it_preferredSymmAlg}
  SN_id_it_preferredSymmAlg = 'id-it-preferredSymmAlg';
  {$EXTERNALSYM NID_id_it_preferredSymmAlg}
  NID_id_it_preferredSymmAlg = 301;

  {$EXTERNALSYM SN_id_it_caKeyUpdateInfo}
  SN_id_it_caKeyUpdateInfo = 'id-it-caKeyUpdateInfo';
  {$EXTERNALSYM NID_id_it_caKeyUpdateInfo}
  NID_id_it_caKeyUpdateInfo = 302;

  {$EXTERNALSYM SN_id_it_currentCRL}
  SN_id_it_currentCRL = 'id-it-currentCRL';
  {$EXTERNALSYM NID_id_it_currentCRL}
  NID_id_it_currentCRL = 303;

  {$EXTERNALSYM SN_id_it_unsupportedOIDs}
  SN_id_it_unsupportedOIDs = 'id-it-unsupportedOIDs';
  {$EXTERNALSYM NID_id_it_unsupportedOIDs}
  NID_id_it_unsupportedOIDs = 304;

  {$EXTERNALSYM SN_id_it_subscriptionRequest}
  SN_id_it_subscriptionRequest = 'id-it-subscriptionRequest';
  {$EXTERNALSYM NID_id_it_subscriptionRequest}
  NID_id_it_subscriptionRequest = 305;

  {$EXTERNALSYM SN_id_it_subscriptionResponse}
  SN_id_it_subscriptionResponse = 'id-it-subscriptionResponse';
  {$EXTERNALSYM NID_id_it_subscriptionResponse}
  NID_id_it_subscriptionResponse = 306;

  {$EXTERNALSYM SN_id_it_keyPairParamReq}
  SN_id_it_keyPairParamReq = 'id-it-keyPairParamReq';
  {$EXTERNALSYM NID_id_it_keyPairParamReq}
  NID_id_it_keyPairParamReq = 307;

  {$EXTERNALSYM SN_id_it_keyPairParamRep}
  SN_id_it_keyPairParamRep = 'id-it-keyPairParamRep';
  {$EXTERNALSYM NID_id_it_keyPairParamRep}
  NID_id_it_keyPairParamRep = 308;

  {$EXTERNALSYM SN_id_it_revPassphrase}
  SN_id_it_revPassphrase = 'id-it-revPassphrase';
  {$EXTERNALSYM NID_id_it_revPassphrase}
  NID_id_it_revPassphrase = 309;

  {$EXTERNALSYM SN_id_it_implicitConfirm}
  SN_id_it_implicitConfirm = 'id-it-implicitConfirm';
  {$EXTERNALSYM NID_id_it_implicitConfirm}
  NID_id_it_implicitConfirm = 310;

  {$EXTERNALSYM SN_id_it_confirmWaitTime}
  SN_id_it_confirmWaitTime = 'id-it-confirmWaitTime';
  {$EXTERNALSYM NID_id_it_confirmWaitTime}
  NID_id_it_confirmWaitTime = 311;

  {$EXTERNALSYM SN_id_it_origPKIMessage}
  SN_id_it_origPKIMessage = 'id-it-origPKIMessage';
  {$EXTERNALSYM NID_id_it_origPKIMessage}
  NID_id_it_origPKIMessage = 312;

  {$EXTERNALSYM SN_id_it_suppLangTags}
  SN_id_it_suppLangTags = 'id-it-suppLangTags';
  {$EXTERNALSYM NID_id_it_suppLangTags}
  NID_id_it_suppLangTags = 784;

  {$EXTERNALSYM SN_id_regCtrl}
  SN_id_regCtrl = 'id-regCtrl';
  {$EXTERNALSYM NID_id_regCtrl}
  NID_id_regCtrl = 313;

  {$EXTERNALSYM SN_id_regInfo}
  SN_id_regInfo = 'id-regInfo';
  {$EXTERNALSYM NID_id_regInfo}
  NID_id_regInfo = 314;

  {$EXTERNALSYM SN_id_regCtrl_regToken}
  SN_id_regCtrl_regToken = 'id-regCtrl-regToken';
  {$EXTERNALSYM NID_id_regCtrl_regToken}
  NID_id_regCtrl_regToken = 315;

  {$EXTERNALSYM SN_id_regCtrl_authenticator}
  SN_id_regCtrl_authenticator = 'id-regCtrl-authenticator';
  {$EXTERNALSYM NID_id_regCtrl_authenticator}
  NID_id_regCtrl_authenticator = 316;

  {$EXTERNALSYM SN_id_regCtrl_pkiPublicationInfo}
  SN_id_regCtrl_pkiPublicationInfo = 'id-regCtrl-pkiPublicationInfo';
  {$EXTERNALSYM NID_id_regCtrl_pkiPublicationInfo}
  NID_id_regCtrl_pkiPublicationInfo = 317;

  {$EXTERNALSYM SN_id_regCtrl_pkiArchiveOptions}
  SN_id_regCtrl_pkiArchiveOptions = 'id-regCtrl-pkiArchiveOptions';
  {$EXTERNALSYM NID_id_regCtrl_pkiArchiveOptions}
  NID_id_regCtrl_pkiArchiveOptions = 318;

  {$EXTERNALSYM SN_id_regCtrl_oldCertID}
  SN_id_regCtrl_oldCertID = 'id-regCtrl-oldCertID';
  {$EXTERNALSYM NID_id_regCtrl_oldCertID}
  NID_id_regCtrl_oldCertID = 319;

  {$EXTERNALSYM SN_id_regCtrl_protocolEncrKey}
  SN_id_regCtrl_protocolEncrKey = 'id-regCtrl-protocolEncrKey';
  {$EXTERNALSYM NID_id_regCtrl_protocolEncrKey}
  NID_id_regCtrl_protocolEncrKey = 320;

  {$EXTERNALSYM SN_id_regInfo_utf8Pairs}
  SN_id_regInfo_utf8Pairs = 'id-regInfo-utf8Pairs';
  {$EXTERNALSYM NID_id_regInfo_utf8Pairs}
  NID_id_regInfo_utf8Pairs = 321;

  {$EXTERNALSYM SN_id_regInfo_certReq}
  SN_id_regInfo_certReq = 'id-regInfo-certReq';
  {$EXTERNALSYM NID_id_regInfo_certReq}
  NID_id_regInfo_certReq = 322;

  {$EXTERNALSYM SN_id_alg_des40}
  SN_id_alg_des40 = 'id-alg-des40';
  {$EXTERNALSYM NID_id_alg_des40}
  NID_id_alg_des40 = 323;

  {$EXTERNALSYM SN_id_alg_noSignature}
  SN_id_alg_noSignature = 'id-alg-noSignature';
  {$EXTERNALSYM NID_id_alg_noSignature}
  NID_id_alg_noSignature = 324;

  {$EXTERNALSYM SN_id_alg_dh_sig_hmac_sha1}
  SN_id_alg_dh_sig_hmac_sha1 = 'id-alg-dh-sig-hmac-sha1';
  {$EXTERNALSYM NID_id_alg_dh_sig_hmac_sha1}
  NID_id_alg_dh_sig_hmac_sha1 = 325;

  {$EXTERNALSYM SN_id_alg_dh_pop}
  SN_id_alg_dh_pop = 'id-alg-dh-pop';
  {$EXTERNALSYM NID_id_alg_dh_pop}
  NID_id_alg_dh_pop = 326;

  {$EXTERNALSYM SN_id_cmc_statusInfo}
  SN_id_cmc_statusInfo = 'id-cmc-statusInfo';
  {$EXTERNALSYM NID_id_cmc_statusInfo}
  NID_id_cmc_statusInfo = 327;

  {$EXTERNALSYM SN_id_cmc_identification}
  SN_id_cmc_identification = 'id-cmc-identification';
  {$EXTERNALSYM NID_id_cmc_identification}
  NID_id_cmc_identification = 328;

  {$EXTERNALSYM SN_id_cmc_identityProof}
  SN_id_cmc_identityProof = 'id-cmc-identityProof';
  {$EXTERNALSYM NID_id_cmc_identityProof}
  NID_id_cmc_identityProof = 329;

  {$EXTERNALSYM SN_id_cmc_dataReturn}
  SN_id_cmc_dataReturn = 'id-cmc-dataReturn';
  {$EXTERNALSYM NID_id_cmc_dataReturn}
  NID_id_cmc_dataReturn = 330;

  {$EXTERNALSYM SN_id_cmc_transactionId}
  SN_id_cmc_transactionId = 'id-cmc-transactionId';
  {$EXTERNALSYM NID_id_cmc_transactionId}
  NID_id_cmc_transactionId = 331;

  {$EXTERNALSYM SN_id_cmc_senderNonce}
  SN_id_cmc_senderNonce = 'id-cmc-senderNonce';
  {$EXTERNALSYM NID_id_cmc_senderNonce}
  NID_id_cmc_senderNonce = 332;

  {$EXTERNALSYM SN_id_cmc_recipientNonce}
  SN_id_cmc_recipientNonce = 'id-cmc-recipientNonce';
  {$EXTERNALSYM NID_id_cmc_recipientNonce}
  NID_id_cmc_recipientNonce = 333;

  {$EXTERNALSYM SN_id_cmc_addExtensions}
  SN_id_cmc_addExtensions = 'id-cmc-addExtensions';
  {$EXTERNALSYM NID_id_cmc_addExtensions}
  NID_id_cmc_addExtensions = 334;

  {$EXTERNALSYM SN_id_cmc_encryptedPOP}
  SN_id_cmc_encryptedPOP = 'id-cmc-encryptedPOP';
  {$EXTERNALSYM NID_id_cmc_encryptedPOP}
  NID_id_cmc_encryptedPOP = 335;

  {$EXTERNALSYM SN_id_cmc_decryptedPOP}
  SN_id_cmc_decryptedPOP = 'id-cmc-decryptedPOP';
  {$EXTERNALSYM NID_id_cmc_decryptedPOP}
  NID_id_cmc_decryptedPOP = 336;

  {$EXTERNALSYM SN_id_cmc_lraPOPWitness}
  SN_id_cmc_lraPOPWitness = 'id-cmc-lraPOPWitness';
  {$EXTERNALSYM NID_id_cmc_lraPOPWitness}
  NID_id_cmc_lraPOPWitness = 337;

  {$EXTERNALSYM SN_id_cmc_getCert}
  SN_id_cmc_getCert = 'id-cmc-getCert';
  {$EXTERNALSYM NID_id_cmc_getCert}
  NID_id_cmc_getCert = 338;

  {$EXTERNALSYM SN_id_cmc_getCRL}
  SN_id_cmc_getCRL = 'id-cmc-getCRL';
  {$EXTERNALSYM NID_id_cmc_getCRL}
  NID_id_cmc_getCRL = 339;

  {$EXTERNALSYM SN_id_cmc_revokeRequest}
  SN_id_cmc_revokeRequest = 'id-cmc-revokeRequest';
  {$EXTERNALSYM NID_id_cmc_revokeRequest}
  NID_id_cmc_revokeRequest = 340;

  {$EXTERNALSYM SN_id_cmc_regInfo}
  SN_id_cmc_regInfo = 'id-cmc-regInfo';
  {$EXTERNALSYM NID_id_cmc_regInfo}
  NID_id_cmc_regInfo = 341;

  {$EXTERNALSYM SN_id_cmc_responseInfo}
  SN_id_cmc_responseInfo = 'id-cmc-responseInfo';
  {$EXTERNALSYM NID_id_cmc_responseInfo}
  NID_id_cmc_responseInfo = 342;

  {$EXTERNALSYM SN_id_cmc_queryPending}
  SN_id_cmc_queryPending = 'id-cmc-queryPending';
  {$EXTERNALSYM NID_id_cmc_queryPending}
  NID_id_cmc_queryPending = 343;

  {$EXTERNALSYM SN_id_cmc_popLinkRandom}
  SN_id_cmc_popLinkRandom = 'id-cmc-popLinkRandom';
  {$EXTERNALSYM NID_id_cmc_popLinkRandom}
  NID_id_cmc_popLinkRandom = 344;

  {$EXTERNALSYM SN_id_cmc_popLinkWitness}
  SN_id_cmc_popLinkWitness = 'id-cmc-popLinkWitness';
  {$EXTERNALSYM NID_id_cmc_popLinkWitness}
  NID_id_cmc_popLinkWitness = 345;

  {$EXTERNALSYM SN_id_cmc_confirmCertAcceptance}
  SN_id_cmc_confirmCertAcceptance = 'id-cmc-confirmCertAcceptance';
  {$EXTERNALSYM NID_id_cmc_confirmCertAcceptance}
  NID_id_cmc_confirmCertAcceptance = 346;

  {$EXTERNALSYM SN_id_on_personalData}
  SN_id_on_personalData = 'id-on-personalData';
  {$EXTERNALSYM NID_id_on_personalData}
  NID_id_on_personalData = 347;

  {$EXTERNALSYM SN_id_on_permanentIdentifier}
  SN_id_on_permanentIdentifier = 'id-on-permanentIdentifier';
  {$EXTERNALSYM LN_id_on_permanentIdentifier}
  LN_id_on_permanentIdentifier = 'Permanent Identifier';
  {$EXTERNALSYM NID_id_on_permanentIdentifier}
  NID_id_on_permanentIdentifier = 858;

  {$EXTERNALSYM SN_id_pda_dateOfBirth}
  SN_id_pda_dateOfBirth = 'id-pda-dateOfBirth';
  {$EXTERNALSYM NID_id_pda_dateOfBirth}
  NID_id_pda_dateOfBirth = 348;

  {$EXTERNALSYM SN_id_pda_placeOfBirth}
  SN_id_pda_placeOfBirth = 'id-pda-placeOfBirth';
  {$EXTERNALSYM NID_id_pda_placeOfBirth}
  NID_id_pda_placeOfBirth = 349;

  {$EXTERNALSYM SN_id_pda_gender}
  SN_id_pda_gender = 'id-pda-gender';
  {$EXTERNALSYM NID_id_pda_gender}
  NID_id_pda_gender = 351;

  {$EXTERNALSYM SN_id_pda_countryOfCitizenship}
  SN_id_pda_countryOfCitizenship = 'id-pda-countryOfCitizenship';
  {$EXTERNALSYM NID_id_pda_countryOfCitizenship}
  NID_id_pda_countryOfCitizenship = 352;

  {$EXTERNALSYM SN_id_pda_countryOfResidence}
  SN_id_pda_countryOfResidence = 'id-pda-countryOfResidence';
  {$EXTERNALSYM NID_id_pda_countryOfResidence}
  NID_id_pda_countryOfResidence = 353;

  {$EXTERNALSYM SN_id_aca_authenticationInfo}
  SN_id_aca_authenticationInfo = 'id-aca-authenticationInfo';
  {$EXTERNALSYM NID_id_aca_authenticationInfo}
  NID_id_aca_authenticationInfo = 354;

  {$EXTERNALSYM SN_id_aca_accessIdentity}
  SN_id_aca_accessIdentity = 'id-aca-accessIdentity';
  {$EXTERNALSYM NID_id_aca_accessIdentity}
  NID_id_aca_accessIdentity = 355;

  {$EXTERNALSYM SN_id_aca_chargingIdentity}
  SN_id_aca_chargingIdentity = 'id-aca-chargingIdentity';
  {$EXTERNALSYM NID_id_aca_chargingIdentity}
  NID_id_aca_chargingIdentity = 356;

  {$EXTERNALSYM SN_id_aca_group}
  SN_id_aca_group = 'id-aca-group';
  {$EXTERNALSYM NID_id_aca_group}
  NID_id_aca_group = 357;

  {$EXTERNALSYM SN_id_aca_role}
  SN_id_aca_role = 'id-aca-role';
  {$EXTERNALSYM NID_id_aca_role}
  NID_id_aca_role = 358;

  {$EXTERNALSYM SN_id_aca_encAttrs}
  SN_id_aca_encAttrs = 'id-aca-encAttrs';
  {$EXTERNALSYM NID_id_aca_encAttrs}
  NID_id_aca_encAttrs = 399;

  {$EXTERNALSYM SN_id_qcs_pkixQCSyntax_v1}
  SN_id_qcs_pkixQCSyntax_v1 = 'id-qcs-pkixQCSyntax-v1';
  {$EXTERNALSYM NID_id_qcs_pkixQCSyntax_v1}
  NID_id_qcs_pkixQCSyntax_v1 = 359;

  {$EXTERNALSYM SN_id_cct_crs}
  SN_id_cct_crs = 'id-cct-crs';
  {$EXTERNALSYM NID_id_cct_crs}
  NID_id_cct_crs = 360;

  {$EXTERNALSYM SN_id_cct_PKIData}
  SN_id_cct_PKIData = 'id-cct-PKIData';
  {$EXTERNALSYM NID_id_cct_PKIData}
  NID_id_cct_PKIData = 361;

  {$EXTERNALSYM SN_id_cct_PKIResponse}
  SN_id_cct_PKIResponse = 'id-cct-PKIResponse';
  {$EXTERNALSYM NID_id_cct_PKIResponse}
  NID_id_cct_PKIResponse = 362;

  {$EXTERNALSYM SN_id_ppl_anyLanguage}
  SN_id_ppl_anyLanguage = 'id-ppl-anyLanguage';
  {$EXTERNALSYM LN_id_ppl_anyLanguage}
  LN_id_ppl_anyLanguage = 'Any language';

  {$EXTERNALSYM NID_id_ppl_anyLanguage}
  NID_id_ppl_anyLanguage = 664;
  {$EXTERNALSYM SN_id_ppl_inheritAll}
  SN_id_ppl_inheritAll = 'id-ppl-inheritAll';

  {$EXTERNALSYM LN_id_ppl_inheritAll}
  LN_id_ppl_inheritAll = 'Inherit all';
  {$EXTERNALSYM NID_id_ppl_inheritAll}
  NID_id_ppl_inheritAll = 665;

  {$EXTERNALSYM SN_Independent}
  SN_Independent = 'id-ppl-independent';
  {$EXTERNALSYM LN_Independent}
  LN_Independent = 'Independent';
  {$EXTERNALSYM NID_Independent}
  NID_Independent = 667;

  {$EXTERNALSYM SN_ad_OCSP}
  SN_ad_OCSP = 'OCSP';
  {$EXTERNALSYM LN_ad_OCSP}
  LN_ad_OCSP = 'OCSP';
  {$EXTERNALSYM NID_ad_OCSP}
  NID_ad_OCSP = 178;

  {$EXTERNALSYM SN_ad_ca_issuers}
  SN_ad_ca_issuers = 'caIssuers';
  {$EXTERNALSYM LN_ad_ca_issuers}
  LN_ad_ca_issuers = 'CA Issuers';
  {$EXTERNALSYM NID_ad_ca_issuers}
  NID_ad_ca_issuers = 179;

  {$EXTERNALSYM SN_ad_timeStamping}
  SN_ad_timeStamping = 'ad_timestamping';
  {$EXTERNALSYM LN_ad_timeStamping}
  LN_ad_timeStamping = 'AD Time Stamping';
  {$EXTERNALSYM NID_ad_timeStamping}
  NID_ad_timeStamping = 363;

  {$EXTERNALSYM SN_ad_dvcs}
  SN_ad_dvcs = 'AD_DVCS';
  {$EXTERNALSYM LN_ad_dvcs}
  LN_ad_dvcs = 'ad dvcs';
  {$EXTERNALSYM NID_ad_dvcs}
  NID_ad_dvcs = 364;

  {$EXTERNALSYM SN_caRepository}
  SN_caRepository = 'caRepository';
  {$EXTERNALSYM LN_caRepository}
  LN_caRepository = 'CA Repository';
  {$EXTERNALSYM NID_caRepository}
  NID_caRepository = 785;

  {$EXTERNALSYM SN_id_pkix_OCSP_basic}
  SN_id_pkix_OCSP_basic = 'basicOCSPResponse';
  {$EXTERNALSYM LN_id_pkix_OCSP_basic}
  LN_id_pkix_OCSP_basic = 'Basic OCSP Response';
  {$EXTERNALSYM NID_id_pkix_OCSP_basic}
  NID_id_pkix_OCSP_basic = 365;

  {$EXTERNALSYM SN_id_pkix_OCSP_Nonce}
  SN_id_pkix_OCSP_Nonce = 'Nonce';
  {$EXTERNALSYM LN_id_pkix_OCSP_Nonce}
  LN_id_pkix_OCSP_Nonce = 'OCSP Nonce';
  {$EXTERNALSYM NID_id_pkix_OCSP_Nonce}
  NID_id_pkix_OCSP_Nonce = 366;

  {$EXTERNALSYM SN_id_pkix_OCSP_CrlID}
  SN_id_pkix_OCSP_CrlID = 'CrlID';
  {$EXTERNALSYM LN_id_pkix_OCSP_CrlID}
  LN_id_pkix_OCSP_CrlID = 'OCSP CRL ID';
  {$EXTERNALSYM NID_id_pkix_OCSP_CrlID}
  NID_id_pkix_OCSP_CrlID = 367;

  {$EXTERNALSYM SN_id_pkix_OCSP_acceptableResponses}
  SN_id_pkix_OCSP_acceptableResponses = 'acceptableResponses';
  {$EXTERNALSYM LN_id_pkix_OCSP_acceptableResponses}
  LN_id_pkix_OCSP_acceptableResponses = 'Acceptable OCSP Responses';
  {$EXTERNALSYM NID_id_pkix_OCSP_acceptableResponses}
  NID_id_pkix_OCSP_acceptableResponses = 368;

  {$EXTERNALSYM SN_id_pkix_OCSP_noCheck}
  SN_id_pkix_OCSP_noCheck = 'noCheck';
  {$EXTERNALSYM LN_id_pkix_OCSP_noCheck}
  LN_id_pkix_OCSP_noCheck = 'OCSP No Check';
  {$EXTERNALSYM NID_id_pkix_OCSP_noCheck}
  NID_id_pkix_OCSP_noCheck = 369;

  {$EXTERNALSYM SN_id_pkix_OCSP_archiveCutoff}
  SN_id_pkix_OCSP_archiveCutoff = 'archiveCutoff';
  {$EXTERNALSYM LN_id_pkix_OCSP_archiveCutoff}
  LN_id_pkix_OCSP_archiveCutoff = 'OCSP Archive Cutoff';
  {$EXTERNALSYM NID_id_pkix_OCSP_archiveCutoff}
  NID_id_pkix_OCSP_archiveCutoff = 370;

  {$EXTERNALSYM SN_id_pkix_OCSP_serviceLocator}
  SN_id_pkix_OCSP_serviceLocator = 'serviceLocator';
  {$EXTERNALSYM LN_id_pkix_OCSP_serviceLocator}
  LN_id_pkix_OCSP_serviceLocator = 'OCSP Service Locator';
  {$EXTERNALSYM NID_id_pkix_OCSP_serviceLocator}
  NID_id_pkix_OCSP_serviceLocator = 371;

  {$EXTERNALSYM SN_id_pkix_OCSP_extendedStatus}
  SN_id_pkix_OCSP_extendedStatus = 'extendedStatus';
  {$EXTERNALSYM LN_id_pkix_OCSP_extendedStatus}
  LN_id_pkix_OCSP_extendedStatus = 'Extended OCSP Status';
  {$EXTERNALSYM NID_id_pkix_OCSP_extendedStatus}
  NID_id_pkix_OCSP_extendedStatus = 372;

  {$EXTERNALSYM SN_id_pkix_OCSP_valid}
  SN_id_pkix_OCSP_valid = 'valid';
  {$EXTERNALSYM NID_id_pkix_OCSP_valid}
  NID_id_pkix_OCSP_valid = 373;

  {$EXTERNALSYM SN_id_pkix_OCSP_path}
  SN_id_pkix_OCSP_path = 'path';
  {$EXTERNALSYM NID_id_pkix_OCSP_path}
  NID_id_pkix_OCSP_path = 374;

  {$EXTERNALSYM SN_id_pkix_OCSP_trustRoot}
  SN_id_pkix_OCSP_trustRoot = 'trustRoot';
  {$EXTERNALSYM LN_id_pkix_OCSP_trustRoot}
  LN_id_pkix_OCSP_trustRoot = 'Trust Root';
  {$EXTERNALSYM NID_id_pkix_OCSP_trustRoot}
  NID_id_pkix_OCSP_trustRoot = 375;

  {$EXTERNALSYM SN_algorithm}
  SN_algorithm = 'algorithm';
  {$EXTERNALSYM LN_algorithm}
  LN_algorithm = 'algorithm';
  {$EXTERNALSYM NID_algorithm}
  NID_algorithm = 376;

  {$EXTERNALSYM SN_md5WithRSA}
  SN_md5WithRSA = 'RSA-NP-MD5';
  {$EXTERNALSYM LN_md5WithRSA}
  LN_md5WithRSA = 'md5WithRSA';
  {$EXTERNALSYM NID_md5WithRSA}
  NID_md5WithRSA = 104;

  {$EXTERNALSYM SN_des_ecb}
  SN_des_ecb = 'DES-ECB';
  {$EXTERNALSYM LN_des_ecb}
  LN_des_ecb = 'des-ecb';
  {$EXTERNALSYM NID_des_ecb}
  NID_des_ecb = 29;

  {$EXTERNALSYM SN_des_cbc}
  SN_des_cbc = 'DES-CBC';
  {$EXTERNALSYM LN_des_cbc}
  LN_des_cbc = 'des-cbc';
  {$EXTERNALSYM NID_des_cbc}
  NID_des_cbc = 31;

  {$EXTERNALSYM SN_des_ofb64}
  SN_des_ofb64 = 'DES-OFB';
  {$EXTERNALSYM LN_des_ofb64}
  LN_des_ofb64 = 'des-ofb';
  {$EXTERNALSYM NID_des_ofb64}
  NID_des_ofb64 = 45;

  {$EXTERNALSYM SN_des_cfb64}
  SN_des_cfb64 = 'DES-CFB';
  {$EXTERNALSYM LN_des_cfb64}
  LN_des_cfb64 = 'des-cfb';
  {$EXTERNALSYM NID_des_cfb64}
  NID_des_cfb64 = 30;

  {$EXTERNALSYM SN_rsaSignature}
  SN_rsaSignature = 'rsaSignature';
  {$EXTERNALSYM NID_rsaSignature}
  NID_rsaSignature = 377;

  {$EXTERNALSYM SN_dsa_2}
  SN_dsa_2 = 'DSA-old';
  {$EXTERNALSYM LN_dsa_2}
  LN_dsa_2 = 'dsaEncryption-old';
  {$EXTERNALSYM NID_dsa_2}
  NID_dsa_2 = 67;

  {$EXTERNALSYM SN_dsaWithSHA}
  SN_dsaWithSHA = 'DSA-SHA';
  {$EXTERNALSYM LN_dsaWithSHA}
  LN_dsaWithSHA = 'dsaWithSHA';
  {$EXTERNALSYM NID_dsaWithSHA}
  NID_dsaWithSHA = 66;

  {$EXTERNALSYM SN_shaWithRSAEncryption}
  SN_shaWithRSAEncryption = 'RSA-SHA';
  {$EXTERNALSYM LN_shaWithRSAEncryption}
  LN_shaWithRSAEncryption = 'shaWithRSAEncryption';
  {$EXTERNALSYM NID_shaWithRSAEncryption}
  NID_shaWithRSAEncryption = 42;

  {$EXTERNALSYM SN_des_ede_ecb}
  SN_des_ede_ecb = 'DES-EDE';
  {$EXTERNALSYM LN_des_ede_ecb}
  LN_des_ede_ecb = 'des-ede';
  {$EXTERNALSYM NID_des_ede_ecb}
  NID_des_ede_ecb = 32;

  {$EXTERNALSYM SN_des_ede3_ecb}
  SN_des_ede3_ecb = 'DES-EDE3';
  {$EXTERNALSYM LN_des_ede3_ecb}
  LN_des_ede3_ecb = 'des-ede3';
  {$EXTERNALSYM NID_des_ede3_ecb}
  NID_des_ede3_ecb = 33;

  {$EXTERNALSYM SN_des_ede_cbc}
  SN_des_ede_cbc = 'DES-EDE-CBC';
  {$EXTERNALSYM LN_des_ede_cbc}
  LN_des_ede_cbc = 'des-ede-cbc';
  {$EXTERNALSYM NID_des_ede_cbc}
  NID_des_ede_cbc = 43;

  {$EXTERNALSYM SN_des_ede_cfb64}
  SN_des_ede_cfb64 = 'DES-EDE-CFB';
  {$EXTERNALSYM LN_des_ede_cfb64}
  LN_des_ede_cfb64 = 'des-ede-cfb';
  {$EXTERNALSYM NID_des_ede_cfb64}
  NID_des_ede_cfb64 = 60;

  {$EXTERNALSYM SN_des_ede3_cfb64}
  SN_des_ede3_cfb64 = 'DES-EDE3-CFB';
  {$EXTERNALSYM LN_des_ede3_cfb64}
  LN_des_ede3_cfb64 = 'des-ede3-cfb';
  {$EXTERNALSYM NID_des_ede3_cfb64}
  NID_des_ede3_cfb64 = 61;

  {$EXTERNALSYM SN_des_ede_ofb64}
  SN_des_ede_ofb64 = 'DES-EDE-OFB';
  {$EXTERNALSYM LN_des_ede_ofb64}
  LN_des_ede_ofb64 = 'des-ede-ofb';
  {$EXTERNALSYM NID_des_ede_ofb64}
  NID_des_ede_ofb64 = 62;

  {$EXTERNALSYM SN_des_ede3_ofb64}
  SN_des_ede3_ofb64 = 'DES-EDE3-OFB';
  {$EXTERNALSYM LN_des_ede3_ofb64}
  LN_des_ede3_ofb64 = 'des-ede3-ofb';
  {$EXTERNALSYM NID_des_ede3_ofb64}
  NID_des_ede3_ofb64 = 63;

  {$EXTERNALSYM SN_desx_cbc}
  SN_desx_cbc = 'DESX-CBC';
  {$EXTERNALSYM LN_desx_cbc}
  LN_desx_cbc = 'desx-cbc';
  {$EXTERNALSYM NID_desx_cbc}
  NID_desx_cbc = 80;

  {$EXTERNALSYM SN_sha}
  SN_sha = 'SHA';
  {$EXTERNALSYM LN_sha}
  LN_sha = 'sha';
  {$EXTERNALSYM NID_sha}
  NID_sha = 41;

  {$EXTERNALSYM SN_sha1}
  SN_sha1 = 'SHA1';
  {$EXTERNALSYM LN_sha1}
  LN_sha1 = 'sha1';
  {$EXTERNALSYM NID_sha1}
  NID_sha1 = 64;

  {$EXTERNALSYM SN_dsaWithSHA1_2}
  SN_dsaWithSHA1_2 = 'DSA-SHA1-old';
  {$EXTERNALSYM LN_dsaWithSHA1_2}
  LN_dsaWithSHA1_2 = 'dsaWithSHA1-old';
  {$EXTERNALSYM NID_dsaWithSHA1_2}
  NID_dsaWithSHA1_2 = 70;

  {$EXTERNALSYM SN_sha1WithRSA}
  SN_sha1WithRSA = 'RSA-SHA1-2';
  {$EXTERNALSYM LN_sha1WithRSA}
  LN_sha1WithRSA = 'sha1WithRSA';
  {$EXTERNALSYM NID_sha1WithRSA}
  NID_sha1WithRSA = 115;

  {$EXTERNALSYM SN_ripemd160}
  SN_ripemd160 = 'RIPEMD160';
  {$EXTERNALSYM LN_ripemd160}
  LN_ripemd160 = 'ripemd160';
  {$EXTERNALSYM NID_ripemd160}
  NID_ripemd160 = 117;

  {$EXTERNALSYM SN_ripemd160WithRSA}
  SN_ripemd160WithRSA = 'RSA-RIPEMD160';
  {$EXTERNALSYM LN_ripemd160WithRSA}
  LN_ripemd160WithRSA = 'ripemd160WithRSA';
  {$EXTERNALSYM NID_ripemd160WithRSA}
  NID_ripemd160WithRSA = 119;

  {$EXTERNALSYM SN_blake2b512}
  SN_blake2b512 = 'BLAKE2b512';
  {$EXTERNALSYM LN_blake2b512}
  LN_blake2b512 = 'blake2b512';
  {$EXTERNALSYM NID_blake2b512}
  NID_blake2b512 = 1056;

  {$EXTERNALSYM SN_blake2s256}
  SN_blake2s256 = 'BLAKE2s256';
  {$EXTERNALSYM LN_blake2s256}
  LN_blake2s256 = 'blake2s256';
  {$EXTERNALSYM NID_blake2s256}
  NID_blake2s256 = 1057;

  {$EXTERNALSYM SN_sxnet}
  SN_sxnet = 'SXNetID';
  {$EXTERNALSYM LN_sxnet}
  LN_sxnet = 'Strong Extranet ID';
  {$EXTERNALSYM NID_sxnet}
  NID_sxnet = 143;

  {$EXTERNALSYM SN_X500}
  SN_X500 = 'X500';
  {$EXTERNALSYM LN_X500}
  LN_X500 = 'directory services(X.500)';
  {$EXTERNALSYM NID_X500}
  NID_X500 = 11;

  {$EXTERNALSYM SN_X509}
  SN_X509 = 'X509';
  {$EXTERNALSYM NID_X509}
  NID_X509 = 12;

  {$EXTERNALSYM SN_commonName}
  SN_commonName = 'CN';
  {$EXTERNALSYM LN_commonName}
  LN_commonName = 'commonName';
  {$EXTERNALSYM NID_commonName}
  NID_commonName = 13;

  {$EXTERNALSYM SN_surname}
  SN_surname = 'SN';
  {$EXTERNALSYM LN_surname}
  LN_surname = 'surname';
  {$EXTERNALSYM NID_surname}
  NID_surname = 100;

  {$EXTERNALSYM LN_serialNumber}
  LN_serialNumber = 'serialNumber';
  {$EXTERNALSYM NID_serialNumber}
  NID_serialNumber = 105;

  {$EXTERNALSYM SN_countryName}
  SN_countryName = 'C';
  {$EXTERNALSYM LN_countryName}
  LN_countryName = 'countryName';
  {$EXTERNALSYM NID_countryName}
  NID_countryName = 14;

  {$EXTERNALSYM SN_localityName}
  SN_localityName = 'L';
  {$EXTERNALSYM LN_localityName}
  LN_localityName = 'localityName';
  {$EXTERNALSYM NID_localityName}
  NID_localityName = 15;

  {$EXTERNALSYM SN_stateOrProvinceName}
  SN_stateOrProvinceName = 'ST';
  {$EXTERNALSYM LN_stateOrProvinceName}
  LN_stateOrProvinceName = 'stateOrProvinceName';
  {$EXTERNALSYM NID_stateOrProvinceName}
  NID_stateOrProvinceName = 16;

  {$EXTERNALSYM SN_streetAddress}
  SN_streetAddress = 'street';
  {$EXTERNALSYM LN_streetAddress}
  LN_streetAddress = 'streetAddress';
  {$EXTERNALSYM NID_streetAddress}
  NID_streetAddress = 660;

  {$EXTERNALSYM SN_organizationName}
  SN_organizationName = 'O';
  {$EXTERNALSYM LN_organizationName}
  LN_organizationName = 'organizationName';
  {$EXTERNALSYM NID_organizationName}
  NID_organizationName = 17;

  {$EXTERNALSYM SN_organizationalUnitName}
  SN_organizationalUnitName = 'OU';
  {$EXTERNALSYM LN_organizationalUnitName}
  LN_organizationalUnitName = 'organizationalUnitName';
  {$EXTERNALSYM NID_organizationalUnitName}
  NID_organizationalUnitName = 18;

  {$EXTERNALSYM SN_title}
  SN_title = 'title';
  {$EXTERNALSYM LN_title}
  LN_title = 'title';
  {$EXTERNALSYM NID_title}
  NID_title = 106;

  {$EXTERNALSYM LN_description}
  LN_description = 'description';
  {$EXTERNALSYM NID_description}
  NID_description = 107;

  {$EXTERNALSYM LN_searchGuide}
  LN_searchGuide = 'searchGuide';
  {$EXTERNALSYM NID_searchGuide}
  NID_searchGuide = 859;
  {$EXTERNALSYM LN_businessCategory}
  LN_businessCategory = 'businessCategory';
  {$EXTERNALSYM NID_businessCategory}
  NID_businessCategory = 860;

  {$EXTERNALSYM LN_postalAddress}
  LN_postalAddress = 'postalAddress';
  {$EXTERNALSYM NID_postalAddress}
  NID_postalAddress = 861;

  {$EXTERNALSYM LN_postalCode}
  LN_postalCode = 'postalCode';
  {$EXTERNALSYM NID_postalCode}
  NID_postalCode = 661;

  {$EXTERNALSYM LN_postOfficeBox}
  LN_postOfficeBox = 'postOfficeBox';
  {$EXTERNALSYM NID_postOfficeBox}
  NID_postOfficeBox = 862;

  {$EXTERNALSYM LN_physicalDeliveryOfficeName}
  LN_physicalDeliveryOfficeName = 'physicalDeliveryOfficeName';
  {$EXTERNALSYM NID_physicalDeliveryOfficeName}
  NID_physicalDeliveryOfficeName = 863;

  {$EXTERNALSYM LN_telephoneNumber}
  LN_telephoneNumber = 'telephoneNumber';
  {$EXTERNALSYM NID_telephoneNumber}
  NID_telephoneNumber = 864;

  {$EXTERNALSYM LN_telexNumber}
  LN_telexNumber = 'telexNumber';
  {$EXTERNALSYM NID_telexNumber}
  NID_telexNumber = 865;

  {$EXTERNALSYM LN_teletexTerminalIdentifier}
  LN_teletexTerminalIdentifier = 'teletexTerminalIdentifier';
  {$EXTERNALSYM NID_teletexTerminalIdentifier}
  NID_teletexTerminalIdentifier = 866;

  {$EXTERNALSYM LN_facsimileTelephoneNumber}
  LN_facsimileTelephoneNumber = 'facsimileTelephoneNumber';
  {$EXTERNALSYM NID_facsimileTelephoneNumber}
  NID_facsimileTelephoneNumber = 867;

  {$EXTERNALSYM LN_x121Address}
  LN_x121Address = 'x121Address';
  {$EXTERNALSYM NID_x121Address}
  NID_x121Address = 868;

  {$EXTERNALSYM LN_internationaliSDNNumber}
  LN_internationaliSDNNumber = 'internationaliSDNNumber';
  {$EXTERNALSYM NID_internationaliSDNNumber}
  NID_internationaliSDNNumber = 869;

  {$EXTERNALSYM LN_registeredAddress}
  LN_registeredAddress = 'registeredAddress';
  {$EXTERNALSYM NID_registeredAddress}
  NID_registeredAddress = 870;

  {$EXTERNALSYM LN_destinationIndicator}
  LN_destinationIndicator = 'destinationIndicator';
  {$EXTERNALSYM NID_destinationIndicator}
  NID_destinationIndicator = 871;

  {$EXTERNALSYM LN_preferredDeliveryMethod}
  LN_preferredDeliveryMethod = 'preferredDeliveryMethod';
  {$EXTERNALSYM NID_preferredDeliveryMethod}
  NID_preferredDeliveryMethod = 872;

  {$EXTERNALSYM LN_presentationAddress}
  LN_presentationAddress = 'presentationAddress';
  {$EXTERNALSYM NID_presentationAddress}
  NID_presentationAddress = 873;

  {$EXTERNALSYM LN_supportedApplicationContext}
  LN_supportedApplicationContext = 'supportedApplicationContext';
  {$EXTERNALSYM NID_supportedApplicationContext}
  NID_supportedApplicationContext = 874;

  {$EXTERNALSYM SN_member}
  SN_member = 'member';
  {$EXTERNALSYM NID_member}
  NID_member = 875;

  {$EXTERNALSYM SN_owner}
  SN_owner = 'owner';
  {$EXTERNALSYM NID_owner}
  NID_owner = 876;

  {$EXTERNALSYM LN_roleOccupant}
  LN_roleOccupant = 'roleOccupant';
  {$EXTERNALSYM NID_roleOccupant}
  NID_roleOccupant = 877;

  {$EXTERNALSYM SN_seeAlso}
  SN_seeAlso = 'seeAlso';
  {$EXTERNALSYM NID_seeAlso}
  NID_seeAlso = 878;

  {$EXTERNALSYM LN_userPassword}
  LN_userPassword = 'userPassword';
  {$EXTERNALSYM NID_userPassword}
  NID_userPassword = 879;

  {$EXTERNALSYM LN_userCertificate}
  LN_userCertificate = 'userCertificate';
  {$EXTERNALSYM NID_userCertificate}
  NID_userCertificate = 880;

  {$EXTERNALSYM LN_cACertificate}
  LN_cACertificate = 'cACertificate';
  {$EXTERNALSYM NID_cACertificate}
  NID_cACertificate = 881;

  {$EXTERNALSYM LN_authorityRevocationList}
  LN_authorityRevocationList = 'authorityRevocationList';
  {$EXTERNALSYM NID_authorityRevocationList}
  NID_authorityRevocationList = 882;

  {$EXTERNALSYM LN_certificateRevocationList}
  LN_certificateRevocationList = 'certificateRevocationList';
  {$EXTERNALSYM NID_certificateRevocationList}
  NID_certificateRevocationList = 883;

  {$EXTERNALSYM LN_crossCertificatePair}
  LN_crossCertificatePair = 'crossCertificatePair';
  {$EXTERNALSYM NID_crossCertificatePair}
  NID_crossCertificatePair = 884;

  {$EXTERNALSYM SN_name}
  SN_name = 'name';
  {$EXTERNALSYM LN_name}
  LN_name = 'name';
  {$EXTERNALSYM NID_name}
  NID_name = 173;

  {$EXTERNALSYM SN_givenName}
  SN_givenName = 'GN';
  {$EXTERNALSYM LN_givenName}
  LN_givenName = 'givenName';
  {$EXTERNALSYM NID_givenName}
  NID_givenName = 99;

  {$EXTERNALSYM SN_initials}
  SN_initials = 'initials';
  {$EXTERNALSYM LN_initials}
  LN_initials = 'initials';
  {$EXTERNALSYM NID_initials}
  NID_initials = 101;

  {$EXTERNALSYM LN_generationQualifier}
  LN_generationQualifier = 'generationQualifier';
  {$EXTERNALSYM NID_generationQualifier}
  NID_generationQualifier = 509;

  {$EXTERNALSYM LN_x500UniqueIdentifier}
  LN_x500UniqueIdentifier = 'x500UniqueIdentifier';
  {$EXTERNALSYM NID_x500UniqueIdentifier}
  NID_x500UniqueIdentifier = 503;

  {$EXTERNALSYM SN_dnQualifier}
  SN_dnQualifier = 'dnQualifier';
  {$EXTERNALSYM LN_dnQualifier}
  LN_dnQualifier = 'dnQualifier';
  {$EXTERNALSYM NID_dnQualifier}
  NID_dnQualifier = 174;

  {$EXTERNALSYM LN_enhancedSearchGuide}
  LN_enhancedSearchGuide = 'enhancedSearchGuide';
  {$EXTERNALSYM NID_enhancedSearchGuide}
  NID_enhancedSearchGuide = 885;

  {$EXTERNALSYM LN_protocolInformation}
  LN_protocolInformation = 'protocolInformation';
  {$EXTERNALSYM NID_protocolInformation}
  NID_protocolInformation = 886;

  {$EXTERNALSYM LN_distinguishedName}
  LN_distinguishedName = 'distinguishedName';
  {$EXTERNALSYM NID_distinguishedName}
  NID_distinguishedName = 887;

  {$EXTERNALSYM LN_uniqueMember}
  LN_uniqueMember = 'uniqueMember';
  {$EXTERNALSYM NID_uniqueMember}
  NID_uniqueMember = 888;

  {$EXTERNALSYM LN_houseIdentifier}
  LN_houseIdentifier = 'houseIdentifier';
  {$EXTERNALSYM NID_houseIdentifier}
  NID_houseIdentifier = 889;

  {$EXTERNALSYM LN_supportedAlgorithms}
  LN_supportedAlgorithms = 'supportedAlgorithms';
  {$EXTERNALSYM NID_supportedAlgorithms}
  NID_supportedAlgorithms = 890;

  {$EXTERNALSYM LN_deltaRevocationList}
  LN_deltaRevocationList = 'deltaRevocationList';
  {$EXTERNALSYM NID_deltaRevocationList}
  NID_deltaRevocationList = 891;

  {$EXTERNALSYM SN_dmdName}
  SN_dmdName = 'dmdName';
  {$EXTERNALSYM NID_dmdName}
  NID_dmdName = 892;

  {$EXTERNALSYM LN_pseudonym}
  LN_pseudonym = 'pseudonym';
  {$EXTERNALSYM NID_pseudonym}
  NID_pseudonym = 510;

  {$EXTERNALSYM SN_role}
  SN_role = 'role';
  {$EXTERNALSYM LN_role}
  LN_role = 'role';
  {$EXTERNALSYM NID_role}
  NID_role = 400;

  {$EXTERNALSYM LN_organizationIdentifier}
  LN_organizationIdentifier = 'organizationIdentifier';
  {$EXTERNALSYM NID_organizationIdentifier}
  NID_organizationIdentifier = 1089;

  {$EXTERNALSYM SN_countryCode3c}
  SN_countryCode3c = 'c3';
  {$EXTERNALSYM LN_countryCode3c}
  LN_countryCode3c = 'countryCode3c';
  {$EXTERNALSYM NID_countryCode3c}
  NID_countryCode3c = 1090;

  {$EXTERNALSYM SN_countryCode3n}
  SN_countryCode3n = 'n3';
  {$EXTERNALSYM LN_countryCode3n}
  LN_countryCode3n = 'countryCode3n';
  {$EXTERNALSYM NID_countryCode3n}
  NID_countryCode3n = 1091;

  {$EXTERNALSYM LN_dnsName}
  LN_dnsName = 'dnsName';
  {$EXTERNALSYM NID_dnsName}
  NID_dnsName = 1092;

  {$EXTERNALSYM SN_X500algorithms}
  SN_X500algorithms = 'X500algorithms';
  {$EXTERNALSYM LN_X500algorithms}
  LN_X500algorithms = 'directory services - algorithms';
  {$EXTERNALSYM NID_X500algorithms}
  NID_X500algorithms = 378;

  {$EXTERNALSYM SN_rsa}
  SN_rsa = 'RSA';
  {$EXTERNALSYM LN_rsa}
  LN_rsa = 'rsa';
  {$EXTERNALSYM NID_rsa}
  NID_rsa = 19;

  {$EXTERNALSYM SN_mdc2WithRSA}
  SN_mdc2WithRSA = 'RSA-MDC2';
  {$EXTERNALSYM LN_mdc2WithRSA}
  LN_mdc2WithRSA = 'mdc2WithRSA';
  {$EXTERNALSYM NID_mdc2WithRSA}
  NID_mdc2WithRSA = 96;

  {$EXTERNALSYM SN_mdc2}
  SN_mdc2 = 'MDC2';
  {$EXTERNALSYM LN_mdc2}
  LN_mdc2 = 'mdc2';
  {$EXTERNALSYM NID_mdc2}
  NID_mdc2 = 95;

  {$EXTERNALSYM SN_id_ce}
  SN_id_ce = 'id-ce';
  {$EXTERNALSYM NID_id_ce}
  NID_id_ce = 81;

  {$EXTERNALSYM SN_subject_directory_attributes}
  SN_subject_directory_attributes = 'subjectDirectoryAttributes';
  {$EXTERNALSYM LN_subject_directory_attributes}
  LN_subject_directory_attributes = 'X509v3 Subject Directory Attributes';
  {$EXTERNALSYM NID_subject_directory_attributes}
  NID_subject_directory_attributes = 769;

  {$EXTERNALSYM SN_subject_key_identifier}
  SN_subject_key_identifier = 'subjectKeyIdentifier';
  {$EXTERNALSYM LN_subject_key_identifier}
  LN_subject_key_identifier = 'X509v3 Subject Key Identifier';
  {$EXTERNALSYM NID_subject_key_identifier}
  NID_subject_key_identifier = 82;

  {$EXTERNALSYM SN_key_usage}
  SN_key_usage = 'keyUsage';
  {$EXTERNALSYM LN_key_usage}
  LN_key_usage = 'X509v3 Key Usage';
  {$EXTERNALSYM NID_key_usage}
  NID_key_usage = 83;

  {$EXTERNALSYM SN_private_key_usage_period}
  SN_private_key_usage_period = 'privateKeyUsagePeriod';
  {$EXTERNALSYM LN_private_key_usage_period}
  LN_private_key_usage_period = 'X509v3 Private Key Usage Period';
  {$EXTERNALSYM NID_private_key_usage_period}
  NID_private_key_usage_period = 84;

  {$EXTERNALSYM SN_subject_alt_name}
  SN_subject_alt_name = 'subjectAltName';
  {$EXTERNALSYM LN_subject_alt_name}
  LN_subject_alt_name = 'X509v3 Subject Alternative Name';
  {$EXTERNALSYM NID_subject_alt_name}
  NID_subject_alt_name = 85;

  {$EXTERNALSYM SN_issuer_alt_name}
  SN_issuer_alt_name = 'issuerAltName';
  {$EXTERNALSYM LN_issuer_alt_name}
  LN_issuer_alt_name = 'X509v3 Issuer Alternative Name';
  {$EXTERNALSYM NID_issuer_alt_name}
  NID_issuer_alt_name = 86;

  {$EXTERNALSYM SN_basic_constraints}
  SN_basic_constraints = 'basicConstraints';
  {$EXTERNALSYM LN_basic_constraints}
  LN_basic_constraints = 'X509v3 Basic Constraints';
  {$EXTERNALSYM NID_basic_constraints}
  NID_basic_constraints = 87;

  {$EXTERNALSYM SN_crl_number}
  SN_crl_number = 'crlNumber';
  {$EXTERNALSYM LN_crl_number}
  LN_crl_number = 'X509v3 CRL Number';
  {$EXTERNALSYM NID_crl_number}
  NID_crl_number = 88;

  {$EXTERNALSYM SN_crl_reason}
  SN_crl_reason = 'CRLReason';
  {$EXTERNALSYM LN_crl_reason}
  LN_crl_reason = 'X509v3 CRL Reason Code';
  {$EXTERNALSYM NID_crl_reason}
  NID_crl_reason = 141;

  {$EXTERNALSYM SN_invalidity_date}
  SN_invalidity_date = 'invalidityDate';
  {$EXTERNALSYM LN_invalidity_date}
  LN_invalidity_date = 'Invalidity Date';
  {$EXTERNALSYM NID_invalidity_date}
  NID_invalidity_date = 142;

  {$EXTERNALSYM SN_delta_crl}
  SN_delta_crl = 'deltaCRL';
  {$EXTERNALSYM LN_delta_crl}
  LN_delta_crl = 'X509v3 Delta CRL Indicator';
  {$EXTERNALSYM NID_delta_crl}
  NID_delta_crl = 140;

  {$EXTERNALSYM SN_issuing_distribution_point}
  SN_issuing_distribution_point = 'issuingDistributionPoint';
  {$EXTERNALSYM LN_issuing_distribution_point}
  LN_issuing_distribution_point = 'X509v3 Issuing Distribution Point';
  {$EXTERNALSYM NID_issuing_distribution_point}
  NID_issuing_distribution_point = 770;

  {$EXTERNALSYM SN_certificate_issuer}
  SN_certificate_issuer = 'certificateIssuer';
  {$EXTERNALSYM LN_certificate_issuer}
  LN_certificate_issuer = 'X509v3 Certificate Issuer';
  {$EXTERNALSYM NID_certificate_issuer}
  NID_certificate_issuer = 771;

  {$EXTERNALSYM SN_name_constraints}
  SN_name_constraints = 'nameConstraints';
  {$EXTERNALSYM LN_name_constraints}
  LN_name_constraints = 'X509v3 Name Constraints';
  {$EXTERNALSYM NID_name_constraints}
  NID_name_constraints = 666;

  {$EXTERNALSYM SN_crl_distribution_points}
  SN_crl_distribution_points = 'crlDistributionPoints';
  {$EXTERNALSYM LN_crl_distribution_points}
  LN_crl_distribution_points = 'X509v3 CRL Distribution Points';
  {$EXTERNALSYM NID_crl_distribution_points}
  NID_crl_distribution_points = 103;

  {$EXTERNALSYM SN_certificate_policies}
  SN_certificate_policies = 'certificatePolicies';
  {$EXTERNALSYM LN_certificate_policies}
  LN_certificate_policies = 'X509v3 Certificate Policies';
  {$EXTERNALSYM NID_certificate_policies}
  NID_certificate_policies = 89;

  {$EXTERNALSYM SN_any_policy}
  SN_any_policy = 'anyPolicy';
  {$EXTERNALSYM LN_any_policy}
  LN_any_policy = 'X509v3 Any Policy';
  {$EXTERNALSYM NID_any_policy}
  NID_any_policy = 746;

  {$EXTERNALSYM SN_policy_mappings}
  SN_policy_mappings = 'policyMappings';
  {$EXTERNALSYM LN_policy_mappings}
  LN_policy_mappings = 'X509v3 Policy Mappings';
  {$EXTERNALSYM NID_policy_mappings}
  NID_policy_mappings = 747;

  {$EXTERNALSYM SN_authority_key_identifier}
  SN_authority_key_identifier = 'authorityKeyIdentifier';
  {$EXTERNALSYM LN_authority_key_identifier}
  LN_authority_key_identifier = 'X509v3 Authority Key Identifier';
  {$EXTERNALSYM NID_authority_key_identifier}
  NID_authority_key_identifier = 90;

  {$EXTERNALSYM SN_policy_constraints}
  SN_policy_constraints = 'policyConstraints';
  {$EXTERNALSYM LN_policy_constraints}
  LN_policy_constraints = 'X509v3 Policy Constraints';
  {$EXTERNALSYM NID_policy_constraints}
  NID_policy_constraints = 401;

  {$EXTERNALSYM SN_ext_key_usage}
  SN_ext_key_usage = 'extendedKeyUsage';
  {$EXTERNALSYM LN_ext_key_usage}
  LN_ext_key_usage = 'X509v3 Extended Key Usage';
  {$EXTERNALSYM NID_ext_key_usage}
  NID_ext_key_usage = 126;

  {$EXTERNALSYM SN_freshest_crl}
  SN_freshest_crl = 'freshestCRL';
  {$EXTERNALSYM LN_freshest_crl}
  LN_freshest_crl = 'X509v3 Freshest CRL';
  {$EXTERNALSYM NID_freshest_crl}
  NID_freshest_crl = 857;

  {$EXTERNALSYM SN_inhibit_any_policy}
  SN_inhibit_any_policy = 'inhibitAnyPolicy';
  {$EXTERNALSYM LN_inhibit_any_policy}
  LN_inhibit_any_policy = 'X509v3 Inhibit Any Policy';
  {$EXTERNALSYM NID_inhibit_any_policy}
  NID_inhibit_any_policy = 748;

  {$EXTERNALSYM SN_target_information}
  SN_target_information = 'targetInformation';
  {$EXTERNALSYM LN_target_information}
  LN_target_information = 'X509v3 AC Targeting';
  {$EXTERNALSYM NID_target_information}
  NID_target_information = 402;

  {$EXTERNALSYM SN_no_rev_avail}
  SN_no_rev_avail = 'noRevAvail';
  {$EXTERNALSYM LN_no_rev_avail}
  LN_no_rev_avail = 'X509v3 No Revocation Available';
  {$EXTERNALSYM NID_no_rev_avail}
  NID_no_rev_avail = 403;

  {$EXTERNALSYM SN_anyExtendedKeyUsage}
  SN_anyExtendedKeyUsage = 'anyExtendedKeyUsage';
  {$EXTERNALSYM LN_anyExtendedKeyUsage}
  LN_anyExtendedKeyUsage = 'Any Extended Key Usage';
  {$EXTERNALSYM NID_anyExtendedKeyUsage}
  NID_anyExtendedKeyUsage = 910;

  {$EXTERNALSYM SN_netscape}
  SN_netscape = 'Netscape';
  {$EXTERNALSYM LN_netscape}
  LN_netscape = 'Netscape Communications Corp.';
  {$EXTERNALSYM NID_netscape}
  NID_netscape = 57;

  {$EXTERNALSYM SN_netscape_cert_extension}
  SN_netscape_cert_extension = 'nsCertExt';
  {$EXTERNALSYM LN_netscape_cert_extension}
  LN_netscape_cert_extension = 'Netscape Certificate Extension';
  {$EXTERNALSYM NID_netscape_cert_extension}
  NID_netscape_cert_extension = 58;

  {$EXTERNALSYM SN_netscape_data_type}
  SN_netscape_data_type = 'nsDataType';
  {$EXTERNALSYM LN_netscape_data_type}
  LN_netscape_data_type = 'Netscape Data Type';
  {$EXTERNALSYM NID_netscape_data_type}
  NID_netscape_data_type = 59;

  {$EXTERNALSYM SN_netscape_cert_type}
  SN_netscape_cert_type = 'nsCertType';
  {$EXTERNALSYM LN_netscape_cert_type}
  LN_netscape_cert_type = 'Netscape Cert Type';
  {$EXTERNALSYM NID_netscape_cert_type}
  NID_netscape_cert_type = 71;

  {$EXTERNALSYM SN_netscape_base_url}
  SN_netscape_base_url = 'nsBaseUrl';
  {$EXTERNALSYM LN_netscape_base_url}
  LN_netscape_base_url = 'Netscape Base Url';
  {$EXTERNALSYM NID_netscape_base_url}
  NID_netscape_base_url = 72;

  {$EXTERNALSYM SN_netscape_revocation_url}
  SN_netscape_revocation_url = 'nsRevocationUrl';
  {$EXTERNALSYM LN_netscape_revocation_url}
  LN_netscape_revocation_url = 'Netscape Revocation Url';
  {$EXTERNALSYM NID_netscape_revocation_url}
  NID_netscape_revocation_url = 73;

  {$EXTERNALSYM SN_netscape_ca_revocation_url}
  SN_netscape_ca_revocation_url = 'nsCaRevocationUrl';
  {$EXTERNALSYM LN_netscape_ca_revocation_url}
  LN_netscape_ca_revocation_url = 'Netscape CA Revocation Url';
  {$EXTERNALSYM NID_netscape_ca_revocation_url}
  NID_netscape_ca_revocation_url = 74;

  {$EXTERNALSYM SN_netscape_renewal_url}
  SN_netscape_renewal_url = 'nsRenewalUrl';
  {$EXTERNALSYM LN_netscape_renewal_url}
  LN_netscape_renewal_url = 'Netscape Renewal Url';
  {$EXTERNALSYM NID_netscape_renewal_url}
  NID_netscape_renewal_url = 75;

  {$EXTERNALSYM SN_netscape_ca_policy_url}
  SN_netscape_ca_policy_url = 'nsCaPolicyUrl';
  {$EXTERNALSYM LN_netscape_ca_policy_url}
  LN_netscape_ca_policy_url = 'Netscape CA Policy Url';
  {$EXTERNALSYM NID_netscape_ca_policy_url}
  NID_netscape_ca_policy_url = 76;

  {$EXTERNALSYM SN_netscape_ssl_server_name}
  SN_netscape_ssl_server_name = 'nsSslServerName';
  {$EXTERNALSYM LN_netscape_ssl_server_name}
  LN_netscape_ssl_server_name = 'Netscape Server: SSl Name';
  {$EXTERNALSYM NID_netscape_ssl_server_name}
  NID_netscape_ssl_server_name = 77;

  {$EXTERNALSYM SN_netscape_comment}
  SN_netscape_comment = 'nsComment';
  {$EXTERNALSYM LN_netscape_comment}
  LN_netscape_comment = 'Netscape Comment';
  {$EXTERNALSYM NID_netscape_comment}
  NID_netscape_comment = 78;

  {$EXTERNALSYM SN_netscape_cert_sequence}
  SN_netscape_cert_sequence = 'nsCertSequence';
  {$EXTERNALSYM LN_netscape_cert_sequence}
  LN_netscape_cert_sequence = 'Netscape Certificate Sequence';
  {$EXTERNALSYM NID_netscape_cert_sequence}
  NID_netscape_cert_sequence = 79;

  {$EXTERNALSYM SN_ns_sgc}
  SN_ns_sgc = 'nsSGC';
  {$EXTERNALSYM LN_ns_sgc}
  LN_ns_sgc = 'Netscape Server Gated Crypto';
  {$EXTERNALSYM NID_ns_sgc}
  NID_ns_sgc = 139;

  {$EXTERNALSYM SN_org}
  SN_org = 'ORG';
  {$EXTERNALSYM LN_org}
  LN_org = 'org';
  {$EXTERNALSYM NID_org}
  NID_org = 379;

  {$EXTERNALSYM SN_dod}
  SN_dod = 'DOD';
  {$EXTERNALSYM LN_dod}
  LN_dod = 'dod';
  {$EXTERNALSYM NID_dod}
  NID_dod = 380;

  {$EXTERNALSYM SN_iana}
  SN_iana = 'IANA';
  {$EXTERNALSYM LN_iana}
  LN_iana = 'iana';
  {$EXTERNALSYM NID_iana}
  NID_iana = 381;

  {$EXTERNALSYM SN_Directory}
  SN_Directory = 'directory';
  {$EXTERNALSYM LN_Directory}
  LN_Directory = 'Directory';
  {$EXTERNALSYM NID_Directory}
  NID_Directory = 382;

  {$EXTERNALSYM SN_Management}
  SN_Management = 'mgmt';
  {$EXTERNALSYM LN_Management}
  LN_Management = 'Management';
  {$EXTERNALSYM NID_Management}
  NID_Management = 383;

  {$EXTERNALSYM SN_Experimental}
  SN_Experimental = 'experimental';
  {$EXTERNALSYM LN_Experimental}
  LN_Experimental = 'Experimental';
  {$EXTERNALSYM NID_Experimental}
  NID_Experimental = 384;

  {$EXTERNALSYM SN_Private}
  SN_Private = 'private';
  {$EXTERNALSYM LN_Private}
  LN_Private = 'Private';
  {$EXTERNALSYM NID_Private}
  NID_Private = 385;

  {$EXTERNALSYM SN_Security}
  SN_Security = 'security';
  {$EXTERNALSYM LN_Security}
  LN_Security = 'Security';
  {$EXTERNALSYM NID_Security}
  NID_Security = 386;

  {$EXTERNALSYM SN_SNMPv2}
  SN_SNMPv2 = 'snmpv2';
  {$EXTERNALSYM LN_SNMPv2}
  LN_SNMPv2 = 'SNMPv2';
  {$EXTERNALSYM NID_SNMPv2}
  NID_SNMPv2 = 387;

  {$EXTERNALSYM LN_Mail}
  LN_Mail = 'Mail';
  {$EXTERNALSYM NID_Mail}
  NID_Mail = 388;

  {$EXTERNALSYM SN_Enterprises}
  SN_Enterprises = 'enterprises';
  {$EXTERNALSYM LN_Enterprises}
  LN_Enterprises = 'Enterprises';
  {$EXTERNALSYM NID_Enterprises}
  NID_Enterprises = 389;

  {$EXTERNALSYM SN_dcObject}
  SN_dcObject = 'dcobject';
  {$EXTERNALSYM LN_dcObject}
  LN_dcObject = 'dcObject';
  {$EXTERNALSYM NID_dcObject}
  NID_dcObject = 390;

  {$EXTERNALSYM SN_mime_mhs}
  SN_mime_mhs = 'mime-mhs';
  {$EXTERNALSYM LN_mime_mhs}
  LN_mime_mhs = 'MIME MHS';
  {$EXTERNALSYM NID_mime_mhs}
  NID_mime_mhs = 504;

  {$EXTERNALSYM SN_mime_mhs_headings}
  SN_mime_mhs_headings = 'mime-mhs-headings';
  {$EXTERNALSYM LN_mime_mhs_headings}
  LN_mime_mhs_headings = 'mime-mhs-headings';
  {$EXTERNALSYM NID_mime_mhs_headings}
  NID_mime_mhs_headings = 505;

  {$EXTERNALSYM SN_mime_mhs_bodies}
  SN_mime_mhs_bodies = 'mime-mhs-bodies';
  {$EXTERNALSYM LN_mime_mhs_bodies}
  LN_mime_mhs_bodies = 'mime-mhs-bodies';
  {$EXTERNALSYM NID_mime_mhs_bodies}
  NID_mime_mhs_bodies = 506;

  {$EXTERNALSYM SN_id_hex_partial_message}
  SN_id_hex_partial_message = 'id-hex-partial-message';
  {$EXTERNALSYM LN_id_hex_partial_message}
  LN_id_hex_partial_message = 'id-hex-partial-message';
  {$EXTERNALSYM NID_id_hex_partial_message}
  NID_id_hex_partial_message = 507;

  {$EXTERNALSYM SN_id_hex_multipart_message}
  SN_id_hex_multipart_message = 'id-hex-multipart-message';
  {$EXTERNALSYM LN_id_hex_multipart_message}
  LN_id_hex_multipart_message = 'id-hex-multipart-message';
  {$EXTERNALSYM NID_id_hex_multipart_message}
  NID_id_hex_multipart_message = 508;

  {$EXTERNALSYM SN_zlib_compression}
  SN_zlib_compression = 'ZLIB';
  {$EXTERNALSYM LN_zlib_compression}
  LN_zlib_compression = 'zlib compression';
  {$EXTERNALSYM NID_zlib_compression}
  NID_zlib_compression = 125;

  {$EXTERNALSYM SN_aes_128_ecb}
  SN_aes_128_ecb = 'AES-128-ECB';
  {$EXTERNALSYM LN_aes_128_ecb}
  LN_aes_128_ecb = 'aes-128-ecb';
  {$EXTERNALSYM NID_aes_128_ecb}
  NID_aes_128_ecb = 418;

  {$EXTERNALSYM SN_aes_128_cbc}
  SN_aes_128_cbc = 'AES-128-CBC';
  {$EXTERNALSYM LN_aes_128_cbc}
  LN_aes_128_cbc = 'aes-128-cbc';
  {$EXTERNALSYM NID_aes_128_cbc}
  NID_aes_128_cbc = 419;

  {$EXTERNALSYM SN_aes_128_ofb128}
  SN_aes_128_ofb128 = 'AES-128-OFB';
  {$EXTERNALSYM LN_aes_128_ofb128}
  LN_aes_128_ofb128 = 'aes-128-ofb';
  {$EXTERNALSYM NID_aes_128_ofb128}
  NID_aes_128_ofb128 = 420;

  {$EXTERNALSYM SN_aes_128_cfb128}
  SN_aes_128_cfb128 = 'AES-128-CFB';
  {$EXTERNALSYM LN_aes_128_cfb128}
  LN_aes_128_cfb128 = 'aes-128-cfb';
  {$EXTERNALSYM NID_aes_128_cfb128}
  NID_aes_128_cfb128 = 421;

  {$EXTERNALSYM SN_id_aes128_wrap}
  SN_id_aes128_wrap = 'id-aes128-wrap';
  {$EXTERNALSYM NID_id_aes128_wrap}
  NID_id_aes128_wrap = 788;

  {$EXTERNALSYM SN_aes_128_gcm}
  SN_aes_128_gcm = 'id-aes128-GCM';
  {$EXTERNALSYM LN_aes_128_gcm}
  LN_aes_128_gcm = 'aes-128-gcm';
  {$EXTERNALSYM NID_aes_128_gcm}
  NID_aes_128_gcm = 895;

  {$EXTERNALSYM SN_aes_128_ccm}
  SN_aes_128_ccm = 'id-aes128-CCM';
  {$EXTERNALSYM LN_aes_128_ccm}
  LN_aes_128_ccm = 'aes-128-ccm';
  {$EXTERNALSYM NID_aes_128_ccm}
  NID_aes_128_ccm = 896;

  {$EXTERNALSYM SN_id_aes128_wrap_pad}
  SN_id_aes128_wrap_pad = 'id-aes128-wrap-pad';
  {$EXTERNALSYM NID_id_aes128_wrap_pad}
  NID_id_aes128_wrap_pad = 897;

  {$EXTERNALSYM SN_aes_192_ecb}
  SN_aes_192_ecb = 'AES-192-ECB';
  {$EXTERNALSYM LN_aes_192_ecb}
  LN_aes_192_ecb = 'aes-192-ecb';
  {$EXTERNALSYM NID_aes_192_ecb}
  NID_aes_192_ecb = 422;

  {$EXTERNALSYM SN_aes_192_cbc}
  SN_aes_192_cbc = 'AES-192-CBC';
  {$EXTERNALSYM LN_aes_192_cbc}
  LN_aes_192_cbc = 'aes-192-cbc';
  {$EXTERNALSYM NID_aes_192_cbc}
  NID_aes_192_cbc = 423;

  {$EXTERNALSYM SN_aes_192_ofb128}
  SN_aes_192_ofb128 = 'AES-192-OFB';
  {$EXTERNALSYM LN_aes_192_ofb128}
  LN_aes_192_ofb128 = 'aes-192-ofb';
  {$EXTERNALSYM NID_aes_192_ofb128}
  NID_aes_192_ofb128 = 424;

  {$EXTERNALSYM SN_aes_192_cfb128}
  SN_aes_192_cfb128 = 'AES-192-CFB';
  {$EXTERNALSYM LN_aes_192_cfb128}
  LN_aes_192_cfb128 = 'aes-192-cfb';
  {$EXTERNALSYM NID_aes_192_cfb128}
  NID_aes_192_cfb128 = 425;

  {$EXTERNALSYM SN_id_aes192_wrap}
  SN_id_aes192_wrap = 'id-aes192-wrap';
  {$EXTERNALSYM NID_id_aes192_wrap}
  NID_id_aes192_wrap = 789;

  {$EXTERNALSYM SN_aes_192_gcm}
  SN_aes_192_gcm = 'id-aes192-GCM';
  {$EXTERNALSYM LN_aes_192_gcm}
  LN_aes_192_gcm = 'aes-192-gcm';
  {$EXTERNALSYM NID_aes_192_gcm}
  NID_aes_192_gcm = 898;

  {$EXTERNALSYM SN_aes_192_ccm}
  SN_aes_192_ccm = 'id-aes192-CCM';
  {$EXTERNALSYM LN_aes_192_ccm}
  LN_aes_192_ccm = 'aes-192-ccm';
  {$EXTERNALSYM NID_aes_192_ccm}
  NID_aes_192_ccm = 899;

  {$EXTERNALSYM SN_id_aes192_wrap_pad}
  SN_id_aes192_wrap_pad = 'id-aes192-wrap-pad';
  {$EXTERNALSYM NID_id_aes192_wrap_pad}
  NID_id_aes192_wrap_pad = 900;

  {$EXTERNALSYM SN_aes_256_ecb}
  SN_aes_256_ecb = 'AES-256-ECB';
  {$EXTERNALSYM LN_aes_256_ecb}
  LN_aes_256_ecb = 'aes-256-ecb';
  {$EXTERNALSYM NID_aes_256_ecb}
  NID_aes_256_ecb = 426;

  {$EXTERNALSYM SN_aes_256_cbc}
  SN_aes_256_cbc = 'AES-256-CBC';
  {$EXTERNALSYM LN_aes_256_cbc}
  LN_aes_256_cbc = 'aes-256-cbc';
  {$EXTERNALSYM NID_aes_256_cbc}
  NID_aes_256_cbc = 427;

  {$EXTERNALSYM SN_aes_256_ofb128}
  SN_aes_256_ofb128 = 'AES-256-OFB';
  {$EXTERNALSYM LN_aes_256_ofb128}
  LN_aes_256_ofb128 = 'aes-256-ofb';
  {$EXTERNALSYM NID_aes_256_ofb128}
  NID_aes_256_ofb128 = 428;

  {$EXTERNALSYM SN_aes_256_cfb128}
  SN_aes_256_cfb128 = 'AES-256-CFB';
  {$EXTERNALSYM LN_aes_256_cfb128}
  LN_aes_256_cfb128 = 'aes-256-cfb';
  {$EXTERNALSYM NID_aes_256_cfb128}
  NID_aes_256_cfb128 = 429;

  {$EXTERNALSYM SN_id_aes256_wrap}
  SN_id_aes256_wrap = 'id-aes256-wrap';
  {$EXTERNALSYM NID_id_aes256_wrap}
  NID_id_aes256_wrap = 790;

  {$EXTERNALSYM SN_aes_256_gcm}
  SN_aes_256_gcm = 'id-aes256-GCM';
  {$EXTERNALSYM LN_aes_256_gcm}
  LN_aes_256_gcm = 'aes-256-gcm';
  {$EXTERNALSYM NID_aes_256_gcm}
  NID_aes_256_gcm = 901;

  {$EXTERNALSYM SN_aes_256_ccm}
  SN_aes_256_ccm = 'id-aes256-CCM';
  {$EXTERNALSYM LN_aes_256_ccm}
  LN_aes_256_ccm = 'aes-256-ccm';
  {$EXTERNALSYM NID_aes_256_ccm}
  NID_aes_256_ccm = 902;

  {$EXTERNALSYM SN_id_aes256_wrap_pad}
  SN_id_aes256_wrap_pad = 'id-aes256-wrap-pad';
  {$EXTERNALSYM NID_id_aes256_wrap_pad}
  NID_id_aes256_wrap_pad = 903;

  {$EXTERNALSYM SN_aes_128_xts}
  SN_aes_128_xts = 'AES-128-XTS';
  {$EXTERNALSYM LN_aes_128_xts}
  LN_aes_128_xts = 'aes-128-xts';
  {$EXTERNALSYM NID_aes_128_xts}
  NID_aes_128_xts = 913;

  {$EXTERNALSYM SN_aes_256_xts}
  SN_aes_256_xts = 'AES-256-XTS';
  {$EXTERNALSYM LN_aes_256_xts}
  LN_aes_256_xts = 'aes-256-xts';
  {$EXTERNALSYM NID_aes_256_xts}
  NID_aes_256_xts = 914;

  {$EXTERNALSYM SN_aes_128_cfb1}
  SN_aes_128_cfb1 = 'AES-128-CFB1';
  {$EXTERNALSYM LN_aes_128_cfb1}
  LN_aes_128_cfb1 = 'aes-128-cfb1';
  {$EXTERNALSYM NID_aes_128_cfb1}
  NID_aes_128_cfb1 = 650;

  {$EXTERNALSYM SN_aes_192_cfb1}
  SN_aes_192_cfb1 = 'AES-192-CFB1';
  {$EXTERNALSYM LN_aes_192_cfb1}
  LN_aes_192_cfb1 = 'aes-192-cfb1';
  {$EXTERNALSYM NID_aes_192_cfb1}
  NID_aes_192_cfb1 = 651;

  {$EXTERNALSYM SN_aes_256_cfb1}
  SN_aes_256_cfb1 = 'AES-256-CFB1';
  {$EXTERNALSYM LN_aes_256_cfb1}
  LN_aes_256_cfb1 = 'aes-256-cfb1';
  {$EXTERNALSYM NID_aes_256_cfb1}
  NID_aes_256_cfb1 = 652;

  {$EXTERNALSYM SN_aes_128_cfb8}
  SN_aes_128_cfb8 = 'AES-128-CFB8';
  {$EXTERNALSYM LN_aes_128_cfb8}
  LN_aes_128_cfb8 = 'aes-128-cfb8';
  {$EXTERNALSYM NID_aes_128_cfb8}
  NID_aes_128_cfb8 = 653;

  {$EXTERNALSYM SN_aes_192_cfb8}
  SN_aes_192_cfb8 = 'AES-192-CFB8';
  {$EXTERNALSYM LN_aes_192_cfb8}
  LN_aes_192_cfb8 = 'aes-192-cfb8';
  {$EXTERNALSYM NID_aes_192_cfb8}
  NID_aes_192_cfb8 = 654;

  {$EXTERNALSYM SN_aes_256_cfb8}
  SN_aes_256_cfb8 = 'AES-256-CFB8';
  {$EXTERNALSYM LN_aes_256_cfb8}
  LN_aes_256_cfb8 = 'aes-256-cfb8';
  {$EXTERNALSYM NID_aes_256_cfb8}
  NID_aes_256_cfb8 = 655;

  {$EXTERNALSYM SN_aes_128_ctr}
  SN_aes_128_ctr = 'AES-128-CTR';
  {$EXTERNALSYM LN_aes_128_ctr}
  LN_aes_128_ctr = 'aes-128-ctr';
  {$EXTERNALSYM NID_aes_128_ctr}
  NID_aes_128_ctr = 904;

  {$EXTERNALSYM SN_aes_192_ctr}
  SN_aes_192_ctr = 'AES-192-CTR';
  {$EXTERNALSYM LN_aes_192_ctr}
  LN_aes_192_ctr = 'aes-192-ctr';
  {$EXTERNALSYM NID_aes_192_ctr}
  NID_aes_192_ctr = 905;

  {$EXTERNALSYM SN_aes_256_ctr}
  SN_aes_256_ctr = 'AES-256-CTR';
  {$EXTERNALSYM LN_aes_256_ctr}
  LN_aes_256_ctr = 'aes-256-ctr';
  {$EXTERNALSYM NID_aes_256_ctr}
  NID_aes_256_ctr = 906;

  {$EXTERNALSYM SN_aes_128_ocb}
  SN_aes_128_ocb = 'AES-128-OCB';
  {$EXTERNALSYM LN_aes_128_ocb}
  LN_aes_128_ocb = 'aes-128-ocb';
  {$EXTERNALSYM NID_aes_128_ocb}
  NID_aes_128_ocb = 958;

  {$EXTERNALSYM SN_aes_192_ocb}
  SN_aes_192_ocb = 'AES-192-OCB';
  {$EXTERNALSYM LN_aes_192_ocb}
  LN_aes_192_ocb = 'aes-192-ocb';
  {$EXTERNALSYM NID_aes_192_ocb}
  NID_aes_192_ocb = 959;

  {$EXTERNALSYM SN_aes_256_ocb}
  SN_aes_256_ocb = 'AES-256-OCB';
  {$EXTERNALSYM LN_aes_256_ocb}
  LN_aes_256_ocb = 'aes-256-ocb';
  {$EXTERNALSYM NID_aes_256_ocb}
  NID_aes_256_ocb = 960;

  {$EXTERNALSYM SN_des_cfb1}
  SN_des_cfb1 = 'DES-CFB1';
  {$EXTERNALSYM LN_des_cfb1}
  LN_des_cfb1 = 'des-cfb1';
  {$EXTERNALSYM NID_des_cfb1}
  NID_des_cfb1 = 656;

  {$EXTERNALSYM SN_des_cfb8}
  SN_des_cfb8 = 'DES-CFB8';
  {$EXTERNALSYM LN_des_cfb8}
  LN_des_cfb8 = 'des-cfb8';
  {$EXTERNALSYM NID_des_cfb8}
  NID_des_cfb8 = 657;

  {$EXTERNALSYM SN_des_ede3_cfb1}
  SN_des_ede3_cfb1 = 'DES-EDE3-CFB1';
  {$EXTERNALSYM LN_des_ede3_cfb1}
  LN_des_ede3_cfb1 = 'des-ede3-cfb1';
  {$EXTERNALSYM NID_des_ede3_cfb1}
  NID_des_ede3_cfb1 = 658;

  {$EXTERNALSYM SN_des_ede3_cfb8}
  SN_des_ede3_cfb8 = 'DES-EDE3-CFB8';
  {$EXTERNALSYM LN_des_ede3_cfb8}
  LN_des_ede3_cfb8 = 'des-ede3-cfb8';
  {$EXTERNALSYM NID_des_ede3_cfb8}
  NID_des_ede3_cfb8 = 659;

  {$EXTERNALSYM SN_sha256}
  SN_sha256 = 'SHA256';
  {$EXTERNALSYM LN_sha256}
  LN_sha256 = 'sha256';
  {$EXTERNALSYM NID_sha256}
  NID_sha256 = 672;

  {$EXTERNALSYM SN_sha384}
  SN_sha384 = 'SHA384';
  {$EXTERNALSYM LN_sha384}
  LN_sha384 = 'sha384';
  {$EXTERNALSYM NID_sha384}
  NID_sha384 = 673;

  {$EXTERNALSYM SN_sha512}
  SN_sha512 = 'SHA512';
  {$EXTERNALSYM LN_sha512}
  LN_sha512 = 'sha512';
  {$EXTERNALSYM NID_sha512}
  NID_sha512 = 674;

  {$EXTERNALSYM SN_sha224}
  SN_sha224 = 'SHA224';
  {$EXTERNALSYM LN_sha224}
  LN_sha224 = 'sha224';
  {$EXTERNALSYM NID_sha224}
  NID_sha224 = 675;

  {$EXTERNALSYM SN_sha512_224}
  SN_sha512_224 = 'SHA512-224';
  {$EXTERNALSYM LN_sha512_224}
  LN_sha512_224 = 'sha512-224';
  {$EXTERNALSYM NID_sha512_224}
  NID_sha512_224 = 1094;

  {$EXTERNALSYM SN_sha512_256}
  SN_sha512_256 = 'SHA512-256';
  {$EXTERNALSYM LN_sha512_256}
  LN_sha512_256 = 'sha512-256';
  {$EXTERNALSYM NID_sha512_256}
  NID_sha512_256 = 1095;

  {$EXTERNALSYM SN_sha3_224}
  SN_sha3_224 = 'SHA3-224';
  {$EXTERNALSYM LN_sha3_224}
  LN_sha3_224 = 'sha3-224';
  {$EXTERNALSYM NID_sha3_224}
  NID_sha3_224 = 1096;

  {$EXTERNALSYM SN_sha3_256}
  SN_sha3_256 = 'SHA3-256';
  {$EXTERNALSYM LN_sha3_256}
  LN_sha3_256 = 'sha3-256';
  {$EXTERNALSYM NID_sha3_256}
  NID_sha3_256 = 1097;

  {$EXTERNALSYM SN_sha3_384}
  SN_sha3_384 = 'SHA3-384';
  {$EXTERNALSYM LN_sha3_384}
  LN_sha3_384 = 'sha3-384';
  {$EXTERNALSYM NID_sha3_384}
  NID_sha3_384 = 1098;

  {$EXTERNALSYM SN_sha3_512}
  SN_sha3_512 = 'SHA3-512';
  {$EXTERNALSYM LN_sha3_512}
  LN_sha3_512 = 'sha3-512';
  {$EXTERNALSYM NID_sha3_512}
  NID_sha3_512 = 1099;

  {$EXTERNALSYM SN_shake128}
  SN_shake128 = 'SHAKE128';
  {$EXTERNALSYM LN_shake128}
  LN_shake128 = 'shake128';
  {$EXTERNALSYM NID_shake128}
  NID_shake128 = 1100;

  {$EXTERNALSYM SN_shake256}
  SN_shake256 = 'SHAKE256';
  {$EXTERNALSYM LN_shake256}
  LN_shake256 = 'shake256';
  {$EXTERNALSYM NID_shake256}
  NID_shake256 = 1101;

  {$EXTERNALSYM SN_hmac_sha3_224}
  SN_hmac_sha3_224 = 'id-hmacWithSHA3-224';
  {$EXTERNALSYM LN_hmac_sha3_224}
  LN_hmac_sha3_224 = 'hmac-sha3-224';
  {$EXTERNALSYM NID_hmac_sha3_224}
  NID_hmac_sha3_224 = 1102;

  {$EXTERNALSYM SN_hmac_sha3_256}
  SN_hmac_sha3_256 = 'id-hmacWithSHA3-256';
  {$EXTERNALSYM LN_hmac_sha3_256}
  LN_hmac_sha3_256 = 'hmac-sha3-256';
  {$EXTERNALSYM NID_hmac_sha3_256}
  NID_hmac_sha3_256 = 1103;

  {$EXTERNALSYM SN_hmac_sha3_384}
  SN_hmac_sha3_384 = 'id-hmacWithSHA3-384';
  {$EXTERNALSYM LN_hmac_sha3_384}
  LN_hmac_sha3_384 = 'hmac-sha3-384';
  {$EXTERNALSYM NID_hmac_sha3_384}
  NID_hmac_sha3_384 = 1104;

  {$EXTERNALSYM SN_hmac_sha3_512}
  SN_hmac_sha3_512 = 'id-hmacWithSHA3-512';
  {$EXTERNALSYM LN_hmac_sha3_512}
  LN_hmac_sha3_512 = 'hmac-sha3-512';
  {$EXTERNALSYM NID_hmac_sha3_512}
  NID_hmac_sha3_512 = 1105;

  {$EXTERNALSYM SN_dsa_with_SHA224}
  SN_dsa_with_SHA224 = 'dsa_with_SHA224';
  {$EXTERNALSYM NID_dsa_with_SHA224}
  NID_dsa_with_SHA224 = 802;

  {$EXTERNALSYM SN_dsa_with_SHA256}
  SN_dsa_with_SHA256 = 'dsa_with_SHA256';
  {$EXTERNALSYM NID_dsa_with_SHA256}
  NID_dsa_with_SHA256 = 803;

  {$EXTERNALSYM SN_dsa_with_SHA384}
  SN_dsa_with_SHA384 = 'id-dsa-with-sha384';
  {$EXTERNALSYM LN_dsa_with_SHA384}
  LN_dsa_with_SHA384 = 'dsa_with_SHA384';
  {$EXTERNALSYM NID_dsa_with_SHA384}
  NID_dsa_with_SHA384 = 1106;

  {$EXTERNALSYM SN_dsa_with_SHA512}
  SN_dsa_with_SHA512 = 'id-dsa-with-sha512';
  {$EXTERNALSYM LN_dsa_with_SHA512}
  LN_dsa_with_SHA512 = 'dsa_with_SHA512';
  {$EXTERNALSYM NID_dsa_with_SHA512}
  NID_dsa_with_SHA512 = 1107;

  {$EXTERNALSYM SN_dsa_with_SHA3_224}
  SN_dsa_with_SHA3_224 = 'id-dsa-with-sha3-224';
  {$EXTERNALSYM LN_dsa_with_SHA3_224}
  LN_dsa_with_SHA3_224 = 'dsa_with_SHA3-224';
  {$EXTERNALSYM NID_dsa_with_SHA3_224}
  NID_dsa_with_SHA3_224 = 1108;

  {$EXTERNALSYM SN_dsa_with_SHA3_256}
  SN_dsa_with_SHA3_256 = 'id-dsa-with-sha3-256';
  {$EXTERNALSYM LN_dsa_with_SHA3_256}
  LN_dsa_with_SHA3_256 = 'dsa_with_SHA3-256';
  {$EXTERNALSYM NID_dsa_with_SHA3_256}
  NID_dsa_with_SHA3_256 = 1109;

  {$EXTERNALSYM SN_dsa_with_SHA3_384}
  SN_dsa_with_SHA3_384 = 'id-dsa-with-sha3-384';
  {$EXTERNALSYM LN_dsa_with_SHA3_384}
  LN_dsa_with_SHA3_384 = 'dsa_with_SHA3-384';
  {$EXTERNALSYM NID_dsa_with_SHA3_384}
  NID_dsa_with_SHA3_384 = 1110;

  {$EXTERNALSYM SN_dsa_with_SHA3_512}
  SN_dsa_with_SHA3_512 = 'id-dsa-with-sha3-512';
  {$EXTERNALSYM LN_dsa_with_SHA3_512}
  LN_dsa_with_SHA3_512 = 'dsa_with_SHA3-512';
  {$EXTERNALSYM NID_dsa_with_SHA3_512}
  NID_dsa_with_SHA3_512 = 1111;

  {$EXTERNALSYM SN_ecdsa_with_SHA3_224}
  SN_ecdsa_with_SHA3_224 = 'id-ecdsa-with-sha3-224';
  {$EXTERNALSYM LN_ecdsa_with_SHA3_224}
  LN_ecdsa_with_SHA3_224 = 'ecdsa_with_SHA3-224';
  {$EXTERNALSYM NID_ecdsa_with_SHA3_224}
  NID_ecdsa_with_SHA3_224 = 1112;

  {$EXTERNALSYM SN_ecdsa_with_SHA3_256}
  SN_ecdsa_with_SHA3_256 = 'id-ecdsa-with-sha3-256';
  {$EXTERNALSYM LN_ecdsa_with_SHA3_256}
  LN_ecdsa_with_SHA3_256 = 'ecdsa_with_SHA3-256';
  {$EXTERNALSYM NID_ecdsa_with_SHA3_256}
  NID_ecdsa_with_SHA3_256 = 1113;

  {$EXTERNALSYM SN_ecdsa_with_SHA3_384}
  SN_ecdsa_with_SHA3_384 = 'id-ecdsa-with-sha3-384';
  {$EXTERNALSYM LN_ecdsa_with_SHA3_384}
  LN_ecdsa_with_SHA3_384 = 'ecdsa_with_SHA3-384';
  {$EXTERNALSYM NID_ecdsa_with_SHA3_384}
  NID_ecdsa_with_SHA3_384 = 1114;

  {$EXTERNALSYM SN_ecdsa_with_SHA3_512}
  SN_ecdsa_with_SHA3_512 = 'id-ecdsa-with-sha3-512';
  {$EXTERNALSYM LN_ecdsa_with_SHA3_512}
  LN_ecdsa_with_SHA3_512 = 'ecdsa_with_SHA3-512';
  {$EXTERNALSYM NID_ecdsa_with_SHA3_512}
  NID_ecdsa_with_SHA3_512 = 1115;

  {$EXTERNALSYM SN_RSA_SHA3_224}
  SN_RSA_SHA3_224 = 'id-rsassa-pkcs1-v1_5-with-sha3-224';
  {$EXTERNALSYM LN_RSA_SHA3_224}
  LN_RSA_SHA3_224 = 'RSA-SHA3-224';
  {$EXTERNALSYM NID_RSA_SHA3_224}
  NID_RSA_SHA3_224 = 1116;

  {$EXTERNALSYM SN_RSA_SHA3_256}
  SN_RSA_SHA3_256 = 'id-rsassa-pkcs1-v1_5-with-sha3-256';
  {$EXTERNALSYM LN_RSA_SHA3_256}
  LN_RSA_SHA3_256 = 'RSA-SHA3-256';
  {$EXTERNALSYM NID_RSA_SHA3_256}
  NID_RSA_SHA3_256 = 1117;

  {$EXTERNALSYM SN_RSA_SHA3_384}
  SN_RSA_SHA3_384 = 'id-rsassa-pkcs1-v1_5-with-sha3-384';
  {$EXTERNALSYM LN_RSA_SHA3_384}
  LN_RSA_SHA3_384 = 'RSA-SHA3-384';
  {$EXTERNALSYM NID_RSA_SHA3_384}
  NID_RSA_SHA3_384 = 1118;

  {$EXTERNALSYM SN_RSA_SHA3_512}
  SN_RSA_SHA3_512 = 'id-rsassa-pkcs1-v1_5-with-sha3-512';
  {$EXTERNALSYM LN_RSA_SHA3_512}
  LN_RSA_SHA3_512 = 'RSA-SHA3-512';
  {$EXTERNALSYM NID_RSA_SHA3_512}
  NID_RSA_SHA3_512 = 1119;

  {$EXTERNALSYM SN_hold_instruction_code}
  SN_hold_instruction_code = 'holdInstructionCode';
  {$EXTERNALSYM LN_hold_instruction_code}
  LN_hold_instruction_code = 'Hold Instruction Code';
  {$EXTERNALSYM NID_hold_instruction_code}
  NID_hold_instruction_code = 430;

  {$EXTERNALSYM SN_hold_instruction_none}
  SN_hold_instruction_none = 'holdInstructionNone';
  {$EXTERNALSYM LN_hold_instruction_none}
  LN_hold_instruction_none = 'Hold Instruction None';
  {$EXTERNALSYM NID_hold_instruction_none}
  NID_hold_instruction_none = 431;

  {$EXTERNALSYM SN_hold_instruction_call_issuer}
  SN_hold_instruction_call_issuer = 'holdInstructionCallIssuer';
  {$EXTERNALSYM LN_hold_instruction_call_issuer}
  LN_hold_instruction_call_issuer = 'Hold Instruction Call Issuer';
  {$EXTERNALSYM NID_hold_instruction_call_issuer}
  NID_hold_instruction_call_issuer = 432;

  {$EXTERNALSYM SN_hold_instruction_reject}
  SN_hold_instruction_reject = 'holdInstructionReject';
  {$EXTERNALSYM LN_hold_instruction_reject}
  LN_hold_instruction_reject = 'Hold Instruction Reject';
  {$EXTERNALSYM NID_hold_instruction_reject}
  NID_hold_instruction_reject = 433;

  {$EXTERNALSYM SN_data}
  SN_data = 'data';
  {$EXTERNALSYM NID_data}
  NID_data = 434;

  {$EXTERNALSYM SN_pss}
  SN_pss = 'pss';
  {$EXTERNALSYM NID_pss}
  NID_pss = 435;

  {$EXTERNALSYM SN_ucl}
  SN_ucl = 'ucl';
  {$EXTERNALSYM NID_ucl}
  NID_ucl = 436;

  {$EXTERNALSYM SN_pilot}
  SN_pilot = 'pilot';
  {$EXTERNALSYM NID_pilot}
  NID_pilot = 437;

  {$EXTERNALSYM LN_pilotAttributeType}
  LN_pilotAttributeType = 'pilotAttributeType';
  {$EXTERNALSYM NID_pilotAttributeType}
  NID_pilotAttributeType = 438;

  {$EXTERNALSYM LN_pilotAttributeSyntax}
  LN_pilotAttributeSyntax = 'pilotAttributeSyntax';
  {$EXTERNALSYM NID_pilotAttributeSyntax}
  NID_pilotAttributeSyntax = 439;

  {$EXTERNALSYM LN_pilotObjectClass}
  LN_pilotObjectClass = 'pilotObjectClass';
  {$EXTERNALSYM NID_pilotObjectClass}
  NID_pilotObjectClass = 440;

  {$EXTERNALSYM LN_pilotGroups}
  LN_pilotGroups = 'pilotGroups';
  {$EXTERNALSYM NID_pilotGroups}
  NID_pilotGroups = 441;

  {$EXTERNALSYM LN_iA5StringSyntax}
  LN_iA5StringSyntax = 'iA5StringSyntax';
  {$EXTERNALSYM NID_iA5StringSyntax}
  NID_iA5StringSyntax = 442;

  {$EXTERNALSYM LN_caseIgnoreIA5StringSyntax}
  LN_caseIgnoreIA5StringSyntax = 'caseIgnoreIA5StringSyntax';
  {$EXTERNALSYM NID_caseIgnoreIA5StringSyntax}
  NID_caseIgnoreIA5StringSyntax = 443;

  {$EXTERNALSYM LN_pilotObject}
  LN_pilotObject = 'pilotObject';
  {$EXTERNALSYM NID_pilotObject}
  NID_pilotObject = 444;

  {$EXTERNALSYM LN_pilotPerson}
  LN_pilotPerson = 'pilotPerson';
  {$EXTERNALSYM NID_pilotPerson}
  NID_pilotPerson = 445;

  {$EXTERNALSYM SN_account}
  SN_account = 'account';
  {$EXTERNALSYM NID_account}
  NID_account = 446;

  {$EXTERNALSYM SN_document}
  SN_document = 'document';
  {$EXTERNALSYM NID_document}
  NID_document = 447;

  {$EXTERNALSYM SN_room}
  SN_room = 'room';
  {$EXTERNALSYM NID_room}
  NID_room = 448;

  {$EXTERNALSYM LN_documentSeries}
  LN_documentSeries = 'documentSeries';
  {$EXTERNALSYM NID_documentSeries}
  NID_documentSeries = 449;

  {$EXTERNALSYM SN_Domain}
  SN_Domain = 'domain';
  {$EXTERNALSYM LN_Domain}
  LN_Domain = 'Domain';
  {$EXTERNALSYM NID_Domain}
  NID_Domain = 392;

  {$EXTERNALSYM LN_rFC822localPart}
  LN_rFC822localPart = 'rFC822localPart';
  {$EXTERNALSYM NID_rFC822localPart}
  NID_rFC822localPart = 450;

  {$EXTERNALSYM LN_dNSDomain}
  LN_dNSDomain = 'dNSDomain';
  {$EXTERNALSYM NID_dNSDomain}
  NID_dNSDomain = 451;

  {$EXTERNALSYM LN_domainRelatedObject}
  LN_domainRelatedObject = 'domainRelatedObject';
  {$EXTERNALSYM NID_domainRelatedObject}
  NID_domainRelatedObject = 452;

  {$EXTERNALSYM LN_friendlyCountry}
  LN_friendlyCountry = 'friendlyCountry';
  {$EXTERNALSYM NID_friendlyCountry}
  NID_friendlyCountry = 453;

  {$EXTERNALSYM LN_simpleSecurityObject}
  LN_simpleSecurityObject = 'simpleSecurityObject';
  {$EXTERNALSYM NID_simpleSecurityObject}
  NID_simpleSecurityObject = 454;

  {$EXTERNALSYM LN_pilotOrganization}
  LN_pilotOrganization = 'pilotOrganization';
  {$EXTERNALSYM NID_pilotOrganization}
  NID_pilotOrganization = 455;

  {$EXTERNALSYM LN_pilotDSA}
  LN_pilotDSA = 'pilotDSA';
  {$EXTERNALSYM NID_pilotDSA}
  NID_pilotDSA = 456;

  {$EXTERNALSYM LN_qualityLabelledData}
  LN_qualityLabelledData = 'qualityLabelledData';
  {$EXTERNALSYM NID_qualityLabelledData}
  NID_qualityLabelledData = 457;

  {$EXTERNALSYM SN_userId}
  SN_userId = 'UID';
  {$EXTERNALSYM LN_userId}
  LN_userId = 'userId';
  {$EXTERNALSYM NID_userId}
  NID_userId = 458;

  {$EXTERNALSYM LN_textEncodedORAddress}
  LN_textEncodedORAddress = 'textEncodedORAddress';
  {$EXTERNALSYM NID_textEncodedORAddress}
  NID_textEncodedORAddress = 459;

  {$EXTERNALSYM SN_rfc822Mailbox}
  SN_rfc822Mailbox = 'mail';
  {$EXTERNALSYM LN_rfc822Mailbox}
  LN_rfc822Mailbox = 'rfc822Mailbox';
  {$EXTERNALSYM NID_rfc822Mailbox}
  NID_rfc822Mailbox = 460;

  {$EXTERNALSYM SN_info}
  SN_info = 'info';
  {$EXTERNALSYM NID_info}
  NID_info = 461;

  {$EXTERNALSYM LN_favouriteDrink}
  LN_favouriteDrink = 'favouriteDrink';
  {$EXTERNALSYM NID_favouriteDrink}
  NID_favouriteDrink = 462;

  {$EXTERNALSYM LN_roomNumber}
  LN_roomNumber = 'roomNumber';
  {$EXTERNALSYM NID_roomNumber}
  NID_roomNumber = 463;

  {$EXTERNALSYM SN_photo}
  SN_photo = 'photo';
  {$EXTERNALSYM NID_photo}
  NID_photo = 464;

  {$EXTERNALSYM LN_userClass}
  LN_userClass = 'userClass';
  {$EXTERNALSYM NID_userClass}
  NID_userClass = 465;

  {$EXTERNALSYM SN_host}
  SN_host = 'host';
  {$EXTERNALSYM NID_host}
  NID_host = 466;

  {$EXTERNALSYM SN_manager}
  SN_manager = 'manager';
  {$EXTERNALSYM NID_manager}
  NID_manager = 467;

  {$EXTERNALSYM LN_documentIdentifier}
  LN_documentIdentifier = 'documentIdentifier';
  {$EXTERNALSYM NID_documentIdentifier}
  NID_documentIdentifier = 468;

  {$EXTERNALSYM LN_documentTitle}
  LN_documentTitle = 'documentTitle';
  {$EXTERNALSYM NID_documentTitle}
  NID_documentTitle = 469;

  {$EXTERNALSYM LN_documentVersion}
  LN_documentVersion = 'documentVersion';
  {$EXTERNALSYM NID_documentVersion}
  NID_documentVersion = 470;

  {$EXTERNALSYM LN_documentAuthor}
  LN_documentAuthor = 'documentAuthor';
  {$EXTERNALSYM NID_documentAuthor}
  NID_documentAuthor = 471;

  {$EXTERNALSYM LN_documentLocation}
  LN_documentLocation = 'documentLocation';
  {$EXTERNALSYM NID_documentLocation}
  NID_documentLocation = 472;

  {$EXTERNALSYM LN_homeTelephoneNumber}
  LN_homeTelephoneNumber = 'homeTelephoneNumber';
  {$EXTERNALSYM NID_homeTelephoneNumber}
  NID_homeTelephoneNumber = 473;

  {$EXTERNALSYM SN_secretary}
  SN_secretary = 'secretary';
  {$EXTERNALSYM NID_secretary}
  NID_secretary = 474;

  {$EXTERNALSYM LN_otherMailbox}
  LN_otherMailbox = 'otherMailbox';
  {$EXTERNALSYM NID_otherMailbox}
  NID_otherMailbox = 475;

  {$EXTERNALSYM LN_lastModifiedTime}
  LN_lastModifiedTime = 'lastModifiedTime';
  {$EXTERNALSYM NID_lastModifiedTime}
  NID_lastModifiedTime = 476;

  {$EXTERNALSYM LN_lastModifiedBy}
  LN_lastModifiedBy = 'lastModifiedBy';
  {$EXTERNALSYM NID_lastModifiedBy}
  NID_lastModifiedBy = 477;

  {$EXTERNALSYM SN_domainComponent}
  SN_domainComponent = 'DC';
  {$EXTERNALSYM LN_domainComponent}
  LN_domainComponent = 'domainComponent';
  {$EXTERNALSYM NID_domainComponent}
  NID_domainComponent = 391;

  {$EXTERNALSYM LN_aRecord}
  LN_aRecord = 'aRecord';
  {$EXTERNALSYM NID_aRecord}
  NID_aRecord = 478;

  {$EXTERNALSYM LN_pilotAttributeType27}
  LN_pilotAttributeType27 = 'pilotAttributeType27';
  {$EXTERNALSYM NID_pilotAttributeType27}
  NID_pilotAttributeType27 = 479;

  {$EXTERNALSYM LN_mXRecord}
  LN_mXRecord = 'mXRecord';
  {$EXTERNALSYM NID_mXRecord}
  NID_mXRecord = 480;

  {$EXTERNALSYM LN_nSRecord}
  LN_nSRecord = 'nSRecord';
  {$EXTERNALSYM NID_nSRecord}
  NID_nSRecord = 481;

  {$EXTERNALSYM LN_sOARecord}
  LN_sOARecord = 'sOARecord';
  {$EXTERNALSYM NID_sOARecord}
  NID_sOARecord = 482;

  {$EXTERNALSYM LN_cNAMERecord}
  LN_cNAMERecord = 'cNAMERecord';
  {$EXTERNALSYM NID_cNAMERecord}
  NID_cNAMERecord = 483;

  {$EXTERNALSYM LN_associatedDomain}
  LN_associatedDomain = 'associatedDomain';
  {$EXTERNALSYM NID_associatedDomain}
  NID_associatedDomain = 484;

  {$EXTERNALSYM LN_associatedName}
  LN_associatedName = 'associatedName';
  {$EXTERNALSYM NID_associatedName}
  NID_associatedName = 485;

  {$EXTERNALSYM LN_homePostalAddress}
  LN_homePostalAddress = 'homePostalAddress';
  {$EXTERNALSYM NID_homePostalAddress}
  NID_homePostalAddress = 486;

  {$EXTERNALSYM LN_personalTitle}
  LN_personalTitle = 'personalTitle';
  {$EXTERNALSYM NID_personalTitle}
  NID_personalTitle = 487;

  {$EXTERNALSYM LN_mobileTelephoneNumber}
  LN_mobileTelephoneNumber = 'mobileTelephoneNumber';
  {$EXTERNALSYM NID_mobileTelephoneNumber}
  NID_mobileTelephoneNumber = 488;

  {$EXTERNALSYM LN_pagerTelephoneNumber}
  LN_pagerTelephoneNumber = 'pagerTelephoneNumber';
  {$EXTERNALSYM NID_pagerTelephoneNumber}
  NID_pagerTelephoneNumber = 489;

  {$EXTERNALSYM LN_friendlyCountryName}
  LN_friendlyCountryName = 'friendlyCountryName';
  {$EXTERNALSYM NID_friendlyCountryName}
  NID_friendlyCountryName = 490;

  {$EXTERNALSYM SN_uniqueIdentifier}
  SN_uniqueIdentifier = 'uid';
  {$EXTERNALSYM LN_uniqueIdentifier}
  LN_uniqueIdentifier = 'uniqueIdentifier';
  {$EXTERNALSYM NID_uniqueIdentifier}
  NID_uniqueIdentifier = 102;

  {$EXTERNALSYM LN_organizationalStatus}
  LN_organizationalStatus = 'organizationalStatus';
  {$EXTERNALSYM NID_organizationalStatus}
  NID_organizationalStatus = 491;

  {$EXTERNALSYM LN_janetMailbox}
  LN_janetMailbox = 'janetMailbox';
  {$EXTERNALSYM NID_janetMailbox}
  NID_janetMailbox = 492;
  {$EXTERNALSYM LN_mailPreferenceOption}
  LN_mailPreferenceOption = 'mailPreferenceOption';
  {$EXTERNALSYM NID_mailPreferenceOption}
  NID_mailPreferenceOption = 493;

  {$EXTERNALSYM LN_buildingName}
  LN_buildingName = 'buildingName';
  {$EXTERNALSYM NID_buildingName}
  NID_buildingName = 494;

  {$EXTERNALSYM LN_dSAQuality}
  LN_dSAQuality = 'dSAQuality';
  {$EXTERNALSYM NID_dSAQuality}
  NID_dSAQuality = 495;

  {$EXTERNALSYM LN_singleLevelQuality}
  LN_singleLevelQuality = 'singleLevelQuality';
  {$EXTERNALSYM NID_singleLevelQuality}
  NID_singleLevelQuality = 496;

  {$EXTERNALSYM LN_subtreeMinimumQuality}
  LN_subtreeMinimumQuality = 'subtreeMinimumQuality';
  {$EXTERNALSYM NID_subtreeMinimumQuality}
  NID_subtreeMinimumQuality = 497;

  {$EXTERNALSYM LN_subtreeMaximumQuality}
  LN_subtreeMaximumQuality = 'subtreeMaximumQuality';
  {$EXTERNALSYM NID_subtreeMaximumQuality}
  NID_subtreeMaximumQuality = 498;

  {$EXTERNALSYM LN_personalSignature}
  LN_personalSignature = 'personalSignature';
  {$EXTERNALSYM NID_personalSignature}
  NID_personalSignature = 499;

  {$EXTERNALSYM LN_dITRedirect}
  LN_dITRedirect = 'dITRedirect';
  {$EXTERNALSYM NID_dITRedirect}
  NID_dITRedirect = 500;

  {$EXTERNALSYM SN_audio}
  SN_audio = 'audio';
  {$EXTERNALSYM NID_audio}
  NID_audio = 501;

  {$EXTERNALSYM LN_documentPublisher}
  LN_documentPublisher = 'documentPublisher';
  {$EXTERNALSYM NID_documentPublisher}
  NID_documentPublisher = 502;

  {$EXTERNALSYM SN_id_set}
  SN_id_set = 'id-set';
  {$EXTERNALSYM LN_id_set}
  LN_id_set = 'Secure Electronic Transactions';
  {$EXTERNALSYM NID_id_set}
  NID_id_set = 512;

  {$EXTERNALSYM SN_set_ctype}
  SN_set_ctype = 'set-ctype';
  {$EXTERNALSYM LN_set_ctype}
  LN_set_ctype = 'content types';
  {$EXTERNALSYM NID_set_ctype}
  NID_set_ctype = 513;

  {$EXTERNALSYM SN_set_msgExt}
  SN_set_msgExt = 'set-msgExt';
  {$EXTERNALSYM LN_set_msgExt}
  LN_set_msgExt = 'message extensions';
  {$EXTERNALSYM NID_set_msgExt}
  NID_set_msgExt = 514;

  {$EXTERNALSYM SN_set_attr}
  SN_set_attr = 'set-attr';
  {$EXTERNALSYM NID_set_attr}
  NID_set_attr = 515;

  {$EXTERNALSYM SN_set_policy}
  SN_set_policy = 'set-policy';
  {$EXTERNALSYM NID_set_policy}
  NID_set_policy = 516;

  {$EXTERNALSYM SN_set_certExt}
  SN_set_certExt = 'set-certExt';
  {$EXTERNALSYM LN_set_certExt}
  LN_set_certExt = 'certificate extensions';
  {$EXTERNALSYM NID_set_certExt}
  NID_set_certExt = 517;

  {$EXTERNALSYM SN_set_brand}
  SN_set_brand = 'set-brand';
  {$EXTERNALSYM NID_set_brand}
  NID_set_brand = 518;

  {$EXTERNALSYM SN_setct_PANData}
  SN_setct_PANData = 'setct-PANData';
  {$EXTERNALSYM NID_setct_PANData}
  NID_setct_PANData = 519;

  {$EXTERNALSYM SN_setct_PANToken}
  SN_setct_PANToken = 'setct-PANToken';
  {$EXTERNALSYM NID_setct_PANToken}
  NID_setct_PANToken = 520;

  {$EXTERNALSYM SN_setct_PANOnly}
  SN_setct_PANOnly = 'setct-PANOnly';
  {$EXTERNALSYM NID_setct_PANOnly}
  NID_setct_PANOnly = 521;

  {$EXTERNALSYM SN_setct_OIData}
  SN_setct_OIData = 'setct-OIData';
  {$EXTERNALSYM NID_setct_OIData}
  NID_setct_OIData = 522;

  {$EXTERNALSYM SN_setct_PI}
  SN_setct_PI = 'setct-PI';
  {$EXTERNALSYM NID_setct_PI}
  NID_setct_PI = 523;

  {$EXTERNALSYM SN_setct_PIData}
  SN_setct_PIData = 'setct-PIData';
  {$EXTERNALSYM NID_setct_PIData}
  NID_setct_PIData = 524;

  {$EXTERNALSYM SN_setct_PIDataUnsigned}
  SN_setct_PIDataUnsigned = 'setct-PIDataUnsigned';
  {$EXTERNALSYM NID_setct_PIDataUnsigned}
  NID_setct_PIDataUnsigned = 525;

  {$EXTERNALSYM SN_setct_HODInput}
  SN_setct_HODInput = 'setct-HODInput';
  {$EXTERNALSYM NID_setct_HODInput}
  NID_setct_HODInput = 526;

  {$EXTERNALSYM SN_setct_AuthResBaggage}
  SN_setct_AuthResBaggage = 'setct-AuthResBaggage';
  {$EXTERNALSYM NID_setct_AuthResBaggage}
  NID_setct_AuthResBaggage = 527;

  {$EXTERNALSYM SN_setct_AuthRevReqBaggage}
  SN_setct_AuthRevReqBaggage = 'setct-AuthRevReqBaggage';
  {$EXTERNALSYM NID_setct_AuthRevReqBaggage}
  NID_setct_AuthRevReqBaggage = 528;

  {$EXTERNALSYM SN_setct_AuthRevResBaggage}
  SN_setct_AuthRevResBaggage = 'setct-AuthRevResBaggage';
  {$EXTERNALSYM NID_setct_AuthRevResBaggage}
  NID_setct_AuthRevResBaggage = 529;

  {$EXTERNALSYM SN_setct_CapTokenSeq}
  SN_setct_CapTokenSeq = 'setct-CapTokenSeq';
  {$EXTERNALSYM NID_setct_CapTokenSeq}
  NID_setct_CapTokenSeq = 530;

  {$EXTERNALSYM SN_setct_PInitResData}
  SN_setct_PInitResData = 'setct-PInitResData';
  {$EXTERNALSYM NID_setct_PInitResData}
  NID_setct_PInitResData = 531;

  {$EXTERNALSYM SN_setct_PI_TBS}
  SN_setct_PI_TBS = 'setct-PI-TBS';
  {$EXTERNALSYM NID_setct_PI_TBS}
  NID_setct_PI_TBS = 532;

  {$EXTERNALSYM SN_setct_PResData}
  SN_setct_PResData = 'setct-PResData';
  {$EXTERNALSYM NID_setct_PResData}
  NID_setct_PResData = 533;

  {$EXTERNALSYM SN_setct_AuthReqTBS}
  SN_setct_AuthReqTBS = 'setct-AuthReqTBS';
  {$EXTERNALSYM NID_setct_AuthReqTBS}
  NID_setct_AuthReqTBS = 534;

  {$EXTERNALSYM SN_setct_AuthResTBS}
  SN_setct_AuthResTBS = 'setct-AuthResTBS';
  {$EXTERNALSYM NID_setct_AuthResTBS}
  NID_setct_AuthResTBS = 535;

  {$EXTERNALSYM SN_setct_AuthResTBSX}
  SN_setct_AuthResTBSX = 'setct-AuthResTBSX';
  {$EXTERNALSYM NID_setct_AuthResTBSX}
  NID_setct_AuthResTBSX = 536;

  {$EXTERNALSYM SN_setct_AuthTokenTBS}
  SN_setct_AuthTokenTBS = 'setct-AuthTokenTBS';
  {$EXTERNALSYM NID_setct_AuthTokenTBS}
  NID_setct_AuthTokenTBS = 537;

  {$EXTERNALSYM SN_setct_CapTokenData}
  SN_setct_CapTokenData = 'setct-CapTokenData';
  {$EXTERNALSYM NID_setct_CapTokenData}
  NID_setct_CapTokenData = 538;

  {$EXTERNALSYM SN_setct_CapTokenTBS}
  SN_setct_CapTokenTBS = 'setct-CapTokenTBS';
  {$EXTERNALSYM NID_setct_CapTokenTBS}
  NID_setct_CapTokenTBS = 539;

  {$EXTERNALSYM SN_setct_AcqCardCodeMsg}
  SN_setct_AcqCardCodeMsg = 'setct-AcqCardCodeMsg';
  {$EXTERNALSYM NID_setct_AcqCardCodeMsg}
  NID_setct_AcqCardCodeMsg = 540;

  {$EXTERNALSYM SN_setct_AuthRevReqTBS}
  SN_setct_AuthRevReqTBS = 'setct-AuthRevReqTBS';
  {$EXTERNALSYM NID_setct_AuthRevReqTBS}
  NID_setct_AuthRevReqTBS = 541;

  {$EXTERNALSYM SN_setct_AuthRevResData}
  SN_setct_AuthRevResData = 'setct-AuthRevResData';
  {$EXTERNALSYM NID_setct_AuthRevResData}
  NID_setct_AuthRevResData = 542;

  {$EXTERNALSYM SN_setct_AuthRevResTBS}
  SN_setct_AuthRevResTBS = 'setct-AuthRevResTBS';
  {$EXTERNALSYM NID_setct_AuthRevResTBS}
  NID_setct_AuthRevResTBS = 543;

  {$EXTERNALSYM SN_setct_CapReqTBS}
  SN_setct_CapReqTBS = 'setct-CapReqTBS';
  {$EXTERNALSYM NID_setct_CapReqTBS}
  NID_setct_CapReqTBS = 544;

  {$EXTERNALSYM SN_setct_CapReqTBSX}
  SN_setct_CapReqTBSX = 'setct-CapReqTBSX';
  {$EXTERNALSYM NID_setct_CapReqTBSX}
  NID_setct_CapReqTBSX = 545;

  {$EXTERNALSYM SN_setct_CapResData}
  SN_setct_CapResData = 'setct-CapResData';
  {$EXTERNALSYM NID_setct_CapResData}
  NID_setct_CapResData = 546;

  {$EXTERNALSYM SN_setct_CapRevReqTBS}
  SN_setct_CapRevReqTBS = 'setct-CapRevReqTBS';
  {$EXTERNALSYM NID_setct_CapRevReqTBS}
  NID_setct_CapRevReqTBS = 547;

  {$EXTERNALSYM SN_setct_CapRevReqTBSX}
  SN_setct_CapRevReqTBSX = 'setct-CapRevReqTBSX';
  {$EXTERNALSYM NID_setct_CapRevReqTBSX}
  NID_setct_CapRevReqTBSX = 548;

  {$EXTERNALSYM SN_setct_CapRevResData}
  SN_setct_CapRevResData = 'setct-CapRevResData';
  {$EXTERNALSYM NID_setct_CapRevResData}
  NID_setct_CapRevResData = 549;

  {$EXTERNALSYM SN_setct_CredReqTBS}
  SN_setct_CredReqTBS = 'setct-CredReqTBS';
  {$EXTERNALSYM NID_setct_CredReqTBS}
  NID_setct_CredReqTBS = 550;

  {$EXTERNALSYM SN_setct_CredReqTBSX}
  SN_setct_CredReqTBSX = 'setct-CredReqTBSX';
  {$EXTERNALSYM NID_setct_CredReqTBSX}
  NID_setct_CredReqTBSX = 551;

  {$EXTERNALSYM SN_setct_CredResData}
  SN_setct_CredResData = 'setct-CredResData';
  {$EXTERNALSYM NID_setct_CredResData}
  NID_setct_CredResData = 552;

  {$EXTERNALSYM SN_setct_CredRevReqTBS}
  SN_setct_CredRevReqTBS = 'setct-CredRevReqTBS';
  {$EXTERNALSYM NID_setct_CredRevReqTBS}
  NID_setct_CredRevReqTBS = 553;

  {$EXTERNALSYM SN_setct_CredRevReqTBSX}
  SN_setct_CredRevReqTBSX = 'setct-CredRevReqTBSX';
  {$EXTERNALSYM NID_setct_CredRevReqTBSX}
  NID_setct_CredRevReqTBSX = 554;

  {$EXTERNALSYM SN_setct_CredRevResData}
  SN_setct_CredRevResData = 'setct-CredRevResData';
  {$EXTERNALSYM NID_setct_CredRevResData}
  NID_setct_CredRevResData = 555;

  {$EXTERNALSYM SN_setct_PCertReqData}
  SN_setct_PCertReqData = 'setct-PCertReqData';
  {$EXTERNALSYM NID_setct_PCertReqData}
  NID_setct_PCertReqData = 556;

  {$EXTERNALSYM SN_setct_PCertResTBS}
  SN_setct_PCertResTBS = 'setct-PCertResTBS';
  {$EXTERNALSYM NID_setct_PCertResTBS}
  NID_setct_PCertResTBS = 557;

  {$EXTERNALSYM SN_setct_BatchAdminReqData}
  SN_setct_BatchAdminReqData = 'setct-BatchAdminReqData';
  {$EXTERNALSYM NID_setct_BatchAdminReqData}
  NID_setct_BatchAdminReqData = 558;

  {$EXTERNALSYM SN_setct_BatchAdminResData}
  SN_setct_BatchAdminResData = 'setct-BatchAdminResData';
  {$EXTERNALSYM NID_setct_BatchAdminResData}
  NID_setct_BatchAdminResData = 559;

  {$EXTERNALSYM SN_setct_CardCInitResTBS}
  SN_setct_CardCInitResTBS = 'setct-CardCInitResTBS';
  {$EXTERNALSYM NID_setct_CardCInitResTBS}
  NID_setct_CardCInitResTBS = 560;

  {$EXTERNALSYM SN_setct_MeAqCInitResTBS}
  SN_setct_MeAqCInitResTBS = 'setct-MeAqCInitResTBS';
  {$EXTERNALSYM NID_setct_MeAqCInitResTBS}
  NID_setct_MeAqCInitResTBS = 561;

  {$EXTERNALSYM SN_setct_RegFormResTBS}
  SN_setct_RegFormResTBS = 'setct-RegFormResTBS';
  {$EXTERNALSYM NID_setct_RegFormResTBS}
  NID_setct_RegFormResTBS = 562;

  {$EXTERNALSYM SN_setct_CertReqData}
  SN_setct_CertReqData = 'setct-CertReqData';
  {$EXTERNALSYM NID_setct_CertReqData}
  NID_setct_CertReqData = 563;

  {$EXTERNALSYM SN_setct_CertReqTBS}
  SN_setct_CertReqTBS = 'setct-CertReqTBS';
  {$EXTERNALSYM NID_setct_CertReqTBS}
  NID_setct_CertReqTBS = 564;

  {$EXTERNALSYM SN_setct_CertResData}
  SN_setct_CertResData = 'setct-CertResData';
  {$EXTERNALSYM NID_setct_CertResData}
  NID_setct_CertResData = 565;

  {$EXTERNALSYM SN_setct_CertInqReqTBS}
  SN_setct_CertInqReqTBS = 'setct-CertInqReqTBS';
  {$EXTERNALSYM NID_setct_CertInqReqTBS}
  NID_setct_CertInqReqTBS = 566;

  {$EXTERNALSYM SN_setct_ErrorTBS}
  SN_setct_ErrorTBS = 'setct-ErrorTBS';
  {$EXTERNALSYM NID_setct_ErrorTBS}
  NID_setct_ErrorTBS = 567;

  {$EXTERNALSYM SN_setct_PIDualSignedTBE}
  SN_setct_PIDualSignedTBE = 'setct-PIDualSignedTBE';
  {$EXTERNALSYM NID_setct_PIDualSignedTBE}
  NID_setct_PIDualSignedTBE = 568;

  {$EXTERNALSYM SN_setct_PIUnsignedTBE}
  SN_setct_PIUnsignedTBE = 'setct-PIUnsignedTBE';
  {$EXTERNALSYM NID_setct_PIUnsignedTBE}
  NID_setct_PIUnsignedTBE = 569;

  {$EXTERNALSYM SN_setct_AuthReqTBE}
  SN_setct_AuthReqTBE = 'setct-AuthReqTBE';
  {$EXTERNALSYM NID_setct_AuthReqTBE}
  NID_setct_AuthReqTBE = 570;

  {$EXTERNALSYM SN_setct_AuthResTBE}
  SN_setct_AuthResTBE = 'setct-AuthResTBE';
  {$EXTERNALSYM NID_setct_AuthResTBE}
  NID_setct_AuthResTBE = 571;

  {$EXTERNALSYM SN_setct_AuthResTBEX}
  SN_setct_AuthResTBEX = 'setct-AuthResTBEX';
  {$EXTERNALSYM NID_setct_AuthResTBEX}
  NID_setct_AuthResTBEX = 572;

  {$EXTERNALSYM SN_setct_AuthTokenTBE}
  SN_setct_AuthTokenTBE = 'setct-AuthTokenTBE';
  {$EXTERNALSYM NID_setct_AuthTokenTBE}
  NID_setct_AuthTokenTBE = 573;

  {$EXTERNALSYM SN_setct_CapTokenTBE}
  SN_setct_CapTokenTBE = 'setct-CapTokenTBE';
  {$EXTERNALSYM NID_setct_CapTokenTBE}
  NID_setct_CapTokenTBE = 574;

  {$EXTERNALSYM SN_setct_CapTokenTBEX}
  SN_setct_CapTokenTBEX = 'setct-CapTokenTBEX';
  {$EXTERNALSYM NID_setct_CapTokenTBEX}
  NID_setct_CapTokenTBEX = 575;

  {$EXTERNALSYM SN_setct_AcqCardCodeMsgTBE}
  SN_setct_AcqCardCodeMsgTBE = 'setct-AcqCardCodeMsgTBE';
  {$EXTERNALSYM NID_setct_AcqCardCodeMsgTBE}
  NID_setct_AcqCardCodeMsgTBE = 576;

  {$EXTERNALSYM SN_setct_AuthRevReqTBE}
  SN_setct_AuthRevReqTBE = 'setct-AuthRevReqTBE';
  {$EXTERNALSYM NID_setct_AuthRevReqTBE}
  NID_setct_AuthRevReqTBE = 577;

  {$EXTERNALSYM SN_setct_AuthRevResTBE}
  SN_setct_AuthRevResTBE = 'setct-AuthRevResTBE';
  {$EXTERNALSYM NID_setct_AuthRevResTBE}
  NID_setct_AuthRevResTBE = 578;

  {$EXTERNALSYM SN_setct_AuthRevResTBEB}
  SN_setct_AuthRevResTBEB = 'setct-AuthRevResTBEB';
  {$EXTERNALSYM NID_setct_AuthRevResTBEB}
  NID_setct_AuthRevResTBEB = 579;

  {$EXTERNALSYM SN_setct_CapReqTBE}
  SN_setct_CapReqTBE = 'setct-CapReqTBE';
  {$EXTERNALSYM NID_setct_CapReqTBE}
  NID_setct_CapReqTBE = 580;

  {$EXTERNALSYM SN_setct_CapReqTBEX}
  SN_setct_CapReqTBEX = 'setct-CapReqTBEX';
  {$EXTERNALSYM NID_setct_CapReqTBEX}
  NID_setct_CapReqTBEX = 581;

  {$EXTERNALSYM SN_setct_CapResTBE}
  SN_setct_CapResTBE = 'setct-CapResTBE';
  {$EXTERNALSYM NID_setct_CapResTBE}
  NID_setct_CapResTBE = 582;

  {$EXTERNALSYM SN_setct_CapRevReqTBE}
  SN_setct_CapRevReqTBE = 'setct-CapRevReqTBE';
  {$EXTERNALSYM NID_setct_CapRevReqTBE}
  NID_setct_CapRevReqTBE = 583;

  {$EXTERNALSYM SN_setct_CapRevReqTBEX}
  SN_setct_CapRevReqTBEX = 'setct-CapRevReqTBEX';
  {$EXTERNALSYM NID_setct_CapRevReqTBEX}
  NID_setct_CapRevReqTBEX = 584;

  {$EXTERNALSYM SN_setct_CapRevResTBE}
  SN_setct_CapRevResTBE = 'setct-CapRevResTBE';
  {$EXTERNALSYM NID_setct_CapRevResTBE}
  NID_setct_CapRevResTBE = 585;

  {$EXTERNALSYM SN_setct_CredReqTBE}
  SN_setct_CredReqTBE = 'setct-CredReqTBE';
  {$EXTERNALSYM NID_setct_CredReqTBE}
  NID_setct_CredReqTBE = 586;

  {$EXTERNALSYM SN_setct_CredReqTBEX}
  SN_setct_CredReqTBEX = 'setct-CredReqTBEX';
  {$EXTERNALSYM NID_setct_CredReqTBEX}
  NID_setct_CredReqTBEX = 587;

  {$EXTERNALSYM SN_setct_CredResTBE}
  SN_setct_CredResTBE = 'setct-CredResTBE';
  {$EXTERNALSYM NID_setct_CredResTBE}
  NID_setct_CredResTBE = 588;

  {$EXTERNALSYM SN_setct_CredRevReqTBE}
  SN_setct_CredRevReqTBE = 'setct-CredRevReqTBE';
  {$EXTERNALSYM NID_setct_CredRevReqTBE}
  NID_setct_CredRevReqTBE = 589;

  {$EXTERNALSYM SN_setct_CredRevReqTBEX}
  SN_setct_CredRevReqTBEX = 'setct-CredRevReqTBEX';
  {$EXTERNALSYM NID_setct_CredRevReqTBEX}
  NID_setct_CredRevReqTBEX = 590;

  {$EXTERNALSYM SN_setct_CredRevResTBE}
  SN_setct_CredRevResTBE = 'setct-CredRevResTBE';
  {$EXTERNALSYM NID_setct_CredRevResTBE}
  NID_setct_CredRevResTBE = 591;

  {$EXTERNALSYM SN_setct_BatchAdminReqTBE}
  SN_setct_BatchAdminReqTBE = 'setct-BatchAdminReqTBE';
  {$EXTERNALSYM NID_setct_BatchAdminReqTBE}
  NID_setct_BatchAdminReqTBE = 592;

  {$EXTERNALSYM SN_setct_BatchAdminResTBE}
  SN_setct_BatchAdminResTBE = 'setct-BatchAdminResTBE';
  {$EXTERNALSYM NID_setct_BatchAdminResTBE}
  NID_setct_BatchAdminResTBE = 593;

  {$EXTERNALSYM SN_setct_RegFormReqTBE}
  SN_setct_RegFormReqTBE = 'setct-RegFormReqTBE';
  {$EXTERNALSYM NID_setct_RegFormReqTBE}
  NID_setct_RegFormReqTBE = 594;

  {$EXTERNALSYM SN_setct_CertReqTBE}
  SN_setct_CertReqTBE = 'setct-CertReqTBE';
  {$EXTERNALSYM NID_setct_CertReqTBE}
  NID_setct_CertReqTBE = 595;

  {$EXTERNALSYM SN_setct_CertReqTBEX}
  SN_setct_CertReqTBEX = 'setct-CertReqTBEX';
  {$EXTERNALSYM NID_setct_CertReqTBEX}
  NID_setct_CertReqTBEX = 596;

  {$EXTERNALSYM SN_setct_CertResTBE}
  SN_setct_CertResTBE = 'setct-CertResTBE';
  {$EXTERNALSYM NID_setct_CertResTBE}
  NID_setct_CertResTBE = 597;

  {$EXTERNALSYM SN_setct_CRLNotificationTBS}
  SN_setct_CRLNotificationTBS = 'setct-CRLNotificationTBS';
  {$EXTERNALSYM NID_setct_CRLNotificationTBS}
  NID_setct_CRLNotificationTBS = 598;

  {$EXTERNALSYM SN_setct_CRLNotificationResTBS}
  SN_setct_CRLNotificationResTBS = 'setct-CRLNotificationResTBS';
  {$EXTERNALSYM NID_setct_CRLNotificationResTBS}
  NID_setct_CRLNotificationResTBS = 599;

  {$EXTERNALSYM SN_setct_BCIDistributionTBS}
  SN_setct_BCIDistributionTBS = 'setct-BCIDistributionTBS';
  {$EXTERNALSYM NID_setct_BCIDistributionTBS}
  NID_setct_BCIDistributionTBS = 600;

  {$EXTERNALSYM SN_setext_genCrypt}
  SN_setext_genCrypt = 'setext-genCrypt';
  {$EXTERNALSYM LN_setext_genCrypt}
  LN_setext_genCrypt = 'generic cryptogram';
  {$EXTERNALSYM NID_setext_genCrypt}
  NID_setext_genCrypt = 601;

  {$EXTERNALSYM SN_setext_miAuth}
  SN_setext_miAuth = 'setext-miAuth';
  {$EXTERNALSYM LN_setext_miAuth}
  LN_setext_miAuth = 'merchant initiated auth';
  {$EXTERNALSYM NID_setext_miAuth}
  NID_setext_miAuth = 602;

  {$EXTERNALSYM SN_setext_pinSecure}
  SN_setext_pinSecure = 'setext-pinSecure';
  {$EXTERNALSYM NID_setext_pinSecure}
  NID_setext_pinSecure = 603;

  {$EXTERNALSYM SN_setext_pinAny}
  SN_setext_pinAny = 'setext-pinAny';
  {$EXTERNALSYM NID_setext_pinAny}
  NID_setext_pinAny = 604;

  {$EXTERNALSYM SN_setext_track2}
  SN_setext_track2 = 'setext-track2';
  {$EXTERNALSYM NID_setext_track2}
  NID_setext_track2 = 605;

  {$EXTERNALSYM SN_setext_cv}
  SN_setext_cv = 'setext-cv';
  {$EXTERNALSYM LN_setext_cv}
  LN_setext_cv = 'additional verification';
  {$EXTERNALSYM NID_setext_cv}
  NID_setext_cv = 606;

  {$EXTERNALSYM SN_set_policy_root}
  SN_set_policy_root = 'set-policy-root';
  {$EXTERNALSYM NID_set_policy_root}
  NID_set_policy_root = 607;

  {$EXTERNALSYM SN_setCext_hashedRoot}
  SN_setCext_hashedRoot = 'setCext-hashedRoot';
  {$EXTERNALSYM NID_setCext_hashedRoot}
  NID_setCext_hashedRoot = 608;

  {$EXTERNALSYM SN_setCext_certType}
  SN_setCext_certType = 'setCext-certType';
  {$EXTERNALSYM NID_setCext_certType}
  NID_setCext_certType = 609;

  {$EXTERNALSYM SN_setCext_merchData}
  SN_setCext_merchData = 'setCext-merchData';
  {$EXTERNALSYM NID_setCext_merchData}
  NID_setCext_merchData = 610;

  {$EXTERNALSYM SN_setCext_cCertRequired}
  SN_setCext_cCertRequired = 'setCext-cCertRequired';
  {$EXTERNALSYM NID_setCext_cCertRequired}
  NID_setCext_cCertRequired = 611;

  {$EXTERNALSYM SN_setCext_tunneling}
  SN_setCext_tunneling = 'setCext-tunneling';
  {$EXTERNALSYM NID_setCext_tunneling}
  NID_setCext_tunneling = 612;

  {$EXTERNALSYM SN_setCext_setExt}
  SN_setCext_setExt = 'setCext-setExt';
  {$EXTERNALSYM NID_setCext_setExt}
  NID_setCext_setExt = 613;

  {$EXTERNALSYM SN_setCext_setQualf}
  SN_setCext_setQualf = 'setCext-setQualf';
  {$EXTERNALSYM NID_setCext_setQualf}
  NID_setCext_setQualf = 614;

  {$EXTERNALSYM SN_setCext_PGWYcapabilities}
  SN_setCext_PGWYcapabilities = 'setCext-PGWYcapabilities';
  {$EXTERNALSYM NID_setCext_PGWYcapabilities}
  NID_setCext_PGWYcapabilities = 615;

  {$EXTERNALSYM SN_setCext_TokenIdentifier}
  SN_setCext_TokenIdentifier = 'setCext-TokenIdentifier';
  {$EXTERNALSYM NID_setCext_TokenIdentifier}
  NID_setCext_TokenIdentifier = 616;

  {$EXTERNALSYM SN_setCext_Track2Data}
  SN_setCext_Track2Data = 'setCext-Track2Data';
  {$EXTERNALSYM NID_setCext_Track2Data}
  NID_setCext_Track2Data = 617;

  {$EXTERNALSYM SN_setCext_TokenType}
  SN_setCext_TokenType = 'setCext-TokenType';
  {$EXTERNALSYM NID_setCext_TokenType}
  NID_setCext_TokenType = 618;

  {$EXTERNALSYM SN_setCext_IssuerCapabilities}
  SN_setCext_IssuerCapabilities = 'setCext-IssuerCapabilities';
  {$EXTERNALSYM NID_setCext_IssuerCapabilities}
  NID_setCext_IssuerCapabilities = 619;

  {$EXTERNALSYM SN_setAttr_Cert}
  SN_setAttr_Cert = 'setAttr-Cert';
  {$EXTERNALSYM NID_setAttr_Cert}
  NID_setAttr_Cert = 620;

  {$EXTERNALSYM SN_setAttr_PGWYcap}
  SN_setAttr_PGWYcap = 'setAttr-PGWYcap';
  {$EXTERNALSYM LN_setAttr_PGWYcap}
  LN_setAttr_PGWYcap = 'payment gateway capabilities';
  {$EXTERNALSYM NID_setAttr_PGWYcap}
  NID_setAttr_PGWYcap = 621;

  {$EXTERNALSYM SN_setAttr_TokenType}
  SN_setAttr_TokenType = 'setAttr-TokenType';
  {$EXTERNALSYM NID_setAttr_TokenType}
  NID_setAttr_TokenType = 622;

  {$EXTERNALSYM SN_setAttr_IssCap}
  SN_setAttr_IssCap = 'setAttr-IssCap';
  {$EXTERNALSYM LN_setAttr_IssCap}
  LN_setAttr_IssCap = 'issuer capabilities';
  {$EXTERNALSYM NID_setAttr_IssCap}
  NID_setAttr_IssCap = 623;

  {$EXTERNALSYM SN_set_rootKeyThumb}
  SN_set_rootKeyThumb = 'set-rootKeyThumb';
  {$EXTERNALSYM NID_set_rootKeyThumb}
  NID_set_rootKeyThumb = 624;

  {$EXTERNALSYM SN_set_addPolicy}
  SN_set_addPolicy = 'set-addPolicy';
  {$EXTERNALSYM NID_set_addPolicy}
  NID_set_addPolicy = 625;

  {$EXTERNALSYM SN_setAttr_Token_EMV}
  SN_setAttr_Token_EMV = 'setAttr-Token-EMV';
  {$EXTERNALSYM NID_setAttr_Token_EMV}
  NID_setAttr_Token_EMV = 626;

  {$EXTERNALSYM SN_setAttr_Token_B0Prime}
  SN_setAttr_Token_B0Prime = 'setAttr-Token-B0Prime';
  {$EXTERNALSYM NID_setAttr_Token_B0Prime}
  NID_setAttr_Token_B0Prime = 627;

  {$EXTERNALSYM SN_setAttr_IssCap_CVM}
  SN_setAttr_IssCap_CVM = 'setAttr-IssCap-CVM';
  {$EXTERNALSYM NID_setAttr_IssCap_CVM}
  NID_setAttr_IssCap_CVM = 628;

  {$EXTERNALSYM SN_setAttr_IssCap_T2}
  SN_setAttr_IssCap_T2 = 'setAttr-IssCap-T2';
  {$EXTERNALSYM NID_setAttr_IssCap_T2}
  NID_setAttr_IssCap_T2 = 629;

  {$EXTERNALSYM SN_setAttr_IssCap_Sig}
  SN_setAttr_IssCap_Sig = 'setAttr-IssCap-Sig';
  {$EXTERNALSYM NID_setAttr_IssCap_Sig}
  NID_setAttr_IssCap_Sig = 630;

  {$EXTERNALSYM SN_setAttr_GenCryptgrm}
  SN_setAttr_GenCryptgrm = 'setAttr-GenCryptgrm';
  {$EXTERNALSYM LN_setAttr_GenCryptgrm}
  LN_setAttr_GenCryptgrm = 'generate cryptogram';
  {$EXTERNALSYM NID_setAttr_GenCryptgrm}
  NID_setAttr_GenCryptgrm = 631;

  {$EXTERNALSYM SN_setAttr_T2Enc}
  SN_setAttr_T2Enc = 'setAttr-T2Enc';
  {$EXTERNALSYM LN_setAttr_T2Enc}
  LN_setAttr_T2Enc = 'encrypted track 2';
  {$EXTERNALSYM NID_setAttr_T2Enc}
  NID_setAttr_T2Enc = 632;

  {$EXTERNALSYM SN_setAttr_T2cleartxt}
  SN_setAttr_T2cleartxt = 'setAttr-T2cleartxt';
  {$EXTERNALSYM LN_setAttr_T2cleartxt}
  LN_setAttr_T2cleartxt = 'cleartext track 2';
  {$EXTERNALSYM NID_setAttr_T2cleartxt}
  NID_setAttr_T2cleartxt = 633;

  {$EXTERNALSYM SN_setAttr_TokICCsig}
  SN_setAttr_TokICCsig = 'setAttr-TokICCsig';
  {$EXTERNALSYM LN_setAttr_TokICCsig}
  LN_setAttr_TokICCsig = 'ICC or token signature';
  {$EXTERNALSYM NID_setAttr_TokICCsig}
  NID_setAttr_TokICCsig = 634;

  {$EXTERNALSYM SN_setAttr_SecDevSig}
  SN_setAttr_SecDevSig = 'setAttr-SecDevSig';
  {$EXTERNALSYM LN_setAttr_SecDevSig}
  LN_setAttr_SecDevSig = 'secure device signature';
  {$EXTERNALSYM NID_setAttr_SecDevSig}
  NID_setAttr_SecDevSig = 635;

  {$EXTERNALSYM SN_set_brand_IATA_ATA}
  SN_set_brand_IATA_ATA = 'set-brand-IATA-ATA';
  {$EXTERNALSYM NID_set_brand_IATA_ATA}
  NID_set_brand_IATA_ATA = 636;

  {$EXTERNALSYM SN_set_brand_Diners}
  SN_set_brand_Diners = 'set-brand-Diners';
  {$EXTERNALSYM NID_set_brand_Diners}
  NID_set_brand_Diners = 637;

  {$EXTERNALSYM SN_set_brand_AmericanExpress}
  SN_set_brand_AmericanExpress = 'set-brand-AmericanExpress';
  {$EXTERNALSYM NID_set_brand_AmericanExpress}
  NID_set_brand_AmericanExpress = 638;

  {$EXTERNALSYM SN_set_brand_JCB}
  SN_set_brand_JCB = 'set-brand-JCB';
  {$EXTERNALSYM NID_set_brand_JCB}
  NID_set_brand_JCB = 639;

  {$EXTERNALSYM SN_set_brand_Visa}
  SN_set_brand_Visa = 'set-brand-Visa';
  {$EXTERNALSYM NID_set_brand_Visa}
  NID_set_brand_Visa = 640;

  {$EXTERNALSYM SN_set_brand_MasterCard}
  SN_set_brand_MasterCard = 'set-brand-MasterCard';
  {$EXTERNALSYM NID_set_brand_MasterCard}
  NID_set_brand_MasterCard = 641;

  {$EXTERNALSYM SN_set_brand_Novus}
  SN_set_brand_Novus = 'set-brand-Novus';
  {$EXTERNALSYM NID_set_brand_Novus}
  NID_set_brand_Novus = 642;

  {$EXTERNALSYM SN_des_cdmf}
  SN_des_cdmf = 'DES-CDMF';
  {$EXTERNALSYM LN_des_cdmf}
  LN_des_cdmf = 'des-cdmf';
  {$EXTERNALSYM NID_des_cdmf}
  NID_des_cdmf = 643;

  {$EXTERNALSYM SN_rsaOAEPEncryptionSET}
  SN_rsaOAEPEncryptionSET = 'rsaOAEPEncryptionSET';
  {$EXTERNALSYM NID_rsaOAEPEncryptionSET}
  NID_rsaOAEPEncryptionSET = 644;

  {$EXTERNALSYM SN_ipsec3}
  SN_ipsec3 = 'Oakley-EC2N-3';
  {$EXTERNALSYM LN_ipsec3}
  LN_ipsec3 = 'ipsec3';
  {$EXTERNALSYM NID_ipsec3}
  NID_ipsec3 = 749;

  {$EXTERNALSYM SN_ipsec4}
  SN_ipsec4 = 'Oakley-EC2N-4';
  {$EXTERNALSYM LN_ipsec4}
  LN_ipsec4 = 'ipsec4';
  {$EXTERNALSYM NID_ipsec4}
  NID_ipsec4 = 750;

  {$EXTERNALSYM SN_whirlpool}
  SN_whirlpool = 'whirlpool';
  {$EXTERNALSYM NID_whirlpool}
  NID_whirlpool = 804;

  {$EXTERNALSYM SN_cryptopro}
  SN_cryptopro = 'cryptopro';
  {$EXTERNALSYM NID_cryptopro}
  NID_cryptopro = 805;

  {$EXTERNALSYM SN_cryptocom}
  SN_cryptocom = 'cryptocom';
  {$EXTERNALSYM NID_cryptocom}
  NID_cryptocom = 806;

  {$EXTERNALSYM SN_id_tc26}
  SN_id_tc26 = 'id-tc26';
  {$EXTERNALSYM NID_id_tc26}
  NID_id_tc26 = 974;

  {$EXTERNALSYM SN_id_GostR3411_94_with_GostR3410_2001}
  SN_id_GostR3411_94_with_GostR3410_2001 = 'id-GostR3411-94-with-GostR3410-2001';
  {$EXTERNALSYM LN_id_GostR3411_94_with_GostR3410_2001}
  LN_id_GostR3411_94_with_GostR3410_2001 = 'GOST R 34.11-94 with GOST R 34.10-2001';
  {$EXTERNALSYM NID_id_GostR3411_94_with_GostR3410_2001}
  NID_id_GostR3411_94_with_GostR3410_2001 = 807;

  {$EXTERNALSYM SN_id_GostR3411_94_with_GostR3410_94}
  SN_id_GostR3411_94_with_GostR3410_94 = 'id-GostR3411-94-with-GostR3410-94';
  {$EXTERNALSYM LN_id_GostR3411_94_with_GostR3410_94}
  LN_id_GostR3411_94_with_GostR3410_94 = 'GOST R 34.11-94 with GOST R 34.10-94';
  {$EXTERNALSYM NID_id_GostR3411_94_with_GostR3410_94}
  NID_id_GostR3411_94_with_GostR3410_94 = 808;

  {$EXTERNALSYM SN_id_GostR3411_94}
  SN_id_GostR3411_94 = 'md_gost94';
  {$EXTERNALSYM LN_id_GostR3411_94}
  LN_id_GostR3411_94 = 'GOST R 34.11-94';
  {$EXTERNALSYM NID_id_GostR3411_94}
  NID_id_GostR3411_94 = 809;

  {$EXTERNALSYM SN_id_HMACGostR3411_94}
  SN_id_HMACGostR3411_94 = 'id-HMACGostR3411-94';
  {$EXTERNALSYM LN_id_HMACGostR3411_94}
  LN_id_HMACGostR3411_94 = 'HMAC GOST 34.11-94';
  {$EXTERNALSYM NID_id_HMACGostR3411_94}
  NID_id_HMACGostR3411_94 = 810;

  {$EXTERNALSYM SN_id_GostR3410_2001}
  SN_id_GostR3410_2001 = 'gost2001';
  {$EXTERNALSYM LN_id_GostR3410_2001}
  LN_id_GostR3410_2001 = 'GOST R 34.10-2001';
  {$EXTERNALSYM NID_id_GostR3410_2001}
  NID_id_GostR3410_2001 = 811;

  {$EXTERNALSYM SN_id_GostR3410_94}
  SN_id_GostR3410_94 = 'gost94';
  {$EXTERNALSYM LN_id_GostR3410_94}
  LN_id_GostR3410_94 = 'GOST R 34.10-94';
  {$EXTERNALSYM NID_id_GostR3410_94}
  NID_id_GostR3410_94 = 812;

  {$EXTERNALSYM SN_id_Gost28147_89}
  SN_id_Gost28147_89 = 'gost89';
  {$EXTERNALSYM LN_id_Gost28147_89}
  LN_id_Gost28147_89 = 'GOST 28147-89';
  {$EXTERNALSYM NID_id_Gost28147_89}
  NID_id_Gost28147_89 = 813;

  {$EXTERNALSYM SN_gost89_cnt}
  SN_gost89_cnt = 'gost89-cnt';
  {$EXTERNALSYM NID_gost89_cnt}
  NID_gost89_cnt = 814;

  {$EXTERNALSYM SN_gost89_cnt_12}
  SN_gost89_cnt_12 = 'gost89-cnt-12';
  {$EXTERNALSYM NID_gost89_cnt_12}
  NID_gost89_cnt_12 = 975;

  {$EXTERNALSYM SN_gost89_cbc}
  SN_gost89_cbc = 'gost89-cbc';
  {$EXTERNALSYM NID_gost89_cbc}
  NID_gost89_cbc = 1009;

  {$EXTERNALSYM SN_gost89_ecb}
  SN_gost89_ecb = 'gost89-ecb';
  {$EXTERNALSYM NID_gost89_ecb}
  NID_gost89_ecb = 1010;

  {$EXTERNALSYM SN_gost89_ctr}
  SN_gost89_ctr = 'gost89-ctr';
  {$EXTERNALSYM NID_gost89_ctr}
  NID_gost89_ctr = 1011;

  {$EXTERNALSYM SN_id_Gost28147_89_MAC}
  SN_id_Gost28147_89_MAC = 'gost-mac';
  {$EXTERNALSYM LN_id_Gost28147_89_MAC}
  LN_id_Gost28147_89_MAC = 'GOST 28147-89 MAC';
  {$EXTERNALSYM NID_id_Gost28147_89_MAC}
  NID_id_Gost28147_89_MAC = 815;

  {$EXTERNALSYM SN_gost_mac_12}
  SN_gost_mac_12 = 'gost-mac-12';
  {$EXTERNALSYM NID_gost_mac_12}
  NID_gost_mac_12 = 976;

  {$EXTERNALSYM SN_id_GostR3411_94_prf}
  SN_id_GostR3411_94_prf = 'prf-gostr3411-94';
  {$EXTERNALSYM LN_id_GostR3411_94_prf}
  LN_id_GostR3411_94_prf = 'GOST R 34.11-94 PRF';
  {$EXTERNALSYM NID_id_GostR3411_94_prf}
  NID_id_GostR3411_94_prf = 816;

  {$EXTERNALSYM SN_id_GostR3410_2001DH}
  SN_id_GostR3410_2001DH = 'id-GostR3410-2001DH';
  {$EXTERNALSYM LN_id_GostR3410_2001DH}
  LN_id_GostR3410_2001DH = 'GOST R 34.10-2001 DH';
  {$EXTERNALSYM NID_id_GostR3410_2001DH}
  NID_id_GostR3410_2001DH = 817;

  {$EXTERNALSYM SN_id_GostR3410_94DH}
  SN_id_GostR3410_94DH = 'id-GostR3410-94DH';
  {$EXTERNALSYM LN_id_GostR3410_94DH}
  LN_id_GostR3410_94DH = 'GOST R 34.10-94 DH';
  {$EXTERNALSYM NID_id_GostR3410_94DH}
  NID_id_GostR3410_94DH = 818;

  {$EXTERNALSYM SN_id_Gost28147_89_CryptoPro_KeyMeshing}
  SN_id_Gost28147_89_CryptoPro_KeyMeshing = 'id-Gost28147-89-CryptoPro-KeyMeshing';
  {$EXTERNALSYM NID_id_Gost28147_89_CryptoPro_KeyMeshing}
  NID_id_Gost28147_89_CryptoPro_KeyMeshing = 819;

  {$EXTERNALSYM SN_id_Gost28147_89_None_KeyMeshing}
  SN_id_Gost28147_89_None_KeyMeshing = 'id-Gost28147-89-None-KeyMeshing';
  {$EXTERNALSYM NID_id_Gost28147_89_None_KeyMeshing}
  NID_id_Gost28147_89_None_KeyMeshing = 820;

  {$EXTERNALSYM SN_id_GostR3411_94_TestParamSet}
  SN_id_GostR3411_94_TestParamSet = 'id-GostR3411-94-TestParamSet';
  {$EXTERNALSYM NID_id_GostR3411_94_TestParamSet}
  NID_id_GostR3411_94_TestParamSet = 821;

  {$EXTERNALSYM SN_id_GostR3411_94_CryptoProParamSet}
  SN_id_GostR3411_94_CryptoProParamSet = 'id-GostR3411-94-CryptoProParamSet';
  {$EXTERNALSYM NID_id_GostR3411_94_CryptoProParamSet}
  NID_id_GostR3411_94_CryptoProParamSet = 822;

  {$EXTERNALSYM SN_id_Gost28147_89_TestParamSet}
  SN_id_Gost28147_89_TestParamSet = 'id-Gost28147-89-TestParamSet';
  {$EXTERNALSYM NID_id_Gost28147_89_TestParamSet}
  NID_id_Gost28147_89_TestParamSet = 823;

  {$EXTERNALSYM SN_id_Gost28147_89_CryptoPro_A_ParamSet}
  SN_id_Gost28147_89_CryptoPro_A_ParamSet = 'id-Gost28147-89-CryptoPro-A-ParamSet';
  {$EXTERNALSYM NID_id_Gost28147_89_CryptoPro_A_ParamSet}
  NID_id_Gost28147_89_CryptoPro_A_ParamSet = 824;

  {$EXTERNALSYM SN_id_Gost28147_89_CryptoPro_B_ParamSet}
  SN_id_Gost28147_89_CryptoPro_B_ParamSet = 'id-Gost28147-89-CryptoPro-B-ParamSet';
  {$EXTERNALSYM NID_id_Gost28147_89_CryptoPro_B_ParamSet}
  NID_id_Gost28147_89_CryptoPro_B_ParamSet = 825;

  {$EXTERNALSYM SN_id_Gost28147_89_CryptoPro_C_ParamSet}
  SN_id_Gost28147_89_CryptoPro_C_ParamSet = 'id-Gost28147-89-CryptoPro-C-ParamSet';
  {$EXTERNALSYM NID_id_Gost28147_89_CryptoPro_C_ParamSet}
  NID_id_Gost28147_89_CryptoPro_C_ParamSet = 826;

  {$EXTERNALSYM SN_id_Gost28147_89_CryptoPro_D_ParamSet}
  SN_id_Gost28147_89_CryptoPro_D_ParamSet = 'id-Gost28147-89-CryptoPro-D-ParamSet';
  {$EXTERNALSYM NID_id_Gost28147_89_CryptoPro_D_ParamSet}
  NID_id_Gost28147_89_CryptoPro_D_ParamSet = 827;

  {$EXTERNALSYM SN_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet}
  SN_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet = 'id-Gost28147-89-CryptoPro-Oscar-1-1-ParamSet';
  {$EXTERNALSYM NID_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet}
  NID_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet = 828;

  {$EXTERNALSYM SN_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet}
  SN_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet = 'id-Gost28147-89-CryptoPro-Oscar-1-0-ParamSet';
  {$EXTERNALSYM NID_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet}
  NID_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet = 829;

  {$EXTERNALSYM SN_id_Gost28147_89_CryptoPro_RIC_1_ParamSet}
  SN_id_Gost28147_89_CryptoPro_RIC_1_ParamSet = 'id-Gost28147-89-CryptoPro-RIC-1-ParamSet';
  {$EXTERNALSYM NID_id_Gost28147_89_CryptoPro_RIC_1_ParamSet}
  NID_id_Gost28147_89_CryptoPro_RIC_1_ParamSet = 830;

  {$EXTERNALSYM SN_id_GostR3410_94_TestParamSet}
  SN_id_GostR3410_94_TestParamSet = 'id-GostR3410-94-TestParamSet';
  {$EXTERNALSYM NID_id_GostR3410_94_TestParamSet}
  NID_id_GostR3410_94_TestParamSet = 831;

  {$EXTERNALSYM SN_id_GostR3410_94_CryptoPro_A_ParamSet}
  SN_id_GostR3410_94_CryptoPro_A_ParamSet = 'id-GostR3410-94-CryptoPro-A-ParamSet';
  {$EXTERNALSYM NID_id_GostR3410_94_CryptoPro_A_ParamSet}
  NID_id_GostR3410_94_CryptoPro_A_ParamSet = 832;

  {$EXTERNALSYM SN_id_GostR3410_94_CryptoPro_B_ParamSet}
  SN_id_GostR3410_94_CryptoPro_B_ParamSet = 'id-GostR3410-94-CryptoPro-B-ParamSet';
  {$EXTERNALSYM NID_id_GostR3410_94_CryptoPro_B_ParamSet}
  NID_id_GostR3410_94_CryptoPro_B_ParamSet = 833;

  {$EXTERNALSYM SN_id_GostR3410_94_CryptoPro_C_ParamSet}
  SN_id_GostR3410_94_CryptoPro_C_ParamSet = 'id-GostR3410-94-CryptoPro-C-ParamSet';
  {$EXTERNALSYM NID_id_GostR3410_94_CryptoPro_C_ParamSet}
  NID_id_GostR3410_94_CryptoPro_C_ParamSet = 834;

  {$EXTERNALSYM SN_id_GostR3410_94_CryptoPro_D_ParamSet}
  SN_id_GostR3410_94_CryptoPro_D_ParamSet = 'id-GostR3410-94-CryptoPro-D-ParamSet';
  {$EXTERNALSYM NID_id_GostR3410_94_CryptoPro_D_ParamSet}
  NID_id_GostR3410_94_CryptoPro_D_ParamSet = 835;

  {$EXTERNALSYM SN_id_GostR3410_94_CryptoPro_XchA_ParamSet}
  SN_id_GostR3410_94_CryptoPro_XchA_ParamSet = 'id-GostR3410-94-CryptoPro-XchA-ParamSet';
  {$EXTERNALSYM NID_id_GostR3410_94_CryptoPro_XchA_ParamSet}
  NID_id_GostR3410_94_CryptoPro_XchA_ParamSet = 836;

  {$EXTERNALSYM SN_id_GostR3410_94_CryptoPro_XchB_ParamSet}
  SN_id_GostR3410_94_CryptoPro_XchB_ParamSet = 'id-GostR3410-94-CryptoPro-XchB-ParamSet';
  {$EXTERNALSYM NID_id_GostR3410_94_CryptoPro_XchB_ParamSet}
  NID_id_GostR3410_94_CryptoPro_XchB_ParamSet = 837;

  {$EXTERNALSYM SN_id_GostR3410_94_CryptoPro_XchC_ParamSet}
  SN_id_GostR3410_94_CryptoPro_XchC_ParamSet = 'id-GostR3410-94-CryptoPro-XchC-ParamSet';
  {$EXTERNALSYM NID_id_GostR3410_94_CryptoPro_XchC_ParamSet}
  NID_id_GostR3410_94_CryptoPro_XchC_ParamSet = 838;

  {$EXTERNALSYM SN_id_GostR3410_2001_TestParamSet}
  SN_id_GostR3410_2001_TestParamSet = 'id-GostR3410-2001-TestParamSet';
  {$EXTERNALSYM NID_id_GostR3410_2001_TestParamSet}
  NID_id_GostR3410_2001_TestParamSet = 839;

  {$EXTERNALSYM SN_id_GostR3410_2001_CryptoPro_A_ParamSet}
  SN_id_GostR3410_2001_CryptoPro_A_ParamSet = 'id-GostR3410-2001-CryptoPro-A-ParamSet';
  {$EXTERNALSYM NID_id_GostR3410_2001_CryptoPro_A_ParamSet}
  NID_id_GostR3410_2001_CryptoPro_A_ParamSet = 840;

  {$EXTERNALSYM SN_id_GostR3410_2001_CryptoPro_B_ParamSet}
  SN_id_GostR3410_2001_CryptoPro_B_ParamSet = 'id-GostR3410-2001-CryptoPro-B-ParamSet';
  {$EXTERNALSYM NID_id_GostR3410_2001_CryptoPro_B_ParamSet}
  NID_id_GostR3410_2001_CryptoPro_B_ParamSet = 841;

  {$EXTERNALSYM SN_id_GostR3410_2001_CryptoPro_C_ParamSet}
  SN_id_GostR3410_2001_CryptoPro_C_ParamSet = 'id-GostR3410-2001-CryptoPro-C-ParamSet';
  {$EXTERNALSYM NID_id_GostR3410_2001_CryptoPro_C_ParamSet}
  NID_id_GostR3410_2001_CryptoPro_C_ParamSet = 842;

  {$EXTERNALSYM SN_id_GostR3410_2001_CryptoPro_XchA_ParamSet}
  SN_id_GostR3410_2001_CryptoPro_XchA_ParamSet = 'id-GostR3410-2001-CryptoPro-XchA-ParamSet';
  {$EXTERNALSYM NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet}
  NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet = 843;

  {$EXTERNALSYM SN_id_GostR3410_2001_CryptoPro_XchB_ParamSet}
  SN_id_GostR3410_2001_CryptoPro_XchB_ParamSet = 'id-GostR3410-2001-CryptoPro-XchB-ParamSet';
  {$EXTERNALSYM NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet}
  NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet = 844;

  {$EXTERNALSYM SN_id_GostR3410_94_a}
  SN_id_GostR3410_94_a = 'id-GostR3410-94-a';
  {$EXTERNALSYM NID_id_GostR3410_94_a}
  NID_id_GostR3410_94_a = 845;

  {$EXTERNALSYM SN_id_GostR3410_94_aBis}
  SN_id_GostR3410_94_aBis = 'id-GostR3410-94-aBis';
  {$EXTERNALSYM NID_id_GostR3410_94_aBis}
  NID_id_GostR3410_94_aBis = 846;

  {$EXTERNALSYM SN_id_GostR3410_94_b}
  SN_id_GostR3410_94_b = 'id-GostR3410-94-b';
  {$EXTERNALSYM NID_id_GostR3410_94_b}
  NID_id_GostR3410_94_b = 847;

  {$EXTERNALSYM SN_id_GostR3410_94_bBis}
  SN_id_GostR3410_94_bBis = 'id-GostR3410-94-bBis';
  {$EXTERNALSYM NID_id_GostR3410_94_bBis}
  NID_id_GostR3410_94_bBis = 848;

  {$EXTERNALSYM SN_id_Gost28147_89_cc}
  SN_id_Gost28147_89_cc = 'id-Gost28147-89-cc';
  {$EXTERNALSYM LN_id_Gost28147_89_cc}
  LN_id_Gost28147_89_cc = 'GOST 28147-89 Cryptocom ParamSet';
  {$EXTERNALSYM NID_id_Gost28147_89_cc}
  NID_id_Gost28147_89_cc = 849;

  {$EXTERNALSYM SN_id_GostR3410_94_cc}
  SN_id_GostR3410_94_cc = 'gost94cc';
  {$EXTERNALSYM LN_id_GostR3410_94_cc}
  LN_id_GostR3410_94_cc = 'GOST 34.10-94 Cryptocom';
  {$EXTERNALSYM NID_id_GostR3410_94_cc}
  NID_id_GostR3410_94_cc = 850;

  {$EXTERNALSYM SN_id_GostR3410_2001_cc}
  SN_id_GostR3410_2001_cc = 'gost2001cc';
  {$EXTERNALSYM LN_id_GostR3410_2001_cc}
  LN_id_GostR3410_2001_cc = 'GOST 34.10-2001 Cryptocom';
  {$EXTERNALSYM NID_id_GostR3410_2001_cc}
  NID_id_GostR3410_2001_cc = 851;

  {$EXTERNALSYM SN_id_GostR3411_94_with_GostR3410_94_cc}
  SN_id_GostR3411_94_with_GostR3410_94_cc = 'id-GostR3411-94-with-GostR3410-94-cc';
  {$EXTERNALSYM LN_id_GostR3411_94_with_GostR3410_94_cc}
  LN_id_GostR3411_94_with_GostR3410_94_cc = 'GOST R 34.11-94 with GOST R 34.10-94 Cryptocom';
  {$EXTERNALSYM NID_id_GostR3411_94_with_GostR3410_94_cc}
  NID_id_GostR3411_94_with_GostR3410_94_cc = 852;

  {$EXTERNALSYM SN_id_GostR3411_94_with_GostR3410_2001_cc}
  SN_id_GostR3411_94_with_GostR3410_2001_cc = 'id-GostR3411-94-with-GostR3410-2001-cc';
  {$EXTERNALSYM LN_id_GostR3411_94_with_GostR3410_2001_cc}
  LN_id_GostR3411_94_with_GostR3410_2001_cc = 'GOST R 34.11-94 with GOST R 34.10-2001 Cryptocom';
  {$EXTERNALSYM NID_id_GostR3411_94_with_GostR3410_2001_cc}
  NID_id_GostR3411_94_with_GostR3410_2001_cc = 853;

  {$EXTERNALSYM SN_id_GostR3410_2001_ParamSet_cc}
  SN_id_GostR3410_2001_ParamSet_cc = 'id-GostR3410-2001-ParamSet-cc';
  {$EXTERNALSYM LN_id_GostR3410_2001_ParamSet_cc}
  LN_id_GostR3410_2001_ParamSet_cc = 'GOST R 3410-2001 Parameter Set Cryptocom';
  {$EXTERNALSYM NID_id_GostR3410_2001_ParamSet_cc}
  NID_id_GostR3410_2001_ParamSet_cc = 854;

  {$EXTERNALSYM SN_id_tc26_algorithms}
  SN_id_tc26_algorithms = 'id-tc26-algorithms';
  {$EXTERNALSYM NID_id_tc26_algorithms}
  NID_id_tc26_algorithms = 977;

  {$EXTERNALSYM SN_id_tc26_sign}
  SN_id_tc26_sign = 'id-tc26-sign';
  {$EXTERNALSYM NID_id_tc26_sign}
  NID_id_tc26_sign = 978;

  {$EXTERNALSYM SN_id_GostR3410_2012_256}
  SN_id_GostR3410_2012_256 = 'gost2012_256';
  {$EXTERNALSYM LN_id_GostR3410_2012_256}
  LN_id_GostR3410_2012_256 = 'GOST R 34.10-2012 with 256 bit modulus';
  {$EXTERNALSYM NID_id_GostR3410_2012_256}
  NID_id_GostR3410_2012_256 = 979;

  {$EXTERNALSYM SN_id_GostR3410_2012_512}
  SN_id_GostR3410_2012_512 = 'gost2012_512';
  {$EXTERNALSYM LN_id_GostR3410_2012_512}
  LN_id_GostR3410_2012_512 = 'GOST R 34.10-2012 with 512 bit modulus';
  {$EXTERNALSYM NID_id_GostR3410_2012_512}
  NID_id_GostR3410_2012_512 = 980;

  {$EXTERNALSYM SN_id_tc26_digest}
  SN_id_tc26_digest = 'id-tc26-digest';
  {$EXTERNALSYM NID_id_tc26_digest}
  NID_id_tc26_digest = 981;

  {$EXTERNALSYM SN_id_GostR3411_2012_256}
  SN_id_GostR3411_2012_256 = 'md_gost12_256';
  {$EXTERNALSYM LN_id_GostR3411_2012_256}
  LN_id_GostR3411_2012_256 = 'GOST R 34.11-2012 with 256 bit hash';
  {$EXTERNALSYM NID_id_GostR3411_2012_256}
  NID_id_GostR3411_2012_256 = 982;

  {$EXTERNALSYM SN_id_GostR3411_2012_512}
  SN_id_GostR3411_2012_512 = 'md_gost12_512';
  {$EXTERNALSYM LN_id_GostR3411_2012_512}
  LN_id_GostR3411_2012_512 = 'GOST R 34.11-2012 with 512 bit hash';
  {$EXTERNALSYM NID_id_GostR3411_2012_512}
  NID_id_GostR3411_2012_512 = 983;

  {$EXTERNALSYM SN_id_tc26_signwithdigest}
  SN_id_tc26_signwithdigest = 'id-tc26-signwithdigest';
  {$EXTERNALSYM NID_id_tc26_signwithdigest}
  NID_id_tc26_signwithdigest = 984;

  {$EXTERNALSYM SN_id_tc26_signwithdigest_gost3410_2012_256}
  SN_id_tc26_signwithdigest_gost3410_2012_256 = 'id-tc26-signwithdigest-gost3410-2012-256';
  {$EXTERNALSYM LN_id_tc26_signwithdigest_gost3410_2012_256}
  LN_id_tc26_signwithdigest_gost3410_2012_256 = 'GOST R 34.10-2012 with GOST R 34.11-2012(256 bit)';
  {$EXTERNALSYM NID_id_tc26_signwithdigest_gost3410_2012_256}
  NID_id_tc26_signwithdigest_gost3410_2012_256 = 985;

  {$EXTERNALSYM SN_id_tc26_signwithdigest_gost3410_2012_512}
  SN_id_tc26_signwithdigest_gost3410_2012_512 = 'id-tc26-signwithdigest-gost3410-2012-512';
  {$EXTERNALSYM LN_id_tc26_signwithdigest_gost3410_2012_512}
  LN_id_tc26_signwithdigest_gost3410_2012_512 = 'GOST R 34.10-2012 with GOST R 34.11-2012(512 bit)';
  {$EXTERNALSYM NID_id_tc26_signwithdigest_gost3410_2012_512}
  NID_id_tc26_signwithdigest_gost3410_2012_512 = 986;

  {$EXTERNALSYM SN_id_tc26_mac}
  SN_id_tc26_mac = 'id-tc26-mac';
  {$EXTERNALSYM NID_id_tc26_mac}
  NID_id_tc26_mac = 987;

  {$EXTERNALSYM SN_id_tc26_hmac_gost_3411_2012_256}
  SN_id_tc26_hmac_gost_3411_2012_256 = 'id-tc26-hmac-gost-3411-2012-256';
  {$EXTERNALSYM LN_id_tc26_hmac_gost_3411_2012_256}
  LN_id_tc26_hmac_gost_3411_2012_256 = 'HMAC GOST 34.11-2012 256 bit';
  {$EXTERNALSYM NID_id_tc26_hmac_gost_3411_2012_256}
  NID_id_tc26_hmac_gost_3411_2012_256 = 988;

  {$EXTERNALSYM SN_id_tc26_hmac_gost_3411_2012_512}
  SN_id_tc26_hmac_gost_3411_2012_512 = 'id-tc26-hmac-gost-3411-2012-512';
  {$EXTERNALSYM LN_id_tc26_hmac_gost_3411_2012_512}
  LN_id_tc26_hmac_gost_3411_2012_512 = 'HMAC GOST 34.11-2012 512 bit';
  {$EXTERNALSYM NID_id_tc26_hmac_gost_3411_2012_512}
  NID_id_tc26_hmac_gost_3411_2012_512 = 989;

  {$EXTERNALSYM SN_id_tc26_cipher}
  SN_id_tc26_cipher = 'id-tc26-cipher';
  {$EXTERNALSYM NID_id_tc26_cipher}
  NID_id_tc26_cipher = 990;

  {$EXTERNALSYM SN_id_tc26_cipher_gostr3412_2015_magma}
  SN_id_tc26_cipher_gostr3412_2015_magma = 'id-tc26-cipher-gostr3412-2015-magma';
  {$EXTERNALSYM NID_id_tc26_cipher_gostr3412_2015_magma}
  NID_id_tc26_cipher_gostr3412_2015_magma = 1173;

  {$EXTERNALSYM SN_id_tc26_cipher_gostr3412_2015_magma_ctracpkm}
  SN_id_tc26_cipher_gostr3412_2015_magma_ctracpkm = 'id-tc26-cipher-gostr3412-2015-magma-ctracpkm';
  {$EXTERNALSYM NID_id_tc26_cipher_gostr3412_2015_magma_ctracpkm}
  NID_id_tc26_cipher_gostr3412_2015_magma_ctracpkm = 1174;

  {$EXTERNALSYM SN_id_tc26_cipher_gostr3412_2015_magma_ctracpkm_omac}
  SN_id_tc26_cipher_gostr3412_2015_magma_ctracpkm_omac = 'id-tc26-cipher-gostr3412-2015-magma-ctracpkm-omac';
  {$EXTERNALSYM NID_id_tc26_cipher_gostr3412_2015_magma_ctracpkm_omac}
  NID_id_tc26_cipher_gostr3412_2015_magma_ctracpkm_omac = 1175;

  {$EXTERNALSYM SN_id_tc26_cipher_gostr3412_2015_kuznyechik}
  SN_id_tc26_cipher_gostr3412_2015_kuznyechik = 'id-tc26-cipher-gostr3412-2015-kuznyechik';
  {$EXTERNALSYM NID_id_tc26_cipher_gostr3412_2015_kuznyechik}
  NID_id_tc26_cipher_gostr3412_2015_kuznyechik = 1176;

  {$EXTERNALSYM SN_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm}
  SN_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm = 'id-tc26-cipher-gostr3412-2015-kuznyechik-ctracpkm';
  {$EXTERNALSYM NID_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm}
  NID_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm = 1177;

  {$EXTERNALSYM SN_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm_omac}
  SN_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm_omac = 'id-tc26-cipher-gostr3412-2015-kuznyechik-ctracpkm-omac';
  {$EXTERNALSYM NID_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm_omac}
  NID_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm_omac = 1178;

  {$EXTERNALSYM SN_id_tc26_agreement}
  SN_id_tc26_agreement = 'id-tc26-agreement';
  {$EXTERNALSYM NID_id_tc26_agreement}
  NID_id_tc26_agreement = 991;

  {$EXTERNALSYM SN_id_tc26_agreement_gost_3410_2012_256}
  SN_id_tc26_agreement_gost_3410_2012_256 = 'id-tc26-agreement-gost-3410-2012-256';
  {$EXTERNALSYM NID_id_tc26_agreement_gost_3410_2012_256}
  NID_id_tc26_agreement_gost_3410_2012_256 = 992;

  {$EXTERNALSYM SN_id_tc26_agreement_gost_3410_2012_512}
  SN_id_tc26_agreement_gost_3410_2012_512 = 'id-tc26-agreement-gost-3410-2012-512';
  {$EXTERNALSYM NID_id_tc26_agreement_gost_3410_2012_512}
  NID_id_tc26_agreement_gost_3410_2012_512 = 993;

  {$EXTERNALSYM SN_id_tc26_wrap}
  SN_id_tc26_wrap = 'id-tc26-wrap';
  {$EXTERNALSYM NID_id_tc26_wrap}
  NID_id_tc26_wrap = 1179;

  {$EXTERNALSYM SN_id_tc26_wrap_gostr3412_2015_magma}
  SN_id_tc26_wrap_gostr3412_2015_magma = 'id-tc26-wrap-gostr3412-2015-magma';
  {$EXTERNALSYM NID_id_tc26_wrap_gostr3412_2015_magma}
  NID_id_tc26_wrap_gostr3412_2015_magma = 1180;

  {$EXTERNALSYM SN_id_tc26_wrap_gostr3412_2015_magma_kexp15}
  SN_id_tc26_wrap_gostr3412_2015_magma_kexp15 = 'id-tc26-wrap-gostr3412-2015-magma-kexp15';
  {$EXTERNALSYM NID_id_tc26_wrap_gostr3412_2015_magma_kexp15}
  NID_id_tc26_wrap_gostr3412_2015_magma_kexp15 = 1181;

  {$EXTERNALSYM SN_id_tc26_wrap_gostr3412_2015_kuznyechik}
  SN_id_tc26_wrap_gostr3412_2015_kuznyechik = 'id-tc26-wrap-gostr3412-2015-kuznyechik';
  {$EXTERNALSYM NID_id_tc26_wrap_gostr3412_2015_kuznyechik}
  NID_id_tc26_wrap_gostr3412_2015_kuznyechik = 1182;

  {$EXTERNALSYM SN_id_tc26_wrap_gostr3412_2015_kuznyechik_kexp15}
  SN_id_tc26_wrap_gostr3412_2015_kuznyechik_kexp15 = 'id-tc26-wrap-gostr3412-2015-kuznyechik-kexp15';
  {$EXTERNALSYM NID_id_tc26_wrap_gostr3412_2015_kuznyechik_kexp15}
  NID_id_tc26_wrap_gostr3412_2015_kuznyechik_kexp15 = 1183;

  {$EXTERNALSYM SN_id_tc26_constants}
  SN_id_tc26_constants = 'id-tc26-constants';
  {$EXTERNALSYM NID_id_tc26_constants}
  NID_id_tc26_constants = 994;

  {$EXTERNALSYM SN_id_tc26_sign_constants}
  SN_id_tc26_sign_constants = 'id-tc26-sign-constants';
  {$EXTERNALSYM NID_id_tc26_sign_constants}
  NID_id_tc26_sign_constants = 995;

  {$EXTERNALSYM SN_id_tc26_gost_3410_2012_256_constants}
  SN_id_tc26_gost_3410_2012_256_constants = 'id-tc26-gost-3410-2012-256-constants';
  {$EXTERNALSYM NID_id_tc26_gost_3410_2012_256_constants}
  NID_id_tc26_gost_3410_2012_256_constants = 1147;

  {$EXTERNALSYM SN_id_tc26_gost_3410_2012_256_paramSetA}
  SN_id_tc26_gost_3410_2012_256_paramSetA = 'id-tc26-gost-3410-2012-256-paramSetA';
  {$EXTERNALSYM LN_id_tc26_gost_3410_2012_256_paramSetA}
  LN_id_tc26_gost_3410_2012_256_paramSetA = 'GOST R 34.10-2012(256 bit)ParamSet A';
  {$EXTERNALSYM NID_id_tc26_gost_3410_2012_256_paramSetA}
  NID_id_tc26_gost_3410_2012_256_paramSetA = 1148;

  {$EXTERNALSYM SN_id_tc26_gost_3410_2012_256_paramSetB}
  SN_id_tc26_gost_3410_2012_256_paramSetB = 'id-tc26-gost-3410-2012-256-paramSetB';
  {$EXTERNALSYM LN_id_tc26_gost_3410_2012_256_paramSetB}
  LN_id_tc26_gost_3410_2012_256_paramSetB = 'GOST R 34.10-2012(256 bit)ParamSet B';
  {$EXTERNALSYM NID_id_tc26_gost_3410_2012_256_paramSetB}
  NID_id_tc26_gost_3410_2012_256_paramSetB = 1184;

  {$EXTERNALSYM SN_id_tc26_gost_3410_2012_256_paramSetC}
  SN_id_tc26_gost_3410_2012_256_paramSetC = 'id-tc26-gost-3410-2012-256-paramSetC';
  {$EXTERNALSYM LN_id_tc26_gost_3410_2012_256_paramSetC}
  LN_id_tc26_gost_3410_2012_256_paramSetC = 'GOST R 34.10-2012(256 bit)ParamSet C';
  {$EXTERNALSYM NID_id_tc26_gost_3410_2012_256_paramSetC}
  NID_id_tc26_gost_3410_2012_256_paramSetC = 1185;

  {$EXTERNALSYM SN_id_tc26_gost_3410_2012_256_paramSetD}
  SN_id_tc26_gost_3410_2012_256_paramSetD = 'id-tc26-gost-3410-2012-256-paramSetD';
  {$EXTERNALSYM LN_id_tc26_gost_3410_2012_256_paramSetD}
  LN_id_tc26_gost_3410_2012_256_paramSetD = 'GOST R 34.10-2012(256 bit)ParamSet D';
  {$EXTERNALSYM NID_id_tc26_gost_3410_2012_256_paramSetD}
  NID_id_tc26_gost_3410_2012_256_paramSetD = 1186;

  {$EXTERNALSYM SN_id_tc26_gost_3410_2012_512_constants}
  SN_id_tc26_gost_3410_2012_512_constants = 'id-tc26-gost-3410-2012-512-constants';
  {$EXTERNALSYM NID_id_tc26_gost_3410_2012_512_constants}
  NID_id_tc26_gost_3410_2012_512_constants = 996;

  {$EXTERNALSYM SN_id_tc26_gost_3410_2012_512_paramSetTest}
  SN_id_tc26_gost_3410_2012_512_paramSetTest = 'id-tc26-gost-3410-2012-512-paramSetTest';
  {$EXTERNALSYM LN_id_tc26_gost_3410_2012_512_paramSetTest}
  LN_id_tc26_gost_3410_2012_512_paramSetTest = 'GOST R 34.10-2012(512 bit)testing parameter set';
  {$EXTERNALSYM NID_id_tc26_gost_3410_2012_512_paramSetTest}
  NID_id_tc26_gost_3410_2012_512_paramSetTest = 997;

  {$EXTERNALSYM SN_id_tc26_gost_3410_2012_512_paramSetA}
  SN_id_tc26_gost_3410_2012_512_paramSetA = 'id-tc26-gost-3410-2012-512-paramSetA';
  {$EXTERNALSYM LN_id_tc26_gost_3410_2012_512_paramSetA}
  LN_id_tc26_gost_3410_2012_512_paramSetA = 'GOST R 34.10-2012(512 bit)ParamSet A';
  {$EXTERNALSYM NID_id_tc26_gost_3410_2012_512_paramSetA}
  NID_id_tc26_gost_3410_2012_512_paramSetA = 998;

  {$EXTERNALSYM SN_id_tc26_gost_3410_2012_512_paramSetB}
  SN_id_tc26_gost_3410_2012_512_paramSetB = 'id-tc26-gost-3410-2012-512-paramSetB';
  {$EXTERNALSYM LN_id_tc26_gost_3410_2012_512_paramSetB}
  LN_id_tc26_gost_3410_2012_512_paramSetB = 'GOST R 34.10-2012(512 bit)ParamSet B';
  {$EXTERNALSYM NID_id_tc26_gost_3410_2012_512_paramSetB}
  NID_id_tc26_gost_3410_2012_512_paramSetB = 999;

  {$EXTERNALSYM SN_id_tc26_gost_3410_2012_512_paramSetC}
  SN_id_tc26_gost_3410_2012_512_paramSetC = 'id-tc26-gost-3410-2012-512-paramSetC';
  {$EXTERNALSYM LN_id_tc26_gost_3410_2012_512_paramSetC}
  LN_id_tc26_gost_3410_2012_512_paramSetC = 'GOST R 34.10-2012(512 bit)ParamSet C';
  {$EXTERNALSYM NID_id_tc26_gost_3410_2012_512_paramSetC}
  NID_id_tc26_gost_3410_2012_512_paramSetC = 1149;

  {$EXTERNALSYM SN_id_tc26_digest_constants}
  SN_id_tc26_digest_constants = 'id-tc26-digest-constants';
  {$EXTERNALSYM NID_id_tc26_digest_constants}
  NID_id_tc26_digest_constants = 1000;

  {$EXTERNALSYM SN_id_tc26_cipher_constants}
  SN_id_tc26_cipher_constants = 'id-tc26-cipher-constants';
  {$EXTERNALSYM NID_id_tc26_cipher_constants}
  NID_id_tc26_cipher_constants = 1001;

  {$EXTERNALSYM SN_id_tc26_gost_28147_constants}
  SN_id_tc26_gost_28147_constants = 'id-tc26-gost-28147-constants';
  {$EXTERNALSYM NID_id_tc26_gost_28147_constants}
  NID_id_tc26_gost_28147_constants = 1002;

  {$EXTERNALSYM SN_id_tc26_gost_28147_param_Z}
  SN_id_tc26_gost_28147_param_Z = 'id-tc26-gost-28147-param-Z';
  {$EXTERNALSYM LN_id_tc26_gost_28147_param_Z}
  LN_id_tc26_gost_28147_param_Z = 'GOST 28147-89 TC26 parameter set';
  {$EXTERNALSYM NID_id_tc26_gost_28147_param_Z}
  NID_id_tc26_gost_28147_param_Z = 1003;

  {$EXTERNALSYM SN_INN}
  SN_INN = 'INN';
  {$EXTERNALSYM LN_INN}
  LN_INN = 'INN';
  {$EXTERNALSYM NID_INN}
  NID_INN = 1004;

  {$EXTERNALSYM SN_OGRN}
  SN_OGRN = 'OGRN';
  {$EXTERNALSYM LN_OGRN}
  LN_OGRN = 'OGRN';
  {$EXTERNALSYM NID_OGRN}
  NID_OGRN = 1005;

  {$EXTERNALSYM SN_SNILS}
  SN_SNILS = 'SNILS';
  {$EXTERNALSYM LN_SNILS}
  LN_SNILS = 'SNILS';
  {$EXTERNALSYM NID_SNILS}
  NID_SNILS = 1006;

  {$EXTERNALSYM SN_subjectSignTool}
  SN_subjectSignTool = 'subjectSignTool';
  {$EXTERNALSYM LN_subjectSignTool}
  LN_subjectSignTool = 'Signing Tool of Subject';
  {$EXTERNALSYM NID_subjectSignTool}
  NID_subjectSignTool = 1007;

  {$EXTERNALSYM SN_issuerSignTool}
  SN_issuerSignTool = 'issuerSignTool';
  {$EXTERNALSYM LN_issuerSignTool}
  LN_issuerSignTool = 'Signing Tool of Issuer';
  {$EXTERNALSYM NID_issuerSignTool}
  NID_issuerSignTool = 1008;

  {$EXTERNALSYM SN_grasshopper_ecb}
  SN_grasshopper_ecb = 'grasshopper-ecb';
  {$EXTERNALSYM NID_grasshopper_ecb}
  NID_grasshopper_ecb = 1012;

  {$EXTERNALSYM SN_grasshopper_ctr}
  SN_grasshopper_ctr = 'grasshopper-ctr';
  {$EXTERNALSYM NID_grasshopper_ctr}
  NID_grasshopper_ctr = 1013;

  {$EXTERNALSYM SN_grasshopper_ofb}
  SN_grasshopper_ofb = 'grasshopper-ofb';
  {$EXTERNALSYM NID_grasshopper_ofb}
  NID_grasshopper_ofb = 1014;

  {$EXTERNALSYM SN_grasshopper_cbc}
  SN_grasshopper_cbc = 'grasshopper-cbc';
  {$EXTERNALSYM NID_grasshopper_cbc}
  NID_grasshopper_cbc = 1015;

  {$EXTERNALSYM SN_grasshopper_cfb}
  SN_grasshopper_cfb = 'grasshopper-cfb';
  {$EXTERNALSYM NID_grasshopper_cfb}
  NID_grasshopper_cfb = 1016;

  {$EXTERNALSYM SN_grasshopper_mac}
  SN_grasshopper_mac = 'grasshopper-mac';
  {$EXTERNALSYM NID_grasshopper_mac}
  NID_grasshopper_mac = 1017;

  {$EXTERNALSYM SN_magma_ecb}
  SN_magma_ecb = 'magma-ecb';
  {$EXTERNALSYM NID_magma_ecb}
  NID_magma_ecb = 1187;

  {$EXTERNALSYM SN_magma_ctr}
  SN_magma_ctr = 'magma-ctr';
  {$EXTERNALSYM NID_magma_ctr}
  NID_magma_ctr = 1188;

  {$EXTERNALSYM SN_magma_ofb}
  SN_magma_ofb = 'magma-ofb';
  {$EXTERNALSYM NID_magma_ofb}
  NID_magma_ofb = 1189;

  {$EXTERNALSYM SN_magma_cbc}
  SN_magma_cbc = 'magma-cbc';
  {$EXTERNALSYM NID_magma_cbc}
  NID_magma_cbc = 1190;

  {$EXTERNALSYM SN_magma_cfb}
  SN_magma_cfb = 'magma-cfb';
  {$EXTERNALSYM NID_magma_cfb}
  NID_magma_cfb = 1191;

  {$EXTERNALSYM SN_magma_mac}
  SN_magma_mac = 'magma-mac';
  {$EXTERNALSYM NID_magma_mac}
  NID_magma_mac = 1192;

  {$EXTERNALSYM SN_camellia_128_cbc}
  SN_camellia_128_cbc = 'CAMELLIA-128-CBC';
  {$EXTERNALSYM LN_camellia_128_cbc}
  LN_camellia_128_cbc = 'camellia-128-cbc';
  {$EXTERNALSYM NID_camellia_128_cbc}
  NID_camellia_128_cbc = 751;

  {$EXTERNALSYM SN_camellia_192_cbc}
  SN_camellia_192_cbc = 'CAMELLIA-192-CBC';
  {$EXTERNALSYM LN_camellia_192_cbc}
  LN_camellia_192_cbc = 'camellia-192-cbc';
  {$EXTERNALSYM NID_camellia_192_cbc}
  NID_camellia_192_cbc = 752;

  {$EXTERNALSYM SN_camellia_256_cbc}
  SN_camellia_256_cbc = 'CAMELLIA-256-CBC';
  {$EXTERNALSYM LN_camellia_256_cbc}
  LN_camellia_256_cbc = 'camellia-256-cbc';
  {$EXTERNALSYM NID_camellia_256_cbc}
  NID_camellia_256_cbc = 753;

  {$EXTERNALSYM SN_id_camellia128_wrap}
  SN_id_camellia128_wrap = 'id-camellia128-wrap';
  {$EXTERNALSYM NID_id_camellia128_wrap}
  NID_id_camellia128_wrap = 907;

  {$EXTERNALSYM SN_id_camellia192_wrap}
  SN_id_camellia192_wrap = 'id-camellia192-wrap';
  {$EXTERNALSYM NID_id_camellia192_wrap}
  NID_id_camellia192_wrap = 908;

  {$EXTERNALSYM SN_id_camellia256_wrap}
  SN_id_camellia256_wrap = 'id-camellia256-wrap';
  {$EXTERNALSYM NID_id_camellia256_wrap}
  NID_id_camellia256_wrap = 909;

  {$EXTERNALSYM SN_camellia_128_ecb}
  SN_camellia_128_ecb = 'CAMELLIA-128-ECB';
  {$EXTERNALSYM LN_camellia_128_ecb}
  LN_camellia_128_ecb = 'camellia-128-ecb';
  {$EXTERNALSYM NID_camellia_128_ecb}
  NID_camellia_128_ecb = 754;

  {$EXTERNALSYM SN_camellia_128_ofb128}
  SN_camellia_128_ofb128 = 'CAMELLIA-128-OFB';
  {$EXTERNALSYM LN_camellia_128_ofb128}
  LN_camellia_128_ofb128 = 'camellia-128-ofb';
  {$EXTERNALSYM NID_camellia_128_ofb128}
  NID_camellia_128_ofb128 = 766;

  {$EXTERNALSYM SN_camellia_128_cfb128}
  SN_camellia_128_cfb128 = 'CAMELLIA-128-CFB';
  {$EXTERNALSYM LN_camellia_128_cfb128}
  LN_camellia_128_cfb128 = 'camellia-128-cfb';
  {$EXTERNALSYM NID_camellia_128_cfb128}
  NID_camellia_128_cfb128 = 757;

  {$EXTERNALSYM SN_camellia_128_gcm}
  SN_camellia_128_gcm = 'CAMELLIA-128-GCM';
  {$EXTERNALSYM LN_camellia_128_gcm}
  LN_camellia_128_gcm = 'camellia-128-gcm';
  {$EXTERNALSYM NID_camellia_128_gcm}
  NID_camellia_128_gcm = 961;

  {$EXTERNALSYM SN_camellia_128_ccm}
  SN_camellia_128_ccm = 'CAMELLIA-128-CCM';
  {$EXTERNALSYM LN_camellia_128_ccm}
  LN_camellia_128_ccm = 'camellia-128-ccm';
  {$EXTERNALSYM NID_camellia_128_ccm}
  NID_camellia_128_ccm = 962;

  {$EXTERNALSYM SN_camellia_128_ctr}
  SN_camellia_128_ctr = 'CAMELLIA-128-CTR';
  {$EXTERNALSYM LN_camellia_128_ctr}
  LN_camellia_128_ctr = 'camellia-128-ctr';
  {$EXTERNALSYM NID_camellia_128_ctr}
  NID_camellia_128_ctr = 963;

  {$EXTERNALSYM SN_camellia_128_cmac}
  SN_camellia_128_cmac = 'CAMELLIA-128-CMAC';
  {$EXTERNALSYM LN_camellia_128_cmac}
  LN_camellia_128_cmac = 'camellia-128-cmac';
  {$EXTERNALSYM NID_camellia_128_cmac}
  NID_camellia_128_cmac = 964;

  {$EXTERNALSYM SN_camellia_192_ecb}
  SN_camellia_192_ecb = 'CAMELLIA-192-ECB';
  {$EXTERNALSYM LN_camellia_192_ecb}
  LN_camellia_192_ecb = 'camellia-192-ecb';
  {$EXTERNALSYM NID_camellia_192_ecb}
  NID_camellia_192_ecb = 755;

  {$EXTERNALSYM SN_camellia_192_ofb128}
  SN_camellia_192_ofb128 = 'CAMELLIA-192-OFB';
  {$EXTERNALSYM LN_camellia_192_ofb128}
  LN_camellia_192_ofb128 = 'camellia-192-ofb';
  {$EXTERNALSYM NID_camellia_192_ofb128}
  NID_camellia_192_ofb128 = 767;

  {$EXTERNALSYM SN_camellia_192_cfb128}
  SN_camellia_192_cfb128 = 'CAMELLIA-192-CFB';
  {$EXTERNALSYM LN_camellia_192_cfb128}
  LN_camellia_192_cfb128 = 'camellia-192-cfb';
  {$EXTERNALSYM NID_camellia_192_cfb128}
  NID_camellia_192_cfb128 = 758;

  {$EXTERNALSYM SN_camellia_192_gcm}
  SN_camellia_192_gcm = 'CAMELLIA-192-GCM';
  {$EXTERNALSYM LN_camellia_192_gcm}
  LN_camellia_192_gcm = 'camellia-192-gcm';
  {$EXTERNALSYM NID_camellia_192_gcm}
  NID_camellia_192_gcm = 965;

  {$EXTERNALSYM SN_camellia_192_ccm}
  SN_camellia_192_ccm = 'CAMELLIA-192-CCM';
  {$EXTERNALSYM LN_camellia_192_ccm}
  LN_camellia_192_ccm = 'camellia-192-ccm';
  {$EXTERNALSYM NID_camellia_192_ccm}
  NID_camellia_192_ccm = 966;

  {$EXTERNALSYM SN_camellia_192_ctr}
  SN_camellia_192_ctr = 'CAMELLIA-192-CTR';
  {$EXTERNALSYM LN_camellia_192_ctr}
  LN_camellia_192_ctr = 'camellia-192-ctr';
  {$EXTERNALSYM NID_camellia_192_ctr}
  NID_camellia_192_ctr = 967;

  {$EXTERNALSYM SN_camellia_192_cmac}
  SN_camellia_192_cmac = 'CAMELLIA-192-CMAC';
  {$EXTERNALSYM LN_camellia_192_cmac}
  LN_camellia_192_cmac = 'camellia-192-cmac';
  {$EXTERNALSYM NID_camellia_192_cmac}
  NID_camellia_192_cmac = 968;

  {$EXTERNALSYM SN_camellia_256_ecb}
  SN_camellia_256_ecb = 'CAMELLIA-256-ECB';
  {$EXTERNALSYM LN_camellia_256_ecb}
  LN_camellia_256_ecb = 'camellia-256-ecb';
  {$EXTERNALSYM NID_camellia_256_ecb}
  NID_camellia_256_ecb = 756;

  {$EXTERNALSYM SN_camellia_256_ofb128}
  SN_camellia_256_ofb128 = 'CAMELLIA-256-OFB';
  {$EXTERNALSYM LN_camellia_256_ofb128}
  LN_camellia_256_ofb128 = 'camellia-256-ofb';
  {$EXTERNALSYM NID_camellia_256_ofb128}
  NID_camellia_256_ofb128 = 768;

  {$EXTERNALSYM SN_camellia_256_cfb128}
  SN_camellia_256_cfb128 = 'CAMELLIA-256-CFB';
  {$EXTERNALSYM LN_camellia_256_cfb128}
  LN_camellia_256_cfb128 = 'camellia-256-cfb';
  {$EXTERNALSYM NID_camellia_256_cfb128}
  NID_camellia_256_cfb128 = 759;

  {$EXTERNALSYM SN_camellia_256_gcm}
  SN_camellia_256_gcm = 'CAMELLIA-256-GCM';
  {$EXTERNALSYM LN_camellia_256_gcm}
  LN_camellia_256_gcm = 'camellia-256-gcm';
  {$EXTERNALSYM NID_camellia_256_gcm}
  NID_camellia_256_gcm = 969;

  {$EXTERNALSYM SN_camellia_256_ccm}
  SN_camellia_256_ccm = 'CAMELLIA-256-CCM';
  {$EXTERNALSYM LN_camellia_256_ccm}
  LN_camellia_256_ccm = 'camellia-256-ccm';
  {$EXTERNALSYM NID_camellia_256_ccm}
  NID_camellia_256_ccm = 970;

  {$EXTERNALSYM SN_camellia_256_ctr}
  SN_camellia_256_ctr = 'CAMELLIA-256-CTR';
  {$EXTERNALSYM LN_camellia_256_ctr}
  LN_camellia_256_ctr = 'camellia-256-ctr';
  {$EXTERNALSYM NID_camellia_256_ctr}
  NID_camellia_256_ctr = 971;

  {$EXTERNALSYM SN_camellia_256_cmac}
  SN_camellia_256_cmac = 'CAMELLIA-256-CMAC';
  {$EXTERNALSYM LN_camellia_256_cmac}
  LN_camellia_256_cmac = 'camellia-256-cmac';
  {$EXTERNALSYM NID_camellia_256_cmac}
  NID_camellia_256_cmac = 972;

  {$EXTERNALSYM SN_camellia_128_cfb1}
  SN_camellia_128_cfb1 = 'CAMELLIA-128-CFB1';
  {$EXTERNALSYM LN_camellia_128_cfb1}
  LN_camellia_128_cfb1 = 'camellia-128-cfb1';
  {$EXTERNALSYM NID_camellia_128_cfb1}
  NID_camellia_128_cfb1 = 760;

  {$EXTERNALSYM SN_camellia_192_cfb1}
  SN_camellia_192_cfb1 = 'CAMELLIA-192-CFB1';
  {$EXTERNALSYM LN_camellia_192_cfb1}
  LN_camellia_192_cfb1 = 'camellia-192-cfb1';
  {$EXTERNALSYM NID_camellia_192_cfb1}
  NID_camellia_192_cfb1 = 761;

  {$EXTERNALSYM SN_camellia_256_cfb1}
  SN_camellia_256_cfb1 = 'CAMELLIA-256-CFB1';
  {$EXTERNALSYM LN_camellia_256_cfb1}
  LN_camellia_256_cfb1 = 'camellia-256-cfb1';
  {$EXTERNALSYM NID_camellia_256_cfb1}
  NID_camellia_256_cfb1 = 762;

  {$EXTERNALSYM SN_camellia_128_cfb8}
  SN_camellia_128_cfb8 = 'CAMELLIA-128-CFB8';
  {$EXTERNALSYM LN_camellia_128_cfb8}
  LN_camellia_128_cfb8 = 'camellia-128-cfb8';
  {$EXTERNALSYM NID_camellia_128_cfb8}
  NID_camellia_128_cfb8 = 763;

  {$EXTERNALSYM SN_camellia_192_cfb8}
  SN_camellia_192_cfb8 = 'CAMELLIA-192-CFB8';
  {$EXTERNALSYM LN_camellia_192_cfb8}
  LN_camellia_192_cfb8 = 'camellia-192-cfb8';
  {$EXTERNALSYM NID_camellia_192_cfb8}
  NID_camellia_192_cfb8 = 764;

  {$EXTERNALSYM SN_camellia_256_cfb8}
  SN_camellia_256_cfb8 = 'CAMELLIA-256-CFB8';
  {$EXTERNALSYM LN_camellia_256_cfb8}
  LN_camellia_256_cfb8 = 'camellia-256-cfb8';
  {$EXTERNALSYM NID_camellia_256_cfb8}
  NID_camellia_256_cfb8 = 765;

  {$EXTERNALSYM SN_aria_128_ecb}
  SN_aria_128_ecb = 'ARIA-128-ECB';
  {$EXTERNALSYM LN_aria_128_ecb}
  LN_aria_128_ecb = 'aria-128-ecb';
  {$EXTERNALSYM NID_aria_128_ecb}
  NID_aria_128_ecb = 1065;

  {$EXTERNALSYM SN_aria_128_cbc}
  SN_aria_128_cbc = 'ARIA-128-CBC';
  {$EXTERNALSYM LN_aria_128_cbc}
  LN_aria_128_cbc = 'aria-128-cbc';
  {$EXTERNALSYM NID_aria_128_cbc}
  NID_aria_128_cbc = 1066;

  {$EXTERNALSYM SN_aria_128_cfb128}
  SN_aria_128_cfb128 = 'ARIA-128-CFB';
  {$EXTERNALSYM LN_aria_128_cfb128}
  LN_aria_128_cfb128 = 'aria-128-cfb';
  {$EXTERNALSYM NID_aria_128_cfb128}
  NID_aria_128_cfb128 = 1067;

  {$EXTERNALSYM SN_aria_128_ofb128}
  SN_aria_128_ofb128 = 'ARIA-128-OFB';
  {$EXTERNALSYM LN_aria_128_ofb128}
  LN_aria_128_ofb128 = 'aria-128-ofb';
  {$EXTERNALSYM NID_aria_128_ofb128}
  NID_aria_128_ofb128 = 1068;

  {$EXTERNALSYM SN_aria_128_ctr}
  SN_aria_128_ctr = 'ARIA-128-CTR';
  {$EXTERNALSYM LN_aria_128_ctr}
  LN_aria_128_ctr = 'aria-128-ctr';
  {$EXTERNALSYM NID_aria_128_ctr}
  NID_aria_128_ctr = 1069;

  {$EXTERNALSYM SN_aria_192_ecb}
  SN_aria_192_ecb = 'ARIA-192-ECB';
  {$EXTERNALSYM LN_aria_192_ecb}
  LN_aria_192_ecb = 'aria-192-ecb';
  {$EXTERNALSYM NID_aria_192_ecb}
  NID_aria_192_ecb = 1070;

  {$EXTERNALSYM SN_aria_192_cbc}
  SN_aria_192_cbc = 'ARIA-192-CBC';
  {$EXTERNALSYM LN_aria_192_cbc}
  LN_aria_192_cbc = 'aria-192-cbc';
  {$EXTERNALSYM NID_aria_192_cbc}
  NID_aria_192_cbc = 1071;

  {$EXTERNALSYM SN_aria_192_cfb128}
  SN_aria_192_cfb128 = 'ARIA-192-CFB';
  {$EXTERNALSYM LN_aria_192_cfb128}
  LN_aria_192_cfb128 = 'aria-192-cfb';
  {$EXTERNALSYM NID_aria_192_cfb128}
  NID_aria_192_cfb128 = 1072;

  {$EXTERNALSYM SN_aria_192_ofb128}
  SN_aria_192_ofb128 = 'ARIA-192-OFB';
  {$EXTERNALSYM LN_aria_192_ofb128}
  LN_aria_192_ofb128 = 'aria-192-ofb';
  {$EXTERNALSYM NID_aria_192_ofb128}
  NID_aria_192_ofb128 = 1073;

  {$EXTERNALSYM SN_aria_192_ctr}
  SN_aria_192_ctr = 'ARIA-192-CTR';
  {$EXTERNALSYM LN_aria_192_ctr}
  LN_aria_192_ctr = 'aria-192-ctr';
  {$EXTERNALSYM NID_aria_192_ctr}
  NID_aria_192_ctr = 1074;

  {$EXTERNALSYM SN_aria_256_ecb}
  SN_aria_256_ecb = 'ARIA-256-ECB';
  {$EXTERNALSYM LN_aria_256_ecb}
  LN_aria_256_ecb = 'aria-256-ecb';
  {$EXTERNALSYM NID_aria_256_ecb}
  NID_aria_256_ecb = 1075;

  {$EXTERNALSYM SN_aria_256_cbc}
  SN_aria_256_cbc = 'ARIA-256-CBC';
  {$EXTERNALSYM LN_aria_256_cbc}
  LN_aria_256_cbc = 'aria-256-cbc';
  {$EXTERNALSYM NID_aria_256_cbc}
  NID_aria_256_cbc = 1076;

  {$EXTERNALSYM SN_aria_256_cfb128}
  SN_aria_256_cfb128 = 'ARIA-256-CFB';
  {$EXTERNALSYM LN_aria_256_cfb128}
  LN_aria_256_cfb128 = 'aria-256-cfb';
  {$EXTERNALSYM NID_aria_256_cfb128}
  NID_aria_256_cfb128 = 1077;

  {$EXTERNALSYM SN_aria_256_ofb128}
  SN_aria_256_ofb128 = 'ARIA-256-OFB';
  {$EXTERNALSYM LN_aria_256_ofb128}
  LN_aria_256_ofb128 = 'aria-256-ofb';
  {$EXTERNALSYM NID_aria_256_ofb128}
  NID_aria_256_ofb128 = 1078;

  {$EXTERNALSYM SN_aria_256_ctr}
  SN_aria_256_ctr = 'ARIA-256-CTR';
  {$EXTERNALSYM LN_aria_256_ctr}
  LN_aria_256_ctr = 'aria-256-ctr';
  {$EXTERNALSYM NID_aria_256_ctr}
  NID_aria_256_ctr = 1079;

  {$EXTERNALSYM SN_aria_128_cfb1}
  SN_aria_128_cfb1 = 'ARIA-128-CFB1';
  {$EXTERNALSYM LN_aria_128_cfb1}
  LN_aria_128_cfb1 = 'aria-128-cfb1';
  {$EXTERNALSYM NID_aria_128_cfb1}
  NID_aria_128_cfb1 = 1080;

  {$EXTERNALSYM SN_aria_192_cfb1}
  SN_aria_192_cfb1 = 'ARIA-192-CFB1';
  {$EXTERNALSYM LN_aria_192_cfb1}
  LN_aria_192_cfb1 = 'aria-192-cfb1';
  {$EXTERNALSYM NID_aria_192_cfb1}
  NID_aria_192_cfb1 = 1081;

  {$EXTERNALSYM SN_aria_256_cfb1}
  SN_aria_256_cfb1 = 'ARIA-256-CFB1';
  {$EXTERNALSYM LN_aria_256_cfb1}
  LN_aria_256_cfb1 = 'aria-256-cfb1';
  {$EXTERNALSYM NID_aria_256_cfb1}
  NID_aria_256_cfb1 = 1082;

  {$EXTERNALSYM SN_aria_128_cfb8}
  SN_aria_128_cfb8 = 'ARIA-128-CFB8';
  {$EXTERNALSYM LN_aria_128_cfb8}
  LN_aria_128_cfb8 = 'aria-128-cfb8';
  {$EXTERNALSYM NID_aria_128_cfb8}
  NID_aria_128_cfb8 = 1083;

  {$EXTERNALSYM SN_aria_192_cfb8}
  SN_aria_192_cfb8 = 'ARIA-192-CFB8';
  {$EXTERNALSYM LN_aria_192_cfb8}
  LN_aria_192_cfb8 = 'aria-192-cfb8';
  {$EXTERNALSYM NID_aria_192_cfb8}
  NID_aria_192_cfb8 = 1084;

  {$EXTERNALSYM SN_aria_256_cfb8}
  SN_aria_256_cfb8 = 'ARIA-256-CFB8';
  {$EXTERNALSYM LN_aria_256_cfb8}
  LN_aria_256_cfb8 = 'aria-256-cfb8';
  {$EXTERNALSYM NID_aria_256_cfb8}
  NID_aria_256_cfb8 = 1085;

  {$EXTERNALSYM SN_aria_128_ccm}
  SN_aria_128_ccm = 'ARIA-128-CCM';
  {$EXTERNALSYM LN_aria_128_ccm}
  LN_aria_128_ccm = 'aria-128-ccm';
  {$EXTERNALSYM NID_aria_128_ccm}
  NID_aria_128_ccm = 1120;

  {$EXTERNALSYM SN_aria_192_ccm}
  SN_aria_192_ccm = 'ARIA-192-CCM';
  {$EXTERNALSYM LN_aria_192_ccm}
  LN_aria_192_ccm = 'aria-192-ccm';
  {$EXTERNALSYM NID_aria_192_ccm}
  NID_aria_192_ccm = 1121;

  {$EXTERNALSYM SN_aria_256_ccm}
  SN_aria_256_ccm = 'ARIA-256-CCM';
  {$EXTERNALSYM LN_aria_256_ccm}
  LN_aria_256_ccm = 'aria-256-ccm';
  {$EXTERNALSYM NID_aria_256_ccm}
  NID_aria_256_ccm = 1122;

  {$EXTERNALSYM SN_aria_128_gcm}
  SN_aria_128_gcm = 'ARIA-128-GCM';
  {$EXTERNALSYM LN_aria_128_gcm}
  LN_aria_128_gcm = 'aria-128-gcm';
  {$EXTERNALSYM NID_aria_128_gcm}
  NID_aria_128_gcm = 1123;

  {$EXTERNALSYM SN_aria_192_gcm}
  SN_aria_192_gcm = 'ARIA-192-GCM';
  {$EXTERNALSYM LN_aria_192_gcm}
  LN_aria_192_gcm = 'aria-192-gcm';
  {$EXTERNALSYM NID_aria_192_gcm}
  NID_aria_192_gcm = 1124;

  {$EXTERNALSYM SN_aria_256_gcm}
  SN_aria_256_gcm = 'ARIA-256-GCM';
  {$EXTERNALSYM LN_aria_256_gcm}
  LN_aria_256_gcm = 'aria-256-gcm';
  {$EXTERNALSYM NID_aria_256_gcm}
  NID_aria_256_gcm = 1125;

  {$EXTERNALSYM SN_kisa}
  SN_kisa = 'KISA';
  {$EXTERNALSYM LN_kisa}
  LN_kisa = 'kisa';
  {$EXTERNALSYM NID_kisa}
  NID_kisa = 773;

  {$EXTERNALSYM SN_seed_ecb}
  SN_seed_ecb = 'SEED-ECB';
  {$EXTERNALSYM LN_seed_ecb}
  LN_seed_ecb = 'seed-ecb';
  {$EXTERNALSYM NID_seed_ecb}
  NID_seed_ecb = 776;

  {$EXTERNALSYM SN_seed_cbc}
  SN_seed_cbc = 'SEED-CBC';
  {$EXTERNALSYM LN_seed_cbc}
  LN_seed_cbc = 'seed-cbc';
  {$EXTERNALSYM NID_seed_cbc}
  NID_seed_cbc = 777;

  {$EXTERNALSYM SN_seed_cfb128}
  SN_seed_cfb128 = 'SEED-CFB';
  {$EXTERNALSYM LN_seed_cfb128}
  LN_seed_cfb128 = 'seed-cfb';
  {$EXTERNALSYM NID_seed_cfb128}
  NID_seed_cfb128 = 779;

  {$EXTERNALSYM SN_seed_ofb128}
  SN_seed_ofb128 = 'SEED-OFB';
  {$EXTERNALSYM LN_seed_ofb128}
  LN_seed_ofb128 = 'seed-ofb';
  {$EXTERNALSYM NID_seed_ofb128}
  NID_seed_ofb128 = 778;

  {$EXTERNALSYM SN_sm4_ecb}
  SN_sm4_ecb = 'SM4-ECB';
  {$EXTERNALSYM LN_sm4_ecb}
  LN_sm4_ecb = 'sm4-ecb';
  {$EXTERNALSYM NID_sm4_ecb}
  NID_sm4_ecb = 1133;

  {$EXTERNALSYM SN_sm4_cbc}
  SN_sm4_cbc = 'SM4-CBC';
  {$EXTERNALSYM LN_sm4_cbc}
  LN_sm4_cbc = 'sm4-cbc';
  {$EXTERNALSYM NID_sm4_cbc}
  NID_sm4_cbc = 1134;

  {$EXTERNALSYM SN_sm4_ofb128}
  SN_sm4_ofb128 = 'SM4-OFB';
  {$EXTERNALSYM LN_sm4_ofb128}
  LN_sm4_ofb128 = 'sm4-ofb';
  {$EXTERNALSYM NID_sm4_ofb128}
  NID_sm4_ofb128 = 1135;

  {$EXTERNALSYM SN_sm4_cfb128}
  SN_sm4_cfb128 = 'SM4-CFB';
  {$EXTERNALSYM LN_sm4_cfb128}
  LN_sm4_cfb128 = 'sm4-cfb';
  {$EXTERNALSYM NID_sm4_cfb128}
  NID_sm4_cfb128 = 1137;

  {$EXTERNALSYM SN_sm4_cfb1}
  SN_sm4_cfb1 = 'SM4-CFB1';
  {$EXTERNALSYM LN_sm4_cfb1}
  LN_sm4_cfb1 = 'sm4-cfb1';
  {$EXTERNALSYM NID_sm4_cfb1}
  NID_sm4_cfb1 = 1136;

  {$EXTERNALSYM SN_sm4_cfb8}
  SN_sm4_cfb8 = 'SM4-CFB8';
  {$EXTERNALSYM LN_sm4_cfb8}
  LN_sm4_cfb8 = 'sm4-cfb8';
  {$EXTERNALSYM NID_sm4_cfb8}
  NID_sm4_cfb8 = 1138;

  {$EXTERNALSYM SN_sm4_ctr}
  SN_sm4_ctr = 'SM4-CTR';
  {$EXTERNALSYM LN_sm4_ctr}
  LN_sm4_ctr = 'sm4-ctr';
  {$EXTERNALSYM NID_sm4_ctr}
  NID_sm4_ctr = 1139;

  {$EXTERNALSYM SN_hmac}
  SN_hmac = 'HMAC';
  {$EXTERNALSYM LN_hmac}
  LN_hmac = 'hmac';
  {$EXTERNALSYM NID_hmac}
  NID_hmac = 855;

  {$EXTERNALSYM SN_cmac}
  SN_cmac = 'CMAC';
  {$EXTERNALSYM LN_cmac}
  LN_cmac = 'cmac';
  {$EXTERNALSYM NID_cmac}
  NID_cmac = 894;

  {$EXTERNALSYM SN_rc4_hmac_md5}
  SN_rc4_hmac_md5 = 'RC4-HMAC-MD5';
  {$EXTERNALSYM LN_rc4_hmac_md5}
  LN_rc4_hmac_md5 = 'rc4-hmac-md5';
  {$EXTERNALSYM NID_rc4_hmac_md5}
  NID_rc4_hmac_md5 = 915;

  {$EXTERNALSYM SN_aes_128_cbc_hmac_sha1}
  SN_aes_128_cbc_hmac_sha1 = 'AES-128-CBC-HMAC-SHA1';
  {$EXTERNALSYM LN_aes_128_cbc_hmac_sha1}
  LN_aes_128_cbc_hmac_sha1 = 'aes-128-cbc-hmac-sha1';
  {$EXTERNALSYM NID_aes_128_cbc_hmac_sha1}
  NID_aes_128_cbc_hmac_sha1 = 916;

  {$EXTERNALSYM SN_aes_192_cbc_hmac_sha1}
  SN_aes_192_cbc_hmac_sha1 = 'AES-192-CBC-HMAC-SHA1';
  {$EXTERNALSYM LN_aes_192_cbc_hmac_sha1}
  LN_aes_192_cbc_hmac_sha1 = 'aes-192-cbc-hmac-sha1';
  {$EXTERNALSYM NID_aes_192_cbc_hmac_sha1}
  NID_aes_192_cbc_hmac_sha1 = 917;

  {$EXTERNALSYM SN_aes_256_cbc_hmac_sha1}
  SN_aes_256_cbc_hmac_sha1 = 'AES-256-CBC-HMAC-SHA1';
  {$EXTERNALSYM LN_aes_256_cbc_hmac_sha1}
  LN_aes_256_cbc_hmac_sha1 = 'aes-256-cbc-hmac-sha1';
  {$EXTERNALSYM NID_aes_256_cbc_hmac_sha1}
  NID_aes_256_cbc_hmac_sha1 = 918;

  {$EXTERNALSYM SN_aes_128_cbc_hmac_sha256}
  SN_aes_128_cbc_hmac_sha256 = 'AES-128-CBC-HMAC-SHA256';
  {$EXTERNALSYM LN_aes_128_cbc_hmac_sha256}
  LN_aes_128_cbc_hmac_sha256 = 'aes-128-cbc-hmac-sha256';
  {$EXTERNALSYM NID_aes_128_cbc_hmac_sha256}
  NID_aes_128_cbc_hmac_sha256 = 948;

  {$EXTERNALSYM SN_aes_192_cbc_hmac_sha256}
  SN_aes_192_cbc_hmac_sha256 = 'AES-192-CBC-HMAC-SHA256';
  {$EXTERNALSYM LN_aes_192_cbc_hmac_sha256}
  LN_aes_192_cbc_hmac_sha256 = 'aes-192-cbc-hmac-sha256';
  {$EXTERNALSYM NID_aes_192_cbc_hmac_sha256}
  NID_aes_192_cbc_hmac_sha256 = 949;

  {$EXTERNALSYM SN_aes_256_cbc_hmac_sha256}
  SN_aes_256_cbc_hmac_sha256 = 'AES-256-CBC-HMAC-SHA256';
  {$EXTERNALSYM LN_aes_256_cbc_hmac_sha256}
  LN_aes_256_cbc_hmac_sha256 = 'aes-256-cbc-hmac-sha256';
  {$EXTERNALSYM NID_aes_256_cbc_hmac_sha256}
  NID_aes_256_cbc_hmac_sha256 = 950;

  {$EXTERNALSYM SN_chacha20_poly1305}
  SN_chacha20_poly1305 = 'ChaCha20-Poly1305';
  {$EXTERNALSYM LN_chacha20_poly1305}
  LN_chacha20_poly1305 = 'chacha20-poly1305';
  {$EXTERNALSYM NID_chacha20_poly1305}
  NID_chacha20_poly1305 = 1018;

  {$EXTERNALSYM SN_chacha20}
  SN_chacha20 = 'ChaCha20';
  {$EXTERNALSYM LN_chacha20}
  LN_chacha20 = 'chacha20';
  {$EXTERNALSYM NID_chacha20}
  NID_chacha20 = 1019;

  {$EXTERNALSYM SN_dhpublicnumber}
  SN_dhpublicnumber = 'dhpublicnumber';
  {$EXTERNALSYM LN_dhpublicnumber}
  LN_dhpublicnumber = 'X9.42 DH';
  {$EXTERNALSYM NID_dhpublicnumber}
  NID_dhpublicnumber = 920;

  {$EXTERNALSYM SN_brainpoolP160r1}
  SN_brainpoolP160r1 = 'brainpoolP160r1';
  {$EXTERNALSYM NID_brainpoolP160r1}
  NID_brainpoolP160r1 = 921;

  {$EXTERNALSYM SN_brainpoolP160t1}
  SN_brainpoolP160t1 = 'brainpoolP160t1';
  {$EXTERNALSYM NID_brainpoolP160t1}
  NID_brainpoolP160t1 = 922;

  {$EXTERNALSYM SN_brainpoolP192r1}
  SN_brainpoolP192r1 = 'brainpoolP192r1';
  {$EXTERNALSYM NID_brainpoolP192r1}
  NID_brainpoolP192r1 = 923;

  {$EXTERNALSYM SN_brainpoolP192t1}
  SN_brainpoolP192t1 = 'brainpoolP192t1';
  {$EXTERNALSYM NID_brainpoolP192t1}
  NID_brainpoolP192t1 = 924;

  {$EXTERNALSYM SN_brainpoolP224r1}
  SN_brainpoolP224r1 = 'brainpoolP224r1';
  {$EXTERNALSYM NID_brainpoolP224r1}
  NID_brainpoolP224r1 = 925;

  {$EXTERNALSYM SN_brainpoolP224t1}
  SN_brainpoolP224t1 = 'brainpoolP224t1';
  {$EXTERNALSYM NID_brainpoolP224t1}
  NID_brainpoolP224t1 = 926;

  {$EXTERNALSYM SN_brainpoolP256r1}
  SN_brainpoolP256r1 = 'brainpoolP256r1';
  {$EXTERNALSYM NID_brainpoolP256r1}
  NID_brainpoolP256r1 = 927;

  {$EXTERNALSYM SN_brainpoolP256t1}
  SN_brainpoolP256t1 = 'brainpoolP256t1';
  {$EXTERNALSYM NID_brainpoolP256t1}
  NID_brainpoolP256t1 = 928;

  {$EXTERNALSYM SN_brainpoolP320r1}
  SN_brainpoolP320r1 = 'brainpoolP320r1';
  {$EXTERNALSYM NID_brainpoolP320r1}
  NID_brainpoolP320r1 = 929;

  {$EXTERNALSYM SN_brainpoolP320t1}
  SN_brainpoolP320t1 = 'brainpoolP320t1';
  {$EXTERNALSYM NID_brainpoolP320t1}
  NID_brainpoolP320t1 = 930;

  {$EXTERNALSYM SN_brainpoolP384r1}
  SN_brainpoolP384r1 = 'brainpoolP384r1';
  {$EXTERNALSYM NID_brainpoolP384r1}
  NID_brainpoolP384r1 = 931;

  {$EXTERNALSYM SN_brainpoolP384t1}
  SN_brainpoolP384t1 = 'brainpoolP384t1';
  {$EXTERNALSYM NID_brainpoolP384t1}
  NID_brainpoolP384t1 = 932;

  {$EXTERNALSYM SN_brainpoolP512r1}
  SN_brainpoolP512r1 = 'brainpoolP512r1';
  {$EXTERNALSYM NID_brainpoolP512r1}
  NID_brainpoolP512r1 = 933;

  {$EXTERNALSYM SN_brainpoolP512t1}
  SN_brainpoolP512t1 = 'brainpoolP512t1';
  {$EXTERNALSYM NID_brainpoolP512t1}
  NID_brainpoolP512t1 = 934;

  {$EXTERNALSYM SN_dhSinglePass_stdDH_sha1kdf_scheme}
  SN_dhSinglePass_stdDH_sha1kdf_scheme = 'dhSinglePass-stdDH-sha1kdf-scheme';
  {$EXTERNALSYM NID_dhSinglePass_stdDH_sha1kdf_scheme}
  NID_dhSinglePass_stdDH_sha1kdf_scheme = 936;

  {$EXTERNALSYM SN_dhSinglePass_stdDH_sha224kdf_scheme}
  SN_dhSinglePass_stdDH_sha224kdf_scheme = 'dhSinglePass-stdDH-sha224kdf-scheme';
  {$EXTERNALSYM NID_dhSinglePass_stdDH_sha224kdf_scheme}
  NID_dhSinglePass_stdDH_sha224kdf_scheme = 937;

  {$EXTERNALSYM SN_dhSinglePass_stdDH_sha256kdf_scheme}
  SN_dhSinglePass_stdDH_sha256kdf_scheme = 'dhSinglePass-stdDH-sha256kdf-scheme';
  {$EXTERNALSYM NID_dhSinglePass_stdDH_sha256kdf_scheme}
  NID_dhSinglePass_stdDH_sha256kdf_scheme = 938;

  {$EXTERNALSYM SN_dhSinglePass_stdDH_sha384kdf_scheme}
  SN_dhSinglePass_stdDH_sha384kdf_scheme = 'dhSinglePass-stdDH-sha384kdf-scheme';
  {$EXTERNALSYM NID_dhSinglePass_stdDH_sha384kdf_scheme}
  NID_dhSinglePass_stdDH_sha384kdf_scheme = 939;

  {$EXTERNALSYM SN_dhSinglePass_stdDH_sha512kdf_scheme}
  SN_dhSinglePass_stdDH_sha512kdf_scheme = 'dhSinglePass-stdDH-sha512kdf-scheme';
  {$EXTERNALSYM NID_dhSinglePass_stdDH_sha512kdf_scheme}
  NID_dhSinglePass_stdDH_sha512kdf_scheme = 940;

  {$EXTERNALSYM SN_dhSinglePass_cofactorDH_sha1kdf_scheme}
  SN_dhSinglePass_cofactorDH_sha1kdf_scheme = 'dhSinglePass-cofactorDH-sha1kdf-scheme';
  {$EXTERNALSYM NID_dhSinglePass_cofactorDH_sha1kdf_scheme}
  NID_dhSinglePass_cofactorDH_sha1kdf_scheme = 941;

  {$EXTERNALSYM SN_dhSinglePass_cofactorDH_sha224kdf_scheme}
  SN_dhSinglePass_cofactorDH_sha224kdf_scheme = 'dhSinglePass-cofactorDH-sha224kdf-scheme';
  {$EXTERNALSYM NID_dhSinglePass_cofactorDH_sha224kdf_scheme}
  NID_dhSinglePass_cofactorDH_sha224kdf_scheme = 942;

  {$EXTERNALSYM SN_dhSinglePass_cofactorDH_sha256kdf_scheme}
  SN_dhSinglePass_cofactorDH_sha256kdf_scheme = 'dhSinglePass-cofactorDH-sha256kdf-scheme';
  {$EXTERNALSYM NID_dhSinglePass_cofactorDH_sha256kdf_scheme}
  NID_dhSinglePass_cofactorDH_sha256kdf_scheme = 943;

  {$EXTERNALSYM SN_dhSinglePass_cofactorDH_sha384kdf_scheme}
  SN_dhSinglePass_cofactorDH_sha384kdf_scheme = 'dhSinglePass-cofactorDH-sha384kdf-scheme';
  {$EXTERNALSYM NID_dhSinglePass_cofactorDH_sha384kdf_scheme}
  NID_dhSinglePass_cofactorDH_sha384kdf_scheme = 944;

  {$EXTERNALSYM SN_dhSinglePass_cofactorDH_sha512kdf_scheme}
  SN_dhSinglePass_cofactorDH_sha512kdf_scheme = 'dhSinglePass-cofactorDH-sha512kdf-scheme';
  {$EXTERNALSYM NID_dhSinglePass_cofactorDH_sha512kdf_scheme}
  NID_dhSinglePass_cofactorDH_sha512kdf_scheme = 945;

  {$EXTERNALSYM SN_dh_std_kdf}
  SN_dh_std_kdf = 'dh-std-kdf';
  {$EXTERNALSYM NID_dh_std_kdf}
  NID_dh_std_kdf = 946;

  {$EXTERNALSYM SN_dh_cofactor_kdf}
  SN_dh_cofactor_kdf = 'dh-cofactor-kdf';
  {$EXTERNALSYM NID_dh_cofactor_kdf}
  NID_dh_cofactor_kdf = 947;

  {$EXTERNALSYM SN_ct_precert_scts}
  SN_ct_precert_scts = 'ct_precert_scts';
  {$EXTERNALSYM LN_ct_precert_scts}
  LN_ct_precert_scts = 'CT Precertificate SCTs';
  {$EXTERNALSYM NID_ct_precert_scts}
  NID_ct_precert_scts = 951;

  {$EXTERNALSYM SN_ct_precert_poison}
  SN_ct_precert_poison = 'ct_precert_poison';
  {$EXTERNALSYM LN_ct_precert_poison}
  LN_ct_precert_poison = 'CT Precertificate Poison';
  {$EXTERNALSYM NID_ct_precert_poison}
  NID_ct_precert_poison = 952;

  {$EXTERNALSYM SN_ct_precert_signer}
  SN_ct_precert_signer = 'ct_precert_signer';
  {$EXTERNALSYM LN_ct_precert_signer}
  LN_ct_precert_signer = 'CT Precertificate Signer';
  {$EXTERNALSYM NID_ct_precert_signer}
  NID_ct_precert_signer = 953;

  {$EXTERNALSYM SN_ct_cert_scts}
  SN_ct_cert_scts = 'ct_cert_scts';
  {$EXTERNALSYM LN_ct_cert_scts}
  LN_ct_cert_scts = 'CT Certificate SCTs';
  {$EXTERNALSYM NID_ct_cert_scts}
  NID_ct_cert_scts = 954;

  {$EXTERNALSYM SN_jurisdictionLocalityName}
  SN_jurisdictionLocalityName = 'jurisdictionL';
  {$EXTERNALSYM LN_jurisdictionLocalityName}
  LN_jurisdictionLocalityName = 'jurisdictionLocalityName';
  {$EXTERNALSYM NID_jurisdictionLocalityName}
  NID_jurisdictionLocalityName = 955;

  {$EXTERNALSYM SN_jurisdictionStateOrProvinceName}
  SN_jurisdictionStateOrProvinceName = 'jurisdictionST';
  {$EXTERNALSYM LN_jurisdictionStateOrProvinceName}
  LN_jurisdictionStateOrProvinceName = 'jurisdictionStateOrProvinceName';
  {$EXTERNALSYM NID_jurisdictionStateOrProvinceName}
  NID_jurisdictionStateOrProvinceName = 956;

  {$EXTERNALSYM SN_jurisdictionCountryName}
  SN_jurisdictionCountryName = 'jurisdictionC';
  {$EXTERNALSYM LN_jurisdictionCountryName}
  LN_jurisdictionCountryName = 'jurisdictionCountryName';
  {$EXTERNALSYM NID_jurisdictionCountryName}
  NID_jurisdictionCountryName = 957;

  {$EXTERNALSYM SN_id_scrypt}
  SN_id_scrypt = 'id-scrypt';
  {$EXTERNALSYM LN_id_scrypt}
  LN_id_scrypt = 'scrypt';
  {$EXTERNALSYM NID_id_scrypt}
  NID_id_scrypt = 973;

  {$EXTERNALSYM SN_tls1_prf}
  SN_tls1_prf = 'TLS1-PRF';
  {$EXTERNALSYM LN_tls1_prf}
  LN_tls1_prf = 'tls1-prf';
  {$EXTERNALSYM NID_tls1_prf}
  NID_tls1_prf = 1021;

  {$EXTERNALSYM SN_hkdf}
  SN_hkdf = 'HKDF';
  {$EXTERNALSYM LN_hkdf}
  LN_hkdf = 'hkdf';
  {$EXTERNALSYM NID_hkdf}
  NID_hkdf = 1036;

  {$EXTERNALSYM SN_id_pkinit}
  SN_id_pkinit = 'id-pkinit';
  {$EXTERNALSYM NID_id_pkinit}
  NID_id_pkinit = 1031;

  {$EXTERNALSYM SN_pkInitClientAuth}
  SN_pkInitClientAuth = 'pkInitClientAuth';
  {$EXTERNALSYM LN_pkInitClientAuth}
  LN_pkInitClientAuth = 'PKINIT Client Auth';
  {$EXTERNALSYM NID_pkInitClientAuth}
  NID_pkInitClientAuth = 1032;

  {$EXTERNALSYM SN_pkInitKDC}
  SN_pkInitKDC = 'pkInitKDC';
  {$EXTERNALSYM LN_pkInitKDC}
  LN_pkInitKDC = 'Signing KDC Response';
  {$EXTERNALSYM NID_pkInitKDC}
  NID_pkInitKDC = 1033;

  {$EXTERNALSYM SN_X25519}
  SN_X25519 = 'X25519';
  {$EXTERNALSYM NID_X25519}
  NID_X25519 = 1034;

  {$EXTERNALSYM SN_X448}
  SN_X448 = 'X448';
  {$EXTERNALSYM NID_X448}
  NID_X448 = 1035;

  {$EXTERNALSYM SN_ED25519}
  SN_ED25519 = 'ED25519';
  {$EXTERNALSYM NID_ED25519}
  NID_ED25519 = 1087;

  {$EXTERNALSYM SN_ED448}
  SN_ED448 = 'ED448';
  {$EXTERNALSYM NID_ED448}
  NID_ED448 = 1088;

  {$EXTERNALSYM SN_kx_rsa}
  SN_kx_rsa = 'KxRSA';
  {$EXTERNALSYM LN_kx_rsa}
  LN_kx_rsa = 'kx-rsa';
  {$EXTERNALSYM NID_kx_rsa}
  NID_kx_rsa = 1037;

  {$EXTERNALSYM SN_kx_ecdhe}
  SN_kx_ecdhe = 'KxECDHE';
  {$EXTERNALSYM LN_kx_ecdhe}
  LN_kx_ecdhe = 'kx-ecdhe';
  {$EXTERNALSYM NID_kx_ecdhe}
  NID_kx_ecdhe = 1038;

  {$EXTERNALSYM SN_kx_dhe}
  SN_kx_dhe = 'KxDHE';
  {$EXTERNALSYM LN_kx_dhe}
  LN_kx_dhe = 'kx-dhe';
  {$EXTERNALSYM NID_kx_dhe}
  NID_kx_dhe = 1039;

  {$EXTERNALSYM SN_kx_ecdhe_psk}
  SN_kx_ecdhe_psk = 'KxECDHE-PSK';
  {$EXTERNALSYM LN_kx_ecdhe_psk}
  LN_kx_ecdhe_psk = 'kx-ecdhe-psk';
  {$EXTERNALSYM NID_kx_ecdhe_psk}
  NID_kx_ecdhe_psk = 1040;

  {$EXTERNALSYM SN_kx_dhe_psk}
  SN_kx_dhe_psk = 'KxDHE-PSK';
  {$EXTERNALSYM LN_kx_dhe_psk}
  LN_kx_dhe_psk = 'kx-dhe-psk';
  {$EXTERNALSYM NID_kx_dhe_psk}
  NID_kx_dhe_psk = 1041;

  {$EXTERNALSYM SN_kx_rsa_psk}
  SN_kx_rsa_psk = 'KxRSA_PSK';
  {$EXTERNALSYM LN_kx_rsa_psk}
  LN_kx_rsa_psk = 'kx-rsa-psk';
  {$EXTERNALSYM NID_kx_rsa_psk}
  NID_kx_rsa_psk = 1042;

  {$EXTERNALSYM SN_kx_psk}
  SN_kx_psk = 'KxPSK';
  {$EXTERNALSYM LN_kx_psk}
  LN_kx_psk = 'kx-psk';
  {$EXTERNALSYM NID_kx_psk}
  NID_kx_psk = 1043;

  {$EXTERNALSYM SN_kx_srp}
  SN_kx_srp = 'KxSRP';
  {$EXTERNALSYM LN_kx_srp}
  LN_kx_srp = 'kx-srp';
  {$EXTERNALSYM NID_kx_srp}
  NID_kx_srp = 1044;

  {$EXTERNALSYM SN_kx_gost}
  SN_kx_gost = 'KxGOST';
  {$EXTERNALSYM LN_kx_gost}
  LN_kx_gost = 'kx-gost';
  {$EXTERNALSYM NID_kx_gost}
  NID_kx_gost = 1045;

  {$EXTERNALSYM SN_kx_any}
  SN_kx_any = 'KxANY';
  {$EXTERNALSYM LN_kx_any}
  LN_kx_any = 'kx-any';
  {$EXTERNALSYM NID_kx_any}
  NID_kx_any = 1063;

  {$EXTERNALSYM SN_auth_rsa}
  SN_auth_rsa = 'AuthRSA';
  {$EXTERNALSYM LN_auth_rsa}
  LN_auth_rsa = 'auth-rsa';
  {$EXTERNALSYM NID_auth_rsa}
  NID_auth_rsa = 1046;

  {$EXTERNALSYM SN_auth_ecdsa}
  SN_auth_ecdsa = 'AuthECDSA';
  {$EXTERNALSYM LN_auth_ecdsa}
  LN_auth_ecdsa = 'auth-ecdsa';
  {$EXTERNALSYM NID_auth_ecdsa}
  NID_auth_ecdsa = 1047;

  {$EXTERNALSYM SN_auth_psk}
  SN_auth_psk = 'AuthPSK';
  {$EXTERNALSYM LN_auth_psk}
  LN_auth_psk = 'auth-psk';
  {$EXTERNALSYM NID_auth_psk}
  NID_auth_psk = 1048;

  {$EXTERNALSYM SN_auth_dss}
  SN_auth_dss = 'AuthDSS';
  {$EXTERNALSYM LN_auth_dss}
  LN_auth_dss = 'auth-dss';
  {$EXTERNALSYM NID_auth_dss}
  NID_auth_dss = 1049;

  {$EXTERNALSYM SN_auth_gost01}
  SN_auth_gost01 = 'AuthGOST01';
  {$EXTERNALSYM LN_auth_gost01}
  LN_auth_gost01 = 'auth-gost01';
  {$EXTERNALSYM NID_auth_gost01}
  NID_auth_gost01 = 1050;

  {$EXTERNALSYM SN_auth_gost12}
  SN_auth_gost12 = 'AuthGOST12';
  {$EXTERNALSYM LN_auth_gost12}
  LN_auth_gost12 = 'auth-gost12';
  {$EXTERNALSYM NID_auth_gost12}
  NID_auth_gost12 = 1051;

  {$EXTERNALSYM SN_auth_srp}
  SN_auth_srp = 'AuthSRP';
  {$EXTERNALSYM LN_auth_srp}
  LN_auth_srp = 'auth-srp';
  {$EXTERNALSYM NID_auth_srp}
  NID_auth_srp = 1052;

  {$EXTERNALSYM SN_auth_null}
  SN_auth_null = 'AuthNULL';
  {$EXTERNALSYM LN_auth_null}
  LN_auth_null = 'auth-null';
  {$EXTERNALSYM NID_auth_null}
  NID_auth_null = 1053;

  {$EXTERNALSYM SN_auth_any}
  SN_auth_any = 'AuthANY';
  {$EXTERNALSYM LN_auth_any}
  LN_auth_any = 'auth-any';
  {$EXTERNALSYM NID_auth_any}
  NID_auth_any = 1064;

  {$EXTERNALSYM SN_poly1305}
  SN_poly1305 = 'Poly1305';
  {$EXTERNALSYM LN_poly1305}
  LN_poly1305 = 'poly1305';
  {$EXTERNALSYM NID_poly1305}
  NID_poly1305 = 1061;

  {$EXTERNALSYM SN_siphash}
  SN_siphash = 'SipHash';
  {$EXTERNALSYM LN_siphash}
  LN_siphash = 'siphash';
  {$EXTERNALSYM NID_siphash}
  NID_siphash = 1062;

  {$EXTERNALSYM SN_ffdhe2048}
  SN_ffdhe2048 = 'ffdhe2048';
  {$EXTERNALSYM NID_ffdhe2048}
  NID_ffdhe2048 = 1126;

  {$EXTERNALSYM SN_ffdhe3072}
  SN_ffdhe3072 = 'ffdhe3072';
  {$EXTERNALSYM NID_ffdhe3072}
  NID_ffdhe3072 = 1127;

  {$EXTERNALSYM SN_ffdhe4096}
  SN_ffdhe4096 = 'ffdhe4096';
  {$EXTERNALSYM NID_ffdhe4096}
  NID_ffdhe4096 = 1128;

  {$EXTERNALSYM SN_ffdhe6144}
  SN_ffdhe6144 = 'ffdhe6144';
  {$EXTERNALSYM NID_ffdhe6144}
  NID_ffdhe6144 = 1129;

  {$EXTERNALSYM SN_ffdhe8192}
  SN_ffdhe8192 = 'ffdhe8192';
  {$EXTERNALSYM NID_ffdhe8192}
  NID_ffdhe8192 = 1130;

  {$EXTERNALSYM SN_ISO_UA}
  SN_ISO_UA = 'ISO-UA';
  {$EXTERNALSYM NID_ISO_UA}
  NID_ISO_UA = 1150;

  {$EXTERNALSYM SN_ua_pki}
  SN_ua_pki = 'ua-pki';
  {$EXTERNALSYM NID_ua_pki}
  NID_ua_pki = 1151;

  {$EXTERNALSYM SN_dstu28147}
  SN_dstu28147 = 'dstu28147';
  {$EXTERNALSYM LN_dstu28147}
  LN_dstu28147 = 'DSTU Gost 28147-2009';
  {$EXTERNALSYM NID_dstu28147}
  NID_dstu28147 = 1152;

  {$EXTERNALSYM SN_dstu28147_ofb}
  SN_dstu28147_ofb = 'dstu28147-ofb';
  {$EXTERNALSYM LN_dstu28147_ofb}
  LN_dstu28147_ofb = 'DSTU Gost 28147-2009 OFB mode';
  {$EXTERNALSYM NID_dstu28147_ofb}
  NID_dstu28147_ofb = 1153;

  {$EXTERNALSYM SN_dstu28147_cfb}
  SN_dstu28147_cfb = 'dstu28147-cfb';
  {$EXTERNALSYM LN_dstu28147_cfb}
  LN_dstu28147_cfb = 'DSTU Gost 28147-2009 CFB mode';
  {$EXTERNALSYM NID_dstu28147_cfb}
  NID_dstu28147_cfb = 1154;

  {$EXTERNALSYM SN_dstu28147_wrap}
  SN_dstu28147_wrap = 'dstu28147-wrap';
  {$EXTERNALSYM LN_dstu28147_wrap}
  LN_dstu28147_wrap = 'DSTU Gost 28147-2009 key wrap';
  {$EXTERNALSYM NID_dstu28147_wrap}
  NID_dstu28147_wrap = 1155;

  {$EXTERNALSYM SN_hmacWithDstu34311}
  SN_hmacWithDstu34311 = 'hmacWithDstu34311';
  {$EXTERNALSYM LN_hmacWithDstu34311}
  LN_hmacWithDstu34311 = 'HMAC DSTU Gost 34311-95';
  {$EXTERNALSYM NID_hmacWithDstu34311}
  NID_hmacWithDstu34311 = 1156;

  {$EXTERNALSYM SN_dstu34311}
  SN_dstu34311 = 'dstu34311';
  {$EXTERNALSYM LN_dstu34311}
  LN_dstu34311 = 'DSTU Gost 34311-95';
  {$EXTERNALSYM NID_dstu34311}
  NID_dstu34311 = 1157;

  {$EXTERNALSYM SN_dstu4145le}
  SN_dstu4145le = 'dstu4145le';
  {$EXTERNALSYM LN_dstu4145le}
  LN_dstu4145le = 'DSTU 4145-2002 little endian';
  {$EXTERNALSYM NID_dstu4145le}
  NID_dstu4145le = 1158;

  {$EXTERNALSYM SN_dstu4145be}
  SN_dstu4145be = 'dstu4145be';
  {$EXTERNALSYM LN_dstu4145be}
  LN_dstu4145be = 'DSTU 4145-2002 big endian';
  {$EXTERNALSYM NID_dstu4145be}
  NID_dstu4145be = 1159;

  {$EXTERNALSYM SN_uacurve0}
  SN_uacurve0 = 'uacurve0';
  {$EXTERNALSYM LN_uacurve0}
  LN_uacurve0 = 'DSTU curve 0';
  {$EXTERNALSYM NID_uacurve0}
  NID_uacurve0 = 1160;

  {$EXTERNALSYM SN_uacurve1}
  SN_uacurve1 = 'uacurve1';
  {$EXTERNALSYM LN_uacurve1}
  LN_uacurve1 = 'DSTU curve 1';
  {$EXTERNALSYM NID_uacurve1}
  NID_uacurve1 = 1161;

  {$EXTERNALSYM SN_uacurve2}
  SN_uacurve2 = 'uacurve2';
  {$EXTERNALSYM LN_uacurve2}
  LN_uacurve2 = 'DSTU curve 2';
  {$EXTERNALSYM NID_uacurve2}
  NID_uacurve2 = 1162;

  {$EXTERNALSYM SN_uacurve3}
  SN_uacurve3 = 'uacurve3';
  {$EXTERNALSYM LN_uacurve3}
  LN_uacurve3 = 'DSTU curve 3';
  {$EXTERNALSYM NID_uacurve3}
  NID_uacurve3 = 1163;

  {$EXTERNALSYM SN_uacurve4}
  SN_uacurve4 = 'uacurve4';
  {$EXTERNALSYM LN_uacurve4}
  LN_uacurve4 = 'DSTU curve 4';
  {$EXTERNALSYM NID_uacurve4}
  NID_uacurve4 = 1164;

  {$EXTERNALSYM SN_uacurve5}
  SN_uacurve5 = 'uacurve5';
  {$EXTERNALSYM LN_uacurve5}
  LN_uacurve5 = 'DSTU curve 5';
  {$EXTERNALSYM NID_uacurve5}
  NID_uacurve5 = 1165;

  {$EXTERNALSYM SN_uacurve6}
  SN_uacurve6 = 'uacurve6';
  {$EXTERNALSYM LN_uacurve6}
  LN_uacurve6 = 'DSTU curve 6';
  {$EXTERNALSYM NID_uacurve6}
  NID_uacurve6 = 1166;

  {$EXTERNALSYM SN_uacurve7}
  SN_uacurve7 = 'uacurve7';
  {$EXTERNALSYM LN_uacurve7}
  LN_uacurve7 = 'DSTU curve 7';
  {$EXTERNALSYM NID_uacurve7}
  NID_uacurve7 = 1167;

  {$EXTERNALSYM SN_uacurve8}
  SN_uacurve8 = 'uacurve8';
  {$EXTERNALSYM LN_uacurve8}
  LN_uacurve8 = 'DSTU curve 8';
  {$EXTERNALSYM NID_uacurve8}
  NID_uacurve8 = 1168;

  {$EXTERNALSYM SN_uacurve9}
  SN_uacurve9 = 'uacurve9';
  {$EXTERNALSYM LN_uacurve9}
  LN_uacurve9 = 'DSTU curve 9';
  {$EXTERNALSYM NID_uacurve9}
  NID_uacurve9 = 1169;

implementation

end.
