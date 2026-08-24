/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_asn1err.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_asn1err.h2pas
     and this file regenerated. TaurusTLSHeaders_asn1err.h2pas is distributed with the full Indy
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

unit TaurusTLSHeaders_asn1err;

interface

// Headers for OpenSSL 1.1.1
// asn1err.h


uses
  IdCTypes,
  IdGlobal
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  , TaurusTLSConsts
  {$ENDIF};

const

// ASN1 function codes.
  {$EXTERNALSYM ASN1_F_A2D_ASN1_OBJECT}
  ASN1_F_A2D_ASN1_OBJECT                          = 100;
  {$EXTERNALSYM ASN1_F_A2I_ASN1_INTEGER}
  ASN1_F_A2I_ASN1_INTEGER                         = 102;
  {$EXTERNALSYM ASN1_F_A2I_ASN1_STRING}
  ASN1_F_A2I_ASN1_STRING                          = 103;
  {$EXTERNALSYM ASN1_F_APPEND_EXP}
  ASN1_F_APPEND_EXP                               = 176;
  {$EXTERNALSYM ASN1_F_ASN1_BIO_INIT}
  ASN1_F_ASN1_BIO_INIT                            = 113;
  {$EXTERNALSYM ASN1_F_ASN1_BIT_STRING_SET_BIT}
  ASN1_F_ASN1_BIT_STRING_SET_BIT                  = 183;
  {$EXTERNALSYM ASN1_F_ASN1_CB}
  ASN1_F_ASN1_CB                                  = 177;
  {$EXTERNALSYM ASN1_F_ASN1_CHECK_TLEN}
  ASN1_F_ASN1_CHECK_TLEN                          = 104;
  {$EXTERNALSYM ASN1_F_ASN1_COLLECT}
  ASN1_F_ASN1_COLLECT                             = 106;
  {$EXTERNALSYM ASN1_F_ASN1_D2I_EX_PRIMITIVE}
  ASN1_F_ASN1_D2I_EX_PRIMITIVE                    = 108;
  {$EXTERNALSYM ASN1_F_ASN1_D2I_FP}
  ASN1_F_ASN1_D2I_FP                              = 109;
  {$EXTERNALSYM ASN1_F_ASN1_D2I_READ_BIO}
  ASN1_F_ASN1_D2I_READ_BIO                        = 107;
  {$EXTERNALSYM ASN1_F_ASN1_DIGEST}
  ASN1_F_ASN1_DIGEST                              = 184;
  {$EXTERNALSYM ASN1_F_ASN1_DO_ADB}
  ASN1_F_ASN1_DO_ADB                              = 110;
  {$EXTERNALSYM ASN1_F_ASN1_DO_LOCK}
  ASN1_F_ASN1_DO_LOCK                             = 233;
  {$EXTERNALSYM ASN1_F_ASN1_DUP}
  ASN1_F_ASN1_DUP                                 = 111;
  {$EXTERNALSYM ASN1_F_ASN1_ENC_SAVE}
  ASN1_F_ASN1_ENC_SAVE                            = 115;
  {$EXTERNALSYM ASN1_F_ASN1_EX_C2I}
  ASN1_F_ASN1_EX_C2I                              = 204;
  {$EXTERNALSYM ASN1_F_ASN1_FIND_END}
  ASN1_F_ASN1_FIND_END                            = 190;
  {$EXTERNALSYM ASN1_F_ASN1_GENERALIZEDTIME_ADJ}
  ASN1_F_ASN1_GENERALIZEDTIME_ADJ                 = 216;
  {$EXTERNALSYM ASN1_F_ASN1_GENERATE_V3}
  ASN1_F_ASN1_GENERATE_V3                         = 178;
  {$EXTERNALSYM ASN1_F_ASN1_GET_INT64}
  ASN1_F_ASN1_GET_INT64                           = 224;
  {$EXTERNALSYM ASN1_F_ASN1_GET_OBJECT}
  ASN1_F_ASN1_GET_OBJECT                          = 114;
  {$EXTERNALSYM ASN1_F_ASN1_GET_UINT64}
  ASN1_F_ASN1_GET_UINT64                          = 225;
  {$EXTERNALSYM ASN1_F_ASN1_I2D_BIO}
  ASN1_F_ASN1_I2D_BIO                             = 116;
  {$EXTERNALSYM ASN1_F_ASN1_I2D_FP}
  ASN1_F_ASN1_I2D_FP                              = 117;
  {$EXTERNALSYM ASN1_F_ASN1_ITEM_D2I_FP}
  ASN1_F_ASN1_ITEM_D2I_FP                         = 206;
  {$EXTERNALSYM ASN1_F_ASN1_ITEM_DUP}
  ASN1_F_ASN1_ITEM_DUP                            = 191;
  {$EXTERNALSYM ASN1_F_ASN1_ITEM_EMBED_D2I}
  ASN1_F_ASN1_ITEM_EMBED_D2I                      = 120;
  {$EXTERNALSYM ASN1_F_ASN1_ITEM_EMBED_NEW}
  ASN1_F_ASN1_ITEM_EMBED_NEW                      = 121;
  {$EXTERNALSYM ASN1_F_ASN1_ITEM_FLAGS_I2D}
  ASN1_F_ASN1_ITEM_FLAGS_I2D                      = 118;
  {$EXTERNALSYM ASN1_F_ASN1_ITEM_I2D_BIO}
  ASN1_F_ASN1_ITEM_I2D_BIO                        = 192;
  {$EXTERNALSYM ASN1_F_ASN1_ITEM_I2D_FP}
  ASN1_F_ASN1_ITEM_I2D_FP                         = 193;
  {$EXTERNALSYM ASN1_F_ASN1_ITEM_PACK}
  ASN1_F_ASN1_ITEM_PACK                           = 198;
  {$EXTERNALSYM ASN1_F_ASN1_ITEM_SIGN}
  ASN1_F_ASN1_ITEM_SIGN                           = 195;
  {$EXTERNALSYM ASN1_F_ASN1_ITEM_SIGN_CTX}
  ASN1_F_ASN1_ITEM_SIGN_CTX                       = 220;
  {$EXTERNALSYM ASN1_F_ASN1_ITEM_UNPACK}
  ASN1_F_ASN1_ITEM_UNPACK                         = 199;
  {$EXTERNALSYM ASN1_F_ASN1_ITEM_VERIFY}
  ASN1_F_ASN1_ITEM_VERIFY                         = 197;
  {$EXTERNALSYM ASN1_F_ASN1_MBSTRING_NCOPY}
  ASN1_F_ASN1_MBSTRING_NCOPY                      = 122;
  {$EXTERNALSYM ASN1_F_ASN1_OBJECT_NEW}
  ASN1_F_ASN1_OBJECT_NEW                          = 123;
  {$EXTERNALSYM ASN1_F_ASN1_OUTPUT_DATA}
  ASN1_F_ASN1_OUTPUT_DATA                         = 214;
  {$EXTERNALSYM ASN1_F_ASN1_PCTX_NEW}
  ASN1_F_ASN1_PCTX_NEW                            = 205;
  {$EXTERNALSYM ASN1_F_ASN1_PRIMITIVE_NEW}
  ASN1_F_ASN1_PRIMITIVE_NEW                       = 119;
  {$EXTERNALSYM ASN1_F_ASN1_SCTX_NEW}
  ASN1_F_ASN1_SCTX_NEW                            = 221;
  {$EXTERNALSYM ASN1_F_ASN1_SIGN}
  ASN1_F_ASN1_SIGN                                = 128;
  {$EXTERNALSYM ASN1_F_ASN1_STR2TYPE}
  ASN1_F_ASN1_STR2TYPE                            = 179;
  {$EXTERNALSYM ASN1_F_ASN1_STRING_GET_INT64}
  ASN1_F_ASN1_STRING_GET_INT64                    = 227;
  {$EXTERNALSYM ASN1_F_ASN1_STRING_GET_UINT64}
  ASN1_F_ASN1_STRING_GET_UINT64                   = 230;
  {$EXTERNALSYM ASN1_F_ASN1_STRING_SET}
  ASN1_F_ASN1_STRING_SET                          = 186;
  {$EXTERNALSYM ASN1_F_ASN1_STRING_TABLE_ADD}
  ASN1_F_ASN1_STRING_TABLE_ADD                    = 129;
  {$EXTERNALSYM ASN1_F_ASN1_STRING_TO_BN}
  ASN1_F_ASN1_STRING_TO_BN                        = 228;
  {$EXTERNALSYM ASN1_F_ASN1_STRING_TYPE_NEW}
  ASN1_F_ASN1_STRING_TYPE_NEW                     = 130;
  {$EXTERNALSYM ASN1_F_ASN1_TEMPLATE_EX_D2I}
  ASN1_F_ASN1_TEMPLATE_EX_D2I                     = 132;
  {$EXTERNALSYM ASN1_F_ASN1_TEMPLATE_NEW}
  ASN1_F_ASN1_TEMPLATE_NEW                        = 133;
  {$EXTERNALSYM ASN1_F_ASN1_TEMPLATE_NOEXP_D2I}
  ASN1_F_ASN1_TEMPLATE_NOEXP_D2I                  = 131;
  {$EXTERNALSYM ASN1_F_ASN1_TIME_ADJ}
  ASN1_F_ASN1_TIME_ADJ                            = 217;
  {$EXTERNALSYM ASN1_F_ASN1_TYPE_GET_INT_OCTETSTRING}
  ASN1_F_ASN1_TYPE_GET_INT_OCTETSTRING            = 134;
  {$EXTERNALSYM ASN1_F_ASN1_TYPE_GET_OCTETSTRING}
  ASN1_F_ASN1_TYPE_GET_OCTETSTRING                = 135;
  {$EXTERNALSYM ASN1_F_ASN1_UTCTIME_ADJ}
  ASN1_F_ASN1_UTCTIME_ADJ                         = 218;
  {$EXTERNALSYM ASN1_F_ASN1_VERIFY}
  ASN1_F_ASN1_VERIFY                              = 137;
  {$EXTERNALSYM ASN1_F_B64_READ_ASN1}
  ASN1_F_B64_READ_ASN1                            = 209;
  {$EXTERNALSYM ASN1_F_B64_WRITE_ASN1}
  ASN1_F_B64_WRITE_ASN1                           = 210;
  {$EXTERNALSYM ASN1_F_BIO_NEW_NDEF}
  ASN1_F_BIO_NEW_NDEF                             = 208;
  {$EXTERNALSYM ASN1_F_BITSTR_CB}
  ASN1_F_BITSTR_CB                                = 180;
  {$EXTERNALSYM ASN1_F_BN_TO_ASN1_STRING}
  ASN1_F_BN_TO_ASN1_STRING                        = 229;
  {$EXTERNALSYM ASN1_F_C2I_ASN1_BIT_STRING}
  ASN1_F_C2I_ASN1_BIT_STRING                      = 189;
  {$EXTERNALSYM ASN1_F_C2I_ASN1_INTEGER}
  ASN1_F_C2I_ASN1_INTEGER                         = 194;
  {$EXTERNALSYM ASN1_F_C2I_ASN1_OBJECT}
  ASN1_F_C2I_ASN1_OBJECT                          = 196;
  {$EXTERNALSYM ASN1_F_C2I_IBUF}
  ASN1_F_C2I_IBUF                                 = 226;
  {$EXTERNALSYM ASN1_F_C2I_UINT64_INT}
  ASN1_F_C2I_UINT64_INT                           = 101;
  {$EXTERNALSYM ASN1_F_COLLECT_DATA}
  ASN1_F_COLLECT_DATA                             = 140;
  {$EXTERNALSYM ASN1_F_D2I_ASN1_OBJECT}
  ASN1_F_D2I_ASN1_OBJECT                          = 147;
  {$EXTERNALSYM ASN1_F_D2I_ASN1_UINTEGER}
  ASN1_F_D2I_ASN1_UINTEGER                        = 150;
  {$EXTERNALSYM ASN1_F_D2I_AUTOPRIVATEKEY}
  ASN1_F_D2I_AUTOPRIVATEKEY                       = 207;
  {$EXTERNALSYM ASN1_F_D2I_PRIVATEKEY}
  ASN1_F_D2I_PRIVATEKEY                           = 154;
  {$EXTERNALSYM ASN1_F_D2I_PUBLICKEY}
  ASN1_F_D2I_PUBLICKEY                            = 155;
  {$EXTERNALSYM ASN1_F_DO_BUF}
  ASN1_F_DO_BUF                                   = 142;
  {$EXTERNALSYM ASN1_F_DO_CREATE}
  ASN1_F_DO_CREATE                                = 124;
  {$EXTERNALSYM ASN1_F_DO_DUMP}
  ASN1_F_DO_DUMP                                  = 125;
  {$EXTERNALSYM ASN1_F_DO_TCREATE}
  ASN1_F_DO_TCREATE                               = 222;
  {$EXTERNALSYM ASN1_F_I2A_ASN1_OBJECT}
  ASN1_F_I2A_ASN1_OBJECT                          = 126;
  {$EXTERNALSYM ASN1_F_I2D_ASN1_BIO_STREAM}
  ASN1_F_I2D_ASN1_BIO_STREAM                      = 211;
  {$EXTERNALSYM ASN1_F_I2D_ASN1_OBJECT}
  ASN1_F_I2D_ASN1_OBJECT                          = 143;
  {$EXTERNALSYM ASN1_F_I2D_DSA_PUBKEY}
  ASN1_F_I2D_DSA_PUBKEY                           = 161;
  {$EXTERNALSYM ASN1_F_I2D_EC_PUBKEY}
  ASN1_F_I2D_EC_PUBKEY                            = 181;
  {$EXTERNALSYM ASN1_F_I2D_PRIVATEKEY}
  ASN1_F_I2D_PRIVATEKEY                           = 163;
  {$EXTERNALSYM ASN1_F_I2D_PUBLICKEY}
  ASN1_F_I2D_PUBLICKEY                            = 164;
  {$EXTERNALSYM ASN1_F_I2D_RSA_PUBKEY}
  ASN1_F_I2D_RSA_PUBKEY                           = 165;
  {$EXTERNALSYM ASN1_F_LONG_C2I}
  ASN1_F_LONG_C2I                                 = 166;
  {$EXTERNALSYM ASN1_F_NDEF_PREFIX}
  ASN1_F_NDEF_PREFIX                              = 127;
  {$EXTERNALSYM ASN1_F_NDEF_SUFFIX}
  ASN1_F_NDEF_SUFFIX                              = 136;
  {$EXTERNALSYM ASN1_F_OID_MODULE_INIT}
  ASN1_F_OID_MODULE_INIT                          = 174;
  {$EXTERNALSYM ASN1_F_PARSE_TAGGING}
  ASN1_F_PARSE_TAGGING                            = 182;
  {$EXTERNALSYM ASN1_F_PKCS5_PBE2_SET_IV}
  ASN1_F_PKCS5_PBE2_SET_IV                        = 167;
  {$EXTERNALSYM ASN1_F_PKCS5_PBE2_SET_SCRYPT}
  ASN1_F_PKCS5_PBE2_SET_SCRYPT                    = 231;
  {$EXTERNALSYM ASN1_F_PKCS5_PBE_SET}
  ASN1_F_PKCS5_PBE_SET                            = 202;
  {$EXTERNALSYM ASN1_F_PKCS5_PBE_SET0_ALGOR}
  ASN1_F_PKCS5_PBE_SET0_ALGOR                     = 215;
  {$EXTERNALSYM ASN1_F_PKCS5_PBKDF2_SET}
  ASN1_F_PKCS5_PBKDF2_SET                         = 219;
  {$EXTERNALSYM ASN1_F_PKCS5_SCRYPT_SET}
  ASN1_F_PKCS5_SCRYPT_SET                         = 232;
  {$EXTERNALSYM ASN1_F_SMIME_READ_ASN1}
  ASN1_F_SMIME_READ_ASN1                          = 212;
  {$EXTERNALSYM ASN1_F_SMIME_TEXT}
  ASN1_F_SMIME_TEXT                               = 213;
  {$EXTERNALSYM ASN1_F_STABLE_GET}
  ASN1_F_STABLE_GET                               = 138;
  {$EXTERNALSYM ASN1_F_STBL_MODULE_INIT}
  ASN1_F_STBL_MODULE_INIT                         = 223;
  {$EXTERNALSYM ASN1_F_UINT32_C2I}
  ASN1_F_UINT32_C2I                               = 105;
  {$EXTERNALSYM ASN1_F_UINT32_NEW}
  ASN1_F_UINT32_NEW                               = 139;
  {$EXTERNALSYM ASN1_F_UINT64_C2I}
  ASN1_F_UINT64_C2I                               = 112;
  {$EXTERNALSYM ASN1_F_UINT64_NEW}
  ASN1_F_UINT64_NEW                               = 141;
  {$EXTERNALSYM ASN1_F_X509_CRL_ADD0_REVOKED}
  ASN1_F_X509_CRL_ADD0_REVOKED                    = 169;
  {$EXTERNALSYM ASN1_F_X509_INFO_NEW}
  ASN1_F_X509_INFO_NEW                            = 170;
  {$EXTERNALSYM ASN1_F_X509_NAME_ENCODE}
  ASN1_F_X509_NAME_ENCODE                         = 203;
  {$EXTERNALSYM ASN1_F_X509_NAME_EX_D2I}
  ASN1_F_X509_NAME_EX_D2I                         = 158;
  {$EXTERNALSYM ASN1_F_X509_NAME_EX_NEW}
  ASN1_F_X509_NAME_EX_NEW                         = 171;
  {$EXTERNALSYM ASN1_F_X509_PKEY_NEW}
  ASN1_F_X509_PKEY_NEW                            = 173;

// ASN1 reason codes.
  {$EXTERNALSYM ASN1_R_ADDING_OBJECT}
  ASN1_R_ADDING_OBJECT                            = 171;
  {$EXTERNALSYM ASN1_R_ASN1_PARSE_ERROR}
  ASN1_R_ASN1_PARSE_ERROR                         = 203;
  {$EXTERNALSYM ASN1_R_ASN1_SIG_PARSE_ERROR}
  ASN1_R_ASN1_SIG_PARSE_ERROR                     = 204;
  {$EXTERNALSYM ASN1_R_AUX_ERROR}
  ASN1_R_AUX_ERROR                                = 100;
  {$EXTERNALSYM ASN1_R_BAD_OBJECT_HEADER}
  ASN1_R_BAD_OBJECT_HEADER                        = 102;
  {$EXTERNALSYM ASN1_R_BMPSTRING_IS_WRONG_LENGTH}
  ASN1_R_BMPSTRING_IS_WRONG_LENGTH                = 214;
  {$EXTERNALSYM ASN1_R_BN_LIB}
  ASN1_R_BN_LIB                                   = 105;
  {$EXTERNALSYM ASN1_R_BOOLEAN_IS_WRONG_LENGTH}
  ASN1_R_BOOLEAN_IS_WRONG_LENGTH                  = 106;
  {$EXTERNALSYM ASN1_R_BUFFER_TOO_SMALL}
  ASN1_R_BUFFER_TOO_SMALL                         = 107;
  {$EXTERNALSYM ASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER}
  ASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER          = 108;
  {$EXTERNALSYM ASN1_R_CONTEXT_NOT_INITIALISED}
  ASN1_R_CONTEXT_NOT_INITIALISED                  = 217;
  {$EXTERNALSYM ASN1_R_DATA_IS_WRONG}
  ASN1_R_DATA_IS_WRONG                            = 109;
  {$EXTERNALSYM ASN1_R_DECODE_ERROR}
  ASN1_R_DECODE_ERROR                             = 110;
  {$EXTERNALSYM ASN1_R_DEPTH_EXCEEDED}
  ASN1_R_DEPTH_EXCEEDED                           = 174;
  {$EXTERNALSYM ASN1_R_DIGEST_AND_KEY_TYPE_NOT_SUPPORTED}
  ASN1_R_DIGEST_AND_KEY_TYPE_NOT_SUPPORTED        = 198;
  {$EXTERNALSYM ASN1_R_ENCODE_ERROR}
  ASN1_R_ENCODE_ERROR                             = 112;
  {$EXTERNALSYM ASN1_R_ERROR_GETTING_TIME}
  ASN1_R_ERROR_GETTING_TIME                       = 173;
  {$EXTERNALSYM ASN1_R_ERROR_LOADING_SECTION}
  ASN1_R_ERROR_LOADING_SECTION                    = 172;
  {$EXTERNALSYM ASN1_R_ERROR_SETTING_CIPHER_PARAMS}
  ASN1_R_ERROR_SETTING_CIPHER_PARAMS              = 114;
  {$EXTERNALSYM ASN1_R_EXPECTING_AN_INTEGER}
  ASN1_R_EXPECTING_AN_INTEGER                     = 115;
  {$EXTERNALSYM ASN1_R_EXPECTING_AN_OBJECT}
  ASN1_R_EXPECTING_AN_OBJECT                      = 116;
  {$EXTERNALSYM ASN1_R_EXPLICIT_LENGTH_MISMATCH}
  ASN1_R_EXPLICIT_LENGTH_MISMATCH                 = 119;
  {$EXTERNALSYM ASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED}
  ASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED             = 120;
  {$EXTERNALSYM ASN1_R_FIELD_MISSING}
  ASN1_R_FIELD_MISSING                            = 121;
  {$EXTERNALSYM ASN1_R_FIRST_NUM_TOO_LARGE}
  ASN1_R_FIRST_NUM_TOO_LARGE                      = 122;
  {$EXTERNALSYM ASN1_R_HEADER_TOO_LONG}
  ASN1_R_HEADER_TOO_LONG                          = 123;
  {$EXTERNALSYM ASN1_R_ILLEGAL_BITSTRING_FORMAT}
  ASN1_R_ILLEGAL_BITSTRING_FORMAT                 = 175;
  {$EXTERNALSYM ASN1_R_ILLEGAL_BOOLEAN}
  ASN1_R_ILLEGAL_BOOLEAN                          = 176;
  {$EXTERNALSYM ASN1_R_ILLEGAL_CHARACTERS}
  ASN1_R_ILLEGAL_CHARACTERS                       = 124;
  {$EXTERNALSYM ASN1_R_ILLEGAL_FORMAT}
  ASN1_R_ILLEGAL_FORMAT                           = 177;
  {$EXTERNALSYM ASN1_R_ILLEGAL_HEX}
  ASN1_R_ILLEGAL_HEX                              = 178;
  {$EXTERNALSYM ASN1_R_ILLEGAL_IMPLICIT_TAG}
  ASN1_R_ILLEGAL_IMPLICIT_TAG                     = 179;
  {$EXTERNALSYM ASN1_R_ILLEGAL_INTEGER}
  ASN1_R_ILLEGAL_INTEGER                          = 180;
  {$EXTERNALSYM ASN1_R_ILLEGAL_NEGATIVE_VALUE}
  ASN1_R_ILLEGAL_NEGATIVE_VALUE                   = 226;
  {$EXTERNALSYM ASN1_R_ILLEGAL_NESTED_TAGGING}
  ASN1_R_ILLEGAL_NESTED_TAGGING                   = 181;
  {$EXTERNALSYM ASN1_R_ILLEGAL_NULL}
  ASN1_R_ILLEGAL_NULL                             = 125;
  {$EXTERNALSYM ASN1_R_ILLEGAL_NULL_VALUE}
  ASN1_R_ILLEGAL_NULL_VALUE                       = 182;
  {$EXTERNALSYM ASN1_R_ILLEGAL_OBJECT}
  ASN1_R_ILLEGAL_OBJECT                           = 183;
  {$EXTERNALSYM ASN1_R_ILLEGAL_OPTIONAL_ANY}
  ASN1_R_ILLEGAL_OPTIONAL_ANY                     = 126;
  {$EXTERNALSYM ASN1_R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE}
  ASN1_R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE         = 170;
  {$EXTERNALSYM ASN1_R_ILLEGAL_PADDING}
  ASN1_R_ILLEGAL_PADDING                          = 221;
  {$EXTERNALSYM ASN1_R_ILLEGAL_TAGGED_ANY}
  ASN1_R_ILLEGAL_TAGGED_ANY                       = 127;
  {$EXTERNALSYM ASN1_R_ILLEGAL_TIME_VALUE}
  ASN1_R_ILLEGAL_TIME_VALUE                       = 184;
  {$EXTERNALSYM ASN1_R_ILLEGAL_ZERO_CONTENT}
  ASN1_R_ILLEGAL_ZERO_CONTENT                     = 222;
  {$EXTERNALSYM ASN1_R_INTEGER_NOT_ASCII_FORMAT}
  ASN1_R_INTEGER_NOT_ASCII_FORMAT                 = 185;
  {$EXTERNALSYM ASN1_R_INTEGER_TOO_LARGE_FOR_LONG}
  ASN1_R_INTEGER_TOO_LARGE_FOR_LONG               = 128;
  {$EXTERNALSYM ASN1_R_INVALID_BIT_STRING_BITS_LEFT}
  ASN1_R_INVALID_BIT_STRING_BITS_LEFT             = 220;
  {$EXTERNALSYM ASN1_R_INVALID_BMPSTRING_LENGTH}
  ASN1_R_INVALID_BMPSTRING_LENGTH                 = 129;
  {$EXTERNALSYM ASN1_R_INVALID_DIGIT}
  ASN1_R_INVALID_DIGIT                            = 130;
  {$EXTERNALSYM ASN1_R_INVALID_MIME_TYPE}
  ASN1_R_INVALID_MIME_TYPE                        = 205;
  {$EXTERNALSYM ASN1_R_INVALID_MODIFIER}
  ASN1_R_INVALID_MODIFIER                         = 186;
  {$EXTERNALSYM ASN1_R_INVALID_NUMBER}
  ASN1_R_INVALID_NUMBER                           = 187;
  {$EXTERNALSYM ASN1_R_INVALID_OBJECT_ENCODING}
  ASN1_R_INVALID_OBJECT_ENCODING                  = 216;
  {$EXTERNALSYM ASN1_R_INVALID_SCRYPT_PARAMETERS}
  ASN1_R_INVALID_SCRYPT_PARAMETERS                = 227;
  {$EXTERNALSYM ASN1_R_INVALID_SEPARATOR}
  ASN1_R_INVALID_SEPARATOR                        = 131;
  {$EXTERNALSYM ASN1_R_INVALID_STRING_TABLE_VALUE}
  ASN1_R_INVALID_STRING_TABLE_VALUE               = 218;
  {$EXTERNALSYM ASN1_R_INVALID_UNIVERSALSTRING_LENGTH}
  ASN1_R_INVALID_UNIVERSALSTRING_LENGTH           = 133;
  {$EXTERNALSYM ASN1_R_INVALID_UTF8STRING}
  ASN1_R_INVALID_UTF8STRING                       = 134;
  {$EXTERNALSYM ASN1_R_INVALID_VALUE}
  ASN1_R_INVALID_VALUE                            = 219;
  {$EXTERNALSYM ASN1_R_LIST_ERROR}
  ASN1_R_LIST_ERROR                               = 188;
  {$EXTERNALSYM ASN1_R_MIME_NO_CONTENT_TYPE}
  ASN1_R_MIME_NO_CONTENT_TYPE                     = 206;
  {$EXTERNALSYM ASN1_R_MIME_PARSE_ERROR}
  ASN1_R_MIME_PARSE_ERROR                         = 207;
  {$EXTERNALSYM ASN1_R_MIME_SIG_PARSE_ERROR}
  ASN1_R_MIME_SIG_PARSE_ERROR                     = 208;
  {$EXTERNALSYM ASN1_R_MISSING_EOC}
  ASN1_R_MISSING_EOC                              = 137;
  {$EXTERNALSYM ASN1_R_MISSING_SECOND_NUMBER}
  ASN1_R_MISSING_SECOND_NUMBER                    = 138;
  {$EXTERNALSYM ASN1_R_MISSING_VALUE}
  ASN1_R_MISSING_VALUE                            = 189;
  {$EXTERNALSYM ASN1_R_MSTRING_NOT_UNIVERSAL}
  ASN1_R_MSTRING_NOT_UNIVERSAL                    = 139;
  {$EXTERNALSYM ASN1_R_MSTRING_WRONG_TAG}
  ASN1_R_MSTRING_WRONG_TAG                        = 140;
  {$EXTERNALSYM ASN1_R_NESTED_ASN1_STRING}
  ASN1_R_NESTED_ASN1_STRING                       = 197;
  {$EXTERNALSYM ASN1_R_NESTED_TOO_DEEP}
  ASN1_R_NESTED_TOO_DEEP                          = 201;
  {$EXTERNALSYM ASN1_R_NON_HEX_CHARACTERS}
  ASN1_R_NON_HEX_CHARACTERS                       = 141;
  {$EXTERNALSYM ASN1_R_NOT_ASCII_FORMAT}
  ASN1_R_NOT_ASCII_FORMAT                         = 190;
  {$EXTERNALSYM ASN1_R_NOT_ENOUGH_DATA}
  ASN1_R_NOT_ENOUGH_DATA                          = 142;
  {$EXTERNALSYM ASN1_R_NO_CONTENT_TYPE}
  ASN1_R_NO_CONTENT_TYPE                          = 209;
  {$EXTERNALSYM ASN1_R_NO_MATCHING_CHOICE_TYPE}
  ASN1_R_NO_MATCHING_CHOICE_TYPE                  = 143;
  {$EXTERNALSYM ASN1_R_NO_MULTIPART_BODY_FAILURE}
  ASN1_R_NO_MULTIPART_BODY_FAILURE                = 210;
  {$EXTERNALSYM ASN1_R_NO_MULTIPART_BOUNDARY}
  ASN1_R_NO_MULTIPART_BOUNDARY                    = 211;
  {$EXTERNALSYM ASN1_R_NO_SIG_CONTENT_TYPE}
  ASN1_R_NO_SIG_CONTENT_TYPE                      = 212;
  {$EXTERNALSYM ASN1_R_NULL_IS_WRONG_LENGTH}
  ASN1_R_NULL_IS_WRONG_LENGTH                     = 144;
  {$EXTERNALSYM ASN1_R_OBJECT_NOT_ASCII_FORMAT}
  ASN1_R_OBJECT_NOT_ASCII_FORMAT                  = 191;
  {$EXTERNALSYM ASN1_R_ODD_NUMBER_OF_CHARS}
  ASN1_R_ODD_NUMBER_OF_CHARS                      = 145;
  {$EXTERNALSYM ASN1_R_SECOND_NUMBER_TOO_LARGE}
  ASN1_R_SECOND_NUMBER_TOO_LARGE                  = 147;
  {$EXTERNALSYM ASN1_R_SEQUENCE_LENGTH_MISMATCH}
  ASN1_R_SEQUENCE_LENGTH_MISMATCH                 = 148;
  {$EXTERNALSYM ASN1_R_SEQUENCE_NOT_CONSTRUCTED}
  ASN1_R_SEQUENCE_NOT_CONSTRUCTED                 = 149;
  {$EXTERNALSYM ASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG}
  ASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG             = 192;
  {$EXTERNALSYM ASN1_R_SHORT_LINE}
  ASN1_R_SHORT_LINE                               = 150;
  {$EXTERNALSYM ASN1_R_SIG_INVALID_MIME_TYPE}
  ASN1_R_SIG_INVALID_MIME_TYPE                    = 213;
  {$EXTERNALSYM ASN1_R_STREAMING_NOT_SUPPORTED}
  ASN1_R_STREAMING_NOT_SUPPORTED                  = 202;
  {$EXTERNALSYM ASN1_R_STRING_TOO_LONG}
  ASN1_R_STRING_TOO_LONG                          = 151;
  {$EXTERNALSYM ASN1_R_STRING_TOO_SHORT}
  ASN1_R_STRING_TOO_SHORT                         = 152;
  {$EXTERNALSYM ASN1_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD}
  ASN1_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD = 154;
  {$EXTERNALSYM ASN1_R_TIME_NOT_ASCII_FORMAT}
  ASN1_R_TIME_NOT_ASCII_FORMAT                    = 193;
  {$EXTERNALSYM ASN1_R_TOO_LARGE}
  ASN1_R_TOO_LARGE                                = 223;
  {$EXTERNALSYM ASN1_R_TOO_LONG}
  ASN1_R_TOO_LONG                                 = 155;
  {$EXTERNALSYM ASN1_R_TOO_SMALL}
  ASN1_R_TOO_SMALL                                = 224;
  {$EXTERNALSYM ASN1_R_TYPE_NOT_CONSTRUCTED}
  ASN1_R_TYPE_NOT_CONSTRUCTED                     = 156;
  {$EXTERNALSYM ASN1_R_TYPE_NOT_PRIMITIVE}
  ASN1_R_TYPE_NOT_PRIMITIVE                       = 195;
  {$EXTERNALSYM ASN1_R_UNEXPECTED_EOC}
  ASN1_R_UNEXPECTED_EOC                           = 159;
  {$EXTERNALSYM ASN1_R_UNIVERSALSTRING_IS_WRONG_LENGTH}
  ASN1_R_UNIVERSALSTRING_IS_WRONG_LENGTH          = 215;
  {$EXTERNALSYM ASN1_R_UNKNOWN_FORMAT}
  ASN1_R_UNKNOWN_FORMAT                           = 160;
  {$EXTERNALSYM ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM}
  ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM         = 161;
  {$EXTERNALSYM ASN1_R_UNKNOWN_OBJECT_TYPE}
  ASN1_R_UNKNOWN_OBJECT_TYPE                      = 162;
  {$EXTERNALSYM ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE}
  ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE                  = 163;
  {$EXTERNALSYM ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM}
  ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM              = 199;
  {$EXTERNALSYM ASN1_R_UNKNOWN_TAG}
  ASN1_R_UNKNOWN_TAG                              = 194;
  {$EXTERNALSYM ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE}
  ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE          = 164;
  {$EXTERNALSYM ASN1_R_UNSUPPORTED_CIPHER}
  ASN1_R_UNSUPPORTED_CIPHER                       = 228;
  {$EXTERNALSYM ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE}
  ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE              = 167;
  {$EXTERNALSYM ASN1_R_UNSUPPORTED_TYPE}
  ASN1_R_UNSUPPORTED_TYPE                         = 196;
  {$EXTERNALSYM ASN1_R_WRONG_INTEGER_TYPE}
  ASN1_R_WRONG_INTEGER_TYPE                       = 225;
  {$EXTERNALSYM ASN1_R_WRONG_PUBLIC_KEY_TYPE}
  ASN1_R_WRONG_PUBLIC_KEY_TYPE                    = 200;
  {$EXTERNALSYM ASN1_R_WRONG_TAG}
  ASN1_R_WRONG_TAG                                = 168;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM ERR_load_ASN1_strings}
  ERR_load_ASN1_strings: function : TIdC_INT; cdecl = nil;

{$ELSE}
  {$EXTERNALSYM ERR_load_ASN1_strings}
  function ERR_load_ASN1_strings: TIdC_INT cdecl; external CLibCrypto;

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
  ERR_load_ASN1_strings_procname = 'ERR_load_ASN1_strings';

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 
function  ERR_ERR_load_ASN1_strings: TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_load_ASN1_strings_procname);
end;



  {$I TaurusTLSNoRetValOn.inc} 
  {$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  ERR_load_ASN1_strings := LoadLibFunction(ADllHandle, ERR_load_ASN1_strings_procname);
  FuncLoadError := not assigned(ERR_load_ASN1_strings);
  if FuncLoadError then
  begin
    {$if not defined(ERR_load_ASN1_strings_allownil)}
    ERR_load_ASN1_strings := ERR_ERR_load_ASN1_strings;
    {$ifend}
    {$if declared(ERR_load_ASN1_strings_introduced)}
    if LibVersion < ERR_load_ASN1_strings_introduced then
    begin
      {$if declared(FC_ERR_load_ASN1_strings)}
      ERR_load_ASN1_strings := FC_ERR_load_ASN1_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_load_ASN1_strings_removed)}
    if ERR_load_ASN1_strings_removed <= LibVersion then
    begin
      {$if declared(_ERR_load_ASN1_strings)}
      ERR_load_ASN1_strings := _ERR_load_ASN1_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_load_ASN1_strings_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_load_ASN1_strings');
    {$ifend}
  end;
end;
  {$I TaurusTLSUnusedParamOn.inc}

procedure Unload;
begin
  ERR_load_ASN1_strings := nil;
end;
 {$ENDIF}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
