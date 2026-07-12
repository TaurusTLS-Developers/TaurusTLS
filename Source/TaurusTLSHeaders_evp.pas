/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_evp.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_evp.h2pas
     and this file regenerated. TaurusTLSHeaders_evp.h2pas is distributed with the full Indy
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
unit TaurusTLSHeaders_evp;

interface

// Headers for OpenSSL 1.1.1
// evp.h


uses
  IdCTypes,
  IdGlobal,
  TaurusTLSHeaders_bio,
  TaurusTLSHeaders_obj_mac,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_core;

const
  {$EXTERNALSYM EVP_MAX_MD_SIZE}
  EVP_MAX_MD_SIZE = 64; // longest known is SHA512
  {$EXTERNALSYM EVP_MAX_KEY_LENGTH}
  EVP_MAX_KEY_LENGTH = 64;
  {$EXTERNALSYM EVP_MAX_IV_LENGTH}
  EVP_MAX_IV_LENGTH = 16;
  {$EXTERNALSYM EVP_MAX_BLOCK_LENGTH}
  EVP_MAX_BLOCK_LENGTH = 32;
  {$EXTERNALSYM PKCS5_SALT_LEN}
  PKCS5_SALT_LEN = 8;
  // Default PKCS#5 iteration count
  {$EXTERNALSYM PKCS5_DEFAULT_ITER}
  PKCS5_DEFAULT_ITER = 2048;
  {$EXTERNALSYM EVP_PK_RSA}
  EVP_PK_RSA = $0001;
  {$EXTERNALSYM EVP_PK_DSA}
  EVP_PK_DSA = $0002;
  {$EXTERNALSYM EVP_PK_DH}
  EVP_PK_DH  = $0004;
  {$EXTERNALSYM EVP_PK_EC}
  EVP_PK_EC = $0008;
  {$EXTERNALSYM EVP_PKT_SIGN}
  EVP_PKT_SIGN = $0010;
  {$EXTERNALSYM EVP_PKT_ENC}
  EVP_PKT_ENC = $0020;
  {$EXTERNALSYM EVP_PKT_EXCH}
  EVP_PKT_EXCH = $0040;
  {$EXTERNALSYM EVP_PKS_RSA}
  EVP_PKS_RSA = $0100;
  {$EXTERNALSYM EVP_PKS_DSA}
  EVP_PKS_DSA = $0200;
  {$EXTERNALSYM EVP_PKS_EC}
  EVP_PKS_EC = $0400;

  {$EXTERNALSYM EVP_PKEY_NONE}
  EVP_PKEY_NONE = NID_undef;
  {$EXTERNALSYM EVP_PKEY_RSA}
  EVP_PKEY_RSA = NID_rsaEncryption;
  {$EXTERNALSYM EVP_PKEY_RSA2}
  EVP_PKEY_RSA2 = NID_rsa;
  {$EXTERNALSYM EVP_PKEY_RSA_PSS}
  EVP_PKEY_RSA_PSS = NID_rsassaPss;
  {$EXTERNALSYM EVP_PKEY_DSA}
  EVP_PKEY_DSA = NID_dsa;
  {$EXTERNALSYM EVP_PKEY_DSA1}
  EVP_PKEY_DSA1 = NID_dsa_2;
  {$EXTERNALSYM EVP_PKEY_DSA2}
  EVP_PKEY_DSA2 = NID_dsaWithSHA;
  {$EXTERNALSYM EVP_PKEY_DSA3}
  EVP_PKEY_DSA3 = NID_dsaWithSHA1;
  {$EXTERNALSYM EVP_PKEY_DSA4}
  EVP_PKEY_DSA4 = NID_dsaWithSHA1_2;
  {$EXTERNALSYM EVP_PKEY_DH}
  EVP_PKEY_DH = NID_dhKeyAgreement;
  {$EXTERNALSYM EVP_PKEY_DHX}
  EVP_PKEY_DHX = NID_dhpublicnumber;
  {$EXTERNALSYM EVP_PKEY_EC}
  EVP_PKEY_EC = NID_X9_62_id_ecPublicKey;
  {$EXTERNALSYM EVP_PKEY_SM2}
  EVP_PKEY_SM2 = NID_sm2;
  {$EXTERNALSYM EVP_PKEY_HMAC}
  EVP_PKEY_HMAC = NID_hmac;
  {$EXTERNALSYM EVP_PKEY_CMAC}
  EVP_PKEY_CMAC = NID_cmac;
  {$EXTERNALSYM EVP_PKEY_SCRYPT}
  EVP_PKEY_SCRYPT = NID_id_scrypt;
  {$EXTERNALSYM EVP_PKEY_TLS1_PRF}
  EVP_PKEY_TLS1_PRF = NID_tls1_prf;
  {$EXTERNALSYM EVP_PKEY_HKDF}
  EVP_PKEY_HKDF = NID_hkdf;
  {$EXTERNALSYM EVP_PKEY_POLY1305}
  EVP_PKEY_POLY1305 = NID_poly1305;
  {$EXTERNALSYM EVP_PKEY_SIPHASH}
  EVP_PKEY_SIPHASH = NID_siphash;
  {$EXTERNALSYM EVP_PKEY_X25519}
  EVP_PKEY_X25519 = NID_X25519;
  {$EXTERNALSYM EVP_PKEY_ED25519}
  EVP_PKEY_ED25519 = NID_ED25519;
  {$EXTERNALSYM EVP_PKEY_X448}
  EVP_PKEY_X448 = NID_X448;
  {$EXTERNALSYM EVP_PKEY_ED448}
  EVP_PKEY_ED448 = NID_ED448;

  {$EXTERNALSYM EVP_PKEY_MO_SIGN}
  EVP_PKEY_MO_SIGN = $0001;
  {$EXTERNALSYM EVP_PKEY_MO_VERIFY}
  EVP_PKEY_MO_VERIFY = $0002;
  {$EXTERNALSYM EVP_PKEY_MO_ENCRYPT}
  EVP_PKEY_MO_ENCRYPT = $0004;
  {$EXTERNALSYM EVP_PKEY_MO_DECRYPT}
  EVP_PKEY_MO_DECRYPT = $0008;

// digest can only handle a single block ///
  {$EXTERNALSYM EVP_MD_FLAG_ONESHOT}
  EVP_MD_FLAG_ONESHOT = $0001;

// digest is extensible-output function; XOF ///

  {$EXTERNALSYM EVP_MD_FLAG_XOF}
  EVP_MD_FLAG_XOF = $0002;

// DigestAlgorithmIdentifier flags... ///

  {$EXTERNALSYM EVP_MD_FLAG_DIGALGID_MASK}
  EVP_MD_FLAG_DIGALGID_MASK = $0018;

// NULL or absent parameter accepted. Use NULL ///

  {$EXTERNALSYM EVP_MD_FLAG_DIGALGID_NULL}
  EVP_MD_FLAG_DIGALGID_NULL = $0000;

// NULL or absent parameter accepted. Use NULL for PKCS#1 otherwise absent ///

  {$EXTERNALSYM EVP_MD_FLAG_DIGALGID_ABSENT}
  EVP_MD_FLAG_DIGALGID_ABSENT = $0008;

// Custom handling via ctrl ///

  {$EXTERNALSYM EVP_MD_FLAG_DIGALGID_CUSTOM}
  EVP_MD_FLAG_DIGALGID_CUSTOM = $0018;

// Note if suitable for use in FIPS mode ///

  {$EXTERNALSYM EVP_MD_FLAG_FIPS}
  EVP_MD_FLAG_FIPS = $0400;

// Digest ctrls ///

  {$EXTERNALSYM EVP_MD_CTRL_DIGALGID}
  EVP_MD_CTRL_DIGALGID = $1;
  {$EXTERNALSYM EVP_MD_CTRL_MICALG}
  EVP_MD_CTRL_MICALG = $2;
  {$EXTERNALSYM EVP_MD_CTRL_XOF_LEN}
  EVP_MD_CTRL_XOF_LEN = $3;

// Minimum Algorithm specific ctrl value ///

  {$EXTERNALSYM EVP_MD_CTRL_ALG_CTRL}
  EVP_MD_CTRL_ALG_CTRL = $1000;
 // not EVP_MD ///

// values for EVP_MD_CTX flags ///
  {$EXTERNALSYM EVP_MD_CTX_FLAG_ONESHOT}
  EVP_MD_CTX_FLAG_ONESHOT = $0001;
  {$EXTERNALSYM EVP_MD_CTX_FLAG_CLEANED}
  EVP_MD_CTX_FLAG_CLEANED = $0002;
  {$EXTERNALSYM EVP_MD_CTX_FLAG_REUSE}
  EVP_MD_CTX_FLAG_REUSE = $0004;
//
 // FIPS and pad options are ignored in 1.0.0; definitions are here so we
 // don't accidentally reuse the values for other purposes.
 ///

  {$EXTERNALSYM EVP_MD_CTX_FLAG_NON_FIPS_ALLOW}
  EVP_MD_CTX_FLAG_NON_FIPS_ALLOW = $0008;

//
 // The following PAD options are also currently ignored in 1.0.0; digest
 // parameters are handled through EVP_DigestSign//() and EVP_DigestVerify//()
 // instead.
 ///
  {$EXTERNALSYM EVP_MD_CTX_FLAG_PAD_MASK}
  EVP_MD_CTX_FLAG_PAD_MASK = $F0;
  {$EXTERNALSYM EVP_MD_CTX_FLAG_PAD_PKCS1}
  EVP_MD_CTX_FLAG_PAD_PKCS1 = $00;
  {$EXTERNALSYM EVP_MD_CTX_FLAG_PAD_X931}
  EVP_MD_CTX_FLAG_PAD_X931 = $10;
  {$EXTERNALSYM EVP_MD_CTX_FLAG_PAD_PSS}
  EVP_MD_CTX_FLAG_PAD_PSS = $20;

  {$EXTERNALSYM EVP_MD_CTX_FLAG_NO_INIT}
  EVP_MD_CTX_FLAG_NO_INIT = $0100;
//
 // Some functions such as EVP_DigestSign only finalise copies of internal
 // contexts so additional data can be included after the finalisation call.
 // This is inefficient if this functionality is not required: it is disabled
 // if the following flag is set.
 ///
  {$EXTERNALSYM EVP_MD_CTX_FLAG_FINALISE}
  EVP_MD_CTX_FLAG_FINALISE = $0200;


// NOTE: $0400 is reserved for internal usage ///
// Values for cipher flags ///

// Modes for ciphers ///

  {$EXTERNALSYM EVP_CIPH_STREAM_CIPHER}
  EVP_CIPH_STREAM_CIPHER = $0;
  {$EXTERNALSYM EVP_CIPH_ECB_MODE}
  EVP_CIPH_ECB_MODE = $1;
  {$EXTERNALSYM EVP_CIPH_CBC_MODE}
  EVP_CIPH_CBC_MODE = $2;
  {$EXTERNALSYM EVP_CIPH_CFB_MODE}
  EVP_CIPH_CFB_MODE = $3;
  {$EXTERNALSYM EVP_CIPH_OFB_MODE}
  EVP_CIPH_OFB_MODE = $4;
  {$EXTERNALSYM EVP_CIPH_CTR_MODE}
  EVP_CIPH_CTR_MODE = $5;
  {$EXTERNALSYM EVP_CIPH_GCM_MODE}
  EVP_CIPH_GCM_MODE = $6;
  {$EXTERNALSYM EVP_CIPH_CCM_MODE}
  EVP_CIPH_CCM_MODE = $7;
  {$EXTERNALSYM EVP_CIPH_XTS_MODE}
  EVP_CIPH_XTS_MODE = $10001;
  {$EXTERNALSYM EVP_CIPH_WRAP_MODE}
  EVP_CIPH_WRAP_MODE = $10002;
  {$EXTERNALSYM EVP_CIPH_OCB_MODE}
  EVP_CIPH_OCB_MODE = $10003;
  {$EXTERNALSYM EVP_CIPH_MODE}
  EVP_CIPH_MODE = $F0007;
// Set if variable length cipher ///
  {$EXTERNALSYM EVP_CIPH_VARIABLE_LENGTH}
  EVP_CIPH_VARIABLE_LENGTH = $8;
// Set if the iv handling should be done by the cipher itself ///
  {$EXTERNALSYM EVP_CIPH_CUSTOM_IV}
  EVP_CIPH_CUSTOM_IV = $10;
// Set if the cipher's init() function should be called if key is NULL ///
  {$EXTERNALSYM EVP_CIPH_ALWAYS_CALL_INIT}
  EVP_CIPH_ALWAYS_CALL_INIT = $20;
// Call ctrl() to init cipher parameters ///
  {$EXTERNALSYM EVP_CIPH_CTRL_INIT}
  EVP_CIPH_CTRL_INIT = $40;
// Don't use standard key length function ///
  {$EXTERNALSYM EVP_CIPH_CUSTOM_KEY_LENGTH}
  EVP_CIPH_CUSTOM_KEY_LENGTH = $80;
// Don't use standard block padding ///
  {$EXTERNALSYM EVP_CIPH_NO_PADDING}
  EVP_CIPH_NO_PADDING = $100;
// cipher handles random key generation ///
  {$EXTERNALSYM EVP_CIPH_RAND_KEY}
  EVP_CIPH_RAND_KEY = $200;
// cipher has its own additional copying logic ///
  {$EXTERNALSYM EVP_CIPH_CUSTOM_COPY}
  EVP_CIPH_CUSTOM_COPY = $400;
// Don't use standard iv length function ///
  {$EXTERNALSYM EVP_CIPH_CUSTOM_IV_LENGTH}
  EVP_CIPH_CUSTOM_IV_LENGTH = $800;
// Allow use default ASN1 get/set iv ///
  {$EXTERNALSYM EVP_CIPH_FLAG_DEFAULT_ASN1}
  EVP_CIPH_FLAG_DEFAULT_ASN1 = $1000;
// Buffer length in bits not bytes: CFB1 mode only ///
  {$EXTERNALSYM EVP_CIPH_FLAG_LENGTH_BITS}
  EVP_CIPH_FLAG_LENGTH_BITS = $2000;
// Note if suitable for use in FIPS mode ///
//  was EVP_CIPH_FLAG_FIPS = $4000;
  {$EXTERNALSYM EVP_CIPH_FLAG_FIPS}
  EVP_CIPH_FLAG_FIPS           = 0;

// Allow non FIPS cipher in FIPS mode ///
// was  EVP_CIPH_FLAG_NON_FIPS_ALLOW = $8000;
  {$EXTERNALSYM EVP_CIPH_FLAG_NON_FIPS_ALLOW}
  EVP_CIPH_FLAG_NON_FIPS_ALLOW = 0;
//
 // Cipher handles any and all padding logic as well as finalisation.
 ///
  {$EXTERNALSYM EVP_CIPH_FLAG_CUSTOM_CIPHER}
  EVP_CIPH_FLAG_CUSTOM_CIPHER = $100000;
  {$EXTERNALSYM EVP_CIPH_FLAG_AEAD_CIPHER}
  EVP_CIPH_FLAG_AEAD_CIPHER = $200000;
  {$EXTERNALSYM EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK}
  EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK = $400000;
// Cipher can handle pipeline operations ///
  {$EXTERNALSYM EVP_CIPH_FLAG_PIPELINE}
  EVP_CIPH_FLAG_PIPELINE = $800000;

//* For provider implementations that handle  ASN1 get/set param themselves */
  {$EXTERNALSYM EVP_CIPH_FLAG_CUSTOM_ASN1}
  EVP_CIPH_FLAG_CUSTOM_ASN1      = $1000000;
//* For ciphers generating unprotected CMS attributes */
  {$EXTERNALSYM EVP_CIPH_FLAG_CIPHER_WITH_MAC}
  EVP_CIPH_FLAG_CIPHER_WITH_MAC   = $2000000;
//* For supplementary wrap cipher support */
  {$EXTERNALSYM EVP_CIPH_FLAG_GET_WRAP_CIPHER}
  EVP_CIPH_FLAG_GET_WRAP_CIPHER  = $4000000;
  {$EXTERNALSYM EVP_CIPH_FLAG_INVERSE_CIPHER}
  EVP_CIPH_FLAG_INVERSE_CIPHER   = $8000000;

//
 // Cipher context flag to indicate we can handle wrap mode: if allowed in
 // older applications it could overflow buffers.
 ///

  {$EXTERNALSYM EVP_CIPHER_CTX_FLAG_WRAP_ALLOW}
  EVP_CIPHER_CTX_FLAG_WRAP_ALLOW = $1;

// ctrl() values ///

  {$EXTERNALSYM EVP_CTRL_INIT}
  EVP_CTRL_INIT = $0;
  {$EXTERNALSYM EVP_CTRL_SET_KEY_LENGTH}
  EVP_CTRL_SET_KEY_LENGTH = $1;
  {$EXTERNALSYM EVP_CTRL_GET_RC2_KEY_BITS}
  EVP_CTRL_GET_RC2_KEY_BITS = $2;
  {$EXTERNALSYM EVP_CTRL_SET_RC2_KEY_BITS}
  EVP_CTRL_SET_RC2_KEY_BITS = $3;
  {$EXTERNALSYM EVP_CTRL_GET_RC5_ROUNDS}
  EVP_CTRL_GET_RC5_ROUNDS = $4;
  {$EXTERNALSYM EVP_CTRL_SET_RC5_ROUNDS}
  EVP_CTRL_SET_RC5_ROUNDS = $5;
  {$EXTERNALSYM EVP_CTRL_RAND_KEY}
  EVP_CTRL_RAND_KEY = $6;
  {$EXTERNALSYM EVP_CTRL_PBE_PRF_NID}
  EVP_CTRL_PBE_PRF_NID = $7;
  {$EXTERNALSYM EVP_CTRL_COPY}
  EVP_CTRL_COPY = $8;
  {$EXTERNALSYM EVP_CTRL_AEAD_SET_IVLEN}
  EVP_CTRL_AEAD_SET_IVLEN = $9;
  {$EXTERNALSYM EVP_CTRL_AEAD_GET_TAG}
  EVP_CTRL_AEAD_GET_TAG = $10;
  {$EXTERNALSYM EVP_CTRL_AEAD_SET_TAG}
  EVP_CTRL_AEAD_SET_TAG = $11;
  {$EXTERNALSYM EVP_CTRL_AEAD_SET_IV_FIXED}
  EVP_CTRL_AEAD_SET_IV_FIXED = $12;
  {$EXTERNALSYM EVP_CTRL_GCM_SET_IVLEN}
  EVP_CTRL_GCM_SET_IVLEN = EVP_CTRL_AEAD_SET_IVLEN;
  {$EXTERNALSYM EVP_CTRL_GCM_GET_TAG}
  EVP_CTRL_GCM_GET_TAG = EVP_CTRL_AEAD_GET_TAG;
  {$EXTERNALSYM EVP_CTRL_GCM_SET_TAG}
  EVP_CTRL_GCM_SET_TAG = EVP_CTRL_AEAD_SET_TAG;
  {$EXTERNALSYM EVP_CTRL_GCM_SET_IV_FIXED}
  EVP_CTRL_GCM_SET_IV_FIXED = EVP_CTRL_AEAD_SET_IV_FIXED;
  {$EXTERNALSYM EVP_CTRL_GCM_IV_GEN}
  EVP_CTRL_GCM_IV_GEN = $13;
  {$EXTERNALSYM EVP_CTRL_CCM_SET_IVLEN}
  EVP_CTRL_CCM_SET_IVLEN = EVP_CTRL_AEAD_SET_IVLEN;
  {$EXTERNALSYM EVP_CTRL_CCM_GET_TAG}
  EVP_CTRL_CCM_GET_TAG = EVP_CTRL_AEAD_GET_TAG;
  {$EXTERNALSYM EVP_CTRL_CCM_SET_TAG}
  EVP_CTRL_CCM_SET_TAG = EVP_CTRL_AEAD_SET_TAG;
  {$EXTERNALSYM EVP_CTRL_CCM_SET_IV_FIXED}
  EVP_CTRL_CCM_SET_IV_FIXED = EVP_CTRL_AEAD_SET_IV_FIXED;
  {$EXTERNALSYM EVP_CTRL_CCM_SET_L}
  EVP_CTRL_CCM_SET_L = $14;
  {$EXTERNALSYM EVP_CTRL_CCM_SET_MSGLEN}
  EVP_CTRL_CCM_SET_MSGLEN = $15;
//
 // AEAD cipher deduces payload length and returns number of bytes required to
 // store MAC and eventual padding. Subsequent call to EVP_Cipher even
 // appends/verifies MAC.
 ///
  {$EXTERNALSYM EVP_CTRL_AEAD_TLS1_AAD}
  EVP_CTRL_AEAD_TLS1_AAD = $16;
// Used by composite AEAD ciphers; no-op in GCM; CCM... ///
  {$EXTERNALSYM EVP_CTRL_AEAD_SET_MAC_KEY}
  EVP_CTRL_AEAD_SET_MAC_KEY = $17;
// Set the GCM invocation field; decrypt only ///
  {$EXTERNALSYM EVP_CTRL_GCM_SET_IV_INV}
  EVP_CTRL_GCM_SET_IV_INV = $18;

  {$EXTERNALSYM EVP_CTRL_TLS1_1_MULTIBLOCK_AAD}
  EVP_CTRL_TLS1_1_MULTIBLOCK_AAD = $19;
  {$EXTERNALSYM EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT}
  EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT = $1a;
  {$EXTERNALSYM EVP_CTRL_TLS1_1_MULTIBLOCK_DECRYPT}
  EVP_CTRL_TLS1_1_MULTIBLOCK_DECRYPT = $1b;
  {$EXTERNALSYM EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE}
  EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE = $1c;

  {$EXTERNALSYM EVP_CTRL_SSL3_MASTER_SECRET}
  EVP_CTRL_SSL3_MASTER_SECRET = $1d;

// EVP_CTRL_SET_SBOX takes the PIdAnsiChar// specifying S-boxes///
  {$EXTERNALSYM EVP_CTRL_SET_SBOX}
  EVP_CTRL_SET_SBOX = $1e;
//
// EVP_CTRL_SBOX_USED takes a 'TIdC_SIZET' and 'PIdAnsiChar//'; pointing at a
// pre-allocated buffer with specified size
///
  {$EXTERNALSYM EVP_CTRL_SBOX_USED}
  EVP_CTRL_SBOX_USED = $1f;
// EVP_CTRL_KEY_MESH takes 'TIdC_SIZET' number of bytes to mesh the key after;
// 0 switches meshing off
///
  {$EXTERNALSYM EVP_CTRL_KEY_MESH}
  EVP_CTRL_KEY_MESH = $20;
// EVP_CTRL_BLOCK_PADDING_MODE takes the padding mode///
  {$EXTERNALSYM EVP_CTRL_BLOCK_PADDING_MODE}
  EVP_CTRL_BLOCK_PADDING_MODE = $21;

// Set the output buffers to use for a pipelined operation///
  {$EXTERNALSYM EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS}
  EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS = $22;
// Set the input buffers to use for a pipelined operation///
  {$EXTERNALSYM EVP_CTRL_SET_PIPELINE_INPUT_BUFS}
  EVP_CTRL_SET_PIPELINE_INPUT_BUFS = $23;
// Set the input buffer lengths to use for a pipelined operation///
  {$EXTERNALSYM EVP_CTRL_SET_PIPELINE_INPUT_LENS}
  EVP_CTRL_SET_PIPELINE_INPUT_LENS = $24;

  {$EXTERNALSYM EVP_CTRL_GET_IVLEN}
  EVP_CTRL_GET_IVLEN = $25;

// Padding modes///
  {$EXTERNALSYM EVP_PADDING_PKCS7}
  EVP_PADDING_PKCS7 = 1;
  {$EXTERNALSYM EVP_PADDING_ISO7816_4}
  EVP_PADDING_ISO7816_4 = 2;
  {$EXTERNALSYM EVP_PADDING_ANSI923}
  EVP_PADDING_ANSI923 = 3;
  {$EXTERNALSYM EVP_PADDING_ISO10126}
  EVP_PADDING_ISO10126 = 4;
  {$EXTERNALSYM EVP_PADDING_ZERO}
  EVP_PADDING_ZERO = 5;

// RFC 5246 defines additional data to be 13 bytes in length///
  {$EXTERNALSYM EVP_AEAD_TLS1_AAD_LEN}
  EVP_AEAD_TLS1_AAD_LEN = 13;

// GCM TLS constants///
// Length of fixed part of IV derived from PRF///
  {$EXTERNALSYM EVP_GCM_TLS_FIXED_IV_LEN}
  EVP_GCM_TLS_FIXED_IV_LEN = 4;
// Length of explicit part of IV part of TLS records///
  {$EXTERNALSYM EVP_GCM_TLS_EXPLICIT_IV_LEN}
  EVP_GCM_TLS_EXPLICIT_IV_LEN = 8;
// Length of tag for TLS
  {$EXTERNALSYM EVP_GCM_TLS_TAG_LEN}
  EVP_GCM_TLS_TAG_LEN = 16;

/// CCM TLS constants ///
/// Length of fixed part of IV derived from PRF ///
  {$EXTERNALSYM EVP_CCM_TLS_FIXED_IV_LEN}
  EVP_CCM_TLS_FIXED_IV_LEN = 4;
/// Length of explicit part of IV part of TLS records ///
  {$EXTERNALSYM EVP_CCM_TLS_EXPLICIT_IV_LEN}
  EVP_CCM_TLS_EXPLICIT_IV_LEN = 8;
/// Total length of CCM IV length for TLS ///
  {$EXTERNALSYM EVP_CCM_TLS_IV_LEN}
  EVP_CCM_TLS_IV_LEN = 12;
/// Length of tag for TLS ///
  {$EXTERNALSYM EVP_CCM_TLS_TAG_LEN}
  EVP_CCM_TLS_TAG_LEN = 16;
/// Length of CCM8 tag for TLS ///
  {$EXTERNALSYM EVP_CCM8_TLS_TAG_LEN}
  EVP_CCM8_TLS_TAG_LEN = 8;

/// Length of tag for TLS ///
  {$EXTERNALSYM EVP_CHACHAPOLY_TLS_TAG_LEN}
  EVP_CHACHAPOLY_TLS_TAG_LEN = 16;

(* Can appear as the outermost AlgorithmIdentifier *)
  {$EXTERNALSYM EVP_PBE_TYPE_OUTER}
  EVP_PBE_TYPE_OUTER = $0;
(* Is an PRF type OID *)
  {$EXTERNALSYM EVP_PBE_TYPE_PRF}
  EVP_PBE_TYPE_PRF = $1;
(* Is a PKCS#5 v2.0 KDF *)
  {$EXTERNALSYM EVP_PBE_TYPE_KDF}
  EVP_PBE_TYPE_KDF = $2;

  {$EXTERNALSYM ASN1_PKEY_ALIAS}
  ASN1_PKEY_ALIAS = $1;
  {$EXTERNALSYM ASN1_PKEY_DYNAMIC}
  ASN1_PKEY_DYNAMIC = $2;
  {$EXTERNALSYM ASN1_PKEY_SIGPARAM_NULL}
  ASN1_PKEY_SIGPARAM_NULL = $4;

  {$EXTERNALSYM ASN1_PKEY_CTRL_PKCS7_SIGN}
  ASN1_PKEY_CTRL_PKCS7_SIGN = $1;
  {$EXTERNALSYM ASN1_PKEY_CTRL_PKCS7_ENCRYPT}
  ASN1_PKEY_CTRL_PKCS7_ENCRYPT = $2;
  {$EXTERNALSYM ASN1_PKEY_CTRL_DEFAULT_MD_NID}
  ASN1_PKEY_CTRL_DEFAULT_MD_NID = $3;
  {$EXTERNALSYM ASN1_PKEY_CTRL_CMS_SIGN}
  ASN1_PKEY_CTRL_CMS_SIGN = $5;
  {$EXTERNALSYM ASN1_PKEY_CTRL_CMS_ENVELOPE}
  ASN1_PKEY_CTRL_CMS_ENVELOPE = $7;
  {$EXTERNALSYM ASN1_PKEY_CTRL_CMS_RI_TYPE}
  ASN1_PKEY_CTRL_CMS_RI_TYPE = $8;

  {$EXTERNALSYM ASN1_PKEY_CTRL_SET1_TLS_ENCPT}
  ASN1_PKEY_CTRL_SET1_TLS_ENCPT = $9;
  {$EXTERNALSYM ASN1_PKEY_CTRL_GET1_TLS_ENCPT}
  ASN1_PKEY_CTRL_GET1_TLS_ENCPT = $a;

  {$EXTERNALSYM EVP_PKEY_OP_UNDEFINED}
  EVP_PKEY_OP_UNDEFINED = 0;
  {$EXTERNALSYM EVP_PKEY_OP_PARAMGEN}
  EVP_PKEY_OP_PARAMGEN = (1 shl 1);
  {$EXTERNALSYM EVP_PKEY_OP_KEYGEN}
  EVP_PKEY_OP_KEYGEN = (1 shl 2);
  {$EXTERNALSYM EVP_PKEY_OP_SIGN}
  EVP_PKEY_OP_SIGN = (1 shl 3);
  {$EXTERNALSYM EVP_PKEY_OP_VERIFY}
  EVP_PKEY_OP_VERIFY = (1 shl 4);
  {$EXTERNALSYM EVP_PKEY_OP_VERIFYRECOVER}
  EVP_PKEY_OP_VERIFYRECOVER = (1 shl 5);
  {$EXTERNALSYM EVP_PKEY_OP_SIGNCTX}
  EVP_PKEY_OP_SIGNCTX = (1 shl 6);
  {$EXTERNALSYM EVP_PKEY_OP_VERIFYCTX}
  EVP_PKEY_OP_VERIFYCTX = (1 shl 7);
  {$EXTERNALSYM EVP_PKEY_OP_ENCRYPT}
  EVP_PKEY_OP_ENCRYPT = (1 shl 8);
  {$EXTERNALSYM EVP_PKEY_OP_DECRYPT}
  EVP_PKEY_OP_DECRYPT = (1 shl 9);
  {$EXTERNALSYM EVP_PKEY_OP_DERIVE}
  EVP_PKEY_OP_DERIVE = (1 shl 10);

  {$EXTERNALSYM EVP_PKEY_OP_TYPE_SIG}
  EVP_PKEY_OP_TYPE_SIG = EVP_PKEY_OP_SIGN or EVP_PKEY_OP_VERIFY
    or EVP_PKEY_OP_VERIFYRECOVER or EVP_PKEY_OP_SIGNCTX or EVP_PKEY_OP_VERIFYCTX;

  {$EXTERNALSYM EVP_PKEY_OP_TYPE_CRYPT}
  EVP_PKEY_OP_TYPE_CRYPT = EVP_PKEY_OP_ENCRYPT or EVP_PKEY_OP_DECRYPT;

  {$EXTERNALSYM EVP_PKEY_OP_TYPE_NOGEN}
  EVP_PKEY_OP_TYPE_NOGEN = EVP_PKEY_OP_TYPE_SIG or EVP_PKEY_OP_TYPE_CRYPT or EVP_PKEY_OP_DERIVE;

  {$EXTERNALSYM EVP_PKEY_OP_TYPE_GEN}
  EVP_PKEY_OP_TYPE_GEN = EVP_PKEY_OP_PARAMGEN or EVP_PKEY_OP_KEYGEN;

  {$EXTERNALSYM EVP_PKEY_CTRL_MD}
  EVP_PKEY_CTRL_MD = 1;
  {$EXTERNALSYM EVP_PKEY_CTRL_PEER_KEY}
  EVP_PKEY_CTRL_PEER_KEY = 2;

  {$EXTERNALSYM EVP_PKEY_CTRL_PKCS7_ENCRYPT}
  EVP_PKEY_CTRL_PKCS7_ENCRYPT = 3;
  {$EXTERNALSYM EVP_PKEY_CTRL_PKCS7_DECRYPT}
  EVP_PKEY_CTRL_PKCS7_DECRYPT = 4;

  {$EXTERNALSYM EVP_PKEY_CTRL_PKCS7_SIGN}
  EVP_PKEY_CTRL_PKCS7_SIGN = 5;

  {$EXTERNALSYM EVP_PKEY_CTRL_SET_MAC_KEY}
  EVP_PKEY_CTRL_SET_MAC_KEY = 6;

  {$EXTERNALSYM EVP_PKEY_CTRL_DIGESTINIT}
  EVP_PKEY_CTRL_DIGESTINIT = 7;

(* Used by GOST key encryption in TLS *)
  {$EXTERNALSYM EVP_PKEY_CTRL_SET_IV}
  EVP_PKEY_CTRL_SET_IV = 8;

  {$EXTERNALSYM EVP_PKEY_CTRL_CMS_ENCRYPT}
  EVP_PKEY_CTRL_CMS_ENCRYPT = 9;
  {$EXTERNALSYM EVP_PKEY_CTRL_CMS_DECRYPT}
  EVP_PKEY_CTRL_CMS_DECRYPT = 10;
  {$EXTERNALSYM EVP_PKEY_CTRL_CMS_SIGN}
  EVP_PKEY_CTRL_CMS_SIGN = 11;

  {$EXTERNALSYM EVP_PKEY_CTRL_CIPHER}
  EVP_PKEY_CTRL_CIPHER = 12;

  {$EXTERNALSYM EVP_PKEY_CTRL_GET_MD}
  EVP_PKEY_CTRL_GET_MD = 13;

  {$EXTERNALSYM EVP_PKEY_CTRL_SET_DIGEST_SIZE}
  EVP_PKEY_CTRL_SET_DIGEST_SIZE = 14;

  {$EXTERNALSYM EVP_PKEY_ALG_CTRL}
  EVP_PKEY_ALG_CTRL = $1000;

  {$EXTERNALSYM EVP_PKEY_FLAG_AUTOARGLEN}
  EVP_PKEY_FLAG_AUTOARGLEN = 2;
  //
 // Method handles all operations: don't assume any digest related defaults.
 //
  {$EXTERNALSYM EVP_PKEY_FLAG_SIGCTX_CUSTOM}
  EVP_PKEY_FLAG_SIGCTX_CUSTOM = 4;

type
  {$EXTERNALSYM EVP_MD_meth_init}
  EVP_MD_meth_init = function(ctx: PEVP_MD_CTX): TIdC_INT; cdecl;
  {$EXTERNALSYM EVP_MD_meth_update}
  EVP_MD_meth_update = function(ctx: PEVP_MD_CTX; const data: Pointer;
    count: TIdC_SIZET): TIdC_INT; cdecl;
  {$EXTERNALSYM EVP_MD_meth_final}
  EVP_MD_meth_final = function(ctx: PEVP_MD_CTX; const md: PByte): TIdC_INT; cdecl;
  {$EXTERNALSYM EVP_MD_meth_copy}
  EVP_MD_meth_copy = function(to_: PEVP_MD_CTX; const from: PEVP_MD_CTX): TIdC_INT; cdecl;
  {$EXTERNALSYM EVP_MD_meth_cleanup}
  EVP_MD_meth_cleanup = function(ctx: PEVP_MD_CTX): TIdC_INT; cdecl;
  {$EXTERNALSYM EVP_MD_meth_ctrl}
  EVP_MD_meth_ctrl = function(ctx: PEVP_MD_CTX; cmd: TIdC_INT; p1: TIdC_INT;
    p2: Pointer): TIdC_INT; cdecl;

  {$EXTERNALSYM EVP_CIPHER_meth_init}
  EVP_CIPHER_meth_init = function(ctx: PEVP_CIPHER_CTX; const key: PByte;
    const iv: PByte; enc: TIdC_SIZET): TIdC_INT; cdecl;
  {$EXTERNALSYM EVP_CIPHER_meth_do_cipher}
  EVP_CIPHER_meth_do_cipher = function(ctx: PEVP_CIPHER_CTX; var out_;
    const in_; inl: TIdC_SIZET): TIdC_INT; cdecl;
  {$EXTERNALSYM EVP_CIPHER_meth_cleanup}
  EVP_CIPHER_meth_cleanup = function(v1: PEVP_CIPHER_CTX): TIdC_INT; cdecl;
  {$EXTERNALSYM EVP_CIPHER_meth_set_asn1_params}
  EVP_CIPHER_meth_set_asn1_params = function(v1: PEVP_CIPHER_CTX;
    v2: PASN1_TYPE): TIdC_INT; cdecl;
  {$EXTERNALSYM EVP_CIPHER_meth_get_asn1_params}
  EVP_CIPHER_meth_get_asn1_params = function(v1: PEVP_CIPHER_CTX;
    v2: PASN1_TYPE): TIdC_INT; cdecl;
  {$EXTERNALSYM EVP_CIPHER_meth_ctrl}
  EVP_CIPHER_meth_ctrl = function(v1: PEVP_CIPHER_CTX; type_: TIdC_INT;
    arg: TIdC_INT; _ptr: Pointer): TIdC_INT; cdecl;

  {$EXTERNALSYM EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM}
  EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM = record
    out_: PByte;
    inp: PByte;
    len: TIdC_SIZET;
    interleave: TidC_UINT;
  end;

  {$EXTERNALSYM evp_cipher_info_st}
  evp_cipher_info_st = record
    cipher: PEVP_CIPHER;
    iv: array[0 .. EVP_MAX_IV_LENGTH - 1] of PByte;
  end;
  {$EXTERNALSYM EVP_CIPHER_INFO}
  EVP_CIPHER_INFO = evp_cipher_info_st;

  {$EXTERNALSYM EVP_MD_CTX_update}
  EVP_MD_CTX_update = function(ctx: PEVP_MD_CTX; const data: Pointer; count: TIdC_SIZET): TIdC_INT; cdecl;

  {$EXTERNALSYM fn}
  fn = procedure(const ciph: PEVP_CIPHER; const from: PIdAnsiChar; const to_: PIdAnsiChar; x: Pointer); cdecl;

  {$EXTERNALSYM pub_decode}
  pub_decode = function(pk: PEVP_PKEY; pub: PX509_PUBKEY): TIdC_INT; cdecl;
  {$EXTERNALSYM pub_encode}
  pub_encode = function(pub: PX509_PUBKEY; const pk: PEVP_PKEY): TIdC_INT; cdecl;
  {$EXTERNALSYM pub_cmd}
  pub_cmd = function(const a: PEVP_PKEY; const b: PEVP_PKEY): TIdC_INT; cdecl;
  {$EXTERNALSYM pub_print}
  pub_print = function(out_: PBIO; const pkey: PEVP_PKEY; indent: TIdC_INT; pctx: PASN1_PCTX): TIdC_INT; cdecl;
  {$EXTERNALSYM pkey_size}
  pkey_size = function(const pk: PEVP_PKEY): TIdC_INT; cdecl;
  {$EXTERNALSYM pkey_bits}
  pkey_bits = function(const pk: PEVP_PKEY): TIdC_INT; cdecl;

  {$EXTERNALSYM priv_decode}
  priv_decode = function(pk: PEVP_PKEY; const p8inf: PKCS8_PRIV_KEY_INFO): TIdC_INT; cdecl;
  {$EXTERNALSYM priv_encode}
  priv_encode = function(p8: PPKCS8_PRIV_KEY_INFO; const pk: PEVP_PKEY): TIdC_INT; cdecl;
  {$EXTERNALSYM priv_print}
  priv_print = function(out_: PBIO; const pkea: PEVP_PKEY; indent: TIdC_INT; pctx: PASN1_PCTX): TIdC_INT; cdecl;

  {$EXTERNALSYM param_decode}
  param_decode = function(pkey: PEVP_PKEY; const pder: PPByte; derlen: TIdC_INT): TIdC_INT; cdecl;
  {$EXTERNALSYM param_encode}
  param_encode = function(const pkey: PEVP_PKEY; pder: PPByte): TIdC_INT; cdecl;
  {$EXTERNALSYM param_missing}
  param_missing = function(const pk: PEVP_PKEY): TIdC_INT; cdecl;
  {$EXTERNALSYM param_copy}
  param_copy = function(to_: PEVP_PKEY; const from: PEVP_PKEY): TIdC_INT; cdecl;
  {$EXTERNALSYM param_cmp}
  param_cmp = function(const a: PEVP_PKEY; const b: PEVP_PKEY): TIdC_INT; cdecl;
  {$EXTERNALSYM param_print}
  param_print = function(out_: PBIO; const pkey: PEVP_PKEY; indent: TIdC_INT; pctx: PASN1_PCTX): TIdC_INT; cdecl;

  {$EXTERNALSYM pkey_free}
  pkey_free = procedure(pkey: PEVP_PKEY); cdecl;
  {$EXTERNALSYM pkey_ctrl}
  pkey_ctrl = function(pkey: PEVP_PKEY; op: TIdC_INT; arg1: TIdC_LONG; arg2: Pointer): TIdC_INT; cdecl;
  {$EXTERNALSYM item_verify}
  item_verify = function(ctx: PEVP_MD_CTX; const it: PASN1_ITEM; asn: Pointer;
    a: PX509_ALGOR; sig: PASN1_BIT_STRING; pkey: PEVP_PKEY): TIdC_INT; cdecl;
  {$EXTERNALSYM item_sign}
  item_sign = function(ctx: PEVP_MD_CTX; const it: PASN1_ITEM; asn: Pointer;
    alg1: PX509_ALGOR; alg2: PX509_ALGOR; sig: PASN1_BIT_STRING): TIdC_INT; cdecl;
  {$EXTERNALSYM siginf_set}
  siginf_set = function(siginf: PX509_SIG_INFO; const alg: PX509_ALGOR; const sig: PASN1_STRING): TIdC_INT; cdecl;
  {$EXTERNALSYM pkey_check}
  pkey_check = function(const pk: PEVP_PKEY): TIdC_INT; cdecl;
  {$EXTERNALSYM pkey_pub_check}
  pkey_pub_check = function(const pk: PEVP_PKEY): TIdC_INT; cdecl;
  {$EXTERNALSYM pkey_param_check}
  pkey_param_check = function(const pk: PEVP_PKEY): TIdC_INT; cdecl;
  {$EXTERNALSYM set_priv_key}
  set_priv_key = function(pk: PEVP_PKEY; const priv: PByte; len: TIdC_SIZET): TIdC_INT; cdecl;
  {$EXTERNALSYM set_pub_key}
  set_pub_key = function(pk: PEVP_PKEY; const pub: PByte; len: TIdC_SIZET): TIdC_INT; cdecl;
  {$EXTERNALSYM get_priv_key}
  get_priv_key = function(const pk: PEVP_PKEY; priv: PByte; len: PIdC_SIZET): TIdC_INT; cdecl;
  {$EXTERNALSYM get_pub_key}
  get_pub_key = function(const pk: PEVP_PKEY; pub: PByte; len: PIdC_SIZET): TIdC_INT; cdecl;
  {$EXTERNALSYM pkey_security_bits}
  pkey_security_bits = function(const pk: PEVP_PKEY): TIdC_INT; cdecl;

  {$EXTERNALSYM EVP_PKEY_gen_cb}
  EVP_PKEY_gen_cb = function(ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl;
//  PEVP_PKEY_gen_cb = ^EVP_PKEY_gen_cb;

  {$EXTERNALSYM EVP_PKEY_meth_init}
  EVP_PKEY_meth_init = function(ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_init}
  PEVP_PKEY_meth_init = ^EVP_PKEY_meth_init;
  {$EXTERNALSYM EVP_PKEY_meth_copy_cb}
  EVP_PKEY_meth_copy_cb = function(dst: PEVP_PKEY_CTX; src: PEVP_PKEY_CTX): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_copy}
  PEVP_PKEY_meth_copy = ^EVP_PKEY_meth_copy_cb;
  {$EXTERNALSYM EVP_PKEY_meth_cleanup}
  EVP_PKEY_meth_cleanup = procedure(ctx: PEVP_PKEY_CTX); cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_cleanup}
  PEVP_PKEY_meth_cleanup = ^EVP_PKEY_meth_cleanup;
  {$EXTERNALSYM EVP_PKEY_meth_paramgen_init}
  EVP_PKEY_meth_paramgen_init = function(ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_paramgen_init}
  PEVP_PKEY_meth_paramgen_init = ^EVP_PKEY_meth_paramgen_init;
  {$EXTERNALSYM EVP_PKEY_meth_paramgen}
  EVP_PKEY_meth_paramgen = function(ctx: PEVP_PKEY_CTX; pkey: PEVP_PKEY): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_paramgen}
  PEVP_PKEY_meth_paramgen = ^EVP_PKEY_meth_paramgen;
  {$EXTERNALSYM EVP_PKEY_meth_keygen_init}
  EVP_PKEY_meth_keygen_init = function(ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_keygen_init}
  PEVP_PKEY_meth_keygen_init = ^EVP_PKEY_meth_keygen_init;
  {$EXTERNALSYM EVP_PKEY_meth_keygen}
  EVP_PKEY_meth_keygen = function(ctx: PEVP_PKEY_CTX; pkey: PEVP_PKEY): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_keygen}
  PEVP_PKEY_meth_keygen = ^EVP_PKEY_meth_keygen;
  {$EXTERNALSYM EVP_PKEY_meth_sign_init}
  EVP_PKEY_meth_sign_init = function(ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_sign_init}
  PEVP_PKEY_meth_sign_init = ^EVP_PKEY_meth_sign_init;
  {$EXTERNALSYM EVP_PKEY_meth_sign}
  EVP_PKEY_meth_sign = function(ctx: PEVP_PKEY_CTX; sig: PByte; siglen: TIdC_SIZET;
    const tbs: PByte; tbslen: TIdC_SIZET): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_sign}
  PEVP_PKEY_meth_sign = ^EVP_PKEY_meth_sign;
  {$EXTERNALSYM EVP_PKEY_meth_verify_init}
  EVP_PKEY_meth_verify_init = function(ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_verify_init}
  PEVP_PKEY_meth_verify_init = ^EVP_PKEY_meth_verify_init;
  {$EXTERNALSYM EVP_PKEY_meth_verify}
  EVP_PKEY_meth_verify = function(ctx: PEVP_PKEY_CTX; const sig: PByte;
    siglen: TIdC_SIZET; const tbs: PByte; tbslen: TIdC_SIZET): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_verify}
  PEVP_PKEY_meth_verify = ^EVP_PKEY_meth_verify;
  {$EXTERNALSYM EVP_PKEY_meth_verify_recover_init}
  EVP_PKEY_meth_verify_recover_init = function(ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_verify_recover_init}
  PEVP_PKEY_meth_verify_recover_init = ^EVP_PKEY_meth_verify_recover_init;
  {$EXTERNALSYM EVP_PKEY_meth_verify_recover}
  EVP_PKEY_meth_verify_recover = function(ctx: PEVP_PKEY_CTX; sig: PByte;
    siglen: TIdC_SIZET; const tbs: PByte; tbslen: TIdC_SIZET): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_verify_recover}
  PEVP_PKEY_meth_verify_recover = ^EVP_PKEY_meth_verify_recover;
  {$EXTERNALSYM EVP_PKEY_meth_signctx_init}
  EVP_PKEY_meth_signctx_init = function(ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_signctx_init}
  PEVP_PKEY_meth_signctx_init = ^EVP_PKEY_meth_signctx_init;
  {$EXTERNALSYM EVP_PKEY_meth_signctx}
  EVP_PKEY_meth_signctx = function(ctx: PEVP_PKEY_CTX; sig: Pbyte;
    siglen: TIdC_SIZET; mctx: PEVP_MD_CTX): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_signctx}
  PEVP_PKEY_meth_signctx = ^EVP_PKEY_meth_signctx;
  {$EXTERNALSYM EVP_PKEY_meth_verifyctx_init}
  EVP_PKEY_meth_verifyctx_init = function(ctx: PEVP_PKEY_CTX; mctx: PEVP_MD_CTX): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_verifyctx_init}
  PEVP_PKEY_meth_verifyctx_init = ^EVP_PKEY_meth_verifyctx_init;
  {$EXTERNALSYM EVP_PKEY_meth_verifyctx}
  EVP_PKEY_meth_verifyctx = function(ctx: PEVP_PKEY_CTX; const sig: PByte;
    siglen: TIdC_INT; mctx: PEVP_MD_CTX): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_verifyctx}
  PEVP_PKEY_meth_verifyctx = ^EVP_PKEY_meth_verifyctx;
  {$EXTERNALSYM EVP_PKEY_meth_encrypt_init}
  EVP_PKEY_meth_encrypt_init = function(ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_encrypt_init}
  PEVP_PKEY_meth_encrypt_init = ^EVP_PKEY_meth_encrypt_init;
  {$EXTERNALSYM EVP_PKEY_meth_encrypt}
  EVP_PKEY_meth_encrypt = function(ctx: PEVP_PKEY_CTX; var out_;
    outlen: TIdC_SIZET; const in_: PByte): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_encrypt}
  PEVP_PKEY_meth_encrypt = ^ EVP_PKEY_meth_encrypt;
  {$EXTERNALSYM EVP_PKEY_meth_decrypt_init}
  EVP_PKEY_meth_decrypt_init = function(ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_decrypt_init}
  PEVP_PKEY_meth_decrypt_init = ^EVP_PKEY_meth_decrypt_init;
  {$EXTERNALSYM EVP_PKEY_meth_decrypt}
  EVP_PKEY_meth_decrypt = function(ctx: PEVP_PKEY_CTX; var out_;
    outlen: TIdC_SIZET; const in_; inlen: TIdC_SIZET): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_decrypt}
  PEVP_PKEY_meth_decrypt = ^EVP_PKEY_meth_decrypt;
  {$EXTERNALSYM EVP_PKEY_meth_derive_init}
  EVP_PKEY_meth_derive_init = function(ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_derive_init}
  PEVP_PKEY_meth_derive_init = ^EVP_PKEY_meth_derive_init;
  {$EXTERNALSYM EVP_PKEY_meth_derive}
  EVP_PKEY_meth_derive = function(ctx: PEVP_PKEY_CTX; key: PByte; keylen: PIdC_SIZET): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_derive}
  PEVP_PKEY_meth_derive = ^EVP_PKEY_meth_derive;
  {$EXTERNALSYM EVP_PKEY_meth_ctrl}
  EVP_PKEY_meth_ctrl = function(ctx: PEVP_PKEY_CTX; type_: TIdC_INT; p1: TIdC_INT; p2: Pointer): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_ctrl}
  PEVP_PKEY_meth_ctrl = ^EVP_PKEY_meth_ctrl;
  {$EXTERNALSYM EVP_PKEY_meth_ctrl_str}
  EVP_PKEY_meth_ctrl_str = function(ctx: PEVP_PKEY_CTX; key: PByte; keylen: PIdC_SIZET): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_ctrl_str}
  PEVP_PKEY_meth_ctrl_str = ^EVP_PKEY_meth_ctrl_str;
  {$EXTERNALSYM EVP_PKEY_meth_digestsign}
  EVP_PKEY_meth_digestsign = function(ctx: PEVP_PKEY_CTX; sig: PByte;
    siglen: PIdC_SIZET; const tbs: PByte; tbslen: TIdC_SIZET): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_digestsign}
  PEVP_PKEY_meth_digestsign = ^EVP_PKEY_meth_digestsign;
  {$EXTERNALSYM EVP_PKEY_meth_digestverify}
  EVP_PKEY_meth_digestverify = function(ctx: PEVP_MD_CTX; const sig: PByte;
    siglen: TIdC_SIZET; const tbs: PByte; tbslen: TIdC_SIZET): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_digestverify}
  PEVP_PKEY_meth_digestverify = ^EVP_PKEY_meth_digestverify;
  {$EXTERNALSYM EVP_PKEY_meth_check}
  EVP_PKEY_meth_check = function(pkey: PEVP_PKEY): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_check}
  PEVP_PKEY_meth_check = ^EVP_PKEY_meth_check;
  {$EXTERNALSYM EVP_PKEY_meth_public_check}
  EVP_PKEY_meth_public_check = function(pkey: PEVP_PKEY): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_public_check}
  PEVP_PKEY_meth_public_check = ^EVP_PKEY_meth_public_check;
  {$EXTERNALSYM EVP_PKEY_meth_param_check}
  EVP_PKEY_meth_param_check = function(pkey: PEVP_PKEY): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_param_check}
  PEVP_PKEY_meth_param_check = ^EVP_PKEY_meth_param_check;
  {$EXTERNALSYM EVP_PKEY_meth_digest_custom}
  EVP_PKEY_meth_digest_custom = function(pkey: PEVP_PKEY; mctx: PEVP_MD_CTX): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PKEY_meth_digest_custom}
  PEVP_PKEY_meth_digest_custom = ^EVP_PKEY_meth_digest_custom;

  // Password based encryption function
  {$EXTERNALSYM EVP_PBE_KEYGEN}
  EVP_PBE_KEYGEN = function(ctx: PEVP_CIPHER_CTX; const pass: PIdAnsiChar;
    passlen: TIdC_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER;
    const md: PEVP_MD; en_de: TIdC_INT): TIdC_INT; cdecl;
  {$EXTERNALSYM PEVP_PBE_KEYGEN}
  PEVP_PBE_KEYGEN = ^EVP_PBE_KEYGEN;
  {$EXTERNALSYM PPEVP_PBE_KEYGEN}
  PPEVP_PBE_KEYGEN = ^PEVP_PBE_KEYGEN;

  //* MAC Stuff */
  {$EXTERNALSYM EVP_MAC_names_do_all_fn}
  EVP_MAC_names_do_all_fn = procedure (const name : PIdAnsiChar; data : Pointer) cdecl;
  {$EXTERNALSYM EVP_MAC_do_all_provided_fn}
  EVP_MAC_do_all_provided_fn = procedure(mac : PEVP_MAC; arg : Pointer) cdecl;
    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM EVP_PKEY_assign_RSA}
  EVP_PKEY_assign_RSA: function (pkey: PEVP_PKEY; rsa: Pointer): TIdC_INT; cdecl = nil; {removed 1.0.0}
  {$EXTERNALSYM EVP_PKEY_assign_DSA}
  EVP_PKEY_assign_DSA: function (pkey: PEVP_PKEY; dsa: Pointer): TIdC_INT; cdecl = nil; {removed 1.0.0}
  {$EXTERNALSYM EVP_PKEY_assign_DH}
  EVP_PKEY_assign_DH: function (pkey: PEVP_PKEY; dh: Pointer): TIdC_INT; cdecl = nil; {removed 1.0.0}
  {$EXTERNALSYM EVP_PKEY_assign_EC_KEY}
  EVP_PKEY_assign_EC_KEY: function (pkey: PEVP_PKEY; eckey: Pointer): TIdC_INT; cdecl = nil; {removed 1.0.0}
  {$EXTERNALSYM EVP_PKEY_assign_SIPHASH}
  EVP_PKEY_assign_SIPHASH: function (pkey: PEVP_PKEY; shkey: Pointer): TIdC_INT; cdecl = nil; {removed 1.0.0}
  {$EXTERNALSYM EVP_PKEY_assign_POLY1305}
  EVP_PKEY_assign_POLY1305: function (pkey: PEVP_PKEY; polykey: Pointer): TIdC_INT; cdecl = nil; {removed 1.0.0}

  {$EXTERNALSYM EVP_MD_meth_new}
  EVP_MD_meth_new: function (md_type: TIdC_INT; pkey_type: TIdC_INT): PEVP_MD; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_dup}
  EVP_MD_meth_dup: function (const md: PEVP_MD): PEVP_MD; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_free}
  EVP_MD_meth_free: procedure (md: PEVP_MD); cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EVP_MD_meth_set_input_blocksize}
  EVP_MD_meth_set_input_blocksize: function (md: PEVP_MD; blocksize: TIdC_INT): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_set_result_size}
  EVP_MD_meth_set_result_size: function (md: PEVP_MD; resultsize: TIdC_INT): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_set_app_datasize}
  EVP_MD_meth_set_app_datasize: function (md: PEVP_MD; datasize: TIdC_INT): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_set_flags}
  EVP_MD_meth_set_flags: function (md: PEVP_MD; flags: TIdC_ULONG): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_set_init}
  EVP_MD_meth_set_init: function (md: PEVP_MD; init: EVP_MD_meth_init): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_set_update}
  EVP_MD_meth_set_update: function (md: PEVP_MD; update: EVP_MD_meth_update): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_set_final}
  EVP_MD_meth_set_final: function (md: PEVP_MD; final_: EVP_MD_meth_final): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_set_copy}
  EVP_MD_meth_set_copy: function (md: PEVP_MD; _copy: EVP_MD_meth_copy): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_set_cleanup}
  EVP_MD_meth_set_cleanup: function (md: PEVP_MD; cleanup: EVP_MD_meth_cleanup): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_set_ctrl}
  EVP_MD_meth_set_ctrl: function (md: PEVP_MD; ctrl: EVP_MD_meth_ctrl): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EVP_MD_meth_get_input_blocksize}
  EVP_MD_meth_get_input_blocksize: function (const md: PEVP_MD): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_get_result_size}
  EVP_MD_meth_get_result_size: function (const md: PEVP_MD): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_get_app_datasize}
  EVP_MD_meth_get_app_datasize: function (const md: PEVP_MD): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_get_flags}
  EVP_MD_meth_get_flags: function (const md: PEVP_MD): TIdC_ULONG; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_get_init}
  EVP_MD_meth_get_init: function (const md: PEVP_MD): EVP_MD_meth_init; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_get_update}
  EVP_MD_meth_get_update: function (const md: PEVP_MD): EVP_MD_meth_update; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_get_final}
  EVP_MD_meth_get_final: function (const md: PEVP_MD): EVP_MD_meth_final; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_get_copy}
  EVP_MD_meth_get_copy: function (const md: PEVP_MD): EVP_MD_meth_copy; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_get_cleanup}
  EVP_MD_meth_get_cleanup: function (const md: PEVP_MD): EVP_MD_meth_cleanup; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_get_ctrl}
  EVP_MD_meth_get_ctrl: function (const md: PEVP_MD): EVP_MD_meth_ctrl; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EVP_CIPHER_meth_new}
  EVP_CIPHER_meth_new: function (cipher_type: TIdC_INT; block_size: TIdC_INT; key_len: TIdC_INT): PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_dup}
  EVP_CIPHER_meth_dup: function (const cipher: PEVP_CIPHER): PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_free}
  EVP_CIPHER_meth_free: procedure (cipher: PEVP_CIPHER); cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EVP_CIPHER_meth_set_iv_length}
  EVP_CIPHER_meth_set_iv_length: function (cipher: PEVP_CIPHER; iv_len: TIdC_INT): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_set_flags}
  EVP_CIPHER_meth_set_flags: function (cipher: PEVP_CIPHER; flags: TIdC_ULONG): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_set_impl_ctx_size}
  EVP_CIPHER_meth_set_impl_ctx_size: function (cipher: PEVP_CIPHER; ctx_size: TIdC_INT): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_set_init}
  EVP_CIPHER_meth_set_init: function (cipher: PEVP_CIPHER; init: EVP_CIPHER_meth_init): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_set_do_cipher}
  EVP_CIPHER_meth_set_do_cipher: function (cipher: PEVP_CIPHER; do_cipher: EVP_CIPHER_meth_do_cipher): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_set_cleanup}
  EVP_CIPHER_meth_set_cleanup: function (cipher: PEVP_CIPHER; cleanup: EVP_CIPHER_meth_cleanup): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_set_set_asn1_params}
  EVP_CIPHER_meth_set_set_asn1_params: function (cipher: PEVP_CIPHER; set_asn1_parameters: EVP_CIPHER_meth_set_asn1_params): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_set_get_asn1_params}
  EVP_CIPHER_meth_set_get_asn1_params: function (cipher: PEVP_CIPHER; get_asn1_parameters: EVP_CIPHER_meth_get_asn1_params): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_set_ctrl}
  EVP_CIPHER_meth_set_ctrl: function (cipher: PEVP_CIPHER; ctrl: EVP_CIPHER_meth_ctrl): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_get_init}
  EVP_CIPHER_meth_get_init: function (const cipher: PEVP_CIPHER): EVP_CIPHER_meth_init; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_get_do_cipher}
  EVP_CIPHER_meth_get_do_cipher: function (const cipher: PEVP_CIPHER): EVP_CIPHER_meth_do_cipher; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_get_cleanup}
  EVP_CIPHER_meth_get_cleanup: function (const cipher: PEVP_CIPHER): EVP_CIPHER_meth_cleanup; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_get_set_asn1_params}
  EVP_CIPHER_meth_get_set_asn1_params: function (const cipher: PEVP_CIPHER): EVP_CIPHER_meth_set_asn1_params; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_get_get_asn1_params}
  EVP_CIPHER_meth_get_get_asn1_params: function (const cipher: PEVP_CIPHER): EVP_CIPHER_meth_get_asn1_params; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_get_ctrl}
  EVP_CIPHER_meth_get_ctrl: function (const cipher: PEVP_CIPHER): EVP_CIPHER_meth_ctrl; cdecl = nil; {introduced 1.1.0}

  /// Add some extra combinations ///
  //# define EVP_get_digestbynid(a) EVP_get_digestbyname(OBJ_nid2sn(a));
  //# define EVP_get_digestbyobj(a) EVP_get_digestbynid(OBJ_obj2nid(a));
  //# define EVP_get_cipherbynid(a) EVP_get_cipherbyname(OBJ_nid2sn(a));
  //# define EVP_get_cipherbyobj(a) EVP_get_cipherbynid(OBJ_obj2nid(a));

  {$EXTERNALSYM EVP_MD_type}
  EVP_MD_type: function (const md: PEVP_MD): TIdC_INT; cdecl = nil; {removed 3.0.0}
  //# define EVP_MD_nid(e)                   EVP_MD_type(e)
  //# define EVP_MD_name(e)                  OBJ_nid2sn(EVP_MD_nid(e))
  {$EXTERNALSYM EVP_MD_pkey_type}
  EVP_MD_pkey_type: function (const md: PEVP_MD): TIdC_INT; cdecl = nil; {removed 3.0.0}
  {$EXTERNALSYM EVP_MD_size}
  EVP_MD_size: function (const md: PEVP_MD): TIdC_INT; cdecl = nil; {removed 3.0.0}
  {$EXTERNALSYM EVP_MD_block_size}
  EVP_MD_block_size: function (const md: PEVP_MD): TIdC_INT; cdecl = nil; {removed 3.0.0}
  {$EXTERNALSYM EVP_MD_flags}
  EVP_MD_flags: function (const md: PEVP_MD): PIdC_ULONG; cdecl = nil; {removed 3.0.0}

  {$EXTERNALSYM EVP_MD_CTX_md}
  EVP_MD_CTX_md: function (ctx: PEVP_MD_CTX): PEVP_MD; cdecl = nil;
  {$EXTERNALSYM EVP_MD_CTX_update_fn}
  EVP_MD_CTX_update_fn: function (ctx: PEVP_MD_CTX): EVP_MD_CTX_update; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_CTX_set_update_fn}
  EVP_MD_CTX_set_update_fn: procedure (ctx: PEVP_MD_CTX; update: EVP_MD_CTX_update); cdecl = nil; {introduced 1.1.0}
  //  EVP_MD_CTX_size(e)              EVP_MD_size(EVP_MD_CTX_md(e))
  //  EVP_MD_CTX_block_size(e)        EVP_MD_block_size(EVP_MD_CTX_md(e))
  //  EVP_MD_CTX_type(e)              EVP_MD_type(EVP_MD_CTX_md(e))
  {$EXTERNALSYM EVP_MD_CTX_pkey_ctx}
  EVP_MD_CTX_pkey_ctx: function (const ctx: PEVP_MD_CTX): PEVP_PKEY_CTX; cdecl = nil; {introduced 1.1.0 removed 3.0.0}
  {$EXTERNALSYM EVP_MD_CTX_set_pkey_ctx}
  EVP_MD_CTX_set_pkey_ctx: procedure (ctx: PEVP_MD_CTX; pctx: PEVP_PKEY_CTX); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_CTX_md_data}
  EVP_MD_CTX_md_data: function (const ctx: PEVP_MD_CTX): Pointer; cdecl = nil; {introduced 1.1.0 removed 3.0.0}

  {$EXTERNALSYM EVP_CIPHER_nid}
  EVP_CIPHER_nid: function (const cipher: PEVP_CIPHER): TIdC_INT; cdecl = nil; {removed 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_get_nid}
  EVP_CIPHER_get_nid : function(const cipher : PEVP_CIPHER) : TIdC_INT; cdecl = nil; {introduced 3.0.0}
  //# define EVP_CIPHER_name(e)              OBJ_nid2sn(EVP_CIPHER_nid(e))
  {$EXTERNALSYM EVP_CIPHER_get0_name}
  EVP_CIPHER_get0_name : function(const cipher : PEVP_CIPHER) : PIdAnsiChar; cdecl = nil; {introduced 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_block_size}
  EVP_CIPHER_block_size: function (const cipher: PEVP_CIPHER): TIdC_INT; cdecl = nil; {removed 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_get_block_size}
  EVP_CIPHER_get_block_size: function (const cipher: PEVP_CIPHER): TIdC_INT; cdecl = nil; {introduced 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_impl_ctx_size}
  EVP_CIPHER_impl_ctx_size: function (const cipher: PEVP_CIPHER): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_key_length}
  EVP_CIPHER_key_length: function (const cipher: PEVP_CIPHER): TIdC_INT; cdecl = nil; {removed 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_get_key_length}
  EVP_CIPHER_get_key_length: function (const cipher: PEVP_CIPHER): TIdC_INT; cdecl = nil; {introduced 3.0.0}

  {$EXTERNALSYM EVP_CIPHER_iv_length}
  EVP_CIPHER_iv_length: function (const cipher: PEVP_CIPHER): TIdC_INT; cdecl = nil; {removed 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_get_iv_length}
  EVP_CIPHER_get_iv_length: function (const cipher: PEVP_CIPHER): TIdC_INT; cdecl = nil; {introduced 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_flags}
  EVP_CIPHER_flags: function (const cipher: PEVP_CIPHER): TIdC_ULONG; cdecl = nil; {removed 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_get_flags}
  EVP_CIPHER_get_flags: function (const cipher: PEVP_CIPHER): TIdC_ULONG; cdecl = nil; {introduced 3.0.0}
  //# define EVP_CIPHER_mode(e)              (EVP_CIPHER_flags(e) & EVP_CIPH_MODE)

  {$EXTERNALSYM EVP_CIPHER_CTX_cipher}
  EVP_CIPHER_CTX_cipher: function (const ctx: PEVP_CIPHER_CTX): PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_CIPHER_CTX_get0_cipher}
  EVP_CIPHER_CTX_get0_cipher: function(const ctx: PEVP_CIPHER_CTX): PEVP_CIPHER; cdecl = nil; {introduced 3.0.0}

  {$EXTERNALSYM EVP_CIPHER_CTX_encrypting}
  EVP_CIPHER_CTX_encrypting: function (const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl = nil; {introduced 1.1.0 removed 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_is_encrypting}
  EVP_CIPHER_CTX_is_encrypting : function (const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl = nil;  {introduced 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_nid}
  EVP_CIPHER_CTX_nid: function (const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl = nil; {removed 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_get_nid}
  EVP_CIPHER_CTX_get_nid : function (const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl = nil; {introduced3.0.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_block_size}
  EVP_CIPHER_CTX_block_size: function (const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl = nil; {removed 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_get_block_size}
  EVP_CIPHER_CTX_get_block_size: function (const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl = nil; {introduced 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_key_length}
  EVP_CIPHER_CTX_key_length: function (const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl = nil; {removed 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_get_key_length}
  EVP_CIPHER_CTX_get_key_length: function (const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl = nil; {introduced 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_iv_length}
  EVP_CIPHER_CTX_iv_length: function (const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl = nil; {removed 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_get_iv_length}
  EVP_CIPHER_CTX_get_iv_length: function (const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl = nil; {removed 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_iv}
  EVP_CIPHER_CTX_iv: function (const ctx: PEVP_CIPHER_CTX): PByte; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_original_iv}
  EVP_CIPHER_CTX_original_iv: function (const ctx: PEVP_CIPHER_CTX): PByte; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_iv_noconst}
  EVP_CIPHER_CTX_iv_noconst: function (ctx: PEVP_CIPHER_CTX): PByte; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_buf_noconst}
  EVP_CIPHER_CTX_buf_noconst: function (ctx: PEVP_CIPHER_CTX): PByte; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_num}
  EVP_CIPHER_CTX_num: function (const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl = nil; {introduced 1.1.0 removed 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_get_num}
  EVP_CIPHER_CTX_get_num: function (const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl = nil; {introduced 3.0.0}

  {$EXTERNALSYM EVP_CIPHER_CTX_set_num}
  EVP_CIPHER_CTX_set_num: procedure (ctx: PEVP_CIPHER_CTX; num: TIdC_INT); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_copy}
  EVP_CIPHER_CTX_copy: function (out_: PEVP_CIPHER_CTX; const in_: PEVP_CIPHER_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_CIPHER_CTX_get_app_data}
  EVP_CIPHER_CTX_get_app_data: function (const ctx: PEVP_CIPHER_CTX): Pointer; cdecl = nil;
  {$EXTERNALSYM EVP_CIPHER_CTX_set_app_data}
  EVP_CIPHER_CTX_set_app_data: procedure (ctx: PEVP_CIPHER_CTX; data: Pointer); cdecl = nil;
  {$EXTERNALSYM EVP_CIPHER_CTX_get_cipher_data}
  EVP_CIPHER_CTX_get_cipher_data: function (const ctx: PEVP_CIPHER_CTX): Pointer; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_set_cipher_data}
  EVP_CIPHER_CTX_set_cipher_data: function (ctx: PEVP_CIPHER_CTX; cipher_data: Pointer): Pointer; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_tag_length}
  EVP_CIPHER_CTX_tag_length:  function (const ctx : PEVP_CIPHER_CTX) : TIdC_INT;  cdecl = nil; {removed 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_get_tag_length}
  EVP_CIPHER_CTX_get_tag_length: function (const ctx : PEVP_CIPHER_CTX) : TIdC_INT; cdecl = nil; {introduced 3.0.0}

  //# define EVP_CIPHER_CTX_type(c)         EVP_CIPHER_type(EVP_CIPHER_CTX_cipher(c))
  //# if OPENSSL_API_COMPAT < 0x10100000L
  //#  define EVP_CIPHER_CTX_flags(c)       EVP_CIPHER_flags(EVP_CIPHER_CTX_cipher(c))
  //# endif
  //# define EVP_CIPHER_CTX_mode(c)         EVP_CIPHER_mode(EVP_CIPHER_CTX_cipher(c))
  //
  //# define EVP_ENCODE_LENGTH(l)    ((((l)+2)/3*4)+((l)/48+1)*2+80)
  //# define EVP_DECODE_LENGTH(l)    (((l)+3)/4*3+80)
  //
  //# define EVP_SignInit_ex(a;b;c)          EVP_DigestInit_ex(a;b;c)
  //# define EVP_SignInit(a;b)               EVP_DigestInit(a;b)
  //# define EVP_SignUpdate(a;b;c)           EVP_DigestUpdate(a;b;c)
  //# define EVP_VerifyInit_ex(a;b;c)        EVP_DigestInit_ex(a;b;c)
  //# define EVP_VerifyInit(a;b)             EVP_DigestInit(a;b)
  //# define EVP_VerifyUpdate(a;b;c)         EVP_DigestUpdate(a;b;c)
  //# define EVP_OpenUpdate(a;b;c;d;e)       EVP_DecryptUpdate(a;b;c;d;e)
  //# define EVP_SealUpdate(a;b;c;d;e)       EVP_EncryptUpdate(a;b;c;d;e)
  //# define EVP_DigestSignUpdate(a;b;c)     EVP_DigestUpdate(a;b;c)
  //# define EVP_DigestVerifyUpdate(a;b;c)   EVP_DigestUpdate(a;b;c)

  {$EXTERNALSYM BIO_set_md}
  BIO_set_md: procedure (v1: PBIO; const md: PEVP_MD); cdecl = nil; {removed 1.0.0}
  //# define BIO_get_md(b;mdp)          BIO_ctrl(b;BIO_C_GET_MD;0;(PIdAnsiChar)(mdp))
  //# define BIO_get_md_ctx(b;mdcp)     BIO_ctrl(b;BIO_C_GET_MD_CTX;0; (PIdAnsiChar)(mdcp))
  //# define BIO_set_md_ctx(b;mdcp)     BIO_ctrl(b;BIO_C_SET_MD_CTX;0; (PIdAnsiChar)(mdcp))
  //# define BIO_get_cipher_status(b)   BIO_ctrl(b;BIO_C_GET_CIPHER_STATUS;0;NULL)
  //# define BIO_get_cipher_ctx(b;c_pp) BIO_ctrl(b;BIO_C_GET_CIPHER_CTX;0; (PIdAnsiChar)(c_pp))

  //function EVP_Cipher(c: PEVP_CIPHER_CTX; var out_; const in_; in1: TIdC_UINT): TIdC_INT;

  //# define EVP_add_cipher_alias(n;alias) OBJ_NAME_add((alias);OBJ_NAME_TYPE_CIPHER_METH|OBJ_NAME_ALIAS;(n))
  //# define EVP_add_digest_alias(n;alias) OBJ_NAME_add((alias);OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS;(n))
  //# define EVP_delete_cipher_alias(alias) OBJ_NAME_remove(alias;OBJ_NAME_TYPE_CIPHER_METH|OBJ_NAME_ALIAS);
  //# define EVP_delete_digest_alias(alias) OBJ_NAME_remove(alias;OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS);

  //void EVP_MD_CTX_init(EVP_MD_CTX *ctx);
  //int EVP_MD_CTX_cleanup(EVP_MD_CTX *ctx);
  {$EXTERNALSYM EVP_MD_CTX_init}
  EVP_MD_CTX_init: procedure (ctx : PEVP_MD_CTX); cdecl = nil; {removed 1.1.0}
  {$EXTERNALSYM EVP_MD_CTX_cleanup}
  EVP_MD_CTX_cleanup: function (ctx : PEVP_MD_CTX): TIdC_INT; cdecl = nil; {removed 1.1.0}

  {$EXTERNALSYM EVP_MD_CTX_ctrl}
  EVP_MD_CTX_ctrl: function (ctx: PEVP_MD_CTX; cmd: TIdC_INT; p1: TIdC_INT; p2: Pointer): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_CTX_new}
  EVP_MD_CTX_new: function : PEVP_MD_CTX; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_CTX_reset}
  EVP_MD_CTX_reset: function (ctx: PEVP_MD_CTX): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_CTX_free}
  EVP_MD_CTX_free: procedure (ctx: PEVP_MD_CTX); cdecl = nil; {introduced 1.1.0}
  //# define EVP_MD_CTX_create()     EVP_MD_CTX_new()
  //# define EVP_MD_CTX_init(ctx)    EVP_MD_CTX_reset((ctx))
  //# define EVP_MD_CTX_destroy(ctx) EVP_MD_CTX_free((ctx))
  {$EXTERNALSYM EVP_MD_CTX_copy_ex}
  EVP_MD_CTX_copy_ex: function (out_: PEVP_MD_CTX; const in_: PEVP_MD_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_MD_CTX_set_flags}
  EVP_MD_CTX_set_flags: procedure (ctx: PEVP_MD_CTX; flags: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM EVP_MD_CTX_clear_flags}
  EVP_MD_CTX_clear_flags: procedure (ctx: PEVP_MD_CTX; flags: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM EVP_MD_CTX_test_flags}
  EVP_MD_CTX_test_flags: function (const ctx: PEVP_MD_CTX; flags: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_DigestInit_ex}
  EVP_DigestInit_ex: function (ctx: PEVP_MD_CTX; const type_: PEVP_MD; impl: PENGINE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_DigestUpdate}
  EVP_DigestUpdate: function (ctx: PEVP_MD_CTX; const d: Pointer; cnt: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_DigestFinal_ex}
  EVP_DigestFinal_ex: function (ctx: PEVP_MD_CTX; md: PByte; var s: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_Digest}
  EVP_Digest: function (const data: Pointer; count: TIdC_SIZET; md: PByte; size: PIdC_UINT; const type_: PEVP_MD; impl: PENGINE): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EVP_MD_CTX_copy}
  EVP_MD_CTX_copy: function (out_: PEVP_MD_CTX; const in_: PEVP_MD_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_DigestInit}
  EVP_DigestInit: function (ctx: PEVP_MD_CTX; const type_: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_DigestFinal}
  EVP_DigestFinal: function (ctx: PEVP_MD_CTX; md: PByte; var s: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_DigestFinalXOF}
  EVP_DigestFinalXOF: function (ctx: PEVP_MD_CTX; md: PByte; len: TIdC_SIZET): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EVP_read_pw_string}
  EVP_read_pw_string: function (buf: PIdAnsiChar; _length: TIdC_INT; const prompt: PIdAnsiChar; verify: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_read_pw_string_min}
  EVP_read_pw_string_min: function (buf: PIdAnsiChar; minlen: TIdC_INT; maxlen: TIdC_INT; const prompt: PIdAnsiChar; verify: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_set_pw_prompt}
  EVP_set_pw_prompt: procedure (const prompt: PIdAnsiChar); cdecl = nil;
  {$EXTERNALSYM EVP_get_pw_prompt}
  EVP_get_pw_prompt: function : PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM EVP_BytesToKey}
  EVP_BytesToKey: function (const type_: PEVP_CIPHER; const md: PEVP_MD; const salt: PByte; const data: PByte; data1: TIdC_INT; count: TIdC_INT; key: PByte; iv: PByte): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EVP_CIPHER_CTX_set_flags}
  EVP_CIPHER_CTX_set_flags: procedure (ctx: PEVP_CIPHER_CTX; flags: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM EVP_CIPHER_CTX_clear_flags}
  EVP_CIPHER_CTX_clear_flags: procedure (ctx: PEVP_CIPHER_CTX; flags: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM EVP_CIPHER_CTX_test_flags}
  EVP_CIPHER_CTX_test_flags: function (const ctx: PEVP_CIPHER_CTX; flags: TIdC_INT): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EVP_EncryptInit}
  EVP_EncryptInit: function (ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; const key: PByte; const iv: PByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_EncryptInit_ex}
  EVP_EncryptInit_ex: function (ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_EncryptUpdate}
  EVP_EncryptUpdate: function (ctx: PEVP_CIPHER_CTX; var out_; var out1: TIdC_INT; const in_; in_1: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_EncryptFinal_ex}
  EVP_EncryptFinal_ex: function (ctx: PEVP_CIPHER_CTX; var out_; var out1: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_EncryptFinal}
  EVP_EncryptFinal: function (ctx: PEVP_CIPHER_CTX; var out_; var out1: TIdC_INT): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EVP_DecryptInit}
  EVP_DecryptInit: function (ctx: PEVP_CIPHER_CTX; var out_; var out1: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_DecryptInit_ex}
  EVP_DecryptInit_ex: function (ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_DecryptUpdate}
  EVP_DecryptUpdate: function (ctx: PEVP_CIPHER_CTX; var out_; var out1: TIdC_INT; const in_; in_1: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_DecryptFinal}
  EVP_DecryptFinal: function (ctx: PEVP_CIPHER_CTX; var outm; var out1: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_DecryptFinal_ex}
  EVP_DecryptFinal_ex: function (ctx: PEVP_MD_CTX; var outm; var out1: TIdC_INT): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EVP_CipherInit}
  EVP_CipherInit: function (ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; const key: PByte; const iv: PByte; enc: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_CipherInit_ex}
  EVP_CipherInit_ex: function (ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte; enc: TidC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_CipherUpdate}
  EVP_CipherUpdate: function (ctx: PEVP_CIPHER_CTX; var out_; var out1: TIdC_INT; const in_; in1: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_CipherFinal}
  EVP_CipherFinal: function (ctx: PEVP_CIPHER_CTX; var outm; var out1: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_CipherFinal_ex}
  EVP_CipherFinal_ex: function (ctx: PEVP_CIPHER_CTX; var outm; var out1: TIdC_INT): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EVP_SignFinal}
  EVP_SignFinal: function (ctx: PEVP_CIPHER_CTX; md: PByte; s: PIdC_UINT; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EVP_DigestSign}
  EVP_DigestSign: function (ctx: PEVP_CIPHER_CTX; sigret: PByte; siglen: PIdC_SIZET; const tbs: PByte; tbslen: TIdC_SIZET): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EVP_VerifyFinal}
  EVP_VerifyFinal: function (ctx: PEVP_MD_CTX; const sigbuf: PByte; siglen: TIdC_UINT; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EVP_DigestVerify}
  EVP_DigestVerify: function (ctx: PEVP_CIPHER_CTX; const sigret: PByte; siglen: TIdC_SIZET; const tbs: PByte; tbslen: TIdC_SIZET): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EVP_DigestSignInit}
  EVP_DigestSignInit: function (ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; const type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_DigestSignFinal}
  EVP_DigestSignFinal: function (ctx: PEVP_MD_CTX; sigret: PByte; siglen: PIdC_SIZET): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EVP_DigestVerifyInit}
  EVP_DigestVerifyInit: function (ctx: PEVP_MD_CTX; ppctx: PPEVP_PKEY_CTX; const type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_DigestVerifyFinal}
  EVP_DigestVerifyFinal: function (ctx: PEVP_MD_CTX; const sig: PByte; siglen: TIdC_SIZET): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EVP_OpenInit}
  EVP_OpenInit: function (ctx: PEVP_CIPHER_CTX; const type_: PEVP_CIPHER; const ek: PByte; ek1: TIdC_INT; const iv: PByte; priv: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_OpenFinal}
  EVP_OpenFinal: function (ctx: PEVP_CIPHER_CTX; var out_; var out1: TIdC_INT): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EVP_SealInit}
  EVP_SealInit: function (ctx: PEVP_CIPHER_CTX; const type_: PEVP_CIPHER; ek: PPByte; ek1: PIdC_INT; iv: PByte; pubk: PPEVP_PKEY; npubk: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_SealFinal}
  EVP_SealFinal: function (ctx: PEVP_CIPHER_CTX; var out_; var out1: TIdC_INT): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EVP_ENCODE_CTX_new}
  EVP_ENCODE_CTX_new: function : PEVP_ENCODE_CTX; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_ENCODE_CTX_free}
  EVP_ENCODE_CTX_free: procedure (ctx: PEVP_ENCODE_CTX); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_ENCODE_CTX_copy}
  EVP_ENCODE_CTX_copy: function (dctx: PEVP_ENCODE_CTX; sctx: PEVP_ENCODE_CTX): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_ENCODE_CTX_num}
  EVP_ENCODE_CTX_num: function (ctx: PEVP_ENCODE_CTX): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_EncodeInit}
  EVP_EncodeInit: procedure (ctx: PEVP_ENCODE_CTX); cdecl = nil;
  {$EXTERNALSYM EVP_EncodeUpdate}
  EVP_EncodeUpdate: function (ctx: PEVP_ENCODE_CTX; var out_; var out1: TIdC_INT; const in_; in1: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_EncodeFinal}
  EVP_EncodeFinal: procedure (ctx: PEVP_ENCODE_CTX; var out_; var out1: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM EVP_EncodeBlock}
  EVP_EncodeBlock: function (t: PByte; const f: PByte; n: TIdC_INT): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EVP_DecodeInit}
  EVP_DecodeInit: procedure (ctx: PEVP_ENCODE_CTX); cdecl = nil;
  {$EXTERNALSYM EVP_DecodeUpdate}
  EVP_DecodeUpdate: function (ctx: PEVP_ENCODE_CTX; var out_; var out1: TIdC_INT; const in_; in1: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_DecodeFinal}
  EVP_DecodeFinal: function (ctx: PEVP_ENCODE_CTX; var out_; var out1: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_DecodeBlock}
  EVP_DecodeBlock: function (t: PByte; const f: PByte; n: TIdC_INT): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EVP_CIPHER_fetch}
  EVP_CIPHER_fetch: function (ctx: POSSL_LIB_CTX; const algorithm, properties: PIdAnsiChar): PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_CIPHER_free}
  EVP_CIPHER_free: procedure (cipher: PEVP_CIPHER); cdecl = nil;
  {$EXTERNALSYM EVP_CIPHER_CTX_new}
  EVP_CIPHER_CTX_new: function : PEVP_CIPHER_CTX; cdecl = nil;
  {$EXTERNALSYM EVP_CIPHER_CTX_reset}
  EVP_CIPHER_CTX_reset: function (c: PEVP_CIPHER_CTX): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_free}
  EVP_CIPHER_CTX_free: procedure (c: PEVP_CIPHER_CTX); cdecl = nil;
  {$EXTERNALSYM EVP_CIPHER_CTX_set_key_length}
  EVP_CIPHER_CTX_set_key_length: function (x: PEVP_CIPHER_CTX; keylen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_CIPHER_CTX_set_padding}
  EVP_CIPHER_CTX_set_padding: function (c: PEVP_CIPHER_CTX; pad: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_CIPHER_CTX_ctrl}
  EVP_CIPHER_CTX_ctrl: function (ctx: PEVP_CIPHER_CTX; type_: TIdC_INT; arg: TIdC_INT; _ptr: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_CIPHER_CTX_rand_key}
  EVP_CIPHER_CTX_rand_key: function (ctx: PEVP_CIPHER_CTX; key: PByte): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM BIO_f_md}
  BIO_f_md: function : PBIO_METHOD; cdecl = nil;
  {$EXTERNALSYM BIO_f_base64}
  BIO_f_base64: function : PBIO_METHOD; cdecl = nil;
  {$EXTERNALSYM BIO_f_cipher}
  BIO_f_cipher: function : PBIO_METHOD; cdecl = nil;
  {$EXTERNALSYM BIO_f_reliable}
  BIO_f_reliable: function : PBIO_METHOD; cdecl = nil;
  {$EXTERNALSYM BIO_set_cipher}
  BIO_set_cipher: function (b: PBIO; c: PEVP_CIPHER; const k: PByte; const i: PByte; enc: TIdC_INT): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EVP_md_null}
  EVP_md_null: function : PEVP_MD; cdecl = nil;

  {$EXTERNALSYM EVP_md2}
  EVP_md2: function : PEVP_MD; cdecl = nil; {removed 1.1.0 allow_nil}
  {$EXTERNALSYM EVP_md4}
  EVP_md4: function : PEVP_MD; cdecl = nil; {removed 1.1.0 allow_nil}
  {$EXTERNALSYM EVP_md5}
  EVP_md5: function : PEVP_MD; cdecl = nil; {removed 1.1.0 allow_nil}
  {$EXTERNALSYM EVP_md5_sha1}
  EVP_md5_sha1: function : PEVP_MD; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EVP_sha1}
  EVP_sha1: function : PEVP_MD; cdecl = nil;
  {$EXTERNALSYM EVP_sha224}
  EVP_sha224: function : PEVP_MD; cdecl = nil;
  {$EXTERNALSYM EVP_sha256}
  EVP_sha256: function : PEVP_MD; cdecl = nil;
  {$EXTERNALSYM EVP_sha384}
  EVP_sha384: function : PEVP_MD; cdecl = nil;
  {$EXTERNALSYM EVP_sha512}
  EVP_sha512: function : PEVP_MD; cdecl = nil;
  {$EXTERNALSYM EVP_sha512_224}
  EVP_sha512_224: function : PEVP_MD; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_sha512_256}
  EVP_sha512_256: function : PEVP_MD; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_sha3_224}
  EVP_sha3_224: function : PEVP_MD; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_sha3_256}
  EVP_sha3_256: function : PEVP_MD; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_sha3_384}
  EVP_sha3_384: function : PEVP_MD; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_sha3_512}
  EVP_sha3_512: function : PEVP_MD; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_shake128}
  EVP_shake128: function : PEVP_MD; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_shake256}
  EVP_shake256: function : PEVP_MD; cdecl = nil; {introduced 1.1.0}

  (* does nothing :-) *)
  {$EXTERNALSYM EVP_enc_null}
  EVP_enc_null: function : PEVP_CIPHER; cdecl = nil;

  {$EXTERNALSYM EVP_des_ecb}
  EVP_des_ecb: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_des_ede}
  EVP_des_ede: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_des_ede3}
  EVP_des_ede3: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_des_ede_ecb}
  EVP_des_ede_ecb: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_des_ede3_ecb}
  EVP_des_ede3_ecb: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_des_cfb64}
  EVP_des_cfb64: function : PEVP_CIPHER; cdecl = nil;
  //EVP_des_cfb EVP_des_cfb64
  {$EXTERNALSYM EVP_des_cfb1}
  EVP_des_cfb1: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_des_cfb8}
  EVP_des_cfb8: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_des_ede_cfb64}
  EVP_des_ede_cfb64: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_des_ede3_cfb64}
  EVP_des_ede3_cfb64: function : PEVP_CIPHER; cdecl = nil;
  //EVP_des_ede3_cfb EVP_des_ede3_cfb64
  {$EXTERNALSYM EVP_des_ede3_cfb1}
  EVP_des_ede3_cfb1: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_des_ede3_cfb8}
  EVP_des_ede3_cfb8: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_des_ofb}
  EVP_des_ofb: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_des_ede_ofb}
  EVP_des_ede_ofb: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_des_ede3_ofb}
  EVP_des_ede3_ofb: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_des_cbc}
  EVP_des_cbc: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_des_ede_cbc}
  EVP_des_ede_cbc: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_des_ede3_cbc}
  EVP_des_ede3_cbc: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_desx_cbc}
  EVP_desx_cbc: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_des_ede3_wrap}
  EVP_des_ede3_wrap: function : PEVP_CIPHER; cdecl = nil;
  //
  // This should now be supported through the dev_crypto ENGINE. But also, why
  // are rc4 and md5 declarations made here inside a "NO_DES" precompiler
  // branch?
  //
  {$EXTERNALSYM EVP_rc4}
  EVP_rc4: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_rc4_40}
  EVP_rc4_40: function : PEVP_CIPHER; cdecl = nil;
//  function EVP_idea_ecb: PEVP_CIPHER;
// function EVP_idea_cfb64: PEVP_CIPHER;
  //EVP_idea_cfb EVP_idea_cfb64
//  function EVP_idea_ofb: PEVP_CIPHER;
 // function EVP_idea_cbc: PEVP_CIPHER;
  {$EXTERNALSYM EVP_rc2_ecb}
  EVP_rc2_ecb: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_rc2_cbc}
  EVP_rc2_cbc: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_rc2_40_cbc}
  EVP_rc2_40_cbc: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_rc2_64_cbc}
  EVP_rc2_64_cbc: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_rc2_cfb64}
  EVP_rc2_cfb64: function : PEVP_CIPHER; cdecl = nil;
  //EVP_rc2_cfb EVP_rc2_cfb64
  {$EXTERNALSYM EVP_rc2_ofb}
  EVP_rc2_ofb: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_bf_ecb}
  EVP_bf_ecb: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_bf_cbc}
  EVP_bf_cbc: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_bf_cfb64}
  EVP_bf_cfb64: function : PEVP_CIPHER; cdecl = nil;
  //EVP_bf_cfb EVP_bf_cfb64
  {$EXTERNALSYM EVP_bf_ofb}
  EVP_bf_ofb: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_cast5_ecb}
  EVP_cast5_ecb: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_cast5_cbc}
  EVP_cast5_cbc: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_cast5_cfb64}
  EVP_cast5_cfb64: function : PEVP_CIPHER; cdecl = nil;
  //EVP_cast5_cfb EVP_cast5_cfb64
  {$EXTERNALSYM EVP_cast5_ofb}
  EVP_cast5_ofb: function : PEVP_CIPHER; cdecl = nil;
//  function EVP_rc5_32_12_16_cbc: PEVP_CIPHER;
//  function EVP_rc5_32_12_16_ecb: PEVP_CIPHER;
//  function EVP_rc5_32_12_16_cfb64: PEVP_CIPHER;
  //EVP_rc5_32_12_16_cfb EVP_rc5_32_12_16_cfb64
//  function EVP_rc5_32_12_16_ofb: PEVP_CIPHER;

  {$EXTERNALSYM EVP_aes_128_ecb}
  EVP_aes_128_ecb: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_128_cbc}
  EVP_aes_128_cbc: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_128_cfb1}
  EVP_aes_128_cfb1: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_128_cfb8}
  EVP_aes_128_cfb8: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_128_cfb128}
  EVP_aes_128_cfb128: function : PEVP_CIPHER; cdecl = nil;
  //EVP_aes_128_cfb EVP_aes_128_cfb128
  {$EXTERNALSYM EVP_aes_128_ofb}
  EVP_aes_128_ofb: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_128_ctr}
  EVP_aes_128_ctr: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_128_ccm}
  EVP_aes_128_ccm: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_128_gcm}
  EVP_aes_128_gcm: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_128_xts}
  EVP_aes_128_xts: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_128_wrap}
  EVP_aes_128_wrap: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_128_wrap_pad}
  EVP_aes_128_wrap_pad: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aes_128_ocb}
  EVP_aes_128_ocb: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aes_192_ecb}
  EVP_aes_192_ecb: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_192_cbc}
  EVP_aes_192_cbc: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_192_cfb1}
  EVP_aes_192_cfb1: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_192_cfb8}
  EVP_aes_192_cfb8: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_192_cfb128}
  EVP_aes_192_cfb128: function : PEVP_CIPHER; cdecl = nil;
  //EVP_aes_192_cfb EVP_aes_192_cfb128
  {$EXTERNALSYM EVP_aes_192_ofb}
  EVP_aes_192_ofb: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_192_ctr}
  EVP_aes_192_ctr: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_192_ccm}
  EVP_aes_192_ccm: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_192_gcm}
  EVP_aes_192_gcm: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_192_wrap}
  EVP_aes_192_wrap: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_192_wrap_pad}
  EVP_aes_192_wrap_pad: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aes_192_ocb}
  EVP_aes_192_ocb: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aes_256_ecb}
  EVP_aes_256_ecb: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_256_cbc}
  EVP_aes_256_cbc: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_256_cfb1}
  EVP_aes_256_cfb1: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_256_cfb8}
  EVP_aes_256_cfb8: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_256_cfb128}
  EVP_aes_256_cfb128: function : PEVP_CIPHER; cdecl = nil;
  //EVP_aes_256_cfb EVP_aes_256_cfb128
  {$EXTERNALSYM EVP_aes_256_ofb}
  EVP_aes_256_ofb: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_256_ctr}
  EVP_aes_256_ctr: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_256_ccm}
  EVP_aes_256_ccm: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_256_gcm}
  EVP_aes_256_gcm: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_256_xts}
  EVP_aes_256_xts: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_256_wrap}
  EVP_aes_256_wrap: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_256_wrap_pad}
  EVP_aes_256_wrap_pad: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aes_256_ocb}
  EVP_aes_256_ocb: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aes_128_cbc_hmac_sha1}
  EVP_aes_128_cbc_hmac_sha1: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_256_cbc_hmac_sha1}
  EVP_aes_256_cbc_hmac_sha1: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_128_cbc_hmac_sha256}
  EVP_aes_128_cbc_hmac_sha256: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_aes_256_cbc_hmac_sha256}
  EVP_aes_256_cbc_hmac_sha256: function : PEVP_CIPHER; cdecl = nil;

  {$EXTERNALSYM EVP_aria_128_ecb}
  EVP_aria_128_ecb: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_128_cbc}
  EVP_aria_128_cbc: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_128_cfb1}
  EVP_aria_128_cfb1: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_128_cfb8}
  EVP_aria_128_cfb8: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_128_cfb128}
  EVP_aria_128_cfb128: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_128_ctr}
  EVP_aria_128_ctr: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_128_ofb}
  EVP_aria_128_ofb: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_128_gcm}
  EVP_aria_128_gcm: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_128_ccm}
  EVP_aria_128_ccm: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_192_ecb}
  EVP_aria_192_ecb: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_192_cbc}
  EVP_aria_192_cbc: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_192_cfb1}
  EVP_aria_192_cfb1: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_192_cfb8}
  EVP_aria_192_cfb8: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_192_cfb128}
  EVP_aria_192_cfb128: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  //EVP_aria_192_cfb EVP_aria_192_cfb128
  {$EXTERNALSYM EVP_aria_192_ctr}
  EVP_aria_192_ctr: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_192_ofb}
  EVP_aria_192_ofb: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_192_gcm}
  EVP_aria_192_gcm: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_192_ccm}
  EVP_aria_192_ccm: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_256_ecb}
  EVP_aria_256_ecb: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_256_cbc}
  EVP_aria_256_cbc: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_256_cfb1}
  EVP_aria_256_cfb1: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_256_cfb8}
  EVP_aria_256_cfb8: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_256_cfb128}
  EVP_aria_256_cfb128: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  //EVP_aria_256_cfb EVP_aria_256_cfb128
  {$EXTERNALSYM EVP_aria_256_ctr}
  EVP_aria_256_ctr: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_256_ofb}
  EVP_aria_256_ofb: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_256_gcm}
  EVP_aria_256_gcm: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_256_ccm}
  EVP_aria_256_ccm: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EVP_camellia_128_ecb}
  EVP_camellia_128_ecb: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_camellia_128_cbc}
  EVP_camellia_128_cbc: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_camellia_128_cfb1}
  EVP_camellia_128_cfb1: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_camellia_128_cfb8}
  EVP_camellia_128_cfb8: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_camellia_128_cfb128}
  EVP_camellia_128_cfb128: function : PEVP_CIPHER; cdecl = nil;
  //EVP_camellia_128_cfb EVP_camellia_128_cfb128
  {$EXTERNALSYM EVP_camellia_128_ofb}
  EVP_camellia_128_ofb: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_camellia_128_ctr}
  EVP_camellia_128_ctr: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_camellia_192_ecb}
  EVP_camellia_192_ecb: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_camellia_192_cbc}
  EVP_camellia_192_cbc: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_camellia_192_cfb1}
  EVP_camellia_192_cfb1: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_camellia_192_cfb8}
  EVP_camellia_192_cfb8: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_camellia_192_cfb128}
  EVP_camellia_192_cfb128: function : PEVP_CIPHER; cdecl = nil;
  //EVP_camellia_192_cfb EVP_camellia_192_cfb128
  {$EXTERNALSYM EVP_camellia_192_ofb}
  EVP_camellia_192_ofb: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_camellia_192_ctr}
  EVP_camellia_192_ctr: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_camellia_256_ecb}
  EVP_camellia_256_ecb: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_camellia_256_cbc}
  EVP_camellia_256_cbc: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_camellia_256_cfb1}
  EVP_camellia_256_cfb1: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_camellia_256_cfb8}
  EVP_camellia_256_cfb8: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_camellia_256_cfb128}
  EVP_camellia_256_cfb128: function : PEVP_CIPHER; cdecl = nil;
  //EVP_camellia_256_cfb EVP_camellia_256_cfb128
  {$EXTERNALSYM EVP_camellia_256_ofb}
  EVP_camellia_256_ofb: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_camellia_256_ctr}
  EVP_camellia_256_ctr: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EVP_chacha20}
  EVP_chacha20: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_chacha20_poly1305}
  EVP_chacha20_poly1305: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EVP_seed_ecb}
  EVP_seed_ecb: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_seed_cbc}
  EVP_seed_cbc: function : PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_seed_cfb128}
  EVP_seed_cfb128: function : PEVP_CIPHER; cdecl = nil;
  //EVP_seed_cfb EVP_seed_cfb128
  {$EXTERNALSYM EVP_seed_ofb}
  EVP_seed_ofb: function : PEVP_CIPHER; cdecl = nil;

  {$EXTERNALSYM EVP_sm4_ecb}
  EVP_sm4_ecb: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_sm4_cbc}
  EVP_sm4_cbc: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_sm4_cfb128}
  EVP_sm4_cfb128: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  //EVP_sm4_cfb EVP_sm4_cfb128
  {$EXTERNALSYM EVP_sm4_ofb}
  EVP_sm4_ofb: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_sm4_ctr}
  EVP_sm4_ctr: function : PEVP_CIPHER; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EVP_add_cipher}
  EVP_add_cipher: function (const cipher: PEVP_CIPHER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_add_digest}
  EVP_add_digest: function (const digest: PEVP_MD): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EVP_get_cipherbyname}
  EVP_get_cipherbyname: function (const name: PIdAnsiChar): PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM EVP_get_digestbyname}
  EVP_get_digestbyname: function (const name: PIdAnsiChar): PEVP_MD; cdecl = nil;

  {$EXTERNALSYM EVP_CIPHER_do_all}
  EVP_CIPHER_do_all: procedure (AFn: fn; arg: Pointer); cdecl = nil;
  {$EXTERNALSYM EVP_CIPHER_do_all_sorted}
  EVP_CIPHER_do_all_sorted: procedure (AFn: fn; arg: Pointer); cdecl = nil;

  {$EXTERNALSYM EVP_MD_do_all}
  EVP_MD_do_all: procedure (AFn: fn; arg: Pointer); cdecl = nil;
  {$EXTERNALSYM EVP_MD_do_all_sorted}
  EVP_MD_do_all_sorted: procedure (AFn: fn; arg: Pointer); cdecl = nil;

  {$EXTERNALSYM EVP_PKEY_decrypt_old}
  EVP_PKEY_decrypt_old: function (dec_key: PByte; const enc_key: PByte; enc_key_len: TIdC_INT; private_key: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_encrypt_old}
  EVP_PKEY_encrypt_old: function (dec_key: PByte; const enc_key: PByte; key_len: TIdC_INT; pub_key: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_type}
  EVP_PKEY_type: function (type_: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_id}
  EVP_PKEY_id: function (const pkey: PEVP_PKEY): TIdC_INT; cdecl = nil; {removed 3.0.0}
  {$EXTERNALSYM EVP_PKEY_base_id}
  EVP_PKEY_base_id: function (const pkey: PEVP_PKEY): TIdC_INT; cdecl = nil; {removed 3.0.0}
  {$EXTERNALSYM EVP_PKEY_bits}
  EVP_PKEY_bits: function (const pkey: PEVP_PKEY): TIdC_INT; cdecl = nil; {removed 3.0.0}
  {$EXTERNALSYM EVP_PKEY_security_bits}
  EVP_PKEY_security_bits: function (const pkey: PEVP_PKEY): TIdC_INT; cdecl = nil; {introduced 1.1.0 removed 3.0.0}
  {$EXTERNALSYM EVP_PKEY_size}
  EVP_PKEY_size: function (const pkey: PEVP_PKEY): TIdC_INT; cdecl = nil; {removed 3.0.0}
  {$EXTERNALSYM EVP_PKEY_set_type}
  EVP_PKEY_set_type: function (pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_set_type_str}
  EVP_PKEY_set_type_str: function (pkey: PEVP_PKEY; const _str: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_set_alias_type}
  EVP_PKEY_set_alias_type: function (pkey: PEVP_PKEY; type_: TIdC_INT): TIdC_INT; cdecl = nil; {introduced 1.1.0 removed 3.0.0}

  {$EXTERNALSYM EVP_PKEY_set1_engine}
  EVP_PKEY_set1_engine: function (pkey: PEVP_PKEY; e: PENGINE): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_get0_engine}
  EVP_PKEY_get0_engine: function (const pkey: PEVP_PKEY): PENGINE; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_assign}
  EVP_PKEY_assign: function (pkey: PEVP_PKEY; type_: TIdC_INT; key: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_get0}
  EVP_PKEY_get0: function (const pkey: PEVP_PKEY): Pointer; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_get0_hmac}
  EVP_PKEY_get0_hmac: function (const pkey: PEVP_PKEY; len: PIdC_SIZET): PByte; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_get0_poly1305}
  EVP_PKEY_get0_poly1305: function (const pkey: PEVP_PKEY; len: PIdC_SIZET): PByte; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_get0_siphash}
  EVP_PKEY_get0_siphash: function (const pkey: PEVP_PKEY; len: PIdC_SIZET): PByte; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_set1_RSA}
  EVP_PKEY_set1_RSA: function (pkey: PEVP_PKEY; key: PRSA): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_get0_RSA}
  EVP_PKEY_get0_RSA: function (pkey: PEVP_PKEY): PRSA; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_get1_RSA}
  EVP_PKEY_get1_RSA: function (pkey: PEVP_PKEY): PRSA; cdecl = nil;

  {$EXTERNALSYM EVP_PKEY_set1_DSA}
  EVP_PKEY_set1_DSA: function (pkey: PEVP_PKEY; key: PDSA): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_get0_DSA}
  EVP_PKEY_get0_DSA: function (pkey: PEVP_PKEY): PDSA; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_get1_DSA}
  EVP_PKEY_get1_DSA: function (pkey: PEVP_PKEY): PDSA; cdecl = nil;

  {$EXTERNALSYM EVP_PKEY_set1_DH}
  EVP_PKEY_set1_DH: function (pkey: PEVP_PKEY; key: PDH): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_get0_DH}
  EVP_PKEY_get0_DH: function (pkey: PEVP_PKEY): PDH; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_get1_DH}
  EVP_PKEY_get1_DH: function (pkey: PEVP_PKEY): PDH; cdecl = nil;

  {$EXTERNALSYM EVP_PKEY_set1_EC_KEY}
  EVP_PKEY_set1_EC_KEY: function (pkey: PEVP_PKEY; key: PEC_KEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_get0_EC_KEY}
  EVP_PKEY_get0_EC_KEY: function (pkey: PEVP_PKEY): PEC_KEY; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_get1_EC_KEY}
  EVP_PKEY_get1_EC_KEY: function (pkey: PEVP_PKEY): PEC_KEY; cdecl = nil;

  {$EXTERNALSYM EVP_PKEY_new}
  EVP_PKEY_new: function : PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_up_ref}
  EVP_PKEY_up_ref: function (pkey: PEVP_PKEY): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_free}
  EVP_PKEY_free: procedure (pkey: PEVP_PKEY); cdecl = nil;

  {$EXTERNALSYM d2i_PublicKey}
  d2i_PublicKey: function (type_: TIdC_INT; a: PPEVP_PKEY; const pp: PPByte; _length: TIdC_LONG): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM i2d_PublicKey}
  i2d_PublicKey: function (a: PEVP_PKEY; pp: PPByte): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM d2i_PrivateKey}
  d2i_PrivateKey: function (type_: TIdC_INT; a: PEVP_PKEY; const pp: PPByte; _length: TIdC_LONG): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM d2i_AutoPrivateKey}
  d2i_AutoPrivateKey: function (a: PPEVP_PKEY; const pp: PPByte; _length: TIdC_LONG): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM d2i_AutoPrivateKey_ex}
  d2i_AutoPrivateKey_ex : function(a: PPEVP_PKEY; const pp: PPByte; _length: TIdC_LONG;
    libctx : POSSL_LIB_CTX; propq : PIdAnsiChar): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM i2d_PrivateKey}
  i2d_PrivateKey: function (a: PEVP_PKEY; pp: PPByte): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM i2d_KeyParams_bio}
  i2d_KeyParams_bio : function(pb : PBIO; const pkey : PEVP_PKEY) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_KeyParams_bio}
  d2i_KeyParams_bio : function(type_ : TIdC_INT; var a : PEVP_PKEY; in_ : PBIO) : PEVP_PKEY; cdecl = nil;

  {$EXTERNALSYM EVP_PKEY_copy_parameters}
  EVP_PKEY_copy_parameters: function (to_: PEVP_PKEY; const from: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_missing_parameters}
  EVP_PKEY_missing_parameters: function (const pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_save_parameters}
  EVP_PKEY_save_parameters: function (pkey: PEVP_PKEY; mode: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_cmp_parameters}
  EVP_PKEY_cmp_parameters: function (const a: PEVP_PKEY; const b: PEVP_PKEY): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EVP_PKEY_cmp}
  EVP_PKEY_cmp: function (const a: PEVP_PKEY; const b: PEVP_PKEY): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EVP_PKEY_print_public}
  EVP_PKEY_print_public: function (out_: PBIO; const pkey: PEVP_PKEY; indent: TIdC_INT; pctx: PASN1_PCTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_print_private}
  EVP_PKEY_print_private: function (out_: PBIO; const pkey: PEVP_PKEY; indent: TIdC_INT; pctx: PASN1_PCTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_print_params}
  EVP_PKEY_print_params: function (out_: PBIO; const pkey: PEVP_PKEY; indent: TIdC_INT; pctx: PASN1_PCTX): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EVP_PKEY_get_default_digest_nid}
  EVP_PKEY_get_default_digest_nid: function (pkey: PEVP_PKEY; pnid: PIdC_INT): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EVP_PKEY_set1_tls_encodedpoint}
  EVP_PKEY_set1_tls_encodedpoint: function (pkey: PEVP_PKEY; const pt: PByte; ptlen: TIdC_SIZET): TIdC_INT; cdecl = nil; {introduced 1.1.0 removed 3.0.0}
  {$EXTERNALSYM EVP_PKEY_get1_tls_encodedpoint}
  EVP_PKEY_get1_tls_encodedpoint: function (pkey: PEVP_PKEY; ppt: PPByte): TIdC_SIZET; cdecl = nil; {introduced 1.1.0 removed 3.0.0}

  {$EXTERNALSYM EVP_CIPHER_type}
  EVP_CIPHER_type: function (const cipher: PEVP_CIPHER): TIdC_INT; cdecl = nil; {removed 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_get_type}
  EVP_CIPHER_get_type: function (const cipher: PEVP_CIPHER): TIdC_INT; cdecl = nil; {introduced 3.0.0}
  (* calls methods *)
  {$EXTERNALSYM EVP_CIPHER_param_to_asn1}
  EVP_CIPHER_param_to_asn1: function (c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_CIPHER_asn1_to_param}
  EVP_CIPHER_asn1_to_param: function (c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TIdC_INT; cdecl = nil;

  (* These are used by EVP_CIPHER methods *)
  {$EXTERNALSYM EVP_CIPHER_set_asn1_iv}
  EVP_CIPHER_set_asn1_iv: function (c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_CIPHER_get_asn1_iv}
  EVP_CIPHER_get_asn1_iv: function (c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EVP_CIPHER_get_mode}
   EVP_CIPHER_get_mode: function (const cipher : PEVP_CIPHER) : TIdC_INT; cdecl = nil;

  (* PKCS5 password based encryption *)
  {$EXTERNALSYM PKCS5_PBE_keyivgen}
  PKCS5_PBE_keyivgen: function (ctx: PEVP_CIPHER_CTX; const pass: PIdAnsiChar; passlen: TIdC_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md: PEVP_MD; en_de: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS5_PBKDF2_HMAC_SHA1}
  PKCS5_PBKDF2_HMAC_SHA1: function (const pass: PIdAnsiChar; passlen: TIdC_INT; const salt: PByte; saltlen: TIdC_INT; iter: TIdC_INT; keylen: TIdC_INT; out_: PByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS5_PBKDF2_HMAC}
  PKCS5_PBKDF2_HMAC: function (const pass: PIdAnsiChar; passlen: TIdC_INT; const salt: PByte; saltlen: TIdC_INT; iter: TIdC_INT; const digest: PEVP_MD; keylen: TIdC_INT; out_: PByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS5_v2_PBE_keyivgen}
  PKCS5_v2_PBE_keyivgen: function (ctx: PEVP_CIPHER_CTX; const pass: PIdAnsiChar; passlen: TIdC_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md: PEVP_MD; en_de: TIdC_INT): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EVP_PBE_scrypt}
  EVP_PBE_scrypt: function (const pass: PIdAnsiChar; passlen: TIdC_SIZET; const salt: PByte; saltlen: TIdC_SIZET; N: TIdC_UINT64; r: TIdC_UINT64; p: TIdC_UINT64; maxmem: TIdC_UINT64; key: PByte; keylen: TIdC_SIZET): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM PKCS5_v2_scrypt_keyivgen}
  PKCS5_v2_scrypt_keyivgen: function (ctx: PEVP_CIPHER_CTX; const pass: PIdAnsiChar; passlen: TIdC_INT; param: PASN1_TYPE; const c: PEVP_CIPHER; const md: PEVP_MD; en_de: TIdC_INT): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM PKCS5_PBE_add}
  PKCS5_PBE_add: procedure ; cdecl = nil;

  {$EXTERNALSYM EVP_PBE_CipherInit}
  EVP_PBE_CipherInit: function (pbe_obj: PASN1_OBJECT; const pass: PIdAnsiChar; passlen: TIdC_INT; param: PASN1_TYPE; ctx: PEVP_CIPHER_CTX; en_de: TIdC_INT): TIdC_INT; cdecl = nil;

  (* PBE type *)
  {$EXTERNALSYM EVP_PBE_alg_add_type}
  EVP_PBE_alg_add_type: function (pbe_type: TIdC_INT; pbe_nid: TIdC_INT; cipher_nid: TIdC_INT; md_nid: TIdC_INT; keygen: PEVP_PBE_KEYGEN): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PBE_alg_add}
  EVP_PBE_alg_add: function (nid: TIdC_INT; const cipher: PEVP_CIPHER; const md: PEVP_MD; keygen: PEVP_PBE_KEYGEN): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PBE_find}
  EVP_PBE_find: function (type_: TIdC_INT; pbe_nid: TIdC_INT; pcnid: PIdC_INT; pmnid: PIdC_INT; pkeygen: PPEVP_PBE_KEYGEN): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PBE_cleanup}
  EVP_PBE_cleanup: procedure ; cdecl = nil;
  {$EXTERNALSYM EVP_PBE_get}
  EVP_PBE_get: function (ptype: PIdC_INT; ppbe_nid: PIdC_INT; num: TIdC_SIZET): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_asn1_get_count}
  EVP_PKEY_asn1_get_count: function : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_asn1_get0}
  EVP_PKEY_asn1_get0: function (idx: TIdC_INT): PEVP_PKEY_ASN1_METHOD; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_asn1_find}
  EVP_PKEY_asn1_find: function (pe: PPENGINE; type_: TIdC_INT): PEVP_PKEY_ASN1_METHOD; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_asn1_find_str}
  EVP_PKEY_asn1_find_str: function (pe: PPENGINE; const _str: PIdAnsiChar; len: TIdC_INT): PEVP_PKEY_ASN1_METHOD; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_asn1_add0}
  EVP_PKEY_asn1_add0: function (const ameth: PEVP_PKEY_ASN1_METHOD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_asn1_add_alias}
  EVP_PKEY_asn1_add_alias: function (to_: TIdC_INT; from: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_asn1_get0_info}
  EVP_PKEY_asn1_get0_info: function (ppkey_id: PIdC_INT; pkey_base_id: PIdC_INT; ppkey_flags: PIdC_INT; const pinfo: PPIdAnsiChar; const ppem_str: PPIdAnsiChar; const ameth: PEVP_PKEY_ASN1_METHOD): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EVP_PKEY_get0_asn1}
  EVP_PKEY_get0_asn1: function (const pkey: PEVP_PKEY): PEVP_PKEY_ASN1_METHOD; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_asn1_new}
  EVP_PKEY_asn1_new: function (id: TIdC_INT; flags: TIdC_INT; const pem_str: PIdAnsiChar; const info: PIdAnsiChar): PEVP_PKEY_ASN1_METHOD; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_asn1_copy}
  EVP_PKEY_asn1_copy: procedure (dst: PEVP_PKEY_ASN1_METHOD; const src: PEVP_PKEY_ASN1_METHOD); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_asn1_free}
  EVP_PKEY_asn1_free: procedure (ameth: PEVP_PKEY_ASN1_METHOD); cdecl = nil;

  {$EXTERNALSYM EVP_PKEY_asn1_set_public}
  EVP_PKEY_asn1_set_public: procedure (ameth: PEVP_PKEY_ASN1_METHOD; APub_decode: pub_decode; APub_encode: pub_encode; APub_cmd: pub_cmd; APub_print: pub_print; APkey_size: pkey_size; APkey_bits: pkey_bits); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_asn1_set_private}
  EVP_PKEY_asn1_set_private: procedure (ameth: PEVP_PKEY_ASN1_METHOD; APriv_decode: priv_decode; APriv_encode: priv_encode; APriv_print: priv_print); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_asn1_set_param}
  EVP_PKEY_asn1_set_param: procedure (ameth: PEVP_PKEY_ASN1_METHOD; AParam_decode: param_decode; AParam_encode: param_encode; AParam_missing: param_missing; AParam_copy: param_copy; AParam_cmp: param_cmp; AParam_print: param_print); cdecl = nil;

  {$EXTERNALSYM EVP_PKEY_asn1_set_free}
  EVP_PKEY_asn1_set_free: procedure (ameth: PEVP_PKEY_ASN1_METHOD; APkey_free: pkey_free); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_asn1_set_ctrl}
  EVP_PKEY_asn1_set_ctrl: procedure (ameth: PEVP_PKEY_ASN1_METHOD; APkey_ctrl: pkey_ctrl); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_asn1_set_item}
  EVP_PKEY_asn1_set_item: procedure (ameth: PEVP_PKEY_ASN1_METHOD; AItem_verify: item_verify; AItem_sign: item_sign); cdecl = nil;

  {$EXTERNALSYM EVP_PKEY_asn1_set_siginf}
  EVP_PKEY_asn1_set_siginf: procedure (ameth: PEVP_PKEY_ASN1_METHOD; ASiginf_set: siginf_set); cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_asn1_set_check}
  EVP_PKEY_asn1_set_check: procedure (ameth: PEVP_PKEY_ASN1_METHOD; APkey_check: pkey_check); cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_asn1_set_public_check}
  EVP_PKEY_asn1_set_public_check: procedure (ameth: PEVP_PKEY_ASN1_METHOD; APkey_pub_check: pkey_pub_check); cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_asn1_set_param_check}
  EVP_PKEY_asn1_set_param_check: procedure (ameth: PEVP_PKEY_ASN1_METHOD; APkey_param_check: pkey_param_check); cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_asn1_set_set_priv_key}
  EVP_PKEY_asn1_set_set_priv_key: procedure (ameth: PEVP_PKEY_ASN1_METHOD; ASet_priv_key: set_priv_key); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_asn1_set_set_pub_key}
  EVP_PKEY_asn1_set_set_pub_key: procedure (ameth: PEVP_PKEY_ASN1_METHOD; ASet_pub_key: set_pub_key); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_asn1_set_get_priv_key}
  EVP_PKEY_asn1_set_get_priv_key: procedure (ameth: PEVP_PKEY_ASN1_METHOD; AGet_priv_key: get_priv_key); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_asn1_set_get_pub_key}
  EVP_PKEY_asn1_set_get_pub_key: procedure (ameth: PEVP_PKEY_ASN1_METHOD; AGet_pub_key: get_pub_key); cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_asn1_set_security_bits}
  EVP_PKEY_asn1_set_security_bits: procedure (ameth: PEVP_PKEY_ASN1_METHOD; APkey_security_bits: pkey_security_bits); cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_meth_find}
  EVP_PKEY_meth_find: function (type_: TIdC_INT): PEVP_PKEY_METHOD; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_new}
  EVP_PKEY_meth_new: function (id: TIdC_INT; flags: TIdC_INT): PEVP_PKEY_METHOD; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_get0_info}
  EVP_PKEY_meth_get0_info: procedure (ppkey_id: PIdC_INT; pflags: PIdC_INT; const meth: PEVP_PKEY_METHOD); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_copy}
  EVP_PKEY_meth_copy: procedure (dst: PEVP_PKEY_METHOD; const src: PEVP_PKEY_METHOD); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_free}
  EVP_PKEY_meth_free: procedure (pmeth: PEVP_PKEY_METHOD); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_add0}
  EVP_PKEY_meth_add0: function (const pmeth: PEVP_PKEY_METHOD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_remove}
  EVP_PKEY_meth_remove: function (const pmeth: PEVP_PKEY_METHOD): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_meth_get_count}
  EVP_PKEY_meth_get_count: function : TIdC_SIZET; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_meth_get0}
  EVP_PKEY_meth_get0: function (idx: TIdC_SIZET): PEVP_PKEY_METHOD; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_CTX_new}
  EVP_PKEY_CTX_new: function (pkey: PEVP_PKEY; e: PENGINE): PEVP_PKEY_CTX; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_new_id}
  EVP_PKEY_CTX_new_id: function (id: TIdC_INT; e: PENGINE): PEVP_PKEY_CTX; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_dup}
  EVP_PKEY_CTX_dup: function (ctx: PEVP_PKEY_CTX): PEVP_PKEY_CTX; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_free}
  EVP_PKEY_CTX_free: procedure (ctx: PEVP_PKEY_CTX); cdecl = nil;

  {$EXTERNALSYM EVP_PKEY_CTX_ctrl}
  EVP_PKEY_CTX_ctrl: function (ctx: PEVP_PKEY_CTX; keytype: TIdC_INT; optype: TIdC_INT; cmd: TIdC_INT; p1: TIdC_INT; p2: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_ctrl_str}
  EVP_PKEY_CTX_ctrl_str: function (ctx: PEVP_PKEY_CTX; const type_: PIdAnsiChar; const value: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_ctrl_uint64}
  EVP_PKEY_CTX_ctrl_uint64: function (ctx: PEVP_PKEY_CTX; keytype: TIdC_INT; optype: TIdC_INT; cmd: TIdC_INT; value: TIdC_UINT64): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_CTX_str2ctrl}
  EVP_PKEY_CTX_str2ctrl: function (ctx: PEVP_PKEY_CTX; cmd: TIdC_INT; const _str: PIdAnsiChar): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_CTX_hex2ctrl}
  EVP_PKEY_CTX_hex2ctrl: function (ctx: PEVP_PKEY_CTX; cmd: TIdC_INT; const hex: PIdAnsiChar): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_CTX_md}
  EVP_PKEY_CTX_md: function (ctx: PEVP_PKEY_CTX; optype: TIdC_INT; cmd: TIdC_INT; const md: PIdAnsiChar): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_CTX_get_operation}
  EVP_PKEY_CTX_get_operation: function (ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set0_keygen_info}
  EVP_PKEY_CTX_set0_keygen_info: procedure (ctx: PEVP_PKEY_CTX; dat: PIdC_INT; datlen: TIdC_INT); cdecl = nil;

  {$EXTERNALSYM EVP_PKEY_new_mac_key}
  EVP_PKEY_new_mac_key: function (type_: TIdC_INT; e: PENGINE; const key: PByte; keylen: TIdC_INT): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_new_raw_private_key}
  EVP_PKEY_new_raw_private_key: function (type_: TIdC_INT; e: PENGINE; const priv: PByte; len: TIdC_SIZET): PEVP_PKEY; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_new_raw_public_key}
  EVP_PKEY_new_raw_public_key: function (type_: TIdC_INT; e: PENGINE; const pub: PByte; len: TIdC_SIZET): PEVP_PKEY; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_get_raw_private_key}
  EVP_PKEY_get_raw_private_key: function (const pkey: PEVP_PKEY; priv: PByte; len: PIdC_SIZET): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_get_raw_public_key}
  EVP_PKEY_get_raw_public_key: function (const pkey: PEVP_PKEY; pub: PByte; len: PIdC_SIZET): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_new_CMAC_key}
  EVP_PKEY_new_CMAC_key: function (e: PENGINE; const priv: PByte; len: TIdC_SIZET; const cipher: PEVP_CIPHER): PEVP_PKEY; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_CTX_set_data}
  EVP_PKEY_CTX_set_data: procedure (ctx: PEVP_PKEY_CTX; data: Pointer); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_get_data}
  EVP_PKEY_CTX_get_data: function (ctx: PEVP_PKEY_CTX): Pointer; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_get0_pkey}
  EVP_PKEY_CTX_get0_pkey: function (ctx: PEVP_PKEY_CTX): PEVP_PKEY; cdecl = nil;

  {$EXTERNALSYM EVP_PKEY_CTX_get0_peerkey}
  EVP_PKEY_CTX_get0_peerkey: function (ctx: PEVP_PKEY_CTX): PEVP_PKEY; cdecl = nil;

  {$EXTERNALSYM EVP_PKEY_CTX_set_app_data}
  EVP_PKEY_CTX_set_app_data: procedure (ctx: PEVP_PKEY_CTX; data: Pointer); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_get_app_data}
  EVP_PKEY_CTX_get_app_data: function (ctx: PEVP_PKEY_CTX): Pointer; cdecl = nil;

  {$EXTERNALSYM EVP_PKEY_sign_init}
  EVP_PKEY_sign_init: function (ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_sign}
  EVP_PKEY_sign: function (ctx: PEVP_PKEY_CTX; sig: PByte; siglen: PIdC_SIZET; const tbs: PByte; tbslen: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_verify_init}
  EVP_PKEY_verify_init: function (ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_verify}
  EVP_PKEY_verify: function (ctx: PEVP_PKEY_CTX; const sig: PByte; siglen: TIdC_SIZET; const tbs: PByte; tbslen: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_verify_recover_init}
  EVP_PKEY_verify_recover_init: function (ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_verify_recover}
  EVP_PKEY_verify_recover: function (ctx: PEVP_PKEY_CTX; rout: PByte; var outlen: TIdC_SIZET; const sig: PByte; siglen: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_encrypt_init}
  EVP_PKEY_encrypt_init: function (ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_encrypt}
  EVP_PKEY_encrypt: function (ctx: PEVP_PKEY_CTX; var out_; var outlen: TIdC_SIZET; const in_; inlen: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_decrypt_init}
  EVP_PKEY_decrypt_init: function (ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_decrypt}
  EVP_PKEY_decrypt: function (ctx: PEVP_PKEY_CTX; var out_; var outlen: TIdC_SIZET; const in_; inlen: TIdC_SIZET): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EVP_PKEY_derive_init}
  EVP_PKEY_derive_init: function (ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_derive_set_peer}
  EVP_PKEY_derive_set_peer: function (ctx: PEVP_PKEY_CTX; peer: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_derive}
  EVP_PKEY_derive: function (ctx: PEVP_PKEY_CTX; key: PByte; keylen: PIdC_SIZET): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EVP_PKEY_paramgen_init}
  EVP_PKEY_paramgen_init: function (ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_paramgen}
  EVP_PKEY_paramgen: function (ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_keygen_init}
  EVP_PKEY_keygen_init: function (ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_keygen}
  EVP_PKEY_keygen: function (ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_check}
  EVP_PKEY_check: function (ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_public_check}
  EVP_PKEY_public_check: function (ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_param_check}
  EVP_PKEY_param_check: function (ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_CTX_set_cb}
  EVP_PKEY_CTX_set_cb: procedure (ctx: PEVP_PKEY_CTX; cb: EVP_PKEY_gen_cb); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_get_cb}
  EVP_PKEY_CTX_get_cb: function (ctx: PEVP_PKEY_CTX): EVP_PKEY_gen_cb; cdecl = nil;

  {$EXTERNALSYM EVP_PKEY_CTX_get_keygen_info}
  EVP_PKEY_CTX_get_keygen_info: function (ctx: PEVP_PKEY_CTX; idx: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_set_init}
  EVP_PKEY_meth_set_init: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_init: EVP_PKEY_meth_init); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_set_copy}
  EVP_PKEY_meth_set_copy: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_copy_cb: EVP_PKEY_meth_copy_cb); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_set_cleanup}
  EVP_PKEY_meth_set_cleanup: procedure (pmeth: PEVP_PKEY_METHOD; PEVP_PKEY_meth_cleanup: EVP_PKEY_meth_cleanup); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_set_paramgen}
  EVP_PKEY_meth_set_paramgen: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_paramgen_init: EVP_PKEY_meth_paramgen_init; AEVP_PKEY_meth_paramgen: EVP_PKEY_meth_paramgen_init); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_set_keygen}
  EVP_PKEY_meth_set_keygen: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_keygen_init: EVP_PKEY_meth_keygen_init; AEVP_PKEY_meth_keygen: EVP_PKEY_meth_keygen); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_set_sign}
  EVP_PKEY_meth_set_sign: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_sign_init: EVP_PKEY_meth_sign_init; AEVP_PKEY_meth_sign: EVP_PKEY_meth_sign); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_set_verify}
  EVP_PKEY_meth_set_verify: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_init: EVP_PKEY_meth_verify_init; AEVP_PKEY_meth_verify: EVP_PKEY_meth_verify_init); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_set_verify_recover}
  EVP_PKEY_meth_set_verify_recover: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_recover_init: EVP_PKEY_meth_verify_recover_init; AEVP_PKEY_meth_verify_recover: EVP_PKEY_meth_verify_recover_init); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_set_signctx}
  EVP_PKEY_meth_set_signctx: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_signctx_init: EVP_PKEY_meth_signctx_init; AEVP_PKEY_meth_signctx: EVP_PKEY_meth_signctx); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_set_verifyctx}
  EVP_PKEY_meth_set_verifyctx: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verifyctx_init: EVP_PKEY_meth_verifyctx_init; AEVP_PKEY_meth_verifyctx: EVP_PKEY_meth_verifyctx); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_set_encrypt}
  EVP_PKEY_meth_set_encrypt: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_encrypt_init: EVP_PKEY_meth_encrypt_init; AEVP_PKEY_meth_encrypt: EVP_PKEY_meth_encrypt); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_set_decrypt}
  EVP_PKEY_meth_set_decrypt: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_decrypt_init: EVP_PKEY_meth_decrypt_init; AEVP_PKEY_meth_decrypt: EVP_PKEY_meth_decrypt); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_set_derive}
  EVP_PKEY_meth_set_derive: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_derive_init: EVP_PKEY_meth_derive_init; AEVP_PKEY_meth_derive: EVP_PKEY_meth_derive); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_set_ctrl}
  EVP_PKEY_meth_set_ctrl: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_ctrl: EVP_PKEY_meth_ctrl; AEVP_PKEY_meth_ctrl_str: EVP_PKEY_meth_ctrl_str); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_set_digestsign}
  EVP_PKEY_meth_set_digestsign: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestsign: EVP_PKEY_meth_digestsign); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_meth_set_digestverify}
  EVP_PKEY_meth_set_digestverify: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestverify: EVP_PKEY_meth_digestverify); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_meth_set_check}
  EVP_PKEY_meth_set_check: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_check: EVP_PKEY_meth_check); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_meth_set_public_check}
  EVP_PKEY_meth_set_public_check: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_public_check: EVP_PKEY_meth_public_check); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_meth_set_param_check}
  EVP_PKEY_meth_set_param_check: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_param_check: EVP_PKEY_meth_param_check); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_meth_set_digest_custom}
  EVP_PKEY_meth_set_digest_custom: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digest_custom: EVP_PKEY_meth_digest_custom); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_meth_get_init}
  EVP_PKEY_meth_get_init: procedure (const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_init: PEVP_PKEY_meth_init); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_get_copy}
  EVP_PKEY_meth_get_copy: procedure (const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth__copy: PEVP_PKEY_meth_copy); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_get_cleanup}
  EVP_PKEY_meth_get_cleanup: procedure (const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_cleanup: PEVP_PKEY_meth_cleanup); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_get_paramgen}
  EVP_PKEY_meth_get_paramgen: procedure (const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_paramgen_init: EVP_PKEY_meth_paramgen_init; AEVP_PKEY_meth_paramgen: PEVP_PKEY_meth_paramgen); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_get_keygen}
  EVP_PKEY_meth_get_keygen: procedure (const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_keygen_init: EVP_PKEY_meth_keygen_init; AEVP_PKEY_meth_keygen: PEVP_PKEY_meth_keygen); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_get_sign}
  EVP_PKEY_meth_get_sign: procedure (const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_sign_init: PEVP_PKEY_meth_sign_init; AEVP_PKEY_meth_sign: PEVP_PKEY_meth_sign); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_get_verify}
  EVP_PKEY_meth_get_verify: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_init: PEVP_PKEY_meth_verify_init; AEVP_PKEY_meth_verify: PEVP_PKEY_meth_verify_init); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_get_verify_recover}
  EVP_PKEY_meth_get_verify_recover: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_recover_init: PEVP_PKEY_meth_verify_recover_init; AEVP_PKEY_meth_verify_recover: PEVP_PKEY_meth_verify_recover_init); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_get_signctx}
  EVP_PKEY_meth_get_signctx: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_signctx_init: PEVP_PKEY_meth_signctx_init; AEVP_PKEY_meth_signctx: PEVP_PKEY_meth_signctx); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_get_verifyctx}
  EVP_PKEY_meth_get_verifyctx: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verifyctx_init: PEVP_PKEY_meth_verifyctx_init; AEVP_PKEY_meth_verifyctx: PEVP_PKEY_meth_verifyctx); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_get_encrypt}
  EVP_PKEY_meth_get_encrypt: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_encrypt_init: PEVP_PKEY_meth_encrypt_init; AEVP_PKEY_meth_encrypt: PEVP_PKEY_meth_encrypt); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_get_decrypt}
  EVP_PKEY_meth_get_decrypt: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_decrypt_init: PEVP_PKEY_meth_decrypt_init; AEVP_PKEY_meth_decrypt: PEVP_PKEY_meth_decrypt); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_get_derive}
  EVP_PKEY_meth_get_derive: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_derive_init: PEVP_PKEY_meth_derive_init; AEVP_PKEY_meth_derive: PEVP_PKEY_meth_derive); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_get_ctrl}
  EVP_PKEY_meth_get_ctrl: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_ctrl: PEVP_PKEY_meth_ctrl; AEVP_PKEY_meth_ctrl_str: PEVP_PKEY_meth_ctrl_str); cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_meth_get_digestsign}
  EVP_PKEY_meth_get_digestsign: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestsign: PEVP_PKEY_meth_digestsign); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_meth_get_digestverify}
  EVP_PKEY_meth_get_digestverify: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestverify: PEVP_PKEY_meth_digestverify); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_meth_get_check}
  EVP_PKEY_meth_get_check: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_check: PEVP_PKEY_meth_check); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_meth_get_public_check}
  EVP_PKEY_meth_get_public_check: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_public_check: PEVP_PKEY_meth_public_check); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_meth_get_param_check}
  EVP_PKEY_meth_get_param_check: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_param_check: PEVP_PKEY_meth_param_check); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_meth_get_digest_custom}
  EVP_PKEY_meth_get_digest_custom: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digest_custom: PEVP_PKEY_meth_digest_custom); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EVP_add_alg_module}
  EVP_add_alg_module: procedure ; cdecl = nil;
  {$EXTERNALSYM OpenSSL_add_all_ciphers}
  OpenSSL_add_all_ciphers: procedure ; cdecl = nil; {removed 1.1.0}
  {$EXTERNALSYM OpenSSL_add_all_digests}
  OpenSSL_add_all_digests: procedure ; cdecl = nil; {removed 1.1.0}
  {$EXTERNALSYM EVP_cleanup}
  EVP_cleanup: procedure ; cdecl = nil; {removed 1.1.0}
  //* MAC stuff */
  {$EXTERNALSYM EVP_MAC_fetch}
  EVP_MAC_fetch : function(libctx : POSSL_LIB_CTX;
    const algorithm, properties : PIdAnsiChar) : PEVP_MAC; cdecl = nil;
  {$EXTERNALSYM EVP_MAC_up_ref}
  EVP_MAC_up_ref : function(mac : PEVP_MAC) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_MAC_free}
  EVP_MAC_free : procedure(mac : PEVP_MAC); cdecl = nil;
  {$EXTERNALSYM EVP_MAC_is_a}
  EVP_MAC_is_a : function(const mac : PEVP_MAC; const name : PIdAnsiChar) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_MAC_get0_name}
  EVP_MAC_get0_name : function(const mac : PEVP_MAC) : PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM EVP_MAC_names_do_all}
  EVP_MAC_names_do_all : function(const mac : PEVP_MAC; fn : EVP_MAC_names_do_all_fn;
                         data : Pointer) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_MAC_get0_description}
  EVP_MAC_get0_description : function(const mac : PEVP_MAC) : PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM EVP_MAC_get0_provider}
  EVP_MAC_get0_provider : function(const mac :PEVP_MAC) : POSSL_PROVIDER; cdecl = nil;

  {$EXTERNALSYM EVP_MAC_get_params}
  EVP_MAC_get_params : function(mac : PEVP_MAC; params : POSSL_PARAM_ARRAY) : TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EVP_MAC_CTX_new}
  EVP_MAC_CTX_new : function (mac : PEVP_MAC) : PEVP_MAC_CTX; cdecl = nil; {introduced 3.0.0}
  {$EXTERNALSYM EVP_MAC_CTX_free}
  EVP_MAC_CTX_free : procedure (ctx : PEVP_MAC_CTX ); cdecl = nil;  {introduced 3.0.0}

  {$EXTERNALSYM EVP_MAC_CTX_dup}
  EVP_MAC_CTX_dup : function(const  src : PEVP_MAC_CTX) : PEVP_MAC_CTX; cdecl = nil;
  {$EXTERNALSYM EVP_MAC_CTX_get0_mac}
  EVP_MAC_CTX_get0_mac : function(ctx : PEVP_MAC_CTX) : PEVP_MAC; cdecl = nil;
  {$EXTERNALSYM EVP_MAC_CTX_get_params}
  EVP_MAC_CTX_get_params : function(ctx : PEVP_MAC_CTX; params : POSSL_PARAM_ARRAY) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_MAC_CTX_set_params}
  EVP_MAC_CTX_set_params : function(ctx : PEVP_MAC_CTX; const  params : POSSL_PARAM_ARRAY) : TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EVP_MAC_CTX_get_mac_size}
  EVP_MAC_CTX_get_mac_size : function (ctx : PEVP_MAC_CTX) : TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM EVP_MAC_CTX_get_block_size}
  EVP_MAC_CTX_get_block_size : function (ctx : PEVP_MAC_CTX) : TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM EVP_Q_mac}
  EVP_Q_mac : function(libctx : POSSL_LIB_CTX; const name, propq, subalg : PIdAnsiChar;
    const params : POSSL_PARAM; const key : Pointer; keylen : TIdC_SIZET;
    const data : PIdAnsiChar; datalen : TIdC_SIZET; _out : PIdAnsiChar;
    outsize : TIdC_SIZET;  var outlen : TIdC_SIZET) : PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM EVP_MAC_init}
  EVP_MAC_init: function(ctx : PEVP_MAC_CTX; const key : PIdAnsiChar; keylen : TIdC_SIZET;
     const  params : POSSL_PARAM_ARRAY) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_MAC_init_SKEY}
  EVP_MAC_init_SKEY : function(ctx : PEVP_MAC_CTX;  skey : PEVP_SKEY; const  params : POSSL_PARAM_ARRAY) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_MAC_update}
  EVP_MAC_update : function(ctx : PEVP_MAC_CTX; const data : PIdAnsiChar;
    datalen : TIdC_SIZET) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_MAC_final}
  EVP_MAC_final : function(ctx : PEVP_MAC_CTX;
    _out : PIdAnsiChar; var outl : TIdC_SIZET; outsize : TIdC_SIZET) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_MAC_finalXOF}
  EVP_MAC_finalXOF : function(ctx : PEVP_MAC_CTX; _out : PIdAnsiChar; outsize : TIdC_SIZET) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_MAC_do_all_provided}
  EVP_MAC_do_all_provided : procedure(libctx : POSSL_LIB_CTX;
                             fn : EVP_MAC_do_all_provided_fn;
                             arg : Pointer);  cdecl = nil;
{$ELSE}

  {$EXTERNALSYM EVP_MD_meth_new}
  function EVP_MD_meth_new(md_type: TIdC_INT; pkey_type: TIdC_INT): PEVP_MD cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_dup}
  function EVP_MD_meth_dup(const md: PEVP_MD): PEVP_MD cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_free}
  procedure EVP_MD_meth_free(md: PEVP_MD) cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_MD_meth_set_input_blocksize}
  function EVP_MD_meth_set_input_blocksize(md: PEVP_MD; blocksize: TIdC_INT): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_set_result_size}
  function EVP_MD_meth_set_result_size(md: PEVP_MD; resultsize: TIdC_INT): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_set_app_datasize}
  function EVP_MD_meth_set_app_datasize(md: PEVP_MD; datasize: TIdC_INT): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_set_flags}
  function EVP_MD_meth_set_flags(md: PEVP_MD; flags: TIdC_ULONG): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_set_init}
  function EVP_MD_meth_set_init(md: PEVP_MD; init: EVP_MD_meth_init): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_set_update}
  function EVP_MD_meth_set_update(md: PEVP_MD; update: EVP_MD_meth_update): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_set_final}
  function EVP_MD_meth_set_final(md: PEVP_MD; final_: EVP_MD_meth_final): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_set_copy}
  function EVP_MD_meth_set_copy(md: PEVP_MD; _copy: EVP_MD_meth_copy): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_set_cleanup}
  function EVP_MD_meth_set_cleanup(md: PEVP_MD; cleanup: EVP_MD_meth_cleanup): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_set_ctrl}
  function EVP_MD_meth_set_ctrl(md: PEVP_MD; ctrl: EVP_MD_meth_ctrl): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_MD_meth_get_input_blocksize}
  function EVP_MD_meth_get_input_blocksize(const md: PEVP_MD): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_get_result_size}
  function EVP_MD_meth_get_result_size(const md: PEVP_MD): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_get_app_datasize}
  function EVP_MD_meth_get_app_datasize(const md: PEVP_MD): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_get_flags}
  function EVP_MD_meth_get_flags(const md: PEVP_MD): TIdC_ULONG cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_get_init}
  function EVP_MD_meth_get_init(const md: PEVP_MD): EVP_MD_meth_init cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_get_update}
  function EVP_MD_meth_get_update(const md: PEVP_MD): EVP_MD_meth_update cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_get_final}
  function EVP_MD_meth_get_final(const md: PEVP_MD): EVP_MD_meth_final cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_get_copy}
  function EVP_MD_meth_get_copy(const md: PEVP_MD): EVP_MD_meth_copy cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_get_cleanup}
  function EVP_MD_meth_get_cleanup(const md: PEVP_MD): EVP_MD_meth_cleanup cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_meth_get_ctrl}
  function EVP_MD_meth_get_ctrl(const md: PEVP_MD): EVP_MD_meth_ctrl cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_CIPHER_meth_new}
  function EVP_CIPHER_meth_new(cipher_type: TIdC_INT; block_size: TIdC_INT; key_len: TIdC_INT): PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_dup}
  function EVP_CIPHER_meth_dup(const cipher: PEVP_CIPHER): PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_free}
  procedure EVP_CIPHER_meth_free(cipher: PEVP_CIPHER) cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_CIPHER_meth_set_iv_length}
  function EVP_CIPHER_meth_set_iv_length(cipher: PEVP_CIPHER; iv_len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_set_flags}
  function EVP_CIPHER_meth_set_flags(cipher: PEVP_CIPHER; flags: TIdC_ULONG): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_set_impl_ctx_size}
  function EVP_CIPHER_meth_set_impl_ctx_size(cipher: PEVP_CIPHER; ctx_size: TIdC_INT): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_set_init}
  function EVP_CIPHER_meth_set_init(cipher: PEVP_CIPHER; init: EVP_CIPHER_meth_init): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_set_do_cipher}
  function EVP_CIPHER_meth_set_do_cipher(cipher: PEVP_CIPHER; do_cipher: EVP_CIPHER_meth_do_cipher): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_set_cleanup}
  function EVP_CIPHER_meth_set_cleanup(cipher: PEVP_CIPHER; cleanup: EVP_CIPHER_meth_cleanup): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_set_set_asn1_params}
  function EVP_CIPHER_meth_set_set_asn1_params(cipher: PEVP_CIPHER; set_asn1_parameters: EVP_CIPHER_meth_set_asn1_params): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_set_get_asn1_params}
  function EVP_CIPHER_meth_set_get_asn1_params(cipher: PEVP_CIPHER; get_asn1_parameters: EVP_CIPHER_meth_get_asn1_params): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_set_ctrl}
  function EVP_CIPHER_meth_set_ctrl(cipher: PEVP_CIPHER; ctrl: EVP_CIPHER_meth_ctrl): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_get_init}
  function EVP_CIPHER_meth_get_init(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_init cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_get_do_cipher}
  function EVP_CIPHER_meth_get_do_cipher(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_do_cipher cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_get_cleanup}
  function EVP_CIPHER_meth_get_cleanup(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_cleanup cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_get_set_asn1_params}
  function EVP_CIPHER_meth_get_set_asn1_params(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_set_asn1_params cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_get_get_asn1_params}
  function EVP_CIPHER_meth_get_get_asn1_params(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_get_asn1_params cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_meth_get_ctrl}
  function EVP_CIPHER_meth_get_ctrl(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_ctrl cdecl; external CLibCrypto; {introduced 1.1.0}

  /// Add some extra combinations ///
  //# define EVP_get_digestbynid(a) EVP_get_digestbyname(OBJ_nid2sn(a));
  //# define EVP_get_digestbyobj(a) EVP_get_digestbynid(OBJ_obj2nid(a));
  //# define EVP_get_cipherbynid(a) EVP_get_cipherbyname(OBJ_nid2sn(a));
  //# define EVP_get_cipherbyobj(a) EVP_get_cipherbynid(OBJ_obj2nid(a));

  //# define EVP_MD_nid(e)                   EVP_MD_type(e)
  //# define EVP_MD_name(e)                  OBJ_nid2sn(EVP_MD_nid(e))

  {$EXTERNALSYM EVP_MD_CTX_md}
  function EVP_MD_CTX_md(ctx: PEVP_MD_CTX): PEVP_MD cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_MD_CTX_update_fn}
  function EVP_MD_CTX_update_fn(ctx: PEVP_MD_CTX): EVP_MD_CTX_update cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_CTX_set_update_fn}
  procedure EVP_MD_CTX_set_update_fn(ctx: PEVP_MD_CTX; update: EVP_MD_CTX_update) cdecl; external CLibCrypto; {introduced 1.1.0}
  //  EVP_MD_CTX_size(e)              EVP_MD_size(EVP_MD_CTX_md(e))
  //  EVP_MD_CTX_block_size(e)        EVP_MD_block_size(EVP_MD_CTX_md(e))
  //  EVP_MD_CTX_type(e)              EVP_MD_type(EVP_MD_CTX_md(e))
  {$EXTERNALSYM EVP_MD_CTX_set_pkey_ctx}
  procedure EVP_MD_CTX_set_pkey_ctx(ctx: PEVP_MD_CTX; pctx: PEVP_PKEY_CTX) cdecl; external CLibCrypto; {introduced 1.1.0}

  //# define EVP_CIPHER_name(e)              OBJ_nid2sn(EVP_CIPHER_nid(e))
  {$EXTERNALSYM EVP_CIPHER_get_nid}
  function EVP_CIPHER_get_nid(const cipher : PEVP_CIPHER) : TIdC_INT cdecl; external CLibCrypto; {introduced 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_get0_name}
  function EVP_CIPHER_get0_name(const cipher : PEVP_CIPHER) : PIdAnsiChar cdecl; external CLibCrypto; {introduced 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_impl_ctx_size}
  function EVP_CIPHER_impl_ctx_size(const cipher: PEVP_CIPHER): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  //# define EVP_CIPHER_mode(e)              (EVP_CIPHER_flags(e) & EVP_CIPH_MODE)

  {$EXTERNALSYM EVP_CIPHER_get_flags}
  function EVP_CIPHER_get_flags(const cipher: PEVP_CIPHER): TIdC_ULONG; cdecl; external CLibCrypto; {introduced 3.0.0}


  {$EXTERNALSYM EVP_CIPHER_CTX_cipher}
  function EVP_CIPHER_CTX_cipher(const ctx: PEVP_CIPHER_CTX): PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_CIPHER_CTX_get0_cipher}
  function EVP_CIPHER_CTX_get0_cipher(const ctx: PEVP_CIPHER_CTX): PEVP_CIPHER cdecl; external CLibCrypto; {introduced 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_get_type}
  function EVP_CIPHER_get_type(const cipher: PEVP_CIPHER): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_CIPHER_CTX_iv}
  function EVP_CIPHER_CTX_iv(const ctx: PEVP_CIPHER_CTX): PByte cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_original_iv}
  function EVP_CIPHER_CTX_original_iv(const ctx: PEVP_CIPHER_CTX): PByte cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_iv_noconst}
  function EVP_CIPHER_CTX_iv_noconst(ctx: PEVP_CIPHER_CTX): PByte cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_buf_noconst}
  function EVP_CIPHER_CTX_buf_noconst(ctx: PEVP_CIPHER_CTX): PByte cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_set_num}
  procedure EVP_CIPHER_CTX_set_num(ctx: PEVP_CIPHER_CTX; num: TIdC_INT) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_copy}
  function EVP_CIPHER_CTX_copy(out_: PEVP_CIPHER_CTX; const in_: PEVP_CIPHER_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_CIPHER_CTX_get_app_data}
  function EVP_CIPHER_CTX_get_app_data(const ctx: PEVP_CIPHER_CTX): Pointer cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_CIPHER_CTX_set_app_data}
  procedure EVP_CIPHER_CTX_set_app_data(ctx: PEVP_CIPHER_CTX; data: Pointer) cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_CIPHER_CTX_get_cipher_data}
  function EVP_CIPHER_CTX_get_cipher_data(const ctx: PEVP_CIPHER_CTX): Pointer cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_set_cipher_data}
  function EVP_CIPHER_CTX_set_cipher_data(ctx: PEVP_CIPHER_CTX; cipher_data: Pointer): Pointer cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_get_tag_length}
  function EVP_CIPHER_CTX_get_tag_length(const ctx : PEVP_CIPHER_CTX) : TIdC_INT; cdecl; external CLibCrypto; {introduced 3.0.0}

  {$EXTERNALSYM EVP_CIPHER_CTX_is_encrypting}
  function EVP_CIPHER_CTX_is_encrypting(const ctx: PEVP_CIPHER_CTX): TIdC_INT cdecl; external CLibCrypto;  {introduced 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_get_block_size}
  function EVP_CIPHER_CTX_get_block_size(const ctx: PEVP_CIPHER_CTX): TIdC_INT  cdecl; external CLibCrypto; {introduced 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_get_key_length}
  function EVP_CIPHER_CTX_get_key_length(const ctx: PEVP_CIPHER_CTX): TIdC_INT  cdecl; external CLibCrypto; {introduced 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_get_iv_length}
  function EVP_CIPHER_CTX_get_iv_length(const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl; external CLibCrypto; {introduced 3.0.0}

  {$EXTERNALSYM EVP_CIPHER_get_iv_length}
  function EVP_CIPHER_get_iv_length(const cipher: PEVP_CIPHER): TIdC_INT cdecl; external CLibCrypto; {introduced 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_get_block_size}
  function EVP_CIPHER_get_block_size (const cipher: PEVP_CIPHER): TIdC_INT cdecl; external CLibCrypto; {introduced 3.0.0}
  //# define EVP_CIPHER_CTX_type(c)         EVP_CIPHER_type(EVP_CIPHER_CTX_cipher(c))

  //# if OPENSSL_API_COMPAT < 0x10100000L
  //#  define EVP_CIPHER_CTX_flags(c)       EVP_CIPHER_flags(EVP_CIPHER_CTX_cipher(c))
  //# endif
  //# define EVP_CIPHER_CTX_mode(c)         EVP_CIPHER_mode(EVP_CIPHER_CTX_cipher(c))
  //
  //# define EVP_ENCODE_LENGTH(l)    ((((l)+2)/3*4)+((l)/48+1)*2+80)
  //# define EVP_DECODE_LENGTH(l)    (((l)+3)/4*3+80)
  //
  //# define EVP_SignInit_ex(a;b;c)          EVP_DigestInit_ex(a;b;c)
  //# define EVP_SignInit(a;b)               EVP_DigestInit(a;b)
  //# define EVP_SignUpdate(a;b;c)           EVP_DigestUpdate(a;b;c)
  //# define EVP_VerifyInit_ex(a;b;c)        EVP_DigestInit_ex(a;b;c)
  //# define EVP_VerifyInit(a;b)             EVP_DigestInit(a;b)
  //# define EVP_VerifyUpdate(a;b;c)         EVP_DigestUpdate(a;b;c)
  //# define EVP_OpenUpdate(a;b;c;d;e)       EVP_DecryptUpdate(a;b;c;d;e)
  //# define EVP_SealUpdate(a;b;c;d;e)       EVP_EncryptUpdate(a;b;c;d;e)
  //# define EVP_DigestSignUpdate(a;b;c)     EVP_DigestUpdate(a;b;c)
  //# define EVP_DigestVerifyUpdate(a;b;c)   EVP_DigestUpdate(a;b;c)

  //# define BIO_get_md(b;mdp)          BIO_ctrl(b;BIO_C_GET_MD;0;(PIdAnsiChar)(mdp))
  //# define BIO_get_md_ctx(b;mdcp)     BIO_ctrl(b;BIO_C_GET_MD_CTX;0; (PIdAnsiChar)(mdcp))
  //# define BIO_set_md_ctx(b;mdcp)     BIO_ctrl(b;BIO_C_SET_MD_CTX;0; (PIdAnsiChar)(mdcp))
  //# define BIO_get_cipher_status(b)   BIO_ctrl(b;BIO_C_GET_CIPHER_STATUS;0;NULL)
  //# define BIO_get_cipher_ctx(b;c_pp) BIO_ctrl(b;BIO_C_GET_CIPHER_CTX;0; (PIdAnsiChar)(c_pp))

  //function EVP_Cipher(c: PEVP_CIPHER_CTX; var out_; const in_; in1: TIdC_UINT): TIdC_INT;

  //# define EVP_add_cipher_alias(n;alias) OBJ_NAME_add((alias);OBJ_NAME_TYPE_CIPHER_METH|OBJ_NAME_ALIAS;(n))
  //# define EVP_add_digest_alias(n;alias) OBJ_NAME_add((alias);OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS;(n))
  //# define EVP_delete_cipher_alias(alias) OBJ_NAME_remove(alias;OBJ_NAME_TYPE_CIPHER_METH|OBJ_NAME_ALIAS);
  //# define EVP_delete_digest_alias(alias) OBJ_NAME_remove(alias;OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS);

  //void EVP_MD_CTX_init(EVP_MD_CTX *ctx);
  //int EVP_MD_CTX_cleanup(EVP_MD_CTX *ctx);

  {$EXTERNALSYM EVP_MD_CTX_ctrl}
  function EVP_MD_CTX_ctrl(ctx: PEVP_MD_CTX; cmd: TIdC_INT; p1: TIdC_INT; p2: Pointer): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_CTX_new}
  function EVP_MD_CTX_new: PEVP_MD_CTX cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_CTX_reset}
  function EVP_MD_CTX_reset(ctx: PEVP_MD_CTX): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_MD_CTX_free}
  procedure EVP_MD_CTX_free(ctx: PEVP_MD_CTX) cdecl; external CLibCrypto; {introduced 1.1.0}
  //# define EVP_MD_CTX_create()     EVP_MD_CTX_new()
  //# define EVP_MD_CTX_init(ctx)    EVP_MD_CTX_reset((ctx))
  //# define EVP_MD_CTX_destroy(ctx) EVP_MD_CTX_free((ctx))
  {$EXTERNALSYM EVP_MD_CTX_copy_ex}
  function EVP_MD_CTX_copy_ex(out_: PEVP_MD_CTX; const in_: PEVP_MD_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_MD_CTX_set_flags}
  procedure EVP_MD_CTX_set_flags(ctx: PEVP_MD_CTX; flags: TIdC_INT) cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_MD_CTX_clear_flags}
  procedure EVP_MD_CTX_clear_flags(ctx: PEVP_MD_CTX; flags: TIdC_INT) cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_MD_CTX_test_flags}
  function EVP_MD_CTX_test_flags(const ctx: PEVP_MD_CTX; flags: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_DigestInit_ex}
  function EVP_DigestInit_ex(ctx: PEVP_MD_CTX; const type_: PEVP_MD; impl: PENGINE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_DigestUpdate}
  function EVP_DigestUpdate(ctx: PEVP_MD_CTX; const d: Pointer; cnt: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_DigestFinal_ex}
  function EVP_DigestFinal_ex(ctx: PEVP_MD_CTX; md: PByte; var s: TIdC_UINT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_Digest}
  function EVP_Digest(const data: Pointer; count: TIdC_SIZET; md: PByte; size: PIdC_UINT; const type_: PEVP_MD; impl: PENGINE): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_MD_CTX_copy}
  function EVP_MD_CTX_copy(out_: PEVP_MD_CTX; const in_: PEVP_MD_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_DigestInit}
  function EVP_DigestInit(ctx: PEVP_MD_CTX; const type_: PEVP_MD): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_DigestFinal}
  function EVP_DigestFinal(ctx: PEVP_MD_CTX; md: PByte; var s: TIdC_UINT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_DigestFinalXOF}
  function EVP_DigestFinalXOF(ctx: PEVP_MD_CTX; md: PByte; len: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_read_pw_string}
  function EVP_read_pw_string(buf: PIdAnsiChar; _length: TIdC_INT; const prompt: PIdAnsiChar; verify: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_read_pw_string_min}
  function EVP_read_pw_string_min(buf: PIdAnsiChar; minlen: TIdC_INT; maxlen: TIdC_INT; const prompt: PIdAnsiChar; verify: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_set_pw_prompt}
  procedure EVP_set_pw_prompt(const prompt: PIdAnsiChar) cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_get_pw_prompt}
  function EVP_get_pw_prompt: PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_BytesToKey}
  function EVP_BytesToKey(const type_: PEVP_CIPHER; const md: PEVP_MD; const salt: PByte; const data: PByte; data1: TIdC_INT; count: TIdC_INT; key: PByte; iv: PByte): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_CIPHER_CTX_set_flags}
  procedure EVP_CIPHER_CTX_set_flags(ctx: PEVP_CIPHER_CTX; flags: TIdC_INT) cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_CIPHER_CTX_clear_flags}
  procedure EVP_CIPHER_CTX_clear_flags(ctx: PEVP_CIPHER_CTX; flags: TIdC_INT) cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_CIPHER_CTX_test_flags}
  function EVP_CIPHER_CTX_test_flags(const ctx: PEVP_CIPHER_CTX; flags: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_EncryptInit}
  function EVP_EncryptInit(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; const key: PByte; const iv: PByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_EncryptInit_ex}
  function EVP_EncryptInit_ex(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_EncryptUpdate}
  function EVP_EncryptUpdate(ctx: PEVP_CIPHER_CTX; var out_; var out1: TIdC_INT; const in_; in_1: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_EncryptFinal_ex}
  function EVP_EncryptFinal_ex(ctx: PEVP_CIPHER_CTX; var out_; var out1: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_EncryptFinal}
  function EVP_EncryptFinal(ctx: PEVP_CIPHER_CTX; var out_; var out1: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_DecryptInit}
  function EVP_DecryptInit(ctx: PEVP_CIPHER_CTX; var out_; var out1: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_DecryptInit_ex}
  function EVP_DecryptInit_ex(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_DecryptUpdate}
  function EVP_DecryptUpdate(ctx: PEVP_CIPHER_CTX; var out_; var out1: TIdC_INT; const in_; in_1: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_DecryptFinal}
  function EVP_DecryptFinal(ctx: PEVP_CIPHER_CTX; var outm; var out1: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_DecryptFinal_ex}
  function EVP_DecryptFinal_ex(ctx: PEVP_MD_CTX; var outm; var out1: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_CipherInit}
  function EVP_CipherInit(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; const key: PByte; const iv: PByte; enc: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_CipherInit_ex}
  function EVP_CipherInit_ex(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte; enc: TidC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_CipherUpdate}
  function EVP_CipherUpdate(ctx: PEVP_CIPHER_CTX; var out_; var out1: TIdC_INT; const in_; in1: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_CipherFinal}
  function EVP_CipherFinal(ctx: PEVP_CIPHER_CTX; var outm; var out1: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_CipherFinal_ex}
  function EVP_CipherFinal_ex(ctx: PEVP_CIPHER_CTX; var outm; var out1: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_SignFinal}
  function EVP_SignFinal(ctx: PEVP_CIPHER_CTX; md: PByte; s: PIdC_UINT; pkey: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_DigestSign}
  function EVP_DigestSign(ctx: PEVP_CIPHER_CTX; sigret: PByte; siglen: PIdC_SIZET; const tbs: PByte; tbslen: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_VerifyFinal}
  function EVP_VerifyFinal(ctx: PEVP_MD_CTX; const sigbuf: PByte; siglen: TIdC_UINT; pkey: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_DigestVerify}
  function EVP_DigestVerify(ctx: PEVP_CIPHER_CTX; const sigret: PByte; siglen: TIdC_SIZET; const tbs: PByte; tbslen: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_DigestSignInit}
  function EVP_DigestSignInit(ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; const type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_DigestSignFinal}
  function EVP_DigestSignFinal(ctx: PEVP_MD_CTX; sigret: PByte; siglen: PIdC_SIZET): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_DigestVerifyInit}
  function EVP_DigestVerifyInit(ctx: PEVP_MD_CTX; ppctx: PPEVP_PKEY_CTX; const type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_DigestVerifyFinal}
  function EVP_DigestVerifyFinal(ctx: PEVP_MD_CTX; const sig: PByte; siglen: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_OpenInit}
  function EVP_OpenInit(ctx: PEVP_CIPHER_CTX; const type_: PEVP_CIPHER; const ek: PByte; ek1: TIdC_INT; const iv: PByte; priv: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_OpenFinal}
  function EVP_OpenFinal(ctx: PEVP_CIPHER_CTX; var out_; var out1: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_SealInit}
  function EVP_SealInit(ctx: PEVP_CIPHER_CTX; const type_: PEVP_CIPHER; ek: PPByte; ek1: PIdC_INT; iv: PByte; pubk: PPEVP_PKEY; npubk: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_SealFinal}
  function EVP_SealFinal(ctx: PEVP_CIPHER_CTX; var out_; var out1: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_ENCODE_CTX_new}
  function EVP_ENCODE_CTX_new: PEVP_ENCODE_CTX cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_ENCODE_CTX_free}
  procedure EVP_ENCODE_CTX_free(ctx: PEVP_ENCODE_CTX) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_ENCODE_CTX_copy}
  function EVP_ENCODE_CTX_copy(dctx: PEVP_ENCODE_CTX; sctx: PEVP_ENCODE_CTX): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_ENCODE_CTX_num}
  function EVP_ENCODE_CTX_num(ctx: PEVP_ENCODE_CTX): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_EncodeInit}
  procedure EVP_EncodeInit(ctx: PEVP_ENCODE_CTX) cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_EncodeUpdate}
  function EVP_EncodeUpdate(ctx: PEVP_ENCODE_CTX; var out_; var out1: TIdC_INT; const in_; in1: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_EncodeFinal}
  procedure EVP_EncodeFinal(ctx: PEVP_ENCODE_CTX; var out_; var out1: TIdC_INT) cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_EncodeBlock}
  function EVP_EncodeBlock(t: PByte; const f: PByte; n: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_DecodeInit}
  procedure EVP_DecodeInit(ctx: PEVP_ENCODE_CTX) cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_DecodeUpdate}
  function EVP_DecodeUpdate(ctx: PEVP_ENCODE_CTX; var out_; var out1: TIdC_INT; const in_; in1: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_DecodeFinal}
  function EVP_DecodeFinal(ctx: PEVP_ENCODE_CTX; var out_; var out1: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_DecodeBlock}
  function EVP_DecodeBlock(t: PByte; const f: PByte; n: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_CIPHER_fetch}
  function EVP_CIPHER_fetch(ctx: POSSL_LIB_CTX; const algorithm, properties: PIdAnsiChar): PEVP_CIPHER; cdecl; external CLibCrypto; {introduced 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_free}
  procedure EVP_CIPHER_free(cipher: PEVP_CIPHER); cdecl; external CLibCrypto; {introduced 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_new}
  function EVP_CIPHER_CTX_new: PEVP_CIPHER_CTX cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_CIPHER_CTX_reset}
  function EVP_CIPHER_CTX_reset(c: PEVP_CIPHER_CTX): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_CIPHER_CTX_free}
  procedure EVP_CIPHER_CTX_free(c: PEVP_CIPHER_CTX) cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_CIPHER_CTX_set_key_length}
  function EVP_CIPHER_CTX_set_key_length(x: PEVP_CIPHER_CTX; keylen: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_CIPHER_CTX_set_padding}
  function EVP_CIPHER_CTX_set_padding(c: PEVP_CIPHER_CTX; pad: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_CIPHER_CTX_ctrl}
  function EVP_CIPHER_CTX_ctrl(ctx: PEVP_CIPHER_CTX; type_: TIdC_INT; arg: TIdC_INT; _ptr: Pointer): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_CIPHER_CTX_rand_key}
  function EVP_CIPHER_CTX_rand_key(ctx: PEVP_CIPHER_CTX; key: PByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_CIPHER_CTX_get_nid}
  function EVP_CIPHER_CTX_get_nid(const ctx: PEVP_CIPHER_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_CIPHER_CTX_get_num}
  function EVP_CIPHER_CTX_get_num(const ctx: PEVP_CIPHER_CTX): TIdC_INT cdecl; external CLibCrypto; {introduced 3.0.0}


  {$EXTERNALSYM BIO_f_md}
  function BIO_f_md: PBIO_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM BIO_f_base64}
  function BIO_f_base64: PBIO_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM BIO_f_cipher}
  function BIO_f_cipher: PBIO_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM BIO_f_reliable}
  function BIO_f_reliable: PBIO_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM BIO_set_cipher}
  function BIO_set_cipher(b: PBIO; c: PEVP_CIPHER; const k: PByte; const i: PByte; enc: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_md_null}
  function EVP_md_null: PEVP_MD cdecl; external CLibCrypto;

  {$IFNDEF OPENSSL_NO_MD2}
  {$ENDIF}
  {$IFNDEF OPENSSL_NO_MD4}
  {$ENDIF}
  {$IFNDEF OPENSSL_NO_MD5}
  {$ENDIF}
  {$EXTERNALSYM EVP_md5_sha1}
  function EVP_md5_sha1: PEVP_MD cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_sha1}
  function EVP_sha1: PEVP_MD cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_sha224}
  function EVP_sha224: PEVP_MD cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_sha256}
  function EVP_sha256: PEVP_MD cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_sha384}
  function EVP_sha384: PEVP_MD cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_sha512}
  function EVP_sha512: PEVP_MD cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_sha512_224}
  function EVP_sha512_224: PEVP_MD cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_sha512_256}
  function EVP_sha512_256: PEVP_MD cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_sha3_224}
  function EVP_sha3_224: PEVP_MD cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_sha3_256}
  function EVP_sha3_256: PEVP_MD cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_sha3_384}
  function EVP_sha3_384: PEVP_MD cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_sha3_512}
  function EVP_sha3_512: PEVP_MD cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_shake128}
  function EVP_shake128: PEVP_MD cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_shake256}
  function EVP_shake256: PEVP_MD cdecl; external CLibCrypto; {introduced 1.1.0}

  (* does nothing :-) *)
  {$EXTERNALSYM EVP_enc_null}
  function EVP_enc_null: PEVP_CIPHER cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_des_ecb}
  function EVP_des_ecb: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_des_ede}
  function EVP_des_ede: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_des_ede3}
  function EVP_des_ede3: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_des_ede_ecb}
  function EVP_des_ede_ecb: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_des_ede3_ecb}
  function EVP_des_ede3_ecb: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_des_cfb64}
  function EVP_des_cfb64: PEVP_CIPHER cdecl; external CLibCrypto;
  //EVP_des_cfb EVP_des_cfb64
  {$EXTERNALSYM EVP_des_cfb1}
  function EVP_des_cfb1: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_des_cfb8}
  function EVP_des_cfb8: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_des_ede_cfb64}
  function EVP_des_ede_cfb64: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_des_ede3_cfb64}
  function EVP_des_ede3_cfb64: PEVP_CIPHER cdecl; external CLibCrypto;
  //EVP_des_ede3_cfb EVP_des_ede3_cfb64
  {$EXTERNALSYM EVP_des_ede3_cfb1}
  function EVP_des_ede3_cfb1: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_des_ede3_cfb8}
  function EVP_des_ede3_cfb8: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_des_ofb}
  function EVP_des_ofb: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_des_ede_ofb}
  function EVP_des_ede_ofb: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_des_ede3_ofb}
  function EVP_des_ede3_ofb: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_des_cbc}
  function EVP_des_cbc: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_des_ede_cbc}
  function EVP_des_ede_cbc: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_des_ede3_cbc}
  function EVP_des_ede3_cbc: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_desx_cbc}
  function EVP_desx_cbc: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_des_ede3_wrap}
  function EVP_des_ede3_wrap: PEVP_CIPHER cdecl; external CLibCrypto;
  //
  // This should now be supported through the dev_crypto ENGINE. But also, why
  // are rc4 and md5 declarations made here inside a "NO_DES" precompiler
  // branch?
  //
  {$EXTERNALSYM EVP_rc4}
  function EVP_rc4: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_rc4_40}
  function EVP_rc4_40: PEVP_CIPHER cdecl; external CLibCrypto;
//  function EVP_idea_ecb: PEVP_CIPHER;
// function EVP_idea_cfb64: PEVP_CIPHER;
  //EVP_idea_cfb EVP_idea_cfb64
//  function EVP_idea_ofb: PEVP_CIPHER;
 // function EVP_idea_cbc: PEVP_CIPHER;
  {$EXTERNALSYM EVP_rc2_ecb}
  function EVP_rc2_ecb: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_rc2_cbc}
  function EVP_rc2_cbc: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_rc2_40_cbc}
  function EVP_rc2_40_cbc: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_rc2_64_cbc}
  function EVP_rc2_64_cbc: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_rc2_cfb64}
  function EVP_rc2_cfb64: PEVP_CIPHER cdecl; external CLibCrypto;
  //EVP_rc2_cfb EVP_rc2_cfb64
  {$EXTERNALSYM EVP_rc2_ofb}
  function EVP_rc2_ofb: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_bf_ecb}
  function EVP_bf_ecb: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_bf_cbc}
  function EVP_bf_cbc: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_bf_cfb64}
  function EVP_bf_cfb64: PEVP_CIPHER cdecl; external CLibCrypto;
  //EVP_bf_cfb EVP_bf_cfb64
  {$EXTERNALSYM EVP_bf_ofb}
  function EVP_bf_ofb: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_cast5_ecb}
  function EVP_cast5_ecb: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_cast5_cbc}
  function EVP_cast5_cbc: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_cast5_cfb64}
  function EVP_cast5_cfb64: PEVP_CIPHER cdecl; external CLibCrypto;
  //EVP_cast5_cfb EVP_cast5_cfb64
  {$EXTERNALSYM EVP_cast5_ofb}
  function EVP_cast5_ofb: PEVP_CIPHER cdecl; external CLibCrypto;
//  function EVP_rc5_32_12_16_cbc: PEVP_CIPHER;
//  function EVP_rc5_32_12_16_ecb: PEVP_CIPHER;
//  function EVP_rc5_32_12_16_cfb64: PEVP_CIPHER;
  //EVP_rc5_32_12_16_cfb EVP_rc5_32_12_16_cfb64
//  function EVP_rc5_32_12_16_ofb: PEVP_CIPHER;

  {$EXTERNALSYM EVP_aes_128_ecb}
  function EVP_aes_128_ecb: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_128_cbc}
  function EVP_aes_128_cbc: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_128_cfb1}
  function EVP_aes_128_cfb1: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_128_cfb8}
  function EVP_aes_128_cfb8: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_128_cfb128}
  function EVP_aes_128_cfb128: PEVP_CIPHER cdecl; external CLibCrypto;
  //EVP_aes_128_cfb EVP_aes_128_cfb128
  {$EXTERNALSYM EVP_aes_128_ofb}
  function EVP_aes_128_ofb: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_128_ctr}
  function EVP_aes_128_ctr: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_128_ccm}
  function EVP_aes_128_ccm: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_128_gcm}
  function EVP_aes_128_gcm: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_128_xts}
  function EVP_aes_128_xts: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_128_wrap}
  function EVP_aes_128_wrap: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_128_wrap_pad}
  function EVP_aes_128_wrap_pad: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aes_128_ocb}
  function EVP_aes_128_ocb: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aes_192_ecb}
  function EVP_aes_192_ecb: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_192_cbc}
  function EVP_aes_192_cbc: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_192_cfb1}
  function EVP_aes_192_cfb1: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_192_cfb8}
  function EVP_aes_192_cfb8: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_192_cfb128}
  function EVP_aes_192_cfb128: PEVP_CIPHER cdecl; external CLibCrypto;
  //EVP_aes_192_cfb EVP_aes_192_cfb128
  {$EXTERNALSYM EVP_aes_192_ofb}
  function EVP_aes_192_ofb: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_192_ctr}
  function EVP_aes_192_ctr: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_192_ccm}
  function EVP_aes_192_ccm: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_192_gcm}
  function EVP_aes_192_gcm: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_192_wrap}
  function EVP_aes_192_wrap: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_192_wrap_pad}
  function EVP_aes_192_wrap_pad: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aes_192_ocb}
  function EVP_aes_192_ocb: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aes_256_ecb}
  function EVP_aes_256_ecb: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_256_cbc}
  function EVP_aes_256_cbc: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_256_cfb1}
  function EVP_aes_256_cfb1: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_256_cfb8}
  function EVP_aes_256_cfb8: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_256_cfb128}
  function EVP_aes_256_cfb128: PEVP_CIPHER cdecl; external CLibCrypto;
  //EVP_aes_256_cfb EVP_aes_256_cfb128
  {$EXTERNALSYM EVP_aes_256_ofb}
  function EVP_aes_256_ofb: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_256_ctr}
  function EVP_aes_256_ctr: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_256_ccm}
  function EVP_aes_256_ccm: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_256_gcm}
  function EVP_aes_256_gcm: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_256_xts}
  function EVP_aes_256_xts: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_256_wrap}
  function EVP_aes_256_wrap: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_256_wrap_pad}
  function EVP_aes_256_wrap_pad: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aes_256_ocb}
  function EVP_aes_256_ocb: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aes_128_cbc_hmac_sha1}
  function EVP_aes_128_cbc_hmac_sha1: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_256_cbc_hmac_sha1}
  function EVP_aes_256_cbc_hmac_sha1: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_128_cbc_hmac_sha256}
  function EVP_aes_128_cbc_hmac_sha256: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_aes_256_cbc_hmac_sha256}
  function EVP_aes_256_cbc_hmac_sha256: PEVP_CIPHER cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_aria_128_ecb}
  function EVP_aria_128_ecb: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_128_cbc}
  function EVP_aria_128_cbc: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_128_cfb1}
  function EVP_aria_128_cfb1: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_128_cfb8}
  function EVP_aria_128_cfb8: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_128_cfb128}
  function EVP_aria_128_cfb128: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_128_ctr}
  function EVP_aria_128_ctr: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_128_ofb}
  function EVP_aria_128_ofb: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_128_gcm}
  function EVP_aria_128_gcm: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_128_ccm}
  function EVP_aria_128_ccm: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_192_ecb}
  function EVP_aria_192_ecb: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_192_cbc}
  function EVP_aria_192_cbc: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_192_cfb1}
  function EVP_aria_192_cfb1: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_192_cfb8}
  function EVP_aria_192_cfb8: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_192_cfb128}
  function EVP_aria_192_cfb128: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  //EVP_aria_192_cfb EVP_aria_192_cfb128
  {$EXTERNALSYM EVP_aria_192_ctr}
  function EVP_aria_192_ctr: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_192_ofb}
  function EVP_aria_192_ofb: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_192_gcm}
  function EVP_aria_192_gcm: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_192_ccm}
  function EVP_aria_192_ccm: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_256_ecb}
  function EVP_aria_256_ecb: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_256_cbc}
  function EVP_aria_256_cbc: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_256_cfb1}
  function EVP_aria_256_cfb1: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_256_cfb8}
  function EVP_aria_256_cfb8: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_256_cfb128}
  function EVP_aria_256_cfb128: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  //EVP_aria_256_cfb EVP_aria_256_cfb128
  {$EXTERNALSYM EVP_aria_256_ctr}
  function EVP_aria_256_ctr: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_256_ofb}
  function EVP_aria_256_ofb: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_256_gcm}
  function EVP_aria_256_gcm: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_aria_256_ccm}
  function EVP_aria_256_ccm: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_camellia_128_ecb}
  function EVP_camellia_128_ecb: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_camellia_128_cbc}
  function EVP_camellia_128_cbc: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_camellia_128_cfb1}
  function EVP_camellia_128_cfb1: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_camellia_128_cfb8}
  function EVP_camellia_128_cfb8: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_camellia_128_cfb128}
  function EVP_camellia_128_cfb128: PEVP_CIPHER cdecl; external CLibCrypto;
  //EVP_camellia_128_cfb EVP_camellia_128_cfb128
  {$EXTERNALSYM EVP_camellia_128_ofb}
  function EVP_camellia_128_ofb: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_camellia_128_ctr}
  function EVP_camellia_128_ctr: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_camellia_192_ecb}
  function EVP_camellia_192_ecb: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_camellia_192_cbc}
  function EVP_camellia_192_cbc: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_camellia_192_cfb1}
  function EVP_camellia_192_cfb1: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_camellia_192_cfb8}
  function EVP_camellia_192_cfb8: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_camellia_192_cfb128}
  function EVP_camellia_192_cfb128: PEVP_CIPHER cdecl; external CLibCrypto;
  //EVP_camellia_192_cfb EVP_camellia_192_cfb128
  {$EXTERNALSYM EVP_camellia_192_ofb}
  function EVP_camellia_192_ofb: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_camellia_192_ctr}
  function EVP_camellia_192_ctr: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_camellia_256_ecb}
  function EVP_camellia_256_ecb: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_camellia_256_cbc}
  function EVP_camellia_256_cbc: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_camellia_256_cfb1}
  function EVP_camellia_256_cfb1: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_camellia_256_cfb8}
  function EVP_camellia_256_cfb8: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_camellia_256_cfb128}
  function EVP_camellia_256_cfb128: PEVP_CIPHER cdecl; external CLibCrypto;
  //EVP_camellia_256_cfb EVP_camellia_256_cfb128
  {$EXTERNALSYM EVP_camellia_256_ofb}
  function EVP_camellia_256_ofb: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_camellia_256_ctr}
  function EVP_camellia_256_ctr: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_chacha20}
  function EVP_chacha20: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_chacha20_poly1305}
  function EVP_chacha20_poly1305: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_seed_ecb}
  function EVP_seed_ecb: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_seed_cbc}
  function EVP_seed_cbc: PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_seed_cfb128}
  function EVP_seed_cfb128: PEVP_CIPHER cdecl; external CLibCrypto;
  //EVP_seed_cfb EVP_seed_cfb128
  {$EXTERNALSYM EVP_seed_ofb}
  function EVP_seed_ofb: PEVP_CIPHER cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_sm4_ecb}
  function EVP_sm4_ecb: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_sm4_cbc}
  function EVP_sm4_cbc: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_sm4_cfb128}
  function EVP_sm4_cfb128: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  //EVP_sm4_cfb EVP_sm4_cfb128
  {$EXTERNALSYM EVP_sm4_ofb}
  function EVP_sm4_ofb: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_sm4_ctr}
  function EVP_sm4_ctr: PEVP_CIPHER cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_add_cipher}
  function EVP_add_cipher(const cipher: PEVP_CIPHER): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_add_digest}
  function EVP_add_digest(const digest: PEVP_MD): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_get_cipherbyname}
  function EVP_get_cipherbyname(const name: PIdAnsiChar): PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_get_digestbyname}
  function EVP_get_digestbyname(const name: PIdAnsiChar): PEVP_MD cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_CIPHER_do_all}
  procedure EVP_CIPHER_do_all(AFn: fn; arg: Pointer) cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_CIPHER_do_all_sorted}
  procedure EVP_CIPHER_do_all_sorted(AFn: fn; arg: Pointer) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_MD_do_all}
  procedure EVP_MD_do_all(AFn: fn; arg: Pointer) cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_MD_do_all_sorted}
  procedure EVP_MD_do_all_sorted(AFn: fn; arg: Pointer) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_decrypt_old}
  function EVP_PKEY_decrypt_old(dec_key: PByte; const enc_key: PByte; enc_key_len: TIdC_INT; private_key: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_encrypt_old}
  function EVP_PKEY_encrypt_old(dec_key: PByte; const enc_key: PByte; key_len: TIdC_INT; pub_key: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_type}
  function EVP_PKEY_type(type_: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_id}
  function EVP_PKEY_id(const pkey: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto; {removed 3.0.0}
  {$EXTERNALSYM EVP_PKEY_base_id}
  function EVP_PKEY_base_id(const pkey: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto name 'EVP_PKEY_get_id'; {removed 3.0.0}
  {$EXTERNALSYM EVP_PKEY_bits}
  function EVP_PKEY_bits(const pkey: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto name 'EVP_PKEY_get_bits';
  {$EXTERNALSYM EVP_PKEY_security_bits}
  function EVP_PKEY_security_bits(const pkey: PEVP_PKEY): TIdC_INT  cdecl; external CLibCrypto name 'EVP_PKEY_get_security_bits'; {introduced 1.1.0 removed 3.0.0}
  {$EXTERNALSYM EVP_PKEY_size}
  function EVP_PKEY_size(const pkey: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto name 'EVP_PKEY_get_size'; {removed 3.0.0}
  {$EXTERNALSYM EVP_PKEY_set_type}
  function EVP_PKEY_set_type(pkey: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_set_type_str}
  function EVP_PKEY_set_type_str(pkey: PEVP_PKEY; const _str: PIdAnsiChar; len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_set_alias_type}
  function EVP_PKEY_set_alias_type(pkey: PEVP_PKEY; type_: TIdC_INT): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0 removed 3.0.0}

  {$EXTERNALSYM EVP_PKEY_set1_engine}
  function EVP_PKEY_set1_engine(pkey: PEVP_PKEY; e: PENGINE): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_get0_engine}
  function EVP_PKEY_get0_engine(const pkey: PEVP_PKEY): PENGINE cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_assign}
  function EVP_PKEY_assign(pkey: PEVP_PKEY; type_: TIdC_INT; key: Pointer): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_get0}
  function EVP_PKEY_get0(const pkey: PEVP_PKEY): Pointer cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_get0_hmac}
  function EVP_PKEY_get0_hmac(const pkey: PEVP_PKEY; len: PIdC_SIZET): PByte cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_get0_poly1305}
  function EVP_PKEY_get0_poly1305(const pkey: PEVP_PKEY; len: PIdC_SIZET): PByte cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_get0_siphash}
  function EVP_PKEY_get0_siphash(const pkey: PEVP_PKEY; len: PIdC_SIZET): PByte cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_set1_RSA}
  function EVP_PKEY_set1_RSA(pkey: PEVP_PKEY; key: PRSA): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_get0_RSA}
  function EVP_PKEY_get0_RSA(pkey: PEVP_PKEY): PRSA cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_get1_RSA}
  function EVP_PKEY_get1_RSA(pkey: PEVP_PKEY): PRSA cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_set1_DSA}
  function EVP_PKEY_set1_DSA(pkey: PEVP_PKEY; key: PDSA): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_get0_DSA}
  function EVP_PKEY_get0_DSA(pkey: PEVP_PKEY): PDSA cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_get1_DSA}
  function EVP_PKEY_get1_DSA(pkey: PEVP_PKEY): PDSA cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_set1_DH}
  function EVP_PKEY_set1_DH(pkey: PEVP_PKEY; key: PDH): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_get0_DH}
  function EVP_PKEY_get0_DH(pkey: PEVP_PKEY): PDH cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_get1_DH}
  function EVP_PKEY_get1_DH(pkey: PEVP_PKEY): PDH cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_set1_EC_KEY}
  function EVP_PKEY_set1_EC_KEY(pkey: PEVP_PKEY; key: PEC_KEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_get0_EC_KEY}
  function EVP_PKEY_get0_EC_KEY(pkey: PEVP_PKEY): PEC_KEY cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_get1_EC_KEY}
  function EVP_PKEY_get1_EC_KEY(pkey: PEVP_PKEY): PEC_KEY cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_new}
  function EVP_PKEY_new: PEVP_PKEY cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_up_ref}
  function EVP_PKEY_up_ref(pkey: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_free}
  procedure EVP_PKEY_free(pkey: PEVP_PKEY) cdecl; external CLibCrypto;

  {$EXTERNALSYM d2i_PublicKey}
  function d2i_PublicKey(type_: TIdC_INT; a: PPEVP_PKEY; const pp: PPByte; _length: TIdC_LONG): PEVP_PKEY cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_PublicKey}
  function i2d_PublicKey(a: PEVP_PKEY; pp: PPByte): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM d2i_PrivateKey}
  function d2i_PrivateKey(type_: TIdC_INT; a: PEVP_PKEY; const pp: PPByte; _length: TIdC_LONG): PEVP_PKEY cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_AutoPrivateKey}
  function d2i_AutoPrivateKey(a: PPEVP_PKEY; const pp: PPByte; _length: TIdC_LONG): PEVP_PKEY cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_AutoPrivateKey_ex}
  function d2i_AutoPrivateKey_ex(a: PPEVP_PKEY; const pp: PPByte; _length: TIdC_LONG;
    libctx : POSSL_LIB_CTX; propq : PIdAnsiChar): PEVP_PKEY; cdecl;  external CLibCrypto;
  {$EXTERNALSYM i2d_PrivateKey}
  function i2d_PrivateKey(a: PEVP_PKEY; pp: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_KeyParams_bio}
  function i2d_KeyParams_bio(pb : PBIO; const pkey : PEVP_PKEY) : TIdC_INT;  cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_KeyParams_bio}
  function d2i_KeyParams_bio(type_ : TIdC_INT; var a : PEVP_PKEY; in_ : PBIO) : PEVP_PKEY;  cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_copy_parameters}
  function EVP_PKEY_copy_parameters(to_: PEVP_PKEY; const from: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_missing_parameters}
  function EVP_PKEY_missing_parameters(const pkey: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_save_parameters}
  function EVP_PKEY_save_parameters(pkey: PEVP_PKEY; mode: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_cmp_parameters}
  function EVP_PKEY_cmp_parameters(const a: PEVP_PKEY; const b: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_cmp}
  function EVP_PKEY_cmp(const a: PEVP_PKEY; const b: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_print_public}
  function EVP_PKEY_print_public(out_: PBIO; const pkey: PEVP_PKEY; indent: TIdC_INT; pctx: PASN1_PCTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_print_private}
  function EVP_PKEY_print_private(out_: PBIO; const pkey: PEVP_PKEY; indent: TIdC_INT; pctx: PASN1_PCTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_print_params}
  function EVP_PKEY_print_params(out_: PBIO; const pkey: PEVP_PKEY; indent: TIdC_INT; pctx: PASN1_PCTX): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_get_default_digest_nid}
  function EVP_PKEY_get_default_digest_nid(pkey: PEVP_PKEY; pnid: PIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  (* calls methods *)
  {$EXTERNALSYM EVP_CIPHER_param_to_asn1}
  function EVP_CIPHER_param_to_asn1(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_CIPHER_asn1_to_param}
  function EVP_CIPHER_asn1_to_param(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TIdC_INT cdecl; external CLibCrypto;

  (* These are used by EVP_CIPHER methods *)
  {$EXTERNALSYM EVP_CIPHER_set_asn1_iv}
  function EVP_CIPHER_set_asn1_iv(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_CIPHER_get_asn1_iv}
  function EVP_CIPHER_get_asn1_iv(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_CIPHER_get_mode}
  function EVP_CIPHER_get_mode(const cipher : PEVP_CIPHER) : TIdC_INT cdecl; external CLibCrypto;  {introduced 3.0.0}
  (* PKCS5 password based encryption *)
  {$EXTERNALSYM PKCS5_PBE_keyivgen}
  function PKCS5_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; const pass: PIdAnsiChar; passlen: TIdC_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md: PEVP_MD; en_de: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS5_PBKDF2_HMAC_SHA1}
  function PKCS5_PBKDF2_HMAC_SHA1(const pass: PIdAnsiChar; passlen: TIdC_INT; const salt: PByte; saltlen: TIdC_INT; iter: TIdC_INT; keylen: TIdC_INT; out_: PByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS5_PBKDF2_HMAC}
  function PKCS5_PBKDF2_HMAC(const pass: PIdAnsiChar; passlen: TIdC_INT; const salt: PByte; saltlen: TIdC_INT; iter: TIdC_INT; const digest: PEVP_MD; keylen: TIdC_INT; out_: PByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS5_v2_PBE_keyivgen}
  function PKCS5_v2_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; const pass: PIdAnsiChar; passlen: TIdC_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md: PEVP_MD; en_de: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PBE_scrypt}
  function EVP_PBE_scrypt(const pass: PIdAnsiChar; passlen: TIdC_SIZET; const salt: PByte; saltlen: TIdC_SIZET; N: TIdC_UINT64; r: TIdC_UINT64; p: TIdC_UINT64; maxmem: TIdC_UINT64; key: PByte; keylen: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM PKCS5_v2_scrypt_keyivgen}
  function PKCS5_v2_scrypt_keyivgen(ctx: PEVP_CIPHER_CTX; const pass: PIdAnsiChar; passlen: TIdC_INT; param: PASN1_TYPE; const c: PEVP_CIPHER; const md: PEVP_MD; en_de: TIdC_INT): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM PKCS5_PBE_add}
  procedure PKCS5_PBE_add cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PBE_CipherInit}
  function EVP_PBE_CipherInit(pbe_obj: PASN1_OBJECT; const pass: PIdAnsiChar; passlen: TIdC_INT; param: PASN1_TYPE; ctx: PEVP_CIPHER_CTX; en_de: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  (* PBE type *)
  {$EXTERNALSYM EVP_PBE_alg_add_type}
  function EVP_PBE_alg_add_type(pbe_type: TIdC_INT; pbe_nid: TIdC_INT; cipher_nid: TIdC_INT; md_nid: TIdC_INT; keygen: PEVP_PBE_KEYGEN): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PBE_alg_add}
  function EVP_PBE_alg_add(nid: TIdC_INT; const cipher: PEVP_CIPHER; const md: PEVP_MD; keygen: PEVP_PBE_KEYGEN): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PBE_find}
  function EVP_PBE_find(type_: TIdC_INT; pbe_nid: TIdC_INT; pcnid: PIdC_INT; pmnid: PIdC_INT; pkeygen: PPEVP_PBE_KEYGEN): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PBE_cleanup}
  procedure EVP_PBE_cleanup cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PBE_get}
  function EVP_PBE_get(ptype: PIdC_INT; ppbe_nid: PIdC_INT; num: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_asn1_get_count}
  function EVP_PKEY_asn1_get_count: TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_asn1_get0}
  function EVP_PKEY_asn1_get0(idx: TIdC_INT): PEVP_PKEY_ASN1_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_asn1_find}
  function EVP_PKEY_asn1_find(pe: PPENGINE; type_: TIdC_INT): PEVP_PKEY_ASN1_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_asn1_find_str}
  function EVP_PKEY_asn1_find_str(pe: PPENGINE; const _str: PIdAnsiChar; len: TIdC_INT): PEVP_PKEY_ASN1_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_asn1_add0}
  function EVP_PKEY_asn1_add0(const ameth: PEVP_PKEY_ASN1_METHOD): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_asn1_add_alias}
  function EVP_PKEY_asn1_add_alias(to_: TIdC_INT; from: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_asn1_get0_info}
  function EVP_PKEY_asn1_get0_info(ppkey_id: PIdC_INT; pkey_base_id: PIdC_INT; ppkey_flags: PIdC_INT; const pinfo: PPIdAnsiChar; const ppem_str: PPIdAnsiChar; const ameth: PEVP_PKEY_ASN1_METHOD): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_get0_asn1}
  function EVP_PKEY_get0_asn1(const pkey: PEVP_PKEY): PEVP_PKEY_ASN1_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_asn1_new}
  function EVP_PKEY_asn1_new(id: TIdC_INT; flags: TIdC_INT; const pem_str: PIdAnsiChar; const info: PIdAnsiChar): PEVP_PKEY_ASN1_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_asn1_copy}
  procedure EVP_PKEY_asn1_copy(dst: PEVP_PKEY_ASN1_METHOD; const src: PEVP_PKEY_ASN1_METHOD) cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_asn1_free}
  procedure EVP_PKEY_asn1_free(ameth: PEVP_PKEY_ASN1_METHOD) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_asn1_set_public}
  procedure EVP_PKEY_asn1_set_public(ameth: PEVP_PKEY_ASN1_METHOD; APub_decode: pub_decode; APub_encode: pub_encode; APub_cmd: pub_cmd; APub_print: pub_print; APkey_size: pkey_size; APkey_bits: pkey_bits) cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_asn1_set_private}
  procedure EVP_PKEY_asn1_set_private(ameth: PEVP_PKEY_ASN1_METHOD; APriv_decode: priv_decode; APriv_encode: priv_encode; APriv_print: priv_print) cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_asn1_set_param}
  procedure EVP_PKEY_asn1_set_param(ameth: PEVP_PKEY_ASN1_METHOD; AParam_decode: param_decode; AParam_encode: param_encode; AParam_missing: param_missing; AParam__copy: param_copy; AParam_cmp: param_cmp; AParam_print: param_print) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_asn1_set_free}
  procedure EVP_PKEY_asn1_set_free(ameth: PEVP_PKEY_ASN1_METHOD; APkey_free: pkey_free) cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_asn1_set_ctrl}
  procedure EVP_PKEY_asn1_set_ctrl(ameth: PEVP_PKEY_ASN1_METHOD; APkey_ctrl: pkey_ctrl) cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_asn1_set_item}
  procedure EVP_PKEY_asn1_set_item(ameth: PEVP_PKEY_ASN1_METHOD; AItem_verify: item_verify; AItem_sign: item_sign) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_asn1_set_siginf}
  procedure EVP_PKEY_asn1_set_siginf(ameth: PEVP_PKEY_ASN1_METHOD; ASiginf_set: siginf_set) cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_asn1_set_check}
  procedure EVP_PKEY_asn1_set_check(ameth: PEVP_PKEY_ASN1_METHOD; APkey_check: pkey_check) cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_asn1_set_public_check}
  procedure EVP_PKEY_asn1_set_public_check(ameth: PEVP_PKEY_ASN1_METHOD; APkey_pub_check: pkey_pub_check) cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_asn1_set_param_check}
  procedure EVP_PKEY_asn1_set_param_check(ameth: PEVP_PKEY_ASN1_METHOD; APkey_param_check: pkey_param_check) cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_asn1_set_set_priv_key}
  procedure EVP_PKEY_asn1_set_set_priv_key(ameth: PEVP_PKEY_ASN1_METHOD; ASet_priv_key: set_priv_key) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_asn1_set_set_pub_key}
  procedure EVP_PKEY_asn1_set_set_pub_key(ameth: PEVP_PKEY_ASN1_METHOD; ASet_pub_key: set_pub_key) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_asn1_set_get_priv_key}
  procedure EVP_PKEY_asn1_set_get_priv_key(ameth: PEVP_PKEY_ASN1_METHOD; AGet_priv_key: get_priv_key) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_asn1_set_get_pub_key}
  procedure EVP_PKEY_asn1_set_get_pub_key(ameth: PEVP_PKEY_ASN1_METHOD; AGet_pub_key: get_pub_key) cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_asn1_set_security_bits}
  procedure EVP_PKEY_asn1_set_security_bits(ameth: PEVP_PKEY_ASN1_METHOD; APkey_security_bits: pkey_security_bits) cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_meth_find}
  function EVP_PKEY_meth_find(type_: TIdC_INT): PEVP_PKEY_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_meth_new}
  function EVP_PKEY_meth_new(id: TIdC_INT; flags: TIdC_INT): PEVP_PKEY_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_meth_get0_info}
  procedure EVP_PKEY_meth_get0_info(ppkey_id: PIdC_INT; pflags: PIdC_INT; const meth: PEVP_PKEY_METHOD) cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_meth_copy}
  procedure EVP_PKEY_meth_copy(dst: PEVP_PKEY_METHOD; const src: PEVP_PKEY_METHOD) cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_meth_free}
  procedure EVP_PKEY_meth_free(pmeth: PEVP_PKEY_METHOD) cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_meth_add0}
  function EVP_PKEY_meth_add0(const pmeth: PEVP_PKEY_METHOD): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_meth_remove}
  function EVP_PKEY_meth_remove(const pmeth: PEVP_PKEY_METHOD): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_meth_get_count}
  function EVP_PKEY_meth_get_count: TIdC_SIZET cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_meth_get0}
  function EVP_PKEY_meth_get0(idx: TIdC_SIZET): PEVP_PKEY_METHOD cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_CTX_new}
  function EVP_PKEY_CTX_new(pkey: PEVP_PKEY; e: PENGINE): PEVP_PKEY_CTX cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_CTX_new_id}
  function EVP_PKEY_CTX_new_id(id: TIdC_INT; e: PENGINE): PEVP_PKEY_CTX cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_CTX_dup}
  function EVP_PKEY_CTX_dup(ctx: PEVP_PKEY_CTX): PEVP_PKEY_CTX cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_CTX_free}
  procedure EVP_PKEY_CTX_free(ctx: PEVP_PKEY_CTX) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_CTX_ctrl}
  function EVP_PKEY_CTX_ctrl(ctx: PEVP_PKEY_CTX; keytype: TIdC_INT; optype: TIdC_INT; cmd: TIdC_INT; p1: TIdC_INT; p2: Pointer): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_CTX_ctrl_str}
  function EVP_PKEY_CTX_ctrl_str(ctx: PEVP_PKEY_CTX; const type_: PIdAnsiChar; const value: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_CTX_ctrl_uint64}
  function EVP_PKEY_CTX_ctrl_uint64(ctx: PEVP_PKEY_CTX; keytype: TIdC_INT; optype: TIdC_INT; cmd: TIdC_INT; value: TIdC_UINT64): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_CTX_str2ctrl}
  function EVP_PKEY_CTX_str2ctrl(ctx: PEVP_PKEY_CTX; cmd: TIdC_INT; const _str: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_CTX_hex2ctrl}
  function EVP_PKEY_CTX_hex2ctrl(ctx: PEVP_PKEY_CTX; cmd: TIdC_INT; const hex: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_CTX_md}
  function EVP_PKEY_CTX_md(ctx: PEVP_PKEY_CTX; optype: TIdC_INT; cmd: TIdC_INT; const md: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_CTX_get_operation}
  function EVP_PKEY_CTX_get_operation(ctx: PEVP_PKEY_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_CTX_set0_keygen_info}
  procedure EVP_PKEY_CTX_set0_keygen_info(ctx: PEVP_PKEY_CTX; dat: PIdC_INT; datlen: TIdC_INT) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_new_mac_key}
  function EVP_PKEY_new_mac_key(type_: TIdC_INT; e: PENGINE; const key: PByte; keylen: TIdC_INT): PEVP_PKEY cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_new_raw_private_key}
  function EVP_PKEY_new_raw_private_key(type_: TIdC_INT; e: PENGINE; const priv: PByte; len: TIdC_SIZET): PEVP_PKEY cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_new_raw_public_key}
  function EVP_PKEY_new_raw_public_key(type_: TIdC_INT; e: PENGINE; const pub: PByte; len: TIdC_SIZET): PEVP_PKEY cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_get_raw_private_key}
  function EVP_PKEY_get_raw_private_key(const pkey: PEVP_PKEY; priv: PByte; len: PIdC_SIZET): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_get_raw_public_key}
  function EVP_PKEY_get_raw_public_key(const pkey: PEVP_PKEY; pub: PByte; len: PIdC_SIZET): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_new_CMAC_key}
  function EVP_PKEY_new_CMAC_key(e: PENGINE; const priv: PByte; len: TIdC_SIZET; const cipher: PEVP_CIPHER): PEVP_PKEY cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_CTX_set_data}
  procedure EVP_PKEY_CTX_set_data(ctx: PEVP_PKEY_CTX; data: Pointer) cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_CTX_get_data}
  function EVP_PKEY_CTX_get_data(ctx: PEVP_PKEY_CTX): Pointer cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_CTX_get0_pkey}
  function EVP_PKEY_CTX_get0_pkey(ctx: PEVP_PKEY_CTX): PEVP_PKEY cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_CTX_get0_peerkey}
  function EVP_PKEY_CTX_get0_peerkey(ctx: PEVP_PKEY_CTX): PEVP_PKEY cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_CTX_set_app_data}
  procedure EVP_PKEY_CTX_set_app_data(ctx: PEVP_PKEY_CTX; data: Pointer) cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_CTX_get_app_data}
  function EVP_PKEY_CTX_get_app_data(ctx: PEVP_PKEY_CTX): Pointer cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_sign_init}
  function EVP_PKEY_sign_init(ctx: PEVP_PKEY_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_sign}
  function EVP_PKEY_sign(ctx: PEVP_PKEY_CTX; sig: PByte; siglen: PIdC_SIZET; const tbs: PByte; tbslen: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_verify_init}
  function EVP_PKEY_verify_init(ctx: PEVP_PKEY_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_verify}
  function EVP_PKEY_verify(ctx: PEVP_PKEY_CTX; const sig: PByte; siglen: TIdC_SIZET; const tbs: PByte; tbslen: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_verify_recover_init}
  function EVP_PKEY_verify_recover_init(ctx: PEVP_PKEY_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_verify_recover}
  function EVP_PKEY_verify_recover(ctx: PEVP_PKEY_CTX; rout: PByte; var outlen: TIdC_SIZET; const sig: PByte; siglen: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_encrypt_init}
  function EVP_PKEY_encrypt_init(ctx: PEVP_PKEY_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_encrypt}
  function EVP_PKEY_encrypt(ctx: PEVP_PKEY_CTX; var out_; var outlen: TIdC_SIZET; const in_; inlen: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_decrypt_init}
  function EVP_PKEY_decrypt_init(ctx: PEVP_PKEY_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_decrypt}
  function EVP_PKEY_decrypt(ctx: PEVP_PKEY_CTX; var out_; var outlen: TIdC_SIZET; const in_; inlen: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_derive_init}
  function EVP_PKEY_derive_init(ctx: PEVP_PKEY_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_derive_set_peer}
  function EVP_PKEY_derive_set_peer(ctx: PEVP_PKEY_CTX; peer: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_derive}
  function EVP_PKEY_derive(ctx: PEVP_PKEY_CTX; key: PByte; keylen: PIdC_SIZET): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_paramgen_init}
  function EVP_PKEY_paramgen_init(ctx: PEVP_PKEY_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_paramgen}
  function EVP_PKEY_paramgen(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_keygen_init}
  function EVP_PKEY_keygen_init(ctx: PEVP_PKEY_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_keygen}
  function EVP_PKEY_keygen(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_check}
  function EVP_PKEY_check(ctx: PEVP_PKEY_CTX): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_public_check}
  function EVP_PKEY_public_check(ctx: PEVP_PKEY_CTX): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EVP_PKEY_param_check}
  function EVP_PKEY_param_check(ctx: PEVP_PKEY_CTX): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_CTX_set_cb}
  procedure EVP_PKEY_CTX_set_cb(ctx: PEVP_PKEY_CTX; cb: EVP_PKEY_gen_cb) cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_CTX_get_cb}
  function EVP_PKEY_CTX_get_cb(ctx: PEVP_PKEY_CTX): EVP_PKEY_gen_cb cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_CTX_get_keygen_info}
  function EVP_PKEY_CTX_get_keygen_info(ctx: PEVP_PKEY_CTX; idx: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_set_init}
  procedure EVP_PKEY_meth_set_init(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_init: EVP_PKEY_meth_init) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_set_copy}
  procedure EVP_PKEY_meth_set_copy(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_copy_cb: EVP_PKEY_meth_copy_cb) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_set_cleanup}
  procedure EVP_PKEY_meth_set_cleanup(pmeth: PEVP_PKEY_METHOD; PEVP_PKEY_meth_cleanup: EVP_PKEY_meth_cleanup) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_set_paramgen}
  procedure EVP_PKEY_meth_set_paramgen(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_paramgen_init: EVP_PKEY_meth_paramgen_init; AEVP_PKEY_meth_paramgen: EVP_PKEY_meth_paramgen_init) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_set_keygen}
  procedure EVP_PKEY_meth_set_keygen(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_keygen_init: EVP_PKEY_meth_keygen_init; AEVP_PKEY_meth_keygen: EVP_PKEY_meth_keygen) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_set_sign}
  procedure EVP_PKEY_meth_set_sign(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_sign_init: EVP_PKEY_meth_sign_init; AEVP_PKEY_meth_sign: EVP_PKEY_meth_sign) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_set_verify}
  procedure EVP_PKEY_meth_set_verify(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_init: EVP_PKEY_meth_verify_init; AEVP_PKEY_meth_verify: EVP_PKEY_meth_verify_init) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_set_verify_recover}
  procedure EVP_PKEY_meth_set_verify_recover(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_recover_init: EVP_PKEY_meth_verify_recover_init; AEVP_PKEY_meth_verify_recover: EVP_PKEY_meth_verify_recover_init) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_set_signctx}
  procedure EVP_PKEY_meth_set_signctx(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_signctx_init: EVP_PKEY_meth_signctx_init; AEVP_PKEY_meth_signctx: EVP_PKEY_meth_signctx) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_set_verifyctx}
  procedure EVP_PKEY_meth_set_verifyctx(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verifyctx_init: EVP_PKEY_meth_verifyctx_init; AEVP_PKEY_meth_verifyctx: EVP_PKEY_meth_verifyctx) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_set_encrypt}
  procedure EVP_PKEY_meth_set_encrypt(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_encrypt_init: EVP_PKEY_meth_encrypt_init; AEVP_PKEY_meth_encrypt: EVP_PKEY_meth_encrypt) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_set_decrypt}
  procedure EVP_PKEY_meth_set_decrypt(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_decrypt_init: EVP_PKEY_meth_decrypt_init; AEVP_PKEY_meth_decrypt: EVP_PKEY_meth_decrypt) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_set_derive}
  procedure EVP_PKEY_meth_set_derive(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_derive_init: EVP_PKEY_meth_derive_init; AEVP_PKEY_meth_derive: EVP_PKEY_meth_derive) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_set_ctrl}
  procedure EVP_PKEY_meth_set_ctrl(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_ctrl: EVP_PKEY_meth_ctrl; AEVP_PKEY_meth_ctrl_str: EVP_PKEY_meth_ctrl_str) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_set_digestsign}
  procedure EVP_PKEY_meth_set_digestsign(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestsign: EVP_PKEY_meth_digestsign) cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_meth_set_digestverify}
  procedure EVP_PKEY_meth_set_digestverify(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestverify: EVP_PKEY_meth_digestverify) cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_meth_set_check}
  procedure EVP_PKEY_meth_set_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_check: EVP_PKEY_meth_check) cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_meth_set_public_check}
  procedure EVP_PKEY_meth_set_public_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_public_check: EVP_PKEY_meth_public_check) cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_meth_set_param_check}
  procedure EVP_PKEY_meth_set_param_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_param_check: EVP_PKEY_meth_param_check) cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_meth_set_digest_custom}
  procedure EVP_PKEY_meth_set_digest_custom(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digest_custom: EVP_PKEY_meth_digest_custom) cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_meth_get_init}
  procedure EVP_PKEY_meth_get_init(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_init: PEVP_PKEY_meth_init) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_get_copy}
  procedure EVP_PKEY_meth_get_copy(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth__copy: PEVP_PKEY_meth_copy) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_get_cleanup}
  procedure EVP_PKEY_meth_get_cleanup(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_cleanup: PEVP_PKEY_meth_cleanup) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_get_paramgen}
  procedure EVP_PKEY_meth_get_paramgen(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_paramgen_init: EVP_PKEY_meth_paramgen_init; AEVP_PKEY_meth_paramgen: PEVP_PKEY_meth_paramgen) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_get_keygen}
  procedure EVP_PKEY_meth_get_keygen(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_keygen_init: EVP_PKEY_meth_keygen_init; AEVP_PKEY_meth_keygen: PEVP_PKEY_meth_keygen) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_get_sign}
  procedure EVP_PKEY_meth_get_sign(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_sign_init: PEVP_PKEY_meth_sign_init; AEVP_PKEY_meth_sign: PEVP_PKEY_meth_sign) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_get_verify}
  procedure EVP_PKEY_meth_get_verify(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_init: PEVP_PKEY_meth_verify_init; AEVP_PKEY_meth_verify: PEVP_PKEY_meth_verify_init) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_get_verify_recover}
  procedure EVP_PKEY_meth_get_verify_recover(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_recover_init: PEVP_PKEY_meth_verify_recover_init; AEVP_PKEY_meth_verify_recover: PEVP_PKEY_meth_verify_recover_init) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_get_signctx}
  procedure EVP_PKEY_meth_get_signctx(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_signctx_init: PEVP_PKEY_meth_signctx_init; AEVP_PKEY_meth_signctx: PEVP_PKEY_meth_signctx) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_get_verifyctx}
  procedure EVP_PKEY_meth_get_verifyctx(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verifyctx_init: PEVP_PKEY_meth_verifyctx_init; AEVP_PKEY_meth_verifyctx: PEVP_PKEY_meth_verifyctx) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_get_encrypt}
  procedure EVP_PKEY_meth_get_encrypt(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_encrypt_init: PEVP_PKEY_meth_encrypt_init; AEVP_PKEY_meth_encrypt: PEVP_PKEY_meth_encrypt) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_get_decrypt}
  procedure EVP_PKEY_meth_get_decrypt(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_decrypt_init: PEVP_PKEY_meth_decrypt_init; AEVP_PKEY_meth_decrypt: PEVP_PKEY_meth_decrypt) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_get_derive}
  procedure EVP_PKEY_meth_get_derive(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_derive_init: PEVP_PKEY_meth_derive_init; AEVP_PKEY_meth_derive: PEVP_PKEY_meth_derive) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_get_ctrl}
  procedure EVP_PKEY_meth_get_ctrl(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_ctrl: PEVP_PKEY_meth_ctrl; AEVP_PKEY_meth_ctrl_str: PEVP_PKEY_meth_ctrl_str) cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_meth_get_digestsign}
  procedure EVP_PKEY_meth_get_digestsign(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestsign: PEVP_PKEY_meth_digestsign) cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_meth_get_digestverify}
  procedure EVP_PKEY_meth_get_digestverify(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestverify: PEVP_PKEY_meth_digestverify) cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_meth_get_check}
  procedure EVP_PKEY_meth_get_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_check: PEVP_PKEY_meth_check) cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_meth_get_public_check}
  procedure EVP_PKEY_meth_get_public_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_public_check: PEVP_PKEY_meth_public_check) cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_meth_get_param_check}
  procedure EVP_PKEY_meth_get_param_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_param_check: PEVP_PKEY_meth_param_check) cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_PKEY_meth_get_digest_custom}
  procedure EVP_PKEY_meth_get_digest_custom(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digest_custom: PEVP_PKEY_meth_digest_custom) cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EVP_add_alg_module}
  procedure EVP_add_alg_module cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_CIPHER_get_key_length}
  function EVP_CIPHER_get_key_length(const cipher: PEVP_CIPHER): TIdC_INT cdecl; external CLibCrypto; {introduced 3.0.0}
  {$EXTERNALSYM EVP_CIPHER_nid}
  function EVP_CIPHER_nid(const cipher: PEVP_CIPHER): TIdC_INT cdecl; external CLibCrypto;


  {$EXTERNALSYM EVP_PKEY_assign_RSA}
function EVP_PKEY_assign_RSA(pkey: PEVP_PKEY; rsa: Pointer): TIdC_INT; {removed 1.0.0}
  {$EXTERNALSYM EVP_PKEY_assign_DSA}
function EVP_PKEY_assign_DSA(pkey: PEVP_PKEY; dsa: Pointer): TIdC_INT; {removed 1.0.0}
  {$EXTERNALSYM EVP_PKEY_assign_DH}
function EVP_PKEY_assign_DH(pkey: PEVP_PKEY; dh: Pointer): TIdC_INT; {removed 1.0.0}
  {$EXTERNALSYM EVP_PKEY_assign_EC_KEY}
function EVP_PKEY_assign_EC_KEY(pkey: PEVP_PKEY; eckey: Pointer): TIdC_INT; {removed 1.0.0}
  {$EXTERNALSYM EVP_PKEY_assign_SIPHASH}
function EVP_PKEY_assign_SIPHASH(pkey: PEVP_PKEY; shkey: Pointer): TIdC_INT; {removed 1.0.0}
  {$EXTERNALSYM EVP_PKEY_assign_POLY1305}
function EVP_PKEY_assign_POLY1305(pkey: PEVP_PKEY; polykey: Pointer): TIdC_INT; {removed 1.0.0}
  {$EXTERNALSYM BIO_set_md}
  procedure BIO_set_md(v1: PBIO; const md: PEVP_MD); {removed 1.0.0}
  {$EXTERNALSYM EVP_md2}
  function EVP_md2: PEVP_MD; {removed 1.1.0 allow_nil}
  {$EXTERNALSYM EVP_md4}
  function EVP_md4: PEVP_MD; {removed 1.1.0 allow_nil}
  {$EXTERNALSYM EVP_md5}
  function EVP_md5: PEVP_MD; {removed 1.1.0 allow_nil}
  procedure OpenSSL_add_all_ciphers; {removed 1.1.0}
  procedure OpenSSL_add_all_digests; {removed 1.1.0}
  procedure EVP_cleanup; {removed 1.1.0}
//* MAC Stuff */
  {$EXTERNALSYM EVP_MAC_fetch}
  function EVP_MAC_fetch(libctx : POSSL_LIB_CTX;
    const algorithm, properties : PIdAnsiChar) : PEVP_MAC; cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_MAC_up_ref}
  function EVP_MAC_up_ref(mac : PEVP_MAC) : TIdC_INT; cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_MAC_free}
  procedure EVP_MAC_free(mac : PEVP_MAC); cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_MAC_is_a}
  function EVP_MAC_is_a(const mac : PEVP_MAC; const name : PIdAnsiChar) : TIdC_INT; cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_MAC_get0_name}
  function EVP_MAC_get0_name(const mac : PEVP_MAC) : PIdAnsiChar; cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_MAC_names_do_all}
  function EVP_MAC_names_do_all(const mac : PEVP_MAC; fn : EVP_MAC_names_do_all_fn;
                         data : Pointer) : TIdC_INT; cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_MAC_get0_description}
  function EVP_MAC_get0_description(const mac : PEVP_MAC) : PIdAnsiChar; cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_MAC_get0_provider}
  function EVP_MAC_get0_provider(const mac :PEVP_MAC) : POSSL_PROVIDER; cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_MAC_get_params}
  function EVP_MAC_get_params(mac : PEVP_MAC; params : POSSL_PARAM_ARRAY) : TIdC_INT; cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_MAC_CTX_new}
  function EVP_MAC_CTX_new(mac : PEVP_MAC) : PEVP_MAC_CTX cdecl; external CLibCrypto;  {introduced 3.0.0}
  {$EXTERNALSYM EVP_MAC_CTX_free}
  procedure EVP_MAC_CTX_free (ctx : PEVP_MAC_CTX ) cdecl; external CLibCrypto;   {introduced 3.0.0}

  {$EXTERNALSYM EVP_MAC_CTX_dup}
  function EVP_MAC_CTX_dup(const  src : PEVP_MAC_CTX) : PEVP_MAC_CTX; cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_MAC_CTX_get0_mac}
  function EVP_MAC_CTX_get0_mac(ctx : PEVP_MAC_CTX) : PEVP_MAC; cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_MAC_CTX_get_params}
  function EVP_MAC_CTX_get_params(ctx : PEVP_MAC_CTX; params : POSSL_PARAM_ARRAY) : TIdC_INT; cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_MAC_CTX_set_params}
  function EVP_MAC_CTX_set_params(ctx : PEVP_MAC_CTX; const  params : POSSL_PARAM_ARRAY) : TIdC_INT; cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_MAC_CTX_get_mac_size}
  function EVP_MAC_CTX_get_mac_size(ctx : PEVP_MAC_CTX) : TIdC_SIZET; cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_MAC_CTX_get_block_size}
  function EVP_MAC_CTX_get_block_size(ctx : PEVP_MAC_CTX) : TIdC_SIZET; cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_Q_mac}
  function EVP_Q_mac(libctx : POSSL_LIB_CTX;
    const name, propq, subalg : PIdAnsiChar; const params : POSSL_PARAM;
    const key : Pointer; keylen : TIdC_SIZET;
    const data : PIdAnsiChar; datalen : TIdC_SIZET;
    _out : PIdAnsiChar; outsize : TIdC_SIZET;
    var outlen : TIdC_SIZET) : PIdAnsiChar; cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_MAC_init}
  function EVP_MAC_init(ctx : PEVP_MAC_CTX; const key : PIdAnsiChar; keylen : TIdC_SIZET;
                 const  params : POSSL_PARAM_ARRAY) : TIdC_INT; cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_MAC_init_SKEY}
  function EVP_MAC_init_SKEY(ctx : PEVP_MAC_CTX;  skey : PEVP_SKEY; const  params : POSSL_PARAM_ARRAY) : TIdC_INT; cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_MAC_update}
  function EVP_MAC_update(ctx : PEVP_MAC_CTX; const data : PIdAnsiChar;
    datalen : TIdC_SIZET) : TIdC_INT; cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_MAC_final}
  function EVP_MAC_final(ctx : PEVP_MAC_CTX;
    _out : PIdAnsiChar; var outl : TIdC_SIZET; outsize : TIdC_SIZET) : TIdC_INT; cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_MAC_finalXOF}
  function EVP_MAC_finalXOF(ctx : PEVP_MAC_CTX; _out : PIdAnsiChar; outsize : TIdC_SIZET) : TIdC_INT; cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_MAC_gettable_params}
  function EVP_MAC_gettable_params(const mac : PEVP_MAC) : POSSL_PARAM;  cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_MAC_gettable_ctx_params}
  function EVP_MAC_gettable_ctx_params(const mac : PEVP_MAC) : POSSL_PARAM; cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_MAC_settable_ctx_params}
  function EVP_MAC_settable_ctx_params(const mac : PEVP_MAC) : POSSL_PARAM;  cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_MAC_CTX_gettable_params}
  function EVP_MAC_CTX_gettable_params(ctx : PEVP_MAC_CTX) : POSSL_PARAM; cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_MAC_CTX_settable_params}
  function EVP_MAC_CTX_settable_params(ctx : PEVP_MAC_CTX) : POSSL_PARAM; cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_MAC_do_all_provided}
  procedure EVP_MAC_do_all_provided(libctx : POSSL_LIB_CTX;
                             fn : EVP_MAC_do_all_provided_fn;
                             arg : Pointer);  cdecl; external CLibCrypto;
{$ENDIF}

 //# define EVP_CIPHER_name(e)              OBJ_nid2sn(EVP_CIPHER_nid(e))

  {$EXTERNALSYM EVP_CIPHER_CTX_type}
function  EVP_CIPHER_CTX_type(c : PEVP_CIPHER_CTX)  : TIdC_INT; {$IFDEF USE_INLINE}inline; {$ENDIF}
  {$EXTERNALSYM EVP_CIPHER_CTX_get_type}
function EVP_CIPHER_CTX_get_type(c : PEVP_CIPHER_CTX) : TIdC_INT; {$IFDEF USE_INLINE}inline; {$ENDIF}

  {$EXTERNALSYM EVP_CIPHER_CTX_get_mode}
function EVP_CIPHER_CTX_get_mode(c: PEVP_CIPHER_CTX) : TIdC_INT;  {$IFDEF USE_INLINE}inline; {$ENDIF}

  {$EXTERNALSYM EVP_CIPHER_mode}
function EVP_CIPHER_mode(e : PEVP_CIPHER) : TIdC_INT;  {$IFDEF USE_INLINE}inline; {$ENDIF}


implementation

uses
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  classes,
  TaurusTLSLoader,
  {$ENDIF}
  TaurusTLS_ResourceStrings,
  TaurusTLSExceptionHandlers,
  TaurusTLSHeaders_crypto,
  TaurusTLSHeaders_objects;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

function  EVP_CIPHER_CTX_type(c : PEVP_CIPHER_CTX)  : TIdC_INT;
 {$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := EVP_CIPHER_type(EVP_CIPHER_CTX_cipher(c));
end;

function EVP_CIPHER_CTX_get_type(c : PEVP_CIPHER_CTX) : TIdC_INT;
 {$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := EVP_CIPHER_get_type(EVP_CIPHER_CTX_get0_cipher(c));
end;

//EVP_CIPHER_CTX_get_mode(c)  EVP_CIPHER_get_mode(EVP_CIPHER_CTX_get0_cipher(c))
function EVP_CIPHER_CTX_get_mode(c: PEVP_CIPHER_CTX) : TIdC_INT;
 {$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result :=  EVP_CIPHER_get_mode(EVP_CIPHER_CTX_get0_cipher(c))
end;

function EVP_CIPHER_mode(e : PEVP_CIPHER) : TIdC_INT;
 {$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := EVP_CIPHER_flags(e) and EVP_CIPH_MODE;
end;

{$ELSE}

function EVP_CIPHER_CTX_get_type(c : PEVP_CIPHER_CTX) : TIdC_INT;
 {$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := EVP_CIPHER_get_type(EVP_CIPHER_CTX_get0_cipher(c));
end;

function  EVP_CIPHER_CTX_type(c : PEVP_CIPHER_CTX)  : TIdC_INT;
 {$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := EVP_CIPHER_CTX_get_type(c);
end;

function EVP_CIPHER_CTX_get_mode(c: PEVP_CIPHER_CTX) : TIdC_INT;
begin
  Result := EVP_CIPHER_get_mode(EVP_CIPHER_CTX_get0_cipher(c));
end;

function EVP_CIPHER_mode(e : PEVP_CIPHER) : TIdC_INT;
begin
  Result := EVP_CIPHER_get_mode(e);
end;
{$ENDIF}

const
  EVP_MD_meth_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_meth_new_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_meth_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_meth_dup_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_meth_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_meth_free_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_meth_set_input_blocksize_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_meth_set_input_blocksize_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_meth_set_result_size_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_meth_set_result_size_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_meth_set_app_datasize_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_meth_set_app_datasize_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_meth_set_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_meth_set_flags_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_meth_set_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_meth_set_init_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_meth_set_update_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_meth_set_update_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_meth_set_final_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_meth_set_final_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_meth_set_copy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_meth_set_copy_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_meth_set_cleanup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_meth_set_cleanup_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_meth_set_ctrl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_meth_set_ctrl_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_meth_get_input_blocksize_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_meth_get_input_blocksize_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_meth_get_result_size_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_meth_get_result_size_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_meth_get_app_datasize_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_meth_get_app_datasize_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_meth_get_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_meth_get_flags_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_meth_get_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_meth_get_init_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_meth_get_update_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_meth_get_update_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_meth_get_final_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_meth_get_final_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_meth_get_copy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_meth_get_copy_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_meth_get_cleanup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_meth_get_cleanup_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_meth_get_ctrl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_meth_get_ctrl_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_get0_name_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);  {introduced 3.0.0}
  EVP_CIPHER_meth_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_meth_new_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_meth_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_meth_dup_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_meth_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_meth_free_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_meth_set_iv_length_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_meth_set_iv_length_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_meth_set_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_meth_set_flags_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_meth_set_impl_ctx_size_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_meth_set_impl_ctx_size_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_meth_set_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_meth_set_init_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_meth_set_do_cipher_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_meth_set_do_cipher_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_meth_set_cleanup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_meth_set_cleanup_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_meth_set_set_asn1_params_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_meth_set_set_asn1_params_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_meth_set_get_asn1_params_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_meth_set_get_asn1_params_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_meth_set_ctrl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_meth_set_ctrl_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_meth_get_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_meth_get_init_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_meth_get_do_cipher_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_meth_get_do_cipher_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_meth_get_cleanup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_meth_get_cleanup_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_meth_get_set_asn1_params_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_meth_get_set_asn1_params_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_meth_get_get_asn1_params_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_meth_get_get_asn1_params_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_meth_get_ctrl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_meth_get_ctrl_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_CTX_get0_cipher_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_CTX_update_fn_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_CTX_update_fn_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_CTX_set_update_fn_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_CTX_set_update_fn_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_CTX_pkey_ctx_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_CTX_set_pkey_ctx_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_CTX_md_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_impl_ctx_size_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_CTX_encrypting_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_CTX_is_encrypting_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_CTX_iv_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_CTX_original_iv_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_CTX_iv_noconst_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_CTX_buf_noconst_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_CTX_num_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_CTX_get_num_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_CTX_set_num_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_CTX_get_cipher_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_CTX_set_cipher_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_CTX_tag_length_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_CTX_get_tag_length_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_CTX_ctrl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_CTX_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_CTX_reset_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_CTX_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_DigestFinalXOF_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_DigestSign_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_DigestVerify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_ENCODE_CTX_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_ENCODE_CTX_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_ENCODE_CTX_copy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_ENCODE_CTX_num_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_CIPHER_fetch_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_CTX_reset_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_md5_sha1_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_sha512_224_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_sha512_256_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_sha3_224_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_sha3_256_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_sha3_384_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_sha3_512_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_shake128_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_shake256_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aes_128_wrap_pad_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aes_128_ocb_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aes_192_wrap_pad_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aes_192_ocb_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aes_256_wrap_pad_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aes_256_ocb_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aria_128_ecb_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aria_128_cbc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aria_128_cfb1_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aria_128_cfb8_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aria_128_cfb128_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aria_128_ctr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aria_128_ofb_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aria_128_gcm_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aria_128_ccm_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aria_192_ecb_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aria_192_cbc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aria_192_cfb1_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aria_192_cfb8_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aria_192_cfb128_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aria_192_ctr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aria_192_ofb_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aria_192_gcm_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aria_192_ccm_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aria_256_ecb_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aria_256_cbc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aria_256_cfb1_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aria_256_cfb8_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aria_256_cfb128_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aria_256_ctr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aria_256_ofb_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aria_256_gcm_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_aria_256_ccm_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_camellia_128_ctr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_camellia_192_ctr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_camellia_256_ctr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_chacha20_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_chacha20_poly1305_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_sm4_ecb_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_sm4_cbc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_sm4_cfb128_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_sm4_ofb_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_sm4_ctr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_security_bits_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_set_alias_type_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_set1_engine_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_set1_engine_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_get0_engine_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_get0_engine_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_get0_hmac_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_get0_poly1305_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_get0_siphash_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_get0_RSA_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_get0_DSA_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_get0_DH_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_get0_EC_KEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_up_ref_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_set1_tls_encodedpoint_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_get1_tls_encodedpoint_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PBE_scrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PKCS5_v2_scrypt_keyivgen_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PBE_get_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_asn1_get_count_removed =  (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_asn1_get0_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_asn1_find_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_asn1_find_str_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_asn1_add0_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_asn1_add_alias_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_asn1_get0_info_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_get0_asn1_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_asn1_new_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_asn1_copy_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_asn1_free_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_asn1_set_public_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_asn1_set_private_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_asn1_set_param_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_asn1_set_free_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_asn1_set_ctrl_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_asn1_set_item_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_asn1_set_siginf_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_asn1_set_check_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_asn1_set_public_check_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_asn1_set_param_check_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_asn1_set_set_priv_key_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_asn1_set_set_pub_key_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_asn1_set_get_priv_key_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_asn1_set_get_pub_key_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_asn1_set_security_bits_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_asn1_set_siginf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_asn1_set_check_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_asn1_set_public_check_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_asn1_set_param_check_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_asn1_set_set_priv_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_asn1_set_set_pub_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_asn1_set_get_priv_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_asn1_set_get_pub_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_asn1_set_security_bits_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_meth_remove_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_meth_get_count_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_meth_get0_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_CTX_ctrl_uint64_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_CTX_str2ctrl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_CTX_hex2ctrl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_CTX_md_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_new_raw_private_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_new_raw_public_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_get_raw_private_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_get_raw_public_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_new_CMAC_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_check_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_public_check_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_param_check_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_meth_find_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_new_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_get0_info_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_copy_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_free_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_add0_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_remove_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_get_count_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_get0_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_set_init_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_set_copy_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_set_cleanup_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_set_paramgen_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_set_keygen_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_set_sign_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_set_verify_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_set_verify_recover_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_set_signctx_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_set_verifyctx_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_set_encrypt_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_set_decrypt_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_set_derive_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_set_ctrl_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_set_digestsign_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_meth_set_digestsign_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_set_digestverify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_meth_set_digestverify_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_set_check_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_meth_set_check_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_set_public_check_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_meth_set_public_check_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_set_param_check_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_meth_set_param_check_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_set_digest_custom_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_meth_set_digest_custom_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_get_init_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_get_copy_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_get_cleanup_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_get_paramgen_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_get_keygen_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_get_sign_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_get_verify_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_get_verify_recover_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_get_signctx_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_get_verifyctx_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_get_derive_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_get_encrypt_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_get_decrypt_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_get_ctrl_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_get_digestsign_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_meth_get_digestsign_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_get_digestverify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_meth_get_digestverify_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_get_check_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_meth_get_check_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_get_public_check_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_meth_get_public_check_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_get_param_check_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_meth_get_param_check_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_meth_get_digest_custom_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_meth_get_digest_custom_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_assign_RSA_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_assign_DSA_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_assign_DH_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_assign_EC_KEY_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_assign_SIPHASH_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_assign_POLY1305_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_type_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_pkey_type_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_size_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_block_size_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_flags_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_CTX_pkey_ctx_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_CTX_md_data_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_nid_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_get_nid_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_block_size_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_get_block_size_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_key_length_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_get_key_length_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_iv_length_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_get_iv_length_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_flags_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_get_flags_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_CTX_encrypting_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_CTX_nid_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_CTX_get_nid_introduced =  (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_CTX_block_size_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_CTX_get_block_size_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_CTX_key_length_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_CTX_get_key_length_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_CTX_iv_length_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_CTX_get_iv_length_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_CTX_num_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  BIO_set_md_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MD_CTX_init_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_MD_CTX_cleanup_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_md2_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_md4_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_md5_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_PKEY_id_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_base_id_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_bits_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_security_bits_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_size_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_set_alias_type_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_set1_tls_encodedpoint_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_PKEY_get1_tls_encodedpoint_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_type_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_get_type_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_CIPHER_get_mode_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  d2i_AutoPrivateKey_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OpenSSL_add_all_ciphers_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OpenSSL_add_all_digests_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EVP_cleanup_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  //* MAC Stuff
  EVP_MAC_fetch_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MAC_up_ref_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MAC_names_do_all_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MAC_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MAC_is_a_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MAC_get0_name_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MAC_get0_provider_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MAC_CTX_new_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MAC_CTX_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MAC_CTX_get_params_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MAC_CTX_set_params_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MAC_CTX_get0_mac_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_Q_mac_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MAC_init_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MAC_init_SKEY_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);
  EVP_MAC_update_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MAC_final_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MAC_finalXOF_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MAC_CTX_get_mac_size_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);
  EVP_MAC_CTX_get_block_size_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);
  EVP_MAC_do_all_provided_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);
  EVP_MAC_get0_description_introduced =  (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MAC_get_params_introduced =  (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EVP_MAC_CTX_dup_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

//# These 2 weren't found in the OpenSSL 1.1.1w binaries.  It's unclear if they
//were provided in that version of OpenSSL.
  i2d_KeyParams_bio_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  d2i_KeyParams_bio_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  BIO_f_reliable_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
//#  define EVP_PKEY_assign_RSA(pkey,rsa) EVP_PKEY_assign((pkey),EVP_PKEY_RSA, (char *)(rsa))
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
const
  EVP_PKEY_assign_RSA_procname = 'EVP_PKEY_assign_RSA'; {removed 1.0.0}
  EVP_PKEY_assign_DSA_procname = 'EVP_PKEY_assign_DSA'; {removed 1.0.0}
  EVP_PKEY_assign_DH_procname = 'EVP_PKEY_assign_DH'; {removed 1.0.0}
  EVP_PKEY_assign_EC_KEY_procname = 'EVP_PKEY_assign_EC_KEY'; {removed 1.0.0}
  EVP_PKEY_assign_SIPHASH_procname = 'EVP_PKEY_assign_SIPHASH'; {removed 1.0.0}
  EVP_PKEY_assign_POLY1305_procname = 'EVP_PKEY_assign_POLY1305'; {removed 1.0.0}

  EVP_MD_meth_new_procname = 'EVP_MD_meth_new'; {introduced 1.1.0}
  EVP_MD_meth_dup_procname = 'EVP_MD_meth_dup'; {introduced 1.1.0}
  EVP_MD_meth_free_procname = 'EVP_MD_meth_free'; {introduced 1.1.0}

  EVP_MD_meth_set_input_blocksize_procname = 'EVP_MD_meth_set_input_blocksize'; {introduced 1.1.0}
  EVP_MD_meth_set_result_size_procname = 'EVP_MD_meth_set_result_size'; {introduced 1.1.0}
  EVP_MD_meth_set_app_datasize_procname = 'EVP_MD_meth_set_app_datasize'; {introduced 1.1.0}
  EVP_MD_meth_set_flags_procname = 'EVP_MD_meth_set_flags'; {introduced 1.1.0}
  EVP_MD_meth_set_init_procname = 'EVP_MD_meth_set_init'; {introduced 1.1.0}
  EVP_MD_meth_set_update_procname = 'EVP_MD_meth_set_update'; {introduced 1.1.0}
  EVP_MD_meth_set_final_procname = 'EVP_MD_meth_set_final'; {introduced 1.1.0}
  EVP_MD_meth_set_copy_procname = 'EVP_MD_meth_set_copy'; {introduced 1.1.0}
  EVP_MD_meth_set_cleanup_procname = 'EVP_MD_meth_set_cleanup'; {introduced 1.1.0}
  EVP_MD_meth_set_ctrl_procname = 'EVP_MD_meth_set_ctrl'; {introduced 1.1.0}

  EVP_MD_meth_get_input_blocksize_procname = 'EVP_MD_meth_get_input_blocksize'; {introduced 1.1.0}
  EVP_MD_meth_get_result_size_procname = 'EVP_MD_meth_get_result_size'; {introduced 1.1.0}
  EVP_MD_meth_get_app_datasize_procname = 'EVP_MD_meth_get_app_datasize'; {introduced 1.1.0}
  EVP_MD_meth_get_flags_procname = 'EVP_MD_meth_get_flags'; {introduced 1.1.0}
  EVP_MD_meth_get_init_procname = 'EVP_MD_meth_get_init'; {introduced 1.1.0}
  EVP_MD_meth_get_update_procname = 'EVP_MD_meth_get_update'; {introduced 1.1.0}
  EVP_MD_meth_get_final_procname = 'EVP_MD_meth_get_final'; {introduced 1.1.0}
  EVP_MD_meth_get_copy_procname = 'EVP_MD_meth_get_copy'; {introduced 1.1.0}
  EVP_MD_meth_get_cleanup_procname = 'EVP_MD_meth_get_cleanup'; {introduced 1.1.0}
  EVP_MD_meth_get_ctrl_procname = 'EVP_MD_meth_get_ctrl'; {introduced 1.1.0}

  EVP_CIPHER_meth_new_procname = 'EVP_CIPHER_meth_new'; {introduced 1.1.0}
  EVP_CIPHER_meth_dup_procname = 'EVP_CIPHER_meth_dup'; {introduced 1.1.0}
  EVP_CIPHER_meth_free_procname = 'EVP_CIPHER_meth_free'; {introduced 1.1.0}

  EVP_CIPHER_meth_set_iv_length_procname = 'EVP_CIPHER_meth_set_iv_length'; {introduced 1.1.0}
  EVP_CIPHER_meth_set_flags_procname = 'EVP_CIPHER_meth_set_flags'; {introduced 1.1.0}
  EVP_CIPHER_meth_set_impl_ctx_size_procname = 'EVP_CIPHER_meth_set_impl_ctx_size'; {introduced 1.1.0}
  EVP_CIPHER_meth_set_init_procname = 'EVP_CIPHER_meth_set_init'; {introduced 1.1.0}
  EVP_CIPHER_meth_set_do_cipher_procname = 'EVP_CIPHER_meth_set_do_cipher'; {introduced 1.1.0}
  EVP_CIPHER_meth_set_cleanup_procname = 'EVP_CIPHER_meth_set_cleanup'; {introduced 1.1.0}
  EVP_CIPHER_meth_set_set_asn1_params_procname = 'EVP_CIPHER_meth_set_set_asn1_params'; {introduced 1.1.0}
  EVP_CIPHER_meth_set_get_asn1_params_procname = 'EVP_CIPHER_meth_set_get_asn1_params'; {introduced 1.1.0}
  EVP_CIPHER_meth_set_ctrl_procname = 'EVP_CIPHER_meth_set_ctrl'; {introduced 1.1.0}
  EVP_CIPHER_meth_get_init_procname = 'EVP_CIPHER_meth_get_init'; {introduced 1.1.0}
  EVP_CIPHER_meth_get_do_cipher_procname = 'EVP_CIPHER_meth_get_do_cipher'; {introduced 1.1.0}
  EVP_CIPHER_meth_get_cleanup_procname = 'EVP_CIPHER_meth_get_cleanup'; {introduced 1.1.0}
  EVP_CIPHER_meth_get_set_asn1_params_procname = 'EVP_CIPHER_meth_get_set_asn1_params'; {introduced 1.1.0}
  EVP_CIPHER_meth_get_get_asn1_params_procname = 'EVP_CIPHER_meth_get_get_asn1_params'; {introduced 1.1.0}
  EVP_CIPHER_meth_get_ctrl_procname = 'EVP_CIPHER_meth_get_ctrl'; {introduced 1.1.0}

  /// Add some extra combinations ///
  //# define EVP_get_digestbynid(a) EVP_get_digestbyname(OBJ_nid2sn(a));
  //# define EVP_get_digestbyobj(a) EVP_get_digestbynid(OBJ_obj2nid(a));
  //# define EVP_get_cipherbynid(a) EVP_get_cipherbyname(OBJ_nid2sn(a));
  //# define EVP_get_cipherbyobj(a) EVP_get_cipherbynid(OBJ_obj2nid(a));

  EVP_MD_type_procname = 'EVP_MD_type'; {removed 3.0.0}
  //# define EVP_MD_nid(e)                   EVP_MD_type(e)
  //# define EVP_MD_name(e)                  OBJ_nid2sn(EVP_MD_nid(e))
  EVP_MD_pkey_type_procname = 'EVP_MD_pkey_type'; {removed 3.0.0}
  EVP_MD_size_procname = 'EVP_MD_size'; {removed 3.0.0}
  EVP_MD_block_size_procname = 'EVP_MD_block_size'; {removed 3.0.0}
  EVP_MD_flags_procname = 'EVP_MD_flags'; {removed 3.0.0}

  EVP_MD_CTX_md_procname = 'EVP_MD_CTX_md';
  EVP_MD_CTX_update_fn_procname = 'EVP_MD_CTX_update_fn'; {introduced 1.1.0}
  EVP_MD_CTX_set_update_fn_procname = 'EVP_MD_CTX_set_update_fn'; {introduced 1.1.0}
  //  EVP_MD_CTX_size(e)              EVP_MD_size(EVP_MD_CTX_md(e))
  //  EVP_MD_CTX_block_size(e)        EVP_MD_block_size(EVP_MD_CTX_md(e))
  //  EVP_MD_CTX_type(e)              EVP_MD_type(EVP_MD_CTX_md(e))
  EVP_MD_CTX_pkey_ctx_procname = 'EVP_MD_CTX_pkey_ctx'; {introduced 1.1.0 removed 3.0.0}
  EVP_MD_CTX_set_pkey_ctx_procname = 'EVP_MD_CTX_set_pkey_ctx'; {introduced 1.1.0}
  EVP_MD_CTX_md_data_procname = 'EVP_MD_CTX_md_data'; {introduced 1.1.0 removed 3.0.0}

  EVP_CIPHER_nid_procname = 'EVP_CIPHER_nid'; {removed 3.0.0}
  EVP_CIPHER_get_nid_procname = 'EVP_CIPHER_get_nid'; {introduced 3.0.0}
  //# define EVP_CIPHER_name(e)              OBJ_nid2sn(EVP_CIPHER_nid(e))
  EVP_CIPHER_get0_name_procname = 'EVP_CIPHER_get0_name';  {introduced 3.0.0}
  EVP_CIPHER_block_size_procname = 'EVP_CIPHER_block_size'; {removed 3.0.0}
  EVP_CIPHER_get_block_size_procname = 'EVP_CIPHER_get_block_size'; {introduced 3.0.0}
  EVP_CIPHER_impl_ctx_size_procname = 'EVP_CIPHER_impl_ctx_size'; {introduced 1.1.0}
  EVP_CIPHER_key_length_procname = 'EVP_CIPHER_key_length'; {removed 3.0.0}
  EVP_CIPHER_get_key_length_procname = 'EVP_CIPHER_get_key_length'; {introduced 3.0.0}
  EVP_CIPHER_iv_length_procname = 'EVP_CIPHER_iv_length'; {removed 3.0.0}
  EVP_CIPHER_get_iv_length_procname = 'EVP_CIPHER_get_iv_length'; {introduced 3.0.0}
  EVP_CIPHER_flags_procname = 'EVP_CIPHER_flags'; {removed 3.0.0}
  EVP_CIPHER_get_flags_procname = 'EVP_CIPHER_get_flags'; {introduced 3.0.0}
  //# define EVP_CIPHER_mode(e)              (EVP_CIPHER_flags(e) & EVP_CIPH_MODE)

  EVP_CIPHER_CTX_cipher_procname = 'EVP_CIPHER_CTX_cipher';
  EVP_CIPHER_CTX_get0_cipher_procname = 'EVP_CIPHER_CTX_get0_cipher'; {introduced 3.0.0}
  EVP_CIPHER_CTX_encrypting_procname = 'EVP_CIPHER_CTX_encrypting'; {introduced 1.1.0 removed 3.0.0}
  EVP_CIPHER_CTX_is_encrypting_procname = 'EVP_CIPHER_CTX_is_encrypting'; {introduced 3.0.0}
  EVP_CIPHER_CTX_nid_procname = 'EVP_CIPHER_CTX_nid'; {removed 3.0.0}
  EVP_CIPHER_CTX_get_nid_procname = 'EVP_CIPHER_CTX_get_nid'; {introduced 3.0.0}
  EVP_CIPHER_CTX_block_size_procname = 'EVP_CIPHER_CTX_block_size'; {removed 3.0.0}
  EVP_CIPHER_CTX_get_block_size_procname = 'EVP_CIPHER_CTX_get_block_size'; {introduced 3.0.0}
  EVP_CIPHER_CTX_key_length_procname = 'EVP_CIPHER_CTX_key_length'; {removed 3.0.0}
  EVP_CIPHER_CTX_get_key_length_procname = 'EVP_CIPHER_CTX_get_key_length'; {introduced 3.0.0}
  EVP_CIPHER_CTX_iv_length_procname = 'EVP_CIPHER_CTX_iv_length'; {removed 3.0.0}
  EVP_CIPHER_CTX_get_iv_length_procname = 'EVP_CIPHER_CTX_get_iv_length'; {introduced 3.0.0}
  EVP_CIPHER_CTX_iv_procname = 'EVP_CIPHER_CTX_iv'; {introduced 1.1.0}
  EVP_CIPHER_CTX_original_iv_procname = 'EVP_CIPHER_CTX_original_iv'; {introduced 1.1.0}
  EVP_CIPHER_CTX_iv_noconst_procname = 'EVP_CIPHER_CTX_iv_noconst'; {introduced 1.1.0}
  EVP_CIPHER_CTX_buf_noconst_procname = 'EVP_CIPHER_CTX_buf_noconst'; {introduced 1.1.0}
  EVP_CIPHER_CTX_num_procname = 'EVP_CIPHER_CTX_num'; {introduced 1.1.0 removed 3.0.0}
  EVP_CIPHER_CTX_get_num_procname = 'EVP_CIPHER_CTX_get_num'; {introduced 3.0.0}
  EVP_CIPHER_CTX_set_num_procname = 'EVP_CIPHER_CTX_set_num'; {introduced 1.1.0}
  EVP_CIPHER_CTX_copy_procname = 'EVP_CIPHER_CTX_copy';
  EVP_CIPHER_CTX_get_app_data_procname = 'EVP_CIPHER_CTX_get_app_data';
  EVP_CIPHER_CTX_set_app_data_procname = 'EVP_CIPHER_CTX_set_app_data';
  EVP_CIPHER_CTX_get_cipher_data_procname = 'EVP_CIPHER_CTX_get_cipher_data'; {introduced 1.1.0}
  EVP_CIPHER_CTX_set_cipher_data_procname = 'EVP_CIPHER_CTX_set_cipher_data'; {introduced 1.1.0}
  EVP_CIPHER_CTX_tag_length_procname = 'EVP_CIPHER_CTX_tag_length'; {removed 3.0.0}
  EVP_CIPHER_CTX_get_tag_length_procname = 'EVP_CIPHER_CTX_get_tag_length'; {introduced 3.0.0}

  //# define EVP_CIPHER_CTX_type(c)         EVP_CIPHER_type(EVP_CIPHER_CTX_cipher(c))
  //# if OPENSSL_API_COMPAT < 0x10100000L
  //#  define EVP_CIPHER_CTX_flags(c)       EVP_CIPHER_flags(EVP_CIPHER_CTX_cipher(c))
  //# endif
  //# define EVP_CIPHER_CTX_mode(c)         EVP_CIPHER_mode(EVP_CIPHER_CTX_cipher(c))
  //
  //# define EVP_ENCODE_LENGTH(l)    ((((l)+2)/3*4)+((l)/48+1)*2+80)
  //# define EVP_DECODE_LENGTH(l)    (((l)+3)/4*3+80)
  //
  //# define EVP_SignInit_ex(a;b;c)          EVP_DigestInit_ex(a;b;c)
  //# define EVP_SignInit(a;b)               EVP_DigestInit(a;b)
  //# define EVP_SignUpdate(a;b;c)           EVP_DigestUpdate(a;b;c)
  //# define EVP_VerifyInit_ex(a;b;c)        EVP_DigestInit_ex(a;b;c)
  //# define EVP_VerifyInit(a;b)             EVP_DigestInit(a;b)
  //# define EVP_VerifyUpdate(a;b;c)         EVP_DigestUpdate(a;b;c)
  //# define EVP_OpenUpdate(a;b;c;d;e)       EVP_DecryptUpdate(a;b;c;d;e)
  //# define EVP_SealUpdate(a;b;c;d;e)       EVP_EncryptUpdate(a;b;c;d;e)
  //# define EVP_DigestSignUpdate(a;b;c)     EVP_DigestUpdate(a;b;c)
  //# define EVP_DigestVerifyUpdate(a;b;c)   EVP_DigestUpdate(a;b;c)

  BIO_set_md_procname = 'BIO_set_md'; {removed 1.0.0}
  //# define BIO_get_md(b;mdp)          BIO_ctrl(b;BIO_C_GET_MD;0;(PIdAnsiChar)(mdp))
  //# define BIO_get_md_ctx(b;mdcp)     BIO_ctrl(b;BIO_C_GET_MD_CTX;0; (PIdAnsiChar)(mdcp))
  //# define BIO_set_md_ctx(b;mdcp)     BIO_ctrl(b;BIO_C_SET_MD_CTX;0; (PIdAnsiChar)(mdcp))
  //# define BIO_get_cipher_status(b)   BIO_ctrl(b;BIO_C_GET_CIPHER_STATUS;0;NULL)
  //# define BIO_get_cipher_ctx(b;c_pp) BIO_ctrl(b;BIO_C_GET_CIPHER_CTX;0; (PIdAnsiChar)(c_pp))

  //function EVP_Cipher(c: PEVP_CIPHER_CTX; var out_; const in_; in1: TIdC_UINT): TIdC_INT;

  //# define EVP_add_cipher_alias(n;alias) OBJ_NAME_add((alias);OBJ_NAME_TYPE_CIPHER_METH|OBJ_NAME_ALIAS;(n))
  //# define EVP_add_digest_alias(n;alias) OBJ_NAME_add((alias);OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS;(n))
  //# define EVP_delete_cipher_alias(alias) OBJ_NAME_remove(alias;OBJ_NAME_TYPE_CIPHER_METH|OBJ_NAME_ALIAS);
  //# define EVP_delete_digest_alias(alias) OBJ_NAME_remove(alias;OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS);

  //void EVP_MD_CTX_init(EVP_MD_CTX *ctx);
  //int EVP_MD_CTX_cleanup(EVP_MD_CTX *ctx);
  EVP_MD_CTX_init_procname = 'EVP_MD_CTX_init'; {removed 1.1.0}
  EVP_MD_CTX_cleanup_procname = 'EVP_MD_CTX_cleanup'; {removed 1.1.0}

  EVP_MD_CTX_ctrl_procname = 'EVP_MD_CTX_ctrl'; {introduced 1.1.0}
  EVP_MD_CTX_new_procname = 'EVP_MD_CTX_new'; {introduced 1.1.0}
  EVP_MD_CTX_reset_procname = 'EVP_MD_CTX_reset'; {introduced 1.1.0}
  EVP_MD_CTX_free_procname = 'EVP_MD_CTX_free'; {introduced 1.1.0}
  //# define EVP_MD_CTX_create()     EVP_MD_CTX_new()
  //# define EVP_MD_CTX_init(ctx)    EVP_MD_CTX_reset((ctx))
  //# define EVP_MD_CTX_destroy(ctx) EVP_MD_CTX_free((ctx))
  EVP_MD_CTX_copy_ex_procname = 'EVP_MD_CTX_copy_ex';
  EVP_MD_CTX_set_flags_procname = 'EVP_MD_CTX_set_flags';
  EVP_MD_CTX_clear_flags_procname = 'EVP_MD_CTX_clear_flags';
  EVP_MD_CTX_test_flags_procname = 'EVP_MD_CTX_test_flags';
  EVP_DigestInit_ex_procname = 'EVP_DigestInit_ex';
  EVP_DigestUpdate_procname = 'EVP_DigestUpdate';
  EVP_DigestFinal_ex_procname = 'EVP_DigestFinal_ex';
  EVP_Digest_procname = 'EVP_Digest';

  EVP_MD_CTX_copy_procname = 'EVP_MD_CTX_copy';
  EVP_DigestInit_procname = 'EVP_DigestInit';
  EVP_DigestFinal_procname = 'EVP_DigestFinal';
  EVP_DigestFinalXOF_procname = 'EVP_DigestFinalXOF'; {introduced 1.1.0}

  EVP_read_pw_string_procname = 'EVP_read_pw_string';
  EVP_read_pw_string_min_procname = 'EVP_read_pw_string_min';
  EVP_set_pw_prompt_procname = 'EVP_set_pw_prompt';
  EVP_get_pw_prompt_procname = 'EVP_get_pw_prompt';
  EVP_BytesToKey_procname = 'EVP_BytesToKey';

  EVP_CIPHER_CTX_set_flags_procname = 'EVP_CIPHER_CTX_set_flags';
  EVP_CIPHER_CTX_clear_flags_procname = 'EVP_CIPHER_CTX_clear_flags';
  EVP_CIPHER_CTX_test_flags_procname = 'EVP_CIPHER_CTX_test_flags';

  EVP_EncryptInit_procname = 'EVP_EncryptInit';
  EVP_EncryptInit_ex_procname = 'EVP_EncryptInit_ex';
  EVP_EncryptUpdate_procname = 'EVP_EncryptUpdate';
  EVP_EncryptFinal_ex_procname = 'EVP_EncryptFinal_ex';
  EVP_EncryptFinal_procname = 'EVP_EncryptFinal';

  EVP_DecryptInit_procname = 'EVP_DecryptInit';
  EVP_DecryptInit_ex_procname = 'EVP_DecryptInit_ex';
  EVP_DecryptUpdate_procname = 'EVP_DecryptUpdate';
  EVP_DecryptFinal_procname = 'EVP_DecryptFinal';
  EVP_DecryptFinal_ex_procname = 'EVP_DecryptFinal_ex';

  EVP_CipherInit_procname = 'EVP_CipherInit';
  EVP_CipherInit_ex_procname = 'EVP_CipherInit_ex';
  EVP_CipherUpdate_procname = 'EVP_CipherUpdate';
  EVP_CipherFinal_procname = 'EVP_CipherFinal';
  EVP_CipherFinal_ex_procname = 'EVP_CipherFinal_ex';

  EVP_SignFinal_procname = 'EVP_SignFinal';

  EVP_DigestSign_procname = 'EVP_DigestSign'; {introduced 1.1.0}

  EVP_VerifyFinal_procname = 'EVP_VerifyFinal';

  EVP_DigestVerify_procname = 'EVP_DigestVerify'; {introduced 1.1.0}

  EVP_DigestSignInit_procname = 'EVP_DigestSignInit';
  EVP_DigestSignFinal_procname = 'EVP_DigestSignFinal';

  EVP_DigestVerifyInit_procname = 'EVP_DigestVerifyInit';
  EVP_DigestVerifyFinal_procname = 'EVP_DigestVerifyFinal';

  EVP_OpenInit_procname = 'EVP_OpenInit';
  EVP_OpenFinal_procname = 'EVP_OpenFinal';

  EVP_SealInit_procname = 'EVP_SealInit';
  EVP_SealFinal_procname = 'EVP_SealFinal';

  EVP_ENCODE_CTX_new_procname = 'EVP_ENCODE_CTX_new'; {introduced 1.1.0}
  EVP_ENCODE_CTX_free_procname = 'EVP_ENCODE_CTX_free'; {introduced 1.1.0}
  EVP_ENCODE_CTX_copy_procname = 'EVP_ENCODE_CTX_copy'; {introduced 1.1.0}
  EVP_ENCODE_CTX_num_procname = 'EVP_ENCODE_CTX_num'; {introduced 1.1.0}
  EVP_EncodeInit_procname = 'EVP_EncodeInit';
  EVP_EncodeUpdate_procname = 'EVP_EncodeUpdate';
  EVP_EncodeFinal_procname = 'EVP_EncodeFinal';
  EVP_EncodeBlock_procname = 'EVP_EncodeBlock';

  EVP_DecodeInit_procname = 'EVP_DecodeInit';
  EVP_DecodeUpdate_procname = 'EVP_DecodeUpdate';
  EVP_DecodeFinal_procname = 'EVP_DecodeFinal';
  EVP_DecodeBlock_procname = 'EVP_DecodeBlock';

  EVP_CIPHER_fetch_procname = 'EVP_CIPHER_fetch';
  EVP_CIPHER_free_procname = 'EVP_CIPHER_free';
  EVP_CIPHER_CTX_new_procname = 'EVP_CIPHER_CTX_new';
  EVP_CIPHER_CTX_reset_procname = 'EVP_CIPHER_CTX_reset'; {introduced 1.1.0}
  EVP_CIPHER_CTX_free_procname = 'EVP_CIPHER_CTX_free';
  EVP_CIPHER_CTX_set_key_length_procname = 'EVP_CIPHER_CTX_set_key_length';
  EVP_CIPHER_CTX_set_padding_procname = 'EVP_CIPHER_CTX_set_padding';
  EVP_CIPHER_CTX_ctrl_procname = 'EVP_CIPHER_CTX_ctrl';
  EVP_CIPHER_CTX_rand_key_procname = 'EVP_CIPHER_CTX_rand_key';

  BIO_f_md_procname = 'BIO_f_md';
  BIO_f_base64_procname = 'BIO_f_base64';
  BIO_f_cipher_procname = 'BIO_f_cipher';
  BIO_f_reliable_procname = 'BIO_f_reliable';
  BIO_set_cipher_procname = 'BIO_set_cipher';

  EVP_md_null_procname = 'EVP_md_null';

  EVP_md2_procname = 'EVP_md2'; {removed 1.1.0 allow_nil}
  EVP_md4_procname = 'EVP_md4'; {removed 1.1.0 allow_nil}
  EVP_md5_procname = 'EVP_md5'; {removed 1.1.0 allow_nil}
  EVP_md5_sha1_procname = 'EVP_md5_sha1'; {introduced 1.1.0}

  EVP_sha1_procname = 'EVP_sha1';
  EVP_sha224_procname = 'EVP_sha224';
  EVP_sha256_procname = 'EVP_sha256';
  EVP_sha384_procname = 'EVP_sha384';
  EVP_sha512_procname = 'EVP_sha512';
  EVP_sha512_224_procname = 'EVP_sha512_224'; {introduced 1.1.0}
  EVP_sha512_256_procname = 'EVP_sha512_256'; {introduced 1.1.0}
  EVP_sha3_224_procname = 'EVP_sha3_224'; {introduced 1.1.0}
  EVP_sha3_256_procname = 'EVP_sha3_256'; {introduced 1.1.0}
  EVP_sha3_384_procname = 'EVP_sha3_384'; {introduced 1.1.0}
  EVP_sha3_512_procname = 'EVP_sha3_512'; {introduced 1.1.0}
  EVP_shake128_procname = 'EVP_shake128'; {introduced 1.1.0}
  EVP_shake256_procname = 'EVP_shake256'; {introduced 1.1.0}

  (* does nothing :-) *)
  EVP_enc_null_procname = 'EVP_enc_null';

  EVP_des_ecb_procname = 'EVP_des_ecb';
  EVP_des_ede_procname = 'EVP_des_ede';
  EVP_des_ede3_procname = 'EVP_des_ede3';
  EVP_des_ede_ecb_procname = 'EVP_des_ede_ecb';
  EVP_des_ede3_ecb_procname = 'EVP_des_ede3_ecb';
  EVP_des_cfb64_procname = 'EVP_des_cfb64';
  //EVP_des_cfb EVP_des_cfb64
  EVP_des_cfb1_procname = 'EVP_des_cfb1';
  EVP_des_cfb8_procname = 'EVP_des_cfb8';
  EVP_des_ede_cfb64_procname = 'EVP_des_ede_cfb64';
  EVP_des_ede3_cfb64_procname = 'EVP_des_ede3_cfb64';
  //EVP_des_ede3_cfb EVP_des_ede3_cfb64
  EVP_des_ede3_cfb1_procname = 'EVP_des_ede3_cfb1';
  EVP_des_ede3_cfb8_procname = 'EVP_des_ede3_cfb8';
  EVP_des_ofb_procname = 'EVP_des_ofb';
  EVP_des_ede_ofb_procname = 'EVP_des_ede_ofb';
  EVP_des_ede3_ofb_procname = 'EVP_des_ede3_ofb';
  EVP_des_cbc_procname = 'EVP_des_cbc';
  EVP_des_ede_cbc_procname = 'EVP_des_ede_cbc';
  EVP_des_ede3_cbc_procname = 'EVP_des_ede3_cbc';
  EVP_desx_cbc_procname = 'EVP_desx_cbc';
  EVP_des_ede3_wrap_procname = 'EVP_des_ede3_wrap';
  //
  // This should now be supported through the dev_crypto ENGINE. But also, why
  // are rc4 and md5 declarations made here inside a "NO_DES" precompiler
  // branch?
  //
  EVP_rc4_procname = 'EVP_rc4';
  EVP_rc4_40_procname = 'EVP_rc4_40';
//  function EVP_idea_ecb: PEVP_CIPHER;
// function EVP_idea_cfb64: PEVP_CIPHER;
  //EVP_idea_cfb EVP_idea_cfb64
//  function EVP_idea_ofb: PEVP_CIPHER;
 // function EVP_idea_cbc: PEVP_CIPHER;
  EVP_rc2_ecb_procname = 'EVP_rc2_ecb';
  EVP_rc2_cbc_procname = 'EVP_rc2_cbc';
  EVP_rc2_40_cbc_procname = 'EVP_rc2_40_cbc';
  EVP_rc2_64_cbc_procname = 'EVP_rc2_64_cbc';
  EVP_rc2_cfb64_procname = 'EVP_rc2_cfb64';
  //EVP_rc2_cfb EVP_rc2_cfb64
  EVP_rc2_ofb_procname = 'EVP_rc2_ofb';
  EVP_bf_ecb_procname = 'EVP_bf_ecb';
  EVP_bf_cbc_procname = 'EVP_bf_cbc';
  EVP_bf_cfb64_procname = 'EVP_bf_cfb64';
  //EVP_bf_cfb EVP_bf_cfb64
  EVP_bf_ofb_procname = 'EVP_bf_ofb';
  EVP_cast5_ecb_procname = 'EVP_cast5_ecb';
  EVP_cast5_cbc_procname = 'EVP_cast5_cbc';
  EVP_cast5_cfb64_procname = 'EVP_cast5_cfb64';
  //EVP_cast5_cfb EVP_cast5_cfb64
  EVP_cast5_ofb_procname = 'EVP_cast5_ofb';
//  function EVP_rc5_32_12_16_cbc: PEVP_CIPHER;
//  function EVP_rc5_32_12_16_ecb: PEVP_CIPHER;
//  function EVP_rc5_32_12_16_cfb64: PEVP_CIPHER;
  //EVP_rc5_32_12_16_cfb EVP_rc5_32_12_16_cfb64
//  function EVP_rc5_32_12_16_ofb: PEVP_CIPHER;

  EVP_aes_128_ecb_procname = 'EVP_aes_128_ecb';
  EVP_aes_128_cbc_procname = 'EVP_aes_128_cbc';
  EVP_aes_128_cfb1_procname = 'EVP_aes_128_cfb1';
  EVP_aes_128_cfb8_procname = 'EVP_aes_128_cfb8';
  EVP_aes_128_cfb128_procname = 'EVP_aes_128_cfb128';
  //EVP_aes_128_cfb EVP_aes_128_cfb128
  EVP_aes_128_ofb_procname = 'EVP_aes_128_ofb';
  EVP_aes_128_ctr_procname = 'EVP_aes_128_ctr';
  EVP_aes_128_ccm_procname = 'EVP_aes_128_ccm';
  EVP_aes_128_gcm_procname = 'EVP_aes_128_gcm';
  EVP_aes_128_xts_procname = 'EVP_aes_128_xts';
  EVP_aes_128_wrap_procname = 'EVP_aes_128_wrap';
  EVP_aes_128_wrap_pad_procname = 'EVP_aes_128_wrap_pad'; {introduced 1.1.0}
  EVP_aes_128_ocb_procname = 'EVP_aes_128_ocb'; {introduced 1.1.0}
  EVP_aes_192_ecb_procname = 'EVP_aes_192_ecb';
  EVP_aes_192_cbc_procname = 'EVP_aes_192_cbc';
  EVP_aes_192_cfb1_procname = 'EVP_aes_192_cfb1';
  EVP_aes_192_cfb8_procname = 'EVP_aes_192_cfb8';
  EVP_aes_192_cfb128_procname = 'EVP_aes_192_cfb128';
  //EVP_aes_192_cfb EVP_aes_192_cfb128
  EVP_aes_192_ofb_procname = 'EVP_aes_192_ofb';
  EVP_aes_192_ctr_procname = 'EVP_aes_192_ctr';
  EVP_aes_192_ccm_procname = 'EVP_aes_192_ccm';
  EVP_aes_192_gcm_procname = 'EVP_aes_192_gcm';
  EVP_aes_192_wrap_procname = 'EVP_aes_192_wrap';
  EVP_aes_192_wrap_pad_procname = 'EVP_aes_192_wrap_pad'; {introduced 1.1.0}
  EVP_aes_192_ocb_procname = 'EVP_aes_192_ocb'; {introduced 1.1.0}
  EVP_aes_256_ecb_procname = 'EVP_aes_256_ecb';
  EVP_aes_256_cbc_procname = 'EVP_aes_256_cbc';
  EVP_aes_256_cfb1_procname = 'EVP_aes_256_cfb1';
  EVP_aes_256_cfb8_procname = 'EVP_aes_256_cfb8';
  EVP_aes_256_cfb128_procname = 'EVP_aes_256_cfb128';
  //EVP_aes_256_cfb EVP_aes_256_cfb128
  EVP_aes_256_ofb_procname = 'EVP_aes_256_ofb';
  EVP_aes_256_ctr_procname = 'EVP_aes_256_ctr';
  EVP_aes_256_ccm_procname = 'EVP_aes_256_ccm';
  EVP_aes_256_gcm_procname = 'EVP_aes_256_gcm';
  EVP_aes_256_xts_procname = 'EVP_aes_256_xts';
  EVP_aes_256_wrap_procname = 'EVP_aes_256_wrap';
  EVP_aes_256_wrap_pad_procname = 'EVP_aes_256_wrap_pad'; {introduced 1.1.0}
  EVP_aes_256_ocb_procname = 'EVP_aes_256_ocb'; {introduced 1.1.0}
  EVP_aes_128_cbc_hmac_sha1_procname = 'EVP_aes_128_cbc_hmac_sha1';
  EVP_aes_256_cbc_hmac_sha1_procname = 'EVP_aes_256_cbc_hmac_sha1';
  EVP_aes_128_cbc_hmac_sha256_procname = 'EVP_aes_128_cbc_hmac_sha256';
  EVP_aes_256_cbc_hmac_sha256_procname = 'EVP_aes_256_cbc_hmac_sha256';

  EVP_aria_128_ecb_procname = 'EVP_aria_128_ecb'; {introduced 1.1.0}
  EVP_aria_128_cbc_procname = 'EVP_aria_128_cbc'; {introduced 1.1.0}
  EVP_aria_128_cfb1_procname = 'EVP_aria_128_cfb1'; {introduced 1.1.0}
  EVP_aria_128_cfb8_procname = 'EVP_aria_128_cfb8'; {introduced 1.1.0}
  EVP_aria_128_cfb128_procname = 'EVP_aria_128_cfb128'; {introduced 1.1.0}
  EVP_aria_128_ctr_procname = 'EVP_aria_128_ctr'; {introduced 1.1.0}
  EVP_aria_128_ofb_procname = 'EVP_aria_128_ofb'; {introduced 1.1.0}
  EVP_aria_128_gcm_procname = 'EVP_aria_128_gcm'; {introduced 1.1.0}
  EVP_aria_128_ccm_procname = 'EVP_aria_128_ccm'; {introduced 1.1.0}
  EVP_aria_192_ecb_procname = 'EVP_aria_192_ecb'; {introduced 1.1.0}
  EVP_aria_192_cbc_procname = 'EVP_aria_192_cbc'; {introduced 1.1.0}
  EVP_aria_192_cfb1_procname = 'EVP_aria_192_cfb1'; {introduced 1.1.0}
  EVP_aria_192_cfb8_procname = 'EVP_aria_192_cfb8'; {introduced 1.1.0}
  EVP_aria_192_cfb128_procname = 'EVP_aria_192_cfb128'; {introduced 1.1.0}
  //EVP_aria_192_cfb EVP_aria_192_cfb128
  EVP_aria_192_ctr_procname = 'EVP_aria_192_ctr'; {introduced 1.1.0}
  EVP_aria_192_ofb_procname = 'EVP_aria_192_ofb'; {introduced 1.1.0}
  EVP_aria_192_gcm_procname = 'EVP_aria_192_gcm'; {introduced 1.1.0}
  EVP_aria_192_ccm_procname = 'EVP_aria_192_ccm'; {introduced 1.1.0}
  EVP_aria_256_ecb_procname = 'EVP_aria_256_ecb'; {introduced 1.1.0}
  EVP_aria_256_cbc_procname = 'EVP_aria_256_cbc'; {introduced 1.1.0}
  EVP_aria_256_cfb1_procname = 'EVP_aria_256_cfb1'; {introduced 1.1.0}
  EVP_aria_256_cfb8_procname = 'EVP_aria_256_cfb8'; {introduced 1.1.0}
  EVP_aria_256_cfb128_procname = 'EVP_aria_256_cfb128'; {introduced 1.1.0}
  //EVP_aria_256_cfb EVP_aria_256_cfb128
  EVP_aria_256_ctr_procname = 'EVP_aria_256_ctr'; {introduced 1.1.0}
  EVP_aria_256_ofb_procname = 'EVP_aria_256_ofb'; {introduced 1.1.0}
  EVP_aria_256_gcm_procname = 'EVP_aria_256_gcm'; {introduced 1.1.0}
  EVP_aria_256_ccm_procname = 'EVP_aria_256_ccm'; {introduced 1.1.0}

  EVP_camellia_128_ecb_procname = 'EVP_camellia_128_ecb';
  EVP_camellia_128_cbc_procname = 'EVP_camellia_128_cbc';
  EVP_camellia_128_cfb1_procname = 'EVP_camellia_128_cfb1';
  EVP_camellia_128_cfb8_procname = 'EVP_camellia_128_cfb8';
  EVP_camellia_128_cfb128_procname = 'EVP_camellia_128_cfb128';
  //EVP_camellia_128_cfb EVP_camellia_128_cfb128
  EVP_camellia_128_ofb_procname = 'EVP_camellia_128_ofb';
  EVP_camellia_128_ctr_procname = 'EVP_camellia_128_ctr'; {introduced 1.1.0}
  EVP_camellia_192_ecb_procname = 'EVP_camellia_192_ecb';
  EVP_camellia_192_cbc_procname = 'EVP_camellia_192_cbc';
  EVP_camellia_192_cfb1_procname = 'EVP_camellia_192_cfb1';
  EVP_camellia_192_cfb8_procname = 'EVP_camellia_192_cfb8';
  EVP_camellia_192_cfb128_procname = 'EVP_camellia_192_cfb128';
  //EVP_camellia_192_cfb EVP_camellia_192_cfb128
  EVP_camellia_192_ofb_procname = 'EVP_camellia_192_ofb';
  EVP_camellia_192_ctr_procname = 'EVP_camellia_192_ctr'; {introduced 1.1.0}
  EVP_camellia_256_ecb_procname = 'EVP_camellia_256_ecb';
  EVP_camellia_256_cbc_procname = 'EVP_camellia_256_cbc';
  EVP_camellia_256_cfb1_procname = 'EVP_camellia_256_cfb1';
  EVP_camellia_256_cfb8_procname = 'EVP_camellia_256_cfb8';
  EVP_camellia_256_cfb128_procname = 'EVP_camellia_256_cfb128';
  //EVP_camellia_256_cfb EVP_camellia_256_cfb128
  EVP_camellia_256_ofb_procname = 'EVP_camellia_256_ofb';
  EVP_camellia_256_ctr_procname = 'EVP_camellia_256_ctr'; {introduced 1.1.0}

  EVP_chacha20_procname = 'EVP_chacha20'; {introduced 1.1.0}
  EVP_chacha20_poly1305_procname = 'EVP_chacha20_poly1305'; {introduced 1.1.0}

  EVP_seed_ecb_procname = 'EVP_seed_ecb';
  EVP_seed_cbc_procname = 'EVP_seed_cbc';
  EVP_seed_cfb128_procname = 'EVP_seed_cfb128';
  //EVP_seed_cfb EVP_seed_cfb128
  EVP_seed_ofb_procname = 'EVP_seed_ofb';

  EVP_sm4_ecb_procname = 'EVP_sm4_ecb'; {introduced 1.1.0}
  EVP_sm4_cbc_procname = 'EVP_sm4_cbc'; {introduced 1.1.0}
  EVP_sm4_cfb128_procname = 'EVP_sm4_cfb128'; {introduced 1.1.0}
  //EVP_sm4_cfb EVP_sm4_cfb128
  EVP_sm4_ofb_procname = 'EVP_sm4_ofb'; {introduced 1.1.0}
  EVP_sm4_ctr_procname = 'EVP_sm4_ctr'; {introduced 1.1.0}

  EVP_add_cipher_procname = 'EVP_add_cipher';
  EVP_add_digest_procname = 'EVP_add_digest';

  EVP_get_cipherbyname_procname = 'EVP_get_cipherbyname';
  EVP_get_digestbyname_procname = 'EVP_get_digestbyname';

  EVP_CIPHER_do_all_procname = 'EVP_CIPHER_do_all';
  EVP_CIPHER_do_all_sorted_procname = 'EVP_CIPHER_do_all_sorted';

  EVP_MD_do_all_procname = 'EVP_MD_do_all';
  EVP_MD_do_all_sorted_procname = 'EVP_MD_do_all_sorted';

  EVP_PKEY_decrypt_old_procname = 'EVP_PKEY_decrypt_old';
  EVP_PKEY_encrypt_old_procname = 'EVP_PKEY_encrypt_old';
  EVP_PKEY_type_procname = 'EVP_PKEY_type';
  EVP_PKEY_id_procname = 'EVP_PKEY_id'; {removed 3.0.0}
  EVP_PKEY_base_id_procname = 'EVP_PKEY_base_id'; {removed 3.0.0}
  EVP_PKEY_get_base_id_procname = 'EVP_PKEY_get_base_id';  {introduced 3.0.0}
  EVP_PKEY_bits_procname = 'EVP_PKEY_bits'; {removed 3.0.0}
  EVP_PKEY_get_bits_procname = 'EVP_PKEY_get_bits';  {introduced 3.0.0}
  EVP_PKEY_security_bits_procname = 'EVP_PKEY_security_bits'; {introduced 1.1.0 removed 3.0.0}
  EVP_PKEY_get_security_bits_procname = 'EVP_PKEY_get_security_bits';  {introduced 3.0.0}
  EVP_PKEY_size_procname = 'EVP_PKEY_size'; {removed 3.0.0}
  EVP_PKEY_get_size_procname = 'EVP_PKEY_get_size';  {introduced 3.0.0}
  EVP_PKEY_set_type_procname = 'EVP_PKEY_set_type';
  EVP_PKEY_set_type_str_procname = 'EVP_PKEY_set_type_str';
  EVP_PKEY_set_alias_type_procname = 'EVP_PKEY_set_alias_type'; {introduced 1.1.0 removed 3.0.0}

  EVP_PKEY_set1_engine_procname = 'EVP_PKEY_set1_engine'; {introduced 1.1.0}
  EVP_PKEY_get0_engine_procname = 'EVP_PKEY_get0_engine'; {introduced 1.1.0}

  EVP_PKEY_assign_procname = 'EVP_PKEY_assign';
  EVP_PKEY_get0_procname = 'EVP_PKEY_get0';
  EVP_PKEY_get0_hmac_procname = 'EVP_PKEY_get0_hmac'; {introduced 1.1.0}
  EVP_PKEY_get0_poly1305_procname = 'EVP_PKEY_get0_poly1305'; {introduced 1.1.0}
  EVP_PKEY_get0_siphash_procname = 'EVP_PKEY_get0_siphash'; {introduced 1.1.0}

  EVP_PKEY_set1_RSA_procname = 'EVP_PKEY_set1_RSA';
  EVP_PKEY_get0_RSA_procname = 'EVP_PKEY_get0_RSA'; {introduced 1.1.0}
  EVP_PKEY_get1_RSA_procname = 'EVP_PKEY_get1_RSA';

  EVP_PKEY_set1_DSA_procname = 'EVP_PKEY_set1_DSA';
  EVP_PKEY_get0_DSA_procname = 'EVP_PKEY_get0_DSA'; {introduced 1.1.0}
  EVP_PKEY_get1_DSA_procname = 'EVP_PKEY_get1_DSA';

  EVP_PKEY_set1_DH_procname = 'EVP_PKEY_set1_DH';
  EVP_PKEY_get0_DH_procname = 'EVP_PKEY_get0_DH'; {introduced 1.1.0}
  EVP_PKEY_get1_DH_procname = 'EVP_PKEY_get1_DH';

  EVP_PKEY_set1_EC_KEY_procname = 'EVP_PKEY_set1_EC_KEY';
  EVP_PKEY_get0_EC_KEY_procname = 'EVP_PKEY_get0_EC_KEY'; {introduced 1.1.0}
  EVP_PKEY_get1_EC_KEY_procname = 'EVP_PKEY_get1_EC_KEY';

  EVP_PKEY_new_procname = 'EVP_PKEY_new';
  EVP_PKEY_up_ref_procname = 'EVP_PKEY_up_ref'; {introduced 1.1.0}
  EVP_PKEY_free_procname = 'EVP_PKEY_free';

  d2i_PublicKey_procname = 'd2i_PublicKey';
  i2d_PublicKey_procname = 'i2d_PublicKey';

  d2i_PrivateKey_procname = 'd2i_PrivateKey';
  d2i_AutoPrivateKey_procname = 'd2i_AutoPrivateKey';
  d2i_AutoPrivateKey_ex_procname = 'd2i_AutoPrivateKey_ex';
  i2d_PrivateKey_procname = 'i2d_PrivateKey';

  i2d_KeyParams_bio_procname = 'i2d_KeyParams_bio';
  d2i_KeyParams_bio_procname = 'd2i_KeyParams_bio';

  EVP_PKEY_copy_parameters_procname = 'EVP_PKEY_copy_parameters';
  EVP_PKEY_missing_parameters_procname = 'EVP_PKEY_missing_parameters';
  EVP_PKEY_save_parameters_procname = 'EVP_PKEY_save_parameters';
  EVP_PKEY_cmp_parameters_procname = 'EVP_PKEY_cmp_parameters';

  EVP_PKEY_cmp_procname = 'EVP_PKEY_cmp';

  EVP_PKEY_print_public_procname = 'EVP_PKEY_print_public';
  EVP_PKEY_print_private_procname = 'EVP_PKEY_print_private';
  EVP_PKEY_print_params_procname = 'EVP_PKEY_print_params';


  EVP_PKEY_get_default_digest_nid_procname = 'EVP_PKEY_get_default_digest_nid';

  EVP_PKEY_set1_tls_encodedpoint_procname = 'EVP_PKEY_set1_tls_encodedpoint'; {introduced 1.1.0 removed 3.0.0}
  EVP_PKEY_get1_tls_encodedpoint_procname = 'EVP_PKEY_get1_tls_encodedpoint'; {introduced 1.1.0 removed 3.0.0}

  EVP_CIPHER_type_procname = 'EVP_CIPHER_type'; {removed 3.0.0}
  EVP_CIPHER_get_type_procname = 'EVP_CIPHER_get_type'; {remove 3.0.0}

  (* calls methods *)
  EVP_CIPHER_param_to_asn1_procname = 'EVP_CIPHER_param_to_asn1';
  EVP_CIPHER_asn1_to_param_procname = 'EVP_CIPHER_asn1_to_param';

  (* These are used by EVP_CIPHER methods *)
  EVP_CIPHER_set_asn1_iv_procname = 'EVP_CIPHER_set_asn1_iv';
  EVP_CIPHER_get_asn1_iv_procname = 'EVP_CIPHER_get_asn1_iv';

  EVP_CIPHER_get_mode_procname = 'EVP_CIPHER_get_mode'; {introduced 3.0.0}
  (* PKCS5 password based encryption *)
  PKCS5_PBE_keyivgen_procname = 'PKCS5_PBE_keyivgen';
  PKCS5_PBKDF2_HMAC_SHA1_procname = 'PKCS5_PBKDF2_HMAC_SHA1';
  PKCS5_PBKDF2_HMAC_procname = 'PKCS5_PBKDF2_HMAC';
  PKCS5_v2_PBE_keyivgen_procname = 'PKCS5_v2_PBE_keyivgen';

  EVP_PBE_scrypt_procname = 'EVP_PBE_scrypt'; {introduced 1.1.0}

  PKCS5_v2_scrypt_keyivgen_procname = 'PKCS5_v2_scrypt_keyivgen'; {introduced 1.1.0}

  PKCS5_PBE_add_procname = 'PKCS5_PBE_add';

  EVP_PBE_CipherInit_procname = 'EVP_PBE_CipherInit';

  (* PBE type *)
  EVP_PBE_alg_add_type_procname = 'EVP_PBE_alg_add_type';
  EVP_PBE_alg_add_procname = 'EVP_PBE_alg_add';
  EVP_PBE_find_procname = 'EVP_PBE_find';
  EVP_PBE_cleanup_procname = 'EVP_PBE_cleanup';
  EVP_PBE_get_procname = 'EVP_PBE_get'; {introduced 1.1.0}

  EVP_PKEY_asn1_get_count_procname = 'EVP_PKEY_asn1_get_count';
  EVP_PKEY_asn1_get0_procname = 'EVP_PKEY_asn1_get0';
  EVP_PKEY_asn1_find_procname = 'EVP_PKEY_asn1_find';
  EVP_PKEY_asn1_find_str_procname = 'EVP_PKEY_asn1_find_str';
  EVP_PKEY_asn1_add0_procname = 'EVP_PKEY_asn1_add0';
  EVP_PKEY_asn1_add_alias_procname = 'EVP_PKEY_asn1_add_alias';
  EVP_PKEY_asn1_get0_info_procname = 'EVP_PKEY_asn1_get0_info';

  EVP_PKEY_get0_asn1_procname = 'EVP_PKEY_get0_asn1';
  EVP_PKEY_asn1_new_procname = 'EVP_PKEY_asn1_new';
  EVP_PKEY_asn1_copy_procname = 'EVP_PKEY_asn1_copy';
  EVP_PKEY_asn1_free_procname = 'EVP_PKEY_asn1_free';

  EVP_PKEY_asn1_set_public_procname = 'EVP_PKEY_asn1_set_public';
  EVP_PKEY_asn1_set_private_procname = 'EVP_PKEY_asn1_set_private';
  EVP_PKEY_asn1_set_param_procname = 'EVP_PKEY_asn1_set_param';

  EVP_PKEY_asn1_set_free_procname = 'EVP_PKEY_asn1_set_free';
  EVP_PKEY_asn1_set_ctrl_procname = 'EVP_PKEY_asn1_set_ctrl';
  EVP_PKEY_asn1_set_item_procname = 'EVP_PKEY_asn1_set_item';

  EVP_PKEY_asn1_set_siginf_procname = 'EVP_PKEY_asn1_set_siginf'; {introduced 1.1.0}

  EVP_PKEY_asn1_set_check_procname = 'EVP_PKEY_asn1_set_check'; {introduced 1.1.0}

  EVP_PKEY_asn1_set_public_check_procname = 'EVP_PKEY_asn1_set_public_check'; {introduced 1.1.0}

  EVP_PKEY_asn1_set_param_check_procname = 'EVP_PKEY_asn1_set_param_check'; {introduced 1.1.0}

  EVP_PKEY_asn1_set_set_priv_key_procname = 'EVP_PKEY_asn1_set_set_priv_key'; {introduced 1.1.0}
  EVP_PKEY_asn1_set_set_pub_key_procname = 'EVP_PKEY_asn1_set_set_pub_key'; {introduced 1.1.0}
  EVP_PKEY_asn1_set_get_priv_key_procname = 'EVP_PKEY_asn1_set_get_priv_key'; {introduced 1.1.0}
  EVP_PKEY_asn1_set_get_pub_key_procname = 'EVP_PKEY_asn1_set_get_pub_key'; {introduced 1.1.0}

  EVP_PKEY_asn1_set_security_bits_procname = 'EVP_PKEY_asn1_set_security_bits'; {introduced 1.1.0}

  EVP_PKEY_meth_find_procname = 'EVP_PKEY_meth_find';
  EVP_PKEY_meth_new_procname = 'EVP_PKEY_meth_new';
  EVP_PKEY_meth_get0_info_procname = 'EVP_PKEY_meth_get0_info';
  EVP_PKEY_meth_copy_procname = 'EVP_PKEY_meth_copy';
  EVP_PKEY_meth_free_procname = 'EVP_PKEY_meth_free';
  EVP_PKEY_meth_add0_procname = 'EVP_PKEY_meth_add0';
  EVP_PKEY_meth_remove_procname = 'EVP_PKEY_meth_remove'; {introduced 1.1.0}
  EVP_PKEY_meth_get_count_procname = 'EVP_PKEY_meth_get_count'; {introduced 1.1.0}
  EVP_PKEY_meth_get0_procname = 'EVP_PKEY_meth_get0'; {introduced 1.1.0}

  EVP_PKEY_CTX_new_procname = 'EVP_PKEY_CTX_new';
  EVP_PKEY_CTX_new_id_procname = 'EVP_PKEY_CTX_new_id';
  EVP_PKEY_CTX_dup_procname = 'EVP_PKEY_CTX_dup';
  EVP_PKEY_CTX_free_procname = 'EVP_PKEY_CTX_free';

  EVP_PKEY_CTX_ctrl_procname = 'EVP_PKEY_CTX_ctrl';
  EVP_PKEY_CTX_ctrl_str_procname = 'EVP_PKEY_CTX_ctrl_str';
  EVP_PKEY_CTX_ctrl_uint64_procname = 'EVP_PKEY_CTX_ctrl_uint64'; {introduced 1.1.0}

  EVP_PKEY_CTX_str2ctrl_procname = 'EVP_PKEY_CTX_str2ctrl'; {introduced 1.1.0}
  EVP_PKEY_CTX_hex2ctrl_procname = 'EVP_PKEY_CTX_hex2ctrl'; {introduced 1.1.0}

  EVP_PKEY_CTX_md_procname = 'EVP_PKEY_CTX_md'; {introduced 1.1.0}

  EVP_PKEY_CTX_get_operation_procname = 'EVP_PKEY_CTX_get_operation';
  EVP_PKEY_CTX_set0_keygen_info_procname = 'EVP_PKEY_CTX_set0_keygen_info';

  EVP_PKEY_new_mac_key_procname = 'EVP_PKEY_new_mac_key';
  EVP_PKEY_new_raw_private_key_procname = 'EVP_PKEY_new_raw_private_key'; {introduced 1.1.0}
  EVP_PKEY_new_raw_public_key_procname = 'EVP_PKEY_new_raw_public_key'; {introduced 1.1.0}
  EVP_PKEY_get_raw_private_key_procname = 'EVP_PKEY_get_raw_private_key'; {introduced 1.1.0}
  EVP_PKEY_get_raw_public_key_procname = 'EVP_PKEY_get_raw_public_key'; {introduced 1.1.0}

  EVP_PKEY_new_CMAC_key_procname = 'EVP_PKEY_new_CMAC_key'; {introduced 1.1.0}

  EVP_PKEY_CTX_set_data_procname = 'EVP_PKEY_CTX_set_data';
  EVP_PKEY_CTX_get_data_procname = 'EVP_PKEY_CTX_get_data';
  EVP_PKEY_CTX_get0_pkey_procname = 'EVP_PKEY_CTX_get0_pkey';

  EVP_PKEY_CTX_get0_peerkey_procname = 'EVP_PKEY_CTX_get0_peerkey';

  EVP_PKEY_CTX_set_app_data_procname = 'EVP_PKEY_CTX_set_app_data';
  EVP_PKEY_CTX_get_app_data_procname = 'EVP_PKEY_CTX_get_app_data';

  EVP_PKEY_sign_init_procname = 'EVP_PKEY_sign_init';
  EVP_PKEY_sign_procname = 'EVP_PKEY_sign';
  EVP_PKEY_verify_init_procname = 'EVP_PKEY_verify_init';
  EVP_PKEY_verify_procname = 'EVP_PKEY_verify';
  EVP_PKEY_verify_recover_init_procname = 'EVP_PKEY_verify_recover_init';
  EVP_PKEY_verify_recover_procname = 'EVP_PKEY_verify_recover';
  EVP_PKEY_encrypt_init_procname = 'EVP_PKEY_encrypt_init';
  EVP_PKEY_encrypt_procname = 'EVP_PKEY_encrypt';
  EVP_PKEY_decrypt_init_procname = 'EVP_PKEY_decrypt_init';
  EVP_PKEY_decrypt_procname = 'EVP_PKEY_decrypt';

  EVP_PKEY_derive_init_procname = 'EVP_PKEY_derive_init';
  EVP_PKEY_derive_set_peer_procname = 'EVP_PKEY_derive_set_peer';
  EVP_PKEY_derive_procname = 'EVP_PKEY_derive';

  EVP_PKEY_paramgen_init_procname = 'EVP_PKEY_paramgen_init';
  EVP_PKEY_paramgen_procname = 'EVP_PKEY_paramgen';
  EVP_PKEY_keygen_init_procname = 'EVP_PKEY_keygen_init';
  EVP_PKEY_keygen_procname = 'EVP_PKEY_keygen';
  EVP_PKEY_check_procname = 'EVP_PKEY_check'; {introduced 1.1.0}
  EVP_PKEY_public_check_procname = 'EVP_PKEY_public_check'; {introduced 1.1.0}
  EVP_PKEY_param_check_procname = 'EVP_PKEY_param_check'; {introduced 1.1.0}

  EVP_PKEY_CTX_set_cb_procname = 'EVP_PKEY_CTX_set_cb';
  EVP_PKEY_CTX_get_cb_procname = 'EVP_PKEY_CTX_get_cb';

  EVP_PKEY_CTX_get_keygen_info_procname = 'EVP_PKEY_CTX_get_keygen_info';
  EVP_PKEY_meth_set_init_procname = 'EVP_PKEY_meth_set_init';
  EVP_PKEY_meth_set_copy_procname = 'EVP_PKEY_meth_set_copy';
  EVP_PKEY_meth_set_cleanup_procname = 'EVP_PKEY_meth_set_cleanup';
  EVP_PKEY_meth_set_paramgen_procname = 'EVP_PKEY_meth_set_paramgen';
  EVP_PKEY_meth_set_keygen_procname = 'EVP_PKEY_meth_set_keygen';
  EVP_PKEY_meth_set_sign_procname = 'EVP_PKEY_meth_set_sign';
  EVP_PKEY_meth_set_verify_procname = 'EVP_PKEY_meth_set_verify';
  EVP_PKEY_meth_set_verify_recover_procname = 'EVP_PKEY_meth_set_verify_recover';
  EVP_PKEY_meth_set_signctx_procname = 'EVP_PKEY_meth_set_signctx';
  EVP_PKEY_meth_set_verifyctx_procname = 'EVP_PKEY_meth_set_verifyctx';
  EVP_PKEY_meth_set_encrypt_procname = 'EVP_PKEY_meth_set_encrypt';
  EVP_PKEY_meth_set_decrypt_procname = 'EVP_PKEY_meth_set_decrypt';
  EVP_PKEY_meth_set_derive_procname = 'EVP_PKEY_meth_set_derive';
  EVP_PKEY_meth_set_ctrl_procname = 'EVP_PKEY_meth_set_ctrl';
  EVP_PKEY_meth_set_digestsign_procname = 'EVP_PKEY_meth_set_digestsign'; {introduced 1.1.0}
  EVP_PKEY_meth_set_digestverify_procname = 'EVP_PKEY_meth_set_digestverify'; {introduced 1.1.0}
  EVP_PKEY_meth_set_check_procname = 'EVP_PKEY_meth_set_check'; {introduced 1.1.0}
  EVP_PKEY_meth_set_public_check_procname = 'EVP_PKEY_meth_set_public_check'; {introduced 1.1.0}
  EVP_PKEY_meth_set_param_check_procname = 'EVP_PKEY_meth_set_param_check'; {introduced 1.1.0}
  EVP_PKEY_meth_set_digest_custom_procname = 'EVP_PKEY_meth_set_digest_custom'; {introduced 1.1.0}
  EVP_PKEY_meth_get_init_procname = 'EVP_PKEY_meth_get_init';
  EVP_PKEY_meth_get_copy_procname = 'EVP_PKEY_meth_get_copy';
  EVP_PKEY_meth_get_cleanup_procname = 'EVP_PKEY_meth_get_cleanup';
  EVP_PKEY_meth_get_paramgen_procname = 'EVP_PKEY_meth_get_paramgen';
  EVP_PKEY_meth_get_keygen_procname = 'EVP_PKEY_meth_get_keygen';
  EVP_PKEY_meth_get_sign_procname = 'EVP_PKEY_meth_get_sign';
  EVP_PKEY_meth_get_verify_procname = 'EVP_PKEY_meth_get_verify';
  EVP_PKEY_meth_get_verify_recover_procname = 'EVP_PKEY_meth_get_verify_recover';
  EVP_PKEY_meth_get_signctx_procname = 'EVP_PKEY_meth_get_signctx';
  EVP_PKEY_meth_get_verifyctx_procname = 'EVP_PKEY_meth_get_verifyctx';
  EVP_PKEY_meth_get_encrypt_procname = 'EVP_PKEY_meth_get_encrypt';
  EVP_PKEY_meth_get_decrypt_procname = 'EVP_PKEY_meth_get_decrypt';
  EVP_PKEY_meth_get_derive_procname = 'EVP_PKEY_meth_get_derive';
  EVP_PKEY_meth_get_ctrl_procname = 'EVP_PKEY_meth_get_ctrl';
  EVP_PKEY_meth_get_digestsign_procname = 'EVP_PKEY_meth_get_digestsign'; {introduced 1.1.0}
  EVP_PKEY_meth_get_digestverify_procname = 'EVP_PKEY_meth_get_digestverify'; {introduced 1.1.0}
  EVP_PKEY_meth_get_check_procname = 'EVP_PKEY_meth_get_check'; {introduced 1.1.0}
  EVP_PKEY_meth_get_public_check_procname = 'EVP_PKEY_meth_get_public_check'; {introduced 1.1.0}
  EVP_PKEY_meth_get_param_check_procname = 'EVP_PKEY_meth_get_param_check'; {introduced 1.1.0}
  EVP_PKEY_meth_get_digest_custom_procname = 'EVP_PKEY_meth_get_digest_custom'; {introduced 1.1.0}
  EVP_add_alg_module_procname = 'EVP_add_alg_module';
  OpenSSL_add_all_ciphers_procname = 'OpenSSL_add_all_ciphers'; {removed 1.1.0}
  OpenSSL_add_all_digests_procname = 'OpenSSL_add_all_digests'; {removed 1.1.0}
  EVP_cleanup_procname = 'EVP_cleanup'; {removed 1.1.0}

  //* MAC Stuff */
  EVP_MAC_fetch_procname = 'EVP_MAC_fetch';
  EVP_MAC_up_ref_procname = 'EVP_MAC_up_ref';
  EVP_MAC_free_procname = 'EVP_MAC_free';
  EVP_MAC_is_a_procname = 'EVP_MAC_is_a';
  EVP_MAC_get0_name_procname = 'EVP_MAC_get0_name';
  EVP_MAC_names_do_all_procname = 'EVP_MAC_names_do_all';
  EVP_MAC_get0_description_procname = 'EVP_MAC_get0_description';
  EVP_MAC_get0_provider_procname = 'EVP_MAC_get0_provider';
  EVP_MAC_get_params_procname = 'EVP_MAC_get_params';

  EVP_MAC_CTX_new_procname = 'EVP_MAC_CTX_new';
  EVP_MAC_CTX_free_procname =  'EVP_MAC_CTX_free';
  EVP_MAC_CTX_dup_procname = 'EVP_MAC_CTX_dup';
  EVP_MAC_CTX_get0_mac_procname = 'EVP_MAC_CTX_get0_mac';
  EVP_MAC_CTX_get_params_procname = 'EVP_MAC_CTX_get_params';
  EVP_MAC_CTX_set_params_procname = 'EVP_MAC_CTX_set_params';

  EVP_MAC_CTX_get_mac_size_procname = 'EVP_MAC_CTX_get_mac_size';
  EVP_MAC_CTX_get_block_size_procname = 'EVP_MAC_CTX_get_block_size';
  EVP_MAC_init_procname = 'EVP_MAC_init';
  EVP_MAC_init_SKEY_procname = 'EVP_MAC_init_SKEY';

  EVP_MAC_update_procname = 'EVP_MAC_update';
  EVP_MAC_final_procname = 'EVP_MAC_final';
  EVP_MAC_finalXOF_procname = 'EVP_MAC_finalXOF';

  EVP_MAC_do_all_provided_procname = 'EVP_MAC_do_all_provided';

{function introduced - compatibility}
  {$IFNDEF _FIXINSIGHT_}
{$I TaurusTLSUnusedParamOff.inc}
function FC_EVP_CIPHER_fetch(ctx: POSSL_LIB_CTX; const algorithm, properties: PIdAnsiChar): PEVP_CIPHER; cdecl;
begin
  Result:=EVP_get_cipherbyname(algorithm);
end;

procedure FC_EVP_CIPHER_free(cipher: PEVP_CIPHER); cdecl;
begin
  // only needs for compatibility with 1.1.1
  // it does nothing as EVP_get_cipherbyname does not initialize the cipher
end;    //PALOFF - Empty begin/end-blocks

function FC_EVP_CIPHER_get_nid(const cipher : PEVP_CIPHER) : TIdC_INT; cdecl;
begin
  Result := EVP_CIPHER_nid(cipher);
end;

function FC_EVP_CIPHER_get0_name(const e : PEVP_CIPHER) : PIdAnsiChar; cdecl;
begin
  Result := OBJ_nid2sn(EVP_CIPHER_nid(e));
end;

function FC_EVP_CIPHER_get_block_size (const cipher: PEVP_CIPHER): TIdC_INT; cdecl;
begin
  Result := EVP_CIPHER_block_size(cipher);
end;

function FC_EVP_CIPHER_get_key_length(const cipher: PEVP_CIPHER): TIdC_INT; cdecl;
begin
  Result := EVP_CIPHER_key_length(cipher);
end;

function FC_EVP_CIPHER_get_iv_length(const cipher: PEVP_CIPHER): TIdC_INT; cdecl;
begin
  Result := EVP_CIPHER_iv_length(cipher);
end;

function FC_EVP_CIPHER_get_flags(const cipher: PEVP_CIPHER): TIdC_ULONG; cdecl;
begin
  Result := EVP_CIPHER_flags(cipher);
end;

function FC_EVP_CIPHER_CTX_get_nid(const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl;
begin
  Result := EVP_CIPHER_CTX_nid(ctx);
end;

function FC_EVP_CIPHER_CTX_get_block_size(const ctx: PEVP_CIPHER_CTX): TIdC_INT;  cdecl;
begin
  Result := EVP_CIPHER_CTX_block_size(ctx);
end;

function FC_EVP_CIPHER_CTX_get_key_length(const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl;
begin
  Result := EVP_CIPHER_CTX_key_length(ctx);
end;

function FC_EVP_CIPHER_CTX_get_iv_length(const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl;
begin
  Result :=  EVP_CIPHER_CTX_iv_length(ctx);
end;

function FC_EVP_CIPHER_CTX_get_tag_length(const ctx : PEVP_CIPHER_CTX) : TIdC_INT; cdecl;
begin
  Result := EVP_CIPHER_CTX_tag_length(ctx);
end;

function FC_EVP_CIPHER_CTX_num (const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl;
begin
  Result := -1;
end;

function FC_EVP_CIPHER_CTX_get_num (const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl;
begin
  Result := EVP_CIPHER_CTX_num(ctx);
end;

function FC_EVP_CIPHER_CTX_get0_cipher(const ctx: PEVP_CIPHER_CTX): PEVP_CIPHER; cdecl;
begin
  Result := EVP_CIPHER_CTX_cipher(ctx);
end;

function FC_EVP_CIPHER_get_type(const cipher: PEVP_CIPHER): TIdC_INT; cdecl;
begin
  Result := EVP_CIPHER_type(cipher);
end;

function FC_EVP_CIPHER_get_mode(const cipher: PEVP_CIPHER): TIdC_INT; cdecl;
begin
  Result :=  EVP_CIPHER_mode(cipher);
end;

function FC_EVP_CIPHER_CTX_is_encrypting(const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl;
begin
  Result:=EVP_CIPHER_CTX_encrypting(ctx);
end;
{$I TaurusTLSUnusedParamOn.inc}
  {$ENDIF}
{function removals - compatability}

{$DEFINE EVP_md2_allownil} {removed 1.1.0 allow_nil}
{$DEFINE EVP_md4_allownil} {removed 1.1.0 allow_nil}
{$DEFINE EVP_md5_allownil} {removed 1.1.0 allow_nil}

//#  define EVP_PKEY_assign_RSA(pkey,rsa) EVP_PKEY_assign((pkey),EVP_PKEY_RSA, (char *)(rsa))
function  _EVP_PKEY_assign_RSA(pkey: PEVP_PKEY; rsa: Pointer): TIdC_INT; cdecl;
begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_RSA, rsa);
end;

//#  define EVP_PKEY_assign_DSA(pkey,dsa) EVP_PKEY_assign((pkey),EVP_PKEY_DSA, (char *)(dsa))
function  _EVP_PKEY_assign_DSA(pkey: PEVP_PKEY; dsa: Pointer): TIdC_INT; cdecl;
begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_DSA, dsa);
end;

//#  define EVP_PKEY_assign_DH(pkey,dh) EVP_PKEY_assign((pkey),EVP_PKEY_DH, (char *)(dh))
function  _EVP_PKEY_assign_DH(pkey: PEVP_PKEY; dh: Pointer): TIdC_INT; cdecl;
begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_DH, dh);
end;

//#  define EVP_PKEY_assign_EC_KEY(pkey,eckey) EVP_PKEY_assign((pkey),EVP_PKEY_EC, (char *)(eckey))
function  _EVP_PKEY_assign_EC_KEY(pkey: PEVP_PKEY; eckey: Pointer): TIdC_INT; cdecl;
begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_EC, eckey);
end;

//#  define EVP_PKEY_assign_SIPHASH(pkey,shkey) EVP_PKEY_assign((pkey),EVP_PKEY_SIPHASH, (char *)(shkey))
function  _EVP_PKEY_assign_SIPHASH(pkey: PEVP_PKEY; shkey: Pointer): TIdC_INT; cdecl;
begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_SIPHASH, shkey);
end;

//#  define EVP_PKEY_assign_POLY1305(pkey,polykey) EVP_PKEY_assign((pkey),EVP_PKEY_POLY1305, (char *)(polykey))
function  _EVP_PKEY_assign_POLY1305(pkey: PEVP_PKEY; polykey: Pointer): TIdC_INT; cdecl;
begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_POLY1305, polykey);
end;

procedure  _OpenSSL_add_all_ciphers; cdecl;
begin
  OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS, nil);  //PALOFF - Functions called as procedures
end;

procedure  _OpenSSL_add_all_digests; cdecl;
begin
  OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, Nil);  //PALOFF - Functions called as procedures
end;

procedure  _EVP_cleanup; cdecl;
begin //FI:W519 - Method is empty
   //Do not remove this empty procedure.  It's used in a procedural pointer.
end;   //PALOFF - Empty begin/end-blocks

procedure  _BIO_set_md(v1: PBIO; const md: PEVP_MD); cdecl;
begin
  {define BIO_set_md(b,md)  BIO_ctrl(b,BIO_C_SET_MD,0,(char *)(md))}
  BIO_ctrl(v1,BIO_C_SET_MD,0,PIdAnsiChar(md));
end;


{$IFNDEF OPENSSL_NO_MD2}
function  _EVP_md2: PEVP_MD; cdecl;
begin
  Result := nil;
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ROSUnsupported);
end;
{$ENDIF}

{$IFNDEF OPENSSL_NO_MD4}
function  _EVP_md4: PEVP_MD; cdecl;
begin
  Result := nil;
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ROSUnsupported);
end;
{$ENDIF}

{$IFNDEF OPENSSL_NO_MD5}
function  _EVP_md5: PEVP_MD; cdecl;
begin
  Result := nil;
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ROSUnsupported);
end;
{$ENDIF}

function _EVP_CIPHER_CTX_encrypting (const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl;
begin
  Result := EVP_CIPHER_CTX_is_encrypting(ctx);
end;

function _EVP_CIPHER_key_length(const cipher: PEVP_CIPHER): TIdC_INT; cdecl;
begin
  Result := EVP_CIPHER_get_key_length(cipher);
end;

function _EVP_CIPHER_block_size(const cipher: PEVP_CIPHER): TIdC_INT; cdecl;
begin
  Result := EVP_CIPHER_get_block_size(cipher);
end;

function _EVP_CIPHER_nid(const cipher: PEVP_CIPHER): TIdC_INT cdecl;
begin
  Result := EVP_CIPHER_get_nid(cipher);
end;

function _EVP_CIPHER_iv_length(const cipher: PEVP_CIPHER): TIdC_INT; cdecl;
begin
  Result := EVP_CIPHER_get_iv_length(cipher);
end;

function _EVP_CIPHER_CTX_nid(const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl;
begin
  Result := EVP_CIPHER_CTX_get_nid(ctx);
end;

function _EVP_CIPHER_CTX_key_length(const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl;
begin
  Result := EVP_CIPHER_CTX_get_block_size(ctx);
end;

function _EVP_CIPHER_CTX_iv_length(const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl;
begin
  Result := EVP_CIPHER_CTX_get_key_length(ctx);
end;

function _EVP_CIPHER_CTX_tag_length(const ctx : PEVP_CIPHER_CTX) : TIdC_INT; cdecl;
begin
  Result := EVP_CIPHER_CTX_get_tag_length(ctx);
end;

function _EVP_CIPHER_CTX_num (const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl;
begin
  Result := EVP_CIPHER_CTX_get_num(ctx);
end;

function _EVP_CIPHER_type(const ctx: PEVP_CIPHER): TIdC_INT; cdecl;
begin
  Result := EVP_CIPHER_get_type(ctx);
end;

function _EVP_CIPHER_flags(const cipher: PEVP_CIPHER): TIdC_ULONG; cdecl;
begin
  Result := EVP_CIPHER_get_flags(cipher);
end;

  {$IFNDEF _FIXINSIGHT_}
{$I TaurusTLSUnusedParamOff.inc}
function FC_d2i_AutoPrivateKey_ex(a: PPEVP_PKEY; const pp: PPByte; _length: TIdC_LONG;
    libctx : POSSL_LIB_CTX; propq : PIdAnsiChar): PEVP_PKEY; cdecl;
begin
  Result :=  d2i_AutoPrivateKey(a,pp,_length);
end;
{$I TaurusTLSUnusedParamOn.inc}

  {$I TaurusTLSNoRetValOff.inc} 
function  ERR_EVP_PKEY_assign_RSA(pkey: PEVP_PKEY; rsa: Pointer): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_assign_RSA_procname);
end;


function  ERR_EVP_PKEY_assign_DSA(pkey: PEVP_PKEY; dsa: Pointer): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_assign_DSA_procname);
end;


function  ERR_EVP_PKEY_assign_DH(pkey: PEVP_PKEY; dh: Pointer): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_assign_DH_procname);
end;


function  ERR_EVP_PKEY_assign_EC_KEY(pkey: PEVP_PKEY; eckey: Pointer): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_assign_EC_KEY_procname);
end;


function  ERR_EVP_PKEY_assign_SIPHASH(pkey: PEVP_PKEY; shkey: Pointer): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_assign_SIPHASH_procname);
end;


function  ERR_EVP_PKEY_assign_POLY1305(pkey: PEVP_PKEY; polykey: Pointer): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_assign_POLY1305_procname);
end;



function  ERR_EVP_MD_meth_new(md_type: TIdC_INT; pkey_type: TIdC_INT): PEVP_MD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_meth_new_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_MD_meth_dup(const md: PEVP_MD): PEVP_MD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_meth_dup_procname);
end;

 {introduced 1.1.0}
procedure  ERR_EVP_MD_meth_free(md: PEVP_MD);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_meth_free_procname);
end;

 {introduced 1.1.0}

function  ERR_EVP_MD_meth_set_input_blocksize(md: PEVP_MD; blocksize: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_meth_set_input_blocksize_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_MD_meth_set_result_size(md: PEVP_MD; resultsize: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_meth_set_result_size_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_MD_meth_set_app_datasize(md: PEVP_MD; datasize: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_meth_set_app_datasize_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_MD_meth_set_flags(md: PEVP_MD; flags: TIdC_ULONG): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_meth_set_flags_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_MD_meth_set_init(md: PEVP_MD; init: EVP_MD_meth_init): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_meth_set_init_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_MD_meth_set_update(md: PEVP_MD; update: EVP_MD_meth_update): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_meth_set_update_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_MD_meth_set_final(md: PEVP_MD; final_: EVP_MD_meth_final): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_meth_set_final_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_MD_meth_set_copy(md: PEVP_MD; _copy: EVP_MD_meth_copy): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_meth_set_copy_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_MD_meth_set_cleanup(md: PEVP_MD; cleanup: EVP_MD_meth_cleanup): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_meth_set_cleanup_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_MD_meth_set_ctrl(md: PEVP_MD; ctrl: EVP_MD_meth_ctrl): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_meth_set_ctrl_procname);
end;

 {introduced 1.1.0}

function  ERR_EVP_MD_meth_get_input_blocksize(const md: PEVP_MD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_meth_get_input_blocksize_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_MD_meth_get_result_size(const md: PEVP_MD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_meth_get_result_size_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_MD_meth_get_app_datasize(const md: PEVP_MD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_meth_get_app_datasize_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_MD_meth_get_flags(const md: PEVP_MD): TIdC_ULONG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_meth_get_flags_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_MD_meth_get_init(const md: PEVP_MD): EVP_MD_meth_init;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_meth_get_init_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_MD_meth_get_update(const md: PEVP_MD): EVP_MD_meth_update;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_meth_get_update_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_MD_meth_get_final(const md: PEVP_MD): EVP_MD_meth_final;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_meth_get_final_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_MD_meth_get_copy(const md: PEVP_MD): EVP_MD_meth_copy;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_meth_get_copy_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_MD_meth_get_cleanup(const md: PEVP_MD): EVP_MD_meth_cleanup;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_meth_get_cleanup_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_MD_meth_get_ctrl(const md: PEVP_MD): EVP_MD_meth_ctrl;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_meth_get_ctrl_procname);
end;

 {introduced 1.1.0}

function  ERR_EVP_CIPHER_meth_new(cipher_type: TIdC_INT; block_size: TIdC_INT; key_len: TIdC_INT): PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_meth_new_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_CIPHER_meth_dup(const cipher: PEVP_CIPHER): PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_meth_dup_procname);
end;

 {introduced 1.1.0}
procedure  ERR_EVP_CIPHER_meth_free(cipher: PEVP_CIPHER);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_meth_free_procname);
end;

 {introduced 1.1.0}

function  ERR_EVP_CIPHER_meth_set_iv_length(cipher: PEVP_CIPHER; iv_len: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_meth_set_iv_length_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_CIPHER_meth_set_flags(cipher: PEVP_CIPHER; flags: TIdC_ULONG): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_meth_set_flags_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_CIPHER_meth_set_impl_ctx_size(cipher: PEVP_CIPHER; ctx_size: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_meth_set_impl_ctx_size_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_CIPHER_meth_set_init(cipher: PEVP_CIPHER; init: EVP_CIPHER_meth_init): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_meth_set_init_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_CIPHER_meth_set_do_cipher(cipher: PEVP_CIPHER; do_cipher: EVP_CIPHER_meth_do_cipher): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_meth_set_do_cipher_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_CIPHER_meth_set_cleanup(cipher: PEVP_CIPHER; cleanup: EVP_CIPHER_meth_cleanup): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_meth_set_cleanup_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_CIPHER_meth_set_set_asn1_params(cipher: PEVP_CIPHER; set_asn1_parameters: EVP_CIPHER_meth_set_asn1_params): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_meth_set_set_asn1_params_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_CIPHER_meth_set_get_asn1_params(cipher: PEVP_CIPHER; get_asn1_parameters: EVP_CIPHER_meth_get_asn1_params): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_meth_set_get_asn1_params_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_CIPHER_meth_set_ctrl(cipher: PEVP_CIPHER; ctrl: EVP_CIPHER_meth_ctrl): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_meth_set_ctrl_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_CIPHER_meth_get_init(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_init;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_meth_get_init_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_CIPHER_meth_get_do_cipher(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_do_cipher;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_meth_get_do_cipher_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_CIPHER_meth_get_cleanup(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_cleanup;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_meth_get_cleanup_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_CIPHER_meth_get_set_asn1_params(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_set_asn1_params;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_meth_get_set_asn1_params_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_CIPHER_meth_get_get_asn1_params(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_get_asn1_params;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_meth_get_get_asn1_params_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_CIPHER_meth_get_ctrl(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_ctrl;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_meth_get_ctrl_procname);
end;

 {introduced 1.1.0}

  /// Add some extra combinations ///
  //# define EVP_get_digestbynid(a) EVP_get_digestbyname(OBJ_nid2sn(a));
  //# define EVP_get_digestbyobj(a) EVP_get_digestbynid(OBJ_obj2nid(a));
  //# define EVP_get_cipherbynid(a) EVP_get_cipherbyname(OBJ_nid2sn(a));
  //# define EVP_get_cipherbyobj(a) EVP_get_cipherbynid(OBJ_obj2nid(a));

function  ERR_EVP_MD_type(const md: PEVP_MD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_type_procname);
end;


  //# define EVP_MD_nid(e)                   EVP_MD_type(e)
  //# define EVP_MD_name(e)                  OBJ_nid2sn(EVP_MD_nid(e))
function  ERR_EVP_MD_pkey_type(const md: PEVP_MD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_pkey_type_procname);
end;


function  ERR_EVP_MD_size(const md: PEVP_MD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_size_procname);
end;


function  ERR_EVP_MD_block_size(const md: PEVP_MD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_block_size_procname);
end;


function  ERR_EVP_MD_flags(const md: PEVP_MD): PIdC_ULONG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_flags_procname);
end;



function  ERR_EVP_MD_CTX_md(ctx: PEVP_MD_CTX): PEVP_MD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_CTX_md_procname);
end;


function  ERR_EVP_MD_CTX_update_fn(ctx: PEVP_MD_CTX): EVP_MD_CTX_update;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_CTX_update_fn_procname);
end;

 {introduced 1.1.0}
procedure  ERR_EVP_MD_CTX_set_update_fn(ctx: PEVP_MD_CTX; update: EVP_MD_CTX_update);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_CTX_set_update_fn_procname);
end;

 {introduced 1.1.0}
  //  EVP_MD_CTX_size(e)              EVP_MD_size(EVP_MD_CTX_md(e))
  //  EVP_MD_CTX_block_size(e)        EVP_MD_block_size(EVP_MD_CTX_md(e))
  //  EVP_MD_CTX_type(e)              EVP_MD_type(EVP_MD_CTX_md(e))
function  ERR_EVP_MD_CTX_pkey_ctx(const ctx: PEVP_MD_CTX): PEVP_PKEY_CTX;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_CTX_pkey_ctx_procname);
end;


procedure  ERR_EVP_MD_CTX_set_pkey_ctx(ctx: PEVP_MD_CTX; pctx: PEVP_PKEY_CTX);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_CTX_set_pkey_ctx_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_MD_CTX_md_data(const ctx: PEVP_MD_CTX): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_CTX_md_data_procname);
end;



function  ERR_EVP_CIPHER_nid(const ctx: PEVP_CIPHER): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_nid_procname);
end;

function  ERR_EVP_CIPHER_get_nid(const ctx: PEVP_CIPHER): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_nid_procname);
end;

  //# define EVP_CIPHER_name(e)              OBJ_nid2sn(EVP_CIPHER_nid(e))

function ERR_EVP_CIPHER_get0_name(const cipher : PEVP_CIPHER) : PIdAnsiChar; {introduced 3.0.0} cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_get0_name_procname);
end;

function  ERR_EVP_CIPHER_block_size(const cipher: PEVP_CIPHER): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_block_size_procname);
end;

function  ERR_EVP_CIPHER_get_block_size(const cipher: PEVP_CIPHER): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_get_block_size_procname);
end;

function  ERR_EVP_CIPHER_impl_ctx_size(const cipher: PEVP_CIPHER): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_impl_ctx_size_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_CIPHER_key_length(const cipher: PEVP_CIPHER): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_key_length_procname);
end;

function  ERR_EVP_CIPHER_get_key_length(const cipher: PEVP_CIPHER): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_get_key_length_procname);
end;

function  ERR_EVP_CIPHER_iv_length(const cipher: PEVP_CIPHER): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_iv_length_procname);
end;

function ERR_EVP_CIPHER_get_iv_length(const cipher: PEVP_CIPHER): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_get_iv_length_procname);
end;

function ERR_EVP_CIPHER_flags(const cipher: PEVP_CIPHER): TIdC_ULONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_flags_procname);
end;

function  ERR_EVP_CIPHER_get_flags(const cipher: PEVP_CIPHER): TIdC_ULONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_get_flags_procname);
end;

  //# define EVP_CIPHER_mode(e)              (EVP_CIPHER_flags(e) & EVP_CIPH_MODE)

function  ERR_EVP_CIPHER_CTX_cipher(const ctx: PEVP_CIPHER_CTX): PEVP_CIPHER; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_cipher_procname);
end;

function  ERR_EVP_CIPHER_CTX_get0_cipher(const ctx: PEVP_CIPHER_CTX): PEVP_CIPHER; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_get0_cipher_procname);
end;

function  ERR_EVP_CIPHER_CTX_encrypting(const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_encrypting_procname);
end;

function  ERR_EVP_CIPHER_CTX_is_encrypting(const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_is_encrypting_procname);
end;

function  ERR_EVP_CIPHER_CTX_nid(const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_nid_procname);
end;

function ERR_EVP_CIPHER_CTX_get_nid(const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_get_nid_procname);
end;

function  ERR_EVP_CIPHER_CTX_block_size(const ctx: PEVP_CIPHER_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_block_size_procname);
end;

function ERR_EVP_CIPHER_CTX_get_block_size(const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_get_block_size_procname);
end;

function  ERR_EVP_CIPHER_CTX_key_length(const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_key_length_procname);
end;

function ERR_EVP_CIPHER_CTX_get_key_length(const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_get_key_length_procname);
end;

function  ERR_EVP_CIPHER_CTX_iv_length(const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_iv_length_procname);
end;

function ERR_EVP_CIPHER_CTX_get_iv_length(const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_get_iv_length_procname);
end;

function  ERR_EVP_CIPHER_CTX_iv(const ctx: PEVP_CIPHER_CTX): PByte;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_iv_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_CIPHER_CTX_original_iv(const ctx: PEVP_CIPHER_CTX): PByte;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_original_iv_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_CIPHER_CTX_iv_noconst(ctx: PEVP_CIPHER_CTX): PByte; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_iv_noconst_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_CIPHER_CTX_buf_noconst(ctx: PEVP_CIPHER_CTX): PByte;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_buf_noconst_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_CIPHER_CTX_num(const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_num_procname);
end;

{introduced 3.0.0}
function  ERR_EVP_CIPHER_CTX_get_num(const ctx: PEVP_CIPHER_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_get_num_procname);
end;

procedure  ERR_EVP_CIPHER_CTX_set_num(ctx: PEVP_CIPHER_CTX; num: TIdC_INT);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_set_num_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_CIPHER_CTX_copy(out_: PEVP_CIPHER_CTX; const in_: PEVP_CIPHER_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_copy_procname);
end;


function  ERR_EVP_CIPHER_CTX_get_app_data(const ctx: PEVP_CIPHER_CTX): Pointer;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_get_app_data_procname);
end;


procedure  ERR_EVP_CIPHER_CTX_set_app_data(ctx: PEVP_CIPHER_CTX; data: Pointer);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_set_app_data_procname);
end;


function  ERR_EVP_CIPHER_CTX_get_cipher_data(const ctx: PEVP_CIPHER_CTX): Pointer;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_get_cipher_data_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_CIPHER_CTX_set_cipher_data(ctx: PEVP_CIPHER_CTX; cipher_data: Pointer): Pointer;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_set_cipher_data_procname);
end;

{removed 3.0.0}
function ERR_EVP_CIPHER_CTX_tag_length (const ctx : PEVP_CIPHER_CTX) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_tag_length_procname);
end;

{introduced 3.0.0}
function ERR_EVP_CIPHER_CTX_get_tag_length(const ctx : PEVP_CIPHER_CTX) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_get_tag_length_procname);
end;

 {introduced 1.1.0}

  //# define EVP_CIPHER_CTX_type(c)         EVP_CIPHER_type(EVP_CIPHER_CTX_cipher(c))
  //# if OPENSSL_API_COMPAT < 0x10100000L
  //#  define EVP_CIPHER_CTX_flags(c)       EVP_CIPHER_flags(EVP_CIPHER_CTX_cipher(c))
  //# endif
  //# define EVP_CIPHER_CTX_mode(c)         EVP_CIPHER_mode(EVP_CIPHER_CTX_cipher(c))
  //
  //# define EVP_ENCODE_LENGTH(l)    ((((l)+2)/3*4)+((l)/48+1)*2+80)
  //# define EVP_DECODE_LENGTH(l)    (((l)+3)/4*3+80)
  //
  //# define EVP_SignInit_ex(a;b;c)          EVP_DigestInit_ex(a;b;c)
  //# define EVP_SignInit(a;b)               EVP_DigestInit(a;b)
  //# define EVP_SignUpdate(a;b;c)           EVP_DigestUpdate(a;b;c)
  //# define EVP_VerifyInit_ex(a;b;c)        EVP_DigestInit_ex(a;b;c)
  //# define EVP_VerifyInit(a;b)             EVP_DigestInit(a;b)
  //# define EVP_VerifyUpdate(a;b;c)         EVP_DigestUpdate(a;b;c)
  //# define EVP_OpenUpdate(a;b;c;d;e)       EVP_DecryptUpdate(a;b;c;d;e)
  //# define EVP_SealUpdate(a;b;c;d;e)       EVP_EncryptUpdate(a;b;c;d;e)
  //# define EVP_DigestSignUpdate(a;b;c)     EVP_DigestUpdate(a;b;c)
  //# define EVP_DigestVerifyUpdate(a;b;c)   EVP_DigestUpdate(a;b;c)

procedure  ERR_BIO_set_md(v1: PBIO; const md: PEVP_MD);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_md_procname);
end;


  //# define BIO_get_md(b;mdp)          BIO_ctrl(b;BIO_C_GET_MD;0;(PIdAnsiChar)(mdp))
  //# define BIO_get_md_ctx(b;mdcp)     BIO_ctrl(b;BIO_C_GET_MD_CTX;0; (PIdAnsiChar)(mdcp))
  //# define BIO_set_md_ctx(b;mdcp)     BIO_ctrl(b;BIO_C_SET_MD_CTX;0; (PIdAnsiChar)(mdcp))
  //# define BIO_get_cipher_status(b)   BIO_ctrl(b;BIO_C_GET_CIPHER_STATUS;0;NULL)
  //# define BIO_get_cipher_ctx(b;c_pp) BIO_ctrl(b;BIO_C_GET_CIPHER_CTX;0; (PIdAnsiChar)(c_pp))

  //function EVP_Cipher(c: PEVP_CIPHER_CTX; var out_; const in_; in1: TIdC_UINT): TIdC_INT;

  //# define EVP_add_cipher_alias(n;alias) OBJ_NAME_add((alias);OBJ_NAME_TYPE_CIPHER_METH|OBJ_NAME_ALIAS;(n))
  //# define EVP_add_digest_alias(n;alias) OBJ_NAME_add((alias);OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS;(n))
  //# define EVP_delete_cipher_alias(alias) OBJ_NAME_remove(alias;OBJ_NAME_TYPE_CIPHER_METH|OBJ_NAME_ALIAS);
  //# define EVP_delete_digest_alias(alias) OBJ_NAME_remove(alias;OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS);

  //void EVP_MD_CTX_init(EVP_MD_CTX *ctx);
  //int EVP_MD_CTX_cleanup(EVP_MD_CTX *ctx);
procedure  ERR_EVP_MD_CTX_init(ctx : PEVP_MD_CTX);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_CTX_init_procname);
end;


function  ERR_EVP_MD_CTX_cleanup(ctx : PEVP_MD_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_CTX_cleanup_procname);
end;



function  ERR_EVP_MD_CTX_ctrl(ctx: PEVP_MD_CTX; cmd: TIdC_INT; p1: TIdC_INT; p2: Pointer): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_CTX_ctrl_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_MD_CTX_new: PEVP_MD_CTX;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_CTX_new_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_MD_CTX_reset(ctx: PEVP_MD_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_CTX_reset_procname);
end;

 {introduced 1.1.0}
procedure  ERR_EVP_MD_CTX_free(ctx: PEVP_MD_CTX); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_CTX_free_procname);
end;

 {introduced 1.1.0}
  //# define EVP_MD_CTX_create()     EVP_MD_CTX_new()
  //# define EVP_MD_CTX_init(ctx)    EVP_MD_CTX_reset((ctx))
  //# define EVP_MD_CTX_destroy(ctx) EVP_MD_CTX_free((ctx))
function  ERR_EVP_MD_CTX_copy_ex(out_: PEVP_MD_CTX; const in_: PEVP_MD_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_CTX_copy_ex_procname);
end;


procedure  ERR_EVP_MD_CTX_set_flags(ctx: PEVP_MD_CTX; flags: TIdC_INT);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_CTX_set_flags_procname);
end;


procedure  ERR_EVP_MD_CTX_clear_flags(ctx: PEVP_MD_CTX; flags: TIdC_INT);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_CTX_clear_flags_procname);
end;


function  ERR_EVP_MD_CTX_test_flags(const ctx: PEVP_MD_CTX; flags: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_CTX_test_flags_procname);
end;


function  ERR_EVP_DigestInit_ex(ctx: PEVP_MD_CTX; const type_: PEVP_MD; impl: PENGINE): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_DigestInit_ex_procname);
end;


function  ERR_EVP_DigestUpdate(ctx: PEVP_MD_CTX; const d: Pointer; cnt: TIdC_SIZET): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_DigestUpdate_procname);
end;


function  ERR_EVP_DigestFinal_ex(ctx: PEVP_MD_CTX; md: PByte; var s: TIdC_UINT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_DigestFinal_ex_procname);
end;


function  ERR_EVP_Digest(const data: Pointer; count: TIdC_SIZET; md: PByte; size: PIdC_UINT; const type_: PEVP_MD; impl: PENGINE): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_Digest_procname);
end;



function  ERR_EVP_MD_CTX_copy(out_: PEVP_MD_CTX; const in_: PEVP_MD_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_CTX_copy_procname);
end;


function  ERR_EVP_DigestInit(ctx: PEVP_MD_CTX; const type_: PEVP_MD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_DigestInit_procname);
end;


function  ERR_EVP_DigestFinal(ctx: PEVP_MD_CTX; md: PByte; var s: TIdC_UINT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_DigestFinal_procname);
end;


function  ERR_EVP_DigestFinalXOF(ctx: PEVP_MD_CTX; md: PByte; len: TIdC_SIZET): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_DigestFinalXOF_procname);
end;

 {introduced 1.1.0}

function  ERR_EVP_read_pw_string(buf: PIdAnsiChar; _length: TIdC_INT; const prompt: PIdAnsiChar; verify: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_read_pw_string_procname);
end;


function  ERR_EVP_read_pw_string_min(buf: PIdAnsiChar; minlen: TIdC_INT; maxlen: TIdC_INT; const prompt: PIdAnsiChar; verify: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_read_pw_string_min_procname);
end;


procedure  ERR_EVP_set_pw_prompt(const prompt: PIdAnsiChar);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_set_pw_prompt_procname);
end;


function  ERR_EVP_get_pw_prompt: PIdAnsiChar;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_get_pw_prompt_procname);
end;


function  ERR_EVP_BytesToKey(const type_: PEVP_CIPHER; const md: PEVP_MD; const salt: PByte; const data: PByte; data1: TIdC_INT; count: TIdC_INT; key: PByte; iv: PByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_BytesToKey_procname);
end;



procedure  ERR_EVP_CIPHER_CTX_set_flags(ctx: PEVP_CIPHER_CTX; flags: TIdC_INT);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_set_flags_procname);
end;


procedure  ERR_EVP_CIPHER_CTX_clear_flags(ctx: PEVP_CIPHER_CTX; flags: TIdC_INT);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_clear_flags_procname);
end;


function  ERR_EVP_CIPHER_CTX_test_flags(const ctx: PEVP_CIPHER_CTX; flags: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_test_flags_procname);
end;



function  ERR_EVP_EncryptInit(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; const key: PByte; const iv: PByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_EncryptInit_procname);
end;


function  ERR_EVP_EncryptInit_ex(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_EncryptInit_ex_procname);
end;


function  ERR_EVP_EncryptUpdate(ctx: PEVP_CIPHER_CTX; var out_; var out1: TIdC_INT; const in_; in_1: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_EncryptUpdate_procname);
end;


function  ERR_EVP_EncryptFinal_ex(ctx: PEVP_CIPHER_CTX; var out_; var out1: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_EncryptFinal_ex_procname);
end;


function  ERR_EVP_EncryptFinal(ctx: PEVP_CIPHER_CTX; var out_; var out1: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_EncryptFinal_procname);
end;



function  ERR_EVP_DecryptInit(ctx: PEVP_CIPHER_CTX; var out_; var out1: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_DecryptInit_procname);
end;


function  ERR_EVP_DecryptInit_ex(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_DecryptInit_ex_procname);
end;


function  ERR_EVP_DecryptUpdate(ctx: PEVP_CIPHER_CTX; var out_; var out1: TIdC_INT; const in_; in_1: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_DecryptUpdate_procname);
end;


function  ERR_EVP_DecryptFinal(ctx: PEVP_CIPHER_CTX; var outm; var out1: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_DecryptFinal_procname);
end;


function  ERR_EVP_DecryptFinal_ex(ctx: PEVP_MD_CTX; var outm; var out1: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_DecryptFinal_ex_procname);
end;



function  ERR_EVP_CipherInit(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; const key: PByte; const iv: PByte; enc: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CipherInit_procname);
end;


function  ERR_EVP_CipherInit_ex(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte; enc: TidC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CipherInit_ex_procname);
end;


function  ERR_EVP_CipherUpdate(ctx: PEVP_CIPHER_CTX; var out_; var out1: TIdC_INT; const in_; in1: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CipherUpdate_procname);
end;


function  ERR_EVP_CipherFinal(ctx: PEVP_CIPHER_CTX; var outm; var out1: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CipherFinal_procname);
end;


function  ERR_EVP_CipherFinal_ex(ctx: PEVP_CIPHER_CTX; var outm; var out1: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CipherFinal_ex_procname);
end;



function  ERR_EVP_SignFinal(ctx: PEVP_CIPHER_CTX; md: PByte; s: PIdC_UINT; pkey: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_SignFinal_procname);
end;



function  ERR_EVP_DigestSign(ctx: PEVP_CIPHER_CTX; sigret: PByte; siglen: PIdC_SIZET; const tbs: PByte; tbslen: TIdC_SIZET): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_DigestSign_procname);
end;

 {introduced 1.1.0}

function  ERR_EVP_VerifyFinal(ctx: PEVP_MD_CTX; const sigbuf: PByte; siglen: TIdC_UINT; pkey: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_VerifyFinal_procname);
end;



function  ERR_EVP_DigestVerify(ctx: PEVP_CIPHER_CTX; const sigret: PByte; siglen: TIdC_SIZET; const tbs: PByte; tbslen: TIdC_SIZET): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_DigestVerify_procname);
end;

 {introduced 1.1.0}

function  ERR_EVP_DigestSignInit(ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; const type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_DigestSignInit_procname);
end;


function  ERR_EVP_DigestSignFinal(ctx: PEVP_MD_CTX; sigret: PByte; siglen: PIdC_SIZET): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_DigestSignFinal_procname);
end;



function  ERR_EVP_DigestVerifyInit(ctx: PEVP_MD_CTX; ppctx: PPEVP_PKEY_CTX; const type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_DigestVerifyInit_procname);
end;


function  ERR_EVP_DigestVerifyFinal(ctx: PEVP_MD_CTX; const sig: PByte; siglen: TIdC_SIZET): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_DigestVerifyFinal_procname);
end;



function  ERR_EVP_OpenInit(ctx: PEVP_CIPHER_CTX; const type_: PEVP_CIPHER; const ek: PByte; ek1: TIdC_INT; const iv: PByte; priv: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_OpenInit_procname);
end;


function  ERR_EVP_OpenFinal(ctx: PEVP_CIPHER_CTX; var out_; var out1: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_OpenFinal_procname);
end;



function  ERR_EVP_SealInit(ctx: PEVP_CIPHER_CTX; const type_: PEVP_CIPHER; ek: PPByte; ek1: PIdC_INT; iv: PByte; pubk: PPEVP_PKEY; npubk: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_SealInit_procname);
end;


function  ERR_EVP_SealFinal(ctx: PEVP_CIPHER_CTX; var out_; var out1: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_SealFinal_procname);
end;



function  ERR_EVP_ENCODE_CTX_new: PEVP_ENCODE_CTX;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_ENCODE_CTX_new_procname);
end;

 {introduced 1.1.0}
procedure  ERR_EVP_ENCODE_CTX_free(ctx: PEVP_ENCODE_CTX);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_ENCODE_CTX_free_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_ENCODE_CTX_copy(dctx: PEVP_ENCODE_CTX; sctx: PEVP_ENCODE_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_ENCODE_CTX_copy_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_ENCODE_CTX_num(ctx: PEVP_ENCODE_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_ENCODE_CTX_num_procname);
end;

 {introduced 1.1.0}
procedure  ERR_EVP_EncodeInit(ctx: PEVP_ENCODE_CTX);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_EncodeInit_procname);
end;


function  ERR_EVP_EncodeUpdate(ctx: PEVP_ENCODE_CTX; var out_; var out1: TIdC_INT; const in_; in1: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_EncodeUpdate_procname);
end;


procedure  ERR_EVP_EncodeFinal(ctx: PEVP_ENCODE_CTX; var out_; var out1: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_EncodeFinal_procname);
end;


function  ERR_EVP_EncodeBlock(t: PByte; const f: PByte; n: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_EncodeBlock_procname);
end;



procedure  ERR_EVP_DecodeInit(ctx: PEVP_ENCODE_CTX);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_DecodeInit_procname);
end;


function  ERR_EVP_DecodeUpdate(ctx: PEVP_ENCODE_CTX; var out_; var out1: TIdC_INT; const in_; in1: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_DecodeUpdate_procname);
end;


function  ERR_EVP_DecodeFinal(ctx: PEVP_ENCODE_CTX; var out_; var out1: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_DecodeFinal_procname);
end;


function  ERR_EVP_DecodeBlock(t: PByte; const f: PByte; n: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_DecodeBlock_procname);
end;


function ERR_EVP_CIPHER_fetch(ctx: POSSL_LIB_CTX; const algorithm, properties: PIdAnsiChar): PEVP_CIPHER; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_fetch_procname);
end;

procedure ERR_EVP_CIPHER_free(cipher: PEVP_CIPHER); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_free_procname);
end;


function  ERR_EVP_CIPHER_CTX_new: PEVP_CIPHER_CTX; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_new_procname);
end;


function  ERR_EVP_CIPHER_CTX_reset(c: PEVP_CIPHER_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_reset_procname);
end;

 {introduced 1.1.0}
procedure  ERR_EVP_CIPHER_CTX_free(c: PEVP_CIPHER_CTX);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_free_procname);
end;


function  ERR_EVP_CIPHER_CTX_set_key_length(x: PEVP_CIPHER_CTX; keylen: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_set_key_length_procname);
end;


function  ERR_EVP_CIPHER_CTX_set_padding(c: PEVP_CIPHER_CTX; pad: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_set_padding_procname);
end;


function  ERR_EVP_CIPHER_CTX_ctrl(ctx: PEVP_CIPHER_CTX; type_: TIdC_INT; arg: TIdC_INT; _ptr: Pointer): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_ctrl_procname);
end;


function  ERR_EVP_CIPHER_CTX_rand_key(ctx: PEVP_CIPHER_CTX; key: PByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_CTX_rand_key_procname);
end;



function  ERR_BIO_f_md: PBIO_METHOD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_f_md_procname);
end;


function  ERR_BIO_f_base64: PBIO_METHOD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_f_base64_procname);
end;


function  ERR_BIO_f_cipher: PBIO_METHOD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_f_cipher_procname);
end;


function  ERR_BIO_f_reliable: PBIO_METHOD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_f_reliable_procname);
end;


function  ERR_BIO_set_cipher(b: PBIO; c: PEVP_CIPHER; const k: PByte; const i: PByte; enc: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_cipher_procname);
end;



function  ERR_EVP_md_null: PEVP_MD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_md_null_procname);
end;



function  ERR_EVP_md2: PEVP_MD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_md2_procname);
end;

 {removed 1.1.0 allow_nil}
function  ERR_EVP_md4: PEVP_MD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_md4_procname);
end;

 {removed 1.1.0 allow_nil}
function  ERR_EVP_md5: PEVP_MD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_md5_procname);
end;

 {removed 1.1.0 allow_nil}
function  ERR_EVP_md5_sha1: PEVP_MD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_md5_sha1_procname);
end;

 {introduced 1.1.0}

function  ERR_EVP_sha1: PEVP_MD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_sha1_procname);
end;


function  ERR_EVP_sha224: PEVP_MD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_sha224_procname);
end;


function  ERR_EVP_sha256: PEVP_MD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_sha256_procname);
end;


function  ERR_EVP_sha384: PEVP_MD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_sha384_procname);
end;


function  ERR_EVP_sha512: PEVP_MD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_sha512_procname);
end;


function  ERR_EVP_sha512_224: PEVP_MD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_sha512_224_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_sha512_256: PEVP_MD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_sha512_256_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_sha3_224: PEVP_MD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_sha3_224_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_sha3_256: PEVP_MD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_sha3_256_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_sha3_384: PEVP_MD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_sha3_384_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_sha3_512: PEVP_MD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_sha3_512_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_shake128: PEVP_MD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_shake128_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_shake256: PEVP_MD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_shake256_procname);
end;

 {introduced 1.1.0}

  (* does nothing :-) *)
function  ERR_EVP_enc_null: PEVP_CIPHER; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_enc_null_procname);
end;



function  ERR_EVP_des_ecb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_des_ecb_procname);
end;


function  ERR_EVP_des_ede: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_des_ede_procname);
end;


function  ERR_EVP_des_ede3: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_des_ede3_procname);
end;


function  ERR_EVP_des_ede_ecb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_des_ede_ecb_procname);
end;


function  ERR_EVP_des_ede3_ecb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_des_ede3_ecb_procname);
end;


function  ERR_EVP_des_cfb64: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_des_cfb64_procname);
end;


  //EVP_des_cfb EVP_des_cfb64
function  ERR_EVP_des_cfb1: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_des_cfb1_procname);
end;


function  ERR_EVP_des_cfb8: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_des_cfb8_procname);
end;


function  ERR_EVP_des_ede_cfb64: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_des_ede_cfb64_procname);
end;


function  ERR_EVP_des_ede3_cfb64: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_des_ede3_cfb64_procname);
end;


  //EVP_des_ede3_cfb EVP_des_ede3_cfb64
function  ERR_EVP_des_ede3_cfb1: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_des_ede3_cfb1_procname);
end;


function  ERR_EVP_des_ede3_cfb8: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_des_ede3_cfb8_procname);
end;


function  ERR_EVP_des_ofb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_des_ofb_procname);
end;


function  ERR_EVP_des_ede_ofb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_des_ede_ofb_procname);
end;


function  ERR_EVP_des_ede3_ofb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_des_ede3_ofb_procname);
end;


function  ERR_EVP_des_cbc: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_des_cbc_procname);
end;


function  ERR_EVP_des_ede_cbc: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_des_ede_cbc_procname);
end;


function  ERR_EVP_des_ede3_cbc: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_des_ede3_cbc_procname);
end;


function  ERR_EVP_desx_cbc: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_desx_cbc_procname);
end;


function  ERR_EVP_des_ede3_wrap: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_des_ede3_wrap_procname);
end;


  //
  // This should now be supported through the dev_crypto ENGINE. But also, why
  // are rc4 and md5 declarations made here inside a "NO_DES" precompiler
  // branch?
  //
function  ERR_EVP_rc4: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_rc4_procname);
end;


function  ERR_EVP_rc4_40: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_rc4_40_procname);
end;


//  function EVP_idea_ecb: PEVP_CIPHER;
// function EVP_idea_cfb64: PEVP_CIPHER;
  //EVP_idea_cfb EVP_idea_cfb64
//  function EVP_idea_ofb: PEVP_CIPHER;
 // function EVP_idea_cbc: PEVP_CIPHER;
function  ERR_EVP_rc2_ecb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_rc2_ecb_procname);
end;


function  ERR_EVP_rc2_cbc: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_rc2_cbc_procname);
end;


function  ERR_EVP_rc2_40_cbc: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_rc2_40_cbc_procname);
end;


function  ERR_EVP_rc2_64_cbc: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_rc2_64_cbc_procname);
end;


function  ERR_EVP_rc2_cfb64: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_rc2_cfb64_procname);
end;


  //EVP_rc2_cfb EVP_rc2_cfb64
function  ERR_EVP_rc2_ofb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_rc2_ofb_procname);
end;


function  ERR_EVP_bf_ecb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_bf_ecb_procname);
end;


function  ERR_EVP_bf_cbc: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_bf_cbc_procname);
end;


function  ERR_EVP_bf_cfb64: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_bf_cfb64_procname);
end;


  //EVP_bf_cfb EVP_bf_cfb64
function  ERR_EVP_bf_ofb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_bf_ofb_procname);
end;


function  ERR_EVP_cast5_ecb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_cast5_ecb_procname);
end;


function  ERR_EVP_cast5_cbc: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_cast5_cbc_procname);
end;


function  ERR_EVP_cast5_cfb64: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_cast5_cfb64_procname);
end;


  //EVP_cast5_cfb EVP_cast5_cfb64
function  ERR_EVP_cast5_ofb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_cast5_ofb_procname);
end;


//  function EVP_rc5_32_12_16_cbc: PEVP_CIPHER;
//  function EVP_rc5_32_12_16_ecb: PEVP_CIPHER;
//  function EVP_rc5_32_12_16_cfb64: PEVP_CIPHER;
  //EVP_rc5_32_12_16_cfb EVP_rc5_32_12_16_cfb64
//  function EVP_rc5_32_12_16_ofb: PEVP_CIPHER;

function  ERR_EVP_aes_128_ecb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_128_ecb_procname);
end;


function  ERR_EVP_aes_128_cbc: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_128_cbc_procname);
end;


function  ERR_EVP_aes_128_cfb1: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_128_cfb1_procname);
end;


function  ERR_EVP_aes_128_cfb8: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_128_cfb8_procname);
end;


function  ERR_EVP_aes_128_cfb128: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_128_cfb128_procname);
end;


  //EVP_aes_128_cfb EVP_aes_128_cfb128
function  ERR_EVP_aes_128_ofb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_128_ofb_procname);
end;


function  ERR_EVP_aes_128_ctr: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_128_ctr_procname);
end;


function  ERR_EVP_aes_128_ccm: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_128_ccm_procname);
end;


function  ERR_EVP_aes_128_gcm: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_128_gcm_procname);
end;


function  ERR_EVP_aes_128_xts: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_128_xts_procname);
end;


function  ERR_EVP_aes_128_wrap: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_128_wrap_procname);
end;


function  ERR_EVP_aes_128_wrap_pad: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_128_wrap_pad_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aes_128_ocb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_128_ocb_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aes_192_ecb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_192_ecb_procname);
end;


function  ERR_EVP_aes_192_cbc: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_192_cbc_procname);
end;


function  ERR_EVP_aes_192_cfb1: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_192_cfb1_procname);
end;


function  ERR_EVP_aes_192_cfb8: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_192_cfb8_procname);
end;


function  ERR_EVP_aes_192_cfb128: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_192_cfb128_procname);
end;


  //EVP_aes_192_cfb EVP_aes_192_cfb128
function  ERR_EVP_aes_192_ofb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_192_ofb_procname);
end;


function  ERR_EVP_aes_192_ctr: PEVP_CIPHER; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_192_ctr_procname);
end;


function  ERR_EVP_aes_192_ccm: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_192_ccm_procname);
end;


function  ERR_EVP_aes_192_gcm: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_192_gcm_procname);
end;


function  ERR_EVP_aes_192_wrap: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_192_wrap_procname);
end;


function  ERR_EVP_aes_192_wrap_pad: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_192_wrap_pad_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aes_192_ocb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_192_ocb_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aes_256_ecb: PEVP_CIPHER; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_256_ecb_procname);
end;


function  ERR_EVP_aes_256_cbc: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_256_cbc_procname);
end;


function  ERR_EVP_aes_256_cfb1: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_256_cfb1_procname);
end;


function  ERR_EVP_aes_256_cfb8: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_256_cfb8_procname);
end;


function  ERR_EVP_aes_256_cfb128: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_256_cfb128_procname);
end;


  //EVP_aes_256_cfb EVP_aes_256_cfb128
function  ERR_EVP_aes_256_ofb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_256_ofb_procname);
end;


function  ERR_EVP_aes_256_ctr: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_256_ctr_procname);
end;


function  ERR_EVP_aes_256_ccm: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_256_ccm_procname);
end;


function  ERR_EVP_aes_256_gcm: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_256_gcm_procname);
end;


function  ERR_EVP_aes_256_xts: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_256_xts_procname);
end;


function  ERR_EVP_aes_256_wrap: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_256_wrap_procname);
end;


function  ERR_EVP_aes_256_wrap_pad: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_256_wrap_pad_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aes_256_ocb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_256_ocb_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aes_128_cbc_hmac_sha1: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_128_cbc_hmac_sha1_procname);
end;


function  ERR_EVP_aes_256_cbc_hmac_sha1: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_256_cbc_hmac_sha1_procname);
end;


function  ERR_EVP_aes_128_cbc_hmac_sha256: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_128_cbc_hmac_sha256_procname);
end;


function  ERR_EVP_aes_256_cbc_hmac_sha256: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aes_256_cbc_hmac_sha256_procname);
end;



function  ERR_EVP_aria_128_ecb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aria_128_ecb_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aria_128_cbc: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aria_128_cbc_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aria_128_cfb1: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aria_128_cfb1_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aria_128_cfb8: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aria_128_cfb8_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aria_128_cfb128: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aria_128_cfb128_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aria_128_ctr: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aria_128_ctr_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aria_128_ofb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aria_128_ofb_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aria_128_gcm: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aria_128_gcm_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aria_128_ccm: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aria_128_ccm_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aria_192_ecb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aria_192_ecb_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aria_192_cbc: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aria_192_cbc_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aria_192_cfb1: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aria_192_cfb1_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aria_192_cfb8: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aria_192_cfb8_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aria_192_cfb128: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aria_192_cfb128_procname);
end;

 {introduced 1.1.0}
  //EVP_aria_192_cfb EVP_aria_192_cfb128
function  ERR_EVP_aria_192_ctr: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aria_192_ctr_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aria_192_ofb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aria_192_ofb_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aria_192_gcm: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aria_192_gcm_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aria_192_ccm: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aria_192_ccm_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aria_256_ecb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aria_256_ecb_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aria_256_cbc: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aria_256_cbc_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aria_256_cfb1: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aria_256_cfb1_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aria_256_cfb8: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aria_256_cfb8_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aria_256_cfb128: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aria_256_cfb128_procname);
end;

 {introduced 1.1.0}
  //EVP_aria_256_cfb EVP_aria_256_cfb128
function  ERR_EVP_aria_256_ctr: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aria_256_ctr_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aria_256_ofb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aria_256_ofb_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aria_256_gcm: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aria_256_gcm_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_aria_256_ccm: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_aria_256_ccm_procname);
end;

 {introduced 1.1.0}

function  ERR_EVP_camellia_128_ecb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_camellia_128_ecb_procname);
end;


function  ERR_EVP_camellia_128_cbc: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_camellia_128_cbc_procname);
end;


function  ERR_EVP_camellia_128_cfb1: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_camellia_128_cfb1_procname);
end;


function  ERR_EVP_camellia_128_cfb8: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_camellia_128_cfb8_procname);
end;


function  ERR_EVP_camellia_128_cfb128: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_camellia_128_cfb128_procname);
end;


  //EVP_camellia_128_cfb EVP_camellia_128_cfb128
function  ERR_EVP_camellia_128_ofb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_camellia_128_ofb_procname);
end;


function  ERR_EVP_camellia_128_ctr: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_camellia_128_ctr_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_camellia_192_ecb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_camellia_192_ecb_procname);
end;


function  ERR_EVP_camellia_192_cbc: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_camellia_192_cbc_procname);
end;


function  ERR_EVP_camellia_192_cfb1: PEVP_CIPHER; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_camellia_192_cfb1_procname);
end;


function  ERR_EVP_camellia_192_cfb8: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_camellia_192_cfb8_procname);
end;


function  ERR_EVP_camellia_192_cfb128: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_camellia_192_cfb128_procname);
end;


  //EVP_camellia_192_cfb EVP_camellia_192_cfb128
function  ERR_EVP_camellia_192_ofb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_camellia_192_ofb_procname);
end;


function  ERR_EVP_camellia_192_ctr: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_camellia_192_ctr_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_camellia_256_ecb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_camellia_256_ecb_procname);
end;


function  ERR_EVP_camellia_256_cbc: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_camellia_256_cbc_procname);
end;


function  ERR_EVP_camellia_256_cfb1: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_camellia_256_cfb1_procname);
end;


function  ERR_EVP_camellia_256_cfb8: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_camellia_256_cfb8_procname);
end;


function  ERR_EVP_camellia_256_cfb128: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_camellia_256_cfb128_procname);
end;


  //EVP_camellia_256_cfb EVP_camellia_256_cfb128
function  ERR_EVP_camellia_256_ofb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_camellia_256_ofb_procname);
end;


function  ERR_EVP_camellia_256_ctr: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_camellia_256_ctr_procname);
end;

 {introduced 1.1.0}

function  ERR_EVP_chacha20: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_chacha20_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_chacha20_poly1305: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_chacha20_poly1305_procname);
end;

 {introduced 1.1.0}

function  ERR_EVP_seed_ecb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_seed_ecb_procname);
end;


function  ERR_EVP_seed_cbc: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_seed_cbc_procname);
end;


function  ERR_EVP_seed_cfb128: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_seed_cfb128_procname);
end;


  //EVP_seed_cfb EVP_seed_cfb128
function  ERR_EVP_seed_ofb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_seed_ofb_procname);
end;



function  ERR_EVP_sm4_ecb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_sm4_ecb_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_sm4_cbc: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_sm4_cbc_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_sm4_cfb128: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_sm4_cfb128_procname);
end;

 {introduced 1.1.0}
  //EVP_sm4_cfb EVP_sm4_cfb128
function  ERR_EVP_sm4_ofb: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_sm4_ofb_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_sm4_ctr: PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_sm4_ctr_procname);
end;

 {introduced 1.1.0}

function  ERR_EVP_add_cipher(const cipher: PEVP_CIPHER): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_add_cipher_procname);
end;


function  ERR_EVP_add_digest(const digest: PEVP_MD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_add_digest_procname);
end;



function  ERR_EVP_get_cipherbyname(const name: PIdAnsiChar): PEVP_CIPHER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_get_cipherbyname_procname);
end;


function  ERR_EVP_get_digestbyname(const name: PIdAnsiChar): PEVP_MD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_get_digestbyname_procname);
end;



procedure  ERR_EVP_CIPHER_do_all(AFn: fn; arg: Pointer);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_do_all_procname);
end;


procedure  ERR_EVP_CIPHER_do_all_sorted(AFn: fn; arg: Pointer);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_do_all_sorted_procname);
end;



procedure  ERR_EVP_MD_do_all(AFn: fn; arg: Pointer);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_do_all_procname);
end;


procedure  ERR_EVP_MD_do_all_sorted(AFn: fn; arg: Pointer);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MD_do_all_sorted_procname);
end;



function  ERR_EVP_PKEY_decrypt_old(dec_key: PByte; const enc_key: PByte; enc_key_len: TIdC_INT; private_key: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_decrypt_old_procname);
end;


function  ERR_EVP_PKEY_encrypt_old(dec_key: PByte; const enc_key: PByte; key_len: TIdC_INT; pub_key: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_encrypt_old_procname);
end;


function  ERR_EVP_PKEY_type(type_: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_type_procname);
end;


function  ERR_EVP_PKEY_id(const pkey: PEVP_PKEY): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_id_procname);
end;


function  ERR_EVP_PKEY_base_id(const pkey: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_base_id_procname);
end;


function  ERR_EVP_PKEY_bits(const pkey: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_bits_procname);
end;


function  ERR_EVP_PKEY_security_bits(const pkey: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_security_bits_procname);
end;


function  ERR_EVP_PKEY_size(const pkey: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_size_procname);
end;


function  ERR_EVP_PKEY_set_type(pkey: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_set_type_procname);
end;


function  ERR_EVP_PKEY_set_type_str(pkey: PEVP_PKEY; const _str: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_set_type_str_procname);
end;


function  ERR_EVP_PKEY_set_alias_type(pkey: PEVP_PKEY; type_: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_set_alias_type_procname);
end;



function  ERR_EVP_PKEY_set1_engine(pkey: PEVP_PKEY; e: PENGINE): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_set1_engine_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_PKEY_get0_engine(const pkey: PEVP_PKEY): PENGINE;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_get0_engine_procname);
end;

 {introduced 1.1.0}

function  ERR_EVP_PKEY_assign(pkey: PEVP_PKEY; type_: TIdC_INT; key: Pointer): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_assign_procname);
end;


function  ERR_EVP_PKEY_get0(const pkey: PEVP_PKEY): Pointer;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_get0_procname);
end;


function  ERR_EVP_PKEY_get0_hmac(const pkey: PEVP_PKEY; len: PIdC_SIZET): PByte;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_get0_hmac_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_PKEY_get0_poly1305(const pkey: PEVP_PKEY; len: PIdC_SIZET): PByte;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_get0_poly1305_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_PKEY_get0_siphash(const pkey: PEVP_PKEY; len: PIdC_SIZET): PByte;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_get0_siphash_procname);
end;

 {introduced 1.1.0}

function  ERR_EVP_PKEY_set1_RSA(pkey: PEVP_PKEY; key: PRSA): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_set1_RSA_procname);
end;


function  ERR_EVP_PKEY_get0_RSA(pkey: PEVP_PKEY): PRSA;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_get0_RSA_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_PKEY_get1_RSA(pkey: PEVP_PKEY): PRSA;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_get1_RSA_procname);
end;



function  ERR_EVP_PKEY_set1_DSA(pkey: PEVP_PKEY; key: PDSA): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_set1_DSA_procname);
end;


function  ERR_EVP_PKEY_get0_DSA(pkey: PEVP_PKEY): PDSA;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_get0_DSA_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_PKEY_get1_DSA(pkey: PEVP_PKEY): PDSA;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_get1_DSA_procname);
end;



function  ERR_EVP_PKEY_set1_DH(pkey: PEVP_PKEY; key: PDH): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_set1_DH_procname);
end;


function  ERR_EVP_PKEY_get0_DH(pkey: PEVP_PKEY): PDH;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_get0_DH_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_PKEY_get1_DH(pkey: PEVP_PKEY): PDH;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_get1_DH_procname);
end;



function  ERR_EVP_PKEY_set1_EC_KEY(pkey: PEVP_PKEY; key: PEC_KEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_set1_EC_KEY_procname);
end;


function  ERR_EVP_PKEY_get0_EC_KEY(pkey: PEVP_PKEY): PEC_KEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_get0_EC_KEY_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_PKEY_get1_EC_KEY(pkey: PEVP_PKEY): PEC_KEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_get1_EC_KEY_procname);
end;



function  ERR_EVP_PKEY_new: PEVP_PKEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_new_procname);
end;


function  ERR_EVP_PKEY_up_ref(pkey: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_up_ref_procname);
end;

 {introduced 1.1.0}
procedure  ERR_EVP_PKEY_free(pkey: PEVP_PKEY);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_free_procname);
end;



function  ERR_d2i_PublicKey(type_: TIdC_INT; a: PPEVP_PKEY; const pp: PPByte; _length: TIdC_LONG): PEVP_PKEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PublicKey_procname);
end;


function  ERR_i2d_PublicKey(a: PEVP_PKEY; pp: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PublicKey_procname);
end;



function  ERR_d2i_PrivateKey(type_: TIdC_INT; a: PEVP_PKEY; const pp: PPByte; _length: TIdC_LONG): PEVP_PKEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PrivateKey_procname);
end;


function  ERR_d2i_AutoPrivateKey(a: PPEVP_PKEY; const pp: PPByte; _length: TIdC_LONG): PEVP_PKEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_AutoPrivateKey_procname);
end;

function ERR_d2i_AutoPrivateKey_ex(a: PPEVP_PKEY; const pp: PPByte; _length: TIdC_LONG;
    libctx : POSSL_LIB_CTX; propq : PIdAnsiChar): PEVP_PKEY; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_AutoPrivateKey_ex_procname);
end;

function  ERR_i2d_PrivateKey(a: PEVP_PKEY; pp: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PrivateKey_procname);
end;

function ERR_i2d_KeyParams_bio(pb : PBIO; const pkey : PEVP_PKEY) : TIdC_INT; cdecl;
begin
   ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_KeyParams_bio_procname);
end;

function ERR_d2i_KeyParams_bio(type_ : TIdC_INT; var a : PEVP_PKEY; in_ : PBIO) : PEVP_PKEY; cdecl;
begin
   ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_KeyParams_bio_procname);
end;

function  ERR_EVP_PKEY_copy_parameters(to_: PEVP_PKEY; const from: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_copy_parameters_procname);
end;


function  ERR_EVP_PKEY_missing_parameters(const pkey: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_missing_parameters_procname);
end;


function  ERR_EVP_PKEY_save_parameters(pkey: PEVP_PKEY; mode: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_save_parameters_procname);
end;


function  ERR_EVP_PKEY_cmp_parameters(const a: PEVP_PKEY; const b: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_cmp_parameters_procname);
end;



function  ERR_EVP_PKEY_cmp(const a: PEVP_PKEY; const b: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_cmp_procname);
end;



function  ERR_EVP_PKEY_print_public(out_: PBIO; const pkey: PEVP_PKEY; indent: TIdC_INT; pctx: PASN1_PCTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_print_public_procname);
end;


function  ERR_EVP_PKEY_print_private(out_: PBIO; const pkey: PEVP_PKEY; indent: TIdC_INT; pctx: PASN1_PCTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_print_private_procname);
end;


function  ERR_EVP_PKEY_print_params(out_: PBIO; const pkey: PEVP_PKEY; indent: TIdC_INT; pctx: PASN1_PCTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_print_params_procname);
end;




function  ERR_EVP_PKEY_get_default_digest_nid(pkey: PEVP_PKEY; pnid: PIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_get_default_digest_nid_procname);
end;



function  ERR_EVP_PKEY_set1_tls_encodedpoint(pkey: PEVP_PKEY; const pt: PByte; ptlen: TIdC_SIZET): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_set1_tls_encodedpoint_procname);
end;


function  ERR_EVP_PKEY_get1_tls_encodedpoint(pkey: PEVP_PKEY; ppt: PPByte): TIdC_SIZET;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_get1_tls_encodedpoint_procname);
end;



function  ERR_EVP_CIPHER_type(const ctx: PEVP_CIPHER): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_type_procname);
end;

function  ERR_EVP_CIPHER_get_type(const ctx: PEVP_CIPHER): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_get_type_procname);
end;

  (* calls methods *)
function  ERR_EVP_CIPHER_param_to_asn1(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_param_to_asn1_procname);
end;


function  ERR_EVP_CIPHER_asn1_to_param(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_asn1_to_param_procname);
end;



  (* These are used by EVP_CIPHER methods *)
function  ERR_EVP_CIPHER_set_asn1_iv(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_set_asn1_iv_procname);
end;


function  ERR_EVP_CIPHER_get_asn1_iv(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_get_asn1_iv_procname);
end;

function ERR_EVP_CIPHER_get_mode(const cipher : PEVP_CIPHER) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_CIPHER_get_mode_procname);
end;



  (* PKCS5 password based encryption *)
function  ERR_PKCS5_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; const pass: PIdAnsiChar; passlen: TIdC_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md: PEVP_MD; en_de: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS5_PBE_keyivgen_procname);
end;


function  ERR_PKCS5_PBKDF2_HMAC_SHA1(const pass: PIdAnsiChar; passlen: TIdC_INT; const salt: PByte; saltlen: TIdC_INT; iter: TIdC_INT; keylen: TIdC_INT; out_: PByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS5_PBKDF2_HMAC_SHA1_procname);
end;


function  ERR_PKCS5_PBKDF2_HMAC(const pass: PIdAnsiChar; passlen: TIdC_INT; const salt: PByte; saltlen: TIdC_INT; iter: TIdC_INT; const digest: PEVP_MD; keylen: TIdC_INT; out_: PByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS5_PBKDF2_HMAC_procname);
end;


function  ERR_PKCS5_v2_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; const pass: PIdAnsiChar; passlen: TIdC_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md: PEVP_MD; en_de: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS5_v2_PBE_keyivgen_procname);
end;



function  ERR_EVP_PBE_scrypt(const pass: PIdAnsiChar; passlen: TIdC_SIZET; const salt: PByte; saltlen: TIdC_SIZET; N: TIdC_UINT64; r: TIdC_UINT64; p: TIdC_UINT64; maxmem: TIdC_UINT64; key: PByte; keylen: TIdC_SIZET): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PBE_scrypt_procname);
end;

 {introduced 1.1.0}

function  ERR_PKCS5_v2_scrypt_keyivgen(ctx: PEVP_CIPHER_CTX; const pass: PIdAnsiChar; passlen: TIdC_INT; param: PASN1_TYPE; const c: PEVP_CIPHER; const md: PEVP_MD; en_de: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS5_v2_scrypt_keyivgen_procname);
end;

 {introduced 1.1.0}

procedure  ERR_PKCS5_PBE_add;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS5_PBE_add_procname);
end;



function  ERR_EVP_PBE_CipherInit(pbe_obj: PASN1_OBJECT; const pass: PIdAnsiChar; passlen: TIdC_INT; param: PASN1_TYPE; ctx: PEVP_CIPHER_CTX; en_de: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PBE_CipherInit_procname);
end;



  (* PBE type *)
function  ERR_EVP_PBE_alg_add_type(pbe_type: TIdC_INT; pbe_nid: TIdC_INT; cipher_nid: TIdC_INT; md_nid: TIdC_INT; keygen: PEVP_PBE_KEYGEN): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PBE_alg_add_type_procname);
end;


function  ERR_EVP_PBE_alg_add(nid: TIdC_INT; const cipher: PEVP_CIPHER; const md: PEVP_MD; keygen: PEVP_PBE_KEYGEN): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PBE_alg_add_procname);
end;


function  ERR_EVP_PBE_find(type_: TIdC_INT; pbe_nid: TIdC_INT; pcnid: PIdC_INT; pmnid: PIdC_INT; pkeygen: PPEVP_PBE_KEYGEN): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PBE_find_procname);
end;


procedure  ERR_EVP_PBE_cleanup;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PBE_cleanup_procname);
end;


function  ERR_EVP_PBE_get(ptype: PIdC_INT; ppbe_nid: PIdC_INT; num: TIdC_SIZET): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PBE_get_procname);
end;

 {introduced 1.1.0}

function  ERR_EVP_PKEY_asn1_get_count: TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_asn1_get_count_procname);
end;


function  ERR_EVP_PKEY_asn1_get0(idx: TIdC_INT): PEVP_PKEY_ASN1_METHOD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_asn1_get0_procname);
end;


function  ERR_EVP_PKEY_asn1_find(pe: PPENGINE; type_: TIdC_INT): PEVP_PKEY_ASN1_METHOD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_asn1_find_procname);
end;


function  ERR_EVP_PKEY_asn1_find_str(pe: PPENGINE; const _str: PIdAnsiChar; len: TIdC_INT): PEVP_PKEY_ASN1_METHOD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_asn1_find_str_procname);
end;


function  ERR_EVP_PKEY_asn1_add0(const ameth: PEVP_PKEY_ASN1_METHOD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_asn1_add0_procname);
end;


function  ERR_EVP_PKEY_asn1_add_alias(to_: TIdC_INT; from: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_asn1_add_alias_procname);
end;


function  ERR_EVP_PKEY_asn1_get0_info(ppkey_id: PIdC_INT; pkey_base_id: PIdC_INT; ppkey_flags: PIdC_INT; const pinfo: PPIdAnsiChar; const ppem_str: PPIdAnsiChar; const ameth: PEVP_PKEY_ASN1_METHOD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_asn1_get0_info_procname);
end;



function  ERR_EVP_PKEY_get0_asn1(const pkey: PEVP_PKEY): PEVP_PKEY_ASN1_METHOD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_get0_asn1_procname);
end;


function  ERR_EVP_PKEY_asn1_new(id: TIdC_INT; flags: TIdC_INT; const pem_str: PIdAnsiChar; const info: PIdAnsiChar): PEVP_PKEY_ASN1_METHOD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_asn1_new_procname);
end;


procedure  ERR_EVP_PKEY_asn1_copy(dst: PEVP_PKEY_ASN1_METHOD; const src: PEVP_PKEY_ASN1_METHOD);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_asn1_copy_procname);
end;


procedure  ERR_EVP_PKEY_asn1_free(ameth: PEVP_PKEY_ASN1_METHOD);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_asn1_free_procname);
end;



procedure  ERR_EVP_PKEY_asn1_set_public(ameth: PEVP_PKEY_ASN1_METHOD; APub_decode: pub_decode; APub_encode: pub_encode; APub_cmd: pub_cmd; APub_print: pub_print; APkey_size: pkey_size; APkey_bits: pkey_bits);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_asn1_set_public_procname);
end;


procedure  ERR_EVP_PKEY_asn1_set_private(ameth: PEVP_PKEY_ASN1_METHOD; APriv_decode: priv_decode; APriv_encode: priv_encode; APriv_print: priv_print);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_asn1_set_private_procname);
end;


procedure  ERR_EVP_PKEY_asn1_set_param(ameth: PEVP_PKEY_ASN1_METHOD; AParam_decode: param_decode; AParam_encode: param_encode; AParam_missing: param_missing; AParam__copy: param_copy; AParam_cmp: param_cmp; AParam_print: param_print);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_asn1_set_param_procname);
end;



procedure  ERR_EVP_PKEY_asn1_set_free(ameth: PEVP_PKEY_ASN1_METHOD; APkey_free: pkey_free);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_asn1_set_free_procname);
end;


procedure  ERR_EVP_PKEY_asn1_set_ctrl(ameth: PEVP_PKEY_ASN1_METHOD; APkey_ctrl: pkey_ctrl);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_asn1_set_ctrl_procname);
end;


procedure  ERR_EVP_PKEY_asn1_set_item(ameth: PEVP_PKEY_ASN1_METHOD; AItem_verify: item_verify; AItem_sign: item_sign);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_asn1_set_item_procname);
end;



procedure  ERR_EVP_PKEY_asn1_set_siginf(ameth: PEVP_PKEY_ASN1_METHOD; ASiginf_set: siginf_set); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_asn1_set_siginf_procname);
end;

 {introduced 1.1.0}

procedure  ERR_EVP_PKEY_asn1_set_check(ameth: PEVP_PKEY_ASN1_METHOD; APkey_check: pkey_check);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_asn1_set_check_procname);
end;

 {introduced 1.1.0}

procedure  ERR_EVP_PKEY_asn1_set_public_check(ameth: PEVP_PKEY_ASN1_METHOD; APkey_pub_check: pkey_pub_check);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_asn1_set_public_check_procname);
end;

 {introduced 1.1.0}

procedure  ERR_EVP_PKEY_asn1_set_param_check(ameth: PEVP_PKEY_ASN1_METHOD; APkey_param_check: pkey_param_check);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_asn1_set_param_check_procname);
end;

 {introduced 1.1.0}

procedure  ERR_EVP_PKEY_asn1_set_set_priv_key(ameth: PEVP_PKEY_ASN1_METHOD; ASet_priv_key: set_priv_key);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_asn1_set_set_priv_key_procname);
end;

 {introduced 1.1.0}
procedure  ERR_EVP_PKEY_asn1_set_set_pub_key(ameth: PEVP_PKEY_ASN1_METHOD; ASet_pub_key: set_pub_key);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_asn1_set_set_pub_key_procname);
end;

 {introduced 1.1.0}
procedure  ERR_EVP_PKEY_asn1_set_get_priv_key(ameth: PEVP_PKEY_ASN1_METHOD; AGet_priv_key: get_priv_key);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_asn1_set_get_priv_key_procname);
end;

 {introduced 1.1.0}
procedure  ERR_EVP_PKEY_asn1_set_get_pub_key(ameth: PEVP_PKEY_ASN1_METHOD; AGet_pub_key: get_pub_key);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_asn1_set_get_pub_key_procname);
end;

 {introduced 1.1.0}

procedure  ERR_EVP_PKEY_asn1_set_security_bits(ameth: PEVP_PKEY_ASN1_METHOD; APkey_security_bits: pkey_security_bits);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_asn1_set_security_bits_procname);
end;

 {introduced 1.1.0}

function  ERR_EVP_PKEY_meth_find(type_: TIdC_INT): PEVP_PKEY_METHOD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_find_procname);
end;


function  ERR_EVP_PKEY_meth_new(id: TIdC_INT; flags: TIdC_INT): PEVP_PKEY_METHOD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_new_procname);
end;


procedure  ERR_EVP_PKEY_meth_get0_info(ppkey_id: PIdC_INT; pflags: PIdC_INT; const meth: PEVP_PKEY_METHOD); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_get0_info_procname);
end;


procedure  ERR_EVP_PKEY_meth_copy(dst: PEVP_PKEY_METHOD; const src: PEVP_PKEY_METHOD);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_copy_procname);
end;


procedure  ERR_EVP_PKEY_meth_free(pmeth: PEVP_PKEY_METHOD);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_free_procname);
end;


function  ERR_EVP_PKEY_meth_add0(const pmeth: PEVP_PKEY_METHOD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_add0_procname);
end;


function  ERR_EVP_PKEY_meth_remove(const pmeth: PEVP_PKEY_METHOD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_remove_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_PKEY_meth_get_count: TIdC_SIZET;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_get_count_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_PKEY_meth_get0(idx: TIdC_SIZET): PEVP_PKEY_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_get0_procname);
end;

 {introduced 1.1.0}

function  ERR_EVP_PKEY_CTX_new(pkey: PEVP_PKEY; e: PENGINE): PEVP_PKEY_CTX;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_new_procname);
end;


function  ERR_EVP_PKEY_CTX_new_id(id: TIdC_INT; e: PENGINE): PEVP_PKEY_CTX;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_new_id_procname);
end;


function  ERR_EVP_PKEY_CTX_dup(ctx: PEVP_PKEY_CTX): PEVP_PKEY_CTX;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_dup_procname);
end;


procedure  ERR_EVP_PKEY_CTX_free(ctx: PEVP_PKEY_CTX);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_free_procname);
end;



function  ERR_EVP_PKEY_CTX_ctrl(ctx: PEVP_PKEY_CTX; keytype: TIdC_INT; optype: TIdC_INT; cmd: TIdC_INT; p1: TIdC_INT; p2: Pointer): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_ctrl_procname);
end;


function  ERR_EVP_PKEY_CTX_ctrl_str(ctx: PEVP_PKEY_CTX; const type_: PIdAnsiChar; const value: PIdAnsiChar): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_ctrl_str_procname);
end;


function  ERR_EVP_PKEY_CTX_ctrl_uint64(ctx: PEVP_PKEY_CTX; keytype: TIdC_INT; optype: TIdC_INT; cmd: TIdC_INT; value: TIdC_UINT64): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_ctrl_uint64_procname);
end;

 {introduced 1.1.0}

function  ERR_EVP_PKEY_CTX_str2ctrl(ctx: PEVP_PKEY_CTX; cmd: TIdC_INT; const _str: PIdAnsiChar): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_str2ctrl_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_PKEY_CTX_hex2ctrl(ctx: PEVP_PKEY_CTX; cmd: TIdC_INT; const hex: PIdAnsiChar): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_hex2ctrl_procname);
end;

 {introduced 1.1.0}

function  ERR_EVP_PKEY_CTX_md(ctx: PEVP_PKEY_CTX; optype: TIdC_INT; cmd: TIdC_INT; const md: PIdAnsiChar): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_md_procname);
end;

 {introduced 1.1.0}

function  ERR_EVP_PKEY_CTX_get_operation(ctx: PEVP_PKEY_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_get_operation_procname);
end;


procedure  ERR_EVP_PKEY_CTX_set0_keygen_info(ctx: PEVP_PKEY_CTX; dat: PIdC_INT; datlen: TIdC_INT);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set0_keygen_info_procname);
end;



function  ERR_EVP_PKEY_new_mac_key(type_: TIdC_INT; e: PENGINE; const key: PByte; keylen: TIdC_INT): PEVP_PKEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_new_mac_key_procname);
end;


function  ERR_EVP_PKEY_new_raw_private_key(type_: TIdC_INT; e: PENGINE; const priv: PByte; len: TIdC_SIZET): PEVP_PKEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_new_raw_private_key_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_PKEY_new_raw_public_key(type_: TIdC_INT; e: PENGINE; const pub: PByte; len: TIdC_SIZET): PEVP_PKEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_new_raw_public_key_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_PKEY_get_raw_private_key(const pkey: PEVP_PKEY; priv: PByte; len: PIdC_SIZET): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_get_raw_private_key_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_PKEY_get_raw_public_key(const pkey: PEVP_PKEY; pub: PByte; len: PIdC_SIZET): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_get_raw_public_key_procname);
end;

 {introduced 1.1.0}

function  ERR_EVP_PKEY_new_CMAC_key(e: PENGINE; const priv: PByte; len: TIdC_SIZET; const cipher: PEVP_CIPHER): PEVP_PKEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_new_CMAC_key_procname);
end;

 {introduced 1.1.0}

procedure  ERR_EVP_PKEY_CTX_set_data(ctx: PEVP_PKEY_CTX; data: Pointer);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_data_procname);
end;


function  ERR_EVP_PKEY_CTX_get_data(ctx: PEVP_PKEY_CTX): Pointer;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_get_data_procname);
end;


function  ERR_EVP_PKEY_CTX_get0_pkey(ctx: PEVP_PKEY_CTX): PEVP_PKEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_get0_pkey_procname);
end;



function  ERR_EVP_PKEY_CTX_get0_peerkey(ctx: PEVP_PKEY_CTX): PEVP_PKEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_get0_peerkey_procname);
end;



procedure  ERR_EVP_PKEY_CTX_set_app_data(ctx: PEVP_PKEY_CTX; data: Pointer);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_app_data_procname);
end;


function  ERR_EVP_PKEY_CTX_get_app_data(ctx: PEVP_PKEY_CTX): Pointer;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_get_app_data_procname);
end;



function  ERR_EVP_PKEY_sign_init(ctx: PEVP_PKEY_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_sign_init_procname);
end;


function  ERR_EVP_PKEY_sign(ctx: PEVP_PKEY_CTX; sig: PByte; siglen: PIdC_SIZET; const tbs: PByte; tbslen: TIdC_SIZET): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_sign_procname);
end;


function  ERR_EVP_PKEY_verify_init(ctx: PEVP_PKEY_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_verify_init_procname);
end;


function  ERR_EVP_PKEY_verify(ctx: PEVP_PKEY_CTX; const sig: PByte; siglen: TIdC_SIZET; const tbs: PByte; tbslen: TIdC_SIZET): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_verify_procname);
end;


function  ERR_EVP_PKEY_verify_recover_init(ctx: PEVP_PKEY_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_verify_recover_init_procname);
end;


function  ERR_EVP_PKEY_verify_recover(ctx: PEVP_PKEY_CTX; rout: PByte; var outlen: TIdC_SIZET; const sig: PByte; siglen: TIdC_SIZET): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_verify_recover_procname);
end;


function  ERR_EVP_PKEY_encrypt_init(ctx: PEVP_PKEY_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_encrypt_init_procname);
end;


function  ERR_EVP_PKEY_encrypt(ctx: PEVP_PKEY_CTX; var out_; var outlen: TIdC_SIZET; const in_; inlen: TIdC_SIZET): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_encrypt_procname);
end;


function  ERR_EVP_PKEY_decrypt_init(ctx: PEVP_PKEY_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_decrypt_init_procname);
end;


function  ERR_EVP_PKEY_decrypt(ctx: PEVP_PKEY_CTX; var out_; var outlen: TIdC_SIZET; const in_; inlen: TIdC_SIZET): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_decrypt_procname);
end;



function  ERR_EVP_PKEY_derive_init(ctx: PEVP_PKEY_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_derive_init_procname);
end;


function  ERR_EVP_PKEY_derive_set_peer(ctx: PEVP_PKEY_CTX; peer: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_derive_set_peer_procname);
end;


function  ERR_EVP_PKEY_derive(ctx: PEVP_PKEY_CTX; key: PByte; keylen: PIdC_SIZET): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_derive_procname);
end;



function  ERR_EVP_PKEY_paramgen_init(ctx: PEVP_PKEY_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_paramgen_init_procname);
end;


function  ERR_EVP_PKEY_paramgen(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_paramgen_procname);
end;


function  ERR_EVP_PKEY_keygen_init(ctx: PEVP_PKEY_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_keygen_init_procname);
end;


function  ERR_EVP_PKEY_keygen(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_keygen_procname);
end;


function  ERR_EVP_PKEY_check(ctx: PEVP_PKEY_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_check_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_PKEY_public_check(ctx: PEVP_PKEY_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_public_check_procname);
end;

 {introduced 1.1.0}
function  ERR_EVP_PKEY_param_check(ctx: PEVP_PKEY_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_param_check_procname);
end;

 {introduced 1.1.0}

procedure  ERR_EVP_PKEY_CTX_set_cb(ctx: PEVP_PKEY_CTX; cb: EVP_PKEY_gen_cb);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_cb_procname);
end;


function  ERR_EVP_PKEY_CTX_get_cb(ctx: PEVP_PKEY_CTX): EVP_PKEY_gen_cb;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_get_cb_procname);
end;



function  ERR_EVP_PKEY_CTX_get_keygen_info(ctx: PEVP_PKEY_CTX; idx: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_get_keygen_info_procname);
end;



procedure  ERR_EVP_PKEY_meth_set_init(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_init: EVP_PKEY_meth_init);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_set_init_procname);
end;



procedure  ERR_EVP_PKEY_meth_set_copy(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_copy_cb: EVP_PKEY_meth_copy_cb);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_set_copy_procname);
end;



procedure  ERR_EVP_PKEY_meth_set_cleanup(pmeth: PEVP_PKEY_METHOD; PEVP_PKEY_meth_cleanup: EVP_PKEY_meth_cleanup);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_set_cleanup_procname);
end;



procedure  ERR_EVP_PKEY_meth_set_paramgen(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_paramgen_init: EVP_PKEY_meth_paramgen_init; AEVP_PKEY_meth_paramgen: EVP_PKEY_meth_paramgen_init);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_set_paramgen_procname);
end;



procedure  ERR_EVP_PKEY_meth_set_keygen(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_keygen_init: EVP_PKEY_meth_keygen_init; AEVP_PKEY_meth_keygen: EVP_PKEY_meth_keygen);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_set_keygen_procname);
end;



procedure  ERR_EVP_PKEY_meth_set_sign(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_sign_init: EVP_PKEY_meth_sign_init; AEVP_PKEY_meth_sign: EVP_PKEY_meth_sign);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_set_sign_procname);
end;



procedure  ERR_EVP_PKEY_meth_set_verify(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_init: EVP_PKEY_meth_verify_init; AEVP_PKEY_meth_verify: EVP_PKEY_meth_verify_init);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_set_verify_procname);
end;



procedure  ERR_EVP_PKEY_meth_set_verify_recover(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_recover_init: EVP_PKEY_meth_verify_recover_init; AEVP_PKEY_meth_verify_recover: EVP_PKEY_meth_verify_recover_init);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_set_verify_recover_procname);
end;



procedure  ERR_EVP_PKEY_meth_set_signctx(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_signctx_init: EVP_PKEY_meth_signctx_init; AEVP_PKEY_meth_signctx: EVP_PKEY_meth_signctx); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_set_signctx_procname);
end;



procedure  ERR_EVP_PKEY_meth_set_verifyctx(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verifyctx_init: EVP_PKEY_meth_verifyctx_init; AEVP_PKEY_meth_verifyctx: EVP_PKEY_meth_verifyctx);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_set_verifyctx_procname);
end;



procedure  ERR_EVP_PKEY_meth_set_encrypt(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_encrypt_init: EVP_PKEY_meth_encrypt_init; AEVP_PKEY_meth_encrypt: EVP_PKEY_meth_encrypt);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_set_encrypt_procname);
end;



procedure  ERR_EVP_PKEY_meth_set_decrypt(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_decrypt_init: EVP_PKEY_meth_decrypt_init; AEVP_PKEY_meth_decrypt: EVP_PKEY_meth_decrypt);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_set_decrypt_procname);
end;



procedure  ERR_EVP_PKEY_meth_set_derive(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_derive_init: EVP_PKEY_meth_derive_init; AEVP_PKEY_meth_derive: EVP_PKEY_meth_derive);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_set_derive_procname);
end;



procedure  ERR_EVP_PKEY_meth_set_ctrl(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_ctrl: EVP_PKEY_meth_ctrl; AEVP_PKEY_meth_ctrl_str: EVP_PKEY_meth_ctrl_str);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_set_ctrl_procname);
end;



procedure  ERR_EVP_PKEY_meth_set_digestsign(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestsign: EVP_PKEY_meth_digestsign);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_set_digestsign_procname);
end;

 {introduced 1.1.0}

procedure  ERR_EVP_PKEY_meth_set_digestverify(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestverify: EVP_PKEY_meth_digestverify);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_set_digestverify_procname);
end;

 {introduced 1.1.0}

procedure  ERR_EVP_PKEY_meth_set_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_check: EVP_PKEY_meth_check);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_set_check_procname);
end;

 {introduced 1.1.0}

procedure  ERR_EVP_PKEY_meth_set_public_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_public_check: EVP_PKEY_meth_public_check);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_set_public_check_procname);
end;

 {introduced 1.1.0}

procedure  ERR_EVP_PKEY_meth_set_param_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_param_check: EVP_PKEY_meth_param_check);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_set_param_check_procname);
end;

 {introduced 1.1.0}

procedure  ERR_EVP_PKEY_meth_set_digest_custom(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digest_custom: EVP_PKEY_meth_digest_custom);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_set_digest_custom_procname);
end;

 {introduced 1.1.0}

procedure  ERR_EVP_PKEY_meth_get_init(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_init: PEVP_PKEY_meth_init);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_get_init_procname);
end;



procedure  ERR_EVP_PKEY_meth_get_copy(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth__copy: PEVP_PKEY_meth_copy);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_get_copy_procname);
end;



procedure  ERR_EVP_PKEY_meth_get_cleanup(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_cleanup: PEVP_PKEY_meth_cleanup);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_get_cleanup_procname);
end;



procedure  ERR_EVP_PKEY_meth_get_paramgen(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_paramgen_init: EVP_PKEY_meth_paramgen_init; AEVP_PKEY_meth_paramgen: PEVP_PKEY_meth_paramgen);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_get_paramgen_procname);
end;



procedure  ERR_EVP_PKEY_meth_get_keygen(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_keygen_init: EVP_PKEY_meth_keygen_init; AEVP_PKEY_meth_keygen: PEVP_PKEY_meth_keygen);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_get_keygen_procname);
end;



procedure  ERR_EVP_PKEY_meth_get_sign(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_sign_init: PEVP_PKEY_meth_sign_init; AEVP_PKEY_meth_sign: PEVP_PKEY_meth_sign);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_get_sign_procname);
end;



procedure  ERR_EVP_PKEY_meth_get_verify(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_init: PEVP_PKEY_meth_verify_init; AEVP_PKEY_meth_verify: PEVP_PKEY_meth_verify_init);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_get_verify_procname);
end;



procedure  ERR_EVP_PKEY_meth_get_verify_recover(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_recover_init: PEVP_PKEY_meth_verify_recover_init; AEVP_PKEY_meth_verify_recover: PEVP_PKEY_meth_verify_recover_init);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_get_verify_recover_procname);
end;



procedure  ERR_EVP_PKEY_meth_get_signctx(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_signctx_init: PEVP_PKEY_meth_signctx_init; AEVP_PKEY_meth_signctx: PEVP_PKEY_meth_signctx);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_get_signctx_procname);
end;



procedure  ERR_EVP_PKEY_meth_get_verifyctx(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verifyctx_init: PEVP_PKEY_meth_verifyctx_init; AEVP_PKEY_meth_verifyctx: PEVP_PKEY_meth_verifyctx);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_get_verifyctx_procname);
end;



procedure  ERR_EVP_PKEY_meth_get_encrypt(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_encrypt_init: PEVP_PKEY_meth_encrypt_init; AEVP_PKEY_meth_encrypt: PEVP_PKEY_meth_encrypt);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_get_encrypt_procname);
end;



procedure  ERR_EVP_PKEY_meth_get_decrypt(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_decrypt_init: PEVP_PKEY_meth_decrypt_init; AEVP_PKEY_meth_decrypt: PEVP_PKEY_meth_decrypt);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_get_decrypt_procname);
end;



procedure  ERR_EVP_PKEY_meth_get_derive(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_derive_init: PEVP_PKEY_meth_derive_init; AEVP_PKEY_meth_derive: PEVP_PKEY_meth_derive);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_get_derive_procname);
end;



procedure  ERR_EVP_PKEY_meth_get_ctrl(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_ctrl: PEVP_PKEY_meth_ctrl; AEVP_PKEY_meth_ctrl_str: PEVP_PKEY_meth_ctrl_str);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_get_ctrl_procname);
end;



procedure  ERR_EVP_PKEY_meth_get_digestsign(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestsign: PEVP_PKEY_meth_digestsign);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_get_digestsign_procname);
end;

 {introduced 1.1.0}

procedure  ERR_EVP_PKEY_meth_get_digestverify(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestverify: PEVP_PKEY_meth_digestverify);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_get_digestverify_procname);
end;

 {introduced 1.1.0}

procedure  ERR_EVP_PKEY_meth_get_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_check: PEVP_PKEY_meth_check);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_get_check_procname);
end;

 {introduced 1.1.0}

procedure  ERR_EVP_PKEY_meth_get_public_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_public_check: PEVP_PKEY_meth_public_check);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_get_public_check_procname);
end;

 {introduced 1.1.0}

procedure  ERR_EVP_PKEY_meth_get_param_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_param_check: PEVP_PKEY_meth_param_check);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_get_param_check_procname);
end;

 {introduced 1.1.0}

procedure  ERR_EVP_PKEY_meth_get_digest_custom(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digest_custom: PEVP_PKEY_meth_digest_custom);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_meth_get_digest_custom_procname);
end;

 {introduced 1.1.0}

procedure  ERR_EVP_add_alg_module;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_add_alg_module_procname);
end;



procedure  ERR_OpenSSL_add_all_ciphers; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OpenSSL_add_all_ciphers_procname);
end;



procedure  ERR_OpenSSL_add_all_digests; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OpenSSL_add_all_digests_procname);
end;



procedure  ERR_EVP_cleanup;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_cleanup_procname);
end;

//* MAC Stuff */
function ERR_EVP_MAC_fetch(libctx : POSSL_LIB_CTX;
    const algorithm, properties : PIdAnsiChar) : PEVP_MAC; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MAC_fetch_procname);

end;

  function ERR_EVP_MAC_up_ref(mac : PEVP_MAC) : TIdC_INT; cdecl;
begin
   ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MAC_up_ref_procname);

end;

procedure ERR_EVP_MAC_free(mac : PEVP_MAC); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MAC_free_procname);

end;

function ERR_EVP_MAC_is_a(const mac : PEVP_MAC; const name : PIdAnsiChar) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MAC_is_a_procname);

end;

function ERR_EVP_MAC_get0_name(const mac : PEVP_MAC) : PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MAC_get0_name_procname);

end;

function ERR_EVP_MAC_names_do_all(const mac : PEVP_MAC; fn : EVP_MAC_names_do_all_fn;
                         data : Pointer) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MAC_names_do_all_procname);

end;
function ERR_EVP_MAC_get0_description(const mac : PEVP_MAC) : PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MAC_get0_description_procname);

end;

function ERR_EVP_MAC_get0_provider(const mac :PEVP_MAC) : POSSL_PROVIDER; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MAC_get0_provider_procname);
end;

function ERR_EVP_MAC_get_params(mac : PEVP_MAC; params : POSSL_PARAM_ARRAY) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MAC_get_params_procname);
end;

function ERR_EVP_MAC_CTX_new(mac : PEVP_MAC) : PEVP_MAC_CTX;  {introduced 3.0.0} cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MAC_CTX_new_procname);
end;

procedure ERR_EVP_MAC_CTX_free (ctx : PEVP_MAC_CTX );   {introduced 3.0.0} cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MAC_CTX_free_procname);
end;

  function ERR_EVP_MAC_CTX_dup(const  src : PEVP_MAC_CTX) : PEVP_MAC_CTX; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MAC_CTX_dup_procname);
end;

  function ERR_EVP_MAC_CTX_get0_mac(ctx : PEVP_MAC_CTX) : PEVP_MAC; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MAC_CTX_get0_mac_procname);
end;

  function ERR_EVP_MAC_CTX_get_params(ctx : PEVP_MAC_CTX; params : POSSL_PARAM_ARRAY) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MAC_CTX_get_params_procname);
end;

  function ERR_EVP_MAC_CTX_set_params(ctx : PEVP_MAC_CTX; const  params : POSSL_PARAM_ARRAY) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MAC_CTX_set_params_procname);
end;

function ERR_EVP_MAC_CTX_get_mac_size(ctx : PEVP_MAC_CTX) : TIdC_SIZET; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MAC_CTX_get_mac_size_procname);
end;

function ERR_EVP_MAC_CTX_get_block_size(ctx : PEVP_MAC_CTX) : TIdC_SIZET; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MAC_CTX_get_block_size_procname);
end;

function ERR_EVP_MAC_init(ctx : PEVP_MAC_CTX; const key : PIdAnsiChar; keylen : TIdC_SIZET;
                 const  params : POSSL_PARAM_ARRAY) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MAC_init_procname);
end;

function ERR_EVP_MAC_init_SKEY(ctx : PEVP_MAC_CTX;  skey : PEVP_SKEY; const  params : POSSL_PARAM_ARRAY) : TIdC_INT; cdecl;
begin
   ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MAC_init_SKEY_procname);
end;

function ERR_EVP_MAC_update(ctx : PEVP_MAC_CTX; const data : PIdAnsiChar;
    datalen : TIdC_SIZET) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MAC_update_procname);
end;

function ERR_EVP_MAC_final(ctx : PEVP_MAC_CTX;
    _out : PIdAnsiChar; var outl : TIdC_SIZET; outsize : TIdC_SIZET) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MAC_final_procname);
end;

function ERR_EVP_MAC_finalXOF(ctx : PEVP_MAC_CTX; _out : PIdAnsiChar; outsize : TIdC_SIZET) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MAC_finalXOF_procname);
end;

procedure ERR_EVP_MAC_do_all_provided(libctx : POSSL_LIB_CTX;
                             fn : EVP_MAC_do_all_provided_fn;
                             arg : Pointer); cdecl;
begin
   ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_MAC_do_all_provided_procname);
end;

  {$I TaurusTLSNoRetValOn.inc} 

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  EVP_PKEY_assign_RSA := LoadLibFunction(ADllHandle, EVP_PKEY_assign_RSA_procname);
  FuncLoadError := not assigned(EVP_PKEY_assign_RSA);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_assign_RSA_allownil)}
    EVP_PKEY_assign_RSA := ERR_EVP_PKEY_assign_RSA;
    {$ifend}
    {$if declared(EVP_PKEY_assign_RSA_introduced)}
    if LibVersion < EVP_PKEY_assign_RSA_introduced then
    begin
      {$if declared(FC_EVP_PKEY_assign_RSA)}
      EVP_PKEY_assign_RSA := FC_EVP_PKEY_assign_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_assign_RSA_removed)}
    if EVP_PKEY_assign_RSA_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_assign_RSA)}
      EVP_PKEY_assign_RSA := _EVP_PKEY_assign_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_assign_RSA_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_assign_RSA');
    {$ifend}
  end;


  EVP_PKEY_assign_DSA := LoadLibFunction(ADllHandle, EVP_PKEY_assign_DSA_procname);
  FuncLoadError := not assigned(EVP_PKEY_assign_DSA);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_assign_DSA_allownil)}
    EVP_PKEY_assign_DSA := ERR_EVP_PKEY_assign_DSA;
    {$ifend}
    {$if declared(EVP_PKEY_assign_DSA_introduced)}
    if LibVersion < EVP_PKEY_assign_DSA_introduced then
    begin
      {$if declared(FC_EVP_PKEY_assign_DSA)}
      EVP_PKEY_assign_DSA := FC_EVP_PKEY_assign_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_assign_DSA_removed)}
    if EVP_PKEY_assign_DSA_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_assign_DSA)}
      EVP_PKEY_assign_DSA := _EVP_PKEY_assign_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_assign_DSA_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_assign_DSA');
    {$ifend}
  end;

 
  EVP_PKEY_assign_DH := LoadLibFunction(ADllHandle, EVP_PKEY_assign_DH_procname);
  FuncLoadError := not assigned(EVP_PKEY_assign_DH);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_assign_DH_allownil)}
    EVP_PKEY_assign_DH := ERR_EVP_PKEY_assign_DH;
    {$ifend}
    {$if declared(EVP_PKEY_assign_DH_introduced)}
    if LibVersion < EVP_PKEY_assign_DH_introduced then
    begin
      {$if declared(FC_EVP_PKEY_assign_DH)}
      EVP_PKEY_assign_DH := FC_EVP_PKEY_assign_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_assign_DH_removed)}
    if EVP_PKEY_assign_DH_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_assign_DH)}
      EVP_PKEY_assign_DH := _EVP_PKEY_assign_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_assign_DH_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_assign_DH');
    {$ifend}
  end;

 
  EVP_PKEY_assign_EC_KEY := LoadLibFunction(ADllHandle, EVP_PKEY_assign_EC_KEY_procname);
  FuncLoadError := not assigned(EVP_PKEY_assign_EC_KEY);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_assign_EC_KEY_allownil)}
    EVP_PKEY_assign_EC_KEY := ERR_EVP_PKEY_assign_EC_KEY;
    {$ifend}
    {$if declared(EVP_PKEY_assign_EC_KEY_introduced)}
    if LibVersion < EVP_PKEY_assign_EC_KEY_introduced then
    begin
      {$if declared(FC_EVP_PKEY_assign_EC_KEY)}
      EVP_PKEY_assign_EC_KEY := FC_EVP_PKEY_assign_EC_KEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_assign_EC_KEY_removed)}
    if EVP_PKEY_assign_EC_KEY_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_assign_EC_KEY)}
      EVP_PKEY_assign_EC_KEY := _EVP_PKEY_assign_EC_KEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_assign_EC_KEY_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_assign_EC_KEY');
    {$ifend}
  end;

 
  EVP_PKEY_assign_SIPHASH := LoadLibFunction(ADllHandle, EVP_PKEY_assign_SIPHASH_procname);
  FuncLoadError := not assigned(EVP_PKEY_assign_SIPHASH);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_assign_SIPHASH_allownil)}
    EVP_PKEY_assign_SIPHASH := ERR_EVP_PKEY_assign_SIPHASH;
    {$ifend}
    {$if declared(EVP_PKEY_assign_SIPHASH_introduced)}
    if LibVersion < EVP_PKEY_assign_SIPHASH_introduced then
    begin
      {$if declared(FC_EVP_PKEY_assign_SIPHASH)}
      EVP_PKEY_assign_SIPHASH := FC_EVP_PKEY_assign_SIPHASH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_assign_SIPHASH_removed)}
    if EVP_PKEY_assign_SIPHASH_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_assign_SIPHASH)}
      EVP_PKEY_assign_SIPHASH := _EVP_PKEY_assign_SIPHASH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_assign_SIPHASH_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_assign_SIPHASH');
    {$ifend}
  end;

 
  EVP_PKEY_assign_POLY1305 := LoadLibFunction(ADllHandle, EVP_PKEY_assign_POLY1305_procname);
  FuncLoadError := not assigned(EVP_PKEY_assign_POLY1305);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_assign_POLY1305_allownil)}
    EVP_PKEY_assign_POLY1305 := ERR_EVP_PKEY_assign_POLY1305;
    {$ifend}
    {$if declared(EVP_PKEY_assign_POLY1305_introduced)}
    if LibVersion < EVP_PKEY_assign_POLY1305_introduced then
    begin
      {$if declared(FC_EVP_PKEY_assign_POLY1305)}
      EVP_PKEY_assign_POLY1305 := FC_EVP_PKEY_assign_POLY1305;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_assign_POLY1305_removed)}
    if EVP_PKEY_assign_POLY1305_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_assign_POLY1305)}
      EVP_PKEY_assign_POLY1305 := _EVP_PKEY_assign_POLY1305;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_assign_POLY1305_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_assign_POLY1305');
    {$ifend}
  end;

 
  EVP_MD_meth_new := LoadLibFunction(ADllHandle, EVP_MD_meth_new_procname);
  FuncLoadError := not assigned(EVP_MD_meth_new);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_meth_new_allownil)}
    EVP_MD_meth_new := ERR_EVP_MD_meth_new;
    {$ifend}
    {$if declared(EVP_MD_meth_new_introduced)}
    if LibVersion < EVP_MD_meth_new_introduced then
    begin
      {$if declared(FC_EVP_MD_meth_new)}
      EVP_MD_meth_new := FC_EVP_MD_meth_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_meth_new_removed)}
    if EVP_MD_meth_new_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_meth_new)}
      EVP_MD_meth_new := _EVP_MD_meth_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_meth_new_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_meth_new');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_meth_dup := LoadLibFunction(ADllHandle, EVP_MD_meth_dup_procname);
  FuncLoadError := not assigned(EVP_MD_meth_dup);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_meth_dup_allownil)}
    EVP_MD_meth_dup := ERR_EVP_MD_meth_dup;
    {$ifend}
    {$if declared(EVP_MD_meth_dup_introduced)}
    if LibVersion < EVP_MD_meth_dup_introduced then
    begin
      {$if declared(FC_EVP_MD_meth_dup)}
      EVP_MD_meth_dup := FC_EVP_MD_meth_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_meth_dup_removed)}
    if EVP_MD_meth_dup_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_meth_dup)}
      EVP_MD_meth_dup := _EVP_MD_meth_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_meth_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_meth_dup');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_meth_free := LoadLibFunction(ADllHandle, EVP_MD_meth_free_procname);
  FuncLoadError := not assigned(EVP_MD_meth_free);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_meth_free_allownil)}
    EVP_MD_meth_free := ERR_EVP_MD_meth_free;
    {$ifend}
    {$if declared(EVP_MD_meth_free_introduced)}
    if LibVersion < EVP_MD_meth_free_introduced then
    begin
      {$if declared(FC_EVP_MD_meth_free)}
      EVP_MD_meth_free := FC_EVP_MD_meth_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_meth_free_removed)}
    if EVP_MD_meth_free_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_meth_free)}
      EVP_MD_meth_free := _EVP_MD_meth_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_meth_free_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_meth_free');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_meth_set_input_blocksize := LoadLibFunction(ADllHandle, EVP_MD_meth_set_input_blocksize_procname);
  FuncLoadError := not assigned(EVP_MD_meth_set_input_blocksize);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_meth_set_input_blocksize_allownil)}
    EVP_MD_meth_set_input_blocksize := ERR_EVP_MD_meth_set_input_blocksize;
    {$ifend}
    {$if declared(EVP_MD_meth_set_input_blocksize_introduced)}
    if LibVersion < EVP_MD_meth_set_input_blocksize_introduced then
    begin
      {$if declared(FC_EVP_MD_meth_set_input_blocksize)}
      EVP_MD_meth_set_input_blocksize := FC_EVP_MD_meth_set_input_blocksize;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_meth_set_input_blocksize_removed)}
    if EVP_MD_meth_set_input_blocksize_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_meth_set_input_blocksize)}
      EVP_MD_meth_set_input_blocksize := _EVP_MD_meth_set_input_blocksize;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_meth_set_input_blocksize_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_meth_set_input_blocksize');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_meth_set_result_size := LoadLibFunction(ADllHandle, EVP_MD_meth_set_result_size_procname);
  FuncLoadError := not assigned(EVP_MD_meth_set_result_size);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_meth_set_result_size_allownil)}
    EVP_MD_meth_set_result_size := ERR_EVP_MD_meth_set_result_size;
    {$ifend}
    {$if declared(EVP_MD_meth_set_result_size_introduced)}
    if LibVersion < EVP_MD_meth_set_result_size_introduced then
    begin
      {$if declared(FC_EVP_MD_meth_set_result_size)}
      EVP_MD_meth_set_result_size := FC_EVP_MD_meth_set_result_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_meth_set_result_size_removed)}
    if EVP_MD_meth_set_result_size_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_meth_set_result_size)}
      EVP_MD_meth_set_result_size := _EVP_MD_meth_set_result_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_meth_set_result_size_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_meth_set_result_size');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_meth_set_app_datasize := LoadLibFunction(ADllHandle, EVP_MD_meth_set_app_datasize_procname);
  FuncLoadError := not assigned(EVP_MD_meth_set_app_datasize);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_meth_set_app_datasize_allownil)}
    EVP_MD_meth_set_app_datasize := ERR_EVP_MD_meth_set_app_datasize;
    {$ifend}
    {$if declared(EVP_MD_meth_set_app_datasize_introduced)}
    if LibVersion < EVP_MD_meth_set_app_datasize_introduced then
    begin
      {$if declared(FC_EVP_MD_meth_set_app_datasize)}
      EVP_MD_meth_set_app_datasize := FC_EVP_MD_meth_set_app_datasize;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_meth_set_app_datasize_removed)}
    if EVP_MD_meth_set_app_datasize_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_meth_set_app_datasize)}
      EVP_MD_meth_set_app_datasize := _EVP_MD_meth_set_app_datasize;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_meth_set_app_datasize_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_meth_set_app_datasize');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_meth_set_flags := LoadLibFunction(ADllHandle, EVP_MD_meth_set_flags_procname);
  FuncLoadError := not assigned(EVP_MD_meth_set_flags);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_meth_set_flags_allownil)}
    EVP_MD_meth_set_flags := ERR_EVP_MD_meth_set_flags;
    {$ifend}
    {$if declared(EVP_MD_meth_set_flags_introduced)}
    if LibVersion < EVP_MD_meth_set_flags_introduced then
    begin
      {$if declared(FC_EVP_MD_meth_set_flags)}
      EVP_MD_meth_set_flags := FC_EVP_MD_meth_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_meth_set_flags_removed)}
    if EVP_MD_meth_set_flags_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_meth_set_flags)}
      EVP_MD_meth_set_flags := _EVP_MD_meth_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_meth_set_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_meth_set_flags');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_meth_set_init := LoadLibFunction(ADllHandle, EVP_MD_meth_set_init_procname);
  FuncLoadError := not assigned(EVP_MD_meth_set_init);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_meth_set_init_allownil)}
    EVP_MD_meth_set_init := ERR_EVP_MD_meth_set_init;
    {$ifend}
    {$if declared(EVP_MD_meth_set_init_introduced)}
    if LibVersion < EVP_MD_meth_set_init_introduced then
    begin
      {$if declared(FC_EVP_MD_meth_set_init)}
      EVP_MD_meth_set_init := FC_EVP_MD_meth_set_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_meth_set_init_removed)}
    if EVP_MD_meth_set_init_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_meth_set_init)}
      EVP_MD_meth_set_init := _EVP_MD_meth_set_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_meth_set_init_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_meth_set_init');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_meth_set_update := LoadLibFunction(ADllHandle, EVP_MD_meth_set_update_procname);
  FuncLoadError := not assigned(EVP_MD_meth_set_update);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_meth_set_update_allownil)}
    EVP_MD_meth_set_update := ERR_EVP_MD_meth_set_update;
    {$ifend}
    {$if declared(EVP_MD_meth_set_update_introduced)}
    if LibVersion < EVP_MD_meth_set_update_introduced then
    begin
      {$if declared(FC_EVP_MD_meth_set_update)}
      EVP_MD_meth_set_update := FC_EVP_MD_meth_set_update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_meth_set_update_removed)}
    if EVP_MD_meth_set_update_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_meth_set_update)}
      EVP_MD_meth_set_update := _EVP_MD_meth_set_update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_meth_set_update_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_meth_set_update');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_meth_set_final := LoadLibFunction(ADllHandle, EVP_MD_meth_set_final_procname);
  FuncLoadError := not assigned(EVP_MD_meth_set_final);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_meth_set_final_allownil)}
    EVP_MD_meth_set_final := ERR_EVP_MD_meth_set_final;
    {$ifend}
    {$if declared(EVP_MD_meth_set_final_introduced)}
    if LibVersion < EVP_MD_meth_set_final_introduced then
    begin
      {$if declared(FC_EVP_MD_meth_set_final)}
      EVP_MD_meth_set_final := FC_EVP_MD_meth_set_final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_meth_set_final_removed)}
    if EVP_MD_meth_set_final_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_meth_set_final)}
      EVP_MD_meth_set_final := _EVP_MD_meth_set_final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_meth_set_final_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_meth_set_final');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_meth_set_copy := LoadLibFunction(ADllHandle, EVP_MD_meth_set_copy_procname);
  FuncLoadError := not assigned(EVP_MD_meth_set_copy);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_meth_set_copy_allownil)}
    EVP_MD_meth_set_copy := ERR_EVP_MD_meth_set_copy;
    {$ifend}
    {$if declared(EVP_MD_meth_set_copy_introduced)}
    if LibVersion < EVP_MD_meth_set_copy_introduced then
    begin
      {$if declared(FC_EVP_MD_meth_set_copy)}
      EVP_MD_meth_set_copy := FC_EVP_MD_meth_set_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_meth_set_copy_removed)}
    if EVP_MD_meth_set_copy_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_meth_set_copy)}
      EVP_MD_meth_set_copy := _EVP_MD_meth_set_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_meth_set_copy_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_meth_set_copy');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_meth_set_cleanup := LoadLibFunction(ADllHandle, EVP_MD_meth_set_cleanup_procname);
  FuncLoadError := not assigned(EVP_MD_meth_set_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_meth_set_cleanup_allownil)}
    EVP_MD_meth_set_cleanup := ERR_EVP_MD_meth_set_cleanup;
    {$ifend}
    {$if declared(EVP_MD_meth_set_cleanup_introduced)}
    if LibVersion < EVP_MD_meth_set_cleanup_introduced then
    begin
      {$if declared(FC_EVP_MD_meth_set_cleanup)}
      EVP_MD_meth_set_cleanup := FC_EVP_MD_meth_set_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_meth_set_cleanup_removed)}
    if EVP_MD_meth_set_cleanup_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_meth_set_cleanup)}
      EVP_MD_meth_set_cleanup := _EVP_MD_meth_set_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_meth_set_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_meth_set_cleanup');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_meth_set_ctrl := LoadLibFunction(ADllHandle, EVP_MD_meth_set_ctrl_procname);
  FuncLoadError := not assigned(EVP_MD_meth_set_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_meth_set_ctrl_allownil)}
    EVP_MD_meth_set_ctrl := ERR_EVP_MD_meth_set_ctrl;
    {$ifend}
    {$if declared(EVP_MD_meth_set_ctrl_introduced)}
    if LibVersion < EVP_MD_meth_set_ctrl_introduced then
    begin
      {$if declared(FC_EVP_MD_meth_set_ctrl)}
      EVP_MD_meth_set_ctrl := FC_EVP_MD_meth_set_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_meth_set_ctrl_removed)}
    if EVP_MD_meth_set_ctrl_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_meth_set_ctrl)}
      EVP_MD_meth_set_ctrl := _EVP_MD_meth_set_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_meth_set_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_meth_set_ctrl');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_meth_get_input_blocksize := LoadLibFunction(ADllHandle, EVP_MD_meth_get_input_blocksize_procname);
  FuncLoadError := not assigned(EVP_MD_meth_get_input_blocksize);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_meth_get_input_blocksize_allownil)}
    EVP_MD_meth_get_input_blocksize := ERR_EVP_MD_meth_get_input_blocksize;
    {$ifend}
    {$if declared(EVP_MD_meth_get_input_blocksize_introduced)}
    if LibVersion < EVP_MD_meth_get_input_blocksize_introduced then
    begin
      {$if declared(FC_EVP_MD_meth_get_input_blocksize)}
      EVP_MD_meth_get_input_blocksize := FC_EVP_MD_meth_get_input_blocksize;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_meth_get_input_blocksize_removed)}
    if EVP_MD_meth_get_input_blocksize_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_meth_get_input_blocksize)}
      EVP_MD_meth_get_input_blocksize := _EVP_MD_meth_get_input_blocksize;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_meth_get_input_blocksize_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_meth_get_input_blocksize');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_meth_get_result_size := LoadLibFunction(ADllHandle, EVP_MD_meth_get_result_size_procname);
  FuncLoadError := not assigned(EVP_MD_meth_get_result_size);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_meth_get_result_size_allownil)}
    EVP_MD_meth_get_result_size := ERR_EVP_MD_meth_get_result_size;
    {$ifend}
    {$if declared(EVP_MD_meth_get_result_size_introduced)}
    if LibVersion < EVP_MD_meth_get_result_size_introduced then
    begin
      {$if declared(FC_EVP_MD_meth_get_result_size)}
      EVP_MD_meth_get_result_size := FC_EVP_MD_meth_get_result_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_meth_get_result_size_removed)}
    if EVP_MD_meth_get_result_size_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_meth_get_result_size)}
      EVP_MD_meth_get_result_size := _EVP_MD_meth_get_result_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_meth_get_result_size_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_meth_get_result_size');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_meth_get_app_datasize := LoadLibFunction(ADllHandle, EVP_MD_meth_get_app_datasize_procname);
  FuncLoadError := not assigned(EVP_MD_meth_get_app_datasize);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_meth_get_app_datasize_allownil)}
    EVP_MD_meth_get_app_datasize := ERR_EVP_MD_meth_get_app_datasize;
    {$ifend}
    {$if declared(EVP_MD_meth_get_app_datasize_introduced)}
    if LibVersion < EVP_MD_meth_get_app_datasize_introduced then
    begin
      {$if declared(FC_EVP_MD_meth_get_app_datasize)}
      EVP_MD_meth_get_app_datasize := FC_EVP_MD_meth_get_app_datasize;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_meth_get_app_datasize_removed)}
    if EVP_MD_meth_get_app_datasize_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_meth_get_app_datasize)}
      EVP_MD_meth_get_app_datasize := _EVP_MD_meth_get_app_datasize;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_meth_get_app_datasize_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_meth_get_app_datasize');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_meth_get_flags := LoadLibFunction(ADllHandle, EVP_MD_meth_get_flags_procname);
  FuncLoadError := not assigned(EVP_MD_meth_get_flags);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_meth_get_flags_allownil)}
    EVP_MD_meth_get_flags := ERR_EVP_MD_meth_get_flags;
    {$ifend}
    {$if declared(EVP_MD_meth_get_flags_introduced)}
    if LibVersion < EVP_MD_meth_get_flags_introduced then
    begin
      {$if declared(FC_EVP_MD_meth_get_flags)}
      EVP_MD_meth_get_flags := FC_EVP_MD_meth_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_meth_get_flags_removed)}
    if EVP_MD_meth_get_flags_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_meth_get_flags)}
      EVP_MD_meth_get_flags := _EVP_MD_meth_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_meth_get_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_meth_get_flags');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_meth_get_init := LoadLibFunction(ADllHandle, EVP_MD_meth_get_init_procname);
  FuncLoadError := not assigned(EVP_MD_meth_get_init);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_meth_get_init_allownil)}
    EVP_MD_meth_get_init := ERR_EVP_MD_meth_get_init;
    {$ifend}
    {$if declared(EVP_MD_meth_get_init_introduced)}
    if LibVersion < EVP_MD_meth_get_init_introduced then
    begin
      {$if declared(FC_EVP_MD_meth_get_init)}
      EVP_MD_meth_get_init := FC_EVP_MD_meth_get_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_meth_get_init_removed)}
    if EVP_MD_meth_get_init_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_meth_get_init)}
      EVP_MD_meth_get_init := _EVP_MD_meth_get_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_meth_get_init_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_meth_get_init');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_meth_get_update := LoadLibFunction(ADllHandle, EVP_MD_meth_get_update_procname);
  FuncLoadError := not assigned(EVP_MD_meth_get_update);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_meth_get_update_allownil)}
    EVP_MD_meth_get_update := ERR_EVP_MD_meth_get_update;
    {$ifend}
    {$if declared(EVP_MD_meth_get_update_introduced)}
    if LibVersion < EVP_MD_meth_get_update_introduced then
    begin
      {$if declared(FC_EVP_MD_meth_get_update)}
      EVP_MD_meth_get_update := FC_EVP_MD_meth_get_update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_meth_get_update_removed)}
    if EVP_MD_meth_get_update_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_meth_get_update)}
      EVP_MD_meth_get_update := _EVP_MD_meth_get_update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_meth_get_update_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_meth_get_update');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_meth_get_final := LoadLibFunction(ADllHandle, EVP_MD_meth_get_final_procname);
  FuncLoadError := not assigned(EVP_MD_meth_get_final);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_meth_get_final_allownil)}
    EVP_MD_meth_get_final := ERR_EVP_MD_meth_get_final;
    {$ifend}
    {$if declared(EVP_MD_meth_get_final_introduced)}
    if LibVersion < EVP_MD_meth_get_final_introduced then
    begin
      {$if declared(FC_EVP_MD_meth_get_final)}
      EVP_MD_meth_get_final := FC_EVP_MD_meth_get_final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_meth_get_final_removed)}
    if EVP_MD_meth_get_final_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_meth_get_final)}
      EVP_MD_meth_get_final := _EVP_MD_meth_get_final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_meth_get_final_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_meth_get_final');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_meth_get_copy := LoadLibFunction(ADllHandle, EVP_MD_meth_get_copy_procname);
  FuncLoadError := not assigned(EVP_MD_meth_get_copy);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_meth_get_copy_allownil)}
    EVP_MD_meth_get_copy := ERR_EVP_MD_meth_get_copy;
    {$ifend}
    {$if declared(EVP_MD_meth_get_copy_introduced)}
    if LibVersion < EVP_MD_meth_get_copy_introduced then
    begin
      {$if declared(FC_EVP_MD_meth_get_copy)}
      EVP_MD_meth_get_copy := FC_EVP_MD_meth_get_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_meth_get_copy_removed)}
    if EVP_MD_meth_get_copy_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_meth_get_copy)}
      EVP_MD_meth_get_copy := _EVP_MD_meth_get_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_meth_get_copy_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_meth_get_copy');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_meth_get_cleanup := LoadLibFunction(ADllHandle, EVP_MD_meth_get_cleanup_procname);
  FuncLoadError := not assigned(EVP_MD_meth_get_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_meth_get_cleanup_allownil)}
    EVP_MD_meth_get_cleanup := ERR_EVP_MD_meth_get_cleanup;
    {$ifend}
    {$if declared(EVP_MD_meth_get_cleanup_introduced)}
    if LibVersion < EVP_MD_meth_get_cleanup_introduced then
    begin
      {$if declared(FC_EVP_MD_meth_get_cleanup)}
      EVP_MD_meth_get_cleanup := FC_EVP_MD_meth_get_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_meth_get_cleanup_removed)}
    if EVP_MD_meth_get_cleanup_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_meth_get_cleanup)}
      EVP_MD_meth_get_cleanup := _EVP_MD_meth_get_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_meth_get_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_meth_get_cleanup');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_meth_get_ctrl := LoadLibFunction(ADllHandle, EVP_MD_meth_get_ctrl_procname);
  FuncLoadError := not assigned(EVP_MD_meth_get_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_meth_get_ctrl_allownil)}
    EVP_MD_meth_get_ctrl := ERR_EVP_MD_meth_get_ctrl;
    {$ifend}
    {$if declared(EVP_MD_meth_get_ctrl_introduced)}
    if LibVersion < EVP_MD_meth_get_ctrl_introduced then
    begin
      {$if declared(FC_EVP_MD_meth_get_ctrl)}
      EVP_MD_meth_get_ctrl := FC_EVP_MD_meth_get_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_meth_get_ctrl_removed)}
    if EVP_MD_meth_get_ctrl_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_meth_get_ctrl)}
      EVP_MD_meth_get_ctrl := _EVP_MD_meth_get_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_meth_get_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_meth_get_ctrl');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_CIPHER_meth_new := LoadLibFunction(ADllHandle, EVP_CIPHER_meth_new_procname);
  FuncLoadError := not assigned(EVP_CIPHER_meth_new);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_meth_new_allownil)}
    EVP_CIPHER_meth_new := ERR_EVP_CIPHER_meth_new;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_new_introduced)}
    if LibVersion < EVP_CIPHER_meth_new_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_meth_new)}
      EVP_CIPHER_meth_new := FC_EVP_CIPHER_meth_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_new_removed)}
    if EVP_CIPHER_meth_new_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_meth_new)}
      EVP_CIPHER_meth_new := _EVP_CIPHER_meth_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_meth_new_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_meth_new');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_CIPHER_meth_dup := LoadLibFunction(ADllHandle, EVP_CIPHER_meth_dup_procname);
  FuncLoadError := not assigned(EVP_CIPHER_meth_dup);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_meth_dup_allownil)}
    EVP_CIPHER_meth_dup := ERR_EVP_CIPHER_meth_dup;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_dup_introduced)}
    if LibVersion < EVP_CIPHER_meth_dup_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_meth_dup)}
      EVP_CIPHER_meth_dup := FC_EVP_CIPHER_meth_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_dup_removed)}
    if EVP_CIPHER_meth_dup_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_meth_dup)}
      EVP_CIPHER_meth_dup := _EVP_CIPHER_meth_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_meth_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_meth_dup');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_CIPHER_meth_free := LoadLibFunction(ADllHandle, EVP_CIPHER_meth_free_procname);
  FuncLoadError := not assigned(EVP_CIPHER_meth_free);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_meth_free_allownil)}
    EVP_CIPHER_meth_free := ERR_EVP_CIPHER_meth_free;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_free_introduced)}
    if LibVersion < EVP_CIPHER_meth_free_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_meth_free)}
      EVP_CIPHER_meth_free := FC_EVP_CIPHER_meth_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_free_removed)}
    if EVP_CIPHER_meth_free_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_meth_free)}
      EVP_CIPHER_meth_free := _EVP_CIPHER_meth_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_meth_free_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_meth_free');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_CIPHER_meth_set_iv_length := LoadLibFunction(ADllHandle, EVP_CIPHER_meth_set_iv_length_procname);
  FuncLoadError := not assigned(EVP_CIPHER_meth_set_iv_length);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_meth_set_iv_length_allownil)}
    EVP_CIPHER_meth_set_iv_length := ERR_EVP_CIPHER_meth_set_iv_length;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_set_iv_length_introduced)}
    if LibVersion < EVP_CIPHER_meth_set_iv_length_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_meth_set_iv_length)}
      EVP_CIPHER_meth_set_iv_length := FC_EVP_CIPHER_meth_set_iv_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_set_iv_length_removed)}
    if EVP_CIPHER_meth_set_iv_length_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_meth_set_iv_length)}
      EVP_CIPHER_meth_set_iv_length := _EVP_CIPHER_meth_set_iv_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_meth_set_iv_length_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_meth_set_iv_length');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_CIPHER_meth_set_flags := LoadLibFunction(ADllHandle, EVP_CIPHER_meth_set_flags_procname);
  FuncLoadError := not assigned(EVP_CIPHER_meth_set_flags);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_meth_set_flags_allownil)}
    EVP_CIPHER_meth_set_flags := ERR_EVP_CIPHER_meth_set_flags;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_set_flags_introduced)}
    if LibVersion < EVP_CIPHER_meth_set_flags_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_meth_set_flags)}
      EVP_CIPHER_meth_set_flags := FC_EVP_CIPHER_meth_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_set_flags_removed)}
    if EVP_CIPHER_meth_set_flags_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_meth_set_flags)}
      EVP_CIPHER_meth_set_flags := _EVP_CIPHER_meth_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_meth_set_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_meth_set_flags');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_CIPHER_meth_set_impl_ctx_size := LoadLibFunction(ADllHandle, EVP_CIPHER_meth_set_impl_ctx_size_procname);
  FuncLoadError := not assigned(EVP_CIPHER_meth_set_impl_ctx_size);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_meth_set_impl_ctx_size_allownil)}
    EVP_CIPHER_meth_set_impl_ctx_size := ERR_EVP_CIPHER_meth_set_impl_ctx_size;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_set_impl_ctx_size_introduced)}
    if LibVersion < EVP_CIPHER_meth_set_impl_ctx_size_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_meth_set_impl_ctx_size)}
      EVP_CIPHER_meth_set_impl_ctx_size := FC_EVP_CIPHER_meth_set_impl_ctx_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_set_impl_ctx_size_removed)}
    if EVP_CIPHER_meth_set_impl_ctx_size_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_meth_set_impl_ctx_size)}
      EVP_CIPHER_meth_set_impl_ctx_size := _EVP_CIPHER_meth_set_impl_ctx_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_meth_set_impl_ctx_size_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_meth_set_impl_ctx_size');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_CIPHER_meth_set_init := LoadLibFunction(ADllHandle, EVP_CIPHER_meth_set_init_procname);
  FuncLoadError := not assigned(EVP_CIPHER_meth_set_init);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_meth_set_init_allownil)}
    EVP_CIPHER_meth_set_init := ERR_EVP_CIPHER_meth_set_init;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_set_init_introduced)}
    if LibVersion < EVP_CIPHER_meth_set_init_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_meth_set_init)}
      EVP_CIPHER_meth_set_init := FC_EVP_CIPHER_meth_set_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_set_init_removed)}
    if EVP_CIPHER_meth_set_init_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_meth_set_init)}
      EVP_CIPHER_meth_set_init := _EVP_CIPHER_meth_set_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_meth_set_init_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_meth_set_init');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_CIPHER_meth_set_do_cipher := LoadLibFunction(ADllHandle, EVP_CIPHER_meth_set_do_cipher_procname);
  FuncLoadError := not assigned(EVP_CIPHER_meth_set_do_cipher);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_meth_set_do_cipher_allownil)}
    EVP_CIPHER_meth_set_do_cipher := ERR_EVP_CIPHER_meth_set_do_cipher;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_set_do_cipher_introduced)}
    if LibVersion < EVP_CIPHER_meth_set_do_cipher_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_meth_set_do_cipher)}
      EVP_CIPHER_meth_set_do_cipher := FC_EVP_CIPHER_meth_set_do_cipher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_set_do_cipher_removed)}
    if EVP_CIPHER_meth_set_do_cipher_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_meth_set_do_cipher)}
      EVP_CIPHER_meth_set_do_cipher := _EVP_CIPHER_meth_set_do_cipher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_meth_set_do_cipher_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_meth_set_do_cipher');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_CIPHER_meth_set_cleanup := LoadLibFunction(ADllHandle, EVP_CIPHER_meth_set_cleanup_procname);
  FuncLoadError := not assigned(EVP_CIPHER_meth_set_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_meth_set_cleanup_allownil)}
    EVP_CIPHER_meth_set_cleanup := ERR_EVP_CIPHER_meth_set_cleanup;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_set_cleanup_introduced)}
    if LibVersion < EVP_CIPHER_meth_set_cleanup_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_meth_set_cleanup)}
      EVP_CIPHER_meth_set_cleanup := FC_EVP_CIPHER_meth_set_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_set_cleanup_removed)}
    if EVP_CIPHER_meth_set_cleanup_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_meth_set_cleanup)}
      EVP_CIPHER_meth_set_cleanup := _EVP_CIPHER_meth_set_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_meth_set_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_meth_set_cleanup');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_CIPHER_meth_set_set_asn1_params := LoadLibFunction(ADllHandle, EVP_CIPHER_meth_set_set_asn1_params_procname);
  FuncLoadError := not assigned(EVP_CIPHER_meth_set_set_asn1_params);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_meth_set_set_asn1_params_allownil)}
    EVP_CIPHER_meth_set_set_asn1_params := ERR_EVP_CIPHER_meth_set_set_asn1_params;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_set_set_asn1_params_introduced)}
    if LibVersion < EVP_CIPHER_meth_set_set_asn1_params_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_meth_set_set_asn1_params)}
      EVP_CIPHER_meth_set_set_asn1_params := FC_EVP_CIPHER_meth_set_set_asn1_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_set_set_asn1_params_removed)}
    if EVP_CIPHER_meth_set_set_asn1_params_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_meth_set_set_asn1_params)}
      EVP_CIPHER_meth_set_set_asn1_params := _EVP_CIPHER_meth_set_set_asn1_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_meth_set_set_asn1_params_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_meth_set_set_asn1_params');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_CIPHER_meth_set_get_asn1_params := LoadLibFunction(ADllHandle, EVP_CIPHER_meth_set_get_asn1_params_procname);
  FuncLoadError := not assigned(EVP_CIPHER_meth_set_get_asn1_params);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_meth_set_get_asn1_params_allownil)}
    EVP_CIPHER_meth_set_get_asn1_params := ERR_EVP_CIPHER_meth_set_get_asn1_params;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_set_get_asn1_params_introduced)}
    if LibVersion < EVP_CIPHER_meth_set_get_asn1_params_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_meth_set_get_asn1_params)}
      EVP_CIPHER_meth_set_get_asn1_params := FC_EVP_CIPHER_meth_set_get_asn1_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_set_get_asn1_params_removed)}
    if EVP_CIPHER_meth_set_get_asn1_params_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_meth_set_get_asn1_params)}
      EVP_CIPHER_meth_set_get_asn1_params := _EVP_CIPHER_meth_set_get_asn1_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_meth_set_get_asn1_params_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_meth_set_get_asn1_params');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_CIPHER_meth_set_ctrl := LoadLibFunction(ADllHandle, EVP_CIPHER_meth_set_ctrl_procname);
  FuncLoadError := not assigned(EVP_CIPHER_meth_set_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_meth_set_ctrl_allownil)}
    EVP_CIPHER_meth_set_ctrl := ERR_EVP_CIPHER_meth_set_ctrl;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_set_ctrl_introduced)}
    if LibVersion < EVP_CIPHER_meth_set_ctrl_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_meth_set_ctrl)}
      EVP_CIPHER_meth_set_ctrl := FC_EVP_CIPHER_meth_set_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_set_ctrl_removed)}
    if EVP_CIPHER_meth_set_ctrl_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_meth_set_ctrl)}
      EVP_CIPHER_meth_set_ctrl := _EVP_CIPHER_meth_set_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_meth_set_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_meth_set_ctrl');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_CIPHER_meth_get_init := LoadLibFunction(ADllHandle, EVP_CIPHER_meth_get_init_procname);
  FuncLoadError := not assigned(EVP_CIPHER_meth_get_init);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_meth_get_init_allownil)}
    EVP_CIPHER_meth_get_init := ERR_EVP_CIPHER_meth_get_init;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_get_init_introduced)}
    if LibVersion < EVP_CIPHER_meth_get_init_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_meth_get_init)}
      EVP_CIPHER_meth_get_init := FC_EVP_CIPHER_meth_get_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_get_init_removed)}
    if EVP_CIPHER_meth_get_init_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_meth_get_init)}
      EVP_CIPHER_meth_get_init := _EVP_CIPHER_meth_get_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_meth_get_init_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_meth_get_init');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_CIPHER_meth_get_do_cipher := LoadLibFunction(ADllHandle, EVP_CIPHER_meth_get_do_cipher_procname);
  FuncLoadError := not assigned(EVP_CIPHER_meth_get_do_cipher);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_meth_get_do_cipher_allownil)}
    EVP_CIPHER_meth_get_do_cipher := ERR_EVP_CIPHER_meth_get_do_cipher;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_get_do_cipher_introduced)}
    if LibVersion < EVP_CIPHER_meth_get_do_cipher_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_meth_get_do_cipher)}
      EVP_CIPHER_meth_get_do_cipher := FC_EVP_CIPHER_meth_get_do_cipher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_get_do_cipher_removed)}
    if EVP_CIPHER_meth_get_do_cipher_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_meth_get_do_cipher)}
      EVP_CIPHER_meth_get_do_cipher := _EVP_CIPHER_meth_get_do_cipher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_meth_get_do_cipher_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_meth_get_do_cipher');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_CIPHER_meth_get_cleanup := LoadLibFunction(ADllHandle, EVP_CIPHER_meth_get_cleanup_procname);
  FuncLoadError := not assigned(EVP_CIPHER_meth_get_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_meth_get_cleanup_allownil)}
    EVP_CIPHER_meth_get_cleanup := ERR_EVP_CIPHER_meth_get_cleanup;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_get_cleanup_introduced)}
    if LibVersion < EVP_CIPHER_meth_get_cleanup_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_meth_get_cleanup)}
      EVP_CIPHER_meth_get_cleanup := FC_EVP_CIPHER_meth_get_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_get_cleanup_removed)}
    if EVP_CIPHER_meth_get_cleanup_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_meth_get_cleanup)}
      EVP_CIPHER_meth_get_cleanup := _EVP_CIPHER_meth_get_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_meth_get_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_meth_get_cleanup');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_CIPHER_meth_get_set_asn1_params := LoadLibFunction(ADllHandle, EVP_CIPHER_meth_get_set_asn1_params_procname);
  FuncLoadError := not assigned(EVP_CIPHER_meth_get_set_asn1_params);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_meth_get_set_asn1_params_allownil)}
    EVP_CIPHER_meth_get_set_asn1_params := ERR_EVP_CIPHER_meth_get_set_asn1_params;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_get_set_asn1_params_introduced)}
    if LibVersion < EVP_CIPHER_meth_get_set_asn1_params_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_meth_get_set_asn1_params)}
      EVP_CIPHER_meth_get_set_asn1_params := FC_EVP_CIPHER_meth_get_set_asn1_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_get_set_asn1_params_removed)}
    if EVP_CIPHER_meth_get_set_asn1_params_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_meth_get_set_asn1_params)}
      EVP_CIPHER_meth_get_set_asn1_params := _EVP_CIPHER_meth_get_set_asn1_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_meth_get_set_asn1_params_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_meth_get_set_asn1_params');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_CIPHER_meth_get_get_asn1_params := LoadLibFunction(ADllHandle, EVP_CIPHER_meth_get_get_asn1_params_procname);
  FuncLoadError := not assigned(EVP_CIPHER_meth_get_get_asn1_params);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_meth_get_get_asn1_params_allownil)}
    EVP_CIPHER_meth_get_get_asn1_params := ERR_EVP_CIPHER_meth_get_get_asn1_params;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_get_get_asn1_params_introduced)}
    if LibVersion < EVP_CIPHER_meth_get_get_asn1_params_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_meth_get_get_asn1_params)}
      EVP_CIPHER_meth_get_get_asn1_params := FC_EVP_CIPHER_meth_get_get_asn1_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_get_get_asn1_params_removed)}
    if EVP_CIPHER_meth_get_get_asn1_params_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_meth_get_get_asn1_params)}
      EVP_CIPHER_meth_get_get_asn1_params := _EVP_CIPHER_meth_get_get_asn1_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_meth_get_get_asn1_params_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_meth_get_get_asn1_params');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_CIPHER_meth_get_ctrl := LoadLibFunction(ADllHandle, EVP_CIPHER_meth_get_ctrl_procname);
  FuncLoadError := not assigned(EVP_CIPHER_meth_get_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_meth_get_ctrl_allownil)}
    EVP_CIPHER_meth_get_ctrl := ERR_EVP_CIPHER_meth_get_ctrl;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_get_ctrl_introduced)}
    if LibVersion < EVP_CIPHER_meth_get_ctrl_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_meth_get_ctrl)}
      EVP_CIPHER_meth_get_ctrl := FC_EVP_CIPHER_meth_get_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_meth_get_ctrl_removed)}
    if EVP_CIPHER_meth_get_ctrl_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_meth_get_ctrl)}
      EVP_CIPHER_meth_get_ctrl := _EVP_CIPHER_meth_get_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_meth_get_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_meth_get_ctrl');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_type := LoadLibFunction(ADllHandle, EVP_MD_type_procname);
  FuncLoadError := not assigned(EVP_MD_type);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_type_allownil)}
    EVP_MD_type := ERR_EVP_MD_type;
    {$ifend}
    {$if declared(EVP_MD_type_introduced)}
    if LibVersion < EVP_MD_type_introduced then
    begin
      {$if declared(FC_EVP_MD_type)}
      EVP_MD_type := FC_EVP_MD_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_type_removed)}
    if EVP_MD_type_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_type)}
      EVP_MD_type := _EVP_MD_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_type_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_type');
    {$ifend}
  end;

 
  EVP_MD_pkey_type := LoadLibFunction(ADllHandle, EVP_MD_pkey_type_procname);
  FuncLoadError := not assigned(EVP_MD_pkey_type);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_pkey_type_allownil)}
    EVP_MD_pkey_type := ERR_EVP_MD_pkey_type;
    {$ifend}
    {$if declared(EVP_MD_pkey_type_introduced)}
    if LibVersion < EVP_MD_pkey_type_introduced then
    begin
      {$if declared(FC_EVP_MD_pkey_type)}
      EVP_MD_pkey_type := FC_EVP_MD_pkey_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_pkey_type_removed)}
    if EVP_MD_pkey_type_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_pkey_type)}
      EVP_MD_pkey_type := _EVP_MD_pkey_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_pkey_type_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_pkey_type');
    {$ifend}
  end;

 
  EVP_MD_size := LoadLibFunction(ADllHandle, EVP_MD_size_procname);
  FuncLoadError := not assigned(EVP_MD_size);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_size_allownil)}
    EVP_MD_size := ERR_EVP_MD_size;
    {$ifend}
    {$if declared(EVP_MD_size_introduced)}
    if LibVersion < EVP_MD_size_introduced then
    begin
      {$if declared(FC_EVP_MD_size)}
      EVP_MD_size := FC_EVP_MD_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_size_removed)}
    if EVP_MD_size_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_size)}
      EVP_MD_size := _EVP_MD_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_size_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_size');
    {$ifend}
  end;

 
  EVP_MD_block_size := LoadLibFunction(ADllHandle, EVP_MD_block_size_procname);
  FuncLoadError := not assigned(EVP_MD_block_size);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_block_size_allownil)}
    EVP_MD_block_size := ERR_EVP_MD_block_size;
    {$ifend}
    {$if declared(EVP_MD_block_size_introduced)}
    if LibVersion < EVP_MD_block_size_introduced then
    begin
      {$if declared(FC_EVP_MD_block_size)}
      EVP_MD_block_size := FC_EVP_MD_block_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_block_size_removed)}
    if EVP_MD_block_size_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_block_size)}
      EVP_MD_block_size := _EVP_MD_block_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_block_size_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_block_size');
    {$ifend}
  end;

 
  EVP_MD_flags := LoadLibFunction(ADllHandle, EVP_MD_flags_procname);
  FuncLoadError := not assigned(EVP_MD_flags);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_flags_allownil)}
    EVP_MD_flags := ERR_EVP_MD_flags;
    {$ifend}
    {$if declared(EVP_MD_flags_introduced)}
    if LibVersion < EVP_MD_flags_introduced then
    begin
      {$if declared(FC_EVP_MD_flags)}
      EVP_MD_flags := FC_EVP_MD_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_flags_removed)}
    if EVP_MD_flags_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_flags)}
      EVP_MD_flags := _EVP_MD_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_flags');
    {$ifend}
  end;

 
  EVP_MD_CTX_md := LoadLibFunction(ADllHandle, EVP_MD_CTX_md_procname);
  FuncLoadError := not assigned(EVP_MD_CTX_md);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_CTX_md_allownil)}
    EVP_MD_CTX_md := ERR_EVP_MD_CTX_md;
    {$ifend}
    {$if declared(EVP_MD_CTX_md_introduced)}
    if LibVersion < EVP_MD_CTX_md_introduced then
    begin
      {$if declared(FC_EVP_MD_CTX_md)}
      EVP_MD_CTX_md := FC_EVP_MD_CTX_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_CTX_md_removed)}
    if EVP_MD_CTX_md_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_CTX_md)}
      EVP_MD_CTX_md := _EVP_MD_CTX_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_CTX_md_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_CTX_md');
    {$ifend}
  end;


  EVP_MD_CTX_update_fn := LoadLibFunction(ADllHandle, EVP_MD_CTX_update_fn_procname);
  FuncLoadError := not assigned(EVP_MD_CTX_update_fn);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_CTX_update_fn_allownil)}
    EVP_MD_CTX_update_fn := ERR_EVP_MD_CTX_update_fn;
    {$ifend}
    {$if declared(EVP_MD_CTX_update_fn_introduced)}
    if LibVersion < EVP_MD_CTX_update_fn_introduced then
    begin
      {$if declared(FC_EVP_MD_CTX_update_fn)}
      EVP_MD_CTX_update_fn := FC_EVP_MD_CTX_update_fn;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_CTX_update_fn_removed)}
    if EVP_MD_CTX_update_fn_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_CTX_update_fn)}
      EVP_MD_CTX_update_fn := _EVP_MD_CTX_update_fn;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_CTX_update_fn_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_CTX_update_fn');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_CTX_set_update_fn := LoadLibFunction(ADllHandle, EVP_MD_CTX_set_update_fn_procname);
  FuncLoadError := not assigned(EVP_MD_CTX_set_update_fn);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_CTX_set_update_fn_allownil)}
    EVP_MD_CTX_set_update_fn := ERR_EVP_MD_CTX_set_update_fn;
    {$ifend}
    {$if declared(EVP_MD_CTX_set_update_fn_introduced)}
    if LibVersion < EVP_MD_CTX_set_update_fn_introduced then
    begin
      {$if declared(FC_EVP_MD_CTX_set_update_fn)}
      EVP_MD_CTX_set_update_fn := FC_EVP_MD_CTX_set_update_fn;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_CTX_set_update_fn_removed)}
    if EVP_MD_CTX_set_update_fn_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_CTX_set_update_fn)}
      EVP_MD_CTX_set_update_fn := _EVP_MD_CTX_set_update_fn;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_CTX_set_update_fn_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_CTX_set_update_fn');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_CTX_pkey_ctx := LoadLibFunction(ADllHandle, EVP_MD_CTX_pkey_ctx_procname);
  FuncLoadError := not assigned(EVP_MD_CTX_pkey_ctx);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_CTX_pkey_ctx_allownil)}
    EVP_MD_CTX_pkey_ctx := ERR_EVP_MD_CTX_pkey_ctx;
    {$ifend}
    {$if declared(EVP_MD_CTX_pkey_ctx_introduced)}
    if LibVersion < EVP_MD_CTX_pkey_ctx_introduced then
    begin
      {$if declared(FC_EVP_MD_CTX_pkey_ctx)}
      EVP_MD_CTX_pkey_ctx := FC_EVP_MD_CTX_pkey_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_CTX_pkey_ctx_removed)}
    if EVP_MD_CTX_pkey_ctx_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_CTX_pkey_ctx)}
      EVP_MD_CTX_pkey_ctx := _EVP_MD_CTX_pkey_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_CTX_pkey_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_CTX_pkey_ctx');
    {$ifend}
  end;

 
  EVP_MD_CTX_set_pkey_ctx := LoadLibFunction(ADllHandle, EVP_MD_CTX_set_pkey_ctx_procname);
  FuncLoadError := not assigned(EVP_MD_CTX_set_pkey_ctx);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_CTX_set_pkey_ctx_allownil)}
    EVP_MD_CTX_set_pkey_ctx := ERR_EVP_MD_CTX_set_pkey_ctx;
    {$ifend}
    {$if declared(EVP_MD_CTX_set_pkey_ctx_introduced)}
    if LibVersion < EVP_MD_CTX_set_pkey_ctx_introduced then
    begin
      {$if declared(FC_EVP_MD_CTX_set_pkey_ctx)}
      EVP_MD_CTX_set_pkey_ctx := FC_EVP_MD_CTX_set_pkey_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_CTX_set_pkey_ctx_removed)}
    if EVP_MD_CTX_set_pkey_ctx_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_CTX_set_pkey_ctx)}
      EVP_MD_CTX_set_pkey_ctx := _EVP_MD_CTX_set_pkey_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_CTX_set_pkey_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_CTX_set_pkey_ctx');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_CTX_md_data := LoadLibFunction(ADllHandle, EVP_MD_CTX_md_data_procname);
  FuncLoadError := not assigned(EVP_MD_CTX_md_data);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_CTX_md_data_allownil)}
    EVP_MD_CTX_md_data := ERR_EVP_MD_CTX_md_data;
    {$ifend}
    {$if declared(EVP_MD_CTX_md_data_introduced)}
    if LibVersion < EVP_MD_CTX_md_data_introduced then
    begin
      {$if declared(FC_EVP_MD_CTX_md_data)}
      EVP_MD_CTX_md_data := FC_EVP_MD_CTX_md_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_CTX_md_data_removed)}
    if EVP_MD_CTX_md_data_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_CTX_md_data)}
      EVP_MD_CTX_md_data := _EVP_MD_CTX_md_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_CTX_md_data_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_CTX_md_data');
    {$ifend}
  end;


  EVP_CIPHER_nid := LoadLibFunction(ADllHandle, EVP_CIPHER_nid_procname);
  FuncLoadError := not assigned(EVP_CIPHER_nid);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_nid_allownil)}
    EVP_CIPHER_nid := ERR_EVP_CIPHER_nid;
    {$ifend}
    {$if declared(EVP_CIPHER_nid_introduced)}
    if LibVersion < EVP_CIPHER_nid_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_nid)}
      EVP_CIPHER_nid := FC_EVP_CIPHER_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_nid_removed)}
    if EVP_CIPHER_nid_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_nid)}
      EVP_CIPHER_nid := _EVP_CIPHER_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_nid');
    {$ifend}
  end;

  EVP_CIPHER_get_nid := LoadLibFunction(ADllHandle, EVP_CIPHER_get_nid_procname);
  FuncLoadError := not assigned(EVP_CIPHER_get_nid);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_get_nid_allownil)}
    EVP_CIPHER_get_nid := ERR_EVP_CIPHER_get_nid;
    {$ifend}
    {$if declared(EVP_CIPHER_get_nid_introduced)}
    if LibVersion < EVP_CIPHER_get_nid_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_get_nid)}
      EVP_CIPHER_get_nid := FC_EVP_CIPHER_get_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_get_nid_removed)}
    if EVP_CIPHER_get_nid_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_get_nid)}
      EVP_CIPHER_get_nid := _EVP_CIPHER_get_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_get_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_get_nid');
    {$ifend}
  end;
 
  EVP_CIPHER_get0_name := LoadLibFunction(ADllHandle, EVP_CIPHER_get0_name_procname);
  FuncLoadError := not assigned(EVP_CIPHER_get0_name);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_get0_name_allownil)}
    EVP_CIPHER_get0_name := ERR_EVP_CIPHER_get0_name;
    {$ifend}
    {$if declared(EVP_CIPHER_get0_name_introduced)}
    if LibVersion < EVP_CIPHER_get0_name_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_get0_name)}
      EVP_CIPHER_get0_name := FC_EVP_CIPHER_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_get0_name_removed)}
    if EVP_CIPHER_get0_name_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_get0_name)}
      EVP_CIPHER_get0_name := _EVP_CIPHER_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_get0_name_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_get0_name');
    {$ifend}
  end;

  EVP_CIPHER_block_size := LoadLibFunction(ADllHandle, EVP_CIPHER_block_size_procname);
  FuncLoadError := not assigned(EVP_CIPHER_block_size);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_block_size_allownil)}
    EVP_CIPHER_block_size := ERR_EVP_CIPHER_block_size;
    {$ifend}
    {$if declared(EVP_CIPHER_block_size_introduced)}
    if LibVersion < EVP_CIPHER_block_size_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_block_size)}
      EVP_CIPHER_block_size := FC_EVP_CIPHER_block_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_block_size_removed)}
    if EVP_CIPHER_block_size_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_block_size)}
      EVP_CIPHER_block_size := _EVP_CIPHER_block_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_block_size_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_block_size');
    {$ifend}
  end;

   EVP_CIPHER_get_block_size := LoadLibFunction(ADllHandle, EVP_CIPHER_get_block_size_procname);
  FuncLoadError := not assigned(EVP_CIPHER_get_block_size);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_get_block_size_allownil)}
    EVP_CIPHER_get_block_size := ERR_EVP_CIPHER_get_block_size;
    {$ifend}
    {$if declared(EVP_CIPHER_get_block_size_introduced)}
    if LibVersion < EVP_CIPHER_get_block_size_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_get_block_size)}
      EVP_CIPHER_get_block_size := FC_EVP_CIPHER_get_block_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_get_block_size_removed)}
    if EVP_CIPHER_get_block_size_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_get_block_size)}
      EVP_CIPHER_get_block_size := _EVP_CIPHER_get_block_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_get_block_size_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_get_block_size');
    {$ifend}
  end;

 
  EVP_CIPHER_impl_ctx_size := LoadLibFunction(ADllHandle, EVP_CIPHER_impl_ctx_size_procname);
  FuncLoadError := not assigned(EVP_CIPHER_impl_ctx_size);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_impl_ctx_size_allownil)}
    EVP_CIPHER_impl_ctx_size := ERR_EVP_CIPHER_impl_ctx_size;
    {$ifend}
    {$if declared(EVP_CIPHER_impl_ctx_size_introduced)}
    if LibVersion < EVP_CIPHER_impl_ctx_size_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_impl_ctx_size)}
      EVP_CIPHER_impl_ctx_size := FC_EVP_CIPHER_impl_ctx_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_impl_ctx_size_removed)}
    if EVP_CIPHER_impl_ctx_size_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_impl_ctx_size)}
      EVP_CIPHER_impl_ctx_size := _EVP_CIPHER_impl_ctx_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_impl_ctx_size_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_impl_ctx_size');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_CIPHER_key_length := LoadLibFunction(ADllHandle, EVP_CIPHER_key_length_procname);
  FuncLoadError := not assigned(EVP_CIPHER_key_length);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_key_length_allownil)}
    EVP_CIPHER_key_length := ERR_EVP_CIPHER_key_length;
    {$ifend}
    {$if declared(EVP_CIPHER_key_length_introduced)}
    if LibVersion < EVP_CIPHER_key_length_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_key_length)}
      EVP_CIPHER_key_length := FC_EVP_CIPHER_key_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_key_length_removed)}
    if EVP_CIPHER_key_length_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_key_length)}
      EVP_CIPHER_key_length := _EVP_CIPHER_key_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_key_length_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_key_length');
    {$ifend}
  end;

  EVP_CIPHER_get_key_length := LoadLibFunction(ADllHandle, EVP_CIPHER_get_key_length_procname);
  FuncLoadError := not assigned(EVP_CIPHER_get_key_length);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_get_key_length_allownil)}
    EVP_CIPHER_get_key_length := ERR_EVP_CIPHER_get_key_length;
    {$ifend}
    {$if declared(EVP_CIPHER_get_key_length_introduced)}
    if LibVersion < EVP_CIPHER_get_key_length_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_get_key_length)}
      EVP_CIPHER_get_key_length := FC_EVP_CIPHER_get_key_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_get_key_length_removed)}
    if EVP_CIPHER_get_key_length_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_get_key_length)}
      EVP_CIPHER_get_key_length := _EVP_CIPHER_get_key_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_get_key_length_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_get_key_length');
    {$ifend}
  end;
 
  EVP_CIPHER_iv_length := LoadLibFunction(ADllHandle, EVP_CIPHER_iv_length_procname);
  FuncLoadError := not assigned(EVP_CIPHER_iv_length);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_iv_length_allownil)}
    EVP_CIPHER_iv_length := ERR_EVP_CIPHER_iv_length;
    {$ifend}
    {$if declared(EVP_CIPHER_iv_length_introduced)}
    if LibVersion < EVP_CIPHER_iv_length_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_iv_length)}
      EVP_CIPHER_iv_length := FC_EVP_CIPHER_iv_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_iv_length_removed)}
    if EVP_CIPHER_iv_length_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_iv_length)}
      EVP_CIPHER_iv_length := _EVP_CIPHER_iv_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_iv_length_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_iv_length');
    {$ifend}
  end;

  EVP_CIPHER_get_iv_length := LoadLibFunction(ADllHandle, EVP_CIPHER_get_iv_length_procname);
  FuncLoadError := not assigned(EVP_CIPHER_get_iv_length);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_get_iv_length_allownil)}
    EVP_CIPHER_get_iv_length := ERR_EVP_CIPHER_get_iv_length;
    {$ifend}
    {$if declared(EVP_CIPHER_get_iv_length_introduced)}
    if LibVersion < EVP_CIPHER_get_iv_length_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_get_iv_length)}
      EVP_CIPHER_get_iv_length := FC_EVP_CIPHER_get_iv_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_get_iv_length_removed)}
    if EVP_CIPHER_get_iv_length_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_get_iv_length)}
      EVP_CIPHER_get_iv_length := _EVP_CIPHER_get_iv_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_get_iv_length_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_get_iv_length');
    {$ifend}
  end;

  EVP_CIPHER_flags := LoadLibFunction(ADllHandle, EVP_CIPHER_flags_procname);
  FuncLoadError := not assigned(EVP_CIPHER_flags);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_flags_allownil)}
    EVP_CIPHER_flags := ERR_EVP_CIPHER_flags;
    {$ifend}
    {$if declared(EVP_CIPHER_flags_introduced)}
    if LibVersion < EVP_CIPHER_flags_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_flags)}
      EVP_CIPHER_flags := FC_EVP_CIPHER_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_flags_removed)}
    if EVP_CIPHER_flags_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_flags)}
      EVP_CIPHER_flags := _EVP_CIPHER_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_flags');
    {$ifend}
  end;


  EVP_CIPHER_get_flags := LoadLibFunction(ADllHandle, EVP_CIPHER_get_flags_procname);
  FuncLoadError := not assigned(EVP_CIPHER_get_flags);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_get_flags_allownil)}
    EVP_CIPHER_get_flags := ERR_EVP_CIPHER_get_flags;
    {$ifend}
    {$if declared(EVP_CIPHER_get_flags_introduced)}
    if LibVersion < EVP_CIPHER_get_flags_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_get_flags)}
      EVP_CIPHER_get_flags := FC_EVP_CIPHER_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_get_flags_removed)}
    if EVP_CIPHER_get_flags_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_get_flags)}
      EVP_CIPHER_get_flags := _EVP_CIPHER_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_get_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_get_flags');
    {$ifend}
  end;


  EVP_CIPHER_CTX_get0_cipher := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_get0_cipher_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_get0_cipher);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_get0_cipher_allownil)}
    EVP_CIPHER_CTX_get0_cipher := ERR_EVP_CIPHER_CTX_get0_cipher;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_get0_cipher_introduced)}
    if LibVersion < EVP_CIPHER_CTX_get0_cipher_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_get0_cipher)}
      EVP_CIPHER_CTX_get0_cipher := FC_EVP_CIPHER_CTX_get0_cipher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_get0_cipher_removed)}
    if EVP_CIPHER_CTX_get0_cipher_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_get0_cipher)}
      EVP_CIPHER_CTX_get0_cipher := _EVP_CIPHER_CTX_get0_cipher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_get0_cipher_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_get0_cipher');
    {$ifend}
  end;


  EVP_CIPHER_CTX_encrypting := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_encrypting_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_encrypting);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_encrypting_allownil)}
    EVP_CIPHER_CTX_encrypting := ERR_EVP_CIPHER_CTX_encrypting;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_encrypting_introduced)}
    if LibVersion < EVP_CIPHER_CTX_encrypting_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_encrypting)}
      EVP_CIPHER_CTX_encrypting := FC_EVP_CIPHER_CTX_encrypting;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_encrypting_removed)}
    if EVP_CIPHER_CTX_encrypting_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_encrypting)}
      EVP_CIPHER_CTX_encrypting := _EVP_CIPHER_CTX_encrypting;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_encrypting_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_encrypting');
    {$ifend}
  end;

  EVP_CIPHER_CTX_is_encrypting := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_is_encrypting_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_is_encrypting);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_is_encrypting_allownil)}
    EVP_CIPHER_CTX_is_encrypting := ERR_EVP_CIPHER_CTX_is_encrypting;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_is_encrypting_introduced)}
    if LibVersion < EVP_CIPHER_CTX_is_encrypting_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_is_encrypting)}
      EVP_CIPHER_CTX_is_encrypting := FC_EVP_CIPHER_CTX_is_encrypting;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_is_encrypting_removed)}
    if EVP_CIPHER_CTX_is_encrypting_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_is_encrypting)}
      EVP_CIPHER_CTX_is_encrypting := _EVP_CIPHER_CTX_is_encrypting;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_is_encrypting_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_is_encrypting');
    {$ifend}
  end;


  EVP_CIPHER_CTX_nid := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_nid_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_nid);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_nid_allownil)}
    EVP_CIPHER_CTX_nid := ERR_EVP_CIPHER_CTX_nid;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_nid_introduced)}
    if LibVersion < EVP_CIPHER_CTX_nid_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_nid)}
      EVP_CIPHER_CTX_nid := FC_EVP_CIPHER_CTX_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_nid_removed)}
    if EVP_CIPHER_CTX_nid_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_nid)}
      EVP_CIPHER_CTX_nid := _EVP_CIPHER_CTX_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_nid');
    {$ifend}
  end;

  EVP_CIPHER_CTX_get_nid := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_get_nid_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_get_nid);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_get_nid_allownil)}
    EVP_CIPHER_CTX_get_nid := ERR_EVP_CIPHER_CTX_get_nid;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_get_nid_introduced)}
    if LibVersion < EVP_CIPHER_CTX_get_nid_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_get_nid)}
      EVP_CIPHER_CTX_get_nid := FC_EVP_CIPHER_CTX_get_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_get_nid_removed)}
    if EVP_CIPHER_CTX_get_nid_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_get_nid)}
      EVP_CIPHER_CTX_get_nid := _EVP_CIPHER_CTX_get_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_get_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_get_nid');
    {$ifend}
  end;
 
  EVP_CIPHER_CTX_block_size := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_block_size_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_block_size);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_block_size_allownil)}
    EVP_CIPHER_CTX_block_size := ERR_EVP_CIPHER_CTX_block_size;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_block_size_introduced)}
    if LibVersion < EVP_CIPHER_CTX_block_size_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_block_size)}
      EVP_CIPHER_CTX_block_size := FC_EVP_CIPHER_CTX_block_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_block_size_removed)}
    if EVP_CIPHER_CTX_block_size_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_block_size)}
      EVP_CIPHER_CTX_block_size := _EVP_CIPHER_CTX_block_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_block_size_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_block_size');
    {$ifend}
  end;

  EVP_CIPHER_CTX_get_block_size := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_get_block_size_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_get_block_size);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_get_block_size_allownil)}
    EVP_CIPHER_CTX_get_block_size := ERR_EVP_CIPHER_CTX_get_block_size;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_get_block_size_introduced)}
    if LibVersion < EVP_CIPHER_CTX_get_block_size_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_get_block_size)}
      EVP_CIPHER_CTX_get_block_size := FC_EVP_CIPHER_CTX_get_block_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_get_block_size_removed)}
    if EVP_CIPHER_CTX_get_block_size_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_get_block_size)}
      EVP_CIPHER_CTX_get_block_size := _EVP_CIPHER_CTX_get_block_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_get_block_size_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_get_block_size');
    {$ifend}
  end;

  EVP_CIPHER_CTX_key_length := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_key_length_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_key_length);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_key_length_allownil)}
    EVP_CIPHER_CTX_key_length := ERR_EVP_CIPHER_CTX_key_length;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_key_length_introduced)}
    if LibVersion < EVP_CIPHER_CTX_key_length_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_key_length)}
      EVP_CIPHER_CTX_key_length := FC_EVP_CIPHER_CTX_key_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_key_length_removed)}
    if EVP_CIPHER_CTX_key_length_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_key_length)}
      EVP_CIPHER_CTX_key_length := _EVP_CIPHER_CTX_key_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_key_length_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_key_length');
    {$ifend}
  end;

  EVP_CIPHER_CTX_get_key_length := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_get_key_length_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_get_key_length);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_get_key_length_allownil)}
    EVP_CIPHER_CTX_get_key_length := ERR_EVP_CIPHER_CTX_get_key_length;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_get_key_length_introduced)}
    if LibVersion < EVP_CIPHER_CTX_get_key_length_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_get_key_length)}
      EVP_CIPHER_CTX_get_key_length := FC_EVP_CIPHER_CTX_get_key_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_get_key_length_removed)}
    if EVP_CIPHER_CTX_get_key_length_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_get_key_length)}
      EVP_CIPHER_CTX_get_key_length := _EVP_CIPHER_CTX_get_key_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_get_key_length_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_get_key_length');
    {$ifend}
  end;
 
  EVP_CIPHER_CTX_iv_length := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_iv_length_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_iv_length);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_iv_length_allownil)}
    EVP_CIPHER_CTX_iv_length := ERR_EVP_CIPHER_CTX_iv_length;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_iv_length_introduced)}
    if LibVersion < EVP_CIPHER_CTX_iv_length_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_iv_length)}
      EVP_CIPHER_CTX_iv_length := FC_EVP_CIPHER_CTX_iv_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_iv_length_removed)}
    if EVP_CIPHER_CTX_iv_length_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_iv_length)}
      EVP_CIPHER_CTX_iv_length := _EVP_CIPHER_CTX_iv_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_iv_length_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_iv_length');
    {$ifend}
  end;

   EVP_CIPHER_CTX_get_iv_length := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_get_iv_length_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_get_iv_length);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_get_iv_length_allownil)}
    EVP_CIPHER_CTX_get_iv_length := ERR_EVP_CIPHER_CTX_get_iv_length;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_get_iv_length_introduced)}
    if LibVersion < EVP_CIPHER_CTX_get_iv_length_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_get_iv_length)}
      EVP_CIPHER_CTX_get_iv_length := FC_EVP_CIPHER_CTX_get_iv_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_get_iv_length_removed)}
    if EVP_CIPHER_CTX_get_iv_length_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_get_iv_length)}
      EVP_CIPHER_CTX_get_iv_length := _EVP_CIPHER_CTX_get_iv_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_get_iv_length_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_get_iv_length');
    {$ifend}
  end;
 
  EVP_CIPHER_CTX_iv := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_iv_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_iv);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_iv_allownil)}
    EVP_CIPHER_CTX_iv := ERR_EVP_CIPHER_CTX_iv;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_iv_introduced)}
    if LibVersion < EVP_CIPHER_CTX_iv_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_iv)}
      EVP_CIPHER_CTX_iv := FC_EVP_CIPHER_CTX_iv;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_iv_removed)}
    if EVP_CIPHER_CTX_iv_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_iv)}
      EVP_CIPHER_CTX_iv := _EVP_CIPHER_CTX_iv;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_iv_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_iv');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_CIPHER_CTX_original_iv := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_original_iv_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_original_iv);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_original_iv_allownil)}
    EVP_CIPHER_CTX_original_iv := ERR_EVP_CIPHER_CTX_original_iv;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_original_iv_introduced)}
    if LibVersion < EVP_CIPHER_CTX_original_iv_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_original_iv)}
      EVP_CIPHER_CTX_original_iv := FC_EVP_CIPHER_CTX_original_iv;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_original_iv_removed)}
    if EVP_CIPHER_CTX_original_iv_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_original_iv)}
      EVP_CIPHER_CTX_original_iv := _EVP_CIPHER_CTX_original_iv;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_original_iv_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_original_iv');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_CIPHER_CTX_iv_noconst := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_iv_noconst_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_iv_noconst);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_iv_noconst_allownil)}
    EVP_CIPHER_CTX_iv_noconst := ERR_EVP_CIPHER_CTX_iv_noconst;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_iv_noconst_introduced)}
    if LibVersion < EVP_CIPHER_CTX_iv_noconst_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_iv_noconst)}
      EVP_CIPHER_CTX_iv_noconst := FC_EVP_CIPHER_CTX_iv_noconst;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_iv_noconst_removed)}
    if EVP_CIPHER_CTX_iv_noconst_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_iv_noconst)}
      EVP_CIPHER_CTX_iv_noconst := _EVP_CIPHER_CTX_iv_noconst;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_iv_noconst_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_iv_noconst');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_CIPHER_CTX_buf_noconst := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_buf_noconst_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_buf_noconst);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_buf_noconst_allownil)}
    EVP_CIPHER_CTX_buf_noconst := ERR_EVP_CIPHER_CTX_buf_noconst;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_buf_noconst_introduced)}
    if LibVersion < EVP_CIPHER_CTX_buf_noconst_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_buf_noconst)}
      EVP_CIPHER_CTX_buf_noconst := FC_EVP_CIPHER_CTX_buf_noconst;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_buf_noconst_removed)}
    if EVP_CIPHER_CTX_buf_noconst_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_buf_noconst)}
      EVP_CIPHER_CTX_buf_noconst := _EVP_CIPHER_CTX_buf_noconst;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_buf_noconst_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_buf_noconst');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_CIPHER_CTX_num := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_num_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_num);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_num_allownil)}
    EVP_CIPHER_CTX_num := ERR_EVP_CIPHER_CTX_num;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_num_introduced)}
    if LibVersion < EVP_CIPHER_CTX_num_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_num)}
      EVP_CIPHER_CTX_num := FC_EVP_CIPHER_CTX_num;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_num_removed)}
    if EVP_CIPHER_CTX_num_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_num)}
      EVP_CIPHER_CTX_num := _EVP_CIPHER_CTX_num;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_num_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_num');
    {$ifend}
  end;

  {introduced 3.0.0}
  EVP_CIPHER_CTX_get_num := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_get_num_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_get_num);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_get_num_allownil)}
    EVP_CIPHER_CTX_get_num := ERR_EVP_CIPHER_CTX_get_num;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_get_num_introduced)}
    if LibVersion < EVP_CIPHER_CTX_get_num_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_get_num)}
      EVP_CIPHER_CTX_get_num := FC_EVP_CIPHER_CTX_get_num;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_get_num_removed)}
    if EVP_CIPHER_CTX_get_num_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_get_num)}
      EVP_CIPHER_CTX_get_num := _EVP_CIPHER_CTX_get_num;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_get_num_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_get_num');
    {$ifend}
  end;

 
  EVP_CIPHER_CTX_set_num := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_set_num_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_set_num);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_set_num_allownil)}
    EVP_CIPHER_CTX_set_num := ERR_EVP_CIPHER_CTX_set_num;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_set_num_introduced)}
    if LibVersion < EVP_CIPHER_CTX_set_num_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_set_num)}
      EVP_CIPHER_CTX_set_num := FC_EVP_CIPHER_CTX_set_num;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_set_num_removed)}
    if EVP_CIPHER_CTX_set_num_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_set_num)}
      EVP_CIPHER_CTX_set_num := _EVP_CIPHER_CTX_set_num;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_set_num_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_set_num');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_CIPHER_CTX_copy := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_copy_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_copy);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_copy_allownil)}
    EVP_CIPHER_CTX_copy := ERR_EVP_CIPHER_CTX_copy;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_copy_introduced)}
    if LibVersion < EVP_CIPHER_CTX_copy_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_copy)}
      EVP_CIPHER_CTX_copy := FC_EVP_CIPHER_CTX_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_copy_removed)}
    if EVP_CIPHER_CTX_copy_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_copy)}
      EVP_CIPHER_CTX_copy := _EVP_CIPHER_CTX_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_copy_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_copy');
    {$ifend}
  end;


  EVP_CIPHER_CTX_get_app_data := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_get_app_data_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_get_app_data);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_get_app_data_allownil)}
    EVP_CIPHER_CTX_get_app_data := ERR_EVP_CIPHER_CTX_get_app_data;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_get_app_data_introduced)}
    if LibVersion < EVP_CIPHER_CTX_get_app_data_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_get_app_data)}
      EVP_CIPHER_CTX_get_app_data := FC_EVP_CIPHER_CTX_get_app_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_get_app_data_removed)}
    if EVP_CIPHER_CTX_get_app_data_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_get_app_data)}
      EVP_CIPHER_CTX_get_app_data := _EVP_CIPHER_CTX_get_app_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_get_app_data_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_get_app_data');
    {$ifend}
  end;


  EVP_CIPHER_CTX_set_app_data := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_set_app_data_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_set_app_data);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_set_app_data_allownil)}
    EVP_CIPHER_CTX_set_app_data := ERR_EVP_CIPHER_CTX_set_app_data;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_set_app_data_introduced)}
    if LibVersion < EVP_CIPHER_CTX_set_app_data_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_set_app_data)}
      EVP_CIPHER_CTX_set_app_data := FC_EVP_CIPHER_CTX_set_app_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_set_app_data_removed)}
    if EVP_CIPHER_CTX_set_app_data_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_set_app_data)}
      EVP_CIPHER_CTX_set_app_data := _EVP_CIPHER_CTX_set_app_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_set_app_data_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_set_app_data');
    {$ifend}
  end;


  EVP_CIPHER_CTX_get_cipher_data := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_get_cipher_data_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_get_cipher_data);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_get_cipher_data_allownil)}
    EVP_CIPHER_CTX_get_cipher_data := ERR_EVP_CIPHER_CTX_get_cipher_data;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_get_cipher_data_introduced)}
    if LibVersion < EVP_CIPHER_CTX_get_cipher_data_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_get_cipher_data)}
      EVP_CIPHER_CTX_get_cipher_data := FC_EVP_CIPHER_CTX_get_cipher_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_get_cipher_data_removed)}
    if EVP_CIPHER_CTX_get_cipher_data_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_get_cipher_data)}
      EVP_CIPHER_CTX_get_cipher_data := _EVP_CIPHER_CTX_get_cipher_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_get_cipher_data_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_get_cipher_data');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_CIPHER_CTX_set_cipher_data := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_set_cipher_data_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_set_cipher_data);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_set_cipher_data_allownil)}
    EVP_CIPHER_CTX_set_cipher_data := ERR_EVP_CIPHER_CTX_set_cipher_data;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_set_cipher_data_introduced)}
    if LibVersion < EVP_CIPHER_CTX_set_cipher_data_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_set_cipher_data)}
      EVP_CIPHER_CTX_set_cipher_data := FC_EVP_CIPHER_CTX_set_cipher_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_set_cipher_data_removed)}
    if EVP_CIPHER_CTX_set_cipher_data_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_set_cipher_data)}
      EVP_CIPHER_CTX_set_cipher_data := _EVP_CIPHER_CTX_set_cipher_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_set_cipher_data_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_set_cipher_data');
    {$ifend}
  end;

 {removed 3.0.0}
  EVP_CIPHER_CTX_tag_length := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_tag_length_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_tag_length);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_tag_length_allownil)}
    EVP_CIPHER_CTX_tag_length := ERR_EVP_CIPHER_CTX_tag_length;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_tag_length_introduced)}
    if LibVersion < EVP_CIPHER_CTX_tag_length_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_tag_length)}
      EVP_CIPHER_CTX_tag_length := FC_EVP_CIPHER_CTX_tag_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_tag_length_removed)}
    if EVP_CIPHER_CTX_tag_length_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_tag_length)}
      EVP_CIPHER_CTX_tag_length := _EVP_CIPHER_CTX_tag_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_tag_length_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_tag_length');
    {$ifend}
  end;

 {introduced 3.0.0}
  EVP_CIPHER_CTX_get_tag_length := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_get_tag_length_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_get_tag_length);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_get_tag_length_allownil)}
    EVP_CIPHER_CTX_get_tag_length := ERR_EVP_CIPHER_CTX_get_tag_length;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_get_tag_length_introduced)}
    if LibVersion < EVP_CIPHER_CTX_get_tag_length_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_get_tag_length)}
      EVP_CIPHER_CTX_get_tag_length := FC_EVP_CIPHER_CTX_get_tag_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_get_tag_length_removed)}
    if EVP_CIPHER_CTX_get_tag_length_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_get_tag_length)}
      EVP_CIPHER_CTX_get_tag_length := _EVP_CIPHER_CTX_get_tag_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_get_tag_length_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_get_tag_length');
    {$ifend}
  end;

 {introduced 1.1.0}
  BIO_set_md := LoadLibFunction(ADllHandle, BIO_set_md_procname);
  FuncLoadError := not assigned(BIO_set_md);
  if FuncLoadError then
  begin
    {$if not defined(BIO_set_md_allownil)}
    BIO_set_md := ERR_BIO_set_md;
    {$ifend}
    {$if declared(BIO_set_md_introduced)}
    if LibVersion < BIO_set_md_introduced then
    begin
      {$if declared(FC_BIO_set_md)}
      BIO_set_md := FC_BIO_set_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_set_md_removed)}
    if BIO_set_md_removed <= LibVersion then
    begin
      {$if declared(_BIO_set_md)}
      BIO_set_md := _BIO_set_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_set_md_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_set_md');
    {$ifend}
  end;

 
  EVP_MD_CTX_init := LoadLibFunction(ADllHandle, EVP_MD_CTX_init_procname);
  FuncLoadError := not assigned(EVP_MD_CTX_init);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_CTX_init_allownil)}
    EVP_MD_CTX_init := ERR_EVP_MD_CTX_init;
    {$ifend}
    {$if declared(EVP_MD_CTX_init_introduced)}
    if LibVersion < EVP_MD_CTX_init_introduced then
    begin
      {$if declared(FC_EVP_MD_CTX_init)}
      EVP_MD_CTX_init := FC_EVP_MD_CTX_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_CTX_init_removed)}
    if EVP_MD_CTX_init_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_CTX_init)}
      EVP_MD_CTX_init := _EVP_MD_CTX_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_CTX_init_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_CTX_init');
    {$ifend}
  end;

 
  EVP_MD_CTX_cleanup := LoadLibFunction(ADllHandle, EVP_MD_CTX_cleanup_procname);
  FuncLoadError := not assigned(EVP_MD_CTX_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_CTX_cleanup_allownil)}
    EVP_MD_CTX_cleanup := ERR_EVP_MD_CTX_cleanup;
    {$ifend}
    {$if declared(EVP_MD_CTX_cleanup_introduced)}
    if LibVersion < EVP_MD_CTX_cleanup_introduced then
    begin
      {$if declared(FC_EVP_MD_CTX_cleanup)}
      EVP_MD_CTX_cleanup := FC_EVP_MD_CTX_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_CTX_cleanup_removed)}
    if EVP_MD_CTX_cleanup_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_CTX_cleanup)}
      EVP_MD_CTX_cleanup := _EVP_MD_CTX_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_CTX_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_CTX_cleanup');
    {$ifend}
  end;

 
  EVP_MD_CTX_ctrl := LoadLibFunction(ADllHandle, EVP_MD_CTX_ctrl_procname);
  FuncLoadError := not assigned(EVP_MD_CTX_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_CTX_ctrl_allownil)}
    EVP_MD_CTX_ctrl := ERR_EVP_MD_CTX_ctrl;
    {$ifend}
    {$if declared(EVP_MD_CTX_ctrl_introduced)}
    if LibVersion < EVP_MD_CTX_ctrl_introduced then
    begin
      {$if declared(FC_EVP_MD_CTX_ctrl)}
      EVP_MD_CTX_ctrl := FC_EVP_MD_CTX_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_CTX_ctrl_removed)}
    if EVP_MD_CTX_ctrl_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_CTX_ctrl)}
      EVP_MD_CTX_ctrl := _EVP_MD_CTX_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_CTX_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_CTX_ctrl');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_CTX_new := LoadLibFunction(ADllHandle, EVP_MD_CTX_new_procname);
  FuncLoadError := not assigned(EVP_MD_CTX_new);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_CTX_new_allownil)}
    EVP_MD_CTX_new := ERR_EVP_MD_CTX_new;
    {$ifend}
    {$if declared(EVP_MD_CTX_new_introduced)}
    if LibVersion < EVP_MD_CTX_new_introduced then
    begin
      {$if declared(FC_EVP_MD_CTX_new)}
      EVP_MD_CTX_new := FC_EVP_MD_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_CTX_new_removed)}
    if EVP_MD_CTX_new_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_CTX_new)}
      EVP_MD_CTX_new := _EVP_MD_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_CTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_CTX_new');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_CTX_reset := LoadLibFunction(ADllHandle, EVP_MD_CTX_reset_procname);
  FuncLoadError := not assigned(EVP_MD_CTX_reset);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_CTX_reset_allownil)}
    EVP_MD_CTX_reset := ERR_EVP_MD_CTX_reset;
    {$ifend}
    {$if declared(EVP_MD_CTX_reset_introduced)}
    if LibVersion < EVP_MD_CTX_reset_introduced then
    begin
      {$if declared(FC_EVP_MD_CTX_reset)}
      EVP_MD_CTX_reset := FC_EVP_MD_CTX_reset;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_CTX_reset_removed)}
    if EVP_MD_CTX_reset_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_CTX_reset)}
      EVP_MD_CTX_reset := _EVP_MD_CTX_reset;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_CTX_reset_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_CTX_reset');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_CTX_free := LoadLibFunction(ADllHandle, EVP_MD_CTX_free_procname);
  FuncLoadError := not assigned(EVP_MD_CTX_free);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_CTX_free_allownil)}
    EVP_MD_CTX_free := ERR_EVP_MD_CTX_free;
    {$ifend}
    {$if declared(EVP_MD_CTX_free_introduced)}
    if LibVersion < EVP_MD_CTX_free_introduced then
    begin
      {$if declared(FC_EVP_MD_CTX_free)}
      EVP_MD_CTX_free := FC_EVP_MD_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_CTX_free_removed)}
    if EVP_MD_CTX_free_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_CTX_free)}
      EVP_MD_CTX_free := _EVP_MD_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_CTX_free');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_MD_CTX_copy_ex := LoadLibFunction(ADllHandle, EVP_MD_CTX_copy_ex_procname);
  FuncLoadError := not assigned(EVP_MD_CTX_copy_ex);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_CTX_copy_ex_allownil)}
    EVP_MD_CTX_copy_ex := ERR_EVP_MD_CTX_copy_ex;
    {$ifend}
    {$if declared(EVP_MD_CTX_copy_ex_introduced)}
    if LibVersion < EVP_MD_CTX_copy_ex_introduced then
    begin
      {$if declared(FC_EVP_MD_CTX_copy_ex)}
      EVP_MD_CTX_copy_ex := FC_EVP_MD_CTX_copy_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_CTX_copy_ex_removed)}
    if EVP_MD_CTX_copy_ex_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_CTX_copy_ex)}
      EVP_MD_CTX_copy_ex := _EVP_MD_CTX_copy_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_CTX_copy_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_CTX_copy_ex');
    {$ifend}
  end;


  EVP_MD_CTX_set_flags := LoadLibFunction(ADllHandle, EVP_MD_CTX_set_flags_procname);
  FuncLoadError := not assigned(EVP_MD_CTX_set_flags);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_CTX_set_flags_allownil)}
    EVP_MD_CTX_set_flags := ERR_EVP_MD_CTX_set_flags;
    {$ifend}
    {$if declared(EVP_MD_CTX_set_flags_introduced)}
    if LibVersion < EVP_MD_CTX_set_flags_introduced then
    begin
      {$if declared(FC_EVP_MD_CTX_set_flags)}
      EVP_MD_CTX_set_flags := FC_EVP_MD_CTX_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_CTX_set_flags_removed)}
    if EVP_MD_CTX_set_flags_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_CTX_set_flags)}
      EVP_MD_CTX_set_flags := _EVP_MD_CTX_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_CTX_set_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_CTX_set_flags');
    {$ifend}
  end;


  EVP_MD_CTX_clear_flags := LoadLibFunction(ADllHandle, EVP_MD_CTX_clear_flags_procname);
  FuncLoadError := not assigned(EVP_MD_CTX_clear_flags);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_CTX_clear_flags_allownil)}
    EVP_MD_CTX_clear_flags := ERR_EVP_MD_CTX_clear_flags;
    {$ifend}
    {$if declared(EVP_MD_CTX_clear_flags_introduced)}
    if LibVersion < EVP_MD_CTX_clear_flags_introduced then
    begin
      {$if declared(FC_EVP_MD_CTX_clear_flags)}
      EVP_MD_CTX_clear_flags := FC_EVP_MD_CTX_clear_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_CTX_clear_flags_removed)}
    if EVP_MD_CTX_clear_flags_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_CTX_clear_flags)}
      EVP_MD_CTX_clear_flags := _EVP_MD_CTX_clear_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_CTX_clear_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_CTX_clear_flags');
    {$ifend}
  end;


  EVP_MD_CTX_test_flags := LoadLibFunction(ADllHandle, EVP_MD_CTX_test_flags_procname);
  FuncLoadError := not assigned(EVP_MD_CTX_test_flags);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_CTX_test_flags_allownil)}
    EVP_MD_CTX_test_flags := ERR_EVP_MD_CTX_test_flags;
    {$ifend}
    {$if declared(EVP_MD_CTX_test_flags_introduced)}
    if LibVersion < EVP_MD_CTX_test_flags_introduced then
    begin
      {$if declared(FC_EVP_MD_CTX_test_flags)}
      EVP_MD_CTX_test_flags := FC_EVP_MD_CTX_test_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_CTX_test_flags_removed)}
    if EVP_MD_CTX_test_flags_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_CTX_test_flags)}
      EVP_MD_CTX_test_flags := _EVP_MD_CTX_test_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_CTX_test_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_CTX_test_flags');
    {$ifend}
  end;


  EVP_DigestInit_ex := LoadLibFunction(ADllHandle, EVP_DigestInit_ex_procname);
  FuncLoadError := not assigned(EVP_DigestInit_ex);
  if FuncLoadError then
  begin
    {$if not defined(EVP_DigestInit_ex_allownil)}
    EVP_DigestInit_ex := ERR_EVP_DigestInit_ex;
    {$ifend}
    {$if declared(EVP_DigestInit_ex_introduced)}
    if LibVersion < EVP_DigestInit_ex_introduced then
    begin
      {$if declared(FC_EVP_DigestInit_ex)}
      EVP_DigestInit_ex := FC_EVP_DigestInit_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_DigestInit_ex_removed)}
    if EVP_DigestInit_ex_removed <= LibVersion then
    begin
      {$if declared(_EVP_DigestInit_ex)}
      EVP_DigestInit_ex := _EVP_DigestInit_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_DigestInit_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_DigestInit_ex');
    {$ifend}
  end;


  EVP_DigestUpdate := LoadLibFunction(ADllHandle, EVP_DigestUpdate_procname);
  FuncLoadError := not assigned(EVP_DigestUpdate);
  if FuncLoadError then
  begin
    {$if not defined(EVP_DigestUpdate_allownil)}
    EVP_DigestUpdate := ERR_EVP_DigestUpdate;
    {$ifend}
    {$if declared(EVP_DigestUpdate_introduced)}
    if LibVersion < EVP_DigestUpdate_introduced then
    begin
      {$if declared(FC_EVP_DigestUpdate)}
      EVP_DigestUpdate := FC_EVP_DigestUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_DigestUpdate_removed)}
    if EVP_DigestUpdate_removed <= LibVersion then
    begin
      {$if declared(_EVP_DigestUpdate)}
      EVP_DigestUpdate := _EVP_DigestUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_DigestUpdate_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_DigestUpdate');
    {$ifend}
  end;


  EVP_DigestFinal_ex := LoadLibFunction(ADllHandle, EVP_DigestFinal_ex_procname);
  FuncLoadError := not assigned(EVP_DigestFinal_ex);
  if FuncLoadError then
  begin
    {$if not defined(EVP_DigestFinal_ex_allownil)}
    EVP_DigestFinal_ex := ERR_EVP_DigestFinal_ex;
    {$ifend}
    {$if declared(EVP_DigestFinal_ex_introduced)}
    if LibVersion < EVP_DigestFinal_ex_introduced then
    begin
      {$if declared(FC_EVP_DigestFinal_ex)}
      EVP_DigestFinal_ex := FC_EVP_DigestFinal_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_DigestFinal_ex_removed)}
    if EVP_DigestFinal_ex_removed <= LibVersion then
    begin
      {$if declared(_EVP_DigestFinal_ex)}
      EVP_DigestFinal_ex := _EVP_DigestFinal_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_DigestFinal_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_DigestFinal_ex');
    {$ifend}
  end;


  EVP_Digest := LoadLibFunction(ADllHandle, EVP_Digest_procname);
  FuncLoadError := not assigned(EVP_Digest);
  if FuncLoadError then
  begin
    {$if not defined(EVP_Digest_allownil)}
    EVP_Digest := ERR_EVP_Digest;
    {$ifend}
    {$if declared(EVP_Digest_introduced)}
    if LibVersion < EVP_Digest_introduced then
    begin
      {$if declared(FC_EVP_Digest)}
      EVP_Digest := FC_EVP_Digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_Digest_removed)}
    if EVP_Digest_removed <= LibVersion then
    begin
      {$if declared(_EVP_Digest)}
      EVP_Digest := _EVP_Digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_Digest_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_Digest');
    {$ifend}
  end;


  EVP_MD_CTX_copy := LoadLibFunction(ADllHandle, EVP_MD_CTX_copy_procname);
  FuncLoadError := not assigned(EVP_MD_CTX_copy);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_CTX_copy_allownil)}
    EVP_MD_CTX_copy := ERR_EVP_MD_CTX_copy;
    {$ifend}
    {$if declared(EVP_MD_CTX_copy_introduced)}
    if LibVersion < EVP_MD_CTX_copy_introduced then
    begin
      {$if declared(FC_EVP_MD_CTX_copy)}
      EVP_MD_CTX_copy := FC_EVP_MD_CTX_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_CTX_copy_removed)}
    if EVP_MD_CTX_copy_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_CTX_copy)}
      EVP_MD_CTX_copy := _EVP_MD_CTX_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_CTX_copy_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_CTX_copy');
    {$ifend}
  end;


  EVP_DigestInit := LoadLibFunction(ADllHandle, EVP_DigestInit_procname);
  FuncLoadError := not assigned(EVP_DigestInit);
  if FuncLoadError then
  begin
    {$if not defined(EVP_DigestInit_allownil)}
    EVP_DigestInit := ERR_EVP_DigestInit;
    {$ifend}
    {$if declared(EVP_DigestInit_introduced)}
    if LibVersion < EVP_DigestInit_introduced then
    begin
      {$if declared(FC_EVP_DigestInit)}
      EVP_DigestInit := FC_EVP_DigestInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_DigestInit_removed)}
    if EVP_DigestInit_removed <= LibVersion then
    begin
      {$if declared(_EVP_DigestInit)}
      EVP_DigestInit := _EVP_DigestInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_DigestInit_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_DigestInit');
    {$ifend}
  end;


  EVP_DigestFinal := LoadLibFunction(ADllHandle, EVP_DigestFinal_procname);
  FuncLoadError := not assigned(EVP_DigestFinal);
  if FuncLoadError then
  begin
    {$if not defined(EVP_DigestFinal_allownil)}
    EVP_DigestFinal := ERR_EVP_DigestFinal;
    {$ifend}
    {$if declared(EVP_DigestFinal_introduced)}
    if LibVersion < EVP_DigestFinal_introduced then
    begin
      {$if declared(FC_EVP_DigestFinal)}
      EVP_DigestFinal := FC_EVP_DigestFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_DigestFinal_removed)}
    if EVP_DigestFinal_removed <= LibVersion then
    begin
      {$if declared(_EVP_DigestFinal)}
      EVP_DigestFinal := _EVP_DigestFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_DigestFinal_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_DigestFinal');
    {$ifend}
  end;


  EVP_DigestFinalXOF := LoadLibFunction(ADllHandle, EVP_DigestFinalXOF_procname);
  FuncLoadError := not assigned(EVP_DigestFinalXOF);
  if FuncLoadError then
  begin
    {$if not defined(EVP_DigestFinalXOF_allownil)}
    EVP_DigestFinalXOF := ERR_EVP_DigestFinalXOF;
    {$ifend}
    {$if declared(EVP_DigestFinalXOF_introduced)}
    if LibVersion < EVP_DigestFinalXOF_introduced then
    begin
      {$if declared(FC_EVP_DigestFinalXOF)}
      EVP_DigestFinalXOF := FC_EVP_DigestFinalXOF;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_DigestFinalXOF_removed)}
    if EVP_DigestFinalXOF_removed <= LibVersion then
    begin
      {$if declared(_EVP_DigestFinalXOF)}
      EVP_DigestFinalXOF := _EVP_DigestFinalXOF;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_DigestFinalXOF_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_DigestFinalXOF');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_read_pw_string := LoadLibFunction(ADllHandle, EVP_read_pw_string_procname);
  FuncLoadError := not assigned(EVP_read_pw_string);
  if FuncLoadError then
  begin
    {$if not defined(EVP_read_pw_string_allownil)}
    EVP_read_pw_string := ERR_EVP_read_pw_string;
    {$ifend}
    {$if declared(EVP_read_pw_string_introduced)}
    if LibVersion < EVP_read_pw_string_introduced then
    begin
      {$if declared(FC_EVP_read_pw_string)}
      EVP_read_pw_string := FC_EVP_read_pw_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_read_pw_string_removed)}
    if EVP_read_pw_string_removed <= LibVersion then
    begin
      {$if declared(_EVP_read_pw_string)}
      EVP_read_pw_string := _EVP_read_pw_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_read_pw_string_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_read_pw_string');
    {$ifend}
  end;


  EVP_read_pw_string_min := LoadLibFunction(ADllHandle, EVP_read_pw_string_min_procname);
  FuncLoadError := not assigned(EVP_read_pw_string_min);
  if FuncLoadError then
  begin
    {$if not defined(EVP_read_pw_string_min_allownil)}
    EVP_read_pw_string_min := ERR_EVP_read_pw_string_min;
    {$ifend}
    {$if declared(EVP_read_pw_string_min_introduced)}
    if LibVersion < EVP_read_pw_string_min_introduced then
    begin
      {$if declared(FC_EVP_read_pw_string_min)}
      EVP_read_pw_string_min := FC_EVP_read_pw_string_min;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_read_pw_string_min_removed)}
    if EVP_read_pw_string_min_removed <= LibVersion then
    begin
      {$if declared(_EVP_read_pw_string_min)}
      EVP_read_pw_string_min := _EVP_read_pw_string_min;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_read_pw_string_min_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_read_pw_string_min');
    {$ifend}
  end;


  EVP_set_pw_prompt := LoadLibFunction(ADllHandle, EVP_set_pw_prompt_procname);
  FuncLoadError := not assigned(EVP_set_pw_prompt);
  if FuncLoadError then
  begin
    {$if not defined(EVP_set_pw_prompt_allownil)}
    EVP_set_pw_prompt := ERR_EVP_set_pw_prompt;
    {$ifend}
    {$if declared(EVP_set_pw_prompt_introduced)}
    if LibVersion < EVP_set_pw_prompt_introduced then
    begin
      {$if declared(FC_EVP_set_pw_prompt)}
      EVP_set_pw_prompt := FC_EVP_set_pw_prompt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_set_pw_prompt_removed)}
    if EVP_set_pw_prompt_removed <= LibVersion then
    begin
      {$if declared(_EVP_set_pw_prompt)}
      EVP_set_pw_prompt := _EVP_set_pw_prompt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_set_pw_prompt_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_set_pw_prompt');
    {$ifend}
  end;


  EVP_get_pw_prompt := LoadLibFunction(ADllHandle, EVP_get_pw_prompt_procname);
  FuncLoadError := not assigned(EVP_get_pw_prompt);
  if FuncLoadError then
  begin
    {$if not defined(EVP_get_pw_prompt_allownil)}
    EVP_get_pw_prompt := ERR_EVP_get_pw_prompt;
    {$ifend}
    {$if declared(EVP_get_pw_prompt_introduced)}
    if LibVersion < EVP_get_pw_prompt_introduced then
    begin
      {$if declared(FC_EVP_get_pw_prompt)}
      EVP_get_pw_prompt := FC_EVP_get_pw_prompt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_get_pw_prompt_removed)}
    if EVP_get_pw_prompt_removed <= LibVersion then
    begin
      {$if declared(_EVP_get_pw_prompt)}
      EVP_get_pw_prompt := _EVP_get_pw_prompt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_get_pw_prompt_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_get_pw_prompt');
    {$ifend}
  end;


  EVP_BytesToKey := LoadLibFunction(ADllHandle, EVP_BytesToKey_procname);
  FuncLoadError := not assigned(EVP_BytesToKey);
  if FuncLoadError then
  begin
    {$if not defined(EVP_BytesToKey_allownil)}
    EVP_BytesToKey := ERR_EVP_BytesToKey;
    {$ifend}
    {$if declared(EVP_BytesToKey_introduced)}
    if LibVersion < EVP_BytesToKey_introduced then
    begin
      {$if declared(FC_EVP_BytesToKey)}
      EVP_BytesToKey := FC_EVP_BytesToKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_BytesToKey_removed)}
    if EVP_BytesToKey_removed <= LibVersion then
    begin
      {$if declared(_EVP_BytesToKey)}
      EVP_BytesToKey := _EVP_BytesToKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_BytesToKey_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_BytesToKey');
    {$ifend}
  end;


  EVP_CIPHER_CTX_set_flags := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_set_flags_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_set_flags);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_set_flags_allownil)}
    EVP_CIPHER_CTX_set_flags := ERR_EVP_CIPHER_CTX_set_flags;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_set_flags_introduced)}
    if LibVersion < EVP_CIPHER_CTX_set_flags_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_set_flags)}
      EVP_CIPHER_CTX_set_flags := FC_EVP_CIPHER_CTX_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_set_flags_removed)}
    if EVP_CIPHER_CTX_set_flags_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_set_flags)}
      EVP_CIPHER_CTX_set_flags := _EVP_CIPHER_CTX_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_set_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_set_flags');
    {$ifend}
  end;


  EVP_CIPHER_CTX_clear_flags := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_clear_flags_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_clear_flags);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_clear_flags_allownil)}
    EVP_CIPHER_CTX_clear_flags := ERR_EVP_CIPHER_CTX_clear_flags;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_clear_flags_introduced)}
    if LibVersion < EVP_CIPHER_CTX_clear_flags_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_clear_flags)}
      EVP_CIPHER_CTX_clear_flags := FC_EVP_CIPHER_CTX_clear_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_clear_flags_removed)}
    if EVP_CIPHER_CTX_clear_flags_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_clear_flags)}
      EVP_CIPHER_CTX_clear_flags := _EVP_CIPHER_CTX_clear_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_clear_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_clear_flags');
    {$ifend}
  end;


  EVP_CIPHER_CTX_test_flags := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_test_flags_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_test_flags);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_test_flags_allownil)}
    EVP_CIPHER_CTX_test_flags := ERR_EVP_CIPHER_CTX_test_flags;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_test_flags_introduced)}
    if LibVersion < EVP_CIPHER_CTX_test_flags_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_test_flags)}
      EVP_CIPHER_CTX_test_flags := FC_EVP_CIPHER_CTX_test_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_test_flags_removed)}
    if EVP_CIPHER_CTX_test_flags_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_test_flags)}
      EVP_CIPHER_CTX_test_flags := _EVP_CIPHER_CTX_test_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_test_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_test_flags');
    {$ifend}
  end;


  EVP_EncryptInit := LoadLibFunction(ADllHandle, EVP_EncryptInit_procname);
  FuncLoadError := not assigned(EVP_EncryptInit);
  if FuncLoadError then
  begin
    {$if not defined(EVP_EncryptInit_allownil)}
    EVP_EncryptInit := ERR_EVP_EncryptInit;
    {$ifend}
    {$if declared(EVP_EncryptInit_introduced)}
    if LibVersion < EVP_EncryptInit_introduced then
    begin
      {$if declared(FC_EVP_EncryptInit)}
      EVP_EncryptInit := FC_EVP_EncryptInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_EncryptInit_removed)}
    if EVP_EncryptInit_removed <= LibVersion then
    begin
      {$if declared(_EVP_EncryptInit)}
      EVP_EncryptInit := _EVP_EncryptInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_EncryptInit_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_EncryptInit');
    {$ifend}
  end;


  EVP_EncryptInit_ex := LoadLibFunction(ADllHandle, EVP_EncryptInit_ex_procname);
  FuncLoadError := not assigned(EVP_EncryptInit_ex);
  if FuncLoadError then
  begin
    {$if not defined(EVP_EncryptInit_ex_allownil)}
    EVP_EncryptInit_ex := ERR_EVP_EncryptInit_ex;
    {$ifend}
    {$if declared(EVP_EncryptInit_ex_introduced)}
    if LibVersion < EVP_EncryptInit_ex_introduced then
    begin
      {$if declared(FC_EVP_EncryptInit_ex)}
      EVP_EncryptInit_ex := FC_EVP_EncryptInit_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_EncryptInit_ex_removed)}
    if EVP_EncryptInit_ex_removed <= LibVersion then
    begin
      {$if declared(_EVP_EncryptInit_ex)}
      EVP_EncryptInit_ex := _EVP_EncryptInit_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_EncryptInit_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_EncryptInit_ex');
    {$ifend}
  end;


  EVP_EncryptUpdate := LoadLibFunction(ADllHandle, EVP_EncryptUpdate_procname);
  FuncLoadError := not assigned(EVP_EncryptUpdate);
  if FuncLoadError then
  begin
    {$if not defined(EVP_EncryptUpdate_allownil)}
    EVP_EncryptUpdate := ERR_EVP_EncryptUpdate;
    {$ifend}
    {$if declared(EVP_EncryptUpdate_introduced)}
    if LibVersion < EVP_EncryptUpdate_introduced then
    begin
      {$if declared(FC_EVP_EncryptUpdate)}
      EVP_EncryptUpdate := FC_EVP_EncryptUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_EncryptUpdate_removed)}
    if EVP_EncryptUpdate_removed <= LibVersion then
    begin
      {$if declared(_EVP_EncryptUpdate)}
      EVP_EncryptUpdate := _EVP_EncryptUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_EncryptUpdate_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_EncryptUpdate');
    {$ifend}
  end;


  EVP_EncryptFinal_ex := LoadLibFunction(ADllHandle, EVP_EncryptFinal_ex_procname);
  FuncLoadError := not assigned(EVP_EncryptFinal_ex);
  if FuncLoadError then
  begin
    {$if not defined(EVP_EncryptFinal_ex_allownil)}
    EVP_EncryptFinal_ex := ERR_EVP_EncryptFinal_ex;
    {$ifend}
    {$if declared(EVP_EncryptFinal_ex_introduced)}
    if LibVersion < EVP_EncryptFinal_ex_introduced then
    begin
      {$if declared(FC_EVP_EncryptFinal_ex)}
      EVP_EncryptFinal_ex := FC_EVP_EncryptFinal_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_EncryptFinal_ex_removed)}
    if EVP_EncryptFinal_ex_removed <= LibVersion then
    begin
      {$if declared(_EVP_EncryptFinal_ex)}
      EVP_EncryptFinal_ex := _EVP_EncryptFinal_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_EncryptFinal_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_EncryptFinal_ex');
    {$ifend}
  end;


  EVP_EncryptFinal := LoadLibFunction(ADllHandle, EVP_EncryptFinal_procname);
  FuncLoadError := not assigned(EVP_EncryptFinal);
  if FuncLoadError then
  begin
    {$if not defined(EVP_EncryptFinal_allownil)}
    EVP_EncryptFinal := ERR_EVP_EncryptFinal;
    {$ifend}
    {$if declared(EVP_EncryptFinal_introduced)}
    if LibVersion < EVP_EncryptFinal_introduced then
    begin
      {$if declared(FC_EVP_EncryptFinal)}
      EVP_EncryptFinal := FC_EVP_EncryptFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_EncryptFinal_removed)}
    if EVP_EncryptFinal_removed <= LibVersion then
    begin
      {$if declared(_EVP_EncryptFinal)}
      EVP_EncryptFinal := _EVP_EncryptFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_EncryptFinal_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_EncryptFinal');
    {$ifend}
  end;


  EVP_DecryptInit := LoadLibFunction(ADllHandle, EVP_DecryptInit_procname);
  FuncLoadError := not assigned(EVP_DecryptInit);
  if FuncLoadError then
  begin
    {$if not defined(EVP_DecryptInit_allownil)}
    EVP_DecryptInit := ERR_EVP_DecryptInit;
    {$ifend}
    {$if declared(EVP_DecryptInit_introduced)}
    if LibVersion < EVP_DecryptInit_introduced then
    begin
      {$if declared(FC_EVP_DecryptInit)}
      EVP_DecryptInit := FC_EVP_DecryptInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_DecryptInit_removed)}
    if EVP_DecryptInit_removed <= LibVersion then
    begin
      {$if declared(_EVP_DecryptInit)}
      EVP_DecryptInit := _EVP_DecryptInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_DecryptInit_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_DecryptInit');
    {$ifend}
  end;


  EVP_DecryptInit_ex := LoadLibFunction(ADllHandle, EVP_DecryptInit_ex_procname);
  FuncLoadError := not assigned(EVP_DecryptInit_ex);
  if FuncLoadError then
  begin
    {$if not defined(EVP_DecryptInit_ex_allownil)}
    EVP_DecryptInit_ex := ERR_EVP_DecryptInit_ex;
    {$ifend}
    {$if declared(EVP_DecryptInit_ex_introduced)}
    if LibVersion < EVP_DecryptInit_ex_introduced then
    begin
      {$if declared(FC_EVP_DecryptInit_ex)}
      EVP_DecryptInit_ex := FC_EVP_DecryptInit_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_DecryptInit_ex_removed)}
    if EVP_DecryptInit_ex_removed <= LibVersion then
    begin
      {$if declared(_EVP_DecryptInit_ex)}
      EVP_DecryptInit_ex := _EVP_DecryptInit_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_DecryptInit_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_DecryptInit_ex');
    {$ifend}
  end;


  EVP_DecryptUpdate := LoadLibFunction(ADllHandle, EVP_DecryptUpdate_procname);
  FuncLoadError := not assigned(EVP_DecryptUpdate);
  if FuncLoadError then
  begin
    {$if not defined(EVP_DecryptUpdate_allownil)}
    EVP_DecryptUpdate := ERR_EVP_DecryptUpdate;
    {$ifend}
    {$if declared(EVP_DecryptUpdate_introduced)}
    if LibVersion < EVP_DecryptUpdate_introduced then
    begin
      {$if declared(FC_EVP_DecryptUpdate)}
      EVP_DecryptUpdate := FC_EVP_DecryptUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_DecryptUpdate_removed)}
    if EVP_DecryptUpdate_removed <= LibVersion then
    begin
      {$if declared(_EVP_DecryptUpdate)}
      EVP_DecryptUpdate := _EVP_DecryptUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_DecryptUpdate_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_DecryptUpdate');
    {$ifend}
  end;


  EVP_DecryptFinal := LoadLibFunction(ADllHandle, EVP_DecryptFinal_procname);
  FuncLoadError := not assigned(EVP_DecryptFinal);
  if FuncLoadError then
  begin
    {$if not defined(EVP_DecryptFinal_allownil)}
    EVP_DecryptFinal := ERR_EVP_DecryptFinal;
    {$ifend}
    {$if declared(EVP_DecryptFinal_introduced)}
    if LibVersion < EVP_DecryptFinal_introduced then
    begin
      {$if declared(FC_EVP_DecryptFinal)}
      EVP_DecryptFinal := FC_EVP_DecryptFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_DecryptFinal_removed)}
    if EVP_DecryptFinal_removed <= LibVersion then
    begin
      {$if declared(_EVP_DecryptFinal)}
      EVP_DecryptFinal := _EVP_DecryptFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_DecryptFinal_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_DecryptFinal');
    {$ifend}
  end;


  EVP_DecryptFinal_ex := LoadLibFunction(ADllHandle, EVP_DecryptFinal_ex_procname);
  FuncLoadError := not assigned(EVP_DecryptFinal_ex);
  if FuncLoadError then
  begin
    {$if not defined(EVP_DecryptFinal_ex_allownil)}
    EVP_DecryptFinal_ex := ERR_EVP_DecryptFinal_ex;
    {$ifend}
    {$if declared(EVP_DecryptFinal_ex_introduced)}
    if LibVersion < EVP_DecryptFinal_ex_introduced then
    begin
      {$if declared(FC_EVP_DecryptFinal_ex)}
      EVP_DecryptFinal_ex := FC_EVP_DecryptFinal_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_DecryptFinal_ex_removed)}
    if EVP_DecryptFinal_ex_removed <= LibVersion then
    begin
      {$if declared(_EVP_DecryptFinal_ex)}
      EVP_DecryptFinal_ex := _EVP_DecryptFinal_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_DecryptFinal_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_DecryptFinal_ex');
    {$ifend}
  end;


  EVP_CipherInit := LoadLibFunction(ADllHandle, EVP_CipherInit_procname);
  FuncLoadError := not assigned(EVP_CipherInit);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CipherInit_allownil)}
    EVP_CipherInit := ERR_EVP_CipherInit;
    {$ifend}
    {$if declared(EVP_CipherInit_introduced)}
    if LibVersion < EVP_CipherInit_introduced then
    begin
      {$if declared(FC_EVP_CipherInit)}
      EVP_CipherInit := FC_EVP_CipherInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CipherInit_removed)}
    if EVP_CipherInit_removed <= LibVersion then
    begin
      {$if declared(_EVP_CipherInit)}
      EVP_CipherInit := _EVP_CipherInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CipherInit_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CipherInit');
    {$ifend}
  end;


  EVP_CipherInit_ex := LoadLibFunction(ADllHandle, EVP_CipherInit_ex_procname);
  FuncLoadError := not assigned(EVP_CipherInit_ex);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CipherInit_ex_allownil)}
    EVP_CipherInit_ex := ERR_EVP_CipherInit_ex;
    {$ifend}
    {$if declared(EVP_CipherInit_ex_introduced)}
    if LibVersion < EVP_CipherInit_ex_introduced then
    begin
      {$if declared(FC_EVP_CipherInit_ex)}
      EVP_CipherInit_ex := FC_EVP_CipherInit_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CipherInit_ex_removed)}
    if EVP_CipherInit_ex_removed <= LibVersion then
    begin
      {$if declared(_EVP_CipherInit_ex)}
      EVP_CipherInit_ex := _EVP_CipherInit_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CipherInit_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CipherInit_ex');
    {$ifend}
  end;


  EVP_CipherUpdate := LoadLibFunction(ADllHandle, EVP_CipherUpdate_procname);
  FuncLoadError := not assigned(EVP_CipherUpdate);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CipherUpdate_allownil)}
    EVP_CipherUpdate := ERR_EVP_CipherUpdate;
    {$ifend}
    {$if declared(EVP_CipherUpdate_introduced)}
    if LibVersion < EVP_CipherUpdate_introduced then
    begin
      {$if declared(FC_EVP_CipherUpdate)}
      EVP_CipherUpdate := FC_EVP_CipherUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CipherUpdate_removed)}
    if EVP_CipherUpdate_removed <= LibVersion then
    begin
      {$if declared(_EVP_CipherUpdate)}
      EVP_CipherUpdate := _EVP_CipherUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CipherUpdate_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CipherUpdate');
    {$ifend}
  end;


  EVP_CipherFinal := LoadLibFunction(ADllHandle, EVP_CipherFinal_procname);
  FuncLoadError := not assigned(EVP_CipherFinal);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CipherFinal_allownil)}
    EVP_CipherFinal := ERR_EVP_CipherFinal;
    {$ifend}
    {$if declared(EVP_CipherFinal_introduced)}
    if LibVersion < EVP_CipherFinal_introduced then
    begin
      {$if declared(FC_EVP_CipherFinal)}
      EVP_CipherFinal := FC_EVP_CipherFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CipherFinal_removed)}
    if EVP_CipherFinal_removed <= LibVersion then
    begin
      {$if declared(_EVP_CipherFinal)}
      EVP_CipherFinal := _EVP_CipherFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CipherFinal_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CipherFinal');
    {$ifend}
  end;


  EVP_CipherFinal_ex := LoadLibFunction(ADllHandle, EVP_CipherFinal_ex_procname);
  FuncLoadError := not assigned(EVP_CipherFinal_ex);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CipherFinal_ex_allownil)}
    EVP_CipherFinal_ex := ERR_EVP_CipherFinal_ex;
    {$ifend}
    {$if declared(EVP_CipherFinal_ex_introduced)}
    if LibVersion < EVP_CipherFinal_ex_introduced then
    begin
      {$if declared(FC_EVP_CipherFinal_ex)}
      EVP_CipherFinal_ex := FC_EVP_CipherFinal_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CipherFinal_ex_removed)}
    if EVP_CipherFinal_ex_removed <= LibVersion then
    begin
      {$if declared(_EVP_CipherFinal_ex)}
      EVP_CipherFinal_ex := _EVP_CipherFinal_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CipherFinal_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CipherFinal_ex');
    {$ifend}
  end;


  EVP_SignFinal := LoadLibFunction(ADllHandle, EVP_SignFinal_procname);
  FuncLoadError := not assigned(EVP_SignFinal);
  if FuncLoadError then
  begin
    {$if not defined(EVP_SignFinal_allownil)}
    EVP_SignFinal := ERR_EVP_SignFinal;
    {$ifend}
    {$if declared(EVP_SignFinal_introduced)}
    if LibVersion < EVP_SignFinal_introduced then
    begin
      {$if declared(FC_EVP_SignFinal)}
      EVP_SignFinal := FC_EVP_SignFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_SignFinal_removed)}
    if EVP_SignFinal_removed <= LibVersion then
    begin
      {$if declared(_EVP_SignFinal)}
      EVP_SignFinal := _EVP_SignFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_SignFinal_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_SignFinal');
    {$ifend}
  end;


  EVP_DigestSign := LoadLibFunction(ADllHandle, EVP_DigestSign_procname);
  FuncLoadError := not assigned(EVP_DigestSign);
  if FuncLoadError then
  begin
    {$if not defined(EVP_DigestSign_allownil)}
    EVP_DigestSign := ERR_EVP_DigestSign;
    {$ifend}
    {$if declared(EVP_DigestSign_introduced)}
    if LibVersion < EVP_DigestSign_introduced then
    begin
      {$if declared(FC_EVP_DigestSign)}
      EVP_DigestSign := FC_EVP_DigestSign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_DigestSign_removed)}
    if EVP_DigestSign_removed <= LibVersion then
    begin
      {$if declared(_EVP_DigestSign)}
      EVP_DigestSign := _EVP_DigestSign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_DigestSign_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_DigestSign');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_VerifyFinal := LoadLibFunction(ADllHandle, EVP_VerifyFinal_procname);
  FuncLoadError := not assigned(EVP_VerifyFinal);
  if FuncLoadError then
  begin
    {$if not defined(EVP_VerifyFinal_allownil)}
    EVP_VerifyFinal := ERR_EVP_VerifyFinal;
    {$ifend}
    {$if declared(EVP_VerifyFinal_introduced)}
    if LibVersion < EVP_VerifyFinal_introduced then
    begin
      {$if declared(FC_EVP_VerifyFinal)}
      EVP_VerifyFinal := FC_EVP_VerifyFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_VerifyFinal_removed)}
    if EVP_VerifyFinal_removed <= LibVersion then
    begin
      {$if declared(_EVP_VerifyFinal)}
      EVP_VerifyFinal := _EVP_VerifyFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_VerifyFinal_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_VerifyFinal');
    {$ifend}
  end;


  EVP_DigestVerify := LoadLibFunction(ADllHandle, EVP_DigestVerify_procname);
  FuncLoadError := not assigned(EVP_DigestVerify);
  if FuncLoadError then
  begin
    {$if not defined(EVP_DigestVerify_allownil)}
    EVP_DigestVerify := ERR_EVP_DigestVerify;
    {$ifend}
    {$if declared(EVP_DigestVerify_introduced)}
    if LibVersion < EVP_DigestVerify_introduced then
    begin
      {$if declared(FC_EVP_DigestVerify)}
      EVP_DigestVerify := FC_EVP_DigestVerify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_DigestVerify_removed)}
    if EVP_DigestVerify_removed <= LibVersion then
    begin
      {$if declared(_EVP_DigestVerify)}
      EVP_DigestVerify := _EVP_DigestVerify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_DigestVerify_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_DigestVerify');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_DigestSignInit := LoadLibFunction(ADllHandle, EVP_DigestSignInit_procname);
  FuncLoadError := not assigned(EVP_DigestSignInit);
  if FuncLoadError then
  begin
    {$if not defined(EVP_DigestSignInit_allownil)}
    EVP_DigestSignInit := ERR_EVP_DigestSignInit;
    {$ifend}
    {$if declared(EVP_DigestSignInit_introduced)}
    if LibVersion < EVP_DigestSignInit_introduced then
    begin
      {$if declared(FC_EVP_DigestSignInit)}
      EVP_DigestSignInit := FC_EVP_DigestSignInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_DigestSignInit_removed)}
    if EVP_DigestSignInit_removed <= LibVersion then
    begin
      {$if declared(_EVP_DigestSignInit)}
      EVP_DigestSignInit := _EVP_DigestSignInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_DigestSignInit_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_DigestSignInit');
    {$ifend}
  end;


  EVP_DigestSignFinal := LoadLibFunction(ADllHandle, EVP_DigestSignFinal_procname);
  FuncLoadError := not assigned(EVP_DigestSignFinal);
  if FuncLoadError then
  begin
    {$if not defined(EVP_DigestSignFinal_allownil)}
    EVP_DigestSignFinal := ERR_EVP_DigestSignFinal;
    {$ifend}
    {$if declared(EVP_DigestSignFinal_introduced)}
    if LibVersion < EVP_DigestSignFinal_introduced then
    begin
      {$if declared(FC_EVP_DigestSignFinal)}
      EVP_DigestSignFinal := FC_EVP_DigestSignFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_DigestSignFinal_removed)}
    if EVP_DigestSignFinal_removed <= LibVersion then
    begin
      {$if declared(_EVP_DigestSignFinal)}
      EVP_DigestSignFinal := _EVP_DigestSignFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_DigestSignFinal_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_DigestSignFinal');
    {$ifend}
  end;


  EVP_DigestVerifyInit := LoadLibFunction(ADllHandle, EVP_DigestVerifyInit_procname);
  FuncLoadError := not assigned(EVP_DigestVerifyInit);
  if FuncLoadError then
  begin
    {$if not defined(EVP_DigestVerifyInit_allownil)}
    EVP_DigestVerifyInit := ERR_EVP_DigestVerifyInit;
    {$ifend}
    {$if declared(EVP_DigestVerifyInit_introduced)}
    if LibVersion < EVP_DigestVerifyInit_introduced then
    begin
      {$if declared(FC_EVP_DigestVerifyInit)}
      EVP_DigestVerifyInit := FC_EVP_DigestVerifyInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_DigestVerifyInit_removed)}
    if EVP_DigestVerifyInit_removed <= LibVersion then
    begin
      {$if declared(_EVP_DigestVerifyInit)}
      EVP_DigestVerifyInit := _EVP_DigestVerifyInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_DigestVerifyInit_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_DigestVerifyInit');
    {$ifend}
  end;


  EVP_DigestVerifyFinal := LoadLibFunction(ADllHandle, EVP_DigestVerifyFinal_procname);
  FuncLoadError := not assigned(EVP_DigestVerifyFinal);
  if FuncLoadError then
  begin
    {$if not defined(EVP_DigestVerifyFinal_allownil)}
    EVP_DigestVerifyFinal := ERR_EVP_DigestVerifyFinal;
    {$ifend}
    {$if declared(EVP_DigestVerifyFinal_introduced)}
    if LibVersion < EVP_DigestVerifyFinal_introduced then
    begin
      {$if declared(FC_EVP_DigestVerifyFinal)}
      EVP_DigestVerifyFinal := FC_EVP_DigestVerifyFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_DigestVerifyFinal_removed)}
    if EVP_DigestVerifyFinal_removed <= LibVersion then
    begin
      {$if declared(_EVP_DigestVerifyFinal)}
      EVP_DigestVerifyFinal := _EVP_DigestVerifyFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_DigestVerifyFinal_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_DigestVerifyFinal');
    {$ifend}
  end;


  EVP_OpenInit := LoadLibFunction(ADllHandle, EVP_OpenInit_procname);
  FuncLoadError := not assigned(EVP_OpenInit);
  if FuncLoadError then
  begin
    {$if not defined(EVP_OpenInit_allownil)}
    EVP_OpenInit := ERR_EVP_OpenInit;
    {$ifend}
    {$if declared(EVP_OpenInit_introduced)}
    if LibVersion < EVP_OpenInit_introduced then
    begin
      {$if declared(FC_EVP_OpenInit)}
      EVP_OpenInit := FC_EVP_OpenInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_OpenInit_removed)}
    if EVP_OpenInit_removed <= LibVersion then
    begin
      {$if declared(_EVP_OpenInit)}
      EVP_OpenInit := _EVP_OpenInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_OpenInit_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_OpenInit');
    {$ifend}
  end;


  EVP_OpenFinal := LoadLibFunction(ADllHandle, EVP_OpenFinal_procname);
  FuncLoadError := not assigned(EVP_OpenFinal);
  if FuncLoadError then
  begin
    {$if not defined(EVP_OpenFinal_allownil)}
    EVP_OpenFinal := ERR_EVP_OpenFinal;
    {$ifend}
    {$if declared(EVP_OpenFinal_introduced)}
    if LibVersion < EVP_OpenFinal_introduced then
    begin
      {$if declared(FC_EVP_OpenFinal)}
      EVP_OpenFinal := FC_EVP_OpenFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_OpenFinal_removed)}
    if EVP_OpenFinal_removed <= LibVersion then
    begin
      {$if declared(_EVP_OpenFinal)}
      EVP_OpenFinal := _EVP_OpenFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_OpenFinal_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_OpenFinal');
    {$ifend}
  end;


  EVP_SealInit := LoadLibFunction(ADllHandle, EVP_SealInit_procname);
  FuncLoadError := not assigned(EVP_SealInit);
  if FuncLoadError then
  begin
    {$if not defined(EVP_SealInit_allownil)}
    EVP_SealInit := ERR_EVP_SealInit;
    {$ifend}
    {$if declared(EVP_SealInit_introduced)}
    if LibVersion < EVP_SealInit_introduced then
    begin
      {$if declared(FC_EVP_SealInit)}
      EVP_SealInit := FC_EVP_SealInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_SealInit_removed)}
    if EVP_SealInit_removed <= LibVersion then
    begin
      {$if declared(_EVP_SealInit)}
      EVP_SealInit := _EVP_SealInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_SealInit_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_SealInit');
    {$ifend}
  end;


  EVP_SealFinal := LoadLibFunction(ADllHandle, EVP_SealFinal_procname);
  FuncLoadError := not assigned(EVP_SealFinal);
  if FuncLoadError then
  begin
    {$if not defined(EVP_SealFinal_allownil)}
    EVP_SealFinal := ERR_EVP_SealFinal;
    {$ifend}
    {$if declared(EVP_SealFinal_introduced)}
    if LibVersion < EVP_SealFinal_introduced then
    begin
      {$if declared(FC_EVP_SealFinal)}
      EVP_SealFinal := FC_EVP_SealFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_SealFinal_removed)}
    if EVP_SealFinal_removed <= LibVersion then
    begin
      {$if declared(_EVP_SealFinal)}
      EVP_SealFinal := _EVP_SealFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_SealFinal_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_SealFinal');
    {$ifend}
  end;


  EVP_ENCODE_CTX_new := LoadLibFunction(ADllHandle, EVP_ENCODE_CTX_new_procname);
  FuncLoadError := not assigned(EVP_ENCODE_CTX_new);
  if FuncLoadError then
  begin
    {$if not defined(EVP_ENCODE_CTX_new_allownil)}
    EVP_ENCODE_CTX_new := ERR_EVP_ENCODE_CTX_new;
    {$ifend}
    {$if declared(EVP_ENCODE_CTX_new_introduced)}
    if LibVersion < EVP_ENCODE_CTX_new_introduced then
    begin
      {$if declared(FC_EVP_ENCODE_CTX_new)}
      EVP_ENCODE_CTX_new := FC_EVP_ENCODE_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_ENCODE_CTX_new_removed)}
    if EVP_ENCODE_CTX_new_removed <= LibVersion then
    begin
      {$if declared(_EVP_ENCODE_CTX_new)}
      EVP_ENCODE_CTX_new := _EVP_ENCODE_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_ENCODE_CTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_ENCODE_CTX_new');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_ENCODE_CTX_free := LoadLibFunction(ADllHandle, EVP_ENCODE_CTX_free_procname);
  FuncLoadError := not assigned(EVP_ENCODE_CTX_free);
  if FuncLoadError then
  begin
    {$if not defined(EVP_ENCODE_CTX_free_allownil)}
    EVP_ENCODE_CTX_free := ERR_EVP_ENCODE_CTX_free;
    {$ifend}
    {$if declared(EVP_ENCODE_CTX_free_introduced)}
    if LibVersion < EVP_ENCODE_CTX_free_introduced then
    begin
      {$if declared(FC_EVP_ENCODE_CTX_free)}
      EVP_ENCODE_CTX_free := FC_EVP_ENCODE_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_ENCODE_CTX_free_removed)}
    if EVP_ENCODE_CTX_free_removed <= LibVersion then
    begin
      {$if declared(_EVP_ENCODE_CTX_free)}
      EVP_ENCODE_CTX_free := _EVP_ENCODE_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_ENCODE_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_ENCODE_CTX_free');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_ENCODE_CTX_copy := LoadLibFunction(ADllHandle, EVP_ENCODE_CTX_copy_procname);
  FuncLoadError := not assigned(EVP_ENCODE_CTX_copy);
  if FuncLoadError then
  begin
    {$if not defined(EVP_ENCODE_CTX_copy_allownil)}
    EVP_ENCODE_CTX_copy := ERR_EVP_ENCODE_CTX_copy;
    {$ifend}
    {$if declared(EVP_ENCODE_CTX_copy_introduced)}
    if LibVersion < EVP_ENCODE_CTX_copy_introduced then
    begin
      {$if declared(FC_EVP_ENCODE_CTX_copy)}
      EVP_ENCODE_CTX_copy := FC_EVP_ENCODE_CTX_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_ENCODE_CTX_copy_removed)}
    if EVP_ENCODE_CTX_copy_removed <= LibVersion then
    begin
      {$if declared(_EVP_ENCODE_CTX_copy)}
      EVP_ENCODE_CTX_copy := _EVP_ENCODE_CTX_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_ENCODE_CTX_copy_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_ENCODE_CTX_copy');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_ENCODE_CTX_num := LoadLibFunction(ADllHandle, EVP_ENCODE_CTX_num_procname);
  FuncLoadError := not assigned(EVP_ENCODE_CTX_num);
  if FuncLoadError then
  begin
    {$if not defined(EVP_ENCODE_CTX_num_allownil)}
    EVP_ENCODE_CTX_num := ERR_EVP_ENCODE_CTX_num;
    {$ifend}
    {$if declared(EVP_ENCODE_CTX_num_introduced)}
    if LibVersion < EVP_ENCODE_CTX_num_introduced then
    begin
      {$if declared(FC_EVP_ENCODE_CTX_num)}
      EVP_ENCODE_CTX_num := FC_EVP_ENCODE_CTX_num;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_ENCODE_CTX_num_removed)}
    if EVP_ENCODE_CTX_num_removed <= LibVersion then
    begin
      {$if declared(_EVP_ENCODE_CTX_num)}
      EVP_ENCODE_CTX_num := _EVP_ENCODE_CTX_num;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_ENCODE_CTX_num_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_ENCODE_CTX_num');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_EncodeInit := LoadLibFunction(ADllHandle, EVP_EncodeInit_procname);
  FuncLoadError := not assigned(EVP_EncodeInit);
  if FuncLoadError then
  begin
    {$if not defined(EVP_EncodeInit_allownil)}
    EVP_EncodeInit := ERR_EVP_EncodeInit;
    {$ifend}
    {$if declared(EVP_EncodeInit_introduced)}
    if LibVersion < EVP_EncodeInit_introduced then
    begin
      {$if declared(FC_EVP_EncodeInit)}
      EVP_EncodeInit := FC_EVP_EncodeInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_EncodeInit_removed)}
    if EVP_EncodeInit_removed <= LibVersion then
    begin
      {$if declared(_EVP_EncodeInit)}
      EVP_EncodeInit := _EVP_EncodeInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_EncodeInit_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_EncodeInit');
    {$ifend}
  end;


  EVP_EncodeUpdate := LoadLibFunction(ADllHandle, EVP_EncodeUpdate_procname);
  FuncLoadError := not assigned(EVP_EncodeUpdate);
  if FuncLoadError then
  begin
    {$if not defined(EVP_EncodeUpdate_allownil)}
    EVP_EncodeUpdate := ERR_EVP_EncodeUpdate;
    {$ifend}
    {$if declared(EVP_EncodeUpdate_introduced)}
    if LibVersion < EVP_EncodeUpdate_introduced then
    begin
      {$if declared(FC_EVP_EncodeUpdate)}
      EVP_EncodeUpdate := FC_EVP_EncodeUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_EncodeUpdate_removed)}
    if EVP_EncodeUpdate_removed <= LibVersion then
    begin
      {$if declared(_EVP_EncodeUpdate)}
      EVP_EncodeUpdate := _EVP_EncodeUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_EncodeUpdate_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_EncodeUpdate');
    {$ifend}
  end;


  EVP_EncodeFinal := LoadLibFunction(ADllHandle, EVP_EncodeFinal_procname);
  FuncLoadError := not assigned(EVP_EncodeFinal);
  if FuncLoadError then
  begin
    {$if not defined(EVP_EncodeFinal_allownil)}
    EVP_EncodeFinal := ERR_EVP_EncodeFinal;
    {$ifend}
    {$if declared(EVP_EncodeFinal_introduced)}
    if LibVersion < EVP_EncodeFinal_introduced then
    begin
      {$if declared(FC_EVP_EncodeFinal)}
      EVP_EncodeFinal := FC_EVP_EncodeFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_EncodeFinal_removed)}
    if EVP_EncodeFinal_removed <= LibVersion then
    begin
      {$if declared(_EVP_EncodeFinal)}
      EVP_EncodeFinal := _EVP_EncodeFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_EncodeFinal_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_EncodeFinal');
    {$ifend}
  end;


  EVP_EncodeBlock := LoadLibFunction(ADllHandle, EVP_EncodeBlock_procname);
  FuncLoadError := not assigned(EVP_EncodeBlock);
  if FuncLoadError then
  begin
    {$if not defined(EVP_EncodeBlock_allownil)}
    EVP_EncodeBlock := ERR_EVP_EncodeBlock;
    {$ifend}
    {$if declared(EVP_EncodeBlock_introduced)}
    if LibVersion < EVP_EncodeBlock_introduced then
    begin
      {$if declared(FC_EVP_EncodeBlock)}
      EVP_EncodeBlock := FC_EVP_EncodeBlock;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_EncodeBlock_removed)}
    if EVP_EncodeBlock_removed <= LibVersion then
    begin
      {$if declared(_EVP_EncodeBlock)}
      EVP_EncodeBlock := _EVP_EncodeBlock;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_EncodeBlock_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_EncodeBlock');
    {$ifend}
  end;


  EVP_DecodeInit := LoadLibFunction(ADllHandle, EVP_DecodeInit_procname);
  FuncLoadError := not assigned(EVP_DecodeInit);
  if FuncLoadError then
  begin
    {$if not defined(EVP_DecodeInit_allownil)}
    EVP_DecodeInit := ERR_EVP_DecodeInit;
    {$ifend}
    {$if declared(EVP_DecodeInit_introduced)}
    if LibVersion < EVP_DecodeInit_introduced then
    begin
      {$if declared(FC_EVP_DecodeInit)}
      EVP_DecodeInit := FC_EVP_DecodeInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_DecodeInit_removed)}
    if EVP_DecodeInit_removed <= LibVersion then
    begin
      {$if declared(_EVP_DecodeInit)}
      EVP_DecodeInit := _EVP_DecodeInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_DecodeInit_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_DecodeInit');
    {$ifend}
  end;


  EVP_DecodeUpdate := LoadLibFunction(ADllHandle, EVP_DecodeUpdate_procname);
  FuncLoadError := not assigned(EVP_DecodeUpdate);
  if FuncLoadError then
  begin
    {$if not defined(EVP_DecodeUpdate_allownil)}
    EVP_DecodeUpdate := ERR_EVP_DecodeUpdate;
    {$ifend}
    {$if declared(EVP_DecodeUpdate_introduced)}
    if LibVersion < EVP_DecodeUpdate_introduced then
    begin
      {$if declared(FC_EVP_DecodeUpdate)}
      EVP_DecodeUpdate := FC_EVP_DecodeUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_DecodeUpdate_removed)}
    if EVP_DecodeUpdate_removed <= LibVersion then
    begin
      {$if declared(_EVP_DecodeUpdate)}
      EVP_DecodeUpdate := _EVP_DecodeUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_DecodeUpdate_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_DecodeUpdate');
    {$ifend}
  end;


  EVP_DecodeFinal := LoadLibFunction(ADllHandle, EVP_DecodeFinal_procname);
  FuncLoadError := not assigned(EVP_DecodeFinal);
  if FuncLoadError then
  begin
    {$if not defined(EVP_DecodeFinal_allownil)}
    EVP_DecodeFinal := ERR_EVP_DecodeFinal;
    {$ifend}
    {$if declared(EVP_DecodeFinal_introduced)}
    if LibVersion < EVP_DecodeFinal_introduced then
    begin
      {$if declared(FC_EVP_DecodeFinal)}
      EVP_DecodeFinal := FC_EVP_DecodeFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_DecodeFinal_removed)}
    if EVP_DecodeFinal_removed <= LibVersion then
    begin
      {$if declared(_EVP_DecodeFinal)}
      EVP_DecodeFinal := _EVP_DecodeFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_DecodeFinal_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_DecodeFinal');
    {$ifend}
  end;


  EVP_DecodeBlock := LoadLibFunction(ADllHandle, EVP_DecodeBlock_procname);
  FuncLoadError := not assigned(EVP_DecodeBlock);
  if FuncLoadError then
  begin
    {$if not defined(EVP_DecodeBlock_allownil)}
    EVP_DecodeBlock := ERR_EVP_DecodeBlock;
    {$ifend}
    {$if declared(EVP_DecodeBlock_introduced)}
    if LibVersion < EVP_DecodeBlock_introduced then
    begin
      {$if declared(FC_EVP_DecodeBlock)}
      EVP_DecodeBlock := FC_EVP_DecodeBlock;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_DecodeBlock_removed)}
    if EVP_DecodeBlock_removed <= LibVersion then
    begin
      {$if declared(_EVP_DecodeBlock)}
      EVP_DecodeBlock := _EVP_DecodeBlock;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_DecodeBlock_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_DecodeBlock');
    {$ifend}
  end;


  EVP_CIPHER_fetch := LoadLibFunction(ADllHandle, EVP_CIPHER_fetch_procname);
  FuncLoadError := not assigned(EVP_CIPHER_fetch);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_fetch_allownil)}
    EVP_CIPHER_fetch := ERR_EVP_CIPHER_fetch;
    {$ifend}
    {$if declared(EVP_CIPHER_fetch_introduced)}
    if LibVersion < EVP_CIPHER_fetch_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_fetch)}
      EVP_CIPHER_fetch := FC_EVP_CIPHER_fetch;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_fetch_removed)}
    if EVP_CIPHER_fetch_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_fetch)}
      EVP_CIPHER_fetch := _EVP_CIPHER_fetch;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_fetch_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_fetch');
    {$ifend}
  end;


  EVP_CIPHER_free := LoadLibFunction(ADllHandle, EVP_CIPHER_free_procname);
  FuncLoadError := not assigned(EVP_CIPHER_free);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_free_allownil)}
    EVP_CIPHER_free := ERR_EVP_CIPHER_free;
    {$ifend}
    {$if declared(EVP_CIPHER_free_introduced)}
    if LibVersion < EVP_CIPHER_free_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_free)}
      EVP_CIPHER_free := FC_EVP_CIPHER_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_free_removed)}
    if EVP_CIPHER_free_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_free)}
      EVP_CIPHER_free := _EVP_CIPHER_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_free_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_free');
    {$ifend}
  end;


  EVP_CIPHER_CTX_new := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_new_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_new);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_new_allownil)}
    EVP_CIPHER_CTX_new := ERR_EVP_CIPHER_CTX_new;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_new_introduced)}
    if LibVersion < EVP_CIPHER_CTX_new_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_new)}
      EVP_CIPHER_CTX_new := FC_EVP_CIPHER_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_new_removed)}
    if EVP_CIPHER_CTX_new_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_new)}
      EVP_CIPHER_CTX_new := _EVP_CIPHER_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_new');
    {$ifend}
  end;


  EVP_CIPHER_CTX_reset := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_reset_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_reset);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_reset_allownil)}
    EVP_CIPHER_CTX_reset := ERR_EVP_CIPHER_CTX_reset;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_reset_introduced)}
    if LibVersion < EVP_CIPHER_CTX_reset_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_reset)}
      EVP_CIPHER_CTX_reset := FC_EVP_CIPHER_CTX_reset;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_reset_removed)}
    if EVP_CIPHER_CTX_reset_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_reset)}
      EVP_CIPHER_CTX_reset := _EVP_CIPHER_CTX_reset;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_reset_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_reset');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_CIPHER_CTX_free := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_free_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_free);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_free_allownil)}
    EVP_CIPHER_CTX_free := ERR_EVP_CIPHER_CTX_free;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_free_introduced)}
    if LibVersion < EVP_CIPHER_CTX_free_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_free)}
      EVP_CIPHER_CTX_free := FC_EVP_CIPHER_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_free_removed)}
    if EVP_CIPHER_CTX_free_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_free)}
      EVP_CIPHER_CTX_free := _EVP_CIPHER_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_free');
    {$ifend}
  end;


  EVP_CIPHER_CTX_set_key_length := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_set_key_length_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_set_key_length);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_set_key_length_allownil)}
    EVP_CIPHER_CTX_set_key_length := ERR_EVP_CIPHER_CTX_set_key_length;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_set_key_length_introduced)}
    if LibVersion < EVP_CIPHER_CTX_set_key_length_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_set_key_length)}
      EVP_CIPHER_CTX_set_key_length := FC_EVP_CIPHER_CTX_set_key_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_set_key_length_removed)}
    if EVP_CIPHER_CTX_set_key_length_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_set_key_length)}
      EVP_CIPHER_CTX_set_key_length := _EVP_CIPHER_CTX_set_key_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_set_key_length_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_set_key_length');
    {$ifend}
  end;


  EVP_CIPHER_CTX_set_padding := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_set_padding_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_set_padding);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_set_padding_allownil)}
    EVP_CIPHER_CTX_set_padding := ERR_EVP_CIPHER_CTX_set_padding;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_set_padding_introduced)}
    if LibVersion < EVP_CIPHER_CTX_set_padding_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_set_padding)}
      EVP_CIPHER_CTX_set_padding := FC_EVP_CIPHER_CTX_set_padding;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_set_padding_removed)}
    if EVP_CIPHER_CTX_set_padding_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_set_padding)}
      EVP_CIPHER_CTX_set_padding := _EVP_CIPHER_CTX_set_padding;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_set_padding_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_set_padding');
    {$ifend}
  end;


  EVP_CIPHER_CTX_ctrl := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_ctrl_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_ctrl_allownil)}
    EVP_CIPHER_CTX_ctrl := ERR_EVP_CIPHER_CTX_ctrl;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_ctrl_introduced)}
    if LibVersion < EVP_CIPHER_CTX_ctrl_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_ctrl)}
      EVP_CIPHER_CTX_ctrl := FC_EVP_CIPHER_CTX_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_ctrl_removed)}
    if EVP_CIPHER_CTX_ctrl_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_ctrl)}
      EVP_CIPHER_CTX_ctrl := _EVP_CIPHER_CTX_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_ctrl');
    {$ifend}
  end;


  EVP_CIPHER_CTX_rand_key := LoadLibFunction(ADllHandle, EVP_CIPHER_CTX_rand_key_procname);
  FuncLoadError := not assigned(EVP_CIPHER_CTX_rand_key);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_CTX_rand_key_allownil)}
    EVP_CIPHER_CTX_rand_key := ERR_EVP_CIPHER_CTX_rand_key;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_rand_key_introduced)}
    if LibVersion < EVP_CIPHER_CTX_rand_key_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_CTX_rand_key)}
      EVP_CIPHER_CTX_rand_key := FC_EVP_CIPHER_CTX_rand_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_CTX_rand_key_removed)}
    if EVP_CIPHER_CTX_rand_key_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_CTX_rand_key)}
      EVP_CIPHER_CTX_rand_key := _EVP_CIPHER_CTX_rand_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_CTX_rand_key_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_rand_key');
    {$ifend}
  end;


  BIO_f_md := LoadLibFunction(ADllHandle, BIO_f_md_procname);
  FuncLoadError := not assigned(BIO_f_md);
  if FuncLoadError then
  begin
    {$if not defined(BIO_f_md_allownil)}
    BIO_f_md := ERR_BIO_f_md;
    {$ifend}
    {$if declared(BIO_f_md_introduced)}
    if LibVersion < BIO_f_md_introduced then
    begin
      {$if declared(FC_BIO_f_md)}
      BIO_f_md := FC_BIO_f_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_f_md_removed)}
    if BIO_f_md_removed <= LibVersion then
    begin
      {$if declared(_BIO_f_md)}
      BIO_f_md := _BIO_f_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_f_md_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_f_md');
    {$ifend}
  end;


  BIO_f_base64 := LoadLibFunction(ADllHandle, BIO_f_base64_procname);
  FuncLoadError := not assigned(BIO_f_base64);
  if FuncLoadError then
  begin
    {$if not defined(BIO_f_base64_allownil)}
    BIO_f_base64 := ERR_BIO_f_base64;
    {$ifend}
    {$if declared(BIO_f_base64_introduced)}
    if LibVersion < BIO_f_base64_introduced then
    begin
      {$if declared(FC_BIO_f_base64)}
      BIO_f_base64 := FC_BIO_f_base64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_f_base64_removed)}
    if BIO_f_base64_removed <= LibVersion then
    begin
      {$if declared(_BIO_f_base64)}
      BIO_f_base64 := _BIO_f_base64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_f_base64_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_f_base64');
    {$ifend}
  end;


  BIO_f_cipher := LoadLibFunction(ADllHandle, BIO_f_cipher_procname);
  FuncLoadError := not assigned(BIO_f_cipher);
  if FuncLoadError then
  begin
    {$if not defined(BIO_f_cipher_allownil)}
    BIO_f_cipher := ERR_BIO_f_cipher;
    {$ifend}
    {$if declared(BIO_f_cipher_introduced)}
    if LibVersion < BIO_f_cipher_introduced then
    begin
      {$if declared(FC_BIO_f_cipher)}
      BIO_f_cipher := FC_BIO_f_cipher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_f_cipher_removed)}
    if BIO_f_cipher_removed <= LibVersion then
    begin
      {$if declared(_BIO_f_cipher)}
      BIO_f_cipher := _BIO_f_cipher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_f_cipher_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_f_cipher');
    {$ifend}
  end;


  BIO_f_reliable := LoadLibFunction(ADllHandle, BIO_f_reliable_procname);
  FuncLoadError := not assigned(BIO_f_reliable);
  if FuncLoadError then
  begin
    {$if not defined(BIO_f_reliable_allownil)}
    BIO_f_reliable := ERR_BIO_f_reliable;
    {$ifend}
    {$if declared(BIO_f_reliable_introduced)}
    if LibVersion < BIO_f_reliable_introduced then
    begin
      {$if declared(FC_BIO_f_reliable)}
      BIO_f_reliable := FC_BIO_f_reliable;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_f_reliable_removed)}
    if BIO_f_reliable_removed <= LibVersion then
    begin
      {$if declared(_BIO_f_reliable)}
      BIO_f_reliable := _BIO_f_reliable;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_f_reliable_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_f_reliable');
    {$ifend}
  end;


  BIO_set_cipher := LoadLibFunction(ADllHandle, BIO_set_cipher_procname);
  FuncLoadError := not assigned(BIO_set_cipher);
  if FuncLoadError then
  begin
    {$if not defined(BIO_set_cipher_allownil)}
    BIO_set_cipher := ERR_BIO_set_cipher;
    {$ifend}
    {$if declared(BIO_set_cipher_introduced)}
    if LibVersion < BIO_set_cipher_introduced then
    begin
      {$if declared(FC_BIO_set_cipher)}
      BIO_set_cipher := FC_BIO_set_cipher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_set_cipher_removed)}
    if BIO_set_cipher_removed <= LibVersion then
    begin
      {$if declared(_BIO_set_cipher)}
      BIO_set_cipher := _BIO_set_cipher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_set_cipher_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_set_cipher');
    {$ifend}
  end;


  EVP_md_null := LoadLibFunction(ADllHandle, EVP_md_null_procname);
  FuncLoadError := not assigned(EVP_md_null);
  if FuncLoadError then
  begin
    {$if not defined(EVP_md_null_allownil)}
    EVP_md_null := ERR_EVP_md_null;
    {$ifend}
    {$if declared(EVP_md_null_introduced)}
    if LibVersion < EVP_md_null_introduced then
    begin
      {$if declared(FC_EVP_md_null)}
      EVP_md_null := FC_EVP_md_null;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_md_null_removed)}
    if EVP_md_null_removed <= LibVersion then
    begin
      {$if declared(_EVP_md_null)}
      EVP_md_null := _EVP_md_null;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_md_null_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_md_null');
    {$ifend}
  end;


  EVP_md2 := LoadLibFunction(ADllHandle, EVP_md2_procname);
  FuncLoadError := not assigned(EVP_md2);
  if FuncLoadError then
  begin
    {$if not defined(EVP_md2_allownil)}
    EVP_md2 := ERR_EVP_md2;
    {$ifend}
    {$if declared(EVP_md2_introduced)}
    if LibVersion < EVP_md2_introduced then
    begin
      {$if declared(FC_EVP_md2)}
      EVP_md2 := FC_EVP_md2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_md2_removed)}
    if EVP_md2_removed <= LibVersion then
    begin
      {$if declared(_EVP_md2)}
      EVP_md2 := _EVP_md2;
      {$ifend}
      {$if not defined(EVP_md2_allownil)}
      FuncLoadError := false;
      {$ifend}
    end;
    {$ifend}
    {$if not defined(EVP_md2_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_md2');
    {$ifend}
  end;  //PALOFF - Empty begin/end-blocks

 {removed 1.1.0 allow_nil}
  EVP_md4 := LoadLibFunction(ADllHandle, EVP_md4_procname);
  FuncLoadError := not assigned(EVP_md4);
  if FuncLoadError then
  begin
    {$if not defined(EVP_md4_allownil)}
    EVP_md4 := ERR_EVP_md4;
    {$ifend}
    {$if declared(EVP_md4_introduced)}
    if LibVersion < EVP_md4_introduced then
    begin
      {$if declared(FC_EVP_md4)}
      EVP_md4 := FC_EVP_md4;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_md4_removed)}
    if EVP_md4_removed <= LibVersion then
    begin
      {$if declared(_EVP_md4)}
      EVP_md4 := _EVP_md4;
      {$ifend}
      {$if not defined(EVP_md4_allownil)}
      FuncLoadError := false;
      {$ifend}
    end;
    {$ifend}
    {$if not defined(EVP_md4_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_md4');
    {$ifend}
  end;    //PALOFF - Empty begin/end-blocks

 {removed 1.1.0 allow_nil}
  EVP_md5 := LoadLibFunction(ADllHandle, EVP_md5_procname);
  FuncLoadError := not assigned(EVP_md5);
  if FuncLoadError then
  begin
    {$if not defined(EVP_md5_allownil)}
    EVP_md5 := ERR_EVP_md5;
    {$ifend}
    {$if declared(EVP_md5_introduced)}
    if LibVersion < EVP_md5_introduced then
    begin
      {$if declared(FC_EVP_md5)}
      EVP_md5 := FC_EVP_md5;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_md5_removed)}
    if EVP_md5_removed <= LibVersion then
    begin
      {$if declared(_EVP_md5)}
      EVP_md5 := _EVP_md5;
      {$ifend}
      {$if not defined(EVP_md5_allownil)}
      FuncLoadError := false;
      {$ifend}
    end;
    {$ifend}
    {$if not defined(EVP_md5_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_md5');
    {$ifend}
  end;  //PALOFF - Empty begin/end-blocks

 {removed 1.1.0 allow_nil}
  EVP_md5_sha1 := LoadLibFunction(ADllHandle, EVP_md5_sha1_procname);
  FuncLoadError := not assigned(EVP_md5_sha1);
  if FuncLoadError then
  begin
    {$if not defined(EVP_md5_sha1_allownil)}
    EVP_md5_sha1 := ERR_EVP_md5_sha1;
    {$ifend}
    {$if declared(EVP_md5_sha1_introduced)}
    if LibVersion < EVP_md5_sha1_introduced then
    begin
      {$if declared(FC_EVP_md5_sha1)}
      EVP_md5_sha1 := FC_EVP_md5_sha1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_md5_sha1_removed)}
    if EVP_md5_sha1_removed <= LibVersion then
    begin
      {$if declared(_EVP_md5_sha1)}
      EVP_md5_sha1 := _EVP_md5_sha1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_md5_sha1_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_md5_sha1');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_sha1 := LoadLibFunction(ADllHandle, EVP_sha1_procname);
  FuncLoadError := not assigned(EVP_sha1);
  if FuncLoadError then
  begin
    {$if not defined(EVP_sha1_allownil)}
    EVP_sha1 := ERR_EVP_sha1;
    {$ifend}
    {$if declared(EVP_sha1_introduced)}
    if LibVersion < EVP_sha1_introduced then
    begin
      {$if declared(FC_EVP_sha1)}
      EVP_sha1 := FC_EVP_sha1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_sha1_removed)}
    if EVP_sha1_removed <= LibVersion then
    begin
      {$if declared(_EVP_sha1)}
      EVP_sha1 := _EVP_sha1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_sha1_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_sha1');
    {$ifend}
  end;


  EVP_sha224 := LoadLibFunction(ADllHandle, EVP_sha224_procname);
  FuncLoadError := not assigned(EVP_sha224);
  if FuncLoadError then
  begin
    {$if not defined(EVP_sha224_allownil)}
    EVP_sha224 := ERR_EVP_sha224;
    {$ifend}
    {$if declared(EVP_sha224_introduced)}
    if LibVersion < EVP_sha224_introduced then
    begin
      {$if declared(FC_EVP_sha224)}
      EVP_sha224 := FC_EVP_sha224;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_sha224_removed)}
    if EVP_sha224_removed <= LibVersion then
    begin
      {$if declared(_EVP_sha224)}
      EVP_sha224 := _EVP_sha224;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_sha224_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_sha224');
    {$ifend}
  end;


  EVP_sha256 := LoadLibFunction(ADllHandle, EVP_sha256_procname);
  FuncLoadError := not assigned(EVP_sha256);
  if FuncLoadError then
  begin
    {$if not defined(EVP_sha256_allownil)}
    EVP_sha256 := ERR_EVP_sha256;
    {$ifend}
    {$if declared(EVP_sha256_introduced)}
    if LibVersion < EVP_sha256_introduced then
    begin
      {$if declared(FC_EVP_sha256)}
      EVP_sha256 := FC_EVP_sha256;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_sha256_removed)}
    if EVP_sha256_removed <= LibVersion then
    begin
      {$if declared(_EVP_sha256)}
      EVP_sha256 := _EVP_sha256;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_sha256_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_sha256');
    {$ifend}
  end;


  EVP_sha384 := LoadLibFunction(ADllHandle, EVP_sha384_procname);
  FuncLoadError := not assigned(EVP_sha384);
  if FuncLoadError then
  begin
    {$if not defined(EVP_sha384_allownil)}
    EVP_sha384 := ERR_EVP_sha384;
    {$ifend}
    {$if declared(EVP_sha384_introduced)}
    if LibVersion < EVP_sha384_introduced then
    begin
      {$if declared(FC_EVP_sha384)}
      EVP_sha384 := FC_EVP_sha384;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_sha384_removed)}
    if EVP_sha384_removed <= LibVersion then
    begin
      {$if declared(_EVP_sha384)}
      EVP_sha384 := _EVP_sha384;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_sha384_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_sha384');
    {$ifend}
  end;


  EVP_sha512 := LoadLibFunction(ADllHandle, EVP_sha512_procname);
  FuncLoadError := not assigned(EVP_sha512);
  if FuncLoadError then
  begin
    {$if not defined(EVP_sha512_allownil)}
    EVP_sha512 := ERR_EVP_sha512;
    {$ifend}
    {$if declared(EVP_sha512_introduced)}
    if LibVersion < EVP_sha512_introduced then
    begin
      {$if declared(FC_EVP_sha512)}
      EVP_sha512 := FC_EVP_sha512;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_sha512_removed)}
    if EVP_sha512_removed <= LibVersion then
    begin
      {$if declared(_EVP_sha512)}
      EVP_sha512 := _EVP_sha512;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_sha512_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_sha512');
    {$ifend}
  end;


  EVP_sha512_224 := LoadLibFunction(ADllHandle, EVP_sha512_224_procname);
  FuncLoadError := not assigned(EVP_sha512_224);
  if FuncLoadError then
  begin
    {$if not defined(EVP_sha512_224_allownil)}
    EVP_sha512_224 := ERR_EVP_sha512_224;
    {$ifend}
    {$if declared(EVP_sha512_224_introduced)}
    if LibVersion < EVP_sha512_224_introduced then
    begin
      {$if declared(FC_EVP_sha512_224)}
      EVP_sha512_224 := FC_EVP_sha512_224;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_sha512_224_removed)}
    if EVP_sha512_224_removed <= LibVersion then
    begin
      {$if declared(_EVP_sha512_224)}
      EVP_sha512_224 := _EVP_sha512_224;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_sha512_224_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_sha512_224');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_sha512_256 := LoadLibFunction(ADllHandle, EVP_sha512_256_procname);
  FuncLoadError := not assigned(EVP_sha512_256);
  if FuncLoadError then
  begin
    {$if not defined(EVP_sha512_256_allownil)}
    EVP_sha512_256 := ERR_EVP_sha512_256;
    {$ifend}
    {$if declared(EVP_sha512_256_introduced)}
    if LibVersion < EVP_sha512_256_introduced then
    begin
      {$if declared(FC_EVP_sha512_256)}
      EVP_sha512_256 := FC_EVP_sha512_256;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_sha512_256_removed)}
    if EVP_sha512_256_removed <= LibVersion then
    begin
      {$if declared(_EVP_sha512_256)}
      EVP_sha512_256 := _EVP_sha512_256;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_sha512_256_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_sha512_256');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_sha3_224 := LoadLibFunction(ADllHandle, EVP_sha3_224_procname);
  FuncLoadError := not assigned(EVP_sha3_224);
  if FuncLoadError then
  begin
    {$if not defined(EVP_sha3_224_allownil)}
    EVP_sha3_224 := ERR_EVP_sha3_224;
    {$ifend}
    {$if declared(EVP_sha3_224_introduced)}
    if LibVersion < EVP_sha3_224_introduced then
    begin
      {$if declared(FC_EVP_sha3_224)}
      EVP_sha3_224 := FC_EVP_sha3_224;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_sha3_224_removed)}
    if EVP_sha3_224_removed <= LibVersion then
    begin
      {$if declared(_EVP_sha3_224)}
      EVP_sha3_224 := _EVP_sha3_224;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_sha3_224_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_sha3_224');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_sha3_256 := LoadLibFunction(ADllHandle, EVP_sha3_256_procname);
  FuncLoadError := not assigned(EVP_sha3_256);
  if FuncLoadError then
  begin
    {$if not defined(EVP_sha3_256_allownil)}
    EVP_sha3_256 := ERR_EVP_sha3_256;
    {$ifend}
    {$if declared(EVP_sha3_256_introduced)}
    if LibVersion < EVP_sha3_256_introduced then
    begin
      {$if declared(FC_EVP_sha3_256)}
      EVP_sha3_256 := FC_EVP_sha3_256;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_sha3_256_removed)}
    if EVP_sha3_256_removed <= LibVersion then
    begin
      {$if declared(_EVP_sha3_256)}
      EVP_sha3_256 := _EVP_sha3_256;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_sha3_256_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_sha3_256');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_sha3_384 := LoadLibFunction(ADllHandle, EVP_sha3_384_procname);
  FuncLoadError := not assigned(EVP_sha3_384);
  if FuncLoadError then
  begin
    {$if not defined(EVP_sha3_384_allownil)}
    EVP_sha3_384 := ERR_EVP_sha3_384;
    {$ifend}
    {$if declared(EVP_sha3_384_introduced)}
    if LibVersion < EVP_sha3_384_introduced then
    begin
      {$if declared(FC_EVP_sha3_384)}
      EVP_sha3_384 := FC_EVP_sha3_384;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_sha3_384_removed)}
    if EVP_sha3_384_removed <= LibVersion then
    begin
      {$if declared(_EVP_sha3_384)}
      EVP_sha3_384 := _EVP_sha3_384;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_sha3_384_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_sha3_384');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_sha3_512 := LoadLibFunction(ADllHandle, EVP_sha3_512_procname);
  FuncLoadError := not assigned(EVP_sha3_512);
  if FuncLoadError then
  begin
    {$if not defined(EVP_sha3_512_allownil)}
    EVP_sha3_512 := ERR_EVP_sha3_512;
    {$ifend}
    {$if declared(EVP_sha3_512_introduced)}
    if LibVersion < EVP_sha3_512_introduced then
    begin
      {$if declared(FC_EVP_sha3_512)}
      EVP_sha3_512 := FC_EVP_sha3_512;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_sha3_512_removed)}
    if EVP_sha3_512_removed <= LibVersion then
    begin
      {$if declared(_EVP_sha3_512)}
      EVP_sha3_512 := _EVP_sha3_512;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_sha3_512_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_sha3_512');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_shake128 := LoadLibFunction(ADllHandle, EVP_shake128_procname);
  FuncLoadError := not assigned(EVP_shake128);
  if FuncLoadError then
  begin
    {$if not defined(EVP_shake128_allownil)}
    EVP_shake128 := ERR_EVP_shake128;
    {$ifend}
    {$if declared(EVP_shake128_introduced)}
    if LibVersion < EVP_shake128_introduced then
    begin
      {$if declared(FC_EVP_shake128)}
      EVP_shake128 := FC_EVP_shake128;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_shake128_removed)}
    if EVP_shake128_removed <= LibVersion then
    begin
      {$if declared(_EVP_shake128)}
      EVP_shake128 := _EVP_shake128;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_shake128_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_shake128');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_shake256 := LoadLibFunction(ADllHandle, EVP_shake256_procname);
  FuncLoadError := not assigned(EVP_shake256);
  if FuncLoadError then
  begin
    {$if not defined(EVP_shake256_allownil)}
    EVP_shake256 := ERR_EVP_shake256;
    {$ifend}
    {$if declared(EVP_shake256_introduced)}
    if LibVersion < EVP_shake256_introduced then
    begin
      {$if declared(FC_EVP_shake256)}
      EVP_shake256 := FC_EVP_shake256;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_shake256_removed)}
    if EVP_shake256_removed <= LibVersion then
    begin
      {$if declared(_EVP_shake256)}
      EVP_shake256 := _EVP_shake256;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_shake256_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_shake256');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_enc_null := LoadLibFunction(ADllHandle, EVP_enc_null_procname);
  FuncLoadError := not assigned(EVP_enc_null);
  if FuncLoadError then
  begin
    {$if not defined(EVP_enc_null_allownil)}
    EVP_enc_null := ERR_EVP_enc_null;
    {$ifend}
    {$if declared(EVP_enc_null_introduced)}
    if LibVersion < EVP_enc_null_introduced then
    begin
      {$if declared(FC_EVP_enc_null)}
      EVP_enc_null := FC_EVP_enc_null;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_enc_null_removed)}
    if EVP_enc_null_removed <= LibVersion then
    begin
      {$if declared(_EVP_enc_null)}
      EVP_enc_null := _EVP_enc_null;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_enc_null_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_enc_null');
    {$ifend}
  end;


  EVP_des_ecb := LoadLibFunction(ADllHandle, EVP_des_ecb_procname);
  FuncLoadError := not assigned(EVP_des_ecb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_des_ecb_allownil)}
    EVP_des_ecb := ERR_EVP_des_ecb;
    {$ifend}
    {$if declared(EVP_des_ecb_introduced)}
    if LibVersion < EVP_des_ecb_introduced then
    begin
      {$if declared(FC_EVP_des_ecb)}
      EVP_des_ecb := FC_EVP_des_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_des_ecb_removed)}
    if EVP_des_ecb_removed <= LibVersion then
    begin
      {$if declared(_EVP_des_ecb)}
      EVP_des_ecb := _EVP_des_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_des_ecb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_des_ecb');
    {$ifend}
  end;


  EVP_des_ede := LoadLibFunction(ADllHandle, EVP_des_ede_procname);
  FuncLoadError := not assigned(EVP_des_ede);
  if FuncLoadError then
  begin
    {$if not defined(EVP_des_ede_allownil)}
    EVP_des_ede := ERR_EVP_des_ede;
    {$ifend}
    {$if declared(EVP_des_ede_introduced)}
    if LibVersion < EVP_des_ede_introduced then
    begin
      {$if declared(FC_EVP_des_ede)}
      EVP_des_ede := FC_EVP_des_ede;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_des_ede_removed)}
    if EVP_des_ede_removed <= LibVersion then
    begin
      {$if declared(_EVP_des_ede)}
      EVP_des_ede := _EVP_des_ede;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_des_ede_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_des_ede');
    {$ifend}
  end;


  EVP_des_ede3 := LoadLibFunction(ADllHandle, EVP_des_ede3_procname);
  FuncLoadError := not assigned(EVP_des_ede3);
  if FuncLoadError then
  begin
    {$if not defined(EVP_des_ede3_allownil)}
    EVP_des_ede3 := ERR_EVP_des_ede3;
    {$ifend}
    {$if declared(EVP_des_ede3_introduced)}
    if LibVersion < EVP_des_ede3_introduced then
    begin
      {$if declared(FC_EVP_des_ede3)}
      EVP_des_ede3 := FC_EVP_des_ede3;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_des_ede3_removed)}
    if EVP_des_ede3_removed <= LibVersion then
    begin
      {$if declared(_EVP_des_ede3)}
      EVP_des_ede3 := _EVP_des_ede3;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_des_ede3_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_des_ede3');
    {$ifend}
  end;


  EVP_des_ede_ecb := LoadLibFunction(ADllHandle, EVP_des_ede_ecb_procname);
  FuncLoadError := not assigned(EVP_des_ede_ecb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_des_ede_ecb_allownil)}
    EVP_des_ede_ecb := ERR_EVP_des_ede_ecb;
    {$ifend}
    {$if declared(EVP_des_ede_ecb_introduced)}
    if LibVersion < EVP_des_ede_ecb_introduced then
    begin
      {$if declared(FC_EVP_des_ede_ecb)}
      EVP_des_ede_ecb := FC_EVP_des_ede_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_des_ede_ecb_removed)}
    if EVP_des_ede_ecb_removed <= LibVersion then
    begin
      {$if declared(_EVP_des_ede_ecb)}
      EVP_des_ede_ecb := _EVP_des_ede_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_des_ede_ecb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_des_ede_ecb');
    {$ifend}
  end;


  EVP_des_ede3_ecb := LoadLibFunction(ADllHandle, EVP_des_ede3_ecb_procname);
  FuncLoadError := not assigned(EVP_des_ede3_ecb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_des_ede3_ecb_allownil)}
    EVP_des_ede3_ecb := ERR_EVP_des_ede3_ecb;
    {$ifend}
    {$if declared(EVP_des_ede3_ecb_introduced)}
    if LibVersion < EVP_des_ede3_ecb_introduced then
    begin
      {$if declared(FC_EVP_des_ede3_ecb)}
      EVP_des_ede3_ecb := FC_EVP_des_ede3_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_des_ede3_ecb_removed)}
    if EVP_des_ede3_ecb_removed <= LibVersion then
    begin
      {$if declared(_EVP_des_ede3_ecb)}
      EVP_des_ede3_ecb := _EVP_des_ede3_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_des_ede3_ecb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_des_ede3_ecb');
    {$ifend}
  end;


  EVP_des_cfb64 := LoadLibFunction(ADllHandle, EVP_des_cfb64_procname);
  FuncLoadError := not assigned(EVP_des_cfb64);
  if FuncLoadError then
  begin
    {$if not defined(EVP_des_cfb64_allownil)}
    EVP_des_cfb64 := ERR_EVP_des_cfb64;
    {$ifend}
    {$if declared(EVP_des_cfb64_introduced)}
    if LibVersion < EVP_des_cfb64_introduced then
    begin
      {$if declared(FC_EVP_des_cfb64)}
      EVP_des_cfb64 := FC_EVP_des_cfb64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_des_cfb64_removed)}
    if EVP_des_cfb64_removed <= LibVersion then
    begin
      {$if declared(_EVP_des_cfb64)}
      EVP_des_cfb64 := _EVP_des_cfb64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_des_cfb64_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_des_cfb64');
    {$ifend}
  end;


  EVP_des_cfb1 := LoadLibFunction(ADllHandle, EVP_des_cfb1_procname);
  FuncLoadError := not assigned(EVP_des_cfb1);
  if FuncLoadError then
  begin
    {$if not defined(EVP_des_cfb1_allownil)}
    EVP_des_cfb1 := ERR_EVP_des_cfb1;
    {$ifend}
    {$if declared(EVP_des_cfb1_introduced)}
    if LibVersion < EVP_des_cfb1_introduced then
    begin
      {$if declared(FC_EVP_des_cfb1)}
      EVP_des_cfb1 := FC_EVP_des_cfb1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_des_cfb1_removed)}
    if EVP_des_cfb1_removed <= LibVersion then
    begin
      {$if declared(_EVP_des_cfb1)}
      EVP_des_cfb1 := _EVP_des_cfb1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_des_cfb1_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_des_cfb1');
    {$ifend}
  end;


  EVP_des_cfb8 := LoadLibFunction(ADllHandle, EVP_des_cfb8_procname);
  FuncLoadError := not assigned(EVP_des_cfb8);
  if FuncLoadError then
  begin
    {$if not defined(EVP_des_cfb8_allownil)}
    EVP_des_cfb8 := ERR_EVP_des_cfb8;
    {$ifend}
    {$if declared(EVP_des_cfb8_introduced)}
    if LibVersion < EVP_des_cfb8_introduced then
    begin
      {$if declared(FC_EVP_des_cfb8)}
      EVP_des_cfb8 := FC_EVP_des_cfb8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_des_cfb8_removed)}
    if EVP_des_cfb8_removed <= LibVersion then
    begin
      {$if declared(_EVP_des_cfb8)}
      EVP_des_cfb8 := _EVP_des_cfb8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_des_cfb8_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_des_cfb8');
    {$ifend}
  end;


  EVP_des_ede_cfb64 := LoadLibFunction(ADllHandle, EVP_des_ede_cfb64_procname);
  FuncLoadError := not assigned(EVP_des_ede_cfb64);
  if FuncLoadError then
  begin
    {$if not defined(EVP_des_ede_cfb64_allownil)}
    EVP_des_ede_cfb64 := ERR_EVP_des_ede_cfb64;
    {$ifend}
    {$if declared(EVP_des_ede_cfb64_introduced)}
    if LibVersion < EVP_des_ede_cfb64_introduced then
    begin
      {$if declared(FC_EVP_des_ede_cfb64)}
      EVP_des_ede_cfb64 := FC_EVP_des_ede_cfb64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_des_ede_cfb64_removed)}
    if EVP_des_ede_cfb64_removed <= LibVersion then
    begin
      {$if declared(_EVP_des_ede_cfb64)}
      EVP_des_ede_cfb64 := _EVP_des_ede_cfb64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_des_ede_cfb64_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_des_ede_cfb64');
    {$ifend}
  end;


  EVP_des_ede3_cfb64 := LoadLibFunction(ADllHandle, EVP_des_ede3_cfb64_procname);
  FuncLoadError := not assigned(EVP_des_ede3_cfb64);
  if FuncLoadError then
  begin
    {$if not defined(EVP_des_ede3_cfb64_allownil)}
    EVP_des_ede3_cfb64 := ERR_EVP_des_ede3_cfb64;
    {$ifend}
    {$if declared(EVP_des_ede3_cfb64_introduced)}
    if LibVersion < EVP_des_ede3_cfb64_introduced then
    begin
      {$if declared(FC_EVP_des_ede3_cfb64)}
      EVP_des_ede3_cfb64 := FC_EVP_des_ede3_cfb64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_des_ede3_cfb64_removed)}
    if EVP_des_ede3_cfb64_removed <= LibVersion then
    begin
      {$if declared(_EVP_des_ede3_cfb64)}
      EVP_des_ede3_cfb64 := _EVP_des_ede3_cfb64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_des_ede3_cfb64_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_des_ede3_cfb64');
    {$ifend}
  end;


  EVP_des_ede3_cfb1 := LoadLibFunction(ADllHandle, EVP_des_ede3_cfb1_procname);
  FuncLoadError := not assigned(EVP_des_ede3_cfb1);
  if FuncLoadError then
  begin
    {$if not defined(EVP_des_ede3_cfb1_allownil)}
    EVP_des_ede3_cfb1 := ERR_EVP_des_ede3_cfb1;
    {$ifend}
    {$if declared(EVP_des_ede3_cfb1_introduced)}
    if LibVersion < EVP_des_ede3_cfb1_introduced then
    begin
      {$if declared(FC_EVP_des_ede3_cfb1)}
      EVP_des_ede3_cfb1 := FC_EVP_des_ede3_cfb1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_des_ede3_cfb1_removed)}
    if EVP_des_ede3_cfb1_removed <= LibVersion then
    begin
      {$if declared(_EVP_des_ede3_cfb1)}
      EVP_des_ede3_cfb1 := _EVP_des_ede3_cfb1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_des_ede3_cfb1_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_des_ede3_cfb1');
    {$ifend}
  end;


  EVP_des_ede3_cfb8 := LoadLibFunction(ADllHandle, EVP_des_ede3_cfb8_procname);
  FuncLoadError := not assigned(EVP_des_ede3_cfb8);
  if FuncLoadError then
  begin
    {$if not defined(EVP_des_ede3_cfb8_allownil)}
    EVP_des_ede3_cfb8 := ERR_EVP_des_ede3_cfb8;
    {$ifend}
    {$if declared(EVP_des_ede3_cfb8_introduced)}
    if LibVersion < EVP_des_ede3_cfb8_introduced then
    begin
      {$if declared(FC_EVP_des_ede3_cfb8)}
      EVP_des_ede3_cfb8 := FC_EVP_des_ede3_cfb8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_des_ede3_cfb8_removed)}
    if EVP_des_ede3_cfb8_removed <= LibVersion then
    begin
      {$if declared(_EVP_des_ede3_cfb8)}
      EVP_des_ede3_cfb8 := _EVP_des_ede3_cfb8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_des_ede3_cfb8_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_des_ede3_cfb8');
    {$ifend}
  end;


  EVP_des_ofb := LoadLibFunction(ADllHandle, EVP_des_ofb_procname);
  FuncLoadError := not assigned(EVP_des_ofb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_des_ofb_allownil)}
    EVP_des_ofb := ERR_EVP_des_ofb;
    {$ifend}
    {$if declared(EVP_des_ofb_introduced)}
    if LibVersion < EVP_des_ofb_introduced then
    begin
      {$if declared(FC_EVP_des_ofb)}
      EVP_des_ofb := FC_EVP_des_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_des_ofb_removed)}
    if EVP_des_ofb_removed <= LibVersion then
    begin
      {$if declared(_EVP_des_ofb)}
      EVP_des_ofb := _EVP_des_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_des_ofb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_des_ofb');
    {$ifend}
  end;


  EVP_des_ede_ofb := LoadLibFunction(ADllHandle, EVP_des_ede_ofb_procname);
  FuncLoadError := not assigned(EVP_des_ede_ofb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_des_ede_ofb_allownil)}
    EVP_des_ede_ofb := ERR_EVP_des_ede_ofb;
    {$ifend}
    {$if declared(EVP_des_ede_ofb_introduced)}
    if LibVersion < EVP_des_ede_ofb_introduced then
    begin
      {$if declared(FC_EVP_des_ede_ofb)}
      EVP_des_ede_ofb := FC_EVP_des_ede_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_des_ede_ofb_removed)}
    if EVP_des_ede_ofb_removed <= LibVersion then
    begin
      {$if declared(_EVP_des_ede_ofb)}
      EVP_des_ede_ofb := _EVP_des_ede_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_des_ede_ofb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_des_ede_ofb');
    {$ifend}
  end;


  EVP_des_ede3_ofb := LoadLibFunction(ADllHandle, EVP_des_ede3_ofb_procname);
  FuncLoadError := not assigned(EVP_des_ede3_ofb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_des_ede3_ofb_allownil)}
    EVP_des_ede3_ofb := ERR_EVP_des_ede3_ofb;
    {$ifend}
    {$if declared(EVP_des_ede3_ofb_introduced)}
    if LibVersion < EVP_des_ede3_ofb_introduced then
    begin
      {$if declared(FC_EVP_des_ede3_ofb)}
      EVP_des_ede3_ofb := FC_EVP_des_ede3_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_des_ede3_ofb_removed)}
    if EVP_des_ede3_ofb_removed <= LibVersion then
    begin
      {$if declared(_EVP_des_ede3_ofb)}
      EVP_des_ede3_ofb := _EVP_des_ede3_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_des_ede3_ofb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_des_ede3_ofb');
    {$ifend}
  end;


  EVP_des_cbc := LoadLibFunction(ADllHandle, EVP_des_cbc_procname);
  FuncLoadError := not assigned(EVP_des_cbc);
  if FuncLoadError then
  begin
    {$if not defined(EVP_des_cbc_allownil)}
    EVP_des_cbc := ERR_EVP_des_cbc;
    {$ifend}
    {$if declared(EVP_des_cbc_introduced)}
    if LibVersion < EVP_des_cbc_introduced then
    begin
      {$if declared(FC_EVP_des_cbc)}
      EVP_des_cbc := FC_EVP_des_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_des_cbc_removed)}
    if EVP_des_cbc_removed <= LibVersion then
    begin
      {$if declared(_EVP_des_cbc)}
      EVP_des_cbc := _EVP_des_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_des_cbc_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_des_cbc');
    {$ifend}
  end;


  EVP_des_ede_cbc := LoadLibFunction(ADllHandle, EVP_des_ede_cbc_procname);
  FuncLoadError := not assigned(EVP_des_ede_cbc);
  if FuncLoadError then
  begin
    {$if not defined(EVP_des_ede_cbc_allownil)}
    EVP_des_ede_cbc := ERR_EVP_des_ede_cbc;
    {$ifend}
    {$if declared(EVP_des_ede_cbc_introduced)}
    if LibVersion < EVP_des_ede_cbc_introduced then
    begin
      {$if declared(FC_EVP_des_ede_cbc)}
      EVP_des_ede_cbc := FC_EVP_des_ede_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_des_ede_cbc_removed)}
    if EVP_des_ede_cbc_removed <= LibVersion then
    begin
      {$if declared(_EVP_des_ede_cbc)}
      EVP_des_ede_cbc := _EVP_des_ede_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_des_ede_cbc_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_des_ede_cbc');
    {$ifend}
  end;


  EVP_des_ede3_cbc := LoadLibFunction(ADllHandle, EVP_des_ede3_cbc_procname);
  FuncLoadError := not assigned(EVP_des_ede3_cbc);
  if FuncLoadError then
  begin
    {$if not defined(EVP_des_ede3_cbc_allownil)}
    EVP_des_ede3_cbc := ERR_EVP_des_ede3_cbc;
    {$ifend}
    {$if declared(EVP_des_ede3_cbc_introduced)}
    if LibVersion < EVP_des_ede3_cbc_introduced then
    begin
      {$if declared(FC_EVP_des_ede3_cbc)}
      EVP_des_ede3_cbc := FC_EVP_des_ede3_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_des_ede3_cbc_removed)}
    if EVP_des_ede3_cbc_removed <= LibVersion then
    begin
      {$if declared(_EVP_des_ede3_cbc)}
      EVP_des_ede3_cbc := _EVP_des_ede3_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_des_ede3_cbc_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_des_ede3_cbc');
    {$ifend}
  end;


  EVP_desx_cbc := LoadLibFunction(ADllHandle, EVP_desx_cbc_procname);
  FuncLoadError := not assigned(EVP_desx_cbc);
  if FuncLoadError then
  begin
    {$if not defined(EVP_desx_cbc_allownil)}
    EVP_desx_cbc := ERR_EVP_desx_cbc;
    {$ifend}
    {$if declared(EVP_desx_cbc_introduced)}
    if LibVersion < EVP_desx_cbc_introduced then
    begin
      {$if declared(FC_EVP_desx_cbc)}
      EVP_desx_cbc := FC_EVP_desx_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_desx_cbc_removed)}
    if EVP_desx_cbc_removed <= LibVersion then
    begin
      {$if declared(_EVP_desx_cbc)}
      EVP_desx_cbc := _EVP_desx_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_desx_cbc_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_desx_cbc');
    {$ifend}
  end;


  EVP_des_ede3_wrap := LoadLibFunction(ADllHandle, EVP_des_ede3_wrap_procname);
  FuncLoadError := not assigned(EVP_des_ede3_wrap);
  if FuncLoadError then
  begin
    {$if not defined(EVP_des_ede3_wrap_allownil)}
    EVP_des_ede3_wrap := ERR_EVP_des_ede3_wrap;
    {$ifend}
    {$if declared(EVP_des_ede3_wrap_introduced)}
    if LibVersion < EVP_des_ede3_wrap_introduced then
    begin
      {$if declared(FC_EVP_des_ede3_wrap)}
      EVP_des_ede3_wrap := FC_EVP_des_ede3_wrap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_des_ede3_wrap_removed)}
    if EVP_des_ede3_wrap_removed <= LibVersion then
    begin
      {$if declared(_EVP_des_ede3_wrap)}
      EVP_des_ede3_wrap := _EVP_des_ede3_wrap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_des_ede3_wrap_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_des_ede3_wrap');
    {$ifend}
  end;


  EVP_rc4 := LoadLibFunction(ADllHandle, EVP_rc4_procname);
  FuncLoadError := not assigned(EVP_rc4);
  if FuncLoadError then
  begin
    {$if not defined(EVP_rc4_allownil)}
    EVP_rc4 := ERR_EVP_rc4;
    {$ifend}
    {$if declared(EVP_rc4_introduced)}
    if LibVersion < EVP_rc4_introduced then
    begin
      {$if declared(FC_EVP_rc4)}
      EVP_rc4 := FC_EVP_rc4;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_rc4_removed)}
    if EVP_rc4_removed <= LibVersion then
    begin
      {$if declared(_EVP_rc4)}
      EVP_rc4 := _EVP_rc4;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_rc4_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_rc4');
    {$ifend}
  end;


  EVP_rc4_40 := LoadLibFunction(ADllHandle, EVP_rc4_40_procname);
  FuncLoadError := not assigned(EVP_rc4_40);
  if FuncLoadError then
  begin
    {$if not defined(EVP_rc4_40_allownil)}
    EVP_rc4_40 := ERR_EVP_rc4_40;
    {$ifend}
    {$if declared(EVP_rc4_40_introduced)}
    if LibVersion < EVP_rc4_40_introduced then
    begin
      {$if declared(FC_EVP_rc4_40)}
      EVP_rc4_40 := FC_EVP_rc4_40;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_rc4_40_removed)}
    if EVP_rc4_40_removed <= LibVersion then
    begin
      {$if declared(_EVP_rc4_40)}
      EVP_rc4_40 := _EVP_rc4_40;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_rc4_40_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_rc4_40');
    {$ifend}
  end;


  EVP_rc2_ecb := LoadLibFunction(ADllHandle, EVP_rc2_ecb_procname);
  FuncLoadError := not assigned(EVP_rc2_ecb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_rc2_ecb_allownil)}
    EVP_rc2_ecb := ERR_EVP_rc2_ecb;
    {$ifend}
    {$if declared(EVP_rc2_ecb_introduced)}
    if LibVersion < EVP_rc2_ecb_introduced then
    begin
      {$if declared(FC_EVP_rc2_ecb)}
      EVP_rc2_ecb := FC_EVP_rc2_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_rc2_ecb_removed)}
    if EVP_rc2_ecb_removed <= LibVersion then
    begin
      {$if declared(_EVP_rc2_ecb)}
      EVP_rc2_ecb := _EVP_rc2_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_rc2_ecb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_rc2_ecb');
    {$ifend}
  end;


  EVP_rc2_cbc := LoadLibFunction(ADllHandle, EVP_rc2_cbc_procname);
  FuncLoadError := not assigned(EVP_rc2_cbc);
  if FuncLoadError then
  begin
    {$if not defined(EVP_rc2_cbc_allownil)}
    EVP_rc2_cbc := ERR_EVP_rc2_cbc;
    {$ifend}
    {$if declared(EVP_rc2_cbc_introduced)}
    if LibVersion < EVP_rc2_cbc_introduced then
    begin
      {$if declared(FC_EVP_rc2_cbc)}
      EVP_rc2_cbc := FC_EVP_rc2_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_rc2_cbc_removed)}
    if EVP_rc2_cbc_removed <= LibVersion then
    begin
      {$if declared(_EVP_rc2_cbc)}
      EVP_rc2_cbc := _EVP_rc2_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_rc2_cbc_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_rc2_cbc');
    {$ifend}
  end;


  EVP_rc2_40_cbc := LoadLibFunction(ADllHandle, EVP_rc2_40_cbc_procname);
  FuncLoadError := not assigned(EVP_rc2_40_cbc);
  if FuncLoadError then
  begin
    {$if not defined(EVP_rc2_40_cbc_allownil)}
    EVP_rc2_40_cbc := ERR_EVP_rc2_40_cbc;
    {$ifend}
    {$if declared(EVP_rc2_40_cbc_introduced)}
    if LibVersion < EVP_rc2_40_cbc_introduced then
    begin
      {$if declared(FC_EVP_rc2_40_cbc)}
      EVP_rc2_40_cbc := FC_EVP_rc2_40_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_rc2_40_cbc_removed)}
    if EVP_rc2_40_cbc_removed <= LibVersion then
    begin
      {$if declared(_EVP_rc2_40_cbc)}
      EVP_rc2_40_cbc := _EVP_rc2_40_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_rc2_40_cbc_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_rc2_40_cbc');
    {$ifend}
  end;


  EVP_rc2_64_cbc := LoadLibFunction(ADllHandle, EVP_rc2_64_cbc_procname);
  FuncLoadError := not assigned(EVP_rc2_64_cbc);
  if FuncLoadError then
  begin
    {$if not defined(EVP_rc2_64_cbc_allownil)}
    EVP_rc2_64_cbc := ERR_EVP_rc2_64_cbc;
    {$ifend}
    {$if declared(EVP_rc2_64_cbc_introduced)}
    if LibVersion < EVP_rc2_64_cbc_introduced then
    begin
      {$if declared(FC_EVP_rc2_64_cbc)}
      EVP_rc2_64_cbc := FC_EVP_rc2_64_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_rc2_64_cbc_removed)}
    if EVP_rc2_64_cbc_removed <= LibVersion then
    begin
      {$if declared(_EVP_rc2_64_cbc)}
      EVP_rc2_64_cbc := _EVP_rc2_64_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_rc2_64_cbc_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_rc2_64_cbc');
    {$ifend}
  end;


  EVP_rc2_cfb64 := LoadLibFunction(ADllHandle, EVP_rc2_cfb64_procname);
  FuncLoadError := not assigned(EVP_rc2_cfb64);
  if FuncLoadError then
  begin
    {$if not defined(EVP_rc2_cfb64_allownil)}
    EVP_rc2_cfb64 := ERR_EVP_rc2_cfb64;
    {$ifend}
    {$if declared(EVP_rc2_cfb64_introduced)}
    if LibVersion < EVP_rc2_cfb64_introduced then
    begin
      {$if declared(FC_EVP_rc2_cfb64)}
      EVP_rc2_cfb64 := FC_EVP_rc2_cfb64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_rc2_cfb64_removed)}
    if EVP_rc2_cfb64_removed <= LibVersion then
    begin
      {$if declared(_EVP_rc2_cfb64)}
      EVP_rc2_cfb64 := _EVP_rc2_cfb64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_rc2_cfb64_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_rc2_cfb64');
    {$ifend}
  end;


  EVP_rc2_ofb := LoadLibFunction(ADllHandle, EVP_rc2_ofb_procname);
  FuncLoadError := not assigned(EVP_rc2_ofb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_rc2_ofb_allownil)}
    EVP_rc2_ofb := ERR_EVP_rc2_ofb;
    {$ifend}
    {$if declared(EVP_rc2_ofb_introduced)}
    if LibVersion < EVP_rc2_ofb_introduced then
    begin
      {$if declared(FC_EVP_rc2_ofb)}
      EVP_rc2_ofb := FC_EVP_rc2_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_rc2_ofb_removed)}
    if EVP_rc2_ofb_removed <= LibVersion then
    begin
      {$if declared(_EVP_rc2_ofb)}
      EVP_rc2_ofb := _EVP_rc2_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_rc2_ofb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_rc2_ofb');
    {$ifend}
  end;


  EVP_bf_ecb := LoadLibFunction(ADllHandle, EVP_bf_ecb_procname);
  FuncLoadError := not assigned(EVP_bf_ecb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_bf_ecb_allownil)}
    EVP_bf_ecb := ERR_EVP_bf_ecb;
    {$ifend}
    {$if declared(EVP_bf_ecb_introduced)}
    if LibVersion < EVP_bf_ecb_introduced then
    begin
      {$if declared(FC_EVP_bf_ecb)}
      EVP_bf_ecb := FC_EVP_bf_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_bf_ecb_removed)}
    if EVP_bf_ecb_removed <= LibVersion then
    begin
      {$if declared(_EVP_bf_ecb)}
      EVP_bf_ecb := _EVP_bf_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_bf_ecb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_bf_ecb');
    {$ifend}
  end;


  EVP_bf_cbc := LoadLibFunction(ADllHandle, EVP_bf_cbc_procname);
  FuncLoadError := not assigned(EVP_bf_cbc);
  if FuncLoadError then
  begin
    {$if not defined(EVP_bf_cbc_allownil)}
    EVP_bf_cbc := ERR_EVP_bf_cbc;
    {$ifend}
    {$if declared(EVP_bf_cbc_introduced)}
    if LibVersion < EVP_bf_cbc_introduced then
    begin
      {$if declared(FC_EVP_bf_cbc)}
      EVP_bf_cbc := FC_EVP_bf_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_bf_cbc_removed)}
    if EVP_bf_cbc_removed <= LibVersion then
    begin
      {$if declared(_EVP_bf_cbc)}
      EVP_bf_cbc := _EVP_bf_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_bf_cbc_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_bf_cbc');
    {$ifend}
  end;


  EVP_bf_cfb64 := LoadLibFunction(ADllHandle, EVP_bf_cfb64_procname);
  FuncLoadError := not assigned(EVP_bf_cfb64);
  if FuncLoadError then
  begin
    {$if not defined(EVP_bf_cfb64_allownil)}
    EVP_bf_cfb64 := ERR_EVP_bf_cfb64;
    {$ifend}
    {$if declared(EVP_bf_cfb64_introduced)}
    if LibVersion < EVP_bf_cfb64_introduced then
    begin
      {$if declared(FC_EVP_bf_cfb64)}
      EVP_bf_cfb64 := FC_EVP_bf_cfb64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_bf_cfb64_removed)}
    if EVP_bf_cfb64_removed <= LibVersion then
    begin
      {$if declared(_EVP_bf_cfb64)}
      EVP_bf_cfb64 := _EVP_bf_cfb64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_bf_cfb64_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_bf_cfb64');
    {$ifend}
  end;


  EVP_bf_ofb := LoadLibFunction(ADllHandle, EVP_bf_ofb_procname);
  FuncLoadError := not assigned(EVP_bf_ofb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_bf_ofb_allownil)}
    EVP_bf_ofb := ERR_EVP_bf_ofb;
    {$ifend}
    {$if declared(EVP_bf_ofb_introduced)}
    if LibVersion < EVP_bf_ofb_introduced then
    begin
      {$if declared(FC_EVP_bf_ofb)}
      EVP_bf_ofb := FC_EVP_bf_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_bf_ofb_removed)}
    if EVP_bf_ofb_removed <= LibVersion then
    begin
      {$if declared(_EVP_bf_ofb)}
      EVP_bf_ofb := _EVP_bf_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_bf_ofb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_bf_ofb');
    {$ifend}
  end;


  EVP_cast5_ecb := LoadLibFunction(ADllHandle, EVP_cast5_ecb_procname);
  FuncLoadError := not assigned(EVP_cast5_ecb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_cast5_ecb_allownil)}
    EVP_cast5_ecb := ERR_EVP_cast5_ecb;
    {$ifend}
    {$if declared(EVP_cast5_ecb_introduced)}
    if LibVersion < EVP_cast5_ecb_introduced then
    begin
      {$if declared(FC_EVP_cast5_ecb)}
      EVP_cast5_ecb := FC_EVP_cast5_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_cast5_ecb_removed)}
    if EVP_cast5_ecb_removed <= LibVersion then
    begin
      {$if declared(_EVP_cast5_ecb)}
      EVP_cast5_ecb := _EVP_cast5_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_cast5_ecb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_cast5_ecb');
    {$ifend}
  end;


  EVP_cast5_cbc := LoadLibFunction(ADllHandle, EVP_cast5_cbc_procname);
  FuncLoadError := not assigned(EVP_cast5_cbc);
  if FuncLoadError then
  begin
    {$if not defined(EVP_cast5_cbc_allownil)}
    EVP_cast5_cbc := ERR_EVP_cast5_cbc;
    {$ifend}
    {$if declared(EVP_cast5_cbc_introduced)}
    if LibVersion < EVP_cast5_cbc_introduced then
    begin
      {$if declared(FC_EVP_cast5_cbc)}
      EVP_cast5_cbc := FC_EVP_cast5_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_cast5_cbc_removed)}
    if EVP_cast5_cbc_removed <= LibVersion then
    begin
      {$if declared(_EVP_cast5_cbc)}
      EVP_cast5_cbc := _EVP_cast5_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_cast5_cbc_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_cast5_cbc');
    {$ifend}
  end;


  EVP_cast5_cfb64 := LoadLibFunction(ADllHandle, EVP_cast5_cfb64_procname);
  FuncLoadError := not assigned(EVP_cast5_cfb64);
  if FuncLoadError then
  begin
    {$if not defined(EVP_cast5_cfb64_allownil)}
    EVP_cast5_cfb64 := ERR_EVP_cast5_cfb64;
    {$ifend}
    {$if declared(EVP_cast5_cfb64_introduced)}
    if LibVersion < EVP_cast5_cfb64_introduced then
    begin
      {$if declared(FC_EVP_cast5_cfb64)}
      EVP_cast5_cfb64 := FC_EVP_cast5_cfb64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_cast5_cfb64_removed)}
    if EVP_cast5_cfb64_removed <= LibVersion then
    begin
      {$if declared(_EVP_cast5_cfb64)}
      EVP_cast5_cfb64 := _EVP_cast5_cfb64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_cast5_cfb64_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_cast5_cfb64');
    {$ifend}
  end;


  EVP_cast5_ofb := LoadLibFunction(ADllHandle, EVP_cast5_ofb_procname);
  FuncLoadError := not assigned(EVP_cast5_ofb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_cast5_ofb_allownil)}
    EVP_cast5_ofb := ERR_EVP_cast5_ofb;
    {$ifend}
    {$if declared(EVP_cast5_ofb_introduced)}
    if LibVersion < EVP_cast5_ofb_introduced then
    begin
      {$if declared(FC_EVP_cast5_ofb)}
      EVP_cast5_ofb := FC_EVP_cast5_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_cast5_ofb_removed)}
    if EVP_cast5_ofb_removed <= LibVersion then
    begin
      {$if declared(_EVP_cast5_ofb)}
      EVP_cast5_ofb := _EVP_cast5_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_cast5_ofb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_cast5_ofb');
    {$ifend}
  end;


  EVP_aes_128_ecb := LoadLibFunction(ADllHandle, EVP_aes_128_ecb_procname);
  FuncLoadError := not assigned(EVP_aes_128_ecb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_128_ecb_allownil)}
    EVP_aes_128_ecb := ERR_EVP_aes_128_ecb;
    {$ifend}
    {$if declared(EVP_aes_128_ecb_introduced)}
    if LibVersion < EVP_aes_128_ecb_introduced then
    begin
      {$if declared(FC_EVP_aes_128_ecb)}
      EVP_aes_128_ecb := FC_EVP_aes_128_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_128_ecb_removed)}
    if EVP_aes_128_ecb_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_128_ecb)}
      EVP_aes_128_ecb := _EVP_aes_128_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_128_ecb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_128_ecb');
    {$ifend}
  end;


  EVP_aes_128_cbc := LoadLibFunction(ADllHandle, EVP_aes_128_cbc_procname);
  FuncLoadError := not assigned(EVP_aes_128_cbc);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_128_cbc_allownil)}
    EVP_aes_128_cbc := ERR_EVP_aes_128_cbc;
    {$ifend}
    {$if declared(EVP_aes_128_cbc_introduced)}
    if LibVersion < EVP_aes_128_cbc_introduced then
    begin
      {$if declared(FC_EVP_aes_128_cbc)}
      EVP_aes_128_cbc := FC_EVP_aes_128_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_128_cbc_removed)}
    if EVP_aes_128_cbc_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_128_cbc)}
      EVP_aes_128_cbc := _EVP_aes_128_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_128_cbc_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_128_cbc');
    {$ifend}
  end;


  EVP_aes_128_cfb1 := LoadLibFunction(ADllHandle, EVP_aes_128_cfb1_procname);
  FuncLoadError := not assigned(EVP_aes_128_cfb1);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_128_cfb1_allownil)}
    EVP_aes_128_cfb1 := ERR_EVP_aes_128_cfb1;
    {$ifend}
    {$if declared(EVP_aes_128_cfb1_introduced)}
    if LibVersion < EVP_aes_128_cfb1_introduced then
    begin
      {$if declared(FC_EVP_aes_128_cfb1)}
      EVP_aes_128_cfb1 := FC_EVP_aes_128_cfb1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_128_cfb1_removed)}
    if EVP_aes_128_cfb1_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_128_cfb1)}
      EVP_aes_128_cfb1 := _EVP_aes_128_cfb1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_128_cfb1_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_128_cfb1');
    {$ifend}
  end;


  EVP_aes_128_cfb8 := LoadLibFunction(ADllHandle, EVP_aes_128_cfb8_procname);
  FuncLoadError := not assigned(EVP_aes_128_cfb8);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_128_cfb8_allownil)}
    EVP_aes_128_cfb8 := ERR_EVP_aes_128_cfb8;
    {$ifend}
    {$if declared(EVP_aes_128_cfb8_introduced)}
    if LibVersion < EVP_aes_128_cfb8_introduced then
    begin
      {$if declared(FC_EVP_aes_128_cfb8)}
      EVP_aes_128_cfb8 := FC_EVP_aes_128_cfb8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_128_cfb8_removed)}
    if EVP_aes_128_cfb8_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_128_cfb8)}
      EVP_aes_128_cfb8 := _EVP_aes_128_cfb8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_128_cfb8_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_128_cfb8');
    {$ifend}
  end;


  EVP_aes_128_cfb128 := LoadLibFunction(ADllHandle, EVP_aes_128_cfb128_procname);
  FuncLoadError := not assigned(EVP_aes_128_cfb128);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_128_cfb128_allownil)}
    EVP_aes_128_cfb128 := ERR_EVP_aes_128_cfb128;
    {$ifend}
    {$if declared(EVP_aes_128_cfb128_introduced)}
    if LibVersion < EVP_aes_128_cfb128_introduced then
    begin
      {$if declared(FC_EVP_aes_128_cfb128)}
      EVP_aes_128_cfb128 := FC_EVP_aes_128_cfb128;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_128_cfb128_removed)}
    if EVP_aes_128_cfb128_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_128_cfb128)}
      EVP_aes_128_cfb128 := _EVP_aes_128_cfb128;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_128_cfb128_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_128_cfb128');
    {$ifend}
  end;


  EVP_aes_128_ofb := LoadLibFunction(ADllHandle, EVP_aes_128_ofb_procname);
  FuncLoadError := not assigned(EVP_aes_128_ofb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_128_ofb_allownil)}
    EVP_aes_128_ofb := ERR_EVP_aes_128_ofb;
    {$ifend}
    {$if declared(EVP_aes_128_ofb_introduced)}
    if LibVersion < EVP_aes_128_ofb_introduced then
    begin
      {$if declared(FC_EVP_aes_128_ofb)}
      EVP_aes_128_ofb := FC_EVP_aes_128_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_128_ofb_removed)}
    if EVP_aes_128_ofb_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_128_ofb)}
      EVP_aes_128_ofb := _EVP_aes_128_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_128_ofb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_128_ofb');
    {$ifend}
  end;


  EVP_aes_128_ctr := LoadLibFunction(ADllHandle, EVP_aes_128_ctr_procname);
  FuncLoadError := not assigned(EVP_aes_128_ctr);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_128_ctr_allownil)}
    EVP_aes_128_ctr := ERR_EVP_aes_128_ctr;
    {$ifend}
    {$if declared(EVP_aes_128_ctr_introduced)}
    if LibVersion < EVP_aes_128_ctr_introduced then
    begin
      {$if declared(FC_EVP_aes_128_ctr)}
      EVP_aes_128_ctr := FC_EVP_aes_128_ctr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_128_ctr_removed)}
    if EVP_aes_128_ctr_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_128_ctr)}
      EVP_aes_128_ctr := _EVP_aes_128_ctr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_128_ctr_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_128_ctr');
    {$ifend}
  end;


  EVP_aes_128_ccm := LoadLibFunction(ADllHandle, EVP_aes_128_ccm_procname);
  FuncLoadError := not assigned(EVP_aes_128_ccm);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_128_ccm_allownil)}
    EVP_aes_128_ccm := ERR_EVP_aes_128_ccm;
    {$ifend}
    {$if declared(EVP_aes_128_ccm_introduced)}
    if LibVersion < EVP_aes_128_ccm_introduced then
    begin
      {$if declared(FC_EVP_aes_128_ccm)}
      EVP_aes_128_ccm := FC_EVP_aes_128_ccm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_128_ccm_removed)}
    if EVP_aes_128_ccm_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_128_ccm)}
      EVP_aes_128_ccm := _EVP_aes_128_ccm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_128_ccm_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_128_ccm');
    {$ifend}
  end;


  EVP_aes_128_gcm := LoadLibFunction(ADllHandle, EVP_aes_128_gcm_procname);
  FuncLoadError := not assigned(EVP_aes_128_gcm);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_128_gcm_allownil)}
    EVP_aes_128_gcm := ERR_EVP_aes_128_gcm;
    {$ifend}
    {$if declared(EVP_aes_128_gcm_introduced)}
    if LibVersion < EVP_aes_128_gcm_introduced then
    begin
      {$if declared(FC_EVP_aes_128_gcm)}
      EVP_aes_128_gcm := FC_EVP_aes_128_gcm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_128_gcm_removed)}
    if EVP_aes_128_gcm_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_128_gcm)}
      EVP_aes_128_gcm := _EVP_aes_128_gcm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_128_gcm_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_128_gcm');
    {$ifend}
  end;


  EVP_aes_128_xts := LoadLibFunction(ADllHandle, EVP_aes_128_xts_procname);
  FuncLoadError := not assigned(EVP_aes_128_xts);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_128_xts_allownil)}
    EVP_aes_128_xts := ERR_EVP_aes_128_xts;
    {$ifend}
    {$if declared(EVP_aes_128_xts_introduced)}
    if LibVersion < EVP_aes_128_xts_introduced then
    begin
      {$if declared(FC_EVP_aes_128_xts)}
      EVP_aes_128_xts := FC_EVP_aes_128_xts;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_128_xts_removed)}
    if EVP_aes_128_xts_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_128_xts)}
      EVP_aes_128_xts := _EVP_aes_128_xts;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_128_xts_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_128_xts');
    {$ifend}
  end;


  EVP_aes_128_wrap := LoadLibFunction(ADllHandle, EVP_aes_128_wrap_procname);
  FuncLoadError := not assigned(EVP_aes_128_wrap);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_128_wrap_allownil)}
    EVP_aes_128_wrap := ERR_EVP_aes_128_wrap;
    {$ifend}
    {$if declared(EVP_aes_128_wrap_introduced)}
    if LibVersion < EVP_aes_128_wrap_introduced then
    begin
      {$if declared(FC_EVP_aes_128_wrap)}
      EVP_aes_128_wrap := FC_EVP_aes_128_wrap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_128_wrap_removed)}
    if EVP_aes_128_wrap_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_128_wrap)}
      EVP_aes_128_wrap := _EVP_aes_128_wrap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_128_wrap_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_128_wrap');
    {$ifend}
  end;


  EVP_aes_128_wrap_pad := LoadLibFunction(ADllHandle, EVP_aes_128_wrap_pad_procname);
  FuncLoadError := not assigned(EVP_aes_128_wrap_pad);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_128_wrap_pad_allownil)}
    EVP_aes_128_wrap_pad := ERR_EVP_aes_128_wrap_pad;
    {$ifend}
    {$if declared(EVP_aes_128_wrap_pad_introduced)}
    if LibVersion < EVP_aes_128_wrap_pad_introduced then
    begin
      {$if declared(FC_EVP_aes_128_wrap_pad)}
      EVP_aes_128_wrap_pad := FC_EVP_aes_128_wrap_pad;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_128_wrap_pad_removed)}
    if EVP_aes_128_wrap_pad_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_128_wrap_pad)}
      EVP_aes_128_wrap_pad := _EVP_aes_128_wrap_pad;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_128_wrap_pad_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_128_wrap_pad');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aes_128_ocb := LoadLibFunction(ADllHandle, EVP_aes_128_ocb_procname);
  FuncLoadError := not assigned(EVP_aes_128_ocb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_128_ocb_allownil)}
    EVP_aes_128_ocb := ERR_EVP_aes_128_ocb;
    {$ifend}
    {$if declared(EVP_aes_128_ocb_introduced)}
    if LibVersion < EVP_aes_128_ocb_introduced then
    begin
      {$if declared(FC_EVP_aes_128_ocb)}
      EVP_aes_128_ocb := FC_EVP_aes_128_ocb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_128_ocb_removed)}
    if EVP_aes_128_ocb_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_128_ocb)}
      EVP_aes_128_ocb := _EVP_aes_128_ocb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_128_ocb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_128_ocb');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aes_192_ecb := LoadLibFunction(ADllHandle, EVP_aes_192_ecb_procname);
  FuncLoadError := not assigned(EVP_aes_192_ecb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_192_ecb_allownil)}
    EVP_aes_192_ecb := ERR_EVP_aes_192_ecb;
    {$ifend}
    {$if declared(EVP_aes_192_ecb_introduced)}
    if LibVersion < EVP_aes_192_ecb_introduced then
    begin
      {$if declared(FC_EVP_aes_192_ecb)}
      EVP_aes_192_ecb := FC_EVP_aes_192_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_192_ecb_removed)}
    if EVP_aes_192_ecb_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_192_ecb)}
      EVP_aes_192_ecb := _EVP_aes_192_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_192_ecb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_192_ecb');
    {$ifend}
  end;


  EVP_aes_192_cbc := LoadLibFunction(ADllHandle, EVP_aes_192_cbc_procname);
  FuncLoadError := not assigned(EVP_aes_192_cbc);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_192_cbc_allownil)}
    EVP_aes_192_cbc := ERR_EVP_aes_192_cbc;
    {$ifend}
    {$if declared(EVP_aes_192_cbc_introduced)}
    if LibVersion < EVP_aes_192_cbc_introduced then
    begin
      {$if declared(FC_EVP_aes_192_cbc)}
      EVP_aes_192_cbc := FC_EVP_aes_192_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_192_cbc_removed)}
    if EVP_aes_192_cbc_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_192_cbc)}
      EVP_aes_192_cbc := _EVP_aes_192_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_192_cbc_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_192_cbc');
    {$ifend}
  end;


  EVP_aes_192_cfb1 := LoadLibFunction(ADllHandle, EVP_aes_192_cfb1_procname);
  FuncLoadError := not assigned(EVP_aes_192_cfb1);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_192_cfb1_allownil)}
    EVP_aes_192_cfb1 := ERR_EVP_aes_192_cfb1;
    {$ifend}
    {$if declared(EVP_aes_192_cfb1_introduced)}
    if LibVersion < EVP_aes_192_cfb1_introduced then
    begin
      {$if declared(FC_EVP_aes_192_cfb1)}
      EVP_aes_192_cfb1 := FC_EVP_aes_192_cfb1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_192_cfb1_removed)}
    if EVP_aes_192_cfb1_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_192_cfb1)}
      EVP_aes_192_cfb1 := _EVP_aes_192_cfb1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_192_cfb1_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_192_cfb1');
    {$ifend}
  end;


  EVP_aes_192_cfb8 := LoadLibFunction(ADllHandle, EVP_aes_192_cfb8_procname);
  FuncLoadError := not assigned(EVP_aes_192_cfb8);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_192_cfb8_allownil)}
    EVP_aes_192_cfb8 := ERR_EVP_aes_192_cfb8;
    {$ifend}
    {$if declared(EVP_aes_192_cfb8_introduced)}
    if LibVersion < EVP_aes_192_cfb8_introduced then
    begin
      {$if declared(FC_EVP_aes_192_cfb8)}
      EVP_aes_192_cfb8 := FC_EVP_aes_192_cfb8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_192_cfb8_removed)}
    if EVP_aes_192_cfb8_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_192_cfb8)}
      EVP_aes_192_cfb8 := _EVP_aes_192_cfb8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_192_cfb8_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_192_cfb8');
    {$ifend}
  end;


  EVP_aes_192_cfb128 := LoadLibFunction(ADllHandle, EVP_aes_192_cfb128_procname);
  FuncLoadError := not assigned(EVP_aes_192_cfb128);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_192_cfb128_allownil)}
    EVP_aes_192_cfb128 := ERR_EVP_aes_192_cfb128;
    {$ifend}
    {$if declared(EVP_aes_192_cfb128_introduced)}
    if LibVersion < EVP_aes_192_cfb128_introduced then
    begin
      {$if declared(FC_EVP_aes_192_cfb128)}
      EVP_aes_192_cfb128 := FC_EVP_aes_192_cfb128;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_192_cfb128_removed)}
    if EVP_aes_192_cfb128_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_192_cfb128)}
      EVP_aes_192_cfb128 := _EVP_aes_192_cfb128;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_192_cfb128_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_192_cfb128');
    {$ifend}
  end;


  EVP_aes_192_ofb := LoadLibFunction(ADllHandle, EVP_aes_192_ofb_procname);
  FuncLoadError := not assigned(EVP_aes_192_ofb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_192_ofb_allownil)}
    EVP_aes_192_ofb := ERR_EVP_aes_192_ofb;
    {$ifend}
    {$if declared(EVP_aes_192_ofb_introduced)}
    if LibVersion < EVP_aes_192_ofb_introduced then
    begin
      {$if declared(FC_EVP_aes_192_ofb)}
      EVP_aes_192_ofb := FC_EVP_aes_192_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_192_ofb_removed)}
    if EVP_aes_192_ofb_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_192_ofb)}
      EVP_aes_192_ofb := _EVP_aes_192_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_192_ofb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_192_ofb');
    {$ifend}
  end;


  EVP_aes_192_ctr := LoadLibFunction(ADllHandle, EVP_aes_192_ctr_procname);
  FuncLoadError := not assigned(EVP_aes_192_ctr);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_192_ctr_allownil)}
    EVP_aes_192_ctr := ERR_EVP_aes_192_ctr;
    {$ifend}
    {$if declared(EVP_aes_192_ctr_introduced)}
    if LibVersion < EVP_aes_192_ctr_introduced then
    begin
      {$if declared(FC_EVP_aes_192_ctr)}
      EVP_aes_192_ctr := FC_EVP_aes_192_ctr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_192_ctr_removed)}
    if EVP_aes_192_ctr_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_192_ctr)}
      EVP_aes_192_ctr := _EVP_aes_192_ctr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_192_ctr_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_192_ctr');
    {$ifend}
  end;


  EVP_aes_192_ccm := LoadLibFunction(ADllHandle, EVP_aes_192_ccm_procname);
  FuncLoadError := not assigned(EVP_aes_192_ccm);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_192_ccm_allownil)}
    EVP_aes_192_ccm := ERR_EVP_aes_192_ccm;
    {$ifend}
    {$if declared(EVP_aes_192_ccm_introduced)}
    if LibVersion < EVP_aes_192_ccm_introduced then
    begin
      {$if declared(FC_EVP_aes_192_ccm)}
      EVP_aes_192_ccm := FC_EVP_aes_192_ccm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_192_ccm_removed)}
    if EVP_aes_192_ccm_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_192_ccm)}
      EVP_aes_192_ccm := _EVP_aes_192_ccm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_192_ccm_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_192_ccm');
    {$ifend}
  end;


  EVP_aes_192_gcm := LoadLibFunction(ADllHandle, EVP_aes_192_gcm_procname);
  FuncLoadError := not assigned(EVP_aes_192_gcm);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_192_gcm_allownil)}
    EVP_aes_192_gcm := ERR_EVP_aes_192_gcm;
    {$ifend}
    {$if declared(EVP_aes_192_gcm_introduced)}
    if LibVersion < EVP_aes_192_gcm_introduced then
    begin
      {$if declared(FC_EVP_aes_192_gcm)}
      EVP_aes_192_gcm := FC_EVP_aes_192_gcm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_192_gcm_removed)}
    if EVP_aes_192_gcm_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_192_gcm)}
      EVP_aes_192_gcm := _EVP_aes_192_gcm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_192_gcm_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_192_gcm');
    {$ifend}
  end;


  EVP_aes_192_wrap := LoadLibFunction(ADllHandle, EVP_aes_192_wrap_procname);
  FuncLoadError := not assigned(EVP_aes_192_wrap);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_192_wrap_allownil)}
    EVP_aes_192_wrap := ERR_EVP_aes_192_wrap;
    {$ifend}
    {$if declared(EVP_aes_192_wrap_introduced)}
    if LibVersion < EVP_aes_192_wrap_introduced then
    begin
      {$if declared(FC_EVP_aes_192_wrap)}
      EVP_aes_192_wrap := FC_EVP_aes_192_wrap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_192_wrap_removed)}
    if EVP_aes_192_wrap_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_192_wrap)}
      EVP_aes_192_wrap := _EVP_aes_192_wrap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_192_wrap_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_192_wrap');
    {$ifend}
  end;


  EVP_aes_192_wrap_pad := LoadLibFunction(ADllHandle, EVP_aes_192_wrap_pad_procname);
  FuncLoadError := not assigned(EVP_aes_192_wrap_pad);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_192_wrap_pad_allownil)}
    EVP_aes_192_wrap_pad := ERR_EVP_aes_192_wrap_pad;
    {$ifend}
    {$if declared(EVP_aes_192_wrap_pad_introduced)}
    if LibVersion < EVP_aes_192_wrap_pad_introduced then
    begin
      {$if declared(FC_EVP_aes_192_wrap_pad)}
      EVP_aes_192_wrap_pad := FC_EVP_aes_192_wrap_pad;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_192_wrap_pad_removed)}
    if EVP_aes_192_wrap_pad_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_192_wrap_pad)}
      EVP_aes_192_wrap_pad := _EVP_aes_192_wrap_pad;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_192_wrap_pad_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_192_wrap_pad');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aes_192_ocb := LoadLibFunction(ADllHandle, EVP_aes_192_ocb_procname);
  FuncLoadError := not assigned(EVP_aes_192_ocb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_192_ocb_allownil)}
    EVP_aes_192_ocb := ERR_EVP_aes_192_ocb;
    {$ifend}
    {$if declared(EVP_aes_192_ocb_introduced)}
    if LibVersion < EVP_aes_192_ocb_introduced then
    begin
      {$if declared(FC_EVP_aes_192_ocb)}
      EVP_aes_192_ocb := FC_EVP_aes_192_ocb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_192_ocb_removed)}
    if EVP_aes_192_ocb_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_192_ocb)}
      EVP_aes_192_ocb := _EVP_aes_192_ocb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_192_ocb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_192_ocb');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aes_256_ecb := LoadLibFunction(ADllHandle, EVP_aes_256_ecb_procname);
  FuncLoadError := not assigned(EVP_aes_256_ecb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_256_ecb_allownil)}
    EVP_aes_256_ecb := ERR_EVP_aes_256_ecb;
    {$ifend}
    {$if declared(EVP_aes_256_ecb_introduced)}
    if LibVersion < EVP_aes_256_ecb_introduced then
    begin
      {$if declared(FC_EVP_aes_256_ecb)}
      EVP_aes_256_ecb := FC_EVP_aes_256_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_256_ecb_removed)}
    if EVP_aes_256_ecb_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_256_ecb)}
      EVP_aes_256_ecb := _EVP_aes_256_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_256_ecb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_256_ecb');
    {$ifend}
  end;


  EVP_aes_256_cbc := LoadLibFunction(ADllHandle, EVP_aes_256_cbc_procname);
  FuncLoadError := not assigned(EVP_aes_256_cbc);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_256_cbc_allownil)}
    EVP_aes_256_cbc := ERR_EVP_aes_256_cbc;
    {$ifend}
    {$if declared(EVP_aes_256_cbc_introduced)}
    if LibVersion < EVP_aes_256_cbc_introduced then
    begin
      {$if declared(FC_EVP_aes_256_cbc)}
      EVP_aes_256_cbc := FC_EVP_aes_256_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_256_cbc_removed)}
    if EVP_aes_256_cbc_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_256_cbc)}
      EVP_aes_256_cbc := _EVP_aes_256_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_256_cbc_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_256_cbc');
    {$ifend}
  end;


  EVP_aes_256_cfb1 := LoadLibFunction(ADllHandle, EVP_aes_256_cfb1_procname);
  FuncLoadError := not assigned(EVP_aes_256_cfb1);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_256_cfb1_allownil)}
    EVP_aes_256_cfb1 := ERR_EVP_aes_256_cfb1;
    {$ifend}
    {$if declared(EVP_aes_256_cfb1_introduced)}
    if LibVersion < EVP_aes_256_cfb1_introduced then
    begin
      {$if declared(FC_EVP_aes_256_cfb1)}
      EVP_aes_256_cfb1 := FC_EVP_aes_256_cfb1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_256_cfb1_removed)}
    if EVP_aes_256_cfb1_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_256_cfb1)}
      EVP_aes_256_cfb1 := _EVP_aes_256_cfb1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_256_cfb1_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_256_cfb1');
    {$ifend}
  end;


  EVP_aes_256_cfb8 := LoadLibFunction(ADllHandle, EVP_aes_256_cfb8_procname);
  FuncLoadError := not assigned(EVP_aes_256_cfb8);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_256_cfb8_allownil)}
    EVP_aes_256_cfb8 := ERR_EVP_aes_256_cfb8;
    {$ifend}
    {$if declared(EVP_aes_256_cfb8_introduced)}
    if LibVersion < EVP_aes_256_cfb8_introduced then
    begin
      {$if declared(FC_EVP_aes_256_cfb8)}
      EVP_aes_256_cfb8 := FC_EVP_aes_256_cfb8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_256_cfb8_removed)}
    if EVP_aes_256_cfb8_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_256_cfb8)}
      EVP_aes_256_cfb8 := _EVP_aes_256_cfb8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_256_cfb8_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_256_cfb8');
    {$ifend}
  end;


  EVP_aes_256_cfb128 := LoadLibFunction(ADllHandle, EVP_aes_256_cfb128_procname);
  FuncLoadError := not assigned(EVP_aes_256_cfb128);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_256_cfb128_allownil)}
    EVP_aes_256_cfb128 := ERR_EVP_aes_256_cfb128;
    {$ifend}
    {$if declared(EVP_aes_256_cfb128_introduced)}
    if LibVersion < EVP_aes_256_cfb128_introduced then
    begin
      {$if declared(FC_EVP_aes_256_cfb128)}
      EVP_aes_256_cfb128 := FC_EVP_aes_256_cfb128;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_256_cfb128_removed)}
    if EVP_aes_256_cfb128_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_256_cfb128)}
      EVP_aes_256_cfb128 := _EVP_aes_256_cfb128;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_256_cfb128_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_256_cfb128');
    {$ifend}
  end;


  EVP_aes_256_ofb := LoadLibFunction(ADllHandle, EVP_aes_256_ofb_procname);
  FuncLoadError := not assigned(EVP_aes_256_ofb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_256_ofb_allownil)}
    EVP_aes_256_ofb := ERR_EVP_aes_256_ofb;
    {$ifend}
    {$if declared(EVP_aes_256_ofb_introduced)}
    if LibVersion < EVP_aes_256_ofb_introduced then
    begin
      {$if declared(FC_EVP_aes_256_ofb)}
      EVP_aes_256_ofb := FC_EVP_aes_256_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_256_ofb_removed)}
    if EVP_aes_256_ofb_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_256_ofb)}
      EVP_aes_256_ofb := _EVP_aes_256_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_256_ofb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_256_ofb');
    {$ifend}
  end;


  EVP_aes_256_ctr := LoadLibFunction(ADllHandle, EVP_aes_256_ctr_procname);
  FuncLoadError := not assigned(EVP_aes_256_ctr);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_256_ctr_allownil)}
    EVP_aes_256_ctr := ERR_EVP_aes_256_ctr;
    {$ifend}
    {$if declared(EVP_aes_256_ctr_introduced)}
    if LibVersion < EVP_aes_256_ctr_introduced then
    begin
      {$if declared(FC_EVP_aes_256_ctr)}
      EVP_aes_256_ctr := FC_EVP_aes_256_ctr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_256_ctr_removed)}
    if EVP_aes_256_ctr_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_256_ctr)}
      EVP_aes_256_ctr := _EVP_aes_256_ctr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_256_ctr_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_256_ctr');
    {$ifend}
  end;


  EVP_aes_256_ccm := LoadLibFunction(ADllHandle, EVP_aes_256_ccm_procname);
  FuncLoadError := not assigned(EVP_aes_256_ccm);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_256_ccm_allownil)}
    EVP_aes_256_ccm := ERR_EVP_aes_256_ccm;
    {$ifend}
    {$if declared(EVP_aes_256_ccm_introduced)}
    if LibVersion < EVP_aes_256_ccm_introduced then
    begin
      {$if declared(FC_EVP_aes_256_ccm)}
      EVP_aes_256_ccm := FC_EVP_aes_256_ccm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_256_ccm_removed)}
    if EVP_aes_256_ccm_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_256_ccm)}
      EVP_aes_256_ccm := _EVP_aes_256_ccm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_256_ccm_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_256_ccm');
    {$ifend}
  end;


  EVP_aes_256_gcm := LoadLibFunction(ADllHandle, EVP_aes_256_gcm_procname);
  FuncLoadError := not assigned(EVP_aes_256_gcm);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_256_gcm_allownil)}
    EVP_aes_256_gcm := ERR_EVP_aes_256_gcm;
    {$ifend}
    {$if declared(EVP_aes_256_gcm_introduced)}
    if LibVersion < EVP_aes_256_gcm_introduced then
    begin
      {$if declared(FC_EVP_aes_256_gcm)}
      EVP_aes_256_gcm := FC_EVP_aes_256_gcm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_256_gcm_removed)}
    if EVP_aes_256_gcm_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_256_gcm)}
      EVP_aes_256_gcm := _EVP_aes_256_gcm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_256_gcm_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_256_gcm');
    {$ifend}
  end;


  EVP_aes_256_xts := LoadLibFunction(ADllHandle, EVP_aes_256_xts_procname);
  FuncLoadError := not assigned(EVP_aes_256_xts);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_256_xts_allownil)}
    EVP_aes_256_xts := ERR_EVP_aes_256_xts;
    {$ifend}
    {$if declared(EVP_aes_256_xts_introduced)}
    if LibVersion < EVP_aes_256_xts_introduced then
    begin
      {$if declared(FC_EVP_aes_256_xts)}
      EVP_aes_256_xts := FC_EVP_aes_256_xts;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_256_xts_removed)}
    if EVP_aes_256_xts_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_256_xts)}
      EVP_aes_256_xts := _EVP_aes_256_xts;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_256_xts_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_256_xts');
    {$ifend}
  end;


  EVP_aes_256_wrap := LoadLibFunction(ADllHandle, EVP_aes_256_wrap_procname);
  FuncLoadError := not assigned(EVP_aes_256_wrap);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_256_wrap_allownil)}
    EVP_aes_256_wrap := ERR_EVP_aes_256_wrap;
    {$ifend}
    {$if declared(EVP_aes_256_wrap_introduced)}
    if LibVersion < EVP_aes_256_wrap_introduced then
    begin
      {$if declared(FC_EVP_aes_256_wrap)}
      EVP_aes_256_wrap := FC_EVP_aes_256_wrap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_256_wrap_removed)}
    if EVP_aes_256_wrap_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_256_wrap)}
      EVP_aes_256_wrap := _EVP_aes_256_wrap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_256_wrap_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_256_wrap');
    {$ifend}
  end;


  EVP_aes_256_wrap_pad := LoadLibFunction(ADllHandle, EVP_aes_256_wrap_pad_procname);
  FuncLoadError := not assigned(EVP_aes_256_wrap_pad);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_256_wrap_pad_allownil)}
    EVP_aes_256_wrap_pad := ERR_EVP_aes_256_wrap_pad;
    {$ifend}
    {$if declared(EVP_aes_256_wrap_pad_introduced)}
    if LibVersion < EVP_aes_256_wrap_pad_introduced then
    begin
      {$if declared(FC_EVP_aes_256_wrap_pad)}
      EVP_aes_256_wrap_pad := FC_EVP_aes_256_wrap_pad;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_256_wrap_pad_removed)}
    if EVP_aes_256_wrap_pad_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_256_wrap_pad)}
      EVP_aes_256_wrap_pad := _EVP_aes_256_wrap_pad;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_256_wrap_pad_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_256_wrap_pad');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aes_256_ocb := LoadLibFunction(ADllHandle, EVP_aes_256_ocb_procname);
  FuncLoadError := not assigned(EVP_aes_256_ocb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_256_ocb_allownil)}
    EVP_aes_256_ocb := ERR_EVP_aes_256_ocb;
    {$ifend}
    {$if declared(EVP_aes_256_ocb_introduced)}
    if LibVersion < EVP_aes_256_ocb_introduced then
    begin
      {$if declared(FC_EVP_aes_256_ocb)}
      EVP_aes_256_ocb := FC_EVP_aes_256_ocb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_256_ocb_removed)}
    if EVP_aes_256_ocb_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_256_ocb)}
      EVP_aes_256_ocb := _EVP_aes_256_ocb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_256_ocb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_256_ocb');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aes_128_cbc_hmac_sha1 := LoadLibFunction(ADllHandle, EVP_aes_128_cbc_hmac_sha1_procname);
  FuncLoadError := not assigned(EVP_aes_128_cbc_hmac_sha1);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_128_cbc_hmac_sha1_allownil)}
    EVP_aes_128_cbc_hmac_sha1 := ERR_EVP_aes_128_cbc_hmac_sha1;
    {$ifend}
    {$if declared(EVP_aes_128_cbc_hmac_sha1_introduced)}
    if LibVersion < EVP_aes_128_cbc_hmac_sha1_introduced then
    begin
      {$if declared(FC_EVP_aes_128_cbc_hmac_sha1)}
      EVP_aes_128_cbc_hmac_sha1 := FC_EVP_aes_128_cbc_hmac_sha1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_128_cbc_hmac_sha1_removed)}
    if EVP_aes_128_cbc_hmac_sha1_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_128_cbc_hmac_sha1)}
      EVP_aes_128_cbc_hmac_sha1 := _EVP_aes_128_cbc_hmac_sha1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_128_cbc_hmac_sha1_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_128_cbc_hmac_sha1');
    {$ifend}
  end;


  EVP_aes_256_cbc_hmac_sha1 := LoadLibFunction(ADllHandle, EVP_aes_256_cbc_hmac_sha1_procname);
  FuncLoadError := not assigned(EVP_aes_256_cbc_hmac_sha1);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_256_cbc_hmac_sha1_allownil)}
    EVP_aes_256_cbc_hmac_sha1 := ERR_EVP_aes_256_cbc_hmac_sha1;
    {$ifend}
    {$if declared(EVP_aes_256_cbc_hmac_sha1_introduced)}
    if LibVersion < EVP_aes_256_cbc_hmac_sha1_introduced then
    begin
      {$if declared(FC_EVP_aes_256_cbc_hmac_sha1)}
      EVP_aes_256_cbc_hmac_sha1 := FC_EVP_aes_256_cbc_hmac_sha1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_256_cbc_hmac_sha1_removed)}
    if EVP_aes_256_cbc_hmac_sha1_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_256_cbc_hmac_sha1)}
      EVP_aes_256_cbc_hmac_sha1 := _EVP_aes_256_cbc_hmac_sha1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_256_cbc_hmac_sha1_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_256_cbc_hmac_sha1');
    {$ifend}
  end;


  EVP_aes_128_cbc_hmac_sha256 := LoadLibFunction(ADllHandle, EVP_aes_128_cbc_hmac_sha256_procname);
  FuncLoadError := not assigned(EVP_aes_128_cbc_hmac_sha256);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_128_cbc_hmac_sha256_allownil)}
    EVP_aes_128_cbc_hmac_sha256 := ERR_EVP_aes_128_cbc_hmac_sha256;
    {$ifend}
    {$if declared(EVP_aes_128_cbc_hmac_sha256_introduced)}
    if LibVersion < EVP_aes_128_cbc_hmac_sha256_introduced then
    begin
      {$if declared(FC_EVP_aes_128_cbc_hmac_sha256)}
      EVP_aes_128_cbc_hmac_sha256 := FC_EVP_aes_128_cbc_hmac_sha256;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_128_cbc_hmac_sha256_removed)}
    if EVP_aes_128_cbc_hmac_sha256_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_128_cbc_hmac_sha256)}
      EVP_aes_128_cbc_hmac_sha256 := _EVP_aes_128_cbc_hmac_sha256;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_128_cbc_hmac_sha256_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_128_cbc_hmac_sha256');
    {$ifend}
  end;


  EVP_aes_256_cbc_hmac_sha256 := LoadLibFunction(ADllHandle, EVP_aes_256_cbc_hmac_sha256_procname);
  FuncLoadError := not assigned(EVP_aes_256_cbc_hmac_sha256);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aes_256_cbc_hmac_sha256_allownil)}
    EVP_aes_256_cbc_hmac_sha256 := ERR_EVP_aes_256_cbc_hmac_sha256;
    {$ifend}
    {$if declared(EVP_aes_256_cbc_hmac_sha256_introduced)}
    if LibVersion < EVP_aes_256_cbc_hmac_sha256_introduced then
    begin
      {$if declared(FC_EVP_aes_256_cbc_hmac_sha256)}
      EVP_aes_256_cbc_hmac_sha256 := FC_EVP_aes_256_cbc_hmac_sha256;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aes_256_cbc_hmac_sha256_removed)}
    if EVP_aes_256_cbc_hmac_sha256_removed <= LibVersion then
    begin
      {$if declared(_EVP_aes_256_cbc_hmac_sha256)}
      EVP_aes_256_cbc_hmac_sha256 := _EVP_aes_256_cbc_hmac_sha256;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aes_256_cbc_hmac_sha256_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aes_256_cbc_hmac_sha256');
    {$ifend}
  end;


  EVP_aria_128_ecb := LoadLibFunction(ADllHandle, EVP_aria_128_ecb_procname);
  FuncLoadError := not assigned(EVP_aria_128_ecb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aria_128_ecb_allownil)}
    EVP_aria_128_ecb := ERR_EVP_aria_128_ecb;
    {$ifend}
    {$if declared(EVP_aria_128_ecb_introduced)}
    if LibVersion < EVP_aria_128_ecb_introduced then
    begin
      {$if declared(FC_EVP_aria_128_ecb)}
      EVP_aria_128_ecb := FC_EVP_aria_128_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aria_128_ecb_removed)}
    if EVP_aria_128_ecb_removed <= LibVersion then
    begin
      {$if declared(_EVP_aria_128_ecb)}
      EVP_aria_128_ecb := _EVP_aria_128_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aria_128_ecb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aria_128_ecb');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aria_128_cbc := LoadLibFunction(ADllHandle, EVP_aria_128_cbc_procname);
  FuncLoadError := not assigned(EVP_aria_128_cbc);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aria_128_cbc_allownil)}
    EVP_aria_128_cbc := ERR_EVP_aria_128_cbc;
    {$ifend}
    {$if declared(EVP_aria_128_cbc_introduced)}
    if LibVersion < EVP_aria_128_cbc_introduced then
    begin
      {$if declared(FC_EVP_aria_128_cbc)}
      EVP_aria_128_cbc := FC_EVP_aria_128_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aria_128_cbc_removed)}
    if EVP_aria_128_cbc_removed <= LibVersion then
    begin
      {$if declared(_EVP_aria_128_cbc)}
      EVP_aria_128_cbc := _EVP_aria_128_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aria_128_cbc_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aria_128_cbc');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aria_128_cfb1 := LoadLibFunction(ADllHandle, EVP_aria_128_cfb1_procname);
  FuncLoadError := not assigned(EVP_aria_128_cfb1);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aria_128_cfb1_allownil)}
    EVP_aria_128_cfb1 := ERR_EVP_aria_128_cfb1;
    {$ifend}
    {$if declared(EVP_aria_128_cfb1_introduced)}
    if LibVersion < EVP_aria_128_cfb1_introduced then
    begin
      {$if declared(FC_EVP_aria_128_cfb1)}
      EVP_aria_128_cfb1 := FC_EVP_aria_128_cfb1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aria_128_cfb1_removed)}
    if EVP_aria_128_cfb1_removed <= LibVersion then
    begin
      {$if declared(_EVP_aria_128_cfb1)}
      EVP_aria_128_cfb1 := _EVP_aria_128_cfb1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aria_128_cfb1_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aria_128_cfb1');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aria_128_cfb8 := LoadLibFunction(ADllHandle, EVP_aria_128_cfb8_procname);
  FuncLoadError := not assigned(EVP_aria_128_cfb8);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aria_128_cfb8_allownil)}
    EVP_aria_128_cfb8 := ERR_EVP_aria_128_cfb8;
    {$ifend}
    {$if declared(EVP_aria_128_cfb8_introduced)}
    if LibVersion < EVP_aria_128_cfb8_introduced then
    begin
      {$if declared(FC_EVP_aria_128_cfb8)}
      EVP_aria_128_cfb8 := FC_EVP_aria_128_cfb8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aria_128_cfb8_removed)}
    if EVP_aria_128_cfb8_removed <= LibVersion then
    begin
      {$if declared(_EVP_aria_128_cfb8)}
      EVP_aria_128_cfb8 := _EVP_aria_128_cfb8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aria_128_cfb8_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aria_128_cfb8');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aria_128_cfb128 := LoadLibFunction(ADllHandle, EVP_aria_128_cfb128_procname);
  FuncLoadError := not assigned(EVP_aria_128_cfb128);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aria_128_cfb128_allownil)}
    EVP_aria_128_cfb128 := ERR_EVP_aria_128_cfb128;
    {$ifend}
    {$if declared(EVP_aria_128_cfb128_introduced)}
    if LibVersion < EVP_aria_128_cfb128_introduced then
    begin
      {$if declared(FC_EVP_aria_128_cfb128)}
      EVP_aria_128_cfb128 := FC_EVP_aria_128_cfb128;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aria_128_cfb128_removed)}
    if EVP_aria_128_cfb128_removed <= LibVersion then
    begin
      {$if declared(_EVP_aria_128_cfb128)}
      EVP_aria_128_cfb128 := _EVP_aria_128_cfb128;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aria_128_cfb128_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aria_128_cfb128');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aria_128_ctr := LoadLibFunction(ADllHandle, EVP_aria_128_ctr_procname);
  FuncLoadError := not assigned(EVP_aria_128_ctr);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aria_128_ctr_allownil)}
    EVP_aria_128_ctr := ERR_EVP_aria_128_ctr;
    {$ifend}
    {$if declared(EVP_aria_128_ctr_introduced)}
    if LibVersion < EVP_aria_128_ctr_introduced then
    begin
      {$if declared(FC_EVP_aria_128_ctr)}
      EVP_aria_128_ctr := FC_EVP_aria_128_ctr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aria_128_ctr_removed)}
    if EVP_aria_128_ctr_removed <= LibVersion then
    begin
      {$if declared(_EVP_aria_128_ctr)}
      EVP_aria_128_ctr := _EVP_aria_128_ctr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aria_128_ctr_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aria_128_ctr');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aria_128_ofb := LoadLibFunction(ADllHandle, EVP_aria_128_ofb_procname);
  FuncLoadError := not assigned(EVP_aria_128_ofb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aria_128_ofb_allownil)}
    EVP_aria_128_ofb := ERR_EVP_aria_128_ofb;
    {$ifend}
    {$if declared(EVP_aria_128_ofb_introduced)}
    if LibVersion < EVP_aria_128_ofb_introduced then
    begin
      {$if declared(FC_EVP_aria_128_ofb)}
      EVP_aria_128_ofb := FC_EVP_aria_128_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aria_128_ofb_removed)}
    if EVP_aria_128_ofb_removed <= LibVersion then
    begin
      {$if declared(_EVP_aria_128_ofb)}
      EVP_aria_128_ofb := _EVP_aria_128_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aria_128_ofb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aria_128_ofb');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aria_128_gcm := LoadLibFunction(ADllHandle, EVP_aria_128_gcm_procname);
  FuncLoadError := not assigned(EVP_aria_128_gcm);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aria_128_gcm_allownil)}
    EVP_aria_128_gcm := ERR_EVP_aria_128_gcm;
    {$ifend}
    {$if declared(EVP_aria_128_gcm_introduced)}
    if LibVersion < EVP_aria_128_gcm_introduced then
    begin
      {$if declared(FC_EVP_aria_128_gcm)}
      EVP_aria_128_gcm := FC_EVP_aria_128_gcm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aria_128_gcm_removed)}
    if EVP_aria_128_gcm_removed <= LibVersion then
    begin
      {$if declared(_EVP_aria_128_gcm)}
      EVP_aria_128_gcm := _EVP_aria_128_gcm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aria_128_gcm_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aria_128_gcm');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aria_128_ccm := LoadLibFunction(ADllHandle, EVP_aria_128_ccm_procname);
  FuncLoadError := not assigned(EVP_aria_128_ccm);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aria_128_ccm_allownil)}
    EVP_aria_128_ccm := ERR_EVP_aria_128_ccm;
    {$ifend}
    {$if declared(EVP_aria_128_ccm_introduced)}
    if LibVersion < EVP_aria_128_ccm_introduced then
    begin
      {$if declared(FC_EVP_aria_128_ccm)}
      EVP_aria_128_ccm := FC_EVP_aria_128_ccm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aria_128_ccm_removed)}
    if EVP_aria_128_ccm_removed <= LibVersion then
    begin
      {$if declared(_EVP_aria_128_ccm)}
      EVP_aria_128_ccm := _EVP_aria_128_ccm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aria_128_ccm_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aria_128_ccm');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aria_192_ecb := LoadLibFunction(ADllHandle, EVP_aria_192_ecb_procname);
  FuncLoadError := not assigned(EVP_aria_192_ecb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aria_192_ecb_allownil)}
    EVP_aria_192_ecb := ERR_EVP_aria_192_ecb;
    {$ifend}
    {$if declared(EVP_aria_192_ecb_introduced)}
    if LibVersion < EVP_aria_192_ecb_introduced then
    begin
      {$if declared(FC_EVP_aria_192_ecb)}
      EVP_aria_192_ecb := FC_EVP_aria_192_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aria_192_ecb_removed)}
    if EVP_aria_192_ecb_removed <= LibVersion then
    begin
      {$if declared(_EVP_aria_192_ecb)}
      EVP_aria_192_ecb := _EVP_aria_192_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aria_192_ecb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aria_192_ecb');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aria_192_cbc := LoadLibFunction(ADllHandle, EVP_aria_192_cbc_procname);
  FuncLoadError := not assigned(EVP_aria_192_cbc);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aria_192_cbc_allownil)}
    EVP_aria_192_cbc := ERR_EVP_aria_192_cbc;
    {$ifend}
    {$if declared(EVP_aria_192_cbc_introduced)}
    if LibVersion < EVP_aria_192_cbc_introduced then
    begin
      {$if declared(FC_EVP_aria_192_cbc)}
      EVP_aria_192_cbc := FC_EVP_aria_192_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aria_192_cbc_removed)}
    if EVP_aria_192_cbc_removed <= LibVersion then
    begin
      {$if declared(_EVP_aria_192_cbc)}
      EVP_aria_192_cbc := _EVP_aria_192_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aria_192_cbc_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aria_192_cbc');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aria_192_cfb1 := LoadLibFunction(ADllHandle, EVP_aria_192_cfb1_procname);
  FuncLoadError := not assigned(EVP_aria_192_cfb1);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aria_192_cfb1_allownil)}
    EVP_aria_192_cfb1 := ERR_EVP_aria_192_cfb1;
    {$ifend}
    {$if declared(EVP_aria_192_cfb1_introduced)}
    if LibVersion < EVP_aria_192_cfb1_introduced then
    begin
      {$if declared(FC_EVP_aria_192_cfb1)}
      EVP_aria_192_cfb1 := FC_EVP_aria_192_cfb1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aria_192_cfb1_removed)}
    if EVP_aria_192_cfb1_removed <= LibVersion then
    begin
      {$if declared(_EVP_aria_192_cfb1)}
      EVP_aria_192_cfb1 := _EVP_aria_192_cfb1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aria_192_cfb1_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aria_192_cfb1');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aria_192_cfb8 := LoadLibFunction(ADllHandle, EVP_aria_192_cfb8_procname);
  FuncLoadError := not assigned(EVP_aria_192_cfb8);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aria_192_cfb8_allownil)}
    EVP_aria_192_cfb8 := ERR_EVP_aria_192_cfb8;
    {$ifend}
    {$if declared(EVP_aria_192_cfb8_introduced)}
    if LibVersion < EVP_aria_192_cfb8_introduced then
    begin
      {$if declared(FC_EVP_aria_192_cfb8)}
      EVP_aria_192_cfb8 := FC_EVP_aria_192_cfb8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aria_192_cfb8_removed)}
    if EVP_aria_192_cfb8_removed <= LibVersion then
    begin
      {$if declared(_EVP_aria_192_cfb8)}
      EVP_aria_192_cfb8 := _EVP_aria_192_cfb8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aria_192_cfb8_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aria_192_cfb8');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aria_192_cfb128 := LoadLibFunction(ADllHandle, EVP_aria_192_cfb128_procname);
  FuncLoadError := not assigned(EVP_aria_192_cfb128);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aria_192_cfb128_allownil)}
    EVP_aria_192_cfb128 := ERR_EVP_aria_192_cfb128;
    {$ifend}
    {$if declared(EVP_aria_192_cfb128_introduced)}
    if LibVersion < EVP_aria_192_cfb128_introduced then
    begin
      {$if declared(FC_EVP_aria_192_cfb128)}
      EVP_aria_192_cfb128 := FC_EVP_aria_192_cfb128;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aria_192_cfb128_removed)}
    if EVP_aria_192_cfb128_removed <= LibVersion then
    begin
      {$if declared(_EVP_aria_192_cfb128)}
      EVP_aria_192_cfb128 := _EVP_aria_192_cfb128;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aria_192_cfb128_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aria_192_cfb128');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aria_192_ctr := LoadLibFunction(ADllHandle, EVP_aria_192_ctr_procname);
  FuncLoadError := not assigned(EVP_aria_192_ctr);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aria_192_ctr_allownil)}
    EVP_aria_192_ctr := ERR_EVP_aria_192_ctr;
    {$ifend}
    {$if declared(EVP_aria_192_ctr_introduced)}
    if LibVersion < EVP_aria_192_ctr_introduced then
    begin
      {$if declared(FC_EVP_aria_192_ctr)}
      EVP_aria_192_ctr := FC_EVP_aria_192_ctr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aria_192_ctr_removed)}
    if EVP_aria_192_ctr_removed <= LibVersion then
    begin
      {$if declared(_EVP_aria_192_ctr)}
      EVP_aria_192_ctr := _EVP_aria_192_ctr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aria_192_ctr_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aria_192_ctr');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aria_192_ofb := LoadLibFunction(ADllHandle, EVP_aria_192_ofb_procname);
  FuncLoadError := not assigned(EVP_aria_192_ofb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aria_192_ofb_allownil)}
    EVP_aria_192_ofb := ERR_EVP_aria_192_ofb;
    {$ifend}
    {$if declared(EVP_aria_192_ofb_introduced)}
    if LibVersion < EVP_aria_192_ofb_introduced then
    begin
      {$if declared(FC_EVP_aria_192_ofb)}
      EVP_aria_192_ofb := FC_EVP_aria_192_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aria_192_ofb_removed)}
    if EVP_aria_192_ofb_removed <= LibVersion then
    begin
      {$if declared(_EVP_aria_192_ofb)}
      EVP_aria_192_ofb := _EVP_aria_192_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aria_192_ofb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aria_192_ofb');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aria_192_gcm := LoadLibFunction(ADllHandle, EVP_aria_192_gcm_procname);
  FuncLoadError := not assigned(EVP_aria_192_gcm);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aria_192_gcm_allownil)}
    EVP_aria_192_gcm := ERR_EVP_aria_192_gcm;
    {$ifend}
    {$if declared(EVP_aria_192_gcm_introduced)}
    if LibVersion < EVP_aria_192_gcm_introduced then
    begin
      {$if declared(FC_EVP_aria_192_gcm)}
      EVP_aria_192_gcm := FC_EVP_aria_192_gcm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aria_192_gcm_removed)}
    if EVP_aria_192_gcm_removed <= LibVersion then
    begin
      {$if declared(_EVP_aria_192_gcm)}
      EVP_aria_192_gcm := _EVP_aria_192_gcm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aria_192_gcm_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aria_192_gcm');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aria_192_ccm := LoadLibFunction(ADllHandle, EVP_aria_192_ccm_procname);
  FuncLoadError := not assigned(EVP_aria_192_ccm);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aria_192_ccm_allownil)}
    EVP_aria_192_ccm := ERR_EVP_aria_192_ccm;
    {$ifend}
    {$if declared(EVP_aria_192_ccm_introduced)}
    if LibVersion < EVP_aria_192_ccm_introduced then
    begin
      {$if declared(FC_EVP_aria_192_ccm)}
      EVP_aria_192_ccm := FC_EVP_aria_192_ccm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aria_192_ccm_removed)}
    if EVP_aria_192_ccm_removed <= LibVersion then
    begin
      {$if declared(_EVP_aria_192_ccm)}
      EVP_aria_192_ccm := _EVP_aria_192_ccm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aria_192_ccm_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aria_192_ccm');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aria_256_ecb := LoadLibFunction(ADllHandle, EVP_aria_256_ecb_procname);
  FuncLoadError := not assigned(EVP_aria_256_ecb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aria_256_ecb_allownil)}
    EVP_aria_256_ecb := ERR_EVP_aria_256_ecb;
    {$ifend}
    {$if declared(EVP_aria_256_ecb_introduced)}
    if LibVersion < EVP_aria_256_ecb_introduced then
    begin
      {$if declared(FC_EVP_aria_256_ecb)}
      EVP_aria_256_ecb := FC_EVP_aria_256_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aria_256_ecb_removed)}
    if EVP_aria_256_ecb_removed <= LibVersion then
    begin
      {$if declared(_EVP_aria_256_ecb)}
      EVP_aria_256_ecb := _EVP_aria_256_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aria_256_ecb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aria_256_ecb');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aria_256_cbc := LoadLibFunction(ADllHandle, EVP_aria_256_cbc_procname);
  FuncLoadError := not assigned(EVP_aria_256_cbc);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aria_256_cbc_allownil)}
    EVP_aria_256_cbc := ERR_EVP_aria_256_cbc;
    {$ifend}
    {$if declared(EVP_aria_256_cbc_introduced)}
    if LibVersion < EVP_aria_256_cbc_introduced then
    begin
      {$if declared(FC_EVP_aria_256_cbc)}
      EVP_aria_256_cbc := FC_EVP_aria_256_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aria_256_cbc_removed)}
    if EVP_aria_256_cbc_removed <= LibVersion then
    begin
      {$if declared(_EVP_aria_256_cbc)}
      EVP_aria_256_cbc := _EVP_aria_256_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aria_256_cbc_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aria_256_cbc');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aria_256_cfb1 := LoadLibFunction(ADllHandle, EVP_aria_256_cfb1_procname);
  FuncLoadError := not assigned(EVP_aria_256_cfb1);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aria_256_cfb1_allownil)}
    EVP_aria_256_cfb1 := ERR_EVP_aria_256_cfb1;
    {$ifend}
    {$if declared(EVP_aria_256_cfb1_introduced)}
    if LibVersion < EVP_aria_256_cfb1_introduced then
    begin
      {$if declared(FC_EVP_aria_256_cfb1)}
      EVP_aria_256_cfb1 := FC_EVP_aria_256_cfb1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aria_256_cfb1_removed)}
    if EVP_aria_256_cfb1_removed <= LibVersion then
    begin
      {$if declared(_EVP_aria_256_cfb1)}
      EVP_aria_256_cfb1 := _EVP_aria_256_cfb1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aria_256_cfb1_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aria_256_cfb1');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aria_256_cfb8 := LoadLibFunction(ADllHandle, EVP_aria_256_cfb8_procname);
  FuncLoadError := not assigned(EVP_aria_256_cfb8);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aria_256_cfb8_allownil)}
    EVP_aria_256_cfb8 := ERR_EVP_aria_256_cfb8;
    {$ifend}
    {$if declared(EVP_aria_256_cfb8_introduced)}
    if LibVersion < EVP_aria_256_cfb8_introduced then
    begin
      {$if declared(FC_EVP_aria_256_cfb8)}
      EVP_aria_256_cfb8 := FC_EVP_aria_256_cfb8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aria_256_cfb8_removed)}
    if EVP_aria_256_cfb8_removed <= LibVersion then
    begin
      {$if declared(_EVP_aria_256_cfb8)}
      EVP_aria_256_cfb8 := _EVP_aria_256_cfb8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aria_256_cfb8_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aria_256_cfb8');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aria_256_cfb128 := LoadLibFunction(ADllHandle, EVP_aria_256_cfb128_procname);
  FuncLoadError := not assigned(EVP_aria_256_cfb128);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aria_256_cfb128_allownil)}
    EVP_aria_256_cfb128 := ERR_EVP_aria_256_cfb128;
    {$ifend}
    {$if declared(EVP_aria_256_cfb128_introduced)}
    if LibVersion < EVP_aria_256_cfb128_introduced then
    begin
      {$if declared(FC_EVP_aria_256_cfb128)}
      EVP_aria_256_cfb128 := FC_EVP_aria_256_cfb128;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aria_256_cfb128_removed)}
    if EVP_aria_256_cfb128_removed <= LibVersion then
    begin
      {$if declared(_EVP_aria_256_cfb128)}
      EVP_aria_256_cfb128 := _EVP_aria_256_cfb128;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aria_256_cfb128_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aria_256_cfb128');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aria_256_ctr := LoadLibFunction(ADllHandle, EVP_aria_256_ctr_procname);
  FuncLoadError := not assigned(EVP_aria_256_ctr);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aria_256_ctr_allownil)}
    EVP_aria_256_ctr := ERR_EVP_aria_256_ctr;
    {$ifend}
    {$if declared(EVP_aria_256_ctr_introduced)}
    if LibVersion < EVP_aria_256_ctr_introduced then
    begin
      {$if declared(FC_EVP_aria_256_ctr)}
      EVP_aria_256_ctr := FC_EVP_aria_256_ctr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aria_256_ctr_removed)}
    if EVP_aria_256_ctr_removed <= LibVersion then
    begin
      {$if declared(_EVP_aria_256_ctr)}
      EVP_aria_256_ctr := _EVP_aria_256_ctr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aria_256_ctr_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aria_256_ctr');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aria_256_ofb := LoadLibFunction(ADllHandle, EVP_aria_256_ofb_procname);
  FuncLoadError := not assigned(EVP_aria_256_ofb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aria_256_ofb_allownil)}
    EVP_aria_256_ofb := ERR_EVP_aria_256_ofb;
    {$ifend}
    {$if declared(EVP_aria_256_ofb_introduced)}
    if LibVersion < EVP_aria_256_ofb_introduced then
    begin
      {$if declared(FC_EVP_aria_256_ofb)}
      EVP_aria_256_ofb := FC_EVP_aria_256_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aria_256_ofb_removed)}
    if EVP_aria_256_ofb_removed <= LibVersion then
    begin
      {$if declared(_EVP_aria_256_ofb)}
      EVP_aria_256_ofb := _EVP_aria_256_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aria_256_ofb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aria_256_ofb');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aria_256_gcm := LoadLibFunction(ADllHandle, EVP_aria_256_gcm_procname);
  FuncLoadError := not assigned(EVP_aria_256_gcm);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aria_256_gcm_allownil)}
    EVP_aria_256_gcm := ERR_EVP_aria_256_gcm;
    {$ifend}
    {$if declared(EVP_aria_256_gcm_introduced)}
    if LibVersion < EVP_aria_256_gcm_introduced then
    begin
      {$if declared(FC_EVP_aria_256_gcm)}
      EVP_aria_256_gcm := FC_EVP_aria_256_gcm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aria_256_gcm_removed)}
    if EVP_aria_256_gcm_removed <= LibVersion then
    begin
      {$if declared(_EVP_aria_256_gcm)}
      EVP_aria_256_gcm := _EVP_aria_256_gcm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aria_256_gcm_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aria_256_gcm');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_aria_256_ccm := LoadLibFunction(ADllHandle, EVP_aria_256_ccm_procname);
  FuncLoadError := not assigned(EVP_aria_256_ccm);
  if FuncLoadError then
  begin
    {$if not defined(EVP_aria_256_ccm_allownil)}
    EVP_aria_256_ccm := ERR_EVP_aria_256_ccm;
    {$ifend}
    {$if declared(EVP_aria_256_ccm_introduced)}
    if LibVersion < EVP_aria_256_ccm_introduced then
    begin
      {$if declared(FC_EVP_aria_256_ccm)}
      EVP_aria_256_ccm := FC_EVP_aria_256_ccm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_aria_256_ccm_removed)}
    if EVP_aria_256_ccm_removed <= LibVersion then
    begin
      {$if declared(_EVP_aria_256_ccm)}
      EVP_aria_256_ccm := _EVP_aria_256_ccm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_aria_256_ccm_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_aria_256_ccm');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_camellia_128_ecb := LoadLibFunction(ADllHandle, EVP_camellia_128_ecb_procname);
  FuncLoadError := not assigned(EVP_camellia_128_ecb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_camellia_128_ecb_allownil)}
    EVP_camellia_128_ecb := ERR_EVP_camellia_128_ecb;
    {$ifend}
    {$if declared(EVP_camellia_128_ecb_introduced)}
    if LibVersion < EVP_camellia_128_ecb_introduced then
    begin
      {$if declared(FC_EVP_camellia_128_ecb)}
      EVP_camellia_128_ecb := FC_EVP_camellia_128_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_camellia_128_ecb_removed)}
    if EVP_camellia_128_ecb_removed <= LibVersion then
    begin
      {$if declared(_EVP_camellia_128_ecb)}
      EVP_camellia_128_ecb := _EVP_camellia_128_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_camellia_128_ecb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_camellia_128_ecb');
    {$ifend}
  end;


  EVP_camellia_128_cbc := LoadLibFunction(ADllHandle, EVP_camellia_128_cbc_procname);
  FuncLoadError := not assigned(EVP_camellia_128_cbc);
  if FuncLoadError then
  begin
    {$if not defined(EVP_camellia_128_cbc_allownil)}
    EVP_camellia_128_cbc := ERR_EVP_camellia_128_cbc;
    {$ifend}
    {$if declared(EVP_camellia_128_cbc_introduced)}
    if LibVersion < EVP_camellia_128_cbc_introduced then
    begin
      {$if declared(FC_EVP_camellia_128_cbc)}
      EVP_camellia_128_cbc := FC_EVP_camellia_128_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_camellia_128_cbc_removed)}
    if EVP_camellia_128_cbc_removed <= LibVersion then
    begin
      {$if declared(_EVP_camellia_128_cbc)}
      EVP_camellia_128_cbc := _EVP_camellia_128_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_camellia_128_cbc_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_camellia_128_cbc');
    {$ifend}
  end;


  EVP_camellia_128_cfb1 := LoadLibFunction(ADllHandle, EVP_camellia_128_cfb1_procname);
  FuncLoadError := not assigned(EVP_camellia_128_cfb1);
  if FuncLoadError then
  begin
    {$if not defined(EVP_camellia_128_cfb1_allownil)}
    EVP_camellia_128_cfb1 := ERR_EVP_camellia_128_cfb1;
    {$ifend}
    {$if declared(EVP_camellia_128_cfb1_introduced)}
    if LibVersion < EVP_camellia_128_cfb1_introduced then
    begin
      {$if declared(FC_EVP_camellia_128_cfb1)}
      EVP_camellia_128_cfb1 := FC_EVP_camellia_128_cfb1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_camellia_128_cfb1_removed)}
    if EVP_camellia_128_cfb1_removed <= LibVersion then
    begin
      {$if declared(_EVP_camellia_128_cfb1)}
      EVP_camellia_128_cfb1 := _EVP_camellia_128_cfb1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_camellia_128_cfb1_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_camellia_128_cfb1');
    {$ifend}
  end;


  EVP_camellia_128_cfb8 := LoadLibFunction(ADllHandle, EVP_camellia_128_cfb8_procname);
  FuncLoadError := not assigned(EVP_camellia_128_cfb8);
  if FuncLoadError then
  begin
    {$if not defined(EVP_camellia_128_cfb8_allownil)}
    EVP_camellia_128_cfb8 := ERR_EVP_camellia_128_cfb8;
    {$ifend}
    {$if declared(EVP_camellia_128_cfb8_introduced)}
    if LibVersion < EVP_camellia_128_cfb8_introduced then
    begin
      {$if declared(FC_EVP_camellia_128_cfb8)}
      EVP_camellia_128_cfb8 := FC_EVP_camellia_128_cfb8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_camellia_128_cfb8_removed)}
    if EVP_camellia_128_cfb8_removed <= LibVersion then
    begin
      {$if declared(_EVP_camellia_128_cfb8)}
      EVP_camellia_128_cfb8 := _EVP_camellia_128_cfb8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_camellia_128_cfb8_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_camellia_128_cfb8');
    {$ifend}
  end;


  EVP_camellia_128_cfb128 := LoadLibFunction(ADllHandle, EVP_camellia_128_cfb128_procname);
  FuncLoadError := not assigned(EVP_camellia_128_cfb128);
  if FuncLoadError then
  begin
    {$if not defined(EVP_camellia_128_cfb128_allownil)}
    EVP_camellia_128_cfb128 := ERR_EVP_camellia_128_cfb128;
    {$ifend}
    {$if declared(EVP_camellia_128_cfb128_introduced)}
    if LibVersion < EVP_camellia_128_cfb128_introduced then
    begin
      {$if declared(FC_EVP_camellia_128_cfb128)}
      EVP_camellia_128_cfb128 := FC_EVP_camellia_128_cfb128;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_camellia_128_cfb128_removed)}
    if EVP_camellia_128_cfb128_removed <= LibVersion then
    begin
      {$if declared(_EVP_camellia_128_cfb128)}
      EVP_camellia_128_cfb128 := _EVP_camellia_128_cfb128;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_camellia_128_cfb128_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_camellia_128_cfb128');
    {$ifend}
  end;


  EVP_camellia_128_ofb := LoadLibFunction(ADllHandle, EVP_camellia_128_ofb_procname);
  FuncLoadError := not assigned(EVP_camellia_128_ofb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_camellia_128_ofb_allownil)}
    EVP_camellia_128_ofb := ERR_EVP_camellia_128_ofb;
    {$ifend}
    {$if declared(EVP_camellia_128_ofb_introduced)}
    if LibVersion < EVP_camellia_128_ofb_introduced then
    begin
      {$if declared(FC_EVP_camellia_128_ofb)}
      EVP_camellia_128_ofb := FC_EVP_camellia_128_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_camellia_128_ofb_removed)}
    if EVP_camellia_128_ofb_removed <= LibVersion then
    begin
      {$if declared(_EVP_camellia_128_ofb)}
      EVP_camellia_128_ofb := _EVP_camellia_128_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_camellia_128_ofb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_camellia_128_ofb');
    {$ifend}
  end;


  EVP_camellia_128_ctr := LoadLibFunction(ADllHandle, EVP_camellia_128_ctr_procname);
  FuncLoadError := not assigned(EVP_camellia_128_ctr);
  if FuncLoadError then
  begin
    {$if not defined(EVP_camellia_128_ctr_allownil)}
    EVP_camellia_128_ctr := ERR_EVP_camellia_128_ctr;
    {$ifend}
    {$if declared(EVP_camellia_128_ctr_introduced)}
    if LibVersion < EVP_camellia_128_ctr_introduced then
    begin
      {$if declared(FC_EVP_camellia_128_ctr)}
      EVP_camellia_128_ctr := FC_EVP_camellia_128_ctr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_camellia_128_ctr_removed)}
    if EVP_camellia_128_ctr_removed <= LibVersion then
    begin
      {$if declared(_EVP_camellia_128_ctr)}
      EVP_camellia_128_ctr := _EVP_camellia_128_ctr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_camellia_128_ctr_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_camellia_128_ctr');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_camellia_192_ecb := LoadLibFunction(ADllHandle, EVP_camellia_192_ecb_procname);
  FuncLoadError := not assigned(EVP_camellia_192_ecb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_camellia_192_ecb_allownil)}
    EVP_camellia_192_ecb := ERR_EVP_camellia_192_ecb;
    {$ifend}
    {$if declared(EVP_camellia_192_ecb_introduced)}
    if LibVersion < EVP_camellia_192_ecb_introduced then
    begin
      {$if declared(FC_EVP_camellia_192_ecb)}
      EVP_camellia_192_ecb := FC_EVP_camellia_192_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_camellia_192_ecb_removed)}
    if EVP_camellia_192_ecb_removed <= LibVersion then
    begin
      {$if declared(_EVP_camellia_192_ecb)}
      EVP_camellia_192_ecb := _EVP_camellia_192_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_camellia_192_ecb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_camellia_192_ecb');
    {$ifend}
  end;


  EVP_camellia_192_cbc := LoadLibFunction(ADllHandle, EVP_camellia_192_cbc_procname);
  FuncLoadError := not assigned(EVP_camellia_192_cbc);
  if FuncLoadError then
  begin
    {$if not defined(EVP_camellia_192_cbc_allownil)}
    EVP_camellia_192_cbc := ERR_EVP_camellia_192_cbc;
    {$ifend}
    {$if declared(EVP_camellia_192_cbc_introduced)}
    if LibVersion < EVP_camellia_192_cbc_introduced then
    begin
      {$if declared(FC_EVP_camellia_192_cbc)}
      EVP_camellia_192_cbc := FC_EVP_camellia_192_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_camellia_192_cbc_removed)}
    if EVP_camellia_192_cbc_removed <= LibVersion then
    begin
      {$if declared(_EVP_camellia_192_cbc)}
      EVP_camellia_192_cbc := _EVP_camellia_192_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_camellia_192_cbc_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_camellia_192_cbc');
    {$ifend}
  end;


  EVP_camellia_192_cfb1 := LoadLibFunction(ADllHandle, EVP_camellia_192_cfb1_procname);
  FuncLoadError := not assigned(EVP_camellia_192_cfb1);
  if FuncLoadError then
  begin
    {$if not defined(EVP_camellia_192_cfb1_allownil)}
    EVP_camellia_192_cfb1 := ERR_EVP_camellia_192_cfb1;
    {$ifend}
    {$if declared(EVP_camellia_192_cfb1_introduced)}
    if LibVersion < EVP_camellia_192_cfb1_introduced then
    begin
      {$if declared(FC_EVP_camellia_192_cfb1)}
      EVP_camellia_192_cfb1 := FC_EVP_camellia_192_cfb1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_camellia_192_cfb1_removed)}
    if EVP_camellia_192_cfb1_removed <= LibVersion then
    begin
      {$if declared(_EVP_camellia_192_cfb1)}
      EVP_camellia_192_cfb1 := _EVP_camellia_192_cfb1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_camellia_192_cfb1_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_camellia_192_cfb1');
    {$ifend}
  end;


  EVP_camellia_192_cfb8 := LoadLibFunction(ADllHandle, EVP_camellia_192_cfb8_procname);
  FuncLoadError := not assigned(EVP_camellia_192_cfb8);
  if FuncLoadError then
  begin
    {$if not defined(EVP_camellia_192_cfb8_allownil)}
    EVP_camellia_192_cfb8 := ERR_EVP_camellia_192_cfb8;
    {$ifend}
    {$if declared(EVP_camellia_192_cfb8_introduced)}
    if LibVersion < EVP_camellia_192_cfb8_introduced then
    begin
      {$if declared(FC_EVP_camellia_192_cfb8)}
      EVP_camellia_192_cfb8 := FC_EVP_camellia_192_cfb8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_camellia_192_cfb8_removed)}
    if EVP_camellia_192_cfb8_removed <= LibVersion then
    begin
      {$if declared(_EVP_camellia_192_cfb8)}
      EVP_camellia_192_cfb8 := _EVP_camellia_192_cfb8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_camellia_192_cfb8_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_camellia_192_cfb8');
    {$ifend}
  end;


  EVP_camellia_192_cfb128 := LoadLibFunction(ADllHandle, EVP_camellia_192_cfb128_procname);
  FuncLoadError := not assigned(EVP_camellia_192_cfb128);
  if FuncLoadError then
  begin
    {$if not defined(EVP_camellia_192_cfb128_allownil)}
    EVP_camellia_192_cfb128 := ERR_EVP_camellia_192_cfb128;
    {$ifend}
    {$if declared(EVP_camellia_192_cfb128_introduced)}
    if LibVersion < EVP_camellia_192_cfb128_introduced then
    begin
      {$if declared(FC_EVP_camellia_192_cfb128)}
      EVP_camellia_192_cfb128 := FC_EVP_camellia_192_cfb128;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_camellia_192_cfb128_removed)}
    if EVP_camellia_192_cfb128_removed <= LibVersion then
    begin
      {$if declared(_EVP_camellia_192_cfb128)}
      EVP_camellia_192_cfb128 := _EVP_camellia_192_cfb128;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_camellia_192_cfb128_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_camellia_192_cfb128');
    {$ifend}
  end;


  EVP_camellia_192_ofb := LoadLibFunction(ADllHandle, EVP_camellia_192_ofb_procname);
  FuncLoadError := not assigned(EVP_camellia_192_ofb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_camellia_192_ofb_allownil)}
    EVP_camellia_192_ofb := ERR_EVP_camellia_192_ofb;
    {$ifend}
    {$if declared(EVP_camellia_192_ofb_introduced)}
    if LibVersion < EVP_camellia_192_ofb_introduced then
    begin
      {$if declared(FC_EVP_camellia_192_ofb)}
      EVP_camellia_192_ofb := FC_EVP_camellia_192_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_camellia_192_ofb_removed)}
    if EVP_camellia_192_ofb_removed <= LibVersion then
    begin
      {$if declared(_EVP_camellia_192_ofb)}
      EVP_camellia_192_ofb := _EVP_camellia_192_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_camellia_192_ofb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_camellia_192_ofb');
    {$ifend}
  end;


  EVP_camellia_192_ctr := LoadLibFunction(ADllHandle, EVP_camellia_192_ctr_procname);
  FuncLoadError := not assigned(EVP_camellia_192_ctr);
  if FuncLoadError then
  begin
    {$if not defined(EVP_camellia_192_ctr_allownil)}
    EVP_camellia_192_ctr := ERR_EVP_camellia_192_ctr;
    {$ifend}
    {$if declared(EVP_camellia_192_ctr_introduced)}
    if LibVersion < EVP_camellia_192_ctr_introduced then
    begin
      {$if declared(FC_EVP_camellia_192_ctr)}
      EVP_camellia_192_ctr := FC_EVP_camellia_192_ctr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_camellia_192_ctr_removed)}
    if EVP_camellia_192_ctr_removed <= LibVersion then
    begin
      {$if declared(_EVP_camellia_192_ctr)}
      EVP_camellia_192_ctr := _EVP_camellia_192_ctr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_camellia_192_ctr_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_camellia_192_ctr');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_camellia_256_ecb := LoadLibFunction(ADllHandle, EVP_camellia_256_ecb_procname);
  FuncLoadError := not assigned(EVP_camellia_256_ecb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_camellia_256_ecb_allownil)}
    EVP_camellia_256_ecb := ERR_EVP_camellia_256_ecb;
    {$ifend}
    {$if declared(EVP_camellia_256_ecb_introduced)}
    if LibVersion < EVP_camellia_256_ecb_introduced then
    begin
      {$if declared(FC_EVP_camellia_256_ecb)}
      EVP_camellia_256_ecb := FC_EVP_camellia_256_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_camellia_256_ecb_removed)}
    if EVP_camellia_256_ecb_removed <= LibVersion then
    begin
      {$if declared(_EVP_camellia_256_ecb)}
      EVP_camellia_256_ecb := _EVP_camellia_256_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_camellia_256_ecb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_camellia_256_ecb');
    {$ifend}
  end;


  EVP_camellia_256_cbc := LoadLibFunction(ADllHandle, EVP_camellia_256_cbc_procname);
  FuncLoadError := not assigned(EVP_camellia_256_cbc);
  if FuncLoadError then
  begin
    {$if not defined(EVP_camellia_256_cbc_allownil)}
    EVP_camellia_256_cbc := ERR_EVP_camellia_256_cbc;
    {$ifend}
    {$if declared(EVP_camellia_256_cbc_introduced)}
    if LibVersion < EVP_camellia_256_cbc_introduced then
    begin
      {$if declared(FC_EVP_camellia_256_cbc)}
      EVP_camellia_256_cbc := FC_EVP_camellia_256_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_camellia_256_cbc_removed)}
    if EVP_camellia_256_cbc_removed <= LibVersion then
    begin
      {$if declared(_EVP_camellia_256_cbc)}
      EVP_camellia_256_cbc := _EVP_camellia_256_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_camellia_256_cbc_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_camellia_256_cbc');
    {$ifend}
  end;


  EVP_camellia_256_cfb1 := LoadLibFunction(ADllHandle, EVP_camellia_256_cfb1_procname);
  FuncLoadError := not assigned(EVP_camellia_256_cfb1);
  if FuncLoadError then
  begin
    {$if not defined(EVP_camellia_256_cfb1_allownil)}
    EVP_camellia_256_cfb1 := ERR_EVP_camellia_256_cfb1;
    {$ifend}
    {$if declared(EVP_camellia_256_cfb1_introduced)}
    if LibVersion < EVP_camellia_256_cfb1_introduced then
    begin
      {$if declared(FC_EVP_camellia_256_cfb1)}
      EVP_camellia_256_cfb1 := FC_EVP_camellia_256_cfb1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_camellia_256_cfb1_removed)}
    if EVP_camellia_256_cfb1_removed <= LibVersion then
    begin
      {$if declared(_EVP_camellia_256_cfb1)}
      EVP_camellia_256_cfb1 := _EVP_camellia_256_cfb1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_camellia_256_cfb1_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_camellia_256_cfb1');
    {$ifend}
  end;


  EVP_camellia_256_cfb8 := LoadLibFunction(ADllHandle, EVP_camellia_256_cfb8_procname);
  FuncLoadError := not assigned(EVP_camellia_256_cfb8);
  if FuncLoadError then
  begin
    {$if not defined(EVP_camellia_256_cfb8_allownil)}
    EVP_camellia_256_cfb8 := ERR_EVP_camellia_256_cfb8;
    {$ifend}
    {$if declared(EVP_camellia_256_cfb8_introduced)}
    if LibVersion < EVP_camellia_256_cfb8_introduced then
    begin
      {$if declared(FC_EVP_camellia_256_cfb8)}
      EVP_camellia_256_cfb8 := FC_EVP_camellia_256_cfb8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_camellia_256_cfb8_removed)}
    if EVP_camellia_256_cfb8_removed <= LibVersion then
    begin
      {$if declared(_EVP_camellia_256_cfb8)}
      EVP_camellia_256_cfb8 := _EVP_camellia_256_cfb8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_camellia_256_cfb8_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_camellia_256_cfb8');
    {$ifend}
  end;


  EVP_camellia_256_cfb128 := LoadLibFunction(ADllHandle, EVP_camellia_256_cfb128_procname);
  FuncLoadError := not assigned(EVP_camellia_256_cfb128);
  if FuncLoadError then
  begin
    {$if not defined(EVP_camellia_256_cfb128_allownil)}
    EVP_camellia_256_cfb128 := ERR_EVP_camellia_256_cfb128;
    {$ifend}
    {$if declared(EVP_camellia_256_cfb128_introduced)}
    if LibVersion < EVP_camellia_256_cfb128_introduced then
    begin
      {$if declared(FC_EVP_camellia_256_cfb128)}
      EVP_camellia_256_cfb128 := FC_EVP_camellia_256_cfb128;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_camellia_256_cfb128_removed)}
    if EVP_camellia_256_cfb128_removed <= LibVersion then
    begin
      {$if declared(_EVP_camellia_256_cfb128)}
      EVP_camellia_256_cfb128 := _EVP_camellia_256_cfb128;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_camellia_256_cfb128_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_camellia_256_cfb128');
    {$ifend}
  end;


  EVP_camellia_256_ofb := LoadLibFunction(ADllHandle, EVP_camellia_256_ofb_procname);
  FuncLoadError := not assigned(EVP_camellia_256_ofb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_camellia_256_ofb_allownil)}
    EVP_camellia_256_ofb := ERR_EVP_camellia_256_ofb;
    {$ifend}
    {$if declared(EVP_camellia_256_ofb_introduced)}
    if LibVersion < EVP_camellia_256_ofb_introduced then
    begin
      {$if declared(FC_EVP_camellia_256_ofb)}
      EVP_camellia_256_ofb := FC_EVP_camellia_256_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_camellia_256_ofb_removed)}
    if EVP_camellia_256_ofb_removed <= LibVersion then
    begin
      {$if declared(_EVP_camellia_256_ofb)}
      EVP_camellia_256_ofb := _EVP_camellia_256_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_camellia_256_ofb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_camellia_256_ofb');
    {$ifend}
  end;


  EVP_camellia_256_ctr := LoadLibFunction(ADllHandle, EVP_camellia_256_ctr_procname);
  FuncLoadError := not assigned(EVP_camellia_256_ctr);
  if FuncLoadError then
  begin
    {$if not defined(EVP_camellia_256_ctr_allownil)}
    EVP_camellia_256_ctr := ERR_EVP_camellia_256_ctr;
    {$ifend}
    {$if declared(EVP_camellia_256_ctr_introduced)}
    if LibVersion < EVP_camellia_256_ctr_introduced then
    begin
      {$if declared(FC_EVP_camellia_256_ctr)}
      EVP_camellia_256_ctr := FC_EVP_camellia_256_ctr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_camellia_256_ctr_removed)}
    if EVP_camellia_256_ctr_removed <= LibVersion then
    begin
      {$if declared(_EVP_camellia_256_ctr)}
      EVP_camellia_256_ctr := _EVP_camellia_256_ctr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_camellia_256_ctr_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_camellia_256_ctr');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_chacha20 := LoadLibFunction(ADllHandle, EVP_chacha20_procname);
  FuncLoadError := not assigned(EVP_chacha20);
  if FuncLoadError then
  begin
    {$if not defined(EVP_chacha20_allownil)}
    EVP_chacha20 := ERR_EVP_chacha20;
    {$ifend}
    {$if declared(EVP_chacha20_introduced)}
    if LibVersion < EVP_chacha20_introduced then
    begin
      {$if declared(FC_EVP_chacha20)}
      EVP_chacha20 := FC_EVP_chacha20;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_chacha20_removed)}
    if EVP_chacha20_removed <= LibVersion then
    begin
      {$if declared(_EVP_chacha20)}
      EVP_chacha20 := _EVP_chacha20;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_chacha20_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_chacha20');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_chacha20_poly1305 := LoadLibFunction(ADllHandle, EVP_chacha20_poly1305_procname);
  FuncLoadError := not assigned(EVP_chacha20_poly1305);
  if FuncLoadError then
  begin
    {$if not defined(EVP_chacha20_poly1305_allownil)}
    EVP_chacha20_poly1305 := ERR_EVP_chacha20_poly1305;
    {$ifend}
    {$if declared(EVP_chacha20_poly1305_introduced)}
    if LibVersion < EVP_chacha20_poly1305_introduced then
    begin
      {$if declared(FC_EVP_chacha20_poly1305)}
      EVP_chacha20_poly1305 := FC_EVP_chacha20_poly1305;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_chacha20_poly1305_removed)}
    if EVP_chacha20_poly1305_removed <= LibVersion then
    begin
      {$if declared(_EVP_chacha20_poly1305)}
      EVP_chacha20_poly1305 := _EVP_chacha20_poly1305;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_chacha20_poly1305_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_chacha20_poly1305');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_seed_ecb := LoadLibFunction(ADllHandle, EVP_seed_ecb_procname);
  FuncLoadError := not assigned(EVP_seed_ecb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_seed_ecb_allownil)}
    EVP_seed_ecb := ERR_EVP_seed_ecb;
    {$ifend}
    {$if declared(EVP_seed_ecb_introduced)}
    if LibVersion < EVP_seed_ecb_introduced then
    begin
      {$if declared(FC_EVP_seed_ecb)}
      EVP_seed_ecb := FC_EVP_seed_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_seed_ecb_removed)}
    if EVP_seed_ecb_removed <= LibVersion then
    begin
      {$if declared(_EVP_seed_ecb)}
      EVP_seed_ecb := _EVP_seed_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_seed_ecb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_seed_ecb');
    {$ifend}
  end;


  EVP_seed_cbc := LoadLibFunction(ADllHandle, EVP_seed_cbc_procname);
  FuncLoadError := not assigned(EVP_seed_cbc);
  if FuncLoadError then
  begin
    {$if not defined(EVP_seed_cbc_allownil)}
    EVP_seed_cbc := ERR_EVP_seed_cbc;
    {$ifend}
    {$if declared(EVP_seed_cbc_introduced)}
    if LibVersion < EVP_seed_cbc_introduced then
    begin
      {$if declared(FC_EVP_seed_cbc)}
      EVP_seed_cbc := FC_EVP_seed_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_seed_cbc_removed)}
    if EVP_seed_cbc_removed <= LibVersion then
    begin
      {$if declared(_EVP_seed_cbc)}
      EVP_seed_cbc := _EVP_seed_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_seed_cbc_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_seed_cbc');
    {$ifend}
  end;


  EVP_seed_cfb128 := LoadLibFunction(ADllHandle, EVP_seed_cfb128_procname);
  FuncLoadError := not assigned(EVP_seed_cfb128);
  if FuncLoadError then
  begin
    {$if not defined(EVP_seed_cfb128_allownil)}
    EVP_seed_cfb128 := ERR_EVP_seed_cfb128;
    {$ifend}
    {$if declared(EVP_seed_cfb128_introduced)}
    if LibVersion < EVP_seed_cfb128_introduced then
    begin
      {$if declared(FC_EVP_seed_cfb128)}
      EVP_seed_cfb128 := FC_EVP_seed_cfb128;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_seed_cfb128_removed)}
    if EVP_seed_cfb128_removed <= LibVersion then
    begin
      {$if declared(_EVP_seed_cfb128)}
      EVP_seed_cfb128 := _EVP_seed_cfb128;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_seed_cfb128_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_seed_cfb128');
    {$ifend}
  end;


  EVP_seed_ofb := LoadLibFunction(ADllHandle, EVP_seed_ofb_procname);
  FuncLoadError := not assigned(EVP_seed_ofb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_seed_ofb_allownil)}
    EVP_seed_ofb := ERR_EVP_seed_ofb;
    {$ifend}
    {$if declared(EVP_seed_ofb_introduced)}
    if LibVersion < EVP_seed_ofb_introduced then
    begin
      {$if declared(FC_EVP_seed_ofb)}
      EVP_seed_ofb := FC_EVP_seed_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_seed_ofb_removed)}
    if EVP_seed_ofb_removed <= LibVersion then
    begin
      {$if declared(_EVP_seed_ofb)}
      EVP_seed_ofb := _EVP_seed_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_seed_ofb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_seed_ofb');
    {$ifend}
  end;


  EVP_sm4_ecb := LoadLibFunction(ADllHandle, EVP_sm4_ecb_procname);
  FuncLoadError := not assigned(EVP_sm4_ecb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_sm4_ecb_allownil)}
    EVP_sm4_ecb := ERR_EVP_sm4_ecb;
    {$ifend}
    {$if declared(EVP_sm4_ecb_introduced)}
    if LibVersion < EVP_sm4_ecb_introduced then
    begin
      {$if declared(FC_EVP_sm4_ecb)}
      EVP_sm4_ecb := FC_EVP_sm4_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_sm4_ecb_removed)}
    if EVP_sm4_ecb_removed <= LibVersion then
    begin
      {$if declared(_EVP_sm4_ecb)}
      EVP_sm4_ecb := _EVP_sm4_ecb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_sm4_ecb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_sm4_ecb');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_sm4_cbc := LoadLibFunction(ADllHandle, EVP_sm4_cbc_procname);
  FuncLoadError := not assigned(EVP_sm4_cbc);
  if FuncLoadError then
  begin
    {$if not defined(EVP_sm4_cbc_allownil)}
    EVP_sm4_cbc := ERR_EVP_sm4_cbc;
    {$ifend}
    {$if declared(EVP_sm4_cbc_introduced)}
    if LibVersion < EVP_sm4_cbc_introduced then
    begin
      {$if declared(FC_EVP_sm4_cbc)}
      EVP_sm4_cbc := FC_EVP_sm4_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_sm4_cbc_removed)}
    if EVP_sm4_cbc_removed <= LibVersion then
    begin
      {$if declared(_EVP_sm4_cbc)}
      EVP_sm4_cbc := _EVP_sm4_cbc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_sm4_cbc_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_sm4_cbc');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_sm4_cfb128 := LoadLibFunction(ADllHandle, EVP_sm4_cfb128_procname);
  FuncLoadError := not assigned(EVP_sm4_cfb128);
  if FuncLoadError then
  begin
    {$if not defined(EVP_sm4_cfb128_allownil)}
    EVP_sm4_cfb128 := ERR_EVP_sm4_cfb128;
    {$ifend}
    {$if declared(EVP_sm4_cfb128_introduced)}
    if LibVersion < EVP_sm4_cfb128_introduced then
    begin
      {$if declared(FC_EVP_sm4_cfb128)}
      EVP_sm4_cfb128 := FC_EVP_sm4_cfb128;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_sm4_cfb128_removed)}
    if EVP_sm4_cfb128_removed <= LibVersion then
    begin
      {$if declared(_EVP_sm4_cfb128)}
      EVP_sm4_cfb128 := _EVP_sm4_cfb128;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_sm4_cfb128_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_sm4_cfb128');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_sm4_ofb := LoadLibFunction(ADllHandle, EVP_sm4_ofb_procname);
  FuncLoadError := not assigned(EVP_sm4_ofb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_sm4_ofb_allownil)}
    EVP_sm4_ofb := ERR_EVP_sm4_ofb;
    {$ifend}
    {$if declared(EVP_sm4_ofb_introduced)}
    if LibVersion < EVP_sm4_ofb_introduced then
    begin
      {$if declared(FC_EVP_sm4_ofb)}
      EVP_sm4_ofb := FC_EVP_sm4_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_sm4_ofb_removed)}
    if EVP_sm4_ofb_removed <= LibVersion then
    begin
      {$if declared(_EVP_sm4_ofb)}
      EVP_sm4_ofb := _EVP_sm4_ofb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_sm4_ofb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_sm4_ofb');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_sm4_ctr := LoadLibFunction(ADllHandle, EVP_sm4_ctr_procname);
  FuncLoadError := not assigned(EVP_sm4_ctr);
  if FuncLoadError then
  begin
    {$if not defined(EVP_sm4_ctr_allownil)}
    EVP_sm4_ctr := ERR_EVP_sm4_ctr;
    {$ifend}
    {$if declared(EVP_sm4_ctr_introduced)}
    if LibVersion < EVP_sm4_ctr_introduced then
    begin
      {$if declared(FC_EVP_sm4_ctr)}
      EVP_sm4_ctr := FC_EVP_sm4_ctr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_sm4_ctr_removed)}
    if EVP_sm4_ctr_removed <= LibVersion then
    begin
      {$if declared(_EVP_sm4_ctr)}
      EVP_sm4_ctr := _EVP_sm4_ctr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_sm4_ctr_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_sm4_ctr');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_add_cipher := LoadLibFunction(ADllHandle, EVP_add_cipher_procname);
  FuncLoadError := not assigned(EVP_add_cipher);
  if FuncLoadError then
  begin
    {$if not defined(EVP_add_cipher_allownil)}
    EVP_add_cipher := ERR_EVP_add_cipher;
    {$ifend}
    {$if declared(EVP_add_cipher_introduced)}
    if LibVersion < EVP_add_cipher_introduced then
    begin
      {$if declared(FC_EVP_add_cipher)}
      EVP_add_cipher := FC_EVP_add_cipher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_add_cipher_removed)}
    if EVP_add_cipher_removed <= LibVersion then
    begin
      {$if declared(_EVP_add_cipher)}
      EVP_add_cipher := _EVP_add_cipher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_add_cipher_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_add_cipher');
    {$ifend}
  end;


  EVP_add_digest := LoadLibFunction(ADllHandle, EVP_add_digest_procname);
  FuncLoadError := not assigned(EVP_add_digest);
  if FuncLoadError then
  begin
    {$if not defined(EVP_add_digest_allownil)}
    EVP_add_digest := ERR_EVP_add_digest;
    {$ifend}
    {$if declared(EVP_add_digest_introduced)}
    if LibVersion < EVP_add_digest_introduced then
    begin
      {$if declared(FC_EVP_add_digest)}
      EVP_add_digest := FC_EVP_add_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_add_digest_removed)}
    if EVP_add_digest_removed <= LibVersion then
    begin
      {$if declared(_EVP_add_digest)}
      EVP_add_digest := _EVP_add_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_add_digest_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_add_digest');
    {$ifend}
  end;


  EVP_get_cipherbyname := LoadLibFunction(ADllHandle, EVP_get_cipherbyname_procname);
  FuncLoadError := not assigned(EVP_get_cipherbyname);
  if FuncLoadError then
  begin
    {$if not defined(EVP_get_cipherbyname_allownil)}
    EVP_get_cipherbyname := ERR_EVP_get_cipherbyname;
    {$ifend}
    {$if declared(EVP_get_cipherbyname_introduced)}
    if LibVersion < EVP_get_cipherbyname_introduced then
    begin
      {$if declared(FC_EVP_get_cipherbyname)}
      EVP_get_cipherbyname := FC_EVP_get_cipherbyname;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_get_cipherbyname_removed)}
    if EVP_get_cipherbyname_removed <= LibVersion then
    begin
      {$if declared(_EVP_get_cipherbyname)}
      EVP_get_cipherbyname := _EVP_get_cipherbyname;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_get_cipherbyname_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_get_cipherbyname');
    {$ifend}
  end;


  EVP_get_digestbyname := LoadLibFunction(ADllHandle, EVP_get_digestbyname_procname);
  FuncLoadError := not assigned(EVP_get_digestbyname);
  if FuncLoadError then
  begin
    {$if not defined(EVP_get_digestbyname_allownil)}
    EVP_get_digestbyname := ERR_EVP_get_digestbyname;
    {$ifend}
    {$if declared(EVP_get_digestbyname_introduced)}
    if LibVersion < EVP_get_digestbyname_introduced then
    begin
      {$if declared(FC_EVP_get_digestbyname)}
      EVP_get_digestbyname := FC_EVP_get_digestbyname;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_get_digestbyname_removed)}
    if EVP_get_digestbyname_removed <= LibVersion then
    begin
      {$if declared(_EVP_get_digestbyname)}
      EVP_get_digestbyname := _EVP_get_digestbyname;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_get_digestbyname_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_get_digestbyname');
    {$ifend}
  end;


  EVP_CIPHER_do_all := LoadLibFunction(ADllHandle, EVP_CIPHER_do_all_procname);
  FuncLoadError := not assigned(EVP_CIPHER_do_all);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_do_all_allownil)}
    EVP_CIPHER_do_all := ERR_EVP_CIPHER_do_all;
    {$ifend}
    {$if declared(EVP_CIPHER_do_all_introduced)}
    if LibVersion < EVP_CIPHER_do_all_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_do_all)}
      EVP_CIPHER_do_all := FC_EVP_CIPHER_do_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_do_all_removed)}
    if EVP_CIPHER_do_all_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_do_all)}
      EVP_CIPHER_do_all := _EVP_CIPHER_do_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_do_all_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_do_all');
    {$ifend}
  end;


  EVP_CIPHER_do_all_sorted := LoadLibFunction(ADllHandle, EVP_CIPHER_do_all_sorted_procname);
  FuncLoadError := not assigned(EVP_CIPHER_do_all_sorted);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_do_all_sorted_allownil)}
    EVP_CIPHER_do_all_sorted := ERR_EVP_CIPHER_do_all_sorted;
    {$ifend}
    {$if declared(EVP_CIPHER_do_all_sorted_introduced)}
    if LibVersion < EVP_CIPHER_do_all_sorted_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_do_all_sorted)}
      EVP_CIPHER_do_all_sorted := FC_EVP_CIPHER_do_all_sorted;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_do_all_sorted_removed)}
    if EVP_CIPHER_do_all_sorted_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_do_all_sorted)}
      EVP_CIPHER_do_all_sorted := _EVP_CIPHER_do_all_sorted;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_do_all_sorted_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_do_all_sorted');
    {$ifend}
  end;


  EVP_MD_do_all := LoadLibFunction(ADllHandle, EVP_MD_do_all_procname);
  FuncLoadError := not assigned(EVP_MD_do_all);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_do_all_allownil)}
    EVP_MD_do_all := ERR_EVP_MD_do_all;
    {$ifend}
    {$if declared(EVP_MD_do_all_introduced)}
    if LibVersion < EVP_MD_do_all_introduced then
    begin
      {$if declared(FC_EVP_MD_do_all)}
      EVP_MD_do_all := FC_EVP_MD_do_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_do_all_removed)}
    if EVP_MD_do_all_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_do_all)}
      EVP_MD_do_all := _EVP_MD_do_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_do_all_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_do_all');
    {$ifend}
  end;


  EVP_MD_do_all_sorted := LoadLibFunction(ADllHandle, EVP_MD_do_all_sorted_procname);
  FuncLoadError := not assigned(EVP_MD_do_all_sorted);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MD_do_all_sorted_allownil)}
    EVP_MD_do_all_sorted := ERR_EVP_MD_do_all_sorted;
    {$ifend}
    {$if declared(EVP_MD_do_all_sorted_introduced)}
    if LibVersion < EVP_MD_do_all_sorted_introduced then
    begin
      {$if declared(FC_EVP_MD_do_all_sorted)}
      EVP_MD_do_all_sorted := FC_EVP_MD_do_all_sorted;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MD_do_all_sorted_removed)}
    if EVP_MD_do_all_sorted_removed <= LibVersion then
    begin
      {$if declared(_EVP_MD_do_all_sorted)}
      EVP_MD_do_all_sorted := _EVP_MD_do_all_sorted;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MD_do_all_sorted_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MD_do_all_sorted');
    {$ifend}
  end;


  EVP_PKEY_decrypt_old := LoadLibFunction(ADllHandle, EVP_PKEY_decrypt_old_procname);
  FuncLoadError := not assigned(EVP_PKEY_decrypt_old);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_decrypt_old_allownil)}
    EVP_PKEY_decrypt_old := ERR_EVP_PKEY_decrypt_old;
    {$ifend}
    {$if declared(EVP_PKEY_decrypt_old_introduced)}
    if LibVersion < EVP_PKEY_decrypt_old_introduced then
    begin
      {$if declared(FC_EVP_PKEY_decrypt_old)}
      EVP_PKEY_decrypt_old := FC_EVP_PKEY_decrypt_old;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_decrypt_old_removed)}
    if EVP_PKEY_decrypt_old_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_decrypt_old)}
      EVP_PKEY_decrypt_old := _EVP_PKEY_decrypt_old;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_decrypt_old_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_decrypt_old');
    {$ifend}
  end;


  EVP_PKEY_encrypt_old := LoadLibFunction(ADllHandle, EVP_PKEY_encrypt_old_procname);
  FuncLoadError := not assigned(EVP_PKEY_encrypt_old);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_encrypt_old_allownil)}
    EVP_PKEY_encrypt_old := ERR_EVP_PKEY_encrypt_old;
    {$ifend}
    {$if declared(EVP_PKEY_encrypt_old_introduced)}
    if LibVersion < EVP_PKEY_encrypt_old_introduced then
    begin
      {$if declared(FC_EVP_PKEY_encrypt_old)}
      EVP_PKEY_encrypt_old := FC_EVP_PKEY_encrypt_old;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_encrypt_old_removed)}
    if EVP_PKEY_encrypt_old_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_encrypt_old)}
      EVP_PKEY_encrypt_old := _EVP_PKEY_encrypt_old;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_encrypt_old_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_encrypt_old');
    {$ifend}
  end;


  EVP_PKEY_type := LoadLibFunction(ADllHandle, EVP_PKEY_type_procname);
  FuncLoadError := not assigned(EVP_PKEY_type);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_type_allownil)}
    EVP_PKEY_type := ERR_EVP_PKEY_type;
    {$ifend}
    {$if declared(EVP_PKEY_type_introduced)}
    if LibVersion < EVP_PKEY_type_introduced then
    begin
      {$if declared(FC_EVP_PKEY_type)}
      EVP_PKEY_type := FC_EVP_PKEY_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_type_removed)}
    if EVP_PKEY_type_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_type)}
      EVP_PKEY_type := _EVP_PKEY_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_type_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_type');
    {$ifend}
  end;


  EVP_PKEY_id := LoadLibFunction(ADllHandle, EVP_PKEY_id_procname);
  FuncLoadError := not assigned(EVP_PKEY_id);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_id_allownil)}
    EVP_PKEY_id := ERR_EVP_PKEY_id;
    {$ifend}
    {$if declared(EVP_PKEY_id_introduced)}
    if LibVersion < EVP_PKEY_id_introduced then
    begin
      {$if declared(FC_EVP_PKEY_id)}
      EVP_PKEY_id := FC_EVP_PKEY_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_id_removed)}
    if EVP_PKEY_id_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_id)}
      EVP_PKEY_id := _EVP_PKEY_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_id_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_id');
    {$ifend}
  end;


  EVP_PKEY_base_id := LoadLibFunction(ADllHandle, EVP_PKEY_base_id_procname);
  if not Assigned(EVP_PKEY_base_id) then begin
     EVP_PKEY_base_id := LoadLibFunction(ADllHandle, EVP_PKEY_get_base_id_procname);
  end;

  FuncLoadError := not assigned(EVP_PKEY_base_id);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_base_id_allownil)}
    EVP_PKEY_base_id := ERR_EVP_PKEY_base_id;
    {$ifend}
    {$if declared(EVP_PKEY_base_id_introduced)}
    if LibVersion < EVP_PKEY_base_id_introduced then
    begin
      {$if declared(FC_EVP_PKEY_base_id)}
      EVP_PKEY_base_id := FC_EVP_PKEY_base_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_base_id_removed)}
    if EVP_PKEY_base_id_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_base_id)}
      EVP_PKEY_base_id := _EVP_PKEY_base_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_base_id_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_base_id');
    {$ifend}
  end;

 
  EVP_PKEY_bits := LoadLibFunction(ADllHandle, EVP_PKEY_bits_procname);
  if not Assigned( EVP_PKEY_bits) then begin
    EVP_PKEY_bits := LoadLibFunction(ADllHandle, EVP_PKEY_get_bits_procname);
  end;

  FuncLoadError := not assigned(EVP_PKEY_bits);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_bits_allownil)}
    EVP_PKEY_bits := ERR_EVP_PKEY_bits;
    {$ifend}
    {$if declared(EVP_PKEY_bits_introduced)}
    if LibVersion < EVP_PKEY_bits_introduced then
    begin
      {$if declared(FC_EVP_PKEY_bits)}
      EVP_PKEY_bits := FC_EVP_PKEY_bits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_bits_removed)}
    if EVP_PKEY_bits_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_bits)}
      EVP_PKEY_bits := _EVP_PKEY_bits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_bits_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_bits');
    {$ifend}
  end;

 
  EVP_PKEY_security_bits := LoadLibFunction(ADllHandle, EVP_PKEY_security_bits_procname);
  if not Assigned( EVP_PKEY_security_bits) then begin
    EVP_PKEY_security_bits := LoadLibFunction(ADllHandle, EVP_PKEY_get_security_bits_procname);
  end;
  FuncLoadError := not assigned(EVP_PKEY_security_bits);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_security_bits_allownil)}
    EVP_PKEY_security_bits := ERR_EVP_PKEY_security_bits;
    {$ifend}
    {$if declared(EVP_PKEY_security_bits_introduced)}
    if LibVersion < EVP_PKEY_security_bits_introduced then
    begin
      {$if declared(FC_EVP_PKEY_security_bits)}
      EVP_PKEY_security_bits := FC_EVP_PKEY_security_bits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_security_bits_removed)}
    if EVP_PKEY_security_bits_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_security_bits)}
      EVP_PKEY_security_bits := _EVP_PKEY_security_bits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_security_bits_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_security_bits');
    {$ifend}
  end;

 
  EVP_PKEY_size := LoadLibFunction(ADllHandle, EVP_PKEY_size_procname);
  if not Assigned( EVP_PKEY_size) then begin
    EVP_PKEY_size := LoadLibFunction(ADllHandle, EVP_PKEY_get_size_procname);
  end;
  FuncLoadError := not assigned(EVP_PKEY_size);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_size_allownil)}
    EVP_PKEY_size := ERR_EVP_PKEY_size;
    {$ifend}
    {$if declared(EVP_PKEY_size_introduced)}
    if LibVersion < EVP_PKEY_size_introduced then
    begin
      {$if declared(FC_EVP_PKEY_size)}
      EVP_PKEY_size := FC_EVP_PKEY_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_size_removed)}
    if EVP_PKEY_size_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_size)}
      EVP_PKEY_size := _EVP_PKEY_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_size_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_size');
    {$ifend}
  end;

 
  EVP_PKEY_set_type := LoadLibFunction(ADllHandle, EVP_PKEY_set_type_procname);
  FuncLoadError := not assigned(EVP_PKEY_set_type);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_set_type_allownil)}
    EVP_PKEY_set_type := ERR_EVP_PKEY_set_type;
    {$ifend}
    {$if declared(EVP_PKEY_set_type_introduced)}
    if LibVersion < EVP_PKEY_set_type_introduced then
    begin
      {$if declared(FC_EVP_PKEY_set_type)}
      EVP_PKEY_set_type := FC_EVP_PKEY_set_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_set_type_removed)}
    if EVP_PKEY_set_type_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_set_type)}
      EVP_PKEY_set_type := _EVP_PKEY_set_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_set_type_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_set_type');
    {$ifend}
  end;


  EVP_PKEY_set_type_str := LoadLibFunction(ADllHandle, EVP_PKEY_set_type_str_procname);
  FuncLoadError := not assigned(EVP_PKEY_set_type_str);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_set_type_str_allownil)}
    EVP_PKEY_set_type_str := ERR_EVP_PKEY_set_type_str;
    {$ifend}
    {$if declared(EVP_PKEY_set_type_str_introduced)}
    if LibVersion < EVP_PKEY_set_type_str_introduced then
    begin
      {$if declared(FC_EVP_PKEY_set_type_str)}
      EVP_PKEY_set_type_str := FC_EVP_PKEY_set_type_str;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_set_type_str_removed)}
    if EVP_PKEY_set_type_str_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_set_type_str)}
      EVP_PKEY_set_type_str := _EVP_PKEY_set_type_str;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_set_type_str_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_set_type_str');
    {$ifend}
  end;


  EVP_PKEY_set_alias_type := LoadLibFunction(ADllHandle, EVP_PKEY_set_alias_type_procname);
  FuncLoadError := not assigned(EVP_PKEY_set_alias_type);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_set_alias_type_allownil)}
    EVP_PKEY_set_alias_type := ERR_EVP_PKEY_set_alias_type;
    {$ifend}
    {$if declared(EVP_PKEY_set_alias_type_introduced)}
    if LibVersion < EVP_PKEY_set_alias_type_introduced then
    begin
      {$if declared(FC_EVP_PKEY_set_alias_type)}
      EVP_PKEY_set_alias_type := FC_EVP_PKEY_set_alias_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_set_alias_type_removed)}
    if EVP_PKEY_set_alias_type_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_set_alias_type)}
      EVP_PKEY_set_alias_type := _EVP_PKEY_set_alias_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_set_alias_type_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_set_alias_type');
    {$ifend}
  end;

 
  EVP_PKEY_set1_engine := LoadLibFunction(ADllHandle, EVP_PKEY_set1_engine_procname);
  FuncLoadError := not assigned(EVP_PKEY_set1_engine);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_set1_engine_allownil)}
    EVP_PKEY_set1_engine := ERR_EVP_PKEY_set1_engine;
    {$ifend}
    {$if declared(EVP_PKEY_set1_engine_introduced)}
    if LibVersion < EVP_PKEY_set1_engine_introduced then
    begin
      {$if declared(FC_EVP_PKEY_set1_engine)}
      EVP_PKEY_set1_engine := FC_EVP_PKEY_set1_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_set1_engine_removed)}
    if EVP_PKEY_set1_engine_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_set1_engine)}
      EVP_PKEY_set1_engine := _EVP_PKEY_set1_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_set1_engine_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_set1_engine');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_get0_engine := LoadLibFunction(ADllHandle, EVP_PKEY_get0_engine_procname);
  FuncLoadError := not assigned(EVP_PKEY_get0_engine);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_get0_engine_allownil)}
    EVP_PKEY_get0_engine := ERR_EVP_PKEY_get0_engine;
    {$ifend}
    {$if declared(EVP_PKEY_get0_engine_introduced)}
    if LibVersion < EVP_PKEY_get0_engine_introduced then
    begin
      {$if declared(FC_EVP_PKEY_get0_engine)}
      EVP_PKEY_get0_engine := FC_EVP_PKEY_get0_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_get0_engine_removed)}
    if EVP_PKEY_get0_engine_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_get0_engine)}
      EVP_PKEY_get0_engine := _EVP_PKEY_get0_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_get0_engine_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_get0_engine');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_assign := LoadLibFunction(ADllHandle, EVP_PKEY_assign_procname);
  FuncLoadError := not assigned(EVP_PKEY_assign);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_assign_allownil)}
    EVP_PKEY_assign := ERR_EVP_PKEY_assign;
    {$ifend}
    {$if declared(EVP_PKEY_assign_introduced)}
    if LibVersion < EVP_PKEY_assign_introduced then
    begin
      {$if declared(FC_EVP_PKEY_assign)}
      EVP_PKEY_assign := FC_EVP_PKEY_assign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_assign_removed)}
    if EVP_PKEY_assign_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_assign)}
      EVP_PKEY_assign := _EVP_PKEY_assign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_assign_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_assign');
    {$ifend}
  end;


  EVP_PKEY_get0 := LoadLibFunction(ADllHandle, EVP_PKEY_get0_procname);
  FuncLoadError := not assigned(EVP_PKEY_get0);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_get0_allownil)}
    EVP_PKEY_get0 := ERR_EVP_PKEY_get0;
    {$ifend}
    {$if declared(EVP_PKEY_get0_introduced)}
    if LibVersion < EVP_PKEY_get0_introduced then
    begin
      {$if declared(FC_EVP_PKEY_get0)}
      EVP_PKEY_get0 := FC_EVP_PKEY_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_get0_removed)}
    if EVP_PKEY_get0_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_get0)}
      EVP_PKEY_get0 := _EVP_PKEY_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_get0_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_get0');
    {$ifend}
  end;


  EVP_PKEY_get0_hmac := LoadLibFunction(ADllHandle, EVP_PKEY_get0_hmac_procname);
  FuncLoadError := not assigned(EVP_PKEY_get0_hmac);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_get0_hmac_allownil)}
    EVP_PKEY_get0_hmac := ERR_EVP_PKEY_get0_hmac;
    {$ifend}
    {$if declared(EVP_PKEY_get0_hmac_introduced)}
    if LibVersion < EVP_PKEY_get0_hmac_introduced then
    begin
      {$if declared(FC_EVP_PKEY_get0_hmac)}
      EVP_PKEY_get0_hmac := FC_EVP_PKEY_get0_hmac;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_get0_hmac_removed)}
    if EVP_PKEY_get0_hmac_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_get0_hmac)}
      EVP_PKEY_get0_hmac := _EVP_PKEY_get0_hmac;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_get0_hmac_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_get0_hmac');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_get0_poly1305 := LoadLibFunction(ADllHandle, EVP_PKEY_get0_poly1305_procname);
  FuncLoadError := not assigned(EVP_PKEY_get0_poly1305);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_get0_poly1305_allownil)}
    EVP_PKEY_get0_poly1305 := ERR_EVP_PKEY_get0_poly1305;
    {$ifend}
    {$if declared(EVP_PKEY_get0_poly1305_introduced)}
    if LibVersion < EVP_PKEY_get0_poly1305_introduced then
    begin
      {$if declared(FC_EVP_PKEY_get0_poly1305)}
      EVP_PKEY_get0_poly1305 := FC_EVP_PKEY_get0_poly1305;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_get0_poly1305_removed)}
    if EVP_PKEY_get0_poly1305_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_get0_poly1305)}
      EVP_PKEY_get0_poly1305 := _EVP_PKEY_get0_poly1305;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_get0_poly1305_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_get0_poly1305');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_get0_siphash := LoadLibFunction(ADllHandle, EVP_PKEY_get0_siphash_procname);
  FuncLoadError := not assigned(EVP_PKEY_get0_siphash);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_get0_siphash_allownil)}
    EVP_PKEY_get0_siphash := ERR_EVP_PKEY_get0_siphash;
    {$ifend}
    {$if declared(EVP_PKEY_get0_siphash_introduced)}
    if LibVersion < EVP_PKEY_get0_siphash_introduced then
    begin
      {$if declared(FC_EVP_PKEY_get0_siphash)}
      EVP_PKEY_get0_siphash := FC_EVP_PKEY_get0_siphash;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_get0_siphash_removed)}
    if EVP_PKEY_get0_siphash_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_get0_siphash)}
      EVP_PKEY_get0_siphash := _EVP_PKEY_get0_siphash;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_get0_siphash_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_get0_siphash');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_set1_RSA := LoadLibFunction(ADllHandle, EVP_PKEY_set1_RSA_procname);
  FuncLoadError := not assigned(EVP_PKEY_set1_RSA);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_set1_RSA_allownil)}
    EVP_PKEY_set1_RSA := ERR_EVP_PKEY_set1_RSA;
    {$ifend}
    {$if declared(EVP_PKEY_set1_RSA_introduced)}
    if LibVersion < EVP_PKEY_set1_RSA_introduced then
    begin
      {$if declared(FC_EVP_PKEY_set1_RSA)}
      EVP_PKEY_set1_RSA := FC_EVP_PKEY_set1_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_set1_RSA_removed)}
    if EVP_PKEY_set1_RSA_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_set1_RSA)}
      EVP_PKEY_set1_RSA := _EVP_PKEY_set1_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_set1_RSA_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_set1_RSA');
    {$ifend}
  end;


  EVP_PKEY_get0_RSA := LoadLibFunction(ADllHandle, EVP_PKEY_get0_RSA_procname);
  FuncLoadError := not assigned(EVP_PKEY_get0_RSA);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_get0_RSA_allownil)}
    EVP_PKEY_get0_RSA := ERR_EVP_PKEY_get0_RSA;
    {$ifend}
    {$if declared(EVP_PKEY_get0_RSA_introduced)}
    if LibVersion < EVP_PKEY_get0_RSA_introduced then
    begin
      {$if declared(FC_EVP_PKEY_get0_RSA)}
      EVP_PKEY_get0_RSA := FC_EVP_PKEY_get0_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_get0_RSA_removed)}
    if EVP_PKEY_get0_RSA_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_get0_RSA)}
      EVP_PKEY_get0_RSA := _EVP_PKEY_get0_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_get0_RSA_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_get0_RSA');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_get1_RSA := LoadLibFunction(ADllHandle, EVP_PKEY_get1_RSA_procname);
  FuncLoadError := not assigned(EVP_PKEY_get1_RSA);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_get1_RSA_allownil)}
    EVP_PKEY_get1_RSA := ERR_EVP_PKEY_get1_RSA;
    {$ifend}
    {$if declared(EVP_PKEY_get1_RSA_introduced)}
    if LibVersion < EVP_PKEY_get1_RSA_introduced then
    begin
      {$if declared(FC_EVP_PKEY_get1_RSA)}
      EVP_PKEY_get1_RSA := FC_EVP_PKEY_get1_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_get1_RSA_removed)}
    if EVP_PKEY_get1_RSA_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_get1_RSA)}
      EVP_PKEY_get1_RSA := _EVP_PKEY_get1_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_get1_RSA_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_get1_RSA');
    {$ifend}
  end;


  EVP_PKEY_set1_DSA := LoadLibFunction(ADllHandle, EVP_PKEY_set1_DSA_procname);
  FuncLoadError := not assigned(EVP_PKEY_set1_DSA);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_set1_DSA_allownil)}
    EVP_PKEY_set1_DSA := ERR_EVP_PKEY_set1_DSA;
    {$ifend}
    {$if declared(EVP_PKEY_set1_DSA_introduced)}
    if LibVersion < EVP_PKEY_set1_DSA_introduced then
    begin
      {$if declared(FC_EVP_PKEY_set1_DSA)}
      EVP_PKEY_set1_DSA := FC_EVP_PKEY_set1_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_set1_DSA_removed)}
    if EVP_PKEY_set1_DSA_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_set1_DSA)}
      EVP_PKEY_set1_DSA := _EVP_PKEY_set1_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_set1_DSA_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_set1_DSA');
    {$ifend}
  end;


  EVP_PKEY_get0_DSA := LoadLibFunction(ADllHandle, EVP_PKEY_get0_DSA_procname);
  FuncLoadError := not assigned(EVP_PKEY_get0_DSA);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_get0_DSA_allownil)}
    EVP_PKEY_get0_DSA := ERR_EVP_PKEY_get0_DSA;
    {$ifend}
    {$if declared(EVP_PKEY_get0_DSA_introduced)}
    if LibVersion < EVP_PKEY_get0_DSA_introduced then
    begin
      {$if declared(FC_EVP_PKEY_get0_DSA)}
      EVP_PKEY_get0_DSA := FC_EVP_PKEY_get0_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_get0_DSA_removed)}
    if EVP_PKEY_get0_DSA_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_get0_DSA)}
      EVP_PKEY_get0_DSA := _EVP_PKEY_get0_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_get0_DSA_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_get0_DSA');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_get1_DSA := LoadLibFunction(ADllHandle, EVP_PKEY_get1_DSA_procname);
  FuncLoadError := not assigned(EVP_PKEY_get1_DSA);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_get1_DSA_allownil)}
    EVP_PKEY_get1_DSA := ERR_EVP_PKEY_get1_DSA;
    {$ifend}
    {$if declared(EVP_PKEY_get1_DSA_introduced)}
    if LibVersion < EVP_PKEY_get1_DSA_introduced then
    begin
      {$if declared(FC_EVP_PKEY_get1_DSA)}
      EVP_PKEY_get1_DSA := FC_EVP_PKEY_get1_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_get1_DSA_removed)}
    if EVP_PKEY_get1_DSA_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_get1_DSA)}
      EVP_PKEY_get1_DSA := _EVP_PKEY_get1_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_get1_DSA_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_get1_DSA');
    {$ifend}
  end;


  EVP_PKEY_set1_DH := LoadLibFunction(ADllHandle, EVP_PKEY_set1_DH_procname);
  FuncLoadError := not assigned(EVP_PKEY_set1_DH);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_set1_DH_allownil)}
    EVP_PKEY_set1_DH := ERR_EVP_PKEY_set1_DH;
    {$ifend}
    {$if declared(EVP_PKEY_set1_DH_introduced)}
    if LibVersion < EVP_PKEY_set1_DH_introduced then
    begin
      {$if declared(FC_EVP_PKEY_set1_DH)}
      EVP_PKEY_set1_DH := FC_EVP_PKEY_set1_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_set1_DH_removed)}
    if EVP_PKEY_set1_DH_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_set1_DH)}
      EVP_PKEY_set1_DH := _EVP_PKEY_set1_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_set1_DH_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_set1_DH');
    {$ifend}
  end;


  EVP_PKEY_get0_DH := LoadLibFunction(ADllHandle, EVP_PKEY_get0_DH_procname);
  FuncLoadError := not assigned(EVP_PKEY_get0_DH);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_get0_DH_allownil)}
    EVP_PKEY_get0_DH := ERR_EVP_PKEY_get0_DH;
    {$ifend}
    {$if declared(EVP_PKEY_get0_DH_introduced)}
    if LibVersion < EVP_PKEY_get0_DH_introduced then
    begin
      {$if declared(FC_EVP_PKEY_get0_DH)}
      EVP_PKEY_get0_DH := FC_EVP_PKEY_get0_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_get0_DH_removed)}
    if EVP_PKEY_get0_DH_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_get0_DH)}
      EVP_PKEY_get0_DH := _EVP_PKEY_get0_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_get0_DH_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_get0_DH');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_get1_DH := LoadLibFunction(ADllHandle, EVP_PKEY_get1_DH_procname);
  FuncLoadError := not assigned(EVP_PKEY_get1_DH);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_get1_DH_allownil)}
    EVP_PKEY_get1_DH := ERR_EVP_PKEY_get1_DH;
    {$ifend}
    {$if declared(EVP_PKEY_get1_DH_introduced)}
    if LibVersion < EVP_PKEY_get1_DH_introduced then
    begin
      {$if declared(FC_EVP_PKEY_get1_DH)}
      EVP_PKEY_get1_DH := FC_EVP_PKEY_get1_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_get1_DH_removed)}
    if EVP_PKEY_get1_DH_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_get1_DH)}
      EVP_PKEY_get1_DH := _EVP_PKEY_get1_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_get1_DH_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_get1_DH');
    {$ifend}
  end;


  EVP_PKEY_set1_EC_KEY := LoadLibFunction(ADllHandle, EVP_PKEY_set1_EC_KEY_procname);
  FuncLoadError := not assigned(EVP_PKEY_set1_EC_KEY);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_set1_EC_KEY_allownil)}
    EVP_PKEY_set1_EC_KEY := ERR_EVP_PKEY_set1_EC_KEY;
    {$ifend}
    {$if declared(EVP_PKEY_set1_EC_KEY_introduced)}
    if LibVersion < EVP_PKEY_set1_EC_KEY_introduced then
    begin
      {$if declared(FC_EVP_PKEY_set1_EC_KEY)}
      EVP_PKEY_set1_EC_KEY := FC_EVP_PKEY_set1_EC_KEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_set1_EC_KEY_removed)}
    if EVP_PKEY_set1_EC_KEY_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_set1_EC_KEY)}
      EVP_PKEY_set1_EC_KEY := _EVP_PKEY_set1_EC_KEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_set1_EC_KEY_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_set1_EC_KEY');
    {$ifend}
  end;


  EVP_PKEY_get0_EC_KEY := LoadLibFunction(ADllHandle, EVP_PKEY_get0_EC_KEY_procname);
  FuncLoadError := not assigned(EVP_PKEY_get0_EC_KEY);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_get0_EC_KEY_allownil)}
    EVP_PKEY_get0_EC_KEY := ERR_EVP_PKEY_get0_EC_KEY;
    {$ifend}
    {$if declared(EVP_PKEY_get0_EC_KEY_introduced)}
    if LibVersion < EVP_PKEY_get0_EC_KEY_introduced then
    begin
      {$if declared(FC_EVP_PKEY_get0_EC_KEY)}
      EVP_PKEY_get0_EC_KEY := FC_EVP_PKEY_get0_EC_KEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_get0_EC_KEY_removed)}
    if EVP_PKEY_get0_EC_KEY_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_get0_EC_KEY)}
      EVP_PKEY_get0_EC_KEY := _EVP_PKEY_get0_EC_KEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_get0_EC_KEY_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_get0_EC_KEY');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_get1_EC_KEY := LoadLibFunction(ADllHandle, EVP_PKEY_get1_EC_KEY_procname);
  FuncLoadError := not assigned(EVP_PKEY_get1_EC_KEY);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_get1_EC_KEY_allownil)}
    EVP_PKEY_get1_EC_KEY := ERR_EVP_PKEY_get1_EC_KEY;
    {$ifend}
    {$if declared(EVP_PKEY_get1_EC_KEY_introduced)}
    if LibVersion < EVP_PKEY_get1_EC_KEY_introduced then
    begin
      {$if declared(FC_EVP_PKEY_get1_EC_KEY)}
      EVP_PKEY_get1_EC_KEY := FC_EVP_PKEY_get1_EC_KEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_get1_EC_KEY_removed)}
    if EVP_PKEY_get1_EC_KEY_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_get1_EC_KEY)}
      EVP_PKEY_get1_EC_KEY := _EVP_PKEY_get1_EC_KEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_get1_EC_KEY_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_get1_EC_KEY');
    {$ifend}
  end;


  EVP_PKEY_new := LoadLibFunction(ADllHandle, EVP_PKEY_new_procname);
  FuncLoadError := not assigned(EVP_PKEY_new);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_new_allownil)}
    EVP_PKEY_new := ERR_EVP_PKEY_new;
    {$ifend}
    {$if declared(EVP_PKEY_new_introduced)}
    if LibVersion < EVP_PKEY_new_introduced then
    begin
      {$if declared(FC_EVP_PKEY_new)}
      EVP_PKEY_new := FC_EVP_PKEY_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_new_removed)}
    if EVP_PKEY_new_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_new)}
      EVP_PKEY_new := _EVP_PKEY_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_new_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_new');
    {$ifend}
  end;


  EVP_PKEY_up_ref := LoadLibFunction(ADllHandle, EVP_PKEY_up_ref_procname);
  FuncLoadError := not assigned(EVP_PKEY_up_ref);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_up_ref_allownil)}
    EVP_PKEY_up_ref := ERR_EVP_PKEY_up_ref;
    {$ifend}
    {$if declared(EVP_PKEY_up_ref_introduced)}
    if LibVersion < EVP_PKEY_up_ref_introduced then
    begin
      {$if declared(FC_EVP_PKEY_up_ref)}
      EVP_PKEY_up_ref := FC_EVP_PKEY_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_up_ref_removed)}
    if EVP_PKEY_up_ref_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_up_ref)}
      EVP_PKEY_up_ref := _EVP_PKEY_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_up_ref_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_up_ref');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_free := LoadLibFunction(ADllHandle, EVP_PKEY_free_procname);
  FuncLoadError := not assigned(EVP_PKEY_free);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_free_allownil)}
    EVP_PKEY_free := ERR_EVP_PKEY_free;
    {$ifend}
    {$if declared(EVP_PKEY_free_introduced)}
    if LibVersion < EVP_PKEY_free_introduced then
    begin
      {$if declared(FC_EVP_PKEY_free)}
      EVP_PKEY_free := FC_EVP_PKEY_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_free_removed)}
    if EVP_PKEY_free_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_free)}
      EVP_PKEY_free := _EVP_PKEY_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_free_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_free');
    {$ifend}
  end;


  d2i_PublicKey := LoadLibFunction(ADllHandle, d2i_PublicKey_procname);
  FuncLoadError := not assigned(d2i_PublicKey);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PublicKey_allownil)}
    d2i_PublicKey := ERR_d2i_PublicKey;
    {$ifend}
    {$if declared(d2i_PublicKey_introduced)}
    if LibVersion < d2i_PublicKey_introduced then
    begin
      {$if declared(FC_d2i_PublicKey)}
      d2i_PublicKey := FC_d2i_PublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PublicKey_removed)}
    if d2i_PublicKey_removed <= LibVersion then
    begin
      {$if declared(_d2i_PublicKey)}
      d2i_PublicKey := _d2i_PublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PublicKey_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PublicKey');
    {$ifend}
  end;


  i2d_PublicKey := LoadLibFunction(ADllHandle, i2d_PublicKey_procname);
  FuncLoadError := not assigned(i2d_PublicKey);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PublicKey_allownil)}
    i2d_PublicKey := ERR_i2d_PublicKey;
    {$ifend}
    {$if declared(i2d_PublicKey_introduced)}
    if LibVersion < i2d_PublicKey_introduced then
    begin
      {$if declared(FC_i2d_PublicKey)}
      i2d_PublicKey := FC_i2d_PublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PublicKey_removed)}
    if i2d_PublicKey_removed <= LibVersion then
    begin
      {$if declared(_i2d_PublicKey)}
      i2d_PublicKey := _i2d_PublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PublicKey_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PublicKey');
    {$ifend}
  end;


  d2i_PrivateKey := LoadLibFunction(ADllHandle, d2i_PrivateKey_procname);
  FuncLoadError := not assigned(d2i_PrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PrivateKey_allownil)}
    d2i_PrivateKey := ERR_d2i_PrivateKey;
    {$ifend}
    {$if declared(d2i_PrivateKey_introduced)}
    if LibVersion < d2i_PrivateKey_introduced then
    begin
      {$if declared(FC_d2i_PrivateKey)}
      d2i_PrivateKey := FC_d2i_PrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PrivateKey_removed)}
    if d2i_PrivateKey_removed <= LibVersion then
    begin
      {$if declared(_d2i_PrivateKey)}
      d2i_PrivateKey := _d2i_PrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PrivateKey');
    {$ifend}
  end;


  d2i_AutoPrivateKey := LoadLibFunction(ADllHandle, d2i_AutoPrivateKey_procname);
  FuncLoadError := not assigned(d2i_AutoPrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(d2i_AutoPrivateKey_allownil)}
    d2i_AutoPrivateKey := ERR_d2i_AutoPrivateKey;
    {$ifend}
    {$if declared(d2i_AutoPrivateKey_introduced)}
    if LibVersion < d2i_AutoPrivateKey_introduced then
    begin
      {$if declared(FC_d2i_AutoPrivateKey)}
      d2i_AutoPrivateKey := FC_d2i_AutoPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_AutoPrivateKey_removed)}
    if d2i_AutoPrivateKey_removed <= LibVersion then
    begin
      {$if declared(_d2i_AutoPrivateKey)}
      d2i_AutoPrivateKey := _d2i_AutoPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_AutoPrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_AutoPrivateKey');
    {$ifend}
  end;

  d2i_AutoPrivateKey_ex := LoadLibFunction(ADllHandle, d2i_AutoPrivateKey_ex_procname);
  FuncLoadError := not assigned(d2i_AutoPrivateKey_ex);
  if FuncLoadError then
  begin
    {$if not defined(d2i_AutoPrivateKey_ex_allownil)}
    d2i_AutoPrivateKey_ex := ERR_d2i_AutoPrivateKey_ex;
    {$ifend}
    {$if declared(d2i_AutoPrivateKey_ex_introduced)}
    if LibVersion < d2i_AutoPrivateKey_ex_introduced then
    begin
      {$if declared(FC_d2i_AutoPrivateKey_ex)}
      d2i_AutoPrivateKey_ex := FC_d2i_AutoPrivateKey_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_AutoPrivateKey_ex_removed)}
    if d2i_AutoPrivateKey_ex_removed <= LibVersion then
    begin
      {$if declared(_d2i_AutoPrivateKey_ex)}
      d2i_AutoPrivateKey_ex := _d2i_AutoPrivateKey_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_AutoPrivateKey_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_AutoPrivateKey_ex');
    {$ifend}
  end;

  i2d_PrivateKey := LoadLibFunction(ADllHandle, i2d_PrivateKey_procname);
  FuncLoadError := not assigned(i2d_PrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PrivateKey_allownil)}
    i2d_PrivateKey := ERR_i2d_PrivateKey;
    {$ifend}
    {$if declared(i2d_PrivateKey_introduced)}
    if LibVersion < i2d_PrivateKey_introduced then
    begin
      {$if declared(FC_i2d_PrivateKey)}
      i2d_PrivateKey := FC_i2d_PrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PrivateKey_removed)}
    if i2d_PrivateKey_removed <= LibVersion then
    begin
      {$if declared(_i2d_PrivateKey)}
      i2d_PrivateKey := _i2d_PrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PrivateKey');
    {$ifend}
  end;

   i2d_KeyParams_bio := LoadLibFunction(ADllHandle, i2d_KeyParams_bio_procname);
  FuncLoadError := not assigned(i2d_KeyParams_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_KeyParams_bio_allownil)}
    i2d_KeyParams_bio := ERR_i2d_KeyParams_bio;
    {$ifend}
    {$if declared(i2d_KeyParams_bio_introduced)}
    if LibVersion < i2d_KeyParams_bio_introduced then
    begin
      {$if declared(FC_i2d_KeyParams_bio)}
      i2d_KeyParams_bio := FC_i2d_KeyParams_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_KeyParams_bio_removed)}
    if i2d_KeyParams_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_KeyParams_bio)}
      i2d_KeyParams_bio := _i2d_KeyParams_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_KeyParams_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_KeyParams_bio');
    {$ifend}
  end;

  d2i_KeyParams_bio := LoadLibFunction(ADllHandle, d2i_KeyParams_bio_procname);
  FuncLoadError := not assigned(d2i_KeyParams_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_KeyParams_bio_allownil)}
    d2i_KeyParams_bio := ERR_d2i_KeyParams_bio;
    {$ifend}
    {$if declared(d2i_KeyParams_bio_introduced)}
    if LibVersion < d2i_KeyParams_bio_introduced then
    begin
      {$if declared(FC_d2i_KeyParams_bio)}
      d2i_KeyParams_bio := FC_d2i_KeyParams_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_KeyParams_bio_removed)}
    if d2i_KeyParams_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_KeyParams_bio)}
      d2i_KeyParams_bio := _d2i_KeyParams_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_KeyParams_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_KeyParams_bio');
    {$ifend}
  end;


  EVP_PKEY_copy_parameters := LoadLibFunction(ADllHandle, EVP_PKEY_copy_parameters_procname);
  FuncLoadError := not assigned(EVP_PKEY_copy_parameters);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_copy_parameters_allownil)}
    EVP_PKEY_copy_parameters := ERR_EVP_PKEY_copy_parameters;
    {$ifend}
    {$if declared(EVP_PKEY_copy_parameters_introduced)}
    if LibVersion < EVP_PKEY_copy_parameters_introduced then
    begin
      {$if declared(FC_EVP_PKEY_copy_parameters)}
      EVP_PKEY_copy_parameters := FC_EVP_PKEY_copy_parameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_copy_parameters_removed)}
    if EVP_PKEY_copy_parameters_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_copy_parameters)}
      EVP_PKEY_copy_parameters := _EVP_PKEY_copy_parameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_copy_parameters_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_copy_parameters');
    {$ifend}
  end;


  EVP_PKEY_missing_parameters := LoadLibFunction(ADllHandle, EVP_PKEY_missing_parameters_procname);
  FuncLoadError := not assigned(EVP_PKEY_missing_parameters);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_missing_parameters_allownil)}
    EVP_PKEY_missing_parameters := ERR_EVP_PKEY_missing_parameters;
    {$ifend}
    {$if declared(EVP_PKEY_missing_parameters_introduced)}
    if LibVersion < EVP_PKEY_missing_parameters_introduced then
    begin
      {$if declared(FC_EVP_PKEY_missing_parameters)}
      EVP_PKEY_missing_parameters := FC_EVP_PKEY_missing_parameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_missing_parameters_removed)}
    if EVP_PKEY_missing_parameters_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_missing_parameters)}
      EVP_PKEY_missing_parameters := _EVP_PKEY_missing_parameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_missing_parameters_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_missing_parameters');
    {$ifend}
  end;


  EVP_PKEY_save_parameters := LoadLibFunction(ADllHandle, EVP_PKEY_save_parameters_procname);
  FuncLoadError := not assigned(EVP_PKEY_save_parameters);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_save_parameters_allownil)}
    EVP_PKEY_save_parameters := ERR_EVP_PKEY_save_parameters;
    {$ifend}
    {$if declared(EVP_PKEY_save_parameters_introduced)}
    if LibVersion < EVP_PKEY_save_parameters_introduced then
    begin
      {$if declared(FC_EVP_PKEY_save_parameters)}
      EVP_PKEY_save_parameters := FC_EVP_PKEY_save_parameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_save_parameters_removed)}
    if EVP_PKEY_save_parameters_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_save_parameters)}
      EVP_PKEY_save_parameters := _EVP_PKEY_save_parameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_save_parameters_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_save_parameters');
    {$ifend}
  end;


  EVP_PKEY_cmp_parameters := LoadLibFunction(ADllHandle, EVP_PKEY_cmp_parameters_procname);
  FuncLoadError := not assigned(EVP_PKEY_cmp_parameters);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_cmp_parameters_allownil)}
    EVP_PKEY_cmp_parameters := ERR_EVP_PKEY_cmp_parameters;
    {$ifend}
    {$if declared(EVP_PKEY_cmp_parameters_introduced)}
    if LibVersion < EVP_PKEY_cmp_parameters_introduced then
    begin
      {$if declared(FC_EVP_PKEY_cmp_parameters)}
      EVP_PKEY_cmp_parameters := FC_EVP_PKEY_cmp_parameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_cmp_parameters_removed)}
    if EVP_PKEY_cmp_parameters_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_cmp_parameters)}
      EVP_PKEY_cmp_parameters := _EVP_PKEY_cmp_parameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_cmp_parameters_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_cmp_parameters');
    {$ifend}
  end;


  EVP_PKEY_cmp := LoadLibFunction(ADllHandle, EVP_PKEY_cmp_procname);
  FuncLoadError := not assigned(EVP_PKEY_cmp);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_cmp_allownil)}
    EVP_PKEY_cmp := ERR_EVP_PKEY_cmp;
    {$ifend}
    {$if declared(EVP_PKEY_cmp_introduced)}
    if LibVersion < EVP_PKEY_cmp_introduced then
    begin
      {$if declared(FC_EVP_PKEY_cmp)}
      EVP_PKEY_cmp := FC_EVP_PKEY_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_cmp_removed)}
    if EVP_PKEY_cmp_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_cmp)}
      EVP_PKEY_cmp := _EVP_PKEY_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_cmp');
    {$ifend}
  end;


  EVP_PKEY_print_public := LoadLibFunction(ADllHandle, EVP_PKEY_print_public_procname);
  FuncLoadError := not assigned(EVP_PKEY_print_public);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_print_public_allownil)}
    EVP_PKEY_print_public := ERR_EVP_PKEY_print_public;
    {$ifend}
    {$if declared(EVP_PKEY_print_public_introduced)}
    if LibVersion < EVP_PKEY_print_public_introduced then
    begin
      {$if declared(FC_EVP_PKEY_print_public)}
      EVP_PKEY_print_public := FC_EVP_PKEY_print_public;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_print_public_removed)}
    if EVP_PKEY_print_public_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_print_public)}
      EVP_PKEY_print_public := _EVP_PKEY_print_public;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_print_public_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_print_public');
    {$ifend}
  end;


  EVP_PKEY_print_private := LoadLibFunction(ADllHandle, EVP_PKEY_print_private_procname);
  FuncLoadError := not assigned(EVP_PKEY_print_private);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_print_private_allownil)}
    EVP_PKEY_print_private := ERR_EVP_PKEY_print_private;
    {$ifend}
    {$if declared(EVP_PKEY_print_private_introduced)}
    if LibVersion < EVP_PKEY_print_private_introduced then
    begin
      {$if declared(FC_EVP_PKEY_print_private)}
      EVP_PKEY_print_private := FC_EVP_PKEY_print_private;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_print_private_removed)}
    if EVP_PKEY_print_private_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_print_private)}
      EVP_PKEY_print_private := _EVP_PKEY_print_private;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_print_private_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_print_private');
    {$ifend}
  end;


  EVP_PKEY_print_params := LoadLibFunction(ADllHandle, EVP_PKEY_print_params_procname);
  FuncLoadError := not assigned(EVP_PKEY_print_params);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_print_params_allownil)}
    EVP_PKEY_print_params := ERR_EVP_PKEY_print_params;
    {$ifend}
    {$if declared(EVP_PKEY_print_params_introduced)}
    if LibVersion < EVP_PKEY_print_params_introduced then
    begin
      {$if declared(FC_EVP_PKEY_print_params)}
      EVP_PKEY_print_params := FC_EVP_PKEY_print_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_print_params_removed)}
    if EVP_PKEY_print_params_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_print_params)}
      EVP_PKEY_print_params := _EVP_PKEY_print_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_print_params_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_print_params');
    {$ifend}
  end;


  EVP_PKEY_get_default_digest_nid := LoadLibFunction(ADllHandle, EVP_PKEY_get_default_digest_nid_procname);
  FuncLoadError := not assigned(EVP_PKEY_get_default_digest_nid);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_get_default_digest_nid_allownil)}
    EVP_PKEY_get_default_digest_nid := ERR_EVP_PKEY_get_default_digest_nid;
    {$ifend}
    {$if declared(EVP_PKEY_get_default_digest_nid_introduced)}
    if LibVersion < EVP_PKEY_get_default_digest_nid_introduced then
    begin
      {$if declared(FC_EVP_PKEY_get_default_digest_nid)}
      EVP_PKEY_get_default_digest_nid := FC_EVP_PKEY_get_default_digest_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_get_default_digest_nid_removed)}
    if EVP_PKEY_get_default_digest_nid_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_get_default_digest_nid)}
      EVP_PKEY_get_default_digest_nid := _EVP_PKEY_get_default_digest_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_get_default_digest_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_get_default_digest_nid');
    {$ifend}
  end;


  EVP_PKEY_set1_tls_encodedpoint := LoadLibFunction(ADllHandle, EVP_PKEY_set1_tls_encodedpoint_procname);
  FuncLoadError := not assigned(EVP_PKEY_set1_tls_encodedpoint);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_set1_tls_encodedpoint_allownil)}
    EVP_PKEY_set1_tls_encodedpoint := ERR_EVP_PKEY_set1_tls_encodedpoint;
    {$ifend}
    {$if declared(EVP_PKEY_set1_tls_encodedpoint_introduced)}
    if LibVersion < EVP_PKEY_set1_tls_encodedpoint_introduced then
    begin
      {$if declared(FC_EVP_PKEY_set1_tls_encodedpoint)}
      EVP_PKEY_set1_tls_encodedpoint := FC_EVP_PKEY_set1_tls_encodedpoint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_set1_tls_encodedpoint_removed)}
    if EVP_PKEY_set1_tls_encodedpoint_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_set1_tls_encodedpoint)}
      EVP_PKEY_set1_tls_encodedpoint := _EVP_PKEY_set1_tls_encodedpoint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_set1_tls_encodedpoint_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_set1_tls_encodedpoint');
    {$ifend}
  end;

 
  EVP_PKEY_get1_tls_encodedpoint := LoadLibFunction(ADllHandle, EVP_PKEY_get1_tls_encodedpoint_procname);
  FuncLoadError := not assigned(EVP_PKEY_get1_tls_encodedpoint);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_get1_tls_encodedpoint_allownil)}
    EVP_PKEY_get1_tls_encodedpoint := ERR_EVP_PKEY_get1_tls_encodedpoint;
    {$ifend}
    {$if declared(EVP_PKEY_get1_tls_encodedpoint_introduced)}
    if LibVersion < EVP_PKEY_get1_tls_encodedpoint_introduced then
    begin
      {$if declared(FC_EVP_PKEY_get1_tls_encodedpoint)}
      EVP_PKEY_get1_tls_encodedpoint := FC_EVP_PKEY_get1_tls_encodedpoint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_get1_tls_encodedpoint_removed)}
    if EVP_PKEY_get1_tls_encodedpoint_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_get1_tls_encodedpoint)}
      EVP_PKEY_get1_tls_encodedpoint := _EVP_PKEY_get1_tls_encodedpoint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_get1_tls_encodedpoint_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_get1_tls_encodedpoint');
    {$ifend}
  end;

 
  EVP_CIPHER_type := LoadLibFunction(ADllHandle, EVP_CIPHER_type_procname);
  FuncLoadError := not assigned(EVP_CIPHER_type);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_type_allownil)}
    EVP_CIPHER_type := ERR_EVP_CIPHER_type;
    {$ifend}
    {$if declared(EVP_CIPHER_type_introduced)}
    if LibVersion < EVP_CIPHER_type_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_type)}
      EVP_CIPHER_type := FC_EVP_CIPHER_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_type_removed)}
    if EVP_CIPHER_type_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_type)}
      EVP_CIPHER_type := _EVP_CIPHER_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_type_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_type');
    {$ifend}
  end;

  EVP_CIPHER_get_type := LoadLibFunction(ADllHandle, EVP_CIPHER_get_type_procname);
  FuncLoadError := not assigned(EVP_CIPHER_get_type);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_get_type_allownil)}
    EVP_CIPHER_get_type := ERR_EVP_CIPHER_get_type;
    {$ifend}
    {$if declared(EVP_CIPHER_get_type_introduced)}
    if LibVersion < EVP_CIPHER_get_type_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_get_type)}
      EVP_CIPHER_get_type := FC_EVP_CIPHER_get_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_get_type_removed)}
    if EVP_CIPHER_get_type_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_get_type)}
      EVP_CIPHER_get_type := _EVP_CIPHER_get_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_get_type_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_get_type');
    {$ifend}
  end;

 
  EVP_CIPHER_param_to_asn1 := LoadLibFunction(ADllHandle, EVP_CIPHER_param_to_asn1_procname);
  FuncLoadError := not assigned(EVP_CIPHER_param_to_asn1);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_param_to_asn1_allownil)}
    EVP_CIPHER_param_to_asn1 := ERR_EVP_CIPHER_param_to_asn1;
    {$ifend}
    {$if declared(EVP_CIPHER_param_to_asn1_introduced)}
    if LibVersion < EVP_CIPHER_param_to_asn1_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_param_to_asn1)}
      EVP_CIPHER_param_to_asn1 := FC_EVP_CIPHER_param_to_asn1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_param_to_asn1_removed)}
    if EVP_CIPHER_param_to_asn1_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_param_to_asn1)}
      EVP_CIPHER_param_to_asn1 := _EVP_CIPHER_param_to_asn1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_param_to_asn1_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_param_to_asn1');
    {$ifend}
  end;


  EVP_CIPHER_asn1_to_param := LoadLibFunction(ADllHandle, EVP_CIPHER_asn1_to_param_procname);
  FuncLoadError := not assigned(EVP_CIPHER_asn1_to_param);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_asn1_to_param_allownil)}
    EVP_CIPHER_asn1_to_param := ERR_EVP_CIPHER_asn1_to_param;
    {$ifend}
    {$if declared(EVP_CIPHER_asn1_to_param_introduced)}
    if LibVersion < EVP_CIPHER_asn1_to_param_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_asn1_to_param)}
      EVP_CIPHER_asn1_to_param := FC_EVP_CIPHER_asn1_to_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_asn1_to_param_removed)}
    if EVP_CIPHER_asn1_to_param_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_asn1_to_param)}
      EVP_CIPHER_asn1_to_param := _EVP_CIPHER_asn1_to_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_asn1_to_param_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_asn1_to_param');
    {$ifend}
  end;


  EVP_CIPHER_set_asn1_iv := LoadLibFunction(ADllHandle, EVP_CIPHER_set_asn1_iv_procname);
  FuncLoadError := not assigned(EVP_CIPHER_set_asn1_iv);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_set_asn1_iv_allownil)}
    EVP_CIPHER_set_asn1_iv := ERR_EVP_CIPHER_set_asn1_iv;
    {$ifend}
    {$if declared(EVP_CIPHER_set_asn1_iv_introduced)}
    if LibVersion < EVP_CIPHER_set_asn1_iv_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_set_asn1_iv)}
      EVP_CIPHER_set_asn1_iv := FC_EVP_CIPHER_set_asn1_iv;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_set_asn1_iv_removed)}
    if EVP_CIPHER_set_asn1_iv_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_set_asn1_iv)}
      EVP_CIPHER_set_asn1_iv := _EVP_CIPHER_set_asn1_iv;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_set_asn1_iv_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_set_asn1_iv');
    {$ifend}
  end;


  EVP_CIPHER_get_asn1_iv := LoadLibFunction(ADllHandle, EVP_CIPHER_get_asn1_iv_procname);
  FuncLoadError := not assigned(EVP_CIPHER_get_asn1_iv);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_get_asn1_iv_allownil)}
    EVP_CIPHER_get_asn1_iv := ERR_EVP_CIPHER_get_asn1_iv;
    {$ifend}
    {$if declared(EVP_CIPHER_get_asn1_iv_introduced)}
    if LibVersion < EVP_CIPHER_get_asn1_iv_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_get_asn1_iv)}
      EVP_CIPHER_get_asn1_iv := FC_EVP_CIPHER_get_asn1_iv;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_get_asn1_iv_removed)}
    if EVP_CIPHER_get_asn1_iv_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_get_asn1_iv)}
      EVP_CIPHER_get_asn1_iv := _EVP_CIPHER_get_asn1_iv;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_get_asn1_iv_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_get_asn1_iv');
    {$ifend}
  end;

  EVP_CIPHER_get_mode := LoadLibFunction(ADllHandle, EVP_CIPHER_get_mode_procname);
  FuncLoadError := not assigned(EVP_CIPHER_get_mode);
  if FuncLoadError then
  begin
    {$if not defined(EVP_CIPHER_get_mode_allownil)}
    EVP_CIPHER_get_mode := ERR_EVP_CIPHER_get_mode;
    {$ifend}
    {$if declared(EVP_CIPHER_get_mode_introduced)}
    if LibVersion < EVP_CIPHER_get_mode_introduced then
    begin
      {$if declared(FC_EVP_CIPHER_get_mode)}
      EVP_CIPHER_get_mode := FC_EVP_CIPHER_get_mode;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_CIPHER_get_mode_removed)}
    if EVP_CIPHER_get_mode_removed <= LibVersion then
    begin
      {$if declared(_EVP_CIPHER_get_mode)}
      EVP_CIPHER_get_mode := _EVP_CIPHER_get_mode;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_CIPHER_get_mode_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_get_mode');
    {$ifend}
  end;

  PKCS5_PBE_keyivgen := LoadLibFunction(ADllHandle, PKCS5_PBE_keyivgen_procname);
  FuncLoadError := not assigned(PKCS5_PBE_keyivgen);
  if FuncLoadError then
  begin
    {$if not defined(PKCS5_PBE_keyivgen_allownil)}
    PKCS5_PBE_keyivgen := ERR_PKCS5_PBE_keyivgen;
    {$ifend}
    {$if declared(PKCS5_PBE_keyivgen_introduced)}
    if LibVersion < PKCS5_PBE_keyivgen_introduced then
    begin
      {$if declared(FC_PKCS5_PBE_keyivgen)}
      PKCS5_PBE_keyivgen := FC_PKCS5_PBE_keyivgen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS5_PBE_keyivgen_removed)}
    if PKCS5_PBE_keyivgen_removed <= LibVersion then
    begin
      {$if declared(_PKCS5_PBE_keyivgen)}
      PKCS5_PBE_keyivgen := _PKCS5_PBE_keyivgen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS5_PBE_keyivgen_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS5_PBE_keyivgen');
    {$ifend}
  end;


  PKCS5_PBKDF2_HMAC_SHA1 := LoadLibFunction(ADllHandle, PKCS5_PBKDF2_HMAC_SHA1_procname);
  FuncLoadError := not assigned(PKCS5_PBKDF2_HMAC_SHA1);
  if FuncLoadError then
  begin
    {$if not defined(PKCS5_PBKDF2_HMAC_SHA1_allownil)}
    PKCS5_PBKDF2_HMAC_SHA1 := ERR_PKCS5_PBKDF2_HMAC_SHA1;
    {$ifend}
    {$if declared(PKCS5_PBKDF2_HMAC_SHA1_introduced)}
    if LibVersion < PKCS5_PBKDF2_HMAC_SHA1_introduced then
    begin
      {$if declared(FC_PKCS5_PBKDF2_HMAC_SHA1)}
      PKCS5_PBKDF2_HMAC_SHA1 := FC_PKCS5_PBKDF2_HMAC_SHA1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS5_PBKDF2_HMAC_SHA1_removed)}
    if PKCS5_PBKDF2_HMAC_SHA1_removed <= LibVersion then
    begin
      {$if declared(_PKCS5_PBKDF2_HMAC_SHA1)}
      PKCS5_PBKDF2_HMAC_SHA1 := _PKCS5_PBKDF2_HMAC_SHA1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS5_PBKDF2_HMAC_SHA1_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS5_PBKDF2_HMAC_SHA1');
    {$ifend}
  end;


  PKCS5_PBKDF2_HMAC := LoadLibFunction(ADllHandle, PKCS5_PBKDF2_HMAC_procname);
  FuncLoadError := not assigned(PKCS5_PBKDF2_HMAC);
  if FuncLoadError then
  begin
    {$if not defined(PKCS5_PBKDF2_HMAC_allownil)}
    PKCS5_PBKDF2_HMAC := ERR_PKCS5_PBKDF2_HMAC;
    {$ifend}
    {$if declared(PKCS5_PBKDF2_HMAC_introduced)}
    if LibVersion < PKCS5_PBKDF2_HMAC_introduced then
    begin
      {$if declared(FC_PKCS5_PBKDF2_HMAC)}
      PKCS5_PBKDF2_HMAC := FC_PKCS5_PBKDF2_HMAC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS5_PBKDF2_HMAC_removed)}
    if PKCS5_PBKDF2_HMAC_removed <= LibVersion then
    begin
      {$if declared(_PKCS5_PBKDF2_HMAC)}
      PKCS5_PBKDF2_HMAC := _PKCS5_PBKDF2_HMAC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS5_PBKDF2_HMAC_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS5_PBKDF2_HMAC');
    {$ifend}
  end;


  PKCS5_v2_PBE_keyivgen := LoadLibFunction(ADllHandle, PKCS5_v2_PBE_keyivgen_procname);
  FuncLoadError := not assigned(PKCS5_v2_PBE_keyivgen);
  if FuncLoadError then
  begin
    {$if not defined(PKCS5_v2_PBE_keyivgen_allownil)}
    PKCS5_v2_PBE_keyivgen := ERR_PKCS5_v2_PBE_keyivgen;
    {$ifend}
    {$if declared(PKCS5_v2_PBE_keyivgen_introduced)}
    if LibVersion < PKCS5_v2_PBE_keyivgen_introduced then
    begin
      {$if declared(FC_PKCS5_v2_PBE_keyivgen)}
      PKCS5_v2_PBE_keyivgen := FC_PKCS5_v2_PBE_keyivgen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS5_v2_PBE_keyivgen_removed)}
    if PKCS5_v2_PBE_keyivgen_removed <= LibVersion then
    begin
      {$if declared(_PKCS5_v2_PBE_keyivgen)}
      PKCS5_v2_PBE_keyivgen := _PKCS5_v2_PBE_keyivgen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS5_v2_PBE_keyivgen_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS5_v2_PBE_keyivgen');
    {$ifend}
  end;


  EVP_PBE_scrypt := LoadLibFunction(ADllHandle, EVP_PBE_scrypt_procname);
  FuncLoadError := not assigned(EVP_PBE_scrypt);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PBE_scrypt_allownil)}
    EVP_PBE_scrypt := ERR_EVP_PBE_scrypt;
    {$ifend}
    {$if declared(EVP_PBE_scrypt_introduced)}
    if LibVersion < EVP_PBE_scrypt_introduced then
    begin
      {$if declared(FC_EVP_PBE_scrypt)}
      EVP_PBE_scrypt := FC_EVP_PBE_scrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PBE_scrypt_removed)}
    if EVP_PBE_scrypt_removed <= LibVersion then
    begin
      {$if declared(_EVP_PBE_scrypt)}
      EVP_PBE_scrypt := _EVP_PBE_scrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PBE_scrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PBE_scrypt');
    {$ifend}
  end;

 {introduced 1.1.0}
  PKCS5_v2_scrypt_keyivgen := LoadLibFunction(ADllHandle, PKCS5_v2_scrypt_keyivgen_procname);
  FuncLoadError := not assigned(PKCS5_v2_scrypt_keyivgen);
  if FuncLoadError then
  begin
    {$if not defined(PKCS5_v2_scrypt_keyivgen_allownil)}
    PKCS5_v2_scrypt_keyivgen := ERR_PKCS5_v2_scrypt_keyivgen;
    {$ifend}
    {$if declared(PKCS5_v2_scrypt_keyivgen_introduced)}
    if LibVersion < PKCS5_v2_scrypt_keyivgen_introduced then
    begin
      {$if declared(FC_PKCS5_v2_scrypt_keyivgen)}
      PKCS5_v2_scrypt_keyivgen := FC_PKCS5_v2_scrypt_keyivgen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS5_v2_scrypt_keyivgen_removed)}
    if PKCS5_v2_scrypt_keyivgen_removed <= LibVersion then
    begin
      {$if declared(_PKCS5_v2_scrypt_keyivgen)}
      PKCS5_v2_scrypt_keyivgen := _PKCS5_v2_scrypt_keyivgen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS5_v2_scrypt_keyivgen_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS5_v2_scrypt_keyivgen');
    {$ifend}
  end;

 {introduced 1.1.0}
  PKCS5_PBE_add := LoadLibFunction(ADllHandle, PKCS5_PBE_add_procname);
  FuncLoadError := not assigned(PKCS5_PBE_add);
  if FuncLoadError then
  begin
    {$if not defined(PKCS5_PBE_add_allownil)}
    PKCS5_PBE_add := ERR_PKCS5_PBE_add;
    {$ifend}
    {$if declared(PKCS5_PBE_add_introduced)}
    if LibVersion < PKCS5_PBE_add_introduced then
    begin
      {$if declared(FC_PKCS5_PBE_add)}
      PKCS5_PBE_add := FC_PKCS5_PBE_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS5_PBE_add_removed)}
    if PKCS5_PBE_add_removed <= LibVersion then
    begin
      {$if declared(_PKCS5_PBE_add)}
      PKCS5_PBE_add := _PKCS5_PBE_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS5_PBE_add_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS5_PBE_add');
    {$ifend}
  end;


  EVP_PBE_CipherInit := LoadLibFunction(ADllHandle, EVP_PBE_CipherInit_procname);
  FuncLoadError := not assigned(EVP_PBE_CipherInit);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PBE_CipherInit_allownil)}
    EVP_PBE_CipherInit := ERR_EVP_PBE_CipherInit;
    {$ifend}
    {$if declared(EVP_PBE_CipherInit_introduced)}
    if LibVersion < EVP_PBE_CipherInit_introduced then
    begin
      {$if declared(FC_EVP_PBE_CipherInit)}
      EVP_PBE_CipherInit := FC_EVP_PBE_CipherInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PBE_CipherInit_removed)}
    if EVP_PBE_CipherInit_removed <= LibVersion then
    begin
      {$if declared(_EVP_PBE_CipherInit)}
      EVP_PBE_CipherInit := _EVP_PBE_CipherInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PBE_CipherInit_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PBE_CipherInit');
    {$ifend}
  end;


  EVP_PBE_alg_add_type := LoadLibFunction(ADllHandle, EVP_PBE_alg_add_type_procname);
  FuncLoadError := not assigned(EVP_PBE_alg_add_type);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PBE_alg_add_type_allownil)}
    EVP_PBE_alg_add_type := ERR_EVP_PBE_alg_add_type;
    {$ifend}
    {$if declared(EVP_PBE_alg_add_type_introduced)}
    if LibVersion < EVP_PBE_alg_add_type_introduced then
    begin
      {$if declared(FC_EVP_PBE_alg_add_type)}
      EVP_PBE_alg_add_type := FC_EVP_PBE_alg_add_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PBE_alg_add_type_removed)}
    if EVP_PBE_alg_add_type_removed <= LibVersion then
    begin
      {$if declared(_EVP_PBE_alg_add_type)}
      EVP_PBE_alg_add_type := _EVP_PBE_alg_add_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PBE_alg_add_type_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PBE_alg_add_type');
    {$ifend}
  end;


  EVP_PBE_alg_add := LoadLibFunction(ADllHandle, EVP_PBE_alg_add_procname);
  FuncLoadError := not assigned(EVP_PBE_alg_add);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PBE_alg_add_allownil)}
    EVP_PBE_alg_add := ERR_EVP_PBE_alg_add;
    {$ifend}
    {$if declared(EVP_PBE_alg_add_introduced)}
    if LibVersion < EVP_PBE_alg_add_introduced then
    begin
      {$if declared(FC_EVP_PBE_alg_add)}
      EVP_PBE_alg_add := FC_EVP_PBE_alg_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PBE_alg_add_removed)}
    if EVP_PBE_alg_add_removed <= LibVersion then
    begin
      {$if declared(_EVP_PBE_alg_add)}
      EVP_PBE_alg_add := _EVP_PBE_alg_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PBE_alg_add_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PBE_alg_add');
    {$ifend}
  end;


  EVP_PBE_find := LoadLibFunction(ADllHandle, EVP_PBE_find_procname);
  FuncLoadError := not assigned(EVP_PBE_find);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PBE_find_allownil)}
    EVP_PBE_find := ERR_EVP_PBE_find;
    {$ifend}
    {$if declared(EVP_PBE_find_introduced)}
    if LibVersion < EVP_PBE_find_introduced then
    begin
      {$if declared(FC_EVP_PBE_find)}
      EVP_PBE_find := FC_EVP_PBE_find;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PBE_find_removed)}
    if EVP_PBE_find_removed <= LibVersion then
    begin
      {$if declared(_EVP_PBE_find)}
      EVP_PBE_find := _EVP_PBE_find;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PBE_find_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PBE_find');
    {$ifend}
  end;


  EVP_PBE_cleanup := LoadLibFunction(ADllHandle, EVP_PBE_cleanup_procname);
  FuncLoadError := not assigned(EVP_PBE_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PBE_cleanup_allownil)}
    EVP_PBE_cleanup := ERR_EVP_PBE_cleanup;
    {$ifend}
    {$if declared(EVP_PBE_cleanup_introduced)}
    if LibVersion < EVP_PBE_cleanup_introduced then
    begin
      {$if declared(FC_EVP_PBE_cleanup)}
      EVP_PBE_cleanup := FC_EVP_PBE_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PBE_cleanup_removed)}
    if EVP_PBE_cleanup_removed <= LibVersion then
    begin
      {$if declared(_EVP_PBE_cleanup)}
      EVP_PBE_cleanup := _EVP_PBE_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PBE_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PBE_cleanup');
    {$ifend}
  end;


  EVP_PBE_get := LoadLibFunction(ADllHandle, EVP_PBE_get_procname);
  FuncLoadError := not assigned(EVP_PBE_get);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PBE_get_allownil)}
    EVP_PBE_get := ERR_EVP_PBE_get;
    {$ifend}
    {$if declared(EVP_PBE_get_introduced)}
    if LibVersion < EVP_PBE_get_introduced then
    begin
      {$if declared(FC_EVP_PBE_get)}
      EVP_PBE_get := FC_EVP_PBE_get;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PBE_get_removed)}
    if EVP_PBE_get_removed <= LibVersion then
    begin
      {$if declared(_EVP_PBE_get)}
      EVP_PBE_get := _EVP_PBE_get;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PBE_get_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PBE_get');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_asn1_get_count := LoadLibFunction(ADllHandle, EVP_PKEY_asn1_get_count_procname);
  FuncLoadError := not assigned(EVP_PKEY_asn1_get_count);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_asn1_get_count_allownil)}
    EVP_PKEY_asn1_get_count := ERR_EVP_PKEY_asn1_get_count;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_get_count_introduced)}
    if LibVersion < EVP_PKEY_asn1_get_count_introduced then
    begin
      {$if declared(FC_EVP_PKEY_asn1_get_count)}
      EVP_PKEY_asn1_get_count := FC_EVP_PKEY_asn1_get_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_get_count_removed)}
    if EVP_PKEY_asn1_get_count_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_asn1_get_count)}
      EVP_PKEY_asn1_get_count := _EVP_PKEY_asn1_get_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_asn1_get_count_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_asn1_get_count');
    {$ifend}
  end;


  EVP_PKEY_asn1_get0 := LoadLibFunction(ADllHandle, EVP_PKEY_asn1_get0_procname);
  FuncLoadError := not assigned(EVP_PKEY_asn1_get0);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_asn1_get0_allownil)}
    EVP_PKEY_asn1_get0 := ERR_EVP_PKEY_asn1_get0;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_get0_introduced)}
    if LibVersion < EVP_PKEY_asn1_get0_introduced then
    begin
      {$if declared(FC_EVP_PKEY_asn1_get0)}
      EVP_PKEY_asn1_get0 := FC_EVP_PKEY_asn1_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_get0_removed)}
    if EVP_PKEY_asn1_get0_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_asn1_get0)}
      EVP_PKEY_asn1_get0 := _EVP_PKEY_asn1_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_asn1_get0_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_asn1_get0');
    {$ifend}
  end;


  EVP_PKEY_asn1_find := LoadLibFunction(ADllHandle, EVP_PKEY_asn1_find_procname);
  FuncLoadError := not assigned(EVP_PKEY_asn1_find);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_asn1_find_allownil)}
    EVP_PKEY_asn1_find := ERR_EVP_PKEY_asn1_find;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_find_introduced)}
    if LibVersion < EVP_PKEY_asn1_find_introduced then
    begin
      {$if declared(FC_EVP_PKEY_asn1_find)}
      EVP_PKEY_asn1_find := FC_EVP_PKEY_asn1_find;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_find_removed)}
    if EVP_PKEY_asn1_find_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_asn1_find)}
      EVP_PKEY_asn1_find := _EVP_PKEY_asn1_find;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_asn1_find_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_asn1_find');
    {$ifend}
  end;


  EVP_PKEY_asn1_find_str := LoadLibFunction(ADllHandle, EVP_PKEY_asn1_find_str_procname);
  FuncLoadError := not assigned(EVP_PKEY_asn1_find_str);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_asn1_find_str_allownil)}
    EVP_PKEY_asn1_find_str := ERR_EVP_PKEY_asn1_find_str;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_find_str_introduced)}
    if LibVersion < EVP_PKEY_asn1_find_str_introduced then
    begin
      {$if declared(FC_EVP_PKEY_asn1_find_str)}
      EVP_PKEY_asn1_find_str := FC_EVP_PKEY_asn1_find_str;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_find_str_removed)}
    if EVP_PKEY_asn1_find_str_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_asn1_find_str)}
      EVP_PKEY_asn1_find_str := _EVP_PKEY_asn1_find_str;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_asn1_find_str_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_asn1_find_str');
    {$ifend}
  end;


  EVP_PKEY_asn1_add0 := LoadLibFunction(ADllHandle, EVP_PKEY_asn1_add0_procname);
  FuncLoadError := not assigned(EVP_PKEY_asn1_add0);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_asn1_add0_allownil)}
    EVP_PKEY_asn1_add0 := ERR_EVP_PKEY_asn1_add0;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_add0_introduced)}
    if LibVersion < EVP_PKEY_asn1_add0_introduced then
    begin
      {$if declared(FC_EVP_PKEY_asn1_add0)}
      EVP_PKEY_asn1_add0 := FC_EVP_PKEY_asn1_add0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_add0_removed)}
    if EVP_PKEY_asn1_add0_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_asn1_add0)}
      EVP_PKEY_asn1_add0 := _EVP_PKEY_asn1_add0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_asn1_add0_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_asn1_add0');
    {$ifend}
  end;


  EVP_PKEY_asn1_add_alias := LoadLibFunction(ADllHandle, EVP_PKEY_asn1_add_alias_procname);
  FuncLoadError := not assigned(EVP_PKEY_asn1_add_alias);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_asn1_add_alias_allownil)}
    EVP_PKEY_asn1_add_alias := ERR_EVP_PKEY_asn1_add_alias;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_add_alias_introduced)}
    if LibVersion < EVP_PKEY_asn1_add_alias_introduced then
    begin
      {$if declared(FC_EVP_PKEY_asn1_add_alias)}
      EVP_PKEY_asn1_add_alias := FC_EVP_PKEY_asn1_add_alias;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_add_alias_removed)}
    if EVP_PKEY_asn1_add_alias_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_asn1_add_alias)}
      EVP_PKEY_asn1_add_alias := _EVP_PKEY_asn1_add_alias;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_asn1_add_alias_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_asn1_add_alias');
    {$ifend}
  end;


  EVP_PKEY_asn1_get0_info := LoadLibFunction(ADllHandle, EVP_PKEY_asn1_get0_info_procname);
  FuncLoadError := not assigned(EVP_PKEY_asn1_get0_info);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_asn1_get0_info_allownil)}
    EVP_PKEY_asn1_get0_info := ERR_EVP_PKEY_asn1_get0_info;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_get0_info_introduced)}
    if LibVersion < EVP_PKEY_asn1_get0_info_introduced then
    begin
      {$if declared(FC_EVP_PKEY_asn1_get0_info)}
      EVP_PKEY_asn1_get0_info := FC_EVP_PKEY_asn1_get0_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_get0_info_removed)}
    if EVP_PKEY_asn1_get0_info_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_asn1_get0_info)}
      EVP_PKEY_asn1_get0_info := _EVP_PKEY_asn1_get0_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_asn1_get0_info_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_asn1_get0_info');
    {$ifend}
  end;


  EVP_PKEY_get0_asn1 := LoadLibFunction(ADllHandle, EVP_PKEY_get0_asn1_procname);
  FuncLoadError := not assigned(EVP_PKEY_get0_asn1);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_get0_asn1_allownil)}
    EVP_PKEY_get0_asn1 := ERR_EVP_PKEY_get0_asn1;
    {$ifend}
    {$if declared(EVP_PKEY_get0_asn1_introduced)}
    if LibVersion < EVP_PKEY_get0_asn1_introduced then
    begin
      {$if declared(FC_EVP_PKEY_get0_asn1)}
      EVP_PKEY_get0_asn1 := FC_EVP_PKEY_get0_asn1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_get0_asn1_removed)}
    if EVP_PKEY_get0_asn1_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_get0_asn1)}
      EVP_PKEY_get0_asn1 := _EVP_PKEY_get0_asn1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_get0_asn1_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_get0_asn1');
    {$ifend}
  end;


  EVP_PKEY_asn1_new := LoadLibFunction(ADllHandle, EVP_PKEY_asn1_new_procname);
  FuncLoadError := not assigned(EVP_PKEY_asn1_new);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_asn1_new_allownil)}
    EVP_PKEY_asn1_new := ERR_EVP_PKEY_asn1_new;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_new_introduced)}
    if LibVersion < EVP_PKEY_asn1_new_introduced then
    begin
      {$if declared(FC_EVP_PKEY_asn1_new)}
      EVP_PKEY_asn1_new := FC_EVP_PKEY_asn1_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_new_removed)}
    if EVP_PKEY_asn1_new_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_asn1_new)}
      EVP_PKEY_asn1_new := _EVP_PKEY_asn1_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_asn1_new_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_asn1_new');
    {$ifend}
  end;


  EVP_PKEY_asn1_copy := LoadLibFunction(ADllHandle, EVP_PKEY_asn1_copy_procname);
  FuncLoadError := not assigned(EVP_PKEY_asn1_copy);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_asn1_copy_allownil)}
    EVP_PKEY_asn1_copy := ERR_EVP_PKEY_asn1_copy;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_copy_introduced)}
    if LibVersion < EVP_PKEY_asn1_copy_introduced then
    begin
      {$if declared(FC_EVP_PKEY_asn1_copy)}
      EVP_PKEY_asn1_copy := FC_EVP_PKEY_asn1_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_copy_removed)}
    if EVP_PKEY_asn1_copy_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_asn1_copy)}
      EVP_PKEY_asn1_copy := _EVP_PKEY_asn1_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_asn1_copy_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_asn1_copy');
    {$ifend}
  end;


  EVP_PKEY_asn1_free := LoadLibFunction(ADllHandle, EVP_PKEY_asn1_free_procname);
  FuncLoadError := not assigned(EVP_PKEY_asn1_free);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_asn1_free_allownil)}
    EVP_PKEY_asn1_free := ERR_EVP_PKEY_asn1_free;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_free_introduced)}
    if LibVersion < EVP_PKEY_asn1_free_introduced then
    begin
      {$if declared(FC_EVP_PKEY_asn1_free)}
      EVP_PKEY_asn1_free := FC_EVP_PKEY_asn1_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_free_removed)}
    if EVP_PKEY_asn1_free_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_asn1_free)}
      EVP_PKEY_asn1_free := _EVP_PKEY_asn1_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_asn1_free_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_asn1_free');
    {$ifend}
  end;


  EVP_PKEY_asn1_set_public := LoadLibFunction(ADllHandle, EVP_PKEY_asn1_set_public_procname);
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_public);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_asn1_set_public_allownil)}
    EVP_PKEY_asn1_set_public := ERR_EVP_PKEY_asn1_set_public;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_public_introduced)}
    if LibVersion < EVP_PKEY_asn1_set_public_introduced then
    begin
      {$if declared(FC_EVP_PKEY_asn1_set_public)}
      EVP_PKEY_asn1_set_public := FC_EVP_PKEY_asn1_set_public;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_public_removed)}
    if EVP_PKEY_asn1_set_public_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_asn1_set_public)}
      EVP_PKEY_asn1_set_public := _EVP_PKEY_asn1_set_public;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_asn1_set_public_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_asn1_set_public');
    {$ifend}
  end;


  EVP_PKEY_asn1_set_private := LoadLibFunction(ADllHandle, EVP_PKEY_asn1_set_private_procname);
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_private);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_asn1_set_private_allownil)}
    EVP_PKEY_asn1_set_private := ERR_EVP_PKEY_asn1_set_private;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_private_introduced)}
    if LibVersion < EVP_PKEY_asn1_set_private_introduced then
    begin
      {$if declared(FC_EVP_PKEY_asn1_set_private)}
      EVP_PKEY_asn1_set_private := FC_EVP_PKEY_asn1_set_private;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_private_removed)}
    if EVP_PKEY_asn1_set_private_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_asn1_set_private)}
      EVP_PKEY_asn1_set_private := _EVP_PKEY_asn1_set_private;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_asn1_set_private_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_asn1_set_private');
    {$ifend}
  end;


  EVP_PKEY_asn1_set_param := LoadLibFunction(ADllHandle, EVP_PKEY_asn1_set_param_procname);
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_param);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_asn1_set_param_allownil)}
    EVP_PKEY_asn1_set_param := ERR_EVP_PKEY_asn1_set_param;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_param_introduced)}
    if LibVersion < EVP_PKEY_asn1_set_param_introduced then
    begin
      {$if declared(FC_EVP_PKEY_asn1_set_param)}
      EVP_PKEY_asn1_set_param := FC_EVP_PKEY_asn1_set_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_param_removed)}
    if EVP_PKEY_asn1_set_param_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_asn1_set_param)}
      EVP_PKEY_asn1_set_param := _EVP_PKEY_asn1_set_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_asn1_set_param_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_asn1_set_param');
    {$ifend}
  end;


  EVP_PKEY_asn1_set_free := LoadLibFunction(ADllHandle, EVP_PKEY_asn1_set_free_procname);
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_free);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_asn1_set_free_allownil)}
    EVP_PKEY_asn1_set_free := ERR_EVP_PKEY_asn1_set_free;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_free_introduced)}
    if LibVersion < EVP_PKEY_asn1_set_free_introduced then
    begin
      {$if declared(FC_EVP_PKEY_asn1_set_free)}
      EVP_PKEY_asn1_set_free := FC_EVP_PKEY_asn1_set_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_free_removed)}
    if EVP_PKEY_asn1_set_free_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_asn1_set_free)}
      EVP_PKEY_asn1_set_free := _EVP_PKEY_asn1_set_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_asn1_set_free_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_asn1_set_free');
    {$ifend}
  end;


  EVP_PKEY_asn1_set_ctrl := LoadLibFunction(ADllHandle, EVP_PKEY_asn1_set_ctrl_procname);
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_asn1_set_ctrl_allownil)}
    EVP_PKEY_asn1_set_ctrl := ERR_EVP_PKEY_asn1_set_ctrl;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_ctrl_introduced)}
    if LibVersion < EVP_PKEY_asn1_set_ctrl_introduced then
    begin
      {$if declared(FC_EVP_PKEY_asn1_set_ctrl)}
      EVP_PKEY_asn1_set_ctrl := FC_EVP_PKEY_asn1_set_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_ctrl_removed)}
    if EVP_PKEY_asn1_set_ctrl_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_asn1_set_ctrl)}
      EVP_PKEY_asn1_set_ctrl := _EVP_PKEY_asn1_set_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_asn1_set_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_asn1_set_ctrl');
    {$ifend}
  end;


  EVP_PKEY_asn1_set_item := LoadLibFunction(ADllHandle, EVP_PKEY_asn1_set_item_procname);
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_item);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_asn1_set_item_allownil)}
    EVP_PKEY_asn1_set_item := ERR_EVP_PKEY_asn1_set_item;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_item_introduced)}
    if LibVersion < EVP_PKEY_asn1_set_item_introduced then
    begin
      {$if declared(FC_EVP_PKEY_asn1_set_item)}
      EVP_PKEY_asn1_set_item := FC_EVP_PKEY_asn1_set_item;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_item_removed)}
    if EVP_PKEY_asn1_set_item_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_asn1_set_item)}
      EVP_PKEY_asn1_set_item := _EVP_PKEY_asn1_set_item;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_asn1_set_item_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_asn1_set_item');
    {$ifend}
  end;


  EVP_PKEY_asn1_set_siginf := LoadLibFunction(ADllHandle, EVP_PKEY_asn1_set_siginf_procname);
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_siginf);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_asn1_set_siginf_allownil)}
    EVP_PKEY_asn1_set_siginf := ERR_EVP_PKEY_asn1_set_siginf;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_siginf_introduced)}
    if LibVersion < EVP_PKEY_asn1_set_siginf_introduced then
    begin
      {$if declared(FC_EVP_PKEY_asn1_set_siginf)}
      EVP_PKEY_asn1_set_siginf := FC_EVP_PKEY_asn1_set_siginf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_siginf_removed)}
    if EVP_PKEY_asn1_set_siginf_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_asn1_set_siginf)}
      EVP_PKEY_asn1_set_siginf := _EVP_PKEY_asn1_set_siginf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_asn1_set_siginf_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_asn1_set_siginf');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_asn1_set_check := LoadLibFunction(ADllHandle, EVP_PKEY_asn1_set_check_procname);
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_check);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_asn1_set_check_allownil)}
    EVP_PKEY_asn1_set_check := ERR_EVP_PKEY_asn1_set_check;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_check_introduced)}
    if LibVersion < EVP_PKEY_asn1_set_check_introduced then
    begin
      {$if declared(FC_EVP_PKEY_asn1_set_check)}
      EVP_PKEY_asn1_set_check := FC_EVP_PKEY_asn1_set_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_check_removed)}
    if EVP_PKEY_asn1_set_check_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_asn1_set_check)}
      EVP_PKEY_asn1_set_check := _EVP_PKEY_asn1_set_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_asn1_set_check_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_asn1_set_check');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_asn1_set_public_check := LoadLibFunction(ADllHandle, EVP_PKEY_asn1_set_public_check_procname);
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_public_check);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_asn1_set_public_check_allownil)}
    EVP_PKEY_asn1_set_public_check := ERR_EVP_PKEY_asn1_set_public_check;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_public_check_introduced)}
    if LibVersion < EVP_PKEY_asn1_set_public_check_introduced then
    begin
      {$if declared(FC_EVP_PKEY_asn1_set_public_check)}
      EVP_PKEY_asn1_set_public_check := FC_EVP_PKEY_asn1_set_public_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_public_check_removed)}
    if EVP_PKEY_asn1_set_public_check_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_asn1_set_public_check)}
      EVP_PKEY_asn1_set_public_check := _EVP_PKEY_asn1_set_public_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_asn1_set_public_check_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_asn1_set_public_check');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_asn1_set_param_check := LoadLibFunction(ADllHandle, EVP_PKEY_asn1_set_param_check_procname);
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_param_check);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_asn1_set_param_check_allownil)}
    EVP_PKEY_asn1_set_param_check := ERR_EVP_PKEY_asn1_set_param_check;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_param_check_introduced)}
    if LibVersion < EVP_PKEY_asn1_set_param_check_introduced then
    begin
      {$if declared(FC_EVP_PKEY_asn1_set_param_check)}
      EVP_PKEY_asn1_set_param_check := FC_EVP_PKEY_asn1_set_param_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_param_check_removed)}
    if EVP_PKEY_asn1_set_param_check_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_asn1_set_param_check)}
      EVP_PKEY_asn1_set_param_check := _EVP_PKEY_asn1_set_param_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_asn1_set_param_check_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_asn1_set_param_check');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_asn1_set_set_priv_key := LoadLibFunction(ADllHandle, EVP_PKEY_asn1_set_set_priv_key_procname);
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_set_priv_key);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_asn1_set_set_priv_key_allownil)}
    EVP_PKEY_asn1_set_set_priv_key := ERR_EVP_PKEY_asn1_set_set_priv_key;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_set_priv_key_introduced)}
    if LibVersion < EVP_PKEY_asn1_set_set_priv_key_introduced then
    begin
      {$if declared(FC_EVP_PKEY_asn1_set_set_priv_key)}
      EVP_PKEY_asn1_set_set_priv_key := FC_EVP_PKEY_asn1_set_set_priv_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_set_priv_key_removed)}
    if EVP_PKEY_asn1_set_set_priv_key_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_asn1_set_set_priv_key)}
      EVP_PKEY_asn1_set_set_priv_key := _EVP_PKEY_asn1_set_set_priv_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_asn1_set_set_priv_key_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_asn1_set_set_priv_key');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_asn1_set_set_pub_key := LoadLibFunction(ADllHandle, EVP_PKEY_asn1_set_set_pub_key_procname);
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_set_pub_key);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_asn1_set_set_pub_key_allownil)}
    EVP_PKEY_asn1_set_set_pub_key := ERR_EVP_PKEY_asn1_set_set_pub_key;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_set_pub_key_introduced)}
    if LibVersion < EVP_PKEY_asn1_set_set_pub_key_introduced then
    begin
      {$if declared(FC_EVP_PKEY_asn1_set_set_pub_key)}
      EVP_PKEY_asn1_set_set_pub_key := FC_EVP_PKEY_asn1_set_set_pub_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_set_pub_key_removed)}
    if EVP_PKEY_asn1_set_set_pub_key_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_asn1_set_set_pub_key)}
      EVP_PKEY_asn1_set_set_pub_key := _EVP_PKEY_asn1_set_set_pub_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_asn1_set_set_pub_key_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_asn1_set_set_pub_key');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_asn1_set_get_priv_key := LoadLibFunction(ADllHandle, EVP_PKEY_asn1_set_get_priv_key_procname);
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_get_priv_key);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_asn1_set_get_priv_key_allownil)}
    EVP_PKEY_asn1_set_get_priv_key := ERR_EVP_PKEY_asn1_set_get_priv_key;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_get_priv_key_introduced)}
    if LibVersion < EVP_PKEY_asn1_set_get_priv_key_introduced then
    begin
      {$if declared(FC_EVP_PKEY_asn1_set_get_priv_key)}
      EVP_PKEY_asn1_set_get_priv_key := FC_EVP_PKEY_asn1_set_get_priv_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_get_priv_key_removed)}
    if EVP_PKEY_asn1_set_get_priv_key_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_asn1_set_get_priv_key)}
      EVP_PKEY_asn1_set_get_priv_key := _EVP_PKEY_asn1_set_get_priv_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_asn1_set_get_priv_key_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_asn1_set_get_priv_key');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_asn1_set_get_pub_key := LoadLibFunction(ADllHandle, EVP_PKEY_asn1_set_get_pub_key_procname);
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_get_pub_key);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_asn1_set_get_pub_key_allownil)}
    EVP_PKEY_asn1_set_get_pub_key := ERR_EVP_PKEY_asn1_set_get_pub_key;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_get_pub_key_introduced)}
    if LibVersion < EVP_PKEY_asn1_set_get_pub_key_introduced then
    begin
      {$if declared(FC_EVP_PKEY_asn1_set_get_pub_key)}
      EVP_PKEY_asn1_set_get_pub_key := FC_EVP_PKEY_asn1_set_get_pub_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_get_pub_key_removed)}
    if EVP_PKEY_asn1_set_get_pub_key_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_asn1_set_get_pub_key)}
      EVP_PKEY_asn1_set_get_pub_key := _EVP_PKEY_asn1_set_get_pub_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_asn1_set_get_pub_key_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_asn1_set_get_pub_key');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_asn1_set_security_bits := LoadLibFunction(ADllHandle, EVP_PKEY_asn1_set_security_bits_procname);
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_security_bits);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_asn1_set_security_bits_allownil)}
    EVP_PKEY_asn1_set_security_bits := ERR_EVP_PKEY_asn1_set_security_bits;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_security_bits_introduced)}
    if LibVersion < EVP_PKEY_asn1_set_security_bits_introduced then
    begin
      {$if declared(FC_EVP_PKEY_asn1_set_security_bits)}
      EVP_PKEY_asn1_set_security_bits := FC_EVP_PKEY_asn1_set_security_bits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_asn1_set_security_bits_removed)}
    if EVP_PKEY_asn1_set_security_bits_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_asn1_set_security_bits)}
      EVP_PKEY_asn1_set_security_bits := _EVP_PKEY_asn1_set_security_bits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_asn1_set_security_bits_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_asn1_set_security_bits');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_meth_find := LoadLibFunction(ADllHandle, EVP_PKEY_meth_find_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_find);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_find_allownil)}
    EVP_PKEY_meth_find := ERR_EVP_PKEY_meth_find;
    {$ifend}
    {$if declared(EVP_PKEY_meth_find_introduced)}
    if LibVersion < EVP_PKEY_meth_find_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_find)}
      EVP_PKEY_meth_find := FC_EVP_PKEY_meth_find;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_find_removed)}
    if EVP_PKEY_meth_find_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_find)}
      EVP_PKEY_meth_find := _EVP_PKEY_meth_find;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_find_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_find');
    {$ifend}
  end;


  EVP_PKEY_meth_new := LoadLibFunction(ADllHandle, EVP_PKEY_meth_new_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_new);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_new_allownil)}
    EVP_PKEY_meth_new := ERR_EVP_PKEY_meth_new;
    {$ifend}
    {$if declared(EVP_PKEY_meth_new_introduced)}
    if LibVersion < EVP_PKEY_meth_new_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_new)}
      EVP_PKEY_meth_new := FC_EVP_PKEY_meth_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_new_removed)}
    if EVP_PKEY_meth_new_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_new)}
      EVP_PKEY_meth_new := _EVP_PKEY_meth_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_new_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_new');
    {$ifend}
  end;


  EVP_PKEY_meth_get0_info := LoadLibFunction(ADllHandle, EVP_PKEY_meth_get0_info_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_get0_info);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_get0_info_allownil)}
    EVP_PKEY_meth_get0_info := ERR_EVP_PKEY_meth_get0_info;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get0_info_introduced)}
    if LibVersion < EVP_PKEY_meth_get0_info_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_get0_info)}
      EVP_PKEY_meth_get0_info := FC_EVP_PKEY_meth_get0_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get0_info_removed)}
    if EVP_PKEY_meth_get0_info_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_get0_info)}
      EVP_PKEY_meth_get0_info := _EVP_PKEY_meth_get0_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_get0_info_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_get0_info');
    {$ifend}
  end;


  EVP_PKEY_meth_copy := LoadLibFunction(ADllHandle, EVP_PKEY_meth_copy_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_copy);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_copy_allownil)}
    EVP_PKEY_meth_copy := ERR_EVP_PKEY_meth_copy;
    {$ifend}
    {$if declared(EVP_PKEY_meth_copy_introduced)}
    if LibVersion < EVP_PKEY_meth_copy_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_copy)}
      EVP_PKEY_meth_copy := FC_EVP_PKEY_meth_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_copy_removed)}
    if EVP_PKEY_meth_copy_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_copy)}
      EVP_PKEY_meth_copy := _EVP_PKEY_meth_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_copy_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_copy');
    {$ifend}
  end;


  EVP_PKEY_meth_free := LoadLibFunction(ADllHandle, EVP_PKEY_meth_free_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_free);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_free_allownil)}
    EVP_PKEY_meth_free := ERR_EVP_PKEY_meth_free;
    {$ifend}
    {$if declared(EVP_PKEY_meth_free_introduced)}
    if LibVersion < EVP_PKEY_meth_free_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_free)}
      EVP_PKEY_meth_free := FC_EVP_PKEY_meth_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_free_removed)}
    if EVP_PKEY_meth_free_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_free)}
      EVP_PKEY_meth_free := _EVP_PKEY_meth_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_free_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_free');
    {$ifend}
  end;


  EVP_PKEY_meth_add0 := LoadLibFunction(ADllHandle, EVP_PKEY_meth_add0_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_add0);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_add0_allownil)}
    EVP_PKEY_meth_add0 := ERR_EVP_PKEY_meth_add0;
    {$ifend}
    {$if declared(EVP_PKEY_meth_add0_introduced)}
    if LibVersion < EVP_PKEY_meth_add0_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_add0)}
      EVP_PKEY_meth_add0 := FC_EVP_PKEY_meth_add0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_add0_removed)}
    if EVP_PKEY_meth_add0_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_add0)}
      EVP_PKEY_meth_add0 := _EVP_PKEY_meth_add0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_add0_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_add0');
    {$ifend}
  end;


  EVP_PKEY_meth_remove := LoadLibFunction(ADllHandle, EVP_PKEY_meth_remove_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_remove);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_remove_allownil)}
    EVP_PKEY_meth_remove := ERR_EVP_PKEY_meth_remove;
    {$ifend}
    {$if declared(EVP_PKEY_meth_remove_introduced)}
    if LibVersion < EVP_PKEY_meth_remove_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_remove)}
      EVP_PKEY_meth_remove := FC_EVP_PKEY_meth_remove;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_remove_removed)}
    if EVP_PKEY_meth_remove_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_remove)}
      EVP_PKEY_meth_remove := _EVP_PKEY_meth_remove;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_remove_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_remove');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_meth_get_count := LoadLibFunction(ADllHandle, EVP_PKEY_meth_get_count_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_get_count);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_get_count_allownil)}
    EVP_PKEY_meth_get_count := ERR_EVP_PKEY_meth_get_count;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_count_introduced)}
    if LibVersion < EVP_PKEY_meth_get_count_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_get_count)}
      EVP_PKEY_meth_get_count := FC_EVP_PKEY_meth_get_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_count_removed)}
    if EVP_PKEY_meth_get_count_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_get_count)}
      EVP_PKEY_meth_get_count := _EVP_PKEY_meth_get_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_get_count_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_get_count');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_meth_get0 := LoadLibFunction(ADllHandle, EVP_PKEY_meth_get0_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_get0);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_get0_allownil)}
    EVP_PKEY_meth_get0 := ERR_EVP_PKEY_meth_get0;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get0_introduced)}
    if LibVersion < EVP_PKEY_meth_get0_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_get0)}
      EVP_PKEY_meth_get0 := FC_EVP_PKEY_meth_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get0_removed)}
    if EVP_PKEY_meth_get0_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_get0)}
      EVP_PKEY_meth_get0 := _EVP_PKEY_meth_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_get0_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_get0');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_CTX_new := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_new_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_new);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_new_allownil)}
    EVP_PKEY_CTX_new := ERR_EVP_PKEY_CTX_new;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_new_introduced)}
    if LibVersion < EVP_PKEY_CTX_new_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_new)}
      EVP_PKEY_CTX_new := FC_EVP_PKEY_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_new_removed)}
    if EVP_PKEY_CTX_new_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_new)}
      EVP_PKEY_CTX_new := _EVP_PKEY_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_new');
    {$ifend}
  end;


  EVP_PKEY_CTX_new_id := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_new_id_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_new_id);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_new_id_allownil)}
    EVP_PKEY_CTX_new_id := ERR_EVP_PKEY_CTX_new_id;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_new_id_introduced)}
    if LibVersion < EVP_PKEY_CTX_new_id_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_new_id)}
      EVP_PKEY_CTX_new_id := FC_EVP_PKEY_CTX_new_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_new_id_removed)}
    if EVP_PKEY_CTX_new_id_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_new_id)}
      EVP_PKEY_CTX_new_id := _EVP_PKEY_CTX_new_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_new_id_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_new_id');
    {$ifend}
  end;


  EVP_PKEY_CTX_dup := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_dup_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_dup);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_dup_allownil)}
    EVP_PKEY_CTX_dup := ERR_EVP_PKEY_CTX_dup;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_dup_introduced)}
    if LibVersion < EVP_PKEY_CTX_dup_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_dup)}
      EVP_PKEY_CTX_dup := FC_EVP_PKEY_CTX_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_dup_removed)}
    if EVP_PKEY_CTX_dup_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_dup)}
      EVP_PKEY_CTX_dup := _EVP_PKEY_CTX_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_dup');
    {$ifend}
  end;


  EVP_PKEY_CTX_free := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_free_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_free);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_free_allownil)}
    EVP_PKEY_CTX_free := ERR_EVP_PKEY_CTX_free;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_free_introduced)}
    if LibVersion < EVP_PKEY_CTX_free_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_free)}
      EVP_PKEY_CTX_free := FC_EVP_PKEY_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_free_removed)}
    if EVP_PKEY_CTX_free_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_free)}
      EVP_PKEY_CTX_free := _EVP_PKEY_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_free');
    {$ifend}
  end;


  EVP_PKEY_CTX_ctrl := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_ctrl_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_ctrl_allownil)}
    EVP_PKEY_CTX_ctrl := ERR_EVP_PKEY_CTX_ctrl;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_ctrl_introduced)}
    if LibVersion < EVP_PKEY_CTX_ctrl_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_ctrl)}
      EVP_PKEY_CTX_ctrl := FC_EVP_PKEY_CTX_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_ctrl_removed)}
    if EVP_PKEY_CTX_ctrl_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_ctrl)}
      EVP_PKEY_CTX_ctrl := _EVP_PKEY_CTX_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_ctrl');
    {$ifend}
  end;


  EVP_PKEY_CTX_ctrl_str := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_ctrl_str_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_ctrl_str);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_ctrl_str_allownil)}
    EVP_PKEY_CTX_ctrl_str := ERR_EVP_PKEY_CTX_ctrl_str;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_ctrl_str_introduced)}
    if LibVersion < EVP_PKEY_CTX_ctrl_str_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_ctrl_str)}
      EVP_PKEY_CTX_ctrl_str := FC_EVP_PKEY_CTX_ctrl_str;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_ctrl_str_removed)}
    if EVP_PKEY_CTX_ctrl_str_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_ctrl_str)}
      EVP_PKEY_CTX_ctrl_str := _EVP_PKEY_CTX_ctrl_str;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_ctrl_str_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_ctrl_str');
    {$ifend}
  end;


  EVP_PKEY_CTX_ctrl_uint64 := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_ctrl_uint64_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_ctrl_uint64);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_ctrl_uint64_allownil)}
    EVP_PKEY_CTX_ctrl_uint64 := ERR_EVP_PKEY_CTX_ctrl_uint64;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_ctrl_uint64_introduced)}
    if LibVersion < EVP_PKEY_CTX_ctrl_uint64_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_ctrl_uint64)}
      EVP_PKEY_CTX_ctrl_uint64 := FC_EVP_PKEY_CTX_ctrl_uint64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_ctrl_uint64_removed)}
    if EVP_PKEY_CTX_ctrl_uint64_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_ctrl_uint64)}
      EVP_PKEY_CTX_ctrl_uint64 := _EVP_PKEY_CTX_ctrl_uint64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_ctrl_uint64_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_ctrl_uint64');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_CTX_str2ctrl := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_str2ctrl_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_str2ctrl);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_str2ctrl_allownil)}
    EVP_PKEY_CTX_str2ctrl := ERR_EVP_PKEY_CTX_str2ctrl;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_str2ctrl_introduced)}
    if LibVersion < EVP_PKEY_CTX_str2ctrl_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_str2ctrl)}
      EVP_PKEY_CTX_str2ctrl := FC_EVP_PKEY_CTX_str2ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_str2ctrl_removed)}
    if EVP_PKEY_CTX_str2ctrl_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_str2ctrl)}
      EVP_PKEY_CTX_str2ctrl := _EVP_PKEY_CTX_str2ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_str2ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_str2ctrl');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_CTX_hex2ctrl := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_hex2ctrl_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_hex2ctrl);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_hex2ctrl_allownil)}
    EVP_PKEY_CTX_hex2ctrl := ERR_EVP_PKEY_CTX_hex2ctrl;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_hex2ctrl_introduced)}
    if LibVersion < EVP_PKEY_CTX_hex2ctrl_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_hex2ctrl)}
      EVP_PKEY_CTX_hex2ctrl := FC_EVP_PKEY_CTX_hex2ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_hex2ctrl_removed)}
    if EVP_PKEY_CTX_hex2ctrl_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_hex2ctrl)}
      EVP_PKEY_CTX_hex2ctrl := _EVP_PKEY_CTX_hex2ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_hex2ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_hex2ctrl');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_CTX_md := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_md_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_md);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_md_allownil)}
    EVP_PKEY_CTX_md := ERR_EVP_PKEY_CTX_md;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_md_introduced)}
    if LibVersion < EVP_PKEY_CTX_md_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_md)}
      EVP_PKEY_CTX_md := FC_EVP_PKEY_CTX_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_md_removed)}
    if EVP_PKEY_CTX_md_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_md)}
      EVP_PKEY_CTX_md := _EVP_PKEY_CTX_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_md_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_md');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_CTX_get_operation := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_get_operation_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_get_operation);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_get_operation_allownil)}
    EVP_PKEY_CTX_get_operation := ERR_EVP_PKEY_CTX_get_operation;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_operation_introduced)}
    if LibVersion < EVP_PKEY_CTX_get_operation_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_get_operation)}
      EVP_PKEY_CTX_get_operation := FC_EVP_PKEY_CTX_get_operation;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_operation_removed)}
    if EVP_PKEY_CTX_get_operation_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_get_operation)}
      EVP_PKEY_CTX_get_operation := _EVP_PKEY_CTX_get_operation;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_get_operation_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_get_operation');
    {$ifend}
  end;


  EVP_PKEY_CTX_set0_keygen_info := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set0_keygen_info_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set0_keygen_info);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set0_keygen_info_allownil)}
    EVP_PKEY_CTX_set0_keygen_info := ERR_EVP_PKEY_CTX_set0_keygen_info;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set0_keygen_info_introduced)}
    if LibVersion < EVP_PKEY_CTX_set0_keygen_info_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set0_keygen_info)}
      EVP_PKEY_CTX_set0_keygen_info := FC_EVP_PKEY_CTX_set0_keygen_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set0_keygen_info_removed)}
    if EVP_PKEY_CTX_set0_keygen_info_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set0_keygen_info)}
      EVP_PKEY_CTX_set0_keygen_info := _EVP_PKEY_CTX_set0_keygen_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set0_keygen_info_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set0_keygen_info');
    {$ifend}
  end;


  EVP_PKEY_new_mac_key := LoadLibFunction(ADllHandle, EVP_PKEY_new_mac_key_procname);
  FuncLoadError := not assigned(EVP_PKEY_new_mac_key);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_new_mac_key_allownil)}
    EVP_PKEY_new_mac_key := ERR_EVP_PKEY_new_mac_key;
    {$ifend}
    {$if declared(EVP_PKEY_new_mac_key_introduced)}
    if LibVersion < EVP_PKEY_new_mac_key_introduced then
    begin
      {$if declared(FC_EVP_PKEY_new_mac_key)}
      EVP_PKEY_new_mac_key := FC_EVP_PKEY_new_mac_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_new_mac_key_removed)}
    if EVP_PKEY_new_mac_key_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_new_mac_key)}
      EVP_PKEY_new_mac_key := _EVP_PKEY_new_mac_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_new_mac_key_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_new_mac_key');
    {$ifend}
  end;


  EVP_PKEY_new_raw_private_key := LoadLibFunction(ADllHandle, EVP_PKEY_new_raw_private_key_procname);
  FuncLoadError := not assigned(EVP_PKEY_new_raw_private_key);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_new_raw_private_key_allownil)}
    EVP_PKEY_new_raw_private_key := ERR_EVP_PKEY_new_raw_private_key;
    {$ifend}
    {$if declared(EVP_PKEY_new_raw_private_key_introduced)}
    if LibVersion < EVP_PKEY_new_raw_private_key_introduced then
    begin
      {$if declared(FC_EVP_PKEY_new_raw_private_key)}
      EVP_PKEY_new_raw_private_key := FC_EVP_PKEY_new_raw_private_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_new_raw_private_key_removed)}
    if EVP_PKEY_new_raw_private_key_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_new_raw_private_key)}
      EVP_PKEY_new_raw_private_key := _EVP_PKEY_new_raw_private_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_new_raw_private_key_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_new_raw_private_key');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_new_raw_public_key := LoadLibFunction(ADllHandle, EVP_PKEY_new_raw_public_key_procname);
  FuncLoadError := not assigned(EVP_PKEY_new_raw_public_key);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_new_raw_public_key_allownil)}
    EVP_PKEY_new_raw_public_key := ERR_EVP_PKEY_new_raw_public_key;
    {$ifend}
    {$if declared(EVP_PKEY_new_raw_public_key_introduced)}
    if LibVersion < EVP_PKEY_new_raw_public_key_introduced then
    begin
      {$if declared(FC_EVP_PKEY_new_raw_public_key)}
      EVP_PKEY_new_raw_public_key := FC_EVP_PKEY_new_raw_public_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_new_raw_public_key_removed)}
    if EVP_PKEY_new_raw_public_key_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_new_raw_public_key)}
      EVP_PKEY_new_raw_public_key := _EVP_PKEY_new_raw_public_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_new_raw_public_key_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_new_raw_public_key');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_get_raw_private_key := LoadLibFunction(ADllHandle, EVP_PKEY_get_raw_private_key_procname);
  FuncLoadError := not assigned(EVP_PKEY_get_raw_private_key);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_get_raw_private_key_allownil)}
    EVP_PKEY_get_raw_private_key := ERR_EVP_PKEY_get_raw_private_key;
    {$ifend}
    {$if declared(EVP_PKEY_get_raw_private_key_introduced)}
    if LibVersion < EVP_PKEY_get_raw_private_key_introduced then
    begin
      {$if declared(FC_EVP_PKEY_get_raw_private_key)}
      EVP_PKEY_get_raw_private_key := FC_EVP_PKEY_get_raw_private_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_get_raw_private_key_removed)}
    if EVP_PKEY_get_raw_private_key_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_get_raw_private_key)}
      EVP_PKEY_get_raw_private_key := _EVP_PKEY_get_raw_private_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_get_raw_private_key_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_get_raw_private_key');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_get_raw_public_key := LoadLibFunction(ADllHandle, EVP_PKEY_get_raw_public_key_procname);
  FuncLoadError := not assigned(EVP_PKEY_get_raw_public_key);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_get_raw_public_key_allownil)}
    EVP_PKEY_get_raw_public_key := ERR_EVP_PKEY_get_raw_public_key;
    {$ifend}
    {$if declared(EVP_PKEY_get_raw_public_key_introduced)}
    if LibVersion < EVP_PKEY_get_raw_public_key_introduced then
    begin
      {$if declared(FC_EVP_PKEY_get_raw_public_key)}
      EVP_PKEY_get_raw_public_key := FC_EVP_PKEY_get_raw_public_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_get_raw_public_key_removed)}
    if EVP_PKEY_get_raw_public_key_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_get_raw_public_key)}
      EVP_PKEY_get_raw_public_key := _EVP_PKEY_get_raw_public_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_get_raw_public_key_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_get_raw_public_key');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_new_CMAC_key := LoadLibFunction(ADllHandle, EVP_PKEY_new_CMAC_key_procname);
  FuncLoadError := not assigned(EVP_PKEY_new_CMAC_key);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_new_CMAC_key_allownil)}
    EVP_PKEY_new_CMAC_key := ERR_EVP_PKEY_new_CMAC_key;
    {$ifend}
    {$if declared(EVP_PKEY_new_CMAC_key_introduced)}
    if LibVersion < EVP_PKEY_new_CMAC_key_introduced then
    begin
      {$if declared(FC_EVP_PKEY_new_CMAC_key)}
      EVP_PKEY_new_CMAC_key := FC_EVP_PKEY_new_CMAC_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_new_CMAC_key_removed)}
    if EVP_PKEY_new_CMAC_key_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_new_CMAC_key)}
      EVP_PKEY_new_CMAC_key := _EVP_PKEY_new_CMAC_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_new_CMAC_key_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_new_CMAC_key');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_CTX_set_data := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_data_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_data);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_data_allownil)}
    EVP_PKEY_CTX_set_data := ERR_EVP_PKEY_CTX_set_data;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_data_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_data_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_data)}
      EVP_PKEY_CTX_set_data := FC_EVP_PKEY_CTX_set_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_data_removed)}
    if EVP_PKEY_CTX_set_data_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_data)}
      EVP_PKEY_CTX_set_data := _EVP_PKEY_CTX_set_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_data_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_data');
    {$ifend}
  end;


  EVP_PKEY_CTX_get_data := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_get_data_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_get_data);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_get_data_allownil)}
    EVP_PKEY_CTX_get_data := ERR_EVP_PKEY_CTX_get_data;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_data_introduced)}
    if LibVersion < EVP_PKEY_CTX_get_data_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_get_data)}
      EVP_PKEY_CTX_get_data := FC_EVP_PKEY_CTX_get_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_data_removed)}
    if EVP_PKEY_CTX_get_data_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_get_data)}
      EVP_PKEY_CTX_get_data := _EVP_PKEY_CTX_get_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_get_data_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_get_data');
    {$ifend}
  end;


  EVP_PKEY_CTX_get0_pkey := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_get0_pkey_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_get0_pkey);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_get0_pkey_allownil)}
    EVP_PKEY_CTX_get0_pkey := ERR_EVP_PKEY_CTX_get0_pkey;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get0_pkey_introduced)}
    if LibVersion < EVP_PKEY_CTX_get0_pkey_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_get0_pkey)}
      EVP_PKEY_CTX_get0_pkey := FC_EVP_PKEY_CTX_get0_pkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get0_pkey_removed)}
    if EVP_PKEY_CTX_get0_pkey_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_get0_pkey)}
      EVP_PKEY_CTX_get0_pkey := _EVP_PKEY_CTX_get0_pkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_get0_pkey_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_get0_pkey');
    {$ifend}
  end;


  EVP_PKEY_CTX_get0_peerkey := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_get0_peerkey_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_get0_peerkey);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_get0_peerkey_allownil)}
    EVP_PKEY_CTX_get0_peerkey := ERR_EVP_PKEY_CTX_get0_peerkey;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get0_peerkey_introduced)}
    if LibVersion < EVP_PKEY_CTX_get0_peerkey_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_get0_peerkey)}
      EVP_PKEY_CTX_get0_peerkey := FC_EVP_PKEY_CTX_get0_peerkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get0_peerkey_removed)}
    if EVP_PKEY_CTX_get0_peerkey_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_get0_peerkey)}
      EVP_PKEY_CTX_get0_peerkey := _EVP_PKEY_CTX_get0_peerkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_get0_peerkey_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_get0_peerkey');
    {$ifend}
  end;


  EVP_PKEY_CTX_set_app_data := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_app_data_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_app_data);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_app_data_allownil)}
    EVP_PKEY_CTX_set_app_data := ERR_EVP_PKEY_CTX_set_app_data;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_app_data_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_app_data_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_app_data)}
      EVP_PKEY_CTX_set_app_data := FC_EVP_PKEY_CTX_set_app_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_app_data_removed)}
    if EVP_PKEY_CTX_set_app_data_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_app_data)}
      EVP_PKEY_CTX_set_app_data := _EVP_PKEY_CTX_set_app_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_app_data_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_app_data');
    {$ifend}
  end;


  EVP_PKEY_CTX_get_app_data := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_get_app_data_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_get_app_data);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_get_app_data_allownil)}
    EVP_PKEY_CTX_get_app_data := ERR_EVP_PKEY_CTX_get_app_data;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_app_data_introduced)}
    if LibVersion < EVP_PKEY_CTX_get_app_data_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_get_app_data)}
      EVP_PKEY_CTX_get_app_data := FC_EVP_PKEY_CTX_get_app_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_app_data_removed)}
    if EVP_PKEY_CTX_get_app_data_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_get_app_data)}
      EVP_PKEY_CTX_get_app_data := _EVP_PKEY_CTX_get_app_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_get_app_data_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_get_app_data');
    {$ifend}
  end;


  EVP_PKEY_sign_init := LoadLibFunction(ADllHandle, EVP_PKEY_sign_init_procname);
  FuncLoadError := not assigned(EVP_PKEY_sign_init);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_sign_init_allownil)}
    EVP_PKEY_sign_init := ERR_EVP_PKEY_sign_init;
    {$ifend}
    {$if declared(EVP_PKEY_sign_init_introduced)}
    if LibVersion < EVP_PKEY_sign_init_introduced then
    begin
      {$if declared(FC_EVP_PKEY_sign_init)}
      EVP_PKEY_sign_init := FC_EVP_PKEY_sign_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_sign_init_removed)}
    if EVP_PKEY_sign_init_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_sign_init)}
      EVP_PKEY_sign_init := _EVP_PKEY_sign_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_sign_init_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_sign_init');
    {$ifend}
  end;


  EVP_PKEY_sign := LoadLibFunction(ADllHandle, EVP_PKEY_sign_procname);
  FuncLoadError := not assigned(EVP_PKEY_sign);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_sign_allownil)}
    EVP_PKEY_sign := ERR_EVP_PKEY_sign;
    {$ifend}
    {$if declared(EVP_PKEY_sign_introduced)}
    if LibVersion < EVP_PKEY_sign_introduced then
    begin
      {$if declared(FC_EVP_PKEY_sign)}
      EVP_PKEY_sign := FC_EVP_PKEY_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_sign_removed)}
    if EVP_PKEY_sign_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_sign)}
      EVP_PKEY_sign := _EVP_PKEY_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_sign');
    {$ifend}
  end;


  EVP_PKEY_verify_init := LoadLibFunction(ADllHandle, EVP_PKEY_verify_init_procname);
  FuncLoadError := not assigned(EVP_PKEY_verify_init);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_verify_init_allownil)}
    EVP_PKEY_verify_init := ERR_EVP_PKEY_verify_init;
    {$ifend}
    {$if declared(EVP_PKEY_verify_init_introduced)}
    if LibVersion < EVP_PKEY_verify_init_introduced then
    begin
      {$if declared(FC_EVP_PKEY_verify_init)}
      EVP_PKEY_verify_init := FC_EVP_PKEY_verify_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_verify_init_removed)}
    if EVP_PKEY_verify_init_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_verify_init)}
      EVP_PKEY_verify_init := _EVP_PKEY_verify_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_verify_init_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_verify_init');
    {$ifend}
  end;


  EVP_PKEY_verify := LoadLibFunction(ADllHandle, EVP_PKEY_verify_procname);
  FuncLoadError := not assigned(EVP_PKEY_verify);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_verify_allownil)}
    EVP_PKEY_verify := ERR_EVP_PKEY_verify;
    {$ifend}
    {$if declared(EVP_PKEY_verify_introduced)}
    if LibVersion < EVP_PKEY_verify_introduced then
    begin
      {$if declared(FC_EVP_PKEY_verify)}
      EVP_PKEY_verify := FC_EVP_PKEY_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_verify_removed)}
    if EVP_PKEY_verify_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_verify)}
      EVP_PKEY_verify := _EVP_PKEY_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_verify');
    {$ifend}
  end;


  EVP_PKEY_verify_recover_init := LoadLibFunction(ADllHandle, EVP_PKEY_verify_recover_init_procname);
  FuncLoadError := not assigned(EVP_PKEY_verify_recover_init);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_verify_recover_init_allownil)}
    EVP_PKEY_verify_recover_init := ERR_EVP_PKEY_verify_recover_init;
    {$ifend}
    {$if declared(EVP_PKEY_verify_recover_init_introduced)}
    if LibVersion < EVP_PKEY_verify_recover_init_introduced then
    begin
      {$if declared(FC_EVP_PKEY_verify_recover_init)}
      EVP_PKEY_verify_recover_init := FC_EVP_PKEY_verify_recover_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_verify_recover_init_removed)}
    if EVP_PKEY_verify_recover_init_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_verify_recover_init)}
      EVP_PKEY_verify_recover_init := _EVP_PKEY_verify_recover_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_verify_recover_init_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_verify_recover_init');
    {$ifend}
  end;


  EVP_PKEY_verify_recover := LoadLibFunction(ADllHandle, EVP_PKEY_verify_recover_procname);
  FuncLoadError := not assigned(EVP_PKEY_verify_recover);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_verify_recover_allownil)}
    EVP_PKEY_verify_recover := ERR_EVP_PKEY_verify_recover;
    {$ifend}
    {$if declared(EVP_PKEY_verify_recover_introduced)}
    if LibVersion < EVP_PKEY_verify_recover_introduced then
    begin
      {$if declared(FC_EVP_PKEY_verify_recover)}
      EVP_PKEY_verify_recover := FC_EVP_PKEY_verify_recover;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_verify_recover_removed)}
    if EVP_PKEY_verify_recover_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_verify_recover)}
      EVP_PKEY_verify_recover := _EVP_PKEY_verify_recover;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_verify_recover_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_verify_recover');
    {$ifend}
  end;


  EVP_PKEY_encrypt_init := LoadLibFunction(ADllHandle, EVP_PKEY_encrypt_init_procname);
  FuncLoadError := not assigned(EVP_PKEY_encrypt_init);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_encrypt_init_allownil)}
    EVP_PKEY_encrypt_init := ERR_EVP_PKEY_encrypt_init;
    {$ifend}
    {$if declared(EVP_PKEY_encrypt_init_introduced)}
    if LibVersion < EVP_PKEY_encrypt_init_introduced then
    begin
      {$if declared(FC_EVP_PKEY_encrypt_init)}
      EVP_PKEY_encrypt_init := FC_EVP_PKEY_encrypt_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_encrypt_init_removed)}
    if EVP_PKEY_encrypt_init_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_encrypt_init)}
      EVP_PKEY_encrypt_init := _EVP_PKEY_encrypt_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_encrypt_init_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_encrypt_init');
    {$ifend}
  end;


  EVP_PKEY_encrypt := LoadLibFunction(ADllHandle, EVP_PKEY_encrypt_procname);
  FuncLoadError := not assigned(EVP_PKEY_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_encrypt_allownil)}
    EVP_PKEY_encrypt := ERR_EVP_PKEY_encrypt;
    {$ifend}
    {$if declared(EVP_PKEY_encrypt_introduced)}
    if LibVersion < EVP_PKEY_encrypt_introduced then
    begin
      {$if declared(FC_EVP_PKEY_encrypt)}
      EVP_PKEY_encrypt := FC_EVP_PKEY_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_encrypt_removed)}
    if EVP_PKEY_encrypt_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_encrypt)}
      EVP_PKEY_encrypt := _EVP_PKEY_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_encrypt');
    {$ifend}
  end;


  EVP_PKEY_decrypt_init := LoadLibFunction(ADllHandle, EVP_PKEY_decrypt_init_procname);
  FuncLoadError := not assigned(EVP_PKEY_decrypt_init);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_decrypt_init_allownil)}
    EVP_PKEY_decrypt_init := ERR_EVP_PKEY_decrypt_init;
    {$ifend}
    {$if declared(EVP_PKEY_decrypt_init_introduced)}
    if LibVersion < EVP_PKEY_decrypt_init_introduced then
    begin
      {$if declared(FC_EVP_PKEY_decrypt_init)}
      EVP_PKEY_decrypt_init := FC_EVP_PKEY_decrypt_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_decrypt_init_removed)}
    if EVP_PKEY_decrypt_init_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_decrypt_init)}
      EVP_PKEY_decrypt_init := _EVP_PKEY_decrypt_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_decrypt_init_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_decrypt_init');
    {$ifend}
  end;


  EVP_PKEY_decrypt := LoadLibFunction(ADllHandle, EVP_PKEY_decrypt_procname);
  FuncLoadError := not assigned(EVP_PKEY_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_decrypt_allownil)}
    EVP_PKEY_decrypt := ERR_EVP_PKEY_decrypt;
    {$ifend}
    {$if declared(EVP_PKEY_decrypt_introduced)}
    if LibVersion < EVP_PKEY_decrypt_introduced then
    begin
      {$if declared(FC_EVP_PKEY_decrypt)}
      EVP_PKEY_decrypt := FC_EVP_PKEY_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_decrypt_removed)}
    if EVP_PKEY_decrypt_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_decrypt)}
      EVP_PKEY_decrypt := _EVP_PKEY_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_decrypt');
    {$ifend}
  end;


  EVP_PKEY_derive_init := LoadLibFunction(ADllHandle, EVP_PKEY_derive_init_procname);
  FuncLoadError := not assigned(EVP_PKEY_derive_init);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_derive_init_allownil)}
    EVP_PKEY_derive_init := ERR_EVP_PKEY_derive_init;
    {$ifend}
    {$if declared(EVP_PKEY_derive_init_introduced)}
    if LibVersion < EVP_PKEY_derive_init_introduced then
    begin
      {$if declared(FC_EVP_PKEY_derive_init)}
      EVP_PKEY_derive_init := FC_EVP_PKEY_derive_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_derive_init_removed)}
    if EVP_PKEY_derive_init_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_derive_init)}
      EVP_PKEY_derive_init := _EVP_PKEY_derive_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_derive_init_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_derive_init');
    {$ifend}
  end;


  EVP_PKEY_derive_set_peer := LoadLibFunction(ADllHandle, EVP_PKEY_derive_set_peer_procname);
  FuncLoadError := not assigned(EVP_PKEY_derive_set_peer);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_derive_set_peer_allownil)}
    EVP_PKEY_derive_set_peer := ERR_EVP_PKEY_derive_set_peer;
    {$ifend}
    {$if declared(EVP_PKEY_derive_set_peer_introduced)}
    if LibVersion < EVP_PKEY_derive_set_peer_introduced then
    begin
      {$if declared(FC_EVP_PKEY_derive_set_peer)}
      EVP_PKEY_derive_set_peer := FC_EVP_PKEY_derive_set_peer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_derive_set_peer_removed)}
    if EVP_PKEY_derive_set_peer_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_derive_set_peer)}
      EVP_PKEY_derive_set_peer := _EVP_PKEY_derive_set_peer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_derive_set_peer_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_derive_set_peer');
    {$ifend}
  end;


  EVP_PKEY_derive := LoadLibFunction(ADllHandle, EVP_PKEY_derive_procname);
  FuncLoadError := not assigned(EVP_PKEY_derive);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_derive_allownil)}
    EVP_PKEY_derive := ERR_EVP_PKEY_derive;
    {$ifend}
    {$if declared(EVP_PKEY_derive_introduced)}
    if LibVersion < EVP_PKEY_derive_introduced then
    begin
      {$if declared(FC_EVP_PKEY_derive)}
      EVP_PKEY_derive := FC_EVP_PKEY_derive;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_derive_removed)}
    if EVP_PKEY_derive_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_derive)}
      EVP_PKEY_derive := _EVP_PKEY_derive;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_derive_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_derive');
    {$ifend}
  end;


  EVP_PKEY_paramgen_init := LoadLibFunction(ADllHandle, EVP_PKEY_paramgen_init_procname);
  FuncLoadError := not assigned(EVP_PKEY_paramgen_init);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_paramgen_init_allownil)}
    EVP_PKEY_paramgen_init := ERR_EVP_PKEY_paramgen_init;
    {$ifend}
    {$if declared(EVP_PKEY_paramgen_init_introduced)}
    if LibVersion < EVP_PKEY_paramgen_init_introduced then
    begin
      {$if declared(FC_EVP_PKEY_paramgen_init)}
      EVP_PKEY_paramgen_init := FC_EVP_PKEY_paramgen_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_paramgen_init_removed)}
    if EVP_PKEY_paramgen_init_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_paramgen_init)}
      EVP_PKEY_paramgen_init := _EVP_PKEY_paramgen_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_paramgen_init_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_paramgen_init');
    {$ifend}
  end;


  EVP_PKEY_paramgen := LoadLibFunction(ADllHandle, EVP_PKEY_paramgen_procname);
  FuncLoadError := not assigned(EVP_PKEY_paramgen);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_paramgen_allownil)}
    EVP_PKEY_paramgen := ERR_EVP_PKEY_paramgen;
    {$ifend}
    {$if declared(EVP_PKEY_paramgen_introduced)}
    if LibVersion < EVP_PKEY_paramgen_introduced then
    begin
      {$if declared(FC_EVP_PKEY_paramgen)}
      EVP_PKEY_paramgen := FC_EVP_PKEY_paramgen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_paramgen_removed)}
    if EVP_PKEY_paramgen_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_paramgen)}
      EVP_PKEY_paramgen := _EVP_PKEY_paramgen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_paramgen_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_paramgen');
    {$ifend}
  end;


  EVP_PKEY_keygen_init := LoadLibFunction(ADllHandle, EVP_PKEY_keygen_init_procname);
  FuncLoadError := not assigned(EVP_PKEY_keygen_init);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_keygen_init_allownil)}
    EVP_PKEY_keygen_init := ERR_EVP_PKEY_keygen_init;
    {$ifend}
    {$if declared(EVP_PKEY_keygen_init_introduced)}
    if LibVersion < EVP_PKEY_keygen_init_introduced then
    begin
      {$if declared(FC_EVP_PKEY_keygen_init)}
      EVP_PKEY_keygen_init := FC_EVP_PKEY_keygen_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_keygen_init_removed)}
    if EVP_PKEY_keygen_init_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_keygen_init)}
      EVP_PKEY_keygen_init := _EVP_PKEY_keygen_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_keygen_init_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_keygen_init');
    {$ifend}
  end;


  EVP_PKEY_keygen := LoadLibFunction(ADllHandle, EVP_PKEY_keygen_procname);
  FuncLoadError := not assigned(EVP_PKEY_keygen);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_keygen_allownil)}
    EVP_PKEY_keygen := ERR_EVP_PKEY_keygen;
    {$ifend}
    {$if declared(EVP_PKEY_keygen_introduced)}
    if LibVersion < EVP_PKEY_keygen_introduced then
    begin
      {$if declared(FC_EVP_PKEY_keygen)}
      EVP_PKEY_keygen := FC_EVP_PKEY_keygen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_keygen_removed)}
    if EVP_PKEY_keygen_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_keygen)}
      EVP_PKEY_keygen := _EVP_PKEY_keygen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_keygen_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_keygen');
    {$ifend}
  end;


  EVP_PKEY_check := LoadLibFunction(ADllHandle, EVP_PKEY_check_procname);
  FuncLoadError := not assigned(EVP_PKEY_check);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_check_allownil)}
    EVP_PKEY_check := ERR_EVP_PKEY_check;
    {$ifend}
    {$if declared(EVP_PKEY_check_introduced)}
    if LibVersion < EVP_PKEY_check_introduced then
    begin
      {$if declared(FC_EVP_PKEY_check)}
      EVP_PKEY_check := FC_EVP_PKEY_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_check_removed)}
    if EVP_PKEY_check_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_check)}
      EVP_PKEY_check := _EVP_PKEY_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_check_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_check');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_public_check := LoadLibFunction(ADllHandle, EVP_PKEY_public_check_procname);
  FuncLoadError := not assigned(EVP_PKEY_public_check);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_public_check_allownil)}
    EVP_PKEY_public_check := ERR_EVP_PKEY_public_check;
    {$ifend}
    {$if declared(EVP_PKEY_public_check_introduced)}
    if LibVersion < EVP_PKEY_public_check_introduced then
    begin
      {$if declared(FC_EVP_PKEY_public_check)}
      EVP_PKEY_public_check := FC_EVP_PKEY_public_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_public_check_removed)}
    if EVP_PKEY_public_check_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_public_check)}
      EVP_PKEY_public_check := _EVP_PKEY_public_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_public_check_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_public_check');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_param_check := LoadLibFunction(ADllHandle, EVP_PKEY_param_check_procname);
  FuncLoadError := not assigned(EVP_PKEY_param_check);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_param_check_allownil)}
    EVP_PKEY_param_check := ERR_EVP_PKEY_param_check;
    {$ifend}
    {$if declared(EVP_PKEY_param_check_introduced)}
    if LibVersion < EVP_PKEY_param_check_introduced then
    begin
      {$if declared(FC_EVP_PKEY_param_check)}
      EVP_PKEY_param_check := FC_EVP_PKEY_param_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_param_check_removed)}
    if EVP_PKEY_param_check_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_param_check)}
      EVP_PKEY_param_check := _EVP_PKEY_param_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_param_check_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_param_check');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_CTX_set_cb := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_cb_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_cb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_cb_allownil)}
    EVP_PKEY_CTX_set_cb := ERR_EVP_PKEY_CTX_set_cb;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_cb_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_cb_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_cb)}
      EVP_PKEY_CTX_set_cb := FC_EVP_PKEY_CTX_set_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_cb_removed)}
    if EVP_PKEY_CTX_set_cb_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_cb)}
      EVP_PKEY_CTX_set_cb := _EVP_PKEY_CTX_set_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_cb');
    {$ifend}
  end;


  EVP_PKEY_CTX_get_cb := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_get_cb_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_get_cb);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_get_cb_allownil)}
    EVP_PKEY_CTX_get_cb := ERR_EVP_PKEY_CTX_get_cb;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_cb_introduced)}
    if LibVersion < EVP_PKEY_CTX_get_cb_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_get_cb)}
      EVP_PKEY_CTX_get_cb := FC_EVP_PKEY_CTX_get_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_cb_removed)}
    if EVP_PKEY_CTX_get_cb_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_get_cb)}
      EVP_PKEY_CTX_get_cb := _EVP_PKEY_CTX_get_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_get_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_get_cb');
    {$ifend}
  end;


  EVP_PKEY_CTX_get_keygen_info := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_get_keygen_info_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_get_keygen_info);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_get_keygen_info_allownil)}
    EVP_PKEY_CTX_get_keygen_info := ERR_EVP_PKEY_CTX_get_keygen_info;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_keygen_info_introduced)}
    if LibVersion < EVP_PKEY_CTX_get_keygen_info_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_get_keygen_info)}
      EVP_PKEY_CTX_get_keygen_info := FC_EVP_PKEY_CTX_get_keygen_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_keygen_info_removed)}
    if EVP_PKEY_CTX_get_keygen_info_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_get_keygen_info)}
      EVP_PKEY_CTX_get_keygen_info := _EVP_PKEY_CTX_get_keygen_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_get_keygen_info_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_get_keygen_info');
    {$ifend}
  end;


  EVP_PKEY_meth_set_init := LoadLibFunction(ADllHandle, EVP_PKEY_meth_set_init_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_set_init);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_set_init_allownil)}
    EVP_PKEY_meth_set_init := ERR_EVP_PKEY_meth_set_init;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_init_introduced)}
    if LibVersion < EVP_PKEY_meth_set_init_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_set_init)}
      EVP_PKEY_meth_set_init := FC_EVP_PKEY_meth_set_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_init_removed)}
    if EVP_PKEY_meth_set_init_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_set_init)}
      EVP_PKEY_meth_set_init := _EVP_PKEY_meth_set_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_set_init_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_set_init');
    {$ifend}
  end;


  EVP_PKEY_meth_set_copy := LoadLibFunction(ADllHandle, EVP_PKEY_meth_set_copy_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_set_copy);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_set_copy_allownil)}
    EVP_PKEY_meth_set_copy := ERR_EVP_PKEY_meth_set_copy;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_copy_introduced)}
    if LibVersion < EVP_PKEY_meth_set_copy_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_set_copy)}
      EVP_PKEY_meth_set_copy := FC_EVP_PKEY_meth_set_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_copy_removed)}
    if EVP_PKEY_meth_set_copy_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_set_copy)}
      EVP_PKEY_meth_set_copy := _EVP_PKEY_meth_set_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_set_copy_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_set_copy');
    {$ifend}
  end;


  EVP_PKEY_meth_set_cleanup := LoadLibFunction(ADllHandle, EVP_PKEY_meth_set_cleanup_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_set_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_set_cleanup_allownil)}
    EVP_PKEY_meth_set_cleanup := ERR_EVP_PKEY_meth_set_cleanup;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_cleanup_introduced)}
    if LibVersion < EVP_PKEY_meth_set_cleanup_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_set_cleanup)}
      EVP_PKEY_meth_set_cleanup := FC_EVP_PKEY_meth_set_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_cleanup_removed)}
    if EVP_PKEY_meth_set_cleanup_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_set_cleanup)}
      EVP_PKEY_meth_set_cleanup := _EVP_PKEY_meth_set_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_set_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_set_cleanup');
    {$ifend}
  end;


  EVP_PKEY_meth_set_paramgen := LoadLibFunction(ADllHandle, EVP_PKEY_meth_set_paramgen_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_set_paramgen);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_set_paramgen_allownil)}
    EVP_PKEY_meth_set_paramgen := ERR_EVP_PKEY_meth_set_paramgen;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_paramgen_introduced)}
    if LibVersion < EVP_PKEY_meth_set_paramgen_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_set_paramgen)}
      EVP_PKEY_meth_set_paramgen := FC_EVP_PKEY_meth_set_paramgen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_paramgen_removed)}
    if EVP_PKEY_meth_set_paramgen_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_set_paramgen)}
      EVP_PKEY_meth_set_paramgen := _EVP_PKEY_meth_set_paramgen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_set_paramgen_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_set_paramgen');
    {$ifend}
  end;


  EVP_PKEY_meth_set_keygen := LoadLibFunction(ADllHandle, EVP_PKEY_meth_set_keygen_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_set_keygen);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_set_keygen_allownil)}
    EVP_PKEY_meth_set_keygen := ERR_EVP_PKEY_meth_set_keygen;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_keygen_introduced)}
    if LibVersion < EVP_PKEY_meth_set_keygen_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_set_keygen)}
      EVP_PKEY_meth_set_keygen := FC_EVP_PKEY_meth_set_keygen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_keygen_removed)}
    if EVP_PKEY_meth_set_keygen_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_set_keygen)}
      EVP_PKEY_meth_set_keygen := _EVP_PKEY_meth_set_keygen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_set_keygen_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_set_keygen');
    {$ifend}
  end;


  EVP_PKEY_meth_set_sign := LoadLibFunction(ADllHandle, EVP_PKEY_meth_set_sign_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_set_sign);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_set_sign_allownil)}
    EVP_PKEY_meth_set_sign := ERR_EVP_PKEY_meth_set_sign;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_sign_introduced)}
    if LibVersion < EVP_PKEY_meth_set_sign_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_set_sign)}
      EVP_PKEY_meth_set_sign := FC_EVP_PKEY_meth_set_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_sign_removed)}
    if EVP_PKEY_meth_set_sign_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_set_sign)}
      EVP_PKEY_meth_set_sign := _EVP_PKEY_meth_set_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_set_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_set_sign');
    {$ifend}
  end;


  EVP_PKEY_meth_set_verify := LoadLibFunction(ADllHandle, EVP_PKEY_meth_set_verify_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_set_verify);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_set_verify_allownil)}
    EVP_PKEY_meth_set_verify := ERR_EVP_PKEY_meth_set_verify;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_verify_introduced)}
    if LibVersion < EVP_PKEY_meth_set_verify_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_set_verify)}
      EVP_PKEY_meth_set_verify := FC_EVP_PKEY_meth_set_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_verify_removed)}
    if EVP_PKEY_meth_set_verify_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_set_verify)}
      EVP_PKEY_meth_set_verify := _EVP_PKEY_meth_set_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_set_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_set_verify');
    {$ifend}
  end;


  EVP_PKEY_meth_set_verify_recover := LoadLibFunction(ADllHandle, EVP_PKEY_meth_set_verify_recover_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_set_verify_recover);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_set_verify_recover_allownil)}
    EVP_PKEY_meth_set_verify_recover := ERR_EVP_PKEY_meth_set_verify_recover;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_verify_recover_introduced)}
    if LibVersion < EVP_PKEY_meth_set_verify_recover_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_set_verify_recover)}
      EVP_PKEY_meth_set_verify_recover := FC_EVP_PKEY_meth_set_verify_recover;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_verify_recover_removed)}
    if EVP_PKEY_meth_set_verify_recover_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_set_verify_recover)}
      EVP_PKEY_meth_set_verify_recover := _EVP_PKEY_meth_set_verify_recover;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_set_verify_recover_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_set_verify_recover');
    {$ifend}
  end;


  EVP_PKEY_meth_set_signctx := LoadLibFunction(ADllHandle, EVP_PKEY_meth_set_signctx_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_set_signctx);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_set_signctx_allownil)}
    EVP_PKEY_meth_set_signctx := ERR_EVP_PKEY_meth_set_signctx;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_signctx_introduced)}
    if LibVersion < EVP_PKEY_meth_set_signctx_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_set_signctx)}
      EVP_PKEY_meth_set_signctx := FC_EVP_PKEY_meth_set_signctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_signctx_removed)}
    if EVP_PKEY_meth_set_signctx_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_set_signctx)}
      EVP_PKEY_meth_set_signctx := _EVP_PKEY_meth_set_signctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_set_signctx_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_set_signctx');
    {$ifend}
  end;


  EVP_PKEY_meth_set_verifyctx := LoadLibFunction(ADllHandle, EVP_PKEY_meth_set_verifyctx_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_set_verifyctx);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_set_verifyctx_allownil)}
    EVP_PKEY_meth_set_verifyctx := ERR_EVP_PKEY_meth_set_verifyctx;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_verifyctx_introduced)}
    if LibVersion < EVP_PKEY_meth_set_verifyctx_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_set_verifyctx)}
      EVP_PKEY_meth_set_verifyctx := FC_EVP_PKEY_meth_set_verifyctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_verifyctx_removed)}
    if EVP_PKEY_meth_set_verifyctx_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_set_verifyctx)}
      EVP_PKEY_meth_set_verifyctx := _EVP_PKEY_meth_set_verifyctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_set_verifyctx_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_set_verifyctx');
    {$ifend}
  end;


  EVP_PKEY_meth_set_encrypt := LoadLibFunction(ADllHandle, EVP_PKEY_meth_set_encrypt_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_set_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_set_encrypt_allownil)}
    EVP_PKEY_meth_set_encrypt := ERR_EVP_PKEY_meth_set_encrypt;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_encrypt_introduced)}
    if LibVersion < EVP_PKEY_meth_set_encrypt_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_set_encrypt)}
      EVP_PKEY_meth_set_encrypt := FC_EVP_PKEY_meth_set_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_encrypt_removed)}
    if EVP_PKEY_meth_set_encrypt_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_set_encrypt)}
      EVP_PKEY_meth_set_encrypt := _EVP_PKEY_meth_set_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_set_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_set_encrypt');
    {$ifend}
  end;


  EVP_PKEY_meth_set_decrypt := LoadLibFunction(ADllHandle, EVP_PKEY_meth_set_decrypt_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_set_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_set_decrypt_allownil)}
    EVP_PKEY_meth_set_decrypt := ERR_EVP_PKEY_meth_set_decrypt;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_decrypt_introduced)}
    if LibVersion < EVP_PKEY_meth_set_decrypt_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_set_decrypt)}
      EVP_PKEY_meth_set_decrypt := FC_EVP_PKEY_meth_set_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_decrypt_removed)}
    if EVP_PKEY_meth_set_decrypt_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_set_decrypt)}
      EVP_PKEY_meth_set_decrypt := _EVP_PKEY_meth_set_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_set_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_set_decrypt');
    {$ifend}
  end;


  EVP_PKEY_meth_set_derive := LoadLibFunction(ADllHandle, EVP_PKEY_meth_set_derive_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_set_derive);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_set_derive_allownil)}
    EVP_PKEY_meth_set_derive := ERR_EVP_PKEY_meth_set_derive;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_derive_introduced)}
    if LibVersion < EVP_PKEY_meth_set_derive_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_set_derive)}
      EVP_PKEY_meth_set_derive := FC_EVP_PKEY_meth_set_derive;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_derive_removed)}
    if EVP_PKEY_meth_set_derive_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_set_derive)}
      EVP_PKEY_meth_set_derive := _EVP_PKEY_meth_set_derive;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_set_derive_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_set_derive');
    {$ifend}
  end;


  EVP_PKEY_meth_set_ctrl := LoadLibFunction(ADllHandle, EVP_PKEY_meth_set_ctrl_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_set_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_set_ctrl_allownil)}
    EVP_PKEY_meth_set_ctrl := ERR_EVP_PKEY_meth_set_ctrl;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_ctrl_introduced)}
    if LibVersion < EVP_PKEY_meth_set_ctrl_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_set_ctrl)}
      EVP_PKEY_meth_set_ctrl := FC_EVP_PKEY_meth_set_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_ctrl_removed)}
    if EVP_PKEY_meth_set_ctrl_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_set_ctrl)}
      EVP_PKEY_meth_set_ctrl := _EVP_PKEY_meth_set_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_set_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_set_ctrl');
    {$ifend}
  end;


  EVP_PKEY_meth_set_digestsign := LoadLibFunction(ADllHandle, EVP_PKEY_meth_set_digestsign_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_set_digestsign);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_set_digestsign_allownil)}
    EVP_PKEY_meth_set_digestsign := ERR_EVP_PKEY_meth_set_digestsign;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_digestsign_introduced)}
    if LibVersion < EVP_PKEY_meth_set_digestsign_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_set_digestsign)}
      EVP_PKEY_meth_set_digestsign := FC_EVP_PKEY_meth_set_digestsign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_digestsign_removed)}
    if EVP_PKEY_meth_set_digestsign_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_set_digestsign)}
      EVP_PKEY_meth_set_digestsign := _EVP_PKEY_meth_set_digestsign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_set_digestsign_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_set_digestsign');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_meth_set_digestverify := LoadLibFunction(ADllHandle, EVP_PKEY_meth_set_digestverify_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_set_digestverify);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_set_digestverify_allownil)}
    EVP_PKEY_meth_set_digestverify := ERR_EVP_PKEY_meth_set_digestverify;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_digestverify_introduced)}
    if LibVersion < EVP_PKEY_meth_set_digestverify_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_set_digestverify)}
      EVP_PKEY_meth_set_digestverify := FC_EVP_PKEY_meth_set_digestverify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_digestverify_removed)}
    if EVP_PKEY_meth_set_digestverify_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_set_digestverify)}
      EVP_PKEY_meth_set_digestverify := _EVP_PKEY_meth_set_digestverify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_set_digestverify_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_set_digestverify');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_meth_set_check := LoadLibFunction(ADllHandle, EVP_PKEY_meth_set_check_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_set_check);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_set_check_allownil)}
    EVP_PKEY_meth_set_check := ERR_EVP_PKEY_meth_set_check;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_check_introduced)}
    if LibVersion < EVP_PKEY_meth_set_check_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_set_check)}
      EVP_PKEY_meth_set_check := FC_EVP_PKEY_meth_set_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_check_removed)}
    if EVP_PKEY_meth_set_check_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_set_check)}
      EVP_PKEY_meth_set_check := _EVP_PKEY_meth_set_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_set_check_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_set_check');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_meth_set_public_check := LoadLibFunction(ADllHandle, EVP_PKEY_meth_set_public_check_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_set_public_check);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_set_public_check_allownil)}
    EVP_PKEY_meth_set_public_check := ERR_EVP_PKEY_meth_set_public_check;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_public_check_introduced)}
    if LibVersion < EVP_PKEY_meth_set_public_check_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_set_public_check)}
      EVP_PKEY_meth_set_public_check := FC_EVP_PKEY_meth_set_public_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_public_check_removed)}
    if EVP_PKEY_meth_set_public_check_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_set_public_check)}
      EVP_PKEY_meth_set_public_check := _EVP_PKEY_meth_set_public_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_set_public_check_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_set_public_check');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_meth_set_param_check := LoadLibFunction(ADllHandle, EVP_PKEY_meth_set_param_check_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_set_param_check);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_set_param_check_allownil)}
    EVP_PKEY_meth_set_param_check := ERR_EVP_PKEY_meth_set_param_check;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_param_check_introduced)}
    if LibVersion < EVP_PKEY_meth_set_param_check_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_set_param_check)}
      EVP_PKEY_meth_set_param_check := FC_EVP_PKEY_meth_set_param_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_param_check_removed)}
    if EVP_PKEY_meth_set_param_check_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_set_param_check)}
      EVP_PKEY_meth_set_param_check := _EVP_PKEY_meth_set_param_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_set_param_check_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_set_param_check');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_meth_set_digest_custom := LoadLibFunction(ADllHandle, EVP_PKEY_meth_set_digest_custom_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_set_digest_custom);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_set_digest_custom_allownil)}
    EVP_PKEY_meth_set_digest_custom := ERR_EVP_PKEY_meth_set_digest_custom;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_digest_custom_introduced)}
    if LibVersion < EVP_PKEY_meth_set_digest_custom_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_set_digest_custom)}
      EVP_PKEY_meth_set_digest_custom := FC_EVP_PKEY_meth_set_digest_custom;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_set_digest_custom_removed)}
    if EVP_PKEY_meth_set_digest_custom_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_set_digest_custom)}
      EVP_PKEY_meth_set_digest_custom := _EVP_PKEY_meth_set_digest_custom;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_set_digest_custom_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_set_digest_custom');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_meth_get_init := LoadLibFunction(ADllHandle, EVP_PKEY_meth_get_init_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_get_init);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_get_init_allownil)}
    EVP_PKEY_meth_get_init := ERR_EVP_PKEY_meth_get_init;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_init_introduced)}
    if LibVersion < EVP_PKEY_meth_get_init_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_get_init)}
      EVP_PKEY_meth_get_init := FC_EVP_PKEY_meth_get_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_init_removed)}
    if EVP_PKEY_meth_get_init_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_get_init)}
      EVP_PKEY_meth_get_init := _EVP_PKEY_meth_get_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_get_init_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_get_init');
    {$ifend}
  end;


  EVP_PKEY_meth_get_copy := LoadLibFunction(ADllHandle, EVP_PKEY_meth_get_copy_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_get_copy);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_get_copy_allownil)}
    EVP_PKEY_meth_get_copy := ERR_EVP_PKEY_meth_get_copy;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_copy_introduced)}
    if LibVersion < EVP_PKEY_meth_get_copy_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_get_copy)}
      EVP_PKEY_meth_get_copy := FC_EVP_PKEY_meth_get_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_copy_removed)}
    if EVP_PKEY_meth_get_copy_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_get_copy)}
      EVP_PKEY_meth_get_copy := _EVP_PKEY_meth_get_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_get_copy_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_get_copy');
    {$ifend}
  end;


  EVP_PKEY_meth_get_cleanup := LoadLibFunction(ADllHandle, EVP_PKEY_meth_get_cleanup_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_get_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_get_cleanup_allownil)}
    EVP_PKEY_meth_get_cleanup := ERR_EVP_PKEY_meth_get_cleanup;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_cleanup_introduced)}
    if LibVersion < EVP_PKEY_meth_get_cleanup_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_get_cleanup)}
      EVP_PKEY_meth_get_cleanup := FC_EVP_PKEY_meth_get_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_cleanup_removed)}
    if EVP_PKEY_meth_get_cleanup_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_get_cleanup)}
      EVP_PKEY_meth_get_cleanup := _EVP_PKEY_meth_get_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_get_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_get_cleanup');
    {$ifend}
  end;


  EVP_PKEY_meth_get_paramgen := LoadLibFunction(ADllHandle, EVP_PKEY_meth_get_paramgen_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_get_paramgen);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_get_paramgen_allownil)}
    EVP_PKEY_meth_get_paramgen := ERR_EVP_PKEY_meth_get_paramgen;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_paramgen_introduced)}
    if LibVersion < EVP_PKEY_meth_get_paramgen_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_get_paramgen)}
      EVP_PKEY_meth_get_paramgen := FC_EVP_PKEY_meth_get_paramgen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_paramgen_removed)}
    if EVP_PKEY_meth_get_paramgen_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_get_paramgen)}
      EVP_PKEY_meth_get_paramgen := _EVP_PKEY_meth_get_paramgen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_get_paramgen_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_get_paramgen');
    {$ifend}
  end;


  EVP_PKEY_meth_get_keygen := LoadLibFunction(ADllHandle, EVP_PKEY_meth_get_keygen_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_get_keygen);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_get_keygen_allownil)}
    EVP_PKEY_meth_get_keygen := ERR_EVP_PKEY_meth_get_keygen;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_keygen_introduced)}
    if LibVersion < EVP_PKEY_meth_get_keygen_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_get_keygen)}
      EVP_PKEY_meth_get_keygen := FC_EVP_PKEY_meth_get_keygen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_keygen_removed)}
    if EVP_PKEY_meth_get_keygen_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_get_keygen)}
      EVP_PKEY_meth_get_keygen := _EVP_PKEY_meth_get_keygen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_get_keygen_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_get_keygen');
    {$ifend}
  end;


  EVP_PKEY_meth_get_sign := LoadLibFunction(ADllHandle, EVP_PKEY_meth_get_sign_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_get_sign);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_get_sign_allownil)}
    EVP_PKEY_meth_get_sign := ERR_EVP_PKEY_meth_get_sign;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_sign_introduced)}
    if LibVersion < EVP_PKEY_meth_get_sign_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_get_sign)}
      EVP_PKEY_meth_get_sign := FC_EVP_PKEY_meth_get_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_sign_removed)}
    if EVP_PKEY_meth_get_sign_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_get_sign)}
      EVP_PKEY_meth_get_sign := _EVP_PKEY_meth_get_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_get_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_get_sign');
    {$ifend}
  end;


  EVP_PKEY_meth_get_verify := LoadLibFunction(ADllHandle, EVP_PKEY_meth_get_verify_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_get_verify);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_get_verify_allownil)}
    EVP_PKEY_meth_get_verify := ERR_EVP_PKEY_meth_get_verify;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_verify_introduced)}
    if LibVersion < EVP_PKEY_meth_get_verify_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_get_verify)}
      EVP_PKEY_meth_get_verify := FC_EVP_PKEY_meth_get_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_verify_removed)}
    if EVP_PKEY_meth_get_verify_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_get_verify)}
      EVP_PKEY_meth_get_verify := _EVP_PKEY_meth_get_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_get_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_get_verify');
    {$ifend}
  end;


  EVP_PKEY_meth_get_verify_recover := LoadLibFunction(ADllHandle, EVP_PKEY_meth_get_verify_recover_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_get_verify_recover);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_get_verify_recover_allownil)}
    EVP_PKEY_meth_get_verify_recover := ERR_EVP_PKEY_meth_get_verify_recover;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_verify_recover_introduced)}
    if LibVersion < EVP_PKEY_meth_get_verify_recover_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_get_verify_recover)}
      EVP_PKEY_meth_get_verify_recover := FC_EVP_PKEY_meth_get_verify_recover;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_verify_recover_removed)}
    if EVP_PKEY_meth_get_verify_recover_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_get_verify_recover)}
      EVP_PKEY_meth_get_verify_recover := _EVP_PKEY_meth_get_verify_recover;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_get_verify_recover_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_get_verify_recover');
    {$ifend}
  end;


  EVP_PKEY_meth_get_signctx := LoadLibFunction(ADllHandle, EVP_PKEY_meth_get_signctx_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_get_signctx);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_get_signctx_allownil)}
    EVP_PKEY_meth_get_signctx := ERR_EVP_PKEY_meth_get_signctx;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_signctx_introduced)}
    if LibVersion < EVP_PKEY_meth_get_signctx_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_get_signctx)}
      EVP_PKEY_meth_get_signctx := FC_EVP_PKEY_meth_get_signctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_signctx_removed)}
    if EVP_PKEY_meth_get_signctx_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_get_signctx)}
      EVP_PKEY_meth_get_signctx := _EVP_PKEY_meth_get_signctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_get_signctx_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_get_signctx');
    {$ifend}
  end;


  EVP_PKEY_meth_get_verifyctx := LoadLibFunction(ADllHandle, EVP_PKEY_meth_get_verifyctx_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_get_verifyctx);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_get_verifyctx_allownil)}
    EVP_PKEY_meth_get_verifyctx := ERR_EVP_PKEY_meth_get_verifyctx;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_verifyctx_introduced)}
    if LibVersion < EVP_PKEY_meth_get_verifyctx_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_get_verifyctx)}
      EVP_PKEY_meth_get_verifyctx := FC_EVP_PKEY_meth_get_verifyctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_verifyctx_removed)}
    if EVP_PKEY_meth_get_verifyctx_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_get_verifyctx)}
      EVP_PKEY_meth_get_verifyctx := _EVP_PKEY_meth_get_verifyctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_get_verifyctx_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_get_verifyctx');
    {$ifend}
  end;


  EVP_PKEY_meth_get_encrypt := LoadLibFunction(ADllHandle, EVP_PKEY_meth_get_encrypt_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_get_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_get_encrypt_allownil)}
    EVP_PKEY_meth_get_encrypt := ERR_EVP_PKEY_meth_get_encrypt;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_encrypt_introduced)}
    if LibVersion < EVP_PKEY_meth_get_encrypt_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_get_encrypt)}
      EVP_PKEY_meth_get_encrypt := FC_EVP_PKEY_meth_get_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_encrypt_removed)}
    if EVP_PKEY_meth_get_encrypt_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_get_encrypt)}
      EVP_PKEY_meth_get_encrypt := _EVP_PKEY_meth_get_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_get_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_get_encrypt');
    {$ifend}
  end;


  EVP_PKEY_meth_get_decrypt := LoadLibFunction(ADllHandle, EVP_PKEY_meth_get_decrypt_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_get_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_get_decrypt_allownil)}
    EVP_PKEY_meth_get_decrypt := ERR_EVP_PKEY_meth_get_decrypt;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_decrypt_introduced)}
    if LibVersion < EVP_PKEY_meth_get_decrypt_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_get_decrypt)}
      EVP_PKEY_meth_get_decrypt := FC_EVP_PKEY_meth_get_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_decrypt_removed)}
    if EVP_PKEY_meth_get_decrypt_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_get_decrypt)}
      EVP_PKEY_meth_get_decrypt := _EVP_PKEY_meth_get_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_get_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_get_decrypt');
    {$ifend}
  end;


  EVP_PKEY_meth_get_derive := LoadLibFunction(ADllHandle, EVP_PKEY_meth_get_derive_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_get_derive);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_get_derive_allownil)}
    EVP_PKEY_meth_get_derive := ERR_EVP_PKEY_meth_get_derive;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_derive_introduced)}
    if LibVersion < EVP_PKEY_meth_get_derive_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_get_derive)}
      EVP_PKEY_meth_get_derive := FC_EVP_PKEY_meth_get_derive;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_derive_removed)}
    if EVP_PKEY_meth_get_derive_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_get_derive)}
      EVP_PKEY_meth_get_derive := _EVP_PKEY_meth_get_derive;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_get_derive_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_get_derive');
    {$ifend}
  end;


  EVP_PKEY_meth_get_ctrl := LoadLibFunction(ADllHandle, EVP_PKEY_meth_get_ctrl_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_get_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_get_ctrl_allownil)}
    EVP_PKEY_meth_get_ctrl := ERR_EVP_PKEY_meth_get_ctrl;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_ctrl_introduced)}
    if LibVersion < EVP_PKEY_meth_get_ctrl_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_get_ctrl)}
      EVP_PKEY_meth_get_ctrl := FC_EVP_PKEY_meth_get_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_ctrl_removed)}
    if EVP_PKEY_meth_get_ctrl_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_get_ctrl)}
      EVP_PKEY_meth_get_ctrl := _EVP_PKEY_meth_get_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_get_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_get_ctrl');
    {$ifend}
  end;


  EVP_PKEY_meth_get_digestsign := LoadLibFunction(ADllHandle, EVP_PKEY_meth_get_digestsign_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_get_digestsign);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_get_digestsign_allownil)}
    EVP_PKEY_meth_get_digestsign := ERR_EVP_PKEY_meth_get_digestsign;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_digestsign_introduced)}
    if LibVersion < EVP_PKEY_meth_get_digestsign_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_get_digestsign)}
      EVP_PKEY_meth_get_digestsign := FC_EVP_PKEY_meth_get_digestsign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_digestsign_removed)}
    if EVP_PKEY_meth_get_digestsign_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_get_digestsign)}
      EVP_PKEY_meth_get_digestsign := _EVP_PKEY_meth_get_digestsign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_get_digestsign_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_get_digestsign');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_meth_get_digestverify := LoadLibFunction(ADllHandle, EVP_PKEY_meth_get_digestverify_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_get_digestverify);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_get_digestverify_allownil)}
    EVP_PKEY_meth_get_digestverify := ERR_EVP_PKEY_meth_get_digestverify;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_digestverify_introduced)}
    if LibVersion < EVP_PKEY_meth_get_digestverify_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_get_digestverify)}
      EVP_PKEY_meth_get_digestverify := FC_EVP_PKEY_meth_get_digestverify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_digestverify_removed)}
    if EVP_PKEY_meth_get_digestverify_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_get_digestverify)}
      EVP_PKEY_meth_get_digestverify := _EVP_PKEY_meth_get_digestverify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_get_digestverify_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_get_digestverify');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_meth_get_check := LoadLibFunction(ADllHandle, EVP_PKEY_meth_get_check_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_get_check);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_get_check_allownil)}
    EVP_PKEY_meth_get_check := ERR_EVP_PKEY_meth_get_check;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_check_introduced)}
    if LibVersion < EVP_PKEY_meth_get_check_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_get_check)}
      EVP_PKEY_meth_get_check := FC_EVP_PKEY_meth_get_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_check_removed)}
    if EVP_PKEY_meth_get_check_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_get_check)}
      EVP_PKEY_meth_get_check := _EVP_PKEY_meth_get_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_get_check_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_get_check');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_meth_get_public_check := LoadLibFunction(ADllHandle, EVP_PKEY_meth_get_public_check_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_get_public_check);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_get_public_check_allownil)}
    EVP_PKEY_meth_get_public_check := ERR_EVP_PKEY_meth_get_public_check;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_public_check_introduced)}
    if LibVersion < EVP_PKEY_meth_get_public_check_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_get_public_check)}
      EVP_PKEY_meth_get_public_check := FC_EVP_PKEY_meth_get_public_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_public_check_removed)}
    if EVP_PKEY_meth_get_public_check_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_get_public_check)}
      EVP_PKEY_meth_get_public_check := _EVP_PKEY_meth_get_public_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_get_public_check_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_get_public_check');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_meth_get_param_check := LoadLibFunction(ADllHandle, EVP_PKEY_meth_get_param_check_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_get_param_check);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_get_param_check_allownil)}
    EVP_PKEY_meth_get_param_check := ERR_EVP_PKEY_meth_get_param_check;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_param_check_introduced)}
    if LibVersion < EVP_PKEY_meth_get_param_check_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_get_param_check)}
      EVP_PKEY_meth_get_param_check := FC_EVP_PKEY_meth_get_param_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_param_check_removed)}
    if EVP_PKEY_meth_get_param_check_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_get_param_check)}
      EVP_PKEY_meth_get_param_check := _EVP_PKEY_meth_get_param_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_get_param_check_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_get_param_check');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_PKEY_meth_get_digest_custom := LoadLibFunction(ADllHandle, EVP_PKEY_meth_get_digest_custom_procname);
  FuncLoadError := not assigned(EVP_PKEY_meth_get_digest_custom);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_meth_get_digest_custom_allownil)}
    EVP_PKEY_meth_get_digest_custom := ERR_EVP_PKEY_meth_get_digest_custom;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_digest_custom_introduced)}
    if LibVersion < EVP_PKEY_meth_get_digest_custom_introduced then
    begin
      {$if declared(FC_EVP_PKEY_meth_get_digest_custom)}
      EVP_PKEY_meth_get_digest_custom := FC_EVP_PKEY_meth_get_digest_custom;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_meth_get_digest_custom_removed)}
    if EVP_PKEY_meth_get_digest_custom_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_meth_get_digest_custom)}
      EVP_PKEY_meth_get_digest_custom := _EVP_PKEY_meth_get_digest_custom;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_meth_get_digest_custom_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_meth_get_digest_custom');
    {$ifend}
  end;

 {introduced 1.1.0}
  EVP_add_alg_module := LoadLibFunction(ADllHandle, EVP_add_alg_module_procname);
  FuncLoadError := not assigned(EVP_add_alg_module);
  if FuncLoadError then
  begin
    {$if not defined(EVP_add_alg_module_allownil)}
    EVP_add_alg_module := ERR_EVP_add_alg_module;
    {$ifend}
    {$if declared(EVP_add_alg_module_introduced)}
    if LibVersion < EVP_add_alg_module_introduced then
    begin
      {$if declared(FC_EVP_add_alg_module)}
      EVP_add_alg_module := FC_EVP_add_alg_module;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_add_alg_module_removed)}
    if EVP_add_alg_module_removed <= LibVersion then
    begin
      {$if declared(_EVP_add_alg_module)}
      EVP_add_alg_module := _EVP_add_alg_module;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_add_alg_module_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_add_alg_module');
    {$ifend}
  end;


  OpenSSL_add_all_ciphers := LoadLibFunction(ADllHandle, OpenSSL_add_all_ciphers_procname);
  FuncLoadError := not assigned(OpenSSL_add_all_ciphers);
  if FuncLoadError then
  begin
    {$if not defined(OpenSSL_add_all_ciphers_allownil)}
    OpenSSL_add_all_ciphers := ERR_OpenSSL_add_all_ciphers;
    {$ifend}
    {$if declared(OpenSSL_add_all_ciphers_introduced)}
    if LibVersion < OpenSSL_add_all_ciphers_introduced then
    begin
      {$if declared(FC_OpenSSL_add_all_ciphers)}
      OpenSSL_add_all_ciphers := FC_OpenSSL_add_all_ciphers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OpenSSL_add_all_ciphers_removed)}
    if OpenSSL_add_all_ciphers_removed <= LibVersion then
    begin
      {$if declared(_OpenSSL_add_all_ciphers)}
      OpenSSL_add_all_ciphers := _OpenSSL_add_all_ciphers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OpenSSL_add_all_ciphers_allownil)}
    if FuncLoadError then
      AFailed.Add('OpenSSL_add_all_ciphers');
    {$ifend}
  end;


  OpenSSL_add_all_digests := LoadLibFunction(ADllHandle, OpenSSL_add_all_digests_procname);
  FuncLoadError := not assigned(OpenSSL_add_all_digests);
  if FuncLoadError then
  begin
    {$if not defined(OpenSSL_add_all_digests_allownil)}
    OpenSSL_add_all_digests := ERR_OpenSSL_add_all_digests;
    {$ifend}
    {$if declared(OpenSSL_add_all_digests_introduced)}
    if LibVersion < OpenSSL_add_all_digests_introduced then
    begin
      {$if declared(FC_OpenSSL_add_all_digests)}
      OpenSSL_add_all_digests := FC_OpenSSL_add_all_digests;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OpenSSL_add_all_digests_removed)}
    if OpenSSL_add_all_digests_removed <= LibVersion then
    begin
      {$if declared(_OpenSSL_add_all_digests)}
      OpenSSL_add_all_digests := _OpenSSL_add_all_digests;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OpenSSL_add_all_digests_allownil)}
    if FuncLoadError then
      AFailed.Add('OpenSSL_add_all_digests');
    {$ifend}
  end;


  EVP_cleanup := LoadLibFunction(ADllHandle, EVP_cleanup_procname);
  FuncLoadError := not assigned(EVP_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(EVP_cleanup_allownil)}
    EVP_cleanup := ERR_EVP_cleanup;
    {$ifend}
    {$if declared(EVP_cleanup_introduced)}
    if LibVersion < EVP_cleanup_introduced then
    begin
      {$if declared(FC_EVP_cleanup)}
      EVP_cleanup := FC_EVP_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_cleanup_removed)}
    if EVP_cleanup_removed <= LibVersion then
    begin
      {$if declared(_EVP_cleanup)}
      EVP_cleanup := _EVP_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_cleanup');
    {$ifend}
  end;

  //* MAC Stuff */
  EVP_MAC_fetch := LoadLibFunction(ADllHandle, EVP_MAC_fetch_procname);
  FuncLoadError := not assigned(EVP_MAC_fetch);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MAC_fetch_allownil)}
    EVP_MAC_fetch := ERR_EVP_MAC_fetch;
    {$ifend}
    {$if declared(EVP_MAC_fetch_introduced)}
    if LibVersion < EVP_MAC_fetch_introduced then
    begin
      {$if declared(FC_EVP_MAC_fetch)}
      EVP_MAC_fetch := FC_EVP_MAC_fetch;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MAC_fetch_removed)}
    if EVP_MAC_fetch_removed <= LibVersion then
    begin
      {$if declared(_EVP_MAC_fetch)}
      EVP_MAC_fetch := _EVP_MAC_fetch;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MAC_fetch_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MAC_fetch');
    {$ifend}
  end;

  EVP_MAC_up_ref := LoadLibFunction(ADllHandle, EVP_MAC_up_ref_procname);
  FuncLoadError := not assigned(EVP_MAC_up_ref);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MAC_up_ref_allownil)}
    EVP_MAC_up_ref := ERR_EVP_MAC_up_ref;
    {$ifend}
    {$if declared(EVP_MAC_up_ref_introduced)}
    if LibVersion < EVP_MAC_up_ref_introduced then
    begin
      {$if declared(FC_EVP_MAC_up_ref)}
      EVP_MAC_up_ref := FC_EVP_MAC_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MAC_up_ref_removed)}
    if EVP_MAC_up_ref_removed <= LibVersion then
    begin
      {$if declared(_EVP_MAC_up_ref)}
      EVP_MAC_up_ref := _EVP_MAC_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MAC_up_ref_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MAC_up_ref');
    {$ifend}
  end;

  EVP_MAC_free := LoadLibFunction(ADllHandle, EVP_MAC_free_procname);
  FuncLoadError := not assigned(EVP_MAC_free);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MAC_free_allownil)}
    EVP_MAC_free := ERR_EVP_MAC_free;
    {$ifend}
    {$if declared(EVP_MAC_free_introduced)}
    if LibVersion < EVP_MAC_free_introduced then
    begin
      {$if declared(FC_EVP_MAC_free)}
      EVP_MAC_free := FC_EVP_MAC_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MAC_free_removed)}
    if EVP_MAC_free_removed <= LibVersion then
    begin
      {$if declared(_EVP_MAC_free)}
      EVP_MAC_free := _EVP_MAC_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MAC_free_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MAC_free');
    {$ifend}
  end;

  EVP_MAC_is_a := LoadLibFunction(ADllHandle, EVP_MAC_is_a_procname);
  FuncLoadError := not assigned(EVP_MAC_is_a);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MAC_is_a_allownil)}
    EVP_MAC_is_a := ERR_EVP_MAC_is_a;
    {$ifend}
    {$if declared(EVP_MAC_is_a_introduced)}
    if LibVersion < EVP_MAC_is_a_introduced then
    begin
      {$if declared(FC_EVP_MAC_is_a)}
      EVP_MAC_is_a := FC_EVP_MAC_is_a;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MAC_is_a_removed)}
    if EVP_MAC_is_a_removed <= LibVersion then
    begin
      {$if declared(_EVP_MAC_is_a)}
      EVP_MAC_is_a := _EVP_MAC_is_a;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MAC_is_a_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MAC_is_a');
    {$ifend}
  end;

  EVP_MAC_get0_name := LoadLibFunction(ADllHandle, EVP_MAC_get0_name_procname);
  FuncLoadError := not assigned(EVP_MAC_get0_name);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MAC_get0_name_allownil)}
    EVP_MAC_get0_name := ERR_EVP_MAC_get0_name;
    {$ifend}
    {$if declared(EVP_MAC_get0_name_introduced)}
    if LibVersion < EVP_MAC_get0_name_introduced then
    begin
      {$if declared(FC_EVP_MAC_get0_name)}
      EVP_MAC_get0_name := FC_EVP_MAC_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MAC_get0_name_removed)}
    if EVP_MAC_get0_name_removed <= LibVersion then
    begin
      {$if declared(_EVP_MAC_get0_name)}
      EVP_MAC_get0_name := _EVP_MAC_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MAC_get0_name_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MAC_get0_name');
    {$ifend}
  end;

  EVP_MAC_names_do_all := LoadLibFunction(ADllHandle, EVP_MAC_names_do_all_procname);
  FuncLoadError := not assigned(EVP_MAC_names_do_all);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MAC_names_do_all_allownil)}
    EVP_MAC_names_do_all := ERR_EVP_MAC_names_do_all;
    {$ifend}
    {$if declared(EVP_MAC_names_do_all_introduced)}
    if LibVersion < EVP_MAC_names_do_all_introduced then
    begin
      {$if declared(FC_EVP_MAC_names_do_all)}
      EVP_MAC_names_do_all := FC_EVP_MAC_names_do_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MAC_names_do_all_removed)}
    if EVP_MAC_names_do_all_removed <= LibVersion then
    begin
      {$if declared(_EVP_MAC_names_do_all)}
      EVP_MAC_names_do_all := _EVP_MAC_names_do_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MAC_names_do_all_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MAC_names_do_all');
    {$ifend}
  end;

  EVP_MAC_get0_description := LoadLibFunction(ADllHandle, EVP_MAC_get0_description_procname);
  FuncLoadError := not assigned(EVP_MAC_get0_description);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MAC_get0_description_allownil)}
    EVP_MAC_get0_description := ERR_EVP_MAC_get0_description;
    {$ifend}
    {$if declared(EVP_MAC_get0_description_introduced)}
    if LibVersion < EVP_MAC_get0_description_introduced then
    begin
      {$if declared(FC_EVP_MAC_get0_description)}
      EVP_MAC_get0_description := FC_EVP_MAC_get0_description;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MAC_get0_description_removed)}
    if EVP_MAC_get0_description_removed <= LibVersion then
    begin
      {$if declared(_EVP_MAC_get0_description)}
      EVP_MAC_get0_description := _EVP_MAC_get0_description;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MAC_get0_description_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MAC_get0_description');
    {$ifend}
  end;

  EVP_MAC_get0_provider := LoadLibFunction(ADllHandle, EVP_MAC_get0_provider_procname);
  FuncLoadError := not assigned(EVP_MAC_get0_provider);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MAC_get0_provider_allownil)}
    EVP_MAC_get0_provider := ERR_EVP_MAC_get0_provider;
    {$ifend}
    {$if declared(EVP_MAC_get0_provider_introduced)}
    if LibVersion < EVP_MAC_get0_provider_introduced then
    begin
      {$if declared(FC_EVP_MAC_get0_provider)}
      EVP_MAC_get0_provider := FC_EVP_MAC_get0_provider;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MAC_get0_provider_removed)}
    if EVP_MAC_get0_provider_removed <= LibVersion then
    begin
      {$if declared(_EVP_MAC_get0_provider)}
      EVP_MAC_get0_provider := _EVP_MAC_get0_provider;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MAC_get0_provider_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MAC_get0_provider');
    {$ifend}
  end;

  EVP_MAC_get_params := LoadLibFunction(ADllHandle, EVP_MAC_get_params_procname);
  FuncLoadError := not assigned(EVP_MAC_get_params);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MAC_get_params_allownil)}
    EVP_MAC_get_params := ERR_EVP_MAC_get_params;
    {$ifend}
    {$if declared(EVP_MAC_get_params_introduced)}
    if LibVersion < EVP_MAC_get_params_introduced then
    begin
      {$if declared(FC_EVP_MAC_get_params)}
      EVP_MAC_get_params := FC_EVP_MAC_get_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MAC_get_params_removed)}
    if EVP_MAC_get_params_removed <= LibVersion then
    begin
      {$if declared(_EVP_MAC_get_params)}
      EVP_MAC_get_params := _EVP_MAC_get_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MAC_get_params_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MAC_get_params');
    {$ifend}
  end;

  EVP_MAC_CTX_new := LoadLibFunction(ADllHandle, EVP_MAC_CTX_new_procname);
  FuncLoadError := not assigned(EVP_MAC_CTX_new);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MAC_CTX_new_allownil)}
    EVP_MAC_CTX_new := ERR_EVP_MAC_CTX_new;
    {$ifend}
    {$if declared(EVP_MAC_CTX_new_introduced)}
    if LibVersion < EVP_MAC_CTX_new_introduced then
    begin
      {$if declared(FC_EVP_MAC_CTX_new)}
      EVP_MAC_CTX_new := FC_EVP_MAC_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MAC_CTX_new_removed)}
    if EVP_MAC_CTX_new_removed <= LibVersion then
    begin
      {$if declared(_EVP_MAC_CTX_new)}
      EVP_MAC_CTX_new := _EVP_MAC_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MAC_CTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MAC_CTX_new');
    {$ifend}
  end;

  EVP_MAC_CTX_free := LoadLibFunction(ADllHandle, EVP_MAC_CTX_free_procname);
  FuncLoadError := not assigned(EVP_MAC_CTX_free);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MAC_CTX_free_allownil)}
    EVP_MAC_CTX_free := ERR_EVP_MAC_CTX_free;
    {$ifend}
    {$if declared(EVP_MAC_CTX_free_introduced)}
    if LibVersion < EVP_MAC_CTX_free_introduced then
    begin
      {$if declared(FC_EVP_MAC_CTX_free)}
      EVP_MAC_CTX_free := FC_EVP_MAC_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MAC_CTX_free_removed)}
    if EVP_MAC_CTX_free_removed <= LibVersion then
    begin
      {$if declared(_EVP_MAC_CTX_free)}
      EVP_MAC_CTX_free := _EVP_MAC_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MAC_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MAC_CTX_free');
    {$ifend}
  end;

  EVP_MAC_CTX_dup := LoadLibFunction(ADllHandle, EVP_MAC_CTX_dup_procname);
  FuncLoadError := not assigned(EVP_MAC_CTX_dup);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MAC_CTX_dup_allownil)}
    EVP_MAC_CTX_dup := ERR_EVP_MAC_CTX_dup;
    {$ifend}
    {$if declared(EVP_MAC_CTX_dup_introduced)}
    if LibVersion < EVP_MAC_CTX_dup_introduced then
    begin
      {$if declared(FC_EVP_MAC_CTX_dup)}
      EVP_MAC_CTX_dup := FC_EVP_MAC_CTX_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MAC_CTX_dup_removed)}
    if EVP_MAC_CTX_dup_removed <= LibVersion then
    begin
      {$if declared(_EVP_MAC_CTX_dup)}
      EVP_MAC_CTX_dup := _EVP_MAC_CTX_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MAC_CTX_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MAC_CTX_dup');
    {$ifend}
  end;

   EVP_MAC_CTX_get0_mac := LoadLibFunction(ADllHandle, EVP_MAC_CTX_get0_mac_procname);
  FuncLoadError := not assigned(EVP_MAC_CTX_get0_mac);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MAC_CTX_get0_mac_allownil)}
    EVP_MAC_CTX_get0_mac := ERR_EVP_MAC_CTX_get0_mac;
    {$ifend}
    {$if declared(EVP_MAC_CTX_get0_mac_introduced)}
    if LibVersion < EVP_MAC_CTX_get0_mac_introduced then
    begin
      {$if declared(FC_EVP_MAC_CTX_get0_mac)}
      EVP_MAC_CTX_get0_mac := FC_EVP_MAC_CTX_get0_mac;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MAC_CTX_get0_mac_removed)}
    if EVP_MAC_CTX_get0_mac_removed <= LibVersion then
    begin
      {$if declared(_EVP_MAC_CTX_get0_mac)}
      EVP_MAC_CTX_get0_mac := _EVP_MAC_CTX_get0_mac;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MAC_CTX_get0_mac_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MAC_CTX_get0_mac');
    {$ifend}
  end;

  EVP_MAC_CTX_get_params := LoadLibFunction(ADllHandle, EVP_MAC_CTX_get_params_procname);
  FuncLoadError := not assigned(EVP_MAC_CTX_get_params);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MAC_CTX_get_params_allownil)}
    EVP_MAC_CTX_get_params := ERR_EVP_MAC_CTX_get_params;
    {$ifend}
    {$if declared(EVP_MAC_CTX_get_params_introduced)}
    if LibVersion < EVP_MAC_CTX_get_params_introduced then
    begin
      {$if declared(FC_EVP_MAC_CTX_get_params)}
      EVP_MAC_CTX_get_params := FC_EVP_MAC_CTX_get_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MAC_CTX_get_params_removed)}
    if EVP_MAC_CTX_get_params_removed <= LibVersion then
    begin
      {$if declared(_EVP_MAC_CTX_get_params)}
      EVP_MAC_CTX_get_params := _EVP_MAC_CTX_get_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MAC_CTX_get_params_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MAC_CTX_get_params');
    {$ifend}
  end;

  EVP_MAC_CTX_set_params := LoadLibFunction(ADllHandle, EVP_MAC_CTX_set_params_procname);
  FuncLoadError := not assigned(EVP_MAC_CTX_set_params);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MAC_CTX_set_params_allownil)}
    EVP_MAC_CTX_set_params := ERR_EVP_MAC_CTX_set_params;
    {$ifend}
    {$if declared(EVP_MAC_CTX_set_params_introduced)}
    if LibVersion < EVP_MAC_CTX_set_params_introduced then
    begin
      {$if declared(FC_EVP_MAC_CTX_set_params)}
      EVP_MAC_CTX_set_params := FC_EVP_MAC_CTX_set_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MAC_CTX_set_params_removed)}
    if EVP_MAC_CTX_set_params_removed <= LibVersion then
    begin
      {$if declared(_EVP_MAC_CTX_set_params)}
      EVP_MAC_CTX_set_params := _EVP_MAC_CTX_set_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MAC_CTX_set_params_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MAC_CTX_set_params');
    {$ifend}
  end;

   EVP_MAC_CTX_get_mac_size := LoadLibFunction(ADllHandle, EVP_MAC_CTX_get_mac_size_procname);
  FuncLoadError := not assigned(EVP_MAC_CTX_get_mac_size);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MAC_CTX_get_mac_size_allownil)}
    EVP_MAC_CTX_get_mac_size := ERR_EVP_MAC_CTX_get_mac_size;
    {$ifend}
    {$if declared(EVP_MAC_CTX_get_mac_size_introduced)}
    if LibVersion < EVP_MAC_CTX_get_mac_size_introduced then
    begin
      {$if declared(FC_EVP_MAC_CTX_get_mac_size)}
      EVP_MAC_CTX_get_mac_size := FC_EVP_MAC_CTX_get_mac_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MAC_CTX_get_mac_size_removed)}
    if EVP_MAC_CTX_get_mac_size_removed <= LibVersion then
    begin
      {$if declared(_EVP_MAC_CTX_get_mac_size)}
      EVP_MAC_CTX_get_mac_size := _EVP_MAC_CTX_get_mac_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MAC_CTX_get_mac_size_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MAC_CTX_get_mac_size');
    {$ifend}
  end;

   EVP_MAC_init := LoadLibFunction(ADllHandle, EVP_MAC_init_procname);
  FuncLoadError := not assigned(EVP_MAC_init);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MAC_init_allownil)}
    EVP_MAC_init := ERR_EVP_MAC_init;
    {$ifend}
    {$if declared(EVP_MAC_init_introduced)}
    if LibVersion < EVP_MAC_init_introduced then
    begin
      {$if declared(FC_EVP_MAC_init)}
      EVP_MAC_init := FC_EVP_MAC_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MAC_init_removed)}
    if EVP_MAC_init_removed <= LibVersion then
    begin
      {$if declared(_EVP_MAC_init)}
      EVP_MAC_init := _EVP_MAC_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MAC_init_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MAC_init');
    {$ifend}
  end;

   EVP_MAC_init_SKEY := LoadLibFunction(ADllHandle, EVP_MAC_init_SKEY_procname);
  FuncLoadError := not assigned(EVP_MAC_init_SKEY);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MAC_init_SKEY_allownil)}
    EVP_MAC_init_SKEY := ERR_EVP_MAC_init_SKEY;
    {$ifend}
    {$if declared(EVP_MAC_init_SKEY_introduced)}
    if LibVersion < EVP_MAC_init_SKEY_introduced then
    begin
      {$if declared(FC_EVP_MAC_init_SKEY)}
      EVP_MAC_init_SKEY := FC_EVP_MAC_init_SKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MAC_init_SKEY_removed)}
    if EVP_MAC_init_SKEY_removed <= LibVersion then
    begin
      {$if declared(_EVP_MAC_init_SKEY)}
      EVP_MAC_init_SKEY := _EVP_MAC_init_SKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MAC_init_SKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MAC_init_SKEY');
    {$ifend}
  end;

  EVP_MAC_CTX_get_block_size := LoadLibFunction(ADllHandle, EVP_MAC_CTX_get_block_size_procname);
  FuncLoadError := not assigned(EVP_MAC_CTX_get_block_size);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MAC_CTX_get_block_size_allownil)}
    EVP_MAC_CTX_get_block_size := ERR_EVP_MAC_CTX_get_block_size;
    {$ifend}
    {$if declared(EVP_MAC_CTX_get_block_size_introduced)}
    if LibVersion < EVP_MAC_CTX_get_block_size_introduced then
    begin
      {$if declared(FC_EVP_MAC_CTX_get_block_size)}
      EVP_MAC_CTX_get_block_size := FC_EVP_MAC_CTX_get_block_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MAC_CTX_get_block_size_removed)}
    if EVP_MAC_CTX_get_block_size_removed <= LibVersion then
    begin
      {$if declared(_EVP_MAC_CTX_get_block_size)}
      EVP_MAC_CTX_get_block_sizee := _EVP_MAC_CTX_get_block_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MAC_CTX_get_block_size_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MAC_CTX_get_block_size');
    {$ifend}
  end;

    EVP_MAC_update := LoadLibFunction(ADllHandle, EVP_MAC_update_procname);
  FuncLoadError := not assigned(EVP_MAC_update);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MAC_update_allownil)}
    EVP_MAC_update := ERR_EVP_MAC_update;
    {$ifend}
    {$if declared(EVP_MAC_update_introduced)}
    if LibVersion < EVP_MAC_update_introduced then
    begin
      {$if declared(FC_EVP_MAC_update)}
      EVP_MAC_update := FC_EVP_MAC_update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MAC_update_removed)}
    if EVP_MAC_update_removed <= LibVersion then
    begin
      {$if declared(_EVP_MAC_update)}
      EVP_MAC_update := _EVP_MAC_update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MAC_update_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MAC_update');
    {$ifend}
  end;

    EVP_MAC_final := LoadLibFunction(ADllHandle, EVP_MAC_final_procname);
  FuncLoadError := not assigned(EVP_MAC_final);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MAC_final_allownil)}
    EVP_MAC_final := ERR_EVP_MAC_final;
    {$ifend}
    {$if declared(EVP_MAC_final_introduced)}
    if LibVersion < EVP_MAC_final_introduced then
    begin
      {$if declared(FC_EVP_MAC_final)}
      EVP_MAC_final := FC_EVP_MAC_final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MAC_final_removed)}
    if EVP_MAC_final_removed <= LibVersion then
    begin
      {$if declared(_EVP_MAC_final)}
      EVP_MAC_final := _EVP_MAC_final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MAC_final_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MAC_final');
    {$ifend}
  end;

  EVP_MAC_finalXOF := LoadLibFunction(ADllHandle, EVP_MAC_finalXOF_procname);
  FuncLoadError := not assigned(EVP_MAC_finalXOF);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MAC_finalXOF_allownil)}
    EVP_MAC_finalXOF := ERR_EVP_MAC_finalXOF;
    {$ifend}
    {$if declared(EVP_MAC_finalXOF_introduced)}
    if LibVersion < EVP_MAC_finalXOF_introduced then
    begin
      {$if declared(FC_EVP_MAC_finalXOF)}
      EVP_MAC_finalXOF := FC_EVP_MAC_finalXOF;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MAC_finalXOF_removed)}
    if EVP_MAC_finalXOF_removed <= LibVersion then
    begin
      {$if declared(_EVP_MAC_finalXOF)}
      EVP_MAC_finalXOF := _EVP_MAC_finalXOF;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MAC_finalXOF_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MAC_finalXOF');
    {$ifend}
  end;

  EVP_MAC_do_all_provided := LoadLibFunction(ADllHandle, EVP_MAC_do_all_provided_procname);
  FuncLoadError := not assigned(EVP_MAC_do_all_provided);
  if FuncLoadError then
  begin
    {$if not defined(EVP_MAC_do_all_provided_allownil)}
    EVP_MAC_do_all_provided := ERR_EVP_MAC_do_all_provided;
    {$ifend}
    {$if declared(EVP_MAC_do_all_provided_introduced)}
    if LibVersion < EVP_MAC_do_all_provided_introduced then
    begin
      {$if declared(FC_EVP_MAC_do_all_provided)}
      EVP_MAC_do_all_provided := FC_EVP_MAC_do_all_provided;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_MAC_do_all_provided_removed)}
    if EVP_MAC_do_all_provided_removed <= LibVersion then
    begin
      {$if declared(_EVP_MAC_do_all_provided)}
      EVP_MAC_do_all_provided := _EVP_MAC_do_all_provided;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_MAC_do_all_provided_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_MAC_do_all_provided');
    {$ifend}
  end;
end;

procedure Unload;
begin
  EVP_PKEY_assign_RSA := nil; {removed 1.0.0}
  EVP_PKEY_assign_DSA := nil; {removed 1.0.0}
  EVP_PKEY_assign_DH := nil; {removed 1.0.0}
  EVP_PKEY_assign_EC_KEY := nil; {removed 1.0.0}
  EVP_PKEY_assign_SIPHASH := nil; {removed 1.0.0}
  EVP_PKEY_assign_POLY1305 := nil; {removed 1.0.0}
  EVP_MD_meth_new := nil; {introduced 1.1.0}
  EVP_MD_meth_dup := nil; {introduced 1.1.0}
  EVP_MD_meth_free := nil; {introduced 1.1.0}
  EVP_MD_meth_set_input_blocksize := nil; {introduced 1.1.0}
  EVP_MD_meth_set_result_size := nil; {introduced 1.1.0}
  EVP_MD_meth_set_app_datasize := nil; {introduced 1.1.0}
  EVP_MD_meth_set_flags := nil; {introduced 1.1.0}
  EVP_MD_meth_set_init := nil; {introduced 1.1.0}
  EVP_MD_meth_set_update := nil; {introduced 1.1.0}
  EVP_MD_meth_set_final := nil; {introduced 1.1.0}
  EVP_MD_meth_set_copy := nil; {introduced 1.1.0}
  EVP_MD_meth_set_cleanup := nil; {introduced 1.1.0}
  EVP_MD_meth_set_ctrl := nil; {introduced 1.1.0}
  EVP_MD_meth_get_input_blocksize := nil; {introduced 1.1.0}
  EVP_MD_meth_get_result_size := nil; {introduced 1.1.0}
  EVP_MD_meth_get_app_datasize := nil; {introduced 1.1.0}
  EVP_MD_meth_get_flags := nil; {introduced 1.1.0}
  EVP_MD_meth_get_init := nil; {introduced 1.1.0}
  EVP_MD_meth_get_update := nil; {introduced 1.1.0}
  EVP_MD_meth_get_final := nil; {introduced 1.1.0}
  EVP_MD_meth_get_copy := nil; {introduced 1.1.0}
  EVP_MD_meth_get_cleanup := nil; {introduced 1.1.0}
  EVP_MD_meth_get_ctrl := nil; {introduced 1.1.0}
  EVP_CIPHER_meth_new := nil; {introduced 1.1.0}
  EVP_CIPHER_meth_dup := nil; {introduced 1.1.0}
  EVP_CIPHER_meth_free := nil; {introduced 1.1.0}
  EVP_CIPHER_meth_set_iv_length := nil; {introduced 1.1.0}
  EVP_CIPHER_meth_set_flags := nil; {introduced 1.1.0}
  EVP_CIPHER_meth_set_impl_ctx_size := nil; {introduced 1.1.0}
  EVP_CIPHER_meth_set_init := nil; {introduced 1.1.0}
  EVP_CIPHER_meth_set_do_cipher := nil; {introduced 1.1.0}
  EVP_CIPHER_meth_set_cleanup := nil; {introduced 1.1.0}
  EVP_CIPHER_meth_set_set_asn1_params := nil; {introduced 1.1.0}
  EVP_CIPHER_meth_set_get_asn1_params := nil; {introduced 1.1.0}
  EVP_CIPHER_meth_set_ctrl := nil; {introduced 1.1.0}
  EVP_CIPHER_meth_get_init := nil; {introduced 1.1.0}
  EVP_CIPHER_meth_get_do_cipher := nil; {introduced 1.1.0}
  EVP_CIPHER_meth_get_cleanup := nil; {introduced 1.1.0}
  EVP_CIPHER_meth_get_set_asn1_params := nil; {introduced 1.1.0}
  EVP_CIPHER_meth_get_get_asn1_params := nil; {introduced 1.1.0}
  EVP_CIPHER_meth_get_ctrl := nil; {introduced 1.1.0}
  EVP_MD_type := nil; {removed 3.0.0}
  EVP_MD_pkey_type := nil; {removed 3.0.0}
  EVP_MD_size := nil; {removed 3.0.0}
  EVP_MD_block_size := nil; {removed 3.0.0}
  EVP_MD_flags := nil; {removed 3.0.0}
  EVP_MD_CTX_md := nil;
  EVP_MD_CTX_update_fn := nil; {introduced 1.1.0}
  EVP_MD_CTX_set_update_fn := nil; {introduced 1.1.0}
  EVP_MD_CTX_pkey_ctx := nil; {introduced 1.1.0 removed 3.0.0}
  EVP_MD_CTX_set_pkey_ctx := nil; {introduced 1.1.0}
  EVP_MD_CTX_md_data := nil; {introduced 1.1.0 removed 3.0.0}
  EVP_CIPHER_nid := nil; {removed 3.0.0}
  EVP_CIPHER_get_nid := nil; {introduced  3.0.0}
  EVP_CIPHER_get0_name := nil; {introduced  3.0.0}
  EVP_CIPHER_block_size := nil; {removed 3.0.0}
  EVP_CIPHER_get_block_size := nil; {introduced  3.0.0}
  EVP_CIPHER_impl_ctx_size := nil; {introduced 1.1.0}
  EVP_CIPHER_key_length := nil; {removed 3.0.0}
  EVP_CIPHER_get_key_length := nil; {introduced 3.0.0}
  EVP_CIPHER_iv_length := nil; {removed 3.0.0}
  EVP_CIPHER_get_iv_length := nil; {introduced  3.0.0}
  EVP_CIPHER_flags := nil; {removed 3.0.0}
  EVP_CIPHER_get_flags := nil; {introduced  3.0.0}
  EVP_CIPHER_get_mode := nil; {introduced  3.0.0}
  EVP_CIPHER_get_type := nil; {introduced  3.0.0}
  EVP_CIPHER_CTX_cipher := nil;
  EVP_CIPHER_CTX_encrypting := nil; {introduced 1.1.0 removed 3.0.0}
  EVP_CIPHER_CTX_is_encrypting := nil; {introduced  3.0.0}
  EVP_CIPHER_CTX_nid := nil; {removed 3.0.0}
  EVP_CIPHER_CTX_get_nid := nil; {introduced  3.0.0}
  EVP_CIPHER_CTX_block_size := nil; {removed 3.0.0}
  EVP_CIPHER_CTX_get_block_size := nil; {introduced  3.0.0}
  EVP_CIPHER_CTX_key_length := nil; {removed 3.0.0}
  EVP_CIPHER_CTX_get_key_length := nil; {introduced  3.0.0}
  EVP_CIPHER_CTX_iv_length := nil; {removed 3.0.0}
  EVP_CIPHER_CTX_get_iv_length := nil; {introduced  3.0.0}
  EVP_CIPHER_CTX_iv := nil; {introduced 1.1.0}
  EVP_CIPHER_CTX_original_iv := nil; {introduced 1.1.0}
  EVP_CIPHER_CTX_iv_noconst := nil; {introduced 1.1.0}
  EVP_CIPHER_CTX_buf_noconst := nil; {introduced 1.1.0}
  EVP_CIPHER_CTX_num := nil; {introduced 1.1.0 removed 3.0.0}
  EVP_CIPHER_CTX_get_num := nil; {introduced  3.0.0}
  EVP_CIPHER_CTX_set_num := nil; {introduced 1.1.0}
  EVP_CIPHER_CTX_get_tag_length := nil; {introduced  3.0.0}
  EVP_CIPHER_CTX_copy := nil;
  EVP_CIPHER_CTX_get_app_data := nil;
  EVP_CIPHER_CTX_set_app_data := nil;
  EVP_CIPHER_CTX_get_cipher_data := nil; {introduced 1.1.0}
  EVP_CIPHER_CTX_set_cipher_data := nil; {introduced 1.1.0}
  BIO_set_md := nil; {removed 1.0.0}
  EVP_MD_CTX_init := nil; {removed 1.1.0}
  EVP_MD_CTX_cleanup := nil; {removed 1.1.0}
  EVP_MD_CTX_ctrl := nil; {introduced 1.1.0}
  EVP_MD_CTX_new := nil; {introduced 1.1.0}
  EVP_MD_CTX_reset := nil; {introduced 1.1.0}
  EVP_MD_CTX_free := nil; {introduced 1.1.0}
  EVP_MD_CTX_copy_ex := nil;
  EVP_MD_CTX_set_flags := nil;
  EVP_MD_CTX_clear_flags := nil;
  EVP_MD_CTX_test_flags := nil;
  EVP_DigestInit_ex := nil;
  EVP_DigestUpdate := nil;
  EVP_DigestFinal_ex := nil;
  EVP_Digest := nil;
  EVP_MD_CTX_copy := nil;
  EVP_DigestInit := nil;
  EVP_DigestFinal := nil;
  EVP_DigestFinalXOF := nil; {introduced 1.1.0}
  EVP_read_pw_string := nil;
  EVP_read_pw_string_min := nil;
  EVP_set_pw_prompt := nil;
  EVP_get_pw_prompt := nil;
  EVP_BytesToKey := nil;
  EVP_CIPHER_CTX_set_flags := nil;
  EVP_CIPHER_CTX_clear_flags := nil;
  EVP_CIPHER_CTX_test_flags := nil;
  EVP_EncryptInit := nil;
  EVP_EncryptInit_ex := nil;
  EVP_EncryptUpdate := nil;
  EVP_EncryptFinal_ex := nil;
  EVP_EncryptFinal := nil;
  EVP_DecryptInit := nil;
  EVP_DecryptInit_ex := nil;
  EVP_DecryptUpdate := nil;
  EVP_DecryptFinal := nil;
  EVP_DecryptFinal_ex := nil;
  EVP_CipherInit := nil;
  EVP_CipherInit_ex := nil;
  EVP_CipherUpdate := nil;
  EVP_CipherFinal := nil;
  EVP_CipherFinal_ex := nil;
  EVP_SignFinal := nil;
  EVP_DigestSign := nil; {introduced 1.1.0}
  EVP_VerifyFinal := nil;
  EVP_DigestVerify := nil; {introduced 1.1.0}
  EVP_DigestSignInit := nil;
  EVP_DigestSignFinal := nil;
  EVP_DigestVerifyInit := nil;
  EVP_DigestVerifyFinal := nil;
  EVP_OpenInit := nil;
  EVP_OpenFinal := nil;
  EVP_SealInit := nil;
  EVP_SealFinal := nil;
  EVP_ENCODE_CTX_new := nil; {introduced 1.1.0}
  EVP_ENCODE_CTX_free := nil; {introduced 1.1.0}
  EVP_ENCODE_CTX_copy := nil; {introduced 1.1.0}
  EVP_ENCODE_CTX_num := nil; {introduced 1.1.0}
  EVP_EncodeInit := nil;
  EVP_EncodeUpdate := nil;
  EVP_EncodeFinal := nil;
  EVP_EncodeBlock := nil;
  EVP_DecodeInit := nil;
  EVP_DecodeUpdate := nil;
  EVP_DecodeFinal := nil;
  EVP_DecodeBlock := nil;
  EVP_CIPHER_CTX_new := nil;
  EVP_CIPHER_CTX_reset := nil; {introduced 1.1.0}
  EVP_CIPHER_CTX_free := nil;
  EVP_CIPHER_CTX_set_key_length := nil;
  EVP_CIPHER_CTX_set_padding := nil;
  EVP_CIPHER_CTX_ctrl := nil;
  EVP_CIPHER_CTX_rand_key := nil;
  BIO_f_md := nil;
  BIO_f_base64 := nil;
  BIO_f_cipher := nil;
  BIO_f_reliable := nil;
  BIO_set_cipher := nil;
  EVP_md_null := nil;
  EVP_md2 := nil; {removed 1.1.0 allow_nil}
  EVP_md4 := nil; {removed 1.1.0 allow_nil}
  EVP_md5 := nil; {removed 1.1.0 allow_nil}
  EVP_md5_sha1 := nil; {introduced 1.1.0}
  EVP_sha1 := nil;
  EVP_sha224 := nil;
  EVP_sha256 := nil;
  EVP_sha384 := nil;
  EVP_sha512 := nil;
  EVP_sha512_224 := nil; {introduced 1.1.0}
  EVP_sha512_256 := nil; {introduced 1.1.0}
  EVP_sha3_224 := nil; {introduced 1.1.0}
  EVP_sha3_256 := nil; {introduced 1.1.0}
  EVP_sha3_384 := nil; {introduced 1.1.0}
  EVP_sha3_512 := nil; {introduced 1.1.0}
  EVP_shake128 := nil; {introduced 1.1.0}
  EVP_shake256 := nil; {introduced 1.1.0}
  EVP_enc_null := nil;
  EVP_des_ecb := nil;
  EVP_des_ede := nil;
  EVP_des_ede3 := nil;
  EVP_des_ede_ecb := nil;
  EVP_des_ede3_ecb := nil;
  EVP_des_cfb64 := nil;
  EVP_des_cfb1 := nil;
  EVP_des_cfb8 := nil;
  EVP_des_ede_cfb64 := nil;
  EVP_des_ede3_cfb64 := nil;
  EVP_des_ede3_cfb1 := nil;
  EVP_des_ede3_cfb8 := nil;
  EVP_des_ofb := nil;
  EVP_des_ede_ofb := nil;
  EVP_des_ede3_ofb := nil;
  EVP_des_cbc := nil;
  EVP_des_ede_cbc := nil;
  EVP_des_ede3_cbc := nil;
  EVP_desx_cbc := nil;
  EVP_des_ede3_wrap := nil;
  EVP_rc4 := nil;
  EVP_rc4_40 := nil;
  EVP_rc2_ecb := nil;
  EVP_rc2_cbc := nil;
  EVP_rc2_40_cbc := nil;
  EVP_rc2_64_cbc := nil;
  EVP_rc2_cfb64 := nil;
  EVP_rc2_ofb := nil;
  EVP_bf_ecb := nil;
  EVP_bf_cbc := nil;
  EVP_bf_cfb64 := nil;
  EVP_bf_ofb := nil;
  EVP_cast5_ecb := nil;
  EVP_cast5_cbc := nil;
  EVP_cast5_cfb64 := nil;
  EVP_cast5_ofb := nil;
  EVP_aes_128_ecb := nil;
  EVP_aes_128_cbc := nil;
  EVP_aes_128_cfb1 := nil;
  EVP_aes_128_cfb8 := nil;
  EVP_aes_128_cfb128 := nil;
  EVP_aes_128_ofb := nil;
  EVP_aes_128_ctr := nil;
  EVP_aes_128_ccm := nil;
  EVP_aes_128_gcm := nil;
  EVP_aes_128_xts := nil;
  EVP_aes_128_wrap := nil;
  EVP_aes_128_wrap_pad := nil; {introduced 1.1.0}
  EVP_aes_128_ocb := nil; {introduced 1.1.0}
  EVP_aes_192_ecb := nil;
  EVP_aes_192_cbc := nil;
  EVP_aes_192_cfb1 := nil;
  EVP_aes_192_cfb8 := nil;
  EVP_aes_192_cfb128 := nil;
  EVP_aes_192_ofb := nil;
  EVP_aes_192_ctr := nil;
  EVP_aes_192_ccm := nil;
  EVP_aes_192_gcm := nil;
  EVP_aes_192_wrap := nil;
  EVP_aes_192_wrap_pad := nil; {introduced 1.1.0}
  EVP_aes_192_ocb := nil; {introduced 1.1.0}
  EVP_aes_256_ecb := nil;
  EVP_aes_256_cbc := nil;
  EVP_aes_256_cfb1 := nil;
  EVP_aes_256_cfb8 := nil;
  EVP_aes_256_cfb128 := nil;
  EVP_aes_256_ofb := nil;
  EVP_aes_256_ctr := nil;
  EVP_aes_256_ccm := nil;
  EVP_aes_256_gcm := nil;
  EVP_aes_256_xts := nil;
  EVP_aes_256_wrap := nil;
  EVP_aes_256_wrap_pad := nil; {introduced 1.1.0}
  EVP_aes_256_ocb := nil; {introduced 1.1.0}
  EVP_aes_128_cbc_hmac_sha1 := nil;
  EVP_aes_256_cbc_hmac_sha1 := nil;
  EVP_aes_128_cbc_hmac_sha256 := nil;
  EVP_aes_256_cbc_hmac_sha256 := nil;
  EVP_aria_128_ecb := nil; {introduced 1.1.0}
  EVP_aria_128_cbc := nil; {introduced 1.1.0}
  EVP_aria_128_cfb1 := nil; {introduced 1.1.0}
  EVP_aria_128_cfb8 := nil; {introduced 1.1.0}
  EVP_aria_128_cfb128 := nil; {introduced 1.1.0}
  EVP_aria_128_ctr := nil; {introduced 1.1.0}
  EVP_aria_128_ofb := nil; {introduced 1.1.0}
  EVP_aria_128_gcm := nil; {introduced 1.1.0}
  EVP_aria_128_ccm := nil; {introduced 1.1.0}
  EVP_aria_192_ecb := nil; {introduced 1.1.0}
  EVP_aria_192_cbc := nil; {introduced 1.1.0}
  EVP_aria_192_cfb1 := nil; {introduced 1.1.0}
  EVP_aria_192_cfb8 := nil; {introduced 1.1.0}
  EVP_aria_192_cfb128 := nil; {introduced 1.1.0}
  EVP_aria_192_ctr := nil; {introduced 1.1.0}
  EVP_aria_192_ofb := nil; {introduced 1.1.0}
  EVP_aria_192_gcm := nil; {introduced 1.1.0}
  EVP_aria_192_ccm := nil; {introduced 1.1.0}
  EVP_aria_256_ecb := nil; {introduced 1.1.0}
  EVP_aria_256_cbc := nil; {introduced 1.1.0}
  EVP_aria_256_cfb1 := nil; {introduced 1.1.0}
  EVP_aria_256_cfb8 := nil; {introduced 1.1.0}
  EVP_aria_256_cfb128 := nil; {introduced 1.1.0}
  EVP_aria_256_ctr := nil; {introduced 1.1.0}
  EVP_aria_256_ofb := nil; {introduced 1.1.0}
  EVP_aria_256_gcm := nil; {introduced 1.1.0}
  EVP_aria_256_ccm := nil; {introduced 1.1.0}
  EVP_camellia_128_ecb := nil;
  EVP_camellia_128_cbc := nil;
  EVP_camellia_128_cfb1 := nil;
  EVP_camellia_128_cfb8 := nil;
  EVP_camellia_128_cfb128 := nil;
  EVP_camellia_128_ofb := nil;
  EVP_camellia_128_ctr := nil; {introduced 1.1.0}
  EVP_camellia_192_ecb := nil;
  EVP_camellia_192_cbc := nil;
  EVP_camellia_192_cfb1 := nil;
  EVP_camellia_192_cfb8 := nil;
  EVP_camellia_192_cfb128 := nil;
  EVP_camellia_192_ofb := nil;
  EVP_camellia_192_ctr := nil; {introduced 1.1.0}
  EVP_camellia_256_ecb := nil;
  EVP_camellia_256_cbc := nil;
  EVP_camellia_256_cfb1 := nil;
  EVP_camellia_256_cfb8 := nil;
  EVP_camellia_256_cfb128 := nil;
  EVP_camellia_256_ofb := nil;
  EVP_camellia_256_ctr := nil; {introduced 1.1.0}
  EVP_chacha20 := nil; {introduced 1.1.0}
  EVP_chacha20_poly1305 := nil; {introduced 1.1.0}
  EVP_seed_ecb := nil;
  EVP_seed_cbc := nil;
  EVP_seed_cfb128 := nil;
  EVP_seed_ofb := nil;
  EVP_sm4_ecb := nil; {introduced 1.1.0}
  EVP_sm4_cbc := nil; {introduced 1.1.0}
  EVP_sm4_cfb128 := nil; {introduced 1.1.0}
  EVP_sm4_ofb := nil; {introduced 1.1.0}
  EVP_sm4_ctr := nil; {introduced 1.1.0}
  EVP_add_cipher := nil;
  EVP_add_digest := nil;
  EVP_get_cipherbyname := nil;
  EVP_get_digestbyname := nil;
  EVP_CIPHER_do_all := nil;
  EVP_CIPHER_do_all_sorted := nil;
  EVP_MD_do_all := nil;
  EVP_MD_do_all_sorted := nil;
  EVP_PKEY_decrypt_old := nil;
  EVP_PKEY_encrypt_old := nil;
  EVP_PKEY_type := nil;
  EVP_PKEY_id := nil; {removed 3.0.0}
  EVP_PKEY_base_id := nil; {removed 3.0.0}
  EVP_PKEY_bits := nil; {removed 3.0.0}
  EVP_PKEY_security_bits := nil; {introduced 1.1.0 removed 3.0.0}
  EVP_PKEY_size := nil; {removed 3.0.0}
  EVP_PKEY_set_type := nil;
  EVP_PKEY_set_type_str := nil;
  EVP_PKEY_set_alias_type := nil; {introduced 1.1.0 removed 3.0.0}
  EVP_PKEY_set1_engine := nil; {introduced 1.1.0}
  EVP_PKEY_get0_engine := nil; {introduced 1.1.0}
  EVP_PKEY_assign := nil;
  EVP_PKEY_get0 := nil;
  EVP_PKEY_get0_hmac := nil; {introduced 1.1.0}
  EVP_PKEY_get0_poly1305 := nil; {introduced 1.1.0}
  EVP_PKEY_get0_siphash := nil; {introduced 1.1.0}
  EVP_PKEY_set1_RSA := nil;
  EVP_PKEY_get0_RSA := nil; {introduced 1.1.0}
  EVP_PKEY_get1_RSA := nil;
  EVP_PKEY_set1_DSA := nil;
  EVP_PKEY_get0_DSA := nil; {introduced 1.1.0}
  EVP_PKEY_get1_DSA := nil;
  EVP_PKEY_set1_DH := nil;
  EVP_PKEY_get0_DH := nil; {introduced 1.1.0}
  EVP_PKEY_get1_DH := nil;
  EVP_PKEY_set1_EC_KEY := nil;
  EVP_PKEY_get0_EC_KEY := nil; {introduced 1.1.0}
  EVP_PKEY_get1_EC_KEY := nil;
  EVP_PKEY_new := nil;
  EVP_PKEY_up_ref := nil; {introduced 1.1.0}
  EVP_PKEY_free := nil;
  d2i_PublicKey := nil;
  i2d_PublicKey := nil;
  d2i_PrivateKey := nil;
  d2i_AutoPrivateKey := nil;
  d2i_AutoPrivateKey_ex := nil;
  i2d_PrivateKey := nil;
  EVP_PKEY_copy_parameters := nil;
  EVP_PKEY_missing_parameters := nil;
  EVP_PKEY_save_parameters := nil;
  EVP_PKEY_cmp_parameters := nil;
  EVP_PKEY_cmp := nil;
  EVP_PKEY_print_public := nil;
  EVP_PKEY_print_private := nil;
  EVP_PKEY_print_params := nil;
  i2d_KeyParams_bio := nil;
  d2i_KeyParams_bio := nil;
  EVP_PKEY_get_default_digest_nid := nil;
  EVP_PKEY_set1_tls_encodedpoint := nil; {introduced 1.1.0 removed 3.0.0}
  EVP_PKEY_get1_tls_encodedpoint := nil; {introduced 1.1.0 removed 3.0.0}
  EVP_CIPHER_type := nil; {removed 3.0.0}
  EVP_CIPHER_param_to_asn1 := nil;
  EVP_CIPHER_asn1_to_param := nil;
  EVP_CIPHER_set_asn1_iv := nil;
  EVP_CIPHER_get_asn1_iv := nil;
  PKCS5_PBE_keyivgen := nil;
  PKCS5_PBKDF2_HMAC_SHA1 := nil;
  PKCS5_PBKDF2_HMAC := nil;
  PKCS5_v2_PBE_keyivgen := nil;
  EVP_PBE_scrypt := nil; {introduced 1.1.0}
  PKCS5_v2_scrypt_keyivgen := nil; {introduced 1.1.0}
  PKCS5_PBE_add := nil;
  EVP_PBE_CipherInit := nil;
  EVP_PBE_alg_add_type := nil;
  EVP_PBE_alg_add := nil;
  EVP_PBE_find := nil;
  EVP_PBE_cleanup := nil;
  EVP_PBE_get := nil; {introduced 1.1.0}
  EVP_PKEY_asn1_get_count := nil;
  EVP_PKEY_asn1_get0 := nil;
  EVP_PKEY_asn1_find := nil;
  EVP_PKEY_asn1_find_str := nil;
  EVP_PKEY_asn1_add0 := nil;
  EVP_PKEY_asn1_add_alias := nil;
  EVP_PKEY_asn1_get0_info := nil;
  EVP_PKEY_get0_asn1 := nil;
  EVP_PKEY_asn1_new := nil;
  EVP_PKEY_asn1_copy := nil;
  EVP_PKEY_asn1_free := nil;
  EVP_PKEY_asn1_set_public := nil;
  EVP_PKEY_asn1_set_private := nil;
  EVP_PKEY_asn1_set_param := nil;
  EVP_PKEY_asn1_set_free := nil;
  EVP_PKEY_asn1_set_ctrl := nil;
  EVP_PKEY_asn1_set_item := nil;
  EVP_PKEY_asn1_set_siginf := nil; {introduced 1.1.0}
  EVP_PKEY_asn1_set_check := nil; {introduced 1.1.0}
  EVP_PKEY_asn1_set_public_check := nil; {introduced 1.1.0}
  EVP_PKEY_asn1_set_param_check := nil; {introduced 1.1.0}
  EVP_PKEY_asn1_set_set_priv_key := nil; {introduced 1.1.0}
  EVP_PKEY_asn1_set_set_pub_key := nil; {introduced 1.1.0}
  EVP_PKEY_asn1_set_get_priv_key := nil; {introduced 1.1.0}
  EVP_PKEY_asn1_set_get_pub_key := nil; {introduced 1.1.0}
  EVP_PKEY_asn1_set_security_bits := nil; {introduced 1.1.0}
  EVP_PKEY_meth_find := nil;
  EVP_PKEY_meth_new := nil;
  EVP_PKEY_meth_get0_info := nil;
  EVP_PKEY_meth_copy := nil;
  EVP_PKEY_meth_free := nil;
  EVP_PKEY_meth_add0 := nil;
  EVP_PKEY_meth_remove := nil; {introduced 1.1.0}
  EVP_PKEY_meth_get_count := nil; {introduced 1.1.0}
  EVP_PKEY_meth_get0 := nil; {introduced 1.1.0}
  EVP_PKEY_CTX_new := nil;
  EVP_PKEY_CTX_new_id := nil;
  EVP_PKEY_CTX_dup := nil;
  EVP_PKEY_CTX_free := nil;
  EVP_PKEY_CTX_ctrl := nil;
  EVP_PKEY_CTX_ctrl_str := nil;
  EVP_PKEY_CTX_ctrl_uint64 := nil; {introduced 1.1.0}
  EVP_PKEY_CTX_str2ctrl := nil; {introduced 1.1.0}
  EVP_PKEY_CTX_hex2ctrl := nil; {introduced 1.1.0}
  EVP_PKEY_CTX_md := nil; {introduced 1.1.0}
  EVP_PKEY_CTX_get_operation := nil;
  EVP_PKEY_CTX_set0_keygen_info := nil;
  EVP_PKEY_new_mac_key := nil;
  EVP_PKEY_new_raw_private_key := nil; {introduced 1.1.0}
  EVP_PKEY_new_raw_public_key := nil; {introduced 1.1.0}
  EVP_PKEY_get_raw_private_key := nil; {introduced 1.1.0}
  EVP_PKEY_get_raw_public_key := nil; {introduced 1.1.0}
  EVP_PKEY_new_CMAC_key := nil; {introduced 1.1.0}
  EVP_PKEY_CTX_set_data := nil;
  EVP_PKEY_CTX_get_data := nil;
  EVP_PKEY_CTX_get0_pkey := nil;
  EVP_PKEY_CTX_get0_peerkey := nil;
  EVP_PKEY_CTX_set_app_data := nil;
  EVP_PKEY_CTX_get_app_data := nil;
  EVP_PKEY_sign_init := nil;
  EVP_PKEY_sign := nil;
  EVP_PKEY_verify_init := nil;
  EVP_PKEY_verify := nil;
  EVP_PKEY_verify_recover_init := nil;
  EVP_PKEY_verify_recover := nil;
  EVP_PKEY_encrypt_init := nil;
  EVP_PKEY_encrypt := nil;
  EVP_PKEY_decrypt_init := nil;
  EVP_PKEY_decrypt := nil;
  EVP_PKEY_derive_init := nil;
  EVP_PKEY_derive_set_peer := nil;
  EVP_PKEY_derive := nil;
  EVP_PKEY_paramgen_init := nil;
  EVP_PKEY_paramgen := nil;
  EVP_PKEY_keygen_init := nil;
  EVP_PKEY_keygen := nil;
  EVP_PKEY_check := nil; {introduced 1.1.0}
  EVP_PKEY_public_check := nil; {introduced 1.1.0}
  EVP_PKEY_param_check := nil; {introduced 1.1.0}
  EVP_PKEY_CTX_set_cb := nil;
  EVP_PKEY_CTX_get_cb := nil;
  EVP_PKEY_CTX_get_keygen_info := nil;
  EVP_PKEY_meth_set_init := nil;
  EVP_PKEY_meth_set_copy := nil;
  EVP_PKEY_meth_set_cleanup := nil;
  EVP_PKEY_meth_set_paramgen := nil;
  EVP_PKEY_meth_set_keygen := nil;
  EVP_PKEY_meth_set_sign := nil;
  EVP_PKEY_meth_set_verify := nil;
  EVP_PKEY_meth_set_verify_recover := nil;
  EVP_PKEY_meth_set_signctx := nil;
  EVP_PKEY_meth_set_verifyctx := nil;
  EVP_PKEY_meth_set_encrypt := nil;
  EVP_PKEY_meth_set_decrypt := nil;
  EVP_PKEY_meth_set_derive := nil;
  EVP_PKEY_meth_set_ctrl := nil;
  EVP_PKEY_meth_set_digestsign := nil; {introduced 1.1.0}
  EVP_PKEY_meth_set_digestverify := nil; {introduced 1.1.0}
  EVP_PKEY_meth_set_check := nil; {introduced 1.1.0}
  EVP_PKEY_meth_set_public_check := nil; {introduced 1.1.0}
  EVP_PKEY_meth_set_param_check := nil; {introduced 1.1.0}
  EVP_PKEY_meth_set_digest_custom := nil; {introduced 1.1.0}
  EVP_PKEY_meth_get_init := nil;
  EVP_PKEY_meth_get_copy := nil;
  EVP_PKEY_meth_get_cleanup := nil;
  EVP_PKEY_meth_get_paramgen := nil;
  EVP_PKEY_meth_get_keygen := nil;
  EVP_PKEY_meth_get_sign := nil;
  EVP_PKEY_meth_get_verify := nil;
  EVP_PKEY_meth_get_verify_recover := nil;
  EVP_PKEY_meth_get_signctx := nil;
  EVP_PKEY_meth_get_verifyctx := nil;
  EVP_PKEY_meth_get_encrypt := nil;
  EVP_PKEY_meth_get_decrypt := nil;
  EVP_PKEY_meth_get_derive := nil;
  EVP_PKEY_meth_get_ctrl := nil;
  EVP_PKEY_meth_get_digestsign := nil; {introduced 1.1.0}
  EVP_PKEY_meth_get_digestverify := nil; {introduced 1.1.0}
  EVP_PKEY_meth_get_check := nil; {introduced 1.1.0}
  EVP_PKEY_meth_get_public_check := nil; {introduced 1.1.0}
  EVP_PKEY_meth_get_param_check := nil; {introduced 1.1.0}
  EVP_PKEY_meth_get_digest_custom := nil; {introduced 1.1.0}
  EVP_add_alg_module := nil;
  OpenSSL_add_all_ciphers := nil; {removed 1.1.0}
  OpenSSL_add_all_digests := nil; {removed 1.1.0}
  EVP_cleanup := nil; {removed 1.1.0}
  //* MAC Stuff */
  EVP_MAC_fetch := nil;
  EVP_MAC_up_ref := nil;
  EVP_MAC_free := nil;
  EVP_MAC_is_a := nil;
  EVP_MAC_get0_name := nil;
  EVP_MAC_names_do_all := nil;
  EVP_MAC_get0_description := nil;
  EVP_MAC_get0_provider := nil;
  EVP_MAC_get_params := nil;
  EVP_MAC_CTX_new := nil;
  EVP_MAC_CTX_free := nil;
  EVP_MAC_CTX_dup := nil;

  EVP_MAC_CTX_get_block_size := nil;
  EVP_MAC_init := nil;
end;
  {$ENDIF}
{$ELSE}
function EVP_PKEY_assign_RSA(pkey: PEVP_PKEY; rsa: Pointer): TIdC_INT;
begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_RSA, rsa);
end;

//#  define EVP_PKEY_assign_DSA(pkey,dsa) EVP_PKEY_assign((pkey),EVP_PKEY_DSA, (char *)(dsa))
function EVP_PKEY_assign_DSA(pkey: PEVP_PKEY; dsa: Pointer): TIdC_INT;
begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_DSA, dsa);
end;

//#  define EVP_PKEY_assign_DH(pkey,dh) EVP_PKEY_assign((pkey),EVP_PKEY_DH, (char *)(dh))
function EVP_PKEY_assign_DH(pkey: PEVP_PKEY; dh: Pointer): TIdC_INT;
begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_DH, dh);
end;

//#  define EVP_PKEY_assign_EC_KEY(pkey,eckey) EVP_PKEY_assign((pkey),EVP_PKEY_EC, (char *)(eckey))
function EVP_PKEY_assign_EC_KEY(pkey: PEVP_PKEY; eckey: Pointer): TIdC_INT;
begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_EC, eckey);
end;

//#  define EVP_PKEY_assign_SIPHASH(pkey,shkey) EVP_PKEY_assign((pkey),EVP_PKEY_SIPHASH, (char *)(shkey))
function EVP_PKEY_assign_SIPHASH(pkey: PEVP_PKEY; shkey: Pointer): TIdC_INT;
begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_SIPHASH, shkey);
end;

//#  define EVP_PKEY_assign_POLY1305(pkey,polykey) EVP_PKEY_assign((pkey),EVP_PKEY_POLY1305, (char *)(polykey))
function EVP_PKEY_assign_POLY1305(pkey: PEVP_PKEY; polykey: Pointer): TIdC_INT;
begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_POLY1305, polykey);
end;

procedure OpenSSL_add_all_ciphers;
begin
  OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS, nil);  //PALOFF - Functions called as procedures
end;

procedure OpenSSL_add_all_digests;
begin
  OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, Nil); //PALOFF - Functions called as procedures
end;

procedure EVP_cleanup;
begin  //FI:W519
end;  //PALOFF  - Empty begin/end-blocks

procedure BIO_set_md(v1: PBIO; const md: PEVP_MD);
begin
  {define BIO_set_md(b,md)  BIO_ctrl(b,BIO_C_SET_MD,0,(char *)(md))}
  BIO_ctrl(v1,BIO_C_SET_MD,0,PIdAnsiChar(md));  //PALOFF - bad pointer usage [md : PEVP_MD cast to PAnsiChar]
end;

  {$IFNDEF _FIXINSIGHT_}
 {$I TaurusTLSNoRetValOff.inc}
{$IFNDEF OPENSSL_NO_MD2}
function EVP_md2: PEVP_MD;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ROSUnsupported);
end;
{$ENDIF}

{$IFNDEF OPENSSL_NO_MD4}
function EVP_md4: PEVP_MD;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ROSUnsupported);
end;
{$ENDIF}

{$IFNDEF OPENSSL_NO_MD5}
function EVP_md5: PEVP_MD;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ROSUnsupported);
end;
{$ENDIF}
 {$I TaurusTLSNoRetValOn.inc}
 {$ENDIF}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
