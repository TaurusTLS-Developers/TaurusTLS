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

unit TaurusTLSHeaders_self_test;

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
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // OSSL_SELF_TEST_set_callback_cb_cb = function(arg1: Possl_param_st; arg2: Pointer): TIdC_INT; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  OSSL_SELF_TEST_PHASE_NONE = 'None';
  OSSL_SELF_TEST_PHASE_START = 'Start';
  OSSL_SELF_TEST_PHASE_CORRUPT = 'Corrupt';
  OSSL_SELF_TEST_PHASE_PASS = 'Pass';
  OSSL_SELF_TEST_PHASE_FAIL = 'Fail';
  OSSL_SELF_TEST_TYPE_NONE = 'None';
  OSSL_SELF_TEST_TYPE_MODULE_INTEGRITY = 'Module_Integrity';
  OSSL_SELF_TEST_TYPE_INSTALL_INTEGRITY = 'Install_Integrity';
  OSSL_SELF_TEST_TYPE_CRNG = 'Continuous_RNG_Test';
  OSSL_SELF_TEST_TYPE_PCT = 'Conditional_PCT';
  OSSL_SELF_TEST_TYPE_PCT_KAT = 'Conditional_KAT';
  OSSL_SELF_TEST_TYPE_PCT_IMPORT = 'Import_PCT';
  OSSL_SELF_TEST_TYPE_KAT_INTEGRITY = 'KAT_Integrity';
  OSSL_SELF_TEST_TYPE_KAT_CIPHER = 'KAT_Cipher';
  OSSL_SELF_TEST_TYPE_KAT_ASYM_CIPHER = 'KAT_AsymmetricCipher';
  OSSL_SELF_TEST_TYPE_KAT_ASYM_KEYGEN = 'KAT_AsymmetricKeyGeneration';
  OSSL_SELF_TEST_TYPE_KAT_KEM = 'KAT_KEM';
  OSSL_SELF_TEST_TYPE_KAT_DIGEST = 'KAT_Digest';
  OSSL_SELF_TEST_TYPE_KAT_SIGNATURE = 'KAT_Signature';
  OSSL_SELF_TEST_TYPE_PCT_SIGNATURE = 'PCT_Signature';
  OSSL_SELF_TEST_TYPE_KAT_KDF = 'KAT_KDF';
  OSSL_SELF_TEST_TYPE_KAT_KA = 'KAT_KA';
  OSSL_SELF_TEST_TYPE_DRBG = 'DRBG';
  OSSL_SELF_TEST_DESC_NONE = 'None';
  OSSL_SELF_TEST_DESC_INTEGRITY_HMAC = 'HMAC';
  OSSL_SELF_TEST_DESC_PCT_RSA = 'RSA';
  OSSL_SELF_TEST_DESC_PCT_RSA_PKCS1 = 'RSA';
  OSSL_SELF_TEST_DESC_PCT_ECDSA = 'ECDSA';
  OSSL_SELF_TEST_DESC_PCT_EDDSA = 'EDDSA';
  OSSL_SELF_TEST_DESC_PCT_DH = 'DH';
  OSSL_SELF_TEST_DESC_PCT_DSA = 'DSA';
  OSSL_SELF_TEST_DESC_PCT_ML_DSA = 'ML-DSA';
  OSSL_SELF_TEST_DESC_PCT_ML_KEM = 'ML-KEM';
  OSSL_SELF_TEST_DESC_PCT_SLH_DSA = 'SLH-DSA';
  OSSL_SELF_TEST_DESC_CIPHER_AES_GCM = 'AES_GCM';
  OSSL_SELF_TEST_DESC_CIPHER_AES_ECB = 'AES_ECB_Decrypt';
  OSSL_SELF_TEST_DESC_CIPHER_TDES = 'TDES';
  OSSL_SELF_TEST_DESC_ASYM_RSA_ENC = 'RSA_Encrypt';
  OSSL_SELF_TEST_DESC_ASYM_RSA_DEC = 'RSA_Decrypt';
  OSSL_SELF_TEST_DESC_MD_SHA1 = 'SHA1';
  OSSL_SELF_TEST_DESC_MD_SHA2 = 'SHA2';
  OSSL_SELF_TEST_DESC_MD_SHA3 = 'SHA3';
  OSSL_SELF_TEST_DESC_SIGN_DSA = 'DSA';
  OSSL_SELF_TEST_DESC_SIGN_RSA = 'RSA';
  OSSL_SELF_TEST_DESC_SIGN_ECDSA = 'ECDSA';
  OSSL_SELF_TEST_DESC_SIGN_DetECDSA = 'DetECDSA';
  OSSL_SELF_TEST_DESC_SIGN_EDDSA = 'EDDSA';
  OSSL_SELF_TEST_DESC_SIGN_LMS = 'LMS';
  OSSL_SELF_TEST_DESC_SIGN_ML_DSA = 'ML-DSA';
  OSSL_SELF_TEST_DESC_SIGN_SLH_DSA = 'SLH-DSA';
  OSSL_SELF_TEST_DESC_KEM = 'KEM';
  OSSL_SELF_TEST_DESC_DRBG_CTR = 'CTR';
  OSSL_SELF_TEST_DESC_DRBG_HASH = 'HASH';
  OSSL_SELF_TEST_DESC_DRBG_HMAC = 'HMAC';
  OSSL_SELF_TEST_DESC_KA_DH = 'DH';
  OSSL_SELF_TEST_DESC_KA_ECDH = 'ECDH';
  OSSL_SELF_TEST_DESC_KDF_HKDF = 'HKDF';
  OSSL_SELF_TEST_DESC_KDF_SSKDF = 'SSKDF';
  OSSL_SELF_TEST_DESC_KDF_X963KDF = 'X963KDF';
  OSSL_SELF_TEST_DESC_KDF_X942KDF = 'X942KDF';
  OSSL_SELF_TEST_DESC_KDF_PBKDF2 = 'PBKDF2';
  OSSL_SELF_TEST_DESC_KDF_SSHKDF = 'SSHKDF';
  OSSL_SELF_TEST_DESC_KDF_TLS12_PRF = 'TLS12_PRF';
  OSSL_SELF_TEST_DESC_KDF_KBKDF = 'KBKDF';
  OSSL_SELF_TEST_DESC_KDF_KBKDF_KMAC = 'KBKDF_KMAC';
  OSSL_SELF_TEST_DESC_KDF_TLS13_EXTRACT = 'TLS13_KDF_EXTRACT';
  OSSL_SELF_TEST_DESC_KDF_TLS13_EXPAND = 'TLS13_KDF_EXPAND';
  OSSL_SELF_TEST_DESC_RNG = 'RNG';
  OSSL_SELF_TEST_DESC_KEYGEN_ML_DSA = 'ML-DSA';
  OSSL_SELF_TEST_DESC_KEYGEN_ML_KEM = 'ML-KEM';
  OSSL_SELF_TEST_DESC_KEYGEN_SLH_DSA = 'SLH-DSA';
  OSSL_SELF_TEST_DESC_ENCAP_KEM = 'KEM_Encap';
  OSSL_SELF_TEST_DESC_DECAP_KEM = 'KEM_Decap';
  OSSL_SELF_TEST_DESC_DECAP_KEM_FAIL = 'KEM_Decap_Reject';

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  OSSL_SELF_TEST_set_callback: function(libctx: POSSL_LIB_CTX; cb: TOSSL_SELF_TEST_set_callback_cb_cb; cbarg: Pointer): void; cdecl = nil;
  {$EXTERNALSYM OSSL_SELF_TEST_set_callback}

  OSSL_SELF_TEST_get_callback: function(libctx: POSSL_LIB_CTX; cb: PPOSSL_CALLBACK; cbarg: PPointer): void; cdecl = nil;
  {$EXTERNALSYM OSSL_SELF_TEST_get_callback}

  OSSL_SELF_TEST_new: function(cb: TOSSL_SELF_TEST_set_callback_cb_cb; cbarg: Pointer): POSSL_SELF_TEST; cdecl = nil;
  {$EXTERNALSYM OSSL_SELF_TEST_new}

  OSSL_SELF_TEST_free: function(st: POSSL_SELF_TEST): void; cdecl = nil;
  {$EXTERNALSYM OSSL_SELF_TEST_free}

  OSSL_SELF_TEST_onbegin: function(st: POSSL_SELF_TEST; _type: PIdAnsiChar; desc: PIdAnsiChar): void; cdecl = nil;
  {$EXTERNALSYM OSSL_SELF_TEST_onbegin}

  OSSL_SELF_TEST_oncorrupt_byte: function(st: POSSL_SELF_TEST; bytes: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_SELF_TEST_oncorrupt_byte}

  OSSL_SELF_TEST_onend: function(st: POSSL_SELF_TEST; ret: TIdC_INT): void; cdecl = nil;
  {$EXTERNALSYM OSSL_SELF_TEST_onend}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function OSSL_SELF_TEST_set_callback(libctx: POSSL_LIB_CTX; cb: TOSSL_SELF_TEST_set_callback_cb_cb; cbarg: Pointer): void; cdecl;
function OSSL_SELF_TEST_get_callback(libctx: POSSL_LIB_CTX; cb: PPOSSL_CALLBACK; cbarg: PPointer): void; cdecl;
function OSSL_SELF_TEST_new(cb: TOSSL_SELF_TEST_set_callback_cb_cb; cbarg: Pointer): POSSL_SELF_TEST; cdecl;
function OSSL_SELF_TEST_free(st: POSSL_SELF_TEST): void; cdecl;
function OSSL_SELF_TEST_onbegin(st: POSSL_SELF_TEST; _type: PIdAnsiChar; desc: PIdAnsiChar): void; cdecl;
function OSSL_SELF_TEST_oncorrupt_byte(st: POSSL_SELF_TEST; bytes: PIdAnsiChar): TIdC_INT; cdecl;
function OSSL_SELF_TEST_onend(st: POSSL_SELF_TEST; ret: TIdC_INT): void; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

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

function OSSL_SELF_TEST_set_callback(libctx: POSSL_LIB_CTX; cb: TOSSL_SELF_TEST_set_callback_cb_cb; cbarg: Pointer): void; cdecl external CLibCrypto name 'OSSL_SELF_TEST_set_callback';
function OSSL_SELF_TEST_get_callback(libctx: POSSL_LIB_CTX; cb: PPOSSL_CALLBACK; cbarg: PPointer): void; cdecl external CLibCrypto name 'OSSL_SELF_TEST_get_callback';
function OSSL_SELF_TEST_new(cb: TOSSL_SELF_TEST_set_callback_cb_cb; cbarg: Pointer): POSSL_SELF_TEST; cdecl external CLibCrypto name 'OSSL_SELF_TEST_new';
function OSSL_SELF_TEST_free(st: POSSL_SELF_TEST): void; cdecl external CLibCrypto name 'OSSL_SELF_TEST_free';
function OSSL_SELF_TEST_onbegin(st: POSSL_SELF_TEST; _type: PIdAnsiChar; desc: PIdAnsiChar): void; cdecl external CLibCrypto name 'OSSL_SELF_TEST_onbegin';
function OSSL_SELF_TEST_oncorrupt_byte(st: POSSL_SELF_TEST; bytes: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_SELF_TEST_oncorrupt_byte';
function OSSL_SELF_TEST_onend(st: POSSL_SELF_TEST; ret: TIdC_INT): void; cdecl external CLibCrypto name 'OSSL_SELF_TEST_onend';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  OSSL_SELF_TEST_set_callback_procname = 'OSSL_SELF_TEST_set_callback';
  OSSL_SELF_TEST_set_callback_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_SELF_TEST_get_callback_procname = 'OSSL_SELF_TEST_get_callback';
  OSSL_SELF_TEST_get_callback_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_SELF_TEST_new_procname = 'OSSL_SELF_TEST_new';
  OSSL_SELF_TEST_new_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_SELF_TEST_free_procname = 'OSSL_SELF_TEST_free';
  OSSL_SELF_TEST_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_SELF_TEST_onbegin_procname = 'OSSL_SELF_TEST_onbegin';
  OSSL_SELF_TEST_onbegin_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_SELF_TEST_oncorrupt_byte_procname = 'OSSL_SELF_TEST_oncorrupt_byte';
  OSSL_SELF_TEST_oncorrupt_byte_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_SELF_TEST_onend_procname = 'OSSL_SELF_TEST_onend';
  OSSL_SELF_TEST_onend_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_OSSL_SELF_TEST_set_callback(libctx: POSSL_LIB_CTX; cb: TOSSL_SELF_TEST_set_callback_cb_cb; cbarg: Pointer): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_SELF_TEST_set_callback_procname);
end;

function ERR_OSSL_SELF_TEST_get_callback(libctx: POSSL_LIB_CTX; cb: PPOSSL_CALLBACK; cbarg: PPointer): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_SELF_TEST_get_callback_procname);
end;

function ERR_OSSL_SELF_TEST_new(cb: TOSSL_SELF_TEST_set_callback_cb_cb; cbarg: Pointer): POSSL_SELF_TEST; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_SELF_TEST_new_procname);
end;

function ERR_OSSL_SELF_TEST_free(st: POSSL_SELF_TEST): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_SELF_TEST_free_procname);
end;

function ERR_OSSL_SELF_TEST_onbegin(st: POSSL_SELF_TEST; _type: PIdAnsiChar; desc: PIdAnsiChar): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_SELF_TEST_onbegin_procname);
end;

function ERR_OSSL_SELF_TEST_oncorrupt_byte(st: POSSL_SELF_TEST; bytes: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_SELF_TEST_oncorrupt_byte_procname);
end;

function ERR_OSSL_SELF_TEST_onend(st: POSSL_SELF_TEST; ret: TIdC_INT): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_SELF_TEST_onend_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  OSSL_SELF_TEST_set_callback := LoadLibFunction(ADllHandle, OSSL_SELF_TEST_set_callback_procname);
  FuncLoadError := not assigned(OSSL_SELF_TEST_set_callback);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_SELF_TEST_set_callback_allownil)}
    OSSL_SELF_TEST_set_callback := ERR_OSSL_SELF_TEST_set_callback;
    {$ifend}
    {$if declared(OSSL_SELF_TEST_set_callback_introduced)}
    if LibVersion < OSSL_SELF_TEST_set_callback_introduced then
    begin
      {$if declared(FC_OSSL_SELF_TEST_set_callback)}
      OSSL_SELF_TEST_set_callback := FC_OSSL_SELF_TEST_set_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_SELF_TEST_set_callback_removed)}
    if OSSL_SELF_TEST_set_callback_removed <= LibVersion then
    begin
      {$if declared(_OSSL_SELF_TEST_set_callback)}
      OSSL_SELF_TEST_set_callback := _OSSL_SELF_TEST_set_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_SELF_TEST_set_callback_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_SELF_TEST_set_callback');
    {$ifend}
  end;
  
  OSSL_SELF_TEST_get_callback := LoadLibFunction(ADllHandle, OSSL_SELF_TEST_get_callback_procname);
  FuncLoadError := not assigned(OSSL_SELF_TEST_get_callback);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_SELF_TEST_get_callback_allownil)}
    OSSL_SELF_TEST_get_callback := ERR_OSSL_SELF_TEST_get_callback;
    {$ifend}
    {$if declared(OSSL_SELF_TEST_get_callback_introduced)}
    if LibVersion < OSSL_SELF_TEST_get_callback_introduced then
    begin
      {$if declared(FC_OSSL_SELF_TEST_get_callback)}
      OSSL_SELF_TEST_get_callback := FC_OSSL_SELF_TEST_get_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_SELF_TEST_get_callback_removed)}
    if OSSL_SELF_TEST_get_callback_removed <= LibVersion then
    begin
      {$if declared(_OSSL_SELF_TEST_get_callback)}
      OSSL_SELF_TEST_get_callback := _OSSL_SELF_TEST_get_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_SELF_TEST_get_callback_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_SELF_TEST_get_callback');
    {$ifend}
  end;
  
  OSSL_SELF_TEST_new := LoadLibFunction(ADllHandle, OSSL_SELF_TEST_new_procname);
  FuncLoadError := not assigned(OSSL_SELF_TEST_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_SELF_TEST_new_allownil)}
    OSSL_SELF_TEST_new := ERR_OSSL_SELF_TEST_new;
    {$ifend}
    {$if declared(OSSL_SELF_TEST_new_introduced)}
    if LibVersion < OSSL_SELF_TEST_new_introduced then
    begin
      {$if declared(FC_OSSL_SELF_TEST_new)}
      OSSL_SELF_TEST_new := FC_OSSL_SELF_TEST_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_SELF_TEST_new_removed)}
    if OSSL_SELF_TEST_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_SELF_TEST_new)}
      OSSL_SELF_TEST_new := _OSSL_SELF_TEST_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_SELF_TEST_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_SELF_TEST_new');
    {$ifend}
  end;
  
  OSSL_SELF_TEST_free := LoadLibFunction(ADllHandle, OSSL_SELF_TEST_free_procname);
  FuncLoadError := not assigned(OSSL_SELF_TEST_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_SELF_TEST_free_allownil)}
    OSSL_SELF_TEST_free := ERR_OSSL_SELF_TEST_free;
    {$ifend}
    {$if declared(OSSL_SELF_TEST_free_introduced)}
    if LibVersion < OSSL_SELF_TEST_free_introduced then
    begin
      {$if declared(FC_OSSL_SELF_TEST_free)}
      OSSL_SELF_TEST_free := FC_OSSL_SELF_TEST_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_SELF_TEST_free_removed)}
    if OSSL_SELF_TEST_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_SELF_TEST_free)}
      OSSL_SELF_TEST_free := _OSSL_SELF_TEST_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_SELF_TEST_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_SELF_TEST_free');
    {$ifend}
  end;
  
  OSSL_SELF_TEST_onbegin := LoadLibFunction(ADllHandle, OSSL_SELF_TEST_onbegin_procname);
  FuncLoadError := not assigned(OSSL_SELF_TEST_onbegin);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_SELF_TEST_onbegin_allownil)}
    OSSL_SELF_TEST_onbegin := ERR_OSSL_SELF_TEST_onbegin;
    {$ifend}
    {$if declared(OSSL_SELF_TEST_onbegin_introduced)}
    if LibVersion < OSSL_SELF_TEST_onbegin_introduced then
    begin
      {$if declared(FC_OSSL_SELF_TEST_onbegin)}
      OSSL_SELF_TEST_onbegin := FC_OSSL_SELF_TEST_onbegin;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_SELF_TEST_onbegin_removed)}
    if OSSL_SELF_TEST_onbegin_removed <= LibVersion then
    begin
      {$if declared(_OSSL_SELF_TEST_onbegin)}
      OSSL_SELF_TEST_onbegin := _OSSL_SELF_TEST_onbegin;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_SELF_TEST_onbegin_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_SELF_TEST_onbegin');
    {$ifend}
  end;
  
  OSSL_SELF_TEST_oncorrupt_byte := LoadLibFunction(ADllHandle, OSSL_SELF_TEST_oncorrupt_byte_procname);
  FuncLoadError := not assigned(OSSL_SELF_TEST_oncorrupt_byte);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_SELF_TEST_oncorrupt_byte_allownil)}
    OSSL_SELF_TEST_oncorrupt_byte := ERR_OSSL_SELF_TEST_oncorrupt_byte;
    {$ifend}
    {$if declared(OSSL_SELF_TEST_oncorrupt_byte_introduced)}
    if LibVersion < OSSL_SELF_TEST_oncorrupt_byte_introduced then
    begin
      {$if declared(FC_OSSL_SELF_TEST_oncorrupt_byte)}
      OSSL_SELF_TEST_oncorrupt_byte := FC_OSSL_SELF_TEST_oncorrupt_byte;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_SELF_TEST_oncorrupt_byte_removed)}
    if OSSL_SELF_TEST_oncorrupt_byte_removed <= LibVersion then
    begin
      {$if declared(_OSSL_SELF_TEST_oncorrupt_byte)}
      OSSL_SELF_TEST_oncorrupt_byte := _OSSL_SELF_TEST_oncorrupt_byte;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_SELF_TEST_oncorrupt_byte_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_SELF_TEST_oncorrupt_byte');
    {$ifend}
  end;
  
  OSSL_SELF_TEST_onend := LoadLibFunction(ADllHandle, OSSL_SELF_TEST_onend_procname);
  FuncLoadError := not assigned(OSSL_SELF_TEST_onend);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_SELF_TEST_onend_allownil)}
    OSSL_SELF_TEST_onend := ERR_OSSL_SELF_TEST_onend;
    {$ifend}
    {$if declared(OSSL_SELF_TEST_onend_introduced)}
    if LibVersion < OSSL_SELF_TEST_onend_introduced then
    begin
      {$if declared(FC_OSSL_SELF_TEST_onend)}
      OSSL_SELF_TEST_onend := FC_OSSL_SELF_TEST_onend;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_SELF_TEST_onend_removed)}
    if OSSL_SELF_TEST_onend_removed <= LibVersion then
    begin
      {$if declared(_OSSL_SELF_TEST_onend)}
      OSSL_SELF_TEST_onend := _OSSL_SELF_TEST_onend;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_SELF_TEST_onend_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_SELF_TEST_onend');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  OSSL_SELF_TEST_set_callback := nil;
  OSSL_SELF_TEST_get_callback := nil;
  OSSL_SELF_TEST_new := nil;
  OSSL_SELF_TEST_free := nil;
  OSSL_SELF_TEST_onbegin := nil;
  OSSL_SELF_TEST_oncorrupt_byte := nil;
  OSSL_SELF_TEST_onend := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.