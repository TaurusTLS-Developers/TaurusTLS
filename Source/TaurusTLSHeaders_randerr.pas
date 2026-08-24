/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_randerr.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_randerr.h2pas
     and this file regenerated. TaurusTLSHeaders_randerr.h2pas is distributed with the full Indy
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
unit TaurusTLSHeaders_randerr;

interface

// Headers for OpenSSL 1.1.1
// randerr.h


uses
  IdCTypes,
  IdGlobal
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  , TaurusTLSConsts
  {$ENDIF};

const
  (*
   * RAND function codes.
   *)
  {$EXTERNALSYM RAND_F_DRBG_BYTES}
  RAND_F_DRBG_BYTES = 101;
  {$EXTERNALSYM RAND_F_DRBG_GET_ENTROPY}
  RAND_F_DRBG_GET_ENTROPY = 105;
  {$EXTERNALSYM RAND_F_DRBG_SETUP}
  RAND_F_DRBG_SETUP = 117;
  {$EXTERNALSYM RAND_F_GET_ENTROPY}
  RAND_F_GET_ENTROPY = 106;
  {$EXTERNALSYM RAND_F_RAND_BYTES}
  RAND_F_RAND_BYTES = 100;
  {$EXTERNALSYM RAND_F_RAND_DRBG_ENABLE_LOCKING}
  RAND_F_RAND_DRBG_ENABLE_LOCKING = 119;
  {$EXTERNALSYM RAND_F_RAND_DRBG_GENERATE}
  RAND_F_RAND_DRBG_GENERATE = 107;
  {$EXTERNALSYM RAND_F_RAND_DRBG_GET_ENTROPY}
  RAND_F_RAND_DRBG_GET_ENTROPY = 120;
  {$EXTERNALSYM RAND_F_RAND_DRBG_GET_NONCE}
  RAND_F_RAND_DRBG_GET_NONCE = 123;
  {$EXTERNALSYM RAND_F_RAND_DRBG_INSTANTIATE}
  RAND_F_RAND_DRBG_INSTANTIATE = 108;
  {$EXTERNALSYM RAND_F_RAND_DRBG_NEW}
  RAND_F_RAND_DRBG_NEW = 109;
  {$EXTERNALSYM RAND_F_RAND_DRBG_RESEED}
  RAND_F_RAND_DRBG_RESEED = 110;
  {$EXTERNALSYM RAND_F_RAND_DRBG_RESTART}
  RAND_F_RAND_DRBG_RESTART = 102;
  {$EXTERNALSYM RAND_F_RAND_DRBG_SET}
  RAND_F_RAND_DRBG_SET = 104;
  {$EXTERNALSYM RAND_F_RAND_DRBG_SET_DEFAULTS}
  RAND_F_RAND_DRBG_SET_DEFAULTS = 121;
  {$EXTERNALSYM RAND_F_RAND_DRBG_UNINSTANTIATE}
  RAND_F_RAND_DRBG_UNINSTANTIATE = 118;
  {$EXTERNALSYM RAND_F_RAND_LOAD_FILE}
  RAND_F_RAND_LOAD_FILE = 111;
  {$EXTERNALSYM RAND_F_RAND_POOL_ACQUIRE_ENTROPY}
  RAND_F_RAND_POOL_ACQUIRE_ENTROPY = 122;
  {$EXTERNALSYM RAND_F_RAND_POOL_ADD}
  RAND_F_RAND_POOL_ADD = 103;
  {$EXTERNALSYM RAND_F_RAND_POOL_ADD_BEGIN}
  RAND_F_RAND_POOL_ADD_BEGIN = 113;
  {$EXTERNALSYM RAND_F_RAND_POOL_ADD_END}
  RAND_F_RAND_POOL_ADD_END = 114;
  {$EXTERNALSYM RAND_F_RAND_POOL_ATTACH}
  RAND_F_RAND_POOL_ATTACH = 124;
  {$EXTERNALSYM RAND_F_RAND_POOL_BYTES_NEEDED}
  RAND_F_RAND_POOL_BYTES_NEEDED = 115;
  {$EXTERNALSYM RAND_F_RAND_POOL_GROW}
  RAND_F_RAND_POOL_GROW = 125;
  {$EXTERNALSYM RAND_F_RAND_POOL_NEW}
  RAND_F_RAND_POOL_NEW = 116;
  {$EXTERNALSYM RAND_F_RAND_WRITE_FILE}
  RAND_F_RAND_WRITE_FILE = 112;

  (*
   * RAND reason codes.
   *)
  {$EXTERNALSYM RAND_R_ADDITIONAL_INPUT_TOO_LONG}
  RAND_R_ADDITIONAL_INPUT_TOO_LONG = 102;
  {$EXTERNALSYM RAND_R_ALREADY_INSTANTIATED}
  RAND_R_ALREADY_INSTANTIATED = 103;
  {$EXTERNALSYM RAND_R_ARGUMENT_OUT_OF_RANGE}
  RAND_R_ARGUMENT_OUT_OF_RANGE = 105;
  {$EXTERNALSYM RAND_R_CANNOT_OPEN_FILE}
  RAND_R_CANNOT_OPEN_FILE = 121;
  {$EXTERNALSYM RAND_R_DRBG_ALREADY_INITIALIZED}
  RAND_R_DRBG_ALREADY_INITIALIZED = 129;
  {$EXTERNALSYM RAND_R_DRBG_NOT_INITIALISED}
  RAND_R_DRBG_NOT_INITIALISED = 104;
  {$EXTERNALSYM RAND_R_ENTROPY_INPUT_TOO_LONG}
  RAND_R_ENTROPY_INPUT_TOO_LONG = 106;
  {$EXTERNALSYM RAND_R_ENTROPY_OUT_OF_RANGE}
  RAND_R_ENTROPY_OUT_OF_RANGE = 124;
  {$EXTERNALSYM RAND_R_ERROR_ENTROPY_POOL_WAS_IGNORED}
  RAND_R_ERROR_ENTROPY_POOL_WAS_IGNORED = 127;
  {$EXTERNALSYM RAND_R_ERROR_INITIALISING_DRBG}
  RAND_R_ERROR_INITIALISING_DRBG = 107;
  {$EXTERNALSYM RAND_R_ERROR_INSTANTIATING_DRBG}
  RAND_R_ERROR_INSTANTIATING_DRBG = 108;
  {$EXTERNALSYM RAND_R_ERROR_RETRIEVING_ADDITIONAL_INPUT}
  RAND_R_ERROR_RETRIEVING_ADDITIONAL_INPUT = 109;
  {$EXTERNALSYM RAND_R_ERROR_RETRIEVING_ENTROPY}
  RAND_R_ERROR_RETRIEVING_ENTROPY = 110;
  {$EXTERNALSYM RAND_R_ERROR_RETRIEVING_NONCE}
  RAND_R_ERROR_RETRIEVING_NONCE = 111;
  {$EXTERNALSYM RAND_R_FAILED_TO_CREATE_LOCK}
  RAND_R_FAILED_TO_CREATE_LOCK = 126;
  {$EXTERNALSYM RAND_R_FUNC_NOT_IMPLEMENTED}
  RAND_R_FUNC_NOT_IMPLEMENTED = 101;
  {$EXTERNALSYM RAND_R_FWRITE_ERROR}
  RAND_R_FWRITE_ERROR = 123;
  {$EXTERNALSYM RAND_R_GENERATE_ERROR}
  RAND_R_GENERATE_ERROR = 112;
  {$EXTERNALSYM RAND_R_INTERNAL_ERROR}
  RAND_R_INTERNAL_ERROR = 113;
  {$EXTERNALSYM RAND_R_IN_ERROR_STATE}
  RAND_R_IN_ERROR_STATE = 114;
  {$EXTERNALSYM RAND_R_NOT_A_REGULAR_FILE}
  RAND_R_NOT_A_REGULAR_FILE = 122;
  {$EXTERNALSYM RAND_R_NOT_INSTANTIATED}
  RAND_R_NOT_INSTANTIATED = 115;
  {$EXTERNALSYM RAND_R_NO_DRBG_IMPLEMENTATION_SELECTED}
  RAND_R_NO_DRBG_IMPLEMENTATION_SELECTED = 128;
  {$EXTERNALSYM RAND_R_PARENT_LOCKING_NOT_ENABLED}
  RAND_R_PARENT_LOCKING_NOT_ENABLED = 130;
  {$EXTERNALSYM RAND_R_PARENT_STRENGTH_TOO_WEAK}
  RAND_R_PARENT_STRENGTH_TOO_WEAK = 131;
  {$EXTERNALSYM RAND_R_PERSONALISATION_STRING_TOO_LONG}
  RAND_R_PERSONALISATION_STRING_TOO_LONG = 116;
  {$EXTERNALSYM RAND_R_PREDICTION_RESISTANCE_NOT_SUPPORTED}
  RAND_R_PREDICTION_RESISTANCE_NOT_SUPPORTED = 133;
  {$EXTERNALSYM RAND_R_PRNG_NOT_SEEDED}
  RAND_R_PRNG_NOT_SEEDED = 100;
  {$EXTERNALSYM RAND_R_RANDOM_POOL_OVERFLOW}
  RAND_R_RANDOM_POOL_OVERFLOW = 125;
  {$EXTERNALSYM RAND_R_RANDOM_POOL_UNDERFLOW}
  RAND_R_RANDOM_POOL_UNDERFLOW = 134;
  {$EXTERNALSYM RAND_R_REQUEST_TOO_LARGE_FOR_DRBG}
  RAND_R_REQUEST_TOO_LARGE_FOR_DRBG = 117;
  {$EXTERNALSYM RAND_R_RESEED_ERROR}
  RAND_R_RESEED_ERROR = 118;
  {$EXTERNALSYM RAND_R_SELFTEST_FAILURE}
  RAND_R_SELFTEST_FAILURE = 119;
  {$EXTERNALSYM RAND_R_TOO_LITTLE_NONCE_REQUESTED}
  RAND_R_TOO_LITTLE_NONCE_REQUESTED = 135;
  {$EXTERNALSYM RAND_R_TOO_MUCH_NONCE_REQUESTED}
  RAND_R_TOO_MUCH_NONCE_REQUESTED = 136;
  {$EXTERNALSYM RAND_R_UNSUPPORTED_DRBG_FLAGS}
  RAND_R_UNSUPPORTED_DRBG_FLAGS = 132;
  {$EXTERNALSYM RAND_R_UNSUPPORTED_DRBG_TYPE}
  RAND_R_UNSUPPORTED_DRBG_TYPE = 120;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM ERR_load_RAND_strings}
  ERR_load_RAND_strings: function : TIdC_INT; cdecl = nil;

{$ELSE}
  {$EXTERNALSYM ERR_load_RAND_strings}
  function ERR_load_RAND_strings: TIdC_INT cdecl; external CLibCrypto;

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
  ERR_load_RAND_strings_procname = 'ERR_load_RAND_strings';

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 
function  ERR_ERR_load_RAND_strings: TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_load_RAND_strings_procname);
end;



  {$I TaurusTLSNoRetValOn.inc} 
  {$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  ERR_load_RAND_strings := LoadLibFunction(ADllHandle, ERR_load_RAND_strings_procname);
  FuncLoadError := not assigned(ERR_load_RAND_strings);
  if FuncLoadError then
  begin
    {$if not defined(ERR_load_RAND_strings_allownil)}
    ERR_load_RAND_strings := ERR_ERR_load_RAND_strings;
    {$ifend}
    {$if declared(ERR_load_RAND_strings_introduced)}
    if LibVersion < ERR_load_RAND_strings_introduced then
    begin
      {$if declared(FC_ERR_load_RAND_strings)}
      ERR_load_RAND_strings := FC_ERR_load_RAND_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_load_RAND_strings_removed)}
    if ERR_load_RAND_strings_removed <= LibVersion then
    begin
      {$if declared(_ERR_load_RAND_strings)}
      ERR_load_RAND_strings := _ERR_load_RAND_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_load_RAND_strings_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_load_RAND_strings');
    {$ifend}
  end;
end;
 {$I TaurusTLSUnusedParamOn.inc}
procedure Unload;
begin
  ERR_load_RAND_strings := nil;
end;
  {$ENDIF}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
