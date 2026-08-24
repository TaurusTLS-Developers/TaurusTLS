/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_bnerr.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_bnerr.h2pas
     and this file regenerated. TaurusTLSHeaders_bnerr.h2pas is distributed with the full Indy
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

unit TaurusTLSHeaders_bnerr;

interface

// Headers for OpenSSL 1.1.1
// bnerr.h


uses
  IdCTypes,
  IdGlobal
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  , TaurusTLSConsts
  {$ENDIF};

const
  (*
   * BN function codes.
   *)
  {$EXTERNALSYM BN_F_BNRAND}
  BN_F_BNRAND = 127;
  {$EXTERNALSYM BN_F_BNRAND_RANGE}
  BN_F_BNRAND_RANGE = 138;
  {$EXTERNALSYM BN_F_BN_BLINDING_CONVERT_EX}
  BN_F_BN_BLINDING_CONVERT_EX = 100;
  {$EXTERNALSYM BN_F_BN_BLINDING_CREATE_PARAM}
  BN_F_BN_BLINDING_CREATE_PARAM = 128;
  {$EXTERNALSYM BN_F_BN_BLINDING_INVERT_EX}
  BN_F_BN_BLINDING_INVERT_EX = 101;
  {$EXTERNALSYM BN_F_BN_BLINDING_NEW}
  BN_F_BN_BLINDING_NEW = 102;
  {$EXTERNALSYM BN_F_BN_BLINDING_UPDATE}
  BN_F_BN_BLINDING_UPDATE = 103;
  {$EXTERNALSYM BN_F_BN_BN2DEC}
  BN_F_BN_BN2DEC = 104;
  {$EXTERNALSYM BN_F_BN_BN2HEX}
  BN_F_BN_BN2HEX = 105;
  {$EXTERNALSYM BN_F_BN_COMPUTE_WNAF}
  BN_F_BN_COMPUTE_WNAF = 142;
  {$EXTERNALSYM BN_F_BN_CTX_GET}
  BN_F_BN_CTX_GET = 116;
  {$EXTERNALSYM BN_F_BN_CTX_NEW}
  BN_F_BN_CTX_NEW = 106;
  {$EXTERNALSYM BN_F_BN_CTX_START}
  BN_F_BN_CTX_START = 129;
  {$EXTERNALSYM BN_F_BN_DIV}
  BN_F_BN_DIV = 107;
  {$EXTERNALSYM BN_F_BN_DIV_RECP}
  BN_F_BN_DIV_RECP = 130;
  {$EXTERNALSYM BN_F_BN_EXP}
  BN_F_BN_EXP = 123;
  {$EXTERNALSYM BN_F_BN_EXPAND_INTERNAL}
  BN_F_BN_EXPAND_INTERNAL = 120;
  {$EXTERNALSYM BN_F_BN_GENCB_NEW}
  BN_F_BN_GENCB_NEW = 143;
  {$EXTERNALSYM BN_F_BN_GENERATE_DSA_NONCE}
  BN_F_BN_GENERATE_DSA_NONCE = 140;
  {$EXTERNALSYM BN_F_BN_GENERATE_PRIME_EX}
  BN_F_BN_GENERATE_PRIME_EX = 141;
  {$EXTERNALSYM BN_F_BN_GF2M_MOD}
  BN_F_BN_GF2M_MOD = 131;
  {$EXTERNALSYM BN_F_BN_GF2M_MOD_EXP}
  BN_F_BN_GF2M_MOD_EXP = 132;
  {$EXTERNALSYM BN_F_BN_GF2M_MOD_MUL}
  BN_F_BN_GF2M_MOD_MUL = 133;
  {$EXTERNALSYM BN_F_BN_GF2M_MOD_SOLVE_QUAD}
  BN_F_BN_GF2M_MOD_SOLVE_QUAD = 134;
  {$EXTERNALSYM BN_F_BN_GF2M_MOD_SOLVE_QUAD_ARR}
  BN_F_BN_GF2M_MOD_SOLVE_QUAD_ARR = 135;
  {$EXTERNALSYM BN_F_BN_GF2M_MOD_SQR}
  BN_F_BN_GF2M_MOD_SQR = 136;
  {$EXTERNALSYM BN_F_BN_GF2M_MOD_SQRT}
  BN_F_BN_GF2M_MOD_SQRT = 137;
  {$EXTERNALSYM BN_F_BN_LSHIFT}
  BN_F_BN_LSHIFT = 145;
  {$EXTERNALSYM BN_F_BN_MOD_EXP2_MONT}
  BN_F_BN_MOD_EXP2_MONT = 118;
  {$EXTERNALSYM BN_F_BN_MOD_EXP_MONT}
  BN_F_BN_MOD_EXP_MONT = 109;
  {$EXTERNALSYM BN_F_BN_MOD_EXP_MONT_CONSTTIME}
  BN_F_BN_MOD_EXP_MONT_CONSTTIME = 124;
  {$EXTERNALSYM BN_F_BN_MOD_EXP_MONT_WORD}
  BN_F_BN_MOD_EXP_MONT_WORD = 117;
  {$EXTERNALSYM BN_F_BN_MOD_EXP_RECP}
  BN_F_BN_MOD_EXP_RECP = 125;
  {$EXTERNALSYM BN_F_BN_MOD_EXP_SIMPLE}
  BN_F_BN_MOD_EXP_SIMPLE = 126;
  {$EXTERNALSYM BN_F_BN_MOD_INVERSE}
  BN_F_BN_MOD_INVERSE = 110;
  {$EXTERNALSYM BN_F_BN_MOD_INVERSE_NO_BRANCH}
  BN_F_BN_MOD_INVERSE_NO_BRANCH = 139;
  {$EXTERNALSYM BN_F_BN_MOD_LSHIFT_QUICK}
  BN_F_BN_MOD_LSHIFT_QUICK = 119;
  {$EXTERNALSYM BN_F_BN_MOD_SQRT}
  BN_F_BN_MOD_SQRT = 121;
  {$EXTERNALSYM BN_F_BN_MONT_CTX_NEW}
  BN_F_BN_MONT_CTX_NEW = 149;
  {$EXTERNALSYM BN_F_BN_MPI2BN}
  BN_F_BN_MPI2BN = 112;
  {$EXTERNALSYM BN_F_BN_NEW}
  BN_F_BN_NEW = 113;
  {$EXTERNALSYM BN_F_BN_POOL_GET}
  BN_F_BN_POOL_GET = 147;
  {$EXTERNALSYM BN_F_BN_RAND}
  BN_F_BN_RAND = 114;
  {$EXTERNALSYM BN_F_BN_RAND_RANGE}
  BN_F_BN_RAND_RANGE = 122;
  {$EXTERNALSYM BN_F_BN_RECP_CTX_NEW}
  BN_F_BN_RECP_CTX_NEW = 150;
  {$EXTERNALSYM BN_F_BN_RSHIFT}
  BN_F_BN_RSHIFT = 146;
  {$EXTERNALSYM BN_F_BN_SET_WORDS}
  BN_F_BN_SET_WORDS = 144;
  {$EXTERNALSYM BN_F_BN_STACK_PUSH}
  BN_F_BN_STACK_PUSH = 148;
  {$EXTERNALSYM BN_F_BN_USUB}
  BN_F_BN_USUB = 115;

  (*
   * BN reason codes.
   *)
  {$EXTERNALSYM BN_R_ARG2_LT_ARG3}
  BN_R_ARG2_LT_ARG3 = 100;
  {$EXTERNALSYM BN_R_BAD_RECIPROCAL}
  BN_R_BAD_RECIPROCAL = 101;
  {$EXTERNALSYM BN_R_BIGNUM_TOO_LONG}
  BN_R_BIGNUM_TOO_LONG = 114;
  {$EXTERNALSYM BN_R_BITS_TOO_SMALL}
  BN_R_BITS_TOO_SMALL = 118;
  {$EXTERNALSYM BN_R_CALLED_WITH_EVEN_MODULUS}
  BN_R_CALLED_WITH_EVEN_MODULUS = 102;
  {$EXTERNALSYM BN_R_DIV_BY_ZERO}
  BN_R_DIV_BY_ZERO = 103;
  {$EXTERNALSYM BN_R_ENCODING_ERROR}
  BN_R_ENCODING_ERROR = 104;
  {$EXTERNALSYM BN_R_EXPAND_ON_STATIC_BIGNUM_DATA}
  BN_R_EXPAND_ON_STATIC_BIGNUM_DATA = 105;
  {$EXTERNALSYM BN_R_INPUT_NOT_REDUCED}
  BN_R_INPUT_NOT_REDUCED = 110;
  {$EXTERNALSYM BN_R_INVALID_LENGTH}
  BN_R_INVALID_LENGTH = 106;
  {$EXTERNALSYM BN_R_INVALID_RANGE}
  BN_R_INVALID_RANGE = 115;
  {$EXTERNALSYM BN_R_INVALID_SHIFT}
  BN_R_INVALID_SHIFT = 119;
  {$EXTERNALSYM BN_R_NOT_A_SQUARE}
  BN_R_NOT_A_SQUARE = 111;
  {$EXTERNALSYM BN_R_NOT_INITIALIZED}
  BN_R_NOT_INITIALIZED = 107;
  {$EXTERNALSYM BN_R_NO_INVERSE}
  BN_R_NO_INVERSE = 108;
  {$EXTERNALSYM BN_R_NO_SOLUTION}
  BN_R_NO_SOLUTION = 116;
  {$EXTERNALSYM BN_R_PRIVATE_KEY_TOO_LARGE}
  BN_R_PRIVATE_KEY_TOO_LARGE = 117;
  {$EXTERNALSYM BN_R_P_IS_NOT_PRIME}
  BN_R_P_IS_NOT_PRIME = 112;
  {$EXTERNALSYM BN_R_TOO_MANY_ITERATIONS}
  BN_R_TOO_MANY_ITERATIONS = 113;
  {$EXTERNALSYM BN_R_TOO_MANY_TEMPORARY_VARIABLES}
  BN_R_TOO_MANY_TEMPORARY_VARIABLES = 109;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM ERR_load_BN_strings}
  ERR_load_BN_strings: function : TIdC_INT; cdecl = nil;

{$ELSE}
  {$EXTERNALSYM ERR_load_BN_strings}
  function ERR_load_BN_strings: TIdC_INT cdecl; external CLibCrypto;

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
  ERR_load_BN_strings_procname = 'ERR_load_BN_strings';

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 
function  ERR_ERR_load_BN_strings: TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_load_BN_strings_procname);
end;



  {$I TaurusTLSNoRetValOn.inc} 
  {$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  ERR_load_BN_strings := LoadLibFunction(ADllHandle, ERR_load_BN_strings_procname);
  FuncLoadError := not assigned(ERR_load_BN_strings);
  if FuncLoadError then
  begin
    {$if not defined(ERR_load_BN_strings_allownil)}
    ERR_load_BN_strings := ERR_ERR_load_BN_strings;
    {$ifend}
    {$if declared(ERR_load_BN_strings_introduced)}
    if LibVersion < ERR_load_BN_strings_introduced then
    begin
      {$if declared(FC_ERR_load_BN_strings)}
      ERR_load_BN_strings := FC_ERR_load_BN_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_load_BN_strings_removed)}
    if ERR_load_BN_strings_removed <= LibVersion then
    begin
      {$if declared(_ERR_load_BN_strings)}
      ERR_load_BN_strings := _ERR_load_BN_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_load_BN_strings_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_load_BN_strings');
    {$ifend}
  end;


end;
  {$I TaurusTLSUnusedParamOn.inc}
procedure Unload;
begin
  ERR_load_BN_strings := nil;
end;
  {$ENDIF}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
