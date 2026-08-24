/// <exclude />
(* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_dsaerr.h2pas
  It should not be modified directly. All changes should be made to TaurusTLSHeaders_dsaerr.h2pas
  and this file regenerated. TaurusTLSHeaders_dsaerr.h2pas is distributed with the full Indy
  Distribution.
*)

{$I TaurusTLSCompilerDefines.inc}
{$I TaurusTLSLinkDefines.inc}
{$IFNDEF USE_OPENSSL}
{ error Should not compile if USE_OPENSSL is not defined!!! }
{$ENDIF}
{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2024 TaurusTLS Developers, All Rights Reserved              * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 – 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  * }
{ ****************************************************************************** }
unit TaurusTLSHeaders_dsaerr;

interface

// Headers for OpenSSL 1.1.1
// dsaerr.h

uses
  IdCTypes,
  IdGlobal
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  , TaurusTLSConsts
  {$ENDIF};

const
  /// *
  // * DSA function codes.
  // */
  {$EXTERNALSYM DSA_F_DSAPARAMS_PRINT}
  DSA_F_DSAPARAMS_PRINT = 100;
  {$EXTERNALSYM DSA_F_DSAPARAMS_PRINT_FP}
  DSA_F_DSAPARAMS_PRINT_FP = 101;
  {$EXTERNALSYM DSA_F_DSA_BUILTIN_PARAMGEN}
  DSA_F_DSA_BUILTIN_PARAMGEN = 125;
  {$EXTERNALSYM DSA_F_DSA_BUILTIN_PARAMGEN2}
  DSA_F_DSA_BUILTIN_PARAMGEN2 = 126;
  {$EXTERNALSYM DSA_F_DSA_DO_SIGN}
  DSA_F_DSA_DO_SIGN = 112;
  {$EXTERNALSYM DSA_F_DSA_DO_VERIFY}
  DSA_F_DSA_DO_VERIFY = 113;
  {$EXTERNALSYM DSA_F_DSA_METH_DUP}
  DSA_F_DSA_METH_DUP = 127;
  {$EXTERNALSYM DSA_F_DSA_METH_NEW}
  DSA_F_DSA_METH_NEW = 128;
  {$EXTERNALSYM DSA_F_DSA_METH_SET1_NAME}
  DSA_F_DSA_METH_SET1_NAME = 129;
  {$EXTERNALSYM DSA_F_DSA_NEW_METHOD}
  DSA_F_DSA_NEW_METHOD = 103;
  {$EXTERNALSYM DSA_F_DSA_PARAM_DECODE}
  DSA_F_DSA_PARAM_DECODE = 119;
  {$EXTERNALSYM DSA_F_DSA_PRINT_FP}
  DSA_F_DSA_PRINT_FP = 105;
  {$EXTERNALSYM DSA_F_DSA_PRIV_DECODE}
  DSA_F_DSA_PRIV_DECODE = 115;
  {$EXTERNALSYM DSA_F_DSA_PRIV_ENCODE}
  DSA_F_DSA_PRIV_ENCODE = 116;
  {$EXTERNALSYM DSA_F_DSA_PUB_DECODE}
  DSA_F_DSA_PUB_DECODE = 117;
  {$EXTERNALSYM DSA_F_DSA_PUB_ENCODE}
  DSA_F_DSA_PUB_ENCODE = 118;
  {$EXTERNALSYM DSA_F_DSA_SIGN}
  DSA_F_DSA_SIGN = 106;
  {$EXTERNALSYM DSA_F_DSA_SIGN_SETUP}
  DSA_F_DSA_SIGN_SETUP = 107;
  {$EXTERNALSYM DSA_F_DSA_SIG_NEW}
  DSA_F_DSA_SIG_NEW = 102;
  {$EXTERNALSYM DSA_F_OLD_DSA_PRIV_DECODE}
  DSA_F_OLD_DSA_PRIV_DECODE = 122;
  {$EXTERNALSYM DSA_F_PKEY_DSA_CTRL}
  DSA_F_PKEY_DSA_CTRL = 120;
  {$EXTERNALSYM DSA_F_PKEY_DSA_CTRL_STR}
  DSA_F_PKEY_DSA_CTRL_STR = 104;
  {$EXTERNALSYM DSA_F_PKEY_DSA_KEYGEN}
  DSA_F_PKEY_DSA_KEYGEN = 121;

  /// *
  // * DSA reason codes.
  // */
  {$EXTERNALSYM DSA_R_BAD_Q_VALUE}
  DSA_R_BAD_Q_VALUE = 102;
  {$EXTERNALSYM DSA_R_BN_DECODE_ERROR}
  DSA_R_BN_DECODE_ERROR = 108;
  {$EXTERNALSYM DSA_R_BN_ERROR}
  DSA_R_BN_ERROR = 109;
  {$EXTERNALSYM DSA_R_DECODE_ERROR}
  DSA_R_DECODE_ERROR = 104;
  {$EXTERNALSYM DSA_R_INVALID_DIGEST_TYPE}
  DSA_R_INVALID_DIGEST_TYPE = 106;
  {$EXTERNALSYM DSA_R_INVALID_PARAMETERS}
  DSA_R_INVALID_PARAMETERS = 112;
  {$EXTERNALSYM DSA_R_MISSING_PARAMETERS}
  DSA_R_MISSING_PARAMETERS = 101;
  {$EXTERNALSYM DSA_R_MISSING_PRIVATE_KEY}
  DSA_R_MISSING_PRIVATE_KEY = 111;
  {$EXTERNALSYM DSA_R_MODULUS_TOO_LARGE}
  DSA_R_MODULUS_TOO_LARGE = 103;
  {$EXTERNALSYM DSA_R_NO_PARAMETERS_SET}
  DSA_R_NO_PARAMETERS_SET = 107;
  {$EXTERNALSYM DSA_R_PARAMETER_ENCODING_ERROR}
  DSA_R_PARAMETER_ENCODING_ERROR = 105;
  {$EXTERNALSYM DSA_R_Q_NOT_PRIME}
  DSA_R_Q_NOT_PRIME = 113;
  {$EXTERNALSYM DSA_R_SEED_LEN_SMALL}
  DSA_R_SEED_LEN_SMALL = 110;

  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

    The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
    files generated for C++. }

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

var
  {$EXTERNALSYM ERR_load_DSA_strings}
  ERR_load_DSA_strings: function: TIdC_INT;
cdecl = nil;

{$ELSE}
  {$EXTERNALSYM ERR_load_DSA_strings}
function ERR_load_DSA_strings: TIdC_INT cdecl; external CLibCrypto;

{$ENDIF}

implementation

uses
  classes,
  TaurusTLSExceptionHandlers
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    , TaurusTLSLoader
{$ENDIF};

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

const
  ERR_load_DSA_strings_procname = 'ERR_load_DSA_strings';

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 

function ERR_ERR_load_DSA_strings: TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_load_DSA_strings_procname);
end;

  {$I TaurusTLSNoRetValOn.inc} 
  {$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);

var
  FuncLoadError: boolean;

begin
  ERR_load_DSA_strings := LoadLibFunction(ADllHandle,
    ERR_load_DSA_strings_procname);
  FuncLoadError := not assigned(ERR_load_DSA_strings);
  if FuncLoadError then
  begin
{$IF not defined(ERR_load_DSA_strings_allownil)}
    ERR_load_DSA_strings := ERR_ERR_load_DSA_strings;
{$IFEND}
{$IF declared(ERR_load_DSA_strings_introduced)}
    if LibVersion < ERR_load_DSA_strings_introduced then
    begin
{$IF declared(FC_ERR_load_DSA_strings)}
      ERR_load_DSA_strings := FC_ERR_load_DSA_strings;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(ERR_load_DSA_strings_removed)}
    if ERR_load_DSA_strings_removed <= LibVersion then
    begin
{$IF declared(_ERR_load_DSA_strings)}
      ERR_load_DSA_strings := _ERR_load_DSA_strings;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(ERR_load_DSA_strings_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_load_DSA_strings');
{$IFEND}
  end;

end;
 {$I TaurusTLSUnusedParamOn.inc}

procedure Unload;
begin
  ERR_load_DSA_strings := nil;
end;
  {$ENDIF}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization

Register_SSLLoader(Load, 'LibCrypto');
Register_SSLUnloader(Unload);
{$ENDIF}

end.
