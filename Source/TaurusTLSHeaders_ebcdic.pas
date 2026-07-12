/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_ebcdic.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_ebcdic.h2pas
     and this file regenerated. TaurusTLSHeaders_ebcdic.h2pas is distributed with the full Indy
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

unit TaurusTLSHeaders_ebcdic;

interface

// Headers for OpenSSL 1.1.1
// ebcdic.h

{$I TaurusTLSUnusedUnitOff.inc}
uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_types;
{$I TaurusTLSUnusedUnitOn.inc}


  //extern const unsigned char os_toascii[256];
  //extern const unsigned char os_toebcdic[256];

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM ebcdic2ascii}
  ebcdic2ascii: function (dest: Pointer; const srce: Pointer; count: TIdC_SIZET): Pointer; cdecl = nil;
  {$EXTERNALSYM ascii2ebcdic}
  ascii2ebcdic: function (dest: Pointer; const srce: Pointer; count: TIdC_SIZET): Pointer; cdecl = nil;

{$ELSE}
  {$EXTERNALSYM ebcdic2ascii}
  function ebcdic2ascii(dest: Pointer; const srce: Pointer; count: TIdC_SIZET): Pointer cdecl; external CLibCrypto;
  {$EXTERNALSYM ascii2ebcdic}
  function ascii2ebcdic(dest: Pointer; const srce: Pointer; count: TIdC_SIZET): Pointer cdecl; external CLibCrypto;

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
  ebcdic2ascii_procname = 'ebcdic2ascii';
  ascii2ebcdic_procname = 'ascii2ebcdic';

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 
function  ERR_ebcdic2ascii(dest: Pointer; const srce: Pointer; count: TIdC_SIZET): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ebcdic2ascii_procname);
end;


function  ERR_ascii2ebcdic(dest: Pointer; const srce: Pointer; count: TIdC_SIZET): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ascii2ebcdic_procname);
end;



  {$I TaurusTLSNoRetValOn.inc} 
  {$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  ebcdic2ascii := LoadLibFunction(ADllHandle, ebcdic2ascii_procname);
  FuncLoadError := not assigned(ebcdic2ascii);
  if FuncLoadError then
  begin
    {$if not defined(ebcdic2ascii_allownil)}
    ebcdic2ascii := ERR_ebcdic2ascii;
    {$ifend}
    {$if declared(ebcdic2ascii_introduced)}
    if LibVersion < ebcdic2ascii_introduced then
    begin
      {$if declared(FC_ebcdic2ascii)}
      ebcdic2ascii := FC_ebcdic2ascii;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ebcdic2ascii_removed)}
    if ebcdic2ascii_removed <= LibVersion then
    begin
      {$if declared(_ebcdic2ascii)}
      ebcdic2ascii := _ebcdic2ascii;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ebcdic2ascii_allownil)}
    if FuncLoadError then
      AFailed.Add('ebcdic2ascii');
    {$ifend}
  end;


  ascii2ebcdic := LoadLibFunction(ADllHandle, ascii2ebcdic_procname);
  FuncLoadError := not assigned(ascii2ebcdic);
  if FuncLoadError then
  begin
    {$if not defined(ascii2ebcdic_allownil)}
    ascii2ebcdic := ERR_ascii2ebcdic;
    {$ifend}
    {$if declared(ascii2ebcdic_introduced)}
    if LibVersion < ascii2ebcdic_introduced then
    begin
      {$if declared(FC_ascii2ebcdic)}
      ascii2ebcdic := FC_ascii2ebcdic;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ascii2ebcdic_removed)}
    if ascii2ebcdic_removed <= LibVersion then
    begin
      {$if declared(_ascii2ebcdic)}
      ascii2ebcdic := _ascii2ebcdic;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ascii2ebcdic_allownil)}
    if FuncLoadError then
      AFailed.Add('ascii2ebcdic');
    {$ifend}
  end;
end;
 {$I TaurusTLSUnusedParamOn.inc}
procedure Unload;
begin
  ebcdic2ascii := nil;
  ascii2ebcdic := nil;
end;
  {$ENDIF}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
