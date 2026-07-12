/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_rc4.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_rc4.h2pas
     and this file regenerated. TaurusTLSHeaders_rc4.h2pas is distributed with the full Indy
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
unit TaurusTLSHeaders_rc4;

interface

{
  Automatically converted by H2Pas 1.0.0 from rc4.h
  The following command line parameters were used:
    rc4.h
}

{$I TaurusTLSUnusedUnitOff.inc}
uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_types;
{$I TaurusTLSUnusedUnitOn.inc}

{$IFDEF FPC}
{$PACKRECORDS C}
{$ENDIF}


  { crypto/rc4/rc4.h  }
  { Copyright (C) 1995-1997 Eric Young (eay@cryptsoft.com)
   * All rights reserved.
   *
   * This package is an SSL implementation written
   * by Eric Young (eay@cryptsoft.com).
   * The implementation was written so as to conform with Netscapes SSL.
   *
   * This library is free for commercial and non-commercial use as long as
   * the following conditions are aheared to.  The following conditions
   * apply to all code found in this distribution, be it the RC4, RSA,
   * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
   * included with this distribution is covered by the same copyright terms
   * except that the holder is Tim Hudson (tjh@cryptsoft.com).
   *
   * Copyright remains Eric Young's, and as such any Copyright notices in
   * the code are not to be removed.
   * If this package is used in a product, Eric Young should be given attribution
   * as the author of the parts of the library used.
   * This can be in the form of a textual message at program startup or
   * in documentation (online or textual) provided with the package.
   *
   * Redistribution and use in source and binary forms, with or without
   * modification, are permitted provided that the following conditions
   * are met:
   * 1. Redistributions of source code must retain the copyright
   *    notice, this list of conditions and the following disclaimer.
   * 2. Redistributions in binary form must reproduce the above copyright
   *    notice, this list of conditions and the following disclaimer in the
   *    documentation and/or other materials provided with the distribution.
   * 3. All advertising materials mentioning features or use of this software
   *    must display the following acknowledgement:
   *    "This product includes cryptographic software written by
   *     Eric Young (eay@cryptsoft.com)"
   *    The word 'cryptographic' can be left out if the rouines from the library
   *    being used are not cryptographic related :-).
   * 4. If you include any Windows specific code (or a derivative thereof) from
   *    the apps directory (application code) you must include an acknowledgement:
   *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
   *
   * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
   * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
   * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
   * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
   * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
   * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
   * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
   * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
   * SUCH DAMAGE.
   *
   * The licence and distribution terms for any publically available version or
   * derivative of this code cannot be changed.  i.e. this code cannot simply be
   * copied and put under another distribution licence
   * [including the GNU Public Licence.]
    }

  type
  {$EXTERNALSYM PRC4_KEY}
    PRC4_KEY  = ^RC4_KEY;
  {$EXTERNALSYM RC4_INT}
    RC4_INT = TIdC_UINT;
  {$EXTERNALSYM rc4_key_st}
    rc4_key_st = record
        x : RC4_INT;
        y : RC4_INT;
        data : array[0..255] of RC4_INT;
      end;
  {$EXTERNALSYM RC4_KEY}
    RC4_KEY = rc4_key_st;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM RC4_options}
  RC4_options: function : PIdAnsiChar; cdecl = nil; {allow_nil}
  {$EXTERNALSYM RC4_set_key}
  RC4_set_key: procedure (key:PRC4_KEY; len: TIdC_LONG; const data:Pbyte); cdecl = nil; {allow_nil}
  {$EXTERNALSYM private_RC4_set_key}
  private_RC4_set_key: procedure (key:PRC4_KEY; len: TIdC_LONG; const data:Pbyte); cdecl = nil; {allow_nil}
  {$EXTERNALSYM RC4}
  RC4: procedure (key:PRC4_KEY; len: TIdC_SIZET; const indata: Pbyte; outdata: Pbyte); cdecl = nil; {allow_nil}

{$ELSE}
{interface_body}
{$IFNDEF OPENSSL_NO_RC4}
  {$EXTERNALSYM RC4_options}
  function RC4_options: PIdAnsiChar cdecl; external CLibCrypto; 
  {$EXTERNALSYM RC4_set_key}
  procedure RC4_set_key(key:PRC4_KEY; len: TIdC_LONG; const data:Pbyte) cdecl; external CLibCrypto; 
  {$EXTERNALSYM private_RC4_set_key}
  procedure private_RC4_set_key(key:PRC4_KEY; len: TIdC_LONG; const data:Pbyte) cdecl; external CLibCrypto; 
  {$EXTERNALSYM RC4}
  procedure RC4(key:PRC4_KEY; len: TIdC_SIZET; const indata: Pbyte; outdata: Pbyte) cdecl; external CLibCrypto; 
{$ENDIF}

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
  RC4_options_procname = 'RC4_options'; {allow_nil}
  RC4_set_key_procname = 'RC4_set_key'; {allow_nil}
  private_RC4_set_key_procname = 'private_RC4_set_key'; {allow_nil}
  RC4_procname = 'RC4'; {allow_nil}

{$DEFINE RC4_options_allownil} {allow_nil}
{$DEFINE RC4_set_key_allownil} {allow_nil}
{$DEFINE private_RC4_set_key_allownil} {allow_nil}
{$DEFINE RC4_allownil} {allow_nil}

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 
function  ERR_RC4_options: PIdAnsiChar;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RC4_options_procname);
end;

 {allow_nil}
procedure  ERR_RC4_set_key(key:PRC4_KEY; len: TIdC_LONG; const data:Pbyte);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RC4_set_key_procname);
end;

 {allow_nil}
procedure  ERR_private_RC4_set_key(key:PRC4_KEY; len: TIdC_LONG; const data:Pbyte);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(private_RC4_set_key_procname);
end;

 {allow_nil}
procedure  ERR_RC4(key:PRC4_KEY; len: TIdC_SIZET; const indata: Pbyte; outdata: Pbyte);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RC4_procname);
end;

 {allow_nil}

  {$I TaurusTLSNoRetValOn.inc} 
  {$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  RC4_options := LoadLibFunction(ADllHandle, RC4_options_procname);
  FuncLoadError := not assigned(RC4_options);
  if FuncLoadError then
  begin
    {$if not defined(RC4_options_allownil)}
    RC4_options := ERR_RC4_options;
    {$ifend}
    {$if declared(RC4_options_introduced)}
    if LibVersion < RC4_options_introduced then
    begin
      {$if declared(FC_RC4_options)}
      RC4_options := FC_RC4_options;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RC4_options_removed)}
    if RC4_options_removed <= LibVersion then
    begin
      {$if declared(_RC4_options)}
      RC4_options := _RC4_options;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RC4_options_allownil)}
    if FuncLoadError then
      AFailed.Add('RC4_options');
    {$ifend}
  end;   //PALOFF Empty begin/end-blocks

 {allow_nil}
  RC4_set_key := LoadLibFunction(ADllHandle, RC4_set_key_procname);
  FuncLoadError := not assigned(RC4_set_key);
  if FuncLoadError then
  begin
    {$if not defined(RC4_set_key_allownil)}
    RC4_set_key := ERR_RC4_set_key;
    {$ifend}
    {$if declared(RC4_set_key_introduced)}
    if LibVersion < RC4_set_key_introduced then
    begin
      {$if declared(FC_RC4_set_key)}
      RC4_set_key := FC_RC4_set_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RC4_set_key_removed)}
    if RC4_set_key_removed <= LibVersion then
    begin
      {$if declared(_RC4_set_key)}
      RC4_set_key := _RC4_set_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RC4_set_key_allownil)}
    if FuncLoadError then
      AFailed.Add('RC4_set_key');
    {$ifend}
  end;  //PALOFF Empty begin/end-blocks

 {allow_nil}
  private_RC4_set_key := LoadLibFunction(ADllHandle, private_RC4_set_key_procname);
  FuncLoadError := not assigned(private_RC4_set_key);
  if FuncLoadError then
  begin
    {$if not defined(private_RC4_set_key_allownil)}
    private_RC4_set_key := ERR_private_RC4_set_key;
    {$ifend}
    {$if declared(private_RC4_set_key_introduced)}
    if LibVersion < private_RC4_set_key_introduced then
    begin
      {$if declared(FC_private_RC4_set_key)}
      private_RC4_set_key := FC_private_RC4_set_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(private_RC4_set_key_removed)}
    if private_RC4_set_key_removed <= LibVersion then
    begin
      {$if declared(_private_RC4_set_key)}
      private_RC4_set_key := _private_RC4_set_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(private_RC4_set_key_allownil)}
    if FuncLoadError then
      AFailed.Add('private_RC4_set_key');
    {$ifend}
  end;   //PALOFF Empty begin/end-blocks

 {allow_nil}
  RC4 := LoadLibFunction(ADllHandle, RC4_procname);
  FuncLoadError := not assigned(RC4);
  if FuncLoadError then
  begin
    {$if not defined(RC4_allownil)}
    RC4 := ERR_RC4;
    {$ifend}
    {$if declared(RC4_introduced)}
    if LibVersion < RC4_introduced then
    begin
      {$if declared(FC_RC4)}
      RC4 := FC_RC4;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RC4_removed)}
    if RC4_removed <= LibVersion then
    begin
      {$if declared(_RC4)}
      RC4 := _RC4;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RC4_allownil)}
    if FuncLoadError then
      AFailed.Add('RC4');
    {$ifend}
  end;   //PALOFF Empty begin/end-blocks

 {allow_nil}
end;   //PALOFF Empty begin/end-blocks
 {$I TaurusTLSUnusedParamOn.inc}

procedure Unload;
begin
  RC4_options := nil; {allow_nil}
  RC4_set_key := nil; {allow_nil}
  private_RC4_set_key := nil; {allow_nil}
  RC4 := nil; {allow_nil}
end;
  {$ENDIF}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
