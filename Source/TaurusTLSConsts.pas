/// <exclude />
{******************************************************************************}
{*  TaurusTLS                                                                 *}
{*           https://github.com/JPeterMugaas/TaurusTLS                        *}
{*                                                                            *}
{*  Copyright (c) 2024 TaurusTLS Developers, All Rights Reserved              *}
{*                                                                            *}
{* Portions of this software are Copyright (c) 1993 – 2018,                   *}
{* Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  *}
{******************************************************************************}
{$I TaurusTLSCompilerDefines.inc}
unit TaurusTLSConsts;

{$I TaurusTLSLinkDefines.inc}

interface

const
  {The default SSLLibraryPath is empty. You can override this by setting the
   OPENSSL_LIBRARY_PATH environment variable to the absolute path of the location
   of your openssl library.}

  TaurusTLSLibraryPath = 'OPENSSL_LIBRARY_PATH'; {environment variable name}
  {$IFNDEF OPENSSL_NO_MIN_VERSION}
  min_supported_ssl_version =  (((byte(3) shl 8) + byte(0)) shl 8) shl 8 + byte(0); {3.0.0}
  {$ELSE}
  min_supported_ssl_version = 0;
  {$ENDIF}
  CLibCryptoBase = 'libcrypto';
  CLibSSLBase = 'libssl';

  {The following lists are used when trying to locate the libcrypto and libssl libraries.
   Default sufficies can be replaced by setting the ITaurusTLSLoader.GetSSLLibVersions property}
  {$IFDEF OPENSSL_USE_STATIC_LIBRARY}
  CLibCrypto = '';
  CLibSSL = '';
  {$LINKLIB ssl.a}
  {$LINKLIB crypto.a}
  {$ENDIF}
  
  {$IFDEF OPENSSL_USE_SHARED_LIBRARY}
    {$IFDEF UNIX}
    CLibCrypto = 'crypto';
    CLibSSL = 'ssl';
    {$ENDIF}
    {$IFDEF WINDOWS}
    CLibCrypto = 'libcrypto.lib';
    CLibSSL = 'libssl.lib';
    {$ENDIF}
  {$ELSE}
    {$IFDEF STATICLOAD_OPENSSL}
    CLibCrypto = 'libcrypto.a';
    CLibSSL = 'libssl.a';
    CLibLegacyProvider = 'liblegacy.a';
    {$ENDIF}
  {$ENDIF}
  
  {$IFDEF UNIX}
  DirListDelimiter = ':';
    {$IFDEF OSX_OR_IOS}
  LibSuffix = '.dylib';
    {$ELSE}
  LibSuffix = '.so';
    {$ENDIF}
  DefaultLibVersions = '.4:.3';
  {$ENDIF}
  {$IFDEF WINDOWS}
  DirListDelimiter = ';';
  LibSuffix = '';
    {$IFDEF CPU64}
      {$IFDEF CPUARM64}
    DefaultLibVersions = '-4-arm64;-3-arm64;';
      {$ELSE}
    DefaultLibVersions = '-4-x64;-3-x64;';
      {$ENDIF}
    {$ENDIF}
    {$IFDEF CPU32}
    DefaultLibVersions = '-4;-3;';
    {$ENDIF}
  {$ENDIF}

implementation

end.
