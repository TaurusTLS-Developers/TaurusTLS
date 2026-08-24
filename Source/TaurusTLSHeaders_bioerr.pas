/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_bioerr.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_bioerr.h2pas
     and this file regenerated. TaurusTLSHeaders_bioerr.h2pas is distributed with the full Indy
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

unit TaurusTLSHeaders_bioerr;

interface

// Headers for OpenSSL 1.1.1
// bioerr.h


uses
  IdCTypes,
  IdGlobal
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  , TaurusTLSConsts
  {$ENDIF};

const
  (*
   * BIO function codes.
   *)
  {$EXTERNALSYM BIO_F_ACPT_STATE}
  BIO_F_ACPT_STATE = 100;
  {$EXTERNALSYM BIO_F_ADDRINFO_WRAP}
  BIO_F_ADDRINFO_WRAP = 148;
  {$EXTERNALSYM BIO_F_ADDR_STRINGS}
  BIO_F_ADDR_STRINGS = 134;
  {$EXTERNALSYM BIO_F_BIO_ACCEPT}
  BIO_F_BIO_ACCEPT = 101;
  {$EXTERNALSYM BIO_F_BIO_ACCEPT_EX}
  BIO_F_BIO_ACCEPT_EX = 137;
  {$EXTERNALSYM BIO_F_BIO_ACCEPT_NEW}
  BIO_F_BIO_ACCEPT_NEW = 152;
  {$EXTERNALSYM BIO_F_BIO_ADDR_NEW}
  BIO_F_BIO_ADDR_NEW = 144;
  {$EXTERNALSYM BIO_F_BIO_BIND}
  BIO_F_BIO_BIND = 147;
  {$EXTERNALSYM BIO_F_BIO_CALLBACK_CTRL}
  BIO_F_BIO_CALLBACK_CTRL = 131;
  {$EXTERNALSYM BIO_F_BIO_CONNECT}
  BIO_F_BIO_CONNECT = 138;
  {$EXTERNALSYM BIO_F_BIO_CONNECT_NEW}
  BIO_F_BIO_CONNECT_NEW = 153;
  {$EXTERNALSYM BIO_F_BIO_CTRL}
  BIO_F_BIO_CTRL = 103;
  {$EXTERNALSYM BIO_F_BIO_GETS}
  BIO_F_BIO_GETS = 104;
  {$EXTERNALSYM BIO_F_BIO_GET_HOST_IP}
  BIO_F_BIO_GET_HOST_IP = 106;
  {$EXTERNALSYM BIO_F_BIO_GET_NEW_INDEX}
  BIO_F_BIO_GET_NEW_INDEX = 102;
  {$EXTERNALSYM BIO_F_BIO_GET_PORT}
  BIO_F_BIO_GET_PORT = 107;
  {$EXTERNALSYM BIO_F_BIO_LISTEN}
  BIO_F_BIO_LISTEN = 139;
  {$EXTERNALSYM BIO_F_BIO_LOOKUP}
  BIO_F_BIO_LOOKUP = 135;
  {$EXTERNALSYM BIO_F_BIO_LOOKUP_EX}
  BIO_F_BIO_LOOKUP_EX = 143;
  {$EXTERNALSYM BIO_F_BIO_MAKE_PAIR}
  BIO_F_BIO_MAKE_PAIR = 121;
  {$EXTERNALSYM BIO_F_BIO_METH_NEW}
  BIO_F_BIO_METH_NEW = 146;
  {$EXTERNALSYM BIO_F_BIO_NEW}
  BIO_F_BIO_NEW = 108;
  {$EXTERNALSYM BIO_F_BIO_NEW_DGRAM_SCTP}
  BIO_F_BIO_NEW_DGRAM_SCTP = 145;
  {$EXTERNALSYM BIO_F_BIO_NEW_FILE}
  BIO_F_BIO_NEW_FILE = 109;
  {$EXTERNALSYM BIO_F_BIO_NEW_MEM_BUF}
  BIO_F_BIO_NEW_MEM_BUF = 126;
  {$EXTERNALSYM BIO_F_BIO_NREAD}
  BIO_F_BIO_NREAD = 123;
  {$EXTERNALSYM BIO_F_BIO_NREAD0}
  BIO_F_BIO_NREAD0 = 124;
  {$EXTERNALSYM BIO_F_BIO_NWRITE}
  BIO_F_BIO_NWRITE = 125;
  {$EXTERNALSYM BIO_F_BIO_NWRITE0}
  BIO_F_BIO_NWRITE0 = 122;
  {$EXTERNALSYM BIO_F_BIO_PARSE_HOSTSERV}
  BIO_F_BIO_PARSE_HOSTSERV = 136;
  {$EXTERNALSYM BIO_F_BIO_PUTS}
  BIO_F_BIO_PUTS = 110;
  {$EXTERNALSYM BIO_F_BIO_READ}
  BIO_F_BIO_READ = 111;
  {$EXTERNALSYM BIO_F_BIO_READ_EX}
  BIO_F_BIO_READ_EX = 105;
  {$EXTERNALSYM BIO_F_BIO_READ_INTERN}
  BIO_F_BIO_READ_INTERN = 120;
  {$EXTERNALSYM BIO_F_BIO_SOCKET}
  BIO_F_BIO_SOCKET = 140;
  {$EXTERNALSYM BIO_F_BIO_SOCKET_NBIO}
  BIO_F_BIO_SOCKET_NBIO = 142;
  {$EXTERNALSYM BIO_F_BIO_SOCK_INFO}
  BIO_F_BIO_SOCK_INFO = 141;
  {$EXTERNALSYM BIO_F_BIO_SOCK_INIT}
  BIO_F_BIO_SOCK_INIT = 112;
  {$EXTERNALSYM BIO_F_BIO_WRITE}
  BIO_F_BIO_WRITE = 113;
  {$EXTERNALSYM BIO_F_BIO_WRITE_EX}
  BIO_F_BIO_WRITE_EX = 119;
  {$EXTERNALSYM BIO_F_BIO_WRITE_INTERN}
  BIO_F_BIO_WRITE_INTERN = 128;
  {$EXTERNALSYM BIO_F_BUFFER_CTRL}
  BIO_F_BUFFER_CTRL = 114;
  {$EXTERNALSYM BIO_F_CONN_CTRL}
  BIO_F_CONN_CTRL = 127;
  {$EXTERNALSYM BIO_F_CONN_STATE}
  BIO_F_CONN_STATE = 115;
  {$EXTERNALSYM BIO_F_DGRAM_SCTP_NEW}
  BIO_F_DGRAM_SCTP_NEW = 149;
  {$EXTERNALSYM BIO_F_DGRAM_SCTP_READ}
  BIO_F_DGRAM_SCTP_READ = 132;
  {$EXTERNALSYM BIO_F_DGRAM_SCTP_WRITE}
  BIO_F_DGRAM_SCTP_WRITE = 133;
  {$EXTERNALSYM BIO_F_DOAPR_OUTCH}
  BIO_F_DOAPR_OUTCH = 150;
  {$EXTERNALSYM BIO_F_FILE_CTRL}
  BIO_F_FILE_CTRL = 116;
  {$EXTERNALSYM BIO_F_FILE_READ}
  BIO_F_FILE_READ = 130;
  {$EXTERNALSYM BIO_F_LINEBUFFER_CTRL}
  BIO_F_LINEBUFFER_CTRL = 129;
  {$EXTERNALSYM BIO_F_LINEBUFFER_NEW}
  BIO_F_LINEBUFFER_NEW = 151;
  {$EXTERNALSYM BIO_F_MEM_WRITE}
  BIO_F_MEM_WRITE = 117;
  {$EXTERNALSYM BIO_F_NBIOF_NEW}
  BIO_F_NBIOF_NEW = 154;
  {$EXTERNALSYM BIO_F_SLG_WRITE}
  BIO_F_SLG_WRITE = 155;
  {$EXTERNALSYM BIO_F_SSL_NEW}
  BIO_F_SSL_NEW = 118;

  (*
   * BIO reason codes.
   *)
  {$EXTERNALSYM BIO_R_ACCEPT_ERROR}
  BIO_R_ACCEPT_ERROR =   100;
  {$EXTERNALSYM BIO_R_ADDRINFO_ADDR_IS_NOT_AF_INET}
  BIO_R_ADDRINFO_ADDR_IS_NOT_AF_INET =  141;
  {$EXTERNALSYM BIO_R_AMBIGUOUS_HOST_OR_SERVICE}
  BIO_R_AMBIGUOUS_HOST_OR_SERVICE =  129;
  {$EXTERNALSYM BIO_R_BAD_FOPEN_MODE}
  BIO_R_BAD_FOPEN_MODE =  101;
  {$EXTERNALSYM BIO_R_BROKEN_PIPE}
  BIO_R_BROKEN_PIPE =   124;
  {$EXTERNALSYM BIO_R_CONNECT_ERROR}
  BIO_R_CONNECT_ERROR =  103;
  {$EXTERNALSYM BIO_R_GETHOSTBYNAME_ADDR_IS_NOT_AF_INET}
  BIO_R_GETHOSTBYNAME_ADDR_IS_NOT_AF_INET = 107;
  {$EXTERNALSYM BIO_R_GETSOCKNAME_ERROR}
  BIO_R_GETSOCKNAME_ERROR =  132;
  {$EXTERNALSYM BIO_R_GETSOCKNAME_TRUNCATED_ADDRESS}
  BIO_R_GETSOCKNAME_TRUNCATED_ADDRESS = 133;
  {$EXTERNALSYM BIO_R_GETTING_SOCKTYPE}
  BIO_R_GETTING_SOCKTYPE =  134;
  {$EXTERNALSYM BIO_R_INVALID_ARGUMENT}
  BIO_R_INVALID_ARGUMENT =  125;
  {$EXTERNALSYM BIO_R_INVALID_SOCKET}
  BIO_R_INVALID_SOCKET =  135;
  {$EXTERNALSYM BIO_R_IN_USE}
  BIO_R_IN_USE =   123;
  {$EXTERNALSYM BIO_R_LENGTH_TOO_LONG}
  BIO_R_LENGTH_TOO_LONG =  102;
  {$EXTERNALSYM BIO_R_LISTEN_V6_ONLY}
  BIO_R_LISTEN_V6_ONLY =  136;
  {$EXTERNALSYM BIO_R_LOOKUP_RETURNED_NOTHING}
  BIO_R_LOOKUP_RETURNED_NOTHING =  142;
  {$EXTERNALSYM BIO_R_MALFORMED_HOST_OR_SERVICE}
  BIO_R_MALFORMED_HOST_OR_SERVICE =  130;
  {$EXTERNALSYM BIO_R_NBIO_CONNECT_ERROR}
  BIO_R_NBIO_CONNECT_ERROR =  110;
  {$EXTERNALSYM BIO_R_NO_ACCEPT_ADDR_OR_SERVICE_SPECIFIED}
  BIO_R_NO_ACCEPT_ADDR_OR_SERVICE_SPECIFIED = 143;
  {$EXTERNALSYM BIO_R_NO_HOSTNAME_OR_SERVICE_SPECIFIED}
  BIO_R_NO_HOSTNAME_OR_SERVICE_SPECIFIED = 144;
  {$EXTERNALSYM BIO_R_NO_PORT_DEFINED}
  BIO_R_NO_PORT_DEFINED =  113;
  {$EXTERNALSYM BIO_R_NO_SUCH_FILE}
  BIO_R_NO_SUCH_FILE =   128;
  {$EXTERNALSYM BIO_R_NULL_PARAMETER}
  BIO_R_NULL_PARAMETER =  115;
  {$EXTERNALSYM BIO_R_UNABLE_TO_BIND_SOCKET}
  BIO_R_UNABLE_TO_BIND_SOCKET =  117;
  {$EXTERNALSYM BIO_R_UNABLE_TO_CREATE_SOCKET}
  BIO_R_UNABLE_TO_CREATE_SOCKET =  118;
  {$EXTERNALSYM BIO_R_UNABLE_TO_KEEPALIVE}
  BIO_R_UNABLE_TO_KEEPALIVE =  137;
  {$EXTERNALSYM BIO_R_UNABLE_TO_LISTEN_SOCKET}
  BIO_R_UNABLE_TO_LISTEN_SOCKET =  119;
  {$EXTERNALSYM BIO_R_UNABLE_TO_NODELAY}
  BIO_R_UNABLE_TO_NODELAY =  138;
  {$EXTERNALSYM BIO_R_UNABLE_TO_REUSEADDR}
  BIO_R_UNABLE_TO_REUSEADDR =  139;
  {$EXTERNALSYM BIO_R_UNAVAILABLE_IP_FAMILY}
  BIO_R_UNAVAILABLE_IP_FAMILY =  145;
  {$EXTERNALSYM BIO_R_UNINITIALIZED}
  BIO_R_UNINITIALIZED =  120;
  {$EXTERNALSYM BIO_R_UNKNOWN_INFO_TYPE}
  BIO_R_UNKNOWN_INFO_TYPE =  140;
  {$EXTERNALSYM BIO_R_UNSUPPORTED_IP_FAMILY}
  BIO_R_UNSUPPORTED_IP_FAMILY =  146;
  {$EXTERNALSYM BIO_R_UNSUPPORTED_METHOD}
  BIO_R_UNSUPPORTED_METHOD =  121;
  {$EXTERNALSYM BIO_R_UNSUPPORTED_PROTOCOL_FAMILY}
  BIO_R_UNSUPPORTED_PROTOCOL_FAMILY =  131;
  {$EXTERNALSYM BIO_R_WRITE_TO_READ_ONLY_BIO}
  BIO_R_WRITE_TO_READ_ONLY_BIO =  126;
  {$EXTERNALSYM BIO_R_WSASTARTUP}
  BIO_R_WSASTARTUP =   122;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM ERR_load_BIO_strings}
  ERR_load_BIO_strings: function : TIdC_INT; cdecl = nil;

{$ELSE}
  {$EXTERNALSYM ERR_load_BIO_strings}
  function ERR_load_BIO_strings: TIdC_INT cdecl; external CLibCrypto;

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
  ERR_load_BIO_strings_procname = 'ERR_load_BIO_strings';

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 
function  ERR_ERR_load_BIO_strings: TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_load_BIO_strings_procname);
end;



  {$I TaurusTLSNoRetValOn.inc} 
  {$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  ERR_load_BIO_strings := LoadLibFunction(ADllHandle, ERR_load_BIO_strings_procname);
  FuncLoadError := not assigned(ERR_load_BIO_strings);
  if FuncLoadError then
  begin
    {$if not defined(ERR_load_BIO_strings_allownil)}
    ERR_load_BIO_strings := ERR_ERR_load_BIO_strings;
    {$ifend}
    {$if declared(ERR_load_BIO_strings_introduced)}
    if LibVersion < ERR_load_BIO_strings_introduced then
    begin
      {$if declared(FC_ERR_load_BIO_strings)}
      ERR_load_BIO_strings := FC_ERR_load_BIO_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_load_BIO_strings_removed)}
    if ERR_load_BIO_strings_removed <= LibVersion then
    begin
      {$if declared(_ERR_load_BIO_strings)}
      ERR_load_BIO_strings := _ERR_load_BIO_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_load_BIO_strings_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_load_BIO_strings');
    {$ifend}
  end;


end;
  {$I TaurusTLSUnusedParamOn.inc}
procedure Unload;
begin
  ERR_load_BIO_strings := nil;
end;
  {$ENDIF}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
