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

uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_core;


// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  BIO_R_ACCEPT_ERROR = 100;
  BIO_R_ADDRINFO_ADDR_IS_NOT_AF_INET = 141;
  BIO_R_AMBIGUOUS_HOST_OR_SERVICE = 129;
  BIO_R_BAD_FOPEN_MODE = 101;
  BIO_R_BROKEN_PIPE = 124;
  BIO_R_CONNECT_ERROR = 103;
  BIO_R_CONNECT_TIMEOUT = 147;
  BIO_R_GETHOSTBYNAME_ADDR_IS_NOT_AF_INET = 107;
  BIO_R_GETSOCKNAME_ERROR = 132;
  BIO_R_GETSOCKNAME_TRUNCATED_ADDRESS = 133;
  BIO_R_GETTING_SOCKTYPE = 134;
  BIO_R_INVALID_ARGUMENT = 125;
  BIO_R_INVALID_SOCKET = 135;
  BIO_R_IN_USE = 123;
  BIO_R_LENGTH_TOO_LONG = 102;
  BIO_R_LISTEN_V6_ONLY = 136;
  BIO_R_LOCAL_ADDR_NOT_AVAILABLE = 111;
  BIO_R_LOOKUP_RETURNED_NOTHING = 142;
  BIO_R_MALFORMED_HOST_OR_SERVICE = 130;
  BIO_R_NBIO_CONNECT_ERROR = 110;
  BIO_R_NON_FATAL = 112;
  BIO_R_NO_ACCEPT_ADDR_OR_SERVICE_SPECIFIED = 143;
  BIO_R_NO_HOSTNAME_OR_SERVICE_SPECIFIED = 144;
  BIO_R_NO_PORT_DEFINED = 113;
  BIO_R_NO_SUCH_FILE = 128;
  BIO_R_NULL_PARAMETER = 115;
  BIO_R_TFO_DISABLED = 106;
  BIO_R_TFO_NO_KERNEL_SUPPORT = 108;
  BIO_R_TRANSFER_ERROR = 104;
  BIO_R_TRANSFER_TIMEOUT = 105;
  BIO_R_UNABLE_TO_BIND_SOCKET = 117;
  BIO_R_UNABLE_TO_CREATE_SOCKET = 118;
  BIO_R_UNABLE_TO_KEEPALIVE = 137;
  BIO_R_UNABLE_TO_LISTEN_SOCKET = 119;
  BIO_R_UNABLE_TO_NODELAY = 138;
  BIO_R_UNABLE_TO_REUSEADDR = 139;
  BIO_R_UNABLE_TO_TFO = 109;
  BIO_R_UNAVAILABLE_IP_FAMILY = 145;
  BIO_R_UNINITIALIZED = 120;
  BIO_R_UNKNOWN_INFO_TYPE = 140;
  BIO_R_UNSUPPORTED_IP_FAMILY = 146;
  BIO_R_UNSUPPORTED_METHOD = 121;
  BIO_R_UNSUPPORTED_PROTOCOL_FAMILY = 131;
  BIO_R_WRITE_TO_READ_ONLY_BIO = 126;
  BIO_R_WSASTARTUP = 122;
  BIO_R_PORT_MISMATCH = 150;
  BIO_R_PEER_ADDR_NOT_AVAILABLE = 151;

implementation

end.