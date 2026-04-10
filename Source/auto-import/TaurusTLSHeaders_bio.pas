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

unit TaurusTLSHeaders_bio;

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
// TYPE DECLARATIONS
// =============================================================================
type
  { TODO 1 -cID Needs manual mapping (Union or complex type) : Review it and update. }
  // union bio_addr_st

  Pbio_addrinfo_st = ^Tbio_addrinfo_st;
  Tbio_addrinfo_st =   record end;
  {$EXTERNALSYM Pbio_addrinfo_st}

  Pbio_method_st = ^Tbio_method_st;
  Tbio_method_st =   record end;
  {$EXTERNALSYM Pbio_method_st}

  Pbio_msg_st = ^Tbio_msg_st;
  Tbio_msg_st =   record
    data: Pointer;
    data_len: TIdC_SIZET;
    peer: PBIO_ADDR;
    local: PBIO_ADDR;
    flags: TIdC_UINT64;
  end;
  {$EXTERNALSYM Pbio_msg_st}

  Pbio_mmsg_cb_args_st = ^Tbio_mmsg_cb_args_st;
  Tbio_mmsg_cb_args_st =   record
    msg: PBIO_MSG;
    stride: TIdC_SIZET;
    num_msg: TIdC_SIZET;
    flags: TIdC_UINT64;
    msgs_processed: PIdC_SIZET;
  end;
  {$EXTERNALSYM Pbio_mmsg_cb_args_st}

  { TODO 1 -cID Needs manual mapping (Union or complex type) : Review it and update. }
  // struct bio_poll_descriptor_st {
  //     uint32_t type;
  //     union {
  //         int fd;
  //         void *custom;
  //         uintptr_t custom_ui;
  //         SSL *ssl;
  //     } value;
  // }

  Phostent = ^Thostent;
  Thostent =   record end;
  {$EXTERNALSYM Phostent}

  { TODO 1 -cID Needs manual mapping (Union or complex type) : Review it and update. }
  // union BIO_sock_info_u {
  //     BIO_ADDR *addr;
  // }


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  TBIO_callback_fn = function(b: PBIO; oper: TIdC_INT; argp: PIdAnsiChar; argi: TIdC_INT; argl: TIdC_LONG; ret: TIdC_LONG): TIdC_LONG; cdecl;
  TBIO_callback_fn_ex = function(b: PBIO; oper: TIdC_INT; argp: PIdAnsiChar; len: TIdC_SIZET; argi: TIdC_INT; argl: TIdC_LONG; ret: TIdC_INT; processed: PIdC_SIZET): TIdC_LONG; cdecl;
  TBIO_info_cb = function(arg1: PBIO; arg2: TIdC_INT; arg3: TIdC_INT): TIdC_INT; cdecl;
  Tbio_info_cb = function(arg1: Pbio_st; arg2: TIdC_INT; arg3: TIdC_INT): TIdC_INT; cdecl;
  Tasn1_ps_func = function(b: PBIO; pbuf: PPIdAnsiChar; plen: PIdC_INT; parg: Pointer): TIdC_INT; cdecl;
  TBIO_dgram_sctp_notification_handler_fn = function(b: PBIO; context: Pointer; buf: Pointer): void; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // BIO_dump_cb_cb_cb = function(data: Pointer; len: TIdC_SIZET; u: Pointer): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // BIO_meth_set_write_write_cb = function(arg1: PBIO; arg2: PIdAnsiChar; arg3: TIdC_INT): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // BIO_meth_set_write_ex_bwrite_cb = function(arg1: PBIO; arg2: PIdAnsiChar; arg3: TIdC_SIZET; arg4: PIdC_SIZET): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // BIO_meth_set_sendmmsg_f_cb = function(arg1: PBIO; arg2: PBIO_MSG; arg3: TIdC_SIZET; arg4: TIdC_SIZET; arg5: TIdC_UINT64; arg6: PIdC_SIZET): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // BIO_meth_set_puts_puts_cb = function(arg1: PBIO; arg2: PIdAnsiChar): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // BIO_meth_set_ctrl_ctrl_cb = function(arg1: PBIO; arg2: TIdC_INT; arg3: TIdC_LONG; arg4: Pointer): TIdC_LONG; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // BIO_meth_set_create_create_cb = function(arg1: PBIO): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // BIO_meth_set_callback_ctrl_callback_ctrl_cb = function(arg1: PBIO; arg2: TIdC_INT; arg3: Tbio_info_cb): TIdC_LONG; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  BIO_TYPE_DESCRIPTOR = $0100;
  BIO_TYPE_FILTER = $0200;
  BIO_TYPE_SOURCE_SINK = $0400;
  BIO_TYPE_NONE = 0;
  BIO_TYPE_MEM = (1 or BIO_TYPE_SOURCE_SINK);
  BIO_TYPE_FILE = (2 or BIO_TYPE_SOURCE_SINK);
  BIO_TYPE_FD = (4 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR);
  BIO_TYPE_SOCKET = (5 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR);
  BIO_TYPE_NULL = (6 or BIO_TYPE_SOURCE_SINK);
  BIO_TYPE_SSL = (7 or BIO_TYPE_FILTER);
  BIO_TYPE_MD = (8 or BIO_TYPE_FILTER);
  BIO_TYPE_BUFFER = (9 or BIO_TYPE_FILTER);
  BIO_TYPE_CIPHER = (10 or BIO_TYPE_FILTER);
  BIO_TYPE_BASE64 = (11 or BIO_TYPE_FILTER);
  BIO_TYPE_CONNECT = (12 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR);
  BIO_TYPE_ACCEPT = (13 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR);
  BIO_TYPE_NBIO_TEST = (16 or BIO_TYPE_FILTER);
  BIO_TYPE_NULL_FILTER = (17 or BIO_TYPE_FILTER);
  BIO_TYPE_BIO = (19 or BIO_TYPE_SOURCE_SINK);
  BIO_TYPE_LINEBUFFER = (20 or BIO_TYPE_FILTER);
  BIO_TYPE_DGRAM = (21 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR);
  BIO_TYPE_ASN1 = (22 or BIO_TYPE_FILTER);
  BIO_TYPE_COMP = (23 or BIO_TYPE_FILTER);
  BIO_TYPE_CORE_TO_PROV = (25 or BIO_TYPE_SOURCE_SINK);
  BIO_TYPE_DGRAM_PAIR = (26 or BIO_TYPE_SOURCE_SINK);
  BIO_TYPE_DGRAM_MEM = (27 or BIO_TYPE_SOURCE_SINK);
  BIO_TYPE_START = 128;
  BIO_TYPE_MASK = $FF;
  BIO_NOCLOSE = $00;
  BIO_CLOSE = $01;
  BIO_CTRL_RESET = 1;
  BIO_CTRL_EOF = 2;
  BIO_CTRL_INFO = 3;
  BIO_CTRL_SET = 4;
  BIO_CTRL_GET = 5;
  BIO_CTRL_PUSH = 6;
  BIO_CTRL_POP = 7;
  BIO_CTRL_GET_CLOSE = 8;
  BIO_CTRL_SET_CLOSE = 9;
  BIO_CTRL_PENDING = 10;
  BIO_CTRL_FLUSH = 11;
  BIO_CTRL_DUP = 12;
  BIO_CTRL_WPENDING = 13;
  BIO_CTRL_SET_CALLBACK = 14;
  BIO_CTRL_GET_CALLBACK = 15;
  BIO_CTRL_PEEK = 29;
  BIO_CTRL_SET_FILENAME = 30;
  BIO_CTRL_DGRAM_CONNECT = 31;
  BIO_CTRL_DGRAM_SET_CONNECTED = 32;
  BIO_CTRL_DGRAM_SET_RECV_TIMEOUT = 33;
  BIO_CTRL_DGRAM_GET_RECV_TIMEOUT = 34;
  BIO_CTRL_DGRAM_SET_SEND_TIMEOUT = 35;
  BIO_CTRL_DGRAM_GET_SEND_TIMEOUT = 36;
  BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP = 37;
  BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP = 38;
  BIO_CTRL_DGRAM_MTU_DISCOVER = 39;
  BIO_CTRL_DGRAM_QUERY_MTU = 40;
  BIO_CTRL_DGRAM_GET_FALLBACK_MTU = 47;
  BIO_CTRL_DGRAM_GET_MTU = 41;
  BIO_CTRL_DGRAM_SET_MTU = 42;
  BIO_CTRL_DGRAM_MTU_EXCEEDED = 43;
  BIO_CTRL_DGRAM_GET_PEER = 46;
  BIO_CTRL_DGRAM_SET_PEER = 44;
  BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT = 45;
  BIO_CTRL_DGRAM_SET_DONT_FRAG = 48;
  BIO_CTRL_DGRAM_GET_MTU_OVERHEAD = 49;
  BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE = 50;
  BIO_CTRL_DGRAM_SET_PEEK_MODE = 71;
  BIO_CTRL_GET_KTLS_SEND = 73;
  BIO_CTRL_GET_KTLS_RECV = 76;
  BIO_CTRL_DGRAM_SCTP_WAIT_FOR_DRY = 77;
  BIO_CTRL_DGRAM_SCTP_MSG_WAITING = 78;
  BIO_CTRL_SET_PREFIX = 79;
  BIO_CTRL_SET_INDENT = 80;
  BIO_CTRL_GET_INDENT = 81;
  BIO_CTRL_DGRAM_GET_LOCAL_ADDR_CAP = 82;
  BIO_CTRL_DGRAM_GET_LOCAL_ADDR_ENABLE = 83;
  BIO_CTRL_DGRAM_SET_LOCAL_ADDR_ENABLE = 84;
  BIO_CTRL_DGRAM_GET_EFFECTIVE_CAPS = 85;
  BIO_CTRL_DGRAM_GET_CAPS = 86;
  BIO_CTRL_DGRAM_SET_CAPS = 87;
  BIO_CTRL_DGRAM_GET_NO_TRUNC = 88;
  BIO_CTRL_DGRAM_SET_NO_TRUNC = 89;
  BIO_CTRL_GET_RPOLL_DESCRIPTOR = 91;
  BIO_CTRL_GET_WPOLL_DESCRIPTOR = 92;
  BIO_CTRL_DGRAM_DETECT_PEER_ADDR = 93;
  BIO_CTRL_DGRAM_SET0_LOCAL_ADDR = 94;
  BIO_DGRAM_CAP_NONE = 0;
  BIO_DGRAM_CAP_HANDLES_SRC_ADDR = (1 shl 0);
  BIO_DGRAM_CAP_HANDLES_DST_ADDR = (1 shl 1);
  BIO_DGRAM_CAP_PROVIDES_SRC_ADDR = (1 shl 2);
  BIO_DGRAM_CAP_PROVIDES_DST_ADDR = (1 shl 3);
  BIO_FP_READ = $02;
  BIO_FP_WRITE = $04;
  BIO_FP_APPEND = $08;
  BIO_FP_TEXT = $10;
  BIO_FLAGS_READ = $01;
  BIO_FLAGS_WRITE = $02;
  BIO_FLAGS_IO_SPECIAL = $04;
  BIO_FLAGS_RWS = (BIO_FLAGS_READ or BIO_FLAGS_WRITE or BIO_FLAGS_IO_SPECIAL);
  BIO_FLAGS_SHOULD_RETRY = $08;
  BIO_FLAGS_UPLINK = 0;
  BIO_FLAGS_BASE64_NO_NL = $100;
  BIO_FLAGS_MEM_RDONLY = $200;
  BIO_FLAGS_NONCLEAR_RST = $400;
  BIO_FLAGS_IN_EOF = $800;
  BIO_RR_SSL_X509_LOOKUP = $01;
  BIO_RR_CONNECT = $02;
  BIO_RR_ACCEPT = $03;
  BIO_CB_FREE = $01;
  BIO_CB_READ = $02;
  BIO_CB_WRITE = $03;
  BIO_CB_PUTS = $04;
  BIO_CB_GETS = $05;
  BIO_CB_CTRL = $06;
  BIO_CB_RECVMMSG = $07;
  BIO_CB_SENDMMSG = $08;
  BIO_CB_RETURN = $80;
  BIO_POLL_DESCRIPTOR_TYPE_NONE = 0;
  BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD = 1;
  BIO_POLL_DESCRIPTOR_TYPE_SSL = 2;
  BIO_POLL_DESCRIPTOR_CUSTOM_START = 8192;
  BIO_C_SET_CONNECT = 100;
  BIO_C_DO_STATE_MACHINE = 101;
  BIO_C_SET_NBIO = 102;
  BIO_C_SET_FD = 104;
  BIO_C_GET_FD = 105;
  BIO_C_SET_FILE_PTR = 106;
  BIO_C_GET_FILE_PTR = 107;
  BIO_C_SET_FILENAME = 108;
  BIO_C_SET_SSL = 109;
  BIO_C_GET_SSL = 110;
  BIO_C_SET_MD = 111;
  BIO_C_GET_MD = 112;
  BIO_C_GET_CIPHER_STATUS = 113;
  BIO_C_SET_BUF_MEM = 114;
  BIO_C_GET_BUF_MEM_PTR = 115;
  BIO_C_GET_BUFF_NUM_LINES = 116;
  BIO_C_SET_BUFF_SIZE = 117;
  BIO_C_SET_ACCEPT = 118;
  BIO_C_SSL_MODE = 119;
  BIO_C_GET_MD_CTX = 120;
  BIO_C_SET_BUFF_READ_DATA = 122;
  BIO_C_GET_CONNECT = 123;
  BIO_C_GET_ACCEPT = 124;
  BIO_C_SET_SSL_RENEGOTIATE_BYTES = 125;
  BIO_C_GET_SSL_NUM_RENEGOTIATES = 126;
  BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT = 127;
  BIO_C_FILE_SEEK = 128;
  BIO_C_GET_CIPHER_CTX = 129;
  BIO_C_SET_BUF_MEM_EOF_RETURN = 130;
  BIO_C_SET_BIND_MODE = 131;
  BIO_C_GET_BIND_MODE = 132;
  BIO_C_FILE_TELL = 133;
  BIO_C_GET_SOCKS = 134;
  BIO_C_SET_SOCKS = 135;
  BIO_C_SET_WRITE_BUF_SIZE = 136;
  BIO_C_GET_WRITE_BUF_SIZE = 137;
  BIO_C_MAKE_BIO_PAIR = 138;
  BIO_C_DESTROY_BIO_PAIR = 139;
  BIO_C_GET_WRITE_GUARANTEE = 140;
  BIO_C_GET_READ_REQUEST = 141;
  BIO_C_SHUTDOWN_WR = 142;
  BIO_C_NREAD0 = 143;
  BIO_C_NREAD = 144;
  BIO_C_NWRITE0 = 145;
  BIO_C_NWRITE = 146;
  BIO_C_RESET_READ_REQUEST = 147;
  BIO_C_SET_MD_CTX = 148;
  BIO_C_SET_PREFIX = 149;
  BIO_C_GET_PREFIX = 150;
  BIO_C_SET_SUFFIX = 151;
  BIO_C_GET_SUFFIX = 152;
  BIO_C_SET_EX_ARG = 153;
  BIO_C_GET_EX_ARG = 154;
  BIO_C_SET_CONNECT_MODE = 155;
  BIO_C_SET_TFO = 156;
  BIO_C_SET_SOCK_TYPE = 157;
  BIO_C_GET_SOCK_TYPE = 158;
  BIO_C_GET_DGRAM_BIO = 159;
  BIO_FAMILY_IPV4 = 4;
  BIO_FAMILY_IPV6 = 6;
  BIO_FAMILY_IPANY = 256;
  BIO_BIND_NORMAL = 0;
  BIO_BIND_REUSEADDR = BIO_SOCK_REUSEADDR;
  BIO_BIND_REUSEADDR_IF_UNUSED = BIO_SOCK_REUSEADDR;
  BIO_SOCK_REUSEADDR = $01;
  BIO_SOCK_V6_ONLY = $02;
  BIO_SOCK_KEEPALIVE = $04;
  BIO_SOCK_NONBLOCK = $08;
  BIO_SOCK_NODELAY = $10;
  BIO_SOCK_TFO = $20;
  ossl_bio__printf__ = __printf__;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  BIO_get_new_index: function: TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_get_new_index}

  BIO_set_flags: function(b: PBIO; flags: TIdC_INT): void; cdecl = nil;
  {$EXTERNALSYM BIO_set_flags}

  BIO_test_flags: function(b: PBIO; flags: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_test_flags}

  BIO_clear_flags: function(b: PBIO; flags: TIdC_INT): void; cdecl = nil;
  {$EXTERNALSYM BIO_clear_flags}

  BIO_get_callback: function(b: PBIO): TBIO_callback_fn; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM BIO_get_callback}

  BIO_set_callback: function(b: PBIO; callback: TBIO_callback_fn): void; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM BIO_set_callback}

  BIO_debug_callback: function(bio: PBIO; cmd: TIdC_INT; argp: PIdAnsiChar; argi: TIdC_INT; argl: TIdC_LONG; ret: TIdC_LONG): TIdC_LONG; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM BIO_debug_callback}

  BIO_get_callback_ex: function(b: PBIO): TBIO_callback_fn_ex; cdecl = nil;
  {$EXTERNALSYM BIO_get_callback_ex}

  BIO_set_callback_ex: function(b: PBIO; callback: TBIO_callback_fn_ex): void; cdecl = nil;
  {$EXTERNALSYM BIO_set_callback_ex}

  BIO_debug_callback_ex: function(bio: PBIO; oper: TIdC_INT; argp: PIdAnsiChar; len: TIdC_SIZET; argi: TIdC_INT; argl: TIdC_LONG; ret: TIdC_INT; processed: PIdC_SIZET): TIdC_LONG; cdecl = nil;
  {$EXTERNALSYM BIO_debug_callback_ex}

  BIO_get_callback_arg: function(b: PBIO): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM BIO_get_callback_arg}

  BIO_set_callback_arg: function(b: PBIO; arg: PIdAnsiChar): void; cdecl = nil;
  {$EXTERNALSYM BIO_set_callback_arg}

  BIO_method_name: function(b: PBIO): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM BIO_method_name}

  BIO_method_type: function(b: PBIO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_method_type}

  BIO_ctrl_pending: function(b: PBIO): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM BIO_ctrl_pending}

  BIO_ctrl_wpending: function(b: PBIO): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM BIO_ctrl_wpending}

  BIO_ctrl_get_write_guarantee: function(b: PBIO): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM BIO_ctrl_get_write_guarantee}

  BIO_ctrl_get_read_request: function(b: PBIO): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM BIO_ctrl_get_read_request}

  BIO_ctrl_reset_read_request: function(b: PBIO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_ctrl_reset_read_request}

  BIO_set_ex_data: function(bio: PBIO; idx: TIdC_INT; data: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_set_ex_data}

  BIO_get_ex_data: function(bio: PBIO; idx: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM BIO_get_ex_data}

  BIO_number_read: function(bio: PBIO): TIdC_UINT64; cdecl = nil;
  {$EXTERNALSYM BIO_number_read}

  BIO_number_written: function(bio: PBIO): TIdC_UINT64; cdecl = nil;
  {$EXTERNALSYM BIO_number_written}

  BIO_asn1_set_prefix: function(b: PBIO; prefix: Tasn1_ps_func; prefix_free: Tasn1_ps_func): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_asn1_set_prefix}

  BIO_asn1_get_prefix: function(b: PBIO; pprefix: PPasn1_ps_func; pprefix_free: PPasn1_ps_func): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_asn1_get_prefix}

  BIO_asn1_set_suffix: function(b: PBIO; suffix: Tasn1_ps_func; suffix_free: Tasn1_ps_func): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_asn1_set_suffix}

  BIO_asn1_get_suffix: function(b: PBIO; psuffix: PPasn1_ps_func; psuffix_free: PPasn1_ps_func): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_asn1_get_suffix}

  BIO_s_file: function: PBIO_METHOD; cdecl = nil;
  {$EXTERNALSYM BIO_s_file}

  BIO_new_file: function(filename: PIdAnsiChar; mode: PIdAnsiChar): PBIO; cdecl = nil;
  {$EXTERNALSYM BIO_new_file}

  BIO_new_from_core_bio: function(libctx: POSSL_LIB_CTX; corebio: POSSL_CORE_BIO): PBIO; cdecl = nil;
  {$EXTERNALSYM BIO_new_from_core_bio}

  BIO_new_fp: function(stream: PFILE; close_flag: TIdC_INT): PBIO; cdecl = nil;
  {$EXTERNALSYM BIO_new_fp}

  BIO_new_ex: function(libctx: POSSL_LIB_CTX; method: PBIO_METHOD): PBIO; cdecl = nil;
  {$EXTERNALSYM BIO_new_ex}

  BIO_new: function(_type: PBIO_METHOD): PBIO; cdecl = nil;
  {$EXTERNALSYM BIO_new}

  BIO_free: function(a: PBIO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_free}

  BIO_set_data: function(a: PBIO; ptr: Pointer): void; cdecl = nil;
  {$EXTERNALSYM BIO_set_data}

  BIO_get_data: function(a: PBIO): Pointer; cdecl = nil;
  {$EXTERNALSYM BIO_get_data}

  BIO_set_init: function(a: PBIO; init: TIdC_INT): void; cdecl = nil;
  {$EXTERNALSYM BIO_set_init}

  BIO_get_init: function(a: PBIO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_get_init}

  BIO_set_shutdown: function(a: PBIO; shut: TIdC_INT): void; cdecl = nil;
  {$EXTERNALSYM BIO_set_shutdown}

  BIO_get_shutdown: function(a: PBIO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_get_shutdown}

  BIO_vfree: function(a: PBIO): void; cdecl = nil;
  {$EXTERNALSYM BIO_vfree}

  BIO_up_ref: function(a: PBIO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_up_ref}

  BIO_read: function(b: PBIO; data: Pointer; dlen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_read}

  BIO_read_ex: function(b: PBIO; data: Pointer; dlen: TIdC_SIZET; readbytes: PIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_read_ex}

  BIO_recvmmsg: function(b: PBIO; msg: PBIO_MSG; stride: TIdC_SIZET; num_msg: TIdC_SIZET; flags: TIdC_UINT64; msgs_processed: PIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_recvmmsg}

  BIO_gets: function(bp: PBIO; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_gets}

  BIO_get_line: function(bio: PBIO; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_get_line}

  BIO_write: function(b: PBIO; data: Pointer; dlen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_write}

  BIO_write_ex: function(b: PBIO; data: Pointer; dlen: TIdC_SIZET; written: PIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_write_ex}

  BIO_sendmmsg: function(b: PBIO; msg: PBIO_MSG; stride: TIdC_SIZET; num_msg: TIdC_SIZET; flags: TIdC_UINT64; msgs_processed: PIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_sendmmsg}

  BIO_get_rpoll_descriptor: function(b: PBIO; desc: PBIO_POLL_DESCRIPTOR): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_get_rpoll_descriptor}

  BIO_get_wpoll_descriptor: function(b: PBIO; desc: PBIO_POLL_DESCRIPTOR): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_get_wpoll_descriptor}

  BIO_puts: function(bp: PBIO; buf: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_puts}

  BIO_indent: function(b: PBIO; indent: TIdC_INT; max: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_indent}

  BIO_ctrl: function(bp: PBIO; cmd: TIdC_INT; larg: TIdC_LONG; parg: Pointer): TIdC_LONG; cdecl = nil;
  {$EXTERNALSYM BIO_ctrl}

  BIO_callback_ctrl: function(b: PBIO; cmd: TIdC_INT; fp: Tbio_info_cb): TIdC_LONG; cdecl = nil;
  {$EXTERNALSYM BIO_callback_ctrl}

  BIO_ptr_ctrl: function(bp: PBIO; cmd: TIdC_INT; larg: TIdC_LONG): Pointer; cdecl = nil;
  {$EXTERNALSYM BIO_ptr_ctrl}

  BIO_int_ctrl: function(bp: PBIO; cmd: TIdC_INT; larg: TIdC_LONG; iarg: TIdC_INT): TIdC_LONG; cdecl = nil;
  {$EXTERNALSYM BIO_int_ctrl}

  BIO_push: function(b: PBIO; append: PBIO): PBIO; cdecl = nil;
  {$EXTERNALSYM BIO_push}

  BIO_pop: function(b: PBIO): PBIO; cdecl = nil;
  {$EXTERNALSYM BIO_pop}

  BIO_free_all: function(a: PBIO): void; cdecl = nil;
  {$EXTERNALSYM BIO_free_all}

  BIO_find_type: function(b: PBIO; bio_type: TIdC_INT): PBIO; cdecl = nil;
  {$EXTERNALSYM BIO_find_type}

  BIO_next: function(b: PBIO): PBIO; cdecl = nil;
  {$EXTERNALSYM BIO_next}

  BIO_set_next: function(b: PBIO; next: PBIO): void; cdecl = nil;
  {$EXTERNALSYM BIO_set_next}

  BIO_get_retry_BIO: function(bio: PBIO; reason: PIdC_INT): PBIO; cdecl = nil;
  {$EXTERNALSYM BIO_get_retry_BIO}

  BIO_get_retry_reason: function(bio: PBIO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_get_retry_reason}

  BIO_set_retry_reason: function(bio: PBIO; reason: TIdC_INT): void; cdecl = nil;
  {$EXTERNALSYM BIO_set_retry_reason}

  BIO_dup_chain: function(_in: PBIO): PBIO; cdecl = nil;
  {$EXTERNALSYM BIO_dup_chain}

  BIO_nread0: function(bio: PBIO; buf: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_nread0}

  BIO_nread: function(bio: PBIO; buf: PPIdAnsiChar; num: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_nread}

  BIO_nwrite0: function(bio: PBIO; buf: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_nwrite0}

  BIO_nwrite: function(bio: PBIO; buf: PPIdAnsiChar; num: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_nwrite}

  BIO_s_mem: function: PBIO_METHOD; cdecl = nil;
  {$EXTERNALSYM BIO_s_mem}

  BIO_s_dgram_mem: function: PBIO_METHOD; cdecl = nil;
  {$EXTERNALSYM BIO_s_dgram_mem}

  BIO_s_secmem: function: PBIO_METHOD; cdecl = nil;
  {$EXTERNALSYM BIO_s_secmem}

  BIO_new_mem_buf: function(buf: Pointer; len: TIdC_INT): PBIO; cdecl = nil;
  {$EXTERNALSYM BIO_new_mem_buf}

  BIO_s_socket: function: PBIO_METHOD; cdecl = nil;
  {$EXTERNALSYM BIO_s_socket}

  BIO_s_connect: function: PBIO_METHOD; cdecl = nil;
  {$EXTERNALSYM BIO_s_connect}

  BIO_s_accept: function: PBIO_METHOD; cdecl = nil;
  {$EXTERNALSYM BIO_s_accept}

  BIO_s_fd: function: PBIO_METHOD; cdecl = nil;
  {$EXTERNALSYM BIO_s_fd}

  BIO_s_log: function: PBIO_METHOD; cdecl = nil;
  {$EXTERNALSYM BIO_s_log}

  BIO_s_bio: function: PBIO_METHOD; cdecl = nil;
  {$EXTERNALSYM BIO_s_bio}

  BIO_s_null: function: PBIO_METHOD; cdecl = nil;
  {$EXTERNALSYM BIO_s_null}

  BIO_f_null: function: PBIO_METHOD; cdecl = nil;
  {$EXTERNALSYM BIO_f_null}

  BIO_f_buffer: function: PBIO_METHOD; cdecl = nil;
  {$EXTERNALSYM BIO_f_buffer}

  BIO_f_readbuffer: function: PBIO_METHOD; cdecl = nil;
  {$EXTERNALSYM BIO_f_readbuffer}

  BIO_f_linebuffer: function: PBIO_METHOD; cdecl = nil;
  {$EXTERNALSYM BIO_f_linebuffer}

  BIO_f_nbio_test: function: PBIO_METHOD; cdecl = nil;
  {$EXTERNALSYM BIO_f_nbio_test}

  BIO_f_prefix: function: PBIO_METHOD; cdecl = nil;
  {$EXTERNALSYM BIO_f_prefix}

  BIO_s_core: function: PBIO_METHOD; cdecl = nil;
  {$EXTERNALSYM BIO_s_core}

  BIO_s_dgram_pair: function: PBIO_METHOD; cdecl = nil;
  {$EXTERNALSYM BIO_s_dgram_pair}

  BIO_s_datagram: function: PBIO_METHOD; cdecl = nil;
  {$EXTERNALSYM BIO_s_datagram}

  BIO_dgram_non_fatal_error: function(error: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_dgram_non_fatal_error}

  BIO_new_dgram: function(fd: TIdC_INT; close_flag: TIdC_INT): PBIO; cdecl = nil;
  {$EXTERNALSYM BIO_new_dgram}

  BIO_sock_should_retry: function(i: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_sock_should_retry}

  BIO_sock_non_fatal_error: function(error: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_sock_non_fatal_error}

  BIO_err_is_non_fatal: function(errcode: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_err_is_non_fatal}

  BIO_socket_wait: function(fd: TIdC_INT; for_read: TIdC_INT; max_time: TIdC_TIMET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_socket_wait}

  BIO_wait: function(bio: PBIO; max_time: TIdC_TIMET; nap_milliseconds: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_wait}

  BIO_do_connect_retry: function(bio: PBIO; timeout: TIdC_INT; nap_milliseconds: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_do_connect_retry}

  BIO_fd_should_retry: function(i: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_fd_should_retry}

  BIO_fd_non_fatal_error: function(error: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_fd_non_fatal_error}

  BIO_dump_cb: function(cb: TBIO_dump_cb_cb_cb; u: Pointer; s: Pointer; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_dump_cb}

  BIO_dump_indent_cb: function(cb: TBIO_dump_cb_cb_cb; u: Pointer; s: Pointer; len: TIdC_INT; indent: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_dump_indent_cb}

  BIO_dump: function(b: PBIO; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_dump}

  BIO_dump_indent: function(b: PBIO; bytes: Pointer; len: TIdC_INT; indent: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_dump_indent}

  BIO_dump_fp: function(fp: PFILE; s: Pointer; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_dump_fp}

  BIO_dump_indent_fp: function(fp: PFILE; s: Pointer; len: TIdC_INT; indent: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_dump_indent_fp}

  BIO_hex_string: function(_out: PBIO; indent: TIdC_INT; width: TIdC_INT; data: Pointer; datalen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_hex_string}

  BIO_ADDR_new: function: PBIO_ADDR; cdecl = nil;
  {$EXTERNALSYM BIO_ADDR_new}

  BIO_ADDR_copy: function(dst: PBIO_ADDR; src: PBIO_ADDR): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_ADDR_copy}

  BIO_ADDR_dup: function(ap: PBIO_ADDR): PBIO_ADDR; cdecl = nil;
  {$EXTERNALSYM BIO_ADDR_dup}

  BIO_ADDR_rawmake: function(ap: PBIO_ADDR; family: TIdC_INT; where: Pointer; wherelen: TIdC_SIZET; port: TIdC_USHORT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_ADDR_rawmake}

  BIO_ADDR_free: function(arg1: PBIO_ADDR): void; cdecl = nil;
  {$EXTERNALSYM BIO_ADDR_free}

  BIO_ADDR_clear: function(ap: PBIO_ADDR): void; cdecl = nil;
  {$EXTERNALSYM BIO_ADDR_clear}

  BIO_ADDR_family: function(ap: PBIO_ADDR): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_ADDR_family}

  BIO_ADDR_rawaddress: function(ap: PBIO_ADDR; p: Pointer; l: PIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_ADDR_rawaddress}

  BIO_ADDR_rawport: function(ap: PBIO_ADDR): TIdC_USHORT; cdecl = nil;
  {$EXTERNALSYM BIO_ADDR_rawport}

  BIO_ADDR_hostname_string: function(ap: PBIO_ADDR; numeric: TIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM BIO_ADDR_hostname_string}

  BIO_ADDR_service_string: function(ap: PBIO_ADDR; numeric: TIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM BIO_ADDR_service_string}

  BIO_ADDR_path_string: function(ap: PBIO_ADDR): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM BIO_ADDR_path_string}

  BIO_ADDRINFO_next: function(bai: PBIO_ADDRINFO): PBIO_ADDRINFO; cdecl = nil;
  {$EXTERNALSYM BIO_ADDRINFO_next}

  BIO_ADDRINFO_family: function(bai: PBIO_ADDRINFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_ADDRINFO_family}

  BIO_ADDRINFO_socktype: function(bai: PBIO_ADDRINFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_ADDRINFO_socktype}

  BIO_ADDRINFO_protocol: function(bai: PBIO_ADDRINFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_ADDRINFO_protocol}

  BIO_ADDRINFO_address: function(bai: PBIO_ADDRINFO): PBIO_ADDR; cdecl = nil;
  {$EXTERNALSYM BIO_ADDRINFO_address}

  BIO_ADDRINFO_free: function(bai: PBIO_ADDRINFO): void; cdecl = nil;
  {$EXTERNALSYM BIO_ADDRINFO_free}

  BIO_parse_hostserv: function(hostserv: PIdAnsiChar; host: PPIdAnsiChar; service: PPIdAnsiChar; hostserv_prio: TBIO_hostserv_priorities): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_parse_hostserv}

  BIO_lookup: function(host: PIdAnsiChar; service: PIdAnsiChar; lookup_type: TBIO_lookup_type; family: TIdC_INT; socktype: TIdC_INT; res: PPBIO_ADDRINFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_lookup}

  BIO_lookup_ex: function(host: PIdAnsiChar; service: PIdAnsiChar; lookup_type: TIdC_INT; family: TIdC_INT; socktype: TIdC_INT; protocol: TIdC_INT; res: PPBIO_ADDRINFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_lookup_ex}

  BIO_sock_error: function(sock: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_sock_error}

  BIO_socket_ioctl: function(fd: TIdC_INT; _type: TIdC_LONG; arg: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_socket_ioctl}

  BIO_socket_nbio: function(fd: TIdC_INT; mode: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_socket_nbio}

  BIO_sock_init: function: TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_sock_init}

  BIO_set_tcp_ndelay: function(sock: TIdC_INT; turn_on: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_set_tcp_ndelay}

  BIO_sock_info: function(sock: TIdC_INT; _type: TBIO_sock_info_type; info: PBIO_sock_info_u): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_sock_info}

  BIO_socket: function(domain: TIdC_INT; socktype: TIdC_INT; protocol: TIdC_INT; options: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_socket}

  BIO_connect: function(sock: TIdC_INT; addr: PBIO_ADDR; options: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_connect}

  BIO_bind: function(sock: TIdC_INT; addr: PBIO_ADDR; options: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_bind}

  BIO_listen: function(sock: TIdC_INT; addr: PBIO_ADDR; options: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_listen}

  BIO_accept_ex: function(accept_sock: TIdC_INT; addr: PBIO_ADDR; options: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_accept_ex}

  BIO_closesocket: function(sock: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_closesocket}

  BIO_new_socket: function(sock: TIdC_INT; close_flag: TIdC_INT): PBIO; cdecl = nil;
  {$EXTERNALSYM BIO_new_socket}

  BIO_new_connect: function(host_port: PIdAnsiChar): PBIO; cdecl = nil;
  {$EXTERNALSYM BIO_new_connect}

  BIO_new_accept: function(host_port: PIdAnsiChar): PBIO; cdecl = nil;
  {$EXTERNALSYM BIO_new_accept}

  BIO_new_fd: function(fd: TIdC_INT; close_flag: TIdC_INT): PBIO; cdecl = nil;
  {$EXTERNALSYM BIO_new_fd}

  BIO_new_bio_pair: function(bio1: PPBIO; writebuf1: TIdC_SIZET; bio2: PPBIO; writebuf2: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_new_bio_pair}

  BIO_new_bio_dgram_pair: function(bio1: PPBIO; writebuf1: TIdC_SIZET; bio2: PPBIO; writebuf2: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_new_bio_dgram_pair}

  BIO_copy_next_retry: function(b: PBIO): void; cdecl = nil;
  {$EXTERNALSYM BIO_copy_next_retry}

  BIO_printf: function(bio: PBIO; format: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_printf}

  BIO_vprintf: function(bio: PBIO; format: PIdAnsiChar; args: Tva_list): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_vprintf}

  BIO_snprintf: function(buf: PIdAnsiChar; n: TIdC_SIZET; format: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_snprintf}

  BIO_vsnprintf: function(buf: PIdAnsiChar; n: TIdC_SIZET; format: PIdAnsiChar; args: Tva_list): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_vsnprintf}

  BIO_meth_new: function(_type: TIdC_INT; name: PIdAnsiChar): PBIO_METHOD; cdecl = nil;
  {$EXTERNALSYM BIO_meth_new}

  BIO_meth_free: function(biom: PBIO_METHOD): void; cdecl = nil;
  {$EXTERNALSYM BIO_meth_free}

  BIO_meth_set_write: function(biom: PBIO_METHOD; write: TBIO_meth_set_write_write_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_meth_set_write}

  BIO_meth_set_write_ex: function(biom: PBIO_METHOD; bwrite: TBIO_meth_set_write_ex_bwrite_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_meth_set_write_ex}

  BIO_meth_set_sendmmsg: function(biom: PBIO_METHOD; f: TBIO_meth_set_sendmmsg_f_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_meth_set_sendmmsg}

  BIO_meth_set_read: function(biom: PBIO_METHOD; read: TBIO_meth_set_write_write_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_meth_set_read}

  BIO_meth_set_read_ex: function(biom: PBIO_METHOD; bread: TBIO_meth_set_write_ex_bwrite_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_meth_set_read_ex}

  BIO_meth_set_recvmmsg: function(biom: PBIO_METHOD; f: TBIO_meth_set_sendmmsg_f_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_meth_set_recvmmsg}

  BIO_meth_set_puts: function(biom: PBIO_METHOD; puts: TBIO_meth_set_puts_puts_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_meth_set_puts}

  BIO_meth_set_gets: function(biom: PBIO_METHOD; ossl_gets: TBIO_meth_set_write_write_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_meth_set_gets}

  BIO_meth_set_ctrl: function(biom: PBIO_METHOD; ctrl: TBIO_meth_set_ctrl_ctrl_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_meth_set_ctrl}

  BIO_meth_set_create: function(biom: PBIO_METHOD; create: TBIO_meth_set_create_create_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_meth_set_create}

  BIO_meth_set_destroy: function(biom: PBIO_METHOD; destroy: TBIO_meth_set_create_create_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_meth_set_destroy}

  BIO_meth_set_callback_ctrl: function(biom: PBIO_METHOD; callback_ctrl: TBIO_meth_set_callback_ctrl_callback_ctrl_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM BIO_meth_set_callback_ctrl}

  BIO_meth_get_write: function(biom: PBIO_METHOD): TBIO_meth_set_write_write_cb; cdecl = nil; // Deprecated in 3_5_0
  {$EXTERNALSYM BIO_meth_get_write}

  BIO_meth_get_write_ex: function(biom: PBIO_METHOD): TBIO_meth_set_write_ex_bwrite_cb; cdecl = nil; // Deprecated in 3_5_0
  {$EXTERNALSYM BIO_meth_get_write_ex}

  BIO_meth_get_sendmmsg: function(biom: PBIO_METHOD): TBIO_meth_set_sendmmsg_f_cb; cdecl = nil; // Deprecated in 3_5_0
  {$EXTERNALSYM BIO_meth_get_sendmmsg}

  BIO_meth_get_read: function(biom: PBIO_METHOD): TBIO_meth_set_write_write_cb; cdecl = nil; // Deprecated in 3_5_0
  {$EXTERNALSYM BIO_meth_get_read}

  BIO_meth_get_read_ex: function(biom: PBIO_METHOD): TBIO_meth_set_write_ex_bwrite_cb; cdecl = nil; // Deprecated in 3_5_0
  {$EXTERNALSYM BIO_meth_get_read_ex}

  BIO_meth_get_recvmmsg: function(biom: PBIO_METHOD): TBIO_meth_set_sendmmsg_f_cb; cdecl = nil; // Deprecated in 3_5_0
  {$EXTERNALSYM BIO_meth_get_recvmmsg}

  BIO_meth_get_puts: function(biom: PBIO_METHOD): TBIO_meth_set_puts_puts_cb; cdecl = nil; // Deprecated in 3_5_0
  {$EXTERNALSYM BIO_meth_get_puts}

  BIO_meth_get_gets: function(biom: PBIO_METHOD): TBIO_meth_set_write_write_cb; cdecl = nil; // Deprecated in 3_5_0
  {$EXTERNALSYM BIO_meth_get_gets}

  BIO_meth_get_ctrl: function(biom: PBIO_METHOD): TBIO_meth_set_ctrl_ctrl_cb; cdecl = nil; // Deprecated in 3_5_0
  {$EXTERNALSYM BIO_meth_get_ctrl}

  BIO_meth_get_create: function(bion: PBIO_METHOD): TBIO_meth_set_create_create_cb; cdecl = nil; // Deprecated in 3_5_0
  {$EXTERNALSYM BIO_meth_get_create}

  BIO_meth_get_destroy: function(biom: PBIO_METHOD): TBIO_meth_set_create_create_cb; cdecl = nil; // Deprecated in 3_5_0
  {$EXTERNALSYM BIO_meth_get_destroy}

  BIO_meth_get_callback_ctrl: function(biom: PBIO_METHOD): TBIO_meth_set_callback_ctrl_callback_ctrl_cb; cdecl = nil; // Deprecated in 3_5_0
  {$EXTERNALSYM BIO_meth_get_callback_ctrl}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function BIO_get_new_index: TIdC_INT; cdecl;
function BIO_set_flags(b: PBIO; flags: TIdC_INT): void; cdecl;
function BIO_test_flags(b: PBIO; flags: TIdC_INT): TIdC_INT; cdecl;
function BIO_clear_flags(b: PBIO; flags: TIdC_INT): void; cdecl;
function BIO_get_callback(b: PBIO): TBIO_callback_fn; cdecl; deprecated 'In OpenSSL 3_0_0';
function BIO_set_callback(b: PBIO; callback: TBIO_callback_fn): void; cdecl; deprecated 'In OpenSSL 3_0_0';
function BIO_debug_callback(bio: PBIO; cmd: TIdC_INT; argp: PIdAnsiChar; argi: TIdC_INT; argl: TIdC_LONG; ret: TIdC_LONG): TIdC_LONG; cdecl; deprecated 'In OpenSSL 3_0_0';
function BIO_get_callback_ex(b: PBIO): TBIO_callback_fn_ex; cdecl;
function BIO_set_callback_ex(b: PBIO; callback: TBIO_callback_fn_ex): void; cdecl;
function BIO_debug_callback_ex(bio: PBIO; oper: TIdC_INT; argp: PIdAnsiChar; len: TIdC_SIZET; argi: TIdC_INT; argl: TIdC_LONG; ret: TIdC_INT; processed: PIdC_SIZET): TIdC_LONG; cdecl;
function BIO_get_callback_arg(b: PBIO): PIdAnsiChar; cdecl;
function BIO_set_callback_arg(b: PBIO; arg: PIdAnsiChar): void; cdecl;
function BIO_method_name(b: PBIO): PIdAnsiChar; cdecl;
function BIO_method_type(b: PBIO): TIdC_INT; cdecl;
function BIO_ctrl_pending(b: PBIO): TIdC_SIZET; cdecl;
function BIO_ctrl_wpending(b: PBIO): TIdC_SIZET; cdecl;
function BIO_ctrl_get_write_guarantee(b: PBIO): TIdC_SIZET; cdecl;
function BIO_ctrl_get_read_request(b: PBIO): TIdC_SIZET; cdecl;
function BIO_ctrl_reset_read_request(b: PBIO): TIdC_INT; cdecl;
function BIO_set_ex_data(bio: PBIO; idx: TIdC_INT; data: Pointer): TIdC_INT; cdecl;
function BIO_get_ex_data(bio: PBIO; idx: TIdC_INT): Pointer; cdecl;
function BIO_number_read(bio: PBIO): TIdC_UINT64; cdecl;
function BIO_number_written(bio: PBIO): TIdC_UINT64; cdecl;
function BIO_asn1_set_prefix(b: PBIO; prefix: Tasn1_ps_func; prefix_free: Tasn1_ps_func): TIdC_INT; cdecl;
function BIO_asn1_get_prefix(b: PBIO; pprefix: PPasn1_ps_func; pprefix_free: PPasn1_ps_func): TIdC_INT; cdecl;
function BIO_asn1_set_suffix(b: PBIO; suffix: Tasn1_ps_func; suffix_free: Tasn1_ps_func): TIdC_INT; cdecl;
function BIO_asn1_get_suffix(b: PBIO; psuffix: PPasn1_ps_func; psuffix_free: PPasn1_ps_func): TIdC_INT; cdecl;
function BIO_s_file: PBIO_METHOD; cdecl;
function BIO_new_file(filename: PIdAnsiChar; mode: PIdAnsiChar): PBIO; cdecl;
function BIO_new_from_core_bio(libctx: POSSL_LIB_CTX; corebio: POSSL_CORE_BIO): PBIO; cdecl;
function BIO_new_fp(stream: PFILE; close_flag: TIdC_INT): PBIO; cdecl;
function BIO_new_ex(libctx: POSSL_LIB_CTX; method: PBIO_METHOD): PBIO; cdecl;
function BIO_new(_type: PBIO_METHOD): PBIO; cdecl;
function BIO_free(a: PBIO): TIdC_INT; cdecl;
function BIO_set_data(a: PBIO; ptr: Pointer): void; cdecl;
function BIO_get_data(a: PBIO): Pointer; cdecl;
function BIO_set_init(a: PBIO; init: TIdC_INT): void; cdecl;
function BIO_get_init(a: PBIO): TIdC_INT; cdecl;
function BIO_set_shutdown(a: PBIO; shut: TIdC_INT): void; cdecl;
function BIO_get_shutdown(a: PBIO): TIdC_INT; cdecl;
function BIO_vfree(a: PBIO): void; cdecl;
function BIO_up_ref(a: PBIO): TIdC_INT; cdecl;
function BIO_read(b: PBIO; data: Pointer; dlen: TIdC_INT): TIdC_INT; cdecl;
function BIO_read_ex(b: PBIO; data: Pointer; dlen: TIdC_SIZET; readbytes: PIdC_SIZET): TIdC_INT; cdecl;
function BIO_recvmmsg(b: PBIO; msg: PBIO_MSG; stride: TIdC_SIZET; num_msg: TIdC_SIZET; flags: TIdC_UINT64; msgs_processed: PIdC_SIZET): TIdC_INT; cdecl;
function BIO_gets(bp: PBIO; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT; cdecl;
function BIO_get_line(bio: PBIO; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT; cdecl;
function BIO_write(b: PBIO; data: Pointer; dlen: TIdC_INT): TIdC_INT; cdecl;
function BIO_write_ex(b: PBIO; data: Pointer; dlen: TIdC_SIZET; written: PIdC_SIZET): TIdC_INT; cdecl;
function BIO_sendmmsg(b: PBIO; msg: PBIO_MSG; stride: TIdC_SIZET; num_msg: TIdC_SIZET; flags: TIdC_UINT64; msgs_processed: PIdC_SIZET): TIdC_INT; cdecl;
function BIO_get_rpoll_descriptor(b: PBIO; desc: PBIO_POLL_DESCRIPTOR): TIdC_INT; cdecl;
function BIO_get_wpoll_descriptor(b: PBIO; desc: PBIO_POLL_DESCRIPTOR): TIdC_INT; cdecl;
function BIO_puts(bp: PBIO; buf: PIdAnsiChar): TIdC_INT; cdecl;
function BIO_indent(b: PBIO; indent: TIdC_INT; max: TIdC_INT): TIdC_INT; cdecl;
function BIO_ctrl(bp: PBIO; cmd: TIdC_INT; larg: TIdC_LONG; parg: Pointer): TIdC_LONG; cdecl;
function BIO_callback_ctrl(b: PBIO; cmd: TIdC_INT; fp: Tbio_info_cb): TIdC_LONG; cdecl;
function BIO_ptr_ctrl(bp: PBIO; cmd: TIdC_INT; larg: TIdC_LONG): Pointer; cdecl;
function BIO_int_ctrl(bp: PBIO; cmd: TIdC_INT; larg: TIdC_LONG; iarg: TIdC_INT): TIdC_LONG; cdecl;
function BIO_push(b: PBIO; append: PBIO): PBIO; cdecl;
function BIO_pop(b: PBIO): PBIO; cdecl;
function BIO_free_all(a: PBIO): void; cdecl;
function BIO_find_type(b: PBIO; bio_type: TIdC_INT): PBIO; cdecl;
function BIO_next(b: PBIO): PBIO; cdecl;
function BIO_set_next(b: PBIO; next: PBIO): void; cdecl;
function BIO_get_retry_BIO(bio: PBIO; reason: PIdC_INT): PBIO; cdecl;
function BIO_get_retry_reason(bio: PBIO): TIdC_INT; cdecl;
function BIO_set_retry_reason(bio: PBIO; reason: TIdC_INT): void; cdecl;
function BIO_dup_chain(_in: PBIO): PBIO; cdecl;
function BIO_nread0(bio: PBIO; buf: PPIdAnsiChar): TIdC_INT; cdecl;
function BIO_nread(bio: PBIO; buf: PPIdAnsiChar; num: TIdC_INT): TIdC_INT; cdecl;
function BIO_nwrite0(bio: PBIO; buf: PPIdAnsiChar): TIdC_INT; cdecl;
function BIO_nwrite(bio: PBIO; buf: PPIdAnsiChar; num: TIdC_INT): TIdC_INT; cdecl;
function BIO_s_mem: PBIO_METHOD; cdecl;
function BIO_s_dgram_mem: PBIO_METHOD; cdecl;
function BIO_s_secmem: PBIO_METHOD; cdecl;
function BIO_new_mem_buf(buf: Pointer; len: TIdC_INT): PBIO; cdecl;
function BIO_s_socket: PBIO_METHOD; cdecl;
function BIO_s_connect: PBIO_METHOD; cdecl;
function BIO_s_accept: PBIO_METHOD; cdecl;
function BIO_s_fd: PBIO_METHOD; cdecl;
function BIO_s_log: PBIO_METHOD; cdecl;
function BIO_s_bio: PBIO_METHOD; cdecl;
function BIO_s_null: PBIO_METHOD; cdecl;
function BIO_f_null: PBIO_METHOD; cdecl;
function BIO_f_buffer: PBIO_METHOD; cdecl;
function BIO_f_readbuffer: PBIO_METHOD; cdecl;
function BIO_f_linebuffer: PBIO_METHOD; cdecl;
function BIO_f_nbio_test: PBIO_METHOD; cdecl;
function BIO_f_prefix: PBIO_METHOD; cdecl;
function BIO_s_core: PBIO_METHOD; cdecl;
function BIO_s_dgram_pair: PBIO_METHOD; cdecl;
function BIO_s_datagram: PBIO_METHOD; cdecl;
function BIO_dgram_non_fatal_error(error: TIdC_INT): TIdC_INT; cdecl;
function BIO_new_dgram(fd: TIdC_INT; close_flag: TIdC_INT): PBIO; cdecl;
function BIO_sock_should_retry(i: TIdC_INT): TIdC_INT; cdecl;
function BIO_sock_non_fatal_error(error: TIdC_INT): TIdC_INT; cdecl;
function BIO_err_is_non_fatal(errcode: TIdC_UINT): TIdC_INT; cdecl;
function BIO_socket_wait(fd: TIdC_INT; for_read: TIdC_INT; max_time: TIdC_TIMET): TIdC_INT; cdecl;
function BIO_wait(bio: PBIO; max_time: TIdC_TIMET; nap_milliseconds: TIdC_UINT): TIdC_INT; cdecl;
function BIO_do_connect_retry(bio: PBIO; timeout: TIdC_INT; nap_milliseconds: TIdC_INT): TIdC_INT; cdecl;
function BIO_fd_should_retry(i: TIdC_INT): TIdC_INT; cdecl;
function BIO_fd_non_fatal_error(error: TIdC_INT): TIdC_INT; cdecl;
function BIO_dump_cb(cb: TBIO_dump_cb_cb_cb; u: Pointer; s: Pointer; len: TIdC_INT): TIdC_INT; cdecl;
function BIO_dump_indent_cb(cb: TBIO_dump_cb_cb_cb; u: Pointer; s: Pointer; len: TIdC_INT; indent: TIdC_INT): TIdC_INT; cdecl;
function BIO_dump(b: PBIO; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl;
function BIO_dump_indent(b: PBIO; bytes: Pointer; len: TIdC_INT; indent: TIdC_INT): TIdC_INT; cdecl;
function BIO_dump_fp(fp: PFILE; s: Pointer; len: TIdC_INT): TIdC_INT; cdecl;
function BIO_dump_indent_fp(fp: PFILE; s: Pointer; len: TIdC_INT; indent: TIdC_INT): TIdC_INT; cdecl;
function BIO_hex_string(_out: PBIO; indent: TIdC_INT; width: TIdC_INT; data: Pointer; datalen: TIdC_INT): TIdC_INT; cdecl;
function BIO_ADDR_new: PBIO_ADDR; cdecl;
function BIO_ADDR_copy(dst: PBIO_ADDR; src: PBIO_ADDR): TIdC_INT; cdecl;
function BIO_ADDR_dup(ap: PBIO_ADDR): PBIO_ADDR; cdecl;
function BIO_ADDR_rawmake(ap: PBIO_ADDR; family: TIdC_INT; where: Pointer; wherelen: TIdC_SIZET; port: TIdC_USHORT): TIdC_INT; cdecl;
function BIO_ADDR_free(arg1: PBIO_ADDR): void; cdecl;
function BIO_ADDR_clear(ap: PBIO_ADDR): void; cdecl;
function BIO_ADDR_family(ap: PBIO_ADDR): TIdC_INT; cdecl;
function BIO_ADDR_rawaddress(ap: PBIO_ADDR; p: Pointer; l: PIdC_SIZET): TIdC_INT; cdecl;
function BIO_ADDR_rawport(ap: PBIO_ADDR): TIdC_USHORT; cdecl;
function BIO_ADDR_hostname_string(ap: PBIO_ADDR; numeric: TIdC_INT): PIdAnsiChar; cdecl;
function BIO_ADDR_service_string(ap: PBIO_ADDR; numeric: TIdC_INT): PIdAnsiChar; cdecl;
function BIO_ADDR_path_string(ap: PBIO_ADDR): PIdAnsiChar; cdecl;
function BIO_ADDRINFO_next(bai: PBIO_ADDRINFO): PBIO_ADDRINFO; cdecl;
function BIO_ADDRINFO_family(bai: PBIO_ADDRINFO): TIdC_INT; cdecl;
function BIO_ADDRINFO_socktype(bai: PBIO_ADDRINFO): TIdC_INT; cdecl;
function BIO_ADDRINFO_protocol(bai: PBIO_ADDRINFO): TIdC_INT; cdecl;
function BIO_ADDRINFO_address(bai: PBIO_ADDRINFO): PBIO_ADDR; cdecl;
function BIO_ADDRINFO_free(bai: PBIO_ADDRINFO): void; cdecl;
function BIO_parse_hostserv(hostserv: PIdAnsiChar; host: PPIdAnsiChar; service: PPIdAnsiChar; hostserv_prio: TBIO_hostserv_priorities): TIdC_INT; cdecl;
function BIO_lookup(host: PIdAnsiChar; service: PIdAnsiChar; lookup_type: TBIO_lookup_type; family: TIdC_INT; socktype: TIdC_INT; res: PPBIO_ADDRINFO): TIdC_INT; cdecl;
function BIO_lookup_ex(host: PIdAnsiChar; service: PIdAnsiChar; lookup_type: TIdC_INT; family: TIdC_INT; socktype: TIdC_INT; protocol: TIdC_INT; res: PPBIO_ADDRINFO): TIdC_INT; cdecl;
function BIO_sock_error(sock: TIdC_INT): TIdC_INT; cdecl;
function BIO_socket_ioctl(fd: TIdC_INT; _type: TIdC_LONG; arg: Pointer): TIdC_INT; cdecl;
function BIO_socket_nbio(fd: TIdC_INT; mode: TIdC_INT): TIdC_INT; cdecl;
function BIO_sock_init: TIdC_INT; cdecl;
function BIO_set_tcp_ndelay(sock: TIdC_INT; turn_on: TIdC_INT): TIdC_INT; cdecl;
function BIO_sock_info(sock: TIdC_INT; _type: TBIO_sock_info_type; info: PBIO_sock_info_u): TIdC_INT; cdecl;
function BIO_socket(domain: TIdC_INT; socktype: TIdC_INT; protocol: TIdC_INT; options: TIdC_INT): TIdC_INT; cdecl;
function BIO_connect(sock: TIdC_INT; addr: PBIO_ADDR; options: TIdC_INT): TIdC_INT; cdecl;
function BIO_bind(sock: TIdC_INT; addr: PBIO_ADDR; options: TIdC_INT): TIdC_INT; cdecl;
function BIO_listen(sock: TIdC_INT; addr: PBIO_ADDR; options: TIdC_INT): TIdC_INT; cdecl;
function BIO_accept_ex(accept_sock: TIdC_INT; addr: PBIO_ADDR; options: TIdC_INT): TIdC_INT; cdecl;
function BIO_closesocket(sock: TIdC_INT): TIdC_INT; cdecl;
function BIO_new_socket(sock: TIdC_INT; close_flag: TIdC_INT): PBIO; cdecl;
function BIO_new_connect(host_port: PIdAnsiChar): PBIO; cdecl;
function BIO_new_accept(host_port: PIdAnsiChar): PBIO; cdecl;
function BIO_new_fd(fd: TIdC_INT; close_flag: TIdC_INT): PBIO; cdecl;
function BIO_new_bio_pair(bio1: PPBIO; writebuf1: TIdC_SIZET; bio2: PPBIO; writebuf2: TIdC_SIZET): TIdC_INT; cdecl;
function BIO_new_bio_dgram_pair(bio1: PPBIO; writebuf1: TIdC_SIZET; bio2: PPBIO; writebuf2: TIdC_SIZET): TIdC_INT; cdecl;
function BIO_copy_next_retry(b: PBIO): void; cdecl;
function BIO_printf(bio: PBIO; format: PIdAnsiChar): TIdC_INT; cdecl;
function BIO_vprintf(bio: PBIO; format: PIdAnsiChar; args: Tva_list): TIdC_INT; cdecl;
function BIO_snprintf(buf: PIdAnsiChar; n: TIdC_SIZET; format: PIdAnsiChar): TIdC_INT; cdecl;
function BIO_vsnprintf(buf: PIdAnsiChar; n: TIdC_SIZET; format: PIdAnsiChar; args: Tva_list): TIdC_INT; cdecl;
function BIO_meth_new(_type: TIdC_INT; name: PIdAnsiChar): PBIO_METHOD; cdecl;
function BIO_meth_free(biom: PBIO_METHOD): void; cdecl;
function BIO_meth_set_write(biom: PBIO_METHOD; write: TBIO_meth_set_write_write_cb): TIdC_INT; cdecl;
function BIO_meth_set_write_ex(biom: PBIO_METHOD; bwrite: TBIO_meth_set_write_ex_bwrite_cb): TIdC_INT; cdecl;
function BIO_meth_set_sendmmsg(biom: PBIO_METHOD; f: TBIO_meth_set_sendmmsg_f_cb): TIdC_INT; cdecl;
function BIO_meth_set_read(biom: PBIO_METHOD; read: TBIO_meth_set_write_write_cb): TIdC_INT; cdecl;
function BIO_meth_set_read_ex(biom: PBIO_METHOD; bread: TBIO_meth_set_write_ex_bwrite_cb): TIdC_INT; cdecl;
function BIO_meth_set_recvmmsg(biom: PBIO_METHOD; f: TBIO_meth_set_sendmmsg_f_cb): TIdC_INT; cdecl;
function BIO_meth_set_puts(biom: PBIO_METHOD; puts: TBIO_meth_set_puts_puts_cb): TIdC_INT; cdecl;
function BIO_meth_set_gets(biom: PBIO_METHOD; ossl_gets: TBIO_meth_set_write_write_cb): TIdC_INT; cdecl;
function BIO_meth_set_ctrl(biom: PBIO_METHOD; ctrl: TBIO_meth_set_ctrl_ctrl_cb): TIdC_INT; cdecl;
function BIO_meth_set_create(biom: PBIO_METHOD; create: TBIO_meth_set_create_create_cb): TIdC_INT; cdecl;
function BIO_meth_set_destroy(biom: PBIO_METHOD; destroy: TBIO_meth_set_create_create_cb): TIdC_INT; cdecl;
function BIO_meth_set_callback_ctrl(biom: PBIO_METHOD; callback_ctrl: TBIO_meth_set_callback_ctrl_callback_ctrl_cb): TIdC_INT; cdecl;
function BIO_meth_get_write(biom: PBIO_METHOD): TBIO_meth_set_write_write_cb; cdecl; deprecated 'In OpenSSL 3_5_0';
function BIO_meth_get_write_ex(biom: PBIO_METHOD): TBIO_meth_set_write_ex_bwrite_cb; cdecl; deprecated 'In OpenSSL 3_5_0';
function BIO_meth_get_sendmmsg(biom: PBIO_METHOD): TBIO_meth_set_sendmmsg_f_cb; cdecl; deprecated 'In OpenSSL 3_5_0';
function BIO_meth_get_read(biom: PBIO_METHOD): TBIO_meth_set_write_write_cb; cdecl; deprecated 'In OpenSSL 3_5_0';
function BIO_meth_get_read_ex(biom: PBIO_METHOD): TBIO_meth_set_write_ex_bwrite_cb; cdecl; deprecated 'In OpenSSL 3_5_0';
function BIO_meth_get_recvmmsg(biom: PBIO_METHOD): TBIO_meth_set_sendmmsg_f_cb; cdecl; deprecated 'In OpenSSL 3_5_0';
function BIO_meth_get_puts(biom: PBIO_METHOD): TBIO_meth_set_puts_puts_cb; cdecl; deprecated 'In OpenSSL 3_5_0';
function BIO_meth_get_gets(biom: PBIO_METHOD): TBIO_meth_set_write_write_cb; cdecl; deprecated 'In OpenSSL 3_5_0';
function BIO_meth_get_ctrl(biom: PBIO_METHOD): TBIO_meth_set_ctrl_ctrl_cb; cdecl; deprecated 'In OpenSSL 3_5_0';
function BIO_meth_get_create(bion: PBIO_METHOD): TBIO_meth_set_create_create_cb; cdecl; deprecated 'In OpenSSL 3_5_0';
function BIO_meth_get_destroy(biom: PBIO_METHOD): TBIO_meth_set_create_create_cb; cdecl; deprecated 'In OpenSSL 3_5_0';
function BIO_meth_get_callback_ctrl(biom: PBIO_METHOD): TBIO_meth_set_callback_ctrl_callback_ctrl_cb; cdecl; deprecated 'In OpenSSL 3_5_0';
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// INLINE OR MACRO ROUTINES
// =============================================================================

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_ktls_send(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_ktls_recv(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_flags(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_retry_special(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_retry_read(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_retry_write(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_clear_retry_flags(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_retry_flags(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_should_read(a: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_should_write(a: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_should_io_special(a: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_retry_type(a: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_should_retry(a: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_app_data(s: Pointer; arg: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_app_data(s: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_nbio(b: Pointer; n: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_tfo(b: Pointer; n: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_conn_hostname(b: Pointer; name: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_conn_port(b: Pointer; port: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_conn_address(b: Pointer; addr: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_conn_ip_family(b: Pointer; f: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_conn_hostname(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_conn_port(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_conn_address(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_conn_ip_family(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_conn_mode(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_conn_mode(b: Pointer; n: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_sock_type(b: Pointer; t: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_sock_type(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get0_dgram_bio(b: Pointer; p: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_accept_name(b: Pointer; name: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_accept_port(b: Pointer; port: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_accept_name(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_accept_port(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_peer_name(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_peer_port(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_nbio_accept(b: Pointer; n: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_accept_bios(b: Pointer; bio: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_accept_ip_family(b: Pointer; f: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_accept_ip_family(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_tfo_accept(b: Pointer; n: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_bind_mode(b: Pointer; mode: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_bind_mode(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_do_connect(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_do_accept(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_do_handshake(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_fd(b: Pointer; fd: Pointer; c: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_fd(b: Pointer; c: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_fp(b: Pointer; fp: Pointer; c: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_fp(b: Pointer; fpp: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_seek(b: Pointer; ofs: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_tell(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_read_filename(b: Pointer; name: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_write_filename(b: Pointer; name: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_append_filename(b: Pointer; name: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_rw_filename(b: Pointer; name: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_ssl(b: Pointer; ssl: Pointer; c: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_ssl(b: Pointer; sslp: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_ssl_mode(b: Pointer; client: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_ssl_renegotiate_bytes(b: Pointer; num: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_num_renegotiates(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_ssl_renegotiate_timeout(b: Pointer; seconds: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_mem_data(b: Pointer; pp: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_mem_buf(b: Pointer; bm: Pointer; c: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_mem_ptr(b: Pointer; pp: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_mem_eof_return(b: Pointer; v: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_buffer_num_lines(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_buffer_size(b: Pointer; size: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_read_buffer_size(b: Pointer; size: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_write_buffer_size(b: Pointer; size: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_buffer_read_data(b: Pointer; buf: Pointer; num: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_reset(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_eof(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_close(b: Pointer; c: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_close(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_pending(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_wpending(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_flush(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_info_callback(b: Pointer; cbp: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_info_callback(b: Pointer; cb: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_write_buf_size(b: Pointer; size: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_write_buf_size(b: Pointer; size: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_make_bio_pair(b1: Pointer; b2: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_destroy_bio_pair(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_shutdown_wr(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_write_guarantee(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_read_request(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_ctrl_dgram_connect(b: Pointer; peer: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_ctrl_set_connected(b: Pointer; peer: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_dgram_recv_timedout(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_dgram_send_timedout(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_dgram_get_peer(b: Pointer; peer: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_dgram_set_peer(b: Pointer; peer: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_dgram_detect_peer_addr(b: Pointer; peer: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_dgram_get_mtu_overhead(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_dgram_get_local_addr_cap(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_dgram_get_local_addr_enable(b: Pointer; penable: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_dgram_set_local_addr_enable(b: Pointer; enable: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_dgram_get_effective_caps(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_dgram_get_caps(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_dgram_set_caps(b: Pointer; caps: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_dgram_get_no_trunc(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_dgram_set_no_trunc(b: Pointer; enable: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_dgram_get_mtu(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_dgram_set_mtu(b: Pointer; mtu: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_dgram_set0_local_addr(b: Pointer; addr: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_prefix(b: Pointer; p: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_set_indent(b: Pointer; i: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_indent(b: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function BIO_get_ex_new_index(l: Pointer; p: Pointer; newf: Pointer; dupf: Pointer; freef: Pointer): TIdC_INT; cdecl;


// =============================================================================
// OPENSSL STACK DEFINITIONS
// =============================================================================
type
  { TODO 1 -copenssl stack BIO definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_BIO = Pointer;
  {$EXTERNALSYM PSTACK_OF_BIO}

  { Original Stack Macros for BIO:
    SKM_DEFINE_STACK_OF_INTERNAL(BIO, BIO, BIO)
    sk_BIO_num(sk) OPENSSL_sk_num(ossl_check_const_BIO_sk_type(sk))
    sk_BIO_value(sk, idx) ((BIO *)OPENSSL_sk_value(ossl_check_const_BIO_sk_type(sk), (idx)))
    sk_BIO_new(cmp) ((STACK_OF(BIO) *)OPENSSL_sk_new(ossl_check_BIO_compfunc_type(cmp)))
    sk_BIO_new_null() ((STACK_OF(BIO) *)OPENSSL_sk_new_null())
    sk_BIO_new_reserve(cmp, n) ((STACK_OF(BIO) *)OPENSSL_sk_new_reserve(ossl_check_BIO_compfunc_type(cmp), (n)))
    sk_BIO_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_BIO_sk_type(sk), (n))
    sk_BIO_free(sk) OPENSSL_sk_free(ossl_check_BIO_sk_type(sk))
    sk_BIO_zero(sk) OPENSSL_sk_zero(ossl_check_BIO_sk_type(sk))
    sk_BIO_delete(sk, i) ((BIO *)OPENSSL_sk_delete(ossl_check_BIO_sk_type(sk), (i)))
    sk_BIO_delete_ptr(sk, ptr) ((BIO *)OPENSSL_sk_delete_ptr(ossl_check_BIO_sk_type(sk), ossl_check_BIO_type(ptr)))
    sk_BIO_push(sk, ptr) OPENSSL_sk_push(ossl_check_BIO_sk_type(sk), ossl_check_BIO_type(ptr))
    sk_BIO_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_BIO_sk_type(sk), ossl_check_BIO_type(ptr))
    sk_BIO_pop(sk) ((BIO *)OPENSSL_sk_pop(ossl_check_BIO_sk_type(sk)))
    sk_BIO_shift(sk) ((BIO *)OPENSSL_sk_shift(ossl_check_BIO_sk_type(sk)))
    sk_BIO_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_BIO_sk_type(sk), ossl_check_BIO_freefunc_type(freefunc))
    sk_BIO_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_BIO_sk_type(sk), ossl_check_BIO_type(ptr), (idx))
    sk_BIO_set(sk, idx, ptr) ((BIO *)OPENSSL_sk_set(ossl_check_BIO_sk_type(sk), (idx), ossl_check_BIO_type(ptr)))
    sk_BIO_find(sk, ptr) OPENSSL_sk_find(ossl_check_BIO_sk_type(sk), ossl_check_BIO_type(ptr))
    sk_BIO_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_BIO_sk_type(sk), ossl_check_BIO_type(ptr))
    sk_BIO_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_BIO_sk_type(sk), ossl_check_BIO_type(ptr), pnum)
    sk_BIO_sort(sk) OPENSSL_sk_sort(ossl_check_BIO_sk_type(sk))
    sk_BIO_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_BIO_sk_type(sk))
    sk_BIO_dup(sk) ((STACK_OF(BIO) *)OPENSSL_sk_dup(ossl_check_const_BIO_sk_type(sk)))
    sk_BIO_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(BIO) *)OPENSSL_sk_deep_copy(ossl_check_const_BIO_sk_type(sk), ossl_check_BIO_copyfunc_type(copyfunc), ossl_check_BIO_freefunc_type(freefunc)))
    sk_BIO_set_cmp_func(sk, cmp) ((sk_BIO_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_BIO_sk_type(sk), ossl_check_BIO_compfunc_type(cmp)))
  }


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

function BIO_get_new_index: TIdC_INT; cdecl external CLibCrypto name 'BIO_get_new_index';
function BIO_set_flags(b: PBIO; flags: TIdC_INT): void; cdecl external CLibCrypto name 'BIO_set_flags';
function BIO_test_flags(b: PBIO; flags: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_test_flags';
function BIO_clear_flags(b: PBIO; flags: TIdC_INT): void; cdecl external CLibCrypto name 'BIO_clear_flags';
function BIO_get_callback(b: PBIO): TBIO_callback_fn; cdecl external CLibCrypto name 'BIO_get_callback';
function BIO_set_callback(b: PBIO; callback: TBIO_callback_fn): void; cdecl external CLibCrypto name 'BIO_set_callback';
function BIO_debug_callback(bio: PBIO; cmd: TIdC_INT; argp: PIdAnsiChar; argi: TIdC_INT; argl: TIdC_LONG; ret: TIdC_LONG): TIdC_LONG; cdecl external CLibCrypto name 'BIO_debug_callback';
function BIO_get_callback_ex(b: PBIO): TBIO_callback_fn_ex; cdecl external CLibCrypto name 'BIO_get_callback_ex';
function BIO_set_callback_ex(b: PBIO; callback: TBIO_callback_fn_ex): void; cdecl external CLibCrypto name 'BIO_set_callback_ex';
function BIO_debug_callback_ex(bio: PBIO; oper: TIdC_INT; argp: PIdAnsiChar; len: TIdC_SIZET; argi: TIdC_INT; argl: TIdC_LONG; ret: TIdC_INT; processed: PIdC_SIZET): TIdC_LONG; cdecl external CLibCrypto name 'BIO_debug_callback_ex';
function BIO_get_callback_arg(b: PBIO): PIdAnsiChar; cdecl external CLibCrypto name 'BIO_get_callback_arg';
function BIO_set_callback_arg(b: PBIO; arg: PIdAnsiChar): void; cdecl external CLibCrypto name 'BIO_set_callback_arg';
function BIO_method_name(b: PBIO): PIdAnsiChar; cdecl external CLibCrypto name 'BIO_method_name';
function BIO_method_type(b: PBIO): TIdC_INT; cdecl external CLibCrypto name 'BIO_method_type';
function BIO_ctrl_pending(b: PBIO): TIdC_SIZET; cdecl external CLibCrypto name 'BIO_ctrl_pending';
function BIO_ctrl_wpending(b: PBIO): TIdC_SIZET; cdecl external CLibCrypto name 'BIO_ctrl_wpending';
function BIO_ctrl_get_write_guarantee(b: PBIO): TIdC_SIZET; cdecl external CLibCrypto name 'BIO_ctrl_get_write_guarantee';
function BIO_ctrl_get_read_request(b: PBIO): TIdC_SIZET; cdecl external CLibCrypto name 'BIO_ctrl_get_read_request';
function BIO_ctrl_reset_read_request(b: PBIO): TIdC_INT; cdecl external CLibCrypto name 'BIO_ctrl_reset_read_request';
function BIO_set_ex_data(bio: PBIO; idx: TIdC_INT; data: Pointer): TIdC_INT; cdecl external CLibCrypto name 'BIO_set_ex_data';
function BIO_get_ex_data(bio: PBIO; idx: TIdC_INT): Pointer; cdecl external CLibCrypto name 'BIO_get_ex_data';
function BIO_number_read(bio: PBIO): TIdC_UINT64; cdecl external CLibCrypto name 'BIO_number_read';
function BIO_number_written(bio: PBIO): TIdC_UINT64; cdecl external CLibCrypto name 'BIO_number_written';
function BIO_asn1_set_prefix(b: PBIO; prefix: Tasn1_ps_func; prefix_free: Tasn1_ps_func): TIdC_INT; cdecl external CLibCrypto name 'BIO_asn1_set_prefix';
function BIO_asn1_get_prefix(b: PBIO; pprefix: PPasn1_ps_func; pprefix_free: PPasn1_ps_func): TIdC_INT; cdecl external CLibCrypto name 'BIO_asn1_get_prefix';
function BIO_asn1_set_suffix(b: PBIO; suffix: Tasn1_ps_func; suffix_free: Tasn1_ps_func): TIdC_INT; cdecl external CLibCrypto name 'BIO_asn1_set_suffix';
function BIO_asn1_get_suffix(b: PBIO; psuffix: PPasn1_ps_func; psuffix_free: PPasn1_ps_func): TIdC_INT; cdecl external CLibCrypto name 'BIO_asn1_get_suffix';
function BIO_s_file: PBIO_METHOD; cdecl external CLibCrypto name 'BIO_s_file';
function BIO_new_file(filename: PIdAnsiChar; mode: PIdAnsiChar): PBIO; cdecl external CLibCrypto name 'BIO_new_file';
function BIO_new_from_core_bio(libctx: POSSL_LIB_CTX; corebio: POSSL_CORE_BIO): PBIO; cdecl external CLibCrypto name 'BIO_new_from_core_bio';
function BIO_new_fp(stream: PFILE; close_flag: TIdC_INT): PBIO; cdecl external CLibCrypto name 'BIO_new_fp';
function BIO_new_ex(libctx: POSSL_LIB_CTX; method: PBIO_METHOD): PBIO; cdecl external CLibCrypto name 'BIO_new_ex';
function BIO_new(_type: PBIO_METHOD): PBIO; cdecl external CLibCrypto name 'BIO_new';
function BIO_free(a: PBIO): TIdC_INT; cdecl external CLibCrypto name 'BIO_free';
function BIO_set_data(a: PBIO; ptr: Pointer): void; cdecl external CLibCrypto name 'BIO_set_data';
function BIO_get_data(a: PBIO): Pointer; cdecl external CLibCrypto name 'BIO_get_data';
function BIO_set_init(a: PBIO; init: TIdC_INT): void; cdecl external CLibCrypto name 'BIO_set_init';
function BIO_get_init(a: PBIO): TIdC_INT; cdecl external CLibCrypto name 'BIO_get_init';
function BIO_set_shutdown(a: PBIO; shut: TIdC_INT): void; cdecl external CLibCrypto name 'BIO_set_shutdown';
function BIO_get_shutdown(a: PBIO): TIdC_INT; cdecl external CLibCrypto name 'BIO_get_shutdown';
function BIO_vfree(a: PBIO): void; cdecl external CLibCrypto name 'BIO_vfree';
function BIO_up_ref(a: PBIO): TIdC_INT; cdecl external CLibCrypto name 'BIO_up_ref';
function BIO_read(b: PBIO; data: Pointer; dlen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_read';
function BIO_read_ex(b: PBIO; data: Pointer; dlen: TIdC_SIZET; readbytes: PIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'BIO_read_ex';
function BIO_recvmmsg(b: PBIO; msg: PBIO_MSG; stride: TIdC_SIZET; num_msg: TIdC_SIZET; flags: TIdC_UINT64; msgs_processed: PIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'BIO_recvmmsg';
function BIO_gets(bp: PBIO; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_gets';
function BIO_get_line(bio: PBIO; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_get_line';
function BIO_write(b: PBIO; data: Pointer; dlen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_write';
function BIO_write_ex(b: PBIO; data: Pointer; dlen: TIdC_SIZET; written: PIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'BIO_write_ex';
function BIO_sendmmsg(b: PBIO; msg: PBIO_MSG; stride: TIdC_SIZET; num_msg: TIdC_SIZET; flags: TIdC_UINT64; msgs_processed: PIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'BIO_sendmmsg';
function BIO_get_rpoll_descriptor(b: PBIO; desc: PBIO_POLL_DESCRIPTOR): TIdC_INT; cdecl external CLibCrypto name 'BIO_get_rpoll_descriptor';
function BIO_get_wpoll_descriptor(b: PBIO; desc: PBIO_POLL_DESCRIPTOR): TIdC_INT; cdecl external CLibCrypto name 'BIO_get_wpoll_descriptor';
function BIO_puts(bp: PBIO; buf: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'BIO_puts';
function BIO_indent(b: PBIO; indent: TIdC_INT; max: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_indent';
function BIO_ctrl(bp: PBIO; cmd: TIdC_INT; larg: TIdC_LONG; parg: Pointer): TIdC_LONG; cdecl external CLibCrypto name 'BIO_ctrl';
function BIO_callback_ctrl(b: PBIO; cmd: TIdC_INT; fp: Tbio_info_cb): TIdC_LONG; cdecl external CLibCrypto name 'BIO_callback_ctrl';
function BIO_ptr_ctrl(bp: PBIO; cmd: TIdC_INT; larg: TIdC_LONG): Pointer; cdecl external CLibCrypto name 'BIO_ptr_ctrl';
function BIO_int_ctrl(bp: PBIO; cmd: TIdC_INT; larg: TIdC_LONG; iarg: TIdC_INT): TIdC_LONG; cdecl external CLibCrypto name 'BIO_int_ctrl';
function BIO_push(b: PBIO; append: PBIO): PBIO; cdecl external CLibCrypto name 'BIO_push';
function BIO_pop(b: PBIO): PBIO; cdecl external CLibCrypto name 'BIO_pop';
function BIO_free_all(a: PBIO): void; cdecl external CLibCrypto name 'BIO_free_all';
function BIO_find_type(b: PBIO; bio_type: TIdC_INT): PBIO; cdecl external CLibCrypto name 'BIO_find_type';
function BIO_next(b: PBIO): PBIO; cdecl external CLibCrypto name 'BIO_next';
function BIO_set_next(b: PBIO; next: PBIO): void; cdecl external CLibCrypto name 'BIO_set_next';
function BIO_get_retry_BIO(bio: PBIO; reason: PIdC_INT): PBIO; cdecl external CLibCrypto name 'BIO_get_retry_BIO';
function BIO_get_retry_reason(bio: PBIO): TIdC_INT; cdecl external CLibCrypto name 'BIO_get_retry_reason';
function BIO_set_retry_reason(bio: PBIO; reason: TIdC_INT): void; cdecl external CLibCrypto name 'BIO_set_retry_reason';
function BIO_dup_chain(_in: PBIO): PBIO; cdecl external CLibCrypto name 'BIO_dup_chain';
function BIO_nread0(bio: PBIO; buf: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'BIO_nread0';
function BIO_nread(bio: PBIO; buf: PPIdAnsiChar; num: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_nread';
function BIO_nwrite0(bio: PBIO; buf: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'BIO_nwrite0';
function BIO_nwrite(bio: PBIO; buf: PPIdAnsiChar; num: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_nwrite';
function BIO_s_mem: PBIO_METHOD; cdecl external CLibCrypto name 'BIO_s_mem';
function BIO_s_dgram_mem: PBIO_METHOD; cdecl external CLibCrypto name 'BIO_s_dgram_mem';
function BIO_s_secmem: PBIO_METHOD; cdecl external CLibCrypto name 'BIO_s_secmem';
function BIO_new_mem_buf(buf: Pointer; len: TIdC_INT): PBIO; cdecl external CLibCrypto name 'BIO_new_mem_buf';
function BIO_s_socket: PBIO_METHOD; cdecl external CLibCrypto name 'BIO_s_socket';
function BIO_s_connect: PBIO_METHOD; cdecl external CLibCrypto name 'BIO_s_connect';
function BIO_s_accept: PBIO_METHOD; cdecl external CLibCrypto name 'BIO_s_accept';
function BIO_s_fd: PBIO_METHOD; cdecl external CLibCrypto name 'BIO_s_fd';
function BIO_s_log: PBIO_METHOD; cdecl external CLibCrypto name 'BIO_s_log';
function BIO_s_bio: PBIO_METHOD; cdecl external CLibCrypto name 'BIO_s_bio';
function BIO_s_null: PBIO_METHOD; cdecl external CLibCrypto name 'BIO_s_null';
function BIO_f_null: PBIO_METHOD; cdecl external CLibCrypto name 'BIO_f_null';
function BIO_f_buffer: PBIO_METHOD; cdecl external CLibCrypto name 'BIO_f_buffer';
function BIO_f_readbuffer: PBIO_METHOD; cdecl external CLibCrypto name 'BIO_f_readbuffer';
function BIO_f_linebuffer: PBIO_METHOD; cdecl external CLibCrypto name 'BIO_f_linebuffer';
function BIO_f_nbio_test: PBIO_METHOD; cdecl external CLibCrypto name 'BIO_f_nbio_test';
function BIO_f_prefix: PBIO_METHOD; cdecl external CLibCrypto name 'BIO_f_prefix';
function BIO_s_core: PBIO_METHOD; cdecl external CLibCrypto name 'BIO_s_core';
function BIO_s_dgram_pair: PBIO_METHOD; cdecl external CLibCrypto name 'BIO_s_dgram_pair';
function BIO_s_datagram: PBIO_METHOD; cdecl external CLibCrypto name 'BIO_s_datagram';
function BIO_dgram_non_fatal_error(error: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_dgram_non_fatal_error';
function BIO_new_dgram(fd: TIdC_INT; close_flag: TIdC_INT): PBIO; cdecl external CLibCrypto name 'BIO_new_dgram';
function BIO_sock_should_retry(i: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_sock_should_retry';
function BIO_sock_non_fatal_error(error: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_sock_non_fatal_error';
function BIO_err_is_non_fatal(errcode: TIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'BIO_err_is_non_fatal';
function BIO_socket_wait(fd: TIdC_INT; for_read: TIdC_INT; max_time: TIdC_TIMET): TIdC_INT; cdecl external CLibCrypto name 'BIO_socket_wait';
function BIO_wait(bio: PBIO; max_time: TIdC_TIMET; nap_milliseconds: TIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'BIO_wait';
function BIO_do_connect_retry(bio: PBIO; timeout: TIdC_INT; nap_milliseconds: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_do_connect_retry';
function BIO_fd_should_retry(i: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_fd_should_retry';
function BIO_fd_non_fatal_error(error: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_fd_non_fatal_error';
function BIO_dump_cb(cb: TBIO_dump_cb_cb_cb; u: Pointer; s: Pointer; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_dump_cb';
function BIO_dump_indent_cb(cb: TBIO_dump_cb_cb_cb; u: Pointer; s: Pointer; len: TIdC_INT; indent: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_dump_indent_cb';
function BIO_dump(b: PBIO; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_dump';
function BIO_dump_indent(b: PBIO; bytes: Pointer; len: TIdC_INT; indent: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_dump_indent';
function BIO_dump_fp(fp: PFILE; s: Pointer; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_dump_fp';
function BIO_dump_indent_fp(fp: PFILE; s: Pointer; len: TIdC_INT; indent: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_dump_indent_fp';
function BIO_hex_string(_out: PBIO; indent: TIdC_INT; width: TIdC_INT; data: Pointer; datalen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_hex_string';
function BIO_ADDR_new: PBIO_ADDR; cdecl external CLibCrypto name 'BIO_ADDR_new';
function BIO_ADDR_copy(dst: PBIO_ADDR; src: PBIO_ADDR): TIdC_INT; cdecl external CLibCrypto name 'BIO_ADDR_copy';
function BIO_ADDR_dup(ap: PBIO_ADDR): PBIO_ADDR; cdecl external CLibCrypto name 'BIO_ADDR_dup';
function BIO_ADDR_rawmake(ap: PBIO_ADDR; family: TIdC_INT; where: Pointer; wherelen: TIdC_SIZET; port: TIdC_USHORT): TIdC_INT; cdecl external CLibCrypto name 'BIO_ADDR_rawmake';
function BIO_ADDR_free(arg1: PBIO_ADDR): void; cdecl external CLibCrypto name 'BIO_ADDR_free';
function BIO_ADDR_clear(ap: PBIO_ADDR): void; cdecl external CLibCrypto name 'BIO_ADDR_clear';
function BIO_ADDR_family(ap: PBIO_ADDR): TIdC_INT; cdecl external CLibCrypto name 'BIO_ADDR_family';
function BIO_ADDR_rawaddress(ap: PBIO_ADDR; p: Pointer; l: PIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'BIO_ADDR_rawaddress';
function BIO_ADDR_rawport(ap: PBIO_ADDR): TIdC_USHORT; cdecl external CLibCrypto name 'BIO_ADDR_rawport';
function BIO_ADDR_hostname_string(ap: PBIO_ADDR; numeric: TIdC_INT): PIdAnsiChar; cdecl external CLibCrypto name 'BIO_ADDR_hostname_string';
function BIO_ADDR_service_string(ap: PBIO_ADDR; numeric: TIdC_INT): PIdAnsiChar; cdecl external CLibCrypto name 'BIO_ADDR_service_string';
function BIO_ADDR_path_string(ap: PBIO_ADDR): PIdAnsiChar; cdecl external CLibCrypto name 'BIO_ADDR_path_string';
function BIO_ADDRINFO_next(bai: PBIO_ADDRINFO): PBIO_ADDRINFO; cdecl external CLibCrypto name 'BIO_ADDRINFO_next';
function BIO_ADDRINFO_family(bai: PBIO_ADDRINFO): TIdC_INT; cdecl external CLibCrypto name 'BIO_ADDRINFO_family';
function BIO_ADDRINFO_socktype(bai: PBIO_ADDRINFO): TIdC_INT; cdecl external CLibCrypto name 'BIO_ADDRINFO_socktype';
function BIO_ADDRINFO_protocol(bai: PBIO_ADDRINFO): TIdC_INT; cdecl external CLibCrypto name 'BIO_ADDRINFO_protocol';
function BIO_ADDRINFO_address(bai: PBIO_ADDRINFO): PBIO_ADDR; cdecl external CLibCrypto name 'BIO_ADDRINFO_address';
function BIO_ADDRINFO_free(bai: PBIO_ADDRINFO): void; cdecl external CLibCrypto name 'BIO_ADDRINFO_free';
function BIO_parse_hostserv(hostserv: PIdAnsiChar; host: PPIdAnsiChar; service: PPIdAnsiChar; hostserv_prio: TBIO_hostserv_priorities): TIdC_INT; cdecl external CLibCrypto name 'BIO_parse_hostserv';
function BIO_lookup(host: PIdAnsiChar; service: PIdAnsiChar; lookup_type: TBIO_lookup_type; family: TIdC_INT; socktype: TIdC_INT; res: PPBIO_ADDRINFO): TIdC_INT; cdecl external CLibCrypto name 'BIO_lookup';
function BIO_lookup_ex(host: PIdAnsiChar; service: PIdAnsiChar; lookup_type: TIdC_INT; family: TIdC_INT; socktype: TIdC_INT; protocol: TIdC_INT; res: PPBIO_ADDRINFO): TIdC_INT; cdecl external CLibCrypto name 'BIO_lookup_ex';
function BIO_sock_error(sock: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_sock_error';
function BIO_socket_ioctl(fd: TIdC_INT; _type: TIdC_LONG; arg: Pointer): TIdC_INT; cdecl external CLibCrypto name 'BIO_socket_ioctl';
function BIO_socket_nbio(fd: TIdC_INT; mode: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_socket_nbio';
function BIO_sock_init: TIdC_INT; cdecl external CLibCrypto name 'BIO_sock_init';
function BIO_set_tcp_ndelay(sock: TIdC_INT; turn_on: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_set_tcp_ndelay';
function BIO_sock_info(sock: TIdC_INT; _type: TBIO_sock_info_type; info: PBIO_sock_info_u): TIdC_INT; cdecl external CLibCrypto name 'BIO_sock_info';
function BIO_socket(domain: TIdC_INT; socktype: TIdC_INT; protocol: TIdC_INT; options: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_socket';
function BIO_connect(sock: TIdC_INT; addr: PBIO_ADDR; options: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_connect';
function BIO_bind(sock: TIdC_INT; addr: PBIO_ADDR; options: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_bind';
function BIO_listen(sock: TIdC_INT; addr: PBIO_ADDR; options: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_listen';
function BIO_accept_ex(accept_sock: TIdC_INT; addr: PBIO_ADDR; options: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_accept_ex';
function BIO_closesocket(sock: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'BIO_closesocket';
function BIO_new_socket(sock: TIdC_INT; close_flag: TIdC_INT): PBIO; cdecl external CLibCrypto name 'BIO_new_socket';
function BIO_new_connect(host_port: PIdAnsiChar): PBIO; cdecl external CLibCrypto name 'BIO_new_connect';
function BIO_new_accept(host_port: PIdAnsiChar): PBIO; cdecl external CLibCrypto name 'BIO_new_accept';
function BIO_new_fd(fd: TIdC_INT; close_flag: TIdC_INT): PBIO; cdecl external CLibCrypto name 'BIO_new_fd';
function BIO_new_bio_pair(bio1: PPBIO; writebuf1: TIdC_SIZET; bio2: PPBIO; writebuf2: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'BIO_new_bio_pair';
function BIO_new_bio_dgram_pair(bio1: PPBIO; writebuf1: TIdC_SIZET; bio2: PPBIO; writebuf2: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'BIO_new_bio_dgram_pair';
function BIO_copy_next_retry(b: PBIO): void; cdecl external CLibCrypto name 'BIO_copy_next_retry';
function BIO_printf(bio: PBIO; format: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'BIO_printf';
function BIO_vprintf(bio: PBIO; format: PIdAnsiChar; args: Tva_list): TIdC_INT; cdecl external CLibCrypto name 'BIO_vprintf';
function BIO_snprintf(buf: PIdAnsiChar; n: TIdC_SIZET; format: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'BIO_snprintf';
function BIO_vsnprintf(buf: PIdAnsiChar; n: TIdC_SIZET; format: PIdAnsiChar; args: Tva_list): TIdC_INT; cdecl external CLibCrypto name 'BIO_vsnprintf';
function BIO_meth_new(_type: TIdC_INT; name: PIdAnsiChar): PBIO_METHOD; cdecl external CLibCrypto name 'BIO_meth_new';
function BIO_meth_free(biom: PBIO_METHOD): void; cdecl external CLibCrypto name 'BIO_meth_free';
function BIO_meth_set_write(biom: PBIO_METHOD; write: TBIO_meth_set_write_write_cb): TIdC_INT; cdecl external CLibCrypto name 'BIO_meth_set_write';
function BIO_meth_set_write_ex(biom: PBIO_METHOD; bwrite: TBIO_meth_set_write_ex_bwrite_cb): TIdC_INT; cdecl external CLibCrypto name 'BIO_meth_set_write_ex';
function BIO_meth_set_sendmmsg(biom: PBIO_METHOD; f: TBIO_meth_set_sendmmsg_f_cb): TIdC_INT; cdecl external CLibCrypto name 'BIO_meth_set_sendmmsg';
function BIO_meth_set_read(biom: PBIO_METHOD; read: TBIO_meth_set_write_write_cb): TIdC_INT; cdecl external CLibCrypto name 'BIO_meth_set_read';
function BIO_meth_set_read_ex(biom: PBIO_METHOD; bread: TBIO_meth_set_write_ex_bwrite_cb): TIdC_INT; cdecl external CLibCrypto name 'BIO_meth_set_read_ex';
function BIO_meth_set_recvmmsg(biom: PBIO_METHOD; f: TBIO_meth_set_sendmmsg_f_cb): TIdC_INT; cdecl external CLibCrypto name 'BIO_meth_set_recvmmsg';
function BIO_meth_set_puts(biom: PBIO_METHOD; puts: TBIO_meth_set_puts_puts_cb): TIdC_INT; cdecl external CLibCrypto name 'BIO_meth_set_puts';
function BIO_meth_set_gets(biom: PBIO_METHOD; ossl_gets: TBIO_meth_set_write_write_cb): TIdC_INT; cdecl external CLibCrypto name 'BIO_meth_set_gets';
function BIO_meth_set_ctrl(biom: PBIO_METHOD; ctrl: TBIO_meth_set_ctrl_ctrl_cb): TIdC_INT; cdecl external CLibCrypto name 'BIO_meth_set_ctrl';
function BIO_meth_set_create(biom: PBIO_METHOD; create: TBIO_meth_set_create_create_cb): TIdC_INT; cdecl external CLibCrypto name 'BIO_meth_set_create';
function BIO_meth_set_destroy(biom: PBIO_METHOD; destroy: TBIO_meth_set_create_create_cb): TIdC_INT; cdecl external CLibCrypto name 'BIO_meth_set_destroy';
function BIO_meth_set_callback_ctrl(biom: PBIO_METHOD; callback_ctrl: TBIO_meth_set_callback_ctrl_callback_ctrl_cb): TIdC_INT; cdecl external CLibCrypto name 'BIO_meth_set_callback_ctrl';
function BIO_meth_get_write(biom: PBIO_METHOD): TBIO_meth_set_write_write_cb; cdecl external CLibCrypto name 'BIO_meth_get_write';
function BIO_meth_get_write_ex(biom: PBIO_METHOD): TBIO_meth_set_write_ex_bwrite_cb; cdecl external CLibCrypto name 'BIO_meth_get_write_ex';
function BIO_meth_get_sendmmsg(biom: PBIO_METHOD): TBIO_meth_set_sendmmsg_f_cb; cdecl external CLibCrypto name 'BIO_meth_get_sendmmsg';
function BIO_meth_get_read(biom: PBIO_METHOD): TBIO_meth_set_write_write_cb; cdecl external CLibCrypto name 'BIO_meth_get_read';
function BIO_meth_get_read_ex(biom: PBIO_METHOD): TBIO_meth_set_write_ex_bwrite_cb; cdecl external CLibCrypto name 'BIO_meth_get_read_ex';
function BIO_meth_get_recvmmsg(biom: PBIO_METHOD): TBIO_meth_set_sendmmsg_f_cb; cdecl external CLibCrypto name 'BIO_meth_get_recvmmsg';
function BIO_meth_get_puts(biom: PBIO_METHOD): TBIO_meth_set_puts_puts_cb; cdecl external CLibCrypto name 'BIO_meth_get_puts';
function BIO_meth_get_gets(biom: PBIO_METHOD): TBIO_meth_set_write_write_cb; cdecl external CLibCrypto name 'BIO_meth_get_gets';
function BIO_meth_get_ctrl(biom: PBIO_METHOD): TBIO_meth_set_ctrl_ctrl_cb; cdecl external CLibCrypto name 'BIO_meth_get_ctrl';
function BIO_meth_get_create(bion: PBIO_METHOD): TBIO_meth_set_create_create_cb; cdecl external CLibCrypto name 'BIO_meth_get_create';
function BIO_meth_get_destroy(biom: PBIO_METHOD): TBIO_meth_set_create_create_cb; cdecl external CLibCrypto name 'BIO_meth_get_destroy';
function BIO_meth_get_callback_ctrl(biom: PBIO_METHOD): TBIO_meth_set_callback_ctrl_callback_ctrl_cb; cdecl external CLibCrypto name 'BIO_meth_get_callback_ctrl';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  BIO_get_new_index_procname = 'BIO_get_new_index';
  BIO_get_new_index_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_set_flags_procname = 'BIO_set_flags';
  BIO_set_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_test_flags_procname = 'BIO_test_flags';
  BIO_test_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_clear_flags_procname = 'BIO_clear_flags';
  BIO_clear_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_get_callback_procname = 'BIO_get_callback';
  BIO_get_callback_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_get_callback_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  BIO_set_callback_procname = 'BIO_set_callback';
  BIO_set_callback_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_set_callback_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  BIO_debug_callback_procname = 'BIO_debug_callback';
  BIO_debug_callback_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_debug_callback_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  BIO_get_callback_ex_procname = 'BIO_get_callback_ex';
  BIO_get_callback_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  BIO_set_callback_ex_procname = 'BIO_set_callback_ex';
  BIO_set_callback_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  BIO_debug_callback_ex_procname = 'BIO_debug_callback_ex';
  BIO_debug_callback_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  BIO_get_callback_arg_procname = 'BIO_get_callback_arg';
  BIO_get_callback_arg_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_set_callback_arg_procname = 'BIO_set_callback_arg';
  BIO_set_callback_arg_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_method_name_procname = 'BIO_method_name';
  BIO_method_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_method_type_procname = 'BIO_method_type';
  BIO_method_type_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_ctrl_pending_procname = 'BIO_ctrl_pending';
  BIO_ctrl_pending_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_ctrl_wpending_procname = 'BIO_ctrl_wpending';
  BIO_ctrl_wpending_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_ctrl_get_write_guarantee_procname = 'BIO_ctrl_get_write_guarantee';
  BIO_ctrl_get_write_guarantee_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_ctrl_get_read_request_procname = 'BIO_ctrl_get_read_request';
  BIO_ctrl_get_read_request_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_ctrl_reset_read_request_procname = 'BIO_ctrl_reset_read_request';
  BIO_ctrl_reset_read_request_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_set_ex_data_procname = 'BIO_set_ex_data';
  BIO_set_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_get_ex_data_procname = 'BIO_get_ex_data';
  BIO_get_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_number_read_procname = 'BIO_number_read';
  BIO_number_read_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_number_written_procname = 'BIO_number_written';
  BIO_number_written_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_asn1_set_prefix_procname = 'BIO_asn1_set_prefix';
  BIO_asn1_set_prefix_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_asn1_get_prefix_procname = 'BIO_asn1_get_prefix';
  BIO_asn1_get_prefix_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_asn1_set_suffix_procname = 'BIO_asn1_set_suffix';
  BIO_asn1_set_suffix_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_asn1_get_suffix_procname = 'BIO_asn1_get_suffix';
  BIO_asn1_get_suffix_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_s_file_procname = 'BIO_s_file';
  BIO_s_file_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_new_file_procname = 'BIO_new_file';
  BIO_new_file_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_new_from_core_bio_procname = 'BIO_new_from_core_bio';
  BIO_new_from_core_bio_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  BIO_new_fp_procname = 'BIO_new_fp';
  BIO_new_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_new_ex_procname = 'BIO_new_ex';
  BIO_new_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  BIO_new_procname = 'BIO_new';
  BIO_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_free_procname = 'BIO_free';
  BIO_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_set_data_procname = 'BIO_set_data';
  BIO_set_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_get_data_procname = 'BIO_get_data';
  BIO_get_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_set_init_procname = 'BIO_set_init';
  BIO_set_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_get_init_procname = 'BIO_get_init';
  BIO_get_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_set_shutdown_procname = 'BIO_set_shutdown';
  BIO_set_shutdown_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_get_shutdown_procname = 'BIO_get_shutdown';
  BIO_get_shutdown_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_vfree_procname = 'BIO_vfree';
  BIO_vfree_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_up_ref_procname = 'BIO_up_ref';
  BIO_up_ref_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_read_procname = 'BIO_read';
  BIO_read_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_read_ex_procname = 'BIO_read_ex';
  BIO_read_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  BIO_recvmmsg_procname = 'BIO_recvmmsg';
  BIO_recvmmsg_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  BIO_gets_procname = 'BIO_gets';
  BIO_gets_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_get_line_procname = 'BIO_get_line';
  BIO_get_line_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  BIO_write_procname = 'BIO_write';
  BIO_write_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_write_ex_procname = 'BIO_write_ex';
  BIO_write_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  BIO_sendmmsg_procname = 'BIO_sendmmsg';
  BIO_sendmmsg_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  BIO_get_rpoll_descriptor_procname = 'BIO_get_rpoll_descriptor';
  BIO_get_rpoll_descriptor_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  BIO_get_wpoll_descriptor_procname = 'BIO_get_wpoll_descriptor';
  BIO_get_wpoll_descriptor_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  BIO_puts_procname = 'BIO_puts';
  BIO_puts_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_indent_procname = 'BIO_indent';
  BIO_indent_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_ctrl_procname = 'BIO_ctrl';
  BIO_ctrl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_callback_ctrl_procname = 'BIO_callback_ctrl';
  BIO_callback_ctrl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_ptr_ctrl_procname = 'BIO_ptr_ctrl';
  BIO_ptr_ctrl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_int_ctrl_procname = 'BIO_int_ctrl';
  BIO_int_ctrl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_push_procname = 'BIO_push';
  BIO_push_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_pop_procname = 'BIO_pop';
  BIO_pop_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_free_all_procname = 'BIO_free_all';
  BIO_free_all_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_find_type_procname = 'BIO_find_type';
  BIO_find_type_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_next_procname = 'BIO_next';
  BIO_next_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_set_next_procname = 'BIO_set_next';
  BIO_set_next_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_get_retry_BIO_procname = 'BIO_get_retry_BIO';
  BIO_get_retry_BIO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_get_retry_reason_procname = 'BIO_get_retry_reason';
  BIO_get_retry_reason_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_set_retry_reason_procname = 'BIO_set_retry_reason';
  BIO_set_retry_reason_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_dup_chain_procname = 'BIO_dup_chain';
  BIO_dup_chain_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_nread0_procname = 'BIO_nread0';
  BIO_nread0_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_nread_procname = 'BIO_nread';
  BIO_nread_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_nwrite0_procname = 'BIO_nwrite0';
  BIO_nwrite0_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_nwrite_procname = 'BIO_nwrite';
  BIO_nwrite_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_s_mem_procname = 'BIO_s_mem';
  BIO_s_mem_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_s_dgram_mem_procname = 'BIO_s_dgram_mem';
  BIO_s_dgram_mem_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  BIO_s_secmem_procname = 'BIO_s_secmem';
  BIO_s_secmem_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_new_mem_buf_procname = 'BIO_new_mem_buf';
  BIO_new_mem_buf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_s_socket_procname = 'BIO_s_socket';
  BIO_s_socket_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_s_connect_procname = 'BIO_s_connect';
  BIO_s_connect_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_s_accept_procname = 'BIO_s_accept';
  BIO_s_accept_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_s_fd_procname = 'BIO_s_fd';
  BIO_s_fd_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_s_log_procname = 'BIO_s_log';
  BIO_s_log_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_s_bio_procname = 'BIO_s_bio';
  BIO_s_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_s_null_procname = 'BIO_s_null';
  BIO_s_null_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_f_null_procname = 'BIO_f_null';
  BIO_f_null_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_f_buffer_procname = 'BIO_f_buffer';
  BIO_f_buffer_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_f_readbuffer_procname = 'BIO_f_readbuffer';
  BIO_f_readbuffer_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  BIO_f_linebuffer_procname = 'BIO_f_linebuffer';
  BIO_f_linebuffer_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_f_nbio_test_procname = 'BIO_f_nbio_test';
  BIO_f_nbio_test_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_f_prefix_procname = 'BIO_f_prefix';
  BIO_f_prefix_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  BIO_s_core_procname = 'BIO_s_core';
  BIO_s_core_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  BIO_s_dgram_pair_procname = 'BIO_s_dgram_pair';
  BIO_s_dgram_pair_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  BIO_s_datagram_procname = 'BIO_s_datagram';
  BIO_s_datagram_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_dgram_non_fatal_error_procname = 'BIO_dgram_non_fatal_error';
  BIO_dgram_non_fatal_error_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_new_dgram_procname = 'BIO_new_dgram';
  BIO_new_dgram_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_sock_should_retry_procname = 'BIO_sock_should_retry';
  BIO_sock_should_retry_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_sock_non_fatal_error_procname = 'BIO_sock_non_fatal_error';
  BIO_sock_non_fatal_error_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_err_is_non_fatal_procname = 'BIO_err_is_non_fatal';
  BIO_err_is_non_fatal_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  BIO_socket_wait_procname = 'BIO_socket_wait';
  BIO_socket_wait_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  BIO_wait_procname = 'BIO_wait';
  BIO_wait_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  BIO_do_connect_retry_procname = 'BIO_do_connect_retry';
  BIO_do_connect_retry_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  BIO_fd_should_retry_procname = 'BIO_fd_should_retry';
  BIO_fd_should_retry_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_fd_non_fatal_error_procname = 'BIO_fd_non_fatal_error';
  BIO_fd_non_fatal_error_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_dump_cb_procname = 'BIO_dump_cb';
  BIO_dump_cb_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_dump_indent_cb_procname = 'BIO_dump_indent_cb';
  BIO_dump_indent_cb_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_dump_procname = 'BIO_dump';
  BIO_dump_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_dump_indent_procname = 'BIO_dump_indent';
  BIO_dump_indent_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_dump_fp_procname = 'BIO_dump_fp';
  BIO_dump_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_dump_indent_fp_procname = 'BIO_dump_indent_fp';
  BIO_dump_indent_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_hex_string_procname = 'BIO_hex_string';
  BIO_hex_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_ADDR_new_procname = 'BIO_ADDR_new';
  BIO_ADDR_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_ADDR_copy_procname = 'BIO_ADDR_copy';
  BIO_ADDR_copy_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  BIO_ADDR_dup_procname = 'BIO_ADDR_dup';
  BIO_ADDR_dup_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  BIO_ADDR_rawmake_procname = 'BIO_ADDR_rawmake';
  BIO_ADDR_rawmake_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_ADDR_free_procname = 'BIO_ADDR_free';
  BIO_ADDR_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_ADDR_clear_procname = 'BIO_ADDR_clear';
  BIO_ADDR_clear_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_ADDR_family_procname = 'BIO_ADDR_family';
  BIO_ADDR_family_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_ADDR_rawaddress_procname = 'BIO_ADDR_rawaddress';
  BIO_ADDR_rawaddress_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_ADDR_rawport_procname = 'BIO_ADDR_rawport';
  BIO_ADDR_rawport_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_ADDR_hostname_string_procname = 'BIO_ADDR_hostname_string';
  BIO_ADDR_hostname_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_ADDR_service_string_procname = 'BIO_ADDR_service_string';
  BIO_ADDR_service_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_ADDR_path_string_procname = 'BIO_ADDR_path_string';
  BIO_ADDR_path_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_ADDRINFO_next_procname = 'BIO_ADDRINFO_next';
  BIO_ADDRINFO_next_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_ADDRINFO_family_procname = 'BIO_ADDRINFO_family';
  BIO_ADDRINFO_family_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_ADDRINFO_socktype_procname = 'BIO_ADDRINFO_socktype';
  BIO_ADDRINFO_socktype_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_ADDRINFO_protocol_procname = 'BIO_ADDRINFO_protocol';
  BIO_ADDRINFO_protocol_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_ADDRINFO_address_procname = 'BIO_ADDRINFO_address';
  BIO_ADDRINFO_address_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_ADDRINFO_free_procname = 'BIO_ADDRINFO_free';
  BIO_ADDRINFO_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_parse_hostserv_procname = 'BIO_parse_hostserv';
  BIO_parse_hostserv_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_lookup_procname = 'BIO_lookup';
  BIO_lookup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_lookup_ex_procname = 'BIO_lookup_ex';
  BIO_lookup_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  BIO_sock_error_procname = 'BIO_sock_error';
  BIO_sock_error_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_socket_ioctl_procname = 'BIO_socket_ioctl';
  BIO_socket_ioctl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_socket_nbio_procname = 'BIO_socket_nbio';
  BIO_socket_nbio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_sock_init_procname = 'BIO_sock_init';
  BIO_sock_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_set_tcp_ndelay_procname = 'BIO_set_tcp_ndelay';
  BIO_set_tcp_ndelay_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_sock_info_procname = 'BIO_sock_info';
  BIO_sock_info_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_socket_procname = 'BIO_socket';
  BIO_socket_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_connect_procname = 'BIO_connect';
  BIO_connect_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_bind_procname = 'BIO_bind';
  BIO_bind_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  BIO_listen_procname = 'BIO_listen';
  BIO_listen_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_accept_ex_procname = 'BIO_accept_ex';
  BIO_accept_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_closesocket_procname = 'BIO_closesocket';
  BIO_closesocket_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_new_socket_procname = 'BIO_new_socket';
  BIO_new_socket_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_new_connect_procname = 'BIO_new_connect';
  BIO_new_connect_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_new_accept_procname = 'BIO_new_accept';
  BIO_new_accept_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_new_fd_procname = 'BIO_new_fd';
  BIO_new_fd_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_new_bio_pair_procname = 'BIO_new_bio_pair';
  BIO_new_bio_pair_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_new_bio_dgram_pair_procname = 'BIO_new_bio_dgram_pair';
  BIO_new_bio_dgram_pair_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  BIO_copy_next_retry_procname = 'BIO_copy_next_retry';
  BIO_copy_next_retry_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_printf_procname = 'BIO_printf';
  BIO_printf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_vprintf_procname = 'BIO_vprintf';
  BIO_vprintf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_snprintf_procname = 'BIO_snprintf';
  BIO_snprintf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_vsnprintf_procname = 'BIO_vsnprintf';
  BIO_vsnprintf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_meth_new_procname = 'BIO_meth_new';
  BIO_meth_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_meth_free_procname = 'BIO_meth_free';
  BIO_meth_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_meth_set_write_procname = 'BIO_meth_set_write';
  BIO_meth_set_write_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_meth_set_write_ex_procname = 'BIO_meth_set_write_ex';
  BIO_meth_set_write_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  BIO_meth_set_sendmmsg_procname = 'BIO_meth_set_sendmmsg';
  BIO_meth_set_sendmmsg_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  BIO_meth_set_read_procname = 'BIO_meth_set_read';
  BIO_meth_set_read_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_meth_set_read_ex_procname = 'BIO_meth_set_read_ex';
  BIO_meth_set_read_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  BIO_meth_set_recvmmsg_procname = 'BIO_meth_set_recvmmsg';
  BIO_meth_set_recvmmsg_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  BIO_meth_set_puts_procname = 'BIO_meth_set_puts';
  BIO_meth_set_puts_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_meth_set_gets_procname = 'BIO_meth_set_gets';
  BIO_meth_set_gets_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_meth_set_ctrl_procname = 'BIO_meth_set_ctrl';
  BIO_meth_set_ctrl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_meth_set_create_procname = 'BIO_meth_set_create';
  BIO_meth_set_create_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_meth_set_destroy_procname = 'BIO_meth_set_destroy';
  BIO_meth_set_destroy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_meth_set_callback_ctrl_procname = 'BIO_meth_set_callback_ctrl';
  BIO_meth_set_callback_ctrl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_meth_get_write_procname = 'BIO_meth_get_write';
  BIO_meth_get_write_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_meth_get_write_removed = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  BIO_meth_get_write_ex_procname = 'BIO_meth_get_write_ex';
  BIO_meth_get_write_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  BIO_meth_get_write_ex_removed = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  BIO_meth_get_sendmmsg_procname = 'BIO_meth_get_sendmmsg';
  BIO_meth_get_sendmmsg_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
  BIO_meth_get_sendmmsg_removed = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  BIO_meth_get_read_procname = 'BIO_meth_get_read';
  BIO_meth_get_read_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_meth_get_read_removed = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  BIO_meth_get_read_ex_procname = 'BIO_meth_get_read_ex';
  BIO_meth_get_read_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  BIO_meth_get_read_ex_removed = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  BIO_meth_get_recvmmsg_procname = 'BIO_meth_get_recvmmsg';
  BIO_meth_get_recvmmsg_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
  BIO_meth_get_recvmmsg_removed = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  BIO_meth_get_puts_procname = 'BIO_meth_get_puts';
  BIO_meth_get_puts_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_meth_get_puts_removed = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  BIO_meth_get_gets_procname = 'BIO_meth_get_gets';
  BIO_meth_get_gets_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_meth_get_gets_removed = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  BIO_meth_get_ctrl_procname = 'BIO_meth_get_ctrl';
  BIO_meth_get_ctrl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_meth_get_ctrl_removed = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  BIO_meth_get_create_procname = 'BIO_meth_get_create';
  BIO_meth_get_create_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_meth_get_create_removed = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  BIO_meth_get_destroy_procname = 'BIO_meth_get_destroy';
  BIO_meth_get_destroy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_meth_get_destroy_removed = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  BIO_meth_get_callback_ctrl_procname = 'BIO_meth_get_callback_ctrl';
  BIO_meth_get_callback_ctrl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_meth_get_callback_ctrl_removed = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

// =============================================================================
// INLINE/MACRO IMPLEMENTATIONS
// =============================================================================

function BIO_get_ktls_send(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_ktls_send(b) (0)
  }
end;

function BIO_get_ktls_recv(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_ktls_recv(b) (0)
  }
end;

function BIO_get_flags(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_flags(b) BIO_test_flags(b, ~(0x0))
  }
end;

function BIO_set_retry_special(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_retry_special(b) \
    BIO_set_flags(b, (BIO_FLAGS_IO_SPECIAL | BIO_FLAGS_SHOULD_RETRY))
  }
end;

function BIO_set_retry_read(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_retry_read(b) \
    BIO_set_flags(b, (BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY))
  }
end;

function BIO_set_retry_write(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_retry_write(b) \
    BIO_set_flags(b, (BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY))
  }
end;

function BIO_clear_retry_flags(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_clear_retry_flags(b) \
    BIO_clear_flags(b, (BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY))
  }
end;

function BIO_get_retry_flags(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_retry_flags(b) \
    BIO_test_flags(b, (BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY))
  }
end;

function BIO_should_read(a: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_should_read(a) BIO_test_flags(a, BIO_FLAGS_READ)
  }
end;

function BIO_should_write(a: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_should_write(a) BIO_test_flags(a, BIO_FLAGS_WRITE)
  }
end;

function BIO_should_io_special(a: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_should_io_special(a) BIO_test_flags(a, BIO_FLAGS_IO_SPECIAL)
  }
end;

function BIO_retry_type(a: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_retry_type(a) BIO_test_flags(a, BIO_FLAGS_RWS)
  }
end;

function BIO_should_retry(a: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_should_retry(a) BIO_test_flags(a, BIO_FLAGS_SHOULD_RETRY)
  }
end;

function BIO_set_app_data(s: Pointer; arg: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_app_data(s, arg) BIO_set_ex_data(s, 0, arg)
  }
end;

function BIO_get_app_data(s: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_app_data(s) BIO_get_ex_data(s, 0)
  }
end;

function BIO_set_nbio(b: Pointer; n: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_nbio(b, n) BIO_ctrl(b, BIO_C_SET_NBIO, (n), NULL)
  }
end;

function BIO_set_tfo(b: Pointer; n: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_tfo(b, n) BIO_ctrl(b, BIO_C_SET_TFO, (n), NULL)
  }
end;

function BIO_set_conn_hostname(b: Pointer; name: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_conn_hostname(b, name) BIO_ctrl(b, BIO_C_SET_CONNECT, 0, \
    (char *)(name))
  }
end;

function BIO_set_conn_port(b: Pointer; port: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_conn_port(b, port) BIO_ctrl(b, BIO_C_SET_CONNECT, 1, \
    (char *)(port))
  }
end;

function BIO_set_conn_address(b: Pointer; addr: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_conn_address(b, addr) BIO_ctrl(b, BIO_C_SET_CONNECT, 2, \
    (char *)(addr))
  }
end;

function BIO_set_conn_ip_family(b: Pointer; f: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_conn_ip_family(b, f) BIO_int_ctrl(b, BIO_C_SET_CONNECT, 3, f)
  }
end;

function BIO_get_conn_hostname(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_conn_hostname(b) ((const char *)BIO_ptr_ctrl(b, BIO_C_GET_CONNECT, 0))
  }
end;

function BIO_get_conn_port(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_conn_port(b) ((const char *)BIO_ptr_ctrl(b, BIO_C_GET_CONNECT, 1))
  }
end;

function BIO_get_conn_address(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_conn_address(b) ((const BIO_ADDR *)BIO_ptr_ctrl(b, BIO_C_GET_CONNECT, 2))
  }
end;

function BIO_get_conn_ip_family(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_conn_ip_family(b) BIO_ctrl(b, BIO_C_GET_CONNECT, 3, NULL)
  }
end;

function BIO_get_conn_mode(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_conn_mode(b) BIO_ctrl(b, BIO_C_GET_CONNECT, 4, NULL)
  }
end;

function BIO_set_conn_mode(b: Pointer; n: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_conn_mode(b, n) BIO_ctrl(b, BIO_C_SET_CONNECT_MODE, (n), NULL)
  }
end;

function BIO_set_sock_type(b: Pointer; t: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_sock_type(b, t) BIO_ctrl(b, BIO_C_SET_SOCK_TYPE, (t), NULL)
  }
end;

function BIO_get_sock_type(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_sock_type(b) BIO_ctrl(b, BIO_C_GET_SOCK_TYPE, 0, NULL)
  }
end;

function BIO_get0_dgram_bio(b: Pointer; p: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get0_dgram_bio(b, p) BIO_ctrl(b, BIO_C_GET_DGRAM_BIO, 0, (void *)(BIO **)(p))
  }
end;

function BIO_set_accept_name(b: Pointer; name: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_accept_name(b, name) BIO_ctrl(b, BIO_C_SET_ACCEPT, 0, \
    (char *)(name))
  }
end;

function BIO_set_accept_port(b: Pointer; port: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_accept_port(b, port) BIO_ctrl(b, BIO_C_SET_ACCEPT, 1, \
    (char *)(port))
  }
end;

function BIO_get_accept_name(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_accept_name(b) ((const char *)BIO_ptr_ctrl(b, BIO_C_GET_ACCEPT, 0))
  }
end;

function BIO_get_accept_port(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_accept_port(b) ((const char *)BIO_ptr_ctrl(b, BIO_C_GET_ACCEPT, 1))
  }
end;

function BIO_get_peer_name(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_peer_name(b) ((const char *)BIO_ptr_ctrl(b, BIO_C_GET_ACCEPT, 2))
  }
end;

function BIO_get_peer_port(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_peer_port(b) ((const char *)BIO_ptr_ctrl(b, BIO_C_GET_ACCEPT, 3))
  }
end;

function BIO_set_nbio_accept(b: Pointer; n: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_nbio_accept(b, n) BIO_ctrl(b, BIO_C_SET_ACCEPT, 2, (n) ? (void *)"a" : NULL)
  }
end;

function BIO_set_accept_bios(b: Pointer; bio: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_accept_bios(b, bio) BIO_ctrl(b, BIO_C_SET_ACCEPT, 3, \
    (char *)(bio))
  }
end;

function BIO_set_accept_ip_family(b: Pointer; f: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_accept_ip_family(b, f) BIO_int_ctrl(b, BIO_C_SET_ACCEPT, 4, f)
  }
end;

function BIO_get_accept_ip_family(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_accept_ip_family(b) BIO_ctrl(b, BIO_C_GET_ACCEPT, 4, NULL)
  }
end;

function BIO_set_tfo_accept(b: Pointer; n: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_tfo_accept(b, n) BIO_ctrl(b, BIO_C_SET_ACCEPT, 5, (n) ? (void *)"a" : NULL)
  }
end;

function BIO_set_bind_mode(b: Pointer; mode: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_bind_mode(b, mode) BIO_ctrl(b, BIO_C_SET_BIND_MODE, mode, NULL)
  }
end;

function BIO_get_bind_mode(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_bind_mode(b) BIO_ctrl(b, BIO_C_GET_BIND_MODE, 0, NULL)
  }
end;

function BIO_do_connect(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_do_connect(b) BIO_do_handshake(b)
  }
end;

function BIO_do_accept(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_do_accept(b) BIO_do_handshake(b)
  }
end;

function BIO_do_handshake(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_do_handshake(b) BIO_ctrl(b, BIO_C_DO_STATE_MACHINE, 0, NULL)
  }
end;

function BIO_set_fd(b: Pointer; fd: Pointer; c: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_fd(b, fd, c) BIO_int_ctrl(b, BIO_C_SET_FD, c, fd)
  }
end;

function BIO_get_fd(b: Pointer; c: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_fd(b, c) BIO_ctrl(b, BIO_C_GET_FD, 0, (char *)(c))
  }
end;

function BIO_set_fp(b: Pointer; fp: Pointer; c: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_fp(b, fp, c) BIO_ctrl(b, BIO_C_SET_FILE_PTR, c, (char *)(fp))
  }
end;

function BIO_get_fp(b: Pointer; fpp: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_fp(b, fpp) BIO_ctrl(b, BIO_C_GET_FILE_PTR, 0, (char *)(fpp))
  }
end;

function BIO_seek(b: Pointer; ofs: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_seek(b, ofs) (int)BIO_ctrl(b, BIO_C_FILE_SEEK, ofs, NULL)
  }
end;

function BIO_tell(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_tell(b) (int)BIO_ctrl(b, BIO_C_FILE_TELL, 0, NULL)
  }
end;

function BIO_read_filename(b: Pointer; name: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_read_filename(b, name) (int)BIO_ctrl(b, BIO_C_SET_FILENAME, \
    BIO_CLOSE | BIO_FP_READ, (char *)(name))
  }
end;

function BIO_write_filename(b: Pointer; name: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_write_filename(b, name) (int)BIO_ctrl(b, BIO_C_SET_FILENAME, \
    BIO_CLOSE | BIO_FP_WRITE, name)
  }
end;

function BIO_append_filename(b: Pointer; name: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_append_filename(b, name) (int)BIO_ctrl(b, BIO_C_SET_FILENAME, \
    BIO_CLOSE | BIO_FP_APPEND, name)
  }
end;

function BIO_rw_filename(b: Pointer; name: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_rw_filename(b, name) (int)BIO_ctrl(b, BIO_C_SET_FILENAME, \
    BIO_CLOSE | BIO_FP_READ | BIO_FP_WRITE, name)
  }
end;

function BIO_set_ssl(b: Pointer; ssl: Pointer; c: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_ssl(b, ssl, c) BIO_ctrl(b, BIO_C_SET_SSL, c, (char *)(ssl))
  }
end;

function BIO_get_ssl(b: Pointer; sslp: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_ssl(b, sslp) BIO_ctrl(b, BIO_C_GET_SSL, 0, (char *)(sslp))
  }
end;

function BIO_set_ssl_mode(b: Pointer; client: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_ssl_mode(b, client) BIO_ctrl(b, BIO_C_SSL_MODE, client, NULL)
  }
end;

function BIO_set_ssl_renegotiate_bytes(b: Pointer; num: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_ssl_renegotiate_bytes(b, num) \
    BIO_ctrl(b, BIO_C_SET_SSL_RENEGOTIATE_BYTES, num, NULL)
  }
end;

function BIO_get_num_renegotiates(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_num_renegotiates(b) \
    BIO_ctrl(b, BIO_C_GET_SSL_NUM_RENEGOTIATES, 0, NULL)
  }
end;

function BIO_set_ssl_renegotiate_timeout(b: Pointer; seconds: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_ssl_renegotiate_timeout(b, seconds) \
    BIO_ctrl(b, BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT, seconds, NULL)
  }
end;

function BIO_get_mem_data(b: Pointer; pp: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_mem_data(b, pp) BIO_ctrl(b, BIO_CTRL_INFO, 0, (char *)(pp))
  }
end;

function BIO_set_mem_buf(b: Pointer; bm: Pointer; c: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_mem_buf(b, bm, c) BIO_ctrl(b, BIO_C_SET_BUF_MEM, c, (char *)(bm))
  }
end;

function BIO_get_mem_ptr(b: Pointer; pp: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_mem_ptr(b, pp) BIO_ctrl(b, BIO_C_GET_BUF_MEM_PTR, 0, \
    (char *)(pp))
  }
end;

function BIO_set_mem_eof_return(b: Pointer; v: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_mem_eof_return(b, v) \
    BIO_ctrl(b, BIO_C_SET_BUF_MEM_EOF_RETURN, v, NULL)
  }
end;

function BIO_get_buffer_num_lines(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_buffer_num_lines(b) BIO_ctrl(b, BIO_C_GET_BUFF_NUM_LINES, 0, NULL)
  }
end;

function BIO_set_buffer_size(b: Pointer; size: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_buffer_size(b, size) BIO_ctrl(b, BIO_C_SET_BUFF_SIZE, size, NULL)
  }
end;

function BIO_set_read_buffer_size(b: Pointer; size: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_read_buffer_size(b, size) BIO_int_ctrl(b, BIO_C_SET_BUFF_SIZE, size, 0)
  }
end;

function BIO_set_write_buffer_size(b: Pointer; size: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_write_buffer_size(b, size) BIO_int_ctrl(b, BIO_C_SET_BUFF_SIZE, size, 1)
  }
end;

function BIO_set_buffer_read_data(b: Pointer; buf: Pointer; num: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_buffer_read_data(b, buf, num) BIO_ctrl(b, BIO_C_SET_BUFF_READ_DATA, num, buf)
  }
end;

function BIO_reset(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_reset(b) (int)BIO_ctrl(b, BIO_CTRL_RESET, 0, NULL)
  }
end;

function BIO_eof(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_eof(b) (int)BIO_ctrl(b, BIO_CTRL_EOF, 0, NULL)
  }
end;

function BIO_set_close(b: Pointer; c: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_close(b, c) (int)BIO_ctrl(b, BIO_CTRL_SET_CLOSE, (c), NULL)
  }
end;

function BIO_get_close(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_close(b) (int)BIO_ctrl(b, BIO_CTRL_GET_CLOSE, 0, NULL)
  }
end;

function BIO_pending(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_pending(b) (int)BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL)
  }
end;

function BIO_wpending(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_wpending(b) (int)BIO_ctrl(b, BIO_CTRL_WPENDING, 0, NULL)
  }
end;

function BIO_flush(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_flush(b) (int)BIO_ctrl(b, BIO_CTRL_FLUSH, 0, NULL)
  }
end;

function BIO_get_info_callback(b: Pointer; cbp: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_info_callback(b, cbp) (int)BIO_ctrl(b, BIO_CTRL_GET_CALLBACK, 0, \
    cbp)
  }
end;

function BIO_set_info_callback(b: Pointer; cb: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_info_callback(b, cb) (int)BIO_callback_ctrl(b, BIO_CTRL_SET_CALLBACK, cb)
  }
end;

function BIO_set_write_buf_size(b: Pointer; size: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_write_buf_size(b, size) (int)BIO_ctrl(b, BIO_C_SET_WRITE_BUF_SIZE, size, NULL)
  }
end;

function BIO_get_write_buf_size(b: Pointer; size: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_write_buf_size(b, size) (size_t)BIO_ctrl(b, BIO_C_GET_WRITE_BUF_SIZE, size, NULL)
  }
end;

function BIO_make_bio_pair(b1: Pointer; b2: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_make_bio_pair(b1, b2) (int)BIO_ctrl(b1, BIO_C_MAKE_BIO_PAIR, 0, b2)
  }
end;

function BIO_destroy_bio_pair(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_destroy_bio_pair(b) (int)BIO_ctrl(b, BIO_C_DESTROY_BIO_PAIR, 0, NULL)
  }
end;

function BIO_shutdown_wr(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_shutdown_wr(b) (int)BIO_ctrl(b, BIO_C_SHUTDOWN_WR, 0, NULL)
  }
end;

function BIO_get_write_guarantee(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_write_guarantee(b) (int)BIO_ctrl(b, BIO_C_GET_WRITE_GUARANTEE, 0, NULL)
  }
end;

function BIO_get_read_request(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_read_request(b) (int)BIO_ctrl(b, BIO_C_GET_READ_REQUEST, 0, NULL)
  }
end;

function BIO_ctrl_dgram_connect(b: Pointer; peer: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_ctrl_dgram_connect(b, peer) \
    (int)BIO_ctrl(b, BIO_CTRL_DGRAM_CONNECT, 0, (char *)(peer))
  }
end;

function BIO_ctrl_set_connected(b: Pointer; peer: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_ctrl_set_connected(b, peer) \
    (int)BIO_ctrl(b, BIO_CTRL_DGRAM_SET_CONNECTED, 0, (char *)(peer))
  }
end;

function BIO_dgram_recv_timedout(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_dgram_recv_timedout(b) \
    (int)BIO_ctrl(b, BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, NULL)
  }
end;

function BIO_dgram_send_timedout(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_dgram_send_timedout(b) \
    (int)BIO_ctrl(b, BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP, 0, NULL)
  }
end;

function BIO_dgram_get_peer(b: Pointer; peer: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_dgram_get_peer(b, peer) \
    (int)BIO_ctrl(b, BIO_CTRL_DGRAM_GET_PEER, 0, (char *)(peer))
  }
end;

function BIO_dgram_set_peer(b: Pointer; peer: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_dgram_set_peer(b, peer) \
    (int)BIO_ctrl(b, BIO_CTRL_DGRAM_SET_PEER, 0, (char *)(peer))
  }
end;

function BIO_dgram_detect_peer_addr(b: Pointer; peer: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_dgram_detect_peer_addr(b, peer) \
    (int)BIO_ctrl(b, BIO_CTRL_DGRAM_DETECT_PEER_ADDR, 0, (char *)(peer))
  }
end;

function BIO_dgram_get_mtu_overhead(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_dgram_get_mtu_overhead(b) \
    (unsigned int)BIO_ctrl((b), BIO_CTRL_DGRAM_GET_MTU_OVERHEAD, 0, NULL)
  }
end;

function BIO_dgram_get_local_addr_cap(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_dgram_get_local_addr_cap(b) \
    (int)BIO_ctrl((b), BIO_CTRL_DGRAM_GET_LOCAL_ADDR_CAP, 0, NULL)
  }
end;

function BIO_dgram_get_local_addr_enable(b: Pointer; penable: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_dgram_get_local_addr_enable(b, penable) \
    (int)BIO_ctrl((b), BIO_CTRL_DGRAM_GET_LOCAL_ADDR_ENABLE, 0, (char *)(penable))
  }
end;

function BIO_dgram_set_local_addr_enable(b: Pointer; enable: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_dgram_set_local_addr_enable(b, enable) \
    (int)BIO_ctrl((b), BIO_CTRL_DGRAM_SET_LOCAL_ADDR_ENABLE, (enable), NULL)
  }
end;

function BIO_dgram_get_effective_caps(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_dgram_get_effective_caps(b) \
    (uint32_t)BIO_ctrl((b), BIO_CTRL_DGRAM_GET_EFFECTIVE_CAPS, 0, NULL)
  }
end;

function BIO_dgram_get_caps(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_dgram_get_caps(b) \
    (uint32_t)BIO_ctrl((b), BIO_CTRL_DGRAM_GET_CAPS, 0, NULL)
  }
end;

function BIO_dgram_set_caps(b: Pointer; caps: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_dgram_set_caps(b, caps) \
    (int)BIO_ctrl((b), BIO_CTRL_DGRAM_SET_CAPS, (long)(caps), NULL)
  }
end;

function BIO_dgram_get_no_trunc(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_dgram_get_no_trunc(b) \
    (unsigned int)BIO_ctrl((b), BIO_CTRL_DGRAM_GET_NO_TRUNC, 0, NULL)
  }
end;

function BIO_dgram_set_no_trunc(b: Pointer; enable: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_dgram_set_no_trunc(b, enable) \
    (int)BIO_ctrl((b), BIO_CTRL_DGRAM_SET_NO_TRUNC, (enable), NULL)
  }
end;

function BIO_dgram_get_mtu(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_dgram_get_mtu(b) \
    (unsigned int)BIO_ctrl((b), BIO_CTRL_DGRAM_GET_MTU, 0, NULL)
  }
end;

function BIO_dgram_set_mtu(b: Pointer; mtu: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_dgram_set_mtu(b, mtu) \
    (int)BIO_ctrl((b), BIO_CTRL_DGRAM_SET_MTU, (mtu), NULL)
  }
end;

function BIO_dgram_set0_local_addr(b: Pointer; addr: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_dgram_set0_local_addr(b, addr) \
    (int)BIO_ctrl((b), BIO_CTRL_DGRAM_SET0_LOCAL_ADDR, 0, (addr))
  }
end;

function BIO_set_prefix(b: Pointer; p: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_prefix(b, p) BIO_ctrl((b), BIO_CTRL_SET_PREFIX, 0, (void *)(p))
  }
end;

function BIO_set_indent(b: Pointer; i: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_set_indent(b, i) BIO_ctrl((b), BIO_CTRL_SET_INDENT, (i), NULL)
  }
end;

function BIO_get_indent(b: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_indent(b) BIO_ctrl((b), BIO_CTRL_GET_INDENT, 0, NULL)
  }
end;

function BIO_get_ex_new_index(l: Pointer; p: Pointer; newf: Pointer; dupf: Pointer; freef: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    BIO_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_BIO, l, p, newf, dupf, freef)
  }
end;

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_BIO_get_new_index: TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_new_index_procname);
end;

function ERR_BIO_set_flags(b: PBIO; flags: TIdC_INT): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_flags_procname);
end;

function ERR_BIO_test_flags(b: PBIO; flags: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_test_flags_procname);
end;

function ERR_BIO_clear_flags(b: PBIO; flags: TIdC_INT): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_clear_flags_procname);
end;

function ERR_BIO_get_callback(b: PBIO): TBIO_callback_fn; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_callback_procname);
end;

function ERR_BIO_set_callback(b: PBIO; callback: TBIO_callback_fn): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_callback_procname);
end;

function ERR_BIO_debug_callback(bio: PBIO; cmd: TIdC_INT; argp: PIdAnsiChar; argi: TIdC_INT; argl: TIdC_LONG; ret: TIdC_LONG): TIdC_LONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_debug_callback_procname);
end;

function ERR_BIO_get_callback_ex(b: PBIO): TBIO_callback_fn_ex; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_callback_ex_procname);
end;

function ERR_BIO_set_callback_ex(b: PBIO; callback: TBIO_callback_fn_ex): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_callback_ex_procname);
end;

function ERR_BIO_debug_callback_ex(bio: PBIO; oper: TIdC_INT; argp: PIdAnsiChar; len: TIdC_SIZET; argi: TIdC_INT; argl: TIdC_LONG; ret: TIdC_INT; processed: PIdC_SIZET): TIdC_LONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_debug_callback_ex_procname);
end;

function ERR_BIO_get_callback_arg(b: PBIO): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_callback_arg_procname);
end;

function ERR_BIO_set_callback_arg(b: PBIO; arg: PIdAnsiChar): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_callback_arg_procname);
end;

function ERR_BIO_method_name(b: PBIO): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_method_name_procname);
end;

function ERR_BIO_method_type(b: PBIO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_method_type_procname);
end;

function ERR_BIO_ctrl_pending(b: PBIO): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ctrl_pending_procname);
end;

function ERR_BIO_ctrl_wpending(b: PBIO): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ctrl_wpending_procname);
end;

function ERR_BIO_ctrl_get_write_guarantee(b: PBIO): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ctrl_get_write_guarantee_procname);
end;

function ERR_BIO_ctrl_get_read_request(b: PBIO): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ctrl_get_read_request_procname);
end;

function ERR_BIO_ctrl_reset_read_request(b: PBIO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ctrl_reset_read_request_procname);
end;

function ERR_BIO_set_ex_data(bio: PBIO; idx: TIdC_INT; data: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_ex_data_procname);
end;

function ERR_BIO_get_ex_data(bio: PBIO; idx: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_ex_data_procname);
end;

function ERR_BIO_number_read(bio: PBIO): TIdC_UINT64; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_number_read_procname);
end;

function ERR_BIO_number_written(bio: PBIO): TIdC_UINT64; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_number_written_procname);
end;

function ERR_BIO_asn1_set_prefix(b: PBIO; prefix: Tasn1_ps_func; prefix_free: Tasn1_ps_func): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_asn1_set_prefix_procname);
end;

function ERR_BIO_asn1_get_prefix(b: PBIO; pprefix: PPasn1_ps_func; pprefix_free: PPasn1_ps_func): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_asn1_get_prefix_procname);
end;

function ERR_BIO_asn1_set_suffix(b: PBIO; suffix: Tasn1_ps_func; suffix_free: Tasn1_ps_func): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_asn1_set_suffix_procname);
end;

function ERR_BIO_asn1_get_suffix(b: PBIO; psuffix: PPasn1_ps_func; psuffix_free: PPasn1_ps_func): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_asn1_get_suffix_procname);
end;

function ERR_BIO_s_file: PBIO_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_s_file_procname);
end;

function ERR_BIO_new_file(filename: PIdAnsiChar; mode: PIdAnsiChar): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_new_file_procname);
end;

function ERR_BIO_new_from_core_bio(libctx: POSSL_LIB_CTX; corebio: POSSL_CORE_BIO): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_new_from_core_bio_procname);
end;

function ERR_BIO_new_fp(stream: PFILE; close_flag: TIdC_INT): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_new_fp_procname);
end;

function ERR_BIO_new_ex(libctx: POSSL_LIB_CTX; method: PBIO_METHOD): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_new_ex_procname);
end;

function ERR_BIO_new(_type: PBIO_METHOD): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_new_procname);
end;

function ERR_BIO_free(a: PBIO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_free_procname);
end;

function ERR_BIO_set_data(a: PBIO; ptr: Pointer): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_data_procname);
end;

function ERR_BIO_get_data(a: PBIO): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_data_procname);
end;

function ERR_BIO_set_init(a: PBIO; init: TIdC_INT): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_init_procname);
end;

function ERR_BIO_get_init(a: PBIO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_init_procname);
end;

function ERR_BIO_set_shutdown(a: PBIO; shut: TIdC_INT): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_shutdown_procname);
end;

function ERR_BIO_get_shutdown(a: PBIO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_shutdown_procname);
end;

function ERR_BIO_vfree(a: PBIO): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_vfree_procname);
end;

function ERR_BIO_up_ref(a: PBIO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_up_ref_procname);
end;

function ERR_BIO_read(b: PBIO; data: Pointer; dlen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_read_procname);
end;

function ERR_BIO_read_ex(b: PBIO; data: Pointer; dlen: TIdC_SIZET; readbytes: PIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_read_ex_procname);
end;

function ERR_BIO_recvmmsg(b: PBIO; msg: PBIO_MSG; stride: TIdC_SIZET; num_msg: TIdC_SIZET; flags: TIdC_UINT64; msgs_processed: PIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_recvmmsg_procname);
end;

function ERR_BIO_gets(bp: PBIO; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_gets_procname);
end;

function ERR_BIO_get_line(bio: PBIO; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_line_procname);
end;

function ERR_BIO_write(b: PBIO; data: Pointer; dlen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_write_procname);
end;

function ERR_BIO_write_ex(b: PBIO; data: Pointer; dlen: TIdC_SIZET; written: PIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_write_ex_procname);
end;

function ERR_BIO_sendmmsg(b: PBIO; msg: PBIO_MSG; stride: TIdC_SIZET; num_msg: TIdC_SIZET; flags: TIdC_UINT64; msgs_processed: PIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_sendmmsg_procname);
end;

function ERR_BIO_get_rpoll_descriptor(b: PBIO; desc: PBIO_POLL_DESCRIPTOR): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_rpoll_descriptor_procname);
end;

function ERR_BIO_get_wpoll_descriptor(b: PBIO; desc: PBIO_POLL_DESCRIPTOR): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_wpoll_descriptor_procname);
end;

function ERR_BIO_puts(bp: PBIO; buf: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_puts_procname);
end;

function ERR_BIO_indent(b: PBIO; indent: TIdC_INT; max: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_indent_procname);
end;

function ERR_BIO_ctrl(bp: PBIO; cmd: TIdC_INT; larg: TIdC_LONG; parg: Pointer): TIdC_LONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ctrl_procname);
end;

function ERR_BIO_callback_ctrl(b: PBIO; cmd: TIdC_INT; fp: Tbio_info_cb): TIdC_LONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_callback_ctrl_procname);
end;

function ERR_BIO_ptr_ctrl(bp: PBIO; cmd: TIdC_INT; larg: TIdC_LONG): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ptr_ctrl_procname);
end;

function ERR_BIO_int_ctrl(bp: PBIO; cmd: TIdC_INT; larg: TIdC_LONG; iarg: TIdC_INT): TIdC_LONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_int_ctrl_procname);
end;

function ERR_BIO_push(b: PBIO; append: PBIO): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_push_procname);
end;

function ERR_BIO_pop(b: PBIO): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_pop_procname);
end;

function ERR_BIO_free_all(a: PBIO): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_free_all_procname);
end;

function ERR_BIO_find_type(b: PBIO; bio_type: TIdC_INT): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_find_type_procname);
end;

function ERR_BIO_next(b: PBIO): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_next_procname);
end;

function ERR_BIO_set_next(b: PBIO; next: PBIO): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_next_procname);
end;

function ERR_BIO_get_retry_BIO(bio: PBIO; reason: PIdC_INT): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_retry_BIO_procname);
end;

function ERR_BIO_get_retry_reason(bio: PBIO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_retry_reason_procname);
end;

function ERR_BIO_set_retry_reason(bio: PBIO; reason: TIdC_INT): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_retry_reason_procname);
end;

function ERR_BIO_dup_chain(_in: PBIO): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_dup_chain_procname);
end;

function ERR_BIO_nread0(bio: PBIO; buf: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_nread0_procname);
end;

function ERR_BIO_nread(bio: PBIO; buf: PPIdAnsiChar; num: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_nread_procname);
end;

function ERR_BIO_nwrite0(bio: PBIO; buf: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_nwrite0_procname);
end;

function ERR_BIO_nwrite(bio: PBIO; buf: PPIdAnsiChar; num: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_nwrite_procname);
end;

function ERR_BIO_s_mem: PBIO_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_s_mem_procname);
end;

function ERR_BIO_s_dgram_mem: PBIO_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_s_dgram_mem_procname);
end;

function ERR_BIO_s_secmem: PBIO_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_s_secmem_procname);
end;

function ERR_BIO_new_mem_buf(buf: Pointer; len: TIdC_INT): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_new_mem_buf_procname);
end;

function ERR_BIO_s_socket: PBIO_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_s_socket_procname);
end;

function ERR_BIO_s_connect: PBIO_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_s_connect_procname);
end;

function ERR_BIO_s_accept: PBIO_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_s_accept_procname);
end;

function ERR_BIO_s_fd: PBIO_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_s_fd_procname);
end;

function ERR_BIO_s_log: PBIO_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_s_log_procname);
end;

function ERR_BIO_s_bio: PBIO_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_s_bio_procname);
end;

function ERR_BIO_s_null: PBIO_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_s_null_procname);
end;

function ERR_BIO_f_null: PBIO_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_f_null_procname);
end;

function ERR_BIO_f_buffer: PBIO_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_f_buffer_procname);
end;

function ERR_BIO_f_readbuffer: PBIO_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_f_readbuffer_procname);
end;

function ERR_BIO_f_linebuffer: PBIO_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_f_linebuffer_procname);
end;

function ERR_BIO_f_nbio_test: PBIO_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_f_nbio_test_procname);
end;

function ERR_BIO_f_prefix: PBIO_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_f_prefix_procname);
end;

function ERR_BIO_s_core: PBIO_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_s_core_procname);
end;

function ERR_BIO_s_dgram_pair: PBIO_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_s_dgram_pair_procname);
end;

function ERR_BIO_s_datagram: PBIO_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_s_datagram_procname);
end;

function ERR_BIO_dgram_non_fatal_error(error: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_dgram_non_fatal_error_procname);
end;

function ERR_BIO_new_dgram(fd: TIdC_INT; close_flag: TIdC_INT): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_new_dgram_procname);
end;

function ERR_BIO_sock_should_retry(i: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_sock_should_retry_procname);
end;

function ERR_BIO_sock_non_fatal_error(error: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_sock_non_fatal_error_procname);
end;

function ERR_BIO_err_is_non_fatal(errcode: TIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_err_is_non_fatal_procname);
end;

function ERR_BIO_socket_wait(fd: TIdC_INT; for_read: TIdC_INT; max_time: TIdC_TIMET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_socket_wait_procname);
end;

function ERR_BIO_wait(bio: PBIO; max_time: TIdC_TIMET; nap_milliseconds: TIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_wait_procname);
end;

function ERR_BIO_do_connect_retry(bio: PBIO; timeout: TIdC_INT; nap_milliseconds: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_do_connect_retry_procname);
end;

function ERR_BIO_fd_should_retry(i: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_fd_should_retry_procname);
end;

function ERR_BIO_fd_non_fatal_error(error: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_fd_non_fatal_error_procname);
end;

function ERR_BIO_dump_cb(cb: TBIO_dump_cb_cb_cb; u: Pointer; s: Pointer; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_dump_cb_procname);
end;

function ERR_BIO_dump_indent_cb(cb: TBIO_dump_cb_cb_cb; u: Pointer; s: Pointer; len: TIdC_INT; indent: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_dump_indent_cb_procname);
end;

function ERR_BIO_dump(b: PBIO; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_dump_procname);
end;

function ERR_BIO_dump_indent(b: PBIO; bytes: Pointer; len: TIdC_INT; indent: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_dump_indent_procname);
end;

function ERR_BIO_dump_fp(fp: PFILE; s: Pointer; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_dump_fp_procname);
end;

function ERR_BIO_dump_indent_fp(fp: PFILE; s: Pointer; len: TIdC_INT; indent: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_dump_indent_fp_procname);
end;

function ERR_BIO_hex_string(_out: PBIO; indent: TIdC_INT; width: TIdC_INT; data: Pointer; datalen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_hex_string_procname);
end;

function ERR_BIO_ADDR_new: PBIO_ADDR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDR_new_procname);
end;

function ERR_BIO_ADDR_copy(dst: PBIO_ADDR; src: PBIO_ADDR): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDR_copy_procname);
end;

function ERR_BIO_ADDR_dup(ap: PBIO_ADDR): PBIO_ADDR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDR_dup_procname);
end;

function ERR_BIO_ADDR_rawmake(ap: PBIO_ADDR; family: TIdC_INT; where: Pointer; wherelen: TIdC_SIZET; port: TIdC_USHORT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDR_rawmake_procname);
end;

function ERR_BIO_ADDR_free(arg1: PBIO_ADDR): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDR_free_procname);
end;

function ERR_BIO_ADDR_clear(ap: PBIO_ADDR): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDR_clear_procname);
end;

function ERR_BIO_ADDR_family(ap: PBIO_ADDR): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDR_family_procname);
end;

function ERR_BIO_ADDR_rawaddress(ap: PBIO_ADDR; p: Pointer; l: PIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDR_rawaddress_procname);
end;

function ERR_BIO_ADDR_rawport(ap: PBIO_ADDR): TIdC_USHORT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDR_rawport_procname);
end;

function ERR_BIO_ADDR_hostname_string(ap: PBIO_ADDR; numeric: TIdC_INT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDR_hostname_string_procname);
end;

function ERR_BIO_ADDR_service_string(ap: PBIO_ADDR; numeric: TIdC_INT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDR_service_string_procname);
end;

function ERR_BIO_ADDR_path_string(ap: PBIO_ADDR): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDR_path_string_procname);
end;

function ERR_BIO_ADDRINFO_next(bai: PBIO_ADDRINFO): PBIO_ADDRINFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDRINFO_next_procname);
end;

function ERR_BIO_ADDRINFO_family(bai: PBIO_ADDRINFO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDRINFO_family_procname);
end;

function ERR_BIO_ADDRINFO_socktype(bai: PBIO_ADDRINFO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDRINFO_socktype_procname);
end;

function ERR_BIO_ADDRINFO_protocol(bai: PBIO_ADDRINFO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDRINFO_protocol_procname);
end;

function ERR_BIO_ADDRINFO_address(bai: PBIO_ADDRINFO): PBIO_ADDR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDRINFO_address_procname);
end;

function ERR_BIO_ADDRINFO_free(bai: PBIO_ADDRINFO): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDRINFO_free_procname);
end;

function ERR_BIO_parse_hostserv(hostserv: PIdAnsiChar; host: PPIdAnsiChar; service: PPIdAnsiChar; hostserv_prio: TBIO_hostserv_priorities): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_parse_hostserv_procname);
end;

function ERR_BIO_lookup(host: PIdAnsiChar; service: PIdAnsiChar; lookup_type: TBIO_lookup_type; family: TIdC_INT; socktype: TIdC_INT; res: PPBIO_ADDRINFO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_lookup_procname);
end;

function ERR_BIO_lookup_ex(host: PIdAnsiChar; service: PIdAnsiChar; lookup_type: TIdC_INT; family: TIdC_INT; socktype: TIdC_INT; protocol: TIdC_INT; res: PPBIO_ADDRINFO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_lookup_ex_procname);
end;

function ERR_BIO_sock_error(sock: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_sock_error_procname);
end;

function ERR_BIO_socket_ioctl(fd: TIdC_INT; _type: TIdC_LONG; arg: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_socket_ioctl_procname);
end;

function ERR_BIO_socket_nbio(fd: TIdC_INT; mode: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_socket_nbio_procname);
end;

function ERR_BIO_sock_init: TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_sock_init_procname);
end;

function ERR_BIO_set_tcp_ndelay(sock: TIdC_INT; turn_on: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_tcp_ndelay_procname);
end;

function ERR_BIO_sock_info(sock: TIdC_INT; _type: TBIO_sock_info_type; info: PBIO_sock_info_u): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_sock_info_procname);
end;

function ERR_BIO_socket(domain: TIdC_INT; socktype: TIdC_INT; protocol: TIdC_INT; options: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_socket_procname);
end;

function ERR_BIO_connect(sock: TIdC_INT; addr: PBIO_ADDR; options: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_connect_procname);
end;

function ERR_BIO_bind(sock: TIdC_INT; addr: PBIO_ADDR; options: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_bind_procname);
end;

function ERR_BIO_listen(sock: TIdC_INT; addr: PBIO_ADDR; options: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_listen_procname);
end;

function ERR_BIO_accept_ex(accept_sock: TIdC_INT; addr: PBIO_ADDR; options: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_accept_ex_procname);
end;

function ERR_BIO_closesocket(sock: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_closesocket_procname);
end;

function ERR_BIO_new_socket(sock: TIdC_INT; close_flag: TIdC_INT): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_new_socket_procname);
end;

function ERR_BIO_new_connect(host_port: PIdAnsiChar): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_new_connect_procname);
end;

function ERR_BIO_new_accept(host_port: PIdAnsiChar): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_new_accept_procname);
end;

function ERR_BIO_new_fd(fd: TIdC_INT; close_flag: TIdC_INT): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_new_fd_procname);
end;

function ERR_BIO_new_bio_pair(bio1: PPBIO; writebuf1: TIdC_SIZET; bio2: PPBIO; writebuf2: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_new_bio_pair_procname);
end;

function ERR_BIO_new_bio_dgram_pair(bio1: PPBIO; writebuf1: TIdC_SIZET; bio2: PPBIO; writebuf2: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_new_bio_dgram_pair_procname);
end;

function ERR_BIO_copy_next_retry(b: PBIO): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_copy_next_retry_procname);
end;

function ERR_BIO_printf(bio: PBIO; format: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_printf_procname);
end;

function ERR_BIO_vprintf(bio: PBIO; format: PIdAnsiChar; args: Tva_list): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_vprintf_procname);
end;

function ERR_BIO_snprintf(buf: PIdAnsiChar; n: TIdC_SIZET; format: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_snprintf_procname);
end;

function ERR_BIO_vsnprintf(buf: PIdAnsiChar; n: TIdC_SIZET; format: PIdAnsiChar; args: Tva_list): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_vsnprintf_procname);
end;

function ERR_BIO_meth_new(_type: TIdC_INT; name: PIdAnsiChar): PBIO_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_meth_new_procname);
end;

function ERR_BIO_meth_free(biom: PBIO_METHOD): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_meth_free_procname);
end;

function ERR_BIO_meth_set_write(biom: PBIO_METHOD; write: TBIO_meth_set_write_write_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_meth_set_write_procname);
end;

function ERR_BIO_meth_set_write_ex(biom: PBIO_METHOD; bwrite: TBIO_meth_set_write_ex_bwrite_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_meth_set_write_ex_procname);
end;

function ERR_BIO_meth_set_sendmmsg(biom: PBIO_METHOD; f: TBIO_meth_set_sendmmsg_f_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_meth_set_sendmmsg_procname);
end;

function ERR_BIO_meth_set_read(biom: PBIO_METHOD; read: TBIO_meth_set_write_write_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_meth_set_read_procname);
end;

function ERR_BIO_meth_set_read_ex(biom: PBIO_METHOD; bread: TBIO_meth_set_write_ex_bwrite_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_meth_set_read_ex_procname);
end;

function ERR_BIO_meth_set_recvmmsg(biom: PBIO_METHOD; f: TBIO_meth_set_sendmmsg_f_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_meth_set_recvmmsg_procname);
end;

function ERR_BIO_meth_set_puts(biom: PBIO_METHOD; puts: TBIO_meth_set_puts_puts_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_meth_set_puts_procname);
end;

function ERR_BIO_meth_set_gets(biom: PBIO_METHOD; ossl_gets: TBIO_meth_set_write_write_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_meth_set_gets_procname);
end;

function ERR_BIO_meth_set_ctrl(biom: PBIO_METHOD; ctrl: TBIO_meth_set_ctrl_ctrl_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_meth_set_ctrl_procname);
end;

function ERR_BIO_meth_set_create(biom: PBIO_METHOD; create: TBIO_meth_set_create_create_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_meth_set_create_procname);
end;

function ERR_BIO_meth_set_destroy(biom: PBIO_METHOD; destroy: TBIO_meth_set_create_create_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_meth_set_destroy_procname);
end;

function ERR_BIO_meth_set_callback_ctrl(biom: PBIO_METHOD; callback_ctrl: TBIO_meth_set_callback_ctrl_callback_ctrl_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_meth_set_callback_ctrl_procname);
end;

function ERR_BIO_meth_get_write(biom: PBIO_METHOD): TBIO_meth_set_write_write_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_meth_get_write_procname);
end;

function ERR_BIO_meth_get_write_ex(biom: PBIO_METHOD): TBIO_meth_set_write_ex_bwrite_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_meth_get_write_ex_procname);
end;

function ERR_BIO_meth_get_sendmmsg(biom: PBIO_METHOD): TBIO_meth_set_sendmmsg_f_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_meth_get_sendmmsg_procname);
end;

function ERR_BIO_meth_get_read(biom: PBIO_METHOD): TBIO_meth_set_write_write_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_meth_get_read_procname);
end;

function ERR_BIO_meth_get_read_ex(biom: PBIO_METHOD): TBIO_meth_set_write_ex_bwrite_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_meth_get_read_ex_procname);
end;

function ERR_BIO_meth_get_recvmmsg(biom: PBIO_METHOD): TBIO_meth_set_sendmmsg_f_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_meth_get_recvmmsg_procname);
end;

function ERR_BIO_meth_get_puts(biom: PBIO_METHOD): TBIO_meth_set_puts_puts_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_meth_get_puts_procname);
end;

function ERR_BIO_meth_get_gets(biom: PBIO_METHOD): TBIO_meth_set_write_write_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_meth_get_gets_procname);
end;

function ERR_BIO_meth_get_ctrl(biom: PBIO_METHOD): TBIO_meth_set_ctrl_ctrl_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_meth_get_ctrl_procname);
end;

function ERR_BIO_meth_get_create(bion: PBIO_METHOD): TBIO_meth_set_create_create_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_meth_get_create_procname);
end;

function ERR_BIO_meth_get_destroy(biom: PBIO_METHOD): TBIO_meth_set_create_create_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_meth_get_destroy_procname);
end;

function ERR_BIO_meth_get_callback_ctrl(biom: PBIO_METHOD): TBIO_meth_set_callback_ctrl_callback_ctrl_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_meth_get_callback_ctrl_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  BIO_get_new_index := LoadLibFunction(ADllHandle, BIO_get_new_index_procname);
  FuncLoadError := not assigned(BIO_get_new_index);
  if FuncLoadError then
  begin
    {$if not defined(BIO_get_new_index_allownil)}
    BIO_get_new_index := ERR_BIO_get_new_index;
    {$ifend}
    {$if declared(BIO_get_new_index_introduced)}
    if LibVersion < BIO_get_new_index_introduced then
    begin
      {$if declared(FC_BIO_get_new_index)}
      BIO_get_new_index := FC_BIO_get_new_index;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_get_new_index_removed)}
    if BIO_get_new_index_removed <= LibVersion then
    begin
      {$if declared(_BIO_get_new_index)}
      BIO_get_new_index := _BIO_get_new_index;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_get_new_index_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_get_new_index');
    {$ifend}
  end;
  
  BIO_set_flags := LoadLibFunction(ADllHandle, BIO_set_flags_procname);
  FuncLoadError := not assigned(BIO_set_flags);
  if FuncLoadError then
  begin
    {$if not defined(BIO_set_flags_allownil)}
    BIO_set_flags := ERR_BIO_set_flags;
    {$ifend}
    {$if declared(BIO_set_flags_introduced)}
    if LibVersion < BIO_set_flags_introduced then
    begin
      {$if declared(FC_BIO_set_flags)}
      BIO_set_flags := FC_BIO_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_set_flags_removed)}
    if BIO_set_flags_removed <= LibVersion then
    begin
      {$if declared(_BIO_set_flags)}
      BIO_set_flags := _BIO_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_set_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_set_flags');
    {$ifend}
  end;
  
  BIO_test_flags := LoadLibFunction(ADllHandle, BIO_test_flags_procname);
  FuncLoadError := not assigned(BIO_test_flags);
  if FuncLoadError then
  begin
    {$if not defined(BIO_test_flags_allownil)}
    BIO_test_flags := ERR_BIO_test_flags;
    {$ifend}
    {$if declared(BIO_test_flags_introduced)}
    if LibVersion < BIO_test_flags_introduced then
    begin
      {$if declared(FC_BIO_test_flags)}
      BIO_test_flags := FC_BIO_test_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_test_flags_removed)}
    if BIO_test_flags_removed <= LibVersion then
    begin
      {$if declared(_BIO_test_flags)}
      BIO_test_flags := _BIO_test_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_test_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_test_flags');
    {$ifend}
  end;
  
  BIO_clear_flags := LoadLibFunction(ADllHandle, BIO_clear_flags_procname);
  FuncLoadError := not assigned(BIO_clear_flags);
  if FuncLoadError then
  begin
    {$if not defined(BIO_clear_flags_allownil)}
    BIO_clear_flags := ERR_BIO_clear_flags;
    {$ifend}
    {$if declared(BIO_clear_flags_introduced)}
    if LibVersion < BIO_clear_flags_introduced then
    begin
      {$if declared(FC_BIO_clear_flags)}
      BIO_clear_flags := FC_BIO_clear_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_clear_flags_removed)}
    if BIO_clear_flags_removed <= LibVersion then
    begin
      {$if declared(_BIO_clear_flags)}
      BIO_clear_flags := _BIO_clear_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_clear_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_clear_flags');
    {$ifend}
  end;
  
  BIO_get_callback := LoadLibFunction(ADllHandle, BIO_get_callback_procname);
  FuncLoadError := not assigned(BIO_get_callback);
  if FuncLoadError then
  begin
    {$if not defined(BIO_get_callback_allownil)}
    BIO_get_callback := ERR_BIO_get_callback;
    {$ifend}
    {$if declared(BIO_get_callback_introduced)}
    if LibVersion < BIO_get_callback_introduced then
    begin
      {$if declared(FC_BIO_get_callback)}
      BIO_get_callback := FC_BIO_get_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_get_callback_removed)}
    if BIO_get_callback_removed <= LibVersion then
    begin
      {$if declared(_BIO_get_callback)}
      BIO_get_callback := _BIO_get_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_get_callback_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_get_callback');
    {$ifend}
  end;
  
  BIO_set_callback := LoadLibFunction(ADllHandle, BIO_set_callback_procname);
  FuncLoadError := not assigned(BIO_set_callback);
  if FuncLoadError then
  begin
    {$if not defined(BIO_set_callback_allownil)}
    BIO_set_callback := ERR_BIO_set_callback;
    {$ifend}
    {$if declared(BIO_set_callback_introduced)}
    if LibVersion < BIO_set_callback_introduced then
    begin
      {$if declared(FC_BIO_set_callback)}
      BIO_set_callback := FC_BIO_set_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_set_callback_removed)}
    if BIO_set_callback_removed <= LibVersion then
    begin
      {$if declared(_BIO_set_callback)}
      BIO_set_callback := _BIO_set_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_set_callback_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_set_callback');
    {$ifend}
  end;
  
  BIO_debug_callback := LoadLibFunction(ADllHandle, BIO_debug_callback_procname);
  FuncLoadError := not assigned(BIO_debug_callback);
  if FuncLoadError then
  begin
    {$if not defined(BIO_debug_callback_allownil)}
    BIO_debug_callback := ERR_BIO_debug_callback;
    {$ifend}
    {$if declared(BIO_debug_callback_introduced)}
    if LibVersion < BIO_debug_callback_introduced then
    begin
      {$if declared(FC_BIO_debug_callback)}
      BIO_debug_callback := FC_BIO_debug_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_debug_callback_removed)}
    if BIO_debug_callback_removed <= LibVersion then
    begin
      {$if declared(_BIO_debug_callback)}
      BIO_debug_callback := _BIO_debug_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_debug_callback_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_debug_callback');
    {$ifend}
  end;
  
  BIO_get_callback_ex := LoadLibFunction(ADllHandle, BIO_get_callback_ex_procname);
  FuncLoadError := not assigned(BIO_get_callback_ex);
  if FuncLoadError then
  begin
    {$if not defined(BIO_get_callback_ex_allownil)}
    BIO_get_callback_ex := ERR_BIO_get_callback_ex;
    {$ifend}
    {$if declared(BIO_get_callback_ex_introduced)}
    if LibVersion < BIO_get_callback_ex_introduced then
    begin
      {$if declared(FC_BIO_get_callback_ex)}
      BIO_get_callback_ex := FC_BIO_get_callback_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_get_callback_ex_removed)}
    if BIO_get_callback_ex_removed <= LibVersion then
    begin
      {$if declared(_BIO_get_callback_ex)}
      BIO_get_callback_ex := _BIO_get_callback_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_get_callback_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_get_callback_ex');
    {$ifend}
  end;
  
  BIO_set_callback_ex := LoadLibFunction(ADllHandle, BIO_set_callback_ex_procname);
  FuncLoadError := not assigned(BIO_set_callback_ex);
  if FuncLoadError then
  begin
    {$if not defined(BIO_set_callback_ex_allownil)}
    BIO_set_callback_ex := ERR_BIO_set_callback_ex;
    {$ifend}
    {$if declared(BIO_set_callback_ex_introduced)}
    if LibVersion < BIO_set_callback_ex_introduced then
    begin
      {$if declared(FC_BIO_set_callback_ex)}
      BIO_set_callback_ex := FC_BIO_set_callback_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_set_callback_ex_removed)}
    if BIO_set_callback_ex_removed <= LibVersion then
    begin
      {$if declared(_BIO_set_callback_ex)}
      BIO_set_callback_ex := _BIO_set_callback_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_set_callback_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_set_callback_ex');
    {$ifend}
  end;
  
  BIO_debug_callback_ex := LoadLibFunction(ADllHandle, BIO_debug_callback_ex_procname);
  FuncLoadError := not assigned(BIO_debug_callback_ex);
  if FuncLoadError then
  begin
    {$if not defined(BIO_debug_callback_ex_allownil)}
    BIO_debug_callback_ex := ERR_BIO_debug_callback_ex;
    {$ifend}
    {$if declared(BIO_debug_callback_ex_introduced)}
    if LibVersion < BIO_debug_callback_ex_introduced then
    begin
      {$if declared(FC_BIO_debug_callback_ex)}
      BIO_debug_callback_ex := FC_BIO_debug_callback_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_debug_callback_ex_removed)}
    if BIO_debug_callback_ex_removed <= LibVersion then
    begin
      {$if declared(_BIO_debug_callback_ex)}
      BIO_debug_callback_ex := _BIO_debug_callback_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_debug_callback_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_debug_callback_ex');
    {$ifend}
  end;
  
  BIO_get_callback_arg := LoadLibFunction(ADllHandle, BIO_get_callback_arg_procname);
  FuncLoadError := not assigned(BIO_get_callback_arg);
  if FuncLoadError then
  begin
    {$if not defined(BIO_get_callback_arg_allownil)}
    BIO_get_callback_arg := ERR_BIO_get_callback_arg;
    {$ifend}
    {$if declared(BIO_get_callback_arg_introduced)}
    if LibVersion < BIO_get_callback_arg_introduced then
    begin
      {$if declared(FC_BIO_get_callback_arg)}
      BIO_get_callback_arg := FC_BIO_get_callback_arg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_get_callback_arg_removed)}
    if BIO_get_callback_arg_removed <= LibVersion then
    begin
      {$if declared(_BIO_get_callback_arg)}
      BIO_get_callback_arg := _BIO_get_callback_arg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_get_callback_arg_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_get_callback_arg');
    {$ifend}
  end;
  
  BIO_set_callback_arg := LoadLibFunction(ADllHandle, BIO_set_callback_arg_procname);
  FuncLoadError := not assigned(BIO_set_callback_arg);
  if FuncLoadError then
  begin
    {$if not defined(BIO_set_callback_arg_allownil)}
    BIO_set_callback_arg := ERR_BIO_set_callback_arg;
    {$ifend}
    {$if declared(BIO_set_callback_arg_introduced)}
    if LibVersion < BIO_set_callback_arg_introduced then
    begin
      {$if declared(FC_BIO_set_callback_arg)}
      BIO_set_callback_arg := FC_BIO_set_callback_arg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_set_callback_arg_removed)}
    if BIO_set_callback_arg_removed <= LibVersion then
    begin
      {$if declared(_BIO_set_callback_arg)}
      BIO_set_callback_arg := _BIO_set_callback_arg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_set_callback_arg_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_set_callback_arg');
    {$ifend}
  end;
  
  BIO_method_name := LoadLibFunction(ADllHandle, BIO_method_name_procname);
  FuncLoadError := not assigned(BIO_method_name);
  if FuncLoadError then
  begin
    {$if not defined(BIO_method_name_allownil)}
    BIO_method_name := ERR_BIO_method_name;
    {$ifend}
    {$if declared(BIO_method_name_introduced)}
    if LibVersion < BIO_method_name_introduced then
    begin
      {$if declared(FC_BIO_method_name)}
      BIO_method_name := FC_BIO_method_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_method_name_removed)}
    if BIO_method_name_removed <= LibVersion then
    begin
      {$if declared(_BIO_method_name)}
      BIO_method_name := _BIO_method_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_method_name_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_method_name');
    {$ifend}
  end;
  
  BIO_method_type := LoadLibFunction(ADllHandle, BIO_method_type_procname);
  FuncLoadError := not assigned(BIO_method_type);
  if FuncLoadError then
  begin
    {$if not defined(BIO_method_type_allownil)}
    BIO_method_type := ERR_BIO_method_type;
    {$ifend}
    {$if declared(BIO_method_type_introduced)}
    if LibVersion < BIO_method_type_introduced then
    begin
      {$if declared(FC_BIO_method_type)}
      BIO_method_type := FC_BIO_method_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_method_type_removed)}
    if BIO_method_type_removed <= LibVersion then
    begin
      {$if declared(_BIO_method_type)}
      BIO_method_type := _BIO_method_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_method_type_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_method_type');
    {$ifend}
  end;
  
  BIO_ctrl_pending := LoadLibFunction(ADllHandle, BIO_ctrl_pending_procname);
  FuncLoadError := not assigned(BIO_ctrl_pending);
  if FuncLoadError then
  begin
    {$if not defined(BIO_ctrl_pending_allownil)}
    BIO_ctrl_pending := ERR_BIO_ctrl_pending;
    {$ifend}
    {$if declared(BIO_ctrl_pending_introduced)}
    if LibVersion < BIO_ctrl_pending_introduced then
    begin
      {$if declared(FC_BIO_ctrl_pending)}
      BIO_ctrl_pending := FC_BIO_ctrl_pending;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_ctrl_pending_removed)}
    if BIO_ctrl_pending_removed <= LibVersion then
    begin
      {$if declared(_BIO_ctrl_pending)}
      BIO_ctrl_pending := _BIO_ctrl_pending;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_ctrl_pending_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_ctrl_pending');
    {$ifend}
  end;
  
  BIO_ctrl_wpending := LoadLibFunction(ADllHandle, BIO_ctrl_wpending_procname);
  FuncLoadError := not assigned(BIO_ctrl_wpending);
  if FuncLoadError then
  begin
    {$if not defined(BIO_ctrl_wpending_allownil)}
    BIO_ctrl_wpending := ERR_BIO_ctrl_wpending;
    {$ifend}
    {$if declared(BIO_ctrl_wpending_introduced)}
    if LibVersion < BIO_ctrl_wpending_introduced then
    begin
      {$if declared(FC_BIO_ctrl_wpending)}
      BIO_ctrl_wpending := FC_BIO_ctrl_wpending;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_ctrl_wpending_removed)}
    if BIO_ctrl_wpending_removed <= LibVersion then
    begin
      {$if declared(_BIO_ctrl_wpending)}
      BIO_ctrl_wpending := _BIO_ctrl_wpending;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_ctrl_wpending_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_ctrl_wpending');
    {$ifend}
  end;
  
  BIO_ctrl_get_write_guarantee := LoadLibFunction(ADllHandle, BIO_ctrl_get_write_guarantee_procname);
  FuncLoadError := not assigned(BIO_ctrl_get_write_guarantee);
  if FuncLoadError then
  begin
    {$if not defined(BIO_ctrl_get_write_guarantee_allownil)}
    BIO_ctrl_get_write_guarantee := ERR_BIO_ctrl_get_write_guarantee;
    {$ifend}
    {$if declared(BIO_ctrl_get_write_guarantee_introduced)}
    if LibVersion < BIO_ctrl_get_write_guarantee_introduced then
    begin
      {$if declared(FC_BIO_ctrl_get_write_guarantee)}
      BIO_ctrl_get_write_guarantee := FC_BIO_ctrl_get_write_guarantee;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_ctrl_get_write_guarantee_removed)}
    if BIO_ctrl_get_write_guarantee_removed <= LibVersion then
    begin
      {$if declared(_BIO_ctrl_get_write_guarantee)}
      BIO_ctrl_get_write_guarantee := _BIO_ctrl_get_write_guarantee;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_ctrl_get_write_guarantee_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_ctrl_get_write_guarantee');
    {$ifend}
  end;
  
  BIO_ctrl_get_read_request := LoadLibFunction(ADllHandle, BIO_ctrl_get_read_request_procname);
  FuncLoadError := not assigned(BIO_ctrl_get_read_request);
  if FuncLoadError then
  begin
    {$if not defined(BIO_ctrl_get_read_request_allownil)}
    BIO_ctrl_get_read_request := ERR_BIO_ctrl_get_read_request;
    {$ifend}
    {$if declared(BIO_ctrl_get_read_request_introduced)}
    if LibVersion < BIO_ctrl_get_read_request_introduced then
    begin
      {$if declared(FC_BIO_ctrl_get_read_request)}
      BIO_ctrl_get_read_request := FC_BIO_ctrl_get_read_request;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_ctrl_get_read_request_removed)}
    if BIO_ctrl_get_read_request_removed <= LibVersion then
    begin
      {$if declared(_BIO_ctrl_get_read_request)}
      BIO_ctrl_get_read_request := _BIO_ctrl_get_read_request;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_ctrl_get_read_request_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_ctrl_get_read_request');
    {$ifend}
  end;
  
  BIO_ctrl_reset_read_request := LoadLibFunction(ADllHandle, BIO_ctrl_reset_read_request_procname);
  FuncLoadError := not assigned(BIO_ctrl_reset_read_request);
  if FuncLoadError then
  begin
    {$if not defined(BIO_ctrl_reset_read_request_allownil)}
    BIO_ctrl_reset_read_request := ERR_BIO_ctrl_reset_read_request;
    {$ifend}
    {$if declared(BIO_ctrl_reset_read_request_introduced)}
    if LibVersion < BIO_ctrl_reset_read_request_introduced then
    begin
      {$if declared(FC_BIO_ctrl_reset_read_request)}
      BIO_ctrl_reset_read_request := FC_BIO_ctrl_reset_read_request;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_ctrl_reset_read_request_removed)}
    if BIO_ctrl_reset_read_request_removed <= LibVersion then
    begin
      {$if declared(_BIO_ctrl_reset_read_request)}
      BIO_ctrl_reset_read_request := _BIO_ctrl_reset_read_request;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_ctrl_reset_read_request_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_ctrl_reset_read_request');
    {$ifend}
  end;
  
  BIO_set_ex_data := LoadLibFunction(ADllHandle, BIO_set_ex_data_procname);
  FuncLoadError := not assigned(BIO_set_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(BIO_set_ex_data_allownil)}
    BIO_set_ex_data := ERR_BIO_set_ex_data;
    {$ifend}
    {$if declared(BIO_set_ex_data_introduced)}
    if LibVersion < BIO_set_ex_data_introduced then
    begin
      {$if declared(FC_BIO_set_ex_data)}
      BIO_set_ex_data := FC_BIO_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_set_ex_data_removed)}
    if BIO_set_ex_data_removed <= LibVersion then
    begin
      {$if declared(_BIO_set_ex_data)}
      BIO_set_ex_data := _BIO_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_set_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_set_ex_data');
    {$ifend}
  end;
  
  BIO_get_ex_data := LoadLibFunction(ADllHandle, BIO_get_ex_data_procname);
  FuncLoadError := not assigned(BIO_get_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(BIO_get_ex_data_allownil)}
    BIO_get_ex_data := ERR_BIO_get_ex_data;
    {$ifend}
    {$if declared(BIO_get_ex_data_introduced)}
    if LibVersion < BIO_get_ex_data_introduced then
    begin
      {$if declared(FC_BIO_get_ex_data)}
      BIO_get_ex_data := FC_BIO_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_get_ex_data_removed)}
    if BIO_get_ex_data_removed <= LibVersion then
    begin
      {$if declared(_BIO_get_ex_data)}
      BIO_get_ex_data := _BIO_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_get_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_get_ex_data');
    {$ifend}
  end;
  
  BIO_number_read := LoadLibFunction(ADllHandle, BIO_number_read_procname);
  FuncLoadError := not assigned(BIO_number_read);
  if FuncLoadError then
  begin
    {$if not defined(BIO_number_read_allownil)}
    BIO_number_read := ERR_BIO_number_read;
    {$ifend}
    {$if declared(BIO_number_read_introduced)}
    if LibVersion < BIO_number_read_introduced then
    begin
      {$if declared(FC_BIO_number_read)}
      BIO_number_read := FC_BIO_number_read;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_number_read_removed)}
    if BIO_number_read_removed <= LibVersion then
    begin
      {$if declared(_BIO_number_read)}
      BIO_number_read := _BIO_number_read;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_number_read_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_number_read');
    {$ifend}
  end;
  
  BIO_number_written := LoadLibFunction(ADllHandle, BIO_number_written_procname);
  FuncLoadError := not assigned(BIO_number_written);
  if FuncLoadError then
  begin
    {$if not defined(BIO_number_written_allownil)}
    BIO_number_written := ERR_BIO_number_written;
    {$ifend}
    {$if declared(BIO_number_written_introduced)}
    if LibVersion < BIO_number_written_introduced then
    begin
      {$if declared(FC_BIO_number_written)}
      BIO_number_written := FC_BIO_number_written;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_number_written_removed)}
    if BIO_number_written_removed <= LibVersion then
    begin
      {$if declared(_BIO_number_written)}
      BIO_number_written := _BIO_number_written;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_number_written_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_number_written');
    {$ifend}
  end;
  
  BIO_asn1_set_prefix := LoadLibFunction(ADllHandle, BIO_asn1_set_prefix_procname);
  FuncLoadError := not assigned(BIO_asn1_set_prefix);
  if FuncLoadError then
  begin
    {$if not defined(BIO_asn1_set_prefix_allownil)}
    BIO_asn1_set_prefix := ERR_BIO_asn1_set_prefix;
    {$ifend}
    {$if declared(BIO_asn1_set_prefix_introduced)}
    if LibVersion < BIO_asn1_set_prefix_introduced then
    begin
      {$if declared(FC_BIO_asn1_set_prefix)}
      BIO_asn1_set_prefix := FC_BIO_asn1_set_prefix;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_asn1_set_prefix_removed)}
    if BIO_asn1_set_prefix_removed <= LibVersion then
    begin
      {$if declared(_BIO_asn1_set_prefix)}
      BIO_asn1_set_prefix := _BIO_asn1_set_prefix;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_asn1_set_prefix_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_asn1_set_prefix');
    {$ifend}
  end;
  
  BIO_asn1_get_prefix := LoadLibFunction(ADllHandle, BIO_asn1_get_prefix_procname);
  FuncLoadError := not assigned(BIO_asn1_get_prefix);
  if FuncLoadError then
  begin
    {$if not defined(BIO_asn1_get_prefix_allownil)}
    BIO_asn1_get_prefix := ERR_BIO_asn1_get_prefix;
    {$ifend}
    {$if declared(BIO_asn1_get_prefix_introduced)}
    if LibVersion < BIO_asn1_get_prefix_introduced then
    begin
      {$if declared(FC_BIO_asn1_get_prefix)}
      BIO_asn1_get_prefix := FC_BIO_asn1_get_prefix;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_asn1_get_prefix_removed)}
    if BIO_asn1_get_prefix_removed <= LibVersion then
    begin
      {$if declared(_BIO_asn1_get_prefix)}
      BIO_asn1_get_prefix := _BIO_asn1_get_prefix;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_asn1_get_prefix_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_asn1_get_prefix');
    {$ifend}
  end;
  
  BIO_asn1_set_suffix := LoadLibFunction(ADllHandle, BIO_asn1_set_suffix_procname);
  FuncLoadError := not assigned(BIO_asn1_set_suffix);
  if FuncLoadError then
  begin
    {$if not defined(BIO_asn1_set_suffix_allownil)}
    BIO_asn1_set_suffix := ERR_BIO_asn1_set_suffix;
    {$ifend}
    {$if declared(BIO_asn1_set_suffix_introduced)}
    if LibVersion < BIO_asn1_set_suffix_introduced then
    begin
      {$if declared(FC_BIO_asn1_set_suffix)}
      BIO_asn1_set_suffix := FC_BIO_asn1_set_suffix;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_asn1_set_suffix_removed)}
    if BIO_asn1_set_suffix_removed <= LibVersion then
    begin
      {$if declared(_BIO_asn1_set_suffix)}
      BIO_asn1_set_suffix := _BIO_asn1_set_suffix;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_asn1_set_suffix_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_asn1_set_suffix');
    {$ifend}
  end;
  
  BIO_asn1_get_suffix := LoadLibFunction(ADllHandle, BIO_asn1_get_suffix_procname);
  FuncLoadError := not assigned(BIO_asn1_get_suffix);
  if FuncLoadError then
  begin
    {$if not defined(BIO_asn1_get_suffix_allownil)}
    BIO_asn1_get_suffix := ERR_BIO_asn1_get_suffix;
    {$ifend}
    {$if declared(BIO_asn1_get_suffix_introduced)}
    if LibVersion < BIO_asn1_get_suffix_introduced then
    begin
      {$if declared(FC_BIO_asn1_get_suffix)}
      BIO_asn1_get_suffix := FC_BIO_asn1_get_suffix;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_asn1_get_suffix_removed)}
    if BIO_asn1_get_suffix_removed <= LibVersion then
    begin
      {$if declared(_BIO_asn1_get_suffix)}
      BIO_asn1_get_suffix := _BIO_asn1_get_suffix;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_asn1_get_suffix_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_asn1_get_suffix');
    {$ifend}
  end;
  
  BIO_s_file := LoadLibFunction(ADllHandle, BIO_s_file_procname);
  FuncLoadError := not assigned(BIO_s_file);
  if FuncLoadError then
  begin
    {$if not defined(BIO_s_file_allownil)}
    BIO_s_file := ERR_BIO_s_file;
    {$ifend}
    {$if declared(BIO_s_file_introduced)}
    if LibVersion < BIO_s_file_introduced then
    begin
      {$if declared(FC_BIO_s_file)}
      BIO_s_file := FC_BIO_s_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_s_file_removed)}
    if BIO_s_file_removed <= LibVersion then
    begin
      {$if declared(_BIO_s_file)}
      BIO_s_file := _BIO_s_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_s_file_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_s_file');
    {$ifend}
  end;
  
  BIO_new_file := LoadLibFunction(ADllHandle, BIO_new_file_procname);
  FuncLoadError := not assigned(BIO_new_file);
  if FuncLoadError then
  begin
    {$if not defined(BIO_new_file_allownil)}
    BIO_new_file := ERR_BIO_new_file;
    {$ifend}
    {$if declared(BIO_new_file_introduced)}
    if LibVersion < BIO_new_file_introduced then
    begin
      {$if declared(FC_BIO_new_file)}
      BIO_new_file := FC_BIO_new_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_new_file_removed)}
    if BIO_new_file_removed <= LibVersion then
    begin
      {$if declared(_BIO_new_file)}
      BIO_new_file := _BIO_new_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_new_file_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_new_file');
    {$ifend}
  end;
  
  BIO_new_from_core_bio := LoadLibFunction(ADllHandle, BIO_new_from_core_bio_procname);
  FuncLoadError := not assigned(BIO_new_from_core_bio);
  if FuncLoadError then
  begin
    {$if not defined(BIO_new_from_core_bio_allownil)}
    BIO_new_from_core_bio := ERR_BIO_new_from_core_bio;
    {$ifend}
    {$if declared(BIO_new_from_core_bio_introduced)}
    if LibVersion < BIO_new_from_core_bio_introduced then
    begin
      {$if declared(FC_BIO_new_from_core_bio)}
      BIO_new_from_core_bio := FC_BIO_new_from_core_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_new_from_core_bio_removed)}
    if BIO_new_from_core_bio_removed <= LibVersion then
    begin
      {$if declared(_BIO_new_from_core_bio)}
      BIO_new_from_core_bio := _BIO_new_from_core_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_new_from_core_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_new_from_core_bio');
    {$ifend}
  end;
  
  BIO_new_fp := LoadLibFunction(ADllHandle, BIO_new_fp_procname);
  FuncLoadError := not assigned(BIO_new_fp);
  if FuncLoadError then
  begin
    {$if not defined(BIO_new_fp_allownil)}
    BIO_new_fp := ERR_BIO_new_fp;
    {$ifend}
    {$if declared(BIO_new_fp_introduced)}
    if LibVersion < BIO_new_fp_introduced then
    begin
      {$if declared(FC_BIO_new_fp)}
      BIO_new_fp := FC_BIO_new_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_new_fp_removed)}
    if BIO_new_fp_removed <= LibVersion then
    begin
      {$if declared(_BIO_new_fp)}
      BIO_new_fp := _BIO_new_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_new_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_new_fp');
    {$ifend}
  end;
  
  BIO_new_ex := LoadLibFunction(ADllHandle, BIO_new_ex_procname);
  FuncLoadError := not assigned(BIO_new_ex);
  if FuncLoadError then
  begin
    {$if not defined(BIO_new_ex_allownil)}
    BIO_new_ex := ERR_BIO_new_ex;
    {$ifend}
    {$if declared(BIO_new_ex_introduced)}
    if LibVersion < BIO_new_ex_introduced then
    begin
      {$if declared(FC_BIO_new_ex)}
      BIO_new_ex := FC_BIO_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_new_ex_removed)}
    if BIO_new_ex_removed <= LibVersion then
    begin
      {$if declared(_BIO_new_ex)}
      BIO_new_ex := _BIO_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_new_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_new_ex');
    {$ifend}
  end;
  
  BIO_new := LoadLibFunction(ADllHandle, BIO_new_procname);
  FuncLoadError := not assigned(BIO_new);
  if FuncLoadError then
  begin
    {$if not defined(BIO_new_allownil)}
    BIO_new := ERR_BIO_new;
    {$ifend}
    {$if declared(BIO_new_introduced)}
    if LibVersion < BIO_new_introduced then
    begin
      {$if declared(FC_BIO_new)}
      BIO_new := FC_BIO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_new_removed)}
    if BIO_new_removed <= LibVersion then
    begin
      {$if declared(_BIO_new)}
      BIO_new := _BIO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_new_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_new');
    {$ifend}
  end;
  
  BIO_free := LoadLibFunction(ADllHandle, BIO_free_procname);
  FuncLoadError := not assigned(BIO_free);
  if FuncLoadError then
  begin
    {$if not defined(BIO_free_allownil)}
    BIO_free := ERR_BIO_free;
    {$ifend}
    {$if declared(BIO_free_introduced)}
    if LibVersion < BIO_free_introduced then
    begin
      {$if declared(FC_BIO_free)}
      BIO_free := FC_BIO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_free_removed)}
    if BIO_free_removed <= LibVersion then
    begin
      {$if declared(_BIO_free)}
      BIO_free := _BIO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_free_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_free');
    {$ifend}
  end;
  
  BIO_set_data := LoadLibFunction(ADllHandle, BIO_set_data_procname);
  FuncLoadError := not assigned(BIO_set_data);
  if FuncLoadError then
  begin
    {$if not defined(BIO_set_data_allownil)}
    BIO_set_data := ERR_BIO_set_data;
    {$ifend}
    {$if declared(BIO_set_data_introduced)}
    if LibVersion < BIO_set_data_introduced then
    begin
      {$if declared(FC_BIO_set_data)}
      BIO_set_data := FC_BIO_set_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_set_data_removed)}
    if BIO_set_data_removed <= LibVersion then
    begin
      {$if declared(_BIO_set_data)}
      BIO_set_data := _BIO_set_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_set_data_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_set_data');
    {$ifend}
  end;
  
  BIO_get_data := LoadLibFunction(ADllHandle, BIO_get_data_procname);
  FuncLoadError := not assigned(BIO_get_data);
  if FuncLoadError then
  begin
    {$if not defined(BIO_get_data_allownil)}
    BIO_get_data := ERR_BIO_get_data;
    {$ifend}
    {$if declared(BIO_get_data_introduced)}
    if LibVersion < BIO_get_data_introduced then
    begin
      {$if declared(FC_BIO_get_data)}
      BIO_get_data := FC_BIO_get_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_get_data_removed)}
    if BIO_get_data_removed <= LibVersion then
    begin
      {$if declared(_BIO_get_data)}
      BIO_get_data := _BIO_get_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_get_data_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_get_data');
    {$ifend}
  end;
  
  BIO_set_init := LoadLibFunction(ADllHandle, BIO_set_init_procname);
  FuncLoadError := not assigned(BIO_set_init);
  if FuncLoadError then
  begin
    {$if not defined(BIO_set_init_allownil)}
    BIO_set_init := ERR_BIO_set_init;
    {$ifend}
    {$if declared(BIO_set_init_introduced)}
    if LibVersion < BIO_set_init_introduced then
    begin
      {$if declared(FC_BIO_set_init)}
      BIO_set_init := FC_BIO_set_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_set_init_removed)}
    if BIO_set_init_removed <= LibVersion then
    begin
      {$if declared(_BIO_set_init)}
      BIO_set_init := _BIO_set_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_set_init_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_set_init');
    {$ifend}
  end;
  
  BIO_get_init := LoadLibFunction(ADllHandle, BIO_get_init_procname);
  FuncLoadError := not assigned(BIO_get_init);
  if FuncLoadError then
  begin
    {$if not defined(BIO_get_init_allownil)}
    BIO_get_init := ERR_BIO_get_init;
    {$ifend}
    {$if declared(BIO_get_init_introduced)}
    if LibVersion < BIO_get_init_introduced then
    begin
      {$if declared(FC_BIO_get_init)}
      BIO_get_init := FC_BIO_get_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_get_init_removed)}
    if BIO_get_init_removed <= LibVersion then
    begin
      {$if declared(_BIO_get_init)}
      BIO_get_init := _BIO_get_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_get_init_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_get_init');
    {$ifend}
  end;
  
  BIO_set_shutdown := LoadLibFunction(ADllHandle, BIO_set_shutdown_procname);
  FuncLoadError := not assigned(BIO_set_shutdown);
  if FuncLoadError then
  begin
    {$if not defined(BIO_set_shutdown_allownil)}
    BIO_set_shutdown := ERR_BIO_set_shutdown;
    {$ifend}
    {$if declared(BIO_set_shutdown_introduced)}
    if LibVersion < BIO_set_shutdown_introduced then
    begin
      {$if declared(FC_BIO_set_shutdown)}
      BIO_set_shutdown := FC_BIO_set_shutdown;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_set_shutdown_removed)}
    if BIO_set_shutdown_removed <= LibVersion then
    begin
      {$if declared(_BIO_set_shutdown)}
      BIO_set_shutdown := _BIO_set_shutdown;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_set_shutdown_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_set_shutdown');
    {$ifend}
  end;
  
  BIO_get_shutdown := LoadLibFunction(ADllHandle, BIO_get_shutdown_procname);
  FuncLoadError := not assigned(BIO_get_shutdown);
  if FuncLoadError then
  begin
    {$if not defined(BIO_get_shutdown_allownil)}
    BIO_get_shutdown := ERR_BIO_get_shutdown;
    {$ifend}
    {$if declared(BIO_get_shutdown_introduced)}
    if LibVersion < BIO_get_shutdown_introduced then
    begin
      {$if declared(FC_BIO_get_shutdown)}
      BIO_get_shutdown := FC_BIO_get_shutdown;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_get_shutdown_removed)}
    if BIO_get_shutdown_removed <= LibVersion then
    begin
      {$if declared(_BIO_get_shutdown)}
      BIO_get_shutdown := _BIO_get_shutdown;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_get_shutdown_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_get_shutdown');
    {$ifend}
  end;
  
  BIO_vfree := LoadLibFunction(ADllHandle, BIO_vfree_procname);
  FuncLoadError := not assigned(BIO_vfree);
  if FuncLoadError then
  begin
    {$if not defined(BIO_vfree_allownil)}
    BIO_vfree := ERR_BIO_vfree;
    {$ifend}
    {$if declared(BIO_vfree_introduced)}
    if LibVersion < BIO_vfree_introduced then
    begin
      {$if declared(FC_BIO_vfree)}
      BIO_vfree := FC_BIO_vfree;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_vfree_removed)}
    if BIO_vfree_removed <= LibVersion then
    begin
      {$if declared(_BIO_vfree)}
      BIO_vfree := _BIO_vfree;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_vfree_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_vfree');
    {$ifend}
  end;
  
  BIO_up_ref := LoadLibFunction(ADllHandle, BIO_up_ref_procname);
  FuncLoadError := not assigned(BIO_up_ref);
  if FuncLoadError then
  begin
    {$if not defined(BIO_up_ref_allownil)}
    BIO_up_ref := ERR_BIO_up_ref;
    {$ifend}
    {$if declared(BIO_up_ref_introduced)}
    if LibVersion < BIO_up_ref_introduced then
    begin
      {$if declared(FC_BIO_up_ref)}
      BIO_up_ref := FC_BIO_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_up_ref_removed)}
    if BIO_up_ref_removed <= LibVersion then
    begin
      {$if declared(_BIO_up_ref)}
      BIO_up_ref := _BIO_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_up_ref_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_up_ref');
    {$ifend}
  end;
  
  BIO_read := LoadLibFunction(ADllHandle, BIO_read_procname);
  FuncLoadError := not assigned(BIO_read);
  if FuncLoadError then
  begin
    {$if not defined(BIO_read_allownil)}
    BIO_read := ERR_BIO_read;
    {$ifend}
    {$if declared(BIO_read_introduced)}
    if LibVersion < BIO_read_introduced then
    begin
      {$if declared(FC_BIO_read)}
      BIO_read := FC_BIO_read;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_read_removed)}
    if BIO_read_removed <= LibVersion then
    begin
      {$if declared(_BIO_read)}
      BIO_read := _BIO_read;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_read_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_read');
    {$ifend}
  end;
  
  BIO_read_ex := LoadLibFunction(ADllHandle, BIO_read_ex_procname);
  FuncLoadError := not assigned(BIO_read_ex);
  if FuncLoadError then
  begin
    {$if not defined(BIO_read_ex_allownil)}
    BIO_read_ex := ERR_BIO_read_ex;
    {$ifend}
    {$if declared(BIO_read_ex_introduced)}
    if LibVersion < BIO_read_ex_introduced then
    begin
      {$if declared(FC_BIO_read_ex)}
      BIO_read_ex := FC_BIO_read_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_read_ex_removed)}
    if BIO_read_ex_removed <= LibVersion then
    begin
      {$if declared(_BIO_read_ex)}
      BIO_read_ex := _BIO_read_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_read_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_read_ex');
    {$ifend}
  end;
  
  BIO_recvmmsg := LoadLibFunction(ADllHandle, BIO_recvmmsg_procname);
  FuncLoadError := not assigned(BIO_recvmmsg);
  if FuncLoadError then
  begin
    {$if not defined(BIO_recvmmsg_allownil)}
    BIO_recvmmsg := ERR_BIO_recvmmsg;
    {$ifend}
    {$if declared(BIO_recvmmsg_introduced)}
    if LibVersion < BIO_recvmmsg_introduced then
    begin
      {$if declared(FC_BIO_recvmmsg)}
      BIO_recvmmsg := FC_BIO_recvmmsg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_recvmmsg_removed)}
    if BIO_recvmmsg_removed <= LibVersion then
    begin
      {$if declared(_BIO_recvmmsg)}
      BIO_recvmmsg := _BIO_recvmmsg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_recvmmsg_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_recvmmsg');
    {$ifend}
  end;
  
  BIO_gets := LoadLibFunction(ADllHandle, BIO_gets_procname);
  FuncLoadError := not assigned(BIO_gets);
  if FuncLoadError then
  begin
    {$if not defined(BIO_gets_allownil)}
    BIO_gets := ERR_BIO_gets;
    {$ifend}
    {$if declared(BIO_gets_introduced)}
    if LibVersion < BIO_gets_introduced then
    begin
      {$if declared(FC_BIO_gets)}
      BIO_gets := FC_BIO_gets;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_gets_removed)}
    if BIO_gets_removed <= LibVersion then
    begin
      {$if declared(_BIO_gets)}
      BIO_gets := _BIO_gets;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_gets_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_gets');
    {$ifend}
  end;
  
  BIO_get_line := LoadLibFunction(ADllHandle, BIO_get_line_procname);
  FuncLoadError := not assigned(BIO_get_line);
  if FuncLoadError then
  begin
    {$if not defined(BIO_get_line_allownil)}
    BIO_get_line := ERR_BIO_get_line;
    {$ifend}
    {$if declared(BIO_get_line_introduced)}
    if LibVersion < BIO_get_line_introduced then
    begin
      {$if declared(FC_BIO_get_line)}
      BIO_get_line := FC_BIO_get_line;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_get_line_removed)}
    if BIO_get_line_removed <= LibVersion then
    begin
      {$if declared(_BIO_get_line)}
      BIO_get_line := _BIO_get_line;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_get_line_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_get_line');
    {$ifend}
  end;
  
  BIO_write := LoadLibFunction(ADllHandle, BIO_write_procname);
  FuncLoadError := not assigned(BIO_write);
  if FuncLoadError then
  begin
    {$if not defined(BIO_write_allownil)}
    BIO_write := ERR_BIO_write;
    {$ifend}
    {$if declared(BIO_write_introduced)}
    if LibVersion < BIO_write_introduced then
    begin
      {$if declared(FC_BIO_write)}
      BIO_write := FC_BIO_write;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_write_removed)}
    if BIO_write_removed <= LibVersion then
    begin
      {$if declared(_BIO_write)}
      BIO_write := _BIO_write;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_write_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_write');
    {$ifend}
  end;
  
  BIO_write_ex := LoadLibFunction(ADllHandle, BIO_write_ex_procname);
  FuncLoadError := not assigned(BIO_write_ex);
  if FuncLoadError then
  begin
    {$if not defined(BIO_write_ex_allownil)}
    BIO_write_ex := ERR_BIO_write_ex;
    {$ifend}
    {$if declared(BIO_write_ex_introduced)}
    if LibVersion < BIO_write_ex_introduced then
    begin
      {$if declared(FC_BIO_write_ex)}
      BIO_write_ex := FC_BIO_write_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_write_ex_removed)}
    if BIO_write_ex_removed <= LibVersion then
    begin
      {$if declared(_BIO_write_ex)}
      BIO_write_ex := _BIO_write_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_write_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_write_ex');
    {$ifend}
  end;
  
  BIO_sendmmsg := LoadLibFunction(ADllHandle, BIO_sendmmsg_procname);
  FuncLoadError := not assigned(BIO_sendmmsg);
  if FuncLoadError then
  begin
    {$if not defined(BIO_sendmmsg_allownil)}
    BIO_sendmmsg := ERR_BIO_sendmmsg;
    {$ifend}
    {$if declared(BIO_sendmmsg_introduced)}
    if LibVersion < BIO_sendmmsg_introduced then
    begin
      {$if declared(FC_BIO_sendmmsg)}
      BIO_sendmmsg := FC_BIO_sendmmsg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_sendmmsg_removed)}
    if BIO_sendmmsg_removed <= LibVersion then
    begin
      {$if declared(_BIO_sendmmsg)}
      BIO_sendmmsg := _BIO_sendmmsg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_sendmmsg_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_sendmmsg');
    {$ifend}
  end;
  
  BIO_get_rpoll_descriptor := LoadLibFunction(ADllHandle, BIO_get_rpoll_descriptor_procname);
  FuncLoadError := not assigned(BIO_get_rpoll_descriptor);
  if FuncLoadError then
  begin
    {$if not defined(BIO_get_rpoll_descriptor_allownil)}
    BIO_get_rpoll_descriptor := ERR_BIO_get_rpoll_descriptor;
    {$ifend}
    {$if declared(BIO_get_rpoll_descriptor_introduced)}
    if LibVersion < BIO_get_rpoll_descriptor_introduced then
    begin
      {$if declared(FC_BIO_get_rpoll_descriptor)}
      BIO_get_rpoll_descriptor := FC_BIO_get_rpoll_descriptor;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_get_rpoll_descriptor_removed)}
    if BIO_get_rpoll_descriptor_removed <= LibVersion then
    begin
      {$if declared(_BIO_get_rpoll_descriptor)}
      BIO_get_rpoll_descriptor := _BIO_get_rpoll_descriptor;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_get_rpoll_descriptor_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_get_rpoll_descriptor');
    {$ifend}
  end;
  
  BIO_get_wpoll_descriptor := LoadLibFunction(ADllHandle, BIO_get_wpoll_descriptor_procname);
  FuncLoadError := not assigned(BIO_get_wpoll_descriptor);
  if FuncLoadError then
  begin
    {$if not defined(BIO_get_wpoll_descriptor_allownil)}
    BIO_get_wpoll_descriptor := ERR_BIO_get_wpoll_descriptor;
    {$ifend}
    {$if declared(BIO_get_wpoll_descriptor_introduced)}
    if LibVersion < BIO_get_wpoll_descriptor_introduced then
    begin
      {$if declared(FC_BIO_get_wpoll_descriptor)}
      BIO_get_wpoll_descriptor := FC_BIO_get_wpoll_descriptor;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_get_wpoll_descriptor_removed)}
    if BIO_get_wpoll_descriptor_removed <= LibVersion then
    begin
      {$if declared(_BIO_get_wpoll_descriptor)}
      BIO_get_wpoll_descriptor := _BIO_get_wpoll_descriptor;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_get_wpoll_descriptor_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_get_wpoll_descriptor');
    {$ifend}
  end;
  
  BIO_puts := LoadLibFunction(ADllHandle, BIO_puts_procname);
  FuncLoadError := not assigned(BIO_puts);
  if FuncLoadError then
  begin
    {$if not defined(BIO_puts_allownil)}
    BIO_puts := ERR_BIO_puts;
    {$ifend}
    {$if declared(BIO_puts_introduced)}
    if LibVersion < BIO_puts_introduced then
    begin
      {$if declared(FC_BIO_puts)}
      BIO_puts := FC_BIO_puts;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_puts_removed)}
    if BIO_puts_removed <= LibVersion then
    begin
      {$if declared(_BIO_puts)}
      BIO_puts := _BIO_puts;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_puts_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_puts');
    {$ifend}
  end;
  
  BIO_indent := LoadLibFunction(ADllHandle, BIO_indent_procname);
  FuncLoadError := not assigned(BIO_indent);
  if FuncLoadError then
  begin
    {$if not defined(BIO_indent_allownil)}
    BIO_indent := ERR_BIO_indent;
    {$ifend}
    {$if declared(BIO_indent_introduced)}
    if LibVersion < BIO_indent_introduced then
    begin
      {$if declared(FC_BIO_indent)}
      BIO_indent := FC_BIO_indent;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_indent_removed)}
    if BIO_indent_removed <= LibVersion then
    begin
      {$if declared(_BIO_indent)}
      BIO_indent := _BIO_indent;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_indent_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_indent');
    {$ifend}
  end;
  
  BIO_ctrl := LoadLibFunction(ADllHandle, BIO_ctrl_procname);
  FuncLoadError := not assigned(BIO_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(BIO_ctrl_allownil)}
    BIO_ctrl := ERR_BIO_ctrl;
    {$ifend}
    {$if declared(BIO_ctrl_introduced)}
    if LibVersion < BIO_ctrl_introduced then
    begin
      {$if declared(FC_BIO_ctrl)}
      BIO_ctrl := FC_BIO_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_ctrl_removed)}
    if BIO_ctrl_removed <= LibVersion then
    begin
      {$if declared(_BIO_ctrl)}
      BIO_ctrl := _BIO_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_ctrl');
    {$ifend}
  end;
  
  BIO_callback_ctrl := LoadLibFunction(ADllHandle, BIO_callback_ctrl_procname);
  FuncLoadError := not assigned(BIO_callback_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(BIO_callback_ctrl_allownil)}
    BIO_callback_ctrl := ERR_BIO_callback_ctrl;
    {$ifend}
    {$if declared(BIO_callback_ctrl_introduced)}
    if LibVersion < BIO_callback_ctrl_introduced then
    begin
      {$if declared(FC_BIO_callback_ctrl)}
      BIO_callback_ctrl := FC_BIO_callback_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_callback_ctrl_removed)}
    if BIO_callback_ctrl_removed <= LibVersion then
    begin
      {$if declared(_BIO_callback_ctrl)}
      BIO_callback_ctrl := _BIO_callback_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_callback_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_callback_ctrl');
    {$ifend}
  end;
  
  BIO_ptr_ctrl := LoadLibFunction(ADllHandle, BIO_ptr_ctrl_procname);
  FuncLoadError := not assigned(BIO_ptr_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(BIO_ptr_ctrl_allownil)}
    BIO_ptr_ctrl := ERR_BIO_ptr_ctrl;
    {$ifend}
    {$if declared(BIO_ptr_ctrl_introduced)}
    if LibVersion < BIO_ptr_ctrl_introduced then
    begin
      {$if declared(FC_BIO_ptr_ctrl)}
      BIO_ptr_ctrl := FC_BIO_ptr_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_ptr_ctrl_removed)}
    if BIO_ptr_ctrl_removed <= LibVersion then
    begin
      {$if declared(_BIO_ptr_ctrl)}
      BIO_ptr_ctrl := _BIO_ptr_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_ptr_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_ptr_ctrl');
    {$ifend}
  end;
  
  BIO_int_ctrl := LoadLibFunction(ADllHandle, BIO_int_ctrl_procname);
  FuncLoadError := not assigned(BIO_int_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(BIO_int_ctrl_allownil)}
    BIO_int_ctrl := ERR_BIO_int_ctrl;
    {$ifend}
    {$if declared(BIO_int_ctrl_introduced)}
    if LibVersion < BIO_int_ctrl_introduced then
    begin
      {$if declared(FC_BIO_int_ctrl)}
      BIO_int_ctrl := FC_BIO_int_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_int_ctrl_removed)}
    if BIO_int_ctrl_removed <= LibVersion then
    begin
      {$if declared(_BIO_int_ctrl)}
      BIO_int_ctrl := _BIO_int_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_int_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_int_ctrl');
    {$ifend}
  end;
  
  BIO_push := LoadLibFunction(ADllHandle, BIO_push_procname);
  FuncLoadError := not assigned(BIO_push);
  if FuncLoadError then
  begin
    {$if not defined(BIO_push_allownil)}
    BIO_push := ERR_BIO_push;
    {$ifend}
    {$if declared(BIO_push_introduced)}
    if LibVersion < BIO_push_introduced then
    begin
      {$if declared(FC_BIO_push)}
      BIO_push := FC_BIO_push;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_push_removed)}
    if BIO_push_removed <= LibVersion then
    begin
      {$if declared(_BIO_push)}
      BIO_push := _BIO_push;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_push_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_push');
    {$ifend}
  end;
  
  BIO_pop := LoadLibFunction(ADllHandle, BIO_pop_procname);
  FuncLoadError := not assigned(BIO_pop);
  if FuncLoadError then
  begin
    {$if not defined(BIO_pop_allownil)}
    BIO_pop := ERR_BIO_pop;
    {$ifend}
    {$if declared(BIO_pop_introduced)}
    if LibVersion < BIO_pop_introduced then
    begin
      {$if declared(FC_BIO_pop)}
      BIO_pop := FC_BIO_pop;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_pop_removed)}
    if BIO_pop_removed <= LibVersion then
    begin
      {$if declared(_BIO_pop)}
      BIO_pop := _BIO_pop;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_pop_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_pop');
    {$ifend}
  end;
  
  BIO_free_all := LoadLibFunction(ADllHandle, BIO_free_all_procname);
  FuncLoadError := not assigned(BIO_free_all);
  if FuncLoadError then
  begin
    {$if not defined(BIO_free_all_allownil)}
    BIO_free_all := ERR_BIO_free_all;
    {$ifend}
    {$if declared(BIO_free_all_introduced)}
    if LibVersion < BIO_free_all_introduced then
    begin
      {$if declared(FC_BIO_free_all)}
      BIO_free_all := FC_BIO_free_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_free_all_removed)}
    if BIO_free_all_removed <= LibVersion then
    begin
      {$if declared(_BIO_free_all)}
      BIO_free_all := _BIO_free_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_free_all_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_free_all');
    {$ifend}
  end;
  
  BIO_find_type := LoadLibFunction(ADllHandle, BIO_find_type_procname);
  FuncLoadError := not assigned(BIO_find_type);
  if FuncLoadError then
  begin
    {$if not defined(BIO_find_type_allownil)}
    BIO_find_type := ERR_BIO_find_type;
    {$ifend}
    {$if declared(BIO_find_type_introduced)}
    if LibVersion < BIO_find_type_introduced then
    begin
      {$if declared(FC_BIO_find_type)}
      BIO_find_type := FC_BIO_find_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_find_type_removed)}
    if BIO_find_type_removed <= LibVersion then
    begin
      {$if declared(_BIO_find_type)}
      BIO_find_type := _BIO_find_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_find_type_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_find_type');
    {$ifend}
  end;
  
  BIO_next := LoadLibFunction(ADllHandle, BIO_next_procname);
  FuncLoadError := not assigned(BIO_next);
  if FuncLoadError then
  begin
    {$if not defined(BIO_next_allownil)}
    BIO_next := ERR_BIO_next;
    {$ifend}
    {$if declared(BIO_next_introduced)}
    if LibVersion < BIO_next_introduced then
    begin
      {$if declared(FC_BIO_next)}
      BIO_next := FC_BIO_next;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_next_removed)}
    if BIO_next_removed <= LibVersion then
    begin
      {$if declared(_BIO_next)}
      BIO_next := _BIO_next;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_next_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_next');
    {$ifend}
  end;
  
  BIO_set_next := LoadLibFunction(ADllHandle, BIO_set_next_procname);
  FuncLoadError := not assigned(BIO_set_next);
  if FuncLoadError then
  begin
    {$if not defined(BIO_set_next_allownil)}
    BIO_set_next := ERR_BIO_set_next;
    {$ifend}
    {$if declared(BIO_set_next_introduced)}
    if LibVersion < BIO_set_next_introduced then
    begin
      {$if declared(FC_BIO_set_next)}
      BIO_set_next := FC_BIO_set_next;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_set_next_removed)}
    if BIO_set_next_removed <= LibVersion then
    begin
      {$if declared(_BIO_set_next)}
      BIO_set_next := _BIO_set_next;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_set_next_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_set_next');
    {$ifend}
  end;
  
  BIO_get_retry_BIO := LoadLibFunction(ADllHandle, BIO_get_retry_BIO_procname);
  FuncLoadError := not assigned(BIO_get_retry_BIO);
  if FuncLoadError then
  begin
    {$if not defined(BIO_get_retry_BIO_allownil)}
    BIO_get_retry_BIO := ERR_BIO_get_retry_BIO;
    {$ifend}
    {$if declared(BIO_get_retry_BIO_introduced)}
    if LibVersion < BIO_get_retry_BIO_introduced then
    begin
      {$if declared(FC_BIO_get_retry_BIO)}
      BIO_get_retry_BIO := FC_BIO_get_retry_BIO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_get_retry_BIO_removed)}
    if BIO_get_retry_BIO_removed <= LibVersion then
    begin
      {$if declared(_BIO_get_retry_BIO)}
      BIO_get_retry_BIO := _BIO_get_retry_BIO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_get_retry_BIO_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_get_retry_BIO');
    {$ifend}
  end;
  
  BIO_get_retry_reason := LoadLibFunction(ADllHandle, BIO_get_retry_reason_procname);
  FuncLoadError := not assigned(BIO_get_retry_reason);
  if FuncLoadError then
  begin
    {$if not defined(BIO_get_retry_reason_allownil)}
    BIO_get_retry_reason := ERR_BIO_get_retry_reason;
    {$ifend}
    {$if declared(BIO_get_retry_reason_introduced)}
    if LibVersion < BIO_get_retry_reason_introduced then
    begin
      {$if declared(FC_BIO_get_retry_reason)}
      BIO_get_retry_reason := FC_BIO_get_retry_reason;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_get_retry_reason_removed)}
    if BIO_get_retry_reason_removed <= LibVersion then
    begin
      {$if declared(_BIO_get_retry_reason)}
      BIO_get_retry_reason := _BIO_get_retry_reason;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_get_retry_reason_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_get_retry_reason');
    {$ifend}
  end;
  
  BIO_set_retry_reason := LoadLibFunction(ADllHandle, BIO_set_retry_reason_procname);
  FuncLoadError := not assigned(BIO_set_retry_reason);
  if FuncLoadError then
  begin
    {$if not defined(BIO_set_retry_reason_allownil)}
    BIO_set_retry_reason := ERR_BIO_set_retry_reason;
    {$ifend}
    {$if declared(BIO_set_retry_reason_introduced)}
    if LibVersion < BIO_set_retry_reason_introduced then
    begin
      {$if declared(FC_BIO_set_retry_reason)}
      BIO_set_retry_reason := FC_BIO_set_retry_reason;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_set_retry_reason_removed)}
    if BIO_set_retry_reason_removed <= LibVersion then
    begin
      {$if declared(_BIO_set_retry_reason)}
      BIO_set_retry_reason := _BIO_set_retry_reason;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_set_retry_reason_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_set_retry_reason');
    {$ifend}
  end;
  
  BIO_dup_chain := LoadLibFunction(ADllHandle, BIO_dup_chain_procname);
  FuncLoadError := not assigned(BIO_dup_chain);
  if FuncLoadError then
  begin
    {$if not defined(BIO_dup_chain_allownil)}
    BIO_dup_chain := ERR_BIO_dup_chain;
    {$ifend}
    {$if declared(BIO_dup_chain_introduced)}
    if LibVersion < BIO_dup_chain_introduced then
    begin
      {$if declared(FC_BIO_dup_chain)}
      BIO_dup_chain := FC_BIO_dup_chain;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_dup_chain_removed)}
    if BIO_dup_chain_removed <= LibVersion then
    begin
      {$if declared(_BIO_dup_chain)}
      BIO_dup_chain := _BIO_dup_chain;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_dup_chain_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_dup_chain');
    {$ifend}
  end;
  
  BIO_nread0 := LoadLibFunction(ADllHandle, BIO_nread0_procname);
  FuncLoadError := not assigned(BIO_nread0);
  if FuncLoadError then
  begin
    {$if not defined(BIO_nread0_allownil)}
    BIO_nread0 := ERR_BIO_nread0;
    {$ifend}
    {$if declared(BIO_nread0_introduced)}
    if LibVersion < BIO_nread0_introduced then
    begin
      {$if declared(FC_BIO_nread0)}
      BIO_nread0 := FC_BIO_nread0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_nread0_removed)}
    if BIO_nread0_removed <= LibVersion then
    begin
      {$if declared(_BIO_nread0)}
      BIO_nread0 := _BIO_nread0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_nread0_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_nread0');
    {$ifend}
  end;
  
  BIO_nread := LoadLibFunction(ADllHandle, BIO_nread_procname);
  FuncLoadError := not assigned(BIO_nread);
  if FuncLoadError then
  begin
    {$if not defined(BIO_nread_allownil)}
    BIO_nread := ERR_BIO_nread;
    {$ifend}
    {$if declared(BIO_nread_introduced)}
    if LibVersion < BIO_nread_introduced then
    begin
      {$if declared(FC_BIO_nread)}
      BIO_nread := FC_BIO_nread;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_nread_removed)}
    if BIO_nread_removed <= LibVersion then
    begin
      {$if declared(_BIO_nread)}
      BIO_nread := _BIO_nread;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_nread_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_nread');
    {$ifend}
  end;
  
  BIO_nwrite0 := LoadLibFunction(ADllHandle, BIO_nwrite0_procname);
  FuncLoadError := not assigned(BIO_nwrite0);
  if FuncLoadError then
  begin
    {$if not defined(BIO_nwrite0_allownil)}
    BIO_nwrite0 := ERR_BIO_nwrite0;
    {$ifend}
    {$if declared(BIO_nwrite0_introduced)}
    if LibVersion < BIO_nwrite0_introduced then
    begin
      {$if declared(FC_BIO_nwrite0)}
      BIO_nwrite0 := FC_BIO_nwrite0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_nwrite0_removed)}
    if BIO_nwrite0_removed <= LibVersion then
    begin
      {$if declared(_BIO_nwrite0)}
      BIO_nwrite0 := _BIO_nwrite0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_nwrite0_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_nwrite0');
    {$ifend}
  end;
  
  BIO_nwrite := LoadLibFunction(ADllHandle, BIO_nwrite_procname);
  FuncLoadError := not assigned(BIO_nwrite);
  if FuncLoadError then
  begin
    {$if not defined(BIO_nwrite_allownil)}
    BIO_nwrite := ERR_BIO_nwrite;
    {$ifend}
    {$if declared(BIO_nwrite_introduced)}
    if LibVersion < BIO_nwrite_introduced then
    begin
      {$if declared(FC_BIO_nwrite)}
      BIO_nwrite := FC_BIO_nwrite;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_nwrite_removed)}
    if BIO_nwrite_removed <= LibVersion then
    begin
      {$if declared(_BIO_nwrite)}
      BIO_nwrite := _BIO_nwrite;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_nwrite_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_nwrite');
    {$ifend}
  end;
  
  BIO_s_mem := LoadLibFunction(ADllHandle, BIO_s_mem_procname);
  FuncLoadError := not assigned(BIO_s_mem);
  if FuncLoadError then
  begin
    {$if not defined(BIO_s_mem_allownil)}
    BIO_s_mem := ERR_BIO_s_mem;
    {$ifend}
    {$if declared(BIO_s_mem_introduced)}
    if LibVersion < BIO_s_mem_introduced then
    begin
      {$if declared(FC_BIO_s_mem)}
      BIO_s_mem := FC_BIO_s_mem;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_s_mem_removed)}
    if BIO_s_mem_removed <= LibVersion then
    begin
      {$if declared(_BIO_s_mem)}
      BIO_s_mem := _BIO_s_mem;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_s_mem_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_s_mem');
    {$ifend}
  end;
  
  BIO_s_dgram_mem := LoadLibFunction(ADllHandle, BIO_s_dgram_mem_procname);
  FuncLoadError := not assigned(BIO_s_dgram_mem);
  if FuncLoadError then
  begin
    {$if not defined(BIO_s_dgram_mem_allownil)}
    BIO_s_dgram_mem := ERR_BIO_s_dgram_mem;
    {$ifend}
    {$if declared(BIO_s_dgram_mem_introduced)}
    if LibVersion < BIO_s_dgram_mem_introduced then
    begin
      {$if declared(FC_BIO_s_dgram_mem)}
      BIO_s_dgram_mem := FC_BIO_s_dgram_mem;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_s_dgram_mem_removed)}
    if BIO_s_dgram_mem_removed <= LibVersion then
    begin
      {$if declared(_BIO_s_dgram_mem)}
      BIO_s_dgram_mem := _BIO_s_dgram_mem;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_s_dgram_mem_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_s_dgram_mem');
    {$ifend}
  end;
  
  BIO_s_secmem := LoadLibFunction(ADllHandle, BIO_s_secmem_procname);
  FuncLoadError := not assigned(BIO_s_secmem);
  if FuncLoadError then
  begin
    {$if not defined(BIO_s_secmem_allownil)}
    BIO_s_secmem := ERR_BIO_s_secmem;
    {$ifend}
    {$if declared(BIO_s_secmem_introduced)}
    if LibVersion < BIO_s_secmem_introduced then
    begin
      {$if declared(FC_BIO_s_secmem)}
      BIO_s_secmem := FC_BIO_s_secmem;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_s_secmem_removed)}
    if BIO_s_secmem_removed <= LibVersion then
    begin
      {$if declared(_BIO_s_secmem)}
      BIO_s_secmem := _BIO_s_secmem;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_s_secmem_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_s_secmem');
    {$ifend}
  end;
  
  BIO_new_mem_buf := LoadLibFunction(ADllHandle, BIO_new_mem_buf_procname);
  FuncLoadError := not assigned(BIO_new_mem_buf);
  if FuncLoadError then
  begin
    {$if not defined(BIO_new_mem_buf_allownil)}
    BIO_new_mem_buf := ERR_BIO_new_mem_buf;
    {$ifend}
    {$if declared(BIO_new_mem_buf_introduced)}
    if LibVersion < BIO_new_mem_buf_introduced then
    begin
      {$if declared(FC_BIO_new_mem_buf)}
      BIO_new_mem_buf := FC_BIO_new_mem_buf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_new_mem_buf_removed)}
    if BIO_new_mem_buf_removed <= LibVersion then
    begin
      {$if declared(_BIO_new_mem_buf)}
      BIO_new_mem_buf := _BIO_new_mem_buf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_new_mem_buf_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_new_mem_buf');
    {$ifend}
  end;
  
  BIO_s_socket := LoadLibFunction(ADllHandle, BIO_s_socket_procname);
  FuncLoadError := not assigned(BIO_s_socket);
  if FuncLoadError then
  begin
    {$if not defined(BIO_s_socket_allownil)}
    BIO_s_socket := ERR_BIO_s_socket;
    {$ifend}
    {$if declared(BIO_s_socket_introduced)}
    if LibVersion < BIO_s_socket_introduced then
    begin
      {$if declared(FC_BIO_s_socket)}
      BIO_s_socket := FC_BIO_s_socket;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_s_socket_removed)}
    if BIO_s_socket_removed <= LibVersion then
    begin
      {$if declared(_BIO_s_socket)}
      BIO_s_socket := _BIO_s_socket;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_s_socket_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_s_socket');
    {$ifend}
  end;
  
  BIO_s_connect := LoadLibFunction(ADllHandle, BIO_s_connect_procname);
  FuncLoadError := not assigned(BIO_s_connect);
  if FuncLoadError then
  begin
    {$if not defined(BIO_s_connect_allownil)}
    BIO_s_connect := ERR_BIO_s_connect;
    {$ifend}
    {$if declared(BIO_s_connect_introduced)}
    if LibVersion < BIO_s_connect_introduced then
    begin
      {$if declared(FC_BIO_s_connect)}
      BIO_s_connect := FC_BIO_s_connect;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_s_connect_removed)}
    if BIO_s_connect_removed <= LibVersion then
    begin
      {$if declared(_BIO_s_connect)}
      BIO_s_connect := _BIO_s_connect;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_s_connect_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_s_connect');
    {$ifend}
  end;
  
  BIO_s_accept := LoadLibFunction(ADllHandle, BIO_s_accept_procname);
  FuncLoadError := not assigned(BIO_s_accept);
  if FuncLoadError then
  begin
    {$if not defined(BIO_s_accept_allownil)}
    BIO_s_accept := ERR_BIO_s_accept;
    {$ifend}
    {$if declared(BIO_s_accept_introduced)}
    if LibVersion < BIO_s_accept_introduced then
    begin
      {$if declared(FC_BIO_s_accept)}
      BIO_s_accept := FC_BIO_s_accept;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_s_accept_removed)}
    if BIO_s_accept_removed <= LibVersion then
    begin
      {$if declared(_BIO_s_accept)}
      BIO_s_accept := _BIO_s_accept;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_s_accept_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_s_accept');
    {$ifend}
  end;
  
  BIO_s_fd := LoadLibFunction(ADllHandle, BIO_s_fd_procname);
  FuncLoadError := not assigned(BIO_s_fd);
  if FuncLoadError then
  begin
    {$if not defined(BIO_s_fd_allownil)}
    BIO_s_fd := ERR_BIO_s_fd;
    {$ifend}
    {$if declared(BIO_s_fd_introduced)}
    if LibVersion < BIO_s_fd_introduced then
    begin
      {$if declared(FC_BIO_s_fd)}
      BIO_s_fd := FC_BIO_s_fd;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_s_fd_removed)}
    if BIO_s_fd_removed <= LibVersion then
    begin
      {$if declared(_BIO_s_fd)}
      BIO_s_fd := _BIO_s_fd;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_s_fd_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_s_fd');
    {$ifend}
  end;
  
  BIO_s_log := LoadLibFunction(ADllHandle, BIO_s_log_procname);
  FuncLoadError := not assigned(BIO_s_log);
  if FuncLoadError then
  begin
    {$if not defined(BIO_s_log_allownil)}
    BIO_s_log := ERR_BIO_s_log;
    {$ifend}
    {$if declared(BIO_s_log_introduced)}
    if LibVersion < BIO_s_log_introduced then
    begin
      {$if declared(FC_BIO_s_log)}
      BIO_s_log := FC_BIO_s_log;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_s_log_removed)}
    if BIO_s_log_removed <= LibVersion then
    begin
      {$if declared(_BIO_s_log)}
      BIO_s_log := _BIO_s_log;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_s_log_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_s_log');
    {$ifend}
  end;
  
  BIO_s_bio := LoadLibFunction(ADllHandle, BIO_s_bio_procname);
  FuncLoadError := not assigned(BIO_s_bio);
  if FuncLoadError then
  begin
    {$if not defined(BIO_s_bio_allownil)}
    BIO_s_bio := ERR_BIO_s_bio;
    {$ifend}
    {$if declared(BIO_s_bio_introduced)}
    if LibVersion < BIO_s_bio_introduced then
    begin
      {$if declared(FC_BIO_s_bio)}
      BIO_s_bio := FC_BIO_s_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_s_bio_removed)}
    if BIO_s_bio_removed <= LibVersion then
    begin
      {$if declared(_BIO_s_bio)}
      BIO_s_bio := _BIO_s_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_s_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_s_bio');
    {$ifend}
  end;
  
  BIO_s_null := LoadLibFunction(ADllHandle, BIO_s_null_procname);
  FuncLoadError := not assigned(BIO_s_null);
  if FuncLoadError then
  begin
    {$if not defined(BIO_s_null_allownil)}
    BIO_s_null := ERR_BIO_s_null;
    {$ifend}
    {$if declared(BIO_s_null_introduced)}
    if LibVersion < BIO_s_null_introduced then
    begin
      {$if declared(FC_BIO_s_null)}
      BIO_s_null := FC_BIO_s_null;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_s_null_removed)}
    if BIO_s_null_removed <= LibVersion then
    begin
      {$if declared(_BIO_s_null)}
      BIO_s_null := _BIO_s_null;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_s_null_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_s_null');
    {$ifend}
  end;
  
  BIO_f_null := LoadLibFunction(ADllHandle, BIO_f_null_procname);
  FuncLoadError := not assigned(BIO_f_null);
  if FuncLoadError then
  begin
    {$if not defined(BIO_f_null_allownil)}
    BIO_f_null := ERR_BIO_f_null;
    {$ifend}
    {$if declared(BIO_f_null_introduced)}
    if LibVersion < BIO_f_null_introduced then
    begin
      {$if declared(FC_BIO_f_null)}
      BIO_f_null := FC_BIO_f_null;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_f_null_removed)}
    if BIO_f_null_removed <= LibVersion then
    begin
      {$if declared(_BIO_f_null)}
      BIO_f_null := _BIO_f_null;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_f_null_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_f_null');
    {$ifend}
  end;
  
  BIO_f_buffer := LoadLibFunction(ADllHandle, BIO_f_buffer_procname);
  FuncLoadError := not assigned(BIO_f_buffer);
  if FuncLoadError then
  begin
    {$if not defined(BIO_f_buffer_allownil)}
    BIO_f_buffer := ERR_BIO_f_buffer;
    {$ifend}
    {$if declared(BIO_f_buffer_introduced)}
    if LibVersion < BIO_f_buffer_introduced then
    begin
      {$if declared(FC_BIO_f_buffer)}
      BIO_f_buffer := FC_BIO_f_buffer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_f_buffer_removed)}
    if BIO_f_buffer_removed <= LibVersion then
    begin
      {$if declared(_BIO_f_buffer)}
      BIO_f_buffer := _BIO_f_buffer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_f_buffer_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_f_buffer');
    {$ifend}
  end;
  
  BIO_f_readbuffer := LoadLibFunction(ADllHandle, BIO_f_readbuffer_procname);
  FuncLoadError := not assigned(BIO_f_readbuffer);
  if FuncLoadError then
  begin
    {$if not defined(BIO_f_readbuffer_allownil)}
    BIO_f_readbuffer := ERR_BIO_f_readbuffer;
    {$ifend}
    {$if declared(BIO_f_readbuffer_introduced)}
    if LibVersion < BIO_f_readbuffer_introduced then
    begin
      {$if declared(FC_BIO_f_readbuffer)}
      BIO_f_readbuffer := FC_BIO_f_readbuffer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_f_readbuffer_removed)}
    if BIO_f_readbuffer_removed <= LibVersion then
    begin
      {$if declared(_BIO_f_readbuffer)}
      BIO_f_readbuffer := _BIO_f_readbuffer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_f_readbuffer_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_f_readbuffer');
    {$ifend}
  end;
  
  BIO_f_linebuffer := LoadLibFunction(ADllHandle, BIO_f_linebuffer_procname);
  FuncLoadError := not assigned(BIO_f_linebuffer);
  if FuncLoadError then
  begin
    {$if not defined(BIO_f_linebuffer_allownil)}
    BIO_f_linebuffer := ERR_BIO_f_linebuffer;
    {$ifend}
    {$if declared(BIO_f_linebuffer_introduced)}
    if LibVersion < BIO_f_linebuffer_introduced then
    begin
      {$if declared(FC_BIO_f_linebuffer)}
      BIO_f_linebuffer := FC_BIO_f_linebuffer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_f_linebuffer_removed)}
    if BIO_f_linebuffer_removed <= LibVersion then
    begin
      {$if declared(_BIO_f_linebuffer)}
      BIO_f_linebuffer := _BIO_f_linebuffer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_f_linebuffer_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_f_linebuffer');
    {$ifend}
  end;
  
  BIO_f_nbio_test := LoadLibFunction(ADllHandle, BIO_f_nbio_test_procname);
  FuncLoadError := not assigned(BIO_f_nbio_test);
  if FuncLoadError then
  begin
    {$if not defined(BIO_f_nbio_test_allownil)}
    BIO_f_nbio_test := ERR_BIO_f_nbio_test;
    {$ifend}
    {$if declared(BIO_f_nbio_test_introduced)}
    if LibVersion < BIO_f_nbio_test_introduced then
    begin
      {$if declared(FC_BIO_f_nbio_test)}
      BIO_f_nbio_test := FC_BIO_f_nbio_test;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_f_nbio_test_removed)}
    if BIO_f_nbio_test_removed <= LibVersion then
    begin
      {$if declared(_BIO_f_nbio_test)}
      BIO_f_nbio_test := _BIO_f_nbio_test;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_f_nbio_test_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_f_nbio_test');
    {$ifend}
  end;
  
  BIO_f_prefix := LoadLibFunction(ADllHandle, BIO_f_prefix_procname);
  FuncLoadError := not assigned(BIO_f_prefix);
  if FuncLoadError then
  begin
    {$if not defined(BIO_f_prefix_allownil)}
    BIO_f_prefix := ERR_BIO_f_prefix;
    {$ifend}
    {$if declared(BIO_f_prefix_introduced)}
    if LibVersion < BIO_f_prefix_introduced then
    begin
      {$if declared(FC_BIO_f_prefix)}
      BIO_f_prefix := FC_BIO_f_prefix;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_f_prefix_removed)}
    if BIO_f_prefix_removed <= LibVersion then
    begin
      {$if declared(_BIO_f_prefix)}
      BIO_f_prefix := _BIO_f_prefix;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_f_prefix_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_f_prefix');
    {$ifend}
  end;
  
  BIO_s_core := LoadLibFunction(ADllHandle, BIO_s_core_procname);
  FuncLoadError := not assigned(BIO_s_core);
  if FuncLoadError then
  begin
    {$if not defined(BIO_s_core_allownil)}
    BIO_s_core := ERR_BIO_s_core;
    {$ifend}
    {$if declared(BIO_s_core_introduced)}
    if LibVersion < BIO_s_core_introduced then
    begin
      {$if declared(FC_BIO_s_core)}
      BIO_s_core := FC_BIO_s_core;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_s_core_removed)}
    if BIO_s_core_removed <= LibVersion then
    begin
      {$if declared(_BIO_s_core)}
      BIO_s_core := _BIO_s_core;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_s_core_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_s_core');
    {$ifend}
  end;
  
  BIO_s_dgram_pair := LoadLibFunction(ADllHandle, BIO_s_dgram_pair_procname);
  FuncLoadError := not assigned(BIO_s_dgram_pair);
  if FuncLoadError then
  begin
    {$if not defined(BIO_s_dgram_pair_allownil)}
    BIO_s_dgram_pair := ERR_BIO_s_dgram_pair;
    {$ifend}
    {$if declared(BIO_s_dgram_pair_introduced)}
    if LibVersion < BIO_s_dgram_pair_introduced then
    begin
      {$if declared(FC_BIO_s_dgram_pair)}
      BIO_s_dgram_pair := FC_BIO_s_dgram_pair;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_s_dgram_pair_removed)}
    if BIO_s_dgram_pair_removed <= LibVersion then
    begin
      {$if declared(_BIO_s_dgram_pair)}
      BIO_s_dgram_pair := _BIO_s_dgram_pair;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_s_dgram_pair_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_s_dgram_pair');
    {$ifend}
  end;
  
  BIO_s_datagram := LoadLibFunction(ADllHandle, BIO_s_datagram_procname);
  FuncLoadError := not assigned(BIO_s_datagram);
  if FuncLoadError then
  begin
    {$if not defined(BIO_s_datagram_allownil)}
    BIO_s_datagram := ERR_BIO_s_datagram;
    {$ifend}
    {$if declared(BIO_s_datagram_introduced)}
    if LibVersion < BIO_s_datagram_introduced then
    begin
      {$if declared(FC_BIO_s_datagram)}
      BIO_s_datagram := FC_BIO_s_datagram;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_s_datagram_removed)}
    if BIO_s_datagram_removed <= LibVersion then
    begin
      {$if declared(_BIO_s_datagram)}
      BIO_s_datagram := _BIO_s_datagram;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_s_datagram_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_s_datagram');
    {$ifend}
  end;
  
  BIO_dgram_non_fatal_error := LoadLibFunction(ADllHandle, BIO_dgram_non_fatal_error_procname);
  FuncLoadError := not assigned(BIO_dgram_non_fatal_error);
  if FuncLoadError then
  begin
    {$if not defined(BIO_dgram_non_fatal_error_allownil)}
    BIO_dgram_non_fatal_error := ERR_BIO_dgram_non_fatal_error;
    {$ifend}
    {$if declared(BIO_dgram_non_fatal_error_introduced)}
    if LibVersion < BIO_dgram_non_fatal_error_introduced then
    begin
      {$if declared(FC_BIO_dgram_non_fatal_error)}
      BIO_dgram_non_fatal_error := FC_BIO_dgram_non_fatal_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_dgram_non_fatal_error_removed)}
    if BIO_dgram_non_fatal_error_removed <= LibVersion then
    begin
      {$if declared(_BIO_dgram_non_fatal_error)}
      BIO_dgram_non_fatal_error := _BIO_dgram_non_fatal_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_dgram_non_fatal_error_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_dgram_non_fatal_error');
    {$ifend}
  end;
  
  BIO_new_dgram := LoadLibFunction(ADllHandle, BIO_new_dgram_procname);
  FuncLoadError := not assigned(BIO_new_dgram);
  if FuncLoadError then
  begin
    {$if not defined(BIO_new_dgram_allownil)}
    BIO_new_dgram := ERR_BIO_new_dgram;
    {$ifend}
    {$if declared(BIO_new_dgram_introduced)}
    if LibVersion < BIO_new_dgram_introduced then
    begin
      {$if declared(FC_BIO_new_dgram)}
      BIO_new_dgram := FC_BIO_new_dgram;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_new_dgram_removed)}
    if BIO_new_dgram_removed <= LibVersion then
    begin
      {$if declared(_BIO_new_dgram)}
      BIO_new_dgram := _BIO_new_dgram;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_new_dgram_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_new_dgram');
    {$ifend}
  end;
  
  BIO_sock_should_retry := LoadLibFunction(ADllHandle, BIO_sock_should_retry_procname);
  FuncLoadError := not assigned(BIO_sock_should_retry);
  if FuncLoadError then
  begin
    {$if not defined(BIO_sock_should_retry_allownil)}
    BIO_sock_should_retry := ERR_BIO_sock_should_retry;
    {$ifend}
    {$if declared(BIO_sock_should_retry_introduced)}
    if LibVersion < BIO_sock_should_retry_introduced then
    begin
      {$if declared(FC_BIO_sock_should_retry)}
      BIO_sock_should_retry := FC_BIO_sock_should_retry;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_sock_should_retry_removed)}
    if BIO_sock_should_retry_removed <= LibVersion then
    begin
      {$if declared(_BIO_sock_should_retry)}
      BIO_sock_should_retry := _BIO_sock_should_retry;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_sock_should_retry_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_sock_should_retry');
    {$ifend}
  end;
  
  BIO_sock_non_fatal_error := LoadLibFunction(ADllHandle, BIO_sock_non_fatal_error_procname);
  FuncLoadError := not assigned(BIO_sock_non_fatal_error);
  if FuncLoadError then
  begin
    {$if not defined(BIO_sock_non_fatal_error_allownil)}
    BIO_sock_non_fatal_error := ERR_BIO_sock_non_fatal_error;
    {$ifend}
    {$if declared(BIO_sock_non_fatal_error_introduced)}
    if LibVersion < BIO_sock_non_fatal_error_introduced then
    begin
      {$if declared(FC_BIO_sock_non_fatal_error)}
      BIO_sock_non_fatal_error := FC_BIO_sock_non_fatal_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_sock_non_fatal_error_removed)}
    if BIO_sock_non_fatal_error_removed <= LibVersion then
    begin
      {$if declared(_BIO_sock_non_fatal_error)}
      BIO_sock_non_fatal_error := _BIO_sock_non_fatal_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_sock_non_fatal_error_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_sock_non_fatal_error');
    {$ifend}
  end;
  
  BIO_err_is_non_fatal := LoadLibFunction(ADllHandle, BIO_err_is_non_fatal_procname);
  FuncLoadError := not assigned(BIO_err_is_non_fatal);
  if FuncLoadError then
  begin
    {$if not defined(BIO_err_is_non_fatal_allownil)}
    BIO_err_is_non_fatal := ERR_BIO_err_is_non_fatal;
    {$ifend}
    {$if declared(BIO_err_is_non_fatal_introduced)}
    if LibVersion < BIO_err_is_non_fatal_introduced then
    begin
      {$if declared(FC_BIO_err_is_non_fatal)}
      BIO_err_is_non_fatal := FC_BIO_err_is_non_fatal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_err_is_non_fatal_removed)}
    if BIO_err_is_non_fatal_removed <= LibVersion then
    begin
      {$if declared(_BIO_err_is_non_fatal)}
      BIO_err_is_non_fatal := _BIO_err_is_non_fatal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_err_is_non_fatal_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_err_is_non_fatal');
    {$ifend}
  end;
  
  BIO_socket_wait := LoadLibFunction(ADllHandle, BIO_socket_wait_procname);
  FuncLoadError := not assigned(BIO_socket_wait);
  if FuncLoadError then
  begin
    {$if not defined(BIO_socket_wait_allownil)}
    BIO_socket_wait := ERR_BIO_socket_wait;
    {$ifend}
    {$if declared(BIO_socket_wait_introduced)}
    if LibVersion < BIO_socket_wait_introduced then
    begin
      {$if declared(FC_BIO_socket_wait)}
      BIO_socket_wait := FC_BIO_socket_wait;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_socket_wait_removed)}
    if BIO_socket_wait_removed <= LibVersion then
    begin
      {$if declared(_BIO_socket_wait)}
      BIO_socket_wait := _BIO_socket_wait;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_socket_wait_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_socket_wait');
    {$ifend}
  end;
  
  BIO_wait := LoadLibFunction(ADllHandle, BIO_wait_procname);
  FuncLoadError := not assigned(BIO_wait);
  if FuncLoadError then
  begin
    {$if not defined(BIO_wait_allownil)}
    BIO_wait := ERR_BIO_wait;
    {$ifend}
    {$if declared(BIO_wait_introduced)}
    if LibVersion < BIO_wait_introduced then
    begin
      {$if declared(FC_BIO_wait)}
      BIO_wait := FC_BIO_wait;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_wait_removed)}
    if BIO_wait_removed <= LibVersion then
    begin
      {$if declared(_BIO_wait)}
      BIO_wait := _BIO_wait;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_wait_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_wait');
    {$ifend}
  end;
  
  BIO_do_connect_retry := LoadLibFunction(ADllHandle, BIO_do_connect_retry_procname);
  FuncLoadError := not assigned(BIO_do_connect_retry);
  if FuncLoadError then
  begin
    {$if not defined(BIO_do_connect_retry_allownil)}
    BIO_do_connect_retry := ERR_BIO_do_connect_retry;
    {$ifend}
    {$if declared(BIO_do_connect_retry_introduced)}
    if LibVersion < BIO_do_connect_retry_introduced then
    begin
      {$if declared(FC_BIO_do_connect_retry)}
      BIO_do_connect_retry := FC_BIO_do_connect_retry;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_do_connect_retry_removed)}
    if BIO_do_connect_retry_removed <= LibVersion then
    begin
      {$if declared(_BIO_do_connect_retry)}
      BIO_do_connect_retry := _BIO_do_connect_retry;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_do_connect_retry_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_do_connect_retry');
    {$ifend}
  end;
  
  BIO_fd_should_retry := LoadLibFunction(ADllHandle, BIO_fd_should_retry_procname);
  FuncLoadError := not assigned(BIO_fd_should_retry);
  if FuncLoadError then
  begin
    {$if not defined(BIO_fd_should_retry_allownil)}
    BIO_fd_should_retry := ERR_BIO_fd_should_retry;
    {$ifend}
    {$if declared(BIO_fd_should_retry_introduced)}
    if LibVersion < BIO_fd_should_retry_introduced then
    begin
      {$if declared(FC_BIO_fd_should_retry)}
      BIO_fd_should_retry := FC_BIO_fd_should_retry;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_fd_should_retry_removed)}
    if BIO_fd_should_retry_removed <= LibVersion then
    begin
      {$if declared(_BIO_fd_should_retry)}
      BIO_fd_should_retry := _BIO_fd_should_retry;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_fd_should_retry_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_fd_should_retry');
    {$ifend}
  end;
  
  BIO_fd_non_fatal_error := LoadLibFunction(ADllHandle, BIO_fd_non_fatal_error_procname);
  FuncLoadError := not assigned(BIO_fd_non_fatal_error);
  if FuncLoadError then
  begin
    {$if not defined(BIO_fd_non_fatal_error_allownil)}
    BIO_fd_non_fatal_error := ERR_BIO_fd_non_fatal_error;
    {$ifend}
    {$if declared(BIO_fd_non_fatal_error_introduced)}
    if LibVersion < BIO_fd_non_fatal_error_introduced then
    begin
      {$if declared(FC_BIO_fd_non_fatal_error)}
      BIO_fd_non_fatal_error := FC_BIO_fd_non_fatal_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_fd_non_fatal_error_removed)}
    if BIO_fd_non_fatal_error_removed <= LibVersion then
    begin
      {$if declared(_BIO_fd_non_fatal_error)}
      BIO_fd_non_fatal_error := _BIO_fd_non_fatal_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_fd_non_fatal_error_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_fd_non_fatal_error');
    {$ifend}
  end;
  
  BIO_dump_cb := LoadLibFunction(ADllHandle, BIO_dump_cb_procname);
  FuncLoadError := not assigned(BIO_dump_cb);
  if FuncLoadError then
  begin
    {$if not defined(BIO_dump_cb_allownil)}
    BIO_dump_cb := ERR_BIO_dump_cb;
    {$ifend}
    {$if declared(BIO_dump_cb_introduced)}
    if LibVersion < BIO_dump_cb_introduced then
    begin
      {$if declared(FC_BIO_dump_cb)}
      BIO_dump_cb := FC_BIO_dump_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_dump_cb_removed)}
    if BIO_dump_cb_removed <= LibVersion then
    begin
      {$if declared(_BIO_dump_cb)}
      BIO_dump_cb := _BIO_dump_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_dump_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_dump_cb');
    {$ifend}
  end;
  
  BIO_dump_indent_cb := LoadLibFunction(ADllHandle, BIO_dump_indent_cb_procname);
  FuncLoadError := not assigned(BIO_dump_indent_cb);
  if FuncLoadError then
  begin
    {$if not defined(BIO_dump_indent_cb_allownil)}
    BIO_dump_indent_cb := ERR_BIO_dump_indent_cb;
    {$ifend}
    {$if declared(BIO_dump_indent_cb_introduced)}
    if LibVersion < BIO_dump_indent_cb_introduced then
    begin
      {$if declared(FC_BIO_dump_indent_cb)}
      BIO_dump_indent_cb := FC_BIO_dump_indent_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_dump_indent_cb_removed)}
    if BIO_dump_indent_cb_removed <= LibVersion then
    begin
      {$if declared(_BIO_dump_indent_cb)}
      BIO_dump_indent_cb := _BIO_dump_indent_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_dump_indent_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_dump_indent_cb');
    {$ifend}
  end;
  
  BIO_dump := LoadLibFunction(ADllHandle, BIO_dump_procname);
  FuncLoadError := not assigned(BIO_dump);
  if FuncLoadError then
  begin
    {$if not defined(BIO_dump_allownil)}
    BIO_dump := ERR_BIO_dump;
    {$ifend}
    {$if declared(BIO_dump_introduced)}
    if LibVersion < BIO_dump_introduced then
    begin
      {$if declared(FC_BIO_dump)}
      BIO_dump := FC_BIO_dump;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_dump_removed)}
    if BIO_dump_removed <= LibVersion then
    begin
      {$if declared(_BIO_dump)}
      BIO_dump := _BIO_dump;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_dump_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_dump');
    {$ifend}
  end;
  
  BIO_dump_indent := LoadLibFunction(ADllHandle, BIO_dump_indent_procname);
  FuncLoadError := not assigned(BIO_dump_indent);
  if FuncLoadError then
  begin
    {$if not defined(BIO_dump_indent_allownil)}
    BIO_dump_indent := ERR_BIO_dump_indent;
    {$ifend}
    {$if declared(BIO_dump_indent_introduced)}
    if LibVersion < BIO_dump_indent_introduced then
    begin
      {$if declared(FC_BIO_dump_indent)}
      BIO_dump_indent := FC_BIO_dump_indent;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_dump_indent_removed)}
    if BIO_dump_indent_removed <= LibVersion then
    begin
      {$if declared(_BIO_dump_indent)}
      BIO_dump_indent := _BIO_dump_indent;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_dump_indent_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_dump_indent');
    {$ifend}
  end;
  
  BIO_dump_fp := LoadLibFunction(ADllHandle, BIO_dump_fp_procname);
  FuncLoadError := not assigned(BIO_dump_fp);
  if FuncLoadError then
  begin
    {$if not defined(BIO_dump_fp_allownil)}
    BIO_dump_fp := ERR_BIO_dump_fp;
    {$ifend}
    {$if declared(BIO_dump_fp_introduced)}
    if LibVersion < BIO_dump_fp_introduced then
    begin
      {$if declared(FC_BIO_dump_fp)}
      BIO_dump_fp := FC_BIO_dump_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_dump_fp_removed)}
    if BIO_dump_fp_removed <= LibVersion then
    begin
      {$if declared(_BIO_dump_fp)}
      BIO_dump_fp := _BIO_dump_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_dump_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_dump_fp');
    {$ifend}
  end;
  
  BIO_dump_indent_fp := LoadLibFunction(ADllHandle, BIO_dump_indent_fp_procname);
  FuncLoadError := not assigned(BIO_dump_indent_fp);
  if FuncLoadError then
  begin
    {$if not defined(BIO_dump_indent_fp_allownil)}
    BIO_dump_indent_fp := ERR_BIO_dump_indent_fp;
    {$ifend}
    {$if declared(BIO_dump_indent_fp_introduced)}
    if LibVersion < BIO_dump_indent_fp_introduced then
    begin
      {$if declared(FC_BIO_dump_indent_fp)}
      BIO_dump_indent_fp := FC_BIO_dump_indent_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_dump_indent_fp_removed)}
    if BIO_dump_indent_fp_removed <= LibVersion then
    begin
      {$if declared(_BIO_dump_indent_fp)}
      BIO_dump_indent_fp := _BIO_dump_indent_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_dump_indent_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_dump_indent_fp');
    {$ifend}
  end;
  
  BIO_hex_string := LoadLibFunction(ADllHandle, BIO_hex_string_procname);
  FuncLoadError := not assigned(BIO_hex_string);
  if FuncLoadError then
  begin
    {$if not defined(BIO_hex_string_allownil)}
    BIO_hex_string := ERR_BIO_hex_string;
    {$ifend}
    {$if declared(BIO_hex_string_introduced)}
    if LibVersion < BIO_hex_string_introduced then
    begin
      {$if declared(FC_BIO_hex_string)}
      BIO_hex_string := FC_BIO_hex_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_hex_string_removed)}
    if BIO_hex_string_removed <= LibVersion then
    begin
      {$if declared(_BIO_hex_string)}
      BIO_hex_string := _BIO_hex_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_hex_string_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_hex_string');
    {$ifend}
  end;
  
  BIO_ADDR_new := LoadLibFunction(ADllHandle, BIO_ADDR_new_procname);
  FuncLoadError := not assigned(BIO_ADDR_new);
  if FuncLoadError then
  begin
    {$if not defined(BIO_ADDR_new_allownil)}
    BIO_ADDR_new := ERR_BIO_ADDR_new;
    {$ifend}
    {$if declared(BIO_ADDR_new_introduced)}
    if LibVersion < BIO_ADDR_new_introduced then
    begin
      {$if declared(FC_BIO_ADDR_new)}
      BIO_ADDR_new := FC_BIO_ADDR_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_ADDR_new_removed)}
    if BIO_ADDR_new_removed <= LibVersion then
    begin
      {$if declared(_BIO_ADDR_new)}
      BIO_ADDR_new := _BIO_ADDR_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_ADDR_new_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_ADDR_new');
    {$ifend}
  end;
  
  BIO_ADDR_copy := LoadLibFunction(ADllHandle, BIO_ADDR_copy_procname);
  FuncLoadError := not assigned(BIO_ADDR_copy);
  if FuncLoadError then
  begin
    {$if not defined(BIO_ADDR_copy_allownil)}
    BIO_ADDR_copy := ERR_BIO_ADDR_copy;
    {$ifend}
    {$if declared(BIO_ADDR_copy_introduced)}
    if LibVersion < BIO_ADDR_copy_introduced then
    begin
      {$if declared(FC_BIO_ADDR_copy)}
      BIO_ADDR_copy := FC_BIO_ADDR_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_ADDR_copy_removed)}
    if BIO_ADDR_copy_removed <= LibVersion then
    begin
      {$if declared(_BIO_ADDR_copy)}
      BIO_ADDR_copy := _BIO_ADDR_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_ADDR_copy_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_ADDR_copy');
    {$ifend}
  end;
  
  BIO_ADDR_dup := LoadLibFunction(ADllHandle, BIO_ADDR_dup_procname);
  FuncLoadError := not assigned(BIO_ADDR_dup);
  if FuncLoadError then
  begin
    {$if not defined(BIO_ADDR_dup_allownil)}
    BIO_ADDR_dup := ERR_BIO_ADDR_dup;
    {$ifend}
    {$if declared(BIO_ADDR_dup_introduced)}
    if LibVersion < BIO_ADDR_dup_introduced then
    begin
      {$if declared(FC_BIO_ADDR_dup)}
      BIO_ADDR_dup := FC_BIO_ADDR_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_ADDR_dup_removed)}
    if BIO_ADDR_dup_removed <= LibVersion then
    begin
      {$if declared(_BIO_ADDR_dup)}
      BIO_ADDR_dup := _BIO_ADDR_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_ADDR_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_ADDR_dup');
    {$ifend}
  end;
  
  BIO_ADDR_rawmake := LoadLibFunction(ADllHandle, BIO_ADDR_rawmake_procname);
  FuncLoadError := not assigned(BIO_ADDR_rawmake);
  if FuncLoadError then
  begin
    {$if not defined(BIO_ADDR_rawmake_allownil)}
    BIO_ADDR_rawmake := ERR_BIO_ADDR_rawmake;
    {$ifend}
    {$if declared(BIO_ADDR_rawmake_introduced)}
    if LibVersion < BIO_ADDR_rawmake_introduced then
    begin
      {$if declared(FC_BIO_ADDR_rawmake)}
      BIO_ADDR_rawmake := FC_BIO_ADDR_rawmake;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_ADDR_rawmake_removed)}
    if BIO_ADDR_rawmake_removed <= LibVersion then
    begin
      {$if declared(_BIO_ADDR_rawmake)}
      BIO_ADDR_rawmake := _BIO_ADDR_rawmake;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_ADDR_rawmake_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_ADDR_rawmake');
    {$ifend}
  end;
  
  BIO_ADDR_free := LoadLibFunction(ADllHandle, BIO_ADDR_free_procname);
  FuncLoadError := not assigned(BIO_ADDR_free);
  if FuncLoadError then
  begin
    {$if not defined(BIO_ADDR_free_allownil)}
    BIO_ADDR_free := ERR_BIO_ADDR_free;
    {$ifend}
    {$if declared(BIO_ADDR_free_introduced)}
    if LibVersion < BIO_ADDR_free_introduced then
    begin
      {$if declared(FC_BIO_ADDR_free)}
      BIO_ADDR_free := FC_BIO_ADDR_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_ADDR_free_removed)}
    if BIO_ADDR_free_removed <= LibVersion then
    begin
      {$if declared(_BIO_ADDR_free)}
      BIO_ADDR_free := _BIO_ADDR_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_ADDR_free_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_ADDR_free');
    {$ifend}
  end;
  
  BIO_ADDR_clear := LoadLibFunction(ADllHandle, BIO_ADDR_clear_procname);
  FuncLoadError := not assigned(BIO_ADDR_clear);
  if FuncLoadError then
  begin
    {$if not defined(BIO_ADDR_clear_allownil)}
    BIO_ADDR_clear := ERR_BIO_ADDR_clear;
    {$ifend}
    {$if declared(BIO_ADDR_clear_introduced)}
    if LibVersion < BIO_ADDR_clear_introduced then
    begin
      {$if declared(FC_BIO_ADDR_clear)}
      BIO_ADDR_clear := FC_BIO_ADDR_clear;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_ADDR_clear_removed)}
    if BIO_ADDR_clear_removed <= LibVersion then
    begin
      {$if declared(_BIO_ADDR_clear)}
      BIO_ADDR_clear := _BIO_ADDR_clear;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_ADDR_clear_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_ADDR_clear');
    {$ifend}
  end;
  
  BIO_ADDR_family := LoadLibFunction(ADllHandle, BIO_ADDR_family_procname);
  FuncLoadError := not assigned(BIO_ADDR_family);
  if FuncLoadError then
  begin
    {$if not defined(BIO_ADDR_family_allownil)}
    BIO_ADDR_family := ERR_BIO_ADDR_family;
    {$ifend}
    {$if declared(BIO_ADDR_family_introduced)}
    if LibVersion < BIO_ADDR_family_introduced then
    begin
      {$if declared(FC_BIO_ADDR_family)}
      BIO_ADDR_family := FC_BIO_ADDR_family;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_ADDR_family_removed)}
    if BIO_ADDR_family_removed <= LibVersion then
    begin
      {$if declared(_BIO_ADDR_family)}
      BIO_ADDR_family := _BIO_ADDR_family;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_ADDR_family_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_ADDR_family');
    {$ifend}
  end;
  
  BIO_ADDR_rawaddress := LoadLibFunction(ADllHandle, BIO_ADDR_rawaddress_procname);
  FuncLoadError := not assigned(BIO_ADDR_rawaddress);
  if FuncLoadError then
  begin
    {$if not defined(BIO_ADDR_rawaddress_allownil)}
    BIO_ADDR_rawaddress := ERR_BIO_ADDR_rawaddress;
    {$ifend}
    {$if declared(BIO_ADDR_rawaddress_introduced)}
    if LibVersion < BIO_ADDR_rawaddress_introduced then
    begin
      {$if declared(FC_BIO_ADDR_rawaddress)}
      BIO_ADDR_rawaddress := FC_BIO_ADDR_rawaddress;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_ADDR_rawaddress_removed)}
    if BIO_ADDR_rawaddress_removed <= LibVersion then
    begin
      {$if declared(_BIO_ADDR_rawaddress)}
      BIO_ADDR_rawaddress := _BIO_ADDR_rawaddress;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_ADDR_rawaddress_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_ADDR_rawaddress');
    {$ifend}
  end;
  
  BIO_ADDR_rawport := LoadLibFunction(ADllHandle, BIO_ADDR_rawport_procname);
  FuncLoadError := not assigned(BIO_ADDR_rawport);
  if FuncLoadError then
  begin
    {$if not defined(BIO_ADDR_rawport_allownil)}
    BIO_ADDR_rawport := ERR_BIO_ADDR_rawport;
    {$ifend}
    {$if declared(BIO_ADDR_rawport_introduced)}
    if LibVersion < BIO_ADDR_rawport_introduced then
    begin
      {$if declared(FC_BIO_ADDR_rawport)}
      BIO_ADDR_rawport := FC_BIO_ADDR_rawport;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_ADDR_rawport_removed)}
    if BIO_ADDR_rawport_removed <= LibVersion then
    begin
      {$if declared(_BIO_ADDR_rawport)}
      BIO_ADDR_rawport := _BIO_ADDR_rawport;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_ADDR_rawport_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_ADDR_rawport');
    {$ifend}
  end;
  
  BIO_ADDR_hostname_string := LoadLibFunction(ADllHandle, BIO_ADDR_hostname_string_procname);
  FuncLoadError := not assigned(BIO_ADDR_hostname_string);
  if FuncLoadError then
  begin
    {$if not defined(BIO_ADDR_hostname_string_allownil)}
    BIO_ADDR_hostname_string := ERR_BIO_ADDR_hostname_string;
    {$ifend}
    {$if declared(BIO_ADDR_hostname_string_introduced)}
    if LibVersion < BIO_ADDR_hostname_string_introduced then
    begin
      {$if declared(FC_BIO_ADDR_hostname_string)}
      BIO_ADDR_hostname_string := FC_BIO_ADDR_hostname_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_ADDR_hostname_string_removed)}
    if BIO_ADDR_hostname_string_removed <= LibVersion then
    begin
      {$if declared(_BIO_ADDR_hostname_string)}
      BIO_ADDR_hostname_string := _BIO_ADDR_hostname_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_ADDR_hostname_string_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_ADDR_hostname_string');
    {$ifend}
  end;
  
  BIO_ADDR_service_string := LoadLibFunction(ADllHandle, BIO_ADDR_service_string_procname);
  FuncLoadError := not assigned(BIO_ADDR_service_string);
  if FuncLoadError then
  begin
    {$if not defined(BIO_ADDR_service_string_allownil)}
    BIO_ADDR_service_string := ERR_BIO_ADDR_service_string;
    {$ifend}
    {$if declared(BIO_ADDR_service_string_introduced)}
    if LibVersion < BIO_ADDR_service_string_introduced then
    begin
      {$if declared(FC_BIO_ADDR_service_string)}
      BIO_ADDR_service_string := FC_BIO_ADDR_service_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_ADDR_service_string_removed)}
    if BIO_ADDR_service_string_removed <= LibVersion then
    begin
      {$if declared(_BIO_ADDR_service_string)}
      BIO_ADDR_service_string := _BIO_ADDR_service_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_ADDR_service_string_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_ADDR_service_string');
    {$ifend}
  end;
  
  BIO_ADDR_path_string := LoadLibFunction(ADllHandle, BIO_ADDR_path_string_procname);
  FuncLoadError := not assigned(BIO_ADDR_path_string);
  if FuncLoadError then
  begin
    {$if not defined(BIO_ADDR_path_string_allownil)}
    BIO_ADDR_path_string := ERR_BIO_ADDR_path_string;
    {$ifend}
    {$if declared(BIO_ADDR_path_string_introduced)}
    if LibVersion < BIO_ADDR_path_string_introduced then
    begin
      {$if declared(FC_BIO_ADDR_path_string)}
      BIO_ADDR_path_string := FC_BIO_ADDR_path_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_ADDR_path_string_removed)}
    if BIO_ADDR_path_string_removed <= LibVersion then
    begin
      {$if declared(_BIO_ADDR_path_string)}
      BIO_ADDR_path_string := _BIO_ADDR_path_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_ADDR_path_string_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_ADDR_path_string');
    {$ifend}
  end;
  
  BIO_ADDRINFO_next := LoadLibFunction(ADllHandle, BIO_ADDRINFO_next_procname);
  FuncLoadError := not assigned(BIO_ADDRINFO_next);
  if FuncLoadError then
  begin
    {$if not defined(BIO_ADDRINFO_next_allownil)}
    BIO_ADDRINFO_next := ERR_BIO_ADDRINFO_next;
    {$ifend}
    {$if declared(BIO_ADDRINFO_next_introduced)}
    if LibVersion < BIO_ADDRINFO_next_introduced then
    begin
      {$if declared(FC_BIO_ADDRINFO_next)}
      BIO_ADDRINFO_next := FC_BIO_ADDRINFO_next;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_ADDRINFO_next_removed)}
    if BIO_ADDRINFO_next_removed <= LibVersion then
    begin
      {$if declared(_BIO_ADDRINFO_next)}
      BIO_ADDRINFO_next := _BIO_ADDRINFO_next;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_ADDRINFO_next_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_ADDRINFO_next');
    {$ifend}
  end;
  
  BIO_ADDRINFO_family := LoadLibFunction(ADllHandle, BIO_ADDRINFO_family_procname);
  FuncLoadError := not assigned(BIO_ADDRINFO_family);
  if FuncLoadError then
  begin
    {$if not defined(BIO_ADDRINFO_family_allownil)}
    BIO_ADDRINFO_family := ERR_BIO_ADDRINFO_family;
    {$ifend}
    {$if declared(BIO_ADDRINFO_family_introduced)}
    if LibVersion < BIO_ADDRINFO_family_introduced then
    begin
      {$if declared(FC_BIO_ADDRINFO_family)}
      BIO_ADDRINFO_family := FC_BIO_ADDRINFO_family;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_ADDRINFO_family_removed)}
    if BIO_ADDRINFO_family_removed <= LibVersion then
    begin
      {$if declared(_BIO_ADDRINFO_family)}
      BIO_ADDRINFO_family := _BIO_ADDRINFO_family;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_ADDRINFO_family_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_ADDRINFO_family');
    {$ifend}
  end;
  
  BIO_ADDRINFO_socktype := LoadLibFunction(ADllHandle, BIO_ADDRINFO_socktype_procname);
  FuncLoadError := not assigned(BIO_ADDRINFO_socktype);
  if FuncLoadError then
  begin
    {$if not defined(BIO_ADDRINFO_socktype_allownil)}
    BIO_ADDRINFO_socktype := ERR_BIO_ADDRINFO_socktype;
    {$ifend}
    {$if declared(BIO_ADDRINFO_socktype_introduced)}
    if LibVersion < BIO_ADDRINFO_socktype_introduced then
    begin
      {$if declared(FC_BIO_ADDRINFO_socktype)}
      BIO_ADDRINFO_socktype := FC_BIO_ADDRINFO_socktype;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_ADDRINFO_socktype_removed)}
    if BIO_ADDRINFO_socktype_removed <= LibVersion then
    begin
      {$if declared(_BIO_ADDRINFO_socktype)}
      BIO_ADDRINFO_socktype := _BIO_ADDRINFO_socktype;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_ADDRINFO_socktype_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_ADDRINFO_socktype');
    {$ifend}
  end;
  
  BIO_ADDRINFO_protocol := LoadLibFunction(ADllHandle, BIO_ADDRINFO_protocol_procname);
  FuncLoadError := not assigned(BIO_ADDRINFO_protocol);
  if FuncLoadError then
  begin
    {$if not defined(BIO_ADDRINFO_protocol_allownil)}
    BIO_ADDRINFO_protocol := ERR_BIO_ADDRINFO_protocol;
    {$ifend}
    {$if declared(BIO_ADDRINFO_protocol_introduced)}
    if LibVersion < BIO_ADDRINFO_protocol_introduced then
    begin
      {$if declared(FC_BIO_ADDRINFO_protocol)}
      BIO_ADDRINFO_protocol := FC_BIO_ADDRINFO_protocol;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_ADDRINFO_protocol_removed)}
    if BIO_ADDRINFO_protocol_removed <= LibVersion then
    begin
      {$if declared(_BIO_ADDRINFO_protocol)}
      BIO_ADDRINFO_protocol := _BIO_ADDRINFO_protocol;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_ADDRINFO_protocol_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_ADDRINFO_protocol');
    {$ifend}
  end;
  
  BIO_ADDRINFO_address := LoadLibFunction(ADllHandle, BIO_ADDRINFO_address_procname);
  FuncLoadError := not assigned(BIO_ADDRINFO_address);
  if FuncLoadError then
  begin
    {$if not defined(BIO_ADDRINFO_address_allownil)}
    BIO_ADDRINFO_address := ERR_BIO_ADDRINFO_address;
    {$ifend}
    {$if declared(BIO_ADDRINFO_address_introduced)}
    if LibVersion < BIO_ADDRINFO_address_introduced then
    begin
      {$if declared(FC_BIO_ADDRINFO_address)}
      BIO_ADDRINFO_address := FC_BIO_ADDRINFO_address;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_ADDRINFO_address_removed)}
    if BIO_ADDRINFO_address_removed <= LibVersion then
    begin
      {$if declared(_BIO_ADDRINFO_address)}
      BIO_ADDRINFO_address := _BIO_ADDRINFO_address;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_ADDRINFO_address_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_ADDRINFO_address');
    {$ifend}
  end;
  
  BIO_ADDRINFO_free := LoadLibFunction(ADllHandle, BIO_ADDRINFO_free_procname);
  FuncLoadError := not assigned(BIO_ADDRINFO_free);
  if FuncLoadError then
  begin
    {$if not defined(BIO_ADDRINFO_free_allownil)}
    BIO_ADDRINFO_free := ERR_BIO_ADDRINFO_free;
    {$ifend}
    {$if declared(BIO_ADDRINFO_free_introduced)}
    if LibVersion < BIO_ADDRINFO_free_introduced then
    begin
      {$if declared(FC_BIO_ADDRINFO_free)}
      BIO_ADDRINFO_free := FC_BIO_ADDRINFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_ADDRINFO_free_removed)}
    if BIO_ADDRINFO_free_removed <= LibVersion then
    begin
      {$if declared(_BIO_ADDRINFO_free)}
      BIO_ADDRINFO_free := _BIO_ADDRINFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_ADDRINFO_free_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_ADDRINFO_free');
    {$ifend}
  end;
  
  BIO_parse_hostserv := LoadLibFunction(ADllHandle, BIO_parse_hostserv_procname);
  FuncLoadError := not assigned(BIO_parse_hostserv);
  if FuncLoadError then
  begin
    {$if not defined(BIO_parse_hostserv_allownil)}
    BIO_parse_hostserv := ERR_BIO_parse_hostserv;
    {$ifend}
    {$if declared(BIO_parse_hostserv_introduced)}
    if LibVersion < BIO_parse_hostserv_introduced then
    begin
      {$if declared(FC_BIO_parse_hostserv)}
      BIO_parse_hostserv := FC_BIO_parse_hostserv;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_parse_hostserv_removed)}
    if BIO_parse_hostserv_removed <= LibVersion then
    begin
      {$if declared(_BIO_parse_hostserv)}
      BIO_parse_hostserv := _BIO_parse_hostserv;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_parse_hostserv_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_parse_hostserv');
    {$ifend}
  end;
  
  BIO_lookup := LoadLibFunction(ADllHandle, BIO_lookup_procname);
  FuncLoadError := not assigned(BIO_lookup);
  if FuncLoadError then
  begin
    {$if not defined(BIO_lookup_allownil)}
    BIO_lookup := ERR_BIO_lookup;
    {$ifend}
    {$if declared(BIO_lookup_introduced)}
    if LibVersion < BIO_lookup_introduced then
    begin
      {$if declared(FC_BIO_lookup)}
      BIO_lookup := FC_BIO_lookup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_lookup_removed)}
    if BIO_lookup_removed <= LibVersion then
    begin
      {$if declared(_BIO_lookup)}
      BIO_lookup := _BIO_lookup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_lookup_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_lookup');
    {$ifend}
  end;
  
  BIO_lookup_ex := LoadLibFunction(ADllHandle, BIO_lookup_ex_procname);
  FuncLoadError := not assigned(BIO_lookup_ex);
  if FuncLoadError then
  begin
    {$if not defined(BIO_lookup_ex_allownil)}
    BIO_lookup_ex := ERR_BIO_lookup_ex;
    {$ifend}
    {$if declared(BIO_lookup_ex_introduced)}
    if LibVersion < BIO_lookup_ex_introduced then
    begin
      {$if declared(FC_BIO_lookup_ex)}
      BIO_lookup_ex := FC_BIO_lookup_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_lookup_ex_removed)}
    if BIO_lookup_ex_removed <= LibVersion then
    begin
      {$if declared(_BIO_lookup_ex)}
      BIO_lookup_ex := _BIO_lookup_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_lookup_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_lookup_ex');
    {$ifend}
  end;
  
  BIO_sock_error := LoadLibFunction(ADllHandle, BIO_sock_error_procname);
  FuncLoadError := not assigned(BIO_sock_error);
  if FuncLoadError then
  begin
    {$if not defined(BIO_sock_error_allownil)}
    BIO_sock_error := ERR_BIO_sock_error;
    {$ifend}
    {$if declared(BIO_sock_error_introduced)}
    if LibVersion < BIO_sock_error_introduced then
    begin
      {$if declared(FC_BIO_sock_error)}
      BIO_sock_error := FC_BIO_sock_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_sock_error_removed)}
    if BIO_sock_error_removed <= LibVersion then
    begin
      {$if declared(_BIO_sock_error)}
      BIO_sock_error := _BIO_sock_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_sock_error_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_sock_error');
    {$ifend}
  end;
  
  BIO_socket_ioctl := LoadLibFunction(ADllHandle, BIO_socket_ioctl_procname);
  FuncLoadError := not assigned(BIO_socket_ioctl);
  if FuncLoadError then
  begin
    {$if not defined(BIO_socket_ioctl_allownil)}
    BIO_socket_ioctl := ERR_BIO_socket_ioctl;
    {$ifend}
    {$if declared(BIO_socket_ioctl_introduced)}
    if LibVersion < BIO_socket_ioctl_introduced then
    begin
      {$if declared(FC_BIO_socket_ioctl)}
      BIO_socket_ioctl := FC_BIO_socket_ioctl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_socket_ioctl_removed)}
    if BIO_socket_ioctl_removed <= LibVersion then
    begin
      {$if declared(_BIO_socket_ioctl)}
      BIO_socket_ioctl := _BIO_socket_ioctl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_socket_ioctl_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_socket_ioctl');
    {$ifend}
  end;
  
  BIO_socket_nbio := LoadLibFunction(ADllHandle, BIO_socket_nbio_procname);
  FuncLoadError := not assigned(BIO_socket_nbio);
  if FuncLoadError then
  begin
    {$if not defined(BIO_socket_nbio_allownil)}
    BIO_socket_nbio := ERR_BIO_socket_nbio;
    {$ifend}
    {$if declared(BIO_socket_nbio_introduced)}
    if LibVersion < BIO_socket_nbio_introduced then
    begin
      {$if declared(FC_BIO_socket_nbio)}
      BIO_socket_nbio := FC_BIO_socket_nbio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_socket_nbio_removed)}
    if BIO_socket_nbio_removed <= LibVersion then
    begin
      {$if declared(_BIO_socket_nbio)}
      BIO_socket_nbio := _BIO_socket_nbio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_socket_nbio_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_socket_nbio');
    {$ifend}
  end;
  
  BIO_sock_init := LoadLibFunction(ADllHandle, BIO_sock_init_procname);
  FuncLoadError := not assigned(BIO_sock_init);
  if FuncLoadError then
  begin
    {$if not defined(BIO_sock_init_allownil)}
    BIO_sock_init := ERR_BIO_sock_init;
    {$ifend}
    {$if declared(BIO_sock_init_introduced)}
    if LibVersion < BIO_sock_init_introduced then
    begin
      {$if declared(FC_BIO_sock_init)}
      BIO_sock_init := FC_BIO_sock_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_sock_init_removed)}
    if BIO_sock_init_removed <= LibVersion then
    begin
      {$if declared(_BIO_sock_init)}
      BIO_sock_init := _BIO_sock_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_sock_init_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_sock_init');
    {$ifend}
  end;
  
  BIO_set_tcp_ndelay := LoadLibFunction(ADllHandle, BIO_set_tcp_ndelay_procname);
  FuncLoadError := not assigned(BIO_set_tcp_ndelay);
  if FuncLoadError then
  begin
    {$if not defined(BIO_set_tcp_ndelay_allownil)}
    BIO_set_tcp_ndelay := ERR_BIO_set_tcp_ndelay;
    {$ifend}
    {$if declared(BIO_set_tcp_ndelay_introduced)}
    if LibVersion < BIO_set_tcp_ndelay_introduced then
    begin
      {$if declared(FC_BIO_set_tcp_ndelay)}
      BIO_set_tcp_ndelay := FC_BIO_set_tcp_ndelay;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_set_tcp_ndelay_removed)}
    if BIO_set_tcp_ndelay_removed <= LibVersion then
    begin
      {$if declared(_BIO_set_tcp_ndelay)}
      BIO_set_tcp_ndelay := _BIO_set_tcp_ndelay;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_set_tcp_ndelay_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_set_tcp_ndelay');
    {$ifend}
  end;
  
  
  
  
  
  
  BIO_sock_info := LoadLibFunction(ADllHandle, BIO_sock_info_procname);
  FuncLoadError := not assigned(BIO_sock_info);
  if FuncLoadError then
  begin
    {$if not defined(BIO_sock_info_allownil)}
    BIO_sock_info := ERR_BIO_sock_info;
    {$ifend}
    {$if declared(BIO_sock_info_introduced)}
    if LibVersion < BIO_sock_info_introduced then
    begin
      {$if declared(FC_BIO_sock_info)}
      BIO_sock_info := FC_BIO_sock_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_sock_info_removed)}
    if BIO_sock_info_removed <= LibVersion then
    begin
      {$if declared(_BIO_sock_info)}
      BIO_sock_info := _BIO_sock_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_sock_info_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_sock_info');
    {$ifend}
  end;
  
  BIO_socket := LoadLibFunction(ADllHandle, BIO_socket_procname);
  FuncLoadError := not assigned(BIO_socket);
  if FuncLoadError then
  begin
    {$if not defined(BIO_socket_allownil)}
    BIO_socket := ERR_BIO_socket;
    {$ifend}
    {$if declared(BIO_socket_introduced)}
    if LibVersion < BIO_socket_introduced then
    begin
      {$if declared(FC_BIO_socket)}
      BIO_socket := FC_BIO_socket;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_socket_removed)}
    if BIO_socket_removed <= LibVersion then
    begin
      {$if declared(_BIO_socket)}
      BIO_socket := _BIO_socket;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_socket_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_socket');
    {$ifend}
  end;
  
  BIO_connect := LoadLibFunction(ADllHandle, BIO_connect_procname);
  FuncLoadError := not assigned(BIO_connect);
  if FuncLoadError then
  begin
    {$if not defined(BIO_connect_allownil)}
    BIO_connect := ERR_BIO_connect;
    {$ifend}
    {$if declared(BIO_connect_introduced)}
    if LibVersion < BIO_connect_introduced then
    begin
      {$if declared(FC_BIO_connect)}
      BIO_connect := FC_BIO_connect;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_connect_removed)}
    if BIO_connect_removed <= LibVersion then
    begin
      {$if declared(_BIO_connect)}
      BIO_connect := _BIO_connect;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_connect_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_connect');
    {$ifend}
  end;
  
  BIO_bind := LoadLibFunction(ADllHandle, BIO_bind_procname);
  FuncLoadError := not assigned(BIO_bind);
  if FuncLoadError then
  begin
    {$if not defined(BIO_bind_allownil)}
    BIO_bind := ERR_BIO_bind;
    {$ifend}
    {$if declared(BIO_bind_introduced)}
    if LibVersion < BIO_bind_introduced then
    begin
      {$if declared(FC_BIO_bind)}
      BIO_bind := FC_BIO_bind;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_bind_removed)}
    if BIO_bind_removed <= LibVersion then
    begin
      {$if declared(_BIO_bind)}
      BIO_bind := _BIO_bind;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_bind_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_bind');
    {$ifend}
  end;
  
  BIO_listen := LoadLibFunction(ADllHandle, BIO_listen_procname);
  FuncLoadError := not assigned(BIO_listen);
  if FuncLoadError then
  begin
    {$if not defined(BIO_listen_allownil)}
    BIO_listen := ERR_BIO_listen;
    {$ifend}
    {$if declared(BIO_listen_introduced)}
    if LibVersion < BIO_listen_introduced then
    begin
      {$if declared(FC_BIO_listen)}
      BIO_listen := FC_BIO_listen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_listen_removed)}
    if BIO_listen_removed <= LibVersion then
    begin
      {$if declared(_BIO_listen)}
      BIO_listen := _BIO_listen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_listen_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_listen');
    {$ifend}
  end;
  
  BIO_accept_ex := LoadLibFunction(ADllHandle, BIO_accept_ex_procname);
  FuncLoadError := not assigned(BIO_accept_ex);
  if FuncLoadError then
  begin
    {$if not defined(BIO_accept_ex_allownil)}
    BIO_accept_ex := ERR_BIO_accept_ex;
    {$ifend}
    {$if declared(BIO_accept_ex_introduced)}
    if LibVersion < BIO_accept_ex_introduced then
    begin
      {$if declared(FC_BIO_accept_ex)}
      BIO_accept_ex := FC_BIO_accept_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_accept_ex_removed)}
    if BIO_accept_ex_removed <= LibVersion then
    begin
      {$if declared(_BIO_accept_ex)}
      BIO_accept_ex := _BIO_accept_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_accept_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_accept_ex');
    {$ifend}
  end;
  
  BIO_closesocket := LoadLibFunction(ADllHandle, BIO_closesocket_procname);
  FuncLoadError := not assigned(BIO_closesocket);
  if FuncLoadError then
  begin
    {$if not defined(BIO_closesocket_allownil)}
    BIO_closesocket := ERR_BIO_closesocket;
    {$ifend}
    {$if declared(BIO_closesocket_introduced)}
    if LibVersion < BIO_closesocket_introduced then
    begin
      {$if declared(FC_BIO_closesocket)}
      BIO_closesocket := FC_BIO_closesocket;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_closesocket_removed)}
    if BIO_closesocket_removed <= LibVersion then
    begin
      {$if declared(_BIO_closesocket)}
      BIO_closesocket := _BIO_closesocket;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_closesocket_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_closesocket');
    {$ifend}
  end;
  
  BIO_new_socket := LoadLibFunction(ADllHandle, BIO_new_socket_procname);
  FuncLoadError := not assigned(BIO_new_socket);
  if FuncLoadError then
  begin
    {$if not defined(BIO_new_socket_allownil)}
    BIO_new_socket := ERR_BIO_new_socket;
    {$ifend}
    {$if declared(BIO_new_socket_introduced)}
    if LibVersion < BIO_new_socket_introduced then
    begin
      {$if declared(FC_BIO_new_socket)}
      BIO_new_socket := FC_BIO_new_socket;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_new_socket_removed)}
    if BIO_new_socket_removed <= LibVersion then
    begin
      {$if declared(_BIO_new_socket)}
      BIO_new_socket := _BIO_new_socket;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_new_socket_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_new_socket');
    {$ifend}
  end;
  
  BIO_new_connect := LoadLibFunction(ADllHandle, BIO_new_connect_procname);
  FuncLoadError := not assigned(BIO_new_connect);
  if FuncLoadError then
  begin
    {$if not defined(BIO_new_connect_allownil)}
    BIO_new_connect := ERR_BIO_new_connect;
    {$ifend}
    {$if declared(BIO_new_connect_introduced)}
    if LibVersion < BIO_new_connect_introduced then
    begin
      {$if declared(FC_BIO_new_connect)}
      BIO_new_connect := FC_BIO_new_connect;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_new_connect_removed)}
    if BIO_new_connect_removed <= LibVersion then
    begin
      {$if declared(_BIO_new_connect)}
      BIO_new_connect := _BIO_new_connect;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_new_connect_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_new_connect');
    {$ifend}
  end;
  
  BIO_new_accept := LoadLibFunction(ADllHandle, BIO_new_accept_procname);
  FuncLoadError := not assigned(BIO_new_accept);
  if FuncLoadError then
  begin
    {$if not defined(BIO_new_accept_allownil)}
    BIO_new_accept := ERR_BIO_new_accept;
    {$ifend}
    {$if declared(BIO_new_accept_introduced)}
    if LibVersion < BIO_new_accept_introduced then
    begin
      {$if declared(FC_BIO_new_accept)}
      BIO_new_accept := FC_BIO_new_accept;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_new_accept_removed)}
    if BIO_new_accept_removed <= LibVersion then
    begin
      {$if declared(_BIO_new_accept)}
      BIO_new_accept := _BIO_new_accept;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_new_accept_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_new_accept');
    {$ifend}
  end;
  
  BIO_new_fd := LoadLibFunction(ADllHandle, BIO_new_fd_procname);
  FuncLoadError := not assigned(BIO_new_fd);
  if FuncLoadError then
  begin
    {$if not defined(BIO_new_fd_allownil)}
    BIO_new_fd := ERR_BIO_new_fd;
    {$ifend}
    {$if declared(BIO_new_fd_introduced)}
    if LibVersion < BIO_new_fd_introduced then
    begin
      {$if declared(FC_BIO_new_fd)}
      BIO_new_fd := FC_BIO_new_fd;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_new_fd_removed)}
    if BIO_new_fd_removed <= LibVersion then
    begin
      {$if declared(_BIO_new_fd)}
      BIO_new_fd := _BIO_new_fd;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_new_fd_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_new_fd');
    {$ifend}
  end;
  
  BIO_new_bio_pair := LoadLibFunction(ADllHandle, BIO_new_bio_pair_procname);
  FuncLoadError := not assigned(BIO_new_bio_pair);
  if FuncLoadError then
  begin
    {$if not defined(BIO_new_bio_pair_allownil)}
    BIO_new_bio_pair := ERR_BIO_new_bio_pair;
    {$ifend}
    {$if declared(BIO_new_bio_pair_introduced)}
    if LibVersion < BIO_new_bio_pair_introduced then
    begin
      {$if declared(FC_BIO_new_bio_pair)}
      BIO_new_bio_pair := FC_BIO_new_bio_pair;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_new_bio_pair_removed)}
    if BIO_new_bio_pair_removed <= LibVersion then
    begin
      {$if declared(_BIO_new_bio_pair)}
      BIO_new_bio_pair := _BIO_new_bio_pair;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_new_bio_pair_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_new_bio_pair');
    {$ifend}
  end;
  
  BIO_new_bio_dgram_pair := LoadLibFunction(ADllHandle, BIO_new_bio_dgram_pair_procname);
  FuncLoadError := not assigned(BIO_new_bio_dgram_pair);
  if FuncLoadError then
  begin
    {$if not defined(BIO_new_bio_dgram_pair_allownil)}
    BIO_new_bio_dgram_pair := ERR_BIO_new_bio_dgram_pair;
    {$ifend}
    {$if declared(BIO_new_bio_dgram_pair_introduced)}
    if LibVersion < BIO_new_bio_dgram_pair_introduced then
    begin
      {$if declared(FC_BIO_new_bio_dgram_pair)}
      BIO_new_bio_dgram_pair := FC_BIO_new_bio_dgram_pair;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_new_bio_dgram_pair_removed)}
    if BIO_new_bio_dgram_pair_removed <= LibVersion then
    begin
      {$if declared(_BIO_new_bio_dgram_pair)}
      BIO_new_bio_dgram_pair := _BIO_new_bio_dgram_pair;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_new_bio_dgram_pair_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_new_bio_dgram_pair');
    {$ifend}
  end;
  
  BIO_copy_next_retry := LoadLibFunction(ADllHandle, BIO_copy_next_retry_procname);
  FuncLoadError := not assigned(BIO_copy_next_retry);
  if FuncLoadError then
  begin
    {$if not defined(BIO_copy_next_retry_allownil)}
    BIO_copy_next_retry := ERR_BIO_copy_next_retry;
    {$ifend}
    {$if declared(BIO_copy_next_retry_introduced)}
    if LibVersion < BIO_copy_next_retry_introduced then
    begin
      {$if declared(FC_BIO_copy_next_retry)}
      BIO_copy_next_retry := FC_BIO_copy_next_retry;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_copy_next_retry_removed)}
    if BIO_copy_next_retry_removed <= LibVersion then
    begin
      {$if declared(_BIO_copy_next_retry)}
      BIO_copy_next_retry := _BIO_copy_next_retry;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_copy_next_retry_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_copy_next_retry');
    {$ifend}
  end;
  
  BIO_printf := LoadLibFunction(ADllHandle, BIO_printf_procname);
  FuncLoadError := not assigned(BIO_printf);
  if FuncLoadError then
  begin
    {$if not defined(BIO_printf_allownil)}
    BIO_printf := ERR_BIO_printf;
    {$ifend}
    {$if declared(BIO_printf_introduced)}
    if LibVersion < BIO_printf_introduced then
    begin
      {$if declared(FC_BIO_printf)}
      BIO_printf := FC_BIO_printf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_printf_removed)}
    if BIO_printf_removed <= LibVersion then
    begin
      {$if declared(_BIO_printf)}
      BIO_printf := _BIO_printf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_printf_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_printf');
    {$ifend}
  end;
  
  BIO_vprintf := LoadLibFunction(ADllHandle, BIO_vprintf_procname);
  FuncLoadError := not assigned(BIO_vprintf);
  if FuncLoadError then
  begin
    {$if not defined(BIO_vprintf_allownil)}
    BIO_vprintf := ERR_BIO_vprintf;
    {$ifend}
    {$if declared(BIO_vprintf_introduced)}
    if LibVersion < BIO_vprintf_introduced then
    begin
      {$if declared(FC_BIO_vprintf)}
      BIO_vprintf := FC_BIO_vprintf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_vprintf_removed)}
    if BIO_vprintf_removed <= LibVersion then
    begin
      {$if declared(_BIO_vprintf)}
      BIO_vprintf := _BIO_vprintf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_vprintf_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_vprintf');
    {$ifend}
  end;
  
  BIO_snprintf := LoadLibFunction(ADllHandle, BIO_snprintf_procname);
  FuncLoadError := not assigned(BIO_snprintf);
  if FuncLoadError then
  begin
    {$if not defined(BIO_snprintf_allownil)}
    BIO_snprintf := ERR_BIO_snprintf;
    {$ifend}
    {$if declared(BIO_snprintf_introduced)}
    if LibVersion < BIO_snprintf_introduced then
    begin
      {$if declared(FC_BIO_snprintf)}
      BIO_snprintf := FC_BIO_snprintf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_snprintf_removed)}
    if BIO_snprintf_removed <= LibVersion then
    begin
      {$if declared(_BIO_snprintf)}
      BIO_snprintf := _BIO_snprintf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_snprintf_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_snprintf');
    {$ifend}
  end;
  
  BIO_vsnprintf := LoadLibFunction(ADllHandle, BIO_vsnprintf_procname);
  FuncLoadError := not assigned(BIO_vsnprintf);
  if FuncLoadError then
  begin
    {$if not defined(BIO_vsnprintf_allownil)}
    BIO_vsnprintf := ERR_BIO_vsnprintf;
    {$ifend}
    {$if declared(BIO_vsnprintf_introduced)}
    if LibVersion < BIO_vsnprintf_introduced then
    begin
      {$if declared(FC_BIO_vsnprintf)}
      BIO_vsnprintf := FC_BIO_vsnprintf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_vsnprintf_removed)}
    if BIO_vsnprintf_removed <= LibVersion then
    begin
      {$if declared(_BIO_vsnprintf)}
      BIO_vsnprintf := _BIO_vsnprintf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_vsnprintf_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_vsnprintf');
    {$ifend}
  end;
  
  BIO_meth_new := LoadLibFunction(ADllHandle, BIO_meth_new_procname);
  FuncLoadError := not assigned(BIO_meth_new);
  if FuncLoadError then
  begin
    {$if not defined(BIO_meth_new_allownil)}
    BIO_meth_new := ERR_BIO_meth_new;
    {$ifend}
    {$if declared(BIO_meth_new_introduced)}
    if LibVersion < BIO_meth_new_introduced then
    begin
      {$if declared(FC_BIO_meth_new)}
      BIO_meth_new := FC_BIO_meth_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_meth_new_removed)}
    if BIO_meth_new_removed <= LibVersion then
    begin
      {$if declared(_BIO_meth_new)}
      BIO_meth_new := _BIO_meth_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_meth_new_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_meth_new');
    {$ifend}
  end;
  
  BIO_meth_free := LoadLibFunction(ADllHandle, BIO_meth_free_procname);
  FuncLoadError := not assigned(BIO_meth_free);
  if FuncLoadError then
  begin
    {$if not defined(BIO_meth_free_allownil)}
    BIO_meth_free := ERR_BIO_meth_free;
    {$ifend}
    {$if declared(BIO_meth_free_introduced)}
    if LibVersion < BIO_meth_free_introduced then
    begin
      {$if declared(FC_BIO_meth_free)}
      BIO_meth_free := FC_BIO_meth_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_meth_free_removed)}
    if BIO_meth_free_removed <= LibVersion then
    begin
      {$if declared(_BIO_meth_free)}
      BIO_meth_free := _BIO_meth_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_meth_free_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_meth_free');
    {$ifend}
  end;
  
  BIO_meth_set_write := LoadLibFunction(ADllHandle, BIO_meth_set_write_procname);
  FuncLoadError := not assigned(BIO_meth_set_write);
  if FuncLoadError then
  begin
    {$if not defined(BIO_meth_set_write_allownil)}
    BIO_meth_set_write := ERR_BIO_meth_set_write;
    {$ifend}
    {$if declared(BIO_meth_set_write_introduced)}
    if LibVersion < BIO_meth_set_write_introduced then
    begin
      {$if declared(FC_BIO_meth_set_write)}
      BIO_meth_set_write := FC_BIO_meth_set_write;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_meth_set_write_removed)}
    if BIO_meth_set_write_removed <= LibVersion then
    begin
      {$if declared(_BIO_meth_set_write)}
      BIO_meth_set_write := _BIO_meth_set_write;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_meth_set_write_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_meth_set_write');
    {$ifend}
  end;
  
  BIO_meth_set_write_ex := LoadLibFunction(ADllHandle, BIO_meth_set_write_ex_procname);
  FuncLoadError := not assigned(BIO_meth_set_write_ex);
  if FuncLoadError then
  begin
    {$if not defined(BIO_meth_set_write_ex_allownil)}
    BIO_meth_set_write_ex := ERR_BIO_meth_set_write_ex;
    {$ifend}
    {$if declared(BIO_meth_set_write_ex_introduced)}
    if LibVersion < BIO_meth_set_write_ex_introduced then
    begin
      {$if declared(FC_BIO_meth_set_write_ex)}
      BIO_meth_set_write_ex := FC_BIO_meth_set_write_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_meth_set_write_ex_removed)}
    if BIO_meth_set_write_ex_removed <= LibVersion then
    begin
      {$if declared(_BIO_meth_set_write_ex)}
      BIO_meth_set_write_ex := _BIO_meth_set_write_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_meth_set_write_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_meth_set_write_ex');
    {$ifend}
  end;
  
  BIO_meth_set_sendmmsg := LoadLibFunction(ADllHandle, BIO_meth_set_sendmmsg_procname);
  FuncLoadError := not assigned(BIO_meth_set_sendmmsg);
  if FuncLoadError then
  begin
    {$if not defined(BIO_meth_set_sendmmsg_allownil)}
    BIO_meth_set_sendmmsg := ERR_BIO_meth_set_sendmmsg;
    {$ifend}
    {$if declared(BIO_meth_set_sendmmsg_introduced)}
    if LibVersion < BIO_meth_set_sendmmsg_introduced then
    begin
      {$if declared(FC_BIO_meth_set_sendmmsg)}
      BIO_meth_set_sendmmsg := FC_BIO_meth_set_sendmmsg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_meth_set_sendmmsg_removed)}
    if BIO_meth_set_sendmmsg_removed <= LibVersion then
    begin
      {$if declared(_BIO_meth_set_sendmmsg)}
      BIO_meth_set_sendmmsg := _BIO_meth_set_sendmmsg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_meth_set_sendmmsg_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_meth_set_sendmmsg');
    {$ifend}
  end;
  
  BIO_meth_set_read := LoadLibFunction(ADllHandle, BIO_meth_set_read_procname);
  FuncLoadError := not assigned(BIO_meth_set_read);
  if FuncLoadError then
  begin
    {$if not defined(BIO_meth_set_read_allownil)}
    BIO_meth_set_read := ERR_BIO_meth_set_read;
    {$ifend}
    {$if declared(BIO_meth_set_read_introduced)}
    if LibVersion < BIO_meth_set_read_introduced then
    begin
      {$if declared(FC_BIO_meth_set_read)}
      BIO_meth_set_read := FC_BIO_meth_set_read;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_meth_set_read_removed)}
    if BIO_meth_set_read_removed <= LibVersion then
    begin
      {$if declared(_BIO_meth_set_read)}
      BIO_meth_set_read := _BIO_meth_set_read;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_meth_set_read_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_meth_set_read');
    {$ifend}
  end;
  
  BIO_meth_set_read_ex := LoadLibFunction(ADllHandle, BIO_meth_set_read_ex_procname);
  FuncLoadError := not assigned(BIO_meth_set_read_ex);
  if FuncLoadError then
  begin
    {$if not defined(BIO_meth_set_read_ex_allownil)}
    BIO_meth_set_read_ex := ERR_BIO_meth_set_read_ex;
    {$ifend}
    {$if declared(BIO_meth_set_read_ex_introduced)}
    if LibVersion < BIO_meth_set_read_ex_introduced then
    begin
      {$if declared(FC_BIO_meth_set_read_ex)}
      BIO_meth_set_read_ex := FC_BIO_meth_set_read_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_meth_set_read_ex_removed)}
    if BIO_meth_set_read_ex_removed <= LibVersion then
    begin
      {$if declared(_BIO_meth_set_read_ex)}
      BIO_meth_set_read_ex := _BIO_meth_set_read_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_meth_set_read_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_meth_set_read_ex');
    {$ifend}
  end;
  
  BIO_meth_set_recvmmsg := LoadLibFunction(ADllHandle, BIO_meth_set_recvmmsg_procname);
  FuncLoadError := not assigned(BIO_meth_set_recvmmsg);
  if FuncLoadError then
  begin
    {$if not defined(BIO_meth_set_recvmmsg_allownil)}
    BIO_meth_set_recvmmsg := ERR_BIO_meth_set_recvmmsg;
    {$ifend}
    {$if declared(BIO_meth_set_recvmmsg_introduced)}
    if LibVersion < BIO_meth_set_recvmmsg_introduced then
    begin
      {$if declared(FC_BIO_meth_set_recvmmsg)}
      BIO_meth_set_recvmmsg := FC_BIO_meth_set_recvmmsg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_meth_set_recvmmsg_removed)}
    if BIO_meth_set_recvmmsg_removed <= LibVersion then
    begin
      {$if declared(_BIO_meth_set_recvmmsg)}
      BIO_meth_set_recvmmsg := _BIO_meth_set_recvmmsg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_meth_set_recvmmsg_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_meth_set_recvmmsg');
    {$ifend}
  end;
  
  BIO_meth_set_puts := LoadLibFunction(ADllHandle, BIO_meth_set_puts_procname);
  FuncLoadError := not assigned(BIO_meth_set_puts);
  if FuncLoadError then
  begin
    {$if not defined(BIO_meth_set_puts_allownil)}
    BIO_meth_set_puts := ERR_BIO_meth_set_puts;
    {$ifend}
    {$if declared(BIO_meth_set_puts_introduced)}
    if LibVersion < BIO_meth_set_puts_introduced then
    begin
      {$if declared(FC_BIO_meth_set_puts)}
      BIO_meth_set_puts := FC_BIO_meth_set_puts;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_meth_set_puts_removed)}
    if BIO_meth_set_puts_removed <= LibVersion then
    begin
      {$if declared(_BIO_meth_set_puts)}
      BIO_meth_set_puts := _BIO_meth_set_puts;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_meth_set_puts_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_meth_set_puts');
    {$ifend}
  end;
  
  BIO_meth_set_gets := LoadLibFunction(ADllHandle, BIO_meth_set_gets_procname);
  FuncLoadError := not assigned(BIO_meth_set_gets);
  if FuncLoadError then
  begin
    {$if not defined(BIO_meth_set_gets_allownil)}
    BIO_meth_set_gets := ERR_BIO_meth_set_gets;
    {$ifend}
    {$if declared(BIO_meth_set_gets_introduced)}
    if LibVersion < BIO_meth_set_gets_introduced then
    begin
      {$if declared(FC_BIO_meth_set_gets)}
      BIO_meth_set_gets := FC_BIO_meth_set_gets;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_meth_set_gets_removed)}
    if BIO_meth_set_gets_removed <= LibVersion then
    begin
      {$if declared(_BIO_meth_set_gets)}
      BIO_meth_set_gets := _BIO_meth_set_gets;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_meth_set_gets_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_meth_set_gets');
    {$ifend}
  end;
  
  BIO_meth_set_ctrl := LoadLibFunction(ADllHandle, BIO_meth_set_ctrl_procname);
  FuncLoadError := not assigned(BIO_meth_set_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(BIO_meth_set_ctrl_allownil)}
    BIO_meth_set_ctrl := ERR_BIO_meth_set_ctrl;
    {$ifend}
    {$if declared(BIO_meth_set_ctrl_introduced)}
    if LibVersion < BIO_meth_set_ctrl_introduced then
    begin
      {$if declared(FC_BIO_meth_set_ctrl)}
      BIO_meth_set_ctrl := FC_BIO_meth_set_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_meth_set_ctrl_removed)}
    if BIO_meth_set_ctrl_removed <= LibVersion then
    begin
      {$if declared(_BIO_meth_set_ctrl)}
      BIO_meth_set_ctrl := _BIO_meth_set_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_meth_set_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_meth_set_ctrl');
    {$ifend}
  end;
  
  BIO_meth_set_create := LoadLibFunction(ADllHandle, BIO_meth_set_create_procname);
  FuncLoadError := not assigned(BIO_meth_set_create);
  if FuncLoadError then
  begin
    {$if not defined(BIO_meth_set_create_allownil)}
    BIO_meth_set_create := ERR_BIO_meth_set_create;
    {$ifend}
    {$if declared(BIO_meth_set_create_introduced)}
    if LibVersion < BIO_meth_set_create_introduced then
    begin
      {$if declared(FC_BIO_meth_set_create)}
      BIO_meth_set_create := FC_BIO_meth_set_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_meth_set_create_removed)}
    if BIO_meth_set_create_removed <= LibVersion then
    begin
      {$if declared(_BIO_meth_set_create)}
      BIO_meth_set_create := _BIO_meth_set_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_meth_set_create_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_meth_set_create');
    {$ifend}
  end;
  
  BIO_meth_set_destroy := LoadLibFunction(ADllHandle, BIO_meth_set_destroy_procname);
  FuncLoadError := not assigned(BIO_meth_set_destroy);
  if FuncLoadError then
  begin
    {$if not defined(BIO_meth_set_destroy_allownil)}
    BIO_meth_set_destroy := ERR_BIO_meth_set_destroy;
    {$ifend}
    {$if declared(BIO_meth_set_destroy_introduced)}
    if LibVersion < BIO_meth_set_destroy_introduced then
    begin
      {$if declared(FC_BIO_meth_set_destroy)}
      BIO_meth_set_destroy := FC_BIO_meth_set_destroy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_meth_set_destroy_removed)}
    if BIO_meth_set_destroy_removed <= LibVersion then
    begin
      {$if declared(_BIO_meth_set_destroy)}
      BIO_meth_set_destroy := _BIO_meth_set_destroy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_meth_set_destroy_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_meth_set_destroy');
    {$ifend}
  end;
  
  BIO_meth_set_callback_ctrl := LoadLibFunction(ADllHandle, BIO_meth_set_callback_ctrl_procname);
  FuncLoadError := not assigned(BIO_meth_set_callback_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(BIO_meth_set_callback_ctrl_allownil)}
    BIO_meth_set_callback_ctrl := ERR_BIO_meth_set_callback_ctrl;
    {$ifend}
    {$if declared(BIO_meth_set_callback_ctrl_introduced)}
    if LibVersion < BIO_meth_set_callback_ctrl_introduced then
    begin
      {$if declared(FC_BIO_meth_set_callback_ctrl)}
      BIO_meth_set_callback_ctrl := FC_BIO_meth_set_callback_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_meth_set_callback_ctrl_removed)}
    if BIO_meth_set_callback_ctrl_removed <= LibVersion then
    begin
      {$if declared(_BIO_meth_set_callback_ctrl)}
      BIO_meth_set_callback_ctrl := _BIO_meth_set_callback_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_meth_set_callback_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_meth_set_callback_ctrl');
    {$ifend}
  end;
  
  BIO_meth_get_write := LoadLibFunction(ADllHandle, BIO_meth_get_write_procname);
  FuncLoadError := not assigned(BIO_meth_get_write);
  if FuncLoadError then
  begin
    {$if not defined(BIO_meth_get_write_allownil)}
    BIO_meth_get_write := ERR_BIO_meth_get_write;
    {$ifend}
    {$if declared(BIO_meth_get_write_introduced)}
    if LibVersion < BIO_meth_get_write_introduced then
    begin
      {$if declared(FC_BIO_meth_get_write)}
      BIO_meth_get_write := FC_BIO_meth_get_write;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_meth_get_write_removed)}
    if BIO_meth_get_write_removed <= LibVersion then
    begin
      {$if declared(_BIO_meth_get_write)}
      BIO_meth_get_write := _BIO_meth_get_write;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_meth_get_write_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_meth_get_write');
    {$ifend}
  end;
  
  BIO_meth_get_write_ex := LoadLibFunction(ADllHandle, BIO_meth_get_write_ex_procname);
  FuncLoadError := not assigned(BIO_meth_get_write_ex);
  if FuncLoadError then
  begin
    {$if not defined(BIO_meth_get_write_ex_allownil)}
    BIO_meth_get_write_ex := ERR_BIO_meth_get_write_ex;
    {$ifend}
    {$if declared(BIO_meth_get_write_ex_introduced)}
    if LibVersion < BIO_meth_get_write_ex_introduced then
    begin
      {$if declared(FC_BIO_meth_get_write_ex)}
      BIO_meth_get_write_ex := FC_BIO_meth_get_write_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_meth_get_write_ex_removed)}
    if BIO_meth_get_write_ex_removed <= LibVersion then
    begin
      {$if declared(_BIO_meth_get_write_ex)}
      BIO_meth_get_write_ex := _BIO_meth_get_write_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_meth_get_write_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_meth_get_write_ex');
    {$ifend}
  end;
  
  BIO_meth_get_sendmmsg := LoadLibFunction(ADllHandle, BIO_meth_get_sendmmsg_procname);
  FuncLoadError := not assigned(BIO_meth_get_sendmmsg);
  if FuncLoadError then
  begin
    {$if not defined(BIO_meth_get_sendmmsg_allownil)}
    BIO_meth_get_sendmmsg := ERR_BIO_meth_get_sendmmsg;
    {$ifend}
    {$if declared(BIO_meth_get_sendmmsg_introduced)}
    if LibVersion < BIO_meth_get_sendmmsg_introduced then
    begin
      {$if declared(FC_BIO_meth_get_sendmmsg)}
      BIO_meth_get_sendmmsg := FC_BIO_meth_get_sendmmsg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_meth_get_sendmmsg_removed)}
    if BIO_meth_get_sendmmsg_removed <= LibVersion then
    begin
      {$if declared(_BIO_meth_get_sendmmsg)}
      BIO_meth_get_sendmmsg := _BIO_meth_get_sendmmsg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_meth_get_sendmmsg_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_meth_get_sendmmsg');
    {$ifend}
  end;
  
  BIO_meth_get_read := LoadLibFunction(ADllHandle, BIO_meth_get_read_procname);
  FuncLoadError := not assigned(BIO_meth_get_read);
  if FuncLoadError then
  begin
    {$if not defined(BIO_meth_get_read_allownil)}
    BIO_meth_get_read := ERR_BIO_meth_get_read;
    {$ifend}
    {$if declared(BIO_meth_get_read_introduced)}
    if LibVersion < BIO_meth_get_read_introduced then
    begin
      {$if declared(FC_BIO_meth_get_read)}
      BIO_meth_get_read := FC_BIO_meth_get_read;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_meth_get_read_removed)}
    if BIO_meth_get_read_removed <= LibVersion then
    begin
      {$if declared(_BIO_meth_get_read)}
      BIO_meth_get_read := _BIO_meth_get_read;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_meth_get_read_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_meth_get_read');
    {$ifend}
  end;
  
  BIO_meth_get_read_ex := LoadLibFunction(ADllHandle, BIO_meth_get_read_ex_procname);
  FuncLoadError := not assigned(BIO_meth_get_read_ex);
  if FuncLoadError then
  begin
    {$if not defined(BIO_meth_get_read_ex_allownil)}
    BIO_meth_get_read_ex := ERR_BIO_meth_get_read_ex;
    {$ifend}
    {$if declared(BIO_meth_get_read_ex_introduced)}
    if LibVersion < BIO_meth_get_read_ex_introduced then
    begin
      {$if declared(FC_BIO_meth_get_read_ex)}
      BIO_meth_get_read_ex := FC_BIO_meth_get_read_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_meth_get_read_ex_removed)}
    if BIO_meth_get_read_ex_removed <= LibVersion then
    begin
      {$if declared(_BIO_meth_get_read_ex)}
      BIO_meth_get_read_ex := _BIO_meth_get_read_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_meth_get_read_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_meth_get_read_ex');
    {$ifend}
  end;
  
  BIO_meth_get_recvmmsg := LoadLibFunction(ADllHandle, BIO_meth_get_recvmmsg_procname);
  FuncLoadError := not assigned(BIO_meth_get_recvmmsg);
  if FuncLoadError then
  begin
    {$if not defined(BIO_meth_get_recvmmsg_allownil)}
    BIO_meth_get_recvmmsg := ERR_BIO_meth_get_recvmmsg;
    {$ifend}
    {$if declared(BIO_meth_get_recvmmsg_introduced)}
    if LibVersion < BIO_meth_get_recvmmsg_introduced then
    begin
      {$if declared(FC_BIO_meth_get_recvmmsg)}
      BIO_meth_get_recvmmsg := FC_BIO_meth_get_recvmmsg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_meth_get_recvmmsg_removed)}
    if BIO_meth_get_recvmmsg_removed <= LibVersion then
    begin
      {$if declared(_BIO_meth_get_recvmmsg)}
      BIO_meth_get_recvmmsg := _BIO_meth_get_recvmmsg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_meth_get_recvmmsg_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_meth_get_recvmmsg');
    {$ifend}
  end;
  
  BIO_meth_get_puts := LoadLibFunction(ADllHandle, BIO_meth_get_puts_procname);
  FuncLoadError := not assigned(BIO_meth_get_puts);
  if FuncLoadError then
  begin
    {$if not defined(BIO_meth_get_puts_allownil)}
    BIO_meth_get_puts := ERR_BIO_meth_get_puts;
    {$ifend}
    {$if declared(BIO_meth_get_puts_introduced)}
    if LibVersion < BIO_meth_get_puts_introduced then
    begin
      {$if declared(FC_BIO_meth_get_puts)}
      BIO_meth_get_puts := FC_BIO_meth_get_puts;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_meth_get_puts_removed)}
    if BIO_meth_get_puts_removed <= LibVersion then
    begin
      {$if declared(_BIO_meth_get_puts)}
      BIO_meth_get_puts := _BIO_meth_get_puts;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_meth_get_puts_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_meth_get_puts');
    {$ifend}
  end;
  
  BIO_meth_get_gets := LoadLibFunction(ADllHandle, BIO_meth_get_gets_procname);
  FuncLoadError := not assigned(BIO_meth_get_gets);
  if FuncLoadError then
  begin
    {$if not defined(BIO_meth_get_gets_allownil)}
    BIO_meth_get_gets := ERR_BIO_meth_get_gets;
    {$ifend}
    {$if declared(BIO_meth_get_gets_introduced)}
    if LibVersion < BIO_meth_get_gets_introduced then
    begin
      {$if declared(FC_BIO_meth_get_gets)}
      BIO_meth_get_gets := FC_BIO_meth_get_gets;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_meth_get_gets_removed)}
    if BIO_meth_get_gets_removed <= LibVersion then
    begin
      {$if declared(_BIO_meth_get_gets)}
      BIO_meth_get_gets := _BIO_meth_get_gets;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_meth_get_gets_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_meth_get_gets');
    {$ifend}
  end;
  
  BIO_meth_get_ctrl := LoadLibFunction(ADllHandle, BIO_meth_get_ctrl_procname);
  FuncLoadError := not assigned(BIO_meth_get_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(BIO_meth_get_ctrl_allownil)}
    BIO_meth_get_ctrl := ERR_BIO_meth_get_ctrl;
    {$ifend}
    {$if declared(BIO_meth_get_ctrl_introduced)}
    if LibVersion < BIO_meth_get_ctrl_introduced then
    begin
      {$if declared(FC_BIO_meth_get_ctrl)}
      BIO_meth_get_ctrl := FC_BIO_meth_get_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_meth_get_ctrl_removed)}
    if BIO_meth_get_ctrl_removed <= LibVersion then
    begin
      {$if declared(_BIO_meth_get_ctrl)}
      BIO_meth_get_ctrl := _BIO_meth_get_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_meth_get_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_meth_get_ctrl');
    {$ifend}
  end;
  
  BIO_meth_get_create := LoadLibFunction(ADllHandle, BIO_meth_get_create_procname);
  FuncLoadError := not assigned(BIO_meth_get_create);
  if FuncLoadError then
  begin
    {$if not defined(BIO_meth_get_create_allownil)}
    BIO_meth_get_create := ERR_BIO_meth_get_create;
    {$ifend}
    {$if declared(BIO_meth_get_create_introduced)}
    if LibVersion < BIO_meth_get_create_introduced then
    begin
      {$if declared(FC_BIO_meth_get_create)}
      BIO_meth_get_create := FC_BIO_meth_get_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_meth_get_create_removed)}
    if BIO_meth_get_create_removed <= LibVersion then
    begin
      {$if declared(_BIO_meth_get_create)}
      BIO_meth_get_create := _BIO_meth_get_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_meth_get_create_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_meth_get_create');
    {$ifend}
  end;
  
  BIO_meth_get_destroy := LoadLibFunction(ADllHandle, BIO_meth_get_destroy_procname);
  FuncLoadError := not assigned(BIO_meth_get_destroy);
  if FuncLoadError then
  begin
    {$if not defined(BIO_meth_get_destroy_allownil)}
    BIO_meth_get_destroy := ERR_BIO_meth_get_destroy;
    {$ifend}
    {$if declared(BIO_meth_get_destroy_introduced)}
    if LibVersion < BIO_meth_get_destroy_introduced then
    begin
      {$if declared(FC_BIO_meth_get_destroy)}
      BIO_meth_get_destroy := FC_BIO_meth_get_destroy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_meth_get_destroy_removed)}
    if BIO_meth_get_destroy_removed <= LibVersion then
    begin
      {$if declared(_BIO_meth_get_destroy)}
      BIO_meth_get_destroy := _BIO_meth_get_destroy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_meth_get_destroy_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_meth_get_destroy');
    {$ifend}
  end;
  
  BIO_meth_get_callback_ctrl := LoadLibFunction(ADllHandle, BIO_meth_get_callback_ctrl_procname);
  FuncLoadError := not assigned(BIO_meth_get_callback_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(BIO_meth_get_callback_ctrl_allownil)}
    BIO_meth_get_callback_ctrl := ERR_BIO_meth_get_callback_ctrl;
    {$ifend}
    {$if declared(BIO_meth_get_callback_ctrl_introduced)}
    if LibVersion < BIO_meth_get_callback_ctrl_introduced then
    begin
      {$if declared(FC_BIO_meth_get_callback_ctrl)}
      BIO_meth_get_callback_ctrl := FC_BIO_meth_get_callback_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_meth_get_callback_ctrl_removed)}
    if BIO_meth_get_callback_ctrl_removed <= LibVersion then
    begin
      {$if declared(_BIO_meth_get_callback_ctrl)}
      BIO_meth_get_callback_ctrl := _BIO_meth_get_callback_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_meth_get_callback_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_meth_get_callback_ctrl');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  BIO_get_new_index := nil;
  BIO_set_flags := nil;
  BIO_test_flags := nil;
  BIO_clear_flags := nil;
  BIO_get_callback := nil;
  BIO_set_callback := nil;
  BIO_debug_callback := nil;
  BIO_get_callback_ex := nil;
  BIO_set_callback_ex := nil;
  BIO_debug_callback_ex := nil;
  BIO_get_callback_arg := nil;
  BIO_set_callback_arg := nil;
  BIO_method_name := nil;
  BIO_method_type := nil;
  BIO_ctrl_pending := nil;
  BIO_ctrl_wpending := nil;
  BIO_ctrl_get_write_guarantee := nil;
  BIO_ctrl_get_read_request := nil;
  BIO_ctrl_reset_read_request := nil;
  BIO_set_ex_data := nil;
  BIO_get_ex_data := nil;
  BIO_number_read := nil;
  BIO_number_written := nil;
  BIO_asn1_set_prefix := nil;
  BIO_asn1_get_prefix := nil;
  BIO_asn1_set_suffix := nil;
  BIO_asn1_get_suffix := nil;
  BIO_s_file := nil;
  BIO_new_file := nil;
  BIO_new_from_core_bio := nil;
  BIO_new_fp := nil;
  BIO_new_ex := nil;
  BIO_new := nil;
  BIO_free := nil;
  BIO_set_data := nil;
  BIO_get_data := nil;
  BIO_set_init := nil;
  BIO_get_init := nil;
  BIO_set_shutdown := nil;
  BIO_get_shutdown := nil;
  BIO_vfree := nil;
  BIO_up_ref := nil;
  BIO_read := nil;
  BIO_read_ex := nil;
  BIO_recvmmsg := nil;
  BIO_gets := nil;
  BIO_get_line := nil;
  BIO_write := nil;
  BIO_write_ex := nil;
  BIO_sendmmsg := nil;
  BIO_get_rpoll_descriptor := nil;
  BIO_get_wpoll_descriptor := nil;
  BIO_puts := nil;
  BIO_indent := nil;
  BIO_ctrl := nil;
  BIO_callback_ctrl := nil;
  BIO_ptr_ctrl := nil;
  BIO_int_ctrl := nil;
  BIO_push := nil;
  BIO_pop := nil;
  BIO_free_all := nil;
  BIO_find_type := nil;
  BIO_next := nil;
  BIO_set_next := nil;
  BIO_get_retry_BIO := nil;
  BIO_get_retry_reason := nil;
  BIO_set_retry_reason := nil;
  BIO_dup_chain := nil;
  BIO_nread0 := nil;
  BIO_nread := nil;
  BIO_nwrite0 := nil;
  BIO_nwrite := nil;
  BIO_s_mem := nil;
  BIO_s_dgram_mem := nil;
  BIO_s_secmem := nil;
  BIO_new_mem_buf := nil;
  BIO_s_socket := nil;
  BIO_s_connect := nil;
  BIO_s_accept := nil;
  BIO_s_fd := nil;
  BIO_s_log := nil;
  BIO_s_bio := nil;
  BIO_s_null := nil;
  BIO_f_null := nil;
  BIO_f_buffer := nil;
  BIO_f_readbuffer := nil;
  BIO_f_linebuffer := nil;
  BIO_f_nbio_test := nil;
  BIO_f_prefix := nil;
  BIO_s_core := nil;
  BIO_s_dgram_pair := nil;
  BIO_s_datagram := nil;
  BIO_dgram_non_fatal_error := nil;
  BIO_new_dgram := nil;
  BIO_sock_should_retry := nil;
  BIO_sock_non_fatal_error := nil;
  BIO_err_is_non_fatal := nil;
  BIO_socket_wait := nil;
  BIO_wait := nil;
  BIO_do_connect_retry := nil;
  BIO_fd_should_retry := nil;
  BIO_fd_non_fatal_error := nil;
  BIO_dump_cb := nil;
  BIO_dump_indent_cb := nil;
  BIO_dump := nil;
  BIO_dump_indent := nil;
  BIO_dump_fp := nil;
  BIO_dump_indent_fp := nil;
  BIO_hex_string := nil;
  BIO_ADDR_new := nil;
  BIO_ADDR_copy := nil;
  BIO_ADDR_dup := nil;
  BIO_ADDR_rawmake := nil;
  BIO_ADDR_free := nil;
  BIO_ADDR_clear := nil;
  BIO_ADDR_family := nil;
  BIO_ADDR_rawaddress := nil;
  BIO_ADDR_rawport := nil;
  BIO_ADDR_hostname_string := nil;
  BIO_ADDR_service_string := nil;
  BIO_ADDR_path_string := nil;
  BIO_ADDRINFO_next := nil;
  BIO_ADDRINFO_family := nil;
  BIO_ADDRINFO_socktype := nil;
  BIO_ADDRINFO_protocol := nil;
  BIO_ADDRINFO_address := nil;
  BIO_ADDRINFO_free := nil;
  BIO_parse_hostserv := nil;
  BIO_lookup := nil;
  BIO_lookup_ex := nil;
  BIO_sock_error := nil;
  BIO_socket_ioctl := nil;
  BIO_socket_nbio := nil;
  BIO_sock_init := nil;
  BIO_set_tcp_ndelay := nil;
  BIO_sock_info := nil;
  BIO_socket := nil;
  BIO_connect := nil;
  BIO_bind := nil;
  BIO_listen := nil;
  BIO_accept_ex := nil;
  BIO_closesocket := nil;
  BIO_new_socket := nil;
  BIO_new_connect := nil;
  BIO_new_accept := nil;
  BIO_new_fd := nil;
  BIO_new_bio_pair := nil;
  BIO_new_bio_dgram_pair := nil;
  BIO_copy_next_retry := nil;
  BIO_printf := nil;
  BIO_vprintf := nil;
  BIO_snprintf := nil;
  BIO_vsnprintf := nil;
  BIO_meth_new := nil;
  BIO_meth_free := nil;
  BIO_meth_set_write := nil;
  BIO_meth_set_write_ex := nil;
  BIO_meth_set_sendmmsg := nil;
  BIO_meth_set_read := nil;
  BIO_meth_set_read_ex := nil;
  BIO_meth_set_recvmmsg := nil;
  BIO_meth_set_puts := nil;
  BIO_meth_set_gets := nil;
  BIO_meth_set_ctrl := nil;
  BIO_meth_set_create := nil;
  BIO_meth_set_destroy := nil;
  BIO_meth_set_callback_ctrl := nil;
  BIO_meth_get_write := nil;
  BIO_meth_get_write_ex := nil;
  BIO_meth_get_sendmmsg := nil;
  BIO_meth_get_read := nil;
  BIO_meth_get_read_ex := nil;
  BIO_meth_get_recvmmsg := nil;
  BIO_meth_get_puts := nil;
  BIO_meth_get_gets := nil;
  BIO_meth_get_ctrl := nil;
  BIO_meth_get_create := nil;
  BIO_meth_get_destroy := nil;
  BIO_meth_get_callback_ctrl := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.