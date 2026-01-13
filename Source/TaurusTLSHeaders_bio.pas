/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_bio.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_bio.h2pas
     and this file regenerated. TaurusTLSHeaders_bio.h2pas is distributed with the full Indy
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

unit TaurusTLSHeaders_bio;

interface

// Headers for OpenSSL 1.1.1
// bio.h


uses
  IdCTypes,
  IdGlobal
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  , TaurusTLSConsts
  {$ENDIF},
  TaurusTLSHeaders_types;

{$MINENUMSIZE 4}

const
  (* There are the classes of BIOs *)
  BIO_TYPE_DESCRIPTOR = $0100;
  BIO_TYPE_FILTER = $0200;
  BIO_TYPE_SOURCE_SINK = $0400;

  (* These are the 'types' of BIOs *)
  BIO_TYPE_NONE = 0;
  BIO_TYPE_MEM =  1 or BIO_TYPE_SOURCE_SINK;
  BIO_TYPE_FILE =  2 or BIO_TYPE_SOURCE_SINK;

  BIO_TYPE_FD          =  4 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR;
  BIO_TYPE_SOCKET      =  5 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR;
  BIO_TYPE_NULL        =  6 or BIO_TYPE_SOURCE_SINK;
  BIO_TYPE_SSL         =  7 or BIO_TYPE_FILTER;
  BIO_TYPE_MD          =  8 or BIO_TYPE_FILTER;
  BIO_TYPE_BUFFER      =  9 or BIO_TYPE_FILTER;
  BIO_TYPE_CIPHER      = 10 or BIO_TYPE_FILTER;
  BIO_TYPE_BASE64      = 11 or BIO_TYPE_FILTER;
  BIO_TYPE_CONNECT     = 12 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR;
  BIO_TYPE_ACCEPT      = 13 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR;

  BIO_TYPE_NBIO_TEST   = 16 or BIO_TYPE_FILTER;
  BIO_TYPE_NULL_FILTER = 17 or BIO_TYPE_FILTER;
  BIO_TYPE_BIO         = 19 or BIO_TYPE_SOURCE_SINK;
  BIO_TYPE_LINEBUFFER  = 20 or BIO_TYPE_FILTER;
  BIO_TYPE_DGRAM       = 21 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR;
  BIO_TYPE_ASN1        = 22 or BIO_TYPE_FILTER;
  BIO_TYPE_COMP        = 23 or BIO_TYPE_FILTER;
  BIO_TYPE_DGRAM_SCTP  = 24 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR;

  BIO_TYPE_START = 128;

  (*
   * BIO_FILENAME_READ|BIO_CLOSE to open or close on free.
   * BIO_set_fp(in,stdin,BIO_NOCLOSE);
   *)
  BIO_NOCLOSE = $00;
  BIO_CLOSE   = $01;

  (*
   * These are used in the following macros and are passed to BIO_ctrl()
   *)
  BIO_CTRL_RESET        = 1;(* opt - rewind/zero etc *)
  BIO_CTRL_EOF          = 2;(* opt - are we at the eof *)
  BIO_CTRL_INFO         = 3;(* opt - extra tit-bits *)
  BIO_CTRL_SET          = 4;(* man - set the 'IO' type *)
  BIO_CTRL_GET          = 5;(* man - get the 'IO' type *)
  BIO_CTRL_PUSH         = 6;(* opt - internal, used to signify change *)
  BIO_CTRL_POP          = 7;(* opt - internal, used to signify change *)
  BIO_CTRL_GET_CLOSE    = 8;(* man - set the 'close' on free *)
  BIO_CTRL_SET_CLOSE    = 9;(* man - set the 'close' on free *)
  // Added "_const" to prevent naming clashes
  BIO_CTRL_PENDING_const      = 10;(* opt - is their more data buffered *)
  BIO_CTRL_FLUSH        = 11;(* opt - 'flush' buffered output *)
  BIO_CTRL_DUP          = 12;(* man - extra stuff for 'duped' BIO *)
  // Added "_const" to prevent naming clashes
  BIO_CTRL_WPENDING_const     = 13;(* opt - number of bytes still to write *)
  BIO_CTRL_SET_CALLBACK = 14;(* opt - set callback function *)
  BIO_CTRL_GET_CALLBACK = 15;(* opt - set callback function *)

  BIO_CTRL_PEEK         = 29;(* BIO_f_buffer special *)
  BIO_CTRL_SET_FILENAME = 30;(* BIO_s_file special *)

  (* dgram BIO stuff *)
  BIO_CTRL_DGRAM_CONNECT       = 31;(* BIO dgram special *)
  BIO_CTRL_DGRAM_SET_CONNECTED = 32;(* allow for an externally connected
                                           * socket to be passed in *)
  BIO_CTRL_DGRAM_SET_RECV_TIMEOUT = 33;(* setsockopt, essentially *)
  BIO_CTRL_DGRAM_GET_RECV_TIMEOUT = 34;(* getsockopt, essentially *)
  BIO_CTRL_DGRAM_SET_SEND_TIMEOUT = 35;(* setsockopt, essentially *)
  BIO_CTRL_DGRAM_GET_SEND_TIMEOUT = 36;(* getsockopt, essentially *)

  BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP = 37;(* flag whether the last *)
  BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP = 38;(* I/O operation tiemd out *)

  BIO_CTRL_DGRAM_MTU_DISCOVER     = 39;(* set DF bit on egress packets *)

  BIO_CTRL_DGRAM_QUERY_MTU        = 40;(* as kernel for current MTU *)
  BIO_CTRL_DGRAM_GET_FALLBACK_MTU = 47;
  BIO_CTRL_DGRAM_GET_MTU          = 41;(* get cached value for MTU *)
  BIO_CTRL_DGRAM_SET_MTU          = 42;(* set cached value for MTU.
                                                * want to use this if asking
                                                * the kernel fails *)

  BIO_CTRL_DGRAM_MTU_EXCEEDED     = 43;(* check whether the MTU was
                                                * exceed in the previous write
                                                * operation *)

  BIO_CTRL_DGRAM_GET_PEER         = 46;
  BIO_CTRL_DGRAM_SET_PEER         = 44;(* Destination for the data *)

  BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT = 45;(* Next DTLS handshake timeout
                                                * to adjust socket timeouts *)
  BIO_CTRL_DGRAM_SET_DONT_FRAG    = 48;

  BIO_CTRL_DGRAM_GET_MTU_OVERHEAD = 49;

  (* Deliberately outside of OPENSSL_NO_SCTP - used in bss_dgram.c *)
  BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE  = 50;
  (* SCTP stuff *)
  BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY      = 51;
  BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY     = 52;
  BIO_CTRL_DGRAM_SCTP_AUTH_CCS_RCVD     = 53;
  BIO_CTRL_DGRAM_SCTP_GET_SNDINFO       = 60;
  BIO_CTRL_DGRAM_SCTP_SET_SNDINFO       = 61;
  BIO_CTRL_DGRAM_SCTP_GET_RCVINFO       = 62;
  BIO_CTRL_DGRAM_SCTP_SET_RCVINFO       = 63;
  BIO_CTRL_DGRAM_SCTP_GET_PRINFO        = 64;
  BIO_CTRL_DGRAM_SCTP_SET_PRINFO        = 65;
  BIO_CTRL_DGRAM_SCTP_SAVE_SHUTDOWN     = 70;

  BIO_CTRL_DGRAM_SET_PEEK_MODE          = 71;

  BIO_CTRL_GET_KTLS_SEND                = 73;
  BIO_CTRL_GET_KTLS_RECV                = 76;

  BIO_CTRL_DGRAM_SCTP_WAIT_FOR_DRY      = 77;
  BIO_CTRL_DGRAM_SCTP_MSG_WAITING       = 78;

//* BIO_f_prefix controls */
  BIO_CTRL_SET_PREFIX                   = 79;
  BIO_CTRL_SET_INDENT                   = 80;
  BIO_CTRL_GET_INDENT                   = 81;

  BIO_CTRL_DGRAM_GET_LOCAL_ADDR_CAP     = 82;
  BIO_CTRL_DGRAM_GET_LOCAL_ADDR_ENABLE  = 83;
  BIO_CTRL_DGRAM_SET_LOCAL_ADDR_ENABLE  = 84;
  BIO_CTRL_DGRAM_GET_EFFECTIVE_CAPS     = 85;
  BIO_CTRL_DGRAM_GET_CAPS               = 86;
  BIO_CTRL_DGRAM_SET_CAPS               = 87;
  BIO_CTRL_DGRAM_GET_NO_TRUNC           = 88;
  BIO_CTRL_DGRAM_SET_NO_TRUNC           = 89;

{*
 * internal BIO:
 *   BIO_CTRL_SET_KTLS_TX_ZEROCOPY_SENDFILE 90
 *}

  BIO_CTRL_GET_RPOLL_DESCRIPTOR         = 91;
  BIO_CTRL_GET_WPOLL_DESCRIPTOR         = 92;
  BIO_CTRL_DGRAM_DETECT_PEER_ADDR       = 93;
  BIO_CTRL_DGRAM_SET0_LOCAL_ADDR        = 94;

  BIO_DGRAM_CAP_NONE = 0;

  BIO_DGRAM_CAP_HANDLES_SRC_ADDR = 1 shl 0;
  BIO_DGRAM_CAP_HANDLES_DST_ADDR = 1 shl 1;
  BIO_DGRAM_CAP_PROVIDES_SRC_ADDR = 1 shl 2;
  BIO_DGRAM_CAP_PROVIDES_DST_ADDR = 1 shl 3;

  (* modifiers *)
  BIO_FP_READ            = $02;
  BIO_FP_WRITE           = $04;
  BIO_FP_APPEND          = $08;
  BIO_FP_TEXT            = $10;

  BIO_FLAGS_READ         = $01;
  BIO_FLAGS_WRITE        = $02;
  BIO_FLAGS_IO_SPECIAL   = $04;
  BIO_FLAGS_RWS          = BIO_FLAGS_READ or BIO_FLAGS_WRITE or BIO_FLAGS_IO_SPECIAL;
  BIO_FLAGS_SHOULD_RETRY = $08;

  BIO_FLAGS_BASE64_NO_NL = $100;

  (*
   * This is used with memory BIOs:
   * BIO_FLAGS_MEM_RDONLY means we shouldn't free up or change the data in any way;
   * BIO_FLAGS_NONCLEAR_RST means we shouldn't clear data on reset.
   *)
  BIO_FLAGS_MEM_RDONLY   = $200;
  BIO_FLAGS_NONCLEAR_RST = $400;

  BIO_RR_SSL_X509_LOOKUP = $01;
  (* Returned from the connect BIO when a connect would have blocked *)
  BIO_RR_CONNECT         = $02;
  (* Returned from the accept BIO when an accept would have blocked *)
  BIO_RR_ACCEPT          = $03;

  (* These are passed by the BIO callback *)
  BIO_CB_FREE  = $01;
  BIO_CB_READ  = $02;
  BIO_CB_WRITE = $03;
  BIO_CB_PUTS  = $04;
  BIO_CB_GETS  = $05;
  BIO_CB_CTRL  = $06;
///*
// * The callback is called before and after the underling operation, The
// * BIO_CB_RETURN flag indicates if it is after the call
// */
//# define BIO_CB_RETURN   0x80
//# define BIO_CB_return(a) ((a)|BIO_CB_RETURN)
//# define BIO_cb_pre(a)   (!((a)&BIO_CB_RETURN))
//# define BIO_cb_post(a)  ((a)&BIO_CB_RETURN)

  BIO_C_SET_CONNECT                 = 100;
  BIO_C_DO_STATE_MACHINE            = 101;
  BIO_C_SET_NBIO                    = 102;
  (* BIO_C_SET_PROXY_PARAM            = 103 *)
  BIO_C_SET_FD                      = 104;
  BIO_C_GET_FD                      = 105;
  BIO_C_SET_FILE_PTR                = 106;
  BIO_C_GET_FILE_PTR                = 107;
  BIO_C_SET_FILENAME                = 108;
  BIO_C_SET_SSL                     = 109;
  BIO_C_GET_SSL                     = 110;
  BIO_C_SET_MD                      = 111;
  BIO_C_GET_MD                      = 112;
  BIO_C_GET_CIPHER_STATUS           = 113;
  BIO_C_SET_BUF_MEM                 = 114;
  BIO_C_GET_BUF_MEM_PTR             = 115;
  BIO_C_GET_BUFF_NUM_LINES          = 116;
  BIO_C_SET_BUFF_SIZE               = 117;
  BIO_C_SET_ACCEPT                  = 118;
  BIO_C_SSL_MODE                    = 119;
  BIO_C_GET_MD_CTX                  = 120;
  (* BIO_C_GET_PROXY_PARAM             = 121 *)
  BIO_C_SET_BUFF_READ_DATA          = 122;(* data to read first *)
  BIO_C_GET_CONNECT                 = 123;
  BIO_C_GET_ACCEPT                  = 124;
  BIO_C_SET_SSL_RENEGOTIATE_BYTES   = 125;
  BIO_C_GET_SSL_NUM_RENEGOTIATES    = 126;
  BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT = 127;
  BIO_C_FILE_SEEK                   = 128;
  BIO_C_GET_CIPHER_CTX              = 129;
  BIO_C_SET_BUF_MEM_EOF_RETURN      = 130;(* return end of input
                                                       * value *)
  BIO_C_SET_BIND_MODE               = 131;
  BIO_C_GET_BIND_MODE               = 132;
  BIO_C_FILE_TELL                   = 133;
  BIO_C_GET_SOCKS                   = 134;
  BIO_C_SET_SOCKS                   = 135;

  BIO_C_SET_WRITE_BUF_SIZE          = 136;(* for BIO_s_bio *)
  BIO_C_GET_WRITE_BUF_SIZE          = 137;
  BIO_C_MAKE_BIO_PAIR               = 138;
  BIO_C_DESTROY_BIO_PAIR            = 139;
  BIO_C_GET_WRITE_GUARANTEE         = 140;
  BIO_C_GET_READ_REQUEST            = 141;
  BIO_C_SHUTDOWN_WR                 = 142;
  BIO_C_NREAD0                      = 143;
  BIO_C_NREAD                       = 144;
  BIO_C_NWRITE0                     = 145;
  BIO_C_NWRITE                      = 146;
  BIO_C_RESET_READ_REQUEST          = 147;
  BIO_C_SET_MD_CTX                  = 148;

  BIO_C_SET_PREFIX                  = 149;
  BIO_C_GET_PREFIX                  = 150;
  BIO_C_SET_SUFFIX                  = 151;
  BIO_C_GET_SUFFIX                  = 152;

  BIO_C_SET_EX_ARG                  = 153;
  BIO_C_GET_EX_ARG                  = 154;

  BIO_C_SET_CONNECT_MODE            = 155;

  BIO_SOCK_REUSEADDR = $01;
  BIO_SOCK_V6_ONLY   = $02;
  BIO_SOCK_KEEPALIVE = $04;
  BIO_SOCK_NONBLOCK  = $08;
  BIO_SOCK_NODELAY   = $10;

  BIO_POLL_DESCRIPTOR_TYPE_NONE     =  0;
  BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD    = 1;
  BIO_POLL_DESCRIPTOR_TYPE_SSL        = 2;
  BIO_POLL_DESCRIPTOR_CUSTOM_START    = 8192;

type
  BIO_ADDR = Pointer; // bio_addr_st
  PBIO_ADDR = ^BIO_ADDR;
  BIO_ADDRINFO = Pointer; // bio_addrinfo_st
  PBIO_ADDRINFO = ^BIO_ADDRINFO;
  PPBIO_ADDRINFO = ^PBIO_ADDRINFO;
  BIO_callback_fn = function(b: PBIO; oper: TIdC_INT; const argp: PIdAnsiChar;
    argi: TIdC_INT; argl: TIdC_LONG; ret: TIdC_LONG): TIdC_LONG;
  BIO_callback_fn_ex = function(b: PBIO; oper: TIdC_INT; const argp: PIdAnsiChar; len: TIdC_SIZET; argi: TIdC_INT; argl: TIdC_LONG; ret: TIdC_INT; processed: PIdC_SIZET): TIdC_LONG;
  BIO_METHOD = Pointer; // bio_method_st
  PBIO_METHOD = ^BIO_METHOD;
  BIO_info_cb = function(v1: PBIO; v2: TIdC_INT; v3: TIdC_INT): TIdC_INT;
  PBIO_info_cb = ^BIO_info_cb;
  asn1_ps_func = function(b: PBIO; pbuf: PPIdAnsiChar; plen: PIdC_INT; parg: Pointer): TIdC_INT;

  bio_dgram_sctp_sndinfo = record
    snd_sid: TIdC_UINT16;
    snd_flags: TIdC_UINT16;
    snd_ppid: TIdC_UINT32;
    snd_context: TIdC_UINT32;
  end;

  bio_dgram_sctp_rcvinfo = record
    rcv_sid: TIdC_UINT16;
    rcv_ssn: TIdC_UINT16;
    rcv_flags: TIdC_UINT16;
    rcv_ppid: TIdC_UINT32;
    rcv_tsn: TIdC_UINT32;
    rcv_cumtsn: TIdC_UINT32;
    rcv_context: TIdC_UINT32;
  end;

  bio_dgram_sctp_prinfo = record
    pr_policy: TIdC_UINT16;
    pr_value: TIdC_UINT32;
  end;

  BIO_hostserv_priorities = (BIO_PARSE_PRIO_HOST, BIO_PARSE_PRIO_SERV);

  BIO_lookup_type = (BIO_LOOKUP_CLIENT, BIO_LOOKUP_SERVER);

  BIO_sock_info_u = record
    address: PBIO_ADDR;
  end;
  PBIO_sock_info_u = ^BIO_sock_info_u;

  BIO_sock_info_type = (BIO_SOCK_INFO_ADDRESS);

  //* BIO_sendmmsg/BIO_recvmmsg-related definitions */
  bio_msg_st = record
    data : Pointer;
    data_len : TIdC_SIZET;
    peer, local_ : PBIO_ADDR;
    flags : TIdC_UINT64;
  end;
  BIO_MSG = bio_msg_st;
  PBIO_MSG = ^BIO_MSG;

  bio_mmsg_cb_args_st = record
    msg : PBIO_MSG;
    stride, num_msg : TIdC_SIZET;
    flags : TIdC_UINT64;
    msgs_processed : PIdC_SIZET;
  end;
  BIO_MMSG_CB_ARGS = bio_mmsg_cb_args_st;
  PBIO_MMSG_CB_ARGS = ^BIO_MMSG_CB_ARGS;

  // Define a union type for the value field
  TValueUnion = record
    case Integer of
      0: (fd: TIdC_INT);
      1: (custom: Pointer);
      2: (custom_ui: TIdC_SIZET); //Todo: use something besides TIdC_SIZET
      3: (ssl: PSSL);
  end;
  bio_poll_descriptor_st = record
    _type : TIdC_UINT32;
    value : TValueUnion;
  end;
  BIO_POLL_DESCRIPTOR = bio_poll_descriptor_st;
  PBIO_POLL_DESCRIPTOR = ^BIO_POLL_DESCRIPTOR;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  
  {$EXTERNALSYM BIO_get_new_index} {introduced 1.1.0}
  {$EXTERNALSYM BIO_set_flags}
  {$EXTERNALSYM BIO_test_flags}
  {$EXTERNALSYM BIO_clear_flags}
  {$EXTERNALSYM BIO_get_callback}
  {$EXTERNALSYM BIO_set_callback}
  {$EXTERNALSYM BIO_get_callback_ex} {introduced 1.1.0}
  {$EXTERNALSYM BIO_set_callback_ex} {introduced 1.1.0}
  {$EXTERNALSYM BIO_get_callback_arg}
  {$EXTERNALSYM BIO_set_callback_arg}
  {$EXTERNALSYM BIO_method_name}
  {$EXTERNALSYM BIO_method_type}
//  {$EXTERNALSYM PBIO}
  {$EXTERNALSYM BIO_ctrl_pending}
  {$EXTERNALSYM BIO_ctrl_wpending}
  {$EXTERNALSYM BIO_ctrl_get_write_guarantee}
  {$EXTERNALSYM BIO_ctrl_get_read_request}
  {$EXTERNALSYM BIO_ctrl_reset_read_request}
  {$EXTERNALSYM BIO_set_ex_data}
  {$EXTERNALSYM BIO_get_ex_data}
  {$EXTERNALSYM BIO_number_read}
  {$EXTERNALSYM BIO_number_written}
  {$EXTERNALSYM BIO_s_file}
  {$EXTERNALSYM BIO_new_file}
  {$EXTERNALSYM BIO_new}
  {$EXTERNALSYM BIO_free}
  {$EXTERNALSYM BIO_set_data} {introduced 1.1.0}
  {$EXTERNALSYM BIO_get_data} {introduced 1.1.0}
  {$EXTERNALSYM BIO_set_init} {introduced 1.1.0}
  {$EXTERNALSYM BIO_get_init} {introduced 1.1.0}
  {$EXTERNALSYM BIO_set_shutdown} {introduced 1.1.0}
  {$EXTERNALSYM BIO_get_shutdown} {introduced 1.1.0}
  {$EXTERNALSYM BIO_vfree}
  {$EXTERNALSYM BIO_up_ref} {introduced 1.1.0}
  {$EXTERNALSYM BIO_read}
  {$EXTERNALSYM BIO_read_ex} {introduced 1.1.0}
  {$EXTERNALSYM BIO_gets}
  {$EXTERNALSYM BIO_write}
  {$EXTERNALSYM BIO_write_ex} {introduced 1.1.0}
  {$EXTERNALSYM BIO_puts}
  {$EXTERNALSYM BIO_indent}
  {$EXTERNALSYM BIO_ctrl}
  {$EXTERNALSYM BIO_callback_ctrl}
  {$EXTERNALSYM BIO_ptr_ctrl}
  {$EXTERNALSYM BIO_int_ctrl}
  {$EXTERNALSYM BIO_push}
  {$EXTERNALSYM BIO_pop}
  {$EXTERNALSYM BIO_free_all}
  {$EXTERNALSYM BIO_find_type}
  {$EXTERNALSYM BIO_next}
  {$EXTERNALSYM BIO_set_next} {introduced 1.1.0}
  {$EXTERNALSYM BIO_get_retry_BIO}
  {$EXTERNALSYM BIO_get_retry_reason}
  {$EXTERNALSYM BIO_set_retry_reason} {introduced 1.1.0}
  {$EXTERNALSYM BIO_dup_chain}
  {$EXTERNALSYM BIO_nread0}
  {$EXTERNALSYM BIO_nread}
  {$EXTERNALSYM BIO_nwrite0}
  {$EXTERNALSYM BIO_nwrite}
  {$EXTERNALSYM BIO_debug_callback}
  {$EXTERNALSYM BIO_s_mem}
  {$EXTERNALSYM BIO_s_secmem} {introduced 1.1.0}
  {$EXTERNALSYM BIO_new_mem_buf}
  {$EXTERNALSYM BIO_s_socket}
  {$EXTERNALSYM BIO_s_connect}
  {$EXTERNALSYM BIO_s_accept}
  {$EXTERNALSYM BIO_s_fd}
  {$EXTERNALSYM BIO_s_log}
  {$EXTERNALSYM BIO_s_bio}
  {$EXTERNALSYM BIO_s_null}
  {$EXTERNALSYM BIO_f_null}
  {$EXTERNALSYM BIO_f_buffer}
  {$EXTERNALSYM BIO_f_linebuffer} {introduced 1.1.0}
  {$EXTERNALSYM BIO_f_nbio_test}
  {$EXTERNALSYM BIO_s_datagram}
  {$EXTERNALSYM BIO_dgram_non_fatal_error}
  {$EXTERNALSYM BIO_new_dgram}
  {$EXTERNALSYM BIO_sock_should_retry}
  {$EXTERNALSYM BIO_sock_non_fatal_error}
  {$EXTERNALSYM BIO_fd_should_retry}
  {$EXTERNALSYM BIO_fd_non_fatal_error}
  {$EXTERNALSYM BIO_dump}
  {$EXTERNALSYM BIO_dump_indent}
  {$EXTERNALSYM BIO_hex_string}
  {$EXTERNALSYM BIO_ADDR_new} {introduced 1.1.0}
  {$EXTERNALSYM BIO_ADDR_rawmake} {introduced 1.1.0}
  {$EXTERNALSYM BIO_ADDR_free} {introduced 1.1.0}
  {$EXTERNALSYM BIO_ADDR_clear} {introduced 1.1.0}
  {$EXTERNALSYM BIO_ADDR_family} {introduced 1.1.0}
  {$EXTERNALSYM BIO_ADDR_rawaddress} {introduced 1.1.0}
  {$EXTERNALSYM BIO_ADDR_rawport} {introduced 1.1.0}
  {$EXTERNALSYM BIO_ADDR_hostname_string} {introduced 1.1.0}
  {$EXTERNALSYM BIO_ADDR_service_string} {introduced 1.1.0}
  {$EXTERNALSYM BIO_ADDR_path_string} {introduced 1.1.0}
  {$EXTERNALSYM BIO_ADDRINFO_next} {introduced 1.1.0}
  {$EXTERNALSYM BIO_ADDRINFO_family} {introduced 1.1.0}
  {$EXTERNALSYM BIO_ADDRINFO_socktype} {introduced 1.1.0}
  {$EXTERNALSYM BIO_ADDRINFO_protocol} {introduced 1.1.0}
  {$EXTERNALSYM BIO_ADDRINFO_address} {introduced 1.1.0}
  {$EXTERNALSYM BIO_ADDRINFO_free} {introduced 1.1.0}
  {$EXTERNALSYM BIO_parse_hostserv} {introduced 1.1.0}
  {$EXTERNALSYM BIO_lookup} {introduced 1.1.0}
  {$EXTERNALSYM BIO_lookup_ex} {introduced 1.1.0}
  {$EXTERNALSYM BIO_sock_error}
  {$EXTERNALSYM BIO_socket_ioctl}
  {$EXTERNALSYM BIO_socket_nbio}
  {$EXTERNALSYM BIO_sock_init}
  {$EXTERNALSYM BIO_set_tcp_ndelay}
  {$EXTERNALSYM BIO_sock_info} {introduced 1.1.0}
  {$EXTERNALSYM BIO_socket} {introduced 1.1.0}
  {$EXTERNALSYM BIO_connect} {introduced 1.1.0}
  {$EXTERNALSYM BIO_bind} {introduced 1.1.0}
  {$EXTERNALSYM BIO_listen} {introduced 1.1.0}
  {$EXTERNALSYM BIO_accept_ex} {introduced 1.1.0}
  {$EXTERNALSYM BIO_closesocket} {introduced 1.1.0}
  {$EXTERNALSYM BIO_new_socket}
  {$EXTERNALSYM BIO_new_connect}
  {$EXTERNALSYM BIO_new_accept}
  {$EXTERNALSYM BIO_new_fd}
  {$EXTERNALSYM BIO_new_bio_pair}
  {$EXTERNALSYM BIO_copy_next_retry}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM BIO_get_flags} {removed 1.0.0}
  {$EXTERNALSYM BIO_set_retry_special} {removed 1.0.0}
  {$EXTERNALSYM BIO_set_retry_read} {removed 1.0.0}
  {$EXTERNALSYM BIO_set_retry_write} {removed 1.0.0}
  {$EXTERNALSYM BIO_clear_retry_flags} {removed 1.0.0}
  {$EXTERNALSYM BIO_get_retry_flags} {removed 1.0.0}
  {$EXTERNALSYM BIO_should_read} {removed 1.0.0}
  {$EXTERNALSYM BIO_should_write} {removed 1.0.0}
  {$EXTERNALSYM BIO_should_io_special} {removed 1.0.0}
  {$EXTERNALSYM BIO_retry_type} {removed 1.0.0}
  {$EXTERNALSYM BIO_should_retry} {removed 1.0.0}
  {$EXTERNALSYM BIO_do_connect} {removed 1.0.0}
  {$EXTERNALSYM BIO_do_accept} {removed 1.0.0}
  {$EXTERNALSYM BIO_do_handshake} {removed 1.0.0}
  {$EXTERNALSYM BIO_get_mem_data} {removed 1.0.0}
  {$EXTERNALSYM BIO_set_mem_buf} {removed 1.0.0}
  {$EXTERNALSYM BIO_get_mem_ptr} {removed 1.0.0}
  {$EXTERNALSYM BIO_set_mem_eof_return} {removed 1.0.0}
  BIO_get_flags: function (const b: PBIO): TIdC_INT; cdecl = nil; {removed 1.0.0}
  BIO_set_retry_special: procedure (b: PBIO); cdecl = nil; {removed 1.0.0}
  BIO_set_retry_read: procedure (b: PBIO); cdecl = nil; {removed 1.0.0}
  BIO_set_retry_write: procedure (b: PBIO); cdecl = nil; {removed 1.0.0}

(* These are normally used internally in BIOs *)
  BIO_clear_retry_flags: procedure (b: PBIO); cdecl = nil; {removed 1.0.0}
  BIO_get_retry_flags: function (b: PBIO): TIdC_INT; cdecl = nil; {removed 1.0.0}

(* These should be used by the application to tell why we should retry *)
  BIO_should_read: function (b: PBIO): TIdC_INT; cdecl = nil; {removed 1.0.0}
  BIO_should_write: function (b: PBIO): TIdC_INT; cdecl = nil; {removed 1.0.0}
  BIO_should_io_special: function (b: PBIO): TIdC_INT; cdecl = nil; {removed 1.0.0}
  BIO_retry_type: function (b: PBIO): TIdC_INT; cdecl = nil; {removed 1.0.0}
  BIO_should_retry: function (b: PBIO): TIdC_INT; cdecl = nil; {removed 1.0.0}

(* BIO_s_accept() and BIO_s_connect() *)
  BIO_do_connect: function (b: PBIO): TIdC_LONG; cdecl = nil; {removed 1.0.0}
  BIO_do_accept: function (b: PBIO): TIdC_LONG; cdecl = nil; {removed 1.0.0}
  BIO_do_handshake: function (b: PBIO): TIdC_LONG; cdecl = nil; {removed 1.0.0}

  // WAS DECLARED AS:
  // original declaration of parameter pp was invalid.
  // correct declaration should be "pp: Pointer" according to OpenSSL documentation}
  // BIO_get_mem_data: function (b: PBIO; pp: Pointer) : TIdC_INT; cdecl = nil; {removed 1.0.0}
  BIO_get_mem_data: function (b: PBIO; out pp: Pointer) : TIdC_INT; cdecl = nil; {removed 1.0.0}
  BIO_set_mem_buf: function (b: PBIO; bm: PBUF_MEM; c: TIdC_INT): TIdC_INT; cdecl = nil; {removed 1.0.0}
  // WAS DECLARED AS:
  // original declaration of parameter pp was invalid.
  // correct declaration should be "pp: Pointer" according to OpenSSL documentation}
  // BIO_get_mem_data: function (b: PBIO; pp: Pointer) : TIdC_INT; cdecl = nil; {removed 1.0.0}
  BIO_get_mem_ptr: function (b: PBIO; out pp: PBUF_MEM): TIdC_INT; cdecl = nil; {removed 1.0.0}
  BIO_set_mem_eof_return: function (b: PBIO; v: TIdC_INT): TIdC_INT; cdecl = nil; {removed 1.0.0}

  BIO_get_new_index: function : TIdC_INT; cdecl = nil; {introduced 1.1.0}
  BIO_set_flags: procedure (b: PBIO; flags: TIdC_INT); cdecl = nil;
  BIO_test_flags: function (const b: PBIO; flags: TIdC_INT): TIdC_INT; cdecl = nil;
  BIO_clear_flags: procedure (b: PBIO; flags: TIdC_INT); cdecl = nil;

  BIO_get_callback: function (b: PBIO): BIO_callback_fn; cdecl = nil;
  BIO_set_callback: procedure (b: PBIO; callback: BIO_callback_fn); cdecl = nil;

  BIO_get_callback_ex: function (b: PBIO): BIO_callback_fn_ex; cdecl = nil; {introduced 1.1.0}
  BIO_set_callback_ex: procedure (b: PBIO; callback: BIO_callback_fn_ex); cdecl = nil; {introduced 1.1.0}

  BIO_get_callback_arg: function (const b: PBIO): PIdAnsiChar; cdecl = nil;
  BIO_set_callback_arg: procedure (var b: PBIO; arg: PIdAnsiChar); cdecl = nil;

  BIO_method_name: function (const b: PBIO): PIdAnsiChar; cdecl = nil;
  BIO_method_type: function (const b: PBIO): TIdC_INT; cdecl = nil;

//  {$HPPEMIT '# define BIO_set_app_data(s,arg)         BIO_set_ex_data(s,0,arg)'}
//  {$HPPEMIT '# define BIO_get_app_data(s)             BIO_get_ex_data(s,0)'}
//
//  {$HPPEMIT '# define BIO_set_nbio(b,n)             BIO_ctrl(b,BIO_C_SET_NBIO,(n),NULL)'}
//
//  {$HPPEMIT '# ifndef OPENSSL_NO_SOCK'}
//  (* IP families we support, for BIO_s_connect() and BIO_s_accept() *)
//  (* Note: the underlying operating system may not support some of them *)
//  {$HPPEMIT '#  define BIO_FAMILY_IPV4                         4'}
//  {$HPPEMIT '#  define BIO_FAMILY_IPV6                         6'}
//  {$HPPEMIT '#  define BIO_FAMILY_IPANY                        256'}
//
//  (* BIO_s_connect() *)
//  {$HPPEMIT '#  define BIO_set_conn_hostname(b,name) BIO_ctrl(b,BIO_C_SET_CONNECT,0,'}
//                                                   (char (name))
//  {$HPPEMIT '#  define BIO_set_conn_port(b,port)     BIO_ctrl(b,BIO_C_SET_CONNECT,1,'}
//                                                   (char (port))
//  {$HPPEMIT '#  define BIO_set_conn_address(b,addr)  BIO_ctrl(b,BIO_C_SET_CONNECT,2,'}
//                                                   (char (addr))
//  {$HPPEMIT '#  define BIO_set_conn_ip_family(b,f)   BIO_int_ctrl(b,BIO_C_SET_CONNECT,3,f)'}
//  {$HPPEMIT '#  define BIO_get_conn_hostname(b)      (( char )BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,0))'}
//  {$HPPEMIT '#  define BIO_get_conn_port(b)          (( char )BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,1))'}
//  {$HPPEMIT '#  define BIO_get_conn_address(b)       (( PBIO_ADDR )BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,2))'}
//  {$HPPEMIT '#  define BIO_get_conn_ip_family(b)     BIO_ctrl(b,BIO_C_GET_CONNECT,3,NULL)'}
//  {$HPPEMIT '#  define BIO_set_conn_mode(b,n)        BIO_ctrl(b,BIO_C_SET_CONNECT_MODE,(n),NULL)'}
//
//  (* BIO_s_accept() *)
//  {$HPPEMIT '#  define BIO_set_accept_name(b,name)   BIO_ctrl(b,BIO_C_SET_ACCEPT,0,'}
//  {$EXTERNALSYM PBIO}
//                                                   (char (name))
//  {$HPPEMIT '#  define BIO_set_accept_port(b,port)   BIO_ctrl(b,BIO_C_SET_ACCEPT,1,'}
//                                                   (char (port))
//  {$HPPEMIT '#  define BIO_get_accept_name(b)        (( char )BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,0))'}
//  {$HPPEMIT '#  define BIO_get_accept_port(b)        (( char )BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,1))'}
//  {$HPPEMIT '#  define BIO_get_peer_name(b)          (( char )BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,2))'}
//  {$HPPEMIT '#  define BIO_get_peer_port(b)          (( char )BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,3))'}
//  (* #define BIO_set_nbio(b,n)    BIO_ctrl(b,BIO_C_SET_NBIO,(n),NULL) *)
//  {$HPPEMIT '#  define BIO_set_nbio_accept(b,n)      #  define BIO_set_nbio_accept(b,n)      BIO_ctrl(b,BIO_C_SET_ACCEPT,2,(n)?(procedure )'a':NULL)  BIO_ctrl(b,BIO_C_SET_ACCEPT,3,'}
//                                                   (char (bio))
//  {$HPPEMIT '#  define BIO_set_accept_ip_family(b,f) BIO_int_ctrl(b,BIO_C_SET_ACCEPT,4,f)'}
//  {$HPPEMIT '#  define BIO_get_accept_ip_family(b)   BIO_ctrl(b,BIO_C_GET_ACCEPT,4,NULL)'}
//
//  (* Aliases kept for backward compatibility *)
//  {$HPPEMIT '#  define BIO_BIND_NORMAL                 0'}
//  {$HPPEMIT '#  define BIO_BIND_REUSEADDR              BIO_SOCK_REUSEADDR'}
//  {$HPPEMIT '#  define BIO_BIND_REUSEADDR_IF_UNUSED    BIO_SOCK_REUSEADDR'}
//  {$HPPEMIT '#  define BIO_set_bind_mode(b,mode) BIO_ctrl(b,BIO_C_SET_BIND_MODE,mode,NULL)'}
//  {$HPPEMIT '#  define BIO_get_bind_mode(b)    BIO_ctrl(b,BIO_C_GET_BIND_MODE,0,NULL)'}
//
//  (* BIO_s_accept() and BIO_s_connect() *)
//  {$HPPEMIT '#  define BIO_do_connect(b)       BIO_do_handshake(b)'}
//  {$HPPEMIT '#  define BIO_do_accept(b)        BIO_do_handshake(b)'}
//  {$HPPEMIT '# endif'}	(* OPENSSL_NO_SOCK *)
//
//  {$HPPEMIT '# define BIO_do_handshake(b)     BIO_ctrl(b,BIO_C_DO_STATE_MACHINE,0,NULL)'}
//
//  (* BIO_s_datagram(), BIO_s_fd(), BIO_s_socket(), BIO_s_accept() and BIO_s_connect() *)
//  {$HPPEMIT '# define BIO_set_fd(b,fd,c)      BIO_int_ctrl(b,BIO_C_SET_FD,c,fd)'}
//  {$HPPEMIT '# define BIO_get_fd(b,c)         BIO_ctrl(b,BIO_C_GET_FD,0,(char (c))'}
//
//  (* BIO_s_file() *)
//  {$HPPEMIT '# define BIO_set_fp(b,fp,c)      BIO_ctrl(b,BIO_C_SET_FILE_PTR,c,(char (fp))'}
//  {$HPPEMIT '# define BIO_get_fp(b,fpp)       BIO_ctrl(b,BIO_C_GET_FILE_PTR,0,(char (fpp))'}
//
//  (* BIO_s_fd() and BIO_s_file() *)
//  {$HPPEMIT '# define BIO_seek(b,ofs(int)BIO_ctrl(b,BIO_C_FILE_SEEK,ofs,NULL)'}
//  {$HPPEMIT '# define BIO_tell(b)     (int)BIO_ctrl(b,BIO_C_FILE_TELL,0,NULL)'}
//
//  (*
//   * name is cast to lose , but might be better to route through a
//   * cFunction so we can do it safely
//   *)
//  {$HPPEMIT '# ifdef CONST_STRICT'}
//  (*
//   * If you are wondering why this isn't defined, its because CONST_STRICT is
//   * purely a compile-time kludge to allow  to be checked.
//   *)
////  function BIO_read_filename(b: PBIO; const name: PIdAnsiChar): TIdC_INT;
//  {$HPPEMIT '# define BIO_write_filename(b,name(int)BIO_ctrl(b,BIO_C_SET_FILENAME,'}
//                  BIO_CLOSE or BIO_FP_WRITE,name)
//  {$HPPEMIT '# define BIO_append_filename(b,name(int)BIO_ctrl(b,BIO_C_SET_FILENAME,'}
//                  BIO_CLOSE or BIO_FP_APPEND,name)
//  {$HPPEMIT '# define BIO_rw_filename(b,name(int)BIO_ctrl(b,BIO_C_SET_FILENAME,'}
//                  BIO_CLOSE or BIO_FP_READ or BIO_FP_WRITE,name)
//
//  (*
//   * WARNING WARNING, this ups the reference count on the read bio of the SSL
//   * structure.  This is because the ssl read PBIO is now pointed to by the
//   * next_bio field in the bio.  So when you free the PBIO, make sure you are
//   * doing a BIO_free_all() to catch the underlying PBIO.
//   *)
//  {$HPPEMIT '# define BIO_set_ssl(b,ssl,c)    BIO_ctrl(b,BIO_C_SET_SSL,c,(char (ssl))'}
//  {$HPPEMIT '# define BIO_get_ssl(b,sslp)     BIO_ctrl(b,BIO_C_GET_SSL,0,(char (sslp))'}
//  {$HPPEMIT '# define BIO_set_ssl_mode(b,client)      BIO_ctrl(b,BIO_C_SSL_MODE,client,NULL)'}
//  {$HPPEMIT '# define BIO_set_ssl_renegotiate_bytes(b,num)'}
//          BIO_ctrl(b,BIO_C_SET_SSL_RENEGOTIATE_BYTES,num,0)
//  {$HPPEMIT '# define BIO_get_num_renegotiates(b)'}
//          BIO_ctrl(b,BIO_C_GET_SSL_NUM_RENEGOTIATES,0,0)
//  {$HPPEMIT '# define BIO_set_ssl_renegotiate_timeout(b,seconds)'}
//          BIO_ctrl(b,BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT,seconds,0)
//
//  (* defined in evp.h *)
//  (* #define BIO_set_md(b,md)     BIO_ctrl(b,BIO_C_SET_MD,1,(char )(md)) *)
//
//  (* For the BIO_f_buffer() type *)
//  {$HPPEMIT '# define BIO_get_buffer_num_lines(b)     BIO_ctrl(b,BIO_C_GET_BUFF_NUM_LINES,0,NULL)'}
//  {$HPPEMIT '# define BIO_set_buffer_size(b,size)     BIO_ctrl(b,BIO_C_SET_BUFF_SIZE,size,NULL)'}
//  {$HPPEMIT '# define BIO_set_read_buffer_size(b,size) BIO_int_ctrl(b,BIO_C_SET_BUFF_SIZE,size,0)'}
//  {$HPPEMIT '# define BIO_set_write_buffer_size(b,size) BIO_int_ctrl(b,BIO_C_SET_BUFF_SIZE,size,1)'}
//  {$HPPEMIT '# define BIO_set_buffer_read_data(b,buf,num) BIO_ctrl(b,BIO_C_SET_BUFF_READ_DATA,num,buf)'}
//
//  (* Don't use the next one unless you know what you are doing :-) */
//  {$HPPEMIT '# define BIO_dup_state(b,ret)    BIO_ctrl(b,BIO_CTRL_DUP,0,(char (ret))'}
//
//  {$HPPEMIT '# define BIO_reset(b)            (int)BIO_ctrl(b,BIO_CTRL_RESET,0,NULL)'}
//  {$HPPEMIT '# define BIO_eof(b)              (int)BIO_ctrl(b,BIO_CTRL_EOF,0,NULL)'}
//  {$HPPEMIT '# define BIO_set_close(b,c)      (int)BIO_ctrl(b,BIO_CTRL_SET_CLOSE,(c),NULL)'}
//  {$HPPEMIT '# define BIO_get_close(b)        (int)BIO_ctrl(b,BIO_CTRL_GET_CLOSE,0,NULL)'}
//  {$HPPEMIT '# define BIO_pending(b)          (int)BIO_ctrl(b,BIO_CTRL_PENDING,0,NULL)'}
//  {$HPPEMIT '# define BIO_wpending(b)         (int)BIO_ctrl(b,BIO_CTRL_WPENDING,0,NULL)'}
  (* ...pending macros have inappropriate return type *)
  BIO_ctrl_pending: function (b: PBIO): TIdC_SIZET; cdecl = nil;
  BIO_ctrl_wpending: function (b: PBIO): TIdC_SIZET; cdecl = nil;
//  {$HPPEMIT '# define BIO_flush(b)            (int)BIO_ctrl(b,BIO_CTRL_FLUSH,0,NULL)'}
//  {$HPPEMIT '# define BIO_get_info_callback(b,cbp(int)BIO_ctrl(b,BIO_CTRL_GET_CALLBACK,0,'}
//                                                     cbp)
//  {$HPPEMIT '# define BIO_set_info_callback(b,cb(int)BIO_callback_ctrl(b,BIO_CTRL_SET_CALLBACK,cb)'}
//
//  (* For the BIO_f_buffer() type *)
//  {$HPPEMIT '# define BIO_buffer_get_num_lines(b) BIO_ctrl(b,BIO_CTRL_GET,0,NULL)'}
//  {$HPPEMIT '# define BIO_buffer_peek(b,s,l) BIO_ctrl(b,BIO_CTRL_PEEK,(l),(s))'}
//
//  (* For BIO_s_bio() *)
//  {$HPPEMIT '# define BIO_set_write_buf_size(b,size(int)BIO_ctrl(b,BIO_C_SET_WRITE_BUF_SIZE,size,NULL)'}
//  {$HPPEMIT '# define BIO_get_write_buf_size(b,size(TIdC_SIZET)BIO_ctrl(b,BIO_C_GET_WRITE_BUF_SIZE,size,NULL)'}
//  {$HPPEMIT '# define BIO_make_bio_pair(b1,b2)   (int)BIO_ctrl(b1,BIO_C_MAKE_BIO_PAIR,0,b2)'}
//  {$HPPEMIT '# define BIO_destroy_bio_pair(b)    (int)BIO_ctrl(b,BIO_C_DESTROY_BIO_PAIR,0,NULL)'}
//  {$HPPEMIT '# define BIO_shutdown_wr(b(int)BIO_ctrl(b, BIO_C_SHUTDOWN_WR, 0, NULL)'}
//  (* macros with inappropriate type -- but ...pending macros use int too: *)
//  {$HPPEMIT '# define BIO_get_write_guarantee(b(int)BIO_ctrl(b,BIO_C_GET_WRITE_GUARANTEE,0,NULL)'}
//  {$HPPEMIT '# define BIO_get_read_request(b)    (int)BIO_ctrl(b,BIO_C_GET_READ_REQUEST,0,NULL)'}
  BIO_ctrl_get_write_guarantee: function (b: PBIO): TIdC_SIZET; cdecl = nil;
  BIO_ctrl_get_read_request: function (b: PBIO): TIdC_SIZET; cdecl = nil;
  BIO_ctrl_reset_read_request: function (b: PBIO): TIdC_INT; cdecl = nil;

  (* ctrl macros for dgram *)
//  {$HPPEMIT '# define BIO_ctrl_dgram_connect(b,peer)'}
//                       (TIdC_INT)BIO_ctrl(b,BIO_CTRL_DGRAM_CONNECT,0, (char (peer))
//  {$HPPEMIT '# define BIO_ctrl_set_connected(b,peer)'}
//           (TIdC_INT)BIO_ctrl(b, BIO_CTRL_DGRAM_SET_CONNECTED, 0, (char (peer))
//  {$HPPEMIT '# define BIO_dgram_recv_timedout(b)'}
//           (TIdC_INT)BIO_ctrl(b, BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, 0)
//  {$HPPEMIT '# define BIO_dgram_send_timedout(b)'}
//           (TIdC_INT)BIO_ctrl(b, BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP, 0, 0)
//  {$HPPEMIT '# define BIO_dgram_get_peer(b,peer)'}
//           (TIdC_INT)BIO_ctrl(b, BIO_CTRL_DGRAM_GET_PEER, 0, (char (peer))
//  {$HPPEMIT '# define BIO_dgram_set_peer(b,peer)'}
//           (TIdC_INT)BIO_ctrl(b, BIO_CTRL_DGRAM_SET_PEER, 0, (char (peer))
//  {$HPPEMIT '# define BIO_dgram_get_mtu_overhead(b)'}
//           (Cardinal)BIO_ctrl((b), BIO_CTRL_DGRAM_GET_MTU_OVERHEAD, 0, 0)

//#define BIO_get_ex_new_index(l, p, newf, dupf, freef) \
//    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_BIO, l, p, newf, dupf, freef)

  BIO_set_ex_data: function (bio: PBIO; idx: TIdC_INT; data: Pointer): TIdC_INT; cdecl = nil;
  BIO_get_ex_data: function (bio: PBIO; idx: TIdC_INT): Pointer; cdecl = nil;
  BIO_number_read: function (bio: PBIO): TIdC_UINT64; cdecl = nil;
  BIO_number_written: function (bio: PBIO): TIdC_UINT64; cdecl = nil;

  (* For BIO_f_asn1() *)
//  function BIO_asn1_set_prefix(b: PBIO; prefix: ^asn1_ps_func; prefix_free: ^asn1_ps_func): TIdC_INT;
//  function BIO_asn1_get_prefix(b: PBIO; pprefix: ^^asn1_ps_func; pprefix_free: ^^asn1_ps_func): TIdC_INT;
//  function BIO_asn1_set_suffix(b: PBIO; suffix: ^asn1_ps_func; suffix_free: ^asn1_ps_func): TIdC_INT;
//  function BIO_asn1_get_suffix(b: PBIO; psuffix: ^asn1_ps_func; psuffix_free: ^^asn1_ps_func): TIdC_INT;

  BIO_s_file: function : PBIO_METHOD; cdecl = nil;
  BIO_new_file: function (const filename: PIdAnsiChar; const mode: PIdAnsiChar): PBIO; cdecl = nil;
//  function BIO_new_fp(stream: cFile; close_flag: TIdC_INT): PBIO;
  BIO_new: function (const cType: PBIO_METHOD): PBIO; cdecl = nil;
  BIO_free: function (a: PBIO): TIdC_INT; cdecl = nil;
  BIO_set_data: procedure (a: PBIO; _ptr: Pointer); cdecl = nil; {introduced 1.1.0}
  BIO_get_data: function (a: PBIO): Pointer; cdecl = nil; {introduced 1.1.0}
  BIO_set_init: procedure (a: PBIO; init: TIdC_INT); cdecl = nil; {introduced 1.1.0}
  BIO_get_init: function (a: PBIO): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  BIO_set_shutdown: procedure (a: PBIO; shut: TIdC_INT); cdecl = nil; {introduced 1.1.0}
  BIO_get_shutdown: function (a: PBIO): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  BIO_vfree: procedure (a: PBIO); cdecl = nil;
  BIO_up_ref: function (a: PBIO): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  // WAS DECLARED AS:
  // BIO_read: function (b: PBIO; data: Pointer; dlen: TIdC_INT): TIdC_INT; cdecl = nil;
  BIO_read: function (b: PBIO; var data; dlen: TIdC_INT): TIdC_INT; cdecl = nil;
  // WAS DECLARED AS:
  // BIO_read_ex: function (b: PBIO; data: Pointer; dlen: TIdC_SIZET; readbytes: PIdC_SIZET): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  BIO_read_ex: function (b: PBIO; var data; dlen: TIdC_SIZET; out readbytes: TIdC_SIZET): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  BIO_recvmmsg: function (b : PBIO; msg : PBIO_MSG;
    stride, num_msg : TIdC_SIZET; flags : TIdC_UINT64;
    msgs_processed : PIdC_SIZET): TIdC_INT; cdecl = nil;
  BIO_gets: function ( bp: PBIO; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT; cdecl = nil;
  // WAS DECLARED AS:
  // BIO_write: function (b: PBIO; const data: Pointer; dlen: TIdC_INT): TIdC_INT; cdecl = nil;
  BIO_write: function (b: PBIO; const data; dlen: TIdC_INT): TIdC_INT; cdecl = nil;
  // WAS DECLARED AS:
  // BIO_write_ex: function (b: PBIO; const data: Pointer; dlen: TIdC_SIZET; written: PIdC_SIZET): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  BIO_write_ex: function (b: PBIO; const data; dlen: TIdC_SIZET; out written: TIdC_SIZET): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  BIO_sendmmsg : function (b0 : PBIO; msg : PBIO_MSG;
    stride, num_msg : TIdC_SIZET; flags : TIdC_UINT64;
    msgs_processed : PIdC_SIZET) : TIdC_INT; cdecl = nil;
  BIO_get_rpoll_descriptor : function(b : PBIO; desc : PBIO_POLL_DESCRIPTOR)  : TIdC_INT; cdecl = nil;
  BIO_get_wpoll_descriptor : function(b : PBIO; desc : PBIO_POLL_DESCRIPTOR) : TIdC_INT; cdecl = nil;

  BIO_puts: function (bp: PBIO; const buf: PIdAnsiChar): TIdC_INT; cdecl = nil;
  BIO_indent: function (b: PBIO; indent: TIdC_INT; max: TIdC_INT): TIdC_INT; cdecl = nil;
  BIO_ctrl: function (bp: PBIO; cmd: TIdC_INT; larg: TIdC_LONG; parg: Pointer): TIdC_LONG; cdecl = nil;
  BIO_callback_ctrl: function (b: PBIO; cmd: TIdC_INT; fp: PBIO_info_cb): TIdC_LONG; cdecl = nil;
  BIO_ptr_ctrl: function (bp: PBIO; cmd: TIdC_INT; larg: TIdC_LONG): Pointer; cdecl = nil;
  BIO_int_ctrl: function (bp: PBIO; cmd: TIdC_INT; larg: TIdC_LONG; iarg: TIdC_INT): TIdC_LONG; cdecl = nil;
  BIO_push: function (b: PBIO; _append: PBIO): PBIO; cdecl = nil;
  BIO_pop: function (b: PBIO): PBIO; cdecl = nil;
  BIO_free_all: procedure (a: PBIO); cdecl = nil;
  BIO_find_type: function (b: PBIO; bio_type: TIdC_INT): PBIO; cdecl = nil;
  BIO_next: function (b: PBIO): PBIO; cdecl = nil;
  BIO_set_next: procedure (b: PBIO; next: PBIO); cdecl = nil; {introduced 1.1.0}
  BIO_get_retry_BIO: function (bio: PBIO; reason: TIdC_INT): PBIO; cdecl = nil;
  BIO_get_retry_reason: function (bio: PBIO): TIdC_INT; cdecl = nil;
  BIO_set_retry_reason: procedure (bio: PBIO; reason: TIdC_INT); cdecl = nil; {introduced 1.1.0}
  BIO_dup_chain: function (in_: PBIO): PBIO; cdecl = nil;

  BIO_nread0: function (bio: PBIO; buf: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  BIO_nread: function (bio: PBIO; buf: PPIdAnsiChar; num: TIdC_INT): TIdC_INT; cdecl = nil;
  BIO_nwrite0: function (bio: PBIO; buf: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  BIO_nwrite: function (bio: PBIO; buf: PPIdAnsiChar; num: TIdC_INT): TIdC_INT; cdecl = nil;

  BIO_debug_callback: function (bio: PBIO; cmd: TIdC_INT; const argp: PIdAnsiChar; argi: TIdC_INT; argl: TIdC_LONG; ret: TIdC_LONG): TIdC_LONG; cdecl = nil;

  BIO_s_mem: function : PBIO_METHOD; cdecl = nil;
  BIO_s_secmem: function : PBIO_METHOD; cdecl = nil; {introduced 1.1.0}
  // WAS DECLARED AS:
  // BIO_new_mem_buf: function (const buf: Pointer; len: TIdC_INT): PBIO; cdecl = nil;
  BIO_new_mem_buf: function (const buf; len: TIdC_INT): PBIO; cdecl = nil;

  BIO_s_socket: function : PBIO_METHOD; cdecl = nil;
  BIO_s_connect: function : PBIO_METHOD; cdecl = nil;
  BIO_s_accept: function : PBIO_METHOD; cdecl = nil;

  BIO_s_fd: function : PBIO_METHOD; cdecl = nil;
  BIO_s_log: function : PBIO_METHOD; cdecl = nil;
  BIO_s_bio: function : PBIO_METHOD; cdecl = nil;
  BIO_s_null: function : PBIO_METHOD; cdecl = nil;
  BIO_f_null: function : PBIO_METHOD; cdecl = nil;
  BIO_f_buffer: function : PBIO_METHOD; cdecl = nil;
  BIO_f_linebuffer: function : PBIO_METHOD; cdecl = nil; {introduced 1.1.0}
  BIO_f_nbio_test: function : PBIO_METHOD; cdecl = nil;
  BIO_s_datagram: function : PBIO_METHOD; cdecl = nil;
  BIO_dgram_non_fatal_error: function (_error: TIdC_INT): TIdC_INT; cdecl = nil;
  BIO_new_dgram: function (fd: TIdC_INT; close_flag: TIdC_INT): PBIO; cdecl = nil;

//  function BIO_s_datagram_sctp: PBIO_METHOD;
//  function BIO_new_dgram_sctp(fd: TIdC_INT; close_flag: TIdC_INT): PBIO;
//  function BIO_dgram_is_sctp(bio: PBIO): TIdC_INT;
//  function BIO_dgram_sctp_notification_cb(bio: PBIO; handle_notifications(PBIO;
//    context: Pointer;
//    buf: Pointer): TIdC_INT, Pointer context);
//  function BIO_dgram_sctp_wait_for_dry(b: PBIO): TIdC_INT;
//  function BIO_dgram_sctp_msg_waiting(b: PBIO): TIdC_INT;

  BIO_sock_should_retry: function (i: TIdC_INT): TIdC_INT; cdecl = nil;
  BIO_sock_non_fatal_error: function (_error: TIdC_INT): TIdC_INT; cdecl = nil;
  BIO_err_is_non_fatal : function(errcode : TIdC_UINT) : TIdC_INT; cdecl = nil;
  BIO_fd_should_retry: function (i: TIdC_INT): TIdC_INT; cdecl = nil;
  BIO_fd_non_fatal_error: function (_error: TIdC_INT): TIdC_INT; cdecl = nil;
//  function BIO_dump_cb(
//    Pointer data: cb(;
//    len: TIdC_SIZET;
//    function: Pointer): u: TIdC_INT, Pointer function ,  PIdAnsiChar s, TIdC_INT len): u;
//  function BIO_dump_indent_cb(TIdC_INT (cb( Pointer data, TIdC_SIZET len, Pointer function ): u: TIdC_INT, Pointer function ,  PIdAnsiChar s, TIdC_INT len, TIdC_INT indent): u;
  BIO_dump: function (b: PBIO; const bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  BIO_dump_indent: function (b: PBIO; const bytes: PIdAnsiChar; len: TIdC_INT; indent: TIdC_INT): TIdC_INT; cdecl = nil;

//  function BIO_dump_fp(fp: cFile; const s: PByte; len: TIdC_INT): TIdC_INT;
//  function BIO_dump_indent_fp(fp: cFile; const s: PByte; len: TIdC_INT; indent: TIdC_INT): TIdC_INT;

  BIO_hex_string: function (out_: PBIO; indent: TIdC_INT; width: TIdC_INT; data: PByte; datalen: TIdC_INT): TIdC_INT; cdecl = nil;

  BIO_ADDR_new: function : PBIO_ADDR; cdecl = nil; {introduced 1.1.0}
  BIO_ADDR_rawmake: function (ap: PBIO_ADDR; familiy: TIdC_INT; const where: Pointer; wherelen: TIdC_SIZET; port: TIdC_SHORT): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  BIO_ADDR_free: procedure (a: PBIO_ADDR); cdecl = nil; {introduced 1.1.0}
  BIO_ADDR_clear: procedure (ap: PBIO_ADDR); cdecl = nil; {introduced 1.1.0}
  BIO_ADDR_family: function (const ap: PBIO_ADDR): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  // WAS DECLARED AS:
  // BIO_ADDR_rawaddress: function (const ap: PBIO_ADDR; p: Pointer; l: PIdC_SIZET): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  BIO_ADDR_rawaddress: function (const ap: PBIO_ADDR; p: Pointer; out l: TIdC_SIZET): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  BIO_ADDR_rawport: function (const ap: PBIO_ADDR): TIdC_SHORT; cdecl = nil; {introduced 1.1.0}
  BIO_ADDR_hostname_string: function (const ap: PBIO_ADDR; numeric: TIdC_INT): PIdAnsiChar; cdecl = nil; {introduced 1.1.0}
  BIO_ADDR_service_string: function (const ap: PBIO_ADDR; numeric: TIdC_INT): PIdAnsiChar; cdecl = nil; {introduced 1.1.0}
  BIO_ADDR_path_string: function (const ap: PBIO_ADDR): PIdAnsiChar; cdecl = nil; {introduced 1.1.0}

  BIO_ADDRINFO_next: function (const bai: PBIO_ADDRINFO): PBIO_ADDRINFO; cdecl = nil; {introduced 1.1.0}
  BIO_ADDRINFO_family: function (const bai: PBIO_ADDRINFO): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  BIO_ADDRINFO_socktype: function (const bai: PBIO_ADDRINFO): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  BIO_ADDRINFO_protocol: function (const bai: PBIO_ADDRINFO): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  BIO_ADDRINFO_address: function (const bai: PBIO_ADDRINFO): PBIO_ADDR; cdecl = nil; {introduced 1.1.0}
  BIO_ADDRINFO_free: procedure (bai: PBIO_ADDRINFO); cdecl = nil; {introduced 1.1.0}

  // WAS DECLARED AS:
  // BIO_parse_hostserv: function (const hostserv: PIdAnsiChar; host: PPIdAnsiChar; service: PPIdAnsiChar; hostserv_prio: BIO_hostserv_priorities): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  BIO_parse_hostserv: function (const hostserv: PIdAnsiChar; var host, service: PIdAnsiChar; hostserv_prio: BIO_hostserv_priorities): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  BIO_lookup: function (const host: PIdAnsiChar; const service: PIdAnsiChar; lookup_type: BIO_lookup_type; family: TIdC_INT; socktype: TIdC_INT; res: PPBIO_ADDRINFO): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  BIO_lookup_ex: function (const host: PIdAnsiChar; const service: PIdAnsiChar; lookup_type: TIdC_INT; family: TIdC_INT; socktype: TIdC_INT; protocol: TIdC_INT; res: PPBIO_ADDRINFO): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  BIO_sock_error: function (sock: TIdC_INT): TIdC_INT; cdecl = nil;
  BIO_socket_ioctl: function (fd: TIdC_INT; cType: TIdC_LONG; arg: Pointer): TIdC_INT; cdecl = nil;
  BIO_socket_nbio: function (fd: TIdC_INT; mode: TIdC_INT): TIdC_INT; cdecl = nil;
  BIO_sock_init: function : TIdC_INT; cdecl = nil;

  BIO_set_tcp_ndelay: function (sock: TIdC_INT; turn_on: TIdC_INT): TIdC_INT; cdecl = nil;

  BIO_sock_info: function (sock: TIdC_INT; type_: BIO_sock_info_type; info: PBIO_sock_info_u): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  BIO_socket: function (domain: TIdC_INT; socktype: TIdC_INT; protocol: TIdC_INT; options: TIdC_INT): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  BIO_connect: function (sock: TIdC_INT; const address: PBIO_ADDR; options: TIdC_INT): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  BIO_bind: function (sock: TIdC_INT; const address: PBIO_ADDR; options: TIdC_INT): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  BIO_listen: function (sock: TIdC_INT; const address: PBIO_ADDR; options: TIdC_INT): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  BIO_accept_ex: function (accept_sock: TIdC_INT; address: PBIO_ADDR; options: TIdC_INT): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  BIO_closesocket: function (sock: TIdC_INT): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  BIO_new_socket: function (sock: TIdC_INT; close_flag: TIdC_INT): PBIO; cdecl = nil;
  BIO_new_connect: function (const host_port: PIdAnsiChar): PBIO; cdecl = nil;
  BIO_new_accept: function (const host_port: PIdAnsiChar): PBIO; cdecl = nil;

  BIO_new_fd: function (fd: TIdC_INT; close_flag: TIdC_INT): PBIO; cdecl = nil;

  BIO_new_bio_pair: function (bio1: PPBIO; writebuf1: TIdC_SIZET; bio2: PPBIO; writebuf2: TIdC_SIZET): TIdC_INT; cdecl = nil;
  (*
   * If successful, returns 1 and in *bio1, *bio2 two BIO pair endpoints.
   * Otherwise returns 0 and sets *bio1 and *bio2 to NULL. Size 0 uses default
   * value.
   *)

  BIO_copy_next_retry: procedure (b: PBIO); cdecl = nil;

//  BIO_METHOD *BIO_meth_new(int type, const char *name);
//  void BIO_meth_free(BIO_METHOD *biom);
//  int (*BIO_meth_get_write(const BIO_METHOD *biom)) (BIO *, const char *, int);
//  int (*BIO_meth_get_write_ex(const BIO_METHOD *biom)) (BIO *, const char *, TIdC_SIZET,
//                                                  TIdC_SIZET *);
//  int BIO_meth_set_write(BIO_METHOD *biom,
//                         int (*write) (BIO *, const char *, int));
//  int BIO_meth_set_write_ex(BIO_METHOD *biom,
//                         int (*bwrite) (BIO *, const char *, TIdC_SIZET, TIdC_SIZET *));
//  int (*BIO_meth_get_read(const BIO_METHOD *biom)) (BIO *, char *, int);
//  int (*BIO_meth_get_read_ex(const BIO_METHOD *biom)) (BIO *, char *, TIdC_SIZET, TIdC_SIZET *);
//  int BIO_meth_set_read(BIO_METHOD *biom,
//                        int (*read) (BIO *, char *, int));
//  int BIO_meth_set_read_ex(BIO_METHOD *biom,
//                           int (*bread) (BIO *, char *, TIdC_SIZET, TIdC_SIZET *));
//  int (*BIO_meth_get_puts(const BIO_METHOD *biom)) (BIO *, const char *);
//  int BIO_meth_set_puts(BIO_METHOD *biom,
//                        int (*puts) (BIO *, const char *));
//  int (*BIO_meth_get_gets(const BIO_METHOD *biom)) (BIO *, char *, int);
//  int BIO_meth_set_gets(BIO_METHOD *biom,
//                        int (*gets) (BIO *, char *, int));
//  long (*BIO_meth_get_ctrl(const BIO_METHOD *biom)) (BIO *, int, long, void *);
//  int BIO_meth_set_ctrl(BIO_METHOD *biom,
//                        long (*ctrl) (BIO *, int, long, void *));
//  int (*BIO_meth_get_create(const BIO_METHOD *bion)) (BIO *);
//  int BIO_meth_set_create(BIO_METHOD *biom, int (*create) (BIO *));
//  int (*BIO_meth_get_destroy(const BIO_METHOD *biom)) (BIO *);
//  int BIO_meth_set_destroy(BIO_METHOD *biom, int (*destroy) (BIO *));
//  long (*BIO_meth_get_callback_ctrl(const BIO_METHOD *biom))
//                                   (BIO *, int, BIO_info_cb *);
//  int BIO_meth_set_callback_ctrl(BIO_METHOD *biom,
//                                 long (*callback_ctrl) (BIO *, int,
//                                                        BIO_info_cb *));

{$ELSE}

(* These are normally used internally in BIOs *)

(* These should be used by the application to tell why we should retry *)

(* BIO_s_accept() and BIO_s_connect() *)


  function BIO_get_new_index: TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  procedure BIO_set_flags(b: PBIO; flags: TIdC_INT) cdecl; external CLibCrypto;
  function BIO_test_flags(const b: PBIO; flags: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  procedure BIO_clear_flags(b: PBIO; flags: TIdC_INT) cdecl; external CLibCrypto;

  function BIO_get_callback(b: PBIO): BIO_callback_fn cdecl; external CLibCrypto;
  procedure BIO_set_callback(b: PBIO; callback: BIO_callback_fn) cdecl; external CLibCrypto;

  function BIO_get_callback_ex(b: PBIO): BIO_callback_fn_ex cdecl; external CLibCrypto; {introduced 1.1.0}
  procedure BIO_set_callback_ex(b: PBIO; callback: BIO_callback_fn_ex) cdecl; external CLibCrypto; {introduced 1.1.0}

  function BIO_get_callback_arg(const b: PBIO): PIdAnsiChar cdecl; external CLibCrypto;
  procedure BIO_set_callback_arg(var b: PBIO; arg: PIdAnsiChar) cdecl; external CLibCrypto;

  function BIO_method_name(const b: PBIO): PIdAnsiChar cdecl; external CLibCrypto;
  function BIO_method_type(const b: PBIO): TIdC_INT cdecl; external CLibCrypto;

//  {$HPPEMIT '# define BIO_set_app_data(s,arg)         BIO_set_ex_data(s,0,arg)'}
//  {$HPPEMIT '# define BIO_get_app_data(s)             BIO_get_ex_data(s,0)'}
//
//  {$HPPEMIT '# define BIO_set_nbio(b,n)             BIO_ctrl(b,BIO_C_SET_NBIO,(n),NULL)'}
//
//  {$HPPEMIT '# ifndef OPENSSL_NO_SOCK'}
//  (* IP families we support, for BIO_s_connect() and BIO_s_accept() *)
//  (* Note: the underlying operating system may not support some of them *)
//  {$HPPEMIT '#  define BIO_FAMILY_IPV4                         4'}
//  {$HPPEMIT '#  define BIO_FAMILY_IPV6                         6'}
//  {$HPPEMIT '#  define BIO_FAMILY_IPANY                        256'}
//
//  (* BIO_s_connect() *)
//  {$HPPEMIT '#  define BIO_set_conn_hostname(b,name) BIO_ctrl(b,BIO_C_SET_CONNECT,0,'}
//                                                   (char (name))
//  {$HPPEMIT '#  define BIO_set_conn_port(b,port)     BIO_ctrl(b,BIO_C_SET_CONNECT,1,'}
//                                                   (char (port))
//  {$HPPEMIT '#  define BIO_set_conn_address(b,addr)  BIO_ctrl(b,BIO_C_SET_CONNECT,2,'}
//                                                   (char (addr))
//  {$HPPEMIT '#  define BIO_set_conn_ip_family(b,f)   BIO_int_ctrl(b,BIO_C_SET_CONNECT,3,f)'}
//  {$HPPEMIT '#  define BIO_get_conn_hostname(b)      (( char )BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,0))'}
//  {$HPPEMIT '#  define BIO_get_conn_port(b)          (( char )BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,1))'}
//  {$HPPEMIT '#  define BIO_get_conn_address(b)       (( PBIO_ADDR )BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,2))'}
//  {$HPPEMIT '#  define BIO_get_conn_ip_family(b)     BIO_ctrl(b,BIO_C_GET_CONNECT,3,NULL)'}
//  {$HPPEMIT '#  define BIO_set_conn_mode(b,n)        BIO_ctrl(b,BIO_C_SET_CONNECT_MODE,(n),NULL)'}
//
//  (* BIO_s_accept() *)
//  {$HPPEMIT '#  define BIO_set_accept_name(b,name)   BIO_ctrl(b,BIO_C_SET_ACCEPT,0,'}
//  {$EXTERNALSYM PBIO}
//                                                   (char (name))
//  {$HPPEMIT '#  define BIO_set_accept_port(b,port)   BIO_ctrl(b,BIO_C_SET_ACCEPT,1,'}
//                                                   (char (port))
//  {$HPPEMIT '#  define BIO_get_accept_name(b)        (( char )BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,0))'}
//  {$HPPEMIT '#  define BIO_get_accept_port(b)        (( char )BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,1))'}
//  {$HPPEMIT '#  define BIO_get_peer_name(b)          (( char )BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,2))'}
//  {$HPPEMIT '#  define BIO_get_peer_port(b)          (( char )BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,3))'}
//  (* #define BIO_set_nbio(b,n)    BIO_ctrl(b,BIO_C_SET_NBIO,(n),NULL) *)
//  {$HPPEMIT '#  define BIO_set_nbio_accept(b,n)      #  define BIO_set_nbio_accept(b,n)      BIO_ctrl(b,BIO_C_SET_ACCEPT,2,(n)?(procedure )'a':NULL)  BIO_ctrl(b,BIO_C_SET_ACCEPT,3,'}
//                                                   (char (bio))
//  {$HPPEMIT '#  define BIO_set_accept_ip_family(b,f) BIO_int_ctrl(b,BIO_C_SET_ACCEPT,4,f)'}
//  {$HPPEMIT '#  define BIO_get_accept_ip_family(b)   BIO_ctrl(b,BIO_C_GET_ACCEPT,4,NULL)'}
//
//  (* Aliases kept for backward compatibility *)
//  {$HPPEMIT '#  define BIO_BIND_NORMAL                 0'}
//  {$HPPEMIT '#  define BIO_BIND_REUSEADDR              BIO_SOCK_REUSEADDR'}
//  {$HPPEMIT '#  define BIO_BIND_REUSEADDR_IF_UNUSED    BIO_SOCK_REUSEADDR'}
//  {$HPPEMIT '#  define BIO_set_bind_mode(b,mode) BIO_ctrl(b,BIO_C_SET_BIND_MODE,mode,NULL)'}
//  {$HPPEMIT '#  define BIO_get_bind_mode(b)    BIO_ctrl(b,BIO_C_GET_BIND_MODE,0,NULL)'}
//
//  (* BIO_s_accept() and BIO_s_connect() *)
//  {$HPPEMIT '#  define BIO_do_connect(b)       BIO_do_handshake(b)'}
//  {$HPPEMIT '#  define BIO_do_accept(b)        BIO_do_handshake(b)'}
//  {$HPPEMIT '# endif'}	(* OPENSSL_NO_SOCK *)
//
//  {$HPPEMIT '# define BIO_do_handshake(b)     BIO_ctrl(b,BIO_C_DO_STATE_MACHINE,0,NULL)'}
//
//  (* BIO_s_datagram(), BIO_s_fd(), BIO_s_socket(), BIO_s_accept() and BIO_s_connect() *)
//  {$HPPEMIT '# define BIO_set_fd(b,fd,c)      BIO_int_ctrl(b,BIO_C_SET_FD,c,fd)'}
//  {$HPPEMIT '# define BIO_get_fd(b,c)         BIO_ctrl(b,BIO_C_GET_FD,0,(char (c))'}
//
//  (* BIO_s_file() *)
//  {$HPPEMIT '# define BIO_set_fp(b,fp,c)      BIO_ctrl(b,BIO_C_SET_FILE_PTR,c,(char (fp))'}
//  {$HPPEMIT '# define BIO_get_fp(b,fpp)       BIO_ctrl(b,BIO_C_GET_FILE_PTR,0,(char (fpp))'}
//
//  (* BIO_s_fd() and BIO_s_file() *)
//  {$HPPEMIT '# define BIO_seek(b,ofs(int)BIO_ctrl(b,BIO_C_FILE_SEEK,ofs,NULL)'}
//  {$HPPEMIT '# define BIO_tell(b)     (int)BIO_ctrl(b,BIO_C_FILE_TELL,0,NULL)'}
//
//  (*
//   * name is cast to lose , but might be better to route through a
//   * cFunction so we can do it safely
//   *)
//  {$HPPEMIT '# ifdef CONST_STRICT'}
//  (*
//   * If you are wondering why this isn't defined, its because CONST_STRICT is
//   * purely a compile-time kludge to allow  to be checked.
//   *)
////  function BIO_read_filename(b: PBIO; const name: PIdAnsiChar): TIdC_INT;
//  {$HPPEMIT '# define BIO_write_filename(b,name(int)BIO_ctrl(b,BIO_C_SET_FILENAME,'}
//                  BIO_CLOSE or BIO_FP_WRITE,name)
//  {$HPPEMIT '# define BIO_append_filename(b,name(int)BIO_ctrl(b,BIO_C_SET_FILENAME,'}
//                  BIO_CLOSE or BIO_FP_APPEND,name)
//  {$HPPEMIT '# define BIO_rw_filename(b,name(int)BIO_ctrl(b,BIO_C_SET_FILENAME,'}
//                  BIO_CLOSE or BIO_FP_READ or BIO_FP_WRITE,name)
//
//  (*
//   * WARNING WARNING, this ups the reference count on the read bio of the SSL
//   * structure.  This is because the ssl read PBIO is now pointed to by the
//   * next_bio field in the bio.  So when you free the PBIO, make sure you are
//   * doing a BIO_free_all() to catch the underlying PBIO.
//   *)
//  {$HPPEMIT '# define BIO_set_ssl(b,ssl,c)    BIO_ctrl(b,BIO_C_SET_SSL,c,(char (ssl))'}
//  {$HPPEMIT '# define BIO_get_ssl(b,sslp)     BIO_ctrl(b,BIO_C_GET_SSL,0,(char (sslp))'}
//  {$HPPEMIT '# define BIO_set_ssl_mode(b,client)      BIO_ctrl(b,BIO_C_SSL_MODE,client,NULL)'}
//  {$HPPEMIT '# define BIO_set_ssl_renegotiate_bytes(b,num)'}
//          BIO_ctrl(b,BIO_C_SET_SSL_RENEGOTIATE_BYTES,num,0)
//  {$HPPEMIT '# define BIO_get_num_renegotiates(b)'}
//          BIO_ctrl(b,BIO_C_GET_SSL_NUM_RENEGOTIATES,0,0)
//  {$HPPEMIT '# define BIO_set_ssl_renegotiate_timeout(b,seconds)'}
//          BIO_ctrl(b,BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT,seconds,0)
//
//  (* defined in evp.h *)
//  (* #define BIO_set_md(b,md)     BIO_ctrl(b,BIO_C_SET_MD,1,(char )(md)) *)
//
//  (* For the BIO_f_buffer() type *)
//  {$HPPEMIT '# define BIO_get_buffer_num_lines(b)     BIO_ctrl(b,BIO_C_GET_BUFF_NUM_LINES,0,NULL)'}
//  {$HPPEMIT '# define BIO_set_buffer_size(b,size)     BIO_ctrl(b,BIO_C_SET_BUFF_SIZE,size,NULL)'}
//  {$HPPEMIT '# define BIO_set_read_buffer_size(b,size) BIO_int_ctrl(b,BIO_C_SET_BUFF_SIZE,size,0)'}
//  {$HPPEMIT '# define BIO_set_write_buffer_size(b,size) BIO_int_ctrl(b,BIO_C_SET_BUFF_SIZE,size,1)'}
//  {$HPPEMIT '# define BIO_set_buffer_read_data(b,buf,num) BIO_ctrl(b,BIO_C_SET_BUFF_READ_DATA,num,buf)'}
//
//  (* Don't use the next one unless you know what you are doing :-) */
//  {$HPPEMIT '# define BIO_dup_state(b,ret)    BIO_ctrl(b,BIO_CTRL_DUP,0,(char (ret))'}
//
//  {$HPPEMIT '# define BIO_reset(b)            (int)BIO_ctrl(b,BIO_CTRL_RESET,0,NULL)'}
//  {$HPPEMIT '# define BIO_eof(b)              (int)BIO_ctrl(b,BIO_CTRL_EOF,0,NULL)'}
//  {$HPPEMIT '# define BIO_set_close(b,c)      (int)BIO_ctrl(b,BIO_CTRL_SET_CLOSE,(c),NULL)'}
//  {$HPPEMIT '# define BIO_get_close(b)        (int)BIO_ctrl(b,BIO_CTRL_GET_CLOSE,0,NULL)'}
//  {$HPPEMIT '# define BIO_pending(b)          (int)BIO_ctrl(b,BIO_CTRL_PENDING,0,NULL)'}
//  {$HPPEMIT '# define BIO_wpending(b)         (int)BIO_ctrl(b,BIO_CTRL_WPENDING,0,NULL)'}
  (* ...pending macros have inappropriate return type *)
  function BIO_ctrl_pending(b: PBIO): TIdC_SIZET cdecl; external CLibCrypto;
  function BIO_ctrl_wpending(b: PBIO): TIdC_SIZET cdecl; external CLibCrypto;
//  {$HPPEMIT '# define BIO_flush(b)            (int)BIO_ctrl(b,BIO_CTRL_FLUSH,0,NULL)'}
//  {$HPPEMIT '# define BIO_get_info_callback(b,cbp(int)BIO_ctrl(b,BIO_CTRL_GET_CALLBACK,0,'}
//                                                     cbp)
//  {$HPPEMIT '# define BIO_set_info_callback(b,cb(int)BIO_callback_ctrl(b,BIO_CTRL_SET_CALLBACK,cb)'}
//
//  (* For the BIO_f_buffer() type *)
//  {$HPPEMIT '# define BIO_buffer_get_num_lines(b) BIO_ctrl(b,BIO_CTRL_GET,0,NULL)'}
//  {$HPPEMIT '# define BIO_buffer_peek(b,s,l) BIO_ctrl(b,BIO_CTRL_PEEK,(l),(s))'}
//
//  (* For BIO_s_bio() *)
//  {$HPPEMIT '# define BIO_set_write_buf_size(b,size(int)BIO_ctrl(b,BIO_C_SET_WRITE_BUF_SIZE,size,NULL)'}
//  {$HPPEMIT '# define BIO_get_write_buf_size(b,size(TIdC_SIZET)BIO_ctrl(b,BIO_C_GET_WRITE_BUF_SIZE,size,NULL)'}
//  {$HPPEMIT '# define BIO_make_bio_pair(b1,b2)   (int)BIO_ctrl(b1,BIO_C_MAKE_BIO_PAIR,0,b2)'}
//  {$HPPEMIT '# define BIO_destroy_bio_pair(b)    (int)BIO_ctrl(b,BIO_C_DESTROY_BIO_PAIR,0,NULL)'}
//  {$HPPEMIT '# define BIO_shutdown_wr(b(int)BIO_ctrl(b, BIO_C_SHUTDOWN_WR, 0, NULL)'}
//  (* macros with inappropriate type -- but ...pending macros use int too: *)
//  {$HPPEMIT '# define BIO_get_write_guarantee(b(int)BIO_ctrl(b,BIO_C_GET_WRITE_GUARANTEE,0,NULL)'}
//  {$HPPEMIT '# define BIO_get_read_request(b)    (int)BIO_ctrl(b,BIO_C_GET_READ_REQUEST,0,NULL)'}
  function BIO_ctrl_get_write_guarantee(b: PBIO): TIdC_SIZET cdecl; external CLibCrypto;
  function BIO_ctrl_get_read_request(b: PBIO): TIdC_SIZET cdecl; external CLibCrypto;
  function BIO_ctrl_reset_read_request(b: PBIO): TIdC_INT cdecl; external CLibCrypto;

  (* ctrl macros for dgram *)
//  {$HPPEMIT '# define BIO_ctrl_dgram_connect(b,peer)'}
//                       (TIdC_INT)BIO_ctrl(b,BIO_CTRL_DGRAM_CONNECT,0, (char (peer))
//  {$HPPEMIT '# define BIO_ctrl_set_connected(b,peer)'}
//           (TIdC_INT)BIO_ctrl(b, BIO_CTRL_DGRAM_SET_CONNECTED, 0, (char (peer))
//  {$HPPEMIT '# define BIO_dgram_recv_timedout(b)'}
//           (TIdC_INT)BIO_ctrl(b, BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, 0)
//  {$HPPEMIT '# define BIO_dgram_send_timedout(b)'}
//           (TIdC_INT)BIO_ctrl(b, BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP, 0, 0)
//  {$HPPEMIT '# define BIO_dgram_get_peer(b,peer)'}
//           (TIdC_INT)BIO_ctrl(b, BIO_CTRL_DGRAM_GET_PEER, 0, (char (peer))
//  {$HPPEMIT '# define BIO_dgram_set_peer(b,peer)'}
//           (TIdC_INT)BIO_ctrl(b, BIO_CTRL_DGRAM_SET_PEER, 0, (char (peer))
//  {$HPPEMIT '# define BIO_dgram_get_mtu_overhead(b)'}
//           (Cardinal)BIO_ctrl((b), BIO_CTRL_DGRAM_GET_MTU_OVERHEAD, 0, 0)

//#define BIO_get_ex_new_index(l, p, newf, dupf, freef) \
//    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_BIO, l, p, newf, dupf, freef)

  function BIO_set_ex_data(bio: PBIO; idx: TIdC_INT; data: Pointer): TIdC_INT cdecl; external CLibCrypto;
  function BIO_get_ex_data(bio: PBIO; idx: TIdC_INT): Pointer cdecl; external CLibCrypto;
  function BIO_number_read(bio: PBIO): TIdC_UINT64 cdecl; external CLibCrypto;
  function BIO_number_written(bio: PBIO): TIdC_UINT64 cdecl; external CLibCrypto;

  (* For BIO_f_asn1() *)
//  function BIO_asn1_set_prefix(b: PBIO; prefix: ^asn1_ps_func; prefix_free: ^asn1_ps_func): TIdC_INT;
//  function BIO_asn1_get_prefix(b: PBIO; pprefix: ^^asn1_ps_func; pprefix_free: ^^asn1_ps_func): TIdC_INT;
//  function BIO_asn1_set_suffix(b: PBIO; suffix: ^asn1_ps_func; suffix_free: ^asn1_ps_func): TIdC_INT;
//  function BIO_asn1_get_suffix(b: PBIO; psuffix: ^asn1_ps_func; psuffix_free: ^^asn1_ps_func): TIdC_INT;

  function BIO_s_file: PBIO_METHOD cdecl; external CLibCrypto;
  function BIO_new_file(const filename: PIdAnsiChar; const mode: PIdAnsiChar): PBIO cdecl; external CLibCrypto;
//  function BIO_new_fp(stream: cFile; close_flag: TIdC_INT): PBIO;
  function BIO_new(const cType: PBIO_METHOD): PBIO cdecl; external CLibCrypto;
  function BIO_free(a: PBIO): TIdC_INT cdecl; external CLibCrypto;
  procedure BIO_set_data(a: PBIO; _ptr: Pointer) cdecl; external CLibCrypto; {introduced 1.1.0}
  function BIO_get_data(a: PBIO): Pointer cdecl; external CLibCrypto; {introduced 1.1.0}
  procedure BIO_set_init(a: PBIO; init: TIdC_INT) cdecl; external CLibCrypto; {introduced 1.1.0}
  function BIO_get_init(a: PBIO): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  procedure BIO_set_shutdown(a: PBIO; shut: TIdC_INT) cdecl; external CLibCrypto; {introduced 1.1.0}
  function BIO_get_shutdown(a: PBIO): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  procedure BIO_vfree(a: PBIO) cdecl; external CLibCrypto;
  function BIO_up_ref(a: PBIO): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  function BIO_read(b: PBIO; data: Pointer; dlen: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function BIO_read_ex(b: PBIO; data: Pointer; dlen: TIdC_SIZET; readbytes: PIdC_SIZET): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  function BIO_recvmmsg(b : PBIO; msg : PBIO_MSG;
    stride, num_msg : TIdC_SIZET; flags : TIdC_UINT64;
    msgs_processed : PIdC_SIZET): TIdC_INT;  cdecl; external CLibCrypto; {introduced 3.2.0}
  function BIO_gets( bp: PBIO; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function BIO_write(b: PBIO; const data: Pointer; dlen: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function BIO_write_ex(b: PBIO; const data: Pointer; dlen: TIdC_SIZET; written: PIdC_SIZET): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  function BIO_sendmmsg(b0 : PBIO; msg : PBIO_MSG;
    stride, num_msg : TIdC_SIZET; flags : TIdC_UINT64;
    msgs_processed : PIdC_SIZET) : TIdC_INT; cdecl; external CLibCrypto;
  function BIO_get_rpoll_descriptor(b : PBIO; desc : PBIO_POLL_DESCRIPTOR)  : TIdC_INT; cdecl; external CLibCrypto;
  function BIO_get_wpoll_descriptor(b : PBIO; desc : PBIO_POLL_DESCRIPTOR) : TIdC_INT; cdecl; external CLibCrypto;

  function BIO_puts(bp: PBIO; const buf: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;
  function BIO_indent(b: PBIO; indent: TIdC_INT; max: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function BIO_ctrl(bp: PBIO; cmd: TIdC_INT; larg: TIdC_LONG; parg: Pointer): TIdC_LONG cdecl; external CLibCrypto;
  function BIO_callback_ctrl(b: PBIO; cmd: TIdC_INT; fp: PBIO_info_cb): TIdC_LONG cdecl; external CLibCrypto;
  function BIO_ptr_ctrl(bp: PBIO; cmd: TIdC_INT; larg: TIdC_LONG): Pointer cdecl; external CLibCrypto;
  function BIO_int_ctrl(bp: PBIO; cmd: TIdC_INT; larg: TIdC_LONG; iarg: TIdC_INT): TIdC_LONG cdecl; external CLibCrypto;
  function BIO_push(b: PBIO; _append: PBIO): PBIO cdecl; external CLibCrypto;
  function BIO_pop(b: PBIO): PBIO cdecl; external CLibCrypto;
  procedure BIO_free_all(a: PBIO) cdecl; external CLibCrypto;
  function BIO_find_type(b: PBIO; bio_type: TIdC_INT): PBIO cdecl; external CLibCrypto;
  function BIO_next(b: PBIO): PBIO cdecl; external CLibCrypto;
  procedure BIO_set_next(b: PBIO; next: PBIO) cdecl; external CLibCrypto; {introduced 1.1.0}
  function BIO_get_retry_BIO(bio: PBIO; reason: TIdC_INT): PBIO cdecl; external CLibCrypto;
  function BIO_get_retry_reason(bio: PBIO): TIdC_INT cdecl; external CLibCrypto;
  procedure BIO_set_retry_reason(bio: PBIO; reason: TIdC_INT) cdecl; external CLibCrypto; {introduced 1.1.0}
  function BIO_dup_chain(in_: PBIO): PBIO cdecl; external CLibCrypto;

  function BIO_nread0(bio: PBIO; buf: PPIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;
  function BIO_nread(bio: PBIO; buf: PPIdAnsiChar; num: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function BIO_nwrite0(bio: PBIO; buf: PPIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;
  function BIO_nwrite(bio: PBIO; buf: PPIdAnsiChar; num: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  function BIO_debug_callback(bio: PBIO; cmd: TIdC_INT; const argp: PIdAnsiChar; argi: TIdC_INT; argl: TIdC_LONG; ret: TIdC_LONG): TIdC_LONG cdecl; external CLibCrypto;

  function BIO_s_mem: PBIO_METHOD cdecl; external CLibCrypto;
  function BIO_s_secmem: PBIO_METHOD cdecl; external CLibCrypto; {introduced 1.1.0}
  function BIO_new_mem_buf(const buf; len: TIdC_INT): PBIO cdecl; external CLibCrypto;

  function BIO_s_socket: PBIO_METHOD cdecl; external CLibCrypto;
  function BIO_s_connect: PBIO_METHOD cdecl; external CLibCrypto;
  function BIO_s_accept: PBIO_METHOD cdecl; external CLibCrypto;

  function BIO_s_fd: PBIO_METHOD cdecl; external CLibCrypto;
  function BIO_s_log: PBIO_METHOD cdecl; external CLibCrypto;
  function BIO_s_bio: PBIO_METHOD cdecl; external CLibCrypto;
  function BIO_s_null: PBIO_METHOD cdecl; external CLibCrypto;
  function BIO_f_null: PBIO_METHOD cdecl; external CLibCrypto;
  function BIO_f_buffer: PBIO_METHOD cdecl; external CLibCrypto;
  function BIO_f_linebuffer: PBIO_METHOD cdecl; external CLibCrypto; {introduced 1.1.0}
  function BIO_f_nbio_test: PBIO_METHOD cdecl; external CLibCrypto;
  function BIO_s_datagram: PBIO_METHOD cdecl; external CLibCrypto;
  function BIO_dgram_non_fatal_error(_error: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function BIO_new_dgram(fd: TIdC_INT; close_flag: TIdC_INT): PBIO cdecl; external CLibCrypto;

//  function BIO_s_datagram_sctp: PBIO_METHOD;
//  function BIO_new_dgram_sctp(fd: TIdC_INT; close_flag: TIdC_INT): PBIO;
//  function BIO_dgram_is_sctp(bio: PBIO): TIdC_INT;
//  function BIO_dgram_sctp_notification_cb(bio: PBIO; handle_notifications(PBIO;
//    context: Pointer;
//    buf: Pointer): TIdC_INT, Pointer context);
//  function BIO_dgram_sctp_wait_for_dry(b: PBIO): TIdC_INT;
//  function BIO_dgram_sctp_msg_waiting(b: PBIO): TIdC_INT;

  function BIO_sock_should_retry(i: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function BIO_sock_non_fatal_error(_error: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function BIO_err_is_non_fatal(errcode : TIdC_UINT) : TIdC_INT cdecl; external CLibCrypto;


  function BIO_fd_should_retry(i: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function BIO_fd_non_fatal_error(_error: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
//  function BIO_dump_cb(
//    Pointer data: cb(;
//    len: TIdC_SIZET;
//    function: Pointer): u: TIdC_INT, Pointer function ,  PIdAnsiChar s, TIdC_INT len): u;
//  function BIO_dump_indent_cb(TIdC_INT (cb( Pointer data, TIdC_SIZET len, Pointer function ): u: TIdC_INT, Pointer function ,  PIdAnsiChar s, TIdC_INT len, TIdC_INT indent): u;
  function BIO_dump(b: PBIO; const bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function BIO_dump_indent(b: PBIO; const bytes: PIdAnsiChar; len: TIdC_INT; indent: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

//  function BIO_dump_fp(fp: cFile; const s: PByte; len: TIdC_INT): TIdC_INT;
//  function BIO_dump_indent_fp(fp: cFile; const s: PByte; len: TIdC_INT; indent: TIdC_INT): TIdC_INT;

  function BIO_hex_string(out_: PBIO; indent: TIdC_INT; width: TIdC_INT; data: PByte; datalen: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  function BIO_ADDR_new: PBIO_ADDR cdecl; external CLibCrypto; {introduced 1.1.0}
  function BIO_ADDR_rawmake(ap: PBIO_ADDR; familiy: TIdC_INT; const where: Pointer; wherelen: TIdC_SIZET; port: TIdC_SHORT): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  procedure BIO_ADDR_free(a: PBIO_ADDR) cdecl; external CLibCrypto; {introduced 1.1.0}
  procedure BIO_ADDR_clear(ap: PBIO_ADDR) cdecl; external CLibCrypto; {introduced 1.1.0}
  function BIO_ADDR_family(const ap: PBIO_ADDR): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  function BIO_ADDR_rawaddress(const ap: PBIO_ADDR; p: Pointer; l: PIdC_SIZET): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  function BIO_ADDR_rawport(const ap: PBIO_ADDR): TIdC_SHORT cdecl; external CLibCrypto; {introduced 1.1.0}
  function BIO_ADDR_hostname_string(const ap: PBIO_ADDR; numeric: TIdC_INT): PIdAnsiChar cdecl; external CLibCrypto; {introduced 1.1.0}
  function BIO_ADDR_service_string(const ap: PBIO_ADDR; numeric: TIdC_INT): PIdAnsiChar cdecl; external CLibCrypto; {introduced 1.1.0}
  function BIO_ADDR_path_string(const ap: PBIO_ADDR): PIdAnsiChar cdecl; external CLibCrypto; {introduced 1.1.0}

  function BIO_ADDRINFO_next(const bai: PBIO_ADDRINFO): PBIO_ADDRINFO cdecl; external CLibCrypto; {introduced 1.1.0}
  function BIO_ADDRINFO_family(const bai: PBIO_ADDRINFO): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  function BIO_ADDRINFO_socktype(const bai: PBIO_ADDRINFO): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  function BIO_ADDRINFO_protocol(const bai: PBIO_ADDRINFO): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  function BIO_ADDRINFO_address(const bai: PBIO_ADDRINFO): PBIO_ADDR cdecl; external CLibCrypto; {introduced 1.1.0}
  procedure BIO_ADDRINFO_free(bai: PBIO_ADDRINFO) cdecl; external CLibCrypto; {introduced 1.1.0}

  function BIO_parse_hostserv(const hostserv: PIdAnsiChar; var host, service: PIdAnsiChar; hostserv_prio: BIO_hostserv_priorities): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  function BIO_lookup(const host: PIdAnsiChar; const service: PIdAnsiChar; lookup_type: BIO_lookup_type; family: TIdC_INT; socktype: TIdC_INT; res: PPBIO_ADDRINFO): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  function BIO_lookup_ex(const host: PIdAnsiChar; const service: PIdAnsiChar; lookup_type: TIdC_INT; family: TIdC_INT; socktype: TIdC_INT; protocol: TIdC_INT; res: PPBIO_ADDRINFO): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  function BIO_sock_error(sock: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function BIO_socket_ioctl(fd: TIdC_INT; cType: TIdC_LONG; arg: Pointer): TIdC_INT cdecl; external CLibCrypto;
  function BIO_socket_nbio(fd: TIdC_INT; mode: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function BIO_sock_init: TIdC_INT cdecl; external CLibCrypto;

  function BIO_set_tcp_ndelay(sock: TIdC_INT; turn_on: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  function BIO_sock_info(sock: TIdC_INT; type_: BIO_sock_info_type; info: PBIO_sock_info_u): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  function BIO_socket(domain: TIdC_INT; socktype: TIdC_INT; protocol: TIdC_INT; options: TIdC_INT): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  function BIO_connect(sock: TIdC_INT; const address: PBIO_ADDR; options: TIdC_INT): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  function BIO_bind(sock: TIdC_INT; const address: PBIO_ADDR; options: TIdC_INT): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  function BIO_listen(sock: TIdC_INT; const address: PBIO_ADDR; options: TIdC_INT): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  function BIO_accept_ex(accept_sock: TIdC_INT; address: PBIO_ADDR; options: TIdC_INT): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  function BIO_closesocket(sock: TIdC_INT): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  function BIO_new_socket(sock: TIdC_INT; close_flag: TIdC_INT): PBIO cdecl; external CLibCrypto;
  function BIO_new_connect(const host_port: PIdAnsiChar): PBIO cdecl; external CLibCrypto;
  function BIO_new_accept(const host_port: PIdAnsiChar): PBIO cdecl; external CLibCrypto;

  function BIO_new_fd(fd: TIdC_INT; close_flag: TIdC_INT): PBIO cdecl; external CLibCrypto;

  function BIO_new_bio_pair(bio1: PPBIO; writebuf1: TIdC_SIZET; bio2: PPBIO; writebuf2: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto;
  (*
   * If successful, returns 1 and in *bio1, *bio2 two BIO pair endpoints.
   * Otherwise returns 0 and sets *bio1 and *bio2 to NULL. Size 0 uses default
   * value.
   *)

  procedure BIO_copy_next_retry(b: PBIO) cdecl; external CLibCrypto;

//  BIO_METHOD *BIO_meth_new(int type, const char *name);
//  void BIO_meth_free(BIO_METHOD *biom);
//  int (*BIO_meth_get_write(const BIO_METHOD *biom)) (BIO *, const char *, int);
//  int (*BIO_meth_get_write_ex(const BIO_METHOD *biom)) (BIO *, const char *, TIdC_SIZET,
//                                                  TIdC_SIZET *);
//  int BIO_meth_set_write(BIO_METHOD *biom,
//                         int (*write) (BIO *, const char *, int));
//  int BIO_meth_set_write_ex(BIO_METHOD *biom,
//                         int (*bwrite) (BIO *, const char *, TIdC_SIZET, TIdC_SIZET *));
//  int (*BIO_meth_get_read(const BIO_METHOD *biom)) (BIO *, char *, int);
//  int (*BIO_meth_get_read_ex(const BIO_METHOD *biom)) (BIO *, char *, TIdC_SIZET, TIdC_SIZET *);
//  int BIO_meth_set_read(BIO_METHOD *biom,
//                        int (*read) (BIO *, char *, int));
//  int BIO_meth_set_read_ex(BIO_METHOD *biom,
//                           int (*bread) (BIO *, char *, TIdC_SIZET, TIdC_SIZET *));
//  int (*BIO_meth_get_puts(const BIO_METHOD *biom)) (BIO *, const char *);
//  int BIO_meth_set_puts(BIO_METHOD *biom,
//                        int (*puts) (BIO *, const char *));
//  int (*BIO_meth_get_gets(const BIO_METHOD *biom)) (BIO *, char *, int);
//  int BIO_meth_set_gets(BIO_METHOD *biom,
//                        int (*gets) (BIO *, char *, int));
//  long (*BIO_meth_get_ctrl(const BIO_METHOD *biom)) (BIO *, int, long, void *);
//  int BIO_meth_set_ctrl(BIO_METHOD *biom,
//                        long (*ctrl) (BIO *, int, long, void *));
//  int (*BIO_meth_get_create(const BIO_METHOD *bion)) (BIO *);
//  int BIO_meth_set_create(BIO_METHOD *biom, int (*create) (BIO *));
//  int (*BIO_meth_get_destroy(const BIO_METHOD *biom)) (BIO *);
//  int BIO_meth_set_destroy(BIO_METHOD *biom, int (*destroy) (BIO *));
//  long (*BIO_meth_get_callback_ctrl(const BIO_METHOD *biom))
//                                   (BIO *, int, BIO_info_cb *);
//  int BIO_meth_set_callback_ctrl(BIO_METHOD *biom,
//                                 long (*callback_ctrl) (BIO *, int,
//                                                        BIO_info_cb *));

function BIO_get_flags(const b: PBIO): TIdC_INT; {removed 1.0.0}
procedure BIO_set_retry_special(b: PBIO); {removed 1.0.0}
procedure BIO_set_retry_read(b: PBIO); {removed 1.0.0}
procedure BIO_set_retry_write(b: PBIO); {removed 1.0.0}
procedure BIO_clear_retry_flags(b: PBIO); {removed 1.0.0}
function BIO_get_retry_flags(b: PBIO): TIdC_INT; {removed 1.0.0}
function BIO_should_read(b: PBIO): TIdC_INT; {removed 1.0.0}
function BIO_should_write(b: PBIO): TIdC_INT; {removed 1.0.0}
function BIO_should_io_special(b: PBIO): TIdC_INT; {removed 1.0.0}
function BIO_retry_type(b: PBIO): TIdC_INT; {removed 1.0.0}
function BIO_should_retry(b: PBIO): TIdC_INT; {removed 1.0.0}
function BIO_do_connect(b: PBIO): TIdC_LONG; {removed 1.0.0}
function BIO_do_accept(b: PBIO): TIdC_LONG; {removed 1.0.0}
function BIO_do_handshake(b: PBIO): TIdC_LONG; {removed 1.0.0}
// WAS DECLARED AS:
// function BIO_get_mem_data(b: PBIO; pp: Pointer) : TIdC_INT; {removed 1.0.0}
function BIO_get_mem_data(b: PBIO; var pp: Pointer) : TIdC_INT; {removed 1.0.0}
function BIO_set_mem_buf(b: PBIO; bm: PBUF_MEM; c: TIdC_INT): TIdC_INT; {removed 1.0.0}
// WAS DECLARED AS:
// function BIO_get_mem_ptr(b: PBIO; pp: Pointer): TIdC_INT; {removed 1.0.0}
function BIO_get_mem_ptr(b: PBIO; out pp: PBUF_MEM): TIdC_INT; {removed 1.0.0}
function BIO_set_mem_eof_return(b: PBIO; v: TIdC_INT): TIdC_INT; {removed 1.0.0}
{$ENDIF}

function BIO_dgram_get_local_addr_enable(b : PBIO; out penable : TIdC_INT) : TIdC_INT;
function BIO_dgram_set_local_addr_enable(b : PBIO; enable : TIdC_INT) : TIdC_INT;
function BIO_dgram_get_local_addr_cap(b : PBIO) : TIdC_INT;

implementation

  uses
    classes, 
    TaurusTLSExceptionHandlers
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    ,TaurusTLSLoader
  {$ENDIF};

function BIO_dgram_get_local_addr_enable(b : PBIO; out penable : TIdC_INT) : TIdC_INT;
{$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := BIO_ctrl(b, BIO_CTRL_DGRAM_GET_LOCAL_ADDR_ENABLE, 0, @penable);
end;

function BIO_dgram_set_local_addr_enable(b : PBIO; enable : TIdC_INT) : TIdC_INT;
{$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := BIO_ctrl(b, BIO_CTRL_DGRAM_SET_LOCAL_ADDR_ENABLE, enable, nil);
end;

function BIO_dgram_get_local_addr_cap(b : PBIO) : TIdC_INT;
{$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := BIO_ctrl(b, BIO_CTRL_DGRAM_GET_LOCAL_ADDR_CAP, 0, nil);
end;

const
  BIO_get_new_index_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_get_callback_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_set_callback_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_set_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_get_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_set_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_get_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_set_shutdown_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_get_shutdown_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_up_ref_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_read_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_recvmmsg_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
  BIO_write_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_sendmmsg_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
  BIO_get_rpoll_descriptor_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
  BIO_get_wpoll_descriptor_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
  BIO_set_next_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_set_retry_reason_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_s_secmem_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_f_linebuffer_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_ADDR_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_ADDR_rawmake_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_ADDR_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_ADDR_clear_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_ADDR_family_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_ADDR_rawaddress_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_ADDR_rawport_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_ADDR_hostname_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_ADDR_service_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_ADDR_path_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_ADDRINFO_next_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_ADDRINFO_family_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_ADDRINFO_socktype_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_ADDRINFO_protocol_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_ADDRINFO_address_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_ADDRINFO_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_parse_hostserv_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_lookup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_lookup_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_sock_info_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_socket_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_connect_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_bind_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_listen_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_accept_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_closesocket_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BIO_get_flags_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  BIO_set_retry_special_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  BIO_set_retry_read_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  BIO_set_retry_write_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  BIO_clear_retry_flags_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  BIO_get_retry_flags_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  BIO_should_read_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  BIO_should_write_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  BIO_should_io_special_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  BIO_retry_type_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  BIO_should_retry_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  BIO_do_connect_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  BIO_do_accept_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  BIO_do_handshake_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  BIO_get_mem_data_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  BIO_set_mem_buf_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  BIO_get_mem_ptr_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  BIO_set_mem_eof_return_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  BIO_err_is_non_fatal_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
// # define BIO_get_flags(b) BIO_test_flags(b, ~(0x0))
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
const
  BIO_get_flags_procname = 'BIO_get_flags'; {removed 1.0.0}
  BIO_set_retry_special_procname = 'BIO_set_retry_special'; {removed 1.0.0}
  BIO_set_retry_read_procname = 'BIO_set_retry_read'; {removed 1.0.0}
  BIO_set_retry_write_procname = 'BIO_set_retry_write'; {removed 1.0.0}

(* These are normally used internally in BIOs *)
  BIO_clear_retry_flags_procname = 'BIO_clear_retry_flags'; {removed 1.0.0}
  BIO_get_retry_flags_procname = 'BIO_get_retry_flags'; {removed 1.0.0}

(* These should be used by the application to tell why we should retry *)
  BIO_should_read_procname = 'BIO_should_read'; {removed 1.0.0}
  BIO_should_write_procname = 'BIO_should_write'; {removed 1.0.0}
  BIO_should_io_special_procname = 'BIO_should_io_special'; {removed 1.0.0}
  BIO_retry_type_procname = 'BIO_retry_type'; {removed 1.0.0}
  BIO_should_retry_procname = 'BIO_should_retry'; {removed 1.0.0}

(* BIO_s_accept() and BIO_s_connect() *)
  BIO_do_connect_procname = 'BIO_do_connect'; {removed 1.0.0}
  BIO_do_accept_procname = 'BIO_do_accept'; {removed 1.0.0}
  BIO_do_handshake_procname = 'BIO_do_handshake'; {removed 1.0.0}

  BIO_get_mem_data_procname = 'BIO_get_mem_data'; {removed 1.0.0}
  BIO_set_mem_buf_procname = 'BIO_set_mem_buf'; {removed 1.0.0}
  BIO_get_mem_ptr_procname = 'BIO_get_mem_ptr'; {removed 1.0.0}
  BIO_set_mem_eof_return_procname = 'BIO_set_mem_eof_return'; {removed 1.0.0}

  BIO_get_new_index_procname = 'BIO_get_new_index'; {introduced 1.1.0}
  BIO_set_flags_procname = 'BIO_set_flags';
  BIO_test_flags_procname = 'BIO_test_flags';
  BIO_clear_flags_procname = 'BIO_clear_flags';

  BIO_get_callback_procname = 'BIO_get_callback';
  BIO_set_callback_procname = 'BIO_set_callback';

  BIO_get_callback_ex_procname = 'BIO_get_callback_ex'; {introduced 1.1.0}
  BIO_set_callback_ex_procname = 'BIO_set_callback_ex'; {introduced 1.1.0}

  BIO_get_callback_arg_procname = 'BIO_get_callback_arg';
  BIO_set_callback_arg_procname = 'BIO_set_callback_arg';

  BIO_method_name_procname = 'BIO_method_name';
  BIO_method_type_procname = 'BIO_method_type';

//  {$HPPEMIT '# define BIO_set_app_data(s,arg)         BIO_set_ex_data(s,0,arg)'}
//  {$HPPEMIT '# define BIO_get_app_data(s)             BIO_get_ex_data(s,0)'}
//
//  {$HPPEMIT '# define BIO_set_nbio(b,n)             BIO_ctrl(b,BIO_C_SET_NBIO,(n),NULL)'}
//
//  {$HPPEMIT '# ifndef OPENSSL_NO_SOCK'}
//  (* IP families we support, for BIO_s_connect() and BIO_s_accept() *)
//  (* Note: the underlying operating system may not support some of them *)
//  {$HPPEMIT '#  define BIO_FAMILY_IPV4                         4'}
//  {$HPPEMIT '#  define BIO_FAMILY_IPV6                         6'}
//  {$HPPEMIT '#  define BIO_FAMILY_IPANY                        256'}
//
//  (* BIO_s_connect() *)
//  {$HPPEMIT '#  define BIO_set_conn_hostname(b,name) BIO_ctrl(b,BIO_C_SET_CONNECT,0,'}
//                                                   (char (name))
//  {$HPPEMIT '#  define BIO_set_conn_port(b,port)     BIO_ctrl(b,BIO_C_SET_CONNECT,1,'}
//                                                   (char (port))
//  {$HPPEMIT '#  define BIO_set_conn_address(b,addr)  BIO_ctrl(b,BIO_C_SET_CONNECT,2,'}
//                                                   (char (addr))
//  {$HPPEMIT '#  define BIO_set_conn_ip_family(b,f)   BIO_int_ctrl(b,BIO_C_SET_CONNECT,3,f)'}
//  {$HPPEMIT '#  define BIO_get_conn_hostname(b)      (( char )BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,0))'}
//  {$HPPEMIT '#  define BIO_get_conn_port(b)          (( char )BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,1))'}
//  {$HPPEMIT '#  define BIO_get_conn_address(b)       (( PBIO_ADDR )BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,2))'}
//  {$HPPEMIT '#  define BIO_get_conn_ip_family(b)     BIO_ctrl(b,BIO_C_GET_CONNECT,3,NULL)'}
//  {$HPPEMIT '#  define BIO_set_conn_mode(b,n)        BIO_ctrl(b,BIO_C_SET_CONNECT_MODE,(n),NULL)'}
//
//  (* BIO_s_accept() *)
//  {$HPPEMIT '#  define BIO_set_accept_name(b,name)   BIO_ctrl(b,BIO_C_SET_ACCEPT,0,'}
//  {$EXTERNALSYM PBIO}
//                                                   (char (name))
//  {$HPPEMIT '#  define BIO_set_accept_port(b,port)   BIO_ctrl(b,BIO_C_SET_ACCEPT,1,'}
//                                                   (char (port))
//  {$HPPEMIT '#  define BIO_get_accept_name(b)        (( char )BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,0))'}
//  {$HPPEMIT '#  define BIO_get_accept_port(b)        (( char )BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,1))'}
//  {$HPPEMIT '#  define BIO_get_peer_name(b)          (( char )BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,2))'}
//  {$HPPEMIT '#  define BIO_get_peer_port(b)          (( char )BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,3))'}
//  (* #define BIO_set_nbio(b,n)    BIO_ctrl(b,BIO_C_SET_NBIO,(n),NULL) *)
//  {$HPPEMIT '#  define BIO_set_nbio_accept(b,n)      #  define BIO_set_nbio_accept(b,n)      BIO_ctrl(b,BIO_C_SET_ACCEPT,2,(n)?(procedure )'a':NULL)  BIO_ctrl(b,BIO_C_SET_ACCEPT,3,'}
//                                                   (char (bio))
//  {$HPPEMIT '#  define BIO_set_accept_ip_family(b,f) BIO_int_ctrl(b,BIO_C_SET_ACCEPT,4,f)'}
//  {$HPPEMIT '#  define BIO_get_accept_ip_family(b)   BIO_ctrl(b,BIO_C_GET_ACCEPT,4,NULL)'}
//
//  (* Aliases kept for backward compatibility *)
//  {$HPPEMIT '#  define BIO_BIND_NORMAL                 0'}
//  {$HPPEMIT '#  define BIO_BIND_REUSEADDR              BIO_SOCK_REUSEADDR'}
//  {$HPPEMIT '#  define BIO_BIND_REUSEADDR_IF_UNUSED    BIO_SOCK_REUSEADDR'}
//  {$HPPEMIT '#  define BIO_set_bind_mode(b,mode) BIO_ctrl(b,BIO_C_SET_BIND_MODE,mode,NULL)'}
//  {$HPPEMIT '#  define BIO_get_bind_mode(b)    BIO_ctrl(b,BIO_C_GET_BIND_MODE,0,NULL)'}
//
//  (* BIO_s_accept() and BIO_s_connect() *)
//  {$HPPEMIT '#  define BIO_do_connect(b)       BIO_do_handshake(b)'}
//  {$HPPEMIT '#  define BIO_do_accept(b)        BIO_do_handshake(b)'}
//  {$HPPEMIT '# endif'}	(* OPENSSL_NO_SOCK *)
//
//  {$HPPEMIT '# define BIO_do_handshake(b)     BIO_ctrl(b,BIO_C_DO_STATE_MACHINE,0,NULL)'}
//
//  (* BIO_s_datagram(), BIO_s_fd(), BIO_s_socket(), BIO_s_accept() and BIO_s_connect() *)
//  {$HPPEMIT '# define BIO_set_fd(b,fd,c)      BIO_int_ctrl(b,BIO_C_SET_FD,c,fd)'}
//  {$HPPEMIT '# define BIO_get_fd(b,c)         BIO_ctrl(b,BIO_C_GET_FD,0,(char (c))'}
//
//  (* BIO_s_file() *)
//  {$HPPEMIT '# define BIO_set_fp(b,fp,c)      BIO_ctrl(b,BIO_C_SET_FILE_PTR,c,(char (fp))'}
//  {$HPPEMIT '# define BIO_get_fp(b,fpp)       BIO_ctrl(b,BIO_C_GET_FILE_PTR,0,(char (fpp))'}
//
//  (* BIO_s_fd() and BIO_s_file() *)
//  {$HPPEMIT '# define BIO_seek(b,ofs(int)BIO_ctrl(b,BIO_C_FILE_SEEK,ofs,NULL)'}
//  {$HPPEMIT '# define BIO_tell(b)     (int)BIO_ctrl(b,BIO_C_FILE_TELL,0,NULL)'}
//
//  (*
//   * name is cast to lose , but might be better to route through a
//   * cFunction so we can do it safely
//   *)
//  {$HPPEMIT '# ifdef CONST_STRICT'}
//  (*
//   * If you are wondering why this isn't defined, its because CONST_STRICT is
//   * purely a compile-time kludge to allow  to be checked.
//   *)
////  function BIO_read_filename(b: PBIO; const name: PIdAnsiChar): TIdC_INT;
//  {$HPPEMIT '# define BIO_write_filename(b,name(int)BIO_ctrl(b,BIO_C_SET_FILENAME,'}
//                  BIO_CLOSE or BIO_FP_WRITE,name)
//  {$HPPEMIT '# define BIO_append_filename(b,name(int)BIO_ctrl(b,BIO_C_SET_FILENAME,'}
//                  BIO_CLOSE or BIO_FP_APPEND,name)
//  {$HPPEMIT '# define BIO_rw_filename(b,name(int)BIO_ctrl(b,BIO_C_SET_FILENAME,'}
//                  BIO_CLOSE or BIO_FP_READ or BIO_FP_WRITE,name)
//
//  (*
//   * WARNING WARNING, this ups the reference count on the read bio of the SSL
//   * structure.  This is because the ssl read PBIO is now pointed to by the
//   * next_bio field in the bio.  So when you free the PBIO, make sure you are
//   * doing a BIO_free_all() to catch the underlying PBIO.
//   *)
//  {$HPPEMIT '# define BIO_set_ssl(b,ssl,c)    BIO_ctrl(b,BIO_C_SET_SSL,c,(char (ssl))'}
//  {$HPPEMIT '# define BIO_get_ssl(b,sslp)     BIO_ctrl(b,BIO_C_GET_SSL,0,(char (sslp))'}
//  {$HPPEMIT '# define BIO_set_ssl_mode(b,client)      BIO_ctrl(b,BIO_C_SSL_MODE,client,NULL)'}
//  {$HPPEMIT '# define BIO_set_ssl_renegotiate_bytes(b,num)'}
//          BIO_ctrl(b,BIO_C_SET_SSL_RENEGOTIATE_BYTES,num,0)
//  {$HPPEMIT '# define BIO_get_num_renegotiates(b)'}
//          BIO_ctrl(b,BIO_C_GET_SSL_NUM_RENEGOTIATES,0,0)
//  {$HPPEMIT '# define BIO_set_ssl_renegotiate_timeout(b,seconds)'}
//          BIO_ctrl(b,BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT,seconds,0)
//
//  (* defined in evp.h *)
//  (* #define BIO_set_md(b,md)     BIO_ctrl(b,BIO_C_SET_MD,1,(char )(md)) *)
//
//  (* For the BIO_f_buffer() type *)
//  {$HPPEMIT '# define BIO_get_buffer_num_lines(b)     BIO_ctrl(b,BIO_C_GET_BUFF_NUM_LINES,0,NULL)'}
//  {$HPPEMIT '# define BIO_set_buffer_size(b,size)     BIO_ctrl(b,BIO_C_SET_BUFF_SIZE,size,NULL)'}
//  {$HPPEMIT '# define BIO_set_read_buffer_size(b,size) BIO_int_ctrl(b,BIO_C_SET_BUFF_SIZE,size,0)'}
//  {$HPPEMIT '# define BIO_set_write_buffer_size(b,size) BIO_int_ctrl(b,BIO_C_SET_BUFF_SIZE,size,1)'}
//  {$HPPEMIT '# define BIO_set_buffer_read_data(b,buf,num) BIO_ctrl(b,BIO_C_SET_BUFF_READ_DATA,num,buf)'}
//
//  (* Don't use the next one unless you know what you are doing :-) */
//  {$HPPEMIT '# define BIO_dup_state(b,ret)    BIO_ctrl(b,BIO_CTRL_DUP,0,(char (ret))'}
//
//  {$HPPEMIT '# define BIO_reset(b)            (int)BIO_ctrl(b,BIO_CTRL_RESET,0,NULL)'}
//  {$HPPEMIT '# define BIO_eof(b)              (int)BIO_ctrl(b,BIO_CTRL_EOF,0,NULL)'}
//  {$HPPEMIT '# define BIO_set_close(b,c)      (int)BIO_ctrl(b,BIO_CTRL_SET_CLOSE,(c),NULL)'}
//  {$HPPEMIT '# define BIO_get_close(b)        (int)BIO_ctrl(b,BIO_CTRL_GET_CLOSE,0,NULL)'}
//  {$HPPEMIT '# define BIO_pending(b)          (int)BIO_ctrl(b,BIO_CTRL_PENDING,0,NULL)'}
//  {$HPPEMIT '# define BIO_wpending(b)         (int)BIO_ctrl(b,BIO_CTRL_WPENDING,0,NULL)'}
  (* ...pending macros have inappropriate return type *)
  BIO_ctrl_pending_procname = 'BIO_ctrl_pending';
  BIO_ctrl_wpending_procname = 'BIO_ctrl_wpending';
//  {$HPPEMIT '# define BIO_flush(b)            (int)BIO_ctrl(b,BIO_CTRL_FLUSH,0,NULL)'}
//  {$HPPEMIT '# define BIO_get_info_callback(b,cbp(int)BIO_ctrl(b,BIO_CTRL_GET_CALLBACK,0,'}
//                                                     cbp)
//  {$HPPEMIT '# define BIO_set_info_callback(b,cb(int)BIO_callback_ctrl(b,BIO_CTRL_SET_CALLBACK,cb)'}
//
//  (* For the BIO_f_buffer() type *)
//  {$HPPEMIT '# define BIO_buffer_get_num_lines(b) BIO_ctrl(b,BIO_CTRL_GET,0,NULL)'}
//  {$HPPEMIT '# define BIO_buffer_peek(b,s,l) BIO_ctrl(b,BIO_CTRL_PEEK,(l),(s))'}
//
//  (* For BIO_s_bio() *)
//  {$HPPEMIT '# define BIO_set_write_buf_size(b,size(int)BIO_ctrl(b,BIO_C_SET_WRITE_BUF_SIZE,size,NULL)'}
//  {$HPPEMIT '# define BIO_get_write_buf_size(b,size(TIdC_SIZET)BIO_ctrl(b,BIO_C_GET_WRITE_BUF_SIZE,size,NULL)'}
//  {$HPPEMIT '# define BIO_make_bio_pair(b1,b2)   (int)BIO_ctrl(b1,BIO_C_MAKE_BIO_PAIR,0,b2)'}
//  {$HPPEMIT '# define BIO_destroy_bio_pair(b)    (int)BIO_ctrl(b,BIO_C_DESTROY_BIO_PAIR,0,NULL)'}
//  {$HPPEMIT '# define BIO_shutdown_wr(b(int)BIO_ctrl(b, BIO_C_SHUTDOWN_WR, 0, NULL)'}
//  (* macros with inappropriate type -- but ...pending macros use int too: *)
//  {$HPPEMIT '# define BIO_get_write_guarantee(b(int)BIO_ctrl(b,BIO_C_GET_WRITE_GUARANTEE,0,NULL)'}
//  {$HPPEMIT '# define BIO_get_read_request(b)    (int)BIO_ctrl(b,BIO_C_GET_READ_REQUEST,0,NULL)'}
  BIO_ctrl_get_write_guarantee_procname = 'BIO_ctrl_get_write_guarantee';
  BIO_ctrl_get_read_request_procname = 'BIO_ctrl_get_read_request';
  BIO_ctrl_reset_read_request_procname = 'BIO_ctrl_reset_read_request';

  (* ctrl macros for dgram *)
//  {$HPPEMIT '# define BIO_ctrl_dgram_connect(b,peer)'}
//                       (TIdC_INT)BIO_ctrl(b,BIO_CTRL_DGRAM_CONNECT,0, (char (peer))
//  {$HPPEMIT '# define BIO_ctrl_set_connected(b,peer)'}
//           (TIdC_INT)BIO_ctrl(b, BIO_CTRL_DGRAM_SET_CONNECTED, 0, (char (peer))
//  {$HPPEMIT '# define BIO_dgram_recv_timedout(b)'}
//           (TIdC_INT)BIO_ctrl(b, BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, 0)
//  {$HPPEMIT '# define BIO_dgram_send_timedout(b)'}
//           (TIdC_INT)BIO_ctrl(b, BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP, 0, 0)
//  {$HPPEMIT '# define BIO_dgram_get_peer(b,peer)'}
//           (TIdC_INT)BIO_ctrl(b, BIO_CTRL_DGRAM_GET_PEER, 0, (char (peer))
//  {$HPPEMIT '# define BIO_dgram_set_peer(b,peer)'}
//           (TIdC_INT)BIO_ctrl(b, BIO_CTRL_DGRAM_SET_PEER, 0, (char (peer))
//  {$HPPEMIT '# define BIO_dgram_get_mtu_overhead(b)'}
//           (Cardinal)BIO_ctrl((b), BIO_CTRL_DGRAM_GET_MTU_OVERHEAD, 0, 0)


  BIO_set_ex_data_procname = 'BIO_set_ex_data';
  BIO_get_ex_data_procname = 'BIO_get_ex_data';
  BIO_number_read_procname = 'BIO_number_read';
  BIO_number_written_procname = 'BIO_number_written';

  (* For BIO_f_asn1() *)
//  function BIO_asn1_set_prefix(b: PBIO; prefix: ^asn1_ps_func; prefix_free: ^asn1_ps_func): TIdC_INT;
//  function BIO_asn1_get_prefix(b: PBIO; pprefix: ^^asn1_ps_func; pprefix_free: ^^asn1_ps_func): TIdC_INT;
//  function BIO_asn1_set_suffix(b: PBIO; suffix: ^asn1_ps_func; suffix_free: ^asn1_ps_func): TIdC_INT;
//  function BIO_asn1_get_suffix(b: PBIO; psuffix: ^asn1_ps_func; psuffix_free: ^^asn1_ps_func): TIdC_INT;

  BIO_s_file_procname = 'BIO_s_file';
  BIO_new_file_procname = 'BIO_new_file';
//  function BIO_new_fp(stream: cFile; close_flag: TIdC_INT): PBIO;
  BIO_new_procname = 'BIO_new';
  BIO_free_procname = 'BIO_free';
  BIO_set_data_procname = 'BIO_set_data'; {introduced 1.1.0}
  BIO_get_data_procname = 'BIO_get_data'; {introduced 1.1.0}
  BIO_set_init_procname = 'BIO_set_init'; {introduced 1.1.0}
  BIO_get_init_procname = 'BIO_get_init'; {introduced 1.1.0}
  BIO_set_shutdown_procname = 'BIO_set_shutdown'; {introduced 1.1.0}
  BIO_get_shutdown_procname = 'BIO_get_shutdown'; {introduced 1.1.0}
  BIO_vfree_procname = 'BIO_vfree';
  BIO_up_ref_procname = 'BIO_up_ref'; {introduced 1.1.0}
  BIO_read_procname = 'BIO_read';
  BIO_read_ex_procname = 'BIO_read_ex'; {introduced 1.1.0}
  BIO_recvmmsg_procname = 'BIO_recvmmsg'; {introduced 3.2.0}
  BIO_gets_procname = 'BIO_gets';
  BIO_write_procname = 'BIO_write';
  BIO_write_ex_procname = 'BIO_write_ex'; {introduced 1.1.0}
  BIO_sendmmsg_procname = 'BIO_sendmmsg'; {introduced 3.2.0}
  BIO_get_rpoll_descriptor_procname = 'BIO_get_rpoll_descriptor'; {introduced 3.2.0}
  BIO_get_wpoll_descriptor_procname = 'BIO_get_wpoll_descriptor'; {introduced 3.2.0}
  BIO_puts_procname = 'BIO_puts';
  BIO_indent_procname = 'BIO_indent';
  BIO_ctrl_procname = 'BIO_ctrl';
  BIO_callback_ctrl_procname = 'BIO_callback_ctrl';
  BIO_ptr_ctrl_procname = 'BIO_ptr_ctrl';
  BIO_int_ctrl_procname = 'BIO_int_ctrl';
  BIO_push_procname = 'BIO_push';
  BIO_pop_procname = 'BIO_pop';
  BIO_free_all_procname = 'BIO_free_all';
  BIO_find_type_procname = 'BIO_find_type';
  BIO_next_procname = 'BIO_next';
  BIO_set_next_procname = 'BIO_set_next'; {introduced 1.1.0}
  BIO_get_retry_BIO_procname = 'BIO_get_retry_BIO';
  BIO_get_retry_reason_procname = 'BIO_get_retry_reason';
  BIO_set_retry_reason_procname = 'BIO_set_retry_reason'; {introduced 1.1.0}
  BIO_dup_chain_procname = 'BIO_dup_chain';

  BIO_nread0_procname = 'BIO_nread0';
  BIO_nread_procname = 'BIO_nread';
  BIO_nwrite0_procname = 'BIO_nwrite0';
  BIO_nwrite_procname = 'BIO_nwrite';

  BIO_debug_callback_procname = 'BIO_debug_callback';

  BIO_s_mem_procname = 'BIO_s_mem';
  BIO_s_secmem_procname = 'BIO_s_secmem'; {introduced 1.1.0}
  BIO_new_mem_buf_procname = 'BIO_new_mem_buf';

  BIO_s_socket_procname = 'BIO_s_socket';
  BIO_s_connect_procname = 'BIO_s_connect';
  BIO_s_accept_procname = 'BIO_s_accept';

  BIO_s_fd_procname = 'BIO_s_fd';
  BIO_s_log_procname = 'BIO_s_log';
  BIO_s_bio_procname = 'BIO_s_bio';
  BIO_s_null_procname = 'BIO_s_null';
  BIO_f_null_procname = 'BIO_f_null';
  BIO_f_buffer_procname = 'BIO_f_buffer';
  BIO_f_linebuffer_procname = 'BIO_f_linebuffer'; {introduced 1.1.0}
  BIO_f_nbio_test_procname = 'BIO_f_nbio_test';
  BIO_s_datagram_procname = 'BIO_s_datagram';
  BIO_dgram_non_fatal_error_procname = 'BIO_dgram_non_fatal_error';
  BIO_new_dgram_procname = 'BIO_new_dgram';

//  function BIO_s_datagram_sctp: PBIO_METHOD;
//  function BIO_new_dgram_sctp(fd: TIdC_INT; close_flag: TIdC_INT): PBIO;
//  function BIO_dgram_is_sctp(bio: PBIO): TIdC_INT;
//  function BIO_dgram_sctp_notification_cb(bio: PBIO; handle_notifications(PBIO;
//    context: Pointer;
//    buf: Pointer): TIdC_INT, Pointer context);
//  function BIO_dgram_sctp_wait_for_dry(b: PBIO): TIdC_INT;
//  function BIO_dgram_sctp_msg_waiting(b: PBIO): TIdC_INT;

  BIO_sock_should_retry_procname = 'BIO_sock_should_retry';
  BIO_sock_non_fatal_error_procname = 'BIO_sock_non_fatal_error';
  BIO_err_is_non_fatal_procname = 'BIO_err_is_non_fatal';

  BIO_fd_should_retry_procname = 'BIO_fd_should_retry';
  BIO_fd_non_fatal_error_procname = 'BIO_fd_non_fatal_error';
//  function BIO_dump_cb(
//    Pointer data: cb(;
//    len: TIdC_SIZET;
//    function: Pointer): u: TIdC_INT, Pointer function ,  PIdAnsiChar s, TIdC_INT len): u;
//  function BIO_dump_indent_cb(TIdC_INT (cb( Pointer data, TIdC_SIZET len, Pointer function ): u: TIdC_INT, Pointer function ,  PIdAnsiChar s, TIdC_INT len, TIdC_INT indent): u;
  BIO_dump_procname = 'BIO_dump';
  BIO_dump_indent_procname = 'BIO_dump_indent';

//  function BIO_dump_fp(fp: cFile; const s: PByte; len: TIdC_INT): TIdC_INT;
//  function BIO_dump_indent_fp(fp: cFile; const s: PByte; len: TIdC_INT; indent: TIdC_INT): TIdC_INT;

  BIO_hex_string_procname = 'BIO_hex_string';

  BIO_ADDR_new_procname = 'BIO_ADDR_new'; {introduced 1.1.0}
  BIO_ADDR_rawmake_procname = 'BIO_ADDR_rawmake'; {introduced 1.1.0}
  BIO_ADDR_free_procname = 'BIO_ADDR_free'; {introduced 1.1.0}
  BIO_ADDR_clear_procname = 'BIO_ADDR_clear'; {introduced 1.1.0}
  BIO_ADDR_family_procname = 'BIO_ADDR_family'; {introduced 1.1.0}
  BIO_ADDR_rawaddress_procname = 'BIO_ADDR_rawaddress'; {introduced 1.1.0}
  BIO_ADDR_rawport_procname = 'BIO_ADDR_rawport'; {introduced 1.1.0}
  BIO_ADDR_hostname_string_procname = 'BIO_ADDR_hostname_string'; {introduced 1.1.0}
  BIO_ADDR_service_string_procname = 'BIO_ADDR_service_string'; {introduced 1.1.0}
  BIO_ADDR_path_string_procname = 'BIO_ADDR_path_string'; {introduced 1.1.0}

  BIO_ADDRINFO_next_procname = 'BIO_ADDRINFO_next'; {introduced 1.1.0}
  BIO_ADDRINFO_family_procname = 'BIO_ADDRINFO_family'; {introduced 1.1.0}
  BIO_ADDRINFO_socktype_procname = 'BIO_ADDRINFO_socktype'; {introduced 1.1.0}
  BIO_ADDRINFO_protocol_procname = 'BIO_ADDRINFO_protocol'; {introduced 1.1.0}
  BIO_ADDRINFO_address_procname = 'BIO_ADDRINFO_address'; {introduced 1.1.0}
  BIO_ADDRINFO_free_procname = 'BIO_ADDRINFO_free'; {introduced 1.1.0}

  BIO_parse_hostserv_procname = 'BIO_parse_hostserv'; {introduced 1.1.0}

  BIO_lookup_procname = 'BIO_lookup'; {introduced 1.1.0}
  BIO_lookup_ex_procname = 'BIO_lookup_ex'; {introduced 1.1.0}
  BIO_sock_error_procname = 'BIO_sock_error';
  BIO_socket_ioctl_procname = 'BIO_socket_ioctl';
  BIO_socket_nbio_procname = 'BIO_socket_nbio';
  BIO_sock_init_procname = 'BIO_sock_init';

  BIO_set_tcp_ndelay_procname = 'BIO_set_tcp_ndelay';

  BIO_sock_info_procname = 'BIO_sock_info'; {introduced 1.1.0}

  BIO_socket_procname = 'BIO_socket'; {introduced 1.1.0}
  BIO_connect_procname = 'BIO_connect'; {introduced 1.1.0}
  BIO_bind_procname = 'BIO_bind'; {introduced 1.1.0}
  BIO_listen_procname = 'BIO_listen'; {introduced 1.1.0}
  BIO_accept_ex_procname = 'BIO_accept_ex'; {introduced 1.1.0}
  BIO_closesocket_procname = 'BIO_closesocket'; {introduced 1.1.0}

  BIO_new_socket_procname = 'BIO_new_socket';
  BIO_new_connect_procname = 'BIO_new_connect';
  BIO_new_accept_procname = 'BIO_new_accept';

  BIO_new_fd_procname = 'BIO_new_fd';

  BIO_new_bio_pair_procname = 'BIO_new_bio_pair';
  (*
   * If successful, returns 1 and in *bio1, *bio2 two BIO pair endpoints.
   * Otherwise returns 0 and sets *bio1 and *bio2 to NULL. Size 0 uses default
   * value.
   *)

  BIO_copy_next_retry_procname = 'BIO_copy_next_retry';

//  BIO_METHOD *BIO_meth_new(int type, const char *name);
//  void BIO_meth_free(BIO_METHOD *biom);
//  int (*BIO_meth_get_write(const BIO_METHOD *biom)) (BIO *, const char *, int);
//  int (*BIO_meth_get_write_ex(const BIO_METHOD *biom)) (BIO *, const char *, TIdC_SIZET,
//                                                  TIdC_SIZET *);
//  int BIO_meth_set_write(BIO_METHOD *biom,
//                         int (*write) (BIO *, const char *, int));
//  int BIO_meth_set_write_ex(BIO_METHOD *biom,
//                         int (*bwrite) (BIO *, const char *, TIdC_SIZET, TIdC_SIZET *));
//  int (*BIO_meth_get_read(const BIO_METHOD *biom)) (BIO *, char *, int);
//  int (*BIO_meth_get_read_ex(const BIO_METHOD *biom)) (BIO *, char *, TIdC_SIZET, TIdC_SIZET *);
//  int BIO_meth_set_read(BIO_METHOD *biom,
//                        int (*read) (BIO *, char *, int));
//  int BIO_meth_set_read_ex(BIO_METHOD *biom,
//                           int (*bread) (BIO *, char *, TIdC_SIZET, TIdC_SIZET *));
//  int (*BIO_meth_get_puts(const BIO_METHOD *biom)) (BIO *, const char *);
//  int BIO_meth_set_puts(BIO_METHOD *biom,
//                        int (*puts) (BIO *, const char *));
//  int (*BIO_meth_get_gets(const BIO_METHOD *biom)) (BIO *, char *, int);
//  int BIO_meth_set_gets(BIO_METHOD *biom,
//                        int (*gets) (BIO *, char *, int));
//  long (*BIO_meth_get_ctrl(const BIO_METHOD *biom)) (BIO *, int, long, void *);
//  int BIO_meth_set_ctrl(BIO_METHOD *biom,
//                        long (*ctrl) (BIO *, int, long, void *));
//  int (*BIO_meth_get_create(const BIO_METHOD *bion)) (BIO *);
//  int BIO_meth_set_create(BIO_METHOD *biom, int (*create) (BIO *));
//  int (*BIO_meth_get_destroy(const BIO_METHOD *biom)) (BIO *);
//  int BIO_meth_set_destroy(BIO_METHOD *biom, int (*destroy) (BIO *));
//  long (*BIO_meth_get_callback_ctrl(const BIO_METHOD *biom))
//                                   (BIO *, int, BIO_info_cb *);
//  int BIO_meth_set_callback_ctrl(BIO_METHOD *biom,
//                                 long (*callback_ctrl) (BIO *, int,
//                                                        BIO_info_cb *));


// # define BIO_get_flags(b) BIO_test_flags(b, ~(0x0))
function  _BIO_get_flags(const b: PBIO): TIdC_INT; cdecl;
begin
  Result := BIO_test_flags(b, not $0);
end;

//# define BIO_set_retry_special(b) \
//                BIO_set_flags(b, (BIO_FLAGS_IO_SPECIAL|BIO_FLAGS_SHOULD_RETRY))
procedure  _BIO_set_retry_special(b: PBIO); cdecl;
begin
  BIO_set_flags(b, BIO_FLAGS_IO_SPECIAL or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_set_retry_read(b) \
//                BIO_set_flags(b, (BIO_FLAGS_READ|BIO_FLAGS_SHOULD_RETRY))
procedure  _BIO_set_retry_read(b: PBIO); cdecl;
begin
  BIO_set_flags(b, BIO_FLAGS_READ or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_set_retry_write(b) \
//                BIO_set_flags(b, (BIO_FLAGS_WRITE|BIO_FLAGS_SHOULD_RETRY))
procedure  _BIO_set_retry_write(b: PBIO); cdecl;
begin
  BIO_set_flags(b, BIO_FLAGS_WRITE or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_clear_retry_flags(b) \
//                BIO_clear_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))
procedure  _BIO_clear_retry_flags(b: PBIO); cdecl;
begin
  BIO_clear_flags(b, BIO_FLAGS_RWS or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_get_retry_flags(b) \
//                BIO_test_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))
function  _BIO_get_retry_flags(b: PBIO): TIdC_INT; cdecl;
begin
  Result := BIO_test_flags(b, BIO_FLAGS_RWS or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_should_read(a)              BIO_test_flags(a, BIO_FLAGS_READ)
function  _BIO_should_read(b: PBIO): TIdC_INT; cdecl;
begin
  Result := BIO_test_flags(b, BIO_FLAGS_READ);
end;

//# define BIO_should_write(a)             BIO_test_flags(a, BIO_FLAGS_WRITE)
function  _BIO_should_write(b: PBIO): TIdC_INT; cdecl;
begin
  Result := BIO_test_flags(b, BIO_FLAGS_WRITE);
end;

//# define BIO_should_io_special(a)        BIO_test_flags(a, BIO_FLAGS_IO_SPECIAL)
function  _BIO_should_io_special(b: PBIO): TIdC_INT; cdecl;
begin
  Result := BIO_test_flags(b, BIO_FLAGS_IO_SPECIAL);
end;

//# define BIO_retry_type(a)               BIO_test_flags(a, BIO_FLAGS_RWS)
function  _BIO_retry_type(b: PBIO): TIdC_INT; cdecl;
begin
  Result := BIO_test_flags(b, BIO_FLAGS_RWS);
end;

//# define BIO_should_retry(a)             BIO_test_flags(a, BIO_FLAGS_SHOULD_RETRY)
function  _BIO_should_retry(b: PBIO): TIdC_INT; cdecl;
begin
  Result := BIO_test_flags(b, BIO_FLAGS_SHOULD_RETRY);
end;

//#  define BIO_do_connect(b)       BIO_do_handshake(b)
function  _BIO_do_connect(b: PBIO): TIdC_LONG; cdecl;
begin
  Result := BIO_do_handshake(b);
end;

//#  define BIO_do_accept(b)        BIO_do_handshake(b)
function  _BIO_do_accept(b: PBIO): TIdC_LONG; cdecl;
begin
  Result := BIO_do_handshake(b);
end;

//# define BIO_do_handshake(b)     BIO_ctrl(b,BIO_C_DO_STATE_MACHINE,0,NULL)
function  _BIO_do_handshake(b: PBIO): TIdC_LONG; cdecl;
begin
  Result := BIO_ctrl(b, BIO_C_DO_STATE_MACHINE, 0, nil);
end;

// WAS DECLARED AS:
// function  _BIO_get_mem_data(b: PBIO; pp: Pointer) : TIdC_INT; cdecl;
//# define BIO_get_mem_data(b,pp)  BIO_ctrl(b,BIO_CTRL_INFO,0,(char (pp))
function  _BIO_get_mem_data(b: PBIO; out pp: Pointer) : TIdC_INT; cdecl;
begin
  Result := BIO_ctrl(b, BIO_CTRL_INFO, 0, @pp);
end;

//# define BIO_set_mem_buf(b,bm,c) BIO_ctrl(b,BIO_C_SET_BUF_MEM,c,(char (bm))
function  _BIO_set_mem_buf(b: PBIO; bm: PBUF_MEM; c: TIdC_INT): TIdC_INT; cdecl;
begin
  Result := BIO_ctrl(b, BIO_C_SET_BUF_MEM, c, bm);
end;

// WAS DECLARED AS:
// function  _BIO_get_mem_ptr(b: PBIO; pp: Pointer): TIdC_INT; cdecl;
//# define BIO_get_mem_ptr(b,pp)   BIO_ctrl(b,BIO_C_GET_BUF_MEM_PTR,0,(char (pp))
function  _BIO_get_mem_ptr(b: PBIO; out pp: PBUF_MEM): TIdC_INT; cdecl;
begin
  Result := BIO_ctrl(b, BIO_C_GET_BUF_MEM_PTR, 0, @pp);
end;

//# define BIO_set_mem_eof_return(b,v) BIO_ctrl(b,BIO_C_SET_BUF_MEM_EOF_RETURN,v,0)
function  _BIO_set_mem_eof_return(b: PBIO; v: TIdC_INT): TIdC_INT; cdecl;
begin
  Result := BIO_ctrl(b, BIO_C_SET_BUF_MEM_EOF_RETURN, v, nil);
end;

  {$I TaurusTLSNoRetValOff.inc} 
function  ERR_BIO_get_flags(const b: PBIO): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_flags_procname);
end;


procedure  ERR_BIO_set_retry_special(b: PBIO); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_retry_special_procname);
end;


procedure  ERR_BIO_set_retry_read(b: PBIO); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_retry_read_procname);
end;


procedure  ERR_BIO_set_retry_write(b: PBIO); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_retry_write_procname);
end;



(* These are normally used internally in BIOs *)
procedure  ERR_BIO_clear_retry_flags(b: PBIO); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_clear_retry_flags_procname);
end;


function  ERR_BIO_get_retry_flags(b: PBIO): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_retry_flags_procname);
end;



(* These should be used by the application to tell why we should retry *)
function  ERR_BIO_should_read(b: PBIO): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_should_read_procname);
end;


function  ERR_BIO_should_write(b: PBIO): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_should_write_procname);
end;


function  ERR_BIO_should_io_special(b: PBIO): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_should_io_special_procname);
end;


function  ERR_BIO_retry_type(b: PBIO): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_retry_type_procname);
end;

 
function  ERR_BIO_should_retry(b: PBIO): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_should_retry_procname);
end;



(* BIO_s_accept() and BIO_s_connect() *)
function  ERR_BIO_do_connect(b: PBIO): TIdC_LONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_do_connect_procname);
end;


function  ERR_BIO_do_accept(b: PBIO): TIdC_LONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_do_accept_procname);
end;


function  ERR_BIO_do_handshake(b: PBIO): TIdC_LONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_do_handshake_procname);
end;



// WAS DECLARED AS:
// function  ERR_BIO_get_mem_data(b: PBIO; pp: Pointer) : TIdC_INT;
function  ERR_BIO_get_mem_data(b: PBIO; out pp: Pointer) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_mem_data_procname);
end;


function  ERR_BIO_set_mem_buf(b: PBIO; bm: PBUF_MEM; c: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_mem_buf_procname);
end;


// WAS DECLARED AS:
// function  ERR_BIO_get_mem_ptr(b: PBIO; pp: Pointer): TIdC_INT;
function  ERR_BIO_get_mem_ptr(b: PBIO; out pp: PBUF_MEM): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_mem_ptr_procname);
end;


function  ERR_BIO_set_mem_eof_return(b: PBIO; v: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_mem_eof_return_procname);
end;



function  ERR_BIO_get_new_index: TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_new_index_procname);
end;

 {introduced 1.1.0}
procedure  ERR_BIO_set_flags(b: PBIO; flags: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_flags_procname);
end;


function  ERR_BIO_test_flags(const b: PBIO; flags: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_test_flags_procname);
end;


procedure  ERR_BIO_clear_flags(b: PBIO; flags: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_clear_flags_procname);
end;



function  ERR_BIO_get_callback(b: PBIO): BIO_callback_fn; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_callback_procname);
end;


procedure  ERR_BIO_set_callback(b: PBIO; callback: BIO_callback_fn); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_callback_procname);
end;



function  ERR_BIO_get_callback_ex(b: PBIO): BIO_callback_fn_ex; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_callback_ex_procname);
end;

 {introduced 1.1.0}
procedure  ERR_BIO_set_callback_ex(b: PBIO; callback: BIO_callback_fn_ex); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_callback_ex_procname);
end;

 {introduced 1.1.0}

function  ERR_BIO_get_callback_arg(const b: PBIO): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_callback_arg_procname);
end;


procedure  ERR_BIO_set_callback_arg(var b: PBIO; arg: PIdAnsiChar); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_callback_arg_procname);
end;



function  ERR_BIO_method_name(const b: PBIO): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_method_name_procname);
end;


function  ERR_BIO_method_type(const b: PBIO): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_method_type_procname);
end;



//  {$HPPEMIT '# define BIO_set_app_data(s,arg)         BIO_set_ex_data(s,0,arg)'}
//  {$HPPEMIT '# define BIO_get_app_data(s)             BIO_get_ex_data(s,0)'}
//
//  {$HPPEMIT '# define BIO_set_nbio(b,n)             BIO_ctrl(b,BIO_C_SET_NBIO,(n),NULL)'}
//
//  {$HPPEMIT '# ifndef OPENSSL_NO_SOCK'}
//  (* IP families we support, for BIO_s_connect() and BIO_s_accept() *)
//  (* Note: the underlying operating system may not support some of them *)
//  {$HPPEMIT '#  define BIO_FAMILY_IPV4                         4'}
//  {$HPPEMIT '#  define BIO_FAMILY_IPV6                         6'}
//  {$HPPEMIT '#  define BIO_FAMILY_IPANY                        256'}
//
//  (* BIO_s_connect() *)
//  {$HPPEMIT '#  define BIO_set_conn_hostname(b,name) BIO_ctrl(b,BIO_C_SET_CONNECT,0,'}
//                                                   (char (name))
//  {$HPPEMIT '#  define BIO_set_conn_port(b,port)     BIO_ctrl(b,BIO_C_SET_CONNECT,1,'}
//                                                   (char (port))
//  {$HPPEMIT '#  define BIO_set_conn_address(b,addr)  BIO_ctrl(b,BIO_C_SET_CONNECT,2,'}
//                                                   (char (addr))
//  {$HPPEMIT '#  define BIO_set_conn_ip_family(b,f)   BIO_int_ctrl(b,BIO_C_SET_CONNECT,3,f)'}
//  {$HPPEMIT '#  define BIO_get_conn_hostname(b)      (( char )BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,0))'}
//  {$HPPEMIT '#  define BIO_get_conn_port(b)          (( char )BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,1))'}
//  {$HPPEMIT '#  define BIO_get_conn_address(b)       (( PBIO_ADDR )BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,2))'}
//  {$HPPEMIT '#  define BIO_get_conn_ip_family(b)     BIO_ctrl(b,BIO_C_GET_CONNECT,3,NULL)'}
//  {$HPPEMIT '#  define BIO_set_conn_mode(b,n)        BIO_ctrl(b,BIO_C_SET_CONNECT_MODE,(n),NULL)'}
//
//  (* BIO_s_accept() *)
//  {$HPPEMIT '#  define BIO_set_accept_name(b,name)   BIO_ctrl(b,BIO_C_SET_ACCEPT,0,'}
//  {$EXTERNALSYM PBIO}
//                                                   (char (name))
//  {$HPPEMIT '#  define BIO_set_accept_port(b,port)   BIO_ctrl(b,BIO_C_SET_ACCEPT,1,'}
//                                                   (char (port))
//  {$HPPEMIT '#  define BIO_get_accept_name(b)        (( char )BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,0))'}
//  {$HPPEMIT '#  define BIO_get_accept_port(b)        (( char )BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,1))'}
//  {$HPPEMIT '#  define BIO_get_peer_name(b)          (( char )BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,2))'}
//  {$HPPEMIT '#  define BIO_get_peer_port(b)          (( char )BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,3))'}
//  (* #define BIO_set_nbio(b,n)    BIO_ctrl(b,BIO_C_SET_NBIO,(n),NULL) *)
//  {$HPPEMIT '#  define BIO_set_nbio_accept(b,n)      #  define BIO_set_nbio_accept(b,n)      BIO_ctrl(b,BIO_C_SET_ACCEPT,2,(n)?(procedure )'a':NULL)  BIO_ctrl(b,BIO_C_SET_ACCEPT,3,'}
//                                                   (char (bio))
//  {$HPPEMIT '#  define BIO_set_accept_ip_family(b,f) BIO_int_ctrl(b,BIO_C_SET_ACCEPT,4,f)'}
//  {$HPPEMIT '#  define BIO_get_accept_ip_family(b)   BIO_ctrl(b,BIO_C_GET_ACCEPT,4,NULL)'}
//
//  (* Aliases kept for backward compatibility *)
//  {$HPPEMIT '#  define BIO_BIND_NORMAL                 0'}
//  {$HPPEMIT '#  define BIO_BIND_REUSEADDR              BIO_SOCK_REUSEADDR'}
//  {$HPPEMIT '#  define BIO_BIND_REUSEADDR_IF_UNUSED    BIO_SOCK_REUSEADDR'}
//  {$HPPEMIT '#  define BIO_set_bind_mode(b,mode) BIO_ctrl(b,BIO_C_SET_BIND_MODE,mode,NULL)'}
//  {$HPPEMIT '#  define BIO_get_bind_mode(b)    BIO_ctrl(b,BIO_C_GET_BIND_MODE,0,NULL)'}
//
//  (* BIO_s_accept() and BIO_s_connect() *)
//  {$HPPEMIT '#  define BIO_do_connect(b)       BIO_do_handshake(b)'}
//  {$HPPEMIT '#  define BIO_do_accept(b)        BIO_do_handshake(b)'}
//  {$HPPEMIT '# endif'}	(* OPENSSL_NO_SOCK *)
//
//  {$HPPEMIT '# define BIO_do_handshake(b)     BIO_ctrl(b,BIO_C_DO_STATE_MACHINE,0,NULL)'}
//
//  (* BIO_s_datagram(), BIO_s_fd(), BIO_s_socket(), BIO_s_accept() and BIO_s_connect() *)
//  {$HPPEMIT '# define BIO_set_fd(b,fd,c)      BIO_int_ctrl(b,BIO_C_SET_FD,c,fd)'}
//  {$HPPEMIT '# define BIO_get_fd(b,c)         BIO_ctrl(b,BIO_C_GET_FD,0,(char (c))'}
//
//  (* BIO_s_file() *)
//  {$HPPEMIT '# define BIO_set_fp(b,fp,c)      BIO_ctrl(b,BIO_C_SET_FILE_PTR,c,(char (fp))'}
//  {$HPPEMIT '# define BIO_get_fp(b,fpp)       BIO_ctrl(b,BIO_C_GET_FILE_PTR,0,(char (fpp))'}
//
//  (* BIO_s_fd() and BIO_s_file() *)
//  {$HPPEMIT '# define BIO_seek(b,ofs(int)BIO_ctrl(b,BIO_C_FILE_SEEK,ofs,NULL)'}
//  {$HPPEMIT '# define BIO_tell(b)     (int)BIO_ctrl(b,BIO_C_FILE_TELL,0,NULL)'}
//
//  (*
//   * name is cast to lose , but might be better to route through a
//   * cFunction so we can do it safely
//   *)
//  {$HPPEMIT '# ifdef CONST_STRICT'}
//  (*
//   * If you are wondering why this isn't defined, its because CONST_STRICT is
//   * purely a compile-time kludge to allow  to be checked.
//   *)
////  function BIO_read_filename(b: PBIO; const name: PIdAnsiChar): TIdC_INT;
//  {$HPPEMIT '# define BIO_write_filename(b,name(int)BIO_ctrl(b,BIO_C_SET_FILENAME,'}
//                  BIO_CLOSE or BIO_FP_WRITE,name)
//  {$HPPEMIT '# define BIO_append_filename(b,name(int)BIO_ctrl(b,BIO_C_SET_FILENAME,'}
//                  BIO_CLOSE or BIO_FP_APPEND,name)
//  {$HPPEMIT '# define BIO_rw_filename(b,name(int)BIO_ctrl(b,BIO_C_SET_FILENAME,'}
//                  BIO_CLOSE or BIO_FP_READ or BIO_FP_WRITE,name)
//
//  (*
//   * WARNING WARNING, this ups the reference count on the read bio of the SSL
//   * structure.  This is because the ssl read PBIO is now pointed to by the
//   * next_bio field in the bio.  So when you free the PBIO, make sure you are
//   * doing a BIO_free_all() to catch the underlying PBIO.
//   *)
//  {$HPPEMIT '# define BIO_set_ssl(b,ssl,c)    BIO_ctrl(b,BIO_C_SET_SSL,c,(char (ssl))'}
//  {$HPPEMIT '# define BIO_get_ssl(b,sslp)     BIO_ctrl(b,BIO_C_GET_SSL,0,(char (sslp))'}
//  {$HPPEMIT '# define BIO_set_ssl_mode(b,client)      BIO_ctrl(b,BIO_C_SSL_MODE,client,NULL)'}
//  {$HPPEMIT '# define BIO_set_ssl_renegotiate_bytes(b,num)'}
//          BIO_ctrl(b,BIO_C_SET_SSL_RENEGOTIATE_BYTES,num,0)
//  {$HPPEMIT '# define BIO_get_num_renegotiates(b)'}
//          BIO_ctrl(b,BIO_C_GET_SSL_NUM_RENEGOTIATES,0,0)
//  {$HPPEMIT '# define BIO_set_ssl_renegotiate_timeout(b,seconds)'}
//          BIO_ctrl(b,BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT,seconds,0)
//
//  (* defined in evp.h *)
//  (* #define BIO_set_md(b,md)     BIO_ctrl(b,BIO_C_SET_MD,1,(char )(md)) *)
//
//  (* For the BIO_f_buffer() type *)
//  {$HPPEMIT '# define BIO_get_buffer_num_lines(b)     BIO_ctrl(b,BIO_C_GET_BUFF_NUM_LINES,0,NULL)'}
//  {$HPPEMIT '# define BIO_set_buffer_size(b,size)     BIO_ctrl(b,BIO_C_SET_BUFF_SIZE,size,NULL)'}
//  {$HPPEMIT '# define BIO_set_read_buffer_size(b,size) BIO_int_ctrl(b,BIO_C_SET_BUFF_SIZE,size,0)'}
//  {$HPPEMIT '# define BIO_set_write_buffer_size(b,size) BIO_int_ctrl(b,BIO_C_SET_BUFF_SIZE,size,1)'}
//  {$HPPEMIT '# define BIO_set_buffer_read_data(b,buf,num) BIO_ctrl(b,BIO_C_SET_BUFF_READ_DATA,num,buf)'}
//
//  (* Don't use the next one unless you know what you are doing :-) */
//  {$HPPEMIT '# define BIO_dup_state(b,ret)    BIO_ctrl(b,BIO_CTRL_DUP,0,(char (ret))'}
//
//  {$HPPEMIT '# define BIO_reset(b)            (int)BIO_ctrl(b,BIO_CTRL_RESET,0,NULL)'}
//  {$HPPEMIT '# define BIO_eof(b)              (int)BIO_ctrl(b,BIO_CTRL_EOF,0,NULL)'}
//  {$HPPEMIT '# define BIO_set_close(b,c)      (int)BIO_ctrl(b,BIO_CTRL_SET_CLOSE,(c),NULL)'}
//  {$HPPEMIT '# define BIO_get_close(b)        (int)BIO_ctrl(b,BIO_CTRL_GET_CLOSE,0,NULL)'}
//  {$HPPEMIT '# define BIO_pending(b)          (int)BIO_ctrl(b,BIO_CTRL_PENDING,0,NULL)'}
//  {$HPPEMIT '# define BIO_wpending(b)         (int)BIO_ctrl(b,BIO_CTRL_WPENDING,0,NULL)'}
  (* ...pending macros have inappropriate return type *)
function  ERR_BIO_ctrl_pending(b: PBIO): TIdC_SIZET; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ctrl_pending_procname);
end;


function  ERR_BIO_ctrl_wpending(b: PBIO): TIdC_SIZET; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ctrl_wpending_procname);
end;


//  {$HPPEMIT '# define BIO_flush(b)            (int)BIO_ctrl(b,BIO_CTRL_FLUSH,0,NULL)'}
//  {$HPPEMIT '# define BIO_get_info_callback(b,cbp(int)BIO_ctrl(b,BIO_CTRL_GET_CALLBACK,0,'}
//                                                     cbp)
//  {$HPPEMIT '# define BIO_set_info_callback(b,cb(int)BIO_callback_ctrl(b,BIO_CTRL_SET_CALLBACK,cb)'}
//
//  (* For the BIO_f_buffer() type *)
//  {$HPPEMIT '# define BIO_buffer_get_num_lines(b) BIO_ctrl(b,BIO_CTRL_GET,0,NULL)'}
//  {$HPPEMIT '# define BIO_buffer_peek(b,s,l) BIO_ctrl(b,BIO_CTRL_PEEK,(l),(s))'}
//
//  (* For BIO_s_bio() *)
//  {$HPPEMIT '# define BIO_set_write_buf_size(b,size(int)BIO_ctrl(b,BIO_C_SET_WRITE_BUF_SIZE,size,NULL)'}
//  {$HPPEMIT '# define BIO_get_write_buf_size(b,size(TIdC_SIZET)BIO_ctrl(b,BIO_C_GET_WRITE_BUF_SIZE,size,NULL)'}
//  {$HPPEMIT '# define BIO_make_bio_pair(b1,b2)   (int)BIO_ctrl(b1,BIO_C_MAKE_BIO_PAIR,0,b2)'}
//  {$HPPEMIT '# define BIO_destroy_bio_pair(b)    (int)BIO_ctrl(b,BIO_C_DESTROY_BIO_PAIR,0,NULL)'}
//  {$HPPEMIT '# define BIO_shutdown_wr(b(int)BIO_ctrl(b, BIO_C_SHUTDOWN_WR, 0, NULL)'}
//  (* macros with inappropriate type -- but ...pending macros use int too: *)
//  {$HPPEMIT '# define BIO_get_write_guarantee(b(int)BIO_ctrl(b,BIO_C_GET_WRITE_GUARANTEE,0,NULL)'}
//  {$HPPEMIT '# define BIO_get_read_request(b)    (int)BIO_ctrl(b,BIO_C_GET_READ_REQUEST,0,NULL)'}
function  ERR_BIO_ctrl_get_write_guarantee(b: PBIO): TIdC_SIZET; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ctrl_get_write_guarantee_procname);
end;


function  ERR_BIO_ctrl_get_read_request(b: PBIO): TIdC_SIZET; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ctrl_get_read_request_procname);
end;


function  ERR_BIO_ctrl_reset_read_request(b: PBIO): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ctrl_reset_read_request_procname);
end;



  (* ctrl macros for dgram *)
//  {$HPPEMIT '# define BIO_ctrl_dgram_connect(b,peer)'}
//                       (TIdC_INT)BIO_ctrl(b,BIO_CTRL_DGRAM_CONNECT,0, (char (peer))
//  {$HPPEMIT '# define BIO_ctrl_set_connected(b,peer)'}
//           (TIdC_INT)BIO_ctrl(b, BIO_CTRL_DGRAM_SET_CONNECTED, 0, (char (peer))
//  {$HPPEMIT '# define BIO_dgram_recv_timedout(b)'}
//           (TIdC_INT)BIO_ctrl(b, BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, 0)
//  {$HPPEMIT '# define BIO_dgram_send_timedout(b)'}
//           (TIdC_INT)BIO_ctrl(b, BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP, 0, 0)
//  {$HPPEMIT '# define BIO_dgram_get_peer(b,peer)'}
//           (TIdC_INT)BIO_ctrl(b, BIO_CTRL_DGRAM_GET_PEER, 0, (char (peer))
//  {$HPPEMIT '# define BIO_dgram_set_peer(b,peer)'}
//           (TIdC_INT)BIO_ctrl(b, BIO_CTRL_DGRAM_SET_PEER, 0, (char (peer))
//  {$HPPEMIT '# define BIO_dgram_get_mtu_overhead(b)'}
//           (Cardinal)BIO_ctrl((b), BIO_CTRL_DGRAM_GET_MTU_OVERHEAD, 0, 0)

//#define BIO_get_ex_new_index(l, p, newf, dupf, freef) \
//    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_BIO, l, p, newf, dupf, freef)

function  ERR_BIO_set_ex_data(bio: PBIO; idx: TIdC_INT; data: Pointer): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_ex_data_procname);
end;


function  ERR_BIO_get_ex_data(bio: PBIO; idx: TIdC_INT): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_ex_data_procname);
end;


function  ERR_BIO_number_read(bio: PBIO): TIdC_UINT64; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_number_read_procname);
end;


function  ERR_BIO_number_written(bio: PBIO): TIdC_UINT64; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_number_written_procname);
end;



  (* For BIO_f_asn1() *)
//  function BIO_asn1_set_prefix(b: PBIO; prefix: ^asn1_ps_func; prefix_free: ^asn1_ps_func): TIdC_INT;
//  function BIO_asn1_get_prefix(b: PBIO; pprefix: ^^asn1_ps_func; pprefix_free: ^^asn1_ps_func): TIdC_INT;
//  function BIO_asn1_set_suffix(b: PBIO; suffix: ^asn1_ps_func; suffix_free: ^asn1_ps_func): TIdC_INT;
//  function BIO_asn1_get_suffix(b: PBIO; psuffix: ^asn1_ps_func; psuffix_free: ^^asn1_ps_func): TIdC_INT;

function  ERR_BIO_s_file: PBIO_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_s_file_procname);
end;


function  ERR_BIO_new_file(const filename: PIdAnsiChar; const mode: PIdAnsiChar): PBIO; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_new_file_procname);
end;


//  function BIO_new_fp(stream: cFile; close_flag: TIdC_INT): PBIO;
function  ERR_BIO_new(const cType: PBIO_METHOD): PBIO; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_new_procname);
end;


function  ERR_BIO_free(a: PBIO): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_free_procname);
end;


procedure  ERR_BIO_set_data(a: PBIO; _ptr: Pointer); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_data_procname);
end;

 {introduced 1.1.0}
function  ERR_BIO_get_data(a: PBIO): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_data_procname);
end;

 {introduced 1.1.0}
procedure  ERR_BIO_set_init(a: PBIO; init: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_init_procname);
end;

 {introduced 1.1.0}
function  ERR_BIO_get_init(a: PBIO): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_init_procname);
end;

 {introduced 1.1.0}
procedure  ERR_BIO_set_shutdown(a: PBIO; shut: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_shutdown_procname);
end;

 {introduced 1.1.0}
function  ERR_BIO_get_shutdown(a: PBIO): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_shutdown_procname);
end;

 {introduced 1.1.0}
procedure  ERR_BIO_vfree(a: PBIO); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_vfree_procname);
end;


function  ERR_BIO_up_ref(a: PBIO): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_up_ref_procname);
end;

 {introduced 1.1.0}
function  ERR_BIO_read(b: PBIO; var data; dlen: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_read_procname);
end;


function  ERR_BIO_read_ex(b: PBIO; var data; dlen: TIdC_SIZET; out readbytes: TIdC_SIZET): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_read_ex_procname);
end;

 {introduced 3.2.0}
function ERR_BIO_recvmmsg(b : PBIO; msg : PBIO_MSG;
    stride, num_msg : TIdC_SIZET; flags : TIdC_UINT64;
    msgs_processed : PIdC_SIZET): TIdC_INT; cdecl;
begin
   ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_recvmmsg_procname);
end;

 {introduced 1.1.0}
function  ERR_BIO_gets( bp: PBIO; buf: PIdAnsiChar; size: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_gets_procname);
end;


function  ERR_BIO_write(b: PBIO; const data; dlen: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_write_procname);
end;


function  ERR_BIO_write_ex(b: PBIO; const data; dlen: TIdC_SIZET; out written: TIdC_SIZET): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_write_ex_procname);
end;

 {introduced 3.2.0}
function ERR_BIO_sendmmsg(b0 : PBIO; msg : PBIO_MSG;
    stride, num_msg : TIdC_SIZET; flags : TIdC_UINT64;
    msgs_processed : PIdC_SIZET) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_sendmmsg_procname);
end;

function ERR_BIO_get_rpoll_descriptor(b : PBIO; desc : PBIO_POLL_DESCRIPTOR)  : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_rpoll_descriptor_procname);
end;

function ERR_BIO_get_wpoll_descriptor(b : PBIO; desc : PBIO_POLL_DESCRIPTOR) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_wpoll_descriptor_procname);
end;

 {introduced 1.1.0}
function  ERR_BIO_puts(bp: PBIO; const buf: PIdAnsiChar): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_puts_procname);
end;


function  ERR_BIO_indent(b: PBIO; indent: TIdC_INT; max: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_indent_procname);
end;


function  ERR_BIO_ctrl(bp: PBIO; cmd: TIdC_INT; larg: TIdC_LONG; parg: Pointer): TIdC_LONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ctrl_procname);
end;


function  ERR_BIO_callback_ctrl(b: PBIO; cmd: TIdC_INT; fp: PBIO_info_cb): TIdC_LONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_callback_ctrl_procname);
end;


function  ERR_BIO_ptr_ctrl(bp: PBIO; cmd: TIdC_INT; larg: TIdC_LONG): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ptr_ctrl_procname);
end;


function  ERR_BIO_int_ctrl(bp: PBIO; cmd: TIdC_INT; larg: TIdC_LONG; iarg: TIdC_INT): TIdC_LONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_int_ctrl_procname);
end;


function  ERR_BIO_push(b: PBIO; _append: PBIO): PBIO; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_push_procname);
end;


function  ERR_BIO_pop(b: PBIO): PBIO; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_pop_procname);
end;


procedure  ERR_BIO_free_all(a: PBIO); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_free_all_procname);
end;


function  ERR_BIO_find_type(b: PBIO; bio_type: TIdC_INT): PBIO; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_find_type_procname);
end;


function  ERR_BIO_next(b: PBIO): PBIO; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_next_procname);
end;


procedure  ERR_BIO_set_next(b: PBIO; next: PBIO); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_next_procname);
end;

 {introduced 1.1.0}
function  ERR_BIO_get_retry_BIO(bio: PBIO; reason: TIdC_INT): PBIO; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_retry_BIO_procname);
end;


function  ERR_BIO_get_retry_reason(bio: PBIO): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_get_retry_reason_procname);
end;


procedure  ERR_BIO_set_retry_reason(bio: PBIO; reason: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_retry_reason_procname);
end;

 {introduced 1.1.0}
function  ERR_BIO_dup_chain(in_: PBIO): PBIO; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_dup_chain_procname);
end;



function  ERR_BIO_nread0(bio: PBIO; buf: PPIdAnsiChar): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_nread0_procname);
end;


function  ERR_BIO_nread(bio: PBIO; buf: PPIdAnsiChar; num: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_nread_procname);
end;


function  ERR_BIO_nwrite0(bio: PBIO; buf: PPIdAnsiChar): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_nwrite0_procname);
end;


function  ERR_BIO_nwrite(bio: PBIO; buf: PPIdAnsiChar; num: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_nwrite_procname);
end;



function  ERR_BIO_debug_callback(bio: PBIO; cmd: TIdC_INT; const argp: PIdAnsiChar;
  argi: TIdC_INT; argl: TIdC_LONG; ret: TIdC_LONG): TIdC_LONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_debug_callback_procname);
end;



function  ERR_BIO_s_mem: PBIO_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_s_mem_procname);
end;


function  ERR_BIO_s_secmem: PBIO_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_s_secmem_procname);
end;

 {introduced 1.1.0}
function  ERR_BIO_new_mem_buf(const buf; len: TIdC_INT): PBIO; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_new_mem_buf_procname);
end;



function  ERR_BIO_s_socket: PBIO_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_s_socket_procname);
end;


function  ERR_BIO_s_connect: PBIO_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_s_connect_procname);
end;


function  ERR_BIO_s_accept: PBIO_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_s_accept_procname);
end;



function  ERR_BIO_s_fd: PBIO_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_s_fd_procname);
end;


function  ERR_BIO_s_log: PBIO_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_s_log_procname);
end;


function  ERR_BIO_s_bio: PBIO_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_s_bio_procname);
end;


function  ERR_BIO_s_null: PBIO_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_s_null_procname);
end;


function  ERR_BIO_f_null: PBIO_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_f_null_procname);
end;


function  ERR_BIO_f_buffer: PBIO_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_f_buffer_procname);
end;


function  ERR_BIO_f_linebuffer: PBIO_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_f_linebuffer_procname);
end;

 {introduced 1.1.0}
function  ERR_BIO_f_nbio_test: PBIO_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_f_nbio_test_procname);
end;


function  ERR_BIO_s_datagram: PBIO_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_s_datagram_procname);
end;


function  ERR_BIO_dgram_non_fatal_error(_error: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_dgram_non_fatal_error_procname);
end;


function  ERR_BIO_new_dgram(fd: TIdC_INT; close_flag: TIdC_INT): PBIO; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_new_dgram_procname);
end;



//  function BIO_s_datagram_sctp: PBIO_METHOD;
//  function BIO_new_dgram_sctp(fd: TIdC_INT; close_flag: TIdC_INT): PBIO;
//  function BIO_dgram_is_sctp(bio: PBIO): TIdC_INT;
//  function BIO_dgram_sctp_notification_cb(bio: PBIO; handle_notifications(PBIO;
//    context: Pointer;
//    buf: Pointer): TIdC_INT, Pointer context);
//  function BIO_dgram_sctp_wait_for_dry(b: PBIO): TIdC_INT;
//  function BIO_dgram_sctp_msg_waiting(b: PBIO): TIdC_INT;

function  ERR_BIO_sock_should_retry(i: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_sock_should_retry_procname);
end;


function  ERR_BIO_sock_non_fatal_error(_error: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_sock_non_fatal_error_procname);
end;

function ERR_BIO_err_is_non_fatal(errcode : TIdC_UINT) : TIdC_INT; cdecl;
begin
   ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_err_is_non_fatal_procname);
end;

function  ERR_BIO_fd_should_retry(i: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_fd_should_retry_procname);
end;


function  ERR_BIO_fd_non_fatal_error(_error: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_fd_non_fatal_error_procname);
end;


//  function BIO_dump_cb(
//    Pointer data: cb(;
//    len: TIdC_SIZET;
//    function: Pointer): u: TIdC_INT, Pointer function ,  PIdAnsiChar s, TIdC_INT len): u;
//  function BIO_dump_indent_cb(TIdC_INT (cb( Pointer data, TIdC_SIZET len, Pointer function ): u: TIdC_INT, Pointer function ,  PIdAnsiChar s, TIdC_INT len, TIdC_INT indent): u;
function  ERR_BIO_dump(b: PBIO; const bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_dump_procname);
end;


function  ERR_BIO_dump_indent(b: PBIO; const bytes: PIdAnsiChar; len: TIdC_INT; indent: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_dump_indent_procname);
end;



//  function BIO_dump_fp(fp: cFile; const s: PByte; len: TIdC_INT): TIdC_INT;
//  function BIO_dump_indent_fp(fp: cFile; const s: PByte; len: TIdC_INT; indent: TIdC_INT): TIdC_INT;

function  ERR_BIO_hex_string(out_: PBIO; indent: TIdC_INT; width: TIdC_INT; data: PByte;
  datalen: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_hex_string_procname);
end;



function  ERR_BIO_ADDR_new: PBIO_ADDR; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDR_new_procname);
end;

 {introduced 1.1.0}
function  ERR_BIO_ADDR_rawmake(ap: PBIO_ADDR; familiy: TIdC_INT; const where: Pointer;
  wherelen: TIdC_SIZET; port: TIdC_SHORT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDR_rawmake_procname);
end;

 {introduced 1.1.0}
procedure  ERR_BIO_ADDR_free(a: PBIO_ADDR); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDR_free_procname);
end;

 {introduced 1.1.0}
procedure  ERR_BIO_ADDR_clear(ap: PBIO_ADDR); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDR_clear_procname);
end;

 {introduced 1.1.0}
function  ERR_BIO_ADDR_family(const ap: PBIO_ADDR): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDR_family_procname);
end;

 {introduced 1.1.0}
function  ERR_BIO_ADDR_rawaddress(const ap: PBIO_ADDR; p: Pointer; out l: TIdC_SIZET): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDR_rawaddress_procname);
end;

 {introduced 1.1.0}
function  ERR_BIO_ADDR_rawport(const ap: PBIO_ADDR): TIdC_SHORT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDR_rawport_procname);
end;

 {introduced 1.1.0}
function  ERR_BIO_ADDR_hostname_string(const ap: PBIO_ADDR; numeric: TIdC_INT): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDR_hostname_string_procname);
end;

 {introduced 1.1.0}
function  ERR_BIO_ADDR_service_string(const ap: PBIO_ADDR; numeric: TIdC_INT): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDR_service_string_procname);
end;

 {introduced 1.1.0}
function  ERR_BIO_ADDR_path_string(const ap: PBIO_ADDR): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDR_path_string_procname);
end;

 {introduced 1.1.0}

function  ERR_BIO_ADDRINFO_next(const bai: PBIO_ADDRINFO): PBIO_ADDRINFO; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDRINFO_next_procname);
end;

 {introduced 1.1.0}
function  ERR_BIO_ADDRINFO_family(const bai: PBIO_ADDRINFO): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDRINFO_family_procname);
end;

 {introduced 1.1.0}
function  ERR_BIO_ADDRINFO_socktype(const bai: PBIO_ADDRINFO): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDRINFO_socktype_procname);
end;

 {introduced 1.1.0}
function  ERR_BIO_ADDRINFO_protocol(const bai: PBIO_ADDRINFO): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDRINFO_protocol_procname);
end;

 {introduced 1.1.0}
function  ERR_BIO_ADDRINFO_address(const bai: PBIO_ADDRINFO): PBIO_ADDR; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDRINFO_address_procname);
end;

 {introduced 1.1.0}
procedure  ERR_BIO_ADDRINFO_free(bai: PBIO_ADDRINFO); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_ADDRINFO_free_procname);
end;

 {introduced 1.1.0}

function  ERR_BIO_parse_hostserv(const hostserv: PIdAnsiChar; var host, service: PIdAnsiChar;
  hostserv_prio: BIO_hostserv_priorities): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_parse_hostserv_procname);
end;

 {introduced 1.1.0}

function  ERR_BIO_lookup(const host: PIdAnsiChar; const service: PIdAnsiChar; lookup_type: BIO_lookup_type;
  family: TIdC_INT; socktype: TIdC_INT; res: PPBIO_ADDRINFO): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_lookup_procname);
end;

 {introduced 1.1.0}
function  ERR_BIO_lookup_ex(const host: PIdAnsiChar; const service: PIdAnsiChar; lookup_type: TIdC_INT;
  family: TIdC_INT; socktype: TIdC_INT; protocol: TIdC_INT; res: PPBIO_ADDRINFO): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_lookup_ex_procname);
end;

 {introduced 1.1.0}
function  ERR_BIO_sock_error(sock: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_sock_error_procname);
end;


function  ERR_BIO_socket_ioctl(fd: TIdC_INT; cType: TIdC_LONG; arg: Pointer): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_socket_ioctl_procname);
end;


function  ERR_BIO_socket_nbio(fd: TIdC_INT; mode: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_socket_nbio_procname);
end;


function  ERR_BIO_sock_init: TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_sock_init_procname);
end;



function  ERR_BIO_set_tcp_ndelay(sock: TIdC_INT; turn_on: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_set_tcp_ndelay_procname);
end;



function  ERR_BIO_sock_info(sock: TIdC_INT; type_: BIO_sock_info_type; info: PBIO_sock_info_u): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_sock_info_procname);
end;

 {introduced 1.1.0}

function  ERR_BIO_socket(domain: TIdC_INT; socktype: TIdC_INT; protocol: TIdC_INT; options: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_socket_procname);
end;

 {introduced 1.1.0}
function  ERR_BIO_connect(sock: TIdC_INT; const address: PBIO_ADDR; options: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_connect_procname);
end;

 {introduced 1.1.0}
function  ERR_BIO_bind(sock: TIdC_INT; const address: PBIO_ADDR; options: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_bind_procname);
end;

 {introduced 1.1.0}
function  ERR_BIO_listen(sock: TIdC_INT; const address: PBIO_ADDR; options: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_listen_procname);
end;

 {introduced 1.1.0}
function  ERR_BIO_accept_ex(accept_sock: TIdC_INT; address: PBIO_ADDR; options: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_accept_ex_procname);
end;

 {introduced 1.1.0}
function  ERR_BIO_closesocket(sock: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_closesocket_procname);
end;

 {introduced 1.1.0}

function  ERR_BIO_new_socket(sock: TIdC_INT; close_flag: TIdC_INT): PBIO; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_new_socket_procname);
end;


function  ERR_BIO_new_connect(const host_port: PIdAnsiChar): PBIO; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_new_connect_procname);
end;


function  ERR_BIO_new_accept(const host_port: PIdAnsiChar): PBIO; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_new_accept_procname);
end;



function  ERR_BIO_new_fd(fd: TIdC_INT; close_flag: TIdC_INT): PBIO; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_new_fd_procname);
end;



function  ERR_BIO_new_bio_pair(bio1: PPBIO; writebuf1: TIdC_SIZET; bio2: PPBIO;
  writebuf2: TIdC_SIZET): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_new_bio_pair_procname);
end;


  (*
   * If successful, returns 1 and in *bio1, *bio2 two BIO pair endpoints.
   * Otherwise returns 0 and sets *bio1 and *bio2 to NULL. Size 0 uses default
   * value.
   *)

procedure  ERR_BIO_copy_next_retry(b: PBIO); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_copy_next_retry_procname);
end;



//  BIO_METHOD *BIO_meth_new(int type, const char *name);
//  void BIO_meth_free(BIO_METHOD *biom);
//  int (*BIO_meth_get_write(const BIO_METHOD *biom)) (BIO *, const char *, int);
//  int (*BIO_meth_get_write_ex(const BIO_METHOD *biom)) (BIO *, const char *, TIdC_SIZET,
//                                                  TIdC_SIZET *);
//  int BIO_meth_set_write(BIO_METHOD *biom,
//                         int (*write) (BIO *, const char *, int));
//  int BIO_meth_set_write_ex(BIO_METHOD *biom,
//                         int (*bwrite) (BIO *, const char *, TIdC_SIZET, TIdC_SIZET *));
//  int (*BIO_meth_get_read(const BIO_METHOD *biom)) (BIO *, char *, int);
//  int (*BIO_meth_get_read_ex(const BIO_METHOD *biom)) (BIO *, char *, TIdC_SIZET, TIdC_SIZET *);
//  int BIO_meth_set_read(BIO_METHOD *biom,
//                        int (*read) (BIO *, char *, int));
//  int BIO_meth_set_read_ex(BIO_METHOD *biom,
//                           int (*bread) (BIO *, char *, TIdC_SIZET, TIdC_SIZET *));
//  int (*BIO_meth_get_puts(const BIO_METHOD *biom)) (BIO *, const char *);
//  int BIO_meth_set_puts(BIO_METHOD *biom,
//                        int (*puts) (BIO *, const char *));
//  int (*BIO_meth_get_gets(const BIO_METHOD *biom)) (BIO *, char *, int);
//  int BIO_meth_set_gets(BIO_METHOD *biom,
//                        int (*gets) (BIO *, char *, int));
//  long (*BIO_meth_get_ctrl(const BIO_METHOD *biom)) (BIO *, int, long, void *);
//  int BIO_meth_set_ctrl(BIO_METHOD *biom,
//                        long (*ctrl) (BIO *, int, long, void *));
//  int (*BIO_meth_get_create(const BIO_METHOD *bion)) (BIO *);
//  int BIO_meth_set_create(BIO_METHOD *biom, int (*create) (BIO *));
//  int (*BIO_meth_get_destroy(const BIO_METHOD *biom)) (BIO *);
//  int BIO_meth_set_destroy(BIO_METHOD *biom, int (*destroy) (BIO *));
//  long (*BIO_meth_get_callback_ctrl(const BIO_METHOD *biom))
//                                   (BIO *, int, BIO_info_cb *);
//  int BIO_meth_set_callback_ctrl(BIO_METHOD *biom,
//                                 long (*callback_ctrl) (BIO *, int,
//                                                        BIO_info_cb *));

  {$I TaurusTLSNoRetValOn.inc}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  BIO_get_flags := LoadLibFunction(ADllHandle, BIO_get_flags_procname);
  FuncLoadError := not assigned(BIO_get_flags);
  if FuncLoadError then
  begin
    {$if not defined(BIO_get_flags_allownil)}
    BIO_get_flags := ERR_BIO_get_flags;
    {$ifend}
    {$if declared(BIO_get_flags_introduced)}
    if LibVersion < BIO_get_flags_introduced then
    begin
      {$if declared(FC_BIO_get_flags)}
      BIO_get_flags := FC_BIO_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_get_flags_removed)}
    if BIO_get_flags_removed <= LibVersion then
    begin
      {$if declared(_BIO_get_flags)}
      BIO_get_flags := _BIO_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_get_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_get_flags');
    {$ifend}
  end;

 
  BIO_set_retry_special := LoadLibFunction(ADllHandle, BIO_set_retry_special_procname);
  FuncLoadError := not assigned(BIO_set_retry_special);
  if FuncLoadError then
  begin
    {$if not defined(BIO_set_retry_special_allownil)}
    BIO_set_retry_special := ERR_BIO_set_retry_special;
    {$ifend}
    {$if declared(BIO_set_retry_special_introduced)}
    if LibVersion < BIO_set_retry_special_introduced then
    begin
      {$if declared(FC_BIO_set_retry_special)}
      BIO_set_retry_special := FC_BIO_set_retry_special;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_set_retry_special_removed)}
    if BIO_set_retry_special_removed <= LibVersion then
    begin
      {$if declared(_BIO_set_retry_special)}
      BIO_set_retry_special := _BIO_set_retry_special;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_set_retry_special_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_set_retry_special');
    {$ifend}
  end;

 
  BIO_set_retry_read := LoadLibFunction(ADllHandle, BIO_set_retry_read_procname);
  FuncLoadError := not assigned(BIO_set_retry_read);
  if FuncLoadError then
  begin
    {$if not defined(BIO_set_retry_read_allownil)}
    BIO_set_retry_read := ERR_BIO_set_retry_read;
    {$ifend}
    {$if declared(BIO_set_retry_read_introduced)}
    if LibVersion < BIO_set_retry_read_introduced then
    begin
      {$if declared(FC_BIO_set_retry_read)}
      BIO_set_retry_read := FC_BIO_set_retry_read;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_set_retry_read_removed)}
    if BIO_set_retry_read_removed <= LibVersion then
    begin
      {$if declared(_BIO_set_retry_read)}
      BIO_set_retry_read := _BIO_set_retry_read;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_set_retry_read_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_set_retry_read');
    {$ifend}
  end;

 
  BIO_set_retry_write := LoadLibFunction(ADllHandle, BIO_set_retry_write_procname);
  FuncLoadError := not assigned(BIO_set_retry_write);
  if FuncLoadError then
  begin
    {$if not defined(BIO_set_retry_write_allownil)}
    BIO_set_retry_write := ERR_BIO_set_retry_write;
    {$ifend}
    {$if declared(BIO_set_retry_write_introduced)}
    if LibVersion < BIO_set_retry_write_introduced then
    begin
      {$if declared(FC_BIO_set_retry_write)}
      BIO_set_retry_write := FC_BIO_set_retry_write;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_set_retry_write_removed)}
    if BIO_set_retry_write_removed <= LibVersion then
    begin
      {$if declared(_BIO_set_retry_write)}
      BIO_set_retry_write := _BIO_set_retry_write;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_set_retry_write_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_set_retry_write');
    {$ifend}
  end;

 
  BIO_clear_retry_flags := LoadLibFunction(ADllHandle, BIO_clear_retry_flags_procname);
  FuncLoadError := not assigned(BIO_clear_retry_flags);
  if FuncLoadError then
  begin
    {$if not defined(BIO_clear_retry_flags_allownil)}
    BIO_clear_retry_flags := ERR_BIO_clear_retry_flags;
    {$ifend}
    {$if declared(BIO_clear_retry_flags_introduced)}
    if LibVersion < BIO_clear_retry_flags_introduced then
    begin
      {$if declared(FC_BIO_clear_retry_flags)}
      BIO_clear_retry_flags := FC_BIO_clear_retry_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_clear_retry_flags_removed)}
    if BIO_clear_retry_flags_removed <= LibVersion then
    begin
      {$if declared(_BIO_clear_retry_flags)}
      BIO_clear_retry_flags := _BIO_clear_retry_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_clear_retry_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_clear_retry_flags');
    {$ifend}
  end;

 
  BIO_get_retry_flags := LoadLibFunction(ADllHandle, BIO_get_retry_flags_procname);
  FuncLoadError := not assigned(BIO_get_retry_flags);
  if FuncLoadError then
  begin
    {$if not defined(BIO_get_retry_flags_allownil)}
    BIO_get_retry_flags := ERR_BIO_get_retry_flags;
    {$ifend}
    {$if declared(BIO_get_retry_flags_introduced)}
    if LibVersion < BIO_get_retry_flags_introduced then
    begin
      {$if declared(FC_BIO_get_retry_flags)}
      BIO_get_retry_flags := FC_BIO_get_retry_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_get_retry_flags_removed)}
    if BIO_get_retry_flags_removed <= LibVersion then
    begin
      {$if declared(_BIO_get_retry_flags)}
      BIO_get_retry_flags := _BIO_get_retry_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_get_retry_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_get_retry_flags');
    {$ifend}
  end;

 
  BIO_should_read := LoadLibFunction(ADllHandle, BIO_should_read_procname);
  FuncLoadError := not assigned(BIO_should_read);
  if FuncLoadError then
  begin
    {$if not defined(BIO_should_read_allownil)}
    BIO_should_read := ERR_BIO_should_read;
    {$ifend}
    {$if declared(BIO_should_read_introduced)}
    if LibVersion < BIO_should_read_introduced then
    begin
      {$if declared(FC_BIO_should_read)}
      BIO_should_read := FC_BIO_should_read;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_should_read_removed)}
    if BIO_should_read_removed <= LibVersion then
    begin
      {$if declared(_BIO_should_read)}
      BIO_should_read := _BIO_should_read;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_should_read_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_should_read');
    {$ifend}
  end;

 
  BIO_should_write := LoadLibFunction(ADllHandle, BIO_should_write_procname);
  FuncLoadError := not assigned(BIO_should_write);
  if FuncLoadError then
  begin
    {$if not defined(BIO_should_write_allownil)}
    BIO_should_write := ERR_BIO_should_write;
    {$ifend}
    {$if declared(BIO_should_write_introduced)}
    if LibVersion < BIO_should_write_introduced then
    begin
      {$if declared(FC_BIO_should_write)}
      BIO_should_write := FC_BIO_should_write;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_should_write_removed)}
    if BIO_should_write_removed <= LibVersion then
    begin
      {$if declared(_BIO_should_write)}
      BIO_should_write := _BIO_should_write;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_should_write_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_should_write');
    {$ifend}
  end;

 
  BIO_should_io_special := LoadLibFunction(ADllHandle, BIO_should_io_special_procname);
  FuncLoadError := not assigned(BIO_should_io_special);
  if FuncLoadError then
  begin
    {$if not defined(BIO_should_io_special_allownil)}
    BIO_should_io_special := ERR_BIO_should_io_special;
    {$ifend}
    {$if declared(BIO_should_io_special_introduced)}
    if LibVersion < BIO_should_io_special_introduced then
    begin
      {$if declared(FC_BIO_should_io_special)}
      BIO_should_io_special := FC_BIO_should_io_special;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_should_io_special_removed)}
    if BIO_should_io_special_removed <= LibVersion then
    begin
      {$if declared(_BIO_should_io_special)}
      BIO_should_io_special := _BIO_should_io_special;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_should_io_special_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_should_io_special');
    {$ifend}
  end;

 
  BIO_retry_type := LoadLibFunction(ADllHandle, BIO_retry_type_procname);
  FuncLoadError := not assigned(BIO_retry_type);
  if FuncLoadError then
  begin
    {$if not defined(BIO_retry_type_allownil)}
    BIO_retry_type := ERR_BIO_retry_type;
    {$ifend}
    {$if declared(BIO_retry_type_introduced)}
    if LibVersion < BIO_retry_type_introduced then
    begin
      {$if declared(FC_BIO_retry_type)}
      BIO_retry_type := FC_BIO_retry_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_retry_type_removed)}
    if BIO_retry_type_removed <= LibVersion then
    begin
      {$if declared(_BIO_retry_type)}
      BIO_retry_type := _BIO_retry_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_retry_type_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_retry_type');
    {$ifend}
  end;

 
  BIO_should_retry := LoadLibFunction(ADllHandle, BIO_should_retry_procname);
  FuncLoadError := not assigned(BIO_should_retry);
  if FuncLoadError then
  begin
    {$if not defined(BIO_should_retry_allownil)}
    BIO_should_retry := ERR_BIO_should_retry;
    {$ifend}
    {$if declared(BIO_should_retry_introduced)}
    if LibVersion < BIO_should_retry_introduced then
    begin
      {$if declared(FC_BIO_should_retry)}
      BIO_should_retry := FC_BIO_should_retry;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_should_retry_removed)}
    if BIO_should_retry_removed <= LibVersion then
    begin
      {$if declared(_BIO_should_retry)}
      BIO_should_retry := _BIO_should_retry;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_should_retry_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_should_retry');
    {$ifend}
  end;

 
  BIO_do_connect := LoadLibFunction(ADllHandle, BIO_do_connect_procname);
  FuncLoadError := not assigned(BIO_do_connect);
  if FuncLoadError then
  begin
    {$if not defined(BIO_do_connect_allownil)}
    BIO_do_connect := ERR_BIO_do_connect;
    {$ifend}
    {$if declared(BIO_do_connect_introduced)}
    if LibVersion < BIO_do_connect_introduced then
    begin
      {$if declared(FC_BIO_do_connect)}
      BIO_do_connect := FC_BIO_do_connect;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_do_connect_removed)}
    if BIO_do_connect_removed <= LibVersion then
    begin
      {$if declared(_BIO_do_connect)}
      BIO_do_connect := _BIO_do_connect;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_do_connect_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_do_connect');
    {$ifend}
  end;

 
  BIO_do_accept := LoadLibFunction(ADllHandle, BIO_do_accept_procname);
  FuncLoadError := not assigned(BIO_do_accept);
  if FuncLoadError then
  begin
    {$if not defined(BIO_do_accept_allownil)}
    BIO_do_accept := ERR_BIO_do_accept;
    {$ifend}
    {$if declared(BIO_do_accept_introduced)}
    if LibVersion < BIO_do_accept_introduced then
    begin
      {$if declared(FC_BIO_do_accept)}
      BIO_do_accept := FC_BIO_do_accept;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_do_accept_removed)}
    if BIO_do_accept_removed <= LibVersion then
    begin
      {$if declared(_BIO_do_accept)}
      BIO_do_accept := _BIO_do_accept;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_do_accept_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_do_accept');
    {$ifend}
  end;

 
  BIO_do_handshake := LoadLibFunction(ADllHandle, BIO_do_handshake_procname);
  FuncLoadError := not assigned(BIO_do_handshake);
  if FuncLoadError then
  begin
    {$if not defined(BIO_do_handshake_allownil)}
    BIO_do_handshake := ERR_BIO_do_handshake;
    {$ifend}
    {$if declared(BIO_do_handshake_introduced)}
    if LibVersion < BIO_do_handshake_introduced then
    begin
      {$if declared(FC_BIO_do_handshake)}
      BIO_do_handshake := FC_BIO_do_handshake;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_do_handshake_removed)}
    if BIO_do_handshake_removed <= LibVersion then
    begin
      {$if declared(_BIO_do_handshake)}
      BIO_do_handshake := _BIO_do_handshake;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_do_handshake_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_do_handshake');
    {$ifend}
  end;

 
  BIO_get_mem_data := LoadLibFunction(ADllHandle, BIO_get_mem_data_procname);
  FuncLoadError := not assigned(BIO_get_mem_data);
  if FuncLoadError then
  begin
    {$if not defined(BIO_get_mem_data_allownil)}
    BIO_get_mem_data := ERR_BIO_get_mem_data;
    {$ifend}
    {$if declared(BIO_get_mem_data_introduced)}
    if LibVersion < BIO_get_mem_data_introduced then
    begin
      {$if declared(FC_BIO_get_mem_data)}
      BIO_get_mem_data := FC_BIO_get_mem_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_get_mem_data_removed)}
    if BIO_get_mem_data_removed <= LibVersion then
    begin
      {$if declared(_BIO_get_mem_data)}
      BIO_get_mem_data := _BIO_get_mem_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_get_mem_data_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_get_mem_data');
    {$ifend}
  end;

 
  BIO_set_mem_buf := LoadLibFunction(ADllHandle, BIO_set_mem_buf_procname);
  FuncLoadError := not assigned(BIO_set_mem_buf);
  if FuncLoadError then
  begin
    {$if not defined(BIO_set_mem_buf_allownil)}
    BIO_set_mem_buf := ERR_BIO_set_mem_buf;
    {$ifend}
    {$if declared(BIO_set_mem_buf_introduced)}
    if LibVersion < BIO_set_mem_buf_introduced then
    begin
      {$if declared(FC_BIO_set_mem_buf)}
      BIO_set_mem_buf := FC_BIO_set_mem_buf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_set_mem_buf_removed)}
    if BIO_set_mem_buf_removed <= LibVersion then
    begin
      {$if declared(_BIO_set_mem_buf)}
      BIO_set_mem_buf := _BIO_set_mem_buf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_set_mem_buf_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_set_mem_buf');
    {$ifend}
  end;

 
  BIO_get_mem_ptr := LoadLibFunction(ADllHandle, BIO_get_mem_ptr_procname);
  FuncLoadError := not assigned(BIO_get_mem_ptr);
  if FuncLoadError then
  begin
    {$if not defined(BIO_get_mem_ptr_allownil)}
    BIO_get_mem_ptr := ERR_BIO_get_mem_ptr;
    {$ifend}
    {$if declared(BIO_get_mem_ptr_introduced)}
    if LibVersion < BIO_get_mem_ptr_introduced then
    begin
      {$if declared(FC_BIO_get_mem_ptr)}
      BIO_get_mem_ptr := FC_BIO_get_mem_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_get_mem_ptr_removed)}
    if BIO_get_mem_ptr_removed <= LibVersion then
    begin
      {$if declared(_BIO_get_mem_ptr)}
      BIO_get_mem_ptr := _BIO_get_mem_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_get_mem_ptr_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_get_mem_ptr');
    {$ifend}
  end;

 
  BIO_set_mem_eof_return := LoadLibFunction(ADllHandle, BIO_set_mem_eof_return_procname);
  FuncLoadError := not assigned(BIO_set_mem_eof_return);
  if FuncLoadError then
  begin
    {$if not defined(BIO_set_mem_eof_return_allownil)}
    BIO_set_mem_eof_return := ERR_BIO_set_mem_eof_return;
    {$ifend}
    {$if declared(BIO_set_mem_eof_return_introduced)}
    if LibVersion < BIO_set_mem_eof_return_introduced then
    begin
      {$if declared(FC_BIO_set_mem_eof_return)}
      BIO_set_mem_eof_return := FC_BIO_set_mem_eof_return;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_set_mem_eof_return_removed)}
    if BIO_set_mem_eof_return_removed <= LibVersion then
    begin
      {$if declared(_BIO_set_mem_eof_return)}
      BIO_set_mem_eof_return := _BIO_set_mem_eof_return;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_set_mem_eof_return_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_set_mem_eof_return');
    {$ifend}
  end;

 
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

  BIO_err_is_non_fatal := LoadLibFunction(ADllHandle,BIO_err_is_non_fatal_procname);
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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


end;

procedure Unload;
begin
  BIO_get_flags := nil; {removed 1.0.0}
  BIO_set_retry_special := nil; {removed 1.0.0}
  BIO_set_retry_read := nil; {removed 1.0.0}
  BIO_set_retry_write := nil; {removed 1.0.0}
  BIO_clear_retry_flags := nil; {removed 1.0.0}
  BIO_get_retry_flags := nil; {removed 1.0.0}
  BIO_should_read := nil; {removed 1.0.0}
  BIO_should_write := nil; {removed 1.0.0}
  BIO_should_io_special := nil; {removed 1.0.0}
  BIO_retry_type := nil; {removed 1.0.0}
  BIO_should_retry := nil; {removed 1.0.0}
  BIO_do_connect := nil; {removed 1.0.0}
  BIO_do_accept := nil; {removed 1.0.0}
  BIO_do_handshake := nil; {removed 1.0.0}
  BIO_get_mem_data := nil; {removed 1.0.0}
  BIO_set_mem_buf := nil; {removed 1.0.0}
  BIO_get_mem_ptr := nil; {removed 1.0.0}
  BIO_set_mem_eof_return := nil; {removed 1.0.0}
  BIO_get_new_index := nil; {introduced 1.1.0}
  BIO_set_flags := nil;
  BIO_test_flags := nil;
  BIO_clear_flags := nil;
  BIO_get_callback := nil;
  BIO_set_callback := nil;
  BIO_get_callback_ex := nil; {introduced 1.1.0}
  BIO_set_callback_ex := nil; {introduced 1.1.0}
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
  BIO_s_file := nil;
  BIO_new_file := nil;
  BIO_new := nil;
  BIO_free := nil;
  BIO_set_data := nil; {introduced 1.1.0}
  BIO_get_data := nil; {introduced 1.1.0}
  BIO_set_init := nil; {introduced 1.1.0}
  BIO_get_init := nil; {introduced 1.1.0}
  BIO_set_shutdown := nil; {introduced 1.1.0}
  BIO_get_shutdown := nil; {introduced 1.1.0}
  BIO_vfree := nil;
  BIO_up_ref := nil; {introduced 1.1.0}
  BIO_read := nil;
  BIO_read_ex := nil; {introduced 1.1.0}
  BIO_recvmmsg := nil; {introduced 3.2.0}
  BIO_gets := nil;
  BIO_write := nil;
  BIO_write_ex := nil; {introduced 1.1.0}
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
  BIO_set_next := nil; {introduced 1.1.0}
  BIO_get_retry_BIO := nil;
  BIO_get_retry_reason := nil;
  BIO_set_retry_reason := nil; {introduced 1.1.0}
  BIO_dup_chain := nil;
  BIO_nread0 := nil;
  BIO_nread := nil;
  BIO_nwrite0 := nil;
  BIO_nwrite := nil;
  BIO_debug_callback := nil;
  BIO_s_mem := nil;
  BIO_s_secmem := nil; {introduced 1.1.0}
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
  BIO_f_linebuffer := nil; {introduced 1.1.0}
  BIO_f_nbio_test := nil;
  BIO_s_datagram := nil;
  BIO_dgram_non_fatal_error := nil;
  BIO_new_dgram := nil;
  BIO_sock_should_retry := nil;
  BIO_sock_non_fatal_error := nil;
  BIO_fd_should_retry := nil;
  BIO_fd_non_fatal_error := nil;
  BIO_dump := nil;
  BIO_dump_indent := nil;
  BIO_hex_string := nil;
  BIO_ADDR_new := nil; {introduced 1.1.0}
  BIO_ADDR_rawmake := nil; {introduced 1.1.0}
  BIO_ADDR_free := nil; {introduced 1.1.0}
  BIO_ADDR_clear := nil; {introduced 1.1.0}
  BIO_ADDR_family := nil; {introduced 1.1.0}
  BIO_ADDR_rawaddress := nil; {introduced 1.1.0}
  BIO_ADDR_rawport := nil; {introduced 1.1.0}
  BIO_ADDR_hostname_string := nil; {introduced 1.1.0}
  BIO_ADDR_service_string := nil; {introduced 1.1.0}
  BIO_ADDR_path_string := nil; {introduced 1.1.0}
  BIO_ADDRINFO_next := nil; {introduced 1.1.0}
  BIO_ADDRINFO_family := nil; {introduced 1.1.0}
  BIO_ADDRINFO_socktype := nil; {introduced 1.1.0}
  BIO_ADDRINFO_protocol := nil; {introduced 1.1.0}
  BIO_ADDRINFO_address := nil; {introduced 1.1.0}
  BIO_ADDRINFO_free := nil; {introduced 1.1.0}
  BIO_parse_hostserv := nil; {introduced 1.1.0}
  BIO_lookup := nil; {introduced 1.1.0}
  BIO_lookup_ex := nil; {introduced 1.1.0}
  BIO_sock_error := nil;
  BIO_socket_ioctl := nil;
  BIO_socket_nbio := nil;
  BIO_sock_init := nil;
  BIO_set_tcp_ndelay := nil;
  BIO_sock_info := nil; {introduced 1.1.0}
  BIO_socket := nil; {introduced 1.1.0}
  BIO_connect := nil; {introduced 1.1.0}
  BIO_bind := nil; {introduced 1.1.0}
  BIO_listen := nil; {introduced 1.1.0}
  BIO_accept_ex := nil; {introduced 1.1.0}
  BIO_closesocket := nil; {introduced 1.1.0}
  BIO_new_socket := nil;
  BIO_new_connect := nil;
  BIO_new_accept := nil;
  BIO_new_fd := nil;
  BIO_new_bio_pair := nil;
  BIO_copy_next_retry := nil;
end;
{$ELSE}
function BIO_get_flags(const b: PBIO): TIdC_INT;
begin
  Result := BIO_test_flags(b, not $0);
end;

//# define BIO_set_retry_special(b) \
//                BIO_set_flags(b, (BIO_FLAGS_IO_SPECIAL|BIO_FLAGS_SHOULD_RETRY))
procedure BIO_set_retry_special(b: PBIO);
begin
  BIO_set_flags(b, BIO_FLAGS_IO_SPECIAL or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_set_retry_read(b) \
//                BIO_set_flags(b, (BIO_FLAGS_READ|BIO_FLAGS_SHOULD_RETRY))
procedure BIO_set_retry_read(b: PBIO);
begin
  BIO_set_flags(b, BIO_FLAGS_READ or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_set_retry_write(b) \
//                BIO_set_flags(b, (BIO_FLAGS_WRITE|BIO_FLAGS_SHOULD_RETRY))
procedure BIO_set_retry_write(b: PBIO);
begin
  BIO_set_flags(b, BIO_FLAGS_WRITE or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_clear_retry_flags(b) \
//                BIO_clear_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))
procedure BIO_clear_retry_flags(b: PBIO);
begin
  BIO_clear_flags(b, BIO_FLAGS_RWS or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_get_retry_flags(b) \
//                BIO_test_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))
function BIO_get_retry_flags(b: PBIO): TIdC_INT;
begin
  Result := BIO_test_flags(b, BIO_FLAGS_RWS or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_should_read(a)              BIO_test_flags(a, BIO_FLAGS_READ)
function BIO_should_read(b: PBIO): TIdC_INT;
begin
  Result := BIO_test_flags(b, BIO_FLAGS_READ);
end;

//# define BIO_should_write(a)             BIO_test_flags(a, BIO_FLAGS_WRITE)
function BIO_should_write(b: PBIO): TIdC_INT;
begin
  Result := BIO_test_flags(b, BIO_FLAGS_WRITE);
end;

//# define BIO_should_io_special(a)        BIO_test_flags(a, BIO_FLAGS_IO_SPECIAL)
function BIO_should_io_special(b: PBIO): TIdC_INT;
begin
  Result := BIO_test_flags(b, BIO_FLAGS_IO_SPECIAL);
end;

//# define BIO_retry_type(a)               BIO_test_flags(a, BIO_FLAGS_RWS)
function BIO_retry_type(b: PBIO): TIdC_INT;
begin
  Result := BIO_test_flags(b, BIO_FLAGS_RWS);
end;

//# define BIO_should_retry(a)             BIO_test_flags(a, BIO_FLAGS_SHOULD_RETRY)
function BIO_should_retry(b: PBIO): TIdC_INT;
begin
  Result := BIO_test_flags(b, BIO_FLAGS_SHOULD_RETRY);
end;

//#  define BIO_do_connect(b)       BIO_do_handshake(b)
function BIO_do_connect(b: PBIO): TIdC_LONG;
begin
  Result := BIO_do_handshake(b);
end;

//#  define BIO_do_accept(b)        BIO_do_handshake(b)
function BIO_do_accept(b: PBIO): TIdC_LONG;
begin
  Result := BIO_do_handshake(b);
end;

//# define BIO_do_handshake(b)     BIO_ctrl(b,BIO_C_DO_STATE_MACHINE,0,NULL)
function BIO_do_handshake(b: PBIO): TIdC_LONG;
begin
  Result := BIO_ctrl(b, BIO_C_DO_STATE_MACHINE, 0, nil);
end;

// WAS DECLARED AS:
//function BIO_get_mem_data(b: PBIO; pp: Pointer) : TIdC_INT;
//# define BIO_get_mem_data(b,pp)  BIO_ctrl(b,BIO_CTRL_INFO,0,(char (pp))
function BIO_get_mem_data(b: PBIO; var pp: Pointer) : TIdC_INT;
begin
  Result := BIO_ctrl(b, BIO_CTRL_INFO, 0, pp);
end;

//# define BIO_set_mem_buf(b,bm,c) BIO_ctrl(b,BIO_C_SET_BUF_MEM,c,(char (bm))
function BIO_set_mem_buf(b: PBIO; bm: PBUF_MEM; c: TIdC_INT): TIdC_INT;
begin
  Result := BIO_ctrl(b, BIO_C_SET_BUF_MEM, c, bm);
end;

// WAS DECLARED AS:
// function BIO_get_mem_ptr(b: PBIO; pp: Pointer): TIdC_INT;
//# define BIO_get_mem_ptr(b,pp)   BIO_ctrl(b,BIO_C_GET_BUF_MEM_PTR,0,(char (pp))
function BIO_get_mem_ptr(b: PBIO; var pp: PBUF_MEM): TIdC_INT;
begin
  Result := BIO_ctrl(b, BIO_C_GET_BUF_MEM_PTR, 0, pp);
end;

//# define BIO_set_mem_eof_return(b,v) BIO_ctrl(b,BIO_C_SET_BUF_MEM_EOF_RETURN,v,0)
function BIO_set_mem_eof_return(b: PBIO; v: TIdC_INT): TIdC_INT;
begin
  Result := BIO_ctrl(b, BIO_C_SET_BUF_MEM_EOF_RETURN, v, nil);
end;

{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
