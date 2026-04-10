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

unit TaurusTLSHeaders_conftypes;

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
  Pconf_method_st = ^Tconf_method_st;
  Tconf_method_st =   record
    name: PIdAnsiChar;
    create: T_func_cb;
    init: T_func_cb;
    destroy: T_func_cb;
    destroy_data: T_func_cb;
    load_bio: T_func_cb;
    dump: T_func_cb;
    is_number: T_func_cb;
    to_int: T_func_cb;
    load: T_func_cb;
  end;
  {$EXTERNALSYM Pconf_method_st}

  Pconf_st = ^Tconf_st;
  Tconf_st =   record
    meth: PCONF_METHOD;
    meth_data: Pointer;
    data: Plhash_st_CONF_VALUE;
    flag_dollarid: TIdC_INT;
    flag_abspath: TIdC_INT;
    includedir: PIdAnsiChar;
    libctx: POSSL_LIB_CTX;
  end;
  {$EXTERNALSYM Pconf_st}


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // _func_cb = function(meth: PCONF_METHOD): PCONF; cdecl;

implementation

end.