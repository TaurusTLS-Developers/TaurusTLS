// this is placeholder include file
// for addition compiler directives

// FastMM5 is optional. Define USE_FASTMM5 to use it. MEMLEAK_CHECK and
// MEMLEAK_DETAILS need FastMM5, so they define USE_FASTMM5 too.
{$IFDEF MSWINDOWS}
  {$IFDEF MEMLEAK_CHECK}
    {$DEFINE USE_FASTMM5}
  {$ENDIF}
  {$IFDEF MEMLEAK_DETAILS}
    {$DEFINE USE_FASTMM5}
  {$ENDIF}
{$ELSE}
  {$UNDEF USE_FASTMM5}
{$ENDIF}
