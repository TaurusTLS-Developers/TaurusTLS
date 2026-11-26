{ OpenSSL linking modes:

  1. Runtime loading of shared libraries through TaurusTLSLoader is the default
     when none of the linking symbols below is defined.

  2. OPENSSL_USE_SHARED_LIBRARY selects startup loading of shared libraries
     through direct external imports.

  3. STATICLOAD_OPENSSL selects linked archives for Delphi targets such as
     macOS, iOS and Android. OPENSSL_USE_STATIC_LIBRARY selects the existing
     Free Pascal archive-linking configuration.

  STATICLOAD_OPENSSL and OPENSSL_USE_SHARED_LIBRARY are mutually exclusive
  on every target. OPENSSL_STATIC_LINK_MODEL selects direct API imports for
  either startup shared-library loading or archive linking; it does not by
  itself identify an archive deployment.
}
{$IFDEF STATICLOAD_OPENSSL}
{$IFDEF OPENSSL_USE_SHARED_LIBRARY}
{$message Error:STATICLOAD_OPENSSL and OPENSSL_USE_SHARED_LIBRARY are mutually exclusive}
{$ENDIF}
{$ENDIF}
{$IFDEF STATICLOAD_OPENSSL}
{$DEFINE OPENSSL_STATIC_LINK_MODEL}
{$UNDEF OPENSSL_USE_STATIC_LIBRARY}
{$ENDIF}
{$IFDEF OPENSSL_USE_SHARED_LIBRARY}
{$DEFINE OPENSSL_STATIC_LINK_MODEL}
{$ENDIF}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$IFNDEF FPC}
{$message Error:OPENSSL_USE_STATIC_LIBRARY may only be used when compiling with the Free Pascal Compiler}
{$ELSE}
{$DEFINE OPENSSL_STATIC_LINK_MODEL}
{$ENDIF}
{$ENDIF}


