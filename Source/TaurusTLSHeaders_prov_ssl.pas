/// <exclude />
{$I TaurusTLSCompilerDefines.inc}
{$I TaurusTLSLinkDefines.inc}
{$IFNDEF USE_OPENSSL}
{ error Should not compile if USE_OPENSSL is not defined!!! }
{$ENDIF}
{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2026 TaurusTLS Developers, All Rights Reserved              * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 – 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  * }
{ ****************************************************************************** }

unit TaurusTLSHeaders_prov_ssl;

interface
const
//* SSL/TLS related defines useful to providers */
  {$EXTERNALSYM SSL_MAX_MASTER_KEY_LENGTH}
  SSL_MAX_MASTER_KEY_LENGTH = 48;

//* SSL/TLS uses a 2 byte unsigned version number */
  {$EXTERNALSYM SSL3_VERSION}
  SSL3_VERSION = $0300;
  {$EXTERNALSYM TLS1_VERSION}
  TLS1_VERSION = $0301;
  {$EXTERNALSYM TLS1_1_VERSION}
  TLS1_1_VERSION = $0302;
  {$EXTERNALSYM TLS1_2_VERSION}
  TLS1_2_VERSION = $0303;
  {$EXTERNALSYM TLS1_3_VERSION}
  TLS1_3_VERSION = $0304;
  {$EXTERNALSYM DTLS1_VERSION}
  DTLS1_VERSION = $FEFF;
  {$EXTERNALSYM DTLS1_2_VERSION}
  DTLS1_2_VERSION = $FEFD;
  {$EXTERNALSYM DTLS1_3_VERSION}
  DTLS1_3_VERSION = $FEFC;
  {$EXTERNALSYM DTLS1_BAD_VER}
  DTLS1_BAD_VER = $0100;

  {$EXTERNALSYM PROTO_VERSION_UNSET}
  PROTO_VERSION_UNSET = 0;

//* QUIC uses a 4 byte unsigned version number */
  {$EXTERNALSYM OSSL_QUIC1_VERSION}
  OSSL_QUIC1_VERSION = $0000001;

//* Maximum plaintext length: defined by SSL/TLS standards */
  {$EXTERNALSYM SSL3_RT_MAX_PLAIN_LENGTH}
  SSL3_RT_MAX_PLAIN_LENGTH = 16384;

implementation

end.
