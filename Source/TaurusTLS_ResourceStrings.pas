/// <exclude />
{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2024 TaurusTLS Developers, All Rights Reserved              * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 – 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  * }
{ ****************************************************************************** }
{$I TaurusTLSCompilerDefines.inc}
unit TaurusTLS_ResourceStrings;

interface

resourcestring
  { TaurusTLS }
  RSOSSLInitFailed = 'OPENSSL_init_ssl failed';
  RSOSSSessionCanNotBeNul = 'Session can not be nul.';
  RSOSSInvalidSessionValue = 'Invalid Session Value.';
  RSOSSUnsupportedVersion = 'Unsupported SSL Library version: %.8x.';
  RSOSSLModeNotSet = 'Mode has not been set.';

  RSOSSLCouldNotLoadSSLLibrary = 'Could not load SSL library.';

  ROSSLCantGetSSLVersionNo = 'Unable to determine SSL Library Version number';
  ROSSLAPIFunctionNotPresent =
    'TaurusTLS API Function/Procedure %s not found in SSL Library';
  ROSUnrecognisedLibName = 'Unrecognised SSL Library name (%s)';
  ROSCertificateNotAddedToStore =
    'Unable to add X.509 Certificate to cert store';
  RSOSSLMinProtocolError = 'SSL_CTX_set_min_proto_version error';
  RSOSSLMaxProtocolError = 'SSL_CTX_set_max_proto_version error';
  RSOSSLCopySessionIdError = 'SSL_copy_session_id error';
  ROSUnsupported = 'Not Supported';
  {$IFNDEF USE_WINDOWS_CERT_STORE}
  RSOSSLCTXSetDefaultVerifyPathFailed = 'SSL_CTX_set_default_verify_paths failed.';
  {$ENDIF}
  RSSSLSettingTLSHostNameError_2 = 'SSL_set1_host failed error.';
  RSSSL_CTX_set_tlsext_servername_callback = 'SSL_CTX_set_tlsext_servername_callback error';
  RSSSL_CTX_set_tlsext_servername_arg = 'ETaurusTLSSSL_CTX_set_tlsext_servername_arg error';
  // callback where strings
  RSOSSLAlert = '%s Alert';
  RSOSSLReadAlert = '%s Read Alert';
  RSOSSLWriteAlert = '%s Write Alert';
  RSOSSLAcceptLoop = 'Accept Loop';
  RSOSSLAcceptError = 'Accept Error';
  RSOSSLAcceptFailed = 'Accept Failed';
  RSOSSLAcceptExit = 'Accept Exit';
  RSOSSLConnectLoop = 'Connect Loop';
  RSOSSLConnectError = 'Connect Error';
  RSOSSLConnectFailed = 'Connect Failed';
  RSOSSLConnectExit = 'Connect Exit';
  RSOSSLHandshakeStart = 'Handshake Start';
  RSOSSLHandshakeDone = 'Handshake Done';
  { IdSSLTaurusTLSFIPS }
  RSOSSLEVPMDCTXNew = 'EVP_MD_CTX_new error';
  RSOSSLEVPDigestExError = 'EVP_DigestInit_ex error';
  RSOSSLEVPDigestUpdateError = 'EVP_DigestUpdate error';
  RSOSSLEVPDigestError = 'EVP_DigestFinal_ex error';
  RSOSSLHMACCTXnew =  'HMAC_CTX_new error';
  RSOSSLHMACInitExError = 'HMAC_Init_ex error';
  RSOSSLHMACUpdateError = 'HMAC_Update error';
  RSOSSLHMACFinalError = 'HMAC_Final error';
  RSOSSLX509DigestFailed = 'X509_digest failed';
  // long desciptions for cert errors.
  RSMSG_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT = 'the issuer certificate could ' +
    'not be found: this occurs if the issuer certificate of an untrusted ' +
    'certificate cannot be found. ';
  RSMSG_X509_V_ERR_UNABLE_TO_GET_CRL = 'the Certificate Revocation List (CRL) '
    + 'of a certificate could not be found. ';
  RSMSG_X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE = 'The certificate ' +
    'signature could not be decrypted. This means that the actual signature ' +
    'value could not be determined rather than it not matching the expected ' +
    'value, this is only meaningful for RSA keys. ';
  RSMSG_X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE = 'The Certificate ' +
    'Revocation List (CRL) signature could not be decrypted: this means that ' +
    'the actual signature value could not be determined rather than it not ' +
    'matching the expected value. Unused. ';
  RSMSG_X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY = 'The public key in ' +
    'the certificate SubjectPublicKeyInfo could not be read. ';
  RSMSG_X509_V_ERR_CERT_SIGNATURE_FAILURE = 'The signature of the ' +
    'certificate is invalid. ';
  RSMSG_X509_V_ERR_CRL_SIGNATURE_FAILURE = 'The signature of the Certificate ' +
    'Revocation List (CRL) is invalid. ';
  RSMSG_X509_V_ERR_CERT_NOT_YET_VALID = 'The certificate is not yet valid: ' +
    'the notBefore date is after the current time. ';
  RSMSG_X509_V_ERR_CERT_HAS_EXPIRED = 'The certificate has expired: that is ' +
    'the notAfter date is before the current time.';
  RSMSG_X509_V_ERR_CRL_NOT_YET_VALID = 'The Certificate Revocation List (CRL) '
    + 'is not yet valid. ';
  RSMSG_X509_V_ERR_CRL_HAS_EXPIRED = 'The Certificate Revocation List (CRL) ' +
    'has expired. ';
  RSMSG_X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD = 'The certificate ' +
    'notBefore field contains an invalid time.';
  RSMSG_X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD = 'The certificate notAfter ' +
    'field contains an invalid time.';
  RSMSG_X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD = 'The Certificate ' +
    'Revocation List (CRL) lastUpdate field contains an invalid time.';
  RSMSG_X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD = 'The Certificate ' +
    'Revocation List (CRL) nextUpdate field contains an invalid time.';
  RSMSG_X509_V_ERR_OUT_OF_MEM = 'An error occurred trying to allocate memory. '
    + 'This should never happen. ';
  RSMSG_X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT = 'The passed certificate is ' +
    'self signed and the same certificate cannot be found in the list of ' +
    'trusted certificates. ';
  RSMSG_X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN = 'The certificate chain could ' +
    'be built up using the untrusted certificates but the root could not be ' +
    'found locally. ';
  RSNSG_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 'The issuer ' +
    'certificate of a locally looked up certificate could not be found. This ' +
    'normally means the list of trusted certificates is not complete. ';
  RSMSG_X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE = 'No signatures could be ' +
    'verified because the chain contains only one certificate and it is not ' +
    'self signed. ';
  RSMSG_X509_V_ERR_CERT_CHAIN_TOO_LONG = 'The certificate chain length is ' +
    'greater than the supplied maximum depth. Unused. ';
  RSMSG_X509_V_ERR_CERT_REVOKED = 'The certificate has been revoked.';
  RSMSG_X509_V_ERR_NO_ISSUER_PUBLIC_KEY = 'The issuer certificate does not '+
    'have a public key.';
  RSMSG_X509_V_ERR_PATH_LENGTH_EXCEEDED = 'The basicConstraints pathlength ' +
    'parameter has been exceeded. ';
  RSMSG_X509_V_ERR_INVALID_PURPOSE = 'The supplied certificate cannot be used '
    + 'for the specified purpose. ';
  RSMSG_X509_V_ERR_CERT_UNTRUSTED = 'The root Certificate Authority (CA) is ' +
    'not marked as trusted for the specified purpose. ';
  RSMSG_X509_V_ERR_CERT_REJECTED = 'The root Certificate Authority (CA) is ' +
    'marked to reject the specified purpose. ';
  RSMSG_X509_V_ERR_SUBJECT_ISSUER_MISMATCH = 'The current candidate issuer ' +
    'certificate was rejected because its subject name did not match the ' +
    'issuer name of the current certificate. This is only set if issuer ' +
    'check debugging is enabled it is used for status notification and is ' +
    'not in itself an error. ';
  RSMSG_X509_V_ERR_AKID_SKID_MISMATCH = 'The current candidate issuer ' +
    'certificate was rejected because its subject key identifier was present ' +
    'and did not match the authority key identifier current certificate. ' +
    'This is only set if issuer check debugging is enabled it is used for ' +
    'status notification and is not in itself an error. ';
  RSMSG_X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH = 'The current candidate ' +
    'issuer certificate was rejected because its issuer name and serial ' +
    'number was present and did not match the authority key identifier of ' +
    'the current certificate. This is only set if issuer check debugging is ' +
    'enabled it is used for status notification and is not in itself an ' +
    'error. ';
  RSMSG_X509_V_ERR_KEYUSAGE_NO_CERTSIGN = 'The current candidate issuer ' +
    'certificate was rejected because its keyUsage extension does not permit ' +
    'certificate signing. This is only set if issuer check debugging is ' +
    'enabled it is used for status notification and is not in itself an ' +
    'error. ';
  RSMSG_X509_V_ERR_INVALID_EXTENSION = 'A certificate extension had an ' +
    'invalid value (for example an incorrect encoding) or some value ' +
    'inconsistent with other extensions. ';
  RSMSG_X509_V_ERR_INVALID_POLICY_EXTENSION = 'A certificate policies '+
    'extension had an invalid value (for example an incorrect encoding) or '+
    'some value inconsistent with other extensions. This error only occurs if '+
    'policy processing is enabled. ';
  RSMSG_X509_V_ERR_NO_EXPLICIT_POLICY = 'The verification flags were set to '+
    'require and explicit policy but none was present. ';
  RSMSG_X509_V_ERR_DIFFERENT_CRL_SCOPE = 'The only Certificate Revocation '+
    'Lists (CRLs) that could be found did not match the scope of the '+
    'certificate.';
  RSMSG_X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE = 'Some feature of a '+
    'certificate extension is not supported. Unused. ';
  RSMSG_X509_V_ERR_PERMITTED_VIOLATION = 'A name constraint violation occured '+
    'in the permitted subtrees. ';
  RSMSG_X509_V_ERR_EXCLUDED_VIOLATION = 'A name constraint violation occured '+
    'in the excluded subtrees. ';
  RSMSG_X509_V_ERR_SUBTREE_MINMAX = 'A certificate name constraints extension '+
    'included a minimum or maximum field: this is not supported.';
  RSMSG_X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE = 'An unsupported name '+
    'constraint type was encountered. OpenSSL currently only supports '+
    'directory name, DNS name, email and URI types. ';
  RSMSG_X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX = 'The format of the name '+
    'constraint is not recognised: for example an email address format of a '+
    'form not mentioned in RFC3280 . This could be caused by a garbage '+
    'extension or some new feature not currently supported.';
  RSMSG_X509_V_ERR_CRL_PATH_VALIDATION_error = 'An error occured when '+
    'attempting to verify the Certificate Revocation List (CRL) path. This '+
    'error can only happen if extended CRL checking is enabled.';
  RSMSG_X509_V_ERR_APPLICATION_VERIFICATION  = 'An application specific '+
    'error. This will never be returned unless explicitly set by an '+
    'application. ';
  RSMSG_X509_V_ERR_UNSUPPORTED_NAME_SYNTAX = 'Unsupported or invalid name '+
    'syntax.';
  RSMSG_X509_V_ERR_PATH_LOOP = 'Path loop.';
  RSMSG_X509_V_ERR_HOSTNAME_MISMATCH = 'Hostname mismatch.';
  RSMSG_X509_V_ERR_EMAIL_MISMATCH = 'Email address mismatch.';
  RSMSG_X509_V_ERR_IP_ADDRESS_MISMATCH = 'IP address mismatch.';
  RSMSG_X509_V_ERR_DANE_NO_MATCH = 'DNS-based Authentication of Named '+
    'Entities (DANE) Transport Layer Security Authentication (TLSA) '+
    'authentication is enabled, but no TLSA records matched the certificate '+
    'chain. This error is only possible in openssl-s_client(1).';
  RSMSG_X509_V_ERR_EE_KEY_TOO_SMALL = 'End Entry (EE) certificate key too weak.';
  RSMSG_X509_V_ERR_CA_KEY_TOO_SMALL = 'Certificate Authority (CA) '+
    'certificate key too weak.';
  RSMSG_X509_V_ERR_CA_MD_TOO_WEAK = 'Certificate Authority (CA) signature '+
    'digest algorithm too weak';
  RSMSG_X509_V_ERR_INVALID_CALL = 'Invalid certificate verification context.';
  RSMSG_X509_V_ERR_STORE_LOOKUP = 'Issuer certificate lookup error.';
  RSMSG_X509_V_ERR_NO_VALID_SCTS = 'Certificate Transparency required, but no '+
    'valid Signed Certificate Timestamps (SCTs) found.';
  RSMSG_X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION = 'Proxy subject name violation.';
  RSMSG_X509_V_ERR_OCSP_VERIFY_NEEDED = 'Returned by the verify callback to '+
    'indicate an Online Certificate Status Protocol (OCSP) verification is '+
    'needed.';
  RSMSG_X509_V_ERR_OCSP_VERIFY_FAILED = 'Returned by the verify callback to '+
    'indicate Online Certificate Status Protocol (OCSP) verification failed.';
  RSMSG_X509_V_ERR_OCSP_CERT_UNKNOWN = 'Returned by the verify callback to '+
    'indicate that the certificate is not recognized by the Online '+
    'Certificate Status Protoco (OCSP) responder.';
  RSMSG_X509_V_ERR_UNSUPPORTED_SIGNATURE_ALGORITHM = 'Cannot find certificate '+
    'signature algorithm.';
  RSMSG_X509_V_ERR_SIGNATURE_ALGORITHM_MISMATCH = 'The issuer''s public key '+
    'is not of the type required by the signature in the subject''s '+
    'certificate.';
  RSMSG_X509_V_ERR_SIGNATURE_ALGORITHM_INCONSISTENCY = 'The algorithm given '+
    'in the certificate info is inconsistent with the one used for the '+
    'certificate signature.';
  RSMSG_X509_V_ERR_INVALID_CA = 'A Certificate Authority (CA) certificate is '+
    'invalid. Either it is not a CA or its extensions are not consistent '+
    'with the supplied purpose.';
  RSMSG_X509_V_ERR_RPK_UNTRUSTED = 'No TLS records were configured to validate '+
    'the raw public key, or DNS-based Authentication of Named Entities (DANE) '+
    'was not enabled on the connection.';




  //NTLM Messages - DES_set_key
  RSMsg_DES_set_key_wrong_key_parity = 'DES_set_key: Wrong Key Parity';
  RSMsg_DES_weak_key = 'DES_set_key: Weak key';

  // ECHStore meassages
  RSMsg_ECHStore_null_value_err = 'ECHStore can not be initialized with the NULL value.';
  RSMsg_ECHStore_new_config_err = 'ECHConfig initialization error.';
  RSMsg_ECHStore_pem_write_err = 'Failed to export ECHConfig to the PEM format.';
  RSMsg_ECHStore_pem_read_err = 'Failed to import ECHConfig from the PEM format.';
  RSMsg_ECHStore_keypem_read_err = 'Failed to import ECHConfig from the PEM format '+
    'or set a Private Key.';
  RSMsg_ECHStore_read_echconfiglist_err = 'Failed to set ECHConfigList.';
  RSMsg_ECHStore_too_long_echconfiglist_err = 'ECHConfigList exceeds the size limit.';
  RSMsg_ECHStore_num_err = 'Error getting number of ECHConfigList entries.';
  RSMsg_ECHStore_numkey_err = 'Error in counting the number of ECHConfigList private keys.';
  RSMsg_ECHStore_downselect_err = 'Error selecting ECHConfig number %d.';
  RSMsg_ECHStore_flushkeys_err = 'Error flushing ECH private keys.';
  RSMsg_ECHStore_getinfo_err = 'Error getting ECHStore info.';
  RSMsg_ECHStore_pemfmt_err = 'Failed to load ECHConfig. PEM format error.';
  RSMsg_ECHStore_stream_err = 'Stream is a NULL value. Failed to read from or write to it.';
  RSMsg_ECHStore_attachssl_err = 'Failed to attach ECH Store to SSL object.';
  RSMsg_ECHStore_attachsslctx_err = 'Failed to attach ECH Store to SSL context.';

  // ETaurusTLSECHRetryRequired
  RSMsg_ECHFailed_err = 'ECH Handshake failed with status code: %d';
  RSMsg_ECHRetryRequired_err = 'ECH Handshake error. Try to reconnect with updated ECH Config List.';
  RSMsg_ECHRejected_err = 'ECH Handshake failed. '+
    'The server rejected the key and provided no retry configuration.';
  RSMsg_ECHNotConfigured_err = 'The server may not support ECH, '+
    'the client does not send the extention, or a middlebox stripped the extension.';



implementation

end.
