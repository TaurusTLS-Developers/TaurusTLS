# OpenSSL provider configuration examples

| File | Policy |
| --- | --- |
| [openssl-legacy.cnf](openssl-legacy.cnf) | Activates Default and Legacy, including algorithms used by LM/NTLMv1 |
| [openssl-fips.cnf](openssl-fips.cnf) | Activates FIPS and Base and selects fips=yes |

Choose one policy for the application. These examples configure providers; they
do not supply CA trust, certificates, private keys or a complete TLS policy.
Use the [migration guide](../../../Migration_to_1_1.md) for TaurusTLS integration.

## Deploy and select a configuration

Use modules compatible with the deployed OpenSSL runtime and process
architecture. Replace placeholder paths with your installation's absolute paths.
The samples show Unix-style paths and commented Windows alternatives. In OpenSSL
configuration files, forward slashes also work for Windows paths.

```pascal
Loader := GetOpenSSLLoader;
Loader.ConfigFile := ApplicationOpenSSLConfig;
Loader.RequireConfigFile := True;
if not Loader.Load then
  raise ETaurusTLSCouldNotLoadSSLLibrary.Create('OpenSSL startup failed');
```

Use TaurusTLSLoader and TaurusTLSExceptionHandlers; ApplicationOpenSSLConfig is
your application's absolute filename. Also handle exceptions from Load. Configure
before clients connect, servers activate or cryptographic operations begin.

## Legacy

Default is explicitly activated alongside Legacy so ordinary modern algorithms
remain available. For dynamic builds, use OpenSSL's module search path or edit the
commented module setting. For supported Delphi archive builds, add
TaurusTLS_ProviderLegacy, supply liblegacy.a and keep module unset so built-in
registration is used. Activation alone does not guarantee that MD4/DES are built
or permitted by all other application policy.

## FIPS installation

The comments in openssl-fips.cnf contain generation and verification commands.
Run fipsinstall using the appropriate OpenSSL CLI and deployed FIPS module,
following that module's Security Policy. Generate installation data before
selecting the main configuration, then update both its include and module paths.
Do not enable an incomplete FIPS main configuration in the CLI's OPENSSL_CONF
while trying to create its missing installation data. Do not edit generated
integrity values or use another installation's data as a generic template.

Base supplies supporting encoders/decoders. This sample does not activate Default
or Legacy; fips=yes selects FIPS-qualified algorithm implementations. TaurusTLS's
FIPS adapter supports dynamic loading, not its linked/imported build models.
Configuration/provider activation alone is not certification of an application.

After installation, validate in a fresh CLI process with OPENSSL_CONF set to the
adapted main configuration. For example:

```text
openssl list -providers
openssl dgst -propquery fips=yes -sha256 /path/to/test-data.txt
```

Use the [provider scenario runner](../../../Tests/TaurusTLS.UT.Providers.md) for
TaurusTLS-level validation. No generated fipsmodule.cnf or binary modules are
included with these examples.

References: [OpenSSL FIPS installation command](https://docs.openssl.org/3.0/man1/openssl-fipsinstall/)
and [FIPS module configuration](https://docs.openssl.org/3.0/man7/fips_module/).
