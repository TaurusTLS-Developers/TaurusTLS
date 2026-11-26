# IOHandler initialization and AutoLoad — high-level design

Status: Implemented design for TaurusTLS 1.1.
Release: TaurusTLS 1.1.
Reviewed: 2026-11-25 against the current source and test definitions.
Detail: [Detailed design](IOHandler_init_DDD.md).

## Scope and initialization boundary

This document describes TTaurusTLSIOHandlerSocket and TTaurusTLSServerIOHandler
in TaurusTLS.pas. Indy IOHandler Init prepares TLS capability before a client
connects or a server begins accepting connections. This applies even when the
connection starts in plaintext with PassThrough=True.

Constructing an IOHandler, assigning properties, or copying AutoLoad does not
load OpenSSL. Init is the preparation boundary. StartSSL and
OpenEncodedConnection subsequently create/negotiate connection sessions; they
do not perform fallback context construction or automatic loading.

## Runtime readiness and configuration

Both AutoLoad properties default to False. A ready shared runtime is reused
with either setting. Otherwise AutoLoad=True permits Init to call the shared
loader, while AutoLoad=False raises ETaurusTLSLibraryNotLoaded. A False Load
result raises ETaurusTLSCouldNotLoadSSLLibrary; exceptions raised by Load
propagate unchanged.

AutoLoad does not select library paths, configuration files or providers, reset
a failed loader, acquire a runtime lease, or take responsibility for Unload.
Select shared policy before Connect or server activation. In particular,
OnBeforeConnect runs after client context preparation and is too late to
configure the first context. Use an ordinary Indy IOHandler when plaintext
traffic must operate without OpenSSL.

## Preparation and publication

Client Init builds a local TTaurusTLSContext, copies its options and callbacks,
and completes InitContext before publishing the context. Failure frees the
candidate without retaining a partially initialized context.

Server Init builds the default context and all configured SNI contexts before
publishing any of them. It checks native SNI callback setup and verifies that
the certificate collection still has the captured count and item identities.
Publication transfers references without allocations or callbacks. The server
owns the default context; certificate items own the individual SNI contexts.

Both Init implementations reject recursive initialization with an internal
Boolean guard. An existing context is reused only while the shared runtime is
ready and the native context pointer is non-nil. The guards do not make
concurrent activation, shutdown or property mutation supported.

## Connections and ownership

| Operation | Behavior |
| --- | --- |
| Client ConnectClient | Init precedes inherited transport/proxy setup; PassThrough is temporarily enabled for that setup and restored in finally |
| Server Init | Prepares the complete context set during activation, before listener operation |
| Server Accept | Checks runtime/context readiness, assigns the server context to the accepted handler, then invokes AfterAccept |
| AfterAccept | Runs inherited handling, Init and StartSSL; closes and re-raises on failure |
| Clone and server factories | Copy AutoLoad passively; preserve client/peer context and FTP role conventions |
| StartSSL | Opens the secure connection only when PassThrough=False |
| OpenEncodedConnection | Rejects unread plaintext, requires runtime/context readiness, associates a connection session and negotiates |

Accepted handlers borrow server contexts. Client-owned contexts are identified
by their Parent, rather than IsPeer alone. Each handler owns its connection
session wrapper. SSLOptions.Mode determines handshake role, with the existing
IsPeer fallback for sslmBoth. FTP clone hostname verification remains disabled
for data-channel IP addresses.

## STARTTLS and failure handling

Context preparation does not prove that negotiation or peer validation will
succeed. STARTTLS uses the previously prepared context on the existing transport.
Unread plaintext is rejected before TLS negotiation. A failed upgrade clears
buffered input, closes the connection and preserves the original exception;
it does not resume plaintext processing or unload the shared runtime.

OpenEncodedConnection asserts that Binding is assigned. It does not add a
separate explicit Connected check; normal Indy connection lifecycle remains a
prerequisite. This distinction matters in builds where assertions are disabled.

## Shutdown and recovery

Connection Close frees the session before its owned context; borrowed server
contexts remain server-owned. Server Shutdown clears and frees each SNI item
context, frees the default context, and invokes inherited Shutdown. The server
destructor also releases its owned state, including when a standalone handler
was never shut down through Indy.

Retire accepted workers and native consumers before freeing their contexts or
unloading OpenSSL. Neither IOHandler shutdown nor destruction invokes global
Unload or OPENSSL_cleanup. A context-construction failure can be retried after
correcting settings while OpenSSL remains ready. Loader failure still requires
an explicit global reset after retiring every consumer. Live global unload and
reuse of stale contexts are unsupported.

## Verification and compatibility

The detailed design maps behavior to existing regression definitions, including
client failure/retry, server default/SNI rollback and reactivation, startup
failure, AutoLoad propagation, TLS negotiation and STARTTLS rejection/cleanup.
This review did not run tests and does not establish a new platform acceptance
result or resolve historical memory-investigation findings.

Both linking models use the shared readiness contract. These documents make no
additional FPC, mobile or provider-certification claims. Configuration and loader
exception declarations reside in TaurusTLSExceptionHandlers; configuration
exceptions retain their crypto-error hierarchy.

## References

- [Detailed design](IOHandler_init_DDD.md)
- [Implementation](../../../Source/TaurusTLS.pas)
- [Shared loader](../../../Source/TaurusTLSLoader.pas)
- [Central exceptions](../../../Source/TaurusTLSExceptionHandlers.pas)
- [Migration guide](../../../Migration_to_1_1.md)
- [Provider architecture](../Providers/openssl_providers_HLD.md)
