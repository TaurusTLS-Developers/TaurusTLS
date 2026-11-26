# IOHandler initialization and AutoLoad — detailed design

Status: Implemented design for TaurusTLS 1.1.
Release: TaurusTLS 1.1.
Reviewed: 2026-11-25 against current source and test definitions; no tests rerun.
Architecture: [High-level design](IOHandler_init_HLD.md).

## 1. Entry points and ordering

Client connection follows ConnectClient -> Init -> inherited ConnectClient ->
OnBeforeConnect -> StartSSL. Init therefore precedes transport/bind/proxy work.
ConnectClient temporarily sets fPassThrough=True around inherited processing
and restores the saved value in finally. Initialization exceptions are not
suppressed for initially plaintext connections.

Server activation prepares contexts in TTaurusTLSServerIOHandler.Init before
normal Indy listener operation. Accept validates shared runtime readiness,
fSSLContext and its native Context before constructing an accepted handler.
It copies AutoLoad, opens the handler in plaintext mode, accepts the transport,
copies server options, marks it as a peer, assigns a socket wrapper and the
prepared server context, then calls AfterAccept. A local handler is freed on
failure. AfterAccept calls inherited AfterAccept, Init and StartSSL, with an
outer Close-and-reraise handler.

The design relies on the normal Indy activation/shutdown ordering and serialized
component lifecycle. It does not introduce worker-thread context construction,
a lazy initialization state machine or a public PrepareTLS API.

## 2. Readiness helpers and exceptions

Client TryAutoLoad uses explicit branching: return True when the singleton is
ready; otherwise call Load only when fAutoLoad=True; otherwise return False.
Server TryAutoLoad expresses the same policy as:

```pascal
Result := LLoader.IsLoaded or (fAutoLoad and LLoader.Load);
```

The server helper is compiled with short-circuit evaluation forced by a scoped
{$B-} directive, restoring {$B+} afterward if necessary. Complete Boolean
evaluation elsewhere does not cause AutoLoad=False to invoke Load.

Both Init methods first reject fInitializing=True. After setting the guard,
they handle an existing context before attempting automatic loading: require
a ready runtime and a non-nil native Context, then return without rebuilding.
They never automatically reload OpenSSL in order to reuse an existing context.

For a new context, a False TryAutoLoad result maps as follows:

| Condition | Result |
| --- | --- |
| AutoLoad=False | ETaurusTLSLibraryNotLoaded |
| AutoLoad=True | ETaurusTLSCouldNotLoadSSLLibrary with RSOSSLCouldNotLoadSSLLibrary |
| Load itself raises | Original exception propagates |
| Recursive Init or missing native context | ETaurusTLSLoaderError with RSOSSLContextNotReady |

ETaurusTLSLibraryNotLoaded and ETaurusTLSCouldNotLoadSSLLibrary derive from
ETaurusTLSLoaderError. ETaurusTLSConfigFilePathError and
ETaurusTLSConfigFileLoadError derive from ETaurusTLSAPICryptoError, outside that
loader-error branch. All declarations are centralized in
TaurusTLSExceptionHandlers. IOHandler readiness errors do not need native
OpenSSL error-queue calls. No owner-level failure path resets the global loader.

## 3. Client context transaction

Init creates a local LContext only after obtaining runtime readiness. It assigns
Parent=Self, ClientCert public/private/root keys and DH parameters; verification
depth, mode, hostname, directories and system-store choice; bidirectional
shutdown; cipher list/suites and server preference; callback enable flags;
minimum TLS version, mode and security level; and OnContextLoaderCustom.

It calls LContext.InitContext(sslCtxClient), assigns fSSLContext only after
success, and clears the local reference. A finally block frees an untransferred
candidate. The outer finally always clears fInitializing.

OnContextLoaderCustom receives the candidate under construction. The handler's
SSLContext is not a published partial-context accessor. Callbacks must use the
supplied AContext and must not retain it, destroy/reinitialize the owner,
mutate construction configuration, or globally unload OpenSSL.

A borrowed server context follows the existing-context branch. Init does not
adopt it, replace it or create a second client context.

## 4. Server default/SNI transaction

Server Init uses a local LDefaultContext, an LCandidates array of contexts and
an LCertificates array capturing certificate-item identities. Array lengths
come from Certificates.Count before default-context construction.

1. Require runtime readiness and capture certificate items.
2. Build/configure the default context from DefaultCert and SSLOptions, setting
   Parent=Self and OnContextLoaderCustom; call InitContext(sslCtxServer).
3. When certificates exist, install the default context's SNI callback and its
   Self argument. Check both native return values.
4. Create each SNI candidate, store it in LCandidates immediately, copy its
   certificate material/options/callbacks and call InitContext(sslCtxServer).
5. Verify Certificates.Count and every item identity against LCertificates.
6. Transfer candidates into their certificate items and nil each local entry.
   Publish fSSLContext and nil LDefaultContext last.
7. In finally, free remaining candidates/default and clear fInitializing.

The native SNI callback setup precedes individual SNI construction; all setup
still finishes before publication. The default context copies VerifyDirs;
individual SNI candidates do not assign VerifyDirs in the current builder.
Other assignments must be read from their respective builders rather than
assuming the two sets are identical.

Publication performs reference transfers without allocations or callbacks.
A failure before publication leaves the new context set unpublished and frees
owned candidates. The identity checks detect collection count/item changes at
the final check; they are not permission for callbacks to mutate or free items
while construction is using them. Configuration mutation remains unsupported.

The server owns fSSLContext. Each certificate item owns its published Context.
No second owning bundle or native reference-counting policy is introduced.

## 5. Accepted handlers, factories and cloning

Accept assigns the complete server context before AfterAccept. Accepted handlers
and FTP server data-channel handlers borrow it; they do not own its lifetime.
MakeDataChannelIOHandler copies AutoLoad and options, marks the handler as a peer
and sets its callbacks. MakeFTPSvrPasv selects server mode and assigns SSLContext;
MakeFTPSvrPort selects client mode and assigns the same server-owned context.
MakeClientIOHandler copies AutoLoad/options and leaves SSLContext=nil for later
independent preparation.

Clone copies AutoLoad, hostname, options and callbacks. It creates an empty
Pascal socket wrapper but does not initialize OpenSSL or a native TLS session
merely by copying settings. The clone disables hostname verification for FTP
data-channel IP addressing and clears OnVerifyError. Preserve this existing
behavior rather than interpreting passive cloning as secure negotiation.

Handshake role follows fSSLContext.Mode; sslmBoth retains the IsPeer fallback.
IsPeer alone is not the ownership test: Close frees a context only when its
Parent is the current handler.

## 6. TLS transition and failure closure

StartSSL calls OpenEncodedConnection only when PassThrough=False. A later
SetPassThrough(False) uses the context prepared during Connect/AfterAccept.
OpenEncodedConnection does not call Init or Load as a fallback.

Its checked entry sequence is:

1. Set fPassThrough=False.
2. Reject nonempty plaintext input with ETaurusTLSError/RSOSSLUnreadPlaintext.
3. Require the shared loader to be ready.
4. Require fSSLContext and its native Context to be assigned.
5. Assert Binding<>nil; allocate a socket wrapper if needed and associate context.
6. Apply timeouts, select TLS role, resolve client hostname/proxy information and
   call socket Connect or Accept using Binding.Handle.
7. Invoke OnSSLNegotiated and retain fPassThrough=False.

Binding validation is an assertion, not an explicit Connected check. The normal
transport lifecycle is a prerequisite and is not strengthened by this document.

The outer exception handler clears InputBuffer and attempts Close. If cleanup
raises, it attempts inherited Close and suppresses that secondary cleanup error,
then re-raises the original negotiation/prerequisite/callback exception. A failed
upgrade never automatically resumes plaintext operation. Shared server contexts
and global runtime readiness are not invalidated by one peer's failure.

Returning to plaintext through the established FTP CCC/REIN path retains its
SSL_shutdown behavior; it does not unload OpenSSL or reconfigure providers.

## 7. Cleanup, retry and concurrency limits

Close releases fSSLSocket first. It frees fSSLContext only when Parent=Self and
detaches its reference in either ownership case. Borrowed contexts must outlive
all handlers and sessions using them.

Server Shutdown clears each certificate-item Context before freeing it, frees
the default context and calls inherited Shutdown. Indy/application teardown must
have retired workers before this point. The server destructor also frees the
default context and certificate collection, covering standalone handlers that
were initialized and destroyed without an Indy Shutdown call.

Failed context construction leaves the ready runtime available for another
explicit Init/connection/activation attempt after correcting the cause. Repeated
successful Init reuses its complete context set. Shutdown permits fresh server
construction on reactivation. Loader failure is different: its circuit breaker
requires an explicit reset after every native consumer has been retired.

No IOHandler destructor or Shutdown calls global Unload or OPENSSL_cleanup.
AutoLoad conveys neither a reference-counted runtime lease nor unloading rights.
The fInitializing guard rejects recursion only; it does not synchronize concurrent
calls or make live certificate replacement/configuration changes supported.

## 8. Regression mapping and evidence boundaries

The following are existing test definitions, not results of a new execution:

| Behavior | Existing regression definition |
| --- | --- |
| Client/server startup fails before useful connection/listening; plaintext does not suppress errors | TLoaderComponentFixture.IOHandler_StartupFailure |
| Client candidate rollback, retry, ready-runtime preservation and repeated Init reuse | TLoaderComponentFixture.Client_ContextFailureRetry |
| Default/first/last SNI failure, whole-set rollback, retry, Shutdown clearing and fresh reactivation | TLoaderComponentFixture.Server_ContextFailureRetry |
| Default False and ready/cold runtime handling | TLoaderComponentFixture.Client_AutoLoad; Server_AutoLoad |
| Copying AutoLoad through clones and factories | TLoaderComponentFixture.IOHandler_AutoLoadCopies |
| Boolean automatic-load failure and circuit-breaker behavior | TLoaderComponentFixture.Server_AutoLoadFailure |
| TLS negotiation and reconnect | TIOHandshake.Handshake; Reconnect |
| Text and binary exchange | TIOTransfer.Text; Bytes |
| Trust rejection and overlapping protocol versions | TIORejection.Untrusted; Versions |
| Plaintext-to-TLS upgrade and trust/peer failures | TIOStartTLS.Upgrade; Untrusted; PeerFailure |
| Negotiated callback failure, unread plaintext and server upgrade failure | TIOStartTLS.NegotiatedCallbackFailure; UnreadPlaintext; ServerFailure |

This mapping does not claim exhaustive test coverage. In particular, dedicated
IOHandler recursive-Init rejection, certificate-collection mutation detection,
complete-Boolean helper behavior, native SNI registration failure and every FTP
role/borrowed-lifetime permutation are not established by the named tests alone.
Those contracts are supported by source inspection here and remain candidates
for focused regression review. Loader callback reentry tests must not be counted
as IOHandler recursive-Init tests.

Old intermediate suite totals and local implementation checkpoints are omitted:
they are not acceptance evidence for every invariant above. The documentation
review performed no new build, test run, leak check or platform validation.
Historical memory investigations remain separate evidence; functional test
success must not be treated as proof that a reported teardown issue is resolved.

## 9. Related documentation

The migration guide already documents eager context preparation for initially
plaintext connections, default False AutoLoad, passive copying, early error
handling and explicit reset/unload responsibilities. Applications configure the
loader before Connect or server activation, not in later bind/listener callbacks.

- [High-level design](IOHandler_init_HLD.md)
- [IOHandler/context implementation](../../../Source/TaurusTLS.pas)
- [Shared loader](../../../Source/TaurusTLSLoader.pas)
- [Exceptions](../../../Source/TaurusTLSExceptionHandlers.pas)
- [Resource strings](../../../Source/TaurusTLS_ResourceStrings.pas)
- [Loader and component tests](../../../Tests/TaurusTLS.UT.Loader.pas)
- [Loopback integration tests](../../../Tests/TaurusTLS.IT.IOHandlers.pas)
- [Migration guide](../../../Migration_to_1_1.md)
