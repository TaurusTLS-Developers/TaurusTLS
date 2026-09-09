# TaurusTLS 2.0 HTTPS Client Socket Demo

This console demonstration presents the core **TaurusTLS 2.0 Client SSL Socket** architecture, illustrating low-level socket state machine execution, immutable context snapshots, and the fluent context builder pattern without the high-level Indy `IOHandler` layer.

---

## 1. Scope & Architectural Context

*   **Current Focus:** This demo demonstrates the low-level **Data Plane** (`TTaurusTLSClientSocket`, `ITaurusTLSSslSocketCtx`, and `TTaurusTLSSslClientSocketCtxBuilder`).
*   **Relationship to `IOHandler`:** Full `TTaurusTLSIOHandlerSocket` component integration is under active development. This demo illustrates the exact lifecycle operations that the future `IOHandler` will execute under the hood: establishing a raw TCP socket, compiling an immutable snapshot via the builder, instantiating the socket state machine, and driving the handshake to `seEstablished`.
*   **Dual-Track Performance:** Demonstrates how connection threads read directly from the immutable context snapshot with zero interface dispatch overhead during active network I/O.

---

## 2. Client SNI and ECH Modes

The `-m <MODE>` parameter controls how the client presents server names and cryptographic privacy extensions on the wire:

| Mode Identifier | Enum Value | Description |
| :--- | :--- | :--- |
| **`Direct`** | `csmDisabled` | **Direct Connection (No SNI):** Completely suppresses the `server_name` (SNI) extension on the wire. Required by RFC 3546 when connecting directly to raw IP addresses, or in high-privacy setups where domain fronting or server name leakage must be avoided. Peer certificate verification is still performed against the target host/IP. |
| **`SNI`** | `csmStandardSNI` | **Standard Cleartext SNI:** Emits standard unencrypted SNI on the wire using the target `HostName` (or overridden by `-s <SNI>`). Used for standard web access to route connections to specific virtual hosts on shared web servers. |
| **`ECHGrease`** | `csmECHGrease` | **Anti-Ossification GREASE:** Emits the real target domain in cleartext SNI alongside an un-decryptable synthetic ECH extension (random dummy noise). **Use-case:** Generates ECH traffic patterns to prevent network middleboxes and firewalls from ossifying and blocking ECH packets. If the server supports ECH and returns `retry_configs`, the client ignores them and stays connected over cleartext SNI with zero latency penalty. |
| **`ECHGreaseDiscover`**| `csmECHGreaseDiscovery` | **ECH Bootstrapping / Key Discovery:** Probes the server to discover its public ECH keys without leaking the private target domain in cleartext (omits cleartext SNI unless an explicit public decoy is specified via `-s`). If the server supports ECH, it returns `retry_configs`. The client extracts the keys, aborts the initial connection, upgrades its mode to `csmECH`, and reconnects securely with real encryption. |
| **`ECH`** | `csmECH` | **Standard Strict ECH:** Encrypts the true target domain (`Identity`) inside the ECH extension using the provided `-e <ECHConfig>` (Base64). Emits the public decoy (`public_name` from the config or overridden via `-s <SNI>`) in the unencrypted outer SNI so CDN edge routers can route the packet. Aborts with a downgrade error if the server bypasses ECH. |
| **`ECHNoOuter`** | `csmECHNoOuter` | **Private Strict ECH (No Outer SNI):** Encrypts the true target domain inside the ECH extension, but **completely omits the outer SNI extension on the wire (`no_outer = 1`)**. Guarantees zero domain name leakage in plaintext. Required for dedicated IP servers or specialized private gateways. |

---

## 3. Command-Line Syntax

~~~text
HTTPSDemo -d <URL> -m <MODE> [-s <SNI>] [-e <ECHConfig>] [-t <TrustStore>] [-l <OpenSSLPath>]