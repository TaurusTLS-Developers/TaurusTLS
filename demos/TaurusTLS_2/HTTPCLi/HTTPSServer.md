# TaurusTLS OpenSSL Server Emulation Script

A semi-interactive Windows Command Prompt script (`server.cmd`) designed to emulate a TLS server using `openssl s_server`. It supports local PKI provisioning, direct connections (No-SNI), virtual host routing (SNI), and Encrypted Client Hello (ECH) for validating client implementations such as TaurusTLS.

---

## 1. Features

- **Semi-Interactive Execution**: Can be driven entirely by command-line arguments or via an interactive on-screen menu.
- **2-Tier PKI Provisioning**: Generates a self-signed Root CA, an Intermediate CA, full certificate chains for the server, and RFC 9934 ECH key material.
- **Multi-Host Routing**: Emulates multi-tenant TLS servers by utilizing OpenSSL's `-servername`, `-cert2`, and `-key2` contexts.
- **Artifact Management**: Includes automated cleanup routines to purge test certificates and keys from the working directory.

---

## 2. Requirements

- **Operating System**: Windows 10 / Windows 11 / Windows Server 2016+
- **OpenSSL**: OpenSSL 3.0+ (OpenSSL 3.4+ or 4.0 recommended for native RFC 9934 `openssl ech` CLI support).
  - Must be accessible via the system `PATH` or specified directly using `/O <path>`.

---

## 3. PKI Hierarchy & Artifacts

When running the PKI generation step (`/M pki` or Menu Option `1`), the script generates the following materials:

| Artifact | Type | Subject / Purpose |
| :--- | :--- | :--- |
| `ca_root.key` / `ca_root.crt` | Root CA | `CN=TaurusTLS Root CA` (Self-signed, `CA:TRUE`) |
| `ca_intermediate.key` / `ca_intermediate.crt` | Intermediate CA | `CN=TaurusTLS Intermediate CA` (Signed by Root CA, `pathlen:0`) |
| `ca_bundle.crt` | Trust Store | Concatenated `ca_intermediate.crt` + `ca_root.crt` |
| `ca.crt` | Client Anchor | Copy of `ca_root.crt` for client verification |
| `key_default.pem` / `cert_default.pem` | Default Server | `CN=localhost`<br>**SANs**: `127.0.0.1`, `::1`, `default.demo.tld`, `default`<br>Includes intermediate cert in chain. |
| `key_sni.pem` / `cert_sni.pem` | Virtual Host | `CN=sni.demo.tld`<br>**SANs**: `sni.demo.tld`, `sni`<br>Includes intermediate cert in chain. |
| `ech_keypair.pem` | Server ECH | Combined private key and `ECHConfigList` for `s_server -ech_key` |
| `ech_pub.pem` | Client ECH | Standalone public `ECHConfigList` (PEM format) for client distribution |

---

## 4. Command-Line Syntax

~~~text
server.cmd [/O <path>] [/M <mode>] [/P <port>] [/X '<extra_args>']
server.cmd [/? | -h | --help]