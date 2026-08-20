# TaurusTLSHeaderCheck

A small self-contained Delphi console tool that verifies the **three declarations of
every OpenSSL binding in the TaurusTLS headers agree with each other**.

This is the checker offered in the follow-up to issues #59 / #60.

## Why this exists

In `TaurusTLSHeaders_*.pas` every imported OpenSSL routine is declared in **three**
separate places:

| # | Site | Looks like | Used by |
|---|------|-----------|---------|
| 1 | dynamic-load typedef | `EVP_DigestSign: function(ctx: PEVP_MD_CTX; ...): TIdC_INT; cdecl = nil;` | Windows / desktop (`OPENSSL_STATIC_LINK_MODEL` off) |
| 2 | static external | `function EVP_DigestSign(ctx: PEVP_MD_CTX; ...): TIdC_INT cdecl; external CLibCrypto;` | iOS / Android / static linking |
| 3 | `ERR_` fallback stub | `function ERR_EVP_DigestSign(ctx: PEVP_MD_CTX; ...): TIdC_INT; cdecl;` | raised when the symbol is absent |

All three must have **identical signatures**. Nothing in the compiler enforces this,
because only one of them is ever compiled into a given build configuration.

The practical consequences we hit downstream:

* A wrong type in the **typedef** breaks Windows but leaves iOS/Android building fine.
* A wrong type in the **static external** breaks iOS/Android but leaves Windows fine.
* A wrong type in the **`ERR_` stub** breaks whichever configuration falls back to it.

So a defect can sit in the tree for a long time, and — worse — *fixing one site looks
exactly like the fix did not take effect*, because the platform you are testing on
compiles a different site. That cost real time on both sides of #59/#60: several of the
follow-up rounds were single sites that had been missed.

This tool checks all three against each other in about **1.4 seconds** for the whole
`Source` folder, so the class of defect simply cannot reach a release again.

## Building

Requires only the Delphi command-line compiler; no third-party units.

```
build.bat
```

or directly:

```
dcc32 -B TaurusTLSHeaderCheck.dpr
```

It compiles clean with no warnings or hints on Delphi 13 (`dcc32` 37.0), and uses only
`System.SysUtils`, `System.Classes`, `System.StrUtils`, `System.IOUtils`, `System.Math`
and `System.Generics.*`, so it should build on any reasonably modern version.

## Usage

```
TaurusTLSHeaderCheck [options] [<dir-or-file> ...]

  -r, --recursive   recurse into subdirectories
  -q, --quiet       only print mismatches and the summary
  -v, --verbose     print each file as it is scanned
      --no-color    disable ANSI colour
      --strict      also fail on cosmetic const/var/out differences
  -h, --help        show help
```

With no path given, the current directory is scanned.

| Exit code | Meaning |
|---|---|
| `0` | consistent |
| `1` | mismatches found |
| `2` | usage error |

Typical invocation:

```
TaurusTLSHeaderCheck TaurusTLS\Source
```

## What it reports today

Run against the current `main` (the drop after the #59/#60 fixes), it reports
**4 real mismatches and 1 cosmetic difference** out of 4,388 routines that are declared
in more than one place. Each has been checked by hand:

```
ASN1_d2i_bio - declarations disagree
    * parameter count: static external has 4, ERR_ stub has 3
      static external  TaurusTLSHeaders_asn1.pas:1434
                         (pxnew; pd2i_of_void; pbio; ppointer): pointer
      ERR_ stub        TaurusTLSHeaders_asn1.pas:3136
                         (const pasn1_item; pbio; pointer): pointer
```
The stub was copied from `ASN1_item_d2i_bio`. The typedef and external agree and match
`ASN1_d2i_bio(void *(*xnew)(void), d2i_of_void *d2i, BIO *in, void **x)`.

```
AUTHORITY_KEYID_free - declarations disagree
    * parameter 1 type: static external says authority_keyid, ERR_ stub says pauthority_keyid
      static external  TaurusTLSHeaders_x509v3.pas:1382   (authority_keyid)
      ERR_ stub        TaurusTLSHeaders_x509v3.pas:2788   (pauthority_keyid)
```
The static external takes the opaque record **by value** instead of by pointer — the
same shape as the `EVP_MD_CTX` problem from #60. The typedef (line 1044) is correct.

```
BIO_ADDR_rawaddress - declarations disagree
    * parameter 3 type: static external says pidc_sizet, ERR_ stub says tidc_sizet
      static external  TaurusTLSHeaders_bio.pas:1588   (const pbio_addr; pointer; var pidc_sizet): tidc_int
      ERR_ stub        TaurusTLSHeaders_bio.pas:3280   (const pbio_addr; pointer; var tidc_sizet): tidc_int
```
`var l: PIdC_SIZET` is a `size_t **`. The typedef at line 1069 has `var l: TIdC_SIZET`,
matching `BIO_ADDR_rawaddress(const BIO_ADDR *ap, void *p, size_t *l)`. Note the
commented-out line 1067 just above shows the older `l: PIdC_SIZET` form, which is
presumably where the external's version came from.

```
CTLOG_get0_log_id - declarations disagree
    * parameter 2 type: static external says pidansichar, ERR_ stub says ppidansichar
      static external  TaurusTLSHeaders_ct.pas:404   (const pctlog; const pidansichar; tidc_sizet)
      ERR_ stub        TaurusTLSHeaders_ct.pas:881   (const pctlog; const ppidansichar; tidc_sizet)
```
`CTLOG_get0_log_id(const CTLOG *log, const uint8_t **log_id, size_t *log_id_len)` — the
typedef at line 273 has `PPIdAnsiChar` and is correct; the external is one indirection short.

And the cosmetic one, reported as a warning and not failing the build unless `--strict`:

```
SCT_LIST_print - declarations differ cosmetically
    * parameter 4 modifier: static external says "", ERR_ stub says "const"  (cosmetic)
```

## How it works, and its limits

It is a standalone lexer — it does **not** need the units to compile, resolve `uses`,
or evaluate conditionals, so it can be run on the raw tree.

* Comments (`//`, `{ }`, `(* *)`) and quoted strings are blanked **preserving length**,
  so reported line numbers stay exact. Strings must be blanked because of
  `external CLibCrypto name 'OPENSSL_sk_value';`.
* Handles the real shapes in these headers: declarations spanning several lines,
  a declaration spanning several `;`-separated clauses
  (`function f(...): X; cdecl; external CLibCrypto name '...';`), semicolons inside
  parameter lists, `procedure` as well as `function` forms, grouped parameters
  (`write_p, version, content_type : TIdC_INT` counts as three), and no-parameter forms.
* Only `cdecl` declarations are considered.
* `ERR_` stubs are matched back to their routine **only when the remainder is a routine
  that actually exists**, so genuine OpenSSL `ERR_*` routines — whose stubs are
  `ERR_ERR_get_error` and friends — are mapped correctly rather than being mangled.
* Parameter **names** are ignored; only types, modifiers, arity and return type matter.
* Known-equivalent spellings are folded together before comparison
  (`TIdAnsiChar` = `AnsiChar`, `PIdAnsiChar` = `PAnsiChar`, …) so they are not reported
  as differences. The table is `CTypeAliases` near the top of the source, and is easy
  to extend.
* Where a routine is declared more than once in one category (conditional-compilation
  variants), the first is used.
* Types are compared **textually after normalisation** — it will not notice that two
  differently-named types happen to be structurally identical. In this codebase that is
  the desired behaviour, since the naming is consistent by convention.

Files are read as ANSI, matching the encoding of the existing headers.

## Suggested CI use

```yaml
- name: Check TaurusTLS header consistency
  run: |
    dcc32 -B Tests\TaurusTLSHeaderCheck\TaurusTLSHeaderCheck.dpr
    Tests\TaurusTLSHeaderCheck\TaurusTLSHeaderCheck.exe --no-color TaurusTLS\Source
```

The non-zero exit code fails the build. If you would rather land the tool first and
fix the four findings afterwards, run it with `-q` and treat it as advisory until the
tree is clean.

## Validation

* **Positive control** — run against a snapshot of the headers from before the #59/#60
  fixes, it reports 17 mismatches, including every defect that was found by hand
  (`sk_ASN1_GENERALSTRING_value/_new/_push/_find`, the `sk_ASN1_*_push/_find` family,
  `sk_IPAddressFamily_*`) plus `ASN1_d2i_bio` and `AUTHORITY_KEYID_free`, which the
  manual review had missed because it never compared the `ERR_` stubs.
* **Negative control** — the dynamic-vs-static dimension alone is now clean on `main`;
  everything remaining is on the `ERR_` stub side.
* **Robustness** — scanned 5,217 mixed Delphi files (a full third-party component tree,
  including non-TaurusTLS code) without crashing or hanging.

Public domain / do whatever you like with it — no attribution needed.
