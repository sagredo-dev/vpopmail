# nmh RFC 2047 decoder (embedded)

Third-party code, embedded unmodified, in the same manner as `cdb/`.

`fmt_rfc2047.c` decodes RFC 2047 encoded-words — the `=?UTF-8?B?...?=` form that
carries non-ASCII text in mail headers — so that logged header fields can be
read as text rather than as their encoded form.

## Provenance

| | |
|---|---|
| Project | nmh (new MH), the Mail Handling System |
| Upstream | https://cgit.git.savannah.nongnu.org/cgit/nmh.git |
| Files taken | `sbr/fmt_rfc2047.c`, `sbr/fmt_rfc2047.h`, `COPYRIGHT` |
| Fetched | 2026-09-22 from the `master` branch |
| Modified | **No.** Byte-identical to upstream. |

SHA-256 as fetched:

    4f06da0edd5719e0fa5deacaefc95846224c9b6f522476d5d9acf2e6012d60af  fmt_rfc2047.c
    74728fc9857db05380962d1b6c25966dbb9ad566f241aa0f885fdc9393ffa282  fmt_rfc2047.h
    b07de4560d44c58b14fab98112c031b6cba0e37c9944d977eeb8743492a954be  COPYRIGHT

## Licence

nmh is distributed under a three-clause BSD licence; the full text is in
`COPYRIGHT` alongside this file, which is what clause 1 requires of a source
redistribution. The copyright notices at the top of `fmt_rfc2047.c` and
`fmt_rfc2047.h` are part of that obligation and must not be removed.

BSD-3-Clause imposes no conditions that conflict with this project's GPL v3,
so the combination is distributable under the GPL.

Clause 3 forbids using the nmh authors' names to endorse or promote derived
work. Nothing here should be read as nmh endorsing this project.

## Do not edit these files

Every local modification turns a future security update into a manual merge,
and in practice that is how embedded copies stop being updated at all. Keep
them byte-identical; put all adaptation in a separate shim that this project
owns.

## HAVE_ICONV is deliberately not defined

`fmt_rfc2047.c` is compiled without `HAVE_ICONV`, and iconv is not linked.

Upstream uses iconv to convert an encoded-word from whatever charset it
declares into the locale's. Doing that here would mean loading gconv modules
named by a sender-supplied string, inside a delivery process: glibc's iconv
carries charset converters that have had memory-safety bugs (CVE-2024-2961
among them), and the charset name in an encoded-word is chosen by whoever
sent the mail. It would also add a build dependency on every platform, since
iconv is in libc on Linux and the BSDs but a separate library on macOS.

Without it, `check_charset()` decides: charsets it accepts are decoded, and
every other encoded-word is left in the log exactly as it arrived. That
loses nothing, because an encoded-word is losslessly decodable later by
whatever reads the logs, and it is the behaviour this project had before the
decoder was added.

iconv would have validated UTF-8 as a side effect of converting. Since we do
not convert, the decoded bytes are the sender's bytes verbatim, so a
sanitiser is required regardless — see `sanitise_utf8()` in `header_text.c`.
That check is needed either way, so iconv would have bought only legacy
charsets, which we are content to log raw.

## The shim

Everything under `nmh/shim/` is **ours**, not upstream's. It exists so the
files above can stay byte-identical while compiling outside nmh's tree, and
it is on the include path only when compiling `nmh/fmt_rfc2047.c`, so these
stand-in headers cannot leak into the rest of the project.

| file | provides |
|---|---|
| `shim/h/mh.h` | `NUL`, `NMH_UNUSED`, `CONST`, and the libc headers mh.h would have pulled in |
| `shim/check_charset.h` | declares `check_charset()` and `get_charset()` |
| `shim/check_charset.c` | `check_charset()`: accepts UTF-8, UTF8, US-ASCII, ASCII, case-insensitively and on an exact length match |
| `shim/utils.h` | declares `mh_xmalloc()` |

`get_charset()` and `mh_xmalloc()` are referenced by `fmt_rfc2047.c` only
under `HAVE_ICONV`. They are declared but deliberately **not defined**, so
that a build which switches iconv on fails at link time rather than silently
picking up a `malloc` that does not abort on failure.

The public entry point is:

```c
ssize_t decode_rfc2047(char *src, char *dest, size_t dest_len,
                       const char *dest_charset);
```

returning the decoded length excluding the terminating NUL, or -1. Use the
return value rather than `strlen(dest)`: the base64 path can emit NUL bytes.
`dest_charset` is unused without iconv; pass NULL.

## Updating

1. Re-fetch the three files from the upstream URL above.
2. `diff` against these copies — with no local edits, the diff is upstream's.
3. Update the hashes and the fetched date in this file.
4. Rebuild and re-run the header-handling tests.

Because RFC 2047 has been frozen since 1996, this file has no feature churn:
any upstream change to it is a bug fix or a security fix. Nothing notifies
this repository when that happens, so the diff above is worth running
periodically rather than only on demand.
