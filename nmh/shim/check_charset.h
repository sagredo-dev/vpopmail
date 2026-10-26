/*
 * Shim for nmh's check_charset.h. NOT from nmh.
 * On the include path only when compiling nmh/fmt_rfc2047.c.
 */

#ifndef VPOPMAIL_NMH_SHIM_CHECK_CHARSET_H
#define VPOPMAIL_NMH_SHIM_CHECK_CHARSET_H

/* Returns non-zero if fmt_rfc2047.c may copy decoded bytes of this
 * charset straight through, i.e. the charset is UTF-8 or a subset of it.
 * `len` bounds `str`; it is not NUL-terminated at len. */
int check_charset(const char *str, int len);

/* Only referenced under HAVE_ICONV in fmt_rfc2047.c; declared so the
 * header matches upstream's. Deliberately not defined. */
char *get_charset(void);

#endif /* VPOPMAIL_NMH_SHIM_CHECK_CHARSET_H */
