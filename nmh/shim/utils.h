/*
 * Shim for nmh's utils.h. NOT from nmh.
 * On the include path only when compiling nmh/fmt_rfc2047.c.
 */

#ifndef VPOPMAIL_NMH_SHIM_UTILS_H
#define VPOPMAIL_NMH_SHIM_UTILS_H

#include <stddef.h>

/* fmt_rfc2047.c uses mh_xmalloc() only under HAVE_ICONV, which this build
 * never defines. Declared but deliberately not defined, so that an
 * accidental iconv build fails at link time rather than silently picking
 * up a malloc that does not abort on failure. */
void *mh_xmalloc(size_t size);

#endif /* VPOPMAIL_NMH_SHIM_UTILS_H */
