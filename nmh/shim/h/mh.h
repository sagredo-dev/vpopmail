/*
 * Shim for nmh's h/mh.h, providing only what nmh/fmt_rfc2047.c uses.
 *
 * This file is NOT from nmh. It exists so that the embedded upstream
 * source can stay byte-identical while compiling outside nmh's tree.
 * It is on the include path only when compiling nmh/fmt_rfc2047.c.
 */

#ifndef VPOPMAIL_NMH_SHIM_MH_H
#define VPOPMAIL_NMH_SHIM_MH_H

#include <sys/types.h>   /* ssize_t */
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <stdlib.h>

#define NUL '\0'
#define NMH_UNUSED(x) ((void)(x))
#define CONST            /* nmh: __attribute__((const)) when available */

/* ICONV_CONST deliberately undefined: HAVE_ICONV is never defined here. */

#endif /* VPOPMAIL_NMH_SHIM_MH_H */
