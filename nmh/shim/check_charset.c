/*
 * Shim for nmh's check_charset(). NOT from nmh.
 *
 * fmt_rfc2047.c asks this whether the charset named in an encoded-word can
 * be handled "natively", meaning no conversion is required. Because this
 * build never defines HAVE_ICONV, a false answer makes the decoder leave
 * the encoded-word in the log verbatim, which is the behaviour we want for
 * every legacy charset: no iconv, no gconv modules loaded on a
 * sender-chosen name, and no loss -- an encoded-word is losslessly
 * decodable later by whatever reads the logs.
 *
 * A true answer means the decoded bytes are copied through unexamined, so
 * only charsets that already are UTF-8 (or a subset of it) may qualify.
 */

#include <string.h>
#include <strings.h>

#include "check_charset.h"

int check_charset(const char *str, int len)
{
    static const char *const native[] = { "UTF-8", "UTF8", "US-ASCII", "ASCII" };
    size_t i;

    if (str == NULL || len <= 0) {
        return 0;
    }

    for (i = 0; i < sizeof(native) / sizeof(native[0]); i++) {
        size_t n = strlen(native[i]);

        /* Exact length as well as prefix: "UTF-80" must not match "UTF-8".
         * nmh has already trimmed any RFC 2231 *lang suffix from len. */
        if ((size_t)len == n && strncasecmp(str, native[i], n) == 0) {
            return 1;
        }
    }
    return 0;
}
