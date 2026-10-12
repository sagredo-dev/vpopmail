/*
 * header_text.h - storing, decoding and sanitising RFC 5322 header field
 * values for logging.
 *
 * Split out of gelf.c so that it can be unit tested without gelf.c's curl,
 * cJSON and inih dependencies. See tests/test_headers.c.
 */

#ifndef HEADER_TEXT_H
#define HEADER_TEXT_H

#include <stdbool.h>
#include <stddef.h>

/* Default size of a stored header field value, including the NUL. */
#define HEADER_VALUE_MAX 512

/* For the headers that routinely run long: Received, Authentication-Results
 * and X-Spam-Status. */
#define HEADER_VALUE_LONG_MAX 1024

/*
 * Stage 1: append one physical header line to field[] (size bytes, at least
 * 5), unfolding. The bytes are stored as they arrived, so the field is not
 * safe to log until stage 2 has run over the completed field. Returns true
 * if input was lost because the field is full; pass that on as was_cut.
 */
bool store_header_value(char *field, size_t size, const char *src);

/*
 * Stage 2 for a field we don't decode: reduce it in place to valid UTF-8
 * without controls, bidi or zero-width characters.
 *
 * Nothing is lost without the caller being able to find out. Either
 * pointer may be NULL if the caller doesn't need that report:
 *   *repaired  - set if any byte was replaced: an invalid byte or a rejected
 *                character became U+FFFD, or a tab became a space.
 *   *truncated - set if this call cut the value (on a character) and
 *                appended "...", because was_cut said input was already
 *                lost or the result didn't fit. It reports what was done,
 *                not what the text looks like: a value that arrives ending
 *                in "..." is not truncated. Also set if size is below 5,
 *                in which case the field is emptied rather than left raw.
 */
void sanitise_inplace(char *field, size_t size, bool was_cut,
                      bool *repaired, bool *truncated);

/*
 * Stage 2 for a field we decode: decode RFC 2047 encoded-words (UTF-8 and
 * US-ASCII only; other charsets are left encoded, and that is not reported),
 * then sanitise as sanitise_inplace() does, with the same two optional
 * reports. Decoding itself is not a repair.
 */
void decode_header_field(char *field, size_t size,
                         bool *repaired, bool *truncated);

bool extract_address(const char *v, char *out, size_t outsize);

#endif /* HEADER_TEXT_H */
