/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

/*
 * header_text.c - storing, decoding and sanitising RFC 5322 header field
 * values for logging.
 *
 * Two stages. store_header_value() only assembles a value: it trims, joins
 * folded lines and truncates, keeping the bytes exactly as they arrived.
 * Once the whole field has been read, decode_header_field() (for the fields
 * we decode) or sanitise_inplace() (for the rest) makes it safe to log.
 * Nothing is replaced before decoding, so the decoder sees what the sender
 * sent, and the one sanitising pass sees the final bytes.
 *
 * Split out of gelf.c so that it can be unit tested without gelf.c's curl,
 * cJSON and inih dependencies.
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "header_text.h"

/* nmh's fmt_rfc2047.h uses ssize_t and the CONST macro. */
#ifndef CONST
#define CONST
#endif
#include "nmh/fmt_rfc2047.h"

/* U+FFFD REPLACEMENT CHARACTER, as UTF-8. */
static const char replacement[] = "\xEF\xBF\xBD";
#define REPLACEMENT_LEN 3

#define TRUNCATION_MARKER "..."
#define TRUNCATION_MARKER_LEN 3

/* The longest input a sanitising pass accepts. Larger than any field, so
 * that decode_rfc2047() can never fill its buffer (see decode_header_field). */
#define RAW_MAX (2 * HEADER_VALUE_LONG_MAX)


/* Append the value portion of one physical header line to field[] (size
 * bytes), trimming leading whitespace and trailing CRLF. If field[] already
 * has content (fold continuation), a single space is inserted first, which
 * is correct RFC 5322 unfolding.
 *
 * The bytes are copied as they are: nothing is checked or replaced here, so
 * field[] is NOT safe to log until decode_header_field() or
 * sanitise_inplace() has run over the completed field.
 *
 * Returns true if input was lost because field[] is full. What fits is kept,
 * cut before any UTF-8 sequence that would otherwise be split; the caller
 * remembers the loss and passes it on (was_cut), which is what adds "...".
 * A size below 5 stores nothing and returns true.
 */
bool store_header_value(char *field, size_t size, const char *src) {
  size_t used;
  size_t room;
  size_t n;
  size_t k;

  if (size < TRUNCATION_MARKER_LEN + 2) {
    return true;                    /* no room for even one byte and "..." */
  }

  while (*src == ' ' || *src == '\t') {
    ++src;
  }
  n = strlen(src);
  while (n > 0 && (src[n - 1] == '\n' || src[n - 1] == '\r')) {
    --n;
  }
  if (n == 0) {
    return false;
  }

  used = strlen(field);
  if (used > 0) {
    if (used + 1 > size - 1) {
      return true;
    }
    field[used++] = ' ';
    field[used] = '\0';
  }

  room = size - 1 - used;
  if (n <= room) {
    memcpy(field + used, src, n);
    field[used + n] = '\0';
    return false;
  }

  /* Cut at room, unless that lands inside a UTF-8 sequence: then cut before
   * its lead byte. Raw bytes may not be UTF-8 at all, in which case nothing
   * looks like a lead byte and the cut stays where it is. */
  k = room;
  if (((unsigned char)src[k] & 0xC0) == 0x80) {
    size_t j = k;

    while (j > 0 && k - j < 3 && ((unsigned char)src[j - 1] & 0xC0) == 0x80) {
      j--;
    }
    if (j > 0 && (unsigned char)src[j - 1] >= 0xC0) {
      k = j - 1;
    }
  }
  memcpy(field + used, src, k);
  field[used + k] = '\0';
  return true;
}


/*
 * Decode one UTF-8 sequence from s[0..n-1] per RFC 3629 / Unicode Table 3-7.
 * Returns 1 and sets *cp and *seqlen for a well-formed sequence; returns 0
 * for anything else, including overlong encodings, surrogates, code points
 * above U+10FFFF, stray continuation bytes and sequences truncated by n.
 *
 * The byte ranges below are Table 3-7 transcribed directly: encoding the
 * constraints in the lead-byte dispatch is what excludes overlongs and
 * surrogates, rather than decoding first and range-checking afterwards.
 */
static int utf8_next(const unsigned char *s, size_t n,
                     unsigned long *cp, size_t *seqlen) {
  unsigned char lo;
  unsigned char hi;
  unsigned long acc;
  size_t need;
  size_t i;

  if (n == 0) {
    return 0;
  }

  if (s[0] <= 0x7F) {
    *cp = s[0];
    *seqlen = 1;
    return 1;
  } else if (s[0] >= 0xC2 && s[0] <= 0xDF) {
    need = 1; lo = 0x80; hi = 0xBF; acc = s[0] & 0x1FUL;
  } else if (s[0] == 0xE0) {
    need = 2; lo = 0xA0; hi = 0xBF; acc = s[0] & 0x0FUL;
  } else if (s[0] >= 0xE1 && s[0] <= 0xEC) {
    need = 2; lo = 0x80; hi = 0xBF; acc = s[0] & 0x0FUL;
  } else if (s[0] == 0xED) {
    need = 2; lo = 0x80; hi = 0x9F; acc = s[0] & 0x0FUL;  /* excludes surrogates */
  } else if (s[0] >= 0xEE && s[0] <= 0xEF) {
    need = 2; lo = 0x80; hi = 0xBF; acc = s[0] & 0x0FUL;
  } else if (s[0] == 0xF0) {
    need = 3; lo = 0x90; hi = 0xBF; acc = s[0] & 0x07UL;  /* excludes overlongs */
  } else if (s[0] >= 0xF1 && s[0] <= 0xF3) {
    need = 3; lo = 0x80; hi = 0xBF; acc = s[0] & 0x07UL;
  } else if (s[0] == 0xF4) {
    need = 3; lo = 0x80; hi = 0x8F; acc = s[0] & 0x07UL;  /* excludes > U+10FFFF */
  } else {
    return 0;  /* C0, C1, F5..FF, and stray continuation bytes 80..BF */
  }

  if (n < need + 1) {
    return 0;  /* truncated */
  }
  for (i = 1; i <= need; i++) {
    unsigned char c = s[i];
    unsigned char clo = (i == 1) ? lo : 0x80;
    unsigned char chi = (i == 1) ? hi : 0xBF;

    if (c < clo || c > chi) {
      return 0;
    }
    acc = (acc << 6) | (c & 0x3FUL);
  }

  *cp = acc;
  *seqlen = need + 1;
  return 1;
}


/*
 * Code points that are well-formed UTF-8 but must not reach the log.
 * Controls would be escaped by the JSON writer but are meaningless in a
 * header value; the bidi and invisible characters are display attacks -
 * U+202E can make a logged subject render as something it is not, and
 * invisible ones can hide text from a person reading the log. Variation
 * selectors are kept: U+FE0F is part of ordinary emoji.
 */
static int cp_rejected(unsigned long cp) {
  return (cp <= 0x1F)                      /* C0 controls (tab handled first) */
      || (cp == 0x7F)                      /* DEL */
      || (cp >= 0x80   && cp <= 0x9F)      /* C1 controls */
      || (cp == 0xAD)                      /* soft hyphen */
      || (cp == 0x34F)                     /* combining grapheme joiner */
      || (cp == 0x61C)                     /* Arabic letter mark (bidi) */
      || (cp == 0x180E)                    /* Mongolian vowel separator */
      || (cp >= 0x200B && cp <= 0x200F)    /* zero-width, bidi marks */
      || (cp == 0x2028 || cp == 0x2029)    /* line/paragraph separators */
      || (cp >= 0x202A && cp <= 0x202E)    /* bidi embedding/override */
      || (cp >= 0x2060 && cp <= 0x2064)    /* word joiner, invisible operators */
      || (cp >= 0x2066 && cp <= 0x206F)    /* bidi isolates, deprecated format */
      || (cp == 0xFEFF)                    /* BOM / zero-width no-break space */
      || (cp >= 0xFFF9 && cp <= 0xFFFB)    /* interlinear annotation */
      || (cp >= 0xE0000 && cp <= 0xE007F); /* tags: invisible text */
}


/*
 * Sanitise n bytes of src into out[], which must hold 3 * n + 1 bytes, and
 * return the output length. The output is valid UTF-8 and NUL-terminated.
 * Each invalid byte, and each code point in the reject set above, becomes
 * U+FFFD; tab becomes a space. Sets *repaired if any of that happened, and
 * leaves it alone otherwise. src may contain NUL bytes and is not
 * NUL-terminated.
 *
 * Why U+FFFD rather than deletion or '?': the log stream is JSON and
 * therefore UTF-8, so the replacement is the character Unicode recommends.
 * Unicode Security Considerations (UTR #36) warns against deleting
 * ill-formed input instead, because deletion lets neighbouring text join
 * into something that was never sent - "admin<bad>@evil.com" must not
 * become "admin@evil.com". This is not cosmetic: an invalid byte would
 * otherwise reach the JSON as invalid UTF-8 and cost us the whole log
 * record, and validating UTF-8 alone would still let C0 controls and bidi
 * overrides such as U+202E through.
 *
 * One U+FFFD per rejected *byte*, not per rejected sequence, so that the
 * output length reflects how much was wrong.
 */
static size_t sanitise_utf8(const char *src, size_t n, char *out,
                            bool *repaired) {
  const unsigned char *s = (const unsigned char *)src;
  size_t i = 0;
  size_t len = 0;

  while (i < n) {
    unsigned long cp;
    size_t seqlen;

    if (!utf8_next(s + i, n - i, &cp, &seqlen)) {
      memcpy(out + len, replacement, REPLACEMENT_LEN);
      len += REPLACEMENT_LEN;
      i += 1;
      *repaired = true;
    } else if (cp == 0x09) {
      out[len++] = ' ';
      i += seqlen;
      *repaired = true;
    } else if (cp_rejected(cp)) {
      memcpy(out + len, replacement, REPLACEMENT_LEN);
      len += REPLACEMENT_LEN;
      i += seqlen;
      *repaired = true;
    } else {
      memcpy(out + len, s + i, seqlen);
      len += seqlen;
      i += seqlen;
    }
  }
  out[len] = '\0';
  return len;
}


/*
 * Put clean (len bytes of valid UTF-8) into field[] (size bytes, at least 5).
 * If it doesn't fit, or was_cut says input was already lost, cut it on a
 * character boundary and end it with "...". Returns true if field[] holds
 * the whole of clean with no marker.
 */
static bool fit_value(char *field, size_t size, const char *clean, size_t len,
                      bool was_cut) {
  size_t k;

  if (!was_cut && len <= size - 1) {
    memcpy(field, clean, len + 1);
    return true;
  }

  k = size - 1 - TRUNCATION_MARKER_LEN;
  if (len < k) {
    k = len;
  }
  while (k > 0 && ((unsigned char)clean[k] & 0xC0) == 0x80) {
    k--;                            /* clean is valid UTF-8: back to a lead byte */
  }
  memcpy(field, clean, k);
  memcpy(field + k, TRUNCATION_MARKER, TRUNCATION_MARKER_LEN + 1);
  return false;
}


/* Pass the two reports back to whichever pointers the caller supplied. */
static void report(bool *repaired, bool rep, bool *truncated, bool cut) {
  if (repaired != NULL) {
    *repaired = rep;
  }
  if (truncated != NULL) {
    *truncated = cut;
  }
}


/* Sanitise a completed, undecoded field in place. See header_text.h for
 * what *repaired and *truncated report. */
void sanitise_inplace(char *field, size_t size, bool was_cut,
                      bool *repaired, bool *truncated) {
  char clean[3 * RAW_MAX + 1];
  bool rep = false;
  bool cut = true;
  size_t n;
  size_t len;

  if (size < TRUNCATION_MARKER_LEN + 2) {
    if (size > 0) {
      field[0] = '\0';             /* never leave raw bytes behind */
    }
  } else {
    n = strlen(field);
    if (n > RAW_MAX) {
      n = RAW_MAX;
      was_cut = true;
    }
    len = sanitise_utf8(field, n, clean, &rep);
    cut = !fit_value(field, size, clean, len, was_cut);
  }
  report(repaired, rep, truncated, cut);
}


/* Decode RFC 2047 encoded-words in a completed field in place, then
 * sanitise it. The field holds the raw bytes store_header_value() kept, so
 * it may contain raw UTF-8 (RFC 6532) or junk as well as encoded-words.
 * Charsets other than UTF-8/US-ASCII are left encoded. See header_text.h
 * for what *repaired and *truncated report.
 *
 * nmh decodes leniently: inside an encoded-word it silently drops what it
 * can't decode (a malformed "=" or non-base64 characters) and a Q-encoded
 * NUL, so the logged text can join across a dropped byte. A NUL from base64
 * is kept and becomes U+FFFD. */
void decode_header_field(char *field, size_t size,
                         bool *repaired, bool *truncated) {
  char decoded[RAW_MAX];
  char clean[3 * RAW_MAX + 1];
  bool rep = false;
  bool was_cut;
  size_t clean_len;
  ssize_t len;

  if (size < TRUNCATION_MARKER_LEN + 2 || strstr(field, "=?") == NULL) {
    sanitise_inplace(field, size, false, repaired, truncated);
    return;
  }

  len = decode_rfc2047(field, decoded, sizeof(decoded), NULL);
  if (len < 0) {
    sanitise_inplace(field, size, false, repaired, truncated);
    return;
  }

  /* decode_rfc2047() returns sizeof(decoded) - 1 both for a full buffer
   * and an exact fit. Decoded text is never longer than its input, and a
   * field is always shorter than RAW_MAX, so a full buffer can't happen;
   * if it somehow did, the value is marked as cut. */
  was_cut = (size_t)len >= sizeof(decoded) - 1;
  clean_len = sanitise_utf8(decoded, (size_t)len, clean, &rep);
  report(repaired, rep, truncated,
         !fit_value(field, size, clean, clean_len, was_cut));
}


/* A naïve extraction of the address from a decoded, sanitised mailbox
 * header value (From, Sender) into out, which must have room for at least
 * one byte. Accepts "display-name <addr>" and a bare addr. For logging
 * only: it is not a validator.
 *
 * Returns true with the address in out. Returns false, leaving out empty,
 * for anything else, including the features listed below, an empty
 * value, and an address that doesn't fit in outsize.
 *
 * Only the first '<' and the last '>' are looked at, and any text before
 * the '<' is ignored, even another address. Examples:
 *   "a@x <b@y>"                    yields b@y
 *     [a smarter extractor would fail: unquoted display names mustn't contain '@']
 *   "a@x =?UTF-8?Q?=3Cb@y=3E?="    decodes to "a@x <b@y>", yields b@y
 *     [a smarter extractor would fail: the addr mustn't be put inside an encoded-word]
 *   "=?UTF-8?Q?=3Cc@z=3E?= <b@y>"  decodes to "<c@z> <b@y>", which fails
 *   "<b@y> =?UTF-8?Q?=3Cc@z=3E?="  decodes to "<b@y> <c@z>", which fails
 *
 * RFC 5322 features it makes no attempt to support, all of which fail:
 *   - comments (CFWS) after the address or in a bare one: "a@x (Name)"
 *   - groups (RFC 6854 allows them in From): "g: a@x;", "undisclosed:;"
 *   - obs-route: "<@relay:a@x>"
 *   - quoted local parts: "john doe"@x
 *   - domain literals: "a@[192.0.2.1]"
 *   - obsolete whitespace inside an addr-spec: "a . b @ x"
 *   - more than one mailbox (From is a mailbox-list), except that of
 *     "a@x, B <b@y>" b@y is taken
 *   - a quoted display name containing '<'
 *   - a U+FFFD inside the address, where sanitising replaced a byte
 *
 * Nor does it check the address beyond one '@' not at either end and none
 * of the RFC 5322 specials, whitespace or a trailing '.': dot-atom syntax,
 * label lengths and IDNA are not checked. Because the value is decoded
 * first, a whole value sent as one encoded-word, which RFC 2047 forbids
 * but some scripts produce, yields the decoded address. */
bool extract_address(const char *v, char *out, size_t outsize) {
  const char *lt = strchr(v, '<');
  const char *gt = strrchr(v, '>');
  const char *a = v;
  const char *at;
  size_t n = strlen(v);

  out[0] = '\0';
  if (lt != NULL) {
    if (gt == NULL || gt < lt || gt[1 + strspn(gt + 1, " ")] != '\0') {
      return false;           /* no closing '>', or text after it */
    }
    a = lt + 1;
    n = (size_t)(gt - a);
  }
  if (n == 0 || n >= outsize) {
    return false;
  }
  memcpy(out, a, n);
  out[n] = '\0';
  at = strchr(out, '@');
  if (at == NULL || at == out || at[1] == '\0' || strchr(at + 1, '@') != NULL
      || out[n - 1] == '.'
      || strpbrk(out, " \"()<>[]\\,;:") != NULL
      || strstr(out, "\xEF\xBF\xBD") != NULL) {
    out[0] = '\0';
    return false;
  }
  return true;
}
